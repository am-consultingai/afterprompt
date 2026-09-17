"""Deep mode: decode JSON escapes, URL encoding, base64, hex, gzip/zip/tar and JWT payloads to plaintext.

Memory safety: output is streamed to disk; files are read in 32 MB windows; every decode step counts toward a
per-file output cap; a deadline is checked throughout; the pool enforces a per-worker memory cap.
"""
import base64
import binascii
import codecs
import json
import os
import re
import signal
import tarfile
import time
import zipfile
import zlib
from urllib.parse import unquote_to_bytes

from afterprompt import pool


class Budget(Exception):
    pass


PRINT = frozenset(list(range(32, 127)) + [9, 10, 13])
B64 = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
B64U = re.compile(rb"[A-Za-z0-9_\-]{24,}={0,2}")
HEXRUN = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")
PCT = re.compile(rb"(?:[A-Za-z0-9._~+\-]{0,40}%[0-9A-Fa-f]{2})+[A-Za-z0-9._~+\-]{0,200}")
B64SHORT = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,23}={1,2}")
JWTP = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.(eyJ[A-Za-z0-9_\-]{8,})\.")
MAX_DEPTH = 3


def printable(b):
    s = b[:1024]
    return len(s) >= 12 and sum(1 for c in s if c in PRINT) >= 0.9 * len(s)


def inflate(b):
    if b[:2] == b"\x1f\x8b" or b[:1] == b"\x78":
        try:
            return [zlib.decompressobj(47).decompress(b, 16 * 1024 ** 2)]
        except zlib.error:
            pass
    return []


def expand(data, depth, sink, deadline=None):
    if depth > MAX_DEPTH or len(data) < 12:
        return
    if deadline is not None and time.monotonic() > deadline:
        raise TimeoutError()
    if b"\\" in data:
        try:
            u = codecs.decode(data, "unicode_escape", "ignore").encode("utf-8", "replace")
            if u != data:
                sink(u)
                expand(u, depth + 1, sink, deadline)
        except (MemoryError, Budget, TimeoutError, RecursionError):
            raise
        except Exception:  # noqa: BLE001 - malformed escapes are expected
            pass
    for m in PCT.finditer(data):
        if b"%" in m.group(0) and len(m.group(0)) >= 16:
            d = unquote_to_bytes(m.group(0))
            if printable(d):
                sink(d)
                expand(d, depth + 1, sink, deadline)
    for m in B64SHORT.finditer(data):
        try:
            d = base64.b64decode(m.group(0))
        except (binascii.Error, ValueError):
            continue
        if len(d) >= 8 and printable(d):
            sink(d)
    for rx, urlsafe in ((B64, False), (B64U, True)):
        for m in rx.finditer(data):
            blob = m.group(0)
            if len(blob) > 8 * 1024 ** 2 or (urlsafe and b"-" not in blob and b"_" not in blob):
                continue
            try:
                pad = blob + b"=" * (-len(blob) % 4)
                d = base64.urlsafe_b64decode(pad) if urlsafe else base64.b64decode(pad)
            except (binascii.Error, ValueError):
                continue
            for z in inflate(d):
                if printable(z):
                    sink(z)
                    expand(z, depth + 1, sink, deadline)
            if printable(d):
                sink(d)
                expand(d, depth + 1, sink, deadline)
    for m in HEXRUN.finditer(data):
        try:
            d = binascii.unhexlify(m.group(0))
        except binascii.Error:
            continue
        if printable(d):
            sink(d)
            expand(d, depth + 1, sink, deadline)
    for m in JWTP.finditer(data):
        p = m.group(1)
        try:
            d = base64.urlsafe_b64decode(p + b"=" * (-len(p) % 4))
        except (binascii.Error, ValueError):
            continue
        if printable(d):
            sink(d)


def archive_payloads(path):
    with open(path, "rb") as fh:
        head = fh.read(512)
    if head.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist()[:1000]:
                if not info.is_dir() and info.file_size <= 256 * 1024 ** 2:
                    with z.open(info) as m:
                        yield m.read(64 * 1024 ** 2)
    elif head.startswith(b"\x1f\x8b"):
        with open(path, "rb") as fh:
            yield zlib.decompressobj(47).decompress(fh.read(64 * 1024 ** 2), 64 * 1024 ** 2)
    elif head[257:262] == b"ustar":
        with tarfile.open(path) as t:
            for mem in t.getmembers()[:1000]:
                if mem.isfile() and mem.size <= 256 * 1024 ** 2:
                    f = t.extractfile(mem)
                    if f:
                        yield f.read(64 * 1024 ** 2)


def _alarm(signum, frame):
    raise TimeoutError()


def decode_path(path, out_path, out_cap, timeout):
    """Decode one file into out_path. Returns (status, bytes written)."""
    deadline = time.monotonic() + timeout
    n = [0]
    status = "ok"
    part = out_path + ".part"
    use_alarm = hasattr(signal, "SIGALRM")
    if use_alarm:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(max(1, int(timeout) + 5))
    try:
        with open(part, "wb") as fh:
            def sink(b):
                if n[0] > out_cap:
                    raise Budget()
                if time.monotonic() > deadline:
                    raise TimeoutError()
                fh.write(b)
                fh.write(b"\n")
                n[0] += len(b) + 1
            try:
                size = os.path.getsize(path)
                window, step = 32 * 1024 ** 2, 24 * 1024 ** 2
                with open(path, "rb") as src:
                    off = 0
                    while True:
                        if time.monotonic() > deadline:
                            raise TimeoutError()
                        src.seek(off)
                        data = src.read(window)
                        if not data:
                            break
                        expand(data, 0, sink, deadline)
                        del data
                        if off + window >= size:
                            break
                        off += step
                try:
                    for payload in archive_payloads(path):
                        if printable(payload):
                            sink(payload)
                        expand(payload, 1, sink, deadline)
                except (zipfile.BadZipFile, tarfile.TarError, zlib.error, EOFError):
                    pass
            except Budget:
                status = "output-cap"
            except MemoryError:
                status = "memory-cap"
            except TimeoutError:
                status = "timeout"
            except RecursionError:
                status = "recursion"
    except OSError as e:
        status = f"error:{type(e).__name__}"
    finally:
        if use_alarm:
            signal.alarm(0)
    if n[0]:
        os.replace(part, out_path)
    elif os.path.exists(part):
        os.remove(part)
    return status, n[0]


def decode_item(item):
    idx, path = item
    w = pool.WORKER
    marker = os.path.join(w["work_dir"], "state", "expand", f"{idx}.done")
    if os.path.exists(marker):
        return
    t0 = time.monotonic()
    status, n = decode_path(path, os.path.join(w["work_dir"], "store", f"{idx}.txt"), w["file_out_cap"],
                            w["file_timeout"])
    with open(marker, "w", encoding="utf-8") as fh:
        json.dump({"s": status, "n": n, "t": round(time.monotonic() - t0, 1)}, fh)


def run(cfg, rows):
    from afterprompt.util import log, makedirs
    makedirs(cfg.w("store"))
    makedirs(cfg.w("state", "expand"))
    items = [(r.idx, r.path) for r in rows if not r.vendored and not r.self]
    marker = lambda idx: cfg.w("state", "expand", f"{idx}.done")  # noqa: E731

    def is_done(it):
        return os.path.exists(marker(it[0]))

    def on_crash(it, why):
        part = cfg.w("store", f"{it[0]}.txt.part")
        n = 0
        if os.path.exists(part):
            n = os.path.getsize(part)
            os.replace(part, cfg.w("store", f"{it[0]}.txt"))
        with open(marker(it[0]), "w", encoding="utf-8") as fh:
            json.dump({"s": why, "n": n, "t": 0}, fh)

    def decoded_total():
        total = 0
        for fn in os.listdir(cfg.w("state", "expand")):
            try:
                with open(cfg.w("state", "expand", fn), encoding="utf-8") as fh:
                    total += json.load(fh).get("n", 0)
            except (OSError, ValueError):
                pass
        return total

    counter = {"total": decoded_total()}

    def should_stop(it):
        try:
            with open(marker(it[0]), encoding="utf-8") as fh:
                counter["total"] += json.load(fh).get("n", 0)
        except (OSError, ValueError):
            pass
        return counter["total"] >= cfg.max_disk_bytes

    cap_reached = counter["total"] >= cfg.max_disk_bytes
    if cap_reached:
        skipped = [it for it in items if not is_done(it)]
    else:
        skipped = pool.run_pool(decode_item, items, "decode", is_done, on_crash, cfg, should_stop=should_stop)
    for it in skipped:
        with open(marker(it[0]), "w", encoding="utf-8") as fh:
            json.dump({"s": "disk-cap", "n": 0, "t": 0}, fh)
    statuses, nbytes = {}, 0
    for idx, _ in items:
        try:
            with open(marker(idx), encoding="utf-8") as fh:
                j = json.load(fh)
        except (OSError, ValueError):
            j = {"s": "missing", "n": 0}
        statuses[j["s"]] = statuses.get(j["s"], 0) + 1
        nbytes += j["n"]
    log(f"decode: statuses {statuses}, {nbytes / 1e9:.2f} GB decoded")
    return {"eligible": len(items), "statuses": statuses, "decoded_bytes": nbytes,
            "disk_cap_reached": bool(skipped) or cap_reached or nbytes >= cfg.max_disk_bytes
                                or statuses.get("disk-cap", 0) > 0,
            "not_decoded": statuses.get("disk-cap", 0)}
