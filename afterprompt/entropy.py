"""Deep mode: unanchored high-entropy token sweep with shape classification."""
import collections
import json
import os
import re
import signal
import time

from afterprompt import pool
from afterprompt.util import entropy as ent
from afterprompt.util import log, makedirs, mask, sha16

TOK = re.compile(rb"[A-Za-z0-9_\-+/=.]{20,}")
KEYWORD = re.compile(rb"(?i)key|secret|token|passw|pwd|auth|bearer|credential|cookie|session|api")
KEYWORD_STRICT = re.compile(rb"(?i)key|secret|passw|pwd|auth|bearer|credential|token(?!s)")
URLENC = re.compile(rb"^(?:2F|3A|3D|26|2C|22|27|3F|40|2B)")
NUMISH = re.compile(rb"[0-9.\-+=_/]+")
HEXONLY = re.compile(rb"[0-9a-fA-F]+")
UUIDRX = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
WORDY = re.compile(rb"[a-z][a-z0-9_.\-]*")
EXT = re.compile(rb"\.[A-Za-z0-9]{1,5}$")
DOTPART = re.compile(rb"[A-Za-z_\-]+|[0-9]+")
CODE_TOK = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*=|===|==$")
SLUG = re.compile(rb"[a-z0-9]+(?:[-_][a-z0-9]+)+")
CLS_RULES = [
    ("claude_id", re.compile(rb"^(?:srvtoolu_|toolu_|cse_|session_|msg_|req_|sess_|tengu_|bi1-)")),
    ("atlassian", re.compile(rb"^ATATT3")),
    ("anthropic", re.compile(rb"^sk-ant-")),
    ("jwt", re.compile(rb"^eyJ[A-Za-z0-9_\-]+\.eyJ")),
    ("apps_script_id", re.compile(rb"^AKfycb")),
    ("drive_id", re.compile(rb"^1[A-Za-z0-9_\-]{32}$|^1[A-Za-z0-9_\-]{43}$")),
    ("google_page_token", re.compile(rb"^(?:CjQ|CAO|Ablu|CiQ|CAE|CBE)")),
    ("sri_hash", re.compile(rb"^sha(?:256|384|512)-")),
    ("google_client_id", re.compile(rb"apps\.googleusercontent\.com$")),
    ("filename", re.compile(rb"\.(?:js|mjs|cjs|ts|tsx|py|json|jsonl|md|png|jpe?g|gif|webp|svg|css|html?|map|lock|"
                            rb"txt|sh|ya?ml|csv|xlsx?|docx?|pdf|mp[34]|wav|gguf|onnx|bin|pt|ttf|woff2?|sql|zip|gz|"
                            rb"tar|toml|ini|log)$", re.I)),
]
KEEP = {"unclassified", "apps_script_id", "atlassian", "anthropic", "jwt", "long_token"}
# Bits of entropy per character a token needs to be kept: less when a secret-related word is right before it.
MIN_ENTROPY_NEAR_KEYWORD, MIN_ENTROPY = 3.5, 3.8


def classify(v):
    if NUMISH.fullmatch(v):
        return None
    if URLENC.match(v):
        return "urlencoded_fragment"
    if HEXONLY.fullmatch(v):
        return "hex"
    if UUIDRX.fullmatch(v):
        return "uuid"
    for name, rx in CLS_RULES:
        if rx.search(v):
            return name
    if b"/" in v:
        segs = [s for s in v.split(b"/") if s]
        if segs and 2 * sum(1 for s in segs if WORDY.fullmatch(s) or EXT.search(s)) >= len(segs):
            return "path"
    if v.count(b".") >= 2 and all(DOTPART.fullmatch(p) for p in v.split(b".") if p):
        return "dotted_name"
    if CODE_TOK.search(v):
        return "code"
    parts = [p for p in re.split(rb"[-_]", v) if p]
    if len(parts) >= 3 and sum(1 for p in parts if p.isalpha()) >= 0.6 * len(parts):
        return "slug"
    if SLUG.fullmatch(v):
        return "slug"
    if not any(48 <= c <= 57 for c in v):
        return "identifier"
    return "unclassified"


def _alarm(signum, frame):
    raise TimeoutError()


def sweep_path(path, idx, timeout, block=8 * 1024 ** 2):
    """Return (rows, counts, status) for one file."""
    deadline = time.monotonic() + timeout
    rows, counts, status = {}, collections.Counter(), "ok"
    use_alarm = hasattr(signal, "SIGALRM")
    if use_alarm:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(max(1, int(timeout) + 5))
    try:
        with open(path, "rb") as fh:
            bs, ov, pos = block, 256, 0
            while True:
                if time.monotonic() > deadline:
                    raise TimeoutError()
                base = pos - 1 if pos else 0
                fh.seek(base)
                want = bs + (pos - base)
                blk = fh.read(want)
                if not blk:
                    break
                full = len(blk) == want
                seen = 0
                for m in TOK.finditer(blk):
                    seen += 1
                    if seen % 10000 == 0 and time.monotonic() > deadline:
                        raise TimeoutError()
                    if (pos and m.start() == 0) or (full and m.end() == len(blk)):
                        continue
                    v = m.group(0)
                    vstart = m.start()
                    if len(v) > 2256:
                        continue
                    if vstart and blk[vstart - 1] == 92 and v[:1] in (b"n", b"t", b"r"):
                        v = v[1:]
                        vstart += 1
                    core = v.rstrip(b"=")
                    if b"=" in core:
                        tail = core.rsplit(b"=", 1)[1]
                        vstart += len(core) - len(tail)
                        v = tail
                    if len(v) > 200:
                        if len(v) > 2048 or b"+" in v or b"/" in v or not (b"-" in v or b"_" in v):
                            continue
                        if ent(v) < 4.5 or len(set(v)) < 40:
                            continue
                        counts["long_token"] += 1
                        h = sha16(v)
                        if h not in rows:
                            rows[h] = {"h": h, "m": mask(v), "n": len(v), "c": "long_token", "e": round(ent(v), 2),
                                       "op": 0.5, "nk": False, "nks": False, "f": idx, "o": base + vstart}
                        continue
                    n = len(v)
                    if n < 20:
                        continue
                    up = lo = di = sep = 0
                    for c in v:
                        if 65 <= c <= 90:
                            up += 1
                        elif 97 <= c <= 122:
                            lo += 1
                        elif 48 <= c <= 57:
                            di += 1
                        else:
                            sep += 1
                    if (up > 0) + (lo > 0) + (di > 0) < 2 or len(set(v)) < 10:
                        continue
                    lookback = blk[max(0, vstart - 48):vstart]
                    nk = KEYWORD.search(lookback) is not None
                    nks = KEYWORD_STRICT.search(lookback) is not None
                    e = ent(v)
                    if e < (MIN_ENTROPY_NEAR_KEYWORD if nk else MIN_ENTROPY):
                        continue
                    c = classify(v)
                    if c is None:
                        continue
                    counts[c] += 1
                    h = sha16(v)
                    if h in rows:
                        rows[h]["nk"] = rows[h]["nk"] or nk
                        rows[h]["nks"] = rows[h]["nks"] or nks
                        continue
                    op = (min(up, lo) / n) * (1 - sep / n) if (up and lo and di) else 0.0
                    rows[h] = {"h": h, "m": mask(v), "n": n, "c": c, "e": round(e, 2), "op": round(op, 3),
                               "nk": nk, "nks": nks, "f": idx, "o": base + vstart}
                if not full:
                    break
                pos += bs - ov
    except TimeoutError:
        status = "timeout"
    except MemoryError:
        status = "memory-cap"
    except OSError as e:
        status = f"error:{type(e).__name__}"
    finally:
        if use_alarm:
            signal.alarm(0)
    return rows, counts, status


def sweep_item(item):
    idx, path, target = item
    w = pool.WORKER
    outp = os.path.join(w["work_dir"], f"entropy_{target}", f"{idx}.jsonl")
    if os.path.exists(outp):
        return
    rows, counts, status = sweep_path(path, idx, w["file_timeout"])
    with open(outp + ".part", "w", encoding="utf-8") as fo:
        fo.write(json.dumps({"_counts": counts, "_status": status}) + "\n")
        for r in rows.values():
            fo.write(json.dumps(r) + "\n")
    os.replace(outp + ".part", outp)


def run(cfg, target, rows):
    out_dir = cfg.w(f"entropy_{target}")
    makedirs(out_dir)
    if target == "raw":
        items = [(r.idx, r.path, target) for r in rows if not r.vendored and not r.self]
    else:
        flags = {r.idx: (r.vendored, r.self) for r in rows}
        items = []
        store = cfg.w("store")
        for fn in sorted(os.listdir(store)) if os.path.isdir(store) else ():
            if fn.endswith(".txt"):
                i = int(fn.split(".")[0])
                if flags.get(i, (False, False)) == (False, False):
                    items.append((i, os.path.join(store, fn), target))

    def is_done(it):
        return os.path.exists(os.path.join(out_dir, f"{it[0]}.jsonl"))

    def on_crash(it, why):
        with open(os.path.join(out_dir, f"{it[0]}.jsonl"), "w", encoding="utf-8") as fo:
            fo.write(json.dumps({"_counts": {}, "_status": why}) + "\n")

    pool.run_pool(sweep_item, items, f"entropy_{target}", is_done, on_crash, cfg)
    log(f"entropy_{target}: {len(items)} files")
    return {"files": len(items)}
