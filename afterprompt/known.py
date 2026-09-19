"""Search AI-tool data for the live credential values collected by stores.py."""
import base64
import binascii
import json
import os
import subprocess

from afterprompt import stores
from afterprompt.util import log, sha16

RG = ["-uuu", "-a", "-o", "-b", "-N", "-H", "--no-heading", "--no-messages", "--field-match-separator", "\x01"]


def search(cfg, values, pref, paths):
    lookup = {}
    for b in values:
        lookup[b] = (sha16(b), False)
    for p, full in pref.items():
        lookup.setdefault(p, (sha16(full), True))
    store_files = {b: {os.path.normpath(s) for s, _, _ in entries} for b, entries in values.items()}
    for p, full in pref.items():
        store_files.setdefault(p, store_files.get(full, set()))
    paths = [p for p in paths if os.path.exists(p)]
    n = 0
    outp = cfg.w("known.jsonl")
    with open(outp + ".part", "w", encoding="utf-8") as fo:
        if lookup and paths:
            import threading

            # The with block closes both pipes and reaps rg even if the loop raises; closing stdout first makes
            # an rg still writing fail with EPIPE instead of blocking on a full pipe.
            with subprocess.Popen([cfg.rg] + RG + ["-F", "-g", "!*.part", "-f", "-", "--"] + paths,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:

                def feed():
                    try:
                        proc.stdin.write(b"\n".join(lookup) + b"\n")
                    except (OSError, ValueError):
                        pass  # rg exited early or the pipe was closed under us; its exit is handled below
                    finally:
                        try:
                            proc.stdin.close()
                        except OSError:
                            pass

                t = threading.Thread(target=feed, daemon=True)
                t.start()
                for line in proc.stdout:
                    parts = line.rstrip(b"\n").split(b"\x01", 2)
                    if len(parts) != 3 or not parts[1].isdigit() or parts[2] not in lookup:
                        continue
                    path = os.fsdecode(parts[0])
                    if os.path.normpath(path) in store_files.get(parts[2], ()):
                        continue
                    vh, is_prefix = lookup[parts[2]]
                    fo.write(json.dumps({"vh": vh, "prefix": is_prefix, "f": path, "o": int(parts[1])}) + "\n")
                    n += 1
            t.join()
    os.replace(outp + ".part", outp)
    return n


def run(cfg, sources, paths, foreign=None, collected=None):
    """Search AI data for this machine's live values, plus `foreign` ones: the live values of the other
    environments in a multi-environment scan (M5), held in memory only. `collected` reuses a collection made
    earlier in the same process."""
    values, stats = collected if collected is not None else stores.collect(cfg, sources)
    values = {b: list(e) for b, e in values.items()}
    for b, entries in (foreign or {}).items():
        lst = values.setdefault(b, [])
        lst.extend(e for e in entries if e not in lst)
    stats = dict(stats, foreign_values=len(foreign or {}))
    pref = stores.prefixes(values)
    stores.write_index(cfg, values, pref)
    n = search(cfg, values, pref, paths)
    stats.update(prefix_keys=len(pref), occurrences=n)
    log(f"known: {n} occurrences ({len(foreign or {})} values from other environments)")
    return stats


def export_values(values, home=None, windows_home=None):
    """This environment's live values for another environment's search, with display paths for their stores.
    Plaintext: only ever sent over a worker's pipes, never written to disk or argv."""
    from afterprompt.util import display_path
    out = []
    for b, entries in values.items():
        out.append({"v": base64.b64encode(b).decode("ascii"),
                    "e": [[display_path(s, home, windows_home), k, bool(d)] for s, k, d in entries]})
    return out


def import_values(items, prefix, limit=100000):
    """The inverse of export_values, naming each store "[<prefix>] <path>". Defensive about what arrives on a
    pipe: malformed items are dropped, sizes bounded."""
    out = {}
    for it in (items or [])[:limit]:
        try:
            b = base64.b64decode(it["v"], validate=True)
            entries = [(f"[{prefix}] {s}", str(k), bool(d)) for s, k, d in it["e"]][:50]
        except (KeyError, TypeError, ValueError, binascii.Error):
            continue
        if 12 <= len(b) <= 8000 and entries:
            lst = out.setdefault(b, [])
            lst.extend(e for e in entries if e not in lst)
    return out
