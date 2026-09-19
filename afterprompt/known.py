"""Search AI-tool data for the live credential values collected by stores.py."""
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


def run(cfg, sources, paths):
    values, stats = stores.collect(cfg, sources)
    pref = stores.prefixes(values)
    stores.write_index(cfg, values, pref)
    n = search(cfg, values, pref, paths)
    stats.update(prefix_keys=len(pref), occurrences=n)
    log(f"known: {n} occurrences")
    return stats
