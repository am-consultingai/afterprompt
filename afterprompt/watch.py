"""Is the exposure still there?

A scan is a photograph. Once you have rotated a key and cleaned a transcript, the only question left is
whether the value is still sitting on this disk — and that is a question this machine can answer without
asking any vendor anything, which is the only kind of question Afterprompt asks.

The check re-reads the files a finding came from and hashes what matches, exactly as the scan did, then
compares hashes. The plaintext is never kept anywhere, before or after.

What it cannot answer, it says so rather than guessing:
  - a file in another environment (a WSL distro) is not reachable from here;
  - a finding that only existed inside a decoded payload is not in the raw file to be found;
  - a file too large to re-read inside a watchdog tick is left alone.
"""
import os
import re
import time

from afterprompt.patterns import MULTILINE, PATTERNS, escape_aware, strip_residue
from afterprompt.util import sha16
from afterprompt.vendor import value_part      # the same value the scan hashed, so the hashes compare

CAP = 64 * 1024 * 1024          # per file: a re-check is a background chore, not a second scan
PRESENT, GONE, UNKNOWN = "present", "gone", "unknown"
RX = {}


def regex(name):
    """Compiled over bytes, like the scan's: a file is read as bytes and never decoded."""
    if name not in RX:
        for n, rx, _ in PATTERNS:
            if n == name:
                RX[name] = re.compile(escape_aware(rx).encode("utf-8"), re.S if name in MULTILINE else 0)
                break
        else:
            RX[name] = None
    return RX[name]


def resolve(display, home):
    """Findings store display paths ("~/.claude/…"); a re-check needs the real one."""
    if not display:
        return None
    if display.startswith("~/") or display.startswith("~\\"):
        return os.path.join(home, display[2:].replace("\\", os.sep).replace("/", os.sep))
    if display == "~":
        return home
    return display if os.path.isabs(display) else None


def files_for(finding, home, side=None):
    """Every local file this finding says it is in, with why one was left out."""
    out, skipped = [], []
    for loc in finding.get("locations") or []:
        if side and loc.get("side") and loc["side"] != side:
            skipped.append("another environment")
            continue
        if loc.get("decoded"):
            skipped.append("found only inside a decoded payload")
            continue
        path = resolve(loc.get("display"), home)
        if path:
            out.append(path)
        else:
            skipped.append("path not resolvable")
    for store in finding.get("still_on_disk") or []:
        path = resolve(store.get("store"), home)
        if path:
            out.append(path)
    return sorted(set(out)), sorted(set(skipped))


def hashes_in(path, names, cap=CAP):
    """Match hashes and value hashes still in this file. Returns None when it could not look."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return set()                      # gone from disk counts as an answer, not a failure
    if size > cap:
        return None
    try:
        with open(path, "rb") as fh:
            blob = fh.read(cap)
    except OSError:
        return None
    found = set()
    for name in names:
        rx = regex(name)
        if rx is None:
            continue
        for m in rx.finditer(blob):
            value, _ = strip_residue(m.group(0), m.start())
            found.add(sha16(value))
            found.add(sha16(value_part(name, value)))
    return found


def check(finding, home, side=None, cap=CAP, now=None):
    """One finding: present, gone, or unknown, with the files that still hold it."""
    wanted = {finding.get("hash")} | set(finding.get("match_hashes") or [])
    wanted.discard(None)
    names = [n for n in (finding.get("patterns") or []) if regex(n) is not None]
    paths, skipped = files_for(finding, home, side)
    if finding.get("decoded_only"):
        skipped.append("found only inside a decoded payload")
    result = {"state": UNKNOWN, "in": [], "checked": int(now or time.time()), "why": None}
    if not names or not wanted:
        result["why"] = "nothing to match on"
        return result
    if not paths:
        result["why"] = skipped[0] if skipped else "no local file to re-read"
        return result
    looked, unreadable = 0, 0
    for path in paths:
        found = hashes_in(path, names, cap)
        if found is None:
            unreadable += 1
            continue
        looked += 1
        if found & wanted:
            result["in"].append(path)
    if result["in"]:
        result["state"] = PRESENT
    elif looked:
        result["state"] = GONE
        if unreadable or skipped:
            result["why"] = "gone from the files that could be re-read"
    else:
        result["why"] = "no file could be re-read"
    return result


def check_all(findings, home, side=None, cap=CAP, now=None):
    """Every finding in a report, cheapest first: each file is read once, however many findings it holds."""
    cache, out = {}, {}
    items = list(findings.get("rotate") or []) + list(findings.get("review") or [])
    for f in items:
        wanted = {f.get("hash")} | set(f.get("match_hashes") or [])
        wanted.discard(None)
        names = [n for n in (f.get("patterns") or []) if regex(n) is not None]
        paths, skipped = files_for(f, home, side)
        if f.get("decoded_only"):
            skipped.append("found only inside a decoded payload")
        row = {"state": UNKNOWN, "in": [], "checked": int(now or time.time()), "why": None}
        if names and wanted and paths:
            looked = 0
            for path in paths:
                key = (path, tuple(sorted(names)))
                if key not in cache:
                    cache[key] = hashes_in(path, names, cap)
                found = cache[key]
                if found is None:
                    continue
                looked += 1
                if found & wanted:
                    row["in"].append(path)
            if row["in"]:
                row["state"] = PRESENT
            elif looked:
                row["state"] = GONE
            else:
                row["why"] = "no file could be re-read"
        else:
            row["why"] = (skipped[0] if skipped else "no local file to re-read") if not names or not paths \
                else None
        out[f.get("hash")] = row
    return out
