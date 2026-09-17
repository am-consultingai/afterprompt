"""Enumerate every file to scan, with vendored/self flags and the tool and side it belongs to."""
import os
import re
import stat
from collections import Counter, namedtuple

from afterprompt.util import is_under, log, read_json

VEND = re.compile(r"/\.local/share/claude/versions/|/\.claude/plugins/|/node_modules/")
SESSION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

Row = namedtuple("Row", "idx size vendored self tool side path")


def scan_roots(cfg, sources):
    """(path, tool, side) for every root, including extracted Cursor text."""
    out = [(r["path"], r["tool"], r["side"]) for r in sources["roots"]]
    ext = cfg.w("extracted", "cursor")
    if os.path.isdir(ext):
        out.append((ext, "Cursor", cfg.platform))
    return out


def ledger_sides(cfg):
    return {e["tag"]: (e["db"], e["side"]) for e in read_json(cfg.w("extracted", "_ledger.json"), []) or []}


def self_session_ids(sources):
    ids = set()
    for d in sources["self_exclude"]:
        for dp, _, fns in os.walk(d):
            for fn in fns:
                stem = fn[:-6] if fn.endswith(".jsonl") else None
                if stem and SESSION_ID.match(stem):
                    ids.add(stem)
    return ids


def build(cfg, sources):
    excludes = [re.compile(x) for x in cfg.excludes]
    ledger = ledger_sides(cfg)
    ext = cfg.w("extracted", "cursor")
    roots = scan_roots(cfg, sources)
    by_len = sorted(roots, key=lambda r: -len(r[0]))
    files, unreadable, odd = {}, [], 0
    excluded = 0
    for root, _, _ in roots:
        if os.path.isfile(root):
            cand = [root]
        else:
            cand = (os.path.join(dp, fn) for dp, _, fns in os.walk(root) for fn in fns)
        for p in cand:
            if p in files:
                continue
            if "\t" in p or "\n" in p:
                odd += 1
                continue
            if any(x.search(p) for x in excludes):
                excluded += 1
                continue
            try:
                st = os.lstat(p)
                if not stat.S_ISREG(st.st_mode):
                    continue
                with open(p, "rb") as fh:
                    fh.read(1)
            except OSError as e:
                unreadable.append([p, type(e).__name__])
                continue
            files[p] = st.st_size
    ids = self_session_ids(sources)
    self_dirs = sources["self_exclude"]
    rows = []
    for i, p in enumerate(sorted(files)):
        tool, side = next(((t, s) for r, t, s in by_len if is_under(p, r)), ("Extra", cfg.platform))
        if is_under(p, ext):
            tag = os.path.basename(p)[:3]
            side = ledger.get(tag, (None, side))[1]
        vend = bool(VEND.search(p))
        selfs = any(is_under(p, d) for d in self_dirs) or any(f"/{sid}" in p for sid in ids)
        rows.append(Row(i, files[p], vend, selfs, tool, side, p))
    with open(cfg.w("manifest.tsv"), "w", encoding="utf-8") as fo:
        for r in rows:
            fo.write(f"{r.idx}\t{r.size}\t{int(r.vendored)}\t{int(r.self)}\t{r.tool}\t{r.side}\t{r.path}\n")
    per = Counter()
    per_bytes = Counter()
    for r in rows:
        per[f"{r.tool}|{r.side}"] += 1
        per_bytes[f"{r.tool}|{r.side}"] += r.size
    stats = {"files": len(rows), "bytes": sum(files.values()), "vendored": sum(r.vendored for r in rows),
             "self": sum(r.self for r in rows), "excluded": excluded, "unreadable": len(unreadable),
             "unreadable_examples": unreadable[:50], "odd_names": odd,
             "per_source": [{"tool": k.split("|")[0], "side": k.split("|")[1], "files": per[k],
                             "bytes": per_bytes[k]} for k in sorted(per)]}
    log(f"manifest: {stats['files']} files, {stats['bytes'] / 1e9:.2f} GB, vendored={stats['vendored']}, "
        f"self={stats['self']}, excluded={excluded}, unreadable={len(unreadable)}")
    return stats


def load(cfg):
    rows = []
    with open(cfg.w("manifest.tsv"), encoding="utf-8") as fh:
        for line in fh:
            idx, size, vend, selfs, tool, side, path = line.rstrip("\n").split("\t", 6)
            rows.append(Row(int(idx), int(size), vend == "1", selfs == "1", tool, side, path))
    return rows
