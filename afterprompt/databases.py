"""Copy the AI tools' SQLite stores (with -wal/-shm) and dump every row as text, so the scanner sees whole values
(SQLite splits long values across overflow pages). Tables a tool marks as its own login store are left out."""
import glob
import json
import os
import shutil
import sqlite3
import time

from afterprompt import catalogue, progress
from afterprompt.util import log, makedirs, write_json

PART_CAP = 256 * 1024 ** 2


def rows_index(dump_path):
    """Where a dump's row index lives: beside the dumps, not among them, because the dumps are plaintext and are
    removed as soon as the scan has read them, while the index holds only table names, record keys and offsets and
    has to last until triage (see triage.record_at)."""
    d = os.path.dirname(os.path.dirname(dump_path))
    return os.path.join(d, "rows", os.path.splitext(os.path.basename(dump_path))[0] + ".jsonl")


def extract(cfg, sources, part_cap=PART_CAP):
    out_dir = cfg.w("extracted", "db")
    copy_dir = cfg.w("dbcopy")
    makedirs(out_dir)
    makedirs(cfg.w("extracted", "rows"))
    makedirs(copy_dir)
    ledger = []
    for n, db in enumerate(sources["databases"]):
        t0 = time.monotonic()
        tag = f"{n:03d}"
        base = os.path.join(copy_dir, f"{tag}.db")
        tool = db.get("tool", "Cursor")
        skip = {t.lower() for t in catalogue.exclude_tables(tool)}
        entry = {"tag": tag, "db": db["path"], "side": db["side"], "tool": tool}
        try:
            shutil.copyfile(db["path"], base)
            if not db["path"].endswith(".backup"):
                for suf in ("-wal", "-shm"):
                    if os.path.exists(db["path"] + suf):
                        shutil.copyfile(db["path"] + suf, base + suf)
            con = sqlite3.connect(f"file:{base}?mode=ro", uri=True)
            try:
                tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")
                          if r[0].lower() not in skip]
                rows = written = part = 0
                dump = os.path.join(out_dir, f"{tag}_{part:02d}.txt")
                fo = open(dump, "wb")
                fx = open(rows_index(dump), "w", encoding="utf-8")
                fo.write(f"### SOURCE {db['path']}\n".encode("utf-8", "replace"))
                for t in tables:
                    cols = [c[1] for c in con.execute(f'pragma table_info("{t}")')]
                    key_at = [c.lower() for c in cols].index("key") if "key" in [c.lower() for c in cols] else None
                    for r in con.execute(f'select * from "{t}"'):
                        rec = []
                        for c, v in zip(cols, r):
                            if isinstance(v, bytes):
                                v = v.decode("utf-8", "replace")
                            rec.append(f"{c}={v}")
                        line = (f"### {t} | " + " | ".join(rec) + "\n").encode("utf-8", "replace")
                        # Which row starts where, so a hit in this dump can be traced to its record by key.
                        if key_at is not None and r[key_at] is not None:
                            k = r[key_at]
                            k = k.decode("utf-8", "replace") if isinstance(k, bytes) else str(k)
                            fx.write(json.dumps([fo.tell(), t, k]) + "\n")
                        fo.write(line)
                        written += len(line)
                        rows += 1
                        if written > part_cap:
                            fo.close()
                            fx.close()
                            part += 1
                            written = 0
                            dump = os.path.join(out_dir, f"{tag}_{part:02d}.txt")
                            fo = open(dump, "wb")
                            fx = open(rows_index(dump), "w", encoding="utf-8")
                            fo.write(f"### SOURCE {db['path']} (continued)\n".encode("utf-8", "replace"))
                fo.close()
                fx.close()
            finally:
                con.close()
            entry.update(status="ok", tables=tables, rows=rows, parts=part + 1)
        except (OSError, sqlite3.Error) as e:
            entry.update(status=f"error:{type(e).__name__}: {e}")
            for f in glob.glob(os.path.join(glob.escape(out_dir), f"{tag}_*.txt")) + \
                    glob.glob(os.path.join(glob.escape(cfg.w("extracted", "rows")), f"{tag}_*.jsonl")):
                os.remove(f)
        finally:
            for f in glob.glob(glob.escape(base) + "*"):
                try:
                    os.remove(f)
                except OSError:
                    pass
        entry["s"] = round(time.monotonic() - t0, 1)
        ledger.append(entry)
        progress.emit("databases", len(ledger), len(sources["databases"]), tool)
        log(f"  database {tag} {tool} {entry['status'][:80]} rows={entry.get('rows')}")
    write_json(cfg.w("extracted", "_ledger.json"), ledger)
    ok = sum(1 for e in ledger if e["status"] == "ok")
    return {"databases": len(ledger), "ok": ok, "failed": [{"path": e["db"], "error": e["status"]}
                                                           for e in ledger if e["status"] != "ok"]}
