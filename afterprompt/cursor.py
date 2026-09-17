"""Copy Cursor's SQLite chat stores (with -wal/-shm) and dump every row as text, so the scanner sees whole
values (SQLite splits long values across overflow pages)."""
import glob
import os
import shutil
import sqlite3
import time

from afterprompt.util import log, makedirs, write_json

PART_CAP = 256 * 1024 ** 2


def extract(cfg, sources, part_cap=PART_CAP):
    out_dir = cfg.w("extracted", "cursor")
    copy_dir = cfg.w("dbcopy")
    makedirs(out_dir)
    makedirs(copy_dir)
    ledger = []
    for n, db in enumerate(sources["cursor_dbs"]):
        t0 = time.monotonic()
        tag = f"{n:03d}"
        base = os.path.join(copy_dir, f"{tag}.db")
        entry = {"tag": tag, "db": db["path"], "side": db["side"]}
        try:
            shutil.copyfile(db["path"], base)
            if not db["path"].endswith(".backup"):
                for suf in ("-wal", "-shm"):
                    if os.path.exists(db["path"] + suf):
                        shutil.copyfile(db["path"] + suf, base + suf)
            con = sqlite3.connect(f"file:{base}?mode=ro", uri=True)
            try:
                tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
                rows = written = part = 0
                fo = open(os.path.join(out_dir, f"{tag}_{part:02d}.txt"), "wb")
                fo.write(f"### SOURCE {db['path']}\n".encode("utf-8", "replace"))
                for t in tables:
                    cols = [c[1] for c in con.execute(f'pragma table_info("{t}")')]
                    for r in con.execute(f'select * from "{t}"'):
                        rec = []
                        for c, v in zip(cols, r):
                            if isinstance(v, bytes):
                                v = v.decode("utf-8", "replace")
                            rec.append(f"{c}={v}")
                        line = (f"### {t} | " + " | ".join(rec) + "\n").encode("utf-8", "replace")
                        fo.write(line)
                        written += len(line)
                        rows += 1
                        if written > part_cap:
                            fo.close()
                            part += 1
                            written = 0
                            fo = open(os.path.join(out_dir, f"{tag}_{part:02d}.txt"), "wb")
                            fo.write(f"### SOURCE {db['path']} (continued)\n".encode("utf-8", "replace"))
                fo.close()
            finally:
                con.close()
            entry.update(status="ok", tables=tables, rows=rows, parts=part + 1)
        except (OSError, sqlite3.Error) as e:
            entry.update(status=f"error:{type(e).__name__}: {e}")
            for f in glob.glob(os.path.join(glob.escape(out_dir), f"{tag}_*.txt")):
                os.remove(f)
        finally:
            for f in glob.glob(glob.escape(base) + "*"):
                try:
                    os.remove(f)
                except OSError:
                    pass
        entry["s"] = round(time.monotonic() - t0, 1)
        ledger.append(entry)
        log(f"  cursor {tag} {entry['status'][:80]} rows={entry.get('rows')}")
    write_json(cfg.w("extracted", "_ledger.json"), ledger)
    ok = sum(1 for e in ledger if e["status"] == "ok")
    return {"databases": len(ledger), "ok": ok, "failed": [{"path": e["db"], "error": e["status"]}
                                                           for e in ledger if e["status"] != "ok"]}
