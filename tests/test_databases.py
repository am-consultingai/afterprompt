import glob
import os
import sqlite3
import unittest

from afterprompt import databases
from tests.helpers import TempDirTest, cursor_db, make_cfg, requires_posix


def read_parts(cfg):
    out = ""
    for p in sorted(glob.glob(cfg.w("extracted", "db", "*.txt"))):
        with open(p, encoding="utf-8") as fh:
            out += fh.read()
    return out


class CursorTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.cfg = make_cfg(self.tmp)

    def srcs(self, *paths):
        return {"databases": [{"path": p, "side": "linux"} for p in paths]}

    def test_rows_and_blobs(self):  # U-CUR-1
        db = os.path.join(self.tmp, "state.vscdb")
        cursor_db(db, [(1, "hello there"), (2, "reply")])
        info = databases.extract(self.cfg, self.srcs(db))
        self.assertEqual(info["ok"], 1)
        text = read_parts(self.cfg)
        self.assertIn(f"### SOURCE {db}", text)
        self.assertIn("hello there", text)
        self.assertIn("### ItemTable | key=workbench.state", text)

    def test_wal_content(self):  # U-CUR-2
        db = os.path.join(self.tmp, "wal.vscdb")
        con = sqlite3.connect(db)
        con.execute("pragma journal_mode=wal")
        con.execute("pragma wal_autocheckpoint=0")
        con.execute("create table t (v text)")
        con.execute("insert into t values ('only-in-the-wal-9f3k')")
        con.commit()
        self.assertTrue(os.path.exists(db + "-wal"))
        databases.extract(self.cfg, self.srcs(db))
        con.close()
        self.assertIn("only-in-the-wal-9f3k", read_parts(self.cfg))

    def test_backup_db(self):  # U-CUR-3
        db = os.path.join(self.tmp, "state.vscdb.backup")
        cursor_db(db, [(1, "from the backup")])
        with open(db + "-wal", "wb") as fh:
            fh.write(b"garbage")
        info = databases.extract(self.cfg, self.srcs(db))
        self.assertEqual(info["ok"], 1)
        self.assertIn("from the backup", read_parts(self.cfg))

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read mode-000 files")
    @requires_posix  # chmod 000 does not deny the owner on Windows
    def test_unreadable_db(self):  # U-CUR-4
        bad = os.path.join(self.tmp, "locked.vscdb")
        good = os.path.join(self.tmp, "good.vscdb")
        cursor_db(bad, [(1, "x")])
        cursor_db(good, [(1, "readable text")])
        os.chmod(bad, 0)
        info = databases.extract(self.cfg, self.srcs(bad, good))
        self.assertEqual(info["ok"], 1)
        self.assertEqual(len(info["failed"]), 1)
        self.assertIn("readable text", read_parts(self.cfg))

    def test_part_split(self):  # U-CUR-5
        db = os.path.join(self.tmp, "big.vscdb")
        cursor_db(db, [(1, "y" * 400) for _ in range(20)])
        databases.extract(self.cfg, self.srcs(db), part_cap=1000)
        self.assertGreater(len(glob.glob(self.cfg.w("extracted", "db", "000_*.txt"))), 2)

    def test_copies_removed(self):  # U-CUR-6
        db = os.path.join(self.tmp, "state.vscdb")
        cursor_db(db, [(1, "x")])
        databases.extract(self.cfg, self.srcs(db))
        self.assertEqual(os.listdir(self.cfg.w("dbcopy")), [])
