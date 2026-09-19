import json
import multiprocessing
import os
import unittest

from afterprompt import pool
from tests.helpers import TempDirTest, make_cfg


def touch_item(item):
    idx, path = item
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"work_dir": pool.WORKER.get("work_dir")}, fh)


def raise_item(item):
    if item[0] == 1:
        raise ValueError("boom")
    touch_item(item)


def hog_item(item):
    if item[0] == 0:
        import time
        blob = bytearray(600 * 1024 ** 2)
        for i in range(0, len(blob), 4096):
            blob[i] = 1
        time.sleep(5)
    touch_item(item)


class PoolTests(TempDirTest):
    def items(self, n):
        return [(i, os.path.join(self.tmp, f"out{i}.json")) for i in range(n)]

    def run_items(self, fn, items, cfg, **kw):
        crashed = {}
        skipped = pool.run_pool(fn, items, "test", lambda it: os.path.exists(it[1]),
                                lambda it, why: crashed.__setitem__(it[0], why), cfg, **kw)
        return crashed, skipped

    @unittest.skipUnless("fork" in multiprocessing.get_all_start_methods(), "no fork start method")
    def test_fork(self):  # U-POOL-1
        cfg = make_cfg(self.tmp, "linux", mp_start="fork")
        crashed, _ = self.run_items(touch_item, self.items(8), cfg)
        self.assertEqual(crashed, {})
        self.assertTrue(all(os.path.exists(p) for _, p in self.items(8)))

    def test_spawn_sees_worker_config(self):  # U-POOL-2
        cfg = make_cfg(self.tmp, "macos", mp_start="spawn")
        self.run_items(touch_item, self.items(3), cfg)
        with open(self.items(1)[0][1], encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["work_dir"], cfg.work_dir)

    def test_raising_item(self):  # U-POOL-3
        cfg = make_cfg(self.tmp, "linux")
        crashed, _ = self.run_items(raise_item, self.items(3), cfg)
        self.assertEqual(crashed.get(1), "error:ValueError")

    def test_memory_watchdog(self):  # U-POOL-4
        cfg = make_cfg(self.tmp, "macos", mp_start="spawn", workers=2, mem_cap_bytes=200 * 1024 ** 2)
        crashed, _ = self.run_items(hog_item, self.items(3), cfg)
        self.assertEqual(crashed.get(0), "crashed")
        self.assertTrue(os.path.exists(self.items(3)[1][1]))
        self.assertTrue(os.path.exists(self.items(3)[2][1]))

    def test_should_stop(self):  # U-POOL-5
        cfg = make_cfg(self.tmp, "linux", workers=1)
        crashed, skipped = self.run_items(touch_item, self.items(30), cfg, should_stop=lambda it: True)
        self.assertTrue(skipped)
        self.assertLess(sum(os.path.exists(p) for _, p in self.items(30)), 30)
