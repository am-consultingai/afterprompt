import os
import stat
import time

from afterprompt import util
from tests.helpers import TempDirTest, write, WINDOWS


class UtilTests(TempDirTest):
    def test_mask_long_and_short(self):  # U-UTIL-1
        v = "sk-ant-" + "a" * 97 + "WXYZ"
        self.assertEqual(util.mask(v.encode()), "sk-ant…WXYZ")
        self.assertEqual(util.mask(b"abcdefghij"), "abc***")

    def test_scrub(self):  # U-UTIL-2
        out = util.scrub(b"token ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and short words\nnext")
        self.assertIn("token ABCD~32", out)
        self.assertIn("short words next", out)
        self.assertNotIn("ABCDEFGHIJKLMNOP", out)
        self.assertIn("host:pw~12@", util.scrub(b"host:pwA9b8c7d6e5@db"))

    def test_sha16(self):  # U-UTIL-3
        self.assertEqual(len(util.sha16(b"x")), 16)
        self.assertEqual(util.sha16(b"x"), util.sha16("x"))

    def test_entropy(self):  # U-UTIL-4
        self.assertEqual(util.entropy(b"aaaa"), 0.0)
        self.assertAlmostEqual(util.entropy(bytes(range(16))), 4.0)

    def test_display_path(self):  # U-UTIL-5
        self.assertEqual(util.display_path("/home/u/.claude/x", "/home/u", None), "~/.claude/x")
        self.assertEqual(util.display_path("/mnt/c/Users/u/.claude/x", "/home/u", "/mnt/c/Users/u"),
                         "C:\\Users\\u\\.claude\\x")
        self.assertEqual(util.display_path("/opt/x", "/home/u", None), "/opt/x")

    def test_write_json_atomic_and_private(self):  # U-UTIL-6
        p = os.path.join(self.tmp, "a.json")
        util.write_json(p, {"a": 1})
        self.assertFalse(os.path.exists(p + ".part"))
        self.assertEqual(util.read_json(p), {"a": 1})
        if not WINDOWS:  # NTFS has no POSIX mode bits; privacy there comes from the profile's ACL
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_walker_depth_skip_deadline(self):  # U-UTIL-7
        for rel in ("a/b/c/d/deep.txt", "node_modules/x.txt", "OneDrive - Corp/y.txt", "keep/z.txt"):
            write(os.path.join(self.tmp, rel), "x")
        seen = [os.path.relpath(os.path.join(dp, f), self.tmp)
                for dp, _, fns in util.Walker(self.tmp, 2, time.monotonic() + 30) for f in fns]
        self.assertIn(os.path.join("keep", "z.txt"), seen)
        self.assertNotIn(os.path.join("node_modules", "x.txt"), seen)
        self.assertFalse(any(s.startswith("OneDrive") for s in seen))
        self.assertFalse(any(s.endswith("deep.txt") for s in seen))
        w = util.Walker(self.tmp, 5, time.monotonic() - 1)
        self.assertEqual(list(w), [])
        self.assertTrue(w.truncated)
