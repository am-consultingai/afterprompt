import os
import unittest

from afterprompt import manifest
from tests.helpers import TempDirTest, make_cfg, write


class ManifestTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        self.claude = os.path.join(self.home, ".claude")
        self.selfdir = os.path.join(self.claude, "projects", "-self")
        sid = "0e8f9a52-1111-4222-8333-944455556666"
        write(os.path.join(self.claude, "projects", "-app", "s.jsonl"), "a")
        write(os.path.join(self.claude, "plugins", "p", "node_modules", "x.js"), "b")
        write(os.path.join(self.selfdir, sid + ".jsonl"), "c")
        write(os.path.join(self.claude, "file-history", sid, "f.txt"), "d")
        write(os.path.join(self.claude, "projects", "-app", "skip-me.jsonl"), "e")
        write(os.path.join(self.home, "proj", ".claude", "settings.json"), "f")
        self.sources = {"roots": [{"path": self.claude, "tool": "Claude Code", "side": "linux", "kind": "dir"},
                                  {"path": os.path.join(self.home, "proj", ".claude"), "tool": "Cursor",
                                   "side": "linux", "kind": "dir"}],
                        "self_exclude": [self.selfdir]}

    def rows(self, **kw):
        cfg = make_cfg(self.tmp, "linux", self.home, **kw)
        stats = manifest.build(cfg, self.sources)
        return {os.path.relpath(r.path, self.home): r for r in manifest.load(cfg)}, stats

    def test_flags(self):  # U-MAN-1
        rows, stats = self.rows()
        self.assertTrue(rows[".claude/plugins/p/node_modules/x.js"].vendored)
        self.assertTrue(rows[".claude/projects/-self/0e8f9a52-1111-4222-8333-944455556666.jsonl"].self)
        self.assertTrue(rows[".claude/file-history/0e8f9a52-1111-4222-8333-944455556666/f.txt"].self)
        self.assertFalse(rows[".claude/projects/-app/s.jsonl"].self)
        self.assertEqual(rows["proj/.claude/settings.json"].tool, "Cursor")

    def test_excludes(self):  # U-MAN-2
        rows, stats = self.rows(excludes=[r"skip-me\.jsonl$"])
        self.assertNotIn(".claude/projects/-app/skip-me.jsonl", rows)
        self.assertEqual(stats["excluded"], 1)

    def test_symlink_oddname_unreadable(self):  # U-MAN-3
        os.symlink(os.path.join(self.claude, "projects", "-app", "s.jsonl"), os.path.join(self.claude, "link.jsonl"))
        write(os.path.join(self.claude, "odd\tname.txt"), "x")
        locked = write(os.path.join(self.claude, "locked.txt"), "x")
        os.chmod(locked, 0)
        rows, stats = self.rows()
        self.assertNotIn(".claude/link.jsonl", rows)
        self.assertEqual(stats["odd_names"], 1)
        if not (hasattr(os, "geteuid") and os.geteuid() == 0):
            self.assertEqual(stats["unreadable"], 1)
