import json
import os
from unittest import mock

from afterprompt import sources
from tests.helpers import REPO, TempDirTest, cursor_db, make_cfg, write


def discover(cfg):
    sources._WIN_CACHE.clear()
    with mock.patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        return sources.discover(cfg)


def root_paths(out):
    return {(r["path"], r["tool"], r["side"]) for r in out["roots"]}


class SourcesTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)

    def test_macos_layout(self):  # U-SRC-1
        cu = os.path.join(self.home, "Library", "Application Support", "Cursor", "User")
        cursor_db(os.path.join(cu, "globalStorage", "state.vscdb"), [])
        cursor_db(os.path.join(cu, "workspaceStorage", "w1", "state.vscdb"), [])
        os.makedirs(os.path.join(self.home, "Library", "Caches", "claude-cli-nodejs"))
        os.makedirs(os.path.join(self.home, ".claude"))
        out = discover(make_cfg(self.tmp, "macos", self.home))
        self.assertEqual(len(out["cursor_dbs"]), 2)
        self.assertTrue(all(d["side"] == "macos" for d in out["cursor_dbs"]))
        paths = root_paths(out)
        self.assertIn((os.path.join(self.home, "Library", "Caches", "claude-cli-nodejs"), "Claude Code", "macos"), paths)
        self.assertIsNone(out["windows_home"])

    def test_linux_layout(self):  # U-SRC-2
        cursor_db(os.path.join(self.home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), [])
        os.makedirs(os.path.join(self.home, ".cache", "claude-cli-nodejs"))
        out = discover(make_cfg(self.tmp, "linux", self.home))
        self.assertEqual([d["side"] for d in out["cursor_dbs"]], ["linux"])
        self.assertIn((os.path.join(self.home, ".cache", "claude-cli-nodejs"), "Claude Code", "linux"),
                      root_paths(out))
        self.assertFalse(any(r["side"] == "windows" for r in out["roots"]))

    def test_wsl_layout(self):  # U-SRC-3
        win = os.path.join(self.tmp, "Users", "me")
        os.makedirs(os.path.join(win, ".claude", "projects"))
        write(os.path.join(win, ".claude.json"), "{}")
        cursor_db(os.path.join(win, "AppData", "Roaming", "Cursor", "User", "globalStorage", "state.vscdb"), [])
        os.makedirs(os.path.join(self.home, ".claude"))
        out = discover(make_cfg(self.tmp, "wsl", self.home, windows_home=win))
        paths = root_paths(out)
        self.assertIn((os.path.join(win, ".claude"), "Claude Code", "windows"), paths)
        self.assertIn((os.path.join(self.home, ".claude"), "Claude Code", "wsl"), paths)
        self.assertEqual(out["cursor_dbs"][0]["side"], "windows")
        self.assertEqual(out["windows_home_source"], "--windows-home")

    def test_claude_config_dir(self):  # U-SRC-4
        alt = os.path.join(self.tmp, "altclaude")
        os.makedirs(alt)
        os.makedirs(os.path.join(self.home, ".claude"))
        sources._WIN_CACHE.clear()
        with mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": alt}):
            out = sources.discover(make_cfg(self.tmp, "linux", self.home))
        paths = {r["path"] for r in out["roots"]}
        self.assertIn(alt, paths)

    def test_project_dirs(self):  # U-SRC-5
        a = os.path.join(self.tmp, "work", "a")
        b = os.path.join(self.tmp, "work", "b")
        os.makedirs(os.path.join(a, ".claude"))
        write(os.path.join(b, ".mcp.json"), "{}")
        write(os.path.join(self.home, ".claude.json"), json.dumps({"projects": {a: {}, "/does/not/exist": {}}}))
        write(os.path.join(self.home, ".config", "Cursor", "User", "workspaceStorage", "x", "workspace.json"),
              json.dumps({"folder": "file://" + b}))
        out = discover(make_cfg(self.tmp, "linux", self.home))
        self.assertEqual(out["project_dirs"], [a, b])
        paths = {r["path"] for r in out["roots"]}
        self.assertIn(os.path.join(a, ".claude"), paths)
        self.assertIn(os.path.join(b, ".mcp.json"), paths)

    def test_windows_project_keys(self):  # U-SRC-5 (Windows keys)
        from afterprompt import platforms
        win = os.path.join(self.tmp, "Users", "me")
        os.makedirs(win)
        with mock.patch.object(platforms, "automount_root", return_value="/mnt/"):
            dirs = sources.project_dirs(make_cfg(self.tmp, "wsl", self.home, windows_home=win),
                                        {"unix": self.home, "windows": win})
        self.assertEqual(dirs, [])  # C:\ paths translate to /mnt/c/..., which does not exist here

    def test_self_exclusion(self):  # U-SRC-6
        from afterprompt.platforms import claude_project_dirname
        proj = os.path.join(self.home, ".claude", "projects")
        mine = os.path.join(proj, claude_project_dirname(REPO))
        sub = os.path.join(proj, claude_project_dirname(REPO) + "-tests")
        other = os.path.join(proj, "-home-u-other")
        for d in (mine, sub, other):
            os.makedirs(d)
        cfg = make_cfg(self.tmp, "linux", self.home, extra_roots=[REPO])
        out = discover(cfg)
        self.assertEqual(sorted(out["self_exclude"]), sorted([mine, sub]))
        self.assertNotIn(REPO, {r["path"] for r in out["roots"]})

    def test_missing_and_windows_none(self):  # U-SRC-7
        out = discover(make_cfg(self.tmp, "wsl", self.home, windows_home="none"))
        self.assertIsNone(out["windows_home"])
        self.assertEqual(out["windows_home_source"], "disabled")
        self.assertTrue(any(m["path"].endswith(".claude") for m in out["missing"]))

    def test_extra_roots(self):  # U-SRC-8
        extra = os.path.join(self.tmp, "notes")
        write(os.path.join(extra, "a.txt"), "x")
        out = discover(make_cfg(self.tmp, "linux", self.home, extra_roots=[extra]))
        self.assertIn((extra, "Extra", "linux"), root_paths(out))
