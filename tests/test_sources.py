import json
import os
from unittest import mock

from afterprompt import sources
from tests.helpers import REPO, TempDirTest, cursor_db, make_cfg, requires_posix, write


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
        self.assertEqual(len(out["databases"]), 2)
        self.assertTrue(all(d["side"] == "macos" for d in out["databases"]))
        paths = root_paths(out)
        self.assertIn((os.path.join(self.home, "Library", "Caches", "claude-cli-nodejs"), "Claude Code", "macos"), paths)
        self.assertIsNone(out["windows_home"])

    def test_linux_layout(self):  # U-SRC-2
        cursor_db(os.path.join(self.home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), [])
        os.makedirs(os.path.join(self.home, ".cache", "claude-cli-nodejs"))
        out = discover(make_cfg(self.tmp, "linux", self.home))
        self.assertEqual([d["side"] for d in out["databases"]], ["linux"])
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
        self.assertEqual(out["databases"][0]["side"], "windows")
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

    @requires_posix  # asserts unix-style absolute project keys in .claude.json
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
        self.assertEqual(out["windows_home_source"], "left out of this scan")
        self.assertTrue(any(m["path"].endswith(".claude") for m in out["missing"]))

    def test_extra_roots(self):  # U-SRC-8
        extra = os.path.join(self.tmp, "notes")
        write(os.path.join(extra, "a.txt"), "x")
        out = discover(make_cfg(self.tmp, "linux", self.home, extra_roots=[extra]))
        self.assertIn((extra, "Extra", "linux"), root_paths(out))


class NativeWindowsTests(TempDirTest):
    """W3: on Windows the machine's own profile is the 'windows' side, with no WSL bridge involved."""

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "Users", "me")
        os.makedirs(self.home)

    def layout(self):
        """The locations a Windows machine actually uses."""
        self.cursor_user = os.path.join(self.home, "AppData", "Roaming", "Cursor", "User")
        cursor_db(os.path.join(self.cursor_user, "globalStorage", "state.vscdb"), [])
        cursor_db(os.path.join(self.cursor_user, "workspaceStorage", "w1", "state.vscdb"), [])
        self.cli_cache = os.path.join(self.home, "AppData", "Local", "claude-cli-nodejs")
        write(os.path.join(self.cli_cache, "log.txt"), "cache\n")
        os.makedirs(os.path.join(self.home, ".claude"))
        write(os.path.join(self.home, ".claude.json"), json.dumps({"projects": {}}))
        write(os.path.join(self.home, ".cursor", "mcp.json"), json.dumps({"mcpServers": {}}))

    def test_windows_locations_are_found(self):  # U-SRC-W1 (W3)
        self.layout()
        out = discover(make_cfg(self.tmp, "windows", self.home))
        self.assertEqual(out["platform"], "windows")
        # The profile is this machine, not a bridged one.
        self.assertEqual(out["windows_home"], self.home)
        self.assertEqual(out["windows_home_source"], "this machine")
        self.assertEqual(len(out["databases"]), 2)
        self.assertTrue(all(d["side"] == "windows" for d in out["databases"]))
        paths = root_paths(out)
        self.assertIn((self.cli_cache, "Claude Code", "windows"), paths)
        self.assertIn((os.path.join(self.home, ".claude"), "Claude Code", "windows"), paths)
        self.assertIn((os.path.join(self.home, ".cursor", "mcp.json"), "Cursor", "windows"), paths)

    def test_mislabelled_as_linux_misses_appdata(self):  # U-SRC-W2 (W3)
        """The regression this epic exists for: before W2/W3 a native Windows run reported 'linux',
        which skipped every AppData location while still producing a confident report."""
        self.layout()
        as_linux = discover(make_cfg(self.tmp, "linux", self.home))
        linux_paths = {p for p, _, _ in root_paths(as_linux)}
        self.assertNotIn(self.cli_cache, linux_paths)
        self.assertEqual(len(as_linux["databases"]), 0)  # AppData\Roaming\Cursor is invisible to a linux run

        as_windows = discover(make_cfg(self.tmp, "windows", self.home))
        self.assertIn(self.cli_cache, {p for p, _, _ in root_paths(as_windows)})
        self.assertEqual(len(as_windows["databases"]), 2)

    def test_windows_project_dirs_from_claude_json(self):  # U-SRC-W3 (W3)
        """Windows-shaped project paths must resolve natively, not through /mnt/c."""
        self.layout()
        app = os.path.join(self.tmp, "Users", "me", "code", "app")
        os.makedirs(os.path.join(app, ".claude"))
        drive_path = "C:\\Users\\me\\code\\app"
        with mock.patch.object(sources.platforms, "from_windows_path",
                               side_effect=lambda k, m=None, n=False: app if (k == drive_path and n) else None):
            write(os.path.join(self.home, ".claude.json"), json.dumps({"projects": {drive_path: {}}}))
            out = discover(make_cfg(self.tmp, "windows", self.home))
        self.assertIn(app, out["project_dirs"])
        self.assertIn((os.path.join(app, ".claude"), "Claude Code", "windows"), root_paths(out))

    def test_no_unix_side_on_windows(self):  # U-SRC-W4 (W3)
        """A .config/Cursor tree on a Windows profile is a Linux layout and must not be claimed."""
        self.layout()
        cursor_db(os.path.join(self.home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"), [])
        out = discover(make_cfg(self.tmp, "windows", self.home))
        self.assertEqual(len(out["databases"]), 2)
        self.assertTrue(all("AppData" in d["path"] for d in out["databases"]))
