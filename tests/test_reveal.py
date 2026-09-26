"""Open it: showing a reported file in the file manager.

The page names a finding and an index; everything else is decided here. These tests hold the lines that make that
safe: only a file the scan reported, only one on this machine, only ever the file manager, and on Linux only ever a
folder (xdg-open on a file would launch whatever handles it).
"""
import os

from afterprompt import reveal
from tests.helpers import TempDirTest, write

H = "0123456789abcdef"


class RevealTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        write(os.path.join(self.home, ".claude", "s1.jsonl"), "x")
        self.calls = []

    def findings(self, *locs, kind="linux", host_side="linux"):
        return {"platform": {"kind": kind},
                "environments": [{"kind": "host", "side": host_side}],
                "rotate": [{"hash": H, "locations": list(locs)}], "review": []}

    def run_(self, argv, **kw):
        self.calls.append(argv)

    def go(self, data, index=0, plat="linux", which=lambda n: "/usr/bin/" + n, env=None):
        return reveal.reveal(data, H, index, plat=plat, home=self.home, run=self.run_, which=which, env=env or {})

    def test_linux_opens_the_folder_never_the_file(self):
        ok, why = self.go(self.findings({"display": "~/.claude/s1.jsonl", "side": "linux"}))
        self.assertEqual((ok, why), (True, None))
        self.assertEqual(self.calls, [["/usr/bin/xdg-open", os.path.join(self.home, ".claude")]])

    def test_macos_and_windows_select_without_opening(self):
        path = os.path.join(self.home, ".claude", "s1.jsonl")
        self.assertEqual(reveal.command(path, "macos"), ["open", "-R", path])
        self.assertEqual(reveal.command("C:\\Users\\me\\a.db", "windows"), ["explorer.exe", "/select,C:\\Users\\me\\a.db"])

    def test_wsl_hands_explorer_a_windows_path_for_either_side(self):
        which = lambda n: "/mnt/c/Windows/explorer.exe"
        self.assertEqual(reveal.command("/mnt/c/Users/me/a.db", "wsl", which),
                         ["/mnt/c/Windows/explorer.exe", "/select,C:\\Users\\me\\a.db"])
        self.assertEqual(reveal.command("/home/me/a.jsonl", "wsl", which, env={"WSL_DISTRO_NAME": "Ubuntu"}),
                         ["/mnt/c/Windows/explorer.exe", "/select,\\\\wsl.localhost\\Ubuntu\\home\\me\\a.jsonl"])

    def test_wsl_finds_explorer_when_windows_is_not_on_path(self):
        """appendWindowsPath=false leaves explorer.exe off PATH but still runnable where Windows is mounted."""
        mount = os.path.join(self.tmp, "mnt") + os.sep
        write(os.path.join(mount, "c", "Windows", "explorer.exe"), "")
        argv = reveal.command("/mnt/c/Users/me/a.db", "wsl", which=lambda n: None, mount=mount)
        self.assertEqual(argv, [os.path.join(mount, "c", "Windows", "explorer.exe"), "/select,C:\\Users\\me\\a.db"])
        self.assertIsNone(reveal.command("/mnt/c/Users/me/a.db", "wsl", which=lambda n: None,
                                         mount=os.path.join(self.tmp, "none") + os.sep))

    def test_the_label_is_not_part_of_the_path(self):
        self.assertEqual(reveal.strip_label("C:\\x\\state.vscdb (chat database)"), "C:\\x\\state.vscdb")
        self.assertEqual(reveal.strip_label("~/a.jsonl"), "~/a.jsonl")

    def test_refuses_what_is_not_a_file_here(self):
        cases = [({"display": "~/.claude/s1.jsonl", "side": "docker:api"}, "another environment"),
                 ({"display": "~/.claude/s1.jsonl", "side": "linux", "decoded": True}, "decoded"),
                 ({"display": "Cursor chat, 2026-04-15", "side": ""}, "conversation"),
                 ({"display": "~/.claude/gone.jsonl", "side": "linux"}, "no longer there")]
        for loc, reason in cases:
            with self.subTest(reason=reason):
                ok, why = self.go(self.findings(loc))
                self.assertFalse(ok)
                self.assertIn(reason, why)
        self.assertEqual(self.calls, [])

    def test_refuses_an_unknown_finding_or_index(self):
        data = self.findings({"display": "~/.claude/s1.jsonl", "side": "linux"})
        for index in (1, -1, "0", None, True, 0.0):
            with self.subTest(index=index):
                self.assertEqual(self.go(data, index=index), (False, "no such location"))
        self.assertEqual(reveal.reveal(data, "f" * 16, 0, plat="linux", home=self.home, run=self.run_),
                         (False, "no such location"))
        self.assertEqual(self.calls, [])

    def test_no_file_manager_is_said_not_crashed(self):
        ok, why = self.go(self.findings({"display": "~/.claude/s1.jsonl", "side": "linux"}), which=lambda n: None)
        self.assertEqual((ok, why), (False, "no file manager found on this machine"))

    def test_wsl_reaches_its_own_side_and_windows_only(self):
        data = self.findings(kind="wsl", host_side="wsl:Ubuntu")
        self.assertEqual(reveal.local_sides(data), {"wsl", "wsl:Ubuntu", "windows"})
        self.assertEqual(reveal.local_sides(self.findings()), {"linux"})

    def test_openable_lists_only_what_would_work(self):
        data = self.findings({"display": "~/.claude/s1.jsonl", "side": "linux"},
                             {"display": "~/x.jsonl", "side": "docker:api"},
                             {"display": "~/y.jsonl", "side": "linux", "decoded": True})
        self.assertEqual(reveal.openable(data, plat="linux", home=self.home), {H: [0]})
