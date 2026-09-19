"""X2–X5 / X11: which AI tools are installed, found without running anything, and reported when not covered."""
import os
import plistlib
import sys
import unittest
from unittest import mock

from afterprompt import catalogue, detect, merge, report
from tests.helpers import TempDirTest, write

TOOLS = [
    {"product": "Scanned CLI", "status": "scanned", "detect": {"bins": ["scli"], "home": [".scli"]}},
    {"product": "Chat App", "status": "planned", "note": "Encrypted store.",
     "detect": {"mac_bundles": ["com.example.chat"], "windows_apps": ["^Chat App\\b"], "linux_desktop": ["chat-app"],
                "home": ["AppData/Roaming/ChatApp"]}},
    {"product": "Editor Agent", "status": "planned", "note": "In the editor's storage.",
     "detect": {"vscode_extensions": ["acme.agent"]}},
    {"product": "Absent", "status": "planned", "note": "n/a", "detect": {"bins": ["absent-tool"], "home": [".absent"]}},
]


class DetectTests(TempDirTest):
    def probe(self, platform="linux", **kw):
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home, exist_ok=True)
        kw.setdefault("path_env", os.path.join(self.tmp, "bin"))
        kw.setdefault("apps", [])
        kw.setdefault("bundles", {})
        kw.setdefault("desktop_dirs", (os.path.join(self.tmp, "apps"),))
        return detect.Probe([self.home], platform, **kw)

    def found(self, probe):
        return {i["product"]: i for i in detect.installed([self.home], probe.platform, probe=probe, tools=TOOLS)}

    def test_nothing_installed(self):  # U-DET-1
        self.assertEqual(self.found(self.probe()), {})

    def test_binary_on_path_and_home_marker(self):  # U-DET-2
        p = self.probe()
        write(os.path.join(self.tmp, "bin", "scli"), "#!/bin/sh\n")
        got = self.found(p)["Scanned CLI"]
        self.assertEqual(got["status"], "scanned")
        self.assertIn("scli on PATH", got["evidence"][0])
        os.makedirs(os.path.join(self.home, ".scli"))
        self.assertEqual(len(self.found(p)["Scanned CLI"]["evidence"]), 2)

    def test_per_user_bin_folders(self):  # U-DET-3
        p = self.probe(path_env="")
        write(os.path.join(self.home, ".local", "bin", "scli"), "x")
        self.assertIn("Scanned CLI", self.found(p))

    def test_windows_program_names(self):  # U-DET-4
        p = self.probe("windows", apps=["Chat App 1.2.3", "Unrelated"], path_env="")
        write(os.path.join(self.tmp, "bin", "scli.exe"), "x")
        got = self.found(p)
        self.assertEqual(got["Chat App"]["status"], "planned")
        self.assertIn("“Chat App 1.2.3”", got["Chat App"]["evidence"][0])
        self.assertEqual(got["Chat App"]["note"], "Encrypted store.")
        p = self.probe("windows", apps=["Chat Application Suite"])
        self.assertNotIn("Chat App", self.found(p))                    # \b in the regex: no loose matches

    def test_windows_exe_suffix(self):  # U-DET-5
        write(os.path.join(self.tmp, "bin", "scli.exe"), "x")
        self.assertIn("Scanned CLI", self.found(self.probe("windows")))
        self.assertNotIn("Scanned CLI", self.found(self.probe("linux")))

    def test_mac_bundle_by_identifier(self):  # U-DET-6
        """By CFBundleIdentifier, because people rename the .app."""
        app = os.path.join(self.tmp, "home", "Applications", "Renamed.app", "Contents")
        os.makedirs(app)
        with open(os.path.join(app, "Info.plist"), "wb") as fh:
            plistlib.dump({"CFBundleIdentifier": "com.example.chat"}, fh)
        with open(os.path.join(os.path.dirname(app), "..", "Broken.app"), "w"):
            pass
        bundles = detect.mac_bundles([os.path.join(self.tmp, "home")])
        self.assertTrue(bundles["com.example.chat"].endswith("Renamed.app"))
        self.assertIn("Chat App", self.found(self.probe("macos", bundles=bundles)))

    def test_linux_desktop_entry(self):  # U-DET-7
        write(os.path.join(self.tmp, "apps", "chat-app.desktop"), "[Desktop Entry]\nName=Chat App\n")
        self.assertIn("Chat App", self.found(self.probe()))

    def test_extension_in_any_vs_code_family_editor(self):  # U-DET-8
        for ed in (".vscode/extensions", ".cursor/extensions", ".vscode-server/extensions"):
            with self.subTest(editor=ed):
                p = self.probe()
                d = os.path.join(self.home, *ed.split("/"), "acme.agent-1.4.0")
                os.makedirs(d)
                self.assertIn(ed, self.found(p)["Editor Agent"]["evidence"][0])
                os.rmdir(d)
        os.makedirs(os.path.join(self.home, ".vscode", "extensions", "acme.agentic-2.0"))
        self.assertNotIn("Editor Agent", self.found(self.probe()))       # a different extension id

    def test_never_runs_anything(self):  # U-DET-9
        write(os.path.join(self.tmp, "bin", "scli"), "x")
        with mock.patch("subprocess.run", side_effect=AssertionError("ran a program")), \
                mock.patch("subprocess.Popen", side_effect=AssertionError("ran a program")), \
                mock.patch("os.system", side_effect=AssertionError("ran a program")):
            self.assertIn("Scanned CLI", self.found(self.probe()))

    def test_evidence_is_capped(self):  # U-DET-10
        tool = {"product": "Many", "status": "planned", "note": "x", "detect": {"home": [f".m{i}" for i in range(6)]}}
        p = self.probe()
        for i in range(6):
            os.makedirs(os.path.join(self.home, f".m{i}"))
        got = detect.installed([self.home], "linux", probe=p, tools=[tool])
        self.assertEqual(len(got[0]["evidence"]), 3)

    @unittest.skipUnless(sys.platform == "win32", "Windows registry")
    def test_real_windows_registry(self):  # U-DET-11
        apps = detect.windows_apps()
        self.assertIsInstance(apps, list)
        self.assertTrue(all(isinstance(a, str) and a for a in apps))

    def test_shipped_catalogue_detects(self):  # U-DET-12
        """Every product can be detected, and every planned one explains why it is not scanned."""
        for t in catalogue.DATA["tools"]:
            with self.subTest(product=t["product"]):
                self.assertTrue(t.get("detect"), "no way to tell it is installed")
                if t["status"] == "planned":
                    self.assertTrue(t.get("note"))


class ReportTests(unittest.TestCase):
    def rows(self, installed, envs=None):
        cov = {"platform": "linux", "sources": [], "databases": {"total": 0, "ok": 0, "failed": []},
               "unreadable_files": 0, "excluded_files": 0, "vendored_files": 0, "scan_session_files": 0,
               "live_values": {}, "prompts": {}, "limits": [], "missing_locations": [], "pattern_truncations": [],
               "keychain": "not requested", "installed": installed}
        return dict(report.coverage_rows({"coverage": cov}))

    def test_uncovered_tools_are_named_with_the_reason(self):  # U-DET-13
        rows = self.rows([{"product": "Codex CLI", "status": "scanned"},
                          {"product": "Windsurf", "status": "planned", "note": "Conversations are encrypted."}])
        self.assertEqual(rows["AI tools found and scanned"], "Codex CLI")
        self.assertEqual(rows["Installed but NOT scanned"], "Windsurf: Conversations are encrypted.")

    def test_no_row_when_everything_found_is_covered(self):  # U-DET-14
        rows = self.rows([{"product": "Codex CLI", "status": "scanned"}])
        self.assertNotIn("Installed but NOT scanned", rows)
        self.assertNotIn("AI tools found and scanned", self.rows([]))

    def test_other_environments_are_named(self):  # U-DET-15
        host = {"coverage": {"installed": [{"product": "Cursor", "status": "scanned"}]}}
        cov = merge.merge_coverage(host["coverage"], [({"installed": [
            {"product": "Aider", "status": "planned", "note": "Not mapped."}]}, "wsl:Ubuntu", "Ubuntu")])
        rows = self.rows(cov["installed"])
        self.assertEqual(rows["Installed but NOT scanned"], "Aider [Ubuntu]: Not mapped.")


class SimulatedMachineTests(TempDirTest):
    def test_other_home_ignores_this_machine(self):  # U-DET-16
        home = os.path.join(self.tmp, "home")
        os.makedirs(home)
        p = detect.machine_probe([home], "windows", env={"AFTERPROMPT_HOME": home})
        self.assertEqual((p.path_env, p.apps, p.bundles, p.desktop_dirs), ("", [], {}, ()))
        real = detect.machine_probe([home], "linux", env={})
        self.assertEqual(real.path_env, os.environ.get("PATH", ""))
