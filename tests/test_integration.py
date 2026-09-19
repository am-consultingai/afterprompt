"""End-to-end runs of afterprompt.sh on generated fixture machines (test plan §11.4)."""
import json
import os
import stat
import unittest

from tests.helpers import Fixture, TempDirTest, requires_posix, requires_rg, run_dirs


def summary(findings):
    rotate = {r["masked"]: r for r in findings["rotate"]}
    review = {r["masked"]: r for r in findings["review"]}
    return rotate, review


@requires_rg
class IntegrationTests(TempDirTest):
    def scan(self, fx, *args, expect=None, **env):
        p = fx.run(*args, env=fx.env(**env) if env else None)
        out = p.stdout.decode("utf-8", "replace")
        err = p.stderr.decode("utf-8", "replace")
        if expect is not None:
            self.assertEqual(p.returncode, expect, out + err)
        return p, out, err

    def test_wsl_quick(self):  # I-1
        fx = Fixture(self.tmp, "wsl")
        self.scan(fx, expect=10)
        d = fx.findings()
        rotate, review = summary(d)
        self.assertEqual(set(rotate), {fx.masked(k) for k in ("F1", "F2", "F3", "F12")})
        self.assertEqual(rotate[fx.masked("F1")]["category"], "live_credential")
        self.assertEqual(rotate[fx.masked("F1")]["still_on_disk"][0]["key"], "ANTHROPIC_API_KEY")
        self.assertEqual(rotate[fx.masked("F2")]["tools"], ["Cursor"])
        self.assertEqual(rotate[fx.masked("F2")]["sides"], ["windows"])
        self.assertEqual(rotate[fx.masked("F3")]["sides"], ["windows"])
        self.assertEqual(review[fx.masked("F11")]["category"], "configuration")
        self.assertIn(fx.masked("F10"), review)
        shown = set(rotate) | set(review)
        for k in ("F4", "F5", "F6", "F7", "F8", "F9", "F13", "F14", "F16", "F17"):
            self.assertNotIn(fx.masked(k), shown, k)
        for reason in ("placeholder or environment reference", "vendored app or plugin code only", "expired token",
                       "local development connection string", "scan-session transcripts only",
                       "the tool's own credential store"):
            self.assertIn(reason, d["dismissed"])
        self.assertEqual(d["coverage"]["cursor_databases"]["ok"], 1)

    def test_wsl_deep(self):  # I-2
        fx = Fixture(self.tmp, "wsl")
        self.scan(fx, "--deep", expect=10)
        rotate, _ = summary(fx.findings())
        self.assertIn(fx.masked("F4"), rotate)
        self.assertTrue(all(l["decoded"] for l in rotate[fx.masked("F4")]["locations"]))
        self.assertIn("decode", fx.findings()["coverage"])

    @requires_posix  # macOS-only behaviour
    def test_macos_spawn_and_keychain(self):  # I-3
        fx = Fixture(self.tmp, "macos")
        tok = "sk-ant-oat01-" + fx.f.chars("u", 90)
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir)
        with open(os.path.join(bindir, "security"), "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\necho '" + json.dumps({"claudeAiOauth": {"accessToken": tok}}) + "'\n")
        os.chmod(os.path.join(bindir, "security"), stat.S_IRWXU)
        with open(os.path.join(fx.home, ".cursor", "plans", "leak.md"), "w", encoding="utf-8") as fh:
            fh.write(f"token: {tok}\n")
        self.scan(fx, expect=10)
        rotate, _ = summary(fx.findings())
        self.assertIn(fx.masked("F2"), rotate)
        self.assertEqual(fx.findings()["coverage"]["keychain"], "not requested")
        self.scan(fx, "--include-keychain", "--fresh", expect=10, PATH=bindir + os.pathsep + os.environ["PATH"])
        d = fx.findings()
        rotate, _ = summary(d)
        from afterprompt.util import mask
        self.assertEqual(rotate[mask(tok)]["category"], "live_credential")
        self.assertEqual(d["coverage"]["keychain"], "included")

    def test_linux_quick(self):  # I-4
        fx = Fixture(self.tmp, "linux")
        self.scan(fx, expect=10)
        d = fx.findings()
        rotate, _ = summary(d)
        self.assertIn(fx.masked("F1"), rotate)
        self.assertFalse(any(s["side"] == "windows" for s in d["coverage"]["sources"]))

    def test_privacy(self):  # I-5
        fx = Fixture(self.tmp, "wsl")
        _, out, err = self.scan(fx, "--deep", expect=10)
        secrets = [v.encode() for v in fx.s.values()]
        for text in (out, err):
            for v in fx.s.values():
                self.assertNotIn(v, text)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        self.assertFalse(os.path.exists(os.path.join(run, "work")))
        for dp, _, fns in os.walk(run):
            for fn in fns:
                with open(os.path.join(dp, fn), "rb") as fh:
                    data = fh.read()
                for v in secrets:
                    self.assertNotIn(v, data, f"{fn} contains a planted secret")
        self.scan(fx, "--deep", "--keep-work", "--fresh", expect=10)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        work = os.path.join(run, "work")
        self.assertTrue(os.path.isdir(work))
        for dp, _, fns in os.walk(work):
            if os.sep + "store" in dp or os.sep + "extracted" in dp:
                continue
            for fn in fns:
                if fn.endswith((".json", ".jsonl", ".tsv", ".done")):
                    with open(os.path.join(dp, fn), "rb") as fh:
                        data = fh.read()
                    for v in secrets:
                        self.assertNotIn(v, data, f"{fn} contains a planted secret")

    @requires_posix  # asserts POSIX 0700/0600 modes; NTFS uses ACLs
    def test_permissions(self):  # I-6
        fx = Fixture(self.tmp, "linux")
        self.scan(fx, expect=10)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        self.assertEqual(stat.S_IMODE(os.stat(fx.base).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(run).st_mode), 0o700)
        for name in ("report.html", "report.md", "findings.json"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(run, name)).st_mode), 0o600)

    def test_resume(self):  # I-7
        fx = Fixture(self.tmp, "wsl")
        _, out, _ = self.scan(fx, expect=130, AFTERPROMPT_STOP_AFTER="vendor_raw")
        self.assertTrue(os.path.exists(os.path.join(fx.base, "current")))
        p = fx.run("--status")
        status = p.stdout.decode()
        self.assertIn("done  Matching 140 credential patterns", status)
        self.assertNotIn("done  Checking your live credentials", status)
        _, out, _ = self.scan(fx, expect=10)
        self.assertIn("Resuming the scan", out)
        self.assertIn("already done", out)
        self.assertEqual(len(run_dirs(fx.base)), 1)
        rotate, _ = summary(fx.findings())
        self.assertEqual(set(rotate), {fx.masked(k) for k in ("F1", "F2", "F3", "F12")})
        self.assertFalse(os.path.exists(os.path.join(fx.base, "current")))

    def test_discard(self):  # I-8
        fx = Fixture(self.tmp, "linux")
        self.scan(fx, expect=130, AFTERPROMPT_STOP_AFTER="manifest")
        _, out, _ = self.scan(fx, "--deep", expect=130, AFTERPROMPT_STOP_AFTER="manifest")
        self.assertIn("different options", out)
        self.assertEqual(len(run_dirs(fx.base)), 1)
        with open(os.path.join(fx.base, "runs", run_dirs(fx.base)[0], "run.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["mode"], "deep")
        _, out, _ = self.scan(fx, "--deep", "--fresh", expect=10)
        self.assertIn("(--fresh)", out)
        self.assertEqual(len(run_dirs(fx.base)), 1)

    def test_extra_exclude_out(self):  # I-9
        fx = Fixture(self.tmp, "wsl")
        out_dir = os.path.join(self.tmp, "myreport")
        self.scan(fx, "--extra-root", fx.extra, "--exclude", r"excluded\.jsonl$", "--out", out_dir, expect=10)
        rotate, _ = summary(fx.findings(out_dir))
        self.assertIn(fx.masked("F13"), rotate)
        self.assertEqual(rotate[fx.masked("F13")]["tools"], ["Extra"])
        self.assertNotIn(fx.masked("F12"), rotate)
        self.assertTrue(os.path.exists(os.path.join(out_dir, "report.html")))

    def test_disk_cap(self):  # I-10
        fx = Fixture(self.tmp, "linux")
        self.scan(fx, "--deep", "--max-disk", "0.000000001", expect=10)
        self.assertTrue(fx.findings()["coverage"]["decode"]["disk_cap_reached"])

    def test_clean_machine(self):  # I-11
        fx = Fixture(self.tmp, "linux", clean=True)
        _, out, _ = self.scan(fx, expect=0)
        self.assertIn("Rotate now: 0", out)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        with open(os.path.join(run, "report.html"), encoding="utf-8") as fh:
            self.assertIn("Nothing to rotate", fh.read())

    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0, "root can read mode-000 files")
    @requires_posix  # chmod 000 does not deny the owner on Windows
    def test_unreadable_cursor_db(self):  # I-12
        fx = Fixture(self.tmp, "linux")
        db = os.path.join(fx.home, ".config", "Cursor", "User", "globalStorage", "state.vscdb")
        os.chmod(db, 0)
        self.scan(fx, expect=10)
        cov = fx.findings()["coverage"]["cursor_databases"]
        self.assertEqual(len(cov["failed"]), 1)


@requires_rg
class WindowsNativeIntegrationTests(TempDirTest):
    """W3/W6: a full scan of a Windows-shaped machine, with no WSL bridge in play.

    The fixture is generated, so this runs anywhere — and on a real Windows host it also
    exercises afterprompt.ps1 as the launcher.
    """

    def scan(self, fx, *args, expect=None, **env):
        p = fx.run(*args, env=fx.env(**env) if env else None)
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        if expect is not None:
            self.assertEqual(p.returncode, expect, out)
        return p, out

    def test_windows_quick(self):  # I-WIN-1 (W3)
        fx = Fixture(self.tmp, "windows")
        self.scan(fx, expect=10)
        d = fx.findings()
        self.assertEqual(d["platform"]["kind"], "windows")

        rotate, review = summary(d)
        # The key pasted into a transcript and still live in .env
        self.assertIn(fx.masked("F1"), rotate)
        self.assertEqual(rotate[fx.masked("F1")]["still_on_disk"][0]["key"], "ANTHROPIC_API_KEY")
        # The password that only appears in AppData\Local\claude-cli-nodejs and .cursor\plans —
        # locations a run mislabelled as "linux" never looks at.
        self.assertIn(fx.masked("F3"), rotate)
        # The token in Cursor's AppData\Roaming database
        self.assertIn(fx.masked("F2"), rotate)
        self.assertEqual(rotate[fx.masked("F2")]["tools"], ["Cursor"])
        self.assertEqual(d["coverage"]["cursor_databases"]["ok"], 1)

        # Every side reported is the Windows one; nothing claims a unix side.
        for r in list(rotate.values()) + list(review.values()):
            self.assertEqual(set(r["sides"]), {"windows"}, r["masked"])

    def test_windows_findings_have_windows_paths(self):  # I-WIN-2 (W3)
        fx = Fixture(self.tmp, "windows")
        self.scan(fx, expect=10)
        d = fx.findings()
        rotate, _ = summary(d)
        displays = [loc["display"] for r in rotate.values() for loc in r["locations"]]
        self.assertTrue(displays)
        # Locations are shown relative to the profile, never through a /mnt/c bridge path.
        self.assertFalse([p for p in displays if p.startswith("/mnt/")], displays)
