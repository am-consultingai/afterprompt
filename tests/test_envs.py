"""M4 / W8: environment discovery and the workers that scan each environment."""
import io
import os
import shutil
import subprocess
import sys
import tarfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest import mock

from afterprompt import __version__, envs, worker
from tests.helpers import REPO, TempDirTest, make_cfg, requires_posix, write

Env = envs.Environment


def fake_cfg(platform="windows", **kw):
    d = dict(platform=platform, worker=False, install_dir=REPO, rg="rg", home="/home/me")
    d.update(kw)
    return SimpleNamespace(**d)


class DiscoveryTests(TempDirTest):
    def test_host_names(self):  # U-ENV-1
        self.assertEqual(envs.host(fake_cfg("windows"), env={}).label, "Windows (this machine)")
        self.assertEqual(envs.host(fake_cfg("windows"), env={}).side, "windows")
        self.assertEqual(envs.host(fake_cfg("macos"), env={}).side, "macos")
        h = envs.host(fake_cfg("wsl"), env={"WSL_DISTRO_NAME": "Ubuntu"})
        self.assertEqual((h.name, h.kind, h.label, h.side), ("Ubuntu", "host", "WSL: Ubuntu (this machine)",
                                                             "wsl:Ubuntu"))
        self.assertEqual(envs.host(fake_cfg("wsl"), env={}).side, "wsl")

    def test_host_is_always_first_and_alone_by_default(self):  # U-ENV-2
        """Zero extra environments is the normal case, not a degraded run."""
        found = envs.discover(fake_cfg("linux"), providers=[lambda c: []])
        self.assertEqual([e.kind for e in found], ["host"])

    def test_providers_are_pluggable_and_deduplicated(self):  # U-ENV-3
        a = lambda c: [Env("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu")]  # noqa: E731
        b = lambda c: [Env("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu"), Env("Box", "folder", "Box", "env:Box")]  # noqa: E731
        found = envs.discover(fake_cfg("windows"), providers=[a, b])
        self.assertEqual([e.name for e in found], ["Windows", "Ubuntu", "Box"])

    def test_broken_provider_does_not_stop_the_scan(self):  # U-ENV-4
        def boom(cfg):
            raise OSError("wsl.exe hung")
        found = envs.discover(fake_cfg("windows"), providers=[boom, lambda c: [Env("B", "folder", "B", "env:B")]])
        self.assertEqual([e.name for e in found], ["Windows", "B"])

    def test_worker_never_discovers(self):  # U-ENV-5
        called = []
        found = envs.discover(fake_cfg("windows", worker=True), providers=[lambda c: called.append(1) or []])
        self.assertEqual(len(found), 1)
        self.assertEqual(called, [])

    def test_wsl_provider(self):  # U-ENV-6
        distros = lambda: ["Ubuntu", "Debian"]  # noqa: E731
        got = envs.wsl_provider(fake_cfg("windows"), env={}, distros=distros)
        self.assertEqual([(e.name, e.kind, e.label, e.side) for e in got],
                         [("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu"), ("Debian", "wsl", "WSL: Debian", "wsl:Debian")])
        # Inside WSL the distro we run in is the host, not another environment.
        got = envs.wsl_provider(fake_cfg("wsl"), env={"WSL_DISTRO_NAME": "Ubuntu"}, distros=distros)
        self.assertEqual([e.name for e in got], ["Debian"])
        for plat in ("linux", "macos"):
            self.assertEqual(envs.wsl_provider(fake_cfg(plat), env={}, distros=distros), [])

    def test_wsl_provider_ignores_simulated_machines(self):  # U-ENV-7
        """A fixture home or a forced platform is some other machine: this machine's distros are not its own."""
        distros = lambda: ["Ubuntu"]  # noqa: E731
        for var in ("AFTERPROMPT_HOME", "AFTERPROMPT_PLATFORM"):
            with self.subTest(var=var):
                self.assertEqual(envs.wsl_provider(fake_cfg("windows"), env={var: "x"}, distros=distros), [])

    def test_folder_provider(self):  # U-ENV-8
        got = envs.folder_provider(None, env={"AFTERPROMPT_TEST_ENVS": f" Box = {self.tmp} ;bad;=x;y=; Two={self.tmp}"})
        self.assertEqual([(e.name, e.kind, e.side, e.home) for e in got],
                         [("Box", "folder", "env:Box", self.tmp), ("Two", "folder", "env:Two", self.tmp)])
        self.assertEqual(envs.folder_provider(None, env={}), [])

    def test_round_trip_and_slug(self):  # U-ENV-9
        e = Env("Ubuntu 22.04/x", "wsl", "WSL: Ubuntu", "wsl:Ubuntu")
        self.assertEqual(Env.from_dict(e.to_dict()), e)
        self.assertEqual(e.slug, "wsl-Ubuntu_22.04_x")

    def test_other_homes(self):  # U-ENV-10
        for parent, names in (("home", ["me", "alice", ".cache", "lost+found"]),
                              ("Users", ["me", "bob", "Public", "Default", "All Users", "Shared"])):
            root = os.path.join(self.tmp, parent)
            for n in names:
                os.makedirs(os.path.join(root, n))
            write(os.path.join(root, "notes.txt"), "a file, not a home")
        self.assertEqual(envs.other_homes(os.path.join(self.tmp, "home", "me")), ["alice"])
        self.assertEqual(envs.other_homes(os.path.join(self.tmp, "Users", "me") + os.sep), ["bob"])
        self.assertEqual(envs.other_homes(os.path.join(self.tmp, "home", "me", "sub")), [])
        self.assertEqual(envs.other_homes(""), [])
        self.assertEqual(envs.other_homes(os.path.join(self.tmp, "nohome", "me")), [])


class ResultStoreTests(TempDirTest):
    def test_save_load_and_final_states_only(self):  # U-ENV-11
        e = Env("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu")
        self.assertIsNone(envs.load_result(self.tmp, e))
        envs.save_result(self.tmp, envs.skipped(e, "--no-wsl was given"))
        self.assertEqual(envs.load_result(self.tmp, e)["status"], "skipped")
        envs.save_result(self.tmp, dict(envs.skipped(e, None), status="running"))
        self.assertIsNone(envs.load_result(self.tmp, e))

    def test_failure_reasons(self):  # U-ENV-12
        self.assertEqual(envs.failure_reason({"error": {"message": "disk full"}}), "disk full")
        self.assertIn("Python 3.9+ or ripgrep", envs.failure_reason({"exit": 3, "stderr_tail": "no python3"}))
        self.assertIn("no python3", envs.failure_reason({"exit": 3, "stderr_tail": "no python3"}))
        self.assertIn("could not be started there", envs.failure_reason({"exit": 127}))
        self.assertIn("could not be started", envs.failure_reason({"exit": None}))
        self.assertIn("exit code 5", envs.failure_reason({"exit": 5}))


class ShipTests(TempDirTest):
    def names(self, data):
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            return {m.name: m for m in tar.getmembers()}

    def test_engine_tar(self):  # U-ENV-13
        pyc = os.path.join(REPO, "afterprompt", "__pycache__")
        os.makedirs(pyc, exist_ok=True)
        m = self.names(envs.engine_tar(REPO))
        self.assertEqual(m["afterprompt.sh"].mode, 0o755)
        for need in ("afterprompt/__init__.py", "afterprompt/cli.py", "afterprompt/assets/brand.css"):
            self.assertIn(need, m)
        self.assertFalse(any("__pycache__" in n or n.endswith(".pyc") for n in m))
        self.assertFalse(any(n.startswith(("tests/", "site/", "docs/")) for n in m))
        self.assertTrue(all(x.uid == 0 and x.uname == "" for x in m.values()))

    @requires_posix
    def test_ship_and_run_for_real(self):  # U-ENV-14
        """The exact shell snippets used inside a distro: unpack the engine into $HOME and start the launcher."""
        home = os.path.join(self.tmp, "distro-home")
        os.makedirs(home)
        env = dict(os.environ, HOME=home)
        stale = os.path.join(home, ".afterprompt", "engine", "afterprompt", "stale.py")
        write(stale, "old code\n")
        for _ in range(2):  # shipping again replaces the engine cleanly
            r = subprocess.run(["sh", "-c", envs.SHIP], input=envs.engine_tar(REPO), env=env, capture_output=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(stale))
        self.assertEqual(oct(os.stat(os.path.join(home, ".afterprompt")).st_mode & 0o777), "0o700")
        r = subprocess.run(["sh", "-c", envs.RUN, "sh", "--version"], env=env, capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.decode().strip(), f"afterprompt {__version__}")

    def test_ship_command(self):  # U-ENV-15
        seen = {}

        def run(cmd, **kw):
            seen.update(cmd=cmd, input=kw.get("input"))
            return SimpleNamespace(returncode=0, stderr=b"")
        self.assertTrue(envs.ship("wsl.exe", "Ubuntu", REPO, run=run)["ok"])
        self.assertEqual(seen["cmd"][:6], ["wsl.exe", "-d", "Ubuntu", "-e", "sh", "-c"])
        self.assertIn("afterprompt.sh", self.names(seen["input"]))

        def fail(cmd, **kw):
            return SimpleNamespace(returncode=1, stderr="tar: not found\n".encode("utf-16-le"))
        res = envs.ship("wsl.exe", "Ubuntu", REPO, run=fail)
        self.assertFalse(res["ok"])
        self.assertIn("tar: not found", res["stderr_tail"])

        def boom(cmd, **kw):
            raise OSError("no such file")
        self.assertFalse(envs.ship("wsl.exe", "Ubuntu", REPO, run=boom)["ok"])

    def test_distro_home_unc(self):  # U-ENV-16
        ok = lambda cmd, **kw: SimpleNamespace(returncode=0, stdout=b"/home/me\n")  # noqa: E731
        self.assertEqual(envs.distro_home_unc("wsl.exe", "Ubuntu", run=ok), r"\\wsl.localhost\Ubuntu\home\me")
        for r in (SimpleNamespace(returncode=1, stdout=b"/home/me"), SimpleNamespace(returncode=0, stdout=b"")):
            self.assertIsNone(envs.distro_home_unc("wsl.exe", "Ubuntu", run=lambda cmd, _r=r, **kw: _r))

        def boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, 60)
        self.assertIsNone(envs.distro_home_unc("wsl.exe", "Ubuntu", run=boom))


class RunWorkerTests(TempDirTest):
    def script(self, body):
        path = write(os.path.join(self.tmp, "fake_worker.py"), textwrap.dedent(body))
        return [sys.executable, path]

    def test_protocol_and_plain_lines(self):  # U-ENV-17
        cmd = self.script(f"""
            import sys
            sys.path.insert(0, {REPO!r})
            from afterprompt import worker
            print("ripgrep not found; downloading…", flush=True)
            e = worker.Emitter()
            e("hello", version="x", platform="linux", other_homes=["bob"])
            e("say", text="[1/9] Finding AI tool data …")
            print("", flush=True)
            e("result", exit=10, findings={{"rotate": []}})
            sys.stderr.write("a warning\\n")
        """)
        said = []
        out = envs.run_worker(cmd, None, os.path.join(self.tmp, "err.log"), said.append)
        self.assertEqual(said, ["ripgrep not found; downloading…", "[1/9] Finding AI tool data …"])
        self.assertEqual(out["hello"]["other_homes"], ["bob"])
        self.assertEqual(out["result"]["exit"], 10)
        self.assertEqual(out["exit"], 0)
        self.assertEqual(out["stderr_tail"], "a warning")

    def test_crash_without_result(self):  # U-ENV-18
        cmd = self.script("""
            import sys
            sys.stderr.write("Traceback...\\nValueError: boom\\n")
            sys.exit(5)
        """)
        out = envs.run_worker(cmd, None, os.path.join(self.tmp, "err.log"), lambda m: None)
        self.assertIsNone(out["result"])
        self.assertEqual(out["exit"], 5)
        self.assertIn("ValueError: boom", envs.failure_reason(out))

    def test_missing_program(self):  # U-ENV-19
        out = envs.run_worker([os.path.join(self.tmp, "no-such-program")], None, os.path.join(self.tmp, "e.log"),
                              lambda m: None)
        self.assertIsNone(out["exit"])
        self.assertTrue(out["stderr_tail"])

    def test_local_env(self):  # U-ENV-20
        cfg = fake_cfg("windows", rg="/opt/rg")
        base = {"CLAUDE_CONFIG_DIR": "/host/claude", "AFTERPROMPT_TEST_ENVS": "x=y", "AFTERPROMPT_STOP_AFTER": "known",
                "AFTERPROMPT_WINDOWS_HOME": "C:/Users/me", "PYTHONPATH": "/elsewhere", "KEEP": "1"}
        e = Env("Box", "folder", "Box", "env:Box")
        env = envs.local_env(e, "/data/box", cfg, self.tmp, base_env=base)
        for k in ("CLAUDE_CONFIG_DIR", "AFTERPROMPT_TEST_ENVS", "AFTERPROMPT_STOP_AFTER", "AFTERPROMPT_WINDOWS_HOME"):
            self.assertNotIn(k, env)
        self.assertEqual(env["AFTERPROMPT_HOME"], "/data/box")
        self.assertEqual(env["AFTERPROMPT_PLATFORM"], "linux")
        self.assertEqual(env["AFTERPROMPT_RG"], "/opt/rg")
        self.assertEqual(env["PYTHONPATH"], REPO + os.pathsep + "/elsewhere")
        self.assertTrue(env["AFTERPROMPT_DIR"].startswith(self.tmp))
        self.assertEqual(env["KEEP"], "1")


class ScanWslTests(TempDirTest):
    """W8: every route through scanning one distro, with wsl.exe replaced by stand-ins."""

    E = Env("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu")
    FINDINGS = {"rotate": [], "review": [], "coverage": {"files": 3}}

    def go(self, platform="windows", running=("Ubuntu",), ship_ok=True, worker_run=None, share_run=None,
           unc=r"\\wsl.localhost\Ubuntu\home\me", exe="wsl.exe"):
        self.calls = {"worker": [], "share": []}
        said = []

        def fake_worker(cmd, env, err, say):
            self.calls["worker"].append(cmd)
            return worker_run or {"result": {"exit": 0, "findings": self.FINDINGS}, "exit": 0,
                                  "hello": {"other_homes": ["bob"]}}

        def fake_local(e, home, cfg, args, say, state_dir):
            self.calls["share"].append(home)
            return share_run or {"result": {"exit": 0, "findings": self.FINDINGS}, "exit": 0}
        with mock.patch.object(envs.platforms, "wsl_exe", return_value=exe), \
                mock.patch.object(envs.platforms, "running_distros", return_value=list(running) if running is not None else None), \
                mock.patch.object(envs, "ship", return_value={"ok": ship_ok, "exit": 0 if ship_ok else 1,
                                                              "stderr_tail": "" if ship_ok else "tar: not found"}), \
                mock.patch.object(envs, "run_worker", side_effect=fake_worker), \
                mock.patch.object(envs, "run_local", side_effect=fake_local), \
                mock.patch.object(envs, "distro_home_unc", return_value=unc), \
                mock.patch.object(envs.os.path, "isdir", return_value=True):
            res = envs.scan(self.E, fake_cfg(platform), ["--worker", "--deep"], said.append, self.tmp)
        self.said = said
        return res

    def test_scanned_inside(self):  # U-ENV-21
        res = self.go()
        self.assertEqual(res["status"], "scanned")
        self.assertEqual(res["findings"], self.FINDINGS)
        self.assertEqual(res["other_homes"], ["bob"])
        self.assertIsNone(res["notice"])
        cmd = self.calls["worker"][0]
        self.assertEqual(cmd[:8], ["wsl.exe", "-d", "Ubuntu", "-e", "sh", "-c", envs.RUN, "sh"])
        self.assertEqual(cmd[8:], ["--worker", "--deep"])
        self.assertEqual(self.calls["share"], [])
        self.assertEqual(envs.load_result(self.tmp, self.E)["status"], "scanned")

    def test_stopped_distro_is_started_and_said(self):  # U-ENV-22
        res = self.go(running=["Debian"])
        self.assertEqual(res["status"], "scanned")
        self.assertIn("was not running", res["notice"])
        self.assertIn(res["notice"], self.said)
        self.assertIsNone(self.go(running=None)["notice"])  # cannot tell: say nothing rather than guess

    def test_no_python_falls_back_to_the_share_from_windows(self):  # U-ENV-23
        res = self.go(worker_run={"exit": 3, "stderr_tail": "Python 3.9 or newer is required"})
        self.assertEqual(res["status"], "scanned_share")
        self.assertEqual(self.calls["share"], [r"\\wsl.localhost\Ubuntu\home\me"])
        self.assertTrue(any("network share" in s for s in self.said))

    def test_copy_failure_falls_back_to_the_share(self):  # U-ENV-24
        res = self.go(ship_ok=False)
        self.assertEqual(res["status"], "scanned_share")
        self.assertEqual(self.calls["worker"], [])

    def test_no_fallback_from_inside_wsl(self):  # U-ENV-25
        """Another distro's files are not reachable from inside WSL: report it, never tell the user to go there."""
        res = self.go(platform="wsl", worker_run={"exit": 3, "stderr_tail": "no python3"})
        self.assertEqual(res["status"], "not_scanned")
        self.assertIn("Python 3.9+ or ripgrep", res["reason"])
        self.assertNotIn("run Afterprompt", res["reason"])

    def test_real_failure_is_not_retried_over_the_share(self):  # U-ENV-26
        res = self.go(worker_run={"exit": 5, "error": {"message": "The scan failed during 'Listing files'"}})
        self.assertEqual(res["status"], "not_scanned")
        self.assertEqual(res["reason"], "The scan failed during 'Listing files'")
        self.assertEqual(self.calls["share"], [])

    def test_fallback_failure_names_both_causes(self):  # U-ENV-27
        res = self.go(worker_run={"exit": 3, "stderr_tail": "no python3"}, share_run={"exit": 5, "stderr_tail": "boom"})
        self.assertEqual(res["status"], "not_scanned")
        self.assertIn("no python3", res["reason"])
        self.assertIn("network-share fallback failed too", res["reason"])

    def test_share_unreachable(self):  # U-ENV-28
        res = self.go(worker_run={"exit": 3}, unc=None)
        self.assertEqual(res["status"], "not_scanned")
        self.assertEqual(self.calls["share"], [])

    def test_wsl_exe_gone(self):  # U-ENV-29
        res = self.go(exe=None)
        self.assertEqual(res["status"], "not_scanned")
        self.assertIn("wsl.exe", res["reason"])


class FolderScanTests(TempDirTest):
    def test_folder_worker_end_to_end(self):  # U-ENV-30
        """A real worker process through the protocol, scanning a folder as its own Linux home."""
        if not shutil.which("rg"):
            self.skipTest("ripgrep is not installed")
        home = os.path.join(self.tmp, "box")
        write(os.path.join(home, ".claude", "projects", "p", "s.jsonl"), '{"type": "user", "message": "hi"}\n')
        cfg = make_cfg(self.tmp, "linux")
        e = Env("Box", "folder", "Box", "env:Box", home)
        said = []
        res = envs.scan(e, cfg, ["--worker", "--windows-home", "none"], said.append, os.path.join(self.tmp, "envs"))
        self.assertEqual(res["status"], "scanned", res.get("reason"))
        self.assertEqual(res["findings"]["rotate"], [])
        self.assertGreaterEqual(res["findings"]["coverage"]["files"], 1)
        self.assertTrue(any("Finding AI tool data" in s for s in said))
        self.assertFalse(any(s.startswith("afterprompt ") or s.startswith("Report:") for s in said))
        self.assertFalse(any(worker.decode(s) for s in said))


class RealWslTests(TempDirTest):
    @unittest.skipUnless(os.environ.get("AFTERPROMPT_TEST_REAL_WSL_SCAN") == "1", "real distro scan not requested")
    def test_scan_a_real_distro(self):  # U-ENV-31
        """From native Windows: copy the engine into a real distro, scan it from inside, and get findings back.
        Opt-in, because it scans that distro's real home (the result stays in this test's temp folder)."""
        if sys.platform != "win32":
            self.skipTest("only meaningful from Windows")
        found = envs.discover(make_cfg(self.tmp, "windows"), providers=[lambda c: envs.wsl_provider(c, env={})])
        distros = [e for e in found if e.kind == "wsl"]
        if not distros:
            self.skipTest("no WSL distribution installed on this host")
        cfg = make_cfg(self.tmp, "windows")
        res = envs.scan(distros[0], cfg, ["--worker", "--windows-home", "none"], lambda m: None,
                        os.path.join(self.tmp, "envs"))
        self.assertIn(res["status"], ("scanned", "scanned_share"), res.get("reason"))
        self.assertGreater(res["findings"]["coverage"]["files"], 0)


class PlainTextTests(unittest.TestCase):
    def test_plain_text_encodings(self):  # U-ENV-32
        self.assertEqual(envs.plain_text("downloading… ✓".encode("utf-8")), "downloading… ✓")
        with mock.patch("locale.getpreferredencoding", return_value="cp1252"):
            self.assertEqual(envs.plain_text("downloading…".encode("cp1252")), "downloading…")
