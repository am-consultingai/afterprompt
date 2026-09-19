import argparse
import contextlib
import io
import os
from collections import namedtuple
from unittest import mock

from afterprompt import __version__, cli, config, envs, worker
from tests.helpers import Fixture, TempDirTest, requires_rg, write


def run_main(args, env):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, env), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(args)
    return code, out.getvalue(), err.getvalue()


def ns(**kw):
    d = dict(deep=False, out=None, extra_root=None, exclude=None, max_disk=10.0, workers=None, keep_work=False,
             include_keychain=False, windows_home=None)
    d.update(kw)
    return argparse.Namespace(**d)


class CliTests(TempDirTest):
    def env(self):
        return {"AFTERPROMPT_DIR": os.path.join(self.tmp, "base"), "AFTERPROMPT_HOME": os.path.join(self.tmp, "home"),
                "AFTERPROMPT_PLATFORM": "linux"}

    def test_usage_errors(self):  # U-CLI-1
        for args in (["--bogus"], ["--workers", "0"], ["--max-disk", "-1"], ["--extra-root", "/no/such/path"],
                     ["--exclude", "("], ["--windows-home", "/no/such/dir"]):
            with self.subTest(args=args):
                code, _, err = run_main(args, self.env())
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn("afterprompt.sh:", err)

    def test_version(self):  # U-CLI-2
        code, out, _ = run_main(["--version"], self.env())
        self.assertEqual((code, out.strip()), (0, f"afterprompt {__version__}"))

    def test_fingerprint(self):  # U-CLI-3
        with mock.patch.dict(os.environ, self.env()):
            base = config.from_args(ns(), "/r").fingerprint()
            self.assertEqual(base, config.from_args(ns(), "/other").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(deep=True), "/r").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(exclude=["x"]), "/r").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(extra_root=[self.tmp]), "/r").fingerprint())
            self.assertEqual(base, config.from_args(ns(out=self.tmp), "/r").fingerprint())

    def test_start_method(self):  # U-CLI-6
        with mock.patch.dict(os.environ, self.env()):
            for plat in ("linux", "wsl", "macos", "windows"):
                with self.subTest(platform=plat), mock.patch.dict(os.environ, {"AFTERPROMPT_PLATFORM": plat}):
                    self.assertEqual(config.from_args(ns(), "/r").mp_start, "spawn")
            with mock.patch.dict(os.environ, {"AFTERPROMPT_MP_START": "fork"}):
                self.assertEqual(config.from_args(ns(), "/r").mp_start, "fork")

    def test_default_workers(self):  # U-CLI-4
        self.assertEqual(config.default_workers(cpu=12, ram_gb=40), 6)
        self.assertEqual(config.default_workers(cpu=4, ram_gb=40), 3)
        self.assertEqual(config.default_workers(cpu=12, ram_gb=8), 2)
        self.assertEqual(config.default_workers(cpu=1, ram_gb=2), 1)

    def test_disk_preflight(self):  # U-CLI-5
        os.makedirs(os.path.join(self.tmp, "home"))
        Usage = namedtuple("Usage", "total used free")
        gib = config.GIB
        with mock.patch("shutil.disk_usage", return_value=Usage(100 * gib, 99 * gib, gib)):
            code, out, _ = run_main(["--deep"], self.env())
        self.assertEqual(code, cli.EXIT_DISK)
        self.assertIn("Not enough free disk space", out)
        with mock.patch("shutil.disk_usage", return_value=Usage(100 * gib, 95 * gib, 5 * gib)), \
                mock.patch.object(cli, "run_stage", side_effect=KeyboardInterrupt):
            code, out, _ = run_main(["--deep", "--fresh"], self.env())
        self.assertEqual(code, cli.EXIT_INTERRUPTED)
        self.assertIn("decoded data capped at 4.0 GB", out)

    def test_status_without_scan(self):
        code, out, _ = run_main(["--status"], self.env())
        self.assertEqual(code, 0)
        self.assertIn("No scan in progress", out)


@requires_rg
class EnvironmentCliTests(TempDirTest):
    """D1 / M3: one command, every environment, and an exit code that never hides a gap."""

    def fixture(self, clean=True):
        fx = Fixture(os.path.join(self.tmp, "host"), "linux", clean=clean)
        return fx, fx.env(AFTERPROMPT_TEST_ENVS=f"Box={os.path.join(self.tmp, 'box')}")

    def failing_scan(self, e, cfg, worker_args, say, state_dir):
        return envs.save_result(state_dir, dict(envs.skipped(e, None), status="not_scanned",
                                                reason="Python 3.9+ or ripgrep is not available there"))

    def test_exit_7_when_an_environment_was_not_scanned(self):  # U-CLI-7
        fx, env = self.fixture(clean=True)
        with mock.patch.object(envs, "scan", side_effect=self.failing_scan):
            code, out, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_PARTIAL, out)
        self.assertIn("Not scanned: Box — Python 3.9+ or ripgrep is not available there", out)
        self.assertIn("2 environments", out)
        d = fx.findings()
        self.assertEqual([e["status"] for e in d["environments"]], ["scanned", "not_scanned"])

    def test_rotate_still_wins_over_a_gap(self):  # U-CLI-8
        fx, env = self.fixture(clean=False)
        with mock.patch.object(envs, "scan", side_effect=self.failing_scan):
            code, out, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_ROTATE, out)
        self.assertIn("Not scanned: Box", out)

    def test_no_wsl_skips_distros_without_a_gap(self):  # U-CLI-9
        fx, env = self.fixture(clean=True)
        env.pop("AFTERPROMPT_TEST_ENVS")
        ubuntu = envs.Environment("Ubuntu", "wsl", "WSL: Ubuntu", "wsl:Ubuntu")
        with mock.patch.object(envs, "discover", side_effect=lambda cfg: [envs.host(cfg), ubuntu]), \
                mock.patch.object(envs, "scan", side_effect=AssertionError("must not scan")):
            code, out, _ = run_main(["--no-wsl"], env)
        self.assertEqual(code, cli.EXIT_OK, out)
        d = fx.findings()
        self.assertEqual(d["environments"][1]["status"], "skipped")
        self.assertIn("--no-wsl", d["environments"][1]["reason"])

    def test_single_environment_has_no_extra_stage(self):  # U-CLI-10
        fx, env = self.fixture(clean=True)
        env.pop("AFTERPROMPT_TEST_ENVS")
        code, out, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_OK, out)
        self.assertNotIn("other environments", out)
        self.assertNotIn("environments", fx.findings())
        self.assertIn("[9/9]", out)

    def test_worker_speaks_only_protocol(self):  # U-CLI-11
        fx, env = self.fixture(clean=False)
        code, out, err = run_main(["--worker", "--windows-home", "none"], env)
        self.assertEqual(code, cli.EXIT_ROTATE, err)
        msgs = [worker.decode(l) for l in out.splitlines()]
        self.assertTrue(all(msgs), [l for l in out.splitlines() if not worker.decode(l)])
        kinds = [m["type"] for m in msgs]
        self.assertEqual(kinds[0], "hello")
        self.assertEqual(kinds[-1], "result")
        self.assertEqual(kinds.count("result"), 1)
        self.assertNotIn("error", kinds)
        self.assertEqual(msgs[-1]["exit"], cli.EXIT_ROTATE)
        self.assertEqual(len(msgs[-1]["findings"]["rotate"]), 4)
        said = " ".join(m["text"] for m in msgs if m["type"] == "say")
        self.assertIn("Finding AI tool data", said)
        self.assertNotIn("Report:", said)
        # Workers keep their own run folder, so a scan someone started by hand there is never resumed or discarded.
        self.assertTrue(os.path.isdir(os.path.join(fx.base, "worker", "runs")))
        self.assertFalse(os.path.exists(os.path.join(fx.base, "runs")))
        for v in fx.s.values():
            self.assertNotIn(v, out)

    def test_worker_reports_failure(self):  # U-CLI-12
        fx, env = self.fixture(clean=True)
        with mock.patch.object(cli, "run_stage", side_effect=RuntimeError("disk on fire")):
            code, out, _ = run_main(["--worker", "--windows-home", "none"], env)
        self.assertEqual(code, cli.EXIT_FAILED)
        msgs = [worker.decode(l) for l in out.splitlines()]
        self.assertEqual(msgs[-1]["type"], "error")
        self.assertIn("disk on fire", msgs[-1]["message"])
        code, out, err = run_main(["--worker", "--bogus"], env)
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(worker.decode(out.splitlines()[-1])["type"], "error")

    def test_worker_args(self):  # U-CLI-13
        args = cli.parser().parse_args(["--deep", "--no-download", "--keep-work", "--fresh", "--exclude", "x",
                                        "--max-disk", "3", "--extra-root", self.tmp, "--out", self.tmp])
        cfg = config.from_args(args, self.tmp)
        got = cli.worker_args(cfg, args)
        self.assertEqual(got[:5], ["--worker", "--windows-home", "none", "--max-disk", "3.0"])
        for flag in ("--deep", "--no-download", "--keep-work", "--fresh"):
            self.assertIn(flag, got)
        self.assertEqual(got[got.index("--exclude") + 1], "x")
        for host_only in ("--extra-root", "--out", "--no-wsl"):
            self.assertNotIn(host_only, got)

    def test_status_lists_the_environment_stage(self):  # U-CLI-14
        fx, env = self.fixture(clean=True)
        with mock.patch.object(envs, "scan", side_effect=self.failing_scan):
            code, _, _ = run_main([], dict(env, AFTERPROMPT_STOP_AFTER="known"))
        self.assertEqual(code, cli.EXIT_INTERRUPTED)
        _, out, _ = run_main(["--status"], env)
        self.assertIn("Scanning the other environments on this machine", out)

    def test_interrupted_environment_stage_resumes_per_environment(self):  # U-CLI-15
        """Box finished before the interruption, Other did not: only Other is scanned again."""
        fx, env = self.fixture(clean=True)
        env["AFTERPROMPT_TEST_ENVS"] += f";Other={os.path.join(self.tmp, 'other')}"
        scanned = []

        def first(e, cfg, worker_args, say, state_dir):
            if e.name == "Other":
                raise KeyboardInterrupt
            scanned.append(e.name)
            return envs.save_result(state_dir, dict(envs.skipped(e, None), status="scanned", findings=None))
        with mock.patch.object(envs, "scan", side_effect=first):
            code, _, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_INTERRUPTED)

        def second(e, cfg, worker_args, say, state_dir):
            scanned.append(e.name)
            return envs.save_result(state_dir, dict(envs.skipped(e, None), status="scanned", findings=None))
        with mock.patch.object(envs, "scan", side_effect=second):
            code, out, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_OK, out)
        self.assertEqual(scanned, ["Box", "Other"])
        self.assertIn("Box … already done", out)
        self.assertEqual([e["name"] for e in fx.findings()["environments"]], ["Linux", "Box", "Other"])


@requires_rg
class PlaintextLifetimeTests(TempDirTest):
    """Decoded plaintext and database dumps are deleted as soon as nothing reads them, not at the end of the run."""

    def run_until(self, stage, *args):
        fx = Fixture(os.path.join(self.tmp, f"m-{stage}{len(os.listdir(self.tmp))}"), "linux")
        code, out, _ = run_main(["--deep", *args], fx.env(AFTERPROMPT_STOP_AFTER=stage))
        self.assertEqual(code, cli.EXIT_INTERRUPTED, out)
        work = os.path.join(fx.base, "runs", os.listdir(os.path.join(fx.base, "runs"))[0], "work")
        return fx, work

    def test_decoded_store_goes_right_after_known(self):  # U-CLI-16
        _, work = self.run_until("entropy_store")
        self.assertTrue(os.listdir(os.path.join(work, "store")))            # still needed by the known stage
        _, work = self.run_until("known")
        self.assertFalse(os.path.exists(os.path.join(work, "store")))
        self.assertTrue(os.path.isdir(os.path.join(work, "extracted", "db")))  # prompts still reads these

    def test_database_text_goes_right_after_prompts(self):  # U-CLI-17
        _, work = self.run_until("prompts")
        self.assertFalse(os.path.exists(os.path.join(work, "extracted", "db")))
        self.assertTrue(os.path.exists(os.path.join(work, "extracted", "_ledger.json")))

    def test_keep_work_keeps_them(self):  # U-CLI-18
        _, work = self.run_until("prompts", "--keep-work")
        self.assertTrue(os.listdir(os.path.join(work, "store")))
        self.assertTrue(os.listdir(os.path.join(work, "extracted", "db")))

    def test_resume_after_removal_finishes_with_decoded_findings(self):  # U-CLI-19
        fx, work = self.run_until("known")
        code, out, _ = run_main(["--deep"], fx.env())
        self.assertEqual(code, cli.EXIT_ROTATE, out)
        rotate = {r["masked"]: r for r in fx.findings()["rotate"]}
        self.assertTrue(all(l["decoded"] for l in rotate[fx.masked("F4")]["locations"]))
