import argparse
import contextlib
import io
import os
from collections import namedtuple
from unittest import mock

from afterprompt import __version__, cli, config, envs, worker
from afterprompt.util import write_json
from tests.helpers import Fixture, TempDirTest, make_cfg, requires_rg, write


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


class StageDetailTests(TempDirTest):
    """What a step shows when it is opened. Built from what the step already wrote down."""

    def cfg(self):
        c = make_cfg(self.tmp, "linux", os.path.join(self.tmp, "home"))
        return c

    def survey(self, rows):
        cfg = self.cfg()
        os.makedirs(os.path.join(cfg.run_dir, "envs"), exist_ok=True)
        write_json(os.path.join(cfg.run_dir, "envs", "survey.json"), rows)
        return cfg

    def test_environments_names_what_is_here(self):  # U-CLI-D1
        """What this machine has, not the catalogue of what Afterprompt can look for."""
        cfg = self.survey([{"label": "This machine", "found": 1, "status": "scanned"},
                           {"label": "Docker containers", "found": 2, "status": "scanned",
                            "names": ["api-1", "worker-1"]},
                           {"label": "WSL distributions", "found": 0, "status": "absent"},
                           {"label": "Podman containers", "found": 0, "status": "not_installed"},
                           {"label": "GitHub Codespace", "found": 0, "status": "not_applicable"}])
        rows = cli.stage_detail(cfg, "environments", {}, {})
        self.assertEqual([r["label"] for r in rows[:2]], ["This machine", "Docker containers"])
        self.assertEqual(rows[1]["note"], "api-1, worker-1")       # the names, not just the count
        # The three that are not here are one quiet line between them, so a clean result still says so.
        self.assertEqual(rows[-1]["label"], "Not on this machine")
        self.assertEqual(rows[-1]["note"], "WSL distributions, Podman containers, GitHub Codespace")
        self.assertEqual(len(rows), 3)

    def test_images_are_named_as_never_opened(self):  # U-CLI-D6
        """They are on the machine, and a key in a layer is a different tool's problem."""
        cfg = self.survey([{"label": "This machine", "found": 1, "status": "scanned"},
                           {"label": "Docker images", "found": 53, "status": "out_of_scope",
                            "why": "An image is a filesystem nobody has typed into."}])
        rows = cli.stage_detail(cfg, "environments", {}, {})
        images = [r for r in rows if r["label"] == "Docker images"][0]
        self.assertIn("53 here, never opened", images["note"])
        self.assertIn("nobody has typed into", images["note"])
        self.assertEqual(images["tone"], "quiet")
        # No images on the machine, nothing to say about them.
        cfg = self.survey([{"label": "Docker images", "found": 0, "status": "out_of_scope"}])
        self.assertNotIn("Docker images", [r["label"] for r in cli.stage_detail(cfg, "environments", {}, {})])

    def test_listing_files_breaks_down_by_tool(self):  # U-CLI-D2
        info = {"per_source": [{"tool": "Claude Code", "side": "wsl", "files": 7388, "bytes": 1_200_000_000}],
                "vendored": 1201, "self": 167}
        rows = cli.stage_detail(self.cfg(), "manifest", info, {})
        self.assertEqual(rows[0]["label"], "Claude Code (wsl)")
        self.assertIn("7,388 files", rows[0]["note"])
        self.assertIn("Shipped app and plugin code", rows[1]["label"])

    def test_a_step_with_nothing_to_show_says_nothing(self):  # U-CLI-D3
        self.assertEqual(cli.stage_detail(self.cfg(), "cleanup", {}, {}), [])
        self.assertEqual(cli.stage_detail(self.cfg(), "vendor_raw", {"hits": 3}, {}), [])

    def test_a_resumed_step_still_says_what_it_found(self):  # U-CLI-D5
        """Resuming used to leave a row of ticks with nothing behind them; the marker holds what it found."""
        src = open(os.path.join(os.path.dirname(os.path.abspath(cli.__file__)), "cli.py"), encoding="utf-8").read()
        resume = src[src.index("already done"):src.index("if view:\n                view.state.stage(name)")]
        self.assertIn("done_info = read_json(marker, {}) or {}", resume)
        self.assertIn("view.state.detail(name, stage_detail(cfg, name, done_info, ctx))", resume)
        self.assertIn("summary=stage_result_line(name, done_info)", resume)

    def test_detail_never_fails_a_scan(self):  # U-CLI-D4
        """Nothing here is worth losing a scan over, so a missing key is an empty list, not an exception."""
        for name in cli.DESCRIPTIONS:
            self.assertIsInstance(cli.stage_detail(self.cfg(), name, {}, {}), list)


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

    def failing_scan(self, e, cfg, worker_args, say, state_dir, stdin=None):
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

    def test_one_environment_is_still_looked_for_and_said_out_loud(self):  # U-CLI-10
        """The looking happens on every scan; only the scanning of others is conditional."""
        fx, env = self.fixture(clean=True)
        env.pop("AFTERPROMPT_TEST_ENVS")
        code, out, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_OK, out)
        self.assertIn("[1/10] Looking for environments on this machine", out)
        self.assertNotIn("Scanning the other environments", out)     # there are none to scan
        self.assertNotIn("environments", fx.findings())              # and none to merge
        self.assertIn("[10/10]", out)

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
        self.assertIn("Looking for environments on this machine", out)
        self.assertIn("Scanning the other environments", out)

    def test_interrupted_environment_stage_resumes_per_environment(self):  # U-CLI-15
        """Box finished before the interruption, Other did not: only Other is scanned again."""
        fx, env = self.fixture(clean=True)
        env["AFTERPROMPT_TEST_ENVS"] += f";Other={os.path.join(self.tmp, 'other')}"
        scanned = []

        def first(e, cfg, worker_args, say, state_dir, stdin=None):
            if e.name == "Other":
                raise KeyboardInterrupt
            scanned.append(e.name)
            return envs.save_result(state_dir, dict(envs.skipped(e, None), status="scanned", findings=None))
        with mock.patch.object(envs, "scan", side_effect=first):
            code, _, _ = run_main([], env)
        self.assertEqual(code, cli.EXIT_INTERRUPTED)

        def second(e, cfg, worker_args, say, state_dir, stdin=None):
            scanned.append(e.name)
            return envs.save_result(state_dir, dict(envs.skipped(e, None), status="scanned", findings=None))
        with mock.patch.object(envs, "scan", side_effect=second), \
                mock.patch.object(envs, "fetch_values", return_value=[]) as fetched:
            code, out, _ = run_main([], env)
        self.assertEqual([c.args[0].name for c in fetched.call_args_list], ["Box"])   # values re-fetched, not stored
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
