import argparse
import contextlib
import io
import os
from collections import namedtuple
from unittest import mock

from afterprompt import cli, config
from tests.helpers import TempDirTest, write


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
        self.assertEqual((code, out.strip()), (0, "afterprompt 0.1.0"))

    def test_fingerprint(self):  # U-CLI-3
        with mock.patch.dict(os.environ, self.env()):
            base = config.from_args(ns(), "/r").fingerprint()
            self.assertEqual(base, config.from_args(ns(), "/other").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(deep=True), "/r").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(exclude=["x"]), "/r").fingerprint())
            self.assertNotEqual(base, config.from_args(ns(extra_root=[self.tmp]), "/r").fingerprint())
            self.assertEqual(base, config.from_args(ns(out=self.tmp), "/r").fingerprint())

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
