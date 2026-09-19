"""afterprompt.sh environment and dependency handling (test plan §11.5)."""
import hashlib
import os
import shutil
import stat
import subprocess
import tarfile
import unittest

from tests.helpers import SCAN_SH, TempDirTest, requires_posix

BASH = os.environ.get("AFTERPROMPT_TEST_BASH") or "bash"


@requires_posix  # afterprompt.sh needs a POSIX shell; the Windows entry point has its own tests
class LauncherTests(TempDirTest):
    def run_sh(self, *args, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("AFTERPROMPT_") or k == "AFTERPROMPT_PYTHON"}
        e["AFTERPROMPT_DIR"] = os.path.join(self.tmp, "base")
        e.update(env)
        p = subprocess.run([BASH, SCAN_SH, *args], capture_output=True, env=e, timeout=120)
        return p.returncode, p.stdout.decode(), p.stderr.decode()

    def script(self, name, body):
        d = os.path.join(self.tmp, "bin")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, name)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\n" + body + "\n")
        os.chmod(p, stat.S_IRWXU)
        return p

    def fake_rg_tarball(self, folder, target):
        os.makedirs(folder, exist_ok=True)
        rg = self.script("rg-inner", 'echo "ripgrep 15.2.0"')
        name = f"ripgrep-15.2.0-{target}.tar.gz"
        path = os.path.join(folder, name)
        with tarfile.open(path, "w:gz") as tf:
            tf.add(rg, arcname=f"ripgrep-15.2.0-{target}/rg")
        with open(path, "rb") as fh:
            return path, hashlib.sha256(fh.read()).hexdigest()

    def test_git_bash_refused(self):  # L-1
        code, _, err = self.run_sh(AFTERPROMPT_UNAME="MINGW64_NT-10.0-19045")
        self.assertEqual(code, 4)
        self.assertIn("WSL", err)

    def test_unknown_os(self):  # L-2
        self.assertEqual(self.run_sh(AFTERPROMPT_UNAME="FreeBSD")[0], 4)

    def test_python_too_old(self):  # L-3
        fake = self.script("python3.8", "exit 1")
        code, _, err = self.run_sh(AFTERPROMPT_PYTHON=fake)
        self.assertEqual(code, 3)
        self.assertIn("Install it with", err)

    def test_python_missing(self):  # L-4
        self.assertEqual(self.run_sh(AFTERPROMPT_PYTHON="/no/such/python3")[0], 3)

    def test_no_rg_no_download(self):  # L-5
        code, _, err = self.run_sh("--no-download", AFTERPROMPT_IGNORE_SYSTEM_RG="1")
        self.assertEqual(code, 3)
        self.assertRegex(err, "brew install ripgrep|apt install ripgrep")

    def test_old_rg(self):  # L-6
        bindir = os.path.dirname(self.script("rg", 'echo "ripgrep 12.1.1"'))
        code, _, _ = self.run_sh("--no-download", PATH=bindir + os.pathsep + os.environ["PATH"])
        self.assertEqual(code, 3)

    def test_checksum_mismatch(self):  # L-7
        folder = os.path.join(self.tmp, "release")
        self.fake_rg_tarball(folder, "x86_64-unknown-linux-musl")
        code, _, err = self.run_sh(AFTERPROMPT_IGNORE_SYSTEM_RG="1", AFTERPROMPT_UNAME="Linux", AFTERPROMPT_UNAME_M="x86_64",
                                   AFTERPROMPT_RG_BASE_URL="file://" + folder)
        self.assertEqual(code, 3)
        self.assertIn("Checksum mismatch", err)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "base", "bin", "rg")))

    @unittest.skipUnless(shutil.which("curl") or shutil.which("wget"), "no downloader")
    def test_download_success(self):  # L-8
        folder = os.path.join(self.tmp, "release")
        _, sha = self.fake_rg_tarball(folder, "aarch64-apple-darwin")
        code, out, err = self.run_sh(AFTERPROMPT_IGNORE_SYSTEM_RG="1", AFTERPROMPT_UNAME="Darwin", AFTERPROMPT_UNAME_M="arm64",
                                     AFTERPROMPT_RG_BASE_URL="file://" + folder, AFTERPROMPT_RG_SHA256=sha,
                                     AFTERPROMPT_BOOTSTRAP_ONLY="1")
        self.assertEqual(code, 0, err)
        rg = os.path.join(self.tmp, "base", "bin", "rg")
        self.assertIn(f"rg={rg}", out)
        self.assertTrue(os.access(rg, os.X_OK))
        # a second run reuses the installed copy without downloading
        code, out, _ = self.run_sh(AFTERPROMPT_IGNORE_SYSTEM_RG="1", AFTERPROMPT_UNAME="Darwin", AFTERPROMPT_UNAME_M="arm64",
                                   AFTERPROMPT_RG_BASE_URL="file:///nonexistent", AFTERPROMPT_BOOTSTRAP_ONLY="1")
        self.assertEqual(code, 0)
        self.assertNotIn("downloading", out)

    def test_arch_mapping(self):  # L-9
        code, out, err = self.run_sh(AFTERPROMPT_IGNORE_SYSTEM_RG="1", AFTERPROMPT_UNAME="Darwin", AFTERPROMPT_UNAME_M="arm64",
                                     AFTERPROMPT_RG_BASE_URL="file://" + os.path.join(self.tmp, "missing"))
        self.assertEqual(code, 3)
        self.assertIn("aarch64-apple-darwin", out + err)
        self.assertEqual(self.run_sh(AFTERPROMPT_IGNORE_SYSTEM_RG="1", AFTERPROMPT_UNAME_M="sparc64")[0], 3)

    def test_help_version_status_without_rg(self):  # L-10
        for arg in ("--help", "--version", "--status"):
            with self.subTest(arg=arg):
                code, out, err = self.run_sh(arg, "--no-download", AFTERPROMPT_IGNORE_SYSTEM_RG="1")
                self.assertEqual(code, 0, err)
        self.assertIn("afterprompt 0.1.0", self.run_sh("--version", AFTERPROMPT_IGNORE_SYSTEM_RG="1")[1])

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):  # L-11
        p = subprocess.run(["shellcheck", SCAN_SH], capture_output=True)
        self.assertEqual(p.returncode, 0, p.stdout.decode())
