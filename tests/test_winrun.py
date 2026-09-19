"""The WSL→Windows bridge in tools/winrun.sh (W1).

The bridge is development tooling, not part of the shipped scanner: it lets work happening
inside WSL start Windows processes the way a user would, so Windows behaviour can be exercised
without a human driving PowerShell. These tests only run where that is possible — inside WSL,
with the script present.
"""
import os
import subprocess
import unittest

from afterprompt import platforms
from tests.helpers import REPO

WINRUN = os.path.join(REPO, "tools", "winrun.sh")
IN_WSL = platforms.detect() == "wsl"
HAVE = IN_WSL and os.path.exists(WINRUN) and os.access(WINRUN, os.X_OK)


def run(*args, timeout=120):
    return subprocess.run([WINRUN, *args], capture_output=True, timeout=timeout)


@unittest.skipUnless(HAVE, "needs WSL with tools/winrun.sh present")
class WinRunTests(unittest.TestCase):
    def test_runs_a_windows_process(self):  # U-WIN-1 (W1)
        p = run("ps", "Write-Output $env:OS")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertEqual(p.stdout.decode().strip(), "Windows_NT")

    def test_output_is_clean(self):  # U-WIN-2 (W1)
        """PowerShell answers in UTF-16 with CRs through the interop pipe; callers get neither."""
        out = run("ps", "Write-Output 'alpha'").stdout
        self.assertEqual(out, b"alpha\n")
        self.assertNotIn(b"\x00", out)
        self.assertNotIn(b"\r", out)

    def test_exit_code_propagates(self):  # U-WIN-3 (W1)
        """A failing Windows process must fail the WSL caller, or a broken test would look green."""
        self.assertEqual(run("ps", "exit 7").returncode, 7)
        self.assertEqual(run("cmd", "exit /b 3").returncode, 3)

    def test_finds_windows_python(self):  # U-WIN-4 (W1)
        p = run("pyexe")
        if p.returncode == 3:
            self.skipTest("no Windows Python on this host")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertRegex(p.stdout.decode().strip(), r"(?i)^[a-z]:\\.*\.exe$")

    def test_runs_python_on_windows_with_exit_code(self):  # U-WIN-5 (W1)
        if run("pyexe").returncode != 0:
            self.skipTest("no Windows Python on this host")
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_winrun_probe.py")
        with open(script, "w", encoding="utf-8") as fh:
            fh.write("import sys\nprint(sys.platform)\nsys.exit(len(sys.argv) - 1)\n")
        try:
            p = run("py", script, "a", "b")
            self.assertEqual(p.stdout.decode().strip(), "win32")
            self.assertEqual(p.returncode, 2, "arguments must reach the Windows process")
        finally:
            os.remove(script)

    def test_unknown_mode_is_usage_error(self):  # U-WIN-6 (W1)
        p = run("nonsense")
        self.assertEqual(p.returncode, 2)
        self.assertIn(b"winrun.sh", p.stderr)
