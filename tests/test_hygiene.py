"""Repository hygiene: no credential-shaped literals, no network code (test plan S-2, S-5)."""
import ast
import os
import re
import unittest

from afterprompt.patterns import PATTERNS, escape_aware
from tests.helpers import REPO

PUBLISHED = ["README.md", "LICENSE", "afterprompt.sh", "afterprompt", "tests", ".github", "site"]
NETWORK_MODULES = {"socket", "urllib.request", "http.client", "ftplib", "ssl", "smtplib"}


def published_files():
    for entry in PUBLISHED:
        path = os.path.join(REPO, entry)
        if os.path.isfile(path):
            yield path
        elif os.path.isdir(path):
            for dp, dns, fns in os.walk(path):
                dns[:] = [d for d in dns if d != "__pycache__"]
                for fn in fns:
                    if not fn.endswith((".png", ".pyc")):
                        yield os.path.join(dp, fn)


class HygieneTests(unittest.TestCase):
    def test_no_credential_literals(self):  # S-2
        # These patterns match a fixed header or DER prefix only; the pattern library and sample templates
        # necessarily contain those constants, which are not secrets.
        header_only = {"pgp_private_block", "pkcs8_rsa_key_body", "pkcs1_rsa_key_body", "pkcs8_ec_key_body"}
        tier_a = [(n, re.compile(escape_aware(r))) for n, r, t in PATTERNS if t == "A" and n not in header_only]
        found = []
        for path in published_files():
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
            for name, rx in tier_a:
                for m in rx.finditer(text):
                    found.append(f"{os.path.relpath(path, REPO)}: {name}: {m.group(0)[:12]}…")
        self.assertEqual(found, [])

    def test_no_network_imports(self):  # S-5
        offenders = []
        for dp, _, fns in os.walk(os.path.join(REPO, "afterprompt")):
            for fn in fns:
                if not fn.endswith(".py"):
                    continue
                path = os.path.join(dp, fn)
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
                for node in ast.walk(tree):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                    offenders += [f"{fn}: {n}" for n in names if n in NETWORK_MODULES]
        self.assertEqual(offenders, [])

    def test_windows_launcher_matches_shell_launcher(self):  # S-6 (W4)
        """The two launchers must agree on the contract they share: the same ripgrep version,
        the same environment variables and the same options handled before the scan starts."""
        sh = open(os.path.join(REPO, "afterprompt.sh"), encoding="utf-8").read()
        ps1 = open(os.path.join(REPO, "afterprompt.ps1"), encoding="utf-8").read()
        cmd = open(os.path.join(REPO, "afterprompt.cmd"), encoding="utf-8").read()

        version = re.search(r'RG_VERSION="([\d.]+)"', sh).group(1)
        self.assertIn(f"$RG_VERSION = '{version}'", ps1)

        for var in ("AFTERPROMPT_DIR", "AFTERPROMPT_PYTHON", "AFTERPROMPT_RG", "AFTERPROMPT_RG_SHA256",
                    "AFTERPROMPT_RG_BASE_URL", "AFTERPROMPT_IGNORE_SYSTEM_RG", "AFTERPROMPT_BOOTSTRAP_ONLY"):
            self.assertIn(var, ps1, f"{var} is honoured by afterprompt.sh but not by afterprompt.ps1")

        for opt in ("--no-download", "--help", "--version", "--status"):
            self.assertIn(opt, ps1, f"{opt} is handled by afterprompt.sh but not by afterprompt.ps1")

        # The checksum must be a real pin, not a placeholder.
        for sha in re.findall(r"'([0-9a-f]{64})'", ps1):
            self.assertEqual(len(sha), 64)
        self.assertEqual(len(re.findall(r"'([0-9a-f]{64})'", ps1)), 2, "expected x86_64 and aarch64 pins")

        # The .cmd shim exists so an unsigned .ps1 still runs under the default execution policy.
        self.assertIn("-ExecutionPolicy Bypass", cmd)
        self.assertIn("afterprompt.ps1", cmd)

    def test_windows_launcher_does_not_bind_scan_options(self):  # S-7 (W4)
        """A param() block would let PowerShell claim options like --out before the scan sees them."""
        ps1 = open(os.path.join(REPO, "afterprompt.ps1"), encoding="utf-8").read()
        code = [ln for ln in ps1.splitlines() if not ln.lstrip().startswith("#")]
        self.assertFalse([ln for ln in code if "[CmdletBinding()]" in ln])
        self.assertFalse([ln for ln in code if re.match(r"\s*param\s*\(", ln)],
                         "afterprompt.ps1 must read $args instead of declaring parameters")
        self.assertIn("$ScanArgs = @($args)", ps1)

    def test_no_machine_specific_paths(self):  # S-8
        """Nothing that ships may hard-code one machine's paths, user or drive letter.

        Locations must be derived at run time (%USERPROFILE%, $env:TEMP, $HOME, the WSL automount
        root), or an install on any other machine inherits this one's layout.
        """
        files = ["afterprompt.sh", "afterprompt.ps1", "afterprompt.cmd", "tools/winrun.sh"]
        for dp, dns, fns in os.walk(os.path.join(REPO, "afterprompt")):
            dns[:] = [d for d in dns if d != "__pycache__"]
            files += [os.path.relpath(os.path.join(dp, fn), REPO) for fn in fns if fn.endswith(".py")]

        # An absolute Windows path with a real user or a fixed profile folder, rather than a variable.
        absolute_win = re.compile(r"[A-Za-z]:\\\\?(?:Users|Documents and Settings)\\\\?(?!<)[A-Za-z0-9_.-]+", re.I)
        # A unix home belonging to somebody in particular.
        absolute_home = re.compile(r"/(?:home|Users)/(?!<|\$|me\b|u\b|you\b)[a-z][a-z0-9_-]*/")
        offenders = []
        for rel in files:
            with open(os.path.join(REPO, rel), encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    code = line.split("#", 1)[0] if rel.endswith((".sh", ".py")) else line
                    for rx in (absolute_win, absolute_home):
                        m = rx.search(code)
                        if m:
                            offenders.append(f"{rel}:{i}: {m.group(0)}")
        self.assertEqual(offenders, [])

    def test_windows_launcher_derives_its_locations(self):  # S-9
        """The Windows launcher must discover Python and the architecture rather than assume them."""
        ps1 = open(os.path.join(REPO, "afterprompt.ps1"), encoding="utf-8").read()
        # No fixed Python version folders: a list like Python313 stops working when 3.14 ships.
        self.assertFalse(re.search(r"Python\d{2,3}\\python\.exe", ps1),
                         "discover Python installs instead of listing version folders")
        # A 32-bit PowerShell on 64-bit Windows would otherwise pick the wrong ripgrep build.
        self.assertIn("PROCESSOR_ARCHITEW6432", ps1)
        # GitHub refuses TLS below 1.2, which Windows PowerShell 5.1 may still default to.
        self.assertIn("Tls12", ps1)
        # Per-user locations, never a fixed folder.
        self.assertIn("$env:USERPROFILE", ps1)
        # The cmdlets it relies on arrived in PowerShell 5; an older machine gets a clear message.
        self.assertIn("$PSVersionTable.PSVersion.Major -lt 5", ps1)

    def test_python_override_accepts_a_bare_command_name(self):  # S-10 (W4)
        """AFTERPROMPT_PYTHON=python must work in both launchers.

        afterprompt.sh resolves it with `command -v`; the PowerShell launcher must resolve it with
        Get-Command rather than only Test-Path, or a bare name is rejected and the scan never runs.
        CI passes exactly that, and it is the failure this test exists to prevent.
        """
        ps1 = open(os.path.join(REPO, "afterprompt.ps1"), encoding="utf-8").read()
        block = re.search(r"function Find-Python \{.*?\n\}", ps1, re.S)
        self.assertTrue(block, "Find-Python not found in afterprompt.ps1")
        body = block.group(0)
        self.assertIn("AFTERPROMPT_PYTHON", body)
        override = body[body.index("AFTERPROMPT_PYTHON"):]
        self.assertIn("Get-Command $override", override,
                      "a bare command name in AFTERPROMPT_PYTHON must be resolved, not only path-tested")
