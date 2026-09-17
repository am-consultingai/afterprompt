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
