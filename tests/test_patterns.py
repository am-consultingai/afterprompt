import os
import re
import subprocess
import tempfile
import unittest

from afterprompt import patterns as P
from tests.helpers import requires_rg
from tests.samples import SAMPLES, SecretFactory

NAMES = [n for n, _, _ in P.PATTERNS]


class PatternTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        f = SecretFactory(2024)
        cls.samples = {n: f.sample(n) for n in NAMES}

    def test_completeness(self):  # U-PAT-1
        self.assertEqual(len(NAMES), 140)
        self.assertEqual(len(set(NAMES)), len(NAMES))
        self.assertEqual(set(SAMPLES), set(NAMES))
        self.assertEqual(set(P.LABELS), set(NAMES))

    def test_python_match(self):  # U-PAT-2
        for n, rx, _ in P.PATTERNS:
            with self.subTest(pattern=n):
                self.assertIsNotNone(re.search(P.escape_aware(rx), self.samples[n]))

    @requires_rg
    def test_ripgrep_match(self):  # U-PAT-3
        d = tempfile.mkdtemp()
        for n, rx, _ in P.PATTERNS:
            with self.subTest(pattern=n):
                p = os.path.join(d, n)
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write("prefix " + self.samples[n] + " suffix\n")
                r = subprocess.run(["rg", "-a", "-o"] + (["-U"] if n in P.MULTILINE else []) +
                                   ["-e", P.escape_aware(rx), p], capture_output=True)
                self.assertTrue(r.stdout, f"rg found no match for {n}")

    def test_json_escape_prefix(self):  # U-PAT-4
        for n, rx, _ in P.PATTERNS:
            if n in P.MULTILINE:
                continue
            with self.subTest(pattern=n):
                text = "\\n" + self.samples[n]
                m = re.search(P.escape_aware(rx), text)
                self.assertIsNotNone(m)
                stripped, off = P.strip_residue(m.group(0).encode(), m.start())
                self.assertFalse(stripped.startswith(b"\\n"))

    def test_sets_consistent(self):  # U-PAT-5
        tiers = P.TIERS
        self.assertTrue(all(tiers[n] == "B" for n in P.ROTATE_B))
        self.assertTrue(P.SESSION_COOKIE <= set(NAMES))
        self.assertTrue(set(P.REVOKE) <= set(NAMES))

    def test_label_for_value(self):  # U-PAT-6
        self.assertEqual(P.label_for_value(self.samples["anthropic_key"].encode()), "Anthropic API key")
        self.assertIsNone(P.label_for_value(b"justsomewordshere"))

    def test_xai_glued_and_long(self):  # U-PAT-7
        rx = re.compile(P.escape_aware(dict((n, r) for n, r, _ in P.PATTERNS)["xai_key"]))
        key = "xai-" + SecretFactory(5).chars("a", 108)
        self.assertIsNotNone(rx.search("GROKKEY" + key + " next"))

