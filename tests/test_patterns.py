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

    def test_revoke_links_point_where_the_credential_lives(self):  # U-PAT-8
        """Checked against the live redirects on 2026-09-20: a stale link sends someone to the wrong console."""
        self.assertEqual(P.REVOKE["anthropic_key"][1], "https://platform.claude.com/settings/keys")
        self.assertEqual(P.REVOKE["openrouter_key"][1], "https://openrouter.ai/workspaces/default/keys")
        self.assertEqual(P.REVOKE["vercel_token_ctx"][1], "https://vercel.com/account/settings/tokens")
        # Fine-grained tokens are not on the classic tokens page.
        self.assertEqual(P.REVOKE["github_fine_grained_pat"][1], "https://github.com/settings/personal-access-tokens")
        self.assertNotEqual(P.REVOKE["github_fine_grained_pat"][1], P.REVOKE["github_token"][1])
        for n in ("azure_devops_pat", "azure_devops_pat_ctx"):
            self.assertNotIn("portal.azure.com", P.REVOKE[n][1])   # a PAT is not managed from the Azure portal
        for n, (where, url) in P.REVOKE.items():
            with self.subTest(pattern=n):
                self.assertTrue(url.startswith("https://") and where)
                self.assertNotIn("console.anthropic.com", url)     # 301 since Anthropic moved the console

    def test_xai_glued_and_long(self):  # U-PAT-7
        rx = re.compile(P.escape_aware(dict((n, r) for n, r, _ in P.PATTERNS)["xai_key"]))
        key = "xai-" + SecretFactory(5).chars("a", 108)
        self.assertIsNotNone(rx.search("GROKKEY" + key + " next"))



class PatternFileTests(unittest.TestCase):
    """Patterns are data (patterns.json): a vendor changing its key format is an edit there, checked here."""

    def good(self):
        return {"schema": 1, "patterns": [{"name": "demo_key", "tier": "A", "regex": r"\bdemo_[a-z0-9]{20}\b",
                                           "label": "Demo key", "group": "Demo",
                                           "revoke": {"where": "Demo console", "url": "https://demo.example/keys"}}]}

    def test_shipped_file_is_valid(self):  # U-PAT-8
        import json
        with open(P.PATH, encoding="utf-8") as fh:
            self.assertEqual(P.validate(json.load(fh)), [])
        self.assertEqual(P.validate(self.good()), [])

    def test_every_mistake_is_reported(self):  # U-PAT-9
        import copy
        first = lambda d: d["patterns"][0]  # noqa: E731
        cases = {
            "expected": lambda d: d.update(schema=3),
            "lower_snake_case": lambda d: first(d).update(name="Demo Key"),
            "listed twice": lambda d: d["patterns"].append(copy.deepcopy(first(d))),
            "tier must be": lambda d: first(d).update(tier="D"),
            "regex missing": lambda d: first(d).pop("regex"),
            "does not compile": lambda d: first(d).update(regex="(unclosed"),
            "lookaround": lambda d: first(d).update(regex=r"demo(?=_key)"),
            "backreferences": lambda d: first(d).update(regex=r"(a)\1"),
            "label missing": lambda d: first(d).update(label=" "),
            "https:// url": lambda d: first(d)["revoke"].update(url="http://insecure.example"),
            "true or absent": lambda d: first(d).update(header_only=False),
            "only applies to tier B": lambda d: first(d).update(rotate_structural=True),
            "unknown fields": lambda d: first(d).update(severity="high"),
        }
        for want, fn in cases.items():
            with self.subTest(mistake=want):
                d = self.good()
                fn(d)
                errors = P.validate(d)
                self.assertTrue(any(want in e for e in errors), errors)

    def test_load_refuses_an_invalid_file(self):  # U-PAT-10
        import json
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"schema": 1, "patterns": [{"name": "x", "tier": "A", "regex": "(?<=a)b", "label": "X"}]}, fh)
        try:
            with self.assertRaises(P.PatternError) as cm:
                P.load(fh.name)
            self.assertIn("ripgrep", str(cm.exception))
        finally:
            os.remove(fh.name)

    def test_every_pattern_has_a_group(self):  # U-PAT-11
        self.assertTrue(all(r.get("group") for r in P.RULES))
