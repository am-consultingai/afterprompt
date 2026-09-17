import json
import os
import time

from afterprompt import vendor
from afterprompt.patterns import PATTERNS
from tests.helpers import TempDirTest, jwt, make_cfg, requires_rg, write
from tests.samples import SecretFactory


@requires_rg
class VendorTests(TempDirTest):
    def test_hit_rows(self):  # U-VEN-1
        f = SecretFactory(3)
        key = f.sample("anthropic_key")
        token = jwt(f, int(time.time()) - 100)
        pw = f.chars("a", 14)
        path = write(os.path.join(self.tmp, "data", "s.jsonl"),
                     f'{{"text": "ANTHROPIC_API_KEY={key}\\nnext"}}\n'
                     f"token {token}\n"
                     f"postgres://app:{pw}@localhost:5432/db\n")
        cfg = make_cfg(self.tmp)
        pats = [p for p in PATTERNS if p[0] in ("anthropic_key", "env_assignment", "jwt", "url_with_credentials")]
        stats = vendor.run(cfg, "raw", [os.path.dirname(path)], patterns=pats)
        with open(cfg.w("vendor_raw.jsonl"), encoding="utf-8") as fh:
            raw = fh.read()
        rows = [json.loads(l) for l in raw.splitlines()]
        self.assertGreaterEqual(stats["hits"], 4)
        for secret in (key, token, pw):
            self.assertNotIn(secret, raw)
        by = {r["p"]: r for r in rows}
        self.assertEqual(by["anthropic_key"]["vh"], by["env_assignment"]["vh"])
        self.assertTrue(by["anthropic_key"]["m"].startswith("sk-ant"))
        self.assertIsNotNone(by["jwt"]["exp"])
        self.assertTrue(by["url_with_credentials"]["local"])
        self.assertIn("⟪HIT⟫", by["anthropic_key"]["ctx"])

    def test_pattern_timeout(self):  # U-VEN-2
        path = write(os.path.join(self.tmp, "data", "big.txt"), ("a" * 5000 + "\n") * 2000)
        cfg = make_cfg(self.tmp, pattern_timeout=0.001)
        stats = vendor.run(cfg, "raw", [os.path.dirname(path)], patterns=[("slow", r"(?:a|aa)+b", "C")])
        self.assertTrue(any("timed out" in t for t in stats["truncated"]))


class SecretLikeTests(TempDirTest):  # U-VEN-3
    def test_secret_like(self):
        self.assertTrue(vendor.secret_like(b"Xy7pQ2mL9wRt"))
        for v in (b"+%Y-%m-%dT%H:%M:%SZ", b"$EXA_TOKEN", b"var.db_password", b"short1", b"${password}"):
            self.assertFalse(vendor.secret_like(v), v)

    def test_vendor_like_and_b64_text(self):  # U-VEN-4
        import base64
        self.assertTrue(vendor.vendor_like(b"hf_" + b"QwErTyUiOpAsDfGhJkLzXcVbNmQwErTyUi"))
        self.assertFalse(vendor.vendor_like(b"keyVaultName12"))
        self.assertTrue(vendor.decodes_to_text(base64.b64encode(b"invalid-storage-key-for-tests-only")))
        self.assertFalse(vendor.decodes_to_text(base64.b64encode(bytes(range(64)))))

