import os
import unittest

from afterprompt import entropy
from tests.helpers import TempDirTest, write


class ClassifyTests(unittest.TestCase):  # U-ENT-1
    def test_table(self):
        cases = {
            b"123e4567-e89b-12d3-a456-426614174000": "uuid",
            b"0123456789abcdef0123456789abcdef": "hex",
            b"src/components/Button9/index.tsx": "filename",
            b"src/components/button9/widgets": "path",
            b"alpha-beta-gamma-delta-2": "slug",
            b"com.google.android.gms.version": "dotted_name",
            b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0": "jwt",
            b"SomeLongIdentifierNameHere": "identifier",
            b"Zx8Qw2Lp9Rt5Mn3Vb7Kc": "unclassified",
        }
        for v, want in cases.items():
            with self.subTest(v=v):
                self.assertEqual(entropy.classify(v), want)


class SweepTests(TempDirTest):
    def test_long_payload_and_long_token(self):  # U-ENT-2
        import random
        r = random.Random(1)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
        long_tok = "".join(r.choice(alphabet) for _ in range(300))
        payload = "".join(r.choice(alphabet + "+/") for _ in range(3000))
        p = write(os.path.join(self.tmp, "a.txt"), f"x {payload} y\nsession={long_tok} z\n")
        rows, counts, status = entropy.sweep_path(p, 0, 60)
        self.assertEqual(status, "ok")
        classes = {r["c"] for r in rows.values()}
        self.assertIn("long_token", classes)
        self.assertFalse(any(r["n"] > 2256 for r in rows.values()))

    def test_keyword_proximity(self):  # U-ENT-3
        p = write(os.path.join(self.tmp, "b.txt"), "api_key: Zx8Qw2Lp9Rt5Mn3Vb7Kc\n" + "filler words " * 6 + "Qm4Wn8Er2Ty6Ui0Op5As\n")
        rows, _, _ = entropy.sweep_path(p, 0, 60)
        nk = {r["m"]: r["nk"] for r in rows.values()}
        self.assertTrue(nk["Zx8Qw2…b7Kc"])
        self.assertFalse(nk["Qm4Wn8…p5As"])
