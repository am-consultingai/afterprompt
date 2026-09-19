import json
import os
import time

from afterprompt import triage
from afterprompt.util import write_json
from tests.helpers import TempDirTest, make_cfg, write, slash


class TriageTests(TempDirTest):
    """Synthetic work folders: manifest rows, vendor hits, live values, prompts."""

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        self.cfg = make_cfg(self.tmp, "linux", self.home)
        self.files = {}
        self.vendor = []
        self.known = []
        self.live = {}
        self.prompts = []
        self.n = 0

    def file(self, rel, vendored=False, self_=False, tool="Claude Code"):
        p = os.path.join(self.home, rel)
        if p not in self.files:
            self.files[p] = (len(self.files), vendored, self_, tool)
        return p

    def hit(self, rel, pattern, tier, vh, **kw):
        self.n += 1
        row = {"p": pattern, "t": tier, "f": self.file(rel, kw.pop("vendored", False), kw.pop("self_", False)),
               "o": self.n * 100, "vo": self.n * 100, "h": vh + pattern, "vh": vh, "m": f"mask-{vh}", "n": 40,
               "b64": False, "ph": False, "code": False, "ident": False, "num": False, "ve": 4.5, "exp": None,
               "local": False, "ctx": "ctx ⟪HIT⟫"}
        row.update(kw)
        self.vendor.append(row)

    def build(self):
        with open(self.cfg.w("manifest.tsv"), "w", encoding="utf-8") as fh:
            for p, (i, v, s, tool) in sorted(self.files.items(), key=lambda kv: kv[1][0]):
                fh.write(f"{i}\t10\t{int(v)}\t{int(s)}\t{tool}\tlinux\t{p}\n")
        with open(self.cfg.w("vendor_raw.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in self.vendor))
        with open(self.cfg.w("known.jsonl"), "w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in self.known))
        write_json(self.cfg.w("live_index.json"), self.live)
        write_json(self.cfg.w("prompts.json"), self.prompts)
        return triage.build(self.cfg, {"windows_home": None})

    def by_hash(self, out):
        rot = {r["hash"]: r for r in out["rotate"]}
        rev = {r["hash"]: r for r in out["review"]}
        return rot, rev

    def test_live_credential(self):  # U-TRI-1
        store = os.path.join(self.home, "app", ".env")
        self.live["v1"] = {"stores": [{"store": store, "key": "DB_PASSWORD", "designed": False}], "label": None,
                           "masked": "abc…xyz", "n": 20}
        self.known.append({"vh": "v1", "prefix": False, "f": self.file(".claude/projects/p/s.jsonl"), "o": 5})
        rot, _ = self.by_hash(self.build())
        r = rot["v1"]
        self.assertEqual(r["category"], "live_credential")
        self.assertEqual(slash(r["label"]), "Secret from ~/app/.env (DB_PASSWORD)")
        self.assertEqual([{**d, "store": slash(d["store"])} for d in r["still_on_disk"]],
                         [{"store": "~/app/.env", "key": "DB_PASSWORD"}])
        self.assertEqual(r["revoke"]["where"], "The service that issued DB_PASSWORD")

    def test_tier_a(self):  # U-TRI-2
        self.hit(".claude/projects/p/s.jsonl", "anthropic_key", "A", "a1")
        rot, _ = self.by_hash(self.build())
        self.assertEqual(rot["a1"]["revoke"]["where"], "Anthropic Console")

    def test_tier_b_and_c(self):  # U-TRI-3
        self.hit(".claude/projects/p/s.jsonl", "url_with_credentials", "B", "b1")
        self.hit(".claude/projects/p/s.jsonl", "prefixed_key", "B", "b2")
        self.hit(".claude/projects/p/s.jsonl", "env_assignment", "C", "c1")
        rot, rev = self.by_hash(self.build())
        self.assertIn("b1", rot)
        self.assertIn("b2", rev)
        self.assertIn("c1", rev)

    def test_session_cookie(self):  # U-TRI-4
        self.hit(".claude/projects/p/s.jsonl", "google_session_cookie_ctx", "A", "s1")
        _, rev = self.by_hash(self.build())
        self.assertEqual(rev["s1"]["category"], "session_cookie")

    def test_configuration(self):  # U-TRI-5
        self.hit(".cursor/mcp.json", "huggingface_token", "A", "h1")
        cj = self.file(".claude.json")
        self.live["h2"] = {"stores": [{"store": cj, "key": "mcpServers.x.env.K", "designed": False}], "label": None,
                           "masked": "m", "n": 30}
        self.hit(".claude.json", "brave_api_key", "A", "h2")
        _, rev = self.by_hash(self.build())
        self.assertEqual(rev["h1"]["category"], "configuration")
        self.assertEqual(rev["h2"]["category"], "configuration")

    def test_dismissals(self):  # U-TRI-6
        now = time.time()
        self.hit(".claude/projects/me/s.jsonl", "github_token", "A", "d1", self_=True)
        self.hit(".claude/plugins/x/node_modules/a.js", "stripe_secret_key", "A", "d2", vendored=True)
        self.hit(".claude/projects/p/s.jsonl", "openai_project_key", "A", "d3", b64=True)
        self.hit(".claude/.credentials.json", "anthropic_key", "A", "d4")
        self.hit(".claude/projects/p/s.jsonl", "openai_project_key", "A", "d5", ph=True)
        self.hit(".claude/projects/p/s.jsonl", "cli_secret_flag", "B", "d6", num=True)
        self.hit(".claude/projects/p/s.jsonl", "env_assignment", "C", "d7", code=True)
        self.hit(".claude/projects/p/s.jsonl", "jwt", "B", "d8", exp=now - 10)
        self.hit(".claude/projects/p/s.jsonl", "url_with_credentials", "B", "d9", local=True)
        out = self.build()
        self.assertEqual(out["rotate"], [])
        self.assertEqual(out["review"], [])
        self.assertEqual(set(out["dismissed"]), {
            "scan-session transcripts only", "vendored app or plugin code only", "only inside base64 blobs",
            "the tool's own credential store", "placeholder or environment reference", "numeric value",
            "source-code expression", "expired token", "local development connection string"})

    def test_merge(self):  # U-TRI-7
        store = os.path.join(self.home, "app", ".env")
        self.live["m1"] = {"stores": [{"store": store, "key": "ANTHROPIC_API_KEY", "designed": False}],
                           "label": "Anthropic API key", "masked": "sk-ant…", "n": 108}
        self.hit(".claude/projects/p/s.jsonl", "anthropic_key", "A", "m1")
        self.hit(".claude/projects/p/s.jsonl", "env_assignment", "C", "m1")
        self.known.append({"vh": "m1", "prefix": False, "f": self.file(".claude/projects/p/t.jsonl"), "o": 1})
        out = self.build()
        self.assertEqual(len(out["rotate"]), 1)
        r = out["rotate"][0]
        self.assertEqual(r["category"], "live_credential")
        self.assertEqual(r["patterns"], ["anthropic_key", "env_assignment"])
        self.assertEqual(r["files"], 2)

    def test_caps(self):  # U-TRI-8
        for i in range(70):
            self.hit(f".claude/projects/p/s{i}.jsonl", "prefixed_key", "B", f"cap{i}")
        out = self.build()
        self.assertEqual(len([r for r in out["review"] if r["category"] == "pattern"]), 70)
        self.assertEqual(out["review_truncated"]["pattern"], 10)
        self.assertEqual(out["review_totals"]["pattern"], 70)

    def test_ordering(self):  # U-TRI-9
        store = os.path.join(self.home, "app", ".env")
        self.hit(".claude/projects/p/s.jsonl", "url_with_credentials", "B", "o3")
        self.hit(".claude/projects/p/s.jsonl", "github_token", "A", "o2")
        self.live["o1"] = {"stores": [{"store": store, "key": "TOKEN", "designed": False}], "label": None,
                           "masked": "m", "n": 20}
        self.known.append({"vh": "o1", "prefix": False, "f": self.file(".claude/projects/p/s.jsonl"), "o": 1})
        out = self.build()
        self.assertEqual([r["hash"] for r in out["rotate"]], ["o1", "o2", "o3"])

    def test_unknown_files_ignored(self):  # U-TRI-10
        self.hit(".claude/projects/p/s.jsonl", "github_token", "A", "u1")
        self.build()
        self.vendor[0]["f"] = "/somewhere/else.txt"
        with open(self.cfg.w("vendor_raw.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps(self.vendor[0]) + "\n")
        out = triage.build(self.cfg, {"windows_home": None})
        self.assertEqual(out["rotate"], [])

    def test_location_resolution(self):  # U-TRI-11
        src = self.file(".claude/projects/p/s.jsonl")
        idx = self.files[src][0]
        self.hit(".claude/projects/p/other.jsonl", "github_token", "A", "r1")
        self.vendor[-1]["f"] = self.cfg.w("store", f"{idx}.txt")
        ext = self.cfg.w("extracted", "cursor", "000_00.txt")
        write(ext, "x")
        self.files[ext] = (len(self.files), False, False, "Cursor")
        write_json(self.cfg.w("extracted", "_ledger.json"),
                   [{"tag": "000", "db": os.path.join(self.home, ".config/Cursor/User/globalStorage/state.vscdb"),
                     "side": "linux", "status": "ok"}])
        self.n += 1
        self.vendor.append(dict(self.vendor[-1], f=ext, vh="r2", h="r2", o=5, vo=5))
        rot, _ = self.by_hash(self.build())
        self.assertTrue(rot["r1"]["locations"][0]["decoded"])
        self.assertEqual(slash(rot["r1"]["locations"][0]["display"]), "~/.claude/projects/p/s.jsonl")
        self.assertTrue(rot["r2"]["locations"][0]["display"].endswith("state.vscdb (chat database)"))
        self.assertEqual(rot["r2"]["tools"], ["Cursor"])

    def test_precision_gates(self):  # U-TRI-12
        self.hit(".claude/projects/p/s.jsonl", "airtable_key", "A", "g1", n=17, va=False)
        self.hit(".claude/projects/p/s.jsonl", "private_key_header", "B", "g2")
        self.hit(".claude/projects/p/s.jsonl", "pkcs8_rsa_key_body", "A", "g3")
        self.hit(".claude/projects/p/s.jsonl", "curl_user_flag", "B", "g4", vs=False)
        self.hit(".claude/projects/p/s.jsonl", "github_token", "A", "g5", va=False)
        self.hit(".claude/projects/p/s.jsonl", "huggingface_token", "A", "g7", vs=False, va=True)
        self.hit(".claude/projects/p/s.jsonl", "private_key_pem_body", "A", "g6")
        rot, rev = self.by_hash(self.build())
        self.assertEqual(set(rot), {"g6", "g7"})
        self.assertEqual(set(rev), {"g1", "g2", "g3", "g4", "g5"})

    def test_review_ranked_by_entropy(self):  # U-TRI-13
        self.hit(".claude/projects/p/a.jsonl", "env_assignment", "C", "low", vpe=2.5)
        self.hit(".claude/projects/p/b.jsonl", "env_assignment", "C", "high", vpe=4.9)
        out = self.build()
        self.assertEqual([r["hash"] for r in out["review"]], ["high", "low"])

    def test_entropy_filter_and_cap(self):  # U-TRI-14
        from afterprompt import triage as T
        self.cfg.mode = "deep"
        src = self.file(".claude/projects/p/s.jsonl")
        idx = self.files[src][0]
        rows = [{"h": "strong", "m": "Zx8Qw2…b7Kc", "n": 20, "c": "unclassified", "e": 4.3, "op": 0.3, "nk": True,
                 "nks": True, "f": idx, "o": 1},
                {"h": "weakword", "m": "Ab12Cd…Gh56", "n": 20, "c": "unclassified", "e": 4.3, "op": 0.3, "nk": True,
                 "nks": False, "f": idx, "o": 2},
                {"h": "lowercase", "m": "abcdef…mnop", "n": 20, "c": "unclassified", "e": 4.1, "op": 0.0, "nk": True,
                 "nks": True, "f": idx, "o": 3}]
        os.makedirs(self.cfg.w("entropy_raw"), exist_ok=True)
        with open(self.cfg.w("entropy_raw", "0.jsonl"), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"_counts": {}, "_status": "ok"}) + "\n")
            fh.write("".join(json.dumps(r) + "\n" for r in rows))
            for i in range(T.ENTROPY_KEEP_MAX + 5):
                fh.write(json.dumps(dict(rows[0], h=f"x{i}", op=0.2)) + "\n")
        out = self.build()
        hashes = [r["hash"] for r in out["review"] if r["category"] == "entropy"]
        self.assertEqual(hashes[0], "strong")
        self.assertNotIn("weakword", hashes)
        self.assertNotIn("lowercase", hashes)
        self.assertEqual(len(hashes), T.ENTROPY_KEEP_MAX)
        self.assertEqual(out["review_totals"]["entropy"], T.ENTROPY_KEEP_MAX + 6)

