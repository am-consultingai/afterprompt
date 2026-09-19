"""M2 / M3: one report from several environments."""
import copy
import unittest

from afterprompt import merge, report
from afterprompt.triage import CAPS


def rec(h, category="pattern", label="GitHub token", tier="A", files=1, occ=1, side="windows", display="~/a.jsonl",
        tools=("Cursor",), still=(), entropy=0.0, context=None, revoke=None, patterns=("github_token",)):
    return {"id": "X", "category": category, "label": label, "masked": f"m-{h}", "length": 40, "hash": h,
            "match_hashes": [f"mh-{h}"], "patterns": list(patterns), "tier": tier, "tools": list(tools),
            "sides": [side], "files": files, "occurrences": occ,
            "locations": [{"display": display, "tool": tools[0], "side": side, "count": occ, "decoded": False}],
            "decoded_only": False, "still_on_disk": [{"store": s, "key": "K"} for s in still], "revoke": revoke,
            "reason": "r", "context": context, "entropy": entropy}


def data(rotate=(), review=(), totals=None, dismissed=None, files=10, side="windows", other_homes=()):
    review = list(review)
    t = {c: 0 for c in ("configuration", "pattern", "session_cookie", "entropy", "prompt")}
    for r in review:
        t[r["category"]] += 1
    t.update(totals or {})
    return {"schema": 1, "version": "x", "mode": "quick", "finished": "2026-09-19T10:00:00",
            "platform": {"kind": "windows", "home": "~", "windows_home": None, "windows_home_source": "this machine"},
            "summary": {"rotate": len(rotate), "review": 0, "entropy_candidates": 0, "review_shown": 0, "dismissed": 0},
            "rotate": list(rotate), "review": review, "review_totals": t, "review_truncated": {},
            "dismissed": dict(dismissed or {}),
            "coverage": {"platform": "windows", "sources": [{"tool": "Cursor", "side": side, "files": files, "bytes": 100}],
                         "files": files, "bytes": 100, "databases": {"total": 1, "ok": 1, "failed": []},
                         "unreadable_files": 1, "excluded_files": 0, "vendored_files": 2, "scan_session_files": 0,
                         "pattern_truncations": [], "missing_locations": [], "keychain": "not requested",
                         "live_values": {"values": 3, "stores": 1, "env_files": 1, "credential_named_files": 0,
                                         "walk_truncated": [], "expired_skipped": 0, "prefix_keys": 1, "occurrences": 2},
                         "prompts": {"unique_prompts": 5}, "limits": ["x"], "other_homes": list(other_homes)}}


HOST = {"name": "Windows", "kind": "host", "label": "Windows (this machine)", "side": "windows", "home": ""}


def result(name, findings, status="scanned", reason=None, notice=None, other_homes=()):
    return {"name": name, "kind": "wsl", "label": f"WSL: {name}", "side": f"wsl:{name}", "home": "",
            "status": status, "reason": reason, "notice": notice, "other_homes": list(other_homes),
            "findings": findings, "exit": 0}


class MergeFindingsTests(unittest.TestCase):
    def test_same_value_in_two_environments_is_one_finding(self):  # U-MRG-1
        host = data(rotate=[rec("h1", files=1, occ=2, display=r"C:\Users\me\a.vscdb (chat database)")])
        ubu = data(rotate=[rec("h1", files=2, occ=3, side="wsl", display="~/.claude/s.jsonl", tools=("Claude Code",))],
                   side="wsl")
        out = merge.merge(host, HOST, [result("Ubuntu", ubu)])
        self.assertEqual(len(out["rotate"]), 1)
        r = out["rotate"][0]
        self.assertEqual((r["files"], r["occurrences"]), (3, 5))
        self.assertEqual(r["tools"], ["Claude Code", "Cursor"])
        self.assertEqual(r["sides"], ["windows", "wsl:Ubuntu"])
        self.assertEqual([l["display"] for l in r["locations"]],
                         ["[Ubuntu] ~/.claude/s.jsonl", r"C:\Users\me\a.vscdb (chat database)"])
        self.assertEqual(r["id"], "R1")
        self.assertEqual(report.where(r), "Claude Code, Cursor (Windows, WSL: Ubuntu)")

    def test_rotate_wins_over_review(self):  # U-MRG-2
        host = data(review=[rec("h1", category="configuration", label="Secret from ~/.cursor/mcp.json (HF_TOKEN)")])
        ubu = data(rotate=[rec("h1", category="live_credential", label="Hugging Face token", still=["~/.env"])])
        out = merge.merge(host, HOST, [result("Ubuntu", ubu)])
        self.assertEqual(out["review"], [])
        self.assertEqual(out["rotate"][0]["category"], "live_credential")
        self.assertEqual(out["rotate"][0]["label"], "Hugging Face token")
        self.assertEqual(out["rotate"][0]["still_on_disk"], [{"store": "[Ubuntu] ~/.env", "key": "K"}])
        self.assertEqual(out["summary"]["rotate"], 1)
        self.assertEqual(out["summary"]["review"], 0)

    def test_live_credential_beats_pattern_in_rotate(self):  # U-MRG-3
        host = data(rotate=[rec("h1", category="pattern", revoke={"where": "GitHub", "url": "u"}, context="ctx")])
        ubu = data(rotate=[rec("h1", category="live_credential", label="Credential", patterns=())])
        r = merge.merge(host, HOST, [result("Ubuntu", ubu)])["rotate"][0]
        self.assertEqual(r["category"], "live_credential")
        self.assertEqual(r["label"], "GitHub token")        # a generic label gives way to a specific one
        self.assertEqual(r["revoke"], {"where": "GitHub", "url": "u"})
        self.assertEqual(r["context"], "ctx")
        self.assertEqual(r["patterns"], ["github_token"])

    def test_review_category_strength(self):  # U-MRG-4
        host = data(review=[rec("h1", category="prompt", tier=None, entropy=4.0)])
        ubu = data(review=[rec("h1", category="configuration", entropy=1.0)])
        out = merge.merge(host, HOST, [result("Ubuntu", ubu)])
        self.assertEqual([r["category"] for r in out["review"]], ["configuration"])
        self.assertEqual(out["review"][0]["entropy"], 4.0)
        self.assertEqual(out["review_totals"]["configuration"], 1)
        self.assertEqual(out["review_totals"]["prompt"], 0)

    def test_distinct_values_stay_distinct_and_sorted(self):  # U-MRG-5
        host = data(rotate=[rec("a", category="pattern", tier="A", files=1)],
                    review=[rec("p", category="pattern", tier="C"), rec("c", category="configuration")])
        ubu = data(rotate=[rec("b", category="live_credential", files=4)], review=[rec("q", category="pattern", tier="A")])
        out = merge.merge(host, HOST, [result("Ubuntu", ubu)])
        self.assertEqual([r["hash"] for r in out["rotate"]], ["b", "a"])     # live credentials first
        self.assertEqual([r["id"] for r in out["rotate"]], ["R1", "R2"])
        self.assertEqual([r["hash"] for r in out["review"]], ["c", "q", "p"])  # category order, then tier
        self.assertEqual([r["id"] for r in out["review"]], ["V1", "V2", "V3"])

    def test_totals_keep_what_findings_json_did_not_list(self):  # U-MRG-6
        host = data(review=[rec("e1", category="entropy", tier=None)], totals={"entropy": 900})
        ubu = data(review=[rec("e1", category="entropy", tier=None), rec("e2", category="entropy", tier=None)],
                   totals={"entropy": 600})
        out = merge.merge(host, HOST, [result("Ubuntu", ubu)])
        # 2 listed after merging + 899 + 598 that only exist as counts
        self.assertEqual(out["review_totals"]["entropy"], 2 + 899 + 598)
        self.assertEqual(out["review_truncated"]["entropy"], out["review_totals"]["entropy"] - CAPS["entropy"])
        self.assertEqual(out["summary"]["entropy_candidates"], out["review_totals"]["entropy"])

    def test_dismissed_add_up(self):  # U-MRG-7
        out = merge.merge(data(dismissed={"expired token": 2}), HOST,
                          [result("Ubuntu", data(dismissed={"expired token": 1, "numeric value": 4}))])
        self.assertEqual(out["dismissed"], {"expired token": 3, "numeric value": 4})
        self.assertEqual(out["summary"]["dismissed"], 7)

    def test_inputs_are_not_modified(self):  # U-MRG-8
        host = data(rotate=[rec("h1")])
        ubu = data(rotate=[rec("h1")])
        before = copy.deepcopy((host, ubu))
        merge.merge(host, HOST, [result("Ubuntu", ubu)])
        self.assertEqual((host, ubu), before)

    def test_wsl_host_side_is_named_after_its_distro(self):  # U-MRG-9
        host_env = dict(HOST, name="Ubuntu", label="WSL: Ubuntu (this machine)", side="wsl:Ubuntu")
        host = data(rotate=[rec("h1", side="wsl"), rec("h2", side="windows")])
        out = merge.merge(host, host_env, [result("Debian", data(rotate=[rec("h1", side="linux")]))])
        by = {r["hash"]: r for r in out["rotate"]}
        self.assertEqual(by["h1"]["sides"], ["wsl:Debian", "wsl:Ubuntu"])
        self.assertEqual(by["h2"]["sides"], ["windows"])


class MergeCoverageTests(unittest.TestCase):
    def test_counts_add_up_per_environment(self):  # U-MRG-10
        ubu = data(files=30, side="linux")
        ubu["coverage"]["databases"]["failed"] = [{"path": "~/.config/Cursor/x.vscdb", "error": "locked"}]
        ubu["coverage"]["pattern_truncations"] = ["jwt"]
        ubu["coverage"]["decode"] = {"statuses": {"ok": 2}, "decoded_bytes": 10, "disk_cap_reached": True,
                                     "not_decoded": 1}
        out = merge.merge(data(files=10), HOST, [result("Ubuntu", ubu)])
        c = out["coverage"]
        self.assertEqual(c["files"], 40)
        self.assertEqual(c["unreadable_files"], 2)
        self.assertEqual(c["databases"]["total"], 2)
        self.assertEqual(c["databases"]["failed"][0]["path"], "[Ubuntu] ~/.config/Cursor/x.vscdb")
        self.assertEqual(c["pattern_truncations"], ["[Ubuntu] jwt"])
        self.assertEqual(c["live_values"]["values"], 6)
        self.assertEqual(c["prompts"]["unique_prompts"], 10)
        self.assertEqual([s["side"] for s in c["sources"]], ["windows", "wsl:Ubuntu"])
        self.assertEqual(c["decode"]["decoded_bytes"], 10)
        self.assertTrue(c["decode"]["disk_cap_reached"])

    def test_every_environment_has_a_status_line(self):  # U-MRG-11
        """A clean total must never hide a gap: the not-scanned environment is named, with its reason."""
        out = merge.merge(data(other_homes=["bob"]), HOST, [
            result("Ubuntu", data(files=5, rotate=[rec("x")]), notice="WSL: Ubuntu was not running; it was started"),
            result("Debian", None, status="not_scanned", reason="Python 3.9+ or ripgrep is not available there"),
            result("Kali", None, status="skipped", reason="--no-wsl was given")])
        self.assertEqual(out["schema"], 2)
        envs = {e["name"]: e for e in out["environments"]}
        self.assertEqual(list(envs), ["Windows", "Ubuntu", "Debian", "Kali"])
        self.assertEqual(envs["Windows"]["other_homes"], ["bob"])
        self.assertEqual((envs["Ubuntu"]["files"], envs["Ubuntu"]["rotate"]), (5, 1))
        self.assertEqual(out["summary"]["environments"], 4)
        self.assertEqual(out["summary"]["environments_not_scanned"], 1)   # skipping on request is not a gap
        rows = dict(report.coverage_rows(out))
        self.assertIn("scanned · 5 files", rows["Environment: WSL: Ubuntu"])
        self.assertIn("was not running", rows["Environment: WSL: Ubuntu"])
        self.assertEqual(rows["Environment: WSL: Debian"], "not scanned: Python 3.9+ or ripgrep is not available there")
        self.assertEqual(rows["Environment: WSL: Kali"], "skipped: --no-wsl was given")
        self.assertIn("bob", rows["Other users on Windows (this machine)"])
        for text in rows.values():
            self.assertNotIn("run Afterprompt inside", text)
        self.assertIn("4 environments", report.context_line(out))
        md, page = report.render_md(out), report.render_html(out)
        for text in (md, page):
            self.assertIn("WSL: Debian", text)
            self.assertIn("not scanned: Python 3.9+", text)

    def test_share_status_is_explicit(self):  # U-MRG-12
        out = merge.merge(data(), HOST, [result("Alpine", data(files=2), status="scanned_share")])
        rows = dict(report.coverage_rows(out))
        self.assertIn("network share (slower)", rows["Environment: WSL: Alpine"])


class SideLabelTests(unittest.TestCase):
    def test_labels(self):  # U-MRG-13
        self.assertEqual(report.side_label("wsl:Ubuntu-22.04"), "WSL: Ubuntu-22.04")
        self.assertEqual(report.side_label("env:Box"), "Box")
        self.assertEqual(report.side_label("windows"), "Windows")
        self.assertEqual(report.side_label("wsl"), "WSL")
