import json
import os
import re
import unittest

from afterprompt import report
from afterprompt.util import write_json
from tests.helpers import TempDirTest, make_cfg

FINDING = {"id": "R1", "category": "live_credential", "label": "Anthropic API key", "masked": "sk-ant…Ab12",
           "length": 108, "hash": "3f9c0a1b2c3d4e5f", "match_hashes": [], "patterns": ["anthropic_key"], "tier": "A",
           "tools": ["Claude Code"], "sides": ["wsl"], "files": 1, "occurrences": 2,
           "locations": [{"display": "~/.claude/projects/<script>alert(1)</script>/s.jsonl", "tool": "Claude Code",
                          "side": "wsl", "count": 2, "decoded": False}],
           "decoded_only": False, "still_on_disk": [{"store": "~/app/.env", "key": "ANTHROPIC_API_KEY"}],
           "revoke": {"where": "Anthropic Console", "url": "https://console.anthropic.com/settings/keys"},
           "reason": "A credential that is set up on this machine appears in AI assistant history.", "context": "x",
           "impact": "money"}


class ReportCase(TempDirTest):
    def write_report(self, rotate, review=()):
        cfg = make_cfg(self.tmp, "wsl", os.path.join(self.tmp, "home"))
        write_json(cfg.w("triage.json"), {"rotate": list(rotate), "review": list(review),
                                          "review_totals": {"pattern": len(review)}, "review_truncated": {},
                                          "dismissed": {"expired token": 2}})
        write_json(cfg.w("state", "manifest.done"), {"files": 3, "bytes": 1234, "per_source": [
            {"tool": "Claude Code", "side": "wsl", "files": 3, "bytes": 1234}], "unreadable": 0})
        data = report.write(cfg, {"platform": "wsl", "windows_home": None, "windows_home_source": "not found",
                                  "missing": []}, {"run_id": "20260917-120000", "started": "2026-09-17T12:00:00"})
        return cfg, data

    def read(self, cfg, name):
        with open(os.path.join(cfg.report_dir, name), encoding="utf-8") as fh:
            return fh.read()


class ReportTests(ReportCase):
    def test_markdown(self):  # U-REP-1
        review = [dict(FINDING, id="V1", category="pattern", label="Prefixed API key", masked="api_ab…cdef")]
        cfg, _ = self.write_report([FINDING], review)
        md = self.read(cfg, "report.md")
        for heading in ("## Rotate now", "## Review", "## What to do next", "## Coverage",
                        "## What this scan cannot see"):
            self.assertIn(heading, md)
        self.assertIn("sk-ant…Ab12", md)
        self.assertIn("Anthropic Console", md)

    def test_html_escaping(self):  # U-REP-2
        cfg, _ = self.write_report([FINDING])
        html = self.read(cfg, "report.html")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html)

    def test_html_self_contained(self):  # U-REP-3
        cfg, _ = self.write_report([FINDING])
        html = self.read(cfg, "report.html")
        self.assertNotIn("<script", html.replace("&lt;script", ""))
        self.assertFalse(re.search(r'src="https?://', html))
        remote_hrefs = re.findall(r'<a href="(https?://[^"]+)"[^>]*>', html)
        self.assertEqual(remote_hrefs, ["https://console.anthropic.com/settings/keys"])
        self.assertIn('rel="noreferrer noopener"', html)
        self.assertNotIn("<link rel=\"stylesheet\"", html)        # the stylesheet is inline, not a file
        written = {f for f in os.listdir(cfg.report_dir) if not os.path.isdir(os.path.join(cfg.report_dir, f))}
        self.assertEqual(sorted(written), ["findings.json", "report.html", "report.md"])
        here = os.path.join(os.path.dirname(report.__file__), "assets", "NOTICE.md")
        self.assertTrue(os.path.exists(here))

    def test_empty(self):  # U-REP-4
        cfg, data = self.write_report([])
        self.assertIn("Nothing to rotate", self.read(cfg, "report.html"))
        self.assertIn("Nothing to rotate", self.read(cfg, "report.md"))

    def test_findings_schema(self):  # U-REP-5
        cfg, _ = self.write_report([FINDING])
        data = json.loads(self.read(cfg, "findings.json"))
        self.assertEqual(set(data), {"schema", "tool", "version", "run_id", "mode", "started", "finished", "platform",
                                     "summary", "rotate", "review", "review_totals", "review_truncated", "dismissed", "review_dropped",
                                     "coverage"})
        self.assertEqual(set(data["rotate"][0]), set(FINDING))
        self.assertEqual(data["summary"]["rotate"], 1)

    def write_review(self, review, totals=None):
        cfg = make_cfg(self.tmp, "wsl", os.path.join(self.tmp, "home"))
        write_json(cfg.w("triage.json"), {"rotate": [], "review": review,
                                          "review_totals": totals or {"pattern": len(review)},
                                          "review_truncated": {}, "dismissed": {}})
        write_json(cfg.w("state", "manifest.done"), {"files": 1, "bytes": 1, "per_source": [], "unreadable": 0})
        report.write(cfg, {"platform": "wsl", "windows_home": None, "windows_home_source": "not found",
                           "missing": []}, {"run_id": "r", "started": "2026-09-17T12:00:00"})
        return cfg

    def test_repeats_from_one_file_are_one_row(self):  # U-REP-6
        """70 values of the same kind out of one transcript used to spend the whole shown budget."""
        review = [dict(FINDING, id=f"V{i}", category="pattern", label="Airtable API key",
                       masked=f"key{i:02d}…cdef", hash=f"h{i}") for i in range(70)]
        cfg = self.write_review(review)
        md = self.read(cfg, "report.md")
        self.assertEqual(md.count("Airtable API key"), 1)
        self.assertIn("Airtable API key ×70", md)
        self.assertNotIn("more in findings.json", md)
        self.assertIn("×70", self.read(cfg, "report.html"))
        self.assertEqual(len(json.loads(self.read(cfg, "findings.json"))["review"]), 70)

    def test_variety_is_still_capped(self):  # U-REP-6b
        """Different findings in different places are still rows, and the cap still bites."""
        review = [dict(FINDING, id=f"V{i}", category="pattern", label=f"Prefixed API key {i}",
                       masked=f"api_{i:02d}…cdef", hash=f"h{i}",
                       locations=[dict(FINDING["locations"][0], display=f"~/p/{i}.jsonl")]) for i in range(70)]
        cfg = self.write_review(review, {"pattern": 70})
        md = self.read(cfg, "report.md")
        self.assertEqual(md.count("Prefixed API key"), 60)
        self.assertIn("and 10 more in findings.json", md)
        self.assertEqual(len(json.loads(self.read(cfg, "findings.json"))["review"]), 70)

    def test_clusters_do_not_cross_places(self):  # U-REP-6c
        a = [dict(FINDING, id=f"V{i}", category="pattern", label="Airtable API key", masked=f"key{i}…cdef",
                  hash=f"a{i}") for i in range(3)]
        b = [dict(FINDING, id=f"W{i}", category="pattern", label="Airtable API key", masked=f"key{i}…wxyz",
                  hash=f"b{i}", locations=[dict(FINDING["locations"][0], display="~/other.jsonl")])
             for i in range(2)]
        md = self.read(self.write_review(a + b), "report.md")
        self.assertIn("Airtable API key ×3", md)
        self.assertIn("Airtable API key ×2", md)

    def test_the_list_has_an_entry_point(self):  # U-REP-8
        """Twenty findings with no order reads as an afternoon; the report picks the first three."""
        rotate = [dict(FINDING, id=f"R{i}", hash=f"r{i}", label=f"Key {i}",
                       impact=["data", "access", "money", "service"][i % 4]) for i in range(6)]
        cfg, _ = self.write_report(rotate)
        md, html = self.read(cfg, "report.md"), self.read(cfg, "report.html")
        self.assertIn("Start here", md)
        self.assertIn("Start here", html)
        self.assertIn('id="R1"', html)
        self.assertIn('href="#R1"', html)
        # The impact of each finding is on the card, in words rather than a rank number.
        self.assertIn("Can reach stored data", html)
        self.assertIn("Impact: Can reach stored data", md)

    def test_a_short_list_needs_no_lead(self):  # U-REP-8b
        cfg, _ = self.write_report([FINDING])
        self.assertNotIn("Start here", self.read(cfg, "report.md"))

    def test_the_headline_is_one_number(self):  # U-REP-9
        """Two big numbers side by side, the second in red, read as two piles of work."""
        review = [dict(FINDING, id=f"V{i}", category="pattern", hash=f"h{i}") for i in range(5)]
        cfg, _ = self.write_report([FINDING], review)
        html, md = self.read(cfg, "report.html"), self.read(cfg, "report.md")
        self.assertIn("Weaker signals to review", html)
        self.assertIn("Weaker signals to review: 5", md)
        self.assertNotIn("<span>To review</span>", html)
        self.assertNotIn('class="stat warn"', html)

    def test_entropy_counted_separately(self):  # U-REP-7
        cfg = make_cfg(self.tmp, "wsl", os.path.join(self.tmp, "home"), mode="deep")
        write_json(cfg.w("triage.json"), {"rotate": [], "review": [], "review_totals": {"pattern": 3, "entropy": 9000},
                                          "review_truncated": {"entropy": 8970}, "dismissed": {}})
        write_json(cfg.w("state", "manifest.done"), {"files": 1, "bytes": 1, "per_source": [], "unreadable": 0})
        data = report.write(cfg, {"platform": "wsl", "windows_home": None, "windows_home_source": "x", "missing": []},
                            {"run_id": "r", "started": "2026-09-17T12:00:00"})
        self.assertEqual(data["summary"]["review"], 3)
        self.assertEqual(data["summary"]["entropy_candidates"], 9000)
        self.assertIn("Random-looking tokens: 9,000", self.read(cfg, "report.md"))



class WindowsReportTests(unittest.TestCase):
    """W3: a native Windows run must read as Windows, without the WSL bridge's profile note."""

    def data(self, kind, windows_home=None):
        return {"finished": "2026-09-18T09:00:00", "mode": "quick",
                "platform": {"kind": kind, "home": "~", "windows_home": windows_home,
                             "windows_home_source": "this machine" if kind == "windows" else "cmd.exe"}}

    def test_context_line(self):  # U-REP-W1 (W3)
        self.assertEqual(report.context_line(self.data("windows", "C:\\Users\\me")),
                         "2026-09-18 09:00 · quick scan · Windows")
        self.assertEqual(report.context_line(self.data("wsl", "C:\\Users\\me")),
                         "2026-09-18 09:00 · quick scan · Windows (WSL) · Windows profile C:\\Users\\me")
        self.assertEqual(report.context_line(self.data("linux")), "2026-09-18 09:00 · quick scan · Linux")


class WslDistroCoverageTests(unittest.TestCase):
    """W5 / D1: a clean result must not imply anything about environments it did not cover, and the report never
    hands work back to the user ("run it there yourself")."""

    def rows(self, **cov):
        base = {"platform": "windows", "windows_home": "C:\\Users\\me", "windows_home_source": "this machine",
                "sources": [], "databases": {"total": 0, "ok": 0, "failed": []}, "unreadable_files": 0,
                "excluded_files": 0, "vendored_files": 0, "scan_session_files": 0, "live_values": {},
                "prompts": {}, "limits": [], "missing_locations": [], "pattern_truncations": [],
                "keychain": "not requested"}
        base.update(cov)
        return dict(report.coverage_rows({"coverage": base}))

    def test_other_users_are_named_not_read(self):  # U-REP-W2 (W5, D1 decision 4)
        row = self.rows(other_homes=["alice", "bob"])["Other users on this machine"]
        self.assertIn("alice, bob", row)
        self.assertIn("never elevates", row)

    def test_single_environment_has_no_environment_noise(self):  # U-REP-W3 (W5)
        """A machine with no WSL is complete as scanned: no caveat, no noise."""
        rows = self.rows()
        self.assertFalse(any(k.startswith(("Environment:", "Other users", "WSL distributions")) for k in rows))
        for text in rows.values():
            self.assertNotIn("run Afterprompt inside", text)


class LookTests(ReportCase):
    """One report style, self-contained, carrying the Afterprompt mark and the AM Consulting credit."""

    def files(self, cfg):
        return sorted(os.listdir(cfg.report_dir))

    def test_one_look_no_choice(self):  # U-REP-T1
        cfg, _ = self.write_report([FINDING])
        html = self.read(cfg, "report.html")
        self.assertNotIn("report-assets", html)
        self.assertIn('content="light dark"', html)
        self.assertIn('<span class="wordmark">', html)
        self.assertIn("Built by AM Consulting", html)
        self.assertIn("Built by AM Consulting", self.read(cfg, "report.md"))
        # The style is not selectable any more: no theme anywhere in the code that writes it.
        self.assertFalse(hasattr(report, "THEMES"))
        with open(os.path.join(os.path.dirname(report.__file__), "cli.py"), encoding="utf-8") as fh:
            self.assertNotIn("--theme", fh.read())

    def test_the_report_is_one_file(self):  # U-REP-T2
        """It gets emailed and opened somewhere else; a sibling folder it depends on is a footgun."""
        cfg, _ = self.write_report([FINDING])
        html = self.read(cfg, "report.html")
        self.assertIn('viewBox="0 0 64 40"', html)                  # the mark, inline
        self.assertIn('rel="icon" href="data:image/svg+xml', html)  # the icon, inline
        self.assertIn("<style>", html)                              # and the stylesheet, inline
        self.assertIn("--ink", html)
        self.assertNotIn("report-assets", self.files(cfg))
        self.assertEqual([f for f in self.files(cfg) if f.endswith((".css", ".png"))], [])

    def test_a_folder_from_an_older_version_is_cleaned(self):  # U-REP-T3
        cfg, _ = self.write_report([FINDING])
        stale = os.path.join(cfg.report_dir, "report-assets")
        os.makedirs(stale, exist_ok=True)
        with open(os.path.join(stale, "brand.css"), "w", encoding="utf-8") as fh:
            fh.write("/* left by an older version */")
        cfg, _ = self.write_report([FINDING])
        self.assertFalse(os.path.exists(stale))

    def test_it_is_self_contained(self):  # U-REP-T4
        cfg, _ = self.write_report([FINDING])
        html = self.read(cfg, "report.html")
        self.assertFalse(re.search(r'(?:src|href)="(?!data:|#|https://console)[^"]+"', html))
        with open(os.path.join(os.path.dirname(report.__file__), "assets", "report.css"), encoding="utf-8") as fh:
            self.assertNotIn("@import", fh.read())

    def test_the_notice_still_covers_what_ships(self):  # U-REP-T5
        """report.css ships under the project license; the NOTICE must not claim it."""
        here = os.path.join(os.path.dirname(report.__file__), "assets")
        with open(os.path.join(here, "NOTICE.md"), encoding="utf-8") as fh:
            notice = fh.read()
        self.assertIn("report.css", notice)
        # AM Consulting's own marks are bundled for the About screen and are not ours to license.
        self.assertIn("am-logo", notice)
        with open(os.path.join(here, "report.css"), encoding="utf-8") as fh:
            css = fh.read()
        self.assertIn("FSL-1.1-ALv2", css)


class DroppedReasonsTests(unittest.TestCase):
    def test_reasons_listed_in_coverage(self):  # U-REP-D1
        cov = {"platform": "linux", "sources": [], "databases": {"total": 0, "ok": 0, "failed": []},
               "unreadable_files": 0, "excluded_files": 0, "vendored_files": 0, "scan_session_files": 0,
               "live_values": {}, "prompts": {}, "limits": [], "missing_locations": [], "pattern_truncations": [],
               "keychain": "not requested"}
        rows = dict(report.coverage_rows({"coverage": cov, "review_dropped": {"entropy": {"shape: slug": 1200,
                                                                                         "no secret-related word right before it": 40}}}))
        self.assertEqual(rows["Random-looking tokens not shown"],
                         "shape: slug: 1,200; no secret-related word right before it: 40")
        self.assertNotIn("Random-looking tokens not shown", dict(report.coverage_rows({"coverage": cov})))
