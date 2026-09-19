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
           "reason": "A credential that is set up on this machine appears in AI assistant history.", "context": "x"}


class ReportTests(TempDirTest):
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
        self.assertNotIn('<link rel="stylesheet" href="http', html)
        for a in report.ASSETS:
            self.assertTrue(os.path.exists(os.path.join(cfg.report_dir, "report-assets", a)))
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
                                     "summary", "rotate", "review", "review_totals", "review_truncated", "dismissed",
                                     "coverage"})
        self.assertEqual(set(data["rotate"][0]), set(FINDING))
        self.assertEqual(data["summary"]["rotate"], 1)

    def test_review_capped_in_report_not_in_findings(self):  # U-REP-6
        review = [dict(FINDING, id=f"V{i}", category="pattern", label="Prefixed API key", masked=f"api_{i:02d}…cdef",
                       hash=f"h{i}") for i in range(70)]
        cfg = make_cfg(self.tmp, "wsl", os.path.join(self.tmp, "home"))
        write_json(cfg.w("triage.json"), {"rotate": [], "review": review, "review_totals": {"pattern": 70},
                                          "review_truncated": {"pattern": 10}, "dismissed": {}})
        write_json(cfg.w("state", "manifest.done"), {"files": 1, "bytes": 1, "per_source": [], "unreadable": 0})
        report.write(cfg, {"platform": "wsl", "windows_home": None, "windows_home_source": "not found", "missing": []},
                     {"run_id": "r", "started": "2026-09-17T12:00:00"})
        md = self.read(cfg, "report.md")
        self.assertEqual(md.count("Prefixed API key"), 60)
        self.assertIn("and 10 more in findings.json", md)
        self.assertEqual(len(json.loads(self.read(cfg, "findings.json"))["review"]), 70)

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
    """W5: a clean Windows result must not imply the distros are clean too."""

    def rows(self, **cov):
        base = {"platform": "windows", "windows_home": "C:\\Users\\me", "windows_home_source": "this machine",
                "sources": [], "cursor_databases": {"total": 0, "ok": 0, "failed": []}, "unreadable_files": 0,
                "excluded_files": 0, "vendored_files": 0, "scan_session_files": 0, "live_values": {},
                "prompts": {}, "limits": [], "missing_locations": [], "pattern_truncations": [],
                "keychain": "not requested"}
        base.update(cov)
        return dict(report.coverage_rows({"coverage": base}))

    def test_distros_are_named_when_present(self):  # U-REP-W2 (W5)
        rows = self.rows(wsl_distros=["Ubuntu-22.04", "Debian"])
        row = rows["WSL distributions found but not scanned"]
        self.assertIn("Ubuntu-22.04, Debian", row)
        self.assertIn("run Afterprompt inside each one", row)

    def test_no_row_without_wsl(self):  # U-REP-W3 (W5)
        """A machine with no WSL is complete as scanned: no caveat, no noise."""
        self.assertNotIn("WSL distributions found but not scanned", self.rows(wsl_distros=[]))
        self.assertNotIn("WSL distributions found but not scanned", self.rows())
