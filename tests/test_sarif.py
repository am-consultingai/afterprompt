"""report.sarif: SARIF 2.1.0 for code-scanning and SIEM pipelines, masked like every other output."""
import json
import os
import unittest

from afterprompt import __version__, sarif
from tests.helpers import Fixture, TempDirTest, requires_rg, run_dirs


def rec(category, display="~/.claude/projects/p/s.jsonl", h="abc123"):
    return {"id": "R1", "category": category, "label": "GitHub token", "masked": "ghp_Ab…9xYz", "hash": h,
            "reason": "Because.", "tools": ["Claude Code"], "sides": ["linux"], "occurrences": 2,
            "revoke": {"where": "GitHub", "url": "https://github.com/settings/tokens"},
            "locations": [{"display": display, "count": 2}]}


class SarifTests(unittest.TestCase):
    def test_shape(self):  # U-SAR-1
        doc = sarif.build({"mode": "quick", "summary": {"rotate": 1}, "rotate": [rec("live_credential")],
                           "review": [rec("configuration", h="c1"), rec("entropy", h="e1"), rec("prompt", h="p1")]})
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "Afterprompt")
        self.assertEqual(run["tool"]["driver"]["version"], __version__)
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertTrue({r["ruleId"] for r in run["results"]} <= rule_ids)
        levels = [(r["ruleId"], r["level"]) for r in run["results"]]
        self.assertEqual(levels, [("live_credential", "error"), ("configuration", "warning"), ("entropy", "note"),
                                  ("prompt", "warning")])
        self.assertEqual(run["results"][0]["partialFingerprints"], {"afterprompt/valueHash/v1": "abc123"})
        self.assertEqual(run["results"][0]["properties"]["section"], "rotate")
        json.dumps(doc)  # serialisable

    def test_rotate_is_always_an_error(self):  # U-SAR-2
        """A configuration secret that another environment saw leaked is merged into Rotate now: error, not warning."""
        r = sarif.result(rec("configuration"), "rotate")
        self.assertEqual(r["level"], "error")

    def test_locations(self):  # U-SAR-3
        loc = lambda d: sarif.location(d)["physicalLocation"]["artifactLocation"]  # noqa: E731
        self.assertEqual(loc("~/.claude/projects/my project/s.jsonl"),
                         {"uri": ".claude/projects/my%20project/s.jsonl", "uriBaseId": "HOME"})
        self.assertEqual(loc(r"C:\Users\me\AppData\Roaming\Cursor\User\globalStorage\state.vscdb (chat database)"),
                         {"uri": "file:///C:/Users/me/AppData/Roaming/Cursor/User/globalStorage/state.vscdb"})
        self.assertEqual(loc("[Ubuntu] ~/.codex/history.jsonl"), {"uri": ".codex/history.jsonl", "uriBaseId": "HOME"})
        self.assertEqual(loc("/opt/extra/notes.txt"), {"uri": "file:///opt/extra/notes.txt"})
        self.assertEqual(sarif.location("~/a")["message"]["text"], "~/a")

    def test_finding_without_locations_is_still_valid(self):  # U-SAR-4
        r = sarif.result(dict(rec("prompt"), locations=[]), "review")
        self.assertEqual(len(r["locations"]), 1)


@requires_rg
class SarifEndToEndTests(TempDirTest):
    def test_written_only_when_asked_and_masked(self):  # I-SAR-1
        fx = Fixture(self.tmp, "linux")
        p = fx.run()
        self.assertEqual(p.returncode, 10)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        self.assertFalse(os.path.exists(os.path.join(run, "report.sarif")))
        p = fx.run("--sarif", "--fresh")
        self.assertEqual(p.returncode, 10, p.stdout + p.stderr)
        run = os.path.join(fx.base, "runs", run_dirs(fx.base)[-1])
        with open(os.path.join(run, "report.sarif"), encoding="utf-8") as fh:
            text = fh.read()
        doc = json.loads(text)
        d = fx.findings()
        self.assertEqual(len(doc["runs"][0]["results"]), len(d["rotate"]) + len(d["review"]))
        for v in fx.s.values():
            self.assertNotIn(v, text)
