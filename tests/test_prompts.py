import json
import os

from afterprompt import prompts
from tests.helpers import TempDirTest, cursor_db, jsonl, make_cfg, write


class PromptTests(TempDirTest):
    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        self.cfg = make_cfg(self.tmp, "linux", self.home)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)
        self.srcs = {"platform": "linux", "windows_home": None, "self_exclude": []}

    def test_history(self):  # U-PRM-1
        jsonl(os.path.join(self.home, ".claude", "history.jsonl"), [
            {"display": "deploy it", "pastedContents": {"1": {"content": "pasted text body"}}, "timestamp": 1757000000000}])
        texts = [p[2] for p in prompts.collect_prompts(self.cfg, self.srcs)]
        self.assertEqual(texts, ["deploy it\npasted text body"])

    def test_transcripts_user_text_only(self):  # U-PRM-2
        jsonl(os.path.join(self.home, ".claude", "projects", "-p", "s.jsonl"), [
            {"type": "user", "message": {"content": "user typed this"}},
            {"type": "user", "message": {"content": [{"type": "tool_result", "content": "tool output"},
                                                     {"type": "text", "text": "and this"}]}},
            {"type": "assistant", "message": {"content": "assistant said"}}])
        texts = sorted(p[2] for p in prompts.collect_prompts(self.cfg, self.srcs))
        self.assertEqual(texts, ["and this", "user typed this"])

    def test_cursor_bubbles(self):  # U-PRM-3
        from afterprompt import cursor
        db = os.path.join(self.tmp, "state.vscdb")
        cursor_db(db, [(1, "cursor user prompt"), (2, "cursor reply")])
        cursor.extract(self.cfg, {"cursor_dbs": [{"path": db, "side": "linux"}]})
        texts = [p[2] for p in prompts.collect_prompts(self.cfg, self.srcs)]
        self.assertEqual(texts, ["cursor user prompt"])

    def test_candidate_filters(self):  # U-PRM-4
        text = ("my password is Tr0ub4dor&3x please. see https://example.org/a1b2c3d4 and src/app/main9.py "
                "commit 3f2a9c1d7e and myVariableName2 on 2026-09-17")
        _, cands = prompts.candidates([("s", "?", text)])
        shapes = [c["shape"] for c in cands]
        self.assertEqual(len(cands), 1, shapes)
        self.assertTrue(cands[0]["kw"])

    def test_output_has_no_token(self):  # U-PRM-5
        jsonl(os.path.join(self.home, ".claude", "history.jsonl"),
              [{"display": "the vpn password is Qz7xW2pL9mR4 ok", "timestamp": 1757000000000}])
        prompts.run(self.cfg, self.srcs)
        with open(self.cfg.w("prompts.json"), encoding="utf-8") as fh:
            raw = fh.read()
        self.assertNotIn("Qz7xW2pL9mR4", raw)
        self.assertEqual(len(json.loads(raw)), 1)
