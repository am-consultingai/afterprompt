"""More tool coverage: Antigravity, Aider (incl. per-project history), Goose, Qwen Code, LM Studio, Jan, Amp,
Junie, Devin CLI and Claude Desktop's local agent sessions. One planted secret per store, found end to end."""
import json
import os
import sqlite3

from afterprompt.util import mask
from tests.helpers import WINDOWS, Fixture, TempDirTest, jsonl, requires_rg, write
from tests.samples import SecretFactory


def db(path, table, cols, row):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute(f"create table {table} ({', '.join(cols)})")
    con.execute(f"insert into {table} values ({', '.join('?' for _ in cols)})", row)
    con.commit()
    con.close()


def plant(fx, f, platform):
    home = fx.home
    names = ["github_token", "slack_token", "stripe_secret_key", "groq_key", "huggingface_token", "sendgrid_key",
             "openai_project_key", "brave_api_key", "xai_key", "aws_access_key_id", "gitlab_token",
             "digitalocean_token", "notion_token"]
    keys = iter(f.sample(n) for n in names)
    s = {}

    def put(tag, rel, text_fn, tool):
        s[tag] = (next(keys), tool)
        text_fn(os.path.join(home, *rel.split("/")), s[tag][0])

    txt = lambda p, k: write(p, f"token {k} here\n")  # noqa: E731
    put("ag_history", ".gemini/antigravity-cli/history.jsonl",
        lambda p, k: write(p, json.dumps({"display": f"use {k}", "timestamp": 1}) + "\n"), "Google Antigravity")
    put("ag_step", ".gemini/antigravity-cli/brain/u1/.system_generated/steps/3/output.txt", txt, "Google Antigravity")
    put("ag_db", ".gemini/antigravity-cli/conversations/c1.db",
        lambda p, k: db(p, "steps", ["id", "step_payload"], (1, b"\x08\x02\x12" + f"cat .env -> {k}".encode())),
        "Google Antigravity")
    put("aider_home", ".aider.chat.history.md", lambda p, k: write(p, f"#### set key\n\nKEY={k}\n"), "Aider")
    # Aider writes into each project; the project is known from Claude Code's project list. (A simulated Linux
    # machine on a Windows host lists its projects with Windows paths, which Linux rules rightly ignore.)
    proj_key = next(keys)
    if not (WINDOWS and platform != "windows"):
        s["aider_proj"] = (proj_key, "Aider")
        write(os.path.join(home, "projects", "app", ".aider.input.history"), f"# 2026\n+export K={proj_key}\n")
    put("goose", ".local/share/goose/sessions/sessions.db" if platform != "windows" else
        "AppData/Roaming/Block/goose/data/sessions/sessions.db",
        lambda p, k: db(p, "messages", ["id", "content_json"], (1, json.dumps([{"text": f"key {k}"}]))), "Goose")
    put("qwen", ".qwen/projects/-home-me-app/chats/s1.jsonl",
        lambda p, k: write(p, json.dumps({"type": "user", "text": f"use {k}"}) + "\n"), "Qwen Code")
    put("lmstudio", ".lmstudio/conversations/1.conversation.json",
        lambda p, k: write(p, json.dumps({"messages": [{"content": f"key {k}"}]})), "LM Studio")
    jan = {"linux": ".local/share/Jan/data", "windows": "AppData/Roaming/Jan/data"}[platform]
    put("jan", f"{jan}/threads/t1/messages.jsonl",
        lambda p, k: write(p, json.dumps({"content": [{"text": {"value": f"key {k}"}}]}) + "\n"), "Jan")
    put("amp", ".local/share/amp/threads/T-1.json",
        lambda p, k: write(p, json.dumps({"messages": [{"content": f"key {k}"}]})), "Amp")
    put("junie", ".junie/sessions/s1/events.jsonl", lambda p, k: write(p, json.dumps({"out": f"key {k}"}) + "\n"),
        "Junie")
    put("devin", ".local/share/devin/cli/logs/devin_1_2.log" if platform != "windows" else
        "AppData/Roaming/devin/cli/sessions.db",
        (txt if platform != "windows" else
         lambda p, k: db(p, "message_nodes", ["id", "chat_message"], (1, json.dumps({"content": f"key {k}"})))),
        "Devin CLI")
    if platform == "windows":
        put("claude_desktop", "AppData/Roaming/Claude/local-agent-mode-sessions/a/o/local_1/.claude/projects/p/s.jsonl",
            lambda p, k: write(p, json.dumps({"type": "user", "message": {"content": f"use {k}"}}) + "\n"),
            "Claude Desktop")
    return s


@requires_rg
class EndToEndTests(TempDirTest):
    def check(self, platform):
        fx = Fixture(self.tmp, platform, clean=True)
        s = plant(fx, SecretFactory(66), platform)
        p = fx.run()
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 10, out)
        d = fx.findings()
        rotate = {r["masked"]: r for r in d["rotate"]}
        for tag, (key, tool) in s.items():
            with self.subTest(store=tag):
                self.assertIn(mask(key), rotate, tag)
                self.assertEqual(rotate[mask(key)]["tools"], [tool])
        for key, _ in s.values():
            self.assertNotIn(key, out)

    def test_linux(self):  # I-TOOL-3
        self.check("linux")

    def test_windows(self):  # I-TOOL-4
        self.check("windows")
