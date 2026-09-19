"""v0.5.0 tool coverage: Codex CLI, Gemini CLI, OpenCode and Ollama, found where each keeps its data, and their
leaks reported end to end. Layouts follow each tool's source (see "source" in catalogue.json)."""
import json
import os
import sqlite3

from afterprompt import catalogue, sources
from afterprompt.util import mask
from tests.helpers import Fixture, TempDirTest, jsonl, make_cfg, requires_rg, write
from tests.samples import SecretFactory


def opencode_db(path, part_text, credential_value):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table part (id, message_id, session_id, time_created, time_updated, data)")
    con.execute("create table credential (id, integration_id, label, value, connector_id, method_id, active, "
                "time_created, time_updated)")
    con.execute("create table account (id, access_token, refresh_token)")
    con.execute("insert into part values ('p1', 'm1', 's1', 1, 1, ?)",
                (json.dumps({"type": "text", "text": part_text}),))
    con.execute("insert into credential values ('c1', 'anthropic', 'key', ?, '', '', 1, 1, 1)",
                (json.dumps({"key": credential_value}),))
    con.execute("insert into account values ('a1', ?, ?)", (credential_value, credential_value))
    con.commit()
    con.close()


def plant(home, f, windows=False, macos=False):
    """Every new tool's data under one home, each with its own planted secret. Returns {name: secret}."""
    s = {
        "codex_session": f.sample("github_token"),
        "codex_snapshot": f.sample("aws_access_key_id"),
        "codex_auth": f.sample("openai_project_key"),
        "codex_config": f.sample("brave_api_key"),
        "gemini_chat": f.sample("slack_token"),
        "gemini_prompt": f.sample("stripe_secret_key"),
        "gemini_bin": f.sample("sendgrid_key"),
        "opencode_part": f.sample("groq_key"),
        "opencode_login": f.sample("anthropic_key"),
        "ollama_history": f.sample("huggingface_token"),
    }
    jsonl(os.path.join(home, ".codex", "sessions", "2026", "09", "19", "rollout-2026-09-19T10-00-00-x.jsonl"),
          [{"type": "response_item", "payload": {"content": f"git remote set-url origin https://{s['codex_session']}@github.com/o/r"}}])
    write(os.path.join(home, ".codex", "shell_snapshots", "snap.sh"),
          f"declare -x AWS_ACCESS_KEY_ID=\"{s['codex_snapshot']}\"\n")
    write(os.path.join(home, ".codex", "auth.json"), json.dumps({"OPENAI_API_KEY": s["codex_auth"], "tokens": None}))
    write(os.path.join(home, ".codex", "config.toml"),
          f'[mcp_servers.brave]\ncommand = "npx"\nenv = {{ BRAVE_API_KEY = "{s["codex_config"]}" }}\n')
    chats = os.path.join(home, ".gemini", "tmp", "proj1", "chats")
    jsonl(os.path.join(chats, "session-2026-09-19T10-00-abcd1234.jsonl"), [
        {"sessionId": "abcd1234", "kind": "main"},
        {"type": "user", "content": [{"text": f"post to slack with {s['gemini_chat']}"}]},
        # The Codex login's key, pasted into a Gemini chat: a live credential, found through Codex's auth.json.
        {"type": "user", "content": [{"text": f"try OPENAI_API_KEY={s['codex_auth']} instead"}]}])
    write(os.path.join(home, ".gemini", "tmp", "proj1", "logs.json"),
          json.dumps([{"type": "user", "message": f"charge it with {s['gemini_prompt']}"}]))
    write(os.path.join(home, ".gemini", "tmp", "bin", "rg-helper.js"), f"const k = '{s['gemini_bin']}';\n")
    write(os.path.join(home, ".gemini", "oauth_creds.json"), json.dumps({"access_token": "ya29." + f.chars("u", 60)}))
    opencode_db(os.path.join(home, ".local", "share", "opencode", "opencode.db"),
                f"export GROQ_API_KEY={s['opencode_part']}", s["opencode_login"])
    write(os.path.join(home, ".local", "share", "opencode", "log", "opencode.log"), "INFO service=server started\n")
    write(os.path.join(home, ".ollama", "history"), f"why does HF_TOKEN={s['ollama_history']} fail\n")
    write(os.path.join(home, ".ollama", "id_ed25519"), "-----BEGIN OPENSSH PRIVATE KEY-----\nnot a real key\n")
    write(os.path.join(home, ".ollama", "models", "blobs", "sha256-abc"), "model weights\n")
    return s


class DiscoveryTests(TempDirTest):
    def discover(self, platform):
        home = os.path.join(self.tmp, "home")
        plant(home, SecretFactory(3))
        if platform == "windows":
            write(os.path.join(home, "AppData", "Local", "Ollama", "server.log"), "log\n")
            write(os.path.join(home, "AppData", "Local", "Ollama", "server-2.log"), "log\n")
            write(os.path.join(home, "AppData", "Local", "Ollama", "updates", "OllamaSetup.exe"), "binary\n")
            sqlite3.connect(os.path.join(home, "AppData", "Local", "Ollama", "db.sqlite")).close()
        if platform == "macos":
            sqlite3.connect(self.mk(home, "Library", "Application Support", "Ollama", "db.sqlite")).close()
        cfg = make_cfg(self.tmp, platform, home, windows_home="none" if platform != "windows" else None)
        cfg.home = home
        sources._WIN_CACHE.clear()
        out = sources.discover(cfg)
        rel = lambda p: os.path.relpath(p, home).replace(os.sep, "/")  # noqa: E731
        return {rel(r["path"]): r["tool"] for r in out["roots"]}, {rel(d["path"]): d["tool"] for d in out["databases"]}

    def mk(self, *parts):
        os.makedirs(os.path.join(*parts[:-1]), exist_ok=True)
        return os.path.join(*parts)

    def test_linux_layout(self):  # U-TOOL-1
        roots, dbs = self.discover("linux")
        for path, tool in ((".codex/sessions", "Codex CLI"), (".codex/shell_snapshots", "Codex CLI"),
                           (".codex/config.toml", "Codex CLI"), (".gemini/tmp", "Gemini CLI"),
                           (".local/share/opencode/log", "OpenCode"), (".ollama/history", "Ollama")):
            self.assertEqual(roots.get(path), tool, path)
        self.assertEqual(dbs, {".local/share/opencode/opencode.db": "OpenCode"})
        # Login stores, model weights and the tool's own binaries are never scanned as history.
        for never in (".codex/auth.json", ".gemini/oauth_creds.json", ".ollama/id_ed25519", ".ollama/models",
                      ".ollama", ".codex", ".gemini"):
            self.assertNotIn(never, roots)

    def test_codex_sqlite_stores(self):  # U-TOOL-2
        home = os.path.join(self.tmp, "home")
        for name in ("state_5.sqlite", "logs_2.sqlite"):
            sqlite3.connect(self.mk(home, ".codex", name)).close()
        _, dbs = self.discover("linux")
        self.assertEqual({k: v for k, v in dbs.items() if k.startswith(".codex")},
                         {".codex/logs_2.sqlite": "Codex CLI", ".codex/state_5.sqlite": "Codex CLI"})

    def test_windows_layout(self):  # U-TOOL-3
        roots, dbs = self.discover("windows")
        self.assertEqual(roots.get(".codex/sessions"), "Codex CLI")
        self.assertEqual(roots.get(".local/share/opencode/log"), "OpenCode")   # xdg-basedir paths on Windows too
        self.assertEqual(roots.get("AppData/Local/Ollama/server.log"), "Ollama")
        self.assertEqual(roots.get("AppData/Local/Ollama/server-2.log"), "Ollama")
        self.assertFalse([r for r in roots if "updates" in r])
        self.assertEqual(dbs.get("AppData/Local/Ollama/db.sqlite"), "Ollama")

    def test_macos_ollama_app(self):  # U-TOOL-4
        _, dbs = self.discover("macos")
        self.assertEqual(dbs.get("Library/Application Support/Ollama/db.sqlite"), "Ollama")

    def test_catalogue_names_its_sources(self):  # U-TOOL-5
        """Every scanned tool says where its layout comes from, so the next update can be checked."""
        for t in catalogue.DATA["tools"]:
            if t["status"] == "scanned" and t["product"] not in ("Claude Code", "Cursor"):
                self.assertIn("github.com/", t.get("source", ""), t["product"])
        windsurf = [t for t in catalogue.DATA["tools"] if t["product"] == "Windsurf"][0]
        self.assertEqual(windsurf["status"], "planned")
        self.assertIn("encrypted", windsurf["note"])


@requires_rg
class EndToEndTests(TempDirTest):
    def scan(self, platform):
        fx = Fixture(self.tmp, platform, clean=True)
        s = plant(fx.home, SecretFactory(21))
        p = fx.run(env=fx.env())
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 10, out)
        d = fx.findings()
        rotate = {r["masked"]: r for r in d["rotate"]}
        review = {r["masked"]: r for r in d["review"]}
        return fx, s, d, rotate, review, out

    def check(self, platform):
        fx, s, d, rotate, review, out = self.scan(platform)
        for key, tool in (("codex_session", "Codex CLI"), ("codex_snapshot", "Codex CLI"), ("gemini_chat", "Gemini CLI"),
                          ("gemini_prompt", "Gemini CLI"), ("opencode_part", "OpenCode"),
                          ("ollama_history", "Ollama")):
            with self.subTest(leak=key):
                self.assertIn(mask(s[key]), rotate, key)
                self.assertEqual(rotate[mask(s[key])]["tools"], [tool])
        # The Codex login key pasted into Gemini: a live credential of this machine.
        live = rotate[mask(s["codex_auth"])]
        self.assertEqual(live["category"], "live_credential")
        self.assertEqual(live["tools"], ["Gemini CLI"])
        # auth.json is Codex's own login store: the key's intended home, so not a leftover copy to delete.
        self.assertEqual(live["still_on_disk"], [])
        # A key in a tool's own configuration is reported as stored in configuration, not as a leak.
        self.assertEqual(review[mask(s["codex_config"])]["category"], "configuration")
        # Code the tool ships is dismissed; the tool's own login table is never extracted or reported.
        shown = set(rotate) | set(review)
        self.assertNotIn(mask(s["gemini_bin"]), shown)
        self.assertNotIn(mask(s["opencode_login"]), shown)
        run = os.path.join(fx.base, "runs", sorted(os.listdir(os.path.join(fx.base, "runs")))[-1])
        for dp, _, fns in os.walk(run):
            for fn in fns:
                with open(os.path.join(dp, fn), "rb") as fh:
                    data = fh.read()
                for v in s.values():
                    self.assertNotIn(v.encode(), data, fn)
        for v in s.values():
            self.assertNotIn(v, out)
        tools = {src["tool"] for src in d["coverage"]["sources"]}
        self.assertTrue({"Codex CLI", "Gemini CLI", "OpenCode", "Ollama"} <= tools, tools)
        self.assertGreaterEqual(d["coverage"]["databases"]["ok"], 1)

    def test_linux(self):  # I-TOOL-1
        self.check("linux")

    def test_windows(self):  # I-TOOL-2
        self.check("windows")
