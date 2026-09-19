"""X6: the VS Code family. Chat and extension-agent history inside every editor's profile, found once per editor
from one catalogue entry, plus the agents' own folders. Layouts follow each project's source (see "source")."""
import copy
import json
import os
import sqlite3

from afterprompt import catalogue, sources
from afterprompt.util import mask
from tests.helpers import Fixture, TempDirTest, jsonl, make_cfg, requires_rg, write
from tests.samples import SecretFactory


def kilo_db(path, text, login):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table part (id, data)")
    con.execute("create table credential (id, value)")
    con.execute("insert into part values ('p1', ?)", (json.dumps({"text": text}),))
    con.execute("insert into credential values ('c1', ?)", (json.dumps({"key": login}),))
    con.commit()
    con.close()


def cursor_cli_store(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table blobs (id, data)")
    con.execute("create table meta (key, value)")
    con.execute("insert into blobs values ('b1', ?)", (json.dumps({"role": "user", "content": text}).encode(),))
    con.commit()
    con.close()


def plant(home, f, profile):
    """profile: the editor profile root for this platform, e.g. .config or AppData/Roaming."""
    s = {
        "copilot_jsonl": f.sample("github_token"),
        "copilot_json": f.sample("slack_token"),
        "copilot_cli": f.sample("stripe_secret_key"),
        "cline_cursor": f.sample("groq_key"),
        "cline_secret": f.sample("openai_project_key"),
        "roo_remote": f.sample("huggingface_token"),
        "kilo_part": f.sample("sendgrid_key"),
        "kilo_login": f.sample("anthropic_key"),
        "continue_session": f.sample("aws_access_key_id"),
        "amazonq": f.sample("brave_api_key"),
        "cursor_cli": f.sample("xai_key"),
    }
    code = os.path.join(home, *profile.split("/"), "Code", "User")
    cursor = os.path.join(home, *profile.split("/"), "Cursor", "User")
    # VS Code >= 1.109 append log: a key can arrive in a later "set" line, not only the initial snapshot.
    jsonl(os.path.join(code, "workspaceStorage", "ws1", "chatSessions", "s1.jsonl"), [
        {"kind": 0, "v": {"requests": []}},
        {"kind": 1, "k": ["requests", 0, "message", "text"], "v": f"push with {s['copilot_jsonl']}"},
        # the Cline login's key pasted into Copilot Chat: a live credential through Cline's own secrets.json
        {"kind": 2, "k": ["requests"], "v": {"message": {"text": f"OPENAI_API_KEY={s['cline_secret']}"}}}])
    write(os.path.join(code, "globalStorage", "emptyWindowChatSessions", "e1.json"),
          json.dumps({"requests": [{"message": {"text": f"slack {s['copilot_json']}"}}]}))
    write(os.path.join(home, ".copilot", "session-state", "abc", "events.jsonl"),
          json.dumps({"type": "user", "text": f"stripe {s['copilot_cli']}"}) + "\n")
    write(os.path.join(cursor, "globalStorage", "saoudrizwan.claude-dev", "tasks", "t1", "api_conversation_history.json"),
          json.dumps([{"role": "user", "content": [{"type": "text", "text": f"GROQ={s['cline_cursor']}"}]}]))
    write(os.path.join(home, ".cline", "data", "secrets.json"), json.dumps({"openAiApiKey": s["cline_secret"]}))
    write(os.path.join(home, ".vscode-server", "data", "User", "globalStorage", "rooveterinaryinc.roo-cline", "tasks",
                       "t9", "ui_messages.json"), json.dumps([{"text": f"HF_TOKEN={s['roo_remote']}"}]))
    kilo_db(os.path.join(home, ".local", "share", "kilo", "kilo.db"), f"SENDGRID={s['kilo_part']}", s["kilo_login"])
    write(os.path.join(home, ".continue", "sessions", "c1.json"),
          json.dumps({"history": [{"message": {"content": f"AWS_ACCESS_KEY_ID={s['continue_session']}"}}]}))
    write(os.path.join(home, ".aws", "amazonq", "history", "chat-history-ws.json"),
          json.dumps({"collections": [{"data": [{"body": f"BRAVE_API_KEY={s['amazonq']}"}]}]}))
    cursor_cli_store(os.path.join(home, ".cursor", "chats", "h1", "u1", "store.db"), f"use {s['cursor_cli']}")
    return s


class ExpansionTests(TempDirTest):
    def test_one_entry_every_editor_every_os(self):  # U-ED-1
        editors = [{"name": "Code", "server": ".vscode-server"}, {"name": "Kiro"}]
        locs = catalogue.expand({"path": "$EDITOR_USER/globalStorage/x.y", "side": "unix", "remote": True}, editors)
        got = sorted((l["side"], tuple(l["platforms"]), l["path"]) for l in locs)
        self.assertEqual(got, sorted([
            ("unix", ("macos",), "Library/Application Support/Code/User/globalStorage/x.y"),
            ("unix", ("linux", "wsl"), ".config/Code/User/globalStorage/x.y"),
            ("windows", ("wsl", "windows"), "AppData/Roaming/Code/User/globalStorage/x.y"),
            ("unix", ("linux", "wsl"), ".vscode-server/data/User/globalStorage/x.y"),
            ("unix", ("macos",), "Library/Application Support/Kiro/User/globalStorage/x.y"),
            ("unix", ("linux", "wsl"), ".config/Kiro/User/globalStorage/x.y"),
            ("windows", ("wsl", "windows"), "AppData/Roaming/Kiro/User/globalStorage/x.y"),
        ]))
        only = catalogue.expand({"path": "$EDITOR_USER/a", "side": "unix", "editors": ["Kiro"]}, editors)
        self.assertEqual({l["path"].split("/")[-3] for l in only}, {"Kiro"})
        plain = {"path": ".x", "side": "unix"}
        self.assertEqual(catalogue.expand(plain, editors), [plain])

    def test_validation(self):  # U-ED-2
        base = {"schema": 1, "editors": [{"name": "Code"}], "tools": [
            {"product": "T", "kind": "extension", "status": "scanned", "locations": [{"path": "$EDITOR_USER/x", "side": "unix"}]}]}
        self.assertEqual(catalogue.validate(base), [])
        cases = {
            "unknown editors": lambda d: d["tools"][0]["locations"][0].update(editors=["Notepad"]),
            "only apply to $EDITOR_USER": lambda d: d["tools"][0]["locations"].append({"path": ".x", "side": "unix", "remote": True}),
            "unknown placeholder": lambda d: d["tools"][0]["locations"][0].update(path="$APPDATA/x"),
            "needs the catalogue's editors": lambda d: d.pop("editors"),
            "dot-folder": lambda d: d["editors"].append({"name": "X", "server": "/abs"}),
        }
        for want, fn in cases.items():
            with self.subTest(mistake=want):
                d = copy.deepcopy(base)
                fn(d)
                self.assertTrue(any(want in e for e in catalogue.validate(d)), catalogue.validate(d))

    def test_shipped_editors(self):  # U-ED-3
        names = {e["name"] for e in catalogue.DATA["editors"]}
        self.assertTrue({"Code", "Code - Insiders", "VSCodium", "Cursor", "Windsurf", "Kiro", "Antigravity"} <= names)


class DiscoveryTests(TempDirTest):
    def discover(self, platform, profile):
        home = os.path.join(self.tmp, "home")
        plant(home, SecretFactory(4), profile)
        cfg = make_cfg(self.tmp, platform, home, windows_home="none" if platform != "windows" else None)
        cfg.home = home
        sources._WIN_CACHE.clear()
        out = sources.discover(cfg)
        rel = lambda p: os.path.relpath(p, home).replace(os.sep, "/")  # noqa: E731
        return {rel(r["path"]): r["tool"] for r in out["roots"]}, {rel(d["path"]): d["tool"] for d in out["databases"]}

    def test_linux(self):  # U-ED-4
        roots, dbs = self.discover("linux", ".config")
        want = {
            ".config/Code/User/workspaceStorage/ws1/chatSessions/s1.jsonl": "GitHub Copilot",
            ".config/Code/User/globalStorage/emptyWindowChatSessions/e1.json": "GitHub Copilot",
            ".copilot/session-state": "GitHub Copilot",
            ".config/Cursor/User/globalStorage/saoudrizwan.claude-dev": "Cline",
            ".cline/data": "Cline",
            ".vscode-server/data/User/globalStorage/rooveterinaryinc.roo-cline": "Roo Code",
            ".continue/sessions": "Continue",
            ".aws/amazonq/history": "Amazon Q Developer",
        }
        for path, tool in want.items():
            self.assertEqual(roots.get(path), tool, path)
        self.assertEqual(dbs.get(".local/share/kilo/kilo.db"), "Kilo Code")
        self.assertEqual(dbs.get(".cursor/chats/h1/u1/store.db"), "Cursor")

    def test_windows(self):  # U-ED-5
        roots, _ = self.discover("windows", "AppData/Roaming")
        self.assertEqual(roots.get("AppData/Roaming/Code/User/workspaceStorage/ws1/chatSessions/s1.jsonl"), "GitHub Copilot")
        self.assertEqual(roots.get("AppData/Roaming/Cursor/User/globalStorage/saoudrizwan.claude-dev"), "Cline")
        self.assertNotIn(".vscode-server/data/User/globalStorage/rooveterinaryinc.roo-cline", roots)  # no remote server on Windows


@requires_rg
class EndToEndTests(TempDirTest):
    def check(self, platform, profile):
        fx = Fixture(self.tmp, platform, clean=True)
        s = plant(fx.home, SecretFactory(33), profile)
        p = fx.run()
        out = p.stdout.decode("utf-8", "replace") + p.stderr.decode("utf-8", "replace")
        self.assertEqual(p.returncode, 10, out)
        d = fx.findings()
        rotate = {r["masked"]: r for r in d["rotate"]}
        shown = set(rotate) | {r["masked"] for r in d["review"]}
        expect = {"copilot_jsonl": "GitHub Copilot", "copilot_json": "GitHub Copilot", "copilot_cli": "GitHub Copilot",
                  "cline_cursor": "Cline", "kilo_part": "Kilo Code", "continue_session": "Continue",
                  "amazonq": "Amazon Q Developer", "cursor_cli": "Cursor"}
        if platform != "windows":
            expect["roo_remote"] = "Roo Code"
        for key, tool in expect.items():
            with self.subTest(leak=key):
                self.assertIn(mask(s[key]), rotate)
                self.assertEqual(rotate[mask(s[key])]["tools"], [tool])
        live = rotate[mask(s["cline_secret"])]
        self.assertEqual(live["category"], "live_credential")
        self.assertEqual(live["still_on_disk"], [])          # Cline's own secrets.json: its intended home
        self.assertNotIn(mask(s["kilo_login"]), shown)       # Kilo's login table is never extracted
        for v in s.values():
            self.assertNotIn(v, out)

    def test_linux(self):  # I-ED-1
        self.check("linux", ".config")

    def test_windows(self):  # I-ED-2
        self.check("windows", "AppData/Roaming")
