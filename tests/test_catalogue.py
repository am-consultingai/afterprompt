"""The declarative tool catalogue: its schema, and that it describes exactly what the engine used to hard-code."""
import copy
import json
import os
import re
import sqlite3
import unittest
from unittest import mock

from afterprompt import catalogue, databases
from tests.helpers import TempDirTest, make_cfg

# The registry as it was hard-coded in sources.py before it moved to catalogue.json (v0.3.0).
OLD_REGISTRY = [
    ('Claude Code', 'unix', '$CLAUDE_DIR', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', '.cache/claude', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', '.cache/claude-cli-nodejs', 'root', ('linux', 'wsl')),
    ('Claude Code', 'unix', '.claude.json', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', '.claude.json.backup', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', '.local/share/claude', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', '.local/state/claude', 'root', ('linux', 'macos', 'wsl')),
    ('Claude Code', 'unix', 'Library/Caches/claude-cli-nodejs', 'root', ('macos',)),
    ('Claude Code', 'windows', '.claude', 'root', ('windows', 'wsl')),
    ('Claude Code', 'windows', '.claude.json', 'root', ('windows', 'wsl')),
    ('Claude Code', 'windows', '.claude.json.backup', 'root', ('windows', 'wsl')),
    ('Claude Code', 'windows', '.local/share/claude', 'root', ('windows', 'wsl')),
    ('Claude Code', 'windows', 'AppData/Local/claude-cli-nodejs', 'root', ('windows', 'wsl')),
    ('Cursor', 'unix', '.config/Cursor/User', 'sqlite_glob', ('linux', 'wsl')),
    ('Cursor', 'unix', '.cursor/ai-tracking', 'sqlite_dir', ('linux', 'macos', 'wsl')),
    ('Cursor', 'unix', '.cursor/mcp.json', 'root', ('linux', 'macos', 'wsl')),
    ('Cursor', 'unix', '.cursor/plans', 'root', ('linux', 'macos', 'wsl')),
    ('Cursor', 'unix', '.cursor/projects', 'root', ('linux', 'macos', 'wsl')),
    ('Cursor', 'unix', 'Library/Application Support/Cursor/User', 'sqlite_glob', ('macos',)),
    ('Cursor', 'windows', '.cursor/ai-tracking', 'sqlite_dir', ('windows', 'wsl')),
    ('Cursor', 'windows', '.cursor/mcp.json', 'root', ('windows', 'wsl')),
    ('Cursor', 'windows', '.cursor/plans', 'root', ('windows', 'wsl')),
    ('Cursor', 'windows', '.cursor/projects', 'root', ('windows', 'wsl')),
    ('Cursor', 'windows', 'AppData/Roaming/Cursor/User', 'sqlite_glob', ('windows', 'wsl')),
]
OLD_GLOBS = ('globalStorage/state.vscdb', 'globalStorage/state.vscdb.backup', 'workspaceStorage/*/state.vscdb',
             'workspaceStorage/*/state.vscdb.backup')
OLD_CONFIG = re.compile(r"(?:^|/)(?:\.cursor/mcp\.json|\.mcp\.json|\.claude/settings(?:\.local)?\.json|"
                        r"\.claude/config\.json|claude_desktop_config\.json)$")
OLD_DESIGNED = re.compile(r"(?:^|/)\.credentials\.json$")
OLD_VEND = re.compile(r"/\.local/share/claude/versions/|/\.claude/plugins/|/node_modules/")


def rows(tools):
    """The (tool, side, path, role, platforms) rows for the tools that existed before the catalogue."""
    return sorted((l.tool, l.side, l.path, l.role, tuple(sorted(l.platforms)))
                  for l in catalogue.REGISTRY if l.tool in tools)


class RegressionTests(unittest.TestCase):
    """Moving the registry into data must not change what is scanned."""

    def test_same_locations(self):  # U-CAT-1
        # Everything scanned before is still scanned; the only additions since are listed here.
        added = [('Cursor', 'unix', '.cursor/chats', 'sqlite_glob', ('linux', 'macos', 'wsl')),
                 ('Cursor', 'windows', '.cursor/chats', 'sqlite_glob', ('windows', 'wsl'))]
        self.assertEqual(rows({"Claude Code", "Cursor"}), sorted(OLD_REGISTRY + added))
        for loc in catalogue.REGISTRY:
            if loc.tool == "Cursor" and loc.role == "sqlite_glob" and loc.path != ".cursor/chats":
                self.assertEqual(loc.globs, OLD_GLOBS)

    def test_same_classification(self):  # U-CAT-2
        samples = ["/h/.cursor/mcp.json", "/p/.mcp.json", "/p/x.mcp.json", "/p/.claude/settings.json",
                   "/p/.claude/settings.local.json", "/h/.claude/config.json", "/a/claude_desktop_config.json",
                   "/h/.claude/.credentials.json", "/h/.claude/credentials.json", "C:/Users/me/.claude/.credentials.json",
                   "/h/.local/share/claude/versions/1.0/cli.js", "/h/.claude/plugins/p/x.js", "/p/node_modules/a/b.js",
                   "/h/.claude/projects/p/s.jsonl", "/h/.cursor/plans/plan.md", "mcp.json", ".mcp.json"]
        for p in samples:
            with self.subTest(path=p):
                self.assertEqual(bool(catalogue.CONFIG_FILES.search(p)), bool(OLD_CONFIG.search(p)))
                self.assertEqual(bool(catalogue.CREDENTIAL_FILES.search(p)), bool(OLD_DESIGNED.search(p)))
                self.assertEqual(bool(catalogue.VENDORED.search(p)), bool(OLD_VEND.search(p)))


class SchemaTests(unittest.TestCase):
    def good(self):
        return {"schema": 1, "tools": [{"product": "Tool", "vendor": "V", "kind": "cli", "status": "scanned",
                                        "store": ["jsonl"], "locations": [{"path": ".tool", "side": "unix"}]}]}

    def test_shipped_catalogue_is_valid(self):  # U-CAT-3
        with open(catalogue.PATH, encoding="utf-8") as fh:
            self.assertEqual(catalogue.validate(json.load(fh)), [])
        self.assertEqual(catalogue.validate(self.good()), [])

    def test_every_mistake_is_reported(self):  # U-CAT-4
        def broken(fn):
            d = self.good()
            fn(d)
            return catalogue.validate(d)
        t = lambda d: d["tools"][0]  # noqa: E731
        loc = lambda d: d["tools"][0]["locations"][0]  # noqa: E731
        cases = {
            "schema": lambda d: d.update(schema=2),
            "product name": lambda d: t(d).pop("product"),
            "listed twice": lambda d: d["tools"].append(copy.deepcopy(t(d))),
            "kind must be": lambda d: t(d).update(kind="robot"),
            "status must be": lambda d: t(d).update(status="maybe"),
            "needs locations": lambda d: t(d).update(locations=[]),
            "needs a path": lambda d: loc(d).pop("path"),
            "relative to the home": lambda d: loc(d).update(path="/etc/passwd"),
            "relative to the home ": lambda d: loc(d).update(path="../../x"),
            "forward slashes": lambda d: loc(d).update(path="AppData\\Roaming"),
            "side must be": lambda d: loc(d).update(side="mars"),
            "platforms must be": lambda d: loc(d).update(platforms=["windows"]),
            "role must be": lambda d: loc(d).update(role="guess"),
            "sqlite_glob needs": lambda d: loc(d).update(role="sqlite_glob"),
            "bad regex": lambda d: t(d).update(config_files=["("]),
            "list of strings": lambda d: t(d).update(exclude_tables="credential"),
            "detect keys": lambda d: t(d).update(detect={"registry": ["x"]}),
            "non-empty list": lambda d: t(d).update(detect={"bins": []}),
            "bare program names": lambda d: t(d).update(detect={"bins": ["/usr/bin/x"]}),
            "detect.windows_apps: bad regex": lambda d: t(d).update(detect={"windows_apps": ["("]}),
            "detect.home paths": lambda d: t(d).update(detect={"home": ["../x"]}),
            "match is a non-empty": lambda d: loc(d).update(match=[]),
            "names its store formats": lambda d: t(d).pop("store"),
            "store must be a list": lambda d: t(d).update(store="jsonl"),
            "a cloud tool has a note": lambda d: d["tools"].append({"product": "C", "kind": "cloud", "status": "cloud",
                                                                    "locations": [{"path": ".c", "side": "unix"}]}),
        }
        for want, fn in cases.items():
            with self.subTest(mistake=want):
                errors = broken(fn)
                self.assertTrue(any(want.strip() in e for e in errors), errors)

    def test_planned_tools_are_listed_not_scanned(self):  # U-CAT-5
        d = self.good()
        later = {"product": "Later", "vendor": "V", "kind": "desktop", "status": "planned", "locations": []}
        d["tools"].append(later)
        self.assertTrue(any("needs a note" in e for e in catalogue.validate(d)))
        later.update(note="Not mapped yet.", detect={"bins": ["later"]})
        self.assertEqual(catalogue.validate(d), [])
        self.assertEqual({l.tool for l in catalogue.registry(d)}, {"Tool"})

    def test_load_refuses_an_invalid_file(self):  # U-CAT-6
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump({"schema": 1, "tools": [{"product": "X"}]}, fh)
        try:
            with self.assertRaises(catalogue.CatalogueError) as cm:
                catalogue.load(fh.name)
            self.assertIn("X:", str(cm.exception))
        finally:
            os.remove(fh.name)


class ExcludedTablesTests(TempDirTest):
    def test_login_tables_are_never_extracted(self):  # U-CAT-7
        db = os.path.join(self.tmp, "app.db")
        con = sqlite3.connect(db)
        con.execute("create table message (id, text)")
        con.execute("create table credential (id, secret)")
        con.execute("insert into message values (1, 'hello from the chat')")
        con.execute("insert into credential values (1, 'the-tools-own-login-token')")
        con.commit()
        con.close()
        cfg = make_cfg(self.tmp)
        with mock.patch.object(catalogue, "exclude_tables", side_effect=lambda t: ("Credential",) if t == "App" else ()):
            info = databases.extract(cfg, {"databases": [{"path": db, "side": "linux", "tool": "App"}]})
        self.assertEqual(info["ok"], 1)
        out = ""
        for f in os.listdir(cfg.w("extracted", "db")):
            with open(os.path.join(cfg.w("extracted", "db"), f), encoding="utf-8") as fh:
                out += fh.read()
        self.assertIn("hello from the chat", out)
        self.assertNotIn("the-tools-own-login-token", out)
        self.assertEqual(databases_ledger(cfg)[0]["tool"], "App")


def databases_ledger(cfg):
    with open(cfg.w("extracted", "_ledger.json"), encoding="utf-8") as fh:
        return json.load(fh)


class CloudTests(unittest.TestCase):
    def test_cloud_only_products_are_listed_with_a_reason(self):  # U-CAT-8
        cloud = [t for t in catalogue.DATA["tools"] if t["status"] == "cloud"]
        self.assertTrue({"Devin", "v0", "Bolt", "Lovable"} <= {t["product"] for t in cloud})
        for t in cloud:
            self.assertIn("cloud", t["note"])
            self.assertEqual(t["locations"], [])
        self.assertFalse({t["product"] for t in cloud} & {l.tool for l in catalogue.REGISTRY})
