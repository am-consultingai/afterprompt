"""Test helpers: config factory, fixture homes with planted (generated) secrets, and a afterprompt.sh runner."""
import base64
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from afterprompt import platforms
from afterprompt.config import RunConfig
from tests.samples import SecretFactory

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN_SH = os.path.join(REPO, "afterprompt.sh")
SCAN_PS1 = os.path.join(REPO, "afterprompt.ps1")
HAVE_RG = shutil.which("rg") is not None
requires_rg = unittest.skipUnless(HAVE_RG, "ripgrep is not installed")

WINDOWS = sys.platform == "win32"
# POSIX-only behaviour: file modes, symlinks, chmod-based denial, shell scripts, fork.
requires_posix = unittest.skipIf(WINDOWS, "POSIX-only behaviour")


def slash(path):
    """Compare paths across platforms without caring which separator the OS used."""
    return path.replace(os.sep, "/")


class TempDirTest(unittest.TestCase):
    def setUp(self):
        from afterprompt.util import set_log
        set_log(None)
        self._old_umask = os.umask(0o077)
        self.tmp = tempfile.mkdtemp(prefix="afterprompt-test-")

    def tearDown(self):
        os.umask(self._old_umask)
        for dp, dns, fns in os.walk(self.tmp):
            for n in dns + fns:
                try:
                    os.chmod(os.path.join(dp, n), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)


def make_cfg(root, platform="linux", home=None, windows_home=None, mode="quick", **kw):
    run_dir = os.path.join(root, "base", "runs", "test")
    cfg = RunConfig(mode=mode, base_dir=os.path.join(root, "base"), run_dir=run_dir,
                    work_dir=os.path.join(run_dir, "work"), report_dir=run_dir,
                    home=home or os.path.join(root, "home"), windows_home_arg=windows_home or "none",
                    workers=2, mem_cap_bytes=2 * 1024 ** 3, file_timeout=60, pattern_timeout=60, walk_budget=20,
                    rg=shutil.which("rg") or "rg", install_dir=REPO, platform=platform,
                    mp_start="spawn" if platform in ("macos", "windows") or WINDOWS else "fork")
    for k, v in kw.items():
        setattr(cfg, k, v)
    os.makedirs(os.path.join(cfg.work_dir, "state"), exist_ok=True)
    return cfg


def write(path, content, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as fh:
        fh.write(content)
    return path


def jsonl(path, rows):
    return write(path, "".join(json.dumps(r) + "\n" for r in rows))


def cursor_db(path, bubbles):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("create table ItemTable (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    con.execute("create table cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    con.execute("insert into ItemTable values (?, ?)", ("workbench.state", json.dumps({"open": True})))
    for i, (typ, text) in enumerate(bubbles):
        con.execute("insert into cursorDiskKV values (?, ?)",
                    (f"bubbleId:composer{i}:bubble{i}", json.dumps({"type": typ, "text": text}).encode()))
    con.commit()
    con.close()


def jwt(factory, exp):
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'sub': factory.chars('a', 12), 'exp': exp})}." \
           f"{factory.chars('u', 43)}"


class Fixture:
    """A fake machine. `platform` is linux, macos, wsl, or windows. Secrets are generated per instance."""

    def __init__(self, root, platform="wsl", seed=99, clean=False):
        self.root = root
        self.platform = platform
        self.f = SecretFactory(seed)
        self.home = os.path.join(root, "home")
        self.win = os.path.join(root, "Users", "me") if platform == "wsl" else None
        self.other = os.path.join(root, "Users", "other") if platform == "wsl" else None
        self.base = os.path.join(root, "base")
        self.extra = os.path.join(root, "extra")
        self.s = {}
        os.makedirs(self.home, exist_ok=True)
        if self.win:
            os.makedirs(self.win, exist_ok=True)
        if clean:
            self.build_clean()
        else:
            self.build()

    # ------------------------------------------------------------------
    def claude_project(self, name):
        return os.path.join(self.home, ".claude", "projects", name)

    def build_clean(self):
        app = os.path.join(self.home, "projects", "app")
        write(os.path.join(app, "README.md"), "hello\n")
        jsonl(os.path.join(self.claude_project("-home-u-projects-app"), "s1.jsonl"),
              [{"type": "user", "message": {"content": "please refactor the parser"}}])
        write(os.path.join(self.home, ".claude.json"), json.dumps({"projects": {app: {}}}))

    def build(self):
        f, home = self.f, self.home
        app = os.path.join(home, "projects", "app")
        proj = self.claude_project("-home-u-projects-app")
        s = self.s
        s["F1"] = f.sample("anthropic_key")
        s["F2"] = f.sample("github_token")
        s["F3"] = f.chars("a", 14) + "!#" + f.chars("a", 6)
        s["F4"] = f.sample("openai_project_key")
        s["F5"] = "sk-proj-EXAMPLE" + f.chars("a", 40)
        s["F6"] = f.sample("stripe_secret_key")
        s["F7"] = f.sample("slack_token")
        s["F8"] = "sk-ant-oat01-" + f.chars("u", 90)
        s["F9"] = jwt(f, int(time.time()) - 86400)
        s["F10"] = f.chars("a", 10) + "#" + f.chars("a", 3)
        s["F11"] = f.sample("huggingface_token")
        s["F12"] = f.sample("xai_key")
        s["F13"] = f.sample("groq_key")
        s["F14"] = f.sample("gitlab_token")
        s["F16"] = f"postgres://app:{f.chars('a', 12)}@localhost:5432/app"

        write(os.path.join(app, ".env"), f"# app settings\nexport ANTHROPIC_API_KEY=\"{s['F1']}\"\n"
                                          f"DB_PASSWORD={s['F3']}\nDEBUG=true\n")
        write(os.path.join(app, ".env.example"), f"DATABASE_URL={s['F16']}\n")
        write(os.path.join(home, ".claude.json"), json.dumps({"projects": {app: {}}, "numStartups": 4}))

        tool_result = {"type": "user", "message": {"content": [
            {"type": "tool_result", "content": f"ANTHROPIC_API_KEY={s['F1']}\nDEBUG=true\n"}]}}
        jsonl(os.path.join(proj, "s1.jsonl"), [
            {"type": "user", "message": {"content": "show me the env file"}},
            tool_result,
            {"type": "assistant", "message": {"content": [{"type": "text", "text": f"The token {s['F9']} is set."}]}},
        ])
        b64 = base64.b64encode(f"OPENAI_API_KEY={s['F4']}\n".encode()).decode()
        jsonl(os.path.join(proj, "s3.jsonl"), [
            {"type": "user", "message": {"content": [{"type": "tool_result", "content": {"data": b64}}]}},
            {"type": "assistant", "message": {"content": f"Use OPENAI_API_KEY={s['F5']} as a placeholder."}},
            {"type": "assistant", "message": {"content": f"Local database: {s['F16']}"}},
        ])
        jsonl(os.path.join(proj, "excluded.jsonl"), [{"type": "assistant", "message": {"content": f"XAI={s['F12']}"}}])
        write(os.path.join(home, ".claude", "plugins", "p", "node_modules", "x", "index.js"),
              f"const k = '{s['F6']}';\n")
        self_dir = platforms.claude_project_dirname(REPO)
        jsonl(os.path.join(self.claude_project(self_dir), "0e8f9a52-1111-4222-8333-944455556666.jsonl"),
              [{"type": "assistant", "message": {"content": f"slack {s['F7']}"}}])
        write(os.path.join(home, ".claude", ".credentials.json"),
              json.dumps({"claudeAiOauth": {"accessToken": s["F8"], "expiresAt": 1}}))
        jsonl(os.path.join(home, ".claude", "history.jsonl"), [
            {"display": f"the portal password is {s['F10']} for the staging site", "timestamp": 1757000000000,
             "project": app}])
        write(os.path.join(home, ".cursor", "mcp.json"),
              json.dumps({"mcpServers": {"hf": {"command": "hf-mcp", "env": {"HF_TOKEN": s["F11"]}}}}))
        write(os.path.join(self.extra, "notes.txt"), f"groq: {s['F13']}\n")

        # F15: certificate and design tokens that must not become live values
        cert = "-----BEGIN CERTIFICATE-----\n" + "\n".join(f.chars("b", 64) for _ in range(6)) + \
               "\n-----END CERTIFICATE-----\n"
        write(os.path.join(home, "certs", "cacert.pem"), cert)
        write(os.path.join(home, "design", "brand-tokens.json"),
              json.dumps({"fonts": "Inter:wght@300;400;600&display=swap", "logo": "logo/am-logo-600x162-v2.png",
                          "accent": f.chars("a", 24)}))
        # F17: Google client id in a credential-named file, mentioned in a transcript
        client_id = f"{f.chars('d', 12)}-{f.chars('l', 32)}.apps.googleusercontent.com"
        write(os.path.join(home, "Downloads", "client_secret_123.json"),
              json.dumps({"installed": {"client_id": client_id, "project_id": "demo-app"}}))
        s["F17"] = client_id

        if self.platform == "windows":
            # A Windows machine keeps everything in one profile: no second side, no /mnt bridge.
            cursor_user = os.path.join(home, "AppData", "Roaming", "Cursor", "User")
            write(os.path.join(home, "AppData", "Local", "claude-cli-nodejs", "mcp-logs", "cache.log"),
                  f"[info] started with DB_PASSWORD={s['F3']}\n")
            write(os.path.join(home, ".cursor", "plans", "plan.md"), f"Use DB_PASSWORD={s['F3']} for staging.\n")
        elif self.platform == "wsl":
            cursor_user = os.path.join(self.win, "AppData", "Roaming", "Cursor", "User")
            jsonl(os.path.join(self.win, ".claude", "projects", "C--Users-me-app", "s2.jsonl"),
                  [{"type": "assistant", "message": {"content": f"connecting with DB_PASSWORD={s['F3']}"}}])
            jsonl(os.path.join(self.other, ".claude", "projects", "C--Users-other-x", "s.jsonl"),
                  [{"type": "assistant", "message": {"content": s["F14"]}}])
        else:
            if self.platform == "macos":
                cursor_user = os.path.join(home, "Library", "Application Support", "Cursor", "User")
            else:
                cursor_user = os.path.join(home, ".config", "Cursor", "User")
            write(os.path.join(home, ".cursor", "plans", "plan.md"), f"Use DB_PASSWORD={s['F3']} for staging.\n")
        cursor_db(os.path.join(cursor_user, "globalStorage", "state.vscdb"),
                  [(1, f"why does git push fail with token {s['F2']}"), (2, "Try regenerating it.")])
        write(os.path.join(cursor_user, "workspaceStorage", "abc123", "workspace.json"),
              json.dumps({"folder": "file://" + app}))
        jsonl(os.path.join(proj, "s4.jsonl"), [
            {"type": "assistant", "message": {"content": "client id " + client_id + "\n" + cert.replace("\n", " ")}}])

    # ------------------------------------------------------------------
    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CONFIG_DIR" and
               (not k.startswith("AFTERPROMPT_") or k == "AFTERPROMPT_PYTHON")}
        env.update({"AFTERPROMPT_DIR": self.base, "AFTERPROMPT_HOME": self.home, "AFTERPROMPT_PLATFORM": self.platform,
                    "AFTERPROMPT_WALK_BUDGET": "20"})
        if self.platform == "wsl":
            env["AFTERPROMPT_WINDOWS_HOME"] = self.win
        if self.platform in ("macos", "windows") or WINDOWS:
            env["AFTERPROMPT_MP_START"] = "spawn"
        env.update(extra)
        return env

    def run(self, *args, env=None, bash=None):
        if WINDOWS:
            # No bash on Windows: the launcher under test is the PowerShell one.
            cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-File", SCAN_PS1, *args]
        else:
            cmd = [bash or os.environ.get("AFTERPROMPT_TEST_BASH") or "bash", SCAN_SH, *args]
        p = subprocess.run(cmd, capture_output=True, env=env or self.env(), timeout=900)
        return p

    def findings(self, report_dir=None):
        if report_dir is None:
            runs = sorted(os.listdir(os.path.join(self.base, "runs")))
            report_dir = os.path.join(self.base, "runs", runs[-1])
        with open(os.path.join(report_dir, "findings.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def masked(self, key):
        from afterprompt.util import mask
        return mask(self.s[key])


def run_dirs(base):
    d = os.path.join(base, "runs")
    return sorted(os.listdir(d)) if os.path.isdir(d) else []


def py():
    return sys.executable
