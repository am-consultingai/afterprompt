"""Collect live credential values from the machine's standard credential stores, .env files and
credential-named files. These values are then searched for in AI-tool data (known.py)."""
import base64
import binascii
import glob
import json
import os
import re
import subprocess
import time

from afterprompt import catalogue
from afterprompt import sources as src
from afterprompt.patterns import label_for_value
from afterprompt.util import Walker, entropy, is_under, log, mask, sha16, skip_dir, write_json
from afterprompt.vendor import is_local_url

SECRET_WORDS = {"key", "apikey", "secret", "token", "password", "passwords", "passwd", "pass", "pwd",
                "passphrase", "auth", "authorization", "credential", "credentials", "cookie", "session",
                "private", "signature", "dsn", "connection", "bearer"}
NON_SECRET_LAST = {"id", "ids", "path", "dir", "name", "model", "region", "endpoint", "host", "port", "url",
                   "uri", "tier", "type", "count", "at", "expires", "domain", "email"}
NOTSECRET = re.compile(r"(?i)(?:_id|_path|_dir|_model|_name|_region|_endpoint|_host|_port|sessionid|"
                       r"hintsessionid|experiment\w*|firstprompt|onboarding\w*)$|cachedgrowthbook|clientdatacache|"
                       r"statsig|tipshistory|githubrepopaths|examplefiles|passeseligibility")
PLACEHOLDER = re.compile(r"(?i)your[_\- ]|example|changeme|change_me|replace|placeholder|xxxx|<[^>]+>|\$\{")
UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
EMAIL = re.compile(r"^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$")
JWT = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.(eyJ[A-Za-z0-9_\-]+)\.")
STRUCT_PREFIX = re.compile(r"^(?:eyJ|MII|ssh-|-----|[a-z][a-z0-9+.\-]*://|DefaultEndpointsProtocol)")
EXAMPLE_SUFFIX = (".example", ".sample", ".template", ".dist", ".tpl")
NAMEX = re.compile(r"(?i)credential|secret|apikey|api[_-]key|passw|dont[-_]?commit|\.p12$|\.pfx$|\.jks$|\.keystore$|"
                   r"auth\.json$|cookies?\.(?:json|txt)$|(?:^|[_.\-])token\.json$|\.pem$|\.key$")
CODE_EXT = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".go", ".java", ".cs", ".rb", ".php", ".css",
            ".scss", ".html", ".md", ".snap", ".map", ".svg", ".d.ts", ".pyc", ".rs", ".swift", ".kt", ".txt.bak")
TOKX = re.compile(rb"[A-Za-z0-9_\-+/=.~!@#$%^&*]{16,200}")
LINE_KV = re.compile(r"^\s*([^=:#;\s][^=:]*?)\s*[=:]\s*(.+?)\s*$")
NPM_AUTH = re.compile(r"(?i)(?:^|[:/])(_authToken|_auth|_password)\s*=\s*(.+)$")
URL_USERINFO = re.compile(r"[a-z][a-z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@\S+", re.I)
LINE_STORES = (".aws/credentials", ".aws/config", ".npmrc", ".netrc", "_netrc", ".git-credentials", ".pypirc",
               ".pgpass", ".cargo/credentials.toml", ".cargo/credentials", ".gem/credentials", ".kube/config",
               ".config/gh/hosts.yml", "AppData/Roaming/GitHub CLI/hosts.yml")
JSON_STORES = (".docker/config.json", ".azure/*.json", ".config/gcloud/**/*.json", "AppData/Roaming/gcloud/**/*.json",
               ".terraform.d/credentials.tfrc.json", "AppData/Roaming/terraform.d/credentials.tfrc.json",
               ".cursor/mcp.json", "Library/Application Support/Claude/claude_desktop_config.json",
               ".config/Claude/claude_desktop_config.json", "AppData/Roaming/Claude/claude_desktop_config.json")


ALLOWED_TAIL = {"data", "value", "values", "string", "str", "b64", "base64", "raw", "text", "enc", "encoded",
                "encrypted", "plain", "base", "prod", "production", "dev", "development", "test", "live", "staging",
                "local", "new", "old"}


def key_is_secret(path):
    """True when the last component of a key path names a secret: a secret word that is not followed by
    anything other than qualifiers (API_KEY, client-key-data, SECRET_KEY_BASE; not mcpNeedsAuthNoticed)."""
    comps = [c for c in re.split(r"[.\[\]]+", path) if c and not c.isdigit()]
    if not comps:
        return False
    words = [w.lower() for w in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", comps[-1])]
    if not words or words[-1] in NON_SECRET_LAST or ("site" in words and "key" in words):
        return False
    idx = [i for i, w in enumerate(words) if w in SECRET_WORDS]
    if not idx:
        return False
    return all(w in ALLOWED_TAIL or w.isdigit() for w in words[idx[-1] + 1:])


def jwt_expired(v, now):
    m = JWT.match(v)
    if not m:
        return False
    p = m.group(1)
    try:
        payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except (binascii.Error, ValueError):
        return False
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return isinstance(exp, (int, float)) and exp < now


class Collector:
    def __init__(self, now=None):
        self.values = {}          # bytes -> list of (store, key, designed)
        self.per_store = {}
        self.expired = 0
        self.now = now or time.time()

    def add(self, v, store, key, designed=False):
        if v is None or isinstance(v, (bool, int, float)):
            return
        v = str(v).strip()
        if len(v) < 12 or len(v) > 8000 or "\n" in v or "\r" in v:
            return
        b = v.encode("utf-8", "replace")
        if entropy(b) < 3.0 or re.fullmatch(r"[\d\-:.TZ +]+", v) or re.fullmatch(r"[a-z][a-z0-9]*(?:[-.][a-z0-9]+)+", v):
            return
        if (re.match(r"https?://", v) and "@" not in v) or v.startswith(("/", "~/", "./", "../", ".claude/")):
            return
        if PLACEHOLDER.search(v) or re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", v):
            return
        if re.search(r"/.*\.(?:md|json|jsonl|py|ts|js|txt|ya?ml|sh|html|css)$", v):
            return
        if UUID.match(v) or v.endswith(".apps.googleusercontent.com") or EMAIL.match(v):
            return
        if v.startswith(("__Secure-", "__Host-")):
            return
        if not re.search(r"[0-9A-Z]", v) and re.fullmatch(r"[a-z._\-]+|[a-z][a-z0-9_.\-]*(?::[a-z0-9_.@/\-]+)+", v):
            return                                   # lowercase words or plugin:name:ids, not a secret
        if "://" in v and is_local_url(b):
            return                                   # local development database or service
        if jwt_expired(v, self.now):
            self.expired += 1
            return
        entry = (store, key, designed)
        lst = self.values.setdefault(b, [])
        if entry not in lst:
            lst.append(entry)
            self.per_store[store] = self.per_store.get(store, 0) + 1

    def walk_json(self, obj, store, filt, pth="", designed=False):
        if isinstance(obj, dict):
            for k, v in obj.items():
                self.walk_json(v, store, filt, f"{pth}.{k}" if pth else str(k), designed)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self.walk_json(v, store, filt, f"{pth}[{i}]", designed)
        elif filt(pth, obj):
            self.add(obj, store, pth, designed)


def load_json_file(path):
    with open(path, encoding="utf-8-sig", errors="replace") as fh:
        return json.load(fh)


def secret_filter(p, v):
    return key_is_secret(p)


def cookie_filter(p, v):
    return p.endswith("value") and isinstance(v, str) and len(v) >= 20 and entropy(v.encode()) >= 3.5


def parse_line_store(c, path):
    name = os.path.basename(path)
    with open(path, encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith(("#", ";", "[")):
                continue
            for m in URL_USERINFO.finditer(line):
                c.add(m.group(0), path, "url")
            if name == ".pgpass":
                parts = line.split(":")
                if len(parts) >= 5:
                    c.add(":".join(parts[4:]), path, "password")
                continue
            for m in re.finditer(r"\bpassword\s+(\S+)", line):
                c.add(m.group(1), path, "password")
            npm = NPM_AUTH.search(line)
            if npm:
                c.add(npm.group(2).strip().strip("\"'"), path, npm.group(1))
                continue
            kv = LINE_KV.match(line.lstrip("- "))
            if kv:
                k, v = kv.group(1).strip(), kv.group(2).strip().strip("\"'")
                if key_is_secret(k):
                    c.add(v, path, k[:60])


def ssh_slices(c, path, txt, label):
    body = "".join(l.strip() for l in txt.splitlines() if "-----" not in l and ":" not in l)
    for a in (40, len(body) // 2):
        if len(body) >= a + 64:
            c.add(body[a:a + 64], path, label)


def parse_env(c, path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = re.sub(r"^export\s+", "", k.strip()).strip()
            v = v.strip()
            if v[:1] in "\"'" and v[-1:] == v[:1] and len(v) >= 2:
                v = v[1:-1]
            else:
                v = v.split(" #", 1)[0].strip()
            if key_is_secret(k) or ("://" in v and "@" in v):
                c.add(v, path, k)


def parse_named(c, path):
    fn = os.path.basename(path).lower()
    with open(path, "rb") as fh:
        data = fh.read()
    txt = data.decode("utf-8", "replace")
    if "PRIVATE KEY" in txt:
        ssh_slices(c, path, txt, "private key body slice")
        return
    if "CERTIFICATE" in txt:
        return
    if fn.endswith(".json"):
        try:
            obj = json.loads(txt.lstrip("﻿"))
        except ValueError:
            obj = None
        if obj is not None:
            c.walk_json(obj, path, cookie_filter if "cookie" in fn else secret_filter)
            return
    if "cookie" in fn:
        for line in txt.splitlines():
            parts = line.split("\t")
            if len(parts) == 7 and not line.startswith("#"):
                c.add(parts[6], path, f"cookie {parts[5][:40]}")
        return
    for m in TOKX.finditer(data):
        raw = m.group(0).strip(b".=")
        cands = {raw}
        core = raw.rstrip(b"=")
        if b"=" in core:
            cands.add(core.split(b"=", 1)[1])
        for v in cands:
            if len(v) >= 16 and any(48 <= ch <= 57 for ch in v):
                c.add(v.decode("utf-8", "replace"), path, "credential-named file")


def is_env_name(fn):
    low = fn.lower()
    if low.endswith(EXAMPLE_SUFFIX) or re.search(r"\.(?:example|sample|template)\.env$", low):
        return False
    return fn == ".env" or fn.startswith(".env.") or fn.endswith(".env")


def is_named(fn):
    low = fn.lower()
    if not NAMEX.search(fn) or low.endswith(CODE_EXT) or low.endswith(EXAMPLE_SUFFIX):
        return False
    return True


def skip_store_walk(name):
    return skip_dir(name) or name in (".claude", ".cursor")


def keychain(c, status):
    try:
        r = subprocess.run(["security", "find-generic-password", "-s", "Claude Code-credentials", "-w"],
                           capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        status["keychain"] = f"failed: {type(e).__name__}"
        return
    if r.returncode != 0:
        status["keychain"] = f"failed: security exited {r.returncode}"
        return
    out = r.stdout.decode("utf-8", "replace").strip()
    try:
        c.walk_json(json.loads(out), "macOS Keychain (Claude Code-credentials)", secret_filter, designed=True)
    except ValueError:
        c.add(out, "macOS Keychain (Claude Code-credentials)", "password", designed=True)
    status["keychain"] = "included"


def collect(cfg, sources, project_budget=120.0):
    c = Collector(cfg.now or None)
    status = {"keychain": "not requested"}
    handled = set()   # files parsed as structured stores are not re-read as credential-named files
    homes = [(sources["platform"], cfg.home)]
    if sources.get("windows_home"):
        homes.append(("windows", sources["windows_home"]))
    prune = [p for p in (cfg.install_dir, cfg.base_dir) if p]
    for _, home in homes:                            # AI tool data is what gets scanned, not a credential store
        prune += [src.claude_dir(home), os.path.join(home, ".claude"), os.path.join(home, ".cursor")]

    for side, home in homes:
        for pattern in JSON_STORES:
            for f in sorted(glob.glob(os.path.join(glob.escape(home), pattern), recursive=True)):
                if os.path.isfile(f) and os.path.getsize(f) <= 2_000_000:
                    handled.add(os.path.normpath(f))
                    try:
                        c.walk_json(load_json_file(f), f, secret_filter)
                    except (OSError, ValueError) as e:
                        log(f"  known: could not parse {f}: {type(e).__name__}")
        cfg_root = os.path.join(home, ".config")
        if os.path.isdir(cfg_root):
            w = Walker(cfg_root, 4, time.monotonic() + 60, prune_paths=prune)
            for dp, _, fns in w:
                if "gcloud" in dp.split(os.sep):
                    continue
                for fn in fns:
                    f = os.path.join(dp, fn)
                    if fn.endswith(".json") and os.path.isfile(f) and os.path.getsize(f) <= 2_000_000:
                        handled.add(os.path.normpath(f))
                        try:
                            c.walk_json(load_json_file(f), f, secret_filter)
                        except (OSError, ValueError):
                            pass
        cdir = src.claude_dir(home) if side != "windows" else os.path.join(home, ".claude")
        cred = os.path.join(cdir, ".credentials.json")
        handled.add(os.path.normpath(cred))
        if os.path.isfile(cred):
            try:
                c.walk_json(load_json_file(cred), cred, secret_filter, designed=True)
            except (OSError, ValueError):
                pass
        # Every other tool's own login file (catalogue credential_stores): its tokens are live values, so one
        # that turns up in any AI history is caught; the file itself is their intended home.
        for _, rel in catalogue.credential_stores():
            f = os.path.normpath(os.path.join(home, rel))
            if f in handled or not os.path.isfile(f) or os.path.getsize(f) > 2_000_000:
                continue
            handled.add(f)
            try:
                c.walk_json(load_json_file(f), f, secret_filter, designed=True)
            except (OSError, ValueError) as e:
                log(f"  known: could not parse {f}: {type(e).__name__}")
        cj = os.path.join(home, ".claude.json")
        if os.path.isfile(cj):
            try:
                c.walk_json(load_json_file(cj), cj,
                            lambda p, v: (".env." in p or ".headers." in p or key_is_secret(p))
                            and NOTSECRET.search(p) is None)
            except (OSError, ValueError):
                pass
        for rel in LINE_STORES:
            f = os.path.join(home, rel)
            if os.path.isfile(f):
                handled.add(os.path.normpath(f))
                try:
                    parse_line_store(c, f)
                except OSError:
                    pass
        for f in sorted(glob.glob(os.path.join(glob.escape(home), ".ssh", "*"))):
            if f.endswith(".pub") or not os.path.isfile(f):
                continue
            try:
                with open(f, encoding="utf-8", errors="replace") as fh:
                    txt = fh.read(200_000)
            except OSError:
                continue
            if "PRIVATE KEY" in txt:
                handled.add(os.path.normpath(f))
                ssh_slices(c, f, txt, "private key body slice")

    if cfg.include_keychain:
        if cfg.platform == "macos":
            keychain(c, status)
        else:
            status["keychain"] = "not available on this platform"

    env_files, named_files, truncated = set(), set(), []

    def visit(dp, fns):
        for fn in fns:
            p = os.path.join(dp, fn)
            if is_env_name(fn):
                env_files.add(p)
            elif is_named(fn):
                named_files.add(os.path.normpath(p))

    deadline = time.monotonic() + project_budget
    for proj in sources.get("project_dirs", []):
        if os.path.normpath(proj) in {os.path.normpath(h) for _, h in homes}:
            continue
        w = Walker(proj, 6, deadline, prune_paths=prune, skip=skip_store_walk)
        for dp, _, fns in w:
            visit(dp, fns)
        if w.truncated:
            truncated.append(proj)
            break
    for side, home in homes:
        w = Walker(home, 8, time.monotonic() + cfg.walk_budget, prune_paths=prune, skip=skip_store_walk)
        for dp, _, fns in w:
            visit(dp, fns)
        if w.truncated:
            truncated.append(home)

    for f in sorted(env_files):
        try:
            if os.path.isfile(f) and not os.path.islink(f) and os.path.getsize(f) <= 2_000_000:
                parse_env(c, f)
        except OSError:
            pass
    for f in sorted(named_files - handled):
        try:
            if os.path.isfile(f) and not os.path.islink(f) and os.path.getsize(f) <= 2_000_000:
                parse_named(c, f)
        except OSError:
            pass

    stats = {"values": len(c.values), "stores": len(c.per_store), "env_files": len(env_files),
             "credential_named_files": len(named_files), "walk_truncated": truncated,
             "expired_skipped": c.expired, "keychain": status["keychain"]}
    log(f"known: {len(c.values)} live values from {len(c.per_store)} stores; env files {len(env_files)}, "
        f"credential-named files {len(named_files)}, walk truncated: {truncated or 'no'}")
    return c.values, stats


def prefixes(values):
    out = {}
    for b in values:
        if len(b) < 40:
            continue
        p = b[:24]
        if p in values or p in out or entropy(p) < 3.5 or STRUCT_PREFIX.match(p.decode("utf-8", "replace")):
            continue
        out[p] = b
    return out


def write_index(cfg, values, pref):
    idx = {}
    for b, entries in values.items():
        idx[sha16(b)] = {"stores": [{"store": s, "key": k, "designed": d} for s, k, d in entries],
                         "label": label_for_value(b), "masked": mask(b), "n": len(b)}
    write_json(cfg.w("live_index.json"), idx)
    write_json(cfg.w("live_prefix_index.json"), {sha16(p): sha16(full) for p, full in pref.items()})
    return idx
