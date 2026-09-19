"""Run each credential pattern as its own ripgrep pass over raw or decoded data."""
import base64
import binascii
import collections
import json
import os
import re
import subprocess
import threading
import time
from urllib.parse import urlsplit

from afterprompt.patterns import MULTILINE, PATTERNS, escape_aware, strip_residue
from afterprompt.util import entropy, log, mask, scrub, sha16

RG_BASE = ["-uuu", "-a", "-o", "-b", "-N", "-H", "--no-heading", "--no-messages", "--field-match-separator", "\x01"]
HIT_LIMIT = 300000

B64SET = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
PLACEHOLDER = re.compile(rb"(?i)\$\{|\{\{|process\.env|os\.environ|getenv|<[A-Za-z_ \-]+>|your[_\- ]|example|"
                         rb"changeme|change_me|placeholder|redacted|\*{3,}|x{6,}|dummy|fake|sample|"
                         rb"replace[_\-]?me|<hidden>|\.\.\.|\xe2\x80\xa6")
CODEY = re.compile(rb"[()\[\]{};]|process\.env|os\.environ|import\.meta|\bself\.|\bthis\.|\bsettings\.|"
                   rb"\bconfig\.|^\w+\.\w+$")
IDENT = re.compile(rb"[A-Za-z_.]+")
NUMVAL = re.compile(rb"[\d\s,.:\-+]+")
VALPART = re.compile(rb"[:=]\s*[\"'`]?(.+)$")
JWT = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.(eyJ[A-Za-z0-9_\-]{8,})\.[A-Za-z0-9_\-]*")
URL = re.compile(rb"[a-z][a-z0-9+.\-]*://[^\s\"'<>]+", re.I)
LOCAL_HOSTS = {"localhost", "0.0.0.0", "::1", "host.docker.internal"}


class Ctx:
    """Small cache of open file handles for reading context around hits."""

    def __init__(self):
        self.fh = collections.OrderedDict()

    def get(self, path, off, n):
        f = self.fh.get(path)
        if f is None:
            try:
                f = open(path, "rb")
            except OSError:
                return b"", b""
            self.fh[path] = f
            if len(self.fh) > 64:
                self.fh.popitem(last=False)[1].close()
        else:
            self.fh.move_to_end(path)
        start = max(0, off - 160)
        f.seek(start)
        buf = f.read(off - start + n + 60)
        return buf[:off - start], buf[off - start + n:]

    def close(self):
        for f in self.fh.values():
            f.close()


def in_b64(before, after):
    left = 0
    for c in reversed(before):
        if c not in B64SET:
            break
        left += 1
    right = 0
    for c in after:
        if c not in B64SET:
            break
        right += 1
    return left + right >= 40


def jwt_exp(value):
    """The exp claim of the first JWT in value, or None."""
    m = JWT.search(value)
    if not m:
        return None
    p = m.group(1)
    try:
        payload = json.loads(base64.urlsafe_b64decode(p + b"=" * (-len(p) % 4)))
    except (binascii.Error, ValueError):
        return None
    exp = payload.get("exp") if isinstance(payload, dict) else None
    return exp if isinstance(exp, (int, float)) else None


def is_local_url(value):
    m = URL.search(value)
    if not m:
        return False
    try:
        host = (urlsplit(m.group(0).decode("utf-8", "replace")).hostname or "").lower()
    except ValueError:
        return False
    if not host:
        return False
    return host in LOCAL_HOSTS or host.startswith("127.") or "." not in host


CTX_VALUE = {"npmrc_auth_token", "conn_string_password", "http_header_key", "env_assignment", "generic_hex_secret",
             "aws_secret_key_ctx", "aws_session_token_ctx", "azure_storage_key", "azure_shared_access_key",
             "azure_conn_access_key"}
LAST_TOKEN = {"password_in_prose", "hebrew_password_prose", "user_password_pair", "cli_secret_flag",
              "sshpass_mysql_flag", "basic_auth_header", "bearer_header", "bearer_literal"}
ESCAPE = re.compile(rb"\\(?:[nrt\"\\]|u00)")


def value_part(name, m):
    """The credential value inside a match: the text after the key for contextual patterns, the last token for
    prose and header patterns, and the whole match otherwise. Cut at a JSON escape (a value never contains one)."""
    v = m
    if name.endswith("_ctx") or name in CTX_VALUE:
        vm = VALPART.search(m)
        if vm:
            v = vm.group(1)
    elif name in LAST_TOKEN:
        v = re.split(rb"[\s=:]+", m.strip(b"\"'` "))[-1]
        if name == "sshpass_mysql_flag" and v.startswith(b"-p"):
            v = v[2:]
    e = ESCAPE.search(v)
    if e and e.start() > 0:
        v = v[:e.start()]
    return v.strip(b"\"'` ")


CODE_CHARS = re.compile(rb"[$%{}()\[\]<>\\]")
HAS_DIGIT = re.compile(rb"[0-9]")


B64_KEYS = {"azure_storage_key", "azure_shared_access_key", "azure_conn_access_key", "azure_identifiable_b64_44",
            "azure_identifiable_b64_88", "aws_secret_key_ctx", "aws_session_token_ctx"}
B64_VALUE = re.compile(rb"^[A-Za-z0-9+/]{16,}={0,2}$")


def decodes_to_text(v):
    """A base64 key that decodes to readable text is a test value; real keys decode to random bytes."""
    if not B64_VALUE.match(v):
        return False
    try:
        d = base64.b64decode(v + b"=" * (-len(v) % 4))
    except (binascii.Error, ValueError):
        return False
    return len(d) >= 8 and sum(1 for c in d if 32 <= c < 127) >= 0.95 * len(d)


def vendor_like(v):
    """A vendor-format value strong enough to rotate: 20+ characters, random-looking, no code syntax."""
    return len(v) >= 20 and CODE_CHARS.search(v) is None and entropy(v) >= 3.5


def secret_like(v):
    """A value that could be a real credential: long enough, has a digit, no code or template syntax."""
    return len(v) >= 8 and HAS_DIGIT.search(v) is not None and CODE_CHARS.search(v) is None and entropy(v) >= 3.0


def hit_row(name, tier, path, off, m, before, after):
    vp = value_part(name, m)
    vm = VALPART.search(m)
    vf = vm.group(1) if vm else m      # value used by the code/identifier/numeric heuristics
    return {"p": name, "t": tier, "f": path, "o": off, "vo": off + max(0, m.rfind(vp)), "h": sha16(m),
            "vh": sha16(vp), "m": mask(vp),
            "n": len(vp), "vs": secret_like(vp), "va": vendor_like(vp), "vpe": round(entropy(vp), 2),
            "b64": in_b64(before, after),
            "ph": PLACEHOLDER.search(m) is not None or (name in B64_KEYS and decodes_to_text(vp)),
            "code": CODEY.search(vf) is not None, "ident": IDENT.fullmatch(vf) is not None,
            "num": NUMVAL.fullmatch(vf.strip(b"\"',")) is not None, "ve": round(entropy(vf), 2),
            "exp": jwt_exp(m), "local": is_local_url(m + after[:120]),
            "ctx": scrub(before[-100:]) + "⟪HIT⟫" + scrub(after[:40])}


def run(cfg, target, paths, patterns=None):
    stage = f"vendor_{target}"
    outp = cfg.w(f"{stage}.jsonl")
    ctx = Ctx()
    timing, trunc, total = {}, [], 0
    patterns = patterns if patterns is not None else PATTERNS
    paths = [p for p in paths if os.path.exists(p)]
    with open(outp + ".part", "w", encoding="utf-8") as fo:
        for name, rx, tier in patterns:
            t0 = time.monotonic()
            n = 0
            if not paths:
                break
            cmd = [cfg.rg] + RG_BASE + (["-U"] if name in MULTILINE else []) + \
                ["-g", "!*.part", "-e", escape_aware(rx), "--"] + paths
            timed_out = []
            # The with block closes stdout and reaps rg on every exit path, including an exception mid-loop.
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as p:
                watchdog = threading.Timer(cfg.pattern_timeout, lambda: (timed_out.append(1), p.kill()))
                watchdog.start()
                try:
                    for line in p.stdout:
                        parts = line.rstrip(b"\n").split(b"\x01", 2)
                        if len(parts) != 3 or not parts[1].isdigit():
                            continue
                        path = os.fsdecode(parts[0])
                        m, off = strip_residue(parts[2], int(parts[1]))
                        before, after = ctx.get(path, off, len(m))
                        fo.write(json.dumps(hit_row(name, tier, path, off, m, before, after), ensure_ascii=False) + "\n")
                        n += 1
                        if n >= HIT_LIMIT:
                            trunc.append(name)
                            p.kill()
                            break
                finally:
                    p.stdout.close()
                    p.wait()
                    watchdog.cancel()
            if timed_out:
                trunc.append(f"{name} (timed out after {cfg.pattern_timeout}s; results partial)")
                log(f"  {stage} {name}: timed out, results partial")
            timing[name] = round(time.monotonic() - t0, 2)
            total += n
            log(f"  {stage} {name:28s} {timing[name]:7.2f}s  hits={n}")
    ctx.close()
    os.replace(outp + ".part", outp)
    return {"hits": total, "truncated": trunc, "pattern_seconds": timing}
