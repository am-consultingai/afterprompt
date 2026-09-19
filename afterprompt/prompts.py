"""Find password-like strings in what the user typed into their AI tools. Tokens are never stored: output holds
a hash, a shape description and scrubbed surrounding words."""
import collections
import datetime
import glob
import hashlib
import json
import math
import os
import re

from afterprompt import sources as src
from afterprompt.util import is_under, log, sha16, write_json

KW = re.compile(r"(?i)\b(?:pass(?:word|wd|code|phrase)?|pwd|pin|login|log ?in|creds?|credentials?|user(?:name)?|token|"
                r"api[ _-]?key|secret|key is|otp|2fa|mfa)\b|סיסמ|קוד|משתמש|טוקן|מפתח|כניסה|הרשמה|אימייל")
TOKEN = re.compile(r"(?<![\w/\\.@:%-])[^\s\"'`<>()\[\]{},;]{6,64}(?![\w/\\-])")
URLISH = re.compile(r"^(?:https?|ftp|file|s3|gs)://|^www\.|\.(?:com|net|org|io|il|dev|app|ai)(?:/|$)|"
                    r"^[\w.+-]+@[\w-]+\.[\w.]+$")
PATHISH = re.compile(r"[/\\]|^\.|~|\.(?:py|ts|tsx|js|jsx|json|jsonl|md|txt|csv|xlsx?|docx?|pdf|png|jpe?g|svg|html|css|"
                     r"sh|ya?ml|env|sql|log|mp[34]|wav|zip)$", re.I)
HASHISH = re.compile(r"^(?:[0-9a-f]{7,64}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)
DATEVER = re.compile(r"^[vV]?\d[\d.:\-_/T+Z]*$|^\d{1,2}[:/.-]\d{1,2}")
CODEY = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+\(?|^[a-z]+(?:[A-Z][a-z0-9]+)+$|"
                   r"^[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+$|^[a-z0-9]+(?:[-_][a-z0-9]+)+$|^[A-Z0-9]+(?:_[A-Z0-9]+)+$|"
                   r"=>|::|\(\)|^--?[a-z]")
HEBREW = re.compile(r"[֐-׿]")
SCRUB = re.compile(r"[^\s\"'`<>()\[\]{},;]{6,64}")


def classes(t):
    return (any(c.islower() for c in t), any(c.isupper() for c in t), any(c.isdigit() for c in t),
            any(not c.isalnum() for c in t))


def ent(t):
    c = collections.Counter(t)
    n = len(t)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def _jsonl(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue
    except OSError:
        return


def collect_prompts(cfg, sources):
    prompts = []
    homes = [(sources["platform"], cfg.home)]
    if sources.get("windows_home"):
        homes.append(("windows", sources["windows_home"]))
    self_dirs = sources.get("self_exclude", [])
    for side, home in homes:
        cdir = src.claude_dir(home) if side != "windows" else os.path.join(home, ".claude")
        for d in _jsonl(os.path.join(cdir, "history.jsonl")):
            if not isinstance(d, dict):
                continue
            parts = [d.get("display") or ""]
            for pc in (d.get("pastedContents") or {}).values():
                if isinstance(pc, dict) and isinstance(pc.get("content"), str):
                    parts.append(pc["content"])
            ts = d.get("timestamp")
            when = datetime.datetime.fromtimestamp(ts / 1000).strftime("%Y-%m-%d") if isinstance(ts, (int, float)) else "?"
            prompts.append((f"Claude Code history ({side})", when, "\n".join(p for p in parts if isinstance(p, str))))
        for f in glob.glob(os.path.join(glob.escape(cdir), "projects", "**", "*.jsonl"), recursive=True):
            if any(is_under(f, s) for s in self_dirs):
                continue
            for d in _jsonl(f):
                if not isinstance(d, dict) or d.get("type") != "user":
                    continue
                c = (d.get("message") or {}).get("content") if isinstance(d.get("message"), dict) else None
                if isinstance(c, str):
                    texts = [c]
                elif isinstance(c, list):
                    texts = [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
                else:
                    texts = []
                t = "\n".join(x for x in texts if isinstance(x, str) and x)
                if t:
                    ts = d.get("timestamp")
                    prompts.append((f"Claude Code session ({side})", ts[:10] if isinstance(ts, str) else "?", t))
    ext = cfg.w("extracted", "db")
    for f in sorted(glob.glob(os.path.join(glob.escape(ext), "*.txt"))):
        try:
            fh = open(f, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                if "key=bubbleId:" not in line or "value=" not in line:
                    continue
                v = line.split("value=", 1)[1].strip()
                try:
                    d = json.loads(v)
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("type") == 1 and isinstance(d.get("text"), str) and d["text"]:
                    ca = d.get("createdAt")
                    prompts.append(("Cursor chat", ca[:10] if isinstance(ca, str) else "?", d["text"]))
    return prompts


def scrub_ctx(s):
    def f(m):
        t = m.group(0)
        if t == "⟦TOKEN⟧":
            return t
        lo, up, di, sy = classes(t)
        return (t[:2] + "…" + t[-1:]) if (di and (lo or up)) and len(t) >= 8 else t
    return SCRUB.sub(f, s).replace("\n", " ⏎ ")


def candidates(prompts):
    seen, uniq = set(), []
    for p in prompts:
        h = hashlib.sha1(p[2].encode("utf-8", "replace")).hexdigest()
        if h not in seen:
            seen.add(h)
            uniq.append(p)
    by = {}
    for source, when, text in uniq:
        for m in TOKEN.finditer(text):
            t = m.group(0).strip(".:!?")
            if len(t) < 6 or URLISH.search(t) or PATHISH.search(t) or HASHISH.match(t) or DATEVER.match(t) \
                    or CODEY.search(t) or HEBREW.search(t):
                continue
            lo, up, di, sy = classes(t)
            near = text[max(0, m.start() - 70): m.end() + 40]
            kw = bool(KW.search(near))
            shaped = (lo or up) and di and (sy or (lo and up)) and ent(t) >= 2.5
            if not (shaped or (kw and (di or sy) and ent(t) >= 2.3)):
                continue
            if re.fullmatch(r"(?i)[a-z]+\d{1,4}", t) and not kw:
                continue
            if t in by:
                continue
            by[t] = {"h": sha16(t), "kw": kw, "e": round(ent(t), 2), "src": source, "when": when,
                     "shape": f"{t[:2]}…{t[-1:]} len={len(t)} "
                              f"{'a' if lo else ''}{'A' if up else ''}{'9' if di else ''}{'#' if sy else ''}",
                     "ctx": scrub_ctx(text[max(0, m.start() - 90): m.start()] + " ⟦TOKEN⟧ " +
                                      text[m.end(): m.end() + 60])}
    return uniq, list(by.values())


def run(cfg, sources):
    prompts = collect_prompts(cfg, sources)
    uniq, cands = candidates(prompts)
    write_json(cfg.w("prompts.json"), cands)
    per = collections.Counter(p[0] for p in prompts)
    stats = {"prompts": dict(per), "unique_prompts": len(uniq), "candidates": len(cands),
             "near_keyword": sum(1 for c in cands if c["kw"])}
    log(f"prompts: {len(uniq)} unique prompts, {len(cands)} candidates ({stats['near_keyword']} near a keyword)")
    return stats
