"""Show where a credential sits in a file, masked: the browser view's reader ("Open it").

The page names a finding (by value hash) and one of its locations (by index), never a path; the path is looked up
in the findings this process wrote, exactly as reveal.py does. What comes back is never the file: it is the few
places the value sits, each a short window of text with the credential masked and highlighted, and every other
secret in that window masked too — this page never shows a full value, and that holds for text around the one
you asked about.

Finding the value again without keeping it anywhere: every finding records the hash of its value, the value's
length in bytes and its masked form, which begins with the value's first six characters. Every place those six
characters occur, the next `length` bytes are hashed and compared. Values stored escaped (a JSON transcript
writes a private key's line breaks as \\n) are found the way the scan found them, by pattern, and compared by hash.

Masking inside a window, strongest first, so a weaker rule never unmasks what a stronger one caught:
  1. the credential itself;
  2. any other finding in the report whose value is in the window (found the same way, by prefix and hash);
  3. anything a credential pattern matches;
  4. any long, random-looking token, as a net under the other three.
A window never begins or ends inside a token, so a secret cannot be half-shown by being cut.

When a location cannot be shown, the answer says why, as a code the page turns into an explanation: it is in
another environment, it was found only inside decoded data, it is a conversation inside a chat database rather
than a file, it has gone, it is too large, it could not be read.
"""
import json
import os
import re
import sqlite3
import time

from afterprompt import patterns, reveal, watch
from afterprompt.util import entropy, mask, sha16
from afterprompt.vendor import value_part

CAP = watch.CAP                 # a text file larger than this is not read into memory for a view
MAX_HITS = 20                   # places shown; the count says how many there were
AROUND = 200                    # bytes of the value's own line kept on each side of it
CONTEXT = 240                   # bytes kept of the line before and the line after
SCAN_MARGIN = 400               # extra bytes searched for secrets beyond a window, so none is cut unseen
DB_SECONDS = 10.0               # a chat database is read row by row until this runs out
DB_SUFFIXES = (".vscdb", ".vscdb.backup", ".db", ".sqlite", ".sqlite3")
TOKEN = re.compile(rb"[A-Za-z0-9+/_\-=.%~]")
RANDOM = re.compile(rb"[A-Za-z0-9+/_\-=.%~]{20,}")
UUID = re.compile(rb"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
SPEAKER = [(re.compile(rb'"type"\s*:\s*"tool_result"'), "tool"),
           (re.compile(rb'"role"\s*:\s*"assistant"|"type"\s*:\s*"assistant"'), "assistant"),
           (re.compile(rb'"role"\s*:\s*"user"|"type"\s*:\s*"user"'), "user")]
RANK = {"target": 0, "other": 1, "secret": 2, "hidden": 3}


def refuse(code, **params):
    return {"ok": False, "code": code, "params": {k: v for k, v in params.items() if v is not None}}


def prefix_of(f):
    """The value's first characters as bytes, when the masked form carries them (it does above 12 characters)."""
    m = f.get("masked") or ""
    if "…" not in m:
        return None
    head = m.split("…")[0].encode("utf-8")
    return head if len(head) >= 4 else None


# ---- finding values again ---------------------------------------------------------------------------------
def by_value(blob, prefix, length, wanted, lo=0, hi=None):
    """(start, end) of every place the prefix begins a run of `length` bytes whose hash is wanted."""
    out = []
    if not prefix or not length:
        return out
    hi = len(blob) if hi is None else hi
    pos = blob.find(prefix, lo, hi)
    while pos >= 0:
        if sha16(blob[pos:pos + length]) in wanted:
            out.append((pos, pos + length))
        pos = blob.find(prefix, pos + 1, hi)
    return out


def by_pattern(blob, names, wanted):
    """The scan's own matching, for values stored escaped: a match whose value (or whole text) hashes to wanted."""
    out = []
    for name in names:
        rx = watch.regex(name)
        if rx is None:
            continue
        for m in rx.finditer(blob):
            text, off = patterns.strip_residue(m.group(0), m.start())
            part = value_part(name, text)
            if sha16(part) in wanted or sha16(text) in wanted:
                at = text.find(part) if part else -1
                out.append((off + at, off + at + len(part)) if at >= 0 else (off, off + len(text)))
    return out


def locate(blob, f):
    wanted = {f.get("hash")} | set(f.get("match_hashes") or [])
    wanted.discard(None)
    spans = by_value(blob, prefix_of(f), f.get("length"), {f.get("hash")}) or \
        by_pattern(blob, f.get("patterns") or [], wanted)
    return merge(sorted(set(spans)))


def merge(spans):
    out = []
    for s, e in spans:
        if out and s < out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def locatable(f):
    return bool(prefix_of(f) and f.get("length")) or any(watch.regex(n) for n in f.get("patterns") or [])


# ---- masking a window -------------------------------------------------------------------------------------
class Others:
    """Every other finding in the report, indexed so a window can be checked for them cheaply."""

    def __init__(self, findings, skip=None):
        self.rows = []
        for section in ("rotate", "review"):
            for f in findings.get(section) or []:
                p = prefix_of(f)
                if p and f.get("length") and f.get("hash") and f.get("hash") != skip:
                    self.rows.append((p, f["length"], f["hash"], f.get("label"), section))

    def spans(self, blob, lo, hi):
        out = []
        for p, n, h, label, section in self.rows:
            for s, e in by_value(blob, p, n, {h}, lo, hi):
                out.append((s, e, "other", {"label": label, "hash": h, "section": section}))
        return out


def secrets_in(blob, lo, hi):
    """What a credential pattern matches in blob[lo:hi], and long random-looking tokens, as absolute spans."""
    part = blob[lo:hi]
    out = []
    for name, _, _ in patterns.PATTERNS:
        rx = watch.regex(name)
        if rx is None:
            continue
        for m in rx.finditer(part):
            text, off = patterns.strip_residue(m.group(0), m.start())
            v = value_part(name, text)
            at = text.find(v) if v else -1
            s = off + (at if at >= 0 else 0)
            e = s + (len(v) if at >= 0 else len(text))
            if e > s:
                out.append((lo + s, lo + e, "secret", None))
    for m in RANDOM.finditer(part):
        if looks_random(m.group(0)):
            out.append((lo + m.start(), lo + m.end(), "hidden", None))
    return out


def looks_random(t):
    """Long, mixed letters and digits, high entropy, and not a UUID (an identifier, and what a transcript is full
    of). The net under the patterns: it catches what they do not name."""
    return len(t) >= 20 and not UUID.fullmatch(t) and bool(re.search(rb"[0-9]", t)) and \
        bool(re.search(rb"[A-Za-z]", t)) and entropy(t) >= 3.5


def choose(spans, blob=None):
    """Strongest first. A weaker span keeps whatever part of it no stronger span covers, still masked: dropping it
    whole would show the rest of a secret that merely overlapped one already caught. The random-token net is the
    exception: what is left of its token once a secret is cut out is kept masked only if it still looks random,
    so AZURE_KEY=<value> shows its name and masks its value."""
    chosen = []
    for s, e, kind, info in sorted(spans, key=lambda x: (RANK[x[2]], x[0], -(x[1] - x[0]))):
        pieces = [(s, e)]
        for cs, ce, _, _ in chosen:
            pieces = [p for a, b in pieces for p in ((a, min(b, cs)), (max(a, ce), b)) if p[1] > p[0]] \
                if any(a < ce and b > cs for a, b in pieces) else pieces
        for a, b in pieces:
            whole = (a, b) == (s, e)
            if not whole and kind == "hidden" and blob is not None and not looks_random(blob[a:b]):
                continue
            chosen.append((a, b, kind if whole else "hidden", info if whole else None))
    return sorted(chosen)


def snap(blob, ws, we, lo, hi):
    """Move a window's edges off any token they would cut, inward, so no value is shown in part."""
    while lo < ws < hi and TOKEN.match(blob[ws - 1:ws]) and TOKEN.match(blob[ws:ws + 1]):
        ws += 1
    while lo < we < hi and TOKEN.match(blob[we - 1:we]) and TOKEN.match(blob[we:we + 1]):
        we -= 1
    return ws, max(ws, we)


def segments(blob, ws, we, spans, masked_target, json_like=False):
    """blob[ws:we] as [text | masked secret] pieces. A secret that crosses an edge widens the window to hold it."""
    for s, e, _, _ in spans:
        if s < ws < e:
            ws = s
        if s < we < e:
            we = e
    out, at = [], ws
    for s, e, kind, info in spans:
        if e <= ws or s >= we:
            continue
        if s > at:
            out.append({"t": text(blob[at:s], json_like)})
        piece = {"t": masked_target if kind == "target" else mask(blob[s:e]), "k": kind}
        if info:
            piece.update(info)
        out.append(piece)
        at = e
    if at < we:
        out.append({"t": text(blob[at:we], json_like)})
    return out, ws, we


ESCAPE = re.compile(r'\\(["\\/nrtbf]|u[0-9a-fA-F]{4})')
PLAIN = {"n": "\n", "t": "  ", "r": "", "b": "", "f": "", '"': '"', "\\": "\\", "/": "/"}


def unescape(s):
    """A JSON string's escapes as the characters they stand for, so a transcript line reads as the conversation
    it holds rather than as \\n and \\" soup. For display only; nothing is written back."""
    def one(m):
        e = m.group(1)
        if e[0] == "u":
            ch = chr(int(e[1:], 16))
            return ch if ch.isprintable() or ch == "\n" else ""
        return PLAIN[e]
    return ESCAPE.sub(one, s)


def text(b, json_like=False):
    s = b.decode("utf-8", "replace").replace("\r", "")
    if not json_like:
        return s
    s = unescape(s)
    # Cursor keeps a tool's result as a JSON string inside the record's JSON, so its line breaks arrive escaped
    # twice; one more pass, and only while what is left still reads as escaped text.
    return unescape(s) if ("\\n" in s or '\\"' in s) else s


def looks_json(b):
    return b[:64].lstrip()[:1] in (b"{", b"[")


def masked_region(blob, ws, we, lo, hi, others, targets, masked_target, json_like=None):
    # A line of JSON (a transcript line, a chat record) is shown with its escapes read; anything else as it is.
    if json_like is None:
        json_like = looks_json(blob[lo:lo + 64])
    """One region of blob, snapped, searched with margin, and cut into pieces."""
    ws, we = snap(blob, ws, we, lo, hi)
    a, b = max(lo, ws - SCAN_MARGIN), min(hi, we + SCAN_MARGIN)
    spans = [(s, e, "target", None) for s, e in targets if e > a and s < b]
    spans += others.spans(blob, a, b) + secrets_in(blob, a, b)
    return segments(blob, ws, we, choose(spans, blob), masked_target, json_like)


def json_for(blob, ls, record):
    """A database record is JSON or not as a whole: a line break inside it does not start a new document."""
    return looks_json(blob) if record else looks_json(blob[ls:ls + 64])


def speaker(line):
    for rx, who in SPEAKER:
        if rx.search(line[:200000]):
            return who
    return None


STORY_CAP = 8 * 1024 ** 2
TARGET_KEYS = ("targetFile", "target_file", "file_path", "path", "relativeWorkspacePath", "command", "query",
               "pattern", "url")


def record_story(blob, others):
    """What a chat record is, when it is JSON: who wrote it, and for a tool call, which tool and on what — the
    difference between "you pasted this" and "the agent read your .env", which is the whole of why it matters.
    The tool's argument is masked like everything else, since a command line can carry a secret of its own."""
    if len(blob) > STORY_CAP:
        return None, None
    try:
        j = json.loads(blob)
    except (ValueError, UnicodeDecodeError):
        return None, None
    if not isinstance(j, dict):
        return None, None
    tool = j.get("toolFormerData")
    if isinstance(tool, dict) and tool.get("name"):
        params = tool.get("params") or tool.get("rawArgs") or {}
        if isinstance(params, str):
            try:
                params = json.loads(params)
            except ValueError:
                params = {}
        target = next((str(params[k]) for k in TARGET_KEYS if isinstance(params, dict) and params.get(k)), "")
        what = f"{tool['name']} {target}".strip().encode("utf-8", "replace")
        pieces, _, _ = masked_region(what, 0, len(what), 0, len(what), others, [], "…")
        return "tool", pieces
    if j.get("role") == "tool":
        return "tool", None
    return {1: "user", 2: "assistant"}.get(j.get("type")), None


def hits_in(blob, spans, f, others, where=None, story=(None, None)):
    """Each place, as its line number, who wrote that line, the window on it, and a line of context each side."""
    out, line_no, counted = [], 1, 0
    for s, e in spans[:MAX_HITS]:
        line_no += blob.count(b"\n", counted, s)
        counted = s
        ls = blob.rfind(b"\n", 0, s) + 1
        le = blob.find(b"\n", e)
        le = len(blob) if le < 0 else le
        ws, we = max(ls, s - AROUND), min(le, e + AROUND)
        jl = json_for(blob, ls, where is not None)
        pieces, ws, we = masked_region(blob, ws, we, ls, le, others, spans, f.get("masked") or "…", jl)
        hit = {"line": line_no, "where": where, "who": story[0] or speaker(blob[ls:le]), "action": story[1],
               "cut_before": ws > ls, "cut_after": we < le, "text": pieces, "before": None, "after": None}
        if ls > 0:
            ps = blob.rfind(b"\n", 0, ls - 1) + 1
            pe = min(ls - 1, ps + CONTEXT)
            if pe > ps:
                hit["before"], _, cut = masked_region(blob, ps, pe, ps, ls - 1, others, [], "…",
                                                      json_for(blob, ps, where is not None))
                hit["before_cut"] = cut < ls - 1
        if le < len(blob):
            ns = le + 1
            nend = blob.find(b"\n", ns)
            nend = len(blob) if nend < 0 else nend
            ne = min(nend, ns + CONTEXT)
            if ne > ns:
                hit["after"], _, cut = masked_region(blob, ns, ne, ns, nend, others, [], "…",
                                                     json_for(blob, ns, where is not None))
                hit["after_cut"] = cut < nend
        out.append(hit)
    return out


# ---- the two kinds of file --------------------------------------------------------------------------------
def is_database(path, display):
    return display.endswith(reveal.LABELS) or path.lower().endswith(DB_SUFFIXES)


def read_text(path, f, others, cap):
    size = os.path.getsize(path)
    if size > cap:
        return refuse("too_large", size=size, limit=cap)
    try:
        with open(path, "rb") as fh:
            blob = fh.read(cap)
    except OSError as e:
        return refuse("unreadable", error=e.strerror or str(e))
    if b"\0" in blob[:65536]:
        return refuse("binary")
    spans = locate(blob, f)
    if not spans:
        return refuse("not_in_file")
    return {"ok": True, "kind": "text", "size": size, "total": len(spans),
            "hits": hits_in(blob, spans, f, others)}


def tables(con):
    """Every table that stores key/value rows, which is how the editors keep chats."""
    out = []
    for (name,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
        cols = {r[1].lower() for r in con.execute(f'PRAGMA table_info("{name}")')}
        if {"key", "value"} <= cols:
            out.append(name)
    return out


def read_database(path, f, loc, others, seconds=DB_SECONDS, clock=time.monotonic, steps=20000):
    """A chat database, read-only and without taking a lock. Each row is one record, and its key says which
    conversation or setting it is.

    A scan records which rows held the value, and those are fetched by key: milliseconds, however large the file.
    A report from before that has no keys, so the rows are searched for the value's first characters inside SQLite,
    and the search is abandoned when `seconds` run out rather than leaving the page waiting on a gigabyte."""
    size = os.path.getsize(path)
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
    except sqlite3.Error as e:
        return refuse("unreadable", error=str(e))
    hits, total, timed_out = [], 0, False

    def take(key, value):
        nonlocal total
        blob = value if isinstance(value, bytes) else str(value or "").encode("utf-8", "replace")
        spans = locate(blob, f)
        if spans:
            total += len(spans)
            if len(hits) < MAX_HITS:
                hits.extend(hits_in(blob, spans, f, others, where=str(key)[:160],
                                    story=record_story(blob, others))[:MAX_HITS - len(hits)])

    try:
        known = tables(con)
        records = [r for r in loc.get("records") or [] if r.get("table") in known]
        if records:
            for r in records:
                row = con.execute(f'SELECT key, value FROM "{r["table"]}" WHERE key = ?', (r["key"],)).fetchone()
                if row:
                    take(*row)
        else:
            prefix = prefix_of(f)
            started = clock()
            # Called every few thousand SQLite steps; a true return aborts the query.
            con.set_progress_handler(lambda: clock() - started > seconds, steps)
            for table in known:
                if prefix:
                    rows = con.execute(f'SELECT key, value FROM "{table}" WHERE instr(CAST(value AS BLOB), ?) > 0',
                                       (prefix,))
                else:
                    rows = con.execute(f'SELECT key, value FROM "{table}"')
                for key, value in rows:
                    take(key, value)
    except sqlite3.OperationalError as e:
        if "interrupt" not in str(e).lower():
            return refuse("unreadable", error=str(e))
        timed_out = True
    except sqlite3.Error as e:
        return refuse("unreadable", error=str(e))
    finally:
        con.close()
    if not total:
        if timed_out:
            return refuse("db_timeout", seconds=int(seconds), size=size)
        return refuse("not_in_file") if not loc.get("records") else refuse("record_changed")
    return {"ok": True, "kind": "database", "size": size, "total": total, "hits": hits,
            "partial": timed_out, "seconds": int(seconds)}


def open_location(findings, value_hash, index, plat=None, home=None, cap=CAP, db_seconds=DB_SECONDS):
    """What the reader shows for one location of one finding, or why it will not show it."""
    findings = findings or {}
    f = reveal.find(findings, value_hash)
    locs = (f or {}).get("locations") or []
    if not f or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(locs):
        return refuse("stale")
    loc = locs[index]
    display = loc.get("display") or ""
    # A conversation's place names its tool ("Cursor chat, 2026-04-15") when the location itself does not.
    named = re.match(r"(.+?) (?:chat|session)\b", display)
    tool = loc.get("tool") or (named.group(1) if named else None)
    base = {"display": reveal.strip_label(display), "tool": tool, "prefix": (prefix_of(f) or b"").decode()}
    if loc.get("decoded"):
        return dict(refuse("decoded"), **base)
    if not loc.get("side"):
        return dict(refuse("conversation", where=display, tool=tool), **base)
    path, why = reveal.reachable(findings, loc, plat, home)
    if not path:
        env = next((e.get("label") for e in findings.get("environments") or [] if e.get("side") == loc["side"]),
                   loc["side"])
        return dict(refuse("elsewhere" if "environment" in (why or "") else "not_path", env=env), **base)
    if not os.path.isfile(path):
        return dict(refuse("gone", when=findings.get("finished")), **base)
    if not locatable(f):
        return dict(refuse("cannot_locate"), **base)
    try:
        if is_database(path, display):
            out = read_database(path, f, loc, Others(findings, skip=f.get("hash")), seconds=db_seconds)
        else:
            out = read_text(path, f, Others(findings, skip=f.get("hash")), cap)
    except OSError as e:
        out = refuse("unreadable", error=e.strerror or str(e))
    return dict(out, **base)
