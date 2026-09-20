"""Credential pattern library, loaded from patterns.json. Rust-regex compatible (rg): no lookaround or
backreferences.

Tier A = vendor-specific prefix or format; B = structural; C = contextual and weak (noisy by design).
Each pattern runs as its OWN rg pass so rg's literal-prefix fast path applies. A vendor changing its key format is
a data edit to patterns.json; validate() refuses a file with a mistake in it.
"""
import json
import os
import re

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "patterns.json")
TIER_NAMES = ("A", "B", "C")
FLAGS = ("rotate_structural", "header_only", "session_cookie", "multiline")
# Constructs Python accepts but ripgrep's Rust engine does not; a pattern that used one would never match there.
RUST_UNSUPPORTED = re.compile(r"\(\?[=!]|\(\?<[=!]|\\[1-9]|\(\?P=")


class PatternError(ValueError):
    pass


def validate(data):
    """Every problem in a pattern file, as a list of messages. Empty means valid."""
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("patterns"), list):
        return ['patterns: expected {"schema": 1, "patterns": [...]}']
    errors, seen = [], set()
    for p in data["patterns"]:
        name = p.get("name") if isinstance(p, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_]+", name or ""):
            errors.append(f"pattern needs a lower_snake_case name: {p!r}"[:200])
            continue
        if name in seen:
            errors.append(f"{name}: listed twice")
        seen.add(name)
        if p.get("tier") not in TIER_NAMES:
            errors.append(f"{name}: tier must be A, B or C")
        rx = p.get("regex")
        if not isinstance(rx, str) or not rx:
            errors.append(f"{name}: regex missing")
        else:
            try:
                re.compile(rx)
            except re.error as err:
                errors.append(f"{name}: regex does not compile: {err}")
            if RUST_UNSUPPORTED.search(rx):
                errors.append(f"{name}: lookaround and backreferences do not work in ripgrep")
        if not isinstance(p.get("label"), str) or not p["label"].strip():
            errors.append(f"{name}: label missing")
        if "vendor_icon" in p and not p.get("vendor"):
            errors.append(f"{name}: vendor_icon needs a vendor")
        if "vendor" in p and not (isinstance(p["vendor"], str) and p["vendor"].strip()):
            errors.append(f"{name}: vendor must be a name")
        rv = p.get("revoke")
        if rv is not None and (not isinstance(rv, dict) or not rv.get("where") or
                               not str(rv.get("url", "")).startswith("https://")):
            errors.append(f"{name}: revoke needs a 'where' and an https:// url")
        for flag in FLAGS:
            if flag in p and p[flag] is not True:
                errors.append(f"{name}: {flag} is either true or absent")
        if p.get("rotate_structural") and p.get("tier") != "B":
            errors.append(f"{name}: rotate_structural only applies to tier B")
        unknown = set(p) - {"name", "tier", "regex", "label", "group", "revoke", "note", "vendor",
                            "vendor_icon"} - set(FLAGS)
        if unknown:
            errors.append(f"{name}: unknown fields {', '.join(sorted(unknown))}")
    return errors


def load(path=PATH):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    errors = validate(data)
    if errors:
        raise PatternError("invalid pattern file:\n  " + "\n  ".join(errors))
    return data["patterns"]


RULES = load()
PATTERNS = [(p["name"], p["regex"], p["tier"]) for p in RULES]
TIERS = {p["name"]: p["tier"] for p in RULES}
LABELS = {p["name"]: p["label"] for p in RULES}
REVOKE = {p["name"]: (p["revoke"]["where"], p["revoke"]["url"]) for p in RULES if p.get("revoke")}
# Tier-B structures that are unambiguous secrets: reported under "Rotate now".
ROTATE_B = {p["name"] for p in RULES if p.get("rotate_structural")}
# Which service issued a credential, for grouping and for the vendor mark on a card. Structural patterns
# (private keys, cookies, passwords) have no vendor and group by what they are instead.
VENDORS = {p["name"]: p["vendor"] for p in RULES if p.get("vendor")}
# What kind of thing issued it. impact.py turns this into how urgent a leak of it is.
GROUPS = {p["name"]: p["group"] for p in RULES if p.get("group")}
VENDOR_ICONS = {p["vendor"]: p["vendor_icon"] for p in RULES if p.get("vendor_icon")}
# Patterns that match only a fixed key header or DER prefix, not key material: evidence to review, not rotate.
HEADER_ONLY = {p["name"] for p in RULES if p.get("header_only")}
# Session cookies expire and are rotated by signing out, so they go to "Review".
SESSION_COOKIE = {p["name"] for p in RULES if p.get("session_cookie")}
# patterns that must run in rg multiline mode (-U)
MULTILINE = {p["name"] for p in RULES if p.get("multiline")}


def escape_aware(rx):
    """A token right after a JSON escape (literal backslash-n) has no \\b boundary because 'n' is a word
    character. Let every leading \\b also accept an escape; the residue is stripped per match."""
    return re.sub(r"(^(?:\(\?i\))?|\|)\\b",
                  lambda m: m.group(1) + r"(?:\b|\\[ntr]|\\u00[0-9a-fA-F]{2}|%[0-9A-Fa-f]{2})", rx)


RESIDUE = re.compile(rb"^(?:\\[ntr]|\\u00[0-9a-fA-F]{2}|%[0-9A-Fa-f]{2})")


def strip_residue(m, off):
    r = RESIDUE.match(m)
    return (m[r.end():], off + r.end()) if r else (m, off)


_TIER_A = None


def label_for_value(value):
    """Label of the first tier-A pattern that matches a plaintext value, or None."""
    global _TIER_A
    if _TIER_A is None:
        _TIER_A = [(n, re.compile(r)) for n, r, t in PATTERNS if t == "A" and n not in MULTILINE]
    s = value.decode("utf-8", "replace") if isinstance(value, bytes) else value
    for name, rx in _TIER_A:
        if rx.search(s):
            return LABELS[name]
    return None
