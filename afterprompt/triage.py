"""Group detections by credential value and decide: rotate now, review, or dismiss (with a reason)."""
import collections
import json
import os
import re
import time

from afterprompt import catalogue, impact, manifest
from afterprompt.entropy import KEEP as ENTROPY_KEEP
from afterprompt.patterns import HEADER_ONLY, LABELS, REVOKE, ROTATE_B, SESSION_COOKIE, TIERS, VENDORS
from afterprompt.util import display_path, is_under, read_json, write_json

# How many of each review category the report shows; findings.json keeps every one and the totals are exact.
CAPS = {"configuration": 20, "pattern": 60, "session_cookie": 20, "entropy": 30, "prompt": 30}
# Entropy candidates (deep mode) that reach the report. Each rule that drops a token is counted in
# review_dropped["entropy"], so a missing token can always be explained.
ENTROPY_MAX_FILES = 2        # a token repeated across more files is an identifier (a model name, a build hash)
ENTROPY_MIN_MIXING = 0.1     # "op": share of the rarer letter case, scaled by how few separators there are.
                             # Generated keys mix cases; slugs and names do not.
ENTROPY_KEEP_MAX = 500      # entropy candidates kept in findings.json; the total is still counted
REVIEW_ORDER = ["configuration", "pattern", "session_cookie", "entropy", "prompt"]
CONFIG_NAMES = catalogue.CONFIG_FILES      # a tool's configuration: secrets there are "stored in configuration"
DESIGNED = catalogue.CREDENTIAL_FILES      # a tool's own login store: its intended home, not a leak

REASONS = {
    "live_credential": "A credential that is set up on this machine appears in AI assistant history.",
    "pattern": "A credential in a vendor-specific format appears in AI assistant history.",
    "pattern_b": "An unambiguous secret (password, private key or auth header) appears in AI assistant history.",
    "configuration": "Stored in plain text in an AI tool's configuration file. It is not necessarily sent to a "
                     "model, but anyone who can read the file can use it.",
    "review_pattern": "Looks like a credential, but the format is not specific enough to be sure.",
    "session_cookie": "A session cookie. If it may still be valid, sign out of all sessions for that account.",
    "entropy": "A random-looking token near a secret-related word. Only found by the entropy sweep.",
    "prompt": "A password-like string you typed into an AI assistant.",
}


# A credential found in a .env carries no pattern, so its revoke page has to come from the variable's name.
# Each entry names a pattern that already knows where that vendor revokes keys, so the URL is written down
# once, in patterns.json. First match wins, so the specific names come before the general ones.
KEY_REVOKE = [
    (r"AZURE_(OPENAI|FOUNDRY)|AI_FOUNDRY", "azure_openai_key_ctx"),
    (r"AZURE_STORAGE|STORAGE_(ACCOUNT|CONNECTION)", "azure_conn_string"),
    (r"AZURE_(CLIENT_SECRET|AD)|ENTRA", "entra_client_secret"),
    (r"AZURE|MICROSOFT", "azure_identifiable_key"),
    (r"GOOGLE_(CLIENT_SECRET|OAUTH)|GCP_CLIENT|OAUTH_CLIENT_SECRET", "gcp_client_secret"),
    (r"GEMINI|GOOGLE_(API|GENAI|AI)|VERTEX|^GOOGLE_KEY", "google_api_key"),
    (r"^AWS|_AWS", "aws_access_key_id"),
    (r"ANTHROPIC|CLAUDE", "anthropic_key"),
    (r"OPENAI", "openai_project_key"),
    (r"OPENROUTER", "openrouter_key"),
    (r"GROQ", "groq_key"),
    (r"XAI|GROK", "xai_key"),
    (r"ELEVEN", "elevenlabs_key"),
    (r"REPLICATE", "replicate_token"),
    (r"HUGGING|^HF_", "huggingface_token"),
    (r"GITHUB", "github_token"),
    (r"GITLAB", "gitlab_token"),
    (r"DOCKER", "dockerhub_pat"),
    (r"NPM", "npm_token"),
    (r"PYPI", "pypi_token"),
    (r"STRIPE", "stripe_secret_key"),
    (r"SLACK", "slack_token"),
    (r"NOTION", "notion_token"),
    (r"LINEAR", "linear_key"),
    (r"ATLASSIAN|JIRA|CONFLUENCE", "atlassian_api_token"),
    (r"BRAVE", "brave_api_key"),
    (r"SENDGRID", "sendgrid_key"),
    (r"TELEGRAM", "telegram_bot_token"),
    (r"DISCORD", "discord_bot_token"),
    (r"CLOUDFLARE", "cloudflare_token_ctx"),
    (r"DIGITALOCEAN|^DO_TOKEN", "digitalocean_token"),
    (r"VERCEL", "vercel_token_ctx"),
    (r"PORKBUN", "porkbun_api_key"),
]
_KEY_REVOKE = [(re.compile(rx, re.I), name) for rx, name in KEY_REVOKE]
# Credentials with no vendor to send her to. Saying "the service that issued it" and stopping there is the
# one place the report asks the reader a question instead of answering it, so each of these says what to do.
SHAPE_HINTS = [
    (re.compile(r"DATABASE|DB_(URL|PASS)|POSTGRES|MYSQL|MARIADB|MONGO|REDIS", re.I),
     "Change the database password, then update every service that connects with it"),
    (re.compile(r"PRIVATE_KEY|^SSH|_SSH|DEPLOY_KEY", re.I),
     "Replace the key pair and remove the public key everywhere it is trusted"),
    (re.compile(r"WEBHOOK", re.I), "Delete the webhook in the app that owns it and create a new one"),
    (re.compile(r"JWT|SIGNING|SESSION", re.I),
     "Change the signing secret and sign every session out"),
]


def key_vendor(key):
    """Who issued a credential known only by the name it was stored under.

    A key found in a .env matches no pattern, so nothing said who issued it and AZURE_STORAGE_CONNECTION_STRING
    was filed under "other credentials" next to a password from a prompt. The same names that say where to
    revoke it say whose it is."""
    for rx, name in _KEY_REVOKE:
        if rx.search(key or ""):
            return VENDORS.get(name)
    return None


def finding_vendor(patterns, keys):
    """The service a finding belongs to: what matched it, or failing that what it was stored under."""
    for p in patterns or ():
        if p in VENDORS:
            return VENDORS[p]
    for key in keys or ():
        vendor = key_vendor(key)
        if vendor:
            return vendor
    return None


def key_revoke(key):
    """Where to revoke a credential known only by the name it was stored under."""
    for rx, name in _KEY_REVOKE:
        if rx.search(key or "") and name in REVOKE:
            return {"where": REVOKE[name][0], "url": REVOKE[name][1]}
    for rx, advice in SHAPE_HINTS:
        if rx.search(key or ""):
            return {"where": advice, "url": None}
    return None


def store_hint(store, key):
    s = store.replace("\\", "/")
    table = [("/.aws/", ("AWS IAM security credentials", "https://console.aws.amazon.com/iam/home#/security_credentials")),
             ("/.azure/", ("Azure portal", "https://portal.azure.com")),
             ("gcloud", ("Google Cloud credentials", "https://console.cloud.google.com/apis/credentials")),
             ("/.docker/", ("Docker Hub tokens", "https://app.docker.com/settings/personal-access-tokens")),
             ("/.npmrc", ("npm access tokens", "https://www.npmjs.com/settings/~/tokens")),
             ("/.pypirc", ("PyPI API tokens", "https://pypi.org/manage/account/token/")),
             ("gh/hosts.yml", ("GitHub tokens", "https://github.com/settings/tokens")),
             ("GitHub CLI/hosts.yml", ("GitHub tokens", "https://github.com/settings/tokens"))]
    for needle, hint in table:
        if needle in s:
            return {"where": hint[0], "url": hint[1]}
    if "/.ssh/" in s:
        return {"where": "Replace the key pair and remove the public key everywhere it is trusted", "url": None}
    hint = key_revoke(key)
    if hint:
        return hint
    base = os.path.basename(s)
    if base == ".env" or base.startswith(".env.") or base.endswith(".env"):
        return {"where": f"Revoke {key} wherever it was issued — look for API keys or credentials in that "
                         f"service's account settings", "url": None}
    return None


class Resolver:
    def __init__(self, cfg, sources):
        self.cfg = cfg
        self.rows = manifest.load(cfg)
        self.by_idx = {r.idx: r for r in self.rows}
        self.by_path = {r.path: r for r in self.rows}
        self.store = cfg.w("store")
        self.ext = cfg.w("extracted", "db")
        self.ledger = manifest.ledger_sides(cfg)
        self.home = cfg.home
        self.win = sources.get("windows_home")
        self.cache = {}

    def disp(self, p):
        return display_path(p, self.home, self.win)

    def __call__(self, path):
        """Location dict, or None when the file is not part of this scan."""
        if path in self.cache:
            return self.cache[path]
        loc = None
        if is_under(path, self.store):
            try:
                r = self.by_idx[int(os.path.basename(path).split(".")[0])]
            except (ValueError, KeyError):
                r = None
            if r:
                loc = self._loc(r, decoded=True)
        else:
            r = self.by_path.get(path)
            if r:
                loc = self._loc(r, decoded=False)
        self.cache[path] = loc
        return loc

    def _loc(self, r, decoded):
        path, tool, side = r.path, r.tool, r.side
        key = path
        if is_under(path, self.ext):
            tag = os.path.basename(path)[:3]
            db, side, tool = self.ledger.get(tag, (path, side, tool))
            key = db
            disp = self.disp(db) + " (chat database)"
        else:
            disp = self.disp(path)
        norm = key.replace("\\", "/")
        return {"key": key, "display": disp, "tool": tool, "side": side, "vendored": r.vendored, "self": r.self,
                "decoded": decoded, "config": bool(CONFIG_NAMES.search(norm)),
                "designed": bool(DESIGNED.search(norm))}


def rotate_key(r):
    """Worst blast radius first, then how sure we are. A report of twenty is only useful if the first
    three are the three worth doing tonight. Records from an older version carry no impact; they sort last
    within their confidence band rather than breaking the sort."""
    blast = impact.ORDER.get(r.get("impact"), len(impact.RANKS))
    rank = 0 if r["category"] == "live_credential" else (1 if r["tier"] == "A" else 2)
    return (blast, rank, -r["files"], -r["occurrences"], r["label"])


def review_key(r):
    return ({"A": 0, "B": 1, "C": 2}.get(r["tier"], 3), -r["entropy"], -r["files"])


def entropy_drop_reason(g, known_h, res):
    """Why an entropy candidate is not shown, or None when it is. The order is the order of the checks."""
    if len(g["files"]) > ENTROPY_MAX_FILES:
        return f"in more than {ENTROPY_MAX_FILES} files (an identifier)"
    if g["h"] in known_h:
        return "already reported by a pattern or as a live credential"
    if not g.get("nks"):
        return "no secret-related word right before it"
    if g["c"] in ("hex", "uuid"):
        pass
    elif g["c"] not in ENTROPY_KEEP:
        return f"shape: {g['c'].replace('_', ' ')}"
    elif g["c"] != "long_token" and g["op"] < ENTROPY_MIN_MIXING:
        return "letters not mixed like a generated key"
    if not any(i in res.by_idx and not res.by_idx[i].self and not res.by_idx[i].vendored for i in g["files"]):
        return "only in shipped code or this scan's own session"
    return None


def _jsonl(path):
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                yield json.loads(line)
            except ValueError:
                continue


def summarize_locations(hits):
    c = collections.Counter()
    meta = {}
    for loc in hits:
        k = (loc["display"], loc["decoded"])
        c[k] += 1
        meta[k] = loc
    locs = [{"display": d, "tool": meta[(d, dec)]["tool"], "side": meta[(d, dec)]["side"], "count": n,
             "decoded": dec} for (d, dec), n in c.most_common()]
    return locs


def build(cfg, sources, now=None):
    now = now or cfg.now or time.time()
    res = Resolver(cfg, sources)
    live = read_json(cfg.w("live_index.json"), {}) or {}
    dismissed = collections.Counter()

    # ---- pattern groups keyed by value hash
    groups = {}
    for target in ("raw", "store"):
        for r in _jsonl(cfg.w(f"vendor_{target}.jsonl")) or ():
            loc = res(r["f"])
            if loc is None:
                continue
            g = groups.setdefault(r["vh"], {"vh": r["vh"], "patterns": [], "tiers": set(), "m": r["m"], "n": r["n"],
                                            "hits": [], "b64": [], "ph": False, "code": False, "num": False,
                                            "exp": None, "local": False, "ctx": None, "match_hashes": set(),
                                            "vs": r.get("vs", True), "va": r.get("va", True),
                                            "vpe": r.get("vpe", 0.0)})
            if r["p"] not in g["patterns"]:
                g["patterns"].append(r["p"])
            g["tiers"].add(r["t"])
            g["match_hashes"].add(r["h"])
            g["ph"] |= r["ph"]
            g["code"] |= r["code"]
            g["num"] |= r["num"]
            g["local"] |= r.get("local", False)
            if r.get("exp") is not None:
                g["exp"] = r["exp"] if g["exp"] is None else max(g["exp"], r["exp"])
            g["hits"].append(dict(loc, b64=r["b64"], f=r["f"], o=r.get("vo", r["o"])))
            if g["ctx"] is None and not loc["self"] and not loc["vendored"]:
                g["ctx"] = r["ctx"]

    findings = {}   # vh -> finding

    def best_tier(g):
        return "A" if "A" in g["tiers"] else ("B" if "B" in g["tiers"] else "C")

    for vh, g in groups.items():
        hits = g["hits"]
        tier = best_tier(g)
        nonself = [h for h in hits if not h["self"]]
        if not nonself:
            dismissed["scan-session transcripts only"] += 1
            continue
        real = [h for h in nonself if not h["vendored"]]
        if not real:
            dismissed["vendored app or plugin code only"] += 1
            continue
        visible = [h for h in real if not h["b64"]]
        if not visible:
            dismissed["only inside base64 blobs"] += 1
            continue
        if all(h["designed"] for h in visible):
            dismissed["the tool's own credential store"] += 1
            continue
        if g["ph"]:
            dismissed["placeholder or environment reference"] += 1
            continue
        if tier != "A" and g["num"]:
            dismissed["numeric value"] += 1
            continue
        if tier == "C" and g["code"]:
            dismissed["source-code expression"] += 1
            continue
        if g["exp"] is not None and g["exp"] < now:
            dismissed["expired token"] += 1
            continue
        if g["local"]:
            dismissed["local development connection string"] += 1
            continue
        live_entry = live.get(vh)
        store_paths = {os.path.normpath(s["store"]) for s in (live_entry or {}).get("stores", [])}
        in_store_or_config = all(h["config"] or os.path.normpath(h["key"]) in store_paths for h in visible)
        if (live_entry and in_store_or_config) or all(h["config"] for h in visible):
            category, section = "configuration", "review"
        elif any(p in SESSION_COOKIE for p in g["patterns"]):
            category, section = "session_cookie", "review"
        elif all(p in HEADER_ONLY for p in g["patterns"]):
            category, section = "pattern", "review"
        elif tier == "A" and g["va"]:
            category, section = "pattern", "rotate"
        elif any(p in ROTATE_B for p in g["patterns"]) and g["vs"]:
            category, section = "pattern", "rotate"
        else:
            category, section = "pattern", "review"
        findings[vh] = {"vh": vh, "section": section, "category": category, "patterns": g["patterns"],
                        "tier": tier, "masked": g["m"], "length": g["n"], "hits": visible, "ctx": g["ctx"],
                        "match_hashes": sorted(g["match_hashes"]), "entropy": g["vpe"]}

    # ---- live values found in AI data
    kgroups = collections.defaultdict(list)
    for r in _jsonl(cfg.w("known.jsonl")) or ():
        loc = res(r["f"])
        if loc is None or loc["self"] or loc["vendored"]:
            continue
        kgroups[r["vh"]].append(dict(loc, prefix=r.get("prefix", False), f=r["f"], o=r["o"]))
    for vh, hits in kgroups.items():
        entry = live.get(vh) or {}
        if all(h["config"] or h["designed"] for h in hits):
            section, category = "review", "configuration"
        else:
            section, category = "rotate", "live_credential"
        f = findings.get(vh)
        if f is None:
            findings[vh] = {"vh": vh, "section": section, "category": category, "patterns": [], "tier": None,
                            "masked": entry.get("masked", "?"), "length": entry.get("n", 0), "hits": hits,
                            "ctx": None, "match_hashes": [], "entropy": 0.0}
        else:
            f["hits"] = f["hits"] + hits
            if section == "rotate":
                f["section"], f["category"] = "rotate", "live_credential"

    # ---- build output records
    rotate, review = [], collections.defaultdict(list)
    for vh, f in findings.items():
        seen, uniq = set(), []
        for h in f["hits"]:          # several detectors can report the same occurrence
            k = (h["f"], h["o"])
            if k not in seen:
                seen.add(k)
                uniq.append(h)
        raw_files = {h["key"] for h in uniq if not h["decoded"]}
        f["hits"] = [h for h in uniq if not (h["decoded"] and h["key"] in raw_files)]
        entry = live.get(vh) or {}
        stores = [s for s in entry.get("stores", []) if not s.get("designed")]
        tier_a = [p for p in f["patterns"] if TIERS.get(p) == "A"]
        first = (tier_a or f["patterns"] or [None])[0]
        label = entry.get("label")
        if not label and stores and f["category"] in ("live_credential", "configuration") and \
                (not first or TIERS.get(first) != "A"):
            label = f"Secret from {res.disp(stores[0]['store'])} ({stores[0]['key']})"
        label = label or (LABELS.get(first) if first else None) or "Credential"
        revoke = None
        if first and first in REVOKE:
            revoke = {"where": REVOKE[first][0], "url": REVOKE[first][1]}
        for p in f["patterns"]:
            if revoke is None and p in REVOKE:
                revoke = {"where": REVOKE[p][0], "url": REVOKE[p][1]}
        if revoke is None:
            for s in stores:
                revoke = store_hint(s["store"], s["key"])
                if revoke:
                    break
        locs = summarize_locations(f["hits"])
        reason_key = f["category"]
        if f["category"] == "pattern":
            reason_key = "pattern" if f["section"] == "rotate" and f["tier"] == "A" else (
                "pattern_b" if f["section"] == "rotate" else "review_pattern")
        rec = {"category": f["category"], "label": label, "masked": f["masked"], "length": f["length"],
               "hash": vh, "match_hashes": f["match_hashes"], "patterns": f["patterns"], "tier": f["tier"],
               "tools": sorted({h["tool"] for h in f["hits"]}), "sides": sorted({h["side"] for h in f["hits"]}),
               "files": len({h["key"] for h in f["hits"]}), "occurrences": len(f["hits"]),
               "locations": locs[:5], "decoded_only": all(h["decoded"] for h in f["hits"]),
               "still_on_disk": [{"store": res.disp(s["store"]), "key": s["key"]} for s in stores],
               "revoke": revoke, "reason": REASONS[reason_key], "context": f["ctx"], "entropy": f["entropy"],
               "impact": impact.rank(f["patterns"], [s["key"] for s in stores]),
               "vendor": finding_vendor(f["patterns"], [s["key"] for s in stores])}
        if f["section"] == "rotate":
            rotate.append(rec)
        else:
            review[f["category"]].append(rec)

    rotate.sort(key=rotate_key)
    for cat in review:
        review[cat].sort(key=review_key)

    # ---- entropy (deep)
    entropy_dropped = collections.Counter()
    if cfg.deep:
        known_h = set(findings)
        for grp in groups.values():
            known_h.update(grp["match_hashes"])
        E = {}
        for target in ("raw", "store"):
            d = cfg.w(f"entropy_{target}")
            if not os.path.isdir(d):
                continue
            for fn in os.listdir(d):
                if not fn.endswith(".jsonl"):
                    continue
                for r in _jsonl(os.path.join(d, fn)):
                    if "_status" in r:
                        continue
                    g = E.setdefault(r["h"], dict(r, files=set()))
                    g["nk"] = g["nk"] or r["nk"]
                    g["nks"] = g.get("nks", False) or r.get("nks", False)
                    g["files"].add(r["f"])
        # A strict secret word (key, secret, password, auth, bearer, credential, token) right before the token,
        # and a token that looks generated: mixed case with digits, a long url-safe token, or hex/uuid.
        cands = []
        for g in E.values():
            why = entropy_drop_reason(g, known_h, res)
            if why:
                entropy_dropped[why] += 1
            else:
                cands.append(g)
        cands.sort(key=lambda g: (-g["op"], -g["e"]))
        entropy_total = len(cands)
        for g in cands[:ENTROPY_KEEP_MAX]:
            locs = [res._loc(res.by_idx[i], False) for i in sorted(g["files"]) if i in res.by_idx]
            review["entropy"].append({
                "category": "entropy", "label": f"Random-looking token ({g['c'].replace('_', ' ')})",
                "masked": g["m"], "length": g["n"], "hash": g["h"], "match_hashes": [], "patterns": [],
                "tier": None, "tools": sorted({l["tool"] for l in locs}), "sides": sorted({l["side"] for l in locs}),
                "files": len(locs), "occurrences": len(locs), "locations": summarize_locations(locs)[:5],
                "decoded_only": False, "still_on_disk": [], "revoke": None, "reason": REASONS["entropy"],
                "context": None, "entropy": g["e"], "impact": impact.DEFAULT, "vendor": None})

    # ---- prompts
    taken = set(findings)
    for p in sorted(read_json(cfg.w("prompts.json"), []) or [], key=lambda x: -x.get("e", 0)):
        if not p.get("kw") or p["h"] in taken:
            continue
        review["prompt"].append({
            "category": "prompt", "label": "Password-like string in a prompt", "masked": p["shape"],
            "length": None, "hash": p["h"], "match_hashes": [], "patterns": [], "tier": None,
            "tools": ["Cursor" if p["src"].startswith("Cursor") else "Claude Code"], "sides": [],
            "files": 1, "occurrences": 1, "locations": [{"display": f"{p['src']}, {p['when']}", "tool": "", "side": "",
                                                         "count": 1, "decoded": False}],
            "decoded_only": False, "still_on_disk": [], "revoke": None, "reason": REASONS["prompt"],
            "context": p["ctx"], "entropy": p.get("e", 0.0), "impact": impact.DEFAULT, "vendor": None})

    review_out, truncated = [], {}
    for cat in REVIEW_ORDER:
        items = review.get(cat, [])
        if len(items) > CAPS[cat]:
            truncated[cat] = len(items) - CAPS[cat]
        review_out.extend(items)
    for i, r in enumerate(rotate, 1):
        r["id"] = f"R{i}"
    for i, r in enumerate(review_out, 1):
        r["id"] = f"V{i}"
    totals = {c: len(review.get(c, [])) for c in REVIEW_ORDER}
    if cfg.deep:
        totals["entropy"] = entropy_total
        if entropy_total > CAPS["entropy"]:
            truncated["entropy"] = entropy_total - CAPS["entropy"]
    out = {"rotate": rotate, "review": review_out, "review_totals": totals,
           "review_truncated": truncated, "dismissed": dict(dismissed),
           "review_dropped": {"entropy": dict(entropy_dropped)} if cfg.deep else {}}
    write_json(cfg.w("triage.json"), out)
    return out
