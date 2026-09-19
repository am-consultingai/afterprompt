"""findings.json, report.md and report.html (self-contained, no remote resources).

The HTML report is unbranded by default (assets/report.css, part of Afterprompt). --theme am applies the AM
Consulting brand, whose assets are not covered by the project's license (assets/NOTICE.md)."""
import datetime
import html
import os
import shutil

from afterprompt import __version__, envs, merge
from afterprompt.triage import CAPS
from afterprompt.util import human_bytes, read_json, write_json

THEMES = {
    "neutral": {"assets": ("report.css",), "css": "report.css", "icon": None, "scheme": "light dark",
                "credit": ""},
    "am": {"assets": ("brand.css", "am-logo-white-600.png", "am-favicon.png"), "css": "brand.css",
           "icon": "am-favicon.png", "scheme": "dark", "credit": " · Built by AM Consulting"},
}
DEFAULT_THEME = "neutral"
ASSETS = THEMES[DEFAULT_THEME]["assets"]
SIDE_NAMES = {"wsl": "WSL", "windows": "Windows", "macos": "macOS", "linux": "Linux"}
PLATFORM_NAMES = {"wsl": "Windows (WSL)", "macos": "macOS", "linux": "Linux", "windows": "Windows"}
CATEGORY_TITLES = {
    "configuration": "Stored in AI tool configuration",
    "pattern": "Possible credentials",
    "session_cookie": "Session cookies",
    "entropy": "Random-looking tokens (deep scan)",
    "prompt": "Password-like strings in your prompts",
}
LIMITS = [
    "Text inside screenshots and images is not read (no OCR). Compressed PDF streams are skipped.",
    "Tokens with no digits are not treated as entropy candidates.",
    "AI tools prune old transcripts (Claude Code after about 30 days), so older exposure cannot be seen locally.",
    "Copies held on AI vendors' servers cannot be scanned or deleted from this machine.",
    "The scan cannot tell whether a credential is still valid; it does not contact any service.",
]
NEXT_STEPS = [
    ("Rotate every credential under “Rotate now”.",
     "Deleting the transcript does not undo the exposure: the value was already sent to the model vendor as chat "
     "context. Revoke it and issue a new one."),
    ("Remove the copies that are still on disk.",
     "Move secrets out of hardcoded files into environment variables or a secrets manager."),
    ("Change the habits that leak credentials.",
     "Don't paste keys into prompts, and don't let agents cat .env files or print environment variables."),
]


def side_label(s):
    if s.startswith("wsl:"):
        return f"WSL: {s[4:]}"
    if s.startswith("env:"):
        return s[4:]
    return SIDE_NAMES.get(s, s)


def coverage(cfg, sources):
    st = lambda name: read_json(cfg.w("state", f"{name}.done"), {}) or {}  # noqa: E731
    man, cur, ven, known, prm = st("manifest"), st("databases"), st("vendor_raw"), st("known"), st("prompts")
    cov = {
        "platform": sources.get("platform"),
        "windows_home": sources.get("windows_home"),
        "windows_home_source": sources.get("windows_home_source"),
        "other_homes": envs.other_homes(cfg.home),
        "sources": man.get("per_source", []),
        "files": man.get("files", 0), "bytes": man.get("bytes", 0),
        "missing_locations": sources.get("missing", []),
        "databases": {"total": cur.get("databases", 0), "ok": cur.get("ok", 0),
                             "failed": cur.get("failed", [])},
        "unreadable_files": man.get("unreadable", 0), "unreadable_examples": man.get("unreadable_examples", [])[:20],
        "excluded_files": man.get("excluded", 0), "vendored_files": man.get("vendored", 0),
        "scan_session_files": man.get("self", 0),
        "pattern_truncations": ven.get("truncated", []) + st("vendor_store").get("truncated", []),
        "live_values": {k: known.get(k) for k in ("values", "stores", "env_files", "credential_named_files",
                                                  "walk_truncated", "expired_skipped", "prefix_keys", "occurrences")},
        "keychain": known.get("keychain", "not requested"),
        "prompts": prm,
        "limits": LIMITS,
    }
    if cfg.deep:
        dec = st("expand")
        cov["decode"] = {"statuses": dec.get("statuses", {}), "decoded_bytes": dec.get("decoded_bytes", 0),
                         "disk_cap_reached": dec.get("disk_cap_reached", False),
                         "not_decoded": dec.get("not_decoded", 0)}
    return cov


def build_findings(cfg, sources, run_meta):
    tri = read_json(cfg.w("triage.json"), {})
    data = {"schema": 1, "tool": "afterprompt", "version": __version__, "run_id": run_meta["run_id"],
            "mode": cfg.mode, "started": run_meta["started"],
            "finished": datetime.datetime.now().isoformat(timespec="seconds"),
            "platform": {"kind": cfg.platform, "home": "~", "windows_home": sources.get("windows_home"),
                         "windows_home_source": sources.get("windows_home_source")},
            "summary": {"rotate": len(tri["rotate"]),
                        "review": sum(n for c, n in tri["review_totals"].items() if c != "entropy"),
                        "entropy_candidates": tri["review_totals"].get("entropy", 0),
                        "review_shown": sum(min(n, CAPS[c]) for c, n in tri["review_totals"].items()),
                        "dismissed": sum(tri["dismissed"].values())},
            "rotate": tri["rotate"], "review": tri["review"], "review_totals": tri["review_totals"],
            "review_truncated": tri["review_truncated"], "dismissed": tri["dismissed"],
            "coverage": coverage(cfg, sources)}
    from afterprompt.util import display_path
    wh = sources.get("windows_home")
    if wh:
        data["platform"]["windows_home"] = display_path(wh, None, wh)
    return data


def context_line(data):
    when = data["finished"].replace("T", " ")[:16]
    plat = PLATFORM_NAMES.get(data["platform"]["kind"], data["platform"]["kind"])
    # The Windows profile is only worth naming when it was reached across the WSL bridge; on Windows
    # itself it is simply the home directory and the note would be noise.
    show_profile = data["platform"]["kind"] == "wsl" and data["platform"].get("windows_home")
    extra = f" · Windows profile {data['platform']['windows_home']}" if show_profile else ""
    n = len(data.get("environments") or [])
    if n > 1:
        extra += f" · {n} environments"
    return f"{when} · {data['mode']} scan · {plat}{extra}"


def where(rec):
    tools = ", ".join(rec["tools"]) or "—"
    sides = ", ".join(side_label(s) for s in rec["sides"])
    return f"{tools} ({sides})" if sides else tools


# ------------------------------------------------------------------ markdown
def render_md(data, theme=DEFAULT_THEME):
    L = []
    P = L.append
    s = data["summary"]
    P("# Afterprompt report\n")
    P(context_line(data) + "\n")
    extra = f" · Random-looking tokens: {s['entropy_candidates']:,}" if s.get("entropy_candidates") else ""
    P(f"**Rotate now: {s['rotate']}** · Review: {s['review']:,}{extra} · Dismissed automatically: {s['dismissed']:,}\n")
    P("## Rotate now\n")
    if not data["rotate"]:
        P("Nothing to rotate. No credential from this machine and no vendor-specific key was found in AI tool history.\n")
    for r in data["rotate"]:
        P(f"### {r['id']}. {r['label']} `{r['masked']}`\n")
        P(f"- Exposed in: {where(r)} — {r['files']} file(s), {r['occurrences']} occurrence(s)")
        for loc in r["locations"]:
            P(f"  - `{loc['display']}` ×{loc['count']}{' (decoded)' if loc['decoded'] else ''}")
        if r["still_on_disk"]:
            P("- Still on disk: " + ", ".join(f"`{x['store']}` ({x['key']})" for x in r["still_on_disk"]))
        if r["revoke"]:
            P(f"- Revoke: {r['revoke']['where']}" + (f" — {r['revoke']['url']}" if r["revoke"].get("url") else ""))
        P(f"- Why: {r['reason']}\n")
    P("## Review\n")
    if not data["review"]:
        P("Nothing to review.\n")
    for cat in ("configuration", "pattern", "session_cookie", "entropy", "prompt"):
        items = [r for r in data["review"] if r["category"] == cat][:CAPS[cat]]
        if not items:
            continue
        total = data["review_totals"].get(cat, len(items))
        P(f"### {CATEGORY_TITLES[cat]} ({total})\n")
        for r in items:
            loc = r["locations"][0]["display"] if r["locations"] else ""
            ctx = f" — context: `{r['context'][:160]}`" if r.get("context") else ""
            P(f"- {r['label']} `{r['masked']}` — {loc}{ctx}")
        if data["review_truncated"].get(cat):
            P(f"- …and {data['review_truncated'][cat]} more in findings.json")
        P("")
    P("## What to do next\n")
    for title, body in NEXT_STEPS:
        P(f"- **{title}** {body}")
    P("\n## Coverage\n")
    for row in coverage_rows(data):
        P(f"- **{row[0]}:** {row[1]}")
    if data["dismissed"]:
        P("\nDismissed automatically:\n")
        for k, v in sorted(data["dismissed"].items(), key=lambda kv: -kv[1]):
            P(f"- {k}: {v}")
    P("\n## What this scan cannot see\n")
    for x in data["coverage"]["limits"]:
        P(f"- {x}")
    P(f"\n---\nAfterprompt {data['version']} · FSL-1.1-ALv2{THEMES[theme]['credit']}\n")
    return "\n".join(L)


def environment_text(env):
    status = env["status"]
    if status in ("scanned", "scanned_share"):
        text = merge.STATUS_TEXT[status]
        if env.get("files") is not None:
            text += f" · {env['files']:,} files, {human_bytes(env.get('bytes', 0))} · {env.get('rotate', 0)} to rotate"
    else:
        text = f"{merge.STATUS_TEXT.get(status, status)}: {env.get('reason') or 'no reason recorded'}"
    if env.get("notice"):
        text += f" ({env['notice']})"
    return text


def other_homes_text(names):
    return f"{', '.join(names)}: not scanned (they belong to other users, and the scan never elevates)"


def coverage_rows(data):
    c = data["coverage"]
    rows = []
    for s in c["sources"]:
        rows.append((f"{s['tool']} ({side_label(s['side'])})", f"{s['files']:,} files, {human_bytes(s['bytes'])}"))
    if not c["sources"]:
        rows.append(("AI tool data", "none found"))
    if c["platform"] == "wsl":
        rows.append(("Windows profile", f"{c['windows_home'] or 'not found'} ({c['windows_home_source']})"))
    # One line per environment. A clean total must never hide a gap in one of them.
    for env in data.get("environments") or []:
        rows.append((f"Environment: {env['label']}", environment_text(env)))
        if env.get("other_homes"):
            rows.append((f"Other users on {env['label']}", other_homes_text(env["other_homes"])))
    if not data.get("environments") and c.get("other_homes"):
        rows.append(("Other users on this machine", other_homes_text(c["other_homes"])))
    cd = c["databases"]
    rows.append(("Chat databases", f"{cd['ok']} of {cd['total']} read"))
    for f in cd["failed"]:
        rows.append(("Database not read", f"{f['path']}: {f['error']} (quit the app that owns it and run the scan again)"))
    rows.append(("Unreadable files", str(c["unreadable_files"])))
    rows.append(("Excluded / vendored / scan-session files",
                 f"{c['excluded_files']} / {c['vendored_files']} / {c['scan_session_files']}"))
    lv = c["live_values"]
    if lv.get("values") is not None:
        rows.append(("Live credentials checked", f"{lv['values']:,} values from {lv['stores']} stores "
                                                 f"({lv['env_files']} .env files, {lv['credential_named_files']} "
                                                 f"credential-named files)"))
        if lv.get("walk_truncated"):
            rows.append(("Folder search stopped early (time budget)", ", ".join(lv["walk_truncated"])))
    rows.append(("macOS Keychain", c["keychain"]))
    if c.get("prompts"):
        rows.append(("Prompts reviewed", f"{c['prompts'].get('unique_prompts', 0):,}"))
    if c["pattern_truncations"]:
        rows.append(("Pattern passes cut short", "; ".join(c["pattern_truncations"])))
    if "decode" in c:
        d = c["decode"]
        status = ", ".join(f"{k} {v}" for k, v in sorted(d["statuses"].items()))
        rows.append(("Decoded", f"{human_bytes(d['decoded_bytes'])} ({status})"))
        if d["disk_cap_reached"]:
            rows.append(("Disk cap reached", f"{d['not_decoded']} files not decoded; raise --max-disk to cover them"))
    return rows


# ------------------------------------------------------------------ html
CSS = """
.sec{scroll-margin-top:72px}
.hero h2{max-width:none}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:28px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px}
.stat b{display:block;font-family:var(--display);font-size:34px;font-weight:600;line-height:1.1}
.stat span{font-family:var(--mono);font-size:10.5px;letter-spacing:var(--ls);text-transform:uppercase;color:var(--s4)}
.stat.bad b{color:var(--bad)} .stat.warn b{color:var(--warn)} .stat.good b{color:var(--good)}
.findings{display:grid;gap:14px;margin-top:26px}
.finding .top{display:flex;flex-wrap:wrap;align-items:baseline;gap:10px 14px}
.finding h3{font-size:19px}
.badge{font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;text-transform:uppercase;padding:3px 8px;
  border-radius:6px;border:1px solid currentColor}
.badge.bad{color:var(--bad)} .badge.warn{color:var(--warn)}
.finding dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:16px 0 0;font-size:15px}
.finding dt{color:var(--s4);font-family:var(--mono);font-size:11px;letter-spacing:.06em;text-transform:uppercase;
  padding-top:3px}
.finding dd{margin:0;color:var(--s2);min-width:0}
.locs{list-style:none;margin:0;padding:0}
.locs li{font-family:var(--mono);font-size:12.5px;color:var(--s3);overflow-wrap:anywhere}
.why{margin-top:14px;font-size:14.5px;color:var(--s3)}
.acc-b ul{margin:0;padding-left:18px}
.acc-b li{margin:8px 0;overflow-wrap:anywhere}
.acc-b .ctx{display:block;font-family:var(--mono);font-size:12px;color:var(--s4)}
.cov{width:100%;border-collapse:collapse;margin-top:22px;font-size:15px}
.cov td{border-bottom:1px solid var(--line-soft);padding:10px 8px;vertical-align:top;color:var(--s2);overflow-wrap:anywhere}
.cov td:first-child{color:var(--s4);font-family:var(--mono);font-size:11.5px;letter-spacing:.04em;width:34%}
.steps{display:grid;gap:12px;margin-top:22px}
.limits{margin:18px 0 0;padding-left:18px;color:var(--s2);font-size:15.5px}
.limits li{margin:6px 0}
.brandname{font-family:var(--display);font-weight:600;font-size:16px;color:var(--s2);margin-left:auto}
.empty{margin-top:22px}
@media(max-width:640px){.finding dl{grid-template-columns:1fr}.finding dt{padding-top:8px}
  .cov td:first-child{width:auto}.brandname{display:none}}
footer{margin-top:64px}
"""


def e(s):
    return html.escape("" if s is None else str(s), quote=True)


def render_html(data, theme=DEFAULT_THEME):
    th = THEMES[theme]
    s = data["summary"]
    out = []
    P = out.append
    title = f"{s['rotate']} credential{'s' if s['rotate'] != 1 else ''} to rotate" if s["rotate"] else "Nothing to rotate"
    P("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    P("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    P(f"<meta name=\"color-scheme\" content=\"{th['scheme']}\">")
    P(f"<title>Afterprompt report</title>")
    if th["icon"]:
        P(f"<link rel=\"icon\" href=\"report-assets/{th['icon']}\">")
    P(f"<link rel=\"stylesheet\" href=\"report-assets/{th['css']}\">")
    P(f"<style>{CSS}</style></head><body>")
    if theme == "am":
        P("<nav class=\"nav\"><div class=\"nav-in\"><img class=\"nav-logo\" src=\"report-assets/am-logo-white-600.png\" "
          "alt=\"AM Consulting\"><span class=\"brandname\">Afterprompt</span></div></nav>")
    else:
        P("<nav class=\"nav\"><div class=\"nav-in\"><span class=\"wordmark\">Afterprompt</span></div></nav>")
    P("<main>")
    P("<section class=\"sec hero\"><div class=\"eyebrow\">Credential exposure report</div>")
    P(f"<h2>{e(title)}</h2><p class=\"sub\">{e(context_line(data))}</p>")
    P("<div class=\"stats\">")
    P(f"<div class=\"stat {'bad' if s['rotate'] else 'good'}\"><b>{s['rotate']}</b><span>Rotate now</span></div>")
    P(f"<div class=\"stat {'warn' if s['review'] else ''}\"><b>{s['review']:,}</b><span>To review</span></div>")
    P(f"<div class=\"stat\"><b>{s['dismissed']:,}</b><span>Dismissed automatically</span></div>")
    P(f"<div class=\"stat\"><b>{data['coverage']['files']:,}</b><span>Files scanned · "
      f"{e(human_bytes(data['coverage']['bytes']))}</span></div>")
    P("</div></section>")

    P("<section class=\"sec\" id=\"rotate\"><div class=\"eyebrow\">Act now</div><h2>Rotate now</h2>")
    if not data["rotate"]:
        P("<div class=\"rule empty\"><span class=\"ic\">✓</span><p><b>Nothing to rotate.</b> No credential from this "
          "machine and no vendor-specific key was found in AI tool history.</p></div>")
    else:
        P("<p class=\"sub\">Each of these was found in AI assistant history. Revoke it and issue a new one; deleting "
          "the transcript does not undo the exposure.</p><div class=\"findings\">")
        for r in data["rotate"]:
            P("<article class=\"card finding\"><div class=\"top\">")
            P(f"<span class=\"badge bad\">{e(r['id'])}</span><h3>{e(r['label'])}</h3><code>{e(r['masked'])}</code>")
            P("</div><dl>")
            P(f"<dt>Exposed in</dt><dd>{e(where(r))} · {r['files']} file{'s' if r['files'] != 1 else ''}, "
              f"{r['occurrences']} occurrence{'s' if r['occurrences'] != 1 else ''}<ul class=\"locs\">")
            for loc in r["locations"]:
                P(f"<li>{e(loc['display'])} ×{loc['count']}{' (decoded)' if loc['decoded'] else ''}</li>")
            P("</ul></dd>")
            if r["still_on_disk"]:
                P("<dt>Still on disk</dt><dd><ul class=\"locs\">")
                for x in r["still_on_disk"]:
                    P(f"<li>{e(x['store'])} ({e(x['key'])})</li>")
                P("</ul></dd>")
            if r["revoke"]:
                if r["revoke"].get("url"):
                    P(f"<dt>Revoke</dt><dd><a href=\"{e(r['revoke']['url'])}\" rel=\"noreferrer noopener\" "
                      f"target=\"_blank\">{e(r['revoke']['where'])}</a></dd>")
                else:
                    P(f"<dt>Revoke</dt><dd>{e(r['revoke']['where'])}</dd>")
            P(f"</dl><p class=\"why\">{e(r['reason'])}</p></article>")
        P("</div>")
    P("</section>")

    P("<section class=\"sec\" id=\"review\"><div class=\"eyebrow\">Look at these</div><h2>Review</h2>")
    if not data["review"]:
        P("<p class=\"sub\">Nothing to review.</p>")
    else:
        P("<p class=\"sub\">Weaker signals. Open each group and decide whether the value is real and still valid.</p>")
        P("<div style=\"margin-top:18px\">")
        for cat in ("configuration", "pattern", "session_cookie", "entropy", "prompt"):
            items = [r for r in data["review"] if r["category"] == cat][:CAPS[cat]]
            if not items:
                continue
            total = data["review_totals"].get(cat, len(items))
            P(f"<details class=\"acc\"><summary>{e(CATEGORY_TITLES[cat])} "
              f"<span class=\"badge warn\">{total}</span><svg class=\"chev\" viewBox=\"0 0 24 24\">"
              f"<path d=\"M6 9l6 6 6-6\"/></svg></summary><div class=\"acc-b\"><p>{e(items[0]['reason'])}</p><ul>")
            for r in items:
                loc = r["locations"][0]["display"] if r["locations"] else ""
                P(f"<li><b>{e(r['label'])}</b> <code>{e(r['masked'])}</code> — {e(loc)}")
                if r.get("context"):
                    P(f"<span class=\"ctx\">{e(r['context'][:200])}</span>")
                P("</li>")
            if data["review_truncated"].get(cat):
                P(f"<li>…and {data['review_truncated'][cat]} more in findings.json</li>")
            P("</ul></div></details>")
        P("</div>")
    P("</section>")

    P("<section class=\"sec\"><div class=\"eyebrow\">Next</div><h2>What to do next</h2><div class=\"steps\">")
    for i, (t, b) in enumerate(NEXT_STEPS, 1):
        P(f"<div class=\"rule\"><span class=\"ic\">{i}</span><p><b>{e(t)}</b> {e(b)}</p></div>")
    P("</div></section>")

    P("<section class=\"sec\"><div class=\"eyebrow\">Coverage</div><h2>What was scanned</h2><table class=\"cov\">")
    for k, v in coverage_rows(data):
        P(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>")
    if data["dismissed"]:
        dis = "; ".join(f"{k}: {v}" for k, v in sorted(data["dismissed"].items(), key=lambda kv: -kv[1]))
        P(f"<tr><td>Dismissed automatically</td><td>{e(dis)}</td></tr>")
    P("</table><h3 style=\"margin-top:34px;font-size:19px\">What this scan cannot see</h3><ul class=\"limits\">")
    for x in data["coverage"]["limits"]:
        P(f"<li>{e(x)}</li>")
    P("</ul></section></main>")
    P(f"<footer>Afterprompt {e(data['version'])} · FSL-1.1-ALv2{e(th['credit'])}</footer>")
    P("</body></html>")
    return "\n".join(out)


def write(cfg, sources, run_meta, host_env=None, env_results=None):
    data = build_findings(cfg, sources, run_meta)
    if env_results:
        data = merge.merge(data, host_env, env_results)
    theme = getattr(cfg, "theme", None) or DEFAULT_THEME
    os.makedirs(cfg.report_dir, mode=0o700, exist_ok=True)
    write_json(os.path.join(cfg.report_dir, "findings.json"), data)
    with open(os.path.join(cfg.report_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_md(data, theme))
    with open(os.path.join(cfg.report_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html(data, theme))
    assets_out = os.path.join(cfg.report_dir, "report-assets")
    os.makedirs(assets_out, mode=0o700, exist_ok=True)
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")
    # A report folder reused with another theme must not keep the other theme's files.
    for other in {a for t in THEMES.values() for a in t["assets"]} - set(THEMES[theme]["assets"]):
        try:
            os.remove(os.path.join(assets_out, other))
        except OSError:
            pass
    for a in THEMES[theme]["assets"]:
        shutil.copyfile(os.path.join(here, a), os.path.join(assets_out, a))
    return data
