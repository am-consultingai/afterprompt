"""One report from several environments (M2, M3).

Each environment is triaged where it was scanned; only masked values and value hashes come back. Hashes are
unsalted sha256[:16] of the value, so the same credential seen in a WSL transcript and in a Windows Cursor
database is one finding with two locations, not two findings. The rules:

- rotate if any environment says rotate;
- otherwise the strongest category wins (configuration > pattern > session cookie > entropy > prompt);
- counts add up, tools, sides, patterns and still-on-disk stores are united, and locations keep the busiest five.

A gap in one environment must never hide behind a clean total, so every environment keeps its own status line.
"""
import copy

from afterprompt.triage import CAPS, REVIEW_ORDER, review_key, rotate_key

STATUS_TEXT = {"scanned": "scanned", "scanned_share": "scanned over the network share (slower)",
               "not_scanned": "not scanned", "skipped": "skipped"}


def _remap(rec, side, prefix):
    rec = copy.deepcopy(rec)
    rec["sides"] = [side] if rec.get("sides") else []
    for loc in rec.get("locations", []):
        if loc.get("side"):
            loc["side"] = side
        loc["display"] = f"[{prefix}] {loc['display']}"
    for s in rec.get("still_on_disk", []):
        s["store"] = f"[{prefix}] {s['store']}"
    return rec


def _strength(rec, section):
    if section == "rotate":
        return (0, 0 if rec["category"] == "live_credential" else 1)
    return (1, REVIEW_ORDER.index(rec["category"]) if rec["category"] in REVIEW_ORDER else len(REVIEW_ORDER))


def _union(a, b):
    out = list(a or [])
    for x in b or []:
        if x not in out:
            out.append(x)
    return out


def combine(a, a_section, b, b_section):
    """The merged record and its section. a and b describe the same value hash."""
    (base, section), (other, _) = sorted([(a, a_section), (b, b_section)], key=lambda p: _strength(*p))
    out = copy.deepcopy(base)
    out["tools"] = sorted(set(a["tools"]) | set(b["tools"]))
    out["sides"] = sorted(set(a["sides"]) | set(b["sides"]))
    out["files"] = a["files"] + b["files"]
    out["occurrences"] = a["occurrences"] + b["occurrences"]
    out["locations"] = sorted(a["locations"] + b["locations"], key=lambda l: -l["count"])[:5]
    out["still_on_disk"] = _union(a["still_on_disk"], b["still_on_disk"])
    out["patterns"] = _union(base["patterns"], other["patterns"])
    out["match_hashes"] = sorted(set(a["match_hashes"]) | set(b["match_hashes"]))
    out["revoke"] = base.get("revoke") or other.get("revoke")
    out["context"] = base.get("context") or other.get("context")
    out["entropy"] = max(a.get("entropy") or 0, b.get("entropy") or 0)
    out["decoded_only"] = a["decoded_only"] and b["decoded_only"]
    if base["label"] == "Credential" and other["label"] != "Credential":
        out["label"] = other["label"]
    return out, section


def merge_findings(parts):
    """parts: [(data, side, prefix)]; prefix None leaves that environment's records as they are (the host)."""
    merged = {}     # hash -> [record, section]
    order = []
    extra_totals = {c: 0 for c in REVIEW_ORDER}
    dismissed = {}
    for data, side, prefix in parts:
        for section, recs in (("rotate", data.get("rotate", [])), ("review", data.get("review", []))):
            for rec in recs:
                rec = _remap(rec, side, prefix) if prefix else copy.deepcopy(rec)
                h = rec["hash"]
                if h in merged:
                    merged[h] = list(combine(merged[h][0], merged[h][1], rec, section))
                else:
                    merged[h] = [rec, section]
                    order.append(h)
        listed = {c: 0 for c in REVIEW_ORDER}
        for rec in data.get("review", []):
            if rec["category"] in listed:
                listed[rec["category"]] += 1
        # Totals can exceed the list (entropy candidates are capped in findings.json); keep what was not listed.
        for c, n in (data.get("review_totals") or {}).items():
            if c in extra_totals:
                extra_totals[c] += max(0, n - listed.get(c, 0))
        for k, v in (data.get("dismissed") or {}).items():
            dismissed[k] = dismissed.get(k, 0) + v
    rotate = sorted((merged[h][0] for h in order if merged[h][1] == "rotate"), key=rotate_key)
    review = []
    totals = {}
    for c in REVIEW_ORDER:
        items = sorted((merged[h][0] for h in order if merged[h][1] == "review" and merged[h][0]["category"] == c),
                       key=review_key)
        review.extend(items)
        totals[c] = len(items) + extra_totals[c]
    for i, r in enumerate(rotate, 1):
        r["id"] = f"R{i}"
    for i, r in enumerate(review, 1):
        r["id"] = f"V{i}"
    truncated = {c: n - CAPS[c] for c, n in totals.items() if n > CAPS[c]}
    return {"rotate": rotate, "review": review, "review_totals": totals, "review_truncated": truncated,
            "dismissed": dismissed}


def _sum(a, b):
    return (a or 0) + (b or 0)


def merge_coverage(host_cov, others):
    """others: [(coverage, side, prefix)]. Adds the other environments' counts into the host's coverage."""
    cov = copy.deepcopy(host_cov)
    for c, side, prefix in others:
        if not c:
            continue
        cov["sources"] = cov.get("sources", []) + [dict(s, side=side) for s in c.get("sources", [])]
        for k in ("files", "bytes", "unreadable_files", "excluded_files", "vendored_files", "scan_session_files"):
            cov[k] = _sum(cov.get(k), c.get(k))
        cd, od = cov.setdefault("databases", {"total": 0, "ok": 0, "failed": []}), c.get("databases") or {}
        cd["total"] = _sum(cd.get("total"), od.get("total"))
        cd["ok"] = _sum(cd.get("ok"), od.get("ok"))
        cd["failed"] = cd.get("failed", []) + [dict(f, path=f"[{prefix}] {f.get('path', '')}")
                                               for f in od.get("failed", [])]
        cov["pattern_truncations"] = cov.get("pattern_truncations", []) + \
            [f"[{prefix}] {t}" for t in c.get("pattern_truncations", [])]
        lv, olv = cov.setdefault("live_values", {}), c.get("live_values") or {}
        if olv.get("values") is not None:
            for k in ("values", "stores", "env_files", "credential_named_files", "expired_skipped", "prefix_keys",
                      "occurrences"):
                lv[k] = _sum(lv.get(k), olv.get(k))
            if olv.get("walk_truncated"):
                lv["walk_truncated"] = (lv.get("walk_truncated") or []) + \
                    [f"[{prefix}] {w}" for w in olv["walk_truncated"]]
        if c.get("prompts"):
            p = cov.setdefault("prompts", {})
            p["unique_prompts"] = _sum(p.get("unique_prompts"), c["prompts"].get("unique_prompts"))
        if "decode" in c:
            d = cov.setdefault("decode", {"statuses": {}, "decoded_bytes": 0, "disk_cap_reached": False,
                                          "not_decoded": 0})
            for k, v in c["decode"].get("statuses", {}).items():
                d["statuses"][k] = d["statuses"].get(k, 0) + v
            d["decoded_bytes"] = _sum(d.get("decoded_bytes"), c["decode"].get("decoded_bytes"))
            d["not_decoded"] = _sum(d.get("not_decoded"), c["decode"].get("not_decoded"))
            d["disk_cap_reached"] = d.get("disk_cap_reached") or c["decode"].get("disk_cap_reached", False)
    return cov


def environment_row(env, data):
    """One line per environment for the report: what it contributed, or why it did not."""
    row = {"name": env["name"], "kind": env["kind"], "label": env["label"], "status": env["status"],
           "reason": env.get("reason"), "notice": env.get("notice"), "other_homes": env.get("other_homes") or []}
    if data:
        cov = data.get("coverage") or {}
        row.update(files=cov.get("files", 0), bytes=cov.get("bytes", 0),
                   rotate=len(data.get("rotate", [])),
                   review=sum(n for c, n in (data.get("review_totals") or {}).items() if c != "entropy"))
    return row


def merge(host_data, host_env, results):
    """host_data: this machine's findings.json dict. host_env: its Environment dict (status is implied).
    results: the other environments' result records (envs.scan). Returns the merged findings.json dict."""
    host_side = host_env["side"]
    host_prefix = None
    if host_side.startswith("wsl:"):
        # Inside WSL the host's Linux side is named after its distro once other distros are in the report.
        host_data = copy.deepcopy(host_data)
        for sec in ("rotate", "review"):
            for rec in host_data[sec]:
                rec["sides"] = sorted({host_side if s == "wsl" else s for s in rec["sides"]})
                for loc in rec.get("locations", []):
                    if loc.get("side") == "wsl":
                        loc["side"] = host_side
    parts = [(host_data, host_side, host_prefix)]
    others = []
    for r in results:
        if r.get("findings"):
            parts.append((r["findings"], r["side"], r["name"]))
            others.append((r["findings"].get("coverage"), r["side"], r["name"]))
    out = copy.deepcopy(host_data)
    out.update(merge_findings(parts))
    out["coverage"] = merge_coverage(host_data.get("coverage") or {}, others)
    out["schema"] = 2
    host_row = dict(host_env, status="scanned", reason=None, notice=None,
                    other_homes=(host_data.get("coverage") or {}).get("other_homes", []))
    out["environments"] = [environment_row(host_row, host_data)] + \
        [environment_row(r, r.get("findings")) for r in results]
    s = out["summary"]
    s["rotate"] = len(out["rotate"])
    s["review"] = sum(n for c, n in out["review_totals"].items() if c != "entropy")
    s["entropy_candidates"] = out["review_totals"].get("entropy", 0)
    s["review_shown"] = sum(min(n, CAPS[c]) for c, n in out["review_totals"].items())
    s["dismissed"] = sum(out["dismissed"].values())
    s["environments"] = len(out["environments"])
    s["environments_not_scanned"] = sum(1 for r in results if r["status"] == "not_scanned")
    return out
