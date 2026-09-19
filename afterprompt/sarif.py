"""report.sarif (SARIF 2.1.0) for code-scanning and SIEM pipelines: the same findings as findings.json, masked.

One rule per category; "Rotate now" findings are errors, review findings warnings. A finding's value hash is its
stable fingerprint, so a pipeline can track one credential across runs without ever seeing it."""
from urllib.parse import quote

from afterprompt import __version__

RULES = {
    "live_credential": ("A credential set up on this machine appears in AI assistant history.", "error"),
    "pattern": ("A credential in a known format appears in AI assistant history.", "error"),
    "configuration": ("A secret is stored in plain text in an AI tool's configuration.", "warning"),
    "session_cookie": ("A session cookie appears in AI assistant history.", "warning"),
    "entropy": ("A random-looking token near a secret-related word (deep scan).", "note"),
    "prompt": ("A password-like string was typed into an AI assistant.", "warning"),
}


def location(display):
    """A SARIF location for a report display path: ~/… relative to the home, anything else as an absolute URI."""
    path = display.split(" (chat database)")[0]
    if path.startswith("[") and "] " in path:           # another environment: "[Ubuntu] ~/…"
        path = path.split("] ", 1)[1]
    if path.startswith("~/"):
        art = {"uri": quote(path[2:]), "uriBaseId": "HOME"}
    else:
        p = path.replace("\\", "/")
        art = {"uri": "file:///" + quote(p.lstrip("/"), safe="/:")}
    return {"physicalLocation": {"artifactLocation": art}, "message": {"text": display}}


def result(rec, section):
    rule_text, level = RULES[rec["category"]]
    return {
        "ruleId": rec["category"],
        "level": level if section == "review" else "error",
        "kind": "fail",
        "message": {"text": f"{rec['label']} {rec['masked']}: {rec['reason']}"},
        "locations": [location(l["display"]) for l in rec.get("locations", [])][:5] or
                     [{"message": {"text": "no file location"}}],
        "partialFingerprints": {"afterprompt/valueHash/v1": rec["hash"]},
        "properties": {"section": "rotate" if section == "rotate" else "review", "id": rec.get("id"),
                       "tools": rec.get("tools", []), "sides": rec.get("sides", []),
                       "occurrences": rec.get("occurrences"), "revoke": rec.get("revoke")},
    }


def build(data):
    rules = [{"id": k, "name": k, "shortDescription": {"text": v[0]},
              "defaultConfiguration": {"level": v[1]}} for k, v in RULES.items()]
    results = [result(r, "rotate") for r in data.get("rotate", [])] + \
        [result(r, "review") for r in data.get("review", [])]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Afterprompt", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/am-consultingai/afterprompt", "rules": rules}},
            "originalUriBaseIds": {"HOME": {"description": {"text": "The scanned user's home folder"}}},
            "results": results,
            "properties": {"mode": data.get("mode"), "summary": data.get("summary"),
                           "environments": [{"label": e["label"], "status": e["status"]}
                                            for e in data.get("environments") or []]},
        }],
    }
