"""What has been done about each exposure, and what the watchdog last saw.

Two different things live side by side here, and keeping them apart is the point:

  - **status** is what you decided — open, rotating, rotated, ignored. Only a person sets it.
  - **presence** is what the machine observed — the value is still in a file on this disk, it is gone,
    or it could not be looked at. Only the watchdog sets it.

Which is why "rotated, still on disk" is a state this can hold and show. Rotating a key at the vendor
does not delete the transcript that leaked it, and pretending one implies the other would be the kind
of false comfort this tool exists to remove.

Keyed by the finding's value hash, so it survives the next scan: the same credential in a new report
carries its history with it. The file holds hashes, never values.
"""
import os
import time

from afterprompt.util import read_json, write_json

OPEN, ROTATING, ROTATED, IGNORED = "open", "rotating", "rotated", "ignored"
STATUSES = (OPEN, ROTATING, ROTATED, IGNORED)
DEFAULT = OPEN
HASH = 16                      # sha256[:16], the same key the report uses


def path(base_dir):
    return os.path.join(base_dir, "status.json")


def valid_hash(h):
    return isinstance(h, str) and len(h) == HASH and all(c in "0123456789abcdef" for c in h)


def load(base_dir):
    """Every exposure's record, with anything unreadable or unrecognised dropped rather than trusted."""
    raw = read_json(path(base_dir), {}) or {}
    out = {}
    if isinstance(raw, dict):
        for key, row in (raw.get("items") or {}).items():
            if not valid_hash(key) or not isinstance(row, dict):
                continue
            status = row.get("status")
            item = {"status": status if status in STATUSES else DEFAULT,
                    "updated": int(row["updated"]) if str(row.get("updated", "")).isdigit() else None}
            seen = row.get("seen")
            if isinstance(seen, dict) and seen.get("state") in ("present", "gone", "unknown"):
                item["seen"] = {"state": seen["state"],
                                "checked": int(seen["checked"]) if str(seen.get("checked", "")).isdigit() else None,
                                "in": [p for p in (seen.get("in") or []) if isinstance(p, str)][:20],
                                "why": seen.get("why") if isinstance(seen.get("why"), str) else None}
            out[key] = item
    return out


def save(base_dir, items):
    write_json(path(base_dir), {"schema": 1, "items": items})


def set_status(base_dir, key, status, now=None):
    """Returns the new record, or None if the caller asked for something that is not a status."""
    if not valid_hash(key) or status not in STATUSES:
        return None
    items = load(base_dir)
    row = items.get(key) or {}
    row["status"] = status
    row["updated"] = int(now or time.time())
    items[key] = row
    save(base_dir, items)
    return row


def record_seen(base_dir, seen, now=None):
    """The watchdog's answer for one or many findings: {hash: {state, in, checked, why}}."""
    items = load(base_dir)
    changed = {}
    for key, row in (seen or {}).items():
        if not valid_hash(key) or not isinstance(row, dict):
            continue
        before = (items.get(key) or {}).get("seen") or {}
        item = items.setdefault(key, {"status": DEFAULT, "updated": None})
        item["seen"] = {"state": row.get("state", "unknown"),
                        "checked": int(row.get("checked") or now or time.time()),
                        "in": list(row.get("in") or [])[:20],
                        "why": row.get("why")}
        if before.get("state") != item["seen"]["state"]:
            changed[key] = item["seen"]["state"]
    save(base_dir, items)
    return changed


def adopt_checklist(base_dir):
    """0.7.0 and earlier kept a tick per finding. A tick meant rotated; carry it over once."""
    old = os.path.join(base_dir, "checklist.json")
    ticks = read_json(old, {}) or {}
    if not isinstance(ticks, dict) or not ticks:
        return 0
    items = load(base_dir)
    moved = 0
    for key, done in ticks.items():
        if valid_hash(key) and done and key not in items:
            items[key] = {"status": ROTATED, "updated": int(os.path.getmtime(old))}
            moved += 1
    if moved:
        save(base_dir, items)
    return moved
