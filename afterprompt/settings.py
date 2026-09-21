"""Saved defaults for the next scan, and the browser view's own preferences (~/.afterprompt/settings.json).

The file is the lowest-priority source of truth: a command-line flag always wins over it, and it only ever holds
choices — never a path to a secret, never a credential. Each field below carries its own type, default, range and
one line of help, so the settings screen is generated from this table rather than hand-built, and a new setting
cannot be added without the sentence that explains it.
"""
import json
import os

from afterprompt.util import read_json, write_json

NAME = "settings.json"


class Field:
    def __init__(self, key, kind, default, label, help_text, choices=None, minimum=None, maximum=None, scope="scan"):
        self.key, self.kind, self.default = key, kind, default
        self.label, self.help, self.choices = label, help_text, choices
        self.minimum, self.maximum, self.scope = minimum, maximum, scope

    def describe(self):
        d = {"key": self.key, "kind": self.kind, "default": self.default, "label": self.label, "help": self.help,
             "scope": self.scope}
        if self.choices:
            d["choices"] = [{"value": v, "label": l} for v, l in self.choices]
        if self.minimum is not None:
            d["min"], d["max"] = self.minimum, self.maximum
        return d

    def clean(self, value):
        """The value to store, or None when it is not acceptable."""
        if self.kind == "bool":
            return bool(value) if isinstance(value, bool) else None
        if self.kind == "choice":
            return value if any(value == v for v, _ in self.choices) else None
        if self.kind == "number":
            try:
                v = float(value)
            except (TypeError, ValueError):
                return None
            if v != v or v < self.minimum or v > self.maximum:      # NaN, or outside the range
                return None
            return int(v) if float(v).is_integer() and self.maximum >= 1 and isinstance(self.default, int) else v
        if self.kind == "number_or_auto":
            if value in (None, "", "auto"):
                return None
            return Field(self.key, "number", 1, "", "", minimum=self.minimum, maximum=self.maximum).clean(value)
        return None


FIELDS = [
    Field("mode", "choice", "quick", "Scan depth",
          "Deep also decodes nested payloads (base64, gzip, JWTs) and runs an entropy sweep. It finds more and "
          "takes much longer.",
          choices=[("quick", "Quick"), ("deep", "Deep")]),
    Field("no_wsl", "bool", False, "Only this machine",
          "By default a Windows run also scans every WSL distribution, from inside it."),
    Field("include_keychain", "bool", False, "Include the macOS Keychain",
          "macOS only: also check Claude Code's Keychain login. Shows a permission prompt when the scan runs."),
    Field("max_disk_gb", "number", 10, "Deep-mode disk cap (GB)",
          "How much decoded plaintext a deep scan may write before it stops decoding. It is deleted as soon as "
          "nothing needs it.", minimum=1, maximum=500),
    Field("workers", "number_or_auto", None, "Parallel workers",
          "Leave on automatic unless a scan is competing with other work: it is chosen from CPU count and memory.",
          minimum=1, maximum=32),
    Field("keep_work", "bool", False, "Keep intermediate files",
          "For debugging a scan. These include decoded plaintext copies of your history, so they are removed by "
          "default."),
    Field("containers", "choice", "running", "Scan containers",
          "Docker and Podman containers have their own home folders, and a devcontainer is where a lot of AI "
          "coding happens. Their AI tool folders are copied out read-only; nothing is run inside them.",
          choices=[("running", "Running only"), ("all", "Running and stopped"), ("none", "Skip them")]),
    Field("sarif", "bool", False, "Also write SARIF",
          "Writes report.sarif next to the report, for code-scanning and SIEM pipelines."),
    Field("ui_theme", "choice", "auto", "Appearance",
          "This page's light or dark theme.", choices=[("auto", "Match system"), ("light", "Light"), ("dark", "Dark")],
          scope="view"),
    Field("group_by", "choice", "vendor", "Group credentials by",
          "How the list is grouped: the service that issued the credential, how far it reaches if someone has "
          "it, the AI tool it leaked into, or the machine it was found on.",
          # "severity" is kept as the stored value: it used to mean how sure the scan was and now means how far
          # the credential reaches, so a settings file written by an older version still selects the right thing.
          choices=[("vendor", "Vendor"), ("severity", "What it opens"), ("tool", "AI tool"),
                   ("machine", "Machine")], scope="view"),
    Field("collapse_groups", "bool", False, "Start with groups collapsed",
          "Useful when a scan finds a lot: open one group at a time.", scope="view"),
    Field("show_review", "bool", True, "Show items to review",
          "Weaker evidence, shown under the credentials to rotate. Turning this off hides them from this page "
          "only; the report still lists them.", scope="view"),
]
BY_KEY = {f.key: f for f in FIELDS}
DEFAULTS = {f.key: f.default for f in FIELDS}


def path(base_dir):
    return os.path.join(base_dir, NAME)


def load(base_dir):
    """Saved settings merged over the defaults. A corrupt or hostile file degrades to the defaults."""
    raw = read_json(path(base_dir), {}) or {}
    out = dict(DEFAULTS)
    if isinstance(raw, dict):
        for k, v in (raw.get("values") or {}).items():
            f = BY_KEY.get(k)
            if f is None:
                continue
            cleaned = f.clean(v)
            if cleaned is not None or (f.kind == "number_or_auto" and v in (None, "auto")):
                out[k] = cleaned
    return out


def save(base_dir, values):
    write_json(path(base_dir), {"schema": 1, "values": {k: v for k, v in values.items() if k in BY_KEY}})
    return values


def set_value(base_dir, key, value):
    """Apply one change, the way the settings screen does. Returns the new settings, or None when refused."""
    f = BY_KEY.get(key)
    if f is None:
        return None
    cleaned = f.clean(value)
    if cleaned is None and not (f.kind == "number_or_auto" and value in (None, "", "auto")):
        return None
    values = load(base_dir)
    values[key] = cleaned
    return save(base_dir, values)


def describe(base_dir):
    return {"fields": [f.describe() for f in FIELDS], "values": load(base_dir), "defaults": dict(DEFAULTS),
            "path": path(base_dir)}


def json_dumps(base_dir):
    return json.dumps(describe(base_dir))
