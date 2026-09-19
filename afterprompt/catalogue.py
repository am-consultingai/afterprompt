"""The tool catalogue (catalogue.json): where each AI tool keeps its data. Adding a tool is a data edit.

Each tool:
  product, vendor, kind (cli | ide | extension | desktop | runner)
  status        scanned (supported and tested) | planned (listed, not scanned)
  locations     [{path, side, platforms?, role?, match?}]
                  path    relative to the side's home; "$CLAUDE_DIR" is Claude Code's config dir
                  side    unix (the macOS/Linux/WSL home) | windows (the Windows profile: this machine's own
                          home on Windows, the profile across /mnt/c from WSL)
                  platforms  default: every platform that has that side
                  role    root (scan as files, the default) | sqlite_glob (SQLite files under path matching the
                          tool's sqlite_globs) | sqlite_dir (every SQLite file under path; other files are roots)
                  match   root only: scan just the files under path matching these globs (rotating logs)
                  sqlite_globs  for this location only, instead of the tool's
                  editors  with an $EDITOR_USER/ path: only these editors (default: all)
                  remote   with an $EDITOR_USER/ path: also each editor's remote-server profile (~/.<server>/data/User)

A path starting with $EDITOR_USER/ is inside a VS Code-family editor's profile ("User" folder), and is expanded to
every editor in the catalogue's "editors" list, on every platform: Library/Application Support/<name>/User on macOS,
.config/<name>/User on Linux and WSL, AppData/Roaming/<name>/User on Windows.
  sqlite_globs      for sqlite_glob locations
  project_files     file names the tool writes into each project folder it works in (Aider's chat history);
                    looked for in every project folder discovery finds
  exclude_tables    SQLite tables never extracted (the tool's own login, embeddings)
  config_files      regexes: the tool's configuration files. A secret there is "stored in configuration"
  credential_files  regexes: the tool's own login store. A secret only there is its intended home, not a leak
  credential_stores JSON login files (relative to each home) read as live values, so the tool's own token is
                    caught when it turns up anywhere else
  vendored          regexes: code the tool ships. A match only there is dismissed
  detect            how to tell the tool is installed (see detect.py); planned tools use it to be named in the
                    report as "installed but not covered"
  note              for planned tools: why they are not scanned yet

Regexes are matched against a path with forward slashes. config_files and credential_files are anchored to a
path boundary and the end of the path.
"""
import json
import os
import re
from collections import namedtuple

PLATFORMS = ("macos", "linux", "wsl", "windows")
SIDES = {"unix": ("macos", "linux", "wsl"), "windows": ("wsl", "windows")}
ROLES = ("root", "sqlite_glob", "sqlite_dir")
KINDS = ("cli", "ide", "extension", "desktop", "runner")
STATUSES = ("scanned", "planned")
DETECT_KEYS = ("bins", "home", "vscode_extensions", "mac_bundles", "windows_apps", "linux_desktop")
PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalogue.json")

Loc = namedtuple("Loc", "tool platforms side path role globs exclude_tables match")


class CatalogueError(ValueError):
    pass


def _regexes(tool, key, errors):
    out = tool.get(key, [])
    if not isinstance(out, list) or not all(isinstance(x, str) for x in out):
        errors.append(f"{tool.get('product')}: {key} must be a list of strings")
        return []
    for x in out:
        try:
            re.compile(x)
        except re.error as err:
            errors.append(f"{tool.get('product')}: {key}: bad regex {x!r}: {err}")
    return out


def validate(data):
    """Every problem in the catalogue, as a list of messages. Empty means valid."""
    errors = []
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("tools"), list):
        return ["catalogue: expected {\"schema\": 1, \"tools\": [...]}"]
    seen = set()
    for t in data["tools"]:
        name = t.get("product") if isinstance(t, dict) else None
        if not name or not isinstance(name, str):
            errors.append(f"tool without a product name: {t!r}"[:200])
            continue
        if name in seen:
            errors.append(f"{name}: listed twice")
        seen.add(name)
        if t.get("kind") not in KINDS:
            errors.append(f"{name}: kind must be one of {', '.join(KINDS)}")
        if t.get("status") not in STATUSES:
            errors.append(f"{name}: status must be one of {', '.join(STATUSES)}")
        for key in ("config_files", "credential_files", "vendored"):
            _regexes(t, key, errors)
        for key in ("sqlite_globs", "exclude_tables", "credential_stores", "project_files"):
            if key in t and (not isinstance(t[key], list) or not all(isinstance(x, str) for x in t[key])):
                errors.append(f"{name}: {key} must be a list of strings")
        det = t.get("detect", {})
        if not isinstance(det, dict) or set(det) - set(DETECT_KEYS):
            errors.append(f"{name}: detect keys are {', '.join(DETECT_KEYS)}")
        else:
            for k, v in det.items():
                if not isinstance(v, list) or not v or not all(isinstance(x, str) and x for x in v):
                    errors.append(f"{name}: detect.{k} must be a non-empty list of strings")
                    continue
                if k == "windows_apps":
                    for x in v:
                        try:
                            re.compile(x)
                        except re.error as err:
                            errors.append(f"{name}: detect.windows_apps: bad regex {x!r}: {err}")
                if k == "home" and any(os.path.isabs(x) or x.startswith("/") or ".." in x.split("/") for x in v):
                    errors.append(f"{name}: detect.home paths are relative to the home")
                if k == "bins" and any(os.sep in x or "/" in x for x in v):
                    errors.append(f"{name}: detect.bins are bare program names")
        if t.get("status") == "planned" and not (t.get("note") and det):
            errors.append(f"{name}: a planned tool needs a note (why it is not scanned) and a detect block")
        locs = t.get("locations")
        if not isinstance(locs, list) or (t.get("status") == "scanned" and not locs):
            errors.append(f"{name}: a scanned tool needs locations")
            continue
        for loc in locs:
            where = f"{name}: {loc.get('path') if isinstance(loc, dict) else loc!r}"
            if not isinstance(loc, dict) or not isinstance(loc.get("path"), str) or not loc["path"]:
                errors.append(f"{where}: location needs a path")
                continue
            p = loc["path"]
            if p.startswith("$") and not p.startswith(("$CLAUDE_DIR", EDITOR_PREFIX)):
                errors.append(f"{where}: unknown placeholder")
            if os.path.isabs(p) or p.startswith(("/", "\\")) or ".." in p.replace("\\", "/").split("/") or "\\" in p:
                errors.append(f"{where}: path must be relative to the home, with forward slashes")
            if loc.get("side") not in SIDES:
                errors.append(f"{where}: side must be unix or windows")
                continue
            plats = loc.get("platforms", list(SIDES[loc["side"]]))
            if not plats or any(pl not in SIDES[loc["side"]] for pl in plats):
                errors.append(f"{where}: platforms must be a subset of {', '.join(SIDES[loc['side']])}")
            role = loc.get("role", "root")
            if role not in ROLES:
                errors.append(f"{where}: role must be one of {', '.join(ROLES)}")
            names = {e.get("name") for e in data.get("editors", []) if isinstance(e, dict)}
            if p.startswith(EDITOR_PREFIX):
                if not names:
                    errors.append(f"{where}: $EDITOR_USER needs the catalogue's editors list")
                if set(loc.get("editors") or []) - names:
                    errors.append(f"{where}: unknown editors {sorted(set(loc['editors']) - names)}")
            elif loc.get("editors") or loc.get("remote"):
                errors.append(f"{where}: editors and remote only apply to $EDITOR_USER paths")
            if role == "sqlite_glob" and not (t.get("sqlite_globs") or loc.get("sqlite_globs")):
                errors.append(f"{where}: sqlite_glob needs the tool's sqlite_globs")
            m = loc.get("match")
            if m is not None and (role != "root" or not isinstance(m, list) or not m
                                  or not all(isinstance(x, str) and x for x in m)):
                errors.append(f"{where}: match is a non-empty list of globs, for root locations only")
    for e in data.get("editors", []):
        if not isinstance(e, dict) or not isinstance(e.get("name"), str) or not e["name"] or \
                ("server" in e and not (isinstance(e["server"], str) and e["server"].startswith("."))):
            errors.append(f"editors: each needs a name, and server (optional) is a dot-folder in the home: {e!r}")
    for x in data.get("vendored", []):
        try:
            re.compile(x)
        except re.error as err:
            errors.append(f"vendored: bad regex {x!r}: {err}")
    return errors


def load(path=PATH):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    errors = validate(data)
    if errors:
        raise CatalogueError("invalid tool catalogue:\n  " + "\n  ".join(errors))
    return data


EDITOR_PREFIX = "$EDITOR_USER/"
EDITOR_ROOTS = (("unix", ("macos",), "Library/Application Support/{name}/User"),
                ("unix", ("linux", "wsl"), ".config/{name}/User"),
                ("windows", ("wsl", "windows"), "AppData/Roaming/{name}/User"))


def expand(loc, editors):
    """The concrete locations for one catalogue location: itself, or one per editor profile when it starts with
    $EDITOR_USER/."""
    if not loc["path"].startswith(EDITOR_PREFIX):
        return [loc]
    rest = loc["path"][len(EDITOR_PREFIX):]
    only = set(loc.get("editors") or [e["name"] for e in editors])
    out = []
    for e in editors:
        if e["name"] not in only:
            continue
        for side, plats, root in EDITOR_ROOTS:
            out.append(dict(loc, path=f"{root.format(name=e['name'])}/{rest}", side=side, platforms=list(plats)))
        if loc.get("remote") and e.get("server"):
            out.append(dict(loc, path=f"{e['server']}/data/User/{rest}", side="unix", platforms=["linux", "wsl"]))
    return out


def registry(data):
    out = []
    for t in data["tools"]:
        if t["status"] != "scanned":
            continue
        for loc in (x for l in t["locations"] for x in expand(l, data.get("editors", []))):
            out.append(Loc(t["product"], tuple(loc.get("platforms", SIDES[loc["side"]])), loc["side"], loc["path"],
                           loc.get("role", "root"), tuple(loc.get("sqlite_globs") or t.get("sqlite_globs", ())),
                           tuple(t.get("exclude_tables", ())), tuple(loc.get("match", ()))))
    return out


def _names(data, key):
    alts = [x for t in data["tools"] if t["status"] == "scanned" for x in t.get(key, [])]
    return re.compile(r"(?:^|/)(?:" + "|".join(alts) + r")$") if alts else re.compile(r"(?!)")


def _vendored(data):
    alts = list(data.get("vendored", [])) + [x for t in data["tools"] if t["status"] == "scanned"
                                             for x in t.get("vendored", [])]
    return re.compile("|".join(alts)) if alts else re.compile(r"(?!)")


DATA = load()
REGISTRY = registry(DATA)
CONFIG_FILES = _names(DATA, "config_files")
CREDENTIAL_FILES = _names(DATA, "credential_files")
VENDORED = _vendored(DATA)


def exclude_tables(tool):
    for t in DATA["tools"]:
        if t["product"] == tool:
            return tuple(t.get("exclude_tables", ()))
    return ()


def credential_stores():
    """[(tool, relative path)] of the JSON login files every scanned tool keeps."""
    return [(t["product"], p) for t in DATA["tools"] if t["status"] == "scanned" for p in t.get("credential_stores", [])]


def project_files():
    """[(tool, file name)] every scanned tool writes into project folders."""
    return [(t["product"], f) for t in DATA["tools"] if t["status"] == "scanned" for f in t.get("project_files", [])]


def scanned_products():
    return [t["product"] for t in DATA["tools"] if t["status"] == "scanned"]
