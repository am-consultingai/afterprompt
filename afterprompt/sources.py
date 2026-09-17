"""Where each AI tool keeps its data, per platform and side. Adding a tool means adding registry entries."""
import glob
import os
import time
from collections import namedtuple

from afterprompt import platforms
from afterprompt.util import Walker, is_under, log, read_json, write_json

# side: "unix" (the macOS/Linux/WSL home) or "windows" (the Windows profile, WSL only)
# role: root | cursor_db_glob | cursor_sqlite_dir
Loc = namedtuple("Loc", "tool platforms side path role")

ALL = ("macos", "linux", "wsl")
REGISTRY = [
    Loc("Claude Code", ALL, "unix", "$CLAUDE_DIR", "root"),
    Loc("Claude Code", ALL, "unix", ".claude.json", "root"),
    Loc("Claude Code", ALL, "unix", ".claude.json.backup", "root"),
    Loc("Claude Code", ("linux", "wsl"), "unix", ".cache/claude-cli-nodejs", "root"),
    Loc("Claude Code", ("macos",), "unix", "Library/Caches/claude-cli-nodejs", "root"),
    Loc("Claude Code", ALL, "unix", ".cache/claude", "root"),
    Loc("Claude Code", ALL, "unix", ".local/state/claude", "root"),
    Loc("Claude Code", ALL, "unix", ".local/share/claude", "root"),
    Loc("Claude Code", ("wsl",), "windows", ".claude", "root"),
    Loc("Claude Code", ("wsl",), "windows", ".claude.json", "root"),
    Loc("Claude Code", ("wsl",), "windows", ".claude.json.backup", "root"),
    Loc("Claude Code", ("wsl",), "windows", "AppData/Local/claude-cli-nodejs", "root"),
    Loc("Claude Code", ("wsl",), "windows", ".local/share/claude", "root"),
    Loc("Cursor", ("macos",), "unix", "Library/Application Support/Cursor/User", "cursor_db_glob"),
    Loc("Cursor", ("linux", "wsl"), "unix", ".config/Cursor/User", "cursor_db_glob"),
    Loc("Cursor", ("wsl",), "windows", "AppData/Roaming/Cursor/User", "cursor_db_glob"),
    Loc("Cursor", ALL, "unix", ".cursor/projects", "root"),
    Loc("Cursor", ALL, "unix", ".cursor/plans", "root"),
    Loc("Cursor", ALL, "unix", ".cursor/mcp.json", "root"),
    Loc("Cursor", ALL, "unix", ".cursor/ai-tracking", "cursor_sqlite_dir"),
    Loc("Cursor", ("wsl",), "windows", ".cursor/projects", "root"),
    Loc("Cursor", ("wsl",), "windows", ".cursor/plans", "root"),
    Loc("Cursor", ("wsl",), "windows", ".cursor/mcp.json", "root"),
    Loc("Cursor", ("wsl",), "windows", ".cursor/ai-tracking", "cursor_sqlite_dir"),
]

CURSOR_DB_GLOBS = ("globalStorage/state.vscdb", "globalStorage/state.vscdb.backup",
                   "workspaceStorage/*/state.vscdb", "workspaceStorage/*/state.vscdb.backup")


def claude_dir(home, env=None):
    env = os.environ if env is None else env
    d = env.get("CLAUDE_CONFIG_DIR")
    return os.path.abspath(os.path.expanduser(d)) if d else os.path.join(home, ".claude")


def sides(cfg):
    """[(side name, home path)] — the unix side is named after the platform."""
    out = [(cfg.platform, cfg.home)]
    wh = windows_home(cfg)
    if wh[0]:
        out.append(("windows", wh[0]))
    return out


_WIN_CACHE = {}


def windows_home(cfg):
    key = (cfg.platform, cfg.windows_home_arg)
    if key in _WIN_CACHE:
        return _WIN_CACHE[key]
    if cfg.platform != "wsl":
        res = (None, "not applicable")
    elif cfg.windows_home_arg and cfg.windows_home_arg.lower() == "none":
        res = (None, "disabled")
    elif cfg.windows_home_arg:
        p = os.path.abspath(cfg.windows_home_arg)
        res = (p, "--windows-home") if os.path.isdir(p) else (None, f"--windows-home not found: {p}")
    else:
        res = platforms.detect_windows_home()
    _WIN_CACHE[key] = res
    return res


def _is_sqlite(path):
    try:
        with open(path, "rb") as fh:
            return fh.read(16).startswith(b"SQLite format 3")
    except OSError:
        return False


def discover(cfg):
    t0 = time.monotonic()
    win_path, win_source = windows_home(cfg)
    homes = {"unix": cfg.home, "windows": win_path}
    side_name = {"unix": cfg.platform, "windows": "windows"}
    roots, dbs, missing = [], [], []
    drop = [cfg.install_dir, cfg.base_dir]

    def add_root(path, tool, side, kind=None):
        path = os.path.normpath(path)
        if any(is_under(path, d) for d in drop if d):
            return
        if any(r["path"] == path for r in roots):
            return
        roots.append({"path": path, "tool": tool, "side": side,
                      "kind": kind or ("dir" if os.path.isdir(path) else "file")})

    for loc in REGISTRY:
        if cfg.platform not in loc.platforms:
            continue
        home = homes[loc.side]
        if not home:
            continue
        side = side_name[loc.side]
        path = claude_dir(home) if loc.path == "$CLAUDE_DIR" else os.path.join(home, loc.path)
        if not os.path.exists(path):
            missing.append({"tool": loc.tool, "side": side, "path": path})
            continue
        if loc.role == "root":
            add_root(path, loc.tool, side)
        elif loc.role == "cursor_db_glob":
            found = sorted(p for g in CURSOR_DB_GLOBS for p in glob.glob(os.path.join(glob.escape(path), g)))
            for p in found:
                if os.path.isfile(p):
                    dbs.append({"path": p, "side": side})
        elif loc.role == "cursor_sqlite_dir":
            for dp, _, fns in os.walk(path):
                for fn in sorted(fns):
                    p = os.path.join(dp, fn)
                    if not os.path.isfile(p) or os.path.islink(p):
                        continue
                    if _is_sqlite(p):
                        dbs.append({"path": p, "side": side})
                    elif not fn.endswith(("-wal", "-shm", "-journal")):
                        add_root(p, loc.tool, side, "file")

    projects = project_dirs(cfg, homes)
    for p in projects:
        side = "windows" if win_path and is_under(p, win_path) else cfg.platform
        home = win_path if side == "windows" else cfg.home
        home_claude = claude_dir(home) if side == cfg.platform else os.path.join(home, ".claude")
        pc = os.path.join(p, ".claude")
        if os.path.isdir(pc) and os.path.normpath(pc) != os.path.normpath(home_claude):
            add_root(pc, "Claude Code", side, "dir")
        pm = os.path.join(p, ".mcp.json")
        if os.path.isfile(pm):
            add_root(pm, "Claude Code", side, "file")

    walk_truncated = []
    for side_key in ("unix", "windows"):
        home = homes[side_key]
        if not home:
            continue
        side = side_name[side_key]
        home_claude = os.path.normpath(claude_dir(home) if side_key == "unix" else os.path.join(home, ".claude"))
        w = Walker(home, 4, time.monotonic() + 60, prune_paths=[d for d in drop if d] + [home_claude],
                   skip=_skip_for_project_walk)
        for dp, dns, fns in w:
            if ".claude" in dns:
                pc = os.path.join(dp, ".claude")
                if os.path.normpath(pc) != home_claude:
                    add_root(pc, "Claude Code", side, "dir")
            if ".mcp.json" in fns:
                add_root(os.path.join(dp, ".mcp.json"), "Claude Code", side, "file")
        if w.truncated:
            walk_truncated.append(home)

    for p in cfg.extra_roots:
        side = "windows" if win_path and is_under(p, win_path) else cfg.platform
        add_root(p, "Extra", side)

    self_exclude = []
    unix_claude = claude_dir(cfg.home)
    proj_root = os.path.join(unix_claude, "projects")
    marks = {platforms.claude_project_dirname(os.path.normpath(d)) for d in drop if d}
    if os.path.isdir(proj_root):
        for name in sorted(os.listdir(proj_root)):
            if any(name == m or name.startswith(m + "-") for m in marks):
                self_exclude.append(os.path.join(proj_root, name))

    out = {"platform": cfg.platform, "home": cfg.home, "windows_home": win_path, "windows_home_source": win_source,
           "roots": roots, "cursor_dbs": dbs, "project_dirs": projects, "self_exclude": self_exclude,
           "missing": missing, "walk_truncated": walk_truncated}
    write_json(cfg.w("sources.json"), out)
    log(f"discover: {len(roots)} roots, {len(dbs)} Cursor databases, {len(projects)} project dirs, "
        f"windows home: {win_path or '-'} ({win_source}), {time.monotonic() - t0:.1f}s")
    return out


def _skip_for_project_walk(name):
    from afterprompt.util import skip_dir
    return skip_dir(name) or name in (".cursor",)


def project_dirs(cfg, homes):
    mount = platforms.automount_root() if cfg.platform == "wsl" else None
    found = set()
    for side_key, home in homes.items():
        if not home:
            continue
        cj = read_json(os.path.join(home, ".claude.json"), {}) or {}
        for key in (cj.get("projects") or {}) if isinstance(cj, dict) else ():
            p = platforms.from_windows_path(key, mount) if cfg.platform == "wsl" else None
            p = p or (key if key.startswith("/") else None)
            if p:
                found.add(os.path.normpath(p))
    cursor_users = []
    if cfg.platform == "macos":
        cursor_users.append(os.path.join(cfg.home, "Library/Application Support/Cursor/User"))
    else:
        cursor_users.append(os.path.join(cfg.home, ".config/Cursor/User"))
    if homes.get("windows"):
        cursor_users.append(os.path.join(homes["windows"], "AppData/Roaming/Cursor/User"))
    for cu in cursor_users:
        for wj in glob.glob(os.path.join(glob.escape(cu), "workspaceStorage", "*", "workspace.json")):
            d = read_json(wj, {}) or {}
            for k in ("folder", "workspace"):
                p = platforms.from_uri(d.get(k), mount) if isinstance(d, dict) else None
                if p:
                    if p.endswith(".code-workspace"):
                        p = os.path.dirname(p)
                    found.add(os.path.normpath(p))
    for p in cfg.extra_roots:
        if os.path.isdir(p):
            found.add(os.path.normpath(p))
    return sorted(p for p in found if os.path.isdir(p))
