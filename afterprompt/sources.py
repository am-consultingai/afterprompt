"""Where each AI tool keeps its data, per platform and side. Adding a tool means adding registry entries."""
import glob
import os
import time

from afterprompt import catalogue, detect, platforms
from afterprompt.util import Walker, is_under, log, read_json, write_json

# Where each tool keeps its data lives in catalogue.json; see catalogue.py for the fields.
Loc = catalogue.Loc
REGISTRY = catalogue.REGISTRY


def claude_dir(home, env=None):
    env = os.environ if env is None else env
    d = env.get("CLAUDE_CONFIG_DIR")
    return os.path.abspath(os.path.expanduser(d)) if d else os.path.join(home, ".claude")


def native_side(cfg):
    """Which side is the machine we are running on: its own home, not one reached across a bridge."""
    return "windows" if cfg.platform == "windows" else "unix"


def home_claude(cfg, side_key, home):
    """The Claude config dir for that home. CLAUDE_CONFIG_DIR only applies to the machine we run on."""
    return claude_dir(home) if side_key == native_side(cfg) else os.path.join(home, ".claude")


def sides(cfg):
    """[(side name, home path)] — the unix side is named after the platform."""
    out = [(cfg.platform, cfg.home)]
    wh = windows_home(cfg)
    if wh[0]:
        out.append(("windows", wh[0]))
    return out


_WIN_CACHE = {}


# Said the same way wherever it shows: the Start screen's box, --windows-home none, the report.
LEFT_OUT = "left out of this scan"


def scanned_homes(cfg, sources):
    """(side, home) for every home folder this scan reads: this machine's own unless it was left out, and the
    Windows profile when there is one and it was not. Every stage that reads a home asks here."""
    homes = [] if sources.get("host_left_out") else [(sources["platform"], cfg.home)]
    if sources.get("windows_home"):
        homes.append(("windows", sources["windows_home"]))
    return homes


def windows_home(cfg):
    key = (cfg.platform, cfg.windows_home_arg)
    if key in _WIN_CACHE:
        return _WIN_CACHE[key]
    if cfg.platform == "windows":
        res = (cfg.home, "this machine")
    elif cfg.platform != "wsl":
        res = (None, "not applicable")
    elif cfg.windows_home_arg and cfg.windows_home_arg.lower() == "none":
        res = (None, LEFT_OUT)
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
    # On Windows the machine's own home is the "windows" side; there is no unix side to scan.
    homes = {"unix": None if cfg.platform == "windows" else cfg.home, "windows": win_path}
    if cfg.skip_host:
        # Left out on the Start screen. Nothing on this machine's own filesystem is read — not its AI history, not
        # its credential files, not project folders on it — exactly as for any other environment left out.
        if cfg.platform == "windows":
            homes["windows"] = win_path = None
        else:
            homes["unix"] = None
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
        if loc.path == "$CLAUDE_DIR" or (loc.path == ".claude" and loc.side == native_side(cfg)):
            path = claude_dir(home)
        else:
            path = os.path.join(home, loc.path)
        if not os.path.exists(path):
            missing.append({"tool": loc.tool, "side": side, "path": path})
            continue
        if loc.role == "root" and loc.match:
            for p in sorted({p for g in loc.match for p in glob.glob(os.path.join(glob.escape(path), g))}):
                if os.path.isfile(p):
                    add_root(p, loc.tool, side, "file")
        elif loc.role == "root":
            add_root(path, loc.tool, side)
        elif loc.role == "sqlite_glob":
            found = sorted(p for g in loc.globs for p in glob.glob(os.path.join(glob.escape(path), g)))
            for p in found:
                if os.path.isfile(p):
                    dbs.append({"path": p, "side": side, "tool": loc.tool})
        elif loc.role == "sqlite_dir":
            for dp, _, fns in os.walk(path):
                for fn in sorted(fns):
                    p = os.path.join(dp, fn)
                    if not os.path.isfile(p) or os.path.islink(p):
                        continue
                    if _is_sqlite(p):
                        dbs.append({"path": p, "side": side, "tool": loc.tool})
                    elif not fn.endswith(("-wal", "-shm", "-journal")):
                        add_root(p, loc.tool, side, "file")

    projects = project_dirs(cfg, homes)
    if cfg.skip_host:
        # A project on a Windows drive belongs to the Windows side, which may still be in; one on this machine's own
        # filesystem does not.
        mount = platforms.automount_root() if cfg.platform == "wsl" else None
        projects = [p for p in projects if mount and is_under(p, mount)]
    for p in projects:
        side = "windows" if win_path and is_under(p, win_path) else cfg.platform
        home = win_path if side == "windows" else cfg.home
        hc = home_claude(cfg, "windows" if side == "windows" else "unix", home)
        pc = os.path.join(p, ".claude")
        if os.path.isdir(pc) and os.path.normpath(pc) != os.path.normpath(hc):
            add_root(pc, "Claude Code", side, "dir")
        pm = os.path.join(p, ".mcp.json")
        if os.path.isfile(pm):
            add_root(pm, "Claude Code", side, "file")
        for tool, fn in catalogue.project_files():
            pf = os.path.join(p, fn)
            if os.path.isfile(pf):
                add_root(pf, tool, side, "file")

    walk_truncated = []
    for side_key in ("unix", "windows"):
        home = homes[side_key]
        if not home:
            continue
        side = side_name[side_key]
        hc = os.path.normpath(home_claude(cfg, side_key, home))
        w = Walker(home, 4, time.monotonic() + 60, prune_paths=[d for d in drop if d] + [hc],
                   skip=_skip_for_project_walk)
        for dp, dns, fns in w:
            if ".claude" in dns:
                pc = os.path.join(dp, ".claude")
                if os.path.normpath(pc) != hc:
                    add_root(pc, "Claude Code", side, "dir")
            if ".mcp.json" in fns:
                add_root(os.path.join(dp, ".mcp.json"), "Claude Code", side, "file")
        if w.truncated:
            walk_truncated.append(home)

    for p in cfg.extra_roots:
        side = "windows" if win_path and is_under(p, win_path) else cfg.platform
        add_root(p, "Extra", side)

    self_exclude = []
    proj_root = os.path.join(claude_dir(cfg.home), "projects")
    marks = {platforms.claude_project_dirname(os.path.normpath(d)) for d in drop if d}
    if os.path.isdir(proj_root):
        for name in sorted(os.listdir(proj_root)):
            if any(name == m or name.startswith(m + "-") for m in marks):
                self_exclude.append(os.path.join(proj_root, name))

    installed = detect.installed([homes["unix"], homes["windows"]], cfg.platform)
    unknown = detect.unknown_tools([homes["unix"], homes["windows"]])
    out = {"platform": cfg.platform, "home": cfg.home, "host_left_out": bool(cfg.skip_host),
           "windows_home": win_path, "windows_home_source": win_source,
           "installed": installed, "unknown_tools": unknown, "roots": roots, "databases": dbs, "project_dirs": projects, "self_exclude": self_exclude,
           "missing": missing, "walk_truncated": walk_truncated}
    write_json(cfg.w("sources.json"), out)
    log(f"discover: {len(roots)} roots, {len(dbs)} databases, {len(projects)} project dirs, "
        f"windows home: {win_path or '-'} ({win_source}), "
        f"{time.monotonic() - t0:.1f}s")
    return out


def _skip_for_project_walk(name):
    from afterprompt.util import skip_dir
    return skip_dir(name) or name in (".cursor",)


def project_dirs(cfg, homes):
    mount = platforms.automount_root() if cfg.platform == "wsl" else None
    native = cfg.platform == "windows"
    found = set()
    for side_key, home in homes.items():
        if not home:
            continue
        cj = read_json(os.path.join(home, ".claude.json"), {}) or {}
        for key in (cj.get("projects") or {}) if isinstance(cj, dict) else ():
            if cfg.platform in ("wsl", "windows"):
                p = platforms.from_windows_path(key, mount, native)
            else:
                p = None
            p = p or (key if key.startswith("/") else None)
            if p:
                found.add(os.path.normpath(p))
    cursor_users = []
    if cfg.platform == "macos" and homes.get("unix"):
        cursor_users.append(os.path.join(homes["unix"], "Library/Application Support/Cursor/User"))
    elif not native and homes.get("unix"):
        cursor_users.append(os.path.join(homes["unix"], ".config/Cursor/User"))
    if homes.get("windows"):
        cursor_users.append(os.path.join(homes["windows"], "AppData/Roaming/Cursor/User"))
    for cu in cursor_users:
        for wj in glob.glob(os.path.join(glob.escape(cu), "workspaceStorage", "*", "workspace.json")):
            d = read_json(wj, {}) or {}
            for k in ("folder", "workspace"):
                p = platforms.from_uri(d.get(k), mount, native) if isinstance(d, dict) else None
                if p:
                    if p.endswith(".code-workspace"):
                        p = os.path.dirname(p)
                    found.add(os.path.normpath(p))
    for p in cfg.extra_roots:
        if os.path.isdir(p):
            found.add(os.path.normpath(p))
    return sorted(p for p in found if os.path.isdir(p))
