"""Platform detection, Windows profile detection under WSL, and path translation."""
import os
import re
import subprocess
import sys
from urllib.parse import unquote

EXCLUDED_PROFILES = {"public", "default", "default user", "all users", "wdagutilityaccount"}


def detect(override=None, sys_platform=None, osrelease_path="/proc/sys/kernel/osrelease", env=None):
    if override:
        if override not in ("macos", "linux", "wsl"):
            raise ValueError(f"unknown platform {override!r}")
        return override
    env = os.environ if env is None else env
    plat = sys_platform or sys.platform
    if plat == "darwin":
        return "macos"
    if env.get("WSL_DISTRO_NAME"):
        return "wsl"
    try:
        with open(osrelease_path, encoding="utf-8", errors="replace") as fh:
            if "microsoft" in fh.read().lower():
                return "wsl"
    except OSError:
        pass
    return "linux"


def automount_root(conf_path="/etc/wsl.conf"):
    """The folder Windows drives are mounted under (default /mnt/)."""
    root = "/mnt/"
    try:
        section = None
        with open(conf_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip().lower()
                elif section == "automount" and "=" in line:
                    k, v = (x.strip() for x in line.split("=", 1))
                    if k.lower() == "root" and v:
                        root = v.strip("\"'")
    except OSError:
        pass
    return root if root.endswith("/") else root + "/"


_DRIVE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def from_windows_path(p, mount=None):
    """C:\\x, C:/x, file:///c%3A/x → <mount>c/x. None for anything else."""
    if not isinstance(p, str):
        return None
    if p.lower().startswith("file:///"):
        p = unquote(p[len("file:///"):])
    m = _DRIVE.match(p)
    if not m:
        return None
    mount = mount if mount is not None else automount_root()
    rest = m.group(2).replace("\\", "/").strip("/")
    return f"{mount}{m.group(1).lower()}" + (f"/{rest}" if rest else "")


def from_uri(uri, mount=None):
    """Cursor workspace URIs: file:///… (unix or Windows) and vscode-remote://wsl+<distro>/path."""
    if not isinstance(uri, str):
        return None
    low = uri.lower()
    if low.startswith("vscode-remote://"):
        rest = uri[len("vscode-remote://"):]
        authority, _, path = rest.partition("/")
        if unquote(authority).lower().startswith("wsl+"):
            return "/" + unquote(path)
        return None
    if low.startswith("file://"):
        win = from_windows_path(uri, mount)
        if win:
            return win
        return unquote(uri[len("file://"):])
    return None


def to_windows_path(p, mount=None):
    mount = mount if mount is not None else automount_root()
    if not p.startswith(mount):
        return None
    rest = p[len(mount):]
    m = re.match(r"^([a-z])(?:/(.*))?$", rest)
    if not m:
        return None
    return m.group(1).upper() + ":\\" + (m.group(2) or "").replace("/", "\\")


def _run_capture(run, cmd, cwd):
    try:
        r = run(cmd, capture_output=True, timeout=10, cwd=cwd if cwd and os.path.isdir(cwd) else None)
    except (OSError, subprocess.SubprocessError):
        return None
    if getattr(r, "returncode", 1) != 0:
        return None
    out = r.stdout.decode("utf-8", "replace") if isinstance(r.stdout, bytes) else (r.stdout or "")
    out = out.replace("\r", "").strip().splitlines()
    return out[-1].strip() if out else None


def detect_windows_home(run=subprocess.run, mount=None, env=None, which=None):
    """(path, source) of the current Windows user's profile as seen from WSL; (None, 'not found') otherwise."""
    import shutil
    env = os.environ if env is None else env
    which = which or shutil.which
    mount = mount if mount is not None else automount_root()
    drive = f"{mount}c"

    def accept(win_path):
        if not win_path or "%" in win_path:
            return None
        p = from_windows_path(win_path, mount)
        return p if p and os.path.isdir(p) else None

    attempts = []
    if which("cmd.exe"):
        attempts.append(("cmd.exe", ["cmd.exe", "/c", "echo %USERPROFILE%"]))
    sys32 = f"{drive}/Windows/System32/cmd.exe"
    if os.path.exists(sys32):
        attempts.append(("cmd.exe (System32)", [sys32, "/c", "echo %USERPROFILE%"]))
    if which("powershell.exe"):
        attempts.append(("powershell.exe", ["powershell.exe", "-NoProfile", "-Command", "$env:USERPROFILE"]))
    for source, cmd in attempts:
        p = accept(_run_capture(run, cmd, drive))
        if p:
            return p, source
    users = f"{drive}/Users"
    user = env.get("USER") or env.get("LOGNAME")
    if user and os.path.isdir(f"{users}/{user}"):
        return f"{users}/{user}", "$USER"
    try:
        profiles = [d for d in os.listdir(users)
                    if d.lower() not in EXCLUDED_PROFILES and os.path.isdir(f"{users}/{d}")]
    except OSError:
        profiles = []
    if len(profiles) == 1:
        return f"{users}/{profiles[0]}", "single profile"
    return None, "not found"


def claude_project_dirname(path):
    """Claude Code stores each project's sessions under ~/.claude/projects/<path with non-alphanumerics as '-'>."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)
