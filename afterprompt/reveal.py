"""Show a finding's file in this machine's file manager: the browser view's "Open it".

The page never names a path. It names a finding (by value hash) and which of its locations (by index), and the
path is looked up here, in the findings this process wrote. So the most a caller holding the page's key can do is
ask for a folder window on a file the scan already reported.

What runs is fixed per platform and never goes through a shell:
  - Windows, and WSL for either side:  explorer.exe /select,<path>   (selects the file; never opens it)
  - macOS:                             open -R <path>               (reveals in Finder; never opens it)
  - Linux:                             xdg-open <folder>            (the folder, never the file: xdg-open on a file
                                                                     launches whatever handles it)
A location in another environment (another WSL distribution, a container) is not reachable from here, and a
location found only inside a decoded payload is not a file you could open; both are refused with the reason.
"""
import os
import shutil
import subprocess

from afterprompt import platforms, watch

# Labels triage appends to a display path to say what kind of file it is. Not part of the path.
LABELS = (" (chat database)",)


def strip_label(display):
    for label in LABELS:
        if display.endswith(label):
            return display[:-len(label)]
    return display


def local_sides(findings):
    """The location sides this process can reach: its own environment, and Windows when it runs in WSL."""
    sides = {e.get("side") for e in findings.get("environments") or [] if e.get("kind") == "host" and e.get("side")}
    kind = (findings.get("platform") or {}).get("kind")
    if kind:
        sides.add(kind)
    if kind == "wsl":
        sides.add("windows")
    return sides


def find(findings, value_hash):
    for section in ("rotate", "review"):
        for f in findings.get(section) or []:
            if f.get("hash") == value_hash:
                return f
    return None


def local_path(display, side, plat, home):
    """The display path as this process sees it, or None when it is not a path at all."""
    path = strip_label(display or "")
    if platforms.from_windows_path(path, native=True) and side == "windows":
        return path if plat == "windows" else platforms.from_windows_path(path)
    return watch.resolve(path, home)


def reachable(findings, loc, plat=None, home=None):
    """(local path, None) when this location can be shown here, else (None, why not)."""
    plat = plat or platforms.detect()
    home = home or os.path.expanduser("~")
    if loc.get("decoded"):
        return None, "found only inside a decoded payload, so there is no file to show"
    side = loc.get("side") or ""
    if not side:
        return None, "this location is a conversation, not a file"
    if side not in local_sides(findings):
        return None, "that file is in another environment, not reachable from here"
    path = local_path(loc.get("display"), side, plat, home)
    if not path:
        return None, "that location is not a file path"
    return path, None


def openable(findings, plat=None, home=None):
    """{hash: [location indexes the page may offer to open]}, so the page shows the button only where it works."""
    out = {}
    for section in ("rotate", "review"):
        for f in findings.get(section) or []:
            idx = [i for i, loc in enumerate(f.get("locations") or [])
                   if reachable(findings, loc, plat, home)[0]]
            if idx and f.get("hash"):
                out[f["hash"]] = idx
    return out


def command(path, plat, which=None, env=None, mount=None):
    """The argv that shows path in the file manager, or None when there is none."""
    env = os.environ if env is None else env
    which = which or shutil.which
    if plat == "windows":
        return ["explorer.exe", "/select," + path]
    if plat == "wsl":
        win = platforms.to_windows_path(path)
        if not win:
            distro = env.get("WSL_DISTRO_NAME")
            if not distro:
                return None
            win = "\\\\wsl.localhost\\" + distro + path.replace("/", "\\")
        # Found by path when it is not on PATH: appendWindowsPath=false in wsl.conf is common and still leaves
        # Windows binaries runnable.
        exe = which("explorer.exe") or next((p for p in [os.path.join(mount or platforms.automount_root(), "c",
                                                                       "Windows", "explorer.exe")]
                                             if os.path.isfile(p)), None)
        return [exe, "/select," + win] if exe else None
    if plat == "macos":
        return ["open", "-R", path]
    exe = which("xdg-open")
    return [exe, os.path.dirname(path)] if exe else None


def reveal(findings, value_hash, index, plat=None, home=None, run=None, which=None, env=None):
    """Show one location of one finding. (True, None) once the file manager was asked, else (False, why not)."""
    plat = plat or platforms.detect()
    f = find(findings or {}, value_hash)
    locs = (f or {}).get("locations") or []
    if not f or not isinstance(index, int) or isinstance(index, bool) or not 0 <= index < len(locs):
        return False, "no such location"
    path, why = reachable(findings, locs[index], plat, home)
    if not path:
        return False, why
    if not os.path.isfile(path):
        return False, "that file is no longer there"
    argv = command(path, plat, which, env)
    if not argv:
        return False, "no file manager found on this machine"
    run = run or subprocess.Popen
    try:
        # Detached, output discarded: explorer.exe exits 1 even when it worked, so its status says nothing.
        run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=(plat != "windows"))
    except OSError as e:
        return False, f"could not start the file manager ({e.strerror or e})"
    return True, None
