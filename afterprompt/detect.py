"""Which AI tools are installed on this machine (X2–X5), from the "detect" block of each catalogue entry.

Read-only and cheap: nothing is executed (a binary on PATH is noted, never run), the Windows registry is only read,
and no elevation is asked for. The point is honesty in the report (X11): a clean result on a machine that runs an
assistant Afterprompt cannot read yet must say so, not stay silent.

detect keys (all optional):
  bins               executable names looked up on PATH and in the usual per-user bin folders
  home               paths relative to a home (either side) whose existence means the tool has been used
  vscode_extensions  extension ids ("publisher.name") looked up in every VS Code-family extensions folder
  mac_bundles        CFBundleIdentifier values of .app bundles in /Applications and ~/Applications
  windows_apps       regexes matched against DisplayName in the Windows uninstall registry
  linux_desktop      .desktop file names (without .desktop) in the usual application folders
"""
import glob
import os
import re
import shutil
import sys

from afterprompt import catalogue
from afterprompt.util import log

USER_BIN = (".local/bin", ".npm-global/bin", ".bun/bin", ".cargo/bin", ".deno/bin", ".volta/bin", "bin",
            ".opencode/bin", "AppData/Roaming/npm", "AppData/Local/Programs")
EXTENSION_DIRS = (".vscode/extensions", ".vscode-insiders/extensions", ".vscode-server/extensions",
                  ".vscode-oss/extensions", ".cursor/extensions", ".windsurf/extensions", ".devin/extensions",
                  ".trae/extensions", ".kiro/extensions", ".antigravity/extensions")
DESKTOP_DIRS = ("/usr/share/applications", "/usr/local/share/applications", "/var/lib/flatpak/exports/share/applications",
                "/var/lib/snapd/desktop/applications", "~/.local/share/applications",
                "~/.local/share/flatpak/exports/share/applications")
UNINSTALL_KEYS = (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                  r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")


def windows_apps():
    """DisplayName of every installed program, from HKLM and HKCU (both registry views). [] off Windows."""
    if sys.platform != "win32":
        return []
    import winreg
    names = []
    for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for path in UNINSTALL_KEYS:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            except OSError:
                continue
            with key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        with winreg.OpenKey(key, winreg.EnumKey(key, i)) as sub:
                            name = winreg.QueryValueEx(sub, "DisplayName")[0]
                    except OSError:
                        continue
                    if isinstance(name, str) and name.strip():
                        names.append(name.strip())
    return names


def mac_bundles(homes):
    """CFBundleIdentifier -> .app path for bundles in /Applications and each home's Applications folder."""
    import plistlib
    out = {}
    roots = ["/Applications"] + [os.path.join(h, "Applications") for h in homes]
    for root in roots:
        for app in sorted(glob.glob(os.path.join(glob.escape(root), "*.app"))):
            try:
                with open(os.path.join(app, "Contents", "Info.plist"), "rb") as fh:
                    bid = plistlib.load(fh).get("CFBundleIdentifier")
            except (OSError, ValueError, plistlib.InvalidFileException):
                continue
            if isinstance(bid, str):
                out.setdefault(bid, app)
    return out


class Probe:
    """Everything detection looks at, gathered once. Tests replace any part of it."""

    def __init__(self, homes, platform, path_env=None, apps=None, bundles=None, desktop_dirs=DESKTOP_DIRS):
        self.homes = [h for h in homes if h]
        self.platform = platform
        self.path_env = os.environ.get("PATH", "") if path_env is None else path_env
        self._apps = apps
        self._bundles = bundles
        self.desktop_dirs = desktop_dirs

    @property
    def apps(self):
        if self._apps is None:
            try:
                self._apps = windows_apps() if self.platform == "windows" else []
            except OSError:
                self._apps = []
        return self._apps

    @property
    def bundles(self):
        if self._bundles is None:
            self._bundles = mac_bundles(self.homes) if self.platform == "macos" else {}
        return self._bundles

    def which(self, name):
        dirs = [d for d in self.path_env.split(os.pathsep) if d]
        dirs += [os.path.join(h, b) for h in self.homes for b in USER_BIN]
        exts = ("", ".exe", ".cmd", ".bat", ".ps1") if self.platform in ("windows", "wsl") else ("",)
        for d in dirs:
            for ext in exts:
                p = os.path.join(d, name + ext)
                if os.path.isfile(p):
                    return p
        return shutil.which(name, path=os.pathsep.join(dirs)) if dirs else None


def evidence(tool, probe):
    """Why we think this tool is installed: a list of short, human-readable reasons. [] when it is not."""
    d = tool.get("detect") or {}
    found = []
    for b in d.get("bins", []):
        p = probe.which(b)
        if p:
            found.append(f"{b} on PATH ({p})")
    for h in probe.homes:
        for rel in d.get("home", []):
            p = os.path.join(h, *rel.split("/"))
            if os.path.exists(p):
                found.append(p)
        for ext in d.get("vscode_extensions", []):
            for ed in EXTENSION_DIRS:
                hits = glob.glob(os.path.join(glob.escape(os.path.join(h, *ed.split("/"))), glob.escape(ext) + "-*"))
                if hits:
                    found.append(f"extension {ext} in ~/{ed}")
                    break
    for bid in d.get("mac_bundles", []):
        if bid in probe.bundles:
            found.append(probe.bundles[bid])
    for rx in d.get("windows_apps", []):
        for name in probe.apps:
            if re.search(rx, name):
                found.append(f"installed program “{name}”")
                break
    for stem in d.get("linux_desktop", []):
        for dd in probe.desktop_dirs:
            p = os.path.join(os.path.expanduser(dd), stem + ".desktop")
            if os.path.isfile(p):
                found.append(p)
                break
    out = []
    for f in found:
        if f not in out:
            out.append(f)
    return out


def machine_probe(homes, platform, env=None):
    """The probe for this run. A home given with AFTERPROMPT_HOME is some other machine (a fixture, a mounted
    disk): only that home is evidence, not this machine's PATH, registry, app bundles or desktop entries."""
    env = os.environ if env is None else env
    if env.get("AFTERPROMPT_HOME"):
        return Probe(homes, platform, path_env="", apps=[], bundles={}, desktop_dirs=())
    return Probe(homes, platform)


def installed(homes, platform, probe=None, tools=None):
    """[{product, vendor, kind, status, note, evidence}] for every catalogue tool that looks installed."""
    probe = probe or machine_probe(homes, platform)
    out = []
    for t in (catalogue.DATA["tools"] if tools is None else tools):
        ev = evidence(t, probe)
        if ev:
            out.append({"product": t["product"], "vendor": t.get("vendor"), "kind": t.get("kind"),
                        "status": t["status"], "note": t.get("note"), "evidence": ev[:3]})
    log("installed: " + ", ".join(f"{i['product']} ({i['status']})" for i in out))
    return out
