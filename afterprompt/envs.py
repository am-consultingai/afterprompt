"""Environments (M4) and the workers that scan them (W8).

An environment is one filesystem with its own home and its own AI tools. The machine the scan runs on is always
one, and it is scanned in-process. Every other environment is scanned from inside itself by a worker the host
starts (see worker.py), because reading a WSL home from Windows over \\\\wsl.localhost is ~14x slower than reading
it from within the distro. The user never has to start anything: one run covers every environment it can reach,
and says plainly which ones it could not.
"""
import io
import os
import re
import subprocess
import sys
import tarfile
from dataclasses import asdict, dataclass

from afterprompt import platforms, worker
from afterprompt.util import log, read_json, write_json

# Where the host copies the scanner inside a distro: its own ~/.afterprompt, like a run there would use.
ENGINE_DIR = "$HOME/.afterprompt/engine"
SHIP = ('set -e; D="' + ENGINE_DIR + '"; mkdir -p "$HOME/.afterprompt"; chmod 700 "$HOME/.afterprompt"; '
        'rm -rf "$D.new"; mkdir "$D.new"; tar -xf - -C "$D.new"; rm -rf "$D"; mv "$D.new" "$D"')
RUN = 'exec "' + ENGINE_DIR + '/afterprompt.sh" "$@"'
HOST_LABELS = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "wsl": "WSL"}
# Launcher exits that mean "this environment cannot run the scanner itself": no Python or ripgrep (3), or no
# shell able to run the launcher (126, 127). The host can still read such a distro over the network share.
CANNOT_RUN = (3, 126, 127)
FINAL = ("scanned", "scanned_share", "not_scanned", "skipped")


@dataclass
class Environment:
    name: str
    kind: str       # host | wsl | folder
    label: str
    side: str       # how its findings' "sides" are named once merged
    home: str = ""  # folder environments only

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return cls(**{k: d.get(k, "") for k in ("name", "kind", "label", "side", "home")})

    @property
    def slug(self):
        return re.sub(r"[^A-Za-z0-9._-]", "_", f"{self.kind}-{self.name}")


def host(cfg, env=None):
    env = os.environ if env is None else env
    if cfg.platform == "wsl" and env.get("WSL_DISTRO_NAME"):
        name = env["WSL_DISTRO_NAME"]
        return Environment(name, "host", f"WSL: {name} (this machine)", f"wsl:{name}")
    label = HOST_LABELS.get(cfg.platform, cfg.platform)
    return Environment(label, "host", f"{label} (this machine)", cfg.platform)


def wsl_provider(cfg, env=None, distros=None):
    """Every WSL distro other than the one we are running in. Reached through wsl.exe from Windows, and through
    interop from inside WSL."""
    env = os.environ if env is None else env
    if cfg.platform not in ("windows", "wsl"):
        return []
    # An overridden home or platform describes some other machine (a fixture, a mounted disk): the distros
    # installed here are not its environments.
    if env.get("AFTERPROMPT_HOME") or env.get("AFTERPROMPT_PLATFORM"):
        return []
    names = distros() if distros else platforms.wsl_distros()
    me = env.get("WSL_DISTRO_NAME") if cfg.platform == "wsl" else None
    return [Environment(n, "wsl", f"WSL: {n}", f"wsl:{n}") for n in names if n != me]


def folder_provider(cfg, env=None):
    """Test hook: AFTERPROMPT_TEST_ENVS="Name=/path;Other=/path" scans each folder as a separate Linux home,
    through the same worker protocol a WSL distro uses (and the same one the network-share fallback uses)."""
    env = os.environ if env is None else env
    out = []
    for part in (env.get("AFTERPROMPT_TEST_ENVS") or "").split(";"):
        name, sep, path = part.partition("=")
        if sep and name.strip() and path.strip():
            out.append(Environment(name.strip(), "folder", name.strip(), f"env:{name.strip()}",
                                   os.path.abspath(path.strip())))
    return out


PROVIDERS = [wsl_provider, folder_provider]


def discover(cfg, providers=None):
    """[host, *others]. A worker never discovers: only the host orchestrates."""
    envs = [host(cfg)]
    if getattr(cfg, "worker", False):
        return envs
    seen = set()
    for provider in PROVIDERS if providers is None else providers:
        try:
            found = provider(cfg)
        except Exception as err:  # noqa: BLE001 - a broken provider must not stop the scan of this machine
            log(f"environments: provider {getattr(provider, '__name__', provider)} failed: {err}")
            continue
        for e in found:
            if (e.kind, e.name) not in seen:
                seen.add((e.kind, e.name))
                envs.append(e)
    log("environments: " + ", ".join(e.label for e in envs))
    return envs


def other_homes(home):
    """Other people's home folders beside this one. Listed in coverage, never read: no elevation, ever."""
    if not home:
        return []
    home = home.rstrip("/\\")
    parent = os.path.dirname(home)
    if os.path.basename(parent).lower() not in ("home", "users"):
        return []
    skip = platforms.EXCLUDED_PROFILES | {"shared", "guest", "lost+found"}
    try:
        names = sorted(os.listdir(parent))
    except OSError:
        return []
    mine = os.path.basename(home)
    return [n for n in names if n != mine and not n.startswith(".") and n.lower() not in skip
            and os.path.isdir(os.path.join(parent, n))]


# ------------------------------------------------------------------ scanning one environment
def result_path(state_dir, e):
    return os.path.join(state_dir, e.slug + ".json")


def load_result(state_dir, e):
    r = read_json(result_path(state_dir, e), None)
    return r if isinstance(r, dict) and r.get("status") in FINAL else None


def save_result(state_dir, res):
    os.makedirs(state_dir, exist_ok=True)
    write_json(result_path(state_dir, Environment.from_dict(res)), res)
    return res


def skipped(e, reason):
    return dict(e.to_dict(), status="skipped", reason=reason, notice=None, other_homes=[], findings=None, exit=None)


def scan(e, cfg, worker_args, say, state_dir):
    """Scan one environment and return its result record (also saved in state_dir, so a resumed run skips it)."""
    os.makedirs(state_dir, exist_ok=True)
    if e.kind == "wsl":
        res = _scan_wsl(e, cfg, worker_args, say, state_dir)
    elif e.kind == "folder":
        res = _record(e, run_local(e, e.home, cfg, worker_args, say, state_dir), "scanned")
    else:
        raise ValueError(f"cannot scan a {e.kind} environment with a worker")
    return save_result(state_dir, res)


def _record(e, run, ok_status, notice=None):
    res = dict(e.to_dict(), status=ok_status, reason=None, notice=notice,
               other_homes=(run.get("hello") or {}).get("other_homes", []), findings=None, exit=run.get("exit"))
    if run.get("result") and isinstance(run["result"].get("findings"), dict):
        res["findings"] = run["result"]["findings"]
        res["exit"] = run["result"].get("exit", run.get("exit"))
        return res
    res["status"] = "not_scanned"
    res["reason"] = failure_reason(run)
    return res


def failure_reason(run):
    err = run.get("error") or {}
    if err.get("message"):
        return err["message"]
    code = run.get("exit")
    tail = run.get("stderr_tail") or ""
    if code == 3:
        why = "Python 3.9+ or ripgrep is not available there"
    elif code in (126, 127):
        why = "the scanner could not be started there (no bash?)"
    elif code is None:
        why = "the worker could not be started"
    else:
        why = f"the worker stopped with exit code {code}"
    return why + (f": {tail}" if tail else "")


def _scan_wsl(e, cfg, worker_args, say, state_dir):
    exe = platforms.wsl_exe()
    if not exe:
        return dict(skipped(e, None), status="not_scanned", reason="wsl.exe is no longer available")
    running = platforms.running_distros(exe=exe)
    notice = None
    if running is not None and e.name not in running:
        notice = f"{e.label} was not running; it was started for the scan (WSL stops it again when idle)."
        say(notice)
    shipped = ship(exe, e.name, cfg.install_dir)
    run = {"exit": shipped.get("exit"), "stderr_tail": shipped.get("stderr_tail")}
    if shipped.get("ok"):
        cmd = [exe, "-d", e.name, "-e", "sh", "-c", RUN, "sh"] + worker_args
        run = run_worker(cmd, None, os.path.join(state_dir, e.slug + ".stderr.log"), say)
        if run.get("result"):
            return _record(e, run, "scanned", notice)
    # The distro cannot run the scanner itself. From Windows it can still be read over \\wsl.localhost:
    # slower, but complete, and far better than leaving it out.
    if cfg.platform == "windows" and (not shipped.get("ok") or run.get("exit") in CANNOT_RUN):
        unc = distro_home_unc(exe, e.name)
        if unc and os.path.isdir(unc):
            say(f"{e.label}: {failure_reason(run)}; scanning it over the network share instead (slower).")
            share = run_local(e, unc, cfg, worker_args, say, state_dir)
            res = _record(e, share, "scanned_share", notice)
            if res["status"] == "not_scanned":
                res["reason"] = f"{failure_reason(run)}; the network-share fallback failed too: {res['reason']}"
            return res
    return _record(e, run, "scanned", notice)


def engine_tar(install_dir):
    """The launcher and the package as a tar stream. The code is copied into the distro rather than run from
    /mnt/c, so it works the same from a Windows host and from another distro, and imports from a native disk."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        def add(path, arc, mode):
            info = tar.gettarinfo(path, arc)
            info.mode, info.uid, info.gid, info.uname, info.gname = mode, 0, 0, "", ""
            with open(path, "rb") as fh:
                tar.addfile(info, fh)
        add(os.path.join(install_dir, "afterprompt.sh"), "afterprompt.sh", 0o755)
        pkg = os.path.join(install_dir, "afterprompt")
        for dp, dns, fns in os.walk(pkg):
            dns[:] = sorted(d for d in dns if d != "__pycache__")
            for fn in sorted(fns):
                if fn.endswith((".pyc", ".pyo")):
                    continue
                p = os.path.join(dp, fn)
                rel = os.path.relpath(p, install_dir).replace(os.sep, "/")
                add(p, rel, 0o644)
    return buf.getvalue()


def ship(exe, distro, install_dir, run=subprocess.run):
    try:
        r = run([exe, "-d", distro, "-e", "sh", "-c", SHIP], input=engine_tar(install_dir), capture_output=True,
                timeout=300)
    except (OSError, subprocess.SubprocessError) as err:
        return {"ok": False, "exit": None, "stderr_tail": str(err)}
    tail = _tail(r.stderr)
    if r.returncode != 0:
        log(f"environments: copying the scanner into {distro} failed ({r.returncode}): {tail}")
    return {"ok": r.returncode == 0, "exit": r.returncode, "stderr_tail": tail}


def distro_home_unc(exe, distro, run=subprocess.run):
    r"""The distro's default user's home as Windows sees it: \\wsl.localhost\<distro>\home\<user>."""
    try:
        r = run([exe, "-d", distro, "-e", "sh", "-c", 'printf %s "$HOME"'], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    home = (r.stdout or b"").decode("utf-8", "replace").strip()
    if r.returncode != 0 or not home.startswith("/"):
        return None
    return rf"\\wsl.localhost\{distro}" + home.replace("/", "\\")


def local_env(e, home, cfg, state_dir, base_env=None):
    env = dict(os.environ if base_env is None else base_env)
    # The host's own settings describe the host, not the environment being scanned.
    for k in ("CLAUDE_CONFIG_DIR", "AFTERPROMPT_TEST_ENVS", "AFTERPROMPT_STOP_AFTER", "AFTERPROMPT_WINDOWS_HOME",
              "AFTERPROMPT_HOME", "AFTERPROMPT_PLATFORM", "AFTERPROMPT_DIR"):
        env.pop(k, None)
    pp = env.get("PYTHONPATH")
    env.update({"PYTHONPATH": cfg.install_dir + (os.pathsep + pp if pp else ""), "PYTHONUTF8": "1",
                "AFTERPROMPT_HOME": home, "AFTERPROMPT_PLATFORM": "linux", "AFTERPROMPT_RG": cfg.rg,
                "AFTERPROMPT_DIR": os.path.join(state_dir, e.slug, "base")})
    return env


def run_local(e, home, cfg, worker_args, say, state_dir):
    """A worker on this machine for a home that is only reachable as a folder (the network-share fallback, and
    the test hook). Its own base folder keeps it from touching the host's run."""
    cmd = [sys.executable, "-X", "utf8", "-m", "afterprompt"] + worker_args
    return run_worker(cmd, local_env(e, home, cfg, state_dir), os.path.join(state_dir, e.slug + ".stderr.log"), say)


def run_worker(cmd, env, stderr_path, say):
    """Run a worker to completion. {"hello", "result", "error", "exit", "stderr_tail"}."""
    out = {"hello": None, "result": None, "error": None, "exit": None, "stderr_tail": ""}
    log("environments: worker " + " ".join(cmd[:8]) + (" …" if len(cmd) > 8 else ""))
    try:
        with open(stderr_path, "wb") as err, \
                subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=err, env=env) as p:
            try:
                for raw in p.stdout:
                    msg = worker.decode(raw)
                    if msg is None:
                        text = plain_text(raw).rstrip()
                        if text:
                            say(text)
                    elif msg["type"] == "say":
                        say(str(msg.get("text", "")))
                    elif msg["type"] in ("hello", "result", "error"):
                        out[msg["type"]] = msg
            except BaseException:
                p.kill()
                raise
        out["exit"] = p.returncode
    except OSError as err:
        out["stderr_tail"] = str(err)
        return out
    with open(stderr_path, "rb") as fh:
        out["stderr_tail"] = _tail(fh.read())
    return out


def plain_text(raw):
    """A non-protocol line: UTF-8 when it is, otherwise the console's own code page (a Windows program that is
    not in UTF-8 mode writes that)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        import locale
        return raw.decode(locale.getpreferredencoding(False) or "latin-1", "replace")


def _tail(data, n=3):
    text = (data or b"").decode("utf-8", "replace") if isinstance(data, bytes) else (data or "")
    lines = [l.strip() for l in text.replace("\r", "").replace("\x00", "").splitlines() if l.strip()]
    return " / ".join(lines[-n:])[:500]
