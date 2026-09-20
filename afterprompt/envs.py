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
import threading
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


def container_provider(cfg, env=None, listing=None):
    """Each container as an environment. Its home is copied out at scan time, not now: listing is cheap,
    copying is not, and a container that turns out to hold no AI tool data should cost nothing."""
    env = os.environ if env is None else env
    # A fixture home describes another machine, so this machine's containers are not its environments.
    # AFTERPROMPT_TEST_CONTAINERS is the hook that lets a test scan a real container anyway.
    if (env.get("AFTERPROMPT_HOME") or env.get("AFTERPROMPT_PLATFORM")) \
            and not env.get("AFTERPROMPT_TEST_CONTAINERS"):
        return []
    want = getattr(cfg, "containers", "running")
    only = env.get("AFTERPROMPT_TEST_CONTAINERS", "")
    if want == "none":
        return []
    from afterprompt import containers as dock
    from afterprompt.detect import Probe
    probe = Probe([cfg.home], cfg.platform)
    out = []
    for exe in dock.CLIS:
        if not probe.which(exe):
            continue
        rows = listing(exe) if listing else dock.containers(exe, running_only=(want == "running"))
        for row in rows or []:
            name = row["name"]
            if only not in ("", "1") and name != only:
                continue
            out.append(Environment(name, "docker", f"{exe.title()}: {name}", f"docker:{name}"))
    return out


PROVIDERS = [wsl_provider, folder_provider, container_provider]


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
    """Saved so a resumed run skips this environment. Never with its live values: those stay in memory."""
    os.makedirs(state_dir, exist_ok=True)
    write_json(result_path(state_dir, Environment.from_dict(res)), {k: v for k, v in res.items() if k != "values"})
    return res


def skipped(e, reason):
    return dict(e.to_dict(), status="skipped", reason=reason, notice=None, other_homes=[], findings=None, exit=None)


def scan(e, cfg, worker_args, say, state_dir, stdin=None):
    """Scan one environment and return its result record (also saved in state_dir, so a resumed run skips it).
    stdin: bytes for the worker's stdin (the host's live values, M5); the record's "values" holds the worker's
    own, in memory only."""
    os.makedirs(state_dir, exist_ok=True)
    if e.kind == "docker":
        res = _scan_container(e, cfg, worker_args, say, state_dir, stdin)
    elif e.kind == "wsl":
        res = _scan_wsl(e, cfg, worker_args, say, state_dir, stdin)
    elif e.kind == "folder":
        res = _record(e, run_local(e, e.home, cfg, worker_args, say, state_dir, stdin), "scanned")
    else:
        raise ValueError(f"cannot scan a {e.kind} environment with a worker")
    return save_result(state_dir, res)


def _scan_container(e, cfg, worker_args, say, state_dir, stdin):
    """Copy the container's AI tool folders out, scan the copy, then delete it.

    Nothing is executed inside the container and the container is not modified; see containers.py."""
    import shutil
    from afterprompt import containers as dock
    work = os.path.join(state_dir, e.slug + ".home")
    shutil.rmtree(work, ignore_errors=True)
    try:
        got = dock.collect(e.name, work, exe="docker" if e.label.startswith("Docker") else "podman")
    except Exception as err:                          # noqa: BLE001 - one bad container is not a failed scan
        shutil.rmtree(work, ignore_errors=True)
        return dict(e.to_dict(), status="not_scanned", reason=f"could not read it: {err}", notice=None,
                    other_homes=[], findings=None, exit=None)
    if not got["paths"]:
        # The common case by far: a container that runs a database, not an assistant.
        shutil.rmtree(work, ignore_errors=True)
        return dict(e.to_dict(), status="skipped", reason="no AI tool history in it",
                    notice=None, other_homes=[], findings=None, exit=None)
    try:
        res = _record(e, run_local(e, work, cfg, worker_args, say, state_dir, stdin), "scanned",
                      notice=f"{len(got['paths'])} AI tool paths copied out")
    finally:
        # The copy holds someone's history in plain text: it does not outlive the scan of it.
        if not cfg.keep_work:
            shutil.rmtree(work, ignore_errors=True)
    return res


def _record(e, run, ok_status, notice=None):
    res = dict(e.to_dict(), status=ok_status, reason=None, notice=notice,
               other_homes=(run.get("hello") or {}).get("other_homes", []), findings=None, exit=run.get("exit"))
    if run.get("result") and isinstance(run["result"].get("findings"), dict):
        res["findings"] = run["result"]["findings"]
        res["exit"] = run["result"].get("exit", run.get("exit"))
        res["values"] = run["result"].get("values") or []
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


def _scan_wsl(e, cfg, worker_args, say, state_dir, stdin=None):
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
        run = run_worker(cmd, None, os.path.join(state_dir, e.slug + ".stderr.log"), say, stdin)
        if run.get("result"):
            return _record(e, run, "scanned", notice)
    # The distro cannot run the scanner itself. From Windows it can still be read over \\wsl.localhost:
    # slower, but complete, and far better than leaving it out.
    if cfg.platform == "windows" and (not shipped.get("ok") or run.get("exit") in CANNOT_RUN):
        unc = distro_home_unc(exe, e.name)
        if unc and os.path.isdir(unc):
            say(f"{e.label}: {failure_reason(run)}; scanning it over the network share instead (slower).")
            share = run_local(e, unc, cfg, worker_args, say, state_dir, stdin)
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
            # A worker returns values over a pipe: it writes no report and serves no page, so the browser
            # view's assets and the logo pack are several hundred kilobytes it would never open.
            if os.path.basename(dp) in ("ui", "logo") and os.path.basename(os.path.dirname(dp)) == "assets":
                dns[:] = []
                continue
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


def run_local(e, home, cfg, worker_args, say, state_dir, stdin=None):
    """A worker on this machine for a home that is only reachable as a folder (the network-share fallback, and
    the test hook). Its own base folder keeps it from touching the host's run."""
    cmd = [sys.executable, "-X", "utf8", "-m", "afterprompt"] + worker_args
    return run_worker(cmd, local_env(e, home, cfg, state_dir), os.path.join(state_dir, e.slug + ".stderr.log"), say,
                      stdin)


def fetch_values(e, cfg, state_dir, share=False):
    """One environment's live values, collected again (a resumed run never reads them from disk)."""
    args = ["--worker", "--values-only", "--windows-home", "none"]
    quiet = lambda m: None  # noqa: E731
    if e.kind == "wsl" and not share:
        exe = platforms.wsl_exe()
        run = run_worker([exe, "-d", e.name, "-e", "sh", "-c", RUN, "sh"] + args, None,
                         os.path.join(state_dir, e.slug + ".values.log"), quiet) if exe else {}
    else:
        home = e.home or (distro_home_unc(platforms.wsl_exe(), e.name) if e.kind == "wsl" else None)
        run = run_local(e, home, cfg, args, quiet, state_dir) if home else {}
    return ((run or {}).get("result") or {}).get("values") or []


def run_worker(cmd, env, stderr_path, say, stdin=None):
    """Run a worker to completion. {"hello", "result", "error", "exit", "stderr_tail"}. stdin, when given, is
    written to the worker's stdin and closed (the host's live values: a pipe, never argv or a file)."""
    out = {"hello": None, "result": None, "error": None, "exit": None, "stderr_tail": ""}
    log("environments: worker " + " ".join(cmd[:8]) + (" …" if len(cmd) > 8 else ""))
    try:
        with open(stderr_path, "wb") as err, \
                subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=err, env=env) as p:
            if stdin is not None:
                def feed():
                    try:
                        p.stdin.write(stdin)
                    except (OSError, ValueError):
                        pass
                    finally:
                        try:
                            p.stdin.close()
                        except OSError:
                            pass
                threading.Thread(target=feed, daemon=True).start()
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


# ---- what else is on this machine that has its own home folder (M6)
CATALOGUE = None


def catalogue():
    """environments.json: every kind of environment we look for, whether or not this machine has any."""
    global CATALOGUE
    if CATALOGUE is None:
        here = os.path.dirname(os.path.abspath(__file__))
        CATALOGUE = read_json(os.path.join(here, "environments.json"), {"kinds": []}) or {"kinds": []}
    return CATALOGUE


def _lines(cmd, run=subprocess.run, timeout=10):
    """A CLI that lists things, or None when the CLI is not here or does not answer."""
    try:
        p = run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    out = (p.stdout or b"").decode("utf-8", "replace")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]


def _probe(cfg):
    from afterprompt.detect import Probe
    return Probe([cfg.home], cfg.platform)


def containers(cfg, exe="docker", run=subprocess.run):
    """Containers on this machine, running or not. [] when the CLI is there but has none; None when it is not."""
    if not _probe(cfg).which(exe):
        return None
    rows = _lines([exe, "ps", "-a", "--format", "{{.Names}}\t{{.Image}}\t{{.State}}"], run)
    if rows is None:
        return None
    out = []
    for row in rows:
        parts = row.split("\t")
        if len(parts) >= 3:
            out.append({"name": parts[0], "image": parts[1], "state": parts[2]})
    return out


def images(cfg, exe="docker", run=subprocess.run):
    if not _probe(cfg).which(exe):
        return None
    rows = _lines([exe, "images", "--format", "{{.Repository}}:{{.Tag}}"], run)
    return None if rows is None else [r for r in rows if r and not r.startswith("<none>")]


def devcontainers(home):
    """A .devcontainer/devcontainer.json says a container exists, even when it is not running now."""
    if not home:
        return []
    found = []
    for base in (home, os.path.join(home, "projects"), os.path.join(home, "src"),
                 os.path.join(home, "code"), os.path.join(home, "work"), os.path.join(home, "repos")):
        try:
            names = sorted(os.listdir(base))[:400]
        except OSError:
            continue
        for name in names:
            cfg = os.path.join(base, name, ".devcontainer", "devcontainer.json")
            if os.path.exists(cfg):
                found.append(os.path.join(base, name))
    return found[:40]


def survey(cfg, envs_found=None, run=subprocess.run, env=None):
    """One row per kind in environments.json: what was looked for, what was found, what was done about it.

    The point is that the answer to "what about Docker?" is in the report whether or not this machine has
    Docker, instead of being a silence someone has to interpret."""
    env = os.environ if env is None else env
    envs_found = envs_found or []
    # An overridden home or platform means this run describes some other machine (a fixture, a mounted
    # disk). What is installed here says nothing about it, so those kinds are not probed at all.
    describing_elsewhere = bool(env.get("AFTERPROMPT_HOME") or env.get("AFTERPROMPT_PLATFORM"))
    scanned = {e.kind for e in envs_found if getattr(e, "kind", None)}
    counts = {}
    for e in envs_found:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    rows = []
    for kind in catalogue().get("kinds", []):
        row = {"id": kind["id"], "label": kind["label"], "note": kind.get("note"), "why": kind.get("why"),
               "found": 0, "status": "absent"}
        if cfg.platform not in kind.get("platforms", []):
            row["status"] = "not_applicable"
            rows.append(row)
            continue
        kid = kind["id"]
        if describing_elsewhere and not env.get("AFTERPROMPT_TEST_CONTAINERS") \
                and kid in ("docker", "podman", "docker_image", "lima", "multipass"):
            row.update(status="not_checked", why="this scan describes another machine")
            rows.append(row)
            continue
        if kid == "host":
            row.update(found=1, status="scanned")
        elif kid == "wsl":
            row.update(found=counts.get("wsl", 0), status="scanned" if counts.get("wsl") else "absent")
            if cfg.no_wsl:
                row.update(status="skipped", why="turned off for this scan")
        elif kid == "folder":
            row.update(found=counts.get("folder", 0), status="scanned" if counts.get("folder") else "absent")
        elif kid in ("docker", "podman"):
            found = containers(cfg, "docker" if kid == "docker" else "podman", run)
            if found is None:
                row.update(status="not_installed")
            else:
                running = [c for c in found if c["state"] == "running"]
                want = getattr(cfg, "containers", "running")
                covered = found if want == "all" else running
                row.update(found=len(found), running=len(running), names=[c["name"] for c in found[:12]])
                if want == "none":
                    row.update(status="skipped", why="turned off for this scan")
                elif covered:
                    row.update(status="scanned", covered=len(covered),
                               why=None if want == "all" else "running containers; --containers all "
                                                              "includes stopped ones")
                else:
                    row.update(status="absent" if not found else "found_not_scanned",
                               why="none of them are running" if found else None)
        elif kid == "docker_image":
            # Listed, never opened: an image holds no conversation, which is the only thing we look for.
            found = images(cfg, "docker", run)
            row.update(found=0 if found is None else len(found),
                       status="not_installed" if found is None else ("out_of_scope" if found else "absent"))
        elif kid == "devcontainer":
            found = devcontainers(cfg.home)
            row.update(found=len(found), status="found_not_scanned" if found else "absent",
                       names=[os.path.basename(p) for p in found[:12]])
        elif kid == "codespace":
            here = bool(env.get("CODESPACES") or env.get("CODESPACE_NAME"))
            row.update(found=1 if here else 0, status="scanned" if here else "absent")
        elif kid in ("lima", "multipass"):
            exe = "limactl" if kid == "lima" else "multipass"
            rows_out = _lines([exe, "list"], run) if _probe(cfg).which(exe) else None
            if rows_out is None:
                row.update(status="not_installed")
            else:
                n = max(0, len(rows_out) - 1)              # the first line is a header
                row.update(found=n, status="found_not_scanned" if n else "absent")
        elif kid == "other_home":
            others = other_homes(cfg.home)
            row.update(found=len(others), status="found_not_scanned" if others else "absent",
                       names=others[:12])
        rows.append(row)
    log("environments looked for: " + ", ".join(f"{r['label']}={r['status']}" for r in rows))
    return rows
