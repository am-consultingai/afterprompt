"""Docker and Podman (M7): containers have their own home folders, images have their own configuration.

A container is an environment like a WSL distribution is: its own filesystem, its own AI tool history, and
a key pasted inside one is invisible from the machine hosting it. A devcontainer is where a lot of AI
coding actually happens, which makes it exactly the place this tool should be looking.

How it reads them, and what it will not do:

  - **Nothing runs inside a container.** No `docker exec`, no shell, no agent. The AI tool folders are
    streamed out with `docker cp <name>:<path> -`, which is a read-only tar over the daemon socket and
    works on a stopped container too. The container is never started, stopped or modified.
  - **Only the paths we already know.** The roots come from the tool catalogue, the same list the scanner
    uses on a real home, so a container is not trawled.
  - **The tar is treated as hostile.** It came out of someone else's filesystem: absolute paths, "..",
    symlinks, hard links and device nodes are refused, and the extraction stops at a byte cap.
  - **Images are listed, not opened.** An image is a filesystem nobody has typed into: it holds no
    conversation history, which is the only thing this tool looks for. A key baked into an image layer
    is a real problem and a different tool's job.
  - **Configuration is not a finding.** A container's environment variables are how a container is
    given its secrets; that they exist is not a leak. Afterprompt reports a credential when it turns up
    in something a person said to an assistant, and a container is interesting only when an assistant
    ran inside it.
"""
import io
import json
import os
import subprocess
import tarfile

from afterprompt import catalogue
from afterprompt.util import log

CLIS = ("docker", "podman")
COPY_CAP = 256 * 1024 * 1024        # per container: enough for any AI history, not enough to fill a disk
FILE_CAP = 64 * 1024 * 1024
TIMEOUT = 60
# Folders under a home that belong to one tool and can be taken whole. Anything else is asked for by its
# exact path, because .config and .cache hold everything else a person has.
WHOLE = {".claude", ".cursor", ".codeium", ".windsurf", ".aider", ".ollama", ".continue", ".goose",
         ".gemini", ".qwen", ".opencode", ".amp", ".junie", ".devin", ".antigravity", ".copilot"}
SHARED_ROOTS = {".config", ".cache", ".local", ".vscode-server", ".vscode-remote", ".aws", "Library"}


def cli(probe, exe):
    return probe.which(exe)


def _run(cmd, run=subprocess.run, timeout=TIMEOUT):
    try:
        p = run(cmd, capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return (p.stdout or b"").decode("utf-8", "replace")


def containers(exe="docker", run=subprocess.run, running_only=False):
    """Every container, or only the running ones. None when the CLI did not answer."""
    cmd = [exe, "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.State}}"]
    if not running_only:
        cmd.insert(2, "-a")
    out = _run(cmd, run)
    if out is None:
        return None
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].strip():
            rows.append({"name": parts[0].strip(), "image": parts[1].strip(), "state": parts[2].strip()})
    return rows


def images(exe="docker", run=subprocess.run):
    out = _run([exe, "images", "--format", "{{.Repository}}:{{.Tag}}"], run)
    if out is None:
        return None
    return [r.strip() for r in out.splitlines() if r.strip() and not r.startswith("<none>")]


def config(ref, exe="docker", run=subprocess.run, kind="container"):
    """A container's or an image's configuration, or None when it cannot be read."""
    cmd = [exe, "inspect", "--format", "{{json .Config}}", ref] if kind == "container" \
        else [exe, "image", "inspect", "--format", "{{json .Config}}", ref]
    out = _run(cmd, run)
    if not out:
        return None
    try:
        data = json.loads(out.strip().splitlines()[0])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def home_of(cfg_json):
    """Where that container's home is. HOME wins; a named user means /home/<user>; root otherwise."""
    env = (cfg_json or {}).get("Env") or []
    for item in env:
        if isinstance(item, str) and item.startswith("HOME="):
            home = item[5:].strip()
            if home.startswith("/"):
                return home.rstrip("/")
    user = ((cfg_json or {}).get("User") or "").split(":")[0].strip()
    if user and user not in ("0", "root"):
        return "/home/" + user
    return "/root"


def ai_paths(platform="linux"):
    """The home-relative paths any AI tool we know of keeps data in, as (root, [paths])."""
    roots = {}
    for rule in catalogue.REGISTRY:
        tool, platforms, side, path = rule[0], rule[1], rule[2], rule[3]
        if platform not in platforms or side not in ("unix", "both"):
            continue
        path = path.replace("$CLAUDE_DIR", ".claude").replace("$XDG_CONFIG_HOME", ".config")
        if path.startswith("$") or path.startswith("/") or path.startswith("~"):
            continue
        head = path.split("/")[0]
        roots.setdefault(head, set()).add(path)
    return {head: sorted(paths) for head, paths in roots.items()}


def safe_members(tar, cap):
    """Refuse everything a tar out of someone else's filesystem can do to this one."""
    total = 0
    for member in tar:
        name = member.name.replace("\\", "/")
        if name.startswith("/") or ".." in name.split("/"):
            continue
        if member.issym() or member.islnk() or member.ischr() or member.isblk() or member.isfifo():
            continue
        if member.isdir():
            yield member, 0
            continue
        if not member.isfile() or member.size > FILE_CAP:
            continue
        total += member.size
        if total > cap:
            return
        yield member, member.size


def copy_path(name, path, dest, exe="docker", popen=subprocess.Popen, cap=COPY_CAP, timeout=TIMEOUT):
    """Stream one path out of a container into dest. Returns the bytes written, or None if it is not there."""
    try:
        p = popen([exe, "cp", f"{name}:{path}", "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return None
    written = 0
    try:
        with tarfile.open(fileobj=p.stdout, mode="r|*") as tar:
            for member, size in safe_members(tar, cap):
                target = os.path.join(dest, member.name)
                if not os.path.abspath(target).startswith(os.path.abspath(dest) + os.sep):
                    continue
                if member.isdir():
                    os.makedirs(target, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                src = tar.extractfile(member)
                if src is None:
                    continue
                with open(target, "wb") as fh:
                    while True:
                        chunk = src.read(1024 * 256)
                        if not chunk:
                            break
                        fh.write(chunk)
                written += size
    except (tarfile.TarError, OSError):
        written = written or None
    finally:
        try:
            p.stdout.close()
        except OSError:
            pass
        try:
            p.wait(timeout=timeout)
        except subprocess.SubprocessError:
            p.kill()
    return written if written else None


def has_path(name, path, exe="docker", popen=subprocess.Popen, timeout=TIMEOUT):
    """Is that path in the container? Asked by starting the copy and stopping at the first entry."""
    try:
        p = popen([exe, "cp", f"{name}:{path}", "-"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return False
    try:
        head = p.stdout.read(512)
        return bool(head)
    except OSError:
        return False
    finally:
        p.kill()
        try:
            p.wait(timeout=timeout)
        except subprocess.SubprocessError:
            pass


def collect(name, dest, exe="docker", run=subprocess.run, popen=subprocess.Popen, cap=COPY_CAP,
            platform="linux"):
    """Copy one container's AI tool folders and its environment into dest, which becomes its home.

    Returns what was found, so the report can say what a container contributed instead of implying it
    was searched exhaustively."""
    os.makedirs(dest, exist_ok=True)
    cfg_json = config(name, exe, run)
    home = home_of(cfg_json)
    paths = ai_paths(platform)
    got, bytes_in = [], 0
    for head, under in sorted(paths.items()):
        if bytes_in >= cap:
            break
        # docker cp names its tar entries after the basename of what was asked for, so a path is
        # extracted into the folder its own parent would be: .config/Cursor/User lands under .config/Cursor.
        if head in WHOLE:
            n = copy_path(name, f"{home}/{head}", dest, exe, popen, cap - bytes_in)
            if n:
                got.append(head)
                bytes_in += n
            continue
        # A shared root holds far more than AI history, so each known path is asked for by name — and
        # only once the root is known to be there, which costs one cheap refusal per container.
        if not has_path(name, f"{home}/{head}", exe, popen):
            continue
        for path in under:
            into = os.path.join(dest, os.path.dirname(path)) if "/" in path else dest
            n = copy_path(name, f"{home}/{path}", into, exe, popen, max(0, cap - bytes_in))
            if n:
                got.append(path)
                bytes_in += n
            if bytes_in >= cap:
                break
    log(f"containers: {name} home={home} copied={len(got)} paths, {bytes_in} bytes")
    return {"name": name, "home": home, "paths": got, "bytes": bytes_in}
