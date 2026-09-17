"""Shared helpers: logging, hashing, masking, scrubbing, entropy, JSON I/O, walking, display paths."""
import collections
import hashlib
import json
import math
import os
import re
import sys
import time

_LOG = {"path": None, "quiet": False}


def set_log(path, quiet=False):
    _LOG["path"] = path
    _LOG["quiet"] = quiet


def log(msg, console=False):
    """Append a timestamped line to run.log; also print it when console is true."""
    line = time.strftime("%H:%M:%S ") + msg
    if _LOG["path"]:
        try:
            with open(_LOG["path"], "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass
    if console and not _LOG["quiet"]:
        print(msg, flush=True)


def say(msg=""):
    """Print to the console and record in run.log without a timestamp on the console."""
    log(msg, console=True)


def sha16(b):
    if isinstance(b, str):
        b = b.encode("utf-8")
    return hashlib.sha256(b).hexdigest()[:16]


def mask(b):
    s = b.decode("utf-8", "replace") if isinstance(b, bytes) else b
    return s[:6] + "…" + s[-4:] if len(s) > 12 else s[:3] + "***"


_SCRUB = re.compile(rb"[A-Za-z0-9+/_\-=.%!#$*^~]{8,}")
_HAS_DIGIT = re.compile(rb"[0-9]")
_HAS_ALPHA = re.compile(rb"[A-Za-z]")


def _scrub_token(m):
    t = m.group(0)
    if len(t) >= 16:
        return t[:4] + b"~" + str(len(t)).encode()
    if _HAS_DIGIT.search(t) and _HAS_ALPHA.search(t):
        return t[:2] + b"~" + str(len(t)).encode()
    return t


def scrub(b):
    """Context shown next to a hit: tokens of 16+ characters keep 4, mixed letter/digit tokens of 8+ keep 2."""
    if isinstance(b, str):
        b = b.encode("utf-8", "replace")
    return _SCRUB.sub(_scrub_token, b).decode("utf-8", "replace").replace("`", "'").replace("\r", " ") \
        .replace("\n", " ")


def entropy(b):
    if not b:
        return 0.0
    c = collections.Counter(b)
    n = len(b)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def write_json(path, obj, indent=1):
    tmp = path + ".part"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=indent, ensure_ascii=False, default=_default)
    os.replace(tmp, path)


def _default(o):
    if isinstance(o, (set, frozenset)):
        return sorted(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    raise TypeError(type(o).__name__)


def read_json(path, default=None):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def makedirs(path):
    os.makedirs(path, mode=0o700, exist_ok=True)


SKIP_DIRS = frozenset("""node_modules .venv venv .git site-packages __pycache__ dist build .next .cache .local .rustup
.cargo .npm .nvm .pyenv .gradle .m2 go .vscode-server .cursor-server AppData Library .Trash anaconda3 miniconda3
.conda Pods DerivedData .afterprompt cliextensions certifi""".split())


def skip_dir(name):
    return name in SKIP_DIRS or name.startswith("OneDrive")


class Walker:
    """os.walk with depth limit, directory pruning and a deadline. `truncated` is set when stopped early."""

    def __init__(self, root, max_depth, deadline, skip=skip_dir, prune_paths=()):
        self.root = root.rstrip(os.sep) or os.sep
        self.max_depth = max_depth
        self.deadline = deadline
        self.skip = skip
        self.prune = tuple(os.path.normpath(p) for p in prune_paths)
        self.truncated = False

    def __iter__(self):
        base = self.root.count(os.sep)
        for dp, dns, fns in os.walk(self.root):
            if time.monotonic() > self.deadline:
                self.truncated = True
                return
            depth = dp.count(os.sep) - base
            keep = []
            for d in dns:
                full = os.path.join(dp, d)
                if self.skip(d) or os.path.islink(full) or any(full == p or full.startswith(p + os.sep)
                                                               for p in self.prune):
                    continue
                keep.append(d)
            dns[:] = keep if depth < self.max_depth else []
            yield dp, dns, fns


def is_under(path, root):
    path = os.path.normpath(path)
    root = os.path.normpath(root)
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def display_path(path, home=None, windows_home=None):
    """Unix home → ~/…; Windows profile → C:\\Users\\…; anything else unchanged."""
    from afterprompt.platforms import to_windows_path
    if windows_home and is_under(path, windows_home):
        w = to_windows_path(path)
        if w:
            return w
    if home and is_under(path, home):
        return "~" + path[len(home.rstrip(os.sep)):]
    return path


def human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0


def human_duration(s):
    s = int(s)
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {sec:02d}s"


def eprint(*a):
    print(*a, file=sys.stderr, flush=True)
