"""Run configuration: options, environment hooks, worker defaults, fingerprint, run folders."""
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional

from afterprompt import __version__, platforms

GIB = 1024 ** 3


def env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return float(default)


def default_workers(cpu=None, ram_gb=None):
    cpu = cpu if cpu is not None else (os.cpu_count() or 2)
    if ram_gb is None:
        try:
            ram_gb = os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE") / GIB
        except (ValueError, OSError, AttributeError):
            ram_gb = 8
    return max(1, min(6, cpu - 1, int(ram_gb // 3)))


@dataclass
class RunConfig:
    mode: str = "quick"
    base_dir: str = ""
    run_dir: str = ""
    work_dir: str = ""
    report_dir: str = ""
    home: str = ""
    windows_home_arg: Optional[str] = None
    extra_roots: List[str] = field(default_factory=list)
    excludes: List[str] = field(default_factory=list)
    max_disk_bytes: int = 10 * GIB
    workers: int = 1
    mem_cap_bytes: int = 3 * GIB
    file_timeout: int = 1800
    pattern_timeout: int = 900
    walk_budget: float = 180.0
    keep_work: bool = False
    include_keychain: bool = False
    rg: str = "rg"
    install_dir: str = ""
    platform: str = "linux"
    mp_start: str = "fork"
    stop_after: Optional[str] = None
    now: float = 0.0

    @property
    def deep(self):
        return self.mode == "deep"

    def fingerprint(self):
        data = {"version": __version__, "mode": self.mode, "home": self.home,
                "windows_home_arg": self.windows_home_arg, "extra_roots": sorted(self.extra_roots),
                "excludes": sorted(self.excludes), "max_disk_bytes": self.max_disk_bytes,
                "include_keychain": self.include_keychain}
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()

    def worker_dict(self):
        return {"work_dir": self.work_dir, "mem_cap_bytes": self.mem_cap_bytes, "file_timeout": self.file_timeout,
                "file_out_cap": min(512 * 1024 ** 2, self.max_disk_bytes), "platform": self.platform}

    def w(self, *parts):
        return os.path.join(self.work_dir, *parts)


def from_args(args, run_dir):
    install_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base_dir = base_dir_from_env()
    plat = platforms.detect(os.environ.get("AFTERPROMPT_PLATFORM") or None)
    # fork is unavailable on Windows and unsafe from a multi-threaded parent on macOS.
    native_spawn = plat in ("macos", "windows") or sys.platform in ("darwin", "win32")
    mp = os.environ.get("AFTERPROMPT_MP_START") or ("spawn" if native_spawn else "fork")
    win_arg = args.windows_home if args.windows_home is not None else (os.environ.get("AFTERPROMPT_WINDOWS_HOME") or None)
    cfg = RunConfig(
        mode="deep" if args.deep else "quick",
        base_dir=base_dir,
        run_dir=run_dir,
        work_dir=os.path.join(run_dir, "work"),
        report_dir=os.path.abspath(os.path.expanduser(args.out)) if args.out else run_dir,
        home=os.path.abspath(os.environ.get("AFTERPROMPT_HOME") or os.path.expanduser("~")),
        windows_home_arg=win_arg,
        extra_roots=[os.path.abspath(os.path.expanduser(p)) for p in (args.extra_root or [])],
        excludes=list(args.exclude or []),
        max_disk_bytes=int(args.max_disk * GIB),
        workers=args.workers or default_workers(),
        mem_cap_bytes=int(env_float("AFTERPROMPT_MEM_GB", 3) * GIB),
        file_timeout=int(env_float("AFTERPROMPT_FILE_TIMEOUT", 1800)),
        pattern_timeout=int(env_float("AFTERPROMPT_PATTERN_TIMEOUT", 900)),
        walk_budget=env_float("AFTERPROMPT_WALK_BUDGET", 180),
        keep_work=args.keep_work,
        include_keychain=args.include_keychain,
        rg=os.environ.get("AFTERPROMPT_RG") or "rg",
        install_dir=install_dir,
        platform=plat,
        mp_start=mp,
        stop_after=os.environ.get("AFTERPROMPT_STOP_AFTER") or None,
    )
    return cfg


def base_dir_from_env():
    return os.path.abspath(os.path.expanduser(os.environ.get("AFTERPROMPT_DIR") or "~/.afterprompt"))
