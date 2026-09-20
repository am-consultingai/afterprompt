"""A process pool that survives crashed workers and kills any worker above its memory cap."""
import multiprocessing
import os
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from concurrent.futures.process import BrokenProcessPool

from afterprompt import progress
from afterprompt.util import log

WORKER = {}


def worker_init(d):
    WORKER.clear()
    WORKER.update(d)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    if d.get("platform") in ("linux", "wsl") and sys.platform.startswith("linux"):
        try:
            import resource
            cap = int(d["mem_cap_bytes"])
            resource.setrlimit(resource.RLIMIT_AS, (cap, cap))
        except (ValueError, OSError, ImportError):
            pass


def _rss_windows(pid):
    """Resident set from psapi; Windows has no /proc and no ps."""
    import ctypes
    from ctypes import wintypes

    class COUNTERS(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ = 0x1000, 0x0010
    k32, psapi = ctypes.WinDLL("kernel32", use_last_error=True), ctypes.WinDLL("psapi", use_last_error=True)
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, int(pid))
    if not h:
        return 0
    try:
        c = COUNTERS()
        c.cb = ctypes.sizeof(c)
        if not psapi.GetProcessMemoryInfo(h, ctypes.byref(c), c.cb):
            return 0
        return int(c.WorkingSetSize)
    finally:
        k32.CloseHandle(h)


def rss_bytes(pid):
    if sys.platform == "win32":
        try:
            return _rss_windows(pid)
        except (OSError, ValueError, AttributeError):
            return 0
    if sys.platform.startswith("linux"):
        try:
            with open(f"/proc/{pid}/status", encoding="ascii", errors="replace") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        return int(line.split()[1]) * 1024
        except (OSError, ValueError):
            return 0
        return 0
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, timeout=5).stdout
        return int(out.strip() or 0) * 1024
    except (OSError, ValueError, subprocess.SubprocessError):
        return 0


class Watchdog(threading.Thread):
    def __init__(self, ex, cap, label):
        super().__init__(daemon=True)
        self.ex, self.cap, self.label = ex, cap, label
        self.stop = threading.Event()
        self.killed = 0

    def run(self):
        while not self.stop.wait(1.0):
            procs = getattr(self.ex, "_processes", None) or {}
            for pid in list(procs):
                if rss_bytes(pid) > self.cap:
                    try:
                        # Windows has no SIGKILL; os.kill there calls TerminateProcess for any signal.
                        os.kill(pid, signal.SIGTERM if sys.platform == "win32" else signal.SIGKILL)
                        self.killed += 1
                        log(f"  {self.label}: worker {pid} exceeded {self.cap / 1024 ** 3:.2f} GB and was stopped")
                    except OSError:
                        pass


def _executor(cfg, n):
    ctx = multiprocessing.get_context(cfg.mp_start)
    return ProcessPoolExecutor(n, mp_context=ctx, initializer=worker_init, initargs=(cfg.worker_dict(),))


def run_pool(fn, items, label, is_done, on_crash, cfg, should_stop=None):
    """Run fn over items. should_stop(item) is called after each completion; once it returns true the
    remaining not-yet-started items are cancelled and returned."""
    pending = [it for it in items if not is_done(it)]
    skipped = []
    recorded = set()

    def record(it, why):
        recorded.add(it[0])
        on_crash(it, why)
    log(f"{label}: {len(pending)} of {len(items)} to process, {cfg.workers} workers, "
        f"{cfg.mem_cap_bytes / 1024 ** 3:.1f} GB cap each")
    stopping = False
    for rnd in range(1, 4):
        if not pending or stopping:
            break
        t0 = time.monotonic()
        done_n = 0
        broke = False
        with _executor(cfg, cfg.workers) as ex:
            # Submit before starting the watchdog: the executor creates its workers on the first submit, and
            # a fork-started worker must not inherit a live thread.
            futs = {ex.submit(fn, it): it for it in pending}
            wd = Watchdog(ex, cfg.mem_cap_bytes, label)
            wd.start()
            try:
                for fut in as_completed(futs):
                    done_n += 1
                    if fut.cancelled():
                        continue
                    try:
                        fut.result()
                    except BrokenProcessPool:
                        broke = True
                    except Exception as e:  # noqa: BLE001 - recorded per item
                        log(f"  {label}: item {futs[fut][0]} raised {type(e).__name__}: {e}")
                        record(futs[fut], f"error:{type(e).__name__}")
                    progress.emit(label, done_n, len(futs))
                    if done_n % 250 == 0 or done_n == len(futs):
                        log(f"  {label}: {done_n}/{len(futs)} (round {rnd}, {time.monotonic() - t0:.0f}s)")
                    if should_stop and not stopping and should_stop(futs[fut]):
                        stopping = True
                        for f in futs:
                            if not f.done() and f.cancel():
                                skipped.append(futs[f])
            finally:
                wd.stop.set()
        pending = [it for it in pending if not is_done(it) and it not in skipped and it[0] not in recorded]
        if broke:
            log(f"  {label}: worker pool crashed in round {rnd}; {len(pending)} items left")
    if stopping:
        return skipped
    for it in pending:
        try:
            with _executor(cfg, 1) as ex:
                fut = ex.submit(fn, it)
                wd = Watchdog(ex, cfg.mem_cap_bytes, label)
                wd.start()
                try:
                    fut.result()
                finally:
                    wd.stop.set()
        except BrokenProcessPool:
            log(f"  {label}: item {it[0]} crashes its worker even alone; recorded as crashed")
            record(it, "crashed")
        except Exception as e:  # noqa: BLE001
            record(it, f"error:{type(e).__name__}")
        if not is_done(it) and it[0] not in recorded:
            record(it, "incomplete")
    return skipped
