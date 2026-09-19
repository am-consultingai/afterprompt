"""Command line: options, run lifecycle (new, resume, discard), stage orchestration, status, exit codes."""
import argparse
import datetime
import json
import os
import re
import shutil
import sys
import time
import traceback

from afterprompt import __version__, config, envs, platforms, worker
from afterprompt.util import (human_bytes, human_duration, log, makedirs, read_json, say, set_console_sink, set_log,
                              write_json)

EXIT_OK, EXIT_ROTATE, EXIT_USAGE, EXIT_DEPENDENCY, EXIT_UNSUPPORTED, EXIT_FAILED, EXIT_DISK, EXIT_PARTIAL, \
    EXIT_INTERRUPTED = 0, 10, 2, 3, 4, 5, 6, 7, 130

QUICK = ["discover", "databases", "manifest", "vendor_raw", "known", "prompts", "triage", "report", "cleanup"]
DEEP = ["discover", "databases", "manifest", "vendor_raw", "expand", "vendor_store", "entropy_raw", "entropy_store",
        "known", "prompts", "triage", "report", "cleanup"]
DESCRIPTIONS = {
    "discover": "Finding AI tool data",
    "databases": "Reading chat databases",
    "manifest": "Listing files",
    "vendor_raw": "Matching 140 credential patterns",
    "expand": "Decoding nested payloads",
    "vendor_store": "Matching patterns in decoded data",
    "entropy_raw": "Entropy sweep",
    "entropy_store": "Entropy sweep of decoded data",
    "environments": "Scanning the other environments on this machine",
    "known": "Checking your live credentials against AI history",
    "prompts": "Reviewing your prompts for passwords",
    "triage": "Deciding what to rotate",
    "report": "Writing the report",
    "cleanup": "Removing work files",
}


class Usage(Exception):
    pass


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Usage(message)


def positive_float(s):
    try:
        v = float(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {s}")
    if v <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return v


def positive_int(s):
    try:
        v = int(s)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a whole number: {s}")
    if v < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return v


def parser():
    p = Parser(prog="afterprompt.sh", description="Find credentials that leaked into AI coding assistants' local history.",
               epilog="One run covers this machine and every WSL distribution on it; use --no-wsl to scan only "
                      "this machine. Exit codes: 0 nothing to rotate, 10 credentials to rotate, 7 nothing to rotate "
                      "but an environment could not be scanned, 2 usage error, 3 missing dependency, 4 unsupported "
                      "environment, 5 scan failed, 6 not enough disk space, 130 interrupted.")
    p.add_argument("--deep", action="store_true", help="decode nested payloads and run the entropy sweep")
    p.add_argument("--out", metavar="DIR", help="where to write the report (default: ~/.afterprompt/runs/<run-id>)")
    p.add_argument("--extra-root", metavar="PATH", action="append", help="also scan PATH (repeatable)")
    p.add_argument("--exclude", metavar="PATTERN", action="append",
                   help="skip files whose full path matches this regular expression (repeatable)")
    p.add_argument("--max-disk", metavar="GB", type=positive_float, default=10.0,
                   help="cap on decoded plaintext in deep mode (default: 10)")
    p.add_argument("--workers", metavar="N", type=positive_int, help="parallel workers (default: automatic)")
    p.add_argument("--keep-work", action="store_true",
                   help="keep intermediate files, including decoded plaintext, after the scan")
    p.add_argument("--include-keychain", action="store_true",
                   help="macOS: also check Claude Code's Keychain login (shows a permission prompt)")
    p.add_argument("--windows-home", metavar="PATH",
                   help="WSL: the Windows profile to scan, or 'none' to skip the Windows side")
    p.add_argument("--theme", choices=("neutral", "am"), default="neutral",
                   help="report look: neutral (default) or am, the AM Consulting brand")
    p.add_argument("--no-wsl", action="store_true",
                   help="scan only this machine, not the WSL distributions on it")
    p.add_argument("--no-download", action="store_true", help="never download ripgrep; fail if it is not installed")
    p.add_argument("--fresh", action="store_true", help="discard an unfinished scan and start over")
    p.add_argument("--status", action="store_true", help="show progress of a running or interrupted scan")
    p.add_argument("--version", action="store_true", help="print the version and exit")
    # Started by another Afterprompt run to scan the environment it runs in; speaks worker.py's protocol.
    p.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    return p


def new_run_dir(base):
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    runs = os.path.join(base, "runs")
    makedirs(runs)
    rid, n = stamp, 1
    while os.path.exists(os.path.join(runs, rid)):
        n += 1
        rid = f"{stamp}-{n}"
    return rid, os.path.join(runs, rid)


def read_current(base):
    try:
        with open(os.path.join(base, "current"), encoding="utf-8") as fh:
            rid = fh.read().strip()
    except OSError:
        return None, None
    if not rid or not re.fullmatch(r"[0-9]{8}-[0-9]{6}(?:-[0-9]+)?", rid):
        return None, None
    return rid, os.path.join(base, "runs", rid)


def status(base, out=print):
    rid, run_dir = read_current(base)
    if not rid or not os.path.isdir(run_dir):
        latest = None
        runs = os.path.join(base, "runs")
        if os.path.isdir(runs):
            for r in sorted(os.listdir(runs), reverse=True):
                meta = read_json(os.path.join(runs, r, "run.json"), {}) or {}
                if meta.get("finished"):
                    latest = os.path.join(meta.get("report_dir") or os.path.join(runs, r), "report.html")
                    break
        out("No scan in progress.")
        if latest:
            out(f"Latest report: {latest}")
        return EXIT_OK
    meta = read_json(os.path.join(run_dir, "run.json"), {}) or {}
    stages = stage_list(meta.get("mode") == "deep", bool(meta.get("environments")))
    out(f"Scan {rid} ({meta.get('mode', '?')} mode), started {meta.get('started', '?')}")
    for s in stages:
        done = os.path.exists(os.path.join(run_dir, "work", "state", f"{s}.done"))
        out(f"  {'done' if done else '    '}  {DESCRIPTIONS[s]}")
    exp = os.path.join(run_dir, "work", "state", "expand")
    if os.path.isdir(exp):
        man = os.path.join(run_dir, "work", "manifest.tsv")
        total = sum(1 for _ in open(man, encoding="utf-8")) if os.path.exists(man) else 0
        out(f"  decoded files: {len(os.listdir(exp))} of about {total}")
    store = os.path.join(run_dir, "work", "store")
    if os.path.isdir(store):
        size = sum(os.path.getsize(os.path.join(store, f)) for f in os.listdir(store))
        out(f"  decoded plaintext on disk: {human_bytes(size)}")
    return EXIT_OK


def stage_list(deep, other_envs):
    stages = list(DEEP if deep else QUICK)
    if other_envs:
        stages.insert(stages.index("report"), "environments")
    return stages


def worker_args(cfg, args):
    """What a worker needs to scan its environment the way this run scans this one. Paths from this machine
    (--extra-root, --out, --windows-home) mean nothing there; the Windows profile is covered here, not twice."""
    out = ["--worker", "--windows-home", "none", "--max-disk", str(args.max_disk)]
    out += ["--deep"] if cfg.deep else []
    out += ["--no-download"] if args.no_download else []
    out += ["--keep-work"] if cfg.keep_work else []
    out += ["--fresh"] if args.fresh else []
    for x in cfg.excludes:
        out += ["--exclude", x]
    return out


def scan_environments(cfg, ctx):
    state_dir = os.path.join(cfg.run_dir, "envs")
    results = []
    for e in ctx["envs"][1:]:
        prev = envs.load_result(state_dir, e)
        if prev:
            say(f"      {e.label} … already done")
            results.append(prev)
            continue
        if cfg.no_wsl and e.kind == "wsl":
            r = envs.save_result(state_dir, envs.skipped(e, "--no-wsl was given"))
        else:
            say(f"      {e.label}")
            r = envs.scan(e, cfg, ctx["worker_args"], lambda m: say("        " + m), state_dir)
        if r["status"] == "not_scanned":
            say(f"      {e.label}: not scanned — {r['reason']}")
        results.append(r)
    ctx["env_results"] = results
    counts = {s: sum(1 for r in results if r["status"] == s) for s in envs.FINAL}
    return dict(counts, environments=len(results))


def env_results(cfg, ctx):
    if "env_results" in ctx:
        return ctx["env_results"]
    state_dir = os.path.join(cfg.run_dir, "envs")
    return [r for r in (envs.load_result(state_dir, e) for e in ctx["envs"][1:]) if r]


def run_stage(cfg, name, ctx):
    from afterprompt import databases, decode, entropy, known, manifest, prompts, report, sources, triage, vendor
    if name == "discover":
        ctx["sources"] = sources.discover(cfg)
        s = ctx["sources"]
        return {"roots": len(s["roots"]), "databases": len(s["databases"]), "project_dirs": len(s["project_dirs"]),
                "windows_home": s["windows_home"], "windows_home_source": s["windows_home_source"]}
    src = ctx["sources"]
    if name == "databases":
        return databases.extract(cfg, src)
    if name == "manifest":
        return manifest.build(cfg, src)
    rows = manifest.load(cfg)
    raw_paths = [r for r, _, _ in manifest.scan_roots(cfg, src)]
    if name == "vendor_raw":
        return vendor.run(cfg, "raw", raw_paths)
    if name == "expand":
        return decode.run(cfg, rows)
    if name == "vendor_store":
        return vendor.run(cfg, "store", [cfg.w("store")])
    if name == "entropy_raw":
        return entropy.run(cfg, "raw", rows)
    if name == "entropy_store":
        return entropy.run(cfg, "store", rows)
    if name == "known":
        return known.run(cfg, src, raw_paths + ([cfg.w("store")] if cfg.deep else []))
    if name == "prompts":
        return prompts.run(cfg, src)
    if name == "triage":
        t = triage.build(cfg, src)
        ctx["triage"] = t
        return {"rotate": len(t["rotate"]),
                "review": sum(n for c, n in t["review_totals"].items() if c != "entropy"),
                "dismissed": sum(t["dismissed"].values())}
    if name == "environments":
        return scan_environments(cfg, ctx)
    if name == "report":
        data = report.write(cfg, src, ctx["meta"], host_env=ctx["envs"][0].to_dict(), env_results=env_results(cfg, ctx))
        ctx["summary"] = data["summary"]
        write_json(os.path.join(cfg.run_dir, "summary.json"), data["summary"])
        return {}
    if name == "cleanup":
        if not cfg.keep_work:
            shutil.rmtree(cfg.work_dir, ignore_errors=True)
        return {"kept": cfg.keep_work}
    raise ValueError(name)


def stage_result_line(name, info):
    if name == "discover":
        extra = ""
        if info.get("windows_home_source") not in ("not applicable", "disabled"):
            extra = f" · Windows profile: {info.get('windows_home') or 'not found'} ({info.get('windows_home_source')})"
        return f"{info['roots']} locations, {info['databases']} chat databases{extra}"
    if name == "databases":
        failed = len(info.get("failed", []))
        return f"{info['ok']} of {info['databases']} read" + (f" ({failed} could not be read)" if failed else "")
    if name == "manifest":
        return f"{info['files']:,} files, {human_bytes(info['bytes'])}"
    if name in ("vendor_raw", "vendor_store"):
        return f"{info['hits']:,} raw matches"
    if name == "expand":
        return f"{human_bytes(info['decoded_bytes'])} decoded" + (" (disk cap reached)" if info["disk_cap_reached"] else "")
    if name == "known":
        return f"{info['values']:,} live values, {info['occurrences']:,} occurrences in AI data"
    if name == "prompts":
        return f"{info['unique_prompts']:,} prompts, {info['near_keyword']} candidates"
    if name == "triage":
        return f"{info['rotate']} to rotate, {info['review']} to review"
    if name == "environments":
        parts = [f"{info.get(s, 0)} {t}" for s, t in (("scanned", "scanned"), ("scanned_share", "over the share"),
                                                     ("not_scanned", "not scanned"), ("skipped", "skipped"))
                 if info.get(s)]
        return ", ".join(parts)
    return ""


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if "--worker" not in argv:
        return run(argv, None)
    # A worker's stdout belongs to the protocol: console lines become "say" messages, and the run ends with
    # exactly one "result" or "error".
    emit = worker.Emitter()
    said = []

    def sink(msg):
        said.append(msg)
        emit("say", text=msg)
    set_console_sink(sink)
    try:
        code = run(argv, emit)
    except BaseException as err:  # noqa: BLE001 - the host must always hear how the worker ended
        emit("error", exit=EXIT_FAILED, message=f"{type(err).__name__}: {err}")
        raise
    finally:
        set_console_sink(None)
    if code not in (EXIT_OK, EXIT_ROTATE, EXIT_PARTIAL) and not getattr(emit, "finished", False):
        emit("error", exit=code, message=" ".join(m.strip() for m in said[-2:] if m.strip()) or f"exit code {code}")
    return code


def run(argv, emit):
    try:
        args = parser().parse_args(argv)
        for p in args.extra_root or []:
            if not os.path.exists(os.path.expanduser(p)):
                raise Usage(f"--extra-root: path not found: {p}")
        for x in args.exclude or []:
            try:
                re.compile(x)
            except re.error as err:
                raise Usage(f"--exclude: invalid regular expression {x!r}: {err}")
        if args.windows_home and args.windows_home.lower() != "none" and not os.path.isdir(args.windows_home):
            raise Usage(f"--windows-home: folder not found: {args.windows_home}")
    except Usage as err:
        print(f"afterprompt.sh: {err}\nRun ./afterprompt.sh --help for usage.", file=sys.stderr)
        return EXIT_USAGE
    if args.version:
        print(f"afterprompt {__version__}")
        return EXIT_OK

    os.umask(0o077)
    base = config.base_dir_from_env()
    if args.worker:
        # Its own folder, so a worker never resumes or discards a scan someone started by hand in that
        # environment. ripgrep stays shared in <base>/bin, where the launcher put it.
        base = os.path.join(base, "worker")
    makedirs(base)
    if args.status:
        return status(base)

    try:
        platforms.detect(os.environ.get("AFTERPROMPT_PLATFORM") or None)
    except ValueError as err:
        print(f"afterprompt.sh: {err}", file=sys.stderr)
        return EXIT_USAGE

    rid, run_dir = read_current(base)
    probe = config.from_args(args, run_dir or os.path.join(base, "runs", "probe"))
    fp = probe.fingerprint()
    resumed = False
    notice = None
    if rid and os.path.isdir(run_dir):
        meta = read_json(os.path.join(run_dir, "run.json"), {}) or {}
        if meta.get("fingerprint") == fp and not meta.get("finished") and not args.fresh:
            resumed = True
        else:
            shutil.rmtree(run_dir, ignore_errors=True)
            notice = "Discarded an unfinished scan" + (" (--fresh)." if args.fresh else " that used different options.")
    if not resumed:
        rid, run_dir = new_run_dir(base)
        makedirs(run_dir)
    cfg = config.from_args(args, run_dir)
    makedirs(cfg.work_dir)
    makedirs(cfg.w("state"))
    set_log(os.path.join(run_dir, "run.log"))
    meta_path = os.path.join(run_dir, "run.json")
    if resumed:
        meta = read_json(meta_path, {})
        meta["report_dir"] = cfg.report_dir
    else:
        meta = {"run_id": rid, "fingerprint": fp, "mode": cfg.mode, "version": __version__,
                "started": datetime.datetime.now().isoformat(timespec="seconds"), "report_dir": cfg.report_dir,
                "options": {"extra_roots": cfg.extra_roots, "excludes": cfg.excludes,
                            "max_disk_gb": args.max_disk, "include_keychain": cfg.include_keychain,
                            "windows_home": cfg.windows_home_arg}}
    if resumed and "environments" in meta:
        env_list = [envs.host(cfg)] + [envs.Environment.from_dict(d) for d in meta["environments"]]
    else:
        env_list = envs.discover(cfg)
        meta["environments"] = [e.to_dict() for e in env_list[1:]]
    write_json(meta_path, meta)
    with open(os.path.join(base, "current"), "w", encoding="utf-8") as fh:
        fh.write(rid + "\n")

    if emit:
        emit("hello", version=__version__, platform=cfg.platform, other_homes=envs.other_homes(cfg.home))
    else:
        many = f" · {len(env_list)} environments" if len(env_list) > 1 else ""
        say(f"afterprompt {__version__} · {cfg.mode} scan · {cfg.platform}{many}")
    if notice:
        say(notice)
    if resumed:
        say(f"Resuming the scan started at {meta.get('started', '?').replace('T', ' ')}.")

    if cfg.deep:
        free = shutil.disk_usage(base).free
        if free < 2 * config.GIB:
            say(f"Not enough free disk space for a deep scan: {human_bytes(free)} free, at least 2 GB needed.")
            return EXIT_DISK
        if free - config.GIB < cfg.max_disk_bytes:
            cfg.max_disk_bytes = int(free - config.GIB)
            say(f"Only {human_bytes(free)} free: decoded data capped at {human_bytes(cfg.max_disk_bytes)}.")

    stages = stage_list(cfg.deep, len(env_list) > 1)
    ctx = {"meta": meta, "envs": env_list, "worker_args": worker_args(cfg, args)}
    t0 = time.monotonic()
    current = None
    try:
        for k, name in enumerate(stages, 1):
            current = name
            marker = cfg.w("state", f"{name}.done") if name != "cleanup" else None
            if marker and os.path.exists(marker):
                if name == "discover":
                    ctx["sources"] = read_json(cfg.w("sources.json"))
                say(f"[{k}/{len(stages)}] {DESCRIPTIONS[name]} … already done")
                continue
            if name != "discover" and "sources" not in ctx:
                ctx["sources"] = read_json(cfg.w("sources.json"))
            say(f"[{k}/{len(stages)}] {DESCRIPTIONS[name]} …")
            ts = time.monotonic()
            log(f"=== stage {name} start (workers={cfg.workers}, mp={cfg.mp_start})")
            info = run_stage(cfg, name, ctx) or {}
            info["elapsed_s"] = round(time.monotonic() - ts, 1)
            if marker:
                write_json(marker, info)
            line = stage_result_line(name, info)
            if line:
                say(f"      {line}")
            log(f"=== stage {name} end ({info['elapsed_s']}s)")
            if cfg.stop_after == name:
                say(f"Stopped after {name} (AFTERPROMPT_STOP_AFTER).")
                return EXIT_INTERRUPTED
    except KeyboardInterrupt:
        say("")
        say("Interrupted. Run ./afterprompt.sh again with the same options to resume, or ./afterprompt.sh --fresh to start over.")
        say(f"Work files, which may include plaintext copies of chat data, remain in {cfg.work_dir} until then.")
        return EXIT_INTERRUPTED
    except Exception as err:  # noqa: BLE001 - reported and logged
        log("".join(traceback.format_exc()))
        say(f"The scan failed during '{DESCRIPTIONS.get(current, current)}': {type(err).__name__}: {err}")
        say(f"Details: {os.path.join(run_dir, 'run.log')}. Run ./afterprompt.sh again to retry from this step.")
        return EXIT_FAILED

    meta["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
    write_json(meta_path, meta)
    try:
        os.remove(os.path.join(base, "current"))
    except OSError:
        pass
    summary = ctx.get("summary") or read_json(os.path.join(run_dir, "summary.json"), {}) or {}
    code = EXIT_ROTATE if summary.get("rotate", 0) else (EXIT_PARTIAL if summary.get("environments_not_scanned")
                                                        else EXIT_OK)
    if emit:
        emit("result", exit=code, findings=read_json(os.path.join(cfg.report_dir, "findings.json"), {}))
        emit.finished = True
        return code
    say("")
    say(f"Done in {human_duration(time.monotonic() - t0)}.")
    say(f"  Rotate now: {summary.get('rotate', 0)}")
    say(f"  Review:     {summary.get('review', 0):,}")
    if summary.get("entropy_candidates"):
        say(f"  Random-looking tokens (deep scan): {summary['entropy_candidates']:,}; the strongest are listed in the report")
    for r in env_results(cfg, ctx):
        if r["status"] == "not_scanned":
            say(f"  Not scanned: {r['label']} — {r['reason']}")
    say(f"Report: {os.path.join(cfg.report_dir, 'report.html')}")
    return code
