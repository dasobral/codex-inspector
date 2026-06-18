from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .importer import import_fixture_runs, import_jsonl_file, import_transcript_path
from .observe_cycle import run_observation_cycle
from .observer import CodexObserver
from .runner import CODEX_MISSING_MESSAGE, CodexUnavailableError, run_codex_task
from .tailer import FileTailer
from .selftest import run_self_test
from .storage import Storage, default_db_path


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    db_path = getattr(args, "db", None) or default_db_path()
    try:
        if args.command == "init":
            storage = Storage(db_path)
            storage.init_schema()
            print(f"Initialized database: {storage.db_path}")
            return 0
        if args.command == "run":
            prompt = _prompt_from_remainder(args.prompt)
            if not prompt:
                print("A prompt is required after --.", file=sys.stderr)
                return 2
            result = run_codex_task(
                repo=args.repo,
                prompt=prompt,
                db_path=db_path,
                include_full_diff=args.include_full_diff,
                preserve_raw=args.preserve_raw,
            )
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0 if result["exit_code"] == 0 else result["exit_code"] or 1
        if args.command == "import-jsonl":
            result = import_jsonl_file(args.path, db_path=db_path, preserve_raw=args.preserve_raw)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 0
        if args.command == "import-transcript":
            results = import_transcript_path(args.path, db_path=db_path, preserve_raw=args.preserve_raw)
            print(json.dumps(results, indent=2, sort_keys=True))
            return 0
        if args.command == "import-fixtures":
            results = import_fixture_runs(db_path=db_path)
            print(f"Imported {len(results)} synthetic fixture runs into {Storage(db_path).db_path}")
            for result in results:
                print(f"- {result['run_id']}: {result['event_count']} events, {result['analysis']['risk_score']} risk")
            return 0
        if args.command == "discover":
            return discover_sessions(
                db_path,
                candidate_dirs=args.candidate_dir,
                attach_candidates=args.attach_candidates,
            )
        if args.command == "observe":
            return observe_sessions(
                db_path,
                once=args.once,
                watch=args.watch,
                interval=args.interval,
                candidate_dirs=args.candidate_dir,
                idle_seconds=args.idle_seconds,
                attach_candidates=args.attach_candidates,
            )
        if args.command == "attach":
            return attach_observation(db_path, pid=args.pid, path=args.path)
        if args.command == "dashboard":
            return launch_streamlit_dashboard(db_path)
        if args.command == "list-runs":
            return list_runs(db_path, limit=args.limit)
        if args.command == "show-run":
            return show_run(db_path, args.run_id, raw=args.raw)
        if args.command == "self-test":
            result = run_self_test()
            print(result.report)
            return 0 if result.passed else 1
    except CodexUnavailableError:
        print(CODEX_MISSING_MESSAGE, file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"codex-inspector: {exc}", file=sys.stderr)
        return 1
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="codex-inspector", description="Inspect OpenAI Codex CLI runs locally.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--db", default=str(default_db_path()), help="SQLite database path.")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("init", help="Initialize the local SQLite database.")

    run = subparsers.add_parser("run", help="Run Codex through the inspector wrapper.")
    run.add_argument("--repo", default=".", help="Repository path to pass to Codex with -C.")
    run.add_argument("--include-full-diff", action="store_true", help="Capture full git diff after the run.")
    run.add_argument("--preserve-raw", action="store_true", help="Store unredacted raw payloads.")
    run.add_argument("prompt", nargs=argparse.REMAINDER, help="Prompt after --.")

    import_jsonl = subparsers.add_parser("import-jsonl", help="Import a saved Codex JSONL event stream.")
    import_jsonl.add_argument("path")
    import_jsonl.add_argument("--preserve-raw", action="store_true", help="Store unredacted raw payloads.")

    transcript = subparsers.add_parser("import-transcript", help="Best-effort import of transcript files or directories.")
    transcript.add_argument("path")
    transcript.add_argument("--preserve-raw", action="store_true", help="Store unredacted raw payloads.")

    subparsers.add_parser("import-fixtures", help="Import synthetic fixture runs.")

    discover = subparsers.add_parser("discover", help="Discover likely active Codex sessions.")
    discover.add_argument("--candidate-dir", action="append", default=[], help="Optional directory to scan for passive sources.")
    discover.add_argument("--attach-candidates", action="store_true", help="Attach discovered candidate files during discovery.")

    observe = subparsers.add_parser("observe", help="Refresh passive process and source observations.")
    mode = observe.add_mutually_exclusive_group()
    mode.add_argument("--once", action="store_true", help="Run one observation cycle.")
    mode.add_argument("--watch", action="store_true", help="Repeat observation cycles until interrupted.")
    observe.add_argument("--interval", type=float, default=2.0, help="Watch interval in seconds.")
    observe.add_argument("--idle-seconds", type=int, default=None, help="Idle threshold for completed/stale transitions.")
    observe.add_argument("--candidate-dir", action="append", default=[], help="Directory to scan for passive sources.")
    observe.add_argument("--attach-candidates", action="store_true", help="Attach discovered candidate files during observation.")

    attach = subparsers.add_parser("attach", help="Explicitly attach a passive process or source path.")
    attach_target = attach.add_mutually_exclusive_group(required=True)
    attach_target.add_argument("--pid", type=int, help="Process id to attach.")
    attach_target.add_argument("--path", help="File or directory to attach as a passive source.")

    subparsers.add_parser("dashboard", help="Launch the local Streamlit dashboard.")

    list_runs_parser = subparsers.add_parser("list-runs", help="List stored runs.")
    list_runs_parser.add_argument("--limit", type=int, default=20)

    show = subparsers.add_parser("show-run", help="Show one run summary.")
    show.add_argument("run_id")
    show.add_argument("--raw", action="store_true", help="Print event raw payloads.")

    subparsers.add_parser("self-test", help="Run built-in validation checks.")
    return parser


def discover_sessions(
    db_path: str | Path,
    *,
    candidate_dirs: list[str] | None = None,
    attach_candidates: bool = False,
) -> int:
    result = run_observation_cycle(
        Storage(db_path),
        candidate_dirs=candidate_dirs,
        attach_candidates=attach_candidates,
        scan_process_sources=False,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def observe_sessions(
    db_path: str | Path,
    *,
    once: bool,
    watch: bool,
    interval: float,
    candidate_dirs: list[str] | None = None,
    idle_seconds: int | None = None,
    attach_candidates: bool = False,
) -> int:
    storage = Storage(db_path)

    def cycle() -> dict[str, object]:
        return run_observation_cycle(
            storage,
            candidate_dirs=candidate_dirs,
            idle_seconds=idle_seconds,
            attach_candidates=attach_candidates or bool(candidate_dirs),
        )

    if watch:
        try:
            while True:
                print(json.dumps(cycle(), sort_keys=True))
                time.sleep(interval)
        except KeyboardInterrupt:
            return 0
    result = cycle()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def attach_observation(db_path: str | Path, *, pid: int | None = None, path: str | None = None) -> int:
    storage = Storage(db_path)
    storage.init_schema()
    if pid is not None:
        result = CodexObserver(storage).attach_pid(pid)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    if path is not None:
        result = FileTailer(storage).attach_path(path)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    raise ValueError("Either --pid or --path is required")


def launch_streamlit_dashboard(db_path: str | Path) -> int:
    try:
        import streamlit  # noqa: F401
    except ModuleNotFoundError:
        print('Streamlit is not installed. Install with: pip install -e ".[dashboard]"', file=sys.stderr)
        return 2
    dashboard_path = Path(__file__).with_name("dashboard.py")
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            str(dashboard_path),
            "--server.address",
            "127.0.0.1",
            "--",
            "--db",
            str(db_path),
        ],
        check=False,
    ).returncode


def list_runs(db_path: str | Path, *, limit: int) -> int:
    storage = Storage(db_path)
    storage.init_schema()
    runs = storage.list_runs(limit=limit)
    if not runs:
        print("No runs found. Try: codex-inspector import-fixtures")
        return 0
    print("run_id                              status     risk  events  repo/prompt")
    for run in runs:
        label = run.get("repo_path") or run.get("prompt") or ""
        print(
            f"{run['run_id'][:34]:34}  "
            f"{(run.get('status') or '')[:9]:9}  "
            f"{run.get('risk_score', 0):>4}  "
            f"{run.get('event_count', 0):>6}  "
            f"{label[:70]}"
        )
    return 0


def show_run(db_path: str | Path, run_id: str, *, raw: bool = False) -> int:
    storage = Storage(db_path)
    storage.init_schema()
    run = storage.get_run(run_id)
    if not run:
        print(f"Run not found: {run_id}", file=sys.stderr)
        return 1
    print(json.dumps(run, indent=2, sort_keys=True))
    findings = storage.get_findings(run_id)
    if findings:
        print("\nFindings:")
        for finding in findings:
            print(f"- {finding['severity']}: {finding['reason']} ({finding['recommended_action']})")
    events = storage.get_events(run_id)
    print(f"\nEvents: {len(events)}")
    for event in events[:30]:
        print(
            f"- {event['timestamp']} {event['normalized_event_type']} "
            f"{event.get('tool_name') or ''} {event.get('command') or event.get('error_message') or ''}"
        )
        if raw:
            print(json.dumps(event.get("raw_payload"), indent=2, sort_keys=True))
    if len(events) > 30:
        print(f"... {len(events) - 30} more events")
    return 0


def _prompt_from_remainder(items: list[str]) -> str:
    values = list(items)
    if values and values[0] == "--":
        values = values[1:]
    return " ".join(values).strip()
