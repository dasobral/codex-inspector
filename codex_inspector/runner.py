from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .analyzer import analyze_run
from .git_utils import capture_git_snapshot
from .normalizer import diagnostic_event, parse_jsonl_lines, wrapper_event
from .schemas import new_id, utc_now
from .storage import Storage


class CodexUnavailableError(RuntimeError):
    pass


CODEX_MISSING_MESSAGE = (
    "Codex CLI was not found on PATH. Install/configure Codex or use fixture mode:\n"
    "codex-inspector import-fixtures"
)


def run_codex_task(
    *,
    repo: str | Path,
    prompt: str,
    db_path: str | Path | None = None,
    include_full_diff: bool = False,
    preserve_raw: bool = False,
) -> dict[str, Any]:
    repo_path = Path(repo).expanduser().resolve()
    if not repo_path.exists():
        raise FileNotFoundError(f"Repository path does not exist: {repo_path}")
    codex_bin = shutil.which("codex")
    if not codex_bin:
        raise CodexUnavailableError(CODEX_MISSING_MESSAGE)

    storage = Storage(db_path)
    storage.init_schema()
    run_id = new_id("run")
    started_at = utc_now()
    storage.create_run(
        run_id,
        source="codex_exec",
        prompt=prompt,
        repo_path=str(repo_path),
        started_at=started_at,
        status="active",
        observation_quality="wrapped_full",
        confidence=100,
        last_seen_at=started_at,
    )
    before = capture_git_snapshot(run_id, repo_path, "before", include_full_diff=False)
    storage.add_git_snapshot(before)
    command = [codex_bin, "exec", "--json", "-C", str(repo_path), prompt]
    start_event = wrapper_event(
        run_id,
        "run_started",
        source="codex_inspector_runner",
        repo_root=str(repo_path),
        raw_payload={"command": command, "repo": str(repo_path)},
        command=" ".join(command),
    )
    storage.insert_events([start_event])
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        cwd=str(repo_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    streamed_events = 0
    if proc.stdout is not None:
        for line in proc.stdout:
            stripped = line.rstrip("\n")
            if not stripped.strip():
                continue
            batch = parse_jsonl_lines(
                [stripped],
                run_id,
                source="codex_exec_stdout",
                repo_root=str(repo_path),
                preserve_raw=preserve_raw,
            )
            if batch:
                storage.insert_events(batch)
                streamed_events += len(batch)
                now = utc_now()
                storage.update_run(run_id, last_seen_at=now, last_event_at=now)
                analyze_run(storage, run_id)
    stderr = proc.stderr.read() if proc.stderr is not None else ""
    exit_code = proc.wait()
    duration_ms = int((time.monotonic() - start) * 1000)
    trailing_events = []
    if stderr.strip():
        trailing_events.append(
            diagnostic_event(
                run_id,
                source="codex_exec_stderr",
                repo_root=str(repo_path),
                message="Codex wrote to stderr.",
                raw_payload={"stderr": stderr},
                tags=["stderr"],
            )
        )
    after = capture_git_snapshot(run_id, repo_path, "after", include_full_diff=include_full_diff)
    storage.add_git_snapshot(after)
    trailing_events.append(
        wrapper_event(
            run_id,
            "run_finished",
            source="codex_inspector_runner",
            repo_root=str(repo_path),
            raw_payload={"exit_code": exit_code, "duration_ms": duration_ms},
            command_exit_code=exit_code,
            duration_ms=duration_ms,
            files_changed_after_run=after.changed_files,
            diff_summary=after.diff_summary,
        )
    )
    storage.insert_events(trailing_events)
    finished_at = utc_now()
    status = "completed" if exit_code == 0 else "failed"
    storage.update_run(
        run_id,
        finished_at=finished_at,
        status=status,
        codex_exit_code=exit_code,
        last_seen_at=finished_at,
        last_event_at=finished_at,
        completed_reason="wrapped_exit",
    )
    analysis = analyze_run(storage, run_id)
    event_count = len(storage.get_events(run_id))
    return {
        "run_id": run_id,
        "status": status,
        "exit_code": exit_code,
        "event_count": event_count,
        "streamed_event_count": streamed_events,
        "analysis": analysis,
        "db_path": str(storage.db_path),
    }
