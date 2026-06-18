from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .lifecycle import apply_lifecycle_transitions, default_idle_seconds
from .observer import CodexObserver
from .tailer import FileTailer, discover_candidate_files
from .storage import Storage


def default_candidate_dirs() -> list[str]:
    configured = os.environ.get("CODEX_INSPECTOR_CANDIDATE_DIRS")
    if not configured:
        return []
    return [part.strip() for part in configured.split(os.pathsep) if part.strip()]


def run_observation_cycle(
    storage: Storage,
    *,
    candidate_dirs: list[str] | None = None,
    idle_seconds: int | None = None,
    attach_candidates: bool = False,
    scan_process_sources: bool = True,
) -> dict[str, Any]:
    storage.init_schema()
    observer = CodexObserver(storage)
    tailer = FileTailer(storage)
    candidate_dirs = list(candidate_dirs or []) + default_candidate_dirs()
    candidate_dirs = list(dict.fromkeys(candidate_dirs))

    processes = observer.discover()
    source_results: list[dict[str, object]] = []
    if scan_process_sources:
        source_results.extend(_scan_process_sources(storage, tailer, processes))

    source_results.extend(tailer.tail_known_sources())

    candidate_files: list[str] = []
    for candidate_dir in candidate_dirs:
        candidate_files.extend(str(path) for path in discover_candidate_files(candidate_dir))
        if attach_candidates:
            source_results.extend(tailer.attach_path(candidate_dir))

    transitions = apply_lifecycle_transitions(storage, idle_seconds=idle_seconds)
    _analyze_process_only_runs(storage, processes)

    return {
        "processes": processes,
        "sources": source_results,
        "candidate_files": candidate_files,
        "candidate_dirs": candidate_dirs,
        "transitions": transitions,
        "idle_seconds": idle_seconds if idle_seconds is not None else default_idle_seconds(),
    }


def _scan_process_sources(
    storage: Storage,
    tailer: FileTailer,
    processes: list[dict[str, object]],
) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for process in processes:
        run_id = process.get("run_id")
        if not run_id:
            continue
        scan_dirs: list[Path] = []
        for value in (process.get("repo_path"), process.get("cwd")):
            if not value:
                continue
            path = Path(str(value)).expanduser().resolve()
            if path.exists() and path not in scan_dirs:
                scan_dirs.append(path)
        if not scan_dirs:
            continue
        candidates: list[Path] = []
        for scan_dir in scan_dirs:
            candidates.extend(discover_candidate_files(scan_dir))
        if not candidates:
            continue
        newest = max(candidates, key=lambda candidate: candidate.stat().st_mtime)
        results.append(tailer.tail_file(newest, run_id=str(run_id)))
    return results


def _analyze_process_only_runs(storage: Storage, processes: list[dict[str, object]]) -> None:
    from .analyzer import analyze_run

    seen: set[str] = set()
    for process in processes:
        run_id = process.get("run_id")
        if not run_id or run_id in seen:
            continue
        seen.add(str(run_id))
        run = storage.get_run(str(run_id)) or {}
        if run.get("observation_quality") == "process_only":
            analyze_run(storage, str(run_id))
