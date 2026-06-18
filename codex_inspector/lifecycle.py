from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from .schemas import utc_now
from .storage import Storage


def default_idle_seconds() -> int:
    configured = os.environ.get("CODEX_INSPECTOR_IDLE_SECONDS")
    if configured:
        try:
            return max(1, int(configured))
        except ValueError:
            pass
    return 30


def apply_lifecycle_transitions(
    storage: Storage,
    *,
    idle_seconds: int | None = None,
    now: str | None = None,
) -> list[dict[str, Any]]:
    idle_seconds = idle_seconds if idle_seconds is not None else default_idle_seconds()
    now = now or utc_now()
    transitions: list[dict[str, Any]] = []
    for run in storage.list_observed_runs(statuses=["active"], limit=500):
        run_id = str(run["run_id"])
        quality = run.get("observation_quality")
        if quality == "passive_partial":
            transition = _transition_passive_partial(storage, run, idle_seconds=idle_seconds, now=now)
            if transition:
                transitions.append(transition)
        elif quality == "process_only":
            transition = _transition_process_only(storage, run, idle_seconds=idle_seconds, now=now)
            if transition:
                transitions.append(transition)
    return transitions


def _transition_passive_partial(
    storage: Storage,
    run: dict[str, Any],
    *,
    idle_seconds: int,
    now: str,
) -> dict[str, Any] | None:
    run_id = str(run["run_id"])
    processes = storage.get_observed_processes(run_id)
    sources = storage.get_observed_sources(run_id)
    active_process = any(process.get("status") == "active" for process in processes)
    if active_process:
        return None

    events = storage.get_events(run_id)
    saw_finished = any(event.get("normalized_event_type") == "run_finished" for event in events)
    source_idle = _sources_idle(sources, idle_seconds=idle_seconds, now=now)
    eof_stable = _sources_at_eof(sources) if sources else False

    if not source_idle:
        return None

    if saw_finished or eof_stable:
        storage.update_run(
            run_id,
            status="completed",
            last_seen_at=now,
            completed_reason="passive_source_idle_with_terminal_evidence",
        )
        return {"run_id": run_id, "status": "completed", "reason": "passive_source_idle_with_terminal_evidence"}

    last_seen = run.get("last_seen_at") or run.get("last_event_at")
    if last_seen and _seconds_since(last_seen, now) >= idle_seconds:
        storage.update_run(
            run_id,
            status="stale",
            last_seen_at=now,
            completed_reason="passive_source_idle_without_terminal_evidence",
        )
        return {"run_id": run_id, "status": "stale", "reason": "passive_source_idle_without_terminal_evidence"}
    return None


def _transition_process_only(
    storage: Storage,
    run: dict[str, Any],
    *,
    idle_seconds: int,
    now: str,
) -> dict[str, Any] | None:
    run_id = str(run["run_id"])
    processes = storage.get_observed_processes(run_id)
    if any(process.get("status") == "active" for process in processes):
        return None
    if storage.get_observed_sources(run_id):
        return None
    last_seen = run.get("last_seen_at")
    if not last_seen or _seconds_since(last_seen, now) < idle_seconds:
        return None
    if run.get("status") != "stale":
        storage.update_run(
            run_id,
            status="stale",
            last_seen_at=now,
            completed_reason="process_only_idle_without_source",
        )
        return {"run_id": run_id, "status": "stale", "reason": "process_only_idle_without_source"}
    return None


def _sources_idle(sources: list[dict[str, Any]], *, idle_seconds: int, now: str) -> bool:
    if not sources:
        return True
    for source in sources:
        if source.get("status") == "active":
            return False
        last_ingested = source.get("last_ingested_at") or source.get("last_seen_at")
        if last_ingested and _seconds_since(last_ingested, now) < idle_seconds:
            return False
    return True


def _sources_at_eof(sources: list[dict[str, Any]]) -> bool:
    if not sources:
        return False
    for source in sources:
        cursor = int(source.get("cursor_offset") or 0)
        size = int(source.get("last_size") or 0)
        if cursor < size:
            return False
    return True


def _seconds_since(timestamp: str, now: str) -> float:
    start = _parse_iso(timestamp)
    end = _parse_iso(now)
    return (end - start).total_seconds()


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed
