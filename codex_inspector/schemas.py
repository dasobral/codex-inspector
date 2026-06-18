from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = "1.0"

NORMALIZED_EVENT_TYPES = {
    "run_started",
    "run_finished",
    "thread_started",
    "turn_started",
    "turn_finished",
    "model_message",
    "tool_call_started",
    "tool_call_finished",
    "shell_command",
    "file_read",
    "file_write",
    "patch_applied",
    "approval_requested",
    "approval_granted",
    "approval_denied",
    "sandbox_event",
    "error",
    "diagnostic",
    "unknown",
}

RUN_STATUSES = {
    "active",
    "stale",
    "completed",
    "imported",
    "failed",
    "unknown",
    "created",
}

OBSERVATION_QUALITIES = {
    "wrapped_full",
    "imported_full",
    "passive_partial",
    "process_only",
    "unknown",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


@dataclass(slots=True)
class NormalizedEvent:
    schema_version: str = SCHEMA_VERSION
    event_id: str = field(default_factory=lambda: new_id("evt"))
    run_id: str = ""
    session_id: str | None = None
    turn_id: str | None = None
    parent_event_id: str | None = None
    timestamp: str = field(default_factory=utc_now)
    source: str = "codex"
    source_event_type: str | None = None
    normalized_event_type: str = "unknown"
    actor: str | None = None
    cwd: str | None = None
    repo_root: str | None = None
    git_branch: str | None = None
    git_head_before: str | None = None
    git_head_after: str | None = None
    model: str | None = None
    approval_mode: str | None = None
    sandbox_mode: str | None = None
    tool_name: str | None = None
    command: str | None = None
    command_exit_code: int | None = None
    command_stdout_summary: str | None = None
    command_stderr_summary: str | None = None
    file_paths_read: list[str] = field(default_factory=list)
    file_paths_written: list[str] = field(default_factory=list)
    files_changed_after_run: list[str] = field(default_factory=list)
    diff_summary: str | None = None
    approval_status: str | None = None
    error_type: str | None = None
    error_message: str | None = None
    duration_ms: int | None = None
    token_count_input: int | None = None
    token_count_output: int | None = None
    estimated_cost: float | None = None
    risk_level: str | None = None
    tags: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    run_id: str
    severity: str
    reason: str
    evidence_event_id: str | None
    recommended_action: str
    category: str = "general"


@dataclass(slots=True)
class GitSnapshot:
    run_id: str
    phase: str
    repo_path: str
    is_git_repo: bool
    branch: str | None = None
    head: str | None = None
    is_dirty: bool | None = None
    changed_files: list[str] = field(default_factory=list)
    diff_summary: str | None = None
    full_diff: str | None = None
    captured_at: str = field(default_factory=utc_now)
