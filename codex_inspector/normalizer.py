from __future__ import annotations

import json
import shlex
from collections.abc import Iterable
from typing import Any

from .redaction import redact_payload, redact_text
from .schemas import NORMALIZED_EVENT_TYPES, NormalizedEvent, new_id, utc_now


def summarize_text(value: Any, limit: int = 2000) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, sort_keys=True)
    text = redact_text(text.strip())
    if len(text) <= limit:
        return text
    return f"{text[:limit]}... [truncated {len(text) - limit} chars]"


def normalize_event(
    raw_event: Any,
    run_id: str,
    *,
    source: str = "codex",
    repo_root: str | None = None,
    preserve_raw: bool = False,
) -> NormalizedEvent:
    raw = raw_event if isinstance(raw_event, dict) else {"value": raw_event}
    source_event_type = _first(raw, "type", "event_type", "event", "kind", "name")
    tool_name = _extract_tool_name(raw)
    normalized_type = _classify_event(raw, str(source_event_type or ""), str(tool_name or ""))
    event_id = str(_first(raw, "event_id", "id", "uuid") or new_id("evt"))
    command = _extract_command(raw)
    stdout_summary = summarize_text(_first(raw, "stdout", "output", "command_stdout", "result"))
    stderr_summary = summarize_text(_first(raw, "stderr", "error_output", "command_stderr"))
    error_message = summarize_text(_first(raw, "error_message", "message", "error"), limit=1000)
    if normalized_type not in {"error", "diagnostic"} and error_message and not _looks_like_error(raw):
        error_message = None
    file_reads, file_writes = _extract_files(raw)
    event = NormalizedEvent(
        event_id=event_id,
        run_id=run_id,
        session_id=_as_str(_first(raw, "session_id", "conversation_id")),
        turn_id=_as_str(_first(raw, "turn_id", "step_id", "message_id")),
        parent_event_id=_as_str(_first(raw, "parent_event_id", "parent_id")),
        timestamp=_as_str(_first(raw, "timestamp", "time", "created_at")) or utc_now(),
        source=source,
        source_event_type=_as_str(source_event_type),
        normalized_event_type=normalized_type,
        actor=_as_str(_first(raw, "actor", "role")),
        cwd=_as_str(_first(raw, "cwd", "working_directory")),
        repo_root=_as_str(_first(raw, "repo_root", "repository")) or repo_root,
        git_branch=_as_str(_first(raw, "git_branch", "branch")),
        git_head_before=_as_str(_first(raw, "git_head_before", "head_before")),
        git_head_after=_as_str(_first(raw, "git_head_after", "head_after")),
        model=_as_str(_first(raw, "model", "model_name")),
        approval_mode=_as_str(_first(raw, "approval_mode")),
        sandbox_mode=_as_str(_first(raw, "sandbox_mode")),
        tool_name=tool_name,
        command=command,
        command_exit_code=_as_int(_first(raw, "exit_code", "command_exit_code", "returncode")),
        command_stdout_summary=stdout_summary,
        command_stderr_summary=stderr_summary,
        file_paths_read=file_reads,
        file_paths_written=file_writes,
        files_changed_after_run=_as_list(_first(raw, "files_changed_after_run", "changed_files")),
        diff_summary=summarize_text(_first(raw, "diff_summary", "diff_stat"), limit=4000),
        approval_status=_as_str(_first(raw, "approval_status", "decision", "status")),
        error_type=_as_str(_first(raw, "error_type", "exception_type")),
        error_message=error_message,
        duration_ms=_as_int(_first(raw, "duration_ms", "elapsed_ms")),
        token_count_input=_as_int(_first(raw, "token_count_input", "input_tokens", "prompt_tokens")),
        token_count_output=_as_int(_first(raw, "token_count_output", "output_tokens", "completion_tokens")),
        estimated_cost=_as_float(_first(raw, "estimated_cost", "cost")),
        risk_level=_as_str(_first(raw, "risk_level")),
        tags=_as_list(_first(raw, "tags")),
        raw_payload=raw if preserve_raw else redact_payload(raw),
    )
    if normalized_type == "shell_command" and "command" not in event.tags:
        event.tags.append("command")
    return event


def diagnostic_event(
    run_id: str,
    *,
    source: str,
    message: str,
    raw_payload: dict[str, Any] | None = None,
    repo_root: str | None = None,
    tags: list[str] | None = None,
) -> NormalizedEvent:
    payload = redact_payload(raw_payload or {"message": message})
    return NormalizedEvent(
        run_id=run_id,
        source=source,
        source_event_type="diagnostic",
        normalized_event_type="diagnostic",
        repo_root=repo_root,
        error_type="diagnostic",
        error_message=summarize_text(message, limit=1000),
        tags=tags or ["diagnostic"],
        raw_payload=payload,
    )


def wrapper_event(
    run_id: str,
    normalized_event_type: str,
    *,
    source: str = "codex_inspector",
    repo_root: str | None = None,
    raw_payload: dict[str, Any] | None = None,
    **fields: Any,
) -> NormalizedEvent:
    if normalized_event_type not in NORMALIZED_EVENT_TYPES:
        normalized_event_type = "unknown"
    event = NormalizedEvent(
        run_id=run_id,
        source=source,
        source_event_type=normalized_event_type,
        normalized_event_type=normalized_event_type,
        repo_root=repo_root,
        raw_payload=redact_payload(raw_payload or {}),
    )
    for key, value in fields.items():
        if hasattr(event, key):
            setattr(event, key, value)
    return event


def parse_jsonl_lines(
    lines: Iterable[str],
    run_id: str,
    *,
    source: str = "codex_jsonl",
    repo_root: str | None = None,
    preserve_raw: bool = False,
) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError as exc:
            events.append(
                diagnostic_event(
                    run_id,
                    source=source,
                    repo_root=repo_root,
                    message=f"Malformed JSONL line {line_number}: {exc.msg}",
                    raw_payload={
                        "line_number": line_number,
                        "malformed_line": redact_text(stripped),
                        "parse_error": str(exc),
                    },
                    tags=["malformed_jsonl"],
                )
            )
            continue
        event = normalize_event(raw, run_id, source=source, repo_root=repo_root, preserve_raw=preserve_raw)
        event.tags.append(f"line:{line_number}")
        events.append(event)
    return events


def parse_json_document(
    text: str,
    run_id: str,
    *,
    source: str,
    repo_root: str | None = None,
    preserve_raw: bool = False,
) -> list[NormalizedEvent]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return parse_jsonl_lines(text.splitlines(), run_id, source=source, repo_root=repo_root, preserve_raw=preserve_raw)
    items = payload if isinstance(payload, list) else [payload]
    return [
        normalize_event(item, run_id, source=source, repo_root=repo_root, preserve_raw=preserve_raw)
        for item in items
    ]


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] is not None:
            return raw[key]
    for key in keys:
        found = _deep_find(raw, key)
        if found is not None:
            return found
    return None


def _deep_find(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value and value[key] is not None:
            return value[key]
        for item in value.values():
            found = _deep_find(item, key)
            if found is not None:
                return found
    if isinstance(value, list):
        for item in value:
            found = _deep_find(item, key)
            if found is not None:
                return found
    return None


def _classify_event(raw: dict[str, Any], source_event_type: str, tool_name: str) -> str:
    text = f"{source_event_type} {tool_name} {_as_str(raw.get('action')) or ''}".lower()
    status = str(_first(raw, "status", "approval_status", "decision") or "").lower()
    if any(term in text for term in ("run_started", "run.start", "session.started")):
        return "run_started"
    if any(term in text for term in ("run_finished", "run.complete", "run.completed", "session.finished")):
        return "run_finished"
    if "thread" in text and "start" in text:
        return "thread_started"
    if "turn" in text and "start" in text:
        return "turn_started"
    if "turn" in text and any(term in text for term in ("finish", "complete")):
        return "turn_finished"
    if any(term in text for term in ("message", "assistant", "model")) and "tool" not in text:
        return "model_message"
    if any(term in text for term in ("exec", "shell", "command", "bash")) or _extract_command(raw):
        return "shell_command"
    if "patch" in text or "apply_patch" in text:
        return "patch_applied"
    if "file" in text and any(term in text for term in ("read", "open")):
        return "file_read"
    if "file" in text and any(term in text for term in ("write", "edit", "modify")):
        return "file_write"
    if "approval" in text:
        if status in {"approved", "granted", "allow", "allowed"}:
            return "approval_granted"
        if status in {"denied", "rejected", "blocked"}:
            return "approval_denied"
        return "approval_requested"
    if "sandbox" in text:
        return "sandbox_event"
    if _looks_like_error(raw):
        return "error"
    if "tool" in text and any(term in text for term in ("finish", "result", "complete")):
        return "tool_call_finished"
    if "tool" in text or tool_name:
        return "tool_call_started"
    if source_event_type.lower() == "diagnostic":
        return "diagnostic"
    return "unknown"


def _looks_like_error(raw: dict[str, Any]) -> bool:
    text = " ".join(str(_first(raw, "type", "event_type", "level", "status", "error_type") or "").lower().split())
    return "error" in text or "failed" in text or bool(raw.get("error") or raw.get("exception"))


def _extract_tool_name(raw: dict[str, Any]) -> str | None:
    tool = _first(raw, "tool_name", "tool", "name")
    if isinstance(tool, dict):
        tool = _first(tool, "name", "type")
    return _as_str(tool)


def _extract_command(raw: dict[str, Any]) -> str | None:
    command = _first(raw, "command", "cmd", "shell_command")
    if command is None:
        args = _first(raw, "arguments", "args")
        if isinstance(args, dict):
            command = _first(args, "command", "cmd", "shell_command")
        elif isinstance(args, list) and args and all(isinstance(item, str) for item in args):
            command = args
    if isinstance(command, list):
        return " ".join(shlex.quote(str(part)) for part in command)
    return _as_str(command)


def _extract_files(raw: dict[str, Any]) -> tuple[list[str], list[str]]:
    reads = _as_list(_first(raw, "file_paths_read", "files_read", "read_files"))
    writes = _as_list(_first(raw, "file_paths_written", "files_written", "written_files", "modified_files"))
    path = _first(raw, "path", "file_path", "filename")
    event_type = str(_first(raw, "type", "event_type", "action") or "").lower()
    if path:
        if "read" in event_type or "open" in event_type:
            reads.append(str(path))
        if any(term in event_type for term in ("write", "edit", "modify", "patch")):
            writes.append(str(path))
    return _unique(reads), _unique(writes)


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [str(item) for item in value.values()]
    if isinstance(value, Iterable):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result
