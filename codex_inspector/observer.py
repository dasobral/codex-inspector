from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .normalizer import summarize_text
from .redaction import redact_text
from .schemas import utc_now
from .storage import Storage


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    command_line: tuple[str, ...]
    cwd: str | None = None
    started_at: str | None = None
    executable: str | None = None


@dataclass(frozen=True, slots=True)
class ProcessScore:
    detected_kind: str
    confidence: int
    reason: str


class ProcessProvider(Protocol):
    def list_processes(self) -> list[ProcessInfo]:
        ...


class StaticProcessProvider:
    def __init__(self, processes: list[ProcessInfo]) -> None:
        self._processes = list(processes)

    def list_processes(self) -> list[ProcessInfo]:
        return list(self._processes)


class ProcfsProcessProvider:
    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)

    def list_processes(self) -> list[ProcessInfo]:
        processes: list[ProcessInfo] = []
        if not self.proc_root.exists():
            return processes
        for entry in self.proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            process = self._read_process(entry)
            if process is not None:
                processes.append(process)
        return processes

    def _read_process(self, entry: Path) -> ProcessInfo | None:
        try:
            pid = int(entry.name)
            raw_cmdline = (entry / "cmdline").read_bytes()
            parts = tuple(part.decode("utf-8", "replace") for part in raw_cmdline.split(b"\0") if part)
            if not parts:
                comm = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
                parts = (comm,) if comm else ()
            cwd = None
            try:
                cwd = str((entry / "cwd").resolve())
            except OSError:
                cwd = None
            started_at = None
            try:
                stat = (entry / "stat").read_text(encoding="utf-8", errors="replace")
                fields = stat.split()
                if len(fields) > 21:
                    started_at = fields[21]
            except OSError:
                started_at = None
            executable = Path(parts[0]).name if parts else None
            return ProcessInfo(pid=pid, command_line=parts, cwd=cwd, started_at=started_at, executable=executable)
        except (OSError, ValueError):
            return None


def score_process(process: ProcessInfo) -> ProcessScore:
    command_text = " ".join(process.command_line).lower()
    executable = (process.executable or (Path(process.command_line[0]).name if process.command_line else "")).lower()
    arg_basenames = {Path(arg).name.lower() for arg in process.command_line if arg}
    exact_args = {arg.lower() for arg in process.command_line}
    mentions_codex = executable == "codex" or "codex" in arg_basenames or "codex" in exact_args
    if mentions_codex and "exec" in exact_args and "--json" in exact_args:
        return ProcessScore("codex_exec", 96, "codex exec JSON stream")
    if mentions_codex and "exec" in exact_args:
        return ProcessScore("codex_exec", 90, "codex exec process")
    if mentions_codex:
        return ProcessScore("codex_cli", 82, "codex command line")
    if any(term in command_text for term in ("coding-agent", "agent.py", "openai")):
        return ProcessScore("codex_like", 30, "agent-like process")
    return ProcessScore("unknown", 5, "no Codex indicators")


class CodexObserver:
    def __init__(
        self,
        storage: Storage,
        *,
        process_provider: ProcessProvider | None = None,
        clock: callable | None = None,
    ) -> None:
        self.storage = storage
        self.process_provider = process_provider or ProcfsProcessProvider()
        self.clock = clock or utc_now

    def discover(self, *, min_confidence: int = 70) -> list[dict[str, object]]:
        self.storage.init_schema()
        now = self.clock()
        current_process_ids: set[str] = set()
        discovered: list[dict[str, object]] = []
        for process in self.process_provider.list_processes():
            score = score_process(process)
            if score.confidence < min_confidence:
                continue
            record = self._upsert_process(process, score, now=now, explicit=False)
            current_process_ids.add(str(record["process_id"]))
            discovered.append(record)
        self._mark_missing_processes(current_process_ids, now)
        return discovered

    def attach_pid(self, pid: int) -> dict[str, object]:
        self.storage.init_schema()
        now = self.clock()
        for process in self.process_provider.list_processes():
            if process.pid != pid:
                continue
            return self._upsert_process(process, score_process(process), now=now, explicit=True)
        raise ValueError(f"Process not found: {pid}")

    def _upsert_process(self, process: ProcessInfo, score: ProcessScore, *, now: str, explicit: bool) -> dict[str, object]:
        process_id = process_identity(process)
        existing = self.storage.get_observed_process(process_id)
        run_id = existing.get("run_id") if existing else run_identity(process_id)
        command_line = redact_text(" ".join(process.command_line))
        repo_path = _repo_from_cwd(process.cwd)
        confidence = score.confidence if not explicit else max(score.confidence, 20)
        self.storage.create_run(
            str(run_id),
            source="observer",
            prompt=f"Passive observation: {summarize_text(command_line, limit=160) or process.pid}",
            repo_path=repo_path or process.cwd,
            started_at=now,
            status="active",
            observation_quality="process_only",
            confidence=confidence,
            last_seen_at=now,
        )
        row = {
            "process_id": process_id,
            "run_id": str(run_id),
            "pid": process.pid,
            "pid_start_time": process.started_at,
            "command_line": command_line,
            "cwd": process.cwd,
            "repo_path": repo_path,
            "detected_kind": score.detected_kind,
            "confidence": confidence,
            "status": "active",
            "first_seen_at": now,
            "last_seen_at": now,
            "last_error": None,
        }
        self.storage.upsert_observed_process(row)
        return {**row, "reason": score.reason}

    def _mark_missing_processes(self, current_process_ids: set[str], now: str) -> None:
        for process in self.storage.get_observed_processes():
            if process.get("status") != "active" or process["process_id"] in current_process_ids:
                continue
            updated = dict(process)
            updated["status"] = "missing"
            updated["last_seen_at"] = now
            updated["last_error"] = "process no longer visible"
            self.storage.upsert_observed_process(updated)
            run_id = process.get("run_id")
            if run_id:
                run = self.storage.get_run(str(run_id)) or {}
                if run.get("observation_quality") == "process_only" and run.get("status") == "active":
                    self.storage.update_run(
                        str(run_id),
                        status="stale",
                        last_seen_at=now,
                        completed_reason="process_disappeared_without_terminal_evidence",
                    )


def process_identity(process: ProcessInfo) -> str:
    stable = f"{process.pid}:{process.started_at or ''}:{process.executable or ''}"
    digest = hashlib.sha256(stable.encode("utf-8")).hexdigest()[:16]
    return f"proc_{process.pid}_{digest}"


def run_identity(process_id: str) -> str:
    digest = hashlib.sha256(process_id.encode("utf-8")).hexdigest()[:24]
    return f"run_passive_{digest}"


def _repo_from_cwd(cwd: str | None) -> str | None:
    if not cwd:
        return None
    path = Path(cwd)
    for candidate in (path, *path.parents):
        if (candidate / ".git").exists():
            return str(candidate)
    return None
