from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .schemas import Finding, GitSnapshot, NormalizedEvent, utc_now


def default_db_path() -> Path:
    configured = os.environ.get("CODEX_INSPECTOR_DB")
    if configured:
        return Path(configured).expanduser()
    return Path.cwd() / ".codex-inspector" / "codex-inspector.sqlite"


class Storage:
    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path = self.db_path.expanduser()

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    run_id TEXT PRIMARY KEY,
                    source TEXT,
                    prompt TEXT,
                    repo_path TEXT,
                    started_at TEXT,
                    finished_at TEXT,
                    status TEXT,
                    observation_quality TEXT DEFAULT 'unknown',
                    confidence INTEGER DEFAULT 0,
                    last_seen_at TEXT,
                    last_event_at TEXT,
                    completed_reason TEXT,
                    codex_exit_code INTEGER,
                    event_count INTEGER DEFAULT 0,
                    command_count INTEGER DEFAULT 0,
                    file_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    high_risk_count INTEGER DEFAULT 0,
                    summary TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    schema_version TEXT,
                    session_id TEXT,
                    turn_id TEXT,
                    parent_event_id TEXT,
                    timestamp TEXT,
                    source TEXT,
                    source_event_type TEXT,
                    normalized_event_type TEXT,
                    actor TEXT,
                    cwd TEXT,
                    repo_root TEXT,
                    git_branch TEXT,
                    git_head_before TEXT,
                    git_head_after TEXT,
                    model TEXT,
                    approval_mode TEXT,
                    sandbox_mode TEXT,
                    tool_name TEXT,
                    command TEXT,
                    command_exit_code INTEGER,
                    command_stdout_summary TEXT,
                    command_stderr_summary TEXT,
                    file_paths_read TEXT,
                    file_paths_written TEXT,
                    files_changed_after_run TEXT,
                    diff_summary TEXT,
                    approval_status TEXT,
                    error_type TEXT,
                    error_message TEXT,
                    duration_ms INTEGER,
                    token_count_input INTEGER,
                    token_count_output INTEGER,
                    estimated_cost REAL,
                    risk_level TEXT,
                    tags TEXT,
                    raw_payload TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS commands (
                    command_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    timestamp TEXT,
                    command TEXT,
                    exit_code INTEGER,
                    stdout_summary TEXT,
                    stderr_summary TEXT,
                    risk_level TEXT,
                    duration_ms INTEGER,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
                    FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS files_touched (
                    file_touch_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    event_id TEXT,
                    path TEXT NOT NULL,
                    access_type TEXT NOT NULL,
                    sensitive INTEGER DEFAULT 0,
                    attribution TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS git_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    repo_path TEXT,
                    is_git_repo INTEGER,
                    branch TEXT,
                    head TEXT,
                    is_dirty INTEGER,
                    changed_files TEXT,
                    diff_summary TEXT,
                    full_diff TEXT,
                    captured_at TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_event_id TEXT,
                    recommended_action TEXT NOT NULL,
                    category TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS imports (
                    import_id TEXT PRIMARY KEY,
                    source_type TEXT NOT NULL,
                    source_path TEXT,
                    run_id TEXT NOT NULL,
                    imported_at TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    diagnostic_count INTEGER NOT NULL,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS observed_processes (
                    process_id TEXT PRIMARY KEY,
                    run_id TEXT,
                    pid INTEGER NOT NULL,
                    pid_start_time TEXT,
                    command_line TEXT,
                    cwd TEXT,
                    repo_path TEXT,
                    detected_kind TEXT,
                    confidence INTEGER DEFAULT 0,
                    status TEXT,
                    first_seen_at TEXT,
                    last_seen_at TEXT,
                    last_error TEXT,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS observed_sources (
                    source_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    source_kind TEXT,
                    path TEXT,
                    file_identity TEXT,
                    cursor_offset INTEGER DEFAULT 0,
                    cursor_line INTEGER DEFAULT 0,
                    last_event_hash TEXT,
                    last_size INTEGER DEFAULT 0,
                    last_mtime TEXT,
                    confidence INTEGER DEFAULT 0,
                    status TEXT,
                    first_seen_at TEXT,
                    last_seen_at TEXT,
                    last_ingested_at TEXT,
                    diagnostic_count INTEGER DEFAULT 0,
                    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_events_run_time ON events(run_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(normalized_event_type);
                CREATE INDEX IF NOT EXISTS idx_commands_run ON commands(run_id);
                CREATE INDEX IF NOT EXISTS idx_files_run ON files_touched(run_id);
                CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
                CREATE INDEX IF NOT EXISTS idx_runs_status_seen ON runs(status, last_seen_at);
                CREATE INDEX IF NOT EXISTS idx_runs_quality_status ON runs(observation_quality, status);
                CREATE INDEX IF NOT EXISTS idx_observed_processes_pid ON observed_processes(pid, pid_start_time);
                CREATE INDEX IF NOT EXISTS idx_observed_processes_run ON observed_processes(run_id);
                CREATE INDEX IF NOT EXISTS idx_observed_sources_run ON observed_sources(run_id);
                CREATE INDEX IF NOT EXISTS idx_observed_sources_path ON observed_sources(path);
                """
            )
            _ensure_unique_index(conn, "idx_commands_run_event", "commands", "run_id, event_id")
            _ensure_unique_index(
                conn,
                "idx_files_touched_run_event_path",
                "files_touched",
                "run_id, event_id, path, access_type",
            )
            for column, definition in (
                ("observation_quality", "TEXT DEFAULT 'unknown'"),
                ("confidence", "INTEGER DEFAULT 0"),
                ("last_seen_at", "TEXT"),
                ("last_event_at", "TEXT"),
                ("completed_reason", "TEXT"),
            ):
                _ensure_column(conn, "runs", column, definition)

    def create_run(
        self,
        run_id: str,
        *,
        source: str,
        prompt: str | None = None,
        repo_path: str | None = None,
        started_at: str | None = None,
        status: str = "created",
        observation_quality: str = "unknown",
        confidence: int | None = 0,
        last_seen_at: str | None = None,
        last_event_at: str | None = None,
        completed_reason: str | None = None,
    ) -> None:
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, source, prompt, repo_path, started_at, status,
                    observation_quality, confidence, last_seen_at, last_event_at,
                    completed_reason, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    source=excluded.source,
                    prompt=excluded.prompt,
                    repo_path=excluded.repo_path,
                    started_at=COALESCE(excluded.started_at, runs.started_at),
                    status=excluded.status,
                    observation_quality=CASE
                        WHEN runs.observation_quality IN ('passive_partial', 'wrapped_full', 'imported_full')
                        THEN runs.observation_quality
                        ELSE excluded.observation_quality
                    END,
                    confidence=excluded.confidence,
                    last_seen_at=COALESCE(excluded.last_seen_at, runs.last_seen_at),
                    last_event_at=COALESCE(excluded.last_event_at, runs.last_event_at),
                    completed_reason=COALESCE(excluded.completed_reason, runs.completed_reason),
                    updated_at=excluded.updated_at
                """,
                (
                    run_id,
                    source,
                    prompt,
                    repo_path,
                    started_at,
                    status,
                    observation_quality,
                    confidence,
                    last_seen_at,
                    last_event_at,
                    completed_reason,
                    now,
                    now,
                ),
            )

    def update_run(self, run_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = utc_now()
        allowed = {
            "source",
            "prompt",
            "repo_path",
            "started_at",
            "finished_at",
            "status",
            "observation_quality",
            "confidence",
            "last_seen_at",
            "last_event_at",
            "completed_reason",
            "codex_exit_code",
            "event_count",
            "command_count",
            "file_count",
            "failure_count",
            "risk_score",
            "high_risk_count",
            "summary",
            "updated_at",
        }
        assignments = []
        values = []
        for key, value in fields.items():
            if key not in allowed:
                continue
            assignments.append(f"{key} = ?")
            values.append(value)
        if not assignments:
            return
        values.append(run_id)
        with self.connect() as conn:
            conn.execute(f"UPDATE runs SET {', '.join(assignments)} WHERE run_id = ?", values)

    def insert_events(self, events: list[NormalizedEvent]) -> None:
        if not events:
            return
        with self.connect() as conn:
            conn.execute("BEGIN")
            for event in events:
                row = _event_row(event)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO events (
                        schema_version, event_id, run_id, session_id, turn_id, parent_event_id,
                        timestamp, source, source_event_type, normalized_event_type, actor, cwd,
                        repo_root, git_branch, git_head_before, git_head_after, model,
                        approval_mode, sandbox_mode, tool_name, command, command_exit_code,
                        command_stdout_summary, command_stderr_summary, file_paths_read,
                        file_paths_written, files_changed_after_run, diff_summary,
                        approval_status, error_type, error_message, duration_ms,
                        token_count_input, token_count_output, estimated_cost, risk_level,
                        tags, raw_payload
                    ) VALUES (
                        :schema_version, :event_id, :run_id, :session_id, :turn_id,
                        :parent_event_id, :timestamp, :source, :source_event_type,
                        :normalized_event_type, :actor, :cwd, :repo_root, :git_branch,
                        :git_head_before, :git_head_after, :model, :approval_mode,
                        :sandbox_mode, :tool_name, :command, :command_exit_code,
                        :command_stdout_summary, :command_stderr_summary, :file_paths_read,
                        :file_paths_written, :files_changed_after_run, :diff_summary,
                        :approval_status, :error_type, :error_message, :duration_ms,
                        :token_count_input, :token_count_output, :estimated_cost,
                        :risk_level, :tags, :raw_payload
                    )
                    """,
                    row,
                )
                if event.command or event.normalized_event_type == "shell_command":
                    conn.execute(
                        "DELETE FROM commands WHERE run_id = ? AND event_id = ?",
                        (event.run_id, event.event_id),
                    )
                    conn.execute(
                        """
                        INSERT INTO commands (
                            run_id, event_id, timestamp, command, exit_code, stdout_summary,
                            stderr_summary, risk_level, duration_ms
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            event.run_id,
                            event.event_id,
                            event.timestamp,
                            event.command,
                            event.command_exit_code,
                            event.command_stdout_summary,
                            event.command_stderr_summary,
                            event.risk_level,
                            event.duration_ms,
                        ),
                    )
                if (
                    event.file_paths_read
                    or event.file_paths_written
                    or event.files_changed_after_run
                ):
                    conn.execute(
                        "DELETE FROM files_touched WHERE run_id = ? AND event_id = ?",
                        (event.run_id, event.event_id),
                    )
                for path in event.file_paths_read:
                    conn.execute(
                        """
                        INSERT INTO files_touched (run_id, event_id, path, access_type, sensitive, attribution)
                        VALUES (?, ?, ?, 'read', ?, 'observable_event')
                        """,
                        (event.run_id, event.event_id, path, int(is_sensitive_path(path))),
                    )
                for path in event.file_paths_written:
                    conn.execute(
                        """
                        INSERT INTO files_touched (run_id, event_id, path, access_type, sensitive, attribution)
                        VALUES (?, ?, ?, 'write', ?, 'observable_event')
                        """,
                        (event.run_id, event.event_id, path, int(is_sensitive_path(path))),
                    )
                for path in event.files_changed_after_run:
                    conn.execute(
                        """
                        INSERT INTO files_touched (run_id, event_id, path, access_type, sensitive, attribution)
                        VALUES (?, ?, ?, 'changed_after_run', ?, 'git_after_snapshot')
                        """,
                        (event.run_id, event.event_id, path, int(is_sensitive_path(path))),
                    )
            conn.commit()

    def add_git_snapshot(self, snapshot: GitSnapshot | dict[str, Any]) -> None:
        data = _as_dict(snapshot)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO git_snapshots (
                    run_id, phase, repo_path, is_git_repo, branch, head, is_dirty,
                    changed_files, diff_summary, full_diff, captured_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    data["run_id"],
                    data["phase"],
                    data.get("repo_path"),
                    int(bool(data.get("is_git_repo"))),
                    data.get("branch"),
                    data.get("head"),
                    None if data.get("is_dirty") is None else int(bool(data.get("is_dirty"))),
                    _json(data.get("changed_files", [])),
                    data.get("diff_summary"),
                    data.get("full_diff"),
                    data.get("captured_at") or utc_now(),
                ),
            )
            for path in data.get("changed_files", []):
                conn.execute(
                    """
                    INSERT INTO files_touched (run_id, event_id, path, access_type, sensitive, attribution)
                    VALUES (?, NULL, ?, ?, ?, ?)
                    """,
                    (
                        data["run_id"],
                        path,
                        f"git_{data['phase']}",
                        int(is_sensitive_path(path)),
                        "git_snapshot",
                    ),
                )

    def replace_findings(self, run_id: str, findings: list[Finding]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
            conn.executemany(
                """
                INSERT INTO findings (
                    run_id, severity, reason, evidence_event_id, recommended_action, category, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        finding.run_id,
                        finding.severity,
                        finding.reason,
                        finding.evidence_event_id,
                        finding.recommended_action,
                        finding.category,
                        utc_now(),
                    )
                    for finding in findings
                ],
            )

    def record_import(
        self,
        *,
        import_id: str,
        source_type: str,
        source_path: str | None,
        run_id: str,
        event_count: int,
        diagnostic_count: int,
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO imports (
                    import_id, source_type, source_path, run_id, imported_at, event_count, diagnostic_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (import_id, source_type, source_path, run_id, utc_now(), event_count, diagnostic_count),
            )

    def upsert_observed_process(self, process: dict[str, Any]) -> None:
        data = dict(process)
        now = utc_now()
        data.setdefault("run_id", None)
        data.setdefault("pid_start_time", None)
        data.setdefault("command_line", None)
        data.setdefault("cwd", None)
        data.setdefault("repo_path", None)
        data.setdefault("detected_kind", "unknown")
        data.setdefault("first_seen_at", now)
        data.setdefault("last_seen_at", now)
        data.setdefault("confidence", 0)
        data.setdefault("status", "unknown")
        data.setdefault("last_error", None)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO observed_processes (
                    process_id, run_id, pid, pid_start_time, command_line, cwd, repo_path,
                    detected_kind, confidence, status, first_seen_at, last_seen_at, last_error
                ) VALUES (
                    :process_id, :run_id, :pid, :pid_start_time, :command_line, :cwd,
                    :repo_path, :detected_kind, :confidence, :status, :first_seen_at,
                    :last_seen_at, :last_error
                )
                ON CONFLICT(process_id) DO UPDATE SET
                    run_id=excluded.run_id,
                    pid=excluded.pid,
                    pid_start_time=excluded.pid_start_time,
                    command_line=excluded.command_line,
                    cwd=excluded.cwd,
                    repo_path=excluded.repo_path,
                    detected_kind=excluded.detected_kind,
                    confidence=excluded.confidence,
                    status=excluded.status,
                    first_seen_at=COALESCE(observed_processes.first_seen_at, excluded.first_seen_at),
                    last_seen_at=excluded.last_seen_at,
                    last_error=excluded.last_error
                """,
                data,
            )

    def get_observed_process(self, process_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM observed_processes WHERE process_id = ?",
                (process_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_observed_process_by_pid(self, pid: int, pid_start_time: str | None = None) -> dict[str, Any] | None:
        query = "SELECT * FROM observed_processes WHERE pid = ?"
        values: list[Any] = [pid]
        if pid_start_time is not None:
            query += " AND pid_start_time = ?"
            values.append(pid_start_time)
        query += " ORDER BY last_seen_at DESC LIMIT 1"
        with self.connect() as conn:
            row = conn.execute(query, values).fetchone()
        return dict(row) if row else None

    def get_observed_processes(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observed_processes"
        values: list[Any] = []
        if run_id is not None:
            query += " WHERE run_id = ?"
            values.append(run_id)
        query += " ORDER BY last_seen_at DESC, process_id"
        with self.connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def upsert_observed_source(self, source: dict[str, Any]) -> None:
        data = dict(source)
        now = utc_now()
        data.setdefault("source_kind", "unknown")
        data.setdefault("path", None)
        data.setdefault("file_identity", None)
        data.setdefault("first_seen_at", now)
        data.setdefault("last_seen_at", now)
        data.setdefault("cursor_offset", 0)
        data.setdefault("cursor_line", 0)
        data.setdefault("last_event_hash", None)
        data.setdefault("last_size", 0)
        data.setdefault("last_mtime", None)
        data.setdefault("confidence", 0)
        data.setdefault("status", "unknown")
        data.setdefault("last_ingested_at", None)
        data.setdefault("diagnostic_count", 0)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO observed_sources (
                    source_id, run_id, source_kind, path, file_identity, cursor_offset,
                    cursor_line, last_event_hash, last_size, last_mtime, confidence,
                    status, first_seen_at, last_seen_at, last_ingested_at, diagnostic_count
                ) VALUES (
                    :source_id, :run_id, :source_kind, :path, :file_identity,
                    :cursor_offset, :cursor_line, :last_event_hash, :last_size,
                    :last_mtime, :confidence, :status, :first_seen_at, :last_seen_at,
                    :last_ingested_at, :diagnostic_count
                )
                ON CONFLICT(source_id) DO UPDATE SET
                    run_id=excluded.run_id,
                    source_kind=excluded.source_kind,
                    path=excluded.path,
                    file_identity=excluded.file_identity,
                    cursor_offset=excluded.cursor_offset,
                    cursor_line=excluded.cursor_line,
                    last_event_hash=excluded.last_event_hash,
                    last_size=excluded.last_size,
                    last_mtime=excluded.last_mtime,
                    confidence=excluded.confidence,
                    status=excluded.status,
                    first_seen_at=COALESCE(observed_sources.first_seen_at, excluded.first_seen_at),
                    last_seen_at=excluded.last_seen_at,
                    last_ingested_at=excluded.last_ingested_at,
                    diagnostic_count=excluded.diagnostic_count
                """,
                data,
            )

    def get_observed_source(self, source_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM observed_sources WHERE source_id = ?",
                (source_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_observed_source_by_path(self, path: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM observed_sources WHERE path = ? ORDER BY last_seen_at DESC LIMIT 1",
                (path,),
            ).fetchone()
        return dict(row) if row else None

    def get_observed_sources(self, run_id: str | None = None) -> list[dict[str, Any]]:
        query = "SELECT * FROM observed_sources"
        values: list[Any] = []
        if run_id is not None:
            query += " WHERE run_id = ?"
            values.append(run_id)
        query += " ORDER BY last_seen_at DESC, source_id"
        with self.connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def list_observed_runs(self, statuses: list[str] | None = None, limit: int = 100) -> list[dict[str, Any]]:
        query = "SELECT * FROM runs"
        values: list[Any] = []
        if statuses:
            placeholders = ", ".join("?" for _ in statuses)
            query += f" WHERE status IN ({placeholders})"
            values.extend(statuses)
        query += " ORDER BY COALESCE(last_seen_at, last_event_at, started_at, created_at) DESC LIMIT ?"
        values.append(limit)
        with self.connect() as conn:
            rows = conn.execute(query, values).fetchall()
        return [dict(row) for row in rows]

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runs
                ORDER BY COALESCE(started_at, created_at) DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def get_events(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE run_id = ? ORDER BY timestamp, rowid",
                (run_id,),
            ).fetchall()
        return [_decode_event_row(row) for row in rows]

    def get_commands(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM commands WHERE run_id = ? ORDER BY timestamp, command_id",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_files(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM files_touched WHERE run_id = ? ORDER BY path, access_type",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_git_snapshots(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM git_snapshots WHERE run_id = ? ORDER BY snapshot_id",
                (run_id,),
            ).fetchall()
        snapshots = []
        for row in rows:
            data = dict(row)
            data["changed_files"] = _loads(data.get("changed_files"), [])
            snapshots.append(data)
        return snapshots

    def get_findings(self, run_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM findings
                WHERE run_id = ?
                ORDER BY CASE severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'warning' THEN 2
                    ELSE 3
                END, finding_id
                """,
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _ensure_unique_index(conn: sqlite3.Connection, index_name: str, table: str, columns: str) -> None:
    conn.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table} ({columns})")


def is_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    sensitive_terms = (
        ".env",
        "credential",
        "private_key",
        "id_rsa",
        ".ssh/",
        "dockerfile",
        ".github/workflows",
        ".gitlab-ci",
        "deploy",
        "auth",
        "security",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "poetry.lock",
        "cargo.lock",
    )
    return any(term in lowered for term in sensitive_terms)


def _event_row(event: NormalizedEvent) -> dict[str, Any]:
    data = _as_dict(event)
    for key in ("file_paths_read", "file_paths_written", "files_changed_after_run", "tags", "raw_payload"):
        data[key] = _json(data.get(key))
    return data


def _decode_event_row(row: sqlite3.Row) -> dict[str, Any]:
    data = dict(row)
    for key in ("file_paths_read", "file_paths_written", "files_changed_after_run", "tags"):
        data[key] = _loads(data.get(key), [])
    data["raw_payload"] = _loads(data.get("raw_payload"), {})
    return data


def _as_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if is_dataclass(value):
        return asdict(value)
    raise TypeError(f"Expected dataclass or dict, got {type(value)!r}")


def _json(value: Any) -> str:
    return json.dumps(value if value is not None else [], sort_keys=True)


def _loads(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default
