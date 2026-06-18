from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .analyzer import analyze_run
from .correlation import resolve_source_run_id
from .normalizer import diagnostic_event, parse_json_document, parse_jsonl_lines
from .schemas import utc_now
from .storage import Storage

SUPPORTED_SUFFIXES = {".json", ".jsonl", ".txt", ".log"}


def discover_candidate_files(path: str | Path) -> list[Path]:
    target = Path(path).expanduser().resolve()
    if target.is_file():
        return [target] if target.suffix.lower() in SUPPORTED_SUFFIXES else []
    if not target.is_dir():
        return []
    files = [
        file
        for file in target.rglob("*")
        if file.is_file() and file.suffix.lower() in SUPPORTED_SUFFIXES
    ]
    return sorted(files, key=lambda file: (len(file.relative_to(target).parts), str(file)))


def source_identity(path: str | Path) -> str:
    resolved = str(Path(path).expanduser().resolve())
    digest = hashlib.sha256(resolved.encode("utf-8")).hexdigest()[:24]
    return f"src_{digest}"


def run_identity_for_source(path: str | Path) -> str:
    digest = hashlib.sha256(str(Path(path).expanduser().resolve()).encode("utf-8")).hexdigest()[:24]
    return f"run_source_{digest}"


class FileTailer:
    def __init__(self, storage: Storage, *, clock: callable | None = None, preserve_raw: bool = False) -> None:
        self.storage = storage
        self.clock = clock or utc_now
        self.preserve_raw = preserve_raw

    def attach_path(self, path: str | Path, *, run_id: str | None = None) -> list[dict[str, object]]:
        results = []
        for candidate in discover_candidate_files(path):
            results.append(self.tail_file(candidate, run_id=run_id))
        return results

    def tail_known_sources(self) -> list[dict[str, object]]:
        self.storage.init_schema()
        results: list[dict[str, object]] = []
        now = self.clock()
        for source in self.storage.get_observed_sources():
            source_path = source.get("path")
            run_id = str(source.get("run_id")) if source.get("run_id") else None
            if not source_path or not run_id:
                continue
            try:
                results.append(self.tail_file(str(source_path), run_id=run_id))
            except FileNotFoundError:
                updated = dict(source)
                updated["status"] = "missing"
                updated["last_seen_at"] = now
                self.storage.upsert_observed_source(updated)
                self.storage.update_run(
                    run_id,
                    status="stale",
                    last_seen_at=now,
                    completed_reason="source_missing",
                )
                results.append({
                    "source_id": source.get("source_id"),
                    "run_id": run_id,
                    "event_count": 0,
                    "diagnostic_count": 1,
                    "status": "missing",
                })
        return results

    def tail_file(self, path: str | Path, *, run_id: str | None = None) -> dict[str, object]:
        self.storage.init_schema()
        file_path = Path(path).expanduser().resolve()
        if not file_path.exists() or not file_path.is_file():
            raise FileNotFoundError(file_path)
        source_id = source_identity(file_path)
        observed = self.storage.get_observed_source(source_id)
        fallback_run_id = run_identity_for_source(file_path)
        run_id = resolve_source_run_id(
            self.storage,
            file_path,
            explicit_run_id=run_id,
            fallback_run_id=str(observed["run_id"]) if observed and observed.get("run_id") else fallback_run_id,
        )
        now = self.clock()
        existing_run = self.storage.get_run(run_id)
        if not existing_run:
            self.storage.create_run(
                run_id,
                source="observer",
                prompt=f"Passive source observation: {file_path.name}",
                repo_path=str(file_path.parent),
                started_at=now,
                status="active",
                observation_quality="unknown",
                confidence=60,
                last_seen_at=now,
            )
        elif existing_run.get("observation_quality") == "process_only":
            self.storage.update_run(
                run_id,
                observation_quality="passive_partial",
                last_seen_at=now,
            )

        stat = file_path.stat()
        size = stat.st_size
        previous_offset = int((observed or {}).get("cursor_offset") or 0)
        previous_line = int((observed or {}).get("cursor_line") or 0)
        diagnostic_count = int((observed or {}).get("diagnostic_count") or 0)
        events = []
        if previous_offset > size:
            diagnostic_count += 1
            events.append(
                diagnostic_event(
                    run_id,
                    source="passive_tailer",
                    message=f"Observed source was truncated; cursor reset for {file_path}",
                    raw_payload={"source_path": str(file_path), "previous_offset": previous_offset, "new_size": size},
                    tags=["source_truncated", f"source:{source_id}"],
                )
            )
            previous_offset = 0
            previous_line = 0

        with file_path.open("rb") as handle:
            handle.seek(previous_offset)
            chunk = handle.read()
        complete_bytes, complete_line_count = _complete_prefix(chunk)
        new_offset = previous_offset + len(complete_bytes)
        last_event_hash = (observed or {}).get("last_event_hash")
        if complete_bytes:
            text = complete_bytes.decode("utf-8", "replace")
            parsed = self._parse_text(text, file_path, run_id)
            existing_event_ids = {event["event_id"] for event in self.storage.get_events(run_id)}
            for event in parsed:
                if event.event_id in existing_event_ids:
                    continue
                event.tags.extend([f"source:{source_id}", f"source_path:{file_path}", f"cursor:{previous_offset}"])
                events.append(event)
            last_event_hash = hashlib.sha256(complete_bytes.rstrip().splitlines()[-1]).hexdigest() if complete_bytes.rstrip() else last_event_hash

        if events:
            self.storage.insert_events(events)
            self.storage.update_run(
                run_id,
                status="active",
                observation_quality="passive_partial",
                last_seen_at=now,
                last_event_at=now,
            )
            analyze_run(self.storage, run_id)
        else:
            self.storage.update_run(run_id, last_seen_at=now)

        source_row = {
            "source_id": source_id,
            "run_id": run_id,
            "source_kind": _source_kind(file_path),
            "path": str(file_path),
            "file_identity": _file_identity(stat, file_path),
            "cursor_offset": new_offset,
            "cursor_line": previous_line + complete_line_count,
            "last_event_hash": last_event_hash,
            "last_size": size,
            "last_mtime": _mtime_iso(stat.st_mtime),
            "confidence": 80,
            "status": "active" if events else "idle",
            "first_seen_at": (observed or {}).get("first_seen_at") or now,
            "last_seen_at": now,
            "last_ingested_at": now if events else (observed or {}).get("last_ingested_at"),
            "diagnostic_count": diagnostic_count,
        }
        self.storage.upsert_observed_source(source_row)
        return {
            "source_id": source_id,
            "run_id": run_id,
            "event_count": len([event for event in events if event.normalized_event_type != "diagnostic"]),
            "diagnostic_count": len([event for event in events if event.normalized_event_type == "diagnostic"]),
            "cursor_offset": new_offset,
        }

    def _parse_text(self, text: str, path: Path, run_id: str):
        source = "passive_tailer"
        if path.suffix.lower() == ".json":
            return parse_json_document(text, run_id, source=source, preserve_raw=self.preserve_raw)
        return parse_jsonl_lines(text.splitlines(), run_id, source=source, preserve_raw=self.preserve_raw)


def _complete_prefix(chunk: bytes) -> tuple[bytes, int]:
    if not chunk:
        return b"", 0
    if chunk.endswith(b"\n"):
        return chunk, len(chunk.splitlines())
    last_newline = chunk.rfind(b"\n")
    if last_newline == -1:
        return b"", 0
    complete = chunk[: last_newline + 1]
    return complete, len(complete.splitlines())


def _source_kind(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        return "jsonl"
    if suffix == ".json":
        return "json"
    if suffix in {".txt", ".log"}:
        return "transcript"
    return "unknown"


def _file_identity(stat: object, path: Path) -> str:
    device = getattr(stat, "st_dev", None)
    inode = getattr(stat, "st_ino", None)
    if device is not None and inode is not None:
        return f"{device}:{inode}"
    return f"{path}:{getattr(stat, 'st_size', 0)}:{getattr(stat, 'st_mtime', 0)}"


def _mtime_iso(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds")
