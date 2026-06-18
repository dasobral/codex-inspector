from __future__ import annotations

from pathlib import Path
from typing import Any

from .analyzer import analyze_run
from .fixtures import fixture_files
from .normalizer import parse_json_document, parse_jsonl_lines, wrapper_event
from .schemas import new_id, utc_now
from .storage import Storage


def import_jsonl_file(
    path: str | Path,
    *,
    db_path: str | Path | None = None,
    source_type: str = "jsonl",
    repo_path: str | None = None,
    prompt: str | None = None,
    preserve_raw: bool = False,
) -> dict[str, Any]:
    file_path = Path(path).expanduser().resolve()
    if not file_path.exists():
        raise FileNotFoundError(file_path)
    text = file_path.read_text(encoding="utf-8")
    return import_text(
        text,
        db_path=db_path,
        source_type=source_type,
        source_path=str(file_path),
        repo_path=repo_path,
        prompt=prompt or f"Imported {file_path.name}",
        preserve_raw=preserve_raw,
        parse_as_json=file_path.suffix.lower() == ".json",
    )


def import_text(
    text: str,
    *,
    db_path: str | Path | None = None,
    source_type: str,
    source_path: str | None,
    repo_path: str | None = None,
    prompt: str | None = None,
    preserve_raw: bool = False,
    parse_as_json: bool = False,
) -> dict[str, Any]:
    storage = Storage(db_path)
    storage.init_schema()
    run_id = new_id("run")
    import_id = new_id("imp")
    started_at = utc_now()
    storage.create_run(
        run_id,
        source=source_type,
        prompt=prompt,
        repo_path=repo_path,
        started_at=started_at,
        status="imported",
        observation_quality="imported_full",
        confidence=100,
        last_seen_at=started_at,
        last_event_at=started_at,
        completed_reason="import_finished",
    )
    start = wrapper_event(
        run_id,
        "run_started",
        source="codex_inspector_importer",
        repo_root=repo_path,
        raw_payload={"source_type": source_type, "source_path": source_path},
    )
    if parse_as_json:
        events = parse_json_document(text, run_id, source=source_type, repo_root=repo_path, preserve_raw=preserve_raw)
    else:
        events = parse_jsonl_lines(text.splitlines(), run_id, source=source_type, repo_root=repo_path, preserve_raw=preserve_raw)
    finish = wrapper_event(
        run_id,
        "run_finished",
        source="codex_inspector_importer",
        repo_root=repo_path,
        raw_payload={"source_type": source_type, "source_path": source_path, "event_count": len(events)},
    )
    storage.insert_events([start, *events, finish])
    diagnostic_count = len([event for event in events if event.normalized_event_type == "diagnostic"])
    storage.record_import(
        import_id=import_id,
        source_type=source_type,
        source_path=source_path,
        run_id=run_id,
        event_count=len(events),
        diagnostic_count=diagnostic_count,
    )
    analysis = analyze_run(storage, run_id)
    finished_at = utc_now()
    storage.update_run(run_id, finished_at=finished_at, status="imported", last_seen_at=finished_at, last_event_at=finished_at, completed_reason="import_finished")
    return {
        "run_id": run_id,
        "import_id": import_id,
        "source_path": source_path,
        "event_count": len(events),
        "diagnostic_count": diagnostic_count,
        "analysis": analysis,
        "db_path": str(storage.db_path),
    }


def import_fixture_runs(*, db_path: str | Path | None = None) -> list[dict[str, Any]]:
    results = []
    for fixture in fixture_files():
        results.append(
            import_jsonl_file(
                fixture,
                db_path=db_path,
                source_type="synthetic_fixture",
                prompt=f"Synthetic fixture: {fixture.stem.replace('_', ' ')}",
            )
        )
    return results


def import_transcript_path(
    path: str | Path,
    *,
    db_path: str | Path | None = None,
    preserve_raw: bool = False,
) -> list[dict[str, Any]]:
    target = Path(path).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    candidates: list[Path]
    if target.is_dir():
        candidates = sorted(
            file
            for file in target.rglob("*")
            if file.is_file() and file.suffix.lower() in {".json", ".jsonl", ".txt", ".log"}
        )
    else:
        candidates = [target]
    results = []
    for candidate in candidates:
        results.append(
            import_jsonl_file(
                candidate,
                db_path=db_path,
                source_type="transcript",
                prompt=f"Best-effort transcript import: {candidate.name}",
                preserve_raw=preserve_raw,
            )
        )
    return results
