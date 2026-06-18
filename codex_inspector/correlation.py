from __future__ import annotations

from pathlib import Path

from .storage import Storage


def find_run_id_for_source_path(storage: Storage, file_path: str | Path) -> str | None:
    resolved = Path(file_path).expanduser().resolve()
    best_run_id: str | None = None
    best_base_len = -1
    for process in storage.get_observed_processes():
        if process.get("status") not in {"active", "unknown", None}:
            continue
        for base_str in (process.get("repo_path"), process.get("cwd")):
            if not base_str:
                continue
            base = Path(base_str).expanduser().resolve()
            try:
                resolved.relative_to(base)
            except ValueError:
                continue
            base_len = len(str(base))
            if base_len > best_base_len:
                best_base_len = base_len
                run_id = process.get("run_id")
                if run_id:
                    best_run_id = str(run_id)
    return best_run_id


def resolve_source_run_id(
    storage: Storage,
    file_path: str | Path,
    *,
    explicit_run_id: str | None = None,
    fallback_run_id: str,
) -> str:
    if explicit_run_id:
        return explicit_run_id
    correlated = find_run_id_for_source_path(storage, file_path)
    if correlated:
        return correlated
    return fallback_run_id


def reassign_source_run(storage: Storage, source_id: str, new_run_id: str) -> None:
    source = storage.get_observed_source(source_id)
    if not source or source.get("run_id") == new_run_id:
        return
    updated = dict(source)
    updated["run_id"] = new_run_id
    storage.upsert_observed_source(updated)
