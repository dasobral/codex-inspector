from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .schemas import GitSnapshot


def capture_git_snapshot(
    run_id: str,
    repo_path: str | Path,
    phase: str,
    *,
    include_full_diff: bool = False,
) -> GitSnapshot:
    repo = Path(repo_path).resolve()
    if not repo.exists() or not _is_git_repo(repo):
        return GitSnapshot(
            run_id=run_id,
            phase=phase,
            repo_path=str(repo),
            is_git_repo=False,
            is_dirty=None,
        )
    branch = _git(repo, ["rev-parse", "--abbrev-ref", "HEAD"])
    head = _git(repo, ["rev-parse", "HEAD"])
    status = _git(repo, ["status", "--porcelain"])
    changed_files = _parse_porcelain(status)
    diff_summary = _git(repo, ["diff", "--stat"])
    full_diff = _git(repo, ["diff"]) if include_full_diff else None
    return GitSnapshot(
        run_id=run_id,
        phase=phase,
        repo_path=str(repo),
        is_git_repo=True,
        branch=branch or None,
        head=head or None,
        is_dirty=bool(status.strip()),
        changed_files=changed_files,
        diff_summary=diff_summary or None,
        full_diff=full_diff or None,
    )


def git_available() -> bool:
    return shutil.which("git") is not None


def _is_git_repo(repo: Path) -> bool:
    if not git_available():
        return False
    output = _git(repo, ["rev-parse", "--is-inside-work-tree"])
    return output.strip().lower() == "true"


def _git(repo: Path, args: list[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=repo,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _parse_porcelain(status: str) -> list[str]:
    files: list[str] = []
    for line in status.splitlines():
        if not line:
            continue
        path = line[3:] if len(line) > 3 else line
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        files.append(path)
    return files
