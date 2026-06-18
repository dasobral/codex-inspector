from __future__ import annotations

from importlib import resources
from pathlib import Path


def fixture_files() -> list[Path]:
    package_root = resources.files(__package__) / "sample_fixtures"
    return sorted(Path(str(path)) for path in package_root.iterdir() if str(path).endswith(".jsonl"))


def fixture_names() -> list[str]:
    return [path.name for path in fixture_files()]
