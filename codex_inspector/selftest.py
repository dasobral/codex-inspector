from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .git_utils import capture_git_snapshot
from .importer import import_fixture_runs, import_text
from .normalizer import parse_jsonl_lines
from .redaction import redact_payload, redact_text
from .storage import Storage
from .tailer import FileTailer


@dataclass(slots=True)
class SelfTestResult:
    passed: bool
    report: str


def run_self_test() -> SelfTestResult:
    checks: list[tuple[str, bool, str]] = []
    with tempfile.TemporaryDirectory(prefix="codex-inspector-test-") as tmp:
        db_path = Path(tmp) / "inspector.sqlite"
        storage = Storage(db_path)
        storage.init_schema()
        checks.append(("database creation", db_path.exists(), str(db_path)))

        fixture_results = import_fixture_runs(db_path=db_path)
        checks.append(("fixture import", len(fixture_results) >= 4, f"{len(fixture_results)} fixtures"))

        jsonl = "\n".join(
            [
                '{"type":"exec_command","command":"pytest tests","exit_code":0}',
                '{"type":"mystery_event","payload":{"value":42}}',
                'not-json',
                '{"type":"file_write","path":"app.py"}',
            ]
        )
        import_result = import_text(
            jsonl,
            db_path=db_path,
            source_type="self_test_jsonl",
            source_path="inline",
            prompt="self-test import",
        )
        events = storage.get_events(import_result["run_id"])
        checks.append(("Codex JSONL parsing", len(events) >= 5, f"{len(events)} events including wrapper events"))
        checks.append(("malformed line preservation", any(event["normalized_event_type"] == "diagnostic" for event in events), "diagnostic event present"))
        checks.append(("event normalization", any(event["normalized_event_type"] == "shell_command" for event in events), "shell command classified"))
        checks.append(("unknown event preservation", any(event["normalized_event_type"] == "unknown" for event in events), "unknown event classified"))

        parsed = parse_jsonl_lines(['{"type":"exec_command","command":"npm test","exit_code":1}'], "run_self")
        checks.append(("direct parser command extraction", parsed[0].command == "npm test", parsed[0].command or "missing"))

        secret_text = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz password=supersecret"
        checks.append(("redaction text", "supersecret" not in redact_text(secret_text) and "abcdefghijklmnopqrstuvwxyz" not in redact_text(secret_text), redact_text(secret_text)))
        payload = redact_payload({"api_key": "sk-secret", "nested": {"token": "abc"}})
        checks.append(("redaction payload", payload["api_key"] == "[REDACTED]" and payload["nested"]["token"] == "[REDACTED]", str(payload)))

        risky = [result for result in fixture_results if result["analysis"]["risk_score"] > 0]
        checks.append(("risk scoring", bool(risky), f"{len(risky)} risky fixture runs"))

        run_id = fixture_results[0]["run_id"]
        checks.append(("dashboard query functions", bool(storage.get_run(run_id) and storage.get_events(run_id)), run_id))

        git_check, git_detail = _git_snapshot_check(Path(tmp))
        checks.append(("git snapshot logic", git_check, git_detail))

        live_source = Path(tmp) / "live.jsonl"
        live_source.write_text('{"id":"evt_live_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")
        tailer = FileTailer(storage)
        first_tail = tailer.tail_file(live_source)
        live_source.write_text(
            live_source.read_text(encoding="utf-8")
            + '{"id":"evt_live_2","type":"exec_command","command":"python -m unittest discover -s tests","exit_code":0}\n',
            encoding="utf-8",
        )
        second_tail = tailer.tail_file(live_source)
        third_tail = tailer.tail_file(live_source)
        live_run_id = first_tail["run_id"]
        live_events = storage.get_events(str(live_run_id))
        checks.append((
            "passive observation tailing",
            first_tail["event_count"] == 1 and second_tail["event_count"] == 1 and third_tail["event_count"] == 0 and len(live_events) == 2,
            f"{len(live_events)} events; cursors {first_tail['cursor_offset']}->{second_tail['cursor_offset']}",
        ))

    passed = all(check[1] for check in checks)
    lines = ["Codex Run Inspector self-test"]
    for name, ok, detail in checks:
        lines.append(f"{'PASS' if ok else 'FAIL'} {name}: {detail}")
    return SelfTestResult(passed=passed, report="\n".join(lines))


def _git_snapshot_check(tmp: Path) -> tuple[bool, str]:
    if not shutil.which("git"):
        return True, "git unavailable; skipped"
    repo = tmp / "git-repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, capture_output=True, text=True, check=False)
    (repo / "sample.txt").write_text("changed\n", encoding="utf-8")
    snapshot = capture_git_snapshot("run_git_self_test", repo, "before")
    return snapshot.is_git_repo and "sample.txt" in snapshot.changed_files, str(snapshot.changed_files)
