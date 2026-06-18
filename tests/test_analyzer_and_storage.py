from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.analyzer import build_findings
from codex_inspector.observer import CodexObserver, ProcessInfo, StaticProcessProvider
from codex_inspector.storage import Storage


class AnalyzerFindingsTests(unittest.TestCase):
    def test_destructive_command_finding(self) -> None:
        findings = build_findings(
            {"run_id": "run_1"},
            [],
            [{"event_id": "evt_1", "command": "rm -rf ./build", "exit_code": 0}],
            [],
            [],
        )
        categories = {finding.category for finding in findings}
        self.assertIn("destructive_command", categories)

    def test_sensitive_file_finding(self) -> None:
        findings = build_findings(
            {"run_id": "run_1", "repo_path": "/repo"},
            [],
            [],
            [{"event_id": "evt_1", "path": ".env", "access_type": "write"}],
            [],
        )
        categories = {finding.category for finding in findings}
        self.assertIn("sensitive_file", categories)

    def test_sandbox_block_finding(self) -> None:
        findings = build_findings(
            {"run_id": "run_1"},
            [
                {
                    "event_id": "evt_1",
                    "normalized_event_type": "sandbox_event",
                    "error_message": "sandbox blocked destructive delete",
                    "raw_payload": {},
                }
            ],
            [],
            [],
            [],
        )
        categories = {finding.category for finding in findings}
        self.assertIn("sandbox", categories)

    def test_missing_tests_finding(self) -> None:
        findings = build_findings(
            {"run_id": "run_1"},
            [],
            [],
            [{"event_id": "evt_1", "path": "src/app.py", "access_type": "write"}],
            [],
        )
        categories = {finding.category for finding in findings}
        self.assertIn("missing_tests", categories)

    def test_approval_denied_finding(self) -> None:
        findings = build_findings(
            {"run_id": "run_1"},
            [{"event_id": "evt_1", "normalized_event_type": "approval_denied"}],
            [],
            [],
            [],
        )
        categories = {finding.category for finding in findings}
        self.assertIn("approval", categories)


class StorageDedupTests(unittest.TestCase):
    def test_reinserting_command_event_does_not_duplicate_commands(self) -> None:
        from codex_inspector.normalizer import parse_jsonl_lines
        from codex_inspector.schemas import NormalizedEvent

        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            storage.create_run("run_1", source="test", status="active")
            events = parse_jsonl_lines(
                ['{"id":"evt_cmd","type":"exec_command","command":"pytest","exit_code":0}'],
                "run_1",
                source="test",
            )
            storage.insert_events(events)
            storage.insert_events(events)
            self.assertEqual(len(storage.get_commands("run_1")), 1)


class ObserverLifecycleTests(unittest.TestCase):
    def test_missing_process_marks_process_only_run_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            process = ProcessInfo(
                pid=201,
                command_line=("codex", "exec", "--json"),
                cwd=str(Path(tmp)),
                started_at="start-201",
                executable="codex",
            )
            observer = CodexObserver(
                storage,
                process_provider=StaticProcessProvider([process]),
                clock=lambda: "2026-06-12T10:00:00+00:00",
            )
            discovered = observer.discover()
            run_id = str(discovered[0]["run_id"])

            observer.process_provider = StaticProcessProvider([])
            observer.discover()

            run = storage.get_run(run_id)
            self.assertEqual(run["status"], "stale")
            stored_process = storage.get_observed_process(discovered[0]["process_id"])
            self.assertEqual(stored_process["status"], "missing")


class CorrelationTests(unittest.TestCase):
    def test_source_correlates_to_active_process_run(self) -> None:
        from codex_inspector.correlation import find_run_id_for_source_path
        from codex_inspector.tailer import FileTailer

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")
            storage = Storage(db_path)
            storage.init_schema()
            process = ProcessInfo(
                pid=301,
                command_line=("codex", "exec", "--json"),
                cwd=str(root),
                started_at="start-301",
                executable="codex",
            )
            observer = CodexObserver(
                storage,
                process_provider=StaticProcessProvider([process]),
                clock=lambda: "2026-06-12T10:00:00+00:00",
            )
            discovered = observer.discover()
            process_run_id = str(discovered[0]["run_id"])

            correlated = find_run_id_for_source_path(storage, source)
            self.assertEqual(correlated, process_run_id)

            tailer = FileTailer(storage, clock=lambda: "2026-06-12T10:00:00+00:00")
            result = tailer.tail_file(source)
            self.assertEqual(result["run_id"], process_run_id)
            run = storage.get_run(process_run_id)
            self.assertEqual(run["observation_quality"], "passive_partial")


if __name__ == "__main__":
    unittest.main()
