from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.storage import Storage


class ObservationStorageTests(unittest.TestCase):
    def test_schema_adds_v2_run_fields_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            storage.init_schema()

            storage.create_run(
                "run_passive",
                source="observer",
                repo_path="/repo",
                status="active",
                observation_quality="process_only",
                confidence=92,
                last_seen_at="2026-06-12T10:00:00+00:00",
                last_event_at=None,
            )

            run = storage.get_run("run_passive")
            self.assertIsNotNone(run)
            self.assertEqual(run["observation_quality"], "process_only")
            self.assertEqual(run["confidence"], 92)
            self.assertEqual(run["last_seen_at"], "2026-06-12T10:00:00+00:00")

    def test_observed_process_upsert_and_active_listing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            storage.create_run(
                "run_proc",
                source="observer",
                status="active",
                observation_quality="process_only",
                confidence=88,
                last_seen_at="2026-06-12T10:00:00+00:00",
            )

            storage.upsert_observed_process(
                {
                    "process_id": "proc_1",
                    "run_id": "run_proc",
                    "pid": 123,
                    "pid_start_time": "start-1",
                    "command_line": "codex exec --json",
                    "cwd": "/repo",
                    "repo_path": "/repo",
                    "detected_kind": "codex_exec",
                    "confidence": 95,
                    "status": "active",
                    "first_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_error": None,
                }
            )
            storage.upsert_observed_process(
                {
                    "process_id": "proc_1",
                    "run_id": "run_proc",
                    "pid": 123,
                    "pid_start_time": "start-1",
                    "command_line": "codex exec --json",
                    "cwd": "/repo",
                    "repo_path": "/repo",
                    "detected_kind": "codex_exec",
                    "confidence": 95,
                    "status": "missing",
                    "first_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_seen_at": "2026-06-12T10:01:00+00:00",
                    "last_error": "gone",
                }
            )

            process = storage.get_observed_process("proc_1")
            self.assertIsNotNone(process)
            self.assertEqual(process["status"], "missing")
            self.assertEqual(process["last_seen_at"], "2026-06-12T10:01:00+00:00")
            active_runs = storage.list_observed_runs(statuses=["active"])
            self.assertEqual([run["run_id"] for run in active_runs], ["run_proc"])

    def test_observed_source_cursor_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            storage.create_run(
                "run_source",
                source="observer",
                status="active",
                observation_quality="passive_partial",
            )

            storage.upsert_observed_source(
                {
                    "source_id": "src_1",
                    "run_id": "run_source",
                    "source_kind": "jsonl",
                    "path": "/tmp/session.jsonl",
                    "file_identity": "dev:ino",
                    "cursor_offset": 12,
                    "cursor_line": 1,
                    "last_event_hash": "abc",
                    "last_size": 24,
                    "last_mtime": "2026-06-12T10:00:00+00:00",
                    "confidence": 80,
                    "status": "active",
                    "first_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_ingested_at": "2026-06-12T10:00:00+00:00",
                    "diagnostic_count": 0,
                }
            )
            storage.upsert_observed_source(
                {
                    "source_id": "src_1",
                    "run_id": "run_source",
                    "source_kind": "jsonl",
                    "path": "/tmp/session.jsonl",
                    "file_identity": "dev:ino",
                    "cursor_offset": 40,
                    "cursor_line": 2,
                    "last_event_hash": "def",
                    "last_size": 40,
                    "last_mtime": "2026-06-12T10:00:01+00:00",
                    "confidence": 80,
                    "status": "idle",
                    "first_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_seen_at": "2026-06-12T10:00:01+00:00",
                    "last_ingested_at": "2026-06-12T10:00:01+00:00",
                    "diagnostic_count": 1,
                }
            )

            source = storage.get_observed_source("src_1")
            self.assertIsNotNone(source)
            self.assertEqual(source["cursor_offset"], 40)
            self.assertEqual(source["cursor_line"], 2)
            self.assertEqual(source["diagnostic_count"], 1)
            self.assertEqual(len(storage.get_observed_sources("run_source")), 1)


if __name__ == "__main__":
    unittest.main()
