from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.cli import main
from codex_inspector.lifecycle import apply_lifecycle_transitions
from codex_inspector.storage import Storage


class DiscoverCandidateTests(unittest.TestCase):
    def test_discover_lists_candidate_files_without_attaching(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")

            exit_code = main(["--db", str(db_path), "discover", "--candidate-dir", str(root)])

            self.assertEqual(exit_code, 0)
            storage = Storage(db_path)
            self.assertEqual(storage.list_runs(), [])

    def test_discover_attach_candidates_imports_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")

            exit_code = main(
                ["--db", str(db_path), "discover", "--candidate-dir", str(root), "--attach-candidates"]
            )

            self.assertEqual(exit_code, 0)
            storage = Storage(db_path)
            passive_runs = [run for run in storage.list_runs() if run.get("observation_quality") == "passive_partial"]
            self.assertEqual(len(passive_runs), 1)


class LifecycleTransitionTests(unittest.TestCase):
    def test_passive_partial_completes_after_terminal_event_and_idle_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            storage.create_run(
                "run_passive",
                source="observer",
                status="active",
                observation_quality="passive_partial",
                last_seen_at="2026-06-12T10:00:00+00:00",
            )
            storage.upsert_observed_source(
                {
                    "source_id": "src_1",
                    "run_id": "run_passive",
                    "source_kind": "jsonl",
                    "path": str(Path(tmp) / "session.jsonl"),
                    "cursor_offset": 100,
                    "last_size": 100,
                    "status": "idle",
                    "first_seen_at": "2026-06-12T10:00:00+00:00",
                    "last_seen_at": "2026-06-12T09:00:00+00:00",
                    "last_ingested_at": "2026-06-12T09:00:00+00:00",
                }
            )
            from codex_inspector.normalizer import wrapper_event

            storage.insert_events(
                [
                    wrapper_event(
                        "run_passive",
                        "run_finished",
                        source="test",
                        raw_payload={"exit_code": 0},
                        command_exit_code=0,
                    )
                ]
            )

            transitions = apply_lifecycle_transitions(
                storage,
                idle_seconds=30,
                now="2026-06-12T10:05:00+00:00",
            )

            run = storage.get_run("run_passive")
            self.assertEqual(run["status"], "completed")
            self.assertTrue(transitions)


if __name__ == "__main__":
    unittest.main()
