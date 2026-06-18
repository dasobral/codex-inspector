from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.observer import (
    CodexObserver,
    ProcessInfo,
    StaticProcessProvider,
    score_process,
)
from codex_inspector.storage import Storage


class ObserverTests(unittest.TestCase):
    def test_score_process_classifies_codex_exec(self) -> None:
        process = ProcessInfo(
            pid=100,
            command_line=("codex", "exec", "--json", "-C", "/repo", "prompt"),
            cwd="/repo",
            started_at="123",
            executable="codex",
        )

        score = score_process(process)

        self.assertEqual(score.detected_kind, "codex_exec")
        self.assertGreaterEqual(score.confidence, 90)

    def test_discover_creates_process_only_run_for_high_confidence_codex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            process = ProcessInfo(
                pid=101,
                command_line=("codex", "exec", "--json"),
                cwd=str(Path(tmp)),
                started_at="start-101",
                executable="codex",
            )
            observer = CodexObserver(
                storage,
                process_provider=StaticProcessProvider([process]),
                clock=lambda: "2026-06-12T10:00:00+00:00",
            )

            discovered = observer.discover()

            self.assertEqual(len(discovered), 1)
            run = storage.get_run(discovered[0]["run_id"])
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "active")
            self.assertEqual(run["observation_quality"], "process_only")
            self.assertGreaterEqual(run["confidence"], 90)
            stored_process = storage.get_observed_process(discovered[0]["process_id"])
            self.assertEqual(stored_process["pid"], 101)
            self.assertEqual(stored_process["status"], "active")

    def test_explicit_attach_allows_low_confidence_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            process = ProcessInfo(
                pid=102,
                command_line=("python", "agent.py"),
                cwd=str(Path(tmp)),
                started_at="start-102",
                executable="python",
            )
            observer = CodexObserver(
                storage,
                process_provider=StaticProcessProvider([process]),
                clock=lambda: "2026-06-12T10:00:00+00:00",
            )

            attached = observer.attach_pid(102)

            self.assertEqual(attached["pid"], 102)
            run = storage.get_run(attached["run_id"])
            self.assertEqual(run["status"], "active")
            self.assertEqual(run["observation_quality"], "process_only")
            self.assertLess(run["confidence"], 50)

    def test_attach_missing_pid_fails_without_creating_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            storage = Storage(Path(tmp) / "test.sqlite")
            storage.init_schema()
            observer = CodexObserver(
                storage,
                process_provider=StaticProcessProvider([]),
                clock=lambda: "2026-06-12T10:00:00+00:00",
            )

            with self.assertRaises(ValueError):
                observer.attach_pid(999)

            self.assertEqual(storage.list_runs(), [])


if __name__ == "__main__":
    unittest.main()
