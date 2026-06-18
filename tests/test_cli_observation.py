from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.cli import build_parser, main
from codex_inspector.storage import Storage


class CliObservationTests(unittest.TestCase):
    def test_parser_exposes_observation_commands(self) -> None:
        parser = build_parser()

        self.assertEqual(parser.parse_args(["discover"]).command, "discover")
        observe = parser.parse_args(["observe", "--watch", "--interval", "3", "--candidate-dir", "."])
        self.assertEqual(observe.command, "observe")
        self.assertTrue(observe.watch)
        self.assertEqual(observe.interval, 3.0)
        self.assertEqual(parser.parse_args(["attach", "--pid", "123"]).pid, 123)
        self.assertEqual(parser.parse_args(["attach", "--path", "session.jsonl"]).path, "session.jsonl")

    def test_attach_path_imports_passive_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")

            exit_code = main(["--db", str(db_path), "attach", "--path", str(source)])

            self.assertEqual(exit_code, 0)
            storage = Storage(db_path)
            runs = storage.list_observed_runs(statuses=["active"])
            passive_runs = [run for run in runs if run["observation_quality"] == "passive_partial"]
            self.assertEqual(len(passive_runs), 1)
            self.assertEqual(len(storage.get_events(passive_runs[0]["run_id"])), 1)
            self.assertEqual(len(storage.get_observed_sources(passive_runs[0]["run_id"])), 1)

    def test_observe_once_tails_candidate_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")

            exit_code = main(["--db", str(db_path), "observe", "--once", "--candidate-dir", str(root)])

            self.assertEqual(exit_code, 0)
            storage = Storage(db_path)
            runs = storage.list_observed_runs(statuses=["active"])
            passive_runs = [run for run in runs if run["observation_quality"] == "passive_partial"]
            self.assertEqual(len(passive_runs), 1)

    def test_missing_pid_attach_returns_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"

            exit_code = main(["--db", str(db_path), "attach", "--pid", "999999999"])

            self.assertEqual(exit_code, 1)
            storage = Storage(db_path)
            storage.init_schema()
            self.assertEqual(storage.list_runs(), [])


if __name__ == "__main__":
    unittest.main()
