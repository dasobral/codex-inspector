from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.storage import Storage
from codex_inspector.tailer import FileTailer, discover_candidate_files, source_identity


class TailerTests(unittest.TestCase):
    def test_jsonl_tailing_persists_cursor_and_avoids_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db_path = root / "test.sqlite"
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")
            storage = Storage(db_path)
            storage.init_schema()
            storage.create_run("run_tail", source="observer", status="active", observation_quality="passive_partial")
            tailer = FileTailer(storage, clock=lambda: "2026-06-12T10:00:00+00:00")

            first = tailer.tail_file(source, run_id="run_tail")
            second = tailer.tail_file(source, run_id="run_tail")

            self.assertEqual(first["event_count"], 1)
            self.assertEqual(second["event_count"], 0)
            self.assertEqual(len(storage.get_events("run_tail")), 1)
            observed = storage.get_observed_source(source_identity(source))
            self.assertEqual(observed["cursor_offset"], source.stat().st_size)
            self.assertEqual(observed["cursor_line"], 1)

    def test_partial_trailing_line_waits_until_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n{"id":"evt_2"', encoding="utf-8")
            storage = Storage(root / "test.sqlite")
            storage.init_schema()
            storage.create_run("run_tail", source="observer", status="active", observation_quality="passive_partial")
            tailer = FileTailer(storage, clock=lambda: "2026-06-12T10:00:00+00:00")

            first = tailer.tail_file(source, run_id="run_tail")
            source.write_text(source.read_text(encoding="utf-8") + ',"type":"exec_command","command":"npm test","exit_code":0}\n', encoding="utf-8")
            second = tailer.tail_file(source, run_id="run_tail")

            self.assertEqual(first["event_count"], 1)
            self.assertEqual(second["event_count"], 1)
            self.assertEqual([event["event_id"] for event in storage.get_events("run_tail")], ["evt_1", "evt_2"])

    def test_truncation_records_diagnostic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"python -m unittest discover -s tests --verbose","exit_code":0}\n', encoding="utf-8")
            storage = Storage(root / "test.sqlite")
            storage.init_schema()
            storage.create_run("run_tail", source="observer", status="active", observation_quality="passive_partial")
            tailer = FileTailer(storage, clock=lambda: "2026-06-12T10:00:00+00:00")
            tailer.tail_file(source, run_id="run_tail")

            source.write_text('{"id":"evt_2","type":"exec_command","command":"npm test","exit_code":0}\n', encoding="utf-8")
            result = tailer.tail_file(source, run_id="run_tail")

            self.assertEqual(result["diagnostic_count"], 1)
            self.assertTrue(any(event["normalized_event_type"] == "diagnostic" for event in storage.get_events("run_tail")))
            self.assertTrue(any(event["event_id"] == "evt_2" for event in storage.get_events("run_tail")))

    def test_candidate_discovery_is_limited_to_supported_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keep = root / "session.jsonl"
            keep.write_text("", encoding="utf-8")
            nested = root / "nested"
            nested.mkdir()
            keep_nested = nested / "trace.log"
            keep_nested.write_text("", encoding="utf-8")
            skip = root / "notes.md"
            skip.write_text("", encoding="utf-8")

            candidates = discover_candidate_files(root)

            self.assertEqual(candidates, [keep, keep_nested])

    def test_tail_known_sources_refreshes_previously_attached_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "session.jsonl"
            source.write_text('{"id":"evt_1","type":"exec_command","command":"pytest","exit_code":0}\n', encoding="utf-8")
            storage = Storage(root / "test.sqlite")
            storage.init_schema()
            tailer = FileTailer(storage, clock=lambda: "2026-06-12T10:00:00+00:00")
            first = tailer.tail_file(source)
            source.write_text(
                source.read_text(encoding="utf-8")
                + '{"id":"evt_2","type":"exec_command","command":"python -m unittest discover -s tests","exit_code":0}\n',
                encoding="utf-8",
            )

            refreshed = tailer.tail_known_sources()

            self.assertEqual(refreshed[0]["event_count"], 1)
            self.assertEqual(len(storage.get_events(first["run_id"])), 2)


if __name__ == "__main__":
    unittest.main()
