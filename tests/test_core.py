from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.importer import import_text
from codex_inspector.normalizer import parse_jsonl_lines
from codex_inspector.redaction import redact_payload, redact_text
from codex_inspector.storage import Storage


class CoreTests(unittest.TestCase):
    def test_parser_preserves_unknown_and_malformed_events(self) -> None:
        events = parse_jsonl_lines(
            [
                '{"type":"exec_command","command":"pytest","exit_code":0}',
                '{"type":"future_event","value":1}',
                'not json',
            ],
            "run_test",
        )
        self.assertTrue(any(event.normalized_event_type == "shell_command" for event in events))
        self.assertTrue(any(event.normalized_event_type == "unknown" for event in events))
        self.assertTrue(any(event.normalized_event_type == "diagnostic" for event in events))

    def test_redaction_masks_obvious_secrets(self) -> None:
        text = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz password=secret")
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", text)
        self.assertNotIn("secret", text)
        payload = redact_payload({"api_key": "sk-secret", "nested": {"token": "abc"}})
        self.assertEqual(payload["api_key"], "[REDACTED]")
        self.assertEqual(payload["nested"]["token"], "[REDACTED]")

    def test_import_creates_queryable_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            result = import_text(
                '{"type":"exec_command","command":"pytest","exit_code":0}',
                db_path=db_path,
                source_type="test",
                source_path="inline",
                prompt="test",
            )
            storage = Storage(db_path)
            run = storage.get_run(result["run_id"])
            self.assertIsNotNone(run)
            self.assertEqual(run["observation_quality"], "imported_full")
            self.assertGreaterEqual(len(storage.get_events(result["run_id"])), 3)


if __name__ == "__main__":
    unittest.main()
