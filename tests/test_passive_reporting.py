from __future__ import annotations

import unittest

from codex_inspector.analyzer import build_quality_report
from codex_inspector.dashboard import group_runs_by_status
from codex_inspector.selftest import run_self_test


class PassiveReportingTests(unittest.TestCase):
    def test_quality_report_labels_process_only_as_incomplete(self) -> None:
        report = build_quality_report(
            {"run_id": "run_1", "observation_quality": "process_only", "confidence": 82},
            [],
            [],
            [],
            [],
            [],
        )

        self.assertIn("Observation quality: process_only", report)
        self.assertIn("passively and may be incomplete", report)

    def test_dashboard_groups_active_stale_completed_imported_and_failed(self) -> None:
        grouped = group_runs_by_status(
            [
                {"run_id": "active", "status": "active"},
                {"run_id": "stale", "status": "stale"},
                {"run_id": "completed", "status": "completed"},
                {"run_id": "imported", "status": "imported"},
                {"run_id": "failed", "status": "failed"},
                {"run_id": "unknown", "status": "unknown"},
            ]
        )

        self.assertEqual([run["run_id"] for run in grouped["Active"]], ["active"])
        self.assertEqual([run["run_id"] for run in grouped["Stale"]], ["stale"])
        self.assertEqual([run["run_id"] for run in grouped["Completed"]], ["completed"])
        self.assertEqual([run["run_id"] for run in grouped["Imported"]], ["imported"])
        self.assertEqual([run["run_id"] for run in grouped["Failed/Unknown"]], ["failed", "unknown"])

    def test_self_test_includes_passive_observation_check(self) -> None:
        result = run_self_test()

        self.assertTrue(result.passed, result.report)
        self.assertIn("PASS passive observation tailing", result.report)


if __name__ == "__main__":
    unittest.main()
