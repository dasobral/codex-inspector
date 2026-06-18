from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_inspector.analyzer import analyze_run, build_findings
from codex_inspector.fixtures import fixture_files
from codex_inspector.importer import import_jsonl_file
from codex_inspector.storage import Storage


class FixtureRegressionTests(unittest.TestCase):
    def test_all_fixtures_import_and_analyze(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            for fixture_path in fixture_files():
                result = import_jsonl_file(fixture_path, db_path=db_path)
                self.assertGreater(result["event_count"], 0)
                analysis = result["analysis"]
                self.assertIn("risk_score", analysis)

    def test_clean_success_has_low_risk(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            fixture = next(path for path in fixture_files() if path.name == "clean_success.jsonl")
            result = import_jsonl_file(fixture, db_path=db_path)
            self.assertLess(result["analysis"]["risk_score"], 30)

    def test_dangerous_suspicious_has_high_risk_signals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            fixture = next(path for path in fixture_files() if path.name == "dangerous_suspicious.jsonl")
            result = import_jsonl_file(fixture, db_path=db_path)
            categories = {finding["category"] for finding in result["analysis"]["findings"]}
            self.assertIn("destructive_command", categories)
            self.assertIn("sandbox", categories)
            self.assertIn("failed_command", categories)
            self.assertIn("network_command", categories)
            self.assertGreater(result["analysis"]["risk_score"], 40)

    def test_repeated_failures_detects_repeated_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            fixture = next(path for path in fixture_files() if path.name == "repeated_failures.jsonl")
            result = import_jsonl_file(fixture, db_path=db_path)
            categories = {finding["category"] for finding in result["analysis"]["findings"]}
            self.assertIn("repeated_failure", categories)

    def test_risky_dependency_deploy_flags_lockfile_and_deployment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            fixture = next(path for path in fixture_files() if path.name == "risky_dependency_deploy.jsonl")
            result = import_jsonl_file(fixture, db_path=db_path)
            categories = {finding["category"] for finding in result["analysis"]["findings"]}
            self.assertIn("lockfile", categories)
            self.assertIn("deployment", categories)

    def test_risk_ordering_across_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.sqlite"
            scores: dict[str, int] = {}
            for fixture_path in fixture_files():
                result = import_jsonl_file(fixture_path, db_path=db_path)
                scores[fixture_path.name] = result["analysis"]["risk_score"]
            self.assertGreater(scores["dangerous_suspicious.jsonl"], scores["clean_success.jsonl"])


if __name__ == "__main__":
    unittest.main()
