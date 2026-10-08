"""Keep discovery inventories and actual execution evidence distinct."""
import json
import csv
from pathlib import Path
import unittest

from scripts.check_test_evidence import inspect
from scripts.test_inventory import methods


class TestEvidenceContract(unittest.TestCase):
    def test_skipped_or_unselected_required_gate_is_not_passed(self):
        package = "example/auth"
        events = "\n".join(json.dumps(event) for event in [
            {"Package": package, "Test": "TestRedis", "Action": "skip"},
            {"Package": package, "Action": "pass"}])
        result = inspect(events, [package + "::TestRedis", package + "::TestFleet"])
        self.assertFalse(result["valid"])
        self.assertEqual(len(result["mandatory_not_passed"]), 2)
        self.assertEqual(len(result["skipped"]), 1)

    def test_failure_and_empty_log_cannot_certify_release(self):
        self.assertFalse(inspect("", [])["valid"])
        events = json.dumps({"Package": "example/auth", "Action": "fail"})
        self.assertFalse(inspect(events, [])["valid"])

    def test_nested_pass_events_are_labeled_not_inflated_definitions(self):
        events = "\n".join(json.dumps(event) for event in [
            {"Package": "example/auth", "Test": "TestRedis/case", "Action": "pass"},
            {"Package": "example/auth", "Test": "TestRedis", "Action": "pass"},
            {"Package": "example/auth", "Action": "pass"}])
        result = inspect(events, ["example/auth::TestRedis"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["passed_test_events_including_subtests"], 2)

    def test_inventory_counts_methods_not_calls_or_helpers(self):
        source = "class Cases:\n def test_sync(self): pass\n async def test_async(self): pass\n def helper(self): pass\n"
        self.assertEqual(methods(source), ["Cases.test_sync", "Cases.test_async"])

    def test_truncated_log_does_not_pass_completed_package_only(self):
        events = '\n'.join(json.dumps(event) for event in [
            {"Package": "example/first", "Action": "pass"},
            {"Package": "example/second", "Action": "start"}])
        self.assertFalse(inspect(events, [])["valid"])

    def test_later_pass_does_not_erase_prior_failure(self):
        events = '\n'.join(json.dumps(event) for event in [
            {"Package": "example/first", "Action": "fail"},
            {"Package": "example/first", "Action": "pass"}])
        self.assertFalse(inspect(events, [])["valid"])

    def test_legacy_ledger_is_complete_unique_and_honest(self):
        path = Path(__file__).resolve().parents[1] / "docs/legacy-test-ledger.csv"
        with path.open(encoding="utf-8", newline="") as stream:
            rows = list(csv.DictReader(stream))
        self.assertEqual(len(rows), 552)
        self.assertEqual(len({row["legacy_case"] for row in rows}), 552)
        reviewed = [row for row in rows if row["review_status"].startswith("reviewed-")]
        self.assertGreaterEqual(len(reviewed), 9)
        self.assertTrue(all(row["replacement"] for row in reviewed))
        self.assertTrue(all(row["review_status"] == "pending-assertion-review"
                            or row["review_status"].startswith("reviewed-") for row in rows))
