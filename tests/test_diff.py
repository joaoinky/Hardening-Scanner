import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from copy import deepcopy

from nvg_scanner.diff import compare, transition, validate_report
from nvg_scanner.engine import scan
from nvg_scanner.reports import to_json, to_markdown
from tests.fixtures import synthetic_context


class DiffTests(unittest.TestCase):
    def test_all_status_transitions(self):
        expected = {("pass", "pass"): "unchanged", ("fail", "fail"): "unchanged",
                    ("warning", "warning"): "unchanged", ("pass", "fail"): "new_fail",
                    ("warning", "fail"): "new_fail", ("fail", "pass"): "resolved_fail",
                    ("warning", "pass"): "resolved_warning", ("pass", "warning"): "new_warning",
                    ("fail", "warning"): "new_warning", ("fail", None): "removed"}
        for pair, value in expected.items():
            self.assertEqual(transition(*pair), value)

    def test_presence_not_resolution_and_null_delta(self):
        before = scan(synthetic_context(), ["network_checks"])
        after = deepcopy(before)
        after["results"] = []
        after["summary"]["score"] = None
        result = compare(before, after)
        self.assertEqual(result["summary"]["resolved_fail"], 0)
        self.assertEqual(result["summary"]["removed"], 2)
        self.assertIsNone(result["metrics"]["score"]["delta"])

    def test_never_copies_secret_fields(self):
        before = scan(synthetic_context(), ["network_checks"])
        after = deepcopy(before)
        secrets = ["SENSITIVE-SEED-BEFORE", "SENSITIVE-SEED-AFTER"]
        for report, secret in zip((before, after), secrets):
            for key in ("name", "description", "reason", "recommendation", "evidence"):
                report["results"][0][key] = secret
        diff = compare(before, after)
        for rendering in (to_json(diff), to_markdown(diff)):
            for secret in secrets:
                self.assertNotIn(secret, rendering)
        changed = next(c for c in diff["changes"] if c["id"] == before["results"][0]["id"])
        self.assertIn("evidence", changed["changed_fields"])

    def test_duplicate_id_rejected(self):
        report = scan(synthetic_context(), ["network_checks"])
        report["results"].append(report["results"][0])
        with self.assertRaises(ValueError):
            validate_report(report)

    def test_cli_diff_never_reexecutes_checks(self):
        from nvg_scanner.__main__ import main
        report = scan(synthetic_context(), ["network_checks"])
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory, "report.json")
            source.write_text(to_json(report))
            output = Path(directory, "diff")
            with patch("nvg_scanner.__main__.scan", side_effect=AssertionError("Checks não podem executar")):
                code = main(["diff", "--before", str(source), "--after", str(source), "--format", "both", "--output", str(output)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads((output / "diff.json").read_text())["summary"]["unchanged"], 2)
