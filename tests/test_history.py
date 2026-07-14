"""Tests for persistent scan history helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.history import (
    append_scan_history_records,
    build_scan_history_records,
    compute_parse_coverage,
    filter_scan_history_records,
    get_high_risk_scan_history_records,
    get_malicious_scan_history_records,
    load_scan_history,
    search_scan_history_records,
    sort_scan_history_records,
)


class ScanHistoryTestCase(unittest.TestCase):
    """Validate JSON-backed scan history storage and filtering."""

    def test_build_scan_history_records_collects_expected_fields(self) -> None:
        """Build compact history records from analyzed results."""
        analyzed_results = [
            (
                "pdf_a",
                {
                    "summary": {
                        "file_name": "sample.pdf",
                        "final_label": "suspicious",
                        "final_confidence": 0.71,
                        "rule_score": 56.0,
                    },
                    "sha256": "abc123",
                    "recommendation": "Open with caution.",
                    "report_timestamp": "2026-03-26T12:00:00+00:00",
                },
            )
        ]

        records = build_scan_history_records(analyzed_results)

        self.assertEqual(
            records,
            [
                {
                    "timestamp": "2026-03-26T12:00:00+00:00",
                    "file_name": "sample.pdf",
                    "sha256": "abc123",
                    "client_id": "",
                    "final_label": "suspicious",
                    "final_confidence": 0.71,
                    "rule_score": 56.0,
                    "rule_severity": "low",
                    "parsed": True,
                    "triggered_rules": [],
                    "explanations": [],
                    "recommendation": "Open with caution.",
                }
            ],
        )

    def test_append_and_load_scan_history_round_trip(self) -> None:
        """Append records to disk and load them back from JSON storage."""
        analyzed_results = [
            (
                "pdf_a",
                {
                    "summary": {
                        "file_name": "sample.pdf",
                        "final_label": "malicious",
                        "final_confidence": 0.91,
                        "rule_score": 82.0,
                    },
                    "sha256": "deadbeef",
                    "recommendation": "Do not open.",
                    "report_timestamp": "2026-03-26T12:05:00+00:00",
                },
            )
        ]

        history_path = PROJECT_ROOT / "tests" / "_history_test_output.json"
        if history_path.exists():
            history_path.unlink()

        try:
            append_scan_history_records(analyzed_results, history_path=history_path)
            loaded_records = load_scan_history(history_path=history_path)
        finally:
            if history_path.exists():
                history_path.unlink()

        self.assertEqual(len(loaded_records), 1)
        self.assertEqual(loaded_records[0]["file_name"], "sample.pdf")
        self.assertEqual(loaded_records[0]["final_label"], "malicious")
        self.assertEqual(loaded_records[0]["sha256"], "deadbeef")

    def test_filter_scan_history_records_by_verdict(self) -> None:
        """Filter stored history rows by verdict label."""
        history_records = [
            {"final_label": "benign", "file_name": "a.pdf"},
            {"final_label": "suspicious", "file_name": "b.pdf"},
            {"final_label": "malicious", "file_name": "c.pdf"},
        ]

        suspicious_records = filter_scan_history_records(history_records, "suspicious")
        all_records = filter_scan_history_records(history_records, "all")

        self.assertEqual(suspicious_records, [{"final_label": "suspicious", "file_name": "b.pdf"}])
        self.assertEqual(all_records, history_records)

    def test_search_scan_history_records_matches_file_name_and_sha256(self) -> None:
        """Search stored history rows by file name and SHA-256 substring."""
        history_records = [
            {"file_name": "invoice.pdf", "sha256": "abc123"},
            {"file_name": "report.pdf", "sha256": "deadbeef"},
        ]

        file_name_matches = search_scan_history_records(history_records, file_name_query="invoice")
        sha_matches = search_scan_history_records(history_records, sha256_query="beef")

        self.assertEqual(file_name_matches, [{"file_name": "invoice.pdf", "sha256": "abc123"}])
        self.assertEqual(sha_matches, [{"file_name": "report.pdf", "sha256": "deadbeef"}])

    def test_sort_scan_history_records_supports_requested_orders(self) -> None:
        """Sort history rows by newest timestamp, rule score, and confidence."""
        history_records = [
            {
                "timestamp": "2026-03-26T12:00:00+00:00",
                "final_confidence": 0.61,
                "rule_score": 30.0,
            },
            {
                "timestamp": "2026-03-26T12:05:00+00:00",
                "final_confidence": 0.74,
                "rule_score": 22.0,
            },
            {
                "timestamp": "2026-03-26T12:02:00+00:00",
                "final_confidence": 0.68,
                "rule_score": 81.0,
            },
        ]

        newest = sort_scan_history_records(history_records, "newest")
        highest_rule_score = sort_scan_history_records(history_records, "highest_rule_score")
        highest_confidence = sort_scan_history_records(history_records, "highest_confidence")

        self.assertEqual(newest[0]["timestamp"], "2026-03-26T12:05:00+00:00")
        self.assertEqual(highest_rule_score[0]["rule_score"], 81.0)
        self.assertEqual(highest_confidence[0]["final_confidence"], 0.74)

    def test_get_high_risk_and_malicious_scan_history_records(self) -> None:
        """Return malicious files and suspicious files above the high-risk threshold."""
        history_records = [
            {"file_name": "a.pdf", "final_label": "benign", "rule_score": 12.0},
            {"file_name": "b.pdf", "final_label": "suspicious", "rule_score": 72.0},
            {"file_name": "c.pdf", "final_label": "malicious", "rule_score": 45.0},
            {"file_name": "d.pdf", "final_label": "suspicious", "rule_score": 40.0},
        ]

        high_risk_records = get_high_risk_scan_history_records(history_records)
        malicious_records = get_malicious_scan_history_records(history_records)

        self.assertEqual(
            [record["file_name"] for record in high_risk_records],
            ["b.pdf", "c.pdf"],
        )
        self.assertEqual(
            [record["file_name"] for record in malicious_records],
            ["c.pdf"],
        )


    def test_build_scan_history_records_flags_malformed_as_unparseable(self) -> None:
        """A malformed file is recorded as parsed=False, a readable one as True."""
        analyzed_results = [
            (
                "pdf_clean",
                {
                    "summary": {
                        "file_name": "clean.pdf",
                        "final_label": "benign",
                        "final_confidence": 1.0,
                        "rule_score": 0.0,
                        "triggered_rules": [],
                    },
                    "sha256": "clean1",
                    "recommendation": "Safe to open.",
                    "report_timestamp": "2026-03-26T12:00:00+00:00",
                },
            ),
            (
                "pdf_malformed",
                {
                    "summary": {
                        "file_name": "malformed.pdf",
                        "final_label": "suspicious",
                        "final_confidence": 0.9,
                        "rule_score": 85.0,
                        "triggered_rules": [
                            "openaction-with-javascript",
                            "malformed-pdf-structure",
                        ],
                    },
                    "sha256": "malf1",
                    "recommendation": "Open with caution.",
                    "report_timestamp": "2026-03-26T12:01:00+00:00",
                },
            ),
        ]

        records = build_scan_history_records(analyzed_results)

        self.assertTrue(records[0]["parsed"])
        self.assertFalse(records[1]["parsed"])

    def test_build_scan_history_records_stores_verdict_reasons(self) -> None:
        """Triggered rules, explanations and rule severity are stored for later display."""
        analyzed_results = [
            (
                "pdf_a",
                {
                    "summary": {
                        "file_name": "evil.pdf",
                        "final_label": "suspicious",
                        "final_confidence": 0.9,
                        "rule_score": 85.0,
                        "rule_severity": "critical",
                        "triggered_rules": ["malformed-pdf-structure"],
                        "explanations": ["[critical] malformed-pdf-structure: unreadable."],
                    },
                    "sha256": "evil1",
                    "recommendation": "Open with caution.",
                    "report_timestamp": "2026-03-26T12:00:00+00:00",
                },
            )
        ]

        records = build_scan_history_records(analyzed_results)

        self.assertEqual(records[0]["rule_severity"], "critical")
        self.assertEqual(records[0]["triggered_rules"], ["malformed-pdf-structure"])
        self.assertEqual(
            records[0]["explanations"],
            ["[critical] malformed-pdf-structure: unreadable."],
        )

    def test_load_scan_history_defaults_missing_reasons_to_empty(self) -> None:
        """Older records without reasons load cleanly rather than raising."""
        import json

        history_path = PROJECT_ROOT / "tests" / "_history_no_reasons.json"
        history_path.write_text(
            json.dumps(
                [
                    {
                        "timestamp": "2026-03-01T10:00:00+00:00",
                        "file_name": "legacy.pdf",
                        "sha256": "old1",
                        "final_label": "benign",
                        "final_confidence": 1.0,
                        "rule_score": 0.0,
                        "recommendation": "Safe to open.",
                    }
                ]
            ),
            encoding="utf-8",
        )

        try:
            loaded_records = load_scan_history(history_path=history_path)
        finally:
            if history_path.exists():
                history_path.unlink()

        self.assertEqual(loaded_records[0]["triggered_rules"], [])
        self.assertEqual(loaded_records[0]["explanations"], [])
        self.assertEqual(loaded_records[0]["rule_severity"], "low")

    def test_compute_parse_coverage_reports_expected_ratio(self) -> None:
        """Coverage counts readable and unreadable files and returns the ratio."""
        history_records = [
            {"final_label": "benign", "parsed": True},
            {"final_label": "malicious", "parsed": True},
            {"final_label": "suspicious", "parsed": False},
        ]

        coverage = compute_parse_coverage(history_records)

        self.assertEqual(coverage["parsed_count"], 2)
        self.assertEqual(coverage["unparseable_count"], 1)
        self.assertEqual(coverage["known_count"], 3)
        self.assertEqual(coverage["unknown_count"], 0)
        self.assertAlmostEqual(coverage["coverage_ratio"], 2 / 3)

    def test_compute_parse_coverage_excludes_legacy_records(self) -> None:
        """Records saved before the parsed field existed do not distort coverage."""
        legacy_records = [
            {"final_label": "benign"},
            {"final_label": "malicious"},
        ]

        coverage = compute_parse_coverage(legacy_records)

        self.assertEqual(coverage["known_count"], 0)
        self.assertEqual(coverage["unknown_count"], 2)
        self.assertIsNone(coverage["coverage_ratio"])

    def test_load_scan_history_defaults_legacy_records_to_unknown(self) -> None:
        """A record on disk with no parsed field loads as None, not True or False."""
        import json

        history_path = PROJECT_ROOT / "tests" / "_history_legacy_output.json"
        legacy_on_disk = [
            {
                "timestamp": "2026-03-01T10:00:00+00:00",
                "file_name": "legacy.pdf",
                "sha256": "old1",
                "final_label": "benign",
                "final_confidence": 1.0,
                "rule_score": 0.0,
                "recommendation": "Safe to open.",
            }
        ]
        history_path.write_text(json.dumps(legacy_on_disk), encoding="utf-8")

        try:
            loaded_records = load_scan_history(history_path=history_path)
        finally:
            if history_path.exists():
                history_path.unlink()

        self.assertIsNone(loaded_records[0]["parsed"])


if __name__ == "__main__":
    unittest.main()
