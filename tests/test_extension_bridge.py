"""Tests for Chrome extension API bridge helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.extension_bridge import (
    build_recent_scan_rows,
    build_scan_response_from_analysis,
    build_scan_response_from_history_record,
    find_cached_history_record_by_sha256,
)


class ExtensionBridgeTestCase(unittest.TestCase):
    """Validate extension-facing JSON payload helpers."""

    def test_find_cached_history_record_by_sha256_returns_newest_match(self) -> None:
        """Choose the newest matching history row when multiple scans share a hash."""
        history_records = [
            {"timestamp": "2026-03-29T09:00:00+00:00", "sha256": "abc123", "file_name": "old.pdf"},
            {"timestamp": "2026-03-29T10:00:00+00:00", "sha256": "abc123", "file_name": "new.pdf"},
        ]

        record = find_cached_history_record_by_sha256(history_records, "abc123")

        self.assertIsNotNone(record)
        self.assertEqual(record["file_name"], "new.pdf")

    def test_build_scan_response_from_analysis_contains_extension_fields(self) -> None:
        """Serialize a fresh analysis result into extension JSON format."""
        analysis_result = {
            "report_timestamp": "2026-03-29T10:00:00+00:00",
            "sha256": "abc123",
            "recommendation": "Open with caution.",
            "summary": {
                "file_name": "sample.pdf",
                "final_label": "suspicious",
                "final_confidence": 0.82,
                "rule_score": 64.0,
                "rule_severity": "high",
                "ml_label": "malicious",
                "ml_confidence": 0.77,
                "triggered_rules": ["embedded-js"],
                "explanations": ["JavaScript action detected."],
                "suspicious_indicators_found": ["/JavaScript (1)"],
            },
        }

        payload = build_scan_response_from_analysis(
            analysis_result,
            source_url="https://example.com/sample.pdf",
            cached=False,
            review_record={"review_status": "Under Review", "priority": "High"},
        )

        self.assertEqual(payload["status"], "ok")
        self.assertFalse(payload["cached"])
        self.assertEqual(payload["source_url"], "https://example.com/sample.pdf")
        self.assertEqual(payload["final_label"], "suspicious")
        self.assertEqual(payload["rule_score"], 64.0)
        self.assertEqual(payload["review_status"], "Under Review")
        self.assertEqual(payload["priority"], "High")

    def test_build_scan_response_from_history_record_defaults_missing_fields(self) -> None:
        """Serialize a cached history record even when detailed ML fields are unavailable."""
        history_record = {
            "timestamp": "2026-03-29T10:00:00+00:00",
            "file_name": "cached.pdf",
            "sha256": "abc123",
            "final_label": "malicious",
            "final_confidence": 0.95,
            "rule_score": 88.0,
            "recommendation": "Do not open.",
        }

        payload = build_scan_response_from_history_record(history_record)

        self.assertTrue(payload["cached"])
        self.assertEqual(payload["file_name"], "cached.pdf")
        self.assertEqual(payload["ml_label"], "unknown")
        self.assertEqual(payload["rule_severity"], "unknown")
        self.assertEqual(payload["recommendation"], "Do not open.")

    def test_build_recent_scan_rows_merges_review_fields_and_limit(self) -> None:
        """Build a compact recent-scans list with analyst workflow fields."""
        history_records = [
            {
                "timestamp": "2026-03-29T11:00:00+00:00",
                "file_name": "new.pdf",
                "sha256": "newhash",
                "final_label": "malicious",
                "final_confidence": 0.93,
                "rule_score": 82.0,
                "recommendation": "Do not open.",
            },
            {
                "timestamp": "2026-03-29T10:00:00+00:00",
                "file_name": "old.pdf",
                "sha256": "oldhash",
                "final_label": "benign",
                "final_confidence": 0.72,
                "rule_score": 10.0,
                "recommendation": "Safe to open.",
            },
        ]
        review_records_by_sha256 = {
            "newhash": {
                "review_status": "Escalated",
                "priority": "Critical",
                "disposition": "Malicious",
                "analyst_note": "Escalated to incident response.",
            }
        }

        rows = build_recent_scan_rows(history_records, review_records_by_sha256, limit=1)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["file_name"], "new.pdf")
        self.assertEqual(rows[0]["review_status"], "Escalated")
        self.assertEqual(rows[0]["priority"], "Critical")
        self.assertEqual(rows[0]["disposition"], "Malicious")


if __name__ == "__main__":
    unittest.main()
