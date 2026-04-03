"""Tests for forensic reporting helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.forensics import (
    build_forensic_report,
    compute_sha256,
    recommendation_for_verdict,
)


class ForensicReportingTestCase(unittest.TestCase):
    """Validate PDF hashing and forensic report generation."""

    def test_compute_sha256_returns_expected_digest(self) -> None:
        """Hash PDF bytes deterministically."""
        digest = compute_sha256(b"abc")

        self.assertEqual(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_recommendation_for_verdict_returns_expected_guidance(self) -> None:
        """Map final verdicts onto simple operator guidance."""
        self.assertEqual(
            recommendation_for_verdict("benign"),
            "Safe to open under normal precautions.",
        )
        self.assertIn("Open with caution", recommendation_for_verdict("suspicious"))
        self.assertIn("Do not open", recommendation_for_verdict("malicious"))

    def test_build_forensic_report_collects_expected_fields(self) -> None:
        """Assemble a clean structured forensic report."""
        summary = {
            "file_name": "sample.pdf",
            "final_label": "suspicious",
            "final_confidence": 0.71,
            "rule_score": 56.0,
            "rule_severity": "high",
            "ml_label": "suspicious",
            "ml_confidence": 0.67,
            "suspicious_indicators_found": ["/EmbeddedFile (1)"],
            "triggered_rules": ["embedded-file-present"],
            "explanations": ["Embedded payload indicator."],
        }
        reader_result = {
            "metadata": {"/Author": "Analyst"},
            "metadata_field_count": 1,
            "page_count": 3,
            "text_extraction_succeeded": True,
            "warnings": ["Text preview was limited to the first 10 page(s)."],
        }

        report = build_forensic_report(
            summary=summary,
            reader_result=reader_result,
            sha256="deadbeef",
            file_size=2048,
            recommendation="Open with caution. Prefer isolated viewing and further inspection before trusting the file.",
        )

        self.assertEqual(report["sha256"], "deadbeef")
        self.assertEqual(report["file_name"], "sample.pdf")
        self.assertEqual(report["file_size"], 2048)
        self.assertEqual(report["final_label"], "suspicious")
        self.assertEqual(report["rule_score"], 56.0)
        self.assertEqual(report["metadata_summary"]["field_count"], 1)
        self.assertEqual(report["page_count"], 3)
        self.assertEqual(report["text_extraction_status"], "partial")
        self.assertEqual(
            report["safe_reader_warnings"],
            ["Text preview was limited to the first 10 page(s)."],
        )
        self.assertIn("Open with caution", report["recommendation"])


if __name__ == "__main__":
    unittest.main()
