"""Tests for PDF report export helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.pdf_export import build_pdf_report_bytes, _build_pdf_report_lines


class PDFExportTestCase(unittest.TestCase):
    """Validate simple PDF export generation for analyzed files."""

    def test_build_pdf_report_lines_includes_required_sections(self) -> None:
        """Build readable report lines with all required summary fields."""
        report_data = {
            "file_name": "sample.pdf",
            "sha256": "abc123",
            "final_label": "suspicious",
            "final_confidence": 0.71,
            "rule_score": 56.0,
            "rule_severity": "high",
            "ml_label": "suspicious",
            "ml_confidence": 0.67,
            "suspicious_indicators": [],
            "triggered_rules": [],
            "explanations": [],
            "recommendation": "Open with caution.",
        }

        lines = _build_pdf_report_lines(report_data=report_data, timestamp="2026-03-26T12:00:00+00:00")

        self.assertIn("Advanced PDFSafeScan", lines)
        self.assertIn("Intelligent Malicious PDF Detection", lines)
        self.assertIn("File Name: sample.pdf", lines)
        self.assertIn("SHA-256: abc123", lines)
        self.assertIn("Final Label: Suspicious", lines)
        self.assertIn("Recommendation", lines)
        self.assertIn("- None recorded.", lines)

    def test_build_pdf_report_bytes_returns_pdf_payload(self) -> None:
        """Generate a simple PDF payload that contains core report text."""
        report_data = {
            "file_name": "sample.pdf",
            "sha256": "abc123",
            "final_label": "malicious",
            "final_confidence": 0.93,
            "rule_score": 88.0,
            "rule_severity": "critical",
            "ml_label": "malicious",
            "ml_confidence": 0.91,
            "suspicious_indicators": ["JavaScript detected"],
            "triggered_rules": ["embedded-script-present"],
            "explanations": ["Script activity indicator detected."],
            "recommendation": "Do not open. Quarantine or isolate the file and investigate further.",
        }

        pdf_bytes = build_pdf_report_bytes(
            report_data=report_data,
            timestamp="2026-03-26T12:00:00+00:00",
        )

        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"Advanced PDFSafeScan", pdf_bytes)
        self.assertIn(b"Intelligent Malicious PDF Detection", pdf_bytes)
        self.assertIn(b"File Name: sample.pdf", pdf_bytes)
        self.assertIn(b"SHA-256: abc123", pdf_bytes)
        self.assertIn(b"Final Label: Malicious", pdf_bytes)
        self.assertIn(b"Report Timestamp: 2026-03-26T12:00:00+00:00", pdf_bytes)


if __name__ == "__main__":
    unittest.main()
