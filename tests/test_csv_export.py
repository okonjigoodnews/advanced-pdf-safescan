"""Tests for CSV export helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.csv_export import build_csv_export_bytes


class CSVExportTestCase(unittest.TestCase):
    """Validate simple CSV export generation for reporting tables."""

    def test_build_csv_export_bytes_writes_headers_and_rows(self) -> None:
        """Build UTF-8 CSV output from table rows."""
        rows = [
            {
                "timestamp": "2026-03-26T12:00:00+00:00",
                "file_name": "sample.pdf",
                "sha256": "abc123",
                "final_label": "suspicious",
                "final_confidence": 0.71,
                "rule_score": 56.0,
                "recommendation": "Open with caution.",
            }
        ]

        csv_bytes = build_csv_export_bytes(rows)
        csv_text = csv_bytes.decode("utf-8")

        self.assertIn("timestamp,file_name,sha256,final_label,final_confidence,rule_score,recommendation", csv_text)
        self.assertIn("sample.pdf", csv_text)
        self.assertIn("abc123", csv_text)
        self.assertIn("Open with caution.", csv_text)

    def test_build_csv_export_bytes_accepts_explicit_field_order(self) -> None:
        """Respect explicit field ordering when provided."""
        rows = [
            {
                "file_name": "sample.pdf",
                "final_label": "benign",
                "recommendation": "Safe to open.",
            }
        ]

        csv_bytes = build_csv_export_bytes(
            rows,
            fieldnames=["file_name", "final_label", "recommendation"],
        )

        self.assertEqual(
            csv_bytes.decode("utf-8").splitlines()[0],
            "file_name,final_label,recommendation",
        )


if __name__ == "__main__":
    unittest.main()
