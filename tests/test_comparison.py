"""Tests for two-PDF comparison helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.comparison import build_comparison_summary


class ComparisonSummaryTestCase(unittest.TestCase):
    """Validate summary-level comparison logic for two PDFs."""

    def test_build_comparison_summary_identifies_riskier_file(self) -> None:
        """Choose the more dangerous file based on verdict and score."""
        summary_a = {
            "file_name": "a.pdf",
            "final_label": "benign",
            "final_confidence": 0.91,
            "rule_score": 12.0,
            "suspicious_indicators_found": ["/URI (1)"],
        }
        summary_b = {
            "file_name": "b.pdf",
            "final_label": "malicious",
            "final_confidence": 0.87,
            "rule_score": 80.0,
            "suspicious_indicators_found": ["/JavaScript (1)", "/OpenAction (1)"],
        }

        comparison = build_comparison_summary(summary_a, summary_b)

        self.assertEqual(comparison["riskier_file"], "b.pdf")
        self.assertEqual(comparison["higher_rule_score_file"], "b.pdf")
        self.assertEqual(comparison["more_suspicious_indicators_file"], "b.pdf")
        self.assertFalse(comparison["same_final_label"])
        self.assertIn("b.pdf appears riskier overall", comparison["comparison_statement"])

    def test_build_comparison_summary_reports_ties_cleanly(self) -> None:
        """Return ties when the main comparison metrics are equal."""
        summary_a = {
            "file_name": "first.pdf",
            "final_label": "suspicious",
            "final_confidence": 0.71,
            "rule_score": 56.0,
            "suspicious_indicators_found": ["/Launch (1)"],
        }
        summary_b = {
            "file_name": "second.pdf",
            "final_label": "suspicious",
            "final_confidence": 0.71,
            "rule_score": 56.0,
            "suspicious_indicators_found": ["/Launch (1)"],
        }

        comparison = build_comparison_summary(summary_a, summary_b)

        self.assertEqual(comparison["riskier_file"], "tie")
        self.assertEqual(comparison["higher_rule_score_file"], "tie")
        self.assertEqual(comparison["more_suspicious_indicators_file"], "tie")
        self.assertTrue(comparison["same_final_label"])
        self.assertIn("appear similarly risky overall", comparison["comparison_statement"])


if __name__ == "__main__":
    unittest.main()
