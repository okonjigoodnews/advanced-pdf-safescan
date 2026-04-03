"""Tests for explanation panel helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.explanations import build_explanation_panel


class ExplanationPanelTestCase(unittest.TestCase):
    """Validate readable explanation payloads for result panels."""

    def test_build_explanation_panel_uses_existing_explanations_when_present(self) -> None:
        """Prefer backend-generated explanation text when available."""
        summary = {
            "final_label": "malicious",
            "final_confidence": 0.92,
            "suspicious_indicators_found": ["/JavaScript (1)", "/OpenAction (1)"],
            "triggered_rules": ["embedded-script-present"],
            "explanations": ["Embedded script activity was detected in the PDF structure."],
        }

        panel = build_explanation_panel(summary, "Do not open the file.")

        self.assertEqual(panel["top_suspicious_indicators"], ["/JavaScript (1)", "/OpenAction (1)"])
        self.assertEqual(panel["triggered_rules"], ["embedded-script-present"])
        self.assertEqual(
            panel["plain_english_explanation"],
            "Embedded script activity was detected in the PDF structure.",
        )
        self.assertIn("very strong support", panel["confidence_interpretation"])
        self.assertEqual(panel["recommended_action"], "Do not open the file.")

    def test_build_explanation_panel_creates_fallback_text_when_needed(self) -> None:
        """Generate a readable fallback explanation from counts and verdict."""
        summary = {
            "final_label": "suspicious",
            "final_confidence": 0.68,
            "suspicious_indicators_found": ["/URI (2)"],
            "triggered_rules": ["external-link-density"],
            "explanations": [],
        }

        panel = build_explanation_panel(summary, "Open with caution.")

        self.assertIn("marked suspicious", panel["plain_english_explanation"])
        self.assertIn("1 suspicious indicator", panel["plain_english_explanation"])
        self.assertIn("moderate support", panel["confidence_interpretation"])
        self.assertEqual(panel["recommended_action"], "Open with caution.")

    def test_build_explanation_panel_handles_benign_files_with_no_signals(self) -> None:
        """Describe a benign file clearly when no notable signals were found."""
        summary = {
            "final_label": "benign",
            "final_confidence": 0.83,
            "suspicious_indicators_found": [],
            "triggered_rules": [],
            "explanations": [],
        }

        panel = build_explanation_panel(summary, "Safe to open in a normal workflow.")

        self.assertEqual(panel["top_suspicious_indicators"], [])
        self.assertEqual(panel["triggered_rules"], [])
        self.assertIn("did not present notable suspicious indicators", panel["plain_english_explanation"])
        self.assertIn("strong support", panel["confidence_interpretation"])


if __name__ == "__main__":
    unittest.main()
