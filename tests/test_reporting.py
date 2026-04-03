"""Tests for analysis reporting helpers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ml.classifier import MLResult
from src.reporting.summary import (
    build_analysis_summary,
    summary_to_console_text,
    summary_to_json,
)


class ReportingSummaryTestCase(unittest.TestCase):
    """Validate dictionary, JSON, and console reporting output."""

    def test_build_analysis_summary_collects_expected_fields(self) -> None:
        """Build a clean summary from pipeline component outputs."""
        parser_output = {
            "file_name": "suspicious.pdf",
            "file_path": "C:/analysis/suspicious.pdf",
            "suspicious_keyword_counts": {
                "/JavaScript": 1,
                "/OpenAction": 1,
                "/URI": 2,
            },
        }
        features = {"has_javascript": True, "has_openaction": True}
        rule_result = {
            "risk_score_normalized": 82,
            "severity": "critical",
            "triggered_rules": ["openaction-with-javascript"],
            "explanations": ["OpenAction combined with JavaScript can auto-trigger active content."],
        }
        ml_result = MLResult(
            predicted_label="malicious",
            confidence=0.91,
            class_probabilities={"malicious": 0.91, "suspicious": 0.09},
        )
        final_decision = {
            "final_label": "malicious",
            "final_confidence": 0.91,
            "rule_score": 82,
            "rule_severity": "critical",
            "ml_label": "malicious",
            "ml_confidence": 0.91,
            "triggered_rules": ["openaction-with-javascript"],
            "explanations": ["OpenAction combined with JavaScript can auto-trigger active content."],
        }

        summary = build_analysis_summary(
            parser_output=parser_output,
            features=features,
            rule_result=rule_result,
            ml_result=ml_result,
            final_decision=final_decision,
        )

        self.assertEqual(summary["file_name"], "suspicious.pdf")
        self.assertEqual(summary["final_label"], "malicious")
        self.assertEqual(summary["rule_score"], 82.0)
        self.assertEqual(summary["ml_label"], "malicious")
        self.assertIn("/JavaScript (1)", summary["suspicious_indicators_found"])
        self.assertIn("openaction-with-javascript", summary["triggered_rules"])

    def test_summary_to_json_returns_valid_json(self) -> None:
        """Serialize a summary dictionary into JSON."""
        summary = {
            "file_name": "sample.pdf",
            "file_path": "C:/analysis/sample.pdf",
            "final_label": "suspicious",
            "final_confidence": 0.71,
            "rule_score": 56.0,
            "rule_severity": "high",
            "ml_label": "benign",
            "ml_confidence": 0.84,
            "suspicious_indicators_found": ["/EmbeddedFile (1)"],
            "triggered_rules": ["embedded-file-present"],
            "explanations": ["Embedded payload indicator."],
        }

        json_text = summary_to_json(summary)
        parsed = json.loads(json_text)

        self.assertEqual(parsed["final_label"], "suspicious")
        self.assertEqual(parsed["triggered_rules"], ["embedded-file-present"])

    def test_summary_to_console_text_is_readable_and_safe(self) -> None:
        """Render a concise professional console summary."""
        summary = build_analysis_summary(
            parser_output={
                "file_name": "review.pdf",
                "file_path": "C:/analysis/review.pdf",
                "suspicious_keyword_counts": {"/EmbeddedFile": 1, "/Launch": 1},
            },
            rule_result={
                "risk_score_normalized": 56,
                "severity": "high",
                "triggered_rules": ["embedded-file-present", "launch-action-present"],
                "explanations": [
                    "The PDF contains an embedded file.",
                    "The PDF contains a Launch action.",
                ],
            },
            ml_result={"predicted_label": "suspicious", "confidence": 0.67},
            final_decision={
                "final_label": "suspicious",
                "final_confidence": 0.67,
                "rule_score": 56,
                "rule_severity": "high",
                "ml_label": "suspicious",
                "ml_confidence": 0.67,
                "triggered_rules": ["embedded-file-present", "launch-action-present"],
                "explanations": [
                    "The PDF contains an embedded file.",
                    "The PDF contains a Launch action.",
                ],
            },
        )

        console_text = summary_to_console_text(summary)

        self.assertIn("Advanced PDFSafeScan Analysis Summary", console_text)
        self.assertIn("File Name: review.pdf", console_text)
        self.assertIn("Final Label: suspicious", console_text)
        self.assertIn("- /EmbeddedFile (1)", console_text)
        self.assertIn("- launch-action-present", console_text)
        self.assertIn("- The PDF contains a Launch action.", console_text)

    def test_build_analysis_summary_handles_missing_fields_safely(self) -> None:
        """Return safe defaults when pipeline components are incomplete."""
        summary = build_analysis_summary()

        self.assertEqual(summary["file_name"], "unknown")
        self.assertEqual(summary["final_label"], "unknown")
        self.assertEqual(summary["triggered_rules"], [])
        self.assertEqual(summary["suspicious_indicators_found"], [])
