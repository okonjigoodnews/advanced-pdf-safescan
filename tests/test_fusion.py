"""Tests for hybrid fusion of rule and ML outputs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.fusion.decision import HybridDecisionLayer
from src.ml.classifier import MLResult


class HybridDecisionLayerTestCase(unittest.TestCase):
    """Validate final decision behavior across agreement and conflict cases."""

    def setUp(self) -> None:
        """Create a fusion layer instance for each test."""
        self.layer = HybridDecisionLayer()

    def test_high_ml_malicious_and_high_rules_becomes_malicious(self) -> None:
        """Return malicious when both signals strongly agree."""
        rule_result = {
            "risk_score_raw": 110,
            "risk_score_normalized": 82,
            "severity": "critical",
            "triggered_rules": ["openaction-with-javascript"],
            "explanations": ["critical active content chain detected"],
        }
        ml_result = MLResult(
            predicted_label="malicious",
            confidence=0.91,
            class_probabilities={"benign": 0.03, "malicious": 0.91, "suspicious": 0.06},
        )

        final = self.layer.combine(rule_result, ml_result)

        self.assertEqual(final["final_label"], "malicious")
        self.assertEqual(final["rule_severity"], "critical")
        self.assertEqual(final["ml_label"], "malicious")
        self.assertGreaterEqual(final["final_confidence"], 0.91)

    def test_benign_ml_and_low_rule_score_becomes_benign(self) -> None:
        """Return benign when both signals support a low-risk decision."""
        rule_result = {
            "risk_score_raw": 0,
            "risk_score_normalized": 5,
            "severity": "low",
            "triggered_rules": [],
            "explanations": [],
        }
        ml_result = MLResult(
            predicted_label="benign",
            confidence=0.88,
            class_probabilities={"benign": 0.88, "suspicious": 0.12},
        )

        final = self.layer.combine(rule_result, ml_result)

        self.assertEqual(final["final_label"], "benign")
        self.assertEqual(final["final_confidence"], 0.95)

    def test_conflict_defaults_to_suspicious(self) -> None:
        """Avoid falling back to benign when signals disagree materially."""
        rule_result = {
            "risk_score_raw": 45,
            "risk_score_normalized": 56,
            "severity": "high",
            "triggered_rules": ["embedded-file-present"],
            "explanations": ["embedded payload indicator"],
        }
        ml_result = {
            "predicted_label": "benign",
            "confidence": 0.84,
            "class_probabilities": {"benign": 0.84, "malicious": 0.16},
        }

        final = self.layer.combine(rule_result, ml_result)

        self.assertEqual(final["final_label"], "suspicious")
        self.assertEqual(final["ml_label"], "benign")
        self.assertEqual(final["triggered_rules"], ["embedded-file-present"])
        self.assertEqual(final["explanations"], ["embedded payload indicator"])

    def test_medium_ml_and_medium_rules_becomes_suspicious(self) -> None:
        """Return suspicious for medium-confidence suspicious evidence."""
        rule_result = {
            "risk_score_raw": 30,
            "risk_score_normalized": 38,
            "severity": "medium",
            "triggered_rules": ["multiple-action-indicators"],
            "explanations": ["several actions observed"],
        }
        ml_result = MLResult(
            predicted_label="suspicious",
            confidence=0.62,
            class_probabilities={"benign": 0.18, "suspicious": 0.62, "malicious": 0.20},
        )

        final = self.layer.combine(rule_result, ml_result)

        self.assertEqual(final["final_label"], "suspicious")
        self.assertEqual(final["rule_score"], 38.0)
        self.assertEqual(final["ml_confidence"], 0.62)
