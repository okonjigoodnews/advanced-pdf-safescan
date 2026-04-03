"""Tests for explainable rule-based PDF scoring."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.extractor import PDFFeatureExtractor
from src.ingestion.loader import PDFSample
from src.parser.document_parser import PDFParser
from src.rules.engine import RuleEngine


class RuleEngineTestCase(unittest.TestCase):
    """Validate transparent scoring behavior for suspicious PDF features."""

    def setUp(self) -> None:
        """Create reusable pipeline components for each test."""
        self.extractor = PDFFeatureExtractor()
        self.engine = RuleEngine()

    def test_evaluate_returns_low_risk_for_benign_defaults(self) -> None:
        """Return a low score when no suspicious indicators are present."""
        result = self.engine.evaluate(self.extractor.extract({}))

        self.assertEqual(result["risk_score_raw"], 0)
        self.assertEqual(result["risk_score_normalized"], 0)
        self.assertEqual(result["severity"], "low")
        self.assertEqual(result["triggered_rules"], [])
        self.assertEqual(result["explanations"], [])

    def test_evaluate_returns_high_score_for_suspicious_feature_set(self) -> None:
        """Trigger multiple rules for an obviously suspicious feature dictionary."""
        features = {
            "has_javascript": True,
            "has_js": False,
            "has_openaction": True,
            "has_aa": True,
            "has_launch": True,
            "has_uri": True,
            "has_embeddedfile": True,
            "has_encrypt": True,
            "has_objstm": True,
            "has_richmedia": False,
            "has_acroform": True,
            "is_encrypted": True,
            "file_size": 4096,
            "page_count": 2,
            "metadata_field_count": 1,
            "suspicious_keyword_total": 12,
            "javascript_count": 1,
            "js_count": 0,
            "openaction_count": 1,
            "aa_count": 1,
            "launch_count": 1,
            "uri_count": 2,
            "embeddedfile_count": 1,
            "encrypt_count": 1,
            "objstm_count": 2,
            "richmedia_count": 0,
            "acroform_count": 1,
            "action_keyword_total": 5,
            "embedded_or_script_total": 2,
            "stream_like_keyword_total": 3,
            "high_risk_keyword_total": 6,
            "keyword_density_per_page": 6.0,
        }

        result = self.engine.evaluate(features)

        self.assertGreater(result["risk_score_raw"], 0)
        self.assertGreaterEqual(result["risk_score_normalized"], 75)
        self.assertEqual(result["severity"], "critical")
        self.assertIn("launch-action-present", result["triggered_rules"])
        self.assertIn("openaction-with-javascript", result["triggered_rules"])
        self.assertIn("embedded-file-present", result["triggered_rules"])
        self.assertIn("high-suspicious-keyword-volume", result["triggered_rules"])
        self.assertIn("high-high-risk-keyword-volume", result["triggered_rules"])
        self.assertIn("encrypted-with-active-indicators", result["triggered_rules"])
        self.assertIn("multiple-action-indicators", result["triggered_rules"])
        self.assertTrue(any("Launch action" in text for text in result["explanations"]))

    def test_parser_and_features_feed_rule_engine_cleanly(self) -> None:
        """Ensure the parser, extractor, and rule engine compose without glue code."""
        pdf_bytes = (
            b"%PDF-1.7\n"
            b"/JavaScript /OpenAction /Launch /EmbeddedFile /URI /AA /AcroForm\n"
            b"%%EOF"
        )
        parser = PDFParser()
        pdf_path = Path("suspicious.pdf")
        resolved_path = Path("C:/analysis/suspicious.pdf")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "read_bytes", return_value=pdf_bytes
        ), patch.object(
            Path, "stat", return_value=SimpleNamespace(st_size=len(pdf_bytes))
        ), patch.object(
            Path, "resolve", return_value=resolved_path
        ), patch.object(
            PDFParser,
            "_inspect_with_pypdf",
            return_value={
                "page_count": 1,
                "is_encrypted": True,
                "metadata_fields_present": ["/Producer"],
            },
        ):
            parsed_pdf = parser.parse(PDFSample(path=pdf_path))

        features = self.extractor.extract(parsed_pdf)
        result = self.engine.evaluate(features)

        self.assertEqual(features["suspicious_keyword_total"], 7)
        self.assertGreater(result["risk_score_raw"], 0)
        self.assertIn("launch-action-present", result["triggered_rules"])
        self.assertIn("openaction-with-javascript", result["triggered_rules"])
        self.assertIn("embedded-file-present", result["triggered_rules"])
        self.assertIn("encrypted-with-active-indicators", result["triggered_rules"])
