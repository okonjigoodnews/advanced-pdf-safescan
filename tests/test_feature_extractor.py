"""Tests for PDF feature engineering."""

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


class PDFFeatureExtractorTestCase(unittest.TestCase):
    """Validate stable feature extraction from parsed PDF output."""

    def setUp(self) -> None:
        """Create a fresh extractor for each test."""
        self.extractor = PDFFeatureExtractor()

    def test_extract_returns_flat_feature_dictionary(self) -> None:
        """Map parser output into the expected boolean, numeric, and derived features."""
        parsed_pdf = {
            "file_name": "sample.pdf",
            "file_path": "C:/analysis/sample.pdf",
            "file_size": 4096,
            "page_count": 2,
            "is_encrypted": False,
            "metadata_fields_present": ["/Author", "/Title"],
            "metadata_field_count": 2,
            "suspicious_keyword_counts": {
                "/JavaScript": 1,
                "/JS": 0,
                "/OpenAction": 1,
                "/AA": 1,
                "/Launch": 1,
                "/URI": 2,
                "/EmbeddedFile": 1,
                "/Encrypt": 1,
                "/ObjStm": 3,
                "/RichMedia": 0,
                "/AcroForm": 1,
            },
            "suspicious_keyword_total": 11,
        }

        features = self.extractor.extract(parsed_pdf)

        self.assertEqual(features["file_size"], 4096)
        self.assertEqual(features["page_count"], 2)
        self.assertEqual(features["metadata_field_count"], 2)
        self.assertEqual(features["suspicious_keyword_total"], 11)
        self.assertFalse(features["is_encrypted"])
        self.assertTrue(features["has_javascript"])
        self.assertFalse(features["has_js"])
        self.assertTrue(features["has_openaction"])
        self.assertTrue(features["has_aa"])
        self.assertTrue(features["has_launch"])
        self.assertTrue(features["has_uri"])
        self.assertTrue(features["has_embeddedfile"])
        self.assertTrue(features["has_encrypt"])
        self.assertTrue(features["has_objstm"])
        self.assertFalse(features["has_richmedia"])
        self.assertTrue(features["has_acroform"])
        self.assertEqual(features["javascript_count"], 1)
        self.assertEqual(features["uri_count"], 2)
        self.assertEqual(features["objstm_count"], 3)
        self.assertEqual(features["action_keyword_total"], 5)
        self.assertEqual(features["embedded_or_script_total"], 2)
        self.assertEqual(features["stream_like_keyword_total"], 4)
        self.assertEqual(features["high_risk_keyword_total"], 6)
        self.assertEqual(features["keyword_density_per_page"], 5.5)

    def test_extract_uses_safe_defaults_for_missing_values(self) -> None:
        """Return zeroed features and avoid divide-by-zero when keys are absent."""
        features = self.extractor.extract({})

        self.assertEqual(features["file_size"], 0)
        self.assertEqual(features["page_count"], 0)
        self.assertEqual(features["metadata_field_count"], 0)
        self.assertEqual(features["suspicious_keyword_total"], 0)
        self.assertFalse(features["is_encrypted"])
        self.assertFalse(features["has_javascript"])
        self.assertEqual(features["javascript_count"], 0)
        self.assertEqual(features["action_keyword_total"], 0)
        self.assertEqual(features["embedded_or_script_total"], 0)
        self.assertEqual(features["stream_like_keyword_total"], 0)
        self.assertEqual(features["high_risk_keyword_total"], 0)
        self.assertEqual(features["keyword_density_per_page"], 0.0)

    def test_parser_output_flows_cleanly_into_feature_extraction(self) -> None:
        """Ensure parser output can be passed directly into the feature extractor."""
        pdf_bytes = (
            b"%PDF-1.7\n"
            b"/JavaScript /OpenAction /URI /ObjStm /AcroForm\n"
            b"%%EOF"
        )
        parser = PDFParser()
        pdf_path = Path("integration.pdf")
        resolved_path = Path("C:/analysis/integration.pdf")

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
                "is_encrypted": False,
                "metadata_fields_present": ["/Producer"],
            },
        ):
            parsed_pdf = parser.parse(PDFSample(path=pdf_path))

        features = self.extractor.extract(parsed_pdf)

        self.assertEqual(features["page_count"], 1)
        self.assertEqual(features["metadata_field_count"], 1)
        self.assertEqual(features["javascript_count"], 1)
        self.assertEqual(features["openaction_count"], 1)
        self.assertEqual(features["uri_count"], 1)
        self.assertEqual(features["objstm_count"], 1)
        self.assertEqual(features["acroform_count"], 1)
        self.assertEqual(features["suspicious_keyword_total"], 5)
        self.assertEqual(features["keyword_density_per_page"], 5.0)
