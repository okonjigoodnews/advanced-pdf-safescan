"""Tests for safe PDF reader helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, mock_open, patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.pdf_reader import SafePDFReader


class SafePDFReaderTestCase(unittest.TestCase):
    """Validate safe PDF reading for metadata and text preview."""

    def setUp(self) -> None:
        """Create a fresh reader instance for each test."""
        self.reader = SafePDFReader()

    def test_read_extracts_metadata_and_text_preview(self) -> None:
        """Return metadata and page text when the PDF is readable."""
        fake_page_one = MagicMock()
        fake_page_one.extract_text.return_value = "Page one text\n\nwith gaps."
        fake_page_two = MagicMock()
        fake_page_two.extract_text.return_value = "Second page text."
        fake_pdf_reader = MagicMock()
        fake_pdf_reader.pages = [fake_page_one, fake_page_two]
        fake_pdf_reader.metadata = {"/Author": "Analyst", "/Title": "Sample"}
        fake_pdf_module = MagicMock()
        fake_pdf_module.PdfReader.return_value = fake_pdf_reader
        pdf_path = Path("sample.pdf")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "resolve", return_value=Path("C:/analysis/sample.pdf")
        ), patch.object(
            SafePDFReader, "_load_pypdf_module", return_value=fake_pdf_module
        ), patch(
            "pathlib.Path.open",
            mock_open(read_data=b"%PDF-1.7"),
        ):
            result = self.reader.read(pdf_path)

        self.assertEqual(result["file_name"], "sample.pdf")
        self.assertEqual(result["page_count"], 2)
        self.assertEqual(result["metadata"]["/Author"], "Analyst")
        self.assertTrue(result["text_extraction_succeeded"])
        self.assertIn("[Page 1]", result["text_preview"])
        self.assertEqual(result["warnings"], [])

    def test_read_returns_safe_fallback_when_pdf_cannot_be_read(self) -> None:
        """Return a safe fallback result when the reader cannot open the PDF."""
        pdf_path = Path("broken.pdf")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "resolve", return_value=Path("C:/analysis/broken.pdf")
        ), patch.object(
            SafePDFReader, "_load_pypdf_module", side_effect=RuntimeError("boom")
        ):
            result = self.reader.read(pdf_path)

        self.assertEqual(result["file_name"], "broken.pdf")
        self.assertEqual(result["page_count"], 0)
        self.assertFalse(result["text_extraction_succeeded"])
        self.assertIn("could not extract content", result["warnings"][0])

    def test_read_marks_page_level_text_extraction_failures(self) -> None:
        """Keep going when one page fails text extraction."""
        bad_page = MagicMock()
        bad_page.extract_text.side_effect = ValueError("bad page")
        good_page = MagicMock()
        good_page.extract_text.return_value = "Recovered text."
        fake_pdf_reader = MagicMock()
        fake_pdf_reader.pages = [bad_page, good_page]
        fake_pdf_reader.metadata = {}
        fake_pdf_module = MagicMock()
        fake_pdf_module.PdfReader.return_value = fake_pdf_reader
        pdf_path = Path("mixed.pdf")

        with patch.object(Path, "is_file", return_value=True), patch.object(
            Path, "resolve", return_value=Path("C:/analysis/mixed.pdf")
        ), patch.object(
            SafePDFReader, "_load_pypdf_module", return_value=fake_pdf_module
        ), patch(
            "pathlib.Path.open",
            mock_open(read_data=b"%PDF-1.7"),
        ):
            result = self.reader.read(pdf_path)

        self.assertEqual(result["page_count"], 2)
        self.assertEqual(result["text_pages"][0]["text"], "[Text extraction failed for this page.]")
        self.assertTrue(any("page 1" in warning for warning in result["warnings"]))
        self.assertTrue(any(page["extracted"] for page in result["text_pages"]))


if __name__ == "__main__":
    unittest.main()
