"""Tests for safe ZIP ingestion helpers."""

from __future__ import annotations

import io
import sys
import unittest
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.zip_ingest import ZIPIngestError, extract_pdf_uploads_from_zip


class _FakeUpload:
    """Small upload stub used for ZIP ingestion tests."""

    def __init__(self, name: str, payload: bytes) -> None:
        """Store a fake uploaded filename and byte payload."""
        self.name = name
        self._payload = payload

    def getvalue(self) -> bytes:
        """Return the uploaded bytes."""
        return self._payload


class ZIPIngestTestCase(unittest.TestCase):
    """Validate ZIP-based PDF ingestion for batch analysis."""

    def test_extract_pdf_uploads_from_zip_returns_only_pdfs(self) -> None:
        """Extract only PDF files and ignore other archive members."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as archive:
            archive.writestr("reports/first.pdf", b"%PDF-first")
            archive.writestr("reports/notes.txt", b"ignore me")
            archive.writestr("second.PDF", b"%PDF-second")

        uploaded_zip = _FakeUpload("batch.zip", zip_buffer.getvalue())
        extracted_uploads = extract_pdf_uploads_from_zip(uploaded_zip)

        self.assertEqual([upload.name for upload in extracted_uploads], ["reports/first.pdf", "second.PDF"])
        self.assertEqual(extracted_uploads[0].getvalue(), b"%PDF-first")
        self.assertEqual(extracted_uploads[1].getvalue(), b"%PDF-second")

    def test_extract_pdf_uploads_from_zip_normalizes_traversal_segments(self) -> None:
        """Drop traversal segments from archive member names."""
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as archive:
            archive.writestr("../../unsafe.pdf", b"%PDF-unsafe")
            archive.writestr(r"nested\..\safe.pdf", b"%PDF-safe")

        uploaded_zip = _FakeUpload("batch.zip", zip_buffer.getvalue())
        extracted_uploads = extract_pdf_uploads_from_zip(uploaded_zip)

        self.assertEqual([upload.name for upload in extracted_uploads], ["unsafe.pdf", "nested/safe.pdf"])

    def test_extract_pdf_uploads_from_zip_raises_for_invalid_zip(self) -> None:
        """Raise a clear error for invalid ZIP payloads."""
        uploaded_zip = _FakeUpload("batch.zip", b"not-a-zip")

        with self.assertRaises(ZIPIngestError):
            extract_pdf_uploads_from_zip(uploaded_zip)


if __name__ == "__main__":
    unittest.main()
