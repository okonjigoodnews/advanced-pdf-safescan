"""Safe structural PDF parsing helpers built around pypdf."""

from __future__ import annotations

import re
from importlib import import_module
from pathlib import Path
from typing import Any, TypedDict

from src.ingestion.loader import PDFSample


SUSPICIOUS_KEYWORDS: tuple[str, ...] = (
    "/JavaScript",
    "/JS",
    "/OpenAction",
    "/AA",
    "/Launch",
    "/URI",
    "/EmbeddedFile",
    "/Encrypt",
    "/ObjStm",
    "/RichMedia",
    "/AcroForm",
)


class ParsedPDF(TypedDict):
    """Dictionary returned after safe PDF inspection."""

    file_name: str
    file_path: str
    file_size: int
    page_count: int
    is_encrypted: bool
    metadata_fields_present: list[str]
    metadata_field_count: int
    suspicious_keyword_counts: dict[str, int]
    suspicious_keyword_total: int


class PDFParserError(Exception):
    """Base exception for parser-specific failures."""


class PDFDependencyError(PDFParserError):
    """Raised when the required PDF dependency is unavailable."""


class PDFMalformedError(PDFParserError):
    """Raised when a PDF cannot be parsed safely."""


class PDFEncryptedError(PDFParserError):
    """Raised when an encrypted PDF cannot be inspected fully."""


class PDFParser:
    """Inspect PDF files safely without executing embedded content."""

    def parse(self, pdf_input: str | Path | PDFSample) -> ParsedPDF:
        """Parse a PDF path and return a structured dictionary of indicators."""
        path = self._resolve_path(pdf_input)
        if not path.is_file():
            raise FileNotFoundError(f"PDF file not found: {path}")

        raw_bytes = path.read_bytes()
        inspection = self._inspect_with_pypdf(path)
        keyword_counts = self._count_suspicious_keywords(raw_bytes)

        return ParsedPDF(
            file_name=path.name,
            file_path=str(path.resolve()),
            file_size=path.stat().st_size,
            page_count=inspection["page_count"],
            is_encrypted=inspection["is_encrypted"],
            metadata_fields_present=inspection["metadata_fields_present"],
            metadata_field_count=len(inspection["metadata_fields_present"]),
            suspicious_keyword_counts=keyword_counts,
            suspicious_keyword_total=sum(keyword_counts.values()),
        )

    def read_raw_indicators(self, pdf_input: str | Path | PDFSample) -> ParsedPDF:
        """Return raw-byte indicators when full structural parsing is not possible."""
        path = self._resolve_path(pdf_input)
        if not path.is_file():
            raise FileNotFoundError(f"PDF file not found: {path}")

        raw_bytes = path.read_bytes()
        keyword_counts = self._count_suspicious_keywords(raw_bytes)

        return ParsedPDF(
            file_name=path.name,
            file_path=str(path.resolve()),
            file_size=path.stat().st_size,
            page_count=0,
            is_encrypted=False,
            metadata_fields_present=[],
            metadata_field_count=0,
            suspicious_keyword_counts=keyword_counts,
            suspicious_keyword_total=sum(keyword_counts.values()),
        )

    def _resolve_path(self, pdf_input: str | Path | PDFSample) -> Path:
        """Normalize supported parser inputs to a filesystem path."""
        if isinstance(pdf_input, PDFSample):
            return pdf_input.path
        return Path(pdf_input)

    def _inspect_with_pypdf(self, path: Path) -> dict[str, Any]:
        """Read structural PDF details through pypdf."""
        pdf_module = self._load_pypdf_module()
        pdf_reader_class = getattr(pdf_module, "PdfReader")
        pdf_read_error = getattr(pdf_module.errors, "PdfReadError", Exception)

        try:
            with path.open("rb") as pdf_file:
                reader = pdf_reader_class(pdf_file, strict=False)
                is_encrypted = bool(getattr(reader, "is_encrypted", False))

                if is_encrypted and hasattr(reader, "decrypt"):
                    try:
                        reader.decrypt("")
                    except Exception:
                        pass

                try:
                    page_count = len(reader.pages)
                    metadata_fields = self._extract_metadata_fields(
                        getattr(reader, "metadata", None)
                    )
                except Exception as exc:
                    if is_encrypted:
                        raise PDFEncryptedError(
                            f"Encrypted PDF could not be fully inspected: {path}"
                        ) from exc
                    raise PDFMalformedError(
                        f"Malformed or unreadable PDF: {path}"
                    ) from exc
        except PDFParserError:
            raise
        except pdf_read_error as exc:
            raise PDFMalformedError(f"Malformed or unreadable PDF: {path}") from exc
        except FileNotFoundError:
            raise
        except Exception as exc:
            raise PDFMalformedError(f"Malformed or unreadable PDF: {path}") from exc

        return {
            "page_count": page_count,
            "is_encrypted": is_encrypted,
            "metadata_fields_present": metadata_fields,
        }

    def _load_pypdf_module(self) -> Any:
        """Import and return the pypdf module lazily."""
        try:
            return import_module("pypdf")
        except ImportError as exc:
            raise PDFDependencyError(
                "pypdf is required to inspect PDF structure. Install it from requirements.txt."
            ) from exc

    def _extract_metadata_fields(self, metadata: Any) -> list[str]:
        """Return a sorted list of metadata field names with non-empty values."""
        if not metadata or not hasattr(metadata, "items"):
            return []

        present_fields: list[str] = []
        for key, value in metadata.items():
            if value not in (None, ""):
                present_fields.append(str(key))
        return sorted(present_fields)

    def _count_suspicious_keywords(self, raw_bytes: bytes) -> dict[str, int]:
        """Count suspicious PDF name tokens in raw file bytes."""
        counts: dict[str, int] = {}
        for keyword in SUSPICIOUS_KEYWORDS:
            counts[keyword] = self._count_keyword_occurrences(raw_bytes, keyword.encode())
        return counts

    def _count_keyword_occurrences(self, raw_bytes: bytes, keyword: bytes) -> int:
        """Count whole suspicious keyword tokens in raw bytes."""
        pattern = re.compile(rb"(?<![A-Za-z0-9])" + re.escape(keyword) + rb"(?![A-Za-z0-9])")
        return len(pattern.findall(raw_bytes))
