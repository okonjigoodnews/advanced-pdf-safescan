"""Safe PDF reading helpers for metadata and text preview in the demo UI."""

from __future__ import annotations

from importlib import import_module
from pathlib import Path
from typing import Any, TypedDict


DEFAULT_MAX_TEXT_PAGES = 10
DEFAULT_MAX_CHARS_PER_PAGE = 4000


class PageText(TypedDict):
    """Structured extracted text for one PDF page."""

    page_number: int
    text: str
    extracted: bool


class SafePDFReadResult(TypedDict):
    """Structured safe-reader result returned to the Streamlit demo."""

    file_name: str
    file_path: str
    page_count: int
    metadata: dict[str, str]
    metadata_field_count: int
    text_pages: list[PageText]
    text_preview: str
    text_extraction_succeeded: bool
    warnings: list[str]


class PDFReaderError(Exception):
    """Base exception for safe-reader failures."""


class PDFReaderDependencyError(PDFReaderError):
    """Raised when pypdf is unavailable for safe reading."""


class SafePDFReader:
    """Extract metadata and text safely without auto-opening a PDF."""

    def read(
        self,
        pdf_path: str | Path,
        *,
        max_text_pages: int = DEFAULT_MAX_TEXT_PAGES,
        max_chars_per_page: int = DEFAULT_MAX_CHARS_PER_PAGE,
    ) -> SafePDFReadResult:
        """Return safe metadata and text preview details for one PDF file."""
        path = Path(pdf_path)
        if not path.is_file():
            raise FileNotFoundError(f"PDF file not found: {path}")

        try:
            pdf_module = self._load_pypdf_module()
            pdf_reader_class = getattr(pdf_module, "PdfReader")
            with path.open("rb") as pdf_file:
                reader = pdf_reader_class(pdf_file, strict=False)
                page_count = self._safe_page_count(reader)
                metadata = self._extract_metadata(getattr(reader, "metadata", None))
                text_pages, warnings = self._extract_text_pages(
                    reader,
                    page_count=page_count,
                    max_text_pages=max_text_pages,
                    max_chars_per_page=max_chars_per_page,
                )
                return SafePDFReadResult(
                    file_name=path.name,
                    file_path=str(path.resolve()),
                    page_count=page_count,
                    metadata=metadata,
                    metadata_field_count=len(metadata),
                    text_pages=text_pages,
                    text_preview=self._build_text_preview(text_pages),
                    text_extraction_succeeded=any(page["extracted"] for page in text_pages),
                    warnings=warnings,
                )
        except FileNotFoundError:
            raise
        except PDFReaderDependencyError:
            raise
        except Exception as exc:
            return SafePDFReadResult(
                file_name=path.name,
                file_path=str(path.resolve()),
                page_count=0,
                metadata={},
                metadata_field_count=0,
                text_pages=[],
                text_preview="Text preview unavailable because the PDF could not be safely read.",
                text_extraction_succeeded=False,
                warnings=[f"Safe reader could not extract content: {exc}"],
            )

    def _load_pypdf_module(self) -> Any:
        """Import pypdf lazily so the module remains import-safe."""
        try:
            return import_module("pypdf")
        except ImportError as exc:
            raise PDFReaderDependencyError(
                "pypdf is required for safe PDF reading. Install it from requirements.txt."
            ) from exc

    def _safe_page_count(self, reader: Any) -> int:
        """Return the page count safely."""
        try:
            return len(reader.pages)
        except Exception:
            return 0

    def _extract_metadata(self, metadata: Any) -> dict[str, str]:
        """Extract string metadata fields with non-empty values."""
        if not metadata or not hasattr(metadata, "items"):
            return {}

        extracted: dict[str, str] = {}
        for key, value in metadata.items():
            if value in (None, ""):
                continue
            extracted[str(key)] = str(value)
        return dict(sorted(extracted.items()))

    def _extract_text_pages(
        self,
        reader: Any,
        *,
        page_count: int,
        max_text_pages: int,
        max_chars_per_page: int,
    ) -> tuple[list[PageText], list[str]]:
        """Extract text page by page with safe fallbacks."""
        text_pages: list[PageText] = []
        warnings: list[str] = []

        for page_index in range(min(page_count, max_text_pages)):
            try:
                raw_text = reader.pages[page_index].extract_text() or ""
                normalized_text = self._normalize_text(raw_text)
                text_pages.append(
                    PageText(
                        page_number=page_index + 1,
                        text=normalized_text[:max_chars_per_page],
                        extracted=bool(normalized_text),
                    )
                )
            except Exception as exc:
                warnings.append(f"Text extraction failed on page {page_index + 1}: {exc}")
                text_pages.append(
                    PageText(
                        page_number=page_index + 1,
                        text="[Text extraction failed for this page.]",
                        extracted=False,
                    )
                )

        if page_count > max_text_pages:
            warnings.append(
                f"Text preview was limited to the first {max_text_pages} page(s)."
            )

        return text_pages, warnings

    def _build_text_preview(self, text_pages: list[PageText]) -> str:
        """Join extracted page snippets into one readable preview block."""
        preview_chunks = [
            f"[Page {page['page_number']}]\n{page['text']}".strip()
            for page in text_pages
            if page.get("text")
        ]
        if not preview_chunks:
            return "No readable text could be extracted from this PDF."
        return "\n\n".join(preview_chunks)

    def _normalize_text(self, text: str) -> str:
        """Normalize extracted text into a cleaner preview form."""
        collapsed_lines = [line.strip() for line in text.splitlines()]
        meaningful_lines = [line for line in collapsed_lines if line]
        return "\n".join(meaningful_lines)
