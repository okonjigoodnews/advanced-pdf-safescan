"""Safe ZIP ingestion helpers for batch PDF analysis."""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath


class ZIPIngestError(Exception):
    """Raised when an uploaded ZIP archive cannot be processed safely."""


@dataclass(slots=True)
class InMemoryPDFUpload:
    """Simple upload-like wrapper for PDFs extracted from a ZIP archive."""

    name: str
    payload: bytes

    def getvalue(self) -> bytes:
        """Return the in-memory file payload."""
        return self.payload


def extract_pdf_uploads_from_zip(uploaded_zip_file: object) -> list[InMemoryPDFUpload]:
    """Extract PDF files from an uploaded ZIP archive into memory."""
    try:
        zip_bytes = uploaded_zip_file.getvalue()
    except AttributeError as exc:
        raise ZIPIngestError("Uploaded ZIP archive could not be read.") from exc

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
            extracted_uploads: list[InMemoryPDFUpload] = []
            for member in archive.infolist():
                if member.is_dir():
                    continue

                normalized_name = _normalize_member_name(member.filename)
                if not normalized_name or not normalized_name.lower().endswith(".pdf"):
                    continue

                extracted_uploads.append(
                    InMemoryPDFUpload(
                        name=normalized_name,
                        payload=archive.read(member),
                    )
                )
            return extracted_uploads
    except (zipfile.BadZipFile, RuntimeError, ValueError) as exc:
        raise ZIPIngestError("The uploaded ZIP archive is invalid or could not be processed.") from exc


def _normalize_member_name(member_name: str) -> str:
    """Normalize an archive member name and drop traversal segments."""
    normalized_path = PurePosixPath(member_name.replace("\\", "/"))
    safe_parts = [part for part in normalized_path.parts if part not in {"", ".", ".."}]
    return "/".join(safe_parts)
