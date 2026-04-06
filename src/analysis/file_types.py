"""Helpers for supported file-type detection and scan routing."""

from __future__ import annotations

from pathlib import Path
from typing import Final
from urllib.parse import urlparse

FILE_TYPE_PDF: Final[str] = "pdf"
FILE_TYPE_IMAGE: Final[str] = "image"
SUPPORTED_IMAGE_EXTENSIONS: Final[tuple[str, ...]] = (".png", ".jpg", ".jpeg", ".webp", ".gif")
SUPPORTED_IMAGE_MIME_TYPES: Final[tuple[str, ...]] = (
    "image/png",
    "image/jpeg",
    "image/webp",
    "image/gif",
)
SUPPORTED_SCAN_EXTENSIONS: Final[tuple[str, ...]] = (".pdf", *SUPPORTED_IMAGE_EXTENSIONS)


def detect_scan_file_type(*, file_name: str = "", content_type: str = "", file_bytes: bytes = b"") -> str:
    """Detect the supported scan file type from filename, MIME type, and magic bytes."""
    normalized_file_name = str(file_name or "").strip().lower()
    normalized_content_type = str(content_type or "").strip().lower().split(";", 1)[0]

    if looks_like_pdf(file_name=normalized_file_name, content_type=normalized_content_type, file_bytes=file_bytes):
        return FILE_TYPE_PDF
    if looks_like_image(
        file_name=normalized_file_name,
        content_type=normalized_content_type,
        file_bytes=file_bytes,
    ):
        return FILE_TYPE_IMAGE
    return ""


def looks_like_pdf(*, file_name: str = "", content_type: str = "", file_bytes: bytes = b"") -> bool:
    """Return True when a file appears to be a PDF."""
    return (
        str(file_name).lower().endswith(".pdf")
        or "pdf" in str(content_type).lower()
        or bytes(file_bytes[:5]) == b"%PDF-"
    )


def looks_like_image(*, file_name: str = "", content_type: str = "", file_bytes: bytes = b"") -> bool:
    """Return True when a file appears to be a supported image type."""
    normalized_name = str(file_name).lower()
    normalized_type = str(content_type).lower()
    suffix = Path(normalized_name).suffix
    return (
        suffix in SUPPORTED_IMAGE_EXTENSIONS
        or normalized_type in SUPPORTED_IMAGE_MIME_TYPES
        or sniff_image_format(file_bytes) in {"PNG", "JPEG", "WEBP", "GIF"}
    )


def sniff_image_format(file_bytes: bytes) -> str:
    """Inspect magic bytes to detect a supported image format."""
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if file_bytes.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        return "WEBP"
    return ""


def is_supported_image_filename(file_name: str | None) -> bool:
    """Return True when a filename has a supported image extension."""
    return Path(str(file_name or "")).suffix.lower() in SUPPORTED_IMAGE_EXTENSIONS


def is_supported_scan_filename(file_name: str | None) -> bool:
    """Return True when a filename has a supported PDF or image extension."""
    return Path(str(file_name or "")).suffix.lower() in SUPPORTED_SCAN_EXTENSIONS


def is_supported_image_url(url: str) -> bool:
    """Return True when a URL path appears to target a supported image file."""
    return Path(urlparse(str(url or "")).path.lower()).suffix in SUPPORTED_IMAGE_EXTENSIONS


def is_supported_scan_url(url: str) -> bool:
    """Return True when a URL path appears to target a supported PDF or image file."""
    return Path(urlparse(str(url or "")).path.lower()).suffix in SUPPORTED_SCAN_EXTENSIONS
