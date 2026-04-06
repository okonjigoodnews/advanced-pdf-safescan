"""Shared scan dispatcher for PDF and image analysis pipelines."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from app.main import run_pdf_analysis_details
from src.analysis.file_types import FILE_TYPE_IMAGE, FILE_TYPE_PDF, detect_scan_file_type
from src.analysis.image_security import analyze_image_bytes
from src.ml.classifier import MalwareClassifier


def analyze_scan_target(
    *,
    file_bytes: bytes,
    file_name: str,
    content_type: str,
    classifier: MalwareClassifier | None = None,
) -> dict[str, Any]:
    """Dispatch a file scan to the supported PDF or image analysis pipeline."""
    file_type = detect_scan_file_type(
        file_name=file_name,
        content_type=content_type,
        file_bytes=file_bytes,
    )
    if file_type == FILE_TYPE_PDF:
        if classifier is None:
            raise ValueError("The PDF classifier is required for PDF analysis.")
        return analyze_pdf_bytes(file_bytes=file_bytes, file_name=file_name, classifier=classifier)
    if file_type == FILE_TYPE_IMAGE:
        return analyze_image_bytes(file_bytes, file_name=file_name)
    raise ValueError("Unsupported content type. Only PDF and supported image files are accepted.")


def analyze_pdf_bytes(
    *,
    file_bytes: bytes,
    file_name: str,
    classifier: MalwareClassifier,
) -> dict[str, Any]:
    """Analyze PDF bytes through the existing PDF pipeline."""
    temp_pdf_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as temp_file:
            temp_file.write(file_bytes)
            temp_pdf_path = Path(temp_file.name)
        results = run_pdf_analysis_details(temp_pdf_path, classifier)
        summary = {
            **results["summary"],
            "file_name": file_name,
            "file_type": FILE_TYPE_PDF,
        }
        return {
            "summary": summary,
            "results": results,
        }
    finally:
        if temp_pdf_path is not None and temp_pdf_path.exists():
            temp_pdf_path.unlink(missing_ok=True)
