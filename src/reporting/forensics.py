"""Helpers for PDF hashing, verdict guidance, and forensic report assembly."""

from __future__ import annotations

import hashlib
from typing import Any


def compute_sha256(file_bytes: bytes) -> str:
    """Return the SHA-256 hash for a PDF byte payload."""
    return hashlib.sha256(file_bytes).hexdigest()


def recommendation_for_verdict(final_label: str) -> str:
    """Return handling guidance for a final scan verdict."""
    if final_label == "benign":
        return "Safe to open under normal precautions."
    if final_label == "malicious":
        return "Do not open. Quarantine or isolate the file and investigate further."
    return "Open with caution. Prefer isolated viewing and further inspection before trusting the file."


def build_forensic_report(
    *,
    summary: dict[str, Any],
    reader_result: dict[str, Any],
    sha256: str,
    file_size: int,
    recommendation: str,
) -> dict[str, Any]:
    """Build a clean forensic report dictionary for JSON export."""
    metadata = reader_result.get("metadata", {})
    warnings = list(reader_result.get("warnings", []))

    return {
        "sha256": sha256,
        "file_name": str(summary.get("file_name", "unknown")),
        "file_size": int(file_size),
        "final_label": str(summary.get("final_label", "unknown")),
        "final_confidence": _safe_float(summary.get("final_confidence", 0.0)),
        "rule_score": _safe_float(summary.get("rule_score", 0.0)),
        "rule_severity": str(summary.get("rule_severity", "unknown")),
        "ml_label": str(summary.get("ml_label", "unknown")),
        "ml_confidence": _safe_float(summary.get("ml_confidence", 0.0)),
        "suspicious_indicators": list(summary.get("suspicious_indicators_found", [])),
        "triggered_rules": list(summary.get("triggered_rules", [])),
        "explanations": list(summary.get("explanations", [])),
        "metadata_summary": {
            "field_count": int(reader_result.get("metadata_field_count", 0)),
            "fields": dict(metadata if isinstance(metadata, dict) else {}),
        },
        "page_count": int(reader_result.get("page_count", 0)),
        "text_extraction_status": _text_extraction_status(reader_result),
        "safe_reader_warnings": warnings,
        "recommendation": recommendation,
    }


def _text_extraction_status(reader_result: dict[str, Any]) -> str:
    """Return a simple extraction status label for the forensic report."""
    text_extraction_succeeded = bool(reader_result.get("text_extraction_succeeded", False))
    warnings = list(reader_result.get("warnings", []))

    if text_extraction_succeeded and warnings:
        return "partial"
    if text_extraction_succeeded:
        return "success"
    return "limited_or_unavailable"


def _safe_float(value: object, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
