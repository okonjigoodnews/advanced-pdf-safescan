"""Helpers for Chrome extension and API-facing scan responses."""

from __future__ import annotations

from typing import Any


def find_cached_history_record_by_sha256(
    history_records: list[dict[str, Any]],
    sha256: str,
) -> dict[str, Any] | None:
    """Return the newest matching history record for a SHA-256 hash."""
    normalized_sha256 = str(sha256).strip()
    if not normalized_sha256:
        return None

    matches = [
        record for record in history_records
        if str(record.get("sha256", "")).strip() == normalized_sha256
    ]
    if not matches:
        return None

    return sorted(
        matches,
        key=lambda record: str(record.get("timestamp", "")),
        reverse=True,
    )[0]


def build_scan_response_from_analysis(
    analysis_result: dict[str, Any],
    *,
    source_url: str = "",
    cached: bool = False,
    review_record: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an extension/API response from a fresh analysis result."""
    summary = analysis_result.get("summary", {})
    review_fields = _normalize_review_fields(review_record)

    # Pull final_confidence and rule_score from summary directly
    final_confidence = _safe_float(
        summary.get("final_confidence")
        or summary.get("confidence")
        or 0.0
    )
    rule_score = _safe_float(
        summary.get("rule_score")
        or summary.get("risk_score_normalized")
        or 0.0
    )

    return {
        "status": "ok",
        "cached": bool(cached),
        "source_url": source_url,
        "timestamp": str(analysis_result.get("report_timestamp", "")),
        "file_name": str(summary.get("file_name", "unknown")),
        "sha256": str(analysis_result.get("sha256", "")),
        "final_label": str(summary.get("final_label", "unknown")),
        "final_confidence": final_confidence,
        "rule_score": rule_score,
        "rule_severity": str(summary.get("rule_severity", "unknown")),
        "ml_label": str(summary.get("ml_label", "unknown")),
        "ml_confidence": _safe_float(summary.get("ml_confidence", 0.0)),
        "triggered_rules": list(summary.get("triggered_rules", []) or []),
        "explanations": list(summary.get("explanations", []) or []),
        "suspicious_indicators_found": list(summary.get("suspicious_indicators_found", []) or []),
        "recommendation": str(analysis_result.get("recommendation", "")),
        "review_status": review_fields["review_status"],
        "priority": review_fields["priority"],
        "disposition": review_fields["disposition"],
        "analyst_note": review_fields["analyst_note"],
    }


def build_scan_response_from_history_record(
    history_record: dict[str, Any],
    *,
    source_url: str = "",
    cached: bool = True,
    review_record: dict[str, Any] | None = None,
    client_id: str = "",  # FIX: added client_id parameter to match hosted_api.py call
) -> dict[str, Any]:
    """Build an extension/API response from a cached history record."""
    review_fields = _normalize_review_fields(review_record)

    return {
        "status": "ok",
        "cached": bool(cached),
        "source_url": source_url,
        "timestamp": str(history_record.get("timestamp", "")),
        "file_name": str(history_record.get("file_name", "unknown")),
        "sha256": str(history_record.get("sha256", "")),
        "final_label": str(history_record.get("final_label", "unknown")),
        "final_confidence": _safe_float(history_record.get("final_confidence", 0.0)),
        "rule_score": _safe_float(history_record.get("rule_score", 0.0)),
        "rule_severity": str(history_record.get("rule_severity", "unknown")),
        "ml_label": str(history_record.get("ml_label", "unknown")),
        "ml_confidence": _safe_float(history_record.get("ml_confidence", 0.0)),
        "triggered_rules": list(history_record.get("triggered_rules", []) or []),
        "explanations": list(history_record.get("explanations", []) or []),
        "suspicious_indicators_found": list(history_record.get("suspicious_indicators_found", []) or []),
        "recommendation": str(history_record.get("recommendation", "")),
        "review_status": review_fields["review_status"],
        "priority": review_fields["priority"],
        "disposition": review_fields["disposition"],
        "analyst_note": review_fields["analyst_note"],
    }


def build_recent_scan_rows(
    history_records: list[dict[str, Any]],
    review_records_by_sha256: dict[str, dict[str, Any]] | None = None,
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """Build compact recent scan rows for the extension popup."""
    review_records_by_sha256 = review_records_by_sha256 or {}

    sorted_records = sorted(
        history_records,
        key=lambda record: str(record.get("timestamp", "")),
        reverse=True,
    )

    rows: list[dict[str, Any]] = []
    for record in sorted_records[: max(limit, 0)]:
        sha256 = str(record.get("sha256", "")).strip()
        review_fields = _normalize_review_fields(review_records_by_sha256.get(sha256))
        rows.append(
            {
                "timestamp": str(record.get("timestamp", "")),
                "file_name": str(record.get("file_name", "unknown")),
                "sha256": sha256,
                "final_label": str(record.get("final_label", "unknown")),
                "final_confidence": _safe_float(record.get("final_confidence", 0.0)),
                "rule_score": _safe_float(record.get("rule_score", 0.0)),
                "recommendation": str(record.get("recommendation", "")),
                "review_status": review_fields["review_status"],
                "priority": review_fields["priority"],
                "disposition": review_fields["disposition"],
                "analyst_note": review_fields["analyst_note"],
            }
        )
    return rows


def _normalize_review_fields(review_record: dict[str, Any] | None) -> dict[str, str]:
    """Normalize optional analyst review fields."""
    review_record = review_record or {}
    return {
        "review_status": str(review_record.get("review_status", "New")),
        "priority": str(review_record.get("priority", "Medium")),
        "disposition": str(review_record.get("disposition", "")),
        "analyst_note": str(review_record.get("analyst_note", "")),
    }


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
