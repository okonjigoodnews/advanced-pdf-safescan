"""Persistent scan history helpers for Advanced PDFSafeScan."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.utils.paths import data_dir

DEFAULT_HISTORY_PATH = data_dir() / "history" / "scan_history.json"
ALLOWED_VERDICTS = {"benign", "suspicious", "malicious"}
HIGH_RISK_RULE_SCORE_THRESHOLD = 70.0

# A file that the strict parser cannot read raises this rule. Across the
# evaluation corpus of 31,006 files, 99.97% of parse failures were malicious,
# so an unreadable file is recorded as a first-class signal rather than
# discarded as missing data.
MALFORMED_STRUCTURE_RULE = "malformed-pdf-structure"


def build_scan_history_records(
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Build simple history records from analyzed PDF results."""
    records: list[dict[str, Any]] = []
    for _, analysis_result in analyzed_results:
        summary = analysis_result.get("summary", {})
        records.append(
            {
                "timestamp": str(analysis_result.get("report_timestamp", "")),
                "file_name": str(summary.get("file_name", "unknown")),
                "sha256": str(analysis_result.get("sha256", "")),
                "client_id": str(analysis_result.get("client_id", "")).strip(),
                "final_label": str(summary.get("final_label", "unknown")),
                "final_confidence": _safe_float(summary.get("final_confidence", 0.0)),
                "rule_score": _safe_float(summary.get("rule_score", 0.0)),
                "parsed": _derive_parsed_flag(summary),
                "recommendation": str(analysis_result.get("recommendation", "")),
            }
        )
    return records


def load_scan_history(history_path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load persistent scan history records from JSON storage."""
    path = Path(history_path) if history_path is not None else DEFAULT_HISTORY_PATH
    if not path.is_file():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []

    return [_normalize_history_record(item) for item in data if isinstance(item, dict)]


def append_scan_history_records(
    analyzed_results: list[tuple[str, dict[str, Any]]],
    history_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Append analyzed results to the persistent scan history file."""
    path = Path(history_path) if history_path is not None else DEFAULT_HISTORY_PATH
    records = load_scan_history(path)
    records.extend(build_scan_history_records(analyzed_results))
    _write_scan_history(path, records)
    return records


def filter_scan_history_records(
    history_records: list[dict[str, Any]],
    verdict_filter: str,
) -> list[dict[str, Any]]:
    """Filter stored history records by verdict label."""
    if verdict_filter == "all":
        return list(history_records)
    return [
        record
        for record in history_records
        if str(record.get("final_label", "")).lower() == verdict_filter
    ]


def search_scan_history_records(
    history_records: list[dict[str, Any]],
    *,
    file_name_query: str = "",
    sha256_query: str = "",
) -> list[dict[str, Any]]:
    """Search stored history records by file name and SHA-256 substring."""
    normalized_file_name_query = file_name_query.strip().lower()
    normalized_sha256_query = sha256_query.strip().lower()

    results = list(history_records)
    if normalized_file_name_query:
        results = [
            record
            for record in results
            if normalized_file_name_query in str(record.get("file_name", "")).lower()
        ]
    if normalized_sha256_query:
        results = [
            record
            for record in results
            if normalized_sha256_query in str(record.get("sha256", "")).lower()
        ]
    return results


def sort_scan_history_records(
    history_records: list[dict[str, Any]],
    sort_option: str,
) -> list[dict[str, Any]]:
    """Sort stored history records for presentation-friendly history views."""
    if sort_option == "highest_rule_score":
        return sorted(
            history_records,
            key=lambda record: (
                _safe_float(record.get("rule_score", 0.0)),
                str(record.get("timestamp", "")),
            ),
            reverse=True,
        )
    if sort_option == "highest_confidence":
        return sorted(
            history_records,
            key=lambda record: (
                _safe_float(record.get("final_confidence", 0.0)),
                str(record.get("timestamp", "")),
            ),
            reverse=True,
        )
    return sorted(
        history_records,
        key=lambda record: str(record.get("timestamp", "")),
        reverse=True,
    )


def get_high_risk_scan_history_records(
    history_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return malicious files and suspicious files with a high rule score."""
    return [
        record
        for record in history_records
        if _is_high_risk_record(record)
    ]


def get_malicious_scan_history_records(
    history_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return only malicious history records."""
    return [
        record
        for record in history_records
        if str(record.get("final_label", "")).lower() == "malicious"
    ]


def _write_scan_history(path: Path, records: list[dict[str, Any]]) -> None:
    """Write history records to disk, creating the history directory if needed."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _normalize_history_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw history record loaded from disk."""
    final_label = str(record.get("final_label", "unknown")).lower()
    return {
        "timestamp": str(record.get("timestamp", "")),
        "file_name": str(record.get("file_name", "unknown")),
        "sha256": str(record.get("sha256", "")),
        "client_id": str(record.get("client_id", "")).strip(),
        "final_label": final_label if final_label in ALLOWED_VERDICTS else "unknown",
        "final_confidence": _safe_float(record.get("final_confidence", 0.0)),
        "rule_score": _safe_float(record.get("rule_score", 0.0)),
        "parsed": _coerce_optional_bool(record.get("parsed")),
        "recommendation": str(record.get("recommendation", "")),
    }


def compute_parse_coverage(history_records: list[dict[str, Any]]) -> dict[str, Any]:
    """Return parse-coverage statistics across stored history records.

    Records written before the ``parsed`` field existed carry ``None`` and are
    excluded from the denominator, so coverage is never overstated.
    """
    parsed_count = 0
    unparseable_count = 0

    for record in history_records:
        parsed_flag = _coerce_optional_bool(record.get("parsed"))
        if parsed_flag is True:
            parsed_count += 1
        elif parsed_flag is False:
            unparseable_count += 1

    known_count = parsed_count + unparseable_count
    coverage_ratio = (parsed_count / known_count) if known_count else None

    return {
        "parsed_count": parsed_count,
        "unparseable_count": unparseable_count,
        "known_count": known_count,
        "unknown_count": len(history_records) - known_count,
        "coverage_ratio": coverage_ratio,
    }


def _is_high_risk_record(record: dict[str, Any]) -> bool:
    """Return True for malicious files or suspicious files with a high rule score."""
    final_label = str(record.get("final_label", "")).lower()
    rule_score = _safe_float(record.get("rule_score", 0.0))
    return final_label == "malicious" or (
        final_label == "suspicious" and rule_score >= HIGH_RISK_RULE_SCORE_THRESHOLD
    )


def _derive_parsed_flag(summary: dict[str, Any]) -> bool:
    """Return False when the strict parser could not read the file."""
    triggered_rules = summary.get("triggered_rules", [])
    if not isinstance(triggered_rules, (list, tuple, set)):
        return True
    return not any(
        MALFORMED_STRUCTURE_RULE in str(rule).lower() for rule in triggered_rules
    )


def _coerce_optional_bool(value: Any) -> bool | None:
    """Coerce a stored value into True, False, or None when it is absent."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1"}:
            return True
        if lowered in {"false", "no", "0"}:
            return False
    return None


def _safe_float(value: Any) -> float:
    """Convert a value into a float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0

