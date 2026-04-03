"""Persistent analyst review helpers for Advanced PDFSafeScan."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.utils.paths import data_dir

DEFAULT_REVIEW_NOTES_PATH = data_dir() / "history" / "analyst_reviews.json"
REVIEW_STATUS_OPTIONS = ("New", "Under Review", "Reviewed", "Escalated")
PRIORITY_OPTIONS = ("Low", "Medium", "High", "Critical")
DISPOSITION_OPTIONS = ("Safe", "Suspicious", "Malicious", "False Positive")


def load_analyst_review_records(
    review_notes_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Load persistent analyst review records from JSON storage."""
    path = Path(review_notes_path) if review_notes_path is not None else DEFAULT_REVIEW_NOTES_PATH
    if not path.is_file():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    if not isinstance(data, list):
        return []

    return [_normalize_review_record(item) for item in data if isinstance(item, dict)]


def load_analyst_reviews_by_sha256(
    review_notes_path: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Load analyst review records keyed by SHA-256."""
    records = load_analyst_review_records(review_notes_path=review_notes_path)
    return {
        str(record.get("sha256", "")): record
        for record in records
        if str(record.get("sha256", "")).strip()
    }


def get_analyst_review_for_sha256(
    sha256: str,
    review_notes_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Return one analyst review record for the given SHA-256 if it exists."""
    normalized_sha256 = str(sha256).strip()
    if not normalized_sha256:
        return None
    return load_analyst_reviews_by_sha256(review_notes_path=review_notes_path).get(normalized_sha256)


def save_analyst_review(
    *,
    file_name: str,
    sha256: str,
    source_timestamp: str,
    analyst_note: str,
    review_status: str,
    priority: str,
    disposition: str,
    review_notes_path: str | Path | None = None,
) -> dict[str, Any]:
    """Create or update a persistent analyst review record."""
    normalized_sha256 = str(sha256).strip()
    if not normalized_sha256:
        raise ValueError("SHA-256 is required to save an analyst review record.")

    path = Path(review_notes_path) if review_notes_path is not None else DEFAULT_REVIEW_NOTES_PATH
    records = load_analyst_review_records(review_notes_path=path)
    record = _normalize_review_record(
        {
            "file_name": file_name,
            "sha256": normalized_sha256,
            "source_timestamp": source_timestamp,
            "analyst_note": analyst_note,
            "review_status": review_status,
            "priority": priority,
            "disposition": disposition,
            "updated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        }
    )

    updated_records: list[dict[str, Any]] = []
    replaced_existing_record = False
    for existing_record in records:
        if str(existing_record.get("sha256", "")) == normalized_sha256:
            updated_records.append(record)
            replaced_existing_record = True
        else:
            updated_records.append(existing_record)
    if not replaced_existing_record:
        updated_records.append(record)

    _write_review_records(path, updated_records)
    return record


def _write_review_records(path: Path, records: list[dict[str, Any]]) -> None:
    """Write analyst review records to disk."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def _normalize_review_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize one analyst review record loaded from or written to disk."""
    review_status = _normalize_option(
        value=record.get("review_status", REVIEW_STATUS_OPTIONS[0]),
        allowed_values=REVIEW_STATUS_OPTIONS,
        default=REVIEW_STATUS_OPTIONS[0],
    )
    priority = _normalize_option(
        value=record.get("priority", PRIORITY_OPTIONS[1]),
        allowed_values=PRIORITY_OPTIONS,
        default=PRIORITY_OPTIONS[1],
    )
    disposition = _normalize_option(
        value=record.get("disposition", DISPOSITION_OPTIONS[1]),
        allowed_values=DISPOSITION_OPTIONS,
        default=DISPOSITION_OPTIONS[1],
    )
    return {
        "file_name": str(record.get("file_name", "unknown")),
        "sha256": str(record.get("sha256", "")).strip(),
        "source_timestamp": str(record.get("source_timestamp", "")),
        "analyst_note": str(record.get("analyst_note", "")).strip(),
        "review_status": review_status,
        "priority": priority,
        "disposition": disposition,
        "updated_at": str(record.get("updated_at", "")),
    }


def _normalize_option(
    *,
    value: Any,
    allowed_values: tuple[str, ...],
    default: str,
) -> str:
    """Normalize one configured analyst-review option."""
    normalized_value = str(value).strip().casefold()
    allowed_lookup = {allowed_value.casefold(): allowed_value for allowed_value in allowed_values}
    return allowed_lookup.get(normalized_value, default)
