"""CSV export helpers for Advanced PDFSafeScan reporting views."""

from __future__ import annotations

import csv
import io
from typing import Any


def build_csv_export_bytes(
    rows: list[dict[str, Any]],
    *,
    fieldnames: list[str] | None = None,
) -> bytes:
    """Build UTF-8 CSV bytes from a list of row dictionaries."""
    resolved_fieldnames = fieldnames or _collect_fieldnames(rows)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=resolved_fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({field: row.get(field, "") for field in resolved_fieldnames})
    return buffer.getvalue().encode("utf-8")


def _collect_fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    """Collect CSV columns in first-seen order across all rows."""
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames
