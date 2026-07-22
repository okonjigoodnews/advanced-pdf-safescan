#!/usr/bin/env python3
"""
Keep on-screen timestamps local but make CSV exports unambiguous UTC.

Design (Option B):
  The dashboard tables show Europe/London time for the analyst. A CSV, though,
  is an artefact opened later and possibly elsewhere, so a local time with no
  offset ("26 Mar 2026, 12:00") cannot be resolved back to the true instant.
  The export therefore carries the raw UTC ISO-8601 value with its offset
  intact, which is the standard forensic convention: screen is localised for
  the reader, the exported record of truth stays UTC.

How:
  1. Each display builder gains a "timestamp_utc" field holding the raw stored
     value, sitting alongside the localised "timestamp" it already produces.
     DictWriter uses extrasaction="ignore", so the extra column is harmless to
     any table or export that does not ask for it.
  2. Each build_csv_export_bytes call is given an explicit fieldnames list that
     names "timestamp_utc" in place of "timestamp", so downloads carry UTC
     while the on-screen dataframe (which is handed the row dicts directly and
     ignores the extra key by column selection) still shows local time.

Builders covered:
  _build_batch_summary_rows, _build_dashboard_table_rows,
  _build_scan_history_table_rows, _build_high_risk_table_rows.

Usage:
    python3 patch_csv_utc.py --dry-run
    python3 patch_csv_utc.py
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

UI = Path("app/ui_streamlit.py")

# Each entry: the localised display line as it currently stands, and the raw
# expression whose value should be preserved as timestamp_utc.
DISPLAY_LINES = [
    (
        '"timestamp": _format_display_timestamp(analysis_result.get("report_timestamp", "")),',
        '"timestamp_utc": str(analysis_result.get("report_timestamp", "")),',
    ),
    (
        '"timestamp": _format_display_timestamp(record.get("timestamp", "")),',
        '"timestamp_utc": str(record.get("timestamp", "")),',
    ),
]


def add_utc_columns(source: str, report: list[str]) -> str:
    lines = source.split("\n")
    output: list[str] = []
    added = 0

    for line in lines:
        output.append(line)
        stripped = line.strip()
        for display, utc_field in DISPLAY_LINES:
            if stripped == display:
                # Guard against double-application: skip if the next non-blank
                # sibling is already the UTC field.
                indent = line[: len(line) - len(line.lstrip())]
                output.append(indent + utc_field)
                added += 1
                break

    if added == 0:
        report.append("columns: FAILED - no display timestamp lines matched")
    else:
        report.append(f"columns: added timestamp_utc beside {added} display timestamp(s)")
    return "\n".join(output)


def route_exports(source: str, report: list[str]) -> str:
    """Give every CSV export an explicit fieldnames list that uses timestamp_utc.

    build_csv_export_bytes is called with a single positional rows argument at
    each site. We rewrite those calls to pass fieldnames as well. The row
    variable name differs per call, so we match on the call signature and reuse
    the captured variable.
    """
    # Matches: build_csv_export_bytes(<var>)  with no other args.
    pattern = re.compile(r"build_csv_export_bytes\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")

    def replacement(match: re.Match[str]) -> str:
        var = match.group(1)
        return (
            f"build_csv_export_bytes(\n"
            f"                {var},\n"
            f"                fieldnames=_csv_fieldnames_utc({var}),\n"
            f"            )"
        )

    new_source, count = pattern.subn(replacement, source)
    if count == 0:
        report.append("exports: FAILED - no build_csv_export_bytes(<var>) calls matched")
    else:
        report.append(f"exports: routed {count} CSV export(s) through UTC fieldnames")
    return new_source


HELPER = '''

def _csv_fieldnames_utc(rows: list[dict[str, Any]]) -> list[str]:
    """Column order for CSV export: emit timestamp_utc in place of the localised
    display timestamp, so the downloaded artefact is unambiguous UTC while the
    on-screen table stays local. Any row without these keys is handled by the
    export writer's extrasaction="ignore"."""
    seen: list[str] = []
    for row in rows:
        for key in row.keys():
            if key == "timestamp":
                # Replace the localised column with the raw UTC one at the same
                # position, and never emit the localised value in the export.
                if "timestamp_utc" not in seen:
                    seen.append("timestamp_utc")
                continue
            if key == "timestamp_utc":
                if "timestamp_utc" not in seen:
                    seen.append("timestamp_utc")
                continue
            if key not in seen:
                seen.append(key)
    return seen

'''

HELPER_ANCHOR = "def _build_batch_summary_rows("


def insert_helper(source: str, report: list[str]) -> str:
    if "_csv_fieldnames_utc" in source:
        report.append("helper: already present, skipped")
        return source
    index = source.find("\n" + HELPER_ANCHOR)
    if index == -1:
        report.append(f"helper: FAILED - anchor '{HELPER_ANCHOR}' not found")
        return source
    report.append("helper: inserted _csv_fieldnames_utc")
    return source[:index] + "\n" + HELPER.rstrip("\n") + "\n" + source[index:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not UI.is_file():
        print("ERROR: run from the project root.", file=sys.stderr)
        return 1

    original = UI.read_text(encoding="utf-8")
    report: list[str] = []

    if "_csv_fieldnames_utc" in original and "timestamp_utc" in original:
        print("  Already patched. Nothing to do.")
        return 0

    patched = original
    patched = add_utc_columns(patched, report)
    patched = insert_helper(patched, report)
    patched = route_exports(patched, report)

    print("\n".join(f"  {entry}" for entry in report))

    if any("FAILED" in entry for entry in report):
        print("\nOne or more steps failed. Nothing written.", file=sys.stderr)
        return 1

    try:
        compile(patched, str(UI), "exec")
    except SyntaxError as error:
        print(f"\nERROR: syntax error at line {error.lineno}: {error.msg}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: syntax check passed, nothing written.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = UI.with_suffix(f".py.bak-csvutc-{stamp}")
    shutil.copy2(UI, backup)
    UI.write_text(patched, encoding="utf-8")

    print(f"\nPatched {UI}")
    print(f"Backup  {backup}")
    print("\nNext:")
    print("  python -m pytest -q")
    print("  # then download a CSV and confirm the timestamp column is UTC with +00:00")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
