#!/usr/bin/env python3
"""
Localise every displayed timestamp in app/ui_streamlit.py to Europe/London.

Root cause of the one-hour offset:
  _build_live_status_summary called latest_timestamp.astimezone() with no
  argument, which converts to the *server's* local timezone. Render runs in
  UTC, so during British Summer Time the dashboard read an hour behind. The
  fix converts to a named zone instead, so the display follows the clock
  change on 25 October by itself.

What this changes:
  1. Adds _to_display_timezone() and _format_display_timestamp() helpers.
  2. Fixes the bare .astimezone() call so the Last Scan chip is correct at
     source rather than being corrected downstream.
  3. Formats the timestamp column in the history and high-risk table builders,
     so the tables agree with the chip.

What this deliberately does not change:
  The stored records. report_timestamp is written as an ISO string with an
  explicit offset, which is unambiguous and correct for an audit trail. Only
  the presentation layer is localised. The sort key at line ~1126 and the
  SHA-256 and filename searches operate on raw records upstream of these
  builders, so they are untouched.

Note on the CSV export:
  If the download is generated from these display rows, the exported times
  become local as well. For a forensic artefact you may prefer the export to
  stay in UTC with its offset intact. Check after applying, and say so if you
  want the export split back out.

Usage:
    python3 patch_localise_time.py --dry-run
    python3 patch_localise_time.py
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("app/ui_streamlit.py")

HELPERS_ANCHOR = "def _shorten_scan_timestamp("

# Only these builders produce rows for on-screen tables. Every other place the
# timestamp field is assembled feeds a stored record and must not be reformatted.
DISPLAY_BUILDERS = {
    "_build_scan_history_table_rows",
    "_build_high_risk_table_rows",
}

TIMESTAMP_FIELD_OLD = '"timestamp": str(record.get("timestamp", "")),'
TIMESTAMP_FIELD_NEW = '"timestamp": _format_display_timestamp(record.get("timestamp", "")),'

ASTIMEZONE_OLD = 'last_scan_display = latest_timestamp.astimezone().strftime("%Y-%m-%d %H:%M")'
ASTIMEZONE_NEW = (
    'last_scan_display = _to_display_timezone(latest_timestamp).strftime("%Y-%m-%d %H:%M")'
)

HELPERS = '''_DISPLAY_TIMEZONE = "Europe/London"


def _to_display_timezone(moment: datetime) -> datetime:
    """Convert a parsed timestamp to the dashboard's display timezone.

    A bare .astimezone() converts to the host's local zone, which on Render is
    UTC, so the dashboard read an hour behind during British Summer Time. Using
    a named zone rather than a fixed offset means the conversion stays correct
    across the October clock change without further intervention.

    Timestamps arriving without an offset are treated as UTC, matching how the
    server writes them.
    """
    try:
        from zoneinfo import ZoneInfo
    except ImportError:  # pragma: no cover - Python < 3.9
        return moment
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    try:
        return moment.astimezone(ZoneInfo(_DISPLAY_TIMEZONE))
    except Exception:  # pragma: no cover - zone database unavailable on host
        return moment


def _format_display_timestamp(value: Any) -> str:
    """Render a stored timestamp as local time for on-screen tables.

    Returns the original string unchanged when it cannot be parsed, so a
    malformed record shows its raw value rather than disappearing.
    """
    parsed = _parse_history_timestamp(str(value))
    if parsed is None:
        return str(value)
    return _to_display_timezone(parsed).strftime("%d %b %Y, %H:%M")


'''


def function_spans(lines: list[str]) -> dict[str, tuple[int, int]]:
    """Map each top-level function name to its [start, end) line span."""
    spans: dict[str, tuple[int, int]] = {}
    current_name: str | None = None
    current_start = 0
    for index, line in enumerate(lines):
        match = re.match(r"^def (\w+)", line)
        if match:
            if current_name is not None:
                spans[current_name] = (current_start, index)
            current_name = match.group(1)
            current_start = index
    if current_name is not None:
        spans[current_name] = (current_start, len(lines))
    return spans


def patch_timestamp_fields(lines: list[str], report: list[str]) -> list[str]:
    spans = function_spans(lines)
    patched = 0
    skipped: list[str] = []

    for index, line in enumerate(lines):
        if line.strip() != TIMESTAMP_FIELD_OLD:
            continue
        enclosing = None
        for name, (start, end) in spans.items():
            if start <= index < end:
                enclosing = name
                break
        if enclosing in DISPLAY_BUILDERS:
            indent = line[: len(line) - len(line.lstrip())]
            lines[index] = indent + TIMESTAMP_FIELD_NEW
            patched += 1
            report.append(f"timestamp field: patched in {enclosing} (line {index + 1})")
        else:
            skipped.append(f"{enclosing or 'module level'} (line {index + 1})")

    if not patched:
        report.append("timestamp field: FAILED - no occurrences found in the display builders")
    for entry in skipped:
        report.append(f"timestamp field: left alone in {entry}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not TARGET.is_file():
        print("ERROR: run this from the project root.", file=sys.stderr)
        return 1

    original = TARGET.read_text(encoding="utf-8")
    lines = original.split("\n")
    report: list[str] = []

    if "_format_display_timestamp" in original:
        print("  Already patched. Nothing to do.")
        return 0

    inserted = False
    for index, line in enumerate(lines):
        if line.startswith(HELPERS_ANCHOR):
            lines = lines[:index] + HELPERS.rstrip("\n").split("\n") + ["", ""] + lines[index:]
            report.append(f"helpers: inserted before line {index + 1}")
            inserted = True
            break
    if not inserted:
        print(f"  FAILED - anchor '{HELPERS_ANCHOR}' not found.", file=sys.stderr)
        return 1

    source = "\n".join(lines)
    if ASTIMEZONE_OLD in source:
        source = source.replace(ASTIMEZONE_OLD, ASTIMEZONE_NEW, 1)
        report.append("root cause: bare .astimezone() replaced with named-zone conversion")
    else:
        report.append("root cause: FAILED - the .astimezone() call was not found")
    lines = source.split("\n")

    lines = patch_timestamp_fields(lines, report)
    patched = "\n".join(lines)

    print("\n".join(f"  {entry}" for entry in report))

    if any("FAILED" in entry for entry in report):
        print("\nOne or more steps failed. Nothing written.", file=sys.stderr)
        return 1

    try:
        compile(patched, str(TARGET), "exec")
    except SyntaxError as error:
        print(f"\nERROR: syntax error at line {error.lineno}: {error.msg}", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: syntax check passed, no file written.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = TARGET.with_suffix(f".py.bak-tz-{stamp}")
    shutil.copy2(TARGET, backup)
    TARGET.write_text(patched, encoding="utf-8")

    print(f"\nPatched {TARGET}")
    print(f"Backup  {backup}")
    print("\nNext:")
    print("  python -m pytest -q")
    print("  grep -q '^tzdata' requirements.txt || echo tzdata >> requirements.txt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
