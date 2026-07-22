#!/usr/bin/env python3
"""
Finish timestamp localisation: cover the batch and dashboard display tables,
and update the two tests that still assert raw timestamps.

Background:
  An earlier patch localised the scan-history and high-risk tables, which read
  record["timestamp"]. Two more on-screen tables read a different key,
  analysis_result["report_timestamp"], so they were missed and still showed raw
  UTC strings. That left the results table above the history table in a
  different format from it, which looks unfinished. This patch localises both:

    _build_batch_summary_rows      (results table after analysis)
    _build_dashboard_table_rows    (dashboard table)

  Both are rendered on screen. The stored records are untouched; only display
  rows are reformatted, and _format_display_timestamp already exists from the
  earlier patch.

Tests:
  Two tests assert the old raw string. Both are updated to assert localised
  output, computed the same way the code computes it rather than frozen as a
  literal. The scan-history test keeps its existing shape; the batch test is
  corrected to expect localised output too.

Usage:
    python3 patch_localise_batch.py --dry-run
    python3 patch_localise_batch.py
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

UI = Path("app/ui_streamlit.py")
TEST = Path("tests/test_ui_streamlit.py")

REPORT_TS_OLD = '"timestamp": str(analysis_result.get("report_timestamp", "")),'
REPORT_TS_NEW = '"timestamp": _format_display_timestamp(analysis_result.get("report_timestamp", "")),'

# Only the two builders named here render on-screen tables. Any other use of
# report_timestamp feeds stored or exported data and must stay raw, so the
# replacement is scoped to these function bodies by line span rather than
# applied blindly across the file.
DISPLAY_BUILDERS = {
    "_build_batch_summary_rows",
    "_build_dashboard_table_rows",
}

TEST_OLD = '        self.assertEqual(rows[0]["timestamp"], "2026-03-26T12:00:00+00:00")'
TEST_NEW = '''        from zoneinfo import ZoneInfo
        march_expected = (
            datetime.fromisoformat("2026-03-26T12:00:00+00:00")
            .astimezone(ZoneInfo("Europe/London"))
            .strftime("%d %b %Y, %H:%M")
        )
        self.assertEqual(rows[0]["timestamp"], march_expected)
        self.assertNotIn("+00:00", rows[0]["timestamp"])'''


def function_spans(lines: list[str]) -> dict[str, tuple[int, int]]:
    import re

    spans: dict[str, tuple[int, int]] = {}
    name: str | None = None
    start = 0
    for index, line in enumerate(lines):
        match = re.match(r"^def (\w+)", line)
        if match:
            if name is not None:
                spans[name] = (start, index)
            name = match.group(1)
            start = index
    if name is not None:
        spans[name] = (start, len(lines))
    return spans


def patch_ui(dry_run: bool, report: list[str]) -> bool:
    if not UI.is_file():
        report.append("ui: FAILED - app/ui_streamlit.py not found")
        return False

    original = UI.read_text(encoding="utf-8")

    if "_format_display_timestamp" not in original:
        report.append(
            "ui: FAILED - _format_display_timestamp helper missing; run patch_localise_time.py first"
        )
        return False

    lines = original.split("\n")
    spans = function_spans(lines)
    patched = 0

    for index, line in enumerate(lines):
        if line.strip() != REPORT_TS_OLD:
            continue
        enclosing = None
        for name, (start, end) in spans.items():
            if start <= index < end:
                enclosing = name
                break
        if enclosing in DISPLAY_BUILDERS:
            indent = line[: len(line) - len(line.lstrip())]
            lines[index] = indent + REPORT_TS_NEW
            patched += 1
            report.append(f"ui: localised report_timestamp in {enclosing} (line {index + 1})")
        else:
            report.append(f"ui: left report_timestamp alone in {enclosing} (line {index + 1})")

    if patched == 0:
        report.append("ui: FAILED - no report_timestamp lines matched in the display builders")
        return False

    patched_source = "\n".join(lines)
    if patched_source == original:
        return True

    try:
        compile(patched_source, str(UI), "exec")
    except SyntaxError as error:
        report.append(f"ui: FAILED - syntax error at line {error.lineno}: {error.msg}")
        return False

    if not dry_run:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = UI.with_suffix(f".py.bak-batchtz-{stamp}")
        shutil.copy2(UI, backup)
        UI.write_text(patched_source, encoding="utf-8")
        report.append(f"ui: written (backup {backup})")
    return True


def patch_tests(dry_run: bool, report: list[str]) -> bool:
    if not TEST.is_file():
        report.append("test: FAILED - test file not found")
        return False

    original = TEST.read_text(encoding="utf-8")

    count = original.count(TEST_OLD)
    if count == 0:
        report.append("test: FAILED - raw-timestamp assertion not found (already patched?)")
        return False

    patched_source = original.replace(TEST_OLD, TEST_NEW)
    report.append(f"test: updated {count} raw-timestamp assertion(s) to localised checks")

    # Ensure datetime is importable in the test module without landing inside
    # the parenthesised app import block.
    import re

    if not re.search(r"^from datetime import .*\bdatetime\b", patched_source, re.MULTILINE) \
            and not re.search(r"^import datetime\b", patched_source, re.MULTILINE):
        future = "from __future__ import annotations"
        if future in patched_source:
            patched_source = patched_source.replace(
                future, future + "\nfrom datetime import datetime", 1
            )
            report.append("test: added 'from datetime import datetime'")
        else:
            report.append("test: FAILED - no safe anchor for datetime import")
            return False

    try:
        compile(patched_source, str(TEST), "exec")
    except SyntaxError as error:
        report.append(f"test: FAILED - syntax error at line {error.lineno}: {error.msg}")
        return False

    if not dry_run:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = TEST.with_suffix(f".py.bak-batchtz-{stamp}")
        shutil.copy2(TEST, backup)
        TEST.write_text(patched_source, encoding="utf-8")
        report.append(f"test: written (backup {backup})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    report: list[str] = []
    ok = patch_ui(args.dry_run, report)
    ok = patch_tests(args.dry_run, report) and ok

    print("\n".join(f"  {entry}" for entry in report))

    if not ok:
        print("\nOne or more steps failed. Review above.", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: syntax checks passed, nothing written.")
        return 0

    print("\nDone. Next:")
    print("  python -m pytest -q")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
