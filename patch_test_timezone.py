#!/usr/bin/env python3
"""
Update tests/test_ui_streamlit.py for localised timestamp display.

The dashboard now converts stored UTC timestamps to Europe/London before
showing them. One existing test still asserts the raw stored string, so it
fails. This script:

  1. Replaces that assertion with one that checks the display is localised,
     computed the same way the code does rather than frozen as a literal, so
     the test does not depend on the string happening to match on one machine.
  2. Adds a second test using a July (British Summer Time) timestamp, asserting
     the displayed clock time is one hour ahead of UTC. The original March case
     is GMT, where local time and UTC coincide, so on its own it cannot tell a
     working conversion apart from no conversion. The BST case is the one that
     actually exercises the bug that was fixed.
  3. Ensures the datetime import the new assertions need is present.

Usage:
    python3 patch_test_timezone.py --dry-run
    python3 patch_test_timezone.py
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("tests/test_ui_streamlit.py")

OLD_ASSERT = '''        self.assertEqual(rows[0]["timestamp"], "2026-03-26T12:00:00+00:00")'''

NEW_ASSERT = '''        # The stored value is UTC; the table shows Europe/London. March is GMT,
        # so the clock time is unchanged, but the format and the dropped offset
        # still prove localisation ran. Computed rather than frozen so the test
        # does not break where the timezone database differs.
        from zoneinfo import ZoneInfo
        march_expected = (
            datetime.fromisoformat("2026-03-26T12:00:00+00:00")
            .astimezone(ZoneInfo("Europe/London"))
            .strftime("%d %b %Y, %H:%M")
        )
        self.assertEqual(rows[0]["timestamp"], march_expected)
        self.assertNotIn("+00:00", rows[0]["timestamp"])'''

BST_TEST = '''
    def test_build_scan_history_table_rows_localises_bst_timestamp(self) -> None:
        """A summer (BST) timestamp displays one hour ahead of its stored UTC value."""
        from zoneinfo import ZoneInfo

        history_records = [
            {
                "timestamp": "2026-07-20T16:18:41+00:00",
                "file_name": "sample.pdf",
                "sha256": "abc123",
                "final_label": "benign",
                "final_confidence": 0.10,
                "rule_score": 4.0,
                "recommendation": "No action needed.",
            }
        ]

        rows = _build_scan_history_table_rows(history_records)

        expected = (
            datetime.fromisoformat("2026-07-20T16:18:41+00:00")
            .astimezone(ZoneInfo("Europe/London"))
            .strftime("%d %b %Y, %H:%M")
        )
        self.assertEqual(rows[0]["timestamp"], expected)
        # BST is UTC+1, so 16:18 UTC must display as 17:18. This is the case the
        # original bug got wrong; the March test alone cannot catch it.
        self.assertIn("17:18", rows[0]["timestamp"])
'''

# Anchor the new test after the end of the one we just edited, so it lands
# among the other history-table tests rather than at file end.
BST_ANCHOR = '''        self.assertEqual(rows[0]["disposition"], "Suspicious")'''


def ensure_datetime_import(source: str, report: list[str]) -> str:
    import re

    if re.search(r"^from datetime import .*\bdatetime\b", source, re.MULTILINE):
        report.append("import: datetime already imported, skipped")
        return source
    if re.search(r"^import datetime\b", source, re.MULTILINE):
        report.append("import: datetime module already imported, skipped")
        return source

    # Anchor to the __future__ import, which is always the first statement and
    # never part of a parenthesised block, so the new line cannot land inside
    # the multi-line "from app.ui_streamlit import (...)" block.
    future_line = "from __future__ import annotations"
    if future_line in source:
        report.append("import: added 'from datetime import datetime'")
        return source.replace(
            future_line,
            future_line + "\nfrom datetime import datetime",
            1,
        )

    report.append("import: FAILED - could not find a safe anchor for the datetime import")
    return source


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not TARGET.is_file():
        print("ERROR: run this from the project root.", file=sys.stderr)
        return 1

    original = TARGET.read_text(encoding="utf-8")
    report: list[str] = []
    patched = original

    if "test_build_scan_history_table_rows_localises_bst_timestamp" in original:
        print("  Already patched. Nothing to do.")
        return 0

    if OLD_ASSERT in patched:
        patched = patched.replace(OLD_ASSERT, NEW_ASSERT, 1)
        report.append("assertion: replaced raw-timestamp check with localisation check")
    else:
        report.append("assertion: FAILED - the raw-timestamp assertion was not found")

    if BST_ANCHOR in patched:
        # Insert after the first occurrence of the anchor line.
        index = patched.index(BST_ANCHOR) + len(BST_ANCHOR)
        patched = patched[:index] + "\n" + BST_TEST + patched[index:]
        report.append("bst test: inserted after the existing history-table test")
    else:
        report.append("bst test: FAILED - anchor line not found")

    patched = ensure_datetime_import(patched, report)

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
    backup = TARGET.with_suffix(f".py.bak-tztest-{stamp}")
    shutil.copy2(TARGET, backup)
    TARGET.write_text(patched, encoding="utf-8")

    print(f"\nPatched {TARGET}")
    print(f"Backup  {backup}")
    print("\nNext:")
    print("  python -m pytest -q")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
