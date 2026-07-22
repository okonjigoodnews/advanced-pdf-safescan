#!/usr/bin/env python3
"""
Second mobile tooltip fix for app/ui_streamlit.py.

The first patch removed the tooltip encoding from the Altair charts, but
st.altair_chart applies Streamlit's own Vega-Lite theme by default, and that
theme re-attaches a tooltip layer. Omitting the encoding is therefore not
enough. This patch does two things to both chart helpers:

  1. Adds an explicit `tooltip=alt.value(None)` encoding, which overrides any
     tooltip a theme would otherwise attach.
  2. Passes `theme=None` to st.altair_chart, so the chart renders as plain
     Altair rather than through Streamlit's themed Vega spec.

Usage:
    python3 patch_mobile_ui_2.py --dry-run
    python3 patch_mobile_ui_2.py
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("app/ui_streamlit.py")

BAR_ENCODE_OLD = '''        .encode(
            x=alt.X(f"{x_field}:N", title=x_field),
            y=alt.Y(f"{y_field}:Q", title=y_field),
        )'''

BAR_ENCODE_NEW = '''        .encode(
            x=alt.X(f"{x_field}:N", title=x_field),
            y=alt.Y(f"{y_field}:Q", title=y_field),
            tooltip=alt.value(None),
        )'''

TREND_ENCODE_OLD = '''        .encode(
            x=alt.X("date:N", title="date"),
            y=alt.Y(f"{y_field}:Q", title=y_field),
        )'''

TREND_ENCODE_NEW = '''        .encode(
            x=alt.X("date:N", title="date"),
            y=alt.Y(f"{y_field}:Q", title=y_field),
            tooltip=alt.value(None),
        )'''

CALL_OLD = "streamlit_module.altair_chart(chart, use_container_width=True)"
CALL_NEW = "streamlit_module.altair_chart(chart, use_container_width=True, theme=None)"


def apply_block(source: str, old: str, new: str, label: str, report: list[str]) -> str:
    if new in source:
        report.append(f"{label}: already patched, skipped")
        return source
    count = source.count(old)
    if count == 0:
        report.append(f"{label}: FAILED - target block not found")
        return source
    report.append(f"{label}: patched ({count} occurrence{'s' if count != 1 else ''})")
    return source.replace(old, new)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    parser.add_argument("--path", default=str(TARGET), help="path to ui_streamlit.py")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.is_file():
        print(f"ERROR: {target} not found. Run this from the project root.", file=sys.stderr)
        return 1

    original = target.read_text(encoding="utf-8")
    report: list[str] = []

    patched = original
    patched = apply_block(patched, BAR_ENCODE_OLD, BAR_ENCODE_NEW, "bar chart tooltip", report)
    patched = apply_block(patched, TREND_ENCODE_OLD, TREND_ENCODE_NEW, "trend chart tooltip", report)
    patched = apply_block(patched, CALL_OLD, CALL_NEW, "theme opt-out", report)

    print("\n".join(f"  {entry}" for entry in report))

    if patched == original:
        print("\nNo changes made.")
        return 0

    try:
        compile(patched, str(target), "exec")
    except SyntaxError as error:
        print(f"\nERROR: syntax error at line {error.lineno}: {error.msg}")
        print("Nothing was written.", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: syntax check passed, no file written.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = target.with_suffix(f".py.bak2-{stamp}")
    shutil.copy2(target, backup)
    target.write_text(patched, encoding="utf-8")

    print(f"\nPatched {target}")
    print(f"Backup  {backup}")
    print("\nNext:")
    print("  python -m pytest -q")
    print("  git add -A && git commit -m 'Disable Vega tooltip layer on mobile' && git push")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
