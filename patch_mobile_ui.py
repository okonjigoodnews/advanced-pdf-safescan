#!/usr/bin/env python3
"""
Apply the mobile usability fixes to app/ui_streamlit.py.

Fixes applied:
  1. Replaces all five st.line_chart / st.bar_chart calls with explicit Altair
     charts that carry no tooltip encoding. Streamlit's built-in charts attach
     Vega-Lite tooltips automatically and expose no way to disable them; on
     touch devices the tooltip fires on tap and never receives a pointer-exit
     event, so it latches and follows the user down the page.
  2. Shortens the "Last Scan" status chip value so it fits one line at mobile
     width (2026-07-20T16:18:41+00:00 -> 20 Jul, 16:18).
  3. Hides the trend charts behind a caption until the scan history spans at
     least three distinct dates, so a near-empty axis is never rendered.

Usage:
    python3 patch_mobile_ui.py             # apply the patch
    python3 patch_mobile_ui.py --dry-run   # report what would change only

A timestamped backup of the original file is written alongside it.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("app/ui_streamlit.py")

HELPERS_ANCHOR = "def _build_live_status_strip_html("

HELPERS = '''

# --- Mobile rendering helpers -------------------------------------------------
# Streamlit's built-in st.line_chart / st.bar_chart wrap Vega-Lite and attach a
# tooltip layer that cannot be switched off. On touch screens the tooltip fires
# on tap and never receives the pointer-exit event that would dismiss it, so it
# latches open and overlaps whatever the user scrolls to next. Building the
# charts explicitly in Altair means only the encodings declared below are
# attached, and no tooltip is declared.


def _mobile_chart_frame(rows: Any) -> Any:
    """Return a DataFrame for chart rendering, or None when there is nothing to plot."""
    if rows is None:
        return None
    try:
        frame = pd.DataFrame(rows)
    except Exception:  # pragma: no cover - defensive, malformed row input
        return None
    if frame.empty:
        return None
    return frame


def _render_bar_chart(streamlit_module: Any, rows: Any, x_field: str, y_field: str) -> None:
    """Render a tooltip-free bar chart, or nothing when there is no data."""
    frame = _mobile_chart_frame(rows)
    if frame is None:
        return
    chart = (
        alt.Chart(frame)
        .mark_bar()
        .encode(
            x=alt.X(f"{x_field}:N", title=x_field),
            y=alt.Y(f"{y_field}:Q", title=y_field),
        )
    )
    streamlit_module.altair_chart(chart, use_container_width=True)


def _render_trend_chart(
    streamlit_module: Any,
    rows: Any,
    y_field: str,
    min_distinct_dates: int = 3,
) -> None:
    """Render a tooltip-free trend line, suppressed until the history spans several days.

    A single day of scan history produces an axis with one tick and no visible
    line, which reads as a broken chart rather than a sparse one.
    """
    frame = _mobile_chart_frame(rows)
    if frame is None:
        return
    if "date" not in frame.columns or frame["date"].nunique() < min_distinct_dates:
        streamlit_module.caption(
            "Scan trend appears once activity spans several days."
        )
        return
    chart = (
        alt.Chart(frame)
        .mark_line(point=True)
        .encode(
            x=alt.X("date:N", title="date"),
            y=alt.Y(f"{y_field}:Q", title=y_field),
        )
    )
    streamlit_module.altair_chart(chart, use_container_width=True)


def _shorten_scan_timestamp(value: Any) -> str:
    """Compact an ISO-style timestamp so the Last Scan chip fits one mobile line."""
    text = str(value).strip()
    if not text or text.lower() in {"none", "nan", "n/a", "-", "never"}:
        return text
    candidate = text.replace("T", " ").split("+")[0].split(".")[0].strip()
    for parse_format, display_format in (
        ("%Y-%m-%d %H:%M:%S", "%d %b, %H:%M"),
        ("%Y-%m-%d %H:%M", "%d %b, %H:%M"),
        ("%Y-%m-%d", "%d %b %Y"),
    ):
        try:
            return datetime.strptime(candidate, parse_format).strftime(display_format)
        except ValueError:
            continue
    return text


'''

CHART_REPLACEMENTS: dict[str, str] = {
    'streamlit_module.bar_chart(verdict_distribution_rows, x="verdict", y="count")':
        '_render_bar_chart(streamlit_module, verdict_distribution_rows, "verdict", "count")',
    'streamlit_module.bar_chart(score_chart_rows, x="file_name", y="rule_score")':
        '_render_bar_chart(streamlit_module, score_chart_rows, "file_name", "rule_score")',
    'streamlit_module.bar_chart(confidence_chart_rows, x="file_name", y="confidence")':
        '_render_bar_chart(streamlit_module, confidence_chart_rows, "file_name", "confidence")',
    'streamlit_module.line_chart(trend_rows, x="date", y="scan_count")':
        '_render_trend_chart(streamlit_module, trend_rows, "scan_count")',
    'streamlit_module.line_chart(trend_rows, x="date", y="average_rule_score")':
        '_render_trend_chart(streamlit_module, trend_rows, "average_rule_score")',
}

TIMESTAMP_OLD = 'str(summary["last_scan_time"])'
TIMESTAMP_NEW = '_shorten_scan_timestamp(summary["last_scan_time"])'


def find_import_insertion_point(lines: list[str]) -> int:
    """Return the index just after the module's top-level import block."""
    last_import = 0
    for index, line in enumerate(lines[:120]):
        if re.match(r"^(import |from )\S", line):
            last_import = index
    return last_import + 1


def ensure_imports(lines: list[str], report: list[str]) -> list[str]:
    source = "\n".join(lines)
    needed: list[str] = []
    if not re.search(r"^import altair as alt$", source, re.MULTILINE):
        needed.append("import altair as alt")
    if not re.search(r"^import pandas as pd$", source, re.MULTILINE):
        needed.append("import pandas as pd")
    if not re.search(r"^from datetime import .*\bdatetime\b", source, re.MULTILINE) \
            and not re.search(r"^import datetime$", source, re.MULTILINE):
        needed.append("from datetime import datetime")
    if not needed:
        report.append("imports: already present, nothing added")
        return lines
    insert_at = find_import_insertion_point(lines)
    report.append("imports: added " + ", ".join(needed))
    return lines[:insert_at] + needed + lines[insert_at:]


def insert_helpers(lines: list[str], report: list[str]) -> list[str]:
    source = "\n".join(lines)
    if "_render_trend_chart" in source and "def _render_trend_chart" in source:
        report.append("helpers: already present, skipped")
        return lines
    for index, line in enumerate(lines):
        if line.startswith(HELPERS_ANCHOR):
            report.append(f"helpers: inserted before line {index + 1}")
            return lines[:index] + HELPERS.strip("\n").split("\n") + ["", ""] + lines[index:]
    report.append("helpers: FAILED - anchor '%s' not found" % HELPERS_ANCHOR)
    return lines


def replace_charts(lines: list[str], report: list[str]) -> list[str]:
    out: list[str] = []
    hits = 0
    for line in lines:
        stripped = line.strip()
        if stripped in CHART_REPLACEMENTS:
            indent = line[: len(line) - len(line.lstrip())]
            out.append(indent + CHART_REPLACEMENTS[stripped])
            hits += 1
        else:
            out.append(line)
    missing = hits < len(CHART_REPLACEMENTS)
    report.append(
        f"charts: replaced {hits} of {len(CHART_REPLACEMENTS)}"
        + (" - CHECK THE FILE, some calls did not match" if missing else "")
    )
    return out


def replace_timestamp(lines: list[str], report: list[str]) -> list[str]:
    source = "\n".join(lines)
    count = source.count(TIMESTAMP_OLD)
    if count == 0:
        if TIMESTAMP_NEW in source:
            report.append("timestamp: already patched, skipped")
        else:
            report.append("timestamp: FAILED - target expression not found")
        return lines
    if count > 1:
        report.append(
            f"timestamp: found {count} occurrences, patched all - review if unexpected"
        )
    else:
        report.append("timestamp: patched")
    return source.replace(TIMESTAMP_OLD, TIMESTAMP_NEW).split("\n")


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
    lines = original.split("\n")
    report: list[str] = []

    lines = ensure_imports(lines, report)
    lines = insert_helpers(lines, report)
    lines = replace_charts(lines, report)
    lines = replace_timestamp(lines, report)

    patched = "\n".join(lines)

    print("\n".join(f"  {entry}" for entry in report))

    if patched == original:
        print("\nNo changes made.")
        return 0

    try:
        compile(patched, str(target), "exec")
    except SyntaxError as error:
        print(f"\nERROR: patched file has a syntax error at line {error.lineno}: {error.msg}")
        print("Nothing was written. The original file is untouched.", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: syntax check passed, no file written.")
        return 0

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = target.with_suffix(f".py.bak-{stamp}")
    shutil.copy2(target, backup)
    target.write_text(patched, encoding="utf-8")

    print(f"\nPatched {target}")
    print(f"Backup  {backup}")
    print("\nNext:")
    print("  python -m pytest tests/test_ui_streamlit.py -q")
    print("  streamlit run app/ui_streamlit.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
