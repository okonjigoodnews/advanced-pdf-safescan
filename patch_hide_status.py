#!/usr/bin/env python3
"""
Hide Streamlit's built-in developer chrome in app/ui_streamlit.py.

The animated "running" indicator and its Stop button appear top-right whenever
the script executes. They are a development affordance rather than part of the
dashboard, and on a cold start they are the only thing on screen for several
seconds, which reads as the app doing something odd rather than loading.

This patch:
  1. Adds a _inject_chrome_css() helper that hides the status widget, the
     Deploy button and the hamburger menu, called immediately after the PWA
     head injection.
  2. Sets client.toolbarMode = "minimal" in .streamlit/config.toml, which
     suppresses the same chrome server-side as a belt-and-braces measure in
     case a future Streamlit release renames the test IDs the CSS targets.

Trade-off worth knowing:
  Hiding the status widget also hides the only built-in signal that the app is
  busy, and the Stop button with it. If a scan takes noticeable time, the app
  should show its own spinner (st.spinner) so the user is not left looking at a
  static page. Check whether the analysis path already does this.

Usage:
    python3 patch_hide_status.py --dry-run
    python3 patch_hide_status.py
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

TARGET = Path("app/ui_streamlit.py")
CONFIG_FILE = Path(".streamlit/config.toml")

ANCHOR_CALL = "_inject_pwa_head(streamlit_module)"
INJECT_CALL = "_inject_chrome_css(streamlit_module)"

HELPERS_ANCHOR = "def main() -> None:"

HELPERS = '''

# --- Streamlit chrome suppression ---------------------------------------------
# Streamlit renders a running indicator and Stop button in the top right while
# the script executes, plus a Deploy button and hamburger menu. None of these
# belong to the dashboard. Hiding them by test ID is the supported approach;
# the config.toml toolbarMode setting covers the same ground server-side in
# case these IDs change in a future release.

_CHROME_CSS = """
<style>
    [data-testid="stStatusWidget"] { display: none !important; }
    [data-testid="stToolbar"] { display: none !important; }
    [data-testid="stDecoration"] { display: none !important; }
    .stAppDeployButton { display: none !important; }
    #MainMenu { visibility: hidden; }
</style>
"""


def _inject_chrome_css(streamlit_module: Any) -> None:
    """Hide Streamlit's developer chrome. Fails silently under test doubles."""
    try:
        streamlit_module.markdown(_CHROME_CSS, unsafe_allow_html=True)
    except Exception:
        return


'''


def patch_config(dry_run: bool, report: list[str]) -> None:
    setting = 'toolbarMode = "minimal"'
    if CONFIG_FILE.is_file():
        existing = CONFIG_FILE.read_text(encoding="utf-8")
        if "toolbarMode" in existing:
            report.append("config: toolbarMode already set, skipped")
            return
        if "[client]" in existing:
            updated = existing.replace("[client]", f"[client]\n{setting}", 1)
        else:
            updated = existing.rstrip("\n") + f"\n\n[client]\n{setting}\n"
    else:
        updated = f"[client]\n{setting}\n"

    if dry_run:
        report.append(f"config: would set toolbarMode in {CONFIG_FILE}")
        return
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(updated, encoding="utf-8")
    report.append(f"config: set toolbarMode in {CONFIG_FILE}")


def patch_ui(dry_run: bool, report: list[str]) -> bool:
    if not TARGET.is_file():
        report.append(f"ui: FAILED - {TARGET} not found")
        return False

    original = TARGET.read_text(encoding="utf-8")
    lines = original.split("\n")

    if "def _inject_chrome_css" in original:
        report.append("ui: helper already present, skipped")
    else:
        inserted = False
        for index, line in enumerate(lines):
            if line.startswith(HELPERS_ANCHOR):
                lines = lines[:index] + HELPERS.strip("\n").split("\n") + ["", ""] + lines[index:]
                report.append(f"ui: helper inserted before line {index + 1}")
                inserted = True
                break
        if not inserted:
            report.append(f"ui: FAILED - anchor '{HELPERS_ANCHOR}' not found")
            return False

    if INJECT_CALL in "\n".join(lines):
        report.append("ui: injection call already present, skipped")
    else:
        called = False
        output: list[str] = []
        for line in lines:
            output.append(line)
            if line.strip() == ANCHOR_CALL and not called:
                indent = line[: len(line) - len(line.lstrip())]
                output.append(indent + INJECT_CALL)
                called = True
        if not called:
            report.append(f"ui: FAILED - anchor '{ANCHOR_CALL}' not found")
            return False
        lines = output
        report.append("ui: injection call added after the PWA head injection")

    patched = "\n".join(lines)
    if patched == original:
        return True

    try:
        compile(patched, str(TARGET), "exec")
    except SyntaxError as error:
        report.append(f"ui: FAILED - syntax error at line {error.lineno}: {error.msg}")
        return False

    if dry_run:
        report.append("ui: syntax check passed, no file written")
        return True

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = TARGET.with_suffix(f".py.bak-chrome-{stamp}")
    shutil.copy2(TARGET, backup)
    TARGET.write_text(patched, encoding="utf-8")
    report.append(f"ui: patched (backup at {backup})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not TARGET.is_file():
        print("ERROR: run this from the project root.", file=sys.stderr)
        return 1

    report: list[str] = []
    ok = patch_ui(args.dry_run, report)
    patch_config(args.dry_run, report)

    print("\n".join(f"  {entry}" for entry in report))

    if not ok:
        print("\nOne or more steps failed.", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: nothing written.")
        return 0

    print("\nDone. Next:")
    print("  python -m pytest -q")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
