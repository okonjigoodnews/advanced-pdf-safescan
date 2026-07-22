#!/usr/bin/env python3
"""
Set up Progressive Web App packaging for the Advanced PDFSafeScan dashboard.

What this creates:
  1. .streamlit/config.toml  - enables Streamlit's static file serving so the
     manifest and icons can be fetched at /app/static/<name>.
  2. app/static/manifest.json - declares the app name, colours, start URL and
     "display": "standalone", which is the field that makes the app launch
     full screen without browser chrome once added to the home screen.
  3. app/static/icon-192.png, icon-512.png, icon-512-maskable.png - upscaled
     from chrome_extension/icon128.png with Lanczos resampling. The maskable
     variant pads the artwork to 60% so Android's adaptive icon mask does not
     crop the shield.
  4. A _inject_pwa_head() helper in app/ui_streamlit.py, called immediately
     after set_page_config().

Why the head injection is a component and not st.markdown:
  Streamlit renders its own HTML shell and gives no access to <head>, and
  st.markdown does not execute <script> tags. st.components.v1.html renders a
  real same-origin iframe where scripts do run, so the manifest link and icon
  meta tags are appended to window.parent.document.head from inside it. The
  component is zero-height and renders nothing visible.

Known limitation:
  Chrome's automatic install prompt additionally requires a service worker whose
  scope covers the app root. Streamlit serves static files under /app/static/,
  so a worker registered from there cannot claim "/" without a
  Service-Worker-Allowed response header, which Streamlit's server does not let
  you set. Manual "Add to Home Screen" works and launches standalone; the
  automatic prompt will not appear. This is worth stating plainly in the
  implementation write-up rather than hiding.

Usage:
    python3 setup_pwa.py --dry-run
    python3 setup_pwa.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime
from pathlib import Path

UI_FILE = Path("app/ui_streamlit.py")
SOURCE_ICON = Path("chrome_extension/icon128.png")
STATIC_DIR = Path("app/static")
CONFIG_FILE = Path(".streamlit/config.toml")

# Matches the dashboard's dark background so the splash screen and the status
# bar do not flash white on launch.
BACKGROUND_COLOR = "#0b1120"
THEME_COLOR = "#0b1120"

MANIFEST = {
    "name": "Advanced PDFSafeScan",
    "short_name": "PDFSafeScan",
    "description": "Hybrid machine learning and rule-based malicious PDF detection.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "orientation": "portrait",
    "background_color": BACKGROUND_COLOR,
    "theme_color": THEME_COLOR,
    "icons": [
        {
            "src": "/app/static/icon-192.png",
            "sizes": "192x192",
            "type": "image/png",
            "purpose": "any",
        },
        {
            "src": "/app/static/icon-512.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "any",
        },
        {
            "src": "/app/static/icon-512-maskable.png",
            "sizes": "512x512",
            "type": "image/png",
            "purpose": "maskable",
        },
    ],
}

ANCHOR_LINE = 'streamlit_module.set_page_config(page_title="Advanced PDFSafeScan", layout="wide")'
INJECT_CALL = "_inject_pwa_head(streamlit_module)"

HELPERS_ANCHOR = "def main() -> None:"

HELPERS = '''

# --- Progressive Web App head injection ---------------------------------------
# Streamlit renders its own HTML shell and exposes no hook for the document
# <head>, and st.markdown will not execute script tags. st.components.v1.html
# renders a genuine same-origin iframe in which scripts do run, so the manifest
# link and icon metadata are appended to window.parent.document.head from there.
# The component has zero height and renders nothing the user can see.

_PWA_HEAD_SNIPPET = """
<script>
(function () {
    try {
        var head = window.parent.document.head;
        if (!head) { return; }

        function upsert(selector, build) {
            var existing = head.querySelector(selector);
            if (existing) { existing.parentNode.removeChild(existing); }
            head.appendChild(build());
        }

        upsert('link[rel="manifest"]', function () {
            var link = window.parent.document.createElement('link');
            link.rel = 'manifest';
            link.href = '/app/static/manifest.json';
            return link;
        });

        upsert('link[rel="apple-touch-icon"]', function () {
            var link = window.parent.document.createElement('link');
            link.rel = 'apple-touch-icon';
            link.href = '/app/static/icon-192.png';
            return link;
        });

        upsert('meta[name="theme-color"]', function () {
            var meta = window.parent.document.createElement('meta');
            meta.name = 'theme-color';
            meta.content = 'THEME_COLOR_PLACEHOLDER';
            return meta;
        });

        upsert('meta[name="apple-mobile-web-app-capable"]', function () {
            var meta = window.parent.document.createElement('meta');
            meta.name = 'apple-mobile-web-app-capable';
            meta.content = 'yes';
            return meta;
        });

        upsert('meta[name="apple-mobile-web-app-status-bar-style"]', function () {
            var meta = window.parent.document.createElement('meta');
            meta.name = 'apple-mobile-web-app-status-bar-style';
            meta.content = 'black-translucent';
            return meta;
        });
    } catch (error) {
        /* Injection is cosmetic. If the parent document is unreachable the
           dashboard still works as an ordinary web page. */
    }
})();
</script>
"""


def _inject_pwa_head(streamlit_module: Any) -> None:
    """Attach PWA manifest and icon metadata to the parent document head.

    Fails silently. Under test the streamlit module is a stand-in without a
    components API, and a missing home-screen icon should never break a run.
    """
    try:
        components = getattr(streamlit_module, "components", None)
        html_fn = getattr(getattr(components, "v1", None), "html", None)
        if html_fn is None:
            from streamlit.components.v1 import html as html_fn  # type: ignore[no-redef]
        html_fn(_PWA_HEAD_SNIPPET, height=0)
    except Exception:
        return


'''


def build_icons(dry_run: bool, report: list[str]) -> bool:
    try:
        from PIL import Image
    except ImportError:
        report.append("icons: FAILED - Pillow not installed (pip install Pillow)")
        return False

    if not SOURCE_ICON.is_file():
        report.append(f"icons: FAILED - {SOURCE_ICON} not found")
        return False

    source = Image.open(SOURCE_ICON).convert("RGBA")
    targets = [
        ("icon-192.png", 192, False),
        ("icon-512.png", 512, False),
        ("icon-512-maskable.png", 512, True),
    ]

    for name, size, maskable in targets:
        destination = STATIC_DIR / name
        if dry_run:
            report.append(f"icons: would write {destination} ({size}x{size})")
            continue
        if maskable:
            # Android crops maskable icons to a circle or squircle. Padding the
            # artwork to 60% of the canvas keeps the shield inside the safe zone.
            inner = int(size * 0.6)
            canvas = Image.new("RGBA", (size, size), BACKGROUND_COLOR)
            scaled = source.resize((inner, inner), Image.LANCZOS)
            offset = (size - inner) // 2
            canvas.paste(scaled, (offset, offset), scaled)
            canvas.save(destination)
        else:
            source.resize((size, size), Image.LANCZOS).save(destination)
        report.append(f"icons: wrote {destination} ({size}x{size})")

    return True


def write_manifest(dry_run: bool, report: list[str]) -> None:
    destination = STATIC_DIR / "manifest.json"
    payload = json.dumps(MANIFEST, indent=2) + "\n"
    if destination.is_file() and destination.read_text(encoding="utf-8") == payload:
        report.append("manifest: already up to date, skipped")
        return
    if dry_run:
        report.append(f"manifest: would write {destination}")
        return
    destination.write_text(payload, encoding="utf-8")
    report.append(f"manifest: wrote {destination}")


def write_config(dry_run: bool, report: list[str]) -> None:
    setting = "enableStaticServing = true"
    if CONFIG_FILE.is_file():
        existing = CONFIG_FILE.read_text(encoding="utf-8")
        if "enableStaticServing" in existing:
            report.append("config: enableStaticServing already set, skipped")
            return
        if "[server]" in existing:
            updated = existing.replace("[server]", f"[server]\n{setting}", 1)
        else:
            updated = existing.rstrip("\n") + f"\n\n[server]\n{setting}\n"
    else:
        updated = f"[server]\n{setting}\n"

    if dry_run:
        report.append(f"config: would update {CONFIG_FILE}")
        return
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(updated, encoding="utf-8")
    report.append(f"config: updated {CONFIG_FILE}")


def patch_ui(dry_run: bool, report: list[str]) -> bool:
    if not UI_FILE.is_file():
        report.append(f"ui: FAILED - {UI_FILE} not found")
        return False

    original = UI_FILE.read_text(encoding="utf-8")
    lines = original.split("\n")

    if "def _inject_pwa_head" in original:
        report.append("ui: helper already present, skipped")
    else:
        inserted = False
        for index, line in enumerate(lines):
            if line.startswith(HELPERS_ANCHOR):
                helper_lines = HELPERS.strip("\n").replace(
                    "THEME_COLOR_PLACEHOLDER", THEME_COLOR
                ).split("\n")
                lines = lines[:index] + helper_lines + ["", ""] + lines[index:]
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
            if line.strip() == ANCHOR_LINE and not called:
                indent = line[: len(line) - len(line.lstrip())]
                output.append(indent + INJECT_CALL)
                called = True
        if not called:
            report.append("ui: FAILED - set_page_config anchor not found")
            return False
        lines = output
        report.append("ui: injection call added after set_page_config")

    patched = "\n".join(lines)
    if patched == original:
        return True

    try:
        compile(patched, str(UI_FILE), "exec")
    except SyntaxError as error:
        report.append(f"ui: FAILED - syntax error at line {error.lineno}: {error.msg}")
        return False

    if dry_run:
        report.append("ui: syntax check passed, no file written")
        return True

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = UI_FILE.with_suffix(f".py.bak-pwa-{stamp}")
    shutil.copy2(UI_FILE, backup)
    UI_FILE.write_text(patched, encoding="utf-8")
    report.append(f"ui: patched (backup at {backup})")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="report changes without writing")
    args = parser.parse_args()

    if not UI_FILE.is_file():
        print("ERROR: run this from the project root.", file=sys.stderr)
        return 1

    if not args.dry_run:
        STATIC_DIR.mkdir(parents=True, exist_ok=True)

    report: list[str] = []
    ok = build_icons(args.dry_run, report)
    write_manifest(args.dry_run, report)
    write_config(args.dry_run, report)
    ok = patch_ui(args.dry_run, report) and ok

    print("\n".join(f"  {entry}" for entry in report))

    if not ok:
        print("\nOne or more steps failed. Review the report above.", file=sys.stderr)
        return 1

    if args.dry_run:
        print("\nDry run: nothing written.")
        return 0

    print("\nDone. Next:")
    print("  python -m pytest -q")
    print("  streamlit run app/ui_streamlit.py")
    print("  # then visit http://localhost:8501/app/static/manifest.json to confirm serving")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
