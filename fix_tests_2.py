#!/usr/bin/env python3
"""
========================================================================
SECOND-PASS TEST FIXES
========================================================================
The first fix-up took the suite from 8 failures to 4. These are the
remaining 4, all small string mismatches.

WHAT IS LEFT AND WHY

  1 & 2. test_run_pdf_analysis_details_falls_back_for_malformed_pdf
         (in tests/test_cli.py and tests/test_document_parser.py)

         The test looks for the phrase "could not be fully parsed".
         The new explanation text reads "could not be parsed", without
         the word "fully", because the malformed message was rewritten.
         Updated to match.

  3.     test_main_train_prints_training_summary
         The fake training result is still missing another key the code
         prints: 'confusion_matrix_path'. Added.

  4.     test_build_sticky_verdict_bar_html_for_batch...
         Expects "Riskiest File". The dashboard says "Riskiest PDF".
         (The earlier pass fixed "Riskier File" but not this one.)

RUN (from project root, .venv active):
    python fix_tests_2.py
    python -m pytest tests/ -q
========================================================================
"""

import shutil
import sys
from pathlib import Path


def patch_file(path: Path, replacements):
    if not path.exists():
        print(f"  SKIP  {path} (not found)")
        return 0

    source = path.read_text()
    applied, missing = [], []

    for old, new, desc in replacements:
        if old in source:
            source = source.replace(old, new)
            applied.append(desc)
        elif new in source:
            applied.append(f"{desc} (already applied)")
        else:
            missing.append(desc)

    if not applied:
        print(f"  SKIP  {path.name}: nothing to change")
        for m in missing:
            print(f"          could not find: {m}")
        return 0

    backup = path.with_suffix(path.suffix + ".bak2")
    if not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(source)

    print(f"  OK    {path.name}")
    for a in applied:
        print(f"          - {a}")
    for m in missing:
        print(f"          ! could not find: {m}")
    return len(applied)


def main():
    if not Path("tests").is_dir():
        print("ERROR: no tests/ folder. Run this from the project root.")
        return 1

    print("=" * 66)
    print("SECOND-PASS TEST FIXES")
    print("=" * 66)
    total = 0

    # 1 & 2: the explanation wording changed in the patch.
    # Old text: "The PDF could not be fully parsed (...)"
    # New text: "The PDF could not be parsed (...)"
    explanation_fix = [(
        '            any("could not be fully parsed" in explanation '
        'for explanation in summary["explanations"])',
        '            any("could not be parsed" in explanation '
        'for explanation in summary["explanations"])',
        'explanation text: "could not be fully parsed" -> "could not be parsed"',
    )]
    # A more tolerant variant, in case the line is wrapped differently.
    explanation_fix_loose = [(
        '"could not be fully parsed"',
        '"could not be parsed"',
        'explanation phrase (loose match)',
    )]

    print("\n1-2. Malformed-PDF explanation wording")
    print("-" * 66)
    for name in ("tests/test_cli.py", "tests/test_document_parser.py"):
        p = Path(name)
        changed = patch_file(p, explanation_fix)
        if changed == 0:
            changed = patch_file(p, explanation_fix_loose)
        total += changed

    # 3: another missing key in the fake training result
    print("\n3. Missing confusion_matrix_path in the fake training result")
    print("-" * 66)
    total += patch_file(
        Path("tests/test_document_parser.py"),
        [(
            '            "metrics_summary_path": "models/metrics_summary.json",',
            '            "metrics_summary_path": "models/metrics_summary.json",\n'
            '            "confusion_matrix_path": "models/confusion_matrix.png",',
            "add confusion_matrix_path",
        )],
    )

    # 4: "Riskiest File" -> "Riskiest PDF"
    print("\n4. Dashboard wording: Riskiest File -> Riskiest PDF")
    print("-" * 66)
    total += patch_file(
        Path("tests/test_ui_streamlit.py"),
        [(
            '        self.assertIn("Riskiest File", sticky_html)',
            '        self.assertIn("Riskiest PDF", sticky_html)',
            '"Riskiest File" -> "Riskiest PDF"',
        )],
    )

    print("\n" + "=" * 66)
    print(f"Applied {total} change(s). Backups written as .bak2 files.")
    print("\nNow run:  python -m pytest tests/ -q")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
