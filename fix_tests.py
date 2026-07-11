#!/usr/bin/env python3
"""
========================================================================
FIX THE TESTS AFTER THE MALFORMED-PDF TUNING PATCH
========================================================================
Running the test suite after the patch produced 8 failures. Only 2 of
them were caused by the patch. The other 6 were already failing before
it, because the tests had drifted out of sync with the code.

WHAT THIS FIXES

  Caused by the patch (2 tests):
    test_run_pdf_analysis_details_falls_back_for_malformed_pdf
      in tests/test_cli.py and tests/test_document_parser.py
    They assert rule_severity == "medium". The patched code now
    correctly returns "critical" for a malformed PDF, on the evidence
    that 99.97 percent of parse failures in the corpus were malicious.
    The tests are updated to expect the new, correct behaviour.

  Already broken before the patch (6 tests), fixed as a tidy-up:
    - test_main_train_reports_missing_csv_cleanly
        expects an old error message string
    - test_main_train_prints_training_summary
        the fake training result is missing 'metrics_summary_path'
    - test_build_scan_history_records_collects_expected_fields
        the code now adds a 'client_id' field the test does not expect
    - three test_ui_streamlit tests
        expect dashboard wording that has since been renamed

RUN (from project root, .venv active):
    python fix_tests.py            # fix only the 2 patch-related tests
    python fix_tests.py --all      # also fix the 6 pre-existing failures

Every file is backed up before it is touched.
To undo:  restore the .bak files, e.g.
    mv tests/test_cli.py.bak tests/test_cli.py
========================================================================
"""

import argparse
import shutil
import sys
from pathlib import Path


def patch_file(path: Path, replacements, label):
    """Apply a list of (old, new) replacements to a file. Report what changed."""
    if not path.exists():
        print(f"  SKIP  {path} (not found)")
        return 0

    source = path.read_text()
    applied = []
    missing = []

    for old, new, desc in replacements:
        if old in source:
            source = source.replace(old, new, 1)
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

    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        shutil.copy2(path, backup)
    path.write_text(source)

    print(f"  OK    {path.name}  [{label}]")
    for a in applied:
        print(f"          - {a}")
    for m in missing:
        print(f"          ! could not find: {m}")
    return len(applied)


def fix_patch_related():
    """The 2 tests that our patch legitimately changed the behaviour of."""
    print("\nFIXING THE 2 TESTS AFFECTED BY THE PATCH")
    print("-" * 66)

    # The malformed-PDF fallback test now expects critical severity,
    # a higher rule score, and the new rule name.
    reps = [
        (
            '        self.assertEqual(summary["rule_severity"], "medium")',
            '        self.assertEqual(summary["rule_severity"], "critical")',
            'rule_severity: "medium" -> "critical"',
        ),
        (
            '        self.assertGreaterEqual(summary["final_confidence"], 0.55)',
            '        self.assertGreaterEqual(summary["final_confidence"], 0.85)',
            "final_confidence floor: 0.55 -> 0.85",
        ),
        (
            '        self.assertIn("unreadable-pdf", summary["triggered_rules"])',
            '        self.assertIn("malformed-pdf-structure", summary["triggered_rules"])',
            'triggered rule: "unreadable-pdf" -> "malformed-pdf-structure"',
        ),
    ]

    count = 0
    for name in ("tests/test_cli.py", "tests/test_document_parser.py"):
        count += patch_file(Path(name), reps, "patch-related")
    return count


def fix_preexisting():
    """The 6 tests that were already failing before the patch."""
    print("\nFIXING THE 6 PRE-EXISTING FAILURES")
    print("-" * 66)
    count = 0

    # 1. test_cli.py: the training error message changed
    count += patch_file(
        Path("tests/test_cli.py"),
        [(
            '        self.assertIn("Dataset CSV file not found", stderr.getvalue())',
            '        self.assertIn("Dataset file not found", stderr.getvalue())',
            "training error message wording",
        )],
        "pre-existing",
    )

    # 2. test_document_parser.py: fake training result needs metrics_summary_path
    count += patch_file(
        Path("tests/test_document_parser.py"),
        [(
            '            "feature_columns_path": "models/feature_columns.json",',
            '            "feature_columns_path": "models/feature_columns.json",\n'
            '            "metrics_summary_path": "models/metrics_summary.json",\n'
            '            "dataset_row_count": 12059,\n'
            '            "class_distribution": {"benign": 9102, "malicious": 2957},',
            "add metrics_summary_path and dataset fields to the fake result",
        )],
        "pre-existing",
    )

    # 3. test_history.py: the record now includes client_id
    count += patch_file(
        Path("tests/test_history.py"),
        [(
            '                    "timestamp": "2026-03-26T12:00:00+00:00",\n'
            '                    "file_name": "sample.pdf",\n'
            '                    "sha256": "abc123",',
            '                    "timestamp": "2026-03-26T12:00:00+00:00",\n'
            '                    "file_name": "sample.pdf",\n'
            '                    "sha256": "abc123",\n'
            '                    "client_id": "",',
            "add client_id to the expected history record",
        )],
        "pre-existing",
    )

    # 4-6. test_ui_streamlit.py: dashboard wording was renamed
    count += patch_file(
        Path("tests/test_ui_streamlit.py"),
        [
            (
                '        self.assertIn("Cybersecurity Research Dashboard", hero_html)',
                '        self.assertIn("CYBERSECURITY PDF INTELLIGENCE", hero_html)',
                'hero text: "Cybersecurity Research Dashboard" -> '
                '"CYBERSECURITY PDF INTELLIGENCE"',
            ),
            (
                '        self.assertIn("Total Files", sticky_html)',
                '        self.assertIn("Total PDFs", sticky_html)',
                'sticky bar: "Total Files" -> "Total PDFs"',
            ),
            (
                '        self.assertIn("Riskier File", sticky_html)',
                '        self.assertIn("Riskier PDF", sticky_html)',
                'sticky bar: "Riskier File" -> "Riskier PDF"',
            ),
        ],
        "pre-existing",
    )

    return count


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true",
                    help="Also fix the 6 failures that pre-date the patch.")
    args = ap.parse_args()

    if not Path("tests").is_dir():
        print("ERROR: no tests/ folder. Run this from the project root.")
        return 1

    print("=" * 66)
    print("TEST FIX-UP AFTER THE MALFORMED-PDF TUNING PATCH")
    print("=" * 66)

    total = fix_patch_related()
    if args.all:
        total += fix_preexisting()
    else:
        print("\n(Skipping the 6 pre-existing failures. "
              "Re-run with --all to fix those too.)")

    print("\n" + "=" * 66)
    print(f"Applied {total} change(s). Backups written as .bak files.")
    print("\nNow run:  python -m pytest tests/ -q")
    print("=" * 66)
    return 0


if __name__ == "__main__":
    sys.exit(main())
