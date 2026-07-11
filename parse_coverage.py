#!/usr/bin/env python3
"""
========================================================================
PARSE COVERAGE ANALYSIS  —  the "malformed = malicious" finding
========================================================================
This measures, across your ENTIRE dataset, how many benign and malicious
PDFs parse successfully and how many fail. It tests the key finding:

    A PDF that fails to parse is, in this data, almost always malicious.

If that holds at scale, parse failure is a strong, cheap detection
signal that the current pipeline throws away.

WHAT IT PRODUCES:
    parse_coverage.txt   : the full numbers, ready to paste and quote
    parse_coverage.png   : a chart for the dissertation

It reads file STRUCTURE only. It never opens or executes any file.

HOW TO RUN (from project root, .venv active):
    python parse_coverage.py

It processes tens of thousands of files, so it may take a while. It
prints progress as it goes.
========================================================================
"""

import contextlib
import io
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[0]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.extractor import PDFFeatureExtractor
from src.parser.document_parser import PDFParser

BENIGN_DIR = PROJECT_ROOT / "data" / "expanded" / "benign"
MALICIOUS_DIR = PROJECT_ROOT / "data" / "expanded" / "malicious"
PDF_MAGIC = b"%PDF"


def analyse_folder(folder, label, parser, extractor):
    """Run every file in a folder through the real parser and tally outcomes."""
    files = [p for p in sorted(folder.rglob("*")) if p.is_file()]
    total = len(files)
    ok = 0
    failed = 0
    errors = {}
    start = time.time()

    print(f"\nAnalysing {total} {label} files...")
    for i, path in enumerate(files, 1):
        try:
            with path.open("rb") as fh:
                if PDF_MAGIC not in fh.read(1024):
                    errors["no_header"] = errors.get("no_header", 0) + 1
                    failed += 1
                    continue
            with contextlib.redirect_stderr(io.StringIO()):
                parsed = parser.parse(path)
                extractor.extract(parsed)
            ok += 1
        except Exception as exc:  # noqa: BLE001 (we want every failure type)
            failed += 1
            name = type(exc).__name__
            errors[name] = errors.get(name, 0) + 1

        if i % 1000 == 0:
            elapsed = time.time() - start
            rate = i / elapsed if elapsed else 0
            print(f"  {label}: {i}/{total}  ok={ok} failed={failed}  "
                  f"({rate:.0f} files/sec)")

    return {
        "label": label,
        "total": total,
        "ok": ok,
        "failed": failed,
        "errors": errors,
        "seconds": round(time.time() - start, 1),
    }


def main():
    print("=" * 66)
    print("PARSE COVERAGE ANALYSIS")
    print("=" * 66)

    parser = PDFParser()
    extractor = PDFFeatureExtractor()

    benign = analyse_folder(BENIGN_DIR, "benign", parser, extractor)
    malicious = analyse_folder(MALICIOUS_DIR, "malicious", parser, extractor)

    # ---- key derived numbers ----
    b_total, b_ok, b_failed = benign["total"], benign["ok"], benign["failed"]
    m_total, m_ok, m_failed = malicious["total"], malicious["ok"], malicious["failed"]

    b_fail_rate = (b_failed / b_total * 100) if b_total else 0
    m_fail_rate = (m_failed / m_total * 100) if m_total else 0

    total_failures = b_failed + m_failed
    # Of all the files that FAILED to parse, how many were malicious?
    failure_precision = (m_failed / total_failures * 100) if total_failures else 0

    lines = []
    lines.append("PARSE COVERAGE ANALYSIS  (full dataset)")
    lines.append("=" * 66)
    lines.append("")
    lines.append("BENIGN")
    lines.append(f"  Total files      : {b_total}")
    lines.append(f"  Parsed OK        : {b_ok}  ({b_ok/b_total*100:.2f}%)")
    lines.append(f"  Failed to parse  : {b_failed}  ({b_fail_rate:.2f}%)")
    lines.append(f"  Error types      : {benign['errors']}")
    lines.append("")
    lines.append("MALICIOUS")
    lines.append(f"  Total files      : {m_total}")
    lines.append(f"  Parsed OK        : {m_ok}  ({m_ok/m_total*100:.2f}%)")
    lines.append(f"  Failed to parse  : {m_failed}  ({m_fail_rate:.2f}%)")
    lines.append(f"  Error types      : {malicious['errors']}")
    lines.append("")
    lines.append("THE KEY FINDING")
    lines.append("-" * 66)
    lines.append(f"  Benign parse-failure rate    : {b_fail_rate:.2f}%")
    lines.append(f"  Malicious parse-failure rate : {m_fail_rate:.2f}%")
    lines.append(f"  Of ALL files that failed to parse, {failure_precision:.2f}% were malicious.")
    lines.append("")
    if b_fail_rate < 2 and m_fail_rate > 30:
        lines.append("  => Parse failure is a STRONG malicious signal in this dataset.")
        lines.append("     A file that cannot be parsed is overwhelmingly likely malicious.")
        lines.append("     The current pipeline discards these files, silently missing")
        lines.append(f"     roughly {m_fail_rate:.0f}% of the malicious samples.")
    else:
        lines.append("  => The signal is weaker than the sample suggested; interpret with care.")
    lines.append("")
    lines.append("COVERAGE IMPLICATION")
    lines.append("-" * 66)
    lines.append(f"  Current system classifies only files that parse:")
    lines.append(f"    malicious coverage = {m_ok}/{m_total} = {m_ok/m_total*100:.1f}%")
    lines.append(f"  Treating parse failure as 'suspicious' would raise malicious")
    lines.append(f"    coverage to effectively {(m_ok+m_failed)/m_total*100:.1f}%.")
    lines.append("")
    lines.append(f"(Benign analysed in {benign['seconds']}s, "
                 f"malicious in {malicious['seconds']}s.)")

    report = "\n".join(lines)
    with open("parse_coverage.txt", "w") as f:
        f.write(report)
    print("\n" + report)
    print("\nSaved parse_coverage.txt")

    # ---- chart ----
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 5), dpi=150)

        # Left: stacked parse success/failure by class
        classes = ["Benign", "Malicious"]
        ok_vals = [b_ok, m_ok]
        fail_vals = [b_failed, m_failed]
        x = np.arange(len(classes))
        ax1.bar(x, ok_vals, 0.55, label="Parsed OK", color="#2D6A4F")
        ax1.bar(x, fail_vals, 0.55, bottom=ok_vals, label="Failed to parse", color="#D12D3F")
        ax1.set_xticks(x); ax1.set_xticklabels(classes)
        ax1.set_ylabel("Number of files")
        ax1.set_title("Parse Success vs Failure by Class", fontsize=12,
                      fontweight="bold", color="#1F3A5F")
        ax1.legend()
        for s in ["top", "right"]: ax1.spines[s].set_visible(False)

        # Right: failure rates
        rates = [b_fail_rate, m_fail_rate]
        bars = ax2.bar(classes, rates, 0.55, color=["#2D6CB5", "#D12D3F"])
        for b, v in zip(bars, rates):
            ax2.text(b.get_x()+b.get_width()/2, v+1, f"{v:.1f}%",
                     ha="center", fontsize=12, fontweight="bold")
        ax2.set_ylabel("Parse-failure rate (%)")
        ax2.set_ylim(0, max(rates) * 1.25 + 5)
        ax2.set_title("Parse-Failure Rate: A Malicious Signal", fontsize=12,
                      fontweight="bold", color="#1F3A5F")
        for s in ["top", "right"]: ax2.spines[s].set_visible(False)

        plt.tight_layout()
        plt.savefig("parse_coverage.png", dpi=150, facecolor="white")
        print("Saved parse_coverage.png")
    except Exception as e:
        print(f"(Chart skipped: {e})")

    print("\n" + "=" * 66)
    print("DONE. Paste parse_coverage.txt back.")
    print("=" * 66)


if __name__ == "__main__":
    main()
