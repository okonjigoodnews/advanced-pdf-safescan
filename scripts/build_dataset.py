
"""Build a labeled training CSV from benign and malicious PDF folders."""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import sys
from pathlib import Path
from typing import Any, Iterator

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.features.extractor import PDFFeatureExtractor
from src.parser.document_parser import PDFParser, PDFParserError


BENIGN_DIR = PROJECT_ROOT / "data" / "expanded" / "benign"
MALICIOUS_DIR = PROJECT_ROOT / "data" / "expanded" / "malicious"
OUTPUT_CSV = PROJECT_ROOT / "data" / "features" / "train.csv"
PDF_MAGIC = b"%PDF"
PROGRESS_INTERVAL = 10


def is_probably_pdf(path: Path) -> bool:
    """Return True when file content looks like a PDF header."""
    if not path.is_file():
        return False

    try:
        with path.open("rb") as file_handle:
            header = file_handle.read(1024)
    except OSError:
        return False

    return PDF_MAGIC in header


def build_dataset(
    benign_dir: Path = BENIGN_DIR,
    malicious_dir: Path = MALICIOUS_DIR,
    output_csv: Path = OUTPUT_CSV,
) -> dict[str, Any]:
    """Build the training CSV from the benign and malicious PDF folders."""
    parser = PDFParser()
    extractor = PDFFeatureExtractor()
    feature_columns = _feature_columns(extractor)
    output_csv.parent.mkdir(parents=True, exist_ok=True)

    benign_processed = 0
    malicious_processed = 0
    benign_skipped = 0
    malicious_skipped = 0

    with output_csv.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=feature_columns + ["label"])
        writer.writeheader()

        for source_dir, label in ((benign_dir, "benign"), (malicious_dir, "malicious")):
            processed = 0
            skipped = 0

            for path in iter_candidate_files(source_dir):
                row = build_feature_row(
                    path=path,
                    label=label,
                    parser=parser,
                    extractor=extractor,
                    feature_columns=feature_columns,
                )
                if row is None:
                    skipped += 1
                else:
                    writer.writerow(row)
                    processed += 1

                if (processed + skipped) % PROGRESS_INTERVAL == 0:
                    print_progress(label, processed, skipped)

            if label == "benign":
                benign_processed = processed
                benign_skipped = skipped
            else:
                malicious_processed = processed
                malicious_skipped = skipped

    total_skipped = benign_skipped + malicious_skipped
    return {
        "benign_processed": benign_processed,
        "malicious_processed": malicious_processed,
        "skipped": total_skipped,
        "output_csv_path": str(output_csv),
    }


def main() -> int:
    """Build the dataset and print a small processing summary."""
    args = parse_args()
    summary = build_dataset(
        benign_dir=args.benign_dir,
        malicious_dir=args.malicious_dir,
        output_csv=args.output,
    )
    print(f"Benign processed: {summary['benign_processed']}")
    print(f"Malicious processed: {summary['malicious_processed']}")
    print(f"Skipped: {summary['skipped']}")
    print(f"Output CSV: {summary['output_csv_path']}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for dataset building."""
    parser = argparse.ArgumentParser(
        description="Build a labeled PDF feature dataset from benign and malicious folders.",
    )
    parser.add_argument(
        "--benign-dir",
        type=Path,
        default=BENIGN_DIR,
        help="Folder containing benign PDF samples.",
    )
    parser.add_argument(
        "--malicious-dir",
        type=Path,
        default=MALICIOUS_DIR,
        help="Folder containing malicious PDF samples.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_CSV,
        help="Output CSV path for the generated dataset.",
    )
    return parser.parse_args(argv)


def iter_candidate_files(source_dir: Path) -> Iterator[Path]:
    """Yield files from a source directory one at a time."""
    if not source_dir.exists() or not source_dir.is_dir():
        return

    for path in sorted(source_dir.rglob("*")):
        if path.is_file():
            yield path


def build_feature_row(
    *,
    path: Path,
    label: str,
    parser: PDFParser,
    extractor: PDFFeatureExtractor,
    feature_columns: list[str],
) -> dict[str, Any] | None:
    """Build one labeled feature row, or return None when the file should be skipped."""
    if not is_probably_pdf(path):
        return None

    try:
        with contextlib.redirect_stderr(io.StringIO()):
            parsed_pdf = parser.parse(path)
        features = extractor.extract(parsed_pdf)
    except (FileNotFoundError, PDFParserError, OSError, ValueError, TypeError):
        return None

    row = {key: features.get(key, 0) for key in feature_columns}
    row["label"] = label
    return row


def print_progress(label: str, processed: int, skipped: int) -> None:
    """Print a small progress update for one label group."""
    print(f"{label}: processed={processed}, skipped={skipped}")


def _feature_columns(extractor: PDFFeatureExtractor) -> list[str]:
    """Return the stable feature column order used for dataset output."""
    return list(extractor.extract({}).keys())


if __name__ == "__main__":
    raise SystemExit(main())


