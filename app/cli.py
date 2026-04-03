"""Command-line interface helpers for the project."""

from __future__ import annotations

import argparse
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    """Create and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="advanced-pdf-safescan",
        description="Research prototype for malicious PDF detection.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a single PDF file.",
    )
    scan_parser.add_argument(
        "--file",
        dest="file_path",
        required=True,
        type=Path,
        help="Path to the PDF file to scan.",
    )
    scan_parser.add_argument(
        "--model-dir",
        dest="model_dir",
        type=Path,
        default=Path("models"),
        help="Directory containing the saved ML model artifacts.",
    )

    scan_folder_parser = subparsers.add_parser(
        "scan-folder",
        help="Scan all PDF files in a folder.",
    )
    scan_folder_parser.add_argument(
        "--dir",
        dest="directory",
        required=True,
        type=Path,
        help="Path to a folder containing PDF files.",
    )
    scan_folder_parser.add_argument(
        "--model-dir",
        dest="model_dir",
        type=Path,
        default=Path("models"),
        help="Directory containing the saved ML model artifacts.",
    )
    scan_folder_parser.add_argument(
        "--full",
        action="store_true",
        help="Print the full summary for each PDF as well as the short result line.",
    )

    train_parser = subparsers.add_parser(
        "train",
        help="Train the baseline ML model from a CSV dataset.",
    )
    train_parser.add_argument(
        "--csv",
        dest="csv_path",
        required=True,
        type=Path,
        help="Path to the labeled feature CSV dataset.",
    )
    train_parser.add_argument(
        "--model-dir",
        dest="model_dir",
        type=Path,
        default=Path("models"),
        help="Directory where trained model artifacts will be saved.",
    )

    return parser
