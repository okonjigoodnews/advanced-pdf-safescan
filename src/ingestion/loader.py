"""Starter components for ingesting PDF files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class PDFSample:
    """Container describing a PDF file selected for analysis."""

    path: Path


class PDFIngestionService:
    """Placeholder service responsible for validating PDF input paths."""

    def load(self, path: Path) -> PDFSample:
        """Create a sample object from a path."""
        return PDFSample(path=path)
