"""Simple PDF report export helpers for Advanced PDFSafeScan."""

from __future__ import annotations

import textwrap
from typing import Any

PAGE_WIDTH = 612
PAGE_HEIGHT = 792
LEFT_MARGIN = 50
TOP_MARGIN = 760
LINE_HEIGHT = 15
MAX_LINE_WIDTH = 92
LINES_PER_PAGE = 46


def build_pdf_report_bytes(*, report_data: dict[str, Any], timestamp: str) -> bytes:
    """Build a simple PDF report for one analyzed file."""
    lines = _build_pdf_report_lines(report_data=report_data, timestamp=timestamp)
    return _build_simple_pdf(lines)


def _build_pdf_report_lines(*, report_data: dict[str, Any], timestamp: str) -> list[str]:
    """Build readable report lines before rendering them into a PDF."""
    lines = [
        "Advanced PDFSafeScan",
        "Intelligent Malicious PDF Detection",
        "",
        f"Report Timestamp: {timestamp}",
        f"File Name: {report_data.get('file_name', 'unknown')}",
        f"SHA-256: {report_data.get('sha256', 'unknown')}",
        "",
        "Assessment Summary",
        f"Final Label: {str(report_data.get('final_label', 'unknown')).title()}",
        f"Final Confidence: {_format_float(report_data.get('final_confidence', 0.0))}",
        f"Rule Score: {_format_float(report_data.get('rule_score', 0.0))}",
        f"Rule Severity: {str(report_data.get('rule_severity', 'unknown')).title()}",
        f"ML Label: {str(report_data.get('ml_label', 'unknown')).title()}",
        f"ML Confidence: {_format_float(report_data.get('ml_confidence', 0.0))}",
        "",
        "Suspicious Indicators",
    ]

    lines.extend(_format_list_items(report_data.get("suspicious_indicators", [])))
    lines.append("")
    lines.append("Triggered Rules")
    lines.extend(_format_list_items(report_data.get("triggered_rules", [])))
    lines.append("")
    lines.append("Explanations")
    lines.extend(_format_list_items(report_data.get("explanations", [])))
    lines.append("")
    lines.append("Recommendation")
    lines.extend(
        _wrap_text_lines(str(report_data.get("recommendation", "No recommendation available.")))
    )
    return lines


def _format_list_items(items: Any) -> list[str]:
    """Format report list items with wrapping and an empty-state fallback."""
    values = list(items) if isinstance(items, list) else []
    if not values:
        return ["- None recorded."]

    lines: list[str] = []
    for item in values:
        wrapped = _wrap_text_lines(f"- {item}")
        lines.extend(wrapped)
    return lines


def _wrap_text_lines(text: str) -> list[str]:
    """Wrap one report line into readable PDF-width chunks."""
    wrapped = textwrap.wrap(
        text,
        width=MAX_LINE_WIDTH,
        break_long_words=False,
        break_on_hyphens=False,
    )
    return wrapped or [""]


def _format_float(value: Any) -> str:
    """Format numeric values consistently for reports."""
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "0.00"


def _build_simple_pdf(lines: list[str]) -> bytes:
    """Render simple text pages into a minimal PDF byte payload."""
    pages = [lines[index:index + LINES_PER_PAGE] for index in range(0, len(lines), LINES_PER_PAGE)]
    if not pages:
        pages = [[]]

    objects: list[bytes] = []

    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")

    page_object_numbers = [4 + index * 2 for index in range(len(pages))]
    pages_kids = " ".join(f"{object_number} 0 R" for object_number in page_object_numbers)
    objects.append(
        f"<< /Type /Pages /Kids [{pages_kids}] /Count {len(page_object_numbers)} >>".encode("latin-1")
    )

    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    for page_index, page_lines in enumerate(pages):
        page_object_number = 4 + page_index * 2
        content_object_number = page_object_number + 1
        page_object = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_object_number} 0 R >>"
        ).encode("latin-1")
        objects.append(page_object)

        content_stream = _build_page_content_stream(page_lines)
        content_object = (
            f"<< /Length {len(content_stream)} >>\nstream\n".encode("latin-1")
            + content_stream
            + b"\nendstream"
        )
        objects.append(content_object)

    pdf_parts = [b"%PDF-1.4\n"]
    offsets = [0]

    for index, obj in enumerate(objects, start=1):
        offsets.append(sum(len(part) for part in pdf_parts))
        pdf_parts.append(f"{index} 0 obj\n".encode("latin-1"))
        pdf_parts.append(obj)
        pdf_parts.append(b"\nendobj\n")

    xref_offset = sum(len(part) for part in pdf_parts)
    pdf_parts.append(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_parts.append(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf_parts.append(f"{offset:010d} 00000 n \n".encode("latin-1"))
    pdf_parts.append(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("latin-1")
    )
    return b"".join(pdf_parts)


def _build_page_content_stream(lines: list[str]) -> bytes:
    """Build one page text stream for the PDF renderer."""
    stream_lines = [
        "BT",
        "/F1 11 Tf",
        f"{LINE_HEIGHT} TL",
        f"{LEFT_MARGIN} {TOP_MARGIN} Td",
    ]

    for index, line in enumerate(lines):
        escaped_line = _escape_pdf_text(line)
        if index == 0:
            stream_lines.append(f"({escaped_line}) Tj")
        else:
            stream_lines.append("T*")
            stream_lines.append(f"({escaped_line}) Tj")

    stream_lines.append("ET")
    return "\n".join(stream_lines).encode("latin-1", errors="replace")


def _escape_pdf_text(text: str) -> str:
    """Escape a text value for use inside a PDF literal string."""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )
