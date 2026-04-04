"""Streamlit UI for Advanced PDFSafeScan."""

from __future__ import annotations

import base64
import html
import json
import os
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    import streamlit as st
except ImportError:  # pragma: no cover - exercised only when dependency is missing
    st = None

from app.main import run_pdf_analysis_details
from app.runtime_config import API_TOKEN_HEADER_NAME
from src.ml.classifier import MLClassifierError, MalwareClassifier, load_saved_model
from src.parser.document_parser import PDFParserError
from src.reporting.comparison import build_comparison_summary
from src.reporting.csv_export import build_csv_export_bytes
from src.reporting.explanations import build_explanation_panel
from src.reporting.forensics import (
    build_forensic_report,
    compute_sha256,
    recommendation_for_verdict,
)
from src.reporting.history import (
    append_scan_history_records,
    filter_scan_history_records,
    get_high_risk_scan_history_records,
    get_malicious_scan_history_records,
    HIGH_RISK_RULE_SCORE_THRESHOLD,
    load_scan_history,
    search_scan_history_records,
    sort_scan_history_records,
)
from src.reporting.pdf_export import build_pdf_report_bytes
from src.reporting.pdf_reader import PDFReaderError, SafePDFReader
from src.reporting.review_notes import (
    DISPOSITION_OPTIONS,
    PRIORITY_OPTIONS,
    REVIEW_STATUS_OPTIONS,
    load_analyst_reviews_by_sha256,
    save_analyst_review,
)
from src.reporting.summary import summary_to_json
from src.reporting.zip_ingest import ZIPIngestError, extract_pdf_uploads_from_zip

INLINE_PREVIEW_MAX_BYTES = 10 * 1024 * 1024
_HISTORY_API_RECENT_LIMIT = 250
_HISTORY_API_TIMEOUT_SECONDS = 8
_PREVIEW_CHAR_LIMITS = {
    "benign": 5000,
    "suspicious": 1800,
    "malicious": 800,
}
_HISTORY_EXPORT_FIELDNAMES = [
    "timestamp",
    "file_name",
    "sha256",
    "final_label",
    "final_confidence",
    "rule_score",
    "recommendation",
    "review_status",
    "priority",
    "disposition",
    "analyst_note",
]
_HERO_BADGE_TEXT = "Cybersecurity Research Dashboard"
_VERDICT_ICON_HTML = {
    "benign": "&#128737;",
    "suspicious": "&#9888;",
    "malicious": "&#10006;",
}
_VERDICT_ICON_LABELS = {
    "benign": "Protected",
    "suspicious": "Caution",
    "malicious": "Threat",
}
_DEFAULT_REVIEW_STATUS = REVIEW_STATUS_OPTIONS[0]
_DEFAULT_PRIORITY = PRIORITY_OPTIONS[1]


def _require_streamlit() -> Any:
    """Return the Streamlit module or raise a clear runtime error."""
    if st is None:
        raise RuntimeError(
            "Streamlit is required to run the UI. Install dependencies from requirements.txt first."
        )
    return st


def _inject_page_styles(streamlit_module: Any) -> None:
    """Apply a premium cybersecurity dashboard theme while staying Streamlit-native."""
    streamlit_module.markdown(
        """
        <style>
        :root {
            --app-bg: #07111f;
            --panel-bg: rgba(8, 18, 34, 0.62);
            --panel-border: rgba(148, 163, 184, 0.18);
            --panel-shadow: 0 24px 60px rgba(2, 6, 23, 0.42);
            --text-main: #eff6ff;
            --text-muted: #93a9c8;
            --accent-blue: #60a5fa;
            --accent-cyan: #22d3ee;
            --accent-purple: #8b5cf6;
            --success: #22c55e;
            --warning: #f59e0b;
            --danger: #ef4444;
        }
        @keyframes ambientDrift {
            0% { transform: translate3d(0, 0, 0) scale(1); opacity: 0.78; }
            50% { transform: translate3d(0, -8px, 0) scale(1.02); opacity: 1; }
            100% { transform: translate3d(0, 0, 0) scale(1); opacity: 0.82; }
        }
        @keyframes accentSweep {
            0% { background-position: 0% 50%; opacity: 0.62; }
            50% { background-position: 100% 50%; opacity: 1; }
            100% { background-position: 0% 50%; opacity: 0.7; }
        }
        @keyframes verdictPulse {
            0% { box-shadow: 0 10px 24px rgba(14, 165, 233, 0.12), 0 0 0 0 rgba(96, 165, 250, 0.12); }
            50% { box-shadow: 0 12px 28px rgba(14, 165, 233, 0.18), 0 0 0 5px rgba(96, 165, 250, 0.05); }
            100% { box-shadow: 0 10px 24px rgba(14, 165, 233, 0.12), 0 0 0 0 rgba(96, 165, 250, 0.12); }
        }
        .stApp {
            background:
                radial-gradient(circle at 15% 20%, rgba(96, 165, 250, 0.22), transparent 28%),
                radial-gradient(circle at 85% 18%, rgba(139, 92, 246, 0.18), transparent 24%),
                radial-gradient(circle at 60% 78%, rgba(34, 211, 238, 0.12), transparent 26%),
                linear-gradient(145deg, #020817 0%, #07111f 38%, #081426 100%);
            color: var(--text-main);
        }
        .stApp::before {
            content: "";
            position: fixed;
            inset: 0;
            pointer-events: none;
            background:
                linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            background-size: 140px 140px;
            mask-image: linear-gradient(to bottom, rgba(0, 0, 0, 0.22), transparent 82%);
            opacity: 0.35;
        }
        [data-testid="stAppViewContainer"] > .main {
            background: transparent;
        }
        [data-testid="stHeader"] {
            background: rgba(2, 8, 23, 0.3);
            backdrop-filter: blur(12px);
        }
        .block-container {
            max-width: 1240px;
            padding-top: 1.1rem;
            padding-bottom: 3rem;
        }
        h1, h2, h3, h4, h5, h6, p, li, label, div, span {
            color: var(--text-main);
        }
        .stMarkdown p,
        .stCaption,
        .stText,
        label,
        div[data-testid="stMetricLabel"] {
            color: var(--text-muted) !important;
        }
        div[data-testid="stVerticalBlockBorderWrapper"] {
            position: relative;
            overflow: hidden;
            background: var(--panel-bg);
            border: 1px solid var(--panel-border) !important;
            border-radius: 1.2rem;
            box-shadow: var(--panel-shadow);
            backdrop-filter: blur(18px);
        }
        div[data-testid="stVerticalBlockBorderWrapper"]::before {
            content: "";
            position: absolute;
            top: 0;
            left: 1rem;
            right: 1rem;
            height: 2px;
            border-radius: 999px;
            background: linear-gradient(90deg, rgba(34, 211, 238, 0.15), rgba(96, 165, 250, 0.95), rgba(139, 92, 246, 0.18));
            background-size: 200% 100%;
            animation: accentSweep 12s ease-in-out infinite;
            pointer-events: none;
        }
        div[data-testid="stVerticalBlockBorderWrapper"] > div {
            border-radius: 1.2rem;
        }
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.52), rgba(8, 18, 34, 0.88));
            border: 1px solid rgba(96, 165, 250, 0.16);
            border-radius: 1rem;
            padding: 0.85rem 1rem;
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.03);
        }
        div[data-testid="stMetricValue"] {
            color: #f8fbff;
        }
        div[data-testid="stAlert"] {
            border-radius: 1rem;
            border: 1px solid rgba(148, 163, 184, 0.18);
            backdrop-filter: blur(10px);
            background: rgba(10, 18, 33, 0.78);
        }
        div[data-testid="stDataFrame"],
        div[data-testid="stTable"] {
            background: rgba(8, 18, 34, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.14);
            border-radius: 1rem;
            padding: 0.45rem;
        }
        div[data-testid="stExpander"] {
            background: rgba(8, 18, 34, 0.55);
            border: 1px solid rgba(148, 163, 184, 0.14);
            border-radius: 1rem;
            overflow: hidden;
        }
        div[data-testid="stTextInputRootElement"] > div,
        div[data-baseweb="select"] > div,
        div[data-testid="stTextArea"] textarea {
            background: rgba(7, 16, 30, 0.86) !important;
            border: 1px solid rgba(96, 165, 250, 0.18) !important;
            color: var(--text-main) !important;
            border-radius: 0.85rem !important;
        }
        div[data-testid="stTextInputRootElement"] input {
            color: var(--text-main) !important;
        }
        div[data-testid="stButton"] > button,
        div[data-testid="stDownloadButton"] > button {
            color: white;
            border-radius: 0.95rem;
            padding: 0.8rem 1.15rem;
            font-weight: 700;
            letter-spacing: 0.01em;
            transition: transform 0.18s ease, box-shadow 0.18s ease, border-color 0.18s ease;
            box-shadow: 0 14px 28px rgba(8, 15, 28, 0.35);
        }
        div[data-testid="stButton"] > button[kind="primary"] {
            background: linear-gradient(135deg, #2563eb 0%, #22d3ee 100%);
            border: 1px solid rgba(96, 165, 250, 0.55);
            box-shadow: 0 18px 36px rgba(37, 99, 235, 0.33);
        }
        div[data-testid="stButton"] > button[kind="secondary"],
        div[data-testid="stDownloadButton"] > button {
            background: linear-gradient(135deg, rgba(15, 23, 42, 0.96), rgba(19, 34, 61, 0.96));
            border: 1px solid rgba(96, 165, 250, 0.22);
        }
        div[data-testid="stButton"] > button:hover,
        div[data-testid="stDownloadButton"] > button:hover {
            transform: translateY(-1px);
            color: white;
            border-color: rgba(96, 165, 250, 0.58);
            box-shadow: 0 20px 38px rgba(8, 15, 28, 0.42);
        }
        .hero-shell {
            position: relative;
            overflow: hidden;
            margin: 0.2rem 0 1.4rem 0;
            padding: 1.35rem 1.4rem 1.45rem 1.4rem;
            border-radius: 1.45rem;
            background:
                linear-gradient(145deg, rgba(10, 17, 34, 0.88), rgba(6, 12, 25, 0.78)),
                radial-gradient(circle at top right, rgba(96, 165, 250, 0.14), transparent 38%);
            border: 1px solid rgba(96, 165, 250, 0.18);
            box-shadow: 0 28px 55px rgba(2, 6, 23, 0.45);
            backdrop-filter: blur(16px);
        }
        .hero-shell::before {
            content: "";
            position: absolute;
            inset: 0;
            background:
                radial-gradient(circle at 82% 18%, rgba(139, 92, 246, 0.18), transparent 24%),
                radial-gradient(circle at 18% 82%, rgba(34, 211, 238, 0.12), transparent 22%);
            pointer-events: none;
            animation: ambientDrift 14s ease-in-out infinite;
        }
        .hero-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.35rem 0.75rem;
            border-radius: 999px;
            background: rgba(96, 165, 250, 0.12);
            border: 1px solid rgba(96, 165, 250, 0.22);
            color: #dbeafe;
            font-size: 0.77rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
        .hero-title {
            margin: 0.9rem 0 0.45rem 0;
            font-size: clamp(2rem, 4vw, 3rem);
            font-weight: 800;
            line-height: 1.04;
            color: #f8fbff;
        }
        .hero-subtitle {
            font-size: 1rem;
            color: #d6e8ff;
            font-weight: 600;
            margin-bottom: 0.55rem;
        }
        .hero-body {
            max-width: 780px;
            color: #a8bfdd;
            font-size: 1rem;
            line-height: 1.65;
            margin: 0;
        }
        .hero-accent {
            width: 110px;
            height: 4px;
            border-radius: 999px;
            margin-top: 1rem;
            background: linear-gradient(90deg, #22d3ee, #60a5fa, #8b5cf6);
            box-shadow: 0 0 24px rgba(96, 165, 250, 0.42);
            background-size: 200% 100%;
            animation: accentSweep 10s ease-in-out infinite;
        }
        .sticky-verdict-bar {
            position: sticky;
            overflow: hidden;
            top: 0.5rem;
            z-index: 999;
            margin: 0.35rem 0 1.25rem 0;
            padding: 0.95rem 1.05rem;
            border-radius: 1.1rem;
            background:
                linear-gradient(145deg, rgba(7, 16, 30, 0.93), rgba(12, 24, 44, 0.88));
            border: 1px solid rgba(96, 165, 250, 0.16);
            box-shadow: 0 18px 36px rgba(2, 6, 23, 0.32);
            backdrop-filter: blur(16px);
        }
        .sticky-verdict-bar::before {
            content: "";
            position: absolute;
            left: 1rem;
            right: 1rem;
            top: 0;
            height: 2px;
            border-radius: 999px;
            background: linear-gradient(90deg, rgba(34, 211, 238, 0.08), rgba(96, 165, 250, 0.92), rgba(139, 92, 246, 0.12));
            background-size: 200% 100%;
            animation: accentSweep 11s ease-in-out infinite;
        }
        .sticky-verdict-title {
            font-size: 0.74rem;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #c9dcf7;
            margin-bottom: 0.55rem;
            font-weight: 700;
        }
        .sticky-verdict-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.75rem;
            align-items: center;
        }
        .sticky-verdict-item {
            min-width: 0;
            padding: 0.3rem 0.45rem;
            border-radius: 0.8rem;
            background: rgba(255, 255, 255, 0.03);
        }
        .sticky-verdict-label {
            font-size: 0.76rem;
            color: #9fb6d6;
            margin-bottom: 0.18rem;
        }
        .sticky-verdict-value {
            font-size: 0.95rem;
            color: #f8fafc;
            font-weight: 600;
            word-break: break-word;
        }
        .verdict-badge {
            position: relative;
            display: inline-flex;
            align-items: center;
            gap: 0.55rem;
            padding: 0.42rem 0.92rem;
            border-radius: 999px;
            color: white;
            font-weight: 700;
            font-size: 0.88rem;
            letter-spacing: 0.01em;
            border: 1px solid transparent;
            overflow: hidden;
            animation: verdictPulse 6s ease-in-out infinite;
        }
        .verdict-badge::after {
            content: "";
            position: absolute;
            inset: 0;
            background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.14), transparent);
            transform: translateX(-125%);
            animation: accentSweep 9s ease-in-out infinite;
            pointer-events: none;
        }
        .verdict-badge-benign {
            background: linear-gradient(135deg, #15803d, #22c55e);
            border-color: rgba(34, 197, 94, 0.75);
            box-shadow: 0 10px 24px rgba(34, 197, 94, 0.2);
        }
        .verdict-badge-suspicious {
            background: linear-gradient(135deg, #d97706, #f59e0b);
            border-color: rgba(245, 158, 11, 0.78);
            box-shadow: 0 10px 24px rgba(245, 158, 11, 0.2);
        }
        .verdict-badge-malicious {
            background: linear-gradient(135deg, #b91c1c, #ef4444);
            border-color: rgba(239, 68, 68, 0.82);
            box-shadow: 0 10px 24px rgba(239, 68, 68, 0.2);
        }
        .verdict-badge-unknown {
            background: linear-gradient(135deg, #334155, #64748b);
            border-color: rgba(148, 163, 184, 0.5);
            box-shadow: 0 10px 24px rgba(100, 116, 139, 0.16);
        }
        .verdict-badge-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 1.35rem;
            height: 1.35rem;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.16);
            color: #ffffff;
            font-size: 0.88rem;
            line-height: 1;
            flex-shrink: 0;
            box-shadow: inset 0 1px 1px rgba(255, 255, 255, 0.12);
        }
        .verdict-badge-text {
            position: relative;
            z-index: 1;
        }
        .verdict-badge-prefix {
            opacity: 0.88;
            margin-right: 0.15rem;
        }
        .status-strip {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
            gap: 0.8rem;
            margin: 0.15rem 0 1.2rem 0;
        }
        .status-chip {
            position: relative;
            overflow: hidden;
            padding: 0.85rem 1rem 0.9rem 1rem;
            border-radius: 1rem;
            background: linear-gradient(180deg, rgba(9, 18, 34, 0.82), rgba(8, 18, 34, 0.94));
            border: 1px solid rgba(96, 165, 250, 0.14);
            box-shadow: 0 18px 38px rgba(2, 6, 23, 0.28);
            backdrop-filter: blur(14px);
        }
        .status-chip::before {
            content: "";
            position: absolute;
            left: 0.9rem;
            right: 0.9rem;
            top: 0;
            height: 2px;
            border-radius: 999px;
            background: linear-gradient(90deg, rgba(34, 211, 238, 0.14), rgba(96, 165, 250, 0.94), rgba(139, 92, 246, 0.16));
            background-size: 200% 100%;
            animation: accentSweep 10s ease-in-out infinite;
        }
        .status-label {
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #9fb6d6;
            margin-bottom: 0.45rem;
            font-weight: 700;
        }
        .status-value {
            font-size: 1.2rem;
            line-height: 1.1;
            color: #f8fbff;
            font-weight: 800;
            margin-bottom: 0.2rem;
        }
        .status-meta {
            font-size: 0.78rem;
            color: #8ea7c8;
        }
        @media (max-width: 768px) {
            .block-container {
                padding-top: 0.85rem;
                padding-bottom: 2rem;
            }
            .hero-shell {
                padding: 1.15rem 1rem 1.2rem 1rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _build_hero_html() -> str:
    """Build the premium hero banner shown at the top of the application."""
    return (
        '<section class="hero-shell">'
        f'<div class="hero-badge">{html.escape(_HERO_BADGE_TEXT)}</div>'
        '<div class="hero-title">Advanced PDFSafeScan</div>'
        '<div class="hero-subtitle">Intelligent Malicious PDF Detection</div>'
        '<p class="hero-body">'
        "A polished security dashboard for analyzing suspicious PDFs with structural inspection, "
        "hybrid machine learning, explainable rule scoring, forensic exports, and safe review controls."
        "</p>"
        '<div class="hero-accent"></div>'
        "</section>"
    )


def _is_pdf_filename(filename: str | None) -> bool:
    """Return True when the uploaded filename looks like a PDF."""
    return bool(filename) and filename.lower().endswith(".pdf")


def _is_zip_filename(filename: str | None) -> bool:
    """Return True when the uploaded filename looks like a ZIP archive."""
    return bool(filename) and filename.lower().endswith(".zip")


def _save_uploaded_pdf(uploaded_file: Any) -> Path:
    """Persist an uploaded PDF to a temporary file for backend analysis."""
    suffix = Path(uploaded_file.name).suffix or ".pdf"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
        temp_file.write(uploaded_file.getvalue())
        return Path(temp_file.name)


def _run_pipeline(pdf_path: Path, classifier: MalwareClassifier) -> dict[str, Any]:
    """Run the full backend detection pipeline and return all key outputs."""
    return run_pdf_analysis_details(pdf_path, classifier)


def _read_pdf_details(pdf_path: Path) -> dict[str, Any]:
    """Read metadata and text preview details safely for the PDF reader section."""
    reader = SafePDFReader()
    return reader.read(pdf_path)


def _analyze_uploaded_pdf(uploaded_file: Any, classifier: MalwareClassifier) -> dict[str, Any]:
    """Run analysis and safe-reader extraction for one uploaded PDF."""
    pdf_bytes = uploaded_file.getvalue()
    temp_pdf_path: Path | None = None
    try:
        temp_pdf_path = _save_uploaded_pdf(uploaded_file)
        results = _run_pipeline(temp_pdf_path, classifier)
        reader_result = _read_pdf_details(temp_pdf_path)
        summary = results["summary"]
        sha256 = compute_sha256(pdf_bytes)
        file_size = len(pdf_bytes)
        recommendation = recommendation_for_verdict(str(summary.get("final_label", "unknown")))
        report_timestamp = datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
        forensic_report = build_forensic_report(
            summary=summary,
            reader_result=reader_result,
            sha256=sha256,
            file_size=file_size,
            recommendation=recommendation,
        )
        pdf_report_bytes = build_pdf_report_bytes(
            report_data=forensic_report,
            timestamp=report_timestamp,
        )
        return {
            "results": results,
            "reader_result": reader_result,
            "pdf_bytes": pdf_bytes,
            "upload_name": getattr(uploaded_file, "name", "uploaded.pdf"),
            "summary": summary,
            "sha256": sha256,
            "file_size": file_size,
            "recommendation": recommendation,
            "forensic_report": forensic_report,
            "report_timestamp": report_timestamp,
            "pdf_report_bytes": pdf_report_bytes,
        }
    finally:
        if temp_pdf_path is not None and temp_pdf_path.exists():
            temp_pdf_path.unlink(missing_ok=True)


def _build_upload_signature(uploads: list[tuple[str, Any]]) -> list[tuple[str, str, int]]:
    """Build a stable signature for the currently uploaded files."""
    return [
        (
            key_prefix,
            str(getattr(uploaded_file, "name", "")),
            len(uploaded_file.getvalue()),
        )
        for key_prefix, uploaded_file in uploads
    ]


def _count_verdicts(analyzed_results: list[tuple[str, dict[str, Any]]]) -> dict[str, int]:
    """Count benign, suspicious, and malicious verdicts in one batch."""
    counts = {"benign": 0, "suspicious": 0, "malicious": 0}
    for _, analysis_result in analyzed_results:
        final_label = str(analysis_result["summary"].get("final_label", "unknown"))
        if final_label in counts:
            counts[final_label] += 1
    return counts


def _select_riskiest_file(analyzed_results: list[tuple[str, dict[str, Any]]]) -> str:
    """Return the name of the riskiest analyzed file."""
    if not analyzed_results:
        return "N/A"

    label_priority = {"benign": 0, "suspicious": 1, "malicious": 2}

    def rank(item: tuple[str, dict[str, Any]]) -> tuple[int, float, float]:
        summary = item[1]["summary"]
        return (
            label_priority.get(str(summary.get("final_label", "unknown")), -1),
            float(summary.get("rule_score", 0.0)),
            float(summary.get("final_confidence", 0.0)),
        )

    return str(max(analyzed_results, key=rank)[1]["summary"].get("file_name", "unknown"))


def _build_batch_summary_rows(analyzed_results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build a simple summary table payload for batch analysis mode."""
    rows: list[dict[str, Any]] = []
    for _, analysis_result in analyzed_results:
        summary = analysis_result["summary"]
        rows.append(
            {
                "timestamp": str(analysis_result.get("report_timestamp", "")),
                "file_name": str(summary.get("file_name", "unknown")),
                "sha256": str(analysis_result.get("sha256", "")),
                "final_label": str(summary.get("final_label", "unknown")),
                "final_confidence": round(float(summary.get("final_confidence", 0.0)), 3),
                "rule_score": round(float(summary.get("rule_score", 0.0)), 3),
                "recommendation": str(analysis_result.get("recommendation", "")),
            }
        )
    return rows


def _build_dashboard_table_rows(analyzed_results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build dashboard table rows for all analyzed PDFs."""
    rows: list[dict[str, Any]] = []
    for _, analysis_result in analyzed_results:
        summary = analysis_result["summary"]
        rows.append(
            {
                "timestamp": str(analysis_result.get("report_timestamp", "")),
                "file_name": str(summary.get("file_name", "unknown")),
                "sha256": str(analysis_result.get("sha256", "")),
                "final_label": str(summary.get("final_label", "unknown")),
                "confidence": round(float(summary.get("final_confidence", 0.0)), 3),
                "rule_score": round(float(summary.get("rule_score", 0.0)), 3),
                "recommendation": str(analysis_result.get("recommendation", "")),
            }
        )
    return rows


def _build_verdict_distribution_rows(analyzed_results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build verdict distribution rows for a simple dashboard chart."""
    counts = _count_verdicts(analyzed_results)
    return [
        {"verdict": "benign", "count": counts["benign"]},
        {"verdict": "suspicious", "count": counts["suspicious"]},
        {"verdict": "malicious", "count": counts["malicious"]},
    ]


def _build_score_chart_rows(analyzed_results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build per-file rule-score rows for dashboard comparison charts."""
    rows: list[dict[str, Any]] = []
    for _, analysis_result in analyzed_results:
        summary = analysis_result["summary"]
        rows.append(
            {
                "file_name": str(summary.get("file_name", "unknown")),
                "rule_score": float(summary.get("rule_score", 0.0)),
            }
        )
    return rows


def _build_confidence_chart_rows(analyzed_results: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    """Build per-file confidence rows for dashboard comparison charts."""
    rows: list[dict[str, Any]] = []
    for _, analysis_result in analyzed_results:
        summary = analysis_result["summary"]
        rows.append(
            {
                "file_name": str(summary.get("file_name", "unknown")),
                "confidence": float(summary.get("final_confidence", 0.0)),
            }
        )
    return rows


def _build_scan_history_table_rows(
    history_records: list[dict[str, Any]],
    review_records_by_sha256: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build display rows for the persistent scan history section."""
    rows: list[dict[str, Any]] = []
    review_records_by_sha256 = review_records_by_sha256 or {}
    for record in history_records:
        sha256 = str(record.get("sha256", ""))
        review_fields = _normalize_review_record_for_display(
            review_records_by_sha256.get(sha256) or record,
            final_label=str(record.get("final_label", "suspicious")),
        )
        rows.append(
            {
                "timestamp": str(record.get("timestamp", "")),
                "file_name": str(record.get("file_name", "unknown")),
                "sha256": sha256,
                "final_label": str(record.get("final_label", "unknown")).title(),
                "final_confidence": round(float(record.get("final_confidence", 0.0)), 3),
                "rule_score": round(float(record.get("rule_score", 0.0)), 3),
                "recommendation": str(record.get("recommendation", "")),
                "review_status": review_fields["review_status"],
                "priority": review_fields["priority"],
                "disposition": review_fields["disposition"],
                "analyst_note": review_fields["analyst_note"],
            }
        )
    return rows


def _build_high_risk_table_rows(
    history_records: list[dict[str, Any]],
    review_records_by_sha256: dict[str, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Build display rows for the high-risk review workflow."""
    rows: list[dict[str, Any]] = []
    review_records_by_sha256 = review_records_by_sha256 or {}
    for record in history_records:
        sha256 = str(record.get("sha256", ""))
        final_label = str(record.get("final_label", "unknown")).lower()
        risk_category = (
            "Malicious"
            if final_label == "malicious"
            else f"Suspicious (Rule Score >= {HIGH_RISK_RULE_SCORE_THRESHOLD:.0f})"
        )
        review_fields = _normalize_review_record_for_display(
            review_records_by_sha256.get(sha256) or record,
            final_label=final_label,
        )
        rows.append(
            {
                "risk_category": risk_category,
                "timestamp": str(record.get("timestamp", "")),
                "file_name": str(record.get("file_name", "unknown")),
                "sha256": sha256,
                "final_label": str(record.get("final_label", "unknown")).title(),
                "final_confidence": round(float(record.get("final_confidence", 0.0)), 3),
                "rule_score": round(float(record.get("rule_score", 0.0)), 3),
                "recommendation": str(record.get("recommendation", "")),
                "review_status": review_fields["review_status"],
                "priority": review_fields["priority"],
                "disposition": review_fields["disposition"],
                "analyst_note": review_fields["analyst_note"],
            }
        )
    return rows


def _parse_history_timestamp(timestamp: str) -> datetime | None:
    """Parse one history timestamp into a datetime when possible."""
    normalized_timestamp = str(timestamp).strip()
    if not normalized_timestamp:
        return None
    try:
        return datetime.fromisoformat(normalized_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def _safe_float(value: Any) -> float:
    """Convert a numeric-like value into float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _normalize_dashboard_history_record(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a hosted recent-scan row into the local dashboard history shape."""
    final_label = _normalize_verdict(str(record.get("final_label", "unknown")))
    return {
        "timestamp": str(record.get("timestamp", "")),
        "file_name": str(record.get("file_name", "unknown")),
        "sha256": str(record.get("sha256", "")),
        "final_label": final_label,
        "final_confidence": _safe_float(record.get("final_confidence", 0.0)),
        "rule_score": _safe_float(record.get("rule_score", 0.0)),
        "recommendation": str(record.get("recommendation", "")),
        "review_status": str(record.get("review_status", _DEFAULT_REVIEW_STATUS)),
        "priority": str(record.get("priority", _DEFAULT_PRIORITY)),
        "disposition": str(
            record.get("disposition", _default_disposition_for_verdict(final_label))
        ),
        "analyst_note": str(record.get("analyst_note", "")).strip(),
    }


def _fetch_hosted_scan_history(
    *,
    base_url: str | None = None,
    api_auth_token: str | None = None,
    limit: int = _HISTORY_API_RECENT_LIMIT,
) -> list[dict[str, Any]] | None:
    """Fetch recent scan history rows from the hosted API when configured."""
    normalized_base_url = str(
        base_url if base_url is not None else os.getenv("APP_PUBLIC_BASE_URL", "")
    ).strip().rstrip("/")
    if not normalized_base_url:
        return None

    try:
        resolved_limit = max(int(limit), 1)
    except (TypeError, ValueError):
        resolved_limit = _HISTORY_API_RECENT_LIMIT

    request_url = (
        f"{normalized_base_url}/api/scan/recent?"
        f"{urllib.parse.urlencode({'limit': resolved_limit})}"
    )
    headers = {"Accept": "application/json"}
    resolved_api_auth_token = str(
        api_auth_token if api_auth_token is not None else os.getenv("API_AUTH_TOKEN", "")
    ).strip()
    if resolved_api_auth_token:
        headers[API_TOKEN_HEADER_NAME] = resolved_api_auth_token
        headers["Authorization"] = f"Bearer {resolved_api_auth_token}"

    request_object = urllib.request.Request(request_url, headers=headers)
    try:
        with urllib.request.urlopen(request_object, timeout=_HISTORY_API_TIMEOUT_SECONDS) as response:
            response_payload = response.read().decode("utf-8")
    except (urllib.error.URLError, OSError, ValueError):
        return None

    try:
        payload = json.loads(response_payload)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict) or str(payload.get("status", "")).lower() != "ok":
        return None

    items = payload.get("items")
    if not isinstance(items, list):
        return None

    return [
        _normalize_dashboard_history_record(item)
        for item in items
        if isinstance(item, dict)
    ]


def _load_dashboard_history_records(limit: int = _HISTORY_API_RECENT_LIMIT) -> list[dict[str, Any]]:
    """Load dashboard history, preferring hosted API rows when configured."""
    hosted_history_records = _fetch_hosted_scan_history(limit=limit)
    if hosted_history_records is not None:
        return hosted_history_records
    return load_scan_history()


def _build_live_status_summary(history_records: list[dict[str, Any]]) -> dict[str, str | int]:
    """Build small top-strip summary values from persistent scan history."""
    malicious_count = 0
    suspicious_count = 0
    latest_timestamp: datetime | None = None

    for record in history_records:
        final_label = str(record.get("final_label", "")).lower()
        if final_label == "malicious":
            malicious_count += 1
        elif final_label == "suspicious":
            suspicious_count += 1

        parsed_timestamp = _parse_history_timestamp(str(record.get("timestamp", "")))
        if parsed_timestamp is not None and (
            latest_timestamp is None or parsed_timestamp > latest_timestamp
        ):
            latest_timestamp = parsed_timestamp

    if latest_timestamp is None:
        last_scan_display = "No scans yet"
    else:
        last_scan_display = latest_timestamp.astimezone().strftime("%Y-%m-%d %H:%M")

    return {
        "total_scans": len(history_records),
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "last_scan_time": last_scan_display,
    }


def _build_live_status_strip_html(history_records: list[dict[str, Any]]) -> str:
    """Return the live status strip HTML shown near the top of the UI."""
    summary = _build_live_status_summary(history_records)
    chips = [
        ("Total Scans", str(summary["total_scans"]), "Persistent scan history"),
        ("Malicious Files", str(summary["malicious_count"]), "High-priority detections"),
        ("Suspicious Files", str(summary["suspicious_count"]), "Files needing caution"),
        ("Last Scan", str(summary["last_scan_time"]), "Most recent recorded analysis"),
    ]
    return (
        '<section class="status-strip">'
        + "".join(
            (
                '<div class="status-chip">'
                f'<div class="status-label">{html.escape(label)}</div>'
                f'<div class="status-value">{html.escape(value)}</div>'
                f'<div class="status-meta">{html.escape(meta)}</div>'
                "</div>"
            )
            for label, value, meta in chips
        )
        + "</section>"
    )


def _build_history_trend_rows(history_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate history records into simple date-based trend rows."""
    grouped_rows: dict[str, dict[str, float | int | str]] = {}
    for record in history_records:
        parsed_timestamp = _parse_history_timestamp(str(record.get("timestamp", "")))
        if parsed_timestamp is not None:
            bucket = parsed_timestamp.date().isoformat()
        else:
            raw_timestamp = str(record.get("timestamp", "")).strip()
            bucket = raw_timestamp[:10] if len(raw_timestamp) >= 10 else "Unknown"

        row = grouped_rows.setdefault(
            bucket,
            {
                "date": bucket,
                "scan_count": 0,
                "malicious_count": 0,
                "suspicious_count": 0,
                "rule_score_total": 0.0,
            },
        )
        row["scan_count"] = int(row["scan_count"]) + 1
        final_label = str(record.get("final_label", "")).lower()
        if final_label == "malicious":
            row["malicious_count"] = int(row["malicious_count"]) + 1
        if final_label == "suspicious":
            row["suspicious_count"] = int(row["suspicious_count"]) + 1
        row["rule_score_total"] = float(row["rule_score_total"]) + float(record.get("rule_score", 0.0))

    trend_rows: list[dict[str, Any]] = []
    for bucket in sorted(grouped_rows.keys()):
        row = grouped_rows[bucket]
        scan_count = max(int(row["scan_count"]), 1)
        trend_rows.append(
            {
                "date": str(row["date"]),
                "scan_count": int(row["scan_count"]),
                "malicious_count": int(row["malicious_count"]),
                "suspicious_count": int(row["suspicious_count"]),
                "average_rule_score": round(float(row["rule_score_total"]) / scan_count, 2),
            }
        )
    return trend_rows


def _default_disposition_for_verdict(final_label: str) -> str:
    """Map the automated verdict to a practical default analyst disposition."""
    normalized_label = _normalize_verdict(final_label)
    if normalized_label == "benign":
        return "Safe"
    if normalized_label == "malicious":
        return "Malicious"
    return "Suspicious"


def _normalize_review_record_for_display(
    review_record: dict[str, Any] | None,
    *,
    final_label: str = "suspicious",
) -> dict[str, str]:
    """Normalize analyst review values for table display and exports."""
    review_record = review_record or {}
    return {
        "review_status": str(review_record.get("review_status", _DEFAULT_REVIEW_STATUS)),
        "priority": str(review_record.get("priority", _DEFAULT_PRIORITY)),
        "disposition": str(
            review_record.get("disposition", _default_disposition_for_verdict(final_label))
        ),
        "analyst_note": _summarize_analyst_note(str(review_record.get("analyst_note", ""))),
        "analyst_note_full": str(review_record.get("analyst_note", "")).strip(),
        "updated_at": str(review_record.get("updated_at", "")),
    }


def _summarize_analyst_note(note: str, *, char_limit: int = 120) -> str:
    """Return a compact analyst note preview for dense tables."""
    normalized_note = " ".join(str(note).split())
    if not normalized_note:
        return ""
    if len(normalized_note) <= char_limit:
        return normalized_note
    return f"{normalized_note[: char_limit - 3].rstrip()}..."


def _review_record_defaults(
    analysis_result: dict[str, Any],
    review_record: dict[str, Any] | None,
) -> dict[str, str]:
    """Resolve default analyst review values for one analyzed file."""
    summary = analysis_result["summary"]
    normalized_record = _normalize_review_record_for_display(
        review_record,
        final_label=str(summary.get("final_label", "suspicious")),
    )
    return {
        "file_name": str(summary.get("file_name", "unknown")),
        "sha256": str(analysis_result.get("sha256", "")),
        "source_timestamp": str(analysis_result.get("report_timestamp", "")),
        "analyst_note": normalized_record["analyst_note_full"],
        "review_status": normalized_record["review_status"],
        "priority": normalized_record["priority"],
        "disposition": normalized_record["disposition"],
        "updated_at": normalized_record["updated_at"],
    }


def _reader_policy(final_label: str) -> dict[str, Any]:
    """Return the Safe Reader policy for a final scan label."""
    if final_label == "benign":
        return {
            "level": "success",
            "message": "This PDF was classified as benign. Full in-app preview is allowed.",
            "preview_char_limit": _PREVIEW_CHAR_LIMITS["benign"],
            "allow_inline_preview": True,
            "require_confirmation": False,
            "checkbox_label": "",
        }
    if final_label == "malicious":
        return {
            "level": "error",
            "message": (
                "This PDF was classified as malicious. Only restricted metadata and text preview "
                "are shown by default. Full preview requires an explicit override."
            ),
            "preview_char_limit": _PREVIEW_CHAR_LIMITS["malicious"],
            "allow_inline_preview": False,
            "require_confirmation": True,
            "checkbox_label": "I understand the risk and want to render the full PDF preview.",
        }
    return {
        "level": "warning",
        "message": (
            "This PDF was classified as suspicious. Limited text preview is shown by default. "
            "Full preview is available only after explicit confirmation."
        ),
        "preview_char_limit": _PREVIEW_CHAR_LIMITS["suspicious"],
        "allow_inline_preview": False,
        "require_confirmation": True,
        "checkbox_label": "I understand the risk and want to render the full PDF preview.",
    }


def _normalize_verdict(final_label: str) -> str:
    """Normalize verdict labels for consistent UI styling."""
    normalized_label = str(final_label or "unknown").strip().lower()
    if normalized_label in _VERDICT_ICON_HTML:
        return normalized_label
    return "unknown"


def _verdict_color(final_label: str) -> str:
    """Return a consistent color for each verdict."""
    normalized_label = _normalize_verdict(final_label)
    if normalized_label == "benign":
        return "#16a34a"
    if normalized_label == "malicious":
        return "#dc2626"
    if normalized_label == "suspicious":
        return "#f59e0b"
    return "#64748b"


def _verdict_icon_html(final_label: str) -> str:
    """Return a compact icon span for one verdict label."""
    normalized_label = _normalize_verdict(final_label)
    icon_html = _VERDICT_ICON_HTML.get(normalized_label, "&#9679;")
    icon_label = _VERDICT_ICON_LABELS.get(normalized_label, "Unknown")
    return (
        f'<span class="verdict-badge-icon" title="{html.escape(icon_label)}" aria-hidden="true">'
        f"{icon_html}"
        "</span>"
    )


def _verdict_badge_html(final_label: str, *, prefix: str | None = None) -> str:
    """Return a compact colored badge for a verdict label."""
    normalized_label = _normalize_verdict(final_label)
    label_text = str(normalized_label).title()
    prefix_html = ""
    if prefix:
        prefix_html = f'<span class="verdict-badge-prefix">{html.escape(prefix)}:</span> '
    return (
        f'<div class="verdict-badge verdict-badge-{normalized_label}">'
        f"{_verdict_icon_html(normalized_label)}"
        '<span class="verdict-badge-text">'
        f"{prefix_html}{html.escape(label_text)}"
        "</span></div>"
    )


def _verdict_banner_config(final_label: str) -> dict[str, str]:
    """Return the Streamlit-native styling config for a verdict banner."""
    if final_label == "benign":
        return {
            "method": "success",
            "title": "Benign",
        }
    if final_label == "malicious":
        return {
            "method": "error",
            "title": "Malicious",
        }
    return {
        "method": "warning",
        "title": "Suspicious",
    }


def _widget_key(prefix: str, suffix: str) -> str:
    """Build a stable Streamlit widget key."""
    return f"{prefix}_{suffix}"


def _get_card_container(streamlit_module: Any) -> Any:
    """Return a bordered container when supported, otherwise a plain container."""
    try:
        return streamlit_module.container(border=True)
    except TypeError:
        return streamlit_module.container()


def _sticky_bar_item_html(label: str, value: str) -> str:
    """Return one compact sticky-bar item block."""
    return (
        '<div class="sticky-verdict-item">'
        f'<div class="sticky-verdict-label">{html.escape(label)}</div>'
        f'<div class="sticky-verdict-value">{value}</div>'
        "</div>"
    )


def _build_sticky_verdict_bar_html(
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> str:
    """Build the compact sticky verdict bar shown after analysis."""
    if not analyzed_results:
        return ""

    if len(analyzed_results) == 1:
        _, analysis_result = analyzed_results[0]
        summary = analysis_result["summary"]
        items = [
            _sticky_bar_item_html("File", html.escape(str(summary.get("file_name", "unknown")))),
            _sticky_bar_item_html(
                "Verdict",
                _verdict_badge_html(str(summary.get("final_label", "unknown"))),
            ),
            _sticky_bar_item_html(
                "Confidence",
                html.escape(f"{float(summary.get('final_confidence', 0.0)):.2f}"),
            ),
            _sticky_bar_item_html(
                "Rule Score",
                html.escape(f"{float(summary.get('rule_score', 0.0)):.2f}"),
            ),
        ]
    elif len(analyzed_results) == 2:
        summary_a = analyzed_results[0][1]["summary"]
        summary_b = analyzed_results[1][1]["summary"]
        comparison = build_comparison_summary(summary_a, summary_b)
        items = [
            _sticky_bar_item_html(
                "PDF A",
                _verdict_badge_html(str(summary_a.get("final_label", "unknown"))),
            ),
            _sticky_bar_item_html(
                "PDF B",
                _verdict_badge_html(str(summary_b.get("final_label", "unknown"))),
            ),
            _sticky_bar_item_html("Riskier File", html.escape(str(comparison["riskier_file"]))),
            _sticky_bar_item_html(
                "Verdict Match",
                html.escape("Same" if comparison["same_final_label"] else "Different"),
            ),
        ]
    else:
        counts = _count_verdicts(analyzed_results)
        items = [
            _sticky_bar_item_html("Total Files", html.escape(str(len(analyzed_results)))),
            _sticky_bar_item_html("Malicious", html.escape(str(counts["malicious"]))),
            _sticky_bar_item_html("Suspicious", html.escape(str(counts["suspicious"]))),
            _sticky_bar_item_html("Riskiest File", html.escape(_select_riskiest_file(analyzed_results))),
        ]

    return (
        '<div class="sticky-verdict-bar">'
        '<div class="sticky-verdict-title">Current Analysis Status</div>'
        '<div class="sticky-verdict-grid">'
        + "".join(items)
        + "</div></div>"
    )


def _render_sticky_verdict_bar(
    streamlit_module: Any,
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> None:
    """Render the sticky verdict bar after analysis completes."""
    sticky_bar_html = _build_sticky_verdict_bar_html(analyzed_results)
    if sticky_bar_html:
        streamlit_module.markdown(sticky_bar_html, unsafe_allow_html=True)


def _render_page_header(streamlit_module: Any) -> None:
    """Render the premium hero header."""
    streamlit_module.markdown(_build_hero_html(), unsafe_allow_html=True)


def _render_live_status_strip(streamlit_target: Any, history_records: list[dict[str, Any]]) -> None:
    """Render the live operational status strip near the top of the page."""
    streamlit_target.markdown(
        _build_live_status_strip_html(history_records),
        unsafe_allow_html=True,
    )


def _render_analysis_summary_section(streamlit_module: Any, summary: dict[str, Any]) -> None:
    """Render the polished top-level summary section."""
    final_label = str(summary.get("final_label", "unknown"))
    streamlit_module.subheader("Analysis Summary")
    verdict_col, metric_col_2, metric_col_3, metric_col_4 = streamlit_module.columns(4)
    with verdict_col:
        streamlit_module.markdown("**Verdict**")
        streamlit_module.markdown(_verdict_badge_html(final_label), unsafe_allow_html=True)
    metric_col_2.metric(
        "Final Confidence",
        f"{float(summary.get('final_confidence', 0.0)):.2f}",
    )
    metric_col_3.metric(
        "Rule Score",
        f"{float(summary.get('rule_score', 0.0)):.2f}",
    )
    metric_col_4.metric("Rule Severity", str(summary.get("rule_severity", "unknown")).title())

    streamlit_module.markdown(
        f"**Status Signal:** {_VERDICT_ICON_LABELS.get(_normalize_verdict(final_label), 'Unknown posture')}",
    )
    streamlit_module.caption(
        f"File: {summary.get('file_name', 'unknown')} | "
        f"ML Label: {summary.get('ml_label', 'unknown')} | "
        f"ML Confidence: {float(summary.get('ml_confidence', 0.0)):.2f}"
    )


def _render_list_section(streamlit_module: Any, title: str, items: list[Any], empty_message: str) -> None:
    """Render a simple list section with an empty-state message."""
    streamlit_module.subheader(title)
    if items:
        for item in items:
            streamlit_module.write(f"- {item}")
    else:
        streamlit_module.write(empty_message)


def _render_explanation_section(
    streamlit_module: Any,
    *,
    summary: dict[str, Any],
    recommendation: str,
) -> None:
    """Render a clearer explanation panel for the current PDF verdict."""
    explanation_panel = build_explanation_panel(summary, recommendation)

    streamlit_module.subheader("Why This File Was Flagged")

    insight_col_1, insight_col_2 = streamlit_module.columns(2)
    with insight_col_1:
        streamlit_module.markdown("**Confidence Interpretation**")
        streamlit_module.write(explanation_panel["confidence_interpretation"])
    with insight_col_2:
        streamlit_module.markdown("**Recommended Action**")
        streamlit_module.write(explanation_panel["recommended_action"])

    streamlit_module.markdown("**Plain-English Explanation**")
    streamlit_module.write(explanation_panel["plain_english_explanation"])

    streamlit_module.markdown("**Top Suspicious Indicators**")
    top_indicators = list(explanation_panel.get("top_suspicious_indicators", []))
    if top_indicators:
        for indicator in top_indicators:
            streamlit_module.write(f"- {indicator}")
    else:
        streamlit_module.write("No notable suspicious indicators were recorded for this file.")

    streamlit_module.markdown("**Triggered Rules**")
    triggered_rules = list(explanation_panel.get("triggered_rules", []))
    if triggered_rules:
        for rule in triggered_rules:
            streamlit_module.write(f"- {rule}")
    else:
        streamlit_module.write("No rules were triggered during the current analysis.")


def _render_rule_assessment_section(streamlit_module: Any, summary: dict[str, Any]) -> None:
    """Render the rule-based assessment section."""
    streamlit_module.subheader("Rule-Based Assessment")
    streamlit_module.write(f"**Rule Score:** {float(summary.get('rule_score', 0.0)):.2f}")
    streamlit_module.write(f"**Rule Severity:** {summary.get('rule_severity', 'unknown')}")
    triggered_rules = list(summary.get("triggered_rules", []))
    if triggered_rules:
        for rule in triggered_rules:
            streamlit_module.write(f"- {rule}")
    else:
        streamlit_module.write("No rule triggers were recorded.")


def _render_ml_assessment_section(streamlit_module: Any, analysis_result: dict[str, Any]) -> None:
    """Render the machine learning assessment section."""
    summary = analysis_result["summary"]
    streamlit_module.subheader("Machine Learning Assessment")
    streamlit_module.write(f"**Predicted Label:** {summary.get('ml_label', 'unknown')}")
    streamlit_module.write(
        f"**Confidence:** {float(summary.get('ml_confidence', 0.0)):.2f}"
    )
    class_probabilities = analysis_result["results"]["ml_result"].get("class_probabilities") or {}
    if class_probabilities:
        streamlit_module.json(class_probabilities)
    else:
        streamlit_module.write("Class probabilities were not available for this model.")


def _render_final_verdict_section(streamlit_module: Any, summary: dict[str, Any]) -> None:
    """Render the final verdict section with clear verdict styling."""
    streamlit_module.subheader("Final Verdict")
    final_label = str(summary.get("final_label", "unknown"))
    verdict_config = _verdict_banner_config(final_label)
    verdict_message = (
        f"Verdict: {verdict_config['title']} | "
        f"Confidence: {float(summary.get('final_confidence', 0.0)):.2f}"
    )
    getattr(streamlit_module, verdict_config["method"])(verdict_message)
    streamlit_module.markdown(_verdict_badge_html(final_label), unsafe_allow_html=True)

    explanations = list(summary.get("explanations", []))
    if explanations:
        streamlit_module.write("**Explanations:**")
        for explanation in explanations:
            streamlit_module.write(f"- {explanation}")
    else:
        streamlit_module.write("No explanations were generated.")


def _format_file_size(file_size: int) -> str:
    """Return a compact human-readable file size string."""
    if file_size < 1024:
        return f"{file_size} bytes"
    if file_size < 1024 * 1024:
        return f"{file_size / 1024:.1f} KB"
    return f"{file_size / (1024 * 1024):.2f} MB"


def _render_forensic_details_section(streamlit_module: Any, analysis_result: dict[str, Any]) -> None:
    """Render file hash and related forensic details."""
    streamlit_module.subheader("Forensic Details")
    info_col_1, info_col_2 = streamlit_module.columns(2)
    info_col_1.write(
        f"**File Size:** {_format_file_size(int(analysis_result.get('file_size', 0)))}"
    )
    info_col_2.write("**SHA-256:**")
    streamlit_module.code(str(analysis_result.get("sha256", "")), language="text")


def _render_recommendation_section(
    streamlit_module: Any,
    *,
    final_label: str,
    recommendation: str,
) -> None:
    """Render verdict-aware handling guidance."""
    streamlit_module.subheader("Recommendation")
    verdict_config = _verdict_banner_config(final_label)
    getattr(streamlit_module, verdict_config["method"])(recommendation)


def _render_analyst_review_section(
    streamlit_module: Any,
    *,
    analysis_result: dict[str, Any],
    key_prefix: str,
) -> None:
    """Render analyst notes and lightweight review workflow controls."""
    review_records_by_sha256 = load_analyst_reviews_by_sha256()
    existing_review_record = review_records_by_sha256.get(str(analysis_result.get("sha256", "")))
    defaults = _review_record_defaults(analysis_result, existing_review_record)

    saved_message_key = _widget_key(key_prefix, "review_saved_message")
    if streamlit_module.session_state.pop(saved_message_key, False):
        streamlit_module.success("Analyst review saved.")

    streamlit_module.subheader("Analyst Review")
    streamlit_module.caption(
        "Track investigation notes, review state, and handling decisions for this scanned file."
    )

    summary_cols = streamlit_module.columns(4)
    summary_cols[0].metric("Review Status", defaults["review_status"])
    summary_cols[1].metric("Priority", defaults["priority"])
    summary_cols[2].metric("Disposition", defaults["disposition"])
    summary_cols[3].metric("Review Record", "Saved" if existing_review_record else "Not Saved")

    control_cols = streamlit_module.columns(3)
    with control_cols[0]:
        review_status = streamlit_module.selectbox(
            "Review Status",
            options=list(REVIEW_STATUS_OPTIONS),
            index=list(REVIEW_STATUS_OPTIONS).index(defaults["review_status"]),
            key=_widget_key(key_prefix, "review_status"),
        )
    with control_cols[1]:
        priority = streamlit_module.selectbox(
            "Priority",
            options=list(PRIORITY_OPTIONS),
            index=list(PRIORITY_OPTIONS).index(defaults["priority"]),
            key=_widget_key(key_prefix, "priority"),
        )
    with control_cols[2]:
        disposition = streamlit_module.selectbox(
            "Disposition",
            options=list(DISPOSITION_OPTIONS),
            index=list(DISPOSITION_OPTIONS).index(defaults["disposition"]),
            key=_widget_key(key_prefix, "disposition"),
        )
    analyst_note = streamlit_module.text_area(
        "Analyst Note",
        value=defaults["analyst_note"],
        height=150,
        key=_widget_key(key_prefix, "analyst_note"),
        help="Add investigation notes, triage rationale, or follow-up context.",
    )

    if defaults["updated_at"]:
        streamlit_module.caption(f"Last updated: {defaults['updated_at']}")

    save_clicked = streamlit_module.button(
        "Save Analyst Review",
        use_container_width=True,
        key=_widget_key(key_prefix, "save_review"),
    )
    if save_clicked:
        save_analyst_review(
            file_name=defaults["file_name"],
            sha256=defaults["sha256"],
            source_timestamp=defaults["source_timestamp"],
            analyst_note=analyst_note,
            review_status=review_status,
            priority=priority,
            disposition=disposition,
        )
        streamlit_module.session_state[saved_message_key] = True
        streamlit_module.rerun()


def _render_pdf_metadata(streamlit_module: Any, reader_result: dict[str, Any]) -> None:
    """Render PDF metadata extracted by the safe reader."""
    streamlit_module.subheader("PDF Metadata")
    info_col_1, info_col_2 = streamlit_module.columns(2)
    info_col_1.write(f"**Page Count:** {int(reader_result.get('page_count', 0))}")
    info_col_2.write(
        f"**Metadata Fields:** {int(reader_result.get('metadata_field_count', 0))}"
    )
    metadata = reader_result.get("metadata", {})
    if metadata:
        streamlit_module.json(metadata)
    else:
        streamlit_module.write("No metadata could be extracted.")


def _render_text_preview(
    streamlit_module: Any,
    reader_result: dict[str, Any],
    *,
    char_limit: int,
    key_prefix: str,
) -> None:
    """Render a safe extracted-text preview."""
    streamlit_module.subheader("Extracted Text Preview")
    preview_text = str(reader_result.get("text_preview", "") or "")
    limited_preview = preview_text[:char_limit].strip()
    if limited_preview:
        streamlit_module.text_area(
            "Preview",
            value=limited_preview,
            height=260,
            disabled=True,
            key=_widget_key(key_prefix, "text_preview"),
        )
    else:
        streamlit_module.write("No readable text could be extracted from this PDF.")

    warnings = list(reader_result.get("warnings", []))
    if warnings:
        for warning in warnings:
            streamlit_module.caption(warning)


def _render_safe_reader_section(
    streamlit_module: Any,
    *,
    final_label: str,
    pdf_bytes: bytes,
    file_name: str,
    key_prefix: str,
) -> None:
    """Render Safe Reader controls with verdict-aware gating."""
    policy = _reader_policy(final_label)

    streamlit_module.subheader("Safe Reader")
    getattr(streamlit_module, policy["level"])(policy["message"])

    streamlit_module.download_button(
        label="Download Original PDF",
        data=pdf_bytes,
        file_name=file_name,
        mime="application/pdf",
        key=_widget_key(key_prefix, "download_pdf"),
    )

    allow_inline_preview = bool(policy["allow_inline_preview"])
    if bool(policy["require_confirmation"]):
        allow_inline_preview = streamlit_module.checkbox(
            policy["checkbox_label"],
            value=False,
            key=_widget_key(key_prefix, "preview_override"),
        )

    if not allow_inline_preview:
        streamlit_module.caption("Inline PDF rendering is disabled until preview is explicitly allowed.")
        return

    if len(pdf_bytes) > INLINE_PREVIEW_MAX_BYTES:
        streamlit_module.warning(
            "Inline preview is disabled because the file is too large for the embedded viewer."
        )
        return

    _render_inline_pdf_preview(streamlit_module, pdf_bytes, key_prefix=key_prefix)


def _render_inline_pdf_preview(streamlit_module: Any, pdf_bytes: bytes, *, key_prefix: str) -> None:
    """Render an inline PDF preview using a data URI."""
    encoded_pdf = base64.b64encode(pdf_bytes).decode("utf-8")
    iframe_html = (
        '<iframe src="data:application/pdf;base64,'
        f"{encoded_pdf}"
        '" width="100%" height="700" style="border: 1px solid #ccc;"></iframe>'
    )
    streamlit_module.markdown(
        f'<div id="{_widget_key(key_prefix, "inline_preview")}">{iframe_html}</div>',
        unsafe_allow_html=True,
    )


def _render_analysis_panel(
    streamlit_module: Any,
    *,
    title: str,
    analysis_result: dict[str, Any],
    key_prefix: str,
) -> None:
    """Render one full PDF analysis result panel."""
    summary = analysis_result["summary"]
    reader_result = analysis_result["reader_result"]
    final_label = str(summary.get("final_label", "suspicious"))
    review_records_by_sha256 = load_analyst_reviews_by_sha256()
    review_record = review_records_by_sha256.get(str(analysis_result.get("sha256", "")))
    with _get_card_container(streamlit_module):
        streamlit_module.markdown(f"### {title}")
        _render_analysis_summary_section(streamlit_module, summary)
        _render_explanation_section(
            streamlit_module,
            summary=summary,
            recommendation=str(analysis_result.get("recommendation", "")),
        )
        _render_list_section(
            streamlit_module,
            "Threat Indicators",
            list(summary.get("suspicious_indicators_found", [])),
            "No suspicious indicators were found.",
        )
        _render_rule_assessment_section(streamlit_module, summary)
        _render_ml_assessment_section(streamlit_module, analysis_result)
        _render_final_verdict_section(streamlit_module, summary)
        _render_forensic_details_section(streamlit_module, analysis_result)
        _render_recommendation_section(
            streamlit_module,
            final_label=final_label,
            recommendation=str(analysis_result.get("recommendation", "")),
        )
        _render_analyst_review_section(
            streamlit_module,
            analysis_result=analysis_result,
            key_prefix=key_prefix,
        )
        _render_pdf_metadata(streamlit_module, reader_result)
        _render_text_preview(
            streamlit_module,
            reader_result,
            char_limit=int(_reader_policy(final_label)["preview_char_limit"]),
            key_prefix=key_prefix,
        )
        _render_safe_reader_section(
            streamlit_module,
            final_label=final_label,
            pdf_bytes=analysis_result["pdf_bytes"],
            file_name=analysis_result["upload_name"],
            key_prefix=key_prefix,
        )
        streamlit_module.download_button(
            label="Download Forensic Report",
            data=summary_to_json(analysis_result.get("forensic_report", {})),
            file_name=f"{summary.get('file_name', 'analysis')}_forensic_report.json",
            mime="application/json",
            key=_widget_key(key_prefix, "download_report"),
        )
        streamlit_module.download_button(
            label="Download PDF Report",
            data=analysis_result.get("pdf_report_bytes", b""),
            file_name=f"{Path(str(summary.get('file_name', 'analysis'))).stem}_report.pdf",
            mime="application/pdf",
            key=_widget_key(key_prefix, "download_pdf_report"),
        )
        single_result_rows = _build_batch_summary_rows([(key_prefix, analysis_result)])
        if single_result_rows:
            single_result_rows[0].update(
                {
                    key: value
                    for key, value in _normalize_review_record_for_display(
                        review_record,
                        final_label=final_label,
                    ).items()
                    if key in {"review_status", "priority", "disposition", "analyst_note"}
                }
            )
        streamlit_module.download_button(
            label="Download CSV Summary",
            data=build_csv_export_bytes(single_result_rows),
            file_name=f"{Path(str(summary.get('file_name', 'analysis'))).stem}_summary.csv",
            mime="text/csv",
            key=_widget_key(key_prefix, "download_csv_summary"),
        )


def _render_results_dashboard(
    streamlit_module: Any,
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> None:
    """Render a compact dashboard after analysis."""
    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Results Dashboard")

        if len(analyzed_results) == 1:
            _, analysis_result = analyzed_results[0]
            summary = analysis_result["summary"]
            dashboard_cols = streamlit_module.columns(4)
            with dashboard_cols[0]:
                streamlit_module.caption("PDF A Verdict")
                streamlit_module.markdown(
                    _verdict_badge_html(str(summary.get("final_label", "unknown"))),
                    unsafe_allow_html=True,
                )
            dashboard_cols[1].metric("Riskier File", str(summary.get("file_name", "PDF A")))
            dashboard_cols[2].metric("Higher Rule Score", str(summary.get("file_name", "PDF A")))
            dashboard_cols[3].metric("Verdict Match", "Single File")
            return

        if len(analyzed_results) == 2:
            summary_a = analyzed_results[0][1]["summary"]
            summary_b = analyzed_results[1][1]["summary"]
            comparison = build_comparison_summary(summary_a, summary_b)

            dashboard_cols = streamlit_module.columns(5)
            with dashboard_cols[0]:
                streamlit_module.caption("PDF A Verdict")
                streamlit_module.markdown(
                    _verdict_badge_html(str(summary_a.get("final_label", "unknown"))),
                    unsafe_allow_html=True,
                )
            with dashboard_cols[1]:
                streamlit_module.caption("PDF B Verdict")
                streamlit_module.markdown(
                    _verdict_badge_html(str(summary_b.get("final_label", "unknown"))),
                    unsafe_allow_html=True,
                )
            dashboard_cols[2].metric("Riskier File", comparison["riskier_file"])
            dashboard_cols[3].metric("Higher Rule Score", comparison["higher_rule_score_file"])
            dashboard_cols[4].metric(
                "Verdict Match",
                "Same" if comparison["same_final_label"] else "Different",
            )
            return

        counts = _count_verdicts(analyzed_results)
        dashboard_cols = streamlit_module.columns(4)
        dashboard_cols[0].metric("Total Files", str(len(analyzed_results)))
        dashboard_cols[1].metric("Benign", str(counts["benign"]))
        dashboard_cols[2].metric("Suspicious", str(counts["suspicious"]))
        dashboard_cols[3].metric("Malicious", str(counts["malicious"]))


def _render_analytics_dashboard(
    streamlit_module: Any,
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> None:
    """Render a dashboard-style analytics section after analysis."""
    counts = _count_verdicts(analyzed_results)
    dashboard_rows = _build_dashboard_table_rows(analyzed_results)
    verdict_distribution_rows = _build_verdict_distribution_rows(analyzed_results)
    score_chart_rows = _build_score_chart_rows(analyzed_results)
    confidence_chart_rows = _build_confidence_chart_rows(analyzed_results)

    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Analytics Dashboard")
        metric_cols = streamlit_module.columns(4)
        metric_cols[0].metric("Total Files Analyzed", str(len(analyzed_results)))
        metric_cols[1].metric("Benign", str(counts["benign"]))
        metric_cols[2].metric("Suspicious", str(counts["suspicious"]))
        metric_cols[3].metric("Malicious", str(counts["malicious"]))
        chart_col_1, chart_col_2, chart_col_3 = streamlit_module.columns(3)
        with chart_col_1:
            streamlit_module.caption("Verdict Distribution")
            streamlit_module.bar_chart(verdict_distribution_rows, x="verdict", y="count")
        with chart_col_2:
            streamlit_module.caption("Rule Score Comparison")
            streamlit_module.bar_chart(score_chart_rows, x="file_name", y="rule_score")
        with chart_col_3:
            streamlit_module.caption("Confidence Comparison")
            streamlit_module.bar_chart(confidence_chart_rows, x="file_name", y="confidence")

        streamlit_module.subheader("Analyzed Files Table")
        streamlit_module.dataframe(dashboard_rows, use_container_width=True)
        streamlit_module.download_button(
            label="Download Dashboard CSV",
            data=build_csv_export_bytes(dashboard_rows),
            file_name="analysis_dashboard.csv",
            mime="text/csv",
            key="download_dashboard_csv",
        )


def _render_batch_summary(
    streamlit_module: Any,
    analyzed_results: list[tuple[str, dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Render summary metrics and a table for multi-file batch mode."""
    counts = _count_verdicts(analyzed_results)
    rows = _build_batch_summary_rows(analyzed_results)
    analysis_by_name = {
        str(analysis_result["summary"].get("file_name", key_prefix)): analysis_result
        for key_prefix, analysis_result in analyzed_results
    }

    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Batch Analysis Overview")
        metric_cols = streamlit_module.columns(4)
        metric_cols[0].metric("Total Files", str(len(analyzed_results)))
        metric_cols[1].metric("Benign", str(counts["benign"]))
        metric_cols[2].metric("Suspicious", str(counts["suspicious"]))
        metric_cols[3].metric("Malicious", str(counts["malicious"]))

        streamlit_module.subheader("Batch Results Summary")
        streamlit_module.dataframe(rows, use_container_width=True)
        streamlit_module.download_button(
            label="Download Batch Summary CSV",
            data=build_csv_export_bytes(rows),
            file_name="batch_results_summary.csv",
            mime="text/csv",
            key="download_batch_summary_csv",
        )
    return analysis_by_name


def _render_scan_history_section(
    streamlit_module: Any,
    history_records: list[dict[str, Any]] | None = None,
) -> None:
    """Render persistent scan history with search, filters, and sorting."""
    history_records = _load_dashboard_history_records() if history_records is None else history_records
    review_records_by_sha256 = load_analyst_reviews_by_sha256()
    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Scan History")
        if not history_records:
            streamlit_module.caption("No previous scan records are available yet.")
            return

        trend_rows = _build_history_trend_rows(history_records)
        if trend_rows:
            streamlit_module.markdown("#### Risk Trend")
            trend_col_1, trend_col_2 = streamlit_module.columns(2)
            with trend_col_1:
                streamlit_module.caption("Scans Over Time")
                streamlit_module.line_chart(trend_rows, x="date", y="scan_count")
            with trend_col_2:
                streamlit_module.caption("Average Rule Score Over Time")
                streamlit_module.line_chart(trend_rows, x="date", y="average_rule_score")

        search_col_1, search_col_2 = streamlit_module.columns(2)
        with search_col_1:
            file_name_query = streamlit_module.text_input(
                "Search by file name",
                value="",
                key="scan_history_search_file_name",
            )
        with search_col_2:
            sha256_query = streamlit_module.text_input(
                "Search by SHA-256",
                value="",
                key="scan_history_search_sha256",
            )

        sort_col, verdict_col = streamlit_module.columns(2)
        with sort_col:
            sort_option_label = streamlit_module.selectbox(
                "Sort history",
                options=["newest", "highest rule score", "highest confidence"],
                key="scan_history_sort_option",
            )
        with verdict_col:
            verdict_filter = streamlit_module.selectbox(
                "Quick verdict filter",
                options=["all", "benign", "suspicious", "malicious"],
                key="scan_history_verdict_filter",
            )

        sort_option_map = {
            "newest": "newest",
            "highest rule score": "highest_rule_score",
            "highest confidence": "highest_confidence",
        }
        filtered_records = filter_scan_history_records(history_records, verdict_filter)
        filtered_records = search_scan_history_records(
            filtered_records,
            file_name_query=file_name_query,
            sha256_query=sha256_query,
        )
        filtered_records = sort_scan_history_records(
            filtered_records,
            sort_option_map[sort_option_label],
        )
        display_rows = _build_scan_history_table_rows(
            filtered_records,
            review_records_by_sha256=review_records_by_sha256,
        )

        if not display_rows:
            streamlit_module.caption("No history records match the current search and filter settings.")
            return

        streamlit_module.caption(
            "Review workflow columns show the latest saved analyst note, status, priority, and disposition."
        )
        streamlit_module.dataframe(display_rows, use_container_width=True)
        streamlit_module.download_button(
            label="Download Scan History CSV",
            data=build_csv_export_bytes(display_rows, fieldnames=_HISTORY_EXPORT_FIELDNAMES),
            file_name="scan_history.csv",
            mime="text/csv",
            key="download_scan_history_csv",
        )


def _render_high_risk_workflow_section(
    streamlit_module: Any,
    history_records: list[dict[str, Any]] | None = None,
) -> None:
    """Render a practical quarantine-style workflow for malicious and high-risk files."""
    history_records = _load_dashboard_history_records() if history_records is None else history_records
    review_records_by_sha256 = load_analyst_reviews_by_sha256()
    with _get_card_container(streamlit_module):
        streamlit_module.subheader("High-Risk / Quarantine Workflow")
        if not history_records:
            streamlit_module.caption("No scan history is available yet for high-risk review.")
            return

        high_risk_records = sort_scan_history_records(
            get_high_risk_scan_history_records(history_records),
            "newest",
        )
        if not high_risk_records:
            streamlit_module.caption("No malicious or high-risk suspicious files are currently recorded.")
            return

        malicious_records = sort_scan_history_records(
            get_malicious_scan_history_records(history_records),
            "newest",
        )
        high_risk_rows = _build_high_risk_table_rows(
            high_risk_records,
            review_records_by_sha256=review_records_by_sha256,
        )
        malicious_rows = _build_scan_history_table_rows(
            malicious_records,
            review_records_by_sha256=review_records_by_sha256,
        )
        suspicious_high_risk_count = sum(
            1
            for record in high_risk_records
            if str(record.get("final_label", "")).lower() == "suspicious"
        )

        streamlit_module.caption(
            f"This review list includes malicious files and suspicious files with rule score >= "
            f"{HIGH_RISK_RULE_SCORE_THRESHOLD:.0f}."
        )

        metric_cols = streamlit_module.columns(3)
        metric_cols[0].metric("High-Risk Files", str(len(high_risk_records)))
        metric_cols[1].metric("Malicious", str(len(malicious_records)))
        metric_cols[2].metric("High-Risk Suspicious", str(suspicious_high_risk_count))

        streamlit_module.caption(
            "Analyst review fields help track triage ownership and final handling decisions for risky files."
        )
        streamlit_module.dataframe(high_risk_rows, use_container_width=True)
        if malicious_rows:
            streamlit_module.download_button(
                label="Download Malicious CSV",
                data=build_csv_export_bytes(malicious_rows, fieldnames=_HISTORY_EXPORT_FIELDNAMES),
                file_name="malicious_files.csv",
                mime="text/csv",
                key="download_malicious_csv",
            )
        streamlit_module.download_button(
            label="Download High-Risk Review CSV",
            data=build_csv_export_bytes(
                high_risk_rows,
                fieldnames=["risk_category", *_HISTORY_EXPORT_FIELDNAMES],
            ),
            file_name="high_risk_review.csv",
            mime="text/csv",
            key="download_high_risk_csv",
        )


def _render_comparison_overview(
    streamlit_module: Any,
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
) -> None:
    """Render a cleaner high-level comparison overview."""
    comparison = build_comparison_summary(summary_a, summary_b)

    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Comparison Overview")
        badge_col_1, badge_col_2 = streamlit_module.columns(2)
        with badge_col_1:
            streamlit_module.markdown(
                _verdict_badge_html(str(summary_a.get("final_label", "unknown")), prefix="PDF A"),
                unsafe_allow_html=True,
            )
        with badge_col_2:
            streamlit_module.markdown(
                _verdict_badge_html(str(summary_b.get("final_label", "unknown")), prefix="PDF B"),
                unsafe_allow_html=True,
            )

        metric_col_1, metric_col_2, metric_col_3, metric_col_4 = streamlit_module.columns(4)
        metric_col_1.metric("Riskier File", comparison["riskier_file"])
        metric_col_2.metric("Higher Rule Score", comparison["higher_rule_score_file"])
        metric_col_3.metric(
            "More Indicators",
            comparison["more_suspicious_indicators_file"],
        )
        metric_col_4.metric(
            "Same Verdict",
            "Yes" if comparison["same_final_label"] else "No",
        )
        streamlit_module.info(comparison["comparison_statement"])


def main() -> None:
    """Run the Streamlit application."""
    streamlit_module = _require_streamlit()
    streamlit_module.set_page_config(page_title="Advanced PDFSafeScan", layout="wide")
    _inject_page_styles(streamlit_module)
    _render_page_header(streamlit_module)
    status_strip_placeholder = streamlit_module.empty()

    with _get_card_container(streamlit_module):
        streamlit_module.subheader("Upload Files")
        streamlit_module.caption(
            "Upload one PDF for focused analysis, two PDFs for direct comparison, multiple PDFs for batch review, "
            "or one ZIP archive for staged intake."
        )
        upload_col_a, upload_col_b = streamlit_module.columns(2)

        with upload_col_a:
            with _get_card_container(streamlit_module):
                streamlit_module.markdown("#### PDF A")
                streamlit_module.caption("Upload the primary PDF to analyze or compare.")
                uploaded_file_a = streamlit_module.file_uploader(
                    "Choose PDF A",
                    type=["pdf"],
                    key="upload_pdf_a",
                    label_visibility="collapsed",
                )

        with upload_col_b:
            with _get_card_container(streamlit_module):
                streamlit_module.markdown("#### PDF B")
                streamlit_module.caption("Optional: upload a second PDF for side-by-side comparison.")
                uploaded_file_b = streamlit_module.file_uploader(
                    "Choose PDF B",
                    type=["pdf"],
                    key="upload_pdf_b",
                    label_visibility="collapsed",
                )

        with _get_card_container(streamlit_module):
            streamlit_module.markdown("#### Batch Upload")
            streamlit_module.caption("Optional: upload multiple PDFs for one-run batch analysis.")
            batch_uploaded_files = streamlit_module.file_uploader(
                "Choose batch PDFs",
                type=["pdf"],
                key="upload_pdf_batch",
                label_visibility="collapsed",
                accept_multiple_files=True,
            )

        with _get_card_container(streamlit_module):
            streamlit_module.markdown("#### ZIP Batch Upload")
            streamlit_module.caption("Optional: upload one ZIP archive containing multiple PDFs for batch analysis.")
            uploaded_zip_file = streamlit_module.file_uploader(
                "Choose ZIP archive",
                type=["zip"],
                key="upload_pdf_zip",
                label_visibility="collapsed",
            )

        streamlit_module.caption(
            "Workflow: upload one or two PDFs, multiple PDFs, or a ZIP archive of PDFs, then click Analyze Files."
        )

        with streamlit_module.expander("Advanced Settings", expanded=False):
            model_dir_input = streamlit_module.text_input("Model directory", value="models")

        analyze_clicked = streamlit_module.button(
            "Analyze Files",
            type="primary",
            use_container_width=True,
        )

    uploads: list[tuple[str, Any]] = []
    if uploaded_file_a is not None:
        uploads.append(("pdf_a", uploaded_file_a))
    if uploaded_file_b is not None:
        uploads.append(("pdf_b", uploaded_file_b))
    for index, uploaded_file in enumerate(batch_uploaded_files or [], start=1):
        uploads.append((f"batch_{index}", uploaded_file))
    if uploaded_zip_file is not None:
        uploads.append(("zip_batch", uploaded_zip_file))

    current_signature = _build_upload_signature(uploads)
    session_state = streamlit_module.session_state
    history_records = _load_dashboard_history_records()

    if analyze_clicked:
        if not uploads:
            streamlit_module.warning("Upload at least one PDF before starting analysis.")
            return

        direct_uploads: list[tuple[str, Any]] = []
        if uploaded_file_a is not None:
            direct_uploads.append(("pdf_a", uploaded_file_a))
        if uploaded_file_b is not None:
            direct_uploads.append(("pdf_b", uploaded_file_b))
        for index, uploaded_file in enumerate(batch_uploaded_files or [], start=1):
            direct_uploads.append((f"batch_{index}", uploaded_file))

        for _, uploaded_file in direct_uploads:
            if not _is_pdf_filename(getattr(uploaded_file, "name", None)):
                streamlit_module.error("Only PDF files are supported.")
                return

        if uploaded_zip_file is not None and not _is_zip_filename(getattr(uploaded_zip_file, "name", None)):
            streamlit_module.error("ZIP batch upload accepts only .zip files.")
            return

        analysis_uploads = list(direct_uploads)
        if uploaded_zip_file is not None:
            try:
                zip_pdf_uploads = extract_pdf_uploads_from_zip(uploaded_zip_file)
            except ZIPIngestError as exc:
                if analysis_uploads:
                    streamlit_module.warning(f"{exc} Continuing with the other uploaded PDF files.")
                else:
                    streamlit_module.error(str(exc))
                    return
            else:
                if not zip_pdf_uploads:
                    zip_warning = "No PDF files were found inside the uploaded ZIP archive."
                    if analysis_uploads:
                        streamlit_module.warning(f"{zip_warning} Continuing with the other uploaded PDF files.")
                    else:
                        streamlit_module.warning(zip_warning)
                        return
                for index, uploaded_file in enumerate(zip_pdf_uploads, start=1):
                    analysis_uploads.append((f"zip_pdf_{index}", uploaded_file))

        try:
            with streamlit_module.spinner("Analyzing uploaded PDF file(s)..."):
                classifier = load_saved_model(model_dir=Path(model_dir_input))
                analyzed_results = [
                    (key_prefix, _analyze_uploaded_pdf(uploaded_file, classifier))
                    for key_prefix, uploaded_file in analysis_uploads
                ]
            session_state["analysis_results"] = analyzed_results
            session_state["analysis_signature"] = current_signature
            try:
                append_scan_history_records(analyzed_results)
            except OSError as history_error:
                streamlit_module.warning(f"Analysis completed, but scan history could not be saved: {history_error}")
            history_records = _load_dashboard_history_records()
        except (FileNotFoundError, PDFParserError, MLClassifierError, PDFReaderError, ValueError) as exc:
            streamlit_module.error(f"Analysis failed: {exc}")
            return

    _render_live_status_strip(status_strip_placeholder, history_records)

    stored_signature = session_state.get("analysis_signature", [])
    analyzed_results = session_state.get("analysis_results", [])

    if not uploads:
        streamlit_module.info(
            "Upload one PDF for a single analysis, two PDFs for comparison, multiple PDFs, or one ZIP archive of PDFs."
        )
        _render_high_risk_workflow_section(streamlit_module, history_records)
        _render_scan_history_section(streamlit_module, history_records)
        return

    if stored_signature != current_signature:
        streamlit_module.info("Files are ready. Click Analyze Files to run the assessment.")
        _render_high_risk_workflow_section(streamlit_module, history_records)
        _render_scan_history_section(streamlit_module, history_records)
        return

    if not analyzed_results:
        streamlit_module.info("Files are ready. Click Analyze Files to run the assessment.")
        _render_high_risk_workflow_section(streamlit_module, history_records)
        _render_scan_history_section(streamlit_module, history_records)
        return

    streamlit_module.success("Analysis completed.")
    _render_sticky_verdict_bar(streamlit_module, analyzed_results)
    _render_results_dashboard(streamlit_module, analyzed_results)
    _render_analytics_dashboard(streamlit_module, analyzed_results)
    _render_high_risk_workflow_section(streamlit_module, history_records)
    _render_scan_history_section(streamlit_module, history_records)

    if len(analyzed_results) == 1:
        key_prefix, analysis_result = analyzed_results[0]
        _render_analysis_panel(
            streamlit_module,
            title="Analysis Result",
            analysis_result=analysis_result,
            key_prefix=key_prefix,
        )
        return

    if len(analyzed_results) == 2:
        summary_a = analyzed_results[0][1]["summary"]
        summary_b = analyzed_results[1][1]["summary"]
        _render_comparison_overview(streamlit_module, summary_a, summary_b)

        left_col, right_col = streamlit_module.columns(2)
        (key_prefix_a, analysis_result_a), (key_prefix_b, analysis_result_b) = analyzed_results

        with left_col:
            _render_analysis_panel(
                streamlit_module,
                title="PDF A",
                analysis_result=analysis_result_a,
                key_prefix=key_prefix_a,
            )

        with right_col:
            _render_analysis_panel(
                streamlit_module,
                title="PDF B",
                analysis_result=analysis_result_b,
                key_prefix=key_prefix_b,
            )
        return

    analysis_by_name = _render_batch_summary(streamlit_module, analyzed_results)
    selected_file_name = streamlit_module.selectbox(
        "Inspect one file in detail",
        options=list(analysis_by_name.keys()),
        key="batch_detail_select",
    )
    selected_analysis = analysis_by_name[selected_file_name]
    selected_key_prefix = next(
        key_prefix
        for key_prefix, analysis_result in analyzed_results
        if analysis_result is selected_analysis
    )
    _render_analysis_panel(
        streamlit_module,
        title=f"Detailed View: {selected_file_name}",
        analysis_result=selected_analysis,
        key_prefix=selected_key_prefix,
    )


if __name__ == "__main__":
    main()
