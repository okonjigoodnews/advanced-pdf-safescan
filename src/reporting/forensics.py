"""Helpers for PDF hashing, verdict guidance, forensic report assembly, and VirusTotal lookup."""

from __future__ import annotations

import hashlib
import logging
import os
import urllib.error
import urllib.request
import json
from typing import Any

_logger = logging.getLogger(__name__)

# VirusTotal API configuration
_VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
_VIRUSTOTAL_TIMEOUT_SECONDS = 10
_VIRUSTOTAL_API_KEY_ENV = "VIRUSTOTAL_API_KEY"

# Thresholds for VirusTotal verdict
_VT_MALICIOUS_THRESHOLD = 3   # 3+ engines flag = malicious
_VT_SUSPICIOUS_THRESHOLD = 1  # 1+ engines flag = suspicious


def compute_sha256(file_bytes: bytes) -> str:
    """Return the SHA-256 hash for a PDF byte payload."""
    return hashlib.sha256(file_bytes).hexdigest()


def recommendation_for_verdict(final_label: str) -> str:
    """Return handling guidance for a final scan verdict."""
    if final_label == "benign":
        return "Safe to open under normal precautions."
    if final_label == "malicious":
        return "Do not open. Quarantine or isolate the file and investigate further."
    return "Open with caution. Prefer isolated viewing and further inspection before trusting the file."


def lookup_virustotal(sha256: str) -> dict[str, Any]:
    """Look up a SHA-256 hash on VirusTotal and return a structured result.

    Returns a dict with keys:
        - found (bool): whether the hash was found on VirusTotal
        - malicious (int): number of engines flagging as malicious
        - suspicious (int): number of engines flagging as suspicious
        - harmless (int): number of engines flagging as harmless
        - undetected (int): number of engines with no detection
        - total_engines (int): total engines that scanned
        - vt_verdict (str): 'malicious', 'suspicious', 'clean', or 'unknown'
        - vt_permalink (str): link to the VirusTotal report
        - error (str): error message if lookup failed
    """
    api_key = os.getenv(_VIRUSTOTAL_API_KEY_ENV, "").strip()

    # Return unknown result if no API key configured
    if not api_key:
        return _vt_unknown_result("VirusTotal API key not configured.")

    normalized_sha256 = str(sha256).strip().lower()
    if not normalized_sha256:
        return _vt_unknown_result("No SHA-256 hash provided.")

    url = _VIRUSTOTAL_API_URL.format(sha256=normalized_sha256)
    request = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=_VIRUSTOTAL_TIMEOUT_SECONDS) as response:
            raw = response.read()
            data = json.loads(raw)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            # Hash not found on VirusTotal — file has never been submitted
            return {
                "found": False,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "total_engines": 0,
                "vt_verdict": "unknown",
                "vt_permalink": "",
                "error": "Hash not found on VirusTotal. File may not have been submitted before.",
            }
        _logger.warning("VirusTotal API HTTP error: %s", exc.code)
        return _vt_unknown_result(f"VirusTotal API returned HTTP {exc.code}.")
    except urllib.error.URLError as exc:
        _logger.warning("VirusTotal API connection error: %s", exc.reason)
        return _vt_unknown_result(f"Could not connect to VirusTotal: {exc.reason}.")
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        _logger.warning("VirusTotal API response parse error: %s", exc)
        return _vt_unknown_result("Could not parse VirusTotal response.")

    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total_engines = malicious + suspicious + harmless + undetected

        permalink = (
            data.get("data", {})
            .get("links", {})
            .get("self", "")
            .replace("api/v3/files", "gui/file")
        )

        if malicious >= _VT_MALICIOUS_THRESHOLD:
            vt_verdict = "malicious"
        elif suspicious >= _VT_SUSPICIOUS_THRESHOLD or malicious > 0:
            vt_verdict = "suspicious"
        else:
            vt_verdict = "clean"

        return {
            "found": True,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines,
            "vt_verdict": vt_verdict,
            "vt_permalink": permalink,
            "error": "",
        }
    except (KeyError, TypeError) as exc:
        _logger.warning("VirusTotal response missing expected fields: %s", exc)
        return _vt_unknown_result("VirusTotal response was missing expected fields.")


def _vt_unknown_result(error: str) -> dict[str, Any]:
    """Return a safe default VirusTotal result for error cases."""
    return {
        "found": False,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "total_engines": 0,
        "vt_verdict": "unknown",
        "vt_permalink": "",
        "error": error,
    }


def build_forensic_report(
    *,
    summary: dict[str, Any],
    reader_result: dict[str, Any],
    sha256: str,
    file_size: int,
    recommendation: str,
    virustotal_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a clean forensic report dictionary for JSON export."""
    metadata = reader_result.get("metadata", {})
    warnings = list(reader_result.get("warnings", []))

    report = {
        "sha256": sha256,
        "file_name": str(summary.get("file_name", "unknown")),
        "file_size": int(file_size),
        "final_label": str(summary.get("final_label", "unknown")),
        "final_confidence": _safe_float(summary.get("final_confidence", 0.0)),
        "rule_score": _safe_float(summary.get("rule_score", 0.0)),
        "rule_severity": str(summary.get("rule_severity", "unknown")),
        "ml_label": str(summary.get("ml_label", "unknown")),
        "ml_confidence": _safe_float(summary.get("ml_confidence", 0.0)),
        "suspicious_indicators": list(summary.get("suspicious_indicators_found", [])),
        "triggered_rules": list(summary.get("triggered_rules", [])),
        "explanations": list(summary.get("explanations", [])),
        "metadata_summary": {
            "field_count": int(reader_result.get("metadata_field_count", 0)),
            "fields": dict(metadata if isinstance(metadata, dict) else {}),
        },
        "page_count": int(reader_result.get("page_count", 0)),
        "text_extraction_status": _text_extraction_status(reader_result),
        "safe_reader_warnings": warnings,
        "recommendation": recommendation,
    }

    # Add VirusTotal result if available
    if virustotal_result is not None:
        report["virustotal"] = virustotal_result

    return report


def _text_extraction_status(reader_result: dict[str, Any]) -> str:
    """Return a simple extraction status label for the forensic report."""
    text_extraction_succeeded = bool(reader_result.get("text_extraction_succeeded", False))
    warnings = list(reader_result.get("warnings", []))

    if text_extraction_succeeded and warnings:
        return "partial"
    if text_extraction_succeeded:
        return "success"
    return "limited_or_unavailable"


def _safe_float(value: object, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
