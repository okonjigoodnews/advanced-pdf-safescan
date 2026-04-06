"""Security-focused image analysis helpers for suspicious image files."""

from __future__ import annotations

import io
import re
from typing import Any

from src.analysis.file_types import FILE_TYPE_IMAGE, sniff_image_format
from src.reporting.summary import build_analysis_summary

_URL_PATTERN = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+", re.IGNORECASE)
_LURE_FILENAME_TERMS = (
    "invoice",
    "payment",
    "urgent",
    "login",
    "secure",
    "account",
    "verify",
    "bank",
    "receipt",
    "password",
    "reset",
    "payroll",
)
_LOGIN_PHRASES = (
    "sign in",
    "log in",
    "login",
    "password",
    "verify your account",
    "confirm your identity",
    "account suspended",
    "credential",
)
_URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "payment due",
    "invoice overdue",
    "final notice",
    "action required",
    "click here",
)
_BRAND_TERMS = (
    "microsoft",
    "google",
    "paypal",
    "apple",
    "adobe",
    "docusign",
    "amazon",
    "bank",
    "office 365",
)


def analyze_image_bytes(file_bytes: bytes, *, file_name: str) -> dict[str, Any]:
    """Analyze an image for security-relevant metadata, OCR text, and QR content."""
    metadata = _read_image_metadata(file_bytes)
    extracted_text, ocr_status = _extract_text_from_image(file_bytes)
    qr_findings, qr_status = _extract_qr_findings(file_bytes)
    suspicious_text_indicators = find_suspicious_text_indicators(
        extracted_text=extracted_text,
        file_name=file_name,
        qr_findings=qr_findings,
    )
    suspicious_indicators_found, triggered_rules, explanations, rule_score = _score_image_risk(
        file_name=file_name,
        metadata=metadata,
        extracted_text=extracted_text,
        qr_findings=qr_findings,
        suspicious_text_indicators=suspicious_text_indicators,
    )
    final_label = _final_label_for_score(rule_score)
    final_confidence = _confidence_for_score(rule_score)

    image_dimensions = metadata.get("dimensions") or {}
    image_specific_fields = {
        "image_format": str(metadata.get("image_format", sniff_image_format(file_bytes) or "unknown")),
        "image_dimensions": {
            "width": int(image_dimensions.get("width", 0)),
            "height": int(image_dimensions.get("height", 0)),
        },
        "color_mode": str(metadata.get("color_mode", "unknown")),
        "exif_metadata": dict(metadata.get("exif_metadata", {})),
        "extracted_text": extracted_text,
        "suspicious_text_indicators": suspicious_text_indicators,
        "qr_findings": qr_findings,
        "ocr_status": ocr_status,
        "qr_status": qr_status,
        "steganography_status": "not_run",
        "metadata_status": str(metadata.get("metadata_status", "unavailable")),
    }
    summary = build_analysis_summary(
        file_type=FILE_TYPE_IMAGE,
        parser_output={
            "file_name": file_name,
            "file_path": "",
        },
        final_decision={
            "final_label": final_label,
            "final_confidence": final_confidence,
            "rule_score": rule_score,
            "rule_severity": _severity_for_score(rule_score),
            "ml_label": "not_applicable",
            "ml_confidence": 0.0,
            "triggered_rules": triggered_rules,
            "explanations": explanations,
        },
        suspicious_indicators=suspicious_indicators_found,
        extra_fields=image_specific_fields,
    )
    return {
        "summary": summary,
        "image_analysis": {
            **image_specific_fields,
            "metadata": metadata,
        },
    }


def find_suspicious_text_indicators(
    *,
    extracted_text: str,
    file_name: str,
    qr_findings: list[dict[str, str]] | None = None,
) -> list[str]:
    """Return normalized phishing-style text indicators found in image content."""
    indicators: list[str] = []
    normalized_text = str(extracted_text or "").lower()
    normalized_file_name = str(file_name or "").lower()
    qr_findings = qr_findings or []

    for term in _LURE_FILENAME_TERMS:
        if term in normalized_file_name:
            indicators.append(f"Filename lure term: {term}")

    for phrase in _LOGIN_PHRASES:
        if phrase in normalized_text:
            indicators.append(f"Credential prompt text: {phrase}")

    for phrase in _URGENCY_PHRASES:
        if phrase in normalized_text:
            indicators.append(f"Urgent delivery language: {phrase}")

    found_urls = extract_urls_from_text(normalized_text)
    for url in found_urls:
        indicators.append(f"Visible URL: {url}")

    brand_hits = [brand for brand in _BRAND_TERMS if brand in normalized_text]
    if brand_hits and any(marker.startswith("Credential prompt text:") for marker in indicators):
        indicators.append(f"Potential brand impersonation cue: {brand_hits[0]}")

    for qr_finding in qr_findings:
        qr_value = str(qr_finding.get("value", "")).strip()
        if qr_value:
            indicators.append(f"QR payload: {qr_value}")

    return _unique_list(indicators)


def extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from OCR text or QR payloads."""
    return _unique_list(
        match.group(0).rstrip(".,);:")
        for match in _URL_PATTERN.finditer(str(text or ""))
    )


def _read_image_metadata(file_bytes: bytes) -> dict[str, Any]:
    """Read image format, dimensions, mode, and EXIF metadata when available."""
    try:
        from PIL import ExifTags, Image
    except ImportError:
        return {
            "image_format": sniff_image_format(file_bytes) or "unknown",
            "dimensions": {"width": 0, "height": 0},
            "color_mode": "unknown",
            "exif_metadata": {},
            "metadata_status": "unavailable",
        }

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            exif_metadata = {}
            raw_exif = image.getexif() if hasattr(image, "getexif") else None
            if raw_exif:
                for tag, value in raw_exif.items():
                    exif_metadata[str(ExifTags.TAGS.get(tag, tag))] = str(value)
            return {
                "image_format": str(image.format or sniff_image_format(file_bytes) or "unknown"),
                "dimensions": {
                    "width": int(getattr(image, "width", 0) or 0),
                    "height": int(getattr(image, "height", 0) or 0),
                },
                "color_mode": str(image.mode or "unknown"),
                "exif_metadata": exif_metadata,
                "metadata_status": "available",
            }
    except Exception:
        return {
            "image_format": sniff_image_format(file_bytes) or "unknown",
            "dimensions": {"width": 0, "height": 0},
            "color_mode": "unknown",
            "exif_metadata": {},
            "metadata_status": "failed",
        }


def _extract_text_from_image(file_bytes: bytes) -> tuple[str, str]:
    """Run OCR when optional dependencies are available."""
    try:
        from PIL import Image
    except ImportError:
        return "", "unavailable"

    try:
        import pytesseract
    except ImportError:
        return "", "unavailable"

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            return str(pytesseract.image_to_string(image) or "").strip(), "available"
    except Exception:
        return "", "failed"


def _extract_qr_findings(file_bytes: bytes) -> tuple[list[dict[str, str]], str]:
    """Decode QR codes when optional dependencies are available."""
    try:
        from PIL import Image
    except ImportError:
        return [], "unavailable"

    try:
        from pyzbar.pyzbar import decode
    except ImportError:
        return [], "unavailable"

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            findings = []
            for decoded in decode(image):
                value = decoded.data.decode("utf-8", errors="replace").strip()
                findings.append(
                    {
                        "type": str(decoded.type or "QR"),
                        "value": value,
                        "contains_url": "true" if extract_urls_from_text(value) else "false",
                    }
                )
            return findings, "available"
    except Exception:
        return [], "failed"


def _score_image_risk(
    *,
    file_name: str,
    metadata: dict[str, Any],
    extracted_text: str,
    qr_findings: list[dict[str, str]],
    suspicious_text_indicators: list[str],
) -> tuple[list[str], list[str], list[str], float]:
    """Build rule findings, explanations, and a deterministic risk score for images."""
    indicators: list[str] = list(suspicious_text_indicators)
    triggered_rules: list[str] = []
    explanations: list[str] = []
    rule_score = 0.0
    normalized_file_name = str(file_name or "").lower()

    if any(term in normalized_file_name for term in _LURE_FILENAME_TERMS):
        rule_score += 12.0
        triggered_rules.append("suspicious-filename-lure")
        explanations.append("The image filename uses lure terms commonly seen in phishing delivery workflows.")

    visible_urls = extract_urls_from_text(extracted_text)
    if visible_urls:
        rule_score += 18.0
        triggered_rules.append("ocr-visible-url")
        indicators.extend(f"OCR URL: {url}" for url in visible_urls)
        explanations.append("OCR text includes one or more visible URLs that may direct users to external content.")

    if qr_findings:
        rule_score += 20.0
        triggered_rules.append("embedded-qr-code")
        indicators.append("Embedded QR code detected")
        explanations.append("The image contains a QR code that could redirect users to a remote destination.")
        if any(extract_urls_from_text(str(item.get("value", ""))) for item in qr_findings):
            rule_score += 12.0
            triggered_rules.append("qr-code-url")
            explanations.append("A QR code payload contains a URL.")

    credential_prompt_hits = [
        indicator
        for indicator in suspicious_text_indicators
        if indicator.startswith("Credential prompt text:")
    ]
    if credential_prompt_hits:
        rule_score += 18.0
        triggered_rules.append("credential-harvesting-language")
        explanations.append("The extracted text contains credential-collection language.")

    urgency_hits = [
        indicator
        for indicator in suspicious_text_indicators
        if indicator.startswith("Urgent delivery language:")
    ]
    if urgency_hits:
        rule_score += 12.0
        triggered_rules.append("urgent-social-engineering-language")
        explanations.append("The image uses urgency cues commonly associated with phishing or payment pressure.")

    brand_hits = [
        indicator
        for indicator in suspicious_text_indicators
        if indicator.startswith("Potential brand impersonation cue:")
    ]
    if brand_hits:
        rule_score += 22.0
        triggered_rules.append("brand-impersonation-cue")
        explanations.append("The image combines brand references with suspicious credential language.")

    metadata_status = str(metadata.get("metadata_status", "unavailable"))
    if metadata_status != "available":
        rule_score += 4.0
        triggered_rules.append("limited-image-metadata")
        indicators.append("Limited image metadata available")
        explanations.append("Image metadata could not be fully inspected, reducing provenance visibility.")

    if not metadata.get("exif_metadata"):
        indicators.append("No EXIF metadata present")

    return (
        _unique_list(indicators),
        _unique_list(triggered_rules),
        _unique_list(explanations),
        min(rule_score, 100.0),
    )


def _severity_for_score(rule_score: float) -> str:
    """Map a deterministic risk score onto a severity label."""
    if rule_score >= 75.0:
        return "critical"
    if rule_score >= 55.0:
        return "high"
    if rule_score >= 25.0:
        return "medium"
    return "low"


def _final_label_for_score(rule_score: float) -> str:
    """Map a risk score onto the final image verdict label."""
    if rule_score >= 70.0:
        return "malicious"
    if rule_score >= 25.0:
        return "suspicious"
    return "benign"


def _confidence_for_score(rule_score: float) -> float:
    """Return a conservative confidence score derived from the rule score."""
    if rule_score >= 70.0:
        return 0.91
    if rule_score >= 25.0:
        return 0.76
    return 0.64


def _unique_list(values: Any) -> list[str]:
    """Return de-duplicated string values while preserving order."""
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        normalized = str(value).strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered
