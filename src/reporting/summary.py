"""Reporting helpers for structured, JSON, and console-ready analysis output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class PipelineSummary:
    """Backward-compatible simple summary used by the starter entry point."""

    target: str
    status: str
    message: str


def build_analysis_summary(
    *,
    parser_output: dict[str, Any] | None = None,
    features: dict[str, Any] | None = None,
    rule_result: dict[str, Any] | None = None,
    ml_result: dict[str, Any] | Any | None = None,
    final_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build one clean dictionary summary from all backend pipeline outputs."""
    parser_output = parser_output or {}
    features = features or {}
    rule_result = rule_result or {}
    final_decision = final_decision or {}

    ml_label = _ml_value(ml_result, "predicted_label", fallback_key="label") or str(
        final_decision.get("ml_label", "unknown")
    )
    ml_confidence = _safe_float(
        _ml_value(ml_result, "confidence"),
        default=_safe_float(final_decision.get("ml_confidence", 0.0)),
    )

    return {
        "file_name": str(parser_output.get("file_name", "unknown")),
        "file_path": str(parser_output.get("file_path", "unknown")),
        "final_label": str(final_decision.get("final_label", "unknown")),
        "final_confidence": _safe_float(final_decision.get("final_confidence", 0.0)),
        "rule_score": _safe_float(
            final_decision.get(
                "rule_score",
                rule_result.get("risk_score_normalized", 0.0),
            )
        ),
        "rule_severity": str(
            final_decision.get("rule_severity", rule_result.get("severity", "unknown"))
        ),
        "ml_label": str(final_decision.get("ml_label", ml_label)),
        "ml_confidence": _safe_float(final_decision.get("ml_confidence", ml_confidence)),
        "suspicious_indicators_found": _collect_suspicious_indicators(
            parser_output=parser_output,
            features=features,
        ),
        "triggered_rules": list(
            final_decision.get("triggered_rules", rule_result.get("triggered_rules", []))
        ),
        "explanations": list(
            final_decision.get("explanations", rule_result.get("explanations", []))
        ),
    }


def summary_to_json(summary: dict[str, Any]) -> str:
    """Convert an analysis summary dictionary into formatted JSON."""
    return json.dumps(summary, indent=2)


def summary_to_console_text(summary: dict[str, Any]) -> str:
    """Convert an analysis summary dictionary into readable console text."""
    indicator_lines = _format_list_section(
        list(summary.get("suspicious_indicators_found", [])),
        empty_message="None detected.",
    )
    rule_lines = _format_list_section(
        list(summary.get("triggered_rules", [])),
        empty_message="No rules triggered.",
    )
    explanation_lines = _format_list_section(
        list(summary.get("explanations", [])),
        empty_message="No additional explanations.",
    )

    return (
        "Advanced PDFSafeScan Analysis Summary\n"
        f"File Name: {summary.get('file_name', 'unknown')}\n"
        f"File Path: {summary.get('file_path', 'unknown')}\n"
        f"Final Label: {summary.get('final_label', 'unknown')}\n"
        f"Final Confidence: {_format_confidence(summary.get('final_confidence', 0.0))}\n"
        f"Rule Score: {_format_confidence(summary.get('rule_score', 0.0), as_percent=False)}\n"
        f"Rule Severity: {summary.get('rule_severity', 'unknown')}\n"
        f"ML Label: {summary.get('ml_label', 'unknown')}\n"
        f"ML Confidence: {_format_confidence(summary.get('ml_confidence', 0.0))}\n"
        "\n"
        "Suspicious Indicators Found:\n"
        f"{indicator_lines}\n"
        "\n"
        "Triggered Rules:\n"
        f"{rule_lines}\n"
        "\n"
        "Explanations:\n"
        f"{explanation_lines}"
    )


def format_summary(summary: PipelineSummary) -> str:
    """Return the original simple summary text for the starter entry point."""
    return (
        f"Target: {summary.target}\n"
        f"Status: {summary.status}\n"
        f"Message: {summary.message}"
    )


def _collect_suspicious_indicators(
    *,
    parser_output: dict[str, Any],
    features: dict[str, Any],
) -> list[str]:
    """Collect suspicious indicators from parser counts or feature flags."""
    keyword_counts = parser_output.get("suspicious_keyword_counts", {})
    indicators: list[str] = []

    if isinstance(keyword_counts, dict):
        for keyword, count in keyword_counts.items():
            safe_count = _safe_float(count, default=0.0)
            if safe_count > 0:
                indicators.append(f"{keyword} ({int(safe_count)})")

    if indicators:
        return sorted(indicators)

    feature_to_indicator = {
        "has_javascript": "JavaScript present",
        "has_js": "JS action present",
        "has_openaction": "OpenAction present",
        "has_aa": "Additional action present",
        "has_launch": "Launch action present",
        "has_uri": "URI action present",
        "has_embeddedfile": "Embedded file present",
        "has_encrypt": "Encrypt keyword present",
        "has_objstm": "Object stream keyword present",
        "has_richmedia": "Rich media present",
        "has_acroform": "AcroForm present",
    }
    return [
        label
        for key, label in feature_to_indicator.items()
        if bool(features.get(key, False))
    ]


def _ml_value(ml_result: dict[str, Any] | Any | None, key: str, fallback_key: str | None = None) -> Any:
    """Extract a value from either an ML result dictionary or object."""
    if ml_result is None:
        return None
    if isinstance(ml_result, dict):
        if key in ml_result:
            return ml_result.get(key)
        if fallback_key is not None:
            return ml_result.get(fallback_key)
        return None
    if hasattr(ml_result, key):
        return getattr(ml_result, key)
    if fallback_key is not None and hasattr(ml_result, fallback_key):
        return getattr(ml_result, fallback_key)
    return None


def _safe_float(value: object, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _format_confidence(value: object, *, as_percent: bool = True) -> str:
    """Format confidence values consistently for console output."""
    number = _safe_float(value)
    if as_percent and 0.0 <= number <= 1.0:
        return f"{number:.2f}"
    return f"{number:.2f}"


def _format_list_section(items: list[Any], *, empty_message: str) -> str:
    """Render a list section as console-friendly bullet text."""
    if not items:
        return f"- {empty_message}"
    return "\n".join(f"- {item}" for item in items)
