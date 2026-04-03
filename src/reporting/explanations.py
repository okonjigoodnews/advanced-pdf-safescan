"""Explanation helpers for Advanced PDFSafeScan result panels."""

from __future__ import annotations

from typing import Any


def build_explanation_panel(summary: dict[str, Any], recommendation: str) -> dict[str, Any]:
    """Build a concise, presentation-ready explanation payload for one PDF."""
    suspicious_indicators = list(summary.get("suspicious_indicators_found", []))
    triggered_rules = list(summary.get("triggered_rules", []))
    explanations = list(summary.get("explanations", []))
    final_label = str(summary.get("final_label", "unknown"))
    final_confidence = _safe_float(summary.get("final_confidence", 0.0))

    return {
        "top_suspicious_indicators": suspicious_indicators[:5],
        "triggered_rules": triggered_rules,
        "plain_english_explanation": _plain_english_explanation(
            final_label=final_label,
            suspicious_indicators=suspicious_indicators,
            triggered_rules=triggered_rules,
            explanations=explanations,
        ),
        "confidence_interpretation": _confidence_interpretation(
            final_label=final_label,
            final_confidence=final_confidence,
        ),
        "recommended_action": recommendation or "No specific recommendation was generated.",
    }


def _plain_english_explanation(
    *,
    final_label: str,
    suspicious_indicators: list[str],
    triggered_rules: list[str],
    explanations: list[str],
) -> str:
    """Build a readable explanation grounded in the pipeline outputs."""
    if explanations:
        explanation_text = " ".join(str(item).strip() for item in explanations[:2] if str(item).strip())
        if explanation_text:
            return explanation_text

    indicator_count = len(suspicious_indicators)
    rule_count = len(triggered_rules)

    if final_label == "benign":
        if indicator_count == 0 and rule_count == 0:
            return (
                "The file did not present notable suspicious indicators or rule triggers in the current static "
                "analysis workflow, so it was classified as benign."
            )
        return (
            "Some signals were observed, but the overall evidence remained limited and did not justify a suspicious "
            "or malicious verdict in the current analysis workflow."
        )

    if final_label == "malicious":
        return (
            f"The file was marked malicious because the analysis identified {indicator_count} suspicious indicator(s) "
            f"and {rule_count} triggered rule(s), producing a stronger pattern of potentially harmful PDF behavior."
        )

    return (
        f"The file was marked suspicious because the analysis identified {indicator_count} suspicious indicator(s) "
        f"and {rule_count} triggered rule(s), which suggests elevated risk but not enough evidence for a stronger "
        "malicious verdict."
    )


def _confidence_interpretation(*, final_label: str, final_confidence: float) -> str:
    """Translate the final confidence score into a simple narrative for users."""
    if final_confidence >= 0.9:
        strength = "very strong"
    elif final_confidence >= 0.75:
        strength = "strong"
    elif final_confidence >= 0.6:
        strength = "moderate"
    else:
        strength = "limited"

    return (
        f"The final {final_label} verdict has {strength} support in the current model-and-rules assessment "
        f"(confidence {final_confidence:.2f})."
    )


def _safe_float(value: Any) -> float:
    """Convert a value into a float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
