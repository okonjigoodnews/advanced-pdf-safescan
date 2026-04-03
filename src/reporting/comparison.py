"""Helpers for comparing two PDF analysis summaries in the demo UI."""

from __future__ import annotations

from typing import Any, TypedDict


LABEL_RANK = {
    "unknown": -1,
    "benign": 0,
    "suspicious": 1,
    "malicious": 2,
}


class ComparisonSummary(TypedDict):
    """Structured comparison result for two analyzed PDFs."""

    riskier_file: str
    higher_rule_score_file: str
    more_suspicious_indicators_file: str
    same_final_label: bool
    comparison_statement: str


def build_comparison_summary(
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
) -> ComparisonSummary:
    """Build a concise comparison summary for two PDF analysis results."""
    file_a = str(summary_a.get("file_name", "PDF A"))
    file_b = str(summary_b.get("file_name", "PDF B"))

    riskier_file = _choose_riskier_file(summary_a, summary_b, file_a, file_b)
    higher_rule_score_file = _choose_higher_rule_score_file(summary_a, summary_b, file_a, file_b)
    more_suspicious_indicators_file = _choose_more_indicators_file(summary_a, summary_b, file_a, file_b)
    same_final_label = str(summary_a.get("final_label", "unknown")) == str(
        summary_b.get("final_label", "unknown")
    )
    comparison_statement = _build_comparison_statement(
        summary_a=summary_a,
        summary_b=summary_b,
        riskier_file=riskier_file,
        higher_rule_score_file=higher_rule_score_file,
        more_suspicious_indicators_file=more_suspicious_indicators_file,
        same_final_label=same_final_label,
        file_a=file_a,
        file_b=file_b,
    )

    return ComparisonSummary(
        riskier_file=riskier_file,
        higher_rule_score_file=higher_rule_score_file,
        more_suspicious_indicators_file=more_suspicious_indicators_file,
        same_final_label=same_final_label,
        comparison_statement=comparison_statement,
    )


def _choose_riskier_file(
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
    file_a: str,
    file_b: str,
) -> str:
    """Choose the file that appears riskier overall."""
    label_a = LABEL_RANK.get(str(summary_a.get("final_label", "unknown")), -1)
    label_b = LABEL_RANK.get(str(summary_b.get("final_label", "unknown")), -1)
    if label_a > label_b:
        return file_a
    if label_b > label_a:
        return file_b

    rule_score_a = _safe_float(summary_a.get("rule_score", 0.0))
    rule_score_b = _safe_float(summary_b.get("rule_score", 0.0))
    if rule_score_a > rule_score_b:
        return file_a
    if rule_score_b > rule_score_a:
        return file_b

    confidence_a = _safe_float(summary_a.get("final_confidence", 0.0))
    confidence_b = _safe_float(summary_b.get("final_confidence", 0.0))
    if confidence_a > confidence_b:
        return file_a
    if confidence_b > confidence_a:
        return file_b
    return "tie"


def _choose_higher_rule_score_file(
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
    file_a: str,
    file_b: str,
) -> str:
    """Choose the file with the higher rule score."""
    rule_score_a = _safe_float(summary_a.get("rule_score", 0.0))
    rule_score_b = _safe_float(summary_b.get("rule_score", 0.0))
    if rule_score_a > rule_score_b:
        return file_a
    if rule_score_b > rule_score_a:
        return file_b
    return "tie"


def _choose_more_indicators_file(
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
    file_a: str,
    file_b: str,
) -> str:
    """Choose the file with more suspicious indicators."""
    indicators_a = len(list(summary_a.get("suspicious_indicators_found", [])))
    indicators_b = len(list(summary_b.get("suspicious_indicators_found", [])))
    if indicators_a > indicators_b:
        return file_a
    if indicators_b > indicators_a:
        return file_b
    return "tie"


def _build_comparison_statement(
    *,
    summary_a: dict[str, Any],
    summary_b: dict[str, Any],
    riskier_file: str,
    higher_rule_score_file: str,
    more_suspicious_indicators_file: str,
    same_final_label: bool,
    file_a: str,
    file_b: str,
) -> str:
    """Build a short human-readable comparison statement."""
    label_a = str(summary_a.get("final_label", "unknown"))
    label_b = str(summary_b.get("final_label", "unknown"))

    if riskier_file == "tie":
        return (
            f"{file_a} and {file_b} appear similarly risky overall based on their final labels, "
            "rule scores, and confidence values."
        )

    parts = [f"{riskier_file} appears riskier overall"]
    if not same_final_label:
        parts.append(f"because the final labels differ ({label_a} vs {label_b})")
    elif higher_rule_score_file != "tie":
        parts.append(f"and it also has the higher rule score ({higher_rule_score_file})")
    elif more_suspicious_indicators_file != "tie":
        parts.append(
            "and it shows more suspicious indicators "
            f"({more_suspicious_indicators_file})"
        )
    return " ".join(parts) + "."


def _safe_float(value: object, default: float = 0.0) -> float:
    """Convert a value to float safely."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return default
