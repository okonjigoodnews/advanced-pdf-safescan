"""Hybrid decision logic combining rules and machine learning outputs."""

from __future__ import annotations

from typing import Any, TypedDict

from src.ml.classifier import MLResult
from src.rules.engine import RuleResult


FUSION_THRESHOLDS: dict[str, float] = {
    "malicious_ml_confidence_high": 0.80,
    "malicious_ml_confidence_medium": 0.60,
    "suspicious_ml_confidence_medium": 0.55,
    "benign_ml_confidence_high": 0.75,
    "low_rule_score_max": 20.0,
    "medium_rule_score_min": 25.0,
}


class FinalDecision(TypedDict):
    """Structured final decision output for the hybrid pipeline."""

    final_label: str
    final_confidence: float
    rule_score: float
    rule_severity: str
    ml_label: str
    ml_confidence: float
    triggered_rules: list[str]
    explanations: list[str]


class HybridDecisionLayer:
    """Combine explainable rules and ML output into one final decision."""

    def combine(self, rule_result: RuleResult, ml_result: MLResult) -> FinalDecision:
        """Produce a deterministic final label from rule and ML evidence."""
        rule_score = float(rule_result.get("risk_score_normalized", 0))
        rule_severity = str(rule_result.get("severity", "low"))
        triggered_rules = list(rule_result.get("triggered_rules", []))
        explanations = list(rule_result.get("explanations", []))

        ml_label = self._ml_label(ml_result)
        ml_confidence = self._ml_confidence(ml_result)

        final_label = self._final_label(
            rule_score=rule_score,
            rule_severity=rule_severity,
            ml_label=ml_label,
            ml_confidence=ml_confidence,
        )
        final_confidence = self._final_confidence(
            final_label=final_label,
            rule_score=rule_score,
            ml_confidence=ml_confidence,
        )

        return FinalDecision(
            final_label=final_label,
            final_confidence=final_confidence,
            rule_score=rule_score,
            rule_severity=rule_severity,
            ml_label=ml_label,
            ml_confidence=ml_confidence,
            triggered_rules=triggered_rules,
            explanations=explanations,
        )

    def _final_label(
        self,
        *,
        rule_score: float,
        rule_severity: str,
        ml_label: str,
        ml_confidence: float,
    ) -> str:
        """Apply a simple conservative fusion policy."""
        if (
            ml_label == "malicious"
            and ml_confidence >= FUSION_THRESHOLDS["malicious_ml_confidence_high"]
            and rule_severity in {"high", "critical"}
        ):
            return "malicious"

        if (
            ml_label == "benign"
            and ml_confidence >= FUSION_THRESHOLDS["benign_ml_confidence_high"]
            and rule_score <= FUSION_THRESHOLDS["low_rule_score_max"]
            and rule_severity == "low"
        ):
            return "benign"

        if (
            ml_label == "suspicious"
            and ml_confidence >= FUSION_THRESHOLDS["suspicious_ml_confidence_medium"]
            and rule_severity in {"medium", "high", "critical"}
        ):
            return "suspicious"

        if (
            ml_label == "malicious"
            and ml_confidence >= FUSION_THRESHOLDS["malicious_ml_confidence_medium"]
            and rule_severity == "medium"
        ):
            return "suspicious"

        if ml_label == "benign" and rule_severity in {"medium", "high", "critical"}:
            return "suspicious"

        if rule_severity in {"high", "critical"}:
            return "suspicious"

        if (
            ml_label == "malicious"
            and ml_confidence >= FUSION_THRESHOLDS["malicious_ml_confidence_medium"]
        ):
            return "suspicious"

        if ml_label == "suspicious" or rule_score >= FUSION_THRESHOLDS["medium_rule_score_min"]:
            return "suspicious"

        return "benign"

    def _final_confidence(
        self,
        *,
        final_label: str,
        rule_score: float,
        ml_confidence: float,
    ) -> float:
        """Return a stable confidence score for the final decision."""
        rule_confidence = max(0.0, min(1.0, rule_score / 100.0))
        if final_label == "malicious":
            return round(max(ml_confidence, rule_confidence), 3)
        if final_label == "suspicious":
            return round(max(0.55, (ml_confidence + rule_confidence) / 2.0), 3)
        return round(max(ml_confidence, 1.0 - rule_confidence), 3)

    def _ml_label(self, ml_result: MLResult | dict[str, Any]) -> str:
        """Extract the ML label from either a dataclass or dictionary payload."""
        if isinstance(ml_result, dict):
            return str(
                ml_result.get("predicted_label")
                or ml_result.get("label")
                or "suspicious"
            )
        return ml_result.predicted_label

    def _ml_confidence(self, ml_result: MLResult | dict[str, Any]) -> float:
        """Extract the ML confidence from either a dataclass or dictionary payload."""
        if isinstance(ml_result, dict):
            try:
                return float(ml_result.get("confidence", 0.0))
            except (TypeError, ValueError):
                return 0.0
        return float(ml_result.confidence)
