"""Explainable rule-based risk scoring for suspicious PDF features."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, TypeAlias, TypedDict

from src.features.extractor import FeatureVector


class RuleResult(TypedDict):
    """Structured output returned by the rule engine."""

    risk_score_raw: int
    risk_score_normalized: int
    severity: str
    triggered_rules: list[str]
    explanations: list[str]


FeaturePredicate = Callable[[FeatureVector], bool]


@dataclass(frozen=True, slots=True)
class RuleDefinition:
    """Definition for a single transparent scoring rule."""

    name: str
    condition: FeaturePredicate
    score: int
    explanation: str
    severity: str


ThresholdConfig: TypeAlias = dict[str, int]


THRESHOLDS: ThresholdConfig = {
    "suspicious_keyword_total_high": 8,
    "high_risk_keyword_total_high": 4,
    "action_keyword_total_high": 3,
}


def _safe_int(features: FeatureVector, key: str, default: int = 0) -> int:
    """Return an integer feature value with a safe fallback."""
    try:
        return int(features.get(key, default))
    except (TypeError, ValueError):
        return default


def _safe_bool(features: FeatureVector, key: str) -> bool:
    """Return a boolean feature value with a safe fallback."""
    return bool(features.get(key, False))


RULE_DEFINITIONS: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        name="launch-action-present",
        condition=lambda features: _safe_bool(features, "has_launch"),
        score=35,
        explanation="The PDF contains a Launch action, which can be used to start external content.",
        severity="high",
    ),
    RuleDefinition(
        name="openaction-with-javascript",
        condition=lambda features: _safe_bool(features, "has_openaction")
        and (_safe_bool(features, "has_javascript") or _safe_bool(features, "has_js")),
        score=45,
        explanation="OpenAction combined with JavaScript can trigger active content as soon as the document opens.",
        severity="critical",
    ),
    RuleDefinition(
        name="embedded-file-present",
        condition=lambda features: _safe_bool(features, "has_embeddedfile"),
        score=22,
        explanation="The PDF contains an embedded file, which increases the chance of hidden payload delivery.",
        severity="high",
    ),
    RuleDefinition(
        name="high-suspicious-keyword-volume",
        condition=lambda features: _safe_int(features, "suspicious_keyword_total")
        >= THRESHOLDS["suspicious_keyword_total_high"],
        score=15,
        explanation="The PDF has an unusually high number of suspicious structural keywords.",
        severity="medium",
    ),
    RuleDefinition(
        name="high-high-risk-keyword-volume",
        condition=lambda features: _safe_int(features, "high_risk_keyword_total")
        >= THRESHOLDS["high_risk_keyword_total_high"],
        score=18,
        explanation="Multiple high-risk indicators are present at the same time.",
        severity="high",
    ),
    RuleDefinition(
        name="encrypted-with-active-indicators",
        condition=lambda features: _safe_bool(features, "is_encrypted")
        and (
            _safe_bool(features, "has_javascript")
            or _safe_bool(features, "has_js")
            or _safe_bool(features, "has_openaction")
            or _safe_bool(features, "has_aa")
            or _safe_bool(features, "has_launch")
        ),
        score=20,
        explanation="Encryption combined with active indicators can limit visibility while hiding risky behavior.",
        severity="high",
    ),
    RuleDefinition(
        name="multiple-action-indicators",
        condition=lambda features: _safe_int(features, "action_keyword_total")
        >= THRESHOLDS["action_keyword_total_high"],
        score=15,
        explanation="Several action-related indicators appear together, suggesting more complex document behavior.",
        severity="medium",
    ),

    # --- NEW: PDF Encryption Detection Rules ---

    RuleDefinition(
        name="encrypted-pdf-unreadable",
        condition=lambda features: _safe_bool(features, "is_encrypted")
        and not (
            _safe_bool(features, "has_javascript")
            or _safe_bool(features, "has_js")
            or _safe_bool(features, "has_openaction")
            or _safe_bool(features, "has_aa")
            or _safe_bool(features, "has_launch")
        ),
        score=18,
        explanation="The PDF is encrypted and its contents cannot be fully inspected. "
                    "Encrypted PDFs can conceal malicious payloads from scanners.",
        severity="medium",
    ),
    RuleDefinition(
        name="encrypted-with-embedded-file",
        condition=lambda features: _safe_bool(features, "is_encrypted")
        and _safe_bool(features, "has_embeddedfile"),
        score=30,
        explanation="The PDF is encrypted and contains an embedded file. "
                    "This combination is commonly used to hide malicious attachments.",
        severity="high",
    ),
    RuleDefinition(
        name="non-standard-encryption",
        condition=lambda features: _safe_bool(features, "has_non_standard_encryption"),
        score=25,
        explanation="The PDF uses a non-standard or unusual encryption method "
                    "which may be designed to bypass security scanners.",
        severity="high",
    ),
    RuleDefinition(
        name="encrypted-with-uri-action",
        condition=lambda features: _safe_bool(features, "is_encrypted")
        and _safe_bool(features, "has_uri"),
        score=22,
        explanation="The PDF is encrypted and contains URI actions. "
                    "This may be used to redirect users to malicious websites after decryption.",
        severity="high",
    ),
)


class RuleEngine:
    """Apply transparent heuristic rules to engineered PDF features."""

    def evaluate(self, features: FeatureVector) -> RuleResult:
        """Return an explainable risk score and the rules that produced it."""
        triggered_rules: list[str] = []
        explanations: list[str] = []
        raw_score = 0

        for rule in RULE_DEFINITIONS:
            if rule.condition(features):
                raw_score += rule.score
                triggered_rules.append(rule.name)
                explanations.append(
                    f"[{rule.severity}] {rule.name}: {rule.explanation}"
                )

        max_possible_score = sum(rule.score for rule in RULE_DEFINITIONS)
        normalized_score = round((raw_score / max_possible_score) * 100) if max_possible_score else 0

        return RuleResult(
            risk_score_raw=raw_score,
            risk_score_normalized=max(0, min(100, normalized_score)),
            severity=self._severity_from_score(normalized_score),
            triggered_rules=triggered_rules,
            explanations=explanations,
        )

    def _severity_from_score(self, normalized_score: int) -> str:
        """Map a normalized score onto a small set of severity labels."""
        if normalized_score >= 75:
            return "critical"
        if normalized_score >= 50:
            return "high"
        if normalized_score >= 25:
            return "medium"
        return "low"
