"""Content filtering with policy-aware moderation and redaction."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.moderation.toxicity import ToxicityClassifier, ToxicityResult
from src.policies.engine import PolicyAction, PolicyResult, SafetyPolicy


class FilterSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class FilterViolation:
    category: str
    matched_text: str
    severity: FilterSeverity
    action: str
    start: int = 0
    end: int = 0


@dataclass
class FilterResult:
    original_text: str
    filtered_text: str
    violations: list[FilterViolation] = field(default_factory=list)
    action_taken: str = "none"
    toxicity_result: ToxicityResult | None = None
    policy_result: PolicyResult | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return len(self.violations) == 0


# Default profanity list (minimal for demonstration — extend in production)
DEFAULT_PROFANITY_LIST = [
    "fuck", "shit", "bitch", "asshole", "bastard",
    "damn", "crap", "dick", "piss",
]


class ContentFilter:
    """Filters content based on toxicity classification and policy rules."""

    def __init__(
        self,
        toxicity_classifier: ToxicityClassifier | None = None,
        profanity_list: list[str] | None = None,
        replacement: str = "***",
    ) -> None:
        self.toxicity_classifier = toxicity_classifier or ToxicityClassifier()
        self.profanity_list = profanity_list or DEFAULT_PROFANITY_LIST
        self.replacement = replacement

    def filter(
        self,
        text: str,
        policy: SafetyPolicy | None = None,
    ) -> FilterResult:
        """Run content through toxicity check and policy evaluation."""
        violations: list[FilterViolation] = []
        filtered_text = text
        action_taken = "none"

        # Step 1: Toxicity classification
        toxicity_result = self.toxicity_classifier.classify(text)

        if toxicity_result.is_toxic:
            for category in toxicity_result.flagged_categories:
                score = toxicity_result.scores.get(category, 0.0)
                severity = (
                    FilterSeverity.CRITICAL if score >= 0.9
                    else FilterSeverity.WARNING if score >= 0.7
                    else FilterSeverity.INFO
                )
                violations.append(
                    FilterViolation(
                        category=category,
                        matched_text=f"[toxicity:{category}={score:.2f}]",
                        severity=severity,
                        action="flagged",
                    )
                )

        # Step 2: Policy evaluation (if provided)
        policy_result = None
        if policy:
            from src.policies.engine import PolicyEngine
            engine = PolicyEngine([policy])
            policy_result = engine.evaluate(text)

            if policy_result.has_violations:
                for v in policy_result.violations:
                    severity = (
                        FilterSeverity.CRITICAL if v.severity.value == "critical"
                        else FilterSeverity.WARNING if v.severity.value in ("high", "medium")
                        else FilterSeverity.INFO
                    )
                    violations.append(
                        FilterViolation(
                            category=f"policy:{v.rule_description}",
                            matched_text=v.matched_text or "",
                            severity=severity,
                            action=v.action.value,
                        )
                    )

        # Step 3: Profanity filter
        profanity_violations = self._filter_profanity(text)
        violations.extend(profanity_violations)

        # Step 4: Determine action and apply filtering
        if violations:
            worst_severity = max(
                violations,
                key=lambda v: {"critical": 3, "warning": 2, "info": 1}.get(v.severity.value, 0),
            ).severity

            if worst_severity == FilterSeverity.CRITICAL:
                action_taken = "block"
            elif worst_severity == FilterSeverity.WARNING:
                action_taken = "redact"
                filtered_text = self._apply_redactions(text, violations)
            else:
                action_taken = "log"

        return FilterResult(
            original_text=text,
            filtered_text=filtered_text,
            violations=violations,
            action_taken=action_taken,
            toxicity_result=toxicity_result,
            policy_result=policy_result,
        )

    def _filter_profanity(self, text: str) -> list[FilterViolation]:
        """Detect profanity in text."""
        violations: list[FilterViolation] = []
        text_lower = text.lower()

        for word in self.profanity_list:
            pattern = re.compile(r"\b" + re.escape(word) + r"\b", re.IGNORECASE)
            for match in pattern.finditer(text_lower):
                violations.append(
                    FilterViolation(
                        category="profanity",
                        matched_text=match.group(),
                        severity=FilterSeverity.WARNING,
                        action="redact",
                        start=match.start(),
                        end=match.end(),
                    )
                )

        return violations

    def _apply_redactions(self, text: str, violations: list[FilterViolation]) -> str:
        """Apply redactions for violations that have positions."""
        # Sort by position descending to maintain indices
        positioned = sorted(
            [v for v in violations if v.end > v.start],
            key=lambda v: v.start,
            reverse=True,
        )

        result = text
        for v in positioned:
            result = result[:v.start] + self.replacement + result[v.end:]

        return result

    def filter_profanity_only(self, text: str) -> str:
        """Quick profanity-only filter that redacts profane words."""
        result = text
        for word in self.profanity_list:
            pattern = re.compile(r"\b" + re.escape(word) + r"\b", re.IGNORECASE)
            result = pattern.sub(self.replacement, result)
        return result
