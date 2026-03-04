"""Output validation for LLM responses — relevance, safety, grounding, and format checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.moderation.toxicity import ToxicityClassifier


class IssueType(str, Enum):
    IRRELEVANT = "irrelevant"
    UNSAFE = "unsafe"
    UNGROUNDED = "ungrounded"
    FORMAT_VIOLATION = "format_violation"


class IssueSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Issue:
    issue_type: IssueType
    description: str
    severity: IssueSeverity
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationResult:
    is_valid: bool
    issues: list[Issue] = field(default_factory=list)
    corrected_output: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def has_issues(self) -> bool:
        return len(self.issues) > 0


class OutputValidator:
    """Validates LLM outputs for relevance, safety, grounding, and format compliance."""

    def __init__(
        self,
        toxicity_classifier: ToxicityClassifier | None = None,
        llm_client: Any | None = None,
        relevance_threshold: float = 0.3,
        grounding_threshold: float = 0.4,
    ) -> None:
        self.toxicity_classifier = toxicity_classifier or ToxicityClassifier()
        self.llm_client = llm_client
        self.relevance_threshold = relevance_threshold
        self.grounding_threshold = grounding_threshold

    def validate(
        self,
        prompt: str,
        output: str,
        context: str | None = None,
        expected_format: dict[str, Any] | None = None,
    ) -> ValidationResult:
        """Run all validation checks on the output."""
        issues: list[Issue] = []

        # Check 1: Relevance
        relevance_issues = self._check_relevance(prompt, output)
        issues.extend(relevance_issues)

        # Check 2: Safety
        safety_issues = self._check_safety(output)
        issues.extend(safety_issues)

        # Check 3: Factual grounding (if context provided)
        if context:
            grounding_issues = self._check_grounding(output, context)
            issues.extend(grounding_issues)

        # Check 4: Format compliance (if expected format provided)
        if expected_format:
            format_issues = self._check_format(output, expected_format)
            issues.extend(format_issues)

        # Determine overall validity
        has_critical = any(i.severity == IssueSeverity.CRITICAL for i in issues)
        has_high = any(i.severity == IssueSeverity.HIGH for i in issues)
        is_valid = not has_critical and not has_high

        return ValidationResult(
            is_valid=is_valid,
            issues=issues,
            details={
                "checks_run": ["relevance", "safety"]
                + (["grounding"] if context else [])
                + (["format"] if expected_format else []),
            },
        )

    def _check_relevance(self, prompt: str, output: str) -> list[Issue]:
        """Check if output is relevant to the prompt."""
        issues: list[Issue] = []

        # Extract keywords from prompt
        prompt_words = set(re.findall(r"\b\w{3,}\b", prompt.lower()))
        output_words = set(re.findall(r"\b\w{3,}\b", output.lower()))

        stop_words = {
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
            "her", "was", "one", "our", "out", "has", "have", "been", "would",
            "could", "should", "will", "with", "this", "that", "from", "they",
            "were", "what", "when", "where", "which", "who", "how", "than",
            "into", "some", "them", "then", "these", "those", "your",
        }
        prompt_meaningful = prompt_words - stop_words
        output_meaningful = output_words - stop_words

        if not prompt_meaningful:
            return issues

        overlap = prompt_meaningful.intersection(output_meaningful)
        relevance_score = len(overlap) / len(prompt_meaningful) if prompt_meaningful else 0

        if relevance_score < self.relevance_threshold:
            issues.append(
                Issue(
                    issue_type=IssueType.IRRELEVANT,
                    description="Output may not be relevant to the prompt",
                    severity=IssueSeverity.MEDIUM,
                    details={
                        "relevance_score": relevance_score,
                        "threshold": self.relevance_threshold,
                        "prompt_keywords": list(prompt_meaningful)[:10],
                        "matching_keywords": list(overlap),
                    },
                )
            )

        return issues

    def _check_safety(self, output: str) -> list[Issue]:
        """Check if output contains harmful content."""
        issues: list[Issue] = []
        result = self.toxicity_classifier.classify(output)

        if result.is_toxic:
            for category in result.flagged_categories:
                score = result.scores.get(category, 0.0)
                severity = (
                    IssueSeverity.CRITICAL if score >= 0.9
                    else IssueSeverity.HIGH if score >= 0.7
                    else IssueSeverity.MEDIUM
                )
                issues.append(
                    Issue(
                        issue_type=IssueType.UNSAFE,
                        description=f"Output contains potentially harmful content: {category}",
                        severity=severity,
                        details={"category": category, "score": score},
                    )
                )

        return issues

    def _check_grounding(self, output: str, context: str) -> list[Issue]:
        """Check if output stays within provided context (anti-hallucination)."""
        issues: list[Issue] = []

        # Simple grounding check: keyword overlap with context
        output_sentences = re.split(r"(?<=[.!?])\s+", output.strip())
        context_lower = context.lower()

        ungrounded_sentences = 0
        total_sentences = 0

        for sentence in output_sentences:
            sentence = sentence.strip()
            if len(sentence) < 15:
                continue
            total_sentences += 1

            words = set(re.findall(r"\b\w{4,}\b", sentence.lower()))
            stop_words = {"the", "and", "for", "are", "but", "not", "you", "all", "this", "that", "with", "from", "have", "been", "would", "could", "should", "will", "they", "were", "what", "when", "than"}
            meaningful = words - stop_words

            if not meaningful:
                continue

            found = sum(1 for w in meaningful if w in context_lower)
            ratio = found / len(meaningful)

            if ratio < self.grounding_threshold:
                ungrounded_sentences += 1

        if total_sentences > 0:
            ungrounded_ratio = ungrounded_sentences / total_sentences
            if ungrounded_ratio > 0.5:
                issues.append(
                    Issue(
                        issue_type=IssueType.UNGROUNDED,
                        description="Output contains claims not grounded in the provided context",
                        severity=IssueSeverity.HIGH,
                        details={
                            "ungrounded_sentences": ungrounded_sentences,
                            "total_sentences": total_sentences,
                            "ungrounded_ratio": ungrounded_ratio,
                        },
                    )
                )

        return issues

    def _check_format(self, output: str, expected_format: dict[str, Any]) -> list[Issue]:
        """Check if output matches expected format."""
        issues: list[Issue] = []

        # Check max length
        max_length = expected_format.get("max_length")
        if max_length and len(output) > max_length:
            issues.append(
                Issue(
                    issue_type=IssueType.FORMAT_VIOLATION,
                    description=f"Output exceeds max length ({len(output)} > {max_length})",
                    severity=IssueSeverity.LOW,
                    details={"actual_length": len(output), "max_length": max_length},
                )
            )

        # Check min length
        min_length = expected_format.get("min_length")
        if min_length and len(output) < min_length:
            issues.append(
                Issue(
                    issue_type=IssueType.FORMAT_VIOLATION,
                    description=f"Output below min length ({len(output)} < {min_length})",
                    severity=IssueSeverity.LOW,
                    details={"actual_length": len(output), "min_length": min_length},
                )
            )

        # Check expected type (json, markdown, plain)
        expected_type = expected_format.get("type")
        if expected_type == "json":
            import json
            try:
                json.loads(output)
            except json.JSONDecodeError:
                issues.append(
                    Issue(
                        issue_type=IssueType.FORMAT_VIOLATION,
                        description="Output is not valid JSON",
                        severity=IssueSeverity.MEDIUM,
                    )
                )

        # Check required fields (for JSON output)
        required_fields = expected_format.get("required_fields")
        if required_fields and expected_type == "json":
            import json
            try:
                parsed = json.loads(output)
                if isinstance(parsed, dict):
                    missing = [f for f in required_fields if f not in parsed]
                    if missing:
                        issues.append(
                            Issue(
                                issue_type=IssueType.FORMAT_VIOLATION,
                                description=f"Missing required fields: {', '.join(missing)}",
                                severity=IssueSeverity.MEDIUM,
                                details={"missing_fields": missing},
                            )
                        )
            except json.JSONDecodeError:
                pass

        # Check regex pattern
        pattern = expected_format.get("pattern")
        if pattern:
            if not re.search(pattern, output):
                issues.append(
                    Issue(
                        issue_type=IssueType.FORMAT_VIOLATION,
                        description=f"Output does not match expected pattern: {pattern}",
                        severity=IssueSeverity.LOW,
                        details={"pattern": pattern},
                    )
                )

        # Check must_not_contain
        must_not_contain = expected_format.get("must_not_contain", [])
        for forbidden in must_not_contain:
            if forbidden.lower() in output.lower():
                issues.append(
                    Issue(
                        issue_type=IssueType.FORMAT_VIOLATION,
                        description=f"Output contains forbidden content: '{forbidden}'",
                        severity=IssueSeverity.MEDIUM,
                        details={"forbidden": forbidden},
                    )
                )

        return issues
