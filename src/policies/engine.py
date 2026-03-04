"""Safety policy engine for evaluating text against configurable rules."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class PolicyAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    REDACT = "redact"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleType(str, Enum):
    REGEX = "regex"
    KEYWORD = "keyword"
    THRESHOLD = "threshold"
    CUSTOM = "custom"


@dataclass
class Rule:
    rule_type: RuleType
    description: str
    pattern: str | None = None
    keywords: list[str] | None = None
    threshold: float | None = None
    config: dict[str, Any] | None = None

    def evaluate(self, text: str, context: dict[str, Any] | None = None) -> RuleResult:
        """Evaluate the rule against the given text."""
        if self.rule_type == RuleType.REGEX and self.pattern:
            match = re.search(self.pattern, text, re.IGNORECASE)
            if match:
                return RuleResult(
                    violated=True,
                    description=self.description,
                    matched_text=match.group(),
                    rule_type=self.rule_type,
                )
        elif self.rule_type == RuleType.KEYWORD and self.keywords:
            text_lower = text.lower()
            for keyword in self.keywords:
                if keyword.lower() in text_lower:
                    return RuleResult(
                        violated=True,
                        description=self.description,
                        matched_text=keyword,
                        rule_type=self.rule_type,
                    )
        elif self.rule_type == RuleType.THRESHOLD and self.threshold is not None:
            score = context.get("score", 0.0) if context else 0.0
            if score >= self.threshold:
                return RuleResult(
                    violated=True,
                    description=self.description,
                    matched_text=f"score={score}",
                    rule_type=self.rule_type,
                )
        elif self.rule_type == RuleType.CUSTOM and self.config:
            custom_fn = self.config.get("evaluate_fn")
            if custom_fn and callable(custom_fn):
                return custom_fn(text, context)

        return RuleResult(violated=False, description=self.description, rule_type=self.rule_type)


@dataclass
class RuleResult:
    violated: bool
    description: str
    rule_type: RuleType
    matched_text: str | None = None


@dataclass
class Violation:
    rule_description: str
    matched_text: str | None
    severity: Severity
    action: PolicyAction


@dataclass
class PolicyResult:
    passed: bool
    violations: list[Violation] = field(default_factory=list)
    action: PolicyAction = PolicyAction.LOG
    severity: Severity = Severity.LOW

    @property
    def has_violations(self) -> bool:
        return len(self.violations) > 0


@dataclass
class SafetyPolicy:
    name: str
    rules: list[Rule]
    action: PolicyAction = PolicyAction.BLOCK
    severity: Severity = Severity.HIGH
    description: str = ""
    enabled: bool = True


class PolicyEngine:
    """Evaluates text against a set of safety policies."""

    def __init__(self, policies: list[SafetyPolicy] | None = None) -> None:
        self.policies: list[SafetyPolicy] = policies or []

    def add_policy(self, policy: SafetyPolicy) -> None:
        self.policies.append(policy)

    def remove_policy(self, name: str) -> bool:
        initial_len = len(self.policies)
        self.policies = [p for p in self.policies if p.name != name]
        return len(self.policies) < initial_len

    def load_policies(self, config_path: str | Path) -> list[SafetyPolicy]:
        """Load policies from a JSON configuration file."""
        path = Path(config_path)
        with open(path) as f:
            config = json.load(f)

        loaded: list[SafetyPolicy] = []
        for policy_data in config.get("policies", []):
            rules = []
            for rule_data in policy_data.get("rules", []):
                rules.append(
                    Rule(
                        rule_type=RuleType(rule_data["rule_type"]),
                        description=rule_data.get("description", ""),
                        pattern=rule_data.get("pattern"),
                        keywords=rule_data.get("keywords"),
                        threshold=rule_data.get("threshold"),
                        config=rule_data.get("config"),
                    )
                )
            policy = SafetyPolicy(
                name=policy_data["name"],
                rules=rules,
                action=PolicyAction(policy_data.get("action", "block")),
                severity=Severity(policy_data.get("severity", "high")),
                description=policy_data.get("description", ""),
                enabled=policy_data.get("enabled", True),
            )
            loaded.append(policy)

        self.policies.extend(loaded)
        return loaded

    def evaluate(self, text: str, context: dict[str, Any] | None = None) -> PolicyResult:
        """Evaluate text against all enabled policies, returning aggregate result."""
        all_violations: list[Violation] = []
        worst_action = PolicyAction.LOG
        worst_severity = Severity.LOW

        action_rank = {
            PolicyAction.LOG: 0,
            PolicyAction.WARN: 1,
            PolicyAction.REDACT: 2,
            PolicyAction.BLOCK: 3,
        }
        severity_rank = {
            Severity.LOW: 0,
            Severity.MEDIUM: 1,
            Severity.HIGH: 2,
            Severity.CRITICAL: 3,
        }

        for policy in self.policies:
            if not policy.enabled:
                continue

            for rule in policy.rules:
                result = rule.evaluate(text, context)
                if result.violated:
                    violation = Violation(
                        rule_description=result.description,
                        matched_text=result.matched_text,
                        severity=policy.severity,
                        action=policy.action,
                    )
                    all_violations.append(violation)

                    if action_rank[policy.action] > action_rank[worst_action]:
                        worst_action = policy.action
                    if severity_rank[policy.severity] > severity_rank[worst_severity]:
                        worst_severity = policy.severity

        return PolicyResult(
            passed=len(all_violations) == 0,
            violations=all_violations,
            action=worst_action if all_violations else PolicyAction.LOG,
            severity=worst_severity if all_violations else Severity.LOW,
        )
