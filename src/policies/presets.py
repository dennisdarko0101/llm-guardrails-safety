"""Preset safety policy configurations for common use cases."""

from __future__ import annotations

from src.policies.engine import (
    PolicyAction,
    Rule,
    RuleType,
    SafetyPolicy,
    Severity,
)

# --- Shared rule definitions ---

_INJECTION_RULES = [
    Rule(
        rule_type=RuleType.REGEX,
        description="Direct instruction override",
        pattern=r"ignore\s+(all\s+)?previous\s+instructions",
    ),
    Rule(
        rule_type=RuleType.REGEX,
        description="System prompt override attempt",
        pattern=r"(system\s*prompt|system\s*message)\s*[:=]",
    ),
    Rule(
        rule_type=RuleType.REGEX,
        description="Role manipulation attempt",
        pattern=r"you\s+are\s+now\s+(a|an|the|DAN|evil|unrestricted)",
    ),
    Rule(
        rule_type=RuleType.KEYWORD,
        description="Known jailbreak terms",
        keywords=["DAN mode", "jailbreak", "developer mode override"],
    ),
]

_HARMFUL_CONTENT_RULES = [
    Rule(
        rule_type=RuleType.KEYWORD,
        description="Weapons/explosives instructions",
        keywords=["how to make a bomb", "build a weapon", "synthesize poison"],
    ),
    Rule(
        rule_type=RuleType.KEYWORD,
        description="Self-harm content",
        keywords=["how to hurt yourself", "suicide methods"],
    ),
]

_PII_RULES = [
    Rule(
        rule_type=RuleType.REGEX,
        description="Social Security Number detected",
        pattern=r"\b\d{3}-\d{2}-\d{4}\b",
    ),
    Rule(
        rule_type=RuleType.REGEX,
        description="Credit card number detected",
        pattern=r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    ),
    Rule(
        rule_type=RuleType.REGEX,
        description="Email address detected",
        pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    ),
]

_TOPIC_RULES = [
    Rule(
        rule_type=RuleType.KEYWORD,
        description="Off-topic: political content",
        keywords=["vote for", "election fraud", "political party"],
    ),
    Rule(
        rule_type=RuleType.KEYWORD,
        description="Off-topic: religious debate",
        keywords=["my religion is better", "infidel", "heretic"],
    ),
]

# --- Strict Policy ---

STRICT_POLICY: list[SafetyPolicy] = [
    SafetyPolicy(
        name="strict_injection_prevention",
        description="Block all suspected prompt injection attempts",
        rules=_INJECTION_RULES
        + [
            Rule(
                rule_type=RuleType.REGEX,
                description="Instruction-like language",
                pattern=r"(do not|don't|never)\s+(mention|say|reveal|tell)",
            ),
            Rule(
                rule_type=RuleType.REGEX,
                description="Delimiter abuse",
                pattern=r"(```|---|\*\*\*)\s*(system|admin|root|prompt)",
            ),
            Rule(
                rule_type=RuleType.REGEX,
                description="Encoded content suspicious pattern",
                pattern=r"[A-Za-z0-9+/]{20,}={0,2}",
            ),
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.CRITICAL,
    ),
    SafetyPolicy(
        name="strict_harmful_content",
        description="Block all harmful content with zero tolerance",
        rules=_HARMFUL_CONTENT_RULES
        + [
            Rule(
                rule_type=RuleType.KEYWORD,
                description="Violence-related terms",
                keywords=["kill", "murder", "attack plan"],
            ),
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.CRITICAL,
    ),
    SafetyPolicy(
        name="strict_pii_protection",
        description="Block any PII in inputs or outputs",
        rules=_PII_RULES
        + [
            Rule(
                rule_type=RuleType.REGEX,
                description="Phone number detected",
                pattern=r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            ),
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.CRITICAL,
    ),
    SafetyPolicy(
        name="strict_topic_enforcement",
        description="Strict topic boundary enforcement",
        rules=_TOPIC_RULES,
        action=PolicyAction.BLOCK,
        severity=Severity.HIGH,
    ),
]

# --- Moderate Policy ---

MODERATE_POLICY: list[SafetyPolicy] = [
    SafetyPolicy(
        name="moderate_injection_prevention",
        description="Block clear injection attempts, warn on borderline cases",
        rules=_INJECTION_RULES,
        action=PolicyAction.BLOCK,
        severity=Severity.HIGH,
    ),
    SafetyPolicy(
        name="moderate_harmful_content",
        description="Block clearly harmful content",
        rules=_HARMFUL_CONTENT_RULES,
        action=PolicyAction.BLOCK,
        severity=Severity.HIGH,
    ),
    SafetyPolicy(
        name="moderate_pii_protection",
        description="Redact PII found in text",
        rules=_PII_RULES,
        action=PolicyAction.REDACT,
        severity=Severity.MEDIUM,
    ),
    SafetyPolicy(
        name="moderate_topic_enforcement",
        description="Warn on off-topic content",
        rules=_TOPIC_RULES,
        action=PolicyAction.WARN,
        severity=Severity.LOW,
    ),
]

# --- Permissive Policy ---

PERMISSIVE_POLICY: list[SafetyPolicy] = [
    SafetyPolicy(
        name="permissive_injection_prevention",
        description="Log injection attempts, block only obvious ones",
        rules=[
            Rule(
                rule_type=RuleType.REGEX,
                description="Direct instruction override",
                pattern=r"ignore\s+all\s+previous\s+instructions",
            ),
        ],
        action=PolicyAction.BLOCK,
        severity=Severity.HIGH,
    ),
    SafetyPolicy(
        name="permissive_harmful_content",
        description="Log potentially harmful content",
        rules=_HARMFUL_CONTENT_RULES,
        action=PolicyAction.LOG,
        severity=Severity.MEDIUM,
    ),
    SafetyPolicy(
        name="permissive_pii_protection",
        description="Log PII detection",
        rules=_PII_RULES,
        action=PolicyAction.LOG,
        severity=Severity.LOW,
    ),
]


def get_custom_policy_template() -> list[SafetyPolicy]:
    """Return a template for custom policy configuration."""
    return [
        SafetyPolicy(
            name="custom_policy",
            description="Custom safety policy — modify rules as needed",
            rules=[
                Rule(
                    rule_type=RuleType.KEYWORD,
                    description="Custom keyword rule",
                    keywords=["REPLACE_WITH_YOUR_KEYWORDS"],
                ),
                Rule(
                    rule_type=RuleType.REGEX,
                    description="Custom regex rule",
                    pattern=r"REPLACE_WITH_YOUR_PATTERN",
                ),
                Rule(
                    rule_type=RuleType.THRESHOLD,
                    description="Custom threshold rule",
                    threshold=0.8,
                ),
            ],
            action=PolicyAction.WARN,
            severity=Severity.MEDIUM,
            enabled=True,
        ),
    ]


def get_policies_for_level(level: str) -> list[SafetyPolicy]:
    """Return the preset policies for a given safety level."""
    mapping = {
        "strict": STRICT_POLICY,
        "moderate": MODERATE_POLICY,
        "permissive": PERMISSIVE_POLICY,
    }
    return mapping.get(level, MODERATE_POLICY)
