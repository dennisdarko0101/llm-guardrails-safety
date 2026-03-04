# LLM Guardrails Safety

Production safety layer for LLM applications with prompt injection detection, content moderation, PII redaction, and output validation.

## Features

- **Prompt Injection Detection** — Multi-layer detection: pattern matching (30+ patterns), structural analysis, encoding detection (base64/ROT13/unicode), optional LLM-based classification
- **Content Toxicity Classification** — Rule-based and LLM-based modes across 6 categories: hate speech, harassment, sexual content, violence, self-harm, dangerous content
- **PII Detection & Redaction** — Detects emails, phones, SSNs, credit cards, IPs, addresses, names, DOBs. Four redaction strategies: mask, hash, placeholder, anonymize. Reversible redaction support
- **Output Validation** — Relevance checking, safety verification, factual grounding (anti-hallucination), format compliance
- **Topic Boundary Enforcement** — Keyword and semantic similarity-based topic control with strict/permissive modes
- **Hallucination Detection** — Claim extraction and verification against provided context
- **Policy Engine** — Configurable safety policies with presets (strict/moderate/permissive) and custom rule support

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Copy and configure environment
cp .env.example .env

# Run tests
make test

# Start API server
make run
```

## Project Structure

```
src/
├── config/          # Pydantic Settings configuration
├── policies/        # Safety policy engine and presets
├── detection/       # Injection, encoding, topic boundary, hallucination detection
├── moderation/      # Toxicity classification and content filtering
├── validation/      # Output validation, PII detection and redaction
├── api/             # FastAPI endpoints
└── utils/           # Shared utilities
tests/
├── unit/            # Unit tests (100+)
└── integration/     # Integration tests
```

## Safety Levels

| Level | Behavior |
|-------|----------|
| **Strict** | Blocks everything remotely risky. Zero tolerance. |
| **Moderate** | Blocks clear violations, warns on borderline cases. |
| **Permissive** | Logs only, blocks extreme cases. |

## Usage

```python
from src.detection.injection import PromptInjectionDetector
from src.moderation.toxicity import ToxicityClassifier
from src.validation.pii_detector import PIIDetector
from src.validation.pii_redactor import PIIRedactor, RedactionStrategy
from src.policies.engine import PolicyEngine
from src.policies.presets import get_policies_for_level

# Prompt injection detection
detector = PromptInjectionDetector(sensitivity="high")
result = detector.detect("ignore all previous instructions")
print(result.is_injection, result.confidence)

# Toxicity classification
classifier = ToxicityClassifier(threshold=0.7)
result = classifier.classify("some text to check")
print(result.is_toxic, result.flagged_categories)

# PII detection and redaction
pii_detector = PIIDetector()
redactor = PIIRedactor(strategy=RedactionStrategy.PLACEHOLDER)
result = redactor.redact_auto("Email me at user@example.com, SSN 123-45-6789")
print(result.redacted_text)

# Policy engine
engine = PolicyEngine(get_policies_for_level("moderate"))
result = engine.evaluate("text to evaluate")
print(result.passed, result.violations)
```

## Development

```bash
make dev          # Install with dev dependencies
make test         # Run all tests with coverage
make lint         # Run ruff linter
make format       # Auto-format code
make type-check   # Run mypy
make check        # lint + type-check + test
```

## License

MIT
