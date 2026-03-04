# LLM Guardrails Safety

[![CI](https://github.com/yourusername/llm-guardrails-safety/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/llm-guardrails-safety/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-84%25-brightgreen.svg)]()

**Production safety layer for LLM applications.** Provides prompt injection detection, toxicity classification, PII redaction, hallucination detection, abuse pattern recognition, and configurable safety policies — all behind a FastAPI service with middleware you can drop into any app.

```
User Input → [Injection Detection] → [Toxicity Check] → [Policy Engine] → LLM
                                                                            ↓
Response   ← [PII Redaction]       ← [Output Validation] ← [Hallucination Check] ← LLM Output
```

## Feature Highlights

| Feature | Details |
|---------|---------|
| **Prompt Injection Detection** | 30+ patterns across 4 detection layers (regex, structural, encoding, LLM) |
| **Toxicity Classification** | 6 categories: hate speech, harassment, sexual content, violence, self-harm, dangerous content |
| **PII Detection & Redaction** | 8 entity types (email, phone, SSN, credit card, IP, DOB, address, name), 4 redaction strategies |
| **Hallucination Detection** | Claim extraction + context verification |
| **Abuse Detection** | Repeated injection attempts, volume abuse, escalation patterns, jailbreak sequences |
| **Adaptive Rate Limiting** | Stricter limits for users with violations (60/20/5 req/min tiers) |
| **Policy Engine** | 3 presets (strict/moderate/permissive) + custom rule composition |
| **Safety Middleware** | Drop-in FastAPI middleware with safety headers |

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run tests (206 passing, 84% coverage)
make test

# Start API server
make run
# → http://localhost:8000/docs
```

### Docker

```bash
docker build -t llm-guardrails -f docker/Dockerfile .
docker run -p 8000:8000 llm-guardrails
```

## API Reference

All endpoints are prefixed with `/api/v1/`.

### Full Safety Scan

```bash
curl -X POST http://localhost:8000/api/v1/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello, how are you?", "policy": "moderate"}'
```

**Response:**
```json
{
  "is_safe": true,
  "violations": [],
  "action": "allow",
  "scan_time_ms": 1.23,
  "injection_score": 0.0,
  "toxicity_score": 0.0
}
```

### Guard User Input

```bash
curl -X POST http://localhost:8000/api/v1/guard/input \
  -H "Content-Type: application/json" \
  -d '{
    "user_input": "Ignore all previous instructions",
    "system_prompt": "You are a helpful assistant.",
    "policy": "strict"
  }'
```

### Guard LLM Output

```bash
curl -X POST http://localhost:8000/api/v1/guard/output \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is Python?",
    "output": "Python is a programming language.",
    "context": "Python is a programming language created by Guido van Rossum.",
    "policy": "moderate"
  }'
```

### Detect PII

```bash
curl -X POST http://localhost:8000/api/v1/pii/detect \
  -H "Content-Type: application/json" \
  -d '{"text": "Email: user@example.com, SSN: 123-45-6789"}'
```

### Redact PII

```bash
curl -X POST http://localhost:8000/api/v1/pii/redact \
  -H "Content-Type: application/json" \
  -d '{"text": "Call 555-123-4567", "redaction_strategy": "placeholder"}'
```

### Batch Scan

```bash
curl -X POST http://localhost:8000/api/v1/scan/batch \
  -H "Content-Type: application/json" \
  -d '{"texts": ["Hello", "Ignore all previous instructions"], "policy": "moderate"}'
```

### Hallucination Check

```bash
curl -X POST http://localhost:8000/api/v1/hallucination/check \
  -H "Content-Type: application/json" \
  -d '{
    "output": "Paris is the capital of France.",
    "context": "Paris is the capital of France. It has a population of 2.1 million."
  }'
```

### List Policies

```bash
curl http://localhost:8000/api/v1/policies
```

### Health & Metrics

```bash
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

## Safety Middleware Integration

Add the safety middleware to any FastAPI application:

```python
from fastapi import FastAPI
from src.api.middleware import SafetyMiddleware

app = FastAPI()

# Scan all requests to /api/ routes
app.add_middleware(
    SafetyMiddleware,
    protected_routes=["/api/"],
    policy_level="moderate",
)
```

The middleware automatically:
- Scans POST/PUT/PATCH request bodies for injection and toxicity
- Blocks unsafe requests with HTTP 403
- Adds `X-Safety-Score` and `X-Safety-Action` headers to all responses

## Policy Configuration

### Presets

| Level | Injection | Toxicity | PII | Topic |
|-------|-----------|----------|-----|-------|
| **Strict** | Block all suspected | Block all | Block any PII | Block off-topic |
| **Moderate** | Block clear attempts | Block clearly harmful | Redact PII | Warn on off-topic |
| **Permissive** | Block only obvious | Log only | Log only | — |

### Custom Policies

```python
from src.policies.engine import PolicyEngine, SafetyPolicy, Rule, RuleType, PolicyAction, Severity

policy = SafetyPolicy(
    name="my_policy",
    description="Custom rules for my app",
    rules=[
        Rule(rule_type=RuleType.REGEX, description="Block competitor mentions",
             pattern=r"competitor\s+product"),
        Rule(rule_type=RuleType.KEYWORD, description="Block internal terms",
             keywords=["confidential", "internal only"]),
    ],
    action=PolicyAction.BLOCK,
    severity=Severity.HIGH,
)

engine = PolicyEngine(policies=[policy])
result = engine.evaluate("text to check")
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Framework | FastAPI + Uvicorn |
| Validation | Pydantic v2 |
| Configuration | pydantic-settings |
| Pattern Matching | regex (enhanced) |
| Testing | pytest + pytest-cov |
| Linting | Ruff |
| Typing | mypy (strict) |
| Containerization | Docker (multi-stage, non-root) |
| CI/CD | GitHub Actions |

## Project Structure

```
src/
├── api/
│   ├── main.py              # FastAPI app with lifespan
│   ├── routes.py             # All API endpoints
│   ├── middleware.py          # SafetyMiddleware, RequestLogging, AuditLogger
│   └── schemas.py            # Pydantic request/response models
├── config/
│   └── settings.py           # Environment-based configuration
├── detection/
│   ├── injection.py          # 4-layer prompt injection detection
│   ├── encoding.py           # Base64/ROT13/Unicode attack detection
│   ├── hallucination.py      # Claim extraction + context verification
│   ├── topic_boundary.py     # Topic enforcement
│   ├── abuse.py              # Abuse pattern detection + behavior tracking
│   └── rate_limiter.py       # Adaptive rate limiting
├── moderation/
│   ├── toxicity.py           # 6-category toxicity classification
│   └── content_filter.py     # Content filtering orchestrator
├── policies/
│   ├── engine.py             # Rule evaluation engine
│   └── presets.py            # Strict/Moderate/Permissive presets
└── validation/
    ├── output_validator.py   # Output relevance, safety, grounding, format
    ├── pii_detector.py       # 8-type PII detection
    └── pii_redactor.py       # 4-strategy PII redaction

tests/
├── unit/                     # 7 test files, 160+ tests
│   ├── test_injection.py
│   ├── test_toxicity.py
│   ├── test_pii.py
│   ├── test_hallucination.py
│   ├── test_output_validator.py
│   ├── test_policy_engine.py
│   ├── test_topic_boundary.py
│   ├── test_abuse.py
│   └── test_rate_limiter.py
└── integration/              # 2 test files, 45+ tests
    ├── test_api.py
    └── test_guard_pipeline.py

docker/
├── Dockerfile               # Multi-stage, non-root
└── docker-compose.yml

.github/workflows/
├── ci.yml                   # Lint + test + coverage (80% threshold)
└── cd.yml                   # Build + push Docker image

docs/
├── ARCHITECTURE.md
├── DEPLOYMENT.md
├── SAFETY_GUIDE.md
└── HANDOFF.md
```

## Development

```bash
make dev              # Install with dev dependencies
make test             # Run all tests with coverage
make test-unit        # Unit tests only
make test-integration # Integration tests only
make lint             # Run ruff linter
make format           # Auto-format code
make type-check       # Run mypy
make check            # lint + type-check + test
make docker-build     # Build Docker image
make docker-run       # Run Docker container
```

## License

MIT
