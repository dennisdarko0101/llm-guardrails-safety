# LLM Guardrails Safety — Handoff Document

## Status: All Phases Complete

All 3 phases (8 steps) have been implemented and tested.

## Architecture Overview

This project implements a layered safety system for LLM applications. Each layer operates independently and can be composed together via the Policy Engine and FastAPI service.

### Core Components

#### 1. Policy Engine (`src/policies/`)
- **engine.py**: Core `PolicyEngine` class that evaluates text against `SafetyPolicy` objects containing `Rule` lists. Rules support regex, keyword, threshold, and custom evaluation types. The engine aggregates violations and returns the worst action/severity.
- **presets.py**: Three preset configurations (STRICT, MODERATE, PERMISSIVE) plus a custom template.

#### 2. Detection Layer (`src/detection/`)
- **injection.py**: `PromptInjectionDetector` with 4 detection layers: pattern matching (30+ patterns), structural analysis, encoding detection, optional LLM classification.
- **encoding.py**: `EncodingDetector` handles base64, ROT13, homoglyphs, invisible characters, and text normalization.
- **topic_boundary.py**: `TopicBoundaryEnforcer` with keyword and semantic similarity modes.
- **hallucination.py**: `HallucinationDetector` extracts claims and verifies against context.
- **abuse.py**: `AbuseDetector` + `UserBehaviorTracker` for detecting repeated injection, volume abuse, escalation patterns, and jailbreak sequences.
- **rate_limiter.py**: `SafetyRateLimiter` with adaptive tiers (normal: 60/min, warning: 20/min, restricted: 5/min).

#### 3. Moderation Layer (`src/moderation/`)
- **toxicity.py**: `ToxicityClassifier` with rule-based and LLM-based modes across 6 categories.
- **content_filter.py**: `ContentFilter` orchestrates toxicity + policy + profanity filtering.

#### 4. Validation Layer (`src/validation/`)
- **output_validator.py**: `OutputValidator` checks relevance, safety, grounding, and format.
- **pii_detector.py**: `PIIDetector` for 8 entity types.
- **pii_redactor.py**: `PIIRedactor` with 4 strategies, reversible redaction.

#### 5. API Layer (`src/api/`)
- **main.py**: FastAPI app with lifespan, CORS, request logging middleware.
- **routes.py**: 10 endpoints — scan, guard/input, guard/output, pii/detect, pii/redact, scan/batch, hallucination/check, policies, health, metrics.
- **middleware.py**: `SafetyMiddleware` (drop-in for any FastAPI app), `RequestLoggingMiddleware`, `AuditLogger`.
- **schemas.py**: Pydantic v2 models for all requests/responses.

### Configuration (`src/config/settings.py`)
Pydantic Settings with `GUARDRAILS_` env prefix. Key settings: `SAFETY_LEVEL`, `MAX_INPUT_LENGTH`, `ENABLE_PII_REDACTION`, `TOXICITY_THRESHOLD`, `INJECTION_SENSITIVITY`, `ENABLE_LLM_DETECTION`.

## Test Coverage

- **206 tests passing** (0 failures)
- **84% code coverage**
- Unit tests: injection, toxicity, PII, hallucination, output validation, policy engine, topic boundary, abuse detection, rate limiting
- Integration tests: all API endpoints, full guard pipeline, batch scanning

## Key Design Decisions

1. **Rule-based first, LLM optional**: All detection works without API keys.
2. **Composable policies**: Mix presets with custom rules.
3. **Multi-layer injection detection**: Defense in depth via 4 layers.
4. **Reversible PII redaction**: Mapping stored for authorized de-redaction.
5. **Adaptive rate limiting**: Users with violations get progressively stricter limits.
6. **Audit trail**: All safety decisions logged with correlation IDs.

## Deployment

- **Docker**: Multi-stage build, non-root, health checks
- **CI**: GitHub Actions with lint + test + coverage threshold (80%)
- **CD**: Docker image build and push on tags
- See `docs/DEPLOYMENT.md` for Cloud Run, ECS, and Kubernetes guides.
