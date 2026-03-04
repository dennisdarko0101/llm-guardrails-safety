# LLM Guardrails Safety — Handoff Document

## Architecture Overview

This project implements a layered safety system for LLM applications. Each layer operates independently and can be composed together via the Policy Engine.

### Core Components

#### 1. Policy Engine (`src/policies/`)
- **engine.py**: Core `PolicyEngine` class that evaluates text against `SafetyPolicy` objects containing `Rule` lists. Rules support regex, keyword, threshold, and custom evaluation types. The engine aggregates violations and returns the worst action/severity.
- **presets.py**: Three preset configurations (STRICT, MODERATE, PERMISSIVE) plus a custom template. `get_policies_for_level()` is the main entry point.

#### 2. Detection Layer (`src/detection/`)
- **injection.py**: `PromptInjectionDetector` with 4 detection layers:
  1. Pattern matching — 30+ regex patterns covering direct overrides, role manipulation, delimiter injection, indirect injection, prompt extraction, token manipulation, obfuscation
  2. Structural analysis — Detects role-switching markers and instruction delimiters
  3. Encoding detection — Delegates to `EncodingDetector` for base64/ROT13/unicode tricks
  4. LLM classification — Optional, requires an LLM client
- **encoding.py**: `EncodingDetector` handles base64 decoding, ROT13 decoding, homoglyph detection, invisible character detection, and text normalization.
- **topic_boundary.py**: `TopicBoundaryEnforcer` with allowed/blocked topic lists, keyword matching, and optional semantic similarity via sentence-transformers.
- **hallucination.py**: `HallucinationDetector` extracts claims from LLM output and verifies them against provided context using word overlap heuristics or LLM verification.

#### 3. Moderation Layer (`src/moderation/`)
- **toxicity.py**: `ToxicityClassifier` with rule-based (keyword/regex) and LLM-based modes. Classifies across 6 categories with configurable thresholds.
- **content_filter.py**: `ContentFilter` orchestrates toxicity classification + policy evaluation + profanity filtering. Returns `FilterResult` with action (block/redact/log).

#### 4. Validation Layer (`src/validation/`)
- **output_validator.py**: `OutputValidator` checks LLM outputs for relevance (keyword overlap with prompt), safety (toxicity), grounding (context overlap), and format compliance (JSON, length, patterns, required fields).
- **pii_detector.py**: `PIIDetector` with regex patterns for 8 entity types (email, phone, SSN, credit card, IP, DOB, address, name).
- **pii_redactor.py**: `PIIRedactor` with 4 strategies (mask, hash, placeholder, anonymize). Supports reversible redaction via `redaction_map`.

### Configuration (`src/config/settings.py`)
Pydantic Settings with `GUARDRAILS_` env prefix. Key settings: `SAFETY_LEVEL`, `MAX_INPUT_LENGTH`, `ENABLE_PII_REDACTION`, `TOXICITY_THRESHOLD`, `INJECTION_SENSITIVITY`, `ENABLE_LLM_DETECTION`.

## Key Design Decisions

1. **Rule-based first, LLM optional**: All detection works without API keys via regex/keywords. LLM-based modes improve accuracy but add latency and cost.
2. **Composable policies**: Users can mix presets with custom rules. The engine aggregates violations and escalates to the worst action.
3. **Multi-layer injection detection**: No single technique catches all injections. Layering pattern matching + structural analysis + encoding detection provides defense in depth.
4. **Reversible redaction**: PII redaction stores a mapping so authorized users can de-redact later.
5. **Configurable sensitivity**: Every component has tunable thresholds to balance false positives vs. false negatives.

## Testing

- 100+ unit tests across 7 test files in `tests/unit/`
- All LLM calls are mocked
- Run: `make test` or `pytest tests/ -v`

## Phase 3+ Roadmap (Not Yet Implemented)

- FastAPI endpoints (`src/api/`) — REST API wrapping all safety checks
- Prometheus metrics — Request counts, latency, violation rates
- Streaming support — Real-time safety checking for streamed LLM responses
- Webhook alerts — Notify external systems on critical violations
- Admin dashboard — UI for policy management and analytics
- Rate limiting — Per-user and per-IP request throttling
- Async batch processing — Bulk content moderation
- Multi-language support — Detection patterns for non-English text
- Fine-tuned classifier — Custom model trained on injection/toxicity datasets
