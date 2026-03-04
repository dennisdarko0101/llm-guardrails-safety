# Architecture

## System Overview

LLM Guardrails Safety is a layered defense system that sits between users and LLM APIs. Every component is independently usable and testable.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        FastAPI Service                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │ Safety       │  │ Request      │  │ Audit Logger             │  │
│  │ Middleware   │  │ Logging      │  │ (compliance tracking)    │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────────┘  │
│         │                 │                                         │
│  ┌──────▼─────────────────▼─────────────────────────────────────┐  │
│  │                    API Routes (/api/v1)                       │  │
│  │  /scan  /guard/input  /guard/output  /pii/*  /hallucination  │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                             │                                       │
│  ┌──────────────────────────▼───────────────────────────────────┐  │
│  │                    Detection Pipeline                         │  │
│  │                                                               │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────┐  │  │
│  │  │ Injection   │ │ Toxicity     │ │ Policy Engine         │  │  │
│  │  │ Detector    │ │ Classifier   │ │ (rules + presets)     │  │  │
│  │  │ (4 layers)  │ │ (6 cats)     │ │                       │  │  │
│  │  └─────────────┘ └──────────────┘ └───────────────────────┘  │  │
│  │                                                               │  │
│  │  ┌─────────────┐ ┌──────────────┐ ┌───────────────────────┐  │  │
│  │  │ PII         │ │ Hallucination│ │ Output Validator      │  │  │
│  │  │ Detector +  │ │ Detector     │ │ (relevance, safety,   │  │  │
│  │  │ Redactor    │ │              │ │  grounding, format)   │  │  │
│  │  └─────────────┘ └──────────────┘ └───────────────────────┘  │  │
│  │                                                               │  │
│  │  ┌─────────────┐ ┌──────────────┐                            │  │
│  │  │ Abuse       │ │ Rate         │                            │  │
│  │  │ Detector    │ │ Limiter      │                            │  │
│  │  └─────────────┘ └──────────────┘                            │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

## Detection Pipeline

### Prompt Injection Detection (4 Layers)

```
Input Text
  │
  ├─→ Layer 1: Pattern Matching (30+ regex patterns)
  │     → Direct overrides, role manipulation, delimiters, obfuscation
  │
  ├─→ Layer 2: Structural Analysis
  │     → Role markers, instruction delimiters, system prompt patterns
  │
  ├─→ Layer 3: Encoding Detection
  │     → Base64, ROT13, Unicode homoglyphs, invisible characters
  │
  └─→ Layer 4: LLM Classification (optional)
        → Claude/GPT classifies the input as injection or not
        │
        ▼
  Merged Result (highest confidence wins)
```

### Content Safety Flow

```
User Input                              LLM Output
    │                                       │
    ▼                                       ▼
┌─────────────┐                     ┌───────────────┐
│ Input Guard │                     │ Output Guard  │
│             │                     │               │
│ • Injection │                     │ • Relevance   │
│ • Toxicity  │                     │ • Safety      │
│ • Policy    │                     │ • Grounding   │
└──────┬──────┘                     │ • PII Redact  │
       │                            └───────┬───────┘
       ▼                                    ▼
  Allow / Block / Warn              Allow / Block / Warn
```

## Key Design Principles

1. **Rule-based first, LLM optional** — All detection works without API keys. LLM modes improve accuracy but add latency and cost.

2. **Defense in depth** — Multiple detection layers catch different attack vectors. No single technique is sufficient.

3. **Composable policies** — Mix presets with custom rules. The engine aggregates violations to the worst action.

4. **Reversible redaction** — PII redaction stores mappings so authorized users can de-redact.

5. **Adaptive rate limiting** — Users with violations get progressively stricter limits.

6. **Audit trail** — All safety decisions are logged with correlation IDs for compliance.

## Module Dependencies

```
api/main.py
  └─→ api/routes.py
  │     ├─→ detection/injection.py
  │     ├─→ moderation/toxicity.py
  │     ├─→ policies/engine.py + presets.py
  │     ├─→ validation/pii_detector.py + pii_redactor.py
  │     ├─→ validation/output_validator.py
  │     └─→ detection/hallucination.py
  └─→ api/middleware.py
        ├─→ detection/injection.py
        ├─→ moderation/toxicity.py
        └─→ policies/engine.py + presets.py

detection/abuse.py (standalone, no internal deps)
detection/rate_limiter.py (standalone, no internal deps)
```
