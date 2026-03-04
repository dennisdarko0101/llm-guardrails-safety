"""Pydantic models for API request/response schemas."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class PolicyLevel(str, Enum):
    STRICT = "strict"
    MODERATE = "moderate"
    PERMISSIVE = "permissive"
    CUSTOM = "custom"


class RedactionAction(str, Enum):
    DETECT = "detect"
    REDACT = "redact"


class RedactionStrategyEnum(str, Enum):
    MASK = "mask"
    HASH = "hash"
    PLACEHOLDER = "placeholder"
    ANONYMIZE = "anonymize"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Text to scan for safety issues")
    context: str | None = Field(None, description="Optional context for grounding checks")
    policy: PolicyLevel = Field(PolicyLevel.MODERATE, description="Safety policy level")

    model_config = {"json_schema_extra": {"examples": [{"text": "Hello, how are you?", "policy": "moderate"}]}}


class ViolationDetail(BaseModel):
    rule: str = Field(..., description="Rule that was violated")
    matched_text: str | None = Field(None, description="Text that triggered the violation")
    severity: str = Field(..., description="Violation severity")
    action: str = Field(..., description="Recommended action")


class ScanResponse(BaseModel):
    is_safe: bool = Field(..., description="Whether the text passed all safety checks")
    violations: list[ViolationDetail] = Field(default_factory=list, description="List of violations found")
    action: str = Field("allow", description="Recommended action: allow, block, warn, or redact")
    processed_text: str | None = Field(None, description="Processed text (redacted if applicable)")
    scan_time_ms: float = Field(..., description="Scan duration in milliseconds")
    injection_score: float = Field(0.0, description="Prompt injection confidence score")
    toxicity_score: float = Field(0.0, description="Toxicity score")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional scan details")


# ---------------------------------------------------------------------------
# Input / Output Guard
# ---------------------------------------------------------------------------

class InputGuardRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=50000, description="User input to guard")
    system_prompt: str = Field("", description="System prompt for context")
    policy: PolicyLevel = Field(PolicyLevel.MODERATE, description="Safety policy level")


class OutputGuardRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Original prompt")
    output: str = Field(..., min_length=1, max_length=100000, description="LLM output to guard")
    context: str = Field("", description="Context for grounding checks")
    policy: PolicyLevel = Field(PolicyLevel.MODERATE, description="Safety policy level")


class GuardResponse(BaseModel):
    is_safe: bool
    action: str = "allow"
    violations: list[ViolationDetail] = Field(default_factory=list)
    processed_text: str | None = None
    scan_time_ms: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# PII
# ---------------------------------------------------------------------------

class PIIRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="Text to scan for PII")
    action: RedactionAction = Field(RedactionAction.DETECT, description="Detect only or detect and redact")
    redaction_strategy: RedactionStrategyEnum = Field(
        RedactionStrategyEnum.MASK, description="Redaction strategy"
    )
    entity_types: list[str] | None = Field(None, description="Specific PII entity types to detect")


class PIIEntityResponse(BaseModel):
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float


class PIIResponse(BaseModel):
    entities: list[PIIEntityResponse] = Field(default_factory=list)
    redacted_text: str | None = None
    entity_count: int = 0
    scan_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Batch
# ---------------------------------------------------------------------------

class BatchScanRequest(BaseModel):
    texts: list[str] = Field(..., min_length=1, max_length=100, description="Texts to scan")
    policy: PolicyLevel = Field(PolicyLevel.MODERATE)


class BatchScanResponse(BaseModel):
    results: list[ScanResponse]
    total_time_ms: float
    texts_scanned: int


# ---------------------------------------------------------------------------
# Hallucination
# ---------------------------------------------------------------------------

class HallucinationRequest(BaseModel):
    output: str = Field(..., min_length=1, description="LLM output to check")
    context: str = Field(..., min_length=1, description="Context to verify against")


class ClaimDetail(BaseModel):
    text: str
    is_supported: bool
    confidence: float
    supporting_context: str | None = None


class HallucinationResponse(BaseModel):
    has_hallucinations: bool
    hallucination_score: float
    claims: list[ClaimDetail]
    unsupported_claims: list[ClaimDetail]
    scan_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class PolicyInfo(BaseModel):
    name: str
    description: str
    action: str
    severity: str
    rule_count: int


class PoliciesResponse(BaseModel):
    policies: dict[str, list[PolicyInfo]]


# ---------------------------------------------------------------------------
# Health / Metrics
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "0.1.0"
    detectors: dict[str, bool] = Field(default_factory=dict)


class MetricsResponse(BaseModel):
    total_requests: int = 0
    total_blocked: int = 0
    total_warnings: int = 0
    average_scan_time_ms: float = 0.0
    uptime_seconds: float = 0.0
    detectors_loaded: list[str] = Field(default_factory=list)
