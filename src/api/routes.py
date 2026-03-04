"""API route handlers for the LLM safety guardrails service."""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request

from src.api.schemas import (
    BatchScanRequest,
    BatchScanResponse,
    ClaimDetail,
    GuardResponse,
    HallucinationRequest,
    HallucinationResponse,
    HealthResponse,
    InputGuardRequest,
    MetricsResponse,
    OutputGuardRequest,
    PIIEntityResponse,
    PIIRequest,
    PIIResponse,
    PoliciesResponse,
    PolicyInfo,
    ScanRequest,
    ScanResponse,
    ViolationDetail,
)
from src.detection.hallucination import HallucinationDetector
from src.detection.injection import PromptInjectionDetector
from src.moderation.toxicity import ToxicityClassifier
from src.policies.engine import PolicyEngine
from src.policies.presets import (
    MODERATE_POLICY,
    PERMISSIVE_POLICY,
    STRICT_POLICY,
    get_policies_for_level,
)
from src.validation.output_validator import OutputValidator
from src.validation.pii_detector import PIIDetector
from src.validation.pii_redactor import PIIRedactor, RedactionStrategy

router = APIRouter(prefix="/api/v1", tags=["safety"])
health_router = APIRouter(tags=["health"])

# ---------------------------------------------------------------------------
# Module-level detector instances (initialized at startup via init_detectors)
# ---------------------------------------------------------------------------
_injection_detector: PromptInjectionDetector | None = None
_toxicity_classifier: ToxicityClassifier | None = None
_pii_detector: PIIDetector | None = None
_pii_redactor: PIIRedactor | None = None
_hallucination_detector: HallucinationDetector | None = None
_output_validator: OutputValidator | None = None
_start_time: float = 0.0

# Simple in-memory metrics
_metrics: dict[str, Any] = {
    "total_requests": 0,
    "total_blocked": 0,
    "total_warnings": 0,
    "scan_times": [],
}


def init_detectors() -> None:
    """Initialize all detector instances. Called at app startup."""
    global _injection_detector, _toxicity_classifier, _pii_detector, _pii_redactor
    global _hallucination_detector, _output_validator, _start_time

    _injection_detector = PromptInjectionDetector(sensitivity="medium")
    _toxicity_classifier = ToxicityClassifier(threshold=0.7)
    _pii_detector = PIIDetector()
    _pii_redactor = PIIRedactor(strategy=RedactionStrategy.MASK, detector=_pii_detector)
    _hallucination_detector = HallucinationDetector()
    _output_validator = OutputValidator(toxicity_classifier=_toxicity_classifier)
    _start_time = time.time()


def _get_policy_engine(policy_level: str) -> PolicyEngine:
    """Create a PolicyEngine for the given level."""
    policies = get_policies_for_level(policy_level)
    return PolicyEngine(policies=policies)


def _record_metric(scan_time: float, action: str) -> None:
    _metrics["total_requests"] += 1
    if action == "block":
        _metrics["total_blocked"] += 1
    elif action == "warn":
        _metrics["total_warnings"] += 1
    times = _metrics["scan_times"]
    times.append(scan_time)
    # Keep only last 1000 times
    if len(times) > 1000:
        _metrics["scan_times"] = times[-1000:]


# ---------------------------------------------------------------------------
# POST /api/v1/scan — Full safety scan
# ---------------------------------------------------------------------------
@router.post("/scan", response_model=ScanResponse, summary="Full safety scan")
async def scan_text(req: ScanRequest) -> ScanResponse:
    """Run injection detection, toxicity classification, and policy evaluation."""
    start = time.time()
    assert _injection_detector is not None
    assert _toxicity_classifier is not None

    # 1. Injection detection
    injection_result = _injection_detector.detect(req.text)

    # 2. Toxicity classification
    toxicity_result = _toxicity_classifier.classify(req.text)

    # 3. Policy evaluation
    engine = _get_policy_engine(req.policy.value)
    policy_result = engine.evaluate(req.text)

    # Aggregate violations
    violations: list[ViolationDetail] = []
    action = "allow"

    if injection_result.is_injection:
        violations.append(ViolationDetail(
            rule="prompt_injection",
            matched_text=", ".join(injection_result.matched_patterns[:3]) or None,
            severity="high",
            action="block",
        ))
        action = "block"

    if toxicity_result.is_toxic:
        violations.append(ViolationDetail(
            rule="toxicity",
            matched_text=", ".join(toxicity_result.flagged_categories),
            severity="high",
            action="block",
        ))
        action = "block"

    for v in policy_result.violations:
        violations.append(ViolationDetail(
            rule=v.rule_description,
            matched_text=v.matched_text,
            severity=v.severity.value,
            action=v.action.value,
        ))
        if v.action.value == "block":
            action = "block"
        elif v.action.value == "warn" and action == "allow":
            action = "warn"
        elif v.action.value == "redact" and action in ("allow", "warn"):
            action = "redact"

    is_safe = action == "allow"
    scan_time = (time.time() - start) * 1000
    _record_metric(scan_time, action)

    return ScanResponse(
        is_safe=is_safe,
        violations=violations,
        action=action,
        processed_text=req.text if is_safe else None,
        scan_time_ms=round(scan_time, 2),
        injection_score=injection_result.confidence,
        toxicity_score=toxicity_result.overall_score,
        details={
            "policy": req.policy.value,
            "injection_method": injection_result.method.value if injection_result.method else None,
            "flagged_categories": toxicity_result.flagged_categories,
        },
    )


# ---------------------------------------------------------------------------
# POST /api/v1/guard/input
# ---------------------------------------------------------------------------
@router.post("/guard/input", response_model=GuardResponse, summary="Guard user input")
async def guard_input(req: InputGuardRequest) -> GuardResponse:
    """Guard user input before sending to an LLM."""
    start = time.time()
    assert _injection_detector is not None
    assert _toxicity_classifier is not None

    injection_result = _injection_detector.detect(req.user_input)
    toxicity_result = _toxicity_classifier.classify(req.user_input)
    engine = _get_policy_engine(req.policy.value)
    policy_result = engine.evaluate(req.user_input)

    violations: list[ViolationDetail] = []
    action = "allow"

    if injection_result.is_injection:
        violations.append(ViolationDetail(
            rule="prompt_injection",
            matched_text=", ".join(injection_result.matched_patterns[:3]) or None,
            severity="high",
            action="block",
        ))
        action = "block"

    if toxicity_result.is_toxic:
        violations.append(ViolationDetail(
            rule="toxicity",
            matched_text=", ".join(toxicity_result.flagged_categories),
            severity="high",
            action="block",
        ))
        action = "block"

    for v in policy_result.violations:
        violations.append(ViolationDetail(
            rule=v.rule_description,
            matched_text=v.matched_text,
            severity=v.severity.value,
            action=v.action.value,
        ))
        if v.action.value == "block":
            action = "block"
        elif v.action.value == "warn" and action == "allow":
            action = "warn"

    scan_time = (time.time() - start) * 1000
    _record_metric(scan_time, action)

    return GuardResponse(
        is_safe=action == "allow",
        action=action,
        violations=violations,
        processed_text=req.user_input if action == "allow" else None,
        scan_time_ms=round(scan_time, 2),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/guard/output
# ---------------------------------------------------------------------------
@router.post("/guard/output", response_model=GuardResponse, summary="Guard LLM output")
async def guard_output(req: OutputGuardRequest) -> GuardResponse:
    """Guard LLM output before returning to the user."""
    start = time.time()
    assert _output_validator is not None

    validation = _output_validator.validate(
        prompt=req.prompt,
        output=req.output,
        context=req.context or None,
    )

    violations: list[ViolationDetail] = []
    action = "allow"

    for issue in validation.issues:
        severity = issue.severity.value
        issue_action = "block" if severity in ("high", "critical") else "warn"
        violations.append(ViolationDetail(
            rule=issue.issue_type.value,
            matched_text=issue.description,
            severity=severity,
            action=issue_action,
        ))
        if issue_action == "block":
            action = "block"
        elif issue_action == "warn" and action == "allow":
            action = "warn"

    scan_time = (time.time() - start) * 1000
    _record_metric(scan_time, action)

    # is_safe mirrors the validator: only high/critical issues make it unsafe
    is_safe = action != "block"

    return GuardResponse(
        is_safe=is_safe,
        action=action,
        violations=violations,
        processed_text=req.output if is_safe else validation.corrected_output,
        scan_time_ms=round(scan_time, 2),
        details={"validation_issues": len(validation.issues)},
    )


# ---------------------------------------------------------------------------
# POST /api/v1/pii/detect & /api/v1/pii/redact
# ---------------------------------------------------------------------------
@router.post("/pii/detect", response_model=PIIResponse, summary="Detect PII entities")
async def detect_pii(req: PIIRequest) -> PIIResponse:
    """Detect PII entities in text."""
    start = time.time()
    assert _pii_detector is not None

    entity_types = req.entity_types if req.entity_types else None
    detector = PIIDetector(entity_types=entity_types) if entity_types else _pii_detector
    entities = detector.detect(req.text)

    scan_time = (time.time() - start) * 1000
    return PIIResponse(
        entities=[
            PIIEntityResponse(
                entity_type=e.entity_type,
                text=e.text,
                start=e.start,
                end=e.end,
                confidence=e.confidence,
            )
            for e in entities
        ],
        entity_count=len(entities),
        scan_time_ms=round(scan_time, 2),
    )


@router.post("/pii/redact", response_model=PIIResponse, summary="Detect and redact PII")
async def redact_pii(req: PIIRequest) -> PIIResponse:
    """Detect and redact PII from text."""
    start = time.time()
    assert _pii_detector is not None

    strategy_map = {
        "mask": RedactionStrategy.MASK,
        "hash": RedactionStrategy.HASH,
        "placeholder": RedactionStrategy.PLACEHOLDER,
        "anonymize": RedactionStrategy.ANONYMIZE,
    }
    strategy = strategy_map.get(req.redaction_strategy.value, RedactionStrategy.MASK)

    entity_types = req.entity_types if req.entity_types else None
    detector = PIIDetector(entity_types=entity_types) if entity_types else _pii_detector
    redactor = PIIRedactor(strategy=strategy, detector=detector)
    result = redactor.redact_auto(req.text)

    scan_time = (time.time() - start) * 1000
    return PIIResponse(
        entities=[
            PIIEntityResponse(
                entity_type=e.entity_type,
                text=e.text,
                start=e.start,
                end=e.end,
                confidence=e.confidence,
            )
            for e in result.entities_found
        ],
        redacted_text=result.redacted_text,
        entity_count=len(result.entities_found),
        scan_time_ms=round(scan_time, 2),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/scan/batch
# ---------------------------------------------------------------------------
@router.post("/scan/batch", response_model=BatchScanResponse, summary="Batch scan")
async def batch_scan(req: BatchScanRequest) -> BatchScanResponse:
    """Scan multiple texts in a single request."""
    start = time.time()
    results = []
    for text in req.texts:
        single_req = ScanRequest(text=text, policy=req.policy)
        result = await scan_text(single_req)
        results.append(result)

    total_time = (time.time() - start) * 1000
    return BatchScanResponse(
        results=results,
        total_time_ms=round(total_time, 2),
        texts_scanned=len(req.texts),
    )


# ---------------------------------------------------------------------------
# POST /api/v1/hallucination/check
# ---------------------------------------------------------------------------
@router.post(
    "/hallucination/check",
    response_model=HallucinationResponse,
    summary="Check for hallucinations",
)
async def check_hallucination(req: HallucinationRequest) -> HallucinationResponse:
    """Check LLM output for hallucinations against provided context."""
    start = time.time()
    assert _hallucination_detector is not None

    result = _hallucination_detector.detect(output=req.output, context=req.context)

    scan_time = (time.time() - start) * 1000
    return HallucinationResponse(
        has_hallucinations=result.has_hallucinations,
        hallucination_score=result.hallucination_score,
        claims=[
            ClaimDetail(
                text=c.text,
                is_supported=c.is_supported,
                confidence=c.confidence,
                supporting_context=c.supporting_context,
            )
            for c in result.claims
        ],
        unsupported_claims=[
            ClaimDetail(
                text=c.text,
                is_supported=c.is_supported,
                confidence=c.confidence,
                supporting_context=c.supporting_context,
            )
            for c in result.unsupported_claims
        ],
        scan_time_ms=round(scan_time, 2),
    )


# ---------------------------------------------------------------------------
# GET /api/v1/policies
# ---------------------------------------------------------------------------
@router.get("/policies", response_model=PoliciesResponse, summary="List policies")
async def list_policies() -> PoliciesResponse:
    """List all available safety policy presets."""
    result: dict[str, list[PolicyInfo]] = {}
    for level_name, policies in [
        ("strict", STRICT_POLICY),
        ("moderate", MODERATE_POLICY),
        ("permissive", PERMISSIVE_POLICY),
    ]:
        result[level_name] = [
            PolicyInfo(
                name=p.name,
                description=p.description,
                action=p.action.value,
                severity=p.severity.value,
                rule_count=len(p.rules),
            )
            for p in policies
        ]
    return PoliciesResponse(policies=result)


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------
@health_router.get("/health", response_model=HealthResponse, summary="Health check")
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        detectors={
            "injection": _injection_detector is not None,
            "toxicity": _toxicity_classifier is not None,
            "pii": _pii_detector is not None,
            "hallucination": _hallucination_detector is not None,
            "output_validator": _output_validator is not None,
        },
    )


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------
@health_router.get("/metrics", response_model=MetricsResponse, summary="Metrics")
async def get_metrics() -> MetricsResponse:
    scan_times = _metrics["scan_times"]
    avg_time = sum(scan_times) / len(scan_times) if scan_times else 0.0
    uptime = time.time() - _start_time if _start_time else 0.0

    detectors_loaded = []
    if _injection_detector:
        detectors_loaded.append("injection")
    if _toxicity_classifier:
        detectors_loaded.append("toxicity")
    if _pii_detector:
        detectors_loaded.append("pii")
    if _hallucination_detector:
        detectors_loaded.append("hallucination")
    if _output_validator:
        detectors_loaded.append("output_validator")

    return MetricsResponse(
        total_requests=_metrics["total_requests"],
        total_blocked=_metrics["total_blocked"],
        total_warnings=_metrics["total_warnings"],
        average_scan_time_ms=round(avg_time, 2),
        uptime_seconds=round(uptime, 2),
        detectors_loaded=detectors_loaded,
    )
