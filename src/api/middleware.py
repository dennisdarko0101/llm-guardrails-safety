"""Safety middleware for FastAPI applications."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from src.detection.injection import PromptInjectionDetector
from src.moderation.toxicity import ToxicityClassifier
from src.policies.engine import PolicyEngine
from src.policies.presets import get_policies_for_level


class SafetyMiddleware(BaseHTTPMiddleware):
    """Middleware that intercepts requests/responses and applies safety scanning.

    Can be added to any FastAPI application to provide automatic safety guardrails.
    """

    def __init__(
        self,
        app: ASGIApp,
        protected_routes: list[str] | None = None,
        policy_level: str = "moderate",
        scan_responses: bool = False,
    ) -> None:
        super().__init__(app)
        self.protected_routes = protected_routes or ["/api/"]
        self.policy_level = policy_level
        self.scan_responses = scan_responses
        self._injection_detector = PromptInjectionDetector(sensitivity="medium")
        self._toxicity_classifier = ToxicityClassifier(threshold=0.7)
        self._policy_engine = PolicyEngine(policies=get_policies_for_level(policy_level))

    def _should_scan(self, path: str) -> bool:
        """Check if the request path should be scanned."""
        return any(path.startswith(route) for route in self.protected_routes)

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        if not self._should_scan(request.url.path):
            return await call_next(request)

        # Scan request body for POST/PUT/PATCH
        safety_score = 1.0
        safety_action = "allow"

        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
                text = body.decode("utf-8", errors="ignore")
                if text:
                    injection_result = self._injection_detector.detect(text)
                    toxicity_result = self._toxicity_classifier.classify(text)

                    if injection_result.is_injection:
                        safety_score = 1.0 - injection_result.confidence
                        safety_action = "block"

                    if toxicity_result.is_toxic:
                        safety_score = min(safety_score, 1.0 - toxicity_result.overall_score)
                        safety_action = "block"

                    if safety_action == "block":
                        return Response(
                            content='{"error": "Request blocked by safety middleware"}',
                            status_code=403,
                            media_type="application/json",
                            headers={
                                "X-Safety-Score": str(round(safety_score, 3)),
                                "X-Safety-Action": safety_action,
                            },
                        )
            except Exception:
                pass  # Don't block on middleware errors

        response = await call_next(request)

        # Add safety headers
        response.headers["X-Safety-Score"] = str(round(safety_score, 3))
        response.headers["X-Safety-Action"] = safety_action

        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Adds correlation IDs and request timing to all requests."""

    async def dispatch(self, request: Request, call_next: Callable[..., Any]) -> Response:
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))
        start = time.time()

        request.state.correlation_id = correlation_id

        response = await call_next(request)

        duration_ms = (time.time() - start) * 1000
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Response-Time-Ms"] = str(round(duration_ms, 2))

        return response


class AuditLogger:
    """Logs all safety decisions for compliance and auditing."""

    def __init__(self) -> None:
        self._log: list[dict[str, Any]] = []

    def log_decision(
        self,
        correlation_id: str,
        user_id: str | None,
        action: str,
        text_preview: str,
        violations: list[dict[str, Any]] | None = None,
        scan_time_ms: float = 0.0,
    ) -> None:
        """Record a safety decision."""
        entry = {
            "timestamp": time.time(),
            "correlation_id": correlation_id,
            "user_id": user_id,
            "action": action,
            "text_preview": text_preview[:100],
            "violation_count": len(violations) if violations else 0,
            "violations": violations or [],
            "scan_time_ms": scan_time_ms,
        }
        self._log.append(entry)
        # Keep only last 10000 entries in memory
        if len(self._log) > 10000:
            self._log = self._log[-10000:]

    def get_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Retrieve recent audit log entries."""
        return self._log[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get summary statistics from the audit log."""
        if not self._log:
            return {"total": 0, "blocks": 0, "warnings": 0, "allows": 0}

        return {
            "total": len(self._log),
            "blocks": sum(1 for e in self._log if e["action"] == "block"),
            "warnings": sum(1 for e in self._log if e["action"] == "warn"),
            "allows": sum(1 for e in self._log if e["action"] == "allow"),
        }

    def clear(self) -> None:
        """Clear the audit log."""
        self._log.clear()
