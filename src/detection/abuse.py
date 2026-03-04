"""Abuse detection and user behavior tracking for identifying malicious usage patterns."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AbuseType(str, Enum):
    REPEATED_INJECTION = "repeated_injection"
    VOLUME_ABUSE = "volume_abuse"
    ESCALATION = "escalation"
    JAILBREAK_SEQUENCE = "jailbreak_sequence"


class RecommendedAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    THROTTLE = "throttle"
    BLOCK = "block"


@dataclass
class AbuseResult:
    is_abusive: bool
    abuse_type: AbuseType | None = None
    confidence: float = 0.0
    recommended_action: RecommendedAction = RecommendedAction.ALLOW
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrackedRequest:
    text: str
    timestamp: float
    was_injection: bool = False
    was_toxic: bool = False
    was_blocked: bool = False
    confidence: float = 0.0


class UserBehaviorTracker:
    """Tracks per-user request history for abuse pattern detection."""

    def __init__(self, max_history: int = 100, window_seconds: float = 3600.0) -> None:
        self.max_history = max_history
        self.window_seconds = window_seconds
        self._history: dict[str, list[TrackedRequest]] = defaultdict(list)

    def track(self, user_id: str, request: str, safety_result: dict[str, Any]) -> None:
        """Record an interaction for a user."""
        entry = TrackedRequest(
            text=request,
            timestamp=time.time(),
            was_injection=safety_result.get("is_injection", False),
            was_toxic=safety_result.get("is_toxic", False),
            was_blocked=safety_result.get("was_blocked", False),
            confidence=safety_result.get("confidence", 0.0),
        )
        history = self._history[user_id]
        history.append(entry)
        # Enforce max history
        if len(history) > self.max_history:
            self._history[user_id] = history[-self.max_history :]

    def get_history(self, user_id: str) -> list[TrackedRequest]:
        """Get request history within the sliding window."""
        now = time.time()
        cutoff = now - self.window_seconds
        history = self._history.get(user_id, [])
        return [r for r in history if r.timestamp >= cutoff]

    def get_risk_score(self, user_id: str) -> float:
        """Calculate a risk score (0-1) for a user based on recent behavior."""
        history = self.get_history(user_id)
        if not history:
            return 0.0

        total = len(history)
        injection_count = sum(1 for r in history if r.was_injection)
        toxic_count = sum(1 for r in history if r.was_toxic)
        blocked_count = sum(1 for r in history if r.was_blocked)

        # Weighted scoring
        score = (
            (injection_count / total) * 0.4
            + (toxic_count / total) * 0.3
            + (blocked_count / total) * 0.3
        )
        return min(score, 1.0)

    def clear(self, user_id: str) -> None:
        """Clear history for a user."""
        self._history.pop(user_id, None)

    def clear_all(self) -> None:
        """Clear all tracked history."""
        self._history.clear()


class AbuseDetector:
    """Detects abuse patterns across user request histories."""

    def __init__(
        self,
        tracker: UserBehaviorTracker | None = None,
        injection_threshold: int = 3,
        volume_threshold: int = 50,
        escalation_window: int = 5,
    ) -> None:
        self.tracker = tracker or UserBehaviorTracker()
        self.injection_threshold = injection_threshold
        self.volume_threshold = volume_threshold
        self.escalation_window = escalation_window

    def detect_patterns(self, user_id: str, requests: list[str] | None = None) -> AbuseResult:
        """Detect abuse patterns for a user based on their tracked history."""
        history = self.tracker.get_history(user_id)
        if not history:
            return AbuseResult(is_abusive=False)

        # Check each pattern type (most severe first)
        result = self._detect_jailbreak_sequence(history)
        if result.is_abusive:
            return result

        result = self._detect_escalation(history)
        if result.is_abusive:
            return result

        result = self._detect_repeated_injection(history)
        if result.is_abusive:
            return result

        result = self._detect_volume_abuse(history)
        if result.is_abusive:
            return result

        return AbuseResult(is_abusive=False)

    def _detect_repeated_injection(self, history: list[TrackedRequest]) -> AbuseResult:
        """Detect repeated injection attempts from the same user."""
        injection_attempts = [r for r in history if r.was_injection]
        count = len(injection_attempts)

        if count >= self.injection_threshold:
            confidence = min(count / (self.injection_threshold * 2), 1.0)
            action = RecommendedAction.BLOCK if count >= self.injection_threshold * 2 else RecommendedAction.THROTTLE
            return AbuseResult(
                is_abusive=True,
                abuse_type=AbuseType.REPEATED_INJECTION,
                confidence=confidence,
                recommended_action=action,
                details={"injection_count": count, "threshold": self.injection_threshold},
            )
        return AbuseResult(is_abusive=False)

    def _detect_volume_abuse(self, history: list[TrackedRequest]) -> AbuseResult:
        """Detect unusually high request volume."""
        count = len(history)
        if count >= self.volume_threshold:
            confidence = min(count / (self.volume_threshold * 2), 1.0)
            action = RecommendedAction.THROTTLE if count < self.volume_threshold * 2 else RecommendedAction.BLOCK
            return AbuseResult(
                is_abusive=True,
                abuse_type=AbuseType.VOLUME_ABUSE,
                confidence=confidence,
                recommended_action=action,
                details={"request_count": count, "threshold": self.volume_threshold},
            )
        return AbuseResult(is_abusive=False)

    def _detect_escalation(self, history: list[TrackedRequest]) -> AbuseResult:
        """Detect progressively more harmful inputs (escalation pattern)."""
        if len(history) < self.escalation_window:
            return AbuseResult(is_abusive=False)

        # Look at the most recent window of requests
        recent = history[-self.escalation_window :]
        confidences = [r.confidence for r in recent if r.was_injection or r.was_toxic]

        if len(confidences) < 3:
            return AbuseResult(is_abusive=False)

        # Check if confidence scores are increasing (escalation)
        increasing_pairs = sum(
            1 for i in range(1, len(confidences)) if confidences[i] > confidences[i - 1]
        )
        escalation_ratio = increasing_pairs / (len(confidences) - 1) if len(confidences) > 1 else 0

        if escalation_ratio >= 0.6 and len(confidences) >= 3:
            return AbuseResult(
                is_abusive=True,
                abuse_type=AbuseType.ESCALATION,
                confidence=escalation_ratio,
                recommended_action=RecommendedAction.WARN,
                details={
                    "escalation_ratio": escalation_ratio,
                    "confidence_trend": confidences,
                    "window_size": self.escalation_window,
                },
            )
        return AbuseResult(is_abusive=False)

    def _detect_jailbreak_sequence(self, history: list[TrackedRequest]) -> AbuseResult:
        """Detect multi-turn jailbreak manipulation attempts."""
        if len(history) < 3:
            return AbuseResult(is_abusive=False)

        recent = history[-10:]  # Look at last 10 requests

        # Jailbreak indicators: multiple injection attempts with varying techniques
        injection_requests = [r for r in recent if r.was_injection]
        if len(injection_requests) < 3:
            return AbuseResult(is_abusive=False)

        # Check for diversity in injection texts (different attempts = jailbreak sequence)
        unique_texts = set()
        for req in injection_requests:
            # Normalize: lowercase and take first 50 chars
            normalized = req.text.lower().strip()[:50]
            unique_texts.add(normalized)

        # If user is trying many different injection prompts, it's a jailbreak sequence
        diversity_ratio = len(unique_texts) / len(injection_requests) if injection_requests else 0

        if diversity_ratio >= 0.5 and len(injection_requests) >= 3:
            return AbuseResult(
                is_abusive=True,
                abuse_type=AbuseType.JAILBREAK_SEQUENCE,
                confidence=min(diversity_ratio, 1.0),
                recommended_action=RecommendedAction.BLOCK,
                details={
                    "unique_attempts": len(unique_texts),
                    "total_injections": len(injection_requests),
                    "diversity_ratio": diversity_ratio,
                },
            )
        return AbuseResult(is_abusive=False)
