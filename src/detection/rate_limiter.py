"""Adaptive rate limiting that adjusts based on user safety violation history."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class UserTier(str, Enum):
    NORMAL = "normal"
    WARNING = "warning"
    RESTRICTED = "restricted"


# Requests per minute by tier
TIER_LIMITS: dict[UserTier, int] = {
    UserTier.NORMAL: 60,
    UserTier.WARNING: 20,
    UserTier.RESTRICTED: 5,
}


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    limit: int
    reset_time: float
    tier: UserTier = UserTier.NORMAL
    retry_after: float | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class _UserBucket:
    """Internal token bucket for a user."""
    tokens: int
    last_refill: float
    tier: UserTier = UserTier.NORMAL
    warning_count: int = 0
    block_count: int = 0


class SafetyRateLimiter:
    """Adaptive rate limiter that becomes stricter for users with safety violations."""

    def __init__(
        self,
        tier_limits: dict[UserTier, int] | None = None,
        window_seconds: float = 60.0,
        warning_escalation_threshold: int = 3,
        block_escalation_threshold: int = 1,
    ) -> None:
        self.tier_limits = tier_limits or dict(TIER_LIMITS)
        self.window_seconds = window_seconds
        self.warning_escalation_threshold = warning_escalation_threshold
        self.block_escalation_threshold = block_escalation_threshold
        self._buckets: dict[str, _UserBucket] = {}

    def check(self, user_id: str) -> RateLimitResult:
        """Check if a request is allowed under the user's current rate limit."""
        bucket = self._get_or_create_bucket(user_id)
        self._refill(bucket)

        limit = self.tier_limits[bucket.tier]

        if bucket.tokens > 0:
            bucket.tokens -= 1
            return RateLimitResult(
                allowed=True,
                remaining=bucket.tokens,
                limit=limit,
                reset_time=bucket.last_refill + self.window_seconds,
                tier=bucket.tier,
            )

        retry_after = (bucket.last_refill + self.window_seconds) - time.time()
        return RateLimitResult(
            allowed=False,
            remaining=0,
            limit=limit,
            reset_time=bucket.last_refill + self.window_seconds,
            tier=bucket.tier,
            retry_after=max(retry_after, 0.0),
        )

    def record_violation(self, user_id: str, was_blocked: bool = False) -> UserTier:
        """Record a safety violation and potentially escalate the user's tier."""
        bucket = self._get_or_create_bucket(user_id)

        if was_blocked:
            bucket.block_count += 1
        else:
            bucket.warning_count += 1

        # Escalation logic
        new_tier = self._compute_tier(bucket)
        if new_tier != bucket.tier:
            bucket.tier = new_tier
            # Reset tokens to new tier limit
            bucket.tokens = self.tier_limits[new_tier]

        return bucket.tier

    def get_tier(self, user_id: str) -> UserTier:
        """Get the current tier for a user."""
        bucket = self._buckets.get(user_id)
        return bucket.tier if bucket else UserTier.NORMAL

    def reset_user(self, user_id: str) -> None:
        """Reset a user's rate limit state."""
        self._buckets.pop(user_id, None)

    def reset_all(self) -> None:
        """Reset all rate limit state."""
        self._buckets.clear()

    def _get_or_create_bucket(self, user_id: str) -> _UserBucket:
        if user_id not in self._buckets:
            self._buckets[user_id] = _UserBucket(
                tokens=self.tier_limits[UserTier.NORMAL],
                last_refill=time.time(),
                tier=UserTier.NORMAL,
            )
        return self._buckets[user_id]

    def _refill(self, bucket: _UserBucket) -> None:
        """Refill tokens if the window has elapsed."""
        now = time.time()
        elapsed = now - bucket.last_refill
        if elapsed >= self.window_seconds:
            bucket.tokens = self.tier_limits[bucket.tier]
            bucket.last_refill = now

    def _compute_tier(self, bucket: _UserBucket) -> UserTier:
        """Compute the appropriate tier based on violation counts."""
        if bucket.block_count >= self.block_escalation_threshold:
            return UserTier.RESTRICTED
        if bucket.warning_count >= self.warning_escalation_threshold:
            return UserTier.WARNING
        return UserTier.NORMAL
