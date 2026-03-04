"""Tests for adaptive rate limiting."""

from __future__ import annotations

import time

import pytest

from src.detection.rate_limiter import (
    RateLimitResult,
    SafetyRateLimiter,
    UserTier,
    TIER_LIMITS,
)


class TestSafetyRateLimiter:
    def test_normal_user_allowed(self) -> None:
        limiter = SafetyRateLimiter()
        result = limiter.check("user1")
        assert result.allowed is True
        assert result.tier == UserTier.NORMAL
        assert result.remaining == TIER_LIMITS[UserTier.NORMAL] - 1

    def test_rate_limit_exhaustion(self) -> None:
        limiter = SafetyRateLimiter(tier_limits={
            UserTier.NORMAL: 3,
            UserTier.WARNING: 2,
            UserTier.RESTRICTED: 1,
        })
        # Use all tokens
        for _ in range(3):
            result = limiter.check("user1")
            assert result.allowed is True

        # 4th request should be denied
        result = limiter.check("user1")
        assert result.allowed is False
        assert result.remaining == 0
        assert result.retry_after is not None

    def test_token_refill_after_window(self) -> None:
        limiter = SafetyRateLimiter(
            tier_limits={UserTier.NORMAL: 2, UserTier.WARNING: 1, UserTier.RESTRICTED: 1},
            window_seconds=0.1,
        )
        limiter.check("user1")
        limiter.check("user1")
        result = limiter.check("user1")
        assert result.allowed is False

        # Wait for window to pass
        time.sleep(0.15)
        result = limiter.check("user1")
        assert result.allowed is True

    def test_warning_escalation(self) -> None:
        limiter = SafetyRateLimiter(warning_escalation_threshold=2)
        limiter.record_violation("user1", was_blocked=False)
        assert limiter.get_tier("user1") == UserTier.NORMAL
        limiter.record_violation("user1", was_blocked=False)
        assert limiter.get_tier("user1") == UserTier.WARNING

    def test_block_escalation(self) -> None:
        limiter = SafetyRateLimiter(block_escalation_threshold=1)
        limiter.record_violation("user1", was_blocked=True)
        assert limiter.get_tier("user1") == UserTier.RESTRICTED

    def test_restricted_has_lower_limit(self) -> None:
        limiter = SafetyRateLimiter(
            tier_limits={UserTier.NORMAL: 60, UserTier.WARNING: 20, UserTier.RESTRICTED: 2},
            block_escalation_threshold=1,
        )
        limiter.record_violation("user1", was_blocked=True)
        assert limiter.get_tier("user1") == UserTier.RESTRICTED

        # Should have restricted limit
        result = limiter.check("user1")
        assert result.allowed is True
        assert result.limit == 2

        result = limiter.check("user1")
        assert result.allowed is True

        result = limiter.check("user1")
        assert result.allowed is False

    def test_warning_tier_reduced_limit(self) -> None:
        limiter = SafetyRateLimiter(
            tier_limits={UserTier.NORMAL: 10, UserTier.WARNING: 3, UserTier.RESTRICTED: 1},
            warning_escalation_threshold=1,
        )
        limiter.record_violation("user1", was_blocked=False)
        assert limiter.get_tier("user1") == UserTier.WARNING

        result = limiter.check("user1")
        assert result.limit == 3

    def test_reset_user(self) -> None:
        limiter = SafetyRateLimiter(block_escalation_threshold=1)
        limiter.record_violation("user1", was_blocked=True)
        assert limiter.get_tier("user1") == UserTier.RESTRICTED
        limiter.reset_user("user1")
        assert limiter.get_tier("user1") == UserTier.NORMAL

    def test_reset_all(self) -> None:
        limiter = SafetyRateLimiter(block_escalation_threshold=1)
        limiter.record_violation("user1", was_blocked=True)
        limiter.record_violation("user2", was_blocked=True)
        limiter.reset_all()
        assert limiter.get_tier("user1") == UserTier.NORMAL
        assert limiter.get_tier("user2") == UserTier.NORMAL

    def test_unknown_user_normal_tier(self) -> None:
        limiter = SafetyRateLimiter()
        assert limiter.get_tier("unknown") == UserTier.NORMAL

    def test_multiple_warnings_then_block(self) -> None:
        limiter = SafetyRateLimiter(
            warning_escalation_threshold=2,
            block_escalation_threshold=1,
        )
        # Warnings escalate to WARNING tier
        limiter.record_violation("user1", was_blocked=False)
        limiter.record_violation("user1", was_blocked=False)
        assert limiter.get_tier("user1") == UserTier.WARNING

        # A block escalates to RESTRICTED
        limiter.record_violation("user1", was_blocked=True)
        assert limiter.get_tier("user1") == UserTier.RESTRICTED

    def test_tier_limits_applied_correctly(self) -> None:
        custom_limits = {
            UserTier.NORMAL: 100,
            UserTier.WARNING: 50,
            UserTier.RESTRICTED: 10,
        }
        limiter = SafetyRateLimiter(tier_limits=custom_limits)
        result = limiter.check("user1")
        assert result.limit == 100

    def test_record_violation_returns_new_tier(self) -> None:
        limiter = SafetyRateLimiter(block_escalation_threshold=1)
        tier = limiter.record_violation("user1", was_blocked=True)
        assert tier == UserTier.RESTRICTED
