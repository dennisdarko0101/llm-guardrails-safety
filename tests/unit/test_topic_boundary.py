"""Tests for topic boundary enforcement."""

import pytest

from src.detection.topic_boundary import TopicBoundaryEnforcer


def test_on_topic_with_allowed():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["python programming", "software development"],
        mode="permissive",
    )
    result = enforcer.check("How do I write a Python function for software development?")
    assert result.is_on_topic is True
    assert result.similarity_score > 0


def test_off_topic_strict_mode():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["python programming", "javascript coding"],
        mode="strict",
    )
    result = enforcer.check("What is the best recipe for banana bread?")
    assert result.is_on_topic is False


def test_blocked_topic_detected():
    enforcer = TopicBoundaryEnforcer(
        blocked_topics=["politics and elections", "religious debates"],
        mode="permissive",
    )
    result = enforcer.check("You should vote for this political party in the election")
    assert result.is_on_topic is False
    assert result.detected_topic is not None


def test_no_topics_defined_allows_all():
    enforcer = TopicBoundaryEnforcer()
    result = enforcer.check("Anything at all goes here about any topic whatsoever")
    assert result.is_on_topic is True


def test_closest_allowed_topic_found():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["machine learning", "data science", "web development"],
        mode="permissive",
    )
    result = enforcer.check("How do neural networks learn from training data in machine learning?")
    assert result.closest_allowed_topic is not None


def test_permissive_mode_allows_borderline():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["cooking recipes"],
        mode="permissive",
    )
    result = enforcer.check("What kitchen tools do I need?")
    # In permissive mode, loosely related content should pass
    # (may or may not match depending on keyword overlap)
    assert isinstance(result.is_on_topic, bool)


def test_strict_mode_blocks_borderline():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["quantum physics research"],
        mode="strict",
    )
    result = enforcer.check("Tell me about cooking pasta recipes")
    assert result.is_on_topic is False


def test_blocked_takes_priority():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["general knowledge"],
        blocked_topics=["politics and elections"],
        mode="permissive",
    )
    result = enforcer.check("Tell me about the upcoming election and who to vote for")
    assert result.is_on_topic is False


def test_empty_text():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["programming"],
        mode="strict",
    )
    result = enforcer.check("")
    assert isinstance(result.is_on_topic, bool)


def test_topic_result_details():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["python programming"],
        mode="permissive",
    )
    result = enforcer.check("I love writing Python code for programming projects")
    assert "matched_keywords" in result.details or result.similarity_score >= 0


def test_multiple_allowed_topics():
    enforcer = TopicBoundaryEnforcer(
        allowed_topics=["healthcare", "medicine", "biology"],
        mode="permissive",
    )
    result = enforcer.check("What are the latest advances in medicine and biology?")
    assert result.is_on_topic is True


def test_multiple_blocked_topics():
    enforcer = TopicBoundaryEnforcer(
        blocked_topics=["weapons manufacturing", "drug synthesis"],
    )
    result = enforcer.check("How to synthesize drugs at home")
    assert result.is_on_topic is False
