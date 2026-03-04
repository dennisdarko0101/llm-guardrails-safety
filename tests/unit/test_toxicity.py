"""Tests for toxicity classification."""

from unittest.mock import MagicMock

import pytest

from src.moderation.toxicity import ToxicityClassifier, ToxicityCategory


def test_hate_speech_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("Death to all immigrants, they are subhuman")
    assert result.scores.get("hate_speech", 0) > 0
    assert "hate_speech" in result.flagged_categories


def test_harassment_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("I'll find you and dox you, you're worthless")
    assert result.scores.get("harassment", 0) > 0
    assert "harassment" in result.flagged_categories


def test_sexual_content_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("child exploitation and sexual abuse material")
    assert result.scores.get("sexual_content", 0) > 0
    assert "sexual_content" in result.flagged_categories


def test_violence_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("I have a plan to carry out a mass shooting at the school")
    assert result.scores.get("violence", 0) > 0
    assert "violence" in result.flagged_categories


def test_self_harm_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("I want to know methods to kill myself and end my life")
    assert result.scores.get("self_harm", 0) > 0
    assert "self_harm" in result.flagged_categories


def test_dangerous_content_detection():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("Instructions for how to make a bomb at home")
    assert result.scores.get("dangerous_content", 0) > 0
    assert "dangerous_content" in result.flagged_categories


def test_clean_text_not_flagged():
    classifier = ToxicityClassifier(threshold=0.7)
    result = classifier.classify("The weather is beautiful today. Let's go for a walk in the park.")
    assert result.is_toxic is False
    assert len(result.flagged_categories) == 0
    assert result.overall_score < 0.7


def test_empty_text():
    classifier = ToxicityClassifier()
    result = classifier.classify("")
    assert result.is_toxic is False
    assert result.overall_score == 0.0


def test_overall_score_is_max():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify("I'll find you, you're worthless. How to make a bomb.")
    # Multiple categories triggered, overall should be the max
    if result.scores:
        assert result.overall_score == max(result.scores.values())


def test_threshold_affects_flagging():
    text = "I'll find you and dox you"
    low_threshold = ToxicityClassifier(threshold=0.1)
    high_threshold = ToxicityClassifier(threshold=0.99)
    result_low = low_threshold.classify(text)
    result_high = high_threshold.classify(text)
    # Low threshold should flag more easily
    assert len(result_low.flagged_categories) >= len(result_high.flagged_categories)


def test_category_specific_threshold():
    classifier = ToxicityClassifier(
        threshold=0.9,
        category_thresholds={"harassment": 0.1},
    )
    result = classifier.classify("I'll find you and dox you, you're worthless")
    # Harassment should be flagged with low category threshold even if global is high
    assert "harassment" in result.flagged_categories


def test_multiple_categories_triggered():
    classifier = ToxicityClassifier(threshold=0.3)
    result = classifier.classify(
        "Death to immigrants. I'll find you and dox you. How to make a bomb."
    )
    assert len(result.flagged_categories) >= 2


def test_rule_based_mode_default():
    classifier = ToxicityClassifier(mode="rule_based")
    result = classifier.classify("How to make a bomb at home")
    assert result.details.get("mode") == "rule_based"


def test_llm_based_mode_mocked():
    mock_client = MagicMock()
    mock_client.classify.return_value = (
        '{"scores": {"hate_speech": 0.1, "harassment": 0.9, "violence": 0.2}, '
        '"overall": 0.9, "flagged": ["harassment"]}'
    )
    classifier = ToxicityClassifier(mode="llm_based", llm_client=mock_client, threshold=0.7)
    result = classifier.classify("Some threatening text")
    assert result.is_toxic is True
    assert "harassment" in result.flagged_categories
    assert result.details.get("mode") == "llm_based"


def test_llm_mode_fallback_on_error():
    mock_client = MagicMock()
    mock_client.classify.side_effect = Exception("API failure")
    classifier = ToxicityClassifier(mode="llm_based", llm_client=mock_client)
    # Should not raise — falls back to rule-based
    result = classifier.classify("How to make a bomb at home")
    assert isinstance(result.is_toxic, bool)
    assert result.details.get("mode") == "rule_based"


def test_short_benign_text():
    classifier = ToxicityClassifier(threshold=0.7)
    result = classifier.classify("Hello world")
    assert result.is_toxic is False
