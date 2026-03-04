"""Tests for hallucination detection."""

from unittest.mock import MagicMock

import pytest

from src.detection.hallucination import HallucinationDetector, Claim


def test_supported_claims():
    detector = HallucinationDetector()
    context = "Python was created by Guido van Rossum in 1991. It is an interpreted language."
    output = "Python was created by Guido van Rossum. It is an interpreted programming language."
    result = detector.detect(output, context)
    assert result.hallucination_score < 0.5
    assert len(result.unsupported_claims) < len(result.claims)


def test_unsupported_claims():
    detector = HallucinationDetector()
    context = "The company sells software products and has 50 employees."
    output = "The company was founded in 1850 by Napoleon Bonaparte. It has offices on Mars and employs 1 million robots."
    result = detector.detect(output, context)
    assert result.hallucination_score > 0
    assert len(result.unsupported_claims) > 0


def test_mixed_claims():
    detector = HallucinationDetector()
    context = "Alice is a software engineer at TechCorp. She has 5 years of experience."
    output = "Alice is a software engineer at TechCorp. She graduated from Harvard and won a Nobel Prize."
    result = detector.detect(output, context)
    # Some claims supported, some not
    assert len(result.claims) >= 2
    assert 0 < result.hallucination_score <= 1.0


def test_empty_output():
    detector = HallucinationDetector()
    result = detector.detect("", "Some context here.")
    assert result.hallucination_score == 0.0
    assert len(result.claims) == 0


def test_empty_context():
    detector = HallucinationDetector()
    result = detector.detect("The sky is blue and water is wet.", "")
    # All claims unsupported against empty context
    assert result.hallucination_score > 0 or len(result.claims) == 0


def test_claim_extraction():
    detector = HallucinationDetector()
    text = "First sentence here. Second sentence here. Third sentence here."
    claims = detector._extract_claims(text)
    assert len(claims) >= 2  # Short sentences may be filtered


def test_questions_not_extracted_as_claims():
    detector = HallucinationDetector()
    text = "Is this a question? This is a statement. Another question?"
    claims = detector._extract_claims(text)
    # Questions should be filtered out
    for claim in claims:
        assert not claim.text.endswith("?")


def test_hallucination_result_details():
    detector = HallucinationDetector()
    context = "The product costs $100 and comes in red and blue colors."
    output = "The product costs $100 and is available in red and blue. It also comes with free shipping worldwide."
    result = detector.detect(output, context)
    assert "total_claims" in result.details
    assert "supported_claims" in result.details
    assert "unsupported_claims" in result.details


def test_has_hallucinations_property():
    detector = HallucinationDetector()
    context = "Only this fact exists."
    output = "The moon is made of cheese. Jupiter has rings of diamonds."
    result = detector.detect(output, context)
    if result.unsupported_claims:
        assert result.has_hallucinations is True


def test_supporting_context_found():
    detector = HallucinationDetector()
    context = "Python is a popular programming language created by Guido van Rossum. It emphasizes code readability."
    output = "Python is a popular programming language that emphasizes code readability."
    result = detector.detect(output, context)
    supported = [c for c in result.claims if c.is_supported]
    if supported:
        assert any(c.supporting_context is not None for c in supported)


def test_llm_detection_mocked():
    mock_client = MagicMock()
    mock_client.classify.return_value = '{"is_supported": true, "confidence": 0.9, "supporting_text": "matching context"}'
    detector = HallucinationDetector(llm_client=mock_client)
    context = "Some context."
    output = "A single claim sentence here."
    result = detector.detect_with_llm(output, context)
    assert isinstance(result.hallucination_score, float)


def test_llm_detection_error_fallback():
    mock_client = MagicMock()
    mock_client.classify.side_effect = Exception("API error")
    detector = HallucinationDetector(llm_client=mock_client)
    context = "Python was created by Guido."
    output = "Python was created by Guido van Rossum."
    result = detector.detect_with_llm(output, context)
    # Falls back to heuristic, should not raise
    assert isinstance(result.hallucination_score, float)


def test_fully_supported_output():
    detector = HallucinationDetector()
    context = "The Earth orbits the Sun. The Moon orbits the Earth. Water boils at 100 degrees Celsius."
    output = "The Earth orbits the Sun and the Moon orbits the Earth."
    result = detector.detect(output, context)
    assert result.hallucination_score < 0.5
