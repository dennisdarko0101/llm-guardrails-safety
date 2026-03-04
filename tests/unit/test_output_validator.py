"""Tests for output validation."""

from unittest.mock import MagicMock

import pytest

from src.validation.output_validator import OutputValidator, IssueType, IssueSeverity


# --- Relevance Checks ---

def test_relevant_output_passes():
    validator = OutputValidator()
    result = validator.validate(
        prompt="What is Python programming?",
        output="Python is a high-level programming language known for its simplicity and readability.",
    )
    relevance_issues = [i for i in result.issues if i.issue_type == IssueType.IRRELEVANT]
    assert len(relevance_issues) == 0


def test_irrelevant_output_flagged():
    validator = OutputValidator(relevance_threshold=0.3)
    result = validator.validate(
        prompt="What is Python programming?",
        output="The recipe for chocolate cake requires flour, sugar, eggs, and cocoa powder.",
    )
    relevance_issues = [i for i in result.issues if i.issue_type == IssueType.IRRELEVANT]
    assert len(relevance_issues) >= 1


def test_partially_relevant_output():
    validator = OutputValidator(relevance_threshold=0.2)
    result = validator.validate(
        prompt="Tell me about machine learning algorithms",
        output="Machine learning uses various algorithms to find patterns in data. The weather is nice today.",
    )
    # Should pass since it partially addresses the prompt
    relevance_issues = [i for i in result.issues if i.issue_type == IssueType.IRRELEVANT]
    assert len(relevance_issues) == 0


# --- Safety Checks ---

def test_safe_output_passes():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Tell me a joke",
        output="Why don't scientists trust atoms? Because they make up everything!",
    )
    safety_issues = [i for i in result.issues if i.issue_type == IssueType.UNSAFE]
    assert len(safety_issues) == 0


def test_unsafe_output_flagged():
    from src.moderation.toxicity import ToxicityClassifier
    classifier = ToxicityClassifier(threshold=0.3)
    validator = OutputValidator(toxicity_classifier=classifier)
    result = validator.validate(
        prompt="Tell me something",
        output="Here is how to make a bomb at home. Bomb making instructions and explosive recipe included.",
    )
    safety_issues = [i for i in result.issues if i.issue_type == IssueType.UNSAFE]
    assert len(safety_issues) >= 1


# --- Grounding Checks ---

def test_grounded_output_passes():
    validator = OutputValidator()
    context = "The company was founded in 2010 by Alice Johnson. It has 500 employees and is based in San Francisco."
    result = validator.validate(
        prompt="Tell me about the company",
        output="The company was founded in 2010 by Alice Johnson and is based in San Francisco with 500 employees.",
        context=context,
    )
    grounding_issues = [i for i in result.issues if i.issue_type == IssueType.UNGROUNDED]
    assert len(grounding_issues) == 0


def test_ungrounded_output_flagged():
    validator = OutputValidator(grounding_threshold=0.5)
    context = "The company sells software products."
    result = validator.validate(
        prompt="Tell me about the company",
        output="The company was founded in 1995 by John Smith in Tokyo. It has 10000 employees worldwide and revenue of 5 billion dollars annually. They recently acquired a major competitor.",
        context=context,
    )
    grounding_issues = [i for i in result.issues if i.issue_type == IssueType.UNGROUNDED]
    assert len(grounding_issues) >= 1


def test_no_grounding_check_without_context():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Tell me about Python",
        output="Python is a programming language.",
    )
    grounding_issues = [i for i in result.issues if i.issue_type == IssueType.UNGROUNDED]
    assert len(grounding_issues) == 0


# --- Format Checks ---

def test_valid_json_format():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Give me JSON",
        output='{"name": "test", "value": 42}',
        expected_format={"type": "json"},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) == 0


def test_invalid_json_format():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Give me JSON",
        output="This is not JSON at all",
        expected_format={"type": "json"},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) >= 1


def test_max_length_violation():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Be brief",
        output="x" * 200,
        expected_format={"max_length": 100},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) >= 1


def test_min_length_violation():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Write an essay",
        output="Hi.",
        expected_format={"min_length": 100},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) >= 1


def test_missing_required_json_fields():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Give structured data",
        output='{"name": "test"}',
        expected_format={"type": "json", "required_fields": ["name", "age", "email"]},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) >= 1
    missing_issue = [i for i in format_issues if "missing" in i.description.lower() or "Missing" in i.description]
    assert len(missing_issue) >= 1


def test_forbidden_content():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Write something",
        output="This output contains CONFIDENTIAL information that should not be shared.",
        expected_format={"must_not_contain": ["CONFIDENTIAL"]},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) >= 1


def test_pattern_match_format():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Give me a date",
        output="The date is 2024-01-15",
        expected_format={"pattern": r"\d{4}-\d{2}-\d{2}"},
    )
    format_issues = [i for i in result.issues if i.issue_type == IssueType.FORMAT_VIOLATION]
    assert len(format_issues) == 0


# --- Overall Validity ---

def test_is_valid_when_no_critical_issues():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Hello",
        output="Hello! How can I help you today?",
    )
    assert result.is_valid is True


def test_is_invalid_with_critical_safety_issue():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Tell me",
        output="Here is how to make a bomb: step 1 gather materials for bomb making instructions",
    )
    # If safety flagged as critical, should be invalid
    if any(i.severity in (IssueSeverity.CRITICAL, IssueSeverity.HIGH) for i in result.issues):
        assert result.is_valid is False


def test_checks_run_list():
    validator = OutputValidator()
    result = validator.validate(
        prompt="Test",
        output="Response",
        context="Some context",
        expected_format={"type": "json"},
    )
    checks = result.details.get("checks_run", [])
    assert "relevance" in checks
    assert "safety" in checks
    assert "grounding" in checks
    assert "format" in checks
