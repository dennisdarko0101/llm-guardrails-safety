"""Tests for PII detection and redaction."""

import pytest

from src.validation.pii_detector import PIIDetector, PIIEntityType
from src.validation.pii_redactor import PIIRedactor, RedactionStrategy, RedactionResult


# --- Email Detection ---

def test_detect_email():
    detector = PIIDetector()
    entities = detector.detect("Contact me at john.doe@example.com for details")
    emails = [e for e in entities if e.entity_type == "EMAIL"]
    assert len(emails) >= 1
    assert "john.doe@example.com" in emails[0].text


def test_detect_multiple_emails():
    detector = PIIDetector()
    entities = detector.detect("Email alice@test.com or bob@company.org")
    emails = [e for e in entities if e.entity_type == "EMAIL"]
    assert len(emails) >= 2


# --- Phone Detection ---

def test_detect_us_phone():
    detector = PIIDetector()
    entities = detector.detect("Call me at (555) 123-4567")
    phones = [e for e in entities if e.entity_type == "PHONE"]
    assert len(phones) >= 1


def test_detect_phone_with_country_code():
    detector = PIIDetector()
    entities = detector.detect("International: +1-555-123-4567")
    phones = [e for e in entities if e.entity_type == "PHONE"]
    assert len(phones) >= 1


# --- SSN Detection ---

def test_detect_ssn():
    detector = PIIDetector()
    entities = detector.detect("My SSN is 123-45-6789")
    ssns = [e for e in entities if e.entity_type == "SSN"]
    assert len(ssns) >= 1
    assert "123-45-6789" in ssns[0].text


def test_detect_ssn_spaces():
    detector = PIIDetector()
    entities = detector.detect("SSN: 123 45 6789")
    ssns = [e for e in entities if e.entity_type == "SSN"]
    assert len(ssns) >= 1


# --- Credit Card Detection ---

def test_detect_visa():
    detector = PIIDetector()
    entities = detector.detect("Card: 4111-1111-1111-1111")
    cards = [e for e in entities if e.entity_type == "CREDIT_CARD"]
    assert len(cards) >= 1


def test_detect_mastercard():
    detector = PIIDetector()
    entities = detector.detect("Pay with 5500 0000 0000 0004")
    cards = [e for e in entities if e.entity_type == "CREDIT_CARD"]
    assert len(cards) >= 1


# --- IP Address Detection ---

def test_detect_ipv4():
    detector = PIIDetector()
    entities = detector.detect("Server IP is 192.168.1.100")
    ips = [e for e in entities if e.entity_type == "IP_ADDRESS"]
    assert len(ips) >= 1
    assert "192.168.1.100" in ips[0].text


# --- Date of Birth Detection ---

def test_detect_dob_us_format():
    detector = PIIDetector()
    entities = detector.detect("Born on 12/25/1990")
    dobs = [e for e in entities if e.entity_type == "DATE_OF_BIRTH"]
    assert len(dobs) >= 1


def test_detect_dob_iso_format():
    detector = PIIDetector()
    entities = detector.detect("DOB: 1990-12-25")
    dobs = [e for e in entities if e.entity_type == "DATE_OF_BIRTH"]
    assert len(dobs) >= 1


# --- Address Detection ---

def test_detect_street_address():
    detector = PIIDetector()
    entities = detector.detect("I live at 123 Main Street in Springfield")
    addrs = [e for e in entities if e.entity_type == "ADDRESS"]
    assert len(addrs) >= 1


# --- Name Detection ---

def test_detect_name_with_prefix():
    detector = PIIDetector()
    entities = detector.detect("Please contact Dr. John Smith for an appointment")
    names = [e for e in entities if e.entity_type == "NAME"]
    assert len(names) >= 1


# --- Filtering by Entity Type ---

def test_detect_only_emails():
    detector = PIIDetector(entity_types=["EMAIL"])
    text = "Email: test@test.com, SSN: 123-45-6789"
    entities = detector.detect(text)
    assert all(e.entity_type == "EMAIL" for e in entities)


# --- No PII ---

def test_no_pii_in_clean_text():
    detector = PIIDetector()
    entities = detector.detect("The quick brown fox jumps over the lazy dog")
    # Should have no or very few detections
    assert len(entities) == 0


def test_empty_text():
    detector = PIIDetector()
    entities = detector.detect("")
    assert len(entities) == 0


# --- PIIRedactor: Mask Strategy ---

def test_redact_mask():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.MASK, detector=detector)
    result = redactor.redact_auto("Email me at test@example.com")
    assert "test@example.com" not in result.redacted_text
    assert "[REDACTED]" in result.redacted_text
    assert len(result.entities_found) >= 1


# --- PIIRedactor: Placeholder Strategy ---

def test_redact_placeholder():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.PLACEHOLDER, detector=detector)
    result = redactor.redact_auto("SSN: 123-45-6789, email: a@b.com")
    assert "[SSN_" in result.redacted_text or "[EMAIL_" in result.redacted_text
    assert "123-45-6789" not in result.redacted_text


# --- PIIRedactor: Hash Strategy ---

def test_redact_hash():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.HASH, detector=detector)
    result = redactor.redact_auto("Call 555-123-4567")
    assert "[HASH:" in result.redacted_text


# --- PIIRedactor: Anonymize Strategy ---

def test_redact_anonymize():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.ANONYMIZE, detector=detector)
    result = redactor.redact_auto("Email me at john@company.com")
    assert "john@company.com" not in result.redacted_text
    # Should contain fake data
    assert "@example" in result.redacted_text or "ANONYMIZED" in result.redacted_text


# --- Reversible Redaction ---

def test_reversible_redaction():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.PLACEHOLDER, detector=detector)
    original = "Contact test@example.com for info"
    result = redactor.redact_auto(original)
    assert "test@example.com" not in result.redacted_text
    # Reverse it
    restored = redactor.reverse_redaction(result.redacted_text, result.redaction_map)
    assert "test@example.com" in restored


# --- Multiple PII in One Text ---

def test_multiple_pii_types():
    detector = PIIDetector()
    redactor = PIIRedactor(strategy=RedactionStrategy.MASK, detector=detector)
    text = "Name: Dr. Jane Doe, SSN: 123-45-6789, Email: jane@test.com"
    result = redactor.redact_auto(text)
    assert "123-45-6789" not in result.redacted_text
    assert "jane@test.com" not in result.redacted_text
    assert len(result.entities_found) >= 2


# --- Redact with Pre-detected Entities ---

def test_redact_with_provided_entities():
    from src.validation.pii_detector import PIIEntity
    redactor = PIIRedactor(strategy=RedactionStrategy.MASK)
    entities = [PIIEntity(entity_type="EMAIL", text="a@b.com", start=10, end=17, confidence=0.95)]
    text = "Email me: a@b.com please"
    result = redactor.redact(text, entities)
    assert "a@b.com" not in result
    assert "[REDACTED]" in result


# --- Custom Mask Text ---

def test_custom_mask_text():
    redactor = PIIRedactor(strategy=RedactionStrategy.MASK, mask_text="[HIDDEN]")
    from src.validation.pii_detector import PIIEntity
    entities = [PIIEntity(entity_type="SSN", text="123-45-6789", start=5, end=16, confidence=0.95)]
    result = redactor.redact("SSN: 123-45-6789", entities)
    assert "[HIDDEN]" in result
