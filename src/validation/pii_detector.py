"""PII (Personally Identifiable Information) detection using regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class PIIEntityType(str, Enum):
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    ADDRESS = "ADDRESS"
    NAME = "NAME"
    IP_ADDRESS = "IP_ADDRESS"
    DATE_OF_BIRTH = "DATE_OF_BIRTH"


@dataclass
class PIIEntity:
    entity_type: str
    text: str
    start: int
    end: int
    confidence: float = 1.0


# Comprehensive regex patterns for PII detection
PII_PATTERNS: dict[str, list[dict[str, str | float]]] = {
    PIIEntityType.EMAIL: [
        {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "confidence": 0.95,
        },
    ],
    PIIEntityType.PHONE: [
        # US phone numbers
        {
            "pattern": r"\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "confidence": 0.85,
        },
        # International format
        {
            "pattern": r"\b\+\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b",
            "confidence": 0.80,
        },
    ],
    PIIEntityType.SSN: [
        {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "confidence": 0.95,
        },
        {
            "pattern": r"\b\d{3}\s\d{2}\s\d{4}\b",
            "confidence": 0.85,
        },
    ],
    PIIEntityType.CREDIT_CARD: [
        # Visa
        {
            "pattern": r"\b4\d{3}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "confidence": 0.90,
        },
        # Mastercard
        {
            "pattern": r"\b5[1-5]\d{2}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "confidence": 0.90,
        },
        # Amex
        {
            "pattern": r"\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b",
            "confidence": 0.90,
        },
        # Generic 16-digit
        {
            "pattern": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
            "confidence": 0.75,
        },
    ],
    PIIEntityType.IP_ADDRESS: [
        # IPv4
        {
            "pattern": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
            "confidence": 0.90,
        },
        # IPv6 (simplified)
        {
            "pattern": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            "confidence": 0.85,
        },
    ],
    PIIEntityType.DATE_OF_BIRTH: [
        # MM/DD/YYYY or MM-DD-YYYY
        {
            "pattern": r"\b(?:0[1-9]|1[0-2])[/-](?:0[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b",
            "confidence": 0.70,
        },
        # YYYY-MM-DD
        {
            "pattern": r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b",
            "confidence": 0.70,
        },
        # Explicit DOB context
        {
            "pattern": r"(?:date\s+of\s+birth|DOB|born\s+on|birthday)[:\s]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})",
            "confidence": 0.90,
        },
    ],
    PIIEntityType.ADDRESS: [
        # US street address
        {
            "pattern": r"\b\d{1,5}\s+(?:[A-Z][a-z]+\s+){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Court|Ct|Lane|Ln|Road|Rd|Way|Place|Pl)\b\.?",
            "confidence": 0.75,
        },
        # ZIP code
        {
            "pattern": r"\b\d{5}(?:-\d{4})?\b",
            "confidence": 0.50,
        },
    ],
}

# Common name patterns (high false-positive rate, lower confidence)
NAME_PREFIXES = [
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Madam|Lord|Lady)\.\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b",
    r"(?:name\s+is|called|known\s+as|I\s+am|my\s+name)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2})",
]


class PIIDetector:
    """Detects PII entities in text using regex patterns."""

    def __init__(
        self,
        entity_types: list[str] | None = None,
        custom_patterns: dict[str, list[dict[str, str | float]]] | None = None,
    ) -> None:
        self.entity_types = entity_types  # None means detect all
        self.patterns = dict(PII_PATTERNS)
        if custom_patterns:
            for entity_type, patterns in custom_patterns.items():
                if entity_type in self.patterns:
                    self.patterns[entity_type].extend(patterns)
                else:
                    self.patterns[entity_type] = patterns

    def detect(self, text: str) -> list[PIIEntity]:
        """Detect all PII entities in text."""
        entities: list[PIIEntity] = []
        seen_spans: set[tuple[int, int]] = set()

        for entity_type, patterns in self.patterns.items():
            type_str = entity_type if isinstance(entity_type, str) else entity_type.value

            # Skip if not in requested entity types
            if self.entity_types and type_str not in self.entity_types:
                continue

            for pattern_config in patterns:
                pattern = str(pattern_config["pattern"])
                confidence = float(pattern_config.get("confidence", 0.8))

                try:
                    for match in re.finditer(pattern, text, re.IGNORECASE):
                        span = (match.start(), match.end())
                        # Avoid duplicate spans
                        if span in seen_spans:
                            continue
                        seen_spans.add(span)

                        entities.append(
                            PIIEntity(
                                entity_type=type_str,
                                text=match.group(),
                                start=match.start(),
                                end=match.end(),
                                confidence=confidence,
                            )
                        )
                except re.error:
                    continue

        # Detect names (separate due to different logic)
        if self.entity_types is None or PIIEntityType.NAME in (self.entity_types or []):
            name_entities = self._detect_names(text, seen_spans)
            entities.extend(name_entities)

        # Sort by position
        entities.sort(key=lambda e: e.start)
        return entities

    def _detect_names(self, text: str, seen_spans: set[tuple[int, int]]) -> list[PIIEntity]:
        """Detect potential person names in text."""
        entities: list[PIIEntity] = []

        for pattern in NAME_PREFIXES:
            try:
                for match in re.finditer(pattern, text):
                    span = (match.start(), match.end())
                    if span in seen_spans:
                        continue
                    seen_spans.add(span)
                    entities.append(
                        PIIEntity(
                            entity_type=PIIEntityType.NAME,
                            text=match.group(),
                            start=match.start(),
                            end=match.end(),
                            confidence=0.65,
                        )
                    )
            except re.error:
                continue

        return entities

    def detect_types(self, text: str) -> dict[str, list[PIIEntity]]:
        """Detect PII grouped by entity type."""
        entities = self.detect(text)
        grouped: dict[str, list[PIIEntity]] = {}
        for entity in entities:
            grouped.setdefault(entity.entity_type, []).append(entity)
        return grouped
