"""PII redaction with multiple replacement strategies and reversible mode."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from src.validation.pii_detector import PIIDetector, PIIEntity


class RedactionStrategy(str, Enum):
    MASK = "mask"           # [REDACTED]
    HASH = "hash"           # sha256 hash
    PLACEHOLDER = "placeholder"  # [EMAIL_1], [PHONE_2], etc.
    ANONYMIZE = "anonymize"      # Replace with fake data


@dataclass
class RedactionResult:
    redacted_text: str
    entities_found: list[PIIEntity] = field(default_factory=list)
    redaction_map: dict[str, str] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


# Fake data templates for anonymization
FAKE_DATA: dict[str, list[str]] = {
    "EMAIL": ["user@example.com", "contact@example.org", "info@example.net"],
    "PHONE": ["(555) 000-0001", "(555) 000-0002", "(555) 000-0003"],
    "SSN": ["000-00-0000", "000-00-0001", "000-00-0002"],
    "CREDIT_CARD": ["0000-0000-0000-0000", "0000-0000-0000-0001"],
    "IP_ADDRESS": ["0.0.0.0", "127.0.0.1"],
    "NAME": ["John Doe", "Jane Smith", "Alex Johnson"],
    "ADDRESS": ["123 Example Street", "456 Test Avenue"],
    "DATE_OF_BIRTH": ["01/01/2000", "01/01/1990"],
}


class PIIRedactor:
    """Redacts PII from text using configurable strategies."""

    def __init__(
        self,
        strategy: RedactionStrategy = RedactionStrategy.MASK,
        detector: PIIDetector | None = None,
        mask_text: str = "[REDACTED]",
    ) -> None:
        self.strategy = strategy
        self.detector = detector or PIIDetector()
        self.mask_text = mask_text
        self._counters: dict[str, int] = {}
        self._anonymize_counters: dict[str, int] = {}

    def redact(self, text: str, entities: list[PIIEntity]) -> str:
        """Redact specified entities from text."""
        if not entities:
            return text

        self._counters = {}
        self._anonymize_counters = {}

        # Sort by position descending to maintain indices
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        result = text
        for entity in sorted_entities:
            replacement = self._get_replacement(entity)
            result = result[:entity.start] + replacement + result[entity.end:]

        return result

    def redact_auto(self, text: str) -> RedactionResult:
        """Detect and redact PII in one call."""
        entities = self.detector.detect(text)

        if not entities:
            return RedactionResult(
                redacted_text=text,
                entities_found=[],
                redaction_map={},
            )

        # Build redaction map for reversibility
        redaction_map: dict[str, str] = {}
        self._counters = {}
        self._anonymize_counters = {}

        # Sort by position descending
        sorted_entities = sorted(entities, key=lambda e: e.start, reverse=True)

        result = text
        for entity in sorted_entities:
            replacement = self._get_replacement(entity)
            redaction_map[replacement] = entity.text
            result = result[:entity.start] + replacement + result[entity.end:]

        return RedactionResult(
            redacted_text=result,
            entities_found=entities,
            redaction_map=redaction_map,
            details={
                "strategy": self.strategy.value,
                "entities_redacted": len(entities),
            },
        )

    def reverse_redaction(self, redacted_text: str, redaction_map: dict[str, str]) -> str:
        """Reverse a redaction using the stored redaction map."""
        result = redacted_text
        for placeholder, original in redaction_map.items():
            result = result.replace(placeholder, original)
        return result

    def _get_replacement(self, entity: PIIEntity) -> str:
        """Get the replacement string based on the configured strategy."""
        raw = entity.entity_type
        entity_type = raw.value if hasattr(raw, "value") else str(raw)

        if self.strategy == RedactionStrategy.MASK:
            return self.mask_text

        elif self.strategy == RedactionStrategy.HASH:
            hash_val = hashlib.sha256(entity.text.encode()).hexdigest()[:12]
            return f"[HASH:{hash_val}]"

        elif self.strategy == RedactionStrategy.PLACEHOLDER:
            count = self._counters.get(entity_type, 0) + 1
            self._counters[entity_type] = count
            return f"[{entity_type}_{count}]"

        elif self.strategy == RedactionStrategy.ANONYMIZE:
            fake_list = FAKE_DATA.get(entity_type, ["[ANONYMIZED]"])
            idx = self._anonymize_counters.get(entity_type, 0)
            self._anonymize_counters[entity_type] = idx + 1
            return fake_list[idx % len(fake_list)]

        return self.mask_text
