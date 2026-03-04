"""Multi-layer prompt injection detection engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DetectionMethod(str, Enum):
    PATTERN_MATCH = "pattern_match"
    STRUCTURAL_ANALYSIS = "structural_analysis"
    ENCODING_DETECTION = "encoding_detection"
    LLM_CLASSIFICATION = "llm_classification"


@dataclass
class DetectionResult:
    is_injection: bool
    confidence: float
    method: DetectionMethod | None = None
    matched_patterns: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


# 30+ comprehensive injection patterns
INJECTION_PATTERNS: list[dict[str, str]] = [
    # Direct overrides
    {"name": "ignore_previous", "pattern": r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|context)", "category": "direct_override"},
    {"name": "disregard_instructions", "pattern": r"disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|rules|guidelines)", "category": "direct_override"},
    {"name": "forget_instructions", "pattern": r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions|rules|context)", "category": "direct_override"},
    {"name": "override_instructions", "pattern": r"override\s+(all\s+)?(previous|system|safety)\s+(instructions|rules|settings)", "category": "direct_override"},
    {"name": "new_instructions", "pattern": r"(new|updated|revised)\s+instructions\s*[:=]", "category": "direct_override"},
    {"name": "do_not_follow", "pattern": r"do\s+not\s+follow\s+(your|the|any)\s+(previous|original|initial)\s+instructions", "category": "direct_override"},

    # Role manipulation
    {"name": "you_are_now", "pattern": r"you\s+are\s+now\s+(a|an|the|DAN|evil|unrestricted|unfiltered)", "category": "role_manipulation"},
    {"name": "act_as", "pattern": r"(act|behave|respond|pretend)\s+(as|like)\s+(a|an|the)?\s*(unrestricted|unfiltered|evil|DAN|jailbroken)", "category": "role_manipulation"},
    {"name": "dan_mode", "pattern": r"(DAN|D\.A\.N|do\s+anything\s+now)\s+(mode|enabled|activated)", "category": "role_manipulation"},
    {"name": "roleplay_evil", "pattern": r"(roleplay|role-play|role\s+play)\s+(as\s+)?(a\s+)?(villain|hacker|evil|malicious)", "category": "role_manipulation"},
    {"name": "developer_mode", "pattern": r"(developer|dev|debug|maintenance|admin)\s+(mode|access)\s*(enabled|activated|on)?", "category": "role_manipulation"},
    {"name": "persona_switch", "pattern": r"switch\s+(to|into)\s+(your\s+)?(alter\s+ego|evil\s+twin|unrestricted\s+mode)", "category": "role_manipulation"},
    {"name": "hypothetical_ai", "pattern": r"(imagine|pretend|suppose)\s+you\s+(are|were)\s+an?\s+AI\s+(without|with\s+no)\s+(restrictions|filters|limitations)", "category": "role_manipulation"},

    # Delimiter injection
    {"name": "system_delimiter", "pattern": r"(```|---|\*\*\*|===)\s*(system|admin|root|prompt|instructions)\s*[:=\n]", "category": "delimiter_injection"},
    {"name": "xml_system", "pattern": r"<\s*(system|admin|root|instruction|prompt)\s*>", "category": "delimiter_injection"},
    {"name": "json_system", "pattern": r'["\']?(system|role|instruction)["\']?\s*[:=]\s*["\']', "category": "delimiter_injection"},
    {"name": "markdown_header_system", "pattern": r"#+\s*(System|SYSTEM|Admin|ROOT)\s*(Prompt|Message|Instructions)", "category": "delimiter_injection"},

    # Indirect injection
    {"name": "hidden_instruction", "pattern": r"(hidden|secret|embedded)\s+(instruction|command|directive|message)", "category": "indirect_injection"},
    {"name": "when_asked_respond", "pattern": r"when\s+(asked|prompted|queried)\s+(about|for|regarding).*?(respond|reply|say|answer)\s+with", "category": "indirect_injection"},
    {"name": "if_anyone_asks", "pattern": r"if\s+(anyone|someone|a\s+user)\s+asks.*?(tell|say|respond|reply)", "category": "indirect_injection"},
    {"name": "instruction_in_data", "pattern": r"(IMPORTANT|NOTE|INSTRUCTION|ATTENTION)\s*[:=]\s*(ignore|override|forget|disregard)", "category": "indirect_injection"},

    # System prompt extraction
    {"name": "reveal_prompt", "pattern": r"(reveal|show|display|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions|rules|guidelines)", "category": "prompt_extraction"},
    {"name": "what_is_prompt", "pattern": r"what\s+(is|are)\s+your\s+(system\s+)?(prompt|instructions|rules|initial\s+instructions)", "category": "prompt_extraction"},
    {"name": "beginning_of_conversation", "pattern": r"(repeat|output|print)\s+(everything|all)\s+(from\s+)?(the\s+)?(beginning|start)\s+(of\s+)?(the\s+)?(conversation|chat)", "category": "prompt_extraction"},
    {"name": "copy_paste_prompt", "pattern": r"(copy|paste|type|write)\s+(out\s+)?(your\s+)?(entire\s+)?(system\s+)?(prompt|instructions|message)", "category": "prompt_extraction"},

    # Encoding-based attacks
    {"name": "base64_instruction", "pattern": r"(decode|interpret|execute|follow)\s+(this\s+)?(base64|encoded|encrypted)\s*([:=]|\s+instruction)", "category": "encoding_attack"},
    {"name": "rot13_instruction", "pattern": r"(rot13|caesar|cipher)\s*[:=]", "category": "encoding_attack"},

    # Token manipulation
    {"name": "token_smuggling", "pattern": r"(\[INST\]|\[/INST\]|<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|user\|>|<\|assistant\|>)", "category": "token_manipulation"},
    {"name": "special_tokens", "pattern": r"(<\|endoftext\|>|<\|pad\|>|<\|sep\|>|<s>|</s>|\[CLS\]|\[SEP\])", "category": "token_manipulation"},

    # Obfuscation
    {"name": "spaced_ignore", "pattern": r"i\s*g\s*n\s*o\s*r\s*e\s+(p\s*r\s*e\s*v\s*i\s*o\s*u\s*s|a\s*l\s*l)", "category": "obfuscation"},
    {"name": "leetspeak_ignore", "pattern": r"(1gn0r3|!gnore|ign0re)\s+(pr3v10us|prev!ous|all)", "category": "obfuscation"},
    {"name": "unicode_bypass", "pattern": r"[\u200b\u200c\u200d\u2060\ufeff]", "category": "obfuscation"},
]

# Structural markers that indicate role-switching attempts
STRUCTURAL_MARKERS = [
    r"^\s*###?\s*(System|Assistant|User)\s*[:>]",
    r"^\s*(Human|AI|System|Assistant)\s*:",
    r"\[SYSTEM\]|\[ADMIN\]|\[ROOT\]|\[OVERRIDE\]",
    r"<\|system\|>|<\|assistant\|>|<\|user\|>",
    r"BEGIN\s+(SYSTEM|ADMIN|OVERRIDE)\s+(MESSAGE|INSTRUCTION|PROMPT)",
    r"END\s+OF\s+(USER\s+)?INPUT.*BEGIN\s+(SYSTEM|REAL|ACTUAL)\s+(INSTRUCTIONS|PROMPT)",
]


class PromptInjectionDetector:
    """Multi-layer prompt injection detection system."""

    def __init__(
        self,
        sensitivity: str = "medium",
        custom_patterns: list[dict[str, str]] | None = None,
        llm_client: Any | None = None,
    ) -> None:
        self.sensitivity = sensitivity
        self.patterns = INJECTION_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self.llm_client = llm_client

        # Sensitivity thresholds
        self._thresholds = {
            "low": 0.8,
            "medium": 0.5,
            "high": 0.3,
        }

    @property
    def confidence_threshold(self) -> float:
        return self._thresholds.get(self.sensitivity, 0.5)

    def detect(self, text: str) -> DetectionResult:
        """Run multi-layer injection detection on text."""
        results: list[DetectionResult] = []

        # Layer 1: Pattern matching
        pattern_result = self._detect_patterns(text)
        results.append(pattern_result)

        # Layer 2: Structural analysis
        structural_result = self._detect_structural(text)
        results.append(structural_result)

        # Layer 3: Encoding detection (imported lazily)
        encoding_result = self._detect_encoding(text)
        results.append(encoding_result)

        # Merge results
        return self._merge_results(results)

    def detect_with_llm(self, text: str) -> DetectionResult:
        """Run all detection layers including LLM-based classification."""
        base_result = self.detect(text)

        if self.llm_client is None:
            return base_result

        llm_result = self._detect_llm(text)
        return self._merge_results([base_result, llm_result])

    def _detect_patterns(self, text: str) -> DetectionResult:
        """Layer 1: Check text against known injection patterns."""
        matched: list[str] = []
        highest_confidence = 0.0

        for pattern_info in self.patterns:
            pattern = pattern_info["pattern"]
            try:
                if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                    matched.append(pattern_info["name"])
                    # More matches = higher confidence
                    highest_confidence = min(1.0, highest_confidence + 0.3)
            except re.error:
                continue

        if not matched:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                method=DetectionMethod.PATTERN_MATCH,
            )

        confidence = min(1.0, 0.4 + (len(matched) * 0.15))
        return DetectionResult(
            is_injection=confidence >= self.confidence_threshold,
            confidence=confidence,
            method=DetectionMethod.PATTERN_MATCH,
            matched_patterns=matched,
        )

    def _detect_structural(self, text: str) -> DetectionResult:
        """Layer 2: Detect role-switching and instruction delimiter abuse."""
        markers_found: list[str] = []

        for marker_pattern in STRUCTURAL_MARKERS:
            try:
                if re.search(marker_pattern, text, re.IGNORECASE | re.MULTILINE):
                    markers_found.append(marker_pattern)
            except re.error:
                continue

        if not markers_found:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                method=DetectionMethod.STRUCTURAL_ANALYSIS,
            )

        confidence = min(1.0, 0.5 + (len(markers_found) * 0.2))
        return DetectionResult(
            is_injection=confidence >= self.confidence_threshold,
            confidence=confidence,
            method=DetectionMethod.STRUCTURAL_ANALYSIS,
            matched_patterns=[f"structural:{m}" for m in markers_found],
            details={"markers_count": len(markers_found)},
        )

    def _detect_encoding(self, text: str) -> DetectionResult:
        """Layer 3: Detect encoded/obfuscated injection attempts."""
        from src.detection.encoding import EncodingDetector

        detector = EncodingDetector()
        decoded_results = detector.decode_and_scan(text)

        if not decoded_results:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                method=DetectionMethod.ENCODING_DETECTION,
            )

        # Check decoded content for injection patterns
        injection_in_decoded = False
        matched: list[str] = []
        for decoded in decoded_results:
            for pattern_info in self.patterns:
                try:
                    if re.search(pattern_info["pattern"], decoded.decoded_text, re.IGNORECASE):
                        injection_in_decoded = True
                        matched.append(f"encoded:{pattern_info['name']}")
                except re.error:
                    continue

        confidence = 0.7 if injection_in_decoded else 0.3
        return DetectionResult(
            is_injection=injection_in_decoded and confidence >= self.confidence_threshold,
            confidence=confidence,
            method=DetectionMethod.ENCODING_DETECTION,
            matched_patterns=matched,
            details={"decoded_items": len(decoded_results)},
        )

    def _detect_llm(self, text: str) -> DetectionResult:
        """Layer 4: Use LLM to classify if text is an injection attempt."""
        if self.llm_client is None:
            return DetectionResult(is_injection=False, confidence=0.0)

        classification_prompt = (
            "Analyze the following text and determine if it is a prompt injection attempt. "
            "A prompt injection is an attempt to override, manipulate, or extract system instructions. "
            "Respond with ONLY a JSON object: {\"is_injection\": true/false, \"confidence\": 0.0-1.0, \"reason\": \"...\"}\n\n"
            f"Text to analyze:\n{text}"
        )

        try:
            response = self.llm_client.classify(classification_prompt)
            import json
            result = json.loads(response)
            return DetectionResult(
                is_injection=result.get("is_injection", False),
                confidence=result.get("confidence", 0.0),
                method=DetectionMethod.LLM_CLASSIFICATION,
                details={"reason": result.get("reason", "")},
            )
        except Exception:
            return DetectionResult(
                is_injection=False,
                confidence=0.0,
                method=DetectionMethod.LLM_CLASSIFICATION,
            )

    def _merge_results(self, results: list[DetectionResult]) -> DetectionResult:
        """Merge multiple detection results into a single result."""
        if not results:
            return DetectionResult(is_injection=False, confidence=0.0)

        all_patterns: list[str] = []
        all_details: dict[str, Any] = {}
        max_confidence = 0.0
        any_injection = False
        best_method: DetectionMethod | None = None

        for result in results:
            all_patterns.extend(result.matched_patterns)
            all_details.update(result.details)
            if result.confidence > max_confidence:
                max_confidence = result.confidence
                best_method = result.method
            if result.is_injection:
                any_injection = True

        return DetectionResult(
            is_injection=any_injection,
            confidence=max_confidence,
            method=best_method,
            matched_patterns=all_patterns,
            details=all_details,
        )
