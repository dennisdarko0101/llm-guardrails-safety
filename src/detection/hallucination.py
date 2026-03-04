"""Hallucination detection by verifying LLM output claims against provided context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Claim:
    text: str
    is_supported: bool = False
    supporting_context: str | None = None
    confidence: float = 0.0


@dataclass
class HallucinationResult:
    claims: list[Claim] = field(default_factory=list)
    unsupported_claims: list[Claim] = field(default_factory=list)
    hallucination_score: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def has_hallucinations(self) -> bool:
        return len(self.unsupported_claims) > 0


class HallucinationDetector:
    """Detects hallucinations by verifying output claims against provided context."""

    def __init__(self, llm_client: Any | None = None) -> None:
        self.llm_client = llm_client

    def detect(self, output: str, context: str) -> HallucinationResult:
        """Detect hallucinations in output by checking against context."""
        claims = self._extract_claims(output)

        if not claims:
            return HallucinationResult(hallucination_score=0.0)

        verified_claims: list[Claim] = []
        unsupported: list[Claim] = []

        for claim in claims:
            verified = self._verify_claim(claim, context)
            verified_claims.append(verified)
            if not verified.is_supported:
                unsupported.append(verified)

        score = len(unsupported) / len(claims) if claims else 0.0

        return HallucinationResult(
            claims=verified_claims,
            unsupported_claims=unsupported,
            hallucination_score=score,
            details={
                "total_claims": len(claims),
                "supported_claims": len(claims) - len(unsupported),
                "unsupported_claims": len(unsupported),
            },
        )

    def detect_with_llm(self, output: str, context: str) -> HallucinationResult:
        """Use LLM to verify claims against context (more accurate)."""
        if self.llm_client is None:
            return self.detect(output, context)

        claims = self._extract_claims(output)
        if not claims:
            return HallucinationResult(hallucination_score=0.0)

        verified_claims: list[Claim] = []
        unsupported: list[Claim] = []

        for claim in claims:
            verified = self._verify_claim_with_llm(claim, context)
            verified_claims.append(verified)
            if not verified.is_supported:
                unsupported.append(verified)

        score = len(unsupported) / len(claims) if claims else 0.0

        return HallucinationResult(
            claims=verified_claims,
            unsupported_claims=unsupported,
            hallucination_score=score,
            details={
                "total_claims": len(claims),
                "supported_claims": len(claims) - len(unsupported),
                "unsupported_claims": len(unsupported),
                "method": "llm_verification",
            },
        )

    def _extract_claims(self, text: str) -> list[Claim]:
        """Split output into individual verifiable claims."""
        claims: list[Claim] = []

        # Split into sentences
        sentences = re.split(r"(?<=[.!?])\s+", text.strip())

        for sentence in sentences:
            sentence = sentence.strip()
            if not sentence or len(sentence) < 10:
                continue

            # Filter out questions, commands, and filler
            if sentence.endswith("?"):
                continue
            if sentence.lower().startswith(("please", "note that", "in summary", "overall")):
                continue

            claims.append(Claim(text=sentence))

        return claims

    def _verify_claim(self, claim: Claim, context: str) -> Claim:
        """Verify a claim against context using text overlap heuristics."""
        claim_words = set(re.findall(r"\b\w+\b", claim.text.lower()))
        context_lower = context.lower()

        # Remove common stop words
        stop_words = {"the", "a", "an", "is", "are", "was", "were", "be", "been", "have", "has",
                      "had", "do", "does", "did", "will", "would", "could", "should", "may",
                      "might", "shall", "can", "and", "or", "but", "in", "on", "at", "to",
                      "for", "of", "with", "it", "this", "that", "these", "those", "not", "no"}
        meaningful_words = claim_words - stop_words

        if not meaningful_words:
            claim.is_supported = True
            claim.confidence = 0.5
            return claim

        # Check word overlap
        words_found = sum(1 for w in meaningful_words if w in context_lower)
        overlap_ratio = words_found / len(meaningful_words)

        # Check for substring matches (partial sentence match)
        claim_fragments = [claim.text[i:i+20].lower() for i in range(0, len(claim.text) - 19, 10)]
        fragment_matches = sum(1 for f in claim_fragments if f in context_lower) if claim_fragments else 0
        fragment_ratio = fragment_matches / len(claim_fragments) if claim_fragments else 0

        combined_score = (overlap_ratio * 0.6) + (fragment_ratio * 0.4)

        claim.is_supported = combined_score >= 0.4
        claim.confidence = combined_score

        # Find supporting context snippet
        if claim.is_supported:
            best_snippet = self._find_supporting_snippet(claim.text, context)
            claim.supporting_context = best_snippet

        return claim

    def _verify_claim_with_llm(self, claim: Claim, context: str) -> Claim:
        """Use LLM to verify if a claim is supported by context."""
        if self.llm_client is None:
            return self._verify_claim(claim, context)

        prompt = (
            "Given the following context and claim, determine if the claim is supported by the context.\n"
            "Respond with ONLY a JSON object: {\"is_supported\": true/false, \"confidence\": 0.0-1.0, \"supporting_text\": \"...\"}\n\n"
            f"Context:\n{context}\n\n"
            f"Claim:\n{claim.text}"
        )

        try:
            import json
            response = self.llm_client.classify(prompt)
            result = json.loads(response)
            claim.is_supported = result.get("is_supported", False)
            claim.confidence = result.get("confidence", 0.0)
            claim.supporting_context = result.get("supporting_text")
        except Exception:
            return self._verify_claim(claim, context)

        return claim

    def _find_supporting_snippet(self, claim_text: str, context: str, window: int = 200) -> str | None:
        """Find the context snippet that best supports the claim."""
        claim_words = re.findall(r"\b\w+\b", claim_text.lower())
        if not claim_words:
            return None

        context_lower = context.lower()
        best_pos = 0
        best_count = 0

        # Sliding window to find the best matching region
        for i in range(0, max(1, len(context) - window), window // 2):
            window_text = context_lower[i:i + window]
            count = sum(1 for w in claim_words if w in window_text)
            if count > best_count:
                best_count = count
                best_pos = i

        if best_count == 0:
            return None

        start = max(0, best_pos)
        end = min(len(context), best_pos + window)
        return context[start:end].strip()
