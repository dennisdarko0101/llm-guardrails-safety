"""Content toxicity classification with rule-based and LLM-based modes."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ToxicityCategory(str, Enum):
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    SEXUAL_CONTENT = "sexual_content"
    VIOLENCE = "violence"
    SELF_HARM = "self_harm"
    DANGEROUS_CONTENT = "dangerous_content"


@dataclass
class ToxicityResult:
    scores: dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    is_toxic: bool = False
    flagged_categories: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


# Keyword/pattern lists for rule-based classification
TOXICITY_PATTERNS: dict[str, dict[str, Any]] = {
    ToxicityCategory.HATE_SPEECH: {
        "keywords": [
            "racial slur", "ethnic cleansing", "white supremacy", "master race",
            "subhuman", "inferior race", "go back to your country",
            "they're all criminals", "those people are animals",
        ],
        "patterns": [
            r"\b(hate|kill|exterminate|eliminate)\s+(all\s+)?(jews|muslims|christians|blacks|whites|asians|mexicans|immigrants|refugees)\b",
            r"\b(racial|ethnic)\s+(purity|superiority|inferiority)\b",
            r"\bdeath\s+to\s+(all\s+)?\w+\b",
        ],
        "weight": 1.0,
    },
    ToxicityCategory.HARASSMENT: {
        "keywords": [
            "i'll find you", "you're worthless", "kill yourself",
            "nobody likes you", "you deserve to die", "dox you",
            "i know where you live", "swatting", "cyberbully",
        ],
        "patterns": [
            r"\bi['\u2019]?ll\s+(find|hunt|track|get)\s+(you|them|him|her)\b",
            r"\byou\s+(should|deserve\s+to)\s+(die|suffer|be\s+hurt)\b",
            r"\b(dox|doxx|swat)\s+(you|them|him|her)\b",
            r"\b(stalk|harass|threaten|intimidate)\s+(you|them|him|her)\b",
        ],
        "weight": 0.9,
    },
    ToxicityCategory.SEXUAL_CONTENT: {
        "keywords": [
            "explicit sexual", "child exploitation", "csam",
            "sexual abuse", "non-consensual",
            "revenge porn", "sexual predator",
        ],
        "patterns": [
            r"\b(child|minor|underage)\s+(sex|porn|exploitation|abuse)\b",
            r"\b(sexual|indecent)\s+(assault|abuse|exploitation|harassment)\b",
            r"\b(revenge\s+porn|non-?consensual\s+(porn|sex|image))\b",
        ],
        "weight": 1.0,
    },
    ToxicityCategory.VIOLENCE: {
        "keywords": [
            "how to kill", "murder plan", "mass shooting",
            "bomb threat", "terrorist attack", "torture methods",
            "school shooting", "assassination",
        ],
        "patterns": [
            r"\b(how\s+to|plan\s+to|going\s+to)\s+(kill|murder|assassinate|attack)\b",
            r"\b(mass|school|church|mosque)\s+(shooting|attack|bombing)\b",
            r"\b(torture|mutilate|dismember)\s+(someone|a\s+person|them|him|her)\b",
            r"\b(bomb|explosive)\s+(threat|making|instructions|recipe)\b",
        ],
        "weight": 1.0,
    },
    ToxicityCategory.SELF_HARM: {
        "keywords": [
            "how to kill myself", "suicide methods", "painless death",
            "end my life", "cut myself", "self-mutilation",
            "pro-ana", "pro-mia",
        ],
        "patterns": [
            r"\b(how\s+to|ways\s+to|methods\s+to)\s+(kill\s+myself|commit\s+suicide|end\s+my\s+life)\b",
            r"\b(want\s+to|going\s+to)\s+(die|kill\s+myself|hurt\s+myself|end\s+it)\b",
            r"\b(self[- ]?harm|self[- ]?mutilat|cutting\s+myself)\b",
            r"\b(suicide\s+note|suicide\s+plan|suicide\s+method)\b",
        ],
        "weight": 1.0,
    },
    ToxicityCategory.DANGEROUS_CONTENT: {
        "keywords": [
            "how to make a bomb", "synthesize drugs", "make poison",
            "hack into", "steal identity", "counterfeit money",
            "biological weapon", "chemical weapon",
        ],
        "patterns": [
            r"\b(how\s+to|instructions?\s+for)\s+(make|build|create|synthesize)\s+(a\s+)?(bomb|explosive|weapon|poison|drug|meth)\b",
            r"\b(biological|chemical|nuclear)\s+(weapon|warfare|attack)\b",
            r"\b(hack|break)\s+into\s+(a\s+)?(bank|government|system|server|account)\b",
            r"\b(counterfeit|forge)\s+(money|currency|documents|identity)\b",
        ],
        "weight": 0.9,
    },
}


class ToxicityClassifier:
    """Classifies text content for toxicity across multiple categories."""

    def __init__(
        self,
        threshold: float = 0.7,
        category_thresholds: dict[str, float] | None = None,
        mode: str = "rule_based",
        llm_client: Any | None = None,
    ) -> None:
        self.threshold = threshold
        self.category_thresholds = category_thresholds or {}
        self.mode = mode  # "rule_based" or "llm_based"
        self.llm_client = llm_client

    def classify(self, text: str) -> ToxicityResult:
        """Classify text for toxicity."""
        if self.mode == "llm_based" and self.llm_client is not None:
            return self._classify_llm(text)
        return self._classify_rule_based(text)

    def _classify_rule_based(self, text: str) -> ToxicityResult:
        """Rule-based toxicity classification using keywords and regex."""
        scores: dict[str, float] = {}
        flagged: list[str] = []
        text_lower = text.lower()

        for category, config in TOXICITY_PATTERNS.items():
            cat_name = category if isinstance(category, str) else category.value
            score = 0.0
            matches = 0

            # Keyword matching
            for keyword in config["keywords"]:
                if keyword.lower() in text_lower:
                    matches += 1
                    score += 0.3

            # Pattern matching
            for pattern in config["patterns"]:
                try:
                    if re.search(pattern, text, re.IGNORECASE):
                        matches += 1
                        score += 0.4
                except re.error:
                    continue

            # Apply weight and cap at 1.0
            score = min(1.0, score * config.get("weight", 1.0))
            scores[cat_name] = score

            cat_threshold = self.category_thresholds.get(cat_name, self.threshold)
            if score >= cat_threshold:
                flagged.append(cat_name)

        overall = max(scores.values()) if scores else 0.0

        return ToxicityResult(
            scores=scores,
            overall_score=overall,
            is_toxic=overall >= self.threshold,
            flagged_categories=flagged,
            details={"mode": "rule_based"},
        )

    def _classify_llm(self, text: str) -> ToxicityResult:
        """LLM-based toxicity classification."""
        if self.llm_client is None:
            return self._classify_rule_based(text)

        categories_str = ", ".join(c.value for c in ToxicityCategory)
        prompt = (
            f"Analyze the following text for toxicity across these categories: {categories_str}.\n"
            "For each category, provide a score from 0.0 to 1.0.\n"
            "Respond with ONLY a JSON object: {\"scores\": {\"category\": score}, \"overall\": score, \"flagged\": [\"category\"]}\n\n"
            f"Text:\n{text}"
        )

        try:
            import json
            response = self.llm_client.classify(prompt)
            result = json.loads(response)
            scores = result.get("scores", {})
            overall = result.get("overall", max(scores.values()) if scores else 0.0)
            flagged = result.get("flagged", [])

            return ToxicityResult(
                scores=scores,
                overall_score=overall,
                is_toxic=overall >= self.threshold,
                flagged_categories=flagged,
                details={"mode": "llm_based"},
            )
        except Exception:
            return self._classify_rule_based(text)
