"""Topic boundary enforcement to keep LLM interactions on-topic."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class TopicResult:
    is_on_topic: bool
    detected_topic: str | None = None
    similarity_score: float = 0.0
    closest_allowed_topic: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class TopicBoundaryEnforcer:
    """Enforces topic boundaries using keyword matching and semantic similarity."""

    def __init__(
        self,
        allowed_topics: list[str] | None = None,
        blocked_topics: list[str] | None = None,
        mode: str = "permissive",
        semantic_model: Any | None = None,
    ) -> None:
        self.allowed_topics = allowed_topics or []
        self.blocked_topics = blocked_topics or []
        self.mode = mode  # "strict" or "permissive"
        self.semantic_model = semantic_model

        # Build keyword index for each topic
        self._allowed_keywords: dict[str, list[str]] = {}
        self._blocked_keywords: dict[str, list[str]] = {}

        for topic in self.allowed_topics:
            self._allowed_keywords[topic] = self._extract_keywords(topic)
        for topic in self.blocked_topics:
            self._blocked_keywords[topic] = self._extract_keywords(topic)

    @staticmethod
    def _fuzzy_keyword_overlap(text_words: set[str], keywords: list[str]) -> list[str]:
        """Match keywords against text words using stem/prefix overlap."""
        matched: list[str] = []
        for kw in keywords:
            kw_stem = kw[:4] if len(kw) > 4 else kw  # simple prefix stem
            for tw in text_words:
                if tw == kw or tw.startswith(kw_stem) or kw.startswith(tw[:4] if len(tw) > 4 else tw):
                    matched.append(kw)
                    break
        return matched

    def _extract_keywords(self, topic: str) -> list[str]:
        """Extract meaningful keywords from a topic string."""
        words = re.findall(r"\b\w+\b", topic.lower())
        # Filter out common stop words
        stop_words = {"the", "a", "an", "is", "are", "was", "were", "be", "been", "and", "or", "in", "on", "at", "to", "for", "of", "with", "about"}
        return [w for w in words if w not in stop_words and len(w) > 2]

    def check(self, text: str) -> TopicResult:
        """Check if text is within topic boundaries."""
        text_lower = text.lower()
        text_keywords = set(re.findall(r"\b\w+\b", text_lower))

        # Check blocked topics first
        for topic, keywords in self._blocked_keywords.items():
            overlap = self._fuzzy_keyword_overlap(text_keywords, keywords)
            if overlap:
                score = len(overlap) / max(len(keywords), 1)
                if score >= 0.3:
                    return TopicResult(
                        is_on_topic=False,
                        detected_topic=topic,
                        similarity_score=score,
                        details={"matched_keywords": list(overlap), "reason": "blocked_topic"},
                    )

        # Check allowed topics
        if self.allowed_topics:
            best_match_topic = None
            best_score = 0.0
            best_overlap: list[str] = []

            for topic, keywords in self._allowed_keywords.items():
                overlap = self._fuzzy_keyword_overlap(text_keywords, keywords)
                score = len(overlap) / max(len(keywords), 1) if keywords else 0.0
                if score > best_score:
                    best_score = score
                    best_match_topic = topic
                    best_overlap = list(overlap)

            # Try semantic similarity if available and keyword match is low
            if self.semantic_model is not None and best_score < 0.3:
                semantic_result = self._check_semantic_similarity(text)
                if semantic_result.similarity_score > best_score:
                    return semantic_result

            if self.mode == "strict":
                # In strict mode, must match an allowed topic
                is_on_topic = best_score >= 0.3
            else:
                # In permissive mode, only block if clearly off-topic
                is_on_topic = best_score >= 0.1 or not self.allowed_topics

            return TopicResult(
                is_on_topic=is_on_topic,
                detected_topic=best_match_topic if best_score > 0 else None,
                similarity_score=best_score,
                closest_allowed_topic=best_match_topic,
                details={"matched_keywords": best_overlap},
            )

        # No allowed topics defined — everything is on-topic by default
        return TopicResult(is_on_topic=True, similarity_score=1.0)

    def _check_semantic_similarity(self, text: str) -> TopicResult:
        """Use semantic similarity model to check topic relevance."""
        if self.semantic_model is None:
            return TopicResult(is_on_topic=True, similarity_score=0.0)

        try:
            text_embedding = self.semantic_model.encode([text])
            topic_embeddings = self.semantic_model.encode(self.allowed_topics)

            # Compute cosine similarities
            import numpy as np
            similarities = np.dot(text_embedding, topic_embeddings.T).flatten()
            best_idx = int(np.argmax(similarities))
            best_score = float(similarities[best_idx])

            return TopicResult(
                is_on_topic=best_score >= 0.5,
                detected_topic=self.allowed_topics[best_idx] if best_score >= 0.3 else None,
                similarity_score=best_score,
                closest_allowed_topic=self.allowed_topics[best_idx],
                details={"method": "semantic_similarity"},
            )
        except Exception:
            return TopicResult(is_on_topic=True, similarity_score=0.0)
