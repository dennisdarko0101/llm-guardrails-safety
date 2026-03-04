"""Encoding detection and decoding for obfuscated injection attempts."""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass


@dataclass
class DecodedContent:
    original_text: str
    decoded_text: str
    encoding_type: str
    start: int = 0
    end: int = 0


class EncodingDetector:
    """Detects and decodes encoded content that may hide injection attempts."""

    # Mapping of common homoglyphs to ASCII
    HOMOGLYPH_MAP: dict[str, str] = {
        "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
        "\u041d": "H", "\u041a": "K", "\u041c": "M", "\u041e": "O",
        "\u0420": "P", "\u0422": "T", "\u0425": "X",
        "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
        "\u0441": "c", "\u0443": "y", "\u0445": "x",
        "\uff21": "A", "\uff22": "B", "\uff23": "C",
        "\u2000": " ", "\u2001": " ", "\u2002": " ", "\u2003": " ",
        "\u00a0": " ",
    }

    INVISIBLE_CHARS = {
        "\u200b",  # Zero-width space
        "\u200c",  # Zero-width non-joiner
        "\u200d",  # Zero-width joiner
        "\u2060",  # Word joiner
        "\ufeff",  # Zero-width no-break space (BOM)
        "\u00ad",  # Soft hyphen
        "\u200e",  # Left-to-right mark
        "\u200f",  # Right-to-left mark
        "\u202a",  # Left-to-right embedding
        "\u202b",  # Right-to-left embedding
        "\u202c",  # Pop directional formatting
        "\u2066",  # Left-to-right isolate
        "\u2067",  # Right-to-left isolate
        "\u2068",  # First strong isolate
        "\u2069",  # Pop directional isolate
    }

    def detect_base64(self, text: str) -> list[DecodedContent]:
        """Detect and decode base64-encoded strings in text."""
        results: list[DecodedContent] = []
        # Match base64 strings (at least 16 chars to avoid false positives)
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

        for match in b64_pattern.finditer(text):
            candidate = match.group()
            try:
                # Pad if necessary
                padded = candidate + "=" * (4 - len(candidate) % 4) if len(candidate) % 4 else candidate
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="strict")
                # Only keep if decoded text is printable
                if decoded_str.isprintable() and len(decoded_str) >= 4:
                    results.append(
                        DecodedContent(
                            original_text=candidate,
                            decoded_text=decoded_str,
                            encoding_type="base64",
                            start=match.start(),
                            end=match.end(),
                        )
                    )
            except Exception:
                continue

        return results

    def detect_rot13(self, text: str) -> list[DecodedContent]:
        """Detect potential ROT13-encoded text and decode it."""
        results: list[DecodedContent] = []

        # Look for explicit ROT13 markers
        rot13_markers = re.compile(
            r"(?:rot13|ROT13|rot-13)\s*[:=]\s*([A-Za-z\s]+)",
            re.IGNORECASE,
        )

        for match in rot13_markers.finditer(text):
            encoded = match.group(1).strip()
            decoded = codecs.decode(encoded, "rot_13")
            results.append(
                DecodedContent(
                    original_text=encoded,
                    decoded_text=decoded,
                    encoding_type="rot13",
                    start=match.start(1),
                    end=match.end(1),
                )
            )

        return results

    def detect_unicode_tricks(self, text: str) -> list[str]:
        """Detect homoglyph attacks and invisible character abuse."""
        findings: list[str] = []

        # Check for homoglyphs
        homoglyphs_found = []
        for char in text:
            if char in self.HOMOGLYPH_MAP:
                homoglyphs_found.append(char)

        if homoglyphs_found:
            findings.append(
                f"Homoglyph characters detected: {len(homoglyphs_found)} characters "
                f"({', '.join(f'U+{ord(c):04X}' for c in homoglyphs_found[:5])})"
            )

        # Check for invisible characters
        invisible_found = []
        for char in text:
            if char in self.INVISIBLE_CHARS:
                invisible_found.append(char)

        if invisible_found:
            findings.append(
                f"Invisible characters detected: {len(invisible_found)} characters "
                f"({', '.join(f'U+{ord(c):04X}' for c in invisible_found[:5])})"
            )

        # Check for mixed scripts (potential homoglyph attack)
        scripts: set[str] = set()
        for char in text:
            if char.isalpha():
                try:
                    script = unicodedata.name(char, "").split()[0]
                    scripts.add(script)
                except ValueError:
                    pass

        if len(scripts) > 2:
            findings.append(f"Mixed Unicode scripts detected: {', '.join(sorted(scripts))}")

        # Check for right-to-left override characters
        rtl_overrides = [c for c in text if unicodedata.bidirectional(c) in ("RLO", "RLE", "RLI")]
        if rtl_overrides:
            findings.append(f"Right-to-left override characters detected: {len(rtl_overrides)}")

        return findings

    def normalize_text(self, text: str) -> str:
        """Normalize text by replacing homoglyphs and removing invisible chars."""
        normalized = []
        for char in text:
            if char in self.INVISIBLE_CHARS:
                continue
            elif char in self.HOMOGLYPH_MAP:
                normalized.append(self.HOMOGLYPH_MAP[char])
            else:
                normalized.append(char)
        return "".join(normalized)

    def decode_and_scan(self, text: str) -> list[DecodedContent]:
        """Decode all detected encoded content in text."""
        results: list[DecodedContent] = []

        # Scan for base64
        results.extend(self.detect_base64(text))

        # Scan for ROT13
        results.extend(self.detect_rot13(text))

        # Check for homoglyph-normalized version
        normalized = self.normalize_text(text)
        if normalized != text:
            results.append(
                DecodedContent(
                    original_text=text[:100],
                    decoded_text=normalized[:100],
                    encoding_type="unicode_normalization",
                )
            )

        return results
