"""Text canonicalization and normalization utilities for security inspection and DLP."""

import re
import unicodedata
from typing import List

# Target Unicode invisible formatting and zero-width characters:
# \u200b: Zero-width space
# \u200c: Zero-width non-joiner (ZWNJ)
# \u200d: Zero-width joiner (ZWJ)
# \u200e: Left-to-right mark (LRM)
# \u200f: Right-to-left mark (RLM)
# \u2060: Word joiner
# \ufeff: Byte order mark / zero-width no-break space
# \u00ad: Soft hyphen
ZERO_WIDTH_PATTERN = re.compile(r"[\u200b-\u200f\u2060\ufeff\u00ad]")

# SSN boundary with zero-width separator e.g. 123[ZW]45[ZW]6789 -> 123-45-6789
_SSN_ZW_DELIMITER_PATTERN = re.compile(
    r"\b(\d{3})[\u200b-\u200f\u2060\ufeff\u00ad](\d{2})[\u200b-\u200f\u2060\ufeff\u00ad](\d{4})\b"
)


def strip_invisible_characters(text: str) -> str:
    """Remove invisible formatting and zero-width code points from text."""
    if not text:
        return ""
    return ZERO_WIDTH_PATTERN.sub("", text)


def normalize_for_inspection(text: str) -> List[str]:
    """
    Produce canonical text variants for security inspection (prompt injection detection).
    Returns multiple normalized representations to catch both intra-word and
    inter-word zero-width evasion without broad false positives:
      1. Base NFKC normalized text.
      2. Stripped: invisible characters removed (catches intra-token splitting like `ign\\u200bore`).
      3. Spaced: invisible characters replaced by spaces (catches word-boundary evasion like `ignore\\u200ball`).
    """
    if not text:
        return [""]

    # Step 1: Unicode NFKC normalization (unifies full-width Latin, ligatures, etc.)
    nfkc = unicodedata.normalize("NFKC", text)

    # Step 2: Intra-token split defense (strip zero-width characters)
    stripped = ZERO_WIDTH_PATTERN.sub("", nfkc)

    # Step 3: Inter-word boundary evasion defense (replace zero-width characters with whitespace)
    spaced = ZERO_WIDTH_PATTERN.sub(" ", nfkc)

    # Return unique variants
    variants = [nfkc]
    if stripped != nfkc:
        variants.append(stripped)
    if spaced != nfkc and spaced != stripped:
        variants.append(spaced)

    return variants


def canonicalize_for_dlp(text: str) -> str:
    """
    Canonicalize text prior to DLP redaction.
    Normalizes Unicode to NFKC, standardizes zero-width delimited SSNs,
    and strips invisible characters so sensitive patterns cannot be bypassed.
    """
    if not text:
        return ""

    # Step 1: Unicode NFKC normalization
    nfkc = unicodedata.normalize("NFKC", text)

    # Step 2: Normalize any SSNs where zero-width characters were used as delimiters
    standardized = _SSN_ZW_DELIMITER_PATTERN.sub(r"\1-\2-\3", nfkc)

    # Step 3: Strip any remaining zero-width characters (e.g. inside digits, keys, tokens)
    return ZERO_WIDTH_PATTERN.sub("", standardized)
