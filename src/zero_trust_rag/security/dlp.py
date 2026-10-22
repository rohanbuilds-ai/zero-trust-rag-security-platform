"""Data Loss Prevention (DLP) engine for redacting sensitive values before egress."""

import re
from typing import Tuple, Dict, Any, List, Union, Optional

from zero_trust_rag.security.canonicalization import canonicalize_for_dlp

def luhn_checksum_valid(number_str: str) -> bool:
    """Validate a numeric string using the Luhn checksum algorithm."""
    digits = [int(c) for c in number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False

    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0

class DataLossPreventionEngine:
    """
    Local deterministic DLP engine.
    Scans and redacts Social Security numbers, Luhn-valid credit card numbers,
    AWS API keys, JWT tokens, and synthetic test secrets.
    """

    def __init__(self):
        # US SSN Pattern
        self._ssn_pattern = re.compile(
            r"\b(?!000|666|9\d{2})(\d{3})[-\s](?!00)(\d{2})[-\s](?!0000)(\d{4})\b"
        )

        # Potential Credit Card Candidate Pattern (13 to 19 digits with optional hyphens/spaces)
        self._cc_candidate_pattern = re.compile(
            r"\b(?:\d[ -]*?){13,19}\b"
        )

        # AWS Access Key Pattern (AKIA followed by 16 alphanumeric characters)
        self._aws_key_pattern = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

        # JWT Bearer Token Pattern
        self._jwt_pattern = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

        # Synthetic Test Secret Patterns
        self._synthetic_secret_pattern = re.compile(
            r"\b(TEST_SECRET_[A-Z0-9_]+|sk_live_[0-9a-zA-Z]{24,32}|ghp_[0-9a-zA-Z]{36})\b"
        )

        # Generic API Key Assignment Pattern: e.g. api_key: "abc123xyz..."
        self._generic_key_pattern = re.compile(
            r"(?i)\b(api[_-]?key|secret[_-]?key|auth[_-]?token|access[_-]?token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{20,64})['\"]"
        )

    def redact_text(self, text: Optional[str]) -> Tuple[str, int, Dict[str, int]]:
        """
        Redact sensitive tokens in text.
        Returns (sanitized_text, total_redactions, counts_by_category).
        Fails closed on internal errors.
        """
        if not text or not isinstance(text, str):
            return text or "", 0, {}

        try:
            counts: Dict[str, int] = {}
            # Canonicalize text prior to pattern matching: normalize Unicode and strip invisible characters
            sanitized = canonicalize_for_dlp(text)

            # 1. Redact SSNs
            def ssn_replacer(match):
                counts["SSN"] = counts.get("SSN", 0) + 1
                return "[REDACTED_SSN]"
            sanitized = self._ssn_pattern.sub(ssn_replacer, sanitized)

            # 2. Redact Credit Cards (strictly Luhn-valid)
            def cc_replacer(match):
                raw_match = match.group(0)
                cleaned = re.sub(r"[-\s]", "", raw_match)
                if 13 <= len(cleaned) <= 19 and luhn_checksum_valid(cleaned):
                    counts["CREDIT_CARD"] = counts.get("CREDIT_CARD", 0) + 1
                    return "[REDACTED_CREDIT_CARD]"
                return raw_match
            sanitized = self._cc_candidate_pattern.sub(cc_replacer, sanitized)

            # 3. Redact AWS API Keys
            def aws_replacer(match):
                counts["API_KEY"] = counts.get("API_KEY", 0) + 1
                return "[REDACTED_API_KEY]"
            sanitized = self._aws_key_pattern.sub(aws_replacer, sanitized)

            # 4. Redact JWT Bearer Tokens
            def jwt_replacer(match):
                counts["BEARER_TOKEN"] = counts.get("BEARER_TOKEN", 0) + 1
                return "[REDACTED_BEARER_TOKEN]"
            sanitized = self._jwt_pattern.sub(jwt_replacer, sanitized)

            # 5. Redact Synthetic Test Secrets
            def synthetic_replacer(match):
                counts["TEST_SECRET"] = counts.get("TEST_SECRET", 0) + 1
                return "[REDACTED_SECRET]"
            sanitized = self._synthetic_secret_pattern.sub(synthetic_replacer, sanitized)

            # 6. Redact Generic API Key Assignments
            def generic_key_replacer(match):
                prefix = match.group(1)
                counts["API_KEY"] = counts.get("API_KEY", 0) + 1
                return f"{prefix}: \"[REDACTED_API_KEY]\""
            sanitized = self._generic_key_pattern.sub(generic_key_replacer, sanitized)

            total = sum(counts.values())
            return sanitized, total, counts

        except Exception:
            # Fail closed: never return raw uninspected text if an exception occurs
            return "[DLP_INSPECTION_FAILED]", 1, {"DLP_ERROR": 1}

    def inspect_and_redact_object(self, obj: Any) -> Tuple[Any, int, Dict[str, int]]:
        """
        Recursively scan and redact nested dicts, lists, and strings.
        Preserves data structure while scrubbing sensitive values.
        """
        total_redactions = 0
        all_counts: Dict[str, int] = {}

        def _merge_counts(counts: Dict[str, int]):
            nonlocal total_redactions
            for cat, count in counts.items():
                all_counts[cat] = all_counts.get(cat, 0) + count
                total_redactions += count

        def _walk(item: Any) -> Any:
            if isinstance(item, str):
                redacted, count, counts = self.redact_text(item)
                _merge_counts(counts)
                return redacted
            elif isinstance(item, dict):
                return {k: _walk(v) for k, v in item.items()}
            elif isinstance(item, list):
                return [_walk(elem) for elem in item]
            elif isinstance(item, tuple):
                return tuple(_walk(elem) for elem in item)
            elif hasattr(item, "model_dump"):
                # Pydantic v2 model
                data = item.model_dump()
                walked_data = _walk(data)
                return item.__class__(**walked_data)
            return item

        sanitized_obj = _walk(obj)
        return sanitized_obj, total_redactions, all_counts
