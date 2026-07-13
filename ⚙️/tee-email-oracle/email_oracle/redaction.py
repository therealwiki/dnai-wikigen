"""Small redaction helpers for oracle logs and bounded errors."""

from __future__ import annotations

import hashlib
import re


_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted-email>"),
    (re.compile(r"(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"(ORACLE_RUNTIME_AUTH_TOKEN\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r'("(?:pin|otp|password)"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\1<redacted>\2"),
    (re.compile(r"((?:pin|otp|password)\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
)


def redact_text(value: object) -> str:
    """Return text with OTP, password, and bearer material removed."""
    text = str(value)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def hash_text(value: str) -> str:
    """Return a stable public hash for correlating secret-adjacent log values."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
