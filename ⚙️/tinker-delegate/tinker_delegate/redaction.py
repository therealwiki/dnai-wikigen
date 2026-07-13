"""Small redaction helpers for logs and bounded API errors."""

from __future__ import annotations

import re


_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"tml-[A-Za-z0-9_-]{20,}"), "tml-<redacted>"),
    # OpenAI / OpenRouter-style API keys (the evaluator agent uses
    # OPENROUTER_API_KEY, format `sk-or-v1-...`; also `sk-`, `sk-proj-`). A 20+
    # char sk- token is a credential, not benign text — safe to redact.
    (re.compile(r"sk-[A-Za-z0-9_-]{20,}"), "sk-<redacted>"),
    (re.compile(r"(TINKER_API_KEY\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r"(OPENROUTER_API_KEY\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r'("(?:card_number|number)"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\1<redacted>\2"),
    (re.compile(r"((?:card_number|number)\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r'("(?:cvc|cvv)"\s*:\s*")[^"]+(")', re.IGNORECASE), r"\1<redacted>\2"),
    (re.compile(r"((?:cvc|cvv)\s*=\s*)\S+", re.IGNORECASE), r"\1<redacted>"),
    (re.compile(r'("artifact_hex"\s*:\s*")[0-9a-fA-F]{32,}(")', re.IGNORECASE), r"\1<redacted>\2"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "<redacted-card-number>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "<redacted-email>"),
)


def redact_text(value: object) -> str:
    """Return text with credential, card, and artifact-like material removed."""
    text = str(value)
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text
