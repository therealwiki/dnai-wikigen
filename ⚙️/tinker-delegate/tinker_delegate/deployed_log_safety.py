"""Bounded scanners for deployed logs and console output.

The scanner is intentionally evidence-oriented: it reports counts, finding
classes, and line hashes only. It never returns log snippets.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any


CARD_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
UNREDACTED_CARD_FIELD_RE = re.compile(
    r"(?i)\b(?:card_number|cardNumber|cardholder_name|cardholderName|raw_card|payment_card)\b"
    r"\s*[:=]\s*(?![\"']?(?:<redacted>|redacted|\*+|none|null|false|true|$))[\"']?[^\"'\s,}]+"
)
UNREDACTED_CVC_FIELD_RE = re.compile(
    r"(?i)\b(?:cvc|cvv|security_code|securityCode)\b"
    r"\s*[:=]\s*(?![\"']?(?:<redacted>|redacted|\*+|none|null|false|true|$))[\"']?\d{3,4}\b"
)
TINKER_API_KEY_RE = re.compile(r"\btml-[A-Za-z0-9_-]{20,}\b")
BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
OTP_FIELD_RE = re.compile(
    r"(?i)\b(?:otp|one_time_code|verification_code|magic_code)\b"
    r"\s*[:=]\s*(?![\"']?(?:<redacted>|redacted|\*+|none|null|false|true|$))[\"']?\d{6,8}\b"
)
PRIVATE_KEY_RE = re.compile(
    r"(?i)\b(?:private_key|secret_key|signer_key)\b"
    r"\s*[:=]\s*(?![\"']?(?:<redacted>|redacted|\*+|none|null|false|true|$))[\"']?"
    r"(?:0x)?[0-9a-f]{64}\b"
)


@dataclass
class LogSafetyFinding:
    kind: str
    line_number: int
    line_hash: str


@dataclass
class LogSafetyScan:
    source_label: str = ""
    line_count: int = 0
    byte_count: int = 0
    findings: list[LogSafetyFinding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_public_dict(self, *, max_hashes_per_kind: int = 20) -> dict[str, Any]:
        counts: dict[str, int] = {}
        hashes: dict[str, list[str]] = {}
        for finding in self.findings:
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
            bucket = hashes.setdefault(finding.kind, [])
            if len(bucket) < max_hashes_per_kind:
                bucket.append(finding.line_hash)
        return {
            "surface": "deployed_log_safety",
            "success": self.ok,
            "source_label": self.source_label,
            "line_count": self.line_count,
            "byte_count_band": _byte_count_band(self.byte_count),
            "finding_count": len(self.findings),
            "finding_counts": counts,
            "finding_line_hashes": hashes,
            "log_snippets_returned": False,
            "raw_secret_egress": False,
        }


def scan_deployed_log_text(text: str, *, source_label: str = "") -> LogSafetyScan:
    scan = LogSafetyScan(source_label=source_label, byte_count=len(text.encode("utf-8")))
    for line_number, line in enumerate(text.splitlines(), start=1):
        scan.line_count += 1
        for kind in _finding_kinds(line):
            scan.findings.append(
                LogSafetyFinding(
                    kind=kind,
                    line_number=line_number,
                    line_hash=_line_hash(line),
                )
            )
    return scan


def _finding_kinds(line: str) -> list[str]:
    kinds: list[str] = []
    if any(_luhn_valid(_digits(candidate.group(0))) for candidate in CARD_CANDIDATE_RE.finditer(line)):
        kinds.append("luhn_card_number")
    if UNREDACTED_CARD_FIELD_RE.search(line):
        kinds.append("unredacted_card_field")
    if UNREDACTED_CVC_FIELD_RE.search(line):
        kinds.append("unredacted_cvc_field")
    if TINKER_API_KEY_RE.search(line):
        kinds.append("tinker_api_key")
    if BEARER_TOKEN_RE.search(line):
        kinds.append("bearer_token")
    if JWT_RE.search(line):
        kinds.append("jwt")
    if OTP_FIELD_RE.search(line):
        kinds.append("otp_field")
    if PRIVATE_KEY_RE.search(line):
        kinds.append("private_key_field")
    return kinds


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def _luhn_valid(value: str) -> bool:
    if not 13 <= len(value) <= 19 or not value.isdigit():
        return False
    total = 0
    parity = len(value) % 2
    for index, char in enumerate(value):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _line_hash(line: str) -> str:
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _byte_count_band(byte_count: int) -> str:
    if byte_count == 0:
        return "0"
    if byte_count < 10_000:
        return "<10KB"
    if byte_count < 100_000:
        return "10KB-100KB"
    if byte_count < 1_000_000:
        return "100KB-1MB"
    return ">=1MB"
