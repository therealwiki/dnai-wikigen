"""Fail-closed mailbox retention: minimize how long OTP-bearing email is kept.

The TEE email oracle's mailbox receives OTPs and confirmation links. Those
messages are secret-bearing, so they must not linger: once a message has been
consumed (its structured token extracted, see `inbound_email_safety`), the raw
message is deleted — or, only when audit retention is explicitly enabled, redacted
to bounded metadata and kept for a bounded window. A message that was never
consumed expires after a short window rather than being hoarded.

Pure policy: the caller supplies whether a message was consumed, its receipt
time, and the current time (no wall clock here, so it stays deterministic). The
disposition is bounded — delete / redact-for-audit / retain — and never echoes
message content.

Decision:
  consumed + audit off              -> DELETE
  consumed + audit on, within TTL   -> REDACT_FOR_AUDIT (strip body, keep hashes)
  consumed + audit on, past TTL     -> DELETE
  not consumed, within window       -> RETAIN (still usable)
  not consumed, past window         -> DELETE (stale secret-bearing mail expires)
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class MessageDisposition(str, Enum):
    DELETE = "delete"
    REDACT_FOR_AUDIT = "redact_for_audit"
    RETAIN = "retain"


class MailboxRetentionError(ValueError):
    """Raised when a retention policy is misconfigured."""


@dataclass(frozen=True)
class MailboxRetentionPolicy:
    audit_retention_enabled: bool = False       # keep a redacted record for audit
    max_unused_retention_seconds: int = 3600     # unconsumed OTP mail expires
    audit_retention_seconds: int = 30 * 86400    # redacted audit-record TTL

    def __post_init__(self) -> None:
        for name in ("max_unused_retention_seconds", "audit_retention_seconds"):
            if getattr(self, name) < 0:
                raise MailboxRetentionError(f"{name} must be >= 0")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "audit_retention_enabled": self.audit_retention_enabled,
            "max_unused_retention_seconds": self.max_unused_retention_seconds,
            "audit_retention_seconds": self.audit_retention_seconds,
        }


@dataclass(frozen=True)
class MessageRetentionDecision:
    disposition: MessageDisposition
    reason_code: str

    @property
    def deletes(self) -> bool:
        return self.disposition == MessageDisposition.DELETE

    @property
    def keeps_raw_body(self) -> bool:
        # Only a retained (not-yet-consumed) message keeps its raw body; a
        # redacted audit record does not.
        return self.disposition == MessageDisposition.RETAIN

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "message_retention_decision",
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "deletes": self.deletes,
            "keeps_raw_body": self.keeps_raw_body,
            "raw_secret_egress": False,
        }


def decide_message_disposition(
    *,
    consumed: bool,
    received_at: int,
    now: int,
    policy: MailboxRetentionPolicy,
) -> MessageRetentionDecision:
    """Decide what to do with one mailbox message, fail-closed toward deletion."""

    # A non-monotonic clock must never keep a secret alive by accident: clamp a
    # negative age to 0 so the youngest interpretation applies to the RETAIN
    # branch, while consumed messages are handled by the consumed branch anyway.
    age = max(0, now - received_at)

    if consumed:
        if not policy.audit_retention_enabled:
            return MessageRetentionDecision(MessageDisposition.DELETE, "consumed_no_audit")
        if age >= policy.audit_retention_seconds:
            return MessageRetentionDecision(MessageDisposition.DELETE, "audit_ttl_expired")
        return MessageRetentionDecision(
            MessageDisposition.REDACT_FOR_AUDIT, "consumed_audit_redact"
        )

    # Not consumed: keep it briefly so it can still be used, then expire it.
    if age >= policy.max_unused_retention_seconds:
        return MessageRetentionDecision(MessageDisposition.DELETE, "unconsumed_expired")
    return MessageRetentionDecision(MessageDisposition.RETAIN, "unconsumed_within_window")
