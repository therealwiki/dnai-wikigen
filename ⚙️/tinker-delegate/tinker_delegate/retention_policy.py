"""Per-room data-retention policy for sealed diligence-room material.

Each room declares what happens to its sealed artifact/keys after a deal settles:

* ``immediate`` — destroy as soon as the deal resolves.
* ``time_boxed`` — retain (sealed) for a bounded window, then destroy on expiry.
* ``post_settlement_archive`` — keep an encrypted archive under a named key.

`evaluate_retention` turns a policy + the settlement time + now into a bounded,
fail-closed decision: destroy now, retain until a deadline, or keep an encrypted
archive. Fail-closed choices favor destruction — an unknown mode, a non-positive
retention window, or a missing archive key all resolve to ``destroy_now`` rather
than leaving unsealed data around. The decision composes with
`destruction_record`: this says *when* to destroy; that proves it *happened*.

Outputs are bounded (mode, action, deadline, booleans, policy hash); no raw data.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any


class RetentionMode(str, Enum):
    IMMEDIATE = "immediate"
    TIME_BOXED = "time_boxed"
    POST_SETTLEMENT_ARCHIVE = "post_settlement_archive"


class RetentionAction(str, Enum):
    DESTROY_NOW = "destroy_now"
    RETAIN_SEALED = "retain_sealed"
    ARCHIVE_ENCRYPTED = "archive_encrypted"


class RetentionError(ValueError):
    """Raised on a malformed retention policy."""


@dataclass(frozen=True)
class RetentionPolicy:
    mode: RetentionMode
    retention_seconds: int = 0
    archive_key_ref: str = ""

    def __post_init__(self) -> None:
        if self.retention_seconds < 0:
            raise RetentionError("retention_seconds must be non-negative")

    def policy_hash(self) -> str:
        return _sha256_json(
            {
                "mode": self.mode.value,
                "retention_seconds": self.retention_seconds,
                # Only whether an archive key is configured, never the key ref.
                "archive_key_configured": bool(self.archive_key_ref),
            }
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "retention_seconds": self.retention_seconds,
            "archive_key_configured": bool(self.archive_key_ref),
            "policy_hash": self.policy_hash(),
        }


@dataclass(frozen=True)
class RetentionDecision:
    mode: str
    action: RetentionAction
    retain_until: int
    expired: bool
    reason_code: str
    policy_hash: str
    raw_secret_egress: bool = False

    @property
    def must_destroy(self) -> bool:
        return self.action == RetentionAction.DESTROY_NOW

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "retention_decision",
            "mode": self.mode,
            "action": self.action.value,
            "retain_until": self.retain_until,
            "expired": self.expired,
            "reason_code": self.reason_code,
            "policy_hash": self.policy_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def evaluate_retention(policy: RetentionPolicy, *, settled_at: int, now: int) -> RetentionDecision:
    """Decide the fail-closed retention action for a settled deal."""
    policy_hash = policy.policy_hash()

    def decide(action: RetentionAction, reason: str, *, retain_until: int = 0, expired: bool = False) -> RetentionDecision:
        return RetentionDecision(
            mode=policy.mode.value,
            action=action,
            retain_until=retain_until,
            expired=expired,
            reason_code=reason,
            policy_hash=policy_hash,
        )

    if policy.mode == RetentionMode.IMMEDIATE:
        return decide(RetentionAction.DESTROY_NOW, "immediate_destruction")

    if policy.mode == RetentionMode.TIME_BOXED:
        if policy.retention_seconds <= 0:
            # No real window -> fail closed to immediate destruction.
            return decide(RetentionAction.DESTROY_NOW, "time_boxed_zero_window_fail_closed")
        retain_until = int(settled_at) + int(policy.retention_seconds)
        if int(now) >= retain_until:
            return decide(RetentionAction.DESTROY_NOW, "retention_window_expired", retain_until=retain_until, expired=True)
        return decide(RetentionAction.RETAIN_SEALED, "within_retention_window", retain_until=retain_until)

    if policy.mode == RetentionMode.POST_SETTLEMENT_ARCHIVE:
        if not policy.archive_key_ref:
            # Cannot archive safely without a key -> fail closed to destruction.
            return decide(RetentionAction.DESTROY_NOW, "archive_key_missing_fail_closed")
        return decide(RetentionAction.ARCHIVE_ENCRYPTED, "post_settlement_encrypted_archive")

    # Unknown mode -> fail closed.
    return decide(RetentionAction.DESTROY_NOW, "unknown_mode_fail_closed")


def build_retention_policy(settings: Any) -> RetentionPolicy:
    """Build a room retention policy from settings (defaults to immediate)."""
    raw_mode = str(getattr(settings, "retention_mode", "immediate") or "immediate").lower()
    try:
        mode = RetentionMode(raw_mode)
    except ValueError:
        mode = RetentionMode.IMMEDIATE  # unknown mode -> fail closed to immediate
    return RetentionPolicy(
        mode=mode,
        retention_seconds=int(getattr(settings, "retention_seconds", 0) or 0),
        archive_key_ref=str(getattr(settings, "retention_archive_key_ref", "") or ""),
    )


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "0x" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
