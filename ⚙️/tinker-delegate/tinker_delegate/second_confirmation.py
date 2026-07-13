"""Second-confirmation channel gate for high-risk actions.

Some actions are too consequential for the delegate to take on its own authority —
a large card top-up, widened data access, a policy bypass. Such an action must be
confirmed OUT OF BAND through an approved channel (a wallet signature, WebAuthn /
passkey assertion, a device-bound session, or a human reviewer) by a party OTHER
than the requester, before it proceeds. Agents may request and evaluate; they may
not self-approve (the non-self-approval invariant).

Pure policy, fail-closed:
  - `requires_confirmation` decides whether an action's value crosses the
    threshold that demands a second confirmation at all;
  - `evaluate_confirmation` authorizes the action only when enough DISTINCT, fresh
    confirmations arrive through APPROVED channels from parties other than the
    requester. A misconfigured requirement (no approved channels) authorizes
    nothing. Only bounded facts egress — counts, channel names, a reason, evidence
    *hashes* — never raw confirmation evidence.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ConfirmationChannel(str, Enum):
    WALLET_SIGNATURE = "wallet_signature"
    WEBAUTHN = "webauthn"
    PASSKEY = "passkey"
    DEVICE_BOUND_SESSION = "device_bound_session"
    HUMAN_REVIEWER = "human_reviewer"


class SecondConfirmationError(ValueError):
    """Raised when a confirmation requirement is misconfigured."""


@dataclass(frozen=True)
class Confirmation:
    """One out-of-band confirmation of a high-risk action."""

    channel: ConfirmationChannel
    confirmer_ref: str
    evidence_hash: str
    issued_at: int


@dataclass(frozen=True)
class ConfirmationRequirement:
    """How a high-risk action must be second-confirmed."""

    approved_channels: frozenset[ConfirmationChannel]
    required_confirmations: int = 1
    allow_self_confirm: bool = False
    max_age_seconds: int = 900

    def __post_init__(self) -> None:
        if self.required_confirmations < 1:
            raise SecondConfirmationError("required_confirmations must be >= 1")
        if self.max_age_seconds < 0:
            raise SecondConfirmationError("max_age_seconds must be >= 0")


@dataclass(frozen=True)
class ConfirmationDecision:
    authorized: bool
    satisfied_count: int
    required_count: int
    channels_used: tuple[str, ...]
    reason_code: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "second_confirmation_decision",
            "authorized": self.authorized,
            "satisfied_count": self.satisfied_count,
            "required_count": self.required_count,
            "channels_used": list(self.channels_used),
            "reason_code": self.reason_code,
            "raw_secret_egress": False,
        }


def requires_confirmation(action_value_wei: int, *, threshold_wei: int) -> bool:
    """True if an action's value is at/above the threshold that demands a second
    confirmation. A zero threshold means every action requires one (fail-safe)."""
    if action_value_wei < 0 or threshold_wei < 0:
        raise SecondConfirmationError("action value and threshold must be >= 0")
    return action_value_wei >= threshold_wei


def evaluate_confirmation(
    *,
    requester_ref: str,
    requirement: ConfirmationRequirement,
    confirmations: tuple[Confirmation, ...],
    now: int,
) -> ConfirmationDecision:
    """Authorize a high-risk action only on enough valid out-of-band confirmations.

    A confirmation counts only if its channel is approved, it is fresh (within
    `max_age_seconds`), and — unless self-confirm is explicitly allowed — the
    confirmer is not the requester. Distinct confirmers are counted once.
    """
    if not isinstance(requester_ref, str) or not requester_ref:
        raise SecondConfirmationError("requester_ref must be a non-empty string")

    seen_confirmers: set[str] = set()
    channels_used: list[str] = []
    for c in confirmations:
        if c.channel not in requirement.approved_channels:
            continue
        if requirement.max_age_seconds >= 0 and now - c.issued_at > requirement.max_age_seconds:
            continue
        if now < c.issued_at:
            # A confirmation from the future is not trusted (clock tampering).
            continue
        if not requirement.allow_self_confirm and c.confirmer_ref == requester_ref:
            continue
        if not c.confirmer_ref or not c.evidence_hash:
            continue
        if c.confirmer_ref in seen_confirmers:
            continue
        seen_confirmers.add(c.confirmer_ref)
        channels_used.append(c.channel.value)

    satisfied = len(seen_confirmers)
    authorized = satisfied >= requirement.required_confirmations
    if authorized:
        reason = "second_confirmation_satisfied"
    elif satisfied == 0:
        reason = "no_valid_confirmation"
    else:
        reason = "insufficient_confirmations"
    return ConfirmationDecision(
        authorized=authorized,
        satisfied_count=satisfied,
        required_count=requirement.required_confirmations,
        channels_used=tuple(sorted(set(channels_used))),
        reason_code=reason,
    )
