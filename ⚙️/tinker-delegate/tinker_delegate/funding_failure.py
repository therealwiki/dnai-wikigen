"""Fail-closed classification of funding/top-up failure modes.

When an automated funding attempt fails, the delegate must react from an explicit
policy, not ad-hoc retries — repeated blind retries can double-charge a card, and
some failures (bot checks, 3-D Secure) must NEVER be auto-solved (CLAUDE.md:
never bypass CAPTCHAs/bot-detection; entering card/3DS auth is a human action).

`classify_funding_failure` maps a bounded failure signal to a disposition:

  - RATE_LIMIT / BILLING_OUTAGE      -> retry with backoff (transient), until a
                                        max attempt count, then escalate.
  - CARD_DECLINED / INSUFFICIENT_FUNDS -> escalate to a human AND disable
                                        auto-reload (the funding source is bad;
                                        stop auto-charging).
  - THREE_DS_CHALLENGE               -> escalate (interactive auth; never
                                        auto-complete), do not silently retry.
  - BOT_CHECK                        -> abort AND disable auto-reload (never
                                        auto-solve bot-detection).
  - PARTIAL_TOPUP                    -> accept the partial and re-evaluate.
  - UNKNOWN / anything else          -> abort and disable (fail closed).

Pure policy; bounded output (kind/disposition/booleans/reason). The
`disable_auto_reload` flag is designed to flip `topup_policy.TopUpPolicy`'s
`emergency_disabled` kill switch.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Any


class FundingFailureKind(str, Enum):
    CARD_DECLINED = "card_declined"
    THREE_DS_CHALLENGE = "three_ds_challenge"
    BOT_CHECK = "bot_check"
    RATE_LIMIT = "rate_limit"
    INSUFFICIENT_FUNDS = "insufficient_funds"
    BILLING_OUTAGE = "billing_outage"
    PARTIAL_TOPUP = "partial_topup"
    UNKNOWN = "unknown"


class FailureDisposition(str, Enum):
    RETRY_BACKOFF = "retry_backoff"
    ESCALATE_HUMAN = "escalate_human"
    ABORT = "abort"
    ACCEPT_PARTIAL = "accept_partial"


class FundingFailureError(ValueError):
    """Raised when a failure signal cannot be classified (bad inputs)."""


@dataclass(frozen=True)
class FundingFailureAssessment:
    kind: FundingFailureKind
    disposition: FailureDisposition
    retryable: bool
    disable_auto_reload: bool
    reason_code: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "disposition": self.disposition.value,
            "retryable": self.retryable,
            "disable_auto_reload": self.disable_auto_reload,
            "reason_code": self.reason_code,
            "raw_secret_egress": False,
        }


# Base disposition per failure kind (before retry-exhaustion is applied).
_TABLE: dict[FundingFailureKind, tuple[FailureDisposition, bool, bool]] = {
    # kind: (disposition, retryable, disable_auto_reload)
    FundingFailureKind.RATE_LIMIT: (FailureDisposition.RETRY_BACKOFF, True, False),
    FundingFailureKind.BILLING_OUTAGE: (FailureDisposition.RETRY_BACKOFF, True, False),
    FundingFailureKind.CARD_DECLINED: (FailureDisposition.ESCALATE_HUMAN, False, True),
    FundingFailureKind.INSUFFICIENT_FUNDS: (FailureDisposition.ESCALATE_HUMAN, False, True),
    FundingFailureKind.THREE_DS_CHALLENGE: (FailureDisposition.ESCALATE_HUMAN, False, False),
    FundingFailureKind.BOT_CHECK: (FailureDisposition.ABORT, False, True),
    FundingFailureKind.PARTIAL_TOPUP: (FailureDisposition.ACCEPT_PARTIAL, False, False),
    FundingFailureKind.UNKNOWN: (FailureDisposition.ABORT, False, True),
}


def classify_funding_failure(
    kind: FundingFailureKind | str,
    *,
    attempt: int = 1,
    max_attempts: int = 3,
) -> FundingFailureAssessment:
    """Classify a funding failure into a bounded, fail-closed disposition.

    Unknown/unrecognized kinds fail closed to ABORT + disable_auto_reload. A
    retryable kind whose `attempt` has reached `max_attempts` stops retrying and
    escalates to a human (and disables auto-reload), so a transient failure can't
    loop forever and keep re-charging.
    """
    if attempt < 1 or max_attempts < 1:
        raise FundingFailureError("attempt and max_attempts must be >= 1")
    try:
        resolved = FundingFailureKind(kind)
    except ValueError:
        resolved = FundingFailureKind.UNKNOWN

    disposition, retryable, disable = _TABLE[resolved]
    assessment = FundingFailureAssessment(
        kind=resolved,
        disposition=disposition,
        retryable=retryable,
        disable_auto_reload=disable,
        reason_code=f"funding_failure_{resolved.value}",
    )

    if retryable and attempt >= max_attempts:
        # Retries are exhausted: stop looping, escalate, and disable auto-reload
        # so the same charge is not attempted again automatically.
        return replace(
            assessment,
            disposition=FailureDisposition.ESCALATE_HUMAN,
            retryable=False,
            disable_auto_reload=True,
            reason_code=f"funding_failure_{resolved.value}_retries_exhausted",
        )
    return assessment
