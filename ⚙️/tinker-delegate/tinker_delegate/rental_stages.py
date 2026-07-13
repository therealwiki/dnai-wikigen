"""Staged rental states for progressive, consent-gated disclosure.

A diligence-room deal can move a buyer through increasing disclosure tiers, each
with its own reserve, budget cap, bounded result type, and consent requirement:

* ``raw_inspection``  — a bounded score band only (lightest tier).
* ``training``        — a bounded model-utility band from an RLVR/TTT run.
* ``inference``       — a bounded yes/no decision.
* ``full_disclosure`` — the raw artifact itself (heaviest tier).

The state machine is pure and fail-closed:

* Disclosure is *monotonic*: a transition may only move to a strictly higher tier
  (no regression, no re-paying the same tier). Skipping directly to a higher tier
  is allowed only if that tier's own reserve/cap/consent are satisfied.
* Consent comes from the owner via the consent layer, supplied as a boolean — the
  requester can never self-approve it here.
* ``full_disclosure`` (raw artifact) *always* requires consent, regardless of the
  ladder's per-stage flag.
* Missing/unknown stages, below-reserve or over-cap payment, or missing consent
  all DENY.

Outputs are bounded transition records (stages, decision, result type, reason
code); no raw artifact, price internals beyond the caller's amounts, or secrets
leave.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class RentalStage(str, Enum):
    RAW_INSPECTION = "raw_inspection"
    TRAINING = "training"
    INFERENCE = "inference"
    FULL_DISCLOSURE = "full_disclosure"


# Increasing disclosure order.
_STAGE_ORDER: tuple[RentalStage, ...] = (
    RentalStage.RAW_INSPECTION,
    RentalStage.TRAINING,
    RentalStage.INFERENCE,
    RentalStage.FULL_DISCLOSURE,
)


class ResultType(str, Enum):
    SCORE_BAND = "score_band"
    UTILITY_BAND = "utility_band"
    YES_NO = "yes_no"
    ARTIFACT = "artifact"


class TransitionDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"


class RentalStageError(ValueError):
    """Raised when a rental ladder is malformed."""


def _disclosure_level(stage: RentalStage) -> int:
    return _STAGE_ORDER.index(stage)


@dataclass(frozen=True)
class StagePolicy:
    stage: RentalStage
    reserve_wei: int
    cap_wei: int
    result_type: ResultType
    requires_consent: bool

    def __post_init__(self) -> None:
        if self.reserve_wei < 0 or self.cap_wei < 0:
            raise RentalStageError("reserve and cap must be non-negative")
        if self.cap_wei < self.reserve_wei:
            raise RentalStageError("cap must be >= reserve")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage.value,
            "reserve_wei": self.reserve_wei,
            "cap_wei": self.cap_wei,
            "result_type": self.result_type.value,
            "requires_consent": self.requires_consent,
        }


@dataclass(frozen=True)
class RentalLadder:
    policies: tuple[StagePolicy, ...]

    def __post_init__(self) -> None:
        if not self.policies:
            raise RentalStageError("rental ladder must define at least one stage")
        stages = [p.stage for p in self.policies]
        if len(set(stages)) != len(stages):
            raise RentalStageError("rental ladder stages must be unique")
        # Must be listed in strictly increasing disclosure order.
        levels = [_disclosure_level(s) for s in stages]
        if levels != sorted(levels) or len(set(levels)) != len(levels):
            raise RentalStageError("rental ladder stages must be in increasing disclosure order")

    def policy(self, stage: RentalStage) -> StagePolicy | None:
        for p in self.policies:
            if p.stage == stage:
                return p
        return None

    def to_public_dict(self) -> dict[str, Any]:
        return {"stages": [p.to_public_dict() for p in self.policies]}


@dataclass(frozen=True)
class StageTransition:
    from_stage: str
    to_stage: str
    decision: TransitionDecision
    result_type: str
    reason_code: str
    raw_secret_egress: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == TransitionDecision.ALLOWED

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": "rental_stage_transition",
            "from_stage": self.from_stage,
            "to_stage": self.to_stage,
            "decision": self.decision.value,
            "result_type": self.result_type,
            "reason_code": self.reason_code,
            "raw_secret_egress": self.raw_secret_egress,
        }


def advance_stage(
    ladder: RentalLadder,
    *,
    current: RentalStage | None,
    target: RentalStage,
    consent_ok: bool,
    payment_wei: int,
) -> StageTransition:
    """Attempt a fail-closed transition to a higher disclosure tier."""
    from_label = current.value if current is not None else ""

    def deny(reason: str, result_type: str = "") -> StageTransition:
        return StageTransition(
            from_stage=from_label,
            to_stage=target.value,
            decision=TransitionDecision.DENIED,
            result_type=result_type,
            reason_code=reason,
        )

    policy = ladder.policy(target)
    if policy is None:
        return deny("target_stage_not_in_ladder")

    # Monotonic disclosure: strictly higher than current (or first move from none).
    current_level = _disclosure_level(current) if current is not None else -1
    if _disclosure_level(target) <= current_level:
        return deny("no_forward_progress")

    # Consent: owner-supplied; full_disclosure always requires it.
    consent_required = policy.requires_consent or target == RentalStage.FULL_DISCLOSURE
    if consent_required and not consent_ok:
        return deny("consent_required")

    if payment_wei < policy.reserve_wei:
        return deny("payment_below_reserve")
    if payment_wei > policy.cap_wei:
        return deny("payment_above_cap")

    return StageTransition(
        from_stage=from_label,
        to_stage=target.value,
        decision=TransitionDecision.ALLOWED,
        result_type=policy.result_type.value,
        reason_code="stage_advanced",
    )


def default_rental_ladder() -> RentalLadder:
    """A sensible default ladder (amounts in wei; caller sets real economics)."""
    return RentalLadder(
        policies=(
            StagePolicy(
                RentalStage.RAW_INSPECTION,
                reserve_wei=0,
                cap_wei=10**16,  # 0.01 ETH
                result_type=ResultType.SCORE_BAND,
                requires_consent=False,
            ),
            StagePolicy(
                RentalStage.TRAINING,
                reserve_wei=10**16,
                cap_wei=10**17,  # 0.1 ETH
                result_type=ResultType.UTILITY_BAND,
                requires_consent=True,
            ),
            StagePolicy(
                RentalStage.INFERENCE,
                reserve_wei=10**16,
                cap_wei=5 * 10**16,
                result_type=ResultType.YES_NO,
                requires_consent=True,
            ),
            StagePolicy(
                RentalStage.FULL_DISCLOSURE,
                reserve_wei=10**17,
                cap_wei=10**18,  # 1 ETH
                result_type=ResultType.ARTIFACT,
                requires_consent=True,
            ),
        )
    )
