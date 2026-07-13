"""Leaderboard-overfitting defenses: canary candidates + surprising-score review.

An adaptive optimizer that grinds a fixed reward oracle can turn a private score
into a meaningless number, and a leaked or tampered oracle can hand out unearned
bands. Canary candidates are known-answer probes that catch both failure modes:

* a *known-junk* canary (``max_band`` low) must never score above its ceiling —
  if it does, the oracle is leaking or has been gamed;
* a *known-strong* canary (``min_band`` high) must never score below its floor —
  if it does, the oracle has collapsed or been zeroed.

``CanarySentinel.screen`` evaluates the canaries through the environment's own
bounded ``evaluate`` (so it is subject to the same holdout accounting) and returns
a bounded ``CanaryReport`` — per-canary pass/trip/inconclusive, observed band, and
a payload *hash* only. ``assert_clear`` fails closed on any trip.

``flag_surprising_score`` marks a real candidate whose band meets a review
threshold, routing surprising highs to expert review instead of auto-accepting.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from tinker_delegate.private_reward import (
    Candidate,
    Decision,
    PrivateRewardEnvironment,
    RewardBand,
)
from tinker_delegate.private_reward_loop import band_rank
from tinker_delegate.run_metadata_store import stable_hash


class CanaryOutcome(str, Enum):
    PASS = "pass"
    TRIPPED_HIGH = "tripped_high"   # scored above its allowed ceiling
    TRIPPED_LOW = "tripped_low"     # scored below its required floor
    INCONCLUSIVE = "inconclusive"   # no usable band (e.g. budget exhausted)


def _safe_label(value: str) -> str:
    text = str(value).strip().lower()
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789_.:-"
    clipped = "".join(char for char in text[:48] if char in allowed)
    return clipped or "canary"


@dataclass(frozen=True)
class CanaryCandidate:
    """A known-answer probe whose observed band must stay within [min, max]."""

    payload: bytes
    label: str = "canary"
    min_band: RewardBand = RewardBand.WITHHELD
    max_band: RewardBand = RewardBand.EXCEPTIONAL

    def __post_init__(self) -> None:
        if band_rank(self.min_band) > band_rank(self.max_band):
            raise ValueError("canary min_band must not exceed max_band")

    @property
    def payload_hash(self) -> str:
        return stable_hash(self.payload, prefix="canary_payload")


@dataclass(frozen=True)
class CanaryResult:
    label: str
    outcome: CanaryOutcome
    observed_band: RewardBand
    min_band: RewardBand
    max_band: RewardBand
    payload_hash: str

    @property
    def tripped(self) -> bool:
        return self.outcome in (CanaryOutcome.TRIPPED_HIGH, CanaryOutcome.TRIPPED_LOW)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "outcome": self.outcome.value,
            "observed_band": self.observed_band.value,
            "min_band": self.min_band.value,
            "max_band": self.max_band.value,
            "payload_hash": self.payload_hash,
        }


@dataclass(frozen=True)
class CanaryReport:
    results: tuple[CanaryResult, ...]

    @property
    def clear(self) -> bool:
        """True only if no canary tripped (inconclusive does not clear or trip)."""

        return not any(result.tripped for result in self.results)

    @property
    def tripped_count(self) -> int:
        return sum(1 for result in self.results if result.tripped)

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for result in self.results if result.outcome == CanaryOutcome.INCONCLUSIVE)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "surface": "canary_report",
            "canary_count": len(self.results),
            "clear": self.clear,
            "tripped_count": self.tripped_count,
            "inconclusive_count": self.inconclusive_count,
            "results": [result.to_public_dict() for result in self.results],
            "raw_secret_egress": False,
        }


class CanaryTripped(Exception):
    """Raised when a canary scores outside its allowed band (fail-closed)."""


class CanarySentinel:
    """Screen an environment's reward oracle with known-answer canaries."""

    def __init__(self, canaries: tuple[CanaryCandidate, ...] | list[CanaryCandidate]) -> None:
        self._canaries = tuple(canaries)

    def screen(self, environment: PrivateRewardEnvironment) -> CanaryReport:
        results = [self._screen_one(environment, canary) for canary in self._canaries]
        return CanaryReport(tuple(results))

    def assert_clear(self, environment: PrivateRewardEnvironment) -> CanaryReport:
        report = self.screen(environment)
        if not report.clear:
            raise CanaryTripped(
                f"canary screen tripped: {report.tripped_count} of {len(report.results)}"
            )
        return report

    def _screen_one(
        self, environment: PrivateRewardEnvironment, canary: CanaryCandidate
    ) -> CanaryResult:
        feedback = environment.evaluate(Candidate(payload=canary.payload))
        band = feedback.reward_band
        # Budget exhaustion (or any withheld band) yields no usable observation.
        if feedback.decision == Decision.BUDGET_EXHAUSTED or band == RewardBand.WITHHELD:
            outcome = CanaryOutcome.INCONCLUSIVE
        elif band_rank(band) > band_rank(canary.max_band):
            outcome = CanaryOutcome.TRIPPED_HIGH
        elif band_rank(band) < band_rank(canary.min_band):
            outcome = CanaryOutcome.TRIPPED_LOW
        else:
            outcome = CanaryOutcome.PASS
        return CanaryResult(
            label=_safe_label(canary.label),
            outcome=outcome,
            observed_band=band,
            min_band=canary.min_band,
            max_band=canary.max_band,
            payload_hash=canary.payload_hash,
        )


def flag_surprising_score(
    band: RewardBand,
    *,
    review_threshold: RewardBand = RewardBand.HIGH,
) -> bool:
    """True if ``band`` meets/exceeds the review threshold (route to expert review).

    A surprising high score should not auto-settle; the caller routes flagged
    results to a human/biosecurity reviewer instead of accepting on the band
    alone.
    """

    return band_rank(band) >= band_rank(review_threshold) and band != RewardBand.WITHHELD
