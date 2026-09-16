"""Thresholdout gate: DP-noised reusable-holdout access for private reward.

The second classical overfitting defense (Dwork, Feldman, Hardt, Pitassi,
Reingold & Roth, "Preserving Statistical Validity in Adaptive Data Analysis",
2015), complementing the Ladder (`ladder_release.py`). Where the Ladder bounds
overfitting by quantization, Thresholdout bounds it by *charging a differential-
privacy budget only when a candidate diverges from what the optimizer already
knows* — so a fixed sealed holdout answers ~ε-cheaply as long as candidates track
the training statistic, and the per-record leakage budget composes with the query
budget into one stated bound (`total leakage ≤ ε × holdout accesses`).

Band-preserving adaptation for this substrate: the optimizer has effectively been
probing the *reward partition*, so its statistic there is "already known" and can
be re-released for free. A *fresh holdout partition* statistic is consulted only
when the candidate's holdout and reward statistics differ by more than a
noisy threshold — the sign of overfitting — and only then is DP budget spent. The
DP noise gates *which partition's band to release* and perturbs the released value
BEFORE it is quantized to a coarse band, so **no un-noised real ever egresses**:
the public surface is a bounded band index plus minimal budget status. Exact
holdout-access accounting and the secret-dependent branch decision remain
TEE-internal. When the budget is exhausted the gate fails closed (no band).

The gate composes with the shared `DpAccountant` (basic composition), so a
Thresholdout run's privacy ledger is the same `(ε, δ)` accounting the rest of the
system already attests. Noise is injectable for deterministic tests; the default
draws Laplace noise from `os.urandom`.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Callable

from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode


class ThresholdoutError(ValueError):
    """Raised on a malformed Thresholdout policy or query."""


def _default_laplace(scale: float) -> float:
    """Draw Laplace(0, scale) noise from OS entropy (inverse-CDF)."""
    if scale <= 0:
        return 0.0
    # Uniform u in (-0.5, 0.5) from 8 bytes of entropy.
    raw = int.from_bytes(os.urandom(8), "big") / float(1 << 64)  # [0, 1)
    u = raw - 0.5
    # Laplace inverse CDF: -b * sign(u) * ln(1 - 2|u|).
    magnitude = 1.0 - 2.0 * abs(u)
    if magnitude <= 0:
        magnitude = 1e-12
    return -scale * math.copysign(1.0, u) * math.log(magnitude)


@dataclass(frozen=True)
class ThresholdoutPolicy:
    """Thresholdout configuration. All fields are public DP parameters."""

    tolerance: float = 0.1          # T: allowed |holdout - reward| before it "diverges"
    noise_scale: float = 0.05       # Laplace scale for the threshold + answer noise
    epsilon_per_access: float = 0.5  # ε charged per holdout access
    step_denominator: int = 20       # released band grid (1/D), like the Ladder

    def __post_init__(self) -> None:
        if not (self.tolerance >= 0):
            raise ThresholdoutError("tolerance must be >= 0")
        if not (self.noise_scale >= 0):
            raise ThresholdoutError("noise_scale must be >= 0")
        if not (self.epsilon_per_access > 0):
            raise ThresholdoutError("epsilon_per_access must be > 0")
        if not isinstance(self.step_denominator, int) or isinstance(self.step_denominator, bool):
            raise ThresholdoutError("step_denominator must be an int")
        if self.step_denominator < 1:
            raise ThresholdoutError("step_denominator must be >= 1")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "tolerance": self.tolerance,
            "noise_scale": self.noise_scale,
            "epsilon_per_access": self.epsilon_per_access,
            "step_denominator": self.step_denominator,
        }


@dataclass(frozen=True)
class ThresholdoutRelease:
    """Bounded result of one Thresholdout query.

    ``released_step_index`` over ``step_denominator`` is the coarse released band
    (``-1`` when the budget is exhausted and nothing is released). The dataclass
    retains exact ``used_holdout`` / ``holdout_access_count`` for internal
    accounting. ``to_public_dict`` deliberately omits both: revealing that branch
    per query lets an adaptive caller learn whether its private-holdout gap crossed
    the noisy threshold.
    """

    query_index: int
    used_holdout: bool
    released_step_index: int
    step_denominator: int
    holdout_access_count: int
    budget_exhausted: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "query_index": self.query_index,
            "released_step_index": self.released_step_index,
            "step_denominator": self.step_denominator,
            "budget_status": "exhausted" if self.budget_exhausted else "available",
            "has_release": self.released_step_index >= 0,
        }


class ThresholdoutGate:
    """Stateful DP-noised reusable-holdout gate over reward/holdout statistics."""

    def __init__(
        self,
        accountant: DpAccountant,
        policy: ThresholdoutPolicy | None = None,
        *,
        noise_fn: Callable[[float], float] | None = None,
    ) -> None:
        if accountant.mode != PrivacyMode.DP:
            raise ThresholdoutError("Thresholdout requires a DP-mode accountant")
        self._accountant = accountant
        self.policy = policy or ThresholdoutPolicy()
        self._noise = noise_fn or _default_laplace
        self._query_count = 0
        self._holdout_access_count = 0

    @property
    def query_count(self) -> int:
        return self._query_count

    @property
    def holdout_access_count(self) -> int:
        return self._holdout_access_count

    def _quantize(self, value: float) -> int:
        idx = int(max(0.0, min(1.0, value)) * self.policy.step_denominator + 0.5)
        return max(0, min(self.policy.step_denominator, idx))

    def query(self, reward_stat: float, holdout_stat: float) -> ThresholdoutRelease:
        """Answer one query over a candidate's reward-partition and holdout stats.

        Both statistics are internal floats in [0, 1] (higher is better) and never
        egress raw. Returns a bounded band-index release.
        """

        for name, value in (("reward_stat", reward_stat), ("holdout_stat", holdout_stat)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ThresholdoutError(f"{name} must be a real number in [0, 1]")
            if not (0.0 <= float(value) <= 1.0):
                raise ThresholdoutError(f"{name} must be in [0, 1]")

        self._query_count += 1
        reward_stat = float(reward_stat)
        holdout_stat = float(holdout_stat)

        gap = abs(holdout_stat - reward_stat)
        threshold = self.policy.tolerance + self._noise(self.policy.noise_scale)
        diverges = gap > threshold

        if not diverges:
            # Candidate tracks the training statistic the optimizer already knows;
            # re-release it for free (no holdout access, no budget spent).
            released_index = self._quantize(reward_stat)
            return ThresholdoutRelease(
                query_index=self._query_count,
                used_holdout=False,
                released_step_index=released_index,
                step_denominator=self.policy.step_denominator,
                holdout_access_count=self._holdout_access_count,
                budget_exhausted=self._accountant.exhausted,
            )

        # Divergence: consulting the fresh holdout costs DP budget. Fail closed if
        # the budget cannot cover this access.
        charge = self._accountant.charge(DpParams(epsilon=self.policy.epsilon_per_access))
        if not charge.allowed:
            return ThresholdoutRelease(
                query_index=self._query_count,
                used_holdout=False,
                released_step_index=-1,  # nothing released
                step_denominator=self.policy.step_denominator,
                holdout_access_count=self._holdout_access_count,
                budget_exhausted=True,
            )

        self._holdout_access_count += 1
        noised = holdout_stat + self._noise(self.policy.noise_scale)
        released_index = self._quantize(noised)
        return ThresholdoutRelease(
            query_index=self._query_count,
            used_holdout=True,
            released_step_index=released_index,
            step_denominator=self.policy.step_denominator,
            holdout_access_count=self._holdout_access_count,
            budget_exhausted=self._accountant.exhausted,
        )

    def public_manifest(self) -> dict[str, Any]:
        """Bounded public status; exact access accounting remains internal."""
        return {
            "variant": "thresholdout",
            "policy": self.policy.to_public_dict(),
            "query_count": self._query_count,
            "budget_status": "exhausted" if self._accountant.exhausted else "available",
        }
