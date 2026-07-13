"""Differential-privacy accounting for reward releases over individual-level data.

`bio_validation` already fails closed on individual-level data unless it is
`differential_privacy_marked`. That flag needs substance: if rewards are released
over real individual-level data, the environment must *track* a cumulative
(epsilon, delta) privacy budget across releases and refuse further releases once
it is spent — or the environment must be explicitly marked NON-DP and
not-PHI-safe, so nothing pretends the releases are private when they are not.

This module is that accountant. It uses basic (sequential) composition — the
simplest sound bound: cumulative epsilon and delta are the sums of the per-release
costs. Advanced composition would give a tighter bound; basic composition never
*under*-counts, so it is the safe default.

Privacy parameters (epsilon/delta) are public DP configuration, not reward values
or raw data, so the accounting record legitimately carries them as floats — it is
a privacy-accounting surface, not the bounded reward-egress channel. It never
contains raw records or exact reward values.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class PrivacyMode(str, Enum):
    DP = "differential_privacy"           # tracked (epsilon, delta) budget
    NON_DP = "non_dp_not_phi_safe"        # explicitly not private; not PHI-safe


class DpError(ValueError):
    """Raised when DP parameters or a budget are invalid."""


def _check_params(epsilon: float, delta: float, *, allow_zero: bool) -> tuple[float, float]:
    eps = float(epsilon)
    dlt = float(delta)
    low_ok = eps >= 0 if allow_zero else eps > 0
    if not low_ok:
        raise DpError("epsilon must be positive" if not allow_zero else "epsilon must be non-negative")
    if not 0.0 <= dlt < 1.0:
        raise DpError("delta must be in [0, 1)")
    return eps, dlt


@dataclass(frozen=True)
class DpParams:
    """The (epsilon, delta) cost of a single reward release."""

    epsilon: float
    delta: float = 0.0

    def __post_init__(self) -> None:
        _check_params(self.epsilon, self.delta, allow_zero=False)


@dataclass(frozen=True)
class DpChargeResult:
    """Bounded outcome of attempting to charge one release to the budget."""

    allowed: bool
    mode: PrivacyMode
    phi_safe: bool
    spent_epsilon: float
    spent_delta: float
    max_epsilon: float
    max_delta: float
    query_count: int
    exhausted: bool
    reason_code: str

    @property
    def remaining_epsilon(self) -> float:
        return max(0.0, self.max_epsilon - self.spent_epsilon)

    @property
    def remaining_delta(self) -> float:
        return max(0.0, self.max_delta - self.spent_delta)

    def to_public_dict(self) -> dict[str, Any]:
        # Round to kill float-subtraction noise (e.g. 1.0-0.8 = 0.199999...96),
        # which would otherwise render as a long-digit run in the bounded output.
        def _r(x: float) -> float:
            return round(float(x), 9)

        return {
            "surface": "dp_accounting",
            "mode": self.mode.value,
            "phi_safe": self.phi_safe,
            "allowed": self.allowed,
            "exhausted": self.exhausted,
            "reason_code": self.reason_code,
            "spent_epsilon": _r(self.spent_epsilon),
            "spent_delta": _r(self.spent_delta),
            "max_epsilon": _r(self.max_epsilon),
            "max_delta": _r(self.max_delta),
            "remaining_epsilon": _r(self.remaining_epsilon),
            "remaining_delta": _r(self.remaining_delta),
            "query_count": self.query_count,
            "raw_secret_egress": False,
        }


class DpAccountant:
    """Track a cumulative (epsilon, delta) budget across reward releases.

    In ``DP`` mode, ``charge`` admits a release only if basic composition keeps
    the cumulative epsilon and delta within budget, and mutates state only when it
    admits (fail-closed: an over-budget release is denied and changes nothing). In
    ``NON_DP`` mode there is no privacy claim — releases are always admitted but
    every record is stamped ``phi_safe=False`` so no caller mistakes them for
    private.
    """

    def __init__(
        self,
        mode: PrivacyMode = PrivacyMode.NON_DP,
        *,
        max_epsilon: float = 0.0,
        max_delta: float = 0.0,
    ) -> None:
        if mode == PrivacyMode.DP:
            _check_params(max_epsilon, max_delta, allow_zero=True)
            if max_epsilon <= 0:
                raise DpError("DP mode requires a positive max_epsilon budget")
        self._mode = mode
        self._max_epsilon = float(max_epsilon)
        self._max_delta = float(max_delta)
        self._spent_epsilon = 0.0
        self._spent_delta = 0.0
        self._query_count = 0

    @property
    def mode(self) -> PrivacyMode:
        return self._mode

    @property
    def phi_safe(self) -> bool:
        # Only a DP-tracked environment can claim PHI-safety over individual data.
        return self._mode == PrivacyMode.DP

    @property
    def spent_epsilon(self) -> float:
        return self._spent_epsilon

    @property
    def exhausted(self) -> bool:
        if self._mode != PrivacyMode.DP:
            return False
        # Epsilon is the binding global budget: a delta=0 release (allowed by
        # DpParams) always fits while epsilon has headroom, so pure-epsilon DP
        # (max_delta=0) must NOT read as exhausted from the delta dimension.
        # A delta cap that is spent still leaves delta=0 releases admissible;
        # per-charge delta feasibility is enforced by `would_exceed`.
        if self._spent_epsilon >= self._max_epsilon:
            return True
        # Only treat delta as exhausting when it has a positive budget that is
        # fully consumed AND no epsilon-only headroom remains — but since epsilon
        # headroom exists here, a delta=0 release remains admissible.
        return False

    def would_exceed(self, params: DpParams) -> bool:
        if self._mode != PrivacyMode.DP:
            return False
        return (
            self._spent_epsilon + params.epsilon > self._max_epsilon
            or self._spent_delta + params.delta > self._max_delta
        )

    def charge(self, params: DpParams) -> DpChargeResult:
        """Attempt to charge one release; fail-closed if it would exceed budget."""

        if self._mode == PrivacyMode.NON_DP:
            # No privacy budget; admit but never claim PHI-safety.
            self._query_count += 1
            return self._result(allowed=True, reason_code="non_dp_release")

        if self.would_exceed(params):
            # Deny without mutating state.
            return self._result(allowed=False, reason_code="dp_budget_exhausted")

        self._spent_epsilon += params.epsilon
        self._spent_delta += params.delta
        self._query_count += 1
        return self._result(allowed=True, reason_code="dp_release_within_budget")

    def snapshot(self) -> DpChargeResult:
        """Current accounting without charging (allowed reflects headroom)."""

        allowed = self._mode != PrivacyMode.DP or not self.exhausted
        reason = "non_dp_release" if self._mode == PrivacyMode.NON_DP else (
            "dp_budget_exhausted" if self.exhausted else "dp_within_budget"
        )
        return self._result(allowed=allowed, reason_code=reason)

    def _result(self, *, allowed: bool, reason_code: str) -> DpChargeResult:
        return DpChargeResult(
            allowed=allowed,
            mode=self._mode,
            phi_safe=self.phi_safe,
            spent_epsilon=self._spent_epsilon,
            spent_delta=self._spent_delta,
            max_epsilon=self._max_epsilon,
            max_delta=self._max_delta,
            query_count=self._query_count,
            exhausted=self.exhausted,
            reason_code=reason_code,
        )
