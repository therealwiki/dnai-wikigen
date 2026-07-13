"""Ladder-gated reward release for a reused sealed holdout.

The overfitting axis is separate from the leakage axis: an adaptive optimizer can
grind a *fixed* private holdout into a meaningless number without ever
reconstructing a record. The Ladder mechanism (Blum & Hardt, "The Ladder: A
Reliable Leaderboard for Machine Learning Competitions", ICML 2015; grounding
paper at ``📄/ladder/paper.md``) is the defense: only release a new reward when a
candidate beats the running best by more than a margin ``η``, and quantize every
released value to the ``η``-grid. Because rewards live in ``[0, 1]`` there can be
at most ``⌈1/η⌉`` genuine improvement steps, so the description length of the
released sequence is bounded and the leaderboard error grows only
*logarithmically* in the number of submissions ``k`` — versus the ``√k`` decay of
a "release every score" leaderboard. That is what lets a fixed-size sealed
holdout support effectively unlimited optimization attempts while the settlement
number stays honest.

This module implements the fixed-``η`` mechanism of §3 in the reward convention
(higher is better; the paper is written for loss, lower is better — this is the
sign-mirror). The parameter-free paired-t variant (§4) needs the previous best's
per-example loss vector and a ``s/√n`` threshold; it is a documented follow-up
because it introduces per-example state and floating-point thresholds.

Egress discipline: the internal candidate score is a float that lives only inside
the boundary. Every *released* value is the integer number of ``η``-steps of the
running best (``leaderboard_step_index`` over ``step_denominator``), so the public
record carries only small integers and passes ``assert_bounded_egress`` — no exact
reward, gradient, or record ever leaves. The released rational
``index / denominator`` is the Ladder's *intended* public leaderboard number, and
it is exactly the sequence for which the adaptive-overfitting bound holds.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence


class LadderError(ValueError):
    """Raised on a malformed Ladder policy or submission."""


@dataclass(frozen=True)
class LadderPolicy:
    """Fixed-``η`` Ladder configuration.

    ``step_denominator`` (``D``) fixes the grid ``η = 1/D``: released values are
    multiples of ``1/D`` in ``[0, 1]``, and there are at most ``D`` genuine
    improvement steps. A smaller ``D`` (coarser grid) leaks less and settles more
    honestly under adaptivity; a larger ``D`` gives the optimizer finer signal.
    Choosing ``D`` is choosing a point on the utility/safety frontier.
    """

    step_denominator: int = 20
    max_submissions: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.step_denominator, int) or isinstance(self.step_denominator, bool):
            raise LadderError("step_denominator must be an int")
        if self.step_denominator < 1:
            raise LadderError("step_denominator must be >= 1")
        if self.max_submissions is not None:
            if not isinstance(self.max_submissions, int) or isinstance(self.max_submissions, bool):
                raise LadderError("max_submissions must be an int or None")
            if self.max_submissions < 1:
                raise LadderError("max_submissions must be >= 1")

    @property
    def step(self) -> float:
        """The margin/grid ``η = 1/D`` (for internal comparison only)."""
        return 1.0 / self.step_denominator

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "step_denominator": self.step_denominator,
            "max_improvement_steps": self.step_denominator,
            "max_submissions": self.max_submissions,
        }


@dataclass(frozen=True)
class LadderRelease:
    """Bounded result of a single Ladder submission.

    ``leaderboard_step_index`` over ``step_denominator`` is the quantized running
    best (the public leaderboard number); ``-1`` means nothing has been released
    yet (no candidate has cleared the floor). ``accepted`` is whether *this*
    submission advanced the leaderboard. All fields are small ints / bools /
    strings, so the record passes ``assert_bounded_egress``.
    """

    submission_index: int
    accepted: bool
    leaderboard_step_index: int
    step_denominator: int
    improvement_steps_so_far: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "submission_index": self.submission_index,
            "accepted": self.accepted,
            "leaderboard_step_index": self.leaderboard_step_index,
            "step_denominator": self.step_denominator,
            "improvement_steps_so_far": self.improvement_steps_so_far,
            "has_leaderboard_entry": self.leaderboard_step_index >= 0,
        }


class LadderLeaderboard:
    """Stateful fixed-``η`` Ladder over one reused sealed holdout.

    A candidate is submitted with its internal holdout reward score in ``[0, 1]``
    (higher better), computed inside the boundary. The score is compared to the
    running best and, only if it clears ``best + η``, the leaderboard advances to
    the ``η``-grid-rounded new value. Otherwise the previous best is re-released
    and the candidate learns nothing new about the holdout.
    """

    def __init__(self, policy: LadderPolicy | None = None) -> None:
        self.policy = policy or LadderPolicy()
        self._denominator = self.policy.step_denominator
        # Running best as an integer number of η-steps; -1 == nothing released.
        self._best_index = -1
        self._submission_count = 0
        self._improvement_count = 0

    @property
    def best_step_index(self) -> int:
        return self._best_index

    @property
    def submission_count(self) -> int:
        return self._submission_count

    @property
    def improvement_count(self) -> int:
        return self._improvement_count

    def submit(self, internal_score: float) -> LadderRelease:
        """Submit a candidate's internal holdout reward and get a bounded release."""

        if isinstance(internal_score, bool) or not isinstance(internal_score, (int, float)):
            raise LadderError("internal_score must be a real number in [0, 1]")
        score = float(internal_score)
        if not (0.0 <= score <= 1.0):
            raise LadderError("internal_score must be in [0, 1]")
        if self.policy.max_submissions is not None and self._submission_count >= self.policy.max_submissions:
            raise LadderError("ladder submission budget exhausted")

        self._submission_count += 1
        # Ladder rule (reward convention): advance only on a strict > η margin over
        # the current best value. Work in exact step units to avoid float drift:
        # accept iff score*D > best_index + 1, i.e. score exceeds (best+η).
        scaled = score * self._denominator
        accepted = scaled > self._best_index + 1
        if accepted:
            # Round the accepted score to the nearest η-grid step (§3: [R_S]_η),
            # clamped into [0, D]. It is strictly above the old best by construction.
            new_index = int(scaled + 0.5)
            if new_index > self._denominator:
                new_index = self._denominator
            if new_index <= self._best_index:
                # Rounding never drops below the acceptance floor, but clamp defensively.
                new_index = self._best_index + 1
            self._best_index = new_index
            self._improvement_count += 1

        return LadderRelease(
            submission_index=self._submission_count,
            accepted=accepted,
            leaderboard_step_index=self._best_index,
            step_denominator=self._denominator,
            improvement_steps_so_far=self._improvement_count,
        )

    def public_manifest(self) -> dict[str, Any]:
        """Bounded public accounting for the leaderboard so far."""
        return {
            "policy": self.policy.to_public_dict(),
            "submission_count": self._submission_count,
            "improvement_count": self._improvement_count,
            "leaderboard_step_index": self._best_index,
            "step_denominator": self._denominator,
            "has_leaderboard_entry": self._best_index >= 0,
        }


# ---------------------------------------------------------------------------
# Parameter-free (paired-t) Ladder variant — §4 of the paper.
#
# Choosing η ahead of time is awkward. The parameter-free variant replaces the
# fixed margin with a one-sided paired t-test over per-example scores: release a
# new best only when the candidate's per-example score vector is *statistically
# significantly* above the previous best's, using the running threshold `s/√n`
# where `s = std(new − prev)`. The paired test has high power because competing
# submissions are strongly correlated, so the effective significance is ≈0.15.
# The released value is rounded to `1/n` precision (revealing only ~log(n) bits,
# comparable to `1/√n` accuracy) — the *step size*, not the precision, is what
# controls how often a new estimate leaks, so this is safe.
#
# This variant is deterministic (no noise), which suits a TEE reward gate: given
# the same score vectors it always makes the same release. Egress stays bounded —
# the released leaderboard number is the integer `leaderboard_numerator` over the
# per-example vector length `denominator`, never a float or raw reward.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PairedTLadderRelease:
    """Bounded result of a single paired-t Ladder submission.

    ``leaderboard_numerator`` over ``denominator`` (the per-example vector length
    ``n``) is the running-best mean score at ``1/n`` precision; ``-1`` numerator
    means nothing has been released yet. ``accepted`` is whether this submission
    passed the significance test and advanced the best. All fields are small ints
    / bools, so the record passes ``assert_bounded_egress``.
    """

    submission_index: int
    accepted: bool
    leaderboard_numerator: int
    denominator: int
    improvement_steps_so_far: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "submission_index": self.submission_index,
            "accepted": self.accepted,
            "leaderboard_numerator": self.leaderboard_numerator,
            "denominator": self.denominator,
            "improvement_steps_so_far": self.improvement_steps_so_far,
            "has_leaderboard_entry": self.leaderboard_numerator >= 0,
        }


class PairedTLadderLeaderboard:
    """Parameter-free Ladder over per-example score vectors (reward convention).

    Each candidate submits its per-example score vector (e.g. one score per held
    cell / per example) with a fixed length ``n``. The mechanism releases a new
    best only when the candidate's vector is significantly above the previous
    best's by a one-sided paired t-test, and rounds the released mean to ``1/n``.
    Higher is better throughout (the paper is written for loss; this is the
    sign-mirror).
    """

    def __init__(self) -> None:
        self._prev_vector: list[float] | None = None
        self._n: int | None = None
        # Running-best mean at 1/n precision, as an integer numerator; -1 == none.
        self._best_numerator = -1
        self._submission_count = 0
        self._improvement_count = 0

    @property
    def best_numerator(self) -> int:
        return self._best_numerator

    @property
    def submission_count(self) -> int:
        return self._submission_count

    @property
    def improvement_count(self) -> int:
        return self._improvement_count

    def submit(self, per_example_scores: Sequence[float]) -> PairedTLadderRelease:
        """Submit a candidate's per-example score vector; get a bounded release."""

        if isinstance(per_example_scores, (str, bytes)):
            raise LadderError("per_example_scores must be a sequence of numbers")
        vector = list(per_example_scores)
        if not vector:
            raise LadderError("per_example_scores must be non-empty")
        cleaned: list[float] = []
        for value in vector:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise LadderError("per_example_scores must be real numbers in [0, 1]")
            fv = float(value)
            if not (0.0 <= fv <= 1.0):
                raise LadderError("per_example_scores must be in [0, 1]")
            cleaned.append(fv)
        n = len(cleaned)
        if self._n is None:
            self._n = n
        elif n != self._n:
            raise LadderError("per_example score vector length must be stable")

        self._submission_count += 1
        mean_score = sum(cleaned) / n

        if self._prev_vector is None:
            accepted = True
        else:
            # One-sided paired test: is the new vector significantly above prev?
            diffs = [cleaned[i] - self._prev_vector[i] for i in range(n)]
            mean_diff = sum(diffs) / n
            if n > 1:
                var = sum((d - mean_diff) ** 2 for d in diffs) / (n - 1)
                std = var ** 0.5
            else:
                std = 0.0
            threshold = std / (n ** 0.5)
            prev_mean = self._best_numerator / n
            accepted = mean_score > prev_mean + threshold

        if accepted:
            self._prev_vector = cleaned
            numerator = int(mean_score * n + 0.5)  # round mean to the 1/n grid
            if numerator > n:
                numerator = n
            if numerator < 0:
                numerator = 0
            # Never let the *released* number regress even if a significant but
            # tiny improvement rounds below the current best.
            if numerator < self._best_numerator:
                numerator = self._best_numerator
            self._best_numerator = numerator
            self._improvement_count += 1

        return PairedTLadderRelease(
            submission_index=self._submission_count,
            accepted=accepted,
            leaderboard_numerator=self._best_numerator,
            denominator=n,
            improvement_steps_so_far=self._improvement_count,
        )

    def public_manifest(self) -> dict[str, Any]:
        """Bounded public accounting for the paired-t leaderboard so far."""
        return {
            "variant": "paired_t",
            "submission_count": self._submission_count,
            "improvement_count": self._improvement_count,
            "leaderboard_numerator": self._best_numerator,
            "denominator": self._n if self._n is not None else 0,
            "has_leaderboard_entry": self._best_numerator >= 0,
        }
