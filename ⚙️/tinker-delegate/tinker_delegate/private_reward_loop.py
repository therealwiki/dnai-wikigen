"""Optimizer-agnostic RLVR loop over a private verified-reward environment.

This module is the code-level realization of the central PROJECT.md claim: a
candidate (code, model output, or config) can be improved against a private,
TEE-held verifier while the optimizer *method* stays swappable. RL, TTT,
evolutionary search, and an LLM repair loop all plug in behind the same
``LoopOptimizer`` interface.

The security property is structural, not conventional:

* The optimizer receives only the environment's public ``optimizer_view`` and,
  per round, a ``BoundedFeedback`` (decision + score band + candidate/transcript
  hashes). It never sees the exact ``InternalReward``, the sealed data, or raw
  reward-derived gradients.
* The loop refuses to run against an environment whose optimizer policy would
  hand exact rewards to an untrusted optimizer location, unless the caller
  explicitly opts into an internal/attested optimizer that is inside the
  boundary.
* The loop output is a bounded ``LoopOutcome``: round count, best band, a band
  histogram, a stop reason, and the environment's own bounded ``BoundedResult``
  plus attestation. No candidate payloads leave unless the leakage budget
  explicitly allows it.
"""
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from tinker_delegate.private_reward import (
    BoundedFeedback,
    BoundedResult,
    Candidate,
    Decision,
    OptimizerLocation,
    PrivateRewardEnvironment,
    RewardBand,
    assert_bounded_egress,
)


# Ordering of bands from best to worst. WITHHELD sorts lowest so a round that
# leaked no band never looks like progress.
_BAND_RANK: dict[RewardBand, int] = {
    RewardBand.EXCEPTIONAL: 5,
    RewardBand.HIGH: 4,
    RewardBand.MEDIUM: 3,
    RewardBand.LOW: 2,
    RewardBand.NEGLIGIBLE: 1,
    RewardBand.WITHHELD: 0,
}


def band_rank(band: RewardBand) -> int:
    """Public helper: rank a band by quality. Higher is better."""
    return _BAND_RANK.get(band, 0)


class StopReason(str, Enum):
    TARGET_REACHED = "target_reached"
    MAX_ROUNDS = "max_rounds"
    BUDGET_EXHAUSTED = "budget_exhausted"
    OPTIMIZER_HALTED = "optimizer_halted"
    NO_CANDIDATE = "no_candidate"
    CANARY_TRIPPED = "canary_tripped"  # a known-answer probe caught a gamed oracle


@dataclass(frozen=True)
class RoundRecord:
    """Bounded record of a single loop round. No exact reward, no payload."""

    round_index: int
    candidate_hash: str
    decision: Decision
    reward_band: RewardBand
    is_best_so_far: bool

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "round_index": self.round_index,
            "candidate_hash": self.candidate_hash,
            "decision": self.decision.value,
            "reward_band": self.reward_band.value,
            "is_best_so_far": self.is_best_so_far,
        }


@dataclass(frozen=True)
class LoopOutcome:
    """Bounded output of the whole loop."""

    optimizer_name: str
    rounds_run: int
    accepted_rounds: int
    best_band: RewardBand
    best_candidate_hash: str
    stop_reason: StopReason
    band_histogram: dict[str, int]
    rounds: tuple[RoundRecord, ...]
    result: BoundedResult
    loop_transcript_hash: str
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "optimizer_name": self.optimizer_name,
            "rounds_run": self.rounds_run,
            "accepted_rounds": self.accepted_rounds,
            "best_band": self.best_band.value,
            "best_candidate_hash": self.best_candidate_hash,
            "stop_reason": self.stop_reason.value,
            "band_histogram": dict(sorted(self.band_histogram.items())),
            "rounds": [record.to_public_dict() for record in self.rounds],
            "result": self.result.to_public_dict(),
            "loop_transcript_hash": self.loop_transcript_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }

    def certified_public_export(self) -> dict[str, Any]:
        """Return the bounded public dict only after the egress gate admits it.

        ``to_public_dict`` is bounded by construction, but any publication path
        (checkpoint, on-chain packet, cross-boundary handoff) must not *trust*
        that — it must certify it. This runs the shared fail-closed
        ``assert_bounded_egress`` gate over the exact bytes that would leave the
        boundary, so a future reducer regression that smuggled an exact reward (a
        float), a reward-derived gradient (a numeric array), or raw sealed data
        (an oversized blob) raises ``RewardLeakageError`` here instead of
        silently publishing.

        ``result.attestation`` is public, separately-governed environment config
        (e.g. holdout split fractions) that ``finalize()`` already egress-checked
        at the environment choke point; it is excluded from this gate's
        *structural* float-ban exactly as the ``BoundedResult`` egress check does
        (the textual reward-value scan still covers the rest). The returned dict
        is byte-identical to ``to_public_dict``; only the certification is added.
        """

        payload = self.to_public_dict()
        gated = dict(payload)
        result_view = dict(gated.get("result") or {})
        result_view.pop("attestation", None)
        gated["result"] = result_view
        assert_bounded_egress(gated)
        return payload


class LoopOptimizer(ABC):
    """A swappable optimization strategy driven only by bounded feedback.

    Implementations must not attempt to read sealed data or exact rewards; the
    loop only ever hands them ``BoundedFeedback`` and the public optimizer view.
    ``propose`` returns the next ``Candidate`` to evaluate, or ``None`` to halt
    early. ``observe`` receives the bounded feedback for the candidate it last
    proposed.
    """

    #: Human-readable name recorded in the bounded outcome.
    name: str = "optimizer"

    def begin(self, optimizer_view: dict[str, Any]) -> None:
        """Receive the public environment setup. Optional to override."""

    @abstractmethod
    def propose(self) -> Candidate | None:
        """Return the next candidate to evaluate, or None to stop early."""

    def observe(self, candidate: Candidate, feedback: BoundedFeedback) -> None:
        """Receive bounded feedback for the last proposed candidate."""


class CandidateSource(ABC):
    """How raw candidate payloads are sampled and mutated for a search space.

    Keeping this separate from ``LoopOptimizer`` is what makes optimizers
    env-agnostic: the *space* (how to build/mutate a payload) is supplied by the
    caller, while the *strategy* (which payload to try next given bounded bands)
    is the swappable optimizer.
    """

    @abstractmethod
    def seeds(self) -> list[bytes]:
        """Deterministic initial candidate payloads."""

    @abstractmethod
    def mutate(self, payload: bytes, step: int) -> bytes:
        """Deterministically derive a neighbour payload for the given step."""


def run_private_reward_loop(
    environment: PrivateRewardEnvironment,
    optimizer: LoopOptimizer,
    *,
    max_rounds: int,
    target_band: RewardBand = RewardBand.EXCEPTIONAL,
    allow_internal_optimizer: bool = False,
    canary_report: Any = None,
) -> LoopOutcome:
    """Drive a swappable optimizer against a private reward environment.

    The loop enforces the leakage bound structurally: the optimizer only ever
    receives ``environment.optimizer_view()`` and per-round ``BoundedFeedback``.
    It stops at ``target_band``, ``max_rounds``, budget exhaustion, or when the
    optimizer halts.

    ``canary_report`` (a ``canary.CanaryReport``, produced by screening a fresh
    environment instance so it does not consume this run's budget) is a
    fail-closed pre-check: if it is present and not ``clear``, a known-answer
    probe caught the reward oracle leaking/gamed, so the loop refuses to start
    and returns a bounded ``CANARY_TRIPPED`` outcome before spending any budget.
    """
    if max_rounds < 0:
        raise ValueError("max_rounds must be non-negative")

    if canary_report is not None and not canary_report.clear:
        return _canary_tripped_outcome(environment, optimizer)

    policy = environment.optimizer_policy
    optimizer_inside_boundary = policy.location in (
        OptimizerLocation.INTERNAL_TEE,
        OptimizerLocation.ATTESTED_REMOTE,
    )
    if policy.allow_exact_rewards and not (optimizer_inside_boundary and allow_internal_optimizer):
        raise PermissionError(
            "environment optimizer policy would expose exact rewards; "
            "pass allow_internal_optimizer=True only for an in-boundary optimizer"
        )

    optimizer.begin(environment.optimizer_view())

    rounds: list[RoundRecord] = []
    histogram: dict[str, int] = {}
    best_band = RewardBand.WITHHELD
    best_hash = ""
    stop_reason = StopReason.MAX_ROUNDS

    budget = environment.query_budget.max_queries

    for round_index in range(max_rounds):
        if environment.accepted_count >= budget:
            stop_reason = StopReason.BUDGET_EXHAUSTED
            break

        candidate = optimizer.propose()
        if candidate is None:
            stop_reason = StopReason.OPTIMIZER_HALTED if rounds else StopReason.NO_CANDIDATE
            break

        feedback = environment.evaluate(candidate)
        optimizer.observe(candidate, feedback)

        histogram[feedback.reward_band.value] = histogram.get(feedback.reward_band.value, 0) + 1
        improved = band_rank(feedback.reward_band) > band_rank(best_band)
        if improved:
            best_band = feedback.reward_band
            best_hash = feedback.candidate_hash

        rounds.append(
            RoundRecord(
                round_index=round_index,
                candidate_hash=feedback.candidate_hash,
                decision=feedback.decision,
                reward_band=feedback.reward_band,
                is_best_so_far=improved,
            )
        )

        if band_rank(feedback.reward_band) >= band_rank(target_band) and band_rank(target_band) > 0:
            stop_reason = StopReason.TARGET_REACHED
            break
    else:
        stop_reason = StopReason.MAX_ROUNDS if max_rounds else StopReason.NO_CANDIDATE

    result = environment.finalize()
    accepted_rounds = sum(1 for record in rounds if record.decision == Decision.PASS)

    transcript_hash = _sha256_json(
        {
            "optimizer_name": optimizer.name,
            "environment_hash": environment.environment_hash,
            "rounds": [record.to_public_dict() for record in rounds],
            "stop_reason": stop_reason.value,
        }
    )

    return LoopOutcome(
        optimizer_name=optimizer.name,
        rounds_run=len(rounds),
        accepted_rounds=accepted_rounds,
        best_band=best_band,
        best_candidate_hash=best_hash,
        stop_reason=stop_reason,
        band_histogram=histogram,
        rounds=tuple(rounds),
        result=result,
        loop_transcript_hash=transcript_hash,
        raw_secret_egress=False,
    )


def _canary_tripped_outcome(
    environment: PrivateRewardEnvironment, optimizer: LoopOptimizer
) -> LoopOutcome:
    """Bounded zero-round outcome for a loop refused because a canary tripped."""

    stop_reason = StopReason.CANARY_TRIPPED
    result = environment.finalize()
    transcript_hash = _sha256_json(
        {
            "optimizer_name": optimizer.name,
            "environment_hash": environment.environment_hash,
            "rounds": [],
            "stop_reason": stop_reason.value,
        }
    )
    return LoopOutcome(
        optimizer_name=optimizer.name,
        rounds_run=0,
        accepted_rounds=0,
        best_band=RewardBand.WITHHELD,
        best_candidate_hash="",
        stop_reason=stop_reason,
        band_histogram={},
        rounds=(),
        result=result,
        loop_transcript_hash=transcript_hash,
        raw_secret_egress=False,
    )


# --------------------------------------------------------------------------- #
# Swappable optimizer strategies. Each sees only bounded bands + public view.
# --------------------------------------------------------------------------- #


class RandomSearchOptimizer(LoopOptimizer):
    """Deterministic pseudo-random sweep over the candidate space.

    Ignores feedback entirely; it is the baseline that proves the loop works
    with a strategy that uses no reward information at all.
    """

    name = "random_search"

    def __init__(self, source: CandidateSource, *, budget: int = 32) -> None:
        self._source = source
        self._budget = budget
        self._queue: list[bytes] = []
        self._step = 0

    def begin(self, optimizer_view: dict[str, Any]) -> None:
        self._queue = list(self._source.seeds())
        self._step = 0

    def propose(self) -> Candidate | None:
        if self._step >= self._budget:
            return None
        if self._queue:
            payload = self._queue.pop(0)
        else:
            seeds = self._source.seeds()
            base = seeds[self._step % len(seeds)] if seeds else b""
            payload = self._source.mutate(base, self._step)
        self._step += 1
        return Candidate(payload=payload)


class HillClimbOptimizer(LoopOptimizer):
    """Greedy local search that keeps the best band and mutates around it.

    This stands in for evolutionary search / RL: it uses only the bounded band
    ordering to decide whether to keep or discard a neighbour.
    """

    name = "hill_climb"

    def __init__(self, source: CandidateSource, *, budget: int = 32) -> None:
        self._source = source
        self._budget = budget
        self._seeds: list[bytes] = []
        self._best_payload: bytes | None = None
        self._best_rank = -1
        self._pending: bytes | None = None
        self._step = 0

    def begin(self, optimizer_view: dict[str, Any]) -> None:
        self._seeds = list(self._source.seeds())
        self._best_payload = None
        self._best_rank = -1
        self._pending = None
        self._step = 0

    def propose(self) -> Candidate | None:
        if self._step >= self._budget:
            return None
        if self._step < len(self._seeds):
            payload = self._seeds[self._step]
        elif self._best_payload is not None:
            payload = self._source.mutate(self._best_payload, self._step)
        else:
            base = self._seeds[0] if self._seeds else b""
            payload = self._source.mutate(base, self._step)
        self._pending = payload
        self._step += 1
        return Candidate(payload=payload)

    def observe(self, candidate: Candidate, feedback: BoundedFeedback) -> None:
        rank = band_rank(feedback.reward_band)
        if feedback.decision == Decision.PASS and rank > self._best_rank:
            self._best_rank = rank
            self._best_payload = self._pending


class EvolutionaryOptimizer(LoopOptimizer):
    """Population-based (mu+lambda) evolutionary search over bounded bands.

    Unlike hill-climb (which keeps only the single best), this maintains a
    population of candidates ranked by their bounded reward band and, each round,
    mutates a member of the top half to breed the next candidate — keeping several
    lineages alive so it can escape a local optimum a greedy climb would stick in.
    It uses only the public band ordering, never exact rewards.
    """

    name = "evolutionary"

    # When breeding, give up on finding a fresh candidate after this many
    # mutation attempts so a saturated pool halts the loop instead of spinning.
    _MAX_BREED_ATTEMPTS = 16

    def __init__(self, source: CandidateSource, *, population_size: int = 6, budget: int = 32) -> None:
        if population_size < 1:
            raise ValueError("population_size must be >= 1")
        self._source = source
        self._population_size = population_size
        self._budget = budget
        self._seeds: list[bytes] = []
        # population of (payload, rank); rank -1 until observed.
        self._pop: list[tuple[bytes, int]] = []
        self._seen: set[bytes] = set()
        self._pending: bytes | None = None
        self._step = 0

    def begin(self, optimizer_view: dict[str, Any]) -> None:
        self._seeds = list(self._source.seeds())
        self._pop = []
        self._seen = set()
        self._pending = None
        self._step = 0

    def propose(self) -> Candidate | None:
        if self._step >= self._budget:
            return None
        payload = self._next_payload()
        if payload is None:
            # Reachable candidate space is exhausted; halt rather than burn the
            # bounded per-candidate reward-query budget on duplicates.
            return None
        self._seen.add(payload)
        self._pending = payload
        self._step += 1
        return Candidate(payload=payload)

    def _next_payload(self) -> bytes | None:
        # Sweep any unseen seeds first, then breed from the elite.
        for seed in self._seeds:
            if seed not in self._seen:
                return seed
        parent = self._select_parent()
        for attempt in range(self._MAX_BREED_ATTEMPTS):
            child = self._source.mutate(parent, self._step + attempt)
            if child not in self._seen:
                return child
        return None

    def observe(self, candidate: Candidate, feedback: BoundedFeedback) -> None:
        if self._pending is None:
            return
        rank = band_rank(feedback.reward_band) if feedback.decision == Decision.PASS else -1
        self._pop.append((self._pending, rank))
        # (mu+lambda) selection: keep the fittest population_size by band.
        self._pop.sort(key=lambda item: item[1], reverse=True)
        if len(self._pop) > self._population_size:
            self._pop = self._pop[: self._population_size]

    def _select_parent(self) -> bytes:
        if not self._pop:
            return self._seeds[0] if self._seeds else b""
        top_half = self._pop[: max(1, len(self._pop) // 2)]
        # Deterministic round-robin over the elite, so no randomness is needed.
        return top_half[self._step % len(top_half)][0]


class LLMRepairOptimizer(LoopOptimizer):
    """Deterministic stand-in for an LLM repair loop.

    Models the behaviour of "on a weak band, revise the candidate; on a strong
    band, keep it and stop." No real LLM is called; the point is that an LLM
    repair strategy plugs into the exact same bounded interface as RL or
    evolutionary search, proving the optimizer is swappable.
    """

    name = "llm_repair"

    def __init__(
        self,
        source: CandidateSource,
        *,
        budget: int = 16,
        satisfied_band: RewardBand = RewardBand.HIGH,
    ) -> None:
        self._source = source
        self._budget = budget
        self._satisfied_rank = band_rank(satisfied_band)
        self._seeds: list[bytes] = []
        self._current: bytes | None = None
        self._pending: bytes | None = None
        self._step = 0
        self._done = False

    def begin(self, optimizer_view: dict[str, Any]) -> None:
        self._seeds = list(self._source.seeds())
        self._current = self._seeds[0] if self._seeds else b""
        self._pending = None
        self._step = 0
        self._done = False

    def propose(self) -> Candidate | None:
        if self._done or self._step >= self._budget:
            return None
        payload = self._current if self._current is not None else b""
        self._pending = payload
        self._step += 1
        return Candidate(payload=payload)

    def observe(self, candidate: Candidate, feedback: BoundedFeedback) -> None:
        if feedback.decision == Decision.PASS and band_rank(feedback.reward_band) >= self._satisfied_rank:
            self._done = True
            return
        # "Repair": deterministically revise toward the next candidate.
        base = self._pending if self._pending is not None else (self._seeds[0] if self._seeds else b"")
        self._current = self._source.mutate(base, self._step)


class PoolCandidateSource(CandidateSource):
    """Simple candidate space backed by an explicit payload pool.

    ``seeds`` returns the pool in order; ``mutate`` deterministically walks to
    later entries so hill-climb/repair strategies keep exploring the pool
    without randomness (which keeps the loop replayable inside a TEE).
    """

    def __init__(self, payloads: Iterable[bytes]) -> None:
        self._pool = [bytes(item) for item in payloads]
        if not self._pool:
            raise ValueError("candidate pool must be non-empty")

    def seeds(self) -> list[bytes]:
        return list(self._pool)

    def mutate(self, payload: bytes, step: int) -> bytes:
        # Deterministic index derived from the payload and step; stays in-pool.
        digest = hashlib.sha256(payload + step.to_bytes(4, "big")).digest()
        index = int.from_bytes(digest[:4], "big") % len(self._pool)
        return self._pool[index]


def _sha256_json(value: Any) -> str:
    canonical = json.dumps(_stable_public(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _stable_public(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _stable_public(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_stable_public(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
