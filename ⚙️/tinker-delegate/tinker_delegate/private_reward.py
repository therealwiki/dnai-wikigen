"""Private verified-reward environment interface.

This module is the code-level counterpart of the private reward model in
PROJECT.md. Exact rewards and sealed data stay inside the environment; callers
receive only bounded feedback, hashes, attestable transcript metadata, and final
bounded results.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RewardLeakageError(ValueError):
    """Raised when bounded egress would carry a raw reward value or private data."""


# A rendered float (e.g. an exact reward "0.9731") or a long precise integer
# (metrics, wei amounts, timestamps) has no place in bounded egress — bands,
# decisions, hashes, and small counts are the only permitted numeric surface.
_FLOAT_TEXT_PATTERN = re.compile(r"\d*\.\d+")
# Scientific-notation floats without a decimal point (how Python repr() renders a
# very small/large reward, e.g. `1e-05`, `2e+16`) would evade the decimal pattern.
# Requiring a SIGNED exponent catches them while never matching a bare `1e5`
# inside a hex hash (hashes contain no `+`/`-`).
_SCI_FLOAT_TEXT_PATTERN = re.compile(r"\d[eE][+-]\d")
_LONG_DIGIT_PATTERN = re.compile(r"\d{6,}")


class FeedbackMode(str, Enum):
    """How much reward-derived feedback may leave the environment."""
    NONE = "none"
    PASS_HOLD_DENY = "pass_hold_deny"
    BAND = "band"


class RewardBand(str, Enum):
    EXCEPTIONAL = "exceptional"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    WITHHELD = "withheld"


class Decision(str, Enum):
    PASS = "pass"
    HOLD = "hold"
    DENY = "deny"
    BUDGET_EXHAUSTED = "budget_exhausted"
    POLICY_REJECTED = "policy_rejected"


class SecurityTier(str, Enum):
    """Where reward-derived state may live."""
    INTERNAL_TEE = "internal_tee"
    ATTESTED_REMOTE = "attested_remote"
    EXTERNAL_BOUNDED = "external_bounded"


class OptimizerLocation(str, Enum):
    """Where the adaptive optimizer is allowed to run."""
    INTERNAL_TEE = "internal_tee"
    ATTESTED_REMOTE = "attested_remote"
    EXTERNAL = "external"


@dataclass(frozen=True)
class PublicProblem:
    title: str
    statement: str
    public_metadata: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "statement": self.statement,
            "public_metadata": _stable_public(self.public_metadata),
        }


@dataclass(frozen=True)
class CandidateSchema:
    kind: str
    json_schema: dict[str, Any]
    max_bytes: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "json_schema": _stable_public(self.json_schema),
            "max_bytes": self.max_bytes,
        }


@dataclass(frozen=True)
class Candidate:
    payload: bytes
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def candidate_hash(self) -> str:
        return _sha256_hex(self.payload)

    @property
    def size_bytes(self) -> int:
        return len(self.payload)


@dataclass(frozen=True)
class InternalReward:
    """Exact reward value. This must never be returned to external callers."""
    value: float
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class LeakageBudget:
    max_queries: int
    feedback_mode: FeedbackMode = FeedbackMode.BAND
    reward_precision_bits: int = 0
    release_candidate_payloads: bool = False
    timing_band_seconds: int = 60
    cost_band_units: int = 1

    def __post_init__(self) -> None:
        if self.max_queries < 0:
            raise ValueError("max_queries must be non-negative")
        if self.reward_precision_bits < 0:
            raise ValueError("reward_precision_bits must be non-negative")
        if self.feedback_mode != FeedbackMode.NONE and self.reward_precision_bits > 0:
            raise ValueError("public reward precision must be zero unless feedback is withheld")

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "max_queries": self.max_queries,
            "feedback_mode": self.feedback_mode.value,
            "reward_precision_bits": self.reward_precision_bits,
            "release_candidate_payloads": self.release_candidate_payloads,
            "timing_band_seconds": self.timing_band_seconds,
            "cost_band_units": self.cost_band_units,
        }


@dataclass(frozen=True)
class OptimizerPolicy:
    """Policy for optimizer-visible reward-derived state."""
    location: OptimizerLocation
    feedback_mode: FeedbackMode = FeedbackMode.BAND
    allow_exact_rewards: bool = False
    allow_reward_derived_state: bool = False
    allow_private_checkpoints: bool = False
    require_attestation: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        if self.location == OptimizerLocation.EXTERNAL and (
            self.allow_exact_rewards
            or self.allow_reward_derived_state
            or self.allow_private_checkpoints
        ):
            raise ValueError("external optimizers must not receive reward-derived state")
        if self.location == OptimizerLocation.ATTESTED_REMOTE and (
            self.allow_exact_rewards
            or self.allow_reward_derived_state
            or self.allow_private_checkpoints
        ) and not self.require_attestation:
            raise ValueError("attested remote optimizer state requires attestation")

    @classmethod
    def external_bounded(cls, feedback_mode: FeedbackMode = FeedbackMode.BAND) -> "OptimizerPolicy":
        return cls(
            location=OptimizerLocation.EXTERNAL,
            feedback_mode=feedback_mode,
            allow_exact_rewards=False,
            allow_reward_derived_state=False,
            allow_private_checkpoints=False,
            require_attestation=False,
            notes="external optimizer receives public prompt and bounded feedback only",
        )

    @classmethod
    def internal_dense(cls) -> "OptimizerPolicy":
        return cls(
            location=OptimizerLocation.INTERNAL_TEE,
            feedback_mode=FeedbackMode.NONE,
            allow_exact_rewards=True,
            allow_reward_derived_state=True,
            allow_private_checkpoints=True,
            require_attestation=True,
            notes="optimizer is inside the same attested boundary",
        )

    @classmethod
    def attested_remote_dense(cls) -> "OptimizerPolicy":
        return cls(
            location=OptimizerLocation.ATTESTED_REMOTE,
            feedback_mode=FeedbackMode.NONE,
            allow_exact_rewards=True,
            allow_reward_derived_state=True,
            allow_private_checkpoints=True,
            require_attestation=True,
            notes="optimizer is in a separately attested service",
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "location": self.location.value,
            "feedback_mode": self.feedback_mode.value,
            "allow_exact_rewards": self.allow_exact_rewards,
            "allow_reward_derived_state": self.allow_reward_derived_state,
            "allow_private_checkpoints": self.allow_private_checkpoints,
            "require_attestation": self.require_attestation,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class QueryLeakageRecord:
    candidate_hash: str
    accepted: bool
    decision: Decision
    feedback_mode: FeedbackMode
    reward_band: RewardBand = RewardBand.WITHHELD
    public_message: str = ""
    elapsed_band_seconds: int = 0

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "candidate_hash": self.candidate_hash,
            "accepted": self.accepted,
            "decision": self.decision.value,
            "feedback_mode": self.feedback_mode.value,
            "reward_band": self.reward_band.value,
            "public_message": self.public_message,
            "elapsed_band_seconds": self.elapsed_band_seconds,
        }


@dataclass(frozen=True)
class BoundedFeedback:
    """Reward-derived output safe to return outside the private boundary."""
    candidate_hash: str
    decision: Decision
    feedback_mode: FeedbackMode
    reward_band: RewardBand = RewardBand.WITHHELD
    public_message: str = ""
    transcript_hash: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "candidate_hash": self.candidate_hash,
            "decision": self.decision.value,
            "feedback_mode": self.feedback_mode.value,
            "reward_band": self.reward_band.value,
            "public_message": self.public_message,
            "transcript_hash": self.transcript_hash,
        }


@dataclass(frozen=True)
class BoundedResult:
    decision: Decision
    result_band: RewardBand
    accepted_count: int
    rejected_count: int
    transcript_hash: str
    leakage_hash: str
    attestation: dict[str, Any]
    public_message: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "result_band": self.result_band.value,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "transcript_hash": self.transcript_hash,
            "leakage_hash": self.leakage_hash,
            "attestation": _stable_public(self.attestation),
            "public_message": self.public_message,
        }


@dataclass(frozen=True)
class EnvironmentAttestation:
    environment_hash: str
    transcript_hash: str
    leakage_hash: str
    security_tier: SecurityTier
    optimizer_location: OptimizerLocation
    optimizer_policy_hash: str
    query_budget: int
    accepted_count: int
    rejected_count: int
    transcript_chain_head: str = ""
    dp_status: "dict[str, Any] | None" = None

    def to_public_dict(self) -> dict[str, Any]:
        out = {
            "environment_hash": self.environment_hash,
            "transcript_hash": self.transcript_hash,
            "transcript_chain_head": self.transcript_chain_head,
            "leakage_hash": self.leakage_hash,
            "security_tier": self.security_tier.value,
            "optimizer_location": self.optimizer_location.value,
            "optimizer_policy_hash": self.optimizer_policy_hash,
            "query_budget": self.query_budget,
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
        }
        # Only present when a DP budget is configured, so non-DP attestations are
        # byte-identical to before. Public privacy config (epsilon/delta), like
        # the holdout split fractions elsewhere in attestation — not reward.
        if self.dp_status is not None:
            out["dp_status"] = self.dp_status
        return out


class PrivateRewardEnvironment(ABC):
    """Base class for sealed-data reward environments.

    Subclasses provide the problem, candidate schema, exact internal reward, and
    reducer. Callers should use evaluate() and finalize(); direct reward() calls
    are internal TEE-only.
    """

    def __init__(self) -> None:
        self._records: list[QueryLeakageRecord] = []
        self._internal_rewards: list[InternalReward] = []
        # Streaming, append-only tamper-evident chain over the same bounded
        # records that back the flat transcript_hash (see transcript_log).
        from tinker_delegate.transcript_log import TranscriptLogger

        self._transcript_log = TranscriptLogger()
        # Optional differential-privacy budget: when set, each accepted reward
        # query spends one DP charge and releases fail closed once the budget is
        # exhausted (privacy-budget-bounded reward release over individual data).
        self._dp_accountant: Any = None
        self._dp_params: Any = None

    def set_dp_budget(self, accountant: Any, params_per_query: Any) -> None:
        """Attach a differential-privacy budget charged per accepted reward query.

        ``accountant`` is a ``dp_accounting.DpAccountant`` (DP mode) and
        ``params_per_query`` a ``DpParams``. Once the accountant is exhausted,
        `evaluate` fails closed (WITHHELD band) instead of releasing more reward
        signal over the individual-level data.
        """

        self._dp_accountant = accountant
        self._dp_params = params_per_query

    def _append_record(self, record: "QueryLeakageRecord") -> None:
        """Record one bounded query event to both the flat list and the chain."""

        self._records.append(record)
        self._transcript_log.append(record.to_public_dict())

    @abstractmethod
    def problem(self) -> PublicProblem:
        """Public problem statement safe to show optimizers."""

    @property
    @abstractmethod
    def candidate_schema(self) -> CandidateSchema:
        """Allowed candidate format."""

    @property
    @abstractmethod
    def query_budget(self) -> LeakageBudget:
        """Leakage and query budget for the environment."""

    @property
    def security_tier(self) -> SecurityTier:
        return SecurityTier.EXTERNAL_BOUNDED

    @property
    def optimizer_policy(self) -> OptimizerPolicy:
        return OptimizerPolicy.external_bounded(feedback_mode=self.query_budget.feedback_mode)

    def acceptance_policy(self, candidate: Candidate) -> Decision:
        if candidate.size_bytes > self.candidate_schema.max_bytes:
            return Decision.POLICY_REJECTED
        return Decision.PASS

    @abstractmethod
    def reward(self, candidate: Candidate) -> InternalReward:
        """Exact reward over sealed data. Internal-only."""

    @abstractmethod
    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        """Convert exact reward to approved public feedback."""

    def evaluate(self, candidate: Candidate) -> BoundedFeedback:
        """Apply policy and budget, compute private reward, return bounded output."""
        started_at = time.time()
        if self.accepted_count >= self.query_budget.max_queries:
            return self._record_rejection(
                candidate,
                Decision.BUDGET_EXHAUSTED,
                "query budget exhausted",
                started_at,
            )

        decision = self.acceptance_policy(candidate)
        if decision != Decision.PASS:
            return self._record_rejection(candidate, decision, "candidate rejected by policy", started_at)

        # Differential-privacy gate: computing the reward reads the sealed
        # (individual-level) data, so it spends privacy budget. Charge before
        # computing; if the budget is exhausted, fail closed and release nothing.
        if self._dp_accountant is not None:
            charge = self._dp_accountant.charge(self._dp_params)
            if not charge.allowed:
                return self._record_rejection(
                    candidate,
                    Decision.BUDGET_EXHAUSTED,
                    "dp privacy budget exhausted",
                    started_at,
                )

        internal = self.reward(candidate)
        self._internal_rewards.append(internal)
        bounded = self._sanitize_feedback(candidate, self.output_reducer(internal))
        record = QueryLeakageRecord(
            candidate_hash=candidate.candidate_hash,
            accepted=True,
            decision=bounded.decision,
            feedback_mode=bounded.feedback_mode,
            reward_band=bounded.reward_band,
            public_message=bounded.public_message,
            elapsed_band_seconds=self._elapsed_band(started_at),
        )
        self._append_record(record)
        feedback = BoundedFeedback(
            candidate_hash=bounded.candidate_hash,
            decision=bounded.decision,
            feedback_mode=bounded.feedback_mode,
            reward_band=bounded.reward_band,
            public_message=bounded.public_message,
            transcript_hash=self.transcript_hash,
        )
        assert_bounded_egress(feedback.to_public_dict())
        return feedback

    def leakage_records(self) -> tuple[QueryLeakageRecord, ...]:
        return tuple(self._records)

    @property
    def accepted_count(self) -> int:
        return sum(1 for record in self._records if record.accepted)

    @property
    def rejected_count(self) -> int:
        return sum(1 for record in self._records if not record.accepted)

    @property
    def transcript_hash(self) -> str:
        return _hash_public_dicts(record.to_public_dict() for record in self._records)

    @property
    def transcript_chain_head(self) -> str:
        """Head of the append-only, tamper-evident transcript hash chain.

        Complements the flat ``transcript_hash``: a verifier can confirm the
        query log grew append-only (no insert/delete/reorder) by walking the
        chain, without re-hashing the whole set.
        """

        return self._transcript_log.head

    def verify_transcript_chain(self) -> bool:
        """True iff the internal transcript chain is an untampered append-only log."""

        return self._transcript_log.verify()

    @property
    def leakage_hash(self) -> str:
        leakage = {
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
            "records": [record.to_public_dict() for record in self._records],
        }
        return _sha256_json(leakage)

    @property
    def optimizer_policy_hash(self) -> str:
        return _sha256_json(self.optimizer_policy.to_public_dict())

    @property
    def environment_hash(self) -> str:
        return _sha256_json({
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "security_tier": self.security_tier.value,
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
        })

    def optimizer_view(self) -> dict[str, Any]:
        """Public optimizer setup view without private data or exact rewards."""
        return {
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
            "environment_hash": self.environment_hash,
        }

    def internal_reward_for_optimizer(self, index: int = -1) -> InternalReward:
        """Return exact reward only when the optimizer is inside a trusted boundary."""
        policy = self.optimizer_policy
        if not policy.allow_exact_rewards or policy.location == OptimizerLocation.EXTERNAL:
            raise PermissionError("optimizer policy forbids exact rewards")
        if not self._internal_rewards:
            raise IndexError("no internal rewards recorded")
        reward = self._internal_rewards[index]
        return InternalReward(value=reward.value, metrics=dict(reward.metrics))

    def attest(self) -> EnvironmentAttestation:
        return EnvironmentAttestation(
            environment_hash=self.environment_hash,
            transcript_hash=self.transcript_hash,
            leakage_hash=self.leakage_hash,
            security_tier=self.security_tier,
            optimizer_location=self.optimizer_policy.location,
            optimizer_policy_hash=self.optimizer_policy_hash,
            query_budget=self.query_budget.max_queries,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            transcript_chain_head=self.transcript_chain_head,
            dp_status=(
                self._dp_accountant.snapshot().to_public_dict()
                if self._dp_accountant is not None
                else None
            ),
        )

    def finalize(self) -> BoundedResult:
        final_band = RewardBand.WITHHELD
        if self._records:
            final_band = self._records[-1].reward_band
        decision = Decision.PASS if self.accepted_count else Decision.DENY
        result = BoundedResult(
            decision=decision,
            result_band=final_band,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            transcript_hash=self.transcript_hash,
            leakage_hash=self.leakage_hash,
            attestation=self.attest().to_public_dict(),
            public_message="bounded private reward result",
        )
        assert_bounded_egress(result.to_public_dict(), structural_ignore_keys=("attestation",))
        return result

    def _record_rejection(
        self,
        candidate: Candidate,
        decision: Decision,
        message: str,
        started_at: float,
    ) -> BoundedFeedback:
        record = QueryLeakageRecord(
            candidate_hash=candidate.candidate_hash,
            accepted=False,
            decision=decision,
            feedback_mode=self.query_budget.feedback_mode,
            reward_band=RewardBand.WITHHELD,
            public_message=message,
            elapsed_band_seconds=self._elapsed_band(started_at),
        )
        self._append_record(record)
        return BoundedFeedback(
            candidate_hash=candidate.candidate_hash,
            decision=decision,
            feedback_mode=self.query_budget.feedback_mode,
            reward_band=RewardBand.WITHHELD,
            public_message=message,
            transcript_hash=self.transcript_hash,
        )

    def _sanitize_feedback(
        self,
        candidate: Candidate,
        feedback: BoundedFeedback,
    ) -> BoundedFeedback:
        if feedback.candidate_hash and feedback.candidate_hash != candidate.candidate_hash:
            raise ValueError("bounded feedback candidate_hash mismatch")
        if self.query_budget.feedback_mode == FeedbackMode.NONE:
            return BoundedFeedback(
                candidate_hash=candidate.candidate_hash,
                decision=feedback.decision,
                feedback_mode=FeedbackMode.NONE,
                reward_band=RewardBand.WITHHELD,
                public_message=feedback.public_message,
            )
        if self.query_budget.feedback_mode == FeedbackMode.PASS_HOLD_DENY:
            return BoundedFeedback(
                candidate_hash=candidate.candidate_hash,
                decision=feedback.decision,
                feedback_mode=FeedbackMode.PASS_HOLD_DENY,
                reward_band=RewardBand.WITHHELD,
                public_message=feedback.public_message,
            )
        return BoundedFeedback(
            candidate_hash=candidate.candidate_hash,
            decision=feedback.decision,
            feedback_mode=FeedbackMode.BAND,
            reward_band=feedback.reward_band,
            public_message=feedback.public_message,
        )

    def _elapsed_band(self, started_at: float) -> int:
        granularity = max(1, self.query_budget.timing_band_seconds)
        elapsed = max(0, int(time.time() - started_at))
        return (elapsed // granularity) * granularity


def assert_bounded_egress(
    public_dict: dict[str, Any],
    *,
    structural_ignore_keys: tuple[str, ...] = (),
) -> None:
    """Fail closed unless a bounded-output dict carries no reward value or data.

    Enforces PROJECT.md invariant "private reward values do not leave the TEE
    unless released through the bounded-output reducer": structurally there must
    be no floats / numeric arrays / oversized blobs (via the shared optimizer
    export guard), and no string field may render a float or a long precise
    integer (a reward value or metric smuggled into ``public_message``).

    ``structural_ignore_keys`` drops top-level keys from the *structural* float
    check only — used for the ``attestation`` subtree, which is public,
    separately-governed environment metadata (e.g. holdout split fractions) and
    legitimately contains config floats that are not reward values. The textual
    reward-value scan still covers the full dict.
    """
    from tinker_delegate.optimizer_export_guard import audit_optimizer_export

    structural_view = public_dict
    if structural_ignore_keys and isinstance(public_dict, dict):
        structural_view = {
            key: value
            for key, value in public_dict.items()
            if key not in structural_ignore_keys
        }
    audit = audit_optimizer_export(structural_view)
    if not audit.allowed:
        raise RewardLeakageError(f"bounded egress rejected: {audit.reason_code}")
    for text in _iter_strings(public_dict):
        # A rendered float — decimal (`0.97`) or signed-exponent scientific
        # notation (`1e-05`, `2e+16`, how a tiny/huge reward reprs) — is a leak.
        if _FLOAT_TEXT_PATTERN.search(text) or _SCI_FLOAT_TEXT_PATTERN.search(text):
            raise RewardLeakageError("bounded egress contains a numeric reward value")
        # A long precise integer is a leak too, but skip hash/address-shaped hex
        # strings (0x-prefixed, or containing a-f) which legitimately hold digit
        # runs; only pure-decimal long integers are treated as suspect.
        if not _is_hex_shaped(text) and _LONG_DIGIT_PATTERN.search(text):
            raise RewardLeakageError("bounded egress contains a numeric reward value")


def _is_hex_shaped(value: str) -> bool:
    body = value[2:] if value.startswith(("0x", "0X")) else value
    if len(body) < 16 or not all(c in "0123456789abcdefABCDEF" for c in body):
        return False
    return value.startswith(("0x", "0X")) or any(c in "abcdefABCDEF" for c in body)


# Real bounded outputs nest only a few levels; a deeper structure (e.g. a hostile
# reducer, or a deep attestation subtree that skips the structural depth check)
# fails closed cleanly here instead of raising an uncontrolled RecursionError.
_MAX_EGRESS_DEPTH = 64


def _iter_strings(node: Any, depth: int = 0):
    if depth > _MAX_EGRESS_DEPTH:
        raise RewardLeakageError("bounded egress structure too deep")
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        # Scan KEYS as well as values: a JSON dict key is egressed text too, so
        # an exact reward smuggled as a key must be caught. Keys are stringified
        # because JSON serializes a non-string key (float 0.9731, long int
        # 123456789012) via its str() form — which is what actually leaks.
        for key, value in node.items():
            yield key if isinstance(key, str) else str(key)
            yield from _iter_strings(value, depth + 1)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_strings(item, depth + 1)


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_hex(_canonical_json(value).encode("utf-8"))


def _hash_public_dicts(values) -> str:
    return _sha256_json(list(values))


def _canonical_json(value: Any) -> str:
    return json.dumps(_stable_public(value), sort_keys=True, separators=(",", ":"))


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
