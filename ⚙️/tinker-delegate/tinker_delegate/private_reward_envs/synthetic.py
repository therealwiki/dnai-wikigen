"""Synthetic hidden-data private reward environment."""
from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Any, Mapping

from tinker_delegate.private_reward import (
    BoundedFeedback,
    BoundedResult,
    Candidate,
    CandidateSchema,
    Decision,
    FeedbackMode,
    InternalReward,
    LeakageBudget,
    PrivateRewardEnvironment,
    PublicProblem,
    RewardBand,
    SecurityTier,
    assert_bounded_egress,
)
from tinker_delegate.private_reward_holdout import (
    HiddenHoldoutSet,
    HoldoutPartition,
    HoldoutRecord,
    HoldoutSplitPolicy,
)
from tinker_delegate.ladder_release import LadderLeaderboard, LadderPolicy


class SyntheticHiddenKeywordEnvironment(PrivateRewardEnvironment):
    """Toy environment that scores a keyword against hidden record partitions."""

    def __init__(
        self,
        records: Mapping[str, bytes | HoldoutRecord],
        holdout_policy: HoldoutSplitPolicy | None = None,
        query_budget: LeakageBudget | None = None,
        max_candidate_bytes: int = 64,
        ladder_policy: LadderPolicy | None = None,
    ) -> None:
        super().__init__()
        self.holdout = HiddenHoldoutSet(records, holdout_policy)
        self._query_budget = query_budget or LeakageBudget(
            max_queries=self.holdout.policy.max_reward_queries,
            feedback_mode=FeedbackMode.BAND,
        )
        if self._query_budget.max_queries > self.holdout.policy.max_reward_queries:
            raise ValueError("query_budget cannot exceed hidden holdout reward-query budget")
        self._max_candidate_bytes = max_candidate_bytes
        self._accepted_candidates: list[Candidate] = []
        self._final_result: BoundedResult | None = None
        # Opt-in Ladder gate over the adaptive reward-query stream (see
        # ladder_release.py). When set, the released band is the running-best
        # leaderboard, so repeated weak probing cannot move the settled number.
        self._ladder = LadderLeaderboard(ladder_policy) if ladder_policy is not None else None

    def problem(self) -> PublicProblem:
        return PublicProblem(
            title="Synthetic hidden keyword search",
            statement="Submit one UTF-8 keyword. The private environment returns only a bounded score band.",
            public_metadata={
                "environment": "synthetic_hidden_keyword",
                "holdout": self._holdout_setup_public(),
                "ladder": self._ladder_public(),
            },
        )

    @property
    def candidate_schema(self) -> CandidateSchema:
        return CandidateSchema(
            kind="utf8_keyword",
            json_schema={
                "type": "string",
                "minLength": 1,
                "maxLength": self._max_candidate_bytes,
                "pattern": "^[A-Za-z0-9_-]+$",
            },
            max_bytes=self._max_candidate_bytes,
        )

    @property
    def query_budget(self) -> LeakageBudget:
        return self._query_budget

    @property
    def security_tier(self) -> SecurityTier:
        return SecurityTier.INTERNAL_TEE

    @property
    def environment_hash(self) -> str:
        return _sha256_json({
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "security_tier": self.security_tier.value,
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
            "holdout": self._holdout_setup_public(),
            "ladder": self._ladder_public(),
        })

    @property
    def leakage_hash(self) -> str:
        leakage = {
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
            "holdout": self.holdout.public_manifest().to_public_dict(),
            "ladder": self._ladder_public(),
            "records": [record.to_public_dict() for record in self.leakage_records()],
        }
        return _sha256_json(leakage)

    def acceptance_policy(self, candidate: Candidate) -> Decision:
        decision = super().acceptance_policy(candidate)
        if decision != Decision.PASS:
            return decision
        if self.holdout.closed_to_reward_queries:
            return Decision.POLICY_REJECTED
        keyword = _candidate_keyword(candidate)
        if keyword is None:
            return Decision.POLICY_REJECTED
        return Decision.PASS

    def reward(self, candidate: Candidate) -> InternalReward:
        self.holdout.record_reward_query(candidate.candidate_hash)
        score, matches, total = self._score_partition(candidate, HoldoutPartition.REWARD)
        metrics: dict[str, Any] = {
            "partition": HoldoutPartition.REWARD.value,
            "matches": matches,
            "total": total,
        }
        if self._ladder is not None:
            # `score` is already a normalized match fraction in [0,1] (higher
            # better), so it feeds the leaderboard directly.
            release = self._ladder.submit(score)
            metrics["ladder_step_index"] = release.leaderboard_step_index
            metrics["ladder_denominator"] = release.step_denominator
            metrics["ladder_accepted"] = release.accepted
        return InternalReward(value=score, metrics=metrics)

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        if "ladder_step_index" in reward.metrics:
            # Ladder-gated: release the running-best leaderboard band (monotonic,
            # honest under unlimited adaptive querying) instead of this
            # candidate's raw band.
            band = _ladder_band(
                reward.metrics["ladder_step_index"],
                reward.metrics["ladder_denominator"],
            )
            message = "bounded synthetic ladder-gated leaderboard band"
        else:
            band = _score_band(reward.value)
            message = "bounded synthetic holdout score"
        return BoundedFeedback(
            candidate_hash="",
            decision=Decision.PASS,
            feedback_mode=FeedbackMode.BAND,
            reward_band=band,
            public_message=message,
        )

    def evaluate(self, candidate: Candidate) -> BoundedFeedback:
        feedback = super().evaluate(candidate)
        if feedback.decision == Decision.PASS:
            self._accepted_candidates.append(candidate)
        return feedback

    def finalize(self) -> BoundedResult:
        if self._final_result is not None:
            return self._final_result
        if not self._accepted_candidates:
            self._final_result = super().finalize()
            return self._final_result

        candidate = self._accepted_candidates[-1]
        self.holdout.record_final_validation(candidate.candidate_hash)
        final_score, _matches, _total = self._score_partition(candidate, HoldoutPartition.FINAL_VALIDATION)
        final_band = _score_band(final_score)
        decision = Decision.PASS if final_score > 0 else Decision.DENY
        attestation = self.attest().to_public_dict()
        attestation["holdout"] = self.holdout.public_manifest().to_public_dict()
        if self._ladder is not None:
            attestation["ladder"] = self._ladder.public_manifest()
        self._final_result = BoundedResult(
            decision=decision,
            result_band=final_band,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            transcript_hash=self.transcript_hash,
            leakage_hash=self.leakage_hash,
            attestation=attestation,
            public_message="bounded synthetic final validation result",
        )
        assert_bounded_egress(
            self._final_result.to_public_dict(), structural_ignore_keys=("attestation",)
        )
        return self._final_result

    def _score_partition(
        self,
        candidate: Candidate,
        partition: HoldoutPartition,
    ) -> tuple[float, int, int]:
        keyword = _candidate_keyword(candidate)
        if keyword is None:
            return 0.0, 0, 0
        records = self.holdout.records_for(partition)
        if not records:
            return 0.0, 0, 0
        matches = 0
        for record in records:
            text = record.payload.decode("utf-8", errors="ignore").lower()
            if keyword in text:
                matches += 1
        return matches / len(records), matches, len(records)

    def _holdout_setup_public(self) -> dict[str, Any]:
        manifest = self.holdout.public_manifest().to_public_dict()
        return {
            "split_commitment": manifest["split_commitment"],
            "policy": manifest["policy"],
            "partition_counts": manifest["partition_counts"],
        }

    def _ladder_public(self) -> dict[str, Any] | None:
        """Bounded Ladder-policy descriptor for the audited mechanism, or None."""
        if self._ladder is None:
            return None
        return self._ladder.policy.to_public_dict()


def _candidate_keyword(candidate: Candidate) -> str | None:
    try:
        value = candidate.payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    keyword = value.strip().lower()
    if not keyword:
        return None
    if any(not (char.isalnum() or char in {"_", "-"}) for char in keyword):
        return None
    return keyword


def _score_band(score: float) -> RewardBand:
    if score >= 0.9:
        return RewardBand.EXCEPTIONAL
    if score >= 0.5:
        return RewardBand.HIGH
    if score >= 0.25:
        return RewardBand.MEDIUM
    if score > 0:
        return RewardBand.LOW
    return RewardBand.NEGLIGIBLE


def _ladder_band(step_index: int, denominator: int) -> RewardBand:
    """Map a Ladder leaderboard best (step index over denominator) to a band.

    Reuses this env's own ``_score_band`` thresholds because the Ladder score fed
    in is the match fraction, on the same [0,1] scale. ``step_index < 0`` means no
    candidate has cleared the floor yet -> negligible.
    """
    if step_index < 0 or denominator <= 0:
        return RewardBand.NEGLIGIBLE
    return _score_band(step_index / denominator)


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_hex(json.dumps(_stable_public(value), sort_keys=True, separators=(",", ":")).encode("utf-8"))


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
