"""Private reward environment over synthetic assay-QC data.

This is the first concrete, end-to-end private reward environment that the
optimizer-agnostic RLVR loop (`private_reward_loop.py`) can drive: a candidate
"computational-bio program output" (a synthetic assay-QC configuration) receives
reward from a private, TEE-held verifier (the Z'-factor screening-assay quality
score). It closes the loop between three existing pieces:

* `bio_evaluators` — the deterministic synthetic Z'-factor evaluator.
* `private_reward` — the bounded-output reward-environment contract.
* `private_reward_loop` — the swappable-optimizer loop.

The security property mirrors the rest of the substrate:

* The candidate payload is a canonical JSON object of *toy* numeric controls
  (never real bio data, never free text — any string/unknown key is rejected, so
  no dual-use content can ride in on a candidate).
* The exact Z'-factor is the internal reward and is discarded; only a coarse
  ``RewardBand`` leaves the boundary.
* Raw control measurements never appear in any bounded output.

The environment is deliberately synthetic-only and carries no dual-use content,
consistent with `docs/BIO_VALIDATION.md`'s first safe use case.
"""
from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from tinker_delegate.bio_evaluators import SyntheticAssay, z_prime_factor
from tinker_delegate.bio_validation import BioValidationError
from tinker_delegate.private_reward import (
    BoundedFeedback,
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
)
from tinker_delegate.private_reward_loop import CandidateSource

_ALLOWED_KEYS = frozenset({"positive_controls", "negative_controls", "replicates"})
_MAX_CANDIDATE_BYTES = 4096
_MAX_CONTROLS = 64


class BioAssayRewardEnvironment(PrivateRewardEnvironment):
    """Score a candidate synthetic-assay config by its private Z'-factor band.

    Candidates are canonical JSON: ``{"positive_controls": [...],
    "negative_controls": [...], "replicates": int}``. The exact Z'-factor is the
    internal reward; only a ``RewardBand`` is released.
    """

    def __init__(self, *, max_queries: int = 32) -> None:
        super().__init__()
        self._budget = LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND)

    def problem(self) -> PublicProblem:
        return PublicProblem(
            title="Synthetic assay-QC quality search",
            statement=(
                "Submit a synthetic assay configuration (positive/negative control "
                "replicate readings and a replicate count) as canonical JSON. The "
                "private environment scores it with the Z'-factor screening-assay "
                "quality metric and returns only a bounded reward band."
            ),
            public_metadata={
                "environment": "bio_assay_qc",
                "metric": "z_prime_factor",
                "candidate_fields": sorted(_ALLOWED_KEYS),
                "synthetic_only": True,
            },
        )

    @property
    def candidate_schema(self) -> CandidateSchema:
        return CandidateSchema(
            kind="synthetic_assay_json",
            json_schema={
                "type": "object",
                "additionalProperties": False,
                "required": ["positive_controls", "negative_controls"],
                "properties": {
                    "positive_controls": {
                        "type": "array",
                        "items": {"type": "number"},
                        "minItems": 2,
                        "maxItems": _MAX_CONTROLS,
                    },
                    "negative_controls": {
                        "type": "array",
                        "items": {"type": "number"},
                        "minItems": 2,
                        "maxItems": _MAX_CONTROLS,
                    },
                    "replicates": {"type": "integer", "minimum": 1},
                },
            },
            max_bytes=_MAX_CANDIDATE_BYTES,
        )

    @property
    def query_budget(self) -> LeakageBudget:
        return self._budget

    @property
    def security_tier(self) -> SecurityTier:
        return SecurityTier.INTERNAL_TEE

    def acceptance_policy(self, candidate: Candidate) -> Decision:
        decision = super().acceptance_policy(candidate)
        if decision != Decision.PASS:
            return decision
        if _parse_assay(candidate.payload) is None:
            return Decision.POLICY_REJECTED
        return Decision.PASS

    def reward(self, candidate: Candidate) -> InternalReward:
        assay = _parse_assay(candidate.payload)
        if assay is None:  # pragma: no cover - acceptance_policy already guards
            raise BioValidationError("candidate failed assay schema after acceptance")
        pos = [float(v) for v in assay.positive_controls]
        neg = [float(v) for v in assay.negative_controls]
        z_prime = z_prime_factor(pos, neg)
        # Exact Z' and control statistics stay internal; only bands leave.
        return InternalReward(value=z_prime, metrics={"metric": "z_prime_factor"})

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        return BoundedFeedback(
            candidate_hash="",
            decision=Decision.PASS,
            feedback_mode=FeedbackMode.BAND,
            reward_band=_z_prime_band(reward.value),
            public_message="bounded assay-QC reward band",
        )


def _z_prime_band(z_prime: float) -> RewardBand:
    """Map the exact (internal) Z'-factor to a coarse public reward band.

    Z' >= 0.5 is an excellent screening assay; below 0 the control distributions
    overlap and the assay is unacceptable. The finer EXCEPTIONAL/LOW split gives a
    band-guided optimizer signal to climb without revealing the exact value.
    """
    if z_prime >= 0.7:
        return RewardBand.EXCEPTIONAL
    if z_prime >= 0.5:
        return RewardBand.HIGH
    if z_prime >= 0.25:
        return RewardBand.MEDIUM
    if z_prime >= 0.0:
        return RewardBand.LOW
    return RewardBand.NEGLIGIBLE


def _parse_assay(payload: bytes) -> SyntheticAssay | None:
    """Parse a candidate payload into a SyntheticAssay, or None if invalid.

    Rejects anything that is not exactly the numeric assay schema: unknown keys,
    string values, non-finite numbers, or out-of-range sizes. This is what keeps
    dual-use free text and raw record content structurally out of candidates.
    """
    try:
        data = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, Mapping):
        return None
    if set(data.keys()) - _ALLOWED_KEYS:
        return None
    pos = data.get("positive_controls")
    neg = data.get("negative_controls")
    if not _is_number_list(pos) or not _is_number_list(neg):
        return None
    if not (2 <= len(pos) <= _MAX_CONTROLS) or not (2 <= len(neg) <= _MAX_CONTROLS):
        return None
    replicates = data.get("replicates", 1)
    if not isinstance(replicates, int) or isinstance(replicates, bool) or replicates < 1:
        return None
    try:
        return SyntheticAssay(
            positive_controls=[float(v) for v in pos],
            negative_controls=[float(v) for v in neg],
            replicates=replicates,
        )
    except BioValidationError:
        return None


def _is_number_list(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            return False
        if item != item or item in (float("inf"), float("-inf")):
            return False
    return True


def encode_assay_candidate(
    positive_controls: Iterable[float],
    negative_controls: Iterable[float],
    replicates: int = 1,
) -> bytes:
    """Encode an assay config as a canonical candidate payload."""
    payload = {
        "positive_controls": [float(v) for v in positive_controls],
        "negative_controls": [float(v) for v in negative_controls],
        "replicates": int(replicates),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class BioAssayCandidateSource(CandidateSource):
    """Deterministic assay-QC search space for the RLVR loop.

    ``seeds`` returns a spread of configs from overlapping (poor Z') to clean
    (excellent Z'); ``mutate`` deterministically tightens the control spread and
    widens the signal window — a domain-plausible optimizer step toward a higher
    Z'-band. No randomness, so the loop stays replayable inside a TEE.
    """

    def seeds(self) -> list[bytes]:
        return [
            # Overlapping controls -> negligible/low band.
            encode_assay_candidate([50.0, 60.0, 40.0], [45.0, 55.0, 35.0], replicates=1),
            # Some separation, noisy -> low/medium band.
            encode_assay_candidate([90.0, 110.0, 100.0], [30.0, 50.0, 40.0], replicates=2),
            # Clean, well separated -> high/exceptional band.
            encode_assay_candidate([100.0, 101.0, 99.0, 100.0], [10.0, 11.0, 9.0, 10.0], replicates=3),
        ]

    def mutate(self, payload: bytes, step: int) -> bytes:
        assay = _parse_assay(payload)
        if assay is None:
            return self.seeds()[0]
        pos = [float(v) for v in assay.positive_controls]
        neg = [float(v) for v in assay.negative_controls]
        pos_mean = sum(pos) / len(pos)
        neg_mean = sum(neg) / len(neg)
        # Tighten each control toward its mean (reduce sigma) and push the means
        # apart (widen the window) — both raise Z'. Deterministic contraction.
        shrink = 0.5
        spread = 1.0 + 0.25 * (step % 4)
        new_pos = [pos_mean + (v - pos_mean) * shrink + spread for v in pos]
        new_neg = [neg_mean + (v - neg_mean) * shrink - spread for v in neg]
        replicates = min(3, assay.replicates + 1)
        return encode_assay_candidate(new_pos, new_neg, replicates)


def run_bio_assay_reward_demo() -> dict[str, Any]:
    """Deterministic bounded demo: hill-climb a clean assay to a high band."""
    from tinker_delegate.private_reward_loop import (
        HillClimbOptimizer,
        run_private_reward_loop,
    )

    env = BioAssayRewardEnvironment(max_queries=16)
    optimizer = HillClimbOptimizer(BioAssayCandidateSource(), budget=16)
    outcome = run_private_reward_loop(
        env, optimizer, max_rounds=16, target_band=RewardBand.HIGH
    )
    return {
        "demo": "bio_assay_reward",
        "outcome": outcome.to_public_dict(),
        "raw_secret_egress": False,
    }
