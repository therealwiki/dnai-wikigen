"""Private reward environment that scores candidate assay-QC *programs*.

This is the program-candidate counterpart of `bio_assay.BioAssayRewardEnvironment`.
Instead of submitting a static assay configuration, the candidate is a UTF-8
Python program that *processes sealed raw plate readings* into cleaned controls,
and the private, TEE-held verifier scores the Z'-factor of what the program
produced. It is the same shape as `DenoisingHoldoutEnvironment` (candidate
programs run through `PythonCandidateSandbox`), applied to a real computational-bio
QC task: robust control selection / outlier removal on a screening plate.

Trust boundary:
- Sealed data: raw positive/negative well intensity readings (with injected
  outliers). Never egress raw.
- Candidate: a UTF-8 Python program defining
  ``process(positive_wells, negative_wells) -> (clean_positive, clean_negative)``.
  It runs in the sandbox with only ``math``/``random`` and no I/O. It sees the
  sealed wells it is scored on (that input is inside the boundary too).
- Egress: only a coarse ``RewardBand`` and hashes. The exact Z'-factor and raw
  readings stay internal.

Anti-fabrication rule: every value the program returns must be a member of the
corresponding sealed well readings (matched from a multiset within a tight
tolerance). A program may therefore *filter and reorder* wells (e.g. drop
outliers) but cannot fabricate values or move positives into the negative set to
fake a high Z'. This keeps the reward a real QC signal rather than a gaming
target.

Synthetic-only, no dual-use content, consistent with `docs/BIO_VALIDATION.md`'s
first safe use case.
"""
from __future__ import annotations

import ast
import math
from typing import Any, Sequence

from tinker_delegate.bio_evaluators import z_prime_factor
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
from tinker_delegate.private_reward_envs.bio_assay import _z_prime_band
from tinker_delegate.private_reward_loop import CandidateSource
from tinker_delegate.private_reward_sandbox import (
    PythonCandidateSandbox,
    SandboxOutcome,
    SandboxPolicy,
)

_MAX_CANDIDATE_BYTES = 8_192
_MIN_CONTROLS = 2
_MEMBERSHIP_TOL = 1e-9
_RESULT_SENTINEL = "__DNAI_ASSAY_QC__"


class BioAssayProgramEnvironment(PrivateRewardEnvironment):
    """Score a candidate assay-QC program by the Z'-factor of its output controls."""

    def __init__(
        self,
        positive_wells: Sequence[float],
        negative_wells: Sequence[float],
        *,
        replicates: int = 3,
        max_queries: int = 32,
        sandbox: PythonCandidateSandbox | None = None,
    ) -> None:
        super().__init__()
        pos = [float(v) for v in positive_wells]
        neg = [float(v) for v in negative_wells]
        if len(pos) < _MIN_CONTROLS or len(neg) < _MIN_CONTROLS:
            raise ValueError("environment requires at least 2 positive and 2 negative wells")
        if any(not math.isfinite(v) for v in pos + neg):
            raise ValueError("well readings must be finite")
        if replicates < 1:
            raise ValueError("replicates must be >= 1")
        self._positive_wells = pos
        self._negative_wells = neg
        self._replicates = replicates
        self._budget = LeakageBudget(max_queries=max_queries, feedback_mode=FeedbackMode.BAND)
        self._sandbox = sandbox or PythonCandidateSandbox(
            SandboxPolicy(timeout_seconds=2.0, max_source_bytes=32_768)
        )

    def problem(self) -> PublicProblem:
        return PublicProblem(
            title="Assay-QC control selection (sealed plate)",
            statement=(
                "Submit a UTF-8 Python program defining "
                "process(positive_wells, negative_wells) -> (clean_positive, "
                "clean_negative). It receives sealed raw well readings and must "
                "return cleaned control replicates selected from those readings "
                "(you may drop outliers but not fabricate values). Only math and "
                "random are available; no I/O. The environment returns only a "
                "bounded Z'-factor reward band."
            ),
            public_metadata={
                "environment": "bio_assay_program_qc",
                "metric": "z_prime_factor",
                "n_positive_wells": len(self._positive_wells),
                "n_negative_wells": len(self._negative_wells),
                "synthetic_only": True,
                "raw_data_egress": False,
            },
        )

    @property
    def candidate_schema(self) -> CandidateSchema:
        return CandidateSchema(
            kind="python_assay_qc_program",
            json_schema={
                "type": "string",
                "minLength": 1,
                "maxLength": _MAX_CANDIDATE_BYTES,
                "description": "Python source defining process(positive_wells, negative_wells)",
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
        if _decode_program(candidate) is None:
            return Decision.POLICY_REJECTED
        return Decision.PASS

    def reward(self, candidate: Candidate) -> InternalReward:
        controls = self._run_candidate(candidate)
        if controls is None:
            # Sandbox failure, bad output, or fabricated values fail closed.
            return InternalReward(value=float("-inf"), metrics={"metric": "z_prime_factor", "valid": False})
        clean_pos, clean_neg = controls
        z_prime = z_prime_factor(clean_pos, clean_neg)
        return InternalReward(value=z_prime, metrics={"metric": "z_prime_factor", "valid": True})

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        band = _z_prime_band(reward.value) if reward.metrics.get("valid") else RewardBand.NEGLIGIBLE
        return BoundedFeedback(
            candidate_hash="",
            decision=Decision.PASS,
            feedback_mode=FeedbackMode.BAND,
            reward_band=band,
            public_message="bounded assay-QC program reward band",
        )

    def _run_candidate(self, candidate: Candidate) -> tuple[list[float], list[float]] | None:
        program = _decode_program(candidate)
        if program is None:
            return None
        harness_source = _build_harness(program, self._positive_wells, self._negative_wells)
        harness = Candidate(harness_source.encode("utf-8"))
        if harness.size_bytes > self._sandbox.policy.max_source_bytes:
            return None
        result = self._sandbox.run(harness)
        if result.outcome != SandboxOutcome.PASS:
            return None
        parsed = _parse_controls(result.stdout, result.stdout_truncated)
        if parsed is None:
            return None
        clean_pos, clean_neg = parsed
        if not _is_subset_multiset(clean_pos, self._positive_wells):
            return None
        if not _is_subset_multiset(clean_neg, self._negative_wells):
            return None
        if len(clean_pos) < _MIN_CONTROLS or len(clean_neg) < _MIN_CONTROLS:
            return None
        return clean_pos, clean_neg


def _decode_program(candidate: Candidate) -> str | None:
    try:
        source = candidate.payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "def process" not in source:
        return None
    return source


def _build_harness(program: str, positive: Sequence[float], negative: Sequence[float]) -> str:
    pos_literal = repr([float(v) for v in positive])
    neg_literal = repr([float(v) for v in negative])
    return (
        f"{program}\n"
        f"__DNAI_POS__ = {pos_literal}\n"
        f"__DNAI_NEG__ = {neg_literal}\n"
        f"__DNAI_RESULT__ = process(list(__DNAI_POS__), list(__DNAI_NEG__))\n"
        f"print({_RESULT_SENTINEL!r})\n"
        f"print(__DNAI_RESULT__)\n"
    )


def _parse_controls(stdout: str, truncated: bool) -> tuple[list[float], list[float]] | None:
    if truncated:
        return None
    index = stdout.rfind(_RESULT_SENTINEL)
    if index == -1:
        return None
    payload = stdout[index + len(_RESULT_SENTINEL):].strip()
    if not payload:
        return None
    first = payload.splitlines()[0].strip()
    try:
        value = ast.literal_eval(first)
    except (ValueError, SyntaxError):
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 2:
        return None
    pos = _coerce_float_list(value[0])
    neg = _coerce_float_list(value[1])
    if pos is None or neg is None:
        return None
    return pos, neg


def _coerce_float_list(value: Any) -> list[float] | None:
    if not isinstance(value, (list, tuple)) or not value:
        return None
    out: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            return None
        f = float(item)
        if not math.isfinite(f):
            return None
        out.append(f)
    return out


def _is_subset_multiset(subset: Sequence[float], universe: Sequence[float]) -> bool:
    """True if every value in `subset` can be matched to a distinct member of
    `universe` within tolerance (a multiset containment check)."""
    remaining = list(universe)
    for value in subset:
        matched = -1
        for i, candidate in enumerate(remaining):
            if abs(candidate - value) <= _MEMBERSHIP_TOL:
                matched = i
                break
        if matched < 0:
            return False
        remaining.pop(matched)
    return True


# A small library of interchangeable candidate QC programs. The loop can drive
# any of these; the trimmed/robust programs remove outliers and score higher.
_PASSTHROUGH = (
    "def process(positive_wells, negative_wells):\n"
    "    return (positive_wells, negative_wells)\n"
)
_DROP_EXTREMES = (
    "def process(positive_wells, negative_wells):\n"
    "    def trim(xs):\n"
    "        s = sorted(xs)\n"
    "        return s[1:-1] if len(s) > 3 else s\n"
    "    return (trim(positive_wells), trim(negative_wells))\n"
)
_MAD_FILTER = (
    "def process(positive_wells, negative_wells):\n"
    "    def med(xs):\n"
    "        s = sorted(xs); n = len(s)\n"
    "        return s[n//2] if n % 2 else (s[n//2-1]+s[n//2])/2.0\n"
    "    def keep(xs):\n"
    "        m = med(xs)\n"
    "        devs = sorted(abs(x-m) for x in xs)\n"
    "        k = devs[len(devs)//2] or 1.0\n"
    "        out = [x for x in xs if abs(x-m) <= 3.0*k]\n"
    "        return out if len(out) >= 2 else xs\n"
    "    return (keep(positive_wells), keep(negative_wells))\n"
)
_PROGRAM_LIBRARY = (_PASSTHROUGH, _DROP_EXTREMES, _MAD_FILTER)


class BioAssayProgramCandidateSource(CandidateSource):
    """Search space of interchangeable assay-QC programs for the RLVR loop."""

    def seeds(self) -> list[bytes]:
        return [program.encode("utf-8") for program in _PROGRAM_LIBRARY]

    def mutate(self, payload: bytes, step: int) -> bytes:
        # Deterministically walk the program library; robust filters score higher.
        return _PROGRAM_LIBRARY[step % len(_PROGRAM_LIBRARY)].encode("utf-8")


def run_bio_assay_program_demo() -> dict[str, Any]:
    """Deterministic bounded demo: hill-climb over QC programs on a noisy plate."""
    from tinker_delegate.private_reward_loop import (
        HillClimbOptimizer,
        run_private_reward_loop,
    )

    # A clean signal window with one high-side outlier in each control set.
    env = BioAssayProgramEnvironment(
        positive_wells=[100.0, 101.0, 99.0, 100.5, 140.0],
        negative_wells=[10.0, 11.0, 9.0, 10.5, 40.0],
        max_queries=16,
    )
    optimizer = HillClimbOptimizer(BioAssayProgramCandidateSource(), budget=16)
    outcome = run_private_reward_loop(
        env, optimizer, max_rounds=16, target_band=RewardBand.HIGH
    )
    return {
        "demo": "bio_assay_program",
        "outcome": outcome.to_public_dict(),
        "raw_secret_egress": False,
    }
