"""Concrete denoising private-reward environment with hidden-holdout wiring.

This is the concrete counterpart of `SyntheticHiddenKeywordEnvironment`: it wires
`HiddenHoldoutSet` (train / reward / final-validation partitions) into the
OpenProblems-style single-cell denoising reward, and it scores *candidate
denoiser programs* by running them through the real `PythonCandidateSandbox`
rather than accepting a precomputed matrix.

Trust boundary:
- Sealed data: per-cell `train` (observed subsample) and `test` (held-out
  subsample) count vectors. Never egress raw.
- Candidate: a UTF-8 Python program defining `denoise(train)` that maps a
  train count matrix (list of lists) to a same-shape denoised matrix. It runs
  inside the sandbox with only `math`/`random`; it sees the *train* partition
  it is scored on (that input is inside the boundary too) and never sees the
  `test` counts used for scoring.
- Egress: only a coarse `RewardBand`, decisions, hashes, and the holdout public
  manifest. Exact MSE / Poisson values stay internal.

The metric mirrors `environments/openproblems_denoising/denoising_core.py` but is
reimplemented in pure Python (no numpy) so this environment carries no heavy
dependency and stays unit-testable with the rest of `tinker_delegate`. It is a
toy-scale mechanism proof: the sandbox exposes no numpy, so only small matrices
that fit the source/stdout caps can be scored here. Full-scale OpenProblems data
is still scored by the numpy core in `environments/`, which remains `[partial]`
pending real container isolation for untrusted candidate code.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
from enum import Enum
from typing import Any, Mapping, Sequence

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
from tinker_delegate.ladder_release import (
    LadderLeaderboard,
    LadderPolicy,
    PairedTLadderLeaderboard,
)
from tinker_delegate.private_reward_sandbox import (
    PythonCandidateSandbox,
    SandboxOutcome,
    SandboxPolicy,
)

TARGET_SUM = 1e4  # library-size normalization target (mirrors denoising_core)
_POISSON_EPS = 1e-8

# The result sentinel the injected harness prints before the denoised matrix so
# the environment can locate it even if the candidate writes to stdout itself.
_RESULT_SENTINEL = "__DNAI_DENOISED__"


Matrix = list[list[float]]


class SealedCell:
    """One sealed cell: observed `train` counts and held-out `test` counts."""

    __slots__ = ("cell_id", "train", "test")

    def __init__(self, cell_id: str, train: Sequence[float], test: Sequence[float]) -> None:
        train_row = [float(v) for v in train]
        test_row = [float(v) for v in test]
        if not train_row or not test_row:
            raise ValueError("cell train/test rows must be non-empty")
        if len(train_row) != len(test_row):
            raise ValueError("cell train/test rows must share gene count")
        if any((not math.isfinite(v)) or v < 0 for v in train_row + test_row):
            raise ValueError("cell counts must be finite and non-negative")
        self.cell_id = cell_id
        self.train = train_row
        self.test = test_row

    @property
    def n_genes(self) -> int:
        return len(self.train)

    def sealed_bytes(self) -> bytes:
        """Canonical bytes committing the sealed cell into the holdout split."""

        return json.dumps(
            {"cell_id": self.cell_id, "train": self.train, "test": self.test},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class DenoisingHoldoutEnvironment(PrivateRewardEnvironment):
    """Denoising reward over hidden cell partitions, scored via the sandbox."""

    def __init__(
        self,
        cells: Sequence[SealedCell],
        holdout_policy: HoldoutSplitPolicy | None = None,
        query_budget: LeakageBudget | None = None,
        sandbox: PythonCandidateSandbox | None = None,
        max_candidate_bytes: int = 8_192,
        ladder_policy: LadderPolicy | None = None,
        paired_t_ladder: bool = False,
    ) -> None:
        super().__init__()
        if ladder_policy is not None and paired_t_ladder:
            raise ValueError("choose either the fixed-η ladder_policy or paired_t_ladder, not both")
        cell_list = list(cells)
        if not cell_list:
            raise ValueError("denoising environment requires at least one cell")
        n_genes = cell_list[0].n_genes
        if any(cell.n_genes != n_genes for cell in cell_list):
            raise ValueError("all cells must share the same gene count")
        self._cells: dict[str, SealedCell] = {}
        records: dict[str, HoldoutRecord] = {}
        for cell in cell_list:
            if cell.cell_id in self._cells:
                raise ValueError("cell ids must be unique")
            self._cells[cell.cell_id] = cell
            records[cell.cell_id] = HoldoutRecord(
                record_id=cell.cell_id,
                payload=cell.sealed_bytes(),
            )
        self._n_genes = n_genes
        self.holdout = HiddenHoldoutSet(records, holdout_policy)
        self._query_budget = query_budget or LeakageBudget(
            max_queries=self.holdout.policy.max_reward_queries,
            feedback_mode=FeedbackMode.BAND,
        )
        if self._query_budget.max_queries > self.holdout.policy.max_reward_queries:
            raise ValueError("query_budget cannot exceed hidden holdout reward-query budget")
        self._max_candidate_bytes = max_candidate_bytes
        self._sandbox = sandbox or PythonCandidateSandbox(
            SandboxPolicy(timeout_seconds=2.0, max_source_bytes=32_768)
        )
        self._candidate_query_counts: dict[str, int] = {}
        self._accepted_candidates: list[Candidate] = []
        self._final_result: BoundedResult | None = None
        # Opt-in Ladder gate over the adaptive reward-query stream. When set, each
        # reward query advances a running-best leaderboard only on a > η-margin
        # improvement, and the *released* band is the leaderboard best (monotonic,
        # honest under unlimited grinding) rather than the raw per-candidate band.
        self._ladder = LadderLeaderboard(ladder_policy) if ladder_policy is not None else None
        # Opt-in parameter-free (paired-t) Ladder variant. Gates on the continuous
        # per-cell MSE-improvement vector (a per-example score), releasing a new
        # best only when a candidate is statistically significantly better.
        self._paired_t = PairedTLadderLeaderboard() if paired_t_ladder else None

    # -- public problem / schema ------------------------------------------------

    def problem(self) -> PublicProblem:
        return PublicProblem(
            title="Single-cell denoising (hidden holdout)",
            statement=(
                "Submit a UTF-8 Python program defining denoise(train) that maps a "
                "train count matrix (list of lists, cells x genes) to a same-shape "
                "denoised matrix. Only math and random are available; no I/O. The "
                "environment returns only a coarse reward band."
            ),
            public_metadata={
                "environment": "denoising_hidden_holdout",
                "n_genes": self._n_genes,
                "reward_kind": "band",
                "data_sensitivity": "public_benchmark",
                "raw_data_egress": False,
                "holdout": self._holdout_setup_public(),
                "ladder": self._ladder_public(),
            },
        )

    @property
    def candidate_schema(self) -> CandidateSchema:
        return CandidateSchema(
            kind="python_denoiser_program",
            json_schema={
                "type": "string",
                "minLength": 1,
                "maxLength": self._max_candidate_bytes,
                "description": "Python source defining denoise(train) -> matrix",
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
        return _sha256_json(
            {
                "problem": self.problem().to_public_dict(),
                "candidate_schema": self.candidate_schema.to_public_dict(),
                "query_budget": self.query_budget.to_public_dict(),
                "security_tier": self.security_tier.value,
                "optimizer_policy": self.optimizer_policy.to_public_dict(),
                "sandbox_policy": self._sandbox.policy.to_public_dict(),
                "holdout": self._holdout_setup_public(),
                "ladder": self._ladder_public(),
            }
        )

    @property
    def leakage_hash(self) -> str:
        leakage = {
            "problem": self.problem().to_public_dict(),
            "candidate_schema": self.candidate_schema.to_public_dict(),
            "query_budget": self.query_budget.to_public_dict(),
            "optimizer_policy": self.optimizer_policy.to_public_dict(),
            "sandbox_policy": self._sandbox.policy.to_public_dict(),
            "holdout": self.holdout.public_manifest().to_public_dict(),
            "ladder": self._ladder_public(),
            "records": [record.to_public_dict() for record in self.leakage_records()],
        }
        return _sha256_json(leakage)

    # -- policy / reward --------------------------------------------------------

    def acceptance_policy(self, candidate: Candidate) -> Decision:
        decision = super().acceptance_policy(candidate)
        if decision != Decision.PASS:
            return decision
        if self.holdout.closed_to_reward_queries:
            return Decision.POLICY_REJECTED
        if self.holdout.reward_query_count >= self.holdout.policy.max_reward_queries:
            return Decision.BUDGET_EXHAUSTED
        seen = self._candidate_query_counts.get(candidate.candidate_hash, 0)
        if seen >= self.holdout.policy.max_reward_queries_per_candidate:
            return Decision.POLICY_REJECTED
        if _decode_program(candidate) is None:
            return Decision.POLICY_REJECTED
        return Decision.PASS

    def reward(self, candidate: Candidate) -> InternalReward:
        self.holdout.record_reward_query(candidate.candidate_hash)
        self._candidate_query_counts[candidate.candidate_hash] = (
            self._candidate_query_counts.get(candidate.candidate_hash, 0) + 1
        )
        band, metrics, per_cell = self._score_partition(candidate, HoldoutPartition.REWARD)
        reward_metrics: dict[str, Any] = {
            "partition": HoldoutPartition.REWARD.value,
            "reward_band": band.value,
            # Exact metrics stay internal; never placed on bounded feedback.
            "mse": metrics.mse,
            "poisson": metrics.poisson,
            "baseline_mse": metrics.baseline_mse,
            "baseline_poisson": metrics.baseline_poisson,
        }
        if self._paired_t is not None:
            # Parameter-free paired-t gate on the per-cell improvement vector: a
            # new best is released only when it is statistically significantly
            # above the previous best's per-cell vector. Empty vector (no cells)
            # cannot be gated -> fall through to the raw band.
            if per_cell:
                release = self._paired_t.submit(per_cell)
                reward_metrics["paired_t_numerator"] = release.leaderboard_numerator
                reward_metrics["paired_t_denominator"] = release.denominator
                reward_metrics["paired_t_accepted"] = release.accepted
        if self._ladder is not None:
            # Continuous internal score in [0,1]: MSE improvement over baseline,
            # but zeroed when the candidate worsens Poisson NLL (the same domain
            # anti-overfitting rule that caps `reward_band` to negligible), so a
            # candidate cannot climb the leaderboard by trading Poisson for MSE.
            if metrics.poisson > metrics.baseline_poisson:
                score = 0.0
            else:
                score = max(0.0, min(1.0, metrics.mse_improvement()))
            release = self._ladder.submit(score)
            reward_metrics["ladder_step_index"] = release.leaderboard_step_index
            reward_metrics["ladder_denominator"] = release.step_denominator
            reward_metrics["ladder_accepted"] = release.accepted
        return InternalReward(value=band_to_scalar(band), metrics=reward_metrics)

    def output_reducer(self, reward: InternalReward) -> BoundedFeedback:
        if "paired_t_numerator" in reward.metrics:
            # Paired-t gated: release the running-best leaderboard band (the
            # significance-gated best-so-far), mapped from numerator/denominator.
            band = _ladder_band(
                reward.metrics["paired_t_numerator"],
                reward.metrics["paired_t_denominator"],
            )
            message = "bounded denoising paired-t ladder-gated leaderboard band"
            return BoundedFeedback(
                candidate_hash="",
                decision=Decision.PASS,
                feedback_mode=FeedbackMode.BAND,
                reward_band=band,
                public_message=message,
            )
        if "ladder_step_index" in reward.metrics:
            # Ladder-gated: release the running-best leaderboard band, which only
            # advances on a significant improvement, instead of this candidate's
            # raw band. This keeps the released number honest under unlimited
            # adaptive querying of the reused holdout.
            band = _ladder_band(
                reward.metrics["ladder_step_index"],
                reward.metrics["ladder_denominator"],
            )
            message = "bounded denoising ladder-gated leaderboard band"
        else:
            band = RewardBand(reward.metrics.get("reward_band", RewardBand.NEGLIGIBLE.value))
            message = "bounded denoising holdout score"
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
        final_band, _metrics, _per_cell = self._score_partition(
            candidate, HoldoutPartition.FINAL_VALIDATION
        )
        decision = Decision.PASS if final_band != RewardBand.NEGLIGIBLE else Decision.DENY
        attestation = self.attest().to_public_dict()
        attestation["holdout"] = self.holdout.public_manifest().to_public_dict()
        if self._ladder is not None:
            attestation["ladder"] = self._ladder.public_manifest()
        if self._paired_t is not None:
            attestation["ladder"] = self._paired_t.public_manifest()
        self._final_result = BoundedResult(
            decision=decision,
            result_band=final_band,
            accepted_count=self.accepted_count,
            rejected_count=self.rejected_count,
            transcript_hash=self.transcript_hash,
            leakage_hash=self.leakage_hash,
            attestation=attestation,
            public_message="bounded denoising final validation result",
        )
        assert_bounded_egress(
            self._final_result.to_public_dict(), structural_ignore_keys=("attestation",)
        )
        return self._final_result

    # -- internals --------------------------------------------------------------

    def _score_partition(
        self,
        candidate: Candidate,
        partition: HoldoutPartition,
    ) -> tuple[RewardBand, "DenoisingMetrics", list[float]]:
        cell_ids = self.holdout.record_ids_for(partition)
        cells = [self._cells[cell_id] for cell_id in cell_ids]
        empty = DenoisingMetrics(0.0, 0.0, 0.0, 0.0)
        # Per-cell improvement vector (paired-t signal); all-zeros on any failure,
        # length == cell count so the paired-t vector length stays stable.
        zeros = [0.0] * len(cells)
        if not cells:
            return RewardBand.NEGLIGIBLE, empty, zeros
        train = [cell.train for cell in cells]
        test = [cell.test for cell in cells]
        denoised = self._run_candidate(candidate, train)
        if denoised is None:
            return RewardBand.NEGLIGIBLE, empty, zeros
        if len(denoised) != len(train) or any(
            len(row) != self._n_genes for row in denoised
        ):
            return RewardBand.NEGLIGIBLE, empty, zeros
        try:
            metrics = compute_denoising_metrics(denoised, train, test)
            per_cell = per_cell_mse_improvement(denoised, train, test)
        except (ValueError, TypeError):
            return RewardBand.NEGLIGIBLE, empty, zeros
        # Domain anti-overfitting rule: a candidate that worsens Poisson NLL earns
        # no per-cell credit (mirrors the reward_band -> negligible cap).
        if metrics.poisson > metrics.baseline_poisson:
            per_cell = zeros
        return reward_band(metrics), metrics, per_cell

    def _run_candidate(self, candidate: Candidate, train: Matrix) -> Matrix | None:
        program = _decode_program(candidate)
        if program is None:
            return None
        harness_source = _build_harness(program, train)
        harness = Candidate(harness_source.encode("utf-8"))
        if harness.size_bytes > self._sandbox.policy.max_source_bytes:
            return None
        result = self._sandbox.run(harness)
        if result.outcome != SandboxOutcome.PASS:
            return None
        return _parse_denoised(result.stdout, result.stdout_truncated)

    def _holdout_setup_public(self) -> dict[str, Any]:
        manifest = self.holdout.public_manifest().to_public_dict()
        return {
            "split_commitment": manifest["split_commitment"],
            "policy": manifest["policy"],
            "partition_counts": manifest["partition_counts"],
        }

    def _ladder_public(self) -> dict[str, Any] | None:
        """Bounded Ladder descriptor for the audited mechanism, or None."""
        if self._ladder is not None:
            return self._ladder.policy.to_public_dict()
        if self._paired_t is not None:
            return {"variant": "paired_t"}
        return None


# -- pure-Python denoising metrics (mirror of environments/.../denoising_core) --


class DenoisingMetrics:
    __slots__ = ("mse", "poisson", "baseline_mse", "baseline_poisson")

    def __init__(self, mse: float, poisson: float, baseline_mse: float, baseline_poisson: float) -> None:
        self.mse = mse
        self.poisson = poisson
        self.baseline_mse = baseline_mse
        self.baseline_poisson = baseline_poisson

    def mse_improvement(self) -> float:
        if self.baseline_mse <= 0:
            return 0.0
        return (self.baseline_mse - self.mse) / self.baseline_mse


def _validate_matrix(matrix: Any) -> Matrix:
    if not isinstance(matrix, (list, tuple)) or not matrix:
        raise ValueError("matrix must be a non-empty list of rows")
    rows: Matrix = []
    width: int | None = None
    for row in matrix:
        if not isinstance(row, (list, tuple)) or not row:
            raise ValueError("matrix rows must be non-empty lists")
        if width is None:
            width = len(row)
        elif len(row) != width:
            raise ValueError("matrix rows must share width")
        parsed: list[float] = []
        for value in row:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("matrix values must be numeric")
            fvalue = float(value)
            if not math.isfinite(fvalue) or fvalue < 0:
                raise ValueError("matrix values must be finite and non-negative")
            parsed.append(fvalue)
        rows.append(parsed)
    return rows


def _log_normalize(counts: Matrix) -> Matrix:
    out: Matrix = []
    for row in counts:
        total = sum(row) or 1.0
        out.append([math.log1p(value / total * TARGET_SUM) for value in row])
    return out


def log_normalized_mse(denoised: Matrix, test: Matrix) -> float:
    d = _log_normalize(_validate_matrix(denoised))
    t = _log_normalize(_validate_matrix(test))
    if len(d) != len(t) or any(len(a) != len(b) for a, b in zip(d, t)):
        raise ValueError("denoised and test matrices must share shape")
    total = 0.0
    count = 0
    for row_d, row_t in zip(d, t):
        for a, b in zip(row_d, row_t):
            total += (a - b) ** 2
            count += 1
    return total / count if count else 0.0


def poisson_nll(denoised: Matrix, test: Matrix) -> float:
    rate = _validate_matrix(denoised)
    target = _validate_matrix(test)
    if len(rate) != len(target) or any(len(a) != len(b) for a, b in zip(rate, target)):
        raise ValueError("denoised and test matrices must share shape")
    total = 0.0
    count = 0
    for row_r, row_t in zip(rate, target):
        for a, b in zip(row_r, row_t):
            r = a + _POISSON_EPS
            total += r - b * math.log(r)
            count += 1
    return total / count if count else 0.0


def compute_denoising_metrics(denoised: Matrix, train: Matrix, test: Matrix) -> DenoisingMetrics:
    train_m = _validate_matrix(train)
    test_m = _validate_matrix(test)
    baseline: Matrix = []
    for tr, te in zip(train_m, test_m):
        train_sum = sum(tr) or 1.0
        test_sum = sum(te)
        baseline.append([value / train_sum * test_sum for value in tr])
    return DenoisingMetrics(
        mse=log_normalized_mse(denoised, test_m),
        poisson=poisson_nll(denoised, test_m),
        baseline_mse=log_normalized_mse(baseline, test_m),
        baseline_poisson=poisson_nll(baseline, test_m),
    )


def per_cell_mse_improvement(denoised: Matrix, train: Matrix, test: Matrix) -> list[float]:
    """Per-cell MSE improvement over the depth-matched baseline, clamped to [0,1].

    The continuous per-example (per-cell) signal the parameter-free paired-t Ladder
    needs: for each cell, how much the candidate reduces log-normalized MSE vs the
    library-size baseline. Mirrors ``compute_denoising_metrics`` row by row; the
    aggregate mean of this vector tracks the scalar ``mse_improvement``.
    """
    d = _log_normalize(_validate_matrix(denoised))
    test_norm = _log_normalize(_validate_matrix(test))
    train_raw = _validate_matrix(train)
    test_raw = _validate_matrix(test)
    baseline_rows: Matrix = []
    for train_row, test_row in zip(train_raw, test_raw):
        train_sum = sum(train_row) or 1.0
        test_sum = sum(test_row)
        baseline_rows.append([value / train_sum * test_sum for value in train_row])
    baseline_norm = _log_normalize(baseline_rows)

    out: list[float] = []
    for row_d, row_t, row_b in zip(d, test_norm, baseline_norm):
        n = len(row_t) or 1
        mse_d = sum((a - c) ** 2 for a, c in zip(row_d, row_t)) / n
        mse_b = sum((a - c) ** 2 for a, c in zip(row_b, row_t)) / n
        improvement = 0.0 if mse_b <= 0 else (mse_b - mse_d) / mse_b
        out.append(max(0.0, min(1.0, improvement)))
    return out


def reward_band(metrics: DenoisingMetrics) -> RewardBand:
    if metrics.poisson > metrics.baseline_poisson:
        return RewardBand.NEGLIGIBLE
    improvement = metrics.mse_improvement()
    if improvement >= 0.50:
        return RewardBand.EXCEPTIONAL
    if improvement >= 0.25:
        return RewardBand.HIGH
    if improvement >= 0.10:
        return RewardBand.MEDIUM
    if improvement > 0.0:
        return RewardBand.LOW
    return RewardBand.NEGLIGIBLE


_BAND_SCALARS: dict[RewardBand, float] = {
    RewardBand.EXCEPTIONAL: 1.0,
    RewardBand.HIGH: 0.75,
    RewardBand.MEDIUM: 0.5,
    RewardBand.LOW: 0.25,
    RewardBand.NEGLIGIBLE: 0.0,
    RewardBand.WITHHELD: 0.0,
}


def band_to_scalar(band: RewardBand) -> float:
    return _BAND_SCALARS[band]


def _ladder_band(step_index: int, denominator: int) -> RewardBand:
    """Map a Ladder leaderboard best (step index over denominator) to a band.

    Uses the same improvement thresholds as ``reward_band`` because the Ladder
    score fed in is the clamped MSE improvement, so the leaderboard fraction is
    on the same [0,1] improvement scale. ``step_index < 0`` means no candidate has
    cleared the floor yet -> negligible.
    """
    if step_index < 0 or denominator <= 0:
        return RewardBand.NEGLIGIBLE
    fraction = step_index / denominator
    if fraction >= 0.50:
        return RewardBand.EXCEPTIONAL
    if fraction >= 0.25:
        return RewardBand.HIGH
    if fraction >= 0.10:
        return RewardBand.MEDIUM
    if fraction > 0.0:
        return RewardBand.LOW
    return RewardBand.NEGLIGIBLE


# -- candidate program handling ------------------------------------------------


def _decode_program(candidate: Candidate) -> str | None:
    try:
        source = candidate.payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "def denoise" not in source:
        return None
    return source


def _build_harness(program: str, train: Matrix) -> str:
    train_literal = repr([[float(v) for v in row] for row in train])
    return (
        f"{program}\n"
        f"__DNAI_TRAIN__ = {train_literal}\n"
        f"__DNAI_RESULT__ = denoise(__DNAI_TRAIN__)\n"
        f"print({_RESULT_SENTINEL!r})\n"
        f"print(__DNAI_RESULT__)\n"
    )


def _parse_denoised(stdout: str, truncated: bool) -> Matrix | None:
    if truncated:
        # A truncated matrix cannot be parsed safely; fail closed.
        return None
    index = stdout.rfind(_RESULT_SENTINEL)
    if index == -1:
        return None
    payload = stdout[index + len(_RESULT_SENTINEL):].strip()
    if not payload:
        return None
    # Take the first balanced literal after the sentinel.
    try:
        value = ast.literal_eval(payload)
    except (ValueError, SyntaxError):
        # The candidate may have printed extra lines; try the first line only.
        first = payload.splitlines()[0].strip()
        try:
            value = ast.literal_eval(first)
        except (ValueError, SyntaxError):
            return None
    try:
        return _validate_matrix(value)
    except (ValueError, TypeError):
        return None


def _sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: Any) -> str:
    return _sha256_hex(
        json.dumps(_stable_public(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


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
