"""Framework-free core for the OpenProblems denoising private-reward env.

This module holds everything that does NOT depend on `verifiers`, `openenv`,
`anndata`, or any heavy stack, so it is importable and unit-testable with only
numpy. The framework wrapper (`openproblems_denoising.py`) imports this core.

The task is the OpenProblems v1 single-cell RNA-seq *denoising* benchmark, as
used by TTT-Discover (arXiv:2601.16175): observed molecules of a dataset are
partitioned into a `train` and `test` count matrix by binomial sampling. A
candidate denoiser maps the train matrix to a `denoised` matrix; quality is the
mean of a normalized MSE and a normalized Poisson metric in log space.

Bounded-output rule (private-reward invariant): the exact MSE/Poisson values are
computed inside the boundary and are treated as internal. Only a coarse
`RewardBand` — improvement of the candidate over the identity (no-op) baseline —
is allowed to leave. Raw expression values never leave.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

import numpy as np

TARGET_SUM = 1e4  # standard scRNA-seq library-size normalization target


class RewardBand(str, Enum):
    """Coarse, egress-safe reward band (mirrors tinker_delegate.private_reward)."""

    EXCEPTIONAL = "exceptional"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    WITHHELD = "withheld"


def _as_2d_float(matrix: Any) -> np.ndarray:
    arr = np.asarray(matrix, dtype=np.float64)
    if arr.ndim != 2:
        raise ValueError("count matrix must be 2-D (cells x genes)")
    if not np.all(np.isfinite(arr)):
        raise ValueError("count matrix must be finite")
    if np.any(arr < 0):
        raise ValueError("count matrix must be non-negative")
    return arr


def _log_normalize(counts: np.ndarray) -> np.ndarray:
    """Library-size normalize to TARGET_SUM per cell, then log1p."""

    row_sums = counts.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1.0
    normalized = counts / row_sums * TARGET_SUM
    return np.log1p(normalized)


def log_normalized_mse(denoised: np.ndarray, test: np.ndarray) -> float:
    """Mean squared error between log-normalized denoised and test matrices."""

    d = _log_normalize(_as_2d_float(denoised))
    t = _log_normalize(_as_2d_float(test))
    if d.shape != t.shape:
        raise ValueError("denoised and test matrices must share shape")
    return float(np.mean((d - t) ** 2))


def poisson_nll(denoised: np.ndarray, test: np.ndarray) -> float:
    """Mean Poisson negative log-likelihood of test counts under denoised rates.

    Denoised values are treated as non-negative rates; a small epsilon keeps the
    log finite. Lower is better.
    """

    rate = _as_2d_float(denoised)
    target = _as_2d_float(test)
    if rate.shape != target.shape:
        raise ValueError("denoised and test matrices must share shape")
    eps = 1e-8
    rate = rate + eps
    return float(np.mean(rate - target * np.log(rate)))


@dataclass(frozen=True)
class DenoisingMetrics:
    """Internal (TEE-only) exact metrics for one candidate. Do not egress raw."""

    mse: float
    poisson: float
    baseline_mse: float
    baseline_poisson: float

    def mse_improvement(self) -> float:
        """Fractional MSE reduction vs the identity baseline (higher is better)."""

        if self.baseline_mse <= 0:
            return 0.0
        return (self.baseline_mse - self.mse) / self.baseline_mse


def compute_denoising_metrics(
    denoised: np.ndarray,
    train: np.ndarray,
    test: np.ndarray,
) -> DenoisingMetrics:
    """Compute exact denoising metrics for a candidate against the held-out test.

    The identity baseline is the train matrix scaled to the test library size —
    i.e. "no denoising beyond depth matching". Improvement over this baseline is
    the signal the bounded reducer bands.
    """

    train = _as_2d_float(train)
    test = _as_2d_float(test)
    # Depth-match the raw train matrix to the test library size as the baseline
    # denoiser (this is the trivial "scale only" method).
    train_sums = train.sum(axis=1, keepdims=True)
    train_sums[train_sums == 0] = 1.0
    test_sums = test.sum(axis=1, keepdims=True)
    baseline = train / train_sums * test_sums

    return DenoisingMetrics(
        mse=log_normalized_mse(denoised, test),
        poisson=poisson_nll(denoised, test),
        baseline_mse=log_normalized_mse(baseline, test),
        baseline_poisson=poisson_nll(baseline, test),
    )


def reward_band(metrics: DenoisingMetrics) -> RewardBand:
    """Map exact metrics to a coarse, egress-safe band by improvement over baseline.

    Banding is on the MSE improvement fraction, gated by the Poisson constraint
    (a candidate that worsens Poisson vs baseline is capped): TTT-Discover uses
    the MSE as reward "or zero if it violates constraints we add for the Poisson
    score."
    """

    if metrics.poisson > metrics.baseline_poisson:
        # Poisson constraint violated: withhold any positive credit.
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


# Numeric reward for RL trainers that require a scalar. This is a *quantized*
# band value, not the exact MSE, so it still respects the reward-precision
# budget (no exact continuous reward leaves the boundary).
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


def public_problem() -> dict[str, Any]:
    """Public, egress-safe description of the task shown to optimizers."""

    return {
        "task_id": "openproblems_v1_denoising",
        "description": (
            "Denoise a single-cell RNA-seq count matrix. You receive a training "
            "count matrix (a binomial subsample of observed molecules) and must "
            "produce a denoised matrix of the same shape. Quality is measured on "
            "a held-out molecule subsample; only a coarse reward band is returned."
        ),
        "candidate_kind": "denoised_matrix_or_method",
        "reward_kind": "band",
        "reward_bands": [b.value for b in RewardBand if b != RewardBand.WITHHELD],
        "data_sensitivity": "public_benchmark",
        "raw_data_egress": False,
    }
