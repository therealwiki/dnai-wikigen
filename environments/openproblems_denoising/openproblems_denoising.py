"""OpenProblems denoising as a prime-rl / verifiers (v0) private-reward env.

Exposes the standard `load_environment(**env_args) -> vf.Environment` entrypoint
so prime-rl and `vf-eval` can consume it, and so an OpenEnv consumer can reach
it through `vf.OpenEnvEnv`. `verifiers` is imported lazily inside
`load_environment` so this module (and the framework-free core) import and test
without the heavy stack.

Private-reward contract: the reward function computes the exact denoising
metrics inside the boundary but returns only a coarse, quantized band scalar —
never the exact MSE and never raw expression values. The dataset rows carry the
public problem text and a split handle, not the sealed count matrices.
"""
from __future__ import annotations

import json
from typing import Any

from denoising_core import (
    RewardBand,
    band_to_scalar,
    compute_denoising_metrics,
    public_problem,
    reward_band,
)
from denoising_data import DEFAULT_EVAL, DEFAULT_TRAIN, DatasetUnavailable, load_split_pair

import numpy as np


def bounded_denoising_reward(
    completion: Any,
    answer: Any = None,
    state: dict | None = None,
    **kwargs: Any,
) -> float:
    """verifiers-style reward func: returns a quantized reward band scalar.

    `completion` (or `state['denoised']`) must resolve to a denoised count matrix
    for the task's split. `answer` carries the split name. The exact MSE/Poisson
    stay internal; only `band_to_scalar(band)` leaves.
    """

    # Load the split first (infra): a genuinely unavailable dataset is an
    # infrastructure error and must propagate, not be masked as a bad candidate.
    split_name = _resolve_split(answer, state)
    train, test = load_split_pair(split_name)
    try:
        denoised = _resolve_denoised(completion, state)
        metrics = compute_denoising_metrics(denoised, train, test)
        band = reward_band(metrics)
    except (ValueError, TypeError):
        # A malformed / adversarial completion (bad shape, non-numeric, garbage
        # JSON) fails closed to NEGLIGIBLE — matching the private-reward contract
        # so a bad candidate earns no credit and never crashes a rollout or leaks
        # an error body carrying raw content.
        band = RewardBand.NEGLIGIBLE
    if state is not None:
        # Record only the bounded band, never the exact metrics, on the state.
        state.setdefault("metrics", {})["denoising_band"] = band.value
    return band_to_scalar(band)


def score_denoised_matrix(
    denoised: np.ndarray,
    train: np.ndarray,
    test: np.ndarray,
) -> dict[str, Any]:
    """Bounded scoring helper for direct/offline use (no verifiers needed).

    Returns only the band and improvement sign — not the exact metrics.
    """

    metrics = compute_denoising_metrics(denoised, train, test)
    band = reward_band(metrics)
    return {
        "reward_band": band.value,
        "reward_scalar": band_to_scalar(band),
        "improved_over_baseline": metrics.mse_improvement() > 0.0,
        "raw_secret_egress": False,
    }


def _resolve_denoised(completion: Any, state: dict | None) -> np.ndarray:
    if state and "denoised" in state:
        return np.asarray(state["denoised"], dtype=np.float64)
    if isinstance(completion, (list, np.ndarray)):
        return np.asarray(completion, dtype=np.float64)
    if isinstance(completion, str):
        try:
            return np.asarray(json.loads(completion), dtype=np.float64)
        except (ValueError, TypeError) as exc:
            raise ValueError("completion is not a JSON-encoded denoised matrix") from exc
    raise ValueError("could not resolve a denoised matrix from completion/state")


def _resolve_split(answer: Any, state: dict | None) -> str:
    if isinstance(answer, str) and answer:
        return answer
    if state and isinstance(state.get("info"), dict):
        split = state["info"].get("split")
        if isinstance(split, str) and split:
            return split
    return DEFAULT_EVAL


def _build_rows(split_name: str, n: int = 1) -> list[dict[str, Any]]:
    """One public problem row per task. Raw matrices are never placed in rows."""

    problem = public_problem()
    question = json.dumps(problem)
    return [
        {"question": question, "answer": split_name, "info": {"split": split_name}}
        for _ in range(n)
    ]


def load_environment(
    train_dataset: str = DEFAULT_TRAIN,
    eval_dataset: str = DEFAULT_EVAL,
    **env_args: Any,
):
    """Standard verifiers v0 entrypoint. Returns a vf.SingleTurnEnv.

    Raises a clear error if verifiers is not installed; the framework-free core
    (`denoising_core`, `score_denoised_matrix`) does not require it.
    """

    try:
        import verifiers as vf  # noqa: PLC0415
        from datasets import Dataset  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - only without the heavy stack
        raise RuntimeError(
            "verifiers and datasets are required to build the RL environment. "
            "Use score_denoised_matrix()/bounded_denoising_reward() directly for "
            "bounded scoring without the trainer stack."
        ) from exc

    def build_dataset():
        return Dataset.from_list(_build_rows(train_dataset))

    def build_eval_dataset():
        return Dataset.from_list(_build_rows(eval_dataset))

    rubric = vf.Rubric(funcs=[bounded_denoising_reward], weights=[1.0])
    return vf.SingleTurnEnv(
        dataset=build_dataset,
        eval_dataset=build_eval_dataset,
        rubric=rubric,
        **env_args,
    )
