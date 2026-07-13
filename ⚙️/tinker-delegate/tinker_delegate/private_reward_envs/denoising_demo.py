"""Bounded demo runner for the concrete denoising hidden-holdout environment."""

from __future__ import annotations

from typing import Any, Iterable

from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
)
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy


# Small synthetic cells that share a latent gene-rate profile with per-cell
# noise, so pooling information across cells is a genuine denoiser while raw
# train (identity) earns no credit over the depth-matched baseline. Sealed:
# these count vectors never leave the environment boundary.
_DEMO_TRAIN: tuple[tuple[int, ...], ...] = (
    (10, 4, 2, 3, 0, 1),
    (7, 6, 4, 1, 2, 0),
    (9, 5, 3, 2, 1, 1),
    (12, 3, 5, 0, 1, 2),
    (6, 7, 2, 3, 0, 1),
    (8, 5, 4, 2, 2, 0),
    (11, 4, 3, 1, 1, 1),
    (7, 6, 3, 2, 0, 2),
    (9, 5, 3, 2, 1, 1),
    (8, 6, 3, 1, 1, 1),
)
_DEMO_TEST: tuple[tuple[int, ...], ...] = (
    (9, 5, 3, 2, 1, 1),
    (8, 5, 3, 2, 1, 1),
    (10, 4, 4, 1, 1, 1),
    (9, 6, 2, 2, 1, 1),
    (7, 5, 3, 3, 1, 1),
    (9, 5, 3, 2, 1, 1),
    (10, 5, 3, 1, 1, 1),
    (8, 5, 4, 2, 1, 1),
    (9, 5, 3, 2, 1, 1),
    (9, 5, 3, 2, 1, 1),
)


# Candidate denoiser programs submitted by an (untrusted) optimizer. Only their
# reward band leaves the boundary; the program text is public by construction.
IDENTITY_DENOISER = """
def denoise(train):
    return train
""".strip()

POOL_DENOISER = """
def denoise(train):
    n = len(train)
    g = len(train[0])
    col = [sum(train[i][j] for i in range(n)) / n for j in range(g)]
    cs = sum(col) or 1.0
    out = []
    for tr in train:
        depth = sum(tr)
        out.append([col[j] / cs * depth for j in range(g)])
    return out
""".strip()

DEFAULT_DENOISERS: tuple[tuple[str, str], ...] = (
    ("identity", IDENTITY_DENOISER),
    ("pool", POOL_DENOISER),
)


def _demo_cells() -> list[SealedCell]:
    return [
        SealedCell(f"demo-cell-{index:02d}", train, test)
        for index, (train, test) in enumerate(zip(_DEMO_TRAIN, _DEMO_TEST))
    ]


def _demo_policy() -> HoldoutSplitPolicy:
    return HoldoutSplitPolicy(
        train_fraction=0.4,
        reward_fraction=0.3,
        final_validation_fraction=0.3,
        min_train_records=2,
        min_reward_records=2,
        min_final_validation_records=2,
        max_reward_queries=8,
        max_reward_queries_per_candidate=2,
        min_unique_reward_candidates_before_final=1,
    )


def run_denoising_holdout_demo(
    denoisers: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Run a deterministic denoising private-reward demo and return bounded JSON."""

    requested = tuple(denoisers) if denoisers is not None else DEFAULT_DENOISERS
    env = DenoisingHoldoutEnvironment(_demo_cells(), holdout_policy=_demo_policy())
    feedback = []
    for label, program in requested:
        bounded = env.evaluate(Candidate(program.encode("utf-8"))).to_public_dict()
        # The label is optimizer-side metadata; the program text is not echoed.
        feedback.append({"candidate_label": label, **bounded})
    final_result = env.finalize().to_public_dict()
    from tinker_delegate.reward_transcript import RewardTranscript

    transcript = RewardTranscript.from_round_dicts(
        feedback,
        environment_hash=env.environment_hash,
        final_result_hash=final_result["transcript_hash"],
        transcript_chain_head=env.transcript_chain_head,
    )
    certificate = _build_demo_certificate(
        env, final_result, requested, transcript.commitment.commitment_hash
    )
    return {
        "demo": "denoising_hidden_holdout",
        "optimizer_view": env.optimizer_view(),
        "feedback": feedback,
        "final_result": final_result,
        "attestation": env.attest().to_public_dict(),
        "reproducibility_certificate": certificate.to_public_dict(),
        "reward_transcript_commitment": transcript.certified_public_export(),
        "submitted_candidate_count": len(requested),
        "raw_secret_egress": False,
    }


def _build_demo_certificate(env, final_result, requested, transcript_commitment_hash):
    """Bind the run into a bounded, transcript-bound reproducibility certificate."""
    from tinker_delegate import reproducibility as _repro
    from tinker_delegate.private_reward_envs import denoising as _env_module

    run_config = _repro.RunConfig(
        optimizer_name="program_library_sweep",
        model_base="none",
        hyperparameters={"candidate_labels": [label for label, _ in requested]},
        max_rounds=len(requested),
        target_band="high",
    )
    return _repro.build_reproducibility_certificate(
        run_config=run_config,
        data_commitment=env.environment_hash,
        code_hash=_repro.hash_source_files(_env_module),
        result_hash=final_result["transcript_hash"],
        transcript_commitment_hash=transcript_commitment_hash,
    )


def denoising_demo_forbidden_values() -> tuple[str, ...]:
    """Sealed values that must never appear in the public demo output."""

    forbidden: list[str] = []
    for row in _DEMO_TRAIN + _DEMO_TEST:
        forbidden.append(",".join(str(v) for v in row))
        forbidden.append(" ".join(str(v) for v in row))
        forbidden.append(str(list(row)))
    return tuple(forbidden)
