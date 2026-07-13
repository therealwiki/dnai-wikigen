"""Bounded demo runner for the assay-QC program private-reward environment.

Mirrors `denoising_demo.py`: it evaluates a handful of candidate QC programs
against sealed raw plate readings and emits only bounded per-candidate reward
bands plus the final result and attestation. The raw well readings are sealed and
must never appear in the output; `bio_assay_program_demo_forbidden_values()`
enumerates them for the CLI leakage guard.
"""
from __future__ import annotations

from typing import Any, Iterable

from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_envs.bio_assay_program import (
    BioAssayProgramEnvironment,
)

# Sealed raw wells: a clean signal window (positives ~100, negatives ~10) with a
# high-side outlier well in each control set. A good QC program drops the outlier
# and scores a higher Z'-band. These readings never leave the environment.
_DEMO_POSITIVE_WELLS: tuple[float, ...] = (100.0, 101.0, 99.0, 100.5, 98.5, 140.0)
_DEMO_NEGATIVE_WELLS: tuple[float, ...] = (10.0, 11.0, 9.0, 10.5, 9.5, 40.0)


# Candidate QC programs submitted by an (untrusted) optimizer. Only their reward
# band leaves the boundary; the program text is public by construction.
PASSTHROUGH_QC = """
def process(positive_wells, negative_wells):
    return (positive_wells, negative_wells)
""".strip()

DROP_EXTREMES_QC = """
def process(positive_wells, negative_wells):
    def trim(xs):
        s = sorted(xs)
        return s[1:-1] if len(s) > 3 else s
    return (trim(positive_wells), trim(negative_wells))
""".strip()

MAD_FILTER_QC = """
def process(positive_wells, negative_wells):
    def med(xs):
        s = sorted(xs); n = len(s)
        return s[n//2] if n % 2 else (s[n//2-1]+s[n//2])/2.0
    def keep(xs):
        m = med(xs)
        devs = sorted(abs(x-m) for x in xs)
        k = devs[len(devs)//2] or 1.0
        out = [x for x in xs if abs(x-m) <= 3.0*k]
        return out if len(out) >= 2 else xs
    return (keep(positive_wells), keep(negative_wells))
""".strip()

DEFAULT_QC_PROGRAMS: tuple[tuple[str, str], ...] = (
    ("passthrough", PASSTHROUGH_QC),
    ("drop_extremes", DROP_EXTREMES_QC),
    ("mad_filter", MAD_FILTER_QC),
)


def run_bio_assay_program_reward_demo(
    programs: Iterable[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    """Run a deterministic assay-QC program private-reward demo (bounded JSON)."""

    requested = tuple(programs) if programs is not None else DEFAULT_QC_PROGRAMS
    env = BioAssayProgramEnvironment(
        _DEMO_POSITIVE_WELLS,
        _DEMO_NEGATIVE_WELLS,
        max_queries=len(requested) + 1,
    )
    feedback = []
    for label, program in requested:
        bounded = env.evaluate(Candidate(program.encode("utf-8"))).to_public_dict()
        # The label is optimizer-side metadata; the program text is not echoed.
        feedback.append({"candidate_label": label, **bounded})
    final_result = env.finalize().to_public_dict()
    # Proof-carrying transcript: commit the bounded per-candidate feedback into a
    # Merkle root bound to the environment hash and final result hash, so an
    # auditor can later be shown that a single candidate's band belongs to this
    # attested run without revealing the others.
    from tinker_delegate.reward_transcript import RewardTranscript

    transcript = RewardTranscript.from_round_dicts(
        feedback,
        environment_hash=env.environment_hash,
        final_result_hash=final_result["transcript_hash"],
        transcript_chain_head=env.transcript_chain_head,
    )
    # Bind the transcript commitment into the certificate so one certificate hash
    # covers config + data + code + result + the proof-carrying transcript.
    certificate = _build_demo_certificate(
        env, final_result, requested, transcript.commitment.commitment_hash
    )
    return {
        "demo": "bio_assay_program_qc",
        "optimizer_view": env.optimizer_view(),
        "feedback": feedback,
        "final_result": final_result,
        "attestation": env.attest().to_public_dict(),
        "reproducibility_certificate": certificate.to_public_dict(),
        "reward_transcript_commitment": transcript.certified_public_export(),
        "submitted_candidate_count": len(requested),
        "raw_secret_egress": False,
    }


def _build_demo_certificate(env, final_result, requested, transcript_commitment_hash=""):
    """Bind this demo run into a bounded, verifiable reproducibility certificate."""
    from tinker_delegate import reproducibility as _repro
    from tinker_delegate.private_reward_envs import bio_assay_program as _prog_module

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
        code_hash=_repro.hash_source_files(_prog_module),
        result_hash=final_result["transcript_hash"],
        transcript_commitment_hash=transcript_commitment_hash,
    )


def bio_assay_program_demo_forbidden_values() -> tuple[str, ...]:
    """Sealed well readings that must never appear in the public demo output."""

    forbidden: list[str] = []
    for well in _DEMO_POSITIVE_WELLS + _DEMO_NEGATIVE_WELLS:
        forbidden.append(str(well))
    forbidden.append(str(list(_DEMO_POSITIVE_WELLS)))
    forbidden.append(str(list(_DEMO_NEGATIVE_WELLS)))
    return tuple(forbidden)
