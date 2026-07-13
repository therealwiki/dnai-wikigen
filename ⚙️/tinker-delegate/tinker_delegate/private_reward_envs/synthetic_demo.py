"""Bounded demo runner for the synthetic hidden-keyword environment."""

from __future__ import annotations

from typing import Any, Iterable

from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment


DEMO_RECORDS: dict[str, bytes] = {
    "demo-record-00": b"sealed alpha pathway signal",
    "demo-record-01": b"sealed alpha validation note",
    "demo-record-02": b"sealed beta control sample",
    "demo-record-03": b"sealed alpha benchmark example",
    "demo-record-04": b"sealed gamma background row",
    "demo-record-05": b"sealed alpha private reward row",
    "demo-record-06": b"sealed beta synthetic holdout",
    "demo-record-07": b"sealed alpha final check",
    "demo-record-08": b"sealed delta unrelated baseline",
    "demo-record-09": b"sealed alpha hidden corpus",
}

DEFAULT_CANDIDATES: tuple[str, ...] = ("alpha", "beta", "omega")


def run_synthetic_hidden_keyword_demo(candidates: Iterable[str] | None = None) -> dict[str, Any]:
    """Run a deterministic hidden-data reward demo and return bounded public JSON."""

    requested_candidates = tuple(candidates or DEFAULT_CANDIDATES)
    env = SyntheticHiddenKeywordEnvironment(DEMO_RECORDS)
    feedback = [
        env.evaluate(Candidate(candidate.encode("utf-8"))).to_public_dict()
        for candidate in requested_candidates
    ]
    final_result = env.finalize().to_public_dict()
    from tinker_delegate.reward_transcript import RewardTranscript

    transcript = RewardTranscript.from_round_dicts(
        feedback,
        environment_hash=env.environment_hash,
        final_result_hash=final_result["transcript_hash"],
        transcript_chain_head=env.transcript_chain_head,
    )
    certificate = _build_demo_certificate(
        env, final_result, requested_candidates, transcript.commitment.commitment_hash
    )
    return {
        "demo": "synthetic_hidden_keyword",
        "optimizer_view": env.optimizer_view(),
        "feedback": feedback,
        "final_result": final_result,
        "attestation": env.attest().to_public_dict(),
        "reproducibility_certificate": certificate.to_public_dict(),
        "reward_transcript_commitment": transcript.certified_public_export(),
        "submitted_candidate_count": len(requested_candidates),
        "raw_secret_egress": False,
    }


def _build_demo_certificate(env, final_result, candidates, transcript_commitment_hash):
    """Bind the run into a bounded, transcript-bound reproducibility certificate."""
    from tinker_delegate import reproducibility as _repro
    from tinker_delegate.private_reward_envs import synthetic as _env_module

    run_config = _repro.RunConfig(
        optimizer_name="candidate_sweep",
        model_base="none",
        hyperparameters={"candidate_count": len(tuple(candidates))},
        max_rounds=len(tuple(candidates)),
        target_band="high",
    )
    return _repro.build_reproducibility_certificate(
        run_config=run_config,
        data_commitment=env.environment_hash,
        code_hash=_repro.hash_source_files(_env_module),
        result_hash=final_result["transcript_hash"],
        transcript_commitment_hash=transcript_commitment_hash,
    )


def hidden_demo_forbidden_values(candidates: Iterable[str] | None = None) -> tuple[str, ...]:
    """Values that must not appear in the public demo output."""

    candidate_values = tuple(candidates or DEFAULT_CANDIDATES)
    record_values = tuple(value.decode("utf-8", errors="ignore") for value in DEMO_RECORDS.values())
    return tuple(DEMO_RECORDS) + record_values + candidate_values
