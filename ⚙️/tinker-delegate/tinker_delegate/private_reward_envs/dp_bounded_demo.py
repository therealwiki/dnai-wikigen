"""Bounded demo: privacy-budget-bounded reward release over sealed data.

Runs the synthetic hidden-keyword environment with a differential-privacy budget
attached (`PrivateRewardEnvironment.set_dp_budget`). Each accepted reward query
spends epsilon; once the budget is exhausted, `evaluate` fails closed with a
`budget_exhausted` / `withheld` release — so a coarse band is released for the
first few queries and nothing leaks thereafter. The public packet shows that
transition plus the attested `dp_status`, without exposing hidden records or the
submitted keywords.
"""
from __future__ import annotations

from typing import Any, Iterable

from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode
from tinker_delegate.private_reward import Candidate
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_envs.synthetic_demo import DEMO_RECORDS

# Enough queries to exhaust a 1.0 epsilon budget at 0.4/query (two fit, rest fail
# closed), so the packet demonstrates the transition. Keywords avoid "delta" /
# "epsilon" so they don't collide as substrings of the DP field names in the
# attested `dp_status` (candidates are hashed, but the forbidden-value scan is a
# plain substring check).
DEFAULT_DP_CANDIDATES: tuple[str, ...] = ("alpha", "beta", "gamma", "kappa", "omega")


def run_dp_bounded_reward_demo(
    candidates: Iterable[str] | None = None,
    *,
    max_epsilon: float = 1.0,
    epsilon_per_query: float = 0.4,
) -> dict[str, Any]:
    """Run a DP-budget-bounded reward demo; return bounded public JSON."""

    requested = tuple(candidates or DEFAULT_DP_CANDIDATES)
    env = SyntheticHiddenKeywordEnvironment(DEMO_RECORDS)
    env.set_dp_budget(
        DpAccountant(PrivacyMode.DP, max_epsilon=max_epsilon, max_delta=0.0),
        DpParams(epsilon=epsilon_per_query),
    )

    feedback = [
        env.evaluate(Candidate(candidate.encode("utf-8"))).to_public_dict()
        for candidate in requested
    ]
    final_result = env.finalize().to_public_dict()
    attestation = env.attest().to_public_dict()

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

    released = sum(1 for f in feedback if f["decision"] == "pass")
    withheld = sum(1 for f in feedback if f["decision"] == "budget_exhausted")
    return {
        "demo": "dp_bounded_reward",
        "optimizer_view": env.optimizer_view(),
        "feedback": feedback,
        "final_result": final_result,
        "attestation": attestation,
        "reproducibility_certificate": certificate.to_public_dict(),
        "reward_transcript_commitment": transcript.certified_public_export(),
        "dp_released_count": released,
        "dp_withheld_count": withheld,
        "submitted_candidate_count": len(requested),
        "raw_secret_egress": False,
    }


def _build_demo_certificate(env, final_result, requested, transcript_commitment_hash):
    """Bind the run into a bounded, transcript-bound reproducibility certificate."""
    from tinker_delegate import reproducibility as _repro
    from tinker_delegate.private_reward_envs import synthetic as _env_module

    run_config = _repro.RunConfig(
        optimizer_name="dp_bounded_sweep",
        model_base="none",
        hyperparameters={"candidate_count": len(tuple(requested))},
        max_rounds=len(tuple(requested)),
        target_band="high",
    )
    return _repro.build_reproducibility_certificate(
        run_config=run_config,
        data_commitment=env.environment_hash,
        code_hash=_repro.hash_source_files(_env_module),
        result_hash=final_result["transcript_hash"],
        transcript_commitment_hash=transcript_commitment_hash,
    )


def dp_bounded_demo_forbidden_values(candidates: Iterable[str] | None = None) -> tuple[str, ...]:
    """Values that must not appear in the public demo output."""

    candidate_values = tuple(candidates or DEFAULT_DP_CANDIDATES)
    record_values = tuple(v.decode("utf-8", errors="ignore") for v in DEMO_RECORDS.values())
    return tuple(DEMO_RECORDS) + record_values + candidate_values
