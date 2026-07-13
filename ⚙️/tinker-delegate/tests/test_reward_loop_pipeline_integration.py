"""End-to-end integration of the RLVR reward-loop side over sealed data.

The bio pipeline test covers the diligence/review path; this covers the
private verified-reward path, proving those modules compose:

  canary pre-screen (clear)            canary
    -> run_private_reward_loop         private_reward_loop (swappable optimizer)
       with a DP budget attached       dp_accounting + private_reward.set_dp_budget
    -> reproducibility certificate      reproducibility.certify_loop_run
    -> verify certificate               reproducibility.verify_reproducibility_certificate

Only bounded bands/hashes/attestations cross the boundary: the loop never emits
raw records, the DP budget is charged per accepted query and its status appears
in the bounded attestation, a tripped canary would fail the run closed before any
optimization, and the certificate binds the reward transcript commitment.
"""
import unittest

from tinker_delegate.canary import CanaryCandidate, CanarySentinel
from tinker_delegate.dp_accounting import DpAccountant, DpParams, PrivacyMode
from tinker_delegate.private_reward import FeedbackMode, LeakageBudget, RewardBand
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    PoolCandidateSource,
    StopReason,
    run_private_reward_loop,
)
from tinker_delegate.private_reward_envs.synthetic import SyntheticHiddenKeywordEnvironment
from tinker_delegate.reproducibility import (
    RunConfig,
    certify_loop_run,
    hash_code_identity,
    verify_reproducibility_certificate,
)

_RECORDS = {f"rec-{i}": f"the alpha marker {i}".encode() for i in range(10)}


def _make_env():
    return SyntheticHiddenKeywordEnvironment(
        _RECORDS,
        holdout_policy=HoldoutSplitPolicy(max_reward_queries=16),
        query_budget=LeakageBudget(max_queries=16, feedback_mode=FeedbackMode.BAND),
    )


class RewardLoopPipelineIntegrationTest(unittest.TestCase):
    def test_clear_canary_then_dp_bounded_loop_yields_verifiable_certificate(self):
        # 1. Canary pre-screen on a FRESH environment: a decoy that must never
        # score high. Clear -> the loop is allowed to start.
        report = CanarySentinel(
            [CanaryCandidate(b"zzzjunk-decoy", max_band=RewardBand.LOW)]
        ).screen(_make_env())
        self.assertTrue(report.clear)

        # 2. Run the loop with a DP budget attached. A swappable HillClimb
        # optimizer draws from a bounded candidate pool.
        env = _make_env()
        env.set_dp_budget(
            DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=0.0),
            DpParams(epsilon=0.5),
        )
        outcome = run_private_reward_loop(
            env,
            HillClimbOptimizer(PoolCandidateSource([b"alpha", b"beta", b"gamma"]), budget=8),
            max_rounds=8,
            canary_report=report,
        )
        self.assertNotEqual(outcome.stop_reason, StopReason.CANARY_TRIPPED)

        # 3. Bounded attestation carries the DP status; no raw record egress.
        attest = outcome.result.attestation
        self.assertIn("dp_status", attest)
        public = outcome.certified_public_export()
        blob = repr(public).lower()
        for secret in ("alpha marker", "rec-0", "rec-1"):
            self.assertNotIn(secret, blob)

        # 4. Certify the run and verify the certificate; the transcript commitment
        # is folded into the certificate hash (bind_transcript=True by default).
        cert = certify_loop_run(
            outcome,
            run_config=RunConfig(
                optimizer_name="hillclimb",
                model_base="none",
                hyperparameters={},
                max_rounds=8,
                target_band="high",
            ),
            environment=env,
            code_hash=hash_code_identity("synthetic-hidden-keyword"),
        )
        self.assertTrue(verify_reproducibility_certificate(cert))
        self.assertTrue(cert.transcript_commitment_hash)

    def test_tripped_canary_fails_the_run_closed_before_optimizing(self):
        # A canary that DID score high on the fresh screen: the loop must refuse
        # to optimize and stop closed, emitting no rewarded rounds.
        env = _make_env()
        # "alpha" scores high in this synthetic env, so a canary asserting it must
        # stay LOW trips the sentinel.
        report = CanarySentinel(
            [CanaryCandidate(b"alpha", max_band=RewardBand.LOW)]
        ).screen(_make_env())
        self.assertFalse(report.clear)

        outcome = run_private_reward_loop(
            env,
            HillClimbOptimizer(PoolCandidateSource([b"alpha", b"beta"]), budget=8),
            max_rounds=8,
            canary_report=report,
        )
        self.assertEqual(outcome.stop_reason, StopReason.CANARY_TRIPPED)
        self.assertEqual(len(outcome.rounds), 0)


if __name__ == "__main__":
    unittest.main()
