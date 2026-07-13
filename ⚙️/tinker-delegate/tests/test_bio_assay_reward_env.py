import json
import unittest

from tinker_delegate.private_reward import Candidate, Decision, RewardBand
from tinker_delegate.private_reward_envs.bio_assay import (
    BioAssayCandidateSource,
    BioAssayRewardEnvironment,
    encode_assay_candidate,
    run_bio_assay_reward_demo,
)
from tinker_delegate.private_reward_loop import (
    HillClimbOptimizer,
    LLMRepairOptimizer,
    RandomSearchOptimizer,
    StopReason,
    band_rank,
    run_private_reward_loop,
)


class BioAssayRewardEnvTest(unittest.TestCase):
    def test_clean_assay_scores_high_band(self):
        env = BioAssayRewardEnvironment()
        candidate = Candidate(
            payload=encode_assay_candidate(
                [100.0, 101.0, 99.0, 100.0], [10.0, 11.0, 9.0, 10.0], replicates=3
            )
        )
        feedback = env.evaluate(candidate)
        self.assertEqual(feedback.decision, Decision.PASS)
        self.assertGreaterEqual(band_rank(feedback.reward_band), band_rank(RewardBand.HIGH))

    def test_overlapping_controls_score_low(self):
        env = BioAssayRewardEnvironment()
        candidate = Candidate(
            payload=encode_assay_candidate([50.0, 60.0, 40.0], [45.0, 55.0, 35.0])
        )
        feedback = env.evaluate(candidate)
        self.assertLessEqual(band_rank(feedback.reward_band), band_rank(RewardBand.LOW))

    def test_malformed_candidates_rejected(self):
        env = BioAssayRewardEnvironment()
        for bad in (
            b"not json",
            json.dumps({"positive_controls": [1.0]}).encode(),  # too few
            json.dumps(
                {"positive_controls": [1.0, 2.0], "negative_controls": [1.0, 2.0], "notes": "x"}
            ).encode(),  # unknown key -> blocks dual-use text
            json.dumps(
                {"positive_controls": ["a", "b"], "negative_controls": [1.0, 2.0]}
            ).encode(),  # non-numeric
            json.dumps(
                {"positive_controls": [1.0, 2.0], "negative_controls": [1.0, 2.0], "replicates": 0}
            ).encode(),
        ):
            with self.subTest(bad=bad[:24]):
                feedback = env.evaluate(Candidate(payload=bad))
                self.assertEqual(feedback.decision, Decision.POLICY_REJECTED)

    def test_no_raw_measurements_in_bounded_output(self):
        env = BioAssayRewardEnvironment()
        env.evaluate(
            Candidate(payload=encode_assay_candidate([100.0, 101.0], [10.0, 11.0], replicates=3))
        )
        result = env.finalize()
        blob = json.dumps(result.to_public_dict())
        # Exact control values and Z' must not appear anywhere in bounded output.
        self.assertNotIn("z_prime", blob)
        self.assertNotIn("100.0", blob)
        self.assertNotIn("101", blob)

    def test_exact_reward_not_available_to_external_optimizer(self):
        env = BioAssayRewardEnvironment()
        env.evaluate(
            Candidate(payload=encode_assay_candidate([100.0, 101.0], [10.0, 11.0], replicates=3))
        )
        # Default policy is external-bounded: exact reward egress is forbidden.
        with self.assertRaises(PermissionError):
            env.internal_reward_for_optimizer()

    def test_loop_drives_all_optimizers_end_to_end(self):
        for factory in (RandomSearchOptimizer, HillClimbOptimizer, LLMRepairOptimizer):
            with self.subTest(optimizer=factory.__name__):
                env = BioAssayRewardEnvironment(max_queries=16)
                optimizer = factory(BioAssayCandidateSource(), budget=16)
                outcome = run_private_reward_loop(env, optimizer, max_rounds=16)
                self.assertFalse(outcome.raw_secret_egress)
                self.assertGreater(outcome.rounds_run, 0)

    def test_hill_climb_reaches_high_band(self):
        env = BioAssayRewardEnvironment(max_queries=16)
        optimizer = HillClimbOptimizer(BioAssayCandidateSource(), budget=16)
        outcome = run_private_reward_loop(
            env, optimizer, max_rounds=16, target_band=RewardBand.HIGH
        )
        self.assertEqual(outcome.stop_reason, StopReason.TARGET_REACHED)
        self.assertGreaterEqual(band_rank(outcome.best_band), band_rank(RewardBand.HIGH))

    def test_demo_is_bounded_and_deterministic(self):
        first = run_bio_assay_reward_demo()
        second = run_bio_assay_reward_demo()
        self.assertFalse(first["raw_secret_egress"])
        self.assertEqual(
            first["outcome"]["loop_transcript_hash"],
            second["outcome"]["loop_transcript_hash"],
        )


if __name__ == "__main__":
    unittest.main()
