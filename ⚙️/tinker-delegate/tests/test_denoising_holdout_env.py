import json
import unittest

from tinker_delegate.private_reward import Candidate, Decision, FeedbackMode, RewardBand
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
    compute_denoising_metrics,
    reward_band,
)
from tinker_delegate.private_reward_envs.denoising_demo import (
    IDENTITY_DENOISER,
    POOL_DENOISER,
    denoising_demo_forbidden_values,
    run_denoising_holdout_demo,
)
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy


_TRAIN = (
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
_TEST = (
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

_BANNED_IMPORT = "def denoise(train):\n    import os\n    return train\n"
_NO_DENOISE = "def something_else(x):\n    return x\n"
_WRONG_SHAPE = "def denoise(train):\n    return [[1.0]]\n"


def _cells():
    return [SealedCell(f"cell-{i:02d}", _TRAIN[i], _TEST[i]) for i in range(len(_TRAIN))]


def _policy(**overrides):
    base = dict(
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
    base.update(overrides)
    return HoldoutSplitPolicy(**base)


def _env(**overrides):
    return DenoisingHoldoutEnvironment(_cells(), holdout_policy=_policy(**overrides))


class DenoisingMetricTest(unittest.TestCase):
    def test_pure_python_metrics_match_expected_banding(self):
        train = [list(row) for row in _TRAIN]
        test = [list(row) for row in _TEST]
        metrics_identity = compute_denoising_metrics(train, train, test)
        # Identity denoiser: no improvement over the depth-matched baseline.
        self.assertLessEqual(metrics_identity.mse_improvement(), 0.0)
        self.assertEqual(reward_band(metrics_identity), RewardBand.NEGLIGIBLE)

    def test_poisson_constraint_caps_credit(self):
        train = [[10, 0], [0, 10]]
        test = [[9, 1], [1, 9]]
        # A denoiser that inflates rates can lower MSE but blow up Poisson NLL;
        # the constraint must withhold credit.
        inflated = [[1000.0, 1000.0], [1000.0, 1000.0]]
        metrics = compute_denoising_metrics(inflated, train, test)
        if metrics.poisson > metrics.baseline_poisson:
            self.assertEqual(reward_band(metrics), RewardBand.NEGLIGIBLE)


class DenoisingHoldoutEnvironmentTest(unittest.TestCase):
    def test_pool_beats_identity_and_earns_a_band(self):
        env = _env()
        pool_fb = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        ident_fb = env.evaluate(Candidate(IDENTITY_DENOISER.encode("utf-8")))
        self.assertEqual(pool_fb.decision, Decision.PASS)
        self.assertEqual(pool_fb.feedback_mode, FeedbackMode.BAND)
        self.assertNotIn(pool_fb.reward_band, {RewardBand.NEGLIGIBLE, RewardBand.WITHHELD})
        self.assertEqual(ident_fb.reward_band, RewardBand.NEGLIGIBLE)

    def test_banned_import_candidate_scores_negligible_but_consumes_query(self):
        env = _env()
        fb = env.evaluate(Candidate(_BANNED_IMPORT.encode("utf-8")))
        # The program is well-formed (has def denoise) so it is accepted and run,
        # but the sandbox rejects the import, yielding a negligible band.
        self.assertEqual(fb.decision, Decision.PASS)
        self.assertEqual(fb.reward_band, RewardBand.NEGLIGIBLE)
        self.assertEqual(env.holdout.reward_query_count, 1)

    def test_wrong_shape_output_scores_negligible(self):
        env = _env()
        fb = env.evaluate(Candidate(_WRONG_SHAPE.encode("utf-8")))
        self.assertEqual(fb.reward_band, RewardBand.NEGLIGIBLE)

    def test_malformed_candidate_is_policy_rejected_and_not_accepted(self):
        env = _env()
        fb = env.evaluate(Candidate(_NO_DENOISE.encode("utf-8")))
        self.assertEqual(fb.decision, Decision.POLICY_REJECTED)
        self.assertEqual(env.accepted_count, 0)
        self.assertEqual(env.holdout.reward_query_count, 0)

    def test_per_candidate_repeat_cap_is_enforced_without_raising(self):
        env = _env(max_reward_queries_per_candidate=2)
        candidate = Candidate(IDENTITY_DENOISER.encode("utf-8"))
        first = env.evaluate(candidate)
        second = env.evaluate(candidate)
        third = env.evaluate(candidate)
        self.assertEqual(first.decision, Decision.PASS)
        self.assertEqual(second.decision, Decision.PASS)
        self.assertEqual(third.decision, Decision.POLICY_REJECTED)
        self.assertEqual(env.holdout.reward_query_count, 2)

    def test_reward_query_budget_exhaustion_is_bounded(self):
        env = _env(max_reward_queries=2, max_reward_queries_per_candidate=1)
        a = env.evaluate(Candidate(IDENTITY_DENOISER.encode("utf-8")))
        b = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        c = env.evaluate(Candidate(_WRONG_SHAPE.encode("utf-8")))
        self.assertEqual(a.decision, Decision.PASS)
        self.assertEqual(b.decision, Decision.PASS)
        self.assertEqual(c.decision, Decision.BUDGET_EXHAUSTED)

    def test_final_validation_is_one_shot_and_closes_reward_queries(self):
        env = _env()
        env.evaluate(Candidate(IDENTITY_DENOISER.encode("utf-8")))
        env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        final = env.finalize()
        # Pool was submitted last, so final validation lands a positive band.
        self.assertNotEqual(final.result_band, RewardBand.NEGLIGIBLE)
        self.assertEqual(final.decision, Decision.PASS)
        manifest = env.holdout.public_manifest()
        self.assertTrue(manifest.closed_to_reward_queries)
        self.assertEqual(manifest.final_validation_count, 1)
        # Further reward queries after final validation are rejected.
        after = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        self.assertEqual(after.decision, Decision.POLICY_REJECTED)
        # finalize is idempotent.
        self.assertEqual(env.finalize().result_band, final.result_band)

    def test_bounded_outputs_carry_no_raw_counts_or_exact_metrics(self):
        env = _env()
        env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        final = env.finalize()
        blob = json.dumps(
            {
                "optimizer_view": env.optimizer_view(),
                "final": final.to_public_dict(),
                "attestation": env.attest().to_public_dict(),
            }
        )
        for forbidden in denoising_demo_forbidden_values():
            self.assertNotIn(forbidden, blob)
        # Exact metric keys must never appear in any bounded surface.
        self.assertNotIn("baseline_mse", blob)
        self.assertNotIn("poisson", blob)


class DenoisingDemoTest(unittest.TestCase):
    def test_demo_is_bounded_and_ranks_pool_above_identity(self):
        result = run_denoising_holdout_demo()
        self.assertFalse(result["raw_secret_egress"])
        bands = {row["candidate_label"]: row["reward_band"] for row in result["feedback"]}
        self.assertEqual(bands["identity"], RewardBand.NEGLIGIBLE.value)
        self.assertNotIn(bands["pool"], {RewardBand.NEGLIGIBLE.value, RewardBand.WITHHELD.value})
        commitment = result["reward_transcript_commitment"]
        self.assertEqual(commitment["round_count"], result["submitted_candidate_count"])
        self.assertRegex(commitment["transcript_root"], r"^[0-9a-f]{64}$")
        self.assertRegex(commitment["transcript_chain_head"], r"^[0-9a-f]{64}$")
        blob = json.dumps(result)
        for forbidden in denoising_demo_forbidden_values():
            self.assertNotIn(forbidden, blob)
        # No candidate program text should be echoed in the public output.
        self.assertNotIn("def denoise", blob)


if __name__ == "__main__":
    unittest.main()
