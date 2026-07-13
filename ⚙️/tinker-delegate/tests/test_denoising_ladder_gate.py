"""Ladder-gated release wired into the denoising private-reward environment.

Proves the Ladder mechanism (`ladder_release.py`) is not just a standalone
primitive but the live release gate over the denoising env's adaptive
reward-query stream: the released band is the running-best leaderboard, so
repeated weak probing of the reused holdout cannot move the settled number.
"""
import unittest

from tinker_delegate.private_reward import Candidate, RewardBand, assert_bounded_egress
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
)
from tinker_delegate.private_reward_envs.denoising_demo import (
    IDENTITY_DENOISER,
    POOL_DENOISER,
)
from tinker_delegate.private_reward_holdout import HoldoutSplitPolicy
from tinker_delegate.ladder_release import LadderPolicy
from tinker_delegate.private_reward_loop import band_rank

_TRAIN = (
    (10, 4, 2, 3, 0, 1), (7, 6, 4, 1, 2, 0), (9, 5, 3, 2, 1, 1),
    (12, 3, 5, 0, 1, 2), (6, 7, 2, 3, 0, 1), (8, 5, 4, 2, 2, 0),
    (11, 4, 3, 1, 1, 1), (7, 6, 3, 2, 0, 2), (9, 5, 3, 2, 1, 1),
    (8, 6, 3, 1, 1, 1),
)
_TEST = (
    (9, 5, 3, 2, 1, 1), (8, 5, 3, 2, 1, 1), (10, 4, 4, 1, 1, 1),
    (9, 6, 2, 2, 1, 1), (7, 5, 3, 3, 1, 1), (9, 5, 3, 2, 1, 1),
    (10, 5, 3, 1, 1, 1), (8, 5, 4, 2, 1, 1), (9, 5, 3, 2, 1, 1),
    (9, 5, 3, 2, 1, 1),
)


def _cells():
    return [SealedCell(f"cell-{i:02d}", _TRAIN[i], _TEST[i]) for i in range(len(_TRAIN))]


def _policy(**overrides):
    base = dict(
        train_fraction=0.4, reward_fraction=0.3, final_validation_fraction=0.3,
        min_train_records=2, min_reward_records=2, min_final_validation_records=2,
        max_reward_queries=8, max_reward_queries_per_candidate=2,
        min_unique_reward_candidates_before_final=1,
    )
    base.update(overrides)
    return HoldoutSplitPolicy(**base)


def _env(ladder_policy=None, **overrides):
    return DenoisingHoldoutEnvironment(
        _cells(), holdout_policy=_policy(**overrides), ladder_policy=ladder_policy
    )


class DenoisingLadderGateTest(unittest.TestCase):
    def test_ladder_off_by_default_leaves_release_unchanged(self):
        env = _env()
        self.assertIsNone(env.problem().public_metadata["ladder"])
        fb = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        # Un-gated path: the raw per-candidate band and its message.
        self.assertEqual(fb.public_message, "bounded denoising holdout score")

    def test_ladder_gated_release_tracks_monotonic_best(self):
        # η = 0.1 grid. A strong candidate sets the leaderboard; a weak candidate
        # submitted afterwards must RE-RELEASE the best, never drag it down — the
        # honest-number property under adaptive querying of a reused holdout.
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        seq = [IDENTITY_DENOISER, POOL_DENOISER, IDENTITY_DENOISER, POOL_DENOISER]
        bands = [env.evaluate(Candidate(s.encode("utf-8"))).reward_band for s in seq]
        # The released band is monotonic non-decreasing across the whole stream.
        ranks = [band_rank(b) for b in bands]
        self.assertEqual(ranks, sorted(ranks))
        # Weak-after-strong (index 2) re-releases the strong best, not negligible.
        self.assertEqual(bands[2], bands[1])
        self.assertGreater(band_rank(bands[1]), band_rank(RewardBand.NEGLIGIBLE))
        # Every gated release carries the leaderboard message.
        env2 = _env(ladder_policy=LadderPolicy(step_denominator=10))
        fb = env2.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        self.assertEqual(fb.public_message, "bounded denoising ladder-gated leaderboard band")

    def test_only_significant_improvements_advance_the_leaderboard(self):
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        for src in (IDENTITY_DENOISER, POOL_DENOISER, IDENTITY_DENOISER, POOL_DENOISER):
            env.evaluate(Candidate(src.encode("utf-8")))
        manifest = env._ladder.public_manifest()
        # Four probes but only the genuine improvement(s) advanced the board.
        self.assertEqual(manifest["submission_count"], 4)
        self.assertGreaterEqual(manifest["improvement_count"], 1)
        self.assertLess(manifest["improvement_count"], manifest["submission_count"])
        self.assertLessEqual(manifest["improvement_count"], manifest["step_denominator"])

    def test_ladder_policy_is_in_the_audited_public_surfaces(self):
        plain = _env()
        gated = _env(ladder_policy=LadderPolicy(step_denominator=20))
        # The mechanism a third party audits must reflect the Ladder parameters,
        # so both the environment hash and leakage hash change when it is active.
        self.assertNotEqual(plain.environment_hash, gated.environment_hash)
        self.assertNotEqual(plain.leakage_hash, gated.leakage_hash)
        self.assertEqual(
            gated.problem().public_metadata["ladder"]["step_denominator"], 20
        )

    def test_gated_feedback_and_final_are_egress_safe(self):
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        fb = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        assert_bounded_egress(fb.to_public_dict())
        result = env.finalize()
        # The final attestation records bounded Ladder accounting.
        self.assertIn("ladder", result.attestation)
        self.assertEqual(result.attestation["ladder"]["submission_count"], 1)
        assert_bounded_egress(
            result.to_public_dict(), structural_ignore_keys=("attestation",)
        )


if __name__ == "__main__":
    unittest.main()
