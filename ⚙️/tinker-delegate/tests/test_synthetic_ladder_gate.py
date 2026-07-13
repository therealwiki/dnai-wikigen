"""Ladder-gated release wired into the synthetic hidden-keyword environment.

Confirms the Ladder gate (`ladder_release.py`) generalizes across private-reward
environments with different score semantics — not just denoising — by making the
released band the running-best leaderboard so adaptive weak probing of the reused
holdout cannot move the settled number.
"""
import unittest

from tinker_delegate.private_reward import Candidate, RewardBand, assert_bounded_egress
from tinker_delegate.private_reward_envs import SyntheticHiddenKeywordEnvironment
from tinker_delegate.private_reward_loop import band_rank
from tinker_delegate.ladder_release import LadderPolicy


def _records():
    return {
        f"record-{index}": f"private alpha signal {index}".encode("utf-8")
        for index in range(10)
    }


def _env(ladder_policy=None):
    return SyntheticHiddenKeywordEnvironment(_records(), ladder_policy=ladder_policy)


class SyntheticLadderGateTest(unittest.TestCase):
    def test_ladder_off_by_default_leaves_release_unchanged(self):
        env = _env()
        self.assertIsNone(env.problem().public_metadata["ladder"])
        fb = env.evaluate(Candidate(b"alpha"))
        self.assertEqual(fb.public_message, "bounded synthetic holdout score")

    def test_ladder_gated_release_tracks_monotonic_best(self):
        # "alpha" matches every record (score 1.0 -> exceptional); "beta" matches
        # none (0.0 -> negligible). A weak probe after a strong one must
        # re-release the best, never drag it down.
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        seq = [b"beta", b"alpha", b"beta", b"alpha"]
        bands = [env.evaluate(Candidate(k)).reward_band for k in seq]
        ranks = [band_rank(b) for b in bands]
        self.assertEqual(ranks, sorted(ranks))  # monotonic non-decreasing
        self.assertEqual(bands[2], bands[1])  # weak-after-strong re-releases best
        self.assertGreater(band_rank(bands[1]), band_rank(RewardBand.NEGLIGIBLE))
        fb = env.evaluate(Candidate(b"alpha"))
        self.assertEqual(
            fb.public_message, "bounded synthetic ladder-gated leaderboard band"
        )

    def test_improvement_accounting_is_bounded(self):
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        for k in (b"beta", b"alpha", b"beta", b"alpha"):
            env.evaluate(Candidate(k))
        manifest = env._ladder.public_manifest()
        self.assertEqual(manifest["submission_count"], 4)
        self.assertGreaterEqual(manifest["improvement_count"], 1)
        self.assertLess(manifest["improvement_count"], manifest["submission_count"])
        self.assertLessEqual(manifest["improvement_count"], manifest["step_denominator"])

    def test_ladder_policy_is_in_audited_public_surfaces(self):
        plain = _env()
        gated = _env(ladder_policy=LadderPolicy(step_denominator=20))
        self.assertNotEqual(plain.environment_hash, gated.environment_hash)
        self.assertNotEqual(plain.leakage_hash, gated.leakage_hash)
        self.assertEqual(
            gated.problem().public_metadata["ladder"]["step_denominator"], 20
        )

    def test_gated_feedback_and_final_are_egress_safe(self):
        env = _env(ladder_policy=LadderPolicy(step_denominator=10))
        fb = env.evaluate(Candidate(b"alpha"))
        assert_bounded_egress(fb.to_public_dict())
        # No internal score leaks into the bounded surface.
        self.assertNotIn("1.0", str(fb.to_public_dict()))
        result = env.finalize()
        self.assertIn("ladder", result.attestation)
        self.assertEqual(result.attestation["ladder"]["submission_count"], 1)
        assert_bounded_egress(
            result.to_public_dict(), structural_ignore_keys=("attestation",)
        )


if __name__ == "__main__":
    unittest.main()
