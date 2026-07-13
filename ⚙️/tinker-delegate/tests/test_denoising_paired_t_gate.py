"""Parameter-free (paired-t) Ladder wired into the denoising env.

Unlike the fixed-η gate (which gates on a scalar MSE-improvement), the paired-t
gate consults the *per-cell* MSE-improvement vector and releases a new best only
when it is statistically significantly above the previous best's per-cell vector —
the faithful home for the vector-based mechanism (continuous per-example scores).
"""
import unittest

from tinker_delegate.private_reward import Candidate, RewardBand, assert_bounded_egress
from tinker_delegate.private_reward_envs.denoising import (
    DenoisingHoldoutEnvironment,
    SealedCell,
    per_cell_mse_improvement,
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


def _env(**kw):
    return DenoisingHoldoutEnvironment(_cells(), holdout_policy=_policy(), **kw)


class DenoisingPairedTGateTest(unittest.TestCase):
    def test_per_cell_vector_matches_cell_count_and_ranks_denoisers(self):
        train = [c.train for c in _cells()]
        test = [c.test for c in _cells()]
        # Pool denoiser output vs identity output.
        cols = list(zip(*train))
        pooled = [sum(c) / len(c) for c in cols]
        pool_out = [list(pooled) for _ in train]
        pool_vec = per_cell_mse_improvement(pool_out, train, test)
        ident_vec = per_cell_mse_improvement([list(r) for r in train], train, test)
        self.assertEqual(len(pool_vec), len(train))
        self.assertTrue(all(0.0 <= v <= 1.0 for v in pool_vec))
        self.assertGreater(sum(pool_vec), sum(ident_vec))

    def test_off_by_default(self):
        env = _env()
        self.assertIsNone(env.problem().public_metadata["ladder"])
        fb = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        self.assertEqual(fb.public_message, "bounded denoising holdout score")

    def test_paired_t_release_is_monotonic_best(self):
        env = _env(paired_t_ladder=True)
        self.assertEqual(env.problem().public_metadata["ladder"], {"variant": "paired_t"})
        seq = [IDENTITY_DENOISER, POOL_DENOISER, IDENTITY_DENOISER, POOL_DENOISER]
        fbs = [env.evaluate(Candidate(s.encode("utf-8"))) for s in seq]
        bands = [fb.reward_band for fb in fbs]
        ranks = [band_rank(b) for b in bands]
        self.assertEqual(ranks, sorted(ranks))  # monotonic non-decreasing
        self.assertEqual(bands[2], bands[1])  # weak-after-strong re-releases best
        self.assertGreater(band_rank(bands[1]), band_rank(RewardBand.NEGLIGIBLE))
        # The strong candidate's release went through the paired-t gate.
        self.assertEqual(
            fbs[1].public_message, "bounded denoising paired-t ladder-gated leaderboard band"
        )

    def test_final_attestation_carries_paired_t_manifest_and_is_egress_safe(self):
        env = _env(paired_t_ladder=True)
        fb = env.evaluate(Candidate(POOL_DENOISER.encode("utf-8")))
        assert_bounded_egress(fb.to_public_dict())
        result = env.finalize()
        self.assertEqual(result.attestation["ladder"]["variant"], "paired_t")
        assert_bounded_egress(
            result.to_public_dict(), structural_ignore_keys=("attestation",)
        )

    def test_paired_t_changes_audited_hashes(self):
        plain = _env()
        gated = _env(paired_t_ladder=True)
        self.assertNotEqual(plain.environment_hash, gated.environment_hash)
        self.assertNotEqual(plain.leakage_hash, gated.leakage_hash)

    def test_fixed_eta_and_paired_t_are_mutually_exclusive(self):
        with self.assertRaises(ValueError):
            DenoisingHoldoutEnvironment(
                _cells(), holdout_policy=_policy(),
                ladder_policy=LadderPolicy(), paired_t_ladder=True,
            )


if __name__ == "__main__":
    unittest.main()
