import random
import unittest

from tinker_delegate.ladder_release import (
    LadderError,
    LadderLeaderboard,
    LadderPolicy,
    PairedTLadderLeaderboard,
)
from tinker_delegate.private_reward import assert_bounded_egress


class LadderPolicyTest(unittest.TestCase):
    def test_rejects_malformed_policy(self):
        for bad in (0, -1, True, 1.5):
            with self.assertRaises(LadderError):
                LadderPolicy(step_denominator=bad)  # type: ignore[arg-type]
        with self.assertRaises(LadderError):
            LadderPolicy(max_submissions=0)
        with self.assertRaises(LadderError):
            LadderPolicy(max_submissions=True)  # type: ignore[arg-type]

    def test_step_matches_denominator(self):
        self.assertAlmostEqual(LadderPolicy(step_denominator=20).step, 0.05)
        self.assertEqual(LadderPolicy(step_denominator=20).to_public_dict()["max_improvement_steps"], 20)


class LadderSubmitTest(unittest.TestCase):
    def test_rejects_out_of_range_or_non_numeric_score(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=10))
        for bad in (-0.01, 1.01, "0.5", None, True):
            with self.assertRaises(LadderError):
                board.submit(bad)  # type: ignore[arg-type]

    def test_only_significant_improvement_advances(self):
        # η = 0.1. First candidate at 0.55 clears the floor and rounds to 0.6 (index 6).
        board = LadderLeaderboard(LadderPolicy(step_denominator=10))
        r1 = board.submit(0.55)
        self.assertTrue(r1.accepted)
        self.assertEqual(r1.leaderboard_step_index, 6)
        # A candidate that is better but NOT by a full η margin does not advance:
        # 0.62 is above the released 0.6 but not above best+η = 0.7.
        r2 = board.submit(0.62)
        self.assertFalse(r2.accepted)
        self.assertEqual(r2.leaderboard_step_index, 6)  # previous best re-released
        # A candidate clearing best+η (0.75 > 0.7) advances to index 8 (0.75 -> 0.8).
        r3 = board.submit(0.75)
        self.assertTrue(r3.accepted)
        self.assertEqual(r3.leaderboard_step_index, 8)

    def test_leaderboard_is_monotonic_nondecreasing(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=50))
        prev = -1
        rng = random.Random(1234)
        for _ in range(400):
            rel = board.submit(rng.random())
            self.assertGreaterEqual(rel.leaderboard_step_index, prev)
            prev = rel.leaderboard_step_index

    def test_improvement_steps_bounded_by_grid(self):
        # Core Ladder guarantee: rewards in [0,1] admit at most ⌈1/η⌉ = D genuine
        # improvement steps no matter how many submissions arrive.
        D = 20
        board = LadderLeaderboard(LadderPolicy(step_denominator=D))
        rng = random.Random(7)
        for _ in range(2000):
            board.submit(rng.random())
        self.assertLessEqual(board.improvement_count, D)
        self.assertLessEqual(board.best_step_index, D)

    def test_adaptive_random_attack_yields_few_improvements(self):
        # The paper's canonical attack: repeatedly submit random candidates and
        # keep grinding. Against the Ladder the number of *accepted* improvements
        # stays tiny (~O(log k)) relative to k, because each new best makes the
        # next crossing exponentially less likely — this is what keeps the settled
        # number honest under unlimited adaptive querying.
        board = LadderLeaderboard(LadderPolicy(step_denominator=100))
        rng = random.Random(2025)
        k = 5000
        for _ in range(k):
            board.submit(rng.random())
        # Far fewer accepted releases than submissions, and well under the grid cap.
        self.assertLess(board.improvement_count, 40)
        self.assertLess(board.improvement_count, k // 50)

    def test_deterministic_replay(self):
        scores = [0.1, 0.9, 0.42, 0.95, 0.955, 0.99]
        a = LadderLeaderboard(LadderPolicy(step_denominator=20))
        b = LadderLeaderboard(LadderPolicy(step_denominator=20))
        self.assertEqual(
            [a.submit(s).to_public_dict() for s in scores],
            [b.submit(s).to_public_dict() for s in scores],
        )

    def test_submission_budget_fails_closed(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=10, max_submissions=2))
        board.submit(0.5)
        board.submit(0.6)
        with self.assertRaises(LadderError):
            board.submit(0.7)

    def test_perfect_and_zero_scores_clamp_to_grid(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=4))
        self.assertEqual(board.submit(0.0).leaderboard_step_index, -1)  # below floor+η, nothing released
        self.assertEqual(board.submit(1.0).leaderboard_step_index, 4)   # perfect -> top of grid
        # Already at the top: no candidate can advance further.
        self.assertFalse(board.submit(1.0).accepted)


class PairedTLadderTest(unittest.TestCase):
    def test_rejects_malformed_vectors(self):
        board = PairedTLadderLeaderboard()
        for bad in ([], "abc", b"abc"):
            with self.assertRaises(LadderError):
                board.submit(bad)  # type: ignore[arg-type]
        for bad_vec in ([0.5, 1.5], [0.5, -0.1], [0.5, "x"], [0.5, True]):
            with self.assertRaises(LadderError):
                board.submit(bad_vec)  # type: ignore[arg-type]

    def test_vector_length_must_be_stable(self):
        board = PairedTLadderLeaderboard()
        board.submit([0.5, 0.5, 0.5, 0.5])
        with self.assertRaises(LadderError):
            board.submit([0.5, 0.5])

    def test_first_submission_sets_the_baseline(self):
        board = PairedTLadderLeaderboard()
        rel = board.submit([0.5] * 20)
        self.assertTrue(rel.accepted)
        self.assertEqual(rel.leaderboard_numerator, 10)  # round(0.5 * 20)
        self.assertEqual(rel.denominator, 20)

    def test_noise_only_variation_is_not_significant(self):
        # A candidate that merely jiggles around the previous best (overfitting
        # noise, zero-mean per-example differences) must NOT advance the board.
        board = PairedTLadderLeaderboard()
        board.submit([0.5] * 20)
        noisy = [0.52 if i % 2 == 0 else 0.48 for i in range(20)]  # mean still 0.5
        rel = board.submit(noisy)
        self.assertFalse(rel.accepted)
        self.assertEqual(rel.leaderboard_numerator, 10)  # best unchanged

    def test_positive_but_high_variance_is_not_significant(self):
        # Positive mean improvement is not enough; it must clear the s/√n
        # threshold. A high-variance vector with a tiny positive mean is rejected.
        board = PairedTLadderLeaderboard()
        board.submit([0.5] * 20)
        spread = [0.9 if i < 10 else 0.15 for i in range(20)]  # mean 0.525, high var
        rel = board.submit(spread)
        self.assertFalse(rel.accepted)

    def test_uniform_real_improvement_advances(self):
        board = PairedTLadderLeaderboard()
        board.submit([0.5] * 20)
        rel = board.submit([0.6] * 20)  # every example up by 0.1 -> zero-variance, significant
        self.assertTrue(rel.accepted)
        self.assertEqual(rel.leaderboard_numerator, 12)  # round(0.6 * 20)

    def test_released_number_never_regresses(self):
        board = PairedTLadderLeaderboard()
        board.submit([0.6] * 20)
        worse = board.submit([0.2] * 20)
        self.assertFalse(worse.accepted)
        self.assertEqual(worse.leaderboard_numerator, 12)

    def test_deterministic_replay(self):
        vectors = [[0.4] * 16, [0.55] * 16, [0.5] * 16, [0.7] * 16]
        a = PairedTLadderLeaderboard()
        b = PairedTLadderLeaderboard()
        self.assertEqual(
            [a.submit(v).to_public_dict() for v in vectors],
            [b.submit(v).to_public_dict() for v in vectors],
        )

    def test_release_and_manifest_are_bounded_egress_safe(self):
        board = PairedTLadderLeaderboard()
        rng = random.Random(42)
        rel = board.submit([rng.random() for _ in range(30)])
        assert_bounded_egress(rel.to_public_dict())
        assert_bounded_egress(board.public_manifest())


class LadderEgressTest(unittest.TestCase):
    def test_release_and_manifest_are_bounded_egress_safe(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=20))
        rel = board.submit(0.73)
        # No float, numeric array, blob, or smuggled reward value may leave.
        assert_bounded_egress(rel.to_public_dict())
        assert_bounded_egress(board.public_manifest())

    def test_internal_score_never_appears_in_release(self):
        board = LadderLeaderboard(LadderPolicy(step_denominator=20))
        rel = board.submit(0.7314159)
        # The exact internal score must not survive into the bounded surface.
        self.assertNotIn("0.73", str(rel.to_public_dict()))
        self.assertNotIn("7314159", str(rel.to_public_dict()))


if __name__ == "__main__":
    unittest.main()
