import unittest

from tinker_delegate.dp_accounting import DpAccountant, PrivacyMode
from tinker_delegate.private_reward import assert_bounded_egress
from tinker_delegate.thresholdout import (
    ThresholdoutError,
    ThresholdoutGate,
    ThresholdoutPolicy,
)


def _gate(max_epsilon=1.0, noise=0.0, **policy_kw):
    acc = DpAccountant(PrivacyMode.DP, max_epsilon=max_epsilon, max_delta=0.0)
    policy = ThresholdoutPolicy(
        tolerance=policy_kw.pop("tolerance", 0.1),
        noise_scale=policy_kw.pop("noise_scale", 0.0),
        epsilon_per_access=policy_kw.pop("epsilon_per_access", 0.5),
        step_denominator=policy_kw.pop("step_denominator", 10),
    )
    return ThresholdoutGate(acc, policy, noise_fn=lambda s: noise), acc


class ThresholdoutPolicyTest(unittest.TestCase):
    def test_rejects_bad_policy(self):
        for kw in (
            {"tolerance": -0.1}, {"noise_scale": -1.0},
            {"epsilon_per_access": 0.0}, {"step_denominator": 0},
            {"step_denominator": True},
        ):
            with self.assertRaises(ThresholdoutError):
                ThresholdoutPolicy(**kw)

    def test_requires_dp_accountant(self):
        with self.assertRaises(ThresholdoutError):
            ThresholdoutGate(DpAccountant(PrivacyMode.NON_DP))


class ThresholdoutQueryTest(unittest.TestCase):
    def test_rejects_out_of_range_stats(self):
        gate, _ = _gate()
        for bad in ((-0.1, 0.5), (0.5, 1.1), ("x", 0.5), (0.5, True)):
            with self.assertRaises(ThresholdoutError):
                gate.query(*bad)

    def test_tracking_candidate_is_free(self):
        # |holdout - reward| = 0.05 <= tolerance 0.1 -> no holdout access, no spend.
        gate, acc = _gate()
        rel = gate.query(reward_stat=0.6, holdout_stat=0.55)
        self.assertFalse(rel.used_holdout)
        self.assertEqual(rel.holdout_access_count, 0)
        self.assertEqual(acc.spent_epsilon, 0.0)
        self.assertEqual(rel.released_step_index, 6)  # round(0.6 * 10)

    def test_diverging_candidate_spends_budget(self):
        gate, acc = _gate()
        rel = gate.query(reward_stat=0.5, holdout_stat=0.9)
        self.assertTrue(rel.used_holdout)
        self.assertEqual(rel.holdout_access_count, 1)
        self.assertEqual(acc.spent_epsilon, 0.5)
        self.assertEqual(rel.released_step_index, 9)  # releases the (fresh) holdout stat

    def test_budget_exhaustion_fails_closed_on_divergence(self):
        gate, _ = _gate(max_epsilon=1.0, epsilon_per_access=0.5)
        gate.query(0.5, 0.9)  # spend 0.5
        gate.query(0.5, 0.95)  # spend 0.5 -> total 1.0, exhausted
        over = gate.query(0.5, 0.95)  # divergence but no budget left
        self.assertFalse(over.used_holdout)
        self.assertEqual(over.released_step_index, -1)  # nothing released
        self.assertTrue(over.budget_exhausted)

    def test_tracking_still_free_after_exhaustion(self):
        gate, _ = _gate(max_epsilon=0.5, epsilon_per_access=0.5)
        gate.query(0.5, 0.95)  # exhausts on the one holdout access
        rel = gate.query(reward_stat=0.7, holdout_stat=0.72)  # tracking
        self.assertFalse(rel.used_holdout)
        self.assertEqual(rel.released_step_index, 7)

    def test_threshold_noise_can_admit_borderline_as_tracking(self):
        # A gap of 0.15 exceeds tolerance 0.1, but a +0.1 threshold-noise draw
        # raises the bar to 0.2, so it is treated as tracking (no budget spent).
        acc = DpAccountant(PrivacyMode.DP, max_epsilon=1.0)
        policy = ThresholdoutPolicy(tolerance=0.1, noise_scale=0.1, epsilon_per_access=0.5, step_denominator=10)
        gate = ThresholdoutGate(acc, policy, noise_fn=lambda s: 0.1)
        rel = gate.query(reward_stat=0.5, holdout_stat=0.65)  # gap 0.15
        self.assertFalse(rel.used_holdout)
        self.assertEqual(acc.spent_epsilon, 0.0)

    def test_deterministic_replay(self):
        scenarios = [(0.6, 0.55), (0.5, 0.9), (0.4, 0.42), (0.5, 0.95)]
        a, _ = _gate()
        b, _ = _gate()
        self.assertEqual(
            [a.query(*s).to_public_dict() for s in scenarios],
            [b.query(*s).to_public_dict() for s in scenarios],
        )

    def test_release_and_manifest_are_bounded_egress_safe(self):
        gate, _ = _gate()
        rel = gate.query(0.5, 0.9)
        public_release = rel.to_public_dict()
        assert_bounded_egress(public_release)
        self.assertNotIn("used_holdout", public_release)
        self.assertNotIn("holdout_access_count", public_release)
        # The manifest carries public DP params (floats live under `policy`);
        # the release itself is bands, ints, bools, and a status enum only.
        public_manifest = gate.public_manifest()
        self.assertEqual(public_manifest["variant"], "thresholdout")
        self.assertNotIn("holdout_access_count", public_manifest)
        self.assertEqual(public_manifest["budget_status"], "available")

    def test_secret_dependent_access_branch_has_identical_public_shape(self):
        free_gate, _ = _gate(max_epsilon=2.0)
        charged_gate, _ = _gate(max_epsilon=2.0)

        # Both queries release band 5. Internally, one is a free reward-stat
        # release and the other consults the secret holdout and spends epsilon.
        free = free_gate.query(reward_stat=0.5, holdout_stat=0.5)
        charged = charged_gate.query(reward_stat=0.0, holdout_stat=0.5)
        self.assertFalse(free.used_holdout)
        self.assertTrue(charged.used_holdout)
        self.assertNotEqual(free.holdout_access_count, charged.holdout_access_count)

        self.assertEqual(free.to_public_dict(), charged.to_public_dict())
        self.assertEqual(free_gate.public_manifest(), charged_gate.public_manifest())

    def test_total_leakage_bounded_by_epsilon_times_accesses(self):
        # The headline bound: spent epsilon == epsilon_per_access * holdout accesses,
        # and never exceeds the budget.
        gate, acc = _gate(max_epsilon=2.0, epsilon_per_access=0.5)
        for _ in range(6):  # more divergences than the budget allows
            gate.query(0.3, 0.95)
        self.assertLessEqual(acc.spent_epsilon, 2.0)
        self.assertEqual(acc.spent_epsilon, 0.5 * gate.holdout_access_count)
        self.assertEqual(gate.holdout_access_count, 4)  # 2.0 / 0.5


if __name__ == "__main__":
    unittest.main()
