import json
import unittest

from tinker_delegate.dp_accounting import (
    DpAccountant,
    DpError,
    DpParams,
    PrivacyMode,
)


class DpParamsTest(unittest.TestCase):
    def test_valid_params(self):
        p = DpParams(epsilon=0.5, delta=1e-6)
        self.assertEqual(p.epsilon, 0.5)

    def test_non_positive_epsilon_rejected(self):
        with self.assertRaises(DpError):
            DpParams(epsilon=0.0)

    def test_delta_out_of_range_rejected(self):
        with self.assertRaises(DpError):
            DpParams(epsilon=0.5, delta=1.0)
        with self.assertRaises(DpError):
            DpParams(epsilon=0.5, delta=-0.1)


class NonDpModeTest(unittest.TestCase):
    def test_non_dp_admits_but_never_phi_safe(self):
        acct = DpAccountant()  # default NON_DP
        self.assertEqual(acct.mode, PrivacyMode.NON_DP)
        self.assertFalse(acct.phi_safe)
        result = acct.charge(DpParams(epsilon=100.0))
        self.assertTrue(result.allowed)
        self.assertFalse(result.phi_safe)
        self.assertEqual(result.reason_code, "non_dp_release")
        self.assertFalse(result.exhausted)

    def test_non_dp_never_exhausts(self):
        acct = DpAccountant(PrivacyMode.NON_DP)
        for _ in range(50):
            self.assertTrue(acct.charge(DpParams(epsilon=10.0)).allowed)
        self.assertFalse(acct.exhausted)


class DpModeTest(unittest.TestCase):
    def test_dp_mode_requires_positive_budget(self):
        with self.assertRaises(DpError):
            DpAccountant(PrivacyMode.DP, max_epsilon=0.0)

    def test_dp_composes_epsilon_and_delta(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        self.assertTrue(acct.phi_safe)
        r1 = acct.charge(DpParams(epsilon=0.4, delta=3e-6))
        self.assertTrue(r1.allowed)
        self.assertAlmostEqual(r1.spent_epsilon, 0.4)
        self.assertAlmostEqual(r1.spent_delta, 3e-6)
        r2 = acct.charge(DpParams(epsilon=0.4, delta=3e-6))
        self.assertTrue(r2.allowed)
        self.assertAlmostEqual(r2.spent_epsilon, 0.8)
        self.assertEqual(r2.query_count, 2)

    def test_dp_fails_closed_without_mutating_on_over_budget(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        acct.charge(DpParams(epsilon=0.8))
        denied = acct.charge(DpParams(epsilon=0.5))  # 0.8 + 0.5 > 1.0
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason_code, "dp_budget_exhausted")
        # State unchanged by the denied charge.
        self.assertAlmostEqual(denied.spent_epsilon, 0.8)
        self.assertEqual(denied.query_count, 1)
        # A smaller release that still fits is admitted.
        ok = acct.charge(DpParams(epsilon=0.2))
        self.assertTrue(ok.allowed)
        self.assertAlmostEqual(ok.spent_epsilon, 1.0)
        self.assertTrue(ok.exhausted)  # hit the epsilon ceiling exactly

    def test_dp_delta_budget_also_binds(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=100.0, max_delta=5e-6)
        acct.charge(DpParams(epsilon=1.0, delta=4e-6))
        denied = acct.charge(DpParams(epsilon=1.0, delta=2e-6))  # delta would exceed
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason_code, "dp_budget_exhausted")

    def test_pure_epsilon_dp_is_not_spuriously_exhausted(self):
        # Regression: max_delta=0 (pure epsilon-DP) must not read as exhausted
        # while epsilon has headroom — a delta=0 release still fits.
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=0.0)
        self.assertFalse(acct.exhausted)
        self.assertTrue(acct.snapshot().allowed)
        r = acct.charge(DpParams(epsilon=0.4))  # delta defaults to 0.0
        self.assertTrue(r.allowed)
        self.assertFalse(r.exhausted)
        # Only epsilon exhaustion flips it.
        acct.charge(DpParams(epsilon=0.6))
        self.assertTrue(acct.exhausted)
        self.assertFalse(acct.snapshot().allowed)

    def test_would_exceed_predicts_denial(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        acct.charge(DpParams(epsilon=0.9))
        self.assertTrue(acct.would_exceed(DpParams(epsilon=0.2)))
        self.assertFalse(acct.would_exceed(DpParams(epsilon=0.05)))

    def test_snapshot_does_not_charge(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        acct.charge(DpParams(epsilon=0.5))
        snap = acct.snapshot()
        self.assertEqual(snap.query_count, 1)
        self.assertAlmostEqual(snap.spent_epsilon, 0.5)
        # Snapshot did not advance the count.
        self.assertEqual(acct.snapshot().query_count, 1)

    def test_public_dict_has_only_dp_fields_no_raw_data(self):
        acct = DpAccountant(PrivacyMode.DP, max_epsilon=1.0, max_delta=1e-5)
        public = acct.charge(DpParams(epsilon=0.5)).to_public_dict()
        self.assertEqual(public["surface"], "dp_accounting")
        self.assertFalse(public["raw_secret_egress"])
        self.assertTrue(public["phi_safe"])
        # Only DP parameters / counts / flags — no reward values or records.
        expected_keys = {
            "surface", "mode", "phi_safe", "allowed", "exhausted", "reason_code",
            "spent_epsilon", "spent_delta", "max_epsilon", "max_delta",
            "remaining_epsilon", "remaining_delta", "query_count", "raw_secret_egress",
        }
        self.assertEqual(set(public), expected_keys)
        self.assertAlmostEqual(public["remaining_epsilon"], 0.5)
        # Serializable and free of any obvious record content.
        self.assertNotIn("rec-", json.dumps(public))


if __name__ == "__main__":
    unittest.main()
