"""Tests for the fail-closed top-up (auto-reload) policy."""
import json
import unittest

from tinker_delegate.spend_budget import SpendCaps, SpendLedger
from tinker_delegate.topup_policy import (
    TopUpDecision,
    TopUpPolicy,
    TopUpPolicyError,
    decide_topup,
)


def _policy(**overrides) -> TopUpPolicy:
    base = dict(
        min_balance_wei=100,
        target_balance_wei=1000,
        max_topup_wei=2000,
        auto_reload_enabled=True,
    )
    base.update(overrides)
    return TopUpPolicy(**base)


class TopUpPolicyValidationTest(unittest.TestCase):
    def test_negative_amounts_rejected(self):
        with self.assertRaises(TopUpPolicyError):
            TopUpPolicy(min_balance_wei=-1, target_balance_wei=10, max_topup_wei=10)

    def test_target_below_min_rejected(self):
        with self.assertRaises(TopUpPolicyError):
            TopUpPolicy(min_balance_wei=100, target_balance_wei=50, max_topup_wei=10)


class DecideTopUpTest(unittest.TestCase):
    def test_auto_reload_off_by_default_no_topup(self):
        # Default posture: auto-reload disabled -> never tops up.
        policy = TopUpPolicy(min_balance_wei=100, target_balance_wei=1000, max_topup_wei=2000)
        d = decide_topup(0, policy)
        self.assertFalse(d.should_topup)
        self.assertEqual(d.reason_code, "auto_reload_off")

    def test_emergency_disable_wins_over_enabled(self):
        d = decide_topup(0, _policy(emergency_disabled=True))
        self.assertFalse(d.should_topup)
        self.assertEqual(d.reason_code, "emergency_disabled")

    def test_sufficient_balance_no_topup(self):
        d = decide_topup(150, _policy())
        self.assertFalse(d.should_topup)
        self.assertEqual(d.reason_code, "balance_sufficient")

    def test_reload_to_target(self):
        d = decide_topup(50, _policy())
        self.assertTrue(d.should_topup)
        self.assertEqual(d.topup_amount_wei, 950)  # 1000 - 50
        self.assertTrue(d.reaches_target)
        self.assertEqual(d.reason_code, "topup_authorized")

    def test_partial_topup_when_capped(self):
        d = decide_topup(50, _policy(max_topup_wei=500))
        self.assertTrue(d.should_topup)
        self.assertEqual(d.topup_amount_wei, 500)  # capped below the 950 needed
        self.assertFalse(d.reaches_target)
        self.assertEqual(d.reason_code, "partial_topup")

    def test_negative_balance_fails_closed(self):
        d = decide_topup(-1, _policy())
        self.assertFalse(d.should_topup)
        self.assertEqual(d.reason_code, "invalid_balance")

    def test_zero_max_topup_yields_no_topup(self):
        d = decide_topup(0, _policy(max_topup_wei=0))
        self.assertFalse(d.should_topup)
        self.assertEqual(d.reason_code, "no_topup_available")

    def test_output_is_bounded_no_raw_amounts(self):
        d = decide_topup(50, _policy())
        pub = d.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        blob = json.dumps(pub)
        self.assertNotIn("950", blob)  # amount is banded, not raw
        self.assertIn("topup_amount_band", blob)


class TopUpComposesWithSpendBudgetTest(unittest.TestCase):
    def test_topup_amount_is_gated_by_spend_caps(self):
        # A produced top-up is a SPEND: it must still pass the budget caps. Here
        # the daily cap (500) is tighter than the 950 top-up, so the charge is
        # denied and no budget is consumed (fail closed end to end).
        decision = decide_topup(50, _policy())
        self.assertTrue(decision.should_topup)
        ledger = SpendLedger(SpendCaps(daily_cap_wei=500))
        auth = ledger.authorize(decision.topup_amount_wei, day_bucket="2026-07-12")
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.binding_cap, "daily")
        self.assertEqual(ledger.spent_total, 0)

    def test_within_cap_topup_is_authorized(self):
        decision = decide_topup(50, _policy(max_topup_wei=300))  # 300 top-up
        ledger = SpendLedger(SpendCaps(daily_cap_wei=500))
        auth = ledger.authorize(decision.topup_amount_wei, day_bucket="2026-07-12")
        self.assertTrue(auth.allowed)
        self.assertEqual(ledger.spent_total, 300)


if __name__ == "__main__":
    unittest.main()
