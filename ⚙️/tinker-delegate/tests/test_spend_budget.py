"""Tests for fail-closed multi-cap spend budget enforcement."""
import json
import unittest

from tinker_delegate.spend_budget import (
    SpendBudgetError,
    SpendCaps,
    SpendLedger,
)

_DAY = "2026-07-12"


class SpendCapsTest(unittest.TestCase):
    def test_negative_cap_rejected(self):
        with self.assertRaises(SpendBudgetError):
            SpendCaps(buyer_cap_wei=-1)

    def test_active_scopes_reflects_configured_caps(self):
        caps = SpendCaps(buyer_cap_wei=100, daily_cap_wei=50)
        self.assertEqual(set(caps.active_scopes()), {"buyer", "daily"})


class SpendLedgerTest(unittest.TestCase):
    def _ledger(self, **caps):
        return SpendLedger(SpendCaps(**caps))

    def test_within_all_caps_is_allowed_and_consumes_budget(self):
        led = self._ledger(buyer_cap_wei=1000, daily_cap_wei=500)
        a = led.authorize(200, day_bucket=_DAY)
        self.assertTrue(a.allowed)
        self.assertEqual(a.reason_code, "within_budget")
        self.assertEqual(led.spent_total, 200)
        self.assertEqual(led.daily_spent(_DAY), 200)

    def test_exact_cap_boundary_is_allowed(self):
        # A spend that lands exactly on a cap is in-budget (strict `>` denies).
        led = self._ledger(buyer_cap_wei=1000)
        self.assertTrue(led.authorize(1000, day_bucket=_DAY).allowed)
        # One wei more is over.
        self.assertFalse(led.authorize(1, day_bucket=_DAY).allowed)

    def test_daily_cap_denies_and_does_not_mutate(self):
        led = self._ledger(buyer_cap_wei=10_000, daily_cap_wei=300)
        led.authorize(200, day_bucket=_DAY)
        denied = led.authorize(150, day_bucket=_DAY)  # 200+150 > 300
        self.assertFalse(denied.allowed)
        self.assertEqual(denied.binding_cap, "daily")
        self.assertEqual(denied.reason_code, "exceeds_daily_cap")
        # Fail-closed: the rejected charge consumed no budget.
        self.assertEqual(led.spent_total, 200)
        self.assertEqual(led.daily_spent(_DAY), 200)

    def test_daily_cap_resets_per_bucket_but_cumulative_persists(self):
        led = self._ledger(buyer_cap_wei=1000, daily_cap_wei=300)
        led.authorize(300, day_bucket="2026-07-12")  # fills day 12
        # Same amount on a new day is fine for the daily cap...
        self.assertTrue(led.authorize(300, day_bucket="2026-07-13").allowed)
        # ...and cumulative (600) still tracked across days.
        self.assertEqual(led.spent_total, 600)

    def test_buyer_cap_binds_across_days(self):
        led = self._ledger(buyer_cap_wei=1000, daily_cap_wei=10_000)
        led.authorize(600, day_bucket="2026-07-12")
        led.authorize(400, day_bucket="2026-07-13")  # cumulative now 1000 exactly
        over = led.authorize(1, day_bucket="2026-07-14")
        self.assertFalse(over.allowed)
        self.assertEqual(over.binding_cap, "buyer")

    def test_tightest_cap_binds_when_multiple_exceeded(self):
        # Both room (remaining 100) and operator (remaining 50) would be exceeded
        # by a 200 spend; operator is tighter, so it binds.
        led = self._ledger(room_cap_wei=100, operator_cap_wei=50)
        auth = led.authorize(200, day_bucket=_DAY)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.binding_cap, "operator")

    def test_uncapped_scopes_are_not_enforced(self):
        # No caps at all -> any spend allowed.
        led = self._ledger()
        self.assertTrue(led.authorize(10**30, day_bucket=_DAY).allowed)

    def test_negative_amount_is_denied(self):
        led = self._ledger(buyer_cap_wei=1000)
        auth = led.authorize(-5, day_bucket=_DAY)
        self.assertFalse(auth.allowed)
        self.assertEqual(auth.reason_code, "negative_amount")
        self.assertEqual(led.spent_total, 0)

    def test_empty_day_bucket_rejected(self):
        led = self._ledger(daily_cap_wei=100)
        with self.assertRaises(SpendBudgetError):
            led.authorize(10, day_bucket="")

    def test_output_is_bounded_no_raw_amounts(self):
        led = self._ledger(buyer_cap_wei=1000, daily_cap_wei=500)
        auth = led.authorize(200, day_bucket=_DAY)
        pub = auth.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        blob = json.dumps(pub)
        # Coarse bands only — the raw spend/cap wei never appear.
        self.assertNotIn("200", blob)
        self.assertNotIn("1000", blob)
        self.assertIn("remaining_bands", blob)


if __name__ == "__main__":
    unittest.main()
