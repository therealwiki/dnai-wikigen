"""Tests for fail-closed funding-failure classification."""
import json
import unittest

from tinker_delegate.funding_failure import (
    FailureDisposition,
    FundingFailureError,
    FundingFailureKind,
    classify_funding_failure,
)
from tinker_delegate.topup_policy import TopUpPolicy, decide_topup


class ClassifyFundingFailureTest(unittest.TestCase):
    def test_bot_check_aborts_and_disables_never_auto_solved(self):
        a = classify_funding_failure(FundingFailureKind.BOT_CHECK)
        self.assertEqual(a.disposition, FailureDisposition.ABORT)
        self.assertFalse(a.retryable)
        self.assertTrue(a.disable_auto_reload)

    def test_three_ds_escalates_never_auto_completed(self):
        a = classify_funding_failure(FundingFailureKind.THREE_DS_CHALLENGE)
        self.assertEqual(a.disposition, FailureDisposition.ESCALATE_HUMAN)
        self.assertFalse(a.retryable)

    def test_transient_kinds_retry_with_backoff(self):
        for kind in (FundingFailureKind.RATE_LIMIT, FundingFailureKind.BILLING_OUTAGE):
            a = classify_funding_failure(kind, attempt=1, max_attempts=3)
            self.assertEqual(a.disposition, FailureDisposition.RETRY_BACKOFF)
            self.assertTrue(a.retryable)

    def test_retry_exhaustion_escalates_and_disables(self):
        a = classify_funding_failure(
            FundingFailureKind.RATE_LIMIT, attempt=3, max_attempts=3
        )
        self.assertEqual(a.disposition, FailureDisposition.ESCALATE_HUMAN)
        self.assertFalse(a.retryable)
        self.assertTrue(a.disable_auto_reload)
        self.assertTrue(a.reason_code.endswith("retries_exhausted"))

    def test_card_declined_and_insufficient_funds_disable_auto_reload(self):
        for kind in (
            FundingFailureKind.CARD_DECLINED,
            FundingFailureKind.INSUFFICIENT_FUNDS,
        ):
            a = classify_funding_failure(kind)
            self.assertEqual(a.disposition, FailureDisposition.ESCALATE_HUMAN)
            self.assertTrue(a.disable_auto_reload)

    def test_partial_topup_is_accepted(self):
        a = classify_funding_failure(FundingFailureKind.PARTIAL_TOPUP)
        self.assertEqual(a.disposition, FailureDisposition.ACCEPT_PARTIAL)
        self.assertFalse(a.disable_auto_reload)

    def test_unknown_kind_fails_closed(self):
        a = classify_funding_failure("gremlin-mode")
        self.assertEqual(a.kind, FundingFailureKind.UNKNOWN)
        self.assertEqual(a.disposition, FailureDisposition.ABORT)
        self.assertTrue(a.disable_auto_reload)

    def test_invalid_attempt_rejected(self):
        with self.assertRaises(FundingFailureError):
            classify_funding_failure(FundingFailureKind.RATE_LIMIT, attempt=0)

    def test_output_is_bounded(self):
        pub = classify_funding_failure(FundingFailureKind.CARD_DECLINED).to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertIn("disposition", json.dumps(pub))


class FailureFlipsTopUpKillSwitchTest(unittest.TestCase):
    def test_disable_auto_reload_stops_further_topups(self):
        # A card-declined failure sets disable_auto_reload; feeding that into the
        # top-up policy's emergency kill switch stops all further auto-reloads
        # (the failure -> kill-switch -> no-more-charges loop, fail closed).
        failure = classify_funding_failure(FundingFailureKind.CARD_DECLINED)
        self.assertTrue(failure.disable_auto_reload)

        base = dict(min_balance_wei=100, target_balance_wei=1000, max_topup_wei=2000)
        # Before the failure, a low balance would auto-reload.
        live = TopUpPolicy(**base, auto_reload_enabled=True)
        self.assertTrue(decide_topup(10, live).should_topup)
        # After the failure flips the kill switch, it must not.
        disabled = TopUpPolicy(
            **base, auto_reload_enabled=True, emergency_disabled=failure.disable_auto_reload
        )
        decision = decide_topup(10, disabled)
        self.assertFalse(decision.should_topup)
        self.assertEqual(decision.reason_code, "emergency_disabled")


if __name__ == "__main__":
    unittest.main()
