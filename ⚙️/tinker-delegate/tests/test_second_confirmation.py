"""Tests for the second-confirmation gate on high-risk actions."""
import json
import unittest

from tinker_delegate.second_confirmation import (
    Confirmation,
    ConfirmationChannel,
    ConfirmationRequirement,
    SecondConfirmationError,
    evaluate_confirmation,
    requires_confirmation,
)
from tinker_delegate.topup_policy import TopUpPolicy, decide_topup

_HUMAN = ConfirmationChannel.HUMAN_REVIEWER
_WALLET = ConfirmationChannel.WALLET_SIGNATURE
_PASSKEY = ConfirmationChannel.PASSKEY


def _req(**kw):
    kw.setdefault("approved_channels", frozenset({_HUMAN, _WALLET}))
    return ConfirmationRequirement(**kw)


def _c(channel, who, issued_at=100):
    return Confirmation(channel, who, "0x" + "ab" * 32, issued_at)


def _eval(confirmations, requirement=None, requester="agent", now=200):
    return evaluate_confirmation(
        requester_ref=requester,
        requirement=requirement or _req(),
        confirmations=confirmations,
        now=now,
    )


class RequiresConfirmationTest(unittest.TestCase):
    def test_threshold_boundary(self):
        self.assertTrue(requires_confirmation(1000, threshold_wei=1000))
        self.assertFalse(requires_confirmation(999, threshold_wei=1000))

    def test_negative_rejected(self):
        with self.assertRaises(SecondConfirmationError):
            requires_confirmation(-1, threshold_wei=10)


class EvaluateConfirmationTest(unittest.TestCase):
    def test_requirement_validation(self):
        with self.assertRaises(SecondConfirmationError):
            ConfirmationRequirement(approved_channels=frozenset({_HUMAN}), required_confirmations=0)

    def test_two_distinct_approved_confirmations_authorize(self):
        d = _eval((_c(_HUMAN, "alice"), _c(_WALLET, "bob")), _req(required_confirmations=2))
        self.assertTrue(d.authorized)
        self.assertEqual(d.satisfied_count, 2)

    def test_self_confirmation_is_rejected(self):
        # The requester cannot second-confirm its own action.
        d = _eval((_c(_HUMAN, "agent"), _c(_WALLET, "bob")), _req(required_confirmations=2))
        self.assertFalse(d.authorized)
        self.assertEqual(d.satisfied_count, 1)  # only bob counts

    def test_non_approved_channel_does_not_count(self):
        d = _eval((_c(_PASSKEY, "alice"), _c(_WALLET, "bob")), _req(required_confirmations=2))
        self.assertEqual(d.satisfied_count, 1)  # passkey not approved here

    def test_expired_confirmations_do_not_count(self):
        req = _req(required_confirmations=1, max_age_seconds=900)
        d = _eval((_c(_HUMAN, "alice", issued_at=100),), req, now=1500)  # age 1400 > 900
        self.assertFalse(d.authorized)
        self.assertEqual(d.reason_code, "no_valid_confirmation")

    def test_future_confirmation_not_trusted(self):
        d = _eval((_c(_HUMAN, "alice", issued_at=5000),), _req(required_confirmations=1), now=200)
        self.assertFalse(d.authorized)

    def test_duplicate_confirmer_counted_once(self):
        d = _eval((_c(_HUMAN, "alice"), _c(_WALLET, "alice")), _req(required_confirmations=2))
        self.assertEqual(d.satisfied_count, 1)

    def test_missing_approved_channels_authorizes_nothing(self):
        req = ConfirmationRequirement(approved_channels=frozenset())
        d = _eval((_c(_HUMAN, "alice"),), req)
        self.assertFalse(d.authorized)

    def test_single_confirmation_default_authorizes(self):
        d = _eval((_c(_WALLET, "bob"),))
        self.assertTrue(d.authorized)
        self.assertEqual(d.reason_code, "second_confirmation_satisfied")

    def test_output_is_bounded_hashes_only(self):
        d = _eval((_c(_WALLET, "bob"),))
        pub = d.to_public_dict()
        self.assertFalse(pub["raw_secret_egress"])
        self.assertIn("channels_used", json.dumps(pub))


class HighRiskTopUpNeedsConfirmationTest(unittest.TestCase):
    def test_large_topup_requires_second_confirmation(self):
        # A top-up above the high-risk threshold must not proceed on the delegate's
        # own authority: it needs an out-of-band confirmation first.
        policy = TopUpPolicy(
            min_balance_wei=100, target_balance_wei=10_000, max_topup_wei=10_000,
            auto_reload_enabled=True,
        )
        decision = decide_topup(0, policy)  # wants a 10_000 top-up
        self.assertTrue(decision.should_topup)
        threshold = 5_000
        if requires_confirmation(decision.topup_amount_wei, threshold_wei=threshold):
            # No confirmation supplied yet -> the action is NOT authorized.
            gate = _eval((), _req(required_confirmations=1))
            self.assertFalse(gate.authorized)
            # With a valid out-of-band human approval it proceeds.
            gate2 = _eval((_c(_HUMAN, "reviewer-1"),), _req(required_confirmations=1))
            self.assertTrue(gate2.authorized)
        else:  # pragma: no cover
            self.fail("10_000 top-up should be high-risk under a 5_000 threshold")


if __name__ == "__main__":
    unittest.main()
