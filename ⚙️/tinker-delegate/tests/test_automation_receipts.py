import unittest
from unittest.mock import patch

from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    amount_band,
    balance_band,
    classify_automation_error,
    make_receipt,
)


class AutomationReceiptsTest(unittest.TestCase):
    def test_receipt_redacts_raw_secret_evidence(self):
        receipt = make_receipt(
            surface=AutomationSurface.PAYMENT_METHOD,
            outcome=AutomationOutcome.CARD_DECLINED,
            furthest_stage=AutomationStage.PAYMENT_SUBMITTED,
            evidence="card_number=4242424242424242 cvc=123 tml-secretsecretsecretsecret",
            bounded_message="Your card was declined.",
            amount_dollars=4.99,
            balance="$0.00",
            card_payload_destroyed=True,
        ).to_public_dict()

        rendered = repr(receipt)
        self.assertNotIn("4242424242424242", rendered)
        self.assertNotIn("cvc=123", rendered)
        self.assertNotIn("tml-secretsecretsecretsecret", rendered)
        self.assertEqual(receipt["outcome"], "card_declined")
        self.assertEqual(receipt["amount_band"], "lt_5_usd")
        self.assertEqual(receipt["balance_band"], "zero_usd")
        self.assertTrue(receipt["card_payload_destroyed"])
        self.assertFalse(receipt["raw_secret_egress"])
        self.assertIsInstance(receipt["issued_at"], int)
        self.assertEqual(receipt["bounded_message"], "card_declined")

    def test_private_sentences_cannot_influence_public_message_or_evidence_hash(self):
        first_private_sentence = (
            "Your card 4242424242424242 was declined at "
            "https://stripe.example/private/session/first?secret=alpha"
        )
        second_private_sentence = (
            "CVC 123 rejected on a different page sentence with token sk-private-second"
        )
        with patch("tinker_delegate.automation_receipts.time.time", return_value=100):
            first = make_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                outcome=AutomationOutcome.CARD_DECLINED,
                furthest_stage=AutomationStage.PAYMENT_SUBMITTED,
                evidence=first_private_sentence,
                bounded_message=first_private_sentence,
                amount_dollars=10,
                card_payload_destroyed=True,
            ).to_public_dict()
        with patch("tinker_delegate.automation_receipts.time.time", return_value=999):
            second = make_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                outcome=AutomationOutcome.CARD_DECLINED,
                furthest_stage=AutomationStage.PAYMENT_SUBMITTED,
                evidence=second_private_sentence,
                bounded_message=second_private_sentence,
                amount_dollars=10,
                card_payload_destroyed=True,
            ).to_public_dict()

        self.assertEqual(first["bounded_message"], "card_declined")
        self.assertEqual(second["bounded_message"], "card_declined")
        self.assertNotEqual(first["issued_at"], second["issued_at"])
        self.assertEqual(first["evidence_hash"], second["evidence_hash"])
        rendered = repr((first, second))
        self.assertNotIn("4242424242424242", rendered)
        self.assertNotIn("stripe.example", rendered)
        self.assertNotIn("sk-private-second", rendered)

    def test_bounded_projection_change_changes_evidence_hash(self):
        base = make_receipt(
            surface=AutomationSurface.ADD_BALANCE,
            outcome=AutomationOutcome.SUCCESS,
            furthest_stage=AutomationStage.ADD_BALANCE_SUBMITTED,
            amount_dollars=10,
        ).to_public_dict()
        other_band = make_receipt(
            surface=AutomationSurface.ADD_BALANCE,
            outcome=AutomationOutcome.SUCCESS,
            furthest_stage=AutomationStage.ADD_BALANCE_SUBMITTED,
            amount_dollars=50,
        ).to_public_dict()

        self.assertNotEqual(base["amount_band"], other_band["amount_band"])
        self.assertNotEqual(base["evidence_hash"], other_band["evidence_hash"])

    def test_error_classification_is_stable(self):
        self.assertEqual(
            classify_automation_error("Your card was declined."),
            AutomationOutcome.CARD_DECLINED,
        )
        self.assertEqual(
            classify_automation_error("Payment method required before adding balance"),
            AutomationOutcome.PAYMENT_METHOD_REQUIRED,
        )
        self.assertEqual(
            classify_automation_error("Stripe card iframe not found"),
            AutomationOutcome.SELECTOR_MISSING,
        )

    def test_amount_and_balance_bands(self):
        self.assertEqual(amount_band(1), "lt_5_usd")
        self.assertEqual(amount_band(10), "5_25_usd")
        self.assertEqual(amount_band(50), "25_100_usd")
        self.assertEqual(balance_band("$8.25"), "lt_10_usd")
        self.assertEqual(balance_band("$80.00"), "10_100_usd")
        self.assertEqual(balance_band("$-1.00"), "unknown")
        self.assertEqual(balance_band("not-a-balance"), "unknown")


if __name__ == "__main__":
    unittest.main()
