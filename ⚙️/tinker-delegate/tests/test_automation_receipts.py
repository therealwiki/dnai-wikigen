import unittest

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


if __name__ == "__main__":
    unittest.main()
