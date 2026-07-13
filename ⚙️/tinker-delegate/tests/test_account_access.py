import json
import unittest

from tinker_delegate.account_access import (
    ACCESS_BLOCKED_BILLING,
    ACTIVE,
    PAYMENT_REQUIRED,
    UNKNOWN,
    WAITLIST_OR_GATED,
    account_access_receipt,
    classify_account_access,
)


class AccountAccessClassifyTest(unittest.TestCase):
    def test_observed_402_gate_is_blocked_billing(self):
        # The exact text observed on the live account.
        text = "Access is blocked due to billing status. Please add payment."
        self.assertEqual(classify_account_access(text), ACCESS_BLOCKED_BILLING)

    def test_blocked_billing_wins_over_add_payment(self):
        # Even though "add payment" appears, the billing block is the real state.
        text = "Your access is blocked due to billing status. Please add payment method."
        self.assertEqual(classify_account_access(text), ACCESS_BLOCKED_BILLING)

    def test_payment_required_without_block(self):
        text = "No payment method on file. Please add a payment method to continue."
        self.assertEqual(classify_account_access(text), PAYMENT_REQUIRED)

    def test_waitlist_gated(self):
        text = "Tinker is invite only. Join the waitlist to request access."
        self.assertEqual(classify_account_access(text), WAITLIST_OR_GATED)

    def test_active(self):
        text = "Your account is active. API access enabled."
        self.assertEqual(classify_account_access(text), ACTIVE)

    def test_unknown_empty(self):
        self.assertEqual(classify_account_access(""), UNKNOWN)
        self.assertEqual(classify_account_access("Welcome to your dashboard."), UNKNOWN)


class AccountAccessReceiptTest(unittest.TestCase):
    def test_blocked_billing_is_not_self_serve(self):
        receipt = account_access_receipt("Access is blocked due to billing status.")
        self.assertEqual(receipt["state"], ACCESS_BLOCKED_BILLING)
        self.assertFalse(receipt["actionable_by_automation"])
        self.assertEqual(receipt["operator_action"], "contact_provider_for_account_activation")
        self.assertFalse(receipt["raw_secret_egress"])

    def test_payment_required_is_self_serve(self):
        receipt = account_access_receipt("Please add a payment method.")
        self.assertEqual(receipt["state"], PAYMENT_REQUIRED)
        self.assertTrue(receipt["actionable_by_automation"])
        self.assertEqual(receipt["operator_action"], "add_payment_method")

    def test_receipt_is_bounded_and_hashes_page(self):
        text = "Access is blocked due to billing status. Please add payment."
        receipt = account_access_receipt(text)
        blob = json.dumps(receipt)
        # No raw page text leaks; only a hash + bounded enums.
        self.assertNotIn("blocked due to billing", blob)
        self.assertRegex(receipt["page_text_hash"], r"^0x[0-9a-f]{64}$")

    def test_page_hash_changes_when_gate_changes(self):
        blocked = account_access_receipt("Access is blocked due to billing status.")
        active = account_access_receipt("Your account is active. API access enabled.")
        self.assertNotEqual(blocked["page_text_hash"], active["page_text_hash"])
        # Whitespace-only differences do NOT change the hash (normalized).
        a = account_access_receipt("Access is  blocked due to   billing status.")
        b = account_access_receipt("Access is blocked due to billing status.")
        self.assertEqual(a["page_text_hash"], b["page_text_hash"])


if __name__ == "__main__":
    unittest.main()
