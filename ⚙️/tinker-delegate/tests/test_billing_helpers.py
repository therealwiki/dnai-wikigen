import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from tinker_delegate.automation_receipts import AutomationStage
from tinker_delegate.billing import (
    CardDetails,
    add_balance,
    add_payment_method,
    _add_balance_success_detected,
    _debug_screenshot,
    _add_balance_result,
    _billing_error_message,
    _format_expiry,
    _payment_method_result,
    _payment_method_status_from_text,
)
from tinker_delegate.config import Settings


class FakeScreenshotPage:
    def __init__(self):
        self.paths = []

    async def screenshot(self, *, path: str):
        self.paths.append(path)


class BillingHelpersTest(unittest.TestCase):
    def test_format_expiry_accepts_four_digit_year(self):
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        self.assertEqual(_format_expiry(card), "1230")

    def test_format_expiry_accepts_two_digit_year(self):
        card = CardDetails("4242424242424242", "9", "30", "123", "Test User")

        self.assertEqual(_format_expiry(card), "0930")

    def test_billing_error_message_extracts_card_error(self):
        text = "Add payment method Your card number is invalid. Cancel"

        self.assertEqual(_billing_error_message(text), "Your card number is invalid.")

    def test_billing_error_message_does_not_treat_card_management_copy_as_failure(self):
        text = "Payment methods This card can be removed at any time."

        self.assertIsNone(_billing_error_message(text))

    def test_billing_error_message_does_not_treat_add_credit_modal_as_failure(self):
        text = "Add to balance Charge your default payment method to add credit to your balance."

        self.assertIsNone(_billing_error_message(text))

    def test_billing_error_message_does_not_treat_payment_methods_nav_as_failure(self):
        text = "Payment methods Billing history Credit grants Pricing Settings Current balance Credit available to spend."

        self.assertIsNone(_billing_error_message(text))

    def test_add_balance_success_requires_explicit_success_copy(self):
        self.assertTrue(_add_balance_success_detected("Credit added to your balance."))
        self.assertFalse(
            _add_balance_success_detected(
                "Payment methods Billing history Credit grants Pricing Settings Current balance Credit available to spend."
            )
        )

    def test_payment_method_status_text_is_bounded_for_empty_state(self):
        status = _payment_method_status_from_text("No payment methods yet. Add a card to get started.")

        self.assertEqual(status["card_on_file"], False)
        self.assertEqual(status["payment_method_count_band"], "zero")

    def test_payment_method_status_text_is_bounded_for_card_on_file(self):
        status = _payment_method_status_from_text("Payment methods This card can be removed at any time.")

        self.assertEqual(status["card_on_file"], True)
        self.assertEqual(status["payment_method_count_band"], "one_or_more")

    def test_payment_method_status_uses_bounded_remove_control_signal(self):
        status = _payment_method_status_from_text("Payment methods", remove_control_present=True)

        self.assertEqual(status["card_on_file"], True)
        self.assertEqual(status["payment_method_count_band"], "one_or_more")

    def test_payment_method_status_does_not_treat_add_button_alone_as_empty(self):
        status = _payment_method_status_from_text("Payment methods Add payment method")

        self.assertIsNone(status["card_on_file"])
        self.assertEqual(status["payment_method_count_band"], "unknown")

    def test_payment_method_result_returns_bounded_decline_receipt(self):
        result = _payment_method_result(
            False,
            "Your card was declined.",
            AutomationStage.PAYMENT_SUBMITTED,
            "page text",
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["attempt_record"]["surface"], "payment_method")
        self.assertEqual(result["attempt_record"]["outcome"], "card_declined")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "payment_submitted")
        self.assertTrue(result["attempt_record"]["card_payload_destroyed"])

    def test_add_balance_result_bands_amount_without_card_data(self):
        result = _add_balance_result(
            False,
            "Payment method required before adding balance",
            3.0,
            AutomationStage.ADD_BALANCE_MODAL_OPENED,
            "page text",
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "payment_method_required")
        self.assertEqual(result["attempt_record"]["amount_band"], "lt_5_usd")

    def test_auth_required_result_is_bounded_distinct_outcome(self):
        result = _payment_method_result(
            False,
            "Tinker auth required before billing",
            AutomationStage.BILLING_PAGE_LOADED,
            "raw page text should be hashed only",
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["attempt_record"]["surface"], "payment_method")
        self.assertEqual(result["attempt_record"]["outcome"], "auth_required")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "billing_page_loaded")
        self.assertNotIn("raw page text", repr(result))

    def test_add_balance_rejects_non_positive_amount_before_browser(self):
        with patch("tinker_delegate.billing.async_playwright") as playwright:
            result = asyncio.run(add_balance(0, Settings(max_add_balance_usd=5.0)))

        playwright.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "policy_denied")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "policy_denied")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        self.assertEqual(result["attempt_record"]["amount_band"], "zero_or_negative")

    def test_add_balance_rejects_non_finite_amount_before_browser(self):
        with patch("tinker_delegate.billing.async_playwright") as playwright:
            result = asyncio.run(add_balance(float("nan"), Settings(max_add_balance_usd=5.0)))

        playwright.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "policy_denied")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "policy_denied")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        self.assertEqual(result["attempt_record"]["amount_band"], "invalid_amount")

    def test_add_balance_rejects_below_tinker_minimum_before_browser(self):
        with patch("tinker_delegate.billing.async_playwright") as playwright:
            result = asyncio.run(add_balance(5.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0)))

        playwright.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "policy_denied")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "policy_denied")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")

    def test_add_balance_rejects_fractional_amount_before_browser(self):
        with patch("tinker_delegate.billing.async_playwright") as playwright:
            result = asyncio.run(add_balance(10.5, Settings(min_add_balance_usd=10.0, max_add_balance_usd=25.0)))

        playwright.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "policy_denied")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "policy_denied")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")

    def test_add_balance_rejects_over_cap_amount_before_browser(self):
        with patch("tinker_delegate.billing.async_playwright") as playwright:
            result = asyncio.run(add_balance(11.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0)))

        playwright.assert_not_called()
        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "policy_denied")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "policy_denied")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")

    def test_debug_screenshot_writes_non_secret_artifact_when_enabled(self):
        page = FakeScreenshotPage()

        wrote = asyncio.run(
            _debug_screenshot(
                page,
                Settings(debug_screenshots=True),
                "screenshot_no_stripe.png",
            )
        )

        self.assertTrue(wrote)
        self.assertEqual(page.paths, ["screenshot_no_stripe.png"])

    def test_debug_screenshot_suppresses_secret_bearing_artifact_even_when_enabled(self):
        page = FakeScreenshotPage()

        wrote = asyncio.run(
            _debug_screenshot(
                page,
                Settings(debug_screenshots=True),
                "screenshot_billing_filled.png",
                contains_secrets=True,
            )
        )

        self.assertFalse(wrote)
        self.assertEqual(page.paths, [])

    def test_debug_screenshot_disabled_by_default(self):
        page = FakeScreenshotPage()

        wrote = asyncio.run(
            _debug_screenshot(
                page,
                Settings(debug_screenshots=False),
                "screenshot_add_balance.png",
            )
        )

        self.assertFalse(wrote)
        self.assertEqual(page.paths, [])

    def test_add_payment_method_purges_configured_secret_debug_artifacts(self):
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")
        settings = Settings(debug_artifact_dir="/tmp/tinker-debug-artifacts")

        with (
            patch(
                "tinker_delegate.billing._do_add_payment_method",
                new=AsyncMock(return_value={"success": False, "error": "stubbed"}),
            ),
            patch("tinker_delegate.billing.purge_secret_debug_artifacts", return_value=2) as purge,
        ):
            result = asyncio.run(add_payment_method(card, settings))

        self.assertEqual(result["error"], "stubbed")
        purge.assert_called_once_with("/tmp/tinker-debug-artifacts")
        self.assertEqual(card.number, "")
        self.assertEqual(card.cvc, "")


if __name__ == "__main__":
    unittest.main()
