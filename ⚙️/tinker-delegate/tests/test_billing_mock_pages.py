import unittest
from unittest.mock import AsyncMock, patch

from tinker_delegate.billing import (
    ADD_BALANCE_AMOUNT_SELECTORS,
    ADD_BALANCE_CONFIRM_SELECTORS,
    ADD_PAYMENT_METHOD_SELECTORS,
    ADD_TO_BALANCE_SELECTORS,
    CARDHOLDER_NAME_SELECTORS,
    REMOVE_PAYMENT_METHOD_SELECTORS,
    CardDetails,
    _do_add_payment_method,
    _fill_stripe_card,
    _find_stripe_card_frame,
    _amount_choice_selectors,
    add_balance,
    get_balance,
    get_payment_method_status,
)
from tinker_delegate.config import Settings


class AsyncPlaywrightStub:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeContext:
    def __init__(self, page):
        self.pages = [page]

    async def new_page(self):
        return self.pages[0]


class FakeField:
    def __init__(self, selector: str, actions: list[tuple[str, str, str]], *, count: int = 1):
        self.selector = selector
        self.actions = actions
        self._count = count
        self.index = 0

    async def count(self):
        return self._count

    @property
    def first(self):
        self.index = 0
        return self

    @property
    def last(self):
        self.index = max(self._count - 1, 0)
        return self

    def nth(self, index: int):
        field = FakeField(self.selector, self.actions, count=self._count)
        field.index = index
        return field

    def locator(self, selector: str):
        return self.page.locator(selector) if hasattr(self, "page") else FakeField(selector, self.actions)

    async def click(self):
        if (
            getattr(getattr(self, "page", None), "modal_open", False)
            and self.selector == 'button:has-text("Payment methods")'
        ):
            raise RuntimeError("scrim intercepts pointer events")
        if self.selector in {
            'button[aria-label="Close"]',
            'button[aria-label*="close" i]',
            'button:has-text("Cancel")',
            '[data-testid="close"]',
            '[data-testid="close-dialog"]',
        } and hasattr(self, "page"):
            self.page.modal_open = False
        self.actions.append(("click", self.selector, str(self.index)))

    async def fill(self, value: str):
        self.actions.append(("fill", self.selector, value))

    async def type(self, value: str, **_kwargs):
        self.actions.append(("type", self.selector, value))


class FakeStripeFrame:
    def __init__(self, *, url: str = "", name: str = ""):
        self.url = url
        self.name = name
        self.actions: list[tuple[str, str, str]] = []
        self.available_selectors = {
            'input[name="cardnumber"], input[data-elements-stable-field-name="cardNumber"], input[placeholder*="Card number" i]',
            'input[name="exp-date"], input[data-elements-stable-field-name="cardExpiry"]',
            'input[name="cvc"], input[data-elements-stable-field-name="cardCvc"]',
        }

    def locator(self, selector: str):
        return FakeField(
            selector,
            self.actions,
            count=1 if selector in self.available_selectors else 0,
        )


class FakeKeyboard:
    def __init__(self, page):
        self.page = page

    async def press(self, key: str):
        self.page.actions.append(("press", "keyboard", key))
        if key == "Escape":
            self.page.modal_open = False


class FakeBillingPage:
    def __init__(
        self,
        *,
        frames=None,
        initial_text: str = "Add payment method",
        result_text: str = "Your card was declined.",
        dialog_present: bool = True,
        amount_input_present: bool = True,
        confirm_present: bool = True,
        modal_open: bool = False,
        available_overrides: dict[str, int] | None = None,
        url: str = "https://tinker-console.thinkingmachines.ai/billing/balance",
    ):
        self.frames = frames or []
        self.initial_text = initial_text
        self.result_text = result_text
        self.url = url
        self.dialog_present = dialog_present
        self.amount_input_present = amount_input_present
        self.confirm_present = confirm_present
        self.modal_open = modal_open
        self.keyboard = FakeKeyboard(self)
        self.goto_urls: list[str] = []
        self.reload_count = 0
        self.evaluate_count = 0
        self.screenshots: list[str] = []
        self.actions: list[tuple[str, str, str]] = []
        self.available_counts = {
            'button:has-text("Add to balance")': 1,
            'button:has-text("Payment methods")': 0,
            'button:has-text("Add payment method")': 2,
            "#cardholder-name": 1,
            "#service-line1": 1,
            "#service-city": 1,
            "#service-state": 1,
            "#service-postal-code": 1,
            "#service-country": 1,
            '[role="dialog"], dialog': 1 if dialog_present else 0,
            'input[type="number"], input[placeholder*="amount"], input[name*="amount"]': (
                1 if amount_input_present else 0
            ),
            'button:has-text("Confirm"), button:has-text("Add balance"), button:has-text("Add credit"), button:has-text("Pay")': (
                1 if confirm_present else 0
            ),
        }
        if available_overrides:
            self.available_counts.update(available_overrides)

    async def goto(self, url: str, **_kwargs):
        self.goto_urls.append(url)

    async def reload(self, **_kwargs):
        self.reload_count += 1

    def locator(self, selector: str):
        field = FakeField(selector, self.actions, count=self.available_counts.get(selector, 0))
        field.page = self
        return field

    async def evaluate(self, _script: str):
        self.evaluate_count += 1
        if self.evaluate_count == 1:
            return self.initial_text
        return self.result_text

    async def screenshot(self, *, path: str):
        self.screenshots.append(path)


class BillingMockPagesTest(unittest.IsolatedAsyncioTestCase):
    async def test_find_stripe_frame_by_elements_url_or_private_name(self):
        by_url = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        by_name = FakeStripeFrame(name="__privateStripeFrame123")
        page = type("Page", (), {"frames": [FakeStripeFrame(), by_url]})()

        self.assertIs(await _find_stripe_card_frame(page), by_url)

        page = type("Page", (), {"frames": [FakeStripeFrame(), by_name]})()
        self.assertIs(await _find_stripe_card_frame(page), by_name)

    async def test_fill_stripe_card_uses_stripe_field_selectors(self):
        frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()):
            await _fill_stripe_card(frame, card)

        self.assertEqual(
            frame.actions,
            [
                (
                    "click",
                    'input[name="cardnumber"], input[data-elements-stable-field-name="cardNumber"], input[placeholder*="Card number" i]',
                    "0",
                ),
                (
                    "type",
                    'input[name="cardnumber"], input[data-elements-stable-field-name="cardNumber"], input[placeholder*="Card number" i]',
                    "4242424242424242",
                ),
                (
                    "click",
                    'input[name="exp-date"], input[data-elements-stable-field-name="cardExpiry"]',
                    "0",
                ),
                (
                    "type",
                    'input[name="exp-date"], input[data-elements-stable-field-name="cardExpiry"]',
                    "1230",
                ),
                (
                    "click",
                    'input[name="cvc"], input[data-elements-stable-field-name="cardCvc"]',
                    "0",
                ),
                (
                    "type",
                    'input[name="cvc"], input[data-elements-stable-field-name="cardCvc"]',
                    "123",
                ),
            ],
        )

    async def test_add_payment_method_mock_page_reaches_stripe_decline_receipt(self):
        stripe_frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        page = FakeBillingPage(frames=[stripe_frame], result_text="Your card was declined.")
        card = CardDetails(
            "4242424242424242",
            "12",
            "2030",
            "123",
            "Test User",
            address_line1="123 Main St",
            address_city="SF",
            address_state="CA",
            address_postal="94105",
            address_country="US",
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await _do_add_payment_method(card, Settings(debug_screenshots=True))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "card_declined")
        self.assertEqual(result["attempt_record"]["surface"], "payment_method")
        self.assertEqual(result["attempt_record"]["outcome"], "card_declined")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "payment_submitted")
        self.assertNotIn("4242424242424242", repr(result))
        self.assertEqual(page.screenshots, [])
        self.assertIn(("fill", "#cardholder-name", "Test User"), page.actions)
        self.assertIn(("fill", "#service-postal-code", "94105"), page.actions)
        self.assertIn(("click", 'button:has-text("Add payment method")', "1"), page.actions)

    async def test_add_payment_method_uses_selector_fallbacks_for_changed_billing_ui(self):
        stripe_frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        page = FakeBillingPage(
            frames=[stripe_frame],
            available_overrides={
                ADD_TO_BALANCE_SELECTORS[0]: 0,
                ADD_TO_BALANCE_SELECTORS[-1]: 1,
                ADD_PAYMENT_METHOD_SELECTORS[0]: 0,
                ADD_PAYMENT_METHOD_SELECTORS[-1]: 2,
                CARDHOLDER_NAME_SELECTORS[0]: 0,
                CARDHOLDER_NAME_SELECTORS[1]: 1,
            },
        )
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await _do_add_payment_method(card, Settings())

        self.assertFalse(result["success"])
        self.assertEqual(result["attempt_record"]["outcome"], "card_declined")
        self.assertIn(("click", ADD_TO_BALANCE_SELECTORS[-1], "0"), page.actions)
        self.assertIn(("fill", CARDHOLDER_NAME_SELECTORS[1], "Test User"), page.actions)
        self.assertIn(("click", ADD_PAYMENT_METHOD_SELECTORS[-1], "1"), page.actions)

    async def test_add_payment_method_dismisses_open_modal_before_tab_fallback(self):
        stripe_frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        page = FakeBillingPage(
            frames=[stripe_frame],
            initial_text="Current balance $0",
            result_text="Current balance $0",
            modal_open=True,
            available_overrides={
                'button:has-text("Payment methods")': 1,
                'button:has-text("Cancel")': 0,
            },
        )
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            await _do_add_payment_method(card, Settings())

        self.assertIn(("press", "keyboard", "Escape"), page.actions)
        self.assertIn(("click", 'button:has-text("Payment methods")', "0"), page.actions)
        self.assertFalse(page.modal_open)

    async def test_add_payment_method_treats_card_management_copy_as_success(self):
        stripe_frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        page = FakeBillingPage(
            frames=[stripe_frame],
            result_text="Payment methods\nThis card can be removed at any time.",
        )
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await _do_add_payment_method(card, Settings())

        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["attempt_record"]["surface"], "payment_method")
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "payment_submitted")

    async def test_add_payment_method_treats_follow_on_add_credit_modal_as_success(self):
        stripe_frame = FakeStripeFrame(url="https://js.stripe.com/elements-inner-card.html")
        page = FakeBillingPage(
            frames=[stripe_frame],
            result_text="Add to balance\nCharge your default payment method to add credit to your balance.\nAmount (USD)",
        )
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await _do_add_payment_method(card, Settings())

        self.assertTrue(result["success"])
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "payment_submitted")

    async def test_add_payment_method_reports_auth_access_blocked_before_selector_search(self):
        page = FakeBillingPage(initial_text="Access blocked, please contact support.")
        card = CardDetails("4242424242424242", "12", "2030", "123", "Test User")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await _do_add_payment_method(card, Settings())

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "auth_access_blocked")
        self.assertEqual(result["attempt_record"]["surface"], "payment_method")
        self.assertEqual(result["attempt_record"]["outcome"], "auth_access_blocked")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "billing_page_loaded")
        self.assertEqual(page.actions, [])

    async def test_add_balance_mock_page_detects_missing_payment_method(self):
        page = FakeBillingPage(
            initial_text="Add payment method\nName on card",
            result_text="Add payment method\nName on card",
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "payment_method_required")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "payment_method_required")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_modal_opened")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")

    async def test_add_balance_reports_auth_required_before_selector_search(self):
        page = FakeBillingPage(
            initial_text="Sign in to continue",
            available_overrides={selector: 0 for selector in ADD_TO_BALANCE_SELECTORS},
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "auth_required")
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "auth_required")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "billing_page_loaded")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")
        self.assertEqual(page.actions, [])

    async def test_add_balance_retries_after_inline_reauth(self):
        page = FakeBillingPage(
            initial_text="Sign in to continue",
            result_text="Credit added to your balance.",
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing._try_inline_billing_reauth", new=AsyncMock(return_value=True)) as reauth,
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(
                10.0,
                Settings(
                    allow_auth_automation_endpoint=True,
                    min_add_balance_usd=10.0,
                    max_add_balance_usd=10.0,
                ),
            )

        self.assertTrue(result["success"])
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_submitted")
        reauth.assert_awaited_once()

    async def test_add_balance_reports_missing_open_selector_before_amount_entry(self):
        page = FakeBillingPage(
            initial_text="Current balance $0",
            available_overrides={selector: 0 for selector in ADD_TO_BALANCE_SELECTORS},
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "selector_missing")
        self.assertEqual(result["attempt_record"]["outcome"], "selector_missing")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "billing_page_loaded")
        self.assertNotIn("Current balance", repr(result))

    async def test_add_balance_mock_page_fills_amount_and_submits(self):
        page = FakeBillingPage(
            initial_text="Current balance $0",
            result_text="Balance ending in card accepted",
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertTrue(result["success"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["attempt_record"]["surface"], "add_balance")
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_submitted")
        self.assertEqual(result["attempt_record"]["amount_band"], "5_25_usd")
        self.assertIn(
            ("fill", 'input[type="number"], input[placeholder*="amount"], input[name*="amount"]', "10"),
            page.actions,
        )
        self.assertIn(
            (
                "click",
                ADD_BALANCE_CONFIRM_SELECTORS[0],
                "0",
            ),
            page.actions,
        )

    async def test_add_balance_uses_amount_and_confirm_selector_fallbacks(self):
        page = FakeBillingPage(
            initial_text="Current balance $0",
            result_text="Balance ending in card accepted",
            available_overrides={
                ADD_BALANCE_AMOUNT_SELECTORS[0]: 0,
                ADD_BALANCE_AMOUNT_SELECTORS[-1]: 1,
                ADD_BALANCE_CONFIRM_SELECTORS[0]: 0,
                ADD_BALANCE_CONFIRM_SELECTORS[-1]: 1,
            },
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertTrue(result["success"])
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_submitted")
        self.assertIn(("fill", ADD_BALANCE_AMOUNT_SELECTORS[-1], "10"), page.actions)
        self.assertIn(("click", ADD_BALANCE_CONFIRM_SELECTORS[-1], "0"), page.actions)

    async def test_add_balance_can_choose_exact_preset_amount_when_input_is_absent(self):
        preset_selector = _amount_choice_selectors(10.0)[0]
        page = FakeBillingPage(
            initial_text="Current balance $0",
            result_text="Balance ending in card accepted",
            available_overrides={
                **{selector: 0 for selector in ADD_BALANCE_AMOUNT_SELECTORS},
                preset_selector: 1,
            },
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertTrue(result["success"])
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_submitted")
        self.assertIn(("click", preset_selector, "0"), page.actions)
        self.assertIn(
            (
                "click",
                ADD_BALANCE_CONFIRM_SELECTORS[0],
                "0",
            ),
            page.actions,
        )

    async def test_add_balance_reports_unconfirmed_completion_without_page_text(self):
        page = FakeBillingPage(
            initial_text="Current balance $0",
            result_text="Payment methods Billing history Credit grants Pricing Settings Current balance Credit available to spend.",
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await add_balance(10.0, Settings(min_add_balance_usd=10.0, max_add_balance_usd=10.0))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"], "unknown_failure")
        self.assertEqual(result["attempt_record"]["outcome"], "unknown_failure")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "add_balance_submitted")
        self.assertNotIn("Payment methods", result["attempt_record"]["bounded_message"])
        self.assertNotIn("Credit available", repr(result))

    async def test_payment_method_status_uses_remove_control_without_card_details(self):
        page = FakeBillingPage(
            initial_text="Current balance $0",
            result_text="Payment methods Billing history Credit grants Pricing Settings",
            available_overrides={
                'button:has-text("Payment methods")': 1,
                REMOVE_PAYMENT_METHOD_SELECTORS[0]: 1,
            },
        )

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await get_payment_method_status(Settings())

        self.assertTrue(result["success"])
        self.assertTrue(result["card_on_file"])
        self.assertEqual(result["payment_method_count_band"], "one_or_more")
        self.assertEqual(result["attempt_record"]["bounded_message"], "success")
        self.assertNotIn("Payment methods Billing history", repr(result))

    async def test_get_balance_returns_only_a_stable_band(self):
        page = FakeBillingPage(initial_text="$80.37 private exact account balance")

        with (
            patch("tinker_delegate.billing.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.billing.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.billing.get_browser_context", new=AsyncMock(return_value=FakeContext(page))),
            patch("tinker_delegate.billing.asyncio.sleep", new=AsyncMock()),
        ):
            result = await get_balance(Settings())

        self.assertEqual(
            result,
            {
                "success": True,
                "balance_band": "10_100_usd",
                "raw_secret_egress": False,
            },
        )
        self.assertNotIn("80.37", repr(result))
        self.assertNotIn("$", repr(result))


if __name__ == "__main__":
    unittest.main()
