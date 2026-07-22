"""Automate Tinker billing: add payment method, add balance, configure auto-reload.

The payment form uses Stripe Elements (cross-origin iframe for PCI compliance).
Card number/exp/CVC live inside `__privateStripeFrame*` iframe.
Name, address fields are in the parent page.

Trust model:
  - Developer encrypts card details to TEE's TDX public key
  - TEE decrypts inside enclave, fills Stripe form, submits
  - Card details zeroed from memory after submission
  - Stripe tokenizes and stores the card (PCI-compliant)
  - TEE never persists card details — they're ephemeral
"""
import asyncio
import math
import re

from playwright.async_api import async_playwright, Page, Frame

from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    balance_band as classify_balance_band,
    classify_automation_error,
    make_receipt,
)
from tinker_delegate.account_access import account_access_receipt
from tinker_delegate.browser_ready import connect_chromium, get_browser_context
from tinker_delegate.config import Settings
from tinker_delegate.debug_artifacts import purge_secret_debug_artifacts
from tinker_delegate.redaction import redact_text

BILLING_BALANCE_URL = "https://tinker-console.thinkingmachines.ai/billing/balance"

ADD_TO_BALANCE_SELECTORS = (
    'button:has-text("Add to balance")',
    'button:has-text("Add balance")',
    'button:has-text("Add funds")',
    'button[aria-label="Add to balance"]',
    'button[aria-label="Add balance"]',
    '[data-testid="add-to-balance"]',
    '[data-testid="add-balance"]',
)

PAYMENT_METHODS_SELECTORS = (
    'button:has-text("Payment methods")',
    'a:has-text("Payment methods")',
    'text="Payment methods"',
    'button[aria-label="Payment methods"]',
    '[data-testid="payment-methods"]',
)

ADD_PAYMENT_METHOD_SELECTORS = (
    'button:has-text("Add payment method")',
    'button:has-text("Add card")',
    'button:has-text("Save payment method")',
    'button:has-text("Save card")',
    'button[aria-label="Add payment method"]',
    'button[aria-label="Add card"]',
    '[data-testid="add-payment-method"]',
    '[data-testid="save-payment-method"]',
)

REMOVE_PAYMENT_METHOD_SELECTORS = (
    'button:has-text("Remove")',
    'button:has-text("Remove card")',
    'button:has-text("Delete")',
    'button:has-text("Delete card")',
    'button[aria-label*="Remove" i]',
    'button[aria-label*="Delete" i]',
    '[data-testid="remove-payment-method"]',
    '[data-testid="delete-payment-method"]',
)

CONFIRM_REMOVE_PAYMENT_METHOD_SELECTORS = (
    'button:has-text("Remove")',
    'button:has-text("Delete")',
    'button:has-text("Confirm")',
    'button[aria-label*="Remove" i]',
    'button[aria-label*="Delete" i]',
    '[data-testid="confirm-remove-payment-method"]',
)

CARDHOLDER_NAME_SELECTORS = (
    "#cardholder-name",
    'input[name="cardholderName"]',
    'input[autocomplete="cc-name"]',
    'input[placeholder*="Name on card" i]',
    'input[placeholder*="Name"]',
)

ADDRESS_FIELD_SELECTORS = (
    (
        "address_line1",
        (
            "#service-line1",
            'input[name="line1"]',
            'input[autocomplete="billing address-line1"]',
            'input[placeholder*="Address line 1" i]',
        ),
    ),
    ("address_city", ("#service-city", 'input[name="city"]', 'input[autocomplete="billing address-level2"]', 'input[placeholder*="City" i]')),
    (
        "address_state",
        (
            "#service-state",
            'input[name="state"]',
            'input[autocomplete="billing address-level1"]',
            'input[placeholder*="State" i]',
            'input[placeholder*="Province" i]',
        ),
    ),
    (
        "address_postal",
        (
            "#service-postal-code",
            'input[name="postalCode"]',
            'input[autocomplete="billing postal-code"]',
            'input[placeholder*="Postal code" i]',
        ),
    ),
    (
        "address_country",
        (
            "#service-country",
            'select[name="country"]',
            'input[name="country"]',
            'input[placeholder*="Country" i]',
        ),
    ),
)

ADD_BALANCE_DIALOG_SELECTORS = (
    '[role="dialog"], dialog',
    '[role="dialog"]',
    "dialog",
    '[data-testid="add-balance-dialog"]',
)

CLOSE_DIALOG_SELECTORS = (
    'button[aria-label="Close"]',
    'button[aria-label*="close" i]',
    'button:has-text("Cancel")',
    '[data-testid="close"]',
    '[data-testid="close-dialog"]',
)

ADD_BALANCE_AMOUNT_SELECTORS = (
    'input[type="number"], input[placeholder*="amount"], input[name*="amount"]',
    'input[name="amount"]',
    'input[id*="amount" i]',
    'input[aria-label*="amount" i]',
    'input[placeholder*="Amount"]',
    'input[placeholder*="$"]',
    'input[inputmode="decimal"]',
    'input[inputmode="numeric"]',
    'input[type="text"]',
    '[role="spinbutton"]',
    '[data-testid="add-balance-amount"]',
)

ADD_BALANCE_CONFIRM_SELECTORS = (
    'button:has-text("Confirm"), button:has-text("Add balance"), button:has-text("Add credit"), button:has-text("Pay")',
    'button:has-text("Confirm")',
    'button:has-text("Add balance")',
    'button:has-text("Add credit")',
    'button:has-text("Pay")',
    'button[aria-label="Confirm"]',
    'button[aria-label="Add credit"]',
    '[data-testid="confirm-add-balance"]',
)

AUTO_RELOAD_TOGGLE_SELECTORS = (
    'text=Enable auto-reload',
)

AUTO_RELOAD_THRESHOLD_SELECTORS = (
    'input[name*="threshold"], input[placeholder*="threshold"]',
)

AUTO_RELOAD_AMOUNT_SELECTORS = (
    'input[name*="amount"], input[placeholder*="amount"]',
)

AUTO_RELOAD_SAVE_SELECTORS = (
    'button:has-text("Save")',
)

STRIPE_CARD_NUMBER_SELECTORS = (
    'input[name="cardnumber"]',
    'input[data-elements-stable-field-name="cardNumber"]',
    'input[placeholder*="Card number" i]',
)

STRIPE_CARD_EXPIRY_SELECTORS = (
    'input[name="exp-date"]',
    'input[data-elements-stable-field-name="cardExpiry"]',
)

STRIPE_CARD_CVC_SELECTORS = (
    'input[name="cvc"]',
    'input[data-elements-stable-field-name="cardCvc"]',
)

STRIPE_FRAME_MATCHERS = (
    'frame.url contains "elements-inner-card"',
    'frame.name contains "StripeFrame"',
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class CardDetails:
    """Payment card details — ephemeral, zeroed after use."""

    def __init__(
        self,
        number: str,
        exp_month: str,
        exp_year: str,
        cvc: str,
        name: str,
        address_line1: str = "",
        address_city: str = "",
        address_state: str = "",
        address_postal: str = "",
        address_country: str = "US",
    ):
        self.number = number
        self.exp_month = exp_month
        self.exp_year = exp_year
        self.cvc = cvc
        self.name = name
        self.address_line1 = address_line1
        self.address_city = address_city
        self.address_state = address_state
        self.address_postal = address_postal
        self.address_country = address_country

    def zero(self):
        """Overwrite all fields with empty strings."""
        for attr in vars(self):
            setattr(self, attr, "")


# ---------------------------------------------------------------------------
# Stripe iframe interaction
# ---------------------------------------------------------------------------

async def _find_stripe_card_frame(page: Page) -> Frame | None:
    """Find the Stripe card element iframe."""
    for frame in page.frames:
        if "elements-inner-card" in (frame.url or ""):
            return frame
    # Fallback: look for __privateStripeFrame
    for frame in page.frames:
        if frame.name and "StripeFrame" in frame.name:
            return frame
    return None


async def _fill_stripe_card(frame: Frame, card: CardDetails) -> None:
    """Type card details into the Stripe Element iframe.

    Stripe Elements uses a single combined input or separate fields.
    The combined card input accepts: number, then exp MM/YY, then CVC.
    """
    # The Stripe card element is a single input that handles all fields
    # Type card number, then tab to exp, then tab to CVC
    card_input = frame.locator(", ".join(STRIPE_CARD_NUMBER_SELECTORS))
    exp_input = frame.locator(", ".join(STRIPE_CARD_EXPIRY_SELECTORS))
    cvc_input = frame.locator(", ".join(STRIPE_CARD_CVC_SELECTORS))

    if await card_input.count() > 0:
        await card_input.click()
        await card_input.type(card.number, delay=30)
        await asyncio.sleep(0.5)

    # Exp date
    if await exp_input.count() > 0:
        await exp_input.click()
        await exp_input.type(_format_expiry(card), delay=30)
        await asyncio.sleep(0.3)

    # CVC
    if await cvc_input.count() > 0:
        await cvc_input.click()
        await cvc_input.type(card.cvc, delay=30)
        await asyncio.sleep(0.3)
    elif await card_input.count() > 0 and await exp_input.count() <= 0:
        await card_input.type(f" {_format_expiry(card)} {card.cvc}", delay=30)
        await asyncio.sleep(0.3)


def _format_expiry(card: CardDetails) -> str:
    """Return the MMYY string expected by Stripe Elements."""
    month = card.exp_month.strip().zfill(2)
    year = card.exp_year.strip()
    if len(year) == 4:
        year = year[-2:]
    return f"{month}{year}"


def _format_add_balance_amount(amount_dollars: float) -> str:
    """Return the whole-dollar amount string expected by Tinker's balance modal."""
    return str(int(amount_dollars)) if float(amount_dollars).is_integer() else str(amount_dollars)


def _add_balance_policy_error(amount_dollars: float, settings: Settings) -> str | None:
    if not math.isfinite(amount_dollars) or amount_dollars <= 0:
        return "Funding amount must be finite and positive"
    min_amount = float(getattr(settings, "min_add_balance_usd", 0) or 0)
    if amount_dollars < min_amount:
        return f"Funding amount is below Tinker minimum ${_format_add_balance_amount(min_amount)}"
    if not float(amount_dollars).is_integer():
        return "Funding amount must be a whole-dollar amount"
    if amount_dollars > settings.max_add_balance_usd:
        return "Funding amount exceeds approved cap"
    return None


def _billing_error_message(text: str) -> str | None:
    """Extract the most useful visible billing failure without returning the page."""
    normalized = re.sub(r"\s+", " ", text).strip()
    success_hints = (
        "this card can be removed at any time",
        "payment method added",
        "card added",
        "default payment method",
        "charge your default payment method to add credit",
    )
    lowered = normalized.lower()
    if any(hint in lowered for hint in success_hints):
        return None
    patterns = [
        r"(Your card[^.]*\.)",
        r"(The card[^.]*\.)",
        r"(This card (?:was|is|has)[^.]*\.)",
        r"(Payment method\b(?: required| failed| was| is| has| could| cannot| can't| not)[^.]*\.)",
        r"(Unable to[^.]*\.)",
        r"(Failed to[^.]*\.)",
        r"(declined[^.]*\.)",
        r"(invalid[^.]*\.)",
        r"(expired[^.]*\.)",
        r"(test card[^.]*\.)",
        r"(live mode[^.]*\.)",
    ]
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return None


def _add_balance_success_detected(text: str) -> bool:
    """Return true only for explicit add-balance success copy."""
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    success_hints = (
        "added to your balance",
        "credit added",
        "balance updated",
        "payment successful",
        "payment succeeded",
        "transaction successful",
        "add balance successful",
        "add credit successful",
        "balance ending in card accepted",
    )
    return any(hint in normalized for hint in success_hints)


async def _debug_screenshot(page: Page, settings: Settings, path: str, *, contains_secrets: bool = False) -> bool:
    """Write a debug screenshot only when it cannot contain card material."""
    if not settings.debug_screenshots or contains_secrets:
        return False
    await page.screenshot(path=path)
    return True


async def _click_first_available(scope, selectors: tuple[str, ...], *, prefer_last: bool = False) -> str | None:
    """Click the first matching selector in a bounded fallback family."""
    for selector in selectors:
        locator = scope.locator(selector)
        count = await locator.count()
        if count <= 0:
            continue
        target = locator.nth(count - 1) if prefer_last else locator.first
        await target.click()
        return selector
    return None


async def _fill_first_available(scope, selectors: tuple[str, ...], value: str) -> str | None:
    """Fill the first matching selector in a bounded fallback family."""
    for selector in selectors:
        locator = scope.locator(selector)
        if await locator.count() <= 0:
            continue
        await locator.first.fill(value)
        return selector
    return None


async def _any_available(scope, selectors: tuple[str, ...]) -> bool:
    """Return whether any selector in a bounded family is present."""
    for selector in selectors:
        if await scope.locator(selector).count() > 0:
            return True
    return False


def _amount_choice_selectors(amount_dollars: float) -> tuple[str, ...]:
    """Return exact-text selectors for preset amount buttons in the scoped modal."""
    amount = f"{amount_dollars:.2f}"
    dollars = amount[:-3] if amount.endswith(".00") else amount
    labels = tuple(dict.fromkeys((f"${dollars}", f"${amount}", dollars, amount)))
    selectors: list[str] = []
    for label in labels:
        selectors.extend(
            [
                f'button:text-is("{label}")',
                f'[role="button"]:text-is("{label}")',
                f'label:text-is("{label}")',
            ]
        )
    return tuple(selectors)


async def _first_available_scope(scope, selectors: tuple[str, ...]):
    """Return the first matching locator scope, or the original scope."""
    for selector in selectors:
        locator = scope.locator(selector)
        if await locator.count() > 0:
            return locator.last
    return scope


async def _dismiss_open_dialog(page: Page) -> bool:
    """Dismiss an open billing modal before interacting with background tabs."""
    for selector in ADD_BALANCE_DIALOG_SELECTORS:
        dialog = page.locator(selector)
        if await dialog.count() <= 0:
            continue
        scope = dialog.last
        if await _click_first_available(scope, CLOSE_DIALOG_SELECTORS, prefer_last=True):
            await asyncio.sleep(0.5)
            return True
        keyboard = getattr(page, "keyboard", None)
        if keyboard is not None:
            await keyboard.press("Escape")
            await asyncio.sleep(0.5)
            return True
        return False
    return False


def _payment_method_status_from_text(text: str, *, remove_control_present: bool = False) -> dict:
    """Return bounded card-on-file status without card brand, last4, or expiry."""
    lowered = text.lower()
    no_card = (
        "no payment methods yet" in lowered
        or "add a card to get started" in lowered
    )
    card_on_file = (
        remove_control_present
        or "this card can be removed at any time" in lowered
        or "default payment method" in lowered
        or "remove card" in lowered
    )
    if card_on_file:
        count_band = "one_or_more"
    elif no_card:
        count_band = "zero"
    else:
        count_band = "unknown"
    return {
        "card_on_file": card_on_file if count_band != "unknown" else None,
        "payment_method_count_band": count_band,
    }


async def _billing_auth_blocker(page: Page) -> str | None:
    """Return a bounded auth-state reason when billing controls are unavailable."""
    text = await page.evaluate("() => document.body?.innerText || ''")
    lowered = text.lower()
    url = (getattr(page, "url", "") or "").lower()

    if "access blocked" in lowered:
        return "Tinker auth access blocked before billing"
    if "magic-code" in url or "check your email" in lowered:
        return "Tinker auth required before billing"
    if "sign in" in lowered or "log in" in lowered or "login" in lowered:
        return "Tinker auth required before billing"
    if await page.locator('input[type="email"], input[name="email"], input[autocomplete="email"]').count() > 0:
        return "Tinker auth required before billing"
    return None


async def _try_inline_billing_reauth(page: Page, context, settings: Settings) -> bool:
    """Refresh auth in the same browser context before a billing retry."""
    if not settings.allow_auth_automation_endpoint:
        return False
    try:
        from tinker_delegate.oracle_client import OracleClient
        from tinker_delegate.signup import _authenticate, _save_browser_session_state

        oracle = OracleClient(settings)
        email = settings.email or oracle.get_email()
        print("[billing] auth required; attempting same-context bounded reauth")
        await _authenticate(page, email, oracle, settings)
        await _save_browser_session_state(context, settings)
        return True
    except Exception as exc:
        print(f"[billing] same-context reauth failed: {redact_text(exc)}")
        return False


async def _ensure_billing_authenticated(
    page: Page,
    context,
    settings: Settings,
    *,
    wait_after_retry: float = 3,
) -> str | None:
    """Return an auth blocker after one same-context reauth retry."""
    auth_blocker = await _billing_auth_blocker(page)
    if not auth_blocker:
        return None
    if not await _try_inline_billing_reauth(page, context, settings):
        return auth_blocker
    await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
    await asyncio.sleep(wait_after_retry)
    return await _billing_auth_blocker(page)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def add_payment_method(card: CardDetails, settings: Settings | None = None) -> dict:
    """Add a payment method to the Tinker account.

    Fills the Stripe card form + address fields, submits.
    Card details are zeroed from memory after submission.

    Returns dict with success status.
    """
    if settings is None:
        settings = Settings()

    try:
        return await _do_add_payment_method(card, settings)
    finally:
        card.zero()
        if settings.purge_secret_debug_artifacts:
            purge_secret_debug_artifacts(settings.debug_artifact_dir)


async def _do_add_payment_method(card: CardDetails, settings: Settings) -> dict:
    """Internal: fill and submit the payment method form."""
    furthest_stage = AutomationStage.NOT_STARTED
    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        # Navigate to billing page
        print("[billing] navigating to billing page...")
        await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.BILLING_PAGE_LOADED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            return _payment_method_result(False, auth_blocker, furthest_stage, auth_blocker)

        # Click "Add to balance" to trigger the payment modal
        # (which includes "Add payment method" if no card exists)
        if await _click_first_available(page, ADD_TO_BALANCE_SELECTORS):
            await asyncio.sleep(3)
            furthest_stage = AutomationStage.PAYMENT_MODAL_OPENED
            auth_blocker = await _ensure_billing_authenticated(page, context, settings)
            if auth_blocker:
                return _payment_method_result(False, auth_blocker, furthest_stage, auth_blocker)

        # Check if we got the add payment method form
        text = await page.evaluate("() => document.body?.innerText || ''")
        if "Add payment method" not in text:
            await _dismiss_open_dialog(page)
            # Try payment methods tab directly
            if await _click_first_available(page, PAYMENT_METHODS_SELECTORS):
                await asyncio.sleep(2)
            if await _click_first_available(page, ADD_PAYMENT_METHOD_SELECTORS, prefer_last=True):
                await asyncio.sleep(3)
                furthest_stage = AutomationStage.PAYMENT_MODAL_OPENED

        # Wait for Stripe iframe to load
        print("[billing] waiting for Stripe card element...")
        stripe_frame = None
        for _ in range(10):
            stripe_frame = await _find_stripe_card_frame(page)
            if stripe_frame:
                break
            await asyncio.sleep(1)

        if not stripe_frame:
            await _debug_screenshot(page, settings, "screenshot_no_stripe.png")
            error = "Stripe card iframe not found"
            return _payment_method_result(False, error, furthest_stage, text)
        furthest_stage = AutomationStage.STRIPE_IFRAME_FOUND

        # Fill Stripe card fields
        print("[billing] filling card details in Stripe iframe...")
        await _fill_stripe_card(stripe_frame, card)

        # Fill parent page fields
        print("[billing] filling name and address...")
        if await _fill_first_available(page, CARDHOLDER_NAME_SELECTORS, card.name):
            await asyncio.sleep(0.2)

        # Address fields
        for attr, selectors in ADDRESS_FIELD_SELECTORS:
            value = getattr(card, attr)
            if value:
                if await _fill_first_available(page, selectors, value):
                    await asyncio.sleep(0.1)
        furthest_stage = AutomationStage.PAYMENT_FORM_FILLED

        await asyncio.sleep(1)
        await _debug_screenshot(
            page,
            settings,
            "screenshot_billing_filled.png",
            contains_secrets=True,
        )

        # Submit
        print("[billing] submitting payment method...")
        if await _click_first_available(page, ADD_PAYMENT_METHOD_SELECTORS, prefer_last=True):
            furthest_stage = AutomationStage.PAYMENT_SUBMITTED
        else:
            error = "Add payment method submit selector not found"
            return _payment_method_result(False, error, furthest_stage, text)

        await asyncio.sleep(5)

        # Check result
        text = await page.evaluate("() => document.body?.innerText || ''")
        await _debug_screenshot(
            page,
            settings,
            "screenshot_billing_result.png",
            contains_secrets=True,
        )

        error_msg = _billing_error_message(text)
        if error_msg:
            return _payment_method_result(False, error_msg, furthest_stage, text)

        # Check if payment method now shows up
        lowered = text.lower()
        success = (
            "ending in" in lowered
            or "visa" in lowered
            or "mastercard" in lowered
            or "this card can be removed at any time" in lowered
            or "payment method added" in lowered
            or "card added" in lowered
            or "charge your default payment method to add credit" in lowered
        )
        print(f"[billing] payment method added: {success}")

        if not success:
            return _payment_method_result(False, "Payment method was not added", furthest_stage, text)
        return _payment_method_result(True, None, furthest_stage, text)


async def add_balance(amount_dollars: float, settings: Settings | None = None) -> dict:
    """Add credit balance to the Tinker account.

    Requires a payment method to already be on file.
    """
    if settings is None:
        settings = Settings()

    furthest_stage = AutomationStage.NOT_STARTED
    error = _add_balance_policy_error(amount_dollars, settings)
    if error:
        return _add_balance_result(False, error, amount_dollars, furthest_stage, error)

    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.BILLING_PAGE_LOADED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            return _add_balance_result(False, auth_blocker, amount_dollars, furthest_stage, auth_blocker)

        # Click "Add to balance"
        if not await _click_first_available(page, ADD_TO_BALANCE_SELECTORS):
            error = "Add-balance open selector not found"
            return _add_balance_result(False, error, amount_dollars, furthest_stage, error)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.ADD_BALANCE_MODAL_OPENED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            return _add_balance_result(False, auth_blocker, amount_dollars, furthest_stage, auth_blocker)

        text = await page.evaluate("() => document.body?.innerText || ''")
        if "Add payment method" in text and "Name on card" in text:
            error = "Payment method required before adding balance"
            return _add_balance_result(False, error, amount_dollars, furthest_stage, error)

        # Look for amount input
        scope = await _first_available_scope(page, ADD_BALANCE_DIALOG_SELECTORS)
        amount_text = _format_add_balance_amount(amount_dollars)
        if await _fill_first_available(scope, ADD_BALANCE_AMOUNT_SELECTORS, amount_text):
            await asyncio.sleep(0.5)
            furthest_stage = AutomationStage.ADD_BALANCE_AMOUNT_FILLED
        elif await _click_first_available(scope, _amount_choice_selectors(amount_dollars)):
            await asyncio.sleep(0.5)
            furthest_stage = AutomationStage.ADD_BALANCE_AMOUNT_FILLED
        else:
            error = "Add-balance amount input not found"
            return _add_balance_result(False, error, amount_dollars, furthest_stage, error)

        # Submit
        if await _click_first_available(scope, ADD_BALANCE_CONFIRM_SELECTORS):
            await asyncio.sleep(5)
            furthest_stage = AutomationStage.ADD_BALANCE_SUBMITTED
        else:
            error = "Add-balance submit button not found"
            return _add_balance_result(False, error, amount_dollars, furthest_stage, error)

        text = await page.evaluate("() => document.body?.innerText || ''")
        await _debug_screenshot(page, settings, "screenshot_add_balance.png")

        error_msg = _billing_error_message(text)
        if error_msg:
            return _add_balance_result(False, error_msg, amount_dollars, furthest_stage, error_msg)
        if _add_balance_success_detected(text):
            return _add_balance_result(True, None, amount_dollars, furthest_stage, text)
        error = "Add-balance completion not confirmed"
        return _add_balance_result(False, error, amount_dollars, furthest_stage, text)


async def get_payment_method_status(settings: Settings | None = None) -> dict:
    """Return bounded payment-method presence, never card details."""
    if settings is None:
        settings = Settings()

    furthest_stage = AutomationStage.NOT_STARTED
    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.BILLING_PAGE_LOADED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            return _payment_method_status_result(False, auth_blocker, furthest_stage, auth_blocker)

        await _click_first_available(page, PAYMENT_METHODS_SELECTORS)
        await asyncio.sleep(2)
        text = await page.evaluate("() => document.body?.innerText || ''")
        remove_control_present = await _any_available(page, REMOVE_PAYMENT_METHOD_SELECTORS)
        status = _payment_method_status_from_text(text, remove_control_present=remove_control_present)
        if status["payment_method_count_band"] == "unknown":
            return _payment_method_status_result(False, "Payment method status unknown", furthest_stage, text, **status)
        return _payment_method_status_result(True, None, furthest_stage, status, **status)


async def get_account_access_status(settings: Settings | None = None) -> dict:
    """Capture the account's access/billing gate as a bounded receipt.

    Navigates the billing page (reusing the TEE-owned authenticated session) and
    classifies the visible access/billing state — active, access_blocked_billing,
    payment_required, waitlist_or_gated, or unknown — plus whether the automation
    can resolve it and a page-text hash to detect gate changes across runs. It
    egresses only the bounded receipt, never raw page text, card, or secrets.
    """
    if settings is None:
        settings = Settings()

    furthest_stage = AutomationStage.NOT_STARTED
    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.BILLING_PAGE_LOADED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            outcome = classify_automation_error(auth_blocker)
            return {
                "success": False,
                "furthest_stage": furthest_stage.value if hasattr(furthest_stage, "value") else str(furthest_stage),
                "state": "unknown",
                "actionable_by_automation": False,
                "operator_action": "resolve_billing_auth",
                "bounded_message": outcome.value,
                "raw_secret_egress": False,
            }

        text = await page.evaluate("() => document.body?.innerText || ''")
        receipt = account_access_receipt(text)
        receipt["success"] = True
        receipt["furthest_stage"] = (
            furthest_stage.value if hasattr(furthest_stage, "value") else str(furthest_stage)
        )
        return receipt


async def remove_payment_method(settings: Settings | None = None) -> dict:
    """Remove a card-on-file from the Tinker billing page without exposing details."""
    if settings is None:
        settings = Settings()

    furthest_stage = AutomationStage.NOT_STARTED
    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(BILLING_BALANCE_URL, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)
        furthest_stage = AutomationStage.BILLING_PAGE_LOADED
        auth_blocker = await _ensure_billing_authenticated(page, context, settings)
        if auth_blocker:
            return _payment_method_removal_result(False, auth_blocker, furthest_stage, auth_blocker)

        await _click_first_available(page, PAYMENT_METHODS_SELECTORS)
        await asyncio.sleep(2)
        text = await page.evaluate("() => document.body?.innerText || ''")
        status = _payment_method_status_from_text(text)
        if status["payment_method_count_band"] == "zero":
            return _payment_method_removal_result(True, None, furthest_stage, {"already_absent": True})

        if not await _click_first_available(page, REMOVE_PAYMENT_METHOD_SELECTORS, prefer_last=True):
            error = "Remove payment method selector not found"
            return _payment_method_removal_result(False, error, furthest_stage, error)
        await asyncio.sleep(1)

        if await _click_first_available(page, CONFIRM_REMOVE_PAYMENT_METHOD_SELECTORS, prefer_last=True):
            await asyncio.sleep(3)

        text = await page.evaluate("() => document.body?.innerText || ''")
        status = _payment_method_status_from_text(text)
        if status["payment_method_count_band"] == "zero":
            return _payment_method_removal_result(True, None, furthest_stage, {"removed": True})
        return _payment_method_removal_result(False, "Payment method removal not confirmed", furthest_stage, text)


async def configure_auto_reload(
    enabled: bool = True,
    threshold: float = 10.0,
    amount: float = 50.0,
    settings: Settings | None = None,
) -> dict:
    """Configure auto-reload: automatically add credit when balance drops."""
    if settings is None:
        settings = Settings()

    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(
            "https://tinker-console.thinkingmachines.ai/billing/balance",
            wait_until="domcontentloaded", timeout=15000,
        )
        await asyncio.sleep(3)
        await page.reload(wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)

        # Find auto-reload checkbox
        text = await page.evaluate("() => document.body?.innerText || ''")
        if "auto-reload" not in text.lower():
            return {"success": False, "error": AutomationOutcome.SELECTOR_MISSING.value}

        # Toggle checkbox
        checkbox = page.locator(AUTO_RELOAD_TOGGLE_SELECTORS[0])
        if await checkbox.count() > 0:
            await checkbox.click()
            await asyncio.sleep(1)

        # Fill threshold and amount if inputs appear
        # (depends on UI — inputs may only show when enabled)
        threshold_input = page.locator(", ".join(AUTO_RELOAD_THRESHOLD_SELECTORS))
        if await threshold_input.count() > 0:
            await threshold_input.fill(str(threshold))

        amount_input = page.locator(", ".join(AUTO_RELOAD_AMOUNT_SELECTORS))
        if await amount_input.count() > 0:
            await amount_input.fill(str(amount))

        # Save
        save_btn = page.locator(AUTO_RELOAD_SAVE_SELECTORS[0])
        if await save_btn.count() > 0:
            await save_btn.click()
            await asyncio.sleep(3)

        await _debug_screenshot(page, settings, "screenshot_auto_reload.png")
        return {"success": True}


async def get_balance(settings: Settings | None = None) -> dict:
    """Return only a stable balance band; keep the exact value in-boundary."""
    if settings is None:
        settings = Settings()

    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings, prefer_saved_state=True)
        page = context.pages[0] if context.pages else await context.new_page()

        await page.goto(
            "https://tinker-console.thinkingmachines.ai/billing/balance",
            wait_until="domcontentloaded", timeout=15000,
        )
        await asyncio.sleep(3)
        await page.reload(wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(3)

        balance = await page.evaluate("""() => {
            const text = document.body?.innerText || '';
            const match = text.match(/\\$([\\d,.]+)/);
            return match ? match[1] : null;
        }""")

        exact_balance = f"${balance}" if balance else "unknown"
        return {
            "success": True,
            "balance_band": classify_balance_band(exact_balance),
            "raw_secret_egress": False,
        }


def _payment_method_result(
    success: bool,
    error: str | None,
    furthest_stage: AutomationStage,
    evidence: object,
) -> dict:
    outcome = AutomationOutcome.SUCCESS if success else classify_automation_error(error)
    receipt = make_receipt(
        surface=AutomationSurface.PAYMENT_METHOD,
        outcome=outcome,
        furthest_stage=furthest_stage,
        evidence=evidence if success else error,
        bounded_message=outcome.value,
        card_payload_destroyed=True,
    )
    return {
        "success": success,
        "error": None if success else outcome.value,
        "attempt_record": receipt.to_public_dict(),
    }


def _add_balance_result(
    success: bool,
    error: str | None,
    amount_dollars: float,
    furthest_stage: AutomationStage,
    evidence: object,
) -> dict:
    outcome = AutomationOutcome.SUCCESS if success else classify_automation_error(error)
    receipt = make_receipt(
        surface=AutomationSurface.ADD_BALANCE,
        outcome=outcome,
        furthest_stage=furthest_stage,
        evidence=evidence if success else error,
        bounded_message=outcome.value,
        amount_dollars=amount_dollars,
    )
    return {
        "success": success,
        "error": None if success else outcome.value,
        "attempt_record": receipt.to_public_dict(),
    }


def _payment_method_status_result(
    success: bool,
    error: str | None,
    furthest_stage: AutomationStage,
    evidence: object,
    *,
    card_on_file: bool | None = None,
    payment_method_count_band: str = "unknown",
) -> dict:
    outcome = AutomationOutcome.SUCCESS if success else classify_automation_error(error)
    receipt = make_receipt(
        surface=AutomationSurface.PAYMENT_METHOD_STATUS,
        outcome=outcome,
        furthest_stage=furthest_stage,
        evidence=evidence if success else error,
        bounded_message=outcome.value,
    )
    return {
        "success": success,
        "error": None if success else outcome.value,
        "card_on_file": card_on_file,
        "payment_method_count_band": payment_method_count_band,
        "attempt_record": receipt.to_public_dict(),
    }


def _payment_method_removal_result(
    success: bool,
    error: str | None,
    furthest_stage: AutomationStage,
    evidence: object,
) -> dict:
    outcome = AutomationOutcome.SUCCESS if success else classify_automation_error(error)
    receipt = make_receipt(
        surface=AutomationSurface.PAYMENT_METHOD_REMOVAL,
        outcome=outcome,
        furthest_stage=furthest_stage,
        evidence=evidence if success else error,
        bounded_message=outcome.value,
    )
    return {
        "success": success,
        "error": None if success else outcome.value,
        "attempt_record": receipt.to_public_dict(),
    }
