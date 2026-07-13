"""Automate Thinking Machines Tinker signup/sign-in via browser + email oracle.

Full flow:
  1. Navigate to Tinker console → auth.thinkingmachines.ai
  2. Enter email → Continue → magic-code OTP page
  3. Poll email oracle /pin for 6-digit code → enter code
  4. Complete onboarding form (name, TOS)
  5. Create API key → capture it
  6. Seal API key and return bounded hash/status metadata

Requires:
  - Email oracle running
  - Browser automation path that Tinker does not classify as blocked
"""
import asyncio
import hashlib
import time

from playwright.async_api import async_playwright, Page

from tinker_delegate.browser_ready import connect_chromium, get_browser_context
from tinker_delegate.browser_session_store import build_browser_session_store
from tinker_delegate.api_key_store import build_api_key_store
from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    classify_automation_error,
    make_receipt,
)
from tinker_delegate.config import Settings
from tinker_delegate.oracle_client import OracleClient
from tinker_delegate.redaction import redact_text


class AuthAccessBlockedError(RuntimeError):
    """Raised when the Tinker auth flow rejects the browser session."""

    def __init__(
        self,
        message: str,
        *,
        furthest_stage: AutomationStage = AutomationStage.NOT_STARTED,
    ):
        super().__init__(message)
        self.furthest_stage = furthest_stage


API_KEY_CREATE_SELECTORS = (
    'button:has-text("New key")',
    'button:has-text("New API key")',
    'button:has-text("Create key")',
    'button:has-text("Create API key")',
    'button[aria-label="New key"]',
    'button[aria-label="New API key"]',
    'button[aria-label="Create key"]',
    'button[aria-label="Create API key"]',
    '[data-testid="new-key"]',
    '[data-testid="new-api-key"]',
    '[data-testid="create-key"]',
    '[data-testid="create-api-key"]',
    'a:has-text("New key")',
    'a:has-text("Create API key")',
)

API_KEY_CONFIRM_SELECTORS = (
    'button:has-text("Generate key")',
    'button:has-text("Generate API key")',
    'button:has-text("Create key")',
    'button:has-text("Create API key")',
    'button:has-text("Confirm")',
    'button[aria-label="Generate key"]',
    'button[aria-label="Generate API key"]',
    'button[aria-label="Create key"]',
    'button[aria-label="Create API key"]',
    'button[aria-label="Confirm"]',
    '[data-testid="generate-key"]',
    '[data-testid="generate-api-key"]',
    '[data-testid="confirm-key"]',
    '[data-testid="confirm-api-key"]',
)

API_KEY_CLOSE_SELECTORS = (
    'button:has-text("Close")',
    'button:has-text("Done")',
    'button[aria-label="Close"]',
    'button[aria-label="Done"]',
    '[data-testid="close"]',
    '[data-testid="done"]',
)

AUTH_EMAIL_SELECTORS = (
    'input[name="email"]',
)

AUTH_SUBMIT_SELECTORS = (
    'button[type="submit"]',
)

AUTH_SIGNUP_LINK_SELECTORS = (
    'a:has-text("Sign up")',
)

AUTH_FIRST_NAME_SELECTORS = (
    'input[name="first_name"]',
)

AUTH_LAST_NAME_SELECTORS = (
    'input[name="last_name"]',
)

OTP_INPUT_SELECTORS = (
    'input[inputmode="numeric"]',
    'input[data-input-otp="true"]',
    'input[autocomplete="one-time-code"]',
    'input[maxlength="1"]',
)

ONBOARDING_FULL_NAME_SELECTORS = (
    'input[name="fullName"]',
)

ONBOARDING_TOS_SELECTORS = (
    'text=I have read and agree',
)

ONBOARDING_CONTINUE_SELECTORS = (
    'button:has-text("Continue")',
)


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def _click_first_available(page: Page, selectors: tuple[str, ...]) -> str | None:
    """Click the first available selector and return the selector family hit."""
    for selector in selectors:
        locator = page.locator(selector)
        if await locator.count() > 0:
            await locator.first.click()
            return selector
    return None


async def wait_for_otp(oracle: OracleClient, settings: Settings) -> str:
    """Poll email oracle for the Tinker OTP code."""
    start = time.time()
    print("[otp] polling email oracle for verification code...")

    while time.time() - start < settings.otp_poll_timeout:
        result = oracle.get_pin(
            subject_contains="",
            max_age_seconds=settings.otp_max_age,
            extract_pattern=r"\b\d{6}\b",
            caller_identity="tinker-delegate.signup",
            reason="tinker-passwordless-auth",
            delete_after=True,
        )
        if result and result.get("pin"):
            pin = result["pin"]
            sender = str(result.get("sender", ""))
            sender_hash = _hash_text(sender) if sender else ""
            print(f"[otp] got code sender_hash={sender_hash}")
            return pin

        elapsed = int(time.time() - start)
        print(f"[otp] no code yet ({elapsed}s elapsed)...")
        await asyncio.sleep(settings.otp_poll_interval)

    raise TimeoutError(
        f"No OTP received within {settings.otp_poll_timeout}s. "
        "Check oracle readiness and inbox policy."
    )


async def enter_otp(page: Page, code: str) -> None:
    """Enter the 6-digit OTP into the verification page."""
    for selector in OTP_INPUT_SELECTORS:
        inputs = page.locator(selector)
        count = await inputs.count()
        if count >= 6:
            print(f"[otp] entering into {count} input boxes")
            for i, digit in enumerate(code[:6]):
                await inputs.nth(i).fill(digit)
                await asyncio.sleep(0.1)
            return
        elif count == 1:
            await inputs.first.fill(code)
            return

    # Last resort
    await page.keyboard.type(code, delay=80)


async def _navigate(page: Page, url: str) -> None:
    """Navigate with fallback."""
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=20000)
    except Exception:
        await page.goto("https://auth.thinkingmachines.ai/", wait_until="domcontentloaded", timeout=15000)
    await asyncio.sleep(2)


async def _page_state(page: Page) -> dict:
    """Get current page state."""
    return await page.evaluate("""() => ({
        url: window.location.href,
        text: document.body?.innerText?.substring(0, 1500) || '',
        hasEmailInput: !!document.querySelector('input[name="email"]'),
        hasFirstNameInput: !!document.querySelector('input[name="first_name"]'),
        hasFullNameInput: !!document.querySelector('input[name="fullName"]'),
        hasOtpInputs: document.querySelectorAll('input[inputmode="numeric"]').length,
    })""")


# ---------------------------------------------------------------------------
# Main entry points
# ---------------------------------------------------------------------------

async def signup(settings: Settings | None = None) -> dict:
    """Full Tinker signup: auth → onboarding → API key.

    Returns bounded metadata only. The raw API key is sealed to the local/dstack
    key store and is never returned to callers or printed.
    """
    if settings is None:
        settings = Settings()

    stage = AutomationStage.NOT_STARTED
    email = ""
    try:
        oracle = OracleClient(settings)
        email = settings.email or oracle.get_email()
    except Exception as exc:
        return _signup_failure_result(
            email=email,
            outcome=classify_automation_error(str(exc)),
            furthest_stage=stage,
            bounded_message="signup_account_lookup_failed",
            evidence=exc,
        )

    email_hash = _hash_text(email)
    print(f"[signup] email_hash={email_hash}")

    try:
        async with async_playwright() as p:
            browser = await connect_chromium(p, settings)
            stage = AutomationStage.BROWSER_CONNECTED
            context = await get_browser_context(browser, settings)
            page = context.pages[0] if context.pages else await context.new_page()
            stage = AutomationStage.BROWSER_CONTEXT_READY

            # Step 1: Authenticate
            await _authenticate(page, email, oracle, settings)
            stage = AutomationStage.AUTHENTICATED
            await _save_browser_session_state(context, settings)

            # Step 2: Handle onboarding if present
            await _handle_onboarding(page, settings)
            stage = AutomationStage.ONBOARDING_COMPLETE
            await _save_browser_session_state(context, settings)

            # Step 3: Create API key
            api_key = await _create_api_key(page, settings)
    except AuthAccessBlockedError as exc:
        stage = exc.furthest_stage if exc.furthest_stage != AutomationStage.NOT_STARTED else stage
        return _signup_failure_result(
            email=email,
            outcome=AutomationOutcome.AUTH_ACCESS_BLOCKED,
            furthest_stage=stage,
            bounded_message="auth_access_blocked",
            evidence=exc,
        )
    except Exception as exc:
        outcome = classify_automation_error(str(exc))
        return _signup_failure_result(
            email=email,
            outcome=outcome,
            furthest_stage=stage,
            bounded_message=outcome.value,
            evidence=exc,
        )

    receipt = _api_key_receipt(
        email=email,
        api_key_hash=hashlib.sha256(api_key.encode()).hexdigest() if api_key else "",
        stored=False,
        store_error="",
        selector_error=None if api_key else "API key was not captured from the keys page",
    )
    result = {
        "email_hash": email_hash,
        "api_key_created": bool(api_key),
        "api_key_hash": _hash_text(api_key) if api_key else "",
        "stored": False,
        "success": False,
        "attempt_record": receipt.to_public_dict(),
    }
    if api_key:
        try:
            store = build_api_key_store(settings)
            store.save(api_key)
            result["stored"] = True
            result["success"] = True
            result["attempt_record"] = _api_key_receipt(
                email=email,
                api_key_hash=result["api_key_hash"],
                stored=True,
                store_error="",
                selector_error=None,
            ).to_public_dict()
        except Exception as e:
            result["store_error"] = redact_text(e)
            result["attempt_record"] = _api_key_receipt(
                email=email,
                api_key_hash=result["api_key_hash"],
                stored=False,
                store_error=result["store_error"],
                selector_error=None,
            ).to_public_dict()
        print("[done] API key captured and sealed" if result["stored"] else "[done] API key captured but not stored")
    print(f"\n[done] success={result['success']}")
    return result


async def signin(settings: Settings | None = None) -> dict:
    """Sign in to existing Tinker account."""
    if settings is None:
        settings = Settings()

    oracle = OracleClient(settings)
    email = settings.email or oracle.get_email()
    email_hash = _hash_text(email)
    print(f"[signin] email_hash={email_hash}")

    async with async_playwright() as p:
        browser = await connect_chromium(p, settings)
        context = await get_browser_context(browser, settings)
        page = context.pages[0] if context.pages else await context.new_page()

        await _authenticate(page, email, oracle, settings)
        session_state_saved = await _save_browser_session_state(context, settings)

        final_url = page.url
        return {
            "email_hash": email_hash,
            "url_hash": _hash_text(final_url),
            "success": "tinker-console" in final_url,
            "session_state_saved": session_state_saved,
        }


async def reauth(settings: Settings | None = None) -> dict:
    """Refresh Tinker browser authentication through the email OTP flow.

    Returns only bounded metadata. The account email, OTP, browser URL, page
    text, and API key material do not leave this function.
    """
    if settings is None:
        settings = Settings()

    oracle = OracleClient(settings)
    email = settings.email or oracle.get_email()
    print("[reauth] starting bounded Tinker re-auth")

    try:
        async with async_playwright() as p:
            browser = await connect_chromium(p, settings)
            context = await get_browser_context(browser, settings)
            page = context.pages[0] if context.pages else await context.new_page()
            await _authenticate(page, email, oracle, settings)
            session_state_saved = await _save_browser_session_state(context, settings)
    except AuthAccessBlockedError as exc:
        receipt = _auth_receipt(
            email=email,
            outcome=AutomationOutcome.AUTH_ACCESS_BLOCKED,
            furthest_stage=exc.furthest_stage,
            bounded_message="auth_access_blocked",
            evidence=exc,
        )
        return {
            "success": False,
            "authenticated": False,
            "error_kind": AutomationOutcome.AUTH_ACCESS_BLOCKED.value,
            "attempt_record": receipt.to_public_dict(),
        }
    except Exception as exc:
        outcome = classify_automation_error(str(exc))
        receipt = _auth_receipt(
            email=email,
            outcome=outcome,
            furthest_stage=AutomationStage.NOT_STARTED,
            bounded_message=outcome.value,
            evidence=exc,
        )
        return {
            "success": False,
            "authenticated": False,
            "error_kind": outcome.value,
            "attempt_record": receipt.to_public_dict(),
        }

    receipt = _auth_receipt(
        email=email,
        outcome=AutomationOutcome.SUCCESS,
        furthest_stage=AutomationStage.AUTHENTICATED,
        bounded_message="reauthenticated",
        evidence="reauthenticated",
    )
    return {
        "success": True,
        "authenticated": True,
        "error_kind": "",
        "session_state_saved": session_state_saved,
        "attempt_record": receipt.to_public_dict(),
    }


# ---------------------------------------------------------------------------
# Internal steps
# ---------------------------------------------------------------------------

async def _save_browser_session_state(context, settings: Settings) -> bool:
    """Persist Playwright auth state encrypted inside the delegate boundary."""
    storage_state = getattr(context, "storage_state", None)
    if not callable(storage_state):
        return False
    try:
        state = await storage_state()
        build_browser_session_store(settings).save(state)
        return True
    except Exception as exc:
        print(f"[browser_session_store] session state save failed: {redact_text(exc)}")
        return False


async def _authenticate(page: Page, email: str, oracle: OracleClient, settings: Settings) -> None:
    """Navigate to auth, enter email, complete OTP. Leaves browser on console."""
    print("[auth] navigating to Tinker console...")
    await _navigate(page, settings.tinker_console_url)

    state = await _page_state(page)
    stage = AutomationStage.AUTH_PAGE_LOADED

    def ensure_not_access_blocked(state: dict, furthest_stage: AutomationStage) -> None:
        if "access blocked" in state["text"].lower():
            raise AuthAccessBlockedError(
                "Tinker auth returned 'Access blocked, please contact support.' "
                "The current headed local Chrome control passes, but the deployed "
                "headless automation path is being blocked.",
                furthest_stage=furthest_stage,
            )

    ensure_not_access_blocked(state, stage)

    # If on leftover OTP page, start fresh
    if state["hasOtpInputs"] > 0 or "magic-code" in state["url"]:
        print("[auth] clearing stale OTP page...")
        await _navigate(page, settings.tinker_console_url)
        state = await _page_state(page)
        ensure_not_access_blocked(state, stage)

    # Already authenticated?
    if "tinker-console" in state["url"] and not state["hasEmailInput"]:
        print("[auth] already authenticated")
        return

    # Enter email on sign-in page
    if state["hasEmailInput"]:
        print("[auth] entering email...")
        email_input = page.locator(AUTH_EMAIL_SELECTORS[0])
        await email_input.fill("")
        await email_input.click()
        await email_input.type(email, delay=30)
        await asyncio.sleep(0.5)

        await page.click(AUTH_SUBMIT_SELECTORS[0])
        await asyncio.sleep(4)

        state = await _page_state(page)
        stage = AutomationStage.AUTH_EMAIL_SUBMITTED
        ensure_not_access_blocked(state, stage)

        # If landed on sign-up form (new account via sign-in flow)
        if state["hasFirstNameInput"]:
            print("[auth] redirected to sign-up form, filling...")
            await page.fill(AUTH_FIRST_NAME_SELECTORS[0], settings.first_name)
            await asyncio.sleep(0.2)
            await page.fill(AUTH_LAST_NAME_SELECTORS[0], settings.last_name)
            await asyncio.sleep(0.2)
            await page.locator(AUTH_EMAIL_SELECTORS[0]).click()
            await page.locator(AUTH_EMAIL_SELECTORS[0]).type(email, delay=30)
            await asyncio.sleep(0.5)
            await page.click(AUTH_SUBMIT_SELECTORS[0])
            await asyncio.sleep(4)
            state = await _page_state(page)
            stage = AutomationStage.AUTH_EMAIL_SUBMITTED
            ensure_not_access_blocked(state, stage)

        # Should be on magic-code page now
        if "magic-code" not in state["url"] and "Check your email" not in state["text"]:
            # Try clicking Sign up link and filling the form
            signup_link = page.locator(AUTH_SIGNUP_LINK_SELECTORS[0])
            if await signup_link.count() > 0:
                print("[auth] trying sign-up flow...")
                await signup_link.click()
                await page.locator(AUTH_FIRST_NAME_SELECTORS[0]).wait_for(state="visible", timeout=10000)
                await asyncio.sleep(1)
                await page.fill(AUTH_FIRST_NAME_SELECTORS[0], settings.first_name)
                await asyncio.sleep(0.2)
                await page.fill(AUTH_LAST_NAME_SELECTORS[0], settings.last_name)
                await asyncio.sleep(0.2)
                await page.locator(AUTH_EMAIL_SELECTORS[0]).click()
                await page.locator(AUTH_EMAIL_SELECTORS[0]).type(email, delay=30)
                await asyncio.sleep(0.5)
                await page.click(AUTH_SUBMIT_SELECTORS[0])
                await asyncio.sleep(4)
                state = await _page_state(page)
                stage = AutomationStage.AUTH_EMAIL_SUBMITTED
                ensure_not_access_blocked(state, stage)

        ensure_not_access_blocked(state, stage)

    # Complete OTP
    if "magic-code" in state["url"] or "Check your email" in state["text"]:
        stage = AutomationStage.AUTH_OTP_PAGE_REACHED
        print("[auth] on OTP page, waiting for code...")
        code = await wait_for_otp(oracle, settings)
        print("[auth] entering verification code")
        await enter_otp(page, code)
        await asyncio.sleep(5)

        try:
            await page.wait_for_url("**/tinker-console.thinkingmachines.ai/**", timeout=15000)
        except Exception:
            pass

        await asyncio.sleep(2)
        print(f"[auth] authenticated url_hash={_hash_text(page.url)}")
    else:
        raise RuntimeError(
            f"Unexpected state after email submit url_hash={_hash_text(str(state['url']))}"
        )


async def _handle_onboarding(page: Page, settings: Settings) -> None:
    """Complete onboarding form if present."""
    state = await _page_state(page)

    if "onboarding" not in state["url"] and not state["hasFullNameInput"]:
        return

    print("[onboarding] completing form...")
    await page.fill(ONBOARDING_FULL_NAME_SELECTORS[0], f"{settings.first_name} {settings.last_name}")
    await asyncio.sleep(0.3)

    # TOS checkbox — click the label (input is hidden/styled)
    tos_label = page.locator(ONBOARDING_TOS_SELECTORS[0])
    if await tos_label.count() > 0:
        await tos_label.click()
        await asyncio.sleep(0.5)

    await page.click(ONBOARDING_CONTINUE_SELECTORS[0])
    await asyncio.sleep(5)
    print(f"[onboarding] done url_hash={_hash_text(page.url)}")


async def _create_api_key(page: Page, settings: Settings | None = None) -> str | None:
    """Navigate to API keys page, create a key, return it."""
    if settings is None:
        settings = Settings()
    print("[apikey] navigating to API keys page...")
    await page.goto("https://tinker-console.thinkingmachines.ai/keys",
                    wait_until="domcontentloaded", timeout=15000)
    # Wait for page to fully render (initial load shows "Loading...")
    await asyncio.sleep(3)
    await page.reload(wait_until="domcontentloaded", timeout=15000)
    await asyncio.sleep(3)

    # Click "New key" / "Create API key". Tinker has changed this copy before,
    # so keep the selector family explicit and bounded.
    create_selector = await _click_first_available(page, API_KEY_CREATE_SELECTORS)
    if not create_selector:
        print("[apikey] no create-key selector found")
        if settings.debug_screenshots:
            await page.screenshot(path="screenshot_no_new_key.png")
        return None

    print("[apikey] creating new key...")
    await asyncio.sleep(1)

    confirm_selector = await _click_first_available(page, API_KEY_CONFIRM_SELECTORS)
    if confirm_selector:
        print("[apikey] confirming key generation...")
        await asyncio.sleep(3)
    else:
        await asyncio.sleep(2)

    # Extract the key from the dialog
    api_key = await page.evaluate("""() => {
        const candidates = document.querySelectorAll('code, pre, [data-key], input[readonly], .font-mono');
        for (const el of candidates) {
            const text = (el.textContent || el.value || '').trim();
            if (text.startsWith('tml-') && text.length > 30) return text;
        }
        // Fallback: search all text nodes
        const body = document.body?.innerText || '';
        const match = body.match(/tml-[A-Za-z0-9_-]{30,}/);
        return match ? match[0] : null;
    }""")

    if api_key:
        print("[apikey] captured key")
    else:
        print("[apikey] failed to extract key")
        if settings.debug_screenshots:
            await page.screenshot(path="screenshot_key_extraction_fail.png")

    # Close dialog
    if await _click_first_available(page, API_KEY_CLOSE_SELECTORS):
        await asyncio.sleep(1)

    return api_key


def _api_key_receipt(
    *,
    email: str,
    api_key_hash: str,
    stored: bool,
    store_error: str,
    selector_error: str | None,
):
    if stored:
        return make_receipt(
            surface=AutomationSurface.API_KEY_PROVISIONING,
            outcome=AutomationOutcome.SUCCESS,
            furthest_stage=AutomationStage.API_KEY_STORED,
            evidence={"api_key_hash": api_key_hash, "stored": True},
            bounded_message="api_key_captured_and_stored",
            account_identifier=email,
        )
    if store_error:
        return make_receipt(
            surface=AutomationSurface.API_KEY_PROVISIONING,
            outcome=AutomationOutcome.STORE_FAILED,
            furthest_stage=AutomationStage.API_KEY_CAPTURED,
            evidence={"api_key_hash": api_key_hash, "store_error": store_error},
            bounded_message="api_key_captured_but_store_failed",
            account_identifier=email,
        )
    return make_receipt(
        surface=AutomationSurface.API_KEY_PROVISIONING,
        outcome=AutomationOutcome.SELECTOR_MISSING,
        furthest_stage=AutomationStage.API_KEYS_PAGE_LOADED,
        evidence=selector_error or "api_key_not_captured",
        bounded_message="api_key_not_captured",
        account_identifier=email,
    )


def _auth_receipt(
    *,
    email: str,
    outcome: AutomationOutcome,
    furthest_stage: AutomationStage,
    bounded_message: str,
    evidence: object,
):
    return make_receipt(
        surface=AutomationSurface.TINKER_AUTH,
        outcome=outcome,
        furthest_stage=furthest_stage,
        evidence=evidence,
        bounded_message=bounded_message,
        account_identifier=email,
    )


def _signup_failure_result(
    *,
    email: str,
    outcome: AutomationOutcome,
    furthest_stage: AutomationStage,
    bounded_message: str,
    evidence: object,
) -> dict:
    receipt = _auth_receipt(
        email=email,
        outcome=outcome,
        furthest_stage=furthest_stage,
        bounded_message=bounded_message,
        evidence=evidence,
    )
    result = {
        "email_hash": _hash_text(email) if email else "",
        "api_key_created": False,
        "api_key_hash": "",
        "stored": False,
        "success": False,
        "error_kind": outcome.value,
        "attempt_record": receipt.to_public_dict(),
    }
    print(f"[signup] failed outcome={outcome.value} stage={furthest_stage.value}")
    return result
