"""Create a cock.li email account via HTTP POST (primary) or browser CDP (fallback).

Primary path: pure HTTP — fetch registration page, solve CSS captcha, POST form.
Fallback: playwright CDP to neko chromium container.
"""

import imaplib
import os
import re
import secrets

import httpx

from email_oracle.config import Settings
from email_oracle.cred_store import CredentialStore, EmailCredentials
from email_oracle.redaction import hash_text, redact_text


from captcha_solver.parser import parse_box_shadow_pixels, pixels_to_image, extract_captcha_key
from captcha_solver.solver import solve_from_image
from captcha_solver.fetcher import _extract_field


UA = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
PASSWORD_CONFIRM_FIELD = "password_confinm"
PASSWORD_CONFIRM_HONEYPOT_FIELD = "password_confirm"


def generate_credentials(domain: str) -> EmailCredentials:
    """Generate random credentials inside the enclave."""
    username = secrets.token_hex(8)  # 16-char hex string
    password = secrets.token_urlsafe(32)  # 256-bit password
    return EmailCredentials(username=username, domain=domain, password=password)


def _registration_form_data(
    *,
    csrf: str,
    creds: EmailCredentials,
    captcha_key: str,
    captcha_solution: str,
) -> dict[str, str]:
    """Build cock.li registration form data without filling honeypots."""
    return {
        "csrf": csrf,
        "csrf_valid": csrf,
        "username": creds.username,
        "domain": creds.domain,
        "password": creds.password,
        # cock.li currently misspells the real confirm field as "confinm".
        PASSWORD_CONFIRM_FIELD: creds.password,
        "captcha_key": captcha_key,
        "captcha_solution": captcha_solution,
        "noscript": "1",
        "tos_agree": "on",
        PASSWORD_CONFIRM_HONEYPOT_FIELD: "",
    }


def signup_http(settings: Settings) -> EmailCredentials:
    """Create account via HTTP POST (no browser needed).

    1. GET /register.php → HTML with captcha + CSRF
    2. Parse CSS box-shadow captcha → solve via template matching
    3. POST form with credentials + captcha solution
    4. Verify IMAP login works
    """
    creds = generate_credentials(settings.cockli_domain)
    email_hash = hash_text(creds.email)
    print(f"[signup] attempting HTTP registration email_hash={email_hash}")

    with httpx.Client(
        follow_redirects=True,
        timeout=30.0,
        headers={"User-Agent": UA},
    ) as client:
        # Fetch registration page
        resp = client.get(settings.cockli_register_url)
        resp.raise_for_status()
        html = resp.text

        # Extract form tokens
        csrf = _extract_field(html, "csrf")
        captcha_key = extract_captcha_key(html)

        # Solve captcha
        pixels = parse_box_shadow_pixels(html)
        img = pixels_to_image(pixels, scale=1)
        captcha_solution = solve_from_image(img)
        print("[signup] captcha solved")

        # Submit registration
        form_data = _registration_form_data(
            csrf=csrf,
            creds=creds,
            captcha_key=captcha_key,
            captcha_solution=captcha_solution,
        )

        resp = client.post(
            settings.cockli_register_url,
            data=form_data,
            headers={
                "User-Agent": UA,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": settings.cockli_register_url,
            },
        )
        resp.raise_for_status()

        # Check for failure indicators in response
        response_text = resp.text
        response_lower = response_text.lower()

        # cock.li shows specific error messages in the form
        if "already taken" in response_lower or "username is taken" in response_lower:
            raise RuntimeError(f"Generated mailbox collision email_hash={email_hash}")
        if "incorrect" in response_lower and "captcha" in response_lower:
            raise RuntimeError("Captcha solution was incorrect")

        # If the registration page is shown again (captcha div present),
        # something went wrong
        if "box-shadow:" in response_text and "captcha_key" in response_text:
            # Registration form re-rendered = submission failed
            raise RuntimeError("Registration form re-rendered (likely captcha or CSRF error)")

    # Verify IMAP login
    verify_imap_login(creds, settings)
    print(f"[signup] account created and IMAP verified email_hash={email_hash}")
    return creds


def verify_imap_login(creds: EmailCredentials, settings: Settings) -> None:
    """Verify credentials work via IMAP."""
    print(f"[signup] verifying IMAP login email_hash={hash_text(creds.email)}")
    mail = imaplib.IMAP4_SSL(settings.cockli_imap_host, settings.cockli_imap_port)
    try:
        mail.login(creds.imap_login, creds.password)
        mail.select("INBOX")
        print(f"[signup] IMAP login successful")
    finally:
        try:
            mail.logout()
        except Exception:
            pass


async def signup_browser(settings: Settings) -> EmailCredentials:
    """Fallback: create account via playwright CDP to neko chromium.

    Used when HTTP POST fails (e.g. form structure changes).
    Connects to neko's chromium via CDP proxy on port 9222.
    """
    from playwright.async_api import async_playwright

    creds = generate_credentials(settings.cockli_domain)
    email_hash = hash_text(creds.email)
    print(f"[signup] attempting browser registration email_hash={email_hash}")
    print(f"[signup] connecting to CDP at {settings.cdp_url}")

    async with async_playwright() as p:
        browser = await p.chromium.connect_over_cdp(settings.cdp_url)
        context = browser.contexts[0] if browser.contexts else await browser.new_context()
        page = await context.new_page()

        try:
            await page.goto(settings.cockli_register_url, wait_until="domcontentloaded")

            # Solve captcha from page HTML
            html = await page.content()
            pixels = parse_box_shadow_pixels(html)
            img = pixels_to_image(pixels, scale=1)
            captcha_solution = solve_from_image(img)
            print("[signup] captcha solved")

            # Fill form
            await page.fill('input[name="username"]', creds.username)
            await page.select_option('select[name="domain"]', creds.domain)
            await page.fill('input[name="password"]', creds.password)
            await page.fill(f'input[name="{PASSWORD_CONFIRM_FIELD}"]', creds.password)
            await page.fill('input[name="captcha_solution"]', captcha_solution)
            await page.check('input[name="tos_agree"]')

            # Submit
            await page.click('button:has-text("Register"), input[type="submit"]')
            await page.wait_for_load_state("networkidle", timeout=15000)

            # Check result
            result_text = (await page.content()).lower()
            if "already taken" in result_text:
                raise RuntimeError(f"Generated mailbox collision email_hash={email_hash}")
            if "incorrect" in result_text and "captcha" in result_text:
                raise RuntimeError("Captcha solution was incorrect")

        finally:
            await page.close()

    # Verify IMAP login
    verify_imap_login(creds, settings)
    print(f"[signup] browser registration succeeded email_hash={email_hash}")
    return creds


async def create_account(
    settings: Settings,
    store: CredentialStore,
    max_retries: int = 3,
) -> EmailCredentials:
    """Create account with retry logic. Try HTTP first, fall back to browser.

    Returns credentials and saves them to the encrypted store.
    """
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            print(f"[signup] attempt {attempt}/{max_retries} (HTTP POST)")
            creds = signup_http(settings)
            store.save(creds)
            return creds
        except Exception as e:
            last_error = e
            print(f"[signup] HTTP attempt {attempt} failed: {redact_text(e)}")

    # Fall back to browser if HTTP failed
    if settings.use_browser_fallback:
        for attempt in range(1, max_retries + 1):
            try:
                print(f"[signup] browser fallback attempt {attempt}/{max_retries}")
                creds = await signup_browser(settings)
                store.save(creds)
                return creds
            except Exception as e:
                last_error = e
                print(f"[signup] browser attempt {attempt} failed: {redact_text(e)}")

    raise RuntimeError(f"Account creation failed after all attempts: {redact_text(last_error)}")
