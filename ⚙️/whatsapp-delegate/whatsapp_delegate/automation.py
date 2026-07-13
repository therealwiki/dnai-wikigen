"""WhatsApp Web automation via Playwright + CDP.

Connects to the neko Chrome instance over CDP, logs into WhatsApp Web
via QR code scanning, then extracts chat history from the DOM.

WhatsApp Web QR login flow:
  1. Navigate to web.whatsapp.com
  2. WhatsApp displays a QR code
  3. User scans QR with phone camera (WhatsApp → Linked Devices → Link device)
  4. Browser becomes a linked device, chats sync
  5. Scrape chat list and messages

Also supports phone-number linking code as a fallback.
"""

from __future__ import annotations

import asyncio
import base64
import os
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import Page, async_playwright

from .config import settings
from .sealed_store import WhatsAppExport

WHATSAPP_URL = "https://web.whatsapp.com"

# Safety bounds
MAX_CHATS = 100
MAX_MESSAGES_PER_CHAT = 500
PAGE_TIMEOUT = 60_000

# Path for QR code image
QR_CODE_PATH = "/data/qr_code.png"


async def _connect_browser():
    """Connect to neko Chrome via CDP."""
    p = await async_playwright().start()
    browser = await p.chromium.connect_over_cdp(settings.cdp_url)
    return p, browser


async def _find_whatsapp_page(browser):
    """Find the open WhatsApp Web page, or None."""
    for pg in browser.contexts[0].pages:
        if "web.whatsapp.com" in pg.url:
            return pg
    return None


# ---------------------------------------------------------------------------
# QR code login (primary method)
# ---------------------------------------------------------------------------


async def login_qr() -> dict:
    """Navigate to WhatsApp Web and return the QR code for scanning.

    The user scans the QR with their phone:
      WhatsApp → Settings → Linked Devices → Link device → point camera

    Returns:
        {"status": "awaiting_scan", "qr_image_path": "/data/qr_code.png"}
        or {"status": "error", "detail": "..."}
    """
    p, browser = await _connect_browser()
    try:
        # Close any stale WhatsApp pages
        for pg in browser.contexts[0].pages:
            if "web.whatsapp.com" in pg.url:
                await pg.close()

        page = await browser.contexts[0].new_page()
        await page.goto(WHATSAPP_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT)

        # Wait for QR code to render (canvas element inside the QR container)
        try:
            await page.wait_for_selector("canvas", timeout=30_000)
        except Exception:
            return {"status": "error", "detail": "WhatsApp Web did not show QR code in time"}

        # Extra wait for the QR to be fully painted
        await page.wait_for_timeout(2000)

        # Extract QR code from canvas as PNG
        qr_b64 = await page.evaluate("""() => {
            const canvas = document.querySelector('canvas');
            if (!canvas) return null;
            return canvas.toDataURL('image/png');
        }""")

        if not qr_b64:
            return {"status": "error", "detail": "Could not extract QR code from canvas"}

        # Save QR image
        data = qr_b64.split(",")[1]
        raw = base64.b64decode(data)
        Path(QR_CODE_PATH).parent.mkdir(parents=True, exist_ok=True)
        Path(QR_CODE_PATH).write_bytes(raw)

        return {
            "status": "awaiting_scan",
            "detail": (
                "Scan this QR code with your phone: "
                "WhatsApp → Settings → Linked Devices → Link device → point camera at QR"
            ),
        }

    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def get_qr_code() -> bytes | None:
    """Get a fresh QR code image (PNG bytes).

    WhatsApp rotates the QR code every ~20 seconds. This extracts
    the current one from the canvas.

    Returns:
        PNG bytes or None if no QR is available.
    """
    p, browser = await _connect_browser()
    page = await _find_whatsapp_page(browser)
    if page is None:
        return None

    qr_b64 = await page.evaluate("""() => {
        const canvas = document.querySelector('canvas');
        if (!canvas) return null;
        return canvas.toDataURL('image/png');
    }""")

    if not qr_b64:
        return None

    data = qr_b64.split(",")[1]
    return base64.b64decode(data)


# ---------------------------------------------------------------------------
# Phone-number linking code login (fallback)
# ---------------------------------------------------------------------------


async def login_phone(phone_number: str) -> dict:
    """Navigate to WhatsApp Web, enter phone number, return the linking code.

    Fallback method if QR scanning isn't convenient.

    Args:
        phone_number: Full international number, e.g. "+15551234567"

    Returns:
        {"status": "awaiting_link", "linking_code": "2AJP-FPD1", ...}
        or {"status": "error", "detail": "..."}
    """
    p, browser = await _connect_browser()
    try:
        # Close any stale WhatsApp pages
        for pg in browser.contexts[0].pages:
            if "web.whatsapp.com" in pg.url:
                await pg.close()

        page = await browser.contexts[0].new_page()
        await page.goto(WHATSAPP_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT)

        # Wait for QR page to render
        try:
            await page.wait_for_selector(
                'text="Log in with phone number"',
                timeout=30_000,
            )
        except Exception:
            return {"status": "error", "detail": "WhatsApp Web did not load in time"}

        # Extra wait for React hydration
        await page.wait_for_timeout(3000)

        # Click "Log in with phone number"
        btn = page.locator('div[role=button]:has-text("Log in with phone number")')
        await btn.last.click(timeout=5000)
        await page.wait_for_timeout(3000)

        # Find and fill the phone number input
        phone_input = page.locator(
            'input[aria-label="Type your phone number to log in to WhatsApp"]'
        )
        try:
            await phone_input.wait_for(timeout=10_000)
        except Exception:
            phone_input = page.locator("input[type='text']").first
            try:
                await phone_input.wait_for(timeout=5_000)
            except Exception:
                return {"status": "error", "detail": "Could not find phone input field"}

        # Strip country code — the field already has the prefix from the selector
        import re

        current_value = await phone_input.input_value()
        prefix = current_value.strip()

        local_number = phone_number.strip()
        if prefix and local_number.startswith(prefix):
            local_number = local_number[len(prefix):]
        elif local_number.startswith("+"):
            m = re.match(r"^\+(\d{1,3})", local_number)
            if m:
                local_number = local_number[len(m.group(0)):]
        local_number = local_number.strip()

        await phone_input.fill(local_number)
        await page.wait_for_timeout(500)

        # Click Next
        next_btn = page.get_by_text("Next", exact=True)
        try:
            await next_btn.click(timeout=5000)
        except Exception:
            await page.keyboard.press("Enter")

        await page.wait_for_timeout(5000)

        # Extract the linking code
        linking_code = await _extract_linking_code(page)
        if not linking_code:
            return {"status": "error", "detail": "Could not extract linking code from page"}

        return {
            "status": "awaiting_link",
            "linking_code": linking_code,
            "detail": (
                f"Enter code {linking_code} on your phone: "
                "WhatsApp → Settings → Linked Devices → Link device → "
                '"Link with phone number instead" → type this code'
            ),
        }

    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def _extract_linking_code(page: Page) -> str | None:
    """Extract the linking code from the code display page."""
    try:
        heading = page.get_by_text("Enter code on phone")
        await heading.wait_for(timeout=5000)
    except Exception:
        return None

    text = await page.inner_text("body")
    lines = text.split("\n")

    code_chars = []
    capturing = False
    for line in lines:
        line = line.strip()
        if "Enter code on phone" in line:
            capturing = True
            continue
        if capturing:
            if len(line) == 1 and (line.isalnum() or line == "-"):
                code_chars.append(line)
            elif line.startswith("Open WhatsApp") or line.startswith("1"):
                break
            if len(line) > 3:
                continue

    if len(code_chars) >= 8:
        raw = "".join(code_chars)
        if "-" in raw:
            return raw
        return f"{raw[:4]}-{raw[4:]}"

    return None


# ---------------------------------------------------------------------------
# Login status / waiting
# ---------------------------------------------------------------------------


async def check_login_status() -> dict:
    """Check if WhatsApp Web session is linked and chats are loaded.

    Returns:
        {"status": "logged_in"} or {"status": "waiting"} or {"status": "error", ...}
    """
    p, browser = await _connect_browser()
    try:
        page = await _find_whatsapp_page(browser)
        if page is None:
            return {"status": "error", "detail": "No WhatsApp Web page open"}

        # Check for chat list (indicates successful link)
        chat_list = page.locator('[aria-label="Chat list"]')
        try:
            await chat_list.wait_for(timeout=5_000)
            return {"status": "logged_in", "detail": "WhatsApp Web session active"}
        except Exception:
            pass

        # Still on QR page?
        canvas = page.locator("canvas")
        try:
            await canvas.wait_for(timeout=2_000)
            return {"status": "waiting", "detail": "QR code displayed — scan it with your phone"}
        except Exception:
            pass

        # Still on code page?
        code_heading = page.get_by_text("Enter code on phone")
        try:
            await code_heading.wait_for(timeout=2_000)
            return {"status": "waiting", "detail": "Linking code displayed — enter it on your phone"}
        except Exception:
            pass

        return {"status": "waiting", "detail": "Page state unclear — try again"}

    except Exception as e:
        return {"status": "error", "detail": str(e)}


async def wait_for_login(timeout_seconds: int = 120) -> dict:
    """Poll until WhatsApp Web session is linked or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout_seconds
    while asyncio.get_event_loop().time() < deadline:
        result = await check_login_status()
        if result["status"] == "logged_in":
            return result
        if result["status"] == "error":
            return result
        await asyncio.sleep(3)
    return {"status": "timeout", "detail": f"Login not completed within {timeout_seconds}s"}


# ---------------------------------------------------------------------------
# Chat export
# ---------------------------------------------------------------------------


async def export_chats(max_chats: int = MAX_CHATS) -> WhatsAppExport:
    """Extract chat list and messages from a logged-in WhatsApp Web session."""
    p, browser = await _connect_browser()
    page = await _find_whatsapp_page(browser)

    if page is None:
        raise RuntimeError("No logged-in WhatsApp Web page found")

    try:
        await page.wait_for_selector('[aria-label="Chat list"]', timeout=10_000)
    except Exception:
        raise RuntimeError("WhatsApp Web not logged in — link your phone first")

    chats: list[dict] = []

    chat_items = page.locator(
        '[aria-label="Chat list"] [role="listitem"],'
        '[aria-label="Chat list"] [role="row"],'
        '[data-testid="chat-list"] [role="listitem"],'
        '[data-testid="cell-frame-container"]'
    )
    count = min(await chat_items.count(), max_chats)

    for i in range(count):
        try:
            item = chat_items.nth(i)
            await item.scroll_into_view_if_needed()
            await item.click()
            await page.wait_for_timeout(800)

            chat_data = await _extract_current_chat(page)
            if chat_data:
                chats.append(chat_data)
        except Exception:
            continue

    phone = await _get_logged_in_phone(page)

    return WhatsAppExport(
        phone=phone,
        export_ts=datetime.now(timezone.utc).isoformat(),
        chats=chats,
    )


async def _extract_current_chat(page: Page) -> dict | None:
    """Extract messages from the currently open chat."""
    try:
        header = page.locator(
            '[data-testid="conversation-header"] span[title],'
            '[data-testid="conversation-info-header"] span[title],'
            'header span[title]'
        )
        name = "Unknown"
        try:
            name = await header.first.get_attribute("title", timeout=3000) or "Unknown"
        except Exception:
            try:
                name = await header.first.inner_text(timeout=2000)
            except Exception:
                pass

        msg_container = page.locator(
            '[data-testid="conversation-panel-messages"],'
            '[role="application"]'
        )
        for _ in range(3):
            try:
                await msg_container.evaluate("el => el.scrollTop = 0")
                await page.wait_for_timeout(500)
            except Exception:
                break

        messages: list[dict] = []
        msg_rows = page.locator(
            '[data-testid="msg-container"],'
            '.message-in, .message-out'
        )
        msg_count = min(await msg_rows.count(), MAX_MESSAGES_PER_CHAT)

        for j in range(msg_count):
            try:
                row = msg_rows.nth(j)
                text_el = row.locator(
                    '[data-testid="balloon-text"],'
                    '.selectable-text span[dir]'
                )
                text = ""
                try:
                    text = await text_el.first.inner_text(timeout=1000)
                except Exception:
                    continue

                classes = await row.evaluate("el => el.className") or ""
                outer = await row.evaluate("el => el.getAttribute('data-testid') || ''")
                is_outgoing = "message-out" in classes or "msg-self" in outer
                sender = "me" if is_outgoing else name

                ts_el = row.locator('[data-testid="msg-meta"] span')
                timestamp = ""
                try:
                    timestamp = await ts_el.first.inner_text(timeout=500)
                except Exception:
                    pass

                messages.append({"sender": sender, "text": text, "timestamp": timestamp})
            except Exception:
                continue

        if not messages:
            return None

        return {"name": name, "messages": messages}

    except Exception:
        return None


async def _get_logged_in_phone(page: Page) -> str:
    """Try to extract the logged-in phone number from the profile."""
    try:
        profile_btn = page.locator(
            '[data-testid="menu-bar-avatar"],'
            '[data-testid="default-user"],'
            '[aria-label="Profile"]'
        )
        await profile_btn.click(timeout=3000)
        await page.wait_for_timeout(500)

        phone_el = page.locator('[data-testid="profile-phone"], [data-testid="about-phone"]')
        phone = await phone_el.inner_text(timeout=2000)

        await page.keyboard.press("Escape")
        return phone.strip()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Debug
# ---------------------------------------------------------------------------


async def take_screenshot() -> str:
    """Screenshot the current WhatsApp Web state."""
    p, browser = await _connect_browser()
    pages = browser.contexts[0].pages
    page = pages[-1] if pages else await browser.contexts[0].new_page()

    out = os.path.join(settings.data_dir, "whatsapp_screenshot.png")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    await page.screenshot(path=out, full_page=True)
    return out
