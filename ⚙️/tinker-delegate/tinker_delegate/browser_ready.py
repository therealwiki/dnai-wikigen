"""Helpers for waiting on a reachable browser endpoint."""

from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import urlparse
from urllib.request import urlopen

from playwright.async_api import Browser, BrowserContext, Playwright

from tinker_delegate.browser_session_store import build_browser_session_store
from tinker_delegate.config import Settings
from tinker_delegate.redaction import redact_text


def _cdp_probe_url(cdp_url: str) -> str:
    """Convert a CDP endpoint into a probeable HTTP URL."""
    parsed = urlparse(cdp_url)
    scheme = "https" if parsed.scheme in {"wss", "https"} else "http"
    path = parsed.path.rstrip("/")

    if path.endswith("/devtools/browser") or "/devtools/browser/" in path:
        path = ""

    base_path = path.rstrip("/")
    if base_path.endswith("/json/version"):
        probe_path = base_path
    else:
        probe_path = f"{base_path}/json/version" if base_path else "/json/version"

    return f"{scheme}://{parsed.netloc}{probe_path}"


def _probe_cdp(probe_url: str) -> tuple[bool, str]:
    """Synchronously probe the DevTools metadata endpoint."""
    try:
        with urlopen(probe_url, timeout=5) as response:
            payload = response.read().decode("utf-8", errors="replace")
        data = json.loads(payload)
        browser = data.get("Browser", "unknown")
        websocket = data.get("webSocketDebuggerUrl")
        if not websocket:
            return False, "missing webSocketDebuggerUrl"
        return True, browser
    except Exception as exc:  # pragma: no cover - transient network failures
        return False, redact_text(exc)


async def wait_for_cdp(settings: Settings) -> None:
    """Wait until Chrome DevTools is reachable from this container."""
    probe_url = _cdp_probe_url(settings.cdp_url)
    deadline = time.time() + settings.cdp_timeout

    while time.time() < deadline:
        ok, detail = await asyncio.to_thread(_probe_cdp, probe_url)
        if ok:
            print(f"[cdp] ready at {probe_url} ({detail})")
            return
        print(f"[cdp] not ready yet at {probe_url}: {detail}")
        await asyncio.sleep(settings.cdp_poll_interval)

    raise RuntimeError(
        f"cdp did not become ready within {settings.cdp_timeout}s ({probe_url})"
    )


async def connect_playwright_server(
    playwright: Playwright, settings: Settings
) -> Browser:
    """Connect to a remote Playwright browser server with retries."""
    deadline = time.time() + settings.browser_timeout

    while time.time() < deadline:
        try:
            return await asyncio.wait_for(
                playwright.chromium.connect(settings.browser_ws_endpoint),
                timeout=settings.browser_connect_timeout,
            )
        except Exception as exc:
            print(
                "[browser] remote Playwright server not ready yet at "
                f"{settings.browser_ws_endpoint}: {redact_text(exc)}"
            )
            await asyncio.sleep(settings.browser_poll_interval)

    raise RuntimeError(
        "remote Playwright browser server did not become ready within "
        f"{settings.browser_timeout}s ({settings.browser_ws_endpoint})"
    )


async def connect_chromium(playwright: Playwright, settings: Settings) -> Browser:
    """Connect to the shared browser or fall back to a bundled local Chromium."""
    if settings.browser_ws_endpoint:
        try:
            print(
                "[browser] connecting via Playwright server "
                f"{settings.browser_ws_endpoint}"
            )
            return await connect_playwright_server(playwright, settings)
        except Exception as exc:
            if not settings.local_browser_fallback:
                raise
            print(
                "[browser] remote Playwright connect failed, "
                f"falling back to local Chromium: {redact_text(exc)}"
            )

    if settings.cdp_url:
        try:
            await wait_for_cdp(settings)
            return await asyncio.wait_for(
                playwright.chromium.connect_over_cdp(settings.cdp_url),
                timeout=settings.cdp_connect_timeout,
            )
        except Exception as exc:
            if not settings.local_browser_fallback:
                raise
            print(f"[cdp] connect_over_cdp failed, falling back to local Chromium: {redact_text(exc)}")

    print("[browser] launching bundled local Chromium")
    return await playwright.chromium.launch(
        headless=settings.local_browser_headless,
        timeout=int(settings.local_browser_launch_timeout * 1000),
    )


async def get_browser_context(
    browser: Browser,
    settings: Settings | None = None,
    *,
    prefer_saved_state: bool = False,
) -> BrowserContext:
    """Return a context, optionally preferring encrypted Tinker session state."""
    should_load_state = settings is not None and (prefer_saved_state or not browser.contexts)
    if should_load_state:
        state = build_browser_session_store(settings).load()
        if state and (prefer_saved_state or not browser.contexts):
            print("[browser] creating context from encrypted Tinker session state")
            return await browser.new_context(storage_state=state)
    if browser.contexts:
        return browser.contexts[0]
    return await browser.new_context()
