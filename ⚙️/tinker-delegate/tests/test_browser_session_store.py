import asyncio
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.browser_ready import get_browser_context
from tinker_delegate.browser_session_store import BrowserSessionStore
from tinker_delegate.config import Settings


class FakeBrowser:
    def __init__(self):
        self.contexts = []
        self.created_storage_state = None

    async def new_context(self, **kwargs):
        self.created_storage_state = kwargs.get("storage_state")
        context = object()
        self.contexts.append(context)
        return context


class BrowserSessionStoreTest(unittest.TestCase):
    def test_round_trips_encrypted_storage_state_without_plain_cookie_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "browser_session.enc"
            store = BrowserSessionStore(
                str(path),
                "11" * 32,
                dstack_enabled=False,
            )
            state = {
                "cookies": [
                    {
                        "name": "session",
                        "value": "secret-cookie-value",
                        "domain": "tinker-console.thinkingmachines.ai",
                        "path": "/",
                    }
                ],
                "origins": [
                    {
                        "origin": "https://tinker-console.thinkingmachines.ai",
                        "localStorage": [{"name": "token", "value": "secret-local-storage"}],
                    }
                ],
            }

            store.save(state)

            self.assertEqual(store.load(), state)
            raw = path.read_bytes()
            self.assertNotIn(b"secret-cookie-value", raw)
            self.assertNotIn(b"secret-local-storage", raw)
            self.assertNotIn(b"tinker-console.thinkingmachines.ai", raw)

    def test_get_browser_context_loads_encrypted_storage_state_for_new_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "browser_session.enc"
            state = {"cookies": [{"name": "session", "value": "secret"}], "origins": []}
            BrowserSessionStore(str(path), "22" * 32, dstack_enabled=False).save(state)
            settings = Settings(
                browser_session_store_path=str(path),
                browser_session_store_key="22" * 32,
            )
            browser = FakeBrowser()

            context = asyncio.run(get_browser_context(browser, settings))

            self.assertIs(context, browser.contexts[0])
            self.assertEqual(browser.created_storage_state, state)

    def test_get_browser_context_reuses_existing_context_without_loading_store(self):
        settings = Settings(browser_session_store_path="/path/that/does/not/exist.enc")
        existing_context = object()
        browser = FakeBrowser()
        browser.contexts = [existing_context]

        context = asyncio.run(get_browser_context(browser, settings))

        self.assertIs(context, existing_context)
        self.assertIsNone(browser.created_storage_state)

    def test_get_browser_context_can_prefer_saved_state_over_existing_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "browser_session.enc"
            state = {"cookies": [{"name": "session", "value": "secret"}], "origins": []}
            BrowserSessionStore(str(path), "33" * 32, dstack_enabled=False).save(state)
            settings = Settings(
                browser_session_store_path=str(path),
                browser_session_store_key="33" * 32,
            )
            existing_context = object()
            browser = FakeBrowser()
            browser.contexts = [existing_context]

            context = asyncio.run(
                get_browser_context(browser, settings, prefer_saved_state=True)
            )

            self.assertIsNot(context, existing_context)
            self.assertIs(context, browser.contexts[-1])
            self.assertEqual(browser.created_storage_state, state)


if __name__ == "__main__":
    unittest.main()
