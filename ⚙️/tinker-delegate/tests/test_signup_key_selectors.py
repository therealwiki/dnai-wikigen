import unittest
from unittest.mock import AsyncMock, patch

from tinker_delegate.config import Settings
from tinker_delegate.signup import _create_api_key


KEY_VALUE = "tml-" + "A" * 40


class FakeLocator:
    def __init__(self, page, selector: str):
        self.page = page
        self.selector = selector

    async def count(self):
        return 1 if self.selector in self.page.available_selectors else 0

    @property
    def first(self):
        return self

    async def click(self):
        self.page.clicked.append(self.selector)
        self.page.available_selectors.discard(self.selector)
        if self.selector == self.page.create_selector:
            self.page.available_selectors.add(self.page.confirm_selector)
        if self.selector == self.page.confirm_selector and self.page.key_after_confirm:
            self.page.key_visible = True
            self.page.available_selectors.add(self.page.close_selector)


class FakeKeyPage:
    def __init__(
        self,
        *,
        create_selector: str | None,
        confirm_selector: str = '[data-testid="generate-api-key"]',
        close_selector: str = '[data-testid="done"]',
        key_after_confirm: bool = True,
    ):
        self.create_selector = create_selector
        self.confirm_selector = confirm_selector
        self.close_selector = close_selector
        self.key_after_confirm = key_after_confirm
        self.key_visible = False
        self.clicked: list[str] = []
        self.goto_urls: list[str] = []
        self.reload_count = 0
        self.screenshots: list[str] = []
        self.available_selectors = set()
        if create_selector:
            self.available_selectors.add(create_selector)

    async def goto(self, url: str, **_kwargs):
        self.goto_urls.append(url)

    async def reload(self, **_kwargs):
        self.reload_count += 1

    def locator(self, selector: str):
        return FakeLocator(self, selector)

    async def evaluate(self, _script: str):
        return KEY_VALUE if self.key_visible else None

    async def screenshot(self, *, path: str):
        self.screenshots.append(path)


class SignupKeySelectorTest(unittest.IsolatedAsyncioTestCase):
    async def test_create_api_key_uses_data_testid_selector_family(self):
        page = FakeKeyPage(create_selector='[data-testid="create-api-key"]')

        with patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()):
            api_key = await _create_api_key(page, Settings())

        self.assertEqual(api_key, KEY_VALUE)
        self.assertEqual(page.goto_urls, ["https://tinker-console.thinkingmachines.ai/keys"])
        self.assertEqual(page.reload_count, 1)
        self.assertEqual(
            page.clicked,
            [
                '[data-testid="create-api-key"]',
                '[data-testid="generate-api-key"]',
                '[data-testid="done"]',
            ],
        )
        self.assertEqual(page.screenshots, [])

    async def test_create_api_key_uses_aria_selector_family(self):
        page = FakeKeyPage(
            create_selector='button[aria-label="Create API key"]',
            confirm_selector='button[aria-label="Confirm"]',
            close_selector='button[aria-label="Done"]',
        )

        with patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()):
            api_key = await _create_api_key(page, Settings())

        self.assertEqual(api_key, KEY_VALUE)
        self.assertEqual(
            page.clicked,
            [
                'button[aria-label="Create API key"]',
                'button[aria-label="Confirm"]',
                'button[aria-label="Done"]',
            ],
        )

    async def test_create_api_key_reports_missing_create_selector_without_key(self):
        page = FakeKeyPage(create_selector=None)

        with patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()):
            api_key = await _create_api_key(page, Settings(debug_screenshots=True))

        self.assertIsNone(api_key)
        self.assertEqual(page.clicked, [])
        self.assertEqual(page.screenshots, ["screenshot_no_new_key.png"])

    async def test_create_api_key_reports_extraction_failure_without_raw_page_text(self):
        page = FakeKeyPage(
            create_selector='button:has-text("New key")',
            key_after_confirm=False,
        )

        with patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()):
            api_key = await _create_api_key(page, Settings(debug_screenshots=True))

        self.assertIsNone(api_key)
        self.assertEqual(
            page.clicked,
            ['button:has-text("New key")', '[data-testid="generate-api-key"]'],
        )
        self.assertEqual(page.screenshots, ["screenshot_key_extraction_fail.png"])


if __name__ == "__main__":
    unittest.main()
