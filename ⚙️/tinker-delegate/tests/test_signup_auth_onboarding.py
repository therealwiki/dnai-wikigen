import unittest
from unittest.mock import AsyncMock, Mock, patch

from tinker_delegate.automation_receipts import AutomationStage
from tinker_delegate.config import Settings
from tinker_delegate.oracle_client import ORACLE_CALLER_IDENTITY
from tinker_delegate.signup import (
    AuthAccessBlockedError,
    _authenticate,
    _handle_onboarding,
    enter_otp,
    wait_for_otp,
)


class FakeFillable:
    def __init__(self, selector: str, sink: list[tuple[str, str]]):
        self.selector = selector
        self.sink = sink

    async def fill(self, value: str):
        self.sink.append((self.selector, value))

    async def click(self):
        self.sink.append((self.selector, "click"))

    async def type(self, value: str, **_kwargs):
        self.sink.append((self.selector, value))

    async def wait_for(self, **_kwargs):
        self.sink.append((self.selector, "wait_for"))


class FakeOtpLocator:
    def __init__(self, selector: str, count: int, fills: list[tuple[int, str]]):
        self.selector = selector
        self._count = count
        self.fills = fills
        self.index = 0

    async def count(self):
        return self._count

    @property
    def first(self):
        self.index = 0
        return self

    def nth(self, index: int):
        child = FakeOtpLocator(self.selector, self._count, self.fills)
        child.index = index
        return child

    async def fill(self, value: str):
        self.fills.append((self.index, value))


class FakeKeyboard:
    def __init__(self):
        self.typed: list[str] = []

    async def type(self, value: str, **_kwargs):
        self.typed.append(value)


class FakeOtpPage:
    def __init__(self, count_by_selector: dict[str, int]):
        self.count_by_selector = count_by_selector
        self.fills: list[tuple[int, str]] = []
        self.keyboard = FakeKeyboard()

    def locator(self, selector: str):
        return FakeOtpLocator(selector, self.count_by_selector.get(selector, 0), self.fills)


class FakeSelectorLocator:
    def __init__(self, selector: str, count: int, clicks: list[str]):
        self.selector = selector
        self._count = count
        self.clicks = clicks

    async def count(self):
        return self._count

    async def click(self):
        self.clicks.append(self.selector)


class FakeOnboardingPage:
    url = "https://tinker-console.thinkingmachines.ai/onboarding"

    def __init__(self, *, has_tos: bool = True):
        self.has_tos = has_tos
        self.fills: list[tuple[str, str]] = []
        self.clicks: list[str] = []

    async def fill(self, selector: str, value: str):
        self.fills.append((selector, value))

    def locator(self, selector: str):
        count = 1 if selector == "text=I have read and agree" and self.has_tos else 0
        return FakeSelectorLocator(selector, count, self.clicks)

    async def click(self, selector: str):
        self.clicks.append(selector)


class FakeAuthPage:
    def __init__(self):
        self.url = "https://auth.thinkingmachines.ai/"
        self.fillables: list[tuple[str, str]] = []
        self.clicks: list[str] = []
        self.waited_urls: list[str] = []

    def locator(self, selector: str):
        return FakeFillable(selector, self.fillables)

    async def click(self, selector: str):
        self.clicks.append(selector)

    async def fill(self, selector: str, value: str):
        self.fillables.append((selector, value))

    async def wait_for_url(self, pattern: str, **_kwargs):
        self.waited_urls.append(pattern)
        self.url = "https://tinker-console.thinkingmachines.ai/"


class SignupAuthOnboardingTest(unittest.IsolatedAsyncioTestCase):
    async def test_wait_for_otp_uses_the_release_bound_caller_identity(self):
        oracle = Mock()
        oracle.get_pin.return_value = {"pin": "123456"}

        result = await wait_for_otp(oracle, Settings())

        self.assertEqual(result, "123456")
        oracle.get_pin.assert_called_once_with(
            max_age_seconds=Settings().otp_max_age,
            caller_identity=ORACLE_CALLER_IDENTITY,
            reason="tinker-passwordless-auth",
            delete_after=True,
        )

    async def test_enter_otp_fills_six_visible_boxes(self):
        page = FakeOtpPage({"input[inputmode=\"numeric\"]": 6})

        with patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()):
            await enter_otp(page, "123456")

        self.assertEqual(
            page.fills,
            [(0, "1"), (1, "2"), (2, "3"), (3, "4"), (4, "5"), (5, "6")],
        )
        self.assertEqual(page.keyboard.typed, [])

    async def test_enter_otp_fills_single_one_time_code_input(self):
        page = FakeOtpPage(
            {
                "input[inputmode=\"numeric\"]": 0,
                "input[data-input-otp=\"true\"]": 0,
                "input[autocomplete=\"one-time-code\"]": 1,
            }
        )

        await enter_otp(page, "654321")

        self.assertEqual(page.fills, [(0, "654321")])
        self.assertEqual(page.keyboard.typed, [])

    async def test_enter_otp_uses_keyboard_as_last_resort(self):
        page = FakeOtpPage({})

        await enter_otp(page, "111222")

        self.assertEqual(page.fills, [])
        self.assertEqual(page.keyboard.typed, ["111222"])

    async def test_authenticate_enters_email_and_otp_without_exposing_code(self):
        page = FakeAuthPage()
        states = [
            {
                "url": "https://auth.thinkingmachines.ai/",
                "text": "Sign in",
                "hasEmailInput": True,
                "hasFirstNameInput": False,
                "hasFullNameInput": False,
                "hasOtpInputs": 0,
            },
            {
                "url": "https://auth.thinkingmachines.ai/magic-code",
                "text": "Check your email",
                "hasEmailInput": False,
                "hasFirstNameInput": False,
                "hasFullNameInput": False,
                "hasOtpInputs": 6,
            },
        ]

        with (
            patch("tinker_delegate.signup._navigate", new=AsyncMock()),
            patch("tinker_delegate.signup._page_state", new=AsyncMock(side_effect=states)),
            patch("tinker_delegate.signup.wait_for_otp", new=AsyncMock(return_value="123456")) as wait_for_otp,
            patch("tinker_delegate.signup.enter_otp", new=AsyncMock()) as enter_code,
            patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()),
        ):
            await _authenticate(page, "oracle@example.com", object(), Settings())

        self.assertIn(("input[name=\"email\"]", ""), page.fillables)
        self.assertIn(("input[name=\"email\"]", "click"), page.fillables)
        self.assertIn(("input[name=\"email\"]", "oracle@example.com"), page.fillables)
        self.assertEqual(page.clicks, ['button[type="submit"]'])
        wait_for_otp.assert_awaited_once()
        enter_code.assert_awaited_once_with(page, "123456")
        self.assertEqual(page.waited_urls, ["**/tinker-console.thinkingmachines.ai/**"])

    async def test_authenticate_access_blocked_on_initial_page_preserves_stage(self):
        page = FakeAuthPage()
        state = {
            "url": "https://auth.thinkingmachines.ai/",
            "text": "Access blocked, please contact support.",
            "hasEmailInput": False,
            "hasFirstNameInput": False,
            "hasFullNameInput": False,
            "hasOtpInputs": 0,
        }

        with (
            patch("tinker_delegate.signup._navigate", new=AsyncMock()),
            patch("tinker_delegate.signup._page_state", new=AsyncMock(return_value=state)),
        ):
            with self.assertRaises(AuthAccessBlockedError) as raised:
                await _authenticate(page, "oracle@example.com", object(), Settings())

        self.assertEqual(raised.exception.furthest_stage, AutomationStage.AUTH_PAGE_LOADED)

    async def test_authenticate_access_blocked_after_email_submit_preserves_stage(self):
        page = FakeAuthPage()
        states = [
            {
                "url": "https://auth.thinkingmachines.ai/",
                "text": "Sign in",
                "hasEmailInput": True,
                "hasFirstNameInput": False,
                "hasFullNameInput": False,
                "hasOtpInputs": 0,
            },
            {
                "url": "https://auth.thinkingmachines.ai/",
                "text": "Access blocked, please contact support.",
                "hasEmailInput": False,
                "hasFirstNameInput": False,
                "hasFullNameInput": False,
                "hasOtpInputs": 0,
            },
        ]

        with (
            patch("tinker_delegate.signup._navigate", new=AsyncMock()),
            patch("tinker_delegate.signup._page_state", new=AsyncMock(side_effect=states)),
            patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()),
        ):
            with self.assertRaises(AuthAccessBlockedError) as raised:
                await _authenticate(page, "oracle@example.com", object(), Settings())

        self.assertEqual(raised.exception.furthest_stage, AutomationStage.AUTH_EMAIL_SUBMITTED)

    async def test_onboarding_fills_name_accepts_tos_and_continues(self):
        page = FakeOnboardingPage(has_tos=True)
        state = {
            "url": "https://tinker-console.thinkingmachines.ai/onboarding",
            "text": "Welcome",
            "hasEmailInput": False,
            "hasFirstNameInput": False,
            "hasFullNameInput": True,
            "hasOtpInputs": 0,
        }

        with (
            patch("tinker_delegate.signup._page_state", new=AsyncMock(return_value=state)),
            patch("tinker_delegate.signup.asyncio.sleep", new=AsyncMock()),
        ):
            await _handle_onboarding(page, Settings(first_name="Tinker", last_name="Delegate"))

        self.assertEqual(page.fills, [('input[name="fullName"]', "Tinker Delegate")])
        self.assertEqual(page.clicks, ["text=I have read and agree", 'button:has-text("Continue")'])

    async def test_onboarding_noops_when_form_not_present(self):
        page = FakeOnboardingPage()
        state = {
            "url": "https://tinker-console.thinkingmachines.ai/",
            "text": "Dashboard",
            "hasEmailInput": False,
            "hasFirstNameInput": False,
            "hasFullNameInput": False,
            "hasOtpInputs": 0,
        }

        with patch("tinker_delegate.signup._page_state", new=AsyncMock(return_value=state)):
            await _handle_onboarding(page, Settings())

        self.assertEqual(page.fills, [])
        self.assertEqual(page.clicks, [])


if __name__ == "__main__":
    unittest.main()
