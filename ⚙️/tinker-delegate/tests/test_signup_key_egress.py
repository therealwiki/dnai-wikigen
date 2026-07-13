import hashlib
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, Mock, patch

from tinker_delegate.config import Settings
from tinker_delegate.automation_receipts import AutomationStage
from tinker_delegate.signup import AuthAccessBlockedError, reauth, signin, signup


class AsyncPlaywrightStub:
    async def __aenter__(self):
        return object()

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeOracle:
    def __init__(self, settings):
        self.settings = settings

    def get_email(self):
        return "oracle@example.com"


class FakePage:
    url = "https://tinker-console.thinkingmachines.ai/keys"


class FakeContext:
    def __init__(self, pages=None):
        self.pages = pages if pages is not None else [FakePage()]

    async def new_page(self):
        page = FakePage()
        self.pages.append(page)
        return page


class FakeStore:
    def __init__(self, fail_save: bool = False):
        self.fail_save = fail_save
        self.saved_key = None

    def save(self, api_key: str) -> None:
        if self.fail_save:
            raise RuntimeError("seal failed")
        self.saved_key = api_key


class SignupKeyEgressTest(unittest.IsolatedAsyncioTestCase):
    async def test_signup_returns_bounded_metadata_not_raw_api_key(self):
        api_key = "tml-secret-key-material"
        store = FakeStore()

        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()),
            patch("tinker_delegate.signup._handle_onboarding", new=AsyncMock()),
            patch("tinker_delegate.signup._create_api_key", new=AsyncMock(return_value=api_key)),
            patch("tinker_delegate.signup.build_api_key_store", return_value=store),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await signup(Settings())

        self.assertTrue(result["success"])
        self.assertTrue(result["stored"])
        self.assertTrue(result["api_key_created"])
        self.assertNotIn("email", result)
        self.assertEqual(result["email_hash"], hashlib.sha256(b"oracle@example.com").hexdigest())
        self.assertNotIn("api_key", result)
        self.assertEqual(result["api_key_hash"], hashlib.sha256(api_key.encode()).hexdigest())
        self.assertEqual(store.saved_key, api_key)
        self.assertEqual(result["attempt_record"]["surface"], "api_key_provisioning")
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "api_key_stored")
        self.assertNotIn(api_key, repr(result["attempt_record"]))
        self.assertNotIn("oracle@example.com", stdout.getvalue())
        self.assertNotIn(api_key, stdout.getvalue())

    async def test_signup_fails_closed_when_api_key_store_fails(self):
        api_key = "tml-secret-key-material"

        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()),
            patch("tinker_delegate.signup._handle_onboarding", new=AsyncMock()),
            patch("tinker_delegate.signup._create_api_key", new=AsyncMock(return_value=api_key)),
            patch("tinker_delegate.signup.build_api_key_store", return_value=FakeStore(fail_save=True)),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await signup(Settings())

        self.assertFalse(result["success"])
        self.assertFalse(result["stored"])
        self.assertTrue(result["api_key_created"])
        self.assertNotIn("email", result)
        self.assertNotIn("api_key", result)
        self.assertIn("store_error", result)
        self.assertEqual(result["attempt_record"]["outcome"], "store_failed")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "api_key_captured")
        self.assertNotIn("oracle@example.com", stdout.getvalue())

    async def test_signup_reports_selector_missing_when_key_not_captured(self):
        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()),
            patch("tinker_delegate.signup._handle_onboarding", new=AsyncMock()),
            patch("tinker_delegate.signup._create_api_key", new=AsyncMock(return_value=None)),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await signup(Settings())

        self.assertFalse(result["success"])
        self.assertFalse(result["stored"])
        self.assertFalse(result["api_key_created"])
        self.assertNotIn("email", result)
        self.assertEqual(result["attempt_record"]["outcome"], "selector_missing")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "api_keys_page_loaded")
        self.assertNotIn("oracle@example.com", stdout.getvalue())

    async def test_signup_browser_connect_failure_returns_bounded_receipt(self):
        error = RuntimeError(
            "cdp did not become ready for oracle@example.com with OTP 123456 "
            "at https://tinker-console.thinkingmachines.ai using tml-secret-key-material"
        )

        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(side_effect=error)),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await signup(Settings())

        self.assertFalse(result["success"])
        self.assertFalse(result["stored"])
        self.assertFalse(result["api_key_created"])
        self.assertEqual(result["error_kind"], "transient_browser_failure")
        self.assertEqual(result["attempt_record"]["surface"], "tinker_auth")
        self.assertEqual(result["attempt_record"]["outcome"], "transient_browser_failure")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "not_started")
        rendered = repr(result) + stdout.getvalue()
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("tml-secret-key-material", rendered)

    async def test_signup_onboarding_failure_returns_stage_bounded_receipt(self):
        error = RuntimeError(
            "Continue button not found for oracle@example.com at "
            "https://tinker-console.thinkingmachines.ai/onboarding with OTP 123456"
        )

        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()),
            patch("tinker_delegate.signup._handle_onboarding", new=AsyncMock(side_effect=error)),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await signup(Settings())

        self.assertFalse(result["success"])
        self.assertFalse(result["stored"])
        self.assertEqual(result["error_kind"], "selector_missing")
        self.assertEqual(result["attempt_record"]["surface"], "tinker_auth")
        self.assertEqual(result["attempt_record"]["outcome"], "selector_missing")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "authenticated")
        rendered = repr(result) + stdout.getvalue()
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)

    async def test_signin_returns_bounded_metadata_not_email_or_url(self):
        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()),
        ):
            context = FakeContext([FakePage()])
            with patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=context)):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    result = await signin(Settings())

        self.assertTrue(result["success"])
        self.assertEqual(result["email_hash"], hashlib.sha256(b"oracle@example.com").hexdigest())
        self.assertNotIn("email", result)
        self.assertNotIn("url", result)
        rendered = repr(result) + stdout.getvalue()
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)

    async def test_reauth_returns_bounded_metadata_not_email_otp_or_url(self):
        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock()) as authenticate,
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await reauth(Settings())

        self.assertTrue(result["success"])
        self.assertTrue(result["authenticated"])
        self.assertEqual(result["error_kind"], "")
        self.assertEqual(result["attempt_record"]["surface"], "tinker_auth")
        self.assertEqual(result["attempt_record"]["outcome"], "success")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "authenticated")
        authenticate.assert_awaited_once()
        rendered = repr(result)
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("oracle@example.com", stdout.getvalue())

    async def test_reauth_auth_blocked_returns_bounded_receipt(self):
        error = AuthAccessBlockedError(
            "Access blocked for oracle@example.com with OTP 123456 at https://tinker-console.thinkingmachines.ai",
            furthest_stage=AutomationStage.AUTH_EMAIL_SUBMITTED,
        )

        with (
            patch("tinker_delegate.signup.OracleClient", FakeOracle),
            patch("tinker_delegate.signup.async_playwright", return_value=AsyncPlaywrightStub()),
            patch("tinker_delegate.signup.connect_chromium", new=AsyncMock(return_value=object())),
            patch("tinker_delegate.signup.get_browser_context", new=AsyncMock(return_value=FakeContext())),
            patch("tinker_delegate.signup._authenticate", new=AsyncMock(side_effect=error)),
        ):
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                result = await reauth(Settings())

        self.assertFalse(result["success"])
        self.assertFalse(result["authenticated"])
        self.assertEqual(result["error_kind"], "auth_access_blocked")
        self.assertEqual(result["attempt_record"]["surface"], "tinker_auth")
        self.assertEqual(result["attempt_record"]["outcome"], "auth_access_blocked")
        self.assertEqual(result["attempt_record"]["furthest_stage"], "auth_email_submitted")
        rendered = repr(result)
        self.assertNotIn("oracle@example.com", rendered)
        self.assertNotIn("123456", rendered)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("oracle@example.com", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
