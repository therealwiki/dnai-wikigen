import os
import unittest
from unittest.mock import AsyncMock, Mock, patch

from tinker_delegate.config import Settings
from tinker_delegate.main import _bootstrap_error_kind_from_runtime, _ensure_api_key
from tinker_delegate.runtime_state import get_runtime_state, reset_runtime_state


BOUNDED_BOOTSTRAP_RECEIPT = {
    "surface": "api_key_provisioning",
    "outcome": "selector_missing",
    "furthest_stage": "api_keys_page_loaded",
    "bounded_message": "api_key_not_captured",
    "evidence_hash": "a" * 64,
    "account_hash": "b" * 64,
    "amount_band": "",
    "balance_band": "",
    "tdx_quote_hash": "",
    "card_payload_destroyed": False,
    "raw_secret_egress": False,
    "issued_at": 1,
}

BOUNDED_AUTH_BOOTSTRAP_RECEIPT = {
    **BOUNDED_BOOTSTRAP_RECEIPT,
    "surface": "tinker_auth",
    "outcome": "transient_browser_failure",
    "furthest_stage": "not_started",
    "bounded_message": "transient_browser_failure",
}

BOUNDED_UNKNOWN_AUTH_BOOTSTRAP_RECEIPT = {
    **BOUNDED_AUTH_BOOTSTRAP_RECEIPT,
    "outcome": "unknown_failure",
    "bounded_message": "unknown_failure",
}


class BootstrapRuntimeStateTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        reset_runtime_state()

    def tearDown(self):
        reset_runtime_state()

    def _settings(self) -> Settings:
        return Settings(
            api_key_store_path="/tmp/nonexistent-tinker-api-key.enc",
            bootstrap_signup=True,
            bootstrap_fail_open=True,
        )

    async def test_successful_bootstrap_records_bounded_attempt_record(self):
        store = Mock()
        store.exists.return_value = False
        signup_result = {
            "success": True,
            "stored": True,
            "api_key_created": True,
            "api_key_hash": "c" * 64,
            "attempt_record": {
                **BOUNDED_BOOTSTRAP_RECEIPT,
                "outcome": "success",
                "furthest_stage": "api_key_stored",
                "bounded_message": "api_key_captured_and_stored",
            },
        }

        with (
            patch.dict(os.environ, {"TINKER_API_KEY": ""}, clear=False),
            patch("tinker_delegate.main.build_api_key_store", return_value=store),
            patch("tinker_delegate.main._wait_for_oracle"),
            patch("tinker_delegate.signup.signup", new=AsyncMock(return_value=signup_result)),
        ):
            await _ensure_api_key(self._settings())

        runtime = get_runtime_state()
        self.assertTrue(runtime["api_key_available"])
        self.assertTrue(runtime["bootstrap_attempted"])
        self.assertTrue(runtime["bootstrap_success"])
        self.assertEqual(runtime["last_bootstrap_attempt_record"], signup_result["attempt_record"])
        self.assertNotIn("tml-", repr(runtime))
        self.assertNotIn("123456", repr(runtime))

    async def test_failed_bootstrap_preserves_bounded_attempt_record(self):
        store = Mock()
        store.exists.return_value = False
        signup_result = {
            "success": False,
            "stored": False,
            "api_key_created": False,
            "api_key_hash": "",
            "attempt_record": BOUNDED_BOOTSTRAP_RECEIPT,
        }

        with (
            patch.dict(os.environ, {"TINKER_API_KEY": ""}, clear=False),
            patch("tinker_delegate.main.build_api_key_store", return_value=store),
            patch("tinker_delegate.main._wait_for_oracle"),
            patch("tinker_delegate.signup.signup", new=AsyncMock(return_value=signup_result)),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not store an API key"):
                await _ensure_api_key(self._settings())

        runtime = get_runtime_state()
        self.assertFalse(runtime["api_key_available"])
        self.assertTrue(runtime["bootstrap_attempted"])
        self.assertFalse(runtime["bootstrap_success"])
        self.assertEqual(runtime["bootstrap_error_kind"], "selector_missing")
        self.assertEqual(runtime["last_bootstrap_attempt_record"], BOUNDED_BOOTSTRAP_RECEIPT)
        self.assertNotIn("oracle@example.com", repr(runtime))
        self.assertNotIn("tml-", repr(runtime))

    async def test_failed_bootstrap_preserves_early_auth_attempt_record(self):
        store = Mock()
        store.exists.return_value = False
        signup_result = {
            "success": False,
            "stored": False,
            "api_key_created": False,
            "api_key_hash": "",
            "error_kind": "transient_browser_failure",
            "attempt_record": BOUNDED_AUTH_BOOTSTRAP_RECEIPT,
        }

        with (
            patch.dict(os.environ, {"TINKER_API_KEY": ""}, clear=False),
            patch("tinker_delegate.main.build_api_key_store", return_value=store),
            patch("tinker_delegate.main._wait_for_oracle"),
            patch("tinker_delegate.signup.signup", new=AsyncMock(return_value=signup_result)),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not store an API key"):
                await _ensure_api_key(self._settings())

        runtime = get_runtime_state()
        self.assertFalse(runtime["api_key_available"])
        self.assertTrue(runtime["bootstrap_attempted"])
        self.assertFalse(runtime["bootstrap_success"])
        self.assertEqual(runtime["bootstrap_error_kind"], "transient_browser_failure")
        self.assertEqual(runtime["last_bootstrap_attempt_record"], BOUNDED_AUTH_BOOTSTRAP_RECEIPT)
        self.assertNotIn("oracle@example.com", repr(runtime))
        self.assertNotIn("123456", repr(runtime))
        self.assertNotIn("tml-", repr(runtime))

    async def test_serve_catch_preserves_bounded_attempt_outcome(self):
        store = Mock()
        store.exists.return_value = False
        signup_result = {
            "success": False,
            "stored": False,
            "api_key_created": False,
            "api_key_hash": "",
            "attempt_record": BOUNDED_UNKNOWN_AUTH_BOOTSTRAP_RECEIPT,
        }

        with (
            patch.dict(os.environ, {"TINKER_API_KEY": ""}, clear=False),
            patch("tinker_delegate.main.build_api_key_store", return_value=store),
            patch("tinker_delegate.main._wait_for_oracle"),
            patch("tinker_delegate.signup.signup", new=AsyncMock(return_value=signup_result)),
        ):
            with self.assertRaisesRegex(RuntimeError, "did not store an API key") as caught:
                await _ensure_api_key(self._settings())

        self.assertEqual(_bootstrap_error_kind_from_runtime(caught.exception), "unknown_failure")
        runtime = get_runtime_state()
        self.assertEqual(runtime["bootstrap_error_kind"], "unknown_failure")
        self.assertEqual(
            runtime["last_bootstrap_attempt_record"],
            BOUNDED_UNKNOWN_AUTH_BOOTSTRAP_RECEIPT,
        )
        self.assertNotIn("oracle@example.com", repr(runtime))
        self.assertNotIn("123456", repr(runtime))
        self.assertNotIn("tml-", repr(runtime))


if __name__ == "__main__":
    unittest.main()
