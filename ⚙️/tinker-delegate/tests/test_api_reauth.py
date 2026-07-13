import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.runtime_state import get_runtime_state, reset_runtime_state


BOUNDED_REAUTH_RESULT = {
    "success": True,
    "authenticated": True,
    "error_kind": "",
    "attempt_record": {
        "surface": "tinker_auth",
        "outcome": "success",
        "furthest_stage": "authenticated",
        "bounded_message": "reauthenticated",
        "evidence_hash": "a" * 64,
        "account_hash": "b" * 64,
        "amount_band": "",
        "balance_band": "",
        "tdx_quote_hash": "",
        "card_payload_destroyed": False,
        "raw_secret_egress": False,
        "issued_at": 1,
    },
}


class ReauthApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        reset_runtime_state()

    def tearDown(self):
        api.settings = self.original_settings
        reset_runtime_state()

    def test_reauth_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_auth_automation_endpoint=False)
        client = TestClient(api.app)

        with patch(
            "tinker_delegate.signup.reauth",
            new=AsyncMock(return_value=BOUNDED_REAUTH_RESULT),
        ) as reauth:
            response = client.post("/auth/reauth")

        self.assertEqual(response.status_code, 403)
        self.assertIn("auth automation endpoint is disabled", response.json()["detail"])
        reauth.assert_not_called()

    def test_reauth_endpoint_returns_bounded_result_and_updates_runtime_state(self):
        api.settings = Settings(allow_auth_automation_endpoint=True)
        client = TestClient(api.app)

        with patch("tinker_delegate.signup.reauth", new=AsyncMock(return_value=BOUNDED_REAUTH_RESULT)) as reauth:
            response = client.post("/auth/reauth")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body, BOUNDED_REAUTH_RESULT)
        self.assertNotIn("oracle@example.com", repr(body))
        self.assertNotIn("123456", repr(body))
        reauth.assert_awaited_once()

        runtime = get_runtime_state()
        self.assertTrue(runtime["reauth_attempted"])
        self.assertTrue(runtime["reauth_success"])
        self.assertEqual(runtime["reauth_error_kind"], "")
        self.assertEqual(runtime["last_reauth_attempt_record"], BOUNDED_REAUTH_RESULT["attempt_record"])

    def test_reauth_endpoint_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            allow_auth_automation_endpoint=True,
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.signup.reauth", new=AsyncMock(return_value=BOUNDED_REAUTH_RESULT)) as reauth:
            missing = client.post("/auth/reauth")
            wrong = client.post("/auth/reauth", headers={"Authorization": "Bearer wrong"})
            ok = client.post("/auth/reauth", headers={"Authorization": "Bearer operator-secret"})

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(ok.status_code, 200)
        reauth.assert_awaited_once()

    def test_reauth_endpoint_bounds_uncaught_browser_exceptions(self):
        api.settings = Settings(allow_auth_automation_endpoint=True)
        client = TestClient(api.app)
        raw_error = (
            "Page.goto: net::ERR_ABORTED at "
            "https://tinker-console.thinkingmachines.ai/billing/balance"
        )

        with patch("tinker_delegate.signup.reauth", new=AsyncMock(side_effect=RuntimeError(raw_error))):
            response = client.post("/auth/reauth")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = repr(body)
        self.assertFalse(body["success"])
        self.assertFalse(body["authenticated"])
        self.assertEqual(body["error_kind"], "transient_browser_failure")
        self.assertEqual(body["attempt_record"]["surface"], "tinker_auth")
        self.assertEqual(body["attempt_record"]["outcome"], "transient_browser_failure")
        self.assertEqual(body["attempt_record"]["furthest_stage"], "not_started")
        self.assertFalse(body["attempt_record"]["raw_secret_egress"])
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("Page.goto", rendered)
        runtime = get_runtime_state()
        self.assertTrue(runtime["reauth_attempted"])
        self.assertFalse(runtime["reauth_success"])
        self.assertEqual(runtime["reauth_error_kind"], "transient_browser_failure")


if __name__ == "__main__":
    unittest.main()
