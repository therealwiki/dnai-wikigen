import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.tinker_proxy import issue_proxy_token


BOUNDED_SMOKE_RESULT = {
    "surface": "tinker_sdk_smoke",
    "success": True,
    "outcome": "success",
    "furthest_stage": "cleanup_completed",
    "deal_hash": "a" * 64,
    "training_run_id_hash": "b" * 64,
    "checkpoint_path_hash": "c" * 64,
    "sample_observed": True,
    "sample_output_returned": False,
    "cleanup": {"success": True, "training_run_id_hash": "b" * 64},
    "raw_secret_egress": False,
}


class TinkerSmokeApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_smoke_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_tinker_smoke_endpoint=False)
        client = TestClient(api.app)

        with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
            response = client.post("/tinker/smoke", json={"max_usd": 0.05})

        self.assertEqual(response.status_code, 403)
        self.assertIn("Tinker smoke endpoint is disabled", response.json()["detail"])
        smoke.assert_not_called()

    def test_smoke_endpoint_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            allow_tinker_smoke_endpoint=True,
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
            missing = client.post("/tinker/smoke", json={"max_usd": 0.05})
            wrong = client.post(
                "/tinker/smoke",
                json={"max_usd": 0.05},
                headers={"Authorization": "Bearer wrong"},
            )
            ok = client.post(
                "/tinker/smoke",
                json={"max_usd": 0.05},
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(ok.status_code, 200)
        self.assertEqual(ok.json(), BOUNDED_SMOKE_RESULT)
        smoke.assert_called_once()

    def test_smoke_endpoint_accepts_proxy_spend_within_scope_cap(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            claims, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["tinker:smoke"],
                ttl_seconds=60,
                scope_limits={"tinker:smoke": {"max_amount_usd": 0.05}},
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={"max_usd": 0.05},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(
            {key: value for key, value in body.items() if key != "proxy_auth_context"},
            BOUNDED_SMOKE_RESULT,
        )
        self.assertEqual(body["proxy_auth_context"]["required_scope"], "tinker:smoke")
        self.assertEqual(body["proxy_auth_context"]["jwt_id_hash"], claims.to_public_dict()["jwt_id_hash"])
        self.assertFalse(body["proxy_auth_context"]["raw_secret_egress"])
        smoke.assert_called_once()

    def test_smoke_endpoint_rejects_proxy_spend_over_scope_cap_without_running(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["tinker:smoke"],
                ttl_seconds=60,
                scope_limits={"tinker:smoke": {"max_amount_usd": 0.04}},
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={"max_usd": 0.05},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        self.assertIn("exceeds policy limit", response.json()["detail"])
        smoke.assert_not_called()

    def test_smoke_endpoint_rejects_proxy_token_missing_spend_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["tinker:smoke"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={"max_usd": 0.05},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        self.assertIn("scope limit is required", response.json()["detail"])
        smoke.assert_not_called()

    def test_smoke_endpoint_rejects_proxy_token_with_malformed_spend_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["tinker:smoke"],
                ttl_seconds=60,
                scope_limits={"tinker:smoke": {"max_amount_usd": float("nan")}},
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={"max_usd": 0.05},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        self.assertIn("amount limit is invalid", response.json()["detail"])
        smoke.assert_not_called()

    def test_smoke_endpoint_uses_settings_default_for_proxy_cap_enforcement(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                real_sdk_max_usd=0.05,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["tinker:smoke"],
                ttl_seconds=60,
                scope_limits={"tinker:smoke": {"max_amount_usd": 0.04}},
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        self.assertIn("exceeds policy limit", response.json()["detail"])
        smoke.assert_not_called()

    def test_smoke_endpoint_rejects_proxy_jwt_without_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_tinker_smoke_endpoint=True,
                proxy_jwt_key="33" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="33" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["proxy:status"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
                response = client.post(
                    "/tinker/smoke",
                    json={"max_usd": 0.05},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        smoke.assert_not_called()

    def test_smoke_endpoint_rejects_unknown_model_alias_fields(self):
        api.settings = Settings(allow_tinker_smoke_endpoint=True)
        client = TestClient(api.app)

        with patch("tinker_delegate.tinker_smoke.run_tinker_sdk_smoke", return_value=BOUNDED_SMOKE_RESULT) as smoke:
            response = client.post(
                "/tinker/smoke",
                json={"max_usd": 0.05, "base_model": "Qwen/Qwen3-8B"},
            )

        self.assertEqual(response.status_code, 422)
        rendered = str(response.json())
        self.assertIn("extra_forbidden", rendered)
        self.assertNotIn("operator-secret", rendered)
        smoke.assert_not_called()


if __name__ == "__main__":
    unittest.main()
