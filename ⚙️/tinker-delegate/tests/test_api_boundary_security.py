import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.http_security import (
    HttpSecurityError,
    configure_cors,
    parse_cors_origins,
    validate_https_allowlisted_url,
)
from tinker_delegate.runtime_auth import resolve_runtime_auth_token, runtime_auth_enabled


AUTH = {"Authorization": "Bearer operator-secret"}


class CorsPolicyTest(unittest.TestCase):
    def test_exact_allowed_origin_gets_cors_without_credentials(self):
        app = FastAPI()
        configure_cors(
            app,
            Settings(cors_allowed_origins="https://wikigen.pages.dev"),
        )

        @app.get("/ok")
        def ok():
            return {"ok": True}

        response = TestClient(app).options(
            "/ok",
            headers={
                "Origin": "https://wikigen.pages.dev",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers.get("access-control-allow-origin"),
            "https://wikigen.pages.dev",
        )
        self.assertNotIn("access-control-allow-credentials", response.headers)

    def test_frontend_mutation_and_no_cache_preflights_are_exactly_allowed(self):
        app = FastAPI()
        configure_cors(
            app,
            Settings(cors_allowed_origins="http://127.0.0.1:5175"),
        )

        @app.api_route("/ok", methods=["GET", "POST", "DELETE"])
        def ok():
            return {"ok": True}

        client = TestClient(app)
        for method, requested_headers in (
            ("POST", "authorization,content-type,idempotency-key"),
            ("DELETE", "authorization"),
            ("GET", "authorization,cache-control,pragma"),
        ):
            with self.subTest(method=method, requested_headers=requested_headers):
                response = client.options(
                    "/ok",
                    headers={
                        "Origin": "http://127.0.0.1:5175",
                        "Access-Control-Request-Method": method,
                        "Access-Control-Request-Headers": requested_headers,
                    },
                )
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(
                    response.headers.get("access-control-allow-origin"),
                    "http://127.0.0.1:5175",
                )
                self.assertNotIn(
                    "access-control-allow-credentials", response.headers
                )

    def test_unreviewed_frontend_header_remains_disallowed(self):
        app = FastAPI()
        configure_cors(
            app,
            Settings(cors_allowed_origins="http://127.0.0.1:5175"),
        )

        @app.get("/ok")
        def ok():
            return {"ok": True}

        response = TestClient(app).options(
            "/ok",
            headers={
                "Origin": "http://127.0.0.1:5175",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Unreviewed-Header",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_unlisted_origin_gets_no_allow_origin_header(self):
        app = FastAPI()
        configure_cors(app, Settings(cors_allowed_origins="https://wikigen.pages.dev"))

        @app.get("/ok")
        def ok():
            return {"ok": True}

        response = TestClient(app).get(
            "/ok",
            headers={"Origin": "https://evil.example"},
        )
        self.assertNotIn("access-control-allow-origin", response.headers)

    def test_wildcard_and_non_loopback_http_origins_are_rejected(self):
        with self.assertRaises(HttpSecurityError):
            parse_cors_origins("*")
        with self.assertRaises(HttpSecurityError):
            parse_cors_origins("https://*.example.com")
        with self.assertRaises(HttpSecurityError):
            parse_cors_origins("http://wikigen.example")
        self.assertEqual(
            parse_cors_origins("http://localhost:3000,https://wikigen.pages.dev/"),
            ("http://localhost:3000", "https://wikigen.pages.dev"),
        )


class FundingPreflightSecurityTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def _settings(self, tmpdir: str) -> Settings:
        return Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
            funding_mode="operator_capped_validation",
            funding_receipt_store_path=str(Path(tmpdir) / "receipts.enc"),
            funding_receipt_store_key="44" * 32,
            funding_preflight_allowed_hosts="delegate.example",
        )

    def test_preflight_requires_operator_auth(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(tmpdir)
            response = TestClient(api.app).get(
                "/billing/funding-preflight",
                params={"api_url": "https://delegate.example"},
            )
        self.assertEqual(response.status_code, 401)

    def test_preflight_accepts_only_allowlisted_https_origin(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = self._settings(tmpdir)
            client = TestClient(api.app)
            accepted = client.get(
                "/billing/funding-preflight",
                params={
                    "amount_dollars": 10.0,
                    "api_url": "https://delegate.example/",
                    "allow_local_attestation": True,
                },
                headers=AUTH,
            )
            insecure = client.get(
                "/billing/funding-preflight",
                params={"api_url": "http://delegate.example"},
                headers=AUTH,
            )
            unlisted = client.get(
                "/billing/funding-preflight",
                params={"api_url": "https://metadata.example"},
                headers=AUTH,
            )
            credentialed = client.get(
                "/billing/funding-preflight",
                params={"api_url": "https://user@delegate.example"},
                headers=AUTH,
            )

        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertTrue(accepted.json()["ready"])
        self.assertEqual(insecure.status_code, 400)
        self.assertEqual(unlisted.status_code, 400)
        self.assertEqual(credentialed.status_code, 400)

    def test_ip_literals_and_wildcard_allowlists_are_rejected(self):
        with self.assertRaises(HttpSecurityError):
            validate_https_allowlisted_url("https://127.0.0.1", "127.0.0.1")
        with self.assertRaises(HttpSecurityError):
            validate_https_allowlisted_url("https://delegate.example", "*.example")


class InternalDealAuthTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_internal_deal_mutations_fail_closed_without_runtime_auth(self):
        api.settings = Settings(runtime_auth_required=False, runtime_auth_token="")
        client = TestClient(api.app)
        requests = (
            ("/deal/chain-event", {"event_name": "DealCreated", "deal_id": "7"}),
            (
                "/deal/notify-funded",
                {
                    "deal_id": "7",
                    "buyer": "0x" + "22" * 20,
                    "seller": "0x" + "11" * 20,
                    "budget_cap": 100,
                    "reserve_price": 10,
                    "artifact_hash": "0x" + "ab" * 32,
                    "evaluator_policy_commitment": "0x" + "cd" * 32,
                },
            ),
            ("/deal/7/evaluate", None),
            ("/deal/7/resolve", None),
        )

        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            for path, body in requests:
                response = client.post(path, json=body)
                self.assertEqual(response.status_code, 503, path)
        get_control_plane.assert_not_called()

    def test_chain_event_requires_correct_runtime_bearer(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )

        class ControlPlane:
            calls = []

            def on_chain_event(self, *args, **kwargs):
                self.calls.append((args, kwargs))

        cp = ControlPlane()
        client = TestClient(api.app)
        payload = {"event_name": "DealCreated", "deal_id": "7"}
        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            missing = client.post("/deal/chain-event", json=payload)
            wrong = client.post(
                "/deal/chain-event",
                json=payload,
                headers={"Authorization": "Bearer wrong"},
            )
            accepted = client.post("/deal/chain-event", json=payload, headers=AUTH)

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(accepted.status_code, 200)
        self.assertEqual(len(cp.calls), 1)

    def test_dstack_mode_enables_and_derives_runtime_auth(self):
        settings = Settings(runtime_auth_required=False, runtime_auth_key_path="runtime/path")
        with (
            patch("tinker_delegate.runtime_auth.dstack_utils.is_dstack_enabled", return_value=True),
            patch(
                "tinker_delegate.runtime_auth.dstack_utils.derive_storage_key",
                return_value=b"r" * 32,
            ) as derive,
        ):
            self.assertTrue(runtime_auth_enabled(settings))
            first = resolve_runtime_auth_token(settings)
            second = resolve_runtime_auth_token(settings)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)
        self.assertEqual(derive.call_count, 2)
        derive.assert_called_with("runtime/path")


class PublicHealthTest(unittest.TestCase):
    def test_public_health_exposes_liveness_only(self):
        body = TestClient(api.app).get("/health").json()
        self.assertEqual(body, {"status": "ok", "service": "tinker-delegate"})
        self.assertNotIn("cdp", repr(body).lower())
        self.assertNotIn("oracle", repr(body).lower())


if __name__ == "__main__":
    unittest.main()
