import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.automation_receipts import (
    AutomationOutcome,
    AutomationStage,
    AutomationSurface,
    make_receipt,
)
from tinker_delegate.billing_uploader import encrypt_billing_card_payload
from tinker_delegate.card_channel import BillingResponse, attestation_report_data, get_tee_keypair
from tinker_delegate.config import Settings
from tinker_delegate.funding_receipt_store import FundingReceiptStore
from tinker_delegate.tinker_proxy import issue_proxy_token


CARD_PAYLOAD = {
    "card_number": "4242424242424242",
    "exp_month": "12",
    "exp_year": "2030",
    "cvc": "123",
    "cardholder_name": "Test User",
}


def _success_receipt(surface: AutomationSurface) -> dict:
    return make_receipt(
        surface=surface,
        outcome=AutomationOutcome.SUCCESS,
        furthest_stage=AutomationStage.BILLING_PAGE_LOADED,
    ).to_public_dict()


class BillingApiPolicyTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_plaintext_card_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_plaintext_card_endpoint=False)
        client = TestClient(api.app)

        response = client.post("/billing/card", json=CARD_PAYLOAD)

        self.assertEqual(response.status_code, 403)
        self.assertIn("Plaintext card endpoint is disabled", response.json()["detail"])

    def test_plaintext_card_endpoint_requires_non_dstack_local_flag(self):
        api.settings = Settings(allow_plaintext_card_endpoint=True)
        client = TestClient(api.app)

        with (
            patch("tinker_delegate.api.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.api.handle_card_update", new=AsyncMock()) as handle_card_update,
        ):
            response = client.post("/billing/card", json=CARD_PAYLOAD)

        self.assertEqual(response.status_code, 403)
        handle_card_update.assert_not_called()

    def test_plaintext_card_endpoint_can_be_enabled_for_local_dev(self):
        api.settings = Settings(
            allow_plaintext_card_endpoint=True,
            funding_mode="operator_capped_validation",
        )
        client = TestClient(api.app)

        with (
            patch("tinker_delegate.api.is_dstack_enabled", return_value=False),
            patch(
                "tinker_delegate.api.handle_card_update",
                new=AsyncMock(return_value={"success": False, "error": "unknown_failure"}),
            ) as handle_card_update,
        ):
            response = client.post("/billing/card", json=CARD_PAYLOAD)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"], "unknown_failure")
        handle_card_update.assert_awaited_once()

    def test_payment_method_status_exception_is_bounded(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        raw_error = (
            "Page.goto: net::ERR_ABORTED at "
            "https://tinker-console.thinkingmachines.ai/billing/balance"
        )

        with patch(
            "tinker_delegate.card_channel.get_payment_method_status",
            new=AsyncMock(side_effect=RuntimeError(raw_error)),
        ):
            response = client.get(
                "/billing/payment-method-status",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = str(body)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "transient_browser_failure")
        self.assertEqual(body["attempt_record"]["surface"], "payment_method_status")
        self.assertEqual(body["attempt_record"]["outcome"], "transient_browser_failure")
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("Page.goto", rendered)

    def test_account_access_status_returns_bounded_receipt(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        receipt = {
            "kind": "account_access_status",
            "state": "access_blocked_billing",
            "actionable_by_automation": False,
            "operator_action": "contact_provider_for_account_activation",
            "bounded_message": "account_access:access_blocked_billing",
            "page_text_hash": "0x" + "ab" * 32,
            "raw_secret_egress": False,
            "success": True,
        }
        with patch(
            "tinker_delegate.card_channel.get_account_access_status",
            new=AsyncMock(return_value=receipt),
        ):
            response = client.get(
                "/billing/account-access-status",
                headers={"Authorization": "Bearer operator-secret"},
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["state"], "access_blocked_billing")
        self.assertEqual(body["operator_action"], "contact_provider_for_account_activation")
        self.assertFalse(body["raw_secret_egress"])

    def test_account_access_status_requires_auth(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        response = client.get("/billing/account-access-status")
        self.assertEqual(response.status_code, 401)

    def test_account_access_status_exception_is_bounded(self):
        api.settings = Settings()
        client = TestClient(api.app)
        raw_error = (
            "Page.goto: net::ERR_ABORTED at "
            "https://tinker-console.thinkingmachines.ai/billing/balance"
        )
        with patch(
            "tinker_delegate.card_channel.get_account_access_status",
            new=AsyncMock(side_effect=RuntimeError(raw_error)),
        ):
            response = client.get("/billing/account-access-status")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = str(body)
        self.assertFalse(body["success"])
        self.assertEqual(body["state"], "unknown")
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("Page.goto", rendered)

    def test_balance_exception_is_bounded(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        raw_error = (
            "Page.goto: net::ERR_ABORTED at "
            "https://tinker-console.thinkingmachines.ai/billing/balance"
        )

        with patch(
            "tinker_delegate.card_channel.get_balance",
            new=AsyncMock(side_effect=RuntimeError(raw_error)),
        ):
            response = client.get(
                "/billing/balance",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        rendered = str(body)
        self.assertFalse(body["success"])
        self.assertEqual(body["error"], "transient_browser_failure")
        self.assertEqual(
            set(body),
            {"success", "error", "raw_secret_egress"},
        )
        self.assertNotIn("balance", body)
        self.assertNotIn("tinker-console.thinkingmachines.ai", rendered)
        self.assertNotIn("Page.goto", rendered)

    def test_balance_requires_configured_runtime_or_proxy_auth(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.api.handle_get_balance", new=AsyncMock()) as handle_balance:
            missing = client.get("/billing/balance")
            wrong = client.get(
                "/billing/balance",
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        handle_balance.assert_not_awaited()

    def test_balance_returns_exact_band_only_shape_for_runtime_auth(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch(
            "tinker_delegate.api.handle_get_balance",
            new=AsyncMock(
                return_value=BillingResponse(success=True, balance_band="10_100_usd")
            ),
        ):
            response = client.get(
                "/billing/balance",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "success": True,
                "balance_band": "10_100_usd",
                "raw_secret_egress": False,
            },
        )
        self.assertNotIn("$", response.text)

    def test_balance_accepts_only_the_balance_scoped_proxy_token(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                proxy_jwt_key="45" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="45" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:balance"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)
            with patch(
                "tinker_delegate.api.handle_get_balance",
                new=AsyncMock(
                    return_value=BillingResponse(success=True, balance_band="lt_10_usd")
                ),
            ) as handle_balance:
                response = client.get(
                    "/billing/balance",
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["balance_band"], "lt_10_usd")
        self.assertEqual(body["proxy_auth_context"]["required_scope"], "billing:balance")
        self.assertNotIn("balance", {key for key in body if key != "balance_band"})
        self.assertNotIn("$", response.text)
        handle_balance.assert_awaited_once()

    def test_attestation_endpoint_binds_requested_billing_context(self):
        client = TestClient(api.app)

        response = client.get("/attestation", params={"context": "billing"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        keypair = get_tee_keypair()
        self.assertEqual(body["report_context"], "billing")
        self.assertEqual(
            body["report_data"],
            attestation_report_data("billing", keypair.public_key_bytes).hex(),
        )

    def test_attestation_endpoint_strips_nested_secret_metadata(self):
        client = TestClient(api.app)
        sentinel = "sentinel-runtime-auth-secret"
        unbounded = {
            "mode": "tdx",
            "quote": "aa",
            "encryption_public_key": "11" * 32,
            "report_context": "artifact",
            "report_data": "22" * 32,
            "quote_report_data": "22" * 32,
            "app_id": "app-ok",
            "compose_hash": "compose-ok",
            "os_image_hash": "os-ok",
            # Even a lower layer that tries to self-assert verification must be
            # clamped at the public service boundary.
            "verified": True,
            "event_log": {"secret": sentinel},
            "vm_config": {"secret": sentinel},
            "tcb_info": {
                "app_compose": {
                    "docker_compose_file": f"TINKER_RUNTIME_AUTH_TOKEN={sentinel}",
                },
            },
        }

        with patch("tinker_delegate.api.get_attestation", return_value=unbounded):
            response = client.get("/attestation", params={"context": "artifact"})

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["verified"])
        self.assertNotIn(sentinel, response.text)
        for forbidden in ("event_log", "vm_config", "tcb_info", "app_compose"):
            self.assertNotIn(forbidden, body)
        self.assertEqual(
            set(body),
            {
                "mode",
                "quote",
                "encryption_public_key",
                "report_context",
                "report_data",
                "quote_report_data",
                "app_id",
                "compose_hash",
                "os_image_hash",
                "verified",
            },
        )

    def test_attestation_endpoint_rejects_unknown_context(self):
        client = TestClient(api.app)

        response = client.get("/attestation", params={"context": "raw-card-dump"})

        self.assertEqual(response.status_code, 400)

    def test_encrypted_card_endpoint_decrypts_and_persists_bounded_receipt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            key = "aa" * 32
            api.settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key=key,
                funding_mode="operator_capped_validation",
            )
            client = TestClient(api.app)
            attestation = client.get("/attestation", params={"context": "billing"}).json()
            encrypted = encrypt_billing_card_payload(
                CARD_PAYLOAD,
                attestation["encryption_public_key"],
            )

            with patch(
                "tinker_delegate.card_channel.add_payment_method",
                new=AsyncMock(return_value={"success": False, "error": "Your card was declined."}),
            ):
                response = client.post("/billing/card/encrypted", json=encrypted)

            stored = FundingReceiptStore(str(receipt_path), key_hex=key).load()

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["success"])
        self.assertEqual(body["attempt_record"]["outcome"], "card_declined")
        self.assertEqual(stored, [body["attempt_record"]])
        self.assertNotIn("4242424242424242", repr(body))

    def test_encrypted_card_endpoint_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            funding_mode="operator_capped_validation",
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        attestation = client.get("/attestation", params={"context": "billing"}).json()
        encrypted = encrypt_billing_card_payload(CARD_PAYLOAD, attestation["encryption_public_key"])

        with patch("tinker_delegate.card_channel.add_payment_method", new=AsyncMock()) as add_payment:
            missing = client.post("/billing/card/encrypted", json=encrypted)
            wrong = client.post(
                "/billing/card/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        add_payment.assert_not_called()

    def test_funding_receipts_endpoint_returns_bounded_records(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            receipt_path = Path(tmpdir) / "funding_receipts.enc"
            key = "88" * 32
            api.settings = Settings(
                funding_receipt_store_path=str(receipt_path),
                funding_receipt_store_key=key,
            )
            receipt = make_receipt(
                surface=AutomationSurface.PAYMENT_METHOD,
                outcome=AutomationOutcome.CARD_DECLINED,
                furthest_stage=AutomationStage.PAYMENT_SUBMITTED,
                evidence="card_number=4242424242424242",
                bounded_message="Your card was declined.",
                card_payload_destroyed=True,
            ).to_public_dict()
            FundingReceiptStore(str(receipt_path), key_hex=key).append(receipt)
            client = TestClient(api.app)

            response = client.get("/billing/funding-receipts")

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["count"], 1)
        self.assertEqual(body["receipts"][0]["outcome"], "card_declined")
        self.assertNotIn("4242424242424242", repr(body))

    def test_funding_receipt_store_failure_returns_only_store_failed(self):
        class FailingStore:
            def load(self):
                raise RuntimeError(
                    "disk failure at https://private.example/card/4242424242424242"
                )

        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)
        with patch(
            "tinker_delegate.api.build_funding_receipt_store",
            return_value=FailingStore(),
        ):
            response = client.get(
                "/billing/funding-receipts",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {"detail": "store_failed"})
        self.assertNotIn("private.example", response.text)
        self.assertNotIn("4242424242424242", response.text)

    def test_payment_method_status_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.api.handle_payment_method_status", new=AsyncMock()) as handle_status:
            missing = client.get("/billing/payment-method-status")
            wrong = client.get(
                "/billing/payment-method-status",
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        handle_status.assert_not_called()

    def test_payment_method_status_returns_bounded_card_presence_only(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch(
            "tinker_delegate.api.handle_payment_method_status",
            new=AsyncMock(
                return_value={
                    "success": True,
                    "card_on_file": True,
                    "payment_method_count_band": "one_or_more",
                    "attempt_record": _success_receipt(
                        AutomationSurface.PAYMENT_METHOD_STATUS
                    ),
                }
            ),
        ):
            response = client.get(
                "/billing/payment-method-status",
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["card_on_file"])
        self.assertEqual(body["payment_method_count_band"], "one_or_more")
        rendered = repr(body)
        self.assertNotIn("4242424242424242", rendered)
        self.assertNotIn("last4", rendered)
        self.assertNotIn("expiry", rendered)

    def test_remove_card_endpoint_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.api.handle_remove_payment_method", new=AsyncMock()) as handle_remove:
            missing = client.post("/billing/card/remove")
            wrong = client.post(
                "/billing/card/remove",
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        handle_remove.assert_not_called()

    def test_add_balance_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_add_balance_endpoint=False)
        client = TestClient(api.app)

        with patch("tinker_delegate.api.handle_add_balance", new=AsyncMock()) as handle_add_balance:
            response = client.post("/billing/add-balance", json={"amount_dollars": 10.0})

        self.assertEqual(response.status_code, 403)
        self.assertIn("Add-balance endpoint is disabled", response.json()["detail"])
        handle_add_balance.assert_not_called()

    def test_add_balance_endpoint_can_be_explicitly_enabled(self):
        api.settings = Settings(
            allow_add_balance_endpoint=True,
            funding_mode="operator_capped_validation",
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch(
            "tinker_delegate.api.handle_add_balance",
            new=AsyncMock(return_value={"success": False, "error": "unknown_failure"}),
        ) as handle_add_balance:
            response = client.post(
                "/billing/add-balance",
                json={"amount_dollars": 10.0},
                headers={"Authorization": "Bearer operator-secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"], "unknown_failure")
        handle_add_balance.assert_awaited_once()

    def test_payment_method_status_accepts_scoped_proxy_jwt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                proxy_jwt_key="44" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="44" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:payment-method-status"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            with patch(
                "tinker_delegate.api.handle_payment_method_status",
                new=AsyncMock(
                    return_value={
                        "success": True,
                        "card_on_file": True,
                        "payment_method_count_band": "one_or_more",
                        "attempt_record": _success_receipt(
                            AutomationSurface.PAYMENT_METHOD_STATUS
                        ),
                    }
                ),
            ) as handle_status:
                response = client.get(
                    "/billing/payment-method-status",
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["card_on_file"])
        handle_status.assert_awaited_once()

    def test_add_balance_endpoint_accepts_scoped_proxy_jwt(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_add_balance_endpoint=True,
                funding_mode="operator_capped_validation",
                proxy_jwt_key="44" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="44" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:add-balance"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            with patch(
                "tinker_delegate.api.handle_add_balance",
                new=AsyncMock(return_value={"success": False, "error": "unknown_failure"}),
            ) as handle_add_balance:
                response = client.post(
                    "/billing/add-balance",
                    json={"amount_dollars": 10.0},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error"], "unknown_failure")
        handle_add_balance.assert_awaited_once()

    def test_add_balance_endpoint_rejects_proxy_jwt_over_policy_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_add_balance_endpoint=True,
                funding_mode="operator_capped_validation",
                proxy_jwt_key="44" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="44" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:add-balance"],
                ttl_seconds=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10.0}},
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.api.handle_add_balance", new=AsyncMock()) as handle_add_balance:
                response = client.post(
                    "/billing/add-balance",
                    json={"amount_dollars": 11.0},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        self.assertIn("exceeds policy limit", response.json()["detail"])
        handle_add_balance.assert_not_awaited()

    def test_add_balance_endpoint_allows_proxy_jwt_within_policy_limit(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_add_balance_endpoint=True,
                funding_mode="operator_capped_validation",
                proxy_jwt_key="44" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="44" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:add-balance"],
                ttl_seconds=60,
                scope_limits={"billing:add-balance": {"max_amount_usd": 10.0}},
            )
            client = TestClient(api.app)

            with patch(
                "tinker_delegate.api.handle_add_balance",
                new=AsyncMock(return_value={"success": False, "error": "unknown_failure"}),
            ) as handle_add_balance:
                response = client.post(
                    "/billing/add-balance",
                    json={"amount_dollars": 10.0},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["proxy_auth_context"]["scope_limits"]["billing:add-balance"]["max_amount_usd"], 10.0)
        handle_add_balance.assert_awaited_once()

    def test_add_balance_endpoint_rejects_proxy_jwt_without_scope(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            api.settings = Settings(
                allow_add_balance_endpoint=True,
                funding_mode="operator_capped_validation",
                proxy_jwt_key="44" * 32,
                proxy_token_store_path=f"{tmpdir}/proxy_tokens.enc",
                proxy_token_store_key="44" * 32,
            )
            _, token = issue_proxy_token(
                api.settings,
                subject="buyer-agent-1",
                scopes=["billing:payment-method-status"],
                ttl_seconds=60,
            )
            client = TestClient(api.app)

            with patch("tinker_delegate.api.handle_add_balance", new=AsyncMock()) as handle_add_balance:
                response = client.post(
                    "/billing/add-balance",
                    json={"amount_dollars": 10.0},
                    headers={"Authorization": f"Bearer {token}"},
                )

        self.assertEqual(response.status_code, 403)
        handle_add_balance.assert_not_called()

    def test_add_balance_endpoint_requires_runtime_auth_when_enabled(self):
        api.settings = Settings(
            allow_add_balance_endpoint=True,
            funding_mode="operator_capped_validation",
            runtime_auth_required=True,
            runtime_auth_token="operator-secret",
        )
        client = TestClient(api.app)

        with patch("tinker_delegate.api.handle_add_balance", new=AsyncMock()) as handle_add_balance:
            missing = client.post("/billing/add-balance", json={"amount_dollars": 10.0})
            wrong = client.post(
                "/billing/add-balance",
                json={"amount_dollars": 10.0},
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        handle_add_balance.assert_not_called()


if __name__ == "__main__":
    unittest.main()
