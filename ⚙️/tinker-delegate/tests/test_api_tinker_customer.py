from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.tinker_customer_adapter import (
    TinkerCustomerConflict,
    TinkerCustomerNotFound,
    TinkerCustomerUnavailable,
)
from tinker_delegate.tinker_customer_execution import (
    TinkerCustomerReconciliationRequired,
)


ACCOUNT_ID = "tca_" + "11" * 12
CREDENTIAL_ID = "tcc_" + "22" * 12
RESERVATION_ID = "tcr_" + "33" * 12
RECIPIENT_KEY = "44" * 32
WORKLOAD = "sha256:" + "55" * 32
RUNTIME_TOKEN = "tinker-customer-runtime-token"


class FakeCustomerAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.failure: Exception | None = None

    def _result(self, operation: str, values: dict) -> dict:
        self.calls.append((operation, values))
        if self.failure is not None:
            raise self.failure
        return {
            "surface": f"test_{operation}",
            "raw_secret_egress": False,
            **{
                key: value
                for key, value in values.items()
                if key not in {"wallet_token", "credential_token"}
            },
        }

    def request_account(self, **kwargs):
        return self._result("request_account", kwargs)

    def current_account_status(self, **kwargs):
        return self._result("current_account_status", kwargs)

    def account_status(self, **kwargs):
        return self._result("account_status", kwargs)

    def issue_credential(self, **kwargs):
        return self._result("issue_credential", kwargs)

    def list_credentials(self, **kwargs):
        return self._result("list_credentials", kwargs)

    def rotate_credential(self, **kwargs):
        return self._result("rotate_credential", kwargs)

    def revoke_credential(self, **kwargs):
        return self._result("revoke_credential", kwargs)

    def revoke_account(self, **kwargs):
        return self._result("revoke_account", kwargs)

    def reserve_spend(self, **kwargs):
        return self._result("reserve_spend", kwargs)

    def activate_account(self, **kwargs):
        return self._result("activate_account", kwargs)

    def finalize_reservation(self, **kwargs):
        return self._result("finalize_reservation", kwargs)


class FakeCustomerTrainingService:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.failure: Exception | None = None

    def execute(self, **kwargs):
        self.calls.append(kwargs)
        if self.failure is not None:
            raise self.failure
        return {
            "surface": "tinker_customer_training_execution",
            "status": "settled",
            "raw_secret_egress": False,
        }


class TinkerCustomerApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.original_settings = api.settings
        self.original_override = api._tinker_customer_adapter_override
        self.original_instance = api._tinker_customer_adapter_instance
        self.original_identity = api._tinker_customer_adapter_identity
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token=RUNTIME_TOKEN,
        )
        self.adapter = FakeCustomerAdapter()
        api._tinker_customer_adapter_override = self.adapter
        api._tinker_customer_adapter_instance = None
        api._tinker_customer_adapter_identity = None
        self.client = TestClient(api.app)
        self.wallet_headers = {"Authorization": "Bearer wallet-session"}

    def tearDown(self) -> None:
        api.settings = self.original_settings
        api._tinker_customer_adapter_override = self.original_override
        api._tinker_customer_adapter_instance = self.original_instance
        api._tinker_customer_adapter_identity = self.original_identity

    @staticmethod
    def _credential_body() -> dict:
        return {
            "recipient_public_key": RECIPIENT_KEY,
            "operations": ["training"],
            "ttl_seconds": 600,
            "max_operation_policy_units": 25_000,
        }

    def test_wallet_lifecycle_routes_forward_only_bounded_exact_fields(self):
        request = self.client.post(
            "/tinker/customer/accounts/requests",
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "account-request-0001",
            },
            json={"mode": "create"},
        )
        current = self.client.get(
            "/tinker/customer/accounts/current",
            headers=self.wallet_headers,
        )
        status = self.client.get(
            f"/tinker/customer/accounts/{ACCOUNT_ID}",
            headers=self.wallet_headers,
        )
        issued = self.client.post(
            f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials",
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "credential-issue-0001",
            },
            json=self._credential_body(),
        )
        listed = self.client.get(
            f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials",
            headers=self.wallet_headers,
        )
        rotated = self.client.post(
            (
                f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials/"
                f"{CREDENTIAL_ID}/rotate"
            ),
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "credential-rotate-0001",
            },
            json=self._credential_body(),
        )
        revoked = self.client.post(
            (
                f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials/"
                f"{CREDENTIAL_ID}/revoke"
            ),
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "credential-revoke-0001",
            },
            json={},
        )
        account_revoked = self.client.post(
            f"/tinker/customer/accounts/{ACCOUNT_ID}/revoke",
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "account-revoke-0001",
            },
            json={},
        )

        for response in (
            request,
            current,
            status,
            issued,
            listed,
            rotated,
            revoked,
            account_revoked,
        ):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertNotIn("wallet-session", response.text)
            self.assertEqual(
                response.headers["cache-control"],
                "no-store, max-age=0",
            )
            self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(
            [operation for operation, _ in self.adapter.calls],
            [
                "request_account",
                "current_account_status",
                "account_status",
                "issue_credential",
                "list_credentials",
                "rotate_credential",
                "revoke_credential",
                "revoke_account",
            ],
        )
        issue_values = self.adapter.calls[3][1]
        self.assertEqual(issue_values["operations"], ["training"])
        self.assertEqual(issue_values["max_operation_policy_units"], 25_000)
        self.assertEqual(issue_values["recipient_public_key"], RECIPIENT_KEY)
        list_values = self.adapter.calls[4][1]
        self.assertEqual(list_values["limit"], 16)
        self.assertIsNone(list_values["cursor"])

    def test_credential_pages_forward_bounded_limit_and_opaque_cursor(self):
        cursor = "tinker_credentials_v1.opaque.signed"
        response = self.client.get(
            (
                f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials"
                f"?limit=64&cursor={cursor}"
            ),
            headers=self.wallet_headers,
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store, max-age=0",
        )
        operation, values = self.adapter.calls[-1]
        self.assertEqual(operation, "list_credentials")
        self.assertEqual(values["account_id"], ACCOUNT_ID)
        self.assertEqual(values["limit"], 64)
        self.assertEqual(values["cursor"], cursor)

        call_count = len(self.adapter.calls)
        too_large = self.client.get(
            f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials?limit=65",
            headers=self.wallet_headers,
        )
        oversized_cursor = self.client.get(
            (
                f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials"
                f"?cursor={'x' * 1025}"
            ),
            headers=self.wallet_headers,
        )
        body = self.client.request(
            "GET",
            f"/tinker/customer/accounts/{ACCOUNT_ID}/credentials",
            headers=self.wallet_headers,
            json={},
        )
        self.assertEqual(too_large.status_code, 422)
        self.assertEqual(oversized_cursor.status_code, 422)
        self.assertEqual(body.status_code, 413)
        self.assertEqual(len(self.adapter.calls), call_count)

    def test_reservation_is_metadata_only_and_never_claims_dispatch(self):
        response = self.client.post(
            "/tinker/customer/reservations",
            headers={
                "Authorization": "Bearer delegated-customer-token",
                "Idempotency-Key": "customer-reservation-0001",
            },
            json={
                "operation": "training",
                "amount_policy_units": 5_000,
                "workload_commitment": WORKLOAD,
            },
        )

        self.assertEqual(response.status_code, 200, response.text)
        operation, values = self.adapter.calls[-1]
        self.assertEqual(operation, "reserve_spend")
        self.assertEqual(values["credential_token"], "delegated-customer-token")
        self.assertNotIn("delegated-customer-token", response.text)
        self.assertNotIn("prompt", response.text)
        self.assertNotIn("examples", response.text)

    def test_customer_training_route_accepts_only_three_bounded_controls(self):
        training = FakeCustomerTrainingService()
        with patch.object(
            api,
            "_get_tinker_customer_training_service",
            return_value=training,
        ):
            response = self.client.post(
                "/tinker/customer/train",
                headers={
                    "Authorization": "Bearer delegated-customer-token",
                    "Idempotency-Key": "customer-training-request-0001",
                },
                json={
                    "max_usd_micros": 125_000,
                    "steps": 3,
                    "ttl_seconds": 600,
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertNotIn("delegated-customer-token", response.text)
        self.assertEqual(len(training.calls), 1)
        values = training.calls[0]
        self.assertEqual(values["credential_token"], "delegated-customer-token")
        self.assertEqual(
            values["idempotency_key"],
            "customer-training-request-0001",
        )
        self.assertEqual(values["request"].max_usd_micros, 125_000)
        self.assertEqual(values["request"].steps, 3)
        self.assertEqual(values["request"].ttl_seconds, 600)

    def test_customer_training_rejects_secret_fields_and_non_integer_caps(self):
        training = FakeCustomerTrainingService()
        secret = "PROVIDER-KEY-CANARY"
        with patch.object(
            api,
            "_get_tinker_customer_training_service",
            return_value=training,
        ):
            extra = self.client.post(
                "/tinker/customer/train",
                headers={
                    "Authorization": "Bearer delegated-customer-token",
                    "Idempotency-Key": "customer-training-request-0002",
                },
                json={
                    "max_usd_micros": 1,
                    "examples": [["prompt", secret]],
                },
            )
            boolean = self.client.post(
                "/tinker/customer/train",
                headers={
                    "Authorization": "Bearer delegated-customer-token",
                    "Idempotency-Key": "customer-training-request-0003",
                },
                json={"max_usd_micros": True},
            )

        self.assertEqual(extra.status_code, 422)
        self.assertEqual(boolean.status_code, 422)
        self.assertEqual(
            extra.headers["cache-control"],
            "no-store, max-age=0",
        )
        self.assertEqual(extra.headers["pragma"], "no-cache")
        self.assertNotIn(secret, extra.text)
        self.assertEqual(training.calls, [])

    def test_customer_training_reconciliation_is_bounded_and_conflicting(self):
        training = FakeCustomerTrainingService()
        training.failure = TinkerCustomerReconciliationRequired(
            reservation_id=RESERVATION_ID,
            reservation_commitment="sha256:" + "66" * 32,
            workload_commitment=WORKLOAD,
        )
        with patch.object(
            api,
            "_get_tinker_customer_training_service",
            return_value=training,
        ):
            response = self.client.post(
                "/tinker/customer/train",
                headers={
                    "Authorization": "Bearer delegated-customer-token",
                    "Idempotency-Key": "customer-training-request-0004",
                },
                json={"max_usd_micros": 50_000},
            )

        self.assertEqual(response.status_code, 409, response.text)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store, max-age=0",
        )
        detail = response.json()["detail"]
        self.assertEqual(detail["status"], "reconciliation_required")
        self.assertEqual(detail["reservation_id"], RESERVATION_ID)
        self.assertFalse(detail["automatic_provider_redispatch"])
        self.assertFalse(detail["provider_outcome_confirmed"])

    def test_customer_training_body_is_limited_before_validation(self):
        training = FakeCustomerTrainingService()
        with patch.object(
            api,
            "_get_tinker_customer_training_service",
            return_value=training,
        ):
            response = self.client.post(
                "/tinker/customer/train",
                headers={
                    "Authorization": "Bearer delegated-customer-token",
                    "Idempotency-Key": "customer-training-request-0005",
                },
                content=json.dumps(
                    {
                        "max_usd_micros": 1,
                        "padding": "x" * 5_000,
                    }
                ),
            )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store, max-age=0",
        )
        self.assertEqual(response.headers["pragma"], "no-cache")
        self.assertEqual(training.calls, [])

    def test_internal_activation_and_finalization_require_runtime_bearer(self):
        missing = self.client.post(
            f"/tinker/internal/customer/accounts/{ACCOUNT_ID}/activate",
            headers={"Idempotency-Key": "internal-activate-0001"},
            json={},
        )
        activated = self.client.post(
            f"/tinker/internal/customer/accounts/{ACCOUNT_ID}/activate",
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "internal-activate-0001",
            },
            json={},
        )
        finalized = self.client.post(
            (
                "/tinker/internal/customer/reservations/"
                f"{RESERVATION_ID}/finalize"
            ),
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "internal-finalize-0001",
            },
            json={},
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(activated.status_code, 200, activated.text)
        self.assertEqual(finalized.status_code, 200, finalized.text)
        for response in (missing, activated, finalized):
            self.assertEqual(
                response.headers["cache-control"],
                "no-store, max-age=0",
            )
        self.assertEqual(
            [operation for operation, _ in self.adapter.calls],
            ["activate_account", "finalize_reservation"],
        )

    def test_missing_bearer_fails_before_adapter_resolution(self):
        response = self.client.get("/tinker/customer/accounts/current")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.adapter.calls, [])

    def test_disabled_runtime_fails_closed_without_override(self):
        api._tinker_customer_adapter_override = None
        api.settings = Settings(tinker_customer_enabled=False)

        response = self.client.get(
            "/tinker/customer/accounts/current",
            headers=self.wallet_headers,
        )

        self.assertEqual(response.status_code, 503)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store, max-age=0",
        )
        self.assertEqual(
            response.json()["detail"],
            "Tinker customer lifecycle is unavailable",
        )

    def test_adapter_error_mapping_never_reflects_upstream_text(self):
        cases = (
            (TinkerCustomerNotFound("SECRET-not-found"), 404),
            (TinkerCustomerConflict("SECRET-conflict"), 409),
            (TinkerCustomerUnavailable("SECRET-provider"), 503),
        )
        for failure, expected_status in cases:
            with self.subTest(failure=type(failure).__name__):
                self.adapter.failure = failure
                response = self.client.get(
                    "/tinker/customer/accounts/current",
                    headers=self.wallet_headers,
                )
                self.assertEqual(response.status_code, expected_status)
                self.assertNotIn("SECRET", response.text)
        self.adapter.failure = RuntimeError("SECRET-unknown")
        response = self.client.get(
            "/tinker/customer/accounts/current",
            headers=self.wallet_headers,
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SECRET", response.text)

    def test_request_models_reject_secret_fields_and_zero_commitment_without_reflection(self):
        secret = "PROVIDER-SECRET-CANARY"
        extra = self.client.post(
            "/tinker/customer/accounts/requests",
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "account-request-extra-0001",
            },
            json={"mode": "create", "upstream_api_key": secret},
        )
        zero = self.client.post(
            "/tinker/customer/reservations",
            headers={
                "Authorization": "Bearer delegated-customer-token",
                "Idempotency-Key": "reservation-zero-0001",
            },
            json={
                "operation": "training",
                "amount_policy_units": 1,
                "workload_commitment": "sha256:" + "0" * 64,
            },
        )

        self.assertEqual(extra.status_code, 422)
        self.assertEqual(zero.status_code, 422)
        self.assertNotIn(secret, extra.text)
        self.assertEqual(self.adapter.calls, [])

    def test_customer_route_body_is_limited_before_pydantic_buffering(self):
        response = self.client.post(
            "/tinker/customer/accounts/requests",
            headers={
                **self.wallet_headers,
                "Idempotency-Key": "account-request-large-0001",
            },
            content=json.dumps(
                {"mode": "create", "padding": "x" * 5_000}
            ),
        )

        self.assertEqual(response.status_code, 413)
        self.assertEqual(
            response.headers["cache-control"],
            "no-store, max-age=0",
        )
        self.assertEqual(self.adapter.calls, [])


if __name__ == "__main__":
    unittest.main()
