import unittest
from unittest.mock import patch

import httpx

from tinker_delegate.attestation_verifier import AttestationVerificationError
from tinker_delegate.billing_uploader import (
    BillingCardUploadPolicy,
    upload_billing_card_payload,
    verify_billing_attestation,
)
from tinker_delegate.card_channel import get_attestation


def _card_payload() -> dict:
    return {
        "card_number": "4242424242424242",
        "exp_month": "12",
        "exp_year": "2030",
        "cvc": "123",
        "cardholder_name": "Stripe Test User",
        "address_postal": "94105",
    }


def _tdx_billing_attestation(compose_hash: str = "compose-ok", app_id: str = "app-ok") -> dict:
    attestation = get_attestation("billing")
    attestation.update({
        "mode": "tdx",
        "verified": True,
        "quote": "aa",
        "compose_hash": compose_hash,
        "app_id": app_id,
    })
    return attestation


class BillingUploaderTest(unittest.TestCase):
    def test_rejects_local_attestation_by_default(self):
        with self.assertRaisesRegex(AttestationVerificationError, "local attestation"):
            verify_billing_attestation(get_attestation("billing"), BillingCardUploadPolicy())

    def test_allows_local_attestation_only_when_explicit(self):
        public_key = verify_billing_attestation(
            get_attestation("billing"),
            BillingCardUploadPolicy(allow_local=True),
        )

        self.assertEqual(len(bytes.fromhex(public_key)), 32)

    def test_rejects_artifact_context_for_billing_payload(self):
        with self.assertRaisesRegex(AttestationVerificationError, "report context mismatch"):
            verify_billing_attestation(
                get_attestation("artifact"),
                BillingCardUploadPolicy(allow_local=True),
            )

    def test_upload_encrypts_after_attestation_gate_passes(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET" and request.url.path == "/attestation":
                self.assertEqual(request.url.params["context"], "billing")
                return httpx.Response(200, json=_tdx_billing_attestation())
            if request.method == "POST" and request.url.path == "/billing/card/encrypted":
                self.assertEqual(request.headers.get("authorization"), "Bearer operator-secret")
                payload = request.read().decode()
                self.assertIn("ciphertext", payload)
                self.assertIn("ephemeral_public_key", payload)
                self.assertIn("nonce", payload)
                self.assertNotIn("4242424242424242", payload)
                self.assertNotIn("Stripe Test User", payload)
                self.assertNotIn("card_number", payload)
                self.assertNotIn("cvc", payload)
                return httpx.Response(
                    200,
                    json={
                        "success": False,
                        "error": "Your card was declined.",
                        "attempt_record": {
                            "surface": "payment_method",
                            "outcome": "card_declined",
                        },
                    },
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))

        result = upload_billing_card_payload(
            "https://tee.example",
            _card_payload(),
            BillingCardUploadPolicy(
                expected_compose_hash="compose-ok",
                expected_app_id="app-ok",
                auth_token="operator-secret",
            ),
            client=client,
        )

        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.response["success"])
        self.assertEqual(result.response["attempt_record"]["outcome"], "card_declined")
        self.assertEqual([request.url.path for request in requests], [
            "/attestation",
            "/billing/card/encrypted",
        ])

    def test_default_client_timeout_allows_browser_driven_card_update(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET" and request.url.path == "/attestation":
                return httpx.Response(200, json=_tdx_billing_attestation())
            if request.method == "POST" and request.url.path == "/billing/card/encrypted":
                return httpx.Response(
                    200,
                    json={
                        "success": True,
                        "attempt_record": {
                            "surface": "payment_method",
                            "outcome": "success",
                        },
                    },
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with patch("tinker_delegate.billing_uploader.httpx.Client", return_value=client) as client_factory:
            result = upload_billing_card_payload(
                "https://tee.example",
                _card_payload(),
                BillingCardUploadPolicy(
                    expected_compose_hash="compose-ok",
                    expected_app_id="app-ok",
                ),
            )

        self.assertTrue(result.response["success"])
        self.assertEqual(client_factory.call_args.kwargs["timeout"], 180.0)
        self.assertEqual([request.url.path for request in requests], [
            "/attestation",
            "/billing/card/encrypted",
        ])

    def test_upload_does_not_post_when_attestation_fails(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET" and request.url.path == "/attestation":
                self.assertEqual(request.url.params["context"], "billing")
                return httpx.Response(200, json=_tdx_billing_attestation(compose_hash="bad"))
            return httpx.Response(500, json={"error": "should not post"})

        client = httpx.Client(transport=httpx.MockTransport(handler))

        with self.assertRaisesRegex(AttestationVerificationError, "compose hash mismatch"):
            upload_billing_card_payload(
                "https://tee.example",
                _card_payload(),
                BillingCardUploadPolicy(expected_compose_hash="compose-ok"),
                client=client,
            )

        self.assertEqual([request.url.path for request in requests], ["/attestation"])


if __name__ == "__main__":
    unittest.main()
