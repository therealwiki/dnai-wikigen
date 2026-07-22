import unittest
from unittest.mock import Mock

import httpx

from tinker_delegate.config import Settings
from tinker_delegate.oracle_client import ORACLE_CALLER_IDENTITY, OracleClient


class OracleClientTest(unittest.TestCase):
    def test_health_accepts_only_liveness_shape(self):
        client = OracleClient(Settings(oracle_url="https://oracle.example"))
        response = httpx.Response(
            200,
            json={"service": "tee-email-oracle", "status": "ok"},
            request=httpx.Request("GET", "https://oracle.example/health"),
        )
        client._client.get = Mock(return_value=response)

        self.assertEqual(
            client.health(),
            {"service": "tee-email-oracle", "status": "ok"},
        )

    def test_health_rejects_mailbox_state_even_if_otherwise_healthy(self):
        client = OracleClient(Settings(oracle_url="https://oracle.example"))
        response = httpx.Response(
            200,
            json={
                "service": "tee-email-oracle",
                "status": "ok",
                "oracle_ready": True,
                "imap_connected": True,
            },
            request=httpx.Request("GET", "https://oracle.example/health"),
        )
        client._client.get = Mock(return_value=response)

        with self.assertRaisesRegex(RuntimeError, "non-liveness health shape"):
            client.health()

    def test_get_email_status_uses_authenticated_commitment_endpoint(self):
        settings = Settings(
            oracle_url="https://oracle.example",
            oracle_auth_token="shared-secret",
        )
        client = OracleClient(settings)
        response = httpx.Response(
            200,
            json={
                "oracle_ready": True,
                "oracle_email_commitment": "a" * 64,
                "commitment_scheme": "dnai-wikigen/oracle-email/v1",
                "raw_email_egress": False,
                "timestamp": "2026-07-08T00:00:00+00:00",
            },
        )
        response.request = httpx.Request("GET", "https://oracle.example/email")
        client._client.get = Mock(return_value=response)

        receipt = client.get_email_status()

        self.assertTrue(receipt["oracle_ready"])
        self.assertEqual(receipt["oracle_email_commitment"], "a" * 64)
        self.assertNotIn("oracle_email", receipt)
        client._client.get.assert_called_once_with(
            "https://oracle.example/email",
            headers={"Authorization": "Bearer shared-secret"},
        )

    def test_get_email_rejects_raw_address_egress(self):
        settings = Settings(
            oracle_url="https://oracle.example",
            oracle_auth_token="shared-secret",
        )
        client = OracleClient(settings)
        response = httpx.Response(
            200,
            json={
                "oracle_email": "private-oracle@example.test",
                "oracle_email_hash": "a" * 64,
                "timestamp": "2026-07-08T00:00:00+00:00",
            },
        )
        response.request = httpx.Request("GET", "https://oracle.example/email")
        client._client.get = Mock(return_value=response)

        with self.assertRaisesRegex(RuntimeError, "non-allowlisted status shape"):
            client.get_email()

    def test_list_inbox_is_disabled_without_network_access(self):
        client = OracleClient(Settings(oracle_url="https://oracle.example"))
        client._client.get = Mock()

        with self.assertRaisesRegex(RuntimeError, "mailbox listing is permanently disabled"):
            client.list_inbox()

        client._client.get.assert_not_called()

    def test_get_pin_accepts_exact_minimized_response(self):
        client = OracleClient(
            Settings(
                oracle_url="https://oracle.example",
                oracle_auth_token="shared-secret",
            )
        )
        response = httpx.Response(
            200,
            json={
                "pin": "123456",
                "request_hash": "a" * 64,
                "attestation_report_data": "b" * 64,
                "tdx_quote": "cc",
            },
            request=httpx.Request("POST", "https://oracle.example/pin"),
        )
        client._client.post = Mock(return_value=response)

        result = client.get_pin(nonce="nonce-123456")

        self.assertEqual(result["pin"], "123456")
        self.assertEqual(
            set(result),
            {"pin", "request_hash", "attestation_report_data", "tdx_quote"},
        )
        self.assertEqual(
            client._client.post.call_args.kwargs["headers"],
            {"Authorization": "Bearer shared-secret"},
        )
        self.assertEqual(
            client._client.post.call_args.kwargs["json"]["caller_identity"],
            ORACLE_CALLER_IDENTITY,
        )

    def test_get_pin_rejects_private_metadata_fields(self):
        client = OracleClient(Settings(oracle_url="https://oracle.example"))
        response = httpx.Response(
            200,
            json={
                "pin": "123456",
                "request_hash": "a" * 64,
                "attestation_report_data": "b" * 64,
                "tdx_quote": "",
                "sender_hash": "c" * 64,
            },
            request=httpx.Request("POST", "https://oracle.example/pin"),
        )
        client._client.post = Mock(return_value=response)

        with self.assertRaisesRegex(RuntimeError, "non-allowlisted OTP shape"):
            client.get_pin(nonce="nonce-123456")

    def test_get_pin_rejects_legacy_caller_identity_without_network_access(self):
        client = OracleClient(Settings(oracle_url="https://oracle.example"))
        client._client.post = Mock()

        with self.assertRaisesRegex(ValueError, "unsupported email-oracle caller"):
            client.get_pin(
                nonce="nonce-123456",
                caller_identity="tinker-delegate",
            )

        client._client.post.assert_not_called()


if __name__ == "__main__":
    unittest.main()
