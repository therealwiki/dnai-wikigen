import unittest
from unittest.mock import Mock

import httpx

from tinker_delegate.config import Settings
from tinker_delegate.oracle_client import OracleClient


class OracleClientTest(unittest.TestCase):
    def test_get_email_uses_authenticated_email_endpoint(self):
        settings = Settings(
            oracle_url="https://oracle.example",
            oracle_auth_token="shared-secret",
        )
        client = OracleClient(settings)
        response = httpx.Response(
            200,
            json={
                "oracle_email": "oracle@example.com",
                "oracle_email_hash": "a" * 64,
                "timestamp": "2026-07-08T00:00:00+00:00",
            },
        )
        response.request = httpx.Request("GET", "https://oracle.example/email")
        client._client.get = Mock(return_value=response)

        email = client.get_email()

        self.assertEqual(email, "oracle@example.com")
        client._client.get.assert_called_once_with(
            "https://oracle.example/email",
            headers={"Authorization": "Bearer shared-secret"},
        )


if __name__ == "__main__":
    unittest.main()
