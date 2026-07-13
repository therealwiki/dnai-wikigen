import unittest
from unittest.mock import Mock

from email_oracle.credential_uploader import (
    CredentialUploadError,
    CredentialUploadPolicy,
    credential_hashes,
    forbidden_credential_values,
    upload_credentials_payload,
    verify_credential_attestation,
)
from email_oracle.crypto import TEEKeyPair, attestation_report_data


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeHttp:
    def __init__(self, attestation, response):
        self.attestation = attestation
        self.response = response
        self.posts = []

    def get(self, url):
        return FakeResponse(self.attestation)

    def post(self, url, *, headers, json):
        self.posts.append({"url": url, "headers": headers, "json": json})
        return FakeResponse(self.response)


def _attestation(context="oracle-credentials", *, mode="tdx"):
    keypair = TEEKeyPair()
    report_data = attestation_report_data("tee-email-oracle", context, keypair.public_key_bytes)
    return {
        "mode": mode,
        "tdx_quote": "aa" * 128,
        "app_id": "app-ok",
        "compose_hash": "c" * 64,
        "os_image_hash": "os-ok",
        "encryption_public_key": keypair.public_key_bytes.hex(),
        "report_context": context,
        "report_data": report_data.hex(),
        "quote_report_data": report_data.hex(),
        "verified": mode == "tdx",
    }


class CredentialUploaderTest(unittest.TestCase):
    def test_verify_credential_attestation_accepts_context_bound_tdx_key(self):
        public_key = verify_credential_attestation(
            _attestation(),
            CredentialUploadPolicy(
                expected_compose_hash="c" * 64,
                expected_app_id="app-ok",
                expected_os_image_hash="os-ok",
            ),
        )

        self.assertEqual(len(public_key), 64)

    def test_verify_credential_attestation_rejects_report_data_mismatch(self):
        attestation = _attestation()
        attestation["report_data"] = "00" * 32

        with self.assertRaisesRegex(CredentialUploadError, "report data"):
            verify_credential_attestation(
                attestation,
                CredentialUploadPolicy(expected_compose_hash="c" * 64),
            )

    def test_upload_encrypts_credentials_and_posts_no_plaintext(self):
        credentials = {
            "username": "oracle",
            "domain": "example.com",
            "password": "secret-password",
        }
        http = FakeHttp(
            _attestation(),
            {
                "status": "stored",
                **credential_hashes(credentials),
                "raw_secret_egress": False,
            },
        )

        result = upload_credentials_payload(
            "https://oracle.example",
            credentials,
            "provision-token",
            CredentialUploadPolicy(
                expected_compose_hash="c" * 64,
                expected_app_id="app-ok",
                expected_os_image_hash="os-ok",
            ),
            client=http,
        )

        self.assertEqual(result.status_code, 200)
        post = http.posts[0]
        self.assertEqual(post["headers"]["Authorization"], "Bearer provision-token")
        rendered_post = str(post["json"])
        self.assertNotIn("oracle", rendered_post)
        self.assertNotIn("example.com", rendered_post)
        self.assertNotIn("secret-password", rendered_post)
        forbidden = forbidden_credential_values(credentials, "provision-token")
        rendered_result = str(result.response)
        for value in forbidden:
            self.assertNotIn(value, rendered_result)

    def test_upload_requires_token(self):
        with self.assertRaisesRegex(CredentialUploadError, "token is required"):
            upload_credentials_payload(
                "https://oracle.example",
                {"username": "oracle", "domain": "example.com", "password": "pw"},
                "",
                CredentialUploadPolicy(allow_local=True),
                client=Mock(),
            )


if __name__ == "__main__":
    unittest.main()
