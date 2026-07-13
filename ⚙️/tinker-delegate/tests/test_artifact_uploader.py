import unittest

import httpx

from tinker_delegate.artifact_uploader import (
    ArtifactUploadPolicy,
    AttestationVerificationError,
    upload_artifact_bytes,
    verify_artifact_attestation,
)
from tinker_delegate.card_channel import get_attestation


EXPECTED_HASH = "0xc90746b1d4e44c6f2bb662d9bef9e40ab48fdd812b8ac8fee2fc87e0a3517da8"


def _tdx_attestation(compose_hash: str = "compose-ok", app_id: str = "app-ok") -> dict:
    attestation = get_attestation("artifact")
    attestation.update({
        "mode": "tdx",
        "verified": True,
        "quote": "aa",
        "compose_hash": compose_hash,
        "app_id": app_id,
    })
    return attestation


class ArtifactUploaderTest(unittest.TestCase):
    def test_rejects_local_attestation_by_default(self):
        with self.assertRaisesRegex(AttestationVerificationError, "local attestation"):
            verify_artifact_attestation(get_attestation("artifact"), ArtifactUploadPolicy())

    def test_allows_local_attestation_only_when_explicit(self):
        public_key = verify_artifact_attestation(
            get_attestation("artifact"),
            ArtifactUploadPolicy(allow_local=True),
        )

        self.assertEqual(len(bytes.fromhex(public_key)), 32)

    def test_rejects_compose_hash_mismatch(self):
        with self.assertRaisesRegex(AttestationVerificationError, "compose hash mismatch"):
            verify_artifact_attestation(
                _tdx_attestation(compose_hash="compose-a"),
                ArtifactUploadPolicy(expected_compose_hash="compose-b"),
            )

    def test_rejects_report_data_key_mismatch(self):
        attestation = _tdx_attestation()
        attestation["report_data"] = "00" * 32

        with self.assertRaisesRegex(AttestationVerificationError, "report data"):
            verify_artifact_attestation(
                attestation,
                ArtifactUploadPolicy(expected_compose_hash="compose-ok"),
            )

    def test_upload_encrypts_after_attestation_gate_passes(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET" and request.url.path == "/attestation":
                self.assertEqual(request.url.params["context"], "artifact")
                return httpx.Response(200, json=_tdx_attestation())
            if request.method == "POST" and request.url.path == "/deal/deal-1/artifact/encrypted":
                payload = request.read().decode()
                self.assertIn("ciphertext", payload)
                self.assertIn(EXPECTED_HASH, payload)
                self.assertNotIn("artifact_hex", payload)
                self.assertNotIn("test-artifact", payload)
                return httpx.Response(
                    200,
                    json={"deal_id": "deal-1", "received": True, "size": len(b"test-artifact")},
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))

        result = upload_artifact_bytes(
            "https://tee.example",
            "deal-1",
            b"test-artifact",
            ArtifactUploadPolicy(expected_compose_hash="compose-ok", expected_app_id="app-ok"),
            client=client,
        )

        self.assertEqual(result.artifact_hash, EXPECTED_HASH)
        self.assertEqual(result.size, len(b"test-artifact"))
        self.assertEqual(result.status_code, 200)
        self.assertEqual([request.url.path for request in requests], [
            "/attestation",
            "/deal/deal-1/artifact/encrypted",
        ])

    def test_upload_does_not_post_when_attestation_fails(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET" and request.url.path == "/attestation":
                self.assertEqual(request.url.params["context"], "artifact")
                return httpx.Response(200, json=_tdx_attestation(compose_hash="bad"))
            return httpx.Response(500, json={"error": "should not post"})

        client = httpx.Client(transport=httpx.MockTransport(handler))

        with self.assertRaisesRegex(AttestationVerificationError, "compose hash mismatch"):
            upload_artifact_bytes(
                "https://tee.example",
                "deal-1",
                b"test-artifact",
                ArtifactUploadPolicy(expected_compose_hash="compose-ok"),
                client=client,
            )

        self.assertEqual([request.url.path for request in requests], ["/attestation"])


if __name__ == "__main__":
    unittest.main()
