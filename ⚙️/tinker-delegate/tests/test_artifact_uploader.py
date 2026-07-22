import hashlib
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import httpx

from tinker_delegate.artifact_uploader import (
    ArtifactUploadAuthenticationError,
    ArtifactUploadPolicy,
    ArtifactUploadResult,
    AttestationVerificationError,
    load_artifact_commitment_receipt,
    upload_artifact_bytes,
    upload_artifact_file,
    verify_artifact_attestation,
)
from tinker_delegate.card_channel import get_attestation


COMMITMENT_SECRET = bytes(range(32))
EXPECTED_HASH = "0x0f5dd8f2c3fba9bcd4d19565c66257757094f11017d8f3fdd264c7b0b5156d80"
ROOM = "0x3333333333333333333333333333333333333333"
EVALUATOR_POLICY = "0x" + "44" * 32


def _upload_policy(**overrides) -> ArtifactUploadPolicy:
    values = {
        "diligence_room_address": ROOM,
        "evaluator_policy_commitment": EVALUATOR_POLICY,
    }
    values.update(overrides)
    return ArtifactUploadPolicy(**values)


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
    def _write_receipt(self, directory: str, **overrides) -> Path:
        payload = {
            "schema_version": 2,
            "scheme": "dnai-wikigen/artifact-commitment/v2",
            "artifact_commitment": EXPECTED_HASH,
            "commitment_secret": f"0x{COMMITMENT_SECRET.hex()}",
        }
        payload.update(overrides)
        path = Path(directory) / "artifact-commitment-receipt.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_loads_exact_v2_private_recovery_receipt(self):
        with TemporaryDirectory() as directory:
            receipt = load_artifact_commitment_receipt(self._write_receipt(directory))

        self.assertEqual(receipt.artifact_hash, EXPECTED_HASH)
        self.assertEqual(receipt.commitment_secret, bytearray(COMMITMENT_SECRET))

    def test_recovery_receipt_rejects_wrong_scheme_extra_fields_and_short_secret(self):
        invalid_cases = (
            {"scheme": "dnai-wikigen/artifact-commitment/v1"},
            {"schema_version": 2.0},
            {"unexpected": "field"},
            {"commitment_secret": "0x1234"},
            {"commitment_secret": f"0x{COMMITMENT_SECRET.hex().upper()}"},
            {"artifact_commitment": EXPECTED_HASH[2:]},
        )
        for overrides in invalid_cases:
            with self.subTest(overrides=overrides), TemporaryDirectory() as directory:
                path = self._write_receipt(directory, **overrides)
                with self.assertRaises(ValueError):
                    load_artifact_commitment_receipt(path)

    def test_upload_rejects_empty_or_receipt_mismatched_artifact_before_network(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(500)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            upload_artifact_bytes(
                "https://tee.example",
                "1",
                b"",
                _upload_policy(),
                artifact_hash=EXPECTED_HASH,
                commitment_secret=COMMITMENT_SECRET,
                wallet_auth_token="seller-wallet-token",
                client=client,
            )
        with self.assertRaisesRegex(ValueError, "does not match"):
            upload_artifact_bytes(
                "https://tee.example",
                "1",
                b"different-artifact",
                _upload_policy(),
                artifact_hash=EXPECTED_HASH,
                commitment_secret=COMMITMENT_SECRET,
                wallet_auth_token="seller-wallet-token",
                client=client,
            )

        self.assertEqual(requests, [])

    def test_upload_requires_wallet_token_before_any_network_request(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(500)

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with self.assertRaises(ArtifactUploadAuthenticationError):
            upload_artifact_bytes(
                "https://tee.example",
                "1",
                b"test-artifact",
                _upload_policy(),
                artifact_hash=EXPECTED_HASH,
                commitment_secret=COMMITMENT_SECRET,
                wallet_auth_token="",
                client=client,
            )
        self.assertEqual(requests, [])

    def test_file_upload_requires_wallet_token_before_private_files_are_opened(self):
        with self.assertRaises(ArtifactUploadAuthenticationError):
            upload_artifact_file(
                "https://tee.example",
                "1",
                "/private/artifact-does-not-need-to-exist",
                "/private/receipt-does-not-need-to-exist",
                _upload_policy(),
                wallet_auth_token="",
            )

    def test_file_upload_zeroes_artifact_and_receipt_secret_after_use(self):
        captured = {}

        def fake_upload(
            _base_url,
            _deal_id,
            artifact,
            _policy,
            *,
            artifact_hash,
            commitment_secret,
            wallet_auth_token,
        ):
            captured["artifact"] = artifact
            captured["commitment_secret"] = commitment_secret
            self.assertEqual(artifact_hash, EXPECTED_HASH)
            self.assertEqual(wallet_auth_token, "seller-wallet-token")
            return ArtifactUploadResult("1", EXPECTED_HASH, "sha256:" + "0" * 64, 200, {})

        with TemporaryDirectory() as directory:
            artifact_path = Path(directory) / "artifact.bin"
            artifact_path.write_bytes(b"test-artifact")
            receipt_path = self._write_receipt(directory)
            with patch(
                "tinker_delegate.artifact_uploader.upload_artifact_bytes",
                side_effect=fake_upload,
            ):
                upload_artifact_file(
                    "https://tee.example",
                    "1",
                    artifact_path,
                    receipt_path,
                    _upload_policy(),
                    wallet_auth_token="seller-wallet-token",
                )

        self.assertEqual(captured["artifact"], bytearray(len(b"test-artifact")))
        self.assertEqual(captured["commitment_secret"], bytearray(len(COMMITMENT_SECRET)))

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
            if request.method == "POST" and request.url.path == "/deal/1/artifact/encrypted":
                self.assertEqual(request.headers["authorization"], "Bearer seller-wallet-token")
                payload = request.read().decode()
                self.assertIn("ciphertext", payload)
                self.assertIn(EXPECTED_HASH, payload)
                self.assertIn("dnai-wikigen/artifact-commitment/v2", payload)
                self.assertNotIn("artifact_hex", payload)
                self.assertNotIn("test-artifact", payload)
                encoded = json.loads(payload)
                return httpx.Response(
                    200,
                    json={
                        "deal_id": "1",
                        "received": True,
                        "ciphertext_sha256": "sha256:" + hashlib.sha256(
                            bytes.fromhex(encoded["ciphertext"])
                        ).hexdigest(),
                        "commitment_scheme": "dnai-wikigen/artifact-commitment/v2",
                        "envelope_scheme": "dnai-wikigen/artifact-envelope/v3",
                        "padding_profile": "fixed_1m_v3",
                        "exact_plaintext_size_egress": False,
                    },
                )
            return httpx.Response(404)

        client = httpx.Client(transport=httpx.MockTransport(handler))

        result = upload_artifact_bytes(
            "https://tee.example",
            "1",
            b"test-artifact",
            _upload_policy(expected_compose_hash="compose-ok", expected_app_id="app-ok"),
            artifact_hash=EXPECTED_HASH,
            commitment_secret=COMMITMENT_SECRET,
            wallet_auth_token="seller-wallet-token",
            client=client,
        )

        self.assertEqual(result.artifact_hash, EXPECTED_HASH)
        self.assertRegex(result.ciphertext_sha256, r"^sha256:[0-9a-f]{64}$")
        self.assertNotIn("size", result.response)
        self.assertEqual(result.response["padding_profile"], "fixed_1m_v3")
        self.assertFalse(result.response["exact_plaintext_size_egress"])
        self.assertEqual(result.status_code, 200)
        self.assertEqual([request.url.path for request in requests], [
            "/attestation",
            "/deal/1/artifact/encrypted",
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
                "1",
                b"test-artifact",
                _upload_policy(expected_compose_hash="compose-ok"),
                artifact_hash=EXPECTED_HASH,
                commitment_secret=COMMITMENT_SECRET,
                wallet_auth_token="seller-wallet-token",
                client=client,
            )

        self.assertEqual([request.url.path for request in requests], ["/attestation"])

    def test_upload_rejects_legacy_exact_size_receipt(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(200, json=_tdx_attestation())
            return httpx.Response(
                200,
                json={
                    "deal_id": "1",
                    "received": True,
                    "size": len(b"test-artifact"),
                    "commitment_scheme": "dnai-wikigen/artifact-commitment/v2",
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        with self.assertRaisesRegex(ValueError, "non-allowlisted artifact upload receipt"):
            upload_artifact_bytes(
                "https://tee.example",
                "1",
                b"test-artifact",
                _upload_policy(
                    expected_compose_hash="compose-ok",
                    expected_app_id="app-ok",
                ),
                artifact_hash=EXPECTED_HASH,
                commitment_secret=COMMITMENT_SECRET,
                wallet_auth_token="seller-wallet-token",
                client=client,
            )


if __name__ == "__main__":
    unittest.main()
