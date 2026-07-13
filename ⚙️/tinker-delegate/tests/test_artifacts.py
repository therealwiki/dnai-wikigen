import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient
from cryptography.exceptions import InvalidTag

from tinker_delegate import api
from tinker_delegate.artifacts import (
    artifact_associated_data,
    artifact_hkdf_info,
    artifact_keccak256,
    decode_artifact_hex,
    decrypt_artifact_payload,
    encrypt_artifact_payload,
    normalize_artifact_hash,
    verify_artifact_hash,
    zero_buffer,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import EncryptedPayload


EXPECTED_TEST_ARTIFACT_HASH = (
    "0xc90746b1d4e44c6f2bb662d9bef9e40ab48fdd812b8ac8fee2fc87e0a3517da8"
)


class ArtifactHelperTest(unittest.TestCase):
    def test_keccak256_matches_contract_hash_shape(self):
        self.assertEqual(artifact_keccak256(b"test-artifact"), EXPECTED_TEST_ARTIFACT_HASH)
        self.assertEqual(
            verify_artifact_hash(b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH.upper()),
            EXPECTED_TEST_ARTIFACT_HASH,
        )

    def test_hash_and_hex_validation_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "32-byte"):
            normalize_artifact_hash("0x1234")
        with self.assertRaisesRegex(ValueError, "even number"):
            decode_artifact_hex("abc")
        with self.assertRaisesRegex(ValueError, "valid hex"):
            decode_artifact_hex("zz")
        with self.assertRaisesRegex(ValueError, "does not match"):
            verify_artifact_hash(b"other-artifact", EXPECTED_TEST_ARTIFACT_HASH)

    def test_zero_buffer_wipes_mutable_bytes_in_place(self):
        payload = bytearray(b"secret-artifact")
        zero_buffer(payload)
        self.assertEqual(payload, bytearray(len(b"secret-artifact")))

    def test_artifact_key_context_is_per_deal_and_hash(self):
        other_hash = "0x" + "11" * 32

        self.assertEqual(
            artifact_hkdf_info("deal-1", EXPECTED_TEST_ARTIFACT_HASH),
            artifact_hkdf_info("deal-1", EXPECTED_TEST_ARTIFACT_HASH.upper()),
        )
        self.assertNotEqual(
            artifact_hkdf_info("deal-1", EXPECTED_TEST_ARTIFACT_HASH),
            artifact_hkdf_info("deal-2", EXPECTED_TEST_ARTIFACT_HASH),
        )
        self.assertNotEqual(
            artifact_hkdf_info("deal-1", EXPECTED_TEST_ARTIFACT_HASH),
            artifact_hkdf_info("deal-1", other_hash),
        )
        self.assertNotEqual(
            artifact_hkdf_info("deal-1", EXPECTED_TEST_ARTIFACT_HASH),
            artifact_associated_data("deal-1", EXPECTED_TEST_ARTIFACT_HASH),
        )

    def test_encrypted_artifact_keys_are_deal_bound(self):
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="deal-1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
        )
        payload = EncryptedPayload.from_hex(encrypted)

        self.assertEqual(
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="deal-1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            ),
            bytearray(b"test-artifact"),
        )
        with self.assertRaises(InvalidTag):
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="deal-2",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            )


class ArtifactIngressTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings

    def tearDown(self):
        api.settings = self.original_settings

    def test_control_plane_verifies_hash_before_storing_artifact(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        cp._deals = {"deal-1": DealContext("deal-1", "buyer", "seller", 100, 10)}

        uploaded = bytearray(b"test-artifact")
        cp.receive_artifact("deal-1", uploaded, EXPECTED_TEST_ARTIFACT_HASH.upper())

        ctx = cp._deals["deal-1"]
        self.assertEqual(ctx.artifact_hash, EXPECTED_TEST_ARTIFACT_HASH)
        self.assertEqual(ctx.artifact, uploaded)
        self.assertIsInstance(ctx.artifact, bytearray)
        self.assertIsNot(ctx.artifact, uploaded)

    def test_control_plane_rejects_hash_mismatch_without_state_update(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext("deal-1", "buyer", "seller", 100, 10)
        cp._deals = {"deal-1": ctx}

        with self.assertRaisesRegex(ValueError, "does not match"):
            cp.receive_artifact("deal-1", bytearray(b"wrong"), EXPECTED_TEST_ARTIFACT_HASH)

        self.assertIsNone(ctx.artifact)
        self.assertEqual(ctx.artifact_hash, "")

    def test_control_plane_zeroes_stored_artifact_on_resolution(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cleanup_record = object()

        class FakeSession:
            def cleanup(self):
                return cleanup_record

        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext("deal-1", "buyer", "seller", 100, 10)
        ctx.artifact = bytearray(b"test-artifact")
        ctx.session = FakeSession()
        cp._deals = {"deal-1": ctx}
        stored = ctx.artifact

        cp.on_deal_resolved("deal-1")

        self.assertEqual(stored, bytearray(len(b"test-artifact")))
        self.assertIsNone(ctx.artifact)
        self.assertIs(ctx.cleanup_attestation, cleanup_record)

    def test_plaintext_artifact_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=False)
        client = TestClient(api.app)

        response = client.post(
            "/deal/deal-1/artifact",
            json={
                "artifact_hex": b"test-artifact".hex(),
                "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("Plaintext artifact endpoint is disabled", response.json()["detail"])

    def test_plaintext_artifact_endpoint_requires_non_dstack_local_flag(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)
        client = TestClient(api.app)

        with (
            patch("tinker_delegate.api.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.api._get_control_plane") as get_control_plane,
        ):
            response = client.post(
                "/deal/deal-1/artifact",
                json={
                    "artifact_hex": b"test-artifact".hex(),
                    "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                },
            )

        self.assertEqual(response.status_code, 403)
        get_control_plane.assert_not_called()

    def test_api_rejects_invalid_artifact_hex_as_bad_request(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)
        client = TestClient(api.app)

        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            response = client.post(
                "/deal/deal-1/artifact",
                json={"artifact_hex": "abc", "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH},
            )

        self.assertEqual(response.status_code, 400)
        get_control_plane.assert_not_called()
        get_control_plane.return_value.receive_artifact.assert_not_called()

    def test_api_zeroes_transient_artifact_buffer_after_control_plane_error(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)

        class RejectingControlPlane:
            seen = None

            def receive_artifact(self, _deal_id, artifact, _artifact_hash):
                self.seen = artifact
                raise ValueError("artifact_hash does not match uploaded artifact")

        cp = RejectingControlPlane()
        client = TestClient(api.app)

        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            response = client.post(
                "/deal/deal-1/artifact",
                json={
                    "artifact_hex": b"test-artifact".hex(),
                    "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                },
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(cp.seen, bytearray(len(b"test-artifact")))

    def test_encrypted_api_decrypts_before_hash_checked_ingress(self):
        class AcceptingControlPlane:
            seen = None
            seen_ref = None

            def receive_artifact(self, _deal_id, artifact, artifact_hash):
                self.seen = (bytes(artifact), artifact_hash)
                self.seen_ref = artifact

        cp = AcceptingControlPlane()
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="deal-1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
        )

        with patch("tinker_delegate.api._get_control_plane", return_value=cp):
            response = client.post("/deal/deal-1/artifact/encrypted", json=encrypted)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["size"], len(b"test-artifact"))
        self.assertEqual(cp.seen, (b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH))
        self.assertEqual(cp.seen_ref, bytearray(len(b"test-artifact")))

    def test_encrypted_api_rejects_deal_id_tampering_before_control_plane(self):
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="deal-1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
        )

        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            response = client.post("/deal/deal-2/artifact/encrypted", json=encrypted)

        self.assertEqual(response.status_code, 400)
        self.assertIn("could not be decrypted or verified", response.json()["detail"])
        get_control_plane.assert_not_called()

    def test_encrypted_api_does_not_write_raw_artifact_to_disk(self):
        class AcceptingControlPlane:
            def receive_artifact(self, _deal_id, artifact, artifact_hash):
                self.seen = (bytes(artifact), artifact_hash)

        cp = AcceptingControlPlane()
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="deal-1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
        )

        with (
            patch("builtins.open", side_effect=AssertionError("raw artifact disk open")),
            patch("pathlib.Path.open", side_effect=AssertionError("raw artifact path open")),
            patch("pathlib.Path.write_bytes", side_effect=AssertionError("raw artifact write_bytes")),
            patch("pathlib.Path.write_text", side_effect=AssertionError("raw artifact write_text")),
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
        ):
            response = client.post("/deal/deal-1/artifact/encrypted", json=encrypted)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(cp.seen, (b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH))

    def test_control_plane_evaluation_does_not_write_raw_artifact_to_disk(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        class Session:
            compute_cost_wei = 0
            fee_wei = 0

            def cleanup(self):
                pass

        evaluator = AsyncMock(
            return_value={
                "quality_delta": 0.05,
                "benchmark": "unit",
                "confidence": "high",
                "methodology": "bounded",
            }
        )
        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext("deal-1", "buyer", "seller", 100, 10, session=Session())
        ctx.artifact = bytearray(b"test-artifact")
        cp._deals = {"deal-1": ctx}

        async def run():
            with (
                patch("builtins.open", side_effect=AssertionError("raw artifact disk open")),
                patch("pathlib.Path.open", side_effect=AssertionError("raw artifact path open")),
                patch("pathlib.Path.write_bytes", side_effect=AssertionError("raw artifact write_bytes")),
                patch("pathlib.Path.write_text", side_effect=AssertionError("raw artifact write_text")),
            ):
                return await cp.evaluate("deal-1", evaluator)

        import asyncio

        result = asyncio.run(run())

        self.assertEqual(result.quality_delta, "+5-10% on unit")
        evaluator.assert_awaited_once()
        self.assertEqual(evaluator.await_args.kwargs["artifact"], b"test-artifact")


if __name__ == "__main__":
    unittest.main()
