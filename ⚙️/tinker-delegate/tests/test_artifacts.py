import hashlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from fastapi.testclient import TestClient
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError

from tinker_delegate import api
from tinker_delegate.artifacts import (
    ARTIFACT_CIPHERTEXT_BYTES,
    ARTIFACT_COMMITMENT_SCHEME,
    ARTIFACT_ENVELOPE_MAGIC,
    ARTIFACT_ENVELOPE_SCHEME,
    ARTIFACT_FRAME_BYTES,
    ARTIFACT_FRAME_HEADER_BYTES,
    ARTIFACT_PADDING_PROFILE,
    ARTIFACT_RAW_MAX_BYTES,
    BASE_SEPOLIA_CHAIN_ID,
    artifact_commitment,
    artifact_associated_data,
    artifact_hkdf_info,
    decode_artifact_wrapper,
    decode_artifact_hex,
    decrypt_artifact_payload,
    encode_artifact_wrapper,
    encrypt_artifact_payload,
    normalize_artifact_hash,
    verify_artifact_commitment,
    zero_buffer,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import EncryptedPayload, encrypt_for_tee


COMMITMENT_SECRET = bytes(range(32))
OTHER_COMMITMENT_SECRET = bytes(reversed(range(32)))
EXPECTED_TEST_ARTIFACT_HASH = "0x0f5dd8f2c3fba9bcd4d19565c66257757094f11017d8f3fdd264c7b0b5156d80"
SELLER = "0x1111111111111111111111111111111111111111"
ROOM = "0x3333333333333333333333333333333333333333"
EVALUATOR_POLICY = "0x" + "44" * 32
ARTIFACT_CONTEXT = {
    "chain_id": BASE_SEPOLIA_CHAIN_ID,
    "diligence_room_address": ROOM,
    "evaluator_policy_commitment": EVALUATOR_POLICY,
}
STATIC_FRAME_SHA256 = "e7f2c7d6368e30b50140efc2d3cf858d19ea901ec30951bc28ef94fd1248bd5c"
STATIC_HKDF_INFO_SHA256 = "4281a0c2db422d32441993267cd08e2a642646140a4e3f7f345806a41202490f"
STATIC_AAD_SHA256 = "234e48e68de98daf9ea4331505a3542a3f2d48abf597e2dc8f13cd447bc5ea8d"


class ArtifactHelperTest(unittest.TestCase):
    def test_v2_commitment_matches_cross_language_contract_fixture(self):
        self.assertEqual(
            artifact_commitment(b"test-artifact", COMMITMENT_SECRET),
            EXPECTED_TEST_ARTIFACT_HASH,
        )
        self.assertEqual(
            verify_artifact_commitment(
                b"test-artifact",
                COMMITMENT_SECRET,
                EXPECTED_TEST_ARTIFACT_HASH.upper(),
            ),
            EXPECTED_TEST_ARTIFACT_HASH,
        )
        self.assertNotEqual(
            artifact_commitment(b"test-artifact", OTHER_COMMITMENT_SECRET),
            EXPECTED_TEST_ARTIFACT_HASH,
        )

    def test_hash_and_hex_validation_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "between 1 and 1,048,576"):
            artifact_commitment(b"", COMMITMENT_SECRET)
        with self.assertRaisesRegex(ValueError, "between 1 and 1,048,576"):
            artifact_commitment(b"x" * (ARTIFACT_RAW_MAX_BYTES + 1), COMMITMENT_SECRET)
        with self.assertRaisesRegex(ValueError, "32-byte"):
            normalize_artifact_hash("0x1234")
        with self.assertRaisesRegex(ValueError, "exact v3 frame size"):
            decode_artifact_hex("abc")
        with self.assertRaisesRegex(ValueError, "valid hex"):
            decode_artifact_hex("zz" * ARTIFACT_FRAME_BYTES)
        with self.assertRaisesRegex(ValueError, "does not match"):
            verify_artifact_commitment(
                b"other-artifact",
                COMMITMENT_SECRET,
                EXPECTED_TEST_ARTIFACT_HASH,
            )
        with self.assertRaisesRegex(ValueError, "exact v3 size"):
            decode_artifact_wrapper(b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH)

    def test_v3_frame_matches_cross_language_static_vector_and_hides_exact_length(self):
        full = b"Z" * ARTIFACT_RAW_MAX_BYTES
        frame = encode_artifact_wrapper(full, COMMITMENT_SECRET)
        try:
            self.assertEqual(len(frame), ARTIFACT_FRAME_BYTES)
            self.assertEqual(frame[:16], ARTIFACT_ENVELOPE_MAGIC)
            self.assertEqual(int.from_bytes(frame[16:20], "big"), ARTIFACT_RAW_MAX_BYTES)
            self.assertEqual(frame[20:ARTIFACT_FRAME_HEADER_BYTES], COMMITMENT_SECRET)
            self.assertEqual(hashlib.sha256(frame).hexdigest(), STATIC_FRAME_SHA256)
        finally:
            zero_buffer(frame)

        one_byte = encode_artifact_wrapper(b"x", COMMITMENT_SECRET)
        try:
            self.assertEqual(len(one_byte), ARTIFACT_FRAME_BYTES)
            artifact, secret = decode_artifact_wrapper(
                one_byte,
                artifact_commitment(b"x", COMMITMENT_SECRET),
            )
            self.assertEqual(artifact, b"x")
            self.assertEqual(secret, COMMITMENT_SECRET)
            zero_buffer(artifact)
            zero_buffer(secret)
        finally:
            zero_buffer(one_byte)

    def test_zero_buffer_wipes_mutable_bytes_in_place(self):
        payload = bytearray(b"secret-artifact")
        zero_buffer(payload)
        self.assertEqual(payload, bytearray(len(b"secret-artifact")))

    def test_artifact_key_context_is_per_deal_and_hash(self):
        other_hash = "0x" + "11" * 32

        self.assertEqual(
            hashlib.sha256(
                artifact_hkdf_info("42", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT)
            ).hexdigest(),
            STATIC_HKDF_INFO_SHA256,
        )
        self.assertEqual(
            hashlib.sha256(
                artifact_associated_data("42", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT)
            ).hexdigest(),
            STATIC_AAD_SHA256,
        )

        self.assertEqual(
            artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
            artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH.upper(), **ARTIFACT_CONTEXT),
        )
        self.assertNotEqual(
            artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
            artifact_hkdf_info("2", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
        )
        self.assertNotEqual(
            artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
            artifact_hkdf_info("1", other_hash, **ARTIFACT_CONTEXT),
        )
        self.assertNotEqual(
            artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
            artifact_associated_data("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
        )
        for invalid_deal_id in ("", "01", "deal-1"):
            with self.subTest(deal_id=invalid_deal_id), self.assertRaisesRegex(
                ValueError,
                "canonical uint256",
            ):
                artifact_hkdf_info(
                    invalid_deal_id,
                    EXPECTED_TEST_ARTIFACT_HASH,
                    **ARTIFACT_CONTEXT,
                )

    def test_encrypted_artifact_keys_are_deal_bound(self):
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            commitment_secret=COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )
        payload = EncryptedPayload.from_hex(encrypted)

        artifact, secret = decrypt_artifact_payload(
            payload,
            keypair,
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            **ARTIFACT_CONTEXT,
        )
        self.assertEqual(artifact, bytearray(b"test-artifact"))
        self.assertEqual(secret, bytearray(COMMITMENT_SECRET))
        zero_buffer(artifact)
        zero_buffer(secret)
        with self.assertRaises(InvalidTag):
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="2",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                **ARTIFACT_CONTEXT,
            )

    def test_v3_rejects_truncation_tag_tamper_and_context_drift(self):
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            commitment_secret=COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )
        payload = EncryptedPayload.from_hex(encrypted)
        self.assertEqual(len(payload.ciphertext), ARTIFACT_CIPHERTEXT_BYTES)

        truncated = EncryptedPayload(
            payload.ephemeral_public_key,
            payload.nonce,
            payload.ciphertext[:-1],
        )
        with self.assertRaisesRegex(ValueError, "exact v3 size"):
            decrypt_artifact_payload(
                truncated,
                keypair,
                deal_id="1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                **ARTIFACT_CONTEXT,
            )

        tampered_ciphertext = bytearray(payload.ciphertext)
        tampered_ciphertext[-1] ^= 1
        try:
            with self.assertRaises(InvalidTag):
                decrypt_artifact_payload(
                    EncryptedPayload(
                        payload.ephemeral_public_key,
                        payload.nonce,
                        bytes(tampered_ciphertext),
                    ),
                    keypair,
                    deal_id="1",
                    artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                    **ARTIFACT_CONTEXT,
                )
        finally:
            zero_buffer(tampered_ciphertext)

        with self.assertRaises(InvalidTag):
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                **{**ARTIFACT_CONTEXT, "evaluator_policy_commitment": "0x" + "55" * 32},
            )
        with self.assertRaises(InvalidTag):
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                **{**ARTIFACT_CONTEXT, "diligence_room_address": "0x" + "66" * 20},
            )
        with self.assertRaisesRegex(ValueError, "Base Sepolia"):
            decrypt_artifact_payload(
                payload,
                keypair,
                deal_id="1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                **{**ARTIFACT_CONTEXT, "chain_id": 8453},
            )

    def test_v3_rejects_authenticated_wrong_magic_and_private_lengths(self):
        keypair = api.get_tee_keypair()
        valid = encode_artifact_wrapper(b"test-artifact", COMMITMENT_SECRET)
        variants = []
        wrong_magic = bytearray(valid)
        wrong_magic[0] ^= 1
        variants.append((wrong_magic, "magic"))
        zero_length = bytearray(valid)
        zero_length[16:20] = (0).to_bytes(4, "big")
        variants.append((zero_length, "private length"))
        oversize_length = bytearray(valid)
        oversize_length[16:20] = (ARTIFACT_RAW_MAX_BYTES + 1).to_bytes(4, "big")
        variants.append((oversize_length, "private length"))
        try:
            for frame, expected_error in variants:
                with self.subTest(expected_error=expected_error):
                    sealed = encrypt_for_tee(
                        bytes(frame),
                        keypair.public_key_bytes,
                        info=artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
                        associated_data=artifact_associated_data("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
                    )
                    with self.assertRaisesRegex(ValueError, expected_error):
                        decrypt_artifact_payload(
                            sealed,
                            keypair,
                            deal_id="1",
                            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                            **ARTIFACT_CONTEXT,
                        )
        finally:
            zero_buffer(valid)
            for frame, _expected_error in variants:
                zero_buffer(frame)


class ArtifactIngressTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        api.settings = Settings(
            diligence_chain_id=BASE_SEPOLIA_CHAIN_ID,
            diligence_room_address=ROOM,
        )

    def tearDown(self):
        api.settings = self.original_settings

    def test_control_plane_verifies_hash_before_storing_artifact(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        cp._deals = {
            "deal-1": DealContext(
                "deal-1", "buyer", "seller", 100, 10, EXPECTED_TEST_ARTIFACT_HASH
            )
        }

        uploaded = bytearray(b"test-artifact")
        created = cp.receive_artifact(
            "deal-1",
            uploaded,
            EXPECTED_TEST_ARTIFACT_HASH.upper(),
            COMMITMENT_SECRET,
        )

        ctx = cp._deals["deal-1"]
        self.assertTrue(created)
        self.assertEqual(ctx.artifact_hash, EXPECTED_TEST_ARTIFACT_HASH)
        self.assertEqual(ctx.artifact, uploaded)
        self.assertIsInstance(ctx.artifact, bytearray)
        self.assertIsNot(ctx.artifact, uploaded)
        self.assertEqual(ctx.artifact_commitment_secret, bytearray(COMMITMENT_SECRET))

    def test_exact_artifact_replay_is_idempotent_after_state_advance(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext, DealState

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Mock()
        ctx = DealContext(
            "deal-1", "buyer", "seller", 100, 10, EXPECTED_TEST_ARTIFACT_HASH
        )
        cp._deals = {"deal-1": ctx}

        self.assertTrue(
            cp.receive_artifact(
                "deal-1",
                bytearray(b"test-artifact"),
                EXPECTED_TEST_ARTIFACT_HASH,
                COMMITMENT_SECRET,
            )
        )
        stored_artifact = ctx.artifact
        stored_secret = ctx.artifact_commitment_secret
        ctx.state = DealState.EVALUATING

        self.assertFalse(
            cp.receive_artifact(
                "deal-1",
                bytearray(b"test-artifact"),
                EXPECTED_TEST_ARTIFACT_HASH.upper(),
                COMMITMENT_SECRET,
            )
        )
        self.assertIs(ctx.artifact, stored_artifact)
        self.assertIs(ctx.artifact_commitment_secret, stored_secret)
        self.assertEqual(cp._run_metadata_store.append.call_count, 1)

    def test_conflicting_artifact_replays_fail_closed_without_state_update(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Mock()
        ctx = DealContext(
            "deal-1", "buyer", "seller", 100, 10, EXPECTED_TEST_ARTIFACT_HASH
        )
        cp._deals = {"deal-1": ctx}
        cp.receive_artifact(
            "deal-1",
            bytearray(b"test-artifact"),
            EXPECTED_TEST_ARTIFACT_HASH,
            COMMITMENT_SECRET,
        )
        stored_artifact = ctx.artifact
        stored_secret = ctx.artifact_commitment_secret

        conflicts = (
            (b"different-private-artifact", COMMITMENT_SECRET, EXPECTED_TEST_ARTIFACT_HASH),
            (b"test-artifact", OTHER_COMMITMENT_SECRET, EXPECTED_TEST_ARTIFACT_HASH),
            (b"test-artifact", COMMITMENT_SECRET, "0x" + "11" * 32),
        )
        for artifact, secret, submitted_hash in conflicts:
            with self.subTest(
                artifact_length=len(artifact),
                submitted_hash=submitted_hash,
            ), self.assertRaisesRegex(ValueError, "does not match"):
                cp.receive_artifact(
                    "deal-1",
                    artifact,
                    submitted_hash,
                    secret,
                )

        self.assertIs(ctx.artifact, stored_artifact)
        self.assertIs(ctx.artifact_commitment_secret, stored_secret)
        self.assertEqual(cp._run_metadata_store.append.call_count, 1)

    def test_funded_context_commitment_is_write_once_and_replay_idempotent(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext(
            "deal-1",
            "buyer",
            "seller",
            100,
            10,
            EXPECTED_TEST_ARTIFACT_HASH.upper(),
        )
        cp._deals = {"deal-1": ctx}
        cp._authorize_source_use = Mock(side_effect=AssertionError("duplicate created a session"))

        replayed = cp.on_deal_funded(
            "deal-1",
            "buyer",
            "seller",
            100,
            10,
            EXPECTED_TEST_ARTIFACT_HASH,
        )

        self.assertIs(replayed, ctx)
        self.assertEqual(ctx.committed_artifact_hash, EXPECTED_TEST_ARTIFACT_HASH)
        with self.assertRaisesRegex(AttributeError, "immutable"):
            ctx.committed_artifact_hash = "0x" + "11" * 32
        with self.assertRaisesRegex(ValueError, "conflicts"):
            cp.on_deal_funded(
                "deal-1",
                "buyer",
                "seller",
                100,
                10,
                "0x" + "11" * 32,
            )

    def test_control_plane_rejects_hash_mismatch_without_state_update(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext

        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext("deal-1", "buyer", "seller", 100, 10, EXPECTED_TEST_ARTIFACT_HASH)
        cp._deals = {"deal-1": ctx}

        with self.assertRaisesRegex(ValueError, "does not match"):
            cp.receive_artifact(
                "deal-1",
                bytearray(b"wrong"),
                EXPECTED_TEST_ARTIFACT_HASH,
                COMMITMENT_SECRET,
            )

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
        ctx = DealContext("deal-1", "buyer", "seller", 100, 10, EXPECTED_TEST_ARTIFACT_HASH)
        ctx.artifact = bytearray(b"test-artifact")
        ctx.artifact_commitment_secret = bytearray(COMMITMENT_SECRET)
        ctx.artifact_hash = EXPECTED_TEST_ARTIFACT_HASH
        ctx.session = FakeSession()
        cp._deals = {"deal-1": ctx}
        stored = ctx.artifact
        stored_secret = ctx.artifact_commitment_secret

        cp.on_deal_resolved("deal-1")

        self.assertEqual(stored, bytearray(len(b"test-artifact")))
        self.assertIsNone(ctx.artifact)
        self.assertEqual(stored_secret, bytearray(32))
        self.assertIsNone(ctx.artifact_commitment_secret)
        self.assertIs(ctx.cleanup_attestation, cleanup_record)

    def test_plaintext_artifact_endpoint_disabled_by_default(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=False)
        client = TestClient(api.app)
        frame = encode_artifact_wrapper(b"test-artifact", COMMITMENT_SECRET)
        try:
            response = client.post(
                "/deal/1/artifact",
                json={
                    "artifact_hex": frame.hex(),
                    "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                    "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                    "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                    "padding_profile": ARTIFACT_PADDING_PROFILE,
                },
            )
        finally:
            zero_buffer(frame)

        self.assertEqual(response.status_code, 403)
        self.assertIn("Plaintext artifact endpoint is disabled", response.json()["detail"])

    def test_plaintext_artifact_endpoint_requires_non_dstack_local_flag(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)
        client = TestClient(api.app)
        frame = encode_artifact_wrapper(b"test-artifact", COMMITMENT_SECRET)

        try:
            with (
                patch("tinker_delegate.api.is_dstack_enabled", return_value=True),
                patch("tinker_delegate.api._get_control_plane") as get_control_plane,
            ):
                response = client.post(
                    "/deal/1/artifact",
                    json={
                        "artifact_hex": frame.hex(),
                        "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                        "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                        "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                        "padding_profile": ARTIFACT_PADDING_PROFILE,
                    },
                )
        finally:
            zero_buffer(frame)

        self.assertEqual(response.status_code, 403)
        get_control_plane.assert_not_called()

    def test_api_rejects_invalid_artifact_hex_as_bad_request(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)
        client = TestClient(api.app)

        with patch("tinker_delegate.api._get_control_plane") as get_control_plane:
            response = client.post(
                "/deal/1/artifact",
                json={
                    "artifact_hex": "abc",
                    "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                    "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                    "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                    "padding_profile": ARTIFACT_PADDING_PROFILE,
                },
            )

        self.assertEqual(response.status_code, 422)
        get_control_plane.assert_not_called()
        get_control_plane.return_value.receive_artifact.assert_not_called()

    def test_api_zeroes_transient_artifact_buffer_after_control_plane_error(self):
        api.settings = Settings(allow_plaintext_artifact_endpoint=True)

        class RejectingControlPlane:
            seen = None

            def receive_artifact(self, _deal_id, artifact, _artifact_hash, _secret):
                self.seen = artifact
                raise ValueError("artifact_hash does not match uploaded artifact")

        cp = RejectingControlPlane()
        client = TestClient(api.app)

        wrapper = encode_artifact_wrapper(b"test-artifact", COMMITMENT_SECRET)
        try:
            with patch("tinker_delegate.api._get_control_plane", return_value=cp):
                response = client.post(
                    "/deal/1/artifact",
                    json={
                        "artifact_hex": wrapper.hex(),
                        "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                        "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                        "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                        "padding_profile": ARTIFACT_PADDING_PROFILE,
                    },
                )
        finally:
            zero_buffer(wrapper)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(cp.seen, bytearray(len(b"test-artifact")))

    def test_encrypted_api_decrypts_before_hash_checked_ingress(self):
        class AcceptingControlPlane:
            seen = None
            seen_ref = None

            def get_deal_context(self, _deal_id):
                return SimpleNamespace(
                    seller=SELLER,
                    committed_artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                    evaluator_policy_commitment=EVALUATOR_POLICY,
                )

            def receive_artifact(self, _deal_id, artifact, artifact_hash, commitment_secret):
                self.seen = (bytes(artifact), artifact_hash)
                self.seen_ref = artifact
                self.secret_ref = commitment_secret

        cp = AcceptingControlPlane()
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            commitment_secret=COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )

        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
        ):
            response = client.post(
                "/deal/1/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer unit-test-wallet"},
            )

        self.assertEqual(response.status_code, 200)
        receipt = response.json()
        self.assertEqual(
            receipt,
            {
                "deal_id": "1",
                "received": True,
                "ciphertext_sha256": "sha256:" + hashlib.sha256(
                    bytes.fromhex(encrypted["ciphertext"])
                ).hexdigest(),
                "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                "padding_profile": ARTIFACT_PADDING_PROFILE,
                "exact_plaintext_size_egress": False,
            },
        )
        self.assertNotIn("size", receipt)
        self.assertEqual(cp.seen, (b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH))
        self.assertEqual(cp.seen_ref, bytearray(len(b"test-artifact")))
        self.assertEqual(cp.secret_ref, bytearray(32))

    def test_encrypted_api_accepts_fresh_ciphertext_for_exact_artifact_replay(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext, DealState

        cp = ControlPlane.__new__(ControlPlane)
        cp._run_metadata_store = Mock()
        ctx = DealContext(
            "1", "buyer", SELLER, 100, 10, EXPECTED_TEST_ARTIFACT_HASH,
            evaluator_policy_commitment=EVALUATOR_POLICY,
        )
        cp._deals = {"1": ctx}
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted_payloads = [
            encrypt_artifact_payload(
                b"test-artifact",
                keypair.public_key_bytes.hex(),
                deal_id="1",
                artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                commitment_secret=COMMITMENT_SECRET,
                **ARTIFACT_CONTEXT,
            )
            for _ in range(2)
        ]

        responses = []
        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
        ):
            responses.append(
                client.post(
                    "/deal/1/artifact/encrypted",
                    json=encrypted_payloads[0],
                    headers={"Authorization": "Bearer unit-test-wallet"},
                )
            )
            ctx.state = DealState.EVALUATING
            responses.append(
                client.post(
                    "/deal/1/artifact/encrypted",
                    json=encrypted_payloads[1],
                    headers={"Authorization": "Bearer unit-test-wallet"},
                )
            )

        for response, encrypted in zip(responses, encrypted_payloads, strict=True):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(
                response.json(),
                {
                    "deal_id": "1",
                    "received": True,
                    "ciphertext_sha256": "sha256:"
                    + hashlib.sha256(bytes.fromhex(encrypted["ciphertext"])).hexdigest(),
                    "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                    "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                    "padding_profile": ARTIFACT_PADDING_PROFILE,
                    "exact_plaintext_size_egress": False,
                },
            )
        self.assertNotEqual(
            encrypted_payloads[0]["ciphertext"], encrypted_payloads[1]["ciphertext"]
        )
        self.assertEqual(ctx.artifact, bytearray(b"test-artifact"))
        self.assertEqual(ctx.artifact_commitment_secret, bytearray(COMMITMENT_SECRET))
        self.assertEqual(cp._run_metadata_store.append.call_count, 1)

    def test_encrypted_api_rejects_conflicting_decrypted_wrapper(self):
        keypair = api.get_tee_keypair()
        conflicting_wrapper = encode_artifact_wrapper(
            b"test-artifact", OTHER_COMMITMENT_SECRET
        )
        try:
            encrypted = encrypt_for_tee(
                bytes(conflicting_wrapper),
                keypair.public_key_bytes,
                info=artifact_hkdf_info("1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT),
                associated_data=artifact_associated_data(
                    "1", EXPECTED_TEST_ARTIFACT_HASH, **ARTIFACT_CONTEXT
                ),
            ).to_hex()
        finally:
            zero_buffer(conflicting_wrapper)
        encrypted.update(
            {
                "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
                "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
                "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
                "padding_profile": ARTIFACT_PADDING_PROFILE,
            }
        )
        cp = SimpleNamespace()
        cp.get_deal_context = lambda _deal_id: SimpleNamespace(
            seller=SELLER,
            committed_artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            evaluator_policy_commitment=EVALUATOR_POLICY,
        )
        cp.receive_artifact = Mock()

        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
        ):
            response = TestClient(api.app).post(
                "/deal/1/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer unit-test-wallet"},
            )

        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("does not match uploaded artifact", response.json()["detail"])
        cp.receive_artifact.assert_not_called()

    def test_valid_seller_cannot_upload_self_consistent_artifact_b_for_committed_a(self):
        """The chain commitment is checked before any attacker-chosen decrypt."""
        artifact_b = b"different-private-artifact"
        commitment_b = artifact_commitment(artifact_b, OTHER_COMMITMENT_SECRET)
        encrypted_b = encrypt_artifact_payload(
            artifact_b,
            api.get_tee_keypair().public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=commitment_b,
            commitment_secret=OTHER_COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )

        cp = SimpleNamespace()
        cp.get_deal_context = lambda _deal_id: SimpleNamespace(
            seller=SELLER,
            committed_artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            evaluator_policy_commitment=EVALUATOR_POLICY,
        )
        cp.receive_artifact = Mock()
        client = TestClient(api.app)
        with (
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
            patch(
                "tinker_delegate.api.decrypt_artifact_payload",
                side_effect=AssertionError("commitment mismatch must reject before decrypt"),
            ) as decrypt,
        ):
            response = client.post(
                "/deal/1/artifact/encrypted",
                json=encrypted_b,
                headers={"Authorization": "Bearer valid-seller-wallet-token"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("on-chain deal", response.json()["detail"])
        decrypt.assert_not_called()
        cp.receive_artifact.assert_not_called()

    def test_encrypted_api_rejects_deal_id_tampering_before_control_plane(self):
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            commitment_secret=COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )

        with (
            patch("tinker_delegate.api._get_control_plane") as get_control_plane,
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
        ):
            get_control_plane.return_value.get_deal_context.return_value = SimpleNamespace(
                seller=SELLER,
                committed_artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                evaluator_policy_commitment=EVALUATOR_POLICY,
            )
            response = client.post(
                "/deal/2/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer unit-test-wallet"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertIn("could not be decrypted or verified", response.json()["detail"])
        get_control_plane.return_value.receive_artifact.assert_not_called()

    def test_encrypted_api_does_not_write_raw_artifact_to_disk(self):
        class AcceptingControlPlane:
            def get_deal_context(self, _deal_id):
                return SimpleNamespace(
                    seller=SELLER,
                    committed_artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
                    evaluator_policy_commitment=EVALUATOR_POLICY,
                )

            def receive_artifact(self, _deal_id, artifact, artifact_hash, _secret):
                self.seen = (bytes(artifact), artifact_hash)

        cp = AcceptingControlPlane()
        client = TestClient(api.app)
        keypair = api.get_tee_keypair()
        encrypted = encrypt_artifact_payload(
            b"test-artifact",
            keypair.public_key_bytes.hex(),
            deal_id="1",
            artifact_hash=EXPECTED_TEST_ARTIFACT_HASH,
            commitment_secret=COMMITMENT_SECRET,
            **ARTIFACT_CONTEXT,
        )

        with (
            patch("builtins.open", side_effect=AssertionError("raw artifact disk open")),
            patch("pathlib.Path.open", side_effect=AssertionError("raw artifact path open")),
            patch("pathlib.Path.write_bytes", side_effect=AssertionError("raw artifact write_bytes")),
            patch("pathlib.Path.write_text", side_effect=AssertionError("raw artifact write_text")),
            patch("tinker_delegate.api._get_control_plane", return_value=cp),
            patch(
                "tinker_delegate.api._require_wallet_auth",
                return_value=SimpleNamespace(address=SELLER),
            ),
        ):
            response = client.post(
                "/deal/1/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer unit-test-wallet"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(cp.seen, (b"test-artifact", EXPECTED_TEST_ARTIFACT_HASH))

    def test_encrypted_api_rejects_nonexact_ciphertext_before_hex_decode(self):
        encrypted = {
            "ephemeral_public_key": "11" * 32,
            "nonce": "22" * 12,
            "ciphertext": "33" * (ARTIFACT_CIPHERTEXT_BYTES + 1),
            "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
            "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
            "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
            "padding_profile": ARTIFACT_PADDING_PROFILE,
        }
        with patch(
            "tinker_delegate.api.EncryptedPayload.from_hex",
            side_effect=AssertionError("oversize ciphertext must reject before decode"),
        ) as decode:
            response = TestClient(api.app).post(
                "/deal/1/artifact/encrypted",
                json=encrypted,
                headers={"Authorization": "Bearer unit-test-wallet"},
            )
        self.assertEqual(response.status_code, 422)
        decode.assert_not_called()

    def test_encrypted_wire_hex_is_lowercase_canonical(self):
        valid = {
            "ephemeral_public_key": "ab" * 32,
            "nonce": "cd" * 12,
            "ciphertext": "ef" * ARTIFACT_CIPHERTEXT_BYTES,
            "artifact_hash": EXPECTED_TEST_ARTIFACT_HASH,
            "commitment_scheme": ARTIFACT_COMMITMENT_SCHEME,
            "envelope_scheme": ARTIFACT_ENVELOPE_SCHEME,
            "padding_profile": ARTIFACT_PADDING_PROFILE,
        }
        self.assertEqual(api.EncryptedArtifactUpload(**valid).padding_profile, ARTIFACT_PADDING_PROFILE)
        for field in ("ephemeral_public_key", "nonce", "ciphertext", "artifact_hash"):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                api.EncryptedArtifactUpload(**{**valid, field: valid[field].upper()})

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
        ctx = DealContext(
            "deal-1",
            "buyer",
            "seller",
            100,
            10,
            EXPECTED_TEST_ARTIFACT_HASH,
            session=Session(),
        )
        ctx.artifact = bytearray(b"test-artifact")
        ctx.artifact_commitment_secret = bytearray(COMMITMENT_SECRET)
        ctx.artifact_hash = EXPECTED_TEST_ARTIFACT_HASH
        cp._deals = {"deal-1": ctx}

        async def run():
            with (
                patch("builtins.open", side_effect=AssertionError("raw artifact disk open")),
                patch("pathlib.Path.open", side_effect=AssertionError("raw artifact path open")),
                patch("pathlib.Path.write_bytes", side_effect=AssertionError("raw artifact write_bytes")),
                patch("pathlib.Path.write_text", side_effect=AssertionError("raw artifact write_text")),
                patch.object(cp, "_get_tdx_quote", return_value=b"test-only-attestation"),
            ):
                return await cp.evaluate("deal-1", evaluator)

        import asyncio

        result = asyncio.run(run())

        self.assertEqual(result.quality_delta, "5-10% quality-improvement band")
        self.assertEqual(result.confidence, "withheld")
        self.assertEqual(result.methodology_summary, "private_evaluator_details_withheld")
        evaluator.assert_awaited_once()
        self.assertEqual(evaluator.await_args.kwargs["artifact"], b"test-artifact")

    def test_control_plane_rejects_in_memory_artifact_mutation_before_evaluator(self):
        sys.modules.setdefault("tinker", types.SimpleNamespace())
        from tinker_delegate.control_plane import ControlPlane, DealContext, DealState

        evaluator = AsyncMock()
        cp = ControlPlane.__new__(ControlPlane)
        ctx = DealContext(
            "deal-1",
            "buyer",
            "seller",
            100,
            10,
            EXPECTED_TEST_ARTIFACT_HASH,
            session=SimpleNamespace(),
        )
        ctx.artifact = bytearray(b"test-artifact")
        ctx.artifact_commitment_secret = bytearray(COMMITMENT_SECRET)
        ctx.artifact_hash = EXPECTED_TEST_ARTIFACT_HASH
        stored_artifact = ctx.artifact
        stored_secret = ctx.artifact_commitment_secret
        ctx.artifact[0] ^= 1
        cp._deals = {"deal-1": ctx}

        import asyncio

        with self.assertRaisesRegex(ValueError, "does not match"):
            asyncio.run(cp.evaluate("deal-1", evaluator))

        evaluator.assert_not_awaited()
        self.assertEqual(ctx.state, DealState.RESOLVED)
        self.assertIsNone(ctx.artifact)
        self.assertIsNone(ctx.artifact_commitment_secret)
        self.assertEqual(stored_artifact, bytearray(len(b"test-artifact")))
        self.assertEqual(stored_secret, bytearray(len(COMMITMENT_SECRET)))


if __name__ == "__main__":
    unittest.main()
