import base64
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate.arena_ingress import (
    AES_GCM_NONCE_BYTES,
    GCM_TAG_BYTES,
    INGRESS_ALGORITHM,
    INGRESS_ENCODING,
    INGRESS_HKDF_INFO,
    INGRESS_SCHEMA_VERSION,
    MAX_CIPHERTEXT_BYTES,
    MAX_SOURCE_BYTES,
    ArenaCandidateBinding,
    ArenaCandidateEnvelope,
    ArenaCandidateIngressService,
    ArenaCandidateIngressStore,
    ArenaIngressConflict,
    ArenaIngressCorruptError,
    ArenaIngressErasureRetryable,
    ArenaIngressError,
    ArenaIngressUnavailable,
    arena_attestation_report_data,
    arena_candidate_aad,
    arena_ingress_key_id,
    arena_idempotency_key_hash,
    arena_submission_manifest_hash,
    build_arena_candidate_binding,
    build_arena_candidate_ingress,
    resolve_arena_keypair,
    resolve_arena_recipient,
)
from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    ChallengeManifest,
    SubmissionIdentity,
    SubmissionManifest,
    SubmissionMode,
    default_challenge_catalog,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.ladder_release import LadderPolicy


WALLET = "0x" + "ab" * 20
PROJECT = "personal-" + "cd" * 16
FIXED_RECIPIENT_PRIVATE = bytes(range(1, 33))
FIXED_EPHEMERAL_PRIVATE = bytes(range(33, 65))
FIXED_NONCE = bytes(range(AES_GCM_NONCE_BYTES))
VECTOR_SOURCE = (
    b"def process(positive_wells, negative_wells):\n"
    b"    return positive_wells, negative_wells\n"
)
REGISTRY_AUTHORIZATION_SHA256 = "sha256:" + "ee" * 32

# Filled with byte-exact values from the fixed key/nonce/manifest vector. These
# constants are intentionally not recomputed from themselves: changing any
# canonicalization, report-data formula, HKDF parameter, or AES-GCM binding must
# require an explicit protocol-version change and frontend update.
EXPECTED_RECIPIENT_PUBLIC_HEX = (
    "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
)
EXPECTED_KEY_ID = (
    "sha256:aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041"
)
EXPECTED_REPORT_DATA_HEX = (
    "547f9dc53ff63308863384e30462af2f5a7fec064f21d41309c9a50cd913654c"
)
EXPECTED_MANIFEST_HASH = (
    "sha256:4da59dff0de75fb89aae4ec73fe28e06abae4370f0b9aa58a1b2266e2cf57b0c"
)
EXPECTED_AAD_UTF8 = (
    b'{"attestation_report_data_sha256":"sha256:'
    b'4be27ebd9f45b86d00689cb48249afabaa8e0c20e6441052b90f32fe8faf8263",'
    b'"candidate_commitment":"sha256:'
    b'6a6176d27189b7397583025ebc8cea88c93956d09073995be5dcdbfb1f081162",'
    b'"challenge_id":"synthetic-bio-assay-qc",'
    b'"challenge_manifest_hash":'
    b'"d381d2c9bbaad6ed756f0083d2a6004f76990d351754e492f96fa7c7f2d17345",'
    b'"challenge_version":"1.0.0","context":"arena_candidate_ingress",'
    b'"idempotency_key_hash":"sha256:'
    b'7a57ba69f49f62a10aeb2b6cdebd0da66d2bda435744834c39415eaefc9d0856",'
    b'"identity":{"project_id_hash":'
    b'"0b84b7e2e9845831a7d6e22e73d203234e6e3169518e14c74bbd5f52dd126e02",'
    b'"wallet_address_hash":'
    b'"7c881fa2a5c15b14c4c72f50881110d574b578390ae7cc57e4d9b8f9215e3c51"},'
    b'"key_id":"sha256:'
    b'aaa8fff703b50b2297f4f6e13508f72420d96fd01ebb84cb074449caaef64041",'
    b'"registry_authorization_sha256":"sha256:'
    b'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",'
    b'"schema_version":1,"service":"dnai-wikigen",'
    b'"submission_manifest_hash":"sha256:'
    b'4da59dff0de75fb89aae4ec73fe28e06abae4370f0b9aa58a1b2266e2cf57b0c"}'
)
EXPECTED_AAD_SHA256 = (
    "fd9d0cda126ef79d36d491bc4ff4088b37b86fff63b29655a337403d1da75a92"
)
EXPECTED_CIPHERTEXT_B64URL = (
    "jkk46xPX0_Vgxkw5XQ5UKHHj0eWhSzGlL5p7fQCXY_YjT50nmAZAtu_78LCPEdc3G"
    "O8zFdK4cQaHhCjBv3yKgPzUAf7yTSWYmDGJW2kxjrLi4ydowUIywFKICAPfupsIAC"
    "Lc90gqTw"
)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * ((-len(value)) % 4)))


def _recipient(private_bytes: bytes = FIXED_RECIPIENT_PRIVATE):
    return resolve_arena_recipient(private_key_override=private_bytes)


def _challenge() -> ChallengeManifest:
    return default_challenge_catalog().get(BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION)


def _manifest(
    *,
    challenge: ChallengeManifest | None = None,
    source_bytes: int = len(VECTOR_SOURCE),
    mode: SubmissionMode = SubmissionMode.LEADERBOARD,
) -> SubmissionManifest:
    selected = challenge or _challenge()
    return SubmissionManifest(
        schema_version=1,
        challenge_manifest_hash=selected.manifest_hash,
        candidate_kind=selected.candidate_kind,
        runtime=selected.runtime,
        entrypoint=selected.entrypoint,
        source_bytes=source_bytes,
        mode=mode,
    )


def _commitment(source: bytes) -> str:
    return "sha256:" + hashlib.sha256(source).hexdigest()


def _binding(
    source: bytes,
    recipient,
    *,
    challenge: ChallengeManifest | None = None,
    manifest: SubmissionManifest | None = None,
    identity: SubmissionIdentity | None = None,
    idempotency_key: str = "candidate-vector-1",
) -> ArenaCandidateBinding:
    selected = challenge or _challenge()
    candidate_manifest = manifest or _manifest(
        challenge=selected, source_bytes=len(source)
    )
    return build_arena_candidate_binding(
        challenge=selected,
        identity=identity or SubmissionIdentity(WALLET, PROJECT),
        candidate_commitment=_commitment(source),
        manifest=candidate_manifest,
        recipient=recipient,
        idempotency_key=idempotency_key,
        registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
    )


def _encrypt_envelope(
    source: bytes,
    recipient,
    *,
    challenge: ChallengeManifest | None = None,
    manifest: SubmissionManifest | None = None,
    ephemeral_private_bytes: bytes | None = None,
    nonce: bytes | None = None,
    aad_override: bytes | None = None,
    key_id: str | None = None,
    report_data: str | None = None,
    identity: SubmissionIdentity | None = None,
    idempotency_key: str = "candidate-vector-1",
    binding_override: ArenaCandidateBinding | None = None,
) -> tuple[dict, ArenaCandidateBinding]:
    binding = binding_override or _binding(
        source,
        recipient,
        challenge=challenge,
        manifest=manifest,
        identity=identity,
        idempotency_key=idempotency_key,
    )
    aad = aad_override if aad_override is not None else arena_candidate_aad(binding)
    ephemeral_private = X25519PrivateKey.from_private_bytes(
        ephemeral_private_bytes or FIXED_EPHEMERAL_PRIVATE
    )
    ephemeral_public = ephemeral_private.public_key().public_bytes_raw()
    shared_secret = ephemeral_private.exchange(
        X25519PublicKey.from_public_bytes(recipient.public_key)
    )
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=INGRESS_HKDF_INFO,
    ).derive(shared_secret)
    selected_nonce = nonce or FIXED_NONCE
    ciphertext = AESGCM(aes_key).encrypt(selected_nonce, source, aad)
    return (
        {
            "schema_version": INGRESS_SCHEMA_VERSION,
            "algorithm": INGRESS_ALGORITHM,
            "encoding": INGRESS_ENCODING,
            "key_id": key_id or recipient.key_id,
            "attestation_report_data": report_data or recipient.report_data.hex(),
            "aad": _b64url(aad),
            "ephemeral_public_key": _b64url(ephemeral_public),
            "nonce": _b64url(selected_nonce),
            "ciphertext": _b64url(ciphertext),
        },
        binding,
    )


def _decrypt_stored(record, recipient) -> bytes:
    envelope = record.envelope
    ephemeral_public = X25519PublicKey.from_public_bytes(
        _unb64url(envelope.ephemeral_public_key)
    )
    shared_secret = recipient.keypair._private.exchange(ephemeral_public)
    aad = arena_candidate_aad(record.binding)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(aad).digest(),
        info=INGRESS_HKDF_INFO,
    ).derive(shared_secret)
    return AESGCM(aes_key).decrypt(
        _unb64url(envelope.nonce),
        _unb64url(envelope.ciphertext),
        aad,
    )


def _large_challenge(max_source_bytes: int = MAX_SOURCE_BYTES) -> ChallengeManifest:
    return ChallengeManifest(
        challenge_id="synthetic-max-ingress",
        version="1.0.0",
        slug="synthetic-max-ingress-v1",
        title="Synthetic maximum ingress",
        summary="Synthetic-only ingress boundary test.",
        environment="synthetic_max_ingress",
        candidate_kind="opaque_candidate_bytes",
        runtime="wasm-test",
        entrypoint="run",
        max_source_bytes=max_source_bytes,
        metric="bounded_test_metric",
        ladder_policy=LadderPolicy(step_denominator=20, max_submissions=32),
    )


class ArenaIngressKeyTest(unittest.TestCase):
    def test_local_key_is_restart_stable_distinct_and_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key_file = root / "keys" / "arena.key"
            settings = Settings(
                arena_store_path=str(root / "arena.json"),
                arena_candidate_ingress_local_key_file=str(key_file),
            )
            with patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=False,
            ):
                first = resolve_arena_keypair(settings, root_path=root)
                second = resolve_arena_keypair(settings, root_path=root)

            self.assertEqual(first.public_key_bytes, second.public_key_bytes)
            self.assertEqual(os.stat(key_file).st_mode & 0o777, 0o600)
            self.assertEqual(key_file.stat().st_size, 32)
            self.assertNotEqual(
                first.public_key_bytes,
                TEEKeyPair().public_key_bytes,
                "Arena must not alias a boot-random card/ingress key",
            )
            os.chmod(key_file, 0o644)
            with patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=False,
            ):
                with self.assertRaises(ArenaIngressUnavailable):
                    resolve_arena_keypair(settings, root_path=root)

    def test_dstack_uses_distinct_path_and_rejects_local_material(self):
        settings = Settings(
            arena_candidate_ingress_key_path="tinker/arena_candidate_ingress_test"
        )
        derived = bytes(range(32))
        with (
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.derive_storage_key",
                return_value=derived,
            ) as derive,
        ):
            resolved = resolve_arena_keypair(settings)
        derive.assert_called_once_with("tinker/arena_candidate_ingress_test")
        self.assertEqual(
            resolved.public_key_bytes,
            TEEKeyPair.from_private_key_hex(derived.hex()).public_key_bytes,
        )

        local_settings = Settings(
            arena_candidate_ingress_private_key_hex="11" * 32,
            arena_candidate_ingress_local_key_file="/must/not/be/read",
        )
        with (
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.derive_storage_key",
                return_value=derived,
            ),
        ):
            ignored_local = resolve_arena_keypair(local_settings)
        self.assertEqual(ignored_local.public_key_bytes, resolved.public_key_bytes)

        for reused_path in (
            "tinker/wallet_auth",
            "tinker/arena_wallet_auth",
            "tinker/../arena_candidate_ingress",
        ):
            with self.subTest(reused_path=reused_path):
                settings = Settings(
                    arena_candidate_ingress_key_path=reused_path
                )
                with patch(
                    "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                    return_value=True,
                ):
                    with self.assertRaises(ArenaIngressUnavailable):
                        resolve_arena_keypair(settings)

    def test_attestation_binding_is_stable_and_never_self_claims_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(
                arena_store_path=str(Path(directory) / "arena.json"),
                arena_candidate_ingress_private_key_hex="22" * 32,
            )
            with patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=False,
            ):
                from tinker_delegate.arena_ingress import get_arena_ingress_attestation

                attestation = get_arena_ingress_attestation(
                    settings, root_path=directory
                )
            self.assertEqual(attestation["report_context"], "arena")
            self.assertEqual(
                attestation["key_id"],
                arena_ingress_key_id(bytes.fromhex(attestation["encryption_public_key"])),
            )
            self.assertEqual(
                attestation["report_data"],
                arena_attestation_report_data(
                    bytes.fromhex(attestation["encryption_public_key"])
                ).hex(),
            )
            self.assertFalse(attestation["verified"])

    def test_simulator_arena_attestation_is_not_labeled_tdx(self):
        recipient = _recipient()
        details = {
            "quote": "modeled-quote",
            "quote_report_data": recipient.report_data.hex(),
            "app_id": "sim-app",
            "compose_hash": "sim-compose",
            "os_image_hash": "sim-os",
        }
        with (
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.is_dstack_simulator",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_ingress.dstack_utils.get_attestation_details",
                return_value=details,
            ),
        ):
            from tinker_delegate.arena_ingress import get_arena_ingress_attestation

            attestation = get_arena_ingress_attestation(recipient=recipient)

        self.assertEqual(attestation["mode"], "simulator")
        self.assertFalse(attestation["verified"])


class ArenaIngressInteropVectorTest(unittest.TestCase):
    def test_public_manifest_hash_does_not_commit_exact_private_size(self):
        small = _manifest(source_bytes=1)
        large = _manifest(source_bytes=8_192)

        self.assertEqual(
            arena_submission_manifest_hash(small),
            arena_submission_manifest_hash(large),
        )
        self.assertNotIn("source_bytes", small.to_public_dict())
        self.assertFalse(small.to_public_dict()["private_size_egress"])
        self.assertNotEqual(small.to_persisted_dict(), large.to_persisted_dict())

    def test_fixed_browser_interoperability_vector_is_byte_exact(self):
        recipient = _recipient()
        manifest = _manifest(source_bytes=len(VECTOR_SOURCE))
        envelope, binding = _encrypt_envelope(
            VECTOR_SOURCE,
            recipient,
            manifest=manifest,
            ephemeral_private_bytes=FIXED_EPHEMERAL_PRIVATE,
            nonce=FIXED_NONCE,
        )
        aad = arena_candidate_aad(binding)

        self.assertEqual(recipient.public_key.hex(), EXPECTED_RECIPIENT_PUBLIC_HEX)
        self.assertEqual(recipient.key_id, EXPECTED_KEY_ID)
        self.assertEqual(recipient.report_data.hex(), EXPECTED_REPORT_DATA_HEX)
        self.assertEqual(
            arena_submission_manifest_hash(manifest), EXPECTED_MANIFEST_HASH
        )
        self.assertEqual(aad, EXPECTED_AAD_UTF8)
        self.assertEqual(hashlib.sha256(aad).hexdigest(), EXPECTED_AAD_SHA256)
        self.assertEqual(envelope["ciphertext"], EXPECTED_CIPHERTEXT_B64URL)
        self.assertEqual(len(_unb64url(envelope["ciphertext"])), len(VECTOR_SOURCE) + 16)


class ArenaIngressServiceTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.ingress_root = self.root / "candidate-ingress"
        self.recipient = _recipient()
        self.store = ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        self.service = ArenaCandidateIngressService(self.store, self.recipient)
        self.identity = SubmissionIdentity(WALLET, PROJECT)

    def tearDown(self):
        self.tempdir.cleanup()

    def _ingest(
        self,
        source: bytes = VECTOR_SOURCE,
        *,
        idempotency_key: str = "candidate-request-1",
        envelope_changes: dict | None = None,
        challenge: ChallengeManifest | None = None,
        manifest: SubmissionManifest | None = None,
    ):
        selected = challenge or _challenge()
        candidate_manifest = manifest or _manifest(
            challenge=selected, source_bytes=len(source)
        )
        envelope, _binding_value = _encrypt_envelope(
            source,
            self.recipient,
            challenge=selected,
            manifest=candidate_manifest,
            identity=self.identity,
            idempotency_key=idempotency_key,
        )
        if envelope_changes:
            envelope.update(envelope_changes)
        return self.service.ingest(
            challenge=selected,
            identity=self.identity,
            candidate_commitment=_commitment(source),
            manifest=candidate_manifest,
            idempotency_key=idempotency_key,
            registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
            envelope=envelope,
        )

    def test_real_envelope_ingest_and_worker_decrypt_round_trip(self):
        result = self._ingest()

        self.assertTrue(result.created)
        self.assertRegex(
            result.sealed_reference,
            r"^sealed://arena/candidate-[0-9a-f]{64}$",
        )
        stored = self.store.load_envelope(result.sealed_reference)
        self.assertEqual(_decrypt_stored(stored, self.recipient), VECTOR_SOURCE)
        self.assertEqual(
            stored.binding.candidate_commitment, _commitment(VECTOR_SOURCE)
        )

    def test_no_plaintext_persisted_and_public_receipt_has_no_reconstructible_ref(self):
        secret = b"UNIQUE_ARENA_PLAINTEXT_MUST_NEVER_PERSIST"
        result = self._ingest(secret)
        receipt = result.to_public_dict()
        rendered_receipt = json.dumps(receipt, sort_keys=True)

        self.assertNotIn("sealed_reference", receipt)
        self.assertNotIn("envelope_id", receipt)
        self.assertNotIn("candidate-", rendered_receipt)
        self.assertNotIn(WALLET.lower(), rendered_receipt.lower())
        self.assertNotIn(PROJECT, rendered_receipt)
        self.assertNotIn(secret.decode("ascii"), rendered_receipt)
        self.assertFalse(receipt["sealed_reference_public"])
        self.assertFalse(receipt["plaintext_candidate_accepted"])
        self.assertEqual(receipt["product_status"], "modeled")

        persisted = b"".join(
            path.read_bytes()
            for path in self.ingress_root.rglob("*")
            if path.is_file()
        )
        self.assertNotIn(secret, persisted)
        for path in self.ingress_root.rglob("*"):
            if path.is_file():
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_exact_idempotent_replay_does_not_rewrite_ciphertext(self):
        first = self._ingest()
        blob_paths = [
            path
            for path in self.ingress_root.rglob("*")
            if path.is_file() and path.name != "index.json"
        ]
        self.assertEqual(len(blob_paths), 1)
        blob = blob_paths[0]
        before = blob.read_bytes()
        before_stat = blob.stat()

        second = self._ingest()

        self.assertFalse(second.created)
        self.assertEqual(second.sealed_reference, first.sealed_reference)
        self.assertEqual(blob.read_bytes(), before)
        self.assertEqual(blob.stat().st_ino, before_stat.st_ino)
        self.assertEqual(blob.stat().st_mtime_ns, before_stat.st_mtime_ns)

    def test_changed_envelope_under_same_idempotency_key_conflicts_without_echo(self):
        self._ingest()
        changed_nonce = _b64url(bytes(reversed(FIXED_NONCE)))
        with self.assertRaises(ArenaIngressConflict) as raised:
            self._ingest(envelope_changes={"nonce": changed_nonce})
        message = str(raised.exception)
        self.assertNotIn(changed_nonce, message)
        self.assertNotIn("ciphertext", message.lower())

    def test_auth_derived_identity_type_is_required(self):
        envelope, _ = _encrypt_envelope(
            VECTOR_SOURCE,
            self.recipient,
            identity=self.identity,
            idempotency_key="candidate-request-auth",
        )
        with self.assertRaises(ArenaIngressError):
            self.service.ingest(
                challenge=_challenge(),
                identity={"wallet_address": WALLET, "project_id": PROJECT},
                candidate_commitment=_commitment(VECTOR_SOURCE),
                manifest=_manifest(),
                idempotency_key="candidate-request-auth",
                registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
                envelope=envelope,
            )

    def test_key_report_aad_and_commitment_binding_tampering_fails(self):
        recipient_two = _recipient(bytes(reversed(FIXED_RECIPIENT_PRIVATE)))
        cases = (
            {"key_id": recipient_two.key_id},
            {"attestation_report_data": "00" * 32},
            {"aad": _b64url(b"{}")},
        )
        for index, changes in enumerate(cases):
            with self.subTest(changes=set(changes)):
                with self.assertRaises(ArenaIngressError):
                    self._ingest(
                        idempotency_key=f"candidate-binding-{index}",
                        envelope_changes=changes,
                    )

        envelope, _ = _encrypt_envelope(
            VECTOR_SOURCE,
            self.recipient,
            identity=self.identity,
            idempotency_key="candidate-binding-commitment",
        )
        with self.assertRaises(ArenaIngressError):
            self.service.ingest(
                challenge=_challenge(),
                identity=self.identity,
                candidate_commitment="sha256:" + "00" * 32,
                manifest=_manifest(),
                idempotency_key="candidate-binding-commitment",
                registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
                envelope=envelope,
            )

    def test_noncanonical_base64url_and_noncanonical_json_aad_fail(self):
        envelope, binding = _encrypt_envelope(
            VECTOR_SOURCE,
            self.recipient,
            identity=self.identity,
            idempotency_key="candidate-padded-base64",
        )
        padded = dict(envelope)
        padded["nonce"] += "="
        with self.assertRaises(ArenaIngressError):
            ArenaCandidateEnvelope.from_mapping(padded)

        noncanonical_aad = json.dumps(
            binding.to_aad_dict(), sort_keys=False, indent=2
        ).encode("utf-8")
        envelope, _ = _encrypt_envelope(
            VECTOR_SOURCE,
            self.recipient,
            aad_override=noncanonical_aad,
            identity=self.identity,
            idempotency_key="candidate-noncanonical-aad",
        )
        with self.assertRaises(ArenaIngressError):
            self.service.ingest(
                challenge=_challenge(),
                identity=self.identity,
                candidate_commitment=_commitment(VECTOR_SOURCE),
                manifest=_manifest(),
                idempotency_key="candidate-noncanonical-aad",
                registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
                envelope=envelope,
            )

    def test_bio_cap_and_ciphertext_source_plus_tag_are_exact(self):
        too_large_for_bio = b"A" * 8_193
        oversized_manifest = _manifest(source_bytes=len(too_large_for_bio))
        challenge = _challenge()
        idempotency_key = "candidate-bio-8209"
        # Build the browser's declared AAD directly. The service must still
        # reject it because the versioned BIO manifest caps source at 8,192.
        oversized_binding = ArenaCandidateBinding(
            challenge_id=challenge.challenge_id,
            challenge_version=challenge.version,
            challenge_manifest_hash=challenge.manifest_hash,
            submission_manifest_hash=arena_submission_manifest_hash(
                oversized_manifest
            ),
            candidate_commitment=_commitment(too_large_for_bio),
            identity=self.identity.to_public_dict(),
            idempotency_key_hash=arena_idempotency_key_hash(
                challenge=challenge,
                identity=self.identity,
                idempotency_key=idempotency_key,
            ),
            key_id=self.recipient.key_id,
            attestation_report_data_sha256=(
                "sha256:" + hashlib.sha256(self.recipient.report_data).hexdigest()
            ),
            registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
        )
        envelope, _ = _encrypt_envelope(
            too_large_for_bio,
            self.recipient,
            manifest=oversized_manifest,
            identity=self.identity,
            idempotency_key=idempotency_key,
            binding_override=oversized_binding,
        )
        self.assertEqual(len(_unb64url(envelope["ciphertext"])), 8_209)
        with self.assertRaises(ArenaIngressError):
            self.service.ingest(
                challenge=challenge,
                identity=self.identity,
                candidate_commitment=_commitment(too_large_for_bio),
                manifest=oversized_manifest,
                idempotency_key=idempotency_key,
                registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
                envelope=envelope,
            )

        wrong_length_manifest = _manifest(source_bytes=len(VECTOR_SOURCE) + 1)
        envelope, _ = _encrypt_envelope(
            VECTOR_SOURCE,
            self.recipient,
            manifest=wrong_length_manifest,
            identity=self.identity,
            idempotency_key="candidate-wrong-length",
        )
        with self.assertRaisesRegex(ArenaIngressError, "length|source"):
            self.service.ingest(
                challenge=_challenge(),
                identity=self.identity,
                candidate_commitment=_commitment(VECTOR_SOURCE),
                manifest=wrong_length_manifest,
                idempotency_key="candidate-wrong-length",
                registry_authorization_sha256=REGISTRY_AUTHORIZATION_SHA256,
                envelope=envelope,
            )

    def test_global_max_is_65520_source_and_65536_ciphertext(self):
        self.assertEqual(MAX_SOURCE_BYTES, MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES)
        challenge = _large_challenge()
        source = b"M" * MAX_SOURCE_BYTES
        manifest = _manifest(challenge=challenge, source_bytes=len(source))
        result = self._ingest(
            source,
            idempotency_key="candidate-max-size",
            challenge=challenge,
            manifest=manifest,
        )
        stored = self.store.load_envelope(result.sealed_reference)
        self.assertEqual(stored.envelope.ciphertext_bytes, MAX_CIPHERTEXT_BYTES)

        oversized_ciphertext = dict(stored.envelope.to_persisted_dict())
        oversized_ciphertext["ciphertext"] = _b64url(
            b"X" * (MAX_CIPHERTEXT_BYTES + 1)
        )
        with self.assertRaises(ArenaIngressError):
            ArenaCandidateEnvelope.from_mapping(oversized_ciphertext)

    def test_restart_round_trip_missing_blob_and_corruption_fail_closed(self):
        result = self._ingest()
        restarted = ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        loaded = restarted.load_envelope(result.sealed_reference)
        self.assertEqual(loaded.envelope.ciphertext_sha256, result.ciphertext_sha256)

        blob_paths = [
            path
            for path in self.ingress_root.rglob("*")
            if path.is_file() and path.name != "index.json"
        ]
        self.assertEqual(len(blob_paths), 1)
        blob = blob_paths[0]
        original = blob.read_bytes()
        blob.write_bytes(b'{"partial":')
        os.chmod(blob, 0o600)
        corrupted = ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        with self.assertRaises(ArenaIngressCorruptError):
            corrupted.load_envelope(result.sealed_reference)

        blob.write_bytes(original)
        os.chmod(blob, 0o600)
        restarted = ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        os.chmod(blob, 0o644)
        with self.assertRaises(ArenaIngressCorruptError):
            ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        os.chmod(blob, 0o600)
        restarted = ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)
        blob.unlink()
        with self.assertRaises(ArenaIngressCorruptError):
            restarted.load_envelope(result.sealed_reference)

    def test_metadata_read_never_opens_ciphertext_and_unlink_is_idempotent(self):
        result = self._ingest()
        with patch.object(
            ArenaCandidateIngressStore,
            "_load_blob",
            side_effect=AssertionError("ciphertext opened before claim"),
        ):
            restarted = ArenaCandidateIngressStore(
                self.ingress_root,
                max_envelopes=32,
            )
            metadata = restarted.describe_envelope(result.sealed_reference)
        self.assertEqual(metadata.blob_sha256, result.blob_sha256)
        self.assertEqual(metadata.ciphertext_sha256, result.ciphertext_sha256)

        erased = restarted.erase_envelope(result.sealed_reference)
        self.assertEqual(erased.evidence, "directory_entry_unlinked")
        self.assertFalse(erased.to_bounded_dict()["physical_erasure_claimed"])
        replay = restarted.erase_envelope(result.sealed_reference)
        self.assertEqual(replay.evidence, "directory_entry_absent")
        self.assertFalse(replay.to_bounded_dict()["physical_erasure_claimed"])
        with self.assertRaises(ArenaIngressError):
            restarted.load_envelope(result.sealed_reference)

    def test_crash_after_unlink_retries_from_pending_index_and_absence_evidence(self):
        result = self._ingest()
        original_persist = self.store._persist_index
        calls = 0

        def crash_on_finalization(records):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated crash after unlink")
            return original_persist(records)

        with patch.object(
            self.store,
            "_persist_index",
            side_effect=crash_on_finalization,
        ):
            with self.assertRaises(ArenaIngressErasureRetryable):
                self.store.erase_envelope(result.sealed_reference)

        restarted = ArenaCandidateIngressStore(
            self.ingress_root,
            max_envelopes=32,
        )
        with self.assertRaises(ArenaIngressError):
            restarted.describe_envelope(result.sealed_reference)
        retried = restarted.erase_envelope(result.sealed_reference)
        self.assertEqual(retried.evidence, "directory_entry_absent")
        ArenaCandidateIngressStore(self.ingress_root, max_envelopes=32)

    def test_symlink_substitution_fails_closed_without_unlinking_external_target(self):
        result = self._ingest()
        blob = next(
            path
            for path in self.ingress_root.rglob("*")
            if path.is_file() and path.name != "index.json"
        )
        external = self.root / "must-remain.txt"
        external.write_text("outside", encoding="utf-8")
        blob.unlink()
        blob.symlink_to(external)

        with self.assertRaises(ArenaIngressCorruptError):
            self.store.erase_envelope(result.sealed_reference)
        self.assertEqual(external.read_text(encoding="utf-8"), "outside")

    def test_builder_uses_configured_root_and_stable_recipient(self):
        settings = Settings(
            arena_store_path=str(self.root / "arena.json"),
            arena_candidate_ingress_store_path=str(self.root / "configured-ingress"),
            arena_candidate_ingress_local_key_file=str(self.root / "keys" / "arena.key"),
            arena_candidate_ingress_max_envelopes=16,
        )
        with patch(
            "tinker_delegate.arena_ingress.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            first = build_arena_candidate_ingress(settings)
            second = build_arena_candidate_ingress(settings)
        self.assertEqual(first.recipient.key_id, second.recipient.key_id)
        self.assertEqual(first.store.root_dir, self.root / "configured-ingress")


if __name__ == "__main__":
    unittest.main()
