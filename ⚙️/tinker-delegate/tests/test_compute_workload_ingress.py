import base64
import hashlib
import hmac
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate import dstack_utils
from tinker_delegate.compute_workload_ingress import (
    INFERENCE_PAYLOAD_SCHEMA,
    INFERENCE_WORKLOAD_SCHEMA,
    SFT_JSONL_WORKLOAD_SCHEMA,
    WORKLOAD_HKDF_INFO,
    WORKLOAD_INGRESS_ALGORITHM,
    WORKLOAD_INGRESS_ENCODING,
    WORKLOAD_RECIPIENT_ACTIVATION_SCHEMA,
    WORKLOAD_RECIPIENT_RELEASE_DOMAIN,
    ComputeWorkloadEnvelope,
    ComputeWorkloadBinding,
    ComputeWorkloadIngressConflict,
    ComputeWorkloadIngressCorrupt,
    ComputeWorkloadIngressError,
    ComputeWorkloadIngressService,
    ComputeWorkloadIngressStore,
    ComputeWorkloadIngressUnavailable,
    ComputeWorkloadManifest,
    ComputeWorkloadPrincipal,
    ComputeWorkloadRecipient,
    ComputeWorkloadRecipientActivation,
    UnavailableComputeWorkloadActivationProvider,
    authenticate_compute_workload_recipient_activation,
    build_compute_workload_plaintext,
    compute_workload_aad,
    compute_workload_browser_contract,
    compute_workload_commitment,
    compute_workload_execution_binding_commitment,
    compute_workload_execution_binding_payload,
    compute_workload_idempotency_hash,
    validate_compute_workload_plaintext,
)
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)


NOW = 1_800_000_000
WALLET = "0x" + "11" * 20
TEE_SIGNER = "0x" + "71" * 20
COMPUTE_VAULT = "0x" + "72" * 20
RELEASE_POLICY_HASH = "0x" + "33" * 32
COMPOSE_HASH = "0x" + "31" * 32
OS_IMAGE_HASH = "32" * 32
QUOTE_HASH = "0x" + "34" * 32
CHALLENGE_ID = "0x" + "73" * 32
CHALLENGE_DIGEST = "0x" + "74" * 32
VAULT_RUNTIME_CODE_HASH = "0x" + "76" * 32
FRESH_DEPLOYMENT_RECEIPT_SHA256 = "0x" + "77" * 32
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
MEASUREMENT_POLICY_SET_SHA256 = "sha256:" + "45" * 32
MAIN_RUNTIME_EVIDENCE_SHA256 = "sha256:" + "46" * 32
DISPATCH_JOB_ID = "0x" + "81" * 32
DISPATCH_INTENT_COMMITMENT = "0x" + "82" * 32
USAGE_RELEASE_CHECKPOINT = "sha256:" + "83" * 32


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _recipient_attestation(public_key: bytes) -> dict[str, object]:
    return {
        "schema": "dnai.compute-workload-recipient-attestation.v1",
        "context": "compute_workload",
        "audience": "dnai-wikigen:compute-workload-recipient",
        "service": "dnai-wikigen",
        "protocol": "compute_workload_ingress_v1",
        "encryption_public_key": public_key.hex(),
        "key_id": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "activation_signer_address": TEE_SIGNER,
        "activation_signer_key_path": "tinker/compute_workload_activation_signer",
        "activation_signer_custody": (
            "dstack_derived_compute_workload_activation_signer"
        ),
        "chain_id": 84_532,
        "compute_vault_address": COMPUTE_VAULT,
        "compute_vault_runtime_code_hash": VAULT_RUNTIME_CODE_HASH,
        "fresh_contract_deployment_receipt_sha256": (
            FRESH_DEPLOYMENT_RECEIPT_SHA256
        ),
    }


def _authenticated_activation(
    recipient: ComputeWorkloadRecipient,
    *,
    qvl: Account | None = None,
    signing_account: Account | None = None,
    sequence: int = 0,
    compose_hash: str = COMPOSE_HASH,
    release_policy_hash: str = RELEASE_POLICY_HASH,
    measurement_policy_set_sha256: str = MEASUREMENT_POLICY_SET_SHA256,
    main_runtime_evidence_sha256: str = MAIN_RUNTIME_EVIDENCE_SHA256,
) -> ComputeWorkloadRecipientActivation:
    qvl = qvl or Account.from_key(bytes.fromhex("75" * 32))
    challenge_id = (
        CHALLENGE_ID
        if sequence == 0
        else "0x" + hashlib.sha256(f"challenge-{sequence}".encode()).hexdigest()
    )
    challenge_digest = (
        CHALLENGE_DIGEST
        if sequence == 0
        else "0x" + hashlib.sha256(f"digest-{sequence}".encode()).hexdigest()
    )
    quote_hash = (
        QUOTE_HASH
        if sequence == 0
        else "0x" + hashlib.sha256(f"quote-{sequence}".encode()).hexdigest()
    )
    issued_at = NOW - 10 + min(sequence, 5)
    expires_at = NOW + 90 + min(sequence, 5)
    unsigned = IndependentAttestationVerdict(
        schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        verified=True,
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="compute_workload",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=release_policy_hash,
        challenge_id=challenge_id,
        challenge_digest=challenge_digest,
        challenge_issued_at=NOW - 20,
        challenge_expires_at=NOW + 100,
        quote_hash=quote_hash,
        report_data="0x" + recipient.report_data.hex(),
        compose_hash=compose_hash,
        app_id="a1" * 20,
        os_image_hash=OS_IMAGE_HASH,
        signer_address=TEE_SIGNER,
        contract_address=COMPUTE_VAULT,
        issued_at=issued_at,
        activation_evidence_lease_expires_at=expires_at,
        expires_at=expires_at,
        verifier_address=qvl.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    signer = signing_account or qvl
    signed = signer.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    )
    verdict = replace(
        unsigned,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )
    expectation = IndependentAttestationExpectation(
        trusted_verifier_addresses=(qvl.address,),
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="compute_workload",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=release_policy_hash,
        challenge_id=challenge_id,
        challenge_digest=challenge_digest,
        challenge_issued_at=NOW - 20,
        challenge_expires_at=NOW + 100,
        quote_hash=quote_hash,
        report_data="0x" + recipient.report_data.hex(),
        compose_hash=compose_hash,
        app_id="a1" * 20,
        os_image_hash=OS_IMAGE_HASH,
        signer_address=TEE_SIGNER,
        contract_address=COMPUTE_VAULT,
        max_age_seconds=300,
    )
    return authenticate_compute_workload_recipient_activation(
        recipient=recipient,
        verdict=verdict,
        expectation=expectation,
        measurement_policy_set_sha256=measurement_policy_set_sha256,
        main_runtime_evidence_sha256=main_runtime_evidence_sha256,
        now=NOW,
    )


class TestOnlyActivationProvider:
    def __init__(self, activation):
        self.activation = activation
        self.calls = 0

    def verified_activation(self, recipient, *, now):
        self.calls += 1
        return self.activation


class ComputeWorkloadIngressTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "workloads"
        self.recipient_private = bytes.fromhex("21" * 32)
        keypair = TEEKeyPair.from_private_key_hex(self.recipient_private.hex())
        self.recipient = ComputeWorkloadRecipient.from_keypair(
            keypair,
            custody_mode="dstack",
            recipient_attestation=_recipient_attestation(
                keypair.public_key_bytes
            ),
        )
        self.activation = _authenticated_activation(self.recipient)
        self.provider = TestOnlyActivationProvider(self.activation)
        self.store = ComputeWorkloadIngressStore(
            self.root,
            integrity_key=b"i" * 32,
        )
        self.service = ComputeWorkloadIngressService(
            self.store,
            self.recipient,
            self.provider,
            clock=lambda: NOW,
        )
        self.principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id="prj_alpha",
            actor_id=WALLET,
        )
        self.dstack_enabled = patch.object(
            dstack_utils, "is_dstack_enabled", return_value=True
        )
        self.dstack_simulator = patch.object(
            dstack_utils, "is_dstack_simulator", return_value=False
        )
        self.dstack_enabled.start()
        self.dstack_simulator.start()

    def tearDown(self):
        self.store.close()
        self.dstack_simulator.stop()
        self.dstack_enabled.stop()
        self.temporary.cleanup()

    def inference(self, prompt="private sequence observation"):
        payload = _canonical(
            {"schema": INFERENCE_PAYLOAD_SCHEMA, "prompt": prompt}
        )
        manifest = ComputeWorkloadManifest(
            schema=INFERENCE_WORKLOAD_SCHEMA,
            operation="inference",
            model="qwen3_8b",
            recipe="qwen3_8b_bounded",
            payload_size_class="4k",
            example_count_class="none",
            max_prefill_tokens=1024,
            max_sample_tokens=128,
            max_train_tokens=0,
        )
        plaintext = build_compute_workload_plaintext(
            manifest,
            payload,
            blinding=b"\x91" * 32,
            padding=b"\x92" * (4096 - 44 - len(payload)),
        )
        return manifest, plaintext, compute_workload_commitment(manifest, plaintext)

    def training(self):
        examples = [
            {"prompt": "private dna fragment A", "completion": "bounded label A"},
            {"prompt": "private dna fragment B", "completion": "bounded label B"},
        ]
        payload = b"\n".join(_canonical(value) for value in examples) + b"\n"
        manifest = ComputeWorkloadManifest(
            schema=SFT_JSONL_WORKLOAD_SCHEMA,
            operation="training",
            model="qwen3_8b",
            recipe="qwen3_8b_lora_r32",
            payload_size_class="4k",
            example_count_class="1_8",
            max_prefill_tokens=0,
            max_sample_tokens=0,
            max_train_tokens=20_000,
        )
        plaintext = build_compute_workload_plaintext(
            manifest,
            payload,
            blinding=b"\x93" * 32,
            padding=b"\x94" * (4096 - 44 - len(payload)),
        )
        return manifest, plaintext, compute_workload_commitment(manifest, plaintext)

    def envelope(
        self,
        manifest,
        plaintext,
        commitment,
        *,
        idempotency_key="workload.test.0001",
        ephemeral_private=None,
        nonce=None,
        principal=None,
    ):
        source_principal = principal or self.principal
        binding = self.service.binding_for(
            principal=source_principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key=idempotency_key,
            activation=self.activation,
        )
        aad = compute_workload_aad(binding)
        ephemeral = ephemeral_private or X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes_raw()
        shared_secret = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(self.recipient.public_key)
        )
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=WORKLOAD_HKDF_INFO,
        ).derive(shared_secret)
        nonce = nonce or os.urandom(12)
        ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, aad)
        return ComputeWorkloadEnvelope(
            schema_version=1,
            algorithm=WORKLOAD_INGRESS_ALGORITHM,
            encoding=WORKLOAD_INGRESS_ENCODING,
            key_id=self.recipient.key_id,
            attestation_report_data=self.recipient.report_data.hex(),
            activation_commitment=self.activation.commitment,
            aad=_b64(aad),
            ephemeral_public_key=_b64(ephemeral_public),
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
        )

    def ingest(
        self,
        *,
        idempotency_key="workload.test.0001",
        principal=None,
        ephemeral_private=None,
        nonce=None,
    ):
        source_principal = principal or self.principal
        manifest, plaintext, commitment = self.inference()
        envelope = self.envelope(
            manifest,
            plaintext,
            commitment,
            idempotency_key=idempotency_key,
            principal=source_principal,
            ephemeral_private=ephemeral_private,
            nonce=nonce,
        )
        result = self.service.ingest(
            principal=source_principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key=idempotency_key,
            envelope=envelope,
        )
        return manifest, plaintext, commitment, envelope, result

    def test_strict_inference_and_sft_plaintext_validation(self):
        inference_manifest, inference, inference_commitment = self.inference()
        validated = validate_compute_workload_plaintext(
            inference_manifest,
            inference,
            expected_commitment=inference_commitment,
        )
        self.assertEqual(
            validated.to_bounded_dict(),
            {"valid": True, "raw_workload_egress": False},
        )
        self.assertNotIn("private", repr(validated))

        training_manifest, training, training_commitment = self.training()
        trained = validate_compute_workload_plaintext(
            training_manifest,
            training,
            expected_commitment=training_commitment,
        )
        self.assertEqual(
            trained.to_bounded_dict(),
            {"valid": True, "raw_workload_egress": False},
        )

    def test_activation_v3_and_release_v2_have_exact_frozen_wire_preimages(self):
        public = self.activation.to_dict()
        self.assertEqual(
            set(public),
            {
                "app_id",
                "authenticated_at",
                "authenticated_verdict",
                "ceremony_nonce",
                "chain_id",
                "compose_hash",
                "cvm_id",
                "deployment_intent_sha256",
                "domain",
                "expires_at",
                "issued_at",
                "main_runtime_evidence_sha256",
                "measurement_policy_set_sha256",
                "measurement_policy_sha256",
                "os_image_hash",
                "profile",
                "quote_hash",
                "recipient_attestation",
                "recipient_evidence_lease_expires_at",
                "recipient_key_id",
                "recipient_release_commitment",
                "release_authority_sha256",
                "release_policy_hash",
                "report_data",
                "schema",
                "verdict_digest",
                "verifier_address",
            },
        )
        self.assertEqual(public["schema"], WORKLOAD_RECIPIENT_ACTIVATION_SCHEMA)
        self.assertEqual(
            self.activation.commitment,
            "sha256:31c88697625a861b15b7b910df2c9c506fa8966087db86fc4be1edf75d2f8df0",
        )

        verdict = self.activation.authenticated_verdict
        release_payload = {
            "schema": "dnai.compute.workload-recipient-release.v2",
            "chain_id": self.activation.chain_id,
            "domain": self.activation.domain,
            "profile": self.activation.profile,
            "cvm_id": self.activation.cvm_id,
            "deployment_intent_sha256": (
                self.activation.deployment_intent_sha256
            ),
            "release_authority_sha256": (
                self.activation.release_authority_sha256
            ),
            "ceremony_nonce": self.activation.ceremony_nonce,
            "measurement_policy_set_sha256": (
                self.activation.measurement_policy_set_sha256
            ),
            "measurement_policy_sha256": (
                self.activation.measurement_policy_sha256
            ),
            "main_runtime_evidence_sha256": (
                self.activation.main_runtime_evidence_sha256
            ),
            "recipient_key_id": self.activation.recipient_key_id,
            "report_data": self.activation.report_data,
            "compose_hash": self.activation.compose_hash,
            "app_id": self.activation.app_id,
            "os_image_hash": self.activation.os_image_hash,
            "release_policy_hash": self.activation.release_policy_hash,
            "verifier_address": self.activation.verifier_address,
            "verification_method": verdict.verification_method,
            "signer_address": verdict.signer_address.lower(),
            "contract_address": verdict.contract_address.lower(),
            "recipient_attestation": dict(self.activation.recipient_attestation),
        }
        expected_release = "sha256:" + hashlib.sha256(
            WORKLOAD_RECIPIENT_RELEASE_DOMAIN + _canonical(release_payload)
        ).hexdigest()
        self.assertEqual(
            expected_release,
            "sha256:f7b362241093cc99c89194f44cbe5ce96e10cd937f4554d531bbf89c418b2ac9",
        )
        self.assertEqual(
            self.activation.recipient_release_commitment,
            expected_release,
        )

    def test_external_release_authority_evidence_cannot_drift_silently(self):
        policy_drift = _authenticated_activation(
            self.recipient,
            measurement_policy_set_sha256="sha256:" + "47" * 32,
        )
        evidence_drift = _authenticated_activation(
            self.recipient,
            main_runtime_evidence_sha256="sha256:" + "48" * 32,
        )
        for drifted in (policy_drift, evidence_drift):
            self.assertEqual(drifted.verdict_digest, self.activation.verdict_digest)
            self.assertNotEqual(drifted.commitment, self.activation.commitment)
            self.assertNotEqual(
                drifted.recipient_release_commitment,
                self.activation.recipient_release_commitment,
            )
        self.assertEqual(
            policy_drift.to_dict()["measurement_policy_set_sha256"],
            "sha256:" + "47" * 32,
        )
        self.assertEqual(
            evidence_drift.to_dict()["main_runtime_evidence_sha256"],
            "sha256:" + "48" * 32,
        )

    def test_shared_browser_wire_vector_matches_python_exactly(self):
        vector_path = (
            Path(__file__).resolve().parents[3]
            / "web"
            / "src"
            / "lib"
            / "computeWorkloadWireVectors.json"
        )
        vector = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertTrue(vector["fixture_only_nonsecret"])
        manifest = ComputeWorkloadManifest.from_mapping(vector["manifest"])
        principal = ComputeWorkloadPrincipal(
            kind=vector["principal"]["kind"],
            project_id=vector["principal"]["project_id"],
            actor_id=vector["principal"]["actor_id"],
        )
        payload = _canonical(
            {
                "schema": INFERENCE_PAYLOAD_SCHEMA,
                "prompt": vector["payload_utf8"],
            }
        )
        self.assertEqual(payload.hex(), vector["canonical_payload_hex"])
        sealed = build_compute_workload_plaintext(
            manifest,
            payload,
            blinding=bytes.fromhex(vector["blinding_hex"]),
            padding=b"\x92" * (4_096 - 44 - len(payload)),
        )
        recipient = ComputeWorkloadRecipient.from_keypair(
            TEEKeyPair.from_private_key_hex("21" * 32),
            custody_mode="dstack",
            recipient_attestation=vector["recipient_attestation"],
        )
        self.assertEqual(recipient.public_key.hex(), vector["recipient_public_key_hex"])
        self.assertEqual(recipient.key_id, vector["recipient_key_id"])
        self.assertEqual(
            dict(recipient.recipient_attestation),
            vector["recipient_attestation"],
        )
        self.assertEqual(recipient.report_data.hex(), vector["recipient_report_data"])
        report_hash = "sha256:" + hashlib.sha256(recipient.report_data).hexdigest()
        commitment = compute_workload_commitment(manifest, sealed)
        binding = ComputeWorkloadBinding(
            project_commitment=principal.project_commitment,
            actor_kind=principal.kind,
            actor_commitment=principal.actor_commitment,
            manifest=manifest,
            manifest_commitment=manifest.commitment,
            workload_commitment=commitment,
            idempotency_hash=compute_workload_idempotency_hash(
                principal,
                vector["idempotency_key"],
            ),
            recipient_key_id=recipient.key_id,
            report_data_sha256=report_hash,
            activation_commitment=vector["activation_commitment"],
            recipient_release_commitment=vector[
                "recipient_release_commitment"
            ],
        )
        aad = compute_workload_aad(binding)
        self.assertEqual(principal.project_commitment, vector["project_commitment"])
        self.assertEqual(principal.actor_commitment, vector["actor_commitment"])
        self.assertEqual(binding.idempotency_hash, vector["idempotency_hash"])
        self.assertEqual(manifest.commitment, vector["manifest_commitment"])
        self.assertEqual(commitment, vector["workload_commitment"])
        self.assertEqual(report_hash, vector["report_data_sha256"])
        self.assertEqual(_b64(aad), vector["aad_base64url"])
        self.assertEqual(
            "sha256:" + hashlib.sha256(aad).hexdigest(),
            vector["aad_sha256"],
        )
        self.assertEqual(len(sealed), vector["sealed_plaintext_bytes"])

    def test_plaintext_validation_rejects_noncanonical_extra_and_mismatch(self):
        manifest, plaintext, commitment = self.inference()
        noncanonical = json.dumps(
            {"schema": INFERENCE_PAYLOAD_SCHEMA, "prompt": "x"}
        ).encode()
        noncanonical_frame = build_compute_workload_plaintext(
            manifest,
            noncanonical,
            blinding=b"\xa1" * 32,
        )
        with self.assertRaises(ComputeWorkloadIngressError):
            validate_compute_workload_plaintext(
                manifest,
                noncanonical_frame,
                expected_commitment=compute_workload_commitment(
                    manifest, noncanonical_frame
                ),
            )
        extra = _canonical(
            {"schema": INFERENCE_PAYLOAD_SCHEMA, "prompt": "x", "secret": "y"}
        )
        extra_frame = build_compute_workload_plaintext(
            manifest,
            extra,
            blinding=b"\xa2" * 32,
        )
        with self.assertRaises(ComputeWorkloadIngressError):
            validate_compute_workload_plaintext(
                manifest,
                extra_frame,
                expected_commitment=compute_workload_commitment(manifest, extra_frame),
            )
        with self.assertRaisesRegex(ComputeWorkloadIngressError, "commitment mismatch"):
            validate_compute_workload_plaintext(
                manifest,
                plaintext,
                expected_commitment="sha256:" + "ab" * 32,
            )

    def test_secret_blinding_blocks_dictionary_confirmation_and_padding_hides_length(self):
        manifest, _, _ = self.inference()
        short_payload = _canonical(
            {"schema": INFERENCE_PAYLOAD_SCHEMA, "prompt": "A"}
        )
        long_payload = _canonical(
            {
                "schema": INFERENCE_PAYLOAD_SCHEMA,
                "prompt": "A" * 1200,
            }
        )
        first = build_compute_workload_plaintext(
            manifest,
            short_payload,
            blinding=b"\xb1" * 32,
        )
        same_guess_different_secret = build_compute_workload_plaintext(
            manifest,
            short_payload,
            blinding=b"\xb2" * 32,
        )
        different_length = build_compute_workload_plaintext(
            manifest,
            long_payload,
            blinding=b"\xb3" * 32,
        )
        first_commitment = compute_workload_commitment(manifest, first)
        guessed_commitment = compute_workload_commitment(
            manifest,
            same_guess_different_secret,
        )
        self.assertNotEqual(first_commitment, guessed_commitment)
        self.assertEqual(len(first), len(same_guess_different_secret))
        self.assertEqual(len(first), len(different_length))
        self.assertEqual(len(first), 4096)
        first_envelope = self.envelope(
            manifest,
            first,
            first_commitment,
            idempotency_key="workload.privacy.0001",
        )
        long_envelope = self.envelope(
            manifest,
            different_length,
            compute_workload_commitment(manifest, different_length),
            idempotency_key="workload.privacy.0002",
        )
        self.assertEqual(first_envelope.ciphertext_bytes, long_envelope.ciphertext_bytes)
        self.assertEqual(first_envelope.ciphertext_bytes, 4096 + 16)
        self.assertNotIn("content_bytes", manifest.to_dict())
        self.assertNotIn("example_count", manifest.to_dict())

    def test_training_count_class_does_not_reveal_exact_example_count(self):
        manifest, _, _ = self.training()
        one = _canonical({"prompt": "p", "completion": "c"}) + b"\n"
        eight = b"\n".join(
            _canonical({"prompt": f"p{index}", "completion": "c"})
            for index in range(8)
        ) + b"\n"
        one_frame = build_compute_workload_plaintext(
            manifest,
            one,
            blinding=b"\xb4" * 32,
        )
        eight_frame = build_compute_workload_plaintext(
            manifest,
            eight,
            blinding=b"\xb5" * 32,
        )
        self.assertEqual(len(one_frame), len(eight_frame))
        for frame in (one_frame, eight_frame):
            validate_compute_workload_plaintext(
                manifest,
                frame,
                expected_commitment=compute_workload_commitment(manifest, frame),
            )

    def test_ingest_is_exactly_idempotent_and_metadata_is_bounded(self):
        manifest, _, commitment, envelope, created = self.ingest()
        replay = self.service.ingest(
            principal=self.principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key="workload.test.0001",
            envelope=envelope,
        )
        self.assertTrue(created.created)
        self.assertFalse(replay.created)
        self.assertEqual(created.workload_id, replay.workload_id)
        metadata = self.store.public_metadata(
            created.workload_id,
            project_commitment=self.principal.project_commitment,
        )
        serialized = json.dumps(metadata, sort_keys=True)
        self.assertNotIn('"ciphertext":', serialized)
        self.assertNotIn("private sequence observation", serialized)
        self.assertNotIn("content_bytes", serialized)
        self.assertNotIn("example_count\"", serialized)
        self.assertEqual(metadata["payload_size_class"], "4k")
        self.assertEqual(metadata["example_count_class"], "none")
        self.assertFalse(metadata["provider_dispatch_enabled"])
        self.assertEqual(metadata["workload_commitment"], commitment)
        self.assertEqual(
            created.recipient_release_commitment,
            self.activation.recipient_release_commitment,
        )
        self.assertEqual(
            metadata["recipient_release_commitment"],
            self.activation.recipient_release_commitment,
        )

    def test_credential_execution_binding_v1_has_a_frozen_public_kat(self):
        credential = ComputeWorkloadPrincipal(
            kind="credential",
            project_id="prj_alpha",
            actor_id="device_alpha",
        )
        _, _, _, _, created = self.ingest(
            idempotency_key="credential.workload.0001",
            principal=credential,
            ephemeral_private=X25519PrivateKey.from_private_bytes(
                bytes.fromhex("31" * 32)
            ),
            nonce=bytes.fromhex("32" * 12),
        )
        self.assertEqual(
            created.workload_id,
            "wrk_bec902dfeda679768ed7628905f77acb",
        )
        self.assertEqual(
            created.execution_binding_commitment,
            "sha256:abc93fa6b83c41d70c8396c270a049f0e8136b9207b3aeb4450c8aa17979ca90",
        )
        stored = self.store.get_for_project(
            created.workload_id,
            project_commitment=credential.project_commitment,
        )
        self.assertEqual(
            compute_workload_execution_binding_commitment(
                stored.workload_id,
                stored.binding,
                stored.envelope,
            ),
            created.execution_binding_commitment,
        )
        self.assertEqual(
            compute_workload_execution_binding_payload(
                stored.workload_id,
                stored.binding,
                stored.envelope,
            ),
            {
                "schema": "dnai.compute.workload-execution-binding.v1",
                "workload_id": "wrk_bec902dfeda679768ed7628905f77acb",
                "project_commitment": (
                    "sha256:915388e06e578d85b26e541f8a683be78a0fa4909070b93ac348d08cb378e09e"
                ),
                "actor_kind": "credential",
                "actor_commitment": (
                    "sha256:cb76f94d6517afa92a9fbbda4726ae0157f9a2c34504d0acce9b99948148c6d7"
                ),
                "aad_sha256": (
                    "sha256:6083d52180ab3fcf8a44cbaf833529e6908e4af524fa0f40ccf6a85efafa3831"
                ),
                "manifest_commitment": (
                    "sha256:045b0ec3e637d9ebf9751f21d89269ac742d2f3d7b60dff8a14e4217e9bfaa8c"
                ),
                "workload_commitment": (
                    "sha256:fe51038888b9e8feb45c14418bb14b9a1920d6513a5df044c9cb034cb0aafd2e"
                ),
                "recipient_key_id": (
                    "sha256:f05fcd1fe8d7be51f79bf91c6b7cf2857a3ba5179d63a0a70e616f5f94423b4f"
                ),
                "recipient_release_commitment": (
                    "sha256:f7b362241093cc99c89194f44cbe5ce96e10cd937f4554d531bbf89c418b2ac9"
                ),
            },
        )
        receipt = created.to_public_dict()
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(
            receipt["execution_binding"],
            {
                "schema": "dnai.compute.workload-execution-binding.v1",
                "commitment": created.execution_binding_commitment,
                "source_kind": "credential",
                "wallet_adoption_required": True,
                "device_spending_authority": False,
            },
        )
        metadata = self.store.public_metadata(
            created.workload_id,
            project_commitment=credential.project_commitment,
        )
        self.assertEqual(metadata["schema_version"], 2)
        self.assertEqual(metadata["execution_binding"], receipt["execution_binding"])
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            self.store.release_ciphertext_after_checkpoint(
                created.workload_id,
                project_commitment=credential.project_commitment,
                actor_commitment=credential.actor_commitment,
                release_checkpoint_commitment=USAGE_RELEASE_CHECKPOINT,
            )

    def test_dispatch_claim_is_exact_restart_safe_and_one_job_only(self):
        credential = ComputeWorkloadPrincipal(
            kind="credential",
            project_id="prj_alpha",
            actor_id="device_alpha",
        )
        _, _, _, _, created = self.ingest(
            idempotency_key="credential.workload.0001",
            principal=credential,
            ephemeral_private=X25519PrivateKey.from_private_bytes(
                bytes.fromhex("31" * 32)
            ),
            nonce=bytes.fromhex("32" * 12),
        )
        claim, changed = self.service.claim_for_dispatch(
            created.workload_id,
            project_id=credential.project_id,
            job_id=DISPATCH_JOB_ID,
            intent_commitment=DISPATCH_INTENT_COMMITMENT,
            funding_wallet=WALLET,
            source_kind="credential",
            execution_binding_commitment=created.execution_binding_commitment,
            recipient_release_commitment=created.recipient_release_commitment,
        )
        self.assertTrue(changed)
        self.assertEqual(
            claim.commitment,
            "sha256:af1fe4b3d1eeaae8f9273993989c4d54ff2afd373389786673db39a34792a953",
        )
        replay, changed = self.service.claim_for_dispatch(
            created.workload_id,
            project_id=credential.project_id,
            job_id=DISPATCH_JOB_ID,
            intent_commitment=DISPATCH_INTENT_COMMITMENT,
            funding_wallet=WALLET,
            source_kind="credential",
            execution_binding_commitment=created.execution_binding_commitment,
            recipient_release_commitment=created.recipient_release_commitment,
        )
        self.assertFalse(changed)
        self.assertEqual(replay, claim)
        claimed_metadata = self.store.public_metadata(
            created.workload_id,
            project_commitment=credential.project_commitment,
        )
        self.assertEqual(
            claimed_metadata["dispatch_adoption"]["state"],
            "claimed_by_wallet_dispatch",
        )
        self.assertFalse(
            claimed_metadata["dispatch_adoption"][
                "wallet_adoption_eligible"
            ]
        )
        self.assertEqual(
            claimed_metadata["dispatch_adoption"]["claim_commitment"],
            claim.commitment,
        )
        self.assertEqual(
            claimed_metadata["dispatch_adoption"]["funding_authority"],
            "onchain_wallet_job",
        )
        self.assertFalse(
            claimed_metadata["dispatch_adoption"][
                "direct_deletion_allowed"
            ]
        )

        restarted = ComputeWorkloadIngressStore(
            self.root,
            integrity_key=b"i" * 32,
        )
        try:
            observed = restarted.get_claimed_for_execution(
                created.workload_id,
                project_commitment=credential.project_commitment,
                claim=claim,
            )
            self.assertEqual(observed.lifecycle, "dispatch_claimed")
            self.assertEqual(observed.dispatch_claim, claim)
        finally:
            restarted.close()

        with self.assertRaises(ComputeWorkloadIngressConflict):
            self.service.claim_for_dispatch(
                created.workload_id,
                project_id=credential.project_id,
                job_id="0x" + "84" * 32,
                intent_commitment=DISPATCH_INTENT_COMMITMENT,
                funding_wallet=WALLET,
                source_kind="credential",
                execution_binding_commitment=(
                    created.execution_binding_commitment
                ),
                recipient_release_commitment=(
                    created.recipient_release_commitment
                ),
            )

        _, _, _, _, second = self.ingest(
            idempotency_key="credential.workload.0002",
            principal=credential,
            ephemeral_private=X25519PrivateKey.from_private_bytes(
                bytes.fromhex("33" * 32)
            ),
            nonce=bytes.fromhex("34" * 12),
        )
        with self.assertRaises(ComputeWorkloadIngressConflict):
            self.service.claim_for_dispatch(
                second.workload_id,
                project_id=credential.project_id,
                job_id=DISPATCH_JOB_ID,
                intent_commitment=DISPATCH_INTENT_COMMITMENT,
                funding_wallet=WALLET,
                source_kind="credential",
                execution_binding_commitment=(
                    second.execution_binding_commitment
                ),
                recipient_release_commitment=(
                    second.recipient_release_commitment
                ),
            )

        with self.assertRaises(ComputeWorkloadIngressError):
            with self.service.consume_for_execution(
                created.workload_id,
                project_commitment=credential.project_commitment,
            ):
                pass
        self.assertEqual(len(list((self.root / "envelopes").iterdir())), 2)

    def test_claimed_provider_lease_release_is_checkpoint_exact_and_zeroizes(self):
        credential = ComputeWorkloadPrincipal(
            kind="credential",
            project_id="prj_alpha",
            actor_id="device_alpha",
        )
        _, _, _, _, created = self.ingest(
            idempotency_key="credential.workload.0001",
            principal=credential,
        )
        claim, _ = self.service.claim_for_dispatch(
            created.workload_id,
            project_id=credential.project_id,
            job_id=DISPATCH_JOB_ID,
            intent_commitment=DISPATCH_INTENT_COMMITMENT,
            funding_wallet=WALLET,
            source_kind="credential",
            execution_binding_commitment=created.execution_binding_commitment,
            recipient_release_commitment=created.recipient_release_commitment,
        )
        retained = None
        with self.service.lease_for_provider_execution(
            created.workload_id,
            project_id=credential.project_id,
            claim=claim,
            source_kind="credential",
            recipient_release_commitment=created.recipient_release_commitment,
        ) as lease:
            self.assertIn(b"private sequence observation", lease.plaintext)
            self.assertTrue(lease.reauthenticate().valid)
            retained = lease.plaintext
        self.assertIsNotNone(retained)
        self.assertEqual(bytes(retained), b"\x00" * len(retained))
        self.assertEqual(len(list((self.root / "envelopes").iterdir())), 1)

        self.assertTrue(
            self.service.release_after_usage_checkpoint(
                created.workload_id,
                project_id=credential.project_id,
                claim=claim,
                release_checkpoint_commitment=USAGE_RELEASE_CHECKPOINT,
            )
        )
        self.assertFalse(
            self.service.release_after_usage_checkpoint(
                created.workload_id,
                project_id=credential.project_id,
                claim=claim,
                release_checkpoint_commitment=USAGE_RELEASE_CHECKPOINT,
            )
        )
        with self.assertRaises(ComputeWorkloadIngressConflict):
            self.service.release_after_usage_checkpoint(
                created.workload_id,
                project_id=credential.project_id,
                claim=claim,
                release_checkpoint_commitment="sha256:" + "85" * 32,
            )
        self.assertEqual(list((self.root / "envelopes").iterdir()), [])

    def test_authenticated_v1_index_is_not_opened_as_claim_capable_state(self):
        self.ingest()
        self.store.close()
        index_path = self.root / "index.json"
        envelope = json.loads(index_path.read_text(encoding="utf-8"))
        envelope["body"]["schema"] = (
            "dnai.compute.workload-ingress-index.v1"
        )
        envelope["body"]["schema_version"] = 1
        envelope["mac"] = hmac.new(
            b"i" * 32,
            b"dnai-wikigen/compute-workload-store/v1\0"
            + _canonical(envelope["body"]),
            hashlib.sha256,
        ).hexdigest()
        index_path.write_bytes(_canonical(envelope) + b"\n")
        os.chmod(index_path, 0o600)
        with self.assertRaises(ComputeWorkloadIngressCorrupt):
            ComputeWorkloadIngressStore(
                self.root,
                integrity_key=b"i" * 32,
            )

    def test_idempotency_conflict_and_nonce_tuple_replay_are_rejected(self):
        manifest, plaintext, commitment = self.inference()
        first = self.envelope(manifest, plaintext, commitment)
        self.service.ingest(
            principal=self.principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key="workload.test.0001",
            envelope=first,
        )
        changed = self.envelope(manifest, plaintext, commitment)
        with self.assertRaises(ComputeWorkloadIngressConflict):
            self.service.ingest(
                principal=self.principal,
                manifest=manifest,
                workload_commitment=commitment,
                idempotency_key="workload.test.0001",
                envelope=changed,
            )

        ephemeral = X25519PrivateKey.generate()
        nonce = b"\x42" * 12
        second = self.envelope(
            manifest,
            plaintext,
            commitment,
            idempotency_key="workload.test.0002",
            ephemeral_private=ephemeral,
            nonce=nonce,
        )
        self.service.ingest(
            principal=self.principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key="workload.test.0002",
            envelope=second,
        )
        third = self.envelope(
            manifest,
            plaintext,
            commitment,
            idempotency_key="workload.test.0003",
            ephemeral_private=ephemeral,
            nonce=nonce,
        )
        with self.assertRaises(ComputeWorkloadIngressConflict):
            self.service.ingest(
                principal=self.principal,
                manifest=manifest,
                workload_commitment=commitment,
                idempotency_key="workload.test.0003",
                envelope=third,
            )

    def test_store_contains_ciphertext_but_not_plaintext_and_survives_restart(self):
        _, plaintext, _, envelope, created = self.ingest()
        all_bytes = b"".join(
            path.read_bytes() for path in self.root.rglob("*") if path.is_file()
        )
        self.assertNotIn(plaintext, all_bytes)
        self.assertNotIn(b"private sequence observation", all_bytes)
        self.assertIn(envelope.ciphertext.encode("ascii"), all_bytes)
        for path in self.root.rglob("*"):
            if path.is_file():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        restarted = ComputeWorkloadIngressStore(
            self.root,
            integrity_key=b"i" * 32,
        )
        observed = restarted.public_metadata(
            created.workload_id,
            project_commitment=self.principal.project_commitment,
        )
        self.assertEqual(observed["workload_id"], created.workload_id)
        restarted.close()

    def test_restart_completes_interrupted_one_shot_deletion(self):
        _, _, _, _, created = self.ingest()
        with self.store._exclusive_lock():
            records = self.store._load_index()
            record = next(iter(records.values()))
            deleting = dict(records)
            deleting[record.idempotency_hash] = replace(
                record,
                lifecycle="deleting",
            )
            self.store._persist_index(deleting)
        self.store.close()

        restarted = ComputeWorkloadIngressStore(
            self.root,
            integrity_key=b"i" * 32,
        )
        try:
            self.assertEqual(list((self.root / "envelopes").iterdir()), [])
            with self.assertRaises(ComputeWorkloadIngressError):
                restarted.get_for_project(
                    created.workload_id,
                    project_commitment=self.principal.project_commitment,
                )
            self.assertEqual(restarted._load_index(), {})
        finally:
            restarted.close()

    def test_consume_handoff_deletes_ciphertext_and_zeroizes_plaintext(self):
        _, _sealed_plaintext, _, _, created = self.ingest()
        private_payload = _canonical(
            {
                "schema": INFERENCE_PAYLOAD_SCHEMA,
                "prompt": "private sequence observation",
            }
        )
        retained_buffer = None
        with self.service.consume_for_execution(
            created.workload_id,
            project_commitment=self.principal.project_commitment,
        ) as lease:
            self.assertEqual(bytes(lease.plaintext), private_payload)
            self.assertTrue(lease.validated.valid)
            self.assertNotIn("private sequence observation", repr(lease))
            retained_buffer = lease.plaintext
        self.assertIsNotNone(retained_buffer)
        self.assertEqual(bytes(retained_buffer), b"\x00" * len(private_payload))
        self.assertEqual(list((self.root / "envelopes").iterdir()), [])
        with self.assertRaises(ComputeWorkloadIngressError):
            self.store.get_for_project(
                created.workload_id,
                project_commitment=self.principal.project_commitment,
            )

    def test_execution_accepts_fresh_qvl_quote_for_same_stable_release(self):
        _, _, _, _, created = self.ingest()
        upload_activation_commitment = self.activation.commitment
        refreshed = _authenticated_activation(self.recipient, sequence=1)
        self.assertNotEqual(refreshed.commitment, upload_activation_commitment)
        self.assertEqual(
            refreshed.recipient_release_commitment,
            self.activation.recipient_release_commitment,
        )
        self.provider.activation = refreshed

        with self.service.consume_for_execution(
            created.workload_id,
            project_commitment=self.principal.project_commitment,
        ) as lease:
            self.assertIn(b"private sequence observation", lease.plaintext)
        self.assertEqual(list((self.root / "envelopes").iterdir()), [])

    def test_stale_or_release_mismatched_qvl_recheck_preserves_ciphertext(self):
        _, _, _, _, created = self.ingest()
        self.service.clock = lambda: NOW + 91
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            with self.service.consume_for_execution(
                created.workload_id,
                project_commitment=self.principal.project_commitment,
            ):
                pass
        self.assertEqual(len(list((self.root / "envelopes").iterdir())), 1)

        self.service.clock = lambda: NOW
        mismatched = _authenticated_activation(
            self.recipient,
            sequence=2,
            release_policy_hash="0x" + "81" * 32,
        )
        self.provider.activation = mismatched
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            with self.service.consume_for_execution(
                created.workload_id,
                project_commitment=self.principal.project_commitment,
            ):
                pass
        self.assertEqual(len(list((self.root / "envelopes").iterdir())), 1)
        observed = self.store.get_for_project(
            created.workload_id,
            project_commitment=self.principal.project_commitment,
        )
        self.assertEqual(
            observed.binding.activation_commitment,
            self.activation.commitment,
        )

    def test_store_detects_authenticated_index_tamper_and_symlink(self):
        self.ingest()
        index = self.root / "index.json"
        raw = bytearray(index.read_bytes())
        raw[-3] ^= 1
        index.write_bytes(bytes(raw))
        os.chmod(index, 0o600)
        with self.assertRaises(ComputeWorkloadIngressCorrupt):
            self.store.public_metadata(
                "wrk_" + "00" * 16,
                project_commitment=self.principal.project_commitment,
            )

        symlink_root = Path(self.temporary.name) / "symlink-store"
        symlink_root.mkdir(mode=0o700)
        target = Path(self.temporary.name) / "unsafe-index"
        target.write_text("{}", encoding="utf-8")
        os.chmod(target, 0o600)
        (symlink_root / "index.json").symlink_to(target)
        with self.assertRaises(ComputeWorkloadIngressCorrupt):
            ComputeWorkloadIngressStore(
                symlink_root,
                integrity_key=b"s" * 32,
            )

    def test_activation_and_real_dstack_gates_run_before_persistence(self):
        manifest, plaintext, commitment = self.inference()
        envelope = self.envelope(manifest, plaintext, commitment)
        blocked = ComputeWorkloadIngressService(
            self.store,
            self.recipient,
            UnavailableComputeWorkloadActivationProvider(),
            clock=lambda: NOW,
        )
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            blocked.ingest(
                principal=self.principal,
                manifest=manifest,
                workload_commitment=commitment,
                idempotency_key="workload.test.0001",
                envelope=envelope,
            )
        self.assertEqual(list((self.root / "envelopes").iterdir()), [])

        with patch.object(dstack_utils, "is_dstack_simulator", return_value=True):
            with self.assertRaises(ComputeWorkloadIngressUnavailable):
                self.service.current_activation()
        local_keypair = TEEKeyPair.from_private_key_hex("41" * 32)
        local_recipient = ComputeWorkloadRecipient.from_keypair(
            local_keypair,
            custody_mode="local",
            recipient_attestation=_recipient_attestation(
                local_keypair.public_key_bytes
            ),
        )
        local_activation = _authenticated_activation(local_recipient)
        local = ComputeWorkloadIngressService(
            self.store,
            local_recipient,
            TestOnlyActivationProvider(local_activation),
            clock=lambda: NOW,
        )
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            local.current_activation()

    def test_browser_contract_never_enables_provider_dispatch(self):
        live = compute_workload_browser_contract(
            self.recipient,
            activation=self.activation,
            max_envelopes=100,
        )
        blocked = compute_workload_browser_contract(
            self.recipient,
            activation=None,
            max_envelopes=100,
        )
        self.assertTrue(live["upload_enabled"])
        self.assertTrue(live["recipient"]["independent_tdx_verdict_authenticated"])
        self.assertEqual(live["activation"]["verdict_digest"], self.activation.verdict_digest)
        self.assertEqual(
            live["activation"]["authenticated_verdict"]["profile"],
            "compute_workload",
        )
        self.assertFalse(live["gates"]["provider_dispatch_enabled"])
        self.assertFalse(blocked["upload_enabled"])
        self.assertIsNone(blocked["activation"])

    def test_activation_cannot_be_created_from_boolean_or_forged_verdict(self):
        with self.assertRaises(TypeError):
            ComputeWorkloadRecipientActivation(  # type: ignore[call-arg]
                independent_tdx_verdict_verified=True
            )

        trusted_qvl = Account.from_key(bytes.fromhex("75" * 32))
        attacker = Account.from_key(bytes.fromhex("76" * 32))
        with self.assertRaises(ComputeWorkloadIngressUnavailable):
            _authenticated_activation(
                self.recipient,
                qvl=trusted_qvl,
                signing_account=attacker,
            )


if __name__ == "__main__":
    unittest.main()
