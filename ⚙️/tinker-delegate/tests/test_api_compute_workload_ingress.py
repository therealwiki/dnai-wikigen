import base64
import hashlib
import json
import os
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
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.compute_auth import COMPUTE_CREDENTIAL_HKDF_INFO
from tinker_delegate.compute_workload_ingress import (
    INFERENCE_PAYLOAD_SCHEMA,
    INFERENCE_WORKLOAD_SCHEMA,
    WORKLOAD_HKDF_INFO,
    WORKLOAD_INGRESS_ALGORITHM,
    WORKLOAD_INGRESS_ENCODING,
    ComputeWorkloadEnvelope,
    ComputeWorkloadIngressService,
    ComputeWorkloadIngressStore,
    ComputeWorkloadManifest,
    ComputeWorkloadPrincipal,
    ComputeWorkloadRecipient,
    ComputeWorkloadRecipientActivation,
    UnavailableComputeWorkloadActivationProvider,
    authenticate_compute_workload_recipient_activation,
    build_compute_workload_plaintext,
    compute_workload_aad,
    compute_workload_commitment,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import TEEKeyPair, _derive_aes_key
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationExpectation,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)
from tinker_delegate.request_body_limits import (
    COMPUTE_WORKLOAD_REQUEST_MAX_BYTES,
)


PRIVATE_KEY = "0x" + "51" * 32
WALLET_KEY = "workload-wallet-auth-test-key-" + "w" * 48
CREDENTIAL_KEY = "workload-device-auth-test-key-" + "c" * 48
STORE_KEY = "workload-compute-store-test-key-" + "s" * 48
NOW = 1_800_000_000
TEE_SIGNER = "0x" + "71" * 20
COMPUTE_VAULT = "0x" + "72" * 20
RELEASE_POLICY_HASH = "0x" + "64" * 32
COMPOSE_HASH = "0x" + "62" * 32
OS_IMAGE_HASH = "63" * 32
QUOTE_HASH = "0x" + "65" * 32
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


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


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
) -> ComputeWorkloadRecipientActivation:
    qvl = Account.from_key(bytes.fromhex("66" * 32))
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
        release_policy_hash=RELEASE_POLICY_HASH,
        challenge_id=CHALLENGE_ID,
        challenge_digest=CHALLENGE_DIGEST,
        challenge_issued_at=NOW - 20,
        challenge_expires_at=NOW + 100,
        quote_hash=QUOTE_HASH,
        report_data="0x" + recipient.report_data.hex(),
        compose_hash=COMPOSE_HASH,
        app_id="a2" * 20,
        os_image_hash=OS_IMAGE_HASH,
        signer_address=TEE_SIGNER,
        contract_address=COMPUTE_VAULT,
        issued_at=NOW - 10,
        activation_evidence_lease_expires_at=NOW + 90,
        expires_at=NOW + 90,
        verifier_address=qvl.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    signed = qvl.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    )
    verdict = replace(
        unsigned,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )
    return authenticate_compute_workload_recipient_activation(
        recipient=recipient,
        verdict=verdict,
        expectation=IndependentAttestationExpectation(
            trusted_verifier_addresses=(qvl.address,),
            chain_id=84_532,
            domain="main_runtime_cvm",
            profile="compute_workload",
            cvm_id=CVM_ID,
            deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            ceremony_nonce=CEREMONY_NONCE,
            measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
            release_policy_hash=RELEASE_POLICY_HASH,
            challenge_id=CHALLENGE_ID,
            challenge_digest=CHALLENGE_DIGEST,
            challenge_issued_at=NOW - 20,
            challenge_expires_at=NOW + 100,
            quote_hash=QUOTE_HASH,
            report_data="0x" + recipient.report_data.hex(),
            compose_hash=COMPOSE_HASH,
            app_id="a2" * 20,
            os_image_hash=OS_IMAGE_HASH,
            signer_address=TEE_SIGNER,
            contract_address=COMPUTE_VAULT,
            max_age_seconds=300,
        ),
        measurement_policy_set_sha256=MEASUREMENT_POLICY_SET_SHA256,
        main_runtime_evidence_sha256=MAIN_RUNTIME_EVIDENCE_SHA256,
        now=NOW,
    )


class TestOnlyActivationProvider:
    def __init__(self, activation):
        self.activation = activation

    def verified_activation(self, _recipient, *, now):
        del now
        return self.activation


class ComputeWorkloadApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {"DSTACK_ENABLED": "false", "TINKER_DSTACK_ENABLED": "false"},
        )
        self.env.start()
        self.original_settings = api.settings
        api.settings = Settings(
            compute_wallet_auth_signing_key=WALLET_KEY,
            compute_credential_signing_key=CREDENTIAL_KEY,
            compute_store_integrity_key=STORE_KEY,
            compute_store_path=str(Path(self.temporary.name) / "compute.json"),
        )
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_workload_ingress_instance = None
        api._compute_workload_ingress_instance_identity = None
        self.client = TestClient(api.app)
        self.account = Account.from_key(PRIVATE_KEY)
        self.headers = self._wallet_headers()
        self.project_id = self._project()

        self.recipient_private = bytes.fromhex("61" * 32)
        keypair = TEEKeyPair.from_private_key_hex(self.recipient_private.hex())
        self.recipient = ComputeWorkloadRecipient.from_keypair(
            keypair,
            custody_mode="dstack",
            recipient_attestation=_recipient_attestation(
                keypair.public_key_bytes
            ),
        )
        self.activation = _authenticated_activation(self.recipient)
        self.ingress_store = ComputeWorkloadIngressStore(
            Path(self.temporary.name) / "workloads",
            integrity_key=b"i" * 32,
        )
        self.ingress = ComputeWorkloadIngressService(
            self.ingress_store,
            self.recipient,
            TestOnlyActivationProvider(self.activation),
            clock=lambda: NOW,
        )
        self.ingress_patch = patch.object(
            api,
            "_get_compute_workload_ingress",
            return_value=self.ingress,
        )
        self.ingress_patch.start()
        self.activation_patch = patch.object(
            self.ingress,
            "current_activation",
            return_value=self.activation,
        )
        self.activation_patch.start()

    def tearDown(self):
        self.activation_patch.stop()
        self.ingress_patch.stop()
        self.ingress_store.close()
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_workload_ingress_instance = None
        api._compute_workload_ingress_instance_identity = None
        api.settings = self.original_settings
        self.env.stop()
        self.temporary.cleanup()

    def _wallet_headers(self):
        challenge = self.client.post(
            "/auth/compute/challenge",
            json={"address": self.account.address},
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        signature = self.account.sign_message(
            encode_defunct(text=challenge.json()["message"])
        ).signature.hex()
        token = self.client.post(
            "/auth/compute/token",
            json={"nonce": challenge.json()["nonce"], "signature": signature},
        )
        self.assertEqual(token.status_code, 200, token.text)
        return {"Authorization": f"Bearer {token.json()['access_token']}"}

    def _project(self):
        created = self.client.post(
            "/compute/projects",
            json={"name": "sealed-workload-lab"},
            headers={**self.headers, "Idempotency-Key": "workload-project-0001"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        return created.json()["project"]["project_id"]

    @staticmethod
    def _decrypt_capsule(body, private_key):
        capsule = body["capsule"]
        encrypted = capsule["encrypted_token"]
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(
                bytes.fromhex(encrypted["ephemeral_public_key"])
            )
        )
        return AESGCM(
            _derive_aes_key(shared, info=COMPUTE_CREDENTIAL_HKDF_INFO)
        ).decrypt(
            bytes.fromhex(encrypted["nonce"]),
            bytes.fromhex(encrypted["ciphertext"]),
            bytes.fromhex(capsule["associated_data"]),
        ).decode()

    def _credential(self, scopes):
        private = X25519PrivateKey.generate()
        device = self.client.post(
            f"/compute/projects/{self.project_id}/devices",
            json={
                "label": "sealed-workload-agent",
                "kind": "autonomous_agent",
                "public_key": private.public_key().public_bytes_raw().hex(),
            },
            headers=self.headers,
        )
        self.assertEqual(device.status_code, 200, device.text)
        issued = self.client.post(
            f"/compute/projects/{self.project_id}/credentials",
            json={
                "device_id": device.json()["device"]["device_id"],
                "name": "workload-agent",
                "scopes": scopes,
                "expires_in_seconds": 3600,
                "daily_credit_cap": 100,
            },
            headers=self.headers,
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        return (
            issued.json()["credential"]["credential_id"],
            self._decrypt_capsule(issued.json(), private),
        )

    def _payload(self, principal, *, prompt="SECRET PRIVATE DNA PROMPT"):
        private_payload = _canonical(
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
            private_payload,
            blinding=b"\x71" * 32,
        )
        commitment = compute_workload_commitment(manifest, plaintext)
        binding = self.ingress.binding_for(
            principal=principal,
            manifest=manifest,
            workload_commitment=commitment,
            idempotency_key="workload-upload-0001",
            activation=self.activation,
        )
        aad = compute_workload_aad(binding)
        ephemeral = X25519PrivateKey.generate()
        shared = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(self.recipient.public_key)
        )
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=WORKLOAD_HKDF_INFO,
        ).derive(shared)
        nonce = b"\x73" * 12
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        envelope = ComputeWorkloadEnvelope(
            schema_version=1,
            algorithm=WORKLOAD_INGRESS_ALGORITHM,
            encoding=WORKLOAD_INGRESS_ENCODING,
            key_id=self.recipient.key_id,
            attestation_report_data=self.recipient.report_data.hex(),
            activation_commitment=self.activation.commitment,
            aad=_b64(aad),
            ephemeral_public_key=_b64(ephemeral.public_key().public_bytes_raw()),
            nonce=_b64(nonce),
            ciphertext=_b64(ciphertext),
        )
        return {
            "workload_commitment": commitment,
            "manifest": manifest.to_dict(),
            "envelope": envelope.to_dict(),
        }

    def test_wallet_upload_metadata_and_explicit_deletion_never_egress_private_data(self):
        principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id=self.project_id,
            actor_id=self.account.address,
        )
        payload = self._payload(principal)
        created = self.client.post(
            f"/compute/projects/{self.project_id}/workloads",
            json=payload,
            headers={**self.headers, "Idempotency-Key": "workload-upload-0001"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        self.assertNotIn("SECRET PRIVATE DNA PROMPT", created.text)
        workload_id = created.json()["workload_id"]
        metadata = self.client.get(
            f"/compute/projects/{self.project_id}/workloads/{workload_id}",
            headers=self.headers,
        )
        self.assertEqual(metadata.status_code, 200, metadata.text)
        self.assertNotIn("ciphertext\"", metadata.text)
        self.assertNotIn("content_bytes", metadata.text)
        self.assertEqual(metadata.json()["payload_size_class"], "4k")
        self.assertEqual(
            created.json()["recipient_release_commitment"],
            self.activation.recipient_release_commitment,
        )
        self.assertEqual(
            metadata.json()["recipient_release_commitment"],
            self.activation.recipient_release_commitment,
        )
        deleted = self.client.delete(
            f"/compute/projects/{self.project_id}/workloads/{workload_id}",
            headers=self.headers,
        )
        self.assertEqual(deleted.status_code, 200, deleted.text)
        self.assertTrue(deleted.json()["deleted"])
        self.assertEqual(list((Path(self.temporary.name) / "workloads" / "envelopes").iterdir()), [])
        missing = self.client.get(
            f"/compute/projects/{self.project_id}/workloads/{workload_id}",
            headers=self.headers,
        )
        self.assertEqual(missing.status_code, 404, missing.text)

    def test_purpose_scoped_device_can_upload_but_runtime_bearer_cannot(self):
        credential_id, token = self._credential(
            ["workloads:create", "jobs:read", "workloads:delete"]
        )
        principal = ComputeWorkloadPrincipal(
            kind="credential",
            project_id=self.project_id,
            actor_id=credential_id,
        )
        payload = self._payload(principal)
        uploaded = self.client.post(
            f"/compute/projects/{self.project_id}/workloads",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "workload-upload-0001",
            },
        )
        self.assertEqual(uploaded.status_code, 200, uploaded.text)
        rejected = self.client.post(
            f"/compute/projects/{self.project_id}/workloads",
            json=payload,
            headers={
                "Authorization": "Bearer runtime-operator-token",
                "Idempotency-Key": "workload-runtime-0001",
            },
        )
        self.assertEqual(rejected.status_code, 401, rejected.text)

    def test_contract_and_self_attestation_keep_evidence_boundary_explicit(self):
        contract = self.client.get("/compute/workload-encryption-contract")
        self.assertEqual(contract.status_code, 200, contract.text)
        self.assertTrue(contract.json()["upload_enabled"])
        self.assertFalse(contract.json()["gates"]["provider_dispatch_enabled"])
        self.assertEqual(
            contract.json()["activation"]["authenticated_verdict"]["profile"],
            "compute_workload",
        )
        self.assertEqual(
            contract.json()["activation"]["recipient_release_commitment"],
            self.activation.recipient_release_commitment,
        )
        self.assertEqual(
            contract.json()["recipient"]["recipient_release_commitment"],
            self.activation.recipient_release_commitment,
        )
        self.assertTrue(
            contract.json()["recipient"]["independent_tdx_verdict_authenticated"]
        )
        attestation = self.client.get("/attestation?context=compute_workload")
        self.assertEqual(attestation.status_code, 200, attestation.text)
        self.assertFalse(attestation.json()["verified"])
        self.assertEqual(
            attestation.json()["report_context"],
            "compute_workload",
        )

    def test_unavailable_activation_fails_before_ciphertext_persistence(self):
        principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id=self.project_id,
            actor_id=self.account.address,
        )
        payload = self._payload(principal)
        blocked = ComputeWorkloadIngressService(
            self.ingress_store,
            self.recipient,
            UnavailableComputeWorkloadActivationProvider(),
            clock=lambda: NOW,
        )
        with patch.object(api, "_get_compute_workload_ingress", return_value=blocked):
            response = self.client.post(
                f"/compute/projects/{self.project_id}/workloads",
                json=payload,
                headers={**self.headers, "Idempotency-Key": "workload-upload-0001"},
            )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(list((Path(self.temporary.name) / "workloads" / "envelopes").iterdir()), [])

    def test_plaintext_fields_are_structurally_rejected_without_reflection(self):
        principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id=self.project_id,
            actor_id=self.account.address,
        )
        payload = self._payload(principal)
        payload["prompt"] = "SECRET SHOULD NOT BE REFLECTED"
        response = self.client.post(
            f"/compute/projects/{self.project_id}/workloads",
            json=payload,
            headers={**self.headers, "Idempotency-Key": "workload-extra-0001"},
        )
        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn("SECRET SHOULD NOT BE REFLECTED", response.text)

    def test_route_body_limit_rejects_before_auth_or_json_buffering(self):
        response = self.client.post(
            f"/compute/projects/{self.project_id}/workloads",
            content=b"x" * (COMPUTE_WORKLOAD_REQUEST_MAX_BYTES + 1),
            headers={
                **self.headers,
                "Content-Type": "application/json",
                "Idempotency-Key": "workload-oversize-0001",
            },
        )
        self.assertEqual(response.status_code, 413, response.text)
        self.assertNotIn("xxxx", response.text)
        self.assertEqual(
            list((Path(self.temporary.name) / "workloads" / "envelopes").iterdir()),
            [],
        )


if __name__ == "__main__":
    unittest.main()
