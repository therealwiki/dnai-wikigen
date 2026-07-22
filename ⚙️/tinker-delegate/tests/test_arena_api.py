import base64
import hashlib
import json
import tempfile
import time
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
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.arena_ingress import (
    INGRESS_ALGORITHM,
    INGRESS_ENCODING,
    INGRESS_HKDF_INFO,
    arena_candidate_aad,
    build_arena_candidate_binding,
)
from tinker_delegate.arena_store import (
    BIO_CANDIDATE_KIND,
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    BIO_ENTRYPOINT,
    BIO_RUNTIME,
    SubmissionIdentity,
    SubmissionManifest,
    SubmissionMode,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_evidence import (
    ArenaWorkerEvidenceError,
    ArenaWorkerHeartbeat,
    ArenaWorkerReleaseBindings,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
    encode_safe_ir_program,
)
from tinker_delegate.arena_registry_admission import (
    ArenaRegistryAdmissionError,
    ArenaRegistryAuthorizationSnapshot,
    ArenaRegistryIngressAuthorization,
)
from tinker_delegate.config import Settings


LOCAL_SIGNING_KEY = "local-test-arena-api-wallet-key-" + ("9" * 48)
SUBMITTER_KEY = "0x" + ("55" * 32)
RUNTIME_TOKEN = "arena-runtime-operator-token-" + ("8" * 40)


def _signature(message: str, private_key: str) -> str:
    return Account.sign_message(
        encode_defunct(text=message),
        private_key=private_key,
    ).signature.hex()


class ArenaApiTest(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.store_path = Path(self.tempdir.name) / "arena.json"
        self.ingress_path = Path(self.tempdir.name) / "arena-candidates"
        self.ingress_key_path = Path(self.tempdir.name) / "arena-ingress.key"
        self.original_settings = api.settings
        self.original_store = api._arena_store_instance
        self.original_store_path = api._arena_store_instance_path
        self.original_ingress = api._arena_ingress_service_instance
        self.original_ingress_identity = api._arena_ingress_service_identity
        self.registry_gate_patcher = patch(
            "tinker_delegate.arena_registry_admission.authorize_arena_registry_submission",
            side_effect=self._authorize_registry_snapshot,
        )
        self.registry_gate = self.registry_gate_patcher.start()
        api.settings = Settings(
            wallet_auth_signing_key=LOCAL_SIGNING_KEY,
            wallet_auth_domain="arena.example",
            wallet_auth_uri="https://arena.example",
            wallet_auth_chain_id=84532,
            arena_store_path=str(self.store_path),
            arena_candidate_ingress_store_path=str(self.ingress_path),
            arena_candidate_ingress_local_key_file=str(self.ingress_key_path),
            runtime_auth_required=True,
            runtime_auth_token=RUNTIME_TOKEN,
        )
        api._arena_store_instance = None
        api._arena_store_instance_path = ""
        api._arena_ingress_service_instance = None
        api._arena_ingress_service_identity = None
        api._arena_wallet_challenges.clear()
        api._wallet_challenges.clear()
        self.client = TestClient(api.app)
        self.submitter = Account.from_key(SUBMITTER_KEY)

    def tearDown(self):
        self.registry_gate_patcher.stop()
        api._arena_wallet_challenges.clear()
        api._wallet_challenges.clear()
        api._arena_store_instance = self.original_store
        api._arena_store_instance_path = self.original_store_path
        api._arena_ingress_service_instance = self.original_ingress
        api._arena_ingress_service_identity = self.original_ingress_identity
        api.settings = self.original_settings
        self.tempdir.cleanup()

    @staticmethod
    def _authorize_registry_snapshot(
        _settings, *, challenge, snapshot
    ) -> ArenaRegistryIngressAuthorization:
        if (
            snapshot.catalog_challenge_id != challenge.challenge_id
            or snapshot.catalog_challenge_version != challenge.version
            or snapshot.catalog_manifest_hash != challenge.manifest_hash
        ):
            raise AssertionError("test registry snapshot does not match challenge")
        return ArenaRegistryIngressAuthorization(
            snapshot_sha256=snapshot.sha256,
            chain_id=84_532,
            block_number=snapshot.block_number,
            block_hash=snapshot.block_hash,
            registry_address=snapshot.registry_address,
            registry_challenge_id=snapshot.registry_challenge_id,
            registry_version=snapshot.registry_version,
        )

    @staticmethod
    def _registry_snapshot(challenge) -> ArenaRegistryAuthorizationSnapshot:
        registry_id = (
            1 if challenge.challenge_id == DNASEQ_SAFE_IR_CHALLENGE_ID else 2
        )
        return ArenaRegistryAuthorizationSnapshot.from_mapping(
            {
                "schema_version": 1,
                "verification_model": (
                    "single_rpc_reported_finalized_pinned_block"
                ),
                "chain_id": 84_532,
                "block_number": "12345",
                "block_hash": "0x" + "f" * 64,
                "block_timestamp": "1700000000",
                "registry_address": "0x" + "1" * 40,
                "registry_runtime_code_hash": "0x" + "9" * 64,
                "approved_challenge_set_sha256": "sha256:" + "8" * 64,
                "catalog_challenge_id": challenge.challenge_id,
                "catalog_challenge_version": challenge.version,
                "catalog_manifest_hash": challenge.manifest_hash,
                "registry_challenge_id": str(registry_id),
                "registry_version": 7,
                "controller_address": "0x" + "2" * 40,
                "pending_controller_address": "0x" + "0" * 40,
                "metadata_uri": f"ipfs://arena-test-{registry_id}",
                "metadata_hash": "0x" + challenge.manifest_hash,
                "sealed_artifact_commitment": "0x" + "b" * 64,
                "evaluator_commitment": "0x" + "c" * 64,
                "release_policy_commitment": "0x" + "d" * 64,
                "registry_paused": False,
                "challenge_paused": False,
                "lifecycle": 1,
                "configuration_frozen": True,
                "latest_version": 7,
            }
        )

    def _arena_token(
        self,
        challenge_id: str = BIO_CHALLENGE_ID,
        challenge_version: str = BIO_CHALLENGE_VERSION,
    ) -> str:
        challenge = self.client.post(
            "/auth/arena/challenge",
            json={
                "address": self.submitter.address,
                "challenge_id": challenge_id,
                "challenge_version": challenge_version,
            },
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        body = challenge.json()
        self.assertIn("challenge:submit", body["message"])
        exchanged = self.client.post(
            "/auth/arena/token",
            json={
                "nonce": body["nonce"],
                "signature": _signature(body["message"], SUBMITTER_KEY),
            },
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        self.assertEqual(
            exchanged.json()["scopes"],
            ["challenge:submit", "challenge:submissions:read"],
        )
        return exchanged.json()["access_token"]

    def _deal_token(self) -> str:
        challenge = self.client.post(
            "/auth/wallet/challenge",
            json={"address": self.submitter.address, "deal_id": "7"},
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        body = challenge.json()
        exchanged = self.client.post(
            "/auth/wallet/token",
            json={
                "nonce": body["nonce"],
                "signature": _signature(body["message"], SUBMITTER_KEY),
            },
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        return exchanged.json()["access_token"]

    def _manifest(
        self,
        challenge_id: str = BIO_CHALLENGE_ID,
        challenge_version: str = BIO_CHALLENGE_VERSION,
        *,
        source_bytes: int = 512,
    ) -> dict:
        response = self.client.get(
            f"/arena/challenges/{challenge_id}/versions/{challenge_version}"
        )
        self.assertEqual(response.status_code, 200, response.text)
        challenge = response.json()
        return {
            "schema_version": 1,
            "challenge_manifest_hash": challenge["manifest_hash"],
            "candidate_kind": challenge["candidate"]["kind"],
            "runtime": challenge["candidate"]["runtime"],
            "entrypoint": challenge["candidate"]["entrypoint"],
            "source_bytes": source_bytes,
            "mode": "leaderboard",
        }

    def _submission_payload(
        self,
        *,
        key: str = "submission-1",
        commitment_byte: str = "a",
        envelope_changes: dict | None = None,
        challenge_id: str = BIO_CHALLENGE_ID,
        challenge_version: str = BIO_CHALLENGE_VERSION,
        source: bytes | None = None,
    ) -> dict:
        challenge = default_challenge_catalog().get(
            challenge_id, challenge_version
        )
        project_id = "personal-" + hashlib.sha256(
            b"arena-personal-project:" + self.submitter.address.lower().encode("ascii")
        ).hexdigest()[:32]
        identity = SubmissionIdentity(
            wallet_address=self.submitter.address.lower(),
            project_id=project_id,
        )
        candidate_source = source if source is not None else b"A" * 512
        manifest_dict = self._manifest(
            challenge_id,
            challenge_version,
            source_bytes=len(candidate_source),
        )
        manifest = SubmissionManifest.from_mapping(manifest_dict)
        commitment = (
            "sha256:" + hashlib.sha256(candidate_source).hexdigest()
            if source is not None
            else "sha256:" + (commitment_byte * 64)
        )
        registry_snapshot = self._registry_snapshot(challenge)
        ingress = api._get_arena_ingress()
        binding = build_arena_candidate_binding(
            challenge=challenge,
            identity=identity,
            candidate_commitment=commitment,
            manifest=manifest,
            recipient=ingress.recipient,
            idempotency_key=key,
            registry_authorization_sha256=registry_snapshot.sha256,
        )
        aad = arena_candidate_aad(binding)
        ephemeral = X25519PrivateKey.from_private_bytes(
            hashlib.sha256(
                b"arena-api-test-ephemeral\0"
                + key.encode("ascii")
                + commitment.encode("ascii")
            ).digest()
        )
        shared_secret = ephemeral.exchange(
            X25519PublicKey.from_public_bytes(ingress.recipient.public_key)
        )
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=INGRESS_HKDF_INFO,
        ).derive(shared_secret)
        nonce = hashlib.sha256(
            b"arena-api-test-nonce\0"
            + key.encode("ascii")
            + commitment.encode("ascii")
        ).digest()[:12]
        ciphertext = AESGCM(aes_key).encrypt(nonce, candidate_source, aad)

        def b64url(value: bytes) -> str:
            return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

        envelope = {
            "schema_version": 1,
            "algorithm": INGRESS_ALGORITHM,
            "encoding": INGRESS_ENCODING,
            "key_id": ingress.recipient.key_id,
            "attestation_report_data": ingress.recipient.report_data.hex(),
            "aad": b64url(aad),
            "ephemeral_public_key": b64url(
                ephemeral.public_key().public_bytes_raw()
            ),
            "nonce": b64url(nonce),
            "ciphertext": b64url(ciphertext),
        }
        if envelope_changes:
            envelope.update(envelope_changes)
        return {
            "candidate_commitment": commitment,
            "manifest": manifest_dict,
            "registry_authorization": registry_snapshot.to_dict(),
            "envelope": envelope,
        }

    def _submit(
        self,
        *,
        key: str = "submission-1",
        token: str | None = None,
        challenge_id: str = BIO_CHALLENGE_ID,
        challenge_version: str = BIO_CHALLENGE_VERSION,
        source: bytes | None = None,
    ):
        return self.client.post(
            f"/arena/challenges/{challenge_id}/versions/{challenge_version}/submissions",
            json=self._submission_payload(
                key=key,
                challenge_id=challenge_id,
                challenge_version=challenge_version,
                source=source,
            ),
            headers={
                "Authorization": f"Bearer {token or self._arena_token(challenge_id, challenge_version)}",
                "Idempotency-Key": key,
            },
        )

    def _runtime_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {RUNTIME_TOKEN}"}

    def _advance_to_sealed_eval(self, submission_id: str) -> None:
        for to_state, reason in (
            ("policy_screen", "policy_check_started"),
            ("queued", "policy_passed"),
            ("provisioning", "worker_claimed"),
            ("public_tests", "public_tests_started"),
            ("sealed_eval", "sealed_evaluation_started"),
        ):
            response = self.client.post(
                f"/arena/internal/submissions/{submission_id}/transition",
                json={"to_state": to_state, "reason": reason},
                headers=self._runtime_headers(),
            )
            self.assertEqual(response.status_code, 200, response.text)

    def test_public_catalog_exposes_dnaseq_safe_ir_without_claiming_deployment(self):
        response = self.client.get("/arena/challenges")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["surface"], "arena_challenge_catalog")
        self.assertEqual(body["challenge_count"], 2)
        by_id = {item["challenge_id"]: item for item in body["challenges"]}
        challenge = by_id[BIO_CHALLENGE_ID]
        self.assertEqual(challenge["challenge_id"], BIO_CHALLENGE_ID)
        self.assertEqual(challenge["version"], BIO_CHALLENGE_VERSION)
        self.assertTrue(challenge["data_policy"]["synthetic_only"])
        self.assertFalse(challenge["data_policy"]["raw_data_egress"])
        self.assertFalse(challenge["evaluation"]["exact_reward_egress"])
        self.assertEqual(challenge["product_status"], "modeled")
        self.assertFalse(challenge["execution_capability"]["live_execution"])
        self.assertFalse(challenge["execution_capability"]["hostile_code_ready"])
        safe_ir = by_id[DNASEQ_SAFE_IR_CHALLENGE_ID]
        self.assertEqual(safe_ir["challenge_id"], DNASEQ_SAFE_IR_CHALLENGE_ID)
        self.assertEqual(safe_ir["title"], "DNASeq Variant QC · Safe IR")
        self.assertEqual(safe_ir["environment"], "synthetic_dnaseq_variant_qc")
        self.assertEqual(safe_ir["evaluation"]["metric"], "variant_quality_z_prime")
        self.assertEqual(safe_ir["candidate"]["runtime"], "dnai-safe-ir-v1")
        self.assertFalse(safe_ir["execution_capability"]["worker_connected"])
        self.assertIn("Execution remains disabled", safe_ir["execution_capability"]["warning"])
        self.assertNotIn("seed", json.dumps(body).lower())

    def test_worker_capability_is_modeled_until_release_and_fresh_evidence_match(self):
        safe_path = (
            f"/arena/challenges/{DNASEQ_SAFE_IR_CHALLENGE_ID}/versions/"
            "1.0.0/worker-capability"
        )
        modeled = self.client.get(safe_path)
        self.assertEqual(modeled.status_code, 200, modeled.text)
        self.assertEqual(modeled.headers["cache-control"], "no-store, max-age=0")
        self.assertEqual(modeled.json()["schema_version"], 2)
        self.assertEqual(modeled.json()["status"], "modeled")
        self.assertEqual(
            modeled.json()["gate_reason"],
            "live_release_not_enabled",
        )
        self.assertFalse(modeled.json()["live_execution"])
        self.assertFalse(modeled.json()["tdx_attestation_egress"])
        self.assertIsNone(modeled.json()["heartbeat_observed_at"])
        self.assertIsNone(modeled.json()["heartbeat_binding_sha256"])
        self.assertIsNone(modeled.json()["release_binding_sha256"])

        challenge = default_challenge_catalog().get(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            "1.0.0",
        )
        bindings = ArenaWorkerReleaseBindings(
            release_sha="1" * 40,
            image_digest="sha256:" + "2" * 64,
            release_manifest_sha256="sha256:" + "3" * 64,
            approved_challenge_set_sha256="sha256:" + "7" * 64,
            approved_challenge_key=(
                f"{DNASEQ_SAFE_IR_CHALLENGE_ID}@{DNASEQ_SAFE_IR_CHALLENGE_VERSION}"
            ),
            release_policy_commitment="0x" + "4" * 64,
            catalog_manifest_hash=challenge.manifest_hash,
            runtime=SAFE_IR_RUNTIME,
            runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
            compose_hash="5" * 64,
            app_id="app_arena_api_live_test",
            os_image_hash="6" * 64,
        )
        heartbeat = ArenaWorkerHeartbeat(
            bindings=bindings,
            observed_at=int(time.time()),
            state="ready",
        )

        class FreshStore:
            def read(self):
                return heartbeat

        api.settings = api.settings.model_copy(
            update={
                "arena_worker_live_capability_enabled": True,
                "arena_worker_heartbeat_path": str(
                    Path(self.tempdir.name) / "heartbeat.json"
                ),
                "arena_worker_heartbeat_ttl_seconds": 30,
            }
        )
        with (
            patch(
                "tinker_delegate.arena_worker_evidence.arena_worker_expected_release_bindings",
                return_value=bindings,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.arena_worker_heartbeat_integrity_key",
                return_value=b"h" * 32,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.ArenaWorkerHeartbeatStore",
                return_value=FreshStore(),
            ),
        ):
            live = self.client.get(safe_path)
            python_preview = self.client.get(
                f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
                f"{BIO_CHALLENGE_VERSION}/worker-capability"
            )
        self.assertEqual(live.status_code, 200, live.text)
        self.assertEqual(live.json()["status"], "live")
        self.assertTrue(live.json()["live_execution"])
        self.assertEqual(
            live.json()["evidence_classification"],
            "authenticated_worker_presence_not_tdx_attestation",
        )
        self.assertEqual(live.json()["heartbeat_observed_at"], heartbeat.observed_at)
        self.assertRegex(
            live.json()["heartbeat_binding_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertRegex(
            live.json()["release_binding_sha256"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertEqual(live.json()["release_binding"], bindings.to_dict())
        self.assertNotIn("mac", live.json())
        self.assertNotIn("heartbeat", live.json())
        self.assertNotIn("integrity_key", live.json())
        self.assertEqual(python_preview.json()["gate_reason"], "python_preview_only")
        self.assertFalse(python_preview.json()["live_execution"])

        class TamperedStore:
            def read(self):
                raise ArenaWorkerEvidenceError("authentication failed")

        with (
            patch(
                "tinker_delegate.arena_worker_evidence.arena_worker_expected_release_bindings",
                return_value=bindings,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.arena_worker_heartbeat_integrity_key",
                return_value=b"h" * 32,
            ),
            patch(
                "tinker_delegate.arena_worker_evidence.ArenaWorkerHeartbeatStore",
                return_value=TamperedStore(),
            ),
        ):
            failed_closed = self.client.get(safe_path)
        self.assertEqual(failed_closed.json()["status"], "modeled")
        self.assertEqual(failed_closed.json()["gate_reason"], "evidence_invalid")
        self.assertFalse(failed_closed.json()["live_execution"])
        self.assertIsNone(failed_closed.json()["heartbeat_observed_at"])
        self.assertIsNone(failed_closed.json()["heartbeat_binding_sha256"])

    def test_encryption_contract_matches_stable_arena_attestation_and_never_claims_verified(self):
        contract_response = self.client.get("/arena/candidate-encryption-contract")
        self.assertEqual(contract_response.status_code, 200, contract_response.text)
        self.assertEqual(
            contract_response.headers["cache-control"], "no-store, max-age=0"
        )
        contract = contract_response.json()
        self.assertEqual(
            set(contract),
            {
                "surface",
                "schema_version",
                "product_status",
                "execution_assurance",
                "protocol",
                "encoding_rules",
                "aad",
                "recipient",
                "limits",
                "submission_gate",
                "envelope_exact_fields",
                "raw_secret_egress",
            },
        )
        self.assertEqual(contract["product_status"], "modeled")
        self.assertEqual(
            contract["protocol"]["algorithm"],
            "X25519-HKDF-SHA256-AES-256-GCM",
        )
        self.assertEqual(contract["limits"]["max_aad_bytes"], 4096)
        self.assertEqual(
            contract["limits"]["max_ciphertext_bytes_including_gcm_tag"],
            65536,
        )
        self.assertTrue(
            contract["submission_gate"]["fresh_cvm_attestation_required"]
        )
        self.assertFalse(
            contract["submission_gate"]["hostile_code_execution_enabled"]
        )
        self.assertEqual(
            set(contract["recipient"]),
            {
                "encryption_public_key",
                "key_id",
                "report_context",
                "report_data",
                "attestation_report_data_sha256",
                "report_data_contract",
            },
        )

        attestation_response = self.client.get("/attestation?context=arena")
        self.assertEqual(
            attestation_response.status_code, 200, attestation_response.text
        )
        attestation = attestation_response.json()
        self.assertEqual(attestation["mode"], "local")
        self.assertFalse(attestation["verified"])
        self.assertEqual(
            contract["recipient"]["encryption_public_key"],
            attestation["encryption_public_key"],
        )
        self.assertEqual(contract["recipient"]["report_data"], attestation["report_data"])

    def test_submission_requires_arena_token_and_token_domains_do_not_mix(self):
        url = (
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions"
        )
        payload = self._submission_payload()

        missing = self.client.post(
            url,
            json=payload,
            headers={"Idempotency-Key": "missing-auth"},
        )
        self.assertEqual(missing.status_code, 401, missing.text)

        deal_token = self._deal_token()
        wrong_domain = self.client.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {deal_token}",
                "Idempotency-Key": "wrong-domain",
            },
        )
        self.assertEqual(wrong_domain.status_code, 401, wrong_domain.text)

        runtime_domain = self.client.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "runtime-domain",
            },
        )
        self.assertEqual(runtime_domain.status_code, 401, runtime_domain.text)

    def test_finalized_advance_failure_precedes_every_durable_write(self):
        token = self._arena_token()
        payload = self._submission_payload(key="registry-no-write")
        fresh_store = Path(self.tempdir.name) / "blocked-arena.json"
        fresh_ingress = Path(self.tempdir.name) / "blocked-candidates"
        fresh_key = Path(self.tempdir.name) / "blocked-arena.key"
        api.settings = api.settings.model_copy(
            update={
                "arena_store_path": str(fresh_store),
                "arena_candidate_ingress_store_path": str(fresh_ingress),
                "arena_candidate_ingress_local_key_file": str(fresh_key),
            }
        )
        api._arena_store_instance = None
        api._arena_store_instance_path = ""
        api._arena_ingress_service_instance = None
        api._arena_ingress_service_identity = None
        self.registry_gate.side_effect = ArenaRegistryAdmissionError(
            "Arena registry finalized block advanced during verification"
        )
        response = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "registry-no-write",
            },
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            response.json(), {"detail": "Arena registry admission is unavailable"}
        )
        self.assertFalse(fresh_store.exists())
        self.assertFalse(fresh_ingress.exists())
        self.assertFalse(fresh_key.exists())

    def test_registry_snapshot_tamper_breaks_the_aead_binding(self):
        token = self._arena_token()
        payload = self._submission_payload(key="registry-aad-tamper")
        payload["registry_authorization"]["block_hash"] = "0x" + "e" * 64
        response = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "registry-aad-tamper",
            },
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("AAD", response.json()["detail"])

    def test_submit_is_idempotent_and_public_projection_omits_sealed_ref_and_wallet(self):
        token = self._arena_token()
        first = self._submit(token=token)
        self.assertEqual(first.status_code, 200, first.text)
        body = first.json()
        self.assertTrue(body["created"])
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(
            body["registry_ingress_boundary"],
            {
                "surface": "arena_registry_ingress_boundary",
                "schema_version": 1,
                "status": "proxy_independently_verified_at_finalized_block",
                "verification_model": (
                    "single_rpc_reported_finalized_pinned_block"
                ),
                "browser_preflight_accepted_as_authority": False,
                "proxy_registry_authorized": True,
                "worker_registry_authorized": False,
                "registry_authorization_sha256": (
                    self._registry_snapshot(
                        default_challenge_catalog().get(
                            BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION
                        )
                    ).sha256
                ),
                "chain_id": 84_532,
                "block_number": "12345",
                "block_hash": "0x" + "f" * 64,
                "registry_address": "0x" + "1" * 40,
                "registry_challenge_id": "2",
                "registry_version": 7,
                "independent_rpc_quorum_verified": False,
                "consensus_proof_verified": False,
            },
        )
        submission_id = body["submission"]["submission_id"]
        rendered = json.dumps(body, sort_keys=True)
        self.assertNotIn("sealed://arena", rendered)
        self.assertNotIn("candidate-", rendered)
        self.assertNotIn("object_id", rendered)
        self.assertNotIn(self.submitter.address.lower(), rendered.lower())
        self.assertFalse(body["candidate_ingress"]["sealed_reference_public"])
        self.assertTrue(body["candidate_ingress"]["created"])
        self.assertEqual(
            set(body["candidate_ingress"]),
            {
                "surface",
                "schema_version",
                "blob_sha256",
                "ciphertext_sha256",
                "key_id",
                "created",
                "idempotent_replay",
                "sealed_reference_public",
                "plaintext_candidate_accepted",
                "product_status",
                "execution_assurance",
                "raw_secret_egress",
                "private_size_egress",
            },
        )
        self.assertFalse(body["candidate_ingress"]["private_size_egress"])
        self.assertNotIn("source_bytes", body["submission"]["manifest"])
        self.assertFalse(body["submission"]["manifest"]["private_size_egress"])
        self.assertEqual(body["submission"]["product_status"], "modeled")
        self.assertEqual(body["submission"]["schema_version"], 2)
        self.assertEqual(
            body["submission"]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertFalse(
            body["submission"]["execution_provenance"][
                "independently_verified_by_client"
            ]
        )
        self.assertEqual(
            body["submission"]["execution_assurance"],
            "projection_only_no_hardened_executor",
        )
        self.assertFalse(body["submission"]["execution_capability"]["live_execution"])
        self.assertFalse(body["submission"]["exact_timing_egress"])
        for timing_key in ("created_at", "updated_at", "occurred_at", "ladder_released_at"):
            self.assertNotIn(timing_key, rendered)

        replay = self._submit(token=token)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertFalse(replay.json()["created"])
        self.assertTrue(replay.json()["idempotent_replay"])
        self.assertFalse(replay.json()["candidate_ingress"]["created"])
        self.assertTrue(replay.json()["candidate_ingress"]["idempotent_replay"])
        self.assertEqual(replay.json()["submission"]["submission_id"], submission_id)

        changed = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions",
            json=self._submission_payload(commitment_byte="b"),
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "submission-1",
            },
        )
        self.assertEqual(changed.status_code, 409, changed.text)

    def test_dnaseq_safe_ir_submission_is_ciphertext_only_and_deep_queue_ready(self):
        source = encode_safe_ir_program(
            positive_pipeline=[
                {"op": "sort"},
                {"op": "trim", "low": 1, "high": 1},
            ],
            negative_pipeline=[
                {"op": "mad_filter", "threshold_milli": 3000}
            ],
        )
        submitted = self._submit(
            key="dnaseq-safe-ir",
            challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
            challenge_version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
            source=source,
        )
        self.assertEqual(submitted.status_code, 200, submitted.text)
        body = submitted.json()
        self.assertEqual(
            body["submission"]["challenge_id"],
            DNASEQ_SAFE_IR_CHALLENGE_ID,
        )
        self.assertEqual(body["submission"]["manifest"]["runtime"], SAFE_IR_RUNTIME)
        self.assertEqual(
            body["submission"]["manifest"]["entrypoint"],
            "select_variant_evidence",
        )
        self.assertEqual(
            body["submission"]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertFalse(body["submission"]["encrypted_reference_public"])
        self.assertNotIn(source.decode("ascii"), submitted.text)

        queue = self.client.get(
            f"/arena/challenges/{DNASEQ_SAFE_IR_CHALLENGE_ID}/versions/"
            f"{DNASEQ_SAFE_IR_CHALLENGE_VERSION}/queue"
        )
        self.assertEqual(queue.status_code, 200, queue.text)
        projection = queue.json()
        self.assertEqual(projection["schema_version"], 2)
        self.assertEqual(projection["product_status"], "per_row")
        self.assertEqual(
            projection["execution_assurance"],
            "per_submission_execution_provenance",
        )
        self.assertEqual(projection["submissions"][0]["product_status"], "modeled")
        self.assertEqual(
            projection["submissions"][0]["execution_provenance"]["status"],
            "not_executed",
        )
        persisted = self.store_path.read_text(encoding="utf-8")
        self.assertNotIn(source.decode("ascii"), persisted)

    def test_wallet_authenticated_my_submissions_is_bounded_filtered_and_paginated(self):
        token = self._arena_token()
        first = self._submit(key="mine-first", token=token)
        second = self._submit(key="mine-second", token=token)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(second.status_code, 200, second.text)

        challenge = default_challenge_catalog().get(
            BIO_CHALLENGE_ID,
            BIO_CHALLENGE_VERSION,
        )
        outsider = api._get_arena_store().submit(
            challenge_id=BIO_CHALLENGE_ID,
            challenge_version=BIO_CHALLENGE_VERSION,
            identity=SubmissionIdentity(
                wallet_address="0x" + "77" * 20,
                project_id="outsider-project",
            ),
            candidate_commitment="sha256:" + "7" * 64,
            encrypted_reference="sealed://candidates/outsider-private",
            manifest=SubmissionManifest(
                schema_version=1,
                challenge_manifest_hash=challenge.manifest_hash,
                candidate_kind=challenge.candidate_kind,
                runtime=challenge.runtime,
                entrypoint=challenge.entrypoint,
                source_bytes=128,
                mode=SubmissionMode.LEADERBOARD,
            ),
            idempotency_key="outsider-private",
            submitted_at=1,
        ).submission

        path = (
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions/mine"
        )
        denied = self.client.get(path)
        self.assertEqual(denied.status_code, 401, denied.text)
        wrong_domain = self.client.get(
            path,
            headers={"Authorization": f"Bearer {self._deal_token()}"},
        )
        self.assertEqual(wrong_domain.status_code, 401, wrong_domain.text)

        page_one = self.client.get(
            path + "?limit=1&wallet_address=0x" + "77" * 20,
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(page_one.status_code, 200, page_one.text)
        self.assertEqual(page_one.headers["cache-control"], "no-store, max-age=0")
        body = page_one.json()
        self.assertEqual(body["surface"], "arena_owner_submissions")
        self.assertEqual(body["page_count"], 1)
        self.assertTrue(body["has_more"])
        self.assertNotEqual(body["submissions"][0]["submission_id"], outsider.submission_id)
        rendered = json.dumps(body, sort_keys=True)
        self.assertNotIn(self.submitter.address.lower(), rendered.lower())
        self.assertNotIn("0x" + "77" * 20, rendered.lower())
        self.assertNotIn(outsider.submission_id, rendered)
        self.assertNotIn("sealed://", rendered)
        self.assertNotIn("encrypted_reference\"", rendered)
        self.assertNotIn("source_bytes", rendered)
        self.assertNotIn("queue_events", rendered)
        self.assertFalse(body["exact_score_egress"])
        self.assertFalse(body["exact_reward_egress"])
        self.assertFalse(body["exact_timing_egress"])
        self.assertFalse(body["internal_error_egress"])
        for timing_key in ("created_at", "updated_at", "occurred_at", "ladder_released_at"):
            self.assertNotIn(timing_key, rendered)

        page_two = self.client.get(
            path + f"?limit=1&cursor={body['next_cursor']}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(page_two.status_code, 200, page_two.text)
        self.assertEqual(page_two.json()["page_count"], 1)
        self.assertFalse(page_two.json()["has_more"])
        self.assertIsNone(page_two.json()["next_cursor"])

        foreign_cursor = self.client.get(
            path + f"?cursor={outsider.submission_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(foreign_cursor.status_code, 400, foreign_cursor.text)
        oversized = self.client.get(
            path + "?limit=101",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(oversized.status_code, 400, oversized.text)

    def test_plaintext_and_caller_reference_are_rejected_without_echo_or_persistence(self):
        token = self._arena_token()
        payload = self._submission_payload()
        payload["source_code"] = "SUPER_SECRET_CANDIDATE = 42"
        plaintext = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "plaintext-field",
            },
        )
        self.assertEqual(plaintext.status_code, 422, plaintext.text)
        self.assertNotIn("SUPER_SECRET_CANDIDATE", plaintext.text)

        payload = self._submission_payload()
        payload["encrypted_reference"] = "r2://bucket/object?token=secret"
        credential_ref = self.client.post(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/submissions",
            json=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "credential-reference",
            },
        )
        self.assertEqual(credential_ref.status_code, 422, credential_ref.text)
        self.assertNotIn("token=secret", credential_ref.text)
        persisted = self.store_path.read_text(encoding="utf-8") + "\n" + "\n".join(
            path.read_text(encoding="utf-8")
            for path in self.ingress_path.rglob("*")
            if path.is_file()
        )
        self.assertNotIn("SUPER_SECRET_CANDIDATE", persisted)
        self.assertNotIn("token=secret", persisted)
        self.assertIn('"raw_candidate_persisted":false', persisted)

    def test_tampered_and_oversized_envelopes_fail_without_ciphertext_persistence(self):
        token = self._arena_token()
        url = (
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/"
            f"{BIO_CHALLENGE_VERSION}/submissions"
        )
        tampered = self._submission_payload(key="tampered-aad")
        tampered["envelope"]["aad"] = "e30"
        rejected = self.client.post(
            url,
            json=tampered,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "tampered-aad",
            },
        )
        self.assertEqual(rejected.status_code, 400, rejected.text)
        self.assertNotIn(tampered["envelope"]["ciphertext"], rejected.text)

        oversized = self._submission_payload(key="oversized-envelope")
        oversized["envelope"]["ciphertext"] = "A" * 87_383
        rejected = self.client.post(
            url,
            json=oversized,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "oversized-envelope",
            },
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        envelope_files = list((self.ingress_path / "envelopes").glob("*.json"))
        self.assertEqual(envelope_files, [])

    def test_queue_write_failure_rolls_back_new_ciphertext(self):
        token = self._arena_token()
        store = api._get_arena_store()
        with patch.object(store, "submit", side_effect=OSError("synthetic write failure")):
            response = self._submit(key="rollback-candidate", token=token)
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            list((self.ingress_path / "envelopes").glob("*.json")),
            [],
        )
        index = json.loads((self.ingress_path / "index.json").read_text("utf-8"))
        self.assertEqual(index["records"], [])

    def test_runtime_queue_projection_and_bounded_ladder_release(self):
        submitted = self._submit()
        self.assertEqual(submitted.status_code, 200, submitted.text)
        submission_id = submitted.json()["submission"]["submission_id"]

        unauthorized = self.client.post(
            f"/arena/internal/submissions/{submission_id}/transition",
            json={"to_state": "policy_screen", "reason": "policy_check_started"},
        )
        self.assertEqual(unauthorized.status_code, 401, unauthorized.text)

        self._advance_to_sealed_eval(submission_id)
        release = self.client.post(
            f"/arena/internal/submissions/{submission_id}/ladder-release",
            json={
                "submission_index": 1,
                "accepted": True,
                "leaderboard_step_index": 12,
                "step_denominator": 20,
                "improvement_steps_so_far": 1,
            },
            headers=self._runtime_headers(),
        )
        self.assertEqual(release.status_code, 200, release.text)
        self.assertNotIn("internal_score", release.text)
        completed = self.client.post(
            f"/arena/internal/submissions/{submission_id}/transition",
            json={"to_state": "completed", "reason": "evaluation_completed"},
            headers=self._runtime_headers(),
        )
        self.assertEqual(completed.status_code, 200, completed.text)

        queue = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/queue"
        )
        self.assertEqual(queue.status_code, 200, queue.text)
        self.assertEqual(queue.json()["submission_count"], 1)
        self.assertNotIn("candidate-a.enc", queue.text)
        self.assertEqual(queue.json()["product_status"], "per_row")
        self.assertEqual(
            queue.json()["execution_assurance"],
            "per_submission_execution_provenance",
        )
        self.assertEqual(queue.json()["submissions"][0]["product_status"], "modeled")
        self.assertEqual(
            queue.json()["submissions"][0]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertFalse(queue.json()["exact_timing_egress"])
        for timing_key in ("created_at", "updated_at", "occurred_at", "ladder_released_at"):
            self.assertNotIn(timing_key, queue.text)

        leaderboard = self.client.get(
            f"/arena/challenges/{BIO_CHALLENGE_ID}/versions/{BIO_CHALLENGE_VERSION}/leaderboard"
        )
        self.assertEqual(leaderboard.status_code, 200, leaderboard.text)
        board = leaderboard.json()
        self.assertEqual(board["row_count"], 1)
        self.assertEqual(board["product_status"], "per_row")
        self.assertEqual(board["rows"][0]["product_status"], "modeled")
        self.assertEqual(
            board["rows"][0]["execution_provenance"]["status"],
            "not_executed",
        )
        self.assertEqual(board["rows"][0]["leaderboard_step_index"], 12)
        self.assertEqual(board["rows"][0]["step_denominator"], 20)
        self.assertFalse(board["exact_reward_egress"])
        self.assertFalse(board["exact_timing_egress"])
        for timing_key in ("created_at", "updated_at", "occurred_at", "ladder_released_at"):
            self.assertNotIn(timing_key, leaderboard.text)
        self.assertNotIn("internal_score", json.dumps(board).lower())
        self.assertFalse(
            board["rows"][0]["execution_provenance"]["exact_score_egress"]
        )

    def test_sealed_reference_is_available_only_to_runtime_authenticated_worker(self):
        submitted = self._submit()
        submission_id = submitted.json()["submission"]["submission_id"]
        public = self.client.get(f"/arena/submissions/{submission_id}")
        self.assertEqual(public.status_code, 200, public.text)
        self.assertNotIn("encrypted_reference", public.json())

        denied = self.client.get(f"/arena/internal/submissions/{submission_id}")
        self.assertEqual(denied.status_code, 401, denied.text)
        internal = self.client.get(
            f"/arena/internal/submissions/{submission_id}",
            headers=self._runtime_headers(),
        )
        self.assertEqual(internal.status_code, 200, internal.text)
        self.assertRegex(
            internal.json()["encrypted_reference"],
            r"^sealed://arena/candidate-[0-9a-f]{64}$",
        )
        self.assertNotIn(self.submitter.address.lower(), internal.text.lower())


if __name__ == "__main__":
    unittest.main()
