import base64
import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate.arena_ingress import (
    INGRESS_ALGORITHM,
    INGRESS_ENCODING,
    INGRESS_HKDF_INFO,
    INGRESS_SCHEMA_VERSION,
    ArenaCandidateIngressService,
    ArenaCandidateIngressStore,
    ArenaIngressCorruptError,
    ArenaIngressError,
    ArenaIngressRecipient,
    arena_candidate_aad,
    build_arena_candidate_binding,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    encode_safe_ir_program,
    safe_ir_candidate_commitment,
)
from tinker_delegate.arena_safe_worker import (
    ArenaRegistryClaimRequest,
    ArenaSafeIrWorker,
    ArenaSafeWorkerActivation,
    ArenaSafeWorkerError,
    ArenaSafeWorkerRegistryUnavailable,
    ArenaSafeWorkerUnavailable,
    ArenaWorkerRegistryAuthorization,
    BioAssaySafeIrEvaluator,
    RefreshingArenaActivationProvider,
)
from tinker_delegate.arena_store import (
    BIO_CHALLENGE_ID,
    BIO_CHALLENGE_VERSION,
    BIO_SAFE_IR_CHALLENGE_ID,
    BIO_SAFE_IR_CHALLENGE_VERSION,
    ArenaStore,
    ArenaStoreError,
    CiphertextState,
    QueueReason,
    QueueState,
    SubmissionIdentity,
    SubmissionManifest,
    SubmissionMode,
    default_challenge_catalog,
)
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.qvl_freshness import CHALLENGE_SCHEMA, QvlChallenge


WALLET = "0x" + "ab" * 20
PROJECT = "personal-" + "cd" * 16
QUOTE_BYTES = bytes.fromhex("11" * 1_024)
COMPOSE_HASH = "22" * 32
OS_IMAGE_HASH = "33" * 32
APP_ID = "34" * 20
QVL_ADDRESS = "0x" + "77" * 20
TEE_ADDRESS = "0x" + "88" * 20
REGISTRY_ADDRESS = "0x" + "99" * 20
QVL_POLICY_HASH = "0x" + "aa" * 32
QVL_CHALLENGE_DIGEST = "0x" + "bb" * 32
CVM_ID = "cvm-main-runtime-0001"
ARENA_STORE_KEY = b"a" * 32


class _PolicyGate:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.requests = []

    def authorize_arena_execution(self, request, *, occurred_at):
        self.requests.append((request, occurred_at))
        return self.allowed


class _LeasedPolicyGate(_PolicyGate):
    def __init__(self):
        super().__init__(allowed=True)
        self.active = False
        self.exited = False

    @contextmanager
    def authorized_arena_execution_lease(self, request, *, occurred_at):
        self.requests.append((request, occurred_at))
        self.active = True
        try:
            yield self.allowed
        finally:
            self.active = False
            self.exited = True


class _RegistryGate:
    def __init__(self, *, allowed=True, authorization_overrides=None, events=None):
        self.allowed = allowed
        self.authorization_overrides = authorization_overrides or {}
        self.events = events
        self.requests = []
        self.closed = False

    def authorize_arena_claim(self, request, *, occurred_at):
        if self.events is not None:
            self.events.append("registry_authorized")
        self.requests.append((request, occurred_at))
        if not self.allowed:
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena finalized registry authorization is unavailable"
            )
        values = {
            "claim_request_sha256": request.sha256,
            "registry_snapshot_sha256": "sha256:" + "ad" * 32,
            "chain_id": 84_532,
            "block_number": 1_234_567,
            "block_hash": "0x" + "bc" * 32,
            "block_timestamp": occurred_at - 1,
            "registry_address": REGISTRY_ADDRESS,
            "registry_challenge_id": 7,
            "registry_version": 1,
        }
        values.update(self.authorization_overrides)
        return ArenaWorkerRegistryAuthorization(**values)

    def close(self):
        self.closed = True


class _StaticActivationProvider:
    def __init__(self, activation):
        self.activation = activation
        self.refresh_count = 0

    def refresh_activation(self, *, occurred_at):
        del occurred_at
        self.refresh_count += 1
        return self.activation


class _UnusedVerdictProvider:
    def issue_challenge(self):
        return QvlChallenge(
            schema=CHALLENGE_SCHEMA,
            chain_id=84_532,
            domain="main_runtime_cvm",
            profile="arena",
            cvm_id=CVM_ID,
            deployment_intent_sha256="sha256:" + "41" * 32,
            release_authority_sha256="sha256:" + "42" * 32,
            ceremony_nonce="0x" + "43" * 32,
            measurement_policy_sha256="sha256:" + "44" * 32,
            release_policy_hash=QVL_POLICY_HASH,
            challenge_id="0x" + "cc" * 32,
            challenge_digest=QVL_CHALLENGE_DIGEST,
            issued_at=100,
            expires_at=220,
            verifier_address=QVL_ADDRESS,
            verifier_signature="0x" + "11" * 65,
        )

    def verify(self, _packet, _challenge):
        raise AssertionError("QVL must not be reached after local evidence mismatch")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _canonical(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _valid_source() -> bytes:
    return encode_safe_ir_program(
        positive_pipeline=[
            {"op": "sort"},
            {"op": "trim", "low": 1, "high": 1},
        ],
        negative_pipeline=[{"op": "mad_filter", "threshold_milli": 3000}],
    )


class WorkerHarness:
    def __init__(self, directory: str, *, recipient_mode: str = "dstack") -> None:
        root = Path(directory)
        self.challenge = default_challenge_catalog().get(
            BIO_SAFE_IR_CHALLENGE_ID, BIO_SAFE_IR_CHALLENGE_VERSION
        )
        self.identity = SubmissionIdentity(WALLET, PROJECT)
        self.arena = ArenaStore(
            root / "arena.json",
            integrity_key=ARENA_STORE_KEY,
        )
        self.ingress_store = ArenaCandidateIngressStore(root / "candidates")
        self.recipient = ArenaIngressRecipient.from_keypair(
            TEEKeyPair.from_private_key_hex("44" * 32),
            custody_mode=recipient_mode,
        )
        self.ingress = ArenaCandidateIngressService(
            self.ingress_store, self.recipient
        )
        self.evaluator = BioAssaySafeIrEvaluator(
            [100.0, 101.0, 99.0, 100.5, 140.0],
            [10.0, 11.0, 9.0, 10.5, 40.0],
        )
        self.policy_gate = _PolicyGate()
        self.registry_gate = _RegistryGate()

    def activation(self, **overrides) -> ArenaSafeWorkerActivation:
        values = {
            "execution_enabled": True,
            "independent_tdx_verdict_verified": True,
            "compose_hash": COMPOSE_HASH,
            "app_id": APP_ID,
            "os_image_hash": OS_IMAGE_HASH,
            "quote_sha256": "sha256:" + hashlib.sha256(QUOTE_BYTES).hexdigest(),
            "verdict_expires_at": 1_000,
            "challenge_manifest_hash": self.challenge.manifest_hash,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "verifier_address": QVL_ADDRESS,
            "verdict_digest": "0x" + "aa" * 32,
            "chain_id": 84_532,
            "challenge_registry_address": REGISTRY_ADDRESS,
            "tee_signer_address": TEE_ADDRESS,
        }
        values.update(overrides)
        return ArenaSafeWorkerActivation(**values)

    def worker(
        self,
        *,
        activation_provider=None,
        registry_claim_gate=None,
        **activation_overrides,
    ) -> ArenaSafeIrWorker:
        return ArenaSafeIrWorker(
            arena_store=self.arena,
            ingress_store=self.ingress_store,
            recipient=self.recipient,
            evaluator=self.evaluator,
            activation_provider=(
                activation_provider
                or _StaticActivationProvider(
                    self.activation(**activation_overrides)
                )
            ),
            execution_policy_gate=self.policy_gate,
            registry_claim_gate=registry_claim_gate or self.registry_gate,
        )

    def submit(
        self,
        source: bytes,
        *,
        name: str = "candidate-1",
        declared_commitment: str | None = None,
        tamper_ciphertext: bool = False,
        challenge=None,
    ):
        selected = challenge or self.challenge
        commitment = declared_commitment or safe_ir_candidate_commitment(source)
        manifest = SubmissionManifest(
            schema_version=1,
            challenge_manifest_hash=selected.manifest_hash,
            candidate_kind=selected.candidate_kind,
            runtime=selected.runtime,
            entrypoint=selected.entrypoint,
            source_bytes=len(source),
            mode=SubmissionMode.LEADERBOARD,
        )
        binding = build_arena_candidate_binding(
            challenge=selected,
            identity=self.identity,
            candidate_commitment=commitment,
            manifest=manifest,
            recipient=self.recipient,
            idempotency_key=name,
            registry_authorization_sha256="sha256:" + "ee" * 32,
        )
        aad = arena_candidate_aad(binding)
        ephemeral = X25519PrivateKey.from_private_bytes(bytes.fromhex("55" * 32))
        shared = ephemeral.exchange(
            self.recipient.keypair._private.public_key()
        )
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=INGRESS_HKDF_INFO,
        ).derive(shared)
        nonce = bytes.fromhex("66" * 12)
        ciphertext = bytearray(AESGCM(key).encrypt(nonce, source, aad))
        if tamper_ciphertext:
            ciphertext[0] ^= 1
        envelope = {
            "schema_version": INGRESS_SCHEMA_VERSION,
            "algorithm": INGRESS_ALGORITHM,
            "encoding": INGRESS_ENCODING,
            "key_id": self.recipient.key_id,
            "attestation_report_data": self.recipient.report_data.hex(),
            "aad": _b64url(aad),
            "ephemeral_public_key": _b64url(
                ephemeral.public_key().public_bytes_raw()
            ),
            "nonce": _b64url(nonce),
            "ciphertext": _b64url(bytes(ciphertext)),
        }
        ingress_result = self.ingress.ingest(
            challenge=selected,
            identity=self.identity,
            candidate_commitment=commitment,
            manifest=manifest,
            idempotency_key=name,
            registry_authorization_sha256="sha256:" + "ee" * 32,
            envelope=envelope,
        )
        submitted = self.arena.submit(
            challenge_id=selected.challenge_id,
            challenge_version=selected.version,
            identity=self.identity,
            candidate_commitment=commitment,
            encrypted_reference=ingress_result.sealed_reference,
            manifest=manifest,
            idempotency_key=name,
            submitted_at=100,
        )
        return submitted.submission


def _live_evidence(**overrides):
    value = {
        "quote": QUOTE_BYTES.hex(),
        "quote_report_data": "",
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE_HASH,
        "compose_hash": COMPOSE_HASH,
    }
    value.update(overrides)
    return value


class ArenaSafeWorkerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.harness = WorkerHarness(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def _run(self, worker, submission_id, *, occurred_at=200, evidence=None):
        live = evidence or _live_evidence(
            quote_report_data=self.harness.recipient.report_data.hex()
        )
        with (
            patch(
                "tinker_delegate.arena_safe_worker.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_safe_worker.dstack_utils.get_attestation_details",
                return_value=live,
            ),
            patch.dict("os.environ", {"DSTACK_SIMULATOR_ENDPOINT": ""}),
        ):
            return worker.process_submission(
                submission_id, occurred_at=occurred_at
            )

    def test_end_to_end_decrypts_only_after_gate_and_persists_ladder_only(self):
        source = _valid_source()
        record = self.harness.submit(source)
        receipt = self._run(self.harness.worker(), record.submission_id)

        self.assertEqual(receipt.final_state, "completed")
        self.assertEqual(receipt.failure_code, "none")
        self.assertFalse(receipt.idempotent_replay)
        self.assertIsNotNone(receipt.ladder_release)
        stored = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(stored.state, QueueState.COMPLETED)
        self.assertEqual(len(stored.events), 7)
        public = self.harness.arena.public_submission(record.submission_id)
        evidence = public["execution_provenance"]
        self.assertEqual(public["challenge_id"], "dnaseq-variant-qc-safe-ir")
        self.assertEqual(public["product_status"], "live")
        self.assertEqual(evidence["status"], "worker_reported")
        self.assertEqual(evidence["outcome"], "completed")
        self.assertEqual(
            evidence["evidence_classification"],
            "worker_reported_qvl_binding_not_independently_verified",
        )
        self.assertFalse(evidence["independently_verified_by_client"])
        self.assertFalse(evidence["raw_tdx_quote_egress"])
        bounded = receipt.to_bounded_dict()
        encoded = json.dumps(bounded, sort_keys=True)
        self.assertFalse(bounded["raw_candidate_egress"])
        self.assertFalse(bounded["selected_controls_egress"])
        self.assertFalse(bounded["exact_score_egress"])
        self.assertFalse(bounded["public_api_connected"])
        self.assertNotIn(source.decode(), encoded)
        self.assertNotIn("100.5", encoded)
        self.assertNotIn("z_prime", encoded)
        persisted = (Path(self.temp.name) / "arena.json").read_text(encoding="utf-8")
        self.assertNotIn(source.decode(), persisted)
        self.assertNotIn("100.5", persisted)

    def test_finalized_registry_gate_binds_ingress_immediately_before_claim(self):
        events = []
        gate = _RegistryGate(events=events)
        record = self.harness.submit(_valid_source())
        metadata = self.harness.ingress_store.describe_envelope(
            record.encrypted_reference
        )
        original_claim = self.harness.arena.claim_safe_ir_submission
        original_describe = ArenaCandidateIngressStore.describe_envelope
        original_load = ArenaCandidateIngressStore.load_envelope

        def observed_claim(*args, **kwargs):
            events.append("durable_claim")
            return original_claim(*args, **kwargs)

        def observed_describe(store, *args, **kwargs):
            events.append("metadata_read")
            return original_describe(store, *args, **kwargs)

        def observed_load(store, *args, **kwargs):
            events.append("ciphertext_read")
            return original_load(store, *args, **kwargs)

        with (
            patch.object(
                ArenaCandidateIngressStore,
                "describe_envelope",
                new=observed_describe,
            ),
            patch.object(
                ArenaCandidateIngressStore,
                "load_envelope",
                new=observed_load,
            ),
            patch.object(
                self.harness.arena,
                "claim_safe_ir_submission",
                side_effect=observed_claim,
            ),
        ):
            receipt = self._run(
                self.harness.worker(registry_claim_gate=gate),
                record.submission_id,
            )

        self.assertEqual(receipt.final_state, "completed")
        self.assertEqual(
            events[:4],
            [
                "metadata_read",
                "registry_authorized",
                "durable_claim",
                "ciphertext_read",
            ],
        )
        self.assertEqual(len(gate.requests), 1)
        request, occurred_at = gate.requests[0]
        self.assertIsInstance(request, ArenaRegistryClaimRequest)
        self.assertEqual(occurred_at, 200)
        self.assertEqual(
            request.ingress_registry_authorization_sha256,
            "sha256:" + "ee" * 32,
        )
        self.assertEqual(
            request.ingress_binding_sha256,
            metadata.aad_sha256,
        )
        with self.assertRaisesRegex(
            ArenaIngressError, "Unknown Arena sealed reference"
        ):
            self.harness.ingress_store.load_envelope(
                record.encrypted_reference
            )

    def test_metadata_read_then_owner_cancel_prevents_claim_and_ciphertext_read(self):
        record = self.harness.submit(_valid_source(), name="cancel-before-claim")
        ingress = ArenaCandidateIngressStore(
            self.harness.ingress_store.root_dir,
            max_envelopes=self.harness.ingress_store.max_envelopes,
        )
        metadata = ingress.describe_envelope(record.encrypted_reference)
        self.assertEqual(metadata.key_id, self.harness.recipient.key_id)

        cancelled = self.harness.arena.cancel_owner_submission(
            record.submission_id,
            wallet_address=WALLET,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            occurred_at=150,
        )
        self.assertTrue(cancelled.changed)
        cleaned = self.harness.worker().cleanup_submission_ciphertext(
            record.submission_id,
            occurred_at=150,
        )
        self.assertEqual(cleaned.ciphertext_state, CiphertextState.UNLINKED)
        with self.assertRaises(ArenaStoreError):
            self.harness.arena.claim_safe_ir_submission(
                record.submission_id,
                occurred_at=151,
            )
        with self.assertRaises(ArenaIngressError):
            ingress.load_envelope(record.encrypted_reference)

    def test_worker_claim_then_owner_cancel_is_rejected_before_ciphertext_read(self):
        record = self.harness.submit(_valid_source(), name="claim-before-cancel")
        ingress = ArenaCandidateIngressStore(
            self.harness.ingress_store.root_dir,
            max_envelopes=self.harness.ingress_store.max_envelopes,
        )
        metadata = ingress.describe_envelope(record.encrypted_reference)

        claim = self.harness.arena.claim_safe_ir_submission(
            record.submission_id,
            occurred_at=150,
        )
        self.assertIsNotNone(claim.submission.worker_claimed_at)
        with self.assertRaisesRegex(ArenaStoreError, "durably claimed"):
            self.harness.arena.cancel_owner_submission(
                record.submission_id,
                wallet_address=WALLET,
                challenge_id=record.challenge_id,
                challenge_version=record.challenge_version,
                occurred_at=151,
            )
        stored = ingress.load_envelope(record.encrypted_reference)
        self.assertEqual(stored.envelope.ciphertext_sha256, metadata.ciphertext_sha256)

    def test_terminal_replay_cleans_before_activation_and_remains_non_executable(self):
        record = self.harness.submit(_valid_source(), name="terminal-replay-cleanup")
        self.harness.arena.cancel_owner_submission(
            record.submission_id,
            wallet_address=WALLET,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            occurred_at=150,
        )

        with self.assertRaisesRegex(ArenaSafeWorkerError, "not executable"):
            self.harness.worker(execution_enabled=False).process_submission(
                record.submission_id,
                occurred_at=160,
            )

        cleaned = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(cleaned.ciphertext_state, CiphertextState.UNLINKED)
        with self.assertRaises(ArenaIngressError):
            self.harness.ingress_store.load_envelope(
                record.encrypted_reference
            )

    def test_registry_failure_or_wrong_claim_binding_prevents_durable_claim(self):
        for name, gate in (
            ("unavailable", _RegistryGate(allowed=False)),
            (
                "wrong_request",
                _RegistryGate(
                    authorization_overrides={
                        "claim_request_sha256": "sha256:" + "fa" * 32
                    }
                ),
            ),
        ):
            with self.subTest(name=name):
                record = self.harness.submit(_valid_source(), name=name)
                with self.assertRaises(ArenaSafeWorkerRegistryUnavailable):
                    self._run(
                        self.harness.worker(registry_claim_gate=gate),
                        record.submission_id,
                    )
                stored = self.harness.arena.get_submission(record.submission_id)
                self.assertEqual(stored.state, QueueState.SUBMITTED)
                self.assertIsNone(stored.worker_claimed_at)
                self.assertFalse(
                    any(
                        event.reason == QueueReason.WORKER_CLAIMED
                        for event in stored.events
                    )
                )

    def test_policy_lease_remains_held_through_terminal_execution(self):
        gate = _LeasedPolicyGate()

        class _LeaseCheckingEvaluator(BioAssaySafeIrEvaluator):
            def run_public_conformance(inner_self, program):
                if not gate.active:
                    raise AssertionError("policy lease was released before execution")
                return super().run_public_conformance(program)

            def internal_score(inner_self, program):
                if not gate.active:
                    raise AssertionError("policy lease was released before scoring")
                return super().internal_score(program)

        self.harness.policy_gate = gate
        self.harness.evaluator = _LeaseCheckingEvaluator(
            [100.0, 101.0, 99.0, 100.5, 140.0],
            [10.0, 11.0, 9.0, 10.5, 40.0],
        )
        record = self.harness.submit(_valid_source())

        receipt = self._run(self.harness.worker(), record.submission_id)

        self.assertEqual(receipt.final_state, "completed")
        self.assertTrue(gate.exited)
        self.assertFalse(gate.active)

    def test_terminal_retry_is_idempotent_without_duplicate_release_or_events(self):
        record = self.harness.submit(_valid_source())
        worker = self.harness.worker()
        first = self._run(worker, record.submission_id)
        events = len(self.harness.arena.get_submission(record.submission_id).events)
        second = self._run(worker, record.submission_id, occurred_at=201)
        self.assertFalse(first.idempotent_replay)
        self.assertTrue(second.idempotent_replay)
        self.assertEqual(second.ladder_release, first.ladder_release)
        self.assertEqual(
            len(self.harness.arena.get_submission(record.submission_id).events),
            events,
        )

    def test_malformed_ir_fails_with_one_bucket_and_retry_is_idempotent(self):
        source = _canonical(
            {
                "schema": "dnai.dnaseq-variant-qc-safe-ir.v2",
                "positive_pipeline": [{"op": "open", "path": "/etc/passwd"}],
                "negative_pipeline": [],
            }
        )
        record = self.harness.submit(source)
        worker = self.harness.worker()
        first = self._run(worker, record.submission_id)
        second = self._run(worker, record.submission_id, occurred_at=201)
        self.assertEqual(first.final_state, "failed")
        self.assertEqual(first.failure_code, "execution_failed")
        self.assertTrue(second.idempotent_replay)
        failed = self.harness.arena.public_submission(record.submission_id)
        self.assertEqual(failed["execution_provenance"]["status"], "worker_reported")
        self.assertEqual(failed["execution_provenance"]["outcome"], "failed")
        self.assertFalse(
            failed["execution_provenance"]["independently_verified_by_client"]
        )
        self.assertEqual(
            len(self.harness.arena.get_submission(record.submission_id).events), 3
        )
        self.assertNotIn("passwd", json.dumps(first.to_bounded_dict()))
        self.assertNotIn("open", json.dumps(first.to_bounded_dict()))

    def test_plaintext_commitment_mismatch_fails_before_claim_or_ciphertext_read(self):
        record = self.harness.submit(
            _valid_source(), declared_commitment="sha256:" + "0" * 64
        )
        with self.assertRaises(ArenaSafeWorkerRegistryUnavailable):
            self._run(self.harness.worker(), record.submission_id)
        stored = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(stored.state, QueueState.SUBMITTED)
        self.assertIsNone(stored.worker_claimed_at)
        self.assertIsNotNone(
            self.harness.ingress_store.load_envelope(
                record.encrypted_reference
            )
        )

    def test_aes_gcm_tampering_fails_without_detail(self):
        record = self.harness.submit(_valid_source(), tamper_ciphertext=True)
        receipt = self._run(self.harness.worker(), record.submission_id)
        self.assertEqual(receipt.final_state, "failed")
        self.assertEqual(receipt.failure_code, "execution_failed")
        self.assertNotIn("tag", json.dumps(receipt.to_bounded_dict()).lower())

    def test_queue_resume_from_provisioning_completes_once(self):
        record = self.harness.submit(_valid_source())
        for state, reason in (
            (QueueState.POLICY_SCREEN, QueueReason.POLICY_CHECK_STARTED),
            (QueueState.QUEUED, QueueReason.POLICY_PASSED),
            (QueueState.PROVISIONING, QueueReason.WORKER_CLAIMED),
        ):
            self.harness.arena.transition_submission(
                record.submission_id, state, reason=reason, occurred_at=150
            )
        receipt = self._run(self.harness.worker(), record.submission_id)
        self.assertEqual(receipt.final_state, "completed")
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).events[-1].sequence,
            7,
        )

    def test_resume_after_ladder_write_does_not_rescore(self):
        record = self.harness.submit(_valid_source())
        for state, reason in (
            (QueueState.POLICY_SCREEN, QueueReason.POLICY_CHECK_STARTED),
            (QueueState.QUEUED, QueueReason.POLICY_PASSED),
            (QueueState.PROVISIONING, QueueReason.WORKER_CLAIMED),
            (QueueState.PUBLIC_TESTS, QueueReason.PUBLIC_TESTS_STARTED),
            (QueueState.SEALED_EVAL, QueueReason.SEALED_EVALUATION_STARTED),
        ):
            self.harness.arena.transition_submission(
                record.submission_id, state, reason=reason, occurred_at=150
            )
        expected = self.harness.arena.evaluate_ladder_submission(
            record.submission_id, 0.8, occurred_at=150
        )
        receipt = self._run(self.harness.worker(), record.submission_id)
        self.assertEqual(receipt.final_state, "completed")
        self.assertEqual(receipt.ladder_release["submission_index"], expected["submission_index"])

    def test_concurrent_calls_create_one_state_history_and_one_release(self):
        record = self.harness.submit(_valid_source())
        worker = self.harness.worker()

        def run(_):
            return worker.process_submission(record.submission_id, occurred_at=200)

        live = _live_evidence(
            quote_report_data=self.harness.recipient.report_data.hex()
        )
        with (
            patch(
                "tinker_delegate.arena_safe_worker.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_safe_worker.dstack_utils.get_attestation_details",
                return_value=live,
            ),
            patch.dict("os.environ", {"DSTACK_SIMULATOR_ENDPOINT": ""}),
            ThreadPoolExecutor(max_workers=8) as pool,
        ):
            receipts = list(pool.map(run, range(16)))
        self.assertEqual(sum(not item.idempotent_replay for item in receipts), 1)
        stored = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(stored.state, QueueState.COMPLETED)
        self.assertEqual(len(stored.events), 7)
        self.assertIsNotNone(stored.ladder_release)

    def test_local_key_disabled_verdict_and_expiry_fail_before_queue_mutation(self):
        local_temp = tempfile.TemporaryDirectory()
        self.addCleanup(local_temp.cleanup)
        local = WorkerHarness(local_temp.name, recipient_mode="local")
        local_record = local.submit(_valid_source())
        cases = (
            local.worker(),
            self.harness.worker(execution_enabled=False),
            self.harness.worker(independent_tdx_verdict_verified=False),
            self.harness.worker(verdict_expires_at=200),
        )
        for index, worker in enumerate(cases):
            record = local_record if index == 0 else self.harness.submit(
                _valid_source(), name=f"gate-{index}"
            )
            harness = local if index == 0 else self.harness
            with self.subTest(index=index):
                with self.assertRaises(ArenaSafeWorkerUnavailable):
                    self._run(worker, record.submission_id)
                self.assertEqual(
                    harness.arena.get_submission(record.submission_id).state,
                    QueueState.SUBMITTED,
                )

    def test_persisted_policy_gate_is_required_before_first_queue_mutation(self):
        record = self.harness.submit(_valid_source())
        self.harness.policy_gate.allowed = False
        with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "did not pass"):
            self._run(self.harness.worker(), record.submission_id)
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.SUBMITTED,
        )
        request, occurred_at = self.harness.policy_gate.requests[-1]
        self.assertEqual(occurred_at, 200)
        self.assertEqual(request.submission_id, record.submission_id)
        self.assertEqual(request.challenge_manifest_hash, self.harness.challenge.manifest_hash)
        self.assertEqual(request.runtime_policy_commitment, SAFE_IR_POLICY_COMMITMENT)
        self.assertFalse(hasattr(request, "encrypted_reference"))

    def test_simulator_and_live_measurement_mismatch_fail_before_queue_mutation(self):
        record = self.harness.submit(_valid_source())
        provider = RefreshingArenaActivationProvider(
            recipient=self.harness.recipient,
            verdict_provider=_UnusedVerdictProvider(),
            trusted_verifier_addresses=(QVL_ADDRESS,),
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
        )
        worker = self.harness.worker(activation_provider=provider)
        with (
            patch(
                "tinker_delegate.arena_safe_worker.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch.dict(
                "os.environ",
                {"DSTACK_SIMULATOR_ENDPOINT": "http://127.0.0.1:8090"},
            ),
        ):
            with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "simulator"):
                worker.process_submission(record.submission_id, occurred_at=200)
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.SUBMITTED,
        )
        with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "live measurements"):
            self._run(
                worker,
                record.submission_id,
                evidence=_live_evidence(
                    quote_report_data=(
                        self.harness.recipient.report_data.hex()
                        + QVL_CHALLENGE_DIGEST[2:]
                    ),
                    compose_hash="99" * 32,
                ),
            )
        with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "malformed live TDX"):
            self._run(
                worker,
                record.submission_id,
                evidence=_live_evidence(
                    quote_report_data=(
                        self.harness.recipient.report_data.hex() + ("zz" * 32)
                    ),
                ),
            )
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.SUBMITTED,
        )

    def test_python_demo_challenge_is_never_executed_by_safe_worker(self):
        python_challenge = default_challenge_catalog().get(
            BIO_CHALLENGE_ID, BIO_CHALLENGE_VERSION
        )
        record = self.harness.submit(
            b"def process(a, b):\n    return a, b\n",
            name="python-demo",
            challenge=python_challenge,
        )
        worker = self.harness.worker(
            challenge_manifest_hash=python_challenge.manifest_hash
        )
        with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "non-safe-IR"):
            self._run(worker, record.submission_id)
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.SUBMITTED,
        )

    def test_ciphertext_store_corruption_propagates_instead_of_becoming_candidate_failure(self):
        record = self.harness.submit(_valid_source())
        blob = next((Path(self.temp.name) / "candidates" / "envelopes").iterdir())
        blob.write_bytes(blob.read_bytes().replace(b'"surface"', b'"surfXce"'))
        with self.assertRaises(ArenaIngressCorruptError):
            self._run(self.harness.worker(), record.submission_id)
        # Policy screen was durably entered before the storage integrity check;
        # corruption is not misrepresented as a candidate execution failure.
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.POLICY_SCREEN,
        )

    def test_evaluator_repr_and_receipt_never_expose_sealed_controls(self):
        representation = repr(self.harness.evaluator)
        self.assertIn("positive_count=5", representation)
        self.assertNotIn("140", representation)
        record = self.harness.submit(_valid_source())
        receipt = self._run(self.harness.worker(), record.submission_id)
        encoded = json.dumps(receipt.to_bounded_dict(), sort_keys=True)
        for private_value in ("140.0", "40.0", "100.5", "10.5"):
            self.assertNotIn(private_value, encoded)


if __name__ == "__main__":
    unittest.main()
