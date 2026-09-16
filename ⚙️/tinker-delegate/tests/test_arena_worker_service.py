import hashlib
import io
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct

from tests.test_arena_safe_worker import (
    APP_ID,
    ARENA_STORE_KEY,
    COMPOSE_HASH,
    OS_IMAGE_HASH,
    QUOTE_BYTES,
    REGISTRY_ADDRESS,
    TEE_ADDRESS,
    WorkerHarness,
    _live_evidence,
    _valid_source,
)
from tinker_delegate.arena_safe_worker import (
    ArenaAttestationPacket,
    ArenaExecutionPolicyRequest,
    ArenaSafeWorkerUnavailable,
    RefreshingArenaActivationProvider,
    activation_from_independent_verdict,
)
from tinker_delegate.arena_ingress import (
    ArenaIngressError,
    arena_submission_manifest_hash,
)
from tinker_delegate.arena_safe_ir import SAFE_IR_POLICY_COMMITMENT
from tinker_delegate.arena_store import (
    ArenaStore,
    CiphertextState,
    QueueReason,
    QueueState,
)
from tinker_delegate.arena_worker_service import (
    EXIT_ACTIVATION_UNAVAILABLE,
    EXIT_OK,
    ArenaSafeWorkerService,
    ArenaWorkerAlreadyRunning,
    ArenaWorkerProcessLease,
    PersistedArenaExecutionPolicyGate,
    build_verified_arena_worker_service,
    run_arena_worker_process,
    write_bounded_worker_status,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)
from tinker_delegate.execution_policy_store import (
    ExecutionPolicyNotPassed,
    ExecutionPolicyStore,
    ZERO_DECISION_HASH,
    execution_policy_approver_root_hash,
)
from tinker_delegate.execution_policy_anchor import AnchorProjectionRecord
from tests.execution_policy_anchor_fakes import (
    MemoryExecutionPolicyAnchorGateway,
)
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult
from tinker_delegate.chain_submitter import SignerAttestationEvidence
from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    qvl_challenge_digest,
)


QVL_POLICY_HASH = "0x" + "ba" * 32
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32


def _signed_challenge(
    qvl,
    *,
    issued_at=190,
    expires_at=310,
    challenge_id="0x" + "bc" * 32,
):
    unsigned = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="arena",
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=QVL_POLICY_HASH,
        challenge_id=challenge_id,
        challenge_digest="0x" + "01" * 32,
        issued_at=issued_at,
        expires_at=expires_at,
        verifier_address=qvl.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(unsigned)
    signature = qvl.sign_message(encode_defunct(hexstr=digest)).signature
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signature).hex(),
    )


def _challenge_from_verdict(verdict):
    return QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=verdict.chain_id,
        domain=verdict.domain,
        profile=verdict.profile,
        cvm_id=verdict.cvm_id,
        deployment_intent_sha256=verdict.deployment_intent_sha256,
        release_authority_sha256=verdict.release_authority_sha256,
        ceremony_nonce=verdict.ceremony_nonce,
        measurement_policy_sha256=verdict.measurement_policy_sha256,
        release_policy_hash=verdict.release_policy_hash,
        challenge_id=verdict.challenge_id,
        challenge_digest=verdict.challenge_digest,
        issued_at=verdict.challenge_issued_at,
        expires_at=verdict.challenge_expires_at,
        verifier_address=verdict.verifier_address.lower(),
        verifier_signature="0x" + "11" * 65,
    )


class _FixedVerdictProvider:
    def __init__(self, verdict):
        self.verdict = verdict
        self.challenge = _challenge_from_verdict(verdict)
        self.calls = 0

    def issue_challenge(self):
        return self.challenge

    def verify(self, _packet, challenge):
        if challenge != self.challenge:
            raise AssertionError("challenge drift")
        self.calls += 1
        return self.verdict


def _read_only_anchor_gateway(
    store: ExecutionPolicyStore,
) -> MemoryExecutionPolicyAnchorGateway:
    gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
    gateway.records = [
        AnchorProjectionRecord.from_mapping(item)
        for item in store.anchor_projection()
    ]
    return gateway


@contextmanager
def _live_runtime(harness):
    live = _live_evidence(quote_report_data=harness.recipient.report_data.hex())
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
        yield


def _signed_verdict(harness, qvl, *, now=200, challenge=None, signer=None, **overrides):
    issued_at = overrides.get("issued_at", now - 10)
    expires_at = overrides.get("expires_at", now + 110)
    challenge = challenge or _signed_challenge(
        qvl,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    values = {
        "schema": INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        "verification_method": INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        "verified": True,
        "chain_id": challenge.chain_id,
        "domain": challenge.domain,
        "profile": challenge.profile,
        "cvm_id": challenge.cvm_id,
        "deployment_intent_sha256": challenge.deployment_intent_sha256,
        "release_authority_sha256": challenge.release_authority_sha256,
        "ceremony_nonce": challenge.ceremony_nonce,
        "measurement_policy_sha256": challenge.measurement_policy_sha256,
        "release_policy_hash": challenge.release_policy_hash,
        "challenge_id": challenge.challenge_id,
        "challenge_digest": challenge.challenge_digest,
        "challenge_issued_at": challenge.issued_at,
        "challenge_expires_at": challenge.expires_at,
        "quote_hash": "0x" + hashlib.sha256(QUOTE_BYTES).hexdigest(),
        "report_data": "0x" + harness.recipient.report_data.hex(),
        "compose_hash": "0x" + COMPOSE_HASH,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE_HASH,
        "signer_address": TEE_ADDRESS,
        "contract_address": REGISTRY_ADDRESS,
        "issued_at": issued_at,
        "verifier_address": qvl.address,
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    values.setdefault("expires_at", expires_at)
    values.setdefault("activation_evidence_lease_expires_at", values["expires_at"])
    unsigned = IndependentAttestationVerdict(**values)
    digest = independent_attestation_verdict_digest(unsigned)
    signed = (signer or qvl).sign_message(encode_defunct(hexstr=digest))
    return replace(unsigned, verifier_signature="0x" + bytes(signed.signature).hex())


def _attestation_packet(harness, quote=QUOTE_BYTES, **evidence_overrides):
    evidence = SignerAttestationEvidence(
        mode="tdx",
        signer_address=TEE_ADDRESS,
        chain_id=84_532,
        contract_address=REGISTRY_ADDRESS,
        report_data="0x" + harness.recipient.report_data.hex(),
        quote_report_data="0x" + harness.recipient.report_data.hex(),
        quote_hash="0x" + hashlib.sha256(quote).hexdigest(),
        quote_size=len(quote),
        compose_hash="0x" + COMPOSE_HASH,
        app_id=APP_ID,
        os_image_hash=OS_IMAGE_HASH,
    )
    if evidence_overrides:
        evidence = replace(evidence, **evidence_overrides)
    return ArenaAttestationPacket(
        evidence=evidence,
        quote="0x" + quote.hex(),
    )


class _MatchingVerdictProvider:
    """Test QVL that retains only bounded hashes, never the raw quote."""

    def __init__(self, harness, qvl, *, now=200):
        self.harness = harness
        self.qvl = qvl
        self.now = now
        self.quote_hashes = []
        self.challenge_count = 0

    def issue_challenge(self):
        self.challenge_count += 1
        return _signed_challenge(
            self.qvl,
            issued_at=self.now - 10,
            expires_at=self.now + 110,
            challenge_id="0x" + self.challenge_count.to_bytes(32, "big").hex(),
        )

    def verify(self, packet, challenge):
        self.quote_hashes.append(packet.evidence.quote_hash)
        return _signed_verdict(
            self.harness,
            self.qvl,
            now=self.now,
            challenge=challenge,
            quote_hash=packet.evidence.quote_hash,
        )


def _refreshing_provider(harness, verdict_provider, collector):
    return RefreshingArenaActivationProvider(
        recipient=harness.recipient,
        verdict_provider=verdict_provider,
        trusted_verifier_addresses=(verdict_provider.qvl.address,),
        expected_compose_hash=COMPOSE_HASH,
        expected_app_id=APP_ID,
        expected_os_image_hash=OS_IMAGE_HASH,
        expected_tee_signer_address=TEE_ADDRESS,
        chain_id=84_532,
        challenge_registry_address=REGISTRY_ADDRESS,
        attestation_collector=collector,
    )


class ArenaWorkerServiceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.harness = WorkerHarness(self.temp.name)

    def _service(self, **activation_overrides):
        return ArenaSafeWorkerService(
            arena_store=self.harness.arena,
            worker=self.harness.worker(**activation_overrides),
            poll_interval_seconds=0.05,
        )

    def test_process_entrypoint_observes_post_start_ingress_and_emits_bounded_status(self):
        service = self._service()
        source = _valid_source()
        record = self.harness.submit(source)
        statuses = []
        with _live_runtime(self.harness):
            exit_code = run_arena_worker_process(
                service,
                status_sink=statuses.append,
                now=lambda: 200,
                wait=lambda _seconds: None,
                max_iterations=1,
            )
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0].state, "completed")
        self.assertEqual(statuses[0].submission_id, record.submission_id)
        self.assertFalse(statuses[0].recovery)
        output = io.StringIO()
        write_bounded_worker_status(statuses[0], output)
        encoded = output.getvalue()
        self.assertLess(len(encoded), 1_024)
        self.assertNotIn(source.decode(), encoded)
        self.assertNotIn("100.5", encoded)
        self.assertFalse(json.loads(encoded)["exception_detail_egress"])

    def test_recovery_is_prioritized_and_does_not_duplicate_claim(self):
        recovery = self.harness.submit(_valid_source(), name="recovery")
        fresh = self.harness.submit(_valid_source(), name="fresh")
        for state, reason in (
            (QueueState.POLICY_SCREEN, QueueReason.POLICY_CHECK_STARTED),
            (QueueState.QUEUED, QueueReason.POLICY_PASSED),
            (QueueState.PROVISIONING, QueueReason.WORKER_CLAIMED),
        ):
            self.harness.arena.transition_submission(
                recovery.submission_id,
                state,
                reason=reason,
                occurred_at=150,
            )
        with _live_runtime(self.harness):
            status = self._service().run_once(occurred_at=200)
        self.assertTrue(status.recovery)
        self.assertEqual(status.submission_id, recovery.submission_id)
        self.assertEqual(
            self.harness.arena.get_submission(fresh.submission_id).state,
            QueueState.SUBMITTED,
        )
        stored = self.harness.arena.get_submission(recovery.submission_id)
        self.assertEqual(
            sum(event.reason == QueueReason.WORKER_CLAIMED for event in stored.events),
            1,
        )

    def test_idle_status_is_emitted_once_instead_of_once_per_poll(self):
        statuses = []
        heartbeats = []
        with _live_runtime(self.harness):
            exit_code = run_arena_worker_process(
                self._service(),
                status_sink=statuses.append,
                heartbeat_sink=lambda status, observed_at: heartbeats.append(
                    (status.state, observed_at)
                ),
                now=lambda: 200,
                wait=lambda _seconds: None,
                max_iterations=3,
            )
        self.assertEqual(exit_code, EXIT_OK)
        self.assertEqual([status.state for status in statuses], ["idle"])
        self.assertEqual(heartbeats, [("idle", 200), ("idle", 200), ("idle", 200)])

    def test_poll_cycle_retries_terminal_cleanup_left_pending_by_prior_crash(self):
        record = self.harness.submit(
            _valid_source(),
            name="pending-terminal-cleanup",
        )
        cancelled = self.harness.arena.cancel_owner_submission(
            record.submission_id,
            wallet_address=record.identity.wallet_address,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            occurred_at=150,
        )
        self.assertEqual(
            cancelled.submission.ciphertext_state,
            CiphertextState.ERASURE_PENDING,
        )

        status = self._service().run_once(occurred_at=200)

        self.assertEqual(status.state, "idle")
        cleaned = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(cleaned.ciphertext_state, CiphertextState.UNLINKED)
        with self.assertRaises(ArenaIngressError):
            self.harness.ingress_store.load_envelope(
                record.encrypted_reference
            )

    def test_process_lease_refuses_a_second_worker_and_is_kernel_releasable(self):
        first = ArenaWorkerProcessLease(self.harness.arena.path)
        second = ArenaWorkerProcessLease(self.harness.arena.path)
        with first:
            with self.assertRaises(ArenaWorkerAlreadyRunning):
                second.__enter__()
        with second:
            self.assertTrue(second.path.exists())

    def test_activation_and_policy_failures_exit_before_queue_mutation(self):
        activation_record = self.harness.submit(_valid_source(), name="activation")
        activation_statuses = []
        exit_code = run_arena_worker_process(
            self._service(execution_enabled=False),
            status_sink=activation_statuses.append,
            now=lambda: 200,
            wait=lambda _seconds: None,
            max_iterations=1,
        )
        self.assertEqual(exit_code, EXIT_ACTIVATION_UNAVAILABLE)
        self.assertEqual(activation_statuses[0].failure_code, "activation_unavailable")
        self.assertEqual(
            self.harness.arena.get_submission(activation_record.submission_id).state,
            QueueState.SUBMITTED,
        )

        policy_record = self.harness.submit(_valid_source(), name="policy")
        self.harness.policy_gate.allowed = False
        policy_statuses = []
        with _live_runtime(self.harness):
            exit_code = run_arena_worker_process(
                self._service(),
                status_sink=policy_statuses.append,
                now=lambda: 200,
                wait=lambda _seconds: None,
                max_iterations=1,
            )
        self.assertEqual(exit_code, EXIT_ACTIVATION_UNAVAILABLE)
        self.assertEqual(
            policy_statuses[0].failure_code,
            "execution_policy_unavailable",
        )
        self.assertEqual(
            self.harness.arena.get_submission(policy_record.submission_id).state,
            QueueState.SUBMITTED,
        )

        registry_record = self.harness.submit(_valid_source(), name="registry")
        self.harness.policy_gate.allowed = True
        self.harness.registry_gate.allowed = False
        registry_statuses = []
        with _live_runtime(self.harness):
            exit_code = run_arena_worker_process(
                self._service(),
                status_sink=registry_statuses.append,
                now=lambda: 200,
                wait=lambda _seconds: None,
                max_iterations=1,
            )
        self.assertEqual(exit_code, EXIT_ACTIVATION_UNAVAILABLE)
        self.assertEqual(
            registry_statuses[0].failure_code,
            "challenge_registry_unavailable",
        )
        registry_stored = self.harness.arena.get_submission(
            registry_record.submission_id
        )
        self.assertEqual(registry_stored.state, QueueState.SUBMITTED)
        self.assertIsNone(registry_stored.worker_claimed_at)
        self.assertFalse(
            any(
                event.reason == QueueReason.WORKER_CLAIMED
                for event in registry_stored.events
            )
        )

    def test_store_instances_refresh_and_claim_atomically(self):
        record = self.harness.submit(_valid_source())
        other = ArenaStore(
            Path(self.temp.name) / "arena.json",
            integrity_key=ARENA_STORE_KEY,
        )
        self.assertEqual(other.get_submission(record.submission_id), record)
        for state, reason in (
            (QueueState.POLICY_SCREEN, QueueReason.POLICY_CHECK_STARTED),
            (QueueState.QUEUED, QueueReason.POLICY_PASSED),
        ):
            other.transition_submission(
                record.submission_id,
                state,
                reason=reason,
                occurred_at=150,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = list(
                pool.map(
                    lambda store: store.claim_safe_ir_submission(
                        record.submission_id,
                        occurred_at=160,
                    ),
                    (self.harness.arena, other),
                )
            )
        self.assertEqual(sum(not claim.recovered for claim in claims), 1)
        stored = self.harness.arena.get_submission(record.submission_id)
        self.assertEqual(stored.state, QueueState.PROVISIONING)
        self.assertEqual(
            sum(event.reason == QueueReason.WORKER_CLAIMED for event in stored.events),
            1,
        )

    def test_persisted_policy_adapter_fresh_reads_newer_hold(self):
        record = self.harness.submit(_valid_source())
        policy_path = Path(self.temp.name) / "execution-policy.json"
        integrity_key = b"p" * 32
        store = ExecutionPolicyStore(policy_path, integrity_key=integrity_key)
        passed = PolicyGateResult(
            decision=PolicyDecision.PASS,
            corpus_ref="corpus://sealed",
            stage=4,
            reason_code="policy_passed",
            request_hash="1" * 64,
            policy_hash="2" * 64,
        )
        store.append(
            surface="arena_execution",
            resource_id=record.submission_id,
            result=passed,
            recorded_at=190,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash="3" * 64,
            approval_hash="4" * 64,
            approval_domain_hash="5" * 64,
            approver_root_hash=execution_policy_approver_root_hash(
                ["3" * 64]
            ),
        )
        request = ArenaExecutionPolicyRequest(
            submission_id=record.submission_id,
            challenge_id=record.challenge_id,
            challenge_version=record.challenge_version,
            challenge_manifest_hash=self.harness.challenge.manifest_hash,
            submission_manifest_hash=arena_submission_manifest_hash(record.manifest),
            candidate_commitment=record.candidate_commitment,
            wallet_address=record.identity.wallet_address,
            project_id=record.identity.project_id,
            runtime=record.manifest.runtime,
            runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        )
        anchor_gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        anchor_gateway.records = [
            AnchorProjectionRecord.from_mapping(item)
            for item in store.anchor_projection()
        ]
        adapter = PersistedArenaExecutionPolicyGate(
            policy_path,
            integrity_key=integrity_key,
            expected_approval_domain_hash="5" * 64,
            expected_approver_root_hash=execution_policy_approver_root_hash(
                ["3" * 64]
            ),
            approved_approver_hashes={"3" * 64},
            execution_policy_anchor_gateway=anchor_gateway,
        )
        self.assertTrue(
            adapter.authorize_arena_execution(request, occurred_at=200)
        )

        wrong_domain = PersistedArenaExecutionPolicyGate(
            policy_path,
            integrity_key=integrity_key,
            expected_approval_domain_hash="6" * 64,
            expected_approver_root_hash=execution_policy_approver_root_hash(
                ["3" * 64]
            ),
            approved_approver_hashes={"3" * 64},
            execution_policy_anchor_gateway=anchor_gateway,
        )
        with self.assertRaises(ExecutionPolicyNotPassed):
            wrong_domain.authorize_arena_execution(request, occurred_at=200)

        signer_revoked = PersistedArenaExecutionPolicyGate(
            policy_path,
            integrity_key=integrity_key,
            expected_approval_domain_hash="5" * 64,
            expected_approver_root_hash=execution_policy_approver_root_hash(
                ["7" * 64]
            ),
            approved_approver_hashes={"7" * 64},
            execution_policy_anchor_gateway=anchor_gateway,
        )
        with self.assertRaises(ExecutionPolicyNotPassed):
            signer_revoked.authorize_arena_execution(request, occurred_at=200)

        held = replace(passed, decision=PolicyDecision.HOLD, reason_code="review_hold")
        store.append(
            surface="arena_execution",
            resource_id=record.submission_id,
            result=held,
            recorded_at=201,
            expires_at=300,
            expected_previous_decision_hash=store.latest_decision_hash(
                surface="arena_execution",
                resource_id=record.submission_id,
            ),
        )
        anchor_gateway.records = [
            AnchorProjectionRecord.from_mapping(item)
            for item in store.anchor_projection()
        ]
        with self.assertRaises(ExecutionPolicyNotPassed):
            adapter.authorize_arena_execution(request, occurred_at=202)

    def test_live_activation_requires_authenticated_external_qvl(self):
        qvl = Account.create("arena-qvl")
        verdict = _signed_verdict(self.harness, qvl)
        activation = activation_from_independent_verdict(
            verdict,
            trusted_verifier_addresses=(qvl.address,),
            recipient=self.harness.recipient,
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_quote_sha256="sha256:" + hashlib.sha256(QUOTE_BYTES).hexdigest(),
            expected_challenge=_challenge_from_verdict(verdict),
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
            now=200,
        )
        self.assertTrue(activation.independent_tdx_verdict_verified)
        self.assertEqual(activation.verifier_address.lower(), qvl.address.lower())
        self.assertEqual(activation.challenge_manifest_hash, self.harness.challenge.manifest_hash)

        attacker = Account.create("arena-attacker")
        forged = _signed_verdict(self.harness, qvl, signer=attacker)
        with self.assertRaisesRegex(ArenaSafeWorkerUnavailable, "authentication failed"):
            activation_from_independent_verdict(
                forged,
                trusted_verifier_addresses=(qvl.address,),
                recipient=self.harness.recipient,
                expected_compose_hash=COMPOSE_HASH,
                expected_app_id=APP_ID,
                expected_os_image_hash=OS_IMAGE_HASH,
                expected_quote_sha256="sha256:" + hashlib.sha256(QUOTE_BYTES).hexdigest(),
                expected_challenge=_challenge_from_verdict(forged),
                expected_tee_signer_address=TEE_ADDRESS,
                chain_id=84_532,
                challenge_registry_address=REGISTRY_ADDRESS,
                now=200,
            )

    def test_each_job_renews_one_quote_and_accepts_quote_rotation(self):
        first = self.harness.submit(_valid_source(), name="renewal-one")
        second = self.harness.submit(_valid_source(), name="renewal-two")
        second_quote = bytes.fromhex("12" * len(QUOTE_BYTES))
        packets = [
            _attestation_packet(self.harness, QUOTE_BYTES),
            _attestation_packet(self.harness, second_quote),
        ]
        collection_count = 0

        def collect(**_kwargs):
            nonlocal collection_count
            packet = packets[collection_count]
            collection_count += 1
            return packet

        qvl = Account.create("arena-renewing-qvl")
        verdict_provider = _MatchingVerdictProvider(self.harness, qvl)
        activation_provider = _refreshing_provider(
            self.harness,
            verdict_provider,
            collect,
        )
        service = ArenaSafeWorkerService(
            arena_store=self.harness.arena,
            worker=self.harness.worker(
                activation_provider=activation_provider,
            ),
            poll_interval_seconds=0.05,
        )

        first_status = service.run_once(occurred_at=200)
        second_status = service.run_once(occurred_at=201)

        self.assertEqual(first_status.state, "completed")
        self.assertEqual(second_status.state, "completed")
        self.assertEqual(
            {first_status.submission_id, second_status.submission_id},
            {first.submission_id, second.submission_id},
        )
        self.assertEqual(collection_count, 2)
        self.assertEqual(len(verdict_provider.quote_hashes), 2)
        self.assertNotEqual(
            verdict_provider.quote_hashes[0],
            verdict_provider.quote_hashes[1],
        )

    def test_changed_quote_cannot_reuse_the_previous_signed_verdict(self):
        changed_quote = bytes.fromhex("13" * len(QUOTE_BYTES))
        packet = _attestation_packet(self.harness, changed_quote)
        qvl = Account.create("arena-stale-quote-qvl")
        verdict_provider = _FixedVerdictProvider(
            _signed_verdict(self.harness, qvl)
        )
        activation_provider = RefreshingArenaActivationProvider(
            recipient=self.harness.recipient,
            verdict_provider=verdict_provider,
            trusted_verifier_addresses=(qvl.address,),
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
            attestation_collector=lambda **_kwargs: packet,
        )

        with self.assertRaisesRegex(
            ArenaSafeWorkerUnavailable,
            "authentication failed",
        ):
            activation_provider.refresh_activation(occurred_at=200)
        self.assertEqual(verdict_provider.calls, 1)

    def test_expired_fresh_quote_verdict_fails_before_queue_mutation(self):
        record = self.harness.submit(_valid_source(), name="expired-verdict")
        packet = _attestation_packet(self.harness)
        qvl = Account.create("arena-expired-qvl")
        verdict_provider = _FixedVerdictProvider(
            _signed_verdict(
                self.harness,
                qvl,
                issued_at=180,
                expires_at=200,
            )
        )
        activation_provider = RefreshingArenaActivationProvider(
            recipient=self.harness.recipient,
            verdict_provider=verdict_provider,
            trusted_verifier_addresses=(qvl.address,),
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
            attestation_collector=lambda **_kwargs: packet,
        )

        worker = self.harness.worker(activation_provider=activation_provider)
        with self.assertRaisesRegex(
            ArenaSafeWorkerUnavailable,
            "authentication failed",
        ):
            worker.process_submission(record.submission_id, occurred_at=200)
        self.assertEqual(verdict_provider.calls, 1)
        self.assertEqual(
            self.harness.arena.get_submission(record.submission_id).state,
            QueueState.SUBMITTED,
        )

    def test_recipient_report_data_is_not_a_self_declared_qvl_expectation(self):
        packet = _attestation_packet(
            self.harness,
            report_data="0x" + "aa" * 32,
            quote_report_data="0x" + "aa" * 32,
        )
        qvl = Account.create("arena-report-binding-qvl")
        verdict_provider = _FixedVerdictProvider(
            _signed_verdict(self.harness, qvl)
        )
        activation_provider = RefreshingArenaActivationProvider(
            recipient=self.harness.recipient,
            verdict_provider=verdict_provider,
            trusted_verifier_addresses=(qvl.address,),
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
            attestation_collector=lambda **_kwargs: packet,
        )

        with self.assertRaisesRegex(
            ArenaSafeWorkerUnavailable,
            "does not match release pins",
        ):
            activation_provider.refresh_activation(occurred_at=200)
        self.assertEqual(verdict_provider.calls, 0)

    def test_raw_quote_is_ephemeral_and_absent_from_safe_representations(self):
        packet = _attestation_packet(self.harness)
        qvl = Account.create("arena-no-quote-leak-qvl")
        verdict_provider = _MatchingVerdictProvider(self.harness, qvl)
        activation_provider = _refreshing_provider(
            self.harness,
            verdict_provider,
            lambda **_kwargs: packet,
        )

        activation = activation_provider.refresh_activation(occurred_at=200)
        raw_quote_hex = QUOTE_BYTES.hex()
        self.assertNotIn(raw_quote_hex, repr(packet))
        self.assertNotIn(raw_quote_hex, repr(activation))
        self.assertNotIn(raw_quote_hex, repr(activation_provider))
        self.assertNotIn(raw_quote_hex, repr(activation_provider.__dict__))

    def test_verified_service_factory_connects_qvl_policy_and_durable_stores(self):
        record = self.harness.submit(_valid_source())
        policy_path = Path(self.temp.name) / "factory-policy.json"
        integrity_key = b"f" * 32
        policy_store = ExecutionPolicyStore(
            policy_path,
            integrity_key=integrity_key,
        )
        policy_store.append(
            surface="arena_execution",
            resource_id=record.submission_id,
            result=PolicyGateResult(
                decision=PolicyDecision.PASS,
                corpus_ref="corpus://sealed",
                stage=4,
                reason_code="policy_passed",
                request_hash="1" * 64,
                policy_hash="2" * 64,
            ),
            recorded_at=190,
            expires_at=300,
            expected_previous_decision_hash=ZERO_DECISION_HASH,
            approver_hash="3" * 64,
            approval_hash="4" * 64,
            approval_domain_hash="5" * 64,
            approver_root_hash=execution_policy_approver_root_hash(
                ["3" * 64]
            ),
        )
        qvl = Account.create("arena-factory-qvl")
        packet = _attestation_packet(self.harness)
        activation_provider = RefreshingArenaActivationProvider(
            recipient=self.harness.recipient,
            verdict_provider=_FixedVerdictProvider(
                _signed_verdict(self.harness, qvl)
            ),
            trusted_verifier_addresses=(qvl.address,),
            expected_compose_hash=COMPOSE_HASH,
            expected_app_id=APP_ID,
            expected_os_image_hash=OS_IMAGE_HASH,
            expected_tee_signer_address=TEE_ADDRESS,
            chain_id=84_532,
            challenge_registry_address=REGISTRY_ADDRESS,
            attestation_collector=lambda **_kwargs: packet,
        )
        service = build_verified_arena_worker_service(
            arena_store_path=self.harness.arena.path,
            arena_store_integrity_key=ARENA_STORE_KEY,
            ingress_store_path=self.harness.ingress_store.root_dir,
            recipient=self.harness.recipient,
            evaluator=self.harness.evaluator,
            activation_provider=activation_provider,
            registry_claim_gate=self.harness.registry_gate,
            execution_policy_store_path=policy_path,
            execution_policy_integrity_key=integrity_key,
            execution_policy_approval_domain_hash="5" * 64,
            execution_policy_approver_root_hash=execution_policy_approver_root_hash(
                ["3" * 64]
            ),
            execution_policy_approved_approver_hashes={"3" * 64},
            execution_policy_anchor_gateway=(
                _read_only_anchor_gateway(policy_store)
            ),
            poll_interval_seconds=0.05,
        )
        with _live_runtime(self.harness):
            status = service.run_once(occurred_at=200)
        self.assertEqual(status.state, "completed")
        self.assertEqual(status.submission_id, record.submission_id)


if __name__ == "__main__":
    unittest.main()
