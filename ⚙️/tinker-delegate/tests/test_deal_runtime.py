import json
import os
import tempfile
import time
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.chain_submitter import (
    DealRead,
    PreparedSubmissionAttempt,
    SignerAttestationEvidence,
    signer_attestation_report_data,
)
from tinker_delegate.chain_watcher import (
    ChainCursorState,
    ChainCursorStore,
    DiligenceRoomEvent,
)
from tinker_delegate.deal_runtime import (
    AttestationVerdictUnavailable,
    BoundedEvaluation,
    ControlPlaneError,
    DealContextMissing,
    DealRuntimeError,
    DealRuntimeRecord,
    DealRuntimeService,
    DealRuntimeSingleWriterLease,
    DealRuntimeStateStore,
    ExecutionPolicyNotReady,
    HttpsIndependentQvlClient,
    InternalDealApi,
    ProductionResultCoordinator,
    RuntimeStage,
    RuntimeStateError,
    SignerAttestationPacket,
    SubmissionRejected,
    SubmissionOutcome,
    SubmissionReconciliation,
    build_parser,
)
from tinker_delegate.execution_policy_store import execution_resource_hash
from tinker_delegate.policy_kernel import POLICY_CANONICALIZATION_VERSION
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    ResultVerifierPolicy,
    independent_attestation_verdict_digest,
)
from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    qvl_challenge_digest,
)


CONTRACT = "0x" + "44" * 20
TEE = "0x" + "33" * 20
COMPOSE_HASH = "0x" + "99" * 32
RESULT_HASH = "0x" + "cd" * 32
TX_HASH = "0x" + "12" * 32
QVL = "0x" + "77" * 20
QVL_POLICY_HASH = "0x" + "88" * 32
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32


def _signed_qvl_challenge(
    verifier: Account,
    *,
    profile: str = "diligence",
    now: int | None = None,
) -> QvlChallenge:
    issued_at = int(time.time() if now is None else now)
    unsigned = QvlChallenge(
        schema=CHALLENGE_SCHEMA,
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile=profile,
        cvm_id=CVM_ID,
        deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
        release_authority_sha256=RELEASE_AUTHORITY_SHA256,
        ceremony_nonce=CEREMONY_NONCE,
        measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        release_policy_hash=QVL_POLICY_HASH,
        challenge_id="0x" + "ab" * 32,
        challenge_digest="0x" + "01" * 32,
        issued_at=issued_at,
        expires_at=issued_at + 120,
        verifier_address=verifier.address.lower(),
        verifier_signature="0x" + "00" * 65,
    )
    digest = qvl_challenge_digest(unsigned)
    signature = verifier.sign_message(encode_defunct(hexstr=digest)).signature
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signature).hex(),
    )


def _signed_qvl_verdict(
    evidence: SignerAttestationEvidence,
    verifier: Account,
    challenge: QvlChallenge,
) -> IndependentAttestationVerdict:
    unsigned = IndependentAttestationVerdict(
        schema=INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        verification_method=INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        verified=True,
        chain_id=challenge.chain_id,
        domain=challenge.domain,
        profile=challenge.profile,
        cvm_id=challenge.cvm_id,
        deployment_intent_sha256=challenge.deployment_intent_sha256,
        release_authority_sha256=challenge.release_authority_sha256,
        ceremony_nonce=challenge.ceremony_nonce,
        measurement_policy_sha256=challenge.measurement_policy_sha256,
        release_policy_hash=challenge.release_policy_hash,
        challenge_id=challenge.challenge_id,
        challenge_digest=challenge.challenge_digest,
        challenge_issued_at=challenge.issued_at,
        challenge_expires_at=challenge.expires_at,
        quote_hash=evidence.quote_hash,
        report_data=evidence.report_data,
        compose_hash=evidence.compose_hash,
        app_id=evidence.app_id,
        os_image_hash=evidence.os_image_hash,
        signer_address=evidence.signer_address,
        contract_address=evidence.contract_address,
        issued_at=challenge.issued_at,
        activation_evidence_lease_expires_at=challenge.expires_at,
        expires_at=challenge.expires_at,
        verifier_address=verifier.address,
        verifier_signature="0x" + "00" * 65,
    )
    signature = verifier.sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    ).signature
    return replace(unsigned, verifier_signature="0x" + bytes(signature).hex())


def _evaluation(deal_id: str = "7") -> BoundedEvaluation:
    return BoundedEvaluation(
        deal_id=deal_id,
        score_band="high",
        quality_delta="10-20% quality-improvement band",
        offer_price=70_000_000_000_000_000,
        recommendation="accept",
        confidence="withheld",
        methodology_summary="private_evaluator_details_withheld",
        compute_cost_wei=1_000_000_000_000_000,
        fee_wei=10_000_000_000_000,
    )


def _policy_status(deal_id: str = "7", *, current: bool = True) -> dict:
    resource_hash = execution_resource_hash("deal_evaluation", deal_id)
    approval_domain_hash = "66" * 32
    approver_root_hash = "77" * 32
    record = None
    if current:
        record = {
            "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
            "surface": "deal_evaluation",
            "resource_id_hash": resource_hash,
            "decision": "pass",
            "reason_code": "policy_passed",
            "request_hash": "11" * 32,
            "policy_hash": "22" * 32,
            "recorded_at": 1_800_000_000,
            "expires_at": 1_800_000_300,
            "approver_hash": "33" * 32,
            "approval_hash": "44" * 32,
            "approval_domain_hash": approval_domain_hash,
            "decision_hash": "55" * 32,
            "raw_policy_egress": False,
            "raw_resource_id_egress": False,
        }
    return {
        "surface": "execution_policy_status",
        "schema_version": 2,
        "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
        "approval_domain_hash": approval_domain_hash,
        "approver_root_hash": approver_root_hash,
        "found": current,
        "resource_id_hash": resource_hash,
        "current_pass": current,
        "raw_resource_id_egress": False,
        "record": record,
    }


class BoundedEvaluationTest(unittest.TestCase):
    def test_accepts_only_fixed_bounded_projection(self):
        parsed = BoundedEvaluation.from_public_dict(
            _evaluation().to_public_dict(),
            expected_deal_id="7",
        )
        self.assertEqual(parsed.score_band, "high")
        self.assertEqual(parsed.confidence, "withheld")

        invalid = _evaluation().to_public_dict()
        invalid["evaluator_notes"] = "private"
        with self.assertRaisesRegex(ControlPlaneError, "shape_invalid"):
            BoundedEvaluation.from_public_dict(invalid, expected_deal_id="7")

        invalid = _evaluation().to_public_dict()
        invalid["methodology_summary"] = "trained on private examples"
        with self.assertRaisesRegex(ControlPlaneError, "methodology_not_bounded"):
            BoundedEvaluation.from_public_dict(invalid, expected_deal_id="7")

    def test_rejects_bool_as_numeric_and_wrong_deal_binding(self):
        invalid = _evaluation().to_public_dict()
        invalid["compute_cost_wei"] = True
        with self.assertRaisesRegex(ControlPlaneError, "compute_cost_wei_invalid"):
            BoundedEvaluation.from_public_dict(invalid, expected_deal_id="7")

        invalid = _evaluation().to_public_dict()
        invalid["deal_id"] = "8"
        with self.assertRaisesRegex(ControlPlaneError, "deal_binding_invalid"):
            BoundedEvaluation.from_public_dict(invalid, expected_deal_id="7")


class InternalDealApiTest(unittest.TestCase):
    def test_reorg_quarantine_requires_exact_bounded_acknowledgement(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(
                200,
                json={
                    "deal_id": "7",
                    "quarantined": True,
                    "seller_reupload_required": True,
                    "raw_secret_egress": False,
                },
            )

        api = InternalDealApi(
            "http://delegate:8080",
            auth_token="runtime-test-token",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )
        api.quarantine_reorg("7")
        self.assertEqual(requests[0].url.path, "/deal/7/chain-reorg")
        self.assertEqual(
            requests[0].headers["authorization"],
            "Bearer runtime-test-token",
        )

    def test_policy_preflight_and_evaluation_use_runtime_bearer_only_in_header(self):
        requests = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/policy/status":
                return httpx.Response(200, json=_policy_status())
            if request.url.path == "/deal/7/result":
                return httpx.Response(404, json={"detail": "not found"})
            if request.url.path == "/deal/7/evaluate":
                return httpx.Response(200, json=_evaluation().to_public_dict())
            return httpx.Response(500)

        api = InternalDealApi(
            "http://delegate:8080",
            auth_token="runtime-test-token",
            client=httpx.Client(transport=httpx.MockTransport(handler)),
        )

        self.assertTrue(api.execution_policy_current("7"))
        self.assertIsNone(api.get_result("7"))
        self.assertEqual(api.evaluate("7").score_band, "high")
        self.assertEqual(len(requests), 3)
        for request in requests:
            self.assertEqual(request.headers["authorization"], "Bearer runtime-test-token")
            self.assertNotIn(b"runtime-test-token", request.content)

    def test_policy_preflight_validates_exact_resource_binding(self):
        invalid = _policy_status()
        invalid["resource_id_hash"] = "00" * 32

        api = InternalDealApi(
            "http://delegate:8080",
            auth_token="runtime-test-token",
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(200, json=invalid)
                )
            ),
        )
        with self.assertRaisesRegex(ControlPlaneError, "resource_binding_invalid"):
            api.execution_policy_current("7")

    def test_fixed_forbidden_evaluation_is_awaiting_policy(self):
        api = InternalDealApi(
            "http://delegate:8080",
            auth_token="runtime-test-token",
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(
                        403,
                        json={"detail": "Execution policy gate is not passed for this resource"},
                    )
                )
            ),
        )
        with self.assertRaises(ExecutionPolicyNotReady):
            api.evaluate("7")

    def test_requires_runtime_auth_and_never_accepts_url_credentials(self):
        with self.assertRaisesRegex(DealRuntimeError, "runtime auth"):
            InternalDealApi("http://delegate:8080", auth_token="")
        with self.assertRaisesRegex(DealRuntimeError, "endpoint is invalid"):
            InternalDealApi(
                "https://user:password@delegate.example",
                auth_token="runtime-test-token",
            )


class DealRuntimeStateStoreTest(unittest.TestCase):
    def test_round_trip_is_mode_0600_and_contains_only_bounded_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            store = DealRuntimeStateStore(path)
            store.save(
                {
                    "7": DealRuntimeRecord(
                        deal_id="7",
                        stage=RuntimeStage.EVALUATED,
                        evaluation=_evaluation(),
                        funded_tx_hash=TX_HASH,
                        attempt_count=1,
                        last_reason="bounded_evaluation_available",
                    )
                }
            )
            loaded = store.load()
            blob = path.read_text(encoding="utf-8")

            self.assertEqual(loaded["7"].evaluation.score_band, "high")
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertNotIn("artifact", blob.lower())
            self.assertNotIn("runtime-test-token", blob)
            self.assertIn('"raw_secret_egress": false', blob)

    def test_rejects_corrupt_or_secret_claiming_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.json"
            store = DealRuntimeStateStore(path)
            store.save(
                {
                    "7": DealRuntimeRecord(
                        deal_id="7",
                        stage=RuntimeStage.WAITING_ARTIFACT,
                    )
                }
            )
            payload = json.loads(path.read_text(encoding="utf-8"))
            payload["deals"]["7"]["raw_secret_egress"] = True
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(RuntimeStateError):
                store.load()

            os.chmod(path, 0o644)
            with self.assertRaisesRegex(RuntimeStateError, "unsafe"):
                store.load()


class FakeSource:
    contract_address = CONTRACT

    def __init__(self, events, latest=11):
        self.events = events
        self.latest = latest
        self.ranges = []
        self.hashes = {}

    def latest_block(self):
        return self.latest

    def block_hash(self, block_number):
        return self.hashes.get(
            block_number,
            "0x" + f"{block_number + 1:064x}",
        )

    def get_events(self, start, end):
        self.ranges.append((start, end))
        return list(self.events)


class FakeDispatcher:
    def __init__(self):
        self._created = {}
        self.batches = []

    @property
    def created_context(self):
        return dict(self._created)

    def dispatch(self, events):
        self.batches.append(list(events))
        return SimpleNamespace()


class FakeControlPlane:
    def __init__(self, *, policy=True, existing=None, evaluated=None, missing_context=False):
        self.policy = policy
        self.existing = existing
        self.evaluated = evaluated if evaluated is not None else _evaluation()
        self.missing_context = missing_context
        self.calls = []

    def execution_policy_current(self, deal_id):
        self.calls.append(("policy", deal_id))
        return self.policy

    def get_result(self, deal_id):
        self.calls.append(("get", deal_id))
        return self.existing

    def evaluate(self, deal_id):
        self.calls.append(("evaluate", deal_id))
        if self.missing_context:
            raise DealContextMissing("deal_context_missing")
        return self.evaluated

    def notify_funded(self, context):
        self.calls.append(("notify", context["deal_id"]))

    def quarantine_reorg(self, deal_id):
        self.calls.append(("reorg", deal_id))
        self.missing_context = True


class FakeCoordinator:
    def __init__(self, *, disposition="funded", error=None):
        self.disposition = disposition
        self.error = error
        self.submissions = []

    def inspect(self, deal_id):
        return self.disposition

    def funded_context(self, deal_id):
        return {
            "deal_id": deal_id,
            "buyer": "0x" + "22" * 20,
            "seller": "0x" + "11" * 20,
            "budget_cap": 10**17,
            "reserve_price": 10**15,
            "artifact_hash": "0x" + "aa" * 32,
        }

    def submit(self, evaluation, *, before_broadcast=None):
        self.submissions.append(evaluation)
        if self.error:
            raise self.error
        if before_broadcast is not None:
            before_broadcast(
                PreparedSubmissionAttempt(
                    tx_hash=TX_HASH,
                    nonce=7,
                    result_hash=RESULT_HASH,
                    prepared_at=int(time.time()),
                )
            )
        return SubmissionOutcome(tx_hash=TX_HASH, result_hash=RESULT_HASH)

    def reconcile_submission(self, *, deal_id, tx_hash, nonce):
        return SubmissionReconciliation(
            status="confirmed_success",
            receipt_block=11,
            receipt_block_hash="0x" + f"{12:064x}",
            receipt_status=1,
        )


def _funded_event() -> DiligenceRoomEvent:
    return DiligenceRoomEvent(
        name="DealFunded",
        deal_id="7",
        block_number=11,
        tx_hash="0x" + "01" * 32,
        log_index=0,
        fields={
            "buyer": "0x" + "22" * 20,
            "budget_cap": 10**17,
            "payment_token": "0x" + "00" * 20,
        },
    )


class DealRuntimeServiceTest(unittest.TestCase):
    def _service(
        self,
        tmp: str,
        *,
        events=None,
        control_plane=None,
        coordinator=None,
        confirmations=0,
        trace=None,
    ):
        cursor = ChainCursorStore(Path(tmp) / "cursor.json")
        state = DealRuntimeStateStore(Path(tmp) / "state.json")
        if trace is not None:
            original_state_save = state.save
            original_cursor_update = cursor.update_after_scan

            def save(records):
                trace.append("journal")
                return original_state_save(records)

            def update(**kwargs):
                trace.append("cursor")
                return original_cursor_update(**kwargs)

            state.save = save
            cursor.update_after_scan = update
        return DealRuntimeService(
            source=FakeSource(events or [_funded_event()]),
            dispatcher=FakeDispatcher(),
            cursor_store=cursor,
            state_store=state,
            control_plane=control_plane or FakeControlPlane(),
            result_coordinator=coordinator or FakeCoordinator(),
            start_block=11,
            confirmations=confirmations,
        )

    def test_full_confirmed_event_to_bounded_evaluation_to_submission(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane()
            coordinator = FakeCoordinator()
            runtime = self._service(tmp, control_plane=cp, coordinator=coordinator)

            summary = runtime.run_once().to_public_dict()
            record = DealRuntimeStateStore(Path(tmp) / "state.json").load()["7"]

            self.assertEqual(record.stage, RuntimeStage.SUBMITTED)
            self.assertEqual(record.submission_tx_hash, TX_HASH)
            self.assertEqual(record.result_hash, RESULT_HASH)
            self.assertEqual(
                cp.calls,
                [("policy", "7"), ("get", "7"), ("evaluate", "7")],
            )
            self.assertEqual(len(coordinator.submissions), 1)
            self.assertEqual(ChainCursorStore(Path(tmp) / "cursor.json").load().next_block, 12)
            self.assertEqual(summary["submitted"], 1)
            self.assertFalse(summary["raw_secret_egress"])

    def test_journal_is_durable_before_cursor_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            trace = []
            runtime = self._service(tmp, trace=trace)
            runtime.run_once()
            self.assertLess(trace.index("journal"), trace.index("cursor"))

    def test_result_recovery_avoids_duplicate_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane(existing=_evaluation())
            runtime = self._service(tmp, control_plane=cp)
            runtime.run_once()
            self.assertEqual(cp.calls, [("policy", "7"), ("get", "7")])

    def test_missing_policy_never_reads_result_evaluates_or_submits(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane(policy=False)
            coordinator = FakeCoordinator()
            runtime = self._service(tmp, control_plane=cp, coordinator=coordinator)
            runtime.run_once()
            record = DealRuntimeStateStore(Path(tmp) / "state.json").load()["7"]
            self.assertEqual(record.stage, RuntimeStage.AWAITING_EXECUTION_POLICY)
            self.assertEqual(cp.calls, [("policy", "7")])
            self.assertEqual(coordinator.submissions, [])

    def test_qvl_unavailable_is_retryable_without_chain_submission_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            coordinator = FakeCoordinator(
                error=AttestationVerdictUnavailable("independent_qvl_unavailable")
            )
            runtime = self._service(tmp, coordinator=coordinator)
            runtime.run_once()
            record = DealRuntimeStateStore(Path(tmp) / "state.json").load()["7"]
            self.assertEqual(record.stage, RuntimeStage.AWAITING_QVL)
            self.assertEqual(record.submission_tx_hash, "")

    def test_api_restart_rehydrates_public_chain_context_but_requires_reupload(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane(missing_context=True)
            runtime = self._service(tmp, control_plane=cp)
            runtime.run_once()
            record = DealRuntimeStateStore(Path(tmp) / "state.json").load()["7"]
            self.assertEqual(record.stage, RuntimeStage.WAITING_ARTIFACT)
            self.assertEqual(record.last_reason, "funded_context_rehydrated")
            self.assertEqual(
                cp.calls,
                [
                    ("policy", "7"),
                    ("get", "7"),
                    ("evaluate", "7"),
                    ("notify", "7"),
                ],
            )

    def test_confirmed_submission_and_resolution_events_are_monotonic(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = DealRuntimeStateStore(Path(tmp) / "state.json")
            state.save(
                {
                    "7": DealRuntimeRecord(
                        deal_id="7",
                        stage=RuntimeStage.SUBMITTED,
                        evaluation=_evaluation(),
                        submission_tx_hash=TX_HASH,
                        result_hash=RESULT_HASH,
                    )
                }
            )
            runtime = self._service(tmp, events=[_funded_event()])
            runtime.state_store = state
            runtime.records = state.load()
            runtime.run_once()
            self.assertEqual(state.load()["7"].stage, RuntimeStage.SUBMITTED)

            resolved = DiligenceRoomEvent(
                name="DealAccepted",
                deal_id="7",
                block_number=12,
                tx_hash="0x" + "02" * 32,
                log_index=0,
                fields={},
            )
            runtime._observe_events([resolved])
            state.save(runtime.records)
            runtime._observe_events([_funded_event()])
            state.save(runtime.records)
            self.assertEqual(state.load()["7"].stage, RuntimeStage.RESOLVED)

    def test_cursor_contract_mismatch_and_confirmation_downgrade_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._service(tmp)
            runtime.cursor_store.save(
                ChainCursorState(
                    next_block=11,
                    confirmations=2,
                    contract_address="0x" + "55" * 20,
                )
            )
            with self.assertRaisesRegex(RuntimeStateError, "different contract"):
                runtime.run_once()

        with tempfile.TemporaryDirectory() as tmp:
            runtime = self._service(tmp, confirmations=1)
            runtime.cursor_store.save(
                ChainCursorState(
                    next_block=11,
                    confirmations=2,
                    contract_address=CONTRACT,
                )
            )
            with self.assertRaisesRegex(RuntimeStateError, "cannot be downgraded"):
                runtime.run_once()

    def test_crash_after_prepare_recovers_exact_hash_without_rebroadcast(self):
        class CrashAfterPrepare(FakeCoordinator):
            def submit(self, evaluation, *, before_broadcast=None):
                self.submissions.append(evaluation)
                before_broadcast(
                    PreparedSubmissionAttempt(
                        tx_hash=TX_HASH,
                        nonce=9,
                        result_hash=RESULT_HASH,
                        prepared_at=int(time.time()),
                    )
                )
                raise SystemExit("simulated process death after durable prepare")

        class ManualHold(FakeCoordinator):
            def __init__(self):
                super().__init__()
                self.reconciliations = []

            def reconcile_submission(self, *, deal_id, tx_hash, nonce):
                self.reconciliations.append((deal_id, tx_hash, nonce))
                return SubmissionReconciliation(
                    status="exact_transaction_not_found"
                )

        with tempfile.TemporaryDirectory() as tmp:
            first = self._service(tmp, coordinator=CrashAfterPrepare())
            with self.assertRaises(SystemExit):
                first.run_once()
            prepared = DealRuntimeStateStore(
                Path(tmp) / "state.json"
            ).load()["7"]
            self.assertEqual(
                prepared.stage,
                RuntimeStage.SUBMISSION_UNCERTAIN,
            )
            self.assertEqual(prepared.submission_attempt_tx_hash, TX_HASH)
            self.assertEqual(prepared.submission_nonce, 9)
            self.assertEqual(
                prepared.submission_attempt_result_hash,
                RESULT_HASH,
            )

            hold = ManualHold()
            restarted = self._service(
                tmp,
                events=[],
                coordinator=hold,
            )
            restarted.source.events = []
            restarted.run_once()
            recovered = DealRuntimeStateStore(
                Path(tmp) / "state.json"
            ).load()["7"]
            self.assertEqual(
                recovered.stage,
                RuntimeStage.SUBMISSION_UNCERTAIN,
            )
            self.assertEqual(
                recovered.last_reason,
                "exact_submission_not_found_manual_hold",
            )
            self.assertEqual(hold.submissions, [])
            self.assertEqual(hold.reconciliations, [("7", TX_HASH, 9)])

    def test_block_hash_reorg_quarantines_and_rebuilds_from_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane()
            runtime = self._service(tmp, control_plane=cp)
            runtime.run_once()
            runtime.source.hashes[11] = "0x" + "ef" * 32
            runtime.run_once()

            rebuilt = DealRuntimeStateStore(
                Path(tmp) / "state.json"
            ).load()["7"]
            self.assertEqual(rebuilt.stage, RuntimeStage.WAITING_ARTIFACT)
            self.assertEqual(
                rebuilt.last_reason,
                "funded_context_rehydrated",
            )
            self.assertIn(("reorg", "7"), cp.calls)
            self.assertIn(("notify", "7"), cp.calls)
            self.assertIsNone(rebuilt.evaluation)

    def test_reorg_cursor_rewind_survives_crash_before_state_compensation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cp = FakeControlPlane()
            runtime = self._service(tmp, control_plane=cp)
            runtime.run_once()
            runtime.source.hashes[11] = "0x" + "de" * 32
            durable_save = runtime.state_store.save

            def crash_before_empty_state(records):
                if not records:
                    raise SystemExit(
                        "simulated death after cursor rewind"
                    )
                return durable_save(records)

            runtime.state_store.save = crash_before_empty_state
            with self.assertRaises(SystemExit):
                runtime.run_once()
            self.assertEqual(
                ChainCursorStore(Path(tmp) / "cursor.json").load().next_block,
                11,
            )
            # The old checkpoint intentionally remains, so restart can detect
            # and repeat compensation rather than trust the prior cursor.
            self.assertIn(
                "7",
                DealRuntimeStateStore(Path(tmp) / "state.json").load(),
            )

            restarted = self._service(tmp, control_plane=cp)
            restarted.source.hashes[11] = "0x" + "de" * 32
            restarted.run_once()
            rebuilt = DealRuntimeStateStore(
                Path(tmp) / "state.json"
            ).load()["7"]
            self.assertEqual(rebuilt.stage, RuntimeStage.WAITING_ARTIFACT)
            self.assertIn(("notify", "7"), cp.calls)

    def test_single_writer_lease_rejects_second_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "runtime.lock"
            first = DealRuntimeSingleWriterLease(path)
            second = DealRuntimeSingleWriterLease(path)
            first.acquire()
            try:
                with self.assertRaisesRegex(
                    RuntimeStateError,
                    "already held",
                ):
                    second.acquire()
            finally:
                first.release()
            second.acquire()
            second.release()


class InjectedVerifierSigner:
    custody = "injected_runtime_test_verifier"

    def __init__(self):
        self._account = Account.create("deal-runtime-verifier")
        self.address = self._account.address

    def sign_authorization_digest(self, digest):
        signature = self._account.sign_message(encode_defunct(hexstr=digest)).signature
        return "0x" + signature.hex()


class InjectedTeeSigner:
    custody = "injected_test_runtime"

    def __init__(self):
        self.address = Account.create("deal-runtime-tee").address


class FakeRpc:
    def __init__(self, chain_id=31_337):
        self._chain_id = chain_id

    def chain_id(self):
        return self._chain_id


class FakeSubmitter:
    contract_address = CONTRACT

    def __init__(
        self,
        signer,
        verifier_address,
        *,
        attestation_verifier=QVL,
        attestation_release_policy_hash=QVL_POLICY_HASH,
        attestation_binding_frozen=True,
    ):
        self.signer = signer
        self.verifier_address = verifier_address
        self.calls = []
        self.attestation_verifier = attestation_verifier
        self.attestation_release_policy_hash = attestation_release_policy_hash
        self.attestation_binding_frozen = attestation_binding_frozen
        self.deal = DealRead(
            seller="0x" + "11" * 20,
            buyer="0x" + "22" * 20,
            reserve_price=10**15,
            budget_cap=10**17,
            expiry=2_000_000_000,
            state=1,
            artifact_hash="0x" + "aa" * 32,
            tee_identity=signer.address,
            score_band=0,
            compute_cost=0,
            fee=0,
            result_hash="0x" + "00" * 32,
        )

    def read_result_verifier(self):
        return self.verifier_address

    def read_attestation_verifier(self):
        return self.attestation_verifier

    def read_attestation_release_policy_hash(self):
        return self.attestation_release_policy_hash

    def read_attestation_binding_frozen(self):
        return self.attestation_binding_frozen

    def read_deal(self, _deal_id):
        return self.deal

    def read_fee_bps(self):
        return 100

    def read_compute_settlement_policy_enabled(self):
        return True

    def submit_result(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(tx_hash=TX_HASH, result_hash=RESULT_HASH)


class ProductionResultCoordinatorTest(unittest.TestCase):
    def test_local_structural_path_cannot_settle_without_independent_qvl_authorization(self):
        tee = InjectedTeeSigner()
        verifier = InjectedVerifierSigner()
        submitter = FakeSubmitter(tee, verifier.address)
        report_data = "0x" + signer_attestation_report_data(
            signer_address=tee.address,
            chain_id=31_337,
            contract_address=CONTRACT,
        ).hex()
        evidence = SignerAttestationEvidence(
            mode="tdx",
            signer_address=tee.address,
            chain_id=31_337,
            contract_address=CONTRACT,
            report_data=report_data,
            quote_report_data=report_data,
            quote_hash="0x" + "88" * 32,
            quote_size=5_006,
            compose_hash=COMPOSE_HASH,
            app_id="runtime-test-app",
            os_image_hash="runtime-test-os",
        )
        coordinator = ProductionResultCoordinator(
            rpc=FakeRpc(),
            submitter=submitter,
            verifier_signer=verifier,
            policy=ResultVerifierPolicy(
                allowed_compose_hashes=(COMPOSE_HASH,),
                allowed_app_ids=("runtime-test-app",),
                allowed_os_image_hashes=("runtime-test-os",),
                attestation_release_policy_hash=QVL_POLICY_HASH,
                allow_unverified_local_attestation=True,
            ),
            verdict_provider=None,
            allow_unverified_local_attestation=True,
            attestation_collector=lambda **_kwargs: SignerAttestationPacket(
                evidence=evidence,
                quote="0x1234",
            ),
        )

        with self.assertRaisesRegex(
            SubmissionRejected,
            "result_authorization_rejected",
        ):
            coordinator.submit(_evaluation())

        self.assertEqual(submitter.calls, [])

    def test_production_startup_requires_exact_frozen_qvl_root_and_policy(self):
        tee = InjectedTeeSigner()
        verifier = InjectedVerifierSigner()
        submitter = FakeSubmitter(tee, verifier.address)
        policy = ResultVerifierPolicy(
            allowed_compose_hashes=(COMPOSE_HASH,),
            allowed_app_ids=("runtime-test-app",),
            trusted_attestation_verifier_addresses=(QVL,),
        )

        with (
            patch("tinker_delegate.deal_runtime.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.deal_runtime.is_dstack_simulator", return_value=False),
        ):
            coordinator = ProductionResultCoordinator(
                rpc=FakeRpc(84_532),
                submitter=submitter,
                verifier_signer=verifier,
                policy=policy,
                verdict_provider=object(),
                attestation_release_policy_hash=QVL_POLICY_HASH,
            )

        self.assertEqual(coordinator.chain_id, 84_532)

        for roots, policy_hash, expected in (
            ((QVL, "0x" + "66" * 20), QVL_POLICY_HASH, "exactly one"),
            ((QVL,), "0x" + "99" * 32, "policy hash does not match"),
        ):
            with (
                self.subTest(expected=expected),
                patch("tinker_delegate.deal_runtime.is_dstack_enabled", return_value=True),
                patch("tinker_delegate.deal_runtime.is_dstack_simulator", return_value=False),
                self.assertRaisesRegex(DealRuntimeError, expected),
            ):
                ProductionResultCoordinator(
                    rpc=FakeRpc(84_532),
                    submitter=submitter,
                    verifier_signer=verifier,
                    policy=ResultVerifierPolicy(
                        allowed_compose_hashes=(COMPOSE_HASH,),
                        allowed_app_ids=("runtime-test-app",),
                        trusted_attestation_verifier_addresses=roots,
                    ),
                    verdict_provider=object(),
                    attestation_release_policy_hash=policy_hash,
                )

        unfrozen = FakeSubmitter(
            tee,
            verifier.address,
            attestation_binding_frozen=False,
        )
        with (
            patch("tinker_delegate.deal_runtime.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.deal_runtime.is_dstack_simulator", return_value=False),
            self.assertRaisesRegex(DealRuntimeError, "not frozen"),
        ):
            ProductionResultCoordinator(
                rpc=FakeRpc(84_532),
                submitter=unfrozen,
                verifier_signer=verifier,
                policy=policy,
                verdict_provider=object(),
                attestation_release_policy_hash=QVL_POLICY_HASH,
            )

    def test_production_rechecks_qvl_binding_before_each_submission(self):
        tee = InjectedTeeSigner()
        verifier = InjectedVerifierSigner()
        submitter = FakeSubmitter(tee, verifier.address)
        policy = ResultVerifierPolicy(
            allowed_compose_hashes=(COMPOSE_HASH,),
            allowed_app_ids=("runtime-test-app",),
            trusted_attestation_verifier_addresses=(QVL,),
        )
        with (
            patch("tinker_delegate.deal_runtime.is_dstack_enabled", return_value=True),
            patch("tinker_delegate.deal_runtime.is_dstack_simulator", return_value=False),
        ):
            coordinator = ProductionResultCoordinator(
                rpc=FakeRpc(84_532),
                submitter=submitter,
                verifier_signer=verifier,
                policy=policy,
                verdict_provider=object(),
                attestation_release_policy_hash=QVL_POLICY_HASH,
            )

        submitter.attestation_release_policy_hash = "0x" + "99" * 32
        with self.assertRaisesRegex(DealRuntimeError, "policy hash does not match"):
            coordinator.submit(_evaluation())
        self.assertEqual(submitter.calls, [])


class IndependentQvlClientTest(unittest.TestCase):
    def test_https_client_sends_raw_quote_and_accepts_only_strict_verdict(self):
        requests = []
        verifier = Account.create("qvl")
        challenge = _signed_qvl_challenge(verifier)
        report_data = "0x" + "11" * 32
        evidence = SignerAttestationEvidence(
            mode="tdx",
            signer_address=TEE,
            chain_id=84_532,
            contract_address=CONTRACT,
            report_data=report_data,
            quote_report_data=report_data,
            quote_hash="0x" + "88" * 32,
            quote_size=4,
            compose_hash=COMPOSE_HASH,
            app_id="45" * 20,
            os_image_hash="46" * 32,
        )
        verdict = _signed_qvl_verdict(evidence, verifier, challenge).to_public_dict()

        def handler(request):
            requests.append(json.loads(request.content))
            if request.url.path == "/challenge":
                return httpx.Response(200, json=challenge.to_public_dict())
            return httpx.Response(200, json=verdict)

        client = HttpsIndependentQvlClient(
            "https://qvl.example/verify",
            auth_token="diligence-qvl-test-token-" + "x" * 32,
            client=httpx.Client(transport=httpx.MockTransport(handler)),
            trusted_verifier_addresses=(verifier.address,),
            expected_policy_hash=QVL_POLICY_HASH,
            chain_id=84_532,
            cvm_id=CVM_ID,
            deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            ceremony_nonce=CEREMONY_NONCE,
            measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        )
        issued = client.issue_challenge()
        parsed = client.verify(
            SignerAttestationPacket(evidence=evidence, quote="0x01020304"),
            issued,
        )

        self.assertTrue(parsed.verified)
        self.assertEqual(requests[0], {
            "schema": "dnai.attestation-qvl-challenge-request.v2",
            "chain_id": 84_532,
            "domain": "main_runtime_cvm",
            "profile": "diligence",
            "cvm_id": CVM_ID,
            "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
            "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
            "ceremony_nonce": CEREMONY_NONCE,
            "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        })
        self.assertEqual(requests[1]["quote"], "0x01020304")
        self.assertEqual(requests[1]["challenge"], challenge.to_public_dict())
        self.assertEqual(requests[1]["expectation"]["quote_hash"], evidence.quote_hash)
        self.assertEqual(
            requests[1]["expectation"]["quote_report_data"],
            evidence.report_data + challenge.challenge_digest[2:],
        )
        self.assertFalse(requests[1]["expectation"]["raw_secret_egress"])

    def test_plain_http_and_malformed_verdict_fail_closed(self):
        with self.assertRaisesRegex(DealRuntimeError, "endpoint is invalid"):
            HttpsIndependentQvlClient("http://qvl.example/verify")

        client = HttpsIndependentQvlClient(
            "https://qvl.example/verify",
            auth_token="diligence-qvl-test-token-" + "x" * 32,
            client=httpx.Client(
                transport=httpx.MockTransport(
                    lambda _request: httpx.Response(200, json={"verified": True})
                )
            ),
            chain_id=84_532,
            cvm_id=CVM_ID,
            deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            ceremony_nonce=CEREMONY_NONCE,
            measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
        )
        verifier = Account.create("malformed-qvl")
        challenge = _signed_qvl_challenge(verifier)
        packet = SignerAttestationPacket(
            evidence=SimpleNamespace(
                report_data="0x" + "11" * 32,
                to_public_dict=lambda: {},
            ),
            quote="0x01",
        )
        with self.assertRaises(AttestationVerdictUnavailable):
            client.verify(packet, challenge)


class DealRuntimeCliTest(unittest.TestCase):
    def test_cli_has_no_private_key_or_raw_key_option(self):
        options = {
            option
            for action in build_parser()._actions
            for option in action.option_strings
        }
        self.assertNotIn("--private-key", options)
        self.assertNotIn("--key", options)
        self.assertNotIn("--qvl-auth-token-env", options)
        self.assertIn("--qvl-url", options)


if __name__ == "__main__":
    unittest.main()
