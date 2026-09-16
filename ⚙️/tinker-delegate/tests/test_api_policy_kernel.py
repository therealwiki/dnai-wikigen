"""HTTP boundary tests for deterministic policy enforcement."""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.config import Settings
from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    compute_execution_policy_context_hash,
)
from tinker_delegate.execution_policy_store import (
    ZERO_DECISION_HASH,
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
)
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tests.execution_policy_anchor_fakes import (
    MemoryExecutionPolicyAnchorGateway,
)
from tinker_delegate.policy_kernel import (
    MAX_POLICY_KERNEL_PAYLOAD_BYTES,
    POLICY_CANONICALIZATION_VERSION,
    PolicyDecision,
    PolicyGateResult,
)


TOKEN = "policy-operator-test-token"
APPROVER_PRIVATE_KEY = "0x" + "33" * 32
OTHER_PRIVATE_KEY = "0x" + "44" * 32
EVALUATE_IDEMPOTENCY_DOMAIN = (
    b"dnai-wikigen/execution-policy-evaluate-idempotency/v1\0"
)


def _approval_domain(approver_root_hash: str, *, release: str = "1") -> str:
    return (
        "base-sepolia:84532:"
        + release * 64
        + ":0x"
        + "2" * 64
        + ":"
        + "3" * 64
        + ":"
        + approver_root_hash
    )


def _evaluate_idempotency_key(approval_message_hash: str) -> str:
    return "sha256:" + hashlib.sha256(
        EVALUATE_IDEMPOTENCY_DOMAIN
        + bytes.fromhex(approval_message_hash)
    ).hexdigest()


def _request(**overrides):
    payload = {
        "request_id": "request-1",
        "requester_ref": "agent://sponsor",
        "purpose": "rank-candidates",
        "pipeline": "sft-rerank",
        "data_classes": ["assay-summary"],
        "output_schema": "score-band-v1",
        "operations": ["score"],
    }
    payload.update(overrides)
    return payload


def _policy(**overrides):
    payload = {
        "policy_id": "policy-atlas",
        "version": "policy-kernel/v1",
        "corpus_ref": "corpus://private-atlas",
        "allowed_purposes": ["rank-candidates"],
        "denied_purposes": ["publish-raw-records"],
        "allowed_pipelines": ["sft-rerank"],
        "allowed_output_schemas": ["score-band-v1"],
        "allowed_operations": ["score"],
        "known_data_classes": ["assay-summary", "clinical-summary"],
        "restricted_categories": [],
        "hold_categories": ["clinical-summary"],
        "ambiguous_categories": [],
        "hold_routes": {"clinical-summary": "expert-in-the-loop"},
    }
    payload.update(overrides)
    return payload


class PolicyKernelApiTest(unittest.TestCase):
    def setUp(self):
        self.original_settings = api.settings
        self.original_store = api._execution_policy_store_instance
        self.original_store_identity = api._execution_policy_store_instance_identity
        self.original_anchor_override = (
            api._execution_policy_anchor_coordinator_override
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.approver = Account.from_key(APPROVER_PRIVATE_KEY)
        self.approver_hash = execution_policy_approver_hash(
            self.approver.address
        )
        self.approver_root_hash = execution_policy_approver_root_hash(
            [self.approver_hash]
        )
        self.approval_domain = _approval_domain(self.approver_root_hash)
        api.settings = Settings(
            runtime_auth_required=True,
            runtime_auth_token=TOKEN,
            execution_policy_store_path=str(
                Path(self.tempdir.name) / "execution-policy.json"
            ),
            execution_policy_store_integrity_key=(
                "policy-integrity-key-for-tests-only-0001"
            ),
            execution_policy_approved_signers=self.approver.address,
            execution_policy_approver_root_hash=self.approver_root_hash,
            execution_policy_approval_domain=self.approval_domain,
        )
        api._execution_policy_store_instance = None
        api._execution_policy_store_instance_identity = None
        self.anchor_gateway = MemoryExecutionPolicyAnchorGateway()
        api._execution_policy_anchor_coordinator_override = (
            AnchoredExecutionPolicyCoordinator(
                api._get_execution_policy_store(),
                self.anchor_gateway,
            )
        )
        self.client = TestClient(api.app)

    def tearDown(self):
        api.settings = self.original_settings
        api._execution_policy_store_instance = self.original_store
        api._execution_policy_store_instance_identity = self.original_store_identity
        api._execution_policy_anchor_coordinator_override = (
            self.original_anchor_override
        )
        self.tempdir.cleanup()

    def _post(
        self,
        request=None,
        policy=None,
        *,
        token=TOKEN,
        surface="deal_evaluation",
        resource_id="deal-7",
        expires_at=None,
        sign=True,
        signing_key=APPROVER_PRIVATE_KEY,
        approver_address=None,
    ):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        payload = {
            "surface": surface,
            "resource_id": resource_id,
            "expires_at": expires_at or int(time.time()) + 300,
            "request": request if request is not None else _request(),
            "policy": policy if policy is not None else _policy(),
        }
        if sign and token == TOKEN:
            approval = self.client.post(
                "/policy/approval-message", headers=headers, json=payload
            )
            self.assertEqual(approval.status_code, 200, approval.text)
            payload["previous_decision_hash"] = approval.json()[
                "previous_decision_hash"
            ]
            if approval.json()["decision"] == "pass":
                signer = Account.from_key(signing_key)
                payload["approver_address"] = (
                    approver_address or signer.address
                )
                payload["approval_signature"] = Account.sign_message(
                    encode_defunct(text=approval.json()["approval_message"]),
                    private_key=signing_key,
                ).signature.hex()
        else:
            payload["previous_decision_hash"] = ZERO_DECISION_HASH
        return self.client.post("/policy/evaluate", headers=headers, json=payload)

    def _status(self, *, resource_id="deal-7", token=TOKEN):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post(
            "/policy/status",
            headers=headers,
            json={
                "surface": "deal_evaluation",
                "resource_id": resource_id,
            },
        )

    def _idempotent_evaluate_payload(
        self,
        *,
        resource_id: str,
        expires_at: int | None = None,
        signing_key: str = APPROVER_PRIVATE_KEY,
    ) -> tuple[dict[str, str], dict[str, object], dict[str, object]]:
        headers = {"Authorization": f"Bearer {TOKEN}"}
        payload: dict[str, object] = {
            "surface": "deal_evaluation",
            "resource_id": resource_id,
            "expires_at": expires_at or int(time.time()) + 300,
            "request": _request(),
            "policy": _policy(),
        }
        approval = self.client.post(
            "/policy/approval-message",
            headers=headers,
            json=payload,
        )
        self.assertEqual(approval.status_code, 200, approval.text)
        approval_body = approval.json()
        signer = Account.from_key(signing_key)
        payload.update(
            {
                "previous_decision_hash": approval_body[
                    "previous_decision_hash"
                ],
                "approver_address": signer.address,
                "approval_signature": Account.sign_message(
                    encode_defunct(text=approval_body["approval_message"]),
                    private_key=signing_key,
                ).signature.hex(),
                "idempotency_key": _evaluate_idempotency_key(
                    approval_body["approval_message_hash"]
                ),
            }
        )
        return headers, payload, approval_body

    def test_policy_endpoint_requires_runtime_auth(self):
        missing = self._post(token="")
        wrong = self._post(token="wrong-token")
        status_missing = self._status(token="")

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(wrong.status_code, 403)
        self.assertEqual(status_missing.status_code, 401)

    def test_review_queue_anchor_surface_is_not_exposed_by_generic_policy_api(self):
        response = self.client.post(
            "/policy/evaluate",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json={
                "surface": "review_queue_state",
                "resource_id": "review-authority-context",
                "expires_at": int(time.time()) + 300,
                "request": _request(),
                "policy": _policy(),
                "previous_decision_hash": ZERO_DECISION_HASH,
            },
        )
        self.assertEqual(response.status_code, 422)

    def test_compute_context_is_server_derived_and_cannot_be_caller_supplied(self):
        intent = ComputeDispatchIntent.create(
            project_reference="project_context",
            job_reference="job_context",
            user=self.approver.address,
            asset="0x" + "00" * 20,
            authorization_nonce=1,
            max_asset_debit=25,
            authorization_expiry=1_900_000_000,
            rate_policy_commitment="0x" + "11" * 32,
            compose_hash="0x" + "22" * 32,
            operation="inference",
            model="qwen3_8b",
            recipe="qwen3_8b_bounded",
            result_policy="bounded_summary_receipt",
            max_prefill_tokens=1024,
            max_sample_tokens=128,
            max_train_tokens=0,
            workload_id="wrk_" + "ab" * 16,
            workload_schema="dnai.compute.workload.inference.v1",
            manifest_commitment="0x" + "91" * 32,
            workload_commitment="0x" + "92" * 32,
            workload_source_kind="wallet",
            workload_execution_binding_commitment="sha256:" + "94" * 32,
            workload_recipient_release_commitment="sha256:" + "95" * 32,
        )

        class AuthoritativeJournal:
            def get(self, job_id):
                self.requested = job_id
                return {"intent": intent.to_dict()}

        journal = AuthoritativeJournal()
        with patch.object(
            api,
            "_get_compute_dispatch_journal",
            return_value=journal,
        ):
            bound = api._bind_execution_policy_context(
                "compute_dispatch",
                intent.job_id,
                PolicyGateResult(
                    decision=PolicyDecision.PASS,
                    corpus_ref="corpus://compute",
                    stage=4,
                    reason_code="policy_passed",
                    request_hash="a" * 64,
                    policy_hash="b" * 64,
                    execution_context_hash="f" * 64,
                ),
            )
        self.assertEqual(journal.requested, intent.job_id)
        self.assertEqual(
            bound.execution_context_hash,
            compute_execution_policy_context_hash(intent),
        )
        self.assertNotEqual(bound.execution_context_hash, "f" * 64)

        request = {
            "surface": "compute_dispatch",
            "resource_id": intent.job_id,
            "expires_at": int(time.time()) + 300,
            "request": _request(),
            "policy": _policy(),
            "execution_context_hash": "f" * 64,
        }
        rejected = self.client.post(
            "/policy/approval-message",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=request,
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)

    def test_runtime_bearer_alone_cannot_create_a_pass(self):
        response = self._post(sign=False)

        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Execution policy decision could not be persisted",
        )
        status_response = self._status()
        self.assertFalse(status_response.json()["found"])

    def test_unapproved_or_mismatched_signer_cannot_create_a_pass(self):
        unapproved = self._post(signing_key=OTHER_PRIVATE_KEY)
        mismatched = self._post(
            signing_key=OTHER_PRIVATE_KEY,
            approver_address=self.approver.address,
        )

        self.assertEqual(unapproved.status_code, 400, unapproved.text)
        self.assertEqual(mismatched.status_code, 400, mismatched.text)
        self.assertFalse(self._status().json()["found"])

    def test_approval_message_is_hash_only_and_auth_protected(self):
        payload = {
            "surface": "arena_execution",
            "resource_id": "private-submission-7",
            "expires_at": int(time.time()) + 300,
            "request": _request(),
            "policy": _policy(),
        }
        missing = self.client.post("/policy/approval-message", json=payload)
        response = self.client.post(
            "/policy/approval-message",
            headers={"Authorization": f"Bearer {TOKEN}"},
            json=payload,
        )

        self.assertEqual(missing.status_code, 401)
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["surface"], "execution_policy_approval_message")
        self.assertEqual(body["schema_version"], 3)
        self.assertEqual(body["execution_context_hash"], "0" * 64)
        self.assertEqual(
            body["canonicalization_version"],
            POLICY_CANONICALIZATION_VERSION,
        )
        self.assertEqual(body["decision"], "pass")
        self.assertEqual(len(body["approval_message_hash"]), 64)
        self.assertEqual(len(body["approval_domain_hash"]), 64)
        self.assertEqual(body["approver_root_hash"], self.approver_root_hash)
        self.assertFalse(body["raw_policy_egress"])
        self.assertFalse(body["raw_resource_id_egress"])
        rendered = json.dumps(body, sort_keys=True)
        for private in (
            "private-submission-7",
            "corpus://private-atlas",
            "rank-candidates",
            "assay-summary",
        ):
            self.assertNotIn(private, rendered)

    def test_approval_message_fails_closed_without_deployment_trust_roots(self):
        payload = {
            "surface": "compute_dispatch",
            "resource_id": "job-7",
            "expires_at": int(time.time()) + 300,
            "request": _request(),
            "policy": _policy(),
        }
        headers = {"Authorization": f"Bearer {TOKEN}"}
        api.settings = api.settings.model_copy(
            update={"execution_policy_approval_domain": ""}
        )
        missing_domain = self.client.post(
            "/policy/approval-message", headers=headers, json=payload
        )
        api.settings = api.settings.model_copy(
            update={
                "execution_policy_approval_domain": (
                    self.approval_domain
                ),
                "execution_policy_approved_signers": "",
            }
        )
        missing_signers = self.client.post(
            "/policy/approval-message", headers=headers, json=payload
        )

        self.assertEqual(missing_domain.status_code, 503)
        self.assertEqual(missing_signers.status_code, 503)
        self.assertEqual(
            missing_domain.json()["detail"],
            "Execution policy approval trust roots are unavailable",
        )

    def test_pass_response_is_exact_and_omits_raw_policy_inputs(self):
        response = self._post()

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["surface"], "policy_kernel")
        self.assertEqual(body["schema_version"], 3)
        self.assertEqual(body["execution_context_hash"], "0" * 64)
        self.assertEqual(
            body["canonicalization_version"],
            POLICY_CANONICALIZATION_VERSION,
        )
        self.assertEqual(
            body["approval_domain_hash"],
            body["execution_binding"]["approval_domain_hash"],
        )
        self.assertEqual(body["approver_root_hash"], self.approver_root_hash)
        self.assertEqual(
            body["execution_binding"]["canonicalization_version"],
            POLICY_CANONICALIZATION_VERSION,
        )
        self.assertEqual(
            body["execution_binding"]["approver_root_hash"],
            self.approver_root_hash,
        )
        self.assertEqual(body["decision"], "pass")
        self.assertEqual(body["reason_code"], "policy_passed")
        self.assertFalse(body["raw_secret_egress"])
        self.assertFalse(body["raw_policy_egress"])
        self.assertEqual(len(body["corpus_ref_hash"]), 64)
        self.assertEqual(body["execution_binding"]["decision"], "pass")
        self.assertEqual(
            body["execution_binding"]["execution_context_hash"],
            "0" * 64,
        )
        self.assertFalse(body["execution_binding"]["raw_resource_id_egress"])
        self.assertEqual(len(body["execution_binding"]["resource_id_hash"]), 64)
        self.assertEqual(
            body["execution_binding"]["rollback_anchor"]["status"],
            "rpc_reported_finalized_release_match",
        )
        self.assertEqual(
            body["execution_binding"]["rollback_anchor"]["verification_model"],
            "single_rpc_reported_finalized_with_confirmation_depth",
        )
        self.assertFalse(
            body["execution_binding"]["rollback_anchor"][
                "independent_rpc_quorum_verified"
            ]
        )
        self.assertFalse(
            body["execution_binding"]["rollback_anchor"][
                "consensus_proof_verified"
            ]
        )
        self.assertEqual(
            body["execution_binding"]["rollback_anchor"]["resource_sequence"],
            body["execution_binding"]["sequence"],
        )
        rendered = json.dumps(body, sort_keys=True)
        for private in (
            "corpus://private-atlas",
            "rank-candidates",
            "sft-rerank",
            "assay-summary",
            "agent://sponsor",
            "deal-7",
        ):
            self.assertNotIn(private, rendered)

        persisted = api._require_execution_policy_pass(
            "deal_evaluation", "deal-7"
        )
        self.assertEqual(persisted["decision"], "pass")

        status = self._status()
        self.assertEqual(status.status_code, 200, status.text)
        self.assertTrue(status.json()["found"])
        self.assertTrue(status.json()["current_pass"])
        self.assertEqual(status.json()["schema_version"], 3)
        self.assertEqual(
            status.json()["approval_domain_hash"],
            body["approval_domain_hash"],
        )
        self.assertEqual(
            status.json()["approver_root_hash"], self.approver_root_hash
        )
        self.assertEqual(
            status.json()["rollback_anchor"],
            status.json()["record"]["rollback_anchor"],
        )
        self.assertNotIn("deal-7", status.text)

    def test_exact_evaluate_retry_returns_original_result_without_second_append(self):
        headers, payload, _approval = self._idempotent_evaluate_payload(
            resource_id="deal-idempotent-replay"
        )

        first = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )
        replay = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )

        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json(), first.json())
        self.assertNotIn("idempotency_key", replay.json())
        self.assertEqual(
            api._get_execution_policy_store().latest(
                surface="deal_evaluation",
                resource_id="deal-idempotent-replay",
            )["sequence"],
            1,
        )
        self.assertEqual(len(self.anchor_gateway.records), 1)

    def test_evaluate_idempotency_key_rejects_changed_body_or_signature(self):
        other = Account.from_key(OTHER_PRIVATE_KEY)
        other_hash = execution_policy_approver_hash(other.address)
        root = execution_policy_approver_root_hash(
            [self.approver_hash, other_hash]
        )
        api.settings = api.settings.model_copy(
            update={
                "execution_policy_approved_signers": (
                    f"{self.approver.address},{other.address}"
                ),
                "execution_policy_approver_root_hash": root,
                "execution_policy_approval_domain": _approval_domain(root),
            }
        )
        headers, payload, approval = self._idempotent_evaluate_payload(
            resource_id="deal-idempotency-conflict"
        )
        first = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )
        self.assertEqual(first.status_code, 200, first.text)

        changed_body = {
            **payload,
            "request": _request(request_id="changed-request"),
        }
        body_conflict = self.client.post(
            "/policy/evaluate", headers=headers, json=changed_body
        )

        changed_signature = {
            **payload,
            "approver_address": other.address,
            "approval_signature": Account.sign_message(
                encode_defunct(text=approval["approval_message"]),
                private_key=OTHER_PRIVATE_KEY,
            ).signature.hex(),
        }
        signature_conflict = self.client.post(
            "/policy/evaluate", headers=headers, json=changed_signature
        )

        self.assertEqual(body_conflict.status_code, 409, body_conflict.text)
        self.assertEqual(
            body_conflict.json()["detail"],
            "Execution policy idempotency key conflicts with request",
        )
        self.assertEqual(
            signature_conflict.status_code,
            409,
            signature_conflict.text,
        )
        self.assertEqual(
            signature_conflict.json()["detail"],
            (
                "Execution policy idempotency key was already used "
                "for a different approval"
            ),
        )
        self.assertEqual(len(self.anchor_gateway.records), 1)

    def test_exact_retry_reconciles_pending_anchor_before_returning_success(self):
        headers, payload, _approval = self._idempotent_evaluate_payload(
            resource_id="deal-idempotent-anchor-recovery"
        )
        self.anchor_gateway.fail_next_anchor = True

        failed = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )
        recovered = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )

        self.assertEqual(failed.status_code, 503, failed.text)
        self.assertEqual(recovered.status_code, 200, recovered.text)
        self.assertEqual(
            recovered.json()["execution_binding"]["sequence"],
            1,
        )
        self.assertEqual(len(self.anchor_gateway.records), 1)

    def test_replay_still_requires_auth_and_an_unexpired_intent(self):
        expires_at = int(time.time()) + 300
        headers, payload, _approval = self._idempotent_evaluate_payload(
            resource_id="deal-idempotent-auth-expiry",
            expires_at=expires_at,
        )
        first = self.client.post(
            "/policy/evaluate", headers=headers, json=payload
        )
        self.assertEqual(first.status_code, 200, first.text)

        missing_auth = self.client.post("/policy/evaluate", json=payload)
        wrong_auth = self.client.post(
            "/policy/evaluate",
            headers={"Authorization": "Bearer wrong-token"},
            json=payload,
        )
        with patch("time.time", return_value=expires_at + 1):
            expired = self.client.post(
                "/policy/evaluate", headers=headers, json=payload
            )

        self.assertEqual(missing_auth.status_code, 401, missing_auth.text)
        self.assertEqual(wrong_auth.status_code, 403, wrong_auth.text)
        self.assertEqual(expired.status_code, 400, expired.text)
        self.assertEqual(
            expired.json()["detail"],
            "Execution policy decision intent is expired",
        )
        self.assertEqual(len(self.anchor_gateway.records), 1)

    def test_malformed_and_oversized_policy_inputs_return_bounded_deny(self):
        malformed_request = _request(raw_private_artifact="do-not-echo")
        malformed = self._post(request=malformed_request)
        oversized = self._post(
            request=_request(
                requester_ref="private-sentinel-" + "x" * MAX_POLICY_KERNEL_PAYLOAD_BYTES
            )
        )

        for response in (malformed, oversized):
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["decision"], "deny")
        self.assertEqual(malformed.json()["reason_code"], "unknown_request_field")
        self.assertEqual(
            oversized.json()["reason_code"], "malformed_policy_payload"
        )
        self.assertNotIn("do-not-echo", malformed.text)
        self.assertNotIn("private-sentinel", oversized.text)

    def test_hold_returns_only_bounded_route_and_hashes(self):
        response = self._post(
            request=_request(data_classes=["clinical-summary"])
        )

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["decision"], "hold")
        self.assertEqual(body["routed_role"], "expert-in-the-loop")
        self.assertNotIn("clinical-summary", response.text)

    def test_new_hold_supersedes_an_older_pass_for_same_resource(self):
        passed = self._post()
        held = self._post(request=_request(data_classes=["clinical-summary"]))

        self.assertEqual(passed.json()["decision"], "pass")
        self.assertEqual(held.json()["decision"], "hold")
        with self.assertRaises(Exception) as caught:
            api._require_execution_policy_pass("deal_evaluation", "deal-7")
        self.assertEqual(getattr(caught.exception, "status_code", None), 403)
        status = self._status()
        self.assertTrue(status.json()["found"])
        self.assertFalse(status.json()["current_pass"])
        self.assertEqual(status.json()["record"]["decision"], "hold")

    def test_deny_cannot_persist_during_authorized_deal_evaluation(self):
        passed = self._post()
        self.assertEqual(passed.status_code, 200, passed.text)
        self.assertEqual(passed.json()["decision"], "pass")

        coordinator = api._execution_policy_anchor_coordinator_override
        previous = coordinator.latest_decision_hash(
            surface="deal_evaluation",
            resource_id="deal-7",
            now=int(time.time()),
        )
        evaluation_entered = threading.Event()
        release_evaluation = threading.Event()
        revocation_started = threading.Event()
        revocation_finished = threading.Event()
        responses: dict[str, object] = {}
        errors: list[Exception] = []

        class BlockingControlPlane:
            async def evaluate(self, deal_id, evaluator):
                evaluation_entered.set()
                released = await asyncio.to_thread(
                    release_evaluation.wait, 5
                )
                if not released:
                    raise AssertionError("test deal evaluation release timed out")
                raise KeyError(deal_id)

        def evaluate_request():
            try:
                responses["evaluation"] = self.client.post(
                    "/deal/deal-7/evaluate",
                    headers={"Authorization": f"Bearer {TOKEN}"},
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def revoke():
            revocation_started.set()
            now = int(time.time())
            try:
                coordinator.append_and_anchor(
                    surface="deal_evaluation",
                    resource_id="deal-7",
                    result=PolicyGateResult(
                        decision=PolicyDecision.DENY,
                        corpus_ref="corpus://private-atlas",
                        stage=1,
                        reason_code="purpose_denied",
                        request_hash="a" * 64,
                        policy_hash="b" * 64,
                    ),
                    recorded_at=now,
                    expires_at=now + 300,
                    expected_previous_decision_hash=previous,
                    now=now,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                revocation_finished.set()

        with (
            patch(
                "tinker_delegate.evaluator.resolve_deal_evaluator",
                return_value=object(),
            ),
            patch.object(
                api,
                "_get_control_plane",
                return_value=BlockingControlPlane(),
            ),
        ):
            evaluation_thread = threading.Thread(target=evaluate_request)
            evaluation_thread.start()
            self.assertTrue(evaluation_entered.wait(2))
            revocation_thread = threading.Thread(target=revoke)
            revocation_thread.start()
            self.assertTrue(revocation_started.wait(1))
            self.assertFalse(revocation_finished.wait(0.2))
            self.assertEqual(
                coordinator.store.latest(
                    surface="deal_evaluation", resource_id="deal-7"
                )["decision"],
                "pass",
            )
            release_evaluation.set()
            evaluation_thread.join(timeout=5)
            revocation_thread.join(timeout=5)

        self.assertFalse(evaluation_thread.is_alive())
        self.assertFalse(revocation_thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual(responses["evaluation"].status_code, 404)
        self.assertEqual(
            coordinator.store.latest(
                surface="deal_evaluation", resource_id="deal-7"
            )["decision"],
            "deny",
        )

    def test_stale_hold_preview_cannot_supersede_a_newer_pass(self):
        resource_id = "deal-stale-preview"
        headers = {"Authorization": f"Bearer {TOKEN}"}
        stale_payload = {
            "surface": "deal_evaluation",
            "resource_id": resource_id,
            "expires_at": int(time.time()) + 300,
            "request": _request(data_classes=["clinical-summary"]),
            "policy": _policy(),
        }
        preview = self.client.post(
            "/policy/approval-message", headers=headers, json=stale_payload
        )
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertEqual(preview.json()["decision"], "hold")
        stale_payload["previous_decision_hash"] = preview.json()[
            "previous_decision_hash"
        ]

        passed = self._post(resource_id=resource_id)
        self.assertEqual(passed.status_code, 200, passed.text)
        self.assertEqual(passed.json()["decision"], "pass")

        stale = self.client.post(
            "/policy/evaluate", headers=headers, json=stale_payload
        )
        self.assertEqual(stale.status_code, 400, stale.text)
        status_response = self._status(resource_id=resource_id)
        self.assertTrue(status_response.json()["current_pass"])
        self.assertEqual(status_response.json()["record"]["decision"], "pass")

    def test_domain_rotation_or_signer_removal_revokes_current_pass(self):
        passed = self._post()
        self.assertEqual(passed.status_code, 200, passed.text)

        api.settings = api.settings.model_copy(
            update={
                "execution_policy_approval_domain": (
                    _approval_domain(self.approver_root_hash, release="9")
                )
            }
        )
        rotated = self._status()
        self.assertTrue(rotated.json()["found"])
        self.assertFalse(rotated.json()["current_pass"])
        with self.assertRaises(Exception) as domain_error:
            api._require_execution_policy_pass("deal_evaluation", "deal-7")
        self.assertEqual(
            getattr(domain_error.exception, "status_code", None), 403
        )

        api.settings = api.settings.model_copy(
            update={
                "execution_policy_approval_domain": (
                    self.approval_domain
                ),
                "execution_policy_approved_signers": self.approver.address,
            }
        )
        other = Account.from_key(OTHER_PRIVATE_KEY)
        other_root = execution_policy_approver_root_hash(
            [execution_policy_approver_hash(other.address)]
        )
        api.settings = api.settings.model_copy(
            update={
                "execution_policy_approval_domain": _approval_domain(
                    other_root, release="8"
                ),
                "execution_policy_approved_signers": other.address,
                "execution_policy_approver_root_hash": other_root,
            }
        )
        removed = self._status()
        self.assertTrue(removed.json()["found"])
        self.assertFalse(removed.json()["current_pass"])

    def test_missing_status_is_bounded_and_does_not_create_a_record(self):
        response = self._status(resource_id="private-missing-deal")

        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertFalse(body["found"])
        self.assertFalse(body["current_pass"])
        self.assertIsNone(body["record"])
        self.assertEqual(
            body["canonicalization_version"],
            POLICY_CANONICALIZATION_VERSION,
        )
        self.assertEqual(len(body["approval_domain_hash"]), 64)
        self.assertEqual(len(body["approver_root_hash"]), 64)
        self.assertEqual(len(body["resource_id_hash"]), 64)
        self.assertNotIn("private-missing-deal", response.text)

    def test_anchor_failure_after_persist_returns_503_and_reconciles_once(self):
        self.anchor_gateway.fail_next_anchor = True
        failed = self._post(resource_id="deal-anchor-crash")
        self.assertEqual(failed.status_code, 503, failed.text)
        self.assertEqual(
            failed.json()["detail"],
            "Execution policy rollback anchor is unavailable",
        )

        # The next preflight reconciles the one durable pending record. It does
        # not create a second record or require the approver to re-sign the
        # already persisted decision.
        status_response = self._status(resource_id="deal-anchor-crash")
        self.assertEqual(status_response.status_code, 200, status_response.text)
        self.assertTrue(status_response.json()["found"])
        self.assertTrue(status_response.json()["current_pass"])
        self.assertEqual(
            status_response.json()["record"]["sequence"], 1
        )
        self.assertEqual(len(self.anchor_gateway.records), 1)

    def test_anchor_head_mismatch_makes_status_globally_unavailable(self):
        passed = self._post(resource_id="deal-anchor-mismatch")
        self.assertEqual(passed.status_code, 200, passed.text)
        self.anchor_gateway.snapshot_overrides["global_head"] = (
            "0x" + "ff" * 32
        )
        response = self._status(resource_id="deal-anchor-mismatch")
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Execution policy rollback anchor is unavailable",
        )


if __name__ == "__main__":
    unittest.main()
