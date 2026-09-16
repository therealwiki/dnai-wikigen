import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tinker_delegate import api
from tinker_delegate.compute_auth import COMPUTE_CREDENTIAL_HKDF_INFO
from tinker_delegate.config import Settings
from tinker_delegate.crypto import _derive_aes_key
from tinker_delegate.execution_policy_store import (
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
    execution_policy_trust_context,
)
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tests.execution_policy_anchor_fakes import (
    MemoryExecutionPolicyAnchorGateway,
)
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult


PRIVATE_KEY = "0x" + "11" * 32
OTHER_PRIVATE_KEY = "0x" + "22" * 32
POLICY_APPROVER_PRIVATE_KEY = "0x" + "33" * 32
DEAL_KEY = "deal-wallet-test-key-" + "d" * 48
WALLET_KEY = "compute-wallet-test-key-" + "w" * 48
CREDENTIAL_KEY = "compute-credential-test-key-" + "c" * 48
STORE_KEY = "compute-store-test-key-" + "s" * 48
RUNTIME_TOKEN = "runtime-test-token"


class ComputeApiTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.original_settings = api.settings
        self.original_anchor_override = (
            api._execution_policy_anchor_coordinator_override
        )
        self.policy_approver = Account.from_key(POLICY_APPROVER_PRIVATE_KEY)
        policy_approver_root = execution_policy_approver_root_hash(
            [execution_policy_approver_hash(self.policy_approver.address)]
        )
        api.settings = Settings(
            wallet_auth_signing_key=DEAL_KEY,
            compute_wallet_auth_signing_key=WALLET_KEY,
            compute_credential_signing_key=CREDENTIAL_KEY,
            compute_store_integrity_key=STORE_KEY,
            compute_store_path=str(Path(self.temporary.name) / "compute.json"),
            execution_policy_store_path=str(
                Path(self.temporary.name) / "execution-policy.json"
            ),
            execution_policy_store_integrity_key=(
                "compute-policy-integrity-key-for-tests-0001"
            ),
            execution_policy_approved_signers=self.policy_approver.address,
            execution_policy_approver_root_hash=policy_approver_root,
            execution_policy_approval_domain=(
                "base-sepolia:84532:"
                + "1" * 64
                + ":0x"
                + "2" * 64
                + ":"
                + "3" * 64
                + ":"
                + policy_approver_root
            ),
            runtime_auth_required=True,
            runtime_auth_token=RUNTIME_TOKEN,
        )
        api._compute_wallet_challenges.clear()
        api._wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._execution_policy_store_instance = None
        api._execution_policy_store_instance_identity = None
        api._execution_policy_anchor_coordinator_override = (
            AnchoredExecutionPolicyCoordinator(
                api._get_execution_policy_store(),
                MemoryExecutionPolicyAnchorGateway(),
            )
        )
        self.client = TestClient(api.app)
        self.account = Account.from_key(PRIVATE_KEY)

    def tearDown(self):
        api._compute_wallet_challenges.clear()
        api._wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._execution_policy_store_instance = None
        api._execution_policy_store_instance_identity = None
        api._execution_policy_anchor_coordinator_override = (
            self.original_anchor_override
        )
        api.settings = self.original_settings
        self.temporary.cleanup()

    def _compute_token(self, private_key: str = PRIVATE_KEY) -> str:
        account = Account.from_key(private_key)
        challenge = self.client.post(
            "/auth/compute/challenge", json={"address": account.address}
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        body = challenge.json()
        signature = Account.sign_message(
            encode_defunct(text=body["message"]), private_key=private_key
        ).signature.hex()
        exchanged = self.client.post(
            "/auth/compute/token",
            json={"nonce": body["nonce"], "signature": signature},
        )
        self.assertEqual(exchanged.status_code, 200, exchanged.text)
        return exchanged.json()["access_token"]

    def _wallet_headers(
        self, private_key: str = PRIVATE_KEY
    ) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._compute_token(private_key)}"}

    def _project(self, headers: dict[str, str]) -> str:
        response = self.client.post(
            "/compute/projects",
            json={"name": "atlas-research"},
            headers={**headers, "Idempotency-Key": "project-create-1234"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["project"]["project_id"]

    def _grant(self, project_id: str, amount: int = 1000):
        response = self.client.post(
            f"/compute/internal/projects/{project_id}/grants",
            json={
                "amount_credits": amount,
                "reason": "operator_testnet_grant",
            },
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "operator-grant-1234",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)

    def _pass_execution_policy(self, surface: str, resource_id: str):
        payload = {
            "surface": surface,
            "resource_id": resource_id,
            "expires_at": int(time.time()) + 300,
            "request": {
                "request_id": f"policy-{resource_id}",
                "requester_ref": "runtime://compute-dispatcher",
                "purpose": "run-compute-job",
                "pipeline": "tinker-proxy",
                "data_classes": ["bounded-job-metadata"],
                "output_schema": "bounded_summary_receipt",
                "operations": ["dispatch"],
            },
            "policy": {
                "policy_id": "compute-dispatch-policy",
                "version": "policy-kernel/v1",
                "corpus_ref": "corpus://compute-job-metadata",
                "allowed_purposes": ["run-compute-job"],
                "denied_purposes": [],
                "allowed_pipelines": ["tinker-proxy"],
                "allowed_output_schemas": ["bounded_summary_receipt"],
                "allowed_operations": ["dispatch"],
                "known_data_classes": ["bounded-job-metadata"],
                "restricted_categories": [],
                "hold_categories": [],
                "ambiguous_categories": [],
                "hold_routes": {},
            },
        }
        headers = {"Authorization": f"Bearer {RUNTIME_TOKEN}"}
        approval = self.client.post(
            "/policy/approval-message", json=payload, headers=headers
        )
        self.assertEqual(approval.status_code, 200, approval.text)
        payload["previous_decision_hash"] = approval.json()[
            "previous_decision_hash"
        ]
        payload["approver_address"] = self.policy_approver.address
        payload["approval_signature"] = Account.sign_message(
            encode_defunct(text=approval.json()["approval_message"]),
            private_key=POLICY_APPROVER_PRIVATE_KEY,
        ).signature.hex()
        response = self.client.post(
            "/policy/evaluate",
            json=payload,
            headers={"Authorization": f"Bearer {RUNTIME_TOKEN}"},
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["decision"], "pass")

    @staticmethod
    def _decrypt_capsule(body: dict, private_key: X25519PrivateKey) -> str:
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

    def _credential(self, project_id: str, headers: dict[str, str]):
        private_key = X25519PrivateKey.generate()
        device = self.client.post(
            f"/compute/projects/{project_id}/devices",
            json={
                "label": "local-codex",
                "kind": "developer_device",
                "public_key": private_key.public_key().public_bytes_raw().hex(),
            },
            headers=headers,
        )
        self.assertEqual(device.status_code, 200, device.text)
        device_id = device.json()["device"]["device_id"]
        issued = self.client.post(
            f"/compute/projects/{project_id}/credentials",
            json={
                "device_id": device_id,
                "name": "my-agent",
                "scopes": ["jobs:create", "jobs:read"],
                "expires_in_seconds": 3600,
                "daily_credit_cap": 500,
            },
            headers=headers,
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        return issued.json(), self._decrypt_capsule(issued.json(), private_key), private_key

    def test_funding_surface_has_no_compute_payment_mutation_or_card_schema(self):
        response = self.client.get("/compute/funding-capabilities")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["card"]["enabled"])
        self.assertFalse(body["card"]["card_data_accepted"])
        self.assertFalse(body["eth"]["enabled"])
        self.assertFalse(body["usdc"]["enabled"])
        compute_paths = {
            (method, route.path)
            for route in api.app.routes
            if route.path.startswith("/compute")
            for method in (route.methods or set())
        }
        self.assertNotIn(("POST", "/compute/funding"), compute_paths)
        self.assertFalse(any("card" in path for _method, path in compute_paths))

    def test_wallet_project_credit_job_and_ledger_flow(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "bounded-sample",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 100,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={**headers, "Idempotency-Key": "job-create-123456"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        job = created.json()["job"]
        self.assertEqual(job["dispatch_status"], "not_dispatched")
        self.assertFalse(created.json()["provider_dispatch_performed"])
        balance = self.client.get(
            f"/compute/projects/{project_id}/balance", headers=headers
        ).json()
        self.assertEqual(balance["available_credits"], 900)
        self.assertEqual(balance["reserved_credits"], 100)
        settled = self.client.post(
            f"/compute/internal/projects/{project_id}/jobs/{job['job_id']}/settle",
            json={
                "actual_credits": 16,
                "usage_receipt_hash": "sha256:" + "1" * 64,
                "metering_source": "operator_bounded_receipt",
            },
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "job-settle-12345",
            },
        )
        self.assertEqual(settled.status_code, 200, settled.text)
        self.assertFalse(settled.json()["provider_authoritative_settlement"])
        ledger = self.client.get(
            f"/compute/projects/{project_id}/ledger", headers=headers
        ).json()
        self.assertEqual(ledger["balance"]["available_credits"], 984)
        self.assertEqual(ledger["balance"]["reserved_credits"], 0)
        self.assertTrue(all(sum(p["delta"] for p in tx["postings"]) == 0 for tx in ledger["transactions"]))

    def test_wallet_cancel_is_exact_idempotent_and_atomically_releases_credits(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "cancel-before-dispatch",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 125,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={**headers, "Idempotency-Key": "cancel-job-create-1234"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        job_id = created.json()["job"]["job_id"]
        cancel_headers = {
            **headers,
            "Idempotency-Key": "wallet-cancel-job-1234",
        }
        canceled = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={"reason": "user_requested_before_dispatch"},
            headers=cancel_headers,
        )
        self.assertEqual(canceled.status_code, 200, canceled.text)
        body = canceled.json()
        self.assertEqual(
            set(body),
            {
                "surface",
                "schema_version",
                "project_id",
                "job_id",
                "status",
                "changed",
                "idempotent_replay",
                "released_credits",
                "credit_reversal",
                "ledger",
                "provider_dispatch_performed",
                "service_settlement_performed",
            },
        )
        self.assertEqual(
            set(body["ledger"]),
            {
                "transaction_id",
                "sequence",
                "kind",
                "transaction_hash",
                "previous_hash",
                "settlement_status",
            },
        )
        self.assertEqual(body["surface"], "compute_job_cancellation")
        self.assertEqual(body["schema_version"], 1)
        self.assertEqual(body["status"], "canceled")
        self.assertTrue(body["changed"])
        self.assertFalse(body["idempotent_replay"])
        self.assertEqual(body["released_credits"], 125)
        self.assertEqual(body["credit_reversal"], "reserved_to_available")
        self.assertEqual(body["ledger"]["kind"], "job_cancel")
        self.assertEqual(
            body["ledger"]["settlement_status"],
            "user_canceled_before_dispatch",
        )
        self.assertFalse(body["provider_dispatch_performed"])
        self.assertFalse(body["service_settlement_performed"])

        replay = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={"reason": "user_requested_before_dispatch"},
            headers=cancel_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        replay_body = replay.json()
        self.assertFalse(replay_body["changed"])
        self.assertTrue(replay_body["idempotent_replay"])
        self.assertEqual(
            replay_body["ledger"]["transaction_hash"],
            body["ledger"]["transaction_hash"],
        )
        self.assertEqual(
            replay_body["ledger"]["transaction_id"],
            body["ledger"]["transaction_id"],
        )

        balance = self.client.get(
            f"/compute/projects/{project_id}/balance", headers=headers
        ).json()
        self.assertEqual(balance["available_credits"], 1000)
        self.assertEqual(balance["reserved_credits"], 0)
        ledger = self.client.get(
            f"/compute/projects/{project_id}/ledger", headers=headers
        ).json()
        cancellation_records = [
            transaction
            for transaction in ledger["transactions"]
            if transaction["kind"] == "job_cancel"
        ]
        self.assertEqual(len(cancellation_records), 1)
        self.assertEqual(
            sum(posting["delta"] for posting in cancellation_records[0]["postings"]),
            0,
        )

        second_key = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={"reason": "user_requested_before_dispatch"},
            headers={**headers, "Idempotency-Key": "second-cancel-job-1234"},
        )
        self.assertEqual(second_key.status_code, 409, second_key.text)
        self.assertNotIn("wallet", canceled.text.lower())

    def test_cancel_requires_current_mutating_wallet_role_not_device_credential(self):
        owner_headers = self._wallet_headers()
        other_headers = self._wallet_headers(OTHER_PRIVATE_KEY)
        other_account = Account.from_key(OTHER_PRIVATE_KEY)
        project_id = self._project(owner_headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "role-guarded-cancel",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 50,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={**owner_headers, "Idempotency-Key": "role-job-create-1234"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        job_id = created.json()["job"]["job_id"]
        route = f"/compute/projects/{project_id}/jobs/{job_id}/cancel"
        request = {"reason": "user_requested_before_dispatch"}

        outsider = self.client.post(
            route,
            json=request,
            headers={**other_headers, "Idempotency-Key": "outsider-cancel-1234"},
        )
        self.assertEqual(outsider.status_code, 403, outsider.text)
        add_viewer = self.client.post(
            f"/compute/projects/{project_id}/members",
            json={"address": other_account.address, "role": "viewer"},
            headers=owner_headers,
        )
        self.assertEqual(add_viewer.status_code, 200, add_viewer.text)
        viewer = self.client.post(
            route,
            json=request,
            headers={**other_headers, "Idempotency-Key": "viewer-cancel-api-1234"},
        )
        self.assertEqual(viewer.status_code, 403, viewer.text)
        add_developer = self.client.post(
            f"/compute/projects/{project_id}/members",
            json={"address": other_account.address, "role": "developer"},
            headers=owner_headers,
        )
        self.assertEqual(add_developer.status_code, 200, add_developer.text)

        issued, credential_token, _private_key = self._credential(
            project_id, owner_headers
        )
        self.assertIn("credential", issued)
        credential_denied = self.client.post(
            route,
            json=request,
            headers={
                "Authorization": f"Bearer {credential_token}",
                "Idempotency-Key": "credential-cancel-1234",
            },
        )
        self.assertEqual(credential_denied.status_code, 401, credential_denied.text)

        developer = self.client.post(
            route,
            json=request,
            headers={**other_headers, "Idempotency-Key": "developer-cancel-api-1234"},
        )
        self.assertEqual(developer.status_code, 200, developer.text)
        self.assertEqual(developer.json()["status"], "canceled")

    def test_cancel_rejects_running_and_settled_jobs_without_releasing_twice(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "running-job",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 100,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={**headers, "Idempotency-Key": "running-job-create-1234"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        job_id = created.json()["job"]["job_id"]
        start_route = (
            f"/compute/internal/projects/{project_id}/jobs/{job_id}/start"
        )
        missing_policy = self.client.post(
            start_route,
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "running-job-start-no-policy-1234",
            },
        )
        self.assertEqual(missing_policy.status_code, 403, missing_policy.text)
        self._pass_execution_policy("compute_dispatch", job_id)
        started = self.client.post(
            start_route,
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "running-job-start-1234",
            },
        )
        self.assertEqual(started.status_code, 200, started.text)
        running_cancel = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={"reason": "user_requested_before_dispatch"},
            headers={**headers, "Idempotency-Key": "running-job-cancel-1234"},
        )
        self.assertEqual(running_cancel.status_code, 409, running_cancel.text)
        balance = self.client.get(
            f"/compute/projects/{project_id}/balance", headers=headers
        ).json()
        self.assertEqual(balance["available_credits"], 900)
        self.assertEqual(balance["reserved_credits"], 100)

        settled = self.client.post(
            f"/compute/internal/projects/{project_id}/jobs/{job_id}/settle",
            json={
                "actual_credits": 25,
                "usage_receipt_hash": "sha256:" + "2" * 64,
                "metering_source": "operator_bounded_receipt",
            },
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "running-job-settle-1234",
            },
        )
        self.assertEqual(settled.status_code, 200, settled.text)
        settled_cancel = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={"reason": "user_requested_before_dispatch"},
            headers={**headers, "Idempotency-Key": "settled-job-cancel-1234"},
        )
        self.assertEqual(settled_cancel.status_code, 409, settled_cancel.text)

        final_balance = self.client.get(
            f"/compute/projects/{project_id}/balance", headers=headers
        ).json()
        self.assertEqual(final_balance["available_credits"], 975)
        self.assertEqual(final_balance["reserved_credits"], 0)

        extra_input = self.client.post(
            f"/compute/projects/{project_id}/jobs/{job_id}/cancel",
            json={
                "reason": "user_requested_before_dispatch",
                "prompt": "must-not-reflect",
            },
            headers={**headers, "Idempotency-Key": "invalid-cancel-body-1234"},
        )
        self.assertEqual(extra_input.status_code, 422, extra_input.text)
        self.assertNotIn("must-not-reflect", extra_input.text)

    def test_hold_cannot_persist_between_pass_and_compute_start_mutation(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "policy-lease-race",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 100,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={**headers, "Idempotency-Key": "policy-lease-job-create"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        job_id = created.json()["job"]["job_id"]
        self._pass_execution_policy("compute_dispatch", job_id)

        coordinator = api._execution_policy_anchor_coordinator_override
        previous = coordinator.latest_decision_hash(
            surface="compute_dispatch",
            resource_id=job_id,
            now=int(time.time()),
        )
        compute_store = api._get_compute_store()
        original_start = compute_store.start_job
        mutation_entered = threading.Event()
        release_mutation = threading.Event()
        revocation_started = threading.Event()
        revocation_finished = threading.Event()
        responses: dict[str, object] = {}
        errors: list[Exception] = []

        def blocking_start(*args, **kwargs):
            mutation_entered.set()
            if not release_mutation.wait(5):
                raise AssertionError("test compute mutation release timed out")
            return original_start(*args, **kwargs)

        def start_request():
            responses["start"] = self.client.post(
                f"/compute/internal/projects/{project_id}/jobs/{job_id}/start",
                headers={
                    "Authorization": f"Bearer {RUNTIME_TOKEN}",
                    "Idempotency-Key": "policy-lease-job-start",
                },
            )

        def revoke():
            revocation_started.set()
            now = int(time.time())
            try:
                coordinator.append_and_anchor(
                    surface="compute_dispatch",
                    resource_id=job_id,
                    result=PolicyGateResult(
                        decision=PolicyDecision.HOLD,
                        corpus_ref="corpus://compute-job-metadata",
                        stage=4,
                        reason_code="human_review_required",
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

        with patch.object(compute_store, "start_job", side_effect=blocking_start):
            start_thread = threading.Thread(target=start_request)
            start_thread.start()
            self.assertTrue(mutation_entered.wait(2))
            revocation_thread = threading.Thread(target=revoke)
            revocation_thread.start()
            self.assertTrue(revocation_started.wait(1))
            self.assertFalse(revocation_finished.wait(0.2))
            self.assertEqual(
                coordinator.store.latest(
                    surface="compute_dispatch", resource_id=job_id
                )["decision"],
                "pass",
            )
            release_mutation.set()
            start_thread.join(timeout=5)
            revocation_thread.join(timeout=5)

        self.assertFalse(start_thread.is_alive())
        self.assertFalse(revocation_thread.is_alive())
        self.assertFalse(errors)
        self.assertEqual(responses["start"].status_code, 200)
        self.assertEqual(
            coordinator.store.latest(
                surface="compute_dispatch", resource_id=job_id
            )["decision"],
            "hold",
        )

    def test_service_credit_start_rejects_pass_for_different_immutable_job_context(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        created = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "context-bound-job",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 100,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
            },
            headers={
                **headers,
                "Idempotency-Key": "context-bound-job-create-0001",
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        job_id = created.json()["job"]["job_id"]
        authoritative_context = (
            api._get_compute_store().execution_policy_context_hash(job_id)
        )
        wrong_context = (
            "f" * 64 if authoritative_context != "f" * 64 else "e" * 64
        )
        domain_hash, approver_hashes, approver_root = (
            execution_policy_trust_context(api.settings)
        )
        now = int(time.time())
        api._execution_policy_anchor_coordinator_override.append_and_anchor(
            surface="compute_dispatch",
            resource_id=job_id,
            result=PolicyGateResult(
                decision=PolicyDecision.PASS,
                corpus_ref="corpus://compute-job-metadata",
                stage=4,
                reason_code="policy_passed",
                request_hash="a" * 64,
                policy_hash="b" * 64,
                execution_context_hash=wrong_context,
            ),
            recorded_at=now,
            expires_at=now + 300,
            expected_previous_decision_hash="0" * 64,
            approver_hash=next(iter(approver_hashes)),
            approval_hash="c" * 64,
            approval_domain_hash=domain_hash,
            approver_root_hash=approver_root,
            now=now,
        )

        start = self.client.post(
            f"/compute/internal/projects/{project_id}/jobs/{job_id}/start",
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "context-bound-job-start-0001",
            },
        )
        self.assertEqual(start.status_code, 403, start.text)
        observed = self.client.get(
            f"/compute/projects/{project_id}/jobs/{job_id}",
            headers=headers,
        )
        self.assertEqual(observed.status_code, 200, observed.text)
        self.assertEqual(observed.json()["status"], "queued")

    def test_service_credit_start_maps_unknown_context_resource_to_bounded_error(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        response = self.client.post(
            f"/compute/internal/projects/{project_id}/jobs/job_unknown/start",
            headers={
                "Authorization": f"Bearer {RUNTIME_TOKEN}",
                "Idempotency-Key": "unknown-context-job-start-0001",
            },
        )
        self.assertEqual(response.status_code, 400, response.text)
        self.assertEqual(response.json()["detail"], "job not found")

    def test_cancel_openapi_request_and_response_schemas_are_closed(self):
        document = api.app.openapi()
        operation = document["paths"][
            "/compute/projects/{project_id}/jobs/{job_id}/cancel"
        ]["post"]
        request_ref = operation["requestBody"]["content"]["application/json"][
            "schema"
        ]["$ref"]
        response_ref = operation["responses"]["200"]["content"][
            "application/json"
        ]["schema"]["$ref"]
        request_schema = document["components"]["schemas"][
            request_ref.rsplit("/", 1)[-1]
        ]
        response_schema = document["components"]["schemas"][
            response_ref.rsplit("/", 1)[-1]
        ]
        self.assertFalse(request_schema["additionalProperties"])
        self.assertEqual(set(request_schema["properties"]), {"reason"})
        self.assertEqual(request_schema["required"], ["reason"])
        self.assertFalse(response_schema["additionalProperties"])
        self.assertEqual(
            set(response_schema["properties"]),
            {
                "surface",
                "schema_version",
                "project_id",
                "job_id",
                "status",
                "changed",
                "idempotent_replay",
                "released_credits",
                "credit_reversal",
                "ledger",
                "provider_dispatch_performed",
                "service_settlement_performed",
            },
        )

    def test_device_credential_is_encrypted_rotatable_and_revocable(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        self._grant(project_id)
        issued, token, private_key = self._credential(project_id, headers)
        self.assertNotIn("access_token", issued)
        self.assertFalse(issued["plaintext_token_returned"])
        credential_id = issued["credential"]["credential_id"]
        read = self.client.get(
            f"/compute/projects/{project_id}/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(read.status_code, 200, read.text)
        rotated = self.client.post(
            f"/compute/projects/{project_id}/credentials/{credential_id}/rotate",
            json={"expires_in_seconds": 3600},
            headers=headers,
        )
        self.assertEqual(rotated.status_code, 200, rotated.text)
        new_token = self._decrypt_capsule(rotated.json(), private_key)
        old_read = self.client.get(
            f"/compute/projects/{project_id}/jobs",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(old_read.status_code, 403)
        new_read = self.client.get(
            f"/compute/projects/{project_id}/jobs",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        self.assertEqual(new_read.status_code, 200, new_read.text)
        revoked = self.client.post(
            f"/compute/projects/{project_id}/credentials/{credential_id}/revoke",
            headers=headers,
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        after_revoke = self.client.get(
            f"/compute/projects/{project_id}/jobs",
            headers={"Authorization": f"Bearer {new_token}"},
        )
        self.assertEqual(after_revoke.status_code, 403)

    def test_auth_domains_runtime_and_input_boundaries_are_separate(self):
        headers = self._wallet_headers()
        project_id = self._project(headers)
        denied = self.client.post(
            f"/compute/internal/projects/{project_id}/grants",
            json={"amount_credits": 10, "reason": "operator_testnet_grant"},
            headers={**headers, "Idempotency-Key": "grant-denied-1234"},
        )
        self.assertEqual(denied.status_code, 403)

        deal_challenge = self.client.post(
            "/auth/wallet/challenge",
            json={"address": self.account.address, "deal_id": "7"},
        ).json()
        signature = Account.sign_message(
            encode_defunct(text=deal_challenge["message"]), private_key=PRIVATE_KEY
        ).signature.hex()
        deal_token = self.client.post(
            "/auth/wallet/token",
            json={"nonce": deal_challenge["nonce"], "signature": signature},
        ).json()["access_token"]
        cross_domain = self.client.get(
            "/compute/projects",
            headers={"Authorization": f"Bearer {deal_token}"},
        )
        self.assertEqual(cross_domain.status_code, 401)

        card_like = self.client.post(
            f"/compute/projects/{project_id}/jobs",
            json={
                "name": "bad-input",
                "operation": "inference",
                "model": "qwen3_8b",
                "recipe": "qwen3_8b_bounded",
                "max_credits": 10,
                "result_policy": "bounded_summary_receipt",
                "environment_version": "env_v1",
                "card_number": "4242424242424242",
            },
            headers={**headers, "Idempotency-Key": "bad-input-123456"},
        )
        self.assertEqual(card_like.status_code, 422)
        self.assertNotIn("4242424242424242", card_like.text)


if __name__ == "__main__":
    unittest.main()
