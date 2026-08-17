import os
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
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
from tinker_delegate.compute_runtime import (
    ComputeIntentNotFound,
    ComputeRuntimeStateError,
    canonical_compute_job_id,
    canonical_compute_project_id,
)
from tinker_delegate.compute_workload_ingress import (
    ComputeWorkloadDispatchClaim,
    ComputeWorkloadIngressConflict,
    ComputeWorkloadIngressError,
    ComputeWorkloadIngressUnavailable,
)
from tinker_delegate.config import Settings
from tinker_delegate.crypto import _derive_aes_key


PRIVATE_KEY = "0x" + "71" * 32
OTHER_PRIVATE_KEY = "0x" + "72" * 32
WALLET_KEY = "dispatch-wallet-test-key-" + "w" * 48
CREDENTIAL_KEY = "dispatch-credential-test-key-" + "c" * 48
STORE_KEY = "dispatch-legacy-store-test-key-" + "s" * 48
DISPATCH_KEY = "dispatch-exact-asset-journal-key-" + "j" * 48


class ComputeDispatchApiTest(unittest.TestCase):
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
            compute_store_path=str(Path(self.temporary.name) / "legacy.json"),
            compute_dispatch_store_integrity_key=DISPATCH_KEY,
            compute_dispatch_store_path=str(
                Path(self.temporary.name) / "exact-asset-dispatch.json"
            ),
            compute_workload_wallet_adoption_enabled=True,
        )
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_dispatch_journal_instance = None
        api._compute_dispatch_journal_instance_identity = None
        self.client = TestClient(api.app)
        self.account = Account.from_key(PRIVATE_KEY)

    def tearDown(self):
        api._compute_wallet_challenges.clear()
        api._compute_store_instance = None
        api._compute_store_instance_identity = None
        api._compute_dispatch_journal_instance = None
        api._compute_dispatch_journal_instance_identity = None
        api.settings = self.original_settings
        self.env.stop()
        self.temporary.cleanup()

    def _headers(self, private_key=PRIVATE_KEY):
        account = Account.from_key(private_key)
        challenge = self.client.post(
            "/auth/compute/challenge", json={"address": account.address}
        )
        self.assertEqual(challenge.status_code, 200, challenge.text)
        payload = challenge.json()
        signature = account.sign_message(
            encode_defunct(text=payload["message"])
        ).signature.hex()
        token = self.client.post(
            "/auth/compute/token",
            json={"nonce": payload["nonce"], "signature": signature},
        )
        self.assertEqual(token.status_code, 200, token.text)
        return {"Authorization": f"Bearer {token.json()['access_token']}"}

    def _project(self, headers):
        created = self.client.post(
            "/compute/projects",
            json={"name": "exact-asset-lab"},
            headers={**headers, "Idempotency-Key": "project-dispatch-0001"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        return created.json()["project"]["project_id"]

    @staticmethod
    def _decrypt_credential_capsule(body, private_key):
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

    def _credential(self, project_id, headers):
        private = X25519PrivateKey.generate()
        device = self.client.post(
            f"/compute/projects/{project_id}/devices",
            json={
                "label": "dispatch-device",
                "kind": "autonomous_agent",
                "public_key": private.public_key().public_bytes_raw().hex(),
            },
            headers=headers,
        )
        self.assertEqual(device.status_code, 200, device.text)
        issued = self.client.post(
            f"/compute/projects/{project_id}/credentials",
            json={
                "device_id": device.json()["device"]["device_id"],
                "name": "dispatch-device",
                "scopes": ["workloads:create", "jobs:read"],
                "expires_in_seconds": 3600,
                "daily_credit_cap": 100,
            },
            headers=headers,
        )
        self.assertEqual(issued.status_code, 200, issued.text)
        return self._decrypt_credential_capsule(issued.json(), private)

    def _payload(self):
        return {
            "job_reference": "wallet-job-0001",
            "workload_id": "wrk_" + "ab" * 16,
            "asset": "0x" + "00" * 20,
            "authorization_nonce": 0,
            "max_asset_debit": 10**15,
            "authorization_expiry": int(time.time()) + 600,
            "rate_policy_commitment": "0x" + "31" * 32,
            "compose_hash": "0x" + "32" * 32,
            "operation": "inference",
            "model": "qwen3_8b",
            "recipe": "qwen3_8b_bounded",
            "result_policy": "bounded_summary_receipt",
            "max_prefill_tokens": 1_000,
            "max_sample_tokens": 100,
            "max_train_tokens": 0,
        }

    def _enable_dispatch_for_test(self, project_id):
        from tinker_delegate.compute_workload_ingress import (
            ComputeWorkloadPrincipal,
        )

        capability = {
            "metadata_intent_creation": True,
            "provider_dispatch": True,
            "independent_metering": True,
            "settlement": True,
            "credential_workload_wallet_adoption": True,
            "wallet_adoption_authority": "project_owner_admin_developer",
            "wallet_source_transfer_supported": False,
            "device_spending_authority": False,
            "exact_asset_only": True,
            "mutation_route": "/compute/projects/{project_id}/dispatch-intents",
            "status_route_template": (
                "/compute/projects/{project_id}/dispatch-intents/{job_reference}"
            ),
            "status_recovery_by_job_reference": True,
            "automatic_provider_redispatch": False,
            "provider": {
                "schema": "dnai.compute.provider-capability.v1",
                "source_present": True,
                "release_configured": True,
                "provider_dispatch": True,
                "provider_release_sha256": (
                    "sha256:"
                    "4264a2226ac9c850d8f053c98ac90d0f"
                    "6dcbc58702919899384a9b2442b35631"
                ),
                "idempotent_provider_replay_claimed": False,
                "automatic_provider_redispatch": False,
                "allowed_operations": ["inference", "training"],
                "allowed_result_policies": ["bounded_summary_receipt"],
                "adapter_contract": {
                    "at_most_once_attempt_checkpoint": True,
                    "terminal_ambiguity_hold": True,
                    "ambiguous_outcome_ciphertext_retained": True,
                },
                "runtime_guarantees": {
                    "at_most_once_attempt_checkpoint": True,
                    "terminal_ambiguity_hold": True,
                    "ambiguous_outcome_ciphertext_retained": True,
                },
                "runtime": {
                    "authenticated": True,
                    "fresh": True,
                    "process_presence_only": True,
                    "tdx_evidence": False,
                },
            },
            "reason": "unit_test_release_bound_dispatch_available",
        }
        patcher = patch.object(
            api,
            "_compute_dispatch_capability",
            return_value=capability,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        manifest = SimpleNamespace(
            schema="dnai.compute.workload.inference.v1",
            operation="inference",
            model="qwen3_8b",
            recipe="qwen3_8b_bounded",
            max_prefill_tokens=1_000,
            max_sample_tokens=100,
            max_train_tokens=0,
        )
        activation = SimpleNamespace(
            commitment="sha256:" + "41" * 32,
            recipient_release_commitment="sha256:" + "45" * 32,
        )
        workload_principal = ComputeWorkloadPrincipal(
            kind="wallet",
            project_id=project_id,
            actor_id=self.account.address,
        )
        binding = SimpleNamespace(
            actor_kind=workload_principal.kind,
            actor_commitment=workload_principal.actor_commitment,
            recipient_key_id="sha256:" + "42" * 32,
            activation_commitment=activation.commitment,
            recipient_release_commitment=(
                activation.recipient_release_commitment
            ),
            manifest=manifest,
            manifest_commitment="sha256:" + "43" * 32,
            workload_commitment="sha256:" + "44" * 32,
        )
        stored = SimpleNamespace(
            workload_id="wrk_" + "ab" * 16,
            binding=binding,
            execution_binding_commitment="sha256:" + "46" * 32,
        )
        self.compute_workload_binding = binding
        self.compute_stored_workload = stored
        self.workload_principal = workload_principal
        self.dispatch_claim = None
        self.dispatch_claim_calls = []
        self.dispatch_claim_failures = []
        self.cancellation_release_calls = []

        def get_for_project(_workload_id, *, project_commitment):
            if (
                _workload_id != stored.workload_id
                or project_commitment != workload_principal.project_commitment
            ):
                raise ComputeWorkloadIngressError(
                    "Compute workload was not found"
                )
            return stored

        def claim_for_dispatch(workload_id, **kwargs):
            self.dispatch_claim_calls.append((workload_id, kwargs))
            if self.dispatch_claim_failures:
                raise self.dispatch_claim_failures.pop(0)
            claim = ComputeWorkloadDispatchClaim(
                job_id=kwargs["job_id"],
                intent_commitment=kwargs["intent_commitment"],
                funding_wallet=kwargs["funding_wallet"],
                execution_binding_commitment=kwargs[
                    "execution_binding_commitment"
                ],
            )
            if self.dispatch_claim is not None:
                if self.dispatch_claim != claim:
                    raise ComputeWorkloadIngressConflict(
                        "Compute workload is claimed by a different dispatch"
                    )
                return claim, False
            self.dispatch_claim = claim
            return claim, True

        def release_after_cancellation_checkpoint(
            workload_id,
            *,
            project_id,
            claim,
            cancellation_checkpoint_commitment,
        ):
            if claim != self.dispatch_claim:
                raise ComputeWorkloadIngressConflict(
                    "Compute workload is claimed by a different dispatch"
                )
            self.cancellation_release_calls.append(
                (
                    workload_id,
                    project_id,
                    claim.funding_wallet,
                    cancellation_checkpoint_commitment,
                )
            )
            return len(self.cancellation_release_calls) == 1

        ingress = SimpleNamespace(
            recipient=SimpleNamespace(key_id=binding.recipient_key_id),
            current_activation=lambda: activation,
            store=SimpleNamespace(get_for_project=get_for_project),
            claim_for_dispatch=claim_for_dispatch,
            release_after_cancellation_checkpoint=(
                release_after_cancellation_checkpoint
            ),
        )
        ingress_patcher = patch.object(
            api,
            "_get_compute_workload_ingress",
            return_value=ingress,
        )
        ingress_patcher.start()
        self.addCleanup(ingress_patcher.stop)

    def test_metadata_intent_uses_canonical_ids_without_legacy_charge(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        projected = self.client.get(
            f"/compute/projects/{project}", headers=headers
        )
        self.assertEqual(projected.status_code, 200, projected.text)
        self.assertTrue(projected.json()["provider_dispatch_enabled"])
        self.assertTrue(
            self.client.get("/compute/funding-capabilities")
            .json()["dispatch_intents"]["metadata_intent_creation"]
        )
        balance_before = self.client.get(
            f"/compute/projects/{project}/balance", headers=headers
        ).json()
        ledger_before = self.client.get(
            f"/compute/projects/{project}/ledger", headers=headers
        ).json()
        request_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-create-0001",
        }
        created = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(created.status_code, 200, created.text)
        body = created.json()
        self.assertEqual(body["schema_version"], 3)
        self.assertTrue(body["created"])
        self.assertTrue(body["workload_claim_created"])
        self.assertTrue(body["workload_claim_confirmed"])
        self.assertFalse(body["workload_claim_recovered"])
        self.assertFalse(body["legacy_credit_ledger_mutated"])
        self.assertFalse(body["provider_authoritative"])
        intent = body["intent"]
        self.assertEqual(intent["project_id"], canonical_compute_project_id(project))
        self.assertEqual(
            intent["job_id"], canonical_compute_job_id("wallet-job-0001")
        )
        self.assertFalse(intent["raw_prompt_accepted"])
        self.assertFalse(intent["raw_examples_accepted"])
        self.assertEqual(intent["workload_id"], "wrk_" + "ab" * 16)
        self.assertEqual(intent["manifest_commitment"], "0x" + "43" * 32)
        self.assertEqual(intent["workload_commitment"], "0x" + "44" * 32)
        self.assertEqual(intent["workload_authority"]["source_kind"], "wallet")
        self.assertEqual(
            intent["workload_authority"]["execution_binding_commitment"],
            "sha256:" + "46" * 32,
        )
        self.assertFalse(
            intent["workload_authority"]["device_spending_authority"]
        )
        self.assertEqual(intent["authorization"]["kind"], "standalone")
        self.assertTrue(intent["authorization"]["server_derived"])
        self.assertRegex(
            intent["authorization"]["context_commitment"],
            r"^sha256:(?!0{64}$)[0-9a-f]{64}$",
        )
        self.assertTrue(intent["workload_claim_confirmed"])
        self.assertEqual(
            body["workload_claim_commitment"],
            intent["workload_claim_commitment"],
        )

        replay = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertFalse(replay.json()["created"])
        self.assertTrue(replay.json()["idempotent_replay"])

        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 200, fetched.text)
        self.assertEqual(fetched.json()["job_id"], intent["job_id"])

        balance_after = self.client.get(
            f"/compute/projects/{project}/balance", headers=headers
        ).json()
        ledger_after = self.client.get(
            f"/compute/projects/{project}/ledger", headers=headers
        ).json()
        self.assertEqual(balance_after, balance_before)
        self.assertEqual(ledger_after, ledger_before)

    def test_standalone_route_rejects_caller_supplied_collaboration_authority(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        payload = self._payload()
        payload.update(
            {
                "authorization_kind": "collaboration_one_shot",
                "authorization_context_commitment": "sha256:" + "aa" * 32,
            }
        )

        rejected = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=payload,
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-forged-collaboration-0001",
            },
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertIsNone(self.dispatch_claim)
        with self.assertRaises(ComputeIntentNotFound):
            api._get_compute_dispatch_journal().get(
                canonical_compute_job_id("wallet-job-0001")
            )

    def test_dispatch_rejects_wallet_sourced_workload_from_another_wallet(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "wallet"
        self.compute_workload_binding.actor_commitment = "sha256:" + "fe" * 32

        rejected = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-foreign-workload-0001",
            },
        )
        self.assertEqual(rejected.status_code, 404, rejected.text)
        self.assertEqual(rejected.json()["detail"], "Compute workload was not found")
        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 404, fetched.text)

    def test_project_member_wallet_adopts_credential_workload_without_device_spend(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        self.compute_workload_binding.actor_commitment = "sha256:" + "fe" * 32

        adopted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-device-adopt-0001",
            },
        )
        self.assertEqual(adopted.status_code, 200, adopted.text)
        body = adopted.json()
        self.assertTrue(body["workload_claim_confirmed"])
        authority = body["intent"]["workload_authority"]
        self.assertEqual(authority["source_kind"], "credential")
        self.assertEqual(authority["funding_authority"], "onchain_wallet_job")
        self.assertFalse(authority["device_spending_authority"])
        self.assertEqual(self.dispatch_claim.funding_wallet, self.account.address.lower())
        call = self.dispatch_claim_calls[0][1]
        self.assertEqual(call["source_kind"], "credential")
        self.assertEqual(call["funding_wallet"], self.account.address.lower())

    def test_retry_recovers_crash_after_pending_enqueue_before_workload_claim(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        self.dispatch_claim_failures.append(
            ComputeWorkloadIngressUnavailable("test-only claim interruption")
        )
        request_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-crash-before-claim-0001",
        }

        interrupted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)
        journal = api._get_compute_dispatch_journal()
        self.assertEqual(
            journal.get(canonical_compute_job_id("wallet-job-0001"))["stage"],
            "workload_claim_pending",
        )
        self.assertIsNone(journal.next_actionable())

        recovered = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)
        body = recovered.json()
        self.assertFalse(body["created"])
        self.assertTrue(body["idempotent_replay"])
        self.assertTrue(body["workload_claim_created"])
        self.assertTrue(body["workload_claim_confirmed"])
        self.assertTrue(body["workload_claim_recovered"])
        self.assertEqual(body["intent"]["stage"], "intent_created")

    def test_retry_recovers_crash_after_workload_claim_before_journal_confirm(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        journal = api._get_compute_dispatch_journal()
        request_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-crash-after-claim-0001",
        }
        with patch.object(
            journal,
            "confirm_workload_claim",
            side_effect=ComputeRuntimeStateError("test-only journal interruption"),
        ):
            interrupted = self.client.post(
                f"/compute/projects/{project}/dispatch-intents",
                json=self._payload(),
                headers=request_headers,
            )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)
        self.assertIsNotNone(self.dispatch_claim)
        self.assertEqual(
            journal.get(canonical_compute_job_id("wallet-job-0001"))["stage"],
            "workload_claim_pending",
        )

        recovered = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)
        body = recovered.json()
        self.assertFalse(body["created"])
        self.assertFalse(body["workload_claim_created"])
        self.assertTrue(body["workload_claim_confirmed"])
        self.assertTrue(body["workload_claim_recovered"])

    def test_pending_retry_rejects_execution_binding_substitution(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.dispatch_claim_failures.append(
            ComputeWorkloadIngressUnavailable("test-only claim interruption")
        )
        request_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-binding-substitution-0001",
        }
        interrupted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)
        self.compute_stored_workload.execution_binding_commitment = (
            "sha256:" + "ef" * 32
        )
        substituted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers=request_headers,
        )
        self.assertEqual(substituted.status_code, 409, substituted.text)
        self.assertIn("different intent", substituted.json()["detail"])

    def test_adoption_rejects_outsider_viewer_device_spender_and_other_project(self):
        owner_headers = self._headers()
        outsider_headers = self._headers(OTHER_PRIVATE_KEY)
        outsider = Account.from_key(OTHER_PRIVATE_KEY)
        project = self._project(owner_headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        route = f"/compute/projects/{project}/dispatch-intents"

        outsider_response = self.client.post(
            route,
            json=self._payload(),
            headers={
                **outsider_headers,
                "Idempotency-Key": "exact-dispatch-outsider-0001",
            },
        )
        self.assertEqual(outsider_response.status_code, 403, outsider_response.text)

        member = self.client.post(
            f"/compute/projects/{project}/members",
            json={"address": outsider.address, "role": "viewer"},
            headers=owner_headers,
        )
        self.assertEqual(member.status_code, 200, member.text)
        viewer_response = self.client.post(
            route,
            json=self._payload(),
            headers={
                **outsider_headers,
                "Idempotency-Key": "exact-dispatch-viewer-0001",
            },
        )
        self.assertEqual(viewer_response.status_code, 403, viewer_response.text)

        credential_token = self._credential(project, owner_headers)
        credential_response = self.client.post(
            route,
            json=self._payload(),
            headers={
                "Authorization": f"Bearer {credential_token}",
                "Idempotency-Key": "exact-dispatch-device-spend-0001",
            },
        )
        self.assertEqual(
            credential_response.status_code,
            401,
            credential_response.text,
        )

        second = self.client.post(
            "/compute/projects",
            json={"name": "other-adoption-project"},
            headers={
                **owner_headers,
                "Idempotency-Key": "project-dispatch-0002",
            },
        )
        self.assertEqual(second.status_code, 200, second.text)
        second_project = second.json()["project"]["project_id"]
        substituted_project = self.client.post(
            f"/compute/projects/{second_project}/dispatch-intents",
            json=self._payload(),
            headers={
                **owner_headers,
                "Idempotency-Key": "exact-dispatch-other-project-0001",
            },
        )
        self.assertEqual(
            substituted_project.status_code,
            404,
            substituted_project.text,
        )
        self.assertIsNone(self.dispatch_claim)

    def test_status_route_recovers_pending_workload_claim(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        self.dispatch_claim_failures.append(
            ComputeWorkloadIngressUnavailable("test-only claim interruption")
        )
        interrupted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-status-recovery-0001",
            },
        )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)

        recovered = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(recovered.status_code, 200, recovered.text)
        self.assertEqual(recovered.json()["stage"], "intent_created")
        self.assertTrue(recovered.json()["workload_claim_confirmed"])
        self.assertIsNotNone(self.dispatch_claim)

    def test_cancel_route_recovers_pending_claim_before_checkpoint_release(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        self.dispatch_claim_failures.append(
            ComputeWorkloadIngressUnavailable("test-only claim interruption")
        )
        interrupted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-cancel-recovery-0001",
            },
        )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)

        canceled = self.client.post(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/cancel"
            ),
            json={"reason": "user_requested_before_provider_start"},
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-cancel-recovered-0001",
            },
        )
        self.assertEqual(canceled.status_code, 200, canceled.text)
        receipt = canceled.json()
        self.assertEqual(receipt["schema_version"], 2)
        self.assertTrue(receipt["workload_claim_confirmed"])
        self.assertEqual(
            receipt["workload_authority"]["source_kind"],
            "credential",
        )
        self.assertTrue(receipt["workload_ciphertext_released"])

    def test_usage_receipt_route_recovers_pending_claim_before_not_ready(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        self.compute_workload_binding.actor_kind = "credential"
        self.dispatch_claim_failures.append(
            ComputeWorkloadIngressUnavailable("test-only claim interruption")
        )
        interrupted = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-result-recovery-0001",
            },
        )
        self.assertEqual(interrupted.status_code, 503, interrupted.text)

        result = self.client.get(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/usage-receipt"
            ),
            headers=headers,
        )
        self.assertEqual(result.status_code, 409, result.text)
        journal = api._get_compute_dispatch_journal()
        self.assertEqual(
            journal.get(canonical_compute_job_id("wallet-job-0001"))["stage"],
            "intent_created",
        )
        self.assertIsNotNone(self.dispatch_claim)

    def test_dispatch_rejects_result_policy_absent_from_provider_release(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        payload = self._payload()
        payload["result_policy"] = "score_band_hash"

        rejected = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=payload,
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-unsupported-policy-0001",
            },
        )
        self.assertEqual(rejected.status_code, 400, rejected.text)
        self.assertEqual(
            rejected.json()["detail"],
            "operation or result policy is not supported by the provider release",
        )
        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 404, fetched.text)

    def test_creation_gate_rejects_optimistic_top_level_flags(self):
        self.assertFalse(
            api._compute_dispatch_creation_enabled(
                {
                    "metadata_intent_creation": True,
                    "provider_dispatch": True,
                    "independent_metering": True,
                    "settlement": True,
                    "exact_asset_only": True,
                    "mutation_route": (
                        "/compute/projects/{project_id}/dispatch-intents"
                    ),
                    "status_route_template": (
                        "/compute/projects/{project_id}/dispatch-intents/"
                        "{job_reference}"
                    ),
                    "status_recovery_by_job_reference": True,
                    "automatic_provider_redispatch": False,
                }
            )
        )

    def test_wallet_cancellation_stops_journal_and_erases_ciphertext_idempotently(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        created = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-create-0001",
            },
        )
        self.assertEqual(created.status_code, 200, created.text)

        cancel_headers = {
            **headers,
            "Idempotency-Key": "exact-dispatch-cancel-0001",
        }
        canceled = self.client.post(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/cancel"
            ),
            json={"reason": "user_requested_before_provider_start"},
            headers=cancel_headers,
        )
        self.assertEqual(canceled.status_code, 200, canceled.text)
        receipt = canceled.json()
        self.assertTrue(receipt["changed"])
        self.assertFalse(receipt["idempotent_replay"])
        self.assertTrue(receipt["journal_execution_prevented"])
        self.assertTrue(receipt["workload_ciphertext_released"])
        self.assertFalse(receipt["provider_dispatch_performed"])
        self.assertFalse(receipt["provider_dispatch_may_have_occurred"])
        self.assertFalse(receipt["vault_authorization_released"])
        self.assertTrue(receipt["onchain_cancel_required"])
        self.assertFalse(receipt["exact_asset_capacity_released"])
        self.assertEqual(len(self.cancellation_release_calls), 1)
        self.assertEqual(
            self.cancellation_release_calls[0][0],
            self._payload()["workload_id"],
        )

        replay = self.client.post(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/cancel"
            ),
            json={"reason": "user_requested_before_provider_start"},
            headers=cancel_headers,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertFalse(replay.json()["changed"])
        self.assertTrue(replay.json()["idempotent_replay"])
        self.assertEqual(
            replay.json()["cancellation_checkpoint_commitment"],
            receipt["cancellation_checkpoint_commitment"],
        )
        self.assertEqual(len(self.cancellation_release_calls), 2)

        status_response = self.client.get(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001"
            ),
            headers=headers,
        )
        self.assertEqual(status_response.status_code, 200, status_response.text)
        status_body = status_response.json()
        self.assertEqual(status_body["stage"], "blocked")
        self.assertEqual(
            status_body["provider_dispatch_status"],
            "not_started",
        )
        self.assertFalse(
            status_body["provider_dispatch_may_have_occurred"]
        )

        different_key = self.client.post(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/cancel"
            ),
            json={"reason": "user_requested_before_provider_start"},
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-cancel-0002",
            },
        )
        self.assertEqual(different_key.status_code, 409, different_key.text)

    def test_cancellation_request_is_fixed_and_never_reflects_private_fields(self):
        headers = self._headers()
        project = self._project(headers)
        secret = "PRIVATE-CANCEL-NOTE-MUST-NOT-EGRESS"
        rejected = self.client.post(
            (
                f"/compute/projects/{project}/dispatch-intents/"
                "wallet-job-0001/cancel"
            ),
            json={
                "reason": "user_requested_before_provider_start",
                "note": secret,
            },
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-cancel-0001",
            },
        )
        self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertNotIn(secret, rejected.text)

    def test_usage_receipt_requires_auth_membership_and_settlement(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        created = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-create-0001",
            },
        )
        self.assertEqual(created.status_code, 200, created.text)
        route = (
            f"/compute/projects/{project}/dispatch-intents/"
            "wallet-job-0001/usage-receipt"
        )
        unauthorized = self.client.get(route)
        self.assertEqual(unauthorized.status_code, 401, unauthorized.text)
        pending = self.client.get(route, headers=headers)
        self.assertEqual(pending.status_code, 409, pending.text)
        self.assertEqual(
            pending.json()["detail"],
            "Settled exact-asset usage receipt is not available",
        )
        self.assertEqual(pending.headers["cache-control"], "no-store")

    def test_prompt_and_examples_are_rejected_without_reflecting_values(self):
        headers = self._headers()
        project = self._project(headers)
        for forbidden_field, secret in (
            ("prompt", "SECRET PRIVATE PROMPT VALUE"),
            ("examples", "SECRET PRIVATE EXAMPLES VALUE"),
        ):
            payload = self._payload()
            payload[forbidden_field] = secret
            response = self.client.post(
                f"/compute/projects/{project}/dispatch-intents",
                json=payload,
                headers={
                    **headers,
                    "Idempotency-Key": f"forbidden-{forbidden_field}-0001",
                },
            )
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn(secret, response.text)

    def test_browser_decimal_uint256_strings_are_canonicalized_without_precision_loss(self):
        headers = self._headers()
        project = self._project(headers)
        self._enable_dispatch_for_test(project)
        payload = self._payload()
        payload.update(
            {
                "job_reference": "wallet-job-large-uint",
                "authorization_nonce": "9007199254740993",
                "max_asset_debit": "1000000000000000000",
            }
        )
        response = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=payload,
            headers={
                **headers,
                "Idempotency-Key": "exact-dispatch-large-uint-0001",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        intent = response.json()["intent"]
        self.assertEqual(intent["authorization_nonce"], 9_007_199_254_740_993)
        self.assertEqual(intent["max_asset_debit"], 1_000_000_000_000_000_000)

    def test_disabled_release_gate_returns_503_without_journal_mutation(self):
        headers = self._headers()
        project = self._project(headers)
        projected = self.client.get(
            f"/compute/projects/{project}", headers=headers
        )
        self.assertEqual(projected.status_code, 200, projected.text)
        self.assertFalse(projected.json()["provider_dispatch_enabled"])
        listed = self.client.get("/compute/projects", headers=headers)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertFalse(listed.json()["projects"][0]["provider_dispatch_enabled"])

        response = self.client.post(
            f"/compute/projects/{project}/dispatch-intents",
            json=self._payload(),
            headers={
                **headers,
                "Idempotency-Key": "disabled-dispatch-create-0001",
            },
        )
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(
            response.json()["detail"],
            "Exact-asset dispatch intent creation is disabled by this release",
        )

        fetched = self.client.get(
            f"/compute/projects/{project}/dispatch-intents/wallet-job-0001",
            headers=headers,
        )
        self.assertEqual(fetched.status_code, 404, fetched.text)

    def test_funding_capabilities_use_release_bound_exact_asset_language(self):
        response = self.client.get("/compute/funding-capabilities")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(
            body["eth"]["reason"],
            "release_generated_base_sepolia_vault_evidence_required",
        )
        self.assertEqual(
            body["exact_asset_vault"]["review_status"],
            "reviewed_and_extensively_tested_not_formally_audited",
        )
        self.assertFalse(
            body["exact_asset_vault"]["provider_dispatch_authoritative"]
        )
        dispatch = body["dispatch_intents"]
        self.assertFalse(dispatch["metadata_intent_creation"])
        self.assertFalse(dispatch["provider_dispatch"])
        self.assertFalse(dispatch["independent_metering"])
        self.assertFalse(dispatch["settlement"])
        self.assertTrue(dispatch["exact_asset_only"])
        self.assertIsNone(dispatch["mutation_route"])
        self.assertEqual(
            dispatch["status_route_template"],
            "/compute/projects/{project_id}/dispatch-intents/{job_reference}",
        )
        self.assertTrue(dispatch["status_recovery_by_job_reference"])
        self.assertFalse(dispatch["automatic_provider_redispatch"])
        self.assertFalse(dispatch["credential_workload_wallet_adoption"])
        self.assertEqual(
            dispatch["wallet_adoption_authority"],
            "project_owner_admin_developer",
        )
        self.assertFalse(dispatch["wallet_source_transfer_supported"])
        self.assertFalse(dispatch["device_spending_authority"])
        self.assertEqual(dispatch["reason"], "provider_execution_not_enabled")
        provider = dispatch["provider"]
        self.assertTrue(provider["source_present"])
        self.assertFalse(provider["release_configured"])
        self.assertFalse(provider["provider_dispatch"])
        self.assertTrue(
            provider["adapter_contract"]["at_most_once_attempt_checkpoint"]
        )
        self.assertFalse(
            provider["runtime_guarantees"]["at_most_once_attempt_checkpoint"]
        )
        self.assertFalse(provider["idempotent_provider_replay_claimed"])
        self.assertFalse(provider["automatic_provider_redispatch"])
        self.assertTrue(body["credits"]["distinct_from_exact_asset_vault"])
        self.assertNotIn("audited_deposit_vault_not_deployed", response.text)


if __name__ == "__main__":
    unittest.main()
