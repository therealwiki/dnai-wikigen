"""Real ciphertext/store integration; QVL/chain evidence remains test-only."""

import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate import compute_auth
from tinker_delegate.collaboration_execution import CollaborationExecutionAuthorityInvalidated, CollaborationExecutionAuthorityUnavailable, CollaborationExecutionIntent
from tinker_delegate.collaboration_execution_service import AuthenticatedComputeJournalReader, CollaborationExecutionServiceError, CollaborationExecutionServiceUnavailable, CollaborationExecutionWorkerService, royalty_release_binding_from_settings
from tinker_delegate.compute_dispatch_admission import ComputeDispatchAdmissionService, compute_dispatch_claim_for_intent
from tinker_delegate.compute_runtime import ComputeExecutionJournal, canonical_compute_project_id
from tinker_delegate.compute_store import ComputeStore, ComputeStoreCorruptError, ComputeStoreError, compute_project_resolver_from_settings
from tinker_delegate.compute_workload_ingress import ComputeWorkloadIngressError, ComputeWorkloadIngressUnavailable, ComputeWorkloadPrincipal
from tests.test_collaboration_execution_service import _coordinator, _finalized_receipt, _make_release, _royalty_reader, _settings, _stored_grants
from tests import test_compute_workload_ingress as ingress_test

FLOW_REJECTION = (CollaborationExecutionServiceError, CollaborationExecutionServiceUnavailable)


@pytest.fixture
def real_flow(tmp_path, monkeypatch):
    harness = ingress_test.ComputeWorkloadIngressTests(methodName="runTest")
    harness.setUp()
    try:
        coordinator, journal, accounts, snapshot, request, _release = _coordinator(tmp_path)
        wallet = snapshot["requester_address"]
        path = tmp_path / "compute-authority.json"
        key = b"p" * 32
        store = ComputeStore(path, integrity_key=key)
        project = store.create_project(owner_address=wallet, name="real-project", idempotency_key="real-project-create", created_at=ingress_test.NOW)[0]["project_id"]
        reader_settings = SimpleNamespace(compute_store_path=str(path))
        monkeypatch.setattr(compute_auth, "compute_store_integrity_key", lambda _settings: key)
        harness.service.project_resolver = compute_project_resolver_from_settings(reader_settings)
        harness.principal = ComputeWorkloadPrincipal(kind="wallet", project_id=project, actor_id=wallet)
        coordinator.workload_ingress = harness.service
        activation = harness.activation
        coordinator.settings = _settings(_make_release(
            main_runtime_cvm_id=activation.cvm_id,
            deployment_intent_sha256=activation.deployment_intent_sha256,
            release_authority_sha256=activation.release_authority_sha256,
            ceremony_nonce=activation.ceremony_nonce,
            compose_hash=activation.compose_hash,
        ))
        coordinator.settings.main_runtime_cvm_id = activation.cvm_id
        coordinator.settings.compute_vault_compose_hash = activation.compose_hash
        coordinator.settings.compute_vault_address = activation.recipient_attestation["compute_vault_address"]
        coordinator.settings.compute_vault_runtime_code_hash = activation.recipient_attestation["compute_vault_runtime_code_hash"]
        coordinator.settings.release_deployment_intent_sha256 = activation.deployment_intent_sha256
        coordinator.settings.release_authority_sha256 = activation.release_authority_sha256
        coordinator.settings.release_ceremony_nonce = activation.ceremony_nonce
        yield SimpleNamespace(harness=harness, coordinator=coordinator, journal=journal, accounts=accounts, snapshot=snapshot, request=request, wallet=wallet, store=store, project=project, path=path, key=key, tmp_path=tmp_path)
    finally:
        harness.tearDown()


def _upload(flow, *, kind="wallet", actor=None, key="collaboration-upload-1"):
    principal = ComputeWorkloadPrincipal(kind=kind, project_id=flow.project, actor_id=actor or (flow.wallet if kind == "wallet" else "cred_fixture"))
    manifest, _plain, commitment, envelope, result = flow.harness.ingest(principal=principal, idempotency_key=key)
    request = dict(flow.request)
    request.update(compute_project_id=canonical_compute_project_id(flow.project), compute_workload_id=result.workload_id, compute_workload_commitment="0x" + commitment.removeprefix("sha256:"), compute_manifest_commitment="0x" + manifest.commitment.removeprefix("sha256:"), compute_workload_schema=manifest.schema, compute_workload_source_kind=kind, compute_workload_execution_binding_commitment=result.execution_binding_commitment, compute_workload_recipient_release_commitment=result.recipient_release_commitment, max_prefill_tokens=manifest.max_prefill_tokens, max_sample_tokens=manifest.max_sample_tokens, max_train_tokens=manifest.max_train_tokens)
    return request, envelope, result


def _plan(flow, request):
    return flow.coordinator.create_plan(run_id=flow.snapshot["run_id"], requester_address=flow.wallet, request=request, now=ingress_test.NOW)


def _authorize(flow, plan):
    submissions = []
    for account in flow.accounts:
        challenge = flow.coordinator.issue_owner_grant_challenge(plan_token=plan.plan_token, owner_address=account.address.lower(), now=ingress_test.NOW + 1)
        submissions.append({"challenge_token": challenge["challenge_token"], "signature": Account.sign_message(encode_defunct(text=challenge["message"]), account.key).signature.hex()})
    flow.coordinator.authorize(plan_token=plan.plan_token, requester_address=flow.wallet, grant_submissions=submissions, idempotency_key="real-collaboration-authorize", now=ingress_test.NOW + 2)
    with flow.journal._exclusive_lock():
        record = next(iter(flow.journal._load_unlocked()["records"].values()))
    intent = CollaborationExecutionIntent.from_dict(record["intent"])
    grants = _stored_grants(flow.journal)
    return intent, grants, intent.validate_for_grants(grants, now=ingress_test.NOW + 3)


def test_real_prj_upload_collaboration_claim_and_provider_lease_preserve_wire_and_ciphertext(real_flow):
    flow = real_flow
    request, envelope, result = _upload(flow)
    plan = _plan(flow, request)
    intent, grants, compute = _authorize(flow, plan)
    assert compute.project_reference == compute.project_id == canonical_compute_project_id(flow.project)
    assert compute.job_reference == compute.job_id
    assert flow.coordinator.current_basis_for_intent(intent).commitment == plan.basis.commitment
    journal = ComputeExecutionJournal(flow.tmp_path / "dispatch.json", integrity_key=b"j" * 32)
    observed_at = ingress_test.NOW + 3
    finalized = _finalized_receipt(intent, observed_at=observed_at)
    royalty_reader, _calls = _royalty_reader(intent=intent, grants=grants, release=royalty_release_binding_from_settings(flow.coordinator.settings))
    worker = CollaborationExecutionWorkerService(
        coordinator=flow.coordinator, journal=flow.journal,
        vault_reader=SimpleNamespace(observe=lambda _intent, **_kwargs: finalized),
        royalty_reader=royalty_reader,
        admission=ComputeDispatchAdmissionService(journal, flow.harness.service),
        compute_reader=AuthenticatedComputeJournalReader(journal, integrity_key=b"j" * 32),
    )
    cycle = worker.run_once(now=observed_at)
    assert cycle["claimed_execution_id"] == intent.execution_id
    assert journal.public_get(compute.job_id)["workload_claim_confirmed"] is True
    assert cycle["provider_call_performed_by_collaboration"] is False
    claim = compute_dispatch_claim_for_intent(compute)
    stored = flow.harness.store.get_claimed_for_execution(result.workload_id, project_commitment=flow.harness.principal.project_commitment, claim=claim)
    assert stored.envelope == envelope
    assert stored.binding.project_commitment == flow.harness.principal.project_commitment
    with flow.harness.service.lease_for_provider_execution(result.workload_id, project_id=compute.project_reference, claim=claim, source_kind=compute.workload_source_kind, recipient_release_commitment=compute.workload_recipient_release_commitment) as lease:
        assert b"private sequence observation" in lease.plaintext
        assert lease.reauthenticate().valid is True
        plaintext = lease.plaintext
    assert not any(plaintext)
    assert flow.harness.service.release_after_usage_checkpoint(result.workload_id, project_id=compute.project_reference, claim=claim, release_checkpoint_commitment="sha256:" + "f" * 64)


@pytest.mark.parametrize("field,value", [
    ("compute_project_id", "0x" + "a" * 64),
    ("compute_manifest_commitment", "0x" + "b" * 64),
    ("compute_workload_commitment", "0x" + "c" * 64),
    ("compute_workload_execution_binding_commitment", "sha256:" + "d" * 64),
    ("compute_workload_recipient_release_commitment", "sha256:" + "e" * 64),
    ("compute_workload_source_kind", "credential"),
    ("max_prefill_tokens", 1023),
])
def test_real_plan_rejects_project_manifest_source_and_binding_substitution(real_flow, field, value):
    request, envelope, result = _upload(real_flow)
    request[field] = value
    with pytest.raises(FLOW_REJECTION):
        _plan(real_flow, request)
    stored = real_flow.harness.store.get_for_project(result.workload_id, project_commitment=real_flow.harness.principal.project_commitment)
    assert stored.envelope == envelope
    assert stored.lifecycle == "sealed"


def test_another_wallet_upload_cannot_be_adopted_as_wallet_source(real_flow):
    other = real_flow.accounts[1].address.lower()
    real_flow.store.add_member(real_flow.project, actor_address=real_flow.wallet, member_address=other, role="developer", updated_at=ingress_test.NOW)
    request, _envelope, _result = _upload(real_flow, actor=other)
    with pytest.raises(FLOW_REJECTION):
        _plan(real_flow, request)


@pytest.mark.parametrize("role,allowed", [("viewer", False), ("admin", True), ("developer", True)])
def test_plan_requires_current_mutating_compute_membership(real_flow, role, allowed):
    flow = real_flow
    owner = "0x" + "ac" * 20
    project = flow.store.create_project(owner_address=owner, name="role-project", idempotency_key="role-project-create", created_at=ingress_test.NOW)[0]["project_id"]
    flow.store.add_member(project, actor_address=owner, member_address=flow.wallet, role=role, updated_at=ingress_test.NOW)
    flow.project = project
    flow.harness.principal = ComputeWorkloadPrincipal(kind="wallet", project_id=project, actor_id=flow.wallet)
    request, _envelope, _result = _upload(flow)
    if allowed:
        assert _plan(flow, request).basis.compute_project_id == canonical_compute_project_id(project)
    else:
        with pytest.raises(FLOW_REJECTION):
            _plan(flow, request)


def test_credential_source_requires_explicit_release_adoption_gate(real_flow):
    request, _envelope, _result = _upload(real_flow, kind="credential")
    with pytest.raises(FLOW_REJECTION):
        _plan(real_flow, request)
    real_flow.harness.service.wallet_adoption_enabled = True
    plan = _plan(real_flow, request)
    assert plan.basis.compute_workload_source_kind == "credential"
    real_flow.harness.service.wallet_adoption_enabled = False
    with pytest.raises(FLOW_REJECTION):
        real_flow.coordinator._require_current_plan(plan)


def test_current_basis_and_provider_reauthentication_notice_fresh_membership_revocation(real_flow):
    flow = real_flow
    owner = "0x" + "ab" * 20
    second = flow.store.create_project(owner_address=owner, name="delegated-project", idempotency_key="delegated-project-create", created_at=ingress_test.NOW)[0]["project_id"]
    flow.store.add_member(second, actor_address=owner, member_address=flow.wallet, role="developer", updated_at=ingress_test.NOW)
    flow.project = second
    flow.harness.principal = ComputeWorkloadPrincipal(kind="wallet", project_id=second, actor_id=flow.wallet)
    request, _envelope, result = _upload(flow)
    plan = _plan(flow, request)
    intent, _grants, compute = _authorize(flow, plan)
    journal = ComputeExecutionJournal(flow.tmp_path / "dispatch.json", integrity_key=b"j" * 32)
    ComputeDispatchAdmissionService(journal, flow.harness.service).enqueue_collaboration_one_shot(compute, idempotency_key="fresh-membership-handoff", created_at=ingress_test.NOW + 3)
    claim = compute_dispatch_claim_for_intent(compute)
    with flow.harness.service.lease_for_provider_execution(result.workload_id, project_id=compute.project_reference, claim=claim, source_kind=compute.workload_source_kind, recipient_release_commitment=compute.workload_recipient_release_commitment) as lease:
        flow.store.remove_member(second, actor_address=owner, member_address=flow.wallet, updated_at=ingress_test.NOW + 4)
        with pytest.raises(ComputeWorkloadIngressError):
            lease.reauthenticate()
        with pytest.raises(CollaborationExecutionServiceError):
            flow.coordinator.current_basis_for_intent(intent)
    with pytest.raises(FLOW_REJECTION):
        flow.coordinator._require_current_plan(plan)


def test_release_context_drift_invalidates_current_plan(real_flow):
    request, _envelope, _result = _upload(real_flow)
    plan = _plan(real_flow, request)
    real_flow.harness.provider.activation = ingress_test._authenticated_activation(
        real_flow.harness.recipient, sequence=1, compose_hash="0x" + "f" * 64,
    )
    with pytest.raises(FLOW_REJECTION):
        real_flow.coordinator._require_current_plan(plan)


@pytest.mark.parametrize("failure", ["membership_revoked", "authority_store_unavailable"])
def test_worker_claim_checks_current_compute_authority_before_funding_or_handoff(real_flow, failure):
    flow = real_flow
    owner = "0x" + "ad" * 20
    project = flow.store.create_project(owner_address=owner, name="claim-project", idempotency_key="claim-project-create", created_at=ingress_test.NOW)[0]["project_id"]
    flow.store.add_member(project, actor_address=owner, member_address=flow.wallet, role="developer", updated_at=ingress_test.NOW)
    flow.project = project
    flow.harness.principal = ComputeWorkloadPrincipal(kind="wallet", project_id=project, actor_id=flow.wallet)
    request, _envelope, result = _upload(flow)
    intent, _grants, _compute = _authorize(flow, _plan(flow, request))
    journal = ComputeExecutionJournal(flow.tmp_path / "dispatch.json", integrity_key=b"j" * 32)
    before_dispatch = journal.path.read_bytes()
    before_collaboration = flow.journal.path.read_bytes()
    def no_funding_read(*_args, **_kwargs):
        raise AssertionError("current Compute authority must be checked before funding RPC")
    worker = CollaborationExecutionWorkerService(
        coordinator=flow.coordinator, journal=flow.journal,
        vault_reader=SimpleNamespace(observe=no_funding_read),
        royalty_reader=SimpleNamespace(observe=no_funding_read),
        admission=ComputeDispatchAdmissionService(journal, flow.harness.service),
        compute_reader=AuthenticatedComputeJournalReader(journal, integrity_key=b"j" * 32),
    )
    if failure == "membership_revoked":
        flow.store.remove_member(project, actor_address=owner, member_address=flow.wallet, updated_at=ingress_test.NOW + 3)
        expected = CollaborationExecutionAuthorityInvalidated
    else:
        flow.path.write_bytes(b"{}")
        expected = CollaborationExecutionAuthorityUnavailable
    with pytest.raises(expected):
        worker.run_once(now=ingress_test.NOW + 3)
    assert journal.path.read_bytes() == before_dispatch
    stored = flow.harness.store.get_for_project(result.workload_id, project_commitment=flow.harness.principal.project_commitment)
    assert stored.lifecycle == "sealed"
    if failure == "authority_store_unavailable":
        assert flow.journal.path.read_bytes() == before_collaboration
    else:
        with flow.journal._exclusive_lock():
            record = flow.journal._load_unlocked()["records"][intent.execution_id]
        assert record["state"] == "authority_invalidated"


def test_bytes32_cannot_resolve_without_trusted_store(real_flow):
    request, _envelope, _result = _upload(real_flow)
    real_flow.harness.service.project_resolver = None
    with pytest.raises(FLOW_REJECTION):
        _plan(real_flow, request)


def test_readonly_resolver_never_creates_migrates_or_mutates_store(real_flow):
    flow = real_flow
    with pytest.raises(ComputeStoreCorruptError):
        ComputeStore(flow.tmp_path / "absent.json", integrity_key=flow.key, read_only=True)
    assert not (flow.tmp_path / "absent.json").exists()
    root = json.loads(flow.path.read_bytes())
    root["schema_version"] = 1
    del root["payload"]["credential_deliveries"]
    canonical = json.dumps(root["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    root["integrity"]["value"] = hmac.new(flow.key, canonical, hashlib.sha256).hexdigest()
    flow.path.write_text(json.dumps(root))
    before = flow.path.read_bytes()
    reader = ComputeStore(flow.path, integrity_key=flow.key, read_only=True)
    assert reader.resolve_project_reference(canonical_compute_project_id(flow.project), actor_address=flow.wallet) == flow.project
    with pytest.raises(ComputeStoreError):
        reader.create_project(owner_address=flow.wallet, name="forbidden", idempotency_key="forbidden-project-create", created_at=ingress_test.NOW)
    assert flow.path.read_bytes() == before
    root["integrity"]["value"] = "0" * 64
    flow.path.write_text(json.dumps(root))
    with pytest.raises(ComputeStoreCorruptError):
        ComputeStore(flow.path, integrity_key=flow.key, read_only=True)
