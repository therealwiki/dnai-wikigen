"""Local public-auth/ciphertext integration, explicitly NOT execution E2E.

The real wallet challenge verifier, durable Compute directory, device issuance,
capsule encryption, ingress builder/store, HTTPS activation client, and signed
challenge/verdict authentication run together. Only external dstack SDK calls
and the QVL HTTP transport are fixtures. Their synthetic quote and test signer
are not Intel TDX evidence. Provider release guards are never bypassed: this
host fixture has no production provider release, and execution must stop.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.messages import encode_defunct
from fastapi.testclient import TestClient

from tests import test_api_compute_workload_ingress as ingress_fixture
from tests import test_compute_workload_activation as qvl_fixture
from tinker_delegate import api, dstack_utils
from tinker_delegate.compute_auth import ComputeWalletChallengeStore
from tinker_delegate.compute_tinker_provider import (
    TinkerComputeProviderAdapter,
    TinkerProviderReleaseError,
)
from tinker_delegate.compute_workload_activation import (
    HttpsComputeWorkloadActivationProvider,
    QVL_AUTH_TOKEN_ENV,
)
from tinker_delegate.compute_workload_ingress import (
    INFERENCE_PAYLOAD_SCHEMA,
    INFERENCE_WORKLOAD_SCHEMA,
    WORKLOAD_DSTACK_KEY_PATH,
    WORKLOAD_HKDF_INFO,
    WORKLOAD_INGRESS_ALGORITHM,
    WORKLOAD_INGRESS_ENCODING,
    ComputeWorkloadBinding,
    ComputeWorkloadEnvelope,
    ComputeWorkloadIngressService,
    ComputeWorkloadIngressStore,
    ComputeWorkloadManifest,
    ComputeWorkloadPrincipal,
    build_compute_workload_plaintext,
    compute_workload_aad,
    compute_workload_commitment,
    compute_workload_idempotency_hash,
)
from tinker_delegate.config import Settings
from tinker_delegate.qvl_freshness import qvl_challenge_digest
from tinker_delegate.result_verifier import independent_attestation_verdict_digest


FIXTURE_LABEL = "local_external_dstack_and_qvl_transport_not_tdx_evidence"
PRIVATE_PROMPT = "LOCAL PRIVATE DNA PROGRAM INPUT - must never leave the API"


@pytest.fixture
def local_auth_ingress(monkeypatch, tmp_path):
    """Use real production builders; substitute only external SDK/HTTP calls."""
    now = int(time.time())
    monkeypatch.setattr(qvl_fixture, "NOW", now)
    monkeypatch.setenv("DSTACK_ENABLED", "true")
    monkeypatch.delenv("DSTACK_SIMULATOR_ENDPOINT", raising=False)
    monkeypatch.setenv(QVL_AUTH_TOKEN_ENV, qvl_fixture.AUTH_TOKEN)
    external = SimpleNamespace(
        label=FIXTURE_LABEL,
        key_paths=[],
        quote_report_data=[],
        qvl_requests=[],
        unexpected_requests=[],
        challenges={},
        verdicts=[],
        invalid_proof=None,
        recipient_key_epoch="initial",
    )

    class ExternalDstackSdkFixture:
        def get_key(self, path, purpose):
            assert purpose == "encryption"
            external.key_paths.append(path)
            epoch = external.recipient_key_epoch if path == WORKLOAD_DSTACK_KEY_PATH else "initial"
            material = hashlib.sha256((FIXTURE_LABEL + ":" + path + ":" + epoch).encode()).digest()
            return SimpleNamespace(decode_key=lambda: material)

        def info(self):
            return SimpleNamespace(
                app_id=qvl_fixture.APP_ID,
                os_image_hash=qvl_fixture.OS_IMAGE_HASH,
                compose_hash=qvl_fixture.COMPOSE_HASH,
            )

        def get_quote(self, report_data):
            assert len(report_data) == 64
            external.quote_report_data.append(report_data)
            # Deliberately synthetic bytes: only the fixture QVL accepts these.
            return SimpleNamespace(
                quote="0x" + qvl_fixture.QUOTE.hex(),
                report_data="0x" + report_data.hex(),
            )

    monkeypatch.setattr(dstack_utils, "_client", ExternalDstackSdkFixture)

    def external_http_transport(_transport, request):
        if request.url.host != "verify.example":
            external.unexpected_requests.append(str(request.url))
            raise AssertionError("Unmocked external request is forbidden")
        assert request.headers["authorization"] == f"Bearer {qvl_fixture.AUTH_TOKEN}"
        payload = json.loads(request.content)
        external.qvl_requests.append((request.url.path, payload))
        if request.url.path == "/challenge":
            sequence = len(external.qvl_requests)
            challenge = replace(
                qvl_fixture._signed_challenge(qvl_fixture.QVL),
                **{key: value for key, value in payload.items() if key != "schema"},
                release_policy_hash=settings.compute_workload_qvl_release_policy_hash,
                challenge_id="0x" + hashlib.sha256(str(sequence).encode()).hexdigest(),
            )
            if external.invalid_proof == "stale_challenge":
                challenge = replace(challenge, issued_at=now - 180, expires_at=now - 60)
            digest = qvl_challenge_digest(challenge)
            challenge = replace(
                challenge,
                challenge_digest=digest,
                verifier_signature="0x" + bytes(qvl_fixture.QVL.sign_message(
                    encode_defunct(hexstr=digest)
                ).signature).hex(),
            )
            if external.invalid_proof == "forged_challenge":
                challenge = replace(challenge, verifier_signature="0x" + "00" * 65)
            external.challenges[challenge.challenge_id] = challenge
            return httpx.Response(200, json=challenge.to_public_dict(), request=request)
        assert request.url.path == "/verify"
        challenge = external.challenges.pop(payload["challenge"]["challenge_id"])
        verdict = qvl_fixture._signed_verdict(
            qvl_fixture.QVL, challenge, payload["expectation"]
        )
        verdict = replace(verdict, release_policy_hash=challenge.release_policy_hash)
        if external.invalid_proof == "stale_verdict":
            verdict = replace(verdict, issued_at=now - 180,
                              activation_evidence_lease_expires_at=now - 60, expires_at=now - 60)
        verdict = replace(verdict, verifier_signature="0x" + bytes(qvl_fixture.QVL.sign_message(
            encode_defunct(hexstr=independent_attestation_verdict_digest(verdict))
        ).signature).hex())
        if external.invalid_proof == "forged_verdict":
            verdict = replace(verdict, verifier_signature="0x" + "00" * 65)
        external.verdicts.append(verdict)
        return httpx.Response(200, json=verdict.to_public_dict(), request=request)

    # The ASGI TestClient has its own transport; all genuine outbound HTTP is
    # trapped here, including any accidental request to the paid provider.
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", external_http_transport)
    settings = Settings(
        _env_file=None,
        compute_store_path=str(tmp_path / "compute.json"),
        compute_dispatch_store_path=str(tmp_path / "dispatch.json"),
        compute_workload_ingress_store_path=str(tmp_path / "workloads"),
        compute_workload_wallet_adoption_enabled=True,
        compute_provider_execution_enabled=False,
        compute_workload_qvl_url="https://verify.example/verify",
        compute_workload_qvl_verifier_address=qvl_fixture.QVL.address,
        compute_workload_qvl_release_policy_hash=qvl_fixture.RELEASE_POLICY_HASH,
        compute_workload_qvl_max_verdict_age_seconds=120,
        compute_workload_chain_id=84532,
        compute_vault_address=qvl_fixture.COMPUTE_VAULT,
        compute_vault_runtime_code_hash=qvl_fixture.VAULT_RUNTIME_CODE_HASH,
        compute_workload_fresh_deployment_receipt_sha256=qvl_fixture.FRESH_DEPLOYMENT_RECEIPT_SHA256,
        compute_workload_cvm_id=qvl_fixture.CVM_ID,
        compute_workload_deployment_intent_sha256=qvl_fixture.DEPLOYMENT_INTENT_SHA256,
        compute_workload_release_authority_sha256=qvl_fixture.RELEASE_AUTHORITY_SHA256,
        compute_workload_ceremony_nonce=qvl_fixture.CEREMONY_NONCE,
        compute_workload_measurement_policy_set_sha256=qvl_fixture.MEASUREMENT_POLICY_SET_SHA256,
        compute_workload_qvl_measurement_policy_sha256=qvl_fixture.MEASUREMENT_POLICY_SHA256,
        compute_workload_main_runtime_evidence_sha256=qvl_fixture.MAIN_RUNTIME_EVIDENCE_SHA256,
    )
    monkeypatch.setattr(api, "settings", settings)
    for name in (
        "_compute_store_instance", "_compute_store_instance_identity",
        "_compute_workload_ingress_instance", "_compute_workload_ingress_instance_identity",
        "_compute_dispatch_journal_instance", "_compute_dispatch_journal_instance_identity",
    ):
        monkeypatch.setattr(api, name, None)
    monkeypatch.setattr(api, "_compute_wallet_challenges", ComputeWalletChallengeStore())
    client = TestClient(api.app)
    account = Account.from_key("0x" + "51" * 32)
    state = SimpleNamespace(
        settings=settings, client=client, account=account,
        external=external, root=tmp_path,
    )
    try:
        yield state
    finally:
        ingress = api._compute_workload_ingress_instance
        if ingress is not None:
            ingress.store.close()
            ingress.activation_provider._client.close()
        client.close()


def _issue_public_identity(state):
    client, account = state.client, state.account
    challenge = client.post("/auth/compute/challenge", json={"address": account.address})
    assert challenge.status_code == 200, challenge.text
    signature = account.sign_message(encode_defunct(text=challenge.json()["message"]))
    exchanged = client.post("/auth/compute/token", json={
        "nonce": challenge.json()["nonce"], "signature": signature.signature.hex(),
    })
    assert exchanged.status_code == 200, exchanged.text
    headers = {"Authorization": f"Bearer {exchanged.json()['access_token']}"}
    project = client.post("/compute/projects", json={"name": "local-auth-ingress"}, headers={
        **headers, "Idempotency-Key": "local-auth-project-0001",
    })
    assert project.status_code == 200, project.text
    project_id = project.json()["project"]["project_id"]
    private = X25519PrivateKey.generate()
    device = client.post(f"/compute/projects/{project_id}/devices", json={
        "label": "local-integrated-agent", "kind": "autonomous_agent",
        "public_key": private.public_key().public_bytes_raw().hex(),
    }, headers=headers)
    assert device.status_code == 200, device.text
    issued = client.post(f"/compute/projects/{project_id}/credentials", json={
        "device_id": device.json()["device"]["device_id"],
        "name": "local-integrated-credential",
        "scopes": ["workloads:create", "jobs:read", "workloads:delete"],
        "expires_in_seconds": 3600, "daily_credit_cap": 100,
    }, headers=headers)
    assert issued.status_code == 200, issued.text
    credential_token = ingress_fixture.ComputeWorkloadApiTests._decrypt_capsule(
        issued.json(), private
    )
    assert credential_token not in issued.text
    return SimpleNamespace(
        headers=headers, project_id=project_id,
        credential_id=issued.json()["credential"]["credential_id"],
        credential_headers={"Authorization": f"Bearer {credential_token}"},
    )


def _prepare_public_ciphertext(state, identity):
    response = state.client.get("/compute/workload-encryption-contract")
    assert response.status_code == 200, response.text
    contract = response.json()
    assert contract["upload_enabled"] is True
    assert contract["activation"]["schema"] == "dnai.compute.workload-recipient-activation.v4"
    recipient = contract["recipient"]
    ingress = api._get_compute_workload_ingress()
    assert type(ingress) is ComputeWorkloadIngressService
    assert type(ingress.store) is ComputeWorkloadIngressStore
    assert type(ingress.activation_provider) is HttpsComputeWorkloadActivationProvider
    principal = ComputeWorkloadPrincipal(
        kind="credential", project_id=identity.project_id, actor_id=identity.credential_id,
    )
    # Client serialization consumes only the public descriptor. It cannot call
    # current_activation/binding_for or freeze the server's fresh-proof path.
    manifest = ComputeWorkloadManifest(
        schema=INFERENCE_WORKLOAD_SCHEMA, operation="inference", model="qwen3_8b",
        recipe="qwen3_8b_bounded", payload_size_class="4k", example_count_class="none",
        max_prefill_tokens=1024, max_sample_tokens=128, max_train_tokens=0,
    )
    plaintext = build_compute_workload_plaintext(manifest, ingress_fixture._canonical({
        "schema": INFERENCE_PAYLOAD_SCHEMA, "prompt": PRIVATE_PROMPT,
    }), blinding=b"\x71" * 32)
    commitment = compute_workload_commitment(manifest, plaintext)
    binding = ComputeWorkloadBinding(
        project_commitment=principal.project_commitment,
        actor_kind=principal.kind, actor_commitment=principal.actor_commitment,
        manifest=manifest, manifest_commitment=manifest.commitment,
        workload_commitment=commitment,
        idempotency_hash=compute_workload_idempotency_hash(principal, "workload-upload-0001"),
        recipient_key_id=recipient["key_id"], report_data_sha256=recipient["report_data_sha256"],
        activation_commitment=recipient["activation_commitment"],
        recipient_release_commitment=recipient["recipient_release_commitment"],
    )
    aad = compute_workload_aad(binding)
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(recipient["encryption_public_key"])))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(), info=WORKLOAD_HKDF_INFO).derive(shared)
    nonce = b"\x73" * 12
    envelope = ComputeWorkloadEnvelope(
        schema_version=1, algorithm=WORKLOAD_INGRESS_ALGORITHM, encoding=WORKLOAD_INGRESS_ENCODING,
        key_id=recipient["key_id"], attestation_report_data=recipient["report_data"],
        activation_commitment=recipient["activation_commitment"], aad=ingress_fixture._b64(aad),
        ephemeral_public_key=ingress_fixture._b64(ephemeral.public_key().public_bytes_raw()),
        nonce=ingress_fixture._b64(nonce), ciphertext=ingress_fixture._b64(AESGCM(key).encrypt(nonce, plaintext, aad)),
    )
    payload = {"workload_commitment": commitment, "manifest": manifest.to_dict(), "envelope": envelope.to_dict()}
    return ingress, principal, payload, contract


def _post_ciphertext(state, identity, payload):
    return state.client.post(f"/compute/projects/{identity.project_id}/workloads", json=payload, headers={
        **identity.credential_headers, "Idempotency-Key": "workload-upload-0001",
    })


def _upload_public_ciphertext(state, identity):
    ingress, principal, payload, _contract = _prepare_public_ciphertext(state, identity)
    uploaded = _post_ciphertext(state, identity, payload)
    return ingress, principal, payload, uploaded


def test_public_wallet_device_capsule_and_real_ingress_preserve_exact_credential_source(local_auth_ingress):
    state = local_auth_ingress
    identity = _issue_public_identity(state)
    ingress, principal, payload, uploaded = _upload_public_ciphertext(state, identity)
    assert uploaded.status_code == 200, uploaded.text
    receipt = uploaded.json()
    assert PRIVATE_PROMPT not in uploaded.text
    assert receipt["execution_binding"]["source_kind"] == "credential"
    assert receipt["execution_binding"]["wallet_adoption_required"] is True
    assert receipt["execution_binding"]["device_spending_authority"] is False
    assert receipt["dispatch_adoption"]["state"] == "wallet_adoption_required"
    stored = ingress.store.get_for_project(receipt["workload_id"], project_commitment=principal.project_commitment)
    assert stored.binding.actor_commitment == principal.actor_commitment
    assert stored.binding.workload_commitment == payload["workload_commitment"]
    assert stored.execution_binding_commitment == receipt["execution_binding"]["commitment"]

    metadata = state.client.get(f"/compute/projects/{identity.project_id}/workloads/{receipt['workload_id']}", headers=identity.headers)
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["workload_commitment"] == receipt["workload_commitment"]
    assert metadata.json()["recipient_release_commitment"] == receipt["recipient_release_commitment"]
    assert PRIVATE_PROMPT not in metadata.text
    assert "ciphertext\"" not in metadata.text
    assert len(state.external.quote_report_data) >= 2
    first, second = state.external.verdicts[:2]
    assert first.challenge_id != second.challenge_id
    assert independent_attestation_verdict_digest(first) != independent_attestation_verdict_digest(second)
    replay = _post_ciphertext(state, identity, payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["workload_id"] == receipt["workload_id"]
    assert replay.json()["execution_binding"] == receipt["execution_binding"]
    assert len(list((state.root / "workloads" / "envelopes").iterdir())) == 1
    assert not state.external.challenges  # Every fixture challenge was consumed once.
    assert not state.external.unexpected_requests


def test_device_cannot_adopt_and_wallet_cannot_bypass_unconfigured_provider_release(local_auth_ingress):
    state = local_auth_ingress
    identity = _issue_public_identity(state)
    ingress, _principal, _payload, uploaded = _upload_public_ciphertext(state, identity)
    assert uploaded.status_code == 200, uploaded.text
    receipt = uploaded.json()
    request = {
        "job_reference": "local-upload-exact-job", "workload_id": receipt["workload_id"],
        "asset": "0x" + "00" * 20, "authorization_nonce": "0", "max_asset_debit": "1",
        "authorization_expiry": int(time.time()) + 600,
        "rate_policy_commitment": "0x" + "67" * 32, "compose_hash": qvl_fixture.COMPOSE_HASH,
        "operation": "inference", "model": "qwen3_8b", "recipe": "qwen3_8b_bounded",
        "result_policy": "bounded_summary_receipt",
        "max_prefill_tokens": 1024, "max_sample_tokens": 128, "max_train_tokens": 0,
    }
    route = f"/compute/projects/{identity.project_id}/dispatch-intents"
    device_attempt = state.client.post(route, json=request, headers={
        **identity.credential_headers, "Idempotency-Key": "device-cannot-spend-0001",
    })
    assert device_attempt.status_code == 401, device_attempt.text
    wallet_attempt = state.client.post(route, json=request, headers={
        **identity.headers, "Idempotency-Key": "wallet-release-held-0001",
    })
    assert wallet_attempt.status_code == 503, wallet_attempt.text
    assert wallet_attempt.json()["detail"] == "Exact-asset dispatch intent creation is disabled by this release"
    assert not (state.root / "dispatch.json").exists()
    capability = state.client.get("/compute/funding-capabilities").json()["dispatch_intents"]
    assert capability["provider"]["reason"] == "provider_execution_not_enabled"
    assert capability["provider_dispatch"] is False
    assert capability["device_spending_authority"] is False
    with pytest.raises(TinkerProviderReleaseError, match="provider execution is disabled"):
        TinkerComputeProviderAdapter(state.settings, ingress=ingress, result_key=b"r" * 32)
    metadata = state.client.get(f"/compute/projects/{identity.project_id}/workloads/{receipt['workload_id']}", headers=identity.headers)
    assert metadata.status_code == 200, metadata.text
    assert metadata.json()["dispatch_adoption"]["dispatch_claimed"] is False
    assert not state.external.unexpected_requests


@pytest.mark.parametrize("invalid_proof", [
    "forged_verdict", "forged_challenge", "stale_verdict", "stale_challenge", "revoked_quote",
])
def test_real_activation_verifier_rejects_invalid_qvl_before_ingress_persistence(local_auth_ingress, invalid_proof):
    state = local_auth_ingress
    identity = _issue_public_identity(state)
    _ingress, _principal, payload, _contract = _prepare_public_ciphertext(state, identity)
    state.external.invalid_proof = invalid_proof
    if invalid_proof == "revoked_quote":
        state.settings.compute_workload_qvl_revoked_quote_hashes_json = json.dumps([
            "0x" + hashlib.sha256(qvl_fixture.QUOTE).hexdigest(),
        ])
    rejected = _post_ciphertext(state, identity, payload)
    assert rejected.status_code == 503, rejected.text
    assert not list((state.root / "workloads" / "envelopes").iterdir())
    assert PRIVATE_PROMPT not in rejected.text
    assert not state.external.unexpected_requests


@pytest.mark.parametrize("changed_binding", [
    "recipient_key", "compute_workload_ceremony_nonce",
    "compute_workload_release_authority_sha256", "compute_workload_deployment_intent_sha256",
    "compute_workload_qvl_release_policy_hash", "compute_workload_qvl_measurement_policy_sha256",
    "compute_workload_measurement_policy_set_sha256", "compute_workload_main_runtime_evidence_sha256",
    "compute_workload_fresh_deployment_receipt_sha256",
])
def test_fresh_valid_qvl_cannot_rebind_existing_ciphertext_to_changed_release(local_auth_ingress, changed_binding):
    state = local_auth_ingress
    identity = _issue_public_identity(state)
    _ingress, _principal, payload, original = _prepare_public_ciphertext(state, identity)
    if changed_binding == "recipient_key":
        state.external.recipient_key_epoch = "rotated"
        # A recipient-key rotation restarts the actual builder, not its guards.
        api._compute_workload_ingress_instance.store.close()
        api._compute_workload_ingress_instance.activation_provider._client.close()
        api._compute_workload_ingress_instance = None
        api._compute_workload_ingress_instance_identity = None
    else:
        current = getattr(state.settings, changed_binding)
        setattr(state.settings, changed_binding, current.split(":")[0] + ":" + "ab" * 32 if current.startswith("sha256:") else "0x" + "ab" * 32)
    refreshed = state.client.get("/compute/workload-encryption-contract")
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["upload_enabled"] is True  # New release has valid signed proof.
    assert refreshed.json()["recipient"]["activation_commitment"] != original["recipient"]["activation_commitment"]
    rejected = _post_ciphertext(state, identity, payload)
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["detail"] == "Compute workload envelope targets an unverified recipient"
    assert not list((state.root / "workloads" / "envelopes").iterdir())
    assert PRIVATE_PROMPT not in rejected.text
    assert not state.external.unexpected_requests


def test_legacy_v3_full_proof_commitment_fails_closed_without_compatibility_fallback(local_auth_ingress):
    state = local_auth_ingress
    identity = _issue_public_identity(state)
    _ingress, _principal, payload, contract = _prepare_public_ciphertext(state, identity)
    legacy = {**contract["activation"], "schema": "dnai.compute.workload-recipient-activation.v3"}
    payload["envelope"]["activation_commitment"] = "sha256:" + hashlib.sha256(ingress_fixture._canonical(legacy)).hexdigest()
    rejected = _post_ciphertext(state, identity, payload)
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["detail"] == "Compute workload envelope targets an unverified recipient"
    assert not list((state.root / "workloads" / "envelopes").iterdir())
