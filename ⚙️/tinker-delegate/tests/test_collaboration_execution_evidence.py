from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from dataclasses import replace
from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.collaboration_execution_evidence import (
    EVIDENCE_CLASSIFICATION,
    CollaborationExecutionEvidenceError,
    CollaborationExecutionWorkerHeartbeat,
    CollaborationExecutionWorkerHeartbeatStore,
    CollaborationExecutionWorkerReleaseBindings,
    collaboration_execution_worker_heartbeat_integrity_key,
    project_collaboration_execution_worker_capability,
)
from tinker_delegate.qvl_freshness import QvlChallenge, qvl_challenge_digest
from tinker_delegate.royalty_qvl_client import (
    AuthenticatedRoyaltyQvlCapabilityObservation,
)


def _bindings(**changes):
    values = {
        "release_git_sha": "a" * 40,
        "release_verification_sha256": "sha256:" + "1" * 64,
        "deployment_intent_sha256": "sha256:" + "2" * 64,
        "release_authority_sha256": "sha256:" + "3" * 64,
        "ceremony_nonce": "0x" + "4" * 64,
        "main_runtime_cvm_id": "main-runtime-cvm-0001",
        "main_runtime_compose_hash": "0x" + "5" * 64,
        "main_runtime_app_id": "e1" * 20,
        "main_runtime_os_image_hash": "f1" * 32,
        "royalty_release_binding_commitment": "sha256:" + "6" * 64,
        "royalty_distributor_address": "0x" + "7" * 40,
        "compute_vault_address": "0x" + "8" * 40,
        "compute_vault_runtime_code_hash": "0x" + "9" * 64,
    }
    values.update(changes)
    return CollaborationExecutionWorkerReleaseBindings(**values)


def _qvl_observation(bindings, *, observed_at=1_800_000_000):
    signer = Account.from_key("0x" + "42" * 32)
    challenge = QvlChallenge(
        schema="dnai.attestation-qvl-challenge.v2",
        chain_id=84_532,
        domain="main_runtime_cvm",
        profile="royalty_settlement",
        cvm_id=bindings.main_runtime_cvm_id,
        deployment_intent_sha256=bindings.deployment_intent_sha256,
        release_authority_sha256=bindings.release_authority_sha256,
        ceremony_nonce=bindings.ceremony_nonce,
        measurement_policy_sha256="sha256:" + "a" * 64,
        release_policy_hash="0x" + "b" * 64,
        challenge_id="0x" + "c" * 64,
        challenge_digest="0x" + "d" * 64,
        issued_at=observed_at - 1,
        expires_at=observed_at + 60,
        verifier_address=signer.address.lower(),
        verifier_signature="0x" + "01" * 64 + "1b",
    )
    digest = qvl_challenge_digest(challenge)
    signature = signer.sign_message(encode_defunct(hexstr=digest))
    challenge = replace(
        challenge,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signature.signature).hex(),
    )
    return AuthenticatedRoyaltyQvlCapabilityObservation(
        observed_at=observed_at,
        endpoint_sha256="sha256:" + "e" * 64,
        release_binding_sha256=bindings.royalty_release_binding_commitment,
        challenge=challenge,
        qvl_verdict_verifier_address=signer.address.lower(),
        qvl_release_policy_hash=challenge.release_policy_hash,
        royalty_qvl_verifier_address="0x" + "d" * 40,
        royalty_qvl_policy_commitment="0x" + "e" * 64,
        royalty_qvl_signer_key_id="0x" + "f" * 64,
    )


def _heartbeat(
    bindings,
    *,
    observed_at=1_800_000_000,
    state="ready",
    reachability="authenticated_exact_capability",
    observation="default",
):
    qvl_observation = (
        _qvl_observation(bindings, observed_at=observed_at)
        if observation == "default"
        else observation
    )
    return CollaborationExecutionWorkerHeartbeat(
        bindings=bindings,
        observed_at=observed_at,
        state=state,
        real_dstack=True,
        simulator=False,
        qvl_configuration="complete",
        qvl_reachability=reachability,
        qvl_capability_observation=qvl_observation,
    )


def test_fresh_authenticated_exact_presence_is_live_but_not_job_attestation(
    tmp_path,
):
    bindings = _bindings()
    store = CollaborationExecutionWorkerHeartbeatStore(
        tmp_path / "worker.json", integrity_key=b"k" * 32
    )
    store.write(_heartbeat(bindings, observed_at=1_800_000_000))
    result = project_collaboration_execution_worker_capability(
        enabled=True,
        expected_bindings=bindings,
        heartbeat_store=store,
        now=1_800_000_002,
        ttl_seconds=30,
    )
    assert result["status"] == "live"
    assert result["onchain_reservation_ready"] is True
    assert result["queued_work_executable"] is True
    assert result["evidence_classification"] == EVIDENCE_CLASSIFICATION
    assert result["evidence_authenticity"] == "hmac_verified"
    assert result["real_dstack"] is True
    assert result["simulator"] is False
    assert result["tdx_job_attestation_proven"] is False
    assert result["qvl_job_verdict_proven"] is False
    assert result["qvl_capability"] == {
        "configuration": "complete",
        "reachability": "authenticated_exact_capability",
        "observation_sha256": _qvl_observation(bindings).commitment,
        "observed_at": 1_800_000_000,
        "expires_at": 1_800_000_060,
        "profile": "royalty_settlement",
        "royalty_authorization_schema": (
            "dnai.royalty-settlement-qvl-authorization-request.v2"
        ),
        "per_job_qvl_required": True,
        "per_job_qvl_verified": False,
    }


@pytest.mark.parametrize(
    "reachability,observation,reason",
    [
        ("configured_not_probed", None, "qvl_capability_not_probed"),
        ("unreachable", None, "qvl_capability_unreachable"),
        ("mismatch", None, "qvl_capability_mismatch"),
    ],
)
def test_configured_unreachable_or_mismatched_qvl_never_unlocks_funding(
    tmp_path,
    reachability,
    observation,
    reason,
):
    bindings = _bindings()
    store = CollaborationExecutionWorkerHeartbeatStore(
        tmp_path / "worker.json", integrity_key=b"k" * 32
    )
    store.write(
        _heartbeat(
            bindings,
            reachability=reachability,
            observation=observation,
        )
    )
    result = project_collaboration_execution_worker_capability(
        enabled=True,
        expected_bindings=bindings,
        heartbeat_store=store,
        now=1_800_000_002,
        ttl_seconds=30,
    )
    assert result["status"] == "unavailable"
    assert result["gate_reason"] == reason
    assert result["onchain_reservation_ready"] is False


def test_stale_qvl_observation_never_hides_behind_fresh_worker_heartbeat(tmp_path):
    bindings = _bindings()
    store = CollaborationExecutionWorkerHeartbeatStore(
        tmp_path / "worker.json", integrity_key=b"k" * 32
    )
    store.write(
        _heartbeat(
            bindings,
            observed_at=1_800_000_020,
            observation=_qvl_observation(
                bindings,
                observed_at=1_800_000_000,
            ),
        )
    )
    result = project_collaboration_execution_worker_capability(
        enabled=True,
        expected_bindings=bindings,
        heartbeat_store=store,
        now=1_800_000_031,
        ttl_seconds=30,
    )
    assert result["gate_reason"] == "qvl_capability_stale"
    assert result["onchain_reservation_ready"] is False


@pytest.mark.parametrize(
    "enabled,now,expected,reason",
    [
        (False, 1_800_000_002, True, "execution_disabled"),
        (True, 1_800_000_031, True, "heartbeat_stale"),
        (True, 1_799_999_990, True, "heartbeat_invalid"),
        (True, 1_800_000_002, False, "release_binding_mismatch"),
    ],
)
def test_disabled_stale_future_or_mismatched_presence_never_unlocks_reservation(
    tmp_path, enabled, now, expected, reason
):
    bindings = _bindings()
    store = CollaborationExecutionWorkerHeartbeatStore(
        tmp_path / "worker.json", integrity_key=b"k" * 32
    )
    store.write(_heartbeat(bindings))
    result = project_collaboration_execution_worker_capability(
        enabled=enabled,
        expected_bindings=bindings if expected else _bindings(release_git_sha="b" * 40),
        heartbeat_store=store,
        now=now,
        ttl_seconds=30,
    )
    assert result["status"] == "unavailable"
    assert result["gate_reason"] == reason
    assert result["queue_control_plane_available"] is enabled
    assert result["onchain_reservation_ready"] is False
    assert result["heartbeat_observed_at"] is None


def test_heartbeat_tamper_wrong_key_and_time_regression_fail_closed(tmp_path):
    path = tmp_path / "worker.json"
    store = CollaborationExecutionWorkerHeartbeatStore(
        path, integrity_key=b"k" * 32
    )
    bindings = _bindings()
    store.write(_heartbeat(bindings, observed_at=1_800_000_010))
    with pytest.raises(CollaborationExecutionEvidenceError, match="regressed"):
        store.write(_heartbeat(bindings, observed_at=1_800_000_009))
    wrong = CollaborationExecutionWorkerHeartbeatStore(
        path, integrity_key=b"x" * 32
    )
    with pytest.raises(CollaborationExecutionEvidenceError, match="authentication"):
        wrong.read()
    envelope = json.loads(path.read_text("utf-8"))
    envelope["heartbeat"]["state"] = "unavailable"
    path.write_text(json.dumps(envelope), encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(CollaborationExecutionEvidenceError, match="authentication"):
        store.read()


def test_local_key_is_purpose_separated_and_requires_32_bytes(monkeypatch):
    monkeypatch.setattr(
        "tinker_delegate.collaboration_execution_evidence.dstack_utils.is_dstack_enabled",
        lambda: False,
    )
    with pytest.raises(CollaborationExecutionEvidenceError, match="unavailable"):
        collaboration_execution_worker_heartbeat_integrity_key(
            SimpleNamespace(
                collaboration_execution_worker_heartbeat_integrity_key="short"
            )
        )
    key = collaboration_execution_worker_heartbeat_integrity_key(
        SimpleNamespace(
            collaboration_execution_worker_heartbeat_integrity_key="k" * 32
        )
    )
    assert len(key) == 32
    assert key != b"k" * 32
