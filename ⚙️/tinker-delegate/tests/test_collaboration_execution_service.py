from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from eth_abi import decode as abi_decode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from pydantic import ValidationError

from tinker_delegate.api import CollaborationExecutionPlanRequest
from tinker_delegate.collaboration_execution import (
    BASE_SEPOLIA_CHAIN_ID,
    CollaborationExecutionAuthorityInvalidated,
    CollaborationExecutionIntent,
    CollaborationExecutionJournal,
    CollaborationExecutionNotFound,
    ComputeJournalProjection,
    FinalizedComputeVaultObservation,
    OwnerExecutionGrant,
    RoyaltyFundingReservation,
    execution_grant_set_commitment,
)
from tinker_delegate.collaboration_execution_service import (
    AuthenticatedComputeProjection,
    CollaborationExecutionCoordinator,
    CollaborationExecutionServiceError,
    CollaborationExecutionServiceUnavailable,
    CollaborationExecutionWorkerService,
    FinalizedComputeVaultReader,
    FinalizedObservationReceipt,
    FinalizedRoyaltyAuthorityReader,
    royalty_release_binding_commitment,
    royalty_release_binding_from_settings,
)
from tinker_delegate.royalty_settlement_authorization import (
    ROYALTY_AUTHORIZATION_REQUEST_SCHEMA,
    ROYALTY_BINDING_KIND,
    ROYALTY_RELEASE_POLICY_TYPEHASH,
    ROYALTY_SETTLEMENT_POLICY_DOMAIN,
    ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
    ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
    RoyaltySettlementReleaseBinding,
)
import tinker_delegate.collaboration_execution_service as execution_service_module


NOW = 1_800_000_000
ZERO_ADDRESS = "0x" + "00" * 20
VAULT = "0x" + "70" * 20
ANCHOR_WRITER = "0x" + "71" * 20
VAULT_CODE_HASH = "0x" + "72" * 32


def _sha(byte: str) -> str:
    return "sha256:" + byte * 64


def _bytes32(byte: str) -> str:
    return "0x" + byte * 64


def _word_uint(value: int) -> bytes:
    return value.to_bytes(32, "big")


def _word_bool(value: bool) -> bytes:
    return _word_uint(1 if value else 0)


def _word_address(value: str) -> bytes:
    return bytes.fromhex(value[2:]).rjust(32, b"\0")


def _word_bytes32(value: str) -> bytes:
    return bytes.fromhex(value[2:])


def _selector(signature: str) -> bytes:
    return keccak(signature.encode("ascii"))[:4]


def _make_release(*, distributor_code: bytes = b"\x60\x00", **release_overrides) -> RoyaltySettlementReleaseBinding:
    settlement = Account.from_key("0x" + "31" * 32).address.lower()
    qvl = Account.from_key("0x" + "32" * 32).address.lower()
    distributor = Account.from_key("0x" + "33" * 32).address.lower()
    anchor = Account.from_key("0x" + "34" * 32).address.lower()
    owner = Account.from_key("0x" + "35" * 32).address.lower()
    values: dict[str, Any] = {
        "distributor_address": distributor,
        "distributor_runtime_code_hash": "0x" + keccak(distributor_code).hex(),
        "owner_address": owner,
        "authority_nonce": 7,
        "settlement_verifier_address": settlement,
        "royalty_qvl_verifier_address": qvl,
        "execution_policy_anchor_address": anchor,
        "anchor_writer_release_commitment": _bytes32("6"),
        "royalty_qvl_signer_key_id": _bytes32("7"),
        "qvl_release_policy_hash": _bytes32("8"),
        "main_runtime_cvm_id": "main-runtime-cvm-0001",
        "deployment_intent_sha256": _sha("9"),
        "release_authority_sha256": _sha("a"),
        "ceremony_nonce": _bytes32("b"),
        "measurement_policy_sha256": _sha("c"),
        "compose_hash": _bytes32("d"),
        "app_id": "e1" * 20,
        "os_image_hash": "f1" * 32,
    }
    values.update(release_overrides)
    release_policy = "0x" + keccak(
        b"".join(
            (
                ROYALTY_RELEASE_POLICY_TYPEHASH,
                _word_uint(BASE_SEPOLIA_CHAIN_ID),
                _word_address(distributor),
                _word_uint(values["authority_nonce"]),
                _word_address(settlement),
                _word_address(qvl),
                _word_address(anchor),
                _word_bytes32(values["anchor_writer_release_commitment"]),
            )
        )
    ).hex()
    binding = {
        "kind": ROYALTY_BINDING_KIND,
        "distributor_address": distributor,
        "distributor_runtime_code_hash": values[
            "distributor_runtime_code_hash"
        ],
        "owner": owner,
        "settlement_verifier": settlement,
        "settlement_verifier_key_path": ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
        "settlement_verifier_custody": ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
        "execution_policy_anchor": anchor,
        "anchor_writer_release_commitment": values[
            "anchor_writer_release_commitment"
        ],
        "release_policy_commitment": release_policy,
        "authority_nonce": str(values["authority_nonce"]),
        "qvl_signer_key_id": values["royalty_qvl_signer_key_id"],
        "main_runtime_cvm_id": values["main_runtime_cvm_id"],
        "deployment_intent_sha256": values["deployment_intent_sha256"],
        "release_authority_sha256": values["release_authority_sha256"],
        "measurement_policy_sha256": values["measurement_policy_sha256"],
        "max_authorization_lifetime_seconds": 600,
    }
    qvl_policy = {
        "schema": "dnai.royalty-settlement-qvl-policy.v2",
        "authorization_schema": ROYALTY_AUTHORIZATION_REQUEST_SCHEMA,
        "qvl_release_policy_hash": values["qvl_release_policy_hash"],
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "compose_hash": values["compose_hash"],
        "app_id": values["app_id"],
        "os_image_hash": values["os_image_hash"],
        "royalty_qvl_verifier": qvl,
        "binding": binding,
    }
    qvl_policy_commitment = "0x" + hashlib.sha256(
        ROYALTY_SETTLEMENT_POLICY_DOMAIN
        + json.dumps(
            qvl_policy,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    return RoyaltySettlementReleaseBinding(
        **values,
        release_policy_commitment=release_policy,
        royalty_qvl_policy_commitment=qvl_policy_commitment,
    )


def _settings(release: RoyaltySettlementReleaseBinding) -> SimpleNamespace:
    return SimpleNamespace(
        collaboration_execution_release_git_sha="a" * 40,
        collaboration_execution_release_verification_sha256=_sha("1"),
        collaboration_execution_grant_ttl_seconds=300,
        collaboration_execution_royalty_reservation_safety_seconds=900,
        main_runtime_cvm_id=release.main_runtime_cvm_id,
        compute_vault_address=VAULT,
        compute_vault_runtime_code_hash=VAULT_CODE_HASH,
        compute_vault_compose_hash=_bytes32("2"),
        royalty_distributor_address=release.distributor_address,
        royalty_distributor_runtime_code_hash=(
            release.distributor_runtime_code_hash
        ),
        royalty_owner_address=release.owner_address,
        royalty_authority_nonce=release.authority_nonce,
        royalty_settlement_verifier=release.settlement_verifier_address,
        royalty_qvl_verifier=release.royalty_qvl_verifier_address,
        royalty_execution_policy_anchor=release.execution_policy_anchor_address,
        royalty_anchor_writer_release_commitment=(
            release.anchor_writer_release_commitment
        ),
        royalty_release_policy_commitment=release.release_policy_commitment,
        royalty_qvl_policy_commitment=release.royalty_qvl_policy_commitment,
        royalty_qvl_signer_key_id=release.royalty_qvl_signer_key_id,
        royalty_qvl_release_policy_hash=release.qvl_release_policy_hash,
        royalty_measurement_policy_sha256=release.measurement_policy_sha256,
        royalty_main_runtime_compose_hash=release.compose_hash,
        royalty_main_runtime_app_id=release.app_id,
        royalty_main_runtime_os_image_hash=release.os_image_hash,
        release_deployment_intent_sha256=release.deployment_intent_sha256,
        release_authority_sha256=release.release_authority_sha256,
        release_ceremony_nonce=release.ceremony_nonce,
    )


class _Store:
    def __init__(self, snapshot: dict[str, Any]) -> None:
        self.snapshot = snapshot

    def execution_authority_snapshot(
        self, run_id: str, participant_address: str
    ) -> dict[str, Any]:
        assert run_id == self.snapshot["run_id"]
        assert participant_address in {
            item["owner_address"] for item in self.snapshot["owners"]
        }
        return copy.deepcopy(self.snapshot)

    def execution_authority_snapshot_by_commitment(
        self, commitment: str, participant_address: str
    ) -> dict[str, Any]:
        assert commitment == self.snapshot["joint_consent_snapshot_commitment"]
        return self.execution_authority_snapshot(
            self.snapshot["run_id"], participant_address
        )

    def room_projection(self, room_id: str, participant_address: str):
        assert room_id == self.snapshot["room_id"]
        assert participant_address in {
            item["owner_address"] for item in self.snapshot["owners"]
        }
        return {"room_id": room_id}

    def close(self):
        pass


class _RecoveringVerifier:
    def verify(self, *, address: str, message: str, signature: str) -> str:
        recovered = Account.recover_message(
            encode_defunct(text=message), signature=signature
        ).lower()
        if recovered != address:
            raise CollaborationExecutionServiceError(
                "wallet signature does not authorize this execution grant"
            )
        return "eoa"


def _coordinator(tmp_path: Path):
    accounts = sorted(
        (
            Account.from_key("0x" + "11" * 32),
            Account.from_key("0x" + "22" * 32),
        ),
        key=lambda account: account.address.lower(),
    )
    owners = [account.address.lower() for account in accounts]
    snapshot = {
        "schema": "dnai.collaboration.execution-authority-snapshot.v1",
        "state_sequence": 10,
        "run_id": "run_" + "10" * 16,
        "room_id": "room_" + "20" * 16,
        "requester_address": owners[0],
        "room_commitment": _sha("3"),
        "room_generation": 5,
        "room_state_commitment": _sha("4"),
        "query_ref": _sha("5"),
        "query_proposal_commitment": _sha("6"),
        "prospective_query_grant_set_commitment": _sha("7"),
        "allocation_commitment": _sha("8"),
        "joint_consent_snapshot_commitment": _sha("9"),
        "owners": [
            {
                "owner_address": owners[0],
                "allocation_bps": 6_000,
                "prospective_query_grant_authorization_hash": _sha("a"),
                "query_grant_generation": 3,
                "role_consent_generation": 2,
            },
            {
                "owner_address": owners[1],
                "allocation_bps": 4_000,
                "prospective_query_grant_authorization_hash": _sha("b"),
                "query_grant_generation": 4,
                "role_consent_generation": 2,
            },
        ],
        "current": True,
        "raw_signature_egress": False,
        "raw_query_egress": False,
        "raw_artifact_egress": False,
    }
    release = _make_release()
    settings = _settings(release)
    key = b"k" * 32
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=key,
    )
    coordinator = CollaborationExecutionCoordinator(
        settings=settings,
        collaboration_store=_Store(snapshot),
        execution_journal=journal,
        integrity_key=key,
        signature_verifier=_RecoveringVerifier(),
        # These tests isolate grant/funding protocol behavior. The real
        # encrypted-ingress boundary has its own store integration suite.
        workload_ingress=SimpleNamespace(validate_collaboration_workload=lambda _basis, **_kwargs: None),
        clock=lambda: NOW,
    )
    request = {
        "compute_project_id": _bytes32("1"),
        "compute_job_id": _bytes32("2"),
        "compute_workload_id": "wrk_" + "30" * 16,
        "compute_workload_commitment": _bytes32("3"),
        "compute_manifest_commitment": _bytes32("4"),
        "compute_rate_policy_commitment": _bytes32("5"),
        "compute_workload_schema": "dnai.compute.workload.inference.v1",
        "compute_workload_source_kind": "wallet",
        "compute_workload_execution_binding_commitment": _sha("c"),
        "compute_workload_recipient_release_commitment": _sha("d"),
        "compute_user_address": owners[0],
        "operation": "inference",
        "model": "qwen3_8b",
        "recipe": "qwen3_8b_bounded",
        "result_policy": "bounded_summary_receipt",
        "max_prefill_tokens": 4_096,
        "max_sample_tokens": 512,
        "max_train_tokens": 0,
        "sponsor_address": owners[0],
        "asset": ZERO_ADDRESS,
        "max_total_asset_debit": 10_000,
        "max_compute_asset_debit": 8_000,
        "authorization_nonce": 7,
        "authorization_lifetime_seconds": 3_600,
        "royalty_total": 2_000,
    }
    return coordinator, journal, accounts, snapshot, request, release


def _authorize_with_plan(tmp_path: Path):
    coordinator, journal, accounts, snapshot, request, release = _coordinator(
        tmp_path
    )
    plan = coordinator.create_plan(
        run_id=snapshot["run_id"],
        requester_address=snapshot["requester_address"],
        request=request,
        now=NOW,
    )
    submissions = []
    for account in accounts:
        challenge = coordinator.issue_owner_grant_challenge(
            plan_token=plan.plan_token,
            owner_address=account.address.lower(),
            now=NOW + 1,
        )
        signature = Account.sign_message(
            encode_defunct(text=challenge["message"]), account.key
        ).signature.hex()
        submissions.append(
            {
                "challenge_token": challenge["challenge_token"],
                "signature": signature,
            }
        )
    result = coordinator.authorize(
        plan_token=plan.plan_token,
        requester_address=snapshot["requester_address"],
        grant_submissions=submissions,
        idempotency_key="collaboration-execution-0001",
        now=NOW + 2,
    )
    with journal._exclusive_lock():
        body = journal._load_unlocked()
        record = next(iter(body["records"].values()))
    intent = CollaborationExecutionIntent.from_dict(record["intent"])
    return (coordinator, journal, intent, result, request, release), plan


def _authorize(tmp_path: Path):
    return _authorize_with_plan(tmp_path)[0]


def _stored_grants(
    journal: CollaborationExecutionJournal,
) -> tuple[OwnerExecutionGrant, ...]:
    with journal._exclusive_lock():
        record = next(iter(journal._load_unlocked()["records"].values()))
    return tuple(
        OwnerExecutionGrant.from_dict(item)
        for item in record["execution_grants"]
    )


def test_authorization_status_recovers_expired_plan_without_revalidating_or_writing(
    tmp_path, monkeypatch,
):
    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, authorized, _request, _release = values
    before = journal.path.read_bytes()
    before_stat = journal.path.stat()
    coordinator.clock = lambda: NOW + 10_000
    coordinator.store.snapshot["current"] = False
    coordinator.store.snapshot["room_generation"] += 1
    visibility_calls = []
    original_visibility = coordinator.store.room_projection

    def visible(room_id, requester):
        visibility_calls.append((room_id, requester))
        return original_visibility(room_id, requester)

    def forbidden(*_args, **_kwargs):
        pytest.fail("read-only recovery invoked an executable-authority or write path")

    monkeypatch.setattr(coordinator.store, "room_projection", visible)
    for name in ("execution_authority_snapshot", "execution_authority_snapshot_by_commitment"):
        monkeypatch.setattr(coordinator.store, name, forbidden)
    monkeypatch.setattr(coordinator, "_require_current_plan", forbidden)
    monkeypatch.setattr(coordinator, "_basis_from_snapshot", forbidden)
    monkeypatch.setattr(coordinator.signature_verifier, "verify", forbidden)
    monkeypatch.setattr(coordinator.workload_ingress, "validate_collaboration_workload", forbidden)
    for name in ("authorize", "queue", "claim_next", "prepare_compute_handoff",
                 "recover_incomplete", "reconcile_compute_projection", "_write_unlocked"):
        monkeypatch.setattr(journal, name, forbidden)
    request = {
        "plan_token": plan.plan_token,
        "idempotency_key": "collaboration-execution-0001",
    }
    recovered = coordinator.authorization_status(
        **request, requester_address=intent.sponsor_address
    )
    assert set(recovered) == {
        "surface", "schema_version", "request_commitment", "basis_commitment",
        "read_only", "provider_dispatch_performed", "authorization_commitment",
        "royalty_reservation", "execution",
    }
    assert recovered["surface"] == "collaboration_execution_authorization_status"
    assert recovered["schema_version"] == 1
    assert recovered["request_commitment"] == "sha256:" + hashlib.sha256(
        b"dnai.collaboration.execution-authorization-status.v1\0"
        + json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert recovered["basis_commitment"] == plan.basis.commitment
    assert recovered["authorization_commitment"] == authorized["authorization_commitment"]
    assert recovered["execution"] == authorized["execution"]
    assert authorized["execution"]["royalty"]["total"] == str(intent.royalty_total)
    assert recovered["execution"]["royalty"]["total"] == str(intent.royalty_total)
    assert recovered["royalty_reservation"] == authorized["royalty_reservation"]
    assert recovered["read_only"] is True
    assert recovered["provider_dispatch_performed"] is False
    assert "verifier_kinds" not in recovered
    assert visibility_calls == [(intent.room_id, intent.sponsor_address)]
    assert journal.path.read_bytes() == before
    assert journal.path.stat().st_mtime_ns == before_stat.st_mtime_ns
    assert journal.path.stat().st_ino == before_stat.st_ino


@pytest.mark.parametrize("mismatch", ["sponsor", "mac", "key", "plan"])
def test_authorization_status_rejects_wrong_sponsor_mac_key_or_plan(
    tmp_path, mismatch,
):
    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, _authorized, request, _release = values
    lookup = {
        "plan_token": plan.plan_token,
        "requester_address": intent.sponsor_address,
        "idempotency_key": "collaboration-execution-0001",
    }
    expected_error = CollaborationExecutionServiceError
    if mismatch == "sponsor":
        lookup["requester_address"] = intent.owner_addresses[1]
    elif mismatch == "mac":
        encoded, mac = lookup["plan_token"].split(".")
        lookup["plan_token"] = encoded + "." + ("A" if mac[0] != "A" else "B") + mac[1:]
    elif mismatch == "key":
        lookup["idempotency_key"] = "collaboration-execution-other"
        expected_error = CollaborationExecutionNotFound
    else:
        other = coordinator.create_plan(
            run_id=plan.run_id,
            requester_address=intent.sponsor_address,
            request=request,
            now=NOW,
        )
        lookup["plan_token"] = other.plan_token
        expected_error = CollaborationExecutionNotFound
    before = journal.path.read_bytes()
    with pytest.raises(expected_error):
        coordinator.authorization_status(**lookup)
    assert journal.path.read_bytes() == before


@pytest.mark.parametrize("field,value", [
    ("collaboration_execution_release_git_sha", "b" * 40),
    ("collaboration_execution_release_verification_sha256", _sha("e")),
    ("main_runtime_cvm_id", "cvm_changed_release_01"),
    ("compute_vault_compose_hash", _bytes32("e")),
    ("compute_vault_address", "0x" + "e1" * 20),
    ("compute_vault_runtime_code_hash", _bytes32("e")),
    ("royalty_distributor_address", "0x" + "e2" * 20),
    ("royalty_release_policy_commitment", _bytes32("e")),
    ("release_deployment_intent_sha256", _sha("e")),
    ("release_authority_sha256", _sha("e")),
    ("release_ceremony_nonce", _bytes32("e")),
    ("royalty_main_runtime_compose_hash", "e" * 64),
])
def test_authorization_status_requires_configured_release_identity(
    tmp_path, field, value,
):
    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, _authorized, _request, _release = values
    setattr(coordinator.settings, field, value)
    before = journal.path.read_bytes()
    with pytest.raises((CollaborationExecutionServiceError, CollaborationExecutionServiceUnavailable)):
        coordinator.authorization_status(
            plan_token=plan.plan_token,
            requester_address=intent.sponsor_address,
            idempotency_key="collaboration-execution-0001",
        )
    assert journal.path.read_bytes() == before


def test_authorization_status_requires_current_room_visibility(tmp_path, monkeypatch):
    from tinker_delegate.collaboration_store import CollaborationAuthorizationError

    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, _authorized, _request, _release = values

    def not_visible(*_args):
        raise CollaborationAuthorizationError("Wallet cannot view this collaboration room")

    monkeypatch.setattr(coordinator.store, "room_projection", not_visible)
    before = journal.path.read_bytes()
    with pytest.raises(CollaborationAuthorizationError):
        coordinator.authorization_status(
            plan_token=plan.plan_token,
            requester_address=intent.sponsor_address,
            idempotency_key="collaboration-execution-0001",
        )
    assert journal.path.read_bytes() == before


def test_read_only_coordinator_skips_workload_and_preserves_executable_cache(
    tmp_path, monkeypatch,
):
    from tinker_delegate import api
    from tinker_delegate import wallet_signature_verifier

    coordinator, journal, _accounts, _snapshot, _request, _release = _coordinator(tmp_path)
    cached = object()
    cached_identity = ("executable-coordinator",)
    monkeypatch.setattr(api, "settings", coordinator.settings)
    monkeypatch.setattr(api, "_require_collaboration_execution_enabled", lambda: None)
    def existing_journal(*, require_existing):
        assert require_existing is True
        return journal

    monkeypatch.setattr(api, "_get_collaboration_execution_journal", existing_journal)
    monkeypatch.setattr(api, "_get_collaboration_store", lambda: coordinator.store)
    monkeypatch.setattr(api, "_collaboration_execution_coordinator_instance", cached)
    monkeypatch.setattr(api, "_collaboration_execution_coordinator_identity", cached_identity)
    monkeypatch.setattr(execution_service_module, "collaboration_execution_integrity_key", lambda _settings: b"k" * 32)
    monkeypatch.setattr(wallet_signature_verifier, "wallet_signature_verifier_from_settings", lambda _settings: coordinator.signature_verifier)

    def forbidden():
        pytest.fail("recovery attempted to construct current Compute workload authority")

    monkeypatch.setattr(api, "_get_compute_workload_ingress", forbidden)
    reader = api._get_collaboration_execution_coordinator(
        read_only=True, authority_view=coordinator.store
    )
    assert reader is not cached
    assert reader.journal is journal
    assert reader.workload_ingress is None
    assert api._collaboration_execution_coordinator_instance is cached
    assert api._collaboration_execution_coordinator_identity is cached_identity


@pytest.mark.parametrize("cached", [False, True])
def test_authorization_status_api_never_initializes_a_missing_journal(
    tmp_path, monkeypatch, cached,
):
    from fastapi import HTTPException
    from tinker_delegate import api, wallet_signature_verifier

    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, _authorized, _request, _release = values
    coordinator.settings.collaboration_execution_journal_path = str(journal.path)
    identity = (str(journal.path), hashlib.sha256(b"k" * 32).hexdigest())
    monkeypatch.setattr(api, "settings", coordinator.settings)
    monkeypatch.setattr(api, "_require_collaboration_execution_enabled", lambda: None)
    monkeypatch.setattr(api, "_require_collaboration_wallet_auth", lambda _auth, **_kwargs: SimpleNamespace(address=intent.sponsor_address))
    monkeypatch.setattr(api, "_get_read_only_collaboration_store", lambda: coordinator.store)
    monkeypatch.setattr(api, "_get_collaboration_store", lambda: coordinator.store)
    monkeypatch.setattr(api, "_collaboration_execution_journal_instance", journal if cached else None)
    monkeypatch.setattr(api, "_collaboration_execution_journal_instance_identity", identity if cached else None)
    monkeypatch.setattr(execution_service_module, "collaboration_execution_integrity_key", lambda _settings: b"k" * 32)
    monkeypatch.setattr(wallet_signature_verifier, "wallet_signature_verifier_from_settings", lambda _settings: coordinator.signature_verifier)
    journal.path.unlink()
    with pytest.raises(HTTPException) as raised:
        api.collaboration_get_execution_authorization_status(
            api.CollaborationExecutionAuthorizationStatusRequest(
                plan_token=plan.plan_token,
                idempotency_key="collaboration-execution-0001",
            ),
            authorization="Bearer synthetic-wallet-auth",
        )
    assert raised.value.status_code == 503
    assert not journal.path.exists()


def _authorization_status_api_fixture(tmp_path, monkeypatch):
    """Produce a shared browser contract from the real coordinator and route."""

    from tinker_delegate import api
    from tinker_delegate.collaboration_execution_evidence import (
        project_collaboration_execution_worker_capability,
    )

    grant_ids = iter(("41" * 16, "42" * 16))
    monkeypatch.setattr(execution_service_module, "_fresh_nonzero_bytes32", lambda: _bytes32("d"))
    monkeypatch.setattr(execution_service_module, "_fresh_nonzero_uint256", lambda: 2**200 + 123_456_789)
    monkeypatch.setattr(execution_service_module, "secrets", SimpleNamespace(token_hex=lambda _length: next(grant_ids)))
    values, plan = _authorize_with_plan(tmp_path)
    coordinator, journal, intent, authorized, plan_request, _release = values
    request = {
        "plan_token": plan.plan_token,
        "idempotency_key": "collaboration-execution-0001",
    }
    monkeypatch.setattr(api, "_require_collaboration_execution_enabled", lambda: None)
    monkeypatch.setattr(api, "_require_collaboration_wallet_auth", lambda _auth, **_kwargs: SimpleNamespace(address=intent.sponsor_address))
    monkeypatch.setattr(api, "_get_read_only_collaboration_store", lambda: coordinator.store)

    def get_reader(*, read_only, authority_view):
        assert read_only is True
        assert authority_view is coordinator.store
        return coordinator

    monkeypatch.setattr(api, "_get_collaboration_execution_coordinator", get_reader)
    monkeypatch.setattr(api, "_project_collaboration_execution_capability", lambda: project_collaboration_execution_worker_capability(
        enabled=True, expected_bindings=None, heartbeat_store=None,
        now=NOW + 10_000, ttl_seconds=30,
    ))
    coordinator.clock = lambda: NOW + 10_000
    before = journal.path.read_bytes()
    response = api.collaboration_get_execution_authorization_status(
        api.CollaborationExecutionAuthorizationStatusRequest.model_validate(request),
        authorization="Bearer synthetic-wallet-auth",
    )
    assert journal.path.read_bytes() == before
    return {
        "plan_request": plan_request,
        "plan": plan.to_public_dict(),
        "request": request,
        "response": response,
        "authorization_response": api._with_collaboration_execution_capability(
            authorized, resource_kind="execution_authorization"
        ),
    }


def test_authorization_status_api_matches_shared_browser_fixture(tmp_path, monkeypatch):
    fixture_path = Path(__file__).resolve().parents[3] / "web/src/lib/fixtures/collaboration-authorization-status.json"
    expected = json.loads(fixture_path.read_text("utf-8"))
    assert _authorization_status_api_fixture(tmp_path, monkeypatch) == expected


def test_plan_and_grants_bind_a_server_generated_deposited_reservation(tmp_path):
    coordinator, journal, accounts, snapshot, request, _release = _coordinator(
        tmp_path
    )
    first = coordinator.create_plan(
        run_id=snapshot["run_id"],
        requester_address=snapshot["requester_address"],
        request=request,
        now=NOW,
    )
    second = coordinator.create_plan(
        run_id=snapshot["run_id"],
        requester_address=snapshot["requester_address"],
        request=request,
        now=NOW,
    )
    assert first.basis.royalty_settlement_id.startswith("0x")
    assert first.basis.royalty_settlement_id != second.basis.royalty_settlement_id
    assert first.basis.royalty_settlement_nonce > 0
    assert first.basis.royalty_settlement_nonce != second.basis.royalty_settlement_nonce
    assert first.basis.royalty_reservation_safety_seconds == 900
    assert first.basis.commitment != second.basis.commitment

    with pytest.raises(CollaborationExecutionServiceError, match="fields"):
        coordinator.create_plan(
            run_id=snapshot["run_id"],
            requester_address=snapshot["requester_address"],
            request={**request, "royalty_reservation_id": _bytes32("f")},
            now=NOW,
        )
    with pytest.raises(ValidationError):
        CollaborationExecutionPlanRequest.model_validate(
            {**request, "royalty_reservation_id": _bytes32("f")}
        )

    challenges = [
        coordinator.issue_owner_grant_challenge(
            plan_token=first.plan_token,
            owner_address=account.address.lower(),
            now=NOW + 1,
        )
        for account in accounts
    ]
    assert challenges[0]["grant_id"] != challenges[1]["grant_id"]
    assert all(item["scope"] == "one_shot_execution" for item in challenges)
    only_one = Account.sign_message(
        encode_defunct(text=challenges[0]["message"]), accounts[0].key
    ).signature.hex()
    with pytest.raises(
        CollaborationExecutionAuthorityInvalidated,
        match="every collaboration owner",
    ):
        coordinator.authorize(
            plan_token=first.plan_token,
            requester_address=snapshot["requester_address"],
            grant_submissions=[
                {
                    "challenge_token": challenges[0]["challenge_token"],
                    "signature": only_one,
                }
            ],
            idempotency_key="collaboration-execution-missing-owner",
            now=NOW + 2,
        )
    with journal._exclusive_lock():
        assert journal._load_unlocked()["records"] == {}


def test_authorize_returns_exact_reservation_terms_and_retains_no_signature(
    tmp_path,
):
    _coordinator_value, journal, intent, result, _request, _release = _authorize(
        tmp_path
    )
    reservation = result["royalty_reservation"]
    grants = _stored_grants(journal)
    grant_set = execution_grant_set_commitment(
        intent.to_basis(), grants, now=NOW + 2
    )
    expected = RoyaltyFundingReservation.derive(
        intent,
        execution_grant_set_commitment=grant_set,
    ).to_dict()
    assert reservation == expected
    assert reservation["request"]["refund_after"] == str(
        intent.authorization_expiry
        + intent.royalty_reservation_safety_seconds
    )
    assert reservation["transaction"]["function_name"] == "reserveNative"
    assert reservation["transaction"]["value"] == str(intent.royalty_total)
    assert reservation["transaction"]["calldata"].startswith("0x")
    persisted = (journal.path).read_text("utf-8")
    assert "raw_signature" not in persisted
    assert "provider_request" not in persisted
    assert reservation["reservation_id"] in persisted


def test_uint256_nonce_round_trips_plan_grants_reservation_calldata_and_journal(
    tmp_path,
    monkeypatch,
):
    nonce = 2**200 + 123_456_789
    monkeypatch.setattr(
        execution_service_module,
        "_fresh_nonzero_uint256",
        lambda: nonce,
    )
    coordinator, journal, accounts, snapshot, request, _release = _coordinator(
        tmp_path
    )
    plan = coordinator.create_plan(
        run_id=snapshot["run_id"],
        requester_address=snapshot["requester_address"],
        request=request,
        now=NOW,
    )
    public = plan.to_public_dict()
    assert public["basis"]["royalty_settlement_nonce"] == str(nonce)
    assert public["royalty_settlement_nonce"] == str(nonce)

    submissions = []
    for account in accounts:
        challenge = coordinator.issue_owner_grant_challenge(
            plan_token=plan.plan_token,
            owner_address=account.address.lower(),
            now=NOW + 1,
        )
        assert f'"royalty_settlement_nonce":"{nonce}"' in challenge["message"]
        signature = Account.sign_message(
            encode_defunct(text=challenge["message"]), account.key
        ).signature.hex()
        submissions.append(
            {
                "challenge_token": challenge["challenge_token"],
                "signature": signature,
            }
        )
    authorized = coordinator.authorize(
        plan_token=plan.plan_token,
        requester_address=snapshot["requester_address"],
        grant_submissions=submissions,
        idempotency_key="collaboration-large-uint256-nonce",
        now=NOW + 2,
    )
    reservation = authorized["royalty_reservation"]
    assert reservation["request"]["settlement_nonce"] == str(nonce)
    assert isinstance(reservation["request"]["refund_after"], str)
    request_tuple = abi_decode(
        [
            "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,"
            "bytes32,bytes32,address,uint256,bytes32,uint64)"
        ],
        bytes.fromhex(reservation["transaction"]["calldata"][10:]),
    )[0]
    assert request_tuple[1] == nonce
    assert request_tuple[12] == int(reservation["request"]["refund_after"])

    persisted = journal.path.read_text("utf-8")
    assert f'"royalty_settlement_nonce":"{nonce}"' in persisted
    execution_id = authorized["execution"]["execution_id"]
    reopened = CollaborationExecutionJournal(
        journal.path,
        integrity_key=b"k" * 32,
    )
    replay = reopened.public_get(execution_id)
    assert replay["royalty"]["settlement_nonce"] == str(nonce)
    assert replay["royalty"]["funding_reservation"]["reservation_id"] == (
        reservation["reservation_id"]
    )


def _finalized_receipt(
    intent: CollaborationExecutionIntent,
    *,
    observed_at: int = NOW,
    job_state: str = "authorized",
) -> FinalizedObservationReceipt:
    block_hash = _bytes32("e")
    block_timestamp = observed_at - 2
    observation = FinalizedComputeVaultObservation.create(
        chain_id=intent.chain_id,
        vault_address=intent.compute_vault_address,
        vault_runtime_code_hash=intent.compute_vault_runtime_code_hash,
        block_number=20_000_000,
        block_hash=block_hash,
        block_timestamp=block_timestamp,
        source_record_commitment=_sha("e"),
        source_authentication_receipt=_sha("f"),
        finality_model=intent.compute_finality_model,
        reported_finalized=True,
        job_state=job_state,
        compute_project_id=intent.compute_project_id,
        compute_job_id=intent.compute_job_id,
        sponsor_address=intent.sponsor_address,
        compute_user_address=intent.compute_user_address,
        asset=intent.asset,
        authorization_nonce=intent.authorization_nonce,
        max_compute_asset_debit=intent.max_compute_asset_debit,
        authorization_expiry=intent.authorization_expiry,
        compute_workload_commitment=intent.compute_workload_commitment,
        compute_manifest_commitment=intent.compute_manifest_commitment,
        compute_dispatch_intent_commitment=(
            intent.compute_dispatch_intent_commitment
        ),
        observed_at=observed_at,
    )
    return FinalizedObservationReceipt(
        observation=observation,
        block_timestamp=block_timestamp,
        source_record_commitment=observation.source_record_commitment,
        authentication_receipt=observation.source_authentication_receipt,
    )


def _royalty_reader(
    *,
    intent: CollaborationExecutionIntent,
    grants: tuple[OwnerExecutionGrant, ...],
    release: RoyaltySettlementReleaseBinding,
    active: bool = True,
    consumed: bool = False,
    refunded: bool = False,
    refund_after: int | None = None,
    deposited_amount: int | None = None,
    pending_nonce: int = 0,
    owner: str | None = None,
    pending_owner: str = ZERO_ADDRESS,
    settlement_processed: bool = False,
    nonce_processed: bool = False,
):
    grant_set = execution_grant_set_commitment(
        intent.to_basis(), grants, now=max(item.granted_at for item in grants) + 1
    )
    expected_reservation = RoyaltyFundingReservation.derive(
        intent,
        execution_grant_set_commitment=grant_set,
    )
    rpc = FinalizedComputeVaultReader(
        rpc_url="http://127.0.0.1:8545",
        vault_address=intent.compute_vault_address,
        runtime_code_hash=intent.compute_vault_runtime_code_hash,
        receipt_key=b"v" * 32,
        max_block_age_seconds=120,
        max_future_block_skew_seconds=5,
        allow_plain_http_for_test=True,
    )
    calls: list[tuple[str, list[Any]]] = []
    distributor = release.distributor_address
    anchor = release.execution_policy_anchor_address
    reservation_selector = _selector(
        "collaborationFundingReservation(bytes32)"
    )
    settlement_state_selector = _selector(
        "fundingReservationSettlementState(bytes32)"
    )
    reservation_state_selector = _selector(
        "fundingReservationState(bytes32)"
    )
    scalar_values: dict[tuple[str, bytes], bytes] = {
        (distributor, _selector("paused()")): _word_bool(False),
        (distributor, _selector("owner()")): _word_address(
            release.owner_address if owner is None else owner
        ),
        (distributor, _selector("pendingOwner()")): _word_address(
            pending_owner
        ),
        (distributor, _selector("settlementVerifier()")): _word_address(
            release.settlement_verifier_address
        ),
        (distributor, _selector("qvlVerifier()")): _word_address(
            release.royalty_qvl_verifier_address
        ),
        (distributor, _selector("executionPolicyAnchor()")): _word_address(
            anchor
        ),
        (
            distributor,
            _selector("anchorWriterReleaseCommitment()"),
        ): _word_bytes32(release.anchor_writer_release_commitment),
        (distributor, _selector("releasePolicyCommitment()")): _word_bytes32(
            release.release_policy_commitment
        ),
        (distributor, _selector("authorityNonce()")): _word_uint(
            release.authority_nonce
        ),
        (distributor, _selector("pendingSettlementVerifier()")): _word_address(
            ZERO_ADDRESS
        ),
        (distributor, _selector("pendingQvlVerifier()")): _word_address(
            ZERO_ADDRESS
        ),
        (
            distributor,
            _selector("pendingExecutionPolicyAnchor()"),
        ): _word_address(ZERO_ADDRESS),
        (
            distributor,
            _selector("pendingAnchorWriterReleaseCommitment()"),
        ): _word_bytes32(_bytes32("0")),
        (
            distributor,
            _selector("pendingReleasePolicyCommitment()"),
        ): _word_bytes32(_bytes32("0")),
        (distributor, _selector("pendingAuthorityNonce()")): _word_uint(
            pending_nonce
        ),
        (
            distributor,
            _selector("pendingAuthorityActivatesAt()"),
        ): _word_uint(0),
        (
            distributor,
            _selector("pendingAuthorityRevocation()"),
        ): _word_bool(False),
        (anchor, _selector("writer()")): _word_address(ANCHOR_WRITER),
        (anchor, _selector("writerReleaseCommitment()")): _word_bytes32(
            release.anchor_writer_release_commitment
        ),
        (anchor, _selector("writerRotationsFrozen()")): _word_bool(True),
        (anchor, _selector("paused()")): _word_bool(False),
    }
    reservation = b"".join(
        (
            _word_bool(active),
            _word_bool(consumed),
            _word_address(intent.sponsor_address),
            _word_address(intent.royalty_asset),
            _word_uint(intent.royalty_total),
            _word_bytes32(intent.royalty_owner_amounts_hash),
            _word_bytes32(release.release_policy_commitment),
            bytes.fromhex(intent.commitment.removeprefix("sha256:")),
            _word_uint(
                refund_after
                if refund_after is not None
                else intent.authorization_expiry
                + intent.royalty_reservation_safety_seconds
            ),
            _word_uint(
                deposited_amount
                if deposited_amount is not None
                else intent.royalty_total
            ),
        )
    )
    settlement_state = b"".join(
        (
            _word_bool(consumed),
            _word_bool(settlement_processed),
            _word_bool(nonce_processed),
            _word_bytes32(intent.royalty_settlement_id),
            _word_uint(intent.royalty_settlement_nonce),
            _word_address(intent.royalty_asset),
            _word_uint(intent.royalty_total),
            _word_bytes32(intent.royalty_owner_amounts_hash),
        )
    )
    reservation_storage_state = b"".join(
        (
            _word_bytes32(expected_reservation.reservation_id),
            _word_bytes32(intent.royalty_settlement_id),
            _word_uint(intent.royalty_settlement_nonce),
            _word_bytes32(release.release_policy_commitment),
            _word_bytes32(intent.royalty_owner_amounts_hash),
            bytes.fromhex(intent.commitment.removeprefix("sha256:")),
            _word_address(intent.sponsor_address),
            _word_address(intent.royalty_asset),
            _word_uint(intent.royalty_total),
            _word_uint(
                refund_after
                if refund_after is not None
                else intent.authorization_expiry
                + intent.royalty_reservation_safety_seconds
            ),
            _word_uint(3 if refunded else 2 if consumed else 1),
            _word_bool(active),
        )
    )

    def fake_rpc(method: str, params: list[Any]):
        calls.append((method, copy.deepcopy(params)))
        if method == "eth_getCode":
            return "0x6000"
        if method != "eth_call":
            raise AssertionError(f"unexpected RPC method: {method}")
        request = params[0]
        address = request["to"]
        calldata = bytes.fromhex(request["data"][2:])
        if address == distributor and calldata[:4] == reservation_selector:
            assert calldata[4:] == bytes.fromhex(
                expected_reservation.reservation_id[2:]
            )
            return "0x" + reservation.hex()
        if address == distributor and calldata[:4] == settlement_state_selector:
            assert calldata[4:] == bytes.fromhex(
                expected_reservation.reservation_id[2:]
            )
            return "0x" + settlement_state.hex()
        if address == distributor and calldata[:4] == reservation_state_selector:
            assert calldata[4:] == bytes.fromhex(
                expected_reservation.reservation_id[2:]
            )
            return "0x" + reservation_storage_state.hex()
        return "0x" + scalar_values[(address, calldata[:4])].hex()

    rpc._rpc = fake_rpc  # type: ignore[method-assign]
    return FinalizedRoyaltyAuthorityReader(
        rpc,
        receipt_key=b"r" * 32,
    ), calls


def test_finalized_royalty_reader_requires_exact_deposited_reservation(tmp_path):
    coordinator, journal, intent, result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    binding = royalty_release_binding_from_settings(coordinator.settings)
    assert royalty_release_binding_commitment(binding) == (
        intent.royalty_release_binding_commitment
    )
    reader, calls = _royalty_reader(
        intent=intent, grants=grants, release=release
    )
    claim_time = NOW + 3
    finalized = _finalized_receipt(intent, observed_at=claim_time)
    observation = reader.observe(
        binding,
        intent,
        grants,
        finalized=finalized,
        observed_at=claim_time,
    )
    assert observation.reservation_active is True
    assert observation.reservation_consumed is False
    assert observation.reservation_id == result["royalty_reservation"][
        "reservation_id"
    ]
    assert observation.reservation_execution_intent_commitment == intent.commitment
    assert observation.reservation_deposited_amount == intent.royalty_total
    assert observation.source_record_commitment.startswith("sha256:")
    assert observation.source_authentication_receipt.startswith("sha256:")
    for method, params in calls:
        if method in {"eth_call", "eth_getCode"}:
            assert params[-1] == {
                "blockHash": finalized.observation.block_hash,
                "requireCanonical": True,
            }
    called_methods = [method for method, _params in calls]
    assert "eth_getBalance" not in called_methods
    called_data = [
        params[0].get("data", "")
        for method, params in calls
        if method == "eth_call"
    ]
    assert all(
        not value.startswith("0x" + _selector("balanceOf(address)").hex())
        and not value.startswith(
            "0x" + _selector("allowance(address,address)").hex()
        )
        for value in called_data
    )


@pytest.mark.parametrize(
    "reader_changes,match",
    [
        ({"active": False}, "usable"),
        ({"consumed": True}, "usable"),
        ({"deposited_amount": 1_999}, "reservation changed"),
        (
            {"refund_after": NOW + 3_600 + 899},
            "reservation changed",
        ),
        ({"pending_nonce": 8}, "usable"),
        ({"owner": ANCHOR_WRITER}, "active release drifted"),
        ({"pending_owner": ANCHOR_WRITER}, "usable"),
    ],
)
def test_balance_or_allowance_can_never_replace_finalized_reservation(
    tmp_path, reader_changes, match
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    reader, calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
        **reader_changes,
    )
    with pytest.raises(CollaborationExecutionAuthorityInvalidated, match=match):
        claim_time = NOW + 3
        reader.observe(
            royalty_release_binding_from_settings(coordinator.settings),
            intent,
            grants,
            finalized=_finalized_receipt(intent, observed_at=claim_time),
            observed_at=claim_time,
        )
    assert all(method != "eth_getBalance" for method, _params in calls)


def test_settlement_precondition_checks_both_replay_markers_at_same_finalized_head(
    tmp_path,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    reader, calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
    )
    observed_at = NOW + 3
    finalized = _finalized_receipt(intent, observed_at=observed_at)
    result = reader.settlement_precondition(
        royalty_release_binding_from_settings(coordinator.settings),
        intent,
        grants,
        finalized=finalized,
        observed_at=observed_at,
    )
    assert result["settlement_state"] == {
        "consumed": False,
        "settlement_processed": False,
        "nonce_processed": False,
        "settlement_id": intent.royalty_settlement_id,
        "settlement_nonce": intent.royalty_settlement_nonce,
        "asset": intent.royalty_asset,
        "total": intent.royalty_total,
        "owner_amounts_hash": intent.royalty_owner_amounts_hash,
    }
    state_calls = [
        params
        for method, params in calls
        if method == "eth_call"
        and params[0]["data"].startswith(
            "0x"
            + _selector(
                "fundingReservationSettlementState(bytes32)"
            ).hex()
        )
    ]
    assert len(state_calls) == 1
    assert state_calls[0][1] == {
        "blockHash": finalized.observation.block_hash,
        "requireCanonical": True,
    }


def test_finalized_settlement_reconciliation_requires_consumed_reservation_and_markers(
    tmp_path,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    binding = royalty_release_binding_from_settings(coordinator.settings)
    historical_reader, _historical_calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
    )
    historical_time = NOW + 3
    historical = historical_reader.observe(
        binding,
        intent,
        grants,
        finalized=_finalized_receipt(
            intent,
            observed_at=historical_time,
        ),
        observed_at=historical_time,
    )
    reader, _calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
        active=False,
        consumed=True,
        deposited_amount=0,
        settlement_processed=True,
        nonce_processed=True,
    )
    observed_at = NOW + 600
    finalized = _finalized_receipt(
        intent,
        observed_at=observed_at,
        job_state="settled",
    )
    reader.rpc_reader.observe = (  # type: ignore[method-assign]
        lambda observed_intent, *, observed_at: finalized
    )
    reconciliation = reader.reconcile_settlement(
        intent,
        grants,
        historical,
        observed_at=observed_at,
    )
    proof = reconciliation["finalized_settlement"]
    finalized_block_timestamp = reconciliation["block_timestamp"]
    assert reconciliation["state"] == "settled"
    assert proof == {
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "block_number": finalized.observation.block_number,
        "block_hash": finalized.observation.block_hash,
        "block_timestamp": finalized.block_timestamp,
        "reservation_active": False,
        "reservation_consumed": True,
        "settlement_processed": True,
        "settlement_nonce_processed": True,
        "source_commitment": proof["source_commitment"],
    }
    assert finalized_block_timestamp == finalized.block_timestamp
    assert proof["source_commitment"].startswith("sha256:")


def test_settlement_reconciliation_uses_historical_release_after_authority_rotation(
    tmp_path,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    binding = royalty_release_binding_from_settings(coordinator.settings)
    historical_reader, _ = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
    )
    historical_time = NOW + 3
    historical = historical_reader.observe(
        binding,
        intent,
        grants,
        finalized=_finalized_receipt(
            intent,
            observed_at=historical_time,
        ),
        observed_at=historical_time,
    )
    reader, calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
        active=False,
        consumed=True,
        deposited_amount=0,
        settlement_processed=True,
        nonce_processed=True,
        # These deliberately disagree with the original release. Finalized
        # settlement is permanent and must remain recognizable after a later
        # owner/authority rotation.
        owner=ANCHOR_WRITER,
        pending_nonce=release.authority_nonce + 1,
    )
    observed_at = NOW + 600
    finalized = _finalized_receipt(
        intent,
        observed_at=observed_at,
        job_state="settled",
    )
    reader.rpc_reader.observe = (  # type: ignore[method-assign]
        lambda observed_intent, *, observed_at: finalized
    )
    reconciliation = reader.reconcile_settlement(
        intent,
        grants,
        historical,
        observed_at=observed_at,
    )
    assert reconciliation["state"] == "settled"
    called_selectors = {
        params[0]["data"][:10]
        for method, params in calls
        if method == "eth_call"
    }
    current_authority_selectors = {
        "0x" + _selector(signature).hex()
        for signature in (
            "paused()",
            "owner()",
            "pendingOwner()",
            "settlementVerifier()",
            "qvlVerifier()",
            "executionPolicyAnchor()",
            "authorityNonce()",
            "pendingAuthorityNonce()",
        )
    }
    assert called_selectors.isdisjoint(current_authority_selectors)


def test_settlement_reconciliation_rejects_advisory_hash_without_nonce_marker(
    tmp_path,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    binding = royalty_release_binding_from_settings(coordinator.settings)
    historical_reader, _historical_calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
    )
    historical_time = NOW + 3
    historical = historical_reader.observe(
        binding,
        intent,
        grants,
        finalized=_finalized_receipt(
            intent,
            observed_at=historical_time,
        ),
        observed_at=historical_time,
    )
    reader, _calls = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
        active=False,
        consumed=True,
        deposited_amount=0,
        settlement_processed=True,
        nonce_processed=False,
    )
    observed_at = NOW + 600
    finalized = _finalized_receipt(
        intent,
        observed_at=observed_at,
        job_state="settled",
    )
    reader.rpc_reader.observe = (  # type: ignore[method-assign]
        lambda observed_intent, *, observed_at: finalized
    )
    with pytest.raises(
        CollaborationExecutionAuthorityInvalidated,
        match="does not prove exact",
    ):
        reader.reconcile_settlement(
            intent,
            grants,
            historical,
            observed_at=observed_at,
        )


@pytest.mark.parametrize(
    "reader_kwargs,observed_at,expected_state",
    [
        ({}, NOW + 600, "pending"),
        (
            {"active": False, "deposited_amount": 2_000},
            NOW + 4_600,
            "expired_unconsumed",
        ),
        (
            {
                "active": False,
                "refunded": True,
                "deposited_amount": 0,
            },
            NOW + 4_600,
            "refunded",
        ),
    ],
)
def test_reconciliation_distinguishes_pending_expired_and_refunded_reservations(
    tmp_path,
    reader_kwargs,
    observed_at,
    expected_state,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    grants = _stored_grants(journal)
    binding = royalty_release_binding_from_settings(coordinator.settings)
    historical_reader, _ = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
    )
    historical_time = NOW + 3
    historical = historical_reader.observe(
        binding,
        intent,
        grants,
        finalized=_finalized_receipt(
            intent,
            observed_at=historical_time,
        ),
        observed_at=historical_time,
    )
    reader, _ = _royalty_reader(
        intent=intent,
        grants=grants,
        release=release,
        **reader_kwargs,
    )
    finalized = _finalized_receipt(
        intent,
        observed_at=observed_at,
        job_state="settled",
    )
    reader.rpc_reader.observe = (  # type: ignore[method-assign]
        lambda observed_intent, *, observed_at: finalized
    )
    reconciliation = reader.reconcile_settlement(
        intent,
        grants,
        historical,
        observed_at=observed_at,
    )
    assert reconciliation["state"] == expected_state
    assert reconciliation["finalized_settlement"] is None
    assert reconciliation["block_timestamp"] == finalized.block_timestamp
    if expected_state in {"expired_unconsumed", "refunded"}:
        terminal = reconciliation["terminal_evidence"]
        assert terminal["outcome"] == (
            "reservation_refunded"
            if expected_state == "refunded"
            else "reservation_expired"
        )
        assert terminal["funding_reservation_id"] == historical.reservation_id
        assert terminal["block_number"] == finalized.observation.block_number
        assert terminal["block_hash"] == finalized.observation.block_hash
        assert terminal["block_timestamp"] == finalized.block_timestamp
        assert terminal["reservation_storage_status"] == (
            "refunded" if expected_state == "refunded" else "active"
        )
        assert terminal["source_commitment"].startswith("sha256:")
    else:
        assert reconciliation["terminal_evidence"] is None


def test_worker_calls_only_exact_compute_admission_and_reconciles_receipt(
    tmp_path,
):
    coordinator, journal, intent, _result, _request, release = _authorize(
        tmp_path
    )
    claim_time = NOW + 3
    finalized = _finalized_receipt(intent, observed_at=claim_time)
    royalty_reader, _calls = _royalty_reader(
        intent=intent,
        grants=_stored_grants(journal),
        release=release,
    )

    class VaultReader:
        def observe(self, observed_intent, *, observed_at):
            assert observed_intent.commitment == intent.commitment
            assert observed_at == claim_time
            return finalized

    class Admission:
        def __init__(self):
            self.calls = []

        def enqueue_collaboration_one_shot(
            self,
            compute_intent,
            *,
            idempotency_key,
            created_at,
        ):
            self.calls.append(
                (compute_intent, idempotency_key, created_at)
            )
            return {
                "provider_dispatch_may_have_occurred": False,
                "provider_authoritative": False,
            }

    class ComputeReader:
        def read(self, handoff, *, observed_at):
            projection = ComputeJournalProjection.create(
                handoff=handoff,
                source_sequence=1,
                source_record_commitment=_sha("1"),
                source_journal_mac_commitment=_sha("2"),
                source_authentication_receipt=_sha("3"),
                compute_stage="workload_claim_pending",
                provider_dispatch_may_have_occurred=False,
                automatic_provider_redispatch=False,
                bounded_result=None,
                observed_at=observed_at,
            )
            return AuthenticatedComputeProjection(
                projection=projection,
                source_sequence=projection.source_sequence,
                source_record_commitment=(
                    projection.source_record_commitment
                ),
                source_journal_mac_commitment=(
                    projection.source_journal_mac_commitment
                ),
                authentication_receipt=(
                    projection.source_authentication_receipt
                ),
            )

    admission = Admission()
    worker = CollaborationExecutionWorkerService(
        coordinator=coordinator,
        journal=journal,
        vault_reader=VaultReader(),
        royalty_reader=royalty_reader,
        admission=admission,
        compute_reader=ComputeReader(),
    )
    cycle = worker.run_once(now=claim_time)
    assert cycle["claimed_execution_id"] == intent.execution_id
    assert cycle["provider_call_performed_by_collaboration"] is False
    assert cycle["automatic_provider_redispatch"] is False
    assert len(admission.calls) == 1
    compute_intent, idempotency_key, created_at = admission.calls[0]
    assert compute_intent.authorization_kind == "collaboration_one_shot"
    assert compute_intent.commitment == intent.compute_dispatch_intent_commitment
    assert idempotency_key.startswith("chandoff_")
    assert created_at == claim_time
    public = journal.public_get(intent.execution_id)
    assert public["compute_journal_projection"][
        "source_authentication_receipt"
    ] == _sha("3")
    assert public["compute_journal_projection"][
        "automatic_provider_redispatch"
    ] is False
    assert public["claim_royalty_observation"]["reservation_active"] is True

    second = worker.run_once(now=claim_time + 1)
    assert second["claimed_execution_id"] is None
    assert len(second["actions"]) == 1
    assert second["actions"][0]["action"] == "compute_polled_and_reconciled"
    assert second["actions"][0]["compute_admission_invoked"] is False
    assert second["actions"][0]["automatic_provider_redispatch"] is False
    assert len(admission.calls) == 1
