from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest

from tinker_delegate.collaboration_execution import (
    BASE_SEPOLIA_CHAIN_ID,
    BoundedExecutionResult,
    ClaimAuthoritySnapshot,
    ComputeHandoff,
    ComputeJournalProjection,
    CollaborationExecutionAuthorityError,
    CollaborationExecutionAuthorityUnavailable,
    CollaborationExecutionBasis,
    CollaborationExecutionConflict,
    CollaborationExecutionError,
    CollaborationExecutionIntent,
    CollaborationExecutionJournal,
    CollaborationExecutionJournalError,
    ExecutionState,
    FinalizedComputeVaultObservation,
    FinalizedRoyaltyAuthorityObservation,
    OwnerExecutionGrant,
    RoyaltyFundingReservation,
    execution_authorization_commitment,
    execution_grant_set_commitment,
    royalty_funding_reservation_id,
    royalty_owner_amounts_hash,
)


CREATED_AT = 1_800_000_000
OWNER_A = "0x" + "11" * 20
OWNER_B = "0x" + "22" * 20
SPONSOR = "0x" + "33" * 20
ASSET = "0x" + "44" * 20
VAULT = "0x" + "55" * 20
COMPUTE_USER = "0x" + "66" * 20
ROYALTY_DISTRIBUTOR = "0x" + "77" * 20


def _sha(byte: str) -> str:
    return "sha256:" + byte * 64


def _bytes32(byte: str) -> str:
    return "0x" + byte * 64


def test_funding_reservation_id_matches_solidity_known_answer_vector():
    assert royalty_funding_reservation_id(
        chain_id=84_532,
        distributor_address="0x" + "55" * 20,
        sponsor_address="0x" + "66" * 20,
        settlement_id="0x" + "01" * 32,
        settlement_nonce=7,
        release_policy_commitment="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash="0x" + "08" * 32,
        asset="0x" + "77" * 20,
        total=123_456_789,
        execution_commitment="0x" + "09" * 32,
        refund_after=1_800_003_600,
    ) == "0xd0d62c115a12faf9651d4218dd1afb623b46248be0200645058fbd422d50f53f"


def _basis(**changes) -> CollaborationExecutionBasis:
    values = {
        "release_git_sha": "a" * 40,
        "release_verification_sha256": _sha("a"),
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "cvm_id": "cvm_collaboration_01",
        "compose_hash": _bytes32("a"),
        "room_id": "room_" + "ab" * 16,
        "room_commitment": _sha("b"),
        "room_generation": 7,
        "room_state_commitment": _sha("c"),
        "query_ref": _sha("d"),
        "query_proposal_commitment": _sha("e"),
        "prospective_query_grant_set_commitment": _sha("f"),
        "joint_consent_snapshot_commitment": _sha("1"),
        "allocation_commitment": _sha("2"),
        "owner_addresses": [OWNER_A, OWNER_B],
        "compute_project_id": _bytes32("3"),
        "compute_job_id": _bytes32("4"),
        "compute_workload_id": "wrk_" + "56" * 16,
        "compute_workload_commitment": _bytes32("5"),
        "compute_manifest_commitment": _bytes32("6"),
        "compute_rate_policy_commitment": _bytes32("7"),
        "compute_workload_schema": "dnai.compute.workload.inference.v1",
        "compute_workload_source_kind": "wallet",
        "compute_workload_execution_binding_commitment": _sha("6"),
        "compute_workload_recipient_release_commitment": _sha("7"),
        "compute_vault_address": VAULT,
        "compute_vault_runtime_code_hash": _bytes32("8"),
        "compute_finality_model": "single_rpc_reported_finalized",
        "compute_user_address": COMPUTE_USER,
        "operation": "inference",
        "model": "qwen3_8b",
        "recipe": "qwen3_8b_bounded",
        "result_policy": "bounded_summary_receipt",
        "max_prefill_tokens": 4_096,
        "max_sample_tokens": 512,
        "max_train_tokens": 0,
        "sponsor_address": SPONSOR,
        "asset": ASSET,
        "max_total_asset_debit": 10_000,
        "max_compute_asset_debit": 7_000,
        "authorization_nonce": 19,
        "authorization_expiry": CREATED_AT + 3_600,
        "royalty_asset": ASSET,
        "royalty_total": 2_000,
        "royalty_owner_amounts_hash": royalty_owner_amounts_hash(
            owner_amounts={OWNER_A: 1_200, OWNER_B: 800},
            expected_owners=(OWNER_A, OWNER_B),
            expected_total=2_000,
        ),
        "royalty_distributor_address": ROYALTY_DISTRIBUTOR,
        "royalty_release_policy_commitment": _bytes32("c"),
        "royalty_release_binding_commitment": _sha("f"),
        "royalty_settlement_id": _bytes32("8"),
        "royalty_settlement_nonce": 23,
        "royalty_reservation_safety_seconds": 900,
        "intent_created_at": CREATED_AT,
    }
    values.update(changes)
    return CollaborationExecutionBasis.create(**values)


def _intent(**changes) -> CollaborationExecutionIntent:
    basis = _basis(**changes)
    return CollaborationExecutionIntent.finalize(
        basis,
        _grants(basis),
        now=CREATED_AT + 20,
    )


def _replace_intent(
    intent: CollaborationExecutionIntent, **changes
) -> CollaborationExecutionIntent:
    final_fields = {
        field: changes.pop(field)
        for field in tuple(changes)
        if field
        in {
            "compute_authorization_kind",
            "compute_authorization_context_commitment",
            "compute_dispatch_intent_commitment",
        }
    }
    values = intent.to_basis().to_dict()
    values.pop("schema")
    values["royalty_settlement_nonce"] = int(
        values["royalty_settlement_nonce"]
    )
    values.update(changes)
    basis = CollaborationExecutionBasis.create(**values)
    finalized = CollaborationExecutionIntent.finalize(
        basis,
        _grants(basis),
        now=CREATED_AT + 20,
    )
    if not final_fields:
        return finalized
    return CollaborationExecutionIntent.create(
        basis=basis,
        compute_authorization_kind=final_fields.get(
            "compute_authorization_kind",
            finalized.compute_authorization_kind,
        ),
        compute_authorization_context_commitment=final_fields.get(
            "compute_authorization_context_commitment",
            finalized.compute_authorization_context_commitment,
        ),
        compute_dispatch_intent_commitment=final_fields.get(
            "compute_dispatch_intent_commitment",
            finalized.compute_dispatch_intent_commitment,
        ),
    )


def _grant(
    intent: CollaborationExecutionBasis,
    owner: str,
    index: int,
    **changes,
) -> OwnerExecutionGrant:
    values = {
        "grant_id": f"xgrant_{index:032x}",
        "owner_address": owner,
        "basis_commitment": (
            intent.to_basis().commitment
            if isinstance(intent, CollaborationExecutionIntent)
            else intent.commitment
        ),
        "prospective_query_grant_authorization_hash": _sha(str(index)),
        "execution_authorization_hash": _sha(hex(index + 8)[2:]),
        "execution_grant_generation": index,
        "granted_at": CREATED_AT + 10,
        "expires_at": CREATED_AT + 1_800,
    }
    values.update(changes)
    return OwnerExecutionGrant.create(**values)


def _grants(intent: CollaborationExecutionBasis) -> tuple[OwnerExecutionGrant, ...]:
    return (
        _grant(intent, OWNER_A, 1),
        _grant(intent, OWNER_B, 2),
    )


def _independent_intent(
    original: CollaborationExecutionIntent, **changes
) -> CollaborationExecutionIntent:
    final_fields = {
        field: changes.pop(field)
        for field in tuple(changes)
        if field
        in {
            "compute_authorization_kind",
            "compute_authorization_context_commitment",
            "compute_dispatch_intent_commitment",
        }
    }
    values = {
        "release_git_sha": "b" * 40,
        "release_verification_sha256": _sha("b"),
        "room_id": "room_" + "cd" * 16,
        "room_commitment": _sha("3"),
        "room_generation": 8,
        "room_state_commitment": _sha("4"),
        "query_ref": _sha("5"),
        "query_proposal_commitment": _sha("6"),
        "prospective_query_grant_set_commitment": _sha("7"),
        "joint_consent_snapshot_commitment": _sha("8"),
        "allocation_commitment": _sha("9"),
        "compute_project_id": _bytes32("a"),
        "compute_job_id": _bytes32("b"),
        "compute_workload_id": "wrk_" + "cd" * 16,
        "compute_workload_commitment": _bytes32("c"),
        "compute_manifest_commitment": _bytes32("d"),
        "compute_rate_policy_commitment": _bytes32("e"),
        "compute_workload_execution_binding_commitment": _sha("c"),
        "compute_workload_recipient_release_commitment": _sha("d"),
        "authorization_nonce": 20,
        "royalty_settlement_id": _bytes32("e"),
        "royalty_settlement_nonce": 24,
        "royalty_release_binding_commitment": _sha("d"),
        "royalty_owner_amounts_hash": royalty_owner_amounts_hash(
            owner_amounts={OWNER_A: 1_100, OWNER_B: 900},
            expected_owners=(OWNER_A, OWNER_B),
            expected_total=2_000,
        ),
    }
    values.update(changes)
    basis_values = original.to_basis().to_dict()
    basis_values.pop("schema")
    basis_values.update(values)
    basis = CollaborationExecutionBasis.create(**basis_values)
    finalized = CollaborationExecutionIntent.finalize(
        basis,
        _independent_grants(basis),
        now=CREATED_AT + 20,
    )
    if not final_fields:
        return finalized
    return CollaborationExecutionIntent.create(
        basis=basis,
        compute_authorization_kind=final_fields.get(
            "compute_authorization_kind", finalized.compute_authorization_kind
        ),
        compute_authorization_context_commitment=final_fields.get(
            "compute_authorization_context_commitment",
            finalized.compute_authorization_context_commitment,
        ),
        compute_dispatch_intent_commitment=final_fields.get(
            "compute_dispatch_intent_commitment",
            finalized.compute_dispatch_intent_commitment,
        ),
    )


def _independent_grants(
    intent: CollaborationExecutionBasis,
) -> tuple[OwnerExecutionGrant, ...]:
    return (
        _grant(intent, OWNER_A, 3),
        _grant(intent, OWNER_B, 4),
    )


def _result(
    intent: CollaborationExecutionIntent,
    authorization_commitment: str,
    *,
    outcome: str = "succeeded",
    result_policy: str = "bounded_summary_receipt",
    actual_compute_asset_debit: int | None = None,
) -> BoundedExecutionResult:
    return BoundedExecutionResult.create(
        execution_id=intent.execution_id,
        intent_commitment=intent.commitment,
        authorization_commitment=authorization_commitment,
        outcome=outcome,
        result_class=(
            "completed_within_authorized_caps"
            if outcome == "succeeded"
            else "provider_failed_without_raw_detail"
        ),
        result_policy=result_policy,
        result_commitment=_sha("9"),
        usage_commitment=_sha("a"),
        actual_compute_asset_debit=(
            actual_compute_asset_debit
            if actual_compute_asset_debit is not None
            else 900 if outcome == "succeeded" else 0
        ),
        billable_compute_units=90 if outcome == "succeeded" else 0,
        score_band="not_released",
    )


def _vault_observation(
    intent: CollaborationExecutionIntent,
    observed_at: int,
    **changes,
) -> FinalizedComputeVaultObservation:
    values = {
        "chain_id": intent.chain_id,
        "vault_address": intent.compute_vault_address,
        "vault_runtime_code_hash": intent.compute_vault_runtime_code_hash,
        "block_number": 20_000_000,
        "block_hash": _bytes32("9"),
        "block_timestamp": observed_at - 2,
        "source_record_commitment": _sha("4"),
        "source_authentication_receipt": _sha("5"),
        "finality_model": intent.compute_finality_model,
        "reported_finalized": True,
        "job_state": "authorized",
        "compute_project_id": intent.compute_project_id,
        "compute_job_id": intent.compute_job_id,
        "sponsor_address": intent.sponsor_address,
        "compute_user_address": intent.compute_user_address,
        "asset": intent.asset,
        "authorization_nonce": intent.authorization_nonce,
        "max_compute_asset_debit": intent.max_compute_asset_debit,
        "authorization_expiry": intent.authorization_expiry,
        "compute_workload_commitment": intent.compute_workload_commitment,
        "compute_manifest_commitment": intent.compute_manifest_commitment,
        "compute_dispatch_intent_commitment": (
            intent.compute_dispatch_intent_commitment
        ),
        "observed_at": observed_at,
    }
    values.update(changes)
    return FinalizedComputeVaultObservation.create(**values)


def _royalty_observation(
    intent: CollaborationExecutionIntent,
    observed_at: int,
    grants: tuple[OwnerExecutionGrant, ...] | None = None,
    **changes,
) -> FinalizedRoyaltyAuthorityObservation:
    candidate_grants = _grants(intent.to_basis()) if grants is None else grants
    try:
        grant_set = execution_grant_set_commitment(
            intent.to_basis(),
            candidate_grants,
            now=observed_at,
        )
    except CollaborationExecutionAuthorityError:
        grant_set = execution_grant_set_commitment(
            intent.to_basis(),
            _grants(intent.to_basis()),
            now=observed_at,
        )
    reservation = RoyaltyFundingReservation.derive(
        intent,
        execution_grant_set_commitment=grant_set,
    )
    values = {
        "chain_id": intent.chain_id,
        "block_number": 20_000_000,
        "block_hash": _bytes32("9"),
        "block_timestamp": observed_at - 2,
        "distributor_address": intent.royalty_distributor_address,
        "distributor_runtime_code_hash": _bytes32("b"),
        "owner_address": "0x" + "cc" * 20,
        "pending_owner_address": "0x" + "00" * 20,
        "release_binding_commitment": intent.royalty_release_binding_commitment,
        "release_policy_commitment": intent.royalty_release_policy_commitment,
        "authority_nonce": 3,
        "settlement_verifier_address": "0x" + "88" * 20,
        "qvl_verifier_address": "0x" + "99" * 20,
        "execution_policy_anchor_address": "0x" + "aa" * 20,
        "anchor_writer_address": "0x" + "bb" * 20,
        "anchor_writer_release_commitment": _bytes32("d"),
        "distributor_paused": False,
        "pending_authority_empty": True,
        "anchor_paused": False,
        "anchor_writer_rotations_frozen": True,
        "reservation_id": reservation.reservation_id,
        "reservation_active": True,
        "reservation_consumed": False,
        "reservation_sponsor_address": intent.sponsor_address,
        "reservation_asset": intent.royalty_asset,
        "reservation_total": intent.royalty_total,
        "reservation_owner_amounts_hash": intent.royalty_owner_amounts_hash,
        "reservation_release_policy_commitment": (
            reservation.release_policy_commitment
        ),
        "reservation_execution_intent_commitment": intent.commitment,
        "reservation_refund_after": reservation.refund_after,
        "reservation_deposited_amount": intent.royalty_total,
        "source_record_commitment": _sha("6"),
        "source_authentication_receipt": _sha("7"),
        "observed_at": observed_at,
    }
    values.update(changes)
    return FinalizedRoyaltyAuthorityObservation.create(**values)


def _current_validator(
    current_intent: CollaborationExecutionIntent,
    current_grants: tuple[OwnerExecutionGrant, ...],
    *,
    available: bool = True,
    observation_changes: dict | None = None,
    royalty_observation_changes: dict | None = None,
):
    def validate(_intent, _grants, observed_at):
        if not available:
            raise CollaborationExecutionAuthorityUnavailable(
                "finalized Compute vault observation is unavailable"
            )
        return ClaimAuthoritySnapshot.create(
            current_intent=current_intent,
            current_execution_grants=current_grants,
            finalized_vault_observation=_vault_observation(
                current_intent,
                observed_at,
                **(observation_changes or {}),
            ),
            finalized_royalty_observation=_royalty_observation(
                current_intent,
                observed_at,
                current_grants,
                **(royalty_observation_changes or {}),
            ),
            observed_at=observed_at,
        )

    return validate


def _claim_and_prepare(
    journal: CollaborationExecutionJournal,
    intent: CollaborationExecutionIntent,
    grants: tuple[OwnerExecutionGrant, ...],
    *,
    claimed_at: int = CREATED_AT + 30,
    prepared_at: int = CREATED_AT + 31,
) -> ComputeHandoff:
    claimed = journal.claim_next(
        _current_validator(intent, grants),
        claimed_at=claimed_at,
    )
    assert claimed is not None
    return ComputeHandoff.from_dict(
        journal.prepare_compute_handoff(
            intent.execution_id,
            prepared_at=prepared_at,
        )
    )


def _projection(
    handoff: ComputeHandoff,
    *,
    stage: str,
    observed_at: int,
    result: BoundedExecutionResult | None = None,
    provider_dispatch_may_have_occurred: bool | None = None,
) -> ComputeJournalProjection:
    boundary_stages = {
        "provider_attempt_checkpointed",
        "provider_outcome_ambiguous",
        "usage_finalized",
        "workload_released",
        "metering_pending",
        "metering_decided",
        "settlement_prepared",
        "settlement_broadcast",
        "settled",
    }
    return ComputeJournalProjection.create(
        handoff=handoff,
        source_sequence=17,
        source_record_commitment=_sha("b"),
        source_journal_mac_commitment=_sha("c"),
        source_authentication_receipt=_sha("d"),
        compute_stage=stage,
        provider_dispatch_may_have_occurred=(
            stage in boundary_stages
            if provider_dispatch_may_have_occurred is None
            else provider_dispatch_may_have_occurred
        ),
        automatic_provider_redispatch=False,
        bounded_result=result,
        observed_at=observed_at,
    )


def _authorized_and_queued(
    tmp_path: Path,
) -> tuple[
    CollaborationExecutionJournal,
    CollaborationExecutionIntent,
    tuple[OwnerExecutionGrant, ...],
]:
    intent = _intent()
    grants = _grants(intent)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    public, created = journal.authorize(
        intent,
        grants,
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    assert created is True
    assert public["state"] == ExecutionState.AUTHORIZED.value
    journal.queue(intent.execution_id, queued_at=CREATED_AT + 21)
    return journal, intent, grants


def test_intent_is_canonical_and_binds_every_release_collaboration_compute_and_funding_field():
    intent = _intent()
    rebuilt = CollaborationExecutionIntent.from_dict(intent.to_dict())

    assert rebuilt == intent
    assert rebuilt.commitment == intent.commitment
    assert rebuilt.execution_id.startswith("exec_")
    intent_schema_fields = set(rebuilt.to_dict())
    assert intent_schema_fields == {
        "schema",
        "release_git_sha",
        "release_verification_sha256",
        "chain_id",
        "cvm_id",
        "compose_hash",
        "room_id",
        "room_commitment",
        "room_generation",
        "room_state_commitment",
        "query_ref",
        "query_proposal_commitment",
        "prospective_query_grant_set_commitment",
        "joint_consent_snapshot_commitment",
        "allocation_commitment",
        "owner_addresses",
        "compute_project_id",
        "compute_job_id",
        "compute_workload_id",
        "compute_workload_commitment",
        "compute_manifest_commitment",
        "compute_rate_policy_commitment",
        "compute_workload_schema",
        "compute_workload_source_kind",
        "compute_workload_execution_binding_commitment",
        "compute_workload_recipient_release_commitment",
        "compute_dispatch_intent_commitment",
        "compute_authorization_kind",
        "compute_authorization_context_commitment",
        "compute_vault_address",
        "compute_vault_runtime_code_hash",
        "compute_finality_model",
        "compute_user_address",
        "operation",
        "model",
        "recipe",
        "result_policy",
        "max_prefill_tokens",
        "max_sample_tokens",
        "max_train_tokens",
        "sponsor_address",
        "asset",
        "max_total_asset_debit",
        "max_compute_asset_debit",
        "authorization_nonce",
        "authorization_expiry",
        "royalty_asset",
        "royalty_total",
        "royalty_owner_amounts_hash",
        "royalty_distributor_address",
        "royalty_release_policy_commitment",
        "royalty_release_binding_commitment",
        "royalty_settlement_id",
        "royalty_settlement_nonce",
        "royalty_reservation_safety_seconds",
        "intent_created_at",
        "basis_commitment",
    }
    assert set(rebuilt.to_basis().to_dict()) == intent_schema_fields - {
        "basis_commitment",
        "compute_authorization_kind",
        "compute_authorization_context_commitment",
        "compute_dispatch_intent_commitment",
    }
    assert rebuilt.to_dict()["prospective_query_grant_set_commitment"] == _sha("f")
    assert rebuilt.to_dict()["compute_rate_policy_commitment"] == _bytes32("7")
    assert rebuilt.to_dict()["compute_dispatch_intent_commitment"].startswith("0x")
    assert rebuilt.to_dict()["compute_authorization_kind"] == (
        "collaboration_one_shot"
    )
    assert rebuilt.to_dict()["basis_commitment"] == rebuilt.to_basis().commitment
    assert rebuilt.to_dict()["compute_vault_address"] == VAULT
    assert rebuilt.to_dict()["max_total_asset_debit"] == 10_000
    assert rebuilt.to_dict()["max_compute_asset_debit"] == 7_000
    assert rebuilt.to_dict()["royalty_owner_amounts_hash"].startswith("0x")
    assert rebuilt.to_dict()["royalty_settlement_id"] == _bytes32("8")
    assert rebuilt.to_dict()["royalty_settlement_nonce"] == "23"
    assert rebuilt.to_dict()["royalty_reservation_safety_seconds"] == 900

    mutated = _replace_intent(intent, room_generation=8)
    assert mutated.commitment != intent.commitment
    assert _replace_intent(intent, release_git_sha="b" * 40).commitment != intent.commitment
    assert (
        _replace_intent(intent, max_total_asset_debit=10_001).commitment
        != intent.commitment
    )


@pytest.mark.parametrize(
    "invalid",
    [23, 23.0, True, "", "00", "023", "+23", "-23", "23.0", "2.3e1", " 23"],
)
def test_basis_rejects_noncanonical_public_settlement_nonce(invalid):
    serialized = _basis().to_dict()
    serialized["royalty_settlement_nonce"] = invalid
    with pytest.raises(CollaborationExecutionError, match="nonce"):
        CollaborationExecutionBasis.from_dict(serialized)


def test_non_circular_owner_grants_derive_exact_compute_v3_one_shot_handoff():
    basis = _basis()
    grants = _grants(basis)
    intent = CollaborationExecutionIntent.finalize(
        basis,
        grants,
        now=CREATED_AT + 20,
    )
    compute_intent = intent.validate_for_grants(
        grants,
        now=CREATED_AT + 20,
    )
    authorization = execution_authorization_commitment(
        intent,
        grants,
        now=CREATED_AT + 20,
    )
    handoff = ComputeHandoff.create(
        intent,
        authorization_commitment=authorization,
        planned_at=CREATED_AT + 20,
    )

    assert all(grant.basis_commitment == basis.commitment for grant in grants)
    assert intent.to_dict()["basis_commitment"] == basis.commitment
    assert compute_intent.authorization_kind == "collaboration_one_shot"
    assert compute_intent.authorization_context_commitment == (
        intent.compute_authorization_context_commitment
    )
    assert compute_intent.commitment == intent.compute_dispatch_intent_commitment
    assert compute_intent.project_id == basis.compute_project_id
    assert compute_intent.job_id == basis.compute_job_id
    assert compute_intent.max_asset_debit == basis.max_compute_asset_debit
    assert handoff.compute_dispatch_intent == compute_intent
    assert handoff.compute_dispatch_intent_commitment == compute_intent.commitment
    assert handoff.compute_authorization_kind == "collaboration_one_shot"
    assert ComputeHandoff.from_dict(handoff.to_dict()) == handoff
    assert handoff.handoff_id.startswith("chandoff_")
    assert handoff.to_dict()["provider_call_performed_by_collaboration"] is False
    serialized = json.dumps(handoff.to_dict(), sort_keys=True)
    for forbidden in (
        "raw_prompt",
        "raw_result",
        "provider_request_id",
        "provider_account_id",
        "wallet_signature",
    ):
        assert forbidden not in serialized


def test_handoff_validation_binds_every_embedded_compute_intent_field():
    intent = _intent()
    grants = _grants(intent)
    authorization = execution_authorization_commitment(
        intent,
        grants,
        now=CREATED_AT + 20,
    )
    handoff = ComputeHandoff.create(
        intent,
        authorization_commitment=authorization,
        planned_at=CREATED_AT + 20,
    )

    for field_name in handoff.compute_dispatch_intent.__dataclass_fields__:
        current = getattr(handoff.compute_dispatch_intent, field_name)
        if type(current) is int:
            replacement = current + 1
        elif current.startswith("sha256:"):
            replacement = _sha("f")
        elif current.startswith("0x") and len(current) == 42:
            replacement = "0x" + "77" * 20
        elif current.startswith("0x") and len(current) == 66:
            replacement = _bytes32("f")
        else:
            replacement = current + "_changed"
        mutated = replace(
            handoff,
            compute_dispatch_intent=replace(
                handoff.compute_dispatch_intent,
                **{field_name: replacement},
            ),
        )
        with pytest.raises(CollaborationExecutionConflict, match="exact"):
            mutated.validate_for(
                intent,
                authorization_commitment=authorization,
            )


@pytest.mark.parametrize(
    "changes",
    [
        {"chain_id": 8453},
        {"royalty_asset": "0x" + "55" * 20},
        {"royalty_total": 10_001},
        {"max_total_asset_debit": 8_999},
        {"max_compute_asset_debit": 8_001},
        {"recipe": "unreviewed_recipe"},
        {"authorization_expiry": CREATED_AT + 86_401},
        {"owner_addresses": [OWNER_B, OWNER_A]},
    ],
)
def test_intent_fails_closed_on_out_of_scope_or_noncanonical_authority(changes):
    with pytest.raises(CollaborationExecutionError):
        _intent(**changes)


def test_royalty_hash_matches_distributor_order_and_rejects_zero_or_unsorted_payouts():
    expected = royalty_owner_amounts_hash(
        owner_amounts={OWNER_A: 1_200, OWNER_B: 800},
        expected_owners=(OWNER_A, OWNER_B),
        expected_total=2_000,
    )
    assert expected == _intent().royalty_owner_amounts_hash
    assert expected == (
        "0x55fd55b3b72ef101323d9bc161f44774"
        "b4d45cc88612ac6d3cfc540155910bcc"
    )

    basis_fields = _basis().to_dict()
    basis_fields.pop("schema")
    basis_fields.pop("royalty_owner_amounts_hash")
    basis_fields["royalty_settlement_nonce"] = int(
        basis_fields["royalty_settlement_nonce"]
    )
    validated_basis = CollaborationExecutionBasis.create_with_royalty_owner_amounts(
        royalty_owner_amounts={OWNER_A: 1_200, OWNER_B: 800},
        **basis_fields,
    )
    assert validated_basis.royalty_owner_amounts_hash == expected
    with pytest.raises(CollaborationExecutionError, match="cannot bypass"):
        CollaborationExecutionBasis.create_with_royalty_owner_amounts(
            royalty_owner_amounts={OWNER_A: 1_200, OWNER_B: 800},
            royalty_owner_amounts_hash=expected,
            **basis_fields,
        )

    with pytest.raises(CollaborationExecutionError, match="amount"):
        royalty_owner_amounts_hash(
            owner_amounts={OWNER_A: 2_000, OWNER_B: 0},
            expected_owners=(OWNER_A, OWNER_B),
            expected_total=2_000,
        )
    with pytest.raises(CollaborationExecutionError, match="sorted"):
        royalty_owner_amounts_hash(
            owner_amounts={OWNER_B: 800, OWNER_A: 1_200},
            expected_owners=(OWNER_A, OWNER_B),
            expected_total=2_000,
        )


def test_execution_grants_are_fresh_exact_owner_scoped_and_distinct_from_query_grants():
    intent = _intent()
    grants = _grants(intent)

    commitment = execution_grant_set_commitment(
        intent, grants, now=CREATED_AT + 30
    )
    assert commitment.startswith("sha256:")
    assert grants[0].to_dict()["scope"] == "one_shot_execution"
    assert (
        grants[0].execution_authorization_hash
        != grants[0].prospective_query_grant_authorization_hash
    )

    with pytest.raises(CollaborationExecutionError, match="distinct"):
        _grant(
            intent,
            OWNER_A,
            1,
            execution_authorization_hash=_sha("1"),
        )
    with pytest.raises(CollaborationExecutionAuthorityError, match="every"):
        execution_grant_set_commitment(
            intent, grants[:1], now=CREATED_AT + 30
        )
    with pytest.raises(CollaborationExecutionAuthorityError, match="expired"):
        execution_grant_set_commitment(
            intent, grants, now=CREATED_AT + 1_800
        )
    with pytest.raises(CollaborationExecutionAuthorityError, match="not yet"):
        execution_grant_set_commitment(
            intent, grants, now=CREATED_AT + 9
        )


def test_compute_handoff_success_survives_reload_and_public_projection_is_bounded(
    tmp_path,
):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)

    confirmed = journal.confirm_compute_handoff(
        intent.execution_id,
        _projection(
            handoff,
            stage="intent_created",
            observed_at=CREATED_AT + 32,
        ),
        confirmed_at=CREATED_AT + 32,
    )
    assert confirmed["state"] == ExecutionState.COMPUTE_HANDOFF_CONFIRMED.value
    assert confirmed["provider_dispatch_may_have_occurred"] is False
    assert confirmed["provider_dispatch_flag_source"] == (
        "typed_compute_projection_source_not_authenticated_by_core"
    )
    assert confirmed["compute_journal_projection"][
        "source_authentication_proven"
    ] is False
    assert confirmed["compute_journal_projection"][
        "source_authentication_boundary"
    ] == "trusted_local_compute_journal_reader_required"

    result = _result(intent, handoff.authorization_commitment)
    public = journal.reconcile_compute_projection(
        intent.execution_id,
        _projection(
            handoff,
            stage="settled",
            observed_at=CREATED_AT + 33,
            result=result,
        ),
        reconciled_at=CREATED_AT + 33,
    )

    assert public["state"] == ExecutionState.BOUNDED_RESULT_READY.value
    assert public["claim_count"] == 1
    assert public["provider_dispatch_may_have_occurred"] is True
    assert public["collaboration_provider_call_performed"] is False
    assert public["journal_automatic_redispatch"] is False
    assert public["bounded_result"]["result_class"] == (
        "completed_within_authorized_caps"
    )
    assert public["compute_handoff"]["handoff_commitment"] == handoff.commitment
    assert public["claim_vault_observation"]["reported_finalized"] is True
    assert public["claim_royalty_observation"]["reservation_id"] == (
        public["royalty"]["funding_reservation"]["reservation_id"]
    )
    assert public["claim_royalty_observation"]["reservation_active"] is True
    assert public["claim_royalty_observation"]["reservation_consumed"] is False
    assert public["claim_royalty_observation"][
        "reservation_execution_intent_commitment"
    ] == intent.commitment
    assert public["claim_royalty_observation"][
        "source_authentication_receipt_bound"
    ] is True
    assert public["max_total_asset_debit_scope"] == (
        "compute_usage_plus_reserved_royalty"
    )
    assert public["max_compute_asset_debit_scope"] == "compute_usage_only"
    assert public["royalty"]["settlement_id"] == intent.royalty_settlement_id
    assert public["royalty"]["settlement_nonce"] == str(
        intent.royalty_settlement_nonce
    )
    assert public["royalty"]["reservation_safety_seconds"] == 900
    assert public["royalty"]["funding_reservation_finalization_proven"] is True
    assert public["royalty"]["exact_payout_validation_proven"] is False
    assert public["royalty"][
        "fresh_construction_requires_validated_owner_amounts"
    ] is True
    assert public["royalty_distribution_performed"] is False

    reloaded = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    persisted = reloaded.public_get(intent.execution_id)
    assert persisted == public
    assert stat_mode(tmp_path / "collaboration-execution.json") == 0o600

    serialized = json.dumps(persisted, sort_keys=True)
    assert "provider_request_id" not in serialized
    assert "provider_account_id" not in serialized
    assert persisted["journal_raw_input_persisted"] is False
    assert persisted["journal_raw_result_persisted"] is False
    assert persisted["public_projection_raw_input_included"] is False
    assert persisted["public_projection_raw_result_included"] is False
    assert persisted["public_projection_provider_identifier_included"] is False
    assert persisted["whole_system_non_egress_claimed"] is False
    assert persisted["tdx_attestation_claimed"] is False
    assert persisted["qvl_verification_claimed"] is False
    assert persisted["live_deployment_claimed"] is False


def test_handoff_is_planned_and_durable_before_claim_but_only_released_after_claim(
    tmp_path,
):
    intent = _intent()
    grants = _grants(intent)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    authorized, created = journal.authorize(
        intent,
        grants,
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    assert created is True
    assert authorized["compute_handoff_status"] == "planned_not_submitted"
    planned_id = authorized["compute_handoff"]["handoff_id"]
    planned_commitment = authorized["compute_handoff"]["handoff_commitment"]
    assert authorized["compute_handoff"]["planned_at"] == CREATED_AT + 20
    assert authorized["provider_dispatch_may_have_occurred"] is None
    assert journal.recover_incomplete(recovered_at=CREATED_AT + 20) == []

    reloaded = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    assert reloaded.public_get(intent.execution_id)["compute_handoff"] == (
        authorized["compute_handoff"]
    )
    reloaded.queue(intent.execution_id, queued_at=CREATED_AT + 21)
    claimed = reloaded.claim_next(
        _current_validator(intent, grants),
        claimed_at=CREATED_AT + 30,
    )
    assert claimed is not None
    handoff = ComputeHandoff.from_dict(
        reloaded.prepare_compute_handoff(
            intent.execution_id,
            prepared_at=CREATED_AT + 31,
        )
    )
    assert handoff.handoff_id == planned_id
    assert handoff.commitment == planned_commitment
    assert handoff.compute_dispatch_intent.commitment == (
        intent.compute_dispatch_intent_commitment
    )
    assert handoff.handoff_id == handoff.to_dict()["handoff_id"]


def test_competing_instances_claim_once_and_prepare_byte_identical_handoff(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    instances = [
        CollaborationExecutionJournal(
            tmp_path / "collaboration-execution.json",
            integrity_key=b"k" * 32,
        )
        for _ in range(8)
    ]

    def claim(instance):
        return instance.claim_next(
            _current_validator(intent, grants),
            claimed_at=CREATED_AT + 30,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        claims = list(executor.map(claim, instances))
    assert len([item for item in claims if item is not None]) == 1

    def prepare(instance):
        return instance.prepare_compute_handoff(
            intent.execution_id,
            prepared_at=CREATED_AT + 31,
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        handoffs = list(executor.map(prepare, instances))
    assert all(item == handoffs[0] for item in handoffs)
    assert handoffs[0]["provider_call_performed_by_collaboration"] is False


def test_preclaim_owner_revocation_prevents_claim_and_handoff(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)

    with pytest.raises(CollaborationExecutionAuthorityError):
        journal.claim_next(
            _current_validator(intent, grants[:1]),
            claimed_at=CREATED_AT + 30,
        )

    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )
    with pytest.raises(CollaborationExecutionConflict):
        journal.prepare_compute_handoff(
            intent.execution_id,
            prepared_at=CREATED_AT + 31,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"release_verification_sha256": _sha("b")},
        {"room_state_commitment": _sha("d")},
        {"query_proposal_commitment": _sha("c")},
        {"compute_dispatch_intent_commitment": _bytes32("9")},
        {"compute_vault_runtime_code_hash": _bytes32("a")},
        {"compute_user_address": "0x" + "77" * 20},
        {"authorization_nonce": 20},
        {"max_compute_asset_debit": 7_001},
        {"royalty_owner_amounts_hash": _bytes32("9")},
    ],
)
def test_any_release_room_query_compute_funding_or_royalty_mutation_invalidates_claim(
    tmp_path, mutation
):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    changed = _replace_intent(intent, **mutation)

    with pytest.raises(CollaborationExecutionAuthorityError, match="changed"):
        journal.claim_next(
            _current_validator(changed, grants),
            claimed_at=CREATED_AT + 30,
        )

    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )


@pytest.mark.parametrize(
    "observation_changes",
    [
        {"chain_id": 8453},
        {"vault_address": "0x" + "77" * 20},
        {"vault_runtime_code_hash": _bytes32("a")},
        {"compute_project_id": _bytes32("a")},
        {"compute_job_id": _bytes32("b")},
        {"sponsor_address": OWNER_A},
        {"compute_user_address": OWNER_B},
        {"asset": "0x" + "77" * 20},
        {"authorization_nonce": 20},
        {"max_compute_asset_debit": 6_999},
        {"authorization_expiry": CREATED_AT + 3_599},
        {"compute_workload_commitment": _bytes32("a")},
        {"compute_manifest_commitment": _bytes32("b")},
        {"compute_dispatch_intent_commitment": _bytes32("c")},
    ],
)
def test_finalized_vault_observation_substitution_invalidates_atomic_claim(
    tmp_path, observation_changes
):
    journal, intent, grants = _authorized_and_queued(tmp_path)

    with pytest.raises(CollaborationExecutionAuthorityError, match="observation"):
        journal.claim_next(
            _current_validator(
                intent,
                grants,
                observation_changes=observation_changes,
            ),
            claimed_at=CREATED_AT + 30,
        )
    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )


@pytest.mark.parametrize(
    "royalty_observation_changes",
    [
        {"reservation_active": False},
        {"reservation_consumed": True},
        {"owner_address": "0x" + "88" * 20},
        {"pending_owner_address": "0x" + "88" * 20},
        {"reservation_id": _bytes32("7")},
        {"reservation_sponsor_address": OWNER_A},
        {"reservation_asset": "0x" + "00" * 20},
        {"reservation_total": 1_999},
        {"reservation_owner_amounts_hash": _bytes32("7")},
        {"reservation_release_policy_commitment": _bytes32("7")},
        {"reservation_execution_intent_commitment": _sha("7")},
        {"reservation_refund_after": CREATED_AT + 4_499},
        {"reservation_deposited_amount": 1_999},
    ],
)
def test_finalized_royalty_reservation_substitution_invalidates_atomic_claim(
    tmp_path,
    royalty_observation_changes,
):
    journal, intent, grants = _authorized_and_queued(tmp_path)

    with pytest.raises(CollaborationExecutionAuthorityError):
        journal.claim_next(
            _current_validator(
                intent,
                grants,
                royalty_observation_changes=royalty_observation_changes,
            ),
            claimed_at=CREATED_AT + 30,
        )
    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )


def test_compute_and_royalty_reads_must_share_one_finalized_block(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)

    with pytest.raises(
        CollaborationExecutionAuthorityUnavailable,
        match="one finalized block",
    ):
        journal.claim_next(
            _current_validator(
                intent,
                grants,
                royalty_observation_changes={"block_hash": _bytes32("8")},
            ),
            claimed_at=CREATED_AT + 30,
        )
    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.QUEUED.value
    )


def test_vault_observation_unavailable_or_not_finalized_is_retryable(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)

    with pytest.raises(CollaborationExecutionAuthorityUnavailable):
        journal.claim_next(
            _current_validator(intent, grants, available=False),
            claimed_at=CREATED_AT + 30,
        )
    assert journal.public_get(intent.execution_id)["state"] == ExecutionState.QUEUED.value

    with pytest.raises(CollaborationExecutionAuthorityUnavailable, match="finalized"):
        journal.claim_next(
            _current_validator(
                intent,
                grants,
                observation_changes={"reported_finalized": False},
            ),
            claimed_at=CREATED_AT + 31,
        )
    assert journal.public_get(intent.execution_id)["state"] == ExecutionState.QUEUED.value

    claimed = journal.claim_next(
        _current_validator(intent, grants),
        claimed_at=CREATED_AT + 32,
    )
    assert claimed is not None
    assert claimed["state"] == ExecutionState.CLAIMED.value


def test_non_authorized_vault_job_definitively_invalidates_claim(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    with pytest.raises(CollaborationExecutionAuthorityError, match="no longer authorized"):
        journal.claim_next(
            _current_validator(
                intent,
                grants,
                observation_changes={"job_state": "started"},
            ),
            claimed_at=CREATED_AT + 30,
        )
    assert journal.public_get(intent.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )


def test_invalid_oldest_queue_item_is_quarantined_without_starving_next_valid_item(
    tmp_path,
):
    first = _intent()
    first_grants = _grants(first)
    second = _independent_intent(first)
    second_grants = _independent_grants(second)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    for intent, grants, key, queued_at in (
        (first, first_grants, "collab-execution-0001", CREATED_AT + 21),
        (second, second_grants, "collab-execution-0002", CREATED_AT + 22),
    ):
        journal.authorize(
            intent,
            grants,
            idempotency_key=key,
            authorized_at=CREATED_AT + 20,
        )
        journal.queue(intent.execution_id, queued_at=queued_at)

    def validate(intent, _grants_value, observed_at):
        current_grants = (
            first_grants[:1]
            if intent.execution_id == first.execution_id
            else second_grants
        )
        return ClaimAuthoritySnapshot.create(
            current_intent=intent,
            current_execution_grants=current_grants,
                finalized_vault_observation=_vault_observation(intent, observed_at),
                finalized_royalty_observation=_royalty_observation(
                    intent, observed_at, _grants_value
                ),
            observed_at=observed_at,
        )

    claimed = journal.claim_next(validate, claimed_at=CREATED_AT + 30)
    assert claimed is not None
    assert CollaborationExecutionIntent.from_dict(claimed["intent"]).execution_id == (
        second.execution_id
    )
    assert journal.public_get(first.execution_id)["state"] == (
        ExecutionState.AUTHORITY_INVALIDATED.value
    )


def test_temporarily_unavailable_oldest_item_is_skipped_then_retryable(tmp_path):
    first = _intent()
    first_grants = _grants(first)
    second = _independent_intent(first)
    second_grants = _independent_grants(second)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    for intent, grants, key, queued_at in (
        (first, first_grants, "collab-execution-0001", CREATED_AT + 21),
        (second, second_grants, "collab-execution-0002", CREATED_AT + 22),
    ):
        journal.authorize(
            intent,
            grants,
            idempotency_key=key,
            authorized_at=CREATED_AT + 20,
        )
        journal.queue(intent.execution_id, queued_at=queued_at)

    def first_unavailable(intent, grants, observed_at):
        if intent.execution_id == first.execution_id:
            raise CollaborationExecutionAuthorityUnavailable(
                "finalized vault read temporarily unavailable"
            )
        return ClaimAuthoritySnapshot.create(
            current_intent=intent,
            current_execution_grants=grants,
                finalized_vault_observation=_vault_observation(intent, observed_at),
                finalized_royalty_observation=_royalty_observation(
                    intent, observed_at, grants
                ),
            observed_at=observed_at,
        )

    claimed = journal.claim_next(first_unavailable, claimed_at=CREATED_AT + 30)
    assert claimed is not None
    assert CollaborationExecutionIntent.from_dict(claimed["intent"]).execution_id == (
        second.execution_id
    )
    assert journal.public_get(first.execution_id)["state"] == ExecutionState.QUEUED.value

    after_topup = journal.claim_next(
        _current_validator(first, first_grants),
        claimed_at=CREATED_AT + 31,
    )
    assert after_topup is not None
    assert CollaborationExecutionIntent.from_dict(after_topup["intent"]).execution_id == (
        first.execution_id
    )


def test_ambiguous_compute_projection_requires_explicit_exact_manual_resolution(
    tmp_path,
):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    ambiguous = _projection(
        handoff,
        stage="provider_outcome_ambiguous",
        observed_at=CREATED_AT + 32,
    )

    first = journal.reconcile_compute_projection(
        intent.execution_id,
        ambiguous,
        reconciled_at=CREATED_AT + 32,
    )
    assert first["state"] == ExecutionState.RECONCILIATION_HOLD.value
    assert first["reconciliation_hold"] is True
    assert first["bounded_result"] is None
    assert first["provider_dispatch_may_have_occurred"] is True
    assert journal.reconcile_compute_projection(
        intent.execution_id,
        ambiguous,
        reconciled_at=CREATED_AT + 32,
    ) == first
    recovery = journal.recover_incomplete(recovered_at=CREATED_AT + 100)
    assert recovery[0]["recovery_action"] == (
        "manual_exact_compute_reconciliation_required"
    )

    settled = _projection(
        handoff,
        stage="settled",
        observed_at=CREATED_AT + 33,
        result=_result(intent, handoff.authorization_commitment),
    )
    with pytest.raises(CollaborationExecutionConflict, match="explicit manual"):
        journal.reconcile_compute_projection(
            intent.execution_id,
            settled,
            reconciled_at=CREATED_AT + 33,
        )
    with pytest.raises(CollaborationExecutionConflict, match="substitution"):
        journal.resolve_reconciliation_hold(
            intent.execution_id,
            replace(settled, handoff_id="chandoff_" + "f" * 64),
            resolved_at=CREATED_AT + 33,
        )
    same_time_settled = _projection(
        handoff,
        stage="settled",
        observed_at=CREATED_AT + 32,
        result=_result(intent, handoff.authorization_commitment),
    )
    with pytest.raises(CollaborationExecutionConflict, match="regressed"):
        journal.resolve_reconciliation_hold(
            intent.execution_id,
            same_time_settled,
            resolved_at=CREATED_AT + 32,
        )
    resolved = journal.resolve_reconciliation_hold(
        intent.execution_id,
        settled,
        resolved_at=CREATED_AT + 33,
    )
    assert resolved["state"] == ExecutionState.BOUNDED_RESULT_READY.value
    assert resolved["reconciliation_hold"] is False
    assert resolved["reconciliation_was_required"] is True
    assert resolved["journal_automatic_redispatch"] is False
    assert journal.resolve_reconciliation_hold(
        intent.execution_id,
        settled,
        resolved_at=CREATED_AT + 33,
    ) == resolved


def test_crash_after_claim_recovers_by_preparing_handoff(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    claimed = journal.claim_next(
        _current_validator(intent, grants), claimed_at=CREATED_AT + 30
    )
    assert claimed is not None

    reloaded = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    recovered = reloaded.recover_incomplete(recovered_at=CREATED_AT + 31)
    assert len(recovered) == 1
    assert recovered[0]["execution_id"] == intent.execution_id
    assert recovered[0]["state"] == ExecutionState.CLAIMED.value
    assert recovered[0]["recovery_action"] == "prepare_compute_handoff"
    assert ComputeHandoff.from_dict(recovered[0]["compute_handoff"]).planned_at == (
        CREATED_AT + 20
    )
    assert recovered[0]["provider_call_performed_by_collaboration"] is False
    handoff = reloaded.prepare_compute_handoff(
        intent.execution_id,
        prepared_at=CREATED_AT + 31,
    )
    assert handoff["provider_call_performed_by_collaboration"] is False


def test_crash_after_pending_recovers_exact_idempotent_handoff(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    reloaded = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    recovered = reloaded.recover_incomplete(recovered_at=CREATED_AT + 32)
    assert recovered[0]["state"] == ExecutionState.COMPUTE_HANDOFF_PENDING.value
    assert recovered[0]["recovery_action"] == (
        "lookup_or_resubmit_exact_idempotent_compute_handoff"
    )
    assert recovered[0]["compute_handoff"] == handoff.to_dict()
    assert reloaded.prepare_compute_handoff(
        intent.execution_id,
        prepared_at=CREATED_AT + 99,
    ) == handoff.to_dict()


def test_crash_after_confirmed_recovers_by_polling_exact_compute_journal(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    journal.confirm_compute_handoff(
        intent.execution_id,
        _projection(
            handoff,
            stage="intent_created",
            observed_at=CREATED_AT + 32,
        ),
        confirmed_at=CREATED_AT + 32,
    )
    reloaded = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    recovered = reloaded.recover_incomplete(recovered_at=CREATED_AT + 33)
    assert recovered[0]["state"] == ExecutionState.COMPUTE_HANDOFF_CONFIRMED.value
    assert recovered[0]["recovery_action"] == (
        "poll_exact_compute_journal_projection"
    )
    assert recovered[0]["compute_handoff"] == handoff.to_dict()


def test_definitive_bounded_failure_uses_failed_terminal_state(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    result = _result(intent, handoff.authorization_commitment, outcome="failed")
    public = journal.reconcile_compute_projection(
        intent.execution_id,
        _projection(
            handoff,
            stage="settled",
            observed_at=CREATED_AT + 32,
            result=result,
        ),
        reconciled_at=CREATED_AT + 32,
    )
    assert public["state"] == ExecutionState.FAILED.value
    assert public["bounded_result"]["result_class"] == (
        "provider_failed_without_raw_detail"
    )


def test_compute_block_without_result_uses_failed_terminal_state(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    public = journal.reconcile_compute_projection(
        intent.execution_id,
        _projection(
            handoff,
            stage="blocked",
            observed_at=CREATED_AT + 32,
            provider_dispatch_may_have_occurred=False,
        ),
        reconciled_at=CREATED_AT + 32,
    )
    assert public["state"] == ExecutionState.FAILED.value
    assert public["bounded_result"] is None
    assert public["provider_dispatch_may_have_occurred"] is False


def test_bounded_result_rejects_extra_raw_or_provider_fields():
    intent = _intent()
    authorization = execution_authorization_commitment(
        intent,
        _grants(intent),
        now=CREATED_AT + 20,
    )
    value = _result(intent, authorization).to_dict()
    value["raw_result"] = "forbidden"

    with pytest.raises(CollaborationExecutionError, match="schema"):
        BoundedExecutionResult.from_dict(value)


def test_result_compute_debit_must_fit_compute_cap():
    intent = _intent()
    authorization = execution_authorization_commitment(
        intent,
        _grants(intent),
        now=CREATED_AT + 20,
    )
    result = _result(
        intent,
        authorization,
        actual_compute_asset_debit=intent.max_compute_asset_debit + 1,
    )

    with pytest.raises(CollaborationExecutionError, match="Compute cap"):
        result.validate_for(
            intent,
            authorization_commitment=authorization,
        )

def test_failed_result_never_releases_score_band():
    intent = _intent(result_policy="score_band_hash")
    authorization = execution_authorization_commitment(
        intent,
        _grants(intent),
        now=CREATED_AT + 20,
    )

    with pytest.raises(CollaborationExecutionError, match="failed execution"):
        BoundedExecutionResult.create(
            execution_id=intent.execution_id,
            intent_commitment=intent.commitment,
            authorization_commitment=authorization,
            outcome="failed",
            result_class="provider_failed_without_raw_detail",
            result_policy="score_band_hash",
            result_commitment=_sha("9"),
            usage_commitment=_sha("a"),
            actual_compute_asset_debit=0,
            billable_compute_units=0,
            score_band="bottom_10_percent",
        )


def test_bounded_result_from_another_execution_is_rejected_not_imported(tmp_path):
    first = _intent()
    first_grants = _grants(first)
    first_authorization = execution_authorization_commitment(
        first,
        first_grants,
        now=CREATED_AT + 20,
    )
    replayed_result = _result(first, first_authorization)

    second = _independent_intent(first)
    second_grants = _independent_grants(second)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    journal.authorize(
        second,
        second_grants,
        idempotency_key="collab-execution-0002",
        authorized_at=CREATED_AT + 20,
    )
    journal.queue(second.execution_id, queued_at=CREATED_AT + 21)
    handoff = _claim_and_prepare(journal, second, second_grants)
    projection = _projection(
        handoff,
        stage="settled",
        observed_at=CREATED_AT + 32,
        result=replayed_result,
    )
    with pytest.raises(CollaborationExecutionError, match="different"):
        journal.reconcile_compute_projection(
            second.execution_id,
            projection,
            reconciled_at=CREATED_AT + 32,
        )
    assert journal.public_get(second.execution_id)["state"] == (
        ExecutionState.COMPUTE_HANDOFF_PENDING.value
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("handoff_id", "chandoff_" + "f" * 64),
        ("handoff_commitment", _sha("f")),
        ("authorization_commitment", _sha("e")),
        ("compute_job_id", _bytes32("f")),
        ("compute_dispatch_intent_commitment", _bytes32("f")),
    ],
)
def test_compute_projection_substitution_is_rejected(tmp_path, field, replacement):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    projection = replace(
        _projection(
            handoff,
            stage="intent_created",
            observed_at=CREATED_AT + 32,
        ),
        **{field: replacement},
    )
    with pytest.raises(CollaborationExecutionConflict, match="substitution"):
        journal.reconcile_compute_projection(
            intent.execution_id,
            projection,
            reconciled_at=CREATED_AT + 32,
        )


def test_preboundary_projection_cannot_claim_provider_dispatch():
    intent = _intent()
    authorization = execution_authorization_commitment(
        intent,
        _grants(intent),
        now=CREATED_AT + 20,
    )
    handoff = ComputeHandoff.create(
        intent,
        authorization_commitment=authorization,
        planned_at=CREATED_AT + 20,
    )
    with pytest.raises(CollaborationExecutionError, match="pre-boundary"):
        _projection(
            handoff,
            stage="intent_created",
            observed_at=CREATED_AT + 32,
            provider_dispatch_may_have_occurred=True,
        )


def test_compute_projection_stage_and_boundary_flags_cannot_regress(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    journal.reconcile_compute_projection(
        intent.execution_id,
        _projection(
            handoff,
            stage="provider_attempt_checkpointed",
            observed_at=CREATED_AT + 32,
        ),
        reconciled_at=CREATED_AT + 32,
    )

    with pytest.raises(CollaborationExecutionConflict, match="regressed"):
        journal.reconcile_compute_projection(
            intent.execution_id,
            _projection(
                handoff,
                stage="intent_created",
                observed_at=CREATED_AT + 33,
            ),
            reconciled_at=CREATED_AT + 33,
        )
    with pytest.raises(CollaborationExecutionConflict, match="regressed"):
        journal.reconcile_compute_projection(
            intent.execution_id,
            _projection(
                handoff,
                stage="blocked",
                observed_at=CREATED_AT + 33,
                provider_dispatch_may_have_occurred=False,
            ),
            reconciled_at=CREATED_AT + 33,
        )


def test_same_terminal_compute_projection_is_idempotent(tmp_path):
    journal, intent, grants = _authorized_and_queued(tmp_path)
    handoff = _claim_and_prepare(journal, intent, grants)
    projection = _projection(
        handoff,
        stage="settled",
        observed_at=CREATED_AT + 32,
        result=_result(intent, handoff.authorization_commitment),
    )
    first = journal.reconcile_compute_projection(
        intent.execution_id,
        projection,
        reconciled_at=CREATED_AT + 32,
    )
    replay = journal.reconcile_compute_projection(
        intent.execution_id,
        projection,
        reconciled_at=CREATED_AT + 32,
    )
    assert replay == first


def test_journal_hmac_detects_mutation_and_wrong_key(tmp_path):
    journal, intent, _grants_value = _authorized_and_queued(tmp_path)
    path = tmp_path / "collaboration-execution.json"

    with pytest.raises(CollaborationExecutionJournalError, match="authentication"):
        CollaborationExecutionJournal(path, integrity_key=b"z" * 32)

    envelope = json.loads(path.read_text())
    envelope["body"]["records"][intent.execution_id]["state"] = "authorized"
    path.write_text(json.dumps(envelope, sort_keys=True, separators=(",", ":")))
    os.chmod(path, 0o600)

    with pytest.raises(CollaborationExecutionJournalError, match="authentication"):
        CollaborationExecutionJournal(path, integrity_key=b"k" * 32)


def test_journal_rejects_noncanonical_envelope_bytes_even_with_valid_hmac(tmp_path):
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    path = journal.path
    path.write_bytes(path.read_bytes() + b"\n")
    os.chmod(path, 0o600)

    with pytest.raises(CollaborationExecutionJournalError, match="not canonical"):
        CollaborationExecutionJournal(path, integrity_key=b"k" * 32)


def test_preexisting_lock_hardlink_is_rejected_without_chmod_side_effect(tmp_path):
    path = tmp_path / "collaboration-execution.json"
    canary = tmp_path / "canary"
    canary.write_text("do-not-mutate")
    os.chmod(canary, 0o644)
    os.link(canary, path.with_name(f".{path.name}.lock"))

    with pytest.raises(CollaborationExecutionJournalError, match="lock file is unsafe"):
        CollaborationExecutionJournal(path, integrity_key=b"k" * 32)

    assert stat_mode(canary) == 0o644
    assert canary.read_text() == "do-not-mutate"


def test_journal_rejects_user_created_parent_symlink(tmp_path):
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(
        CollaborationExecutionJournalError,
        match="parent path is unsafe",
    ):
        CollaborationExecutionJournal(
            linked_parent / "collaboration-execution.json",
            integrity_key=b"k" * 32,
        )

    assert not (real_parent / "collaboration-execution.json").exists()


def test_symlinked_ancestor_cannot_cause_directory_creation_in_canary_tree(
    tmp_path,
):
    canary = tmp_path / "canary-tree"
    canary.mkdir(mode=0o700)
    marker = canary / "marker"
    marker.write_text("unchanged")
    linked_ancestor = tmp_path / "linked-ancestor"
    linked_ancestor.symlink_to(canary, target_is_directory=True)
    attacker_selected_parent = linked_ancestor / "must-not-be-created"

    with pytest.raises(
        CollaborationExecutionJournalError,
        match="parent path is unsafe",
    ):
        CollaborationExecutionJournal(
            attacker_selected_parent / "collaboration-execution.json",
            integrity_key=b"k" * 32,
        )

    assert not (canary / "must-not-be-created").exists()
    assert marker.read_text() == "unchanged"
    assert sorted(item.name for item in canary.iterdir()) == ["marker"]


def test_authorization_replay_is_idempotent_and_different_grants_fail_context(
    tmp_path,
):
    intent = _intent()
    grants = _grants(intent)
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )

    first, created = journal.authorize(
        intent,
        grants,
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    replay, replay_created = journal.authorize(
        intent,
        grants,
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )

    assert created is True
    assert replay_created is False
    assert replay == first

    changed_grants = (
        _grant(
            intent,
            OWNER_A,
            1,
            execution_authorization_hash=_sha("b"),
        ),
        grants[1],
    )
    with pytest.raises(CollaborationExecutionAuthorityError, match="context"):
        journal.authorize(
            intent,
            changed_grants,
            idempotency_key="collab-execution-0001",
            authorized_at=CREATED_AT + 20,
        )


def test_idempotency_key_is_journal_wide_not_only_execution_id_scoped(tmp_path):
    intent = _intent()
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    journal.authorize(
        intent,
        _grants(intent),
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    changed = _independent_intent(intent)

    with pytest.raises(CollaborationExecutionConflict, match="idempotency_key"):
        journal.authorize(
            changed,
            _independent_grants(changed),
            idempotency_key="collab-execution-0001",
            authorized_at=CREATED_AT + 20,
        )


def test_funding_nonce_cannot_authorize_two_different_execution_ids(tmp_path):
    intent = _intent()
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    journal.authorize(
        intent,
        _grants(intent),
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    changed = _independent_intent(
        intent,
        authorization_nonce=intent.authorization_nonce,
    )

    with pytest.raises(CollaborationExecutionConflict, match="funding_authorization"):
        journal.authorize(
            changed,
            _independent_grants(changed),
            idempotency_key="collab-execution-0002",
            authorized_at=CREATED_AT + 20,
        )


def test_royalty_settlement_id_cannot_back_two_execution_ids(tmp_path):
    intent = _intent()
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    journal.authorize(
        intent,
        _grants(intent),
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    changed = _independent_intent(
        intent,
        royalty_settlement_id=intent.royalty_settlement_id,
    )

    with pytest.raises(
        CollaborationExecutionConflict,
        match="royalty_settlement",
    ):
        journal.authorize(
            changed,
            _independent_grants(changed),
            idempotency_key="collab-execution-0002",
            authorized_at=CREATED_AT + 20,
        )


def test_compute_dispatch_intent_cannot_be_rewrapped_even_before_journal_replay(
    tmp_path,
):
    intent = _intent()
    journal = CollaborationExecutionJournal(
        tmp_path / "collaboration-execution.json",
        integrity_key=b"k" * 32,
    )
    journal.authorize(
        intent,
        _grants(intent),
        idempotency_key="collab-execution-0001",
        authorized_at=CREATED_AT + 20,
    )
    changed = _independent_intent(
        intent,
        compute_dispatch_intent_commitment=(
            intent.compute_dispatch_intent_commitment
        ),
    )

    with pytest.raises(CollaborationExecutionAuthorityError, match="dispatch intent"):
        journal.authorize(
            changed,
            _independent_grants(changed),
            idempotency_key="collab-execution-0002",
            authorized_at=CREATED_AT + 20,
        )


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777
