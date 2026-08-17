from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from tinker_delegate.collaboration_royalty_settlement import (
    CollaborationRoyaltySettlementConflict,
    CollaborationRoyaltySettlementError,
    CollaborationRoyaltySettlementStore,
    CollaborationRoyaltySettlementStoreError,
    collaboration_royalty_settlement_integrity_key,
)


NOW = 1_800_000_000
EXECUTION_ID = "exec_" + "1" * 64
SPONSOR = "0x" + "2" * 40
PLAN = "0x" + "3" * 64


def _authority():
    return {
        "execution_id": EXECUTION_ID,
        "sponsor_address": SPONSOR,
        "funding_reservation_id": "0x" + "4" * 64,
        "settlement_id": "0x" + "5" * 64,
        "settlement_nonce": 2**200 + 17,
        "refund_after": NOW + 3_600,
    }


def _store(tmp_path, key=b"k" * 32):
    return CollaborationRoyaltySettlementStore(
        tmp_path / "royalty-settlement.json",
        integrity_key=key,
    )


def _finalized(**changes):
    value = {
        "chain_id": 84_532,
        "block_number": 12_345_678,
        "block_hash": "0x" + "6" * 64,
        "block_timestamp": NOW + 20,
        "reservation_active": False,
        "reservation_consumed": True,
        "settlement_processed": True,
        "settlement_nonce_processed": True,
        "source_commitment": "sha256:" + "7" * 64,
    }
    value.update(changes)
    return value


def _terminal_evidence(outcome: str):
    refunded = outcome == "reservation_refunded"
    return {
        "outcome": outcome,
        "chain_id": 84_532,
        "block_number": 12_345_679,
        "block_hash": "0x" + "8" * 64,
        "block_timestamp": NOW + 3_700,
        "funding_reservation_id": _authority()["funding_reservation_id"],
        "reservation_storage_status": "refunded" if refunded else "active",
        "reservation_active": False,
        "reservation_consumed": False,
        "reservation_deposited_amount": 0 if refunded else 2_000,
        "settlement_processed": False,
        "settlement_nonce_processed": False,
        "source_commitment": "sha256:" + "9" * 64,
    }


def test_sponsor_on_demand_status_and_uints_are_canonical_decimal_strings(tmp_path):
    store = _store(tmp_path)
    empty = store.status(
        authority=_authority(),
        sponsor_address=SPONSOR,
        wallet_plan=None,
    )
    assert empty["state"] == "not_requested"
    assert empty["generation"] == "0"
    assert empty["settlement_nonce"] == str(2**200 + 17)
    assert empty["refund_after"] == str(NOW + 3_600)
    assert empty["modeled"] is False
    assert empty["raw_secret_egress"] is False

    requested = store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    assert requested["state"] == "prepare_requested"
    assert requested["generation"] == "1"
    assert requested["prepare_requested_at"] == str(NOW)
    assert store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW + 1,
    ) == requested
    persisted = store.path.read_text("utf-8")
    assert "prepare-settlement-0001" not in persisted
    assert "wallet_plan" not in persisted


def test_only_exact_sponsor_and_expired_generation_can_be_replaced(tmp_path):
    store = _store(tmp_path)
    with pytest.raises(CollaborationRoyaltySettlementError, match="sponsor"):
        store.request_prepare(
            authority=_authority(),
            sponsor_address="0x" + "8" * 40,
            idempotency_key="prepare-settlement-0001",
            replace_expired=False,
            requested_at=NOW,
        )
    first = store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    claimed = store.claim_next(claimed_at=NOW + 1)
    assert claimed is not None and claimed["state"] == "authorizing"
    store.mark_expired(
        execution_id=EXECUTION_ID,
        generation=1,
        recorded_at=NOW + 2,
    )
    with pytest.raises(CollaborationRoyaltySettlementConflict):
        store.request_prepare(
            authority=_authority(),
            sponsor_address=SPONSOR,
            idempotency_key="prepare-settlement-0002",
            replace_expired=False,
            requested_at=NOW + 3,
        )
    second = store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0002",
        replace_expired=True,
        requested_at=NOW + 3,
    )
    assert first["generation"] == "1"
    assert second["generation"] == "2"
    assert second["state"] == "prepare_requested"


def test_broadcast_hash_is_only_a_hint_and_finalized_flags_are_authoritative(tmp_path):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    store.claim_next(claimed_at=NOW + 1)
    ready = store.mark_plan_ready(
        execution_id=EXECUTION_ID,
        generation=1,
        plan_commitment=PLAN,
        authorization_expires_at=NOW + 60,
        recorded_at=NOW + 2,
    )
    assert ready["state"] == "plan_ready"
    reported = store.report_broadcast(
        execution_id=EXECUTION_ID,
        sponsor_address=SPONSOR,
        idempotency_key="broadcast-settlement-0001",
        plan_commitment=PLAN,
        transaction_hash="0x" + "9" * 64,
        reported_at=NOW + 3,
    )
    assert reported["state"] == "broadcast_reported"
    assert reported["finalized_settlement"] is None
    assert reported["broadcast_hint"] == {
        "transaction_hash": "0x" + "9" * 64,
        "reported_at": str(NOW + 3),
    }
    replay = store.report_broadcast(
        execution_id=EXECUTION_ID,
        sponsor_address=SPONSOR,
        idempotency_key="broadcast-settlement-0001",
        plan_commitment=PLAN,
        transaction_hash="0x" + "9" * 64,
        reported_at=NOW + 4,
    )
    assert replay == reported
    with pytest.raises(
        CollaborationRoyaltySettlementConflict,
        match="idempotency key",
    ):
        store.report_broadcast(
            execution_id=EXECUTION_ID,
            sponsor_address=SPONSOR,
            idempotency_key="broadcast-settlement-0001",
            plan_commitment=PLAN,
            transaction_hash="0x" + "8" * 64,
            reported_at=NOW + 5,
        )
    with pytest.raises(CollaborationRoyaltySettlementError, match="does not prove"):
        store.mark_finalized(
            execution_id=EXECUTION_ID,
            generation=1,
            finalized_settlement=_finalized(settlement_processed=False),
            recorded_at=NOW + 20,
        )
    settled = store.mark_finalized(
        execution_id=EXECUTION_ID,
        generation=1,
        finalized_settlement=_finalized(),
        recorded_at=NOW + 20,
    )
    assert settled["state"] == "settled"
    assert settled["finalized_settlement"]["block_number"] == "12345678"
    assert settled["finalized_settlement"]["block_timestamp"] == str(NOW + 20)


def test_status_injects_finalized_wallet_plan_without_persisting_it(tmp_path):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    store.claim_next(claimed_at=NOW + 1)
    store.mark_plan_ready(
        execution_id=EXECUTION_ID,
        generation=1,
        plan_commitment=PLAN,
        authorization_expires_at=NOW + 60,
        recorded_at=NOW + 2,
    )
    wallet = {"schema": "dnai.collaboration.royalty-settlement-wallet-plan.v1"}
    status = store.status(
        authority=_authority(),
        sponsor_address=SPONSOR,
        wallet_plan=wallet,
    )
    assert status["wallet_plan"] == wallet
    assert "royalty-settlement-wallet-plan" not in store.path.read_text("utf-8")


def test_first_advisory_hash_can_arrive_after_finalized_settlement(tmp_path):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-late-report-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    store.claim_next(claimed_at=NOW + 1)
    store.mark_plan_ready(
        execution_id=EXECUTION_ID,
        generation=1,
        plan_commitment=PLAN,
        authorization_expires_at=NOW + 60,
        recorded_at=NOW + 2,
    )
    settled = store.mark_finalized(
        execution_id=EXECUTION_ID,
        generation=1,
        finalized_settlement=_finalized(),
        recorded_at=NOW + 20,
    )
    assert settled["broadcast_hint"] is None
    reported = store.report_broadcast(
        execution_id=EXECUTION_ID,
        sponsor_address=SPONSOR,
        idempotency_key="broadcast-late-report-0001",
        plan_commitment=PLAN,
        transaction_hash="0x" + "a" * 64,
        reported_at=NOW + 21,
    )
    assert reported["state"] == "settled"
    assert reported["finalized_settlement"] == settled["finalized_settlement"]
    assert reported["broadcast_hint"] == {
        "transaction_hash": "0x" + "a" * 64,
        "reported_at": str(NOW + 21),
    }


def test_store_tamper_wrong_key_and_local_key_policy_fail_closed(tmp_path, monkeypatch):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    with pytest.raises(CollaborationRoyaltySettlementStoreError):
        CollaborationRoyaltySettlementStore(store.path, integrity_key=b"x" * 32)
    root = json.loads(store.path.read_text("utf-8"))
    root["payload"]["records"][EXECUTION_ID]["state"] = "settled"
    store.path.write_text(json.dumps(root), encoding="utf-8")
    store.path.chmod(0o600)
    with pytest.raises(CollaborationRoyaltySettlementStoreError):
        store.record(EXECUTION_ID)

    monkeypatch.setattr(
        "tinker_delegate.collaboration_royalty_settlement.dstack_utils.is_dstack_enabled",
        lambda: False,
    )
    with pytest.raises(CollaborationRoyaltySettlementStoreError, match="unavailable"):
        collaboration_royalty_settlement_integrity_key(
            SimpleNamespace(
                collaboration_royalty_settlement_store_integrity_key="short"
            )
        )
    key = collaboration_royalty_settlement_integrity_key(
        SimpleNamespace(
            collaboration_royalty_settlement_store_integrity_key="z" * 32
        )
    )
    assert len(key) == 32 and key != b"z" * 32


@pytest.mark.parametrize(
    "terminal_transition,expected_state,expected_failure",
    [
        ("refunded", "refunded", "reservation_refunded"),
        (
            "reservation_expired",
            "reservation_expired",
            "reservation_expired",
        ),
    ],
)
def test_reservation_terminal_states_cannot_be_replaced(
    tmp_path,
    terminal_transition,
    expected_state,
    expected_failure,
):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    store.claim_next(claimed_at=NOW + 1)
    store.mark_plan_ready(
        execution_id=EXECUTION_ID,
        generation=1,
        plan_commitment=PLAN,
        authorization_expires_at=NOW + 60,
        recorded_at=NOW + 2,
    )
    if terminal_transition == "refunded":
        terminal = store.mark_refunded(
            execution_id=EXECUTION_ID,
            generation=1,
            terminal_evidence=_terminal_evidence(
                "reservation_refunded"
            ),
            recorded_at=NOW + 3_700,
        )
    else:
        terminal = store.mark_reservation_expired(
            execution_id=EXECUTION_ID,
            generation=1,
            terminal_evidence=_terminal_evidence(
                "reservation_expired"
            ),
            recorded_at=NOW + 3_700,
        )
    assert terminal["state"] == expected_state
    assert terminal["failure_code"] == expected_failure
    assert terminal["retryable"] is False
    assert terminal["wallet_plan"] is None
    with pytest.raises(
        CollaborationRoyaltySettlementConflict,
        match="already exists",
    ):
        store.request_prepare(
            authority=_authority(),
            sponsor_address=SPONSOR,
            idempotency_key="prepare-settlement-0002",
            replace_expired=True,
            requested_at=NOW + 71,
        )


def test_store_rejects_duplicate_json_members_before_authentication(tmp_path):
    store = _store(tmp_path)
    raw = store.path.read_text("ascii")
    duplicate = raw.replace(
        '{"integrity":',
        '{"schema":"dnai.collaboration.royalty-settlement-store.v2","integrity":',
        1,
    )
    assert duplicate != raw
    store.path.write_text(duplicate, encoding="ascii")
    store.path.chmod(0o600)
    with pytest.raises(
        CollaborationRoyaltySettlementStoreError,
        match="unavailable or unsafe",
    ):
        store.record(EXECUTION_ID)


def test_reconciliation_cursor_is_durable_and_does_not_starve_later_plans(
    tmp_path,
):
    store = _store(tmp_path)
    authorities = (
        _authority(),
        {
            **_authority(),
            "execution_id": "exec_" + "9" * 64,
            "funding_reservation_id": "0x" + "a" * 64,
            "settlement_id": "0x" + "b" * 64,
            "settlement_nonce": 2**200 + 18,
        },
    )
    for index, authority in enumerate(authorities, start=1):
        store.request_prepare(
            authority=authority,
            sponsor_address=SPONSOR,
            idempotency_key=f"prepare-settlement-000{index}",
            replace_expired=False,
            requested_at=NOW + index,
        )
        claimed = store.claim_next(claimed_at=NOW + index + 10)
        assert claimed is not None
        store.mark_plan_ready(
            execution_id=authority["execution_id"],
            generation=1,
            plan_commitment="0x" + str(index + 2) * 64,
            authorization_expires_at=NOW + 60,
            recorded_at=NOW + index + 20,
        )
    first = store.next_reconciliation()
    assert first is not None
    store.defer_reconciliation(
        execution_id=first["execution_id"],
        generation=first["generation"],
    )
    second = store.next_reconciliation()
    assert second is not None
    assert second["execution_id"] != first["execution_id"]


def test_temporary_authorization_failure_rotates_to_the_next_request(tmp_path):
    store = _store(tmp_path)
    second_authority = {
        **_authority(),
        "execution_id": "exec_" + "9" * 64,
        "funding_reservation_id": "0x" + "a" * 64,
        "settlement_id": "0x" + "b" * 64,
        "settlement_nonce": 2**200 + 18,
    }
    for index, authority in enumerate(
        (_authority(), second_authority),
        start=1,
    ):
        store.request_prepare(
            authority=authority,
            sponsor_address=SPONSOR,
            idempotency_key=f"prepare-rotation-000{index}",
            replace_expired=False,
            requested_at=NOW + index,
        )
    first = store.claim_next(claimed_at=NOW + 10)
    assert first is not None and first["state"] == "authorizing"
    store.defer_authorization(
        execution_id=first["execution_id"],
        generation=first["generation"],
    )
    second = store.claim_next(claimed_at=NOW + 11)
    assert second is not None and second["state"] == "authorizing"
    assert second["execution_id"] != first["execution_id"]


def test_authorization_expiry_progresses_to_refundable_then_refunded(tmp_path):
    store = _store(tmp_path)
    store.request_prepare(
        authority=_authority(),
        sponsor_address=SPONSOR,
        idempotency_key="prepare-progression-0001",
        replace_expired=False,
        requested_at=NOW,
    )
    store.claim_next(claimed_at=NOW + 1)
    store.mark_plan_ready(
        execution_id=EXECUTION_ID,
        generation=1,
        plan_commitment=PLAN,
        authorization_expires_at=NOW + 60,
        recorded_at=NOW + 2,
    )
    expired = store.mark_expired(
        execution_id=EXECUTION_ID,
        generation=1,
        recorded_at=NOW + 61,
    )
    assert expired["state"] == "expired"
    assert expired["retryable"] is True

    refundable = store.mark_reservation_expired(
        execution_id=EXECUTION_ID,
        generation=1,
        terminal_evidence=_terminal_evidence("reservation_expired"),
        recorded_at=NOW + 3_700,
    )
    assert refundable["state"] == "reservation_expired"
    assert refundable["retryable"] is False
    assert refundable["terminal_evidence"]["outcome"] == (
        "reservation_expired"
    )
    assert refundable["terminal_evidence"]["block_number"] == "12345679"

    refunded_evidence = {
        **_terminal_evidence("reservation_refunded"),
        "block_number": 12_345_680,
        "block_hash": "0x" + "a" * 64,
        "block_timestamp": NOW + 3_800,
        "source_commitment": "sha256:" + "b" * 64,
    }
    refunded = store.mark_refunded(
        execution_id=EXECUTION_ID,
        generation=1,
        terminal_evidence=refunded_evidence,
        recorded_at=NOW + 3_800,
    )
    assert refunded["state"] == "refunded"
    assert refunded["terminal_evidence"]["outcome"] == (
        "reservation_refunded"
    )
    assert refunded["terminal_evidence"]["block_number"] == "12345680"
