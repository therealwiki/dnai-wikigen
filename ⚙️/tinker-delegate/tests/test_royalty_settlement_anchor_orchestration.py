from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from tinker_delegate.execution_policy_anchor import (
    AnchorProjectionRecord,
    AnchoredExecutionPolicyCoordinator,
    ExecutionPolicyAnchorMismatch,
    ExecutionPolicyRoyaltyAnchorPending,
    ZERO_BYTES32,
    execution_policy_release_marker,
)
from tinker_delegate.execution_policy_store import (
    ZERO_DECISION_HASH,
    ExecutionPolicyStore,
    ExecutionPolicyStoreCorrupt,
)
from tests.test_execution_policy_store import _result
from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    compute_owner_amounts_hash,
)
from tinker_delegate.royalty_qvl_client import PreparedRoyaltyAttestation
from tinker_delegate.royalty_settlement_wallet_plan import (
    RoyaltySettlementWalletPlan,
)
from tests.execution_policy_anchor_fakes import (
    ANCHOR_ADDRESS,
    WRITER_ADDRESS,
    WRITER_RELEASE,
    MemoryExecutionPolicyAnchorGateway,
)
from tests.test_royalty_qvl_client import QUOTE, client_for, signed_challenge
from tests.test_royalty_settlement_authorization import (
    NOW,
    make_intent,
    make_plan,
)


RECIPIENTS = (
    DistributionRecipient("0x" + "81" * 20, 700),
    DistributionRecipient("0x" + "82" * 20, 300),
)
RELEASE_AUTHORITY_SHA256 = "sha256:" + "a7" * 32


def _release_marker():
    return execution_policy_release_marker(
        final_authority_sha256=RELEASE_AUTHORITY_SHA256,
        contract_address=ANCHOR_ADDRESS,
        writer_address=WRITER_ADDRESS,
        writer_release_commitment=WRITER_RELEASE,
    )


def _intent(sequence: int, *, expiry: int = NOW + 30):
    return replace(
        make_intent(expiry=expiry),
        anchor_sequence=sequence,
        owners_amounts_hash=compute_owner_amounts_hash(RECIPIENTS),
    )


def _prepared() -> PreparedRoyaltyAttestation:
    return PreparedRoyaltyAttestation(
        challenge=signed_challenge(),
        quote="0x" + QUOTE.hex(),
        expectation={},
        attestation_evidence_hash="0x" + "91" * 32,
    )


@pytest.fixture
def anchored_store():
    with tempfile.TemporaryDirectory() as directory:
        store = ExecutionPolicyStore(
            Path(directory) / "policy.json",
            integrity_key=bytes(range(32)),
        )
        gateway = MemoryExecutionPolicyAnchorGateway(
            release_marker=_release_marker()
        )
        yield store, gateway, AnchoredExecutionPolicyCoordinator(store, gateway)


def test_release_marker_is_the_only_chain_record_for_an_empty_local_store(tmp_path):
    store = ExecutionPolicyStore(
        tmp_path / "policy.json",
        integrity_key=bytes(range(32)),
    )
    marker = _release_marker()
    gateway = MemoryExecutionPolicyAnchorGateway(release_marker=marker)
    coordinator = AnchoredExecutionPolicyCoordinator(store, gateway)

    snapshot = coordinator.ensure_synchronized(now=NOW, reconcile=True)

    assert store.anchor_projection() == ()
    assert gateway.records == []
    assert snapshot.global_sequence == 1
    assert snapshot.global_head == marker.new_global_head


def test_production_coordinator_rejects_a_missing_release_marker(tmp_path):
    store = ExecutionPolicyStore(
        tmp_path / "policy.json",
        integrity_key=bytes(range(32)),
    )
    gateway = MemoryExecutionPolicyAnchorGateway()
    gateway.allow_zero_genesis_for_test = False

    with pytest.raises(ExecutionPolicyAnchorMismatch, match="marker is required"):
        AnchoredExecutionPolicyCoordinator(store, gateway)


def test_first_local_policy_record_is_on_chain_sequence_two(tmp_path):
    store = ExecutionPolicyStore(
        tmp_path / "policy.json",
        integrity_key=bytes(range(32)),
    )
    gateway = MemoryExecutionPolicyAnchorGateway(release_marker=_release_marker())
    coordinator = AnchoredExecutionPolicyCoordinator(store, gateway)

    record = coordinator.append_and_anchor(
        surface="compute_dispatch",
        resource_id="first-local-policy",
        result=_result(data_classes=["clinical-summary"]),
        recorded_at=NOW,
        expires_at=NOW + 120,
        expected_previous_decision_hash=ZERO_DECISION_HASH,
        now=NOW,
    )

    assert record["sequence"] == 1
    assert record["rollback_anchor"]["global_sequence"] == 2
    assert record["rollback_anchor"]["resource_sequence"] == 2
    assert gateway.records[0].sequence == 1


def test_wrong_or_unanchored_release_marker_fails_closed(tmp_path):
    store = ExecutionPolicyStore(
        tmp_path / "policy.json",
        integrity_key=bytes(range(32)),
    )
    wrong = replace(_release_marker(), new_global_head=ZERO_BYTES32)
    with pytest.raises(ExecutionPolicyAnchorMismatch, match="does not match"):
        AnchoredExecutionPolicyCoordinator(
            store,
            MemoryExecutionPolicyAnchorGateway(release_marker=wrong),
        )

    gateway = MemoryExecutionPolicyAnchorGateway(release_marker=_release_marker())
    gateway.snapshot_overrides.update(
        global_sequence=0,
        global_head=ZERO_BYTES32,
    )
    coordinator = AnchoredExecutionPolicyCoordinator(store, gateway)
    with pytest.raises(ExecutionPolicyAnchorMismatch, match="marker is missing"):
        coordinator.ensure_synchronized(now=NOW, reconcile=True)


def _prepare(
    coordinator,
    *,
    recorded_at: int = NOW,
    expiry: int = NOW + 30,
    replace_expired: bool = False,
):
    client = client_for()

    def authorize_prepared(intent, _prepared_value, *, now):
        assert now == recorded_at
        return make_plan(intent=intent)

    with patch.object(
        client,
        "authorize_prepared",
        side_effect=authorize_prepared,
    ):
        return coordinator.prepare_and_anchor_royalty_settlement(
            qvl_client=client,
            prepared_attestation=_prepared(),
            intent_factory=lambda sequence: _intent(sequence, expiry=expiry),
            recipients=RECIPIENTS,
            refund_after=NOW + 120,
            recorded_at=recorded_at,
            replace_expired=replace_expired,
        )


def test_exact_plan_is_durable_before_external_broadcast_and_only_then_exposed(
    anchored_store,
):
    store, gateway, coordinator = anchored_store
    wallet_plan, snapshot = _prepare(coordinator)

    assert len(gateway.records) == 1
    assert store.royalty_wallet_plan(
        plan_commitment=wallet_plan.plan_commitment
    ) == wallet_plan
    confirmation = store.royalty_anchor_confirmation(
        plan_commitment=wallet_plan.plan_commitment
    )
    assert confirmation is not None
    assert confirmation["sequence"] == 1
    assert confirmation["chain_sequence"] == 2
    sponsor = coordinator.finalized_royalty_wallet_plan(
        plan_commitment=wallet_plan.plan_commitment,
        now=NOW,
    )
    assert sponsor["schema"] == (
        "dnai.collaboration.royalty-settlement-wallet-plan.v1"
    )
    assert sponsor["value"] == "0x0"
    assert sponsor["function"] == "settleReserved"
    assert sponsor["anchor_finality"]["resource_sequence"] == "2"
    assert sponsor["authorization"]["anchor_sequence"] == "2"
    assert sponsor["authorization_expires_at"] == str(NOW + 30)
    assert sponsor["authorization"]["expiry"] == str(NOW + 30)
    assert sponsor["refund_after"] == str(NOW + 120)
    assert "cast_command" not in json.dumps(sponsor)
    assert "private-key" not in json.dumps(sponsor)
    assert snapshot.resource_decision_head == wallet_plan.anchor_decision_hash


def test_sponsor_plan_is_rechecked_after_finality_before_delivery(
    anchored_store,
):
    _store, _gateway, coordinator = anchored_store
    wallet_plan, _snapshot = _prepare(
        coordinator,
        expiry=NOW + 31,
    )
    with patch(
        "tinker_delegate.execution_policy_anchor._advancing_validation_time",
        return_value=NOW + 2,
    ), pytest.raises(
        ExecutionPolicyAnchorMismatch,
        match="minimum sponsor broadcast window",
    ):
        coordinator.finalized_royalty_wallet_plan(
            plan_commitment=wallet_plan.plan_commitment,
            now=NOW,
        )


def test_sponsor_wallet_uint256_fields_are_canonical_strings_above_js_safe_int():
    large_nonce = 2**53 + 17
    large_amount = 2**53 + 101
    recipients = (
        DistributionRecipient(RECIPIENTS[0].owner_address, large_amount),
        DistributionRecipient(RECIPIENTS[1].owner_address, 29),
    )
    intent = replace(
        _intent(2),
        settlement_nonce=large_nonce,
        total=large_amount + 29,
        owners_amounts_hash=compute_owner_amounts_hash(recipients),
    )
    wallet_plan = RoyaltySettlementWalletPlan.create(
        authorized_plan=make_plan(intent=intent),
        recipients=recipients,
        refund_after=NOW + 120,
    )
    gateway = MemoryExecutionPolicyAnchorGateway(release_marker=_release_marker())
    gateway.records.append(
        AnchorProjectionRecord(
            sequence=1,
            chain_sequence=2,
            resource_id_hash=wallet_plan.anchor_resource_hash[2:],
            decision_hash=wallet_plan.anchor_decision_hash[2:],
        )
    )
    sponsor = wallet_plan.to_sponsor_dict(
        finalized_anchor=gateway.finalized_snapshot(
            resource_id_hash=wallet_plan.anchor_resource_hash[2:],
            decision_hash=wallet_plan.anchor_decision_hash[2:],
            now=NOW,
        ).to_bounded_dict()
    )
    round_tripped = json.loads(json.dumps(sponsor))

    assert round_tripped["settlement_nonce"] == str(large_nonce)
    assert round_tripped["authorization"]["settlement_nonce"] == str(large_nonce)
    assert round_tripped["authorization"]["total"] == str(large_amount + 29)
    assert round_tripped["amounts"] == [str(large_amount), "29"]
    assert isinstance(round_tripped["authorization_expires_at"], str)
    assert isinstance(round_tripped["refund_after"], str)
    assert isinstance(round_tripped["authorization"]["anchor_sequence"], str)
    assert isinstance(round_tripped["authorization"]["expiry"], str)
    assert round_tripped["anchor_finality"]["global_sequence"] == "2"
    assert round_tripped["anchor_finality"]["resource_sequence"] == "2"
    assert round_tripped["anchor_finality"]["decision_sequence"] == "2"
    assert isinstance(round_tripped["anchor_finality"]["block_number"], str)
    assert isinstance(round_tripped["anchor_finality"]["block_timestamp"], str)


def test_repeated_sponsor_reads_keep_first_confirmation_after_unrelated_anchor(
    anchored_store,
):
    store, _gateway, coordinator = anchored_store
    wallet_plan, _snapshot = _prepare(coordinator, expiry=NOW + 120)
    first_confirmation = store.royalty_anchor_confirmation(
        plan_commitment=wallet_plan.plan_commitment
    )
    assert first_confirmation is not None

    coordinator.append_and_anchor(
        surface="compute_dispatch",
        resource_id="later-unrelated-policy",
        result=_result(data_classes=["clinical-summary"]),
        recorded_at=NOW + 1,
        expires_at=NOW + 121,
        expected_previous_decision_hash=ZERO_DECISION_HASH,
        now=NOW + 1,
    )
    sponsor = coordinator.finalized_royalty_wallet_plan(
        plan_commitment=wallet_plan.plan_commitment,
        now=NOW + 1,
    )

    assert sponsor["anchor_finality"]["global_sequence"] == "3"
    assert sponsor["anchor_finality"]["resource_sequence"] == "2"
    assert store.royalty_anchor_confirmation(
        plan_commitment=wallet_plan.plan_commitment
    ) == first_confirmation


def test_ambiguous_broadcast_leaves_exact_plan_and_blocks_concurrent_policy_append(
    anchored_store,
):
    store, gateway, coordinator = anchored_store
    gateway.fail_next_anchor = True

    with pytest.raises(ExecutionPolicyAnchorMismatch, match="injected anchor crash"):
        _prepare(coordinator)

    projection = store.anchor_projection()
    assert len(projection) == 1
    plan = store.latest_royalty_wallet_plan(
        anchor_resource_hash="0x" + projection[0]["resource_id_hash"]
    )
    assert plan is not None
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is None
    with pytest.raises(ExecutionPolicyRoyaltyAnchorPending):
        coordinator.ensure_synchronized(now=NOW, reconcile=True)

    recovered, snapshot = coordinator.resume_royalty_settlement_anchor(
        plan_commitment=plan.plan_commitment,
        now=NOW,
    )
    assert recovered.plan_commitment == plan.plan_commitment
    assert snapshot.resource_sequence == 2
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is not None


def test_plan_expiring_during_anchor_confirmation_is_never_exposed(anchored_store):
    store, gateway, coordinator = anchored_store
    with patch(
        "tinker_delegate.execution_policy_anchor._advancing_validation_time",
        side_effect=(NOW, NOW + 31),
    ):
        with pytest.raises(
            ExecutionPolicyAnchorMismatch,
            match="minimum sponsor broadcast window",
        ):
            _prepare(coordinator, expiry=NOW + 30)

    assert len(gateway.records) == 1
    plan = store.latest_royalty_wallet_plan(
        anchor_resource_hash="0x" + store.anchor_projection()[0]["resource_id_hash"]
    )
    assert plan is not None
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is None

    # Recovery may persist the already-finalized anchor, but it never revives
    # expired calldata for the sponsor wallet.
    coordinator.resume_royalty_settlement_anchor(
        plan_commitment=plan.plan_commitment,
        now=NOW + 31,
    )
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is not None
    with pytest.raises(
        ExecutionPolicyAnchorMismatch,
        match="minimum sponsor broadcast window",
    ):
        coordinator.finalized_royalty_wallet_plan(
            plan_commitment=plan.plan_commitment,
            now=NOW + 31,
        )


def test_finalized_anchor_survives_confirmation_journal_crash(anchored_store):
    store, gateway, coordinator = anchored_store
    real_confirm = store.confirm_royalty_anchor
    with patch.object(
        store,
        "confirm_royalty_anchor",
        side_effect=RuntimeError("injected confirmation crash"),
    ):
        with pytest.raises(RuntimeError, match="confirmation crash"):
            _prepare(coordinator)

    assert len(gateway.records) == 1
    plan = store.latest_royalty_wallet_plan(
        anchor_resource_hash="0x" + store.anchor_projection()[0]["resource_id_hash"]
    )
    assert plan is not None
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is None

    with patch.object(store, "confirm_royalty_anchor", wraps=real_confirm):
        recovered, _snapshot = coordinator.resume_royalty_settlement_anchor(
            plan_commitment=plan.plan_commitment,
            now=NOW,
        )
    assert recovered.plan_commitment == plan.plan_commitment
    assert store.royalty_anchor_confirmation(
        plan_commitment=plan.plan_commitment
    ) is not None


def test_expired_unbroadcast_plan_may_only_be_replaced_with_same_authority(
    anchored_store,
):
    store, _gateway, _coordinator = anchored_store
    first = RoyaltySettlementWalletPlan.create(
        authorized_plan=make_plan(intent=_intent(2, expiry=NOW + 30)),
        recipients=RECIPIENTS,
        refund_after=NOW + 120,
    )
    store.append_royalty_wallet_plan(
        wallet_plan=first,
        chain_sequence=2,
        recorded_at=NOW,
        replace_expired=False,
    )
    second = RoyaltySettlementWalletPlan.create(
        authorized_plan=make_plan(intent=_intent(3, expiry=NOW + 60)),
        recipients=RECIPIENTS,
        refund_after=NOW + 120,
    )
    with pytest.raises(Exception, match="not expired"):
        store.append_royalty_wallet_plan(
            wallet_plan=second,
            chain_sequence=3,
            recorded_at=NOW + 29,
            replace_expired=True,
        )
    replaced = store.append_royalty_wallet_plan(
        wallet_plan=second,
        chain_sequence=3,
        recorded_at=NOW + 30,
        replace_expired=True,
    )
    assert replaced["sequence"] == 2

    drifted_recipients = (
        DistributionRecipient(RECIPIENTS[0].owner_address, 600),
        DistributionRecipient(RECIPIENTS[1].owner_address, 400),
    )
    drifted_intent = replace(
        _intent(4, expiry=NOW + 90),
        owners_amounts_hash=compute_owner_amounts_hash(drifted_recipients),
    )
    drifted = RoyaltySettlementWalletPlan.create(
        authorized_plan=make_plan(intent=drifted_intent),
        recipients=drifted_recipients,
        refund_after=NOW + 120,
    )
    with pytest.raises(Exception, match="immutable authority"):
        store.append_royalty_wallet_plan(
            wallet_plan=drifted,
            chain_sequence=4,
            recorded_at=NOW + 60,
            replace_expired=True,
        )


def test_v5_store_is_rejected_without_rewriting_historical_bytes(tmp_path):
    path = tmp_path / "policy.json"
    key = bytes(range(32))
    ExecutionPolicyStore(path, integrity_key=key)
    root = json.loads(path.read_text())
    root["schema_version"] = 5
    payload = json.dumps(
        root["payload"],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    root["integrity"]["value"] = hmac.new(key, payload, hashlib.sha256).hexdigest()
    historical = (
        json.dumps(
            root,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    ).encode()
    path.write_bytes(historical)

    with pytest.raises(ExecutionPolicyStoreCorrupt, match="identity"):
        ExecutionPolicyStore(path, integrity_key=key)
    assert path.read_bytes() == historical


def test_unrelated_policy_prefix_and_expired_replacement_use_global_sequences(
    anchored_store,
):
    store, _gateway, coordinator = anchored_store
    coordinator.append_and_anchor(
        surface="compute_dispatch",
        resource_id="unrelated-job",
        result=_result(data_classes=["clinical-summary"]),
        recorded_at=NOW - 10,
        expires_at=NOW + 120,
        expected_previous_decision_hash=ZERO_DECISION_HASH,
        now=NOW,
    )

    first, first_snapshot = _prepare(coordinator)
    assert first.anchor_sequence == 3
    assert first_snapshot.resource_sequence == 3

    second, second_snapshot = _prepare(
        coordinator,
        recorded_at=NOW + 30,
        expiry=NOW + 60,
        replace_expired=True,
    )
    assert second.anchor_sequence == 4
    assert second_snapshot.resource_sequence == 4
    assert second.anchor_resource_hash == first.anchor_resource_hash
    assert second.anchor_decision_hash != first.anchor_decision_hash
    with pytest.raises(
        ExecutionPolicyAnchorMismatch,
        match="minimum sponsor broadcast window|resource head",
    ):
        coordinator.finalized_royalty_wallet_plan(
            plan_commitment=first.plan_commitment,
            now=NOW + 30,
        )
    exposed = coordinator.finalized_royalty_wallet_plan(
        plan_commitment=second.plan_commitment,
        now=NOW + 30,
    )
    assert exposed["anchor_finality"]["resource_sequence"] == "4"
