from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from tinker_delegate.collaboration_execution_evidence import (
    CollaborationExecutionWorkerHeartbeatStore,
    project_collaboration_execution_worker_capability,
)
from tinker_delegate.collaboration_execution_worker import (
    CollaborationExecutionRuntime,
)
from tinker_delegate.collaboration_royalty_settlement import (
    CollaborationRoyaltySettlementStore,
)
from tinker_delegate.config import Settings
from tinker_delegate.royalty_qvl_client import RoyaltyQvlClientError
from tests.test_collaboration_execution_evidence import (
    _bindings,
    _qvl_observation,
)


class _VaultReader:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _QvlClient:
    def __init__(self, outcomes) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[tuple[str, int]] = []
        self.closed = False

    def probe_capability(self, *, release_binding_sha256: str, now: int):
        self.calls.append((release_binding_sha256, now))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome(now)

    def close(self) -> None:
        self.closed = True


def _runtime(tmp_path, outcomes):
    bindings = _bindings()
    heartbeat_store = CollaborationExecutionWorkerHeartbeatStore(
        tmp_path / "worker-heartbeat.json",
        integrity_key=b"h" * 32,
    )
    qvl = _QvlClient(outcomes)
    vault = _VaultReader()
    runtime = CollaborationExecutionRuntime(
        worker=object(),
        vault_reader=vault,
        heartbeat_store=heartbeat_store,
        heartbeat_bindings=bindings,
        qvl_client=qvl,
        heartbeat_ttl_seconds=30,
    )
    return runtime, heartbeat_store, bindings, qvl, vault


def test_worker_refreshes_exact_qvl_capability_without_probing_every_cycle(tmp_path):
    bindings = _bindings()
    observation = lambda now: _qvl_observation(bindings, observed_at=now)
    runtime, store, bindings, qvl, _vault = _runtime(
        tmp_path,
        [observation, observation],
    )

    assert runtime.write_heartbeat(observed_at=1_800_000_000, state="ready") == (
        "authenticated_exact_capability"
    )
    runtime.write_heartbeat(observed_at=1_800_000_002, state="ready")
    assert len(qvl.calls) == 1
    runtime.write_heartbeat(observed_at=1_800_000_015, state="ready")
    assert len(qvl.calls) == 2

    heartbeat = store.read()
    assert heartbeat.qvl_reachability == "authenticated_exact_capability"
    assert heartbeat.qvl_capability_observation is not None
    capability = project_collaboration_execution_worker_capability(
        enabled=True,
        expected_bindings=bindings,
        heartbeat_store=store,
        now=1_800_000_016,
        ttl_seconds=30,
    )
    assert capability["onchain_reservation_ready"] is True
    assert capability["qvl_job_verdict_proven"] is False
    assert capability["tdx_job_attestation_proven"] is False


def test_failed_refresh_clears_previous_qvl_observation_immediately(tmp_path):
    bindings = _bindings()
    runtime, store, bindings, _qvl, _vault = _runtime(
        tmp_path,
        [
            lambda now: _qvl_observation(bindings, observed_at=now),
            RoyaltyQvlClientError("royalty_qvl_unavailable"),
        ],
    )
    runtime.write_heartbeat(observed_at=1_800_000_000, state="ready")
    assert runtime.write_heartbeat(
        observed_at=1_800_000_015,
        state="ready",
    ) == "unreachable"
    heartbeat = store.read()
    assert heartbeat.qvl_capability_observation is None
    assert heartbeat.qvl_reachability == "unreachable"
    capability = project_collaboration_execution_worker_capability(
        enabled=True,
        expected_bindings=bindings,
        heartbeat_store=store,
        now=1_800_000_016,
        ttl_seconds=30,
    )
    assert capability["gate_reason"] == "qvl_capability_unreachable"
    assert capability["onchain_reservation_ready"] is False


def test_qvl_mismatch_is_bounded_and_direct_bearer_is_not_a_settings_field(tmp_path):
    runtime, store, bindings, _qvl, _vault = _runtime(
        tmp_path,
        [RoyaltyQvlClientError("royalty_qvl_capability_mismatch")],
    )
    assert runtime.write_heartbeat(
        observed_at=1_800_000_000,
        state="ready",
    ) == "mismatch"
    assert store.read().qvl_capability_observation is None
    assert "royalty_settlement_qvl_auth_token" not in Settings.model_fields
    assert "TINKER_ROYALTY_SETTLEMENT_QVL_AUTH_TOKEN" not in str(
        store.read().to_dict()
    )


def test_runtime_closes_qvl_and_rpc_clients(tmp_path):
    bindings = _bindings()
    runtime, _store, _bindings_value, qvl, vault = _runtime(
        tmp_path,
        [lambda now: _qvl_observation(bindings, observed_at=now)],
    )
    runtime.close()
    assert qvl.closed is True
    assert vault.closed is True


def test_runtime_prepares_exact_plan_without_broadcast_then_finalizes_from_chain(
    tmp_path,
):
    now = 1_800_000_000
    execution_id = "exec_" + "a" * 64
    sponsor = "0x" + "11" * 20
    owner_a = "0x" + "22" * 20
    owner_b = "0x" + "33" * 20
    reservation = SimpleNamespace(
        settlement_id="0x" + "01" * 32,
        settlement_nonce=2**53 + 17,
        reservation_id="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash="0x" + "08" * 32,
        asset="0x" + "00" * 20,
        total=2_000,
        execution_commitment="0x" + "09" * 32,
        refund_after=now + 600,
    )
    intent = SimpleNamespace(
        chain_id=84_532,
        royalty_distributor_address="0x" + "44" * 20,
    )
    result = SimpleNamespace(
        result_commitment="sha256:" + "a" * 64,
        usage_commitment="0x" + "0b" * 32,
    )
    source = {
        "intent": intent,
        "grants": (object(), object()),
        "owner_amounts": {owner_a: 1_200, owner_b: 800},
        "funding_reservation": reservation,
        "bounded_result": result,
        "historical_royalty_observation": object(),
    }

    class Journal:
        def royalty_settlement_source(self, observed_execution_id):
            assert observed_execution_id == execution_id
            return source

    class Vault:
        def observe(self, observed_intent, *, observed_at):
            assert observed_intent is intent
            assert observed_at == now
            return object()

    finalized = {
        "chain_id": 84_532,
        "block_number": 12_345_678,
        "block_hash": "0x" + "0c" * 32,
        "block_timestamp": now + 20,
        "reservation_active": False,
        "reservation_consumed": True,
        "settlement_processed": True,
        "settlement_nonce_processed": True,
        "source_commitment": "sha256:" + "d" * 64,
    }

    class RoyaltyReader:
        final = None
        finalized_block_timestamp = None

        def settlement_precondition(self, *args, **kwargs):
            return {"settlement_state": {"settlement_processed": False}}

        def reconcile_settlement(self, *args, **kwargs):
            return {
                "state": "settled" if self.final is not None else "pending",
                "block_timestamp": (
                    self.finalized_block_timestamp
                    or kwargs["observed_at"]
                ),
                "source_commitment": "sha256:" + "d" * 64,
                "finalized_settlement": self.final,
            }

    royalty_reader = RoyaltyReader()

    class Worker:
        def __init__(self):
            self.journal = Journal()
            self.vault_reader = Vault()
            self.royalty_reader = royalty_reader

        def run_once(self, *, now):
            return {"observed_at": now}

    class Qvl:
        def prepare_attestation(self, *, now):
            return SimpleNamespace(
                challenge=SimpleNamespace(expires_at=now + 120)
            )

        def close(self):
            pass

    class PolicyStore:
        def latest_royalty_wallet_plan(self, *, anchor_resource_hash):
            assert anchor_resource_hash.startswith("0x")
            return None

    class Policy:
        store = PolicyStore()

        def prepare_and_anchor_royalty_settlement(self, **kwargs):
            prepared_intent = kwargs["intent_factory"](2)
            assert prepared_intent.settlement_nonce == 2**53 + 17
            assert prepared_intent.total == 2_000
            assert [item.amount for item in kwargs["recipients"]] == [1_200, 800]
            assert kwargs["refund_after"] == now + 600
            return (
                SimpleNamespace(
                    plan_commitment="0x" + "0e" * 32,
                    authorized_plan=SimpleNamespace(
                        authorization_expires_at=prepared_intent.expiry
                    ),
                ),
                object(),
            )

    settlement_store = CollaborationRoyaltySettlementStore(
        Path(tmp_path) / "royalty-settlement.json",
        integrity_key=b"s" * 32,
    )
    settlement_store.request_prepare(
        authority={
            "execution_id": execution_id,
            "sponsor_address": sponsor,
            "funding_reservation_id": reservation.reservation_id,
            "settlement_id": reservation.settlement_id,
            "settlement_nonce": reservation.settlement_nonce,
            "refund_after": reservation.refund_after,
        },
        sponsor_address=sponsor,
        idempotency_key="prepare-settlement-0001",
        replace_expired=False,
        requested_at=now,
    )
    bindings = _bindings()
    runtime = CollaborationExecutionRuntime(
        worker=Worker(),
        vault_reader=_VaultReader(),
        heartbeat_store=CollaborationExecutionWorkerHeartbeatStore(
            Path(tmp_path) / "heartbeat.json",
            integrity_key=b"h" * 32,
        ),
        heartbeat_bindings=bindings,
        qvl_client=Qvl(),
        heartbeat_ttl_seconds=30,
        settlement_store=settlement_store,
        policy_coordinator=Policy(),
        royalty_release=object(),
    )
    prepared = runtime.process_royalty_settlement_once(now=now)
    assert prepared["action"] == "settlement_plan_dual_authorized_and_anchored"
    assert prepared["wallet_broadcast_performed_by_worker"] is False
    status = settlement_store.record(execution_id)
    assert status is not None and status["state"] == "plan_ready"

    royalty_reader.finalized_block_timestamp = now + 119
    pending = runtime.process_royalty_settlement_once(now=now + 121)
    assert pending["reconciliation"]["action"] == "settlement_finality_pending"
    assert settlement_store.record(execution_id)["state"] == "plan_ready"

    royalty_reader.final = finalized
    royalty_reader.finalized_block_timestamp = now + 122
    reconciled = runtime.process_royalty_settlement_once(now=now + 122)
    assert reconciled["reconciliation"]["action"] == "settlement_finalized"
    public = settlement_store.status(
        authority={
            "execution_id": execution_id,
            "sponsor_address": sponsor,
            "funding_reservation_id": reservation.reservation_id,
            "settlement_id": reservation.settlement_id,
            "settlement_nonce": reservation.settlement_nonce,
            "refund_after": reservation.refund_after,
        },
        sponsor_address=sponsor,
        wallet_plan=None,
    )
    assert public["state"] == "settled"
    assert public["settlement_nonce"] == str(2**53 + 17)
    assert public["finalized_settlement"]["block_number"] == "12345678"


def _authorization_runtime(tmp_path, qvl, monotonic_clock):
    now = 1_800_000_000
    execution_id = "exec_" + "c" * 64
    sponsor = "0x" + "11" * 20
    reservation = SimpleNamespace(
        settlement_id="0x" + "01" * 32,
        settlement_nonce=2**53 + 19,
        reservation_id="0x" + "02" * 32,
        room_commitment="0x" + "03" * 32,
        room_state_commitment="0x" + "04" * 32,
        query_commitment="0x" + "05" * 32,
        grant_set_commitment="0x" + "06" * 32,
        allocation_commitment="0x" + "07" * 32,
        owners_amounts_hash="0x" + "08" * 32,
        asset="0x" + "00" * 20,
        total=2_000,
        execution_commitment="0x" + "09" * 32,
        refund_after=now + 600,
    )
    intent = SimpleNamespace(
        chain_id=84_532,
        royalty_distributor_address="0x" + "44" * 20,
    )
    source = {
        "intent": intent,
        "grants": (object(),),
        "owner_amounts": {"0x" + "22" * 20: 2_000},
        "funding_reservation": reservation,
        "bounded_result": SimpleNamespace(
            result_commitment="sha256:" + "a" * 64,
            usage_commitment="0x" + "0b" * 32,
        ),
        "historical_royalty_observation": object(),
    }

    class Journal:
        def royalty_settlement_source(self, observed_execution_id):
            assert observed_execution_id == execution_id
            return source

    class Vault:
        observed_at = None

        def observe(self, observed_intent, *, observed_at):
            assert observed_intent is intent
            self.observed_at = observed_at
            return object()

    class RoyaltyReader:
        precondition_at = None
        outcome = "pending"
        terminal_evidence = None

        def reconcile_settlement(self, *args, **kwargs):
            return {
                "state": self.outcome,
                "block_timestamp": kwargs["observed_at"],
                "source_commitment": "sha256:" + "d" * 64,
                "finalized_settlement": None,
                "terminal_evidence": self.terminal_evidence,
            }

        def settlement_precondition(self, *args, **kwargs):
            self.precondition_at = kwargs["observed_at"]
            return {"settlement_state": {"settlement_processed": False}}

    vault = Vault()
    royalty_reader = RoyaltyReader()

    class Worker:
        def __init__(self):
            self.journal = Journal()
            self.vault_reader = vault
            self.royalty_reader = royalty_reader

    class PolicyStore:
        def latest_royalty_wallet_plan(self, *, anchor_resource_hash):
            return None

    class Policy:
        store = PolicyStore()
        called = False

        def prepare_and_anchor_royalty_settlement(self, **kwargs):
            self.called = True
            raise AssertionError("an eroded authorization must not be anchored")

    settlement_store = CollaborationRoyaltySettlementStore(
        Path(tmp_path) / "authorization-settlement.json",
        integrity_key=b"s" * 32,
    )
    settlement_store.request_prepare(
        authority={
            "execution_id": execution_id,
            "sponsor_address": sponsor,
            "funding_reservation_id": reservation.reservation_id,
            "settlement_id": reservation.settlement_id,
            "settlement_nonce": reservation.settlement_nonce,
            "refund_after": reservation.refund_after,
        },
        sponsor_address=sponsor,
        idempotency_key="prepare-authorization-0001",
        replace_expired=False,
        requested_at=now,
    )
    bindings = _bindings()
    policy = Policy()
    runtime = CollaborationExecutionRuntime(
        worker=Worker(),
        vault_reader=_VaultReader(),
        heartbeat_store=CollaborationExecutionWorkerHeartbeatStore(
            Path(tmp_path) / "authorization-heartbeat.json",
            integrity_key=b"h" * 32,
        ),
        heartbeat_bindings=bindings,
        qvl_client=qvl,
        heartbeat_ttl_seconds=30,
        settlement_store=settlement_store,
        policy_coordinator=policy,
        royalty_release=object(),
        monotonic_clock=monotonic_clock,
    )
    return runtime, settlement_store, vault, royalty_reader, policy, execution_id


def test_qvl_elapsed_time_is_rechecked_before_anchor_authorization(tmp_path):
    now = 1_800_000_000

    class Clock:
        value = 0.0

        def __call__(self):
            return self.value

    clock = Clock()

    class Qvl:
        def prepare_attestation(self, *, now):
            clock.value = 2.0
            return SimpleNamespace(
                challenge=SimpleNamespace(expires_at=now + 31)
            )

    runtime, store, vault, reader, policy, execution_id = (
        _authorization_runtime(tmp_path, Qvl(), clock)
    )
    cycle = runtime.process_royalty_settlement_once(now=now)
    assert cycle["action"] == "settlement_reconciliation_hold"
    assert vault.observed_at == now + 2
    assert reader.precondition_at == now + 2
    assert policy.called is False
    record = store.record(execution_id)
    assert record is not None
    assert record["state"] == "reconciliation_hold"
    assert record["failure_code"] == "settlement_authority_invalidated"


def test_permanent_qvl_drift_holds_while_transport_outage_rotates(tmp_path):
    class Clock:
        def __call__(self):
            return 0.0

    class Qvl:
        def __init__(self, code):
            self.code = code

        def prepare_attestation(self, *, now):
            raise RoyaltyQvlClientError(self.code)

    permanent = _authorization_runtime(
        tmp_path / "permanent",
        Qvl("royalty_dstack_release_drift"),
        Clock(),
    )
    permanent_cycle = permanent[0].process_royalty_settlement_once(
        now=1_800_000_000
    )
    assert permanent_cycle["retryable"] is False
    permanent_record = permanent[1].record(permanent[5])
    assert permanent_record["state"] == "reconciliation_hold"
    assert permanent_record["failure_code"] == (
        "settlement_qvl_authority_invalid"
    )

    temporary = _authorization_runtime(
        tmp_path / "temporary",
        Qvl("royalty_qvl_unavailable"),
        Clock(),
    )
    temporary_cycle = temporary[0].process_royalty_settlement_once(
        now=1_800_000_000
    )
    assert temporary_cycle["retryable"] is True
    temporary_record = temporary[1].record(temporary[5])
    assert temporary_record["state"] == "authorizing"
    assert temporary_record["failure_code"] is None


def test_finalized_refund_progresses_even_before_qvl_authorization(tmp_path):
    class Clock:
        def __call__(self):
            return 0.0

    class Qvl:
        def prepare_attestation(self, *, now):
            raise AssertionError("terminal reservation must not reach QVL")

    runtime, store, _vault, reader, _policy, execution_id = (
        _authorization_runtime(tmp_path, Qvl(), Clock())
    )
    reservation_id = store.record(execution_id)["funding_reservation_id"]

    def terminal(outcome, *, block_number, deposited):
        return {
            "outcome": outcome,
            "chain_id": 84_532,
            "block_number": block_number,
            "block_hash": "0x" + ("e" if deposited else "f") * 64,
            "block_timestamp": (
                1_800_000_700 if deposited else 1_800_000_800
            ),
            "funding_reservation_id": reservation_id,
            "reservation_storage_status": (
                "active"
                if outcome == "reservation_expired"
                else "refunded"
            ),
            "reservation_active": False,
            "reservation_consumed": False,
            "reservation_deposited_amount": deposited,
            "settlement_processed": False,
            "settlement_nonce_processed": False,
            "source_commitment": "sha256:" + (
                "2" if deposited else "3"
            ) * 64,
        }

    reader.outcome = "expired_unconsumed"
    reader.terminal_evidence = terminal(
        "reservation_expired",
        block_number=12_345_679,
        deposited=2_000,
    )
    refundable = runtime.process_royalty_settlement_once(
        now=1_800_000_700
    )
    assert refundable["reconciliation"]["action"] == (
        "settlement_reservation_expired"
    )
    record = store.record(execution_id)
    assert record["state"] == "reservation_expired"
    assert record["terminal_evidence"]["outcome"] == (
        "reservation_expired"
    )

    reader.outcome = "refunded"
    reader.terminal_evidence = terminal(
        "reservation_refunded",
        block_number=12_345_680,
        deposited=0,
    )
    refunded = runtime.process_royalty_settlement_once(
        now=1_800_000_800
    )
    assert refunded["reconciliation"]["action"] == (
        "settlement_reservation_refunded"
    )
    final = store.record(execution_id)
    assert final["state"] == "refunded"
    assert final["terminal_evidence"]["outcome"] == (
        "reservation_refunded"
    )
