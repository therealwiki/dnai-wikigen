"""Rollback-witness tests for the execution-policy HMAC journal."""

from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import httpx
from eth_abi import encode
from eth_hash.auto import keccak

from tests.execution_policy_anchor_fakes import (
    ANCHOR_ADDRESS,
    MemoryExecutionPolicyAnchorGateway,
    WRITER_ADDRESS,
    WRITER_RELEASE,
)
from tinker_delegate import execution_policy_anchor as anchor
from tinker_delegate.execution_policy_anchor import (
    AnchorProjectionRecord,
    AnchoredExecutionPolicyCoordinator,
    DstackExecutionPolicyAnchorSigner,
    ExecutionPolicyAnchorMismatch,
    ExecutionPolicyAnchorSignerUnavailable,
    ExecutionPolicyAnchorUnavailable,
    HttpsExecutionPolicyAnchorGateway,
    PreparedAnchorTransaction,
    ZERO_BYTES32,
    compute_anchor_head,
    verify_live_execution_policy_release_binding,
)
from tinker_delegate.execution_policy_store import (
    ExecutionPolicyNotPassed,
    ExecutionPolicyStore,
    ZERO_DECISION_HASH,
    execution_policy_approver_root_hash,
)
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult


NOW = 1_900_000_000
OWNER = "0x" + "11" * 20
WRITER = "0x" + "22" * 20
CONTRACT = "0x" + "33" * 20
RELEASE = "0x" + "44" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "45" * 32
CODE = bytes.fromhex("6001600055")
CODE_HASH = "0x" + keccak(CODE).hex()
BLOCK_99 = "0x" + "99" * 32
BLOCK_100 = "0x" + "aa" * 32


def _result(decision: PolicyDecision = PolicyDecision.PASS) -> PolicyGateResult:
    return PolicyGateResult(
        decision=decision,
        corpus_ref="corpus://sealed",
        stage=4,
        reason_code={
            PolicyDecision.PASS: "policy_passed",
            PolicyDecision.HOLD: "human_review_required",
            PolicyDecision.DENY: "purpose_denied",
        }[decision],
        request_hash="1" * 64,
        policy_hash="2" * 64,
    )


def _append_kwargs(
    resource_id: str,
    *,
    previous: str = ZERO_DECISION_HASH,
    decision: PolicyDecision = PolicyDecision.PASS,
    recorded_at: int = NOW,
) -> dict:
    passed = decision is PolicyDecision.PASS
    return {
        "surface": "arena_execution",
        "resource_id": resource_id,
        "result": _result(decision),
        "recorded_at": recorded_at,
        "expires_at": recorded_at + 300,
        "expected_previous_decision_hash": previous,
        "approver_hash": "3" * 64 if passed else "",
        "approval_hash": "4" * 64 if passed else "",
        "approval_domain_hash": "5" * 64 if passed else "",
        "approver_root_hash": (
            execution_policy_approver_root_hash({"3" * 64})
            if passed
            else ""
        ),
    }


class _RpcHarness:
    def __init__(self) -> None:
        self.chain_id = 84_532
        self.code = CODE
        self.block_timestamp = NOW - 10
        self.finalized_number = 99
        self.state = {
            "owner": OWNER,
            "pending_owner": anchor.ZERO_ADDRESS,
            "writer": WRITER,
            "writer_release": RELEASE,
            "pending_writer": anchor.ZERO_ADDRESS,
            "pending_writer_release": ZERO_BYTES32,
            "pending_writer_at": 0,
            "frozen": True,
            "paused": False,
            "global_sequence": 0,
            "global_head": ZERO_BYTES32,
            "resource_head": ZERO_BYTES32,
            "resource_sequence": 0,
            "decision_sequence": 0,
        }
        self.calls: list[dict] = []
        self.broadcast_error = ""
        self.client = httpx.Client(
            transport=httpx.MockTransport(self._handle),
            timeout=1.0,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self) -> None:
        self.client.close()

    def _handle(self, request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        self.calls.append(payload)
        method = payload["method"]
        params = payload["params"]
        if method == "eth_chainId":
            result = hex(self.chain_id)
        elif method == "eth_getBlockByNumber":
            if params[0] == "latest":
                number = 100
            elif params[0] == "finalized":
                number = self.finalized_number
            else:
                number = int(params[0], 16)
            result = {
                "number": hex(number),
                "timestamp": hex(self.block_timestamp),
                "hash": BLOCK_100 if number == 100 else BLOCK_99,
            }
        elif method == "eth_getCode":
            result = "0x" + self.code.hex()
        elif method == "eth_call":
            result = "0x" + self._call_result(bytes.fromhex(params[0]["data"][2:])).hex()
        elif method == "eth_sendRawTransaction":
            if self.broadcast_error:
                return self._response(
                    payload,
                    error={"code": -32000, "message": self.broadcast_error},
                )
            result = "0x" + keccak(bytes.fromhex(params[0][2:])).hex()
        elif method == "eth_getTransactionCount":
            self.assert_latest_nonce_tag = params[1]
            result = "0x4"
        elif method == "eth_gasPrice":
            result = "0x3b9aca00"
        elif method == "eth_estimateGas":
            result = "0x186a0"
        else:
            raise AssertionError(f"unexpected RPC method {method}")
        return self._response(payload, result=result)

    @staticmethod
    def _response(payload, *, result=None, error=None):
        body = {"jsonrpc": "2.0", "id": payload["id"]}
        if error is not None:
            body["error"] = error
        else:
            body["result"] = result
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json=body,
        )

    @staticmethod
    def _address_word(value: str) -> bytes:
        return bytes.fromhex(value[2:]).rjust(32, b"\0")

    def _call_result(self, data: bytes) -> bytes:
        selector = data[:4]
        state = self.state
        mapping = {
            anchor._OWNER: self._address_word(state["owner"]),
            anchor._PENDING_OWNER: self._address_word(state["pending_owner"]),
            anchor._WRITER: self._address_word(state["writer"]),
            anchor._WRITER_RELEASE: bytes.fromhex(state["writer_release"][2:]),
            anchor._PENDING_WRITER: self._address_word(state["pending_writer"]),
            anchor._PENDING_WRITER_RELEASE: bytes.fromhex(
                state["pending_writer_release"][2:]
            ),
            anchor._PENDING_WRITER_AT: int(state["pending_writer_at"]).to_bytes(32, "big"),
            anchor._WRITER_ROTATIONS_FROZEN: int(state["frozen"]).to_bytes(32, "big"),
            anchor._PAUSED: int(state["paused"]).to_bytes(32, "big"),
            anchor._GLOBAL_SEQUENCE: int(state["global_sequence"]).to_bytes(32, "big"),
            anchor._GLOBAL_HEAD: bytes.fromhex(state["global_head"][2:]),
            anchor._RESOURCE_DECISION_HEAD: bytes.fromhex(state["resource_head"][2:]),
            anchor._RESOURCE_SEQUENCE: int(state["resource_sequence"]).to_bytes(32, "big"),
            anchor._DECISION_SEQUENCE: int(state["decision_sequence"]).to_bytes(32, "big"),
        }
        if selector not in mapping:
            raise AssertionError(f"unexpected selector 0x{selector.hex()}")
        return mapping[selector]


def _gateway(harness: _RpcHarness, **overrides) -> HttpsExecutionPolicyAnchorGateway:
    values = {
        "contract_address": CONTRACT,
        "runtime_code_hash": CODE_HASH,
        "writer_address": WRITER,
        "writer_release_commitment": RELEASE,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "confirmations": 2,
        "max_block_age_seconds": 3_600,
        "max_future_block_skew_seconds": 30,
        "client": harness.client,
    }
    values.update(overrides)
    return HttpsExecutionPolicyAnchorGateway(
        "https://base.example.test",
        **values,
    )


class AnchorGatewayTest(unittest.TestCase):
    def test_pins_every_read_to_one_finalized_canonical_block(self):
        harness = _RpcHarness()
        gateway = _gateway(harness)
        snapshot = gateway.finalized_snapshot(
            resource_id_hash="6" * 64,
            decision_hash="7" * 64,
            now=NOW,
        )

        self.assertEqual(snapshot.block_number, 99)
        self.assertEqual(snapshot.block_hash, BLOCK_99)
        self.assertEqual(snapshot.writer, WRITER)
        self.assertEqual(snapshot.latest_block_number, 100)
        self.assertEqual(snapshot.rpc_finalized_block_number, 99)
        self.assertEqual(snapshot.rpc_finalized_block_hash, BLOCK_99)
        self.assertEqual(snapshot.minimum_confirmation_depth, 2)
        self.assertEqual(snapshot.observed_confirmation_depth, 2)
        bounded = snapshot.to_bounded_dict()
        self.assertEqual(
            bounded["status"], "rpc_reported_finalized_release_match"
        )
        self.assertEqual(
            bounded["verification_model"],
            "single_rpc_reported_finalized_with_confirmation_depth",
        )
        self.assertFalse(bounded["independent_rpc_quorum_verified"])
        self.assertFalse(bounded["consensus_proof_verified"])
        pinned = [
            call
            for call in harness.calls
            if call["method"] in {"eth_getCode", "eth_call"}
        ]
        self.assertGreater(len(pinned), 10)
        for call in pinned:
            self.assertEqual(
                call["params"][-1],
                {"blockHash": BLOCK_99, "requireCanonical": True},
            )
        harness.close()

    def test_uses_older_of_rpc_finalized_tag_and_confirmation_depth(self):
        harness = _RpcHarness()
        harness.finalized_number = 100
        gateway = _gateway(harness, confirmations=12)
        snapshot = gateway.finalized_snapshot(now=NOW)

        self.assertEqual(snapshot.block_number, 89)
        self.assertEqual(snapshot.latest_block_number, 100)
        self.assertEqual(snapshot.rpc_finalized_block_number, 100)
        self.assertEqual(snapshot.rpc_finalized_block_hash, BLOCK_100)
        self.assertEqual(snapshot.observed_confirmation_depth, 12)
        self.assertIn(
            "finalized",
            [
                call["params"][0]
                for call in harness.calls
                if call["method"] == "eth_getBlockByNumber"
            ],
        )
        harness.close()

    def test_wrong_chain_runtime_writer_release_and_governance_state_fail(self):
        harness = _RpcHarness()
        harness.chain_id = 1
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            _gateway(harness)
        harness.close()

        cases = (
            ("code", b"\x60\x00"),
            ("writer", "0x" + "77" * 20),
            ("writer_release", "0x" + "77" * 32),
            ("pending_writer", "0x" + "77" * 20),
            ("pending_writer_release", "0x" + "77" * 32),
            ("pending_writer_at", 1),
            ("frozen", False),
            ("paused", True),
        )
        for key, value in cases:
            with self.subTest(key=key):
                harness = _RpcHarness()
                if key == "code":
                    harness.code = value
                else:
                    harness.state[key] = value
                gateway = _gateway(harness)
                with self.assertRaises(ExecutionPolicyAnchorMismatch):
                    gateway.finalized_snapshot(now=NOW)
                harness.close()

    def test_stale_and_future_finalized_blocks_fail_closed(self):
        for timestamp, error in (
            (NOW - 301, ExecutionPolicyAnchorUnavailable),
            (NOW + 31, ExecutionPolicyAnchorMismatch),
        ):
            harness = _RpcHarness()
            harness.block_timestamp = timestamp
            gateway = _gateway(harness, max_block_age_seconds=300)
            with self.assertRaises(error):
                gateway.finalized_snapshot(now=NOW)
            harness.close()

    def test_injected_validation_clock_advances_during_confirmation(self):
        with patch.object(anchor.time, "monotonic", return_value=131.9):
            self.assertEqual(
                anchor._advancing_validation_time(NOW, 100.0),
                NOW + 31,
            )
            self.assertIsNone(
                anchor._advancing_validation_time(None, 100.0)
            )

    def test_known_transaction_replay_is_idempotent(self):
        harness = _RpcHarness()
        harness.broadcast_error = "already known"
        gateway = _gateway(harness)
        raw = "0x01"
        prepared = PreparedAnchorTransaction(
            tx_hash="0x" + keccak(bytes.fromhex(raw[2:])).hex(),
            raw_transaction=raw,
            expected_global_sequence=0,
            expected_global_head=ZERO_BYTES32,
            resource_id_hash="6" * 64,
            expected_resource_head=ZERO_BYTES32,
            decision_hash="7" * 64,
            target_sequence=1,
            target_global_head="0x" + "8" * 64,
        )
        gateway.broadcast(prepared)
        harness.close()

    def test_read_only_gateway_never_prepares_a_write(self):
        harness = _RpcHarness()
        gateway = _gateway(harness)
        snapshot = gateway.finalized_snapshot(
            resource_id_hash="6" * 64, now=NOW
        )
        with self.assertRaises(ExecutionPolicyAnchorSignerUnavailable):
            gateway.prepare_anchor(
                snapshot=snapshot,
                resource_id_hash="6" * 64,
                decision_hash="7" * 64,
            )
        harness.close()

    def test_writer_prepares_exact_cas_with_confirmed_nonce(self):
        class _Signer:
            address = WRITER
            custody = "test_execution_policy_anchor_writer"

            def __init__(self):
                self.transaction = None

            def sign_transaction(self, transaction):
                self.transaction = transaction
                return SimpleNamespace(raw_transaction=b"\x01\x02")

        harness = _RpcHarness()
        signer = _Signer()
        gateway = _gateway(
            harness,
            signer=signer,
            allow_plain_http_for_test=True,
        )
        snapshot = gateway.latest_snapshot(
            resource_id_hash="6" * 64,
            decision_hash="7" * 64,
            now=NOW,
        )
        prepared = gateway.prepare_anchor(
            snapshot=snapshot,
            resource_id_hash="6" * 64,
            decision_hash="7" * 64,
        )
        self.assertEqual(harness.assert_latest_nonce_tag, "latest")
        self.assertEqual(signer.transaction["chainId"], 84_532)
        self.assertEqual(signer.transaction["nonce"], 4)
        self.assertEqual(signer.transaction["to"].lower(), CONTRACT)
        data = signer.transaction["data"]
        self.assertEqual(data[:4], anchor._ANCHOR_DECISION)
        self.assertEqual(len(data), 4 + 6 * 32)
        self.assertEqual(prepared.expected_global_sequence, 0)
        self.assertEqual(prepared.target_sequence, 1)
        harness.close()

    def test_production_signer_has_no_non_dstack_fallback(self):
        with patch.object(anchor.dstack_utils, "is_dstack_enabled", return_value=False):
            with self.assertRaises(ExecutionPolicyAnchorSignerUnavailable):
                DstackExecutionPolicyAnchorSigner.from_settings(object())

        settings = SimpleNamespace(
            execution_policy_anchor_writer_key_path="tinker/shared"
        )
        with (
            patch.object(anchor.dstack_utils, "is_dstack_enabled", return_value=True),
            patch.object(anchor.dstack_utils, "is_dstack_simulator", return_value=False),
            patch.object(anchor.dstack_utils, "derive_storage_key") as derive,
        ):
            with self.assertRaises(ExecutionPolicyAnchorSignerUnavailable):
                DstackExecutionPolicyAnchorSigner.from_settings(settings)
            derive.assert_not_called()

    def test_live_release_binding_matches_domain_release_compose_and_app(self):
        harness = _RpcHarness()
        gateway = _gateway(harness)
        app_id = "app_release_binding"
        compose = "0x" + "55" * 32
        domain = ":".join(
            (
                "base-sepolia",
                "84532",
                RELEASE[2:],
                compose,
                hashlib.sha256(app_id.encode("utf-8")).hexdigest(),
                "66" * 32,
            )
        )
        settings = SimpleNamespace(execution_policy_approval_domain=domain)

        def evidence(report_data):
            return {
                "compose_hash": compose,
                "app_id": app_id,
                "quote_report_data": "0x" + report_data.hex(),
            }

        with patch.object(
            anchor.dstack_utils,
            "get_attestation_details",
            side_effect=evidence,
        ):
            verify_live_execution_policy_release_binding(settings, gateway)

        drifted = SimpleNamespace(
            execution_policy_approval_domain=domain.replace(
                RELEASE[2:], "77" * 32, 1
            )
        )
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            verify_live_execution_policy_release_binding(drifted, gateway)

        for field, value in (
            ("compose_hash", "0x" + "99" * 32),
            ("app_id", "app_drifted_release"),
        ):
            with self.subTest(field=field):
                def drifted_evidence(report_data, *, field=field, value=value):
                    payload = evidence(report_data)
                    payload[field] = value
                    return payload

                with (
                    patch.object(
                        anchor.dstack_utils,
                        "get_attestation_details",
                        side_effect=drifted_evidence,
                    ),
                    self.assertRaises(ExecutionPolicyAnchorMismatch),
                ):
                    verify_live_execution_policy_release_binding(
                        settings, gateway
                    )
        harness.close()

    def test_anchor_head_matches_independent_solidity_abi_encoding(self):
        resource = "6" * 64
        decision = "7" * 64
        expected = keccak(
            encode(
                [
                    "bytes32",
                    "uint256",
                    "address",
                    "uint256",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "address",
                    "bytes32",
                ],
                [
                    anchor._ANCHOR_TYPEHASH,
                    84_532,
                    CONTRACT,
                    1,
                    bytes(32),
                    bytes.fromhex(resource),
                    bytes(32),
                    bytes.fromhex(decision),
                    WRITER,
                    bytes.fromhex(RELEASE[2:]),
                ],
            )
        )
        observed = compute_anchor_head(
            contract_address=CONTRACT,
            sequence=1,
            previous_global_head=ZERO_BYTES32,
            resource_id_hash=resource,
            previous_resource_head=ZERO_BYTES32,
            decision_hash=decision,
            writer_address=WRITER,
            writer_release_commitment=RELEASE,
        )
        self.assertEqual(observed, "0x" + expected.hex())


class AnchorCoordinatorTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "policy.json"
        self.key = b"k" * 32
        self.store = ExecutionPolicyStore(self.path, integrity_key=self.key)
        self.gateway = MemoryExecutionPolicyAnchorGateway()
        self.coordinator = AnchoredExecutionPolicyCoordinator(
            self.store, self.gateway
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_every_append_is_anchored_before_success(self):
        record = self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_anchor_one")
        )
        self.assertEqual(record["sequence"], 1)
        self.assertEqual(record["rollback_anchor"]["global_sequence"], 1)
        self.assertEqual(len(self.gateway.records), 1)

    def test_independent_coordinators_serialize_refresh_and_append(self):
        second = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key),
            self.gateway,
        )
        barrier = threading.Barrier(3)
        records: list[dict] = []
        errors: list[Exception] = []

        def append(coordinator, resource):
            barrier.wait()
            try:
                records.append(
                    coordinator.append_and_anchor(
                        now=NOW, **_append_kwargs(resource)
                    )
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        threads = [
            threading.Thread(
                target=append,
                args=(self.coordinator, "sub_concurrent_one"),
            ),
            threading.Thread(
                target=append,
                args=(second, "sub_concurrent_two"),
            ),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        self.assertFalse(errors)
        self.assertEqual(sorted(record["sequence"] for record in records), [1, 2])
        self.assertEqual(len(self.gateway.records), 2)

    def test_authorization_lease_blocks_revocation_until_execution_exits(self):
        passed = self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_policy_lease")
        )
        reader_gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        reader_gateway.records = self.gateway.records
        reader = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key),
            reader_gateway,
        )
        writer = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key),
            self.gateway,
        )
        started = threading.Event()
        finished = threading.Event()
        errors: list[Exception] = []

        def revoke():
            started.set()
            try:
                writer.append_and_anchor(
                    now=NOW + 1,
                    **_append_kwargs(
                        "sub_policy_lease",
                        previous=passed["decision_hash"],
                        decision=PolicyDecision.HOLD,
                        recorded_at=NOW + 1,
                    ),
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                finished.set()

        with reader.authorized_execution_lease(
            surface="arena_execution",
            resource_id="sub_policy_lease",
            now=NOW,
            expected_approval_domain_hash="5" * 64,
            expected_approver_root_hash=execution_policy_approver_root_hash(
                {"3" * 64}
            ),
            approved_approver_hashes={"3" * 64},
        ):
            thread = threading.Thread(target=revoke)
            thread.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(finished.wait(0.2))
        thread.join(timeout=5)

        self.assertFalse(errors)
        self.assertTrue(finished.is_set())
        self.assertEqual(
            writer.store.latest(
                surface="arena_execution", resource_id="sub_policy_lease"
            )["decision"],
            "hold",
        )

    def test_crash_after_persist_reconciles_exact_latest_record(self):
        self.gateway.fail_next_anchor = True
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            self.coordinator.append_and_anchor(
                now=NOW, **_append_kwargs("sub_crash_reconcile")
            )
        self.assertEqual(len(self.store.anchor_projection()), 1)
        self.assertEqual(len(self.gateway.records), 0)

        recovered = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key),
            self.gateway,
        )
        snapshot = recovered.ensure_synchronized(now=NOW, reconcile=True)
        self.assertEqual(snapshot.global_sequence, 1)
        self.assertEqual(
            self.gateway.records[0].decision_hash,
            self.store.anchor_projection()[0]["decision_hash"],
        )

    def test_no_second_append_while_latest_record_is_unanchored(self):
        self.gateway.fail_next_anchor = True
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            self.coordinator.append_and_anchor(
                now=NOW, **_append_kwargs("sub_pending_one")
            )
        self.gateway.fail_next_anchor = True
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            self.coordinator.append_and_anchor(
                now=NOW,
                **_append_kwargs("sub_must_not_append", recorded_at=NOW + 1),
            )
        self.assertEqual(len(self.store.anchor_projection()), 1)

    def test_valid_older_hmac_snapshot_is_detected_by_chain_sequence(self):
        first = self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_snapshot_one")
        )
        old_snapshot = self.path.read_bytes()
        self.coordinator.append_and_anchor(
            now=NOW + 1,
            **_append_kwargs(
                "sub_snapshot_two",
                recorded_at=NOW + 1,
            ),
        )
        self.path.write_bytes(old_snapshot)
        rolled_back_store = ExecutionPolicyStore(
            self.path, integrity_key=self.key
        )
        with self.assertRaisesRegex(
            ExecutionPolicyAnchorMismatch, "ahead of the local HMAC journal"
        ):
            AnchoredExecutionPolicyCoordinator(
                rolled_back_store, self.gateway
            ).ensure_synchronized(now=NOW + 2, reconcile=True)
        self.assertEqual(first["sequence"], 1)

    def test_same_sequence_wrong_global_head_fails_globally(self):
        self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_wrong_head")
        )
        self.gateway.snapshot_overrides["global_head"] = "0x" + "ff" * 32
        with self.assertRaisesRegex(
            ExecutionPolicyAnchorMismatch, "global policy anchor"
        ):
            self.coordinator.ensure_synchronized(now=NOW, reconcile=True)

    def test_read_only_worker_verifies_resource_and_cannot_reconcile(self):
        record = self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_worker_read")
        )
        reader = MemoryExecutionPolicyAnchorGateway(read_only=True)
        reader.records = self.gateway.records
        read_coordinator = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key), reader
        )
        approvers = {"3" * 64}
        passed = read_coordinator.require_pass(
            surface="arena_execution",
            resource_id="sub_worker_read",
            now=NOW + 1,
            expected_approval_domain_hash="5" * 64,
            expected_approver_root_hash=execution_policy_approver_root_hash(
                approvers
            ),
            approved_approver_hashes=approvers,
        )
        self.assertEqual(passed["decision_hash"], record["decision_hash"])

        self.store.append(
            **_append_kwargs(
                "sub_worker_pending",
                recorded_at=NOW + 1,
            )
        )
        read_coordinator = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(self.path, integrity_key=self.key), reader
        )
        with self.assertRaises(ExecutionPolicyAnchorUnavailable):
            read_coordinator.ensure_synchronized(
                now=NOW + 1, reconcile=False
            )

    def test_resource_head_mismatch_denies_current_pass(self):
        self.coordinator.append_and_anchor(
            now=NOW, **_append_kwargs("sub_resource_wrong")
        )
        self.gateway.snapshot_overrides["resource_decision_head"] = ZERO_BYTES32
        with self.assertRaises(ExecutionPolicyAnchorMismatch):
            self.coordinator.require_pass(
                surface="arena_execution",
                resource_id="sub_resource_wrong",
                now=NOW + 1,
                expected_approval_domain_hash="5" * 64,
                expected_approver_root_hash=execution_policy_approver_root_hash(
                    {"3" * 64}
                ),
                approved_approver_hashes={"3" * 64},
            )

    def test_hold_remains_anchored_and_never_authorizes(self):
        self.coordinator.append_and_anchor(
            now=NOW,
            **_append_kwargs(
                "sub_hold", decision=PolicyDecision.HOLD
            ),
        )
        with self.assertRaises(ExecutionPolicyNotPassed):
            self.coordinator.require_pass(
                surface="arena_execution",
                resource_id="sub_hold",
                now=NOW + 1,
                expected_approval_domain_hash="5" * 64,
                expected_approver_root_hash=execution_policy_approver_root_hash(
                    {"3" * 64}
                ),
                approved_approver_hashes={"3" * 64},
            )


if __name__ == "__main__":
    unittest.main()
