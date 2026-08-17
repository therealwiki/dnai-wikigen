import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
from tinker_delegate import api
from tinker_delegate.collaboration_anchor import (
    AnchoredCollaborationStore,
    CollaborationAnchorError,
    CollaborationAnchorHead,
    CollaborationRollbackError,
    ExecutionPolicyCollaborationAnchor,
    ZERO_COLLABORATION_STATE_HASH,
    collaboration_authority_context_hash,
    collaboration_pending_path,
    collaboration_state_hash,
)
from tinker_delegate.collaboration_store import CollaborationStore
from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.execution_policy_store import (
    ZERO_DECISION_HASH,
    execution_resource_hash,
)
from tinker_delegate.policy_kernel import PolicyDecision


NOW = 1_900_000_000
CONTEXT = "a" * 64
KEY = b"collaboration-rollback-anchor-test-key"
CREATOR = "0x" + "11" * 20
OWNER = "0x" + "22" * 20
ROOM = "room_" + "a" * 32


def _commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _rollback_status(
    *,
    sequence: int,
    decision_hash: str,
    context: str = CONTEXT,
) -> dict:
    populated = sequence > 0
    return {
        "schema": "dnai-wikigen/execution-policy-anchor-status/v1",
        "status": "rpc_reported_finalized_release_match",
        "verification_model": (
            "single_rpc_reported_finalized_with_confirmation_depth"
        ),
        "chain_id": 84_532,
        "block_number": 99,
        "block_hash": "0x" + "91" * 32,
        "block_timestamp": NOW,
        "contract_address": "0x" + "41" * 20,
        "runtime_code_hash": "0x" + "42" * 32,
        "writer": "0x" + "43" * 20,
        "writer_release_commitment": "0x" + "44" * 32,
        "writer_rotations_frozen": True,
        "paused": False,
        "global_sequence": sequence,
        "global_head": (
            "0x" + ("45" * 32 if populated else "0" * 64)
        ),
        "resource_id_hash": execution_resource_hash(
            "collaboration_state",
            context,
        ),
        "resource_decision_head": (
            "0x" + decision_hash if populated else "0x" + "0" * 64
        ),
        "resource_sequence": sequence,
        "decision_hash": decision_hash if populated else "",
        "decision_sequence": sequence,
        "latest_block_number": 100,
        "rpc_finalized_block_number": 99,
        "rpc_finalized_block_hash": "0x" + "91" * 32,
        "minimum_confirmation_depth": 2,
        "observed_confirmation_depth": 2,
        "independent_rpc_quorum_verified": False,
        "consensus_proof_verified": False,
        "opaque_commitments_only": True,
        "raw_resource_id_egress": False,
        "raw_policy_egress": False,
    }


class FakeRollbackAnchor:
    def __init__(self, *, context: str = CONTEXT) -> None:
        self.context = context
        self.head = CollaborationAnchorHead(
            authority_context_hash=context,
            state_hash=ZERO_COLLABORATION_STATE_HASH,
            decision_hash=ZERO_DECISION_HASH,
            sequence=0,
            rollback_anchor=_rollback_status(
                sequence=0,
                decision_hash=ZERO_DECISION_HASH,
                context=context,
            ),
        )
        self.fail_after_commit = False
        self.unavailable = False
        self.compare_calls = 0

    def read_head(self, *, now: int) -> CollaborationAnchorHead:
        del now
        if self.unavailable:
            raise CollaborationAnchorError("anchor unavailable")
        return self.head

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> CollaborationAnchorHead:
        del now
        if self.unavailable:
            raise CollaborationAnchorError("anchor unavailable")
        if self.head.state_hash != expected_state_hash:
            raise CollaborationAnchorError("CAS conflict")
        self.compare_calls += 1
        sequence = self.head.sequence + 1
        decision_hash = f"{sequence:064x}"
        self.head = CollaborationAnchorHead(
            authority_context_hash=self.context,
            state_hash=new_state_hash,
            decision_hash=decision_hash,
            sequence=sequence,
            rollback_anchor=_rollback_status(
                sequence=sequence,
                decision_hash=decision_hash,
                context=self.context,
            ),
        )
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise CollaborationAnchorError("ambiguous transport")
        return self.head


def _room_request() -> dict:
    return {
        "room_id": ROOM,
        "idempotency_key": "create-room-0001",
        "creator_address": CREATOR,
        "member_addresses": [OWNER],
        "purpose_commitment": _commitment("purpose"),
        "pipeline_commitment": _commitment("pipeline"),
        "corpus_policy_commitments": {
            OWNER: _commitment("owner-policy"),
        },
        "owner_allocations_bps": {OWNER: 10_000},
        "created_at": NOW,
    }


def _settings() -> Settings:
    return Settings(
        collaboration_enabled=True,
        main_runtime_cvm_id="cvm-main-runtime-0001",
        release_deployment_intent_sha256="sha256:" + "31" * 32,
        release_authority_sha256="sha256:" + "32" * 32,
        release_ceremony_nonce="0x" + "33" * 32,
    )


class CollaborationRollbackRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name).resolve()
        os.chmod(root, 0o700)
        self.path = root / "collaboration.json"
        self.anchor = FakeRollbackAnchor()
        self.store = AnchoredCollaborationStore(
            self.path,
            integrity_key=KEY,
            authority_context_hash=CONTEXT,
            rollback_anchor=self.anchor,
            clock=lambda: NOW,
        )

    def _accept(self) -> None:
        self.store.respond_to_invitation(
            room_id=ROOM,
            participant_address=OWNER,
            decision="accept",
            idempotency_key="accept-owner-0001",
            decided_at=NOW + 1,
        )

    def _role(self, decision: str, index: int) -> None:
        challenge = self.store.issue_consent_challenge(
            room_id=ROOM,
            owner_address=OWNER,
            decision=decision,
            challenge_id="consent_" + f"{index:032x}",
            issued_at=NOW + index * 10,
            expires_at=NOW + index * 10 + 120,
        )
        self.store.consume_verified_consent(
            challenge_id=challenge["challenge_id"],
            owner_address=OWNER,
            decision=decision,
            authorization_hash=_commitment(f"role-{decision}-{index}"),
            verifier_confirmed=True,
            consumed_at=NOW + index * 10 + 1,
        )

    def _query_grant(self, decision: str, index: int) -> None:
        challenge = self.store.issue_query_grant_challenge(
            room_id=ROOM,
            owner_address=OWNER,
            decision=decision,
            challenge_id="qgrant_" + f"{index:032x}",
            issued_at=NOW + 100 + index * 10,
            expires_at=NOW + 100 + index * 10 + 120,
        )
        self.store.consume_verified_query_grant(
            challenge_id=challenge["challenge_id"],
            owner_address=OWNER,
            decision=decision,
            authorization_hash=_commitment(f"query-{decision}-{index}"),
            verifier_confirmed=True,
            consumed_at=NOW + 100 + index * 10 + 1,
        )

    def test_pending_membership_snapshot_cannot_resurrect_after_cancel(self):
        room = self.store.create_room(**_room_request())
        old_bytes = self.path.read_bytes()
        cancelled = self.store.cancel_invitation(
            room_id=ROOM,
            creator_address=CREATOR,
            invitee_address=OWNER,
            idempotency_key="cancel-owner-0001",
            cancelled_at=NOW + 1,
        )
        self.assertEqual(room["requester_membership_status"], "accepted")
        self.assertEqual(cancelled["membership_status"], "cancelled")

        self.path.write_bytes(old_bytes)
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "does not match its rollback witness",
        ):
            self.store.room_projection(ROOM, CREATOR)

    def test_active_owner_snapshot_cannot_resurrect_after_revocation(self):
        self.store.create_room(**_room_request())
        self._accept()
        self._role("activate", 1)
        old_bytes = self.path.read_bytes()
        self._role("revoke", 2)

        self.path.write_bytes(old_bytes)
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "does not match its rollback witness",
        ):
            self.store.room_projection(ROOM, CREATOR)

    def test_approved_query_snapshot_cannot_resurrect_after_revocation(self):
        self.store.create_room(**_room_request())
        self._accept()
        self._role("activate", 1)
        self.store.propose_query(
            room_id=ROOM,
            query_ref=_commitment("query"),
            proposer_address=CREATOR,
            idempotency_key="propose-query-0001",
            proposed_at=NOW + 80,
        )
        self._query_grant("approve", 1)
        old_bytes = self.path.read_bytes()
        self._query_grant("revoke", 2)

        self.path.write_bytes(old_bytes)
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "does not match its rollback witness",
        ):
            self.store.room_projection(ROOM, CREATOR)

    def test_idempotent_replay_does_not_advance_anchor(self):
        first = self.store.create_room(**_room_request())
        first_sequence = self.anchor.head.sequence
        first_calls = self.anchor.compare_calls
        replay = self.store.create_room(**_room_request())

        self.assertEqual(self.anchor.head.sequence, first_sequence)
        self.assertEqual(self.anchor.compare_calls, first_calls)
        self.assertEqual(first, replay)
        self.assertTrue(replay["rollback_protection"])
        self.assertTrue(replay["rollback_witness"]["monotonic"])
        self.assertEqual(
            replay["rollback_witness"]["anchor_sequence"],
            first_sequence,
        )

    def test_every_read_rechecks_current_head_and_detects_regression(self):
        genesis = self.anchor.head
        self.store.create_room(**_room_request())
        current = self.anchor.head
        self.anchor.head = genesis
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "regressed",
        ):
            self.store.room_projection(ROOM, CREATOR)
        self.anchor.head = current
        self.assertEqual(
            self.store.room_projection(ROOM, CREATOR)["room_id"],
            ROOM,
        )

    def test_witness_unavailability_blocks_reads_and_mutations(self):
        self.store.create_room(**_room_request())
        active = self.path.read_bytes()
        self.anchor.unavailable = True
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "unavailable",
        ):
            self.store.room_projection(ROOM, CREATOR)
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "unavailable",
        ):
            self.store.cancel_invitation(
                room_id=ROOM,
                creator_address=CREATOR,
                invitee_address=OWNER,
                idempotency_key="cancel-owner-0001",
                cancelled_at=NOW + 1,
            )
        self.assertEqual(self.path.read_bytes(), active)

    def test_ambiguous_anchor_commit_recovers_matching_pending_state(self):
        self.anchor.fail_after_commit = True
        with self.assertRaisesRegex(
            CollaborationRollbackError,
            "commit is unavailable",
        ):
            self.store.create_room(**_room_request())
        self.assertTrue(collaboration_pending_path(self.path).exists())

        recovered = AnchoredCollaborationStore(
            self.path,
            integrity_key=KEY,
            authority_context_hash=CONTEXT,
            rollback_anchor=self.anchor,
            clock=lambda: NOW,
        )
        self.assertFalse(collaboration_pending_path(self.path).exists())
        self.assertEqual(
            recovered.room_projection(ROOM, CREATOR)["room_id"],
            ROOM,
        )

    def test_local_store_truth_is_explicitly_non_monotonic(self):
        local_path = self.path.with_name("local-collaboration.json")
        local = CollaborationStore(local_path, integrity_key=KEY)
        room = local.create_room(**_room_request())
        witness = room["rollback_witness"]

        self.assertFalse(room["rollback_protection"])
        self.assertEqual(
            witness["mode"],
            "local_hmac_current_state_non_monotonic",
        )
        self.assertFalse(witness["monotonic"])
        self.assertIsNone(witness["authority_context_hash"])
        self.assertIsNone(witness["rollback_anchor"])


class CollaborationAuthorityContextTest(unittest.TestCase):
    def test_context_binds_project_release_domain_and_exact_state(self):
        settings = _settings()
        context = collaboration_authority_context_hash(settings)
        for update in (
            {"main_runtime_cvm_id": "cvm-main-runtime-0002"},
            {
                "release_deployment_intent_sha256": (
                    "sha256:" + "41" * 32
                )
            },
            {"release_authority_sha256": "sha256:" + "42" * 32},
            {"release_ceremony_nonce": "0x" + "43" * 32},
        ):
            with self.subTest(update=update):
                self.assertNotEqual(
                    collaboration_authority_context_hash(
                        settings.model_copy(update=update)
                    ),
                    context,
                )
        with self.assertRaisesRegex(
            CollaborationAnchorError,
            "project, release, or wallet domain",
        ):
            collaboration_authority_context_hash(
                settings.model_copy(
                    update={"wallet_auth_domain": "preview.wikigen.me"}
                )
            )

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state_path = Path(temporary.name) / "state.json"
        store = CollaborationStore(state_path, integrity_key=KEY)
        state = store._load_locked()
        self.assertNotEqual(
            collaboration_state_hash(
                state,
                authority_context_hash=context,
            ),
            collaboration_state_hash(
                state,
                authority_context_hash="b" * 64,
            ),
        )


class CollaborationLiveApiGateTest(unittest.TestCase):
    def test_live_wallet_challenge_fails_before_auth_when_witness_is_unavailable(
        self,
    ):
        with (
            patch.object(api, "settings", _settings()),
            patch.object(api, "is_dstack_enabled", return_value=True),
            patch.object(
                api,
                "_get_collaboration_store",
                side_effect=HTTPException(
                    status_code=503,
                    detail="witness unavailable",
                ),
            ) as get_store,
        ):
            with self.assertRaises(HTTPException) as raised:
                api._collaboration_wallet_auth_service()
        self.assertEqual(raised.exception.status_code, 503)
        get_store.assert_called_once_with()

    def test_cached_live_witness_outage_maps_to_service_unavailable(self):
        store = MagicMock()
        store.rollback_status.side_effect = CollaborationRollbackError(
            "witness unavailable"
        )
        with (
            patch.object(api, "settings", _settings()),
            patch.object(api, "is_dstack_enabled", return_value=True),
            patch.object(
                api,
                "_get_collaboration_store",
                return_value=store,
            ),
        ):
            with self.assertRaises(HTTPException) as raised:
                api._collaboration_wallet_auth_service()
        self.assertEqual(raised.exception.status_code, 503)
        store.rollback_status.assert_called_once_with()

    def test_live_store_rejects_incomplete_release_context_before_anchor_access(
        self,
    ):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        incomplete = _settings().model_copy(
            update={
                "collaboration_store_path": str(
                    Path(temporary.name) / "collaboration.json"
                ),
                "release_authority_sha256": "",
            }
        )
        with (
            patch.object(api, "settings", incomplete),
            patch.object(api, "is_dstack_enabled", return_value=True),
            patch.object(
                api,
                "collaboration_store_integrity_key",
                return_value=KEY,
            ),
            patch.object(
                api,
                "_get_execution_policy_anchor_coordinator",
            ) as coordinator,
            patch.object(api, "_collaboration_store_instance", None),
            patch.object(
                api,
                "_collaboration_store_instance_identity",
                None,
            ),
        ):
            with self.assertRaises(HTTPException) as raised:
                api._get_collaboration_store()
        self.assertEqual(raised.exception.status_code, 503)
        self.assertEqual(
            raised.exception.detail,
            "Collaboration rollback witness is unavailable",
        )
        coordinator.assert_not_called()


class ExecutionPolicyCollaborationAnchorAdapterTest(unittest.TestCase):
    def test_adapter_writes_hold_commitment_not_execution_pass(self):
        class FakeCoordinator(AnchoredExecutionPolicyCoordinator):
            def __init__(self):
                self.gateway = SimpleNamespace(read_only=False)
                self.append_calls = []

            def history(self, **_kwargs):
                return (
                    (),
                    MagicMock(
                        to_bounded_dict=lambda: _rollback_status(
                            sequence=0,
                            decision_hash=ZERO_DECISION_HASH,
                        )
                    ),
                )

            def append_and_anchor(self, **kwargs):
                self.append_calls.append(kwargs)
                return {
                    "surface": "collaboration_state",
                    "decision": "hold",
                    "reason_code": "collaboration_state_commitment",
                    "request_hash": "b" * 64,
                    "policy_hash": CONTEXT,
                    "execution_context_hash": ZERO_COLLABORATION_STATE_HASH,
                    "previous_decision_hash": ZERO_DECISION_HASH,
                    "decision_hash": "c" * 64,
                    "sequence": 1,
                    "rollback_anchor": _rollback_status(
                        sequence=1,
                        decision_hash="c" * 64,
                    ),
                }

        coordinator = FakeCoordinator()
        adapter = ExecutionPolicyCollaborationAnchor(
            coordinator,
            authority_context_hash=CONTEXT,
        )
        head = adapter.compare_and_set(
            expected_state_hash=ZERO_COLLABORATION_STATE_HASH,
            new_state_hash="b" * 64,
            now=NOW,
        )

        call = coordinator.append_calls[0]
        self.assertIs(call["result"].decision, PolicyDecision.HOLD)
        self.assertEqual(call["result"].request_hash, "b" * 64)
        self.assertEqual(call["result"].policy_hash, CONTEXT)
        self.assertEqual(head.state_hash, "b" * 64)

    def test_adapter_rejects_malformed_or_replayed_history(self):
        class FakeCoordinator(AnchoredExecutionPolicyCoordinator):
            def __init__(self):
                self.gateway = SimpleNamespace(read_only=False)

            def history(self, **_kwargs):
                record = {
                    "surface": "collaboration_state",
                    "decision": "hold",
                    "reason_code": "collaboration_state_commitment",
                    "request_hash": "b" * 64,
                    "policy_hash": CONTEXT,
                    "execution_context_hash": "9" * 64,
                    "previous_decision_hash": ZERO_DECISION_HASH,
                    "decision_hash": "c" * 64,
                    "sequence": 1,
                }
                return (
                    (record, {**record}),
                    MagicMock(
                        to_bounded_dict=lambda: _rollback_status(
                            sequence=1,
                            decision_hash="c" * 64,
                        )
                    ),
                )

        adapter = ExecutionPolicyCollaborationAnchor(
            FakeCoordinator(),
            authority_context_hash=CONTEXT,
        )
        with self.assertRaisesRegex(
            CollaborationAnchorError,
            "history is invalid",
        ):
            adapter.read_head(now=NOW)


if __name__ == "__main__":
    unittest.main()
