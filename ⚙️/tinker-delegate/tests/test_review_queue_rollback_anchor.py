import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from tinker_delegate.config import Settings
from tinker_delegate.coordination import HandoffTicket
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.policy_kernel import PolicyDecision
from tinker_delegate.review_authority import (
    REVIEW_ACTIVE_REVIEWERS_SCHEMA,
    REVIEW_AUTHORITY_POLICY_SCHEMA,
    REVIEW_AUTHORITY_ROLES,
    ReviewAuthorityService,
    ReviewAuthorityUnavailable,
    ReviewChallengeStore,
    review_authority_active_reviewers_sha256,
    review_authority_context_hash,
    review_authority_policy,
    review_authority_policy_sha256,
    review_queue_integrity_key,
)
from tinker_delegate.review_queue import (
    ReviewQueueState,
    enqueue_handoff_tickets,
    load_review_queue,
    review_queue_pending_path,
    review_queue_state_hash,
    save_review_queue,
)
from tinker_delegate.review_queue_anchor import (
    ExecutionPolicyReviewQueueAnchor,
    ReviewQueueAnchorError,
    ReviewQueueAnchorHead,
    ZERO_REVIEW_QUEUE_STATE_HASH,
)


NOW = 1_900_000_000


class FakeRollbackAnchor:
    def __init__(self) -> None:
        self.head = ReviewQueueAnchorHead(
            state_hash=ZERO_REVIEW_QUEUE_STATE_HASH,
            decision_hash="0" * 64,
            sequence=0,
            rollback_anchor={"status": "fake-finalized"},
        )
        self.fail_after_commit = False

    def read_head(self, *, now: int) -> ReviewQueueAnchorHead:
        del now
        return self.head

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> ReviewQueueAnchorHead:
        del now
        if self.head.state_hash != expected_state_hash:
            raise ReviewQueueAnchorError("CAS conflict")
        self.head = ReviewQueueAnchorHead(
            state_hash=new_state_hash,
            decision_hash=f"{self.head.sequence + 1:064x}",
            sequence=self.head.sequence + 1,
            rollback_anchor={"status": "fake-finalized"},
        )
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise ReviewQueueAnchorError("ambiguous transport")
        return self.head


class NoopSignatureVerifier:
    def verify(self, **_kwargs):
        return "eoa"


def _settings(path: Path) -> Settings:
    reviewers = [
        {"address": "0x" + "11" * 20, "reviewer_ref": "reviewer-a"},
        {"address": "0x" + "22" * 20, "reviewer_ref": "reviewer-b"},
    ]
    policy = {
        "schema": REVIEW_AUTHORITY_POLICY_SCHEMA,
        "roles": [
            {
                "role": role,
                "threshold": 2,
                "reviewers": reviewers,
            }
            for role in sorted(REVIEW_AUTHORITY_ROLES)
        ],
    }
    active = {
        "schema": REVIEW_ACTIVE_REVIEWERS_SCHEMA,
        "reviewers": [
            {
                "address": reviewer["address"],
                "controller_id": reviewer["reviewer_ref"],
            }
            for reviewer in reviewers
        ],
    }
    return Settings(
        review_queue_path=str(path),
        review_queue_store_integrity_key="q" * 64,
        review_authority_policy_json=json.dumps(policy),
        review_authority_policy_sha256=review_authority_policy_sha256(policy),
        release_reviewer_authority_active_reviewers_json=json.dumps(active),
        release_reviewer_authority_active_reviewers_sha256=(
            review_authority_active_reviewers_sha256(active)
        ),
        main_runtime_cvm_id="cvm-main-runtime-0001",
        release_deployment_intent_sha256="sha256:" + "31" * 32,
        release_authority_sha256="sha256:" + "32" * 32,
        release_ceremony_nonce="0x" + "33" * 32,
        release_reviewer_authority_genesis_acceptance_sha256=(
            "sha256:" + "34" * 32
        ),
        release_reviewer_authority_current_status_epoch=1,
        release_reviewer_authority_current_status_sha256=(
            "sha256:" + "35" * 32
        ),
    )


def _ticket_state(settings: Settings) -> ReviewQueueState:
    policy = review_authority_policy(settings)
    ticket = HandoffTicket(
        ticket_id="ticket-1",
        turn_id="turn-1",
        corpus_ref="corpus://private",
        routed_role="biosecurity-review",
        reason_hash="a" * 64,
        submitter_ref="submitter",
    )
    return enqueue_handoff_tickets(
        ReviewQueueState.empty(),
        (ticket,),
        opened_at=NOW,
        ttl_seconds=600,
        required_approvals_by_role=policy.required_approvals_by_role(),
    )


class ReviewQueueRollbackRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name).resolve()
        os.chmod(root, 0o700)
        self.path = root / "review-queue.json"
        self.settings = _settings(self.path)
        self.key = review_queue_integrity_key(self.settings)
        self.context = review_authority_context_hash(
            self.settings,
            review_authority_policy(self.settings),
        )
        save_review_queue(
            self.path,
            ReviewQueueState.empty(),
            integrity_key=self.key,
            authority_context_hash=self.context,
        )
        self.anchor = FakeRollbackAnchor()

    def tearDown(self):
        self.temporary.cleanup()

    def _service(self) -> ReviewAuthorityService:
        with patch(
            "tinker_delegate.review_authority.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            return ReviewAuthorityService(
                self.settings,
                ReviewChallengeStore(),
                signature_verifier=NoopSignatureVerifier(),
                rollback_anchor=self.anchor,
            )

    def test_empty_genesis_is_anchored_and_old_hmac_snapshot_is_rejected(self):
        service = self._service()
        self.assertNotEqual(
            self.anchor.head.state_hash,
            ZERO_REVIEW_QUEUE_STATE_HASH,
        )
        old_bytes = self.path.read_bytes()
        updated = _ticket_state(self.settings)
        with service._queue_lease():
            service._recover_state(now=NOW)
            service._commit_state(updated, now=NOW)

        self.path.write_bytes(old_bytes)
        os.chmod(self.path, 0o600)
        with self.assertRaisesRegex(
            ReviewAuthorityUnavailable,
            "does not match its rollback anchor",
        ):
            self._service()

    def test_ambiguous_anchor_commit_recovers_only_the_matching_pending_state(self):
        service = self._service()
        updated = _ticket_state(self.settings)
        expected_hash = review_queue_state_hash(
            updated,
            authority_context_hash=self.context,
        )
        self.anchor.fail_after_commit = True
        with self.assertRaisesRegex(
            ReviewAuthorityUnavailable,
            "anchor commit is unavailable",
        ):
            with service._queue_lease():
                service._recover_state(now=NOW)
                service._commit_state(updated, now=NOW)
        self.assertTrue(review_queue_pending_path(self.path).exists())
        self.assertEqual(self.anchor.head.state_hash, expected_hash)

        recovered = self._service()
        self.assertFalse(review_queue_pending_path(self.path).exists())
        state = load_review_queue(
            self.path,
            integrity_key=self.key,
            expected_authority_context_hash=self.context,
        )
        self.assertEqual(len(state.tickets), 1)
        self.assertEqual(recovered._last_anchor_head.state_hash, expected_hash)

    def test_nonempty_unanchored_state_is_never_adopted_as_genesis(self):
        save_review_queue(
            self.path,
            _ticket_state(self.settings),
            integrity_key=self.key,
            authority_context_hash=self.context,
        )
        with self.assertRaisesRegex(
            ReviewAuthorityUnavailable,
            "unanchored review queue state is not empty",
        ):
            self._service()


class ExecutionPolicyReviewQueueAnchorAdapterTest(unittest.TestCase):
    def test_adapter_writes_a_hold_commitment_not_an_execution_pass(self):
        class FakeCoordinator(AnchoredExecutionPolicyCoordinator):
            def __init__(self):
                self.gateway = SimpleNamespace(read_only=False)
                self.history_calls = []
                self.append_calls = []

            def history(self, **kwargs):
                self.history_calls.append(kwargs)
                return (
                    (),
                    MagicMock(to_bounded_dict=lambda: {"status": "finalized"}),
                )

            def append_and_anchor(self, **kwargs):
                self.append_calls.append(kwargs)
                return {
                    "surface": "review_queue_state",
                    "decision": "hold",
                    "reason_code": "review_queue_state_commitment",
                    "request_hash": "b" * 64,
                    "policy_hash": "a" * 64,
                    "execution_context_hash": "0" * 64,
                    "decision_hash": "c" * 64,
                    "sequence": 1,
                    "rollback_anchor": {"status": "finalized"},
                }

        coordinator = FakeCoordinator()
        adapter = ExecutionPolicyReviewQueueAnchor(
            coordinator,
            authority_context_hash="a" * 64,
        )

        head = adapter.compare_and_set(
            expected_state_hash="0" * 64,
            new_state_hash="b" * 64,
            now=NOW,
        )

        kwargs = coordinator.append_calls[0]
        self.assertIs(kwargs["result"].decision, PolicyDecision.HOLD)
        self.assertEqual(kwargs["result"].request_hash, "b" * 64)
        self.assertEqual(kwargs["result"].policy_hash, "a" * 64)
        self.assertEqual(head.state_hash, "b" * 64)

    def test_adapter_rejects_a_malformed_review_state_history(self):
        class FakeCoordinator(AnchoredExecutionPolicyCoordinator):
            def __init__(self):
                self.gateway = SimpleNamespace(read_only=False)

            def history(self, **_kwargs):
                return (
                    (
                        {
                            "surface": "review_queue_state",
                            "decision": "hold",
                            "reason_code": "review_queue_state_commitment",
                            "request_hash": "b" * 64,
                            "policy_hash": "a" * 64,
                            "execution_context_hash": "9" * 64,
                            "previous_decision_hash": "0" * 64,
                            "decision_hash": "c" * 64,
                            "sequence": 1,
                        },
                    ),
                    MagicMock(to_bounded_dict=lambda: {"status": "finalized"}),
                )

        adapter = ExecutionPolicyReviewQueueAnchor(
            FakeCoordinator(),
            authority_context_hash="a" * 64,
        )
        with self.assertRaisesRegex(
            ReviewQueueAnchorError,
            "history is invalid",
        ):
            adapter.read_head(now=NOW)


if __name__ == "__main__":
    unittest.main()
