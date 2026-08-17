import json
import tempfile
import unittest
from pathlib import Path

from tinker_delegate.coordination import (
    CollabSession,
    ConsentGrant,
    CoordinationState,
    Corpus,
    DelegationGrant,
    GateDecision,
    GateResults,
    GatedQuery,
    Participant,
    ParticipantRole,
    SubmitTurn,
    Turn,
    TurnStatus,
    coordinate,
)
from tinker_delegate.review_queue import (
    ReviewQueueError,
    ReviewQueueState,
    ReviewTicketStatus,
    decide_review_ticket,
    enqueue_handoff_tickets,
    expire_review_tickets,
    load_review_queue,
    pending_tickets_for_role,
    review_ticket_ref_hash,
    save_review_queue,
)


def _held_coordination_record():
    session = CollabSession(
        participants=(
            Participant("owner-atlas", ParticipantRole.OWNER),
            Participant("sponsor", ParticipantRole.REQUESTER),
            Participant("cro-agent", ParticipantRole.AGENT, owner_ref="sponsor"),
            Participant("access-officer", ParticipantRole.REVIEWER),
        ),
        corpora=(Corpus("corpus://atlas", "owner-atlas", policy_hash="atlas-policy"),),
        consent_grants=(
            ConsentGrant("corpus://atlas", "owner-atlas", "sponsor", "rank", "sft"),
        ),
        delegation_grants=(
            DelegationGrant("cro-agent", "sponsor", ("corpus://atlas",), ("rank",), ("sft",)),
        ),
    )
    turn = Turn(
        turn_id="turn-1",
        by="cro-agent",
        requester_ref="sponsor",
        purpose="rank",
        pipeline="sft",
        corpora=("corpus://atlas",),
        requests={"corpus://atlas": {"purpose": "rank"}},
    )
    state = coordinate(CoordinationState(session), SubmitTurn(turn))
    state = coordinate(
        state,
        GateResults(
            "turn-1",
            (
                GatedQuery(
                    "corpus://atlas",
                    GateDecision.HOLD,
                    stage=2,
                    reason="dual-use review",
                    routed_role="access-review-officer",
                ),
            ),
        ),
    )
    return state.turns["turn-1"]


class ReviewQueueTest(unittest.TestCase):
    def test_enqueue_handoff_ticket_creates_bounded_pending_queue(self):
        record = _held_coordination_record()

        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300)

        self.assertEqual(queue.to_public_dict()["pending_count"], 1)
        ticket = next(iter(queue.tickets.values()))
        self.assertEqual(ticket.routed_role, "access-review-officer")
        self.assertEqual(ticket.status, ReviewTicketStatus.PENDING)
        rendered = json.dumps(queue.to_public_dict(), sort_keys=True)
        self.assertNotIn("dual-use review", rendered)
        self.assertNotIn("cro-agent", rendered)
        self.assertIn(record.tickets[0].reason_hash, rendered)
        self.assertFalse(queue.to_public_dict()["raw_secret_egress"])

    def test_reviewer_release_records_hash_only_audit(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300)
        ticket_id = record.tickets[0].ticket_id

        queue = decide_review_ticket(
            queue,
            ticket_id,
            decision="release",
            reviewer_ref="access-officer",
            decided_at=120,
            blocked_reviewer_refs=("cro-agent", "sponsor"),
        )

        ticket = queue.tickets[ticket_id]
        self.assertEqual(ticket.status, ReviewTicketStatus.RELEASED)
        self.assertEqual(queue.audit[-1].event.value, "released")
        public = queue.to_public_dict()
        self.assertEqual(public["status_counts"]["released"], 1)
        rendered = json.dumps(public, sort_keys=True)
        self.assertNotIn("access-officer", rendered)
        self.assertNotIn("cro-agent", rendered)
        self.assertIn(ticket.reviewer_ref_hash, rendered)

    def test_blocked_reviewer_and_expired_ticket_fail_closed(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=10)
        ticket_id = record.tickets[0].ticket_id

        with self.assertRaisesRegex(ReviewQueueError, "not allowed"):
            decide_review_ticket(
                queue,
                ticket_id,
                decision="release",
                reviewer_ref="cro-agent",
                decided_at=105,
                blocked_reviewer_refs=("cro-agent",),
            )
        with self.assertRaisesRegex(ReviewQueueError, "expired"):
            decide_review_ticket(
                queue,
                ticket_id,
                decision="deny",
                reviewer_ref="access-officer",
                decided_at=111,
            )

    def test_submitter_cannot_self_approve_even_without_block_list(self):
        # cro-agent submitted the held turn; it must not resolve its own ticket
        # even when the caller forgets to pass blocked_reviewer_refs.
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300)
        ticket_id = record.tickets[0].ticket_id
        # The submitter ref is captured on the ticket (hashed, not raw).
        self.assertTrue(queue.tickets[ticket_id].submitter_ref_hash)

        with self.assertRaisesRegex(ReviewQueueError, "self-approve"):
            decide_review_ticket(
                queue,
                ticket_id,
                decision="release",
                reviewer_ref="cro-agent",  # the submitter
                decided_at=120,
            )

    def test_independent_reviewer_still_resolves(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300)
        ticket_id = record.tickets[0].ticket_id
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="access-officer", decided_at=120
        )
        self.assertEqual(queue.tickets[ticket_id].status, ReviewTicketStatus.RELEASED)

    def test_m_of_n_requires_two_distinct_approvals_to_release(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(),
            record.tickets,
            opened_at=100,
            ttl_seconds=300,
            required_approvals_by_role={"access-review-officer": 2},
        )
        ticket_id = record.tickets[0].ticket_id
        self.assertEqual(queue.tickets[ticket_id].required_approvals, 2)

        # First approval records a vote but the ticket stays PENDING.
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=110
        )
        self.assertEqual(queue.tickets[ticket_id].status, ReviewTicketStatus.PENDING)
        self.assertEqual(queue.audit[-1].event.value, "vote_recorded")

        # A distinct second approver crosses the threshold -> RELEASED.
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-b", decided_at=115
        )
        self.assertEqual(queue.tickets[ticket_id].status, ReviewTicketStatus.RELEASED)
        self.assertEqual(queue.audit[-1].event.value, "released")

    def test_m_of_n_rejects_duplicate_approver(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300,
            required_approvals_by_role={"access-review-officer": 2},
        )
        ticket_id = record.tickets[0].ticket_id
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=110
        )
        # The same reviewer cannot supply a second approval toward the threshold.
        with self.assertRaisesRegex(ReviewQueueError, "already approved"):
            decide_review_ticket(
                queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=112
            )

    def test_m_of_n_single_deny_blocks_immediately(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300,
            required_approvals_by_role={"access-review-officer": 3},
        )
        ticket_id = record.tickets[0].ticket_id
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=110
        )
        # Fail-closed: one deny denies, regardless of prior approvals or threshold.
        queue = decide_review_ticket(
            queue, ticket_id, decision="deny", reviewer_ref="officer-b", decided_at=112
        )
        self.assertEqual(queue.tickets[ticket_id].status, ReviewTicketStatus.DENIED)

    def test_expire_pending_tickets_and_filter_by_role(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=10)

        self.assertEqual(len(pending_tickets_for_role(queue, "access-review-officer", now=105)), 1)
        self.assertEqual(len(pending_tickets_for_role(queue, "access-review-officer", now=111)), 0)
        queue = expire_review_tickets(queue, now=111)

        ticket = next(iter(queue.tickets.values()))
        self.assertEqual(ticket.status, ReviewTicketStatus.EXPIRED)
        self.assertEqual(queue.audit[-1].event.value, "expired")
        self.assertEqual(queue.to_public_dict()["status_counts"]["expired"], 1)

    def test_review_queue_save_load_round_trip(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300)
        queue = decide_review_ticket(
            queue,
            record.tickets[0].ticket_id,
            decision="deny",
            reviewer_ref="access-officer",
            decided_at=120,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir).resolve() / "review-queue.json"
            save_review_queue(path, queue)
            loaded = load_review_queue(path)

        self.assertEqual(loaded.to_public_dict(), queue.to_public_dict())
        rendered = json.dumps(loaded.to_public_dict(), sort_keys=True)
        self.assertNotIn("access-officer", rendered)
        self.assertNotIn("dual-use review", rendered)

    def test_authenticated_store_v2_persists_only_hashes_and_reloads_mutably(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(),
            record.tickets,
            opened_at=100,
            ttl_seconds=300,
        )
        ticket_id = record.tickets[0].ticket_id
        key = b"authenticated-review-store-key-32b"
        context = "a" * 64

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir).resolve() / "review-queue.json"
            save_review_queue(
                path,
                queue,
                integrity_key=key,
                authority_context_hash=context,
            )
            persisted = path.read_text(encoding="utf-8")
            for plaintext in (
                ticket_id,
                "turn-1",
                "corpus://atlas",
                "cro-agent",
                '"ticket_id":',
                '"turn_id":',
                '"corpus_ref":',
            ):
                self.assertNotIn(plaintext, persisted)

            loaded = load_review_queue(
                path,
                integrity_key=key,
                expected_authority_context_hash=context,
            )
            state_key, ticket = next(iter(loaded.tickets.items()))
            self.assertEqual(state_key, review_ticket_ref_hash(ticket_id))
            self.assertEqual((ticket.ticket_id, ticket.turn_id, ticket.corpus_ref), ("", "", ""))
            decided = decide_review_ticket(
                loaded,
                state_key,
                decision="release",
                reviewer_ref="access-officer",
                decided_at=120,
                authorization_hash="b" * 64,
                authority_context_hash=context,
            )
            save_review_queue(
                path,
                decided,
                integrity_key=key,
                authority_context_hash=context,
            )
            reloaded = load_review_queue(
                path,
                integrity_key=key,
                expected_authority_context_hash=context,
            )
        self.assertEqual(
            next(iter(reloaded.tickets.values())).status,
            ReviewTicketStatus.RELEASED,
        )

    def test_authenticated_store_rejects_symlink_target_and_parent(self):
        record = _held_coordination_record()
        queue = enqueue_handoff_tickets(
            ReviewQueueState.empty(), record.tickets, opened_at=100, ttl_seconds=300
        )
        key = b"authenticated-review-store-key-32b"
        context = "a" * 64

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir).resolve()
            real_parent = root / "real"
            real_parent.mkdir(mode=0o700)
            target = root / "target.json"
            target.write_text("do not overwrite", encoding="utf-8")
            linked_target = real_parent / "review.json"
            linked_target.symlink_to(target)
            with self.assertRaisesRegex(ReviewQueueError, "private file"):
                save_review_queue(
                    linked_target,
                    queue,
                    integrity_key=key,
                    authority_context_hash=context,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), "do not overwrite")

            linked_parent = root / "linked-parent"
            linked_parent.symlink_to(real_parent, target_is_directory=True)
            with self.assertRaisesRegex(ReviewQueueError, "symlink component"):
                save_review_queue(
                    linked_parent / "queue.json",
                    queue,
                    integrity_key=key,
                    authority_context_hash=context,
                )


if __name__ == "__main__":
    unittest.main()
