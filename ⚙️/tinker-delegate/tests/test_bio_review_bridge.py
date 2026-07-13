import json
import unittest

from tinker_delegate.bio_review_bridge import (
    bio_review_status,
    enqueue_bio_hold,
    evaluate_and_route,
    resolve_bio_release,
)
from tinker_delegate.bio_validation import (
    BioBand,
    BioReadiness,
    BioReleaseDecision,
    BioResultCandidate,
    evaluate_bio_release,
)
from tinker_delegate.review_queue import (
    ReviewQueueError,
    ReviewQueueState,
    decide_review_ticket,
)


def _held_receipt() -> "tuple":
    # Individual-level data without DP marking -> HOLD / biosecurity review.
    candidate = BioResultCandidate(
        use_case_id="synthetic-assay-qc",
        methodology_class="sft_lora_scorer",
        score_band=BioBand.HIGH,
        individual_level_data=True,
        differential_privacy_marked=False,
    )
    ready = BioReadiness(
        risk_screen_enabled=True,
        reviewer_queue_enabled=True,
        bounded_schema_enabled=True,
        synthetic_or_approved_data_only=True,
    )
    receipt = evaluate_bio_release(candidate, ready)
    return receipt


class BioReviewBridgeTest(unittest.TestCase):
    def setUp(self):
        self.receipt = _held_receipt()
        self.assertEqual(self.receipt.decision, BioReleaseDecision.HOLD)

    def _enqueue(self, **kw):
        return enqueue_bio_hold(
            ReviewQueueState.empty(), self.receipt,
            submitter_ref="cro-agent", opened_at=1000, ttl_seconds=100000, **kw,
        )

    def test_held_result_stays_held_without_a_ticket(self):
        self.assertEqual(
            resolve_bio_release(self.receipt, ReviewQueueState.empty()),
            BioReleaseDecision.HOLD,
        )

    def test_pending_ticket_keeps_hold(self):
        queue = self._enqueue()
        self.assertEqual(resolve_bio_release(self.receipt, queue), BioReleaseDecision.HOLD)

    def test_released_ticket_promotes_to_release(self):
        queue = self._enqueue()
        ticket_id = next(iter(queue.tickets))
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="biosec-officer", decided_at=1100
        )
        self.assertEqual(resolve_bio_release(self.receipt, queue), BioReleaseDecision.RELEASE)

    def test_denied_ticket_becomes_deny(self):
        queue = self._enqueue()
        ticket_id = next(iter(queue.tickets))
        queue = decide_review_ticket(
            queue, ticket_id, decision="deny", reviewer_ref="biosec-officer", decided_at=1100
        )
        self.assertEqual(resolve_bio_release(self.receipt, queue), BioReleaseDecision.DENY)

    def test_submitter_cannot_release_its_own_bio_hold(self):
        queue = self._enqueue()
        ticket_id = next(iter(queue.tickets))
        with self.assertRaisesRegex(ReviewQueueError, "self-approve"):
            decide_review_ticket(
                queue, ticket_id, decision="release", reviewer_ref="cro-agent", decided_at=1100
            )

    def test_m_of_n_biosecurity_review(self):
        route = self.receipt.review_route.value
        queue = self._enqueue(required_approvals_by_role={route: 2})
        ticket_id = next(iter(queue.tickets))
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=1100
        )
        # One approval short: still held.
        self.assertEqual(resolve_bio_release(self.receipt, queue), BioReleaseDecision.HOLD)
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-b", decided_at=1105
        )
        self.assertEqual(resolve_bio_release(self.receipt, queue), BioReleaseDecision.RELEASE)

    def test_status_record_is_bounded(self):
        queue = self._enqueue()
        status = bio_review_status(self.receipt, queue)
        self.assertEqual(status["original_decision"], "hold")
        self.assertEqual(status["resolved_decision"], "hold")
        self.assertTrue(status["ticket_present"])
        self.assertFalse(status["raw_secret_egress"])
        self.assertNotIn("cro-agent", json.dumps(status))

    def test_evaluate_and_route_auto_enqueues_a_hold(self):
        candidate = BioResultCandidate(
            use_case_id="synthetic-assay-qc", methodology_class="sft_lora_scorer",
            score_band=BioBand.HIGH, individual_level_data=True, differential_privacy_marked=False,
        )
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        receipt, queue = evaluate_and_route(
            candidate, ready, submitter_ref="cro-agent",
            queue_state=ReviewQueueState.empty(), opened_at=1000, ttl_seconds=100000,
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        # A held result is never left un-queued.
        self.assertEqual(len(queue.tickets), 1)
        self.assertEqual(resolve_bio_release(receipt, queue), BioReleaseDecision.HOLD)

    def test_evaluate_and_route_leaves_queue_unchanged_on_clear(self):
        candidate = BioResultCandidate(use_case_id="u", methodology_class="m")
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        receipt, queue = evaluate_and_route(
            candidate, ready, submitter_ref="cro-agent",
            queue_state=ReviewQueueState.empty(), opened_at=1000, ttl_seconds=100000,
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.RELEASE)
        self.assertEqual(len(queue.tickets), 0)

    def test_evaluate_and_route_requires_dual_use_screen_holds_and_enqueues(self):
        # The same clean candidate that RELEASEs by default must HOLD and auto-
        # enqueue for biosecurity review when a dual-use-domain caller sets
        # require_dual_use_screen and supplies no assessment — the flag flows
        # through evaluate_and_route's **screens and fails closed to review.
        candidate = BioResultCandidate(use_case_id="u", methodology_class="m")
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        receipt, queue = evaluate_and_route(
            candidate, ready, submitter_ref="cro-agent",
            queue_state=ReviewQueueState.empty(), opened_at=1000, ttl_seconds=100000,
            require_dual_use_screen=True,
        )
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)
        self.assertEqual(receipt.reason_code, "dual_use_screen_required")
        self.assertEqual(len(queue.tickets), 1)

    def test_evaluate_and_route_is_idempotent_per_result(self):
        candidate = BioResultCandidate(
            use_case_id="synthetic-assay-qc", methodology_class="sft_lora_scorer",
            score_band=BioBand.HIGH, individual_level_data=True, differential_privacy_marked=False,
        )
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        _, queue = evaluate_and_route(
            candidate, ready, submitter_ref="cro-agent",
            queue_state=ReviewQueueState.empty(), opened_at=1000, ttl_seconds=100000,
        )
        # Re-evaluating the same held result does not double-enqueue.
        _, queue2 = evaluate_and_route(
            candidate, ready, submitter_ref="cro-agent",
            queue_state=queue, opened_at=1001, ttl_seconds=100000,
        )
        self.assertEqual(len(queue2.tickets), 1)

    def test_non_held_receipt_is_unchanged(self):
        # A cleared receipt has nothing to resolve; the decision passes through.
        candidate = BioResultCandidate(use_case_id="u", methodology_class="m")
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        cleared = evaluate_bio_release(candidate, ready)
        self.assertEqual(cleared.decision, BioReleaseDecision.RELEASE)
        self.assertEqual(
            resolve_bio_release(cleared, ReviewQueueState.empty()), BioReleaseDecision.RELEASE
        )


if __name__ == "__main__":
    unittest.main()
