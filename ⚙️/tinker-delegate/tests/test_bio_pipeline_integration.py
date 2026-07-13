"""End-to-end integration of the bio-diligence pipeline over sealed data.

Ties together the real modules in one cohesive flow, proving they compose:

  evaluate_bio_release (HOLD)          bio_validation
    -> enqueue_bio_hold                bio_review_bridge
    -> M-of-N reviewer release         review_queue (2 distinct biosec officers)
    -> resolve_bio_release (RELEASE)   bio_review_bridge
    -> decide_disclosure (ESCROW)      disclosure_policy
    -> seal + authorized release       solution_escrow

Only bounded bands/hashes/decisions cross boundaries; the submitter cannot
self-approve, a single officer cannot release (M-of-N), and the winning candidate
is only recoverable from escrow with the authorization secret.
"""
import unittest

from tinker_delegate.bio_review_bridge import enqueue_bio_hold, resolve_bio_release
from tinker_delegate.bio_validation import (
    BioBand,
    BioReadiness,
    BioReleaseDecision,
    BioResultCandidate,
    evaluate_bio_release,
)
from tinker_delegate.disclosure_policy import DisclosureMode, decide_disclosure
from tinker_delegate.review_queue import ReviewQueueError, ReviewQueueState, decide_review_ticket
from tinker_delegate.solution_escrow import SolutionEscrowStore


class BioPipelineIntegrationTest(unittest.TestCase):
    def test_held_bio_result_flows_through_review_disclosure_and_escrow(self):
        # 1. Evaluate: individual-level data without DP marking -> HOLD.
        candidate = BioResultCandidate(
            use_case_id="synthetic-assay-qc",
            methodology_class="sft_lora_scorer",
            score_band=BioBand.HIGH,
            individual_level_data=True,
            differential_privacy_marked=False,
        )
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        receipt = evaluate_bio_release(candidate, ready)
        self.assertEqual(receipt.decision, BioReleaseDecision.HOLD)

        # 2. Enqueue to the review queue, requiring 2 distinct biosecurity officers.
        route = receipt.review_route.value
        queue = enqueue_bio_hold(
            ReviewQueueState.empty(), receipt,
            submitter_ref="cro-agent", opened_at=1000, ttl_seconds=100000,
            required_approvals_by_role={route: 2},
        )
        ticket_id = next(iter(queue.tickets))
        # Still held while pending.
        self.assertEqual(resolve_bio_release(receipt, queue), BioReleaseDecision.HOLD)

        # 3a. The submitting agent cannot self-approve.
        with self.assertRaisesRegex(ReviewQueueError, "self-approve"):
            decide_review_ticket(
                queue, ticket_id, decision="release", reviewer_ref="cro-agent", decided_at=1100
            )
        # 3b. One officer is not enough (M-of-N).
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=1100
        )
        self.assertEqual(resolve_bio_release(receipt, queue), BioReleaseDecision.HOLD)
        # 3c. A second distinct officer crosses the threshold.
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-b", decided_at=1110
        )

        # 4. Resolve: the queue release promotes the hold to RELEASE.
        self.assertEqual(resolve_bio_release(receipt, queue), BioReleaseDecision.RELEASE)

        # 5. The winning candidate's code is released only under the disclosure
        # policy. No public permission + individual-level lineage -> ESCROW.
        winning_code = b"def score(assay):\n    return zprime(assay)\n"
        decision = decide_disclosure(winning_code)  # allow_public defaults False
        self.assertEqual(decision.mode, DisclosureMode.ESCROW)
        self.assertIsNone(decision.disclosable_payload(winning_code))

        # 6. Seal it in escrow; only the authorization secret recovers it.
        store = SolutionEscrowStore()
        auth = b"release-secret-for-the-buyer"
        store.seal("deal-bio-1", winning_code, disclosure_mode=decision.mode, authorization=auth)
        with self.assertRaises(Exception):
            store.release("deal-bio-1", authorization=b"wrong")
        self.assertEqual(store.release("deal-bio-1", authorization=auth), winning_code)

    def test_single_deny_vetoes_the_whole_pipeline(self):
        candidate = BioResultCandidate(
            use_case_id="synthetic-assay-qc", methodology_class="sft_lora_scorer",
            score_band=BioBand.HIGH, individual_level_data=True, differential_privacy_marked=False,
        )
        ready = BioReadiness(
            risk_screen_enabled=True, reviewer_queue_enabled=True,
            bounded_schema_enabled=True, synthetic_or_approved_data_only=True,
        )
        receipt = evaluate_bio_release(candidate, ready)
        route = receipt.review_route.value
        queue = enqueue_bio_hold(
            ReviewQueueState.empty(), receipt,
            submitter_ref="cro-agent", opened_at=1000, ttl_seconds=100000,
            required_approvals_by_role={route: 3},
        )
        ticket_id = next(iter(queue.tickets))
        queue = decide_review_ticket(
            queue, ticket_id, decision="release", reviewer_ref="officer-a", decided_at=1100
        )
        # One deny, even with a prior approval and a 3-of-N threshold, denies.
        queue = decide_review_ticket(
            queue, ticket_id, decision="deny", reviewer_ref="officer-b", decided_at=1110
        )
        self.assertEqual(resolve_bio_release(receipt, queue), BioReleaseDecision.DENY)


if __name__ == "__main__":
    unittest.main()
