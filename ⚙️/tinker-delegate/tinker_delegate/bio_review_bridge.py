"""Bridge a held bio-validation result to the human-review queue and back.

`bio_validation.evaluate_bio_release` fails closed to ``HOLD`` and routes to a
review role, but nothing yet connected that hold to the reviewer queue. This
module closes the loop:

* ``enqueue_bio_hold`` turns a HELD ``BioReleaseReceipt`` into a bounded review
  ticket (routed to the receipt's review role, keyed by the result hash) and adds
  it to the queue — with the evaluating agent recorded as the submitter, so it
  cannot self-approve, and a per-role M-of-N threshold if configured.
* ``resolve_bio_release`` maps the ticket's current state back to a final bio
  decision: only a queue ``RELEASED`` promotes the hold to ``RELEASE``; a
  ``DENIED`` becomes ``DENY``; anything else (pending / expired / missing) stays
  ``HOLD`` — fail closed.

Everything stays bounded: the ticket carries hashes only (result hash, hashed
reason, hashed submitter), never the raw result or reason text.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from tinker_delegate.bio_validation import (
    BioReadiness,
    BioReleaseDecision,
    BioReleaseReceipt,
    BioResultCandidate,
    BioReviewRoute,
    evaluate_bio_release,
)
from tinker_delegate.review_queue import (
    ReviewQueueState,
    ReviewTicket,
    ReviewTicketStatus,
    enqueue_handoff_tickets,
    review_ticket_ref_hash,
)


def _bio_ticket_id(result_hash: str) -> str:
    return hashlib.sha256(f"bio_hold:{result_hash}".encode("utf-8")).hexdigest()[:16]


def _bio_ticket(
    state: ReviewQueueState, result_hash: str
) -> ReviewTicket | None:
    """Resolve both process-local/raw and authenticated/hash-only queue keys."""

    ticket_id = _bio_ticket_id(result_hash)
    return state.tickets.get(ticket_id) or state.tickets.get(
        review_ticket_ref_hash(ticket_id)
    )


@dataclass(frozen=True)
class _BioHoldTicket:
    """Handoff-shaped ticket built from a held bio receipt (duck-typed for the
    review queue's ``ReviewTicket.from_handoff``)."""

    ticket_id: str
    turn_id: str
    corpus_ref: str
    routed_role: str
    reason_hash: str
    submitter_ref: str


def bio_hold_to_ticket(
    receipt: BioReleaseReceipt,
    *,
    submitter_ref: str,
    corpus_ref: str = "",
) -> _BioHoldTicket:
    """Build a bounded review ticket for a HELD bio receipt (raises otherwise)."""

    if receipt.decision != BioReleaseDecision.HOLD:
        raise ValueError("only a HELD bio receipt may be enqueued for review")
    route = receipt.review_route or BioReviewRoute.BIOSECURITY_REVIEW
    reason_hash = hashlib.sha256(
        f"bio_reason:{receipt.reason_code}".encode("utf-8")
    ).hexdigest()
    return _BioHoldTicket(
        ticket_id=_bio_ticket_id(receipt.result_hash),
        turn_id=receipt.result_hash,
        # The review queue requires a non-empty corpus ref; default to a bounded
        # marker for bio holds that carry no explicit corpus.
        corpus_ref=corpus_ref or "bio://held-result",
        routed_role=route.value,
        reason_hash=reason_hash,
        submitter_ref=submitter_ref,
    )


def enqueue_bio_hold(
    state: ReviewQueueState,
    receipt: BioReleaseReceipt,
    *,
    submitter_ref: str,
    opened_at: int,
    ttl_seconds: int,
    corpus_ref: str = "",
    required_approvals_by_role: "dict[str, int] | None" = None,
) -> ReviewQueueState:
    """Enqueue a HELD bio receipt into the review queue. Idempotent per result:
    a second enqueue of the same held result raises (the queue rejects a
    duplicate ticket id)."""

    ticket = bio_hold_to_ticket(receipt, submitter_ref=submitter_ref, corpus_ref=corpus_ref)
    return enqueue_handoff_tickets(
        state,
        (ticket,),
        opened_at=opened_at,
        ttl_seconds=ttl_seconds,
        required_approvals_by_role=required_approvals_by_role,
    )


def evaluate_and_route(
    candidate: BioResultCandidate,
    readiness: BioReadiness,
    *,
    submitter_ref: str,
    queue_state: ReviewQueueState,
    opened_at: int,
    ttl_seconds: int,
    corpus_ref: str = "",
    required_approvals_by_role: "dict[str, int] | None" = None,
    **screens: Any,
) -> "tuple[BioReleaseReceipt, ReviewQueueState]":
    """Evaluate a bio result and auto-enqueue it for review iff it HOLDs.

    A live convenience over ``evaluate_bio_release`` + ``enqueue_bio_hold``: the
    caller gets the bounded receipt and the (possibly updated) queue in one call,
    so a held result is never left un-queued. ``screens`` forwards the optional
    ``dual_use`` / ``reid`` / ``data_quality`` / ``dp_charge`` assessments. A
    RELEASE/DENY receipt leaves the queue unchanged. Enqueuing a result whose
    ticket already exists is swallowed (idempotent per result hash).
    """

    receipt = evaluate_bio_release(candidate, readiness, **screens)
    if receipt.decision != BioReleaseDecision.HOLD:
        return receipt, queue_state
    if _bio_ticket(queue_state, receipt.result_hash) is not None:
        return receipt, queue_state
    updated = enqueue_bio_hold(
        queue_state,
        receipt,
        submitter_ref=submitter_ref,
        opened_at=opened_at,
        ttl_seconds=ttl_seconds,
        corpus_ref=corpus_ref,
        required_approvals_by_role=required_approvals_by_role,
    )
    return receipt, updated


def resolve_bio_release(
    receipt: BioReleaseReceipt,
    state: ReviewQueueState,
) -> BioReleaseDecision:
    """Map the review-queue state of a held result back to a final bio decision.

    Fail-closed: only a ``RELEASED`` ticket promotes to ``RELEASE``; ``DENIED``
    becomes ``DENY``; a missing / pending / expired ticket stays ``HOLD``.
    A non-held receipt is returned unchanged (nothing to resolve).
    """

    if receipt.decision != BioReleaseDecision.HOLD:
        return receipt.decision
    ticket = _bio_ticket(state, receipt.result_hash)
    if ticket is None:
        return BioReleaseDecision.HOLD
    if ticket.status == ReviewTicketStatus.RELEASED:
        return BioReleaseDecision.RELEASE
    if ticket.status == ReviewTicketStatus.DENIED:
        return BioReleaseDecision.DENY
    return BioReleaseDecision.HOLD


def bio_review_status(receipt: BioReleaseReceipt, state: ReviewQueueState) -> dict[str, Any]:
    """Bounded status record tying a held bio result to its review ticket."""

    resolved = resolve_bio_release(receipt, state)
    ticket = _bio_ticket(state, receipt.result_hash)
    return {
        "kind": "bio_review_status",
        "result_hash": receipt.result_hash,
        "original_decision": receipt.decision.value,
        "resolved_decision": resolved.value,
        "ticket_present": ticket is not None,
        "ticket_status": ticket.status.value if ticket is not None else "absent",
        "raw_secret_egress": False,
    }
