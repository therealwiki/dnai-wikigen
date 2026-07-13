"""Bounded source-level human review queue.

This module is intentionally local and deterministic. It gives held
coordination tickets a durable queue/audit shape without sending email,
touching Tinker, or resolving coordination state implicitly.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Any


class ReviewQueueError(ValueError):
    """Raised when a review queue operation cannot be applied safely."""


class ReviewTicketStatus(str, Enum):
    PENDING = "pending"
    RELEASED = "released"
    DENIED = "denied"
    EXPIRED = "expired"


class ReviewAuditEventKind(str, Enum):
    ENQUEUED = "enqueued"
    VOTE_RECORDED = "vote_recorded"  # an M-of-N approval short of the threshold
    RELEASED = "released"
    DENIED = "denied"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ReviewTicket:
    ticket_id: str
    turn_id: str
    corpus_ref: str
    routed_role: str
    reason_hash: str
    opened_at: int
    expires_at: int
    status: ReviewTicketStatus = ReviewTicketStatus.PENDING
    reviewer_ref_hash: str = ""
    decision_hash: str = ""
    updated_at: int = 0
    # Hash of the principal that submitted the held item (same hashing as
    # reviewer_ref_hash), so a reviewer who IS the submitter is detectable.
    submitter_ref_hash: str = ""
    # M-of-N approval: a release requires this many DISTINCT reviewer approvals.
    required_approvals: int = 1
    approval_reviewer_hashes: tuple[str, ...] = ()

    @classmethod
    def from_handoff(
        cls, ticket: Any, *, opened_at: int, ttl_seconds: int, required_approvals: int = 1
    ) -> "ReviewTicket":
        if ttl_seconds <= 0:
            raise ReviewQueueError("review ticket ttl must be positive")
        if required_approvals < 1:
            raise ReviewQueueError("required_approvals must be >= 1")
        submitter_ref = getattr(ticket, "submitter_ref", "") or ""
        return cls(
            ticket_id=_require_attr(ticket, "ticket_id"),
            turn_id=_require_attr(ticket, "turn_id"),
            corpus_ref=_require_attr(ticket, "corpus_ref"),
            routed_role=_require_attr(ticket, "routed_role"),
            reason_hash=_require_attr(ticket, "reason_hash"),
            opened_at=int(opened_at),
            expires_at=int(opened_at) + int(ttl_seconds),
            updated_at=int(opened_at),
            submitter_ref_hash=(
                _stable_hash(submitter_ref, prefix="reviewer_ref") if submitter_ref else ""
            ),
            required_approvals=int(required_approvals),
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "turn_id": self.turn_id,
            "corpus_ref": self.corpus_ref,
            "routed_role": self.routed_role,
            "reason_hash": self.reason_hash,
            "opened_at": self.opened_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "reviewer_ref_hash": self.reviewer_ref_hash,
            "submitter_ref_hash": self.submitter_ref_hash,
            "required_approvals": self.required_approvals,
            "approvals_count": len(self.approval_reviewer_hashes),
            "approval_reviewer_hashes": list(self.approval_reviewer_hashes),
            "decision_hash": self.decision_hash,
            "updated_at": self.updated_at,
            "raw_secret_egress": False,
        }


@dataclass(frozen=True)
class ReviewAuditEvent:
    event_id: str
    event: ReviewAuditEventKind
    ticket_id: str
    turn_id: str
    occurred_at: int
    routed_role: str
    actor_ref_hash: str = ""
    status: ReviewTicketStatus = ReviewTicketStatus.PENDING
    decision_hash: str = ""
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event": self.event.value,
            "ticket_id": self.ticket_id,
            "turn_id": self.turn_id,
            "occurred_at": self.occurred_at,
            "routed_role": self.routed_role,
            "actor_ref_hash": self.actor_ref_hash,
            "status": self.status.value,
            "decision_hash": self.decision_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


@dataclass(frozen=True)
class ReviewQueueState:
    tickets: dict[str, ReviewTicket]
    audit: tuple[ReviewAuditEvent, ...] = ()

    @classmethod
    def empty(cls) -> "ReviewQueueState":
        return cls(tickets={})

    def to_public_dict(self) -> dict[str, Any]:
        pending = [ticket for ticket in self.tickets.values() if ticket.status == ReviewTicketStatus.PENDING]
        return {
            "surface": "human_review_queue",
            "schema_version": 1,
            "ticket_count": len(self.tickets),
            "pending_count": len(pending),
            "status_counts": _status_counts(self.tickets.values()),
            "tickets": [ticket.to_public_dict() for ticket in sorted(self.tickets.values(), key=lambda item: item.ticket_id)],
            "audit_hash": _stable_hash(
                [event.to_public_dict() for event in self.audit],
                prefix="review_queue_audit",
            ),
            "audit_count": len(self.audit),
            "raw_secret_egress": False,
        }


def enqueue_handoff_tickets(
    state: ReviewQueueState,
    tickets: tuple[Any, ...],
    *,
    opened_at: int,
    ttl_seconds: int,
    required_approvals_by_role: "dict[str, int] | None" = None,
) -> ReviewQueueState:
    """Ingest handoff tickets. ``required_approvals_by_role`` sets an M-of-N
    approval threshold per routed role (default 1); high-risk roles (e.g.
    biosecurity review) can require multiple distinct reviewers to release."""

    role_thresholds = required_approvals_by_role or {}
    updated = dict(state.tickets)
    audit = list(state.audit)
    for handoff in tickets:
        routed_role = _require_attr(handoff, "routed_role")
        ticket = ReviewTicket.from_handoff(
            handoff,
            opened_at=opened_at,
            ttl_seconds=ttl_seconds,
            required_approvals=int(role_thresholds.get(routed_role, 1)),
        )
        if ticket.ticket_id in updated:
            raise ReviewQueueError("review ticket already exists")
        updated[ticket.ticket_id] = ticket
        audit.append(_audit_event(ReviewAuditEventKind.ENQUEUED, ticket, occurred_at=opened_at))
    return ReviewQueueState(tickets=updated, audit=tuple(audit))


def decide_review_ticket(
    state: ReviewQueueState,
    ticket_id: str,
    *,
    decision: str,
    reviewer_ref: str,
    decided_at: int,
    blocked_reviewer_refs: tuple[str, ...] = (),
) -> ReviewQueueState:
    if decision not in {"release", "deny"}:
        raise ReviewQueueError("review decision must be release or deny")
    if reviewer_ref in blocked_reviewer_refs:
        raise ReviewQueueError("reviewer is not allowed to resolve this ticket")
    ticket = _pending_ticket(state, ticket_id, now=decided_at)
    # Structural non-self-approval: the principal that submitted the held item may
    # never resolve its own ticket, independent of the caller-supplied block list.
    reviewer_hash = _stable_hash(reviewer_ref, prefix="reviewer_ref")
    if ticket.submitter_ref_hash and reviewer_hash == ticket.submitter_ref_hash:
        raise ReviewQueueError("submitter may not self-approve their own review ticket")

    decision_hash = _stable_hash(decision, prefix="review_decision")

    # Deny is immediate and fail-closed: any single reviewer can block release.
    if decision == "deny":
        updated_ticket = replace(
            ticket,
            status=ReviewTicketStatus.DENIED,
            reviewer_ref_hash=reviewer_hash,
            decision_hash=decision_hash,
            updated_at=int(decided_at),
        )
        event_kind = ReviewAuditEventKind.DENIED
    else:
        # Release: accumulate M-of-N distinct approvals. One reviewer, one vote.
        if reviewer_hash in ticket.approval_reviewer_hashes:
            raise ReviewQueueError("reviewer has already approved this ticket")
        approvals = ticket.approval_reviewer_hashes + (reviewer_hash,)
        if len(approvals) >= ticket.required_approvals:
            updated_ticket = replace(
                ticket,
                status=ReviewTicketStatus.RELEASED,
                reviewer_ref_hash=reviewer_hash,
                decision_hash=decision_hash,
                approval_reviewer_hashes=approvals,
                updated_at=int(decided_at),
            )
            event_kind = ReviewAuditEventKind.RELEASED
        else:
            # Threshold not yet met: record the vote; ticket stays PENDING.
            updated_ticket = replace(
                ticket,
                reviewer_ref_hash=reviewer_hash,
                decision_hash=decision_hash,
                approval_reviewer_hashes=approvals,
                updated_at=int(decided_at),
            )
            event_kind = ReviewAuditEventKind.VOTE_RECORDED

    tickets = dict(state.tickets)
    tickets[ticket_id] = updated_ticket
    event = _audit_event(
        event_kind,
        updated_ticket,
        occurred_at=decided_at,
        actor_ref_hash=reviewer_hash,
        decision_hash=decision_hash,
    )
    return ReviewQueueState(tickets=tickets, audit=tuple(state.audit) + (event,))


def expire_review_tickets(state: ReviewQueueState, *, now: int) -> ReviewQueueState:
    tickets = dict(state.tickets)
    audit = list(state.audit)
    for ticket_id, ticket in state.tickets.items():
        if ticket.status != ReviewTicketStatus.PENDING or ticket.expires_at > now:
            continue
        expired = replace(ticket, status=ReviewTicketStatus.EXPIRED, updated_at=int(now))
        tickets[ticket_id] = expired
        audit.append(_audit_event(ReviewAuditEventKind.EXPIRED, expired, occurred_at=now))
    return ReviewQueueState(tickets=tickets, audit=tuple(audit))


def pending_tickets_for_role(state: ReviewQueueState, routed_role: str, *, now: int | None = None) -> tuple[ReviewTicket, ...]:
    tickets = []
    for ticket in state.tickets.values():
        if ticket.routed_role != routed_role or ticket.status != ReviewTicketStatus.PENDING:
            continue
        if now is not None and ticket.expires_at <= now:
            continue
        tickets.append(ticket)
    return tuple(sorted(tickets, key=lambda item: item.ticket_id))


def save_review_queue(path: str | Path, state: ReviewQueueState) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "surface": "human_review_queue_store",
        "schema_version": 1,
        "tickets": [ticket.to_public_dict() for ticket in state.tickets.values()],
        "audit": [event.to_public_dict() for event in state.audit],
        "raw_secret_egress": False,
    }
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, target)


def load_review_queue(path: str | Path) -> ReviewQueueState:
    source = Path(path)
    if not source.exists():
        return ReviewQueueState.empty()
    payload = json.loads(source.read_text(encoding="utf-8"))
    tickets = {
        str(item["ticket_id"]): _ticket_from_public_dict(item)
        for item in payload.get("tickets", [])
    }
    audit = tuple(_audit_from_public_dict(item) for item in payload.get("audit", []))
    return ReviewQueueState(tickets=tickets, audit=audit)


def _pending_ticket(state: ReviewQueueState, ticket_id: str, *, now: int) -> ReviewTicket:
    try:
        ticket = state.tickets[ticket_id]
    except KeyError as exc:
        raise ReviewQueueError("unknown review ticket") from exc
    if ticket.status != ReviewTicketStatus.PENDING:
        raise ReviewQueueError("review ticket is not pending")
    if ticket.expires_at <= now:
        raise ReviewQueueError("review ticket expired")
    return ticket


def _audit_event(
    event: ReviewAuditEventKind,
    ticket: ReviewTicket,
    *,
    occurred_at: int,
    actor_ref_hash: str = "",
    decision_hash: str = "",
) -> ReviewAuditEvent:
    public = {
        "event": event.value,
        "ticket_id": ticket.ticket_id,
        "turn_id": ticket.turn_id,
        "occurred_at": int(occurred_at),
        "routed_role": ticket.routed_role,
        "actor_ref_hash": actor_ref_hash,
        "status": ticket.status.value,
        "decision_hash": decision_hash,
    }
    return ReviewAuditEvent(
        event_id=_stable_hash(public, prefix="review_audit_event")[:16],
        event=event,
        ticket_id=ticket.ticket_id,
        turn_id=ticket.turn_id,
        occurred_at=int(occurred_at),
        routed_role=ticket.routed_role,
        actor_ref_hash=actor_ref_hash,
        status=ticket.status,
        decision_hash=decision_hash,
    )


def _ticket_from_public_dict(payload: dict[str, Any]) -> ReviewTicket:
    return ReviewTicket(
        ticket_id=str(payload["ticket_id"]),
        turn_id=str(payload["turn_id"]),
        corpus_ref=str(payload["corpus_ref"]),
        routed_role=str(payload["routed_role"]),
        reason_hash=str(payload["reason_hash"]),
        opened_at=int(payload["opened_at"]),
        expires_at=int(payload["expires_at"]),
        status=ReviewTicketStatus(str(payload["status"])),
        reviewer_ref_hash=str(payload.get("reviewer_ref_hash", "")),
        submitter_ref_hash=str(payload.get("submitter_ref_hash", "")),
        required_approvals=int(payload.get("required_approvals", 1)),
        approval_reviewer_hashes=tuple(
            str(h) for h in payload.get("approval_reviewer_hashes", ())
        ),
        decision_hash=str(payload.get("decision_hash", "")),
        updated_at=int(payload.get("updated_at", payload["opened_at"])),
    )


def _audit_from_public_dict(payload: dict[str, Any]) -> ReviewAuditEvent:
    return ReviewAuditEvent(
        event_id=str(payload["event_id"]),
        event=ReviewAuditEventKind(str(payload["event"])),
        ticket_id=str(payload["ticket_id"]),
        turn_id=str(payload["turn_id"]),
        occurred_at=int(payload["occurred_at"]),
        routed_role=str(payload["routed_role"]),
        actor_ref_hash=str(payload.get("actor_ref_hash", "")),
        status=ReviewTicketStatus(str(payload.get("status", ReviewTicketStatus.PENDING.value))),
        decision_hash=str(payload.get("decision_hash", "")),
        raw_secret_egress=False,
    )


def _status_counts(tickets: Any) -> dict[str, int]:
    counts = {status.value: 0 for status in ReviewTicketStatus}
    for ticket in tickets:
        counts[ticket.status.value] += 1
    return counts


def _require_attr(value: Any, attr: str) -> str:
    item = getattr(value, attr, "")
    if not isinstance(item, str) or not item:
        raise ReviewQueueError(f"handoff ticket missing {attr}")
    return item


def _stable_hash(value: Any, *, prefix: str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + payload.encode("utf-8")).hexdigest()
