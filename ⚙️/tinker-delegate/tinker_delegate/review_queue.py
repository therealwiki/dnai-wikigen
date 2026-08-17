"""Bounded source-level human review queue.

This module is intentionally local and deterministic. It gives held
coordination tickets a durable queue/audit shape without sending email,
touching Tinker, or resolving coordination state implicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import fcntl
from contextlib import contextmanager
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


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_STORE_INTEGRITY_RE = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_MAX_STORE_BYTES = 8 * 1024 * 1024
_MAX_TICKETS = 20_000
_MAX_AUDIT_EVENTS = 100_000
_TICKET_STORE_FIELDS = frozenset(
    {
        "ticket_ref_hash",
        "turn_ref_hash",
        "corpus_ref_hash",
        "routed_role",
        "reason_hash",
        "opened_at",
        "expires_at",
        "status",
        "reviewer_ref_hash",
        "submitter_ref_hash",
        "required_approvals",
        "approvals_count",
        "approval_reviewer_hashes",
        "approval_authorization_hashes",
        "reviewer_authorization_hash",
        "authority_context_hash",
        "decision_hash",
        "updated_at",
        "raw_secret_egress",
    }
)
_AUDIT_STORE_FIELDS = frozenset(
    {
        "event_id",
        "event",
        "ticket_ref_hash",
        "turn_ref_hash",
        "occurred_at",
        "routed_role",
        "actor_ref_hash",
        "status",
        "decision_hash",
        "authorization_hash",
        "authority_context_hash",
        "raw_secret_egress",
    }
)
_LEGACY_TICKET_STORE_FIELDS = (
    _TICKET_STORE_FIELDS
    - {"ticket_ref_hash", "turn_ref_hash", "corpus_ref_hash"}
) | {"ticket_id", "turn_id", "corpus_ref"}
_LEGACY_AUDIT_STORE_FIELDS = (
    _AUDIT_STORE_FIELDS - {"ticket_ref_hash", "turn_ref_hash"}
) | {"ticket_id", "turn_id"}


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
    # One authorization digest per release approval, in the same order as
    # ``approval_reviewer_hashes``. Raw signatures never enter the queue.
    approval_authorization_hashes: tuple[str, ...] = ()
    # Hash-only evidence for the most recent terminal or partial decision.
    reviewer_authorization_hash: str = ""
    authority_context_hash: str = ""
    # Schema-v2 persistence uses only these domain-separated reference hashes.
    # Raw refs remain process-local for newly enqueued/legacy schema-v1 state.
    ticket_ref_digest: str = ""
    turn_ref_digest: str = ""
    corpus_ref_digest: str = ""

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
            ticket_ref_digest=review_ticket_ref_hash(
                _require_attr(ticket, "ticket_id")
            ),
            turn_ref_digest=_stable_hash(
                _require_attr(ticket, "turn_id"), prefix="review_turn_ref"
            ),
            corpus_ref_digest=_stable_hash(
                _require_attr(ticket, "corpus_ref"), prefix="review_corpus_ref"
            ),
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
            "approval_authorization_hashes": list(self.approval_authorization_hashes),
            "reviewer_authorization_hash": self.reviewer_authorization_hash,
            "authority_context_hash": self.authority_context_hash,
            "decision_hash": self.decision_hash,
            "updated_at": self.updated_at,
            "raw_secret_egress": False,
        }

    def to_browser_dict(self) -> dict[str, Any]:
        """Return the queue projection safe for an unauthenticated browser.

        Internal identifiers can carry tenant or corpus naming. The public
        surface therefore emits only domain-separated hashes for those fields.
        """

        public = self.to_public_dict()
        public.pop("ticket_id")
        public.pop("turn_id")
        public.pop("corpus_ref")
        return {
            "ticket_ref_hash": _ticket_ref_digest(self),
            "turn_ref_hash": _turn_ref_digest(self),
            "corpus_ref_hash": _corpus_ref_digest(self),
            **public,
        }

    def to_store_v2_dict(self) -> dict[str, Any]:
        public = self.to_public_dict()
        public.pop("ticket_id")
        public.pop("turn_id")
        public.pop("corpus_ref")
        return {
            "ticket_ref_hash": _ticket_ref_digest(self),
            "turn_ref_hash": _turn_ref_digest(self),
            "corpus_ref_hash": _corpus_ref_digest(self),
            **public,
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
    authorization_hash: str = ""
    authority_context_hash: str = ""
    ticket_ref_digest: str = ""
    turn_ref_digest: str = ""
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
            "authorization_hash": self.authorization_hash,
            "authority_context_hash": self.authority_context_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }

    def to_store_v2_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event": self.event.value,
            "ticket_ref_hash": _audit_ticket_ref_digest(self),
            "turn_ref_hash": _audit_turn_ref_digest(self),
            "occurred_at": self.occurred_at,
            "routed_role": self.routed_role,
            "actor_ref_hash": self.actor_ref_hash,
            "status": self.status.value,
            "decision_hash": self.decision_hash,
            "authorization_hash": self.authorization_hash,
            "authority_context_hash": self.authority_context_hash,
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
                [event.to_store_v2_dict() for event in self.audit],
                prefix="review_queue_audit",
            ),
            "audit_count": len(self.audit),
            "raw_secret_egress": False,
        }

    def to_browser_dict(self, *, now: int | None = None) -> dict[str, Any]:
        tickets = list(self.tickets.values())
        if now is not None:
            tickets = [
                ticket
                for ticket in tickets
                if ticket.status != ReviewTicketStatus.PENDING
                or ticket.expires_at > now
            ]
        pending = [
            ticket for ticket in tickets if ticket.status == ReviewTicketStatus.PENDING
        ]
        return {
            "surface": "human_review_queue",
            "schema_version": 2,
            "ticket_count": len(tickets),
            "pending_count": len(pending),
            "status_counts": _status_counts(tickets),
            "tickets": [
                ticket.to_browser_dict()
                for ticket in sorted(tickets, key=review_ticket_reference_hash)
            ],
            "audit_hash": _stable_hash(
                [event.to_store_v2_dict() for event in self.audit],
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
        ticket_ref_hash = review_ticket_reference_hash(ticket)
        if any(
            hmac.compare_digest(
                review_ticket_reference_hash(existing), ticket_ref_hash
            )
            for existing in updated.values()
        ):
            raise ReviewQueueError("review ticket already exists")
        # Preserve raw keys for legacy/in-memory callers, but keep a reloaded
        # authenticated state hash-keyed. Never overwrite an unrelated ticket
        # merely because an attacker chose a raw ID equal to an existing key.
        authenticated_state = any(
            existing.ticket_ref_digest and not existing.ticket_id
            for existing in updated.values()
        )
        state_key = ticket_ref_hash if authenticated_state else ticket.ticket_id
        if state_key in updated:
            raise ReviewQueueError("review ticket state key collides")
        updated[state_key] = ticket
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
    authorization_hash: str = "",
    authority_context_hash: str = "",
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
    if bool(authorization_hash) != bool(authority_context_hash):
        raise ReviewQueueError(
            "review authorization and authority context must be supplied together"
        )
    if authorization_hash:
        _require_hash(authorization_hash, "review authorization hash")
        _require_hash(authority_context_hash, "review authority context hash")

    # Deny is immediate and fail-closed: any single reviewer can block release.
    if decision == "deny":
        updated_ticket = replace(
            ticket,
            status=ReviewTicketStatus.DENIED,
            reviewer_ref_hash=reviewer_hash,
            decision_hash=decision_hash,
            reviewer_authorization_hash=authorization_hash,
            authority_context_hash=authority_context_hash,
            updated_at=int(decided_at),
        )
        event_kind = ReviewAuditEventKind.DENIED
    else:
        # Release: accumulate M-of-N distinct approvals. One reviewer, one vote.
        if reviewer_hash in ticket.approval_reviewer_hashes:
            raise ReviewQueueError("reviewer has already approved this ticket")
        approvals = ticket.approval_reviewer_hashes + (reviewer_hash,)
        approval_authorizations = ticket.approval_authorization_hashes + (
            authorization_hash,
        )
        if len(approvals) >= ticket.required_approvals:
            updated_ticket = replace(
                ticket,
                status=ReviewTicketStatus.RELEASED,
                reviewer_ref_hash=reviewer_hash,
                decision_hash=decision_hash,
                approval_reviewer_hashes=approvals,
                approval_authorization_hashes=approval_authorizations,
                reviewer_authorization_hash=authorization_hash,
                authority_context_hash=authority_context_hash,
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
                approval_authorization_hashes=approval_authorizations,
                reviewer_authorization_hash=authorization_hash,
                authority_context_hash=authority_context_hash,
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
        authorization_hash=authorization_hash,
        authority_context_hash=authority_context_hash,
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
    return tuple(sorted(tickets, key=review_ticket_reference_hash))


def save_review_queue(
    path: str | Path,
    state: ReviewQueueState,
    *,
    integrity_key: bytes | None = None,
    authority_context_hash: str = "",
) -> None:
    target = Path(path)
    authenticated = integrity_key is not None
    payload = {
        "surface": "human_review_queue_store",
        "schema_version": 2 if authenticated else 1,
        "tickets": [
            ticket.to_store_v2_dict() if authenticated else ticket.to_public_dict()
            for ticket in state.tickets.values()
        ],
        "audit": [
            event.to_store_v2_dict() if authenticated else event.to_public_dict()
            for event in state.audit
        ],
        "raw_secret_egress": False,
    }
    if integrity_key is not None:
        _require_integrity_key(integrity_key)
        payload["authority_context_hash"] = _require_hash(
            authority_context_hash, "review authority context hash"
        )
        payload["integrity"] = _store_integrity(payload, integrity_key)
    _atomic_write_json(target, payload)


def review_queue_state_hash(
    state: ReviewQueueState,
    *,
    authority_context_hash: str,
) -> str:
    """Commit the exact hash-only queue state for an external rollback witness."""

    context = _require_hash(
        authority_context_hash,
        "review authority context hash",
    )
    payload = {
        "schema": "dnai.review-queue-state-commitment.v1",
        "authority_context_hash": context,
        "tickets": sorted(
            (ticket.to_store_v2_dict() for ticket in state.tickets.values()),
            key=lambda item: item["ticket_ref_hash"],
        ),
        "audit": [event.to_store_v2_dict() for event in state.audit],
        "raw_secret_egress": False,
    }
    return hashlib.sha256(
        b"dnai-wikigen/review-queue-state-commitment/v1\0"
        + _canonical_json(payload)
    ).hexdigest()


def review_queue_pending_path(path: str | Path) -> Path:
    active = Path(path)
    return active.with_name(f".{active.name}.anchoring-pending")


def promote_review_queue_pending(path: str | Path) -> None:
    """Atomically make the already-authenticated pending state active."""

    active = Path(path)
    pending = review_queue_pending_path(active)
    directory = -1
    try:
        directory = _open_store_parent(active)
        pending_info = os.stat(
            pending.name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        _require_store_file(pending_info)
        try:
            active_info = os.stat(
                active.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            active_info = None
        if active_info is not None:
            _require_store_file(active_info)
        os.replace(
            pending.name,
            active.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        committed = os.stat(
            active.name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        _require_store_file(committed)
        if _rename_stable_file_identity(committed) != _rename_stable_file_identity(
            pending_info
        ):
            raise ReviewQueueError("review queue pending promotion changed identity")
        os.fsync(directory)
    except ReviewQueueError:
        raise
    except OSError as exc:
        raise ReviewQueueError(
            "review queue pending promotion failed"
        ) from exc
    finally:
        if directory >= 0:
            os.close(directory)


def discard_review_queue_pending(path: str | Path) -> None:
    """Remove only a validated private pending file after anchor comparison."""

    active = Path(path)
    pending = review_queue_pending_path(active)
    directory = -1
    try:
        directory = _open_store_parent(active)
        try:
            info = os.stat(
                pending.name,
                dir_fd=directory,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        _require_store_file(info)
        os.unlink(pending.name, dir_fd=directory)
        os.fsync(directory)
    except ReviewQueueError:
        raise
    except OSError as exc:
        raise ReviewQueueError("review queue pending discard failed") from exc
    finally:
        if directory >= 0:
            os.close(directory)


@contextmanager
def review_queue_exclusive_lease(path: str | Path):
    """Serialize queue recovery and mutation across API worker processes."""

    active = Path(path)
    lock_name = f".{active.name}.lock"
    directory = -1
    descriptor = -1
    try:
        directory = _open_store_parent(active)
        descriptor = os.open(
            lock_name,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory,
        )
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
        ):
            raise ReviewQueueError("review queue lease file is invalid")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    except ReviewQueueError:
        raise
    except OSError as exc:
        raise ReviewQueueError("review queue lease is unavailable") from exc
    finally:
        if descriptor >= 0:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
        if directory >= 0:
            os.close(directory)


def load_review_queue(
    path: str | Path,
    *,
    integrity_key: bytes | None = None,
    expected_authority_context_hash: str = "",
) -> ReviewQueueState:
    source = Path(path)
    if not source.exists():
        return ReviewQueueState.empty()
    payload = _read_store_json(source)
    authenticated = integrity_key is not None
    if not authenticated:
        expected_keys = {
            "surface",
            "schema_version",
            "tickets",
            "audit",
            "raw_secret_egress",
        }
        if set(payload) != expected_keys or payload.get("schema_version") != 1:
            raise ReviewQueueError("review queue store requires an integrity key")
    else:
        _require_integrity_key(integrity_key)
        expected_keys = {
            "surface",
            "schema_version",
            "tickets",
            "audit",
            "raw_secret_egress",
            "authority_context_hash",
            "integrity",
        }
        if set(payload) != expected_keys or payload.get("schema_version") != 2:
            raise ReviewQueueError("review queue store schema is invalid")
        expected_context = _require_hash(
            expected_authority_context_hash, "review authority context hash"
        )
        stored_context = _require_hash(
            payload.get("authority_context_hash"), "stored review authority context hash"
        )
        if not hmac.compare_digest(stored_context, expected_context):
            raise ReviewQueueError("review queue authority context changed")
        supplied_integrity = payload.get("integrity")
        if (
            not isinstance(supplied_integrity, str)
            or not _STORE_INTEGRITY_RE.fullmatch(supplied_integrity)
        ):
            raise ReviewQueueError("review queue store integrity is invalid")
        unsigned = dict(payload)
        unsigned.pop("integrity")
        expected_integrity = _store_integrity(unsigned, integrity_key)
        if not hmac.compare_digest(supplied_integrity, expected_integrity):
            raise ReviewQueueError("review queue store integrity check failed")
    if (
        payload.get("surface") != "human_review_queue_store"
        or payload.get("raw_secret_egress") is not False
    ):
        raise ReviewQueueError("review queue store metadata is invalid")
    raw_tickets = payload.get("tickets")
    raw_audit = payload.get("audit")
    if (
        not isinstance(raw_tickets, list)
        or len(raw_tickets) > _MAX_TICKETS
        or not isinstance(raw_audit, list)
        or len(raw_audit) > _MAX_AUDIT_EVENTS
    ):
        raise ReviewQueueError("review queue store exceeds its bounded capacity")
    tickets: dict[str, ReviewTicket] = {}
    for item in raw_tickets:
        expected_ticket_fields = (
            _TICKET_STORE_FIELDS if authenticated else _LEGACY_TICKET_STORE_FIELDS
        )
        if not isinstance(item, dict) or set(item) != expected_ticket_fields:
            raise ReviewQueueError("review queue ticket is invalid")
        _validate_ticket_payload(item, authenticated=authenticated)
        ticket = (
            _ticket_from_store_v2_dict(item)
            if authenticated
            else _ticket_from_public_dict(item)
        )
        state_key = _ticket_ref_digest(ticket) if authenticated else ticket.ticket_id
        if state_key in tickets:
            raise ReviewQueueError("review queue contains a duplicate ticket")
        tickets[state_key] = ticket
    audit_items: list[ReviewAuditEvent] = []
    for item in raw_audit:
        expected_audit_fields = (
            _AUDIT_STORE_FIELDS if authenticated else _LEGACY_AUDIT_STORE_FIELDS
        )
        if not isinstance(item, dict) or set(item) != expected_audit_fields:
            raise ReviewQueueError("review queue audit event is invalid")
        _validate_audit_payload(item, authenticated=authenticated)
        audit_items.append(
            _audit_from_store_v2_dict(item)
            if authenticated
            else _audit_from_public_dict(item)
        )
    audit = tuple(audit_items)
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
    authorization_hash: str = "",
    authority_context_hash: str = "",
) -> ReviewAuditEvent:
    public = {
        "event": event.value,
        "ticket_ref_hash": _ticket_ref_digest(ticket),
        "turn_ref_hash": _turn_ref_digest(ticket),
        "occurred_at": int(occurred_at),
        "routed_role": ticket.routed_role,
        "actor_ref_hash": actor_ref_hash,
        "status": ticket.status.value,
        "decision_hash": decision_hash,
        "authorization_hash": authorization_hash,
        "authority_context_hash": authority_context_hash,
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
        authorization_hash=authorization_hash,
        authority_context_hash=authority_context_hash,
        ticket_ref_digest=_ticket_ref_digest(ticket),
        turn_ref_digest=_turn_ref_digest(ticket),
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
        approval_authorization_hashes=tuple(
            str(h) for h in payload.get("approval_authorization_hashes", ())
        ),
        reviewer_authorization_hash=str(
            payload.get("reviewer_authorization_hash", "")
        ),
        authority_context_hash=str(payload.get("authority_context_hash", "")),
        decision_hash=str(payload.get("decision_hash", "")),
        updated_at=int(payload.get("updated_at", payload["opened_at"])),
    )


def _ticket_from_store_v2_dict(payload: dict[str, Any]) -> ReviewTicket:
    return ReviewTicket(
        ticket_id="",
        turn_id="",
        corpus_ref="",
        routed_role=str(payload["routed_role"]),
        reason_hash=str(payload["reason_hash"]),
        opened_at=int(payload["opened_at"]),
        expires_at=int(payload["expires_at"]),
        status=ReviewTicketStatus(str(payload["status"])),
        reviewer_ref_hash=str(payload.get("reviewer_ref_hash", "")),
        decision_hash=str(payload.get("decision_hash", "")),
        updated_at=int(payload.get("updated_at", payload["opened_at"])),
        submitter_ref_hash=str(payload.get("submitter_ref_hash", "")),
        required_approvals=int(payload.get("required_approvals", 1)),
        approval_reviewer_hashes=tuple(
            str(value) for value in payload.get("approval_reviewer_hashes", ())
        ),
        approval_authorization_hashes=tuple(
            str(value) for value in payload.get("approval_authorization_hashes", ())
        ),
        reviewer_authorization_hash=str(
            payload.get("reviewer_authorization_hash", "")
        ),
        authority_context_hash=str(payload.get("authority_context_hash", "")),
        ticket_ref_digest=str(payload["ticket_ref_hash"]),
        turn_ref_digest=str(payload["turn_ref_hash"]),
        corpus_ref_digest=str(payload["corpus_ref_hash"]),
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
        authorization_hash=str(payload.get("authorization_hash", "")),
        authority_context_hash=str(payload.get("authority_context_hash", "")),
        raw_secret_egress=False,
    )


def _audit_from_store_v2_dict(payload: dict[str, Any]) -> ReviewAuditEvent:
    return ReviewAuditEvent(
        event_id=str(payload["event_id"]),
        event=ReviewAuditEventKind(str(payload["event"])),
        ticket_id="",
        turn_id="",
        occurred_at=int(payload["occurred_at"]),
        routed_role=str(payload["routed_role"]),
        actor_ref_hash=str(payload.get("actor_ref_hash", "")),
        status=ReviewTicketStatus(
            str(payload.get("status", ReviewTicketStatus.PENDING.value))
        ),
        decision_hash=str(payload.get("decision_hash", "")),
        authorization_hash=str(payload.get("authorization_hash", "")),
        authority_context_hash=str(payload.get("authority_context_hash", "")),
        ticket_ref_digest=str(payload["ticket_ref_hash"]),
        turn_ref_digest=str(payload["turn_ref_hash"]),
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


def review_ticket_ref_hash(ticket_id: str) -> str:
    return _stable_hash(ticket_id, prefix="review_ticket_ref")


def reviewer_ref_hash(reviewer_ref: str) -> str:
    return _stable_hash(reviewer_ref, prefix="reviewer_ref")


def review_ticket_state_hash(ticket: ReviewTicket) -> str:
    return _stable_hash(ticket.to_browser_dict(), prefix="review_ticket_state_v2")


def review_ticket_reference_hash(ticket: ReviewTicket) -> str:
    """Return a ticket's stable public reference without requiring its raw ID.

    Authenticated schema-v2 stores intentionally discard raw ticket IDs.  This
    accessor keeps callers from accidentally reconstructing persistence or
    lookup logic around a raw identifier that no longer exists after reload.
    """

    return _ticket_ref_digest(ticket)


def _ticket_ref_digest(ticket: ReviewTicket) -> str:
    if ticket.ticket_ref_digest:
        return _require_hash(ticket.ticket_ref_digest, "review ticket reference hash")
    if not ticket.ticket_id:
        raise ReviewQueueError("review ticket reference is unavailable")
    return review_ticket_ref_hash(ticket.ticket_id)


def _turn_ref_digest(ticket: ReviewTicket) -> str:
    if ticket.turn_ref_digest:
        return _require_hash(ticket.turn_ref_digest, "review turn reference hash")
    if not ticket.turn_id:
        raise ReviewQueueError("review turn reference is unavailable")
    return _stable_hash(ticket.turn_id, prefix="review_turn_ref")


def _corpus_ref_digest(ticket: ReviewTicket) -> str:
    if ticket.corpus_ref_digest:
        return _require_hash(ticket.corpus_ref_digest, "review corpus reference hash")
    if not ticket.corpus_ref:
        raise ReviewQueueError("review corpus reference is unavailable")
    return _stable_hash(ticket.corpus_ref, prefix="review_corpus_ref")


def _audit_ticket_ref_digest(event: ReviewAuditEvent) -> str:
    if event.ticket_ref_digest:
        return _require_hash(event.ticket_ref_digest, "review audit ticket reference hash")
    if not event.ticket_id:
        raise ReviewQueueError("review audit ticket reference is unavailable")
    return review_ticket_ref_hash(event.ticket_id)


def _audit_turn_ref_digest(event: ReviewAuditEvent) -> str:
    if event.turn_ref_digest:
        return _require_hash(event.turn_ref_digest, "review audit turn reference hash")
    if not event.turn_id:
        raise ReviewQueueError("review audit turn reference is unavailable")
    return _stable_hash(event.turn_id, prefix="review_turn_ref")


def _require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ReviewQueueError(f"{label} must be lowercase SHA-256 hex")
    return value


def _require_integrity_key(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) < 32:
        raise ReviewQueueError("review queue integrity key is unavailable")


def _validate_ticket_payload(
    payload: dict[str, Any], *, authenticated: bool
) -> None:
    reference_fields = (
        ("ticket_ref_hash", "turn_ref_hash", "corpus_ref_hash")
        if authenticated
        else ("ticket_id", "turn_id", "corpus_ref")
    )
    if authenticated:
        for field in reference_fields:
            _require_hash(payload.get(field), f"review queue {field}")
    for field in (("routed_role",) if authenticated else (*reference_fields, "routed_role")):
        value = payload.get(field)
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 256
            or any(ord(character) < 32 for character in value)
        ):
            raise ReviewQueueError("review queue ticket is invalid")
    _require_hash(payload.get("reason_hash"), "review reason hash")
    for field in (
        "reviewer_ref_hash",
        "submitter_ref_hash",
        "reviewer_authorization_hash",
        "authority_context_hash",
        "decision_hash",
    ):
        value = payload.get(field)
        if value and (not isinstance(value, str) or not _HASH_RE.fullmatch(value)):
            raise ReviewQueueError("review queue ticket hash is invalid")
    for field in ("opened_at", "expires_at", "updated_at"):
        value = payload.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ReviewQueueError("review queue ticket timestamp is invalid")
    required = payload.get("required_approvals")
    approvals = payload.get("approval_reviewer_hashes")
    authorizations = payload.get("approval_authorization_hashes")
    if (
        isinstance(required, bool)
        or not isinstance(required, int)
        or not 1 <= required <= 64
        or not isinstance(approvals, list)
        or not isinstance(authorizations, list)
        or len(approvals) > 64
        or len(authorizations) > 64
        or len(approvals) != len(authorizations)
        or payload.get("approvals_count") != len(approvals)
        or any(not isinstance(value, str) or not _HASH_RE.fullmatch(value) for value in approvals)
        or any(
            value and (not isinstance(value, str) or not _HASH_RE.fullmatch(value))
            for value in authorizations
        )
    ):
        raise ReviewQueueError("review queue ticket approvals are invalid")
    if payload.get("raw_secret_egress") is not False:
        raise ReviewQueueError("review queue ticket egress marker is invalid")
    try:
        ReviewTicketStatus(str(payload.get("status")))
    except ValueError as exc:
        raise ReviewQueueError("review queue ticket status is invalid") from exc


def _validate_audit_payload(
    payload: dict[str, Any], *, authenticated: bool
) -> None:
    event_id = payload.get("event_id")
    if (
        not isinstance(event_id, str)
        or re.fullmatch(r"^[0-9a-f]{16}$", event_id) is None
        or payload.get("raw_secret_egress") is not False
    ):
        raise ReviewQueueError("review queue audit event is invalid")
    if authenticated:
        _require_hash(payload.get("ticket_ref_hash"), "review audit ticket reference")
        _require_hash(payload.get("turn_ref_hash"), "review audit turn reference")
    for field in (("routed_role",) if authenticated else ("ticket_id", "turn_id", "routed_role")):
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ReviewQueueError("review queue audit event is invalid")
    for field in (
        "actor_ref_hash",
        "decision_hash",
        "authorization_hash",
        "authority_context_hash",
    ):
        value = payload.get(field)
        if value and (not isinstance(value, str) or not _HASH_RE.fullmatch(value)):
            raise ReviewQueueError("review queue audit hash is invalid")
    occurred_at = payload.get("occurred_at")
    if isinstance(occurred_at, bool) or not isinstance(occurred_at, int) or occurred_at < 0:
        raise ReviewQueueError("review queue audit timestamp is invalid")
    try:
        ReviewAuditEventKind(str(payload.get("event")))
        ReviewTicketStatus(str(payload.get("status")))
    except ValueError as exc:
        raise ReviewQueueError("review queue audit enum is invalid") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _store_integrity(payload: dict[str, Any], key: bytes) -> str:
    unsigned = dict(payload)
    unsigned.pop("integrity", None)
    digest = hmac.new(
        key,
        b"dnai-wikigen/review-queue-store/v2\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).hexdigest()
    return "hmac-sha256:" + digest


def _read_store_json(source: Path) -> dict[str, Any]:
    directory = -1
    descriptor = -1
    try:
        directory = _open_store_parent(source)
        info = os.stat(source.name, dir_fd=directory, follow_symlinks=False)
        _require_store_file(info)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(source.name, flags, dir_fd=directory)
        opened = os.fstat(descriptor)
        if _file_identity(opened) != _file_identity(info):
            raise ReviewQueueError("review queue store changed while opening")
        raw = b""
        while len(raw) <= _MAX_STORE_BYTES:
            chunk = os.read(
                descriptor, min(65_536, _MAX_STORE_BYTES + 1 - len(raw))
            )
            if not chunk:
                break
            raw += chunk
        if len(raw) > _MAX_STORE_BYTES:
            raise ReviewQueueError("review queue store exceeds its byte limit")
        after = os.fstat(descriptor)
        after_path = os.stat(
            source.name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        _require_store_file(after)
        _require_store_file(after_path)
        if (
            _file_identity(after) != _file_identity(opened)
            or _file_identity(after_path) != _file_identity(opened)
        ):
            raise ReviewQueueError("review queue store changed while reading")
        payload = json.loads(raw)
    except ReviewQueueError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ReviewQueueError("review queue store is unreadable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            os.close(directory)
    if not isinstance(payload, dict):
        raise ReviewQueueError("review queue store root is invalid")
    return payload


def _atomic_write_json(target: Path, payload: dict[str, Any]) -> None:
    encoded = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    if len(encoded) > _MAX_STORE_BYTES:
        raise ReviewQueueError("review queue store exceeds its byte limit")
    tmp_name = f".{target.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory = -1
    descriptor = -1
    initial_identity: tuple[int, int] | None = None
    try:
        directory = _open_store_parent(target)
        try:
            current = os.stat(
                target.name, dir_fd=directory, follow_symlinks=False
            )
        except FileNotFoundError:
            current = None
        if current is not None:
            _require_store_file(current)
            initial_identity = _file_identity(current)
        descriptor = os.open(tmp_name, flags, 0o600, dir_fd=directory)
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1

        try:
            before_replace = os.stat(
                target.name, dir_fd=directory, follow_symlinks=False
            )
        except FileNotFoundError:
            before_replace = None
        if initial_identity is None:
            if before_replace is not None:
                raise ReviewQueueError("review queue store changed before commit")
        elif (
            before_replace is None
            or _file_identity(before_replace) != initial_identity
        ):
            raise ReviewQueueError("review queue store changed before commit")

        os.replace(
            tmp_name,
            target.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        committed = os.stat(
            target.name,
            dir_fd=directory,
            follow_symlinks=False,
        )
        _require_store_file(committed)
        if committed.st_size != len(encoded):
            raise ReviewQueueError("review queue store commit is incomplete")
        os.fsync(directory)
    except ReviewQueueError:
        raise
    except OSError as exc:
        raise ReviewQueueError("review queue store write failed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory >= 0:
            try:
                os.unlink(tmp_name, dir_fd=directory)
            except FileNotFoundError:
                pass
            finally:
                os.close(directory)


def _open_store_parent(path: Path) -> int:
    raw = str(path)
    if (
        not path.is_absolute()
        or not path.name
        or path.name in {".", ".."}
        or os.path.normpath(raw) != raw
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ReviewQueueError("review queue store path is invalid")
    _assert_no_symlink_directory_components(path.parent)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(path.parent, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) & 0o022
        ):
            os.close(descriptor)
            raise ReviewQueueError(
                "review queue store parent is not a private owner directory"
            )
        return descriptor
    except ReviewQueueError:
        raise
    except OSError as exc:
        raise ReviewQueueError("review queue store parent is unavailable") from exc


def _assert_no_symlink_directory_components(path: Path) -> None:
    """Reject a path whose supplied directory ancestry traverses a symlink."""

    current = Path(path.anchor)
    for component in path.parts[1:]:
        current = current / component
        try:
            details = os.lstat(current)
        except OSError as exc:
            raise ReviewQueueError(
                "review queue store parent is unavailable"
            ) from exc
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
            raise ReviewQueueError(
                "review queue store parent contains a symlink component"
            )


def _require_store_file(details: os.stat_result) -> None:
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_IMODE(details.st_mode) != 0o600
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or not 2 <= details.st_size <= _MAX_STORE_BYTES
    ):
        raise ReviewQueueError("review queue store is not a bounded private file")


def _file_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
        details.st_mode,
        details.st_uid,
        details.st_nlink,
    )


def _rename_stable_file_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mode,
        details.st_uid,
        details.st_nlink,
    )
