"""Pure coordination reducer for multi-owner private-reward turns.

This module implements the fail-closed state machine described in
``docs/COORDINATION-ENGINE-SPEC.md``. It deliberately has no network, browser,
email, chain, or Tinker dependencies: service effects are represented as
bounded records that callers can hand to tee-email-oracle or DiligenceRoom
adapters later.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from tinker_delegate.royalty_settlement import OwnerShare, split_royalty


class CoordinationError(ValueError):
    """Raised when an event is malformed or cannot be applied safely."""


class ParticipantRole(str, Enum):
    OWNER = "owner"
    REQUESTER = "requester"
    AGENT = "agent"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class GrantStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class GateDecision(str, Enum):
    PASS = "pass"
    HOLD = "hold"
    DENY = "deny"


class TurnStatus(str, Enum):
    GATING = "gating"
    DENIED = "denied"
    HELD = "held"
    AWAITING_CONSENT = "awaiting-consent"
    SURFACED = "surfaced"
    REVOKED = "revoked"
    SETTLED = "settled"


class TicketStatus(str, Enum):
    PENDING = "pending"
    RELEASED = "released"
    DENIED = "denied"


@dataclass(frozen=True)
class Participant:
    ref: str
    role: ParticipantRole
    owner_ref: str = ""


@dataclass(frozen=True)
class Corpus:
    ref: str
    owner_ref: str
    policy_hash: str
    royalty_per_query: int = 0
    # Optional co-ownership: (owner_ref, weight_bps) pairs summing to 10000. When
    # set, the per-query royalty is split among these owners; otherwise the whole
    # royalty accrues to `owner_ref`.
    owner_shares: tuple[tuple[str, int], ...] = ()

    def __post_init__(self) -> None:
        if self.owner_shares:
            owners = [o for o, _ in self.owner_shares]
            if len(set(owners)) != len(owners):
                raise CoordinationError("corpus owner_shares must have unique owners")
            if any(w < 0 for _, w in self.owner_shares):
                raise CoordinationError("corpus owner_share weights must be non-negative")
            if sum(w for _, w in self.owner_shares) != 10_000:
                raise CoordinationError("corpus owner_share weights must sum to 10000 bps")


@dataclass(frozen=True)
class ConsentGrant:
    corpus_ref: str
    owner_ref: str
    requester_ref: str
    purpose: str
    pipeline: str
    status: GrantStatus = GrantStatus.ACTIVE
    expires_at: int | None = None


@dataclass(frozen=True)
class DelegationGrant:
    agent_ref: str
    grantor_ref: str
    corpora: tuple[str, ...]
    purposes: tuple[str, ...]
    pipelines: tuple[str, ...]
    status: GrantStatus = GrantStatus.ACTIVE
    expires_at: int | None = None


@dataclass(frozen=True)
class CollabSession:
    participants: tuple[Participant, ...]
    corpora: tuple[Corpus, ...]
    consent_grants: tuple[ConsentGrant, ...] = ()
    delegation_grants: tuple[DelegationGrant, ...] = ()
    consent_quorum: str = "unanimous"


@dataclass(frozen=True)
class Turn:
    turn_id: str
    by: str
    requester_ref: str
    purpose: str
    pipeline: str
    corpora: tuple[str, ...]
    requests: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass(frozen=True)
class GatedQuery:
    corpus_ref: str
    decision: GateDecision
    stage: int = 0
    reason: str = ""
    routed_role: str = ""


@dataclass(frozen=True)
class HandoffTicket:
    ticket_id: str
    turn_id: str
    corpus_ref: str
    routed_role: str
    reason_hash: str
    status: TicketStatus = TicketStatus.PENDING
    reviewer_ref: str = ""
    # The principal (agent) that submitted the held turn, so a downstream review
    # queue can structurally forbid the submitter from self-approving.
    submitter_ref: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "turn_id": self.turn_id,
            "corpus_ref": self.corpus_ref,
            "routed_role": self.routed_role,
            "reason_hash": self.reason_hash,
            "status": self.status.value,
            "reviewer_ref": self.reviewer_ref,
        }


@dataclass(frozen=True)
class RoyaltyMeter:
    corpus_ref: str
    owner_ref: str
    amount: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "corpus_ref": self.corpus_ref,
            "owner_ref": self.owner_ref,
            "amount_band": _amount_band(self.amount),
        }


@dataclass(frozen=True)
class ConsentCheck:
    allowed: bool
    reason: str
    missing_corpora: tuple[str, ...] = ()


@dataclass(frozen=True)
class JointAttestation:
    turn_id: str
    status: TurnStatus
    corpus_refs: tuple[str, ...]
    query_hash: str
    ticket_hash: str = ""
    royalty_hash: str = ""
    reviewer_refs: tuple[str, ...] = ()
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "turn_id": self.turn_id,
            "status": self.status.value,
            "corpus_refs": list(self.corpus_refs),
            "query_hash": self.query_hash,
            "ticket_hash": self.ticket_hash,
            "royalty_hash": self.royalty_hash,
            "reviewer_refs": list(self.reviewer_refs),
            "raw_secret_egress": self.raw_secret_egress,
        }


@dataclass(frozen=True)
class TurnRecord:
    turn: Turn
    status: TurnStatus
    queries: tuple[GatedQuery, ...] = ()
    tickets: tuple[HandoffTicket, ...] = ()
    meters: tuple[RoyaltyMeter, ...] = ()
    joint: JointAttestation | None = None
    status_reason: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "turn": {
                "turn_id": self.turn.turn_id,
                "by": self.turn.by,
                "requester_ref": self.turn.requester_ref,
                "purpose_hash": _stable_hash(self.turn.purpose, prefix="purpose"),
                "pipeline": self.turn.pipeline,
                "corpora": list(self.turn.corpora),
            },
            "status": self.status.value,
            "queries": [
                {
                    "corpus_ref": query.corpus_ref,
                    "decision": query.decision.value,
                    "stage": query.stage,
                    "reason_hash": _stable_hash(query.reason, prefix="gate_reason"),
                    "routed_role": query.routed_role,
                }
                for query in self.queries
            ],
            "tickets": [ticket.to_public_dict() for ticket in self.tickets],
            "meters": [meter.to_public_dict() for meter in self.meters],
            "joint": self.joint.to_public_dict() if self.joint else None,
            "status_reason": self.status_reason,
            "raw_secret_egress": False,
        }


@dataclass(frozen=True)
class CoordinationState:
    session: CollabSession
    turns: dict[str, TurnRecord] = field(default_factory=dict)
    revoked_corpora: frozenset[str] = frozenset()


@dataclass(frozen=True)
class CoordinationEnv:
    now: int = 0


@dataclass(frozen=True)
class SubmitTurn:
    turn: Turn


@dataclass(frozen=True)
class GateResults:
    turn_id: str
    queries: tuple[GatedQuery, ...]


@dataclass(frozen=True)
class ReviewerDecision:
    ticket_id: str
    decision: str
    reviewer_ref: str


@dataclass(frozen=True)
class ConsentDecision:
    turn_id: str
    corpus_ref: str
    owner_ref: str
    decision: str
    expires_at: int | None = None


@dataclass(frozen=True)
class RevokeCorpus:
    corpus_ref: str
    by: str


CoordEvent = SubmitTurn | GateResults | ReviewerDecision | ConsentDecision | RevokeCorpus


def coordinate(state: CoordinationState, event: CoordEvent, env: CoordinationEnv | None = None) -> CoordinationState:
    """Apply one coordination event and return a new state."""

    env = env or CoordinationEnv()
    if isinstance(event, SubmitTurn):
        return _submit_turn(state, event.turn, env)
    if isinstance(event, GateResults):
        return _gate_results(state, event, env)
    if isinstance(event, ReviewerDecision):
        return _reviewer_decision(state, event, env)
    if isinstance(event, ConsentDecision):
        return _consent_decision(state, event, env)
    if isinstance(event, RevokeCorpus):
        return _revoke_corpus(state, event, env)
    raise CoordinationError("unsupported coordination event")


def _submit_turn(state: CoordinationState, turn: Turn, env: CoordinationEnv) -> CoordinationState:
    _require_known_participant(state.session, turn.by)
    _require_known_participant(state.session, turn.requester_ref)
    for corpus_ref in turn.corpora:
        _require_known_corpus(state.session, corpus_ref)

    if any(corpus_ref in state.revoked_corpora for corpus_ref in turn.corpora):
        record = _terminal_record(turn, TurnStatus.REVOKED, (), (), (), "corpus_revoked")
    elif not _delegation_allows_turn(state.session, turn, env):
        record = _terminal_record(turn, TurnStatus.DENIED, (), (), (), "delegate_exceeds_scope")
    else:
        record = TurnRecord(turn=turn, status=TurnStatus.GATING)
    return _with_turn(state, record)


def _gate_results(state: CoordinationState, event: GateResults, env: CoordinationEnv) -> CoordinationState:
    record = _get_turn(state, event.turn_id)
    if record.status != TurnStatus.GATING:
        raise CoordinationError("gate results can only be applied to gating turns")
    _require_query_cover(record.turn, event.queries)

    if any(corpus_ref in state.revoked_corpora for corpus_ref in record.turn.corpora):
        updated = _terminal_record(record.turn, TurnStatus.REVOKED, event.queries, (), (), "corpus_revoked")
        return _with_turn(state, updated)

    denied = [query for query in event.queries if query.decision == GateDecision.DENY]
    if denied:
        reason = "restricted_denied" if any(query.stage >= 3 for query in denied) else "gate_denied"
        updated = _terminal_record(record.turn, TurnStatus.DENIED, event.queries, (), (), reason)
        return _with_turn(state, updated)

    held = [query for query in event.queries if query.decision == GateDecision.HOLD]
    if held:
        tickets = tuple(
            HandoffTicket(
                ticket_id=_stable_hash(f"{record.turn.turn_id}:{query.corpus_ref}:{query.reason}", prefix="ticket")[:16],
                turn_id=record.turn.turn_id,
                corpus_ref=query.corpus_ref,
                routed_role=query.routed_role or _route_hold(query),
                reason_hash=_stable_hash(query.reason, prefix="hold_reason"),
                submitter_ref=record.turn.by,
            )
            for query in held
        )
        updated = TurnRecord(
            turn=record.turn,
            status=TurnStatus.HELD,
            queries=tuple(event.queries),
            tickets=tickets,
            joint=_joint(record.turn, TurnStatus.HELD, event.queries, tickets, ()),
            status_reason="gate_held",
        )
        return _with_turn(state, updated)

    consent_check = _consent_check(state.session, record.turn, env)
    if not consent_check.allowed:
        updated = TurnRecord(
            turn=record.turn,
            status=TurnStatus.AWAITING_CONSENT,
            queries=tuple(event.queries),
            joint=_joint(record.turn, TurnStatus.AWAITING_CONSENT, event.queries, (), ()),
            status_reason=consent_check.reason,
        )
        return _with_turn(state, updated)

    meters = _royalty_meters(state.session, record.turn)
    updated = TurnRecord(
        turn=record.turn,
        status=TurnStatus.SETTLED,
        queries=tuple(event.queries),
        meters=meters,
        joint=_joint(record.turn, TurnStatus.SETTLED, event.queries, (), meters),
        status_reason="settled",
    )
    return _with_turn(state, updated)


def _reviewer_decision(state: CoordinationState, event: ReviewerDecision, env: CoordinationEnv) -> CoordinationState:
    if event.decision not in {"release", "deny"}:
        raise CoordinationError("reviewer decision must be release or deny")
    turn_id, ticket = _find_ticket(state, event.ticket_id)
    record = _get_turn(state, turn_id)
    reviewer = _require_known_participant(state.session, event.reviewer_ref)
    if event.reviewer_ref == record.turn.by or event.reviewer_ref == record.turn.requester_ref:
        return _with_turn(
            state,
            _terminal_record(
                record.turn,
                TurnStatus.DENIED,
                record.queries,
                record.tickets,
                record.meters,
                "self_approval_denied",
                reviewer_refs=(event.reviewer_ref,),
            ),
        )
    if reviewer.role not in {ParticipantRole.REVIEWER, ParticipantRole.ADMIN}:
        raise CoordinationError("reviewer must have reviewer/admin role")

    new_tickets = tuple(
        replace(
            item,
            status=TicketStatus.RELEASED if item.ticket_id == ticket.ticket_id and event.decision == "release" else (
                TicketStatus.DENIED if item.ticket_id == ticket.ticket_id else item.status
            ),
            reviewer_ref=event.reviewer_ref if item.ticket_id == ticket.ticket_id else item.reviewer_ref,
        )
        for item in record.tickets
    )
    if event.decision == "deny":
        updated = _terminal_record(
            record.turn,
            TurnStatus.DENIED,
            record.queries,
            new_tickets,
            record.meters,
            "reviewer_denied",
            reviewer_refs=(event.reviewer_ref,),
        )
    else:
        updated = TurnRecord(
            turn=record.turn,
            status=TurnStatus.GATING,
            queries=record.queries,
            tickets=new_tickets,
            joint=_joint(record.turn, TurnStatus.GATING, record.queries, new_tickets, (), reviewer_refs=(event.reviewer_ref,)),
            status_reason="reviewer_released_regate_required",
        )
    return _with_turn(state, updated)


def _consent_decision(state: CoordinationState, event: ConsentDecision, env: CoordinationEnv) -> CoordinationState:
    record = _get_turn(state, event.turn_id)
    if record.status != TurnStatus.AWAITING_CONSENT:
        raise CoordinationError("consent decisions can only be applied to awaiting-consent turns")
    if event.corpus_ref not in record.turn.corpora:
        raise CoordinationError("consent decision corpus is not part of the turn")
    owner = _require_known_participant(state.session, event.owner_ref)
    if owner.role != ParticipantRole.OWNER:
        raise CoordinationError("consent decision must come from a corpus owner")
    corpus = _require_known_corpus(state.session, event.corpus_ref)
    if corpus.owner_ref != event.owner_ref:
        raise CoordinationError("only the corpus owner can decide consent")

    normalized = event.decision.strip().lower()
    if normalized not in {"grant", "deny"}:
        raise CoordinationError("consent decision must be grant or deny")
    if normalized == "deny":
        updated = _terminal_record(record.turn, TurnStatus.DENIED, record.queries, (), (), "consent_denied")
        return _with_turn(state, updated)

    grant = ConsentGrant(
        corpus_ref=event.corpus_ref,
        owner_ref=event.owner_ref,
        requester_ref=record.turn.requester_ref,
        purpose=record.turn.purpose,
        pipeline=record.turn.pipeline,
        expires_at=event.expires_at,
    )
    grants = _append_consent_grant(state.session.consent_grants, grant, env)
    updated_session = replace(state.session, consent_grants=grants)
    updated_state = replace(state, session=updated_session)

    consent_check = _consent_check(updated_session, record.turn, env)
    if not consent_check.allowed:
        updated = TurnRecord(
            turn=record.turn,
            status=TurnStatus.AWAITING_CONSENT,
            queries=record.queries,
            joint=_joint(record.turn, TurnStatus.AWAITING_CONSENT, record.queries, (), ()),
            status_reason=consent_check.reason,
        )
        return _with_turn(updated_state, updated)

    meters = _royalty_meters(updated_session, record.turn)
    updated = TurnRecord(
        turn=record.turn,
        status=TurnStatus.SETTLED,
        queries=record.queries,
        meters=meters,
        joint=_joint(record.turn, TurnStatus.SETTLED, record.queries, (), meters),
        status_reason="settled",
    )
    return _with_turn(updated_state, updated)


def _revoke_corpus(state: CoordinationState, event: RevokeCorpus, env: CoordinationEnv) -> CoordinationState:
    corpus = _require_known_corpus(state.session, event.corpus_ref)
    if corpus.owner_ref != event.by:
        raise CoordinationError("only the corpus owner can revoke consent")
    revoked = frozenset(set(state.revoked_corpora) | {event.corpus_ref})
    turns = dict(state.turns)
    for turn_id, record in state.turns.items():
        if event.corpus_ref not in record.turn.corpora or record.status == TurnStatus.SETTLED:
            continue
        turns[turn_id] = _terminal_record(
            record.turn,
            TurnStatus.REVOKED,
            record.queries,
            record.tickets,
            record.meters,
            "corpus_revoked",
        )
    return replace(state, revoked_corpora=revoked, turns=turns)


def _terminal_record(
    turn: Turn,
    status: TurnStatus,
    queries: tuple[GatedQuery, ...],
    tickets: tuple[HandoffTicket, ...],
    meters: tuple[RoyaltyMeter, ...],
    reason: str,
    *,
    reviewer_refs: tuple[str, ...] = (),
) -> TurnRecord:
    return TurnRecord(
        turn=turn,
        status=status,
        queries=queries,
        tickets=tickets,
        meters=meters,
        joint=_joint(turn, status, queries, tickets, meters, reviewer_refs=reviewer_refs),
        status_reason=reason,
    )


def _with_turn(state: CoordinationState, record: TurnRecord) -> CoordinationState:
    turns = dict(state.turns)
    turns[record.turn.turn_id] = record
    return replace(state, turns=turns)


def _get_turn(state: CoordinationState, turn_id: str) -> TurnRecord:
    try:
        return state.turns[turn_id]
    except KeyError as exc:
        raise CoordinationError("unknown turn") from exc


def _find_ticket(state: CoordinationState, ticket_id: str) -> tuple[str, HandoffTicket]:
    for turn_id, record in state.turns.items():
        for ticket in record.tickets:
            if ticket.ticket_id == ticket_id:
                return turn_id, ticket
    raise CoordinationError("unknown ticket")


def _require_known_participant(session: CollabSession, participant_ref: str) -> Participant:
    for participant in session.participants:
        if participant.ref == participant_ref:
            return participant
    raise CoordinationError("unknown participant")


def _require_known_corpus(session: CollabSession, corpus_ref: str) -> Corpus:
    for corpus in session.corpora:
        if corpus.ref == corpus_ref:
            return corpus
    raise CoordinationError("unknown corpus")


def _require_query_cover(turn: Turn, queries: tuple[GatedQuery, ...]) -> None:
    expected = set(turn.corpora)
    actual = {query.corpus_ref for query in queries}
    if actual != expected:
        raise CoordinationError("gate results must cover exactly the turn corpora")


def _delegation_allows_turn(session: CollabSession, turn: Turn, env: CoordinationEnv) -> bool:
    participant = _require_known_participant(session, turn.by)
    if participant.role != ParticipantRole.AGENT:
        return True
    for grant in session.delegation_grants:
        if grant.agent_ref != turn.by or grant.status != GrantStatus.ACTIVE:
            continue
        if grant.expires_at is not None and grant.expires_at <= env.now:
            continue
        if not set(turn.corpora).issubset(set(grant.corpora)):
            continue
        if turn.purpose not in grant.purposes:
            continue
        if turn.pipeline not in grant.pipelines:
            continue
        if participant.owner_ref and participant.owner_ref != grant.grantor_ref:
            continue
        return True
    return False


def _append_consent_grant(grants: tuple[ConsentGrant, ...], grant: ConsentGrant, env: CoordinationEnv) -> tuple[ConsentGrant, ...]:
    for existing in grants:
        if (
            existing.corpus_ref == grant.corpus_ref
            and existing.owner_ref == grant.owner_ref
            and existing.requester_ref == grant.requester_ref
            and existing.purpose == grant.purpose
            and existing.pipeline == grant.pipeline
            and existing.status == GrantStatus.ACTIVE
            and (existing.expires_at is None or existing.expires_at > env.now)
        ):
            return grants
    return grants + (grant,)


def _consent_check(session: CollabSession, turn: Turn, env: CoordinationEnv) -> ConsentCheck:
    required = _required_consent_count(session.consent_quorum, len(turn.corpora))
    if required is None:
        return ConsentCheck(False, "invalid_consent_quorum", tuple(turn.corpora))

    active = _active_consent_corpora(session, turn, env)
    missing = tuple(corpus_ref for corpus_ref in turn.corpora if corpus_ref not in active)
    if len(active) < required:
        return ConsentCheck(False, "missing_consent", missing)
    return ConsentCheck(True, "consent_quorum_met", missing)


def _required_consent_count(quorum: str, total_corpora: int) -> int | None:
    normalized = quorum.strip().lower()
    if normalized == "unanimous":
        return total_corpora

    if "-of-" not in normalized:
        return None
    required_raw, total_raw = normalized.split("-of-", 1)
    if not required_raw.isdigit() or not total_raw.isdigit():
        return None
    required = int(required_raw)
    declared_total = int(total_raw)
    if declared_total != total_corpora or required < 1 or required > declared_total:
        return None
    return required


def _active_consent_corpora(session: CollabSession, turn: Turn, env: CoordinationEnv) -> frozenset[str]:
    active: set[str] = set()
    for corpus_ref in turn.corpora:
        corpus = _require_known_corpus(session, corpus_ref)
        if any(
            grant.corpus_ref == corpus_ref
            and grant.owner_ref == corpus.owner_ref
            and grant.requester_ref == turn.requester_ref
            and grant.purpose == turn.purpose
            and grant.pipeline == turn.pipeline
            and grant.status == GrantStatus.ACTIVE
            and (grant.expires_at is None or grant.expires_at > env.now)
            for grant in session.consent_grants
        ):
            active.add(corpus_ref)
    return frozenset(active)


def _royalty_meters(session: CollabSession, turn: Turn) -> tuple[RoyaltyMeter, ...]:
    meters: list[RoyaltyMeter] = []
    for corpus_ref in turn.corpora:
        corpus = _require_known_corpus(session, corpus_ref)
        if corpus.owner_shares:
            # Co-owned corpus: split the per-query royalty by weight, conserving.
            shares = [OwnerShare(owner, weight) for owner, weight in corpus.owner_shares]
            for payout in split_royalty(corpus.royalty_per_query, shares):
                meters.append(
                    RoyaltyMeter(
                        corpus_ref=corpus.ref,
                        owner_ref=payout.owner_ref,
                        amount=payout.amount,
                    )
                )
        else:
            meters.append(
                RoyaltyMeter(
                    corpus_ref=corpus.ref,
                    owner_ref=corpus.owner_ref,
                    amount=corpus.royalty_per_query,
                )
            )
    return tuple(meters)


def _route_hold(query: GatedQuery) -> str:
    if query.stage >= 3:
        return "ethics-legal-reviewer"
    if "clinical" in query.reason.lower():
        return "expert-in-the-loop"
    return "access-review-officer"


def _joint(
    turn: Turn,
    status: TurnStatus,
    queries: tuple[GatedQuery, ...],
    tickets: tuple[HandoffTicket, ...],
    meters: tuple[RoyaltyMeter, ...],
    *,
    reviewer_refs: tuple[str, ...] = (),
) -> JointAttestation:
    return JointAttestation(
        turn_id=turn.turn_id,
        status=status,
        corpus_refs=tuple(turn.corpora),
        query_hash=_stable_hash(_public_query_records(queries), prefix="coordination_queries"),
        ticket_hash=_stable_hash(
            [ticket.to_public_dict() for ticket in tickets],
            prefix="coordination_tickets",
        ) if tickets else "",
        royalty_hash=_stable_hash(
            [meter.to_public_dict() for meter in meters],
            prefix="coordination_royalties",
        ) if meters else "",
        reviewer_refs=reviewer_refs,
    )


def _public_query_records(queries: tuple[GatedQuery, ...]) -> list[dict[str, Any]]:
    return [
        {
            "corpus_ref": query.corpus_ref,
            "decision": query.decision.value,
            "stage": query.stage,
            "reason_hash": _stable_hash(query.reason, prefix="gate_reason"),
            "routed_role": query.routed_role,
        }
        for query in queries
    ]


def _stable_hash(value: Any, *, prefix: str) -> str:
    if isinstance(value, str):
        payload = value
    else:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(prefix.encode("utf-8") + b"\0" + payload.encode("utf-8")).hexdigest()


def _amount_band(value: int) -> str:
    if value == 0:
        return "zero"
    if value < 0:
        return "invalid"
    if value < 10**6:
        return "<1e6"
    if value < 10**9:
        return "1e6-1e9"
    if value < 10**12:
        return "1e9-1e12"
    if value < 10**15:
        return "1e12-1e15"
    return ">=1e15"
