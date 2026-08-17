"""Base Sepolia rollback witness adapter for the hash-only review queue.

The existing ``ExecutionPolicyAnchor`` is an opaque global CAS ledger. This
adapter uses one release-context resource within that ledger for review queue
state commitments. It does not treat a queue commitment as an execution-policy
PASS and never sends ticket, reviewer, corpus, or signature material on-chain.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Any, Protocol

from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.execution_policy_store import ZERO_DECISION_HASH
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult


ZERO_REVIEW_QUEUE_STATE_HASH = "0" * 64
REVIEW_QUEUE_ANCHOR_SURFACE = "review_queue_state"
REVIEW_QUEUE_ANCHOR_REASON = "review_queue_state_commitment"
REVIEW_QUEUE_ANCHOR_TTL_SECONDS = 30 * 24 * 60 * 60


class ReviewQueueAnchorError(RuntimeError):
    """The monotonic review queue witness is unavailable or inconsistent."""


@dataclass(frozen=True)
class ReviewQueueAnchorHead:
    state_hash: str
    decision_hash: str
    sequence: int
    rollback_anchor: dict[str, Any]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": "dnai.review-queue-rollback-anchor.v1",
            "state_hash": self.state_hash,
            "decision_hash": self.decision_hash,
            "sequence": self.sequence,
            "rollback_anchor": self.rollback_anchor,
            "opaque_commitments_only": True,
            "raw_ticket_egress": False,
            "raw_reviewer_identity_egress": False,
        }


class ReviewQueueRollbackAnchor(Protocol):
    def read_head(self, *, now: int) -> ReviewQueueAnchorHead: ...

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> ReviewQueueAnchorHead: ...


class ExecutionPolicyReviewQueueAnchor:
    """Project review state into one resource of the release anchor ledger."""

    def __init__(
        self,
        coordinator: AnchoredExecutionPolicyCoordinator,
        *,
        authority_context_hash: str,
    ) -> None:
        if not isinstance(coordinator, AnchoredExecutionPolicyCoordinator):
            raise ReviewQueueAnchorError(
                "review queue requires the execution-policy anchor coordinator"
            )
        if (
            not isinstance(authority_context_hash, str)
            or len(authority_context_hash) != 64
            or any(character not in "0123456789abcdef" for character in authority_context_hash)
            or authority_context_hash == ZERO_REVIEW_QUEUE_STATE_HASH
        ):
            raise ReviewQueueAnchorError("review queue authority context is invalid")
        if getattr(coordinator.gateway, "read_only", True) is not False:
            raise ReviewQueueAnchorError("review queue rollback anchor is read-only")
        self.coordinator = coordinator
        self.authority_context_hash = authority_context_hash

    def read_head(self, *, now: int) -> ReviewQueueAnchorHead:
        try:
            records, snapshot = self.coordinator.history(
                surface=REVIEW_QUEUE_ANCHOR_SURFACE,
                resource_id=self.authority_context_hash,
                now=int(now),
            )
        except Exception:
            raise ReviewQueueAnchorError(
                "review queue rollback anchor is unavailable"
            ) from None
        bounded = snapshot.to_bounded_dict()
        if not records:
            return ReviewQueueAnchorHead(
                state_hash=ZERO_REVIEW_QUEUE_STATE_HASH,
                decision_hash=ZERO_DECISION_HASH,
                sequence=0,
                rollback_anchor=bounded,
            )
        previous_state_hash = ZERO_REVIEW_QUEUE_STATE_HASH
        previous_decision_hash = ZERO_DECISION_HASH
        previous_sequence = 0
        for record in records:
            if (
                record.get("surface") != REVIEW_QUEUE_ANCHOR_SURFACE
                or record.get("decision") != PolicyDecision.HOLD.value
                or record.get("reason_code") != REVIEW_QUEUE_ANCHOR_REASON
                or record.get("policy_hash") != self.authority_context_hash
                or record.get("execution_context_hash") != previous_state_hash
                or record.get("previous_decision_hash") != previous_decision_hash
                or not _bare_hash(record.get("request_hash"))
                or not _bare_hash(record.get("decision_hash"))
                or isinstance(record.get("sequence"), bool)
                or not isinstance(record.get("sequence"), int)
                or record["sequence"] <= previous_sequence
            ):
                raise ReviewQueueAnchorError(
                    "review queue rollback anchor history is invalid"
                )
            previous_state_hash = record["request_hash"]
            previous_decision_hash = record["decision_hash"]
            previous_sequence = record["sequence"]
        record = records[-1]
        return ReviewQueueAnchorHead(
            state_hash=record["request_hash"],
            decision_hash=record["decision_hash"],
            sequence=record["sequence"],
            rollback_anchor=bounded,
        )

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> ReviewQueueAnchorHead:
        expected = _required_hash(expected_state_hash, "expected review state")
        new = _required_hash(new_state_hash, "new review state")
        if hmac.compare_digest(expected, new):
            raise ReviewQueueAnchorError("review queue state did not change")
        current = self.read_head(now=int(now))
        if not hmac.compare_digest(current.state_hash, expected):
            raise ReviewQueueAnchorError("review queue rollback anchor CAS conflict")
        result = PolicyGateResult(
            decision=PolicyDecision.HOLD,
            corpus_ref="review://queue-state",
            stage=0,
            reason_code=REVIEW_QUEUE_ANCHOR_REASON,
            request_hash=new,
            policy_hash=self.authority_context_hash,
            execution_context_hash=expected,
        )
        try:
            record = self.coordinator.append_and_anchor(
                surface=REVIEW_QUEUE_ANCHOR_SURFACE,
                resource_id=self.authority_context_hash,
                result=result,
                recorded_at=int(now),
                expires_at=int(now) + REVIEW_QUEUE_ANCHOR_TTL_SECONDS,
                expected_previous_decision_hash=current.decision_hash,
                now=int(now),
            )
        except Exception:
            raise ReviewQueueAnchorError(
                "review queue rollback anchor commit is unavailable"
            ) from None
        if (
            record.get("request_hash") != new
            or record.get("policy_hash") != self.authority_context_hash
            or record.get("execution_context_hash") != expected
            or not _bare_hash(record.get("decision_hash"))
            or not isinstance(record.get("sequence"), int)
        ):
            raise ReviewQueueAnchorError(
                "review queue rollback anchor commit is invalid"
            )
        return ReviewQueueAnchorHead(
            state_hash=new,
            decision_hash=record["decision_hash"],
            sequence=record["sequence"],
            rollback_anchor=dict(record.get("rollback_anchor") or {}),
        )


def _bare_hash(value: Any) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _required_hash(value: Any, label: str) -> str:
    if not _bare_hash(value):
        raise ReviewQueueAnchorError(f"{label} hash is invalid")
    return value
