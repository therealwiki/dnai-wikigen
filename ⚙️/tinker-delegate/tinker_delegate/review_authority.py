"""Release-bound wallet authority for bounded human-review decisions.

Review decisions do not use the operator runtime bearer. A reviewer asks for a
one-time, current-ticket-state challenge and signs it with an allowlisted Base
Sepolia wallet. The server resolves the review principal from its private
policy, verifies EOA/EIP-1271 signatures through the shared wallet verifier,
and persists only hashes in a release-context-bound queue store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from tinker_delegate import dstack_utils
from tinker_delegate.review_queue import (
    ReviewQueueError,
    ReviewQueueState,
    ReviewTicket,
    ReviewTicketStatus,
    decide_review_ticket,
    enqueue_handoff_tickets,
    expire_review_tickets,
    discard_review_queue_pending,
    load_review_queue,
    promote_review_queue_pending,
    review_queue_exclusive_lease,
    review_queue_pending_path,
    review_queue_state_hash,
    review_ticket_reference_hash,
    review_ticket_state_hash,
    reviewer_ref_hash,
    save_review_queue,
)
from tinker_delegate.review_queue_anchor import (
    ExecutionPolicyReviewQueueAnchor,
    ReviewQueueAnchorError,
    ReviewQueueRollbackAnchor,
    ZERO_REVIEW_QUEUE_STATE_HASH,
)
from tinker_delegate.wallet_auth import (
    MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS,
    normalize_wallet_address,
)
from tinker_delegate.wallet_signature_verifier import (
    BASE_SEPOLIA_CHAIN_ID,
    WalletSignatureError,
    WalletSignatureUnavailable,
    WalletSignatureVerifier,
    wallet_signature_verifier_from_settings,
)


REVIEW_AUTHORITY_POLICY_SCHEMA = "dnai.review-authority-policy.v1"
REVIEW_ACTIVE_REVIEWERS_SCHEMA = "dnai.review-active-reviewers.v1"
REVIEW_AUTHORITY_CONTEXT_SCHEMA = "dnai.review-authority-context.v2"
REVIEW_AUTHORITY_CHALLENGE_SCHEMA = "dnai.review-authority-challenge.v1"
REVIEW_AUTHORITY_ROLES = frozenset(
    {
        "access-review-officer",
        "expert-in-the-loop",
        "biosecurity-review",
        "ethics-legal-reviewer",
    }
)

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32_RE = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
_ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_REVIEWER_REF_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,96}$")
_CVM_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
_SIGNATURE_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{2,8192}$")


class ReviewAuthorityError(ValueError):
    """A challenge, signature, identity, or current ticket state is invalid."""


class ReviewAuthorityUnavailable(RuntimeError):
    """The exact release-bound review authority cannot be established."""


class ReviewChallengeCapacityError(RuntimeError):
    """Raised instead of evicting a still-valid reviewer challenge."""


class ReviewQueueReadRateLimited(RuntimeError):
    """Bounded public queue-read admission was exhausted for this peer."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("review queue read rate limit exceeded")
        self.retry_after = max(1, int(retry_after))


class ReviewQueueReadLimiter:
    """Bounded per-peer sliding window for the unauthenticated queue view."""

    def __init__(
        self,
        *,
        window_seconds: int = 60,
        peer_capacity: int = 120,
        max_peers: int = 4096,
        clock=time.time,
    ) -> None:
        self.window_seconds = _bounded_int(
            window_seconds,
            "review queue read-limit window",
            minimum=1,
            maximum=3600,
        )
        self.peer_capacity = _bounded_int(
            peer_capacity,
            "review queue read peer limit",
            minimum=1,
            maximum=10_000,
        )
        self.max_peers = _bounded_int(
            max_peers,
            "review queue read peer capacity",
            minimum=1,
            maximum=100_000,
        )
        self._clock = clock
        self._records: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self._last_now = float("-inf")

    @classmethod
    def from_settings(cls, settings: Any) -> "ReviewQueueReadLimiter":
        return cls(
            window_seconds=getattr(
                settings, "review_queue_read_limit_window_seconds", 60
            ),
            peer_capacity=getattr(settings, "review_queue_read_peer_limit", 120),
            max_peers=getattr(settings, "review_queue_read_max_peers", 4096),
        )

    def admit(self, peer_source: str) -> None:
        if not isinstance(peer_source, str) or not peer_source or len(peer_source) > 128:
            peer_source = "unknown"
        with self._lock:
            observed = float(self._clock())
            now = max(observed, self._last_now)
            self._last_now = now
            cutoff = now - self.window_seconds
            empty: list[str] = []
            for key, values in self._records.items():
                while values and values[0] <= cutoff:
                    values.popleft()
                if not values:
                    empty.append(key)
            for key in empty:
                self._records.pop(key, None)
            values = self._records.get(peer_source)
            if values is None:
                if len(self._records) >= self.max_peers:
                    oldest = min(
                        (items[0] for items in self._records.values() if items),
                        default=now,
                    )
                    raise ReviewQueueReadRateLimited(
                        max(1, int(oldest + self.window_seconds - now + 0.999))
                    )
                values = deque()
                self._records[peer_source] = values
            if len(values) >= self.peer_capacity:
                raise ReviewQueueReadRateLimited(
                    max(1, int(values[0] + self.window_seconds - now + 0.999))
                )
            values.append(now)


@dataclass(frozen=True)
class ReviewIdentity:
    address: str
    reviewer_ref: str
    reviewer_ref_hash: str


@dataclass(frozen=True)
class ReviewRoleAuthority:
    role: str
    threshold: int
    reviewers: tuple[ReviewIdentity, ...]

    def identity_for_address(self, address: str) -> ReviewIdentity:
        normalized = normalize_wallet_address(address)
        for identity in self.reviewers:
            if hmac.compare_digest(identity.address, normalized):
                return identity
        raise ReviewAuthorityError("review authorization denied")

    @property
    def reviewer_hashes(self) -> frozenset[str]:
        return frozenset(identity.reviewer_ref_hash for identity in self.reviewers)

    def to_public_dict(self) -> dict[str, Any]:
        hashes = sorted(self.reviewer_hashes)
        return {
            "role": self.role,
            "threshold": self.threshold,
            "reviewer_count": len(hashes),
            "reviewer_set_hash": _hash_json(
                "dnai-wikigen/review-authority-role-set/v1", hashes
            ),
        }


@dataclass(frozen=True)
class ReviewAuthorityPolicy:
    roles: tuple[ReviewRoleAuthority, ...]
    policy_sha256: str

    def authority_for_role(self, role: str) -> ReviewRoleAuthority:
        for authority in self.roles:
            if hmac.compare_digest(authority.role, role):
                return authority
        raise ReviewAuthorityError("review authorization denied")

    def required_approvals_by_role(self) -> dict[str, int]:
        return {authority.role: authority.threshold for authority in self.roles}

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": REVIEW_AUTHORITY_POLICY_SCHEMA,
            "policy_sha256": self.policy_sha256,
            "roles": [authority.to_public_dict() for authority in self.roles],
            "raw_reviewer_identity_egress": False,
        }


@dataclass(frozen=True)
class ReviewActiveReviewerSet:
    reviewers: tuple[ReviewIdentity, ...]
    projection_sha256: str

    @property
    def identity_pairs(self) -> frozenset[tuple[str, str]]:
        return frozenset(
            (identity.address, identity.reviewer_ref)
            for identity in self.reviewers
        )

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "active_reviewer_count": len(self.reviewers),
            "active_reviewers_sha256": self.projection_sha256,
            "raw_reviewer_identity_egress": False,
        }


@dataclass(frozen=True)
class ReviewAuthorityReleaseProvenance:
    genesis_acceptance_sha256: str
    current_status_epoch: int
    current_status_sha256: str
    active_reviewers_sha256: str

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "reviewer_authority_genesis_acceptance_sha256": (
                self.genesis_acceptance_sha256
            ),
            "reviewer_authority_current_status_epoch": self.current_status_epoch,
            "reviewer_authority_current_status_sha256": self.current_status_sha256,
            "reviewer_authority_active_reviewers_sha256": (
                self.active_reviewers_sha256
            ),
        }


@dataclass(frozen=True)
class ReviewChallenge:
    address: str
    reviewer_ref_hash: str
    ticket_ref_hash: str
    ticket_state_hash: str
    routed_role: str
    decision: Literal["release", "deny"]
    authority_context_hash: str
    policy_sha256: str
    nonce: str
    message: str
    issued_at: int
    expires_at: int

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": REVIEW_AUTHORITY_CHALLENGE_SCHEMA,
            "ticket_ref_hash": self.ticket_ref_hash,
            "ticket_state_hash": self.ticket_state_hash,
            "routed_role": self.routed_role,
            "decision": self.decision,
            "reviewer_ref_hash": self.reviewer_ref_hash,
            "authority_context_hash": self.authority_context_hash,
            "policy_sha256": self.policy_sha256,
            "nonce": self.nonce,
            "message": self.message,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "raw_reviewer_identity_egress": False,
        }


class ReviewChallengeStore:
    """Bounded process-local, single-use reviewer challenge store.

    Restart invalidation is intentional: a signature cannot be replayed after a
    process restart because the corresponding nonce no longer exists.
    """

    def __init__(self, *, max_pending: int = 1024) -> None:
        if (
            not isinstance(max_pending, int)
            or isinstance(max_pending, bool)
            or max_pending <= 0
        ):
            raise ValueError("review challenge capacity must be positive")
        self.max_pending = max_pending
        self._records: dict[str, ReviewChallenge] = {}
        self._attempts: dict[str, int] = {}
        self._in_flight: set[str] = set()
        self._lock = threading.Lock()

    def put(self, challenge: ReviewChallenge, *, now: int) -> None:
        with self._lock:
            self._prune_locked(now)
            if len(self._records) >= self.max_pending:
                raise ReviewChallengeCapacityError(
                    "review challenge capacity reached"
                )
            self._records[challenge.nonce] = challenge
            self._attempts[challenge.nonce] = 0
            self._in_flight.discard(challenge.nonce)

    def reserve(self, nonce: str, *, now: int) -> ReviewChallenge:
        normalized = _nonce(nonce)
        with self._lock:
            self._prune_locked(now)
            challenge = self._records.get(normalized)
            attempts = self._attempts.get(normalized, 0)
            if (
                challenge is None
                or normalized in self._in_flight
                or attempts >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
            ):
                raise ReviewAuthorityError(
                    "review challenge is unknown, expired, or already used"
                )
            self._attempts[normalized] = attempts + 1
            self._in_flight.add(normalized)
            return challenge

    def release(self, nonce: str, expected: ReviewChallenge) -> None:
        normalized = _nonce(nonce)
        with self._lock:
            if self._records.get(normalized) is not expected:
                return
            self._in_flight.discard(normalized)
            if (
                self._attempts.get(normalized, 0)
                >= MAX_WALLET_CHALLENGE_VERIFICATION_ATTEMPTS
            ):
                self._delete_locked(normalized)

    def consume(
        self, nonce: str, expected: ReviewChallenge, *, now: int
    ) -> ReviewChallenge:
        normalized = _nonce(nonce)
        with self._lock:
            self._prune_locked(now)
            current = self._records.get(normalized)
            if (
                current is None
                or current is not expected
                or normalized not in self._in_flight
            ):
                raise ReviewAuthorityError(
                    "review challenge is unknown, expired, or already used"
                )
            self._delete_locked(normalized)
            return current

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._attempts.clear()
            self._in_flight.clear()

    def _prune_locked(self, now: int) -> None:
        for nonce in [
            nonce
            for nonce, challenge in self._records.items()
            if now >= challenge.expires_at
        ]:
            self._delete_locked(nonce)

    def _delete_locked(self, nonce: str) -> None:
        self._records.pop(nonce, None)
        self._attempts.pop(nonce, None)
        self._in_flight.discard(nonce)


class ReviewAuthorityService:
    """Issue state-bound reviewer challenges and commit signed decisions."""

    def __init__(
        self,
        settings: Any,
        challenge_store: ReviewChallengeStore,
        *,
        repository_lock: threading.RLock | None = None,
        signature_verifier: WalletSignatureVerifier | None = None,
        rollback_anchor: ReviewQueueRollbackAnchor | None = None,
        anchor_coordinator: Any | None = None,
    ) -> None:
        self.settings = settings
        self.challenge_store = challenge_store
        self.active_reviewers = review_authority_active_reviewers(settings)
        self.policy = review_authority_policy(settings)
        self.release_provenance = review_authority_release_provenance(settings)
        self.authority_context_hash = review_authority_context_hash(
            settings, self.policy, self.release_provenance
        )
        if rollback_anchor is not None and anchor_coordinator is not None:
            raise ReviewAuthorityUnavailable(
                "review rollback authority is ambiguously configured"
            )
        if anchor_coordinator is not None:
            try:
                rollback_anchor = ExecutionPolicyReviewQueueAnchor(
                    anchor_coordinator,
                    authority_context_hash=self.authority_context_hash,
                )
            except ReviewQueueAnchorError as exc:
                raise ReviewAuthorityUnavailable(
                    "review rollback anchor is unavailable"
                ) from exc
        if dstack_utils.is_dstack_enabled() and rollback_anchor is None:
            raise ReviewAuthorityUnavailable(
                "production review authority requires a rollback anchor"
            )
        self.rollback_anchor = rollback_anchor
        self._last_anchor_head = None
        self.integrity_key = review_queue_integrity_key(settings)
        self.queue_path = str(getattr(settings, "review_queue_path", "") or "").strip()
        if not self.queue_path:
            raise ReviewAuthorityUnavailable("review queue path is not configured")
        configured_capacity = _bounded_int(
            getattr(settings, "review_authority_max_pending_challenges", 1024),
            "review challenge capacity",
            minimum=1,
            maximum=4096,
        )
        if challenge_store.max_pending != configured_capacity:
            raise ReviewAuthorityUnavailable(
                "review challenge store capacity differs from configuration"
            )
        if dstack_utils.is_dstack_enabled() and signature_verifier is None:
            primary = str(getattr(settings, "wallet_auth_rpc_url", "") or "").strip()
            secondary = str(
                getattr(settings, "wallet_auth_rpc_url_secondary", "") or ""
            ).strip()
            if not primary or not secondary:
                raise ReviewAuthorityUnavailable(
                    "production review verification requires two wallet RPC providers"
                )
        if signature_verifier is None:
            try:
                signature_verifier = wallet_signature_verifier_from_settings(settings)
            except WalletSignatureUnavailable as exc:
                raise ReviewAuthorityUnavailable(
                    "review wallet signature verification is unavailable"
                ) from exc
        self.signature_verifier = signature_verifier
        self._repository_lock = repository_lock or threading.RLock()
        # Constructor readiness is intentional: a missing/corrupt store or
        # policy/context drift is a 503 before challenge admission or nonce
        # lookup, never an identity/replay oracle.
        with self._queue_lease():
            state = self._recover_state(now=int(time.time()))
            self._validate_state_authority(state)

    def authority_status(self) -> dict[str, Any]:
        return {
            "enabled": True,
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "authority_context_hash": self.authority_context_hash,
            "release_context": {
                "schema": "dnai.review-release-context.v1",
                "chain_id": BASE_SEPOLIA_CHAIN_ID,
                "wallet_domain": str(self.settings.wallet_auth_domain),
                "wallet_uri": str(self.settings.wallet_auth_uri),
                "main_runtime_cvm_id": str(self.settings.main_runtime_cvm_id),
                "deployment_intent_sha256": str(
                    self.settings.release_deployment_intent_sha256
                ),
                "release_authority_sha256": str(
                    self.settings.release_authority_sha256
                ),
                "ceremony_nonce": str(self.settings.release_ceremony_nonce),
            },
            "release_provenance": self.release_provenance.to_public_dict(),
            "active_reviewers": self.active_reviewers.to_public_dict(),
            "rollback_protection": (
                "base_sepolia_execution_policy_anchor"
                if self.rollback_anchor is not None
                else "local_test_only_hmac_no_rollback_claim"
            ),
            "rollback_anchor": (
                self._last_anchor_head.to_public_dict()
                if self._last_anchor_head is not None
                else None
            ),
            **self.policy.to_public_dict(),
        }

    def read_public_queue(
        self,
        *,
        routed_role: str = "",
        cursor: str = "",
        limit: int = 50,
        now: int | None = None,
    ) -> dict[str, Any]:
        current = int(time.time() if now is None else now)
        page_limit = _bounded_int(
            limit, "review queue page limit", minimum=1, maximum=100
        )
        normalized_cursor = ""
        if cursor:
            normalized_cursor = _hash(cursor, "review queue cursor")
        with self._queue_lease():
            state = self._recover_state(now=current)
            self._validate_state_authority(state)
        if routed_role:
            normalized_role = _role(routed_role)
            self.policy.authority_for_role(normalized_role)
            filtered = ReviewQueueState(
                tickets={
                    ticket_id: ticket
                    for ticket_id, ticket in state.tickets.items()
                    if ticket.routed_role == normalized_role
                    and ticket.status == ReviewTicketStatus.PENDING
                    and ticket.expires_at > current
                },
                audit=state.audit,
            )
            queue = filtered.to_browser_dict(now=current)
            queue["kind"] = "review_queue_pending"
            queue["routed_role"] = normalized_role
        else:
            queue = state.to_browser_dict(now=current)
        ordered = sorted(
            queue["tickets"], key=lambda item: item["ticket_ref_hash"]
        )
        start = 0
        if normalized_cursor:
            positions = [
                index
                for index, item in enumerate(ordered)
                if hmac.compare_digest(
                    item["ticket_ref_hash"], normalized_cursor
                )
            ]
            if len(positions) != 1:
                raise ReviewAuthorityError("review queue cursor is invalid")
            start = positions[0] + 1
        page = ordered[start : start + page_limit]
        has_more = start + page_limit < len(ordered)
        queue["tickets"] = page
        queue["page"] = {
            "limit": page_limit,
            "returned_count": len(page),
            "has_more": has_more,
            "next_cursor": page[-1]["ticket_ref_hash"] if has_more and page else "",
        }
        queue["authority"] = self.authority_status()
        return queue

    def enqueue_handoffs(
        self,
        tickets: tuple[Any, ...],
        *,
        now: int | None = None,
    ) -> tuple[ReviewQueueState, int]:
        """Persist bounded internal handoffs under the release anchor.

        A ticket ID is an idempotency identity. Replaying the same handoff is
        harmless, while reusing an existing ID with different hash-bound
        fields fails closed instead of silently rebinding the review subject.
        """

        if not isinstance(tickets, tuple) or not 1 <= len(tickets) <= 64:
            raise ReviewAuthorityError("review handoff batch is invalid")
        opened_at = int(time.time() if now is None else now)
        ttl_seconds = _bounded_int(
            getattr(self.settings, "review_ticket_ttl_seconds", 86_400),
            "review ticket ttl",
            minimum=300,
            maximum=30 * 24 * 60 * 60,
        )
        created_count = 0
        with self._queue_lease():
            state = self._recover_state(now=opened_at)
            self._validate_state_authority(state)
            for handoff in tickets:
                role = self.policy.authority_for_role(
                    _role(getattr(handoff, "routed_role", ""))
                )
                try:
                    candidate = ReviewTicket.from_handoff(
                        handoff,
                        opened_at=opened_at,
                        ttl_seconds=ttl_seconds,
                        required_approvals=role.threshold,
                    )
                except ReviewQueueError as exc:
                    raise ReviewAuthorityError(str(exc)) from exc
                candidate_ref = review_ticket_reference_hash(candidate)
                existing = next(
                    (
                        ticket
                        for ticket in state.tickets.values()
                        if hmac.compare_digest(
                            review_ticket_reference_hash(ticket), candidate_ref
                        )
                    ),
                    None,
                )
                if existing is not None:
                    if not _same_handoff_binding(existing, candidate):
                        raise ReviewAuthorityError(
                            "review ticket identity is already bound"
                        )
                    continue
                try:
                    state = enqueue_handoff_tickets(
                        state,
                        (handoff,),
                        opened_at=opened_at,
                        ttl_seconds=ttl_seconds,
                        required_approvals_by_role={role.role: role.threshold},
                    )
                except ReviewQueueError as exc:
                    raise ReviewAuthorityError(str(exc)) from exc
                created_count += 1
            self._validate_state_authority(state)
            if created_count:
                self._commit_state(state, now=opened_at)
        return state, created_count

    def issue_challenge(
        self,
        *,
        address: str,
        ticket_ref_hash_value: str,
        decision: str,
        now: int | None = None,
    ) -> ReviewChallenge:
        issued_at = int(time.time() if now is None else now)
        normalized_address = normalize_wallet_address(address)
        normalized_ref = _hash(ticket_ref_hash_value, "review ticket reference")
        normalized_decision = _decision(decision)
        with self._queue_lease():
            state = self._recover_state(now=issued_at)
            self._validate_state_authority(state)
            _, ticket = _ticket_by_public_ref(state, normalized_ref)
            role = self.policy.authority_for_role(ticket.routed_role)
            self._validate_ticket_authority(ticket, role, now=issued_at)
            identity = role.identity_for_address(normalized_address)
            if (
                ticket.submitter_ref_hash
                and hmac.compare_digest(
                    ticket.submitter_ref_hash, identity.reviewer_ref_hash
                )
            ):
                raise ReviewAuthorityError("review authorization denied")
            if (
                normalized_decision == "release"
                and identity.reviewer_ref_hash in ticket.approval_reviewer_hashes
            ):
                raise ReviewAuthorityError("review authorization denied")
            ticket_state_hash = review_ticket_state_hash(ticket)

        ttl = _bounded_int(
            getattr(settings := self.settings, "review_authority_challenge_ttl_seconds", 300),
            "review challenge ttl",
            minimum=30,
            maximum=300,
        )
        nonce = secrets.token_hex(16)
        expires_at = issued_at + ttl
        message = review_authority_challenge_message(
            settings,
            ticket_ref_hash_value=normalized_ref,
            ticket_state_hash=ticket_state_hash,
            routed_role=ticket.routed_role,
            decision=normalized_decision,
            reviewer_ref_hash_value=identity.reviewer_ref_hash,
            authority_context_hash=self.authority_context_hash,
            policy_sha256=self.policy.policy_sha256,
            nonce=nonce,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        challenge = ReviewChallenge(
            address=normalized_address,
            reviewer_ref_hash=identity.reviewer_ref_hash,
            ticket_ref_hash=normalized_ref,
            ticket_state_hash=ticket_state_hash,
            routed_role=ticket.routed_role,
            decision=normalized_decision,
            authority_context_hash=self.authority_context_hash,
            policy_sha256=self.policy.policy_sha256,
            nonce=nonce,
            message=message,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self.challenge_store.put(challenge, now=issued_at)
        return challenge

    def decide(
        self,
        *,
        nonce: str,
        signature: str,
        now: int | None = None,
    ) -> ReviewQueueState:
        verification_started_at = int(time.time() if now is None else now)
        normalized_nonce = _nonce(nonce)
        challenge = self.challenge_store.reserve(
            normalized_nonce, now=verification_started_at
        )
        verified = False
        verification_kind = ""
        try:
            verifier = self.signature_verifier
            if verifier is None:
                verifier = wallet_signature_verifier_from_settings(self.settings)
            verification_kind = verifier.verify(
                address=challenge.address,
                message=challenge.message,
                signature=signature,
            )
            if verification_kind not in {"eoa", "eip1271"}:
                raise WalletSignatureUnavailable(
                    "review signature verifier returned an unsupported result"
                )
            verified = True
        except WalletSignatureError as exc:
            raise ReviewAuthorityError("review wallet signature is invalid") from exc
        except WalletSignatureUnavailable as exc:
            raise ReviewAuthorityUnavailable(
                "review wallet signature verification is unavailable"
            ) from exc
        except Exception as exc:
            raise ReviewAuthorityUnavailable(
                "review wallet signature verification is unavailable"
            ) from exc
        finally:
            if not verified:
                self.challenge_store.release(normalized_nonce, challenge)

        consumed_at = (
            verification_started_at if now is not None else int(time.time())
        )
        self.challenge_store.consume(
            normalized_nonce, challenge, now=consumed_at
        )
        authorization_hash = review_authorization_hash(
            challenge,
            signature=signature,
            verification_kind=verification_kind,
        )
        with self._queue_lease():
            state = self._recover_state(now=consumed_at)
            self._validate_state_authority(state)
            try:
                ticket_state_key, ticket = _ticket_by_public_ref(
                    state, challenge.ticket_ref_hash
                )
            except ReviewAuthorityError as exc:
                raise ReviewAuthorityError(
                    "review ticket changed after challenge issuance"
                ) from exc
            if not hmac.compare_digest(
                review_ticket_state_hash(ticket), challenge.ticket_state_hash
            ):
                raise ReviewAuthorityError(
                    "review ticket changed after challenge issuance"
                )
            role = self.policy.authority_for_role(ticket.routed_role)
            self._validate_ticket_authority(ticket, role, now=consumed_at)
            identity = role.identity_for_address(challenge.address)
            if (
                not hmac.compare_digest(
                    identity.reviewer_ref_hash, challenge.reviewer_ref_hash
                )
            ):
                raise ReviewAuthorityError("review authority identity changed")
            try:
                state = decide_review_ticket(
                    state,
                    ticket_state_key,
                    decision=challenge.decision,
                    reviewer_ref=identity.reviewer_ref,
                    decided_at=consumed_at,
                    authorization_hash=authorization_hash,
                    authority_context_hash=self.authority_context_hash,
                )
            except ReviewQueueError as exc:
                raise ReviewAuthorityError(str(exc)) from exc
            self._commit_state(state, now=consumed_at)
        return state

    def expire(self, *, now: int | None = None) -> ReviewQueueState:
        current = int(time.time() if now is None else now)
        with self._queue_lease():
            state = self._recover_state(now=current)
            self._validate_state_authority(state)
            updated = expire_review_tickets(state, now=current)
            if review_queue_state_hash(
                updated,
                authority_context_hash=self.authority_context_hash,
            ) != review_queue_state_hash(
                state,
                authority_context_hash=self.authority_context_hash,
            ):
                self._commit_state(updated, now=current)
            state = updated
        return state

    @contextmanager
    def _queue_lease(self):
        with self._repository_lock:
            try:
                with review_queue_exclusive_lease(self.queue_path):
                    yield
            except ReviewQueueError as exc:
                raise ReviewAuthorityUnavailable(
                    "review queue persistence is unavailable"
                ) from exc

    def _load_path(self, path: str | Path) -> ReviewQueueState:
        try:
            return load_review_queue(
                path,
                integrity_key=self.integrity_key,
                expected_authority_context_hash=self.authority_context_hash,
            )
        except ReviewQueueError as exc:
            raise ReviewAuthorityUnavailable(
                "review queue persistence is unavailable"
            ) from exc

    def _recover_state(self, *, now: int) -> ReviewQueueState:
        active_path = Path(self.queue_path)
        pending_path = review_queue_pending_path(active_path)
        active_exists = os.path.lexists(active_path)
        pending_exists = os.path.lexists(pending_path)
        if self.rollback_anchor is None:
            if not active_exists:
                raise ReviewAuthorityUnavailable(
                    "review queue persistence is unavailable"
                )
            return self._load_path(active_path)

        try:
            head = self.rollback_anchor.read_head(now=now)
        except ReviewQueueAnchorError as exc:
            raise ReviewAuthorityUnavailable(
                "review queue rollback anchor is unavailable"
            ) from exc
        self._last_anchor_head = head
        if head.state_hash == ZERO_REVIEW_QUEUE_STATE_HASH:
            if pending_exists:
                try:
                    discard_review_queue_pending(active_path)
                except ReviewQueueError as exc:
                    raise ReviewAuthorityUnavailable(
                        "review queue recovery is unavailable"
                    ) from exc
            if active_exists:
                state = self._load_path(active_path)
                if state.tickets or state.audit:
                    raise ReviewAuthorityUnavailable(
                        "unanchored review queue state is not empty"
                    )
            else:
                state = ReviewQueueState.empty()
                try:
                    save_review_queue(
                        active_path,
                        state,
                        integrity_key=self.integrity_key,
                        authority_context_hash=self.authority_context_hash,
                    )
                except ReviewQueueError as exc:
                    raise ReviewAuthorityUnavailable(
                        "review queue initialization is unavailable"
                    ) from exc
            initial_hash = review_queue_state_hash(
                state,
                authority_context_hash=self.authority_context_hash,
            )
            try:
                head = self.rollback_anchor.compare_and_set(
                    expected_state_hash=ZERO_REVIEW_QUEUE_STATE_HASH,
                    new_state_hash=initial_hash,
                    now=now,
                )
            except ReviewQueueAnchorError as exc:
                raise ReviewAuthorityUnavailable(
                    "review queue initialization anchor is unavailable"
                ) from exc
            self._last_anchor_head = head
            return state

        active_state = self._load_path(active_path) if active_exists else None
        active_hash = (
            review_queue_state_hash(
                active_state,
                authority_context_hash=self.authority_context_hash,
            )
            if active_state is not None
            else ""
        )
        if active_state is not None and hmac.compare_digest(
            active_hash,
            head.state_hash,
        ):
            if pending_exists:
                try:
                    discard_review_queue_pending(active_path)
                except ReviewQueueError as exc:
                    raise ReviewAuthorityUnavailable(
                        "review queue recovery is unavailable"
                    ) from exc
            return active_state

        if pending_exists:
            pending_state = self._load_path(pending_path)
            pending_hash = review_queue_state_hash(
                pending_state,
                authority_context_hash=self.authority_context_hash,
            )
            if hmac.compare_digest(pending_hash, head.state_hash):
                try:
                    promote_review_queue_pending(active_path)
                except ReviewQueueError as exc:
                    raise ReviewAuthorityUnavailable(
                        "review queue recovery is unavailable"
                    ) from exc
                return pending_state
        raise ReviewAuthorityUnavailable(
            "review queue state does not match its rollback anchor"
        )

    def _commit_state(self, state: ReviewQueueState, *, now: int) -> None:
        if self.rollback_anchor is None:
            try:
                save_review_queue(
                    self.queue_path,
                    state,
                    integrity_key=self.integrity_key,
                    authority_context_hash=self.authority_context_hash,
                )
            except ReviewQueueError as exc:
                raise ReviewAuthorityUnavailable(
                    "review queue persistence is unavailable"
                ) from exc
            return
        if self._last_anchor_head is None:
            raise ReviewAuthorityUnavailable(
                "review queue rollback anchor head is unavailable"
            )
        next_hash = review_queue_state_hash(
            state,
            authority_context_hash=self.authority_context_hash,
        )
        previous_hash = self._last_anchor_head.state_hash
        if hmac.compare_digest(next_hash, previous_hash):
            return
        pending_path = review_queue_pending_path(self.queue_path)
        try:
            save_review_queue(
                pending_path,
                state,
                integrity_key=self.integrity_key,
                authority_context_hash=self.authority_context_hash,
            )
        except ReviewQueueError as exc:
            raise ReviewAuthorityUnavailable(
                "review queue pending persistence is unavailable"
            ) from exc
        try:
            head = self.rollback_anchor.compare_and_set(
                expected_state_hash=previous_hash,
                new_state_hash=next_hash,
                now=now,
            )
        except ReviewQueueAnchorError as exc:
            # Preserve the pending file: the anchor transaction may have
            # committed despite a transport/confirmation failure. The next
            # lease authenticates the chain head before promoting or discarding.
            raise ReviewAuthorityUnavailable(
                "review queue rollback anchor commit is unavailable"
            ) from exc
        try:
            promote_review_queue_pending(self.queue_path)
        except ReviewQueueError as exc:
            raise ReviewAuthorityUnavailable(
                "review queue anchored state promotion is unavailable"
            ) from exc
        self._last_anchor_head = head

    def _validate_state_authority(self, state: ReviewQueueState) -> None:
        for ticket in state.tickets.values():
            try:
                role = self.policy.authority_for_role(ticket.routed_role)
            except ReviewAuthorityError as exc:
                raise ReviewAuthorityUnavailable(
                    "review ticket role is not bound by the release policy"
                ) from exc
            self._validate_ticket_authority(ticket, role, now=None)

    def _validate_ticket_authority(
        self,
        ticket: ReviewTicket,
        role: ReviewRoleAuthority,
        *,
        now: int | None,
    ) -> None:
        if ticket.required_approvals != role.threshold:
            raise ReviewAuthorityUnavailable(
                "review ticket threshold differs from current authority"
            )
        if len(ticket.approval_reviewer_hashes) != len(
            ticket.approval_authorization_hashes
        ):
            raise ReviewAuthorityUnavailable(
                "review ticket authorization evidence is incomplete"
            )
        if len(set(ticket.approval_reviewer_hashes)) != len(
            ticket.approval_reviewer_hashes
        ):
            raise ReviewAuthorityUnavailable(
                "review ticket contains duplicate reviewer identities"
            )
        if any(
            reviewer_hash not in role.reviewer_hashes
            for reviewer_hash in ticket.approval_reviewer_hashes
        ):
            raise ReviewAuthorityUnavailable(
                "review ticket contains an unauthorized reviewer identity"
            )
        if any(
            not _HASH_RE.fullmatch(authorization_hash)
            for authorization_hash in ticket.approval_authorization_hashes
        ):
            raise ReviewAuthorityUnavailable(
                "review ticket authorization evidence is invalid"
            )
        if (
            ticket.approval_reviewer_hashes
            and ticket.status != ReviewTicketStatus.DENIED
            and (
            not hmac.compare_digest(
                ticket.reviewer_ref_hash, ticket.approval_reviewer_hashes[-1]
            )
            or not hmac.compare_digest(
                ticket.reviewer_authorization_hash,
                ticket.approval_authorization_hashes[-1],
            )
            )
        ):
            raise ReviewAuthorityUnavailable(
                "review ticket authorization head is inconsistent"
            )
        has_decision_evidence = bool(
            ticket.approval_reviewer_hashes
            or ticket.reviewer_ref_hash
            or ticket.reviewer_authorization_hash
            or ticket.authority_context_hash
        )
        if has_decision_evidence:
            if (
                not hmac.compare_digest(
                    ticket.authority_context_hash, self.authority_context_hash
                )
                or ticket.reviewer_ref_hash not in role.reviewer_hashes
                or not _HASH_RE.fullmatch(ticket.reviewer_authorization_hash)
            ):
                raise ReviewAuthorityUnavailable(
                    "review ticket authority context is invalid"
                )
        if (
            ticket.status == ReviewTicketStatus.RELEASED
            and len(ticket.approval_reviewer_hashes) != role.threshold
        ):
            raise ReviewAuthorityUnavailable(
                "released review ticket does not carry the exact threshold"
            )
        if (
            ticket.status == ReviewTicketStatus.PENDING
            and len(ticket.approval_reviewer_hashes) >= role.threshold
        ):
            raise ReviewAuthorityUnavailable(
                "pending review ticket already meets its release threshold"
            )
        if (
            ticket.status == ReviewTicketStatus.DENIED
            and not ticket.reviewer_authorization_hash
        ):
            raise ReviewAuthorityUnavailable(
                "denied review ticket lacks authorization evidence"
            )
        if now is not None:
            if ticket.status != ReviewTicketStatus.PENDING:
                raise ReviewAuthorityError("review ticket is not pending")
            if ticket.expires_at <= now:
                raise ReviewAuthorityError("review ticket expired")


def review_authority_policy(settings: Any) -> ReviewAuthorityPolicy:
    raw = str(getattr(settings, "review_authority_policy_json", "") or "")
    expected_sha = str(
        getattr(settings, "review_authority_policy_sha256", "") or ""
    ).strip()
    if not raw or len(raw.encode("utf-8")) > 65_536 or not _SHA256_RE.fullmatch(expected_sha):
        raise ReviewAuthorityUnavailable("review authority policy is not configured")
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReviewAuthorityUnavailable("review authority policy is invalid") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "roles"}
        or document.get("schema") != REVIEW_AUTHORITY_POLICY_SCHEMA
        or not isinstance(document.get("roles"), list)
        or not 1 <= len(document["roles"]) <= 32
    ):
        raise ReviewAuthorityUnavailable("review authority policy is invalid")

    roles: list[ReviewRoleAuthority] = []
    seen_roles: set[str] = set()
    address_to_ref: dict[str, str] = {}
    ref_to_address: dict[str, str] = {}
    normalized_roles: list[dict[str, Any]] = []
    for raw_role in document["roles"]:
        if not isinstance(raw_role, dict) or set(raw_role) != {
            "role",
            "threshold",
            "reviewers",
        }:
            raise ReviewAuthorityUnavailable("review authority role is invalid")
        role = _role(raw_role.get("role"))
        if role in seen_roles:
            raise ReviewAuthorityUnavailable("review authority role is duplicated")
        seen_roles.add(role)
        threshold = _bounded_int(
            raw_role.get("threshold"),
            "review authority threshold",
            minimum=2,
            maximum=16,
        )
        raw_reviewers = raw_role.get("reviewers")
        if (
            not isinstance(raw_reviewers, list)
            or not threshold <= len(raw_reviewers) <= 32
        ):
            raise ReviewAuthorityUnavailable(
                "review authority reviewer set is invalid"
            )
        reviewers: list[ReviewIdentity] = []
        seen_role_addresses: set[str] = set()
        seen_role_refs: set[str] = set()
        normalized_reviewers: list[dict[str, str]] = []
        for raw_reviewer in raw_reviewers:
            if not isinstance(raw_reviewer, dict) or set(raw_reviewer) != {
                "address",
                "reviewer_ref",
            }:
                raise ReviewAuthorityUnavailable(
                    "review authority reviewer identity is invalid"
                )
            try:
                address = normalize_wallet_address(raw_reviewer.get("address"))
            except Exception as exc:
                raise ReviewAuthorityUnavailable(
                    "review authority reviewer identity is invalid"
                ) from exc
            reviewer_ref = raw_reviewer.get("reviewer_ref")
            if (
                not isinstance(reviewer_ref, str)
                or not _REVIEWER_REF_RE.fullmatch(reviewer_ref)
            ):
                raise ReviewAuthorityUnavailable(
                    "review authority reviewer identity is invalid"
                )
            if address in seen_role_addresses or reviewer_ref in seen_role_refs:
                raise ReviewAuthorityUnavailable(
                    "review authority reviewer identity is duplicated"
                )
            if address in address_to_ref and address_to_ref[address] != reviewer_ref:
                raise ReviewAuthorityUnavailable(
                    "review authority address maps to multiple identities"
                )
            if reviewer_ref in ref_to_address and ref_to_address[reviewer_ref] != address:
                raise ReviewAuthorityUnavailable(
                    "review authority identity maps to multiple addresses"
                )
            seen_role_addresses.add(address)
            seen_role_refs.add(reviewer_ref)
            address_to_ref[address] = reviewer_ref
            ref_to_address[reviewer_ref] = address
            identity = ReviewIdentity(
                address=address,
                reviewer_ref=reviewer_ref,
                reviewer_ref_hash=reviewer_ref_hash(reviewer_ref),
            )
            reviewers.append(identity)
            normalized_reviewers.append(
                {"address": address, "reviewer_ref": reviewer_ref}
            )
        reviewers.sort(key=lambda item: (item.address, item.reviewer_ref))
        normalized_reviewers.sort(key=lambda item: (item["address"], item["reviewer_ref"]))
        roles.append(
            ReviewRoleAuthority(
                role=role, threshold=threshold, reviewers=tuple(reviewers)
            )
        )
        normalized_roles.append(
            {
                "role": role,
                "threshold": threshold,
                "reviewers": normalized_reviewers,
            }
        )
    roles.sort(key=lambda item: item.role)
    normalized_roles.sort(key=lambda item: item["role"])
    if seen_roles != REVIEW_AUTHORITY_ROLES:
        raise ReviewAuthorityUnavailable(
            "review authority policy must bind the exact product role set"
        )
    normalized = {"schema": REVIEW_AUTHORITY_POLICY_SCHEMA, "roles": normalized_roles}
    actual_sha = "sha256:" + hashlib.sha256(
        b"dnai-wikigen/review-authority-policy/v1\0" + _canonical_json(normalized)
    ).hexdigest()
    if not hmac.compare_digest(actual_sha, expected_sha):
        raise ReviewAuthorityUnavailable(
            "review authority policy hash does not match its canonical contents"
        )
    active = review_authority_active_reviewers(settings)
    policy_pairs = frozenset(
        (identity.address, identity.reviewer_ref)
        for role in roles
        for identity in role.reviewers
    )
    if policy_pairs != active.identity_pairs:
        raise ReviewAuthorityUnavailable(
            "review role policy does not exactly map the active release reviewers"
        )
    return ReviewAuthorityPolicy(roles=tuple(roles), policy_sha256=actual_sha)


def review_authority_policy_sha256(policy_document: dict[str, Any]) -> str:
    """Return the canonical policy digest for an already valid policy document."""

    if not isinstance(policy_document, dict):
        raise ReviewAuthorityError("review authority policy is invalid")
    normalized = _normalize_policy_document_for_digest(policy_document)
    return "sha256:" + hashlib.sha256(
        b"dnai-wikigen/review-authority-policy/v1\0" + _canonical_json(normalized)
    ).hexdigest()


def review_authority_active_reviewers(
    settings: Any,
) -> ReviewActiveReviewerSet:
    raw = str(
        getattr(
            settings,
            "release_reviewer_authority_active_reviewers_json",
            "",
        )
        or ""
    )
    expected_sha = str(
        getattr(
            settings,
            "release_reviewer_authority_active_reviewers_sha256",
            "",
        )
        or ""
    ).strip()
    if (
        not raw
        or len(raw.encode("utf-8")) > 65_536
        or not _SHA256_RE.fullmatch(expected_sha)
    ):
        raise ReviewAuthorityUnavailable(
            "active release reviewer projection is not configured"
        )
    try:
        document = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ReviewAuthorityUnavailable(
            "active release reviewer projection is invalid"
        ) from exc
    try:
        reviewers, normalized_document = _normalize_active_reviewer_document(
            document
        )
    except ReviewAuthorityError as exc:
        raise ReviewAuthorityUnavailable(str(exc)) from exc
    actual_sha = "sha256:" + hashlib.sha256(
        b"dnai-wikigen/review-active-reviewers/v1\0"
        + _canonical_json(normalized_document)
    ).hexdigest()
    if not hmac.compare_digest(actual_sha, expected_sha):
        raise ReviewAuthorityUnavailable(
            "active release reviewer projection hash is invalid"
        )
    return ReviewActiveReviewerSet(
        reviewers=tuple(reviewers),
        projection_sha256=actual_sha,
    )


def review_authority_active_reviewers_sha256(
    projection_document: dict[str, Any],
) -> str:
    """Return the digest for a valid address/controller projection document."""

    _, normalized_document = _normalize_active_reviewer_document(
        projection_document
    )
    return "sha256:" + hashlib.sha256(
        b"dnai-wikigen/review-active-reviewers/v1\0"
        + _canonical_json(normalized_document)
    ).hexdigest()


def _normalize_active_reviewer_document(
    document: Any,
) -> tuple[list[ReviewIdentity], dict[str, Any]]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "reviewers"}
        or document.get("schema") != REVIEW_ACTIVE_REVIEWERS_SCHEMA
        or not isinstance(document.get("reviewers"), list)
        or not 2 <= len(document["reviewers"]) <= 32
    ):
        raise ReviewAuthorityError(
            "active release reviewer projection is invalid"
        )
    reviewers: list[ReviewIdentity] = []
    normalized: list[dict[str, str]] = []
    seen_addresses: set[str] = set()
    seen_controllers: set[str] = set()
    for item in document["reviewers"]:
        if not isinstance(item, dict) or set(item) != {
            "address",
            "controller_id",
        }:
            raise ReviewAuthorityError(
                "active release reviewer projection is invalid"
            )
        try:
            address = normalize_wallet_address(item.get("address"))
        except Exception as exc:
            raise ReviewAuthorityError(
                "active release reviewer projection is invalid"
            ) from exc
        controller_id = item.get("controller_id")
        if (
            not isinstance(controller_id, str)
            or not _REVIEWER_REF_RE.fullmatch(controller_id)
            or address in seen_addresses
            or controller_id in seen_controllers
        ):
            raise ReviewAuthorityError(
                "active release reviewer projection is invalid"
            )
        seen_addresses.add(address)
        seen_controllers.add(controller_id)
        reviewers.append(
            ReviewIdentity(
                address=address,
                reviewer_ref=controller_id,
                reviewer_ref_hash=reviewer_ref_hash(controller_id),
            )
        )
        normalized.append(
            {"address": address, "controller_id": controller_id}
        )
    reviewers.sort(key=lambda item: (item.address, item.reviewer_ref))
    normalized.sort(key=lambda item: (item["address"], item["controller_id"]))
    return reviewers, {
        "schema": REVIEW_ACTIVE_REVIEWERS_SCHEMA,
        "reviewers": normalized,
    }


def review_authority_release_provenance(
    settings: Any,
) -> ReviewAuthorityReleaseProvenance:
    genesis_acceptance = str(
        getattr(
            settings,
            "release_reviewer_authority_genesis_acceptance_sha256",
            "",
        )
        or ""
    ).strip()
    current_status_epoch = getattr(
        settings, "release_reviewer_authority_current_status_epoch", 0
    )
    current_status_sha256 = str(
        getattr(
            settings,
            "release_reviewer_authority_current_status_sha256",
            "",
        )
        or ""
    ).strip()
    active_reviewers_sha256 = str(
        getattr(
            settings,
            "release_reviewer_authority_active_reviewers_sha256",
            "",
        )
        or ""
    ).strip()
    if (
        not _SHA256_RE.fullmatch(genesis_acceptance)
        or isinstance(current_status_epoch, bool)
        or not isinstance(current_status_epoch, int)
        or not 1 <= current_status_epoch <= 0xFFFF_FFFF
        or not _SHA256_RE.fullmatch(current_status_sha256)
        or not _SHA256_RE.fullmatch(active_reviewers_sha256)
    ):
        raise ReviewAuthorityUnavailable(
            "review authority release provenance is incomplete"
        )
    return ReviewAuthorityReleaseProvenance(
        genesis_acceptance_sha256=genesis_acceptance,
        current_status_epoch=current_status_epoch,
        current_status_sha256=current_status_sha256,
        active_reviewers_sha256=active_reviewers_sha256,
    )


def review_authority_context_hash(
    settings: Any,
    policy: ReviewAuthorityPolicy,
    release_provenance: ReviewAuthorityReleaseProvenance | None = None,
) -> str:
    chain_id = getattr(settings, "wallet_auth_chain_id", 0)
    domain = str(getattr(settings, "wallet_auth_domain", "") or "").strip()
    uri = str(getattr(settings, "wallet_auth_uri", "") or "").strip()
    cvm_id = str(getattr(settings, "main_runtime_cvm_id", "") or "").strip()
    deployment_intent = str(
        getattr(settings, "release_deployment_intent_sha256", "") or ""
    ).strip()
    release_authority = str(
        getattr(settings, "release_authority_sha256", "") or ""
    ).strip()
    ceremony_nonce = str(
        getattr(settings, "release_ceremony_nonce", "") or ""
    ).strip()
    if (
        chain_id != BASE_SEPOLIA_CHAIN_ID
        or domain != "www.wikigen.me"
        or uri != "https://www.wikigen.me"
        or not _CVM_ID_RE.fullmatch(cvm_id)
        or not _SHA256_RE.fullmatch(deployment_intent)
        or not _SHA256_RE.fullmatch(release_authority)
        or not _BYTES32_RE.fullmatch(ceremony_nonce)
    ):
        raise ReviewAuthorityUnavailable(
            "review authority release context is incomplete"
        )
    provenance = release_provenance or review_authority_release_provenance(settings)
    context = {
        "schema": REVIEW_AUTHORITY_CONTEXT_SCHEMA,
        "chain_id": chain_id,
        "domain": domain,
        "uri": uri,
        "main_runtime_cvm_id": cvm_id,
        "deployment_intent_sha256": deployment_intent,
        "release_authority_sha256": release_authority,
        "ceremony_nonce": ceremony_nonce,
        "policy_sha256": policy.policy_sha256,
        **provenance.to_public_dict(),
    }
    return _hash_json("dnai-wikigen/review-authority-context/v1", context)


def review_queue_integrity_key(settings: Any) -> bytes:
    domain = b"dnai-wikigen/review-queue-integrity/v1\0"
    if dstack_utils.is_dstack_enabled():
        path = str(
            getattr(
                settings,
                "review_queue_store_integrity_key_path",
                "tinker/review_queue_integrity",
            )
            or ""
        ).strip()
        if not path or path in {
            "tinker/runtime-auth",
            "tinker/wallet_auth",
            "tinker/execution_policy_store_integrity",
            "tinker/compute_store_integrity",
        }:
            raise ReviewAuthorityUnavailable(
                "review queue integrity key path is invalid"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ReviewAuthorityUnavailable(
                "review queue integrity key derivation failed"
            ) from exc
        return hashlib.sha256(domain + b"dstack\0" + material).digest()
    explicit = str(
        getattr(settings, "review_queue_store_integrity_key", "") or ""
    )
    if len(explicit) < 32:
        raise ReviewAuthorityUnavailable(
            "review queue integrity key is unavailable outside dstack"
        )
    return hashlib.sha256(domain + b"local\0" + explicit.encode("utf-8")).digest()


def review_authority_challenge_message(
    settings: Any,
    *,
    ticket_ref_hash_value: str,
    ticket_state_hash: str,
    routed_role: str,
    decision: Literal["release", "deny"],
    reviewer_ref_hash_value: str,
    authority_context_hash: str,
    policy_sha256: str,
    nonce: str,
    issued_at: int,
    expires_at: int,
) -> str:
    payload = {
        "schema": REVIEW_AUTHORITY_CHALLENGE_SCHEMA,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "domain": str(getattr(settings, "wallet_auth_domain", "") or ""),
        "uri": str(getattr(settings, "wallet_auth_uri", "") or ""),
        "authority_context_hash": _hash(
            authority_context_hash, "review authority context"
        ),
        "policy_sha256": _sha256(policy_sha256, "review authority policy"),
        "ticket_ref_hash": _hash(ticket_ref_hash_value, "review ticket reference"),
        "ticket_state_hash": _hash(ticket_state_hash, "review ticket state"),
        "routed_role": _role(routed_role),
        "decision": _decision(decision),
        "reviewer_ref_hash": _hash(
            reviewer_ref_hash_value, "reviewer reference"
        ),
        "nonce": _nonce(nonce),
        "issued_at": _timestamp(issued_at, "review challenge issued_at"),
        "expires_at": _timestamp(expires_at, "review challenge expires_at"),
    }
    if payload["expires_at"] <= payload["issued_at"]:
        raise ReviewAuthorityError("review challenge expiry is invalid")
    return "DNAI Wikigen bounded review authorization\n" + _canonical_json(
        payload
    ).decode("ascii")


def review_authorization_hash(
    challenge: ReviewChallenge,
    *,
    signature: str,
    verification_kind: str,
) -> str:
    if verification_kind not in {"eoa", "eip1271"}:
        raise ReviewAuthorityError("review verification kind is invalid")
    if not isinstance(signature, str) or not _SIGNATURE_RE.fullmatch(signature):
        raise ReviewAuthorityError("review wallet signature is invalid")
    raw_hex = signature[2:] if signature.startswith(("0x", "0X")) else signature
    if len(raw_hex) % 2:
        raise ReviewAuthorityError("review wallet signature is invalid")
    try:
        raw_signature = bytes.fromhex(raw_hex)
    except ValueError as exc:
        raise ReviewAuthorityError("review wallet signature is invalid") from exc
    return hashlib.sha256(
        b"dnai-wikigen/review-authorization/v1\0"
        + bytes.fromhex(challenge.authority_context_hash)
        + hashlib.sha256(challenge.message.encode("utf-8")).digest()
        + verification_kind.encode("ascii")
        + b"\0"
        + raw_signature
    ).hexdigest()


def _ticket_by_public_ref(
    state: ReviewQueueState, ticket_ref_hash_value: str
) -> tuple[str, ReviewTicket]:
    matches = [
        (state_key, ticket)
        for state_key, ticket in state.tickets.items()
        if hmac.compare_digest(
            review_ticket_reference_hash(ticket), ticket_ref_hash_value
        )
    ]
    if len(matches) != 1:
        raise ReviewAuthorityError("review authorization denied")
    return matches[0]


def _same_handoff_binding(existing: ReviewTicket, candidate: ReviewTicket) -> bool:
    """Compare only immutable, hash-bound handoff fields for idempotent retry."""

    return all(
        hmac.compare_digest(left, right)
        for left, right in (
            (review_ticket_reference_hash(existing), review_ticket_reference_hash(candidate)),
            (existing.turn_ref_digest, candidate.turn_ref_digest),
            (existing.corpus_ref_digest, candidate.corpus_ref_digest),
            (existing.routed_role, candidate.routed_role),
            (existing.reason_hash, candidate.reason_hash),
            (existing.submitter_ref_hash, candidate.submitter_ref_hash),
        )
    ) and existing.required_approvals == candidate.required_approvals


def _normalize_policy_document_for_digest(document: dict[str, Any]) -> dict[str, Any]:
    if (
        set(document) != {"schema", "roles"}
        or document.get("schema") != REVIEW_AUTHORITY_POLICY_SCHEMA
        or not isinstance(document.get("roles"), list)
        or not 1 <= len(document["roles"]) <= 32
    ):
        raise ReviewAuthorityError("review authority policy is invalid")
    normalized_roles: list[dict[str, Any]] = []
    seen_roles: set[str] = set()
    address_to_ref: dict[str, str] = {}
    ref_to_address: dict[str, str] = {}
    for raw_role in document["roles"]:
        if not isinstance(raw_role, dict) or set(raw_role) != {
            "role",
            "threshold",
            "reviewers",
        }:
            raise ReviewAuthorityError("review authority policy is invalid")
        role = _role(raw_role["role"])
        if role in seen_roles:
            raise ReviewAuthorityError("review authority policy is invalid")
        seen_roles.add(role)
        threshold = _bounded_int(
            raw_role["threshold"], "review authority threshold", minimum=2, maximum=16
        )
        raw_reviewers = raw_role["reviewers"]
        if not isinstance(raw_reviewers, list) or not threshold <= len(raw_reviewers) <= 32:
            raise ReviewAuthorityError("review authority policy is invalid")
        normalized_reviewers: list[dict[str, str]] = []
        seen_role_addresses: set[str] = set()
        seen_role_refs: set[str] = set()
        for item in raw_reviewers:
            if not isinstance(item, dict) or set(item) != {"address", "reviewer_ref"}:
                raise ReviewAuthorityError("review authority policy is invalid")
            address = normalize_wallet_address(item["address"])
            reviewer_ref = item["reviewer_ref"]
            if not isinstance(reviewer_ref, str) or not _REVIEWER_REF_RE.fullmatch(reviewer_ref):
                raise ReviewAuthorityError("review authority policy is invalid")
            if address in seen_role_addresses or reviewer_ref in seen_role_refs:
                raise ReviewAuthorityError("review authority policy is invalid")
            if address in address_to_ref and address_to_ref[address] != reviewer_ref:
                raise ReviewAuthorityError("review authority policy is invalid")
            if reviewer_ref in ref_to_address and ref_to_address[reviewer_ref] != address:
                raise ReviewAuthorityError("review authority policy is invalid")
            seen_role_addresses.add(address)
            seen_role_refs.add(reviewer_ref)
            address_to_ref[address] = reviewer_ref
            ref_to_address[reviewer_ref] = address
            normalized_reviewers.append(
                {"address": address, "reviewer_ref": reviewer_ref}
            )
        normalized_reviewers.sort(key=lambda item: (item["address"], item["reviewer_ref"]))
        normalized_roles.append(
            {
                "role": role,
                "threshold": threshold,
                "reviewers": normalized_reviewers,
            }
        )
    normalized_roles.sort(key=lambda item: item["role"])
    if seen_roles != REVIEW_AUTHORITY_ROLES:
        raise ReviewAuthorityError("review authority policy is invalid")
    return {"schema": REVIEW_AUTHORITY_POLICY_SCHEMA, "roles": normalized_roles}


def _role(value: Any) -> str:
    if not isinstance(value, str) or not _ROLE_RE.fullmatch(value):
        raise ReviewAuthorityError("review role is invalid")
    return value


def _decision(value: Any) -> Literal["release", "deny"]:
    if value not in {"release", "deny"}:
        raise ReviewAuthorityError("review decision is invalid")
    return value


def _nonce(value: Any) -> str:
    if not isinstance(value, str) or not _NONCE_RE.fullmatch(value):
        raise ReviewAuthorityError("review challenge nonce is invalid")
    return value


def _hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ReviewAuthorityError(f"{label} must be lowercase SHA-256 hex")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ReviewAuthorityError(f"{label} must be a nonzero SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> int:
    return _bounded_int(value, label, minimum=1, maximum=4_102_444_800)


def _bounded_int(
    value: Any, label: str, *, minimum: int, maximum: int
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ReviewAuthorityUnavailable(f"{label} is out of range")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _hash_json(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_json(value)
    ).hexdigest()
