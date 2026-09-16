"""Bounded, authenticated authority for multi-owner collaboration rooms.

Schema v2 separates four facts that v1 incorrectly conflated:

* a creator may *invite* a wallet, but only that wallet can accept membership;
* an accepted corpus owner must separately activate its room role;
* one accepted participant may propose one exact query commitment; and
* every required owner must approve that exact current query before a bounded
  joint-consent snapshot can be recorded.

Only commitments and wallet addresses are persisted. Raw purpose/policy text,
artifacts, and signatures never enter this store. The current file is
HMAC-authenticated, atomically replaced, fsynced, and cross-process locked.
The base store remains explicitly local/non-monotonic; live deployments use
``AnchoredCollaborationStore`` to bind each exact state to an external
release-context witness.
"""

from __future__ import annotations

import base64
import binascii
import copy
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
from typing import Any, Mapping


SCHEMA_VERSION = 2
MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_ROOMS = 1024
MAX_ROOMS_PER_CREATOR = 64
MAX_ACCEPTED_ROOMS_PER_PARTICIPANT = 64
MAX_PENDING_INVITATIONS_PER_TARGET = 32
MAX_PENDING_INVITATIONS_PER_INVITER = 64
MAX_PENDING_INVITATIONS_PER_ROOM = 15
MAX_MEMBERS_PER_ROOM = 16
MAX_OWNERS_PER_ROOM = 16
DEFAULT_ROOM_PAGE_SIZE = 8
MAX_ROOM_PAGE_SIZE = 16
MAX_CURSOR_BYTES = 1024

MAX_CHALLENGES = 4096
MAX_QUERY_CHALLENGES = 4096
MAX_CHALLENGES_PER_WALLET = 64
MAX_CHALLENGES_PER_ROOM = 128
MAX_RUNS = 4096
MAX_RUNS_PER_WALLET = 64
MAX_RUNS_PER_ROOM = 256
MAX_IDEMPOTENCY_RECORDS = 4096
MAX_IDEMPOTENCY_RECORDS_PER_WALLET = 128
MAX_IDEMPOTENCY_RECORDS_PER_ROOM = 512
MAX_CONSENT_TTL_SECONDS = 900

CHALLENGE_RETENTION_SECONDS = 86_400
RUN_RETENTION_SECONDS = 7 * 86_400
IDEMPOTENCY_RETENTION_SECONDS = 7 * 86_400
ROOM_ARCHIVE_RETENTION_SECONDS = 7 * 86_400

_ROOM_ID = re.compile(r"^room_[0-9a-f]{32}$")
_CHALLENGE_ID = re.compile(r"^consent_[0-9a-f]{32}$")
_QUERY_CHALLENGE_ID = re.compile(r"^qgrant_[0-9a-f]{32}$")
_RUN_ID = re.compile(r"^run_[0-9a-f]{32}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_HMAC = re.compile(r"^[0-9a-f]{64}$")
_CURSOR = re.compile(r"^collab_rooms_v1\.[A-Za-z0-9_-]+\.[0-9a-f]{64}$")


class CollaborationStoreError(ValueError):
    """A collaboration request or stored state is invalid."""


class CollaborationStoreCorruptError(CollaborationStoreError):
    """The authenticated current-state file is malformed or was changed."""


class CollaborationAuthorizationError(CollaborationStoreError):
    """The wallet is not authorized for the requested room operation."""


class CollaborationConflictError(CollaborationStoreError):
    """A replay, cursor, idempotency key, or state precondition conflicts."""


class CollaborationNotFoundError(CollaborationStoreError):
    """The requested participant-visible resource does not exist."""


class CollaborationCapacityError(CollaborationStoreError):
    """A global, per-wallet, or per-room cap has been reached."""


def collaboration_allocation_commitment(
    *,
    room_id: str,
    query_ref: str,
    room_commitment: str,
    owner_allocations_bps: Mapping[str, int],
) -> str:
    """Commit one exact allocation set to one v2 room and query."""

    return _hash_json(
        "dnai-wikigen/collaboration-allocation/v2",
        {
            "room_id": _room_id(room_id),
            "query_ref": _commitment(query_ref, "query_ref"),
            "room_commitment": _commitment(
                room_commitment,
                "room_commitment",
            ),
            "owner_allocations_bps": _allocation_map(
                owner_allocations_bps
            ),
        },
    )


class CollaborationStore:
    """Authenticated, bounded collaboration-room current-state repository."""

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        self.path = Path(path)
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise CollaborationStoreError(
                "Collaboration store integrity key must be at least 32 bytes"
            )
        self._integrity_key = bytes(integrity_key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        with self._locked():
            if self.path.exists() or self.path.is_symlink():
                self._load_locked()
            else:
                self._persist_locked(_empty_state())

    def create_room(
        self,
        *,
        room_id: str,
        idempotency_key: str,
        creator_address: str,
        member_addresses: list[str] | tuple[str, ...],
        purpose_commitment: str,
        pipeline_commitment: str,
        corpus_policy_commitments: Mapping[str, str],
        owner_allocations_bps: Mapping[str, int],
        created_at: int,
    ) -> dict[str, Any]:
        room_id = _room_id(room_id)
        idem = _idempotency_key(idempotency_key)
        creator = _wallet(creator_address)
        timestamp = _timestamp(created_at)
        declarations = _member_list(member_addresses, creator=creator)
        purpose = _commitment(purpose_commitment, "purpose_commitment")
        pipeline = _commitment(pipeline_commitment, "pipeline_commitment")
        policies = _policy_map(corpus_policy_commitments)
        allocations = _allocation_map(owner_allocations_bps)
        owners = list(allocations)
        if set(policies) != set(owners):
            raise CollaborationStoreError(
                "Corpus policy owners must exactly match allocation owners"
            )
        if not set(owners).issubset(declarations):
            raise CollaborationStoreError(
                "Every allocation owner must be a declared room invitee"
            )
        pending_invitees = [item for item in declarations if item != creator]
        if len(pending_invitees) > MAX_PENDING_INVITATIONS_PER_ROOM:
            raise CollaborationCapacityError(
                "Pending invitation limit reached for this room"
            )
        request = {
            "room_id": room_id,
            "creator_address": creator,
            "declared_member_addresses": declarations,
            "purpose_commitment": purpose,
            "pipeline_commitment": pipeline,
            "corpus_policy_commitments": policies,
            "owner_allocations_bps": allocations,
        }
        idem_id = _idempotency_id(
            operation="create_room",
            actor=creator,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                return self._room_projection_from_state(
                    candidate,
                    existing["result_id"],
                    creator,
                )
            if room_id in candidate["rooms"]:
                raise CollaborationConflictError(
                    "Collaboration room already exists"
                )
            if len(candidate["rooms"]) >= MAX_ROOMS:
                raise CollaborationCapacityError(
                    "Collaboration room store is full"
                )
            if _rooms_created_by(candidate, creator) >= MAX_ROOMS_PER_CREATOR:
                raise CollaborationCapacityError(
                    "Collaboration room creation limit reached for this wallet"
                )
            if (
                _accepted_room_count(candidate, creator)
                >= MAX_ACCEPTED_ROOMS_PER_PARTICIPANT
            ):
                raise CollaborationCapacityError(
                    "Accepted collaboration room limit reached for creator"
                )
            if (
                _pending_invites_by_creator(candidate, creator)
                + len(pending_invitees)
                > MAX_PENDING_INVITATIONS_PER_INVITER
            ):
                raise CollaborationCapacityError(
                    "Pending invitation limit reached for this inviter"
                )
            for invitee in pending_invitees:
                if (
                    _pending_invite_count(candidate, invitee)
                    >= MAX_PENDING_INVITATIONS_PER_TARGET
                ):
                    raise CollaborationCapacityError(
                        "Pending invitation limit reached for an invitee"
                    )
            _require_idempotency_capacity(
                candidate,
                actor=creator,
                room_id=room_id,
            )
            immutable = {
                "room_id": room_id,
                "creator_address": creator,
                "declared_member_addresses": declarations,
                "purpose_commitment": purpose,
                "pipeline_commitment": pipeline,
                "corpus_policy_commitments": policies,
                "owner_allocations_bps": allocations,
                "created_at": timestamp,
            }
            room = {
                **immutable,
                "room_commitment": _hash_json(
                    "dnai-wikigen/collaboration-room/v2",
                    immutable,
                ),
                "generation": 1,
                "updated_at": timestamp,
                "lifecycle_status": "active",
                "archived_at": 0,
                "reclaimable_after": 0,
                "memberships": {
                    member: {
                        "status": (
                            "accepted" if member == creator else "invited"
                        ),
                        "generation": 1 if member == creator else 0,
                        "decided_at": timestamp if member == creator else 0,
                    }
                    for member in declarations
                },
                "role_consents": {
                    owner: {
                        "status": "pending",
                        "generation": 0,
                        "authorization_hash": "",
                        "updated_at": timestamp,
                    }
                    for owner in owners
                },
                "current_query": None,
            }
            candidate["rooms"][room_id] = room
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation="create_room",
                actor=creator,
                room_id=room_id,
                result_kind="room",
                result_id=room_id,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return self._room_projection_from_state(
                candidate,
                room_id,
                creator,
            )

    def list_room_projections(
        self,
        participant_address: str,
        *,
        limit: int = DEFAULT_ROOM_PAGE_SIZE,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        participant = _wallet(participant_address)
        limit = _integer(
            limit,
            "room page limit",
            minimum=1,
            maximum=MAX_ROOM_PAGE_SIZE,
        )
        with self._locked():
            state = self._load_locked()
            visible = [
                room
                for room in state["rooms"].values()
                if _membership_status(room, participant)
                in {"accepted", "invited"}
            ]
            visible.sort(
                key=lambda room: (room["created_at"], room["room_id"]),
                reverse=True,
            )
            start = 0
            if cursor is not None:
                payload = self._decode_room_cursor(cursor)
                if (
                    payload["participant_address"] != participant
                    or payload["snapshot_sequence"] != state["sequence"]
                ):
                    raise CollaborationConflictError(
                        "Collaboration room cursor is stale; restart listing"
                    )
                anchor = (
                    payload["anchor_created_at"],
                    payload["anchor_room_id"],
                )
                for index, room in enumerate(visible):
                    if (room["created_at"], room["room_id"]) == anchor:
                        start = index + 1
                        break
                else:
                    raise CollaborationConflictError(
                        "Collaboration room cursor is stale; restart listing"
                    )
            selected = visible[start : start + limit]
            has_more = start + len(selected) < len(visible)
            next_cursor = None
            if has_more and selected:
                anchor = selected[-1]
                next_cursor = self._encode_room_cursor(
                    participant=participant,
                    sequence=state["sequence"],
                    created_at=anchor["created_at"],
                    room_id=anchor["room_id"],
                )
            return {
                "surface": "collaboration_rooms",
                "schema_version": 2,
                "rooms": [
                    self._room_projection_from_state(
                        state,
                        room["room_id"],
                        participant,
                    )
                    for room in selected
                ],
                "room_count": len(selected),
                "has_more": has_more,
                "next_cursor": next_cursor,
                "page_limit": limit,
                "maximum_page_size": MAX_ROOM_PAGE_SIZE,
                "maximum_accepted_rooms_per_participant": (
                    MAX_ACCEPTED_ROOMS_PER_PARTICIPANT
                ),
                "maximum_pending_invitations_per_target": (
                    MAX_PENDING_INVITATIONS_PER_TARGET
                ),
                "snapshot_bound_pagination": True,
                "participant_authenticated_projection": True,
                "raw_purpose_egress": False,
                "raw_policy_egress": False,
                "raw_signature_egress": False,
                **self._rollback_truth(),
            }

    def room_projection(
        self,
        room_id: str,
        participant_address: str,
    ) -> dict[str, Any]:
        with self._locked():
            return self._room_projection_from_state(
                self._load_locked(),
                _room_id(room_id),
                _wallet(participant_address),
            )

    def respond_to_invitation(
        self,
        *,
        room_id: str,
        participant_address: str,
        decision: str,
        idempotency_key: str,
        decided_at: int,
    ) -> dict[str, Any]:
        room_id = _room_id(room_id)
        participant = _wallet(participant_address)
        decision = _membership_decision(decision)
        idem = _idempotency_key(idempotency_key)
        timestamp = _timestamp(decided_at)
        request = {
            "room_id": room_id,
            "participant_address": participant,
            "decision": decision,
        }
        idem_id = _idempotency_id(
            operation=f"invitation_{decision}",
            actor=participant,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                return {
                    **_membership_result(
                        _room(candidate, room_id),
                        participant,
                    ),
                    **self._rollback_truth(),
                }
            room = _room(candidate, room_id)
            _require_active_room(room)
            membership = room["memberships"].get(participant)
            if membership is None:
                raise CollaborationAuthorizationError(
                    "Wallet does not have an invitation to this room"
                )
            if membership["status"] != "invited":
                raise CollaborationConflictError(
                    "Collaboration invitation is no longer pending"
                )
            if (
                decision == "accept"
                and _accepted_room_count(candidate, participant)
                >= MAX_ACCEPTED_ROOMS_PER_PARTICIPANT
            ):
                raise CollaborationCapacityError(
                    "Accepted collaboration room limit reached for this wallet"
                )
            _require_idempotency_capacity(
                candidate,
                actor=participant,
                room_id=room_id,
            )
            membership["status"] = (
                "accepted" if decision == "accept" else "declined"
            )
            membership["generation"] = 1
            membership["decided_at"] = timestamp
            room["generation"] += 1
            room["updated_at"] = timestamp
            _invalidate_current_query(room)
            _supersede_room_challenges(candidate, room_id, timestamp)
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation=f"invitation_{decision}",
                actor=participant,
                room_id=room_id,
                result_kind="membership",
                result_id=participant,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return {
                **_membership_result(room, participant),
                **self._rollback_truth(),
            }

    def cancel_invitation(
        self,
        *,
        room_id: str,
        creator_address: str,
        invitee_address: str,
        idempotency_key: str,
        cancelled_at: int,
    ) -> dict[str, Any]:
        """Let the creator explicitly cancel one still-pending invitation."""

        room_id = _room_id(room_id)
        creator = _wallet(creator_address)
        invitee = _wallet(invitee_address)
        idem = _idempotency_key(idempotency_key)
        timestamp = _timestamp(cancelled_at)
        request = {
            "room_id": room_id,
            "creator_address": creator,
            "invitee_address": invitee,
        }
        idem_id = _idempotency_id(
            operation="cancel_invitation",
            actor=creator,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            room = _room(candidate, room_id)
            _require_active_room(room)
            if room["creator_address"] != creator:
                raise CollaborationAuthorizationError(
                    "Only the room creator may cancel an invitation"
                )
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                return {
                    **_membership_result(room, invitee),
                    **self._rollback_truth(),
                }
            membership = room["memberships"].get(invitee)
            if membership is None or membership["status"] != "invited":
                raise CollaborationConflictError(
                    "Collaboration invitation is no longer pending"
                )
            _require_idempotency_capacity(
                candidate,
                actor=creator,
                room_id=room_id,
            )
            membership["status"] = "cancelled"
            membership["generation"] = 1
            membership["decided_at"] = timestamp
            room["generation"] += 1
            room["updated_at"] = timestamp
            _invalidate_current_query(room)
            _supersede_room_challenges(candidate, room_id, timestamp)
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation="cancel_invitation",
                actor=creator,
                room_id=room_id,
                result_kind="membership",
                result_id=invitee,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return {
                **_membership_result(room, invitee),
                **self._rollback_truth(),
            }

    def archive_room(
        self,
        *,
        room_id: str,
        creator_address: str,
        idempotency_key: str,
        archived_at: int,
    ) -> dict[str, Any]:
        """Explicitly close a quiescent room before bounded reclamation."""

        room_id = _room_id(room_id)
        creator = _wallet(creator_address)
        idem = _idempotency_key(idempotency_key)
        timestamp = _timestamp(archived_at)
        request = {
            "room_id": room_id,
            "creator_address": creator,
        }
        idem_id = _idempotency_id(
            operation="archive_room",
            actor=creator,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            room = _room(candidate, room_id)
            if room["creator_address"] != creator:
                raise CollaborationAuthorizationError(
                    "Only the room creator may archive this room"
                )
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                return self._room_projection_from_state(
                    candidate,
                    room_id,
                    creator,
                )
            _require_active_room(room)
            if any(
                membership["status"] == "invited"
                for membership in room["memberships"].values()
            ):
                raise CollaborationConflictError(
                    "Pending invitations must be accepted, declined, or "
                    "explicitly cancelled before archival"
                )
            if any(
                consent["status"] == "active"
                for consent in room["role_consents"].values()
            ):
                raise CollaborationConflictError(
                    "Every active owner role must be revoked before archival"
                )
            query = room["current_query"]
            if query is not None and any(
                grant["status"] == "approved"
                for grant in query["grants"].values()
            ):
                raise CollaborationConflictError(
                    "Every active query grant must be revoked or invalidated "
                    "before archival"
                )
            if any(
                run["room_id"] == room_id
                and run["reclaimable_after"] > timestamp
                for run in candidate["runs"].values()
            ):
                raise CollaborationConflictError(
                    "A retained joint-consent snapshot blocks archival"
                )
            _require_idempotency_capacity(
                candidate,
                actor=creator,
                room_id=room_id,
            )
            _invalidate_current_query(room)
            _supersede_room_challenges(candidate, room_id, timestamp)
            room["generation"] += 1
            room["updated_at"] = timestamp
            room["lifecycle_status"] = "archived"
            room["archived_at"] = timestamp
            room["reclaimable_after"] = (
                timestamp + ROOM_ARCHIVE_RETENTION_SECONDS
            )
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation="archive_room",
                actor=creator,
                room_id=room_id,
                result_kind="room",
                result_id=room_id,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return self._room_projection_from_state(
                candidate,
                room_id,
                creator,
            )

    def issue_consent_challenge(
        self,
        *,
        room_id: str,
        owner_address: str,
        decision: str,
        issued_at: int,
        expires_at: int,
        challenge_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue an exact owner-role activation/revocation challenge."""

        room_id = _room_id(room_id)
        owner = _wallet(owner_address)
        decision = _role_decision(decision)
        issued, expiry = _challenge_times(issued_at, expires_at)
        challenge_id = (
            _challenge_id(challenge_id)
            if challenge_id is not None
            else f"consent_{secrets.token_hex(16)}"
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=issued)
            room = _room(candidate, room_id)
            _require_active_room(room)
            _require_accepted_participant(room, owner)
            if owner not in room["role_consents"]:
                raise CollaborationAuthorizationError(
                    "Wallet is not a consent owner for this room"
                )
            if challenge_id in candidate["challenges"]:
                raise CollaborationConflictError(
                    "Consent challenge already exists"
                )
            _require_challenge_capacity(
                candidate,
                owner=owner,
                room_id=room_id,
            )
            state_commitment = _room_state_commitment(room)
            message = _role_consent_message(
                room=room,
                owner=owner,
                decision=decision,
                challenge_id=challenge_id,
                state_commitment=state_commitment,
                issued_at=issued,
                expires_at=expiry,
            )
            challenge_commitment = _hash_json(
                "dnai-wikigen/collaboration-role-consent-challenge/v2",
                {
                    "challenge_id": challenge_id,
                    "room_id": room_id,
                    "owner_address": owner,
                    "decision": decision,
                    "room_commitment": room["room_commitment"],
                    "room_generation": room["generation"],
                    "room_state_commitment": state_commitment,
                    "message_sha256": _hash_text(
                        "dnai-wikigen/collaboration-role-consent-message/v2",
                        message,
                    ),
                    "issued_at": issued,
                    "expires_at": expiry,
                },
            )
            for previous in candidate["challenges"].values():
                if (
                    previous["room_id"] == room_id
                    and previous["owner_address"] == owner
                    and previous["status"] == "pending"
                ):
                    previous["status"] = "superseded"
                    previous["updated_at"] = issued
            candidate["challenges"][challenge_id] = {
                "challenge_id": challenge_id,
                "room_id": room_id,
                "owner_address": owner,
                "decision": decision,
                "room_commitment": room["room_commitment"],
                "room_generation": room["generation"],
                "room_state_commitment": state_commitment,
                "challenge_commitment": challenge_commitment,
                "message": message,
                "issued_at": issued,
                "expires_at": expiry,
                "status": "pending",
                "authorization_hash": "",
                "consumed_at": 0,
                "updated_at": issued,
            }
            self._commit_locked(candidate)
            return self._challenge_projection_from_state(
                candidate,
                challenge_id,
                owner,
                now=issued,
            )

    def challenge_projection(
        self,
        challenge_id: str,
        participant_address: str,
        *,
        now: int,
    ) -> dict[str, Any]:
        with self._locked():
            return self._challenge_projection_from_state(
                self._load_locked(),
                _challenge_id(challenge_id),
                _wallet(participant_address),
                now=_timestamp(now),
            )

    def consume_verified_consent(
        self,
        *,
        challenge_id: str,
        owner_address: str,
        decision: str,
        authorization_hash: str,
        verifier_confirmed: bool,
        consumed_at: int,
    ) -> dict[str, Any]:
        """Consume a role signature, with exact lost-response replay safety."""

        challenge_id = _challenge_id(challenge_id)
        owner = _wallet(owner_address)
        decision = _role_decision(decision)
        authorization = _commitment(
            authorization_hash,
            "authorization_hash",
        )
        consumed = _timestamp(consumed_at)
        if verifier_confirmed is not True:
            raise CollaborationAuthorizationError(
                "Consent signature must be verifier-confirmed"
            )
        with self._locked():
            state = self._load_locked()
            challenge = _challenge(state, challenge_id)
            if challenge["status"] == "consumed":
                if (
                    challenge["owner_address"] == owner
                    and challenge["decision"] == decision
                    and challenge["authorization_hash"] == authorization
                ):
                    return self._room_projection_from_state(
                        state,
                        challenge["room_id"],
                        owner,
                    )
                raise CollaborationConflictError(
                    "Consumed consent challenge replay does not match"
                )
            if challenge["status"] != "pending":
                raise CollaborationConflictError(
                    "Consent challenge is not pending"
                )
            if consumed < challenge["issued_at"]:
                raise CollaborationStoreError(
                    "Consent consumption time precedes issuance"
                )
            if consumed >= challenge["expires_at"]:
                raise CollaborationConflictError("Consent challenge expired")
            if (
                challenge["owner_address"] != owner
                or challenge["decision"] != decision
            ):
                raise CollaborationAuthorizationError(
                    "Consent signature does not match the requested owner action"
                )
            room = _room(state, challenge["room_id"])
            _require_active_room(room)
            _require_accepted_participant(room, owner)
            if owner not in room["role_consents"]:
                raise CollaborationAuthorizationError(
                    "Wallet is not a consent owner for this room"
                )
            if (
                room["room_commitment"] != challenge["room_commitment"]
                or room["generation"] != challenge["room_generation"]
                or _room_state_commitment(room)
                != challenge["room_state_commitment"]
            ):
                raise CollaborationConflictError(
                    "Consent challenge is stale for the current room state"
                )
            candidate, _ = _compact_reclaimable(state, now=consumed)
            next_room = candidate["rooms"][room["room_id"]]
            consent = next_room["role_consents"][owner]
            consent["status"] = (
                "active" if decision == "activate" else "revoked"
            )
            consent["generation"] += 1
            consent["authorization_hash"] = authorization
            consent["updated_at"] = consumed
            next_room["generation"] += 1
            next_room["updated_at"] = consumed
            _invalidate_current_query(next_room)
            next_challenge = candidate["challenges"][challenge_id]
            next_challenge["status"] = "consumed"
            next_challenge["authorization_hash"] = authorization
            next_challenge["consumed_at"] = consumed
            next_challenge["updated_at"] = consumed
            _supersede_room_challenges(
                candidate,
                room["room_id"],
                consumed,
                except_role_challenge=challenge_id,
            )
            self._commit_locked(candidate)
            return self._room_projection_from_state(
                candidate,
                room["room_id"],
                owner,
            )

    def propose_query(
        self,
        *,
        room_id: str,
        query_ref: str,
        proposer_address: str,
        idempotency_key: str,
        proposed_at: int,
    ) -> dict[str, Any]:
        """Replace the current query and invalidate every prior query grant."""

        room_id = _room_id(room_id)
        query_ref = _commitment(query_ref, "query_ref")
        proposer = _wallet(proposer_address)
        idem = _idempotency_key(idempotency_key)
        timestamp = _timestamp(proposed_at)
        request = {
            "room_id": room_id,
            "query_ref": query_ref,
            "proposer_address": proposer,
        }
        idem_id = _idempotency_id(
            operation="propose_query",
            actor=proposer,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            room = _room(candidate, room_id)
            _require_active_room(room)
            _require_accepted_participant(room, proposer)
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                current = room["current_query"]
                if (
                    current is None
                    or current["proposal_commitment"] != existing["result_id"]
                ):
                    raise CollaborationConflictError(
                        "Idempotent query proposal is no longer current"
                    )
                return self._query_projection(room)
            if not _all_required_roles_active(room):
                raise CollaborationConflictError(
                    "Every required owner must accept membership and activate "
                    "its role before a query can be proposed"
                )
            _require_idempotency_capacity(
                candidate,
                actor=proposer,
                room_id=room_id,
            )
            room["generation"] += 1
            room["updated_at"] = timestamp
            allocation_commitment = collaboration_allocation_commitment(
                room_id=room_id,
                query_ref=query_ref,
                room_commitment=room["room_commitment"],
                owner_allocations_bps=room["owner_allocations_bps"],
            )
            proposal = {
                "query_ref": query_ref,
                "proposer_address": proposer,
                "room_generation": room["generation"],
                "allocation_commitment": allocation_commitment,
                "proposed_at": timestamp,
            }
            proposal_commitment = _hash_json(
                "dnai-wikigen/collaboration-query-proposal/v2",
                {
                    **proposal,
                    "room_id": room_id,
                    "room_commitment": room["room_commitment"],
                    "owner_policy_commitments": room[
                        "corpus_policy_commitments"
                    ],
                },
            )
            room["current_query"] = {
                **proposal,
                "proposal_commitment": proposal_commitment,
                "grants": {
                    owner: {
                        "status": "pending",
                        "generation": 0,
                        "authorization_hash": "",
                        "updated_at": timestamp,
                    }
                    for owner in room["owner_allocations_bps"]
                },
            }
            _supersede_room_challenges(candidate, room_id, timestamp)
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation="propose_query",
                actor=proposer,
                room_id=room_id,
                result_kind="query",
                result_id=proposal_commitment,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return self._query_projection(room)

    def issue_query_grant_challenge(
        self,
        *,
        room_id: str,
        owner_address: str,
        decision: str,
        issued_at: int,
        expires_at: int,
        challenge_id: str | None = None,
    ) -> dict[str, Any]:
        """Issue an owner signature challenge for the exact current query."""

        room_id = _room_id(room_id)
        owner = _wallet(owner_address)
        decision = _query_decision(decision)
        issued, expiry = _challenge_times(issued_at, expires_at)
        challenge_id = (
            _query_challenge_id(challenge_id)
            if challenge_id is not None
            else f"qgrant_{secrets.token_hex(16)}"
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=issued)
            room = _room(candidate, room_id)
            _require_active_room(room)
            _require_accepted_participant(room, owner)
            if owner not in room["role_consents"]:
                raise CollaborationAuthorizationError(
                    "Wallet is not a query-grant owner for this room"
                )
            if not _owner_role_active(room, owner):
                raise CollaborationConflictError(
                    "Owner role must be active before query approval"
                )
            query = room["current_query"]
            if query is None or not _query_proposal_current(room):
                raise CollaborationConflictError(
                    "Room does not have a current query proposal"
                )
            if challenge_id in candidate["query_challenges"]:
                raise CollaborationConflictError(
                    "Query-grant challenge already exists"
                )
            _require_challenge_capacity(
                candidate,
                owner=owner,
                room_id=room_id,
            )
            message = _query_grant_message(
                room=room,
                query=query,
                owner=owner,
                decision=decision,
                challenge_id=challenge_id,
                issued_at=issued,
                expires_at=expiry,
            )
            challenge_commitment = _hash_json(
                "dnai-wikigen/collaboration-query-grant-challenge/v2",
                {
                    "challenge_id": challenge_id,
                    "room_id": room_id,
                    "owner_address": owner,
                    "decision": decision,
                    "room_commitment": room["room_commitment"],
                    "room_generation": room["generation"],
                    "query_ref": query["query_ref"],
                    "proposal_commitment": query["proposal_commitment"],
                    "allocation_commitment": query[
                        "allocation_commitment"
                    ],
                    "owner_policy_commitment": room[
                        "corpus_policy_commitments"
                    ][owner],
                    "message_sha256": _hash_text(
                        "dnai-wikigen/collaboration-query-grant-message/v2",
                        message,
                    ),
                    "issued_at": issued,
                    "expires_at": expiry,
                },
            )
            for previous in candidate["query_challenges"].values():
                if (
                    previous["room_id"] == room_id
                    and previous["owner_address"] == owner
                    and previous["status"] == "pending"
                ):
                    previous["status"] = "superseded"
                    previous["updated_at"] = issued
            candidate["query_challenges"][challenge_id] = {
                "challenge_id": challenge_id,
                "room_id": room_id,
                "owner_address": owner,
                "decision": decision,
                "room_commitment": room["room_commitment"],
                "room_generation": room["generation"],
                "query_ref": query["query_ref"],
                "proposal_commitment": query["proposal_commitment"],
                "allocation_commitment": query["allocation_commitment"],
                "owner_policy_commitment": room[
                    "corpus_policy_commitments"
                ][owner],
                "challenge_commitment": challenge_commitment,
                "message": message,
                "issued_at": issued,
                "expires_at": expiry,
                "status": "pending",
                "authorization_hash": "",
                "consumed_at": 0,
                "updated_at": issued,
            }
            self._commit_locked(candidate)
            return self._query_challenge_projection_from_state(
                candidate,
                challenge_id,
                owner,
                now=issued,
            )

    def query_grant_challenge_projection(
        self,
        challenge_id: str,
        participant_address: str,
        *,
        now: int,
    ) -> dict[str, Any]:
        with self._locked():
            return self._query_challenge_projection_from_state(
                self._load_locked(),
                _query_challenge_id(challenge_id),
                _wallet(participant_address),
                now=_timestamp(now),
            )

    def consume_verified_query_grant(
        self,
        *,
        challenge_id: str,
        owner_address: str,
        decision: str,
        authorization_hash: str,
        verifier_confirmed: bool,
        consumed_at: int,
    ) -> dict[str, Any]:
        """Consume a query signature, with exact lost-response replay safety."""

        challenge_id = _query_challenge_id(challenge_id)
        owner = _wallet(owner_address)
        decision = _query_decision(decision)
        authorization = _commitment(
            authorization_hash,
            "authorization_hash",
        )
        consumed = _timestamp(consumed_at)
        if verifier_confirmed is not True:
            raise CollaborationAuthorizationError(
                "Query-grant signature must be verifier-confirmed"
            )
        with self._locked():
            state = self._load_locked()
            challenge = _query_challenge(state, challenge_id)
            if challenge["status"] == "consumed":
                if (
                    challenge["owner_address"] == owner
                    and challenge["decision"] == decision
                    and challenge["authorization_hash"] == authorization
                ):
                    room = _room(state, challenge["room_id"])
                    _require_visible(room, owner)
                    return self._query_projection(room)
                raise CollaborationConflictError(
                    "Consumed query-grant challenge replay does not match"
                )
            if challenge["status"] != "pending":
                raise CollaborationConflictError(
                    "Query-grant challenge is not pending"
                )
            if consumed < challenge["issued_at"]:
                raise CollaborationStoreError(
                    "Query-grant consumption time precedes issuance"
                )
            if consumed >= challenge["expires_at"]:
                raise CollaborationConflictError(
                    "Query-grant challenge expired"
                )
            if (
                challenge["owner_address"] != owner
                or challenge["decision"] != decision
            ):
                raise CollaborationAuthorizationError(
                    "Query-grant signature does not match the requested action"
                )
            room = _room(state, challenge["room_id"])
            _require_active_room(room)
            _require_accepted_participant(room, owner)
            if not _owner_role_active(room, owner):
                raise CollaborationConflictError(
                    "Owner role is no longer active"
                )
            query = room["current_query"]
            if (
                query is None
                or not _query_proposal_current(room)
                or challenge["room_commitment"] != room["room_commitment"]
                or challenge["room_generation"] != room["generation"]
                or challenge["query_ref"] != query["query_ref"]
                or challenge["proposal_commitment"]
                != query["proposal_commitment"]
                or challenge["allocation_commitment"]
                != query["allocation_commitment"]
                or challenge["owner_policy_commitment"]
                != room["corpus_policy_commitments"][owner]
            ):
                raise CollaborationConflictError(
                    "Query-grant challenge is stale for the current proposal"
                )
            candidate, _ = _compact_reclaimable(state, now=consumed)
            next_room = candidate["rooms"][room["room_id"]]
            grant = next_room["current_query"]["grants"][owner]
            grant["status"] = (
                "approved" if decision == "approve" else "revoked"
            )
            grant["generation"] += 1
            grant["authorization_hash"] = authorization
            grant["updated_at"] = consumed
            next_room["updated_at"] = consumed
            next_challenge = candidate["query_challenges"][challenge_id]
            next_challenge["status"] = "consumed"
            next_challenge["authorization_hash"] = authorization
            next_challenge["consumed_at"] = consumed
            next_challenge["updated_at"] = consumed
            for other_id, other in candidate["query_challenges"].items():
                if (
                    other_id != challenge_id
                    and other["room_id"] == room["room_id"]
                    and other["owner_address"] == owner
                    and other["status"] == "pending"
                ):
                    other["status"] = "superseded"
                    other["updated_at"] = consumed
            self._commit_locked(candidate)
            return self._query_projection(next_room)

    def authorize_joint_run(
        self,
        *,
        room_id: str,
        query_ref: str,
        requester_address: str,
        idempotency_key: str,
        authorized_at: int,
    ) -> dict[str, Any]:
        """Record one bounded, exact-query joint-consent snapshot.

        The receipt is not execution authority and does not dispatch work.
        """

        room_id = _room_id(room_id)
        query_ref = _commitment(query_ref, "query_ref")
        requester = _wallet(requester_address)
        idem = _idempotency_key(idempotency_key)
        timestamp = _timestamp(authorized_at)
        request = {
            "room_id": room_id,
            "query_ref": query_ref,
            "requester_address": requester,
        }
        idem_id = _idempotency_id(
            operation="record_joint_consent_snapshot",
            actor=requester,
            room_id=room_id,
            key=idem,
        )
        with self._locked():
            state = self._load_locked()
            candidate, _ = _compact_reclaimable(state, now=timestamp)
            room = _room(candidate, room_id)
            _require_active_room(room)
            _require_accepted_participant(room, requester)
            existing = candidate["idempotency"].get(idem_id)
            if existing is not None:
                _require_idempotent_request(existing, request)
                return self._run_projection_from_state(
                    candidate,
                    existing["result_id"],
                    requester,
                )
            query = room["current_query"]
            if (
                query is None
                or query["query_ref"] != query_ref
                or not _all_required_query_grants_current(room)
            ):
                raise CollaborationConflictError(
                    "Exact current query lacks every required owner approval"
                )
            _require_run_capacity(
                candidate,
                requester=requester,
                room_id=room_id,
            )
            _require_idempotency_capacity(
                candidate,
                actor=requester,
                room_id=room_id,
            )
            run_id = f"run_{secrets.token_hex(16)}"
            state_commitment = _room_state_commitment(room)
            query_grant_set_commitment = _hash_json(
                "dnai-wikigen/collaboration-query-grant-set/v2",
                {
                    "room_id": room_id,
                    "room_generation": room["generation"],
                    "query_ref": query_ref,
                    "proposal_commitment": query["proposal_commitment"],
                    "grants": {
                        owner: {
                            "generation": grant["generation"],
                            "authorization_hash": grant[
                                "authorization_hash"
                            ],
                        }
                        for owner, grant in sorted(
                            query["grants"].items()
                        )
                    },
                },
            )
            snapshot_commitment = _hash_json(
                "dnai-wikigen/collaboration-joint-consent-snapshot/v2",
                {
                    "run_id": run_id,
                    "room_id": room_id,
                    "query_ref": query_ref,
                    "requester_address": requester,
                    "room_commitment": room["room_commitment"],
                    "room_generation": room["generation"],
                    "room_state_commitment": state_commitment,
                    "query_proposal_commitment": query[
                        "proposal_commitment"
                    ],
                    "query_grant_set_commitment": (
                        query_grant_set_commitment
                    ),
                    "allocation_commitment": query[
                        "allocation_commitment"
                    ],
                    "recorded_at": timestamp,
                },
            )
            run = {
                "run_id": run_id,
                "room_id": room_id,
                "query_ref": query_ref,
                "requester_address": requester,
                "room_commitment": room["room_commitment"],
                "room_generation": room["generation"],
                "room_state_commitment": state_commitment,
                "query_proposal_commitment": query[
                    "proposal_commitment"
                ],
                "query_grant_set_commitment": (
                    query_grant_set_commitment
                ),
                "allocation_commitment": query[
                    "allocation_commitment"
                ],
                "joint_consent_snapshot_commitment": snapshot_commitment,
                "recorded_at": timestamp,
                "reclaimable_after": timestamp + RUN_RETENTION_SECONDS,
                "execution_status": (
                    "joint_consent_snapshot_not_dispatched"
                ),
            }
            candidate["runs"][run_id] = run
            candidate["idempotency"][idem_id] = _idempotency_record(
                request=request,
                operation="record_joint_consent_snapshot",
                actor=requester,
                room_id=room_id,
                result_kind="run",
                result_id=run_id,
                created_at=timestamp,
            )
            self._commit_locked(candidate)
            return self._run_projection_from_state(
                candidate,
                run_id,
                requester,
            )

    def run_projection(
        self,
        run_id: str,
        participant_address: str,
    ) -> dict[str, Any]:
        with self._locked():
            return self._run_projection_from_state(
                self._load_locked(),
                _run_id(run_id),
                _wallet(participant_address),
            )

    def execution_authority_snapshot(
        self,
        run_id: str,
        participant_address: str,
    ) -> dict[str, Any]:
        """Return the exact current commitment-only execution authority.

        This is an in-process worker boundary, not a public projection.  It
        deliberately returns the per-owner query authorization commitments
        and allocation amounts needed to construct fresh one-shot execution
        grants while the Collaboration store lock is held.  Raw signatures,
        purpose material, policies, queries, and artifacts are never returned.
        """

        participant = _wallet(participant_address)
        with self._locked():
            state = self._load_locked()
            return self._execution_authority_snapshot_from_state(
                state,
                _run_id(run_id),
                participant,
            )

    def execution_authority_snapshot_by_commitment(
        self,
        joint_consent_snapshot_commitment: str,
        participant_address: str,
    ) -> dict[str, Any]:
        """Resolve one current run without accepting a caller-selected run ID."""

        commitment = _commitment(
            joint_consent_snapshot_commitment,
            "joint consent snapshot commitment",
        )
        participant = _wallet(participant_address)
        with self._locked():
            state = self._load_locked()
            matches = [
                run_id
                for run_id, run in state["runs"].items()
                if run["joint_consent_snapshot_commitment"] == commitment
            ]
            if len(matches) != 1:
                raise CollaborationNotFoundError(
                    "Collaboration execution authority was not found"
                )
            return self._execution_authority_snapshot_from_state(
                state,
                matches[0],
                participant,
            )

    def _execution_authority_snapshot_from_state(
        self,
        state: dict[str, Any],
        run_id: str,
        participant: str,
    ) -> dict[str, Any]:
            run = _run(state, run_id)
            room = _room(state, run["room_id"])
            _require_accepted_participant(room, participant)
            query = room["current_query"]
            current = (
                query is not None
                and _all_required_query_grants_current(room)
                and query["query_ref"] == run["query_ref"]
                and query["proposal_commitment"]
                == run["query_proposal_commitment"]
                and room["room_commitment"] == run["room_commitment"]
                and room["generation"] == run["room_generation"]
                and _room_state_commitment(room)
                == run["room_state_commitment"]
            )
            if not current:
                raise CollaborationConflictError(
                    "Joint-consent snapshot is no longer current"
                )
            return {
                "schema": "dnai.collaboration.execution-authority-snapshot.v1",
                "state_sequence": state["sequence"],
                "run_id": run["run_id"],
                "room_id": run["room_id"],
                "requester_address": run["requester_address"],
                "room_commitment": run["room_commitment"],
                "room_generation": run["room_generation"],
                "room_state_commitment": run["room_state_commitment"],
                "query_ref": run["query_ref"],
                "query_proposal_commitment": run[
                    "query_proposal_commitment"
                ],
                "prospective_query_grant_set_commitment": run[
                    "query_grant_set_commitment"
                ],
                "allocation_commitment": run["allocation_commitment"],
                "joint_consent_snapshot_commitment": run[
                    "joint_consent_snapshot_commitment"
                ],
                "owners": [
                    {
                        "owner_address": owner,
                        "allocation_bps": room["owner_allocations_bps"][owner],
                        "prospective_query_grant_authorization_hash": query[
                            "grants"
                        ][owner]["authorization_hash"],
                        "query_grant_generation": query["grants"][owner][
                            "generation"
                        ],
                        "role_consent_generation": room["role_consents"][owner][
                            "generation"
                        ],
                    }
                    for owner in sorted(room["owner_allocations_bps"])
                ],
                "current": True,
                "raw_signature_egress": False,
                "raw_query_egress": False,
                "raw_artifact_egress": False,
            }

    def reclaim(self, *, now: int) -> dict[str, Any]:
        """Deterministically compact only records past public retention."""

        timestamp = _timestamp(now)
        with self._locked():
            state = self._load_locked()
            candidate, reclaimed = _compact_reclaimable(
                state,
                now=timestamp,
            )
            if any(reclaimed.values()):
                self._commit_locked(candidate)
            return {
                "surface": "collaboration_reclamation",
                "schema_version": 2,
                "reclaimed": reclaimed,
                "pending_or_active_authority_pruned": False,
                **self._rollback_truth(),
            }

    def _room_projection_from_state(
        self,
        state: dict[str, Any],
        room_id: str,
        participant: str,
    ) -> dict[str, Any]:
        room = _room(state, room_id)
        _require_visible(room, participant)
        memberships = [
            {
                "member_address": member,
                "membership_status": membership["status"],
                "membership_generation": membership["generation"],
                "decision_recorded": membership["decided_at"] > 0,
            }
            for member, membership in sorted(
                room["memberships"].items()
            )
        ]
        accepted = [
            item["member_address"]
            for item in memberships
            if item["membership_status"] == "accepted"
        ]
        invited = [
            item["member_address"]
            for item in memberships
            if item["membership_status"] == "invited"
        ]
        declined = [
            item["member_address"]
            for item in memberships
            if item["membership_status"] == "declined"
        ]
        cancelled = [
            item["member_address"]
            for item in memberships
            if item["membership_status"] == "cancelled"
        ]
        return {
            "surface": "collaboration_room",
            "schema_version": 2,
            "room_id": room["room_id"],
            "creator_address": room["creator_address"],
            "declared_member_addresses": list(
                room["declared_member_addresses"]
            ),
            "accepted_member_addresses": accepted,
            "pending_invitation_addresses": invited,
            "declined_member_addresses": declined,
            "cancelled_invitation_addresses": cancelled,
            "memberships": memberships,
            "requester_membership_status": _membership_status(
                room,
                participant,
            ),
            "purpose_commitment": room["purpose_commitment"],
            "pipeline_commitment": room["pipeline_commitment"],
            "room_commitment": room["room_commitment"],
            "generation": room["generation"],
            "created_at": room["created_at"],
            "updated_at": room["updated_at"],
            "lifecycle_status": room["lifecycle_status"],
            "archived_at": room["archived_at"],
            "reclaimable_after": room["reclaimable_after"],
            "room_retention_policy": (
                "active_not_pruned"
                if room["lifecycle_status"] == "active"
                else "explicit_archive_then_bounded_reclamation"
            ),
            "owners": [
                {
                    "owner_address": owner,
                    "allocation_bps": room[
                        "owner_allocations_bps"
                    ][owner],
                    "corpus_policy_commitment": room[
                        "corpus_policy_commitments"
                    ][owner],
                    "membership_status": room["memberships"][owner][
                        "status"
                    ],
                    "role_consent_status": room[
                        "role_consents"
                    ][owner]["status"],
                    "role_consent_generation": room[
                        "role_consents"
                    ][owner]["generation"],
                    "role_authorization_hash_recorded": bool(
                        room["role_consents"][owner][
                            "authorization_hash"
                        ]
                    ),
                    "role_accepted": _owner_role_active(room, owner),
                }
                for owner in sorted(room["owner_allocations_bps"])
            ],
            "all_required_memberships_accepted": (
                _all_required_memberships_accepted(room)
            ),
            "all_required_roles_active": _all_required_roles_active(room),
            "current_query": (
                None
                if room["current_query"] is None
                else self._query_projection(room)
            ),
            "all_required_query_grants_current": (
                _all_required_query_grants_current(room)
            ),
            "membership_acceptance_mechanism": (
                "wallet_authenticated_invitation_response"
            ),
            "role_acceptance_mechanism": (
                "owner_role_consent_signature"
            ),
            "query_grant_mechanism": (
                "owner_signature_bound_to_current_query_v2"
            ),
            "participant_authenticated_projection": True,
            "raw_purpose_egress": False,
            "raw_policy_egress": False,
            "raw_signature_egress": False,
            "raw_artifact_egress": False,
            **self._rollback_truth(),
        }

    def _query_projection(self, room: dict[str, Any]) -> dict[str, Any]:
        query = room["current_query"]
        if query is None:
            raise CollaborationNotFoundError(
                "Collaboration query proposal was not found"
            )
        current = _query_proposal_current(room)
        return {
            "surface": "collaboration_query_proposal",
            "schema_version": 2,
            "room_id": room["room_id"],
            "query_ref": query["query_ref"],
            "proposer_address": query["proposer_address"],
            "room_commitment": room["room_commitment"],
            "room_generation": query["room_generation"],
            "proposal_commitment": query["proposal_commitment"],
            "allocation_commitment": query["allocation_commitment"],
            "proposed_at": query["proposed_at"],
            "proposal_current": current,
            "owner_query_grants": [
                {
                    "owner_address": owner,
                    "grant_status": grant["status"],
                    "grant_generation": grant["generation"],
                    "authorization_hash_recorded": bool(
                        grant["authorization_hash"]
                    ),
                }
                for owner, grant in sorted(query["grants"].items())
            ],
            "all_required_query_grants_current": (
                _all_required_query_grants_current(room)
            ),
            "raw_query_egress": False,
            "raw_policy_egress": False,
            "raw_signature_egress": False,
            **self._rollback_truth(),
        }

    def _challenge_projection_from_state(
        self,
        state: dict[str, Any],
        challenge_id: str,
        participant: str,
        *,
        now: int,
    ) -> dict[str, Any]:
        challenge = _challenge(state, challenge_id)
        room = _room(state, challenge["room_id"])
        _require_accepted_participant(room, participant)
        status_value = challenge["status"]
        if status_value == "pending" and now >= challenge["expires_at"]:
            status_value = "expired"
        return {
            "surface": "collaboration_role_consent_challenge",
            "schema_version": 2,
            "challenge_id": challenge["challenge_id"],
            "room_id": challenge["room_id"],
            "owner_address": challenge["owner_address"],
            "decision": challenge["decision"],
            "room_commitment": challenge["room_commitment"],
            "room_generation": challenge["room_generation"],
            "room_state_commitment": challenge[
                "room_state_commitment"
            ],
            "challenge_commitment": challenge[
                "challenge_commitment"
            ],
            "message": challenge["message"],
            "issued_at": challenge["issued_at"],
            "expires_at": challenge["expires_at"],
            "status": status_value,
            "authorization_hash_recorded": bool(
                challenge["authorization_hash"]
            ),
            "reclaimable_after": _challenge_reclaimable_after(challenge),
            "retention_policy": (
                "bounded_reclaimable_after_terminal_or_expiry"
            ),
            "participant_authenticated_projection": True,
            "raw_signature_egress": False,
            **self._rollback_truth(),
        }

    def _query_challenge_projection_from_state(
        self,
        state: dict[str, Any],
        challenge_id: str,
        participant: str,
        *,
        now: int,
    ) -> dict[str, Any]:
        challenge = _query_challenge(state, challenge_id)
        room = _room(state, challenge["room_id"])
        _require_accepted_participant(room, participant)
        status_value = challenge["status"]
        if status_value == "pending" and now >= challenge["expires_at"]:
            status_value = "expired"
        return {
            "surface": "collaboration_query_grant_challenge",
            "schema_version": 2,
            "challenge_id": challenge["challenge_id"],
            "room_id": challenge["room_id"],
            "owner_address": challenge["owner_address"],
            "decision": challenge["decision"],
            "room_commitment": challenge["room_commitment"],
            "room_generation": challenge["room_generation"],
            "query_ref": challenge["query_ref"],
            "proposal_commitment": challenge[
                "proposal_commitment"
            ],
            "allocation_commitment": challenge[
                "allocation_commitment"
            ],
            "owner_policy_commitment": challenge[
                "owner_policy_commitment"
            ],
            "challenge_commitment": challenge[
                "challenge_commitment"
            ],
            "message": challenge["message"],
            "issued_at": challenge["issued_at"],
            "expires_at": challenge["expires_at"],
            "status": status_value,
            "authorization_hash_recorded": bool(
                challenge["authorization_hash"]
            ),
            "reclaimable_after": _challenge_reclaimable_after(challenge),
            "retention_policy": (
                "bounded_reclaimable_after_terminal_or_expiry"
            ),
            "participant_authenticated_projection": True,
            "raw_signature_egress": False,
            **self._rollback_truth(),
        }

    def _run_projection_from_state(
        self,
        state: dict[str, Any],
        run_id: str,
        participant: str,
    ) -> dict[str, Any]:
        run = _run(state, run_id)
        room = _room(state, run["room_id"])
        _require_accepted_participant(room, participant)
        query = room["current_query"]
        current = (
            query is not None
            and _all_required_query_grants_current(room)
            and query["query_ref"] == run["query_ref"]
            and query["proposal_commitment"]
            == run["query_proposal_commitment"]
            and room["room_commitment"] == run["room_commitment"]
            and room["generation"] == run["room_generation"]
            and _room_state_commitment(room)
            == run["room_state_commitment"]
        )
        return {
            "surface": "collaboration_joint_consent_snapshot",
            "schema_version": 2,
            "run_id": run["run_id"],
            "room_id": run["room_id"],
            "query_ref": run["query_ref"],
            "requester_address": run["requester_address"],
            "room_commitment": run["room_commitment"],
            "room_generation": run["room_generation"],
            "room_state_commitment": run[
                "room_state_commitment"
            ],
            "query_proposal_commitment": run[
                "query_proposal_commitment"
            ],
            "query_grant_set_commitment": run[
                "query_grant_set_commitment"
            ],
            "allocation_commitment": run[
                "allocation_commitment"
            ],
            "joint_consent_snapshot_commitment": run[
                "joint_consent_snapshot_commitment"
            ],
            "recorded_at": run["recorded_at"],
            "execution_status": run["execution_status"],
            "consent_snapshot_current": current,
            "query_grants_current": current,
            "execution_authority": False,
            "provider_dispatch_performed": False,
            "tdx_attestation": False,
            "settlement_performed": False,
            "royalty_distribution_performed": False,
            "reclaimable_after": run["reclaimable_after"],
            "retention_policy": (
                "bounded_non_dispatched_snapshot_retention"
            ),
            "raw_purpose_egress": False,
            "raw_policy_egress": False,
            "raw_signature_egress": False,
            "raw_artifact_egress": False,
            **self._rollback_truth(),
        }

    def _encode_room_cursor(
        self,
        *,
        participant: str,
        sequence: int,
        created_at: int,
        room_id: str,
    ) -> str:
        payload = {
            "anchor_created_at": created_at,
            "anchor_room_id": room_id,
            "participant_address": participant,
            "snapshot_sequence": sequence,
            "version": 1,
        }
        encoded = _base64url(_canonical_json(payload))
        signature = hmac.new(
            self._integrity_key,
            b"dnai-wikigen/collaboration-room-list-cursor/v1\0"
            + encoded.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return f"collab_rooms_v1.{encoded}.{signature}"

    def _decode_room_cursor(self, cursor: Any) -> dict[str, Any]:
        if (
            not isinstance(cursor, str)
            or len(cursor.encode("utf-8")) > MAX_CURSOR_BYTES
            or _CURSOR.fullmatch(cursor) is None
        ):
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            )
        _, encoded, supplied = cursor.split(".")
        expected = hmac.new(
            self._integrity_key,
            b"dnai-wikigen/collaboration-room-list-cursor/v1\0"
            + encoded.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(supplied, expected):
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            )
        try:
            decoded = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
            payload = json.loads(decoded)
        except (
            binascii.Error,
            UnicodeDecodeError,
            json.JSONDecodeError,
            ValueError,
        ) as exc:
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            ) from exc
        expected_keys = {
            "anchor_created_at",
            "anchor_room_id",
            "participant_address",
            "snapshot_sequence",
            "version",
        }
        if not isinstance(payload, dict) or set(payload) != expected_keys:
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            )
        try:
            _timestamp(payload["anchor_created_at"])
            _room_id(payload["anchor_room_id"])
            _wallet(payload["participant_address"])
            _integer(
                payload["snapshot_sequence"],
                "cursor snapshot sequence",
                minimum=0,
            )
        except CollaborationStoreError as exc:
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            ) from exc
        if payload["version"] != 1:
            raise CollaborationConflictError(
                "Collaboration room cursor is invalid; restart listing"
            )
        return payload

    def _commit_locked(self, candidate: dict[str, Any]) -> None:
        candidate["sequence"] += 1
        _validate_state(candidate)
        self._persist_locked(candidate)

    def _load_locked(self) -> dict[str, Any]:
        return self._load_path_locked(self.path)

    def _load_path_locked(self, path: str | Path) -> dict[str, Any]:
        target = Path(path)
        try:
            info = target.lstat()
        except FileNotFoundError as exc:
            raise CollaborationStoreCorruptError(
                "Collaboration store disappeared"
            ) from exc
        if not stat.S_ISREG(info.st_mode):
            raise CollaborationStoreCorruptError(
                "Collaboration store must be a regular file"
            )
        if info.st_size <= 0 or info.st_size > MAX_STORE_BYTES:
            raise CollaborationStoreCorruptError(
                "Collaboration store size is invalid"
            )
        try:
            encoded = target.read_bytes()
            document = json.loads(encoded)
        except (
            OSError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
        ) as exc:
            raise CollaborationStoreCorruptError(
                "Collaboration store is not valid JSON"
            ) from exc
        if not isinstance(document, dict) or set(document) != {
            "surface",
            "schema_version",
            "payload",
            "integrity",
        }:
            raise CollaborationStoreCorruptError(
                "Collaboration store envelope is invalid"
            )
        if (
            document["surface"] != "collaboration_store"
            or document["schema_version"] != SCHEMA_VERSION
            or not isinstance(document["integrity"], dict)
            or set(document["integrity"]) != {"algorithm", "value"}
            or document["integrity"]["algorithm"] != "HMAC-SHA256"
            or not isinstance(document["integrity"]["value"], str)
            or _HMAC.fullmatch(document["integrity"]["value"]) is None
        ):
            raise CollaborationStoreCorruptError(
                "Collaboration store envelope is invalid"
            )
        payload = document["payload"]
        expected = hmac.new(
            self._integrity_key,
            _canonical_json(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(
            document["integrity"]["value"],
            expected,
        ):
            raise CollaborationStoreCorruptError(
                "Collaboration store integrity check failed"
            )
        try:
            _validate_state(payload)
        except CollaborationStoreError as exc:
            raise CollaborationStoreCorruptError(
                "Collaboration store payload is invalid"
            ) from exc
        return payload

    def _persist_locked(self, payload: dict[str, Any]) -> None:
        self._persist_path_locked(self.path, payload)

    def _persist_path_locked(
        self,
        path: str | Path,
        payload: dict[str, Any],
    ) -> None:
        target = Path(path)
        if target.parent != self.path.parent:
            raise CollaborationStoreCorruptError(
                "Collaboration store target left its authority directory"
            )
        _validate_state(payload)
        envelope = {
            "surface": "collaboration_store",
            "schema_version": SCHEMA_VERSION,
            "payload": payload,
            "integrity": {
                "algorithm": "HMAC-SHA256",
                "value": hmac.new(
                    self._integrity_key,
                    _canonical_json(payload),
                    hashlib.sha256,
                ).hexdigest(),
            },
        }
        encoded = _canonical_json(envelope) + b"\n"
        if len(encoded) > MAX_STORE_BYTES:
            raise CollaborationCapacityError(
                "Collaboration store exceeds its byte limit"
            )
        if target.exists() or target.is_symlink():
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise CollaborationStoreCorruptError(
                    "Collaboration store target must remain a regular file"
                )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.",
            suffix=".tmp",
            dir=target.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            _fsync_directory(target.parent)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _locked(self):
        return _FileLock(self._lock_path)

    def _rollback_truth(self) -> dict[str, Any]:
        return {
            "rollback_protection": False,
            "rollback_witness": {
                "schema": "dnai.collaboration-rollback-witness.v1",
                "mode": "local_hmac_current_state_non_monotonic",
                "monotonic": False,
                "authority_context_hash": None,
                "state_hash": None,
                "decision_hash": None,
                "anchor_sequence": None,
                "rollback_anchor": None,
                "opaque_commitments_only": True,
                "raw_room_egress": False,
                "raw_member_egress": False,
                "raw_query_egress": False,
            },
            "tamper_evident_current_state": True,
        }


class _FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor = -1

    def __enter__(self):
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self.descriptor = os.open(self.path, flags, 0o600)
        info = os.fstat(self.descriptor)
        if not stat.S_ISREG(info.st_mode):
            os.close(self.descriptor)
            self.descriptor = -1
            raise CollaborationStoreCorruptError(
                "Collaboration lock must be a regular file"
            )
        fcntl.flock(self.descriptor, fcntl.LOCK_EX)
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.descriptor >= 0:
            try:
                fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            finally:
                os.close(self.descriptor)
                self.descriptor = -1
        return False


def _empty_state() -> dict[str, Any]:
    return {
        "sequence": 0,
        "rooms": {},
        "challenges": {},
        "query_challenges": {},
        "runs": {},
        "idempotency": {},
    }


def _validate_state(state: Any) -> None:
    if not isinstance(state, dict) or set(state) != {
        "sequence",
        "rooms",
        "challenges",
        "query_challenges",
        "runs",
        "idempotency",
    }:
        raise CollaborationStoreError("Collaboration state shape is invalid")
    _integer(state["sequence"], "sequence", minimum=0)
    for key, maximum in (
        ("rooms", MAX_ROOMS),
        ("challenges", MAX_CHALLENGES),
        ("query_challenges", MAX_QUERY_CHALLENGES),
        ("runs", MAX_RUNS),
        ("idempotency", MAX_IDEMPOTENCY_RECORDS),
    ):
        if not isinstance(state[key], dict) or len(state[key]) > maximum:
            raise CollaborationStoreError(
                f"Collaboration {key} collection is invalid"
            )
    for room_id, room in state["rooms"].items():
        if _room_id(room_id) != room_id:
            raise CollaborationStoreError(
                "Stored room identifier is invalid"
            )
        _validate_room(room)
        if room["room_id"] != room_id:
            raise CollaborationStoreError(
                "Stored room key does not match"
            )
    for challenge_id, challenge in state["challenges"].items():
        if _challenge_id(challenge_id) != challenge_id:
            raise CollaborationStoreError(
                "Stored consent challenge identifier is invalid"
            )
        _validate_role_challenge(challenge)
        room = state["rooms"].get(challenge["room_id"])
        if (
            challenge["challenge_id"] != challenge_id
            or room is None
            or challenge["owner_address"]
            not in room["role_consents"]
        ):
            raise CollaborationStoreError(
                "Stored consent challenge binding is invalid"
            )
    for challenge_id, challenge in state["query_challenges"].items():
        if _query_challenge_id(challenge_id) != challenge_id:
            raise CollaborationStoreError(
                "Stored query-grant challenge identifier is invalid"
            )
        _validate_query_challenge(challenge)
        room = state["rooms"].get(challenge["room_id"])
        if (
            challenge["challenge_id"] != challenge_id
            or room is None
            or challenge["owner_address"]
            not in room["role_consents"]
        ):
            raise CollaborationStoreError(
                "Stored query-grant challenge binding is invalid"
            )
    for run_id, run in state["runs"].items():
        if _run_id(run_id) != run_id:
            raise CollaborationStoreError(
                "Stored run identifier is invalid"
            )
        _validate_run(run)
        if (
            run["run_id"] != run_id
            or run["room_id"] not in state["rooms"]
        ):
            raise CollaborationStoreError(
                "Stored run binding is invalid"
            )
    for idem_id, record in state["idempotency"].items():
        _commitment(idem_id, "idempotency identifier")
        _validate_idempotency_record(record)
        if record["room_id"] not in state["rooms"]:
            raise CollaborationStoreError(
                "Stored idempotency room is missing"
            )
        if (
            record["result_kind"] == "run"
            and record["result_id"] not in state["runs"]
        ):
            raise CollaborationStoreError(
                "Run idempotency result is missing"
            )


def _validate_room(room: Any) -> None:
    expected = {
        "room_id",
        "creator_address",
        "declared_member_addresses",
        "purpose_commitment",
        "pipeline_commitment",
        "corpus_policy_commitments",
        "owner_allocations_bps",
        "created_at",
        "room_commitment",
        "generation",
        "updated_at",
        "lifecycle_status",
        "archived_at",
        "reclaimable_after",
        "memberships",
        "role_consents",
        "current_query",
    }
    if not isinstance(room, dict) or set(room) != expected:
        raise CollaborationStoreError("Stored room shape is invalid")
    room_id = _room_id(room["room_id"])
    creator = _wallet(room["creator_address"])
    declarations = _member_list(
        room["declared_member_addresses"],
        creator=creator,
    )
    policies = _policy_map(room["corpus_policy_commitments"])
    allocations = _allocation_map(room["owner_allocations_bps"])
    if (
        set(policies) != set(allocations)
        or not set(allocations).issubset(declarations)
    ):
        raise CollaborationStoreError(
            "Stored room owner bindings are invalid"
        )
    memberships = room["memberships"]
    if (
        not isinstance(memberships, dict)
        or set(memberships) != set(declarations)
    ):
        raise CollaborationStoreError(
            "Stored room membership set is invalid"
        )
    for member, membership in memberships.items():
        _wallet(member)
        if not isinstance(membership, dict) or set(membership) != {
            "status",
            "generation",
            "decided_at",
        }:
            raise CollaborationStoreError(
                "Stored membership shape is invalid"
            )
        if membership["status"] not in {
            "invited",
            "accepted",
            "declined",
            "cancelled",
        }:
            raise CollaborationStoreError(
                "Stored membership status is invalid"
            )
        generation = _integer(
            membership["generation"],
            "membership generation",
            minimum=0,
            maximum=1,
        )
        decided_at = _timestamp(membership["decided_at"])
        if membership["status"] == "invited":
            if generation != 0 or decided_at != 0 or member == creator:
                raise CollaborationStoreError(
                    "Stored pending invitation state is invalid"
                )
        elif generation != 1 or decided_at == 0:
            raise CollaborationStoreError(
                "Stored decided membership state is invalid"
            )
    if memberships[creator]["status"] != "accepted":
        raise CollaborationStoreError(
            "Stored room creator membership is invalid"
        )
    consents = room["role_consents"]
    if (
        not isinstance(consents, dict)
        or set(consents) != set(allocations)
    ):
        raise CollaborationStoreError(
            "Stored room role-consent set is invalid"
        )
    for owner, consent in consents.items():
        _wallet(owner)
        _validate_authority_record(
            consent,
            allowed_statuses={"pending", "active", "revoked"},
            active_statuses={"active", "revoked"},
            label="role consent",
        )
        if (
            consent["status"] == "active"
            and memberships[owner]["status"] != "accepted"
        ):
            raise CollaborationStoreError(
                "Active owner role lacks accepted membership"
            )
    _commitment(room["purpose_commitment"], "purpose commitment")
    _commitment(room["pipeline_commitment"], "pipeline commitment")
    _commitment(room["room_commitment"], "room commitment")
    generation = _integer(
        room["generation"],
        "room generation",
        minimum=1,
    )
    created = _timestamp(room["created_at"])
    updated = _timestamp(room["updated_at"])
    lifecycle_status = room["lifecycle_status"]
    archived_at = _timestamp(room["archived_at"])
    reclaimable_after = _timestamp(room["reclaimable_after"])
    if lifecycle_status == "active":
        if archived_at != 0 or reclaimable_after != 0:
            raise CollaborationStoreError(
                "Active room retention state is invalid"
            )
    elif lifecycle_status == "archived":
        if (
            archived_at == 0
            or reclaimable_after
            != archived_at + ROOM_ARCHIVE_RETENTION_SECONDS
            or updated < archived_at
        ):
            raise CollaborationStoreError(
                "Archived room retention state is invalid"
            )
    else:
        raise CollaborationStoreError(
            "Stored room lifecycle status is invalid"
        )
    if lifecycle_status == "archived" and (
        any(
            membership["status"] == "invited"
            for membership in memberships.values()
        )
        or any(
            consent["status"] == "active"
            for consent in consents.values()
        )
        or room["current_query"] is not None
    ):
        raise CollaborationStoreError(
            "Archived room retains active or pending authority"
        )
    if updated < created:
        raise CollaborationStoreError(
            "Stored room timestamps are invalid"
        )
    immutable = {
        "room_id": room_id,
        "creator_address": creator,
        "declared_member_addresses": declarations,
        "purpose_commitment": room["purpose_commitment"],
        "pipeline_commitment": room["pipeline_commitment"],
        "corpus_policy_commitments": policies,
        "owner_allocations_bps": allocations,
        "created_at": created,
    }
    if room["room_commitment"] != _hash_json(
        "dnai-wikigen/collaboration-room/v2",
        immutable,
    ):
        raise CollaborationStoreError(
            "Stored room commitment is invalid"
        )
    if room["current_query"] is not None:
        _validate_query(room, generation=generation)


def _validate_query(room: dict[str, Any], *, generation: int) -> None:
    query = room["current_query"]
    expected = {
        "query_ref",
        "proposer_address",
        "room_generation",
        "allocation_commitment",
        "proposed_at",
        "proposal_commitment",
        "grants",
    }
    if not isinstance(query, dict) or set(query) != expected:
        raise CollaborationStoreError(
            "Stored query proposal shape is invalid"
        )
    _commitment(query["query_ref"], "query ref")
    proposer = _wallet(query["proposer_address"])
    if room["memberships"].get(proposer, {}).get("status") != "accepted":
        raise CollaborationStoreError(
            "Stored query proposer membership is invalid"
        )
    query_generation = _integer(
        query["room_generation"],
        "query room generation",
        minimum=1,
    )
    if query_generation > generation:
        raise CollaborationStoreError(
            "Stored query generation is invalid"
        )
    _commitment(
        query["allocation_commitment"],
        "query allocation commitment",
    )
    proposed_at = _timestamp(query["proposed_at"])
    _commitment(
        query["proposal_commitment"],
        "query proposal commitment",
    )
    grants = query["grants"]
    if (
        not isinstance(grants, dict)
        or set(grants) != set(room["owner_allocations_bps"])
    ):
        raise CollaborationStoreError(
            "Stored query grant set is invalid"
        )
    for owner, grant in grants.items():
        _wallet(owner)
        _validate_authority_record(
            grant,
            allowed_statuses={"pending", "approved", "revoked"},
            active_statuses={"approved", "revoked"},
            label="query grant",
        )
    expected_allocation = collaboration_allocation_commitment(
        room_id=room["room_id"],
        query_ref=query["query_ref"],
        room_commitment=room["room_commitment"],
        owner_allocations_bps=room["owner_allocations_bps"],
    )
    if query["allocation_commitment"] != expected_allocation:
        raise CollaborationStoreError(
            "Stored query allocation commitment is invalid"
        )
    proposal = {
        "query_ref": query["query_ref"],
        "proposer_address": proposer,
        "room_generation": query_generation,
        "allocation_commitment": query["allocation_commitment"],
        "proposed_at": proposed_at,
        "room_id": room["room_id"],
        "room_commitment": room["room_commitment"],
        "owner_policy_commitments": room[
            "corpus_policy_commitments"
        ],
    }
    if query["proposal_commitment"] != _hash_json(
        "dnai-wikigen/collaboration-query-proposal/v2",
        proposal,
    ):
        raise CollaborationStoreError(
            "Stored query proposal commitment is invalid"
        )


def _validate_authority_record(
    value: Any,
    *,
    allowed_statuses: set[str],
    active_statuses: set[str],
    label: str,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "status",
        "generation",
        "authorization_hash",
        "updated_at",
    }:
        raise CollaborationStoreError(
            f"Stored {label} shape is invalid"
        )
    if value["status"] not in allowed_statuses:
        raise CollaborationStoreError(
            f"Stored {label} status is invalid"
        )
    generation = _integer(
        value["generation"],
        f"{label} generation",
        minimum=0,
    )
    if generation == 0:
        if (
            value["status"] != "pending"
            or value["authorization_hash"] != ""
        ):
            raise CollaborationStoreError(
                f"Initial {label} state is invalid"
            )
    else:
        if value["status"] not in active_statuses:
            raise CollaborationStoreError(
                f"Decided {label} state is invalid"
            )
        _commitment(
            value["authorization_hash"],
            f"{label} authorization hash",
        )
    _timestamp(value["updated_at"])


def _validate_role_challenge(challenge: Any) -> None:
    expected = {
        "challenge_id",
        "room_id",
        "owner_address",
        "decision",
        "room_commitment",
        "room_generation",
        "room_state_commitment",
        "challenge_commitment",
        "message",
        "issued_at",
        "expires_at",
        "status",
        "authorization_hash",
        "consumed_at",
        "updated_at",
    }
    if not isinstance(challenge, dict) or set(challenge) != expected:
        raise CollaborationStoreError(
            "Stored consent challenge shape is invalid"
        )
    _challenge_id(challenge["challenge_id"])
    _room_id(challenge["room_id"])
    _wallet(challenge["owner_address"])
    _role_decision(challenge["decision"])
    for field in (
        "room_commitment",
        "room_state_commitment",
        "challenge_commitment",
    ):
        _commitment(challenge[field], field)
    _integer(
        challenge["room_generation"],
        "challenge room generation",
        minimum=1,
    )
    _validate_challenge_common(challenge)


def _validate_query_challenge(challenge: Any) -> None:
    expected = {
        "challenge_id",
        "room_id",
        "owner_address",
        "decision",
        "room_commitment",
        "room_generation",
        "query_ref",
        "proposal_commitment",
        "allocation_commitment",
        "owner_policy_commitment",
        "challenge_commitment",
        "message",
        "issued_at",
        "expires_at",
        "status",
        "authorization_hash",
        "consumed_at",
        "updated_at",
    }
    if not isinstance(challenge, dict) or set(challenge) != expected:
        raise CollaborationStoreError(
            "Stored query-grant challenge shape is invalid"
        )
    _query_challenge_id(challenge["challenge_id"])
    _room_id(challenge["room_id"])
    _wallet(challenge["owner_address"])
    _query_decision(challenge["decision"])
    for field in (
        "room_commitment",
        "query_ref",
        "proposal_commitment",
        "allocation_commitment",
        "owner_policy_commitment",
        "challenge_commitment",
    ):
        _commitment(challenge[field], field)
    _integer(
        challenge["room_generation"],
        "query challenge room generation",
        minimum=1,
    )
    _validate_challenge_common(challenge)


def _validate_challenge_common(challenge: dict[str, Any]) -> None:
    message = challenge["message"]
    if (
        not isinstance(message, str)
        or len(message) < 128
        or len(message.encode("utf-8")) > 4096
        or "\x00" in message
    ):
        raise CollaborationStoreError(
            "Stored challenge message is invalid"
        )
    issued = _timestamp(challenge["issued_at"])
    expires = _timestamp(challenge["expires_at"])
    if (
        expires <= issued
        or expires - issued > MAX_CONSENT_TTL_SECONDS
    ):
        raise CollaborationStoreError(
            "Stored challenge expiry is invalid"
        )
    if challenge["status"] not in {
        "pending",
        "consumed",
        "superseded",
    }:
        raise CollaborationStoreError(
            "Stored challenge status is invalid"
        )
    updated = _timestamp(challenge["updated_at"])
    if updated < issued:
        raise CollaborationStoreError(
            "Stored challenge update time is invalid"
        )
    if challenge["status"] == "consumed":
        _commitment(
            challenge["authorization_hash"],
            "challenge authorization hash",
        )
        consumed = _timestamp(challenge["consumed_at"])
        if consumed < issued or consumed != updated:
            raise CollaborationStoreError(
                "Stored challenge consumption time is invalid"
            )
    elif (
        challenge["authorization_hash"] != ""
        or challenge["consumed_at"] != 0
    ):
        raise CollaborationStoreError(
            "Unconsumed challenge contains authorization material"
        )


def _validate_run(run: Any) -> None:
    expected = {
        "run_id",
        "room_id",
        "query_ref",
        "requester_address",
        "room_commitment",
        "room_generation",
        "room_state_commitment",
        "query_proposal_commitment",
        "query_grant_set_commitment",
        "allocation_commitment",
        "joint_consent_snapshot_commitment",
        "recorded_at",
        "reclaimable_after",
        "execution_status",
    }
    if not isinstance(run, dict) or set(run) != expected:
        raise CollaborationStoreError(
            "Stored joint-consent snapshot shape is invalid"
        )
    _run_id(run["run_id"])
    _room_id(run["room_id"])
    _wallet(run["requester_address"])
    for field in (
        "query_ref",
        "room_commitment",
        "room_state_commitment",
        "query_proposal_commitment",
        "query_grant_set_commitment",
        "allocation_commitment",
        "joint_consent_snapshot_commitment",
    ):
        _commitment(run[field], field)
    _integer(
        run["room_generation"],
        "run room generation",
        minimum=1,
    )
    recorded = _timestamp(run["recorded_at"])
    reclaimable = _timestamp(run["reclaimable_after"])
    if reclaimable != recorded + RUN_RETENTION_SECONDS:
        raise CollaborationStoreError(
            "Stored run retention boundary is invalid"
        )
    if (
        run["execution_status"]
        != "joint_consent_snapshot_not_dispatched"
    ):
        raise CollaborationStoreError(
            "Stored run execution status is invalid"
        )


def _validate_idempotency_record(record: Any) -> None:
    expected = {
        "request_hash",
        "operation",
        "actor_address",
        "room_id",
        "result_kind",
        "result_id",
        "created_at",
        "expires_at",
    }
    if not isinstance(record, dict) or set(record) != expected:
        raise CollaborationStoreError(
            "Stored idempotency record is invalid"
        )
    _commitment(record["request_hash"], "idempotency request hash")
    if (
        not isinstance(record["operation"], str)
        or not record["operation"]
        or len(record["operation"]) > 64
    ):
        raise CollaborationStoreError(
            "Stored idempotency operation is invalid"
        )
    _wallet(record["actor_address"])
    _room_id(record["room_id"])
    if record["result_kind"] not in {
        "room",
        "membership",
        "query",
        "run",
    }:
        raise CollaborationStoreError(
            "Stored idempotency result kind is invalid"
        )
    if not isinstance(record["result_id"], str) or not record["result_id"]:
        raise CollaborationStoreError(
            "Stored idempotency result is invalid"
        )
    if record["result_kind"] == "room":
        _room_id(record["result_id"])
    elif record["result_kind"] == "membership":
        _wallet(record["result_id"])
    elif record["result_kind"] == "query":
        _commitment(record["result_id"], "query result commitment")
    else:
        _run_id(record["result_id"])
    created = _timestamp(record["created_at"])
    expires = _timestamp(record["expires_at"])
    if expires != created + IDEMPOTENCY_RETENTION_SECONDS:
        raise CollaborationStoreError(
            "Stored idempotency retention boundary is invalid"
        )


def _room_state_commitment(room: dict[str, Any]) -> str:
    query = room["current_query"]
    return _hash_json(
        "dnai-wikigen/collaboration-room-state/v2",
        {
            "room_id": room["room_id"],
            "room_commitment": room["room_commitment"],
            "generation": room["generation"],
            "memberships": {
                member: {
                    "status": membership["status"],
                    "generation": membership["generation"],
                }
                for member, membership in sorted(
                    room["memberships"].items()
                )
            },
            "role_consents": {
                owner: {
                    "status": consent["status"],
                    "generation": consent["generation"],
                    "authorization_hash": consent[
                        "authorization_hash"
                    ],
                }
                for owner, consent in sorted(
                    room["role_consents"].items()
                )
            },
            "current_query": (
                None
                if query is None
                else {
                    "query_ref": query["query_ref"],
                    "room_generation": query["room_generation"],
                    "proposal_commitment": query[
                        "proposal_commitment"
                    ],
                    "grants": {
                        owner: {
                            "status": grant["status"],
                            "generation": grant["generation"],
                            "authorization_hash": grant[
                                "authorization_hash"
                            ],
                        }
                        for owner, grant in sorted(
                            query["grants"].items()
                        )
                    },
                }
            ),
        },
    )


def _role_consent_message(
    *,
    room: dict[str, Any],
    owner: str,
    decision: str,
    challenge_id: str,
    state_commitment: str,
    issued_at: int,
    expires_at: int,
) -> str:
    verb = "activate" if decision == "activate" else "revoke"
    return (
        "www.wikigen.me wants you to sign in with your Ethereum account:\n"
        f"{owner}\n\n"
        f"{verb.capitalize()} this wallet's owner role for the specified "
        "multi-owner collaboration room. This does not approve any query. "
        "Each query requires a separate exact-query owner signature. This "
        "signature does not dispatch execution, settle funds, or transfer "
        "tokens.\n\n"
        "URI: https://www.wikigen.me\n"
        "Version: 2\n"
        "Chain ID: 84532\n"
        f"Nonce: {challenge_id.removeprefix('consent_')}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:collaboration:room:{room['room_id']}\n"
        f"- urn:dnai:collaboration:room-commitment:{room['room_commitment']}\n"
        f"- urn:dnai:collaboration:room-generation:{room['generation']}\n"
        f"- urn:dnai:collaboration:state:{state_commitment}\n"
        f"- urn:dnai:collaboration:owner-role:{decision}"
    )


def _query_grant_message(
    *,
    room: dict[str, Any],
    query: dict[str, Any],
    owner: str,
    decision: str,
    challenge_id: str,
    issued_at: int,
    expires_at: int,
) -> str:
    verb = "approve" if decision == "approve" else "revoke"
    return (
        "www.wikigen.me wants you to sign in with your Ethereum account:\n"
        f"{owner}\n\n"
        f"{verb.capitalize()} this wallet's grant for exactly the committed "
        "current query below. It cannot be inherited by another query. This "
        "signature records a prospective consent snapshot only; it does not "
        "dispatch execution, settle funds, or transfer tokens.\n\n"
        "URI: https://www.wikigen.me\n"
        "Version: 2\n"
        "Chain ID: 84532\n"
        f"Nonce: {challenge_id.removeprefix('qgrant_')}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}\n"
        "Resources:\n"
        f"- urn:dnai:collaboration:room:{room['room_id']}\n"
        f"- urn:dnai:collaboration:room-commitment:{room['room_commitment']}\n"
        f"- urn:dnai:collaboration:room-generation:{room['generation']}\n"
        f"- urn:dnai:collaboration:query:{query['query_ref']}\n"
        f"- urn:dnai:collaboration:query-proposal:{query['proposal_commitment']}\n"
        f"- urn:dnai:collaboration:owner-policy:"
        f"{room['corpus_policy_commitments'][owner]}\n"
        f"- urn:dnai:collaboration:allocation:"
        f"{query['allocation_commitment']}\n"
        f"- urn:dnai:collaboration:query-grant:{decision}"
    )


def _membership_result(
    room: dict[str, Any],
    participant: str,
) -> dict[str, Any]:
    membership = room["memberships"].get(participant)
    if membership is None:
        raise CollaborationAuthorizationError(
            "Wallet does not have a membership declaration in this room"
        )
    status_value = membership["status"]
    return {
        "surface": "collaboration_invitation_result",
        "schema_version": 2,
        "room_id": room["room_id"],
        "member_address": participant,
        "membership_status": status_value,
        "membership_generation": membership["generation"],
        "decision_recorded": status_value in {
            "accepted",
            "declined",
            "cancelled",
        },
        "visible_after_response": status_value == "accepted",
        "ordinary_participant_authority": status_value == "accepted",
        "room_generation": room["generation"],
        "room_state_commitment": _room_state_commitment(room),
        "raw_purpose_egress": False,
        "raw_policy_egress": False,
        "raw_signature_egress": False,
    }


def _idempotency_id(
    *,
    operation: str,
    actor: str,
    room_id: str,
    key: str,
) -> str:
    return _hash_json(
        "dnai-wikigen/collaboration-idempotency-key/v2",
        {
            "operation": operation,
            "actor": actor,
            "room_id": room_id,
            "key": key,
        },
    )


def _idempotency_record(
    *,
    request: dict[str, Any],
    operation: str,
    actor: str,
    room_id: str,
    result_kind: str,
    result_id: str,
    created_at: int,
) -> dict[str, Any]:
    return {
        "request_hash": _hash_json(
            "dnai-wikigen/collaboration-idempotent-request/v2",
            request,
        ),
        "operation": operation,
        "actor_address": actor,
        "room_id": room_id,
        "result_kind": result_kind,
        "result_id": result_id,
        "created_at": created_at,
        "expires_at": created_at + IDEMPOTENCY_RETENTION_SECONDS,
    }


def _require_idempotent_request(
    record: dict[str, Any],
    request: dict[str, Any],
) -> None:
    expected = _hash_json(
        "dnai-wikigen/collaboration-idempotent-request/v2",
        request,
    )
    if record["request_hash"] != expected:
        raise CollaborationConflictError(
            "Idempotency key was already used for a different request"
        )


def _compact_reclaimable(
    state: dict[str, Any],
    *,
    now: int,
) -> tuple[dict[str, Any], dict[str, int]]:
    candidate = copy.deepcopy(state)
    reclaimed = {
        "archived_rooms": 0,
        "role_consent_challenges": 0,
        "query_grant_challenges": 0,
        "joint_consent_snapshots": 0,
        "idempotency_records": 0,
    }
    for collection, label in (
        ("challenges", "role_consent_challenges"),
        ("query_challenges", "query_grant_challenges"),
    ):
        eligible = sorted(
            (
                (_challenge_reclaimable_after(item), item_id)
                for item_id, item in candidate[collection].items()
                if _challenge_reclaimable_after(item) <= now
            ),
        )
        for _, item_id in eligible:
            del candidate[collection][item_id]
            reclaimed[label] += 1
    removed_runs: set[str] = set()
    for _, run_id in sorted(
        (
            (run["reclaimable_after"], run_id)
            for run_id, run in candidate["runs"].items()
            if run["reclaimable_after"] <= now
        ),
    ):
        del candidate["runs"][run_id]
        removed_runs.add(run_id)
        reclaimed["joint_consent_snapshots"] += 1
    for _, idem_id in sorted(
        (
            (record["expires_at"], idem_id)
            for idem_id, record in candidate["idempotency"].items()
            if (
                record["expires_at"] <= now
                or (
                    record["result_kind"] == "run"
                    and record["result_id"] in removed_runs
                )
            )
        ),
    ):
        del candidate["idempotency"][idem_id]
        reclaimed["idempotency_records"] += 1
    for _, room_id in sorted(
        (
            (room["reclaimable_after"], room_id)
            for room_id, room in candidate["rooms"].items()
            if (
                room["lifecycle_status"] == "archived"
                and room["reclaimable_after"] <= now
                and _archived_room_safe_to_reclaim(
                    candidate,
                    room_id,
                    now=now,
                )
            )
        ),
    ):
        del candidate["rooms"][room_id]
        for collection, label in (
            ("challenges", "role_consent_challenges"),
            ("query_challenges", "query_grant_challenges"),
        ):
            for item_id in sorted(
                item_id
                for item_id, item in candidate[collection].items()
                if item["room_id"] == room_id
            ):
                del candidate[collection][item_id]
                reclaimed[label] += 1
        for idem_id in sorted(
            idem_id
            for idem_id, record in candidate["idempotency"].items()
            if record["room_id"] == room_id
        ):
            del candidate["idempotency"][idem_id]
            reclaimed["idempotency_records"] += 1
        reclaimed["archived_rooms"] += 1
    return candidate, reclaimed


def _challenge_reclaimable_after(challenge: dict[str, Any]) -> int:
    terminal_at = (
        challenge["expires_at"]
        if challenge["status"] == "pending"
        else challenge["updated_at"]
    )
    return terminal_at + CHALLENGE_RETENTION_SECONDS


def _archived_room_safe_to_reclaim(
    state: dict[str, Any],
    room_id: str,
    *,
    now: int,
) -> bool:
    room = state["rooms"][room_id]
    return (
        room["lifecycle_status"] == "archived"
        and not any(
            membership["status"] == "invited"
            for membership in room["memberships"].values()
        )
        and not any(
            consent["status"] == "active"
            for consent in room["role_consents"].values()
        )
        and room["current_query"] is None
        and not any(
            run["room_id"] == room_id
            and run["reclaimable_after"] > now
            for run in state["runs"].values()
        )
    )


def _supersede_room_challenges(
    state: dict[str, Any],
    room_id: str,
    timestamp: int,
    *,
    except_role_challenge: str = "",
    except_query_challenge: str = "",
) -> None:
    for challenge_id, challenge in state["challenges"].items():
        if (
            challenge_id != except_role_challenge
            and challenge["room_id"] == room_id
            and challenge["status"] == "pending"
        ):
            challenge["status"] = "superseded"
            challenge["updated_at"] = timestamp
    for challenge_id, challenge in state["query_challenges"].items():
        if (
            challenge_id != except_query_challenge
            and challenge["room_id"] == room_id
            and challenge["status"] == "pending"
        ):
            challenge["status"] = "superseded"
            challenge["updated_at"] = timestamp


def _invalidate_current_query(room: dict[str, Any]) -> None:
    room["current_query"] = None


def _require_challenge_capacity(
    state: dict[str, Any],
    *,
    owner: str,
    room_id: str,
) -> None:
    combined = list(state["challenges"].values()) + list(
        state["query_challenges"].values()
    )
    if (
        len(state["challenges"]) >= MAX_CHALLENGES
        or len(state["query_challenges"]) >= MAX_QUERY_CHALLENGES
    ):
        raise CollaborationCapacityError(
            "Collaboration challenge store is full"
        )
    if (
        sum(item["owner_address"] == owner for item in combined)
        >= MAX_CHALLENGES_PER_WALLET
    ):
        raise CollaborationCapacityError(
            "Collaboration challenge limit reached for this wallet"
        )
    if (
        sum(item["room_id"] == room_id for item in combined)
        >= MAX_CHALLENGES_PER_ROOM
    ):
        raise CollaborationCapacityError(
            "Collaboration challenge limit reached for this room"
        )


def _require_run_capacity(
    state: dict[str, Any],
    *,
    requester: str,
    room_id: str,
) -> None:
    runs = state["runs"].values()
    if len(state["runs"]) >= MAX_RUNS:
        raise CollaborationCapacityError(
            "Collaboration run store is full"
        )
    if (
        sum(item["requester_address"] == requester for item in runs)
        >= MAX_RUNS_PER_WALLET
    ):
        raise CollaborationCapacityError(
            "Collaboration run limit reached for this wallet"
        )
    if (
        sum(item["room_id"] == room_id for item in runs)
        >= MAX_RUNS_PER_ROOM
    ):
        raise CollaborationCapacityError(
            "Collaboration run limit reached for this room"
        )


def _require_idempotency_capacity(
    state: dict[str, Any],
    *,
    actor: str,
    room_id: str,
) -> None:
    records = state["idempotency"].values()
    if len(state["idempotency"]) >= MAX_IDEMPOTENCY_RECORDS:
        raise CollaborationCapacityError(
            "Collaboration idempotency store is full"
        )
    if (
        sum(item["actor_address"] == actor for item in records)
        >= MAX_IDEMPOTENCY_RECORDS_PER_WALLET
    ):
        raise CollaborationCapacityError(
            "Collaboration idempotency limit reached for this wallet"
        )
    if (
        sum(item["room_id"] == room_id for item in records)
        >= MAX_IDEMPOTENCY_RECORDS_PER_ROOM
    ):
        raise CollaborationCapacityError(
            "Collaboration idempotency limit reached for this room"
        )


def _all_required_memberships_accepted(room: dict[str, Any]) -> bool:
    return bool(room["owner_allocations_bps"]) and all(
        room["memberships"][owner]["status"] == "accepted"
        for owner in room["owner_allocations_bps"]
    )


def _owner_role_active(room: dict[str, Any], owner: str) -> bool:
    consent = room["role_consents"][owner]
    return (
        room["memberships"][owner]["status"] == "accepted"
        and consent["status"] == "active"
        and consent["generation"] > 0
        and bool(consent["authorization_hash"])
    )


def _all_required_roles_active(room: dict[str, Any]) -> bool:
    return _all_required_memberships_accepted(room) and all(
        _owner_role_active(room, owner)
        for owner in room["owner_allocations_bps"]
    )


def _query_proposal_current(room: dict[str, Any]) -> bool:
    query = room["current_query"]
    return (
        query is not None
        and query["room_generation"] == room["generation"]
        and _all_required_roles_active(room)
    )


def _all_required_query_grants_current(room: dict[str, Any]) -> bool:
    query = room["current_query"]
    return (
        query is not None
        and _query_proposal_current(room)
        and bool(query["grants"])
        and all(
            grant["status"] == "approved"
            and grant["generation"] > 0
            and bool(grant["authorization_hash"])
            for grant in query["grants"].values()
        )
    )


def _membership_status(room: dict[str, Any], member: str) -> str:
    membership = room["memberships"].get(member)
    return "" if membership is None else str(membership["status"])


def _rooms_created_by(state: dict[str, Any], creator: str) -> int:
    return sum(
        room["creator_address"] == creator
        and room["lifecycle_status"] == "active"
        for room in state["rooms"].values()
    )


def _accepted_room_count(state: dict[str, Any], member: str) -> int:
    return sum(
        _membership_status(room, member) == "accepted"
        and room["lifecycle_status"] == "active"
        for room in state["rooms"].values()
    )


def _pending_invite_count(state: dict[str, Any], member: str) -> int:
    return sum(
        _membership_status(room, member) == "invited"
        and room["lifecycle_status"] == "active"
        for room in state["rooms"].values()
    )


def _pending_invites_by_creator(
    state: dict[str, Any],
    creator: str,
) -> int:
    return sum(
        sum(
            membership["status"] == "invited"
            for membership in room["memberships"].values()
        )
        for room in state["rooms"].values()
        if (
            room["creator_address"] == creator
            and room["lifecycle_status"] == "active"
        )
    )


def _room(state: dict[str, Any], room_id: str) -> dict[str, Any]:
    room = state["rooms"].get(room_id)
    if room is None:
        raise CollaborationNotFoundError(
            "Collaboration room was not found"
        )
    return room


def _challenge(
    state: dict[str, Any],
    challenge_id: str,
) -> dict[str, Any]:
    challenge = state["challenges"].get(challenge_id)
    if challenge is None:
        raise CollaborationNotFoundError(
            "Collaboration consent challenge was not found"
        )
    return challenge


def _query_challenge(
    state: dict[str, Any],
    challenge_id: str,
) -> dict[str, Any]:
    challenge = state["query_challenges"].get(challenge_id)
    if challenge is None:
        raise CollaborationNotFoundError(
            "Collaboration query-grant challenge was not found"
        )
    return challenge


def _run(state: dict[str, Any], run_id: str) -> dict[str, Any]:
    run = state["runs"].get(run_id)
    if run is None:
        raise CollaborationNotFoundError(
            "Collaboration joint-consent snapshot was not found"
        )
    return run


def _require_visible(room: dict[str, Any], participant: str) -> None:
    if _membership_status(room, participant) not in {
        "accepted",
        "invited",
    }:
        raise CollaborationAuthorizationError(
            "Wallet cannot view this collaboration room"
        )


def _require_active_room(room: dict[str, Any]) -> None:
    if room["lifecycle_status"] != "active":
        raise CollaborationConflictError(
            "Collaboration room is archived"
        )


def _require_accepted_participant(
    room: dict[str, Any],
    participant: str,
) -> None:
    if _membership_status(room, participant) != "accepted":
        raise CollaborationAuthorizationError(
            "Wallet has not accepted membership in this collaboration room"
        )


def _member_list(
    value: list[str] | tuple[str, ...],
    *,
    creator: str,
) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise CollaborationStoreError(
            "Room member declarations must be a list"
        )
    normalized = [_wallet(item) for item in value]
    members = sorted(set(normalized) | {creator})
    if len(normalized) != len(set(normalized)):
        raise CollaborationStoreError(
            "Room member declarations contain a duplicate wallet"
        )
    if not members or len(members) > MAX_MEMBERS_PER_ROOM:
        raise CollaborationStoreError(
            "Room member declaration count is outside the supported range"
        )
    return members


def _policy_map(value: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise CollaborationStoreError(
            "Corpus policy commitments must be an owner map"
        )
    result = {
        _wallet(owner): _commitment(
            commitment,
            "corpus policy commitment",
        )
        for owner, commitment in value.items()
    }
    if (
        not result
        or len(result) > MAX_OWNERS_PER_ROOM
        or len(result) != len(value)
    ):
        raise CollaborationStoreError(
            "Corpus policy owner count is outside the supported range"
        )
    return dict(sorted(result.items()))


def _allocation_map(value: Mapping[str, int]) -> dict[str, int]:
    if not isinstance(value, Mapping):
        raise CollaborationStoreError(
            "Owner allocations must be an address-to-bps map"
        )
    result: dict[str, int] = {}
    for owner, raw_bps in value.items():
        normalized_owner = _wallet(owner)
        bps = _integer(
            raw_bps,
            "owner allocation bps",
            minimum=1,
            maximum=10_000,
        )
        if normalized_owner in result:
            raise CollaborationStoreError(
                "Owner allocations contain a duplicate wallet"
            )
        result[normalized_owner] = bps
    if not result or len(result) > MAX_OWNERS_PER_ROOM:
        raise CollaborationStoreError(
            "Owner allocation count is outside the supported range"
        )
    if sum(result.values()) != 10_000:
        raise CollaborationStoreError(
            "Owner allocation bps must sum to 10000"
        )
    return dict(sorted(result.items()))


def _challenge_times(issued_at: Any, expires_at: Any) -> tuple[int, int]:
    issued = _timestamp(issued_at)
    expiry = _timestamp(expires_at)
    if (
        expiry <= issued
        or expiry - issued > MAX_CONSENT_TTL_SECONDS
    ):
        raise CollaborationStoreError(
            "Challenge expiry is outside the supported range"
        )
    return issued, expiry


def _wallet(value: Any) -> str:
    if not isinstance(value, str):
        raise CollaborationStoreError("Wallet address is invalid")
    normalized = value.lower()
    if _ADDRESS.fullmatch(normalized) is None:
        raise CollaborationStoreError("Wallet address is invalid")
    return normalized


def _room_id(value: Any) -> str:
    if not isinstance(value, str) or _ROOM_ID.fullmatch(value) is None:
        raise CollaborationStoreError(
            "Collaboration room id is invalid"
        )
    return value


def _challenge_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _CHALLENGE_ID.fullmatch(value) is None
    ):
        raise CollaborationStoreError(
            "Collaboration consent challenge id is invalid"
        )
    return value


def _query_challenge_id(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _QUERY_CHALLENGE_ID.fullmatch(value) is None
    ):
        raise CollaborationStoreError(
            "Collaboration query-grant challenge id is invalid"
        )
    return value


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or _RUN_ID.fullmatch(value) is None:
        raise CollaborationStoreError(
            "Collaboration run id is invalid"
        )
    return value


def _idempotency_key(value: Any) -> str:
    if (
        not isinstance(value, str)
        or _IDEMPOTENCY_KEY.fullmatch(value) is None
    ):
        raise CollaborationStoreError(
            "Idempotency key is invalid"
        )
    return value


def _commitment(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256.fullmatch(value) is None
    ):
        raise CollaborationStoreError(f"{label} is invalid")
    return value


def _membership_decision(value: Any) -> str:
    if value not in {"accept", "decline"}:
        raise CollaborationStoreError(
            "Invitation decision must be accept or decline"
        )
    return str(value)


def _role_decision(value: Any) -> str:
    if value not in {"activate", "revoke"}:
        raise CollaborationStoreError(
            "Role consent decision must be activate or revoke"
        )
    return str(value)


def _query_decision(value: Any) -> str:
    if value not in {"approve", "revoke"}:
        raise CollaborationStoreError(
            "Query-grant decision must be approve or revoke"
        )
    return str(value)


def _timestamp(value: Any) -> int:
    return _integer(
        value,
        "timestamp",
        minimum=0,
        maximum=4_102_444_800,
    )


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int = 2**63 - 1,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > maximum
    ):
        raise CollaborationStoreError(f"{label} is invalid")
    return value


def _hash_json(domain: str, value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        domain.encode("utf-8") + b"\0" + _canonical_json(value)
    ).hexdigest()


def _hash_text(domain: str, value: str) -> str:
    return "sha256:" + hashlib.sha256(
        domain.encode("utf-8") + b"\0" + value.encode("utf-8")
    ).hexdigest()


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CollaborationStoreError(
            "Collaboration state is not canonical JSON"
        ) from exc


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
