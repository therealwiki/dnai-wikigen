"""Release-bound monotonic witness for Collaboration schema-v2 authority.

The Collaboration store remains a bounded HMAC-authenticated current-state
document. In a live dstack runtime this module additionally commits each exact
state to one release-context resource in ``ExecutionPolicyAnchor``. The anchor
records are conservative HOLD decisions: they are rollback witnesses only and
never authorize joint execution, provider dispatch, settlement, or data egress.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from tinker_delegate.collaboration_store import (
    CollaborationStore,
    CollaborationStoreCorruptError,
    _empty_state,
    _fsync_directory,
    _validate_state,
)
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.execution_policy_store import (
    ZERO_DECISION_HASH,
    execution_resource_hash,
)
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult
from tinker_delegate.wallet_signature_verifier import BASE_SEPOLIA_CHAIN_ID


ZERO_COLLABORATION_STATE_HASH = "0" * 64
COLLABORATION_ANCHOR_SURFACE = "collaboration_state"
COLLABORATION_ANCHOR_REASON = "collaboration_state_commitment"
COLLABORATION_ANCHOR_TTL_SECONDS = 30 * 24 * 60 * 60
COLLABORATION_AUTHORITY_CONTEXT_SCHEMA = (
    "dnai.collaboration-authority-context.v1"
)
COLLABORATION_ROLLBACK_WITNESS_SCHEMA = (
    "dnai.collaboration-rollback-witness.v1"
)
MAX_PUBLIC_ROLLBACK_ANCHOR_BYTES = 16 * 1024

_ROLLBACK_ANCHOR_KEYS = (
    "schema",
    "status",
    "verification_model",
    "chain_id",
    "block_number",
    "block_hash",
    "block_timestamp",
    "contract_address",
    "runtime_code_hash",
    "writer",
    "writer_release_commitment",
    "writer_rotations_frozen",
    "paused",
    "global_sequence",
    "global_head",
    "resource_id_hash",
    "resource_decision_head",
    "resource_sequence",
    "decision_hash",
    "decision_sequence",
    "latest_block_number",
    "rpc_finalized_block_number",
    "rpc_finalized_block_hash",
    "minimum_confirmation_depth",
    "observed_confirmation_depth",
    "independent_rpc_quorum_verified",
    "consensus_proof_verified",
    "opaque_commitments_only",
    "raw_resource_id_egress",
    "raw_policy_egress",
)

_HASH = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_ANY_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_CVM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")


class CollaborationAnchorError(RuntimeError):
    """The release-bound Collaboration witness is unavailable or inconsistent."""


class CollaborationRollbackError(CollaborationStoreCorruptError):
    """The local Collaboration state cannot be reconciled with its witness."""


@dataclass(frozen=True)
class CollaborationAnchorHead:
    authority_context_hash: str
    state_hash: str
    decision_hash: str
    sequence: int
    rollback_anchor: dict[str, Any]

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": COLLABORATION_ROLLBACK_WITNESS_SCHEMA,
            "mode": "base_sepolia_execution_policy_anchor",
            "monotonic": True,
            "authority_context_hash": self.authority_context_hash,
            "state_hash": self.state_hash,
            "decision_hash": self.decision_hash,
            "anchor_sequence": self.sequence,
            "rollback_anchor": _bounded_rollback_anchor(
                self.rollback_anchor
            ),
            "opaque_commitments_only": True,
            "raw_room_egress": False,
            "raw_member_egress": False,
            "raw_query_egress": False,
        }


class CollaborationRollbackAnchor(Protocol):
    def read_head(self, *, now: int) -> CollaborationAnchorHead: ...

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> CollaborationAnchorHead: ...


class ExecutionPolicyCollaborationAnchor:
    """Project Collaboration state into one release-bound anchor resource."""

    def __init__(
        self,
        coordinator: AnchoredExecutionPolicyCoordinator,
        *,
        authority_context_hash: str,
    ) -> None:
        if not isinstance(coordinator, AnchoredExecutionPolicyCoordinator):
            raise CollaborationAnchorError(
                "Collaboration requires the execution-policy anchor coordinator"
            )
        self.authority_context_hash = _required_hash(
            authority_context_hash,
            "Collaboration authority context",
            allow_zero=False,
        )
        if getattr(coordinator.gateway, "read_only", True) is not False:
            raise CollaborationAnchorError(
                "Collaboration rollback anchor is read-only"
            )
        self.coordinator = coordinator

    def read_head(self, *, now: int) -> CollaborationAnchorHead:
        try:
            records, snapshot = self.coordinator.history(
                surface=COLLABORATION_ANCHOR_SURFACE,
                resource_id=self.authority_context_hash,
                now=int(now),
            )
        except Exception:
            raise CollaborationAnchorError(
                "Collaboration rollback anchor is unavailable"
            ) from None
        bounded = snapshot.to_bounded_dict()
        if not records:
            return CollaborationAnchorHead(
                authority_context_hash=self.authority_context_hash,
                state_hash=ZERO_COLLABORATION_STATE_HASH,
                decision_hash=ZERO_DECISION_HASH,
                sequence=0,
                rollback_anchor=bounded,
            )
        previous_state_hash = ZERO_COLLABORATION_STATE_HASH
        previous_decision_hash = ZERO_DECISION_HASH
        previous_sequence = 0
        for record in records:
            if (
                record.get("surface") != COLLABORATION_ANCHOR_SURFACE
                or record.get("decision") != PolicyDecision.HOLD.value
                or record.get("reason_code") != COLLABORATION_ANCHOR_REASON
                or record.get("policy_hash") != self.authority_context_hash
                or record.get("execution_context_hash")
                != previous_state_hash
                or record.get("previous_decision_hash")
                != previous_decision_hash
                or not _bare_hash(record.get("request_hash"))
                or not _bare_hash(record.get("decision_hash"))
                or isinstance(record.get("sequence"), bool)
                or not isinstance(record.get("sequence"), int)
                or record["sequence"] <= previous_sequence
            ):
                raise CollaborationAnchorError(
                    "Collaboration rollback anchor history is invalid"
                )
            previous_state_hash = record["request_hash"]
            previous_decision_hash = record["decision_hash"]
            previous_sequence = record["sequence"]
        return CollaborationAnchorHead(
            authority_context_hash=self.authority_context_hash,
            state_hash=previous_state_hash,
            decision_hash=previous_decision_hash,
            sequence=previous_sequence,
            rollback_anchor=bounded,
        )

    def compare_and_set(
        self,
        *,
        expected_state_hash: str,
        new_state_hash: str,
        now: int,
    ) -> CollaborationAnchorHead:
        expected = _required_hash(
            expected_state_hash,
            "expected Collaboration state",
        )
        new = _required_hash(
            new_state_hash,
            "new Collaboration state",
            allow_zero=False,
        )
        if hmac.compare_digest(expected, new):
            raise CollaborationAnchorError("Collaboration state did not change")
        current = self.read_head(now=int(now))
        if not hmac.compare_digest(current.state_hash, expected):
            raise CollaborationAnchorError(
                "Collaboration rollback anchor CAS conflict"
            )
        result = PolicyGateResult(
            decision=PolicyDecision.HOLD,
            corpus_ref="collaboration://authority-state",
            stage=0,
            reason_code=COLLABORATION_ANCHOR_REASON,
            request_hash=new,
            policy_hash=self.authority_context_hash,
            execution_context_hash=expected,
        )
        try:
            record = self.coordinator.append_and_anchor(
                surface=COLLABORATION_ANCHOR_SURFACE,
                resource_id=self.authority_context_hash,
                result=result,
                recorded_at=int(now),
                expires_at=int(now) + COLLABORATION_ANCHOR_TTL_SECONDS,
                expected_previous_decision_hash=current.decision_hash,
                now=int(now),
            )
        except Exception:
            raise CollaborationAnchorError(
                "Collaboration rollback anchor commit is unavailable"
            ) from None
        if (
            record.get("surface") != COLLABORATION_ANCHOR_SURFACE
            or record.get("decision") != PolicyDecision.HOLD.value
            or record.get("reason_code") != COLLABORATION_ANCHOR_REASON
            or record.get("request_hash") != new
            or record.get("policy_hash") != self.authority_context_hash
            or record.get("execution_context_hash") != expected
            or record.get("previous_decision_hash")
            != current.decision_hash
            or not _bare_hash(record.get("decision_hash"))
            or isinstance(record.get("sequence"), bool)
            or not isinstance(record.get("sequence"), int)
            or record["sequence"] <= current.sequence
        ):
            raise CollaborationAnchorError(
                "Collaboration rollback anchor commit is invalid"
            )
        return CollaborationAnchorHead(
            authority_context_hash=self.authority_context_hash,
            state_hash=new,
            decision_hash=record["decision_hash"],
            sequence=record["sequence"],
            rollback_anchor=dict(record.get("rollback_anchor") or {}),
        )


def collaboration_authority_context_hash(settings: Any) -> str:
    """Bind the witness resource to one project runtime, release, and domain."""

    chain_id = getattr(settings, "wallet_auth_chain_id", 0)
    domain = str(getattr(settings, "wallet_auth_domain", "") or "").strip()
    uri = str(getattr(settings, "wallet_auth_uri", "") or "").strip()
    runtime_project = str(
        getattr(settings, "main_runtime_cvm_id", "") or ""
    ).strip()
    deployment_intent = str(
        getattr(settings, "release_deployment_intent_sha256", "") or ""
    ).strip()
    release_authority = str(
        getattr(settings, "release_authority_sha256", "") or ""
    ).strip()
    ceremony_nonce = str(
        getattr(settings, "release_ceremony_nonce", "") or ""
    ).strip()
    issuer = str(
        getattr(settings, "collaboration_wallet_auth_issuer", "") or ""
    ).strip()
    audience = str(
        getattr(settings, "collaboration_wallet_auth_audience", "") or ""
    ).strip()
    if (
        getattr(settings, "collaboration_enabled", None) is not True
        or chain_id != BASE_SEPOLIA_CHAIN_ID
        or domain != "www.wikigen.me"
        or uri != "https://www.wikigen.me"
        or not _CVM_ID.fullmatch(runtime_project)
        or not _SHA256.fullmatch(deployment_intent)
        or not _SHA256.fullmatch(release_authority)
        or not _BYTES32.fullmatch(ceremony_nonce)
        or issuer != "dnai-wikigen:collaboration-wallet-auth"
        or audience != "dnai-wikigen:collaboration-console"
    ):
        raise CollaborationAnchorError(
            "Collaboration project, release, or wallet domain is incomplete"
        )
    context = {
        "schema": COLLABORATION_AUTHORITY_CONTEXT_SCHEMA,
        "project": {
            "main_runtime_cvm_id": runtime_project,
            "deployment_intent_sha256": deployment_intent,
        },
        "release": {
            "release_authority_sha256": release_authority,
            "ceremony_nonce": ceremony_nonce,
        },
        "wallet_domain": {
            "chain_id": chain_id,
            "domain": domain,
            "uri": uri,
            "issuer": issuer,
            "audience": audience,
            "scope": "collaboration:console",
        },
        "store_schema_version": 2,
    }
    return hashlib.sha256(
        b"dnai-wikigen/collaboration-authority-context/v1\0"
        + _canonical_json(context)
    ).hexdigest()


def collaboration_state_hash(
    state: Mapping[str, Any],
    *,
    authority_context_hash: str,
) -> str:
    """Commit the exact state and its release-context resource identity."""

    if not isinstance(state, dict):
        raise CollaborationRollbackError("Collaboration state is invalid")
    try:
        _validate_state(state)
    except Exception as exc:
        raise CollaborationRollbackError(
            "Collaboration state is invalid"
        ) from exc
    context = _required_hash(
        authority_context_hash,
        "Collaboration authority context",
        allow_zero=False,
    )
    payload = {
        "schema": "dnai.collaboration-state-commitment.v1",
        "authority_context_hash": context,
        "store_schema_version": 2,
        "state": state,
        "raw_secret_egress": False,
    }
    return hashlib.sha256(
        b"dnai-wikigen/collaboration-state-commitment/v1\0"
        + _canonical_json(payload)
    ).hexdigest()


def collaboration_pending_path(path: str | Path) -> Path:
    active = Path(path)
    return active.with_name(f".{active.name}.anchoring-pending")


def promote_collaboration_pending(path: str | Path) -> None:
    active = Path(path)
    pending = collaboration_pending_path(active)
    _require_private_regular_file(pending, "Collaboration pending state")
    if os.path.lexists(active):
        _require_private_regular_file(active, "Collaboration active state")
    try:
        os.replace(pending, active)
        _require_private_regular_file(active, "Collaboration promoted state")
        _fsync_directory(active.parent)
    except OSError as exc:
        raise CollaborationRollbackError(
            "Collaboration pending-state promotion failed"
        ) from exc


def discard_collaboration_pending(path: str | Path) -> None:
    pending = collaboration_pending_path(path)
    if not os.path.lexists(pending):
        return
    _require_private_regular_file(pending, "Collaboration pending state")
    try:
        pending.unlink()
        _fsync_directory(pending.parent)
    except OSError as exc:
        raise CollaborationRollbackError(
            "Collaboration pending-state discard failed"
        ) from exc


class AnchoredCollaborationStore(CollaborationStore):
    """Collaboration store whose every observed state matches a current anchor."""

    def __init__(
        self,
        path: str | Path,
        *,
        integrity_key: bytes,
        authority_context_hash: str,
        rollback_anchor: CollaborationRollbackAnchor,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if rollback_anchor is None:
            raise CollaborationRollbackError(
                "Live Collaboration requires a rollback anchor"
            )
        self.authority_context_hash = _required_hash(
            authority_context_hash,
            "Collaboration authority context",
            allow_zero=False,
        )
        self.rollback_anchor = rollback_anchor
        self._clock = clock or time.time
        self._last_anchor_head: CollaborationAnchorHead | None = None
        super().__init__(path, integrity_key=integrity_key)
        with self._locked():
            self._recover_locked(now=self._now())

    def rollback_status(self) -> dict[str, Any]:
        with self._locked():
            self._load_locked()
            return dict(self._rollback_truth())

    def _load_locked(self) -> dict[str, Any]:
        return self._recover_locked(now=self._now())

    def _recover_locked(self, *, now: int) -> dict[str, Any]:
        previous_head = self._last_anchor_head
        try:
            head = self.rollback_anchor.read_head(now=now)
        except Exception as exc:
            raise CollaborationRollbackError(
                "Collaboration rollback witness is unavailable"
            ) from exc
        self._require_anchor_head(head, previous=previous_head)
        self._last_anchor_head = head
        active_exists = os.path.lexists(self.path)
        pending_path = collaboration_pending_path(self.path)
        pending_exists = os.path.lexists(pending_path)

        if head.state_hash == ZERO_COLLABORATION_STATE_HASH:
            if pending_exists:
                discard_collaboration_pending(self.path)
            if active_exists:
                active = super()._load_path_locked(self.path)
                if active != _empty_state():
                    raise CollaborationRollbackError(
                        "Unanchored Collaboration state is not empty"
                    )
            else:
                active = _empty_state()
                super()._persist_path_locked(self.path, active)
            initial_hash = collaboration_state_hash(
                active,
                authority_context_hash=self.authority_context_hash,
            )
            try:
                head = self.rollback_anchor.compare_and_set(
                    expected_state_hash=ZERO_COLLABORATION_STATE_HASH,
                    new_state_hash=initial_hash,
                    now=now,
                )
            except Exception as exc:
                raise CollaborationRollbackError(
                    "Collaboration initialization witness is unavailable"
                ) from exc
            self._require_anchor_head(
                head,
                previous=self._last_anchor_head,
                expected_state_hash=initial_hash,
            )
            self._last_anchor_head = head
            return active

        active = (
            super()._load_path_locked(self.path)
            if active_exists
            else None
        )
        if active is not None:
            active_hash = collaboration_state_hash(
                active,
                authority_context_hash=self.authority_context_hash,
            )
            if hmac.compare_digest(active_hash, head.state_hash):
                if pending_exists:
                    discard_collaboration_pending(self.path)
                return active

        if pending_exists:
            pending = super()._load_path_locked(pending_path)
            pending_hash = collaboration_state_hash(
                pending,
                authority_context_hash=self.authority_context_hash,
            )
            if hmac.compare_digest(pending_hash, head.state_hash):
                promote_collaboration_pending(self.path)
                return pending
        raise CollaborationRollbackError(
            "Collaboration state does not match its rollback witness"
        )

    def _commit_locked(self, candidate: dict[str, Any]) -> None:
        if self._last_anchor_head is None:
            raise CollaborationRollbackError(
                "Collaboration rollback witness head is unavailable"
            )
        candidate["sequence"] += 1
        _validate_state(candidate)
        next_hash = collaboration_state_hash(
            candidate,
            authority_context_hash=self.authority_context_hash,
        )
        previous_hash = self._last_anchor_head.state_hash
        if hmac.compare_digest(next_hash, previous_hash):
            raise CollaborationRollbackError(
                "Collaboration mutation did not advance its state"
            )
        pending_path = collaboration_pending_path(self.path)
        super()._persist_path_locked(pending_path, candidate)
        try:
            head = self.rollback_anchor.compare_and_set(
                expected_state_hash=previous_hash,
                new_state_hash=next_hash,
                now=self._now(),
            )
        except Exception as exc:
            # Preserve the pending document. The external CAS may have
            # committed despite a transport failure; the next read compares
            # both authenticated documents to the current head.
            raise CollaborationRollbackError(
                "Collaboration rollback witness commit is unavailable"
            ) from exc
        self._require_anchor_head(
            head,
            previous=self._last_anchor_head,
            expected_state_hash=next_hash,
        )
        try:
            promote_collaboration_pending(self.path)
        except CollaborationRollbackError:
            # Preserve fail-closed behavior. A subsequent read promotes only
            # when the same state hash is still the externally witnessed head.
            raise
        self._last_anchor_head = head

    def _rollback_truth(self) -> dict[str, Any]:
        if self._last_anchor_head is None:
            raise CollaborationRollbackError(
                "Collaboration rollback witness head is unavailable"
            )
        return {
            "rollback_protection": True,
            "rollback_witness": self._last_anchor_head.to_public_dict(),
            "tamper_evident_current_state": True,
        }

    def _require_anchor_head(
        self,
        head: Any,
        *,
        previous: CollaborationAnchorHead | None = None,
        expected_state_hash: str | None = None,
    ) -> None:
        if (
            not isinstance(head, CollaborationAnchorHead)
            or head.authority_context_hash != self.authority_context_hash
            or not _bare_hash(head.state_hash)
            or not _bare_hash(head.decision_hash)
            or isinstance(head.sequence, bool)
            or not isinstance(head.sequence, int)
            or head.sequence < 0
        ):
            raise CollaborationRollbackError(
                "Collaboration rollback witness head is invalid"
            )
        empty = head.sequence == 0
        if (
            empty
            and (
                head.state_hash != ZERO_COLLABORATION_STATE_HASH
                or head.decision_hash != ZERO_DECISION_HASH
            )
        ) or (
            not empty
            and (
                head.state_hash == ZERO_COLLABORATION_STATE_HASH
                or head.decision_hash == ZERO_DECISION_HASH
            )
        ):
            raise CollaborationRollbackError(
                "Collaboration rollback witness head is invalid"
            )
        try:
            projection = _bounded_rollback_anchor(head.rollback_anchor)
            _validate_rollback_anchor_status(
                projection,
                head=head,
                authority_context_hash=self.authority_context_hash,
            )
        except CollaborationAnchorError as exc:
            raise CollaborationRollbackError(
                "Collaboration rollback witness head is invalid"
            ) from exc
        if previous is not None and (
            head.sequence < previous.sequence
            or (
                head.sequence == previous.sequence
                and (
                    not hmac.compare_digest(
                        head.state_hash,
                        previous.state_hash,
                    )
                    or not hmac.compare_digest(
                        head.decision_hash,
                        previous.decision_hash,
                    )
                )
            )
        ):
            raise CollaborationRollbackError(
                "Collaboration rollback witness regressed"
            )
        if expected_state_hash is not None and (
            not hmac.compare_digest(head.state_hash, expected_state_hash)
            or previous is None
            or head.sequence <= previous.sequence
        ):
            raise CollaborationRollbackError(
                "Collaboration rollback witness commit is invalid"
            )

    def _now(self) -> int:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CollaborationRollbackError(
                "Collaboration witness clock is unavailable"
            )
        timestamp = int(value)
        if timestamp < 0:
            raise CollaborationRollbackError(
                "Collaboration witness clock is unavailable"
            )
        return timestamp


def _require_private_regular_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise CollaborationRollbackError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
    ):
        raise CollaborationRollbackError(f"{label} is invalid")


def _bare_hash(value: Any) -> bool:
    return isinstance(value, str) and _HASH.fullmatch(value) is not None


def _required_hash(
    value: Any,
    label: str,
    *,
    allow_zero: bool = True,
) -> str:
    if (
        not _bare_hash(value)
        or (not allow_zero and value == ZERO_COLLABORATION_STATE_HASH)
    ):
        raise CollaborationAnchorError(f"{label} hash is invalid")
    return value


def _bounded_rollback_anchor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(
        _ROLLBACK_ANCHOR_KEYS
    ):
        raise CollaborationAnchorError(
            "Collaboration rollback anchor projection is invalid"
        )
    projection = {key: value[key] for key in _ROLLBACK_ANCHOR_KEYS}
    try:
        encoded = _canonical_json(projection)
    except CollaborationRollbackError as exc:
        raise CollaborationAnchorError(
            "Collaboration rollback anchor projection is invalid"
        ) from exc
    if len(encoded) > MAX_PUBLIC_ROLLBACK_ANCHOR_BYTES:
        raise CollaborationAnchorError(
            "Collaboration rollback anchor projection is too large"
        )
    return projection


def _validate_rollback_anchor_status(
    value: Mapping[str, Any],
    *,
    head: CollaborationAnchorHead,
    authority_context_hash: str,
) -> None:
    integer_fields = (
        "latest_block_number",
        "rpc_finalized_block_number",
        "minimum_confirmation_depth",
        "observed_confirmation_depth",
        "block_number",
        "block_timestamp",
        "global_sequence",
        "resource_sequence",
        "decision_sequence",
    )
    if any(
        isinstance(value[field], bool)
        or not isinstance(value[field], int)
        or value[field] < 0
        or value[field] > 9_007_199_254_740_991
        for field in integer_fields
    ):
        raise CollaborationAnchorError(
            "Collaboration rollback anchor counters are invalid"
        )
    if (
        value["schema"]
        != "dnai-wikigen/execution-policy-anchor-status/v1"
        or value["status"] != "rpc_reported_finalized_release_match"
        or value["verification_model"]
        != "single_rpc_reported_finalized_with_confirmation_depth"
        or value["chain_id"] != BASE_SEPOLIA_CHAIN_ID
        or value["writer_rotations_frozen"] is not True
        or value["paused"] is not False
        or value["independent_rpc_quorum_verified"] is not False
        or value["consensus_proof_verified"] is not False
        or value["opaque_commitments_only"] is not True
        or value["raw_resource_id_egress"] is not False
        or value["raw_policy_egress"] is not False
        or not _matches(_ADDRESS, value["contract_address"])
        or not _matches(_ADDRESS, value["writer"])
        or not _matches(_BYTES32, value["runtime_code_hash"])
        or not _matches(
            _BYTES32,
            value["writer_release_commitment"],
        )
        or not _matches(_BYTES32, value["block_hash"])
        or not _matches(
            _BYTES32,
            value["rpc_finalized_block_hash"],
        )
        or not _matches(_ANY_BYTES32, value["global_head"])
        or not _matches(
            _ANY_BYTES32,
            value["resource_decision_head"],
        )
    ):
        raise CollaborationAnchorError(
            "Collaboration rollback anchor identity is invalid"
        )
    minimum_depth = value["minimum_confirmation_depth"]
    observed_depth = value["observed_confirmation_depth"]
    latest_block = value["latest_block_number"]
    finalized_block = value["rpc_finalized_block_number"]
    selected_block = value["block_number"]
    if (
        not 2 <= minimum_depth <= 256
        or observed_depth < minimum_depth
        or selected_block < 1
        or finalized_block < 1
        or latest_block < 1
        or selected_block > finalized_block
        or finalized_block > latest_block
        or selected_block
        != min(
            latest_block - minimum_depth + 1,
            finalized_block,
        )
        or observed_depth != latest_block - selected_block + 1
        or not 1 <= value["block_timestamp"] <= 4_102_444_800
    ):
        raise CollaborationAnchorError(
            "Collaboration rollback anchor finality is invalid"
        )
    global_empty = (
        value["global_sequence"] == 0
        and value["global_head"] == "0x" + "0" * 64
    )
    global_populated = (
        value["global_sequence"] > 0
        and value["global_head"] != "0x" + "0" * 64
    )
    expected_resource_id = execution_resource_hash(
        COLLABORATION_ANCHOR_SURFACE,
        authority_context_hash,
    )
    if (
        not (global_empty or global_populated)
        or value["resource_id_hash"] != expected_resource_id
        or value["global_sequence"] < head.sequence
    ):
        raise CollaborationAnchorError(
            "Collaboration rollback anchor resource is invalid"
        )
    if head.sequence == 0:
        valid_resource = (
            value["resource_sequence"] == 0
            and value["resource_decision_head"] == "0x" + "0" * 64
            and value["decision_hash"] == ""
            and value["decision_sequence"] == 0
        )
    else:
        valid_resource = (
            value["resource_sequence"] == head.sequence
            and value["resource_decision_head"]
            == "0x" + head.decision_hash
            and value["decision_hash"] == head.decision_hash
            and value["decision_sequence"] == head.sequence
        )
    if not valid_resource:
        raise CollaborationAnchorError(
            "Collaboration rollback anchor head binding is invalid"
        )


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CollaborationRollbackError(
            "Collaboration commitment serialization failed"
        ) from exc
