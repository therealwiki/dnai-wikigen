"""Durable, integrity-protected execution-policy decisions.

The pure policy kernel decides whether a request passes, is held, or is denied.
This module binds that bounded decision to one execution resource without ever
persisting the raw resource identifier, purpose, corpus name, category names,
or policy text. New decisions append and supersede older decisions; execution
always consults the newest unexpired record and therefore fails closed after a
deny, hold, expiry, file corruption, or missing store.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_address, to_checksum_address

from tinker_delegate import dstack_utils
from tinker_delegate.policy_kernel import (
    POLICY_CANONICALIZATION_VERSION,
    PolicyGateResult,
)


SCHEMA_VERSION = 6
EXECUTION_POLICY_APPROVAL_SCHEMA = (
    "dnai-wikigen/execution-policy-approval/v3"
)
EXECUTION_POLICY_API_SCHEMA_VERSION = 3
STORE_SURFACE = "execution_policy_store"
ZERO_DECISION_HASH = "0" * 64
ZERO_RECORD_DIGEST = "0" * 64
POLICY_RECORD_KIND = "execution_policy_decision_v2"
ROYALTY_RECORD_KIND = "royalty_settlement_anchor_v1"
ROYALTY_CONFIRMATION_SCHEMA = "dnai.royalty-settlement-anchor-confirmation.v1"
EXECUTION_SURFACES = frozenset(
    {
        "deal_evaluation",
        "arena_execution",
        "compute_dispatch",
        "review_queue_state",
        "collaboration_state",
    }
)
MAX_RECORDS = 20_000
MAX_STORE_BYTES = 8 * 1024 * 1024
# PASS issuance cannot consume the capacity reserved for subsequent HOLD/DENY
# revocations. Once conservative records consume that reserve, execution fails
# globally closed rather than continuing to honor an older PASS.
REVOCATION_RECORD_RESERVE = 1_024
REVOCATION_BYTE_RESERVE = 512 * 1024
MIN_REVOCATION_RECORD_BYTES = 4 * 1024
MAX_DECISION_TTL_SECONDS = 30 * 24 * 60 * 60
_RESOURCE_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_REASON_RE = re.compile(r"^[a-z0-9_]{1,96}$")
_SIGNATURE_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]{130}$")
_APPROVAL_DOMAIN_RE = re.compile(
    r"^base-sepolia:84532:"
    r"(?P<release_manifest_commitment>[0-9a-f]{64}):"
    r"(?P<compose_hash>0x[0-9a-f]{64}):"
    r"(?P<app_id_hash>[0-9a-f]{64}):"
    r"(?P<approver_root_hash>[0-9a-f]{64})$"
)


class ExecutionPolicyStoreError(RuntimeError):
    """Base error for decision persistence and lookup."""


class ExecutionPolicyStoreUnavailable(ExecutionPolicyStoreError):
    """Raised when the required store/key configuration is unavailable."""


class ExecutionPolicyStoreCorrupt(ExecutionPolicyStoreError):
    """Raised when persisted state fails schema or integrity validation."""


class ExecutionPolicyNotPassed(PermissionError):
    """Raised when the newest decision cannot authorize execution."""


def execution_resource_hash(surface: str, resource_id: str) -> str:
    normalized_surface = _surface(surface)
    normalized_resource = _resource_id(resource_id)
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-resource/v1\0"
        + normalized_surface.encode("ascii")
        + b"\0"
        + normalized_resource.encode("utf-8")
    ).hexdigest()


def execution_policy_integrity_key(settings: Any) -> bytes:
    """Resolve a purpose-separated local or dstack-backed integrity key."""

    domain = b"dnai-wikigen/execution-policy-store-integrity/v1\0"
    if dstack_utils.is_dstack_enabled():
        path = str(
            getattr(
                settings,
                "execution_policy_store_integrity_key_path",
                "tinker/execution_policy_store_integrity",
            )
            or ""
        ).strip()
        if not path or path in {
            "tinker/runtime-auth",
            "tinker/compute_store_integrity",
            "tinker/arena_candidate_ingress",
        }:
            raise ExecutionPolicyStoreUnavailable(
                "execution policy store dstack key path is invalid"
            )
        try:
            material = dstack_utils.derive_storage_key(path)
        except Exception as exc:
            raise ExecutionPolicyStoreUnavailable(
                "execution policy store dstack key derivation failed"
            ) from exc
        return hashlib.sha256(domain + b"dstack\0" + material).digest()

    explicit = str(
        getattr(settings, "execution_policy_store_integrity_key", "") or ""
    )
    if len(explicit) < 32:
        raise ExecutionPolicyStoreUnavailable(
            "execution policy store integrity key is unavailable outside dstack"
        )
    return hashlib.sha256(domain + b"local\0" + explicit.encode("utf-8")).digest()


def execution_policy_approval_message(
    *,
    surface: str,
    resource_id: str,
    result: PolicyGateResult,
    expires_at: int,
    approval_domain: str,
    approver_root_hash: str,
    previous_decision_hash: str,
) -> str:
    """Build the exact hash-only Ethereum personal-sign approval message."""

    normalized_surface = _surface(surface)
    resource_hash = execution_resource_hash(normalized_surface, resource_id)
    expiry = _timestamp(expires_at, "expires_at")
    domain_hash = execution_policy_approval_domain_hash(approval_domain)
    normalized_approver_root = _hash_value(
        approver_root_hash, "approver_root_hash"
    )
    previous_hash = _hash_value(
        previous_decision_hash, "previous_decision_hash"
    )
    if not isinstance(result, PolicyGateResult):
        raise ExecutionPolicyStoreError("policy gate result is required")
    payload = {
        "schema": EXECUTION_POLICY_APPROVAL_SCHEMA,
        "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
        "approval_domain_hash": domain_hash,
        "approver_root_hash": normalized_approver_root,
        "surface": normalized_surface,
        "resource_id_hash": resource_hash,
        "decision": result.decision.value,
        "request_hash": _hash_value(result.request_hash, "request_hash"),
        "policy_hash": _hash_value(result.policy_hash, "policy_hash"),
        "execution_context_hash": _hash_value(
            result.execution_context_hash,
            "execution_context_hash",
        ),
        "previous_decision_hash": previous_hash,
        "expires_at": expiry,
    }
    return "DNAI Wikigen execution policy approval\n" + _canonical_json(payload).decode(
        "ascii"
    )


def execution_policy_approval_domain(settings: Any) -> str:
    """Resolve the deployment-unique public domain required for approvals."""

    raw = str(
        getattr(settings, "execution_policy_approval_domain", "") or ""
    )
    if raw != raw.strip() or not _APPROVAL_DOMAIN_RE.fullmatch(raw):
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approval domain is not an exact Base Sepolia release domain"
        )
    return raw


def execution_policy_approval_domain_components(
    approval_domain: str,
) -> dict[str, str]:
    """Return the exact public release roots carried by an approval domain."""

    if not isinstance(approval_domain, str) or approval_domain != approval_domain.strip():
        raise ExecutionPolicyStoreError(
            "execution policy approval domain is invalid"
        )
    match = _APPROVAL_DOMAIN_RE.fullmatch(approval_domain)
    if match is None:
        raise ExecutionPolicyStoreError(
            "execution policy approval domain is invalid"
        )
    return dict(match.groupdict())


def execution_policy_approval_domain_hash(approval_domain: str) -> str:
    if (
        not isinstance(approval_domain, str)
        or approval_domain != approval_domain.strip()
        or not _APPROVAL_DOMAIN_RE.fullmatch(approval_domain)
    ):
        raise ExecutionPolicyStoreError(
            "execution policy approval domain is invalid"
        )
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-approval-domain/v1\0"
        + approval_domain.encode("ascii")
    ).hexdigest()


def execution_policy_approved_signers(settings: Any) -> tuple[str, ...]:
    """Validate signer trust roots without disclosing them over the API."""

    return tuple(sorted(_approved_signers(settings)))


def execution_policy_approver_root_hash(
    approver_hashes: frozenset[str] | set[str] | tuple[str, ...] | list[str],
) -> str:
    if (
        not isinstance(approver_hashes, (frozenset, set, tuple, list))
        or not approver_hashes
        or len(approver_hashes) > 64
    ):
        raise ExecutionPolicyStoreError(
            "execution policy approver hashes are invalid"
        )
    normalized = sorted(
        {_hash_value(value, "approver_hash") for value in approver_hashes}
    )
    if len(normalized) != len(approver_hashes):
        raise ExecutionPolicyStoreError(
            "execution policy approver hashes are invalid"
        )
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-approver-root/v1\0"
        + _canonical_json(normalized)
    ).hexdigest()


def execution_policy_approver_hash(address: str) -> str:
    normalized = _address(address, "execution policy approver")
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-approver/v1\0"
        + normalized.lower().encode("ascii")
    ).hexdigest()


def execution_policy_trust_context(
    settings: Any,
) -> tuple[str, frozenset[str], str]:
    """Return current domain and signer hashes for execution-time revocation."""

    domain_hash = execution_policy_approval_domain_hash(
        execution_policy_approval_domain(settings)
    )
    approver_hashes = frozenset(
        execution_policy_approver_hash(address)
        for address in _approved_signers(settings)
    )
    approver_root_hash = execution_policy_approver_root_hash(approver_hashes)
    expected_root = str(
        getattr(settings, "execution_policy_approver_root_hash", "") or ""
    )
    try:
        normalized_expected = _hash_value(
            expected_root, "execution_policy_approver_root_hash"
        )
    except ExecutionPolicyStoreError as exc:
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approver root is not configured"
        ) from exc
    if not hmac.compare_digest(approver_root_hash, normalized_expected):
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approver root does not match the signer set"
        )
    approval_domain = execution_policy_approval_domain(settings)
    domain_match = _APPROVAL_DOMAIN_RE.fullmatch(approval_domain)
    if domain_match is None or not hmac.compare_digest(
        domain_match.group("approver_root_hash"), approver_root_hash
    ):
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approval domain does not bind the approver root"
        )
    return domain_hash, approver_hashes, approver_root_hash


def verify_execution_policy_approval(
    *,
    settings: Any,
    surface: str,
    resource_id: str,
    result: PolicyGateResult,
    expires_at: int,
    approver_address: str,
    approval_signature: str,
    previous_decision_hash: str,
) -> tuple[str, str, str, str]:
    """Verify a pass decision against an independently configured signer."""

    if result.decision.value != "pass":
        return "", "", "", ""
    approval_domain = execution_policy_approval_domain(settings)
    domain_hash, allowed_hashes, approver_root_hash = (
        execution_policy_trust_context(settings)
    )
    declared = _address(approver_address, "approver_address")
    approver_hash = execution_policy_approver_hash(declared)
    if approver_hash not in allowed_hashes:
        raise ExecutionPolicyStoreError(
            "execution policy approver is not configured"
        )
    signature = str(approval_signature or "")
    if not _SIGNATURE_RE.fullmatch(signature):
        raise ExecutionPolicyStoreError(
            "execution policy approval signature is invalid"
        )
    message = execution_policy_approval_message(
        surface=surface,
        resource_id=resource_id,
        result=result,
        expires_at=expires_at,
        approval_domain=approval_domain,
        approver_root_hash=approver_root_hash,
        previous_decision_hash=previous_decision_hash,
    )
    try:
        recovered = to_checksum_address(
            Account.recover_message(
                encode_defunct(text=message), signature=signature
            )
        )
    except Exception as exc:
        raise ExecutionPolicyStoreError(
            "execution policy approval signature is invalid"
        ) from exc
    if recovered.lower() != declared.lower():
        raise ExecutionPolicyStoreError(
            "execution policy approval signer does not match"
        )
    normalized_signature = signature[2:] if signature.startswith("0x") else signature
    approval_hash = hashlib.sha256(
        b"dnai-wikigen/execution-policy-signature/v1\0"
        + bytes.fromhex(normalized_signature)
    ).hexdigest()
    return (
        approver_hash,
        approval_hash,
        domain_hash,
        approver_root_hash,
    )


class ExecutionPolicyStore:
    """Single-process append-only decision store with HMAC integrity."""

    _ROOT_FIELDS = frozenset({"surface", "schema_version", "payload", "integrity"})
    _PAYLOAD_FIELDS = frozenset(
        {"sequence", "records", "royalty_confirmations"}
    )
    _POLICY_RECORD_FIELDS = frozenset(
        {
            "record_kind",
            "sequence",
            "previous_record_digest",
            "surface",
            "resource_id_hash",
            "decision",
            "reason_code",
            "request_hash",
            "policy_hash",
            "execution_context_hash",
            "recorded_at",
            "expires_at",
            "approver_hash",
            "approval_hash",
            "approval_domain_hash",
            "approver_root_hash",
            "canonicalization_version",
            "previous_decision_hash",
            "decision_hash",
        }
    )
    _ROYALTY_RECORD_FIELDS = frozenset(
        {
            "record_kind",
            "sequence",
            "chain_sequence",
            "previous_record_digest",
            "resource_id_hash",
            "decision_hash",
            "recorded_at",
            "authorization_expires_at",
            "settlement_scope",
            "plan_commitment",
            "anchor_status",
            "wallet_plan",
        }
    )

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        self.path = Path(path)
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ExecutionPolicyStoreError(
                "execution policy store integrity key must be at least 32 bytes"
            )
        self._integrity_key = bytes(integrity_key)
        self._lock = threading.RLock()
        with self._lock:
            if self.path.exists():
                self._state = self._load()
            else:
                self._state = {
                    "sequence": 0,
                    "records": [],
                    "royalty_confirmations": {},
                }
                self._persist(self._state)

    def append(
        self,
        *,
        surface: str,
        resource_id: str,
        result: PolicyGateResult,
        recorded_at: int,
        expires_at: int,
        expected_previous_decision_hash: str,
        approver_hash: str = "",
        approval_hash: str = "",
        approval_domain_hash: str = "",
        approver_root_hash: str = "",
    ) -> dict[str, Any]:
        normalized_surface = _surface(surface)
        resource_hash = execution_resource_hash(normalized_surface, resource_id)
        recorded = _timestamp(recorded_at, "recorded_at")
        expiry = _timestamp(expires_at, "expires_at")
        if expiry <= recorded or expiry - recorded > MAX_DECISION_TTL_SECONDS:
            raise ExecutionPolicyStoreError("execution policy expiry is invalid")
        if not isinstance(result, PolicyGateResult):
            raise ExecutionPolicyStoreError("policy gate result is required")
        decision = result.decision.value
        if decision not in {"pass", "hold", "deny"}:
            raise ExecutionPolicyStoreError("policy decision is invalid")
        reason = str(result.reason_code)
        if not _REASON_RE.fullmatch(reason):
            raise ExecutionPolicyStoreError("policy reason code is invalid")
        request_hash = _hash_value(result.request_hash, "request_hash")
        policy_hash = _hash_value(result.policy_hash, "policy_hash")
        execution_context_hash = _hash_value(
            result.execution_context_hash,
            "execution_context_hash",
        )
        expected_previous_hash = _hash_value(
            expected_previous_decision_hash,
            "expected_previous_decision_hash",
        )
        if decision == "pass":
            normalized_approver_hash = _hash_value(
                approver_hash, "approver_hash"
            )
            normalized_approval_hash = _hash_value(
                approval_hash, "approval_hash"
            )
            normalized_approval_domain_hash = _hash_value(
                approval_domain_hash, "approval_domain_hash"
            )
            normalized_approver_root_hash = _hash_value(
                approver_root_hash, "approver_root_hash"
            )
        else:
            if (
                approver_hash
                or approval_hash
                or approval_domain_hash
                or approver_root_hash
            ):
                raise ExecutionPolicyStoreError(
                    "non-pass decisions cannot carry approval evidence"
                )
            normalized_approver_hash = ""
            normalized_approval_hash = ""
            normalized_approval_domain_hash = ""
            normalized_approver_root_hash = ""

        with self._lock:
            if len(self._state["records"]) >= MAX_RECORDS:
                raise ExecutionPolicyStoreError("execution policy store is full")
            if decision == "pass" and (
                len(self._state["records"])
                >= MAX_RECORDS - REVOCATION_RECORD_RESERVE
                or len(_canonical_json(self._state))
                >= MAX_STORE_BYTES - REVOCATION_BYTE_RESERVE
            ):
                raise ExecutionPolicyStoreError(
                    "execution policy revocation reserve is active"
                )
            previous_record = self._latest_record_locked(
                normalized_surface, resource_hash
            )
            current_previous_hash = (
                previous_record["decision_hash"]
                if previous_record is not None
                else ZERO_DECISION_HASH
            )
            if not hmac.compare_digest(
                current_previous_hash, expected_previous_hash
            ):
                raise ExecutionPolicyStoreError(
                    "execution policy previous decision changed"
                )
            sequence = int(self._state["sequence"]) + 1
            core = {
                "record_kind": POLICY_RECORD_KIND,
                "sequence": sequence,
                "previous_record_digest": self._record_chain_head_locked(),
                "surface": normalized_surface,
                "resource_id_hash": resource_hash,
                "decision": decision,
                "reason_code": reason,
                "request_hash": request_hash,
                "policy_hash": policy_hash,
                "execution_context_hash": execution_context_hash,
                "recorded_at": recorded,
                "expires_at": expiry,
                "approver_hash": normalized_approver_hash,
                "approval_hash": normalized_approval_hash,
                "approval_domain_hash": normalized_approval_domain_hash,
                "approver_root_hash": normalized_approver_root_hash,
                "canonicalization_version": POLICY_CANONICALIZATION_VERSION,
                "previous_decision_hash": expected_previous_hash,
            }
            record = {
                **core,
                "decision_hash": _hash_json(
                    "execution_policy_decision_v2", core
                ),
            }
            candidate = copy.deepcopy(self._state)
            candidate["sequence"] = sequence
            candidate["records"].append(record)
            if decision == "pass" and len(_canonical_json(candidate)) >= (
                MAX_STORE_BYTES - REVOCATION_BYTE_RESERVE
            ):
                raise ExecutionPolicyStoreError(
                    "execution policy revocation reserve is active"
                )
            self._validate_state(candidate)
            self._persist(candidate)
            self._state = candidate
            return self._public_record(record)

    def append_royalty_wallet_plan(
        self,
        *,
        wallet_plan: Any,
        chain_sequence: int,
        recorded_at: int,
        replace_expired: bool,
    ) -> dict[str, Any]:
        """Persist one exact signed/calldata plan before any anchor broadcast.

        The caller cannot supply anchor hashes or a sequence independently: the
        complete strict wallet-plan object is reconstructed and both hashes are
        recomputed by its authorization core.  Replacement is permitted only
        after the previous current plan for this resource has expired; the
        on-chain reservation/nonce liveness check remains the orchestrator's
        mandatory finalized precondition.
        """

        from tinker_delegate.royalty_settlement_wallet_plan import (
            RoyaltySettlementWalletPlan,
            RoyaltySettlementWalletPlanError,
        )

        if not isinstance(wallet_plan, RoyaltySettlementWalletPlan):
            raise ExecutionPolicyStoreError(
                "exact royalty settlement wallet plan is required"
            )
        prepared_at = _timestamp(recorded_at, "recorded_at")
        expected_chain_sequence = _integer(
            chain_sequence,
            "royalty chain sequence",
            minimum=2,
        )
        if not isinstance(replace_expired, bool):
            raise ExecutionPolicyStoreError(
                "royalty settlement replacement flag is invalid"
            )
        try:
            persisted_plan = wallet_plan.to_persistence_dict()
            # Reconstruct before locking so an invalid/mutable adapter can
            # never enter the shared global sequence.
            checked = RoyaltySettlementWalletPlan.from_persistence_dict(
                persisted_plan
            )
        except RoyaltySettlementWalletPlanError as exc:
            raise ExecutionPolicyStoreError(str(exc)) from exc
        if checked.authorized_plan.authorization_expires_at <= prepared_at:
            raise ExecutionPolicyStoreError(
                "royalty settlement plan is already expired"
            )

        with self._lock:
            if len(self._state["records"]) >= MAX_RECORDS:
                raise ExecutionPolicyStoreError("execution policy store is full")
            sequence = int(self._state["sequence"]) + 1
            if (
                expected_chain_sequence != sequence + 1
                or checked.anchor_sequence != expected_chain_sequence
            ):
                raise ExecutionPolicyStoreError(
                    "royalty settlement anchor sequence does not include the release marker"
                )
            resource_hash = checked.anchor_resource_hash[2:]
            decision_hash = checked.anchor_decision_hash[2:]
            previous = self._latest_royalty_record_locked(resource_hash)
            if previous is None:
                if replace_expired:
                    raise ExecutionPolicyStoreError(
                        "royalty settlement replacement has no prior plan"
                    )
            else:
                if not replace_expired:
                    raise ExecutionPolicyStoreError(
                        "royalty settlement resource already has a plan"
                    )
                if previous["authorization_expires_at"] > prepared_at:
                    raise ExecutionPolicyStoreError(
                        "royalty settlement plan is not expired"
                    )
                prior_plan = RoyaltySettlementWalletPlan.from_persistence_dict(
                    previous["wallet_plan"]
                )
                if self._royalty_replacement_basis(prior_plan) != (
                    self._royalty_replacement_basis(checked)
                ):
                    raise ExecutionPolicyStoreError(
                        "royalty settlement replacement changed immutable authority"
                    )
            record = {
                "record_kind": ROYALTY_RECORD_KIND,
                "sequence": sequence,
                "chain_sequence": expected_chain_sequence,
                "previous_record_digest": self._record_chain_head_locked(),
                "resource_id_hash": resource_hash,
                "decision_hash": decision_hash,
                "recorded_at": prepared_at,
                "authorization_expires_at": (
                    checked.authorized_plan.authorization_expires_at
                ),
                "settlement_scope": checked.authorized_plan.settlement_scope,
                "plan_commitment": checked.plan_commitment,
                "anchor_status": "prepared",
                "wallet_plan": persisted_plan,
            }
            candidate = copy.deepcopy(self._state)
            candidate["sequence"] = sequence
            candidate["records"].append(record)
            self._validate_state(candidate)
            self._persist(candidate)
            self._state = candidate
            return self._public_royalty_record(record)

    def refresh(self) -> None:
        """Reload and authenticate the journal while an external lease is held.

        ``ExecutionPolicyStore`` deliberately keeps an in-memory view for its
        normal single-process API.  The rollback coordinator adds a kernel
        ``flock`` shared by the API writer and Arena worker, then calls this
        method inside that lease so independent processes cannot authorize or
        append against an older authenticated snapshot.
        """

        with self._lock:
            if not self.path.exists():
                raise ExecutionPolicyStoreUnavailable(
                    "execution policy store disappeared"
                )
            self._state = self._load()

    def latest(
        self, *, surface: str, resource_id: str
    ) -> dict[str, Any] | None:
        normalized_surface = _surface(surface)
        resource_hash = execution_resource_hash(normalized_surface, resource_id)
        with self._lock:
            record = self._latest_record_locked(
                normalized_surface, resource_hash
            )
            if record is not None:
                return self._public_record(record)
        return None

    def history(
        self, *, surface: str, resource_id: str
    ) -> tuple[dict[str, Any], ...]:
        """Return one resource's complete bounded, hash-only decision chain."""

        normalized_surface = _surface(surface)
        resource_hash = execution_resource_hash(normalized_surface, resource_id)
        with self._lock:
            return tuple(
                self._public_record(record)
                for record in self._state["records"]
                if record.get("record_kind") == POLICY_RECORD_KIND
                and record["surface"] == normalized_surface
                and hmac.compare_digest(record["resource_id_hash"], resource_hash)
            )

    def latest_decision_hash(self, *, surface: str, resource_id: str) -> str:
        normalized_surface = _surface(surface)
        resource_hash = execution_resource_hash(normalized_surface, resource_id)
        with self._lock:
            record = self._latest_record_locked(
                normalized_surface, resource_hash
            )
            return (
                record["decision_hash"]
                if record is not None
                else ZERO_DECISION_HASH
            )

    def anchor_projection(self) -> tuple[dict[str, Any], ...]:
        """Return the complete hash-only sequence used by the chain witness.

        The projection deliberately excludes decision metadata and raw resource
        identifiers.  Returning a defensive immutable copy lets the rollback
        coordinator reproduce the contract's global head without weakening the
        store lock or exposing mutable internal state.
        """

        with self._lock:
            return tuple(
                {
                    "sequence": record["sequence"],
                    "resource_id_hash": record["resource_id_hash"],
                    "decision_hash": record["decision_hash"],
                    **(
                        {"chain_sequence": record["chain_sequence"]}
                        if record.get("record_kind") == ROYALTY_RECORD_KIND
                        else {}
                    ),
                }
                for record in self._state["records"]
            )

    def royalty_wallet_plan(
        self,
        *,
        plan_commitment: str,
    ) -> Any | None:
        """Restore one exact persisted plan without making a finality claim."""

        from tinker_delegate.royalty_settlement_wallet_plan import (
            RoyaltySettlementWalletPlan,
        )

        commitment = _prefixed_hash_value(
            plan_commitment, "royalty plan commitment"
        )
        with self._lock:
            for record in reversed(self._state["records"]):
                if (
                    record.get("record_kind") == ROYALTY_RECORD_KIND
                    and hmac.compare_digest(record["plan_commitment"], commitment)
                ):
                    return RoyaltySettlementWalletPlan.from_persistence_dict(
                        copy.deepcopy(record["wallet_plan"])
                    )
        return None

    def latest_royalty_wallet_plan(
        self,
        *,
        anchor_resource_hash: str,
    ) -> Any | None:
        """Restore the newest immutable plan for one opaque Royalty resource."""

        from tinker_delegate.royalty_settlement_wallet_plan import (
            RoyaltySettlementWalletPlan,
        )

        resource = _prefixed_hash_value(
            anchor_resource_hash, "royalty anchor resource"
        )[2:]
        with self._lock:
            record = self._latest_royalty_record_locked(resource)
            if record is None:
                return None
            return RoyaltySettlementWalletPlan.from_persistence_dict(
                copy.deepcopy(record["wallet_plan"])
            )

    def confirm_royalty_anchor(
        self,
        *,
        plan_commitment: str,
        snapshot: Any,
        confirmed_at: int,
    ) -> dict[str, Any]:
        """Attach an exact finalized receipt without mutating the anchor record."""

        from tinker_delegate.execution_policy_anchor import (
            BASE_SEPOLIA_CHAIN_ID,
            ExecutionPolicyAnchorSnapshot,
        )

        commitment = _prefixed_hash_value(
            plan_commitment, "royalty plan commitment"
        )
        observed_at = _timestamp(confirmed_at, "confirmed_at")
        if not isinstance(snapshot, ExecutionPolicyAnchorSnapshot):
            raise ExecutionPolicyStoreError(
                "finalized royalty anchor snapshot is required"
            )
        bounded = snapshot.to_bounded_dict()
        with self._lock:
            record = next(
                (
                    candidate
                    for candidate in self._state["records"]
                    if candidate.get("record_kind") == ROYALTY_RECORD_KIND
                    and hmac.compare_digest(
                        candidate["plan_commitment"], commitment
                    )
                ),
                None,
            )
            if record is None:
                raise ExecutionPolicyStoreError(
                    "royalty settlement plan is not persisted"
                )
            if (
                snapshot.chain_id != BASE_SEPOLIA_CHAIN_ID
                or snapshot.resource_id_hash != record["resource_id_hash"]
                or snapshot.resource_decision_head
                != "0x" + record["decision_hash"]
                or snapshot.resource_sequence != record["chain_sequence"]
                or snapshot.decision_hash != record["decision_hash"]
                or snapshot.decision_sequence != record["chain_sequence"]
                or snapshot.global_sequence < record["chain_sequence"]
                or observed_at < snapshot.block_timestamp
            ):
                raise ExecutionPolicyStoreError(
                    "finalized royalty anchor snapshot does not match the plan"
                )
            confirmation = {
                "schema": ROYALTY_CONFIRMATION_SCHEMA,
                "plan_commitment": commitment,
                "sequence": record["sequence"],
                "chain_sequence": record["chain_sequence"],
                "resource_id_hash": record["resource_id_hash"],
                "decision_hash": record["decision_hash"],
                "confirmed_at": observed_at,
                "anchor_snapshot": bounded,
            }
            existing = self._state["royalty_confirmations"].get(commitment)
            if existing is not None:
                # The first exact finalized receipt is immutable.  Later
                # sponsor reads may observe a newer global block/head after
                # unrelated policy records, but the resource and decision
                # sequence checks above still prove this same plan is the
                # finalized resource head.  Do not rewrite first-observed
                # finality or make idempotent GETs depend on their wall clock.
                return copy.deepcopy(existing)
            candidate = copy.deepcopy(self._state)
            candidate["royalty_confirmations"][commitment] = confirmation
            self._validate_state(candidate)
            self._persist(candidate)
            self._state = candidate
            return copy.deepcopy(confirmation)

    def royalty_anchor_confirmation(
        self,
        *,
        plan_commitment: str,
    ) -> dict[str, Any] | None:
        commitment = _prefixed_hash_value(
            plan_commitment, "royalty plan commitment"
        )
        with self._lock:
            value = self._state["royalty_confirmations"].get(commitment)
            return None if value is None else copy.deepcopy(value)

    def anchor_record_kind(self, *, sequence: int) -> str:
        checked = _integer(sequence, "sequence", minimum=1)
        with self._lock:
            if checked > len(self._state["records"]):
                raise ExecutionPolicyStoreError(
                    "execution policy sequence is missing"
                )
            return str(self._state["records"][checked - 1]["record_kind"])

    def _latest_record_locked(
        self, normalized_surface: str, resource_hash: str
    ) -> dict[str, Any] | None:
        for record in reversed(self._state["records"]):
            if (
                record.get("record_kind") == POLICY_RECORD_KIND
                and record["surface"] == normalized_surface
                and hmac.compare_digest(
                    record["resource_id_hash"], resource_hash
                )
            ):
                return record
        return None

    def _latest_royalty_record_locked(
        self,
        resource_hash: str,
    ) -> dict[str, Any] | None:
        for record in reversed(self._state["records"]):
            if (
                record.get("record_kind") == ROYALTY_RECORD_KIND
                and hmac.compare_digest(record["resource_id_hash"], resource_hash)
            ):
                return record
        return None

    def _record_chain_head_locked(self) -> str:
        if not self._state["records"]:
            return ZERO_RECORD_DIGEST
        return _hash_json("execution_policy_global_record_v1", self._state["records"][-1])

    @staticmethod
    def _royalty_replacement_basis(wallet_plan: Any) -> bytes:
        plan = wallet_plan.authorized_plan
        authorization = dict(plan._authorization_dict())
        for mutable in (
            "attestation_evidence_hash",
            "anchor_decision_hash",
            "anchor_sequence",
            "expiry",
        ):
            authorization.pop(mutable)
        return _canonical_json(
            {
                "chain_id": plan.chain_id,
                "distributor_address": plan.distributor_address,
                "authorization": authorization,
                "anchor_resource_hash": plan.authorization.anchor_resource_hash,
                "settlement_verifier_address": plan.settlement_verifier_address,
                "qvl_verifier_address": plan.qvl_verifier_address,
                "qvl_policy_commitment": plan.qvl_policy_commitment,
                "qvl_verdict_verifier_address": plan.qvl_verdict_verifier_address,
                "qvl_release_policy_hash": plan.qvl_release_policy_hash,
                "report_data": plan.report_data,
                "compose_hash": plan.compose_hash,
                "app_id": plan.app_id,
                "os_image_hash": plan.os_image_hash,
                "recipients": [
                    {
                        "owner_address": recipient.owner_address,
                        "amount": recipient.amount,
                    }
                    for recipient in wallet_plan.recipients
                ],
                "refund_after": wallet_plan.refund_after,
            }
        )

    def require_pass(
        self,
        *,
        surface: str,
        resource_id: str,
        now: int,
        expected_approval_domain_hash: str,
        expected_approver_root_hash: str,
        approved_approver_hashes: frozenset[str] | set[str] | tuple[str, ...],
        expected_execution_context_hash: str | None = None,
    ) -> dict[str, Any]:
        timestamp = _timestamp(now, "now")
        expected_domain = _hash_value(
            expected_approval_domain_hash, "expected_approval_domain_hash"
        )
        if (
            not isinstance(approved_approver_hashes, (frozenset, set, tuple))
            or not approved_approver_hashes
            or len(approved_approver_hashes) > 64
        ):
            raise ExecutionPolicyStoreError(
                "approved execution policy approver hashes are invalid"
            )
        approved = frozenset(
            _hash_value(value, "approved_approver_hash")
            for value in approved_approver_hashes
        )
        expected_approver_root = _hash_value(
            expected_approver_root_hash,
            "expected_approver_root_hash",
        )
        if not hmac.compare_digest(
            execution_policy_approver_root_hash(approved),
            expected_approver_root,
        ):
            raise ExecutionPolicyStoreError(
                "approved execution policy approver hashes do not match the release root"
            )
        expected_context = (
            None
            if expected_execution_context_hash is None
            else _hash_value(
                expected_execution_context_hash,
                "expected_execution_context_hash",
            )
        )
        with self._lock:
            if (
                len(self._state["records"]) >= MAX_RECORDS
                or len(_canonical_json(self._state))
                >= MAX_STORE_BYTES - MIN_REVOCATION_RECORD_BYTES
            ):
                raise ExecutionPolicyNotPassed(
                    "execution policy revocation reserve is exhausted"
                )
        record = self.latest(surface=surface, resource_id=resource_id)
        if record is None:
            raise ExecutionPolicyNotPassed("execution policy decision is missing")
        if record["expires_at"] <= timestamp:
            raise ExecutionPolicyNotPassed("execution policy decision is expired")
        if record["recorded_at"] > timestamp:
            raise ExecutionPolicyNotPassed(
                "execution policy decision is future-dated"
            )
        if record["decision"] != "pass":
            raise ExecutionPolicyNotPassed("execution policy decision is not pass")
        if not hmac.compare_digest(
            record["approval_domain_hash"], expected_domain
        ):
            raise ExecutionPolicyNotPassed(
                "execution policy approval domain is no longer current"
            )
        if not hmac.compare_digest(
            record["approver_root_hash"], expected_approver_root
        ):
            raise ExecutionPolicyNotPassed(
                "execution policy approver root is no longer current"
            )
        if record["approver_hash"] not in approved:
            raise ExecutionPolicyNotPassed(
                "execution policy approver is no longer authorized"
            )
        if expected_context is not None and not hmac.compare_digest(
            record["execution_context_hash"], expected_context
        ):
            raise ExecutionPolicyNotPassed(
                "execution policy context does not match the current execution"
            )
        return record

    def _persist(self, payload: dict[str, Any]) -> None:
        canonical_payload = _canonical_json(payload)
        root = {
            "surface": STORE_SURFACE,
            "schema_version": SCHEMA_VERSION,
            "payload": payload,
            "integrity": {
                "algorithm": "HMAC-SHA256",
                "value": hmac.new(
                    self._integrity_key, canonical_payload, hashlib.sha256
                ).hexdigest(),
            },
        }
        encoded = _canonical_json(root) + b"\n"
        if len(encoded) > MAX_STORE_BYTES:
            raise ExecutionPolicyStoreError("execution policy store exceeds size cap")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def _load(self) -> dict[str, Any]:
        try:
            if self.path.stat().st_size > MAX_STORE_BYTES:
                raise ExecutionPolicyStoreCorrupt(
                    "execution policy store exceeds size cap"
                )
            root = json.loads(self.path.read_text(encoding="utf-8"))
        except ExecutionPolicyStoreCorrupt:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ExecutionPolicyStoreCorrupt(
                "execution policy store cannot be decoded"
            ) from exc
        if not isinstance(root, dict) or set(root) != self._ROOT_FIELDS:
            raise ExecutionPolicyStoreCorrupt(
                "execution policy store root schema is invalid"
            )
        if root["surface"] != STORE_SURFACE or root["schema_version"] != SCHEMA_VERSION:
            raise ExecutionPolicyStoreCorrupt(
                "execution policy store identity is invalid"
            )
        payload = root["payload"]
        integrity = root["integrity"]
        if (
            not isinstance(payload, dict)
            or not isinstance(integrity, dict)
            or set(integrity) != {"algorithm", "value"}
            or integrity["algorithm"] != "HMAC-SHA256"
            or not isinstance(integrity["value"], str)
        ):
            raise ExecutionPolicyStoreCorrupt(
                "execution policy store integrity envelope is invalid"
            )
        expected = hmac.new(
            self._integrity_key, _canonical_json(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(integrity["value"], expected):
            raise ExecutionPolicyStoreCorrupt(
                "execution policy store integrity verification failed"
            )
        self._validate_state(payload)
        return payload

    def _validate_state(self, state: Any) -> None:
        try:
            if not isinstance(state, dict) or set(state) != self._PAYLOAD_FIELDS:
                raise ExecutionPolicyStoreCorrupt(
                    "execution policy payload schema is invalid"
                )
            sequence = _integer(state["sequence"], "sequence", minimum=0)
            records = state["records"]
            if not isinstance(records, list) or len(records) > MAX_RECORDS:
                raise ExecutionPolicyStoreCorrupt(
                    "execution policy records are invalid"
                )
            if sequence != len(records):
                raise ExecutionPolicyStoreCorrupt(
                    "execution policy sequence is invalid"
                )
            policy_resource_heads: dict[tuple[str, str], str] = {}
            previous_record_digest = ZERO_RECORD_DIGEST
            for expected_sequence, record in enumerate(records, start=1):
                if not isinstance(record, dict):
                    raise ExecutionPolicyStoreCorrupt(
                        "execution policy record schema is invalid"
                    )
                if not hmac.compare_digest(
                    _hash_value(
                        record.get("previous_record_digest"),
                        "previous_record_digest",
                    ),
                    previous_record_digest,
                ):
                    raise ExecutionPolicyStoreCorrupt(
                        "execution policy global record chain is invalid"
                    )
                kind = record.get("record_kind")
                if kind == POLICY_RECORD_KIND:
                    key = (record.get("surface"), record.get("resource_id_hash"))
                    expected_previous = policy_resource_heads.get(
                        key, ZERO_DECISION_HASH
                    )
                    self._validate_policy_record(
                        record, expected_sequence, expected_previous
                    )
                    policy_resource_heads[key] = record["decision_hash"]
                elif kind == ROYALTY_RECORD_KIND:
                    self._validate_royalty_record(record, expected_sequence)
                else:
                    raise ExecutionPolicyStoreCorrupt(
                        "execution policy record kind is invalid"
                    )
                previous_record_digest = _hash_json(
                    "execution_policy_global_record_v1", record
                )
            confirmations = state["royalty_confirmations"]
            if not isinstance(confirmations, dict) or len(confirmations) > len(records):
                raise ExecutionPolicyStoreCorrupt(
                    "royalty anchor confirmations are invalid"
                )
            royalty_records = {
                record["plan_commitment"]: record
                for record in records
                if record.get("record_kind") == ROYALTY_RECORD_KIND
            }
            for commitment, confirmation in confirmations.items():
                if commitment not in royalty_records:
                    raise ExecutionPolicyStoreCorrupt(
                        "royalty anchor confirmation has no plan"
                    )
                self._validate_royalty_confirmation(
                    confirmation,
                    royalty_records[commitment],
                )
        except ExecutionPolicyStoreCorrupt:
            raise
        except (ExecutionPolicyStoreError, TypeError, ValueError) as exc:
            raise ExecutionPolicyStoreCorrupt(str(exc)) from exc

    def _validate_policy_record(
        self,
        record: Any,
        expected_sequence: int,
        expected_previous_decision_hash: str,
    ) -> None:
        if (
            not isinstance(record, dict)
            or set(record) != self._POLICY_RECORD_FIELDS
            or record.get("record_kind") != POLICY_RECORD_KIND
        ):
            raise ExecutionPolicyStoreCorrupt(
                "execution policy record schema is invalid"
            )
        if _integer(record["sequence"], "sequence", minimum=1) != expected_sequence:
            raise ExecutionPolicyStoreCorrupt(
                "execution policy record sequence is invalid"
            )
        _surface(record["surface"])
        _hash_value(record["resource_id_hash"], "resource_id_hash")
        if record["decision"] not in {"pass", "hold", "deny"}:
            raise ExecutionPolicyStoreCorrupt("execution policy decision is invalid")
        if not isinstance(record["reason_code"], str) or not _REASON_RE.fullmatch(
            record["reason_code"]
        ):
            raise ExecutionPolicyStoreCorrupt("execution policy reason is invalid")
        _hash_value(record["request_hash"], "request_hash")
        _hash_value(record["policy_hash"], "policy_hash")
        _hash_value(
            record["execution_context_hash"], "execution_context_hash"
        )
        if record["canonicalization_version"] != POLICY_CANONICALIZATION_VERSION:
            raise ExecutionPolicyStoreCorrupt(
                "execution policy canonicalization version is invalid"
            )
        if not hmac.compare_digest(
            _hash_value(
                record["previous_decision_hash"],
                "previous_decision_hash",
            ),
            expected_previous_decision_hash,
        ):
            raise ExecutionPolicyStoreCorrupt(
                "execution policy decision chain is invalid"
            )
        if record["decision"] == "pass":
            _hash_value(record["approver_hash"], "approver_hash")
            _hash_value(record["approval_hash"], "approval_hash")
            _hash_value(
                record["approval_domain_hash"], "approval_domain_hash"
            )
            _hash_value(record["approver_root_hash"], "approver_root_hash")
        elif (
            record["approver_hash"]
            or record["approval_hash"]
            or record["approval_domain_hash"]
            or record["approver_root_hash"]
        ):
            raise ExecutionPolicyStoreCorrupt(
                "non-pass execution policy record carries approval evidence"
            )
        recorded = _timestamp(record["recorded_at"], "recorded_at")
        expiry = _timestamp(record["expires_at"], "expires_at")
        if expiry <= recorded or expiry - recorded > MAX_DECISION_TTL_SECONDS:
            raise ExecutionPolicyStoreCorrupt("execution policy expiry is invalid")
        core = {key: value for key, value in record.items() if key != "decision_hash"}
        expected_hash = _hash_json("execution_policy_decision_v2", core)
        if not hmac.compare_digest(
            _hash_value(record["decision_hash"], "decision_hash"), expected_hash
        ):
            raise ExecutionPolicyStoreCorrupt(
                "execution policy decision hash is invalid"
            )

    def _validate_royalty_record(
        self,
        record: Any,
        expected_sequence: int,
    ) -> None:
        from tinker_delegate.royalty_settlement_wallet_plan import (
            RoyaltySettlementWalletPlan,
            RoyaltySettlementWalletPlanError,
        )

        if (
            not isinstance(record, dict)
            or set(record) != self._ROYALTY_RECORD_FIELDS
            or record.get("record_kind") != ROYALTY_RECORD_KIND
        ):
            raise ExecutionPolicyStoreCorrupt(
                "royalty settlement anchor record schema is invalid"
            )
        if _integer(record["sequence"], "sequence", minimum=1) != expected_sequence:
            raise ExecutionPolicyStoreCorrupt(
                "royalty settlement anchor sequence is invalid"
            )
        if record["anchor_status"] != "prepared":
            raise ExecutionPolicyStoreCorrupt(
                "royalty settlement anchor record is mutable"
            )
        recorded = _timestamp(record["recorded_at"], "recorded_at")
        expires = _timestamp(
            record["authorization_expires_at"], "authorization_expires_at"
        )
        if expires <= recorded:
            raise ExecutionPolicyStoreCorrupt(
                "royalty settlement anchor record is expired"
            )
        try:
            wallet_plan = RoyaltySettlementWalletPlan.from_persistence_dict(
                record["wallet_plan"]
            )
        except RoyaltySettlementWalletPlanError as exc:
            raise ExecutionPolicyStoreCorrupt(str(exc)) from exc
        chain_sequence = _integer(
            record["chain_sequence"],
            "royalty chain sequence",
            minimum=2,
        )
        if (
            chain_sequence != expected_sequence + 1
            or wallet_plan.anchor_sequence != chain_sequence
            or wallet_plan.authorized_plan.authorization_expires_at != expires
            or record["resource_id_hash"] != wallet_plan.anchor_resource_hash[2:]
            or record["decision_hash"] != wallet_plan.anchor_decision_hash[2:]
            or record["settlement_scope"]
            != wallet_plan.authorized_plan.settlement_scope
            or record["plan_commitment"] != wallet_plan.plan_commitment
        ):
            raise ExecutionPolicyStoreCorrupt(
                "royalty settlement anchor record does not match its exact plan"
            )
        _hash_value(record["resource_id_hash"], "resource_id_hash")
        _hash_value(record["decision_hash"], "decision_hash")
        _prefixed_hash_value(record["settlement_scope"], "settlement_scope")
        _prefixed_hash_value(record["plan_commitment"], "plan_commitment")

    def _validate_royalty_confirmation(
        self,
        confirmation: Any,
        record: Mapping[str, Any],
    ) -> None:
        fields = {
            "schema",
            "plan_commitment",
            "sequence",
            "chain_sequence",
            "resource_id_hash",
            "decision_hash",
            "confirmed_at",
            "anchor_snapshot",
        }
        snapshot_fields = {
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
        }
        if not isinstance(confirmation, dict) or set(confirmation) != fields:
            raise ExecutionPolicyStoreCorrupt(
                "royalty anchor confirmation schema is invalid"
            )
        snapshot = confirmation["anchor_snapshot"]
        if not isinstance(snapshot, dict) or set(snapshot) != snapshot_fields:
            raise ExecutionPolicyStoreCorrupt(
                "royalty anchor confirmation snapshot is invalid"
            )
        confirmed_at = _timestamp(confirmation["confirmed_at"], "confirmed_at")
        if (
            confirmation["schema"] != ROYALTY_CONFIRMATION_SCHEMA
            or confirmation["plan_commitment"] != record["plan_commitment"]
            or confirmation["sequence"] != record["sequence"]
            or confirmation["chain_sequence"] != record["chain_sequence"]
            or confirmation["resource_id_hash"] != record["resource_id_hash"]
            or confirmation["decision_hash"] != record["decision_hash"]
            or snapshot["schema"]
            != "dnai-wikigen/execution-policy-anchor-status/v1"
            or snapshot["status"]
            != "rpc_reported_finalized_release_match"
            or snapshot["chain_id"] != 84_532
            or snapshot["resource_id_hash"] != record["resource_id_hash"]
            or snapshot["resource_decision_head"]
            != "0x" + record["decision_hash"]
            or snapshot["resource_sequence"] != record["chain_sequence"]
            or snapshot["decision_hash"] != record["decision_hash"]
            or snapshot["decision_sequence"] != record["chain_sequence"]
            or snapshot["global_sequence"] < record["chain_sequence"]
            or confirmed_at < snapshot["block_timestamp"]
            or snapshot["writer_rotations_frozen"] is not True
            or snapshot["paused"] is not False
            or snapshot["opaque_commitments_only"] is not True
            or snapshot["raw_resource_id_egress"] is not False
            or snapshot["raw_policy_egress"] is not False
        ):
            raise ExecutionPolicyStoreCorrupt(
                "royalty anchor confirmation does not match its plan"
            )
        for field in (
            "block_number",
            "block_timestamp",
            "global_sequence",
            "resource_sequence",
            "decision_sequence",
            "latest_block_number",
            "rpc_finalized_block_number",
            "minimum_confirmation_depth",
            "observed_confirmation_depth",
        ):
            _integer(snapshot[field], field, minimum=0)

    @staticmethod
    def _public_record(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "sequence": record["sequence"],
            "surface": record["surface"],
            "resource_id_hash": record["resource_id_hash"],
            "decision": record["decision"],
            "reason_code": record["reason_code"],
            "request_hash": record["request_hash"],
            "policy_hash": record["policy_hash"],
            "execution_context_hash": record["execution_context_hash"],
            "recorded_at": record["recorded_at"],
            "expires_at": record["expires_at"],
            "approver_hash": record["approver_hash"],
            "approval_hash": record["approval_hash"],
            "approval_domain_hash": record["approval_domain_hash"],
            "approver_root_hash": record["approver_root_hash"],
            "canonicalization_version": record["canonicalization_version"],
            "previous_decision_hash": record["previous_decision_hash"],
            "decision_hash": record["decision_hash"],
            "raw_policy_egress": False,
            "raw_resource_id_egress": False,
        }

    @staticmethod
    def _public_royalty_record(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "record_kind": ROYALTY_RECORD_KIND,
            "sequence": record["sequence"],
            "chain_sequence": record["chain_sequence"],
            "resource_id_hash": record["resource_id_hash"],
            "decision_hash": record["decision_hash"],
            "recorded_at": record["recorded_at"],
            "authorization_expires_at": record["authorization_expires_at"],
            "settlement_scope": record["settlement_scope"],
            "plan_commitment": record["plan_commitment"],
            "anchor_status": "prepared",
            "exact_plan_persisted": True,
            "anchor_broadcast_performed": False,
            "anchor_finality_verified": False,
            "sponsor_plan_exposed": False,
            "raw_quote_egress": False,
            "raw_secret_egress": False,
        }


def _surface(value: Any) -> str:
    if not isinstance(value, str) or value not in EXECUTION_SURFACES:
        raise ExecutionPolicyStoreError("execution policy surface is invalid")
    return value


def _resource_id(value: Any) -> str:
    if not isinstance(value, str) or not _RESOURCE_RE.fullmatch(value):
        raise ExecutionPolicyStoreError("execution policy resource id is invalid")
    return value


def _address(value: Any, label: str) -> str:
    if not isinstance(value, str) or not is_address(value):
        raise ExecutionPolicyStoreError(f"{label} is invalid")
    return to_checksum_address(value)


def _approved_signers(settings: Any) -> set[str]:
    raw = str(getattr(settings, "execution_policy_approved_signers", "") or "")
    candidates = [item.strip() for item in raw.split(",") if item.strip()]
    if not candidates or len(candidates) > 64:
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approved signers are not configured"
        )
    try:
        return {_address(item, "approved signer").lower() for item in candidates}
    except ExecutionPolicyStoreError as exc:
        raise ExecutionPolicyStoreUnavailable(
            "execution policy approved signers are invalid"
        ) from exc


def _timestamp(value: Any, label: str) -> int:
    return _integer(value, label, minimum=1, maximum=4_102_444_800)


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int = 2**63 - 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExecutionPolicyStoreError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ExecutionPolicyStoreError(f"{label} is out of range")
    return value


def _hash_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ExecutionPolicyStoreError(f"{label} must be lowercase SHA-256 hex")
    return value


def _prefixed_hash_value(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or not _HASH_RE.fullmatch(value[2:])
        or int(value[2:], 16) == 0
    ):
        raise ExecutionPolicyStoreError(f"{label} must be nonzero bytes32")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _hash_json(domain: str, value: Any) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + b"\0" + _canonical_json(value)
    ).hexdigest()
