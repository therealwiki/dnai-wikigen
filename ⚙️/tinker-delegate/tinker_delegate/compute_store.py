"""Durable, bounded state for the off-chain Compute Console.

The store is intentionally a conservative single-process persistence slice. It
tracks wallet-owned projects, encrypted-delivery credential commitments,
bounded job records, and an append-only double-entry service-credit ledger.
It never accepts payment data, chain deposits, prompts, training examples,
upstream provider credentials, or provider-authoritative metering claims.

Writes are copy-on-write, fsynced, atomically replaced, and authenticated with
an HMAC derived from a distinct dstack key domain.  This is not a distributed
database: deployments must use one API worker until a transactional shared
store replaces it.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
from pathlib import Path
from typing import Any, Mapping

from tinker_delegate.compute_auth import (
    ComputeCredentialClaims,
    SUPPORTED_COMPUTE_CREDENTIAL_SCOPES,
)
from tinker_delegate.wallet_auth import WalletAuthError, normalize_wallet_address


SCHEMA_VERSION = 1
MAX_STORE_BYTES = 16 * 1024 * 1024
MAX_PROJECTS = 1_000
MAX_PROJECTS_PER_WALLET = 16
MAX_MEMBERS_PER_PROJECT = 64
MAX_DEVICES_PER_PROJECT = 128
MAX_CREDENTIALS_PER_PROJECT = 512
MAX_JOBS = 10_000
MAX_LEDGER_TRANSACTIONS = 40_000
MAX_IDEMPOTENCY_RECORDS = 50_000
MAX_TIMESTAMP = 4_102_444_800
SERVICE_CREDIT_EXECUTION_CONTEXT_SCHEMA = (
    "dnai.compute.service-credit-execution-context.v1"
)

DEFAULT_POLICY = {
    "per_job_max_credits": 500,
    "daily_project_max_credits": 2_500,
    "credential_max_ttl_seconds": 604_800,
    "allowed_operations": ["inference", "training"],
}
ALLOWED_ROLES = frozenset({"owner", "admin", "developer", "viewer"})
MUTATING_ROLES = frozenset({"owner", "admin", "developer"})
ADMIN_ROLES = frozenset({"owner", "admin"})
ALLOWED_DEVICE_KINDS = frozenset(
    {"developer_device", "ci_service", "autonomous_agent"}
)
ALLOWED_OPERATIONS = frozenset({"inference", "training"})
ALLOWED_JOB_STATES = frozenset(
    {"queued", "running", "succeeded", "failed", "canceled"}
)
TERMINAL_JOB_STATES = frozenset({"succeeded", "failed", "canceled"})
ALLOWED_RESULT_POLICIES = frozenset(
    {"bounded_summary_receipt", "score_band_hash"}
)
ALLOWED_RECIPES = {
    "inference": frozenset({"qwen3_8b_bounded"}),
    "training": frozenset({"qwen3_8b_lora_r32"}),
}
ALLOWED_MODELS = frozenset({"qwen3_8b"})

_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_X25519_RE = re.compile(r"^[0-9a-f]{64}$")


class ComputeStoreError(ValueError):
    """Base class for bounded domain validation failures."""


class ComputeStoreCorruptError(ComputeStoreError):
    """Raised when persisted state fails schema, HMAC, or ledger validation."""


class ComputeAuthorizationError(ComputeStoreError):
    """Raised when a wallet or credential lacks project authority."""


class ComputeIdempotencyConflict(ComputeStoreError):
    """Raised when an idempotency key is reused with different input."""


class ComputeInsufficientCredits(ComputeStoreError):
    """Raised when a reservation would make project available credit negative."""


class ComputeCapExceeded(ComputeStoreError):
    """Raised when a configured spend or capacity cap would be exceeded."""


class ComputeJobStateConflict(ComputeStoreError):
    """Raised when a requested job transition is no longer safe to perform."""


class ComputeStore:
    """Thread-safe, HMAC-authenticated Compute Console JSON store."""

    _ROOT_FIELDS = frozenset({"surface", "schema_version", "payload", "integrity"})
    _PAYLOAD_FIELDS = frozenset(
        {
            "sequence",
            "projects",
            "devices",
            "credentials",
            "jobs",
            "ledger",
            "idempotency",
        }
    )

    def __init__(
        self,
        path: str | Path,
        *,
        integrity_key: bytes,
        max_operator_grant_credits: int = 100_000,
        max_project_balance_credits: int = 1_000_000,
    ) -> None:
        self.path = Path(path)
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ComputeStoreError("Compute store integrity key must be at least 32 bytes")
        self._integrity_key = bytes(integrity_key)
        self._max_operator_grant = _integer(
            max_operator_grant_credits,
            "max_operator_grant_credits",
            minimum=1,
            maximum=1_000_000,
        )
        self._max_project_balance = _integer(
            max_project_balance_credits,
            "max_project_balance_credits",
            minimum=1,
            maximum=10_000_000,
        )
        self._lock = threading.RLock()
        with self._lock:
            if self.path.exists():
                self._state = self._load()
            else:
                self._state = {
                    "sequence": 0,
                    "projects": {},
                    "devices": {},
                    "credentials": {},
                    "jobs": {},
                    "ledger": [],
                    "idempotency": {},
                }
                self._persist(self._state)

    # ------------------------------------------------------------------
    # Projects and wallet membership
    # ------------------------------------------------------------------

    def create_project(
        self,
        *,
        owner_address: str,
        name: str,
        idempotency_key: str,
        created_at: int,
    ) -> tuple[dict[str, Any], bool]:
        owner = _wallet(owner_address)
        project_name = _name(name, "project name")
        key = _idempotency_key(idempotency_key)
        timestamp = _timestamp(created_at)
        request = {"owner": owner, "name": project_name}
        with self._lock:
            idem_key = _idem_hash("project_create", owner, key)
            existing = self._idempotent_result(idem_key, request)
            if existing is not None:
                return self._project_view(existing["result_id"], owner), False
            owned = sum(
                1
                for project in self._state["projects"].values()
                if project["owner_address"] == owner
            )
            if owned >= MAX_PROJECTS_PER_WALLET:
                raise ComputeCapExceeded("wallet project limit reached")
            if len(self._state["projects"]) >= MAX_PROJECTS:
                raise ComputeCapExceeded("Compute project store is full")
            project_id = _new_id("prj")
            project = {
                "project_id": project_id,
                "name": project_name,
                "owner_address": owner,
                "members": {owner: "owner"},
                "policy": copy.deepcopy(DEFAULT_POLICY),
                "created_at": timestamp,
                "updated_at": timestamp,
            }
            candidate = self._copy_state()
            candidate["projects"][project_id] = project
            self._put_idempotency(
                candidate,
                idem_key,
                request,
                result_kind="project",
                result_id=project_id,
                created_at=timestamp,
            )
            self._commit(candidate)
            return self._project_view(project_id, owner), True

    def list_projects(self, wallet_address: str) -> list[dict[str, Any]]:
        wallet = _wallet(wallet_address)
        with self._lock:
            return [
                self._project_view(project_id, wallet)
                for project_id, project in sorted(self._state["projects"].items())
                if wallet in project["members"]
            ]

    def project(self, project_id: str, wallet_address: str) -> dict[str, Any]:
        wallet = _wallet(wallet_address)
        with self._lock:
            return self._project_view(_resource_id(project_id, "project_id"), wallet)

    def add_member(
        self,
        project_id: str,
        *,
        actor_address: str,
        member_address: str,
        role: str,
        updated_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        member = _wallet(member_address)
        timestamp = _timestamp(updated_at)
        if role not in ALLOWED_ROLES - {"owner"}:
            raise ComputeStoreError("member role must be admin, developer, or viewer")
        with self._lock:
            project = self._require_role(project_id, actor, ADMIN_ROLES)
            if member == project["owner_address"]:
                raise ComputeStoreError("project owner role is immutable")
            if member not in project["members"] and len(project["members"]) >= MAX_MEMBERS_PER_PROJECT:
                raise ComputeCapExceeded("project member limit reached")
            candidate = self._copy_state()
            candidate_project = candidate["projects"][project_id]
            candidate_project["members"][member] = role
            candidate_project["updated_at"] = max(timestamp, candidate_project["updated_at"])
            self._commit(candidate)
            return self._project_view(project_id, actor)

    def remove_member(
        self,
        project_id: str,
        *,
        actor_address: str,
        member_address: str,
        updated_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        member = _wallet(member_address)
        timestamp = _timestamp(updated_at)
        with self._lock:
            project = self._require_role(project_id, actor, ADMIN_ROLES)
            if member == project["owner_address"]:
                raise ComputeStoreError("project owner cannot be removed")
            if member not in project["members"]:
                raise ComputeStoreError("project member not found")
            candidate = self._copy_state()
            del candidate["projects"][project_id]["members"][member]
            candidate["projects"][project_id]["updated_at"] = max(
                timestamp, candidate["projects"][project_id]["updated_at"]
            )
            self._commit(candidate)
            return self._project_view(project_id, actor)

    # ------------------------------------------------------------------
    # Devices and encrypted-delivery credential commitments
    # ------------------------------------------------------------------

    def register_device(
        self,
        project_id: str,
        *,
        actor_address: str,
        label: str,
        kind: str,
        public_key_hex: str,
        registered_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        device_label = _name(label, "device label")
        if kind not in ALLOWED_DEVICE_KINDS:
            raise ComputeStoreError("device kind is unsupported")
        public_key = str(public_key_hex).lower()
        if not _X25519_RE.fullmatch(public_key):
            raise ComputeStoreError("device public key must be 32-byte X25519 hex")
        timestamp = _timestamp(registered_at)
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            project_devices = [
                item
                for item in self._state["devices"].values()
                if item["project_id"] == project_id
            ]
            if len(project_devices) >= MAX_DEVICES_PER_PROJECT:
                raise ComputeCapExceeded("project device limit reached")
            key_hash = _hash_text("compute_device_key", public_key)
            for device in project_devices:
                if device["public_key_hash"] == key_hash:
                    if (
                        device["label"] == device_label
                        and device["kind"] == kind
                        and device["status"] == "active"
                    ):
                        return self._device_view(device)
                    raise ComputeStoreError("device public key is already registered")
            device_id = _new_id("dev")
            device = {
                "device_id": device_id,
                "project_id": project_id,
                "label": device_label,
                "kind": kind,
                "public_key_hex": public_key,
                "public_key_hash": key_hash,
                "status": "active",
                "registered_by": actor,
                "registered_at": timestamp,
                "revoked_at": None,
            }
            candidate = self._copy_state()
            candidate["devices"][device_id] = device
            self._commit(candidate)
            return self._device_view(device)

    def list_devices(self, project_id: str, wallet_address: str) -> list[dict[str, Any]]:
        project_id = _resource_id(project_id, "project_id")
        wallet = _wallet(wallet_address)
        with self._lock:
            self._require_role(project_id, wallet, ALLOWED_ROLES)
            return [
                self._device_view(device)
                for device in sorted(
                    self._state["devices"].values(), key=lambda value: value["registered_at"]
                )
                if device["project_id"] == project_id
            ]

    def device_for_issuance(
        self, project_id: str, *, actor_address: str, device_id: str
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        device_id = _resource_id(device_id, "device_id")
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            device = self._device(project_id, device_id)
            if device["status"] != "active":
                raise ComputeAuthorizationError("device is revoked")
            return copy.deepcopy(device)

    def revoke_device(
        self,
        project_id: str,
        *,
        actor_address: str,
        device_id: str,
        revoked_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        device_id = _resource_id(device_id, "device_id")
        timestamp = _timestamp(revoked_at)
        with self._lock:
            self._require_role(project_id, actor, ADMIN_ROLES)
            device = self._device(project_id, device_id)
            if device["status"] == "revoked":
                return self._device_view(device)
            candidate = self._copy_state()
            candidate_device = candidate["devices"][device_id]
            candidate_device["status"] = "revoked"
            candidate_device["revoked_at"] = timestamp
            for credential in candidate["credentials"].values():
                if credential["device_id"] == device_id and credential["status"] == "active":
                    credential["status"] = "revoked"
                    credential["revoked_at"] = timestamp
            self._commit(candidate)
            return self._device_view(candidate_device)

    def create_credential(
        self,
        project_id: str,
        *,
        actor_address: str,
        credential_id: str,
        device_id: str,
        name: str,
        scopes: tuple[str, ...],
        daily_credit_cap: int,
        generation: int,
        jwt_id_hash: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        credential_id = _resource_id(credential_id, "credential_id")
        device_id = _resource_id(device_id, "device_id")
        credential_name = _name(name, "credential name")
        normalized_scopes = _scopes(scopes)
        cap = _integer(daily_credit_cap, "daily_credit_cap", minimum=1, maximum=1_000_000)
        generation = _integer(generation, "generation", minimum=1, maximum=1)
        if not _HEX64_RE.fullmatch(jwt_id_hash):
            raise ComputeStoreError("credential jwt_id_hash is malformed")
        issued_at = _timestamp(issued_at)
        expires_at = _timestamp(expires_at)
        if expires_at <= issued_at or expires_at - issued_at > DEFAULT_POLICY["credential_max_ttl_seconds"]:
            raise ComputeStoreError("credential expiry is invalid")
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            device = self._device(project_id, device_id)
            if device["status"] != "active":
                raise ComputeAuthorizationError("device is revoked")
            count = sum(
                1
                for item in self._state["credentials"].values()
                if item["project_id"] == project_id
            )
            if count >= MAX_CREDENTIALS_PER_PROJECT:
                raise ComputeCapExceeded("project credential limit reached")
            if credential_id in self._state["credentials"]:
                raise ComputeStoreError("credential id collision")
            credential = {
                "credential_id": credential_id,
                "project_id": project_id,
                "device_id": device_id,
                "name": credential_name,
                "prefix": f"wk_{'svc' if device['kind'] != 'developer_device' else 'dev'}_{credential_id[-6:]}",
                "scopes": list(normalized_scopes),
                "daily_credit_cap": cap,
                "generation": generation,
                "jwt_id_hash": jwt_id_hash,
                "status": "active",
                "issued_by": actor,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "last_used_at": None,
                "rotated_at": None,
                "revoked_at": None,
            }
            candidate = self._copy_state()
            candidate["credentials"][credential_id] = credential
            self._commit(candidate)
            return self._credential_view(credential, now=issued_at)

    def credential_for_rotation(
        self, project_id: str, *, actor_address: str, credential_id: str
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        credential_id = _resource_id(credential_id, "credential_id")
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            credential = self._credential(project_id, credential_id)
            if credential["status"] != "active":
                raise ComputeAuthorizationError("credential is revoked")
            device = self._device(project_id, credential["device_id"])
            if device["status"] != "active":
                raise ComputeAuthorizationError("credential device is revoked")
            return copy.deepcopy(credential), copy.deepcopy(device)

    def rotate_credential(
        self,
        project_id: str,
        *,
        actor_address: str,
        credential_id: str,
        expected_generation: int,
        new_jwt_id_hash: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        credential_id = _resource_id(credential_id, "credential_id")
        if not _HEX64_RE.fullmatch(new_jwt_id_hash):
            raise ComputeStoreError("credential jwt_id_hash is malformed")
        issued_at = _timestamp(issued_at)
        expires_at = _timestamp(expires_at)
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            credential = self._credential(project_id, credential_id)
            if credential["status"] != "active":
                raise ComputeAuthorizationError("credential is revoked")
            if credential["generation"] != expected_generation:
                raise ComputeIdempotencyConflict("credential was concurrently rotated")
            if expires_at <= issued_at or expires_at - issued_at > DEFAULT_POLICY["credential_max_ttl_seconds"]:
                raise ComputeStoreError("credential expiry is invalid")
            candidate = self._copy_state()
            updated = candidate["credentials"][credential_id]
            updated["generation"] = expected_generation + 1
            updated["jwt_id_hash"] = new_jwt_id_hash
            updated["issued_at"] = issued_at
            updated["expires_at"] = expires_at
            updated["rotated_at"] = issued_at
            updated["last_used_at"] = None
            self._commit(candidate)
            return self._credential_view(updated, now=issued_at)

    def revoke_credential(
        self,
        project_id: str,
        *,
        actor_address: str,
        credential_id: str,
        revoked_at: int,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        actor = _wallet(actor_address)
        credential_id = _resource_id(credential_id, "credential_id")
        timestamp = _timestamp(revoked_at)
        with self._lock:
            self._require_role(project_id, actor, MUTATING_ROLES)
            credential = self._credential(project_id, credential_id)
            if credential["status"] == "revoked":
                return self._credential_view(credential, now=timestamp)
            candidate = self._copy_state()
            updated = candidate["credentials"][credential_id]
            updated["status"] = "revoked"
            updated["revoked_at"] = timestamp
            self._commit(candidate)
            return self._credential_view(updated, now=timestamp)

    def list_credentials(
        self, project_id: str, wallet_address: str, *, now: int
    ) -> list[dict[str, Any]]:
        project_id = _resource_id(project_id, "project_id")
        wallet = _wallet(wallet_address)
        timestamp = _timestamp(now)
        with self._lock:
            self._require_role(project_id, wallet, ALLOWED_ROLES)
            return [
                self._credential_view(item, now=timestamp)
                for item in sorted(
                    self._state["credentials"].values(), key=lambda value: value["issued_at"]
                )
                if item["project_id"] == project_id
            ]

    def authorize_credential(
        self,
        claims: ComputeCredentialClaims,
        *,
        required_scope: str,
        used_at: int,
    ) -> dict[str, Any]:
        timestamp = _timestamp(used_at)
        if required_scope not in SUPPORTED_COMPUTE_CREDENTIAL_SCOPES:
            raise ComputeAuthorizationError("unsupported credential scope")
        with self._lock:
            credential = self._credential(claims.project_id, claims.credential_id)
            device = self._device(claims.project_id, claims.device_id)
            expected_jti = _hash_text("compute_credential_jti", claims.jwt_id)
            if (
                credential["status"] != "active"
                or device["status"] != "active"
                or credential["device_id"] != claims.device_id
                or credential["generation"] != claims.generation
                or credential["jwt_id_hash"] != expected_jti
                or tuple(credential["scopes"]) != claims.scopes
                or credential["daily_credit_cap"] != claims.daily_credit_cap
                or credential["expires_at"] != claims.expires_at
                or timestamp >= credential["expires_at"]
                or required_scope not in credential["scopes"]
            ):
                raise ComputeAuthorizationError("Compute credential is inactive or superseded")
            candidate = self._copy_state()
            candidate["credentials"][claims.credential_id]["last_used_at"] = timestamp
            self._commit(candidate)
            return self._credential_view(
                candidate["credentials"][claims.credential_id], now=timestamp
            )

    # ------------------------------------------------------------------
    # Service-credit ledger and bounded jobs
    # ------------------------------------------------------------------

    def grant_credits(
        self,
        project_id: str,
        *,
        amount_credits: int,
        reason: str,
        idempotency_key: str,
        granted_at: int,
    ) -> tuple[dict[str, Any], bool]:
        project_id = _resource_id(project_id, "project_id")
        amount = _integer(
            amount_credits,
            "amount_credits",
            minimum=1,
            maximum=self._max_operator_grant,
        )
        if reason != "operator_testnet_grant":
            raise ComputeStoreError("only operator_testnet_grant is supported")
        key = _idempotency_key(idempotency_key)
        timestamp = _timestamp(granted_at)
        request = {"project_id": project_id, "amount_credits": amount, "reason": reason}
        with self._lock:
            self._project_record(project_id)
            idem_key = _idem_hash("credit_grant", project_id, key)
            existing = self._idempotent_result(idem_key, request)
            if existing is not None:
                return self._ledger_by_id(existing["result_id"]), False
            balance = self._balances(project_id)
            if balance["available_credits"] + balance["reserved_credits"] + amount > self._max_project_balance:
                raise ComputeCapExceeded("project credit balance cap exceeded")
            candidate = self._copy_state()
            transaction = self._append_transaction(
                candidate,
                kind="testnet_grant",
                project_id=project_id,
                job_id=None,
                amount=amount,
                postings=[
                    {"account": f"project:{project_id}:available", "delta": amount},
                    {"account": "system:testnet_grant_pool", "delta": -amount},
                ],
                authority="operator_runtime",
                created_at=timestamp,
                idempotency_key=key,
                request=request,
                settlement_status="operator_testnet_only",
            )
            self._put_idempotency(
                candidate,
                idem_key,
                request,
                result_kind="ledger_transaction",
                result_id=transaction["transaction_id"],
                created_at=timestamp,
            )
            self._commit(candidate)
            return self._ledger_view(transaction, project_id), True

    def create_job(
        self,
        project_id: str,
        *,
        actor_kind: str,
        actor_id: str,
        credential_id: str | None,
        name: str,
        operation: str,
        model: str,
        recipe: str,
        max_credits: int,
        result_policy: str,
        environment_version: str,
        idempotency_key: str,
        created_at: int,
    ) -> tuple[dict[str, Any], bool]:
        project_id = _resource_id(project_id, "project_id")
        job_name = _name(name, "job name")
        if operation not in ALLOWED_OPERATIONS:
            raise ComputeStoreError("job operation is unsupported")
        if model not in ALLOWED_MODELS or recipe not in ALLOWED_RECIPES[operation]:
            raise ComputeStoreError("model or recipe is not allowlisted for this operation")
        if result_policy not in ALLOWED_RESULT_POLICIES:
            raise ComputeStoreError("result policy is unsupported")
        environment = _name(environment_version, "environment version")
        reservation = _integer(
            max_credits, "max_credits", minimum=1, maximum=10_000_000
        )
        key = _idempotency_key(idempotency_key)
        timestamp = _timestamp(created_at)
        if actor_kind not in {"wallet", "credential"}:
            raise ComputeAuthorizationError("job actor kind is invalid")
        request = {
            "project_id": project_id,
            "name": job_name,
            "operation": operation,
            "model": model,
            "recipe": recipe,
            "max_credits": reservation,
            "result_policy": result_policy,
            "environment_version": environment,
            "actor_kind": actor_kind,
            "actor_id": actor_id,
            "credential_id": credential_id,
        }
        with self._lock:
            project = self._project_record(project_id)
            if reservation > project["policy"]["per_job_max_credits"]:
                raise ComputeCapExceeded("per-job credit cap exceeded")
            if actor_kind == "wallet":
                normalized_actor = _wallet(actor_id)
                role = project["members"].get(normalized_actor)
                if role not in MUTATING_ROLES:
                    raise ComputeAuthorizationError("wallet cannot create jobs for this project")
                actor_commitment = _hash_text("compute_job_wallet", normalized_actor)
                credential = None
            else:
                credential_id = _resource_id(str(credential_id or ""), "credential_id")
                credential = self._credential(project_id, credential_id)
                if credential["status"] != "active" or "jobs:create" not in credential["scopes"]:
                    raise ComputeAuthorizationError("credential cannot create jobs")
                actor_commitment = credential_id
            idem_key = _idem_hash("job_create", project_id, actor_commitment, key)
            existing = self._idempotent_result(idem_key, request)
            if existing is not None:
                return self._job_view(self._state["jobs"][existing["result_id"]]), False
            if len(self._state["jobs"]) >= MAX_JOBS:
                raise ComputeCapExceeded("Compute job store is full")
            day = timestamp // 86_400
            project_usage = self._daily_budgeted_credits(project_id, day=day)
            if project_usage + reservation > project["policy"]["daily_project_max_credits"]:
                raise ComputeCapExceeded("project daily credit cap exceeded")
            if credential is not None:
                credential_usage = self._daily_budgeted_credits(
                    project_id, day=day, credential_id=credential_id
                )
                if credential_usage + reservation > credential["daily_credit_cap"]:
                    raise ComputeCapExceeded("credential daily credit cap exceeded")
            balance = self._balances(project_id)
            if balance["available_credits"] < reservation:
                raise ComputeInsufficientCredits("insufficient available Compute Credits")
            job_id = _new_id("job")
            candidate = self._copy_state()
            job = {
                "job_id": job_id,
                "project_id": project_id,
                "name": job_name,
                "operation": operation,
                "model": model,
                "recipe": recipe,
                "max_credits": reservation,
                "actual_credits": None,
                "released_credits": None,
                "result_policy": result_policy,
                "environment_version": environment,
                "status": "queued",
                "dispatch_status": "not_dispatched",
                "backend_capability": (
                    "existing_tinker_training_proxy" if operation == "training" else "future_inference_proxy"
                ),
                "actor_kind": actor_kind,
                "actor_commitment": actor_commitment,
                "credential_id": credential_id,
                "created_at": timestamp,
                "updated_at": timestamp,
                "started_at": None,
                "completed_at": None,
                "metering_source": None,
                "usage_receipt_hash": None,
                "settlement_authority": None,
            }
            candidate["jobs"][job_id] = job
            self._append_transaction(
                candidate,
                kind="job_reserve",
                project_id=project_id,
                job_id=job_id,
                amount=reservation,
                postings=[
                    {"account": f"project:{project_id}:available", "delta": -reservation},
                    {"account": f"project:{project_id}:reserved", "delta": reservation},
                ],
                authority=actor_kind,
                created_at=timestamp,
                idempotency_key=key,
                request=request,
                settlement_status="reserved",
            )
            self._put_idempotency(
                candidate,
                idem_key,
                request,
                result_kind="job",
                result_id=job_id,
                created_at=timestamp,
            )
            self._commit(candidate)
            return self._job_view(job), True

    def start_job(
        self,
        project_id: str,
        job_id: str,
        *,
        idempotency_key: str,
        started_at: int,
    ) -> tuple[dict[str, Any], bool]:
        return self._transition_job(
            project_id,
            job_id,
            action="start",
            payload={},
            idempotency_key=idempotency_key,
            occurred_at=started_at,
        )

    def execution_policy_context_hash(self, job_id: str) -> str:
        """Commit immutable service-credit job and reservation metadata.

        This operator-only projection deliberately excludes mutable lifecycle
        fields.  A policy PASS may therefore survive an idempotent retry, but
        cannot be replayed onto a different project, recipe, resource cap,
        actor commitment, environment, or credit reservation under the same
        public job identifier.
        """

        normalized_job_id = _resource_id(job_id, "job_id")
        with self._lock:
            job = self._state["jobs"].get(normalized_job_id)
            if job is None:
                raise ComputeStoreError("job not found")
            reservations = [
                transaction
                for transaction in self._state["ledger"]
                if transaction["job_id"] == normalized_job_id
                and transaction["kind"] == "job_reserve"
            ]
            if len(reservations) != 1:
                raise ComputeStoreCorruptError(
                    "job reservation ledger is inconsistent"
                )
            payload = {
                "schema": SERVICE_CREDIT_EXECUTION_CONTEXT_SCHEMA,
                "job_id": job["job_id"],
                "project_id": job["project_id"],
                "name": job["name"],
                "operation": job["operation"],
                "model": job["model"],
                "recipe": job["recipe"],
                "max_credits": job["max_credits"],
                "result_policy": job["result_policy"],
                "environment_version": job["environment_version"],
                "backend_capability": job["backend_capability"],
                "actor_kind": job["actor_kind"],
                "actor_commitment": job["actor_commitment"],
                "credential_id": job["credential_id"],
                "created_at": job["created_at"],
                "reservation_transaction_hash": reservations[0][
                    "transaction_hash"
                ],
            }
            return _hash_json(
                "dnai-wikigen/compute-service-credit-execution-context/v1",
                payload,
            )

    def settle_job(
        self,
        project_id: str,
        job_id: str,
        *,
        actual_credits: int,
        usage_receipt_hash: str,
        metering_source: str,
        idempotency_key: str,
        settled_at: int,
    ) -> tuple[dict[str, Any], bool]:
        actual = _integer(actual_credits, "actual_credits", minimum=0, maximum=500)
        if not isinstance(usage_receipt_hash, str) or not usage_receipt_hash.startswith("sha256:") or not _HEX64_RE.fullmatch(usage_receipt_hash[7:]):
            raise ComputeStoreError("usage_receipt_hash must be sha256:<lowercase hex>")
        if metering_source != "operator_bounded_receipt":
            raise ComputeStoreError("metering_source must be operator_bounded_receipt")
        return self._transition_job(
            project_id,
            job_id,
            action="settle",
            payload={
                "actual_credits": actual,
                "usage_receipt_hash": usage_receipt_hash,
                "metering_source": metering_source,
            },
            idempotency_key=idempotency_key,
            occurred_at=settled_at,
        )

    def release_job(
        self,
        project_id: str,
        job_id: str,
        *,
        terminal_status: str,
        reason: str,
        idempotency_key: str,
        released_at: int,
    ) -> tuple[dict[str, Any], bool]:
        if terminal_status not in {"failed", "canceled"}:
            raise ComputeStoreError("release terminal_status must be failed or canceled")
        if reason not in {"operator_failed", "operator_canceled", "dispatch_unavailable"}:
            raise ComputeStoreError("release reason is unsupported")
        return self._transition_job(
            project_id,
            job_id,
            action="release",
            payload={"terminal_status": terminal_status, "reason": reason},
            idempotency_key=idempotency_key,
            occurred_at=released_at,
        )

    def cancel_queued_job(
        self,
        project_id: str,
        job_id: str,
        *,
        actor_address: str,
        reason: str,
        idempotency_key: str,
        canceled_at: int,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        """Cancel one undispatched queued job and release its reservation.

        This is deliberately separate from the operator ``release_job`` path.
        A project member can never use it to release work which started,
        dispatched, metered, settled, or otherwise reached a terminal state.
        The job update, balanced ledger reversal, and replay record are one
        copy-on-write commit under the store lock.
        """

        project_id = _resource_id(project_id, "project_id")
        job_id = _resource_id(job_id, "job_id")
        actor = _wallet(actor_address)
        if reason != "user_requested_before_dispatch":
            raise ComputeStoreError("cancellation reason is unsupported")
        key = _idempotency_key(idempotency_key)
        timestamp = _timestamp(canceled_at)
        actor_commitment = _hash_text("compute_job_cancel_wallet", actor)
        request = {
            "project_id": project_id,
            "job_id": job_id,
            "action": "cancel_before_dispatch",
            "reason": reason,
            "actor_commitment": actor_commitment,
        }

        with self._lock:
            project = self._require_role(project_id, actor, MUTATING_ROLES)
            job = self._state["jobs"].get(job_id)
            if job is None or job["project_id"] != project_id:
                raise ComputeStoreError("job not found")

            # Authorization precedes replay lookup so a removed member cannot
            # use an old idempotency key to inspect or replay the result.
            idem_key = _idem_hash(
                "job_cancel_before_dispatch",
                project_id,
                job_id,
                actor_commitment,
                key,
            )
            existing = self._idempotent_result(idem_key, request)
            if existing is not None:
                transaction = self._ledger_by_id(existing["result_id"])
                if (
                    job["status"] != "canceled"
                    or transaction["kind"] != "job_cancel"
                    or transaction["job_id"] != job_id
                ):
                    raise ComputeStoreCorruptError(
                        "cancellation replay points to inconsistent state"
                    )
                return self._job_view(job), transaction, False

            if (
                job["status"] != "queued"
                or job["dispatch_status"] != "not_dispatched"
                or job["started_at"] is not None
                or job["completed_at"] is not None
                or job["actual_credits"] is not None
                or job["released_credits"] is not None
                or job["metering_source"] is not None
                or job["usage_receipt_hash"] is not None
                or job["settlement_authority"] is not None
            ):
                raise ComputeJobStateConflict(
                    "only a queued, never-dispatched, unsettled job can be canceled"
                )
            if timestamp < job["updated_at"]:
                raise ComputeStoreError("job transition timestamp regressed")
            self._require_open_job_reservation(project_id, job_id, job["max_credits"])

            candidate = self._copy_state()
            updated = candidate["jobs"][job_id]
            reserved = updated["max_credits"]
            transaction_record = self._append_transaction(
                candidate,
                kind="job_cancel",
                project_id=project_id,
                job_id=job_id,
                amount=reserved,
                postings=[
                    {"account": f"project:{project_id}:reserved", "delta": -reserved},
                    {"account": f"project:{project_id}:available", "delta": reserved},
                ],
                authority=f"project_wallet_{project['members'][actor]}",
                created_at=timestamp,
                idempotency_key=key,
                request=request,
                settlement_status="user_canceled_before_dispatch",
            )
            updated["status"] = "canceled"
            updated["actual_credits"] = 0
            updated["released_credits"] = reserved
            updated["completed_at"] = timestamp
            updated["settlement_authority"] = "project_member_pre_dispatch_cancel"
            updated["updated_at"] = timestamp
            self._put_idempotency(
                candidate,
                idem_key,
                request,
                result_kind="ledger_transaction",
                result_id=transaction_record["transaction_id"],
                created_at=timestamp,
            )
            self._commit(candidate)
            return (
                self._job_view(updated),
                self._ledger_view(transaction_record, project_id),
                True,
            )

    def jobs(
        self,
        project_id: str,
        *,
        wallet_address: str | None = None,
        credential_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        project_id = _resource_id(project_id, "project_id")
        limit = _integer(limit, "limit", minimum=1, maximum=100)
        with self._lock:
            self._authorize_read(project_id, wallet_address, credential_id)
            records = [
                item for item in self._state["jobs"].values() if item["project_id"] == project_id
            ]
            records.sort(key=lambda value: (value["created_at"], value["job_id"]), reverse=True)
            return [self._job_view(item) for item in records[:limit]]

    def job(
        self,
        project_id: str,
        job_id: str,
        *,
        wallet_address: str | None = None,
        credential_id: str | None = None,
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        job_id = _resource_id(job_id, "job_id")
        with self._lock:
            self._authorize_read(project_id, wallet_address, credential_id)
            job = self._state["jobs"].get(job_id)
            if job is None or job["project_id"] != project_id:
                raise ComputeStoreError("job not found")
            return self._job_view(job)

    def balance(self, project_id: str, wallet_address: str) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        wallet = _wallet(wallet_address)
        with self._lock:
            self._require_role(project_id, wallet, ALLOWED_ROLES)
            return self._balance_view(project_id)

    def ledger(
        self, project_id: str, wallet_address: str, *, limit: int = 100
    ) -> dict[str, Any]:
        project_id = _resource_id(project_id, "project_id")
        wallet = _wallet(wallet_address)
        limit = _integer(limit, "limit", minimum=1, maximum=100)
        with self._lock:
            self._require_role(project_id, wallet, ALLOWED_ROLES)
            records = [
                item for item in self._state["ledger"] if item["project_id"] == project_id
            ][-limit:]
            records.reverse()
            return {
                "surface": "compute_ledger",
                "schema_version": 1,
                "project_id": project_id,
                "balance": self._balance_view(project_id),
                "transactions": [self._ledger_view(item, project_id) for item in records],
                "append_only": True,
                "double_entry": True,
                "currency": "service_credit",
                "transferable": False,
                "redeemable": False,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _transition_job(
        self,
        project_id: str,
        job_id: str,
        *,
        action: str,
        payload: dict[str, Any],
        idempotency_key: str,
        occurred_at: int,
    ) -> tuple[dict[str, Any], bool]:
        project_id = _resource_id(project_id, "project_id")
        job_id = _resource_id(job_id, "job_id")
        key = _idempotency_key(idempotency_key)
        timestamp = _timestamp(occurred_at)
        request = {"project_id": project_id, "job_id": job_id, "action": action, **payload}
        with self._lock:
            job = self._state["jobs"].get(job_id)
            if job is None or job["project_id"] != project_id:
                raise ComputeStoreError("job not found")
            idem_key = _idem_hash(f"job_{action}", project_id, job_id, key)
            existing = self._idempotent_result(idem_key, request)
            if existing is not None:
                return self._job_view(self._state["jobs"][job_id]), False
            candidate = self._copy_state()
            updated = candidate["jobs"][job_id]
            if timestamp < updated["updated_at"]:
                raise ComputeStoreError("job transition timestamp regressed")
            if action == "start":
                if updated["status"] != "queued":
                    raise ComputeStoreError("only a queued job can start")
                updated["status"] = "running"
                updated["started_at"] = timestamp
                # Dispatch is deliberately not implied by an internal state marker.
                updated["dispatch_status"] = "not_dispatched"
            elif action == "settle":
                if updated["status"] not in {"queued", "running"}:
                    raise ComputeStoreError("only an open job can settle")
                actual = payload["actual_credits"]
                reserved = updated["max_credits"]
                if actual > reserved:
                    raise ComputeCapExceeded("actual credits exceed the hard reservation")
                refund = reserved - actual
                self._append_transaction(
                    candidate,
                    kind="job_settle",
                    project_id=project_id,
                    job_id=job_id,
                    amount=actual,
                    postings=[
                        {"account": f"project:{project_id}:reserved", "delta": -reserved},
                        {"account": "system:service_revenue", "delta": actual},
                        {"account": f"project:{project_id}:available", "delta": refund},
                    ],
                    authority="operator_runtime",
                    created_at=timestamp,
                    idempotency_key=key,
                    request=request,
                    settlement_status="provisional_internal_metering",
                )
                updated["status"] = "succeeded"
                updated["actual_credits"] = actual
                updated["released_credits"] = refund
                updated["completed_at"] = timestamp
                updated["metering_source"] = payload["metering_source"]
                updated["usage_receipt_hash"] = payload["usage_receipt_hash"]
                updated["settlement_authority"] = "operator_runtime_not_provider_authoritative"
            elif action == "release":
                if updated["status"] not in {"queued", "running"}:
                    raise ComputeStoreError("only an open job reservation can release")
                reserved = updated["max_credits"]
                self._append_transaction(
                    candidate,
                    kind="job_release",
                    project_id=project_id,
                    job_id=job_id,
                    amount=reserved,
                    postings=[
                        {"account": f"project:{project_id}:reserved", "delta": -reserved},
                        {"account": f"project:{project_id}:available", "delta": reserved},
                    ],
                    authority="operator_runtime",
                    created_at=timestamp,
                    idempotency_key=key,
                    request=request,
                    settlement_status="released_without_service_settlement",
                )
                updated["status"] = payload["terminal_status"]
                updated["actual_credits"] = 0
                updated["released_credits"] = reserved
                updated["completed_at"] = timestamp
                updated["settlement_authority"] = "operator_runtime_release"
            else:
                raise ComputeStoreError("unsupported job transition")
            updated["updated_at"] = timestamp
            self._put_idempotency(
                candidate,
                idem_key,
                request,
                result_kind="job",
                result_id=job_id,
                created_at=timestamp,
            )
            self._commit(candidate)
            return self._job_view(updated), True

    def _append_transaction(
        self,
        state: dict[str, Any],
        *,
        kind: str,
        project_id: str,
        job_id: str | None,
        amount: int,
        postings: list[dict[str, Any]],
        authority: str,
        created_at: int,
        idempotency_key: str,
        request: dict[str, Any],
        settlement_status: str,
    ) -> dict[str, Any]:
        if len(state["ledger"]) >= MAX_LEDGER_TRANSACTIONS:
            raise ComputeCapExceeded("Compute ledger is full")
        if sum(posting["delta"] for posting in postings) != 0:
            raise ComputeStoreError("ledger postings must balance to zero")
        sequence = state["sequence"] + 1
        previous_hash = state["ledger"][-1]["transaction_hash"] if state["ledger"] else "0" * 64
        body = {
            "transaction_id": _new_id("txn"),
            "sequence": sequence,
            "kind": kind,
            "project_id": project_id,
            "job_id": job_id,
            "amount_credits": amount,
            "postings": postings,
            "authority": authority,
            "created_at": created_at,
            "idempotency_key_hash": _hash_text("compute_ledger_idempotency", idempotency_key),
            "request_hash": _hash_json("compute_ledger_request", request),
            "previous_hash": previous_hash,
            "settlement_status": settlement_status,
        }
        body["transaction_hash"] = _hash_json("compute_ledger_transaction", body)
        state["sequence"] = sequence
        state["ledger"].append(body)
        return body

    def _require_open_job_reservation(
        self, project_id: str, job_id: str, expected_credits: int
    ) -> None:
        """Fail closed unless the job has exactly one still-open reservation."""

        records = [
            transaction
            for transaction in self._state["ledger"]
            if transaction["project_id"] == project_id
            and transaction["job_id"] == job_id
        ]
        reserves = [item for item in records if item["kind"] == "job_reserve"]
        closes = [
            item
            for item in records
            if item["kind"] in {"job_settle", "job_release", "job_cancel"}
        ]
        if (
            len(records) != 1
            or len(reserves) != 1
            or reserves[0]["amount_credits"] != expected_credits
            or closes
        ):
            raise ComputeStoreCorruptError(
                "job reservation ledger is inconsistent"
            )

    def _balances(self, project_id: str) -> dict[str, int]:
        available = 0
        reserved = 0
        for transaction in self._state["ledger"]:
            for posting in transaction["postings"]:
                if posting["account"] == f"project:{project_id}:available":
                    available += posting["delta"]
                elif posting["account"] == f"project:{project_id}:reserved":
                    reserved += posting["delta"]
        return {"available_credits": available, "reserved_credits": reserved}

    def _balance_view(self, project_id: str) -> dict[str, Any]:
        balance = self._balances(project_id)
        return {
            "surface": "compute_credit_balance",
            "schema_version": 1,
            "project_id": project_id,
            **balance,
            "total_service_credits": balance["available_credits"] + balance["reserved_credits"],
            "unit": "service_credit",
            "nominal_usd_cents_per_credit": 1,
            "transferable": False,
            "redeemable": False,
            "onchain_token": False,
        }

    def _daily_budgeted_credits(
        self, project_id: str, *, day: int, credential_id: str | None = None
    ) -> int:
        total = 0
        for job in self._state["jobs"].values():
            if job["project_id"] != project_id or job["created_at"] // 86_400 != day:
                continue
            if credential_id is not None and job["credential_id"] != credential_id:
                continue
            if job["status"] in {"failed", "canceled"}:
                continue
            total += job["actual_credits"] if job["status"] == "succeeded" else job["max_credits"]
        return total

    def _authorize_read(
        self,
        project_id: str,
        wallet_address: str | None,
        credential_id: str | None,
    ) -> None:
        if wallet_address is not None:
            self._require_role(project_id, _wallet(wallet_address), ALLOWED_ROLES)
            return
        if credential_id is not None:
            credential = self._credential(project_id, _resource_id(credential_id, "credential_id"))
            if credential["status"] != "active" or "jobs:read" not in credential["scopes"]:
                raise ComputeAuthorizationError("credential cannot read jobs")
            return
        raise ComputeAuthorizationError("project read authentication is required")

    def _project_view(self, project_id: str, wallet: str) -> dict[str, Any]:
        project = self._project_record(project_id)
        role = project["members"].get(wallet)
        if role not in ALLOWED_ROLES:
            raise ComputeAuthorizationError("wallet is not a project member")
        return {
            "project_id": project_id,
            "name": project["name"],
            "role": role,
            "policy": copy.deepcopy(project["policy"]),
            "members": [
                {"address": address, "role": member_role}
                for address, member_role in sorted(project["members"].items())
            ],
            "created_at": project["created_at"],
            "updated_at": project["updated_at"],
            "credit_instrument": "closed_loop_nontransferable_service_credit",
            "provider_dispatch_enabled": False,
        }

    @staticmethod
    def _device_view(device: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "device_id": device["device_id"],
            "project_id": device["project_id"],
            "label": device["label"],
            "kind": device["kind"],
            "public_key_hash": device["public_key_hash"],
            "status": device["status"],
            "registered_at": device["registered_at"],
            "revoked_at": device["revoked_at"],
            "binding": "encrypted_delivery_only_not_hardware_attestation",
            "public_key_returned": False,
        }

    @staticmethod
    def _credential_view(credential: Mapping[str, Any], *, now: int) -> dict[str, Any]:
        status = credential["status"]
        if status == "active" and now >= credential["expires_at"]:
            status = "expired"
        return {
            "credential_id": credential["credential_id"],
            "project_id": credential["project_id"],
            "device_id": credential["device_id"],
            "name": credential["name"],
            "prefix": credential["prefix"],
            "scopes": list(credential["scopes"]),
            "daily_credit_cap": credential["daily_credit_cap"],
            "generation": credential["generation"],
            "status": status,
            "issued_at": credential["issued_at"],
            "expires_at": credential["expires_at"],
            "last_used_at": credential["last_used_at"],
            "rotated_at": credential["rotated_at"],
            "revoked_at": credential["revoked_at"],
            "plaintext_token_stored": False,
            "upstream_tinker_key_exposed": False,
        }

    @staticmethod
    def _job_view(job: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: copy.deepcopy(job[key])
            for key in (
                "job_id",
                "project_id",
                "name",
                "operation",
                "model",
                "recipe",
                "max_credits",
                "actual_credits",
                "released_credits",
                "result_policy",
                "environment_version",
                "status",
                "dispatch_status",
                "backend_capability",
                "credential_id",
                "created_at",
                "updated_at",
                "started_at",
                "completed_at",
                "metering_source",
                "usage_receipt_hash",
                "settlement_authority",
            )
        } | {
            "provider_authoritative_settlement": False,
            "raw_input_persisted": False,
            "raw_output_persisted": False,
        }

    @staticmethod
    def _ledger_view(transaction: Mapping[str, Any], project_id: str) -> dict[str, Any]:
        return {
            "transaction_id": transaction["transaction_id"],
            "sequence": transaction["sequence"],
            "kind": transaction["kind"],
            "project_id": project_id,
            "job_id": transaction["job_id"],
            "amount_credits": transaction["amount_credits"],
            "postings": copy.deepcopy(transaction["postings"]),
            "authority": transaction["authority"],
            "created_at": transaction["created_at"],
            "settlement_status": transaction["settlement_status"],
            "transaction_hash": transaction["transaction_hash"],
            "previous_hash": transaction["previous_hash"],
        }

    def _project_record(self, project_id: str) -> dict[str, Any]:
        project = self._state["projects"].get(project_id)
        if project is None:
            raise ComputeStoreError("project not found")
        return project

    def _require_role(
        self, project_id: str, wallet: str, allowed_roles: frozenset[str]
    ) -> dict[str, Any]:
        project = self._project_record(project_id)
        if project["members"].get(wallet) not in allowed_roles:
            raise ComputeAuthorizationError("wallet lacks the required project role")
        return project

    def _device(self, project_id: str, device_id: str) -> dict[str, Any]:
        device = self._state["devices"].get(device_id)
        if device is None or device["project_id"] != project_id:
            raise ComputeStoreError("device not found")
        return device

    def _credential(self, project_id: str, credential_id: str) -> dict[str, Any]:
        credential = self._state["credentials"].get(credential_id)
        if credential is None or credential["project_id"] != project_id:
            raise ComputeStoreError("credential not found")
        return credential

    def _ledger_by_id(self, transaction_id: str) -> dict[str, Any]:
        for transaction in self._state["ledger"]:
            if transaction["transaction_id"] == transaction_id:
                return self._ledger_view(transaction, transaction["project_id"])
        raise ComputeStoreCorruptError("idempotency points to missing ledger transaction")

    def _idempotent_result(
        self, idem_key: str, request: dict[str, Any]
    ) -> dict[str, Any] | None:
        record = self._state["idempotency"].get(idem_key)
        if record is None:
            return None
        if record["request_hash"] != _hash_json("compute_idempotent_request", request):
            raise ComputeIdempotencyConflict(
                "idempotency key was already used for a different request"
            )
        return record

    @staticmethod
    def _put_idempotency(
        state: dict[str, Any],
        idem_key: str,
        request: dict[str, Any],
        *,
        result_kind: str,
        result_id: str,
        created_at: int,
    ) -> None:
        if len(state["idempotency"]) >= MAX_IDEMPOTENCY_RECORDS:
            raise ComputeCapExceeded("Compute idempotency store is full")
        state["idempotency"][idem_key] = {
            "request_hash": _hash_json("compute_idempotent_request", request),
            "result_kind": result_kind,
            "result_id": result_id,
            "created_at": created_at,
        }

    def _copy_state(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    def _commit(self, candidate: dict[str, Any]) -> None:
        self._validate_state(candidate)
        self._persist(candidate)
        self._state = candidate

    def _persist(self, payload: dict[str, Any]) -> None:
        canonical_payload = _canonical_json(payload)
        root = {
            "surface": "compute_console_store",
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
            raise ComputeCapExceeded("Compute store exceeds maximum size")
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
                raise ComputeStoreCorruptError("Compute store exceeds maximum size")
            root = json.loads(self.path.read_text(encoding="utf-8"))
        except ComputeStoreCorruptError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ComputeStoreCorruptError("Compute store cannot be decoded") from exc
        if not isinstance(root, dict) or set(root) != self._ROOT_FIELDS:
            raise ComputeStoreCorruptError("Compute store root schema is invalid")
        if root["surface"] != "compute_console_store" or root["schema_version"] != SCHEMA_VERSION:
            raise ComputeStoreCorruptError("Compute store surface or version is invalid")
        payload = root["payload"]
        integrity = root["integrity"]
        if (
            not isinstance(payload, dict)
            or not isinstance(integrity, dict)
            or set(integrity) != {"algorithm", "value"}
            or integrity["algorithm"] != "HMAC-SHA256"
            or not isinstance(integrity["value"], str)
        ):
            raise ComputeStoreCorruptError("Compute store integrity envelope is invalid")
        expected = hmac.new(
            self._integrity_key, _canonical_json(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(integrity["value"], expected):
            raise ComputeStoreCorruptError("Compute store integrity verification failed")
        self._validate_state(payload)
        return payload

    def _validate_state(self, state: dict[str, Any]) -> None:
        try:
            self._validate_state_inner(state)
        except ComputeStoreCorruptError:
            raise
        except ComputeStoreError as exc:
            raise ComputeStoreCorruptError(str(exc)) from exc

    def _validate_state_inner(self, state: dict[str, Any]) -> None:
        if not isinstance(state, dict) or set(state) != self._PAYLOAD_FIELDS:
            raise ComputeStoreCorruptError("Compute payload schema is invalid")
        sequence = _integer(state["sequence"], "sequence", minimum=0, maximum=MAX_LEDGER_TRANSACTIONS)
        for name, maximum in (
            ("projects", MAX_PROJECTS),
            ("devices", MAX_PROJECTS * MAX_DEVICES_PER_PROJECT),
            ("credentials", MAX_PROJECTS * MAX_CREDENTIALS_PER_PROJECT),
            ("jobs", MAX_JOBS),
            ("idempotency", MAX_IDEMPOTENCY_RECORDS),
        ):
            if not isinstance(state[name], dict) or len(state[name]) > maximum:
                raise ComputeStoreCorruptError(f"Compute {name} collection is invalid")
        if not isinstance(state["ledger"], list) or len(state["ledger"]) > MAX_LEDGER_TRANSACTIONS:
            raise ComputeStoreCorruptError("Compute ledger collection is invalid")
        for project_id, project in state["projects"].items():
            _resource_id(project_id, "project_id")
            required = {"project_id", "name", "owner_address", "members", "policy", "created_at", "updated_at"}
            if not isinstance(project, dict) or set(project) != required or project["project_id"] != project_id:
                raise ComputeStoreCorruptError("project record schema is invalid")
            owner = _wallet(project["owner_address"])
            _name(project["name"], "project name")
            _timestamp(project["created_at"])
            _timestamp(project["updated_at"])
            if not isinstance(project["members"], dict) or not 1 <= len(project["members"]) <= MAX_MEMBERS_PER_PROJECT:
                raise ComputeStoreCorruptError("project members are invalid")
            for member, role in project["members"].items():
                _wallet(member)
                if role not in ALLOWED_ROLES:
                    raise ComputeStoreCorruptError("project member role is invalid")
            if project["members"].get(owner) != "owner":
                raise ComputeStoreCorruptError("project owner membership is invalid")
            if project["policy"] != DEFAULT_POLICY:
                raise ComputeStoreCorruptError("project policy is outside configured bounds")
        for device_id, device in state["devices"].items():
            _resource_id(device_id, "device_id")
            required = {"device_id", "project_id", "label", "kind", "public_key_hex", "public_key_hash", "status", "registered_by", "registered_at", "revoked_at"}
            if not isinstance(device, dict) or set(device) != required or device["device_id"] != device_id:
                raise ComputeStoreCorruptError("device record schema is invalid")
            if device["project_id"] not in state["projects"]:
                raise ComputeStoreCorruptError("device references missing project")
            _name(device["label"], "device label")
            if device["kind"] not in ALLOWED_DEVICE_KINDS or device["status"] not in {"active", "revoked"}:
                raise ComputeStoreCorruptError("device kind or status is invalid")
            if not _X25519_RE.fullmatch(device["public_key_hex"]) or device["public_key_hash"] != _hash_text("compute_device_key", device["public_key_hex"]):
                raise ComputeStoreCorruptError("device key commitment is invalid")
            _wallet(device["registered_by"])
            _timestamp(device["registered_at"])
            if device["revoked_at"] is not None:
                _timestamp(device["revoked_at"])
        for credential_id, credential in state["credentials"].items():
            _resource_id(credential_id, "credential_id")
            required = {"credential_id", "project_id", "device_id", "name", "prefix", "scopes", "daily_credit_cap", "generation", "jwt_id_hash", "status", "issued_by", "issued_at", "expires_at", "last_used_at", "rotated_at", "revoked_at"}
            if not isinstance(credential, dict) or set(credential) != required or credential["credential_id"] != credential_id:
                raise ComputeStoreCorruptError("credential record schema is invalid")
            if credential["project_id"] not in state["projects"] or credential["device_id"] not in state["devices"] or state["devices"][credential["device_id"]]["project_id"] != credential["project_id"]:
                raise ComputeStoreCorruptError("credential references invalid project or device")
            _name(credential["name"], "credential name")
            _scopes(credential["scopes"])
            _integer(credential["daily_credit_cap"], "daily_credit_cap", minimum=1, maximum=1_000_000)
            _integer(credential["generation"], "generation", minimum=1, maximum=1_000_000)
            if not _HEX64_RE.fullmatch(credential["jwt_id_hash"]) or credential["status"] not in {"active", "revoked"}:
                raise ComputeStoreCorruptError("credential commitment or status is invalid")
            _wallet(credential["issued_by"])
            for field in ("issued_at", "expires_at"):
                _timestamp(credential[field])
            for field in ("last_used_at", "rotated_at", "revoked_at"):
                if credential[field] is not None:
                    _timestamp(credential[field])
        for job_id, job in state["jobs"].items():
            _resource_id(job_id, "job_id")
            required = {"job_id", "project_id", "name", "operation", "model", "recipe", "max_credits", "actual_credits", "released_credits", "result_policy", "environment_version", "status", "dispatch_status", "backend_capability", "actor_kind", "actor_commitment", "credential_id", "created_at", "updated_at", "started_at", "completed_at", "metering_source", "usage_receipt_hash", "settlement_authority"}
            if not isinstance(job, dict) or set(job) != required or job["job_id"] != job_id or job["project_id"] not in state["projects"]:
                raise ComputeStoreCorruptError("job record schema is invalid")
            _name(job["name"], "job name")
            if job["operation"] not in ALLOWED_OPERATIONS or job["model"] not in ALLOWED_MODELS or job["recipe"] not in ALLOWED_RECIPES[job["operation"]]:
                raise ComputeStoreCorruptError("job operation/model/recipe is invalid")
            if job["status"] not in ALLOWED_JOB_STATES or job["dispatch_status"] != "not_dispatched" or job["result_policy"] not in ALLOWED_RESULT_POLICIES:
                raise ComputeStoreCorruptError("job state or policy is invalid")
            _integer(job["max_credits"], "max_credits", minimum=1, maximum=500)
            for field in ("actual_credits", "released_credits"):
                if job[field] is not None:
                    _integer(job[field], field, minimum=0, maximum=500)
            _timestamp(job["created_at"])
            _timestamp(job["updated_at"])
            for field in ("started_at", "completed_at"):
                if job[field] is not None:
                    _timestamp(job[field])
        previous_hash = "0" * 64
        if sequence != len(state["ledger"]):
            raise ComputeStoreCorruptError("ledger sequence does not match transaction count")
        balances: dict[str, dict[str, int]] = {}
        for position, transaction in enumerate(state["ledger"], start=1):
            required = {"transaction_id", "sequence", "kind", "project_id", "job_id", "amount_credits", "postings", "authority", "created_at", "idempotency_key_hash", "request_hash", "previous_hash", "settlement_status", "transaction_hash"}
            if not isinstance(transaction, dict) or set(transaction) != required or transaction["sequence"] != position or transaction["previous_hash"] != previous_hash:
                raise ComputeStoreCorruptError("ledger transaction schema or chain is invalid")
            if transaction["project_id"] not in state["projects"] or not _ID_RE.fullmatch(transaction["transaction_id"]):
                raise ComputeStoreCorruptError("ledger transaction reference is invalid")
            if not isinstance(transaction["postings"], list) or not 2 <= len(transaction["postings"]) <= 3:
                raise ComputeStoreCorruptError("ledger postings are invalid")
            if sum(_integer(posting.get("delta"), "posting delta", minimum=-10_000_000, maximum=10_000_000) for posting in transaction["postings"] if isinstance(posting, dict)) != 0:
                raise ComputeStoreCorruptError("ledger postings do not balance")
            expected_hash = _hash_json("compute_ledger_transaction", {key: value for key, value in transaction.items() if key != "transaction_hash"})
            if transaction["transaction_hash"] != expected_hash:
                raise ComputeStoreCorruptError("ledger transaction hash is invalid")
            previous_hash = transaction["transaction_hash"]
            project_id = transaction["project_id"]
            bucket = balances.setdefault(project_id, {"available": 0, "reserved": 0})
            for posting in transaction["postings"]:
                if not isinstance(posting, dict) or set(posting) != {"account", "delta"} or not isinstance(posting["account"], str):
                    raise ComputeStoreCorruptError("ledger posting schema is invalid")
                if posting["account"] == f"project:{project_id}:available":
                    bucket["available"] += posting["delta"]
                elif posting["account"] == f"project:{project_id}:reserved":
                    bucket["reserved"] += posting["delta"]
                elif posting["account"] not in {"system:testnet_grant_pool", "system:service_revenue"}:
                    raise ComputeStoreCorruptError("ledger account is unsupported")
            if bucket["available"] < 0 or bucket["reserved"] < 0:
                raise ComputeStoreCorruptError("ledger produces a negative project balance")
        for idem_key, record in state["idempotency"].items():
            if not _HEX64_RE.fullmatch(idem_key) or not isinstance(record, dict) or set(record) != {"request_hash", "result_kind", "result_id", "created_at"} or not _HEX64_RE.fullmatch(record["request_hash"]):
                raise ComputeStoreCorruptError("idempotency record is invalid")
            _resource_id(record["result_id"], "idempotency result_id")
            _timestamp(record["created_at"])


def _wallet(value: Any) -> str:
    try:
        return normalize_wallet_address(str(value))
    except WalletAuthError as exc:
        raise ComputeStoreError(str(exc)) from exc


def _resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ComputeStoreError(f"{label} is malformed")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ComputeStoreError(f"{label} is invalid")
    normalized = value.strip()
    if not _NAME_RE.fullmatch(normalized):
        raise ComputeStoreError(f"{label} is invalid")
    return normalized


def _scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ComputeStoreError("credential scopes are invalid")
    scopes = tuple(sorted(set(value)))
    if not scopes or any(item not in SUPPORTED_COMPUTE_CREDENTIAL_SCOPES for item in scopes):
        raise ComputeStoreError("credential scopes are invalid")
    return scopes


def _timestamp(value: Any) -> int:
    return _integer(value, "timestamp", minimum=0, maximum=MAX_TIMESTAMP)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ComputeStoreError(f"{label} is outside the supported range")
    return value


def _idempotency_key(value: Any) -> str:
    if not isinstance(value, str) or not _IDEMPOTENCY_RE.fullmatch(value):
        raise ComputeStoreError("idempotency_key is malformed or too short")
    return value


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(12)}"


def _idem_hash(namespace: str, *parts: str) -> str:
    return _hash_json(namespace, list(parts))


def _hash_text(prefix: str, value: str) -> str:
    return hashlib.sha256(prefix.encode() + b":" + value.encode()).hexdigest()


def _hash_json(prefix: str, value: Any) -> str:
    return hashlib.sha256(prefix.encode() + b":" + _canonical_json(value)).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
