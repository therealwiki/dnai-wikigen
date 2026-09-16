"""Integrity-protected device credentials for one Arena challenge version.

This store is intentionally separate from the Compute Console and from the
Arena submission queue.  It persists public device keys, token commitments,
revocation state, and a conservative per-day submission-attempt counter.  It
never persists plaintext bearer tokens, candidate source, ciphertext, scores,
or upstream provider credentials.

Every operation holds a same-directory process lock and reloads the durable
state before inspecting it. Writes are copy-on-write, HMAC authenticated,
fsynced, and atomically replaced.

The HMAC detects unauthorized modification, not replay of an older valid file.
Consequently this store is modeled authentication infrastructure only. A live
credential boundary requires rollback-resistant storage or an externally
anchored monotonic high-water mark before it can protect revocation or caps.
"""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping

from tinker_delegate.arena_auth import (
    ARENA_AGENT_SCOPES,
    ARENA_SUBMIT_SCOPE,
    ArenaAgentCredentialClaims,
    ArenaAuthError,
    normalize_challenge_id,
    normalize_challenge_version,
    validate_arena_agent_device_public_key,
)
from tinker_delegate.wallet_auth import WalletAuthError, normalize_wallet_address


SCHEMA_VERSION = 1
MAX_STORE_BYTES = 4 * 1024 * 1024
EMERGENCY_MUTATION_HEADROOM_BYTES = 128 * 1024
MAX_DEVICES = 4_096
MAX_CREDENTIALS = 8_192
MAX_CREDENTIALS_PER_OWNER_CHALLENGE = 128
MAX_TTL_SECONDS = 86_400
MAX_DAILY_SUBMISSION_CAP = 32
MAX_TIMESTAMP = 4_102_444_800

_RESOURCE_ID = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_X25519 = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_DEVICE_KINDS = frozenset({"developer_device", "ci_service", "autonomous_agent"})


class ArenaAgentStoreError(ValueError):
    """Raised when a credential-store operation fails a bounded check."""


class ArenaAgentStoreCorruptError(ArenaAgentStoreError):
    """Raised when persisted state fails schema or integrity verification."""


class ArenaAgentAuthorizationError(ArenaAgentStoreError):
    """Raised when a wallet or credential lacks exact Arena authority."""


class ArenaAgentCapExceeded(ArenaAgentStoreError):
    """Raised when an owner or credential reaches a configured hard cap."""


class ArenaAgentDailyCapExceeded(ArenaAgentCapExceeded):
    """Raised only for a credential's UTC-day submission-attempt cap."""


class ArenaAgentStoreCapacityError(ArenaAgentCapExceeded):
    """Raised for structural record/byte capacity, never a daily retry gate."""


class ArenaAgentStoreUnavailableError(ArenaAgentStoreError):
    """Raised when durable storage cannot be opened, locked, or created."""


class ArenaAgentStore:
    """Bounded durable state for challenge-version-scoped agent credentials."""

    _ROOT_FIELDS = frozenset({"surface", "schema_version", "payload", "integrity"})
    _PAYLOAD_FIELDS = frozenset({"devices", "credentials"})

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        self.path = Path(path).expanduser().absolute()
        if not self.path.name or self.path.name in {".", ".."}:
            raise ArenaAgentStoreError("Arena agent store path is invalid")
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise ArenaAgentStoreError(
                "Arena agent store integrity key must be at least 32 bytes"
            )
        self._integrity_key = bytes(integrity_key)
        self._lock = threading.RLock()
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._operation_depth = 0
        self._operation_fd: int | None = None
        self._state_file_identity: tuple[int, int] | None = None
        self._initialized = False
        self._state: dict[str, Any] = {"devices": {}, "credentials": {}}
        with self._operation(refresh=False):
            if self._lstat_optional(self.path) is not None:
                self._state = self._load()
            else:
                self._persist(self._state)
        self._initialized = True

    def issue_device_credential(
        self,
        *,
        owner_address: str,
        challenge_id: str,
        challenge_version: str,
        device_id: str,
        credential_id: str,
        label: str,
        kind: str,
        public_key_hex: str,
        name: str,
        scopes: tuple[str, ...],
        daily_submission_cap: int,
        generation: int,
        jwt_id_hash: str,
        issued_at: int,
        expires_at: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        owner = _wallet(owner_address)
        challenge = _challenge_id(challenge_id)
        version = _challenge_version(challenge_version)
        device_id = _resource_id(device_id, "device_id")
        credential_id = _resource_id(credential_id, "credential_id")
        label = _name(label, "device label")
        name = _name(name, "credential name")
        if kind not in _DEVICE_KINDS:
            raise ArenaAgentStoreError("Arena agent device kind is unsupported")
        try:
            public_key, _ = validate_arena_agent_device_public_key(public_key_hex)
        except ArenaAuthError as exc:
            raise ArenaAgentStoreError(str(exc)) from exc
        normalized_scopes = _scopes(scopes)
        cap = _integer(
            daily_submission_cap,
            "daily_submission_cap",
            minimum=1,
            maximum=MAX_DAILY_SUBMISSION_CAP,
        )
        generation = _integer(generation, "generation", minimum=1, maximum=1)
        if not _HEX64.fullmatch(jwt_id_hash):
            raise ArenaAgentStoreError("Arena agent credential token commitment is malformed")
        issued_at = _timestamp(issued_at)
        expires_at = _timestamp(expires_at)
        if expires_at <= issued_at or expires_at - issued_at > MAX_TTL_SECONDS:
            raise ArenaAgentStoreError("Arena agent credential expiry is invalid")

        with self._operation():
            candidate = self._copy_state()
            self._compact_expired(candidate, now=issued_at)
            if device_id in candidate["devices"] or credential_id in candidate["credentials"]:
                raise ArenaAgentStoreError("Arena agent credential identifier collision")
            if len(candidate["devices"]) >= MAX_DEVICES or len(candidate["credentials"]) >= MAX_CREDENTIALS:
                raise ArenaAgentStoreCapacityError("Arena agent credential store is full")
            owner_credentials = [
                item
                for item in candidate["credentials"].values()
                if item["owner_address"] == owner
                and item["challenge_id"] == challenge
                and item["challenge_version"] == version
            ]
            if len(owner_credentials) >= MAX_CREDENTIALS_PER_OWNER_CHALLENGE:
                raise ArenaAgentStoreCapacityError(
                    "Arena agent credential limit reached for this challenge version"
                )
            public_key_hash = _hash_text("arena_agent_device_key", public_key)
            if any(
                item["owner_address"] == owner
                and item["challenge_id"] == challenge
                and item["challenge_version"] == version
                and item["public_key_hash"] == public_key_hash
                for item in candidate["devices"].values()
            ):
                raise ArenaAgentStoreError(
                    "Arena agent device key is already registered for this challenge version"
                )
            device = {
                "device_id": device_id,
                "owner_address": owner,
                "challenge_id": challenge,
                "challenge_version": version,
                "label": label,
                "kind": kind,
                "public_key_hex": public_key,
                "public_key_hash": public_key_hash,
                "status": "active",
                "registered_at": issued_at,
                "revoked_at": None,
            }
            credential = {
                "credential_id": credential_id,
                "device_id": device_id,
                "owner_address": owner,
                "challenge_id": challenge,
                "challenge_version": version,
                "name": name,
                "prefix": f"wka_{credential_id[-6:]}",
                "scopes": list(normalized_scopes),
                "daily_submission_cap": cap,
                "generation": generation,
                "jwt_id_hash": jwt_id_hash,
                "status": "active",
                "issued_at": issued_at,
                "expires_at": expires_at,
                "last_used_at": None,
                "rotated_at": None,
                "revoked_at": None,
                "submission_usage_day": None,
                "submission_usage_updated_at": None,
                "submission_attempt_hashes": [],
            }
            candidate["devices"][device_id] = device
            candidate["credentials"][credential_id] = credential
            self._commit(candidate)
            return self._device_view(device), self._credential_view(credential, now=issued_at)

    def list_credentials(
        self,
        *,
        owner_address: str,
        challenge_id: str,
        challenge_version: str,
        now: int,
    ) -> list[dict[str, Any]]:
        owner = _wallet(owner_address)
        challenge = _challenge_id(challenge_id)
        version = _challenge_version(challenge_version)
        now = _timestamp(now)
        with self._operation():
            return [
                self._credential_view(item, now=now)
                for item in sorted(
                    self._state["credentials"].values(),
                    key=lambda value: (value["issued_at"], value["credential_id"]),
                    reverse=True,
                )
                if item["owner_address"] == owner
                and item["challenge_id"] == challenge
                and item["challenge_version"] == version
            ]

    def credential_for_rotation(
        self,
        *,
        owner_address: str,
        challenge_id: str,
        challenge_version: str,
        credential_id: str,
        expected_generation: int,
        now: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        owner = _wallet(owner_address)
        challenge = _challenge_id(challenge_id)
        version = _challenge_version(challenge_version)
        credential_id = _resource_id(credential_id, "credential_id")
        expected_generation = _integer(
            expected_generation,
            "expected_generation",
            minimum=1,
            maximum=1_000_000,
        )
        now = _timestamp(now)
        with self._operation():
            credential = self._owned_credential(
                owner, challenge, version, credential_id
            )
            device = self._state["devices"].get(credential["device_id"])
            if (
                credential["status"] != "active"
                or credential["generation"] != expected_generation
                or now >= credential["expires_at"]
                or device is None
                or device["status"] != "active"
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential or device is inactive or superseded"
                )
            return copy.deepcopy(credential), copy.deepcopy(device)

    def rotate_credential(
        self,
        *,
        owner_address: str,
        challenge_id: str,
        challenge_version: str,
        credential_id: str,
        expected_generation: int,
        new_jwt_id_hash: str,
        issued_at: int,
        expires_at: int,
    ) -> dict[str, Any]:
        owner = _wallet(owner_address)
        challenge = _challenge_id(challenge_id)
        version = _challenge_version(challenge_version)
        credential_id = _resource_id(credential_id, "credential_id")
        expected_generation = _integer(
            expected_generation, "expected_generation", minimum=1, maximum=1_000_000
        )
        if not _HEX64.fullmatch(new_jwt_id_hash):
            raise ArenaAgentStoreError("Arena agent credential token commitment is malformed")
        issued_at = _timestamp(issued_at)
        expires_at = _timestamp(expires_at)
        if expires_at <= issued_at or expires_at - issued_at > MAX_TTL_SECONDS:
            raise ArenaAgentStoreError("Arena agent credential expiry is invalid")
        with self._operation():
            current = self._owned_credential(owner, challenge, version, credential_id)
            device = self._state["devices"].get(current["device_id"])
            if (
                current["status"] != "active"
                or current["generation"] != expected_generation
                or device is None
                or device["status"] != "active"
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential is inactive or superseded"
                )
            monotonic_floor = max(
                current["issued_at"], current["last_used_at"] or 0
            )
            if issued_at < monotonic_floor:
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential rotation time moved backward"
                )
            candidate = self._copy_state()
            updated = candidate["credentials"][credential_id]
            updated["generation"] = expected_generation + 1
            updated["jwt_id_hash"] = new_jwt_id_hash
            updated["issued_at"] = issued_at
            updated["expires_at"] = expires_at
            updated["rotated_at"] = issued_at
            # Rotation supersedes the bearer generation but deliberately keeps
            # the independent daily-attempt ledger. This field describes use
            # of the new bearer only, so a management action must not appear as
            # agent activity in the public projection.
            updated["last_used_at"] = None
            self._commit(candidate)
            return self._credential_view(updated, now=issued_at)

    def revoke_credential(
        self,
        *,
        owner_address: str,
        challenge_id: str,
        challenge_version: str,
        credential_id: str,
        revoked_at: int,
    ) -> dict[str, Any]:
        owner = _wallet(owner_address)
        challenge = _challenge_id(challenge_id)
        version = _challenge_version(challenge_version)
        credential_id = _resource_id(credential_id, "credential_id")
        revoked_at = _timestamp(revoked_at)
        with self._operation():
            current = self._owned_credential(owner, challenge, version, credential_id)
            if current["status"] == "revoked":
                return self._credential_view(current, now=revoked_at)
            if revoked_at < max(current["issued_at"], current["last_used_at"] or 0):
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential revocation time moved backward"
                )
            candidate = self._copy_state()
            updated = candidate["credentials"][credential_id]
            updated["status"] = "revoked"
            updated["revoked_at"] = revoked_at
            self._commit(candidate, allow_emergency_headroom=True)
            return self._credential_view(updated, now=revoked_at)

    def authorize_credential(
        self,
        claims: ArenaAgentCredentialClaims,
        *,
        required_scope: str,
        used_at: int,
        submission_idempotency_key: str | None = None,
        submission_request_commitment: str | None = None,
    ) -> dict[str, Any]:
        """Authorize an exact token generation and conservatively consume a cap.

        An exact idempotency-key + canonical-request pair counts once per UTC
        day. Reusing the key for a different payload is a distinct attempt, so
        it cannot bypass this gate while still causing downstream work. The cap
        deliberately counts admitted attempts even if a later gate fails.
        """

        if not isinstance(claims, ArenaAgentCredentialClaims):
            raise ArenaAgentAuthorizationError("Arena agent credential claims are invalid")
        if required_scope not in ARENA_AGENT_SCOPES:
            raise ArenaAgentAuthorizationError("unsupported Arena agent scope")
        used_at = _timestamp(used_at)
        if required_scope == ARENA_SUBMIT_SCOPE:
            if (
                not isinstance(submission_idempotency_key, str)
                or not _IDEMPOTENCY_KEY.fullmatch(submission_idempotency_key)
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent submission requires a bounded idempotency key"
                )
            if (
                not isinstance(submission_request_commitment, str)
                or not _HEX64.fullmatch(submission_request_commitment)
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent submission requires a canonical request commitment"
                )
        elif (
            submission_idempotency_key is not None
            or submission_request_commitment is not None
        ):
            raise ArenaAgentAuthorizationError(
                "Arena agent read authorization cannot consume a submission attempt"
            )

        with self._operation():
            credential = self._state["credentials"].get(claims.credential_id)
            device = self._state["devices"].get(claims.device_id)
            expected_jti = _hash_text("arena_agent_credential_jti", claims.jwt_id)
            if (
                credential is None
                or device is None
                or credential["status"] != "active"
                or device["status"] != "active"
                or credential["owner_address"] != claims.owner_address
                or credential["challenge_id"] != claims.challenge_id
                or credential["challenge_version"] != claims.challenge_version
                or credential["device_id"] != claims.device_id
                or credential["generation"] != claims.generation
                or credential["jwt_id_hash"] != expected_jti
                or tuple(credential["scopes"]) != claims.scopes
                or credential["daily_submission_cap"] != claims.daily_submission_cap
                or credential["expires_at"] != claims.expires_at
                or used_at >= credential["expires_at"]
                or required_scope not in credential["scopes"]
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential is inactive or superseded"
                )
            last_used_at = credential["last_used_at"]
            if used_at < credential["issued_at"] or (
                last_used_at is not None and used_at < last_used_at
            ):
                raise ArenaAgentAuthorizationError(
                    "Arena agent credential use time moved backward"
                )
            candidate = self._copy_state()
            updated = candidate["credentials"][claims.credential_id]
            updated["last_used_at"] = used_at
            if required_scope == ARENA_SUBMIT_SCOPE:
                day = used_at // 86_400
                recorded_day = updated["submission_usage_day"]
                if recorded_day is not None and day < recorded_day:
                    raise ArenaAgentAuthorizationError(
                        "Arena agent submission usage day moved backward"
                    )
                if recorded_day is None or day > recorded_day:
                    updated["submission_usage_day"] = day
                    updated["submission_usage_updated_at"] = used_at
                    updated["submission_attempt_hashes"] = []
                attempt_hash = _hash_json(
                    "arena_agent_submission_attempt",
                    {
                        "credential_id": claims.credential_id,
                        "idempotency_key": submission_idempotency_key,
                        "request_commitment": submission_request_commitment,
                    },
                )
                attempts = updated["submission_attempt_hashes"]
                if attempt_hash not in attempts:
                    if len(attempts) >= updated["daily_submission_cap"]:
                        raise ArenaAgentDailyCapExceeded(
                            "Arena agent daily submission-attempt cap reached"
                        )
                    attempts.append(attempt_hash)
                updated["submission_usage_updated_at"] = used_at
            self._commit(candidate)
            return self._credential_view(updated, now=used_at)

    def _owned_credential(
        self,
        owner: str,
        challenge: str,
        version: str,
        credential_id: str,
    ) -> dict[str, Any]:
        credential = self._state["credentials"].get(credential_id)
        if (
            credential is None
            or credential["owner_address"] != owner
            or credential["challenge_id"] != challenge
            or credential["challenge_version"] != version
        ):
            raise ArenaAgentAuthorizationError("Arena agent credential not found")
        return credential

    @staticmethod
    def _device_view(device: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "device_id": device["device_id"],
            "challenge_id": device["challenge_id"],
            "challenge_version": device["challenge_version"],
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
        usage_day = credential["submission_usage_day"]
        attempts = (
            len(credential["submission_attempt_hashes"])
            if usage_day is not None and now // 86_400 == usage_day
            else 0
        )
        return {
            "credential_id": credential["credential_id"],
            "device_id": credential["device_id"],
            "challenge_id": credential["challenge_id"],
            "challenge_version": credential["challenge_version"],
            "name": credential["name"],
            "prefix": credential["prefix"],
            "scopes": list(credential["scopes"]),
            "daily_submission_cap": credential["daily_submission_cap"],
            "submission_attempts_used_today": attempts,
            "generation": credential["generation"],
            "status": status,
            "issued_at": credential["issued_at"],
            "expires_at": credential["expires_at"],
            "last_used_at": credential["last_used_at"],
            "rotated_at": credential["rotated_at"],
            "revoked_at": credential["revoked_at"],
            "plaintext_token_stored": False,
            "cross_domain_authority": False,
            "product_status": "modeled",
            "execution_authority": False,
            "tdx_attestation": False,
        }

    def _copy_state(self) -> dict[str, Any]:
        return copy.deepcopy(self._state)

    @staticmethod
    def _compact_expired(state: dict[str, Any], *, now: int) -> None:
        """Remove only credentials whose bearer lifetime is already over.

        Revocation and quota tombstones remain until the original JWT expiry,
        after which token verification rejects the bearer independently of
        this store. Compaction runs inside the same locked issue transaction.
        """

        expired_ids = [
            credential_id
            for credential_id, credential in state["credentials"].items()
            if credential["expires_at"] <= now
        ]
        for credential_id in expired_ids:
            device_id = state["credentials"][credential_id]["device_id"]
            del state["credentials"][credential_id]
            state["devices"].pop(device_id, None)

    @contextmanager
    def _operation(self, *, refresh: bool = True):
        """Serialize one reload/read-or-write transaction across processes."""

        with self._lock:
            outermost = self._operation_depth == 0
            if outermost:
                fd = self._acquire_file_lock()
                self._operation_fd = fd
                try:
                    if refresh:
                        store_stat = self._lstat_optional(self.path)
                        if store_stat is None:
                            if self._initialized:
                                raise ArenaAgentStoreCorruptError(
                                    "Arena agent credential store disappeared"
                                )
                        else:
                            self._state = self._load()
                except Exception:
                    self._release_file_lock(fd)
                    self._operation_fd = None
                    raise
            self._operation_depth += 1
            try:
                yield
            finally:
                self._operation_depth -= 1
                if outermost:
                    fd = self._operation_fd
                    self._operation_fd = None
                    if fd is not None:
                        self._release_file_lock(fd)

    def _acquire_file_lock(self) -> int:
        self._require_safe_parent()
        common_flags = os.O_RDWR
        if hasattr(os, "O_CLOEXEC"):
            common_flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            common_flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            common_flags |= os.O_NONBLOCK
        fd: int | None = None
        created = False
        try:
            try:
                fd = os.open(
                    self._lock_path,
                    common_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                created = True
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
                fd = os.open(self._lock_path, common_flags)
            if created:
                os.fchmod(fd, 0o600)
            lock_stat = os.fstat(fd)
            self._require_safe_file_stat(lock_stat, label="Arena agent store lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            self._require_safe_parent()
            path_stat = self._lstat_optional(self._lock_path)
            if (
                path_stat is None
                or (path_stat.st_dev, path_stat.st_ino)
                != (lock_stat.st_dev, lock_stat.st_ino)
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent store lock changed while acquiring it"
                )
            return fd
        except OSError as exc:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise ArenaAgentStoreUnavailableError(
                "Arena agent durable store lock is unavailable"
            ) from exc
        except Exception:
            if fd is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                os.close(fd)
            raise

    @staticmethod
    def _release_file_lock(fd: int) -> None:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def _require_safe_parent(self) -> None:
        parent = self.path.parent
        if Path(os.path.realpath(parent)) != parent:
            raise ArenaAgentStoreCorruptError(
                "Arena agent store path traverses a symlinked ancestor"
            )
        try:
            parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            parent_stat = os.lstat(parent)
        except OSError as exc:
            raise ArenaAgentStoreUnavailableError(
                "Arena agent store parent directory is unavailable"
            ) from exc
        mode = stat.S_IMODE(parent_stat.st_mode)
        if (
            stat.S_ISLNK(parent_stat.st_mode)
            or not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or mode & 0o022
        ):
            raise ArenaAgentStoreCorruptError(
                "Arena agent store parent directory is aliased or unsafe"
            )
        if Path(os.path.realpath(parent)) != parent:
            raise ArenaAgentStoreCorruptError(
                "Arena agent store parent changed to a symlinked path"
            )

    @staticmethod
    def _require_safe_file_stat(value: os.stat_result, *, label: str) -> None:
        mode = stat.S_IMODE(value.st_mode)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.geteuid()
            or value.st_nlink != 1
            or mode & 0o077
            or mode & 0o600 != 0o600
        ):
            raise ArenaAgentStoreCorruptError(f"{label} ownership or mode is unsafe")

    @staticmethod
    def _lstat_optional(path: Path) -> os.stat_result | None:
        try:
            return os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise ArenaAgentStoreCorruptError(
                "Arena agent store path cannot be inspected"
            ) from exc

    def _commit(
        self,
        candidate: dict[str, Any],
        *,
        allow_emergency_headroom: bool = False,
    ) -> None:
        self._validate_state(candidate)
        self._persist(
            candidate,
            maximum_bytes=(
                MAX_STORE_BYTES
                if allow_emergency_headroom
                else MAX_STORE_BYTES - EMERGENCY_MUTATION_HEADROOM_BYTES
            ),
        )
        self._state = candidate

    def _persist(
        self,
        payload: dict[str, Any],
        *,
        maximum_bytes: int = MAX_STORE_BYTES,
    ) -> None:
        canonical_payload = _canonical_json(payload)
        root = {
            "surface": "arena_agent_credential_store",
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
        if len(encoded) > maximum_bytes:
            raise ArenaAgentStoreCapacityError(
                "Arena agent credential store exceeds maximum size"
            )
        self._require_safe_parent()
        existing = self._lstat_optional(self.path)
        if self._state_file_identity is None:
            if existing is not None:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential store appeared unexpectedly"
                )
        else:
            if existing is None:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential store disappeared before replacement"
                )
            self._require_safe_file_stat(
                existing, label="Arena agent credential store"
            )
            if (existing.st_dev, existing.st_ino) != self._state_file_identity:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential store changed before replacement"
                )
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self._require_safe_parent()
            current = self._lstat_optional(self.path)
            if self._state_file_identity is None:
                if current is not None:
                    raise ArenaAgentStoreCorruptError(
                        "Arena agent credential store appeared before replacement"
                    )
            elif (
                current is None
                or (current.st_dev, current.st_ino) != self._state_file_identity
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential store changed during replacement"
                )
            os.replace(temporary, self.path)
            stored = os.lstat(self.path)
            self._require_safe_file_stat(
                stored, label="Arena agent credential store"
            )
            self._state_file_identity = (stored.st_dev, stored.st_ino)
            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                directory_flags |= os.O_NOFOLLOW
            directory_fd = os.open(self.path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise

    def _load(self) -> dict[str, Any]:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.path, flags)
            try:
                before = os.fstat(fd)
                self._require_safe_file_stat(
                    before, label="Arena agent credential store"
                )
                if before.st_size <= 0 or before.st_size > MAX_STORE_BYTES:
                    raise ArenaAgentStoreCorruptError(
                        "Arena agent credential store is empty or oversized"
                    )
                chunks: list[bytes] = []
                remaining = MAX_STORE_BYTES + 1
                while remaining > 0:
                    chunk = os.read(fd, min(65_536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            path_stat = os.lstat(self.path)
            stable_before = (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            stable_after = (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            if (
                len(raw) > MAX_STORE_BYTES
                or stable_before != stable_after
                or (path_stat.st_dev, path_stat.st_ino)
                != (before.st_dev, before.st_ino)
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential store changed while reading"
                )
            self._require_safe_file_stat(
                path_stat, label="Arena agent credential store"
            )
            root = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except ArenaAgentStoreCorruptError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArenaAgentStoreCorruptError(
                "Arena agent credential store cannot be decoded"
            ) from exc
        if not isinstance(root, dict) or set(root) != self._ROOT_FIELDS:
            raise ArenaAgentStoreCorruptError("Arena agent store root schema is invalid")
        if (
            root["surface"] != "arena_agent_credential_store"
            or not isinstance(root["schema_version"], int)
            or isinstance(root["schema_version"], bool)
            or root["schema_version"] != SCHEMA_VERSION
        ):
            raise ArenaAgentStoreCorruptError(
                "Arena agent store surface or version is invalid"
            )
        payload = root["payload"]
        integrity = root["integrity"]
        if (
            not isinstance(payload, dict)
            or not isinstance(integrity, dict)
            or set(integrity) != {"algorithm", "value"}
            or integrity["algorithm"] != "HMAC-SHA256"
            or not isinstance(integrity["value"], str)
            or not _HEX64.fullmatch(integrity["value"])
        ):
            raise ArenaAgentStoreCorruptError(
                "Arena agent store integrity envelope is invalid"
            )
        expected = hmac.new(
            self._integrity_key, _canonical_json(payload), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(integrity["value"], expected):
            raise ArenaAgentStoreCorruptError(
                "Arena agent store integrity verification failed"
            )
        self._validate_state(payload)
        self._state_file_identity = (path_stat.st_dev, path_stat.st_ino)
        return payload

    def _validate_state(self, state: dict[str, Any]) -> None:
        try:
            self._validate_state_inner(state)
        except ArenaAgentStoreCorruptError:
            raise
        except ArenaAgentStoreError as exc:
            raise ArenaAgentStoreCorruptError(str(exc)) from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise ArenaAgentStoreCorruptError(
                "Arena agent store payload contains an invalid field"
            ) from exc

    def _validate_state_inner(self, state: dict[str, Any]) -> None:
        if not isinstance(state, dict) or set(state) != self._PAYLOAD_FIELDS:
            raise ArenaAgentStoreCorruptError("Arena agent store payload is invalid")
        devices = state["devices"]
        credentials = state["credentials"]
        if not isinstance(devices, dict) or len(devices) > MAX_DEVICES:
            raise ArenaAgentStoreCorruptError("Arena agent device collection is invalid")
        if not isinstance(credentials, dict) or len(credentials) > MAX_CREDENTIALS:
            raise ArenaAgentStoreCorruptError(
                "Arena agent credential collection is invalid"
            )
        device_authority_keys: set[tuple[str, str, str, str]] = set()
        for device_id, device in devices.items():
            _resource_id(device_id, "device_id")
            required = {
                "device_id", "owner_address", "challenge_id", "challenge_version",
                "label", "kind", "public_key_hex", "public_key_hash", "status",
                "registered_at", "revoked_at",
            }
            if not isinstance(device, dict) or set(device) != required or device["device_id"] != device_id:
                raise ArenaAgentStoreCorruptError("Arena agent device record is invalid")
            _wallet(device["owner_address"])
            _challenge_id(device["challenge_id"])
            _challenge_version(device["challenge_version"])
            _name(device["label"], "device label")
            if device["kind"] not in _DEVICE_KINDS or device["status"] not in {"active", "revoked"}:
                raise ArenaAgentStoreCorruptError("Arena agent device state is invalid")
            try:
                public_key, _ = validate_arena_agent_device_public_key(
                    device["public_key_hex"]
                )
            except ArenaAuthError as exc:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent device key is invalid"
                ) from exc
            if device["public_key_hash"] != _hash_text(
                "arena_agent_device_key", public_key
            ):
                raise ArenaAgentStoreCorruptError("Arena agent device key is invalid")
            _timestamp(device["registered_at"])
            if device["revoked_at"] is not None:
                revoked_at = _timestamp(device["revoked_at"])
                if revoked_at < device["registered_at"]:
                    raise ArenaAgentStoreCorruptError(
                        "Arena agent device revocation time is invalid"
                    )
            if (device["status"] == "active") != (device["revoked_at"] is None):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent device status and revocation disagree"
                )
            authority_key = (
                device["owner_address"],
                device["challenge_id"],
                device["challenge_version"],
                device["public_key_hash"],
            )
            if authority_key in device_authority_keys:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent device key is duplicated within an authority boundary"
                )
            device_authority_keys.add(authority_key)
        credential_authority_counts: dict[tuple[str, str, str], int] = {}
        referenced_devices: set[str] = set()
        token_commitments: set[str] = set()
        for credential_id, credential in credentials.items():
            _resource_id(credential_id, "credential_id")
            required = {
                "credential_id", "device_id", "owner_address", "challenge_id",
                "challenge_version", "name", "prefix", "scopes",
                "daily_submission_cap", "generation", "jwt_id_hash", "status",
                "issued_at", "expires_at", "last_used_at", "rotated_at",
                "revoked_at", "submission_usage_day",
                "submission_usage_updated_at", "submission_attempt_hashes",
            }
            if not isinstance(credential, dict) or set(credential) != required or credential["credential_id"] != credential_id:
                raise ArenaAgentStoreCorruptError("Arena agent credential record is invalid")
            device = devices.get(credential["device_id"])
            if device is None:
                raise ArenaAgentStoreCorruptError("Arena agent credential device is missing")
            owner = _wallet(credential["owner_address"])
            challenge = _challenge_id(credential["challenge_id"])
            version = _challenge_version(credential["challenge_version"])
            if (
                device["owner_address"] != owner
                or device["challenge_id"] != challenge
                or device["challenge_version"] != version
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential crosses a device authority boundary"
                )
            if credential["device_id"] in referenced_devices:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent device is bound to multiple credentials"
                )
            referenced_devices.add(credential["device_id"])
            authority = (owner, challenge, version)
            credential_authority_counts[authority] = (
                credential_authority_counts.get(authority, 0) + 1
            )
            if credential_authority_counts[authority] > MAX_CREDENTIALS_PER_OWNER_CHALLENGE:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential authority cap is exceeded"
                )
            _name(credential["name"], "credential name")
            if credential["prefix"] != f"wka_{credential_id[-6:]}":
                raise ArenaAgentStoreCorruptError("Arena agent credential prefix is invalid")
            _scopes(credential["scopes"])
            cap = _integer(
                credential["daily_submission_cap"],
                "daily_submission_cap",
                minimum=1,
                maximum=MAX_DAILY_SUBMISSION_CAP,
            )
            _integer(credential["generation"], "generation", minimum=1, maximum=1_000_000)
            if not _HEX64.fullmatch(credential["jwt_id_hash"]) or credential["status"] not in {"active", "revoked"}:
                raise ArenaAgentStoreCorruptError("Arena agent credential state is invalid")
            if credential["jwt_id_hash"] in token_commitments:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential token commitment is duplicated"
                )
            token_commitments.add(credential["jwt_id_hash"])
            issued_at = _timestamp(credential["issued_at"])
            expires_at = _timestamp(credential["expires_at"])
            if device["registered_at"] > issued_at:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent device registration follows credential issuance"
                )
            if expires_at <= issued_at or expires_at - issued_at > MAX_TTL_SECONDS:
                raise ArenaAgentStoreCorruptError("Arena agent credential lifetime is invalid")
            for field in (
                "last_used_at", "rotated_at", "revoked_at",
                "submission_usage_updated_at",
            ):
                if credential[field] is not None:
                    _timestamp(credential[field])
            if (
                credential["last_used_at"] is not None
                and (
                    credential["last_used_at"] < issued_at
                    or credential["last_used_at"] >= expires_at
                )
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential last-use time is invalid"
                )
            generation = credential["generation"]
            rotated_at = credential["rotated_at"]
            if (generation == 1) != (rotated_at is None):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential generation and rotation disagree"
                )
            if rotated_at is not None and rotated_at != issued_at:
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential rotation time is invalid"
                )
            revoked_at = credential["revoked_at"]
            if (credential["status"] == "active") != (revoked_at is None):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential status and revocation disagree"
                )
            if revoked_at is not None and revoked_at < max(
                issued_at, credential["last_used_at"] or 0, rotated_at or 0
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent credential revocation time is invalid"
                )
            usage_day = credential["submission_usage_day"]
            usage_updated_at = credential["submission_usage_updated_at"]
            attempts = credential["submission_attempt_hashes"]
            if usage_day is not None:
                _integer(usage_day, "submission_usage_day", minimum=0, maximum=MAX_TIMESTAMP // 86_400)
            if (
                not isinstance(attempts, list)
                or len(attempts) > cap
                or any(not isinstance(item, str) or not _HEX64.fullmatch(item) for item in attempts)
                or len(set(attempts)) != len(attempts)
                or ((usage_day is None) != (not attempts))
                or ((usage_updated_at is None) != (not attempts))
                or (
                    attempts
                    and (
                        usage_day != usage_updated_at // 86_400
                        or usage_updated_at < device["registered_at"]
                        or usage_updated_at
                        > max(issued_at, credential["last_used_at"] or 0)
                    )
                )
            ):
                raise ArenaAgentStoreCorruptError(
                    "Arena agent submission-attempt counter is invalid"
                )
            if credential["status"] == "active" and device["status"] != "active":
                raise ArenaAgentStoreCorruptError(
                    "Active Arena agent credential references a revoked device"
                )
        if referenced_devices != set(devices):
            raise ArenaAgentStoreCorruptError(
                "Arena agent store contains an orphaned device"
            )


def _wallet(value: Any) -> str:
    try:
        return normalize_wallet_address(str(value))
    except WalletAuthError as exc:
        raise ArenaAgentStoreError(str(exc)) from exc


def _challenge_id(value: Any) -> str:
    try:
        return normalize_challenge_id(str(value))
    except ArenaAuthError as exc:
        raise ArenaAgentStoreError(str(exc)) from exc


def _challenge_version(value: Any) -> str:
    try:
        return normalize_challenge_version(str(value))
    except ArenaAuthError as exc:
        raise ArenaAgentStoreError(str(exc)) from exc


def _resource_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _RESOURCE_ID.fullmatch(value):
        raise ArenaAgentStoreError(f"{label} is malformed")
    return value


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ArenaAgentStoreError(f"{label} is invalid")
    normalized = value.strip()
    if not _NAME.fullmatch(normalized):
        raise ArenaAgentStoreError(f"{label} is invalid")
    return normalized


def _scopes(value: Any) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise ArenaAgentStoreError("Arena agent credential scopes are invalid")
    normalized = tuple(value)
    if normalized != ARENA_AGENT_SCOPES:
        raise ArenaAgentStoreError(
            "Arena agent credentials require exact ordered submit and owner-read scopes"
        )
    return normalized


def _timestamp(value: Any) -> int:
    return _integer(value, "timestamp", minimum=0, maximum=MAX_TIMESTAMP)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
        raise ArenaAgentStoreError(f"{label} is outside the supported range")
    return value


def _hash_text(prefix: str, value: str) -> str:
    return hashlib.sha256(prefix.encode("ascii") + b":" + value.encode("utf-8")).hexdigest()


def _hash_json(prefix: str, value: Any) -> str:
    return hashlib.sha256(
        prefix.encode("ascii") + b":" + _canonical_json(value)
    ).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ArenaAgentStoreCorruptError(
                "Arena agent credential store contains duplicate JSON keys"
            )
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ArenaAgentStoreCorruptError(
        f"Arena agent credential store contains unsupported JSON constant {value}"
    )


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
