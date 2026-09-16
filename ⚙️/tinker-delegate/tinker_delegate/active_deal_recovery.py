"""Versioned dstack-sealed recovery for active DiligenceRoom deals.

The public deal runtime journal deliberately cannot contain seller artifacts,
commitment secrets, or raw attestation quotes.  This store is the matching
private recovery boundary: one authenticated ciphertext on the CVM data volume,
encrypted under a purpose-separated dstack-derived key.

There is intentionally no production plaintext-key-file fallback.  Unit tests
may inject a 32-byte key; deployed construction must derive the key through
dstack.  The envelope is versioned, mode-0600, atomically replaced, and fsyncs
both the file and parent directory before a successful save returns.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import threading
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tinker_delegate.dstack_utils import derive_storage_key


ACTIVE_DEAL_RECOVERY_SCHEMA = "dnai-wikigen/active-deal-recovery/v1"
ACTIVE_DEAL_RECOVERY_PAYLOAD_SCHEMA = (
    "dnai-wikigen/active-deal-recovery-payload/v1"
)
ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION = 1
ACTIVE_DEAL_RECOVERY_KEY_PATH = "tinker/diligence_active_deal_recovery_v1"
DEFAULT_ACTIVE_DEAL_RECOVERY_PATH = Path("/data/deal_active_recovery.v1.sealed")
MAX_ACTIVE_DEALS = 32
MAX_RECOVERY_FILE_BYTES = 96 * 1024 * 1024
_KEY_INFO = b"dnai-wikigen/active-deal-recovery/aes-256-gcm/v1"


class ActiveDealRecoveryError(RuntimeError):
    """Raised when private recovery state is unavailable or unauthenticated."""


class ActiveDealRecoveryStore:
    """Authenticated encrypted snapshot of exact active private deal state."""

    def __init__(
        self,
        path: str | Path,
        *,
        key: bytes | None = None,
        dstack_enabled: bool = False,
        dstack_key_path: str = ACTIVE_DEAL_RECOVERY_KEY_PATH,
    ) -> None:
        self.path = Path(path)
        if key is not None and dstack_enabled:
            raise ActiveDealRecoveryError(
                "explicit and dstack recovery keys are mutually exclusive"
            )
        if key is not None:
            if not isinstance(key, bytes) or len(key) != 32:
                raise ActiveDealRecoveryError("recovery key must be 32 bytes")
            root = key
            self.key_custody = "injected_test_only"
        elif dstack_enabled:
            if (
                not isinstance(dstack_key_path, str)
                or not dstack_key_path
                or dstack_key_path
                in {
                    "tinker/runtime-auth",
                    "tinker/sealed_retention",
                    "tinker/compute_store_integrity",
                }
            ):
                raise ActiveDealRecoveryError(
                    "active-deal recovery dstack key path is invalid"
                )
            try:
                root = derive_storage_key(dstack_key_path)
            except Exception as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery dstack key derivation failed"
                ) from exc
            if not isinstance(root, bytes) or len(root) < 32:
                raise ActiveDealRecoveryError(
                    "active-deal recovery dstack key is invalid"
                )
            self.key_custody = "dstack_derived"
        else:
            raise ActiveDealRecoveryError(
                "active-deal recovery requires dstack or an injected test key"
            )

        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=_KEY_INFO,
        ).derive(root[:32])
        self._aes = AESGCM(self._key)
        self._generation = 0
        self._lock = threading.RLock()

    def load(self) -> dict[str, dict[str, Any]]:
        """Decrypt and authenticate the latest complete private snapshot."""

        with self._lock:
            if not self.path.exists():
                return {}
            self._require_safe_existing_file()
            try:
                raw = self.path.read_bytes()
            except OSError as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery state could not be read"
                ) from exc
            if not raw or len(raw) > MAX_RECOVERY_FILE_BYTES:
                raise ActiveDealRecoveryError(
                    "active-deal recovery state size is invalid"
                )
            try:
                envelope = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery envelope is invalid"
                ) from exc
            if not isinstance(envelope, dict) or set(envelope) != {
                "schema",
                "schema_version",
                "generation",
                "key_custody",
                "nonce_b64",
                "ciphertext_b64",
            }:
                raise ActiveDealRecoveryError(
                    "active-deal recovery envelope shape is invalid"
                )
            generation = envelope["generation"]
            if (
                envelope["schema"] != ACTIVE_DEAL_RECOVERY_SCHEMA
                or envelope["schema_version"]
                != ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION
                or envelope["key_custody"] != self.key_custody
                or isinstance(generation, bool)
                or not isinstance(generation, int)
                or generation < 1
            ):
                raise ActiveDealRecoveryError(
                    "active-deal recovery envelope header is invalid"
                )
            try:
                nonce = base64.b64decode(
                    envelope["nonce_b64"], validate=True
                )
                ciphertext = base64.b64decode(
                    envelope["ciphertext_b64"], validate=True
                )
            except (TypeError, ValueError) as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery envelope encoding is invalid"
                ) from exc
            if len(nonce) != 12 or len(ciphertext) < 16:
                raise ActiveDealRecoveryError(
                    "active-deal recovery ciphertext is invalid"
                )
            aad = self._aad(generation)
            plaintext = bytearray()
            try:
                plaintext = bytearray(
                    self._aes.decrypt(nonce, ciphertext, aad)
                )
                payload = json.loads(plaintext)
            except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery authentication failed"
                ) from exc
            finally:
                _zero(plaintext)
            if not isinstance(payload, dict) or set(payload) != {
                "schema",
                "schema_version",
                "deals",
            }:
                raise ActiveDealRecoveryError(
                    "active-deal recovery payload shape is invalid"
                )
            deals = payload["deals"]
            if (
                payload["schema"] != ACTIVE_DEAL_RECOVERY_PAYLOAD_SCHEMA
                or payload["schema_version"]
                != ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION
                or not isinstance(deals, dict)
                or len(deals) > MAX_ACTIVE_DEALS
            ):
                raise ActiveDealRecoveryError(
                    "active-deal recovery payload header is invalid"
                )
            for deal_id, entry in deals.items():
                if (
                    not isinstance(deal_id, str)
                    or not deal_id
                    or not isinstance(entry, dict)
                ):
                    raise ActiveDealRecoveryError(
                        "active-deal recovery entry is invalid"
                    )
            self._generation = generation
            return deals

    def save(self, deals: dict[str, dict[str, Any]]) -> None:
        """Seal and durably replace the complete active-deal snapshot."""

        if not isinstance(deals, dict) or len(deals) > MAX_ACTIVE_DEALS:
            raise ActiveDealRecoveryError(
                "active-deal recovery deal count is invalid"
            )
        for deal_id, entry in deals.items():
            if (
                not isinstance(deal_id, str)
                or not deal_id
                or not isinstance(entry, dict)
            ):
                raise ActiveDealRecoveryError(
                    "active-deal recovery entry is invalid"
                )

        with self._lock:
            if self.path.exists():
                self._require_safe_existing_file()
            generation = self._generation + 1
            payload = {
                "schema": ACTIVE_DEAL_RECOVERY_PAYLOAD_SCHEMA,
                "schema_version": ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION,
                "deals": deals,
            }
            plaintext = bytearray(
                json.dumps(
                    payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
            )
            nonce = os.urandom(12)
            try:
                ciphertext = self._aes.encrypt(
                    nonce,
                    bytes(plaintext),
                    self._aad(generation),
                )
            except Exception as exc:
                raise ActiveDealRecoveryError(
                    "active-deal recovery sealing failed"
                ) from exc
            finally:
                _zero(plaintext)
            envelope = {
                "schema": ACTIVE_DEAL_RECOVERY_SCHEMA,
                "schema_version": ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION,
                "generation": generation,
                "key_custody": self.key_custody,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
            }
            encoded = (
                json.dumps(envelope, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("ascii")
            if len(encoded) > MAX_RECOVERY_FILE_BYTES:
                raise ActiveDealRecoveryError(
                    "active-deal recovery snapshot exceeds safe size"
                )
            self._atomic_write(encoded)
            self._generation = generation

    def destroy(self, deal_id: str) -> bool:
        """Remove one private entry by rewriting the authenticated snapshot."""

        deals = self.load()
        removed = deals.pop(str(deal_id), None) is not None
        if removed:
            self.save(deals)
        return removed

    def _aad(self, generation: int) -> bytes:
        return (
            ACTIVE_DEAL_RECOVERY_SCHEMA.encode("ascii")
            + b"\0"
            + str(ACTIVE_DEAL_RECOVERY_SCHEMA_VERSION).encode("ascii")
            + b"\0"
            + self.key_custody.encode("ascii")
            + b"\0"
            + str(generation).encode("ascii")
        )

    def _require_safe_existing_file(self) -> None:
        try:
            info = self.path.lstat()
        except OSError as exc:
            raise ActiveDealRecoveryError(
                "active-deal recovery file metadata is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ActiveDealRecoveryError(
                "active-deal recovery file safety check failed"
            )

    def _atomic_write(self, encoded: bytes) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.parent.is_symlink():
            raise ActiveDealRecoveryError(
                "active-deal recovery directory cannot be a symlink"
            )
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=self.path.parent,
        )
        temp_path = Path(temporary)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, self.path)
            os.chmod(self.path, 0o600)
            directory_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except Exception as exc:
            temp_path.unlink(missing_ok=True)
            if isinstance(exc, ActiveDealRecoveryError):
                raise
            raise ActiveDealRecoveryError(
                "active-deal recovery state could not be persisted"
            ) from exc


def build_dstack_active_deal_recovery_store(
    path: str | Path = DEFAULT_ACTIVE_DEAL_RECOVERY_PATH,
) -> ActiveDealRecoveryStore:
    """Build the production store; callers decide whether dstack is enabled."""

    return ActiveDealRecoveryStore(path, dstack_enabled=True)


def _zero(buffer: bytearray) -> None:
    for index in range(len(buffer)):
        buffer[index] = 0
