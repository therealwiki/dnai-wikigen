"""Ciphertext-only ingress for Arena candidate programs.

The public API authenticates a challenge-version-bound wallet before calling
this module.  This module then accepts only an X25519/HKDF-SHA256/AES-256-GCM
envelope.  It never accepts, decrypts, executes, logs, hashes, or persists
candidate plaintext.  A future runtime worker inside the attested boundary is
responsible for decryption and MUST recheck the plaintext byte length and
``sha256`` commitment before any hardened execution path is considered.

Browser protocol, version 1
===========================

1. Fetch and independently verify ``GET /attestation?context=arena``.  Use the
   stable Arena ``encryption_public_key`` and ``key_id`` only after validating
   the attestation evidence and report-data binding.  Quote presence alone is
   not full Intel TDX verification; the bounded helper in this module always
   reports ``verified: false`` unless an external full policy verifier says
   otherwise.
2. Build the exact canonical AAD object returned by
   :func:`arena_candidate_aad`.  Canonical JSON is UTF-8, ASCII escaped, keys
   sorted lexicographically, with separators ``,`` and ``:`` and no whitespace.
3. Generate an ephemeral X25519 keypair and compute ECDH with the attested Arena
   recipient public key.
4. Derive 32 bytes with HKDF-SHA256 using ``salt = SHA256(AAD)`` and
   ``info = b"dnai-wikigen/arena-candidate-ingress/v1"``.
5. Encrypt the source bytes with AES-256-GCM, a fresh 12-byte nonce, and the
   exact canonical AAD bytes.  AES-GCM appends a 16-byte tag, so the decoded
   ciphertext length MUST equal ``manifest.source_bytes + 16`` and MUST be no
   larger than 65,536 bytes.
6. Encode AAD, ephemeral public key, nonce, and ciphertext as RFC 4648 base64url
   without ``=`` padding and POST this exact, allowlisted object with the same
   ``Idempotency-Key`` on every retry::

      {
        "schema_version": 1,
        "algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
        "encoding": "base64url-nopad",
        "key_id": "sha256:<64 lowercase hex>",
        "attestation_report_data": "<64 lowercase hex>",
        "aad": "<base64url-no-padding canonical AAD>",
        "ephemeral_public_key": "<43 base64url characters>",
        "nonce": "<16 base64url characters>",
        "ciphertext": "<bounded base64url ciphertext plus GCM tag>"
      }

The server generates the ``sealed://arena/...`` reference.  The reference is an
internal handoff to :class:`~tinker_delegate.arena_store.ArenaStore`; it is not
part of any public receipt.  An exact idempotent replay reuses the existing blob
without rewriting it.  A different envelope or binding under the same key fails
closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from tinker_delegate import dstack_utils
from tinker_delegate.arena_store import (
    EXECUTION_ASSURANCE,
    PRODUCT_STATUS,
    ArenaStoreError,
    ChallengeManifest,
    SubmissionIdentity,
    SubmissionManifest,
)
from tinker_delegate.crypto import TEEKeyPair


INGRESS_SCHEMA_VERSION = 1
INGRESS_ALGORITHM = "X25519-HKDF-SHA256-AES-256-GCM"
INGRESS_ENCODING = "base64url-nopad"
INGRESS_SERVICE = "dnai-wikigen"
INGRESS_CONTEXT = "arena_candidate_ingress"
INGRESS_ATTESTATION_CONTEXT = "arena"
INGRESS_HKDF_INFO = b"dnai-wikigen/arena-candidate-ingress/v1"
INGRESS_DSTACK_KEY_PATH = "tinker/arena_candidate_ingress"

# Descriptive aliases used by API clients and tests.  Keep the wire values in
# one place so the browser contract and parser cannot drift.
ARENA_INGRESS_SCHEMA_VERSION = INGRESS_SCHEMA_VERSION
ARENA_CANDIDATE_ALGORITHM = INGRESS_ALGORITHM
ARENA_CANDIDATE_ENCODING = INGRESS_ENCODING
ARENA_CANDIDATE_HKDF_INFO = INGRESS_HKDF_INFO

MAX_CIPHERTEXT_BYTES = 65_536
GCM_TAG_BYTES = 16
MAX_SOURCE_BYTES = MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES
X25519_PUBLIC_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
MAX_AAD_BYTES = 4_096
MAX_ENVELOPES = 10_000
MAX_INDEX_BYTES = 8 * 1024 * 1024
MAX_BLOB_FILE_BYTES = 100_000

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OBJECT_ID = re.compile(r"^candidate-[0-9a-f]{64}$")
_SEALED_REFERENCE = re.compile(r"^sealed://arena/candidate-[0-9a-f]{64}$")
_CHALLENGE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DSTACK_KEY_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")


class ArenaIngressError(ValueError):
    """Raised when ciphertext ingress fails without echoing sensitive input."""


class ArenaIngressConflict(ArenaIngressError):
    """Raised when an Idempotency-Key is reused for a different envelope."""


class ArenaIngressCorruptError(ArenaIngressError):
    """Raised when durable ciphertext state is missing or malformed."""


class ArenaIngressUnavailable(ArenaIngressError):
    """Raised when stable key custody or a storage root is unavailable."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ArenaIngressError("Arena ingress value is not canonical JSON") from exc


def _sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _require_exact_keys(
    payload: Mapping[str, Any], expected: frozenset[str], *, label: str
) -> None:
    if not isinstance(payload, Mapping):
        raise ArenaIngressError(f"{label} must be an object")
    actual = set(payload)
    if actual != expected:
        raise ArenaIngressError(
            f"{label} has missing or non-allowlisted fields"
        )


def _require_string(
    value: Any, *, label: str, minimum: int = 1, maximum: int
) -> str:
    if not isinstance(value, str):
        raise ArenaIngressError(f"{label} must be a string")
    size = len(value.encode("utf-8"))
    if size < minimum or size > maximum:
        raise ArenaIngressError(f"{label} length is outside the allowed bound")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ArenaIngressError(f"{label} contains control characters")
    return value


def _require_int(
    value: Any, *, label: str, minimum: int, maximum: int
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ArenaIngressError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise ArenaIngressError(f"{label} is outside the allowed bound")
    return value


def _b64url_encoded_size(byte_count: int) -> int:
    return (byte_count * 8 + 5) // 6


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(
    value: Any,
    *,
    label: str,
    maximum_bytes: int,
    exact_bytes: int | None = None,
) -> bytes:
    maximum_chars = _b64url_encoded_size(maximum_bytes)
    encoded = _require_string(
        value,
        label=label,
        minimum=1,
        maximum=maximum_chars,
    )
    if not _B64URL.fullmatch(encoded) or "=" in encoded:
        raise ArenaIngressError(f"{label} must be canonical base64url without padding")
    if exact_bytes is not None and len(encoded) != _b64url_encoded_size(exact_bytes):
        raise ArenaIngressError(f"{label} has an invalid encoded length")
    try:
        decoded = base64.b64decode(
            encoded + ("=" * ((-len(encoded)) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ArenaIngressError(f"{label} is not valid base64url") from exc
    if len(decoded) > maximum_bytes:
        raise ArenaIngressError(f"{label} exceeds the decoded byte limit")
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ArenaIngressError(f"{label} has an invalid decoded length")
    if _b64url_encode(decoded) != encoded:
        raise ArenaIngressError(f"{label} is not canonically encoded")
    return decoded


def arena_ingress_key_id(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != X25519_PUBLIC_KEY_BYTES:
        raise ArenaIngressError("Arena recipient public key must be 32 bytes")
    return _sha256_bytes(public_key)


def arena_attestation_report_payload(public_key: bytes) -> dict[str, str]:
    """Return the exact canonical object hashed into TDX report data."""

    key_id = arena_ingress_key_id(public_key)
    return {
        "context": INGRESS_ATTESTATION_CONTEXT,
        "encryption_public_key": public_key.hex(),
        "key_id": key_id,
        "protocol": "arena_candidate_ingress_v1",
        "service": INGRESS_SERVICE,
    }


def arena_attestation_report_data(public_key: bytes) -> bytes:
    """Bind the stable Arena recipient key and protocol to TDX report data."""

    return hashlib.sha256(
        _canonical_json(arena_attestation_report_payload(public_key))
    ).digest()


def arena_submission_manifest_hash(manifest: SubmissionManifest) -> str:
    if not isinstance(manifest, SubmissionManifest):
        raise ArenaIngressError("submission manifest is required")
    return _sha256_bytes(_canonical_json(manifest.to_public_dict()))


def _parse_identity_binding(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ArenaIngressError("Arena candidate identity binding must be an object")
    _require_exact_keys(
        value,
        frozenset({"wallet_address_hash", "project_id_hash"}),
        label="Arena candidate identity binding",
    )
    parsed: dict[str, str] = {}
    for label in ("wallet_address_hash", "project_id_hash"):
        item = _require_string(value[label], label=label, maximum=64)
        if not _HEX_64.fullmatch(item):
            raise ArenaIngressError(
                "Arena candidate identity hashes must be lowercase SHA-256 hex"
            )
        parsed[label] = item
    return parsed


def arena_idempotency_key_hash(
    *,
    challenge: ChallengeManifest,
    identity: SubmissionIdentity,
    idempotency_key: str,
) -> str:
    """Return the browser-reproducible, context-bound retry-key hash."""

    if not isinstance(challenge, ChallengeManifest):
        raise ArenaIngressError("Arena challenge is required")
    if not isinstance(identity, SubmissionIdentity):
        raise ArenaIngressError("Arena submission identity is required")
    key = _require_string(
        idempotency_key,
        label="Arena Idempotency-Key",
        maximum=128,
    )
    if not _IDEMPOTENCY_KEY.fullmatch(key):
        raise ArenaIngressError("Arena Idempotency-Key is malformed")
    return _sha256_bytes(
        _canonical_json(
            {
                "challenge_id": challenge.challenge_id,
                "challenge_version": challenge.version,
                "identity": identity.to_public_dict(),
                "idempotency_key": key,
            }
        )
    )


@dataclass(frozen=True)
class ArenaCandidateBinding:
    challenge_id: str
    challenge_version: str
    challenge_manifest_hash: str
    submission_manifest_hash: str
    candidate_commitment: str
    identity: Mapping[str, str]
    idempotency_key_hash: str
    key_id: str
    attestation_report_data_sha256: str
    registry_authorization_sha256: str

    _FIELDS = frozenset(
        {
            "service",
            "context",
            "schema_version",
            "challenge_id",
            "challenge_version",
            "challenge_manifest_hash",
            "submission_manifest_hash",
            "candidate_commitment",
            "identity",
            "idempotency_key_hash",
            "key_id",
            "attestation_report_data_sha256",
            "registry_authorization_sha256",
        }
    )

    def __post_init__(self) -> None:
        if not _CHALLENGE_ID.fullmatch(self.challenge_id):
            raise ArenaIngressError("challenge_id is malformed")
        if not _SEMVER.fullmatch(self.challenge_version):
            raise ArenaIngressError("challenge_version is malformed")
        if not isinstance(self.challenge_manifest_hash, str) or not _HEX_64.fullmatch(
            self.challenge_manifest_hash
        ):
            raise ArenaIngressError(
                "challenge_manifest_hash must be lowercase SHA-256 hex"
            )
        for label, value in (
            ("submission_manifest_hash", self.submission_manifest_hash),
            ("candidate_commitment", self.candidate_commitment),
            ("idempotency_key_hash", self.idempotency_key_hash),
            ("key_id", self.key_id),
            (
                "attestation_report_data_sha256",
                self.attestation_report_data_sha256,
            ),
            (
                "registry_authorization_sha256",
                self.registry_authorization_sha256,
            ),
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ArenaIngressError(f"{label} must be a lowercase SHA-256 commitment")
        if not isinstance(self.identity, Mapping) or set(self.identity) != {
            "wallet_address_hash",
            "project_id_hash",
        }:
            raise ArenaIngressError("Arena candidate identity binding is malformed")
        for label in ("wallet_address_hash", "project_id_hash"):
            value = self.identity[label]
            if not isinstance(value, str) or not _HEX_64.fullmatch(value):
                raise ArenaIngressError(
                    "Arena candidate identity hashes must be lowercase SHA-256 hex"
                )
        object.__setattr__(
            self,
            "identity",
            MappingProxyType(dict(self.identity)),
        )

    def to_aad_dict(self) -> dict[str, Any]:
        return {
            "service": INGRESS_SERVICE,
            "context": INGRESS_CONTEXT,
            "schema_version": INGRESS_SCHEMA_VERSION,
            "challenge_id": self.challenge_id,
            "challenge_version": self.challenge_version,
            "challenge_manifest_hash": self.challenge_manifest_hash,
            "submission_manifest_hash": self.submission_manifest_hash,
            "candidate_commitment": self.candidate_commitment,
            "identity": dict(self.identity),
            "idempotency_key_hash": self.idempotency_key_hash,
            "key_id": self.key_id,
            "attestation_report_data_sha256": self.attestation_report_data_sha256,
            "registry_authorization_sha256": self.registry_authorization_sha256,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ArenaCandidateBinding":
        _require_exact_keys(payload, cls._FIELDS, label="Arena candidate binding")
        service = _require_string(
            payload["service"], label="binding service", maximum=64
        )
        context = _require_string(
            payload["context"], label="binding context", maximum=64
        )
        schema_version = _require_int(
            payload["schema_version"],
            label="binding schema_version",
            minimum=1,
            maximum=1,
        )
        if (
            service != INGRESS_SERVICE
            or context != INGRESS_CONTEXT
            or schema_version != INGRESS_SCHEMA_VERSION
        ):
            raise ArenaIngressError("Arena candidate binding protocol is unsupported")
        return cls(
            challenge_id=_require_string(
                payload["challenge_id"], label="challenge_id", maximum=64
            ),
            challenge_version=_require_string(
                payload["challenge_version"], label="challenge_version", maximum=32
            ),
            challenge_manifest_hash=_require_string(
                payload["challenge_manifest_hash"],
                label="challenge_manifest_hash",
                maximum=71,
            ),
            submission_manifest_hash=_require_string(
                payload["submission_manifest_hash"],
                label="submission_manifest_hash",
                maximum=71,
            ),
            candidate_commitment=_require_string(
                payload["candidate_commitment"],
                label="candidate_commitment",
                maximum=71,
            ),
            identity=_parse_identity_binding(payload["identity"]),
            idempotency_key_hash=_require_string(
                payload["idempotency_key_hash"],
                label="idempotency_key_hash",
                maximum=71,
            ),
            key_id=_require_string(payload["key_id"], label="key_id", maximum=71),
            attestation_report_data_sha256=_require_string(
                payload["attestation_report_data_sha256"],
                label="attestation_report_data_sha256",
                maximum=71,
            ),
            registry_authorization_sha256=_require_string(
                payload["registry_authorization_sha256"],
                label="registry_authorization_sha256",
                maximum=71,
            ),
        )


def arena_candidate_aad(binding: ArenaCandidateBinding) -> bytes:
    if not isinstance(binding, ArenaCandidateBinding):
        raise ArenaIngressError("Arena candidate binding is required")
    encoded = _canonical_json(binding.to_aad_dict())
    if len(encoded) > MAX_AAD_BYTES:
        raise ArenaIngressError("Arena candidate AAD exceeds its byte limit")
    return encoded


@dataclass(frozen=True, repr=False)
class ArenaCandidateEnvelope:
    schema_version: int
    algorithm: str
    encoding: str
    key_id: str
    attestation_report_data: str
    aad: str
    ephemeral_public_key: str
    nonce: str
    ciphertext: str
    ciphertext_bytes: int = field(init=False)
    ciphertext_sha256: str = field(init=False)
    aad_sha256: str = field(init=False)

    _FIELDS = frozenset(
        {
            "schema_version",
            "algorithm",
            "encoding",
            "key_id",
            "attestation_report_data",
            "aad",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        }
    )

    def __post_init__(self) -> None:
        _require_int(
            self.schema_version,
            label="envelope schema_version",
            minimum=1,
            maximum=1,
        )
        if self.algorithm != INGRESS_ALGORITHM or self.encoding != INGRESS_ENCODING:
            raise ArenaIngressError("Arena candidate envelope algorithm is unsupported")
        if not isinstance(self.key_id, str) or not _SHA256.fullmatch(self.key_id):
            raise ArenaIngressError("Arena candidate envelope key_id is malformed")
        if (
            not isinstance(self.attestation_report_data, str)
            or not _HEX_64.fullmatch(self.attestation_report_data)
        ):
            raise ArenaIngressError("Arena attestation report data is malformed")
        aad_bytes = _b64url_decode(
            self.aad,
            label="aad",
            maximum_bytes=MAX_AAD_BYTES,
        )
        ephemeral = _b64url_decode(
            self.ephemeral_public_key,
            label="ephemeral_public_key",
            maximum_bytes=X25519_PUBLIC_KEY_BYTES,
            exact_bytes=X25519_PUBLIC_KEY_BYTES,
        )
        if ephemeral == b"\0" * X25519_PUBLIC_KEY_BYTES:
            raise ArenaIngressError("ephemeral_public_key is invalid")
        try:
            X25519PublicKey.from_public_bytes(ephemeral)
        except ValueError as exc:
            raise ArenaIngressError("ephemeral_public_key is invalid") from exc
        _b64url_decode(
            self.nonce,
            label="nonce",
            maximum_bytes=AES_GCM_NONCE_BYTES,
            exact_bytes=AES_GCM_NONCE_BYTES,
        )
        ciphertext = _b64url_decode(
            self.ciphertext,
            label="ciphertext",
            maximum_bytes=MAX_CIPHERTEXT_BYTES,
        )
        if len(ciphertext) <= GCM_TAG_BYTES:
            raise ArenaIngressError("ciphertext is too short for AES-GCM")
        object.__setattr__(self, "ciphertext_bytes", len(ciphertext))
        object.__setattr__(self, "ciphertext_sha256", _sha256_bytes(ciphertext))
        object.__setattr__(self, "aad_sha256", _sha256_bytes(aad_bytes))

    def __repr__(self) -> str:
        return (
            "ArenaCandidateEnvelope("
            f"schema_version={self.schema_version}, "
            f"key_id={self.key_id!r}, "
            f"ciphertext_bytes={self.ciphertext_bytes})"
        )

    def to_persisted_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "encoding": self.encoding,
            "key_id": self.key_id,
            "attestation_report_data": self.attestation_report_data,
            "aad": self.aad,
            "ephemeral_public_key": self.ephemeral_public_key,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ArenaCandidateEnvelope":
        _require_exact_keys(payload, cls._FIELDS, label="Arena candidate envelope")
        return cls(
            schema_version=_require_int(
                payload["schema_version"],
                label="envelope schema_version",
                minimum=1,
                maximum=1,
            ),
            algorithm=_require_string(
                payload["algorithm"], label="algorithm", maximum=64
            ),
            encoding=_require_string(
                payload["encoding"], label="encoding", maximum=32
            ),
            key_id=_require_string(payload["key_id"], label="key_id", maximum=71),
            attestation_report_data=_require_string(
                payload["attestation_report_data"],
                label="attestation_report_data",
                maximum=64,
            ),
            aad=_require_string(
                payload["aad"],
                label="aad",
                maximum=_b64url_encoded_size(MAX_AAD_BYTES),
            ),
            ephemeral_public_key=_require_string(
                payload["ephemeral_public_key"],
                label="ephemeral_public_key",
                maximum=_b64url_encoded_size(X25519_PUBLIC_KEY_BYTES),
            ),
            nonce=_require_string(
                payload["nonce"],
                label="nonce",
                maximum=_b64url_encoded_size(AES_GCM_NONCE_BYTES),
            ),
            ciphertext=_require_string(
                payload["ciphertext"],
                label="ciphertext",
                maximum=_b64url_encoded_size(MAX_CIPHERTEXT_BYTES),
            ),
        )


@dataclass(frozen=True, repr=False)
class ArenaIngressRecipient:
    keypair: TEEKeyPair = field(repr=False)
    public_key: bytes
    key_id: str
    report_data: bytes
    custody_mode: str

    @classmethod
    def from_keypair(
        cls,
        keypair: TEEKeyPair,
        *,
        custody_mode: str = "local",
    ) -> "ArenaIngressRecipient":
        if not isinstance(keypair, TEEKeyPair):
            raise ArenaIngressError("Arena ingress keypair is invalid")
        if custody_mode not in {"dstack", "local"}:
            raise ArenaIngressError("Arena ingress custody mode is invalid")
        public_key = keypair.public_key_bytes
        return cls(
            keypair=keypair,
            public_key=public_key,
            key_id=arena_ingress_key_id(public_key),
            report_data=arena_attestation_report_data(public_key),
            custody_mode=custody_mode,
        )

    def __post_init__(self) -> None:
        if self.public_key != self.keypair.public_key_bytes:
            raise ArenaIngressError("Arena ingress recipient public key mismatch")
        if self.key_id != arena_ingress_key_id(self.public_key):
            raise ArenaIngressError("Arena ingress recipient key id mismatch")
        if self.report_data != arena_attestation_report_data(self.public_key):
            raise ArenaIngressError("Arena ingress recipient report data mismatch")
        if self.custody_mode not in {"dstack", "local"}:
            raise ArenaIngressError("Arena ingress custody mode is invalid")

    def __repr__(self) -> str:
        return (
            "ArenaIngressRecipient("
            f"key_id={self.key_id!r}, custody_mode={self.custody_mode!r})"
        )

    def to_attestation_binding(self) -> dict[str, Any]:
        return {
            "encryption_public_key": self.public_key.hex(),
            "key_id": self.key_id,
            "report_context": INGRESS_ATTESTATION_CONTEXT,
            "report_data": self.report_data.hex(),
        }


def _private_key_bytes(value: str | bytes) -> bytes:
    if isinstance(value, bytes):
        raw = value
    elif isinstance(value, str):
        if len(value) != 64 or not _HEX_64.fullmatch(value):
            raise ArenaIngressUnavailable("Arena ingress private key override is malformed")
        raw = bytes.fromhex(value)
    else:
        raise ArenaIngressUnavailable("Arena ingress private key override is malformed")
    if len(raw) != 32 or raw == b"\0" * 32:
        raise ArenaIngressUnavailable(
            "Arena ingress private key must be 32 non-zero bytes"
        )
    return raw


def _secure_directory(path: Path) -> None:
    if path.exists() and path.is_symlink():
        raise ArenaIngressUnavailable("Arena ingress directory cannot be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError as exc:
        raise ArenaIngressUnavailable("Arena ingress directory permissions failed") from exc


def _read_local_key(path: Path) -> bytes:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ArenaIngressUnavailable("Arena ingress local key file is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ArenaIngressUnavailable("Arena ingress local key file must be regular")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise ArenaIngressUnavailable("Arena ingress local key file must have mode 0600")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ArenaIngressUnavailable("Arena ingress local key file is unreadable") from exc
    return _private_key_bytes(raw)


def _create_or_read_local_key(path: Path) -> bytes:
    _secure_directory(path.parent)
    if path.exists():
        return _read_local_key(path)
    raw = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError:
        return _read_local_key(path)
    except OSError as exc:
        raise ArenaIngressUnavailable("Arena ingress local key creation failed") from exc
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    _fsync_directory(path.parent)
    return raw


def _settings_value(settings: Any, name: str, default: Any = "") -> Any:
    return getattr(settings, name, default) if settings is not None else default


def _default_root_path(settings: Any, root_path: str | Path | None) -> Path:
    if root_path is not None and str(root_path).strip():
        return Path(root_path)
    configured_store = str(
        _settings_value(settings, "arena_candidate_ingress_store_path", "") or ""
    ).strip()
    if configured_store:
        return Path(configured_store).parent
    arena_store = str(_settings_value(settings, "arena_store_path", "") or "").strip()
    if arena_store:
        return Path(arena_store).parent
    raise ArenaIngressUnavailable("Arena candidate ingress storage root is not configured")


def resolve_arena_keypair(
    settings: Any = None,
    *,
    root_path: str | Path | None = None,
    private_key_override: str | bytes | None = None,
) -> TEEKeyPair:
    """Resolve a restart-stable, channel-specific X25519 keypair.

    Production dstack mode ignores local key material, deriving only
    at the distinct Arena key path.  Local mode permits a 32-byte explicit test
    override or a dedicated 0600 key file that survives process restarts.
    """

    configured_override = str(
        _settings_value(settings, "arena_candidate_ingress_private_key_hex", "")
        or ""
    ).strip()
    override: str | bytes | None = private_key_override or configured_override or None
    configured_file = str(
        _settings_value(settings, "arena_candidate_ingress_local_key_file", "")
        or ""
    ).strip()
    if dstack_utils.is_dstack_enabled():
        key_path = str(
            _settings_value(
                settings,
                "arena_candidate_ingress_key_path",
                INGRESS_DSTACK_KEY_PATH,
            )
            or INGRESS_DSTACK_KEY_PATH
        ).strip()
        if (
            not _DSTACK_KEY_PATH.fullmatch(key_path)
            or "arena_candidate_ingress" not in key_path
            or any(segment in {"", ".", ".."} for segment in key_path.split("/"))
        ):
            raise ArenaIngressUnavailable("Arena dstack key path is invalid")
        try:
            raw = dstack_utils.derive_storage_key(key_path)
        except Exception as exc:
            raise ArenaIngressUnavailable("Arena dstack key derivation failed") from exc
        private_bytes = _private_key_bytes(raw[:32])
    elif override is not None:
        private_bytes = _private_key_bytes(override)
    else:
        root = _default_root_path(settings, root_path)
        key_file = Path(configured_file) if configured_file else root / "arena-ingress.key"
        private_bytes = _create_or_read_local_key(key_file)
    return TEEKeyPair.from_private_key_hex(private_bytes.hex())


def resolve_arena_recipient(
    settings: Any = None,
    *,
    root_path: str | Path | None = None,
    private_key_override: str | bytes | None = None,
) -> ArenaIngressRecipient:
    return ArenaIngressRecipient.from_keypair(
        resolve_arena_keypair(
            settings,
            root_path=root_path,
            private_key_override=private_key_override,
        ),
        custody_mode="dstack" if dstack_utils.is_dstack_enabled() else "local",
    )


def build_arena_candidate_binding(
    *,
    challenge: ChallengeManifest,
    identity: SubmissionIdentity,
    candidate_commitment: str,
    manifest: SubmissionManifest,
    recipient: ArenaIngressRecipient,
    idempotency_key: str,
    registry_authorization_sha256: str,
) -> ArenaCandidateBinding:
    """Build the one exact binding accepted for a candidate ciphertext."""

    if not isinstance(challenge, ChallengeManifest):
        raise ArenaIngressError("Arena challenge is required")
    if not isinstance(identity, SubmissionIdentity):
        raise ArenaIngressError("Arena submission identity is required")
    if not isinstance(recipient, ArenaIngressRecipient):
        raise ArenaIngressError("Arena ingress recipient is required")
    if not isinstance(candidate_commitment, str) or not _SHA256.fullmatch(
        candidate_commitment
    ):
        raise ArenaIngressError(
            "candidate commitment must be sha256:<64 lowercase hex>"
        )
    if not isinstance(manifest, SubmissionManifest):
        raise ArenaIngressError("Arena submission manifest is required")
    try:
        manifest.validate_for(challenge)
    except ArenaStoreError as exc:
        raise ArenaIngressError(str(exc)) from exc
    if manifest.source_bytes > MAX_SOURCE_BYTES:
        raise ArenaIngressError(
            "submission source_bytes exceeds the Arena ciphertext capacity"
        )
    if (
        not isinstance(registry_authorization_sha256, str)
        or not _SHA256.fullmatch(registry_authorization_sha256)
        or registry_authorization_sha256 == "sha256:" + "0" * 64
    ):
        raise ArenaIngressError(
            "registry authorization must be a nonzero SHA-256 commitment"
        )
    return ArenaCandidateBinding(
        challenge_id=challenge.challenge_id,
        challenge_version=challenge.version,
        challenge_manifest_hash=challenge.manifest_hash,
        submission_manifest_hash=arena_submission_manifest_hash(manifest),
        candidate_commitment=candidate_commitment,
        identity=identity.to_public_dict(),
        idempotency_key_hash=arena_idempotency_key_hash(
            challenge=challenge,
            identity=identity,
            idempotency_key=idempotency_key,
        ),
        key_id=recipient.key_id,
        attestation_report_data_sha256=_sha256_bytes(recipient.report_data),
        registry_authorization_sha256=registry_authorization_sha256,
    )


def get_arena_ingress_attestation(
    settings: Any = None,
    *,
    root_path: str | Path | None = None,
    recipient: ArenaIngressRecipient | None = None,
) -> dict[str, Any]:
    """Return a bounded stable-key attestation envelope for ``context=arena``.

    ``verified`` intentionally remains false.  A quote returned by dstack has
    not, by itself, passed the repository's full external quote/policy verifier.
    """

    recipient = recipient or resolve_arena_recipient(settings, root_path=root_path)
    if not isinstance(recipient, ArenaIngressRecipient):
        raise ArenaIngressError("Arena ingress recipient is required")
    public = {
        **recipient.to_attestation_binding(),
        "quote": "",
        "quote_report_data": "",
        "app_id": "",
        "compose_hash": "",
        "os_image_hash": "",
        "verified": False,
    }
    if not dstack_utils.is_dstack_enabled():
        return {"mode": "local", **public}
    evidence_mode = (
        "simulator" if dstack_utils.is_dstack_simulator() else "tdx"
    )
    try:
        details = dstack_utils.get_attestation_details(recipient.report_data)
    except Exception:
        return {"mode": evidence_mode, **public}
    return {
        "mode": evidence_mode,
        **public,
        "quote": str(details.get("quote") or ""),
        "quote_report_data": str(details.get("quote_report_data") or ""),
        "app_id": str(details.get("app_id") or ""),
        "compose_hash": str(details.get("compose_hash") or ""),
        "os_image_hash": str(details.get("os_image_hash") or ""),
        "verified": False,
    }


def arena_candidate_browser_contract(
    recipient: ArenaIngressRecipient,
    *,
    max_envelopes: int = MAX_ENVELOPES,
) -> dict[str, Any]:
    """Return the exact browser-side cryptographic and gating contract."""

    if not isinstance(recipient, ArenaIngressRecipient):
        raise ArenaIngressError("Arena ingress recipient is required")
    configured_max_envelopes = _require_int(
        max_envelopes,
        label="max_envelopes",
        minimum=1,
        maximum=MAX_ENVELOPES,
    )
    return {
        "surface": "arena_candidate_browser_encryption_contract",
        "schema_version": INGRESS_SCHEMA_VERSION,
        "product_status": PRODUCT_STATUS,
        "execution_assurance": EXECUTION_ASSURANCE,
        "protocol": {
            "algorithm": INGRESS_ALGORITHM,
            "encoding": INGRESS_ENCODING,
            "x25519_public_key_bytes": X25519_PUBLIC_KEY_BYTES,
            "hkdf": {
                "hash": "SHA-256",
                "length_bytes": 32,
                "salt": "SHA-256(canonical_aad_bytes)",
                "info_utf8": INGRESS_HKDF_INFO.decode("ascii"),
            },
            "aes_gcm": {
                "key_bits": 256,
                "nonce_bytes": AES_GCM_NONCE_BYTES,
                "tag_bytes": GCM_TAG_BYTES,
                "additional_authenticated_data": "canonical_aad_bytes",
            },
        },
        "encoding_rules": {
            "binary_fields": "RFC4648 base64url without equals padding",
            "canonical_json": (
                "UTF-8 JSON; lexicographically sorted keys; comma and colon "
                "separators; ensure_ascii=true; allow_nan=false; no whitespace"
            ),
        },
        "aad": {
            "service": INGRESS_SERVICE,
            "context": INGRESS_CONTEXT,
            "schema_version": INGRESS_SCHEMA_VERSION,
            "exact_fields": [
                "service",
                "context",
                "schema_version",
                "challenge_id",
                "challenge_version",
                "challenge_manifest_hash",
                "submission_manifest_hash",
                "candidate_commitment",
                "identity",
                "idempotency_key_hash",
                "key_id",
                "attestation_report_data_sha256",
                "registry_authorization_sha256",
            ],
            "hash_formulas": {
                "challenge_manifest_hash": (
                    "lowercase 64-hex value from the exact challenge manifest"
                ),
                "submission_manifest_hash": (
                    "sha256: + SHA-256(canonical JSON of the exact submission manifest)"
                ),
                "candidate_commitment": "sha256: + SHA-256(raw candidate bytes)",
                "identity.wallet_address_hash": (
                    "SHA-256(utf8('arena_public_wallet') || 0x00 || "
                    "canonical JSON(normalized lowercase wallet address)) as 64 hex"
                ),
                "identity.project_id_hash": (
                    "SHA-256(utf8('arena_public_project') || 0x00 || "
                    "canonical JSON(project id)) as 64 hex"
                ),
                "idempotency_key_hash": (
                    "sha256: + SHA-256(canonical JSON of challenge_id, "
                    "challenge_version, public identity hashes, and raw Idempotency-Key)"
                ),
                "key_id": "sha256: + SHA-256(raw 32-byte recipient public key)",
                "attestation_report_data_sha256": (
                    "sha256: + SHA-256(raw 32-byte attestation report_data)"
                ),
                "registry_authorization_sha256": (
                    "sha256: + SHA-256(domain separator || canonical JSON of "
                    "the exact proposed finalized-block registry snapshot); "
                    "the API independently re-reads that snapshot before persistence"
                ),
            },
            "identity_derivation": {
                "wallet_address": "authenticated EVM address normalized to lowercase",
                "project_id": (
                    "personal- + first 32 lowercase hex characters of "
                    "SHA-256(utf8('arena-personal-project:') || "
                    "utf8(normalized wallet address))"
                ),
            },
        },
        "recipient": {
            **recipient.to_attestation_binding(),
            "attestation_report_data_sha256": _sha256_bytes(recipient.report_data),
            "report_data_contract": {
                "hash": "SHA-256",
                "canonical_json": arena_attestation_report_payload(
                    recipient.public_key
                ),
            },
        },
        "limits": {
            "max_aad_bytes": MAX_AAD_BYTES,
            "max_ciphertext_bytes_including_gcm_tag": MAX_CIPHERTEXT_BYTES,
            "max_plaintext_bytes_from_cipher_limit": (
                MAX_CIPHERTEXT_BYTES - GCM_TAG_BYTES
            ),
            "max_envelopes_per_store": configured_max_envelopes,
            "idempotency_key_max_bytes": 128,
        },
        "submission_gate": {
            "fresh_cvm_attestation_required": True,
            "independent_quote_and_measurement_verification_required": True,
            "matching_current_recipient_key_required": True,
            "matching_report_data_binding_required": True,
            "api_verified_field_is_not_a_policy_verdict": True,
            "server_generated_sealed_reference": True,
            "plaintext_candidate_accepted": False,
            "hostile_code_execution_enabled": False,
        },
        "envelope_exact_fields": [
            "schema_version",
            "algorithm",
            "encoding",
            "key_id",
            "attestation_report_data",
            "aad",
            "ephemeral_public_key",
            "nonce",
            "ciphertext",
        ],
        "raw_secret_egress": False,
    }


@dataclass(frozen=True, repr=False)
class StoredArenaCandidateEnvelope:
    """Strictly verified internal projection of one stored ciphertext blob."""

    binding: ArenaCandidateBinding
    envelope: ArenaCandidateEnvelope = field(repr=False)
    sealed_reference: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "StoredArenaCandidateEnvelope("
            f"challenge_id={self.binding.challenge_id!r}, "
            f"challenge_version={self.binding.challenge_version!r}, "
            f"ciphertext_bytes={self.envelope.ciphertext_bytes})"
        )


@dataclass(frozen=True)
class ArenaIngressResult:
    sealed_reference: str = field(repr=False)
    object_id: str = field(repr=False)
    blob_sha256: str
    ciphertext_sha256: str
    ciphertext_bytes: int
    key_id: str
    idempotency_hash: str = field(repr=False)
    request_hash: str = field(repr=False)
    created: bool

    def to_public_dict(self) -> dict[str, Any]:
        """Return a receipt without a reference or reconstructible object id."""

        return {
            "surface": "arena_candidate_ingress_receipt",
            "schema_version": INGRESS_SCHEMA_VERSION,
            "blob_sha256": self.blob_sha256,
            "ciphertext_sha256": self.ciphertext_sha256,
            "key_id": self.key_id,
            "created": self.created,
            "idempotent_replay": not self.created,
            "sealed_reference_public": False,
            "plaintext_candidate_accepted": False,
            "product_status": PRODUCT_STATUS,
            "execution_assurance": EXECUTION_ASSURANCE,
            "raw_secret_egress": False,
            "private_size_egress": False,
        }


@dataclass(frozen=True)
class _ArenaIngressIndexRecord:
    idempotency_hash: str
    request_hash: str
    object_id: str
    sealed_reference: str
    blob_sha256: str
    ciphertext_sha256: str
    aad_sha256: str
    ciphertext_bytes: int
    key_id: str

    _FIELDS = frozenset(
        {
            "idempotency_hash",
            "request_hash",
            "object_id",
            "sealed_reference",
            "blob_sha256",
            "ciphertext_sha256",
            "aad_sha256",
            "ciphertext_bytes",
            "key_id",
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "idempotency_hash": self.idempotency_hash,
            "request_hash": self.request_hash,
            "object_id": self.object_id,
            "sealed_reference": self.sealed_reference,
            "blob_sha256": self.blob_sha256,
            "ciphertext_sha256": self.ciphertext_sha256,
            "aad_sha256": self.aad_sha256,
            "ciphertext_bytes": self.ciphertext_bytes,
            "key_id": self.key_id,
        }

    @classmethod
    def from_mapping(
        cls, payload: Mapping[str, Any]
    ) -> "_ArenaIngressIndexRecord":
        try:
            _require_exact_keys(
                payload, cls._FIELDS, label="Arena ingress index record"
            )
            ciphertext_bytes = _require_int(
                payload["ciphertext_bytes"],
                label="ciphertext_bytes",
                minimum=GCM_TAG_BYTES + 1,
                maximum=MAX_CIPHERTEXT_BYTES,
            )
            record = cls(
                idempotency_hash=_require_string(
                    payload["idempotency_hash"],
                    label="idempotency_hash",
                    maximum=71,
                ),
                request_hash=_require_string(
                    payload["request_hash"], label="request_hash", maximum=71
                ),
                object_id=_require_string(
                    payload["object_id"], label="object_id", maximum=74
                ),
                sealed_reference=_require_string(
                    payload["sealed_reference"],
                    label="sealed_reference",
                    maximum=96,
                ),
                blob_sha256=_require_string(
                    payload["blob_sha256"], label="blob_sha256", maximum=71
                ),
                ciphertext_sha256=_require_string(
                    payload["ciphertext_sha256"],
                    label="ciphertext_sha256",
                    maximum=71,
                ),
                aad_sha256=_require_string(
                    payload["aad_sha256"], label="aad_sha256", maximum=71
                ),
                ciphertext_bytes=ciphertext_bytes,
                key_id=_require_string(
                    payload["key_id"], label="key_id", maximum=71
                ),
            )
        except ArenaIngressError as exc:
            raise ArenaIngressCorruptError(
                "Arena ingress index record failed verification"
            ) from exc
        for value in (
            record.idempotency_hash,
            record.request_hash,
            record.blob_sha256,
            record.ciphertext_sha256,
            record.aad_sha256,
            record.key_id,
        ):
            if not _SHA256.fullmatch(value):
                raise ArenaIngressCorruptError(
                    "Arena ingress index contains a malformed hash"
                )
        if not _OBJECT_ID.fullmatch(record.object_id):
            raise ArenaIngressCorruptError("Arena ingress object id is malformed")
        if record.sealed_reference != f"sealed://arena/{record.object_id}":
            raise ArenaIngressCorruptError(
                "Arena ingress sealed reference is inconsistent"
            )
        if record.object_id != f"candidate-{record.request_hash[7:]}":
            raise ArenaIngressCorruptError(
                "Arena ingress object id is not request-bound"
            )
        return record


class ArenaCandidateIngressStore:
    """Atomic, bounded store for ciphertext envelopes and hashed retries."""

    _INDEX_FIELDS = frozenset(
        {"surface", "schema_version", "records", "raw_candidate_persisted"}
    )
    _BLOB_FIELDS = frozenset(
        {"surface", "schema_version", "binding", "envelope", "raw_candidate_persisted"}
    )

    def __init__(
        self,
        root_dir: str | Path,
        *,
        max_envelopes: int = MAX_ENVELOPES,
    ) -> None:
        self.max_envelopes = _require_int(
            max_envelopes,
            label="max_envelopes",
            minimum=1,
            maximum=MAX_ENVELOPES,
        )
        self.root_dir = Path(root_dir)
        self.blob_dir = self.root_dir / "envelopes"
        self.index_path = self.root_dir / "index.json"
        self._lock = threading.RLock()
        _secure_directory(self.root_dir)
        _secure_directory(self.blob_dir)
        with self._lock:
            if self.index_path.exists() or self.index_path.is_symlink():
                self._records = self._load_index()
            else:
                self._records: dict[str, _ArenaIngressIndexRecord] = {}
                self._persist_index(self._records)
            self._verify_records(self._records)

    def put(
        self,
        *,
        binding: ArenaCandidateBinding,
        envelope: ArenaCandidateEnvelope,
    ) -> ArenaIngressResult:
        if not isinstance(binding, ArenaCandidateBinding):
            raise ArenaIngressError("Arena candidate binding is required")
        if not isinstance(envelope, ArenaCandidateEnvelope):
            raise ArenaIngressError("Arena candidate envelope is required")
        _verify_envelope_binding(binding, envelope)
        payload = {
            "surface": "arena_candidate_ciphertext_envelope",
            "schema_version": INGRESS_SCHEMA_VERSION,
            "binding": binding.to_aad_dict(),
            "envelope": envelope.to_persisted_dict(),
            "raw_candidate_persisted": False,
        }
        encoded = _canonical_json(payload) + b"\n"
        if len(encoded) > MAX_BLOB_FILE_BYTES:
            raise ArenaIngressError("Arena candidate ciphertext envelope is oversized")
        request_hash = _sha256_bytes(
            _canonical_json(
                {
                    "surface": "arena_candidate_ingress_request",
                    "binding": binding.to_aad_dict(),
                    "envelope": envelope.to_persisted_dict(),
                }
            )
        )
        object_id = f"candidate-{request_hash[7:]}"
        sealed_reference = f"sealed://arena/{object_id}"
        blob_sha256 = _sha256_bytes(
            b"arena_candidate_ciphertext_envelope_v1\0" + encoded
        )
        record = _ArenaIngressIndexRecord(
            idempotency_hash=binding.idempotency_key_hash,
            request_hash=request_hash,
            object_id=object_id,
            sealed_reference=sealed_reference,
            blob_sha256=blob_sha256,
            ciphertext_sha256=envelope.ciphertext_sha256,
            aad_sha256=envelope.aad_sha256,
            ciphertext_bytes=envelope.ciphertext_bytes,
            key_id=envelope.key_id,
        )
        with self._lock:
            existing = self._records.get(binding.idempotency_key_hash)
            if existing is not None:
                if not hmac.compare_digest(existing.request_hash, request_hash):
                    raise ArenaIngressConflict(
                        "Arena Idempotency-Key was already used for a different envelope"
                    )
                self._verify_blob(existing)
                return self._result(existing, created=False)
            if len(self._records) >= self.max_envelopes:
                raise ArenaIngressError("Arena candidate ingress store is full")
            target = self.blob_dir / f"{object_id}.json"
            self._write_new_blob(target, encoded)
            candidate_records = dict(self._records)
            candidate_records[binding.idempotency_key_hash] = record
            try:
                self._persist_index(candidate_records)
            except Exception:
                try:
                    target.unlink()
                    _fsync_directory(self.blob_dir)
                except OSError:
                    pass
                raise
            self._records = candidate_records
            return self._result(record, created=True)

    def load_envelope(self, sealed_reference: str) -> StoredArenaCandidateEnvelope:
        reference = _require_string(
            sealed_reference, label="Arena sealed reference", maximum=96
        )
        if not _SEALED_REFERENCE.fullmatch(reference):
            raise ArenaIngressError("Arena sealed reference is malformed")
        with self._lock:
            matches = [
                record
                for record in self._records.values()
                if hmac.compare_digest(record.sealed_reference, reference)
            ]
            if len(matches) != 1:
                raise ArenaIngressError("Unknown Arena sealed reference")
            binding, envelope = self._load_blob(matches[0])
            return StoredArenaCandidateEnvelope(
                binding=binding,
                envelope=envelope,
                sealed_reference=reference,
            )

    def rollback_created(self, result: ArenaIngressResult) -> None:
        """Roll back a same-request blob if Arena queue persistence then fails."""

        if not isinstance(result, ArenaIngressResult) or not result.created:
            return
        with self._lock:
            record = self._records.get(result.idempotency_hash)
            if record is None or not hmac.compare_digest(
                record.request_hash, result.request_hash
            ):
                return
            candidate_records = dict(self._records)
            del candidate_records[result.idempotency_hash]
            self._persist_index(candidate_records)
            self._records = candidate_records
            target = self.blob_dir / f"{record.object_id}.json"
            try:
                target.unlink()
                _fsync_directory(self.blob_dir)
            except FileNotFoundError:
                pass

    def _result(
        self, record: _ArenaIngressIndexRecord, *, created: bool
    ) -> ArenaIngressResult:
        return ArenaIngressResult(
            sealed_reference=record.sealed_reference,
            object_id=record.object_id,
            blob_sha256=record.blob_sha256,
            ciphertext_sha256=record.ciphertext_sha256,
            ciphertext_bytes=record.ciphertext_bytes,
            key_id=record.key_id,
            idempotency_hash=record.idempotency_hash,
            request_hash=record.request_hash,
            created=created,
        )

    def _write_new_blob(self, target: Path, encoded: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
        except FileExistsError as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate ciphertext object collision"
            ) from exc
        except OSError as exc:
            raise ArenaIngressUnavailable(
                "Arena candidate ciphertext object cannot be created"
            ) from exc
        try:
            os.fchmod(descriptor, 0o600)
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(self.blob_dir)

    def _persist_index(
        self, records: Mapping[str, _ArenaIngressIndexRecord]
    ) -> None:
        payload = {
            "surface": "arena_candidate_ingress_index",
            "schema_version": INGRESS_SCHEMA_VERSION,
            "records": [
                record.to_dict()
                for record in sorted(
                    records.values(), key=lambda item: item.idempotency_hash
                )
            ],
            "raw_candidate_persisted": False,
        }
        encoded = _canonical_json(payload) + b"\n"
        if len(encoded) > MAX_INDEX_BYTES:
            raise ArenaIngressError("Arena candidate ingress index is oversized")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".index.", suffix=".tmp", dir=str(self.root_dir)
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.index_path)
            os.chmod(self.index_path, 0o600)
            _fsync_directory(self.root_dir)
        except Exception:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            raise

    def _load_index(self) -> dict[str, _ArenaIngressIndexRecord]:
        try:
            metadata = self.index_path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ArenaIngressCorruptError("Arena ingress index path is unsafe")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ArenaIngressCorruptError(
                    "Arena ingress index must have mode 0600"
                )
            if metadata.st_size <= 0 or metadata.st_size > MAX_INDEX_BYTES:
                raise ArenaIngressCorruptError(
                    "Arena ingress index is empty or oversized"
                )
            payload = json.loads(
                self.index_path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            _require_exact_keys(
                payload, self._INDEX_FIELDS, label="Arena ingress index"
            )
            surface = _require_string(
                payload["surface"], label="Arena ingress index surface", maximum=64
            )
            schema_version = _require_int(
                payload["schema_version"],
                label="Arena ingress index schema_version",
                minimum=1,
                maximum=1,
            )
            if surface != "arena_candidate_ingress_index":
                raise ArenaIngressCorruptError(
                    "Arena ingress index surface is unsupported"
                )
            if schema_version != INGRESS_SCHEMA_VERSION:
                raise ArenaIngressCorruptError(
                    "Arena ingress index schema is unsupported"
                )
            if payload["raw_candidate_persisted"] is not False:
                raise ArenaIngressCorruptError(
                    "Arena ingress raw-candidate marker is unsafe"
                )
            raw_records = payload["records"]
            if not isinstance(raw_records, list) or len(raw_records) > self.max_envelopes:
                raise ArenaIngressCorruptError("Arena ingress records are malformed")
            records: dict[str, _ArenaIngressIndexRecord] = {}
            for item in raw_records:
                if not isinstance(item, Mapping):
                    raise ArenaIngressCorruptError(
                        "Arena ingress record must be an object"
                    )
                record = _ArenaIngressIndexRecord.from_mapping(item)
                if record.idempotency_hash in records:
                    raise ArenaIngressCorruptError(
                        "Arena ingress index has a duplicate idempotency hash"
                    )
                records[record.idempotency_hash] = record
            return records
        except ArenaIngressCorruptError:
            raise
        except (ArenaIngressError, OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate ingress index failed verification"
            ) from exc

    def _verify_records(
        self, records: Mapping[str, _ArenaIngressIndexRecord]
    ) -> None:
        object_ids: set[str] = set()
        references: set[str] = set()
        for record in records.values():
            if record.object_id in object_ids or record.sealed_reference in references:
                raise ArenaIngressCorruptError(
                    "Arena candidate ingress records are not one-to-one"
                )
            object_ids.add(record.object_id)
            references.add(record.sealed_reference)
            self._verify_blob(record)
        expected_files = {f"{object_id}.json" for object_id in object_ids}
        try:
            actual_files = {entry.name for entry in self.blob_dir.iterdir()}
        except OSError as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope directory is unavailable"
            ) from exc
        if actual_files != expected_files:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope directory contains unindexed state"
            )

    def _verify_blob(self, record: _ArenaIngressIndexRecord) -> None:
        self._load_blob(record)

    def _load_blob(
        self, record: _ArenaIngressIndexRecord
    ) -> tuple[ArenaCandidateBinding, ArenaCandidateEnvelope]:
        target = self.blob_dir / f"{record.object_id}.json"
        try:
            metadata = target.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope path is unsafe"
                )
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope must have mode 0600"
                )
            if metadata.st_size <= 0 or metadata.st_size > MAX_BLOB_FILE_BYTES:
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope is empty or oversized"
                )
            encoded = target.read_bytes()
        except FileNotFoundError as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope is missing"
            ) from exc
        except OSError as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope is unavailable"
            ) from exc
        actual_blob_hash = _sha256_bytes(
            b"arena_candidate_ciphertext_envelope_v1\0" + encoded
        )
        if not hmac.compare_digest(actual_blob_hash, record.blob_sha256):
            raise ArenaIngressCorruptError("Arena candidate envelope hash mismatch")
        try:
            payload = json.loads(
                encoded.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
            _require_exact_keys(
                payload, self._BLOB_FIELDS, label="Arena candidate envelope file"
            )
            surface = _require_string(
                payload["surface"],
                label="Arena candidate envelope surface",
                maximum=64,
            )
            schema_version = _require_int(
                payload["schema_version"],
                label="Arena candidate envelope schema_version",
                minimum=1,
                maximum=1,
            )
            if surface != "arena_candidate_ciphertext_envelope":
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope surface is unsupported"
                )
            if schema_version != INGRESS_SCHEMA_VERSION:
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope schema is unsupported"
                )
            if payload["raw_candidate_persisted"] is not False:
                raise ArenaIngressCorruptError(
                    "Arena candidate envelope raw-candidate marker is unsafe"
                )
            binding = ArenaCandidateBinding.from_mapping(payload["binding"])
            envelope = ArenaCandidateEnvelope.from_mapping(payload["envelope"])
        except ArenaIngressCorruptError:
            raise
        except (ArenaIngressError, UnicodeError, json.JSONDecodeError) as exc:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope failed verification"
            ) from exc
        _verify_envelope_binding(binding, envelope)
        if not hmac.compare_digest(record.idempotency_hash, binding.idempotency_key_hash):
            raise ArenaIngressCorruptError(
                "Arena candidate envelope idempotency binding mismatch"
            )
        for expected, actual, label in (
            (record.ciphertext_sha256, envelope.ciphertext_sha256, "ciphertext hash"),
            (record.aad_sha256, envelope.aad_sha256, "AAD hash"),
            (record.key_id, envelope.key_id, "recipient key"),
        ):
            if not hmac.compare_digest(expected, actual):
                raise ArenaIngressCorruptError(
                    f"Arena candidate envelope {label} mismatch"
                )
        if record.ciphertext_bytes != envelope.ciphertext_bytes:
            raise ArenaIngressCorruptError(
                "Arena candidate envelope ciphertext size mismatch"
            )
        return binding, envelope


class ArenaCandidateIngressService:
    """Validate browser envelopes and persist ciphertext without decrypting it."""

    def __init__(
        self,
        store: ArenaCandidateIngressStore,
        recipient: ArenaIngressRecipient,
    ) -> None:
        if not isinstance(store, ArenaCandidateIngressStore):
            raise ArenaIngressError("Arena candidate ingress store is required")
        if not isinstance(recipient, ArenaIngressRecipient):
            raise ArenaIngressError("Arena ingress recipient is required")
        self.store = store
        self.recipient = recipient

    def binding_for(
        self,
        *,
        challenge: ChallengeManifest,
        identity: SubmissionIdentity,
        candidate_commitment: str,
        manifest: SubmissionManifest,
        idempotency_key: str,
        registry_authorization_sha256: str,
    ) -> ArenaCandidateBinding:
        return build_arena_candidate_binding(
            challenge=challenge,
            identity=identity,
            candidate_commitment=candidate_commitment,
            manifest=manifest,
            recipient=self.recipient,
            idempotency_key=idempotency_key,
            registry_authorization_sha256=registry_authorization_sha256,
        )

    def ingest(
        self,
        *,
        challenge: ChallengeManifest,
        identity: SubmissionIdentity,
        candidate_commitment: str,
        manifest: SubmissionManifest,
        idempotency_key: str,
        registry_authorization_sha256: str,
        envelope: ArenaCandidateEnvelope | Mapping[str, Any],
    ) -> ArenaIngressResult:
        parsed = (
            envelope
            if isinstance(envelope, ArenaCandidateEnvelope)
            else ArenaCandidateEnvelope.from_mapping(envelope)
        )
        binding = self.binding_for(
            challenge=challenge,
            identity=identity,
            candidate_commitment=candidate_commitment,
            manifest=manifest,
            idempotency_key=idempotency_key,
            registry_authorization_sha256=registry_authorization_sha256,
        )
        if not hmac.compare_digest(parsed.key_id, self.recipient.key_id):
            raise ArenaIngressError(
                "Arena candidate envelope targets a different recipient key"
            )
        if not hmac.compare_digest(
            parsed.attestation_report_data, self.recipient.report_data.hex()
        ):
            raise ArenaIngressError(
                "Arena candidate envelope attestation report-data binding mismatch"
            )
        expected_aad = arena_candidate_aad(binding)
        actual_aad = _b64url_decode(
            parsed.aad, label="aad", maximum_bytes=MAX_AAD_BYTES
        )
        if not hmac.compare_digest(actual_aad, expected_aad):
            raise ArenaIngressError("Arena candidate envelope AAD binding mismatch")
        expected_ciphertext_bytes = manifest.source_bytes + GCM_TAG_BYTES
        if parsed.ciphertext_bytes != expected_ciphertext_bytes:
            raise ArenaIngressError(
                "Arena ciphertext length must equal source_bytes plus the GCM tag"
            )
        _verify_envelope_binding(binding, parsed)
        return self.store.put(binding=binding, envelope=parsed)


def build_arena_candidate_ingress(
    settings: Any,
    *,
    root_path: str | Path | None = None,
) -> ArenaCandidateIngressService:
    configured = str(
        _settings_value(settings, "arena_candidate_ingress_store_path", "") or ""
    ).strip()
    if root_path is not None and str(root_path).strip():
        store_path = Path(root_path)
    elif configured:
        store_path = Path(configured)
    else:
        raise ArenaIngressUnavailable(
            "Arena candidate ingress durable store is not configured"
        )
    max_envelopes = _settings_value(
        settings, "arena_candidate_ingress_max_envelopes", MAX_ENVELOPES
    )
    recipient = resolve_arena_recipient(settings, root_path=store_path)
    return ArenaCandidateIngressService(
        ArenaCandidateIngressStore(store_path, max_envelopes=max_envelopes),
        recipient,
    )


def _verify_envelope_binding(
    binding: ArenaCandidateBinding,
    envelope: ArenaCandidateEnvelope,
) -> None:
    if not hmac.compare_digest(binding.key_id, envelope.key_id):
        raise ArenaIngressCorruptError(
            "Arena candidate envelope key binding mismatch"
        )
    report_data = bytes.fromhex(envelope.attestation_report_data)
    if not hmac.compare_digest(
        binding.attestation_report_data_sha256,
        _sha256_bytes(report_data),
    ):
        raise ArenaIngressCorruptError(
            "Arena candidate envelope attestation binding mismatch"
        )
    expected_aad = arena_candidate_aad(binding)
    actual_aad = _b64url_decode(
        envelope.aad, label="aad", maximum_bytes=MAX_AAD_BYTES
    )
    if not hmac.compare_digest(actual_aad, expected_aad):
        raise ArenaIngressCorruptError(
            "Arena candidate envelope canonical AAD mismatch"
        )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArenaIngressCorruptError(
                "Arena candidate ingress JSON contains duplicate keys"
            )
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> Any:
    raise ArenaIngressCorruptError(
        "Arena candidate ingress JSON contains a non-finite number"
    )


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while persisting Arena candidate state")
        view = view[written:]


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)
