"""Production assembly for the wallet-owned Tinker customer adapter.

The HTTP application must not assemble release authority from request fields or
from a loose collection of mutable environment values.  This module loads one
exact SHA-256-pinned private authority document, verifies independently signed
runtime/provisioning/settlement envelopes, and binds the customer journal to a
dedicated opaque head in ``ExecutionPolicyAnchor``.

Provider credentials, provider account identifiers, project identifiers,
prompts, datasets, outputs, and payment-card material are not accepted by any
schema in this module.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import threading
from dataclasses import fields
from dataclasses import asdict
from pathlib import Path
from typing import Any, Mapping, TypeVar

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from tinker_delegate import dstack_utils
from tinker_delegate.execution_policy_anchor import (
    AnchorProjection,
    AnchorProjectionRecord,
    ExecutionPolicyAnchorError,
    HttpsExecutionPolicyAnchorGateway,
    ZERO_BYTES32,
    verify_live_execution_policy_release_binding,
)
from tinker_delegate.tinker_customer_adapter import (
    AttestedProvisioningResult,
    AttestedSettlementResult,
    CustomerAccountPolicy,
    CustomerStateAnchorHead,
    DualRpcTinkerReleaseReader,
    ExpectedTinkerRelease,
    RuntimeEvidence,
    RuntimeEvidencePolicy,
    TinkerCustomerAdapter,
    TinkerCustomerError,
    TinkerCustomerStore,
    TinkerCustomerUnavailable,
)
from tinker_delegate.wallet_signature_verifier import BoundedJsonRpcClient


TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA = (
    "dnai.tinker-customer-runtime-authority.v1"
)
TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA = (
    "dnai.tinker-customer-runtime-evidence-envelope.v1"
)
TINKER_CUSTOMER_PROVISIONING_SCHEMA = (
    "dnai.tinker-customer-provisioning-envelope.v1"
)
TINKER_CUSTOMER_SETTLEMENT_SCHEMA = (
    "dnai.tinker-customer-settlement-envelope.v1"
)
TINKER_CUSTOMER_TRAINING_RESULT_SCHEMA = (
    "dnai.tinker-customer-training-result-envelope.v1"
)

TINKER_CUSTOMER_STORE_KEY_PATH = "tinker/customer_store_integrity"
TINKER_CUSTOMER_CREDENTIAL_KEY_PATH = "tinker/customer_credentials"
TINKER_CUSTOMER_SETTLEMENT_KEY_PATH = "tinker/customer_settlement_evidence"

_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_SHA256_OR_ZERO = re.compile(r"^sha256:[0-9a-f]{64}$")
_BARE_HASH = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_PUBLIC_KEY = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_ACCOUNT_ID = re.compile(r"^tca_[0-9a-f]{24}$")
_RESERVATION_ID = re.compile(r"^tcr_[0-9a-f]{24}$")
_MAX_AUTHORITY_BYTES = 64 * 1024
_MAX_ENVELOPE_BYTES = 256 * 1024
_MAX_TRAINING_RESULT_BYTES = 64 * 1024

_T = TypeVar("_T")


class TinkerCustomerRuntimeError(TinkerCustomerUnavailable):
    """A release-pinned customer runtime dependency is unavailable."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority is not canonical JSON"
        ) from exc


def _exact_mapping(
    value: Any,
    keys: set[str],
    label: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise TinkerCustomerRuntimeError(f"{label} fields are not exact")
    return value


def _private_regular_file(path: Path, *, maximum: int) -> bytes:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise TinkerCustomerRuntimeError("private evidence path is invalid")
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        before = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > maximum
            or before.st_dev != current.st_dev
            or before.st_ino != current.st_ino
        ):
            raise TinkerCustomerRuntimeError(
                "private evidence file metadata is invalid"
            )
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 65_536))
            if not chunk:
                raise TinkerCustomerRuntimeError(
                    "private evidence file ended early"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TinkerCustomerRuntimeError(
                "private evidence file exceeds its declared size"
            )
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            before.st_size != after.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or after.st_dev != current.st_dev
            or after.st_ino != current.st_ino
        ):
            raise TinkerCustomerRuntimeError(
                "private evidence file changed during read"
            )
        return b"".join(chunks)
    except TinkerCustomerRuntimeError:
        raise
    except OSError as exc:
        raise TinkerCustomerRuntimeError(
            "private evidence file is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_directory(path: Path) -> Path:
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise TinkerCustomerRuntimeError("private evidence directory is invalid")
    try:
        details = path.lstat()
    except OSError as exc:
        raise TinkerCustomerRuntimeError(
            "private evidence directory is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise TinkerCustomerRuntimeError(
            "private evidence directory metadata is invalid"
        )
    return path


def _atomic_private_write_once(
    path: Path,
    raw: bytes,
    *,
    maximum: int,
) -> None:
    """Create one immutable-by-content private file or accept an exact replay."""

    if (
        not isinstance(raw, bytes)
        or not raw
        or len(raw) > maximum
        or not path.is_absolute()
        or path.name in {"", ".", ".."}
    ):
        raise TinkerCustomerRuntimeError(
            "private evidence write is invalid"
        )
    parent = _private_directory(path.parent)
    if path.exists():
        existing = _private_regular_file(path, maximum=maximum)
        if not hmac.compare_digest(existing, raw):
            raise TinkerCustomerRuntimeError(
                "private evidence replay differs"
            )
        return
    directory_fd = -1
    descriptor = -1
    temporary_name = (
        f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(8)}"
    )
    try:
        directory_fd = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise TinkerCustomerRuntimeError(
                    "private evidence write ended early"
                )
            view = view[written:]
        os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size != len(raw)
        ):
            raise TinkerCustomerRuntimeError(
                "private evidence staged metadata is invalid"
            )
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(
                temporary_name,
                path.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            existing = _private_regular_file(path, maximum=maximum)
            if not hmac.compare_digest(existing, raw):
                raise TinkerCustomerRuntimeError(
                    "private evidence replay differs"
                ) from None
        os.unlink(temporary_name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    except TinkerCustomerRuntimeError:
        raise
    except OSError as exc:
        raise TinkerCustomerRuntimeError(
            "private evidence write is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
            os.close(directory_fd)


def _json_object(raw: bytes, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise TinkerCustomerRuntimeError(f"{label} is invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise TinkerCustomerRuntimeError(f"{label} must be an object")
    return value


def _sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _public_key(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or _PUBLIC_KEY.fullmatch(value) is None:
        raise TinkerCustomerRuntimeError(f"{label} is invalid")
    return bytes.fromhex(value)


def _absolute_path(value: Any, label: str) -> Path:
    if not isinstance(value, str):
        raise TinkerCustomerRuntimeError(f"{label} is invalid")
    path = Path(value)
    if (
        not path.is_absolute()
        or os.path.normpath(value) != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise TinkerCustomerRuntimeError(f"{label} is invalid")
    return path


def _tuple_of_strings(value: Any, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) for item in value)
    ):
        raise TinkerCustomerRuntimeError(f"{label} is invalid")
    return tuple(value)


def _exact_dataclass_payload(
    payload: Any,
    value_type: type[_T],
    label: str,
) -> _T:
    names = {field.name for field in fields(value_type)}
    exact = _exact_mapping(payload, names, label)
    try:
        return value_type(**dict(exact))
    except (TypeError, ValueError, TinkerCustomerError) as exc:
        raise TinkerCustomerRuntimeError(f"{label} is invalid") from exc


def _signed_payload(
    path: Path,
    *,
    schema: str,
    public_key: bytes,
) -> Mapping[str, Any]:
    envelope = _json_object(
        _private_regular_file(path, maximum=_MAX_ENVELOPE_BYTES),
        "signed Tinker customer envelope",
    )
    exact = _exact_mapping(
        envelope,
        {"schema", "signer_public_key_hash", "payload", "signature"},
        "signed Tinker customer envelope",
    )
    key_hash = _sha256_bytes(public_key)
    if (
        exact["schema"] != schema
        or exact["signer_public_key_hash"] != key_hash
        or not isinstance(exact["signature"], str)
        or _SIGNATURE.fullmatch(exact["signature"]) is None
        or not isinstance(exact["payload"], Mapping)
    ):
        raise TinkerCustomerRuntimeError(
            "signed Tinker customer envelope policy is invalid"
        )
    message = (
        (schema + "\0").encode("ascii")
        + _canonical_json(exact["payload"])
    )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            bytes.fromhex(exact["signature"]),
            message,
        )
    except (InvalidSignature, ValueError) as exc:
        raise TinkerCustomerRuntimeError(
            "signed Tinker customer envelope signature is invalid"
        ) from exc
    return exact["payload"]


class SignedRuntimeEvidenceProvider:
    """Read one short-lived, independently signed runtime-evidence lease."""

    def __init__(self, path: Path, public_key: bytes) -> None:
        self.path = path
        self.public_key = public_key

    def read(self, *, now: int) -> RuntimeEvidence:
        del now  # The adapter validates exact lease time and maximum lifetime.
        payload = _signed_payload(
            self.path,
            schema=TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA,
            public_key=self.public_key,
        )
        exact = dict(payload)
        exact["enabled_operations"] = _tuple_of_strings(
            exact.get("enabled_operations"),
            "runtime enabled operations",
        )
        return _exact_dataclass_payload(
            exact,
            RuntimeEvidence,
            "Tinker customer runtime evidence",
        )


class SignedProvisioningResultProvider:
    """Resolve one request-bound, signer-authenticated provisioning result."""

    def __init__(self, directory: Path, public_key: bytes) -> None:
        self.directory = _private_directory(directory)
        self.public_key = public_key

    def consume(
        self,
        *,
        account_id: str,
        request_commitment: str,
        now: int,
    ) -> AttestedProvisioningResult:
        del request_commitment, now
        if _ACCOUNT_ID.fullmatch(account_id) is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer account result identity is invalid"
            )
        payload = _signed_payload(
            self.directory / f"{account_id}.json",
            schema=TINKER_CUSTOMER_PROVISIONING_SCHEMA,
            public_key=self.public_key,
        )
        result = _exact_dataclass_payload(
            payload,
            AttestedProvisioningResult,
            "Tinker customer provisioning result",
        )
        if result.account_id != account_id:
            raise TinkerCustomerRuntimeError(
                "Tinker customer provisioning result identity differs"
            )
        return result


class SignedSettlementResultProvider:
    """Resolve one reservation-bound, signer-authenticated settlement result."""

    def __init__(
        self,
        directory: Path,
        public_key: bytes,
        *,
        signing_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.directory = _private_directory(directory)
        self.public_key = public_key
        self.signing_key = signing_key
        self._write_lock = threading.RLock()
        if signing_key is not None:
            derived_public = signing_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            if not hmac.compare_digest(derived_public, public_key):
                raise TinkerCustomerRuntimeError(
                    "Tinker customer settlement signer differs from authority"
                )

    def consume(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
        now: int,
    ) -> AttestedSettlementResult:
        del reservation_commitment, now
        if _RESERVATION_ID.fullmatch(reservation_id) is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement result identity is invalid"
            )
        payload = _signed_payload(
            self.directory / f"{reservation_id}.json",
            schema=TINKER_CUSTOMER_SETTLEMENT_SCHEMA,
            public_key=self.public_key,
        )
        result = _exact_dataclass_payload(
            payload,
            AttestedSettlementResult,
            "Tinker customer settlement result",
        )
        if result.reservation_id != reservation_id:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement result identity differs"
            )
        return result

    def publish_training_result(
        self,
        *,
        settlement: AttestedSettlementResult,
        training_result: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        """Persist one signed, replayable bounded training outcome.

        The training envelope is written before the settlement envelope.  A
        crash between those writes is recoverable without provider redispatch:
        an exact retry reuses the authenticated training envelope and repairs
        only the missing settlement projection.
        """

        if self.signing_key is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement writer is unavailable"
            )
        if type(settlement) is not AttestedSettlementResult:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement result is invalid"
            )
        reservation_id = settlement.reservation_id
        if _RESERVATION_ID.fullmatch(reservation_id) is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement identity is invalid"
            )
        if not isinstance(training_result, Mapping):
            raise TinkerCustomerRuntimeError(
                "Tinker customer training result is invalid"
            )
        payload = {
            "reservation_id": reservation_id,
            "reservation_commitment": settlement.reservation_commitment,
            "settlement": asdict(settlement),
            "training_result": dict(training_result),
        }
        training_raw = self._signed_envelope_bytes(
            TINKER_CUSTOMER_TRAINING_RESULT_SCHEMA,
            payload,
        )
        settlement_raw = self._signed_envelope_bytes(
            TINKER_CUSTOMER_SETTLEMENT_SCHEMA,
            asdict(settlement),
        )
        with self._write_lock:
            _atomic_private_write_once(
                self.directory / f"{reservation_id}.training.json",
                training_raw,
                maximum=_MAX_TRAINING_RESULT_BYTES,
            )
            _atomic_private_write_once(
                self.directory / f"{reservation_id}.json",
                settlement_raw,
                maximum=_MAX_ENVELOPE_BYTES,
            )
        return payload

    def recover_training_result(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
    ) -> Mapping[str, Any]:
        """Read and authenticate the replay result, repairing no provider work."""

        if _RESERVATION_ID.fullmatch(reservation_id) is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer training result identity is invalid"
            )
        payload = _signed_payload(
            self.directory / f"{reservation_id}.training.json",
            schema=TINKER_CUSTOMER_TRAINING_RESULT_SCHEMA,
            public_key=self.public_key,
        )
        exact = _exact_mapping(
            payload,
            {
                "reservation_id",
                "reservation_commitment",
                "settlement",
                "training_result",
            },
            "Tinker customer training result",
        )
        if (
            exact["reservation_id"] != reservation_id
            or exact["reservation_commitment"] != reservation_commitment
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer training result binding differs"
            )
        settlement = _exact_dataclass_payload(
            exact["settlement"],
            AttestedSettlementResult,
            "Tinker customer training settlement",
        )
        if (
            settlement.reservation_id != reservation_id
            or settlement.reservation_commitment != reservation_commitment
            or not isinstance(exact["training_result"], Mapping)
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer training settlement binding differs"
            )
        return {
            "reservation_id": reservation_id,
            "reservation_commitment": reservation_commitment,
            "settlement": settlement,
            "training_result": dict(exact["training_result"]),
        }

    def ensure_settlement_projection(
        self,
        *,
        reservation_id: str,
        reservation_commitment: str,
    ) -> Mapping[str, Any]:
        """Recover a partial write by projecting the already signed result."""

        recovered = self.recover_training_result(
            reservation_id=reservation_id,
            reservation_commitment=reservation_commitment,
        )
        settlement = recovered["settlement"]
        if not isinstance(settlement, AttestedSettlementResult):
            raise TinkerCustomerRuntimeError(
                "Tinker customer training settlement is invalid"
            )
        raw = self._signed_envelope_bytes(
            TINKER_CUSTOMER_SETTLEMENT_SCHEMA,
            asdict(settlement),
        )
        with self._write_lock:
            _atomic_private_write_once(
                self.directory / f"{reservation_id}.json",
                raw,
                maximum=_MAX_ENVELOPE_BYTES,
            )
        return recovered

    def _signed_envelope_bytes(
        self,
        schema: str,
        payload: Mapping[str, Any],
    ) -> bytes:
        signing_key = self.signing_key
        if signing_key is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement writer is unavailable"
            )
        message = (schema + "\0").encode("ascii") + _canonical_json(payload)
        envelope = {
            "schema": schema,
            "signer_public_key_hash": _sha256_bytes(self.public_key),
            "payload": dict(payload),
            "signature": signing_key.sign(message).hex(),
        }
        return _canonical_json(envelope)


def _state_head(value: str) -> str:
    if value == ZERO_BYTES32:
        return "sha256:" + "00" * 32
    if not isinstance(value, str) or not re.fullmatch(
        r"^0x[0-9a-f]{64}$",
        value,
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer chain anchor head is invalid"
        )
    return "sha256:" + value[2:]


def _bare_state_head(value: str) -> str:
    if not isinstance(value, str) or _SHA256_OR_ZERO.fullmatch(value) is None:
        raise TinkerCustomerRuntimeError(
            "Tinker customer state head is invalid"
        )
    return value.split(":", 1)[1]


class ExecutionPolicyCustomerStateAnchor:
    """Use one opaque ExecutionPolicyAnchor resource as a rollback witness.

    The contract's resource sequence is a global anchor sequence, so it may
    legitimately skip when another release-bound resource is anchored.  The
    customer store's local sequence remains exact and monotonic; reconciliation
    is based on the committed 32-byte state head.
    """

    def __init__(
        self,
        gateway: HttpsExecutionPolicyAnchorGateway,
        *,
        resource_id_hash: str,
    ) -> None:
        if _BARE_HASH.fullmatch(resource_id_hash) is None:
            raise TinkerCustomerRuntimeError(
                "Tinker customer anchor resource hash is invalid"
            )
        self.gateway = gateway
        self.resource_id_hash = resource_id_hash

    def close(self) -> None:
        self.gateway.close()

    def read_head(self) -> CustomerStateAnchorHead:
        try:
            snapshot = self.gateway.finalized_snapshot(
                resource_id_hash=self.resource_id_hash
            )
        except ExecutionPolicyAnchorError as exc:
            raise TinkerCustomerRuntimeError(
                "Tinker customer state anchor is unavailable"
            ) from exc
        return CustomerStateAnchorHead(
            sequence=snapshot.resource_sequence,
            head_hash=_state_head(snapshot.resource_decision_head),
        )

    def compare_and_set(
        self,
        *,
        expected_sequence: int,
        expected_head_hash: str,
        new_sequence: int,
        new_head_hash: str,
    ) -> CustomerStateAnchorHead:
        if (
            type(expected_sequence) is not int
            or type(new_sequence) is not int
            or expected_sequence < 0
            or new_sequence != expected_sequence + 1
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer local anchor sequence is invalid"
            )
        _bare_state_head(expected_head_hash)
        new_bare = _bare_state_head(new_head_hash)
        try:
            latest = self.gateway.latest_snapshot(
                resource_id_hash=self.resource_id_hash,
                decision_hash=new_bare,
            )
            if not hmac.compare_digest(
                _state_head(latest.resource_decision_head),
                expected_head_hash,
            ):
                raise TinkerCustomerRuntimeError(
                    "Tinker customer state anchor predecessor differs"
                )
            prefix = AnchorProjection(
                sequence=latest.global_sequence,
                global_head=latest.global_head,
                resource_heads={
                    self.resource_id_hash: (
                        latest.resource_decision_head,
                        latest.resource_sequence,
                    )
                },
            )
            anchored = self.gateway.anchor_record(
                prefix=prefix,
                record=AnchorProjectionRecord(
                    sequence=latest.global_sequence + 1,
                    resource_id_hash=self.resource_id_hash,
                    decision_hash=new_bare,
                ),
            )
        except TinkerCustomerRuntimeError:
            raise
        except ExecutionPolicyAnchorError as exc:
            raise TinkerCustomerRuntimeError(
                "Tinker customer state anchor update is unavailable"
            ) from exc
        if (
            not hmac.compare_digest(
                _state_head(anchored.resource_decision_head),
                new_head_hash,
            )
            or anchored.decision_hash != new_bare
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer state anchor successor differs"
            )
        return CustomerStateAnchorHead(
            sequence=new_sequence,
            head_hash=new_head_hash,
        )


def _load_authority(settings: Any) -> dict[str, Any]:
    authority_path = _absolute_path(
        getattr(settings, "tinker_customer_authority_path", ""),
        "Tinker customer authority path",
    )
    expected_digest = getattr(
        settings,
        "tinker_customer_authority_sha256",
        "",
    )
    if not isinstance(expected_digest, str) or _SHA256.fullmatch(
        expected_digest
    ) is None:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority SHA-256 is invalid"
        )
    raw = _private_regular_file(
        authority_path,
        maximum=_MAX_AUTHORITY_BYTES,
    )
    if not hmac.compare_digest(_sha256_bytes(raw), expected_digest):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority SHA-256 differs"
        )
    document = _exact_mapping(
        _json_object(raw, "Tinker customer runtime authority"),
        {
            "schema",
            "status",
            "expected_release",
            "account_policy",
            "runtime_evidence_policy",
            "evidence",
        },
        "Tinker customer runtime authority",
    )
    if (
        document["schema"] != TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA
        or document["status"] != "enabled"
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer runtime authority is not enabled"
        )
    return dict(document)


def _build_expected_release(value: Any) -> ExpectedTinkerRelease:
    keys = {field.name for field in fields(ExpectedTinkerRelease)}
    exact = dict(_exact_mapping(value, keys, "expected Tinker release"))
    exact["approved_compose_hashes"] = _tuple_of_strings(
        exact["approved_compose_hashes"],
        "approved compose hashes",
    )
    exact["managers"] = _tuple_of_strings(
        exact["managers"],
        "release managers",
    )
    try:
        return ExpectedTinkerRelease(**exact)
    except (TypeError, ValueError, TinkerCustomerError) as exc:
        raise TinkerCustomerRuntimeError(
            "expected Tinker release is invalid"
        ) from exc


def _build_account_policy(value: Any) -> CustomerAccountPolicy:
    keys = {field.name for field in fields(CustomerAccountPolicy)}
    exact = dict(_exact_mapping(value, keys, "Tinker customer account policy"))
    exact["allowed_operations"] = _tuple_of_strings(
        exact["allowed_operations"],
        "customer allowed operations",
    )
    try:
        return CustomerAccountPolicy(**exact)
    except (TypeError, ValueError, TinkerCustomerError) as exc:
        raise TinkerCustomerRuntimeError(
            "Tinker customer account policy is invalid"
        ) from exc


def _build_evidence_policy(value: Any) -> RuntimeEvidencePolicy:
    keys = {field.name for field in fields(RuntimeEvidencePolicy)}
    exact = dict(_exact_mapping(value, keys, "Tinker runtime evidence policy"))
    exact["enabled_operations"] = _tuple_of_strings(
        exact["enabled_operations"],
        "runtime enabled operations",
    )
    try:
        return RuntimeEvidencePolicy(**exact)
    except (TypeError, ValueError, TinkerCustomerError) as exc:
        raise TinkerCustomerRuntimeError(
            "Tinker runtime evidence policy is invalid"
        ) from exc


def _runtime_secret(
    settings: Any,
    *,
    explicit_field: str,
    path_field: str,
    required_path: str,
    domain: bytes,
) -> bytes:
    explicit = str(getattr(settings, explicit_field, "") or "")
    configured_path = str(getattr(settings, path_field, "") or "").strip()
    if configured_path != required_path:
        raise TinkerCustomerRuntimeError(
            "Tinker customer dstack key path differs from release policy"
        )
    if dstack_utils.is_dstack_enabled():
        if explicit:
            raise TinkerCustomerRuntimeError(
                "explicit Tinker customer keys are forbidden in dstack"
            )
        if dstack_utils.is_dstack_simulator():
            raise TinkerCustomerRuntimeError(
                "real dstack is required for Tinker customer activation"
            )
        try:
            material = dstack_utils.derive_storage_key(configured_path)
        except Exception as exc:
            raise TinkerCustomerRuntimeError(
                "Tinker customer dstack key derivation failed"
            ) from exc
    else:
        material = explicit.encode("utf-8")
        if len(material) < 32:
            raise TinkerCustomerRuntimeError(
                "local Tinker customer key is unavailable"
            )
    return hashlib.sha256(domain + material).digest()


def _settlement_signing_key(settings: Any) -> Ed25519PrivateKey:
    seed = _runtime_secret(
        settings,
        explicit_field="tinker_customer_settlement_signing_key",
        path_field="tinker_customer_settlement_key_path",
        required_path=TINKER_CUSTOMER_SETTLEMENT_KEY_PATH,
        domain=b"dnai-wikigen/tinker-customer-settlement-evidence/v1\0",
    )
    return Ed25519PrivateKey.from_private_bytes(seed)


def build_tinker_customer_adapter(
    settings: Any,
    *,
    wallet_verifier: Any,
) -> TinkerCustomerAdapter:
    """Assemble the live adapter only from server-owned, pinned authority."""

    if getattr(settings, "tinker_customer_enabled", False) is not True:
        raise TinkerCustomerRuntimeError(
            "Tinker customer lifecycle is disabled by this release"
        )
    authority = _load_authority(settings)
    expected_release = _build_expected_release(authority["expected_release"])
    configured_contract = str(
        getattr(settings, "encumbrance_contract_address", "") or ""
    ).strip().lower()
    if configured_contract and configured_contract != expected_release.contract_address:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority contract differs from runtime configuration"
        )
    account_policy = _build_account_policy(authority["account_policy"])
    evidence_policy = _build_evidence_policy(
        authority["runtime_evidence_policy"]
    )
    evidence = _exact_mapping(
        authority["evidence"],
        {
            "runtime_evidence_path",
            "runtime_evidence_public_key",
            "provisioning_directory",
            "provisioning_public_key",
            "settlement_directory",
            "settlement_public_key",
            "state_anchor_resource_hash",
        },
        "Tinker customer evidence authority",
    )
    runtime_key = _public_key(
        evidence["runtime_evidence_public_key"],
        "runtime evidence public key",
    )
    provisioning_key = _public_key(
        evidence["provisioning_public_key"],
        "provisioning public key",
    )
    settlement_key = _public_key(
        evidence["settlement_public_key"],
        "settlement public key",
    )
    key_hashes = {
        _sha256_bytes(runtime_key),
        _sha256_bytes(provisioning_key),
        _sha256_bytes(settlement_key),
    }
    if len(key_hashes) != 3:
        raise TinkerCustomerRuntimeError(
            "Tinker customer evidence signer keys must be distinct"
        )
    resource_hash = evidence["state_anchor_resource_hash"]
    if not isinstance(resource_hash, str) or _BARE_HASH.fullmatch(
        resource_hash
    ) is None:
        raise TinkerCustomerRuntimeError(
            "Tinker customer state anchor resource hash is invalid"
        )
    primary_url = str(
        getattr(settings, "wallet_auth_rpc_url", "") or ""
    ).strip()
    secondary_url = str(
        getattr(settings, "wallet_auth_rpc_url_secondary", "") or ""
    ).strip()
    if not primary_url or not secondary_url:
        raise TinkerCustomerRuntimeError(
            "Tinker customer release reads require two RPC providers"
        )
    primary = BoundedJsonRpcClient(
        primary_url,
        timeout_seconds=getattr(
            settings,
            "wallet_auth_rpc_timeout_seconds",
            3.0,
        ),
        max_response_bytes=getattr(
            settings,
            "wallet_auth_rpc_max_response_bytes",
            131_072,
        ),
    )
    secondary = BoundedJsonRpcClient(
        secondary_url,
        timeout_seconds=getattr(
            settings,
            "wallet_auth_rpc_timeout_seconds",
            3.0,
        ),
        max_response_bytes=getattr(
            settings,
            "wallet_auth_rpc_max_response_bytes",
            131_072,
        ),
    )
    release_reader = DualRpcTinkerReleaseReader(
        primary,
        secondary,
        expected_release,
    )
    gateway: HttpsExecutionPolicyAnchorGateway | None = None
    state_anchor: ExecutionPolicyCustomerStateAnchor | None = None
    try:
        gateway = HttpsExecutionPolicyAnchorGateway.from_settings(
            settings,
            read_only=False,
        )
        verify_live_execution_policy_release_binding(settings, gateway)
        state_anchor = ExecutionPolicyCustomerStateAnchor(
            gateway,
            resource_id_hash=resource_hash,
        )
        store_path = _absolute_path(
            getattr(settings, "tinker_customer_store_path", ""),
            "Tinker customer store path",
        )
        store_key = _runtime_secret(
            settings,
            explicit_field="tinker_customer_store_integrity_key",
            path_field="tinker_customer_store_integrity_key_path",
            required_path=TINKER_CUSTOMER_STORE_KEY_PATH,
            domain=b"dnai-wikigen/tinker-customer-store-runtime/v1\0",
        )
        credential_key = _runtime_secret(
            settings,
            explicit_field="tinker_customer_credential_signing_key",
            path_field="tinker_customer_credential_key_path",
            required_path=TINKER_CUSTOMER_CREDENTIAL_KEY_PATH,
            domain=b"dnai-wikigen/tinker-customer-credential-runtime/v1\0",
        )
        settlement_signing_key = _settlement_signing_key(settings)
        settlement_signing_public_key = (
            settlement_signing_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        if not hmac.compare_digest(
            settlement_signing_public_key,
            settlement_key,
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer settlement signer differs from authority"
            )
        store = TinkerCustomerStore(
            store_path,
            store_key,
            anchor=state_anchor,
        )
        adapter = TinkerCustomerAdapter(
            wallet_verifier=wallet_verifier,
            release_reader=release_reader,
            expected_release=expected_release,
            evidence_provider=SignedRuntimeEvidenceProvider(
                _absolute_path(
                    evidence["runtime_evidence_path"],
                    "runtime evidence path",
                ),
                runtime_key,
            ),
            evidence_policy=evidence_policy,
            provisioning_provider=SignedProvisioningResultProvider(
                _absolute_path(
                    evidence["provisioning_directory"],
                    "provisioning evidence directory",
                ),
                provisioning_key,
            ),
            settlement_provider=SignedSettlementResultProvider(
                _absolute_path(
                    evidence["settlement_directory"],
                    "settlement evidence directory",
                ),
                settlement_key,
                signing_key=settlement_signing_key,
            ),
            store=store,
            account_policy=account_policy,
            credential_signing_key=credential_key,
        )
    except Exception:
        if state_anchor is not None:
            state_anchor.close()
        elif gateway is not None:
            gateway.close()
        raise
    return adapter


__all__ = [
    "ExecutionPolicyCustomerStateAnchor",
    "SignedProvisioningResultProvider",
    "SignedRuntimeEvidenceProvider",
    "SignedSettlementResultProvider",
    "TINKER_CUSTOMER_CREDENTIAL_KEY_PATH",
    "TINKER_CUSTOMER_PROVISIONING_SCHEMA",
    "TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA",
    "TINKER_CUSTOMER_RUNTIME_EVIDENCE_SCHEMA",
    "TINKER_CUSTOMER_SETTLEMENT_SCHEMA",
    "TINKER_CUSTOMER_STORE_KEY_PATH",
    "TinkerCustomerRuntimeError",
    "build_tinker_customer_adapter",
]
