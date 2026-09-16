"""Measured one-shot mailbox genesis for the canonical main CVM.

This module is deliberately separate from the long-running oracle.  The normal
oracle remains fail closed with automatic genesis disabled.  A reviewed Compose
profile may run this module exactly once to create and seal a mailbox, publish a
bounded receipt, and make a short-lived encrypted mailbox handoff available to
the separately measured Tinker account-genesis service.

The receipt never contains a mailbox address, username, password, provider
identifier, credential hash, ciphertext, nonce, or dstack-derived secret.
Independent QVL verification remains an external ceremony step; this process
only binds the already reviewed lineage and its own bounded dstack observation.
"""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Awaitable, Callable, Mapping
from contextlib import redirect_stderr, redirect_stdout
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from email_oracle.config import Settings
from email_oracle.cred_store import CredentialStore, EmailCredentials
from email_oracle.dstack_utils import derive_storage_key, get_attestation_details


MAILBOX_GENESIS_RECEIPT_SCHEMA = "dnai.main-cvm-mailbox-genesis-receipt.v1"
MAILBOX_GENESIS_CLAIM_SCHEMA = "dnai.main-cvm-mailbox-genesis-claim.v1"
MAILBOX_GENESIS_RETIREMENT_SCHEMA = "dnai.main-cvm-mailbox-genesis-retirement.v1"
ACCOUNT_GENESIS_RETIREMENT_SCHEMA = (
    "dnai.main-cvm-tinker-account-genesis-retirement.v1"
)
MAILBOX_HANDOFF_SCHEMA = "dnai.main-cvm-mailbox-handoff.v1"
MAILBOX_HANDOFF_RETIREMENT_SCHEMA = (
    "dnai.main-cvm-mailbox-handoff-retirement.v1"
)
MAILBOX_HANDOFF_AAD = b"dnai-wikigen/main-cvm-mailbox-handoff/v1\0"
MAILBOX_HANDOFF_KEY_PATH = "tinker/signup-mailbox"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_HEX64 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_APP_ID = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1


class MailboxGenesisProfileError(RuntimeError):
    """Fail-closed one-shot profile error."""


def _canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise MailboxGenesisProfileError("genesis evidence path is not a directory")
    if (
        info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise MailboxGenesisProfileError(
            "genesis evidence directory ownership or mode is invalid"
        )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_retained_directory(path: Path, descriptor: int) -> os.stat_result:
    retained = os.fstat(descriptor)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise MailboxGenesisProfileError(
            "genesis evidence directory binding is invalid"
        ) from exc
    if (
        not stat.S_ISDIR(retained.st_mode)
        or retained.st_uid != os.geteuid()
        or stat.S_IMODE(retained.st_mode) != 0o700
        or not _same_file_identity(retained, current)
    ):
        raise MailboxGenesisProfileError(
            "genesis evidence directory binding is invalid"
        )
    return retained


def _create_private_json(path: Path, value: Mapping[str, Any]) -> None:
    _ensure_private_directory(path.parent)
    directory_fd = os.open(
        path.parent,
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
    )
    descriptor = -1
    try:
        _validate_retained_directory(path.parent, directory_fd)
        descriptor = os.open(
            path.name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=directory_fd,
        )
        payload = _canonical_json_bytes(value)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or not _same_file_identity(info, current)
        ):
            raise MailboxGenesisProfileError(
                "genesis evidence file binding is invalid"
            )
        os.fsync(directory_fd)
        _validate_retained_directory(path.parent, directory_fd)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if not _same_file_identity(info, current):
            raise MailboxGenesisProfileError(
                "genesis evidence file binding is invalid"
            )
    except FileExistsError as exc:
        raise MailboxGenesisProfileError(
            "one-shot mailbox-genesis artifact already exists"
        ) from exc
    except MailboxGenesisProfileError:
        raise
    except OSError as exc:
        raise MailboxGenesisProfileError(
            "mailbox-genesis evidence publication failed"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(directory_fd)


def _sample_timestamp(clock: Callable[[], int]) -> int:
    value = clock()
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > _MAX_JSON_SAFE_INTEGER
    ):
        raise MailboxGenesisProfileError("mailbox-genesis timestamp is invalid")
    return value


def _validate_lineage(lineage: Mapping[str, Any]) -> dict[str, Any]:
    expected_keys = {
        "release_sha",
        "deployment_intent_sha256",
        "genesis_authorization_sha256",
        "main_qvl_verdict_sha256",
        "measurement_policy_sha256",
        "main_runtime_cvm_id",
        "main_app_id",
        "main_compose_hash",
        "main_os_image_hash",
        "tinker_account_binding_ceremony_receipt_sha256",
        "account_binding_commitment",
        "reviewer_genesis_acceptance_sha256",
        "reviewer_current_status_epoch",
        "reviewer_current_status_sha256",
    }
    if set(lineage) != expected_keys:
        raise MailboxGenesisProfileError("mailbox genesis lineage keys are not exact")
    normalized = {key: lineage[key] for key in expected_keys}
    if not isinstance(normalized["release_sha"], str) or not _SHA40.fullmatch(
        normalized["release_sha"]
    ):
        raise MailboxGenesisProfileError("mailbox genesis release SHA is invalid")
    for key in (
        "deployment_intent_sha256",
        "genesis_authorization_sha256",
        "main_qvl_verdict_sha256",
        "measurement_policy_sha256",
        "tinker_account_binding_ceremony_receipt_sha256",
        "reviewer_genesis_acceptance_sha256",
        "reviewer_current_status_sha256",
    ):
        if (
            not isinstance(normalized[key], str)
            or not _SHA256.fullmatch(normalized[key])
        ):
            raise MailboxGenesisProfileError(f"mailbox genesis {key} is invalid")
    if (
        not isinstance(normalized["main_runtime_cvm_id"], str)
        or not normalized["main_runtime_cvm_id"].strip()
        or len(normalized["main_runtime_cvm_id"]) > 160
    ):
        raise MailboxGenesisProfileError("mailbox genesis main CVM id is invalid")
    if not isinstance(normalized["main_app_id"], str) or not _APP_ID.fullmatch(
        normalized["main_app_id"]
    ):
        raise MailboxGenesisProfileError("mailbox genesis main app id is invalid")
    for key in ("main_compose_hash", "main_os_image_hash"):
        if (
            not isinstance(normalized[key], str)
            or not _HEX64.fullmatch(normalized[key])
        ):
            raise MailboxGenesisProfileError(f"mailbox genesis {key} is invalid")
    if (
        not isinstance(normalized["account_binding_commitment"], str)
        or not _BYTES32.fullmatch(normalized["account_binding_commitment"])
    ):
        raise MailboxGenesisProfileError(
            "mailbox genesis account binding commitment is invalid"
        )
    epoch = normalized["reviewer_current_status_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise MailboxGenesisProfileError("mailbox genesis reviewer epoch is invalid")
    normalized["main_runtime_cvm_id"] = normalized["main_runtime_cvm_id"].strip()
    return normalized


def mailbox_genesis_lineage_from_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Read only public, reviewed lineage values from the process environment."""

    source = environment if environment is not None else os.environ
    try:
        epoch = int(source.get("ORACLE_GENESIS_REVIEWER_CURRENT_STATUS_EPOCH", ""))
    except ValueError as exc:
        raise MailboxGenesisProfileError(
            "mailbox genesis reviewer epoch is invalid"
        ) from exc
    return _validate_lineage(
        {
            "release_sha": source.get("ORACLE_GENESIS_RELEASE_SHA", ""),
            "deployment_intent_sha256": source.get(
                "ORACLE_GENESIS_DEPLOYMENT_INTENT_SHA256", ""
            ),
            "genesis_authorization_sha256": source.get(
                "ORACLE_GENESIS_AUTHORIZATION_SHA256", ""
            ),
            "main_qvl_verdict_sha256": source.get(
                "ORACLE_GENESIS_MAIN_QVL_VERDICT_SHA256", ""
            ),
            "measurement_policy_sha256": source.get(
                "ORACLE_GENESIS_MEASUREMENT_POLICY_SHA256", ""
            ),
            "main_runtime_cvm_id": source.get(
                "ORACLE_GENESIS_MAIN_RUNTIME_CVM_ID", ""
            ),
            "main_app_id": source.get("ORACLE_GENESIS_MAIN_APP_ID", ""),
            "main_compose_hash": source.get(
                "ORACLE_GENESIS_MAIN_COMPOSE_HASH", ""
            ),
            "main_os_image_hash": source.get(
                "ORACLE_GENESIS_MAIN_OS_IMAGE_HASH", ""
            ),
            "tinker_account_binding_ceremony_receipt_sha256": source.get(
                "ORACLE_GENESIS_BINDING_CEREMONY_RECEIPT_SHA256",
                "",
            ),
            "account_binding_commitment": source.get(
                "ORACLE_GENESIS_ACCOUNT_BINDING_COMMITMENT",
                "",
            ),
            "reviewer_genesis_acceptance_sha256": source.get(
                "ORACLE_GENESIS_REVIEWER_GENESIS_ACCEPTANCE_SHA256", ""
            ),
            "reviewer_current_status_epoch": epoch,
            "reviewer_current_status_sha256": source.get(
                "ORACLE_GENESIS_REVIEWER_CURRENT_STATUS_SHA256", ""
            ),
        }
    )


def _validate_runtime_evidence(
    evidence: Mapping[str, Any],
    lineage: Mapping[str, Any],
) -> dict[str, str]:
    public = {
        "app_id": evidence.get("app_id"),
        "compose_hash": evidence.get("compose_hash"),
        "os_image_hash": evidence.get("os_image_hash"),
    }
    if public != {
        "app_id": lineage["main_app_id"],
        "compose_hash": lineage["main_compose_hash"],
        "os_image_hash": lineage["main_os_image_hash"],
    }:
        raise MailboxGenesisProfileError(
            "running dstack identity does not match mailbox genesis authority"
        )
    return {key: str(value) for key, value in public.items()}


def _default_runtime_evidence(report_data: bytes) -> Mapping[str, Any]:
    details = get_attestation_details(report_data)
    # Raw quote, event log, VM config, and TCB material are intentionally not
    # returned to the receipt builder. They remain private inputs for the
    # independent QVL ceremony.
    return {
        "app_id": details.get("app_id"),
        "compose_hash": details.get("compose_hash"),
        "os_image_hash": details.get("os_image_hash"),
    }


def seal_mailbox_handoff(
    path: Path,
    credentials: EmailCredentials,
    *,
    key: bytes | None = None,
    key_path: str = MAILBOX_HANDOFF_KEY_PATH,
) -> None:
    """Create the internal encrypted mailbox handoff without logging it."""

    if key is None:
        key = derive_storage_key(key_path)
    if not isinstance(key, bytes) or len(key) != 32:
        raise MailboxGenesisProfileError("mailbox handoff key must be 32 bytes")
    plaintext = _canonical_json_bytes(
        {
            "schema": MAILBOX_HANDOFF_SCHEMA,
            "email": credentials.email,
        }
    )
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, MAILBOX_HANDOFF_AAD)
    _create_private_json(
        path,
        {
            "schema": MAILBOX_HANDOFF_SCHEMA,
            "algorithm": "AES-256-GCM",
            "key_path": key_path,
            "nonce_b64": base64.b64encode(nonce).decode("ascii"),
            "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        },
    )


async def _default_create_account(
    settings: Settings,
    store: CredentialStore,
) -> EmailCredentials:
    from email_oracle.account_creator import create_account

    return await create_account(settings, store)


async def run_mailbox_genesis_profile(
    settings: Settings,
    store: CredentialStore,
    *,
    lineage: Mapping[str, Any],
    evidence_directory: Path,
    handoff_path: Path,
    create_account_fn: Callable[
        [Settings, CredentialStore], Awaitable[EmailCredentials]
    ] = _default_create_account,
    runtime_evidence_fn: Callable[
        [bytes], Mapping[str, Any]
    ] = _default_runtime_evidence,
    handoff_key: bytes | None = None,
    clock: Callable[[], int] = lambda: int(time.time()),
    evidence_mode: str = "measured_runtime_pending_independent_qvl_recheck",
) -> dict[str, Any]:
    """Attempt mailbox creation exactly once and retire the side-effect lane."""

    reviewed_lineage = _validate_lineage(lineage)
    if evidence_mode not in {
        "measured_runtime_pending_independent_qvl_recheck",
        "injected_local_test",
    }:
        raise MailboxGenesisProfileError("mailbox genesis evidence mode is invalid")
    _ensure_private_directory(evidence_directory)
    claim_path = evidence_directory / "claim.json"
    receipt_path = evidence_directory / "receipt.json"
    retirement_path = evidence_directory / "retirement.json"
    if store.exists():
        raise MailboxGenesisProfileError(
            "mailbox credential store already exists; fresh genesis refuses reuse"
        )
    if handoff_path.exists():
        raise MailboxGenesisProfileError(
            "mailbox handoff already exists; fresh genesis refuses reuse"
        )

    started_at = _sample_timestamp(clock)
    _create_private_json(
        claim_path,
        {
            "schema": MAILBOX_GENESIS_CLAIM_SCHEMA,
            "status": "claimed_once",
            "started_at": started_at,
            "release_sha": reviewed_lineage["release_sha"],
            "genesis_authorization_sha256": reviewed_lineage[
                "genesis_authorization_sha256"
            ],
            "tinker_account_binding_ceremony_receipt_sha256": (
                reviewed_lineage[
                    "tinker_account_binding_ceremony_receipt_sha256"
                ]
            ),
            "account_binding_commitment": reviewed_lineage[
                "account_binding_commitment"
            ],
            "raw_secret_egress": False,
        },
    )

    succeeded = False
    receipt: dict[str, Any]
    try:
        report_data = (
            MAILBOX_GENESIS_RECEIPT_SCHEMA
            + "\0"
            + reviewed_lineage["genesis_authorization_sha256"]
        ).encode("ascii")
        runtime = _validate_runtime_evidence(
            runtime_evidence_fn(report_data),
            reviewed_lineage,
        )
        # Provider libraries and the retained research implementation may print
        # mailbox-derived hashes. The one-shot production profile discards all
        # unbounded provider output and emits only its reviewed receipt shape.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with redirect_stdout(sink), redirect_stderr(sink):
                credentials = await create_account_fn(settings, store)
        if not isinstance(credentials, EmailCredentials):
            raise MailboxGenesisProfileError(
                "mailbox provider did not return sealed credential material"
            )
        sealed = store.load() if store.exists() else None
        if sealed is None or sealed.to_dict() != credentials.to_dict():
            raise MailboxGenesisProfileError(
                "mailbox credential store round-trip did not match"
            )
        seal_mailbox_handoff(
            handoff_path,
            credentials,
            key=handoff_key,
        )
        receipt = {
            "schema": MAILBOX_GENESIS_RECEIPT_SCHEMA,
            "status": "mailbox_created_and_sealed",
            "success": True,
            "attempt_count": 1,
            "mailbox_created": True,
            "sealed_credentials_roundtrip_verified": True,
            "sealed_mailbox_handoff_created": True,
            "provider_identifier_committed": False,
            "credential_material_committed": False,
            "raw_secret_egress": False,
            "live_traffic_authorized": False,
            "independent_qvl_verified_by_profile": False,
            "independent_qvl_evidence_bound": True,
            "evidence_mode": evidence_mode,
            "completed_at": _sample_timestamp(clock),
            "lineage": reviewed_lineage,
            "runtime": runtime,
        }
        succeeded = True
    except Exception:
        receipt = {
            "schema": MAILBOX_GENESIS_RECEIPT_SCHEMA,
            "status": "mailbox_creation_not_confirmed",
            "success": False,
            "attempt_count": 1,
            "mailbox_created": None,
            "sealed_credentials_roundtrip_verified": False,
            "sealed_mailbox_handoff_created": False,
            "provider_identifier_committed": False,
            "credential_material_committed": False,
            "raw_secret_egress": False,
            "live_traffic_authorized": False,
            "independent_qvl_verified_by_profile": False,
            "independent_qvl_evidence_bound": True,
            "evidence_mode": evidence_mode,
            "completed_at": _sample_timestamp(clock),
            "lineage": reviewed_lineage,
            "runtime": None,
        }

    _create_private_json(receipt_path, receipt)
    _create_private_json(
        retirement_path,
        {
            "schema": MAILBOX_GENESIS_RETIREMENT_SCHEMA,
            "status": "retired_after_single_attempt",
            "mailbox_genesis_success": succeeded,
            "retry_permitted": False,
            "profile_must_remain_disabled": True,
            "retired_at": _sample_timestamp(clock),
            "release_sha": reviewed_lineage["release_sha"],
            "genesis_authorization_sha256": reviewed_lineage[
                "genesis_authorization_sha256"
            ],
            "tinker_account_binding_ceremony_receipt_sha256": (
                reviewed_lineage[
                    "tinker_account_binding_ceremony_receipt_sha256"
                ]
            ),
            "account_binding_commitment": reviewed_lineage[
                "account_binding_commitment"
            ],
            "raw_secret_egress": False,
        },
    )
    return receipt


def _read_private_canonical_json(
    path: Path,
    *,
    maximum_bytes: int = 16_384,
) -> dict[str, Any]:
    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_retained_directory(path.parent, directory_fd)
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        before = os.fstat(descriptor)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size <= 0
            or before.st_size > maximum_bytes
            or not _same_file_identity(before, current)
        ):
            raise MailboxGenesisProfileError(
                "account retirement artifact binding is invalid"
            )
        payload = bytearray()
        while len(payload) <= maximum_bytes:
            chunk = os.read(
                descriptor,
                min(4096, maximum_bytes + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            len(payload) > maximum_bytes
            or before.st_size != len(payload)
            or before.st_size != after.st_size
            or before.st_nlink != after.st_nlink
            or not _same_file_identity(before, after)
            or not _same_file_identity(after, current)
        ):
            raise MailboxGenesisProfileError(
                "account retirement artifact changed during read"
            )
        _validate_retained_directory(path.parent, directory_fd)
        try:
            value = json.loads(bytes(payload))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MailboxGenesisProfileError(
                "account retirement artifact is not canonical JSON"
            ) from exc
        if (
            not isinstance(value, dict)
            or _canonical_json_bytes(value) != bytes(payload)
        ):
            raise MailboxGenesisProfileError(
                "account retirement artifact is not canonical JSON"
            )
        return value
    except MailboxGenesisProfileError:
        raise
    except OSError as exc:
        raise MailboxGenesisProfileError(
            "account retirement artifact is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


def account_retirement_is_complete(
    path: Path,
    *,
    lineage: Mapping[str, Any],
) -> bool:
    """Accept only the complete canonical account-retirement projection."""

    try:
        value = _read_private_canonical_json(path)
    except MailboxGenesisProfileError:
        return False
    expected_keys = {
        "schema",
        "status",
        "account_genesis_success",
        "retry_permitted",
        "profile_must_remain_disabled",
        "retired_at",
        "release_sha",
        "deployment_intent_sha256",
        "genesis_authorization_sha256",
        "tinker_account_binding_ceremony_receipt_sha256",
        "account_binding_commitment",
        "reviewer_genesis_acceptance_sha256",
        "reviewer_current_status_epoch",
        "reviewer_current_status_sha256",
        "raw_secret_egress",
    }
    retired_at = value.get("retired_at")
    return (
        set(value) == expected_keys
        and value.get("schema") == ACCOUNT_GENESIS_RETIREMENT_SCHEMA
        and value.get("status") == "retired_after_single_attempt"
        and type(value.get("account_genesis_success")) is bool
        and value.get("retry_permitted") is False
        and value.get("profile_must_remain_disabled") is True
        and isinstance(retired_at, int)
        and not isinstance(retired_at, bool)
        and 0 <= retired_at <= _MAX_JSON_SAFE_INTEGER
        and value.get("release_sha") == lineage["release_sha"]
        and value.get("deployment_intent_sha256")
        == lineage["deployment_intent_sha256"]
        and value.get("genesis_authorization_sha256")
        == lineage["genesis_authorization_sha256"]
        and value.get(
            "tinker_account_binding_ceremony_receipt_sha256"
        )
        == lineage["tinker_account_binding_ceremony_receipt_sha256"]
        and value.get("account_binding_commitment")
        == lineage["account_binding_commitment"]
        and value.get("reviewer_genesis_acceptance_sha256")
        == lineage["reviewer_genesis_acceptance_sha256"]
        and value.get("reviewer_current_status_epoch")
        == lineage["reviewer_current_status_epoch"]
        and value.get("reviewer_current_status_sha256")
        == lineage["reviewer_current_status_sha256"]
        and value.get("raw_secret_egress") is False
    )


def durably_unlink_mailbox_handoff(path: Path) -> None:
    """Remove the exact handoff and prove the retained directory commit."""

    directory_fd = -1
    descriptor = -1
    try:
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_retained_directory(path.parent, directory_fd)
        descriptor = os.open(
            path.name,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        retained = os.fstat(descriptor)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(retained.st_mode)
            or retained.st_nlink != 1
            or retained.st_uid != os.geteuid()
            or stat.S_IMODE(retained.st_mode) != 0o600
            or not _same_file_identity(retained, current)
        ):
            raise MailboxGenesisProfileError(
                "mailbox handoff retirement binding is invalid"
            )
        os.unlink(path.name, dir_fd=directory_fd)
        if os.fstat(descriptor).st_nlink != 0:
            raise MailboxGenesisProfileError(
                "mailbox handoff retirement is indeterminate"
            )
        os.fsync(directory_fd)
        _validate_retained_directory(path.parent, directory_fd)
        try:
            os.stat(
                path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            return
        raise MailboxGenesisProfileError(
            "mailbox handoff retirement is indeterminate"
        )
    except MailboxGenesisProfileError:
        raise
    except OSError as exc:
        raise MailboxGenesisProfileError(
            "mailbox handoff retirement is indeterminate"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            os.close(directory_fd)


def publish_mailbox_handoff_retirement(
    *,
    handoff_path: Path,
    lineage: Mapping[str, Any],
    retirement_receipt_path: Path,
    clock: Callable[[], int] = lambda: int(time.time()),
) -> dict[str, Any]:
    """Publish create-only evidence only after the handoff is durably absent."""

    reviewed_lineage = _validate_lineage(lineage)
    directory_fd = -1
    try:
        directory_fd = os.open(
            handoff_path.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        _validate_retained_directory(handoff_path.parent, directory_fd)
        os.fsync(directory_fd)
        try:
            os.stat(
                handoff_path.name,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            pass
        else:
            raise MailboxGenesisProfileError(
                "mailbox handoff is present after retirement"
            )
    except MailboxGenesisProfileError:
        raise
    except OSError as exc:
        raise MailboxGenesisProfileError(
            "mailbox handoff retirement observation is indeterminate"
        ) from exc
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)

    receipt = {
        "schema": MAILBOX_HANDOFF_RETIREMENT_SCHEMA,
        "status": "encrypted_mailbox_handoff_retired",
        "account_genesis_retirement_observed": True,
        "handoff_path_absent_after_directory_fsync": True,
        "release_sha": reviewed_lineage["release_sha"],
        "genesis_authorization_sha256": reviewed_lineage[
            "genesis_authorization_sha256"
        ],
        "tinker_account_binding_ceremony_receipt_sha256": reviewed_lineage[
            "tinker_account_binding_ceremony_receipt_sha256"
        ],
        "retired_at": _sample_timestamp(clock),
        "raw_secret_egress": False,
    }
    _create_private_json(retirement_receipt_path, receipt)
    return receipt


async def serve_genesis_oracle_until_account_retired(
    *,
    account_retirement_path: Path,
    handoff_path: Path,
    lineage: Mapping[str, Any],
    timeout_seconds: int,
    poll_interval_seconds: float = 1.0,
) -> bool:
    """Serve the internal OTP API only until account genesis retires or times out."""

    if not 30 <= timeout_seconds <= 3_600:
        raise MailboxGenesisProfileError("genesis oracle timeout is outside 30..3600")
    if not 0.1 <= poll_interval_seconds <= 10:
        raise MailboxGenesisProfileError("genesis oracle poll interval is invalid")

    import uvicorn

    retirement_observed = False
    with open(os.devnull, "w", encoding="utf-8") as sink:
        # The retained oracle logs mailbox-derived hashes when it loads its
        # store. This private one-shot server therefore suppresses all process
        # output while it exposes only the bearer-protected internal OTP API.
        with redirect_stdout(sink), redirect_stderr(sink):
            config = uvicorn.Config(
                "email_oracle.api:app",
                host="0.0.0.0",
                port=8000,
                log_level="warning",
                access_log=False,
            )
            server = uvicorn.Server(config)

            async def watch_retirement() -> None:
                nonlocal retirement_observed
                deadline = asyncio.get_running_loop().time() + timeout_seconds
                while not server.should_exit:
                    if account_retirement_is_complete(
                        account_retirement_path,
                        lineage=lineage,
                    ):
                        retirement_observed = True
                        server.should_exit = True
                        return
                    if asyncio.get_running_loop().time() >= deadline:
                        server.should_exit = True
                        return
                    await asyncio.sleep(poll_interval_seconds)

            watcher = asyncio.create_task(watch_retirement())
            try:
                await server.serve()
                await watcher
            finally:
                server.should_exit = True
                if not watcher.done():
                    watcher.cancel()
                try:
                    await watcher
                except asyncio.CancelledError:
                    pass
                durably_unlink_mailbox_handoff(handoff_path)
    return retirement_observed


async def cli_run() -> int:
    settings = Settings()
    store = CredentialStore(
        settings.cred_store_path,
        settings.cred_store_key,
        dstack_enabled=settings.dstack_enabled,
        dstack_key_path=settings.dstack_key_path,
    )
    evidence_directory = Path(
        os.environ.get(
            "ORACLE_GENESIS_EVIDENCE_DIRECTORY",
            "/evidence/mailbox-genesis",
        )
    )
    handoff_path = Path(
        os.environ.get(
            "ORACLE_GENESIS_HANDOFF_PATH",
            "/handoff/mailbox-genesis/signup-mailbox.enc",
        )
    )
    account_retirement_path = Path(
        os.environ.get(
            "ORACLE_GENESIS_ACCOUNT_RETIREMENT_PATH",
            "/account-evidence/tinker-account-genesis/retirement.json",
        )
    )
    try:
        timeout_seconds = int(
            os.environ.get("ORACLE_GENESIS_ACCOUNT_TIMEOUT_SECONDS", "900")
        )
    except ValueError as exc:
        raise MailboxGenesisProfileError("genesis oracle timeout is invalid") from exc

    lineage = mailbox_genesis_lineage_from_environment()
    receipt = await run_mailbox_genesis_profile(
        settings,
        store,
        lineage=lineage,
        evidence_directory=evidence_directory,
        handoff_path=handoff_path,
    )
    if receipt["success"] is not True:
        print(
            json.dumps(
                {
                    "schema": MAILBOX_GENESIS_RECEIPT_SCHEMA,
                    "status": receipt["status"],
                    "success": False,
                    "raw_secret_egress": False,
                },
                sort_keys=True,
            )
        )
        return 1
    account_retired = await serve_genesis_oracle_until_account_retired(
        account_retirement_path=account_retirement_path,
        handoff_path=handoff_path,
        lineage=lineage,
        timeout_seconds=timeout_seconds,
    )
    if account_retired:
        publish_mailbox_handoff_retirement(
            handoff_path=handoff_path,
            lineage=lineage,
            retirement_receipt_path=(
                evidence_directory / "handoff-retirement.json"
            ),
        )
    print(
        json.dumps(
            {
                "schema": MAILBOX_GENESIS_RECEIPT_SCHEMA,
                "status": (
                    "mailbox_genesis_retired"
                    if account_retired
                    else "mailbox_genesis_account_timeout"
                ),
                "success": account_retired,
                "raw_secret_egress": False,
            },
            sort_keys=True,
        )
    )
    return 0 if account_retired else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(cli_run()))
