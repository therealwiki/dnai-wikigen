"""Measured one-shot Tinker account genesis for the canonical main CVM.

The profile consumes an encrypted same-CVM mailbox handoff, recomputes the
reviewed opaque account-binding commitment from two private shares, and refuses
all provider interaction if that commitment differs from the immutable
deployment-intent value rendered into the measured descriptor.

Successful provider signup is represented only by bounded booleans.  The
receipt never includes a provider account id, mailbox, API key, binding root,
share, credential/session material, or a hash derived from any of those
secrets.  It is not an independent QVL verdict and cannot enable live traffic.
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

from tinker_delegate.api_key_store import build_api_key_store
from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, get_attestation_details
from tinker_delegate.tinker_account_binding import (
    TINKER_ACCOUNT_BINDING_CHAIN_ID,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    TINKER_ACCOUNT_BINDING_TYPE,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    TINKER_PROVIDER_NAMESPACE,
    TINKER_PROVIDER_NAMESPACE_LABEL,
    derive_tinker_account_binding_root,
    derive_tinker_account_commitment,
)


ACCOUNT_GENESIS_RECEIPT_SCHEMA = "dnai.main-cvm-tinker-account-genesis-receipt.v1"
ACCOUNT_GENESIS_CLAIM_SCHEMA = "dnai.main-cvm-tinker-account-genesis-claim.v1"
ACCOUNT_GENESIS_RETIREMENT_SCHEMA = (
    "dnai.main-cvm-tinker-account-genesis-retirement.v1"
)
MAILBOX_HANDOFF_SCHEMA = "dnai.main-cvm-mailbox-handoff.v1"
MAILBOX_HANDOFF_AAD = b"dnai-wikigen/main-cvm-mailbox-handoff/v1\0"
MAILBOX_HANDOFF_KEY_PATH = "tinker/signup-mailbox"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_HEX64 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_APP_ID = re.compile(r"^0x(?!0{40}$)[0-9a-f]{40}$")
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1


class AccountGenesisProfileError(RuntimeError):
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
        raise AccountGenesisProfileError(
            "account-genesis evidence path is not a directory"
        )
    if (
        info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise AccountGenesisProfileError(
            "account-genesis evidence directory ownership or mode is invalid"
        )


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _validate_retained_directory(path: Path, descriptor: int) -> os.stat_result:
    retained = os.fstat(descriptor)
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise AccountGenesisProfileError(
            "account-genesis evidence directory binding is invalid"
        ) from exc
    if (
        not stat.S_ISDIR(retained.st_mode)
        or retained.st_uid != os.geteuid()
        or stat.S_IMODE(retained.st_mode) != 0o700
        or not _same_file_identity(retained, current)
    ):
        raise AccountGenesisProfileError(
            "account-genesis evidence directory binding is invalid"
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
            raise AccountGenesisProfileError(
                "account-genesis evidence file binding is invalid"
            )
        os.fsync(directory_fd)
        _validate_retained_directory(path.parent, directory_fd)
        current = os.stat(
            path.name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if not _same_file_identity(info, current):
            raise AccountGenesisProfileError(
                "account-genesis evidence file binding is invalid"
            )
    except FileExistsError as exc:
        raise AccountGenesisProfileError(
            "one-shot account-genesis artifact already exists"
        ) from exc
    except AccountGenesisProfileError:
        raise
    except OSError as exc:
        raise AccountGenesisProfileError(
            "account-genesis evidence publication failed"
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
        raise AccountGenesisProfileError("account-genesis timestamp is invalid")
    return value


def _read_private_json(path: Path, *, maximum: int = 16_384) -> dict[str, Any]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.geteuid()
            or info.st_size <= 0
            or info.st_size > maximum
            or stat.S_IMODE(info.st_mode) != 0o600
            or not _same_file_identity(info, current)
        ):
            raise AccountGenesisProfileError(
                "mailbox handoff file is not a bounded 0600 file"
            )
        raw = b""
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if (
            info.st_size != len(raw)
            or info.st_size != after.st_size
            or info.st_nlink != after.st_nlink
            or not _same_file_identity(info, after)
            or not _same_file_identity(after, current)
        ):
            raise AccountGenesisProfileError(
                "mailbox handoff changed during read"
            )
    except AccountGenesisProfileError:
        raise
    except OSError as exc:
        raise AccountGenesisProfileError(
            "mailbox handoff is unavailable"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > maximum:
        raise AccountGenesisProfileError("mailbox handoff file is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AccountGenesisProfileError("mailbox handoff is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AccountGenesisProfileError("mailbox handoff must be an object")
    return value


def unseal_mailbox_handoff(
    path: Path,
    *,
    key: bytes | None = None,
    key_path: str = MAILBOX_HANDOFF_KEY_PATH,
) -> str:
    """Return the raw mailbox only to this process; callers must never log it."""

    envelope = _read_private_json(path)
    if set(envelope) != {
        "schema",
        "algorithm",
        "key_path",
        "nonce_b64",
        "ciphertext_b64",
    }:
        raise AccountGenesisProfileError("mailbox handoff fields are not exact")
    if (
        envelope["schema"] != MAILBOX_HANDOFF_SCHEMA
        or envelope["algorithm"] != "AES-256-GCM"
        or envelope["key_path"] != key_path
    ):
        raise AccountGenesisProfileError("mailbox handoff policy is invalid")
    try:
        nonce = base64.b64decode(envelope["nonce_b64"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise AccountGenesisProfileError("mailbox handoff encoding is invalid") from exc
    if len(nonce) != 12 or len(ciphertext) < 17:
        raise AccountGenesisProfileError("mailbox handoff ciphertext is invalid")
    if key is None:
        key = derive_storage_key(key_path)
    if not isinstance(key, bytes) or len(key) != 32:
        raise AccountGenesisProfileError("mailbox handoff key must be 32 bytes")
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, MAILBOX_HANDOFF_AAD)
        value = json.loads(plaintext)
    except Exception as exc:
        raise AccountGenesisProfileError(
            "mailbox handoff could not be decrypted"
        ) from exc
    if set(value) != {"schema", "email"} or value["schema"] != MAILBOX_HANDOFF_SCHEMA:
        raise AccountGenesisProfileError("mailbox handoff plaintext is invalid")
    email = value["email"]
    if (
        not isinstance(email, str)
        or email != email.strip()
        or len(email) > 254
        or email.count("@") != 1
        or any(ord(character) < 0x21 for character in email)
    ):
        raise AccountGenesisProfileError("mailbox handoff address is invalid")
    return email


def _parse_private_share(value: str) -> bytearray:
    normalized = value[2:] if value.startswith("0x") else value
    if not re.fullmatch(r"[0-9a-f]{64}", normalized) or normalized == "0" * 64:
        raise AccountGenesisProfileError(
            "account-binding shares must be nonzero lowercase 32-byte hex"
        )
    return bytearray.fromhex(normalized)


def consume_private_binding_shares(
    environment: dict[str, str] | os._Environ[str],
) -> tuple[bytearray, bytearray]:
    """Remove the two private shares from the live process environment."""

    first_raw = environment.pop("TINKER_ACCOUNT_BINDING_SHARE_ONE", "")
    second_raw = environment.pop("TINKER_ACCOUNT_BINDING_SHARE_TWO", "")
    first: bytearray | None = None
    second: bytearray | None = None
    try:
        first = _parse_private_share(first_raw)
        second = _parse_private_share(second_raw)
    except Exception:
        if first is not None:
            first[:] = b"\x00" * len(first)
        if second is not None:
            second[:] = b"\x00" * len(second)
        raise
    finally:
        first_raw = ""
        second_raw = ""
    assert first is not None and second is not None
    if first == second:
        for share in (first, second):
            share[:] = b"\x00" * len(share)
        raise AccountGenesisProfileError("account-binding shares must be distinct")
    return first, second


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
        "reviewer_genesis_acceptance_sha256",
        "reviewer_current_status_epoch",
        "reviewer_current_status_sha256",
    }
    if set(lineage) != expected_keys:
        raise AccountGenesisProfileError("account-genesis lineage keys are not exact")
    normalized = {key: lineage[key] for key in expected_keys}
    if not isinstance(normalized["release_sha"], str) or not _SHA40.fullmatch(
        normalized["release_sha"]
    ):
        raise AccountGenesisProfileError("account-genesis release SHA is invalid")
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
            raise AccountGenesisProfileError(f"account-genesis {key} is invalid")
    if (
        not isinstance(normalized["main_runtime_cvm_id"], str)
        or not normalized["main_runtime_cvm_id"].strip()
        or len(normalized["main_runtime_cvm_id"]) > 160
    ):
        raise AccountGenesisProfileError("account-genesis main CVM id is invalid")
    if not isinstance(normalized["main_app_id"], str) or not _APP_ID.fullmatch(
        normalized["main_app_id"]
    ):
        raise AccountGenesisProfileError("account-genesis main app id is invalid")
    for key in ("main_compose_hash", "main_os_image_hash"):
        if (
            not isinstance(normalized[key], str)
            or not _HEX64.fullmatch(normalized[key])
        ):
            raise AccountGenesisProfileError(f"account-genesis {key} is invalid")
    epoch = normalized["reviewer_current_status_epoch"]
    if not isinstance(epoch, int) or isinstance(epoch, bool) or epoch < 0:
        raise AccountGenesisProfileError("account-genesis reviewer epoch is invalid")
    normalized["main_runtime_cvm_id"] = normalized["main_runtime_cvm_id"].strip()
    return normalized


def account_genesis_lineage_from_environment(
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    source = environment if environment is not None else os.environ
    try:
        epoch = int(
            source.get(
                "TINKER_ACCOUNT_GENESIS_REVIEWER_CURRENT_STATUS_EPOCH",
                "",
            )
        )
    except ValueError as exc:
        raise AccountGenesisProfileError(
            "account-genesis reviewer epoch is invalid"
        ) from exc
    return _validate_lineage(
        {
            "release_sha": source.get("TINKER_ACCOUNT_GENESIS_RELEASE_SHA", ""),
            "deployment_intent_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_DEPLOYMENT_INTENT_SHA256", ""
            ),
            "genesis_authorization_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_AUTHORIZATION_SHA256", ""
            ),
            "main_qvl_verdict_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_MAIN_QVL_VERDICT_SHA256", ""
            ),
            "measurement_policy_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_MEASUREMENT_POLICY_SHA256", ""
            ),
            "main_runtime_cvm_id": source.get(
                "TINKER_ACCOUNT_GENESIS_MAIN_RUNTIME_CVM_ID", ""
            ),
            "main_app_id": source.get("TINKER_ACCOUNT_GENESIS_MAIN_APP_ID", ""),
            "main_compose_hash": source.get(
                "TINKER_ACCOUNT_GENESIS_MAIN_COMPOSE_HASH", ""
            ),
            "main_os_image_hash": source.get(
                "TINKER_ACCOUNT_GENESIS_MAIN_OS_IMAGE_HASH", ""
            ),
            "tinker_account_binding_ceremony_receipt_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_BINDING_CEREMONY_RECEIPT_SHA256",
                "",
            ),
            "reviewer_genesis_acceptance_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_REVIEWER_GENESIS_ACCEPTANCE_SHA256", ""
            ),
            "reviewer_current_status_epoch": epoch,
            "reviewer_current_status_sha256": source.get(
                "TINKER_ACCOUNT_GENESIS_REVIEWER_CURRENT_STATUS_SHA256", ""
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
        raise AccountGenesisProfileError(
            "running dstack identity does not match account-genesis authority"
        )
    return {key: str(value) for key, value in public.items()}


def _default_runtime_evidence(report_data: bytes) -> Mapping[str, Any]:
    details = get_attestation_details(report_data)
    return {
        "app_id": details.get("app_id"),
        "compose_hash": details.get("compose_hash"),
        "os_image_hash": details.get("os_image_hash"),
    }


async def _default_signup(settings: Settings) -> dict[str, Any]:
    from tinker_delegate.signup import signup

    return await signup(settings)


def _default_api_key_roundtrip(settings: Settings) -> bool:
    store = build_api_key_store(settings)
    value = store.load() if store.exists() else None
    confirmed = isinstance(value, str) and bool(value)
    value = None
    return confirmed


def _binding_public_policy(commitment: str) -> dict[str, Any]:
    return {
        "schema": TINKER_ACCOUNT_BINDING_SCHEMA,
        "chain_id": TINKER_ACCOUNT_BINDING_CHAIN_ID,
        "provider_namespace_label": TINKER_PROVIDER_NAMESPACE_LABEL,
        "provider_namespace": "0x" + TINKER_PROVIDER_NAMESPACE.hex(),
        "type": TINKER_ACCOUNT_BINDING_TYPE,
        "typehash": "0x" + TINKER_ACCOUNT_BINDING_TYPEHASH.hex(),
        "commitment": commitment,
        "provider_identifier_committed": False,
        "attested_provider_binding_required": True,
    }


async def run_account_genesis_profile(
    settings: Settings,
    *,
    lineage: Mapping[str, Any],
    expected_commitment: str,
    shares: tuple[bytearray, bytearray],
    evidence_directory: Path,
    handoff_path: Path,
    signup_fn: Callable[[Settings], Awaitable[dict[str, Any]]] = _default_signup,
    api_key_roundtrip_fn: Callable[[Settings], bool] = _default_api_key_roundtrip,
    runtime_evidence_fn: Callable[
        [bytes], Mapping[str, Any]
    ] = _default_runtime_evidence,
    handoff_key: bytes | None = None,
    clock: Callable[[], int] = lambda: int(time.time()),
    evidence_mode: str = "measured_runtime_pending_independent_qvl_recheck",
) -> dict[str, Any]:
    """Run at most one provider-side account attempt under the reviewed binding."""

    if (
        not isinstance(shares, tuple)
        or len(shares) != 2
        or not all(
            isinstance(share, bytearray) and len(share) == 32
            for share in shares
        )
    ):
        raise AccountGenesisProfileError(
            "account-genesis requires two mutable 32-byte shares"
        )

    # Wipe valid private-share buffers even when public lineage or commitment
    # validation fails. Recompute and compare before the claim and before any
    # provider-side operation. The private root and shares never enter an
    # artifact.
    binding_root = bytearray()
    try:
        reviewed_lineage = _validate_lineage(lineage)
        if not isinstance(expected_commitment, str) or not _BYTES32.fullmatch(
            expected_commitment
        ):
            raise AccountGenesisProfileError(
                "deployment-intent account-binding commitment is invalid"
            )
        if evidence_mode not in {
            "measured_runtime_pending_independent_qvl_recheck",
            "injected_local_test",
        }:
            raise AccountGenesisProfileError(
                "account-genesis evidence mode is invalid"
            )
        binding_root = bytearray(
            derive_tinker_account_binding_root(
                [bytes(shares[0]), bytes(shares[1])]
            )
        )
        derived_commitment = derive_tinker_account_commitment(bytes(binding_root))
    finally:
        binding_root[:] = b"\x00" * len(binding_root)
        for share in shares:
            share[:] = b"\x00" * len(share)
    if derived_commitment != expected_commitment:
        raise AccountGenesisProfileError(
            "private account-binding shares do not match deployment intent"
        )
    _ensure_private_directory(evidence_directory)
    claim_path = evidence_directory / "claim.json"
    receipt_path = evidence_directory / "receipt.json"
    retirement_path = evidence_directory / "retirement.json"
    started_at = _sample_timestamp(clock)
    _create_private_json(
        claim_path,
        {
            "schema": ACCOUNT_GENESIS_CLAIM_SCHEMA,
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
            "account_binding_commitment": expected_commitment,
            "raw_secret_egress": False,
        },
    )

    success = False
    receipt: dict[str, Any]
    try:
        report_data = (
            ACCOUNT_GENESIS_RECEIPT_SCHEMA
            + "\0"
            + reviewed_lineage["genesis_authorization_sha256"]
            + "\0"
            + expected_commitment
        ).encode("ascii")
        runtime = _validate_runtime_evidence(
            runtime_evidence_fn(report_data),
            reviewed_lineage,
        )
        mailbox = unseal_mailbox_handoff(
            handoff_path,
            key=handoff_key,
        )
        settings.email = mailbox
        # The retained signup implementation prints mailbox/API-key-derived
        # hashes. Suppress all unbounded provider output and project only the
        # exact booleans below.
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with redirect_stdout(sink), redirect_stderr(sink):
                signup_result = await signup_fn(settings)
        provider_success = (
            isinstance(signup_result, dict)
            and signup_result.get("success") is True
            and signup_result.get("stored") is True
            and signup_result.get("api_key_created") is True
        )
        with open(os.devnull, "w", encoding="utf-8") as sink:
            with redirect_stdout(sink), redirect_stderr(sink):
                roundtrip_result = (
                    api_key_roundtrip_fn(settings)
                    if provider_success
                    else False
                )
        sealed_key_roundtrip = roundtrip_result is True
        roundtrip_result = None
        if not provider_success or not sealed_key_roundtrip:
            raise AccountGenesisProfileError(
                "provider account creation and sealed API-key round-trip "
                "were not confirmed"
            )
        receipt = {
            "schema": ACCOUNT_GENESIS_RECEIPT_SCHEMA,
            "status": "account_created_bound_and_sealed",
            "success": True,
            "attempt_count": 1,
            "upstream_account_exists": True,
            "identity_check_performed": True,
            "identity_check_status": "passed",
            "identity_check_method": "signup_and_sealed_api_key_roundtrip",
            "api_key_sealed": True,
            "mailbox_handoff_consumed_inside_cvm": True,
            "binding": _binding_public_policy(expected_commitment),
            "raw_secret_egress": False,
            "live_traffic_authorized": False,
            "funding_authorized": False,
            "independent_qvl_verified_by_profile": False,
            "independent_qvl_evidence_bound": True,
            "evidence_mode": evidence_mode,
            "completed_at": _sample_timestamp(clock),
            "lineage": reviewed_lineage,
            "runtime": runtime,
        }
        success = True
    except Exception:
        receipt = {
            "schema": ACCOUNT_GENESIS_RECEIPT_SCHEMA,
            "status": "account_creation_not_confirmed",
            "success": False,
            "attempt_count": 1,
            "upstream_account_exists": None,
            "identity_check_performed": False,
            "identity_check_status": "not_established",
            "identity_check_method": "signup_and_sealed_api_key_roundtrip",
            "api_key_sealed": False,
            "mailbox_handoff_consumed_inside_cvm": None,
            "binding": _binding_public_policy(expected_commitment),
            "raw_secret_egress": False,
            "live_traffic_authorized": False,
            "funding_authorized": False,
            "independent_qvl_verified_by_profile": False,
            "independent_qvl_evidence_bound": True,
            "evidence_mode": evidence_mode,
            "completed_at": _sample_timestamp(clock),
            "lineage": reviewed_lineage,
            "runtime": None,
        }
    finally:
        settings.email = ""

    _create_private_json(receipt_path, receipt)
    _create_private_json(
        retirement_path,
        {
            "schema": ACCOUNT_GENESIS_RETIREMENT_SCHEMA,
            "status": "retired_after_single_attempt",
            "account_genesis_success": success,
            "retry_permitted": False,
            "profile_must_remain_disabled": True,
            "retired_at": _sample_timestamp(clock),
            "release_sha": reviewed_lineage["release_sha"],
            "deployment_intent_sha256": reviewed_lineage[
                "deployment_intent_sha256"
            ],
            "genesis_authorization_sha256": reviewed_lineage[
                "genesis_authorization_sha256"
            ],
            "tinker_account_binding_ceremony_receipt_sha256": (
                reviewed_lineage[
                    "tinker_account_binding_ceremony_receipt_sha256"
                ]
            ),
            "account_binding_commitment": expected_commitment,
            "reviewer_genesis_acceptance_sha256": reviewed_lineage[
                "reviewer_genesis_acceptance_sha256"
            ],
            "reviewer_current_status_epoch": reviewed_lineage[
                "reviewer_current_status_epoch"
            ],
            "reviewer_current_status_sha256": reviewed_lineage[
                "reviewer_current_status_sha256"
            ],
            "raw_secret_egress": False,
        },
    )
    return receipt


async def cli_run() -> int:
    settings = Settings()
    first, second = consume_private_binding_shares(os.environ)
    try:
        receipt = await run_account_genesis_profile(
            settings,
            lineage=account_genesis_lineage_from_environment(),
            expected_commitment=os.environ.get(
                "TINKER_ACCOUNT_BINDING_EXPECTED_COMMITMENT", ""
            ),
            shares=(first, second),
            evidence_directory=Path(
                os.environ.get(
                    "TINKER_ACCOUNT_GENESIS_EVIDENCE_DIRECTORY",
                    "/evidence/tinker-account-genesis",
                )
            ),
            handoff_path=Path(
                os.environ.get(
                    "TINKER_ACCOUNT_GENESIS_HANDOFF_PATH",
                    "/handoff/mailbox-genesis/signup-mailbox.enc",
                )
            ),
        )
    finally:
        for share in (first, second):
            share[:] = b"\x00" * len(share)
    print(
        json.dumps(
            {
                "schema": ACCOUNT_GENESIS_RECEIPT_SCHEMA,
                "status": receipt["status"],
                "success": receipt["success"],
                "account_binding_commitment": receipt["binding"]["commitment"],
                "raw_secret_egress": False,
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["success"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(cli_run()))
