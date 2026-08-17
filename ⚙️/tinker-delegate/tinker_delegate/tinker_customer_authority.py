"""Networkless initializer for the release-pinned Tinker customer authority.

The final authority projector supplies one canonical base64url document and its
exact SHA-256 through Phala's encrypted final-runtime environment.  This
one-shot process validates the complete document, proves that its settlement
public key matches the purpose-separated dstack-derived signer, and creates the
private authority file exactly once.  It never creates an upstream account,
contacts a provider, accepts a raw provider credential, or emits authority
bytes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping

from cryptography.hazmat.primitives import serialization

from tinker_delegate import dstack_utils
from tinker_delegate.tinker_customer_runtime import (
    TINKER_CUSTOMER_RUNTIME_AUTHORITY_SCHEMA,
    TINKER_CUSTOMER_SETTLEMENT_KEY_PATH,
    TinkerCustomerRuntimeError,
    _absolute_path,
    _atomic_private_write_once,
    _build_account_policy,
    _build_evidence_policy,
    _build_expected_release,
    _canonical_json,
    _exact_mapping,
    _json_object,
    _public_key,
    _settlement_signing_key,
    _sha256_bytes,
)


TINKER_CUSTOMER_AUTHORITY_B64_ENV = "TINKER_CUSTOMER_AUTHORITY_B64"
TINKER_CUSTOMER_AUTHORITY_PATH_ENV = "TINKER_CUSTOMER_AUTHORITY_PATH"
TINKER_CUSTOMER_AUTHORITY_SHA256_ENV = "TINKER_CUSTOMER_AUTHORITY_SHA256"
TINKER_CUSTOMER_ENABLED_ENV = "TINKER_CUSTOMER_ENABLED"
TINKER_CUSTOMER_SETTLEMENT_KEY_PATH_ENV = (
    "TINKER_CUSTOMER_SETTLEMENT_KEY_PATH"
)
TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY_ENV = (
    "TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY"
)

PRODUCTION_TINKER_CUSTOMER_AUTHORITY_PATH = (
    "/sealed/tinker-customer/authority.json"
)
MAX_AUTHORITY_B64_BYTES = 96 * 1024

_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_BARE_HASH = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")


def _decode_canonical_authority(value: str) -> bytes:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_AUTHORITY_B64_BYTES
        or _BASE64URL.fullmatch(value) is None
        or "=" in value
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority envelope is invalid"
        )
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        raw = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority envelope is invalid"
        ) from exc
    if (
        not raw
        or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority envelope is not canonical"
        )
    parsed = _json_object(raw, "Tinker customer runtime authority")
    if raw != _canonical_json(parsed):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority bytes are not canonical"
        )
    return raw


def _validated_authority(
    raw: bytes,
    *,
    expected_sha256: str,
    settlement_public_key: bytes,
) -> Mapping[str, Any]:
    if not hmac.compare_digest(_sha256_bytes(raw), expected_sha256):
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
    expected_release = _build_expected_release(document["expected_release"])
    account_policy = _build_account_policy(document["account_policy"])
    evidence_policy = _build_evidence_policy(
        document["runtime_evidence_policy"]
    )
    if (
        account_policy.max_operation_policy_units
        > expected_release.max_spend_policy_units
        or evidence_policy.customer_policy_digest != account_policy.digest
        or any(
            operation not in evidence_policy.enabled_operations
            for operation in account_policy.allowed_operations
        )
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority policy bindings differ"
        )
    evidence = _exact_mapping(
        document["evidence"],
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
    for key in (
        "runtime_evidence_path",
        "provisioning_directory",
        "settlement_directory",
    ):
        _absolute_path(evidence[key], key)
    public_keys = tuple(
        _public_key(evidence[key], key)
        for key in (
            "runtime_evidence_public_key",
            "provisioning_public_key",
            "settlement_public_key",
        )
    )
    if len({_sha256_bytes(key) for key in public_keys}) != 3:
        raise TinkerCustomerRuntimeError(
            "Tinker customer evidence signer keys must be distinct"
        )
    if not hmac.compare_digest(public_keys[2], settlement_public_key):
        raise TinkerCustomerRuntimeError(
            "Tinker customer settlement signer differs from authority"
        )
    resource_hash = evidence["state_anchor_resource_hash"]
    if (
        not isinstance(resource_hash, str)
        or _BARE_HASH.fullmatch(resource_hash) is None
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer state anchor resource hash is invalid"
        )
    return document


def _prepare_private_parent(path: Path) -> None:
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        details = path.parent.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.geteuid()
        ):
            raise TinkerCustomerRuntimeError(
                "Tinker customer authority directory is invalid"
            )
        os.chmod(path.parent, 0o700)
    except TinkerCustomerRuntimeError:
        raise
    except OSError as exc:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority directory is unavailable"
        ) from exc


def initialize_tinker_customer_authority(
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    enabled = str(env.get(TINKER_CUSTOMER_ENABLED_ENV, "")).strip().lower()
    encoded = str(env.get(TINKER_CUSTOMER_AUTHORITY_B64_ENV, "") or "")
    expected_sha256 = str(
        env.get(TINKER_CUSTOMER_AUTHORITY_SHA256_ENV, "") or ""
    )
    if enabled == "false":
        if encoded:
            raise TinkerCustomerRuntimeError(
                "disabled Tinker customer authority received authority bytes"
            )
        return {
            "surface": "tinker_customer_authority_initializer",
            "schema_version": 1,
            "status": "disabled_no_write",
            "authority_written": False,
            "raw_authority_egress": False,
            "raw_secret_egress": False,
        }
    if enabled != "true":
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority enable marker is invalid"
        )
    path_value = str(
        env.get(TINKER_CUSTOMER_AUTHORITY_PATH_ENV, "") or ""
    )
    if path_value != PRODUCTION_TINKER_CUSTOMER_AUTHORITY_PATH:
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority path differs from release policy"
        )
    if (
        not isinstance(expected_sha256, str)
        or not re.fullmatch(
            r"sha256:(?!0{64}$)[0-9a-f]{64}",
            expected_sha256,
        )
    ):
        raise TinkerCustomerRuntimeError(
            "Tinker customer authority SHA-256 is invalid"
        )
    if dstack_utils.is_dstack_enabled() is not True:
        raise TinkerCustomerRuntimeError(
            "real dstack is required for Tinker customer authority"
        )
    if dstack_utils.is_dstack_simulator():
        raise TinkerCustomerRuntimeError(
            "dstack simulator cannot initialize Tinker customer authority"
        )
    explicit = str(
        env.get(TINKER_CUSTOMER_SETTLEMENT_SIGNING_KEY_ENV, "") or ""
    )
    key_path = str(
        env.get(TINKER_CUSTOMER_SETTLEMENT_KEY_PATH_ENV, "") or ""
    )
    if explicit or key_path != TINKER_CUSTOMER_SETTLEMENT_KEY_PATH:
        raise TinkerCustomerRuntimeError(
            "Tinker customer settlement key policy differs"
        )
    settings = SimpleNamespace(
        tinker_customer_settlement_signing_key="",
        tinker_customer_settlement_key_path=key_path,
    )
    signing_key = _settlement_signing_key(settings)
    settlement_public_key = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    raw = _decode_canonical_authority(encoded)
    _validated_authority(
        raw,
        expected_sha256=expected_sha256,
        settlement_public_key=settlement_public_key,
    )
    path = Path(path_value)
    _prepare_private_parent(path)
    existed = path.exists()
    _atomic_private_write_once(path, raw, maximum=64 * 1024)
    return {
        "surface": "tinker_customer_authority_initializer",
        "schema_version": 1,
        "status": "exact_replay" if existed else "written",
        "authority_sha256": expected_sha256,
        "settlement_signer_public_key_sha256": (
            "sha256:" + hashlib.sha256(settlement_public_key).hexdigest()
        ),
        "authority_written": not existed,
        "raw_authority_egress": False,
        "raw_secret_egress": False,
    }


def main() -> int:
    try:
        result = initialize_tinker_customer_authority()
    except TinkerCustomerRuntimeError:
        print(
            json.dumps(
                {
                    "surface": "tinker_customer_authority_initializer",
                    "schema_version": 1,
                    "status": "failed_closed",
                    "raw_authority_egress": False,
                    "raw_secret_egress": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 78
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
