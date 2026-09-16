"""Strict, non-cyclic final release authority commitments.

This module intentionally has no integration with the current release manifest.
It preserves the frozen ``dnai.final-release-authority-core.v3`` primitive and
an explicit historical v2 replay path for cross-language evidence replay. The
current v4 authority is owned by the canonical JavaScript implementation;
callers must not treat these compatibility aliases as current release authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from eth_hash.auto import keccak

FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA = "dnai.final-release-authority-core.v2"
FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN = (
    b"dnai-wikigen/final-release-authority-core/v2\0"
)
FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA = "dnai.final-release-authority-core.v3"
FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN = (
    b"dnai-wikigen/final-release-authority-core/v3\0"
)
FINAL_RELEASE_AUTHORITY_CORE_SCHEMA = FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA
FINAL_RELEASE_AUTHORITY_CORE_DOMAIN = FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN
MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES = 65_536
DILIGENCE_EVALUATOR_POLICY_SET_TYPE = (
    "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)"
)

# Compatibility aliases for existing ceremony imports. These names now point
# at the final authority primitive and do not retain packet/review semantics.
EXECUTION_POLICY_RELEASE_CORE_SCHEMA = FINAL_RELEASE_AUTHORITY_CORE_SCHEMA
EXECUTION_POLICY_RELEASE_CORE_DOMAIN = FINAL_RELEASE_AUTHORITY_CORE_DOMAIN
MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES = MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES

_BASE_SEPOLIA_CHAIN_ID = 84_532
_BASE_SEPOLIA_PUBLIC_RPC = "https://sepolia.base.org"
_BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
_APPROVER_ROOT_DOMAIN = b"dnai-wikigen/execution-policy-approver-root/v1\0"
_CANONICALIZATION_VERSION = "policy-kernel-canonicalization/v2"
_APPROVAL_SCHEMA = "dnai-wikigen/execution-policy-approval/v3"
_API_SCHEMA_VERSION = 3
_STORE_SCHEMA_VERSION = 5
_ROLLBACK_ANCHOR_SCHEMA = "dnai.execution-policy-rollback-anchor.v1"
_ANCHOR_VERIFICATION_MODEL = (
    "single_rpc_reported_finalized_with_confirmation_depth"
)
_ANCHOR_WRITER_CUSTODY = "dstack_derived_execution_policy_anchor_writer"
_ANCHOR_WRITER_KEY_PATH = "tinker/execution_policy_anchor_writer"
_CHALLENGE_VERSION_REVIEW_DELAY_SECONDS = 172_800
_MAX_GENESIS_CHALLENGES = 32
_GITHUB_REPOSITORY = "therealwiki/dnai-wikigen"
_GITHUB_SIGNER_WORKFLOW = (
    "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
)
_ZERO_ADDRESS = "0x" + "0" * 40
_ZERO_WORD = "0" * 64
_MAX_SAFE_INTEGER = 2**53 - 1
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_RELEASE_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ADDRESS = re.compile(r"0x[0-9a-f]{40}\Z")
_BARE_BYTES32 = re.compile(r"[0-9a-f]{64}\Z")
_BYTES32 = re.compile(r"0x[0-9a-f]{64}\Z")
_SHA256_PIN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HISTORICAL_DNS_OR_IPV4_HOSTNAME_V2 = re.compile(
    r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z"
)
_PUBLIC_DNS_LABEL_V3 = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
_PRIVATE_DNS_SUFFIXES_V3 = (
    "localhost",
    "local",
    "localdomain",
    "internal",
    "lan",
    "home.arpa",
    "onion",
    "test",
    "invalid",
    "example",
    "alt",
)
_ARENA_CATALOG_KEY = re.compile(
    r"[a-z0-9][a-z0-9-]{0,63}@"
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\Z"
)
_PRINTABLE_ASCII = re.compile(r"[\x20-\x7e]+\Z")

_TOP_LEVEL_KEYS = (
    "schema",
    "release_sha",
    "network",
    "operator_address",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "contracts",
    "cvm",
    "arena_registry_bindings",
    "wallet_auth",
    "requested_features",
    "execution_policy",
)

_CONTRACT_KEYS = (
    "diligence_room",
    "challenge_registry",
    "royalty_distributor",
    "tinker_account_encumbrance",
    "compute_credit_vault",
    "email_oracle_auth",
    "usdc",
)

_CVM_KEYS = (
    "app_id",
    "cvm_id",
    "compose_hash",
    "local_compose_hash",
    "rendered_compose_sha256",
    "os_image_hash",
    "os_is_dev",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "tee_identity",
    "delegate_url",
    "images",
    "allowed_browser_origins",
    "compute_workload_ingress",
    "runtime_controls",
)

_IMAGE_KEYS = (
    "service",
    "image",
    "source_digest",
    "source_ref",
    "repo",
    "signer_workflow",
    "provenance_attestation",
    "sbom_attestation",
)

_IMAGE_REPOSITORIES = {
    "delegate": "ghcr.io/therealwiki/dnai-wikigen/tinker-delegate",
    "neko": "ghcr.io/therealwiki/dnai-wikigen/neko-chrome",
    "oracle": "ghcr.io/therealwiki/dnai-wikigen/tee-email-oracle",
}

_REQUIRED_BROWSER_ORIGINS = (
    "https://wikigen.me",
    "https://wikigenme.pages.dev",
    "https://www.wikigen.me",
)

_RUNTIME_CONTROL_EXPECTATIONS = {
    "wallet_auth_required": True,
    "runtime_bearer_required": True,
    "durable_compute_store": True,
    "durable_arena_store": True,
    "durable_arena_ingress_store": True,
    "artifact_ciphertext_only": True,
    "plaintext_artifact_endpoint_disabled": True,
    "plaintext_card_endpoint_disabled": True,
    "bootstrap_fail_open_disabled": True,
    "browser_ports_internal_only": True,
    "nondefault_browser_credentials_required": True,
    "project_owned_browser_images": True,
    "oracle_internal_only": True,
    "oracle_runtime_auth_required": True,
    "oracle_health_liveness_only": True,
    "oracle_pin_response_minimized": True,
    "oracle_private_metadata_egress_prohibited": True,
    "oracle_replay_fail_closed": True,
    "provider_dispatch_enabled": False,
    "hostile_candidate_execution_enabled": False,
    "deal_settlement_enabled": False,
    "remote_artifact_evaluator_enabled": False,
    "raw_secret_egress_prohibited": True,
}

_HISTORICAL_REQUESTED_FEATURE_KEYS_V2 = (
    "contract_writes",
    "artifact_upload",
    "compute_console",
    "compute_vault_funding",
    "compute_vault_authorization",
    "compute_workload_upload",
    "arena_submission",
)

_REQUESTED_FEATURE_KEYS_V3 = (
    "contract_writes",
    "artifact_upload",
    "compute_console",
    "tinker_customer",
    "collaboration",
    "compute_vault_funding",
    "compute_vault_authorization",
    "compute_workload_upload",
    "arena_submission",
)

_EXECUTION_POLICY_KEYS = (
    "canonicalization_version",
    "approval_schema",
    "api_schema_version",
    "store_schema_version",
    "approver_hashes",
    "approver_root_hash",
    "rollback_anchor_target",
)

_ROLLBACK_ANCHOR_TARGET_KEYS = (
    "schema",
    "chain_id",
    "contract_address",
    "runtime_code_hash",
    "writer_address",
    "writer_custody",
    "writer_key_path",
    "writer_release_commitment",
    "confirmations",
    "max_block_age_seconds",
    "max_future_block_skew_seconds",
    "verification_model",
    "independent_rpc_quorum_verified",
    "consensus_proof_verified",
)

_ARENA_REGISTRY_BINDING_KEYS = (
    "registry_challenge_id",
    "registry_version",
    "controller_address",
    "pending_controller_address",
    "lifecycle",
    "paused",
    "configuration_frozen",
    "catalog_manifest_hash",
    "metadata_uri",
    "metadata_hash",
    "sealed_artifact_commitment",
    "evaluator_commitment",
    "release_policy_commitment",
)


class FinalReleaseAuthorityCoreValidationError(ValueError):
    """Raised when a final-authority artifact is noncanonical or unsafe."""


ExecutionPolicyReleaseCoreValidationError = FinalReleaseAuthorityCoreValidationError


def _fail(message: str) -> None:
    raise FinalReleaseAuthorityCoreValidationError(message)


def _assert_string(value: Any, label: str, maximum_bytes: int) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{label} must be a bounded non-control-character string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(f"{label} must not contain an unpaired Unicode surrogate")
    if len(encoded) > maximum_bytes or _CONTROL_CHARACTERS.search(value):
        _fail(f"{label} must be a bounded non-control-character string")
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        _fail(f"{label} must not contain an unpaired Unicode surrogate")
    return value


def _printable_ascii(value: Any, label: str, maximum_bytes: int) -> str:
    observed = _assert_string(value, label, maximum_bytes)
    if _PRINTABLE_ASCII.fullmatch(observed) is None:
        _fail(f"{label} must contain only printable ASCII")
    return observed


def _validate_json_tree(
    value: Any,
    label: str = "release core",
    depth: int = 0,
    ancestors: set[int] | None = None,
) -> None:
    if depth > 16:
        _fail(f"{label} exceeds the maximum nesting depth")
    if ancestors is None:
        ancestors = set()
    if isinstance(value, str):
        if value == "" and label == "release core.wallet_auth.walletconnect_project_id":
            return
        _assert_string(value, label, 4_096)
        return
    if type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > _MAX_SAFE_INTEGER:
            _fail(f"{label} must not contain unsafe integers")
        return
    if isinstance(value, float):
        _fail(f"{label} must not contain floating-point numbers")
    if value is None:
        _fail(f"{label} must not contain null")
    if type(value) is list:
        marker = id(value)
        if marker in ancestors:
            _fail(f"{label} must not contain cycles")
        if len(value) > 256:
            _fail(f"{label} array is too large")
        ancestors.add(marker)
        for index, entry in enumerate(value):
            _validate_json_tree(entry, f"{label}[{index}]", depth + 1, ancestors)
        ancestors.remove(marker)
        return
    if type(value) is dict:
        marker = id(value)
        if marker in ancestors:
            _fail(f"{label} must not contain cycles")
        if len(value) > 128 or any(type(key) is not str for key in value):
            _fail(f"{label} must be a bounded string-keyed JSON object")
        ancestors.add(marker)
        for key, entry in value.items():
            _assert_string(key, f"{label} key", 128)
            _validate_json_tree(entry, f"{label}.{key}", depth + 1, ancestors)
        ancestors.remove(marker)
        return
    _fail(f"{label} must contain only JSON values")


def _exact_record(value: Any, keys: tuple[str, ...], label: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        missing = ",".join(sorted(expected - actual)) or "none"
        extra = ",".join(sorted(actual - expected)) or "none"
        _fail(f"{label} has invalid keys (missing: {missing}; extra: {extra})")
    return value


def _exact_string(value: Any, expected: str, label: str) -> str:
    observed = _assert_string(value, label, max(128, len(expected.encode("utf-8"))))
    if observed != expected:
        _fail(f"{label} must equal {expected}")
    return observed


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        _fail(f"{label} must be an integer from {minimum} through {maximum}")
    return value


def _uint256_decimal(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        _fail(f"{label} must be a canonical uint256 decimal string")
    parsed = int(value)
    if parsed < 0 or parsed >= 2**256:
        _fail(f"{label} must fit uint256")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be boolean")
    return value


def _release_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or _RELEASE_SHA.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase 40-character Git SHA")
    return value


def _address(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _ADDRESS.fullmatch(value) is None
        or value == _ZERO_ADDRESS
    ):
        _fail(f"{label} must be a nonzero lowercase Ethereum address")
    return value


def _zero_address(value: Any, label: str) -> str:
    if value != _ZERO_ADDRESS:
        _fail(f"{label} must be the canonical zero Ethereum address")
    return value


def _bare_bytes32(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _BARE_BYTES32.fullmatch(value) is None
        or value == _ZERO_WORD
    ):
        _fail(f"{label} must be nonzero lowercase 32-byte hex without 0x")
    return value


def _bytes32(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _BYTES32.fullmatch(value) is None
        or value == "0x" + _ZERO_WORD
    ):
        _fail(f"{label} must be a nonzero lowercase 0x-prefixed bytes32")
    return value


def diligence_evaluator_policy_set_root(commitments: Any) -> str:
    if type(commitments) is not list or len(commitments) != 3:
        _fail(
            "DiligenceRoom evaluator policy commitments must contain exactly three entries"
        )
    policies = sorted(
        _bytes32(
            value,
            f"DiligenceRoom evaluator policy commitment[{index}]",
        )
        for index, value in enumerate(commitments)
    )
    if len(set(policies)) != 3:
        _fail("DiligenceRoom evaluator policy commitments must be pairwise distinct")
    typehash = keccak(DILIGENCE_EVALUATOR_POLICY_SET_TYPE.encode("utf-8"))
    encoded = typehash + b"".join(bytes.fromhex(value[2:]) for value in policies)
    return "0x" + keccak(encoded).hex()


def _sha256_pin(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or _SHA256_PIN.fullmatch(value) is None
        or value == "sha256:" + _ZERO_WORD
    ):
        _fail(f"{label} must be a nonzero lowercase sha256 pin")
    return value


def _walletconnect_project_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"(?:|[0-9a-f]{32})", value) is None:
        _fail(f"{label} must be empty or exactly 32 lowercase hexadecimal characters")
    return value


def _historical_https_origin_v2(value: Any, label: str) -> str:
    origin = _assert_string(value, label, 512)
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError:
        _fail(f"{label} must be a canonical HTTPS origin")
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or parsed.hostname != parsed.hostname.lower()
        or _HISTORICAL_DNS_OR_IPV4_HOSTNAME_V2.fullmatch(parsed.hostname) is None
        or port == 443
    ):
        _fail(f"{label} must be a canonical lowercase HTTPS origin without a path")
    expected_netloc = parsed.hostname
    if port is not None:
        expected_netloc += f":{port}"
    if parsed.netloc != expected_netloc or origin != f"https://{expected_netloc}":
        _fail(f"{label} must be a canonical lowercase HTTPS origin without a path")
    return origin


def _current_public_https_origin_v3(value: Any, label: str) -> str:
    origin = _assert_string(value, label, 512)
    if (
        origin != origin.strip()
        or re.fullmatch(r"[\x21-\x7e]+", origin) is None
        or any(character in origin for character in ("\\", "@", "?", "#", "*"))
    ):
        _fail(f"{label} must be a canonical HTTPS origin")
    match = re.fullmatch(r"https://([^/:]+)(?::([0-9]+))?", origin)
    if match is None:
        _fail(f"{label} must be a canonical HTTPS origin")
    hostname, raw_port = match.groups()
    labels = hostname.split(".")
    if (
        len(hostname) > 253
        or hostname.endswith(".")
        or re.fullmatch(r"\d+(?:\.\d+){3}", hostname) is not None
        or len(labels) < 2
        or any(_PUBLIC_DNS_LABEL_V3.fullmatch(entry) is None for entry in labels)
        or any(
            hostname == suffix or hostname.endswith("." + suffix)
            for suffix in _PRIVATE_DNS_SUFFIXES_V3
        )
        or raw_port is not None
    ):
        _fail(f"{label} must be a canonical HTTPS origin")
    return origin


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")


def _approver_root_hash(approver_hashes: list[str]) -> str:
    digest = hashlib.sha256()
    digest.update(_APPROVER_ROOT_DOMAIN)
    digest.update(_canonical_json(approver_hashes))
    return digest.hexdigest()


def _normalize_base_contract(
    value: Any,
    key: str,
    extra_keys: tuple[str, ...] = (),
) -> dict[str, Any]:
    parsed = _exact_record(
        value,
        ("address", "runtime_code_hash", *extra_keys),
        f"contracts.{key}",
    )
    return {
        "address": _address(parsed["address"], f"contracts.{key}.address"),
        "runtime_code_hash": _bytes32(
            parsed["runtime_code_hash"], f"contracts.{key}.runtime_code_hash"
        ),
    }


def _normalize_email_oracle_release(value: Any) -> dict[str, Any]:
    parsed = _exact_record(
        value,
        (
            "device_id",
            "kms_contract_address",
            "kms_runtime_code_hash",
            "kms_implementation_address",
            "kms_implementation_runtime_code_hash",
            "kms_registration_tx_hash",
            "kms_registration_block",
            "kms_registration_block_hash",
            "target_boot",
            "oracle_compose_hash",
            "consumer_compose_hash",
            "restart_key_derivation_proof_hash",
            "external_evidence_sha256",
        ),
        "contracts.email_oracle_auth.release",
    )
    boot = _exact_record(
        parsed["target_boot"],
        (
            "instance_id",
            "mr_aggregated",
            "mr_system",
            "os_image_hash",
            "tcb_status",
            "advisory_ids",
            "info_hash",
        ),
        "contracts.email_oracle_auth.release.target_boot",
    )
    if type(boot["advisory_ids"]) is not list or boot["advisory_ids"]:
        _fail("EmailOracleAuth target boot advisory_ids must be the exact empty array")
    return {
        "device_id": _bytes32(
            parsed["device_id"], "contracts.email_oracle_auth.release.device_id"
        ),
        "kms_contract_address": _address(
            parsed["kms_contract_address"],
            "contracts.email_oracle_auth.release.kms_contract_address",
        ),
        "kms_runtime_code_hash": _bytes32(
            parsed["kms_runtime_code_hash"],
            "contracts.email_oracle_auth.release.kms_runtime_code_hash",
        ),
        "kms_implementation_address": _address(
            parsed["kms_implementation_address"],
            "contracts.email_oracle_auth.release.kms_implementation_address",
        ),
        "kms_implementation_runtime_code_hash": _bytes32(
            parsed["kms_implementation_runtime_code_hash"],
            "contracts.email_oracle_auth.release.kms_implementation_runtime_code_hash",
        ),
        "kms_registration_tx_hash": _bytes32(
            parsed["kms_registration_tx_hash"],
            "contracts.email_oracle_auth.release.kms_registration_tx_hash",
        ),
        "kms_registration_block": _integer(
            parsed["kms_registration_block"],
            "contracts.email_oracle_auth.release.kms_registration_block",
            1,
            _MAX_SAFE_INTEGER,
        ),
        "kms_registration_block_hash": _bytes32(
            parsed["kms_registration_block_hash"],
            "contracts.email_oracle_auth.release.kms_registration_block_hash",
        ),
        "target_boot": {
            "instance_id": _address(
                boot["instance_id"],
                "contracts.email_oracle_auth.release.target_boot.instance_id",
            ),
            "mr_aggregated": _bytes32(
                boot["mr_aggregated"],
                "contracts.email_oracle_auth.release.target_boot.mr_aggregated",
            ),
            "mr_system": _bytes32(
                boot["mr_system"],
                "contracts.email_oracle_auth.release.target_boot.mr_system",
            ),
            "os_image_hash": _bytes32(
                boot["os_image_hash"],
                "contracts.email_oracle_auth.release.target_boot.os_image_hash",
            ),
            "tcb_status": _exact_string(
                boot["tcb_status"],
                "UpToDate",
                "contracts.email_oracle_auth.release.target_boot.tcb_status",
            ),
            "advisory_ids": [],
            "info_hash": _bytes32(
                boot["info_hash"],
                "contracts.email_oracle_auth.release.target_boot.info_hash",
            ),
        },
        "oracle_compose_hash": _bytes32(
            parsed["oracle_compose_hash"],
            "contracts.email_oracle_auth.release.oracle_compose_hash",
        ),
        "consumer_compose_hash": _bytes32(
            parsed["consumer_compose_hash"],
            "contracts.email_oracle_auth.release.consumer_compose_hash",
        ),
        "restart_key_derivation_proof_hash": _bytes32(
            parsed["restart_key_derivation_proof_hash"],
            "contracts.email_oracle_auth.release.restart_key_derivation_proof_hash",
        ),
        "external_evidence_sha256": _bytes32(
            parsed["external_evidence_sha256"],
            "contracts.email_oracle_auth.release.external_evidence_sha256",
        ),
    }


def _normalize_diligence_release_admission(value: Any) -> dict[str, Any]:
    parsed = _exact_record(
        value,
        (
            "tee_identity",
            "compose_hash",
            "approved_tee_identity_count",
            "approved_compose_count",
            "additions_frozen",
        ),
        "contracts.diligence_room.release_admission",
    )
    normalized = {
        "tee_identity": _address(
            parsed["tee_identity"],
            "contracts.diligence_room.release_admission.tee_identity",
        ),
        "compose_hash": _bare_bytes32(
            parsed["compose_hash"],
            "contracts.diligence_room.release_admission.compose_hash",
        ),
        "approved_tee_identity_count": _integer(
            parsed["approved_tee_identity_count"],
            "contracts.diligence_room.release_admission.approved_tee_identity_count",
            1,
            1,
        ),
        "approved_compose_count": _integer(
            parsed["approved_compose_count"],
            "contracts.diligence_room.release_admission.approved_compose_count",
            1,
            1,
        ),
        "additions_frozen": _boolean(
            parsed["additions_frozen"],
            "contracts.diligence_room.release_admission.additions_frozen",
        ),
    }
    if not normalized["additions_frozen"]:
        _fail("DiligenceRoom release admission additions must be frozen")
    return normalized


def _normalize_compute_rate_policy(
    value: Any,
    policy: str,
) -> dict[str, Any]:
    label = f"contracts.compute_credit_vault.rate_policies.{policy}"
    parsed = _exact_record(
        value,
        ("commitment", "asset", "provider", "developer_fee_bps"),
        label,
    )
    asset = (
        _zero_address(parsed["asset"], f"{label}.asset")
        if policy == "native"
        else _address(parsed["asset"], f"{label}.asset")
    )
    return {
        "commitment": _bytes32(parsed["commitment"], f"{label}.commitment"),
        "asset": asset,
        "provider": _address(parsed["provider"], f"{label}.provider"),
        "developer_fee_bps": _integer(
            parsed["developer_fee_bps"], f"{label}.developer_fee_bps", 0, 2_000
        ),
    }


def _normalize_contracts(value: Any) -> dict[str, Any]:
    parsed = _exact_record(value, _CONTRACT_KEYS, "contracts")

    diligence_policy_values = parsed["diligence_room"].get(
        "evaluator_policy_commitments"
    )
    if type(diligence_policy_values) is not list or len(diligence_policy_values) != 3:
        _fail(
            "DiligenceRoom evaluator policy commitments must contain exactly three entries"
        )
    diligence_policies = sorted(
        _bytes32(
            entry,
            f"contracts.diligence_room.evaluator_policy_commitments[{index}]",
        )
        for index, entry in enumerate(diligence_policy_values)
    )
    if len(set(diligence_policies)) != 3:
        _fail("DiligenceRoom evaluator policy commitments must be pairwise distinct")
    diligence_policy_root = diligence_evaluator_policy_set_root(diligence_policies)
    if (
        _bytes32(
            parsed["diligence_room"].get("evaluator_policy_set_root"),
            "contracts.diligence_room.evaluator_policy_set_root",
        )
        != diligence_policy_root
    ):
        _fail(
            "DiligenceRoom evaluator policy set root is not derived from the exact sorted policy set"
        )

    diligence = {
        **_normalize_base_contract(
            parsed["diligence_room"],
            "diligence_room",
            (
                "developer",
                "result_verifier",
                "attestation_verifier",
                "attestation_release_policy_hash",
                "attestation_binding_frozen",
                "evaluator_policy_commitments",
                "evaluator_policy_set_root",
                "release_admission",
            ),
        ),
        "developer": _address(
            parsed["diligence_room"]["developer"],
            "contracts.diligence_room.developer",
        ),
        "result_verifier": _address(
            parsed["diligence_room"]["result_verifier"],
            "contracts.diligence_room.result_verifier",
        ),
        "attestation_verifier": _address(
            parsed["diligence_room"]["attestation_verifier"],
            "contracts.diligence_room.attestation_verifier",
        ),
        "attestation_release_policy_hash": _bytes32(
            parsed["diligence_room"]["attestation_release_policy_hash"],
            "contracts.diligence_room.attestation_release_policy_hash",
        ),
        "attestation_binding_frozen": _boolean(
            parsed["diligence_room"]["attestation_binding_frozen"],
            "contracts.diligence_room.attestation_binding_frozen",
        ),
        "evaluator_policy_commitments": diligence_policies,
        "evaluator_policy_set_root": diligence_policy_root,
        "release_admission": _normalize_diligence_release_admission(
            parsed["diligence_room"]["release_admission"]
        ),
    }
    if not diligence["attestation_binding_frozen"]:
        _fail("DiligenceRoom attestation binding must be frozen")

    challenge = {
        **_normalize_base_contract(
            parsed["challenge_registry"],
            "challenge_registry",
            (
                "owner",
                "pending_owner",
                "registry_paused",
                "minimum_version_review_delay_seconds",
                "expected_challenge_count",
            ),
        ),
        "owner": _address(
            parsed["challenge_registry"]["owner"],
            "contracts.challenge_registry.owner",
        ),
        "pending_owner": _zero_address(
            parsed["challenge_registry"]["pending_owner"],
            "contracts.challenge_registry.pending_owner",
        ),
        "registry_paused": _boolean(
            parsed["challenge_registry"]["registry_paused"],
            "contracts.challenge_registry.registry_paused",
        ),
        "minimum_version_review_delay_seconds": _integer(
            parsed["challenge_registry"]["minimum_version_review_delay_seconds"],
            "contracts.challenge_registry.minimum_version_review_delay_seconds",
            _CHALLENGE_VERSION_REVIEW_DELAY_SECONDS,
            _CHALLENGE_VERSION_REVIEW_DELAY_SECONDS,
        ),
        "expected_challenge_count": _integer(
            parsed["challenge_registry"]["expected_challenge_count"],
            "contracts.challenge_registry.expected_challenge_count",
            1,
            _MAX_GENESIS_CHALLENGES,
        ),
    }
    if challenge["registry_paused"]:
        _fail("ChallengeRegistry must be active for the reviewed genesis catalog")

    royalty = _normalize_base_contract(
        parsed["royalty_distributor"], "royalty_distributor"
    )

    encumbrance_raw = parsed["tinker_account_encumbrance"]
    encumbrance_keys = (
        "owner",
        "account_commitment",
        "max_add_balance_wei",
        "max_spend_wei",
        "approved_compose_hashes",
        "approved_compose_root",
        "approved_compose_count",
        "managers",
        "manager_root",
        "manager_count",
        "release_policy_commitment",
        "release_max_add_balance_wei",
        "release_max_spend_wei",
        "release_compose_root",
        "release_compose_count",
        "release_manager_root",
        "release_manager_count",
        "release_policy_frozen",
        "emergency_halted",
        "per_operation_caps",
        "custodies_funds",
    )
    approved_compose_values = encumbrance_raw.get("approved_compose_hashes")
    if not isinstance(approved_compose_values, list) or len(approved_compose_values) != 1:
        _fail(
            "contracts.tinker_account_encumbrance.approved_compose_hashes must contain exactly one release compose hash"
        )
    approved_compose_hashes = [
        _bytes32(
            entry,
            f"contracts.tinker_account_encumbrance.approved_compose_hashes[{index}]",
        )
        for index, entry in enumerate(approved_compose_values)
    ]
    manager_values = encumbrance_raw.get("managers")
    if not isinstance(manager_values, list) or len(manager_values) != 1:
        _fail(
            "contracts.tinker_account_encumbrance.managers must contain exactly one release manager"
        )
    managers = [
        _address(
            entry,
            f"contracts.tinker_account_encumbrance.managers[{index}]",
        )
        for index, entry in enumerate(manager_values)
    ]
    encumbrance = {
        **_normalize_base_contract(
            encumbrance_raw,
            "tinker_account_encumbrance",
            encumbrance_keys,
        ),
        "owner": _address(
            encumbrance_raw["owner"],
            "contracts.tinker_account_encumbrance.owner",
        ),
        "account_commitment": _bytes32(
            encumbrance_raw["account_commitment"],
            "contracts.tinker_account_encumbrance.account_commitment",
        ),
        "max_add_balance_wei": _uint256_decimal(
            encumbrance_raw["max_add_balance_wei"],
            "contracts.tinker_account_encumbrance.max_add_balance_wei",
        ),
        "max_spend_wei": _uint256_decimal(
            encumbrance_raw["max_spend_wei"],
            "contracts.tinker_account_encumbrance.max_spend_wei",
        ),
        "approved_compose_hashes": approved_compose_hashes,
        "approved_compose_root": _bytes32(
            encumbrance_raw["approved_compose_root"],
            "contracts.tinker_account_encumbrance.approved_compose_root",
        ),
        "approved_compose_count": _integer(
            encumbrance_raw["approved_compose_count"],
            "contracts.tinker_account_encumbrance.approved_compose_count",
            1,
            16,
        ),
        "managers": managers,
        "manager_root": _bytes32(
            encumbrance_raw["manager_root"],
            "contracts.tinker_account_encumbrance.manager_root",
        ),
        "manager_count": _integer(
            encumbrance_raw["manager_count"],
            "contracts.tinker_account_encumbrance.manager_count",
            1,
            16,
        ),
        "release_policy_commitment": _bytes32(
            encumbrance_raw["release_policy_commitment"],
            "contracts.tinker_account_encumbrance.release_policy_commitment",
        ),
        "release_max_add_balance_wei": _uint256_decimal(
            encumbrance_raw["release_max_add_balance_wei"],
            "contracts.tinker_account_encumbrance.release_max_add_balance_wei",
        ),
        "release_max_spend_wei": _uint256_decimal(
            encumbrance_raw["release_max_spend_wei"],
            "contracts.tinker_account_encumbrance.release_max_spend_wei",
        ),
        "release_compose_root": _bytes32(
            encumbrance_raw["release_compose_root"],
            "contracts.tinker_account_encumbrance.release_compose_root",
        ),
        "release_compose_count": _integer(
            encumbrance_raw["release_compose_count"],
            "contracts.tinker_account_encumbrance.release_compose_count",
            1,
            16,
        ),
        "release_manager_root": _bytes32(
            encumbrance_raw["release_manager_root"],
            "contracts.tinker_account_encumbrance.release_manager_root",
        ),
        "release_manager_count": _integer(
            encumbrance_raw["release_manager_count"],
            "contracts.tinker_account_encumbrance.release_manager_count",
            1,
            16,
        ),
        "release_policy_frozen": _boolean(
            encumbrance_raw["release_policy_frozen"],
            "contracts.tinker_account_encumbrance.release_policy_frozen",
        ),
        "emergency_halted": _boolean(
            encumbrance_raw["emergency_halted"],
            "contracts.tinker_account_encumbrance.emergency_halted",
        ),
        "per_operation_caps": _boolean(
            encumbrance_raw["per_operation_caps"],
            "contracts.tinker_account_encumbrance.per_operation_caps",
        ),
        "custodies_funds": _boolean(
            encumbrance_raw["custodies_funds"],
            "contracts.tinker_account_encumbrance.custodies_funds",
        ),
    }
    if (
        encumbrance["approved_compose_count"] != len(approved_compose_hashes)
        or encumbrance["release_compose_count"] != len(approved_compose_hashes)
        or encumbrance["manager_count"] != len(managers)
        or encumbrance["release_manager_count"] != len(managers)
        or encumbrance["approved_compose_root"] != encumbrance["release_compose_root"]
        or encumbrance["manager_root"] != encumbrance["release_manager_root"]
        or encumbrance["max_add_balance_wei"]
        != encumbrance["release_max_add_balance_wei"]
        or encumbrance["max_spend_wei"] != encumbrance["release_max_spend_wei"]
        or encumbrance["release_policy_frozen"] is not True
        or encumbrance["emergency_halted"] is not False
        or encumbrance["per_operation_caps"] is not True
        or encumbrance["custodies_funds"] is not False
    ):
        _fail(
            "TinkerAccountEncumbrance must bind one exact active, frozen, noncustodial release policy"
        )

    vault_raw = parsed["compute_credit_vault"]
    vault = {
        **_normalize_base_contract(
            vault_raw,
            "compute_credit_vault",
            (
                "owner",
                "developer",
                "metering_verifier",
                "metering_qvl_verifier",
                "metering_policy_set_hash",
                "metering_binding_frozen",
                "developer_fee_bps",
                "tee_identity",
                "compose_hash",
                "rate_policies",
            ),
        ),
        "owner": _address(vault_raw["owner"], "contracts.compute_credit_vault.owner"),
        "developer": _address(
            vault_raw["developer"], "contracts.compute_credit_vault.developer"
        ),
        "metering_verifier": _address(
            vault_raw["metering_verifier"],
            "contracts.compute_credit_vault.metering_verifier",
        ),
        "metering_qvl_verifier": _address(
            vault_raw["metering_qvl_verifier"],
            "contracts.compute_credit_vault.metering_qvl_verifier",
        ),
        "metering_policy_set_hash": _bytes32(
            vault_raw["metering_policy_set_hash"],
            "contracts.compute_credit_vault.metering_policy_set_hash",
        ),
        "metering_binding_frozen": _boolean(
            vault_raw["metering_binding_frozen"],
            "contracts.compute_credit_vault.metering_binding_frozen",
        ),
        "developer_fee_bps": _integer(
            vault_raw["developer_fee_bps"],
            "contracts.compute_credit_vault.developer_fee_bps",
            0,
            2_000,
        ),
        "tee_identity": _address(
            vault_raw["tee_identity"], "contracts.compute_credit_vault.tee_identity"
        ),
        "compose_hash": _bare_bytes32(
            vault_raw["compose_hash"], "contracts.compute_credit_vault.compose_hash"
        ),
        "rate_policies": {
            "native": _normalize_compute_rate_policy(
                _exact_record(
                    vault_raw["rate_policies"],
                    ("native", "erc20"),
                    "contracts.compute_credit_vault.rate_policies",
                )["native"],
                "native",
            ),
            "erc20": _normalize_compute_rate_policy(
                vault_raw["rate_policies"]["erc20"], "erc20"
            ),
        },
    }

    email = {
        **_normalize_base_contract(
            parsed["email_oracle_auth"],
            "email_oracle_auth",
            ("owner", "consumer_address", "upgrade_delay_seconds", "release"),
        ),
        "owner": _address(
            parsed["email_oracle_auth"]["owner"],
            "contracts.email_oracle_auth.owner",
        ),
        "consumer_address": _address(
            parsed["email_oracle_auth"]["consumer_address"],
            "contracts.email_oracle_auth.consumer_address",
        ),
        "upgrade_delay_seconds": _integer(
            parsed["email_oracle_auth"]["upgrade_delay_seconds"],
            "contracts.email_oracle_auth.upgrade_delay_seconds",
            172_800,
            31_536_000,
        ),
        "release": _normalize_email_oracle_release(
            parsed["email_oracle_auth"]["release"]
        ),
    }

    usdc = {
        **_normalize_base_contract(parsed["usdc"], "usdc", ("symbol", "decimals")),
        "symbol": _exact_string(parsed["usdc"]["symbol"], "USDC", "contracts.usdc.symbol"),
        "decimals": _integer(parsed["usdc"]["decimals"], "contracts.usdc.decimals", 6, 6),
    }
    if usdc["address"] != _BASE_SEPOLIA_USDC:
        _fail("contracts.usdc.address must be canonical Base Sepolia USDC")
    if vault["rate_policies"]["erc20"]["asset"] != usdc["address"]:
        _fail("ComputeCreditVault ERC20 asset must equal contracts.usdc.address")
    if (
        vault["rate_policies"]["native"]["commitment"]
        == vault["rate_policies"]["erc20"]["commitment"]
    ):
        _fail("ComputeCreditVault native and ERC20 policy commitments must differ")
    if any(
        policy["developer_fee_bps"] != vault["developer_fee_bps"]
        for policy in vault["rate_policies"].values()
    ):
        _fail(
            "ComputeCreditVault rate-policy developer fees must equal developer_fee_bps"
        )
    if (
        vault["rate_policies"]["native"]["provider"]
        == vault["rate_policies"]["erc20"]["provider"]
    ):
        _fail("ComputeCreditVault native and ERC20 providers must differ")
    if not vault["metering_binding_frozen"]:
        _fail("ComputeCreditVault metering binding must be frozen")

    normalized = {
        "diligence_room": diligence,
        "challenge_registry": challenge,
        "royalty_distributor": royalty,
        "tinker_account_encumbrance": encumbrance,
        "compute_credit_vault": vault,
        "email_oracle_auth": email,
        "usdc": usdc,
    }
    addresses = [entry["address"] for entry in normalized.values()]
    if len(set(addresses)) != len(addresses):
        _fail("contract addresses must be unique")
    return normalized


def _normalize_arena_registry_bindings(
    value: Any,
    expected_challenge_count: int,
) -> dict[str, dict[str, Any]]:
    label = "arena_registry_bindings"
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    if not 1 <= len(value) <= _MAX_GENESIS_CHALLENGES:
        _fail(f"{label} must contain one to 32 exact catalog bindings")

    normalized: dict[str, dict[str, Any]] = {}
    registry_challenge_ids: list[int] = []
    registry_versions: set[tuple[int, int]] = set()
    for catalog_key, raw_binding in sorted(value.items()):
        binding_label = f"{label}.{catalog_key}"
        if _ARENA_CATALOG_KEY.fullmatch(catalog_key) is None:
            _fail(
                f"{binding_label} key must be a lowercase challenge slug at a "
                "canonical x.y.z version"
            )
        parsed = _exact_record(
            raw_binding,
            _ARENA_REGISTRY_BINDING_KEYS,
            binding_label,
        )
        registry_challenge_id_text = _uint256_decimal(
            parsed["registry_challenge_id"],
            f"{binding_label}.registry_challenge_id",
        )
        registry_challenge_id = int(registry_challenge_id_text)
        if registry_challenge_id == 0:
            _fail(f"{binding_label}.registry_challenge_id must be positive")
        registry_version = _integer(
            parsed["registry_version"],
            f"{binding_label}.registry_version",
            1,
            2**32 - 1,
        )
        registry_version_key = (registry_challenge_id, registry_version)
        if registry_version_key in registry_versions:
            _fail(
                f"arena registry version {registry_challenge_id_text}@"
                f"{registry_version} is bound more than once"
            )
        registry_versions.add(registry_version_key)
        registry_challenge_ids.append(registry_challenge_id)

        catalog_manifest_hash = _bare_bytes32(
            parsed["catalog_manifest_hash"],
            f"{binding_label}.catalog_manifest_hash",
        )
        metadata_hash = _bytes32(
            parsed["metadata_hash"],
            f"{binding_label}.metadata_hash",
        )
        if metadata_hash != "0x" + catalog_manifest_hash:
            _fail(
                f"{binding_label}.metadata_hash must equal the 0x-prefixed "
                "catalog_manifest_hash"
            )
        sealed_artifact_commitment = _bytes32(
            parsed["sealed_artifact_commitment"],
            f"{binding_label}.sealed_artifact_commitment",
        )
        evaluator_commitment = _bytes32(
            parsed["evaluator_commitment"],
            f"{binding_label}.evaluator_commitment",
        )
        release_policy_commitment = _bytes32(
            parsed["release_policy_commitment"],
            f"{binding_label}.release_policy_commitment",
        )
        commitments = (
            metadata_hash,
            sealed_artifact_commitment,
            evaluator_commitment,
            release_policy_commitment,
        )
        if len(set(commitments)) != len(commitments):
            _fail(f"{binding_label} commitments must be pairwise distinct")

        paused = _boolean(parsed["paused"], f"{binding_label}.paused")
        configuration_frozen = _boolean(
            parsed["configuration_frozen"],
            f"{binding_label}.configuration_frozen",
        )
        if paused or not configuration_frozen:
            _fail(
                f"{binding_label} must be open, unpaused, and configuration-frozen"
            )
        normalized[catalog_key] = {
            "registry_challenge_id": registry_challenge_id_text,
            "registry_version": registry_version,
            "controller_address": _address(
                parsed["controller_address"],
                f"{binding_label}.controller_address",
            ),
            "pending_controller_address": _zero_address(
                parsed["pending_controller_address"],
                f"{binding_label}.pending_controller_address",
            ),
            "lifecycle": _exact_string(
                parsed["lifecycle"],
                "open",
                f"{binding_label}.lifecycle",
            ),
            "paused": paused,
            "configuration_frozen": configuration_frozen,
            "catalog_manifest_hash": catalog_manifest_hash,
            "metadata_uri": _printable_ascii(
                parsed["metadata_uri"],
                f"{binding_label}.metadata_uri",
                256,
            ),
            "metadata_hash": metadata_hash,
            "sealed_artifact_commitment": sealed_artifact_commitment,
            "evaluator_commitment": evaluator_commitment,
            "release_policy_commitment": release_policy_commitment,
        }

    if len(set(registry_challenge_ids)) != len(registry_challenge_ids):
        _fail("arena registry challenge IDs must be unique")
    challenge_count = len(normalized)
    if set(registry_challenge_ids) != set(range(1, challenge_count + 1)):
        _fail("arena registry challenge IDs must be the exact contiguous set 1..N")
    if challenge_count != expected_challenge_count:
        _fail(
            "arena_registry_bindings count must equal "
            "contracts.challenge_registry.expected_challenge_count"
        )
    return normalized


def _normalize_image(value: Any, release: str, index: int) -> dict[str, Any]:
    parsed = _exact_record(value, _IMAGE_KEYS, f"cvm.images[{index}]")
    service = _assert_string(parsed["service"], f"cvm.images[{index}].service", 32)
    repository = _IMAGE_REPOSITORIES.get(service)
    if repository is None:
        _fail(f"cvm.images[{index}].service is not supported")
    image = _assert_string(parsed["image"], f"cvm.images[{index}].image", 512)
    if re.fullmatch(re.escape(repository) + r"@sha256:[0-9a-f]{64}", image) is None:
        _fail(
            f"cvm.images[{index}].image must be the exact project-owned digest reference"
        )
    source_digest = _release_sha(
        parsed["source_digest"], f"cvm.images[{index}].source_digest"
    )
    if source_digest != release:
        _fail(f"cvm.images[{index}].source_digest must equal release_sha")
    source_ref = _assert_string(
        parsed["source_ref"], f"cvm.images[{index}].source_ref", 256
    )
    if source_ref != "refs/heads/main" and re.fullmatch(
        r"refs/tags/v[0-9][0-9A-Za-z._-]*", source_ref
    ) is None:
        _fail(f"cvm.images[{index}].source_ref must be main or a version tag")
    return {
        "service": service,
        "image": image,
        "source_digest": source_digest,
        "source_ref": source_ref,
        "repo": _exact_string(
            parsed["repo"], _GITHUB_REPOSITORY, f"cvm.images[{index}].repo"
        ),
        "signer_workflow": _exact_string(
            parsed["signer_workflow"],
            _GITHUB_SIGNER_WORKFLOW,
            f"cvm.images[{index}].signer_workflow",
        ),
        "provenance_attestation": _exact_string(
            parsed["provenance_attestation"],
            "verified",
            f"cvm.images[{index}].provenance_attestation",
        ),
        "sbom_attestation": _exact_string(
            parsed["sbom_attestation"],
            "verified",
            f"cvm.images[{index}].sbom_attestation",
        ),
    }


def _normalize_runtime_controls(value: Any) -> dict[str, bool]:
    keys = tuple(_RUNTIME_CONTROL_EXPECTATIONS)
    parsed = _exact_record(value, keys, "cvm.runtime_controls")
    normalized: dict[str, bool] = {}
    for key, expected in _RUNTIME_CONTROL_EXPECTATIONS.items():
        observed = _boolean(parsed[key], f"cvm.runtime_controls.{key}")
        if observed != expected:
            _fail(
                f"cvm.runtime_controls.{key} does not match the reviewed release value"
            )
        normalized[key] = observed
    return normalized


def _normalize_compute_workload_ingress(value: Any) -> dict[str, Any]:
    parsed = _exact_record(
        value,
        ("max_verdict_age_seconds", "revoked_quote_hashes"),
        "cvm.compute_workload_ingress",
    )
    maximum_age = _integer(
        parsed["max_verdict_age_seconds"],
        "cvm.compute_workload_ingress.max_verdict_age_seconds",
        1,
        300,
    )
    revoked_values = parsed["revoked_quote_hashes"]
    if type(revoked_values) is not list or len(revoked_values) > 256:
        _fail(
            "cvm.compute_workload_ingress.revoked_quote_hashes must contain at most 256 entries"
        )
    revoked = [
        _bytes32(
            value,
            f"cvm.compute_workload_ingress.revoked_quote_hashes[{index}]",
        )
        for index, value in enumerate(revoked_values)
    ]
    if revoked != sorted(set(revoked)):
        _fail(
            "cvm.compute_workload_ingress.revoked_quote_hashes must be sorted and unique"
        )
    return {
        "max_verdict_age_seconds": maximum_age,
        "revoked_quote_hashes": revoked,
    }


def _normalize_cvm(
    value: Any,
    release: str,
    normalize_https_origin: Callable[[Any, str], str],
) -> dict[str, Any]:
    parsed = _exact_record(value, _CVM_KEYS, "cvm")
    if type(parsed["images"]) is not list or len(parsed["images"]) != 3:
        _fail("cvm.images must contain exactly delegate, neko, and oracle")
    images = sorted(
        (
            _normalize_image(entry, release, index)
            for index, entry in enumerate(parsed["images"])
        ),
        key=lambda entry: entry["service"],
    )
    if [entry["service"] for entry in images] != list(_IMAGE_REPOSITORIES):
        _fail("cvm.images must contain exactly delegate, neko, and oracle once each")

    if (
        type(parsed["allowed_browser_origins"]) is not list
        or len(parsed["allowed_browser_origins"]) != 3
    ):
        _fail("cvm.allowed_browser_origins must contain exactly three reviewed origins")
    origins = sorted(
        normalize_https_origin(entry, f"cvm.allowed_browser_origins[{index}]")
        for index, entry in enumerate(parsed["allowed_browser_origins"])
    )
    if origins != list(_REQUIRED_BROWSER_ORIGINS):
        _fail(
            "cvm.allowed_browser_origins must equal the reviewed production origin set"
        )

    normalized = {
        "app_id": _assert_string(parsed["app_id"], "cvm.app_id", 128),
        "cvm_id": _assert_string(parsed["cvm_id"], "cvm.cvm_id", 128),
        "compose_hash": _bare_bytes32(parsed["compose_hash"], "cvm.compose_hash"),
        "local_compose_hash": _bare_bytes32(
            parsed["local_compose_hash"], "cvm.local_compose_hash"
        ),
        "rendered_compose_sha256": _bare_bytes32(
            parsed["rendered_compose_sha256"], "cvm.rendered_compose_sha256"
        ),
        "os_image_hash": _bare_bytes32(parsed["os_image_hash"], "cvm.os_image_hash"),
        "os_is_dev": _boolean(parsed["os_is_dev"], "cvm.os_is_dev"),
        "public_logs": _boolean(parsed["public_logs"], "cvm.public_logs"),
        "public_sysinfo": _boolean(parsed["public_sysinfo"], "cvm.public_sysinfo"),
        "public_tcbinfo": _boolean(parsed["public_tcbinfo"], "cvm.public_tcbinfo"),
        "tee_identity": _address(parsed["tee_identity"], "cvm.tee_identity"),
        "delegate_url": normalize_https_origin(
            parsed["delegate_url"],
            "cvm.delegate_url",
        ),
        "images": images,
        "allowed_browser_origins": origins,
        "compute_workload_ingress": _normalize_compute_workload_ingress(
            parsed["compute_workload_ingress"]
        ),
        "runtime_controls": _normalize_runtime_controls(parsed["runtime_controls"]),
    }
    if (
        normalized["os_is_dev"]
        or normalized["public_logs"]
        or normalized["public_sysinfo"]
        or normalized["public_tcbinfo"]
    ):
        _fail("cvm must use the reviewed non-dev private production posture")
    return normalized


def _normalize_requested_features(
    value: Any,
    keys: tuple[str, ...],
) -> dict[str, bool]:
    parsed = _exact_record(value, keys, "requested_features")
    normalized = {
        key: _boolean(parsed[key], f"requested_features.{key}")
        for key in keys
    }
    if (
        normalized["compute_vault_authorization"]
        and not normalized["compute_vault_funding"]
    ):
        _fail("compute_vault_authorization requires compute_vault_funding")
    return normalized


def _normalize_execution_policy(value: Any) -> dict[str, Any]:
    parsed = _exact_record(value, _EXECUTION_POLICY_KEYS, "execution_policy")
    if type(parsed["approver_hashes"]) is not list:
        _fail("execution_policy.approver_hashes must be an array")
    if not 1 <= len(parsed["approver_hashes"]) <= 64:
        _fail("execution_policy.approver_hashes must contain one to 64 entries")
    approver_hashes = [
        _bare_bytes32(entry, f"execution_policy.approver_hashes[{index}]")
        for index, entry in enumerate(parsed["approver_hashes"])
    ]
    if approver_hashes != sorted(set(approver_hashes)):
        _fail("execution_policy.approver_hashes must be lowercase, sorted, and unique")
    root = _bare_bytes32(
        parsed["approver_root_hash"], "execution_policy.approver_root_hash"
    )
    if root != _approver_root_hash(approver_hashes):
        _fail(
            "execution_policy.approver_root_hash does not match the exact approver set"
        )

    anchor = _exact_record(
        parsed["rollback_anchor_target"],
        _ROLLBACK_ANCHOR_TARGET_KEYS,
        "execution_policy.rollback_anchor_target",
    )
    normalized_anchor = {
        "schema": _exact_string(
            anchor["schema"],
            _ROLLBACK_ANCHOR_SCHEMA,
            "execution_policy.rollback_anchor_target.schema",
        ),
        "chain_id": _integer(
            anchor["chain_id"],
            "execution_policy.rollback_anchor_target.chain_id",
            _BASE_SEPOLIA_CHAIN_ID,
            _BASE_SEPOLIA_CHAIN_ID,
        ),
        "contract_address": _address(
            anchor["contract_address"],
            "execution_policy.rollback_anchor_target.contract_address",
        ),
        "runtime_code_hash": _bytes32(
            anchor["runtime_code_hash"],
            "execution_policy.rollback_anchor_target.runtime_code_hash",
        ),
        "writer_address": _address(
            anchor["writer_address"],
            "execution_policy.rollback_anchor_target.writer_address",
        ),
        "writer_custody": _exact_string(
            anchor["writer_custody"],
            _ANCHOR_WRITER_CUSTODY,
            "execution_policy.rollback_anchor_target.writer_custody",
        ),
        "writer_key_path": _exact_string(
            anchor["writer_key_path"],
            _ANCHOR_WRITER_KEY_PATH,
            "execution_policy.rollback_anchor_target.writer_key_path",
        ),
        "writer_release_commitment": _bytes32(
            anchor["writer_release_commitment"],
            "execution_policy.rollback_anchor_target.writer_release_commitment",
        ),
        "confirmations": _integer(
            anchor["confirmations"],
            "execution_policy.rollback_anchor_target.confirmations",
            2,
            256,
        ),
        "max_block_age_seconds": _integer(
            anchor["max_block_age_seconds"],
            "execution_policy.rollback_anchor_target.max_block_age_seconds",
            30,
            3_600,
        ),
        "max_future_block_skew_seconds": _integer(
            anchor["max_future_block_skew_seconds"],
            "execution_policy.rollback_anchor_target.max_future_block_skew_seconds",
            0,
            300,
        ),
        "verification_model": _exact_string(
            anchor["verification_model"],
            _ANCHOR_VERIFICATION_MODEL,
            "execution_policy.rollback_anchor_target.verification_model",
        ),
        "independent_rpc_quorum_verified": _boolean(
            anchor["independent_rpc_quorum_verified"],
            "execution_policy.rollback_anchor_target.independent_rpc_quorum_verified",
        ),
        "consensus_proof_verified": _boolean(
            anchor["consensus_proof_verified"],
            "execution_policy.rollback_anchor_target.consensus_proof_verified",
        ),
    }
    if (
        normalized_anchor["independent_rpc_quorum_verified"]
        or normalized_anchor["consensus_proof_verified"]
    ):
        _fail(
            "rollback anchor target must preserve the exact single-RPC trust classification"
        )

    return {
        "canonicalization_version": _exact_string(
            parsed["canonicalization_version"],
            _CANONICALIZATION_VERSION,
            "execution_policy.canonicalization_version",
        ),
        "approval_schema": _exact_string(
            parsed["approval_schema"],
            _APPROVAL_SCHEMA,
            "execution_policy.approval_schema",
        ),
        "api_schema_version": _integer(
            parsed["api_schema_version"],
            "execution_policy.api_schema_version",
            _API_SCHEMA_VERSION,
            _API_SCHEMA_VERSION,
        ),
        "store_schema_version": _integer(
            parsed["store_schema_version"],
            "execution_policy.store_schema_version",
            _STORE_SCHEMA_VERSION,
            _STORE_SCHEMA_VERSION,
        ),
        "approver_hashes": approver_hashes,
        "approver_root_hash": root,
        "rollback_anchor_target": normalized_anchor,
    }


def _validate_cross_bindings(
    core: dict[str, Any],
    *,
    diligence_developer_policy: str,
) -> None:
    contracts = core["contracts"]
    cvm = core["cvm"]
    operator = core["operator_address"]
    policy = core["execution_policy"]
    operator_bindings = [
        ("ChallengeRegistry owner", contracts["challenge_registry"]["owner"]),
        (
            "TinkerAccountEncumbrance owner",
            contracts["tinker_account_encumbrance"]["owner"],
        ),
        ("ComputeCreditVault owner", contracts["compute_credit_vault"]["owner"]),
        ("EmailOracleAuth owner", contracts["email_oracle_auth"]["owner"]),
    ]
    diligence_developer = contracts["diligence_room"]["developer"]
    if diligence_developer_policy == "historical-operator-v2":
        operator_bindings.insert(
            0,
            ("DiligenceRoom developer", diligence_developer),
        )
    elif diligence_developer_policy == "permanent-distinct-v3":
        if diligence_developer in {
            operator,
            contracts["diligence_room"]["address"],
        }:
            _fail(
                "DiligenceRoom permanent developer must differ from the "
                "deployment operator and room contract"
            )
    else:
        _fail("final release authority core uses an unsupported developer policy")
    for label, observed in operator_bindings:
        if observed != operator:
            _fail(f"{label} must equal operator_address")
    if cvm["tee_identity"] == operator:
        _fail("cvm.tee_identity must differ from operator_address")
    diligence_admission = contracts["diligence_room"]["release_admission"]
    if (
        diligence_admission["tee_identity"] != cvm["tee_identity"]
        or diligence_admission["compose_hash"] != cvm["compose_hash"]
    ):
        _fail(
            "DiligenceRoom release admission must equal the one reviewed main CVM compose and TEE identity"
        )
    if (
        contracts["tinker_account_encumbrance"]["approved_compose_hashes"][0]
        != "0x" + cvm["compose_hash"]
        or contracts["tinker_account_encumbrance"]["managers"][0]
        != cvm["tee_identity"]
    ):
        _fail(
            "TinkerAccountEncumbrance release authority must equal the one reviewed main CVM compose and TEE identity"
        )
    if (
        contracts["compute_credit_vault"]["tee_identity"] != cvm["tee_identity"]
        or contracts["compute_credit_vault"]["compose_hash"] != cvm["compose_hash"]
    ):
        _fail("ComputeCreditVault execution roots must match the main CVM")
    email = contracts["email_oracle_auth"]
    if email["consumer_address"] != cvm["tee_identity"]:
        _fail("EmailOracleAuth consumer must equal the main CVM TEE identity")
    if (
        email["release"]["oracle_compose_hash"] != "0x" + cvm["compose_hash"]
        or email["release"]["consumer_compose_hash"]
        != "0x" + cvm["compose_hash"]
    ):
        _fail(
            "EmailOracleAuth oracle and consumer compose hashes must equal the reviewed main CVM compose"
        )
    if (
        email["release"]["target_boot"]["os_image_hash"]
        != "0x" + cvm["os_image_hash"]
    ):
        _fail("EmailOracleAuth target boot OS image must equal the main CVM OS image")
    email_infrastructure_roles = [
        email["address"],
        email["owner"],
        email["consumer_address"],
        email["release"]["kms_contract_address"],
        email["release"]["kms_implementation_address"],
        email["release"]["target_boot"]["instance_id"],
    ]
    if len(set(email_infrastructure_roles)) != len(email_infrastructure_roles):
        _fail(
            "EmailOracleAuth owner, consumer, KMS proxy, implementation, instance, and auth contract must be distinct"
        )
    control_plane_roles = [
        operator,
        cvm["tee_identity"],
        *(
            [diligence_developer]
            if diligence_developer_policy == "permanent-distinct-v3"
            else []
        ),
        contracts["diligence_room"]["result_verifier"],
        contracts["diligence_room"]["attestation_verifier"],
        contracts["compute_credit_vault"]["developer"],
        contracts["compute_credit_vault"]["metering_verifier"],
        contracts["compute_credit_vault"]["metering_qvl_verifier"],
        policy["rollback_anchor_target"]["writer_address"],
    ]
    if len(set(control_plane_roles)) != len(control_plane_roles):
        _fail(
            "all governance, TEE, verifier, metering, and anchor-writer roles must be distinct"
        )

    anchor = policy["rollback_anchor_target"]
    expected_writer_release_commitment = (
        "0x" + core["cvm_launch_intent_sha256"][len("sha256:") :]
    )
    if anchor["writer_release_commitment"] != expected_writer_release_commitment:
        _fail(
            "rollback anchor writer_release_commitment must equal the exact "
            "CVM launch-intent digest"
        )
    contract_addresses = {entry["address"] for entry in contracts.values()}
    provider_forbidden_roles = {
        *control_plane_roles,
        *contract_addresses,
        anchor["contract_address"],
    }
    for label, provider in (
        (
            "native",
            contracts["compute_credit_vault"]["rate_policies"]["native"][
                "provider"
            ],
        ),
        (
            "ERC20",
            contracts["compute_credit_vault"]["rate_policies"]["erc20"][
                "provider"
            ],
        ),
    ):
        if provider in provider_forbidden_roles:
            _fail(
                f"ComputeCreditVault {label} provider must be separate from "
                "governance, contracts, TEE, verifier, metering, and anchor roles"
            )
    for infrastructure_address in (
        email["release"]["kms_contract_address"],
        email["release"]["kms_implementation_address"],
        email["release"]["target_boot"]["instance_id"],
    ):
        if (
            infrastructure_address in contract_addresses
            or infrastructure_address in control_plane_roles
            or infrastructure_address == anchor["contract_address"]
        ):
            _fail(
                "Email KMS and target-instance addresses must be separate from application, control-plane, and anchor roles"
            )
    if anchor["contract_address"] in contract_addresses:
        _fail("rollback anchor target must be separate from the application contracts")
    if any(role in contract_addresses for role in control_plane_roles):
        _fail("control-plane roles must not equal an application contract address")
    if anchor["contract_address"] in control_plane_roles:
        _fail("control-plane roles must not equal the rollback anchor contract")


def _normalize_final_release_authority_core_version(
    value: Any,
    *,
    schema: str,
    requested_feature_keys: tuple[str, ...],
    normalize_https_origin: Callable[[Any, str], str],
    diligence_developer_policy: str,
) -> dict[str, Any]:
    """Validate one exact version and return a fresh normalized artifact."""

    _validate_json_tree(value)
    parsed = _exact_record(value, _TOP_LEVEL_KEYS, "final release authority core")
    release = _release_sha(parsed["release_sha"], "release_sha")
    network = _exact_record(
        parsed["network"], ("chain_id", "public_rpc_url"), "network"
    )
    wallet = _exact_record(
        parsed["wallet_auth"],
        ("domain", "uri", "walletconnect_project_id"),
        "wallet_auth",
    )
    contracts = _normalize_contracts(parsed["contracts"])
    normalized = {
        "schema": _exact_string(
            parsed["schema"], schema, "schema"
        ),
        "release_sha": release,
        "network": {
            "chain_id": _integer(
                network["chain_id"],
                "network.chain_id",
                _BASE_SEPOLIA_CHAIN_ID,
                _BASE_SEPOLIA_CHAIN_ID,
            ),
            "public_rpc_url": _exact_string(
                network["public_rpc_url"],
                _BASE_SEPOLIA_PUBLIC_RPC,
                "network.public_rpc_url",
            ),
        },
        "operator_address": _address(parsed["operator_address"], "operator_address"),
        "deployment_intent_sha256": _sha256_pin(
            parsed["deployment_intent_sha256"], "deployment_intent_sha256"
        ),
        "cvm_launch_intent_sha256": _sha256_pin(
            parsed["cvm_launch_intent_sha256"], "cvm_launch_intent_sha256"
        ),
        "contracts": contracts,
        "cvm": _normalize_cvm(
            parsed["cvm"],
            release,
            normalize_https_origin,
        ),
        "arena_registry_bindings": _normalize_arena_registry_bindings(
            parsed["arena_registry_bindings"],
            contracts["challenge_registry"]["expected_challenge_count"],
        ),
        "wallet_auth": {
            "domain": _exact_string(
                wallet["domain"], "www.wikigen.me", "wallet_auth.domain"
            ),
            "uri": _exact_string(
                wallet["uri"], "https://www.wikigen.me", "wallet_auth.uri"
            ),
            "walletconnect_project_id": _walletconnect_project_id(
                wallet["walletconnect_project_id"],
                "wallet_auth.walletconnect_project_id",
            ),
        },
        "requested_features": _normalize_requested_features(
            parsed["requested_features"],
            requested_feature_keys,
        ),
        "execution_policy": _normalize_execution_policy(parsed["execution_policy"]),
    }
    _validate_cross_bindings(
        normalized,
        diligence_developer_policy=diligence_developer_policy,
    )
    encoded = _canonical_json(normalized)
    if len(encoded) > MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES:
        _fail(
            "canonical final release authority core exceeds "
            f"{MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES} bytes"
        )
    return normalized


def normalize_final_release_authority_core(value: Any) -> dict[str, Any]:
    """Validate the frozen v3 compatibility authority for historical replay."""

    return _normalize_final_release_authority_core_version(
        value,
        schema=FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA,
        requested_feature_keys=_REQUESTED_FEATURE_KEYS_V3,
        normalize_https_origin=_current_public_https_origin_v3,
        diligence_developer_policy="permanent-distinct-v3",
    )


def normalize_historical_final_release_authority_core_v2(
    value: Any,
) -> dict[str, Any]:
    """Validate the frozen historical v2 wire format for offline replay."""

    return _normalize_final_release_authority_core_version(
        value,
        schema=FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
        requested_feature_keys=_HISTORICAL_REQUESTED_FEATURE_KEYS_V2,
        normalize_https_origin=_historical_https_origin_v2,
        diligence_developer_policy="historical-operator-v2",
    )


normalize_execution_policy_release_core = normalize_final_release_authority_core


def canonical_final_release_authority_core_bytes(value: Any) -> bytes:
    """Return compact recursively key-sorted ensure-ASCII JSON without a newline."""

    return _canonical_json(normalize_final_release_authority_core(value))


def canonical_historical_final_release_authority_core_v2_bytes(
    value: Any,
) -> bytes:
    """Return canonical historical v2 bytes for offline replay only."""

    return _canonical_json(normalize_historical_final_release_authority_core_v2(value))


canonical_execution_policy_release_core_bytes = canonical_final_release_authority_core_bytes


def final_release_authority_core_digest(value: Any) -> str:
    """Return the bare lowercase SHA-256 final-authority commitment."""

    digest = hashlib.sha256()
    digest.update(FINAL_RELEASE_AUTHORITY_CORE_DOMAIN)
    digest.update(canonical_final_release_authority_core_bytes(value))
    return digest.hexdigest()


def historical_final_release_authority_core_v2_digest(value: Any) -> str:
    """Return the frozen historical v2 commitment for offline replay only."""

    digest = hashlib.sha256()
    digest.update(FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN)
    digest.update(canonical_historical_final_release_authority_core_v2_bytes(value))
    return digest.hexdigest()


execution_policy_release_core_digest = final_release_authority_core_digest


__all__ = [
    "FINAL_RELEASE_AUTHORITY_CORE_DOMAIN",
    "FINAL_RELEASE_AUTHORITY_CORE_SCHEMA",
    "FINAL_RELEASE_AUTHORITY_CORE_V2_DOMAIN",
    "FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA",
    "FINAL_RELEASE_AUTHORITY_CORE_V3_DOMAIN",
    "FINAL_RELEASE_AUTHORITY_CORE_V3_SCHEMA",
    "MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES",
    "FinalReleaseAuthorityCoreValidationError",
    "canonical_final_release_authority_core_bytes",
    "final_release_authority_core_digest",
    "canonical_historical_final_release_authority_core_v2_bytes",
    "historical_final_release_authority_core_v2_digest",
    "normalize_historical_final_release_authority_core_v2",
    "normalize_final_release_authority_core",
    "EXECUTION_POLICY_RELEASE_CORE_DOMAIN",
    "EXECUTION_POLICY_RELEASE_CORE_SCHEMA",
    "MAX_EXECUTION_POLICY_RELEASE_CORE_BYTES",
    "ExecutionPolicyReleaseCoreValidationError",
    "canonical_execution_policy_release_core_bytes",
    "execution_policy_release_core_digest",
    "normalize_execution_policy_release_core",
]
