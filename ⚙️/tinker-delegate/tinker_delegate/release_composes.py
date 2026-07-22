"""Render the seven digest-pinned Phala CVM release descriptors.

The inputs are the aggregate image-release evidence produced by the repository's
clean GitHub Actions workflow and the exact canonical deployment-intent core
reviewed before deployment.  The renderer is intentionally strict: it accepts
exactly one operator namespace, one workflow identity, one source SHA, one
platform, exactly five canonical image subjects, and the v6 intent validated by
the repository's fixed Node checker.  It never reads a secret-bearing env file
or consumes post-deployment identities, compose hashes, providers, or anchor
facts.  The main runtime, five purpose-separated Intel DCAP QVL instances, and
independent compute-metering service each receive their own compose descriptor;
deployment and TDX verification remain later gates.  The fifth QVL exists
specifically to authenticate the metering CVM rather than accepting that CVM's
self-described signer and deployment pins as TDX evidence.

The five QVL descriptors and the independent metering descriptor intentionally
start with no enabled services.  Their services are gated by the exact
``qvl-runtime`` and ``metering-runtime`` profiles and may be selected only by a
later ``COMPOSE_PROFILES`` environment update.  Docker Compose interpolates a
model before profile selection, so callers must inject every strict
``${KEY:?}`` policy input before invoking Compose for that later phase; profiles
are never treated as an interpolation bypass.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml


SCHEMA = "dnai.tee-image-release.v1"
TOPOLOGY_SCHEMA = "dnai.cvm-topology.v6"
DEPLOYMENT_INTENT_SCHEMA = "dnai.deployment-intent-core.v6"
DEPLOYMENT_INTENT_RECEIPT_SCHEMA = "dnai.deployment-intent-validation-receipt.v6"
DEPLOYMENT_TOOLCHAIN_AUTHORITY = {
    "foundry": {
        "buildProfile": "maxperf",
        "castExecutableSha256": "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d",
        "castVersion": "1.5.1-stable",
        "commitSha": "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
        "forgeVersion": "1.5.1-stable",
    },
    "solidity": {
        "bytecodeHash": "ipfs",
        "cborMetadata": True,
        "compilerVersion": "0.8.28+commit.7893614a",
        "configuredVersion": "0.8.28",
        "evmVersion": "prague",
        "libraries": [],
        "optimizer": True,
        "optimizerRuns": 200,
        "profile": "default",
        "useLiteralContent": False,
        "viaIr": True,
    },
}
PUBLIC_RUNTIME_POLICY_SCHEMA = "dnai.public-runtime-numeric-policy.v1"
SOURCE_REPOSITORY = "therealwiki/dnai-wikigen"
SIGNER_WORKFLOW = "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml"
PROVENANCE_PREDICATE = "https://slsa.dev/provenance/v1"
PLATFORM = "linux/amd64"
IMAGE_PREFIX = "ghcr.io/therealwiki/dnai-wikigen/"
IMAGE_NAMES = (
    "tinker-delegate",
    "tee-email-oracle",
    "neko-chrome",
    "attestation-qvl",
    "compute-metering",
)
MAIN_SERVICES = (
    "neko",
    "oracle",
    "delegate",
    "diligence-policy-init",
    "arena-policy-init",
    "arena-worker",
    "anchor-writer-evidence",
    "deal-runtime",
    "compute-execution-worker",
)
QVL_SERVICES = ("policy-init", "qvl")
METERING_SERVICES = ("policy-init", "state-init", "metering")
QVL_RUNTIME_PROFILE = "qvl-runtime"
METERING_RUNTIME_PROFILE = "metering-runtime"
PHASE_GATE_SCHEMA = "dnai.cvm-compose-phase-gate.v1"
# These execution authorities are intentionally unavailable to the
# three-service bootstrap runtime.  The two public Arena release pins needed
# for heartbeat comparison are deliberately *not* in this list: they grant no
# execution authority, and an absent/mismatched/future/stale heartbeat still
# keeps the capability projection modeled.  Reviewed interpolation remains
# only where a value cannot exist before measurement.
BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS = (
    "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS",
    "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL",
    "TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
    "TINKER_EXECUTION_POLICY_APPROVAL_DOMAIN",
    "TINKER_EXECUTION_POLICY_APPROVED_SIGNERS",
    "TINKER_EXECUTION_POLICY_APPROVER_ROOT_HASH",
)
MAIN_PROVISIONING_RESULT_ENVIRONMENT_KEYS = (
    "EMAIL_ORACLE_CONSUMER_APP_ID",
    "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
    "TINKER_ARENA_WORKER_APP_ID",
    "TINKER_ARENA_WORKER_COMPOSE_HASH",
    "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
    "TINKER_COMPUTE_VAULT_COMPOSE_HASH",
    "TINKER_COMPUTE_WORKLOAD_CVM_ID",
    "TINKER_DILIGENCE_ALLOWED_APP_ID",
    "TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH",
    "TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH",
)
# Docker Compose expands every interpolation before it filters services by
# profile.  These values do not exist until after the measured CVM identities
# are available, so `${KEY:?}` would make even the intentionally empty
# bootstrap model fail to parse.  `${KEY:-}` is the only reviewed late-value
# representation: it has no nonempty fallback, lets the disabled profile stay
# inert, and the phase updater must replace it with a nonempty encrypted value
# before enabling that profile.
MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS = (
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    "TINKER_ARENA_REGISTRY_RPC_URL",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
    "TINKER_ARENA_PROVISION_AUTH_KEY_B64",
    "TINKER_ARENA_PROVISION_AUTH_TAG",
    "TINKER_ARENA_PROVISION_EVALUATOR_B64",
    "TINKER_ARENA_PROVISION_RELEASE_B64",
    "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN",
    "TINKER_CHAIN_RPC_URL",
    "TINKER_COMPUTE_CHAIN_RPC_URL",
    "TINKER_COMPUTE_METERING_AUTH_TOKEN",
    "TINKER_DILIGENCE_QVL_AUTH_TOKEN",
    "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN",
    "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
    "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
    "TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH",
    "TINKER_ARENA_WORKER_QVL_VERDICT_URL",
    "TINKER_COMPUTE_METERING_URL",
    "TINKER_COMPUTE_METERING_POLICY_SET_HASH",
    "TINKER_COMPUTE_VAULT_ADDRESS",
    "TINKER_COMPUTE_VAULT_RUNTIME_CODE_HASH",
    "TINKER_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
    "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
    "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
    "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN",
    "TINKER_COMPUTE_WORKLOAD_QVL_MAX_VERDICT_AGE_SECONDS",
    "TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
    "TINKER_COMPUTE_WORKLOAD_QVL_REVOKED_QUOTE_HASHES_JSON",
    "TINKER_COMPUTE_WORKLOAD_QVL_URL",
    "TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS",
    "TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH",
    "TINKER_DILIGENCE_QVL_URL",
    "TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_RELEASE_POLICY_HASH",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_URL",
    "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_VERIFIER_ADDRESS",
)

# The Arena worker consumes the same signed seven-CVM lineage already
# authorized for the main-runtime/Compute boundary.  Container-facing names
# follow ``Settings`` while every value remains an exact alias of that existing
# authority; this descriptor must never create a second operator-supplied
# lineage namespace.  The Arena QVL measurement-policy digest is its own
# canonical static authority because it cannot be substituted with the
# Compute-workload QVL policy.
ARENA_WORKER_CODE_OWNED_ENVIRONMENT = {
    "TINKER_MAIN_RUNTIME_CVM_ID": (
        "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}"
    ),
    "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256": (
        "${TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:?Signed seven-CVM deployment intent required}"
    ),
    "TINKER_RELEASE_AUTHORITY_SHA256": (
        "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:?Canonical release authority required}"
    ),
    "TINKER_RELEASE_CEREMONY_NONCE": (
        "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}"
    ),
    "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256": (
        "${TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256:?Linked Arena QVL measurement policy required}"
    ),
    "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
        "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:?Authorized ChallengeRegistry challenge-set digest required}"
    ),
    "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": "true",
}

ARENA_WORKER_RENDERED_CODE_OWNED_ENVIRONMENT = {
    **ARENA_WORKER_CODE_OWNED_ENVIRONMENT,
    "TINKER_RELEASE_AUTHORITY_SHA256": (
        "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}"
    ),
    "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
        "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:-}"
    ),
}

ARENA_WORKER_FAIL_CLOSED_HEARTBEAT_ENVIRONMENT = {
    "TINKER_ARENA_WORKER_HEARTBEAT_PATH": "/data/arena_worker_heartbeat.json",
    "TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS": (
        "${TINKER_ARENA_WORKER_HEARTBEAT_TTL_SECONDS:-30}"
    ),
    "TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH": (
        "${TINKER_ARENA_WORKER_HEARTBEAT_KEY_PATH:-tinker/arena_worker_heartbeat}"
    ),
    "TINKER_ARENA_WORKER_HEARTBEAT_INTEGRITY_KEY": "",
}
QVL_POST_MEASUREMENT_ENVIRONMENT_KEYS = (
    "QVL_AUTH_TOKEN",
    "QVL_RELEASE_POLICY_B64",
)
METERING_POST_MEASUREMENT_ENVIRONMENT_KEYS = (
    "METERING_AUTH_TOKEN",
    "METERING_POLICY_SET_B64",
    "METERING_QVL_AUTH_TOKEN",
    "METERING_RPC_URL",
    "METERING_QVL_RELEASE_POLICY_HASH",
    "METERING_QVL_URL",
    "METERING_QVL_VERIFIER_ADDRESS",
    "METERING_RELEASE_AUTHORITY_SHA256",
)
QVL_DOMAINS = (
    (
        "diligence_qvl_cvm",
        "dnai-diligence-attestation-qvl",
        "dnai-diligence-qvl.phala.yaml",
    ),
    (
        "arena_qvl_cvm",
        "dnai-arena-attestation-qvl",
        "dnai-arena-qvl.phala.yaml",
    ),
    (
        "anchor_writer_qvl_cvm",
        "dnai-anchor-writer-attestation-qvl",
        "dnai-anchor-writer-qvl.phala.yaml",
    ),
    (
        "compute_workload_qvl_cvm",
        "dnai-compute-workload-attestation-qvl",
        "dnai-compute-workload-qvl.phala.yaml",
    ),
    (
        "compute_metering_qvl_cvm",
        "dnai-compute-metering-attestation-qvl",
        "dnai-compute-metering-qvl.phala.yaml",
    ),
)
QVL_CONTEXTS = {
    "diligence_qvl_cvm": "diligence",
    "arena_qvl_cvm": "arena",
    "anchor_writer_qvl_cvm": "execution_policy_anchor_writer",
    "compute_workload_qvl_cvm": "compute_workload",
    "compute_metering_qvl_cvm": "compute_metering",
}
QVL_INTENT_DOMAINS = {
    "diligence_qvl_cvm": "diligence",
    "arena_qvl_cvm": "arena",
    "anchor_writer_qvl_cvm": "anchorWriter",
    "compute_workload_qvl_cvm": "computeWorkload",
    "compute_metering_qvl_cvm": "computeMetering",
}
QVL_NUMERIC_ENVIRONMENT_KEYS = (
    "QVL_CHALLENGE_CAPACITY",
    "QVL_CHALLENGE_TTL_SECONDS",
    "QVL_MAX_CONCURRENCY",
    "QVL_RATE_CAPACITY",
    "QVL_RATE_REFILL_PER_SECOND",
    "QVL_REQUEST_BODY_TIMEOUT_SECONDS",
    "QVL_VERIFICATION_TIMEOUT_SECONDS",
)
METERING_NUMERIC_ENVIRONMENT_KEYS = (
    "METERING_MAX_CONCURRENCY",
    "METERING_RATE_CAPACITY",
    "METERING_RATE_REFILL_PER_SECOND",
    "METERING_REQUEST_BODY_TIMEOUT_SECONDS",
    "METERING_RPC_TIMEOUT_SECONDS",
)
PRODUCTION_ORACLE_POLICY = {
    "ORACLE_CRED_STORE_PATH": "/data/credentials.enc",
    "ORACLE_CRED_STORE_KEY": "",
    "ORACLE_AUTO_GENESIS": "false",
    "ORACLE_PRODUCTION_RELEASE": "true",
    "ORACLE_DSTACK_ENABLED": "true",
    "ORACLE_DSTACK_KEY_PATH": "email/creds",
    "ORACLE_RUNTIME_AUTH_REQUIRED": "true",
    "ORACLE_RUNTIME_AUTH_TOKEN": "",
    "ORACLE_RUNTIME_AUTH_KEY_PATH": "oracle/runtime-auth",
    "ORACLE_AUTH_REQUIRED": "true",
    "ORACLE_AUTH_CONTRACT_ADDRESS": (
        "${EMAIL_ORACLE_AUTH_ADDRESS:?Fresh EmailOracleAuth address required}"
    ),
    "ORACLE_AUTH_RPC_URL": (
        "${BASE_SEPOLIA_RPC_URL:?Primary Base Sepolia HTTPS RPC URL required}"
    ),
    "ORACLE_AUTH_RPC_URL_SECONDARY": (
        "${BASE_SEPOLIA_RPC_URL_SECONDARY:?Independent secondary Base Sepolia HTTPS RPC URL required}"
    ),
    "ORACLE_AUTH_CHAIN_ID": "84532",
    "ORACLE_AUTH_CONTRACT_RUNTIME_CODE_HASH": (
        "${EMAIL_ORACLE_AUTH_RUNTIME_CODE_HASH:?EmailOracleAuth runtime code hash required}"
    ),
    "ORACLE_AUTH_CONSUMER_APP_ID": (
        "${EMAIL_ORACLE_CONSUMER_APP_ID:?Release-bound main CVM TEE identity required}"
    ),
    "ORACLE_AUTH_CONSUMER_COMPOSE_HASH": (
        "${EMAIL_ORACLE_CONSUMER_COMPOSE_HASH:?Release-bound main CVM compose hash required}"
    ),
    "ORACLE_AUTH_EXPECTED_CALLER_IDENTITY": "tinker-delegate.signup",
    "ORACLE_AUTH_MAX_FINALIZED_BLOCK_AGE_SECONDS": "900",
    "ORACLE_AUTH_MAX_FUTURE_BLOCK_SKEW_SECONDS": "30",
    "ORACLE_AUTH_CHECKPOINT_STORE_PATH": "/data/email_auth_checkpoint.json",
    "ORACLE_OTP_REPLAY_STORE_PATH": "/data/otp_replay.enc",
    "ORACLE_OTP_REPLAY_STORE_KEY": "",
    "ORACLE_OTP_REPLAY_KEY_PATH": "email/otp_replay",
    "ORACLE_ALLOW_CREDENTIAL_PROVISIONING_ENDPOINT": "false",
    "ORACLE_CREDENTIAL_PROVISIONING_TOKEN": "",
}

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UINT = re.compile(r"^(?:0|[1-9][0-9]{0,77})$")
_DECIMAL = re.compile(
    r"^(?:0\.[0-9]{0,5}[1-9]|[1-9][0-9]{0,2}(?:\.[0-9]{0,5}[1-9])?)$"
)
_SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_SOURCE_REF = re.compile(r"^refs/(?:heads/main|tags/v[0-9][A-Za-z0-9._-]*)$")
_DEPLOYMENT_INTENT_RECEIPT_FIELDS = (
    "schema",
    "status",
    "truthStatus",
    "deploymentIntentSha256",
    "releaseSha",
    "chainId",
    "canonicalContractCount",
    "canonicalCvmCount",
    "dynamicRuntimeAuthorityCount",
    "qvlNumericPolicyCount",
    "reviewerAuthorityCurrentStatusEpoch",
    "reviewerAuthorityCurrentStatusSha256",
    "staticContractInputCount",
)


class ReleaseComposeError(RuntimeError):
    """Raised before any descriptor is written when release evidence is invalid."""


@dataclass(frozen=True)
class ValidatedImage:
    name: str
    repository: str
    digest: str
    image: str


@dataclass(frozen=True)
class ValidatedRelease:
    release_sha: str
    source_ref: str
    generated_at: str
    images: tuple[ValidatedImage, ...]
    raw: Mapping[str, Any]

    @property
    def by_name(self) -> dict[str, ValidatedImage]:
        return {image.name: image for image in self.images}


@dataclass(frozen=True)
class ValidatedDeploymentIntent:
    deployment_intent_sha256: str
    release_sha: str
    qvl_numeric_environment: Mapping[str, Mapping[str, str]]
    metering_numeric_environment: Mapping[str, str]
    raw: Mapping[str, Any]


@dataclass(frozen=True)
class RenderedRelease:
    main_compose: Path
    diligence_qvl_compose: Path
    arena_qvl_compose: Path
    anchor_writer_qvl_compose: Path
    compute_workload_qvl_compose: Path
    compute_metering_qvl_compose: Path
    metering_compose: Path
    image_manifest: Path
    image_manifest_attestation: Path
    deployment_intent: Path
    topology: Path

    def to_public_dict(self) -> dict[str, str]:
        return {
            "status": "rendered_not_deployed",
            "main_compose": str(self.main_compose),
            "diligence_qvl_compose": str(self.diligence_qvl_compose),
            "arena_qvl_compose": str(self.arena_qvl_compose),
            "anchor_writer_qvl_compose": str(self.anchor_writer_qvl_compose),
            "compute_workload_qvl_compose": str(self.compute_workload_qvl_compose),
            "compute_metering_qvl_compose": str(self.compute_metering_qvl_compose),
            "metering_compose": str(self.metering_compose),
            "image_manifest": str(self.image_manifest),
            "image_manifest_attestation": str(self.image_manifest_attestation),
            "deployment_intent": str(self.deployment_intent),
            "topology": str(self.topology),
        }


def _record(value: Any, keys: tuple[str, ...], context: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReleaseComposeError(f"{context} must be an object")
    actual = set(value)
    expected = set(keys)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise ReleaseComposeError(f"{context} has invalid fields: {'; '.join(detail)}")
    return value


def _ordered_record(
    value: Any,
    keys: tuple[str, ...],
    context: str,
) -> Mapping[str, Any]:
    """Require the deterministic field order emitted by a canonical artifact."""

    parsed = _record(value, keys, context)
    if tuple(parsed) != keys:
        raise ReleaseComposeError(f"{context} fields are not in canonical order")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseComposeError(f"release evidence repeats JSON field {key}")
        value[key] = item
    return value


def _text(value: Any, context: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ReleaseComposeError(f"{context} must be a bounded non-empty string")
    if any(ord(character) < 0x20 for character in value):
        raise ReleaseComposeError(f"{context} contains a control character")
    return value


def _integer_string(
    value: Any,
    context: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    result = _text(value, context, maximum=78)
    if not _UINT.fullmatch(result):
        raise ReleaseComposeError(f"{context} must be a canonical base-10 integer string")
    parsed = int(result)
    if parsed < minimum or parsed > maximum:
        raise ReleaseComposeError(
            f"{context} must be between {minimum} and {maximum}"
        )
    return parsed


def _decimal_string(
    value: Any,
    context: str,
    *,
    minimum: float,
    maximum: float,
) -> float:
    result = _text(value, context, maximum=16)
    if not _DECIMAL.fullmatch(result):
        raise ReleaseComposeError(
            f"{context} must be a canonical decimal string with at most 6 fractional digits"
        )
    parsed = float(result)
    if not math.isfinite(parsed) or parsed < minimum or parsed > maximum:
        raise ReleaseComposeError(
            f"{context} must be between {minimum} and {maximum}"
        )
    return parsed


def _validate_qvl_numeric_environment(
    value: Any,
    context: str,
) -> Mapping[str, str]:
    policy = _ordered_record(value, QVL_NUMERIC_ENVIRONMENT_KEYS, context)
    _integer_string(
        policy["QVL_CHALLENGE_CAPACITY"],
        f"{context}.QVL_CHALLENGE_CAPACITY",
        minimum=16,
        maximum=65_536,
    )
    challenge_ttl = _integer_string(
        policy["QVL_CHALLENGE_TTL_SECONDS"],
        f"{context}.QVL_CHALLENGE_TTL_SECONDS",
        minimum=10,
        maximum=120,
    )
    _integer_string(
        policy["QVL_MAX_CONCURRENCY"],
        f"{context}.QVL_MAX_CONCURRENCY",
        minimum=1,
        maximum=16,
    )
    _integer_string(
        policy["QVL_RATE_CAPACITY"],
        f"{context}.QVL_RATE_CAPACITY",
        minimum=1,
        maximum=600,
    )
    _decimal_string(
        policy["QVL_RATE_REFILL_PER_SECOND"],
        f"{context}.QVL_RATE_REFILL_PER_SECOND",
        minimum=float.fromhex("0x0.0000000000001p-1022"),
        maximum=100,
    )
    body_timeout = _decimal_string(
        policy["QVL_REQUEST_BODY_TIMEOUT_SECONDS"],
        f"{context}.QVL_REQUEST_BODY_TIMEOUT_SECONDS",
        minimum=0.5,
        maximum=15,
    )
    verification_timeout = _decimal_string(
        policy["QVL_VERIFICATION_TIMEOUT_SECONDS"],
        f"{context}.QVL_VERIFICATION_TIMEOUT_SECONDS",
        minimum=1,
        maximum=60,
    )
    phase_budget = body_timeout + verification_timeout
    if phase_budget > 25:
        raise ReleaseComposeError(
            f"{context} body plus verification timeouts must be at most 25 seconds"
        )
    if challenge_ttl < math.ceil(phase_budget) + 5:
        raise ReleaseComposeError(
            f"{context}.QVL_CHALLENGE_TTL_SECONDS must cover both phases and headroom"
        )
    return {key: str(policy[key]) for key in QVL_NUMERIC_ENVIRONMENT_KEYS}


def _validate_metering_numeric_environment(
    value: Any,
    context: str,
) -> Mapping[str, str]:
    policy = _ordered_record(value, METERING_NUMERIC_ENVIRONMENT_KEYS, context)
    _integer_string(
        policy["METERING_MAX_CONCURRENCY"],
        f"{context}.METERING_MAX_CONCURRENCY",
        minimum=1,
        maximum=16,
    )
    _integer_string(
        policy["METERING_RATE_CAPACITY"],
        f"{context}.METERING_RATE_CAPACITY",
        minimum=1,
        maximum=600,
    )
    _decimal_string(
        policy["METERING_RATE_REFILL_PER_SECOND"],
        f"{context}.METERING_RATE_REFILL_PER_SECOND",
        minimum=float.fromhex("0x0.0000000000001p-1022"),
        maximum=100,
    )
    _decimal_string(
        policy["METERING_REQUEST_BODY_TIMEOUT_SECONDS"],
        f"{context}.METERING_REQUEST_BODY_TIMEOUT_SECONDS",
        minimum=0.5,
        maximum=15,
    )
    _decimal_string(
        policy["METERING_RPC_TIMEOUT_SECONDS"],
        f"{context}.METERING_RPC_TIMEOUT_SECONDS",
        minimum=1,
        maximum=30,
    )
    return {key: str(policy[key]) for key in METERING_NUMERIC_ENVIRONMENT_KEYS}


def _qvl_numeric_environment_from_intent(
    value: Mapping[str, Any],
    context: str,
) -> Mapping[str, str]:
    source = _ordered_record(
        value,
        (
            "challengeCapacity",
            "challengeTtlSeconds",
            "maxConcurrency",
            "rateCapacity",
            "rateRefillPerSecond",
            "requestBodyTimeoutSeconds",
            "verificationTimeoutSeconds",
        ),
        context,
    )
    environment = {
        "QVL_CHALLENGE_CAPACITY": str(source["challengeCapacity"]),
        "QVL_CHALLENGE_TTL_SECONDS": str(source["challengeTtlSeconds"]),
        "QVL_MAX_CONCURRENCY": str(source["maxConcurrency"]),
        "QVL_RATE_CAPACITY": str(source["rateCapacity"]),
        "QVL_RATE_REFILL_PER_SECOND": str(source["rateRefillPerSecond"]),
        "QVL_REQUEST_BODY_TIMEOUT_SECONDS": str(source["requestBodyTimeoutSeconds"]),
        "QVL_VERIFICATION_TIMEOUT_SECONDS": str(source["verificationTimeoutSeconds"]),
    }
    return _validate_qvl_numeric_environment(environment, context)


def _metering_numeric_environment_from_intent(
    value: Mapping[str, Any],
    context: str,
) -> Mapping[str, str]:
    source = _ordered_record(
        value,
        (
            "maxConcurrency",
            "rateCapacity",
            "rateRefillPerSecond",
            "requestBodyTimeoutSeconds",
            "rpcTimeoutSeconds",
        ),
        context,
    )
    environment = {
        "METERING_MAX_CONCURRENCY": str(source["maxConcurrency"]),
        "METERING_RATE_CAPACITY": str(source["rateCapacity"]),
        "METERING_RATE_REFILL_PER_SECOND": str(source["rateRefillPerSecond"]),
        "METERING_REQUEST_BODY_TIMEOUT_SECONDS": str(source["requestBodyTimeoutSeconds"]),
        "METERING_RPC_TIMEOUT_SECONDS": str(source["rpcTimeoutSeconds"]),
    }
    return _validate_metering_numeric_environment(environment, context)


def _validate_deployment_intent_receipt(
    value: Any,
    *,
    expected_release_sha: str,
    expected_sha256: str,
    expected_reviewer_current_status_epoch: int,
    expected_reviewer_current_status_sha256: str,
) -> Mapping[str, Any]:
    receipt = _record(
        value,
        _DEPLOYMENT_INTENT_RECEIPT_FIELDS,
        "deployment intent validation receipt",
    )
    expected = {
        "schema": DEPLOYMENT_INTENT_RECEIPT_SCHEMA,
        "status": "valid",
        "truthStatus": (
            "intent_shape_and_bounds_validated_not_signer_control_deployment_or_tdx"
        ),
        "deploymentIntentSha256": expected_sha256,
        "releaseSha": expected_release_sha,
        "chainId": 84_532,
        "canonicalContractCount": 7,
        "canonicalCvmCount": 7,
        "dynamicRuntimeAuthorityCount": 0,
        "qvlNumericPolicyCount": 5,
        "reviewerAuthorityCurrentStatusEpoch": (
            expected_reviewer_current_status_epoch
        ),
        "reviewerAuthorityCurrentStatusSha256": (
            expected_reviewer_current_status_sha256
        ),
        "staticContractInputCount": 2,
    }
    if (
        any(type(receipt[name]) is not type(expected[name]) for name in expected)
        or dict(receipt) != expected
    ):
        raise ReleaseComposeError(
            "deployment intent checker returned a mismatched v6 validation receipt"
        )
    return receipt


def validate_deployment_intent(
    value: Any,
    receipt: Any,
    expected_release_sha: str,
    *,
    artifact_bytes: bytes,
) -> ValidatedDeploymentIntent:
    """Consume only the canonical check-intent v6 receipt and numeric policy."""

    expected_release_sha = expected_release_sha.strip().lower()
    if not _SHA40.fullmatch(expected_release_sha):
        raise ReleaseComposeError("expected release SHA must be 40 lowercase hex characters")
    expected_digest = f"sha256:{_sha256(artifact_bytes)}"
    try:
        intent = _record(
            value,
            (
                "deploymentControl",
                "dynamicRuntimeAuthorities",
                "network",
                "numericPolicy",
                "release",
                "schema",
                "scope",
                "staticContractInputs",
                "truthStatus",
            ),
            "deployment intent",
        )
        if intent["schema"] != DEPLOYMENT_INTENT_SCHEMA:
            raise ReleaseComposeError("deployment intent schema mismatch")
        release = _record(
            intent["release"],
            (
                "releaseSha",
                "reviewerAuthorityCurrentStatusEpoch",
                "reviewerAuthorityCurrentStatusSha256",
                "reviewerAuthorityGenesisAcceptanceSha256",
                "toolchain",
            ),
            "deployment intent.release",
        )
        if release["releaseSha"] != expected_release_sha:
            raise ReleaseComposeError(
                "deployment intent release SHA does not match the image manifest"
            )
        reviewer_genesis_acceptance = release[
            "reviewerAuthorityGenesisAcceptanceSha256"
        ]
        if (
            not isinstance(reviewer_genesis_acceptance, str)
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", reviewer_genesis_acceptance
            )
            or reviewer_genesis_acceptance == "sha256:" + ("0" * 64)
        ):
            raise ReleaseComposeError(
                "deployment intent must bind a nonzero signed reviewer-authority genesis acceptance digest"
            )
        reviewer_current_status_epoch = release[
            "reviewerAuthorityCurrentStatusEpoch"
        ]
        if (
            type(reviewer_current_status_epoch) is not int
            or reviewer_current_status_epoch < 1
            or reviewer_current_status_epoch > 4_294_967_295
        ):
            raise ReleaseComposeError(
                "deployment intent must bind a valid reviewer-authority current-status epoch"
            )
        reviewer_current_status_sha256 = release[
            "reviewerAuthorityCurrentStatusSha256"
        ]
        if (
            not isinstance(reviewer_current_status_sha256, str)
            or not _DIGEST.fullmatch(reviewer_current_status_sha256)
            or reviewer_current_status_sha256 == "sha256:" + ("0" * 64)
        ):
            raise ReleaseComposeError(
                "deployment intent must bind a nonzero reviewer-authority current-status digest"
            )
        _validate_deployment_intent_receipt(
            receipt,
            expected_release_sha=expected_release_sha,
            expected_sha256=expected_digest,
            expected_reviewer_current_status_epoch=reviewer_current_status_epoch,
            expected_reviewer_current_status_sha256=(
                reviewer_current_status_sha256
            ),
        )
        toolchain = _record(
            release["toolchain"],
            ("foundry", "solidity"),
            "deployment intent.release.toolchain",
        )
        if toolchain != DEPLOYMENT_TOOLCHAIN_AUTHORITY:
            raise ReleaseComposeError(
                "deployment intent release toolchain does not match the supported exact build authority"
            )
        numeric_policy = _ordered_record(
            intent["numericPolicy"],
            ("contract", "metering", "qvl"),
            "deployment intent.numericPolicy",
        )
        qvl_policy = _ordered_record(
            numeric_policy["qvl"],
            (
                "anchorWriter",
                "arena",
                "computeMetering",
                "computeWorkload",
                "diligence",
            ),
            "deployment intent.numericPolicy.qvl",
        )
        qvl_environments = {
            name: _qvl_numeric_environment_from_intent(
                qvl_policy[name],
                f"deployment intent.numericPolicy.qvl.{name}",
            )
            for name in (
                "anchorWriter",
                "arena",
                "computeMetering",
                "computeWorkload",
                "diligence",
            )
        }
        metering_environment = _metering_numeric_environment_from_intent(
            numeric_policy["metering"],
            "deployment intent.numericPolicy.metering",
        )
    except (KeyError, TypeError) as exc:
        raise ReleaseComposeError("deployment intent numeric policy is malformed") from exc
    return ValidatedDeploymentIntent(
        deployment_intent_sha256=expected_digest,
        release_sha=expected_release_sha,
        qvl_numeric_environment=qvl_environments,
        metering_numeric_environment=metering_environment,
        raw=intent,
    )


def _https_url(value: Any, context: str, host: str, exact_path: str) -> str:
    result = _text(value, context, maximum=1_024)
    parsed = urlparse(result)
    if (
        parsed.scheme != "https"
        or parsed.netloc != host
        or parsed.path != exact_path
        or parsed.username
        or parsed.password
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ReleaseComposeError(f"{context} is outside the required origin")
    return result


def _validate_attestation(value: Any, context: str, predicate: str) -> None:
    parsed = _record(value, ("predicate_type", "id", "url"), context)
    if _text(parsed["predicate_type"], f"{context}.predicate_type") != predicate:
        raise ReleaseComposeError(f"{context} predicate type mismatch")
    identifier = _text(parsed["id"], f"{context}.id", maximum=128)
    if not re.fullmatch(r"[1-9][0-9]*", identifier):
        raise ReleaseComposeError(f"{context}.id must be a positive integer string")
    _https_url(
        parsed["url"],
        f"{context}.url",
        "github.com",
        f"/therealwiki/dnai-wikigen/attestations/{identifier}",
    )


def validate_image_release(value: Any, expected_release_sha: str) -> ValidatedRelease:
    """Validate the aggregate CI image manifest without accepting extra fields."""
    expected_release_sha = expected_release_sha.strip().lower()
    if not _SHA40.fullmatch(expected_release_sha):
        raise ReleaseComposeError("expected release SHA must be 40 lowercase hex characters")

    parsed = _record(
        value,
        (
            "schema",
            "release_sha",
            "source_ref",
            "generated_at",
            "source_repository",
            "signer_workflow",
            "workflow_run_id",
            "workflow_run_url",
            "platform",
            "images",
        ),
        "image release",
    )
    if parsed["schema"] != SCHEMA:
        raise ReleaseComposeError("image release schema mismatch")
    release_sha = _text(parsed["release_sha"], "release_sha").lower()
    if release_sha != parsed["release_sha"] or release_sha != expected_release_sha:
        raise ReleaseComposeError("image release SHA does not match the reviewed release SHA")
    source_ref = _text(parsed["source_ref"], "source_ref")
    if not _SOURCE_REF.fullmatch(source_ref):
        raise ReleaseComposeError("source_ref must be refs/heads/main or a v* release tag")
    generated_at = _text(parsed["generated_at"], "generated_at", maximum=64)
    try:
        generated = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseComposeError("generated_at must be an RFC3339 timestamp") from exc
    if not generated_at.endswith("Z") or generated.tzinfo is None or generated.isoformat(
        timespec="milliseconds"
    ).replace(
        "+00:00", "Z"
    ) != generated_at:
        raise ReleaseComposeError("generated_at must be a canonical UTC timestamp")
    if parsed["source_repository"] != SOURCE_REPOSITORY:
        raise ReleaseComposeError("source repository mismatch")
    if parsed["signer_workflow"] != SIGNER_WORKFLOW:
        raise ReleaseComposeError("signer workflow mismatch")
    workflow_run_id = _text(parsed["workflow_run_id"], "workflow_run_id", maximum=32)
    if not re.fullmatch(r"[1-9][0-9]*", workflow_run_id):
        raise ReleaseComposeError("workflow_run_id must be a positive integer string")
    _https_url(
        parsed["workflow_run_url"],
        "workflow_run_url",
        "github.com",
        f"/therealwiki/dnai-wikigen/actions/runs/{workflow_run_id}",
    )
    if parsed["platform"] != PLATFORM:
        raise ReleaseComposeError("aggregate release platform must be linux/amd64")

    raw_images = parsed["images"]
    if not isinstance(raw_images, list) or len(raw_images) != len(IMAGE_NAMES):
        raise ReleaseComposeError("image release must contain exactly five images")
    if [item.get("name") if isinstance(item, dict) else None for item in raw_images] != list(IMAGE_NAMES):
        raise ReleaseComposeError("image release subjects are missing, duplicated, or out of canonical order")

    images: list[ValidatedImage] = []
    for index, raw_image in enumerate(raw_images):
        context = f"images[{index}]"
        image = _record(
            raw_image,
            (
                "name",
                "repository",
                "digest",
                "image",
                "platform",
                "sbom_artifact",
                "provenance_subject",
                "attestations",
                "verification",
            ),
            context,
        )
        name = IMAGE_NAMES[index]
        repository = f"{IMAGE_PREFIX}{name}"
        if image["name"] != name or image["repository"] != repository:
            raise ReleaseComposeError(f"{context} operator-owned repository mismatch")
        digest = _text(image["digest"], f"{context}.digest").lower()
        if digest != image["digest"] or not _DIGEST.fullmatch(digest):
            raise ReleaseComposeError(f"{context}.digest must be a lowercase immutable sha256 digest")
        exact_image = f"{repository}@{digest}"
        if image["image"] != exact_image:
            raise ReleaseComposeError(f"{context}.image does not equal repository@digest")
        if image["platform"] != PLATFORM:
            raise ReleaseComposeError(f"{context}.platform must be linux/amd64")

        sbom = _record(image["sbom_artifact"], ("filename", "sha256"), f"{context}.sbom_artifact")
        filename = _text(sbom["filename"], f"{context}.sbom_artifact.filename", maximum=192)
        if not _SAFE_FILENAME.fullmatch(filename) or filename != f"{name}.spdx.json":
            raise ReleaseComposeError(f"{context} SBOM filename must be a safe SPDX JSON basename")
        if not _SHA256.fullmatch(_text(sbom["sha256"], f"{context}.sbom_artifact.sha256")):
            raise ReleaseComposeError(f"{context} SBOM sha256 is malformed")

        subject = _record(
            image["provenance_subject"],
            ("name", "digest"),
            f"{context}.provenance_subject",
        )
        if subject["name"] != repository or subject["digest"] != digest:
            raise ReleaseComposeError(f"{context} provenance subject does not bind repository and digest")

        attestations = _record(
            image["attestations"],
            ("provenance", "sbom"),
            f"{context}.attestations",
        )
        _validate_attestation(
            attestations["provenance"],
            f"{context}.attestations.provenance",
            "https://slsa.dev/provenance/v1",
        )
        _validate_attestation(
            attestations["sbom"],
            f"{context}.attestations.sbom",
            "https://spdx.dev/Document/v2.3",
        )

        verification = _record(
            image["verification"],
            (
                "repo",
                "signer_workflow",
                "source_digest",
                "source_ref",
                "provenance_attestation",
                "sbom_attestation",
            ),
            f"{context}.verification",
        )
        expected_verification = {
            "repo": SOURCE_REPOSITORY,
            "signer_workflow": SIGNER_WORKFLOW,
            "source_digest": release_sha,
            "source_ref": source_ref,
            "provenance_attestation": "verified",
            "sbom_attestation": "verified",
        }
        if dict(verification) != expected_verification:
            raise ReleaseComposeError(f"{context} verification policy mismatch")

        images.append(
            ValidatedImage(name=name, repository=repository, digest=digest, image=exact_image)
        )

    return ValidatedRelease(
        release_sha=release_sha,
        source_ref=source_ref,
        generated_at=generated_at,
        images=tuple(images),
        raw=parsed,
    )


class _ComposeLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.Node, deep: bool = False) -> dict[Any, Any]:
        if not isinstance(node, yaml.MappingNode):
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "expected a mapping node",
                node.start_mark,
            )
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def _construct_reset(loader: _ComposeLoader, node: yaml.Node) -> Any:
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_constructor("!reset", _construct_reset)
_ComposeLoader.add_constructor("!override", _construct_reset)


def _load_yaml(path: Path, *, overlay: bool = False) -> dict[str, Any]:
    try:
        value = yaml.load(
            path.read_text(encoding="utf-8"),
            Loader=_ComposeLoader,
        )
    except (OSError, yaml.YAMLError) as exc:
        raise ReleaseComposeError(f"could not load compose template {path.name}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("services"), dict):
        raise ReleaseComposeError(f"compose template {path.name} has no services")
    return value


def _release_metadata(
    release: ValidatedRelease,
    domain: str,
) -> dict[str, Any]:
    return {
        "schema": TOPOLOGY_SCHEMA,
        "release_sha": release.release_sha,
        "source_ref": release.source_ref,
        "platform": PLATFORM,
        "trust_domain": domain,
        "deployment_status": "rendered_not_deployed",
    }


def _runtime_policy_metadata(
    numeric_environment: Mapping[str, str],
) -> dict[str, Any]:
    return {
        "schema": PUBLIC_RUNTIME_POLICY_SCHEMA,
        "source_schema": DEPLOYMENT_INTENT_SCHEMA,
        "numeric_environment": dict(numeric_environment),
    }


def _phase_gate_metadata(profile: str) -> dict[str, Any]:
    """Describe the only reviewed transition out of an empty bootstrap.

    Compose interpolates the whole model before it selects profiles.  This
    metadata is therefore deliberately explicit that the encrypted policy
    environment must already be complete before a caller invokes Compose with
    the listed `COMPOSE_PROFILES` value.  A profile is not an interpolation
    bypass.
    """

    return {
        "schema": PHASE_GATE_SCHEMA,
        "initial_phase": "bootstrap_provision",
        "initial_services": [],
        "initial_compose_profiles": [],
        "post_measurement_phase": "post_measurement_policy_bootstrap",
        "activation_environment": {
            "key": "COMPOSE_PROFILES",
            "exact_value": profile,
        },
        "interpolation_policy": (
            "late_values_use_exact_empty_default_until_nonempty_validated_profile_activation"
        ),
    }


_STRICT_INTERPOLATION = re.compile(
    r"^\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^${}\r\n]{1,160}\}$"
)


def _render_late_environment_pass_through(
    compose: Mapping[str, Any],
    expected_keys: tuple[str, ...],
    *,
    domain: str,
) -> None:
    """Replace reviewed late `${KEY:?…}` uses with exact `${KEY:-}`.

    The replacement is keyed by the referenced host-environment name rather
    than the container variable name, preserving intentional aliases such as
    `TINKER_QVL_AUTH_TOKEN <- TINKER_DILIGENCE_QVL_AUTH_TOKEN`.
    """

    expected = set(expected_keys)
    observed: set[str] = set()
    services = compose.get("services")
    if not isinstance(services, dict):
        raise ReleaseComposeError(f"{domain} services are unavailable")
    def replace(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if not isinstance(value, str):
            return value
        empty_match = re.fullmatch(
            r"\$\{([A-Za-z_][A-Za-z0-9_]*):-\}",
            value,
        )
        if empty_match is not None and empty_match.group(1) in expected:
            observed.add(empty_match.group(1))
            return value
        match = _STRICT_INTERPOLATION.fullmatch(value)
        if match is None or match.group(1) not in expected:
            return value
        referenced_name = match.group(1)
        observed.add(referenced_name)
        return f"${{{referenced_name}:-}}"

    for service_name, service in tuple(services.items()):
        if not isinstance(service, dict):
            raise ReleaseComposeError(f"{domain}.{service_name} must be an object")
        if not isinstance(service.get("environment", {}), dict):
            raise ReleaseComposeError(
                f"{domain}.{service_name} environment must use mapping form"
            )
        services[service_name] = replace(service)
    if observed != expected:
        missing = ", ".join(sorted(expected - observed))
        extra = ", ".join(sorted(observed - expected))
        detail = f"missing {missing}" if missing else f"unexpected {extra}"
        raise ReleaseComposeError(
            f"{domain} late environment pass-through mismatch: {detail}"
        )


def _render_provisioning_result_requirements(
    compose: Mapping[str, Any],
    expected_keys: tuple[str, ...],
) -> None:
    """Make every prepare-derived public value strict before first commit."""

    expected = set(expected_keys)
    observed: set[str] = set()
    strict = re.compile(
        r"^\$\{([A-Za-z_][A-Za-z0-9_]*):\?[^${}\r\n]{1,160}\}$"
    )
    empty = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*):-\}$")

    def replace(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: replace(item) for key, item in value.items()}
        if isinstance(value, list):
            return [replace(item) for item in value]
        if not isinstance(value, str):
            return value
        match = strict.fullmatch(value)
        if match is not None and match.group(1) in expected:
            observed.add(match.group(1))
            return value
        match = empty.fullmatch(value)
        if match is not None and match.group(1) in expected:
            key = match.group(1)
            observed.add(key)
            return f"${{{key}:?prepare-derived value required before CVM commit}}"
        return value

    services = compose.get("services")
    if not isinstance(services, dict):
        raise ReleaseComposeError("main services are unavailable")
    for name, service in tuple(services.items()):
        services[name] = replace(service)
    if observed != expected:
        raise ReleaseComposeError(
            "main provisioning-result interpolation does not cover the exact set"
        )


def _harden_python_service(service: dict[str, Any], *, pids_limit: int = 256) -> None:
    service["init"] = True
    service["read_only"] = True
    service["cap_drop"] = ["ALL"]
    service["security_opt"] = ["no-new-privileges:true"]
    service["pids_limit"] = pids_limit
    service.setdefault("tmpfs", ["/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777"])
    service.setdefault("ulimits", {})["core"] = 0


def _make_dstack_socket_read_only(service: dict[str, Any]) -> None:
    volumes = service.get("volumes")
    if not isinstance(volumes, list):
        return
    service["volumes"] = [
        f"{volume}:ro"
        if volume == "/var/run/dstack.sock:/var/run/dstack.sock"
        else volume
        for volume in volumes
    ]


def _render_main(
    release: ValidatedRelease,
    project_root: Path,
) -> dict[str, Any]:
    main = _load_yaml(project_root / "docker-compose.all.phala.yaml")
    overlay = _load_yaml(project_root / "docker-compose.all.dstack.yaml", overlay=True)
    main["name"] = "dnai-main-runtime"
    main["x-dnai-release"] = _release_metadata(release, "main_runtime_cvm")
    services = main["services"]
    overlay_services = overlay["services"]

    # Preserve the fail-closed production values already present on the three
    # historical services while adding any newly introduced runtime settings.
    for service_name in ("oracle", "delegate"):
        existing_env = services[service_name].setdefault("environment", {})
        for key, value in overlay_services[service_name].get("environment", {}).items():
            existing_env.setdefault(key, value)

    # The initial delegate process has no release-ceremony authority.  Omit
    # these settings completely so its compiled empty defaults reject any
    # authority-dependent operation. Real values appear only on later profile
    # services after measurement and reviewed environment injection. The
    # descriptor's exact `${KEY:-}` form is an inert interpolation placeholder,
    # never a substitute authority value.
    delegate_environment = services["delegate"].setdefault("environment", {})
    for key in BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS:
        delegate_environment.pop(key, None)

    for service_name in MAIN_SERVICES[3:]:
        if service_name not in overlay_services:
            raise ReleaseComposeError(f"dstack overlay is missing {service_name}")
        services[service_name] = deepcopy(overlay_services[service_name])

    images = release.by_name
    service_image = {
        "neko": images["neko-chrome"].image,
        "oracle": images["tee-email-oracle"].image,
        **{name: images["tinker-delegate"].image for name in MAIN_SERVICES[2:]},
    }
    for service_name in MAIN_SERVICES:
        service = services[service_name]
        service.pop("build", None)
        service["image"] = service_image[service_name]
        service["platform"] = PLATFORM
        _make_dstack_socket_read_only(service)

    services["neko"]["init"] = True
    services["neko"]["pids_limit"] = 512
    # Neko/Chrome currently requires the narrowly reviewed SYS_ADMIN exception,
    # but all ambient capabilities are still dropped and privilege escalation is
    # disabled.  No other release service may add a capability.
    services["neko"]["cap_drop"] = ["ALL"]
    services["neko"]["cap_add"] = ["SYS_ADMIN"]
    services["neko"]["security_opt"] = ["no-new-privileges:true"]
    _harden_python_service(services["oracle"])
    _harden_python_service(services["delegate"], pids_limit=512)
    for service_name in MAIN_SERVICES[3:]:
        _harden_python_service(services[service_name])

    # The production lane is one exact three-policy deterministic registry. It
    # never invokes the retained research-only SFT/provider implementation.
    services["delegate"].setdefault("environment", {})[
        "TINKER_EVALUATOR_MODE"
    ] = "deterministic"

    # Enable only the capability projector, not unconditional liveness.  The
    # delegate still reports the Arena worker as modeled unless the shared
    # heartbeat is present, fresh, HMAC-authenticated with a dstack-derived
    # key, and exactly matches every release binding.  The worker's QVL client
    # receives code-owned aliases of the already reviewed release lineage.
    arena_worker_environment = services["arena-worker"].setdefault(
        "environment", {}
    )
    arena_worker_environment.update(ARENA_WORKER_CODE_OWNED_ENVIRONMENT)
    delegate_environment.update(
        {
            "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": "true",
            "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
                ARENA_WORKER_CODE_OWNED_ENVIRONMENT[
                    "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256"
                ]
            ),
        }
    )

    services["compute-execution-worker"]["x-dnai-capability-status"] = (
        "disabled_provider_contract_unavailable"
    )
    services["compute-execution-worker"]["profiles"] = ["compute-execution"]
    # Arena cannot start until its independently reviewed QVL policy and
    # provisioning bundle exist. Keep both the networkless initializer and the
    # worker behind one explicit activation profile so the first main-CVM
    # launch can establish identity without pretending those downstream facts
    # already exist.
    services["arena-policy-init"]["profiles"] = ["arena-runtime"]
    services["arena-worker"]["profiles"] = ["arena-runtime"]
    services["anchor-writer-evidence"]["profiles"] = ["anchor-writer-ceremony"]
    services["deal-runtime"]["profiles"] = ["deal-settlement"]
    services["deal-runtime"]["x-dnai-capability-status"] = (
        "release_pinned_deterministic_evaluator"
    )

    # The one-shot anchor writer needs public HTTPS egress only; it must not
    # share the main service network while holding its QVL bearer.  Deal
    # settlement gets a private, internal-only link to delegate plus a separate
    # public egress network for RPC/QVL traffic.  No other service receives
    # either bearer-bearing egress network.
    networks = main.setdefault("networks", {})
    networks["writer-egress"] = {"driver": "bridge"}
    networks["deal-control"] = {"driver": "bridge", "internal": True}
    networks["deal-egress"] = {"driver": "bridge"}
    services["anchor-writer-evidence"]["networks"] = ["writer-egress"]
    services["deal-runtime"]["networks"] = ["deal-control", "deal-egress"]
    delegate_networks = services["delegate"].setdefault("networks", {})
    if not isinstance(delegate_networks, dict):
        raise ReleaseComposeError("delegate networks must use the reviewed mapping form")
    delegate_networks.setdefault("deal-control", {})

    # These services are intentionally internal to the CVM.  Only the bounded
    # delegate API is exposed by the main descriptor.
    services["neko"].pop("ports", None)
    services["oracle"].pop("ports", None)
    _render_provisioning_result_requirements(
        main,
        MAIN_PROVISIONING_RESULT_ENVIRONMENT_KEYS,
    )
    _render_late_environment_pass_through(
        main,
        MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS,
        domain="main",
    )
    return main


def _render_independent(
    release: ValidatedRelease,
    template: Path,
    *,
    image_name: str,
    compose_name: str,
    trust_domain: str,
    runtime_service_name: str,
    runtime_profile: str,
    numeric_environment: Mapping[str, str],
) -> dict[str, Any]:
    compose = _load_yaml(template)
    compose["name"] = compose_name
    compose["x-dnai-release"] = _release_metadata(release, trust_domain)
    compose["x-dnai-runtime-policy"] = _runtime_policy_metadata(
        numeric_environment,
    )
    compose["x-dnai-phase-gate"] = _phase_gate_metadata(runtime_profile)
    exact_image = release.by_name[image_name].image
    for service in compose["services"].values():
        service.pop("build", None)
        service["image"] = exact_image
        service["platform"] = PLATFORM
        service["profiles"] = [runtime_profile]
    for extension in ("x-qvl-image", "x-metering-image"):
        if extension in compose:
            compose[extension] = exact_image
    service = compose["services"].get(runtime_service_name)
    if not isinstance(service, dict) or not isinstance(service.get("environment"), dict):
        raise ReleaseComposeError(
            f"{trust_domain} runtime service has no reviewed environment mapping"
        )
    service["environment"].update(numeric_environment)
    _render_late_environment_pass_through(
        compose,
        (
            QVL_POST_MEASUREMENT_ENVIRONMENT_KEYS
            if runtime_profile == QVL_RUNTIME_PROFILE
            else METERING_POST_MEASUREMENT_ENVIRONMENT_KEYS
        ),
        domain=trust_domain,
    )
    return compose


def _environment(service: Mapping[str, Any]) -> Mapping[str, Any]:
    value = service.get("environment", {})
    return value if isinstance(value, dict) else {}


def _validate_production_oracle_environment(
    oracle_environment: Mapping[str, Any],
) -> None:
    """Reject any drift in a release-critical oracle production setting."""

    if any(
        oracle_environment.get(name) != value
        for name, value in PRODUCTION_ORACLE_POLICY.items()
    ):
        raise ReleaseComposeError(
            "production oracle must require the exact on-chain and sealed-state policy"
        )


_SECRET_NAME = re.compile(
    r"(?:^|_)(?:PASSWORD(?:_ADMIN)?|TOKEN|API_KEY|SECRET|PRIVATE_KEY|"
    r"SIGNING_KEY|INTEGRITY_KEY|AUTH_KEY_B64|AUTH_TAG|CRED(?:ENTIAL)?_STORE_KEY|"
    r"RPC_URL)(?:$|_)",
)
_PLAIN_SECRET_PLACEHOLDER = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}$")
_EMPTY_SECRET_DEFAULT = re.compile(r"^\$\{[A-Za-z_][A-Za-z0-9_]*:-\}$")
_REQUIRED_SECRET_PLACEHOLDER = re.compile(
    r"^\$\{[A-Za-z_][A-Za-z0-9_]*(?::\?|\?)[^${}\r\n]{1,160}\}$"
)


def _safe_secret_value(value: Any) -> bool:
    if value == "":
        return True
    if not isinstance(value, str):
        return False
    return bool(
        _PLAIN_SECRET_PLACEHOLDER.fullmatch(value)
        or _EMPTY_SECRET_DEFAULT.fullmatch(value)
        or _REQUIRED_SECRET_PLACEHOLDER.fullmatch(value)
    )


def _validate_secret_placeholders(domain: str, services: Mapping[str, Any]) -> None:
    for service_name, service in services.items():
        for name, value in _environment(service).items():
            normalized_name = str(name)
            if normalized_name.endswith(
                ("_KEY_PATH", "_STORE_PATH", "_TTL_SECONDS", "_TIMEOUT_SECONDS")
            ):
                continue
            if not _SECRET_NAME.search(normalized_name):
                continue
            if _safe_secret_value(value):
                continue
            raise ReleaseComposeError(
                f"{domain}.{service_name}.{name} embeds a secret-shaped literal"
            )


def _validate_late_environment_pass_through(
    services: Mapping[str, Any],
    expected_keys: tuple[str, ...],
    *,
    domain: str,
) -> None:
    expected = set(expected_keys)
    observed: set[str] = set()
    interpolation = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)([^}]*)\}$")
    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                visit(item, f"{path}.{key}")
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")
            return
        if not isinstance(value, str):
            return
        match = interpolation.fullmatch(value)
        if match is None or match.group(1) not in expected:
            return
        referenced_name = match.group(1)
        if value != f"${{{referenced_name}:-}}":
            raise ReleaseComposeError(
                f"{path} must use exact post-measurement "
                f"${{{referenced_name}:-}} interpolation"
            )
        observed.add(referenced_name)

    for service_name, service in services.items():
        visit(service, f"{domain}.{service_name}")
    if observed != expected:
        raise ReleaseComposeError(
            f"{domain} does not expose every exact post-measurement key"
        )


def _network_names(service: Mapping[str, Any]) -> set[str]:
    networks = service.get("networks", [])
    if isinstance(networks, list) and all(isinstance(value, str) for value in networks):
        return set(networks)
    if isinstance(networks, dict):
        return set(networks)
    raise ReleaseComposeError("service networks must use a list or mapping")


def _validate_mounts(domain: str, service_name: str, service: Mapping[str, Any]) -> None:
    volumes = service.get("volumes", [])
    if not isinstance(volumes, list):
        raise ReleaseComposeError(f"{domain}.{service_name} volumes must be a list")
    for mount in volumes:
        if isinstance(mount, str):
            source = mount.split(":", 1)[0]
            if source.startswith("/") and mount != (
                "/var/run/dstack.sock:/var/run/dstack.sock:ro"
            ):
                raise ReleaseComposeError(
                    f"{domain}.{service_name} has an unreviewed or writable host bind"
                )
            continue
        if not isinstance(mount, dict):
            raise ReleaseComposeError(f"{domain}.{service_name} has an invalid mount")
        if mount.get("type") == "bind" and mount != {
            "type": "bind",
            "source": "/var/run/dstack.sock",
            "target": "/var/run/dstack.sock",
            "read_only": True,
        }:
            raise ReleaseComposeError(
                f"{domain}.{service_name} has an unreviewed or writable host bind"
            )
        if mount.get("type") not in {"bind", "volume"}:
            raise ReleaseComposeError(f"{domain}.{service_name} has an unsupported mount type")


def _validate_rendered(
    main: Mapping[str, Any],
    qvls: Mapping[str, Mapping[str, Any]],
    metering: Mapping[str, Any],
    release: ValidatedRelease,
    policy: ValidatedDeploymentIntent,
) -> None:
    if main.get("name") != "dnai-main-runtime" or main.get("x-dnai-release") != (
        _release_metadata(release, "main_runtime_cvm")
    ):
        raise ReleaseComposeError("main release metadata drift")
    expected_qvl_names = {domain: name for domain, name, _ in QVL_DOMAINS}
    for domain, qvl in qvls.items():
        if qvl.get("name") != expected_qvl_names.get(domain) or qvl.get(
            "x-dnai-release"
        ) != _release_metadata(release, domain):
            raise ReleaseComposeError(f"{domain} release metadata drift")
        projected_domain = QVL_INTENT_DOMAINS[domain]
        expected_runtime_policy = _runtime_policy_metadata(
            policy.qvl_numeric_environment[projected_domain],
        )
        if qvl.get("x-dnai-runtime-policy") != expected_runtime_policy:
            raise ReleaseComposeError(f"{domain} public runtime-policy metadata drift")
        if qvl.get("x-dnai-phase-gate") != _phase_gate_metadata(QVL_RUNTIME_PROFILE):
            raise ReleaseComposeError(f"{domain} compose phase gate drift")
    if metering.get("name") != "dnai-independent-compute-metering" or metering.get(
        "x-dnai-release"
    ) != _release_metadata(release, "independent_metering_cvm"):
        raise ReleaseComposeError("metering release metadata drift")
    if metering.get("x-dnai-runtime-policy") != _runtime_policy_metadata(
        policy.metering_numeric_environment,
    ):
        raise ReleaseComposeError("metering public runtime-policy metadata drift")
    if metering.get("x-dnai-phase-gate") != _phase_gate_metadata(
        METERING_RUNTIME_PROFILE,
    ):
        raise ReleaseComposeError("metering compose phase gate drift")

    expected_sets = [
        ("main", main, set(MAIN_SERVICES)),
        ("metering", metering, set(METERING_SERVICES)),
    ]
    expected_sets.extend(
        (domain, qvls[domain], set(QVL_SERVICES)) for domain, _, _ in QVL_DOMAINS
    )
    for domain, compose, expected_services in expected_sets:
        services = compose.get("services")
        if not isinstance(services, dict) or set(services) != expected_services:
            raise ReleaseComposeError(f"{domain} compose service topology drift")
        for name, service in services.items():
            if "build" in service:
                raise ReleaseComposeError(f"{domain}.{name} still uses a local build context")
            if service.get("platform") != PLATFORM:
                raise ReleaseComposeError(f"{domain}.{name} does not pin linux/amd64")
            if service.get("privileged") is True:
                raise ReleaseComposeError(f"{domain}.{name} is privileged")
            if service.get("network_mode") in {"host", "service", "container"}:
                raise ReleaseComposeError(f"{domain}.{name} crosses a network namespace")
            if any(service.get(key) == "host" for key in ("pid", "ipc", "uts", "userns_mode")):
                raise ReleaseComposeError(f"{domain}.{name} crosses a host namespace")
            if "devices" in service or "device_cgroup_rules" in service:
                raise ReleaseComposeError(f"{domain}.{name} receives an unreviewed device")
            expected_cap_add: list[str] = []
            if domain == "main" and name == "neko":
                expected_cap_add = ["SYS_ADMIN"]
            elif domain == "metering" and name == "state-init":
                expected_cap_add = ["CHOWN"]
            if service.get("cap_add", []) != expected_cap_add:
                raise ReleaseComposeError(f"{domain}.{name} capability allowlist drift")
            if service.get("cap_drop") != ["ALL"]:
                raise ReleaseComposeError(f"{domain}.{name} does not drop ambient capabilities")
            if service.get("security_opt") != ["no-new-privileges:true"]:
                raise ReleaseComposeError(f"{domain}.{name} permits privilege escalation")
            if not (domain == "main" and name == "neko") and service.get("read_only") is not True:
                raise ReleaseComposeError(f"{domain}.{name} root filesystem is writable")
            _validate_mounts(domain, name, service)
            if domain in qvls and service.get("profiles") != [QVL_RUNTIME_PROFILE]:
                raise ReleaseComposeError(
                    f"{domain}.{name} must remain absent until qvl-runtime activation"
                )
            if domain == "metering" and service.get("profiles") != [
                METERING_RUNTIME_PROFILE
            ]:
                raise ReleaseComposeError(
                    f"{domain}.{name} must remain absent until metering-runtime activation"
                )
        _validate_secret_placeholders(domain, services)
        if domain == "main":
            _validate_late_environment_pass_through(
                services,
                MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS,
                domain=domain,
            )
        elif domain in qvls:
            _validate_late_environment_pass_through(
                services,
                QVL_POST_MEASUREMENT_ENVIRONMENT_KEYS,
                domain=domain,
            )
        else:
            _validate_late_environment_pass_through(
                services,
                METERING_POST_MEASUREMENT_ENVIRONMENT_KEYS,
                domain=domain,
            )

    by_name = release.by_name
    main_images = {service["image"] for service in main["services"].values()}
    if main_images != {
        by_name["tinker-delegate"].image,
        by_name["tee-email-oracle"].image,
        by_name["neko-chrome"].image,
    }:
        raise ReleaseComposeError("main CVM image set crosses an independent trust boundary")
    for domain, qvl in qvls.items():
        if {service["image"] for service in qvl["services"].values()} != {
            by_name["attestation-qvl"].image
        }:
            raise ReleaseComposeError(f"{domain} does not contain exactly the QVL image")
        qvl_environment = _environment(qvl["services"]["qvl"])
        required_qvl_runtime = policy.qvl_numeric_environment[
            QVL_INTENT_DOMAINS[domain]
        ]
        if any(qvl_environment.get(name) != value for name, value in required_qvl_runtime.items()):
            raise ReleaseComposeError(
                f"{domain} is missing the exact bounded freshness/timeout policy"
            )
    if {service["image"] for service in metering["services"].values()} != {
        by_name["compute-metering"].image
    }:
        raise ReleaseComposeError("metering CVM does not contain exactly the metering image")
    metering_environment = _environment(metering["services"]["metering"])
    required_metering_qvl = {
        "METERING_QVL_URL": "${METERING_QVL_URL:-}",
        "METERING_QVL_AUTH_TOKEN": "${METERING_QVL_AUTH_TOKEN:-}",
        "METERING_QVL_VERIFIER_ADDRESS": "${METERING_QVL_VERIFIER_ADDRESS:-}",
        "METERING_QVL_RELEASE_POLICY_HASH": "${METERING_QVL_RELEASE_POLICY_HASH:-}",
        "METERING_CVM_ID": (
            "${METERING_CVM_ID:?pin the canonical independent metering CVM ID}"
        ),
        "METERING_DEPLOYMENT_INTENT_SHA256": (
            "${METERING_DEPLOYMENT_INTENT_SHA256:?pin the signed seven-CVM deployment intent}"
        ),
        "METERING_RELEASE_AUTHORITY_SHA256": (
            "${METERING_RELEASE_AUTHORITY_SHA256:-}"
        ),
        "METERING_CEREMONY_NONCE": (
            "${METERING_CEREMONY_NONCE:?pin the release ceremony nonce}"
        ),
        "METERING_QVL_MEASUREMENT_POLICY_SHA256": (
            "${METERING_QVL_MEASUREMENT_POLICY_SHA256:?pin the linked compute-metering QVL measurement policy}"
        ),
    }
    if any(
        metering_environment.get(name) != value
        for name, value in required_metering_qvl.items()
    ):
        raise ReleaseComposeError(
            "metering CVM is missing the exact challenge-first QVL policy"
        )
    if any(
        metering_environment.get(name) != value
        for name, value in policy.metering_numeric_environment.items()
    ):
        raise ReleaseComposeError(
            "metering CVM is missing the exact public numeric runtime policy"
        )

    main_services = main["services"]
    delegate_environment = _environment(main_services["delegate"])
    leaked_bootstrap_authorities = sorted(
        set(BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS).intersection(delegate_environment)
    )
    if leaked_bootstrap_authorities:
        raise ReleaseComposeError(
            "bootstrap delegate contains deferred authority settings: "
            + ", ".join(leaked_bootstrap_authorities)
        )
    for key in BOOTSTRAP_DELEGATE_FAIL_CLOSED_KEYS:
        for service_name, service in main_services.items():
            if service_name == "delegate":
                continue
            environment = _environment(service)
            if key not in environment:
                continue
            value = environment[key]
            valid = (
                value == f"${{{key}:-}}"
                if key in MAIN_POST_MEASUREMENT_ENVIRONMENT_KEYS
                else isinstance(value, str) and value.startswith(f"${{{key}:?")
            )
            if not valid:
                raise ReleaseComposeError(
                    f"{service_name}.{key} has invalid phase-time interpolation"
                )
    oracle_environment = _environment(main_services["oracle"])
    _validate_production_oracle_environment(oracle_environment)
    oracle_policy_holders = [
        name
        for name, service in main_services.items()
        if any(str(key).startswith("ORACLE_AUTH_") for key in _environment(service))
    ]
    if oracle_policy_holders != ["oracle"]:
        raise ReleaseComposeError("EmailOracleAuth policy inputs escaped the oracle service")
    if main_services["arena-policy-init"].get("network_mode") != "none":
        raise ReleaseComposeError("Arena policy initializer must have no network")
    diligence_initializer = main_services["diligence-policy-init"]
    if diligence_initializer.get("network_mode") != "none":
        raise ReleaseComposeError("Diligence policy initializer must have no network")
    if diligence_initializer.get("profiles"):
        raise ReleaseComposeError("Diligence policy initializer must run before delegate startup")
    if diligence_initializer.get("command") != [
        "tinker-diligence-evaluator-provision"
    ]:
        raise ReleaseComposeError("Diligence policy initializer entrypoint drifted")
    required_diligence_initializer_environment = {
        "TINKER_DILIGENCE_EVALUATOR_RELEASE_B64": (
            "${TINKER_DILIGENCE_EVALUATOR_RELEASE_B64:?Canonical Diligence evaluator release manifest base64url required}"
        ),
        "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH": (
            "${TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH:?Reviewed Diligence evaluator release manifest path required}"
        ),
        "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256": (
            "${TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256:?Reviewed Diligence evaluator release manifest SHA-256 required}"
        ),
        "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT": (
            "${TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT:?Reviewed Diligence evaluator policy-set root required}"
        ),
    }
    if _environment(diligence_initializer) != required_diligence_initializer_environment:
        raise ReleaseComposeError(
            "Diligence policy initializer environment is not the exact public authority set"
        )
    if diligence_initializer.get("volumes") != [
        "diligence-evaluator-policy:/sealed/diligence"
    ]:
        raise ReleaseComposeError("Diligence policy initializer volume drifted")
    if main_services["delegate"].get("depends_on", {}).get(
        "diligence-policy-init"
    ) != {"condition": "service_completed_successfully"}:
        raise ReleaseComposeError("delegate does not fail closed on Diligence policy provisioning")
    if "diligence-evaluator-policy:/sealed/diligence:ro" not in main_services[
        "delegate"
    ].get("volumes", []):
        raise ReleaseComposeError("delegate lacks the read-only Diligence policy volume")
    if main_services["arena-policy-init"].get("profiles") != ["arena-runtime"]:
        raise ReleaseComposeError("Arena policy initializer must remain profile-gated")
    if main_services["arena-worker"].get("profiles") != ["arena-runtime"]:
        raise ReleaseComposeError("Arena worker must remain profile-gated")
    if main_services["anchor-writer-evidence"].get("profiles") != ["anchor-writer-ceremony"]:
        raise ReleaseComposeError("anchor writer must remain a one-shot profile")
    if main_services["deal-runtime"].get("profiles") != ["deal-settlement"]:
        raise ReleaseComposeError("deal runtime must remain profile-gated")
    if (
        main_services["deal-runtime"].get("x-dnai-capability-status")
        != "release_pinned_deterministic_evaluator"
    ):
        raise ReleaseComposeError("deal runtime confidential-evaluator gate is not explicit")
    evaluator_holders = [
        (name, _environment(service).get("TINKER_EVALUATOR_MODE"))
        for name, service in main_services.items()
        if "TINKER_EVALUATOR_MODE" in _environment(service)
    ]
    if evaluator_holders != [("delegate", "deterministic")]:
        raise ReleaseComposeError(
            "production evaluation must use the release-pinned deterministic lane"
        )
    required_diligence_evaluator_environment = {
        "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH": (
            "${TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_PATH:?Reviewed Diligence evaluator release manifest path required}"
        ),
        "TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256": (
            "${TINKER_DILIGENCE_EVALUATOR_RELEASE_MANIFEST_SHA256:?Reviewed Diligence evaluator release manifest SHA-256 required}"
        ),
        "TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT": (
            "${TINKER_DILIGENCE_EVALUATOR_POLICY_SET_ROOT:?Reviewed Diligence evaluator policy-set root required}"
        ),
        "TINKER_DILIGENCE_CHAIN_ID": (
            "${TINKER_DILIGENCE_CHAIN_ID:?Reviewed Diligence chain ID required}"
        ),
        "TINKER_DILIGENCE_ROOM_ADDRESS": (
            "${TINKER_DILIGENCE_ROOM_ADDRESS:?Reviewed DiligenceRoom address required}"
        ),
        "TINKER_CHAIN_CONTRACT_ADDRESS": (
            "${TINKER_CHAIN_CONTRACT_ADDRESS:?DiligenceRoom address required}"
        ),
    }
    if any(
        delegate_environment.get(name) != value
        for name, value in required_diligence_evaluator_environment.items()
    ):
        raise ReleaseComposeError(
            "production evaluator is missing its exact manifest, policy, chain, or room binding"
        )
    if main_services["compute-execution-worker"].get("profiles") != ["compute-execution"]:
        raise ReleaseComposeError("Compute execution must remain profile-gated")
    if (
        main_services["compute-execution-worker"].get("x-dnai-capability-status")
        != "disabled_provider_contract_unavailable"
    ):
        raise ReleaseComposeError("Compute execution provider gate is not explicit")
    required_compute_workload_environment = {
        "TINKER_COMPUTE_WORKLOAD_INGRESS_STORE_PATH": (
            "/data/compute_workload_ingress"
        ),
        "TINKER_COMPUTE_WORKLOAD_INGRESS_INTEGRITY_KEY": "",
        "TINKER_COMPUTE_WORKLOAD_INGRESS_INTEGRITY_KEY_PATH": (
            "tinker/compute_workload_ingress_integrity"
        ),
        "TINKER_COMPUTE_WORKLOAD_INGRESS_KEY_PATH": (
            "tinker/compute_workload_ingress"
        ),
        "TINKER_COMPUTE_WORKLOAD_INGRESS_LOCAL_KEY_FILE": "",
        "TINKER_COMPUTE_WORKLOAD_INGRESS_PRIVATE_KEY_HEX": "",
        "TINKER_COMPUTE_WORKLOAD_QVL_URL": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_URL:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_MAX_VERDICT_AGE_SECONDS": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_MAX_VERDICT_AGE_SECONDS:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_REVOKED_QUOTE_HASHES_JSON": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_REVOKED_QUOTE_HASHES_JSON:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_CHAIN_ID": "84532",
        "TINKER_COMPUTE_VAULT_ADDRESS": "${TINKER_COMPUTE_VAULT_ADDRESS:-}",
        "TINKER_COMPUTE_VAULT_RUNTIME_CODE_HASH": (
            "${TINKER_COMPUTE_VAULT_RUNTIME_CODE_HASH:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_CVM_ID": (
            "${TINKER_COMPUTE_WORKLOAD_CVM_ID:?Canonical main runtime CVM ID required}"
        ),
        "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:?Signed seven-CVM deployment intent required}"
        ),
        "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:-}"
        ),
        "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE": (
            "${TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:?Release ceremony nonce required}"
        ),
        "TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:?Signed QVL measurement-policy set required}"
        ),
        "TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:?Linked Compute-workload QVL measurement policy required}"
        ),
        "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256": (
            "${TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256:-}"
        ),
    }
    if any(
        delegate_environment.get(name) != value
        for name, value in required_compute_workload_environment.items()
    ):
        raise ReleaseComposeError(
            "delegate is missing the exact Compute workload recipient activation boundary"
        )

    arena_environment = _environment(main_services["arena-worker"])
    required_arena_worker_environment = {
        **ARENA_WORKER_RENDERED_CODE_OWNED_ENVIRONMENT,
        **ARENA_WORKER_FAIL_CLOSED_HEARTBEAT_ENVIRONMENT,
        "DSTACK_ENABLED": "true",
        "DSTACK_SIMULATOR_ENDPOINT": "",
        "TINKER_ARENA_WORKER_QVL_VERDICT_PATH": "",
        "TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH": (
            "${TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH:-}"
        ),
    }
    if any(
        arena_environment.get(name) != value
        for name, value in required_arena_worker_environment.items()
    ):
        raise ReleaseComposeError(
            "Arena worker is missing its exact release lineage, QVL, or heartbeat boundary"
        )

    # Only the worker may consume the generic QVL challenge-lineage names.
    # The public delegate receives only the release pins needed to compare the
    # authenticated heartbeat, never a QVL bearer or a second lineage input.
    for name in (
        "TINKER_MAIN_RUNTIME_CVM_ID",
        "TINKER_RELEASE_DEPLOYMENT_INTENT_SHA256",
        "TINKER_RELEASE_AUTHORITY_SHA256",
        "TINKER_RELEASE_CEREMONY_NONCE",
        "TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256",
    ):
        holders = [
            service_name
            for service_name, service in main_services.items()
            if name in _environment(service)
        ]
        if holders != ["arena-worker"]:
            raise ReleaseComposeError(
                f"Arena worker release-lineage alias {name} escaped its service"
            )

    required_delegate_capability_environment = {
        **ARENA_WORKER_FAIL_CLOSED_HEARTBEAT_ENVIRONMENT,
        "TINKER_ARENA_WORKER_LIVE_CAPABILITY_ENABLED": "true",
        "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256": (
            "${TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:-}"
        ),
    }
    if any(
        delegate_environment.get(name) != value
        for name, value in required_delegate_capability_environment.items()
    ):
        raise ReleaseComposeError(
            "delegate Arena capability is not fail-closed on the exact authenticated heartbeat"
        )
    heartbeat_release_binding_keys = (
        "TINKER_ARENA_WORKER_RELEASE_SHA",
        "TINKER_ARENA_WORKER_IMAGE_DIGEST",
        "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256",
        "TINKER_ARENA_WORKER_APPROVED_CHALLENGE_SET_SHA256",
        "TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT",
        "TINKER_ARENA_WORKER_COMPOSE_HASH",
        "TINKER_ARENA_WORKER_APP_ID",
        "TINKER_ARENA_WORKER_OS_IMAGE_HASH",
    )
    if any(
        delegate_environment.get(name) != arena_environment.get(name)
        for name in heartbeat_release_binding_keys
    ):
        raise ReleaseComposeError(
            "Arena worker and delegate heartbeat release bindings diverged"
        )

    writer_token = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"
    holders = [
        name for name, service in main_services.items() if writer_token in _environment(service)
    ]
    if holders != ["anchor-writer-evidence"]:
        raise ReleaseComposeError("anchor-writer QVL bearer escaped its one-shot service")
    writer_volumes = json.dumps(main_services["anchor-writer-evidence"].get("volumes", []))
    if "delegate-data" in writer_volumes or "arena-worker-sealed" in writer_volumes:
        raise ReleaseComposeError("anchor-writer evidence service can access private runtime state")

    deal_command = main_services["deal-runtime"].get("command", [])
    required_deal_qvl_policy = [
        "--attestation-release-policy-hash",
        "${TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH:-}",
    ]
    if not all(value in deal_command for value in required_deal_qvl_policy):
        raise ReleaseComposeError("deal runtime is missing its exact QVL release-policy pin")

    bearer_holders = {
        "TINKER_QVL_AUTH_TOKEN": ["deal-runtime"],
        "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN": ["arena-worker"],
        "TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN": ["delegate"],
        writer_token: ["anchor-writer-evidence"],
    }
    for bearer, expected_holders in bearer_holders.items():
        actual_holders = [
            name for name, service in main_services.items() if bearer in _environment(service)
        ]
        if actual_holders != expected_holders:
            raise ReleaseComposeError(f"{bearer} escaped its purpose-separated service")

    if _network_names(main_services["anchor-writer-evidence"]) != {"writer-egress"}:
        raise ReleaseComposeError("anchor writer must use its dedicated egress network")
    if _network_names(main_services["deal-runtime"]) != {"deal-control", "deal-egress"}:
        raise ReleaseComposeError("deal runtime must use dedicated control and egress networks")
    if "deal-control" not in _network_names(main_services["delegate"]):
        raise ReleaseComposeError("delegate is missing the internal deal control network")
    for name, service in main_services.items():
        networks = _network_names(service)
        if name != "anchor-writer-evidence" and "writer-egress" in networks:
            raise ReleaseComposeError("anchor-writer egress network escaped its service")
        if name not in {"delegate", "deal-runtime"} and "deal-control" in networks:
            raise ReleaseComposeError("deal control network escaped its two services")
        if name != "deal-runtime" and "deal-egress" in networks:
            raise ReleaseComposeError("deal egress network escaped its service")
    if main.get("networks", {}).get("deal-control") != {
        "driver": "bridge",
        "internal": True,
    }:
        raise ReleaseComposeError("deal control network must be internal-only")

    allowed_ports = {
        "main": {"delegate": ["8080:8080"]},
        "metering": {"metering": ["8443:8443"]},
        **{domain: {"qvl": ["8443:8443"]} for domain, _, _ in QVL_DOMAINS},
    }
    for domain, compose, _ in expected_sets:
        for name, service in compose["services"].items():
            if service.get("ports", []) != allowed_ports[domain].get(name, []):
                raise ReleaseComposeError(f"{domain}.{name} exposes an unreviewed port")
            if name == "policy-init" and domain != "main" and service.get("network_mode") != "none":
                raise ReleaseComposeError(f"{domain}.{name} initializer must have no network")


def _yaml_bytes(value: Mapping[str, Any], manifest_sha256: str) -> bytes:
    header = (
        "# Generated by tinker-release-composes. Do not edit by hand.\n"
        f"# Input image manifest sha256: {manifest_sha256}\n"
        "# Status: rendered_not_deployed; deployment and TDX verification are separate gates.\n"
    )
    # JSON is a strict YAML 1.2 subset accepted by Compose.  Canonical JSON
    # avoids YAML anchors, merge keys, duplicate-key ambiguity, and parser drift
    # between the renderer and the activation verifier.
    body = json.dumps(
        dict(value),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ": "),
    ) + "\n"
    return (header + body).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded_regular_file(
    path: Path,
    *,
    maximum: int,
    label: str = "image release manifest",
) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 2 or before.st_size > maximum:
            raise ReleaseComposeError(f"{label} is not a bounded regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise ReleaseComposeError(f"{label} exceeds the size bound")
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in stable_fields):
            raise ReleaseComposeError(f"{label} changed during the bounded read")
        value = b"".join(chunks)
        if len(value) != before.st_size:
            raise ReleaseComposeError(f"{label} size changed during the bounded read")
        return value
    finally:
        os.close(descriptor)


def _check_deployment_intent(
    path: Path,
    initial_bytes: bytes,
    *,
    expected_release_sha: str,
    repository_root: Path,
) -> ValidatedDeploymentIntent:
    checker = repository_root / "scripts" / "operator-policy-packet.mjs"
    try:
        checker_status = checker.lstat()
    except OSError as exc:
        raise ReleaseComposeError(
            "fixed deployment intent checker is unavailable"
        ) from exc
    if not stat.S_ISREG(checker_status.st_mode) or checker.is_symlink():
        raise ReleaseComposeError("fixed deployment intent checker is not a regular source file")

    try:
        completed = subprocess.run(
            [
                "node",
                str(checker),
                "check-intent",
                "--in",
                str(path),
            ],
            cwd=repository_root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseComposeError("deployment intent checker could not run safely") from exc
    if len(completed.stdout) > 16 * 1024 or len(completed.stderr) > 16 * 1024:
        raise ReleaseComposeError("deployment intent checker output exceeded its bound")
    if completed.returncode != 0:
        raise ReleaseComposeError("canonical deployment intent checker rejected the artifact")
    if completed.stderr:
        raise ReleaseComposeError("deployment intent checker emitted unexpected diagnostics")
    try:
        receipt_text = completed.stdout.decode("utf-8", errors="strict")
        receipt = json.loads(
            receipt_text,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseComposeError(
            "deployment intent checker returned an invalid v6 receipt"
        ) from exc
    if receipt_text != json.dumps(receipt, indent=2, ensure_ascii=False) + "\n":
        raise ReleaseComposeError(
            "deployment intent checker returned a noncanonical v6 receipt"
        )

    try:
        final_bytes = _read_bounded_regular_file(
            path,
            maximum=256 * 1024,
            label="deployment intent",
        )
    except OSError as exc:
        raise ReleaseComposeError("deployment intent changed after validation") from exc
    if final_bytes != initial_bytes:
        raise ReleaseComposeError("deployment intent changed during external validation")
    try:
        raw_intent = json.loads(
            initial_bytes,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except json.JSONDecodeError as exc:
        raise ReleaseComposeError("deployment intent is invalid JSON") from exc
    return validate_deployment_intent(
        raw_intent,
        receipt,
        expected_release_sha,
        artifact_bytes=initial_bytes,
    )


def _atomic_write(path: Path, value: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ReleaseComposeError(f"refusing to overwrite symlink: {path.name}")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def render_release_composes(
    manifest_path: Path,
    output_dir: Path,
    *,
    manifest_attestation_bundle_path: Path,
    deployment_intent_path: Path,
    expected_release_sha: str,
    repository_root: Path | None = None,
) -> RenderedRelease:
    """Validate release evidence and publish a topology-committed artifact set."""
    manifest_path = manifest_path.expanduser().absolute()
    manifest_attestation_bundle_path = (
        manifest_attestation_bundle_path.expanduser().absolute()
    )
    deployment_intent_path = deployment_intent_path.expanduser().absolute()
    output_dir = output_dir.resolve()
    repository_root = (
        repository_root.resolve()
        if repository_root is not None
        else Path(__file__).resolve().parents[3]
    )
    project_root = repository_root / "⚙️" / "tinker-delegate"
    try:
        manifest_bytes = _read_bounded_regular_file(manifest_path, maximum=2 * 1024 * 1024)
        raw_manifest = json.loads(
            manifest_bytes,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseComposeError("image release manifest is missing or invalid JSON") from exc
    release = validate_image_release(raw_manifest, expected_release_sha)
    manifest_sha256 = _sha256(manifest_bytes)
    try:
        manifest_attestation_bytes = _read_bounded_regular_file(
            manifest_attestation_bundle_path,
            maximum=2 * 1024 * 1024,
            label="release manifest attestation bundle",
        )
        manifest_attestation = json.loads(
            manifest_attestation_bytes,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseComposeError(
            "release manifest attestation bundle is missing or invalid JSON"
        ) from exc
    if not isinstance(manifest_attestation, dict) or not manifest_attestation:
        raise ReleaseComposeError(
            "release manifest attestation bundle must be a non-empty JSON object"
        )
    manifest_attestation_sha256 = _sha256(manifest_attestation_bytes)

    try:
        deployment_intent_bytes = _read_bounded_regular_file(
            deployment_intent_path,
            maximum=256 * 1024,
            label="deployment intent",
        )
    except OSError as exc:
        raise ReleaseComposeError("deployment intent is missing or unreadable") from exc
    deployment_intent = _check_deployment_intent(
        deployment_intent_path,
        deployment_intent_bytes,
        expected_release_sha=release.release_sha,
        repository_root=repository_root,
    )
    deployment_intent_file_sha256 = _sha256(deployment_intent_bytes)

    main = _render_main(release, project_root)
    qvls = {
        trust_domain: _render_independent(
            release,
            repository_root / "⚙️" / "attestation-qvl" / "docker-compose.production.yml",
            image_name="attestation-qvl",
            compose_name=compose_name,
            trust_domain=trust_domain,
            runtime_service_name="qvl",
            runtime_profile=QVL_RUNTIME_PROFILE,
            numeric_environment=deployment_intent.qvl_numeric_environment[
                QVL_INTENT_DOMAINS[trust_domain]
            ],
        )
        for trust_domain, compose_name, _ in QVL_DOMAINS
    }
    metering = _render_independent(
        release,
        repository_root / "⚙️" / "compute-metering" / "docker-compose.production.yml",
        image_name="compute-metering",
        compose_name="dnai-independent-compute-metering",
        trust_domain="independent_metering_cvm",
        runtime_service_name="metering",
        runtime_profile=METERING_RUNTIME_PROFILE,
        numeric_environment=deployment_intent.metering_numeric_environment,
    )
    _validate_rendered(main, qvls, metering, release, deployment_intent)

    main_bytes = _yaml_bytes(main, manifest_sha256)
    qvl_bytes = {
        domain: _yaml_bytes(compose, manifest_sha256) for domain, compose in qvls.items()
    }
    metering_bytes = _yaml_bytes(metering, manifest_sha256)
    filenames = {
        "main": "dnai-main-runtime.phala.yaml",
        **{domain: filename for domain, _, filename in QVL_DOMAINS},
        "metering": "dnai-independent-metering.phala.yaml",
        "manifest": "dnai-tee-image-release.json",
        "manifest_attestation": "dnai-tee-image-release.bundle.json",
        "deployment_intent": "dnai-deployment-intent-core.json",
        "topology": "dnai-cvm-topology.json",
    }
    topology = {
        "schema": TOPOLOGY_SCHEMA,
        "status": "rendered_not_deployed",
        "release_sha": release.release_sha,
        "source_ref": release.source_ref,
        "generated_at": release.generated_at,
        "deploymentIntentSha256": deployment_intent.deployment_intent_sha256,
        "deploymentIntent": {
            "file": filenames["deployment_intent"],
            "sha256": deployment_intent_file_sha256,
            "schema": DEPLOYMENT_INTENT_SCHEMA,
        },
        "image_manifest": {
            "file": filenames["manifest"],
            "sha256": manifest_sha256,
            "schema": SCHEMA,
        },
        "image_manifest_attestation": {
            "file": filenames["manifest_attestation"],
            "sha256": manifest_attestation_sha256,
            "predicate_type": PROVENANCE_PREDICATE,
        },
        "trust_domains": {
            "main_runtime_cvm": {
                "compose": filenames["main"],
                "sha256": _sha256(main_bytes),
                "services": list(MAIN_SERVICES),
                "images": [release.by_name[name].image for name in IMAGE_NAMES[:3]],
                "compute_execution": "disabled_provider_contract_unavailable",
                "deal_settlement": "release_pinned_deterministic_evaluator",
                "email_oracle_consumer_policy": "required_onchain_exact_release_binding",
            },
            **{
                domain: {
                    "compose": filenames[domain],
                    "sha256": _sha256(qvl_bytes[domain]),
                    "services": list(QVL_SERVICES),
                    "images": [release.by_name["attestation-qvl"].image],
                    "qvl_context": QVL_CONTEXTS[domain],
                    "runtime_policy": dict(
                        deployment_intent.qvl_numeric_environment[
                            QVL_INTENT_DOMAINS[domain]
                        ]
                    ),
                    "phase_gate": _phase_gate_metadata(QVL_RUNTIME_PROFILE),
                }
                for domain, _, _ in QVL_DOMAINS
            },
            "independent_metering_cvm": {
                "compose": filenames["metering"],
                "sha256": _sha256(metering_bytes),
                "services": list(METERING_SERVICES),
                "images": [release.by_name["compute-metering"].image],
                "runtime_policy": dict(
                    deployment_intent.metering_numeric_environment
                ),
                "phase_gate": _phase_gate_metadata(METERING_RUNTIME_PROFILE),
            },
        },
        "checks": {
            "literal_digest_pins": True,
            "linux_amd64_only": True,
            "local_build_contexts": False,
            "seven_cvm_descriptors": True,
            "purpose_separated_qvl_descriptors": True,
            "raw_secret_values_embedded": False,
            "deployment_attempted": False,
            "tdx_verification_claimed": False,
        },
    }
    topology_bytes = (
        json.dumps(topology, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"
    ).encode("utf-8")

    paths = RenderedRelease(
        main_compose=output_dir / filenames["main"],
        diligence_qvl_compose=output_dir / filenames["diligence_qvl_cvm"],
        arena_qvl_compose=output_dir / filenames["arena_qvl_cvm"],
        anchor_writer_qvl_compose=output_dir / filenames["anchor_writer_qvl_cvm"],
        compute_workload_qvl_compose=output_dir / filenames[
            "compute_workload_qvl_cvm"
        ],
        compute_metering_qvl_compose=output_dir / filenames["compute_metering_qvl_cvm"],
        metering_compose=output_dir / filenames["metering"],
        image_manifest=output_dir / filenames["manifest"],
        image_manifest_attestation=output_dir / filenames["manifest_attestation"],
        deployment_intent=output_dir / filenames["deployment_intent"],
        topology=output_dir / filenames["topology"],
    )
    publications = (
        (paths.main_compose, main_bytes),
        (paths.diligence_qvl_compose, qvl_bytes["diligence_qvl_cvm"]),
        (paths.arena_qvl_compose, qvl_bytes["arena_qvl_cvm"]),
        (paths.anchor_writer_qvl_compose, qvl_bytes["anchor_writer_qvl_cvm"]),
        (
            paths.compute_workload_qvl_compose,
            qvl_bytes["compute_workload_qvl_cvm"],
        ),
        (paths.compute_metering_qvl_compose, qvl_bytes["compute_metering_qvl_cvm"]),
        (paths.metering_compose, metering_bytes),
        (paths.image_manifest, manifest_bytes),
        (paths.image_manifest_attestation, manifest_attestation_bytes),
        (paths.deployment_intent, deployment_intent_bytes),
        (paths.topology, topology_bytes),
    )
    # The topology is the generation commit marker and must remain last. Each
    # referenced artifact is individually atomic and durable before that marker
    # is replaced. A pre-existing marker therefore either describes the old
    # complete generation or hash-mismatches a failed mixed generation.
    if publications[-1][0] != paths.topology:
        raise ReleaseComposeError("topology must remain the final publication marker")
    for path, _ in publications:
        if path.is_symlink():
            raise ReleaseComposeError(f"refusing to overwrite symlink: {path.name}")
    for path, content in publications:
        _atomic_write(path, content)
    _fsync_directory(output_dir)
    return paths


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render seven separate, digest-pinned Phala CVM release descriptors.",
    )
    parser.add_argument("--manifest", required=True, help="dnai-tee-image-release.json from clean CI")
    parser.add_argument(
        "--manifest-attestation-bundle",
        required=True,
        help="dnai-tee-image-release.bundle.json from the same clean CI artifact",
    )
    parser.add_argument(
        "--deployment-intent",
        required=True,
        help="canonical reviewed dnai.deployment-intent-core.v6 for this exact release SHA",
    )
    parser.add_argument("--release-sha", required=True, help="reviewed 40-hex release commit")
    parser.add_argument("--output-dir", default=".release", help="output directory (default: .release)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = render_release_composes(
            Path(args.manifest),
            Path(args.output_dir),
            manifest_attestation_bundle_path=Path(args.manifest_attestation_bundle),
            deployment_intent_path=Path(args.deployment_intent),
            expected_release_sha=args.release_sha,
        )
    except ReleaseComposeError as exc:
        print(f"release compose rendering failed safely: {exc}")
        return 2
    print(json.dumps(result.to_public_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
