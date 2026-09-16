"""Executable, fail-closed bootstrap for the attested Arena safe-IR worker.

The command deliberately has no execution-mode, local-key, quote, or
``verified`` option. Its only production construction path requires:

* a real dstack CVM (the simulator is rejected);
* a SHA-256-pinned 0600 release manifest;
* a 0600 sealed synthetic evaluator whose commitment is in that manifest;
* a fresh independent DCAP/QVL verdict for each selected job, obtained only
  through authenticated, bounded HTTPS;
* a stable, fresh finalized-block read of the pinned Base Sepolia
  ChallengeRegistry immediately before every durable worker claim; and
* the shared integrity-protected execution-policy store and its current
  deployment approval domain.

Candidate input remains the capability-free ``dnai-safe-ir-v1`` JSON language.
This module cannot select or import a general-purpose candidate executor.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence, TextIO
from urllib.parse import urlparse

import httpx
from eth_hash.auto import keccak

from tinker_delegate import dstack_utils
from tinker_delegate.arena_ingress import (
    ArenaIngressRecipient,
    resolve_arena_recipient,
)
from tinker_delegate.arena_auth import arena_store_integrity_key
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
)
from tinker_delegate.arena_safe_worker import (
    ArenaAttestationPacket,
    DnaseqVariantQcSafeIrEvaluator,
    MAX_TDX_QUOTE_BYTES,
    MIN_TDX_QUOTE_BYTES,
    ArenaRegistryClaimRequest,
    ArenaSafeWorkerRegistryUnavailable,
    ArenaWorkerRegistryAuthorization,
    RefreshingArenaActivationProvider,
)
from tinker_delegate.arena_store import (
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    default_challenge_catalog,
)
from tinker_delegate.arena_release_approval import (
    normalize_release_approved_challenge_bindings,
    require_release_approved_challenge,
)
from tinker_delegate.arena_worker_service import (
    EXIT_ACTIVATION_UNAVAILABLE,
    ArenaSafeWorkerService,
    ArenaWorkerStatus,
    build_verified_arena_worker_service,
    run_arena_worker_process,
    write_bounded_worker_status,
)
from tinker_delegate.arena_worker_evidence import (
    ArenaWorkerEvidenceError,
    ArenaWorkerHeartbeat,
    ArenaWorkerHeartbeatStore,
    ArenaWorkerReleaseBindings,
    arena_worker_heartbeat_integrity_key,
    worker_status_state,
)
from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_store import (
    execution_policy_approval_domain_hash,
    execution_policy_approver_root_hash,
    execution_policy_integrity_key,
    execution_policy_trust_context,
)
from tinker_delegate.policy_kernel import POLICY_CANONICALIZATION_VERSION
from tinker_delegate.result_verifier import (
    IndependentAttestationVerdict,
    independent_attestation_verdict_from_public_dict,
)
from tinker_delegate.qvl_freshness import (
    QvlChallenge,
    VERIFICATION_REQUEST_SCHEMA,
    authenticate_qvl_challenge,
    challenge_bound_report_data,
    challenge_request,
    qvl_challenge_from_public_dict,
)


BASE_SEPOLIA_CHAIN_ID = 84_532
RELEASE_SCHEMA = "dnai.arena.safe-worker-release.v3"
RELEASE_POLICY_SCHEMA = "dnai.arena.safe-worker-release-policy.v3"
EVALUATOR_SCHEMA = "dnai.arena.synthetic-safe-ir-evaluator.v1"
QVL_REQUEST_SCHEMA = VERIFICATION_REQUEST_SCHEMA
EXECUTION_POLICY_APPROVAL_SCHEMA = (
    "dnai-wikigen/execution-policy-approval/v3"
)
EXECUTION_POLICY_API_SCHEMA_VERSION = 3
EXECUTION_POLICY_STORE_SCHEMA_VERSION = 6
EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA = (
    "dnai.execution-policy-rollback-anchor.v1"
)
EXECUTION_POLICY_ANCHOR_VERIFICATION_MODEL = (
    "single_rpc_reported_finalized_with_confirmation_depth"
)
BOOTSTRAP_STATUS_SCHEMA_VERSION = 1
MAX_SECURE_JSON_BYTES = 65_536
MAX_RPC_RESPONSE_BYTES = 262_144
MAX_BLOCK_AGE_SECONDS = 300
MAX_FUTURE_BLOCK_SKEW_SECONDS = 30
REGISTRY_CLAIM_AUTHORIZATION_SCHEMA = (
    "dnai.arena.worker-registry-claim-authorization.v1"
)
REGISTRY_CLAIM_VERIFICATION_MODEL = (
    "single_rpc_reported_finalized_pinned_block"
)
REGISTRY_CLAIM_AUTHORIZATION_DOMAIN = (
    b"dnai-wikigen/arena-worker-registry-claim-authorization/v1\0"
)
QVL_AUTH_TOKEN_ENV = "TINKER_ARENA_WORKER_QVL_AUTH_TOKEN"

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_APP_ID = re.compile(r"^[\x21-\x7e]{1,128}$")
_METADATA_URI = re.compile(r"^[\x21-\x7e]{1,256}$")

_REGISTRY_PAUSED_SELECTOR = keccak(b"registryPaused()")[:4]
_CHALLENGE_EXISTS_SELECTOR = keccak(b"challengeExists(uint256)")[:4]
_GET_CHALLENGE_SELECTOR = keccak(b"getChallenge(uint256)")[:4]
_GET_VERSION_SELECTOR = keccak(b"getVersion(uint256,uint32)")[:4]

_RELEASE_FIELDS = frozenset(
    {
        "schema",
        "chain_id",
        "challenge_registry_address",
        "challenge_registry_runtime_code_hash",
        "approved_challenge_bindings",
        "approved_challenge_set_sha256",
        "challenge_binding",
        "tee_release",
        "trusted_qvl_verifier_addresses",
        "max_qvl_verdict_age_seconds",
        "execution_policy_canonicalization_version",
        "execution_policy_approval_schema",
        "execution_policy_api_schema_version",
        "execution_policy_store_schema_version",
        "execution_policy_approval_domain",
        "execution_policy_approval_domain_hash",
        "execution_policy_approver_hashes",
        "execution_policy_approver_root_hash",
        "execution_policy_rollback_anchor",
    }
)
_EXECUTION_POLICY_ROLLBACK_ANCHOR_FIELDS = frozenset(
    {
        "schema",
        "status",
        "chain_id",
        "contract_address",
        "runtime_code_hash",
        "release_manifest_commitment",
        "evidence_sha256",
        "writer_address",
        "writer_release_commitment",
        "writer_custody",
        "writer_key_path",
        "confirmations",
        "max_block_age_seconds",
        "max_future_block_skew_seconds",
        "verification_model",
        "independent_rpc_quorum_verified",
        "consensus_proof_verified",
    }
)
_BINDING_FIELDS = frozenset(
    {
        "catalog_challenge_id",
        "catalog_challenge_version",
        "catalog_manifest_hash",
        "runtime",
        "runtime_policy_commitment",
        "registry_challenge_id",
        "registry_version",
        "metadata_uri",
        "metadata_hash",
        "sealed_artifact_commitment",
        "evaluator_commitment",
        "release_policy_commitment",
    }
)
_TEE_RELEASE_FIELDS = frozenset(
    {
        "compose_hash",
        "app_id",
        "os_image_hash",
        "tee_signer_address",
    }
)
_EVALUATOR_FIELDS = frozenset(
    {
        "schema",
        "challenge_id",
        "challenge_version",
        "challenge_manifest_hash",
        "runtime",
        "runtime_policy_commitment",
        "synthetic_only",
        "positive_controls",
        "negative_controls",
    }
)


class ArenaWorkerBootstrapError(RuntimeError):
    """Fail-closed startup error carrying only an allowlisted reason code."""

    _REASONS = frozenset(
        {
            "real_dstack_required",
            "worker_configuration_missing",
            "release_manifest_invalid",
            "sealed_evaluator_invalid",
            "independent_qvl_unavailable",
            "challenge_registry_unavailable",
            "execution_policy_unavailable",
            "worker_initialization_failed",
        }
    )

    def __init__(self, reason: str):
        if reason not in self._REASONS:
            reason = "worker_initialization_failed"
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class ArenaChallengeReleaseBinding:
    catalog_challenge_id: str
    catalog_challenge_version: str
    catalog_manifest_hash: str
    runtime: str
    runtime_policy_commitment: str
    registry_challenge_id: int
    registry_version: int
    metadata_uri: str
    metadata_hash: str
    sealed_artifact_commitment: str
    evaluator_commitment: str
    release_policy_commitment: str
    controller_address: str
    pending_controller_address: str


@dataclass(frozen=True)
class ArenaTeeReleasePins:
    compose_hash: str
    app_id: str
    os_image_hash: str
    tee_signer_address: str


@dataclass(frozen=True)
class ArenaExecutionPolicyRollbackAnchorPins:
    schema: str
    status: str
    chain_id: int
    contract_address: str
    runtime_code_hash: str
    release_manifest_commitment: str
    evidence_sha256: str
    writer_address: str
    writer_release_commitment: str
    writer_custody: str
    writer_key_path: str
    confirmations: int
    max_block_age_seconds: int
    max_future_block_skew_seconds: int
    verification_model: str
    independent_rpc_quorum_verified: bool
    consensus_proof_verified: bool


@dataclass(frozen=True)
class ArenaWorkerReleasePins:
    chain_id: int
    challenge_registry_address: str
    challenge_registry_runtime_code_hash: str
    approved_challenge_bindings: dict[str, dict[str, Any]]
    approved_challenge_set_sha256: str
    challenge_binding: ArenaChallengeReleaseBinding
    tee_release: ArenaTeeReleasePins
    trusted_qvl_verifier_addresses: tuple[str, ...]
    max_qvl_verdict_age_seconds: int
    execution_policy_canonicalization_version: str
    execution_policy_approval_schema: str
    execution_policy_api_schema_version: int
    execution_policy_store_schema_version: int
    execution_policy_approval_domain: str
    execution_policy_approval_domain_hash: str
    execution_policy_approver_hashes: tuple[str, ...]
    execution_policy_approver_root_hash: str
    execution_policy_rollback_anchor: ArenaExecutionPolicyRollbackAnchorPins


@dataclass(frozen=True)
class ArenaRegistryChallengeState:
    controller: str
    pending_controller: str
    lifecycle: int
    latest_version: int
    paused: bool
    configuration_frozen: bool


@dataclass(frozen=True)
class ArenaRegistryVersionState:
    metadata_uri: str
    metadata_hash: str
    sealed_artifact_commitment: str
    evaluator_commitment: str
    release_policy_commitment: str


@dataclass(frozen=True)
class ArenaRegistryBlock:
    number: int
    block_hash: str
    timestamp: int

    def __post_init__(self) -> None:
        if (
            isinstance(self.number, bool)
            or not isinstance(self.number, int)
            or self.number < 1
        ):
            raise ValueError("registry block number is invalid")
        if (
            not isinstance(self.block_hash, str)
            or _BYTES32.fullmatch(self.block_hash) is None
            or self.block_hash == "0x" + "0" * 64
        ):
            raise ValueError("registry block hash is invalid")
        if (
            isinstance(self.timestamp, bool)
            or not isinstance(self.timestamp, int)
            or self.timestamp < 1
        ):
            raise ValueError("registry block timestamp is invalid")


class ArenaRegistryReader(Protocol):
    def chain_id(self) -> int: ...

    def finalized_block(self) -> ArenaRegistryBlock: ...

    def block(self, block_number: int) -> ArenaRegistryBlock: ...

    def bytecode(self, address: str, block_number: int) -> bytes: ...

    def registry_paused(self, address: str, block_number: int) -> bool: ...

    def challenge_exists(
        self, address: str, challenge_id: int, block_number: int
    ) -> bool: ...

    def challenge(
        self, address: str, challenge_id: int, block_number: int
    ) -> ArenaRegistryChallengeState: ...

    def version(
        self,
        address: str,
        challenge_id: int,
        version: int,
        block_number: int,
    ) -> ArenaRegistryVersionState: ...

    def close(self) -> None: ...


class HttpsArenaRegistryReader:
    """Small bounded JSON-RPC reader; it never signs or broadcasts."""

    def __init__(self, rpc_url: str, *, client: httpx.Client | None = None) -> None:
        self.rpc_url = _https_url(rpc_url, label="Base Sepolia RPC")
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(20.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None
        self._next_id = 1

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def _call(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        request = self._client.build_request(
            "POST",
            self.rpc_url,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            json={
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params,
            },
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
            try:
                if response.status_code != 200 or response.history:
                    raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
                raw = _bounded_response_body(response, MAX_RPC_RESPONSE_BYTES)
            finally:
                response.close()
        except ArenaWorkerBootstrapError:
            raise
        except (httpx.HTTPError, OSError) as exc:
            raise ArenaWorkerBootstrapError(
                "challenge_registry_unavailable"
            ) from exc
        try:
            payload = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArenaWorkerBootstrapError(
                "challenge_registry_unavailable"
            ) from exc
        if (
            not isinstance(payload, dict)
            or payload.get("jsonrpc") != "2.0"
            or payload.get("id") != request_id
            or payload.get("error") is not None
            or "result" not in payload
        ):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        return payload["result"]

    def chain_id(self) -> int:
        return _quantity(self._call("eth_chainId", []), label="chain ID")

    @staticmethod
    def _block_from_result(value: Any) -> ArenaRegistryBlock:
        if not isinstance(value, Mapping):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        block_hash = value.get("hash")
        if not isinstance(block_hash, str):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        try:
            return ArenaRegistryBlock(
                number=_quantity(value.get("number"), label="block number"),
                block_hash=_bytes32(block_hash.lower()),
                timestamp=_quantity(value.get("timestamp"), label="block timestamp"),
            )
        except (TypeError, ValueError) as exc:
            raise ArenaWorkerBootstrapError(
                "challenge_registry_unavailable"
            ) from exc

    def finalized_block(self) -> ArenaRegistryBlock:
        return self._block_from_result(
            self._call("eth_getBlockByNumber", ["finalized", False])
        )

    def block(self, block_number: int) -> ArenaRegistryBlock:
        if (
            isinstance(block_number, bool)
            or not isinstance(block_number, int)
            or block_number < 1
        ):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        return self._block_from_result(
            self._call("eth_getBlockByNumber", [_quantity_hex(block_number), False])
        )

    def latest_block(self) -> tuple[int, int]:
        """Compatibility-only latest read; claim authorization uses finalized."""

        block_number = _quantity(
            self._call("eth_blockNumber", []), label="block number"
        )
        block = self._call("eth_getBlockByNumber", [_quantity_hex(block_number), False])
        if not isinstance(block, dict):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        returned_number = _quantity(block.get("number"), label="block number")
        timestamp = _quantity(block.get("timestamp"), label="block timestamp")
        if returned_number != block_number:
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        return block_number, timestamp

    def bytecode(self, address: str, block_number: int) -> bytes:
        return _hex_bytes(
            self._call("eth_getCode", [address, _quantity_hex(block_number)]),
            label="registry bytecode",
            maximum=MAX_RPC_RESPONSE_BYTES // 2,
        )

    def _eth_call(self, address: str, data: bytes, block_number: int) -> bytes:
        return _hex_bytes(
            self._call(
                "eth_call",
                [
                    {"to": address, "data": "0x" + data.hex()},
                    _quantity_hex(block_number),
                ],
            ),
            label="registry call",
            maximum=MAX_SECURE_JSON_BYTES,
        )

    def registry_paused(self, address: str, block_number: int) -> bool:
        return _decode_bool(
            self._eth_call(address, _REGISTRY_PAUSED_SELECTOR, block_number)
        )

    def challenge_exists(
        self, address: str, challenge_id: int, block_number: int
    ) -> bool:
        return _decode_bool(
            self._eth_call(
                address,
                _CHALLENGE_EXISTS_SELECTOR + _uint_word(challenge_id),
                block_number,
            )
        )

    def challenge(
        self, address: str, challenge_id: int, block_number: int
    ) -> ArenaRegistryChallengeState:
        return _decode_challenge(
            self._eth_call(
                address,
                _GET_CHALLENGE_SELECTOR + _uint_word(challenge_id),
                block_number,
            )
        )

    def version(
        self,
        address: str,
        challenge_id: int,
        version: int,
        block_number: int,
    ) -> ArenaRegistryVersionState:
        return _decode_version(
            self._eth_call(
                address,
                _GET_VERSION_SELECTOR
                + _uint_word(challenge_id)
                + _uint_word(version),
                block_number,
            )
        )


class HttpsArenaQvlClient:
    """Bounded authenticated transport for one exact live quote per request."""

    def __init__(
        self,
        url: str,
        *,
        auth_token: str,
        client: httpx.Client | None = None,
        trusted_verifier_addresses: Sequence[str] = (),
        expected_policy_hash: str = "",
        chain_id: int = 0,
        cvm_id: str = "",
        deployment_intent_sha256: str = "",
        release_authority_sha256: str = "",
        ceremony_nonce: str = "",
        measurement_policy_sha256: str = "",
    ) -> None:
        self.url = _https_url(url, label="independent QVL")
        self.challenge_url = self.url.replace("/verify", "/challenge")
        if (
            not 32 <= len(auth_token.encode("utf-8")) <= 4_096
            or any(
                ord(character) < 0x21 or ord(character) > 0x7E
                for character in auth_token
            )
        ):
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable")
        self._auth_token = auth_token
        self._trusted_verifier_addresses = tuple(trusted_verifier_addresses)
        try:
            self._expected_policy_hash = _bytes32(expected_policy_hash)
            self._challenge_request = challenge_request(
                "arena",
                chain_id=chain_id,
                domain="main_runtime_cvm",
                cvm_id=cvm_id,
                deployment_intent_sha256=deployment_intent_sha256,
                release_authority_sha256=release_authority_sha256,
                ceremony_nonce=ceremony_nonce,
                measurement_policy_sha256=measurement_policy_sha256,
            )
        except Exception:
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable") from None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            follow_redirects=False,
            trust_env=False,
        )
        self._owns_client = client is None

    def __repr__(self) -> str:
        return "HttpsArenaQvlClient(authenticated=True)"

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def issue_challenge(self) -> QvlChallenge:
        request = self._client.build_request(
            "POST",
            self.challenge_url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(self._challenge_request),
        )
        try:
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if (
                    response.status_code != 200
                    or response.history
                    or not (content_type == "application/json" or content_type.endswith("+json"))
                ):
                    raise ArenaWorkerBootstrapError("independent_qvl_unavailable")
                raw = _bounded_response_body(response, MAX_SECURE_JSON_BYTES)
            finally:
                response.close()
            return authenticate_qvl_challenge(
                qvl_challenge_from_public_dict(
                    _json_object(raw, label="independent QVL challenge")
                ),
                expected_profile="arena",
                expected_chain_id=int(self._challenge_request["chain_id"]),
                expected_domain=str(self._challenge_request["domain"]),
                expected_cvm_id=str(self._challenge_request["cvm_id"]),
                expected_deployment_intent_sha256=str(
                    self._challenge_request["deployment_intent_sha256"]
                ),
                expected_release_authority_sha256=str(
                    self._challenge_request["release_authority_sha256"]
                ),
                expected_ceremony_nonce=str(self._challenge_request["ceremony_nonce"]),
                expected_measurement_policy_sha256=str(
                    self._challenge_request["measurement_policy_sha256"]
                ),
                trusted_verifier_addresses=self._trusted_verifier_addresses,
                expected_policy_hash=self._expected_policy_hash,
            )
        except ArenaWorkerBootstrapError:
            raise
        except Exception:
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable") from None

    def verify(
        self,
        packet: ArenaAttestationPacket,
        challenge: QvlChallenge,
    ) -> IndependentAttestationVerdict:
        if not isinstance(packet, ArenaAttestationPacket):
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable")
        if (
            not isinstance(packet.quote, str)
            or not packet.quote.startswith("0x")
            or not (
                2 + MIN_TDX_QUOTE_BYTES * 2
                <= len(packet.quote)
                <= 2 + MAX_TDX_QUOTE_BYTES * 2
            )
            or len(packet.quote) % 2
            or not re.fullmatch(r"0x[0-9a-f]+", packet.quote)
        ):
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable")
        expectation = packet.evidence.to_public_dict()
        expectation["quote_report_data"] = challenge_bound_report_data(
            packet.evidence.report_data, challenge
        )
        request_payload = {
            "schema": QVL_REQUEST_SCHEMA,
            "challenge": challenge.to_public_dict(),
            "quote": packet.quote,
            "expectation": expectation,
        }
        request = self._client.build_request(
            "POST",
            self.url,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._auth_token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
            content=_canonical_json(request_payload),
        )
        try:
            response = self._client.send(
                request,
                stream=True,
                follow_redirects=False,
            )
            try:
                content_type = (
                    response.headers.get("content-type", "")
                    .split(";", 1)[0]
                    .lower()
                )
                if (
                    response.status_code != 200
                    or response.history
                    or not (
                        content_type == "application/json"
                        or content_type.endswith("+json")
                    )
                ):
                    raise ArenaWorkerBootstrapError(
                        "independent_qvl_unavailable"
                    )
                raw = _bounded_response_body(response, MAX_SECURE_JSON_BYTES)
            finally:
                response.close()
        except ArenaWorkerBootstrapError:
            raise
        except Exception:
            # Transport exceptions may retain the request object, including the
            # raw quote and bearer header. Never expose that object as a chained
            # exception to callers or supervisor logs.
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable") from None
        try:
            return independent_attestation_verdict_from_public_dict(
                _json_object(raw, label="independent QVL verdict")
            )
        except Exception:
            # A hostile response can place secrets in parser error context.
            raise ArenaWorkerBootstrapError("independent_qvl_unavailable") from None


def compute_arena_release_policy_commitment(
    *,
    chain_id: int,
    challenge_registry_address: str,
    challenge_registry_runtime_code_hash: str,
    approved_challenge_set_sha256: str,
    binding: Mapping[str, Any],
    tee_release: Mapping[str, Any],
    trusted_qvl_verifier_addresses: Sequence[str],
    max_qvl_verdict_age_seconds: int,
    execution_policy_canonicalization_version: str,
    execution_policy_approval_schema: str,
    execution_policy_api_schema_version: int,
    execution_policy_store_schema_version: int,
    execution_policy_approval_domain: str,
    execution_policy_approval_domain_hash: str,
    execution_policy_approver_hashes: Sequence[str],
    execution_policy_approver_root_hash: str,
    execution_policy_rollback_anchor: Mapping[str, Any],
) -> str:
    """Commit the reviewed public worker policy frozen in ChallengeRegistry."""

    policy = {
        "schema": RELEASE_POLICY_SCHEMA,
        "chain_id": chain_id,
        "challenge_registry_address": challenge_registry_address,
        "challenge_registry_runtime_code_hash": challenge_registry_runtime_code_hash,
        "approved_challenge_set_sha256": approved_challenge_set_sha256,
        "catalog_challenge_id": binding["catalog_challenge_id"],
        "catalog_challenge_version": binding["catalog_challenge_version"],
        "catalog_manifest_hash": binding["catalog_manifest_hash"],
        "runtime": binding["runtime"],
        "runtime_policy_commitment": binding["runtime_policy_commitment"],
        "registry_challenge_id": str(binding["registry_challenge_id"]),
        "registry_version": binding["registry_version"],
        "metadata_uri": binding["metadata_uri"],
        "metadata_hash": binding["metadata_hash"],
        "sealed_artifact_commitment": binding["sealed_artifact_commitment"],
        "evaluator_commitment": binding["evaluator_commitment"],
        "compose_hash": tee_release["compose_hash"],
        "app_id": tee_release["app_id"],
        "os_image_hash": tee_release["os_image_hash"],
        "tee_signer_address": tee_release["tee_signer_address"],
        "trusted_qvl_verifier_addresses": list(
            trusted_qvl_verifier_addresses
        ),
        "max_qvl_verdict_age_seconds": max_qvl_verdict_age_seconds,
        "execution_policy_canonicalization_version": (
            execution_policy_canonicalization_version
        ),
        "execution_policy_approval_schema": execution_policy_approval_schema,
        "execution_policy_api_schema_version": execution_policy_api_schema_version,
        "execution_policy_store_schema_version": execution_policy_store_schema_version,
        "execution_policy_approval_domain": execution_policy_approval_domain,
        "execution_policy_approval_domain_hash": execution_policy_approval_domain_hash,
        "execution_policy_approver_hashes": list(
            execution_policy_approver_hashes
        ),
        "execution_policy_approver_root_hash": (
            execution_policy_approver_root_hash
        ),
        "execution_policy_rollback_anchor": dict(
            execution_policy_rollback_anchor
        ),
    }
    digest = hashlib.sha256()
    digest.update(b"dnai-wikigen/arena-safe-worker-release-policy/v3\0")
    digest.update(_canonical_json(policy))
    return "0x" + digest.hexdigest()


def sealed_evaluator_commitment(payload: Mapping[str, Any]) -> str:
    """Return the commitment placed in ``sealedArtifactCommitment``."""

    digest = hashlib.sha256()
    digest.update(b"dnai-wikigen/arena-sealed-synthetic-evaluator/v1\0")
    digest.update(_canonical_json(payload))
    return "0x" + digest.hexdigest()


def load_release_manifest(settings: Settings) -> ArenaWorkerReleasePins:
    path = str(settings.arena_worker_release_manifest_path or "").strip()
    expected_hash = str(settings.arena_worker_release_manifest_sha256 or "").strip()
    if not path or not _SHA256.fullmatch(expected_hash):
        raise ArenaWorkerBootstrapError("worker_configuration_missing")
    try:
        raw = _secure_read_0600(path, maximum=MAX_SECURE_JSON_BYTES)
        observed = "sha256:" + hashlib.sha256(raw).hexdigest()
        if not hmac.compare_digest(observed, expected_hash):
            raise ArenaWorkerBootstrapError("release_manifest_invalid")
        payload = _json_object(raw, label="release manifest")
        _exact_keys(payload, _RELEASE_FIELDS)
        if payload["schema"] != RELEASE_SCHEMA:
            raise ValueError("unsupported release schema")

        chain_id = _integer(payload["chain_id"], minimum=1, maximum=2**63 - 1)
        if chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise ValueError("unsupported chain")
        registry_address = _address(payload["challenge_registry_address"])
        registry_code_hash = _bytes32(
            payload["challenge_registry_runtime_code_hash"]
        )

        approved_bindings = normalize_release_approved_challenge_bindings(
            payload["approved_challenge_bindings"]
        )
        approved_set_sha256 = str(payload["approved_challenge_set_sha256"])
        selected_approval = require_release_approved_challenge(
            approved_bindings,
            approved_set_sha256=approved_set_sha256,
            challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
            challenge_version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        )

        raw_binding = _mapping(payload["challenge_binding"])
        _exact_keys(raw_binding, _BINDING_FIELDS)
        challenge = default_challenge_catalog().get(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        )
        if (
            raw_binding["catalog_challenge_id"] != DNASEQ_SAFE_IR_CHALLENGE_ID
            or raw_binding["catalog_challenge_version"]
            != DNASEQ_SAFE_IR_CHALLENGE_VERSION
            or raw_binding["catalog_manifest_hash"] != challenge.manifest_hash
            or raw_binding["runtime"] != SAFE_IR_RUNTIME
            or raw_binding["runtime_policy_commitment"]
            != SAFE_IR_POLICY_COMMITMENT
        ):
            raise ValueError("safe IR challenge binding mismatch")
        registry_challenge_id = _decimal_uint(raw_binding["registry_challenge_id"])
        registry_version = _integer(
            raw_binding["registry_version"], minimum=1, maximum=2**32 - 1
        )
        metadata_uri = _ascii(raw_binding["metadata_uri"], _METADATA_URI)
        metadata_hash = _bytes32(raw_binding["metadata_hash"])
        if metadata_hash != "0x" + challenge.manifest_hash:
            raise ValueError("metadata hash mismatch")
        sealed_artifact_commitment = _bytes32(
            raw_binding["sealed_artifact_commitment"]
        )
        evaluator_commitment = _bytes32(raw_binding["evaluator_commitment"])
        if evaluator_commitment != "0x" + SAFE_IR_POLICY_COMMITMENT.removeprefix(
            "sha256:"
        ):
            raise ValueError("runtime policy is not the evaluator commitment")
        release_policy_commitment = _bytes32(
            raw_binding["release_policy_commitment"]
        )
        if (
            str(registry_challenge_id)
            != selected_approval["registry_challenge_id"]
            or registry_version != selected_approval["registry_version"]
            or raw_binding["catalog_manifest_hash"]
            != selected_approval["catalog_manifest_hash"]
            or metadata_uri != selected_approval["metadata_uri"]
            or metadata_hash != selected_approval["metadata_hash"]
            or sealed_artifact_commitment
            != selected_approval["sealed_artifact_commitment"]
            or evaluator_commitment
            != selected_approval["evaluator_commitment"]
        ):
            raise ValueError("selected challenge is not the exact approved-set member")

        raw_tee = _mapping(payload["tee_release"])
        _exact_keys(raw_tee, _TEE_RELEASE_FIELDS)
        compose_hash = _bare_bytes32(raw_tee["compose_hash"])
        app_id = _ascii(raw_tee["app_id"], _APP_ID)
        os_image_hash = _bare_bytes32(raw_tee["os_image_hash"])
        tee_signer = _address(raw_tee["tee_signer_address"])

        raw_trusted = payload["trusted_qvl_verifier_addresses"]
        if not isinstance(raw_trusted, list) or not 1 <= len(raw_trusted) <= 16:
            raise ValueError("QVL trust roots are invalid")
        trusted = tuple(sorted({_address(value) for value in raw_trusted}))
        if len(trusted) != len(raw_trusted) or tee_signer in trusted:
            raise ValueError("QVL trust roots are invalid")
        max_age = _integer(
            payload["max_qvl_verdict_age_seconds"], minimum=30, maximum=300
        )
        canonicalization_version = str(
            payload["execution_policy_canonicalization_version"]
        )
        approval_schema = str(payload["execution_policy_approval_schema"])
        api_schema_version = _integer(
            payload["execution_policy_api_schema_version"],
            minimum=1,
            maximum=2**31 - 1,
        )
        store_schema_version = _integer(
            payload["execution_policy_store_schema_version"],
            minimum=1,
            maximum=2**31 - 1,
        )
        if (
            canonicalization_version != POLICY_CANONICALIZATION_VERSION
            or approval_schema != EXECUTION_POLICY_APPROVAL_SCHEMA
            or api_schema_version != EXECUTION_POLICY_API_SCHEMA_VERSION
            or store_schema_version != EXECUTION_POLICY_STORE_SCHEMA_VERSION
        ):
            raise ValueError("execution policy release versions are invalid")
        approval_domain = str(payload["execution_policy_approval_domain"])
        approval_domain_hash = str(
            payload["execution_policy_approval_domain_hash"]
        )
        if (
            not _HEX_64.fullmatch(approval_domain_hash)
            or execution_policy_approval_domain_hash(approval_domain)
            != approval_domain_hash
        ):
            raise ValueError("approval domain hash is invalid")
        raw_approvers = payload["execution_policy_approver_hashes"]
        if not isinstance(raw_approvers, list) or not 1 <= len(raw_approvers) <= 64:
            raise ValueError("execution policy approver hashes are invalid")
        approver_hashes = tuple(str(value) for value in raw_approvers)
        if (
            any(not _HEX_64.fullmatch(value) for value in approver_hashes)
            or tuple(sorted(set(approver_hashes))) != approver_hashes
        ):
            raise ValueError("execution policy approver hashes are invalid")
        approver_root_hash = str(
            payload["execution_policy_approver_root_hash"]
        )
        if (
            not _HEX_64.fullmatch(approver_root_hash)
            or execution_policy_approver_root_hash(approver_hashes)
            != approver_root_hash
            or not approval_domain.endswith(":" + approver_root_hash)
        ):
            raise ValueError("execution policy approver root is invalid")

        raw_anchor = _mapping(payload["execution_policy_rollback_anchor"])
        _exact_keys(raw_anchor, _EXECUTION_POLICY_ROLLBACK_ANCHOR_FIELDS)
        if (
            raw_anchor["schema"] != EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA
            or raw_anchor["status"]
            != "verified_active_frozen_release_writer"
        ):
            raise ValueError("execution policy rollback anchor is unavailable")
        anchor_chain_id = _integer(
            raw_anchor["chain_id"], minimum=1, maximum=2**63 - 1
        )
        if anchor_chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise ValueError("execution policy rollback anchor chain is invalid")
        anchor_address = _address(raw_anchor["contract_address"])
        anchor_runtime_code_hash = _bytes32(raw_anchor["runtime_code_hash"])
        anchor_manifest_commitment = _bare_bytes32(
            raw_anchor["release_manifest_commitment"]
        )
        anchor_evidence_sha256 = str(raw_anchor["evidence_sha256"])
        if (
            not _SHA256.fullmatch(anchor_evidence_sha256)
            or anchor_evidence_sha256 == "sha256:" + "0" * 64
        ):
            raise ValueError("execution policy rollback anchor evidence is invalid")
        anchor_writer = _address(raw_anchor["writer_address"])
        anchor_writer_release = _bytes32(
            raw_anchor["writer_release_commitment"]
        )
        if anchor_writer_release != "0x" + anchor_manifest_commitment:
            raise ValueError(
                "execution policy anchor writer release is invalid"
            )
        anchor_writer_custody = str(raw_anchor["writer_custody"])
        anchor_writer_key_path = str(raw_anchor["writer_key_path"])
        if (
            anchor_writer_custody
            != "dstack_derived_execution_policy_anchor_writer"
            or anchor_writer_key_path
            != "tinker/execution_policy_anchor_writer"
        ):
            raise ValueError("execution policy anchor writer custody is invalid")
        anchor_confirmations = _integer(
            raw_anchor["confirmations"], minimum=2, maximum=256
        )
        anchor_max_block_age = _integer(
            raw_anchor["max_block_age_seconds"], minimum=30, maximum=3_600
        )
        anchor_future_skew = _integer(
            raw_anchor["max_future_block_skew_seconds"],
            minimum=0,
            maximum=300,
        )
        anchor_verification_model = str(raw_anchor["verification_model"])
        anchor_independent_rpc_quorum_verified = raw_anchor[
            "independent_rpc_quorum_verified"
        ]
        anchor_consensus_proof_verified = raw_anchor[
            "consensus_proof_verified"
        ]
        if (
            anchor_verification_model
            != EXECUTION_POLICY_ANCHOR_VERIFICATION_MODEL
            or anchor_independent_rpc_quorum_verified is not False
            or anchor_consensus_proof_verified is not False
        ):
            raise ValueError(
                "execution policy anchor verification model is invalid"
            )
        approval_domain_parts = approval_domain.split(":")
        if (
            len(approval_domain_parts) != 6
            or approval_domain_parts[2] != anchor_manifest_commitment
            or approval_domain_parts[3] != "0x" + compose_hash
            or approval_domain_parts[4]
            != hashlib.sha256(app_id.encode("ascii")).hexdigest()
        ):
            raise ValueError("execution policy rollback anchor release is invalid")
        normalized_anchor = {
            "schema": EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA,
            "status": "verified_active_frozen_release_writer",
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "contract_address": anchor_address,
            "runtime_code_hash": anchor_runtime_code_hash,
            "release_manifest_commitment": anchor_manifest_commitment,
            "evidence_sha256": anchor_evidence_sha256,
            "writer_address": anchor_writer,
            "writer_release_commitment": anchor_writer_release,
            "writer_custody": anchor_writer_custody,
            "writer_key_path": anchor_writer_key_path,
            "confirmations": anchor_confirmations,
            "max_block_age_seconds": anchor_max_block_age,
            "max_future_block_skew_seconds": anchor_future_skew,
            "verification_model": anchor_verification_model,
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
        }

        normalized_binding = {
            "catalog_challenge_id": DNASEQ_SAFE_IR_CHALLENGE_ID,
            "catalog_challenge_version": DNASEQ_SAFE_IR_CHALLENGE_VERSION,
            "catalog_manifest_hash": challenge.manifest_hash,
            "runtime": SAFE_IR_RUNTIME,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "registry_challenge_id": registry_challenge_id,
            "registry_version": registry_version,
            "metadata_uri": metadata_uri,
            "metadata_hash": metadata_hash,
            "sealed_artifact_commitment": sealed_artifact_commitment,
            "evaluator_commitment": evaluator_commitment,
        }
        normalized_tee = {
            "compose_hash": compose_hash,
            "app_id": app_id,
            "os_image_hash": os_image_hash,
            "tee_signer_address": tee_signer,
        }
        expected_policy_commitment = compute_arena_release_policy_commitment(
            chain_id=chain_id,
            challenge_registry_address=registry_address,
            challenge_registry_runtime_code_hash=registry_code_hash,
            approved_challenge_set_sha256=approved_set_sha256,
            binding=normalized_binding,
            tee_release=normalized_tee,
            trusted_qvl_verifier_addresses=trusted,
            max_qvl_verdict_age_seconds=max_age,
            execution_policy_canonicalization_version=canonicalization_version,
            execution_policy_approval_schema=approval_schema,
            execution_policy_api_schema_version=api_schema_version,
            execution_policy_store_schema_version=store_schema_version,
            execution_policy_approval_domain=approval_domain,
            execution_policy_approval_domain_hash=approval_domain_hash,
            execution_policy_approver_hashes=approver_hashes,
            execution_policy_approver_root_hash=approver_root_hash,
            execution_policy_rollback_anchor=normalized_anchor,
        )
        if not hmac.compare_digest(
            release_policy_commitment, expected_policy_commitment
        ):
            raise ValueError("release policy commitment mismatch")

        return ArenaWorkerReleasePins(
            chain_id=chain_id,
            challenge_registry_address=registry_address,
            challenge_registry_runtime_code_hash=registry_code_hash,
            approved_challenge_bindings=approved_bindings,
            approved_challenge_set_sha256=approved_set_sha256,
            challenge_binding=ArenaChallengeReleaseBinding(
                **normalized_binding,
                release_policy_commitment=release_policy_commitment,
                controller_address=selected_approval["controller_address"],
                pending_controller_address=selected_approval[
                    "pending_controller_address"
                ],
            ),
            tee_release=ArenaTeeReleasePins(
                compose_hash=compose_hash,
                app_id=app_id,
                os_image_hash=os_image_hash,
                tee_signer_address=tee_signer,
            ),
            trusted_qvl_verifier_addresses=trusted,
            max_qvl_verdict_age_seconds=max_age,
            execution_policy_canonicalization_version=canonicalization_version,
            execution_policy_approval_schema=approval_schema,
            execution_policy_api_schema_version=api_schema_version,
            execution_policy_store_schema_version=store_schema_version,
            execution_policy_approval_domain=approval_domain,
            execution_policy_approval_domain_hash=approval_domain_hash,
            execution_policy_approver_hashes=approver_hashes,
            execution_policy_approver_root_hash=approver_root_hash,
            execution_policy_rollback_anchor=(
                ArenaExecutionPolicyRollbackAnchorPins(**normalized_anchor)
            ),
        )
    except ArenaWorkerBootstrapError:
        raise
    except Exception as exc:
        raise ArenaWorkerBootstrapError("release_manifest_invalid") from exc


def load_sealed_evaluator(
    settings: Settings,
    *,
    pins: ArenaWorkerReleasePins,
) -> DnaseqVariantQcSafeIrEvaluator:
    path = str(settings.arena_worker_evaluator_path or "").strip()
    if not path:
        raise ArenaWorkerBootstrapError("worker_configuration_missing")
    try:
        raw = _secure_read_0600(path, maximum=MAX_SECURE_JSON_BYTES)
        payload = _json_object(raw, label="sealed evaluator")
        _exact_keys(payload, _EVALUATOR_FIELDS)
        challenge = default_challenge_catalog().get(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        )
        if (
            payload["schema"] != EVALUATOR_SCHEMA
            or payload["challenge_id"] != DNASEQ_SAFE_IR_CHALLENGE_ID
            or payload["challenge_version"] != DNASEQ_SAFE_IR_CHALLENGE_VERSION
            or payload["challenge_manifest_hash"] != challenge.manifest_hash
            or payload["runtime"] != SAFE_IR_RUNTIME
            or payload["runtime_policy_commitment"] != SAFE_IR_POLICY_COMMITMENT
            or payload["synthetic_only"] is not True
        ):
            raise ValueError("sealed evaluator binding mismatch")
        if sealed_evaluator_commitment(payload) != (
            pins.challenge_binding.sealed_artifact_commitment
        ):
            raise ValueError("sealed evaluator commitment mismatch")
        positive = _controls(payload["positive_controls"])
        negative = _controls(payload["negative_controls"])
        return DnaseqVariantQcSafeIrEvaluator(positive, negative)
    except ArenaWorkerBootstrapError:
        raise
    except Exception as exc:
        raise ArenaWorkerBootstrapError("sealed_evaluator_invalid") from exc


def load_independent_qvl_verdict(
    settings: Settings,
    *,
    client: httpx.Client | None = None,
) -> IndependentAttestationVerdict:
    """Load a precomputed verdict for offline/unit verification only.

    The real-dstack executable never calls this function. Production requires
    :class:`HttpsArenaQvlClient` so each job authorizes its newly collected
    quote rather than reusing a startup verdict.
    """

    del client
    file_path = str(settings.arena_worker_qvl_verdict_path or "").strip()
    url = str(settings.arena_worker_qvl_verdict_url or "").strip()
    if not file_path or url:
        raise ArenaWorkerBootstrapError("worker_configuration_missing")
    try:
        raw = _secure_read_0600(file_path, maximum=MAX_SECURE_JSON_BYTES)
        payload = _json_object(raw, label="independent QVL verdict")
        return independent_attestation_verdict_from_public_dict(payload)
    except ArenaWorkerBootstrapError:
        raise
    except Exception as exc:
        raise ArenaWorkerBootstrapError("independent_qvl_unavailable") from exc


def validate_fresh_challenge_registry(
    pins: ArenaWorkerReleasePins,
    reader: ArenaRegistryReader,
    *,
    now: int,
    request: ArenaRegistryClaimRequest,
) -> ArenaWorkerRegistryAuthorization:
    """Authorize one exact claim at a stable, fresh finalized block.

    The returned snapshot commitment includes ``request.sha256``. That request
    in turn commits to the canonical ingress AEAD binding and the proxy's own
    finalized registry authorization digest, so this worker read cannot be
    replayed onto a different sealed envelope.
    """

    try:
        if not isinstance(request, ArenaRegistryClaimRequest):
            raise ValueError("invalid registry claim request")
        binding = pins.challenge_binding
        if (
            request.challenge_id != binding.catalog_challenge_id
            or request.challenge_version != binding.catalog_challenge_version
            or request.challenge_manifest_hash != binding.catalog_manifest_hash
        ):
            raise ValueError("claim request is not release-pinned")
        if reader.chain_id() != BASE_SEPOLIA_CHAIN_ID:
            raise ValueError("wrong chain")
        finalized = reader.finalized_block()
        if (
            isinstance(now, bool)
            or not isinstance(now, int)
            or now < 1
            or finalized.timestamp > now + MAX_FUTURE_BLOCK_SKEW_SECONDS
            or now - finalized.timestamp > MAX_BLOCK_AGE_SECONDS
        ):
            raise ValueError("stale finalized block")
        before = reader.block(finalized.number)
        if before != finalized:
            raise ValueError("finalized block is noncanonical")
        block_number = finalized.number
        address = pins.challenge_registry_address
        code = reader.bytecode(address, block_number)
        if not code or "0x" + keccak(code).hex() != (
            pins.challenge_registry_runtime_code_hash
        ):
            raise ValueError("registry bytecode mismatch")
        registry_paused = reader.registry_paused(address, block_number)
        if registry_paused:
            raise ValueError("registry paused")
        challenge_exists = reader.challenge_exists(
            address, binding.registry_challenge_id, block_number
        )
        if not challenge_exists:
            raise ValueError("challenge missing")
        challenge = reader.challenge(
            address, binding.registry_challenge_id, block_number
        )
        if (
            challenge.controller != binding.controller_address
            or challenge.pending_controller != binding.pending_controller_address
            or challenge.lifecycle != 1
            or challenge.paused
            or not challenge.configuration_frozen
            or challenge.latest_version != binding.registry_version
        ):
            raise ValueError("challenge is not frozen and open")
        version = reader.version(
            address,
            binding.registry_challenge_id,
            binding.registry_version,
            block_number,
        )
        if version != ArenaRegistryVersionState(
            metadata_uri=binding.metadata_uri,
            metadata_hash=binding.metadata_hash,
            sealed_artifact_commitment=binding.sealed_artifact_commitment,
            evaluator_commitment=binding.evaluator_commitment,
            release_policy_commitment=binding.release_policy_commitment,
        ):
            raise ValueError("challenge version commitment mismatch")
        after = reader.block(block_number)
        finalized_after = reader.finalized_block()
        if before != after:
            raise ValueError("registry block changed during verification")
        if finalized_after != finalized:
            raise ValueError("finalized block advanced during verification")

        snapshot = {
            "schema": REGISTRY_CLAIM_AUTHORIZATION_SCHEMA,
            "verification_model": REGISTRY_CLAIM_VERIFICATION_MODEL,
            "claim_request_sha256": request.sha256,
            "ingress_registry_authorization_sha256": (
                request.ingress_registry_authorization_sha256
            ),
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "block_number": str(finalized.number),
            "block_hash": finalized.block_hash,
            "block_timestamp": str(finalized.timestamp),
            "registry_address": address,
            "registry_runtime_code_hash": pins.challenge_registry_runtime_code_hash,
            "approved_challenge_set_sha256": pins.approved_challenge_set_sha256,
            "catalog_challenge_id": binding.catalog_challenge_id,
            "catalog_challenge_version": binding.catalog_challenge_version,
            "catalog_manifest_hash": binding.catalog_manifest_hash,
            "runtime": binding.runtime,
            "runtime_policy_commitment": binding.runtime_policy_commitment,
            "registry_challenge_id": str(binding.registry_challenge_id),
            "registry_version": binding.registry_version,
            "controller_address": challenge.controller,
            "pending_controller_address": challenge.pending_controller,
            "metadata_uri": version.metadata_uri,
            "metadata_hash": version.metadata_hash,
            "sealed_artifact_commitment": version.sealed_artifact_commitment,
            "evaluator_commitment": version.evaluator_commitment,
            "release_policy_commitment": version.release_policy_commitment,
            "registry_paused": registry_paused,
            "challenge_exists": challenge_exists,
            "challenge_paused": challenge.paused,
            "lifecycle": challenge.lifecycle,
            "configuration_frozen": challenge.configuration_frozen,
            "latest_version": challenge.latest_version,
        }
        snapshot_sha256 = "sha256:" + hashlib.sha256(
            REGISTRY_CLAIM_AUTHORIZATION_DOMAIN + _canonical_json(snapshot)
        ).hexdigest()
        return ArenaWorkerRegistryAuthorization(
            claim_request_sha256=request.sha256,
            registry_snapshot_sha256=snapshot_sha256,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            block_number=finalized.number,
            block_hash=finalized.block_hash,
            block_timestamp=finalized.timestamp,
            registry_address=address,
            registry_challenge_id=binding.registry_challenge_id,
            registry_version=binding.registry_version,
        )
    except ArenaWorkerBootstrapError:
        raise
    except Exception as exc:
        raise ArenaWorkerBootstrapError("challenge_registry_unavailable") from exc


class RefreshingArenaRegistryClaimGate:
    """Re-read and authorize ChallengeRegistry immediately before each claim."""

    def __init__(
        self,
        *,
        pins: ArenaWorkerReleasePins,
        reader: ArenaRegistryReader,
        owns_reader: bool,
    ) -> None:
        if not isinstance(pins, ArenaWorkerReleasePins):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        if reader is None or not all(
            callable(getattr(reader, method, None))
            for method in (
                "chain_id",
                "finalized_block",
                "block",
                "bytecode",
                "registry_paused",
                "challenge_exists",
                "challenge",
                "version",
            )
        ):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        if not isinstance(owns_reader, bool):
            raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
        self._pins = pins
        self._reader = reader
        self._owns_reader = owns_reader

    def __repr__(self) -> str:
        return "RefreshingArenaRegistryClaimGate(finalized_read_per_claim=True)"

    def authorize_arena_claim(
        self,
        request: ArenaRegistryClaimRequest,
        *,
        occurred_at: int,
    ) -> ArenaWorkerRegistryAuthorization:
        try:
            return validate_fresh_challenge_registry(
                self._pins,
                self._reader,
                now=occurred_at,
                request=request,
            )
        except ArenaWorkerBootstrapError as exc:
            raise ArenaSafeWorkerRegistryUnavailable(
                "Arena finalized registry authorization is unavailable"
            ) from exc

    def close(self) -> None:
        if not self._owns_reader:
            return
        self._owns_reader = False
        try:
            self._reader.close()
        except Exception:
            # A read-only transport close must not leak transport-specific
            # detail into the worker's bounded status surface.
            pass


def build_arena_worker_service_from_settings(
    settings: Settings,
    *,
    now: int | None = None,
    registry_reader: ArenaRegistryReader | None = None,
    qvl_http_client: httpx.Client | None = None,
) -> ArenaSafeWorkerService:
    """Construct the sole production worker path from trusted release inputs."""

    checked_at = int(time.time() if now is None else now)
    if (
        not dstack_utils.is_dstack_enabled()
        or dstack_utils.is_dstack_simulator()
        or os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "").strip()
    ):
        raise ArenaWorkerBootstrapError("real_dstack_required")
    if (
        str(settings.arena_candidate_ingress_private_key_hex or "").strip()
        or str(settings.arena_candidate_ingress_local_key_file or "").strip()
    ):
        raise ArenaWorkerBootstrapError("real_dstack_required")
    arena_store_path = str(settings.arena_store_path or "").strip()
    ingress_store_path = str(
        settings.arena_candidate_ingress_store_path or ""
    ).strip()
    policy_store_path = str(settings.execution_policy_store_path or "").strip()
    rpc_url = str(settings.chain_rpc_url or "").strip()
    anchor_rpc_url = str(
        settings.execution_policy_anchor_rpc_url or ""
    ).strip()
    if not all(
        (
            arena_store_path,
            ingress_store_path,
            policy_store_path,
            rpc_url,
            anchor_rpc_url,
        )
    ):
        raise ArenaWorkerBootstrapError("worker_configuration_missing")
    try:
        arena_integrity_key = arena_store_integrity_key(settings)
    except Exception as exc:
        raise ArenaWorkerBootstrapError("worker_configuration_missing") from exc

    pins = load_release_manifest(settings)
    anchor_pins = pins.execution_policy_rollback_anchor
    if (
        str(settings.execution_policy_anchor_address or "").lower()
        != anchor_pins.contract_address
        or str(
            settings.execution_policy_anchor_runtime_code_hash or ""
        ).lower()
        != anchor_pins.runtime_code_hash
        or str(
            settings.execution_policy_anchor_writer_address or ""
        ).lower()
        != anchor_pins.writer_address
        or str(
            settings.execution_policy_anchor_writer_release_commitment or ""
        ).lower()
        != anchor_pins.writer_release_commitment
        or str(settings.execution_policy_anchor_writer_key_path or "")
        != anchor_pins.writer_key_path
        or settings.execution_policy_anchor_confirmations
        != anchor_pins.confirmations
        or settings.execution_policy_anchor_max_block_age_seconds
        != anchor_pins.max_block_age_seconds
        or settings.execution_policy_anchor_max_future_block_skew_seconds
        != anchor_pins.max_future_block_skew_seconds
    ):
        raise ArenaWorkerBootstrapError("execution_policy_anchor_unavailable")
    try:
        (
            current_domain_hash,
            approved_approver_hashes,
            current_approver_root_hash,
        ) = (
            execution_policy_trust_context(settings)
        )
        if (
            not hmac.compare_digest(
                current_domain_hash,
                pins.execution_policy_approval_domain_hash,
            )
            or not hmac.compare_digest(
                current_approver_root_hash,
                pins.execution_policy_approver_root_hash,
            )
            or tuple(sorted(approved_approver_hashes))
            != pins.execution_policy_approver_hashes
        ):
            raise ArenaWorkerBootstrapError("execution_policy_unavailable")
        policy_integrity_key = execution_policy_integrity_key(settings)
    except ArenaWorkerBootstrapError:
        raise
    except Exception as exc:
        raise ArenaWorkerBootstrapError("execution_policy_unavailable") from exc

    try:
        recipient = resolve_arena_recipient(
            settings,
            root_path=ingress_store_path,
        )
    except Exception as exc:
        raise ArenaWorkerBootstrapError("real_dstack_required") from exc
    if not isinstance(recipient, ArenaIngressRecipient) or recipient.custody_mode != "dstack":
        raise ArenaWorkerBootstrapError("real_dstack_required")

    evaluator = load_sealed_evaluator(settings, pins=pins)
    qvl_file = str(settings.arena_worker_qvl_verdict_path or "").strip()
    qvl_url = str(settings.arena_worker_qvl_verdict_url or "").strip()
    if qvl_file or not qvl_url:
        # Precomputed verdicts are useful for offline parser tests only. A real
        # CVM must authorize the exact quote freshly collected for each job.
        raise ArenaWorkerBootstrapError("independent_qvl_unavailable")
    qvl_token = os.environ.get(QVL_AUTH_TOKEN_ENV, "")
    from tinker_delegate.execution_policy_anchor import (
        HttpsExecutionPolicyAnchorGateway,
    )

    try:
        anchor_gateway = HttpsExecutionPolicyAnchorGateway.from_settings(
            settings, read_only=True
        )
        # Startup authorization reads the active frozen release at a fresh,
        # sufficiently confirmed canonical block before any queue work.
        anchor_gateway.finalized_snapshot(now=checked_at)
    except Exception as exc:
        raise ArenaWorkerBootstrapError(
            "execution_policy_anchor_unavailable"
        ) from exc
    reader = registry_reader
    owns_reader = reader is None
    try:
        if reader is None:
            reader = HttpsArenaRegistryReader(rpc_url)
        registry_claim_gate = RefreshingArenaRegistryClaimGate(
            pins=pins,
            reader=reader,
            owns_reader=owns_reader,
        )
    except ArenaWorkerBootstrapError:
        anchor_gateway.close()
        raise
    except Exception as exc:
        anchor_gateway.close()
        raise ArenaWorkerBootstrapError("challenge_registry_unavailable") from exc

    qvl_provider: HttpsArenaQvlClient | None = None
    try:
        qvl_provider = HttpsArenaQvlClient(
            qvl_url,
            auth_token=qvl_token,
            client=qvl_http_client,
            trusted_verifier_addresses=pins.trusted_qvl_verifier_addresses,
            expected_policy_hash=settings.arena_worker_qvl_release_policy_hash,
            chain_id=pins.chain_id,
            cvm_id=settings.main_runtime_cvm_id,
            deployment_intent_sha256=settings.release_deployment_intent_sha256,
            release_authority_sha256=settings.release_authority_sha256,
            ceremony_nonce=settings.release_ceremony_nonce,
            measurement_policy_sha256=settings.arena_qvl_measurement_policy_sha256,
        )
        activation_provider = RefreshingArenaActivationProvider(
            recipient=recipient,
            verdict_provider=qvl_provider,
            trusted_verifier_addresses=pins.trusted_qvl_verifier_addresses,
            expected_compose_hash=pins.tee_release.compose_hash,
            expected_app_id=pins.tee_release.app_id,
            expected_os_image_hash=pins.tee_release.os_image_hash,
            expected_tee_signer_address=pins.tee_release.tee_signer_address,
            chain_id=pins.chain_id,
            challenge_registry_address=pins.challenge_registry_address,
            max_verdict_age_seconds=pins.max_qvl_verdict_age_seconds,
        )
        return build_verified_arena_worker_service(
            arena_store_path=arena_store_path,
            arena_store_integrity_key=arena_integrity_key,
            ingress_store_path=ingress_store_path,
            recipient=recipient,
            evaluator=evaluator,
            activation_provider=activation_provider,
            registry_claim_gate=registry_claim_gate,
            execution_policy_store_path=policy_store_path,
            execution_policy_integrity_key=policy_integrity_key,
            execution_policy_approval_domain_hash=current_domain_hash,
            execution_policy_approver_root_hash=(
                current_approver_root_hash
            ),
            execution_policy_approved_approver_hashes=(
                approved_approver_hashes
            ),
            execution_policy_anchor_gateway=anchor_gateway,
            poll_interval_seconds=settings.arena_worker_poll_interval_seconds,
        )
    except Exception as exc:
        anchor_gateway.close()
        registry_claim_gate.close()
        if qvl_provider is not None:
            qvl_provider.close()
        raise ArenaWorkerBootstrapError("worker_initialization_failed") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tinker-arena-worker",
        description=(
            "Run the release-pinned, attested dnai-safe-ir-v1 Arena worker"
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="process at most one queue poll, for supervisor readiness checks",
    )
    return parser


def arena_worker_release_bindings(
    settings: Settings,
    pins: ArenaWorkerReleasePins,
) -> ArenaWorkerReleaseBindings:
    """Build the exact public heartbeat binding from validated release inputs."""

    challenge = default_challenge_catalog().get(
        DNASEQ_SAFE_IR_CHALLENGE_ID,
        DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    )
    return ArenaWorkerReleaseBindings(
        release_sha=str(settings.arena_worker_release_sha or "").strip(),
        image_digest=str(settings.arena_worker_image_digest or "").strip(),
        release_manifest_sha256=str(
            settings.arena_worker_release_manifest_sha256 or ""
        ).strip(),
        approved_challenge_set_sha256=pins.approved_challenge_set_sha256,
        approved_challenge_key=(
            f"{DNASEQ_SAFE_IR_CHALLENGE_ID}@{DNASEQ_SAFE_IR_CHALLENGE_VERSION}"
        ),
        release_policy_commitment=(
            pins.challenge_binding.release_policy_commitment
        ),
        catalog_manifest_hash=challenge.manifest_hash,
        runtime=SAFE_IR_RUNTIME,
        runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        compose_hash=pins.tee_release.compose_hash,
        app_id=pins.tee_release.app_id,
        os_image_hash=pins.tee_release.os_image_hash,
    )


def build_arena_worker_heartbeat_sink(settings: Settings):
    """Return the durable sink only for an explicitly enabled live release."""

    if not settings.arena_worker_live_capability_enabled:
        return None
    path = str(settings.arena_worker_heartbeat_path or "").strip()
    if not path:
        raise ArenaWorkerEvidenceError("worker heartbeat path is unavailable")
    pins = load_release_manifest(settings)
    bindings = arena_worker_release_bindings(settings, pins)
    store = ArenaWorkerHeartbeatStore(
        path,
        integrity_key=arena_worker_heartbeat_integrity_key(settings),
    )

    def sink(status, observed_at: int) -> None:
        store.write(
            ArenaWorkerHeartbeat(
                bindings=bindings,
                observed_at=observed_at,
                state=worker_status_state(status.state),
            )
        )

    return sink


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    heartbeat_sink = None
    service: ArenaSafeWorkerService | None = None
    try:
        settings = Settings()
        service = build_arena_worker_service_from_settings(settings)
        heartbeat_sink = build_arena_worker_heartbeat_sink(settings)
    except ArenaWorkerBootstrapError as exc:
        if service is not None:
            try:
                service.close()
            except Exception:
                pass
        write_bounded_bootstrap_failure(exc.reason, sys.stdout)
        return EXIT_ACTIVATION_UNAVAILABLE
    except Exception:
        if service is not None:
            try:
                service.close()
            except Exception:
                pass
        write_bounded_bootstrap_failure("worker_initialization_failed", sys.stdout)
        return EXIT_ACTIVATION_UNAVAILABLE
    assert service is not None
    try:
        return run_arena_worker_process(
            service,
            status_sink=lambda status: write_bounded_worker_status(
                status, sys.stdout
            ),
            heartbeat_sink=heartbeat_sink,
            max_iterations=1 if args.once else None,
        )
    except KeyboardInterrupt:
        return 0
    except Exception:
        write_bounded_bootstrap_failure("worker_initialization_failed", sys.stdout)
        return EXIT_ACTIVATION_UNAVAILABLE
    finally:
        if heartbeat_sink is not None:
            try:
                heartbeat_sink(
                    ArenaWorkerStatus(
                        state="stopped",
                        submission_id=None,
                        final_state=None,
                        recovery=False,
                        failure_code="none",
                    ),
                    int(time.time()),
                )
            except Exception:
                pass
        service.close()


def write_bounded_bootstrap_failure(reason: str, stream: TextIO) -> None:
    if reason not in ArenaWorkerBootstrapError._REASONS:
        reason = "worker_initialization_failed"
    payload = {
        "surface": "arena_safe_worker_bootstrap",
        "schema_version": BOOTSTRAP_STATUS_SCHEMA_VERSION,
        "started": False,
        "reason": reason,
        "runtime": SAFE_IR_RUNTIME,
        "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
        "raw_candidate_egress": False,
        "ciphertext_egress": False,
        "sealed_evaluator_egress": False,
        "exception_detail_egress": False,
    }
    stream.write(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )
    stream.flush()


def _secure_read_0600(path: str | Path, *, maximum: int) -> bytes:
    text = str(path)
    if not text or "\x00" in text:
        raise ValueError("secure file path is invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(text, flags)
    try:
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or details.st_size < 2
            or details.st_size > maximum
        ):
            raise ValueError("secure file metadata is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) != details.st_size or len(raw) > maximum:
            raise ValueError("secure file size changed")
        return raw
    finally:
        os.close(fd)


def _bounded_response_body(response: httpx.Response, maximum: int) -> bytes:
    length = response.headers.get("content-length")
    if length is not None:
        try:
            parsed_length = int(length)
        except ValueError as exc:
            raise ValueError("response length is invalid") from exc
        if parsed_length < 0 or parsed_length > maximum:
            raise ValueError("response is too large")
    output = bytearray()
    for chunk in response.iter_bytes():
        if len(chunk) > maximum - len(output):
            raise ValueError("response is too large")
        output.extend(chunk)
    if not output:
        raise ValueError("response is empty")
    return bytes(output)


def _json_object(raw: bytes, *, label: str) -> dict[str, Any]:
    del label

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON object key")
            output[key] = value
        return output

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        payload = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        # JSON decoder exceptions retain the source document. Do not attach
        # them to an error that can cross the sealed evaluator boundary.
        raise ValueError("JSON is invalid") from None
    if not isinstance(payload, dict):
        raise ValueError("JSON root is invalid")
    return payload


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ValueError("value is not canonical JSON") from exc


def _exact_keys(value: Mapping[str, Any], expected: frozenset[str]) -> None:
    if set(value) != expected:
        raise ValueError("object fields do not match")


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("object is required")
    return value


def _integer(value: Any, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("integer is required")
    if value < minimum or value > maximum:
        raise ValueError("integer is outside bounds")
    return value


def _decimal_uint(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"^[1-9][0-9]{0,77}$", value):
        raise ValueError("decimal uint is invalid")
    parsed = int(value)
    if parsed >= 2**256:
        raise ValueError("decimal uint is outside uint256")
    return parsed


def _address(value: Any) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise ValueError("address is invalid")
    normalized = value.lower()
    if int(normalized[2:], 16) == 0:
        raise ValueError("address is zero")
    return normalized


def _bytes32(value: Any) -> str:
    if not isinstance(value, str) or not _BYTES32.fullmatch(value):
        raise ValueError("bytes32 is invalid")
    if value == "0x" + "0" * 64:
        raise ValueError("bytes32 is zero")
    return value


def _bare_bytes32(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise ValueError("bare bytes32 is invalid")
    if value == "0" * 64:
        raise ValueError("bare bytes32 is zero")
    return value


def _ascii(value: Any, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("ASCII value is invalid")
    return value


def _controls(value: Any) -> tuple[float, ...]:
    if not isinstance(value, list) or not 2 <= len(value) <= 512:
        raise ValueError("evaluator controls are invalid")
    if any(isinstance(item, bool) or not isinstance(item, (int, float)) for item in value):
        raise ValueError("evaluator controls are invalid")
    controls = tuple(float(item) for item in value)
    if not all(math.isfinite(item) for item in controls):
        raise ValueError("evaluator controls are invalid")
    return controls


def _https_url(value: str, *, label: str) -> str:
    del label
    if not isinstance(value, str) or value != value.strip():
        raise ValueError("HTTPS endpoint is invalid")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("HTTPS endpoint is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("HTTPS endpoint is invalid")
    return value


def _quantity(value: Any, *, label: str) -> int:
    del label
    if not isinstance(value, str) or not re.fullmatch(r"^0x(?:0|[1-9a-f][0-9a-f]*)$", value):
        raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
    return int(value, 16)


def _quantity_hex(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("quantity is invalid")
    return hex(value)


def _hex_bytes(value: Any, *, label: str, maximum: int) -> bytes:
    del label
    if (
        not isinstance(value, str)
        or not value.startswith("0x")
        or len(value) % 2 != 0
        or len(value) > 2 + maximum * 2
    ):
        raise ArenaWorkerBootstrapError("challenge_registry_unavailable")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise ArenaWorkerBootstrapError("challenge_registry_unavailable") from exc


def _uint_word(value: int) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**256:
        raise ValueError("uint256 is invalid")
    return value.to_bytes(32, "big")


def _decode_bool(raw: bytes) -> bool:
    if len(raw) != 32 or raw[:-1] != b"\0" * 31 or raw[-1] not in (0, 1):
        raise ValueError("boolean ABI result is invalid")
    return raw[-1] == 1


def _decode_challenge(raw: bytes) -> ArenaRegistryChallengeState:
    if len(raw) != 8 * 32:
        raise ValueError("challenge ABI result is invalid")
    words = [raw[index : index + 32] for index in range(0, len(raw), 32)]
    if words[0][:-20] != b"\0" * 12 or words[1][:-20] != b"\0" * 12:
        raise ValueError("challenge address is invalid")
    controller = "0x" + words[0][-20:].hex()
    pending_controller = "0x" + words[1][-20:].hex()
    lifecycle = int.from_bytes(words[2], "big")
    latest = int.from_bytes(words[5], "big")
    paused = _decode_bool(words[6])
    frozen = _decode_bool(words[7])
    if (
        int(controller[2:], 16) == 0
        or lifecycle > 4
        or int.from_bytes(words[3], "big") >= 2**64
        or int.from_bytes(words[4], "big") >= 2**64
        or latest >= 2**32
    ):
        raise ValueError("challenge ABI values are invalid")
    return ArenaRegistryChallengeState(
        controller=controller,
        pending_controller=pending_controller,
        lifecycle=lifecycle,
        latest_version=latest,
        paused=paused,
        configuration_frozen=frozen,
    )


def _decode_version(raw: bytes) -> ArenaRegistryVersionState:
    # One returned tuple containing a dynamic string: a top-level tuple offset,
    # six tuple head words, then the padded UTF-8 metadata URI.
    if len(raw) < 8 * 32 or len(raw) % 32 != 0:
        raise ValueError("version ABI result is invalid")
    tuple_start = int.from_bytes(raw[:32], "big")
    if tuple_start != 32 or tuple_start + 6 * 32 > len(raw):
        raise ValueError("version ABI tuple offset is invalid")
    words = [
        raw[tuple_start + index * 32 : tuple_start + (index + 1) * 32]
        for index in range(6)
    ]
    string_offset = int.from_bytes(words[0], "big")
    if string_offset != 6 * 32:
        raise ValueError("version ABI string offset is invalid")
    string_start = tuple_start + string_offset
    if string_start + 32 > len(raw):
        raise ValueError("version ABI string is truncated")
    string_length = int.from_bytes(raw[string_start : string_start + 32], "big")
    padded_length = ((string_length + 31) // 32) * 32
    if (
        not 1 <= string_length <= 256
        or string_start + 32 + padded_length != len(raw)
        or any(raw[string_start + 32 + string_length :])
    ):
        raise ValueError("version ABI string length is invalid")
    try:
        metadata_uri = raw[
            string_start + 32 : string_start + 32 + string_length
        ].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("version ABI metadata URI is invalid") from exc
    _ascii(metadata_uri, _METADATA_URI)
    if int.from_bytes(words[5], "big") >= 2**64:
        raise ValueError("version ABI timestamp is invalid")
    commitments = tuple("0x" + word.hex() for word in words[1:5])
    for commitment in commitments:
        _bytes32(commitment)
    return ArenaRegistryVersionState(
        metadata_uri=metadata_uri,
        metadata_hash=commitments[0],
        sealed_artifact_commitment=commitments[1],
        evaluator_commitment=commitments[2],
        release_policy_commitment=commitments[3],
    )


if __name__ == "__main__":
    raise SystemExit(main())
