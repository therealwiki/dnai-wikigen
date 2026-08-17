"""Credential-free, idempotent Collaboration-to-Compute handoff core.

This module turns an already-recorded Collaboration joint-consent snapshot
into one exact, one-shot execution authorization.  It deliberately owns no
HTTP routes, wallet verification, provider credentials, TDX evidence, QVL
verdicts, or settlement broadcasts.  Those integration boundaries must supply
fresh current-state observations through :class:`ClaimAuthoritySnapshot`.

The journal is a local, HMAC-authenticated, copy-on-write state machine.  It
detects mutation but does not claim monotonic or distributed storage.  A
durable, deterministic Compute handoff is written before an external caller
submits it to the existing Compute authority.  Collaboration never calls a
provider. Provider-boundary ambiguity and bounded results are accepted only as
a typed, handoff-bound Compute projection. This source-capable core validates
the projection's complete binding but cannot authenticate its journal origin;
production wiring must construct it only through a trusted Compute-journal
reader and must never expose it as a client DTO. Recovery returns idempotent
handoff/reconciliation instructions and never performs an automatic provider
redispatch.

Only commitments, bounded policy metadata, wallet addresses, and bounded
result codes are persisted.  Raw prompts, examples, artifacts, results,
provider account IDs, and provider request IDs are outside the schema.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from enum import Enum
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from contextlib import contextmanager
from typing import Any, Callable, Iterator, Mapping, Sequence

from eth_abi import encode as abi_encode
from eth_hash.auto import keccak

from tinker_delegate.royalty_distribution_plan import (
    DistributionRecipient,
    compute_owner_amounts_hash,
)
from tinker_delegate.compute_runtime import (
    ComputeDispatchIntent,
    INFERENCE_WORKLOAD_SCHEMA,
    SFT_JSONL_WORKLOAD_SCHEMA,
    compute_collaboration_one_shot_authorization_context_commitment,
)


BASIS_SCHEMA = "dnai.collaboration.execution-basis.v2"
INTENT_SCHEMA = "dnai.collaboration.execution-intent.v2"
GRANT_SCHEMA = "dnai.collaboration.one-shot-execution-grant.v1"
RESULT_SCHEMA = "dnai.collaboration.bounded-execution-result.v1"
VAULT_OBSERVATION_SCHEMA = "dnai.collaboration.finalized-compute-vault-observation.v1"
ROYALTY_OBSERVATION_SCHEMA = "dnai.collaboration.finalized-royalty-authority-observation.v1"
COMPUTE_HANDOFF_SCHEMA = "dnai.collaboration.compute-handoff.v2"
COMPUTE_PROJECTION_SCHEMA = "dnai.collaboration.compute-journal-projection.v1"
COMPUTE_SOURCE_JOURNAL_SCHEMA = "dnai.compute.execution-journal.v2"
STORE_SCHEMA = "dnai.collaboration.execution-journal.v2"
BASE_SEPOLIA_CHAIN_ID = 84_532

MAX_STORE_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 4_096
MAX_OWNERS = 16
MAX_AUTHORIZATION_LIFETIME_SECONDS = 86_400
MAX_TIMESTAMP = 4_102_444_800
MAX_UINT256 = 2**256 - 1

_BASIS_DOMAIN = b"dnai-wikigen/collaboration-execution-basis/v2\x00"
_INTENT_DOMAIN = b"dnai-wikigen/collaboration-execution-intent/v2\x00"
_GRANT_DOMAIN = b"dnai-wikigen/collaboration-execution-grant/v1\x00"
_GRANT_SET_DOMAIN = b"dnai-wikigen/collaboration-execution-grant-set/v1\x00"
_AUTHORIZATION_DOMAIN = b"dnai-wikigen/collaboration-execution-authorization/v1\x00"
_EXECUTION_ID_DOMAIN = b"dnai-wikigen/collaboration-execution-id/v1\x00"
_RESULT_BINDING_DOMAIN = b"dnai-wikigen/collaboration-execution-result-binding/v1\x00"
_IDEMPOTENCY_DOMAIN = b"dnai-wikigen/collaboration-execution-idempotency/v1\x00"
_STORE_MAC_DOMAIN = b"dnai-wikigen/collaboration-execution-journal-mac/v1\x00"
_ROYALTY_FUNDING_RESERVATION_TYPE = (
    b"RoyaltyFundingReservation(uint256 chainId,address distributor,address sponsor,"
    b"bytes32 settlementId,uint256 settlementNonce,bytes32 releasePolicyCommitment,"
    b"bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,"
    b"bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,"
    b"address asset,uint256 total,bytes32 executionCommitment,uint256 refundAfter)"
)
ROYALTY_FUNDING_RESERVATION_TYPEHASH = keccak(
    _ROYALTY_FUNDING_RESERVATION_TYPE
)

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x(?!0{64}$)[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_ROOM_ID = re.compile(r"^room_[0-9a-f]{32}$")
_WORKLOAD_ID = re.compile(r"^wrk_[0-9a-f]{32}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_GRANT_ID = re.compile(r"^xgrant_[0-9a-f]{32}$")
_EXECUTION_ID = re.compile(r"^exec_[0-9a-f]{64}$")
_HANDOFF_ID = re.compile(r"^chandoff_[0-9a-f]{64}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_CANONICAL_DECIMAL_UINT = re.compile(r"^(?:0|[1-9][0-9]{0,77})$")

_OPERATIONS = frozenset({"inference", "training"})
_MODELS = frozenset({"qwen3_8b"})
_RESULT_POLICIES = frozenset({"bounded_summary_receipt", "score_band_hash"})
_FINALITY_MODELS = frozenset({"single_rpc_reported_finalized"})
_SCORE_BANDS = frozenset(
    {
        "not_released",
        "top_1_percent",
        "top_5_percent",
        "top_10_percent",
        "middle_80_percent",
        "bottom_10_percent",
    }
)
_COMPUTE_PRE_BOUNDARY_STAGES = frozenset(
    {
        "workload_claim_pending",
        "intent_created",
        "start_prepared",
        "start_broadcast",
        "start_confirmed",
        "provider_dispatching",
    }
)
_COMPUTE_BOUNDARY_STAGES = frozenset(
    {
        "provider_attempt_checkpointed",
        "provider_outcome_ambiguous",
        "usage_finalized",
        "workload_released",
        "metering_pending",
        "metering_decided",
        "settlement_prepared",
        "settlement_broadcast",
        "settled",
    }
)
_COMPUTE_STAGES = _COMPUTE_PRE_BOUNDARY_STAGES | _COMPUTE_BOUNDARY_STAGES | {
    "blocked"
}


class CollaborationExecutionError(ValueError):
    """Base class for malformed or unauthorized execution state."""


class CollaborationExecutionConflict(CollaborationExecutionError):
    """A replay or transition conflicts with the durable journal."""


class CollaborationExecutionNotFound(CollaborationExecutionError):
    """No participant-visible execution record exists."""


class CollaborationExecutionAuthorityError(CollaborationExecutionError):
    """Current room, grant, funding, or release authority is unavailable."""


class CollaborationExecutionAuthorityInvalidated(
    CollaborationExecutionAuthorityError
):
    """A definitive release/room/grant/expiry change cancels this intent."""


class CollaborationExecutionAuthorityUnavailable(
    CollaborationExecutionAuthorityError
):
    """A retryable current-authority observation or funding state is absent."""


class CollaborationExecutionJournalError(CollaborationExecutionError):
    """The authenticated journal is malformed, unsafe, or changed."""


class ExecutionState(str, Enum):
    AUTHORIZED = "authorized"
    QUEUED = "queued"
    CLAIMED = "claimed"
    COMPUTE_HANDOFF_PENDING = "compute_handoff_pending"
    COMPUTE_HANDOFF_CONFIRMED = "compute_handoff_confirmed"
    BOUNDED_RESULT_READY = "bounded_result_ready"
    FAILED = "failed"
    RECONCILIATION_HOLD = "reconciliation_hold"
    AUTHORITY_INVALIDATED = "authority_invalidated"


TERMINAL_STATES = frozenset(
    {
        ExecutionState.BOUNDED_RESULT_READY,
        ExecutionState.FAILED,
        ExecutionState.AUTHORITY_INVALIDATED,
    }
)


@dataclass(frozen=True)
class CollaborationExecutionBasis:
    """Owner-approved, non-circular basis for one Collaboration execution."""

    release_git_sha: str
    release_verification_sha256: str
    chain_id: int
    cvm_id: str
    compose_hash: str
    room_id: str
    room_commitment: str
    room_generation: int
    room_state_commitment: str
    query_ref: str
    query_proposal_commitment: str
    prospective_query_grant_set_commitment: str
    joint_consent_snapshot_commitment: str
    allocation_commitment: str
    owner_addresses: tuple[str, ...]
    compute_project_id: str
    compute_job_id: str
    compute_workload_id: str
    compute_workload_commitment: str
    compute_manifest_commitment: str
    compute_rate_policy_commitment: str
    compute_workload_schema: str
    compute_workload_source_kind: str
    compute_workload_execution_binding_commitment: str
    compute_workload_recipient_release_commitment: str
    compute_vault_address: str
    compute_vault_runtime_code_hash: str
    compute_finality_model: str
    compute_user_address: str
    operation: str
    model: str
    recipe: str
    result_policy: str
    max_prefill_tokens: int
    max_sample_tokens: int
    max_train_tokens: int
    sponsor_address: str
    asset: str
    max_total_asset_debit: int
    max_compute_asset_debit: int
    authorization_nonce: int
    authorization_expiry: int
    royalty_asset: str
    royalty_total: int
    royalty_owner_amounts_hash: str
    royalty_distributor_address: str
    royalty_release_policy_commitment: str
    royalty_release_binding_commitment: str
    royalty_settlement_id: str
    royalty_settlement_nonce: int
    royalty_reservation_safety_seconds: int
    intent_created_at: int

    @classmethod
    def create_with_royalty_owner_amounts(
        cls,
        *,
        royalty_owner_amounts: Mapping[str, int],
        **basis_fields: Any,
    ) -> "CollaborationExecutionBasis":
        """Construct a new basis through the exact-payout validation gate.

        Serialized bases retain only the contract-compatible commitment, so a
        fresh product/API construction path must supply the exact allocation
        here. This rejects missing, extra, duplicate, unsorted, zero, negative,
        overflowing, or incorrectly totaled owner payouts before owner grants
        can bind the basis.
        """

        if "royalty_owner_amounts_hash" in basis_fields:
            raise CollaborationExecutionError(
                "royalty owner amounts hash cannot bypass exact-payout validation"
            )
        try:
            owners = basis_fields["owner_addresses"]
            total = basis_fields["royalty_total"]
        except KeyError as exc:
            raise CollaborationExecutionError(
                "royalty owner amounts require owners and royalty total"
            ) from exc
        return cls.create(
            **basis_fields,
            royalty_owner_amounts_hash=royalty_owner_amounts_hash(
                owner_amounts=royalty_owner_amounts,
                expected_owners=owners,
                expected_total=total,
            ),
        )

    @classmethod
    def create(
        cls,
        *,
        release_git_sha: str,
        release_verification_sha256: str,
        chain_id: int,
        cvm_id: str,
        compose_hash: str,
        room_id: str,
        room_commitment: str,
        room_generation: int,
        room_state_commitment: str,
        query_ref: str,
        query_proposal_commitment: str,
        prospective_query_grant_set_commitment: str,
        joint_consent_snapshot_commitment: str,
        allocation_commitment: str,
        owner_addresses: Sequence[str],
        compute_project_id: str,
        compute_job_id: str,
        compute_workload_id: str,
        compute_workload_commitment: str,
        compute_manifest_commitment: str,
        compute_rate_policy_commitment: str,
        compute_workload_schema: str,
        compute_workload_source_kind: str,
        compute_workload_execution_binding_commitment: str,
        compute_workload_recipient_release_commitment: str,
        compute_vault_address: str,
        compute_vault_runtime_code_hash: str,
        compute_finality_model: str,
        compute_user_address: str,
        operation: str,
        model: str,
        recipe: str,
        result_policy: str,
        max_prefill_tokens: int,
        max_sample_tokens: int,
        max_train_tokens: int,
        sponsor_address: str,
        asset: str,
        max_total_asset_debit: int,
        max_compute_asset_debit: int,
        authorization_nonce: int,
        authorization_expiry: int,
        royalty_asset: str,
        royalty_total: int,
        royalty_owner_amounts_hash: str,
        royalty_distributor_address: str,
        royalty_release_policy_commitment: str,
        royalty_release_binding_commitment: str,
        royalty_settlement_id: str,
        royalty_settlement_nonce: int,
        royalty_reservation_safety_seconds: int,
        intent_created_at: int,
    ) -> "CollaborationExecutionBasis":
        owners = tuple(_address(item, "owner address", allow_zero=False) for item in owner_addresses)
        if not owners or len(owners) > MAX_OWNERS or owners != tuple(sorted(set(owners))):
            raise CollaborationExecutionError(
                "execution owners must be a non-empty sorted unique wallet set"
            )
        created = _timestamp(intent_created_at, "intent creation time")
        expiry = _timestamp(authorization_expiry, "authorization expiry")
        if expiry <= created or expiry - created > MAX_AUTHORIZATION_LIFETIME_SECONDS:
            raise CollaborationExecutionError("execution authorization lifetime is invalid")

        normalized_operation = _choice(operation, _OPERATIONS, "operation")
        normalized_model = _choice(model, _MODELS, "model")
        normalized_recipe = _string(recipe, "recipe", maximum=64)
        normalized_result_policy = _choice(
            result_policy, _RESULT_POLICIES, "result policy"
        )
        prefill = _integer(
            max_prefill_tokens,
            "maximum prefill tokens",
            minimum=0,
            maximum=32_768,
        )
        sample = _integer(
            max_sample_tokens,
            "maximum sample tokens",
            minimum=0,
            maximum=4_096,
        )
        train = _integer(
            max_train_tokens,
            "maximum training tokens",
            minimum=0,
            maximum=10_000_000,
        )
        if normalized_operation == "inference":
            if normalized_recipe != "qwen3_8b_bounded" or prefill == 0 or sample == 0 or train != 0:
                raise CollaborationExecutionError("inference recipe or limits are invalid")
        elif (
            normalized_recipe != "qwen3_8b_lora_r32"
            or prefill != 0
            or sample != 0
            or train == 0
        ):
            raise CollaborationExecutionError("training recipe or limits are invalid")
        workload_schema = _choice(
            compute_workload_schema,
            {INFERENCE_WORKLOAD_SCHEMA, SFT_JSONL_WORKLOAD_SCHEMA},
            "Compute workload schema",
        )
        expected_workload_schema = (
            INFERENCE_WORKLOAD_SCHEMA
            if normalized_operation == "inference"
            else SFT_JSONL_WORKLOAD_SCHEMA
        )
        if workload_schema != expected_workload_schema:
            raise CollaborationExecutionError(
                "Compute workload schema does not match the operation"
            )

        normalized_asset = _address(asset, "funding asset", allow_zero=True)
        normalized_royalty_asset = _address(
            royalty_asset, "royalty asset", allow_zero=True
        )
        if normalized_royalty_asset != normalized_asset:
            raise CollaborationExecutionError(
                "royalty asset must equal the exact funded execution asset"
            )
        total_debit = _integer(
            max_total_asset_debit,
            "maximum total asset debit",
            minimum=1,
            maximum=MAX_UINT256,
        )
        compute_debit = _integer(
            max_compute_asset_debit,
            "maximum Compute asset debit",
            minimum=1,
            maximum=MAX_UINT256,
        )
        royalty = _integer(
            royalty_total,
            "royalty total",
            minimum=1,
            maximum=MAX_UINT256,
        )
        if compute_debit + royalty > total_debit:
            raise CollaborationExecutionError(
                "maximum Compute debit plus royalty total exceeds maximum total debit"
            )
        normalized_chain = _integer(
            chain_id, "chain id", minimum=1, maximum=2**63 - 1
        )
        if normalized_chain != BASE_SEPOLIA_CHAIN_ID:
            raise CollaborationExecutionError(
                "collaboration execution v1 is restricted to Base Sepolia"
            )

        return cls(
            release_git_sha=_pattern(
                release_git_sha, _GIT_SHA, "release git SHA"
            ),
            release_verification_sha256=_pattern(
                release_verification_sha256,
                _SHA256,
                "release verification commitment",
            ),
            chain_id=normalized_chain,
            cvm_id=_pattern(cvm_id, _CVM_ID, "CVM id"),
            compose_hash=_pattern(compose_hash, _BYTES32, "compose hash"),
            room_id=_pattern(room_id, _ROOM_ID, "room id"),
            room_commitment=_pattern(
                room_commitment, _SHA256, "room commitment"
            ),
            room_generation=_integer(
                room_generation,
                "room generation",
                minimum=1,
                maximum=2**63 - 1,
            ),
            room_state_commitment=_pattern(
                room_state_commitment, _SHA256, "room state commitment"
            ),
            query_ref=_pattern(query_ref, _SHA256, "query reference"),
            query_proposal_commitment=_pattern(
                query_proposal_commitment,
                _SHA256,
                "query proposal commitment",
            ),
            prospective_query_grant_set_commitment=_pattern(
                prospective_query_grant_set_commitment,
                _SHA256,
                "prospective query grant set commitment",
            ),
            joint_consent_snapshot_commitment=_pattern(
                joint_consent_snapshot_commitment,
                _SHA256,
                "joint consent snapshot commitment",
            ),
            allocation_commitment=_pattern(
                allocation_commitment, _SHA256, "allocation commitment"
            ),
            owner_addresses=owners,
            compute_project_id=_pattern(
                compute_project_id, _BYTES32, "Compute project id"
            ),
            compute_job_id=_pattern(
                compute_job_id, _BYTES32, "Compute job id"
            ),
            compute_workload_id=_pattern(
                compute_workload_id, _WORKLOAD_ID, "Compute workload id"
            ),
            compute_workload_commitment=_pattern(
                compute_workload_commitment,
                _BYTES32,
                "Compute workload commitment",
            ),
            compute_manifest_commitment=_pattern(
                compute_manifest_commitment,
                _BYTES32,
                "Compute manifest commitment",
            ),
            compute_rate_policy_commitment=_pattern(
                compute_rate_policy_commitment,
                _BYTES32,
                "Compute rate policy commitment",
            ),
            compute_workload_schema=workload_schema,
            compute_workload_source_kind=_choice(
                compute_workload_source_kind,
                {"wallet", "credential"},
                "Compute workload source kind",
            ),
            compute_workload_execution_binding_commitment=_pattern(
                compute_workload_execution_binding_commitment,
                _SHA256,
                "Compute workload execution binding commitment",
            ),
            compute_workload_recipient_release_commitment=_pattern(
                compute_workload_recipient_release_commitment,
                _SHA256,
                "Compute workload recipient release commitment",
            ),
            compute_vault_address=_address(
                compute_vault_address,
                "Compute vault address",
                allow_zero=False,
            ),
            compute_vault_runtime_code_hash=_pattern(
                compute_vault_runtime_code_hash,
                _BYTES32,
                "Compute vault runtime code hash",
            ),
            compute_finality_model=_choice(
                compute_finality_model,
                _FINALITY_MODELS,
                "Compute finality model",
            ),
            compute_user_address=_address(
                compute_user_address,
                "Compute user address",
                allow_zero=False,
            ),
            operation=normalized_operation,
            model=normalized_model,
            recipe=normalized_recipe,
            result_policy=normalized_result_policy,
            max_prefill_tokens=prefill,
            max_sample_tokens=sample,
            max_train_tokens=train,
            sponsor_address=_address(
                sponsor_address, "sponsor address", allow_zero=False
            ),
            asset=normalized_asset,
            max_total_asset_debit=total_debit,
            max_compute_asset_debit=compute_debit,
            authorization_nonce=_integer(
                authorization_nonce,
                "authorization nonce",
                minimum=0,
                maximum=MAX_UINT256,
            ),
            authorization_expiry=expiry,
            royalty_asset=normalized_royalty_asset,
            royalty_total=royalty,
            royalty_owner_amounts_hash=_pattern(
                royalty_owner_amounts_hash,
                _BYTES32,
                "royalty owner amounts hash",
            ),
            royalty_distributor_address=_address(
                royalty_distributor_address,
                "royalty distributor address",
                allow_zero=False,
            ),
            royalty_release_policy_commitment=_pattern(
                royalty_release_policy_commitment,
                _BYTES32,
                "royalty release policy commitment",
            ),
            royalty_release_binding_commitment=_pattern(
                royalty_release_binding_commitment,
                _SHA256,
                "royalty release binding commitment",
            ),
            royalty_settlement_id=_pattern(
                royalty_settlement_id,
                _BYTES32,
                "royalty settlement id",
            ),
            royalty_settlement_nonce=_integer(
                royalty_settlement_nonce,
                "royalty settlement nonce",
                minimum=1,
                maximum=MAX_UINT256,
            ),
            royalty_reservation_safety_seconds=_integer(
                royalty_reservation_safety_seconds,
                "royalty reservation safety window",
                minimum=60,
                maximum=3_600,
            ),
            intent_created_at=created,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CollaborationExecutionBasis":
        expected = set(_BASIS_FIELDS) | {"schema"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CollaborationExecutionError("collaboration execution basis schema is invalid")
        if value.get("schema") != BASIS_SCHEMA:
            raise CollaborationExecutionError("collaboration execution basis version is invalid")
        try:
            fields = {
                field: value[field]
                for field in _BASIS_FIELDS
            }
            # This value is generated across the full uint256 range.  It must
            # never cross JSON as an IEEE-754 number: owner signatures, token
            # replay, and Solidity calldata all bind the same canonical
            # decimal string.
            fields["royalty_settlement_nonce"] = _decimal_uint(
                value["royalty_settlement_nonce"],
                "royalty settlement nonce",
                minimum=1,
                maximum=MAX_UINT256,
            )
            return cls.create(
                **fields
            )
        except TypeError as exc:
            raise CollaborationExecutionError(
                "collaboration execution basis fields are invalid"
            ) from exc

    @property
    def commitment(self) -> str:
        return _domain_commitment(_BASIS_DOMAIN, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": BASIS_SCHEMA,
            "release_git_sha": self.release_git_sha,
            "release_verification_sha256": self.release_verification_sha256,
            "chain_id": self.chain_id,
            "cvm_id": self.cvm_id,
            "compose_hash": self.compose_hash,
            "room_id": self.room_id,
            "room_commitment": self.room_commitment,
            "room_generation": self.room_generation,
            "room_state_commitment": self.room_state_commitment,
            "query_ref": self.query_ref,
            "query_proposal_commitment": self.query_proposal_commitment,
            "prospective_query_grant_set_commitment": (
                self.prospective_query_grant_set_commitment
            ),
            "joint_consent_snapshot_commitment": (
                self.joint_consent_snapshot_commitment
            ),
            "allocation_commitment": self.allocation_commitment,
            "owner_addresses": list(self.owner_addresses),
            "compute_project_id": self.compute_project_id,
            "compute_job_id": self.compute_job_id,
            "compute_workload_id": self.compute_workload_id,
            "compute_workload_commitment": self.compute_workload_commitment,
            "compute_manifest_commitment": self.compute_manifest_commitment,
            "compute_rate_policy_commitment": self.compute_rate_policy_commitment,
            "compute_workload_schema": self.compute_workload_schema,
            "compute_workload_source_kind": self.compute_workload_source_kind,
            "compute_workload_execution_binding_commitment": (
                self.compute_workload_execution_binding_commitment
            ),
            "compute_workload_recipient_release_commitment": (
                self.compute_workload_recipient_release_commitment
            ),
            "compute_vault_address": self.compute_vault_address,
            "compute_vault_runtime_code_hash": (
                self.compute_vault_runtime_code_hash
            ),
            "compute_finality_model": self.compute_finality_model,
            "compute_user_address": self.compute_user_address,
            "operation": self.operation,
            "model": self.model,
            "recipe": self.recipe,
            "result_policy": self.result_policy,
            "max_prefill_tokens": self.max_prefill_tokens,
            "max_sample_tokens": self.max_sample_tokens,
            "max_train_tokens": self.max_train_tokens,
            "sponsor_address": self.sponsor_address,
            "asset": self.asset,
            "max_total_asset_debit": self.max_total_asset_debit,
            "max_compute_asset_debit": self.max_compute_asset_debit,
            "authorization_nonce": self.authorization_nonce,
            "authorization_expiry": self.authorization_expiry,
            "royalty_asset": self.royalty_asset,
            "royalty_total": self.royalty_total,
            "royalty_owner_amounts_hash": self.royalty_owner_amounts_hash,
            "royalty_distributor_address": self.royalty_distributor_address,
            "royalty_release_policy_commitment": (
                self.royalty_release_policy_commitment
            ),
            "royalty_release_binding_commitment": (
                self.royalty_release_binding_commitment
            ),
            "royalty_settlement_id": self.royalty_settlement_id,
            "royalty_settlement_nonce": str(self.royalty_settlement_nonce),
            "royalty_reservation_safety_seconds": (
                self.royalty_reservation_safety_seconds
            ),
            "intent_created_at": self.intent_created_at,
        }


_BASIS_FIELDS = (
    "release_git_sha",
    "release_verification_sha256",
    "chain_id",
    "cvm_id",
    "compose_hash",
    "room_id",
    "room_commitment",
    "room_generation",
    "room_state_commitment",
    "query_ref",
    "query_proposal_commitment",
    "prospective_query_grant_set_commitment",
    "joint_consent_snapshot_commitment",
    "allocation_commitment",
    "owner_addresses",
    "compute_project_id",
    "compute_job_id",
    "compute_workload_id",
    "compute_workload_commitment",
    "compute_manifest_commitment",
    "compute_rate_policy_commitment",
    "compute_workload_schema",
    "compute_workload_source_kind",
    "compute_workload_execution_binding_commitment",
    "compute_workload_recipient_release_commitment",
    "compute_vault_address",
    "compute_vault_runtime_code_hash",
    "compute_finality_model",
    "compute_user_address",
    "operation",
    "model",
    "recipe",
    "result_policy",
    "max_prefill_tokens",
    "max_sample_tokens",
    "max_train_tokens",
    "sponsor_address",
    "asset",
    "max_total_asset_debit",
    "max_compute_asset_debit",
    "authorization_nonce",
    "authorization_expiry",
    "royalty_asset",
    "royalty_total",
    "royalty_owner_amounts_hash",
    "royalty_distributor_address",
    "royalty_release_policy_commitment",
    "royalty_release_binding_commitment",
    "royalty_settlement_id",
    "royalty_settlement_nonce",
    "royalty_reservation_safety_seconds",
    "intent_created_at",
)


@dataclass(frozen=True)
class CollaborationExecutionIntent(CollaborationExecutionBasis):
    """Final basis + canonical Compute v3 dispatch commitment.

    Owners grant the non-circular :class:`CollaborationExecutionBasis`. The
    exact grant set then enters Compute's shared Collaboration authorization
    context. Only after that context exists can the canonical Compute v3 intent
    and this final intent be derived without a commitment cycle.
    """

    compute_authorization_kind: str
    compute_authorization_context_commitment: str
    compute_dispatch_intent_commitment: str

    @classmethod
    def create(
        cls,
        *,
        basis: CollaborationExecutionBasis,
        compute_authorization_kind: str,
        compute_authorization_context_commitment: str,
        compute_dispatch_intent_commitment: str,
    ) -> "CollaborationExecutionIntent":
        if not isinstance(basis, CollaborationExecutionBasis):
            raise CollaborationExecutionError(
                "collaboration execution basis is required"
            )
        return cls(
            **{field: getattr(basis, field) for field in _BASIS_FIELDS},
            compute_authorization_kind=_choice(
                compute_authorization_kind,
                {"collaboration_one_shot"},
                "Compute authorization kind",
            ),
            compute_authorization_context_commitment=_pattern(
                compute_authorization_context_commitment,
                _SHA256,
                "Compute authorization context commitment",
            ),
            compute_dispatch_intent_commitment=_pattern(
                compute_dispatch_intent_commitment,
                _BYTES32,
                "Compute dispatch intent commitment",
            ),
        )

    @classmethod
    def finalize(
        cls,
        basis: CollaborationExecutionBasis,
        grants: Sequence["OwnerExecutionGrant"],
        *,
        now: int,
    ) -> "CollaborationExecutionIntent":
        grant_set = execution_grant_set_commitment(basis, grants, now=now)
        context = _compute_collaboration_authorization_context(
            basis,
            grant_set_commitment=grant_set,
        )
        compute_intent = _build_collaboration_compute_dispatch_intent(
            basis,
            authorization_context_commitment=context,
        )
        return cls.create(
            basis=basis,
            compute_authorization_kind="collaboration_one_shot",
            compute_authorization_context_commitment=context,
            compute_dispatch_intent_commitment=compute_intent.commitment,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CollaborationExecutionIntent":
        expected = set(_INTENT_FIELDS) | {"schema", "basis_commitment"}
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema") != INTENT_SCHEMA
        ):
            raise CollaborationExecutionError(
                "collaboration execution intent schema is invalid"
            )
        basis = CollaborationExecutionBasis.from_dict(
            {
                "schema": BASIS_SCHEMA,
                **{field: value[field] for field in _BASIS_FIELDS},
            }
        )
        if value["basis_commitment"] != basis.commitment:
            raise CollaborationExecutionError(
                "collaboration execution basis commitment is invalid"
            )
        return cls.create(
            basis=basis,
            compute_authorization_kind=value["compute_authorization_kind"],
            compute_authorization_context_commitment=value[
                "compute_authorization_context_commitment"
            ],
            compute_dispatch_intent_commitment=value[
                "compute_dispatch_intent_commitment"
            ],
        )

    def to_basis(self) -> CollaborationExecutionBasis:
        return CollaborationExecutionBasis.create(
            **{field: getattr(self, field) for field in _BASIS_FIELDS}
        )

    def validate_for_grants(
        self,
        grants: Sequence["OwnerExecutionGrant"],
        *,
        now: int,
    ) -> ComputeDispatchIntent:
        basis = self.to_basis()
        grant_set = execution_grant_set_commitment(basis, grants, now=now)
        expected_context = _compute_collaboration_authorization_context(
            basis,
            grant_set_commitment=grant_set,
        )
        if (
            self.compute_authorization_kind != "collaboration_one_shot"
            or not hmac.compare_digest(
                self.compute_authorization_context_commitment,
                expected_context,
            )
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute Collaboration authorization context is invalid"
            )
        compute_intent = _build_collaboration_compute_dispatch_intent(
            basis,
            authorization_context_commitment=expected_context,
        )
        if not hmac.compare_digest(
            self.compute_dispatch_intent_commitment,
            compute_intent.commitment,
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute dispatch intent commitment is invalid"
            )
        return compute_intent

    @property
    def commitment(self) -> str:
        return _domain_commitment(_INTENT_DOMAIN, self.to_dict())

    @property
    def execution_id(self) -> str:
        digest = hashlib.sha256(
            _EXECUTION_ID_DOMAIN + self.commitment.encode("ascii")
        ).hexdigest()
        return f"exec_{digest}"

    def to_dict(self) -> dict[str, Any]:
        basis = self.to_basis()
        basis_fields = basis.to_dict()
        basis_fields.pop("schema")
        return {
            "schema": INTENT_SCHEMA,
            **basis_fields,
            "basis_commitment": basis.commitment,
            "compute_authorization_kind": self.compute_authorization_kind,
            "compute_authorization_context_commitment": (
                self.compute_authorization_context_commitment
            ),
            "compute_dispatch_intent_commitment": (
                self.compute_dispatch_intent_commitment
            ),
        }


_INTENT_FIELDS = _BASIS_FIELDS + (
    "compute_authorization_kind",
    "compute_authorization_context_commitment",
    "compute_dispatch_intent_commitment",
)


def _compute_collaboration_authorization_context(
    basis: CollaborationExecutionBasis,
    *,
    grant_set_commitment: str,
) -> str:
    return compute_collaboration_one_shot_authorization_context_commitment(
        collaboration_execution_basis_commitment=basis.commitment,
        collaboration_execution_grant_set_commitment=grant_set_commitment,
        project_id=basis.compute_project_id,
        job_id=basis.compute_job_id,
        user=basis.compute_user_address,
        asset=basis.asset,
        authorization_nonce=basis.authorization_nonce,
        max_asset_debit=basis.max_compute_asset_debit,
        authorization_expiry=basis.authorization_expiry,
        rate_policy_commitment=basis.compute_rate_policy_commitment,
        workload_commitment=basis.compute_workload_commitment,
        manifest_commitment=basis.compute_manifest_commitment,
    )


def _build_collaboration_compute_dispatch_intent(
    basis: CollaborationExecutionBasis,
    *,
    authorization_context_commitment: str,
) -> ComputeDispatchIntent:
    return ComputeDispatchIntent.create(
        project_reference=basis.compute_project_id,
        job_reference=basis.compute_job_id,
        user=basis.compute_user_address,
        asset=basis.asset,
        authorization_nonce=basis.authorization_nonce,
        max_asset_debit=basis.max_compute_asset_debit,
        authorization_expiry=basis.authorization_expiry,
        rate_policy_commitment=basis.compute_rate_policy_commitment,
        compose_hash=basis.compose_hash,
        operation=basis.operation,
        model=basis.model,
        recipe=basis.recipe,
        result_policy=basis.result_policy,
        max_prefill_tokens=basis.max_prefill_tokens,
        max_sample_tokens=basis.max_sample_tokens,
        max_train_tokens=basis.max_train_tokens,
        workload_id=basis.compute_workload_id,
        workload_schema=basis.compute_workload_schema,
        manifest_commitment=basis.compute_manifest_commitment,
        workload_commitment=basis.compute_workload_commitment,
        workload_source_kind=basis.compute_workload_source_kind,
        workload_execution_binding_commitment=(
            basis.compute_workload_execution_binding_commitment
        ),
        workload_recipient_release_commitment=(
            basis.compute_workload_recipient_release_commitment
        ),
        authorization_kind="collaboration_one_shot",
        authorization_context_commitment=authorization_context_commitment,
    )


def royalty_owner_amounts_hash(
    *,
    owner_amounts: Mapping[str, int],
    expected_owners: Sequence[str],
    expected_total: int,
) -> str:
    """Build the exact RoyaltyDistributor owner/amount EIP-712 commitment.

    Callers constructing a new execution basis must use this upstream gate
    before assigning ``CollaborationExecutionBasis.royalty_owner_amounts_hash``;
    the serialized basis intentionally retains only the resulting commitment,
    not the exact allocation. Owners must be the exact strictly sorted
    Collaboration owner set, every payout must be positive, and the sum must
    equal ``royalty_total``. The returned value is byte-for-byte compatible
    with ``RoyaltyDistributor.computeOwnerAmountsHash`` and
    ``royalty_distribution_plan.compute_owner_amounts_hash``.
    """

    if not isinstance(owner_amounts, Mapping):
        raise CollaborationExecutionError("royalty owner amounts are invalid")
    owners = tuple(
        _address(owner, "royalty owner", allow_zero=False)
        for owner in expected_owners
    )
    if (
        not owners
        or len(owners) > MAX_OWNERS
        or owners != tuple(sorted(set(owners)))
        or tuple(owner_amounts) != owners
    ):
        raise CollaborationExecutionError(
            "royalty owners must exactly match the sorted collaboration owners"
        )
    total = _integer(
        expected_total,
        "royalty total",
        minimum=1,
        maximum=MAX_UINT256,
    )
    recipients: list[DistributionRecipient] = []
    running_total = 0
    for owner in owners:
        amount = _integer(
            owner_amounts[owner],
            "royalty owner amount",
            minimum=1,
            maximum=MAX_UINT256,
        )
        running_total += amount
        if running_total > MAX_UINT256:
            raise CollaborationExecutionError("royalty owner amount sum overflows")
        recipients.append(
            DistributionRecipient(owner_address=owner, amount=amount)
        )
    if running_total != total:
        raise CollaborationExecutionError(
            "royalty owner amounts do not sum to royalty total"
        )
    return compute_owner_amounts_hash(recipients)


def _normalize_persisted_royalty_owner_amounts(
    intent: "CollaborationExecutionIntent",
    value: Mapping[str, int] | list[Mapping[str, Any]] | None,
) -> list[dict[str, Any]] | None:
    """Canonicalize exact payouts retained for the later sponsor settlement.

    ``None`` remains accepted for compatibility with credential-free core
    tests and old local fixtures, but production settlement extraction rejects
    it.  The API coordinator always supplies the authenticated plan split.
    """

    if value is None:
        return None
    if isinstance(value, Mapping):
        amounts = dict(value)
    elif isinstance(value, list):
        amounts: dict[str, int] = {}
        for item in value:
            if not isinstance(item, Mapping) or set(item) != {
                "owner_address",
                "amount",
            }:
                raise CollaborationExecutionError(
                    "persisted royalty owner amounts are invalid"
                )
            owner = _address(
                item["owner_address"],
                "royalty owner",
                allow_zero=False,
            )
            if owner in amounts:
                raise CollaborationExecutionError(
                    "persisted royalty owner amounts contain duplicates"
                )
            amounts[owner] = item["amount"]
    else:
        raise CollaborationExecutionError(
            "persisted royalty owner amounts are invalid"
        )
    ordered = {
        owner: amounts[owner]
        for owner in intent.owner_addresses
        if owner in amounts
    }
    if set(amounts) != set(intent.owner_addresses):
        raise CollaborationExecutionError(
            "persisted royalty owners changed"
        )
    expected_hash = royalty_owner_amounts_hash(
        owner_amounts=ordered,
        expected_owners=intent.owner_addresses,
        expected_total=intent.royalty_total,
    )
    if expected_hash != intent.royalty_owner_amounts_hash:
        raise CollaborationExecutionError(
            "persisted royalty owner amounts changed"
        )
    return [
        {"owner_address": owner, "amount": ordered[owner]}
        for owner in intent.owner_addresses
    ]


@dataclass(frozen=True)
class OwnerExecutionGrant:
    """One fresh, verifier-confirmed owner authorization commitment.

    This credential-free core does not verify wallet signatures.  Its caller
    must construct this value only after the existing wallet verifier has
    authenticated an exact, domain-separated one-shot grant.  The journal
    persists only the resulting authorization hash, never the signature.
    """

    grant_id: str
    owner_address: str
    basis_commitment: str
    prospective_query_grant_authorization_hash: str
    execution_authorization_hash: str
    execution_grant_generation: int
    granted_at: int
    expires_at: int

    @classmethod
    def create(
        cls,
        *,
        grant_id: str,
        owner_address: str,
        basis_commitment: str,
        prospective_query_grant_authorization_hash: str,
        execution_authorization_hash: str,
        execution_grant_generation: int,
        granted_at: int,
        expires_at: int,
    ) -> "OwnerExecutionGrant":
        prospective = _pattern(
            prospective_query_grant_authorization_hash,
            _SHA256,
            "prospective query grant authorization hash",
        )
        execution = _pattern(
            execution_authorization_hash,
            _SHA256,
            "execution authorization hash",
        )
        if hmac.compare_digest(prospective, execution):
            raise CollaborationExecutionError(
                "one-shot execution authorization must be distinct from the prospective query grant"
            )
        granted = _timestamp(granted_at, "execution grant time")
        expiry = _timestamp(expires_at, "execution grant expiry")
        if expiry <= granted:
            raise CollaborationExecutionError("execution grant lifetime is invalid")
        return cls(
            grant_id=_pattern(grant_id, _GRANT_ID, "execution grant id"),
            owner_address=_address(
                owner_address, "execution grant owner", allow_zero=False
            ),
            basis_commitment=_pattern(
                basis_commitment, _SHA256, "execution basis commitment"
            ),
            prospective_query_grant_authorization_hash=prospective,
            execution_authorization_hash=execution,
            execution_grant_generation=_integer(
                execution_grant_generation,
                "execution grant generation",
                minimum=1,
                maximum=2**63 - 1,
            ),
            granted_at=granted,
            expires_at=expiry,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "OwnerExecutionGrant":
        expected = {
            "schema",
            "scope",
            "grant_id",
            "owner_address",
            "basis_commitment",
            "prospective_query_grant_authorization_hash",
            "execution_authorization_hash",
            "execution_grant_generation",
            "granted_at",
            "expires_at",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CollaborationExecutionError("owner execution grant schema is invalid")
        if value.get("schema") != GRANT_SCHEMA or value.get("scope") != "one_shot_execution":
            raise CollaborationExecutionError("owner execution grant version or scope is invalid")
        try:
            return cls.create(
                **{
                    field: value[field]
                    for field in expected - {"schema", "scope"}
                }
            )
        except TypeError as exc:
            raise CollaborationExecutionError("owner execution grant fields are invalid") from exc

    def validate_for(self, basis: CollaborationExecutionBasis, *, now: int) -> None:
        timestamp = _timestamp(now, "execution grant validation time")
        if self.basis_commitment != basis.commitment:
            raise CollaborationExecutionAuthorityInvalidated(
                "owner execution grant binds a different execution basis"
            )
        if self.owner_address not in basis.owner_addresses:
            raise CollaborationExecutionAuthorityInvalidated(
                "owner execution grant does not belong to this collaboration"
            )
        if self.granted_at < basis.intent_created_at:
            raise CollaborationExecutionAuthorityInvalidated(
                "owner execution grant predates the exact execution intent"
            )
        if timestamp < self.granted_at:
            raise CollaborationExecutionAuthorityInvalidated(
                "owner execution grant is not yet valid"
            )
        if self.expires_at > basis.authorization_expiry or timestamp >= self.expires_at:
            raise CollaborationExecutionAuthorityInvalidated(
                "owner execution grant is expired or exceeds funding authority"
            )

    @property
    def commitment(self) -> str:
        return _domain_commitment(_GRANT_DOMAIN, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": GRANT_SCHEMA,
            "scope": "one_shot_execution",
            "grant_id": self.grant_id,
            "owner_address": self.owner_address,
            "basis_commitment": self.basis_commitment,
            "prospective_query_grant_authorization_hash": (
                self.prospective_query_grant_authorization_hash
            ),
            "execution_authorization_hash": self.execution_authorization_hash,
            "execution_grant_generation": self.execution_grant_generation,
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
        }


def execution_grant_set_commitment(
    basis: CollaborationExecutionBasis,
    grants: Sequence[OwnerExecutionGrant],
    *,
    now: int,
) -> str:
    """Validate and commit the exact fresh owner-grant set."""

    if not isinstance(basis, CollaborationExecutionBasis):
        raise CollaborationExecutionError("collaboration execution basis is required")
    if isinstance(basis, CollaborationExecutionIntent):
        basis = basis.to_basis()
    normalized = tuple(grants)
    if len(normalized) != len(basis.owner_addresses):
        raise CollaborationExecutionAuthorityInvalidated(
            "every collaboration owner must issue one execution grant"
        )
    if any(not isinstance(grant, OwnerExecutionGrant) for grant in normalized):
        raise CollaborationExecutionError("owner execution grant set is invalid")
    sorted_grants = tuple(sorted(normalized, key=lambda grant: grant.owner_address))
    if tuple(grant.owner_address for grant in sorted_grants) != basis.owner_addresses:
        raise CollaborationExecutionAuthorityInvalidated(
            "owner execution grant set does not exactly match collaboration owners"
        )
    if len({grant.grant_id for grant in sorted_grants}) != len(sorted_grants):
        raise CollaborationExecutionAuthorityInvalidated("execution grant ids must be unique")
    for grant in sorted_grants:
        grant.validate_for(basis, now=now)
    return _domain_commitment(
        _GRANT_SET_DOMAIN,
        {
            "schema": "dnai.collaboration.execution-grant-set.v1",
            "basis_commitment": basis.commitment,
            "grants": [grant.to_dict() for grant in sorted_grants],
        },
    )


@dataclass(frozen=True)
class RoyaltyFundingReservation:
    """Exact, Solidity-compatible prefunding request derived after grants.

    A reservation id cannot be selected by the browser or placed in the
    owner-approved basis: ``RoyaltyDistributor`` derives it from the complete
    request, and that request contains the *final* execution and owner-grant
    commitments.  The basis instead binds a fresh settlement id and nonzero
    settlement nonce.  Once the grants finalize the execution intent, this
    object is deterministic and safe to persist/replay byte-for-byte.
    """

    chain_id: int
    distributor_address: str
    sponsor_address: str
    settlement_id: str
    settlement_nonce: int
    release_policy_commitment: str
    room_commitment: str
    room_state_commitment: str
    query_commitment: str
    grant_set_commitment: str
    allocation_commitment: str
    owners_amounts_hash: str
    asset: str
    total: int
    execution_commitment: str
    refund_after: int
    reservation_id: str

    @classmethod
    def derive(
        cls,
        intent: CollaborationExecutionIntent,
        *,
        execution_grant_set_commitment: str,
    ) -> "RoyaltyFundingReservation":
        if not isinstance(intent, CollaborationExecutionIntent):
            raise CollaborationExecutionError(
                "final Collaboration execution intent is required"
            )
        grant_set = _pattern(
            execution_grant_set_commitment,
            _SHA256,
            "execution grant set commitment",
        )
        if intent.royalty_distributor_address == intent.sponsor_address:
            raise CollaborationExecutionError(
                "royalty sponsor cannot be the distributor"
            )
        refund_after = intent.authorization_expiry + (
            intent.royalty_reservation_safety_seconds
        )
        if refund_after > MAX_TIMESTAMP or refund_after >= 2**64:
            raise CollaborationExecutionError(
                "royalty reservation refund time is invalid"
            )
        values = {
            "chain_id": intent.chain_id,
            "distributor_address": intent.royalty_distributor_address,
            "sponsor_address": intent.sponsor_address,
            "settlement_id": intent.royalty_settlement_id,
            "settlement_nonce": intent.royalty_settlement_nonce,
            "release_policy_commitment": (
                intent.royalty_release_policy_commitment
            ),
            "room_commitment": _as_bytes32_hex(intent.room_commitment),
            "room_state_commitment": _as_bytes32_hex(
                intent.room_state_commitment
            ),
            "query_commitment": _as_bytes32_hex(
                intent.query_proposal_commitment
            ),
            "grant_set_commitment": _as_bytes32_hex(grant_set),
            "allocation_commitment": _as_bytes32_hex(
                intent.allocation_commitment
            ),
            "owners_amounts_hash": intent.royalty_owner_amounts_hash,
            "asset": intent.royalty_asset,
            "total": intent.royalty_total,
            "execution_commitment": _as_bytes32_hex(intent.commitment),
            "refund_after": refund_after,
        }
        reservation_id = royalty_funding_reservation_id(**values)
        return cls(**values, reservation_id=reservation_id)

    @property
    def function_name(self) -> str:
        return "reserveNative" if self.asset == "0x" + "00" * 20 else "reserveERC20"

    @property
    def abi_signature(self) -> str:
        tuple_type = (
            "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,"
            "bytes32,bytes32,address,uint256,bytes32,uint64)"
        )
        return f"{self.function_name}({tuple_type})"

    @property
    def request_tuple(self) -> tuple[Any, ...]:
        return (
            bytes.fromhex(self.settlement_id[2:]),
            self.settlement_nonce,
            bytes.fromhex(self.release_policy_commitment[2:]),
            bytes.fromhex(self.room_commitment[2:]),
            bytes.fromhex(self.room_state_commitment[2:]),
            bytes.fromhex(self.query_commitment[2:]),
            bytes.fromhex(self.grant_set_commitment[2:]),
            bytes.fromhex(self.allocation_commitment[2:]),
            bytes.fromhex(self.owners_amounts_hash[2:]),
            self.asset,
            self.total,
            bytes.fromhex(self.execution_commitment[2:]),
            self.refund_after,
        )

    @property
    def calldata(self) -> str:
        tuple_type = (
            "(bytes32,uint256,bytes32,bytes32,bytes32,bytes32,bytes32,"
            "bytes32,bytes32,address,uint256,bytes32,uint64)"
        )
        encoded = abi_encode([tuple_type], [self.request_tuple])
        return "0x" + (keccak(self.abi_signature.encode("ascii"))[:4] + encoded).hex()

    def to_dict(self) -> dict[str, Any]:
        request = {
            "settlement_id": self.settlement_id,
            "settlement_nonce": str(self.settlement_nonce),
            "release_policy_commitment": self.release_policy_commitment,
            "room_commitment": self.room_commitment,
            "room_state_commitment": self.room_state_commitment,
            "query_commitment": self.query_commitment,
            "grant_set_commitment": self.grant_set_commitment,
            "allocation_commitment": self.allocation_commitment,
            "owners_amounts_hash": self.owners_amounts_hash,
            "asset": self.asset,
            "total": str(self.total),
            "execution_commitment": self.execution_commitment,
            "refund_after": str(self.refund_after),
        }
        native = self.asset == "0x" + "00" * 20
        return {
            "schema": "dnai.collaboration.royalty-funding-reservation.v1",
            "chain_id": self.chain_id,
            "distributor_address": self.distributor_address,
            "sponsor_address": self.sponsor_address,
            "reservation_id": self.reservation_id,
            "request": request,
            "transaction": {
                "to": self.distributor_address,
                "function_name": self.function_name,
                "abi_signature": self.abi_signature,
                "calldata": self.calldata,
                "value": str(self.total if native else 0),
                "erc20_approval_required": not native,
                "erc20_approval": (
                    None
                    if native
                    else {
                        "token_address": self.asset,
                        "spender": self.distributor_address,
                        "minimum_amount": str(self.total),
                    }
                ),
            },
            "derived_after_fresh_owner_grants": True,
            "client_supplied_reservation_id": False,
            "balance_or_allowance_is_not_authorization": True,
        }


def _as_bytes32_hex(value: str) -> str:
    if _BYTES32.fullmatch(value):
        return value
    if _SHA256.fullmatch(value):
        return "0x" + value.removeprefix("sha256:")
    raise CollaborationExecutionError("commitment is not bytes32-compatible")


def royalty_funding_reservation_id(
    *,
    chain_id: int,
    distributor_address: str,
    sponsor_address: str,
    settlement_id: str,
    settlement_nonce: int,
    release_policy_commitment: str,
    room_commitment: str,
    room_state_commitment: str,
    query_commitment: str,
    grant_set_commitment: str,
    allocation_commitment: str,
    owners_amounts_hash: str,
    asset: str,
    total: int,
    execution_commitment: str,
    refund_after: int,
) -> str:
    """Mirror ``RoyaltyDistributor.fundingReservationId`` byte-for-byte."""

    words = (
        ROYALTY_FUNDING_RESERVATION_TYPEHASH,
        _uint256_word(chain_id),
        _address_word(distributor_address),
        _address_word(sponsor_address),
        _bytes32_word(settlement_id),
        _uint256_word(settlement_nonce),
        _bytes32_word(release_policy_commitment),
        _bytes32_word(room_commitment),
        _bytes32_word(room_state_commitment),
        _bytes32_word(query_commitment),
        _bytes32_word(grant_set_commitment),
        _bytes32_word(allocation_commitment),
        _bytes32_word(owners_amounts_hash),
        _address_word(asset),
        _uint256_word(total),
        _bytes32_word(execution_commitment),
        _uint256_word(refund_after),
    )
    return "0x" + keccak(b"".join(words)).hex()


def _bytes32_word(value: str) -> bytes:
    normalized = _as_bytes32_hex(value)
    return bytes.fromhex(normalized[2:])


def _address_word(value: str) -> bytes:
    normalized = _address(value, "address", allow_zero=True)
    return bytes.fromhex(normalized[2:]).rjust(32, b"\x00")


def _uint256_word(value: int) -> bytes:
    normalized = _integer(
        value,
        "uint256 value",
        minimum=0,
        maximum=MAX_UINT256,
    )
    return normalized.to_bytes(32, "big")


def execution_authorization_commitment(
    intent: CollaborationExecutionIntent,
    grants: Sequence[OwnerExecutionGrant],
    *,
    now: int,
) -> str:
    intent.validate_for_grants(grants, now=now)
    grant_set = execution_grant_set_commitment(
        intent.to_basis(), grants, now=now
    )
    return _domain_commitment(
        _AUTHORIZATION_DOMAIN,
        {
            "schema": "dnai.collaboration.execution-authorization.v1",
            "execution_id": intent.execution_id,
            "intent_commitment": intent.commitment,
            "execution_basis_commitment": intent.to_basis().commitment,
            "execution_grant_set_commitment": grant_set,
        },
    )


@dataclass(frozen=True)
class FinalizedComputeVaultObservation:
    """Exact claim-time view of the Base Sepolia Compute vault job.

    ``single_rpc_reported_finalized`` is deliberately named as a reported
    finality model, not independent consensus proof. The API integration must
    reconstruct this object from a fresh finalized-block read of the pinned
    ComputeCreditVault runtime. Missing/unavailable observations are retryable;
    a mismatched or non-authorized job definitively invalidates the handoff.
    """

    chain_id: int
    vault_address: str
    vault_runtime_code_hash: str
    block_number: int
    block_hash: str
    block_timestamp: int
    source_record_commitment: str
    source_authentication_receipt: str
    finality_model: str
    reported_finalized: bool
    job_state: str
    compute_project_id: str
    compute_job_id: str
    sponsor_address: str
    compute_user_address: str
    asset: str
    authorization_nonce: int
    max_compute_asset_debit: int
    authorization_expiry: int
    compute_workload_commitment: str
    compute_manifest_commitment: str
    compute_dispatch_intent_commitment: str
    observed_at: int

    @classmethod
    def create(
        cls,
        *,
        chain_id: int,
        vault_address: str,
        vault_runtime_code_hash: str,
        block_number: int,
        block_hash: str,
        block_timestamp: int,
        source_record_commitment: str,
        source_authentication_receipt: str,
        finality_model: str,
        reported_finalized: bool,
        job_state: str,
        compute_project_id: str,
        compute_job_id: str,
        sponsor_address: str,
        compute_user_address: str,
        asset: str,
        authorization_nonce: int,
        max_compute_asset_debit: int,
        authorization_expiry: int,
        compute_workload_commitment: str,
        compute_manifest_commitment: str,
        compute_dispatch_intent_commitment: str,
        observed_at: int,
    ) -> "FinalizedComputeVaultObservation":
        if type(reported_finalized) is not bool:
            raise CollaborationExecutionAuthorityUnavailable(
                "Compute vault finality observation is invalid"
            )
        return cls(
            chain_id=_integer(
                chain_id, "Compute vault chain id", minimum=1, maximum=2**63 - 1
            ),
            vault_address=_address(
                vault_address, "Compute vault address", allow_zero=False
            ),
            vault_runtime_code_hash=_pattern(
                vault_runtime_code_hash,
                _BYTES32,
                "Compute vault runtime code hash",
            ),
            block_number=_integer(
                block_number,
                "Compute vault finalized block number",
                minimum=1,
                maximum=2**63 - 1,
            ),
            block_hash=_pattern(
                block_hash, _BYTES32, "Compute vault finalized block hash"
            ),
            block_timestamp=_timestamp(
                block_timestamp, "Compute vault finalized block timestamp"
            ),
            source_record_commitment=_pattern(
                source_record_commitment,
                _SHA256,
                "Compute vault source record commitment",
            ),
            source_authentication_receipt=_pattern(
                source_authentication_receipt,
                _SHA256,
                "Compute vault source authentication receipt",
            ),
            finality_model=_choice(
                finality_model, _FINALITY_MODELS, "Compute vault finality model"
            ),
            reported_finalized=reported_finalized,
            job_state=_choice(
                job_state,
                {"authorized", "started", "settled", "canceled", "expired"},
                "Compute vault job state",
            ),
            compute_project_id=_pattern(
                compute_project_id, _BYTES32, "Compute project id"
            ),
            compute_job_id=_pattern(
                compute_job_id, _BYTES32, "Compute job id"
            ),
            sponsor_address=_address(
                sponsor_address, "Compute funding sponsor", allow_zero=False
            ),
            compute_user_address=_address(
                compute_user_address, "Compute job user", allow_zero=False
            ),
            asset=_address(asset, "Compute job asset", allow_zero=True),
            authorization_nonce=_integer(
                authorization_nonce,
                "Compute authorization nonce",
                minimum=0,
                maximum=MAX_UINT256,
            ),
            max_compute_asset_debit=_integer(
                max_compute_asset_debit,
                "Compute maximum asset debit",
                minimum=1,
                maximum=MAX_UINT256,
            ),
            authorization_expiry=_timestamp(
                authorization_expiry, "Compute authorization expiry"
            ),
            compute_workload_commitment=_pattern(
                compute_workload_commitment,
                _BYTES32,
                "Compute workload commitment",
            ),
            compute_manifest_commitment=_pattern(
                compute_manifest_commitment,
                _BYTES32,
                "Compute manifest commitment",
            ),
            compute_dispatch_intent_commitment=_pattern(
                compute_dispatch_intent_commitment,
                _BYTES32,
                "Compute dispatch intent commitment",
            ),
            observed_at=_timestamp(observed_at, "Compute vault observation time"),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, Any]
    ) -> "FinalizedComputeVaultObservation":
        expected = {
            "schema",
            "chain_id",
            "vault_address",
            "vault_runtime_code_hash",
            "block_number",
            "block_hash",
            "block_timestamp",
            "source_record_commitment",
            "source_authentication_receipt",
            "finality_model",
            "reported_finalized",
            "job_state",
            "compute_project_id",
            "compute_job_id",
            "sponsor_address",
            "compute_user_address",
            "asset",
            "authorization_nonce",
            "max_compute_asset_debit",
            "authorization_expiry",
            "compute_workload_commitment",
            "compute_manifest_commitment",
            "compute_dispatch_intent_commitment",
            "observed_at",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema") != VAULT_OBSERVATION_SCHEMA
        ):
            raise CollaborationExecutionError(
                "finalized Compute vault observation schema is invalid"
            )
        return cls.create(
            **{field: value[field] for field in expected - {"schema"}}
        )

    def validate_for(
        self,
        intent: CollaborationExecutionIntent,
        *,
        claimed_at: int,
    ) -> None:
        timestamp = _timestamp(claimed_at, "claim time")
        if self.observed_at != timestamp:
            raise CollaborationExecutionAuthorityUnavailable(
                "Compute vault observation is not from the atomic claim"
            )
        if self.reported_finalized is not True:
            raise CollaborationExecutionAuthorityUnavailable(
                "Compute vault job is not reported finalized"
            )
        exact = (
            self.chain_id == intent.chain_id
            and self.vault_address == intent.compute_vault_address
            and self.vault_runtime_code_hash
            == intent.compute_vault_runtime_code_hash
            and self.finality_model == intent.compute_finality_model
            and self.compute_project_id == intent.compute_project_id
            and self.compute_job_id == intent.compute_job_id
            and self.sponsor_address == intent.sponsor_address
            and self.compute_user_address == intent.compute_user_address
            and self.asset == intent.asset
            and self.authorization_nonce == intent.authorization_nonce
            and self.max_compute_asset_debit
            == intent.max_compute_asset_debit
            and self.authorization_expiry == intent.authorization_expiry
            and self.compute_workload_commitment
            == intent.compute_workload_commitment
            and self.compute_manifest_commitment
            == intent.compute_manifest_commitment
            and self.compute_dispatch_intent_commitment
            == intent.compute_dispatch_intent_commitment
        )
        if not exact:
            raise CollaborationExecutionAuthorityInvalidated(
                "finalized Compute vault observation does not match the exact intent"
            )
        if self.job_state != "authorized":
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute vault job is no longer authorized for handoff"
            )
        if timestamp >= self.authorization_expiry:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute vault authorization expired before claim"
            )

    @property
    def commitment(self) -> str:
        return _domain_commitment(
            b"dnai-wikigen/collaboration-finalized-vault-observation/v1\x00",
            self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": VAULT_OBSERVATION_SCHEMA,
            "chain_id": self.chain_id,
            "vault_address": self.vault_address,
            "vault_runtime_code_hash": self.vault_runtime_code_hash,
            "block_number": self.block_number,
            "block_hash": self.block_hash,
            "block_timestamp": self.block_timestamp,
            "source_record_commitment": self.source_record_commitment,
            "source_authentication_receipt": self.source_authentication_receipt,
            "finality_model": self.finality_model,
            "reported_finalized": self.reported_finalized,
            "job_state": self.job_state,
            "compute_project_id": self.compute_project_id,
            "compute_job_id": self.compute_job_id,
            "sponsor_address": self.sponsor_address,
            "compute_user_address": self.compute_user_address,
            "asset": self.asset,
            "authorization_nonce": self.authorization_nonce,
            "max_compute_asset_debit": self.max_compute_asset_debit,
            "authorization_expiry": self.authorization_expiry,
            "compute_workload_commitment": self.compute_workload_commitment,
            "compute_manifest_commitment": self.compute_manifest_commitment,
            "compute_dispatch_intent_commitment": (
                self.compute_dispatch_intent_commitment
            ),
            "observed_at": self.observed_at,
        }


@dataclass(frozen=True)
class FinalizedRoyaltyAuthorityObservation:
    """Current Royalty release and deposited reservation at claim time.

    A sponsor balance or ERC20 allowance is intentionally absent.  Those
    values are mutable capacity signals, not an execution-specific funding
    reservation, and therefore can never satisfy this authority object.
    """

    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int
    distributor_address: str
    distributor_runtime_code_hash: str
    owner_address: str
    pending_owner_address: str
    release_binding_commitment: str
    release_policy_commitment: str
    authority_nonce: int
    settlement_verifier_address: str
    qvl_verifier_address: str
    execution_policy_anchor_address: str
    anchor_writer_address: str
    anchor_writer_release_commitment: str
    distributor_paused: bool
    pending_authority_empty: bool
    anchor_paused: bool
    anchor_writer_rotations_frozen: bool
    reservation_id: str
    reservation_active: bool
    reservation_consumed: bool
    reservation_sponsor_address: str
    reservation_asset: str
    reservation_total: int
    reservation_owner_amounts_hash: str
    reservation_release_policy_commitment: str
    reservation_execution_intent_commitment: str
    reservation_refund_after: int
    reservation_deposited_amount: int
    source_record_commitment: str
    source_authentication_receipt: str
    observed_at: int

    @classmethod
    def create(cls, **value: Any) -> "FinalizedRoyaltyAuthorityObservation":
        for flag in (
            "distributor_paused",
            "pending_authority_empty",
            "anchor_paused",
            "anchor_writer_rotations_frozen",
            "reservation_active",
            "reservation_consumed",
        ):
            if type(value.get(flag)) is not bool:
                raise CollaborationExecutionAuthorityUnavailable(
                    "Royalty authority observation flags are invalid"
                )
        return cls(
            chain_id=_integer(value.get("chain_id"), "Royalty chain id", minimum=1, maximum=2**63 - 1),
            block_number=_integer(value.get("block_number"), "Royalty finalized block number", minimum=1, maximum=2**63 - 1),
            block_hash=_pattern(value.get("block_hash"), _BYTES32, "Royalty finalized block hash"),
            block_timestamp=_timestamp(value.get("block_timestamp"), "Royalty finalized block timestamp"),
            distributor_address=_address(value.get("distributor_address"), "Royalty distributor", allow_zero=False),
            distributor_runtime_code_hash=_pattern(value.get("distributor_runtime_code_hash"), _BYTES32, "Royalty distributor runtime code hash"),
            owner_address=_address(value.get("owner_address"), "Royalty owner", allow_zero=False),
            pending_owner_address=_address(value.get("pending_owner_address"), "Royalty pending owner", allow_zero=True),
            release_binding_commitment=_pattern(value.get("release_binding_commitment"), _SHA256, "Royalty release binding commitment"),
            release_policy_commitment=_pattern(value.get("release_policy_commitment"), _BYTES32, "Royalty release policy commitment"),
            authority_nonce=_integer(value.get("authority_nonce"), "Royalty authority nonce", minimum=1, maximum=MAX_UINT256),
            settlement_verifier_address=_address(value.get("settlement_verifier_address"), "Royalty settlement verifier", allow_zero=False),
            qvl_verifier_address=_address(value.get("qvl_verifier_address"), "Royalty QVL verifier", allow_zero=False),
            execution_policy_anchor_address=_address(value.get("execution_policy_anchor_address"), "Royalty execution policy anchor", allow_zero=False),
            anchor_writer_address=_address(value.get("anchor_writer_address"), "Royalty anchor writer", allow_zero=False),
            anchor_writer_release_commitment=_pattern(value.get("anchor_writer_release_commitment"), _BYTES32, "Royalty anchor-writer release commitment"),
            distributor_paused=value["distributor_paused"],
            pending_authority_empty=value["pending_authority_empty"],
            anchor_paused=value["anchor_paused"],
            anchor_writer_rotations_frozen=value["anchor_writer_rotations_frozen"],
            reservation_id=_pattern(value.get("reservation_id"), _BYTES32, "Royalty reservation id"),
            reservation_active=value["reservation_active"],
            reservation_consumed=value["reservation_consumed"],
            reservation_sponsor_address=_address(value.get("reservation_sponsor_address"), "Royalty reservation sponsor", allow_zero=False),
            reservation_asset=_address(value.get("reservation_asset"), "Royalty reservation asset", allow_zero=True),
            reservation_total=_integer(value.get("reservation_total"), "Royalty reservation total", minimum=1, maximum=MAX_UINT256),
            reservation_owner_amounts_hash=_pattern(value.get("reservation_owner_amounts_hash"), _BYTES32, "Royalty reservation owner amounts hash"),
            reservation_release_policy_commitment=_pattern(value.get("reservation_release_policy_commitment"), _BYTES32, "Royalty reservation release policy commitment"),
            reservation_execution_intent_commitment=_pattern(value.get("reservation_execution_intent_commitment"), _SHA256, "Royalty reservation execution intent commitment"),
            reservation_refund_after=_timestamp(value.get("reservation_refund_after"), "Royalty reservation refund time"),
            reservation_deposited_amount=_integer(value.get("reservation_deposited_amount"), "Royalty reservation deposited amount", minimum=1, maximum=MAX_UINT256),
            source_record_commitment=_pattern(value.get("source_record_commitment"), _SHA256, "Royalty source record commitment"),
            source_authentication_receipt=_pattern(value.get("source_authentication_receipt"), _SHA256, "Royalty source authentication receipt"),
            observed_at=_timestamp(value.get("observed_at"), "Royalty observation time"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "FinalizedRoyaltyAuthorityObservation":
        expected = {
            "schema", "chain_id", "block_number", "block_hash", "block_timestamp",
            "distributor_address", "distributor_runtime_code_hash",
            "owner_address", "pending_owner_address",
            "release_binding_commitment", "release_policy_commitment", "authority_nonce",
            "settlement_verifier_address", "qvl_verifier_address",
            "execution_policy_anchor_address", "anchor_writer_address",
            "anchor_writer_release_commitment", "distributor_paused",
            "pending_authority_empty", "anchor_paused",
            "anchor_writer_rotations_frozen", "reservation_id",
            "reservation_active", "reservation_consumed",
            "reservation_sponsor_address", "reservation_asset",
            "reservation_total", "reservation_owner_amounts_hash",
            "reservation_release_policy_commitment",
            "reservation_execution_intent_commitment",
            "reservation_refund_after", "reservation_deposited_amount",
            "source_record_commitment", "source_authentication_receipt", "observed_at",
        }
        if not isinstance(value, Mapping) or set(value) != expected or value.get("schema") != ROYALTY_OBSERVATION_SCHEMA:
            raise CollaborationExecutionError("finalized Royalty authority observation schema is invalid")
        return cls.create(**{field: value[field] for field in expected - {"schema"}})

    def validate_for(
        self,
        intent: CollaborationExecutionIntent,
        reservation: RoyaltyFundingReservation,
        *,
        claimed_at: int,
    ) -> None:
        timestamp = _timestamp(claimed_at, "claim time")
        if not isinstance(reservation, RoyaltyFundingReservation):
            raise CollaborationExecutionAuthorityUnavailable(
                "derived Royalty funding reservation is unavailable"
            )
        if self.observed_at != timestamp:
            raise CollaborationExecutionAuthorityUnavailable(
                "Royalty authority observation is not from the atomic claim"
            )
        exact = (
            self.chain_id == intent.chain_id
            and self.distributor_address == reservation.distributor_address
            and self.distributor_address == intent.royalty_distributor_address
            and self.release_binding_commitment == intent.royalty_release_binding_commitment
            and self.release_policy_commitment
            == intent.royalty_release_policy_commitment
            and self.reservation_id == reservation.reservation_id
            and self.reservation_sponsor_address == reservation.sponsor_address
            and self.reservation_asset == reservation.asset
            and self.reservation_total == reservation.total
            and self.reservation_owner_amounts_hash
            == reservation.owners_amounts_hash
            and self.reservation_release_policy_commitment
            == reservation.release_policy_commitment
            and self.reservation_execution_intent_commitment
            == intent.commitment
            and self.reservation_deposited_amount == reservation.total
            and self.reservation_refund_after
            == reservation.refund_after
        )
        if not exact:
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty release or funding reservation changed before claim"
            )
        if (
            self.distributor_paused
            or not self.pending_authority_empty
            or self.anchor_paused
            or not self.anchor_writer_rotations_frozen
            or self.pending_owner_address != "0x" + "0" * 40
            or self.owner_address
            in {
                self.distributor_address,
                self.settlement_verifier_address,
                self.qvl_verifier_address,
                self.execution_policy_anchor_address,
                self.anchor_writer_address,
            }
            or not self.reservation_active
            or self.reservation_consumed
            or self.reservation_refund_after <= self.block_timestamp
            or self.settlement_verifier_address == self.qvl_verifier_address
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "Royalty settlement rail is not currently usable"
            )

    @property
    def commitment(self) -> str:
        return _domain_commitment(
            b"dnai-wikigen/collaboration-finalized-royalty-observation/v1\0",
            self.to_dict(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"schema": ROYALTY_OBSERVATION_SCHEMA, **{
            field: getattr(self, field)
            for field in self.__dataclass_fields__
        }}


@dataclass(frozen=True)
class ClaimAuthoritySnapshot:
    """Fresh exact reconstruction from live release/room/reservation authority.

    The callback used by :meth:`CollaborationExecutionJournal.claim_next`
    reconstructs ``current_intent`` from the current Collaboration room/query,
    release configuration, Compute dispatch metadata, funding reservation,
    and royalty allocation.  Comparing the one canonical commitment makes any
    change to those fields invalidate the claim.  ``current_execution_grants``
    must likewise be reconstructed from the current per-owner grant authority.
    """

    current_intent: CollaborationExecutionIntent
    current_execution_grants: tuple[OwnerExecutionGrant, ...]
    finalized_vault_observation: FinalizedComputeVaultObservation
    finalized_royalty_observation: FinalizedRoyaltyAuthorityObservation
    observed_at: int

    @classmethod
    def create(
        cls,
        *,
        current_intent: CollaborationExecutionIntent,
        current_execution_grants: Sequence[OwnerExecutionGrant],
        finalized_vault_observation: FinalizedComputeVaultObservation,
        finalized_royalty_observation: FinalizedRoyaltyAuthorityObservation,
        observed_at: int,
    ) -> "ClaimAuthoritySnapshot":
        if not isinstance(current_intent, CollaborationExecutionIntent):
            raise CollaborationExecutionAuthorityUnavailable(
                "claim snapshot current intent is invalid"
            )
        if not isinstance(
            finalized_vault_observation,
            FinalizedComputeVaultObservation,
        ):
            raise CollaborationExecutionAuthorityUnavailable(
                "claim snapshot finalized Compute vault observation is invalid"
            )
        if not isinstance(
            finalized_royalty_observation,
            FinalizedRoyaltyAuthorityObservation,
        ):
            raise CollaborationExecutionAuthorityUnavailable(
                "claim snapshot finalized Royalty observation is invalid"
            )
        return cls(
            current_intent=current_intent,
            current_execution_grants=tuple(current_execution_grants),
            finalized_vault_observation=finalized_vault_observation,
            finalized_royalty_observation=finalized_royalty_observation,
            observed_at=_timestamp(observed_at, "claim snapshot time"),
        )

    def validate_for(
        self,
        expected_intent: CollaborationExecutionIntent,
        expected_grants: Sequence[OwnerExecutionGrant],
        *,
        claimed_at: int,
    ) -> None:
        timestamp = _timestamp(claimed_at, "claim time")
        if self.observed_at != timestamp:
            raise CollaborationExecutionAuthorityUnavailable(
                "claim authority snapshot is not from the atomic claim observation"
            )
        if timestamp >= expected_intent.authorization_expiry:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute job authorization expired before claim"
            )
        if not hmac.compare_digest(
            self.current_intent.commitment, expected_intent.commitment
        ):
            raise CollaborationExecutionAuthorityInvalidated(
                "release, room, query, Compute, funding, or royalty authority changed before claim"
            )
        self.finalized_vault_observation.validate_for(
            expected_intent,
            claimed_at=timestamp,
        )
        grant_set = execution_grant_set_commitment(
            expected_intent.to_basis(),
            expected_grants,
            now=timestamp,
        )
        reservation = RoyaltyFundingReservation.derive(
            expected_intent,
            execution_grant_set_commitment=grant_set,
        )
        self.finalized_royalty_observation.validate_for(
            expected_intent,
            reservation,
            claimed_at=timestamp,
        )
        if (
            self.finalized_royalty_observation.block_number
            != self.finalized_vault_observation.block_number
            or self.finalized_royalty_observation.block_hash
            != self.finalized_vault_observation.block_hash
            or self.finalized_royalty_observation.block_timestamp
            != self.finalized_vault_observation.block_timestamp
        ):
            raise CollaborationExecutionAuthorityUnavailable(
                "Compute and Royalty authority are not pinned to one finalized block"
            )
        expected_set = execution_grant_set_commitment(
            expected_intent.to_basis(), expected_grants, now=timestamp
        )
        current_set = execution_grant_set_commitment(
            self.current_intent.to_basis(),
            self.current_execution_grants,
            now=timestamp,
        )
        if not hmac.compare_digest(current_set, expected_set):
            raise CollaborationExecutionAuthorityInvalidated(
                "one or more owner execution grants changed before claim"
            )


@dataclass(frozen=True)
class BoundedExecutionResult:
    """Finite result projection; never a carrier for provider output."""

    execution_id: str
    intent_commitment: str
    authorization_commitment: str
    outcome: str
    result_class: str
    result_policy: str
    result_commitment: str
    usage_commitment: str
    actual_compute_asset_debit: int
    billable_compute_units: int
    score_band: str
    result_binding_commitment: str

    @classmethod
    def create(
        cls,
        *,
        execution_id: str,
        intent_commitment: str,
        authorization_commitment: str,
        outcome: str,
        result_class: str,
        result_policy: str,
        result_commitment: str,
        usage_commitment: str,
        actual_compute_asset_debit: int,
        billable_compute_units: int,
        score_band: str,
    ) -> "BoundedExecutionResult":
        normalized_outcome = _choice(outcome, {"succeeded", "failed"}, "outcome")
        expected_class = (
            "completed_within_authorized_caps"
            if normalized_outcome == "succeeded"
            else "provider_failed_without_raw_detail"
        )
        if result_class != expected_class:
            raise CollaborationExecutionError(
                "bounded result class does not match its outcome"
            )
        normalized_policy = _choice(
            result_policy, _RESULT_POLICIES, "bounded result policy"
        )
        normalized_band = _choice(score_band, _SCORE_BANDS, "score band")
        if normalized_policy == "bounded_summary_receipt" and normalized_band != "not_released":
            raise CollaborationExecutionError(
                "bounded summary policy cannot release a score band"
            )
        if normalized_outcome == "failed" and normalized_band != "not_released":
            raise CollaborationExecutionError(
                "failed execution cannot release a score band"
            )
        normalized_execution_id = _pattern(
            execution_id, _EXECUTION_ID, "bounded result execution id"
        )
        normalized_intent_commitment = _pattern(
            intent_commitment, _SHA256, "bounded result intent commitment"
        )
        normalized_authorization_commitment = _pattern(
            authorization_commitment,
            _SHA256,
            "bounded result authorization commitment",
        )
        normalized_result_commitment = _pattern(
            result_commitment, _SHA256, "bounded result commitment"
        )
        normalized_usage_commitment = _pattern(
            usage_commitment, _SHA256, "bounded usage commitment"
        )
        normalized_debit = _integer(
            actual_compute_asset_debit,
            "actual Compute asset debit",
            minimum=0,
            maximum=MAX_UINT256,
        )
        normalized_units = _integer(
            billable_compute_units,
            "billable compute units",
            minimum=0,
            maximum=2**63 - 1,
        )
        binding = _domain_commitment(
            _RESULT_BINDING_DOMAIN,
            {
                "schema": "dnai.collaboration.bounded-execution-result-binding.v1",
                "execution_id": normalized_execution_id,
                "intent_commitment": normalized_intent_commitment,
                "authorization_commitment": normalized_authorization_commitment,
                "outcome": normalized_outcome,
                "result_class": expected_class,
                "result_policy": normalized_policy,
                "result_commitment": normalized_result_commitment,
                "usage_commitment": normalized_usage_commitment,
                "actual_compute_asset_debit": normalized_debit,
                "billable_compute_units": normalized_units,
                "score_band": normalized_band,
            },
        )
        return cls(
            execution_id=normalized_execution_id,
            intent_commitment=normalized_intent_commitment,
            authorization_commitment=normalized_authorization_commitment,
            outcome=normalized_outcome,
            result_class=expected_class,
            result_policy=normalized_policy,
            result_commitment=normalized_result_commitment,
            usage_commitment=normalized_usage_commitment,
            actual_compute_asset_debit=normalized_debit,
            billable_compute_units=normalized_units,
            score_band=normalized_band,
            result_binding_commitment=binding,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BoundedExecutionResult":
        expected = {
            "schema",
            "execution_id",
            "intent_commitment",
            "authorization_commitment",
            "outcome",
            "result_class",
            "result_policy",
            "result_commitment",
            "usage_commitment",
            "actual_compute_asset_debit",
            "billable_compute_units",
            "score_band",
            "result_binding_commitment",
            "provider_authoritative_invoice",
            "raw_result_persisted",
            "provider_identifier_persisted",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise CollaborationExecutionError("bounded execution result schema is invalid")
        if (
            value.get("schema") != RESULT_SCHEMA
            or value.get("provider_authoritative_invoice") is not False
            or value.get("raw_result_persisted") is not False
            or value.get("provider_identifier_persisted") is not False
        ):
            raise CollaborationExecutionError("bounded execution result flags are invalid")
        parsed = cls.create(
            **{
                field: value[field]
                for field in expected
                - {
                    "schema",
                    "provider_authoritative_invoice",
                    "raw_result_persisted",
                    "provider_identifier_persisted",
                    "result_binding_commitment",
                }
            }
        )
        if value["result_binding_commitment"] != parsed.result_binding_commitment:
            raise CollaborationExecutionError(
                "bounded execution result binding commitment is invalid"
            )
        return parsed

    def validate_for(
        self,
        intent: CollaborationExecutionIntent,
        *,
        authorization_commitment: str,
    ) -> None:
        authorization = _pattern(
            authorization_commitment,
            _SHA256,
            "execution authorization commitment",
        )
        if (
            self.execution_id != intent.execution_id
            or self.intent_commitment != intent.commitment
            or self.authorization_commitment != authorization
        ):
            raise CollaborationExecutionError(
                "bounded result binds a different collaboration execution"
            )
        if self.result_policy != intent.result_policy:
            raise CollaborationExecutionError(
                "bounded result policy does not match the authorized intent"
            )
        if self.actual_compute_asset_debit > intent.max_compute_asset_debit:
            raise CollaborationExecutionError(
                "bounded result Compute debit exceeds the exact Compute cap"
            )
        if self.outcome == "succeeded" and (
            self.actual_compute_asset_debit + intent.royalty_total
            > intent.max_total_asset_debit
        ):
            raise CollaborationExecutionError(
                "compute debit plus reserved royalty exceeds the all-in authorization cap"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RESULT_SCHEMA,
            "execution_id": self.execution_id,
            "intent_commitment": self.intent_commitment,
            "authorization_commitment": self.authorization_commitment,
            "outcome": self.outcome,
            "result_class": self.result_class,
            "result_policy": self.result_policy,
            "result_commitment": self.result_commitment,
            "usage_commitment": self.usage_commitment,
            "actual_compute_asset_debit": self.actual_compute_asset_debit,
            "billable_compute_units": self.billable_compute_units,
            "score_band": self.score_band,
            "result_binding_commitment": self.result_binding_commitment,
            "provider_authoritative_invoice": False,
            "raw_result_persisted": False,
            "provider_identifier_persisted": False,
        }


@dataclass(frozen=True)
class ComputeHandoff:
    """Pre-claim deterministic plan for one idempotent Compute submission."""

    handoff_id: str
    execution_id: str
    intent_commitment: str
    authorization_commitment: str
    compute_project_id: str
    compute_job_id: str
    compute_workload_id: str
    compute_workload_commitment: str
    compute_manifest_commitment: str
    compute_dispatch_intent_commitment: str
    compute_dispatch_intent: ComputeDispatchIntent
    compute_rate_policy_commitment: str
    compute_workload_schema: str
    compute_workload_source_kind: str
    compute_workload_execution_binding_commitment: str
    compute_workload_recipient_release_commitment: str
    compute_authorization_kind: str
    compute_authorization_context_commitment: str
    compute_user_address: str
    asset: str
    authorization_nonce: int
    max_total_asset_debit: int
    max_compute_asset_debit: int
    authorization_expiry: int
    royalty_total: int
    royalty_owner_amounts_hash: str
    royalty_release_binding_commitment: str
    royalty_settlement_id: str
    royalty_settlement_nonce: int
    royalty_reservation_safety_seconds: int
    planned_at: int

    @classmethod
    def create(
        cls,
        intent: CollaborationExecutionIntent,
        *,
        authorization_commitment: str,
        planned_at: int,
    ) -> "ComputeHandoff":
        if not isinstance(intent, CollaborationExecutionIntent):
            raise CollaborationExecutionError("Compute handoff intent is invalid")
        authorization = _pattern(
            authorization_commitment,
            _SHA256,
            "Compute handoff authorization commitment",
        )
        compute_intent = _build_collaboration_compute_dispatch_intent(
            intent.to_basis(),
            authorization_context_commitment=(
                intent.compute_authorization_context_commitment
            ),
        )
        if compute_intent.commitment != intent.compute_dispatch_intent_commitment:
            raise CollaborationExecutionAuthorityInvalidated(
                "Compute handoff intent does not match the finalized dispatch commitment"
            )
        digest = hashlib.sha256(
            b"dnai-wikigen/collaboration-compute-handoff-id/v1\x00"
            + _canonical_json(
                {
                    "execution_id": intent.execution_id,
                    "intent_commitment": intent.commitment,
                    "authorization_commitment": authorization,
                    "compute_job_id": intent.compute_job_id,
                    "compute_dispatch_intent_commitment": (
                        intent.compute_dispatch_intent_commitment
                    ),
                    "compute_authorization_context_commitment": (
                        intent.compute_authorization_context_commitment
                    ),
                }
            )
        ).hexdigest()
        return cls(
            handoff_id=f"chandoff_{digest}",
            execution_id=intent.execution_id,
            intent_commitment=intent.commitment,
            authorization_commitment=authorization,
            compute_project_id=intent.compute_project_id,
            compute_job_id=intent.compute_job_id,
            compute_workload_id=intent.compute_workload_id,
            compute_workload_commitment=intent.compute_workload_commitment,
            compute_manifest_commitment=intent.compute_manifest_commitment,
            compute_dispatch_intent_commitment=(
                intent.compute_dispatch_intent_commitment
            ),
            compute_dispatch_intent=compute_intent,
            compute_rate_policy_commitment=(
                intent.compute_rate_policy_commitment
            ),
            compute_workload_schema=intent.compute_workload_schema,
            compute_workload_source_kind=intent.compute_workload_source_kind,
            compute_workload_execution_binding_commitment=(
                intent.compute_workload_execution_binding_commitment
            ),
            compute_workload_recipient_release_commitment=(
                intent.compute_workload_recipient_release_commitment
            ),
            compute_authorization_kind=intent.compute_authorization_kind,
            compute_authorization_context_commitment=(
                intent.compute_authorization_context_commitment
            ),
            compute_user_address=intent.compute_user_address,
            asset=intent.asset,
            authorization_nonce=intent.authorization_nonce,
            max_total_asset_debit=intent.max_total_asset_debit,
            max_compute_asset_debit=intent.max_compute_asset_debit,
            authorization_expiry=intent.authorization_expiry,
            royalty_total=intent.royalty_total,
            royalty_owner_amounts_hash=intent.royalty_owner_amounts_hash,
            royalty_release_binding_commitment=(
                intent.royalty_release_binding_commitment
            ),
            royalty_settlement_id=intent.royalty_settlement_id,
            royalty_settlement_nonce=intent.royalty_settlement_nonce,
            royalty_reservation_safety_seconds=(
                intent.royalty_reservation_safety_seconds
            ),
            planned_at=_timestamp(planned_at, "Compute handoff plan time"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComputeHandoff":
        expected = {
            "schema",
            "handoff_id",
            "execution_id",
            "intent_commitment",
            "authorization_commitment",
            "compute_project_id",
            "compute_job_id",
            "compute_workload_id",
            "compute_workload_commitment",
            "compute_manifest_commitment",
            "compute_dispatch_intent_commitment",
            "compute_dispatch_intent",
            "compute_rate_policy_commitment",
            "compute_workload_schema",
            "compute_workload_source_kind",
            "compute_workload_execution_binding_commitment",
            "compute_workload_recipient_release_commitment",
            "compute_authorization_kind",
            "compute_authorization_context_commitment",
            "compute_user_address",
            "asset",
            "authorization_nonce",
            "max_total_asset_debit",
            "max_compute_asset_debit",
            "authorization_expiry",
            "royalty_total",
            "royalty_owner_amounts_hash",
            "royalty_release_binding_commitment",
            "royalty_settlement_id",
            "royalty_settlement_nonce",
            "royalty_reservation_safety_seconds",
            "planned_at",
            "handoff_commitment",
            "provider_call_performed_by_collaboration",
        }
        if (
            not isinstance(value, Mapping)
            or set(value) != expected
            or value.get("schema") != COMPUTE_HANDOFF_SCHEMA
            or value.get("provider_call_performed_by_collaboration") is not False
        ):
            raise CollaborationExecutionError("Compute handoff schema is invalid")
        handoff = cls(
            handoff_id=_pattern(value["handoff_id"], _HANDOFF_ID, "Compute handoff id"),
            execution_id=_pattern(value["execution_id"], _EXECUTION_ID, "execution id"),
            intent_commitment=_pattern(value["intent_commitment"], _SHA256, "intent commitment"),
            authorization_commitment=_pattern(value["authorization_commitment"], _SHA256, "authorization commitment"),
            compute_project_id=_pattern(value["compute_project_id"], _BYTES32, "Compute project id"),
            compute_job_id=_pattern(value["compute_job_id"], _BYTES32, "Compute job id"),
            compute_workload_id=_pattern(value["compute_workload_id"], _WORKLOAD_ID, "Compute workload id"),
            compute_workload_commitment=_pattern(value["compute_workload_commitment"], _BYTES32, "Compute workload commitment"),
            compute_manifest_commitment=_pattern(value["compute_manifest_commitment"], _BYTES32, "Compute manifest commitment"),
            compute_dispatch_intent_commitment=_pattern(value["compute_dispatch_intent_commitment"], _BYTES32, "Compute dispatch intent commitment"),
            compute_dispatch_intent=ComputeDispatchIntent.from_dict(value["compute_dispatch_intent"]),
            compute_rate_policy_commitment=_pattern(value["compute_rate_policy_commitment"], _BYTES32, "Compute rate policy commitment"),
            compute_workload_schema=_choice(value["compute_workload_schema"], {INFERENCE_WORKLOAD_SCHEMA, SFT_JSONL_WORKLOAD_SCHEMA}, "Compute workload schema"),
            compute_workload_source_kind=_choice(value["compute_workload_source_kind"], {"wallet", "credential"}, "Compute workload source kind"),
            compute_workload_execution_binding_commitment=_pattern(value["compute_workload_execution_binding_commitment"], _SHA256, "Compute workload execution binding commitment"),
            compute_workload_recipient_release_commitment=_pattern(value["compute_workload_recipient_release_commitment"], _SHA256, "Compute workload recipient release commitment"),
            compute_authorization_kind=_choice(value["compute_authorization_kind"], {"collaboration_one_shot"}, "Compute authorization kind"),
            compute_authorization_context_commitment=_pattern(value["compute_authorization_context_commitment"], _SHA256, "Compute authorization context commitment"),
            compute_user_address=_address(value["compute_user_address"], "Compute user", allow_zero=False),
            asset=_address(value["asset"], "Compute asset", allow_zero=True),
            authorization_nonce=_integer(value["authorization_nonce"], "authorization nonce", minimum=0, maximum=MAX_UINT256),
            max_total_asset_debit=_integer(value["max_total_asset_debit"], "maximum total debit", minimum=1, maximum=MAX_UINT256),
            max_compute_asset_debit=_integer(value["max_compute_asset_debit"], "maximum Compute debit", minimum=1, maximum=MAX_UINT256),
            authorization_expiry=_timestamp(value["authorization_expiry"], "authorization expiry"),
            royalty_total=_integer(value["royalty_total"], "royalty total", minimum=1, maximum=MAX_UINT256),
            royalty_owner_amounts_hash=_pattern(value["royalty_owner_amounts_hash"], _BYTES32, "royalty owner amounts hash"),
            royalty_release_binding_commitment=_pattern(value["royalty_release_binding_commitment"], _SHA256, "royalty release binding commitment"),
            royalty_settlement_id=_pattern(value["royalty_settlement_id"], _BYTES32, "royalty settlement id"),
            royalty_settlement_nonce=_decimal_uint(value["royalty_settlement_nonce"], "royalty settlement nonce", minimum=1, maximum=MAX_UINT256),
            royalty_reservation_safety_seconds=_integer(value["royalty_reservation_safety_seconds"], "royalty reservation safety window", minimum=60, maximum=3_600),
            planned_at=_timestamp(value["planned_at"], "Compute handoff plan time"),
        )
        if not hmac.compare_digest(
            handoff.compute_dispatch_intent.commitment,
            handoff.compute_dispatch_intent_commitment,
        ):
            raise CollaborationExecutionError(
                "Compute handoff dispatch intent commitment is invalid"
            )
        if value["handoff_commitment"] != handoff.commitment:
            raise CollaborationExecutionError("Compute handoff commitment is invalid")
        return handoff

    def validate_for(
        self,
        intent: CollaborationExecutionIntent,
        *,
        authorization_commitment: str,
    ) -> None:
        expected = ComputeHandoff.create(
            intent,
            authorization_commitment=authorization_commitment,
            planned_at=self.planned_at,
        )
        if self != expected:
            raise CollaborationExecutionConflict(
                "Compute handoff does not match the exact collaboration intent"
            )

    @property
    def commitment(self) -> str:
        return _domain_commitment(
            b"dnai-wikigen/collaboration-compute-handoff/v1\x00",
            self._binding_dict(),
        )

    def _binding_dict(self) -> dict[str, Any]:
        return {
            "schema": COMPUTE_HANDOFF_SCHEMA,
            "handoff_id": self.handoff_id,
            "execution_id": self.execution_id,
            "intent_commitment": self.intent_commitment,
            "authorization_commitment": self.authorization_commitment,
            "compute_project_id": self.compute_project_id,
            "compute_job_id": self.compute_job_id,
            "compute_workload_id": self.compute_workload_id,
            "compute_workload_commitment": self.compute_workload_commitment,
            "compute_manifest_commitment": self.compute_manifest_commitment,
            "compute_dispatch_intent_commitment": self.compute_dispatch_intent_commitment,
            "compute_dispatch_intent": self.compute_dispatch_intent.to_dict(),
            "compute_rate_policy_commitment": self.compute_rate_policy_commitment,
            "compute_workload_schema": self.compute_workload_schema,
            "compute_workload_source_kind": self.compute_workload_source_kind,
            "compute_workload_execution_binding_commitment": self.compute_workload_execution_binding_commitment,
            "compute_workload_recipient_release_commitment": self.compute_workload_recipient_release_commitment,
            "compute_authorization_kind": self.compute_authorization_kind,
            "compute_authorization_context_commitment": self.compute_authorization_context_commitment,
            "compute_user_address": self.compute_user_address,
            "asset": self.asset,
            "authorization_nonce": self.authorization_nonce,
            "max_total_asset_debit": self.max_total_asset_debit,
            "max_compute_asset_debit": self.max_compute_asset_debit,
            "authorization_expiry": self.authorization_expiry,
            "royalty_total": self.royalty_total,
            "royalty_owner_amounts_hash": self.royalty_owner_amounts_hash,
            "royalty_release_binding_commitment": (
                self.royalty_release_binding_commitment
            ),
            "royalty_settlement_id": self.royalty_settlement_id,
            "royalty_settlement_nonce": str(self.royalty_settlement_nonce),
            "royalty_reservation_safety_seconds": (
                self.royalty_reservation_safety_seconds
            ),
            "planned_at": self.planned_at,
            "provider_call_performed_by_collaboration": False,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._binding_dict(), "handoff_commitment": self.commitment}


@dataclass(frozen=True)
class ComputeJournalProjection:
    """Bounded, exact-field projection for a trusted Compute-journal reader.

    The type and its self-commitment detect field substitution after
    construction; they are not proof of journal origin. Production integration
    must create this object only from the authenticated local Compute journal,
    never from request data. The public Collaboration surface keeps that source
    authentication boundary explicit until such a reader is wired.
    """

    compute_journal_schema: str
    source_sequence: int
    source_record_commitment: str
    source_journal_mac_commitment: str
    source_authentication_receipt: str
    handoff_id: str
    handoff_commitment: str
    execution_id: str
    intent_commitment: str
    authorization_commitment: str
    compute_project_id: str
    compute_job_id: str
    compute_workload_id: str
    compute_workload_commitment: str
    compute_manifest_commitment: str
    compute_dispatch_intent_commitment: str
    compute_authorization_kind: str
    compute_authorization_context_commitment: str
    compute_user_address: str
    asset: str
    max_compute_asset_debit: int
    authorization_expiry: int
    compute_stage: str
    provider_dispatch_may_have_occurred: bool
    automatic_provider_redispatch: bool
    bounded_result: BoundedExecutionResult | None
    observed_at: int

    @classmethod
    def create(
        cls,
        *,
        handoff: ComputeHandoff,
        source_sequence: int,
        source_record_commitment: str,
        source_journal_mac_commitment: str,
        source_authentication_receipt: str,
        compute_stage: str,
        provider_dispatch_may_have_occurred: bool,
        automatic_provider_redispatch: bool,
        bounded_result: BoundedExecutionResult | None,
        observed_at: int,
    ) -> "ComputeJournalProjection":
        if not isinstance(handoff, ComputeHandoff):
            raise CollaborationExecutionError("Compute handoff is required")
        stage = _choice(compute_stage, _COMPUTE_STAGES, "Compute journal stage")
        if type(provider_dispatch_may_have_occurred) is not bool:
            raise CollaborationExecutionError("Compute provider-boundary projection is invalid")
        if automatic_provider_redispatch is not False:
            raise CollaborationExecutionError("Compute projection permits automatic provider redispatch")
        if stage in _COMPUTE_PRE_BOUNDARY_STAGES and provider_dispatch_may_have_occurred:
            raise CollaborationExecutionError("pre-boundary Compute stage claims provider dispatch")
        if stage in _COMPUTE_BOUNDARY_STAGES and not provider_dispatch_may_have_occurred:
            raise CollaborationExecutionError("post-boundary Compute stage omits provider ambiguity")
        if stage == "provider_outcome_ambiguous" and bounded_result is not None:
            raise CollaborationExecutionError("ambiguous Compute outcome cannot carry a result")
        if stage == "settled" and bounded_result is None:
            raise CollaborationExecutionError("settled Compute projection requires a bounded result")
        if stage not in {"settled", "blocked"} and bounded_result is not None:
            raise CollaborationExecutionError(
                "nonterminal Compute projection cannot carry a bounded result"
            )
        if stage == "blocked" and bounded_result is not None and bounded_result.outcome != "failed":
            raise CollaborationExecutionError("blocked Compute projection cannot carry success")
        return cls(
            compute_journal_schema=COMPUTE_SOURCE_JOURNAL_SCHEMA,
            source_sequence=_integer(
                source_sequence,
                "Compute source journal sequence",
                minimum=1,
                maximum=2**63 - 1,
            ),
            source_record_commitment=_pattern(
                source_record_commitment,
                _SHA256,
                "Compute source record commitment",
            ),
            source_journal_mac_commitment=_pattern(
                source_journal_mac_commitment,
                _SHA256,
                "Compute source journal MAC commitment",
            ),
            source_authentication_receipt=_pattern(
                source_authentication_receipt,
                _SHA256,
                "Compute source authentication receipt",
            ),
            handoff_id=handoff.handoff_id,
            handoff_commitment=handoff.commitment,
            execution_id=handoff.execution_id,
            intent_commitment=handoff.intent_commitment,
            authorization_commitment=handoff.authorization_commitment,
            compute_project_id=handoff.compute_project_id,
            compute_job_id=handoff.compute_job_id,
            compute_workload_id=handoff.compute_workload_id,
            compute_workload_commitment=handoff.compute_workload_commitment,
            compute_manifest_commitment=handoff.compute_manifest_commitment,
            compute_dispatch_intent_commitment=handoff.compute_dispatch_intent_commitment,
            compute_authorization_kind=handoff.compute_authorization_kind,
            compute_authorization_context_commitment=(
                handoff.compute_authorization_context_commitment
            ),
            compute_user_address=handoff.compute_user_address,
            asset=handoff.asset,
            max_compute_asset_debit=handoff.max_compute_asset_debit,
            authorization_expiry=handoff.authorization_expiry,
            compute_stage=stage,
            provider_dispatch_may_have_occurred=provider_dispatch_may_have_occurred,
            automatic_provider_redispatch=False,
            bounded_result=bounded_result,
            observed_at=_timestamp(observed_at, "Compute projection observation time"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComputeJournalProjection":
        expected = {
            "schema", "compute_journal_schema", "source_sequence",
            "source_record_commitment", "source_journal_mac_commitment",
            "source_authentication_receipt", "handoff_id",
            "handoff_commitment", "execution_id",
            "intent_commitment", "authorization_commitment", "compute_project_id",
            "compute_job_id", "compute_workload_id", "compute_workload_commitment",
            "compute_manifest_commitment", "compute_dispatch_intent_commitment",
            "compute_authorization_kind",
            "compute_authorization_context_commitment",
            "compute_user_address", "asset", "max_compute_asset_debit",
            "authorization_expiry", "compute_stage",
            "provider_dispatch_may_have_occurred", "automatic_provider_redispatch",
            "bounded_result", "observed_at", "projection_commitment",
        }
        if not isinstance(value, Mapping) or set(value) != expected or value.get("schema") != COMPUTE_PROJECTION_SCHEMA:
            raise CollaborationExecutionError("Compute journal projection schema is invalid")
        result = None if value["bounded_result"] is None else BoundedExecutionResult.from_dict(value["bounded_result"])
        projection = cls(
            compute_journal_schema=_choice(
                value["compute_journal_schema"],
                {COMPUTE_SOURCE_JOURNAL_SCHEMA},
                "Compute source journal schema",
            ),
            source_sequence=_integer(
                value["source_sequence"],
                "Compute source journal sequence",
                minimum=1,
                maximum=2**63 - 1,
            ),
            source_record_commitment=_pattern(
                value["source_record_commitment"],
                _SHA256,
                "Compute source record commitment",
            ),
            source_journal_mac_commitment=_pattern(
                value["source_journal_mac_commitment"],
                _SHA256,
                "Compute source journal MAC commitment",
            ),
            source_authentication_receipt=_pattern(
                value["source_authentication_receipt"],
                _SHA256,
                "Compute source authentication receipt",
            ),
            handoff_id=_pattern(value["handoff_id"], _HANDOFF_ID, "Compute handoff id"),
            handoff_commitment=_pattern(value["handoff_commitment"], _SHA256, "Compute handoff commitment"),
            execution_id=_pattern(value["execution_id"], _EXECUTION_ID, "execution id"),
            intent_commitment=_pattern(value["intent_commitment"], _SHA256, "intent commitment"),
            authorization_commitment=_pattern(value["authorization_commitment"], _SHA256, "authorization commitment"),
            compute_project_id=_pattern(value["compute_project_id"], _BYTES32, "Compute project id"),
            compute_job_id=_pattern(value["compute_job_id"], _BYTES32, "Compute job id"),
            compute_workload_id=_pattern(value["compute_workload_id"], _WORKLOAD_ID, "Compute workload id"),
            compute_workload_commitment=_pattern(value["compute_workload_commitment"], _BYTES32, "Compute workload commitment"),
            compute_manifest_commitment=_pattern(value["compute_manifest_commitment"], _BYTES32, "Compute manifest commitment"),
            compute_dispatch_intent_commitment=_pattern(value["compute_dispatch_intent_commitment"], _BYTES32, "Compute dispatch intent commitment"),
            compute_authorization_kind=_choice(value["compute_authorization_kind"], {"collaboration_one_shot"}, "Compute authorization kind"),
            compute_authorization_context_commitment=_pattern(value["compute_authorization_context_commitment"], _SHA256, "Compute authorization context commitment"),
            compute_user_address=_address(value["compute_user_address"], "Compute user", allow_zero=False),
            asset=_address(value["asset"], "Compute asset", allow_zero=True),
            max_compute_asset_debit=_integer(value["max_compute_asset_debit"], "maximum Compute debit", minimum=1, maximum=MAX_UINT256),
            authorization_expiry=_timestamp(value["authorization_expiry"], "authorization expiry"),
            compute_stage=_choice(value["compute_stage"], _COMPUTE_STAGES, "Compute stage"),
            provider_dispatch_may_have_occurred=value["provider_dispatch_may_have_occurred"],
            automatic_provider_redispatch=value["automatic_provider_redispatch"],
            bounded_result=result,
            observed_at=_timestamp(value["observed_at"], "Compute projection observation time"),
        )
        if type(projection.provider_dispatch_may_have_occurred) is not bool or projection.automatic_provider_redispatch is not False:
            raise CollaborationExecutionError("Compute projection flags are invalid")
        if (
            projection.compute_stage in _COMPUTE_PRE_BOUNDARY_STAGES
            and projection.provider_dispatch_may_have_occurred
        ):
            raise CollaborationExecutionError(
                "pre-boundary Compute stage claims provider dispatch"
            )
        if (
            projection.compute_stage in _COMPUTE_BOUNDARY_STAGES
            and not projection.provider_dispatch_may_have_occurred
        ):
            raise CollaborationExecutionError(
                "post-boundary Compute stage omits provider ambiguity"
            )
        if projection.compute_stage == "provider_outcome_ambiguous" and result is not None:
            raise CollaborationExecutionError(
                "ambiguous Compute outcome cannot carry a result"
            )
        if projection.compute_stage == "settled" and result is None:
            raise CollaborationExecutionError(
                "settled Compute projection requires a bounded result"
            )
        if (
            projection.compute_stage not in {"settled", "blocked"}
            and result is not None
        ):
            raise CollaborationExecutionError(
                "nonterminal Compute projection cannot carry a bounded result"
            )
        if projection.compute_stage == "blocked" and result is not None and result.outcome != "failed":
            raise CollaborationExecutionError(
                "blocked Compute projection cannot carry success"
            )
        if value["projection_commitment"] != projection.commitment:
            raise CollaborationExecutionError("Compute projection commitment is invalid")
        return projection

    def validate_for(
        self,
        intent: CollaborationExecutionIntent,
        handoff: ComputeHandoff,
        *,
        authorization_commitment: str,
    ) -> None:
        handoff.validate_for(intent, authorization_commitment=authorization_commitment)
        if (
            self.compute_journal_schema != COMPUTE_SOURCE_JOURNAL_SCHEMA
            or self.handoff_id != handoff.handoff_id
            or self.handoff_commitment != handoff.commitment
            or self.execution_id != intent.execution_id
            or self.intent_commitment != intent.commitment
            or self.authorization_commitment != authorization_commitment
            or self.compute_project_id != intent.compute_project_id
            or self.compute_job_id != intent.compute_job_id
            or self.compute_workload_id != intent.compute_workload_id
            or self.compute_workload_commitment != intent.compute_workload_commitment
            or self.compute_manifest_commitment != intent.compute_manifest_commitment
            or self.compute_dispatch_intent_commitment != intent.compute_dispatch_intent_commitment
            or self.compute_authorization_kind
            != intent.compute_authorization_kind
            or self.compute_authorization_context_commitment
            != intent.compute_authorization_context_commitment
            or self.compute_user_address != intent.compute_user_address
            or self.asset != intent.asset
            or self.max_compute_asset_debit != intent.max_compute_asset_debit
            or self.authorization_expiry != intent.authorization_expiry
        ):
            raise CollaborationExecutionConflict("Compute projection substitution detected")
        if self.bounded_result is not None:
            self.bounded_result.validate_for(intent, authorization_commitment=authorization_commitment)

    @property
    def commitment(self) -> str:
        return _domain_commitment(
            b"dnai-wikigen/collaboration-compute-journal-projection/v1\x00",
            self._binding_dict(),
        )

    def _binding_dict(self) -> dict[str, Any]:
        return {
            "schema": COMPUTE_PROJECTION_SCHEMA,
            "compute_journal_schema": self.compute_journal_schema,
            "source_sequence": self.source_sequence,
            "source_record_commitment": self.source_record_commitment,
            "source_journal_mac_commitment": self.source_journal_mac_commitment,
            "source_authentication_receipt": self.source_authentication_receipt,
            "handoff_id": self.handoff_id,
            "handoff_commitment": self.handoff_commitment,
            "execution_id": self.execution_id,
            "intent_commitment": self.intent_commitment,
            "authorization_commitment": self.authorization_commitment,
            "compute_project_id": self.compute_project_id,
            "compute_job_id": self.compute_job_id,
            "compute_workload_id": self.compute_workload_id,
            "compute_workload_commitment": self.compute_workload_commitment,
            "compute_manifest_commitment": self.compute_manifest_commitment,
            "compute_dispatch_intent_commitment": self.compute_dispatch_intent_commitment,
            "compute_authorization_kind": self.compute_authorization_kind,
            "compute_authorization_context_commitment": (
                self.compute_authorization_context_commitment
            ),
            "compute_user_address": self.compute_user_address,
            "asset": self.asset,
            "max_compute_asset_debit": self.max_compute_asset_debit,
            "authorization_expiry": self.authorization_expiry,
            "compute_stage": self.compute_stage,
            "provider_dispatch_may_have_occurred": self.provider_dispatch_may_have_occurred,
            "automatic_provider_redispatch": self.automatic_provider_redispatch,
            "bounded_result": self.bounded_result.to_dict() if self.bounded_result else None,
            "observed_at": self.observed_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self._binding_dict(), "projection_commitment": self.commitment}


ClaimValidator = Callable[
    [CollaborationExecutionIntent, tuple[OwnerExecutionGrant, ...], int],
    ClaimAuthoritySnapshot,
]


class CollaborationExecutionJournal:
    """HMAC-authenticated, cross-process-safe one-shot execution journal."""

    _BODY_FIELDS = {
        "schema",
        "schema_version",
        "sequence",
        "records",
        "raw_input_persisted",
        "raw_result_persisted",
        "provider_identifiers_persisted",
        "anti_rollback_provided",
    }
    _RECORD_FIELDS = {
        "intent",
        "execution_grants",
        "execution_grant_set_commitment",
        "royalty_owner_amounts",
        "royalty_funding_reservation",
        "authorization_commitment",
        "idempotency_key_hash",
        "state",
        "claim_count",
        "claim_vault_observation",
        "claim_royalty_observation",
        "compute_handoff_plan",
        "compute_projection",
        "bounded_result",
        "last_reason",
        "authorized_at",
        "queued_at",
        "claimed_at",
        "handoff_pending_at",
        "handoff_confirmed_at",
        "reconciliation_hold_at",
        "reconciliation_hold_projection_commitment",
        "terminal_at",
        "updated_at",
    }

    def __init__(self, path: str | Path, *, integrity_key: bytes) -> None:
        self.path = Path(os.path.abspath(os.fspath(path)))
        if not str(self.path) or "\x00" in str(self.path):
            raise CollaborationExecutionJournalError(
                "collaboration execution journal path is invalid"
            )
        if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
            raise CollaborationExecutionJournalError(
                "collaboration execution journal integrity key is too short"
        )
        self._integrity_key = bytes(integrity_key)
        self._thread_lock = threading.RLock()
        self._lock_path = self.path.with_name(f".{self.path.name}.lock")
        self._lock_name = self._lock_path.name
        # Open every existing ancestor without following symlinks and require
        # a private, current-owner final parent before creating any journal or
        # lock leaf. The parent must already exist; constructor path validation
        # never creates directories through an untrusted ancestor. Same-UID
        # code that can replace entries in that directory remains part of the
        # trusted local process boundary.
        with self._opened_parent():
            pass
        self._ensure_lock_file()
        with self._exclusive_lock():
            if self.path.exists() or self.path.is_symlink():
                self._load_unlocked()
            else:
                self._write_unlocked(self._empty_body())

    def authorize(
        self,
        intent: CollaborationExecutionIntent,
        grants: Sequence[OwnerExecutionGrant],
        *,
        royalty_owner_amounts: Mapping[str, int] | None = None,
        idempotency_key: str,
        authorized_at: int,
    ) -> tuple[dict[str, Any], bool]:
        if not isinstance(intent, CollaborationExecutionIntent):
            raise CollaborationExecutionError("collaboration execution intent is required")
        timestamp = _timestamp(authorized_at, "authorization time")
        key = _pattern(idempotency_key, _IDEMPOTENCY_KEY, "idempotency key")
        normalized_grants = tuple(sorted(grants, key=lambda grant: grant.owner_address))
        grant_set = execution_grant_set_commitment(
            intent.to_basis(), normalized_grants, now=timestamp
        )
        royalty_reservation = RoyaltyFundingReservation.derive(
            intent,
            execution_grant_set_commitment=grant_set,
        )
        exact_owner_amounts = _normalize_persisted_royalty_owner_amounts(
            intent,
            royalty_owner_amounts,
        )
        authorization = execution_authorization_commitment(
            intent, normalized_grants, now=timestamp
        )
        handoff_plan = ComputeHandoff.create(
            intent,
            authorization_commitment=authorization,
            planned_at=timestamp,
        )
        idem_hash = _domain_hex(_IDEMPOTENCY_DOMAIN, key.encode("ascii"))
        with self._exclusive_lock():
            body = self._load_unlocked()
            existing = body["records"].get(intent.execution_id)
            if existing is not None:
                parsed = self._validate_record(existing)
                if (
                    parsed["intent"] != intent.to_dict()
                    or parsed["execution_grant_set_commitment"] != grant_set
                    or parsed["royalty_owner_amounts"] != exact_owner_amounts
                    or parsed["authorization_commitment"] != authorization
                    or not hmac.compare_digest(parsed["idempotency_key_hash"], idem_hash)
                ):
                    raise CollaborationExecutionConflict(
                        "execution id or idempotency key already binds different authority"
                    )
                return self._public_record(parsed), False
            if len(body["records"]) >= MAX_RECORDS:
                raise CollaborationExecutionJournalError(
                    "collaboration execution journal capacity reached"
                )
            record = {
                "intent": intent.to_dict(),
                "execution_grants": [grant.to_dict() for grant in normalized_grants],
                "execution_grant_set_commitment": grant_set,
                "royalty_owner_amounts": exact_owner_amounts,
                "royalty_funding_reservation": royalty_reservation.to_dict(),
                "authorization_commitment": authorization,
                "idempotency_key_hash": idem_hash,
                "state": ExecutionState.AUTHORIZED.value,
                "claim_count": 0,
                "claim_vault_observation": None,
                "claim_royalty_observation": None,
                "compute_handoff_plan": handoff_plan.to_dict(),
                "compute_projection": None,
                "bounded_result": None,
                "last_reason": "fresh_owner_execution_grants_authorized",
                "authorized_at": timestamp,
                "queued_at": None,
                "claimed_at": None,
                "handoff_pending_at": None,
                "handoff_confirmed_at": None,
                "reconciliation_hold_at": None,
                "reconciliation_hold_projection_commitment": None,
                "terminal_at": None,
                "updated_at": timestamp,
            }
            self._validate_record(record)
            self._reject_replayed_one_shot_authority(
                record,
                body["records"],
            )
            body["records"][intent.execution_id] = record
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public_record(record), True

    def queue(self, execution_id: str, *, queued_at: int) -> dict[str, Any]:
        return self._transition(
            execution_id,
            expected=ExecutionState.AUTHORIZED,
            target=ExecutionState.QUEUED,
            reason="execution_queued_for_claim",
            timestamp=queued_at,
            updates={"queued_at": _timestamp(queued_at, "queue time")},
        )

    def claim_next(
        self,
        validator: ClaimValidator,
        *,
        claimed_at: int,
    ) -> dict[str, Any] | None:
        """Atomically validate current authority and claim the oldest queue item.

        The validator is called while the journal's process/thread lock is held.
        It must be side-effect free and reconstruct a fresh exact snapshot from
        the release, Collaboration, Compute/funding, and execution-grant
        authorities.  A current-authority rejection atomically quarantines the
        stale item before considering the next queue entry, so one revoked or
        expired authorization cannot head-of-line block later valid work. No
        Compute handoff is produced for a quarantined entry.
        """

        if not callable(validator):
            raise CollaborationExecutionError("claim validator is required")
        timestamp = _timestamp(claimed_at, "claim time")
        with self._exclusive_lock():
            body = self._load_unlocked()
            queued = [
                self._validate_record(record)
                for record in body["records"].values()
                if record.get("state") == ExecutionState.QUEUED.value
            ]
            if not queued:
                return None
            queued.sort(
                key=lambda record: (
                    int(record["queued_at"]),
                    CollaborationExecutionIntent.from_dict(record["intent"]).execution_id,
                )
            )
            claimed_candidate: dict[str, Any] | None = None
            last_authority_error: CollaborationExecutionAuthorityError | None = None
            changed = False
            for record in queued:
                intent = CollaborationExecutionIntent.from_dict(record["intent"])
                grants = tuple(
                    OwnerExecutionGrant.from_dict(item)
                    for item in record["execution_grants"]
                )
                try:
                    snapshot = validator(intent, grants, timestamp)
                    if not isinstance(snapshot, ClaimAuthoritySnapshot):
                        raise CollaborationExecutionAuthorityUnavailable(
                            "claim validator did not return an exact authority snapshot"
                        )
                    snapshot.validate_for(
                        intent,
                        grants,
                        claimed_at=timestamp,
                    )
                except CollaborationExecutionAuthorityInvalidated as exc:
                    invalidated = copy.deepcopy(record)
                    invalidated.update(
                        {
                            "state": ExecutionState.AUTHORITY_INVALIDATED.value,
                            "terminal_at": timestamp,
                            "last_reason": "claim_authority_invalidated",
                            "updated_at": timestamp,
                        }
                    )
                    self._validate_record(invalidated)
                    body["records"][intent.execution_id] = invalidated
                    last_authority_error = exc
                    changed = True
                    continue
                except CollaborationExecutionAuthorityUnavailable as exc:
                    # Funding can be topped up and a current-authority service
                    # can recover. Skip this item for this scan without
                    # mutating its durable authorization.
                    last_authority_error = exc
                    continue
                claimed_candidate = copy.deepcopy(record)
                claimed_candidate.update(
                    {
                        "state": ExecutionState.CLAIMED.value,
                        "claim_count": 1,
                        "claim_vault_observation": (
                            snapshot.finalized_vault_observation.to_dict()
                        ),
                        "claim_royalty_observation": (
                            snapshot.finalized_royalty_observation.to_dict()
                        ),
                        "claimed_at": timestamp,
                        "last_reason": "claim_authority_revalidated",
                        "updated_at": timestamp,
                    }
                )
                self._validate_record(claimed_candidate)
                body["records"][intent.execution_id] = claimed_candidate
                changed = True
                break
            if changed:
                body["sequence"] += 1
                self._write_unlocked(body)
            if claimed_candidate is not None:
                return copy.deepcopy(claimed_candidate)
            if last_authority_error is not None:
                raise last_authority_error
            return None

    def prepare_compute_handoff(
        self,
        execution_id: str,
        *,
        prepared_at: int,
    ) -> dict[str, Any]:
        """Persist the exact idempotent Compute handoff before API submission.

        This method performs no Compute API call and no provider call. Repeating
        it after a crash returns the byte-identical handoff request.
        """

        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        timestamp = _timestamp(prepared_at, "Compute handoff preparation time")
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized_id)
            if current is None:
                raise CollaborationExecutionNotFound(
                    "collaboration execution was not found"
                )
            parsed = self._validate_record(current)
            state = ExecutionState(parsed["state"])
            handoff = ComputeHandoff.from_dict(parsed["compute_handoff_plan"])
            if state in {
                ExecutionState.COMPUTE_HANDOFF_PENDING,
                ExecutionState.COMPUTE_HANDOFF_CONFIRMED,
                ExecutionState.BOUNDED_RESULT_READY,
                ExecutionState.FAILED,
                ExecutionState.RECONCILIATION_HOLD,
            }:
                return handoff.to_dict()
            if state != ExecutionState.CLAIMED:
                raise CollaborationExecutionConflict(
                    "Compute handoff cannot be prepared from the current state"
                )
            intent = CollaborationExecutionIntent.from_dict(parsed["intent"])
            if timestamp >= intent.authorization_expiry:
                raise CollaborationExecutionAuthorityInvalidated(
                    "Compute authorization expired before handoff preparation"
                )
            candidate = copy.deepcopy(parsed)
            candidate.update(
                {
                    "state": ExecutionState.COMPUTE_HANDOFF_PENDING.value,
                    "handoff_pending_at": timestamp,
                    "last_reason": "compute_handoff_persisted_before_submission",
                    "updated_at": timestamp,
                }
            )
            self._validate_record(candidate)
            body["records"][normalized_id] = candidate
            body["sequence"] += 1
            self._write_unlocked(body)
            return handoff.to_dict()

    def confirm_compute_handoff(
        self,
        execution_id: str,
        projection: ComputeJournalProjection,
        *,
        confirmed_at: int,
    ) -> dict[str, Any]:
        """Import an exact Compute-journal projection and advance safely."""

        return self.reconcile_compute_projection(
            execution_id,
            projection,
            reconciled_at=confirmed_at,
        )

    def reconcile_compute_projection(
        self,
        execution_id: str,
        projection: ComputeJournalProjection,
        *,
        reconciled_at: int,
    ) -> dict[str, Any]:
        """Advance from a fully bound projection supplied by a trusted reader.

        This core has no Compute-journal integrity key and therefore does not
        claim source authentication. API/worker wiring must keep this method
        behind a local authenticated Compute-journal adapter.
        """

        if not isinstance(projection, ComputeJournalProjection):
            raise CollaborationExecutionError(
                "exact Compute journal projection is required"
            )
        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        timestamp = _timestamp(reconciled_at, "Compute reconciliation time")
        if projection.observed_at != timestamp:
            raise CollaborationExecutionConflict(
                "Compute projection is not from this reconciliation observation"
            )
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized_id)
            if current is None:
                raise CollaborationExecutionNotFound(
                    "collaboration execution was not found"
                )
            parsed = self._validate_record(current)
            state = ExecutionState(parsed["state"])
            if state == ExecutionState.RECONCILIATION_HOLD:
                existing = ComputeJournalProjection.from_dict(
                    parsed["compute_projection"]
                )
                if existing.commitment == projection.commitment:
                    return self._public_record(parsed)
                raise CollaborationExecutionConflict(
                    "ambiguous hold requires explicit manual resolution"
                )
            if state in TERMINAL_STATES:
                existing = parsed["compute_projection"]
                if existing is not None and ComputeJournalProjection.from_dict(
                    existing
                ).commitment == projection.commitment:
                    return self._public_record(parsed)
                raise CollaborationExecutionConflict(
                    "terminal execution cannot import a different Compute projection"
                )
            if state not in {
                ExecutionState.COMPUTE_HANDOFF_PENDING,
                ExecutionState.COMPUTE_HANDOFF_CONFIRMED,
            }:
                raise CollaborationExecutionConflict(
                    "Compute projection is not expected in the current state"
                )
            intent = CollaborationExecutionIntent.from_dict(parsed["intent"])
            handoff = ComputeHandoff.from_dict(parsed["compute_handoff_plan"])
            projection.validate_for(
                intent,
                handoff,
                authorization_commitment=parsed["authorization_commitment"],
            )
            previous = (
                None
                if parsed["compute_projection"] is None
                else ComputeJournalProjection.from_dict(
                    parsed["compute_projection"]
                )
            )
            if previous is not None and not _compute_stage_not_regressed(
                previous.compute_stage,
                projection.compute_stage,
            ):
                raise CollaborationExecutionConflict(
                    "Compute journal projection regressed"
                )
            if previous is not None and (
                projection.observed_at < previous.observed_at
                or (
                    previous.provider_dispatch_may_have_occurred
                    and not projection.provider_dispatch_may_have_occurred
                )
            ):
                raise CollaborationExecutionConflict(
                    "Compute journal projection regressed"
                )
            target = ExecutionState.COMPUTE_HANDOFF_CONFIRMED
            terminal_at: int | None = None
            reason = "compute_handoff_confirmed"
            result = projection.bounded_result
            if projection.compute_stage == "provider_outcome_ambiguous":
                target = ExecutionState.RECONCILIATION_HOLD
                reason = "compute_projection_reports_ambiguous_outcome"
            elif projection.compute_stage == "settled":
                if result is None:
                    raise CollaborationExecutionConflict(
                        "settled Compute projection lacks bounded result"
                    )
                target = (
                    ExecutionState.BOUNDED_RESULT_READY
                    if result.outcome == "succeeded"
                    else ExecutionState.FAILED
                )
                terminal_at = timestamp
                reason = "compute_settled_bounded_result_imported"
            elif projection.compute_stage == "blocked":
                target = ExecutionState.FAILED
                terminal_at = timestamp
                reason = "compute_terminal_block_imported"
            candidate = copy.deepcopy(parsed)
            candidate.update(
                {
                    "state": target.value,
                    "compute_projection": projection.to_dict(),
                    "bounded_result": (
                        result.to_dict() if result is not None else None
                    ),
                    "handoff_confirmed_at": (
                        parsed["handoff_confirmed_at"] or timestamp
                    ),
                    "reconciliation_hold_at": (
                        timestamp
                        if target == ExecutionState.RECONCILIATION_HOLD
                        else parsed["reconciliation_hold_at"]
                    ),
                    "reconciliation_hold_projection_commitment": (
                        projection.commitment
                        if target == ExecutionState.RECONCILIATION_HOLD
                        else parsed[
                            "reconciliation_hold_projection_commitment"
                        ]
                    ),
                    "terminal_at": terminal_at,
                    "last_reason": reason,
                    "updated_at": timestamp,
                }
            )
            self._validate_record(candidate)
            body["records"][normalized_id] = candidate
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public_record(candidate)

    def resolve_reconciliation_hold(
        self,
        execution_id: str,
        projection: ComputeJournalProjection,
        *,
        resolved_at: int,
    ) -> dict[str, Any]:
        """Resolve an ambiguous hold from a later exact Compute projection.

        This path never submits or redispatches work. It accepts only a later
        conclusive ``settled`` or ``blocked`` projection for the same exact
        handoff, intent, authorization, and Compute context.
        """

        if not isinstance(projection, ComputeJournalProjection):
            raise CollaborationExecutionError(
                "exact Compute journal projection is required"
            )
        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        timestamp = _timestamp(resolved_at, "Compute hold resolution time")
        if projection.observed_at != timestamp:
            raise CollaborationExecutionConflict(
                "Compute projection is not from this hold resolution observation"
            )
        if projection.compute_stage not in {"settled", "blocked"}:
            raise CollaborationExecutionConflict(
                "ambiguous hold requires a conclusive Compute projection"
            )
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized_id)
            if current is None:
                raise CollaborationExecutionNotFound(
                    "collaboration execution was not found"
                )
            parsed = self._validate_record(current)
            state = ExecutionState(parsed["state"])
            if state in {
                ExecutionState.BOUNDED_RESULT_READY,
                ExecutionState.FAILED,
            }:
                existing = ComputeJournalProjection.from_dict(
                    parsed["compute_projection"]
                )
                if existing.commitment == projection.commitment:
                    return self._public_record(parsed)
                raise CollaborationExecutionConflict(
                    "resolved execution cannot import a different Compute projection"
                )
            if state != ExecutionState.RECONCILIATION_HOLD:
                raise CollaborationExecutionConflict(
                    "collaboration execution is not awaiting manual reconciliation"
                )
            intent = CollaborationExecutionIntent.from_dict(parsed["intent"])
            handoff = ComputeHandoff.from_dict(parsed["compute_handoff_plan"])
            projection.validate_for(
                intent,
                handoff,
                authorization_commitment=parsed["authorization_commitment"],
            )
            hold_at = int(parsed["reconciliation_hold_at"])
            if (
                projection.observed_at <= hold_at
                or not projection.provider_dispatch_may_have_occurred
                or projection.automatic_provider_redispatch is not False
            ):
                raise CollaborationExecutionConflict(
                    "Compute hold resolution regressed or permits redispatch"
                )
            result = projection.bounded_result
            if projection.compute_stage == "settled":
                if result is None:
                    raise CollaborationExecutionConflict(
                        "settled Compute hold resolution lacks a bounded result"
                    )
                target = (
                    ExecutionState.BOUNDED_RESULT_READY
                    if result.outcome == "succeeded"
                    else ExecutionState.FAILED
                )
            else:
                target = ExecutionState.FAILED
            candidate = copy.deepcopy(parsed)
            candidate.update(
                {
                    "state": target.value,
                    "compute_projection": projection.to_dict(),
                    "bounded_result": (
                        None if result is None else result.to_dict()
                    ),
                    "terminal_at": timestamp,
                    "last_reason": "compute_reconciliation_hold_resolved",
                    "updated_at": timestamp,
                }
            )
            self._validate_record(candidate)
            body["records"][normalized_id] = candidate
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public_record(candidate)

    def recover_incomplete(self, *, recovered_at: int) -> list[dict[str, Any]]:
        """Return exact crash-recovery actions without provider redispatch."""

        _timestamp(recovered_at, "recovery time")
        recovered: list[dict[str, Any]] = []
        with self._exclusive_lock():
            body = self._load_unlocked()
            for current in body["records"].values():
                parsed = self._validate_record(current)
                state = ExecutionState(parsed["state"])
                if state == ExecutionState.CLAIMED:
                    recovered.append(
                        {
                            "execution_id": CollaborationExecutionIntent.from_dict(
                                parsed["intent"]
                            ).execution_id,
                            "state": state.value,
                            "recovery_action": "prepare_compute_handoff",
                            "compute_handoff": copy.deepcopy(
                                parsed["compute_handoff_plan"]
                            ),
                            "provider_call_performed_by_collaboration": False,
                        }
                    )
                elif state == ExecutionState.COMPUTE_HANDOFF_PENDING:
                    recovered.append(
                        {
                            "execution_id": CollaborationExecutionIntent.from_dict(
                                parsed["intent"]
                            ).execution_id,
                            "state": state.value,
                            "recovery_action": "lookup_or_resubmit_exact_idempotent_compute_handoff",
                            "compute_handoff": copy.deepcopy(
                                parsed["compute_handoff_plan"]
                            ),
                            "provider_call_performed_by_collaboration": False,
                        }
                    )
                elif state == ExecutionState.COMPUTE_HANDOFF_CONFIRMED:
                    recovered.append(
                        {
                            "execution_id": CollaborationExecutionIntent.from_dict(
                                parsed["intent"]
                            ).execution_id,
                            "state": state.value,
                            "recovery_action": "poll_exact_compute_journal_projection",
                            "compute_handoff": copy.deepcopy(
                                parsed["compute_handoff_plan"]
                            ),
                            "provider_call_performed_by_collaboration": False,
                        }
                    )
                elif state == ExecutionState.RECONCILIATION_HOLD:
                    recovered.append(
                        {
                            "execution_id": CollaborationExecutionIntent.from_dict(
                                parsed["intent"]
                            ).execution_id,
                            "state": state.value,
                            "recovery_action": (
                                "manual_exact_compute_reconciliation_required"
                            ),
                            "compute_handoff": copy.deepcopy(
                                parsed["compute_handoff_plan"]
                            ),
                            "provider_call_performed_by_collaboration": False,
                        }
                    )
        recovered.sort(key=lambda item: item["execution_id"])
        return recovered

    def public_get(self, execution_id: str) -> dict[str, Any]:
        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        with self._exclusive_lock():
            body = self._load_unlocked()
            record = body["records"].get(normalized_id)
            if record is None:
                raise CollaborationExecutionNotFound("collaboration execution was not found")
            return self._public_record(self._validate_record(record))

    def royalty_settlement_source(self, execution_id: str) -> dict[str, Any]:
        """Return authenticated in-process inputs for one bounded-result payout.

        This is a worker boundary, not a public DTO.  It reauthenticates the
        journal under the process lock and refuses old records that did not
        persist the exact owner allocation.
        """

        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized_id)
            if current is None:
                raise CollaborationExecutionNotFound(
                    "collaboration execution was not found"
                )
            record = self._validate_record(current)
            if record["state"] != ExecutionState.BOUNDED_RESULT_READY.value:
                raise CollaborationExecutionConflict(
                    "collaboration execution has no successful bounded result"
                )
            owner_amounts = record["royalty_owner_amounts"]
            if owner_amounts is None:
                raise CollaborationExecutionJournalError(
                    "exact royalty payout authority is unavailable"
                )
            return {
                "intent": CollaborationExecutionIntent.from_dict(
                    record["intent"]
                ),
                "grants": tuple(
                    OwnerExecutionGrant.from_dict(item)
                    for item in record["execution_grants"]
                ),
                "owner_amounts": {
                    item["owner_address"]: item["amount"]
                    for item in owner_amounts
                },
                "funding_reservation": RoyaltyFundingReservation.derive(
                    CollaborationExecutionIntent.from_dict(record["intent"]),
                    execution_grant_set_commitment=record[
                        "execution_grant_set_commitment"
                    ],
                ),
                "bounded_result": BoundedExecutionResult.from_dict(
                    record["bounded_result"]
                ),
                "historical_royalty_observation": (
                    FinalizedRoyaltyAuthorityObservation.from_dict(
                        record["claim_royalty_observation"]
                    )
                ),
                "authorization_commitment": record[
                    "authorization_commitment"
                ],
                "source_sequence": body["sequence"],
            }

    def _transition(
        self,
        execution_id: str,
        *,
        expected: ExecutionState,
        target: ExecutionState,
        reason: str,
        timestamp: int,
        updates: Mapping[str, Any],
    ) -> dict[str, Any]:
        normalized_id = _pattern(execution_id, _EXECUTION_ID, "execution id")
        normalized_time = _timestamp(timestamp, "transition time")
        normalized_reason = _pattern(reason, _REASON, "transition reason")
        if not isinstance(updates, Mapping) or any(
            field not in self._RECORD_FIELDS for field in updates
        ):
            raise CollaborationExecutionJournalError("execution transition update is invalid")
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized_id)
            if current is None:
                raise CollaborationExecutionNotFound("collaboration execution was not found")
            parsed = self._validate_record(current)
            if parsed["state"] == target.value:
                return self._public_record(parsed)
            if parsed["state"] != expected.value:
                raise CollaborationExecutionConflict(
                    "collaboration execution state changed concurrently"
                )
            candidate = copy.deepcopy(parsed)
            candidate.update(copy.deepcopy(dict(updates)))
            candidate["state"] = target.value
            candidate["last_reason"] = normalized_reason
            candidate["updated_at"] = normalized_time
            self._validate_record(candidate)
            body["records"][normalized_id] = candidate
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public_record(candidate)

    def _public_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        record = self._validate_record(value)
        intent = CollaborationExecutionIntent.from_dict(record["intent"])
        royalty_reservation = copy.deepcopy(
            record["royalty_funding_reservation"]
        )
        state = ExecutionState(record["state"])
        vault_observation = (
            FinalizedComputeVaultObservation.from_dict(
                record["claim_vault_observation"]
            )
            if record["claim_vault_observation"] is not None
            else None
        )
        royalty_observation = (
            FinalizedRoyaltyAuthorityObservation.from_dict(
                record["claim_royalty_observation"]
            )
            if record["claim_royalty_observation"] is not None
            else None
        )
        handoff = (
            ComputeHandoff.from_dict(record["compute_handoff_plan"])
        )
        projection = (
            ComputeJournalProjection.from_dict(record["compute_projection"])
            if record["compute_projection"] is not None
            else None
        )
        result = (
            BoundedExecutionResult.from_dict(record["bounded_result"])
            if record["bounded_result"] is not None
            else None
        )
        return {
            "surface": "collaboration_one_shot_execution",
            "schema_version": 1,
            "execution_id": intent.execution_id,
            "intent_commitment": intent.commitment,
            "authorization_commitment": record["authorization_commitment"],
            "execution_grant_set_commitment": record[
                "execution_grant_set_commitment"
            ],
            "owner_execution_grant_count": len(record["execution_grants"]),
            "release": {
                "git_sha": intent.release_git_sha,
                "verification_sha256": intent.release_verification_sha256,
                "chain_id": intent.chain_id,
                "cvm_id": intent.cvm_id,
                "compose_hash": intent.compose_hash,
            },
            "room_id": intent.room_id,
            "room_commitment": intent.room_commitment,
            "room_generation": intent.room_generation,
            "room_state_commitment": intent.room_state_commitment,
            "query_ref": intent.query_ref,
            "query_proposal_commitment": intent.query_proposal_commitment,
            "prospective_query_grant_set_commitment": (
                intent.prospective_query_grant_set_commitment
            ),
            "joint_consent_snapshot_commitment": (
                intent.joint_consent_snapshot_commitment
            ),
            "allocation_commitment": intent.allocation_commitment,
            "compute_project_id": intent.compute_project_id,
            "compute_job_id": intent.compute_job_id,
            "compute_workload_id": intent.compute_workload_id,
            "compute_workload_commitment": intent.compute_workload_commitment,
            "compute_manifest_commitment": intent.compute_manifest_commitment,
            "compute_dispatch_intent_commitment": (
                intent.compute_dispatch_intent_commitment
            ),
            "compute_authorization": {
                "kind": intent.compute_authorization_kind,
                "context_commitment": (
                    intent.compute_authorization_context_commitment
                ),
                "standalone_path_used": False,
            },
            "compute_rate_policy_commitment": (
                intent.compute_rate_policy_commitment
            ),
            "compute_workload_schema": intent.compute_workload_schema,
            "compute_workload_source_kind": (
                intent.compute_workload_source_kind
            ),
            "compute_workload_execution_binding_commitment": (
                intent.compute_workload_execution_binding_commitment
            ),
            "compute_workload_recipient_release_commitment": (
                intent.compute_workload_recipient_release_commitment
            ),
            "compute_authority": {
                "vault_address": intent.compute_vault_address,
                "vault_runtime_code_hash": intent.compute_vault_runtime_code_hash,
                "finality_model": intent.compute_finality_model,
                "user_address": intent.compute_user_address,
            },
            "operation": intent.operation,
            "model": intent.model,
            "recipe": intent.recipe,
            "result_policy": intent.result_policy,
            "resource_limits": {
                "max_prefill_tokens": intent.max_prefill_tokens,
                "max_sample_tokens": intent.max_sample_tokens,
                "max_train_tokens": intent.max_train_tokens,
            },
            "sponsor_address": intent.sponsor_address,
            "asset": intent.asset,
            "max_total_asset_debit": intent.max_total_asset_debit,
            "max_total_asset_debit_scope": (
                "compute_usage_plus_reserved_royalty"
            ),
            "max_compute_asset_debit": intent.max_compute_asset_debit,
            "max_compute_asset_debit_scope": "compute_usage_only",
            "authorization_nonce": intent.authorization_nonce,
            "authorization_expiry": intent.authorization_expiry,
            "royalty": {
                "asset": intent.royalty_asset,
                "total": intent.royalty_total,
                "owner_amounts_hash": intent.royalty_owner_amounts_hash,
                "owner_amounts": (
                    None
                    if record["royalty_owner_amounts"] is None
                    else [
                        {
                            "owner_address": item["owner_address"],
                            "amount": str(item["amount"]),
                        }
                        for item in record["royalty_owner_amounts"]
                    ]
                ),
                "distributor_address": intent.royalty_distributor_address,
                "release_policy_commitment": (
                    intent.royalty_release_policy_commitment
                ),
                "release_binding_commitment": (
                    intent.royalty_release_binding_commitment
                ),
                "settlement_id": intent.royalty_settlement_id,
                "settlement_nonce": str(intent.royalty_settlement_nonce),
                "funding_reservation": royalty_reservation,
                "reservation_safety_seconds": (
                    intent.royalty_reservation_safety_seconds
                ),
                "funding_reservation_finalization_proven": (
                    royalty_observation is not None
                ),
                "hash_semantics": (
                    "RoyaltyDistributor owner and amount array EIP-712 commitment"
                ),
                "exact_payout_validation_proven": (
                    record["royalty_owner_amounts"] is not None
                ),
                "fresh_construction_requires_validated_owner_amounts": True,
            },
            "state": state.value,
            "claim_count": record["claim_count"],
            "bounded_result": result.to_dict() if result is not None else None,
            "claim_vault_observation": (
                None
                if vault_observation is None
                else {
                    "commitment": vault_observation.commitment,
                    "chain_id": vault_observation.chain_id,
                    "vault_address": vault_observation.vault_address,
                    "vault_runtime_code_hash": (
                        vault_observation.vault_runtime_code_hash
                    ),
                    "block_number": vault_observation.block_number,
                    "block_hash": vault_observation.block_hash,
                    "block_timestamp": vault_observation.block_timestamp,
                    "source_record_commitment": (
                        vault_observation.source_record_commitment
                    ),
                    "source_authentication_receipt": (
                        vault_observation.source_authentication_receipt
                    ),
                    "source_authentication_receipt_bound": True,
                    "finality_model": vault_observation.finality_model,
                    "reported_finalized": vault_observation.reported_finalized,
                    "job_state": vault_observation.job_state,
                    "observed_at": vault_observation.observed_at,
                }
            ),
            "claim_royalty_observation": (
                None
                if royalty_observation is None
                else {
                    "commitment": royalty_observation.commitment,
                    "chain_id": royalty_observation.chain_id,
                    "block_number": royalty_observation.block_number,
                    "block_hash": royalty_observation.block_hash,
                    "block_timestamp": royalty_observation.block_timestamp,
                    "distributor_address": royalty_observation.distributor_address,
                    "distributor_runtime_code_hash": (
                        royalty_observation.distributor_runtime_code_hash
                    ),
                    "owner_address": royalty_observation.owner_address,
                    "pending_owner_address": (
                        royalty_observation.pending_owner_address
                    ),
                    "release_binding_commitment": (
                        royalty_observation.release_binding_commitment
                    ),
                    "release_policy_commitment": (
                        royalty_observation.release_policy_commitment
                    ),
                    "authority_nonce": royalty_observation.authority_nonce,
                    "settlement_verifier_address": (
                        royalty_observation.settlement_verifier_address
                    ),
                    "qvl_verifier_address": royalty_observation.qvl_verifier_address,
                    "execution_policy_anchor_address": (
                        royalty_observation.execution_policy_anchor_address
                    ),
                    "anchor_writer_address": royalty_observation.anchor_writer_address,
                    "anchor_writer_release_commitment": (
                        royalty_observation.anchor_writer_release_commitment
                    ),
                    "distributor_paused": royalty_observation.distributor_paused,
                    "pending_authority_empty": (
                        royalty_observation.pending_authority_empty
                    ),
                    "anchor_paused": royalty_observation.anchor_paused,
                    "anchor_writer_rotations_frozen": (
                        royalty_observation.anchor_writer_rotations_frozen
                    ),
                    "reservation_id": royalty_observation.reservation_id,
                    "reservation_active": royalty_observation.reservation_active,
                    "reservation_consumed": (
                        royalty_observation.reservation_consumed
                    ),
                    "reservation_sponsor_address": (
                        royalty_observation.reservation_sponsor_address
                    ),
                    "reservation_asset": royalty_observation.reservation_asset,
                    "reservation_total": royalty_observation.reservation_total,
                    "reservation_owner_amounts_hash": (
                        royalty_observation.reservation_owner_amounts_hash
                    ),
                    "reservation_release_policy_commitment": (
                        royalty_observation.reservation_release_policy_commitment
                    ),
                    "reservation_execution_intent_commitment": (
                        royalty_observation.reservation_execution_intent_commitment
                    ),
                    "reservation_refund_after": (
                        royalty_observation.reservation_refund_after
                    ),
                    "reservation_deposited_amount": (
                        royalty_observation.reservation_deposited_amount
                    ),
                    "source_record_commitment": (
                        royalty_observation.source_record_commitment
                    ),
                    "source_authentication_receipt": (
                        royalty_observation.source_authentication_receipt
                    ),
                    "source_authentication_receipt_bound": True,
                    "observed_at": royalty_observation.observed_at,
                }
            ),
            "compute_handoff": {
                "handoff_id": handoff.handoff_id,
                "handoff_commitment": handoff.commitment,
                "planned_at": handoff.planned_at,
                "provider_call_performed_by_collaboration": False,
            },
            "compute_handoff_status": (
                "planned_not_submitted"
                if record["handoff_pending_at"] is None
                else "pending"
                if projection is None
                else "confirmed"
            ),
            "compute_journal_projection": (
                None
                if projection is None
                else {
                    "projection_commitment": projection.commitment,
                    "source_journal_schema": projection.compute_journal_schema,
                    "source_sequence": projection.source_sequence,
                    "source_record_commitment": (
                        projection.source_record_commitment
                    ),
                    "source_journal_mac_commitment": (
                        projection.source_journal_mac_commitment
                    ),
                    "source_authentication_receipt": (
                        projection.source_authentication_receipt
                    ),
                    "source_authentication_receipt_bound": True,
                    "source_authentication_proven": False,
                    "source_authentication_boundary": (
                        "trusted_local_compute_journal_reader_required"
                    ),
                    "compute_stage": projection.compute_stage,
                    "provider_dispatch_may_have_occurred": (
                        projection.provider_dispatch_may_have_occurred
                    ),
                    "automatic_provider_redispatch": (
                        projection.automatic_provider_redispatch
                    ),
                    "bounded_result_imported": (
                        projection.bounded_result is not None
                    ),
                    "observed_at": projection.observed_at,
                }
            ),
            # This flag is deliberately unknown until an exact Compute-journal
            # projection is imported. Collaboration never infers it from its
            # own claimed or handoff state.
            "provider_dispatch_may_have_occurred": (
                None
                if projection is None
                else projection.provider_dispatch_may_have_occurred
            ),
            "provider_dispatch_flag_source": (
                None
                if projection is None
                else "typed_compute_projection_source_not_authenticated_by_core"
            ),
            "collaboration_provider_call_performed": False,
            "journal_automatic_redispatch": False,
            "idempotent_provider_replay_claimed": False,
            "reconciliation_hold": state == ExecutionState.RECONCILIATION_HOLD,
            "reconciliation_was_required": (
                record["reconciliation_hold_at"] is not None
            ),
            "reconciliation_hold_at": record["reconciliation_hold_at"],
            "reconciliation_hold_projection_commitment": record[
                "reconciliation_hold_projection_commitment"
            ],
            "authority_invalidated_before_claim": (
                state == ExecutionState.AUTHORITY_INVALIDATED
            ),
            "source_capable_core_only": True,
            "api_worker_wiring_claimed": False,
            "live_deployment_claimed": False,
            "tdx_attestation_claimed": False,
            "qvl_verification_claimed": False,
            "settlement_performed": False,
            "compute_settlement_projected": (
                projection is not None and projection.compute_stage == "settled"
            ),
            "royalty_distribution_performed": False,
            "journal_raw_input_persisted": False,
            "journal_raw_result_persisted": False,
            "public_projection_raw_input_included": False,
            "public_projection_raw_result_included": False,
            "public_projection_provider_identifier_included": False,
            "whole_system_non_egress_claimed": False,
            "anti_rollback_provided": False,
            "authorized_at": record["authorized_at"],
            "queued_at": record["queued_at"],
            "claimed_at": record["claimed_at"],
            "handoff_pending_at": record["handoff_pending_at"],
            "handoff_confirmed_at": record["handoff_confirmed_at"],
            "terminal_at": record["terminal_at"],
        }

    def _validate_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(value, Mapping) or set(value) != self._RECORD_FIELDS:
            raise CollaborationExecutionJournalError("execution journal record schema is invalid")
        try:
            intent = CollaborationExecutionIntent.from_dict(value["intent"])
            grants_raw = value["execution_grants"]
            if not isinstance(grants_raw, list) or len(grants_raw) > MAX_OWNERS:
                raise CollaborationExecutionError
            grants = tuple(OwnerExecutionGrant.from_dict(item) for item in grants_raw)
            authorized_at = _timestamp(value["authorized_at"], "authorization time")
            grant_set = execution_grant_set_commitment(
                intent.to_basis(), grants, now=authorized_at
            )
            authorization = execution_authorization_commitment(
                intent, grants, now=authorized_at
            )
            if value["execution_grant_set_commitment"] != grant_set:
                raise CollaborationExecutionError
            exact_owner_amounts = _normalize_persisted_royalty_owner_amounts(
                intent,
                value["royalty_owner_amounts"],
            )
            if value["royalty_owner_amounts"] != exact_owner_amounts:
                raise CollaborationExecutionError
            royalty_reservation = RoyaltyFundingReservation.derive(
                intent,
                execution_grant_set_commitment=grant_set,
            )
            if value["royalty_funding_reservation"] != royalty_reservation.to_dict():
                raise CollaborationExecutionError
            if value["authorization_commitment"] != authorization:
                raise CollaborationExecutionError
            if not isinstance(value["idempotency_key_hash"], str) or not _HEX64.fullmatch(
                value["idempotency_key_hash"]
            ):
                raise CollaborationExecutionError
            state = ExecutionState(value["state"])
            claim_count = _integer(
                value["claim_count"], "claim count", minimum=0, maximum=1
            )
            updated_at = _timestamp(value["updated_at"], "update time")
            if updated_at < authorized_at:
                raise CollaborationExecutionError
            _pattern(value["last_reason"], _REASON, "execution reason")
            timestamps: dict[str, int | None] = {}
            for field in (
                "queued_at",
                "claimed_at",
                "handoff_pending_at",
                "handoff_confirmed_at",
                "reconciliation_hold_at",
                "terminal_at",
            ):
                item = value[field]
                timestamps[field] = (
                    None if item is None else _timestamp(item, field.replace("_", " "))
                )
            observation = (
                None
                if value["claim_vault_observation"] is None
                else FinalizedComputeVaultObservation.from_dict(
                    value["claim_vault_observation"]
                )
            )
            royalty_observation = (
                None
                if value["claim_royalty_observation"] is None
                else FinalizedRoyaltyAuthorityObservation.from_dict(
                    value["claim_royalty_observation"]
                )
            )
            handoff = ComputeHandoff.from_dict(value["compute_handoff_plan"])
            hold_projection_commitment = value[
                "reconciliation_hold_projection_commitment"
            ]
            if hold_projection_commitment is not None:
                _pattern(
                    hold_projection_commitment,
                    _SHA256,
                    "reconciliation hold projection commitment",
                )
            projection = (
                None
                if value["compute_projection"] is None
                else ComputeJournalProjection.from_dict(
                    value["compute_projection"]
                )
            )
            result = (
                None
                if value["bounded_result"] is None
                else BoundedExecutionResult.from_dict(value["bounded_result"])
            )
            if result is not None:
                result.validate_for(
                    intent,
                    authorization_commitment=value[
                        "authorization_commitment"
                    ],
                )
            claimed = timestamps["claimed_at"]
            pending = timestamps["handoff_pending_at"]
            confirmed = timestamps["handoff_confirmed_at"]
            if observation is not None:
                if claimed is None:
                    raise CollaborationExecutionError
                observation.validate_for(intent, claimed_at=claimed)
            if royalty_observation is not None:
                if claimed is None:
                    raise CollaborationExecutionError
                royalty_observation.validate_for(
                    intent,
                    royalty_reservation,
                    claimed_at=claimed,
                )
            handoff.validate_for(
                intent,
                authorization_commitment=value["authorization_commitment"],
            )
            if (
                handoff.planned_at != authorized_at
                or handoff.planned_at >= intent.authorization_expiry
            ):
                raise CollaborationExecutionError
            if projection is not None:
                if confirmed is None:
                    raise CollaborationExecutionError
                projection.validate_for(
                    intent,
                    handoff,
                    authorization_commitment=value["authorization_commitment"],
                )
                if (
                    projection.observed_at < confirmed
                    or projection.observed_at != updated_at
                ):
                    raise CollaborationExecutionError
            projected_result = (
                None if projection is None else projection.bounded_result
            )
            if projected_result is None:
                if result is not None:
                    raise CollaborationExecutionError
            elif result is None or result.to_dict() != projected_result.to_dict():
                raise CollaborationExecutionError
            hold = timestamps["reconciliation_hold_at"]
            if (hold is None) != (hold_projection_commitment is None):
                raise CollaborationExecutionError
            if hold is not None and (confirmed is None or hold < confirmed):
                raise CollaborationExecutionError
        except CollaborationExecutionJournalError:
            raise
        except Exception:
            raise CollaborationExecutionJournalError(
                "execution journal record is invalid"
            ) from None

        queued = timestamps["queued_at"]
        claimed = timestamps["claimed_at"]
        pending = timestamps["handoff_pending_at"]
        confirmed = timestamps["handoff_confirmed_at"]
        hold = timestamps["reconciliation_hold_at"]
        terminal = timestamps["terminal_at"]
        if state == ExecutionState.AUTHORIZED:
            valid = (
                claim_count == 0
                and queued is claimed is pending is confirmed is hold is terminal is None
                and observation is royalty_observation is projection is result is None
                and handoff is not None
            )
        elif state == ExecutionState.QUEUED:
            valid = (
                claim_count == 0
                and queued is not None
                and claimed is pending is confirmed is hold is terminal is None
                and observation is royalty_observation is projection is result is None
                and handoff is not None
            )
        elif state == ExecutionState.CLAIMED:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is confirmed is hold is terminal is None
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is result is None
            )
        elif state == ExecutionState.COMPUTE_HANDOFF_PENDING:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is not None
                and confirmed is hold is terminal is None
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is result is None
            )
        elif state == ExecutionState.COMPUTE_HANDOFF_CONFIRMED:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is not None
                and confirmed is not None
                and hold is terminal is None
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is not None
                and projection.compute_stage
                not in {"provider_outcome_ambiguous", "settled", "blocked"}
                and result is None
            )
        elif state == ExecutionState.AUTHORITY_INVALIDATED:
            valid = (
                claim_count == 0
                and queued is not None
                and claimed is pending is confirmed is hold is None
                and terminal is not None
                and observation is royalty_observation is projection is result is None
                and handoff is not None
            )
        elif state == ExecutionState.RECONCILIATION_HOLD:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is not None
                and confirmed is not None
                and hold is not None
                and terminal is None
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is not None
                and projection.compute_stage == "provider_outcome_ambiguous"
                and hold_projection_commitment == projection.commitment
                and result is None
            )
        elif state == ExecutionState.BOUNDED_RESULT_READY:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is not None
                and confirmed is not None
                and terminal is not None
                and (hold is None or hold < terminal)
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is not None
                and projection.compute_stage == "settled"
                and result is not None
                and result.outcome == "succeeded"
            )
        else:
            valid = (
                claim_count == 1
                and queued is not None
                and claimed is not None
                and pending is not None
                and confirmed is not None
                and terminal is not None
                and (hold is None or hold < terminal)
                and observation is not None
                and royalty_observation is not None
                and handoff is not None
                and projection is not None
                and (
                    (
                        projection.compute_stage == "settled"
                        and result is not None
                        and result.outcome == "failed"
                    )
                    or (
                        projection.compute_stage == "blocked"
                        and (result is None or result.outcome == "failed")
                    )
                )
            )
        ordered = [
            authorized_at,
            *[
                item
                for item in (queued, claimed, pending, confirmed, hold, terminal)
                if item is not None
            ],
        ]
        if not valid or ordered != sorted(ordered) or updated_at < ordered[-1]:
            raise CollaborationExecutionJournalError(
                "execution journal state transition history is invalid"
            )
        return copy.deepcopy(dict(value))

    def _empty_body(self) -> dict[str, Any]:
        return {
            "schema": STORE_SCHEMA,
            "schema_version": 2,
            "sequence": 0,
            "records": {},
            "raw_input_persisted": False,
            "raw_result_persisted": False,
            "provider_identifiers_persisted": False,
            "anti_rollback_provided": False,
        }

    def _validate_body(self, body: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(body, Mapping) or set(body) != self._BODY_FIELDS:
            raise CollaborationExecutionJournalError("execution journal body schema is invalid")
        if (
            body.get("schema") != STORE_SCHEMA
            or body.get("schema_version") != 2
            or type(body.get("sequence")) is not int
            or body["sequence"] < 0
            or not isinstance(body.get("records"), dict)
            or len(body["records"]) > MAX_RECORDS
            or body.get("raw_input_persisted") is not False
            or body.get("raw_result_persisted") is not False
            or body.get("provider_identifiers_persisted") is not False
            or body.get("anti_rollback_provided") is not False
        ):
            raise CollaborationExecutionJournalError("execution journal body is invalid")
        seen_bindings: dict[tuple[str, str], str] = {}
        for execution_id, record in body["records"].items():
            parsed = self._validate_record(record)
            intent = CollaborationExecutionIntent.from_dict(parsed["intent"])
            if execution_id != intent.execution_id:
                raise CollaborationExecutionJournalError(
                    "execution journal record key does not match its intent"
                )
            for binding in self._one_shot_authority_bindings(parsed):
                previous = seen_bindings.get(binding)
                if previous is not None and previous != execution_id:
                    raise CollaborationExecutionJournalError(
                        "execution journal reuses one-shot authority across records"
                    )
                seen_bindings[binding] = execution_id
        return copy.deepcopy(dict(body))

    def _reject_replayed_one_shot_authority(
        self,
        candidate: Mapping[str, Any],
        existing_records: Mapping[str, Mapping[str, Any]],
    ) -> None:
        """Reject reuse of any credential that can authorize only one run.

        ``execution_id`` commits the complete intent, so it changes whenever a
        release, room, query, or policy field changes.  It is therefore not a
        sufficient replay key on its own.  These journal-wide bindings prevent
        a caller from wrapping the same idempotency key, funding nonce,
        consent snapshot, Compute job/workload/dispatch, or owner signature in
        a different intent and dispatching it again.
        """

        candidate_bindings = set(self._one_shot_authority_bindings(candidate))
        for existing in existing_records.values():
            overlap = candidate_bindings.intersection(
                self._one_shot_authority_bindings(
                    self._validate_record(existing)
                )
            )
            if overlap:
                category = sorted(item[0] for item in overlap)[0]
                raise CollaborationExecutionConflict(
                    f"one-shot {category} already authorizes another execution"
                )

    def _one_shot_authority_bindings(
        self, record: Mapping[str, Any]
    ) -> tuple[tuple[str, str], ...]:
        intent = CollaborationExecutionIntent.from_dict(record["intent"])
        grants = tuple(
            OwnerExecutionGrant.from_dict(item)
            for item in record["execution_grants"]
        )
        funding_nonce = _domain_hex(
            b"dnai-wikigen/collaboration-funding-replay-key/v1\x00",
            _canonical_json(
                {
                    "chain_id": intent.chain_id,
                    "compute_vault_address": intent.compute_vault_address,
                    "sponsor_address": intent.sponsor_address,
                    "compute_user_address": intent.compute_user_address,
                    "asset": intent.asset,
                    "authorization_nonce": intent.authorization_nonce,
                }
            ),
        )
        bindings: list[tuple[str, str]] = [
            ("idempotency_key", str(record["idempotency_key_hash"])),
            ("funding_authorization", funding_nonce),
            (
                "joint_consent_snapshot",
                intent.joint_consent_snapshot_commitment,
            ),
            ("compute_job", intent.compute_job_id),
            ("compute_workload_id", intent.compute_workload_id),
            (
                "compute_workload_commitment",
                intent.compute_workload_commitment,
            ),
            (
                "compute_dispatch_intent",
                intent.compute_dispatch_intent_commitment,
            ),
            ("royalty_settlement", intent.royalty_settlement_id),
            ("royalty_settlement_nonce", str(intent.royalty_settlement_nonce)),
            (
                "royalty_reservation",
                str(record["royalty_funding_reservation"]["reservation_id"]),
            ),
        ]
        bindings.extend(("execution_grant_id", grant.grant_id) for grant in grants)
        bindings.extend(
            (
                "execution_authorization",
                grant.execution_authorization_hash,
            )
            for grant in grants
        )
        return tuple(bindings)

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            with self._opened_parent() as directory_fd:
                fd = os.open(self.path.name, flags, dir_fd=directory_fd)
                try:
                    details = os.fstat(fd)
                    if (
                        not stat.S_ISREG(details.st_mode)
                        or stat.S_IMODE(details.st_mode) != 0o600
                        or details.st_nlink != 1
                        or details.st_uid != os.geteuid()
                        or details.st_size < 2
                        or details.st_size > MAX_STORE_BYTES
                    ):
                        raise CollaborationExecutionJournalError(
                            "execution journal file metadata is invalid"
                        )
                    raw = _read_all(fd, MAX_STORE_BYTES)
                    current = os.stat(
                        self.path.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        current.st_dev != details.st_dev
                        or current.st_ino != details.st_ino
                    ):
                        raise CollaborationExecutionJournalError(
                            "execution journal changed while opening"
                        )
                finally:
                    os.close(fd)
            root = _strict_json_object(raw)
            if set(root) != {"body", "mac"} or not isinstance(root["body"], dict):
                raise CollaborationExecutionJournalError(
                    "execution journal envelope is invalid"
                )
            if raw != _canonical_json(root):
                raise CollaborationExecutionJournalError(
                    "execution journal envelope is not canonical"
                )
            expected = hmac.new(
                self._integrity_key,
                _STORE_MAC_DOMAIN + _canonical_json(root["body"]),
                hashlib.sha256,
            ).hexdigest()
            if not isinstance(root["mac"], str) or not hmac.compare_digest(
                root["mac"], expected
            ):
                raise CollaborationExecutionJournalError(
                    "execution journal authentication failed"
                )
            return self._validate_body(root["body"])
        except CollaborationExecutionJournalError:
            raise
        except Exception:
            raise CollaborationExecutionJournalError(
                "execution journal is unreadable"
            ) from None

    def _write_unlocked(self, body: Mapping[str, Any]) -> None:
        validated = self._validate_body(body)
        mac = hmac.new(
            self._integrity_key,
            _STORE_MAC_DOMAIN + _canonical_json(validated),
            hashlib.sha256,
        ).hexdigest()
        encoded = _canonical_json({"body": validated, "mac": mac})
        if len(encoded) > MAX_STORE_BYTES:
            raise CollaborationExecutionJournalError(
                "execution journal capacity reached"
            )
        temp_name: str | None = None
        fd: int | None = None
        with self._opened_parent() as directory_fd:
            try:
                for _ in range(32):
                    candidate = f".{self.path.name}.{secrets.token_hex(16)}.tmp"
                    try:
                        fd = os.open(
                            candidate,
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            0o600,
                            dir_fd=directory_fd,
                        )
                        temp_name = candidate
                        break
                    except FileExistsError:
                        continue
                if fd is None or temp_name is None:
                    raise CollaborationExecutionJournalError(
                        "execution journal temporary file allocation failed"
                    )
                os.fchmod(fd, 0o600)
                _write_all(fd, encoded)
                os.fsync(fd)
                os.close(fd)
                fd = None
                os.replace(
                    temp_name,
                    self.path.name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
                temp_name = None
                os.fsync(directory_fd)
            finally:
                if fd is not None:
                    os.close(fd)
                if temp_name is not None:
                    try:
                        os.unlink(temp_name, dir_fd=directory_fd)
                    except FileNotFoundError:
                        pass

    @contextmanager
    def _opened_parent(self) -> Iterator[int]:
        """Open the exact private parent without following any path symlink."""

        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = -1
        try:
            descriptor = os.open(os.path.sep, flags)
            for component in self.path.parent.parts[1:]:
                next_descriptor = os.open(
                    component,
                    flags,
                    dir_fd=descriptor,
                )
                details = os.fstat(next_descriptor)
                if not stat.S_ISDIR(details.st_mode):
                    os.close(next_descriptor)
                    raise CollaborationExecutionJournalError(
                        "execution journal parent path is unsafe"
                    )
                os.close(descriptor)
                descriptor = next_descriptor
            parent = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o022
            ):
                raise CollaborationExecutionJournalError(
                    "execution journal parent directory is unsafe"
                )
            yield descriptor
        except CollaborationExecutionJournalError:
            raise
        except OSError:
            raise CollaborationExecutionJournalError(
                "execution journal parent path is unsafe"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _ensure_lock_file(self) -> None:
        common_flags = (
            os.O_RDWR
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        created = False
        with self._opened_parent() as directory_fd:
            try:
                fd = os.open(
                    self._lock_name,
                    common_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=directory_fd,
                )
                created = True
            except FileExistsError:
                try:
                    fd = os.open(
                        self._lock_name,
                        common_flags,
                        dir_fd=directory_fd,
                    )
                except OSError as exc:
                    raise CollaborationExecutionJournalError(
                        "execution journal lock file is unsafe"
                    ) from exc
            except OSError as exc:
                raise CollaborationExecutionJournalError(
                    "execution journal lock file is unsafe"
                ) from exc
            try:
                details = os.fstat(fd)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_uid != os.geteuid()
                    or (
                        not created
                        and stat.S_IMODE(details.st_mode) != 0o600
                    )
                ):
                    raise CollaborationExecutionJournalError(
                        "execution journal lock file is unsafe"
                    )
                if created:
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                    os.fsync(directory_fd)
            finally:
                os.close(fd)

    @contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        with self._thread_lock:
            flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            with self._opened_parent() as directory_fd:
                fd = os.open(self._lock_name, flags, dir_fd=directory_fd)
                try:
                    details = os.fstat(fd)
                    if (
                        not stat.S_ISREG(details.st_mode)
                        or stat.S_IMODE(details.st_mode) != 0o600
                        or details.st_nlink != 1
                        or details.st_uid != os.geteuid()
                    ):
                        raise CollaborationExecutionJournalError(
                            "execution journal lock file metadata is invalid"
                        )
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    current = os.stat(
                        self._lock_name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if (
                        current.st_dev != details.st_dev
                        or current.st_ino != details.st_ino
                    ):
                        raise CollaborationExecutionJournalError(
                            "execution journal lock file changed"
                        )
                    yield
                finally:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    finally:
                        os.close(fd)


_COMPUTE_STAGE_RANK = {
    "workload_claim_pending": 0,
    "intent_created": 1,
    "start_prepared": 2,
    "start_broadcast": 3,
    "start_confirmed": 4,
    "provider_dispatching": 5,
    "provider_attempt_checkpointed": 6,
    "usage_finalized": 7,
    "workload_released": 8,
    "metering_pending": 9,
    "metering_decided": 10,
    "settlement_prepared": 11,
    "settlement_broadcast": 12,
    "settled": 13,
}
_COMPUTE_TERMINAL_STAGES = frozenset(
    {"provider_outcome_ambiguous", "settled", "blocked"}
)


def _compute_stage_not_regressed(previous: str, current: str) -> bool:
    """Allow sparse forward observations but never reopen a terminal stage."""

    if previous in _COMPUTE_TERMINAL_STAGES:
        return current == previous
    if current in {"provider_outcome_ambiguous", "blocked"}:
        return True
    try:
        return _COMPUTE_STAGE_RANK[current] >= _COMPUTE_STAGE_RANK[previous]
    except KeyError:
        return False


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise CollaborationExecutionError("canonical execution JSON is invalid") from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
    except Exception:
        raise CollaborationExecutionJournalError(
            "execution journal JSON is invalid"
        ) from None
    if not isinstance(value, dict):
        raise CollaborationExecutionJournalError(
            "execution journal root must be an object"
        )
    return value


def _domain_hex(domain: bytes, payload: bytes) -> str:
    return hashlib.sha256(domain + payload).hexdigest()


def _domain_commitment(domain: bytes, payload: Any) -> str:
    return "sha256:" + _domain_hex(domain, _canonical_json(payload))


def _pattern(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise CollaborationExecutionError(f"{label} is invalid")
    return value


def _address(value: Any, label: str, *, allow_zero: bool) -> str:
    normalized = _pattern(value, _ADDRESS, label)
    if not allow_zero and int(normalized[2:], 16) == 0:
        raise CollaborationExecutionError(f"{label} cannot be the zero address")
    return normalized


def _choice(value: Any, choices: Sequence[str] | set[str] | frozenset[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise CollaborationExecutionError(f"{label} is invalid")
    return value


def _string(value: Any, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("ascii", errors="ignore")) != len(value)
        or len(value) > maximum
        or re.fullmatch(r"^[a-z0-9_]+$", value) is None
    ):
        raise CollaborationExecutionError(f"{label} is invalid")
    return value


def _integer(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise CollaborationExecutionError(f"{label} is invalid")
    return value


def _decimal_uint(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    """Parse one canonical JSON decimal integer without float coercion.

    The strict grammar rejects signs, whitespace, exponents, decimal points,
    leading zeroes, booleans, and numeric aliases.  The exact string round
    trip is part of the signed/persisted schema.
    """

    if not isinstance(value, str) or not _CANONICAL_DECIMAL_UINT.fullmatch(value):
        raise CollaborationExecutionError(f"{label} is invalid")
    parsed = int(value, 10)
    if parsed < minimum or parsed > maximum or str(parsed) != value:
        raise CollaborationExecutionError(f"{label} is invalid")
    return parsed


def _timestamp(value: Any, label: str) -> int:
    return _integer(value, label, minimum=0, maximum=MAX_TIMESTAMP)


def _read_all(fd: int, maximum: int) -> bytes:
    output = bytearray()
    while True:
        chunk = os.read(fd, min(65_536, maximum + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
        if len(output) > maximum:
            raise CollaborationExecutionJournalError(
                "execution journal exceeds its byte cap"
            )
    return bytes(output)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise CollaborationExecutionJournalError(
                "execution journal write did not make progress"
            )
        view = view[written:]
