"""Exact-asset Compute dispatch journal and execution-CVM worker.

This module is deliberately separate from :mod:`compute_store`.  The latter is
an off-chain modeled service-credit ledger; this runtime consumes only
``ComputeCreditVault`` authorizations and must never reserve or settle those
legacy credits a second time.

The production construction path requires a real dstack identity.  Chain,
provider, and metering dependencies are protocols so deterministic tests can
inject explicitly named test-only fakes without creating a local-key or
self-asserted production mode.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import tempfile
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, ContextManager, Mapping, Protocol, Sequence

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_keys import keys

from tinker_delegate.chain_submitter import derive_ethereum_private_key
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled
from tinker_delegate.wallet_auth import WalletAuthError, normalize_wallet_address


BASE_SEPOLIA_CHAIN_ID = 84_532
INTENT_SCHEMA = "dnai.compute.dispatch-intent.v2"
STORE_SCHEMA = "dnai.compute.execution-journal.v1"
USAGE_ENVELOPE_SCHEMA = "dnai.compute-usage-envelope.v2"
METERING_REQUEST_SCHEMA = "dnai.compute-metering-request.v2"
METERING_DECISION_SCHEMA = "dnai.compute-metering-decision.v2"
PUBLIC_STATUS_SCHEMA = "dnai.compute.execution-status.v1"

PROJECT_ID_DOMAIN = "dnai.wikigen.compute.project.v1:"
JOB_ID_DOMAIN = "dnai.wikigen.compute.job.v1:"
INTENT_COMMITMENT_DOMAIN = b"dnai-wikigen/compute-dispatch-intent/v1\0"
RECIPE_POLICY_DOMAIN = b"dnai-wikigen/compute-compiled-recipe/v1\0"
EXECUTION_POLICY_CONTEXT_DOMAIN = (
    b"dnai-wikigen/compute-execution-policy-context/v1\0"
)
START_COMMITMENT_DOMAIN = b"dnai-wikigen/compute-start/v1\0"
DISPATCH_ID_DOMAIN = b"dnai-wikigen/compute-provider-dispatch/v1\0"
USAGE_COMMITMENT_DOMAIN = b"dnai-wikigen/compute-usage/v1\0"
STORE_MAC_DOMAIN = b"dnai-wikigen/compute-execution-journal/v1\0"

MAX_STORE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 10_000
MAX_TIMESTAMP = 4_102_444_800
MAX_COUNTER = 100_000_000
MAX_UINT256 = 2**256 - 1
MAX_METERING_RECEIPT_LIFETIME = 10 * 60
ZERO_ADDRESS = "0x" + "00" * 20

_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_TX_HASH = re.compile(r"^0x[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^0x[0-9a-f]{130}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_WORKLOAD_ID = re.compile(r"^wrk_[0-9a-f]{32}$")

INFERENCE_WORKLOAD_SCHEMA = "dnai.compute.workload.inference.v1"
SFT_JSONL_WORKLOAD_SCHEMA = "dnai.compute.workload.sft-jsonl.v1"


class ComputeRuntimeError(RuntimeError):
    """Base fail-closed execution error."""


class ComputeRuntimeRetryable(ComputeRuntimeError):
    """A bounded dependency is unavailable; the durable stage is unchanged."""


class ComputeRuntimePolicyError(ComputeRuntimeError):
    """The exact intent/release/on-chain policy does not match."""


class ComputeRuntimeStateError(ComputeRuntimeError):
    """The authenticated execution journal is malformed or inconsistent."""


class ComputeExecutionPolicyUnavailable(ComputeRuntimeError):
    """The rollback-resistant execution-policy gate cannot be verified."""


class ComputeExecutionPolicyNotPassed(ComputeRuntimeError):
    """The exact canonical Compute job does not currently have a valid PASS."""


class ComputeIntentConflict(ComputeRuntimeError):
    """A canonical job identifier was reused for a different exact intent."""


class ComputeIntentNotFound(ComputeRuntimeError):
    """No metadata-only intent exists for the canonical job identifier."""


class ExecutionStage(str, Enum):
    INTENT_CREATED = "intent_created"
    START_PREPARED = "start_prepared"
    START_BROADCAST = "start_broadcast"
    START_CONFIRMED = "start_confirmed"
    PROVIDER_DISPATCHING = "provider_dispatching"
    USAGE_FINALIZED = "usage_finalized"
    METERING_PENDING = "metering_pending"
    METERING_DECIDED = "metering_decided"
    SETTLEMENT_PREPARED = "settlement_prepared"
    SETTLEMENT_BROADCAST = "settlement_broadcast"
    SETTLED = "settled"
    BLOCKED = "blocked"


TERMINAL_STAGES = frozenset({ExecutionStage.SETTLED, ExecutionStage.BLOCKED})


def canonical_compute_project_id(reference: str) -> str:
    """Match ``web/src/lib/computeVault.ts::computeVaultProjectId`` exactly."""

    normalized = _bounded_reference(reference, "project reference")
    if normalized.startswith("0x"):
        return normalized
    return "0x" + keccak((PROJECT_ID_DOMAIN + normalized).encode("utf-8")).hex()


def canonical_compute_job_id(reference: str) -> str:
    """Match ``web/src/lib/computeVault.ts::computeVaultJobId`` exactly."""

    normalized = _bounded_reference(reference, "job reference")
    if normalized.startswith("0x"):
        return normalized
    return "0x" + keccak((JOB_ID_DOMAIN + normalized).encode("utf-8")).hex()


@dataclass(frozen=True)
class CompiledRecipePolicy:
    operation: str
    model: str
    recipe: str
    allowed_result_policies: tuple[str, ...]
    max_prefill_tokens: int
    max_sample_tokens: int
    max_train_tokens: int

    @property
    def commitment(self) -> str:
        payload = {
            "schema": "dnai.compute.compiled-recipe-policy.v1",
            "operation": self.operation,
            "model": self.model,
            "recipe": self.recipe,
            "allowed_result_policies": list(self.allowed_result_policies),
            "max_prefill_tokens": self.max_prefill_tokens,
            "max_sample_tokens": self.max_sample_tokens,
            "max_train_tokens": self.max_train_tokens,
            "raw_prompt_api": False,
            "raw_examples_api": False,
            "arbitrary_program_api": False,
        }
        return _domain_hash(RECIPE_POLICY_DOMAIN, payload)


COMPILED_RECIPES: dict[tuple[str, str, str], CompiledRecipePolicy] = {
    (
        "inference",
        "qwen3_8b",
        "qwen3_8b_bounded",
    ): CompiledRecipePolicy(
        operation="inference",
        model="qwen3_8b",
        recipe="qwen3_8b_bounded",
        allowed_result_policies=("bounded_summary_receipt", "score_band_hash"),
        max_prefill_tokens=32_768,
        max_sample_tokens=4_096,
        max_train_tokens=0,
    ),
    (
        "training",
        "qwen3_8b",
        "qwen3_8b_lora_r32",
    ): CompiledRecipePolicy(
        operation="training",
        model="qwen3_8b",
        recipe="qwen3_8b_lora_r32",
        allowed_result_policies=("bounded_summary_receipt", "score_band_hash"),
        max_prefill_tokens=0,
        max_sample_tokens=0,
        max_train_tokens=10_000_000,
    ),
}


@dataclass(frozen=True)
class ComputeDispatchIntent:
    project_reference: str
    job_reference: str
    project_id: str
    job_id: str
    user: str
    asset: str
    authorization_nonce: int
    max_asset_debit: int
    authorization_expiry: int
    rate_policy_commitment: str
    compose_hash: str
    operation: str
    model: str
    recipe: str
    result_policy: str
    max_prefill_tokens: int
    max_sample_tokens: int
    max_train_tokens: int
    workload_id: str
    workload_schema: str
    manifest_commitment: str
    workload_commitment: str

    @classmethod
    def create(
        cls,
        *,
        project_reference: str,
        job_reference: str,
        user: str,
        asset: str,
        authorization_nonce: int,
        max_asset_debit: int,
        authorization_expiry: int,
        rate_policy_commitment: str,
        compose_hash: str,
        operation: str,
        model: str,
        recipe: str,
        result_policy: str,
        max_prefill_tokens: int,
        max_sample_tokens: int,
        max_train_tokens: int,
        workload_id: str,
        workload_schema: str,
        manifest_commitment: str,
        workload_commitment: str,
    ) -> "ComputeDispatchIntent":
        normalized_project = _bounded_reference(project_reference, "project reference")
        normalized_job = _bounded_reference(job_reference, "job reference")
        intent = cls(
            project_reference=normalized_project,
            job_reference=normalized_job,
            project_id=canonical_compute_project_id(normalized_project),
            job_id=canonical_compute_job_id(normalized_job),
            user=_address(user, allow_zero=False),
            asset=_address(asset, allow_zero=True),
            authorization_nonce=_uint256(authorization_nonce, "authorization nonce"),
            max_asset_debit=_uint256(
                max_asset_debit,
                "maximum asset debit",
                minimum=1,
            ),
            authorization_expiry=_timestamp(authorization_expiry),
            rate_policy_commitment=_bytes32(
                rate_policy_commitment,
                "rate policy commitment",
                allow_zero=False,
            ),
            compose_hash=_bytes32(compose_hash, "compose hash", allow_zero=False),
            operation=_ascii_choice(operation, {"inference", "training"}, "operation"),
            model=_ascii_choice(model, {"qwen3_8b"}, "model"),
            recipe=str(recipe),
            result_policy=_ascii_choice(
                result_policy,
                {"bounded_summary_receipt", "score_band_hash"},
                "result policy",
            ),
            max_prefill_tokens=_counter(max_prefill_tokens, "maximum prefill tokens"),
            max_sample_tokens=_counter(max_sample_tokens, "maximum sample tokens"),
            max_train_tokens=_counter(max_train_tokens, "maximum train tokens"),
            workload_id=_workload_id(workload_id),
            workload_schema=_ascii_choice(
                workload_schema,
                {INFERENCE_WORKLOAD_SCHEMA, SFT_JSONL_WORKLOAD_SCHEMA},
                "workload schema",
            ),
            manifest_commitment=_bytes32(
                manifest_commitment,
                "manifest commitment",
                allow_zero=False,
            ),
            workload_commitment=_bytes32(
                workload_commitment,
                "workload commitment",
                allow_zero=False,
            ),
        )
        intent.validate_compiled_recipe()
        return intent

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ComputeDispatchIntent":
        expected = {
            "schema",
            "project_reference",
            "job_reference",
            "project_id",
            "job_id",
            "user",
            "asset",
            "authorization_nonce",
            "max_asset_debit",
            "authorization_expiry",
            "rate_policy_commitment",
            "compose_hash",
            "operation",
            "model",
            "recipe",
            "result_policy",
            "max_prefill_tokens",
            "max_sample_tokens",
            "max_train_tokens",
            "workload_id",
            "workload_schema",
            "manifest_commitment",
            "workload_commitment",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ComputeRuntimeStateError("dispatch intent schema is invalid")
        if value["schema"] != INTENT_SCHEMA:
            raise ComputeRuntimeStateError("dispatch intent version is invalid")
        try:
            intent = cls.create(
                **{key: value[key] for key in expected if key != "schema" and key not in {"project_id", "job_id"}}
            )
        except (ComputeRuntimeError, TypeError, ValueError) as exc:
            raise ComputeRuntimeStateError("dispatch intent fields are invalid") from exc
        if value["project_id"] != intent.project_id or value["job_id"] != intent.job_id:
            raise ComputeRuntimeStateError("canonical Compute identifier mismatch")
        return intent

    def validate_compiled_recipe(self) -> CompiledRecipePolicy:
        policy = COMPILED_RECIPES.get((self.operation, self.model, self.recipe))
        if policy is None:
            raise ComputeRuntimePolicyError("compiled recipe is not allowlisted")
        if self.result_policy not in policy.allowed_result_policies:
            raise ComputeRuntimePolicyError("result policy is not compiled for recipe")
        limits = (
            (self.max_prefill_tokens, policy.max_prefill_tokens),
            (self.max_sample_tokens, policy.max_sample_tokens),
            (self.max_train_tokens, policy.max_train_tokens),
        )
        if any(requested > allowed for requested, allowed in limits):
            raise ComputeRuntimePolicyError("intent resource limit exceeds compiled recipe")
        if self.operation == "inference" and (
            self.max_prefill_tokens == 0 or self.max_sample_tokens == 0 or self.max_train_tokens != 0
        ):
            raise ComputeRuntimePolicyError("inference resource limits are invalid")
        if self.operation == "training" and (
            self.max_prefill_tokens != 0 or self.max_sample_tokens != 0 or self.max_train_tokens == 0
        ):
            raise ComputeRuntimePolicyError("training resource limits are invalid")
        expected_workload_schema = (
            INFERENCE_WORKLOAD_SCHEMA
            if self.operation == "inference"
            else SFT_JSONL_WORKLOAD_SCHEMA
        )
        if self.workload_schema != expected_workload_schema:
            raise ComputeRuntimePolicyError(
                "workload schema does not match compiled operation"
            )
        return policy

    @property
    def commitment(self) -> str:
        return _domain_hash(INTENT_COMMITMENT_DOMAIN, self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": INTENT_SCHEMA,
            "project_reference": self.project_reference,
            "job_reference": self.job_reference,
            "project_id": self.project_id,
            "job_id": self.job_id,
            "user": self.user,
            "asset": self.asset,
            "authorization_nonce": self.authorization_nonce,
            "max_asset_debit": self.max_asset_debit,
            "authorization_expiry": self.authorization_expiry,
            "rate_policy_commitment": self.rate_policy_commitment,
            "compose_hash": self.compose_hash,
            "operation": self.operation,
            "model": self.model,
            "recipe": self.recipe,
            "result_policy": self.result_policy,
            "max_prefill_tokens": self.max_prefill_tokens,
            "max_sample_tokens": self.max_sample_tokens,
            "max_train_tokens": self.max_train_tokens,
            "workload_id": self.workload_id,
            "workload_schema": self.workload_schema,
            "manifest_commitment": self.manifest_commitment,
            "workload_commitment": self.workload_commitment,
        }


def compute_execution_policy_context_hash(
    intent: ComputeDispatchIntent,
    policy: CompiledRecipePolicy | None = None,
) -> str:
    """Bind one policy PASS to exact public intent and compiled recipe bytes.

    The execution-policy resource remains the canonical on-chain ``job_id``.
    This separate bare ``bytes32`` commitment prevents a PASS for that stable
    identity from being replayed after public intent metadata or the reviewed
    compiled-recipe policy changes.
    """

    if not isinstance(intent, ComputeDispatchIntent):
        raise ComputeRuntimePolicyError("dispatch intent is required")
    compiled = policy if policy is not None else intent.validate_compiled_recipe()
    if not isinstance(compiled, CompiledRecipePolicy):
        raise ComputeRuntimePolicyError("compiled recipe policy is required")
    if compiled is not intent.validate_compiled_recipe():
        # The allowlist is a singleton map in this release. Identity checking
        # rejects a caller-created lookalike with the same visible fields.
        raise ComputeRuntimePolicyError("compiled recipe policy is not release-pinned")
    return _domain_hash(
        EXECUTION_POLICY_CONTEXT_DOMAIN,
        {
            "schema": "dnai.compute.execution-policy-context.v1",
            "job_id": intent.job_id,
            "intent_commitment": intent.commitment,
            "recipe_policy_commitment": compiled.commitment,
        },
    )[2:]


@dataclass(frozen=True)
class VaultJob:
    project_id: str
    user: str
    asset: str
    authorization_nonce: int
    max_asset_debit: int
    actual_asset_debit: int
    authorization_expiry: int
    started_at: int
    usage_ended_at: int
    receipt_expiry: int
    rate_policy_commitment: str
    workload_commitment: str
    manifest_commitment: str
    dispatch_intent_commitment: str
    compose_hash: str
    start_commitment: str
    usage_commitment: str
    attestation_evidence_hash: str
    billable_compute_units: int
    tee_identity: str
    state: int


@dataclass(frozen=True)
class VaultSnapshot:
    chain_id: int
    block_number: int
    block_hash: str
    block_timestamp: int
    vault_address: str
    vault_runtime_code_hash: str
    paused: bool
    developer_fee_frozen: bool
    asset_additions_frozen: bool
    rate_policy_additions_frozen: bool
    compose_policy_frozen: bool
    tee_identity_additions_frozen: bool
    metering_binding_frozen: bool
    metering_policy_set_hash: str
    allowed_asset_count: int
    active_rate_policy_count: int
    approved_compose_count: int
    approved_tee_identity_count: int
    pending_developer_fee_activates_at: int
    pending_asset_count: int
    pending_rate_policy_count: int
    pending_compose_count: int
    pending_tee_identity_count: int
    pending_metering_verifier: str
    pending_metering_qvl_verifier: str
    pending_metering_policy_set_hash: str
    pending_metering_binding_activates_at: int
    compose_approved: bool
    registered_tee_compose_hash: str
    metering_verifier: str
    metering_qvl_verifier: str
    rate_policy_asset: str
    rate_policy_provider: str
    rate_policy_developer_fee_bps: int
    rate_policy_active: bool
    job: VaultJob


@dataclass(frozen=True)
class PreparedTransaction:
    purpose: str
    tx_hash: str
    raw_transaction: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PreparedTransaction":
        if not isinstance(value, Mapping) or set(value) != {
            "purpose",
            "tx_hash",
            "raw_transaction",
        }:
            raise ComputeRuntimeStateError("prepared transaction is invalid")
        purpose = _ascii_choice(value["purpose"], {"start", "settlement"}, "transaction purpose")
        tx_hash = _tx_hash(value["tx_hash"])
        raw = str(value["raw_transaction"])
        if not re.fullmatch(r"^0x[0-9a-f]{2,131072}$", raw) or len(raw) % 2:
            raise ComputeRuntimeStateError("prepared raw transaction is invalid")
        if "0x" + keccak(bytes.fromhex(raw[2:])).hex() != tx_hash:
            raise ComputeRuntimeStateError("prepared transaction hash mismatch")
        return cls(purpose=purpose, tx_hash=tx_hash, raw_transaction=raw)

    def to_dict(self) -> dict[str, Any]:
        return {
            "purpose": self.purpose,
            "tx_hash": self.tx_hash,
            "raw_transaction": self.raw_transaction,
        }


@dataclass(frozen=True)
class ProviderUsage:
    outcome: str
    prefill_tokens: int
    sample_tokens: int
    training_tokens: int
    result_commitment: str
    provider_authoritative_invoice: bool = False

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProviderUsage":
        if not isinstance(value, Mapping) or set(value) != {
            "outcome",
            "prefill_tokens",
            "sample_tokens",
            "training_tokens",
            "result_commitment",
            "provider_authoritative_invoice",
        }:
            raise ComputeRuntimeStateError("provider usage schema is invalid")
        if value["provider_authoritative_invoice"] is not False:
            raise ComputeRuntimePolicyError("provider-authoritative usage is forbidden")
        return cls(
            outcome=_ascii_choice(value["outcome"], {"succeeded", "failed"}, "provider outcome"),
            prefill_tokens=_counter(value["prefill_tokens"], "prefill tokens"),
            sample_tokens=_counter(value["sample_tokens"], "sample tokens"),
            training_tokens=_counter(
                value["training_tokens"], "training tokens"
            ),
            result_commitment=_bytes32(
                value["result_commitment"],
                "result commitment",
                allow_zero=False,
            ),
            provider_authoritative_invoice=False,
        )

    def validate_for(self, intent: ComputeDispatchIntent) -> None:
        if (
            self.prefill_tokens > intent.max_prefill_tokens
            or self.sample_tokens > intent.max_sample_tokens
            or self.training_tokens > intent.max_train_tokens
        ):
            raise ComputeRuntimePolicyError("provider usage exceeds authorized resource limits")

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "prefill_tokens": self.prefill_tokens,
            "sample_tokens": self.sample_tokens,
            "training_tokens": self.training_tokens,
            "result_commitment": self.result_commitment,
            "provider_authoritative_invoice": False,
        }


@dataclass(frozen=True)
class SignedUsageEnvelope:
    block_number: int
    block_hash: str
    envelope: dict[str, Any]
    usage_commitment: str
    tee_signature: str

    @classmethod
    def create(
        cls,
        *,
        intent: ComputeDispatchIntent,
        usage: ProviderUsage,
        tee_identity: "ComputeExecutionIdentity",
        start_commitment: str,
        usage_started_at: int,
        block_number: int,
        block_hash: str,
        usage_observed_at: int,
    ) -> "SignedUsageEnvelope":
        usage.validate_for(intent)
        if usage.outcome == "succeeded" and not any(
            (usage.prefill_tokens, usage.sample_tokens, usage.training_tokens)
        ):
            raise ComputeRuntimePolicyError(
                "successful usage envelope must contain nonzero usage"
            )
        envelope = {
            "schema": USAGE_ENVELOPE_SCHEMA,
            "job_id": intent.job_id,
            "project_id": intent.project_id,
            "user": intent.user,
            "asset": intent.asset,
            "authorization_nonce": str(intent.authorization_nonce),
            "max_asset_debit": str(intent.max_asset_debit),
            "authorization_expiry": intent.authorization_expiry,
            "rate_policy_commitment": intent.rate_policy_commitment,
            "workload_commitment": intent.workload_commitment,
            "manifest_commitment": intent.manifest_commitment,
            "dispatch_intent_commitment": intent.commitment,
            "tee_identity": _address(tee_identity.address, allow_zero=False),
            "compose_hash": intent.compose_hash,
            "start_commitment": _bytes32(
                start_commitment,
                "start commitment",
                allow_zero=False,
            ),
            "model": intent.model,
            "recipe": intent.recipe,
            "outcome": usage.outcome,
            "prefill_tokens": str(usage.prefill_tokens),
            "sample_tokens": str(usage.sample_tokens),
            "training_tokens": str(usage.training_tokens),
            "usage_started_at": _timestamp(usage_started_at),
            "usage_observed_at": _timestamp(usage_observed_at),
            "raw_secret_egress": False,
        }
        commitment = _usage_commitment(envelope)
        signature = _canonical_personal_signature(
            tee_identity.sign_eip191(commitment)
        )
        envelope["usage_commitment"] = commitment
        envelope["tee_signature"] = signature
        return cls(
            block_number=_integer(
                block_number,
                "pinned block number",
                minimum=1,
                maximum=2**63 - 1,
            ),
            block_hash=_bytes32(block_hash, "pinned block hash", allow_zero=False),
            envelope=envelope,
            usage_commitment=commitment,
            tee_signature=signature,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedUsageEnvelope":
        if (
            not isinstance(value, Mapping)
            or set(value) != {"schema", "block", "usage"}
            or value.get("schema") != METERING_REQUEST_SCHEMA
        ):
            raise ComputeRuntimeStateError("metering request schema is invalid")
        block = value.get("block")
        if not isinstance(block, Mapping) or set(block) != {"number", "hash"}:
            raise ComputeRuntimeStateError("pinned metering block is invalid")
        block_number = _integer(
            block.get("number"),
            "pinned block number",
            minimum=1,
            maximum=2**63 - 1,
        )
        block_hash = _bytes32(
            block.get("hash"), "pinned block hash", allow_zero=False
        )
        envelope = value.get("usage")
        expected_fields = {
            "schema",
            "job_id",
            "project_id",
            "user",
            "asset",
            "authorization_nonce",
            "max_asset_debit",
            "authorization_expiry",
            "rate_policy_commitment",
            "workload_commitment",
            "manifest_commitment",
            "dispatch_intent_commitment",
            "tee_identity",
            "compose_hash",
            "start_commitment",
            "model",
            "recipe",
            "outcome",
            "prefill_tokens",
            "sample_tokens",
            "training_tokens",
            "usage_started_at",
            "usage_observed_at",
            "raw_secret_egress",
            "usage_commitment",
            "tee_signature",
        }
        if (
            not isinstance(envelope, Mapping)
            or set(envelope) != expected_fields
            or envelope.get("schema") != USAGE_ENVELOPE_SCHEMA
            or envelope.get("raw_secret_egress") is not False
        ):
            raise ComputeRuntimeStateError("usage envelope is invalid")
        try:
            _bytes32(envelope.get("job_id"), "job ID", allow_zero=False)
            _bytes32(envelope.get("project_id"), "project ID", allow_zero=False)
            _address(envelope.get("user"), allow_zero=False)
            _address(envelope.get("asset"), allow_zero=True)
            _decimal_uint256(envelope.get("authorization_nonce"), "authorization nonce")
            _decimal_uint256(envelope.get("max_asset_debit"), "maximum asset debit")
            _timestamp(envelope.get("authorization_expiry"))
            _bytes32(
                envelope.get("rate_policy_commitment"),
                "rate policy commitment",
                allow_zero=False,
            )
            _bytes32(
                envelope.get("workload_commitment"),
                "workload commitment",
                allow_zero=False,
            )
            _bytes32(
                envelope.get("manifest_commitment"),
                "manifest commitment",
                allow_zero=False,
            )
            _bytes32(
                envelope.get("dispatch_intent_commitment"),
                "dispatch intent commitment",
                allow_zero=False,
            )
            _address(envelope.get("tee_identity"), allow_zero=False)
            _bytes32(envelope.get("compose_hash"), "compose hash", allow_zero=False)
            _bytes32(
                envelope.get("start_commitment"),
                "start commitment",
                allow_zero=False,
            )
            _label(envelope.get("model"), "model")
            _label(envelope.get("recipe"), "recipe")
            outcome = _ascii_choice(
                envelope.get("outcome"),
                {"succeeded", "failed"},
                "provider outcome",
            )
            counters = (
                _decimal_uint256(envelope.get("prefill_tokens"), "prefill tokens"),
                _decimal_uint256(envelope.get("sample_tokens"), "sample tokens"),
                _decimal_uint256(envelope.get("training_tokens"), "training tokens"),
            )
            usage_started_at = _timestamp(envelope.get("usage_started_at"))
            usage_observed_at = _timestamp(envelope.get("usage_observed_at"))
            commitment = _bytes32(
                envelope.get("usage_commitment"),
                "usage commitment",
                allow_zero=False,
            )
            signature = _canonical_personal_signature(
                envelope.get("tee_signature")
            )
        except ComputeRuntimeError as exc:
            raise ComputeRuntimeStateError("usage envelope fields are invalid") from exc
        if outcome == "succeeded" and not any(counters):
            raise ComputeRuntimeStateError("successful usage is empty")
        if usage_observed_at < usage_started_at:
            raise ComputeRuntimeStateError("usage observation precedes job start")
        claims = dict(envelope)
        claims.pop("usage_commitment")
        claims.pop("tee_signature")
        if _usage_commitment(claims) != commitment:
            raise ComputeRuntimeStateError("usage commitment mismatch")
        try:
            signer = Account.recover_message(
                encode_defunct(hexstr=commitment), signature=signature
            )
        except Exception:
            raise ComputeRuntimeStateError("usage signature recovery failed") from None
        if _address(signer, allow_zero=False) != _address(
            envelope.get("tee_identity"), allow_zero=False
        ):
            raise ComputeRuntimeStateError("usage envelope TEE signature mismatch")
        return cls(
            block_number,
            block_hash,
            copy.deepcopy(dict(envelope)),
            commitment,
            signature,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": METERING_REQUEST_SCHEMA,
            "block": {"number": self.block_number, "hash": self.block_hash},
            "usage": copy.deepcopy(self.envelope),
        }

    def validate_for(
        self,
        *,
        intent: ComputeDispatchIntent,
        tee_identity: str,
        start_commitment: str,
        usage_started_at: int,
        block_number: int | None = None,
        block_hash: str | None = None,
    ) -> None:
        """Rebind a persisted envelope to the exact authorized execution.

        The journal MAC already detects storage tampering, but this explicit
        comparison prevents a future schema migration or dependency bug from
        turning a valid signature for one job into authority for another.
        """

        expected = {
            "job_id": intent.job_id,
            "project_id": intent.project_id,
            "user": intent.user,
            "asset": intent.asset,
            "authorization_nonce": str(intent.authorization_nonce),
            "max_asset_debit": str(intent.max_asset_debit),
            "authorization_expiry": intent.authorization_expiry,
            "rate_policy_commitment": intent.rate_policy_commitment,
            "workload_commitment": intent.workload_commitment,
            "manifest_commitment": intent.manifest_commitment,
            "dispatch_intent_commitment": intent.commitment,
            "tee_identity": _address(tee_identity, allow_zero=False),
            "compose_hash": intent.compose_hash,
            "start_commitment": _bytes32(
                start_commitment,
                "start commitment",
                allow_zero=False,
            ),
            "usage_started_at": _timestamp(usage_started_at),
            "model": intent.model,
            "recipe": intent.recipe,
            "raw_secret_egress": False,
            "usage_commitment": self.usage_commitment,
            "tee_signature": self.tee_signature,
        }
        exact_fields = set(expected) | {
            "schema",
            "outcome",
            "prefill_tokens",
            "sample_tokens",
            "training_tokens",
            "usage_observed_at",
        }
        if set(self.envelope) != exact_fields or any(
            self.envelope.get(key) != value for key, value in expected.items()
        ) or (block_number is not None and self.block_number != block_number) or (
            block_hash is not None and self.block_hash != block_hash
        ):
            raise ComputeRuntimePolicyError(
                "signed usage envelope does not match exact execution"
            )
        usage = ProviderUsage(
            outcome=_ascii_choice(
                self.envelope.get("outcome"),
                {"succeeded", "failed"},
                "provider outcome",
            ),
            prefill_tokens=_counter(
                _decimal_uint256(self.envelope.get("prefill_tokens"), "prefill tokens"),
                "prefill tokens",
            ),
            sample_tokens=_counter(
                _decimal_uint256(self.envelope.get("sample_tokens"), "sample tokens"),
                "sample tokens",
            ),
            training_tokens=_counter(
                _decimal_uint256(
                    self.envelope.get("training_tokens"), "training tokens"
                ),
                "training tokens",
            ),
            # The bounded result commitment remains in the execution journal;
            # it is deliberately absent from the metering service contract.
            result_commitment="0x" + "01" * 32,
        )
        usage.validate_for(intent)
        if _timestamp(self.envelope.get("usage_observed_at")) > intent.authorization_expiry:
            raise ComputeRuntimePolicyError("signed usage envelope was issued after expiry")


@dataclass(frozen=True)
class MeteringDecision:
    classification: str
    provider_authoritative_invoice: bool
    chain_id: int
    vault_address: str
    pinned_block_number: int
    pinned_block_hash: str
    policy_set_hash: str
    rate_policy_commitment: str
    workload_commitment: str
    manifest_commitment: str
    dispatch_intent_commitment: str
    asset: str
    job_id: str
    usage_commitment: str
    onchain_usage_commitment: str
    actual_asset_debit: int
    billable_compute_units: int
    usage_started_at: int
    usage_ended_at: int
    attestation_evidence_hash: str
    receipt_expiry: int
    metering_receipt_digest: str
    metering_qvl_receipt_digest: str
    metering_verifier: str
    metering_qvl_verifier: str
    tee_identity: str
    compose_hash: str
    raw_secret_egress: bool
    verifier_signature: str
    qvl_signature: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "MeteringDecision":
        expected = {
            "schema",
            "classification",
            "provider_authoritative_invoice",
            "chain_id",
            "vault_address",
            "pinned_block_number",
            "pinned_block_hash",
            "policy_set_hash",
            "rate_policy_commitment",
            "workload_commitment",
            "manifest_commitment",
            "dispatch_intent_commitment",
            "asset",
            "job_id",
            "usage_commitment",
            "onchain_usage_commitment",
            "actual_asset_debit",
            "billable_compute_units",
            "usage_started_at",
            "usage_ended_at",
            "attestation_evidence_hash",
            "receipt_expiry",
            "metering_receipt_digest",
            "metering_qvl_receipt_digest",
            "metering_verifier",
            "metering_qvl_verifier",
            "tee_identity",
            "compose_hash",
            "raw_secret_egress",
            "verifier_signature",
            "qvl_signature",
        }
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ComputeRuntimePolicyError("metering decision schema is invalid")
        if (
            value["schema"] != METERING_DECISION_SCHEMA
            or value["classification"] != "attested_dual_verified_metering"
            or value["provider_authoritative_invoice"] is not False
            or value["raw_secret_egress"] is not False
        ):
            raise ComputeRuntimePolicyError("metering decision version is invalid")
        return cls(
            classification="attested_dual_verified_metering",
            provider_authoritative_invoice=False,
            chain_id=_integer(value["chain_id"], "metering chain ID", minimum=1, maximum=2**63 - 1),
            vault_address=_address(value["vault_address"], allow_zero=False),
            pinned_block_number=_integer(
                value["pinned_block_number"],
                "pinned block number",
                minimum=1,
                maximum=2**63 - 1,
            ),
            pinned_block_hash=_bytes32(
                value["pinned_block_hash"], "pinned block hash", allow_zero=False
            ),
            policy_set_hash=_bytes32(
                value["policy_set_hash"], "policy set hash", allow_zero=False
            ),
            rate_policy_commitment=_bytes32(
                value["rate_policy_commitment"],
                "rate policy commitment",
                allow_zero=False,
            ),
            workload_commitment=_bytes32(
                value["workload_commitment"],
                "workload commitment",
                allow_zero=False,
            ),
            manifest_commitment=_bytes32(
                value["manifest_commitment"],
                "manifest commitment",
                allow_zero=False,
            ),
            dispatch_intent_commitment=_bytes32(
                value["dispatch_intent_commitment"],
                "dispatch intent commitment",
                allow_zero=False,
            ),
            asset=_address(value["asset"], allow_zero=True),
            job_id=_bytes32(value["job_id"], "metering job ID", allow_zero=False),
            usage_commitment=_bytes32(
                value["usage_commitment"],
                "metering usage commitment",
                allow_zero=False,
            ),
            onchain_usage_commitment=_bytes32(
                value["onchain_usage_commitment"],
                "onchain usage commitment",
                allow_zero=False,
            ),
            actual_asset_debit=_decimal_uint256(
                value["actual_asset_debit"], "actual asset debit"
            ),
            billable_compute_units=_decimal_uint256(
                value["billable_compute_units"], "billable compute units"
            ),
            usage_started_at=_timestamp(value["usage_started_at"]),
            usage_ended_at=_timestamp(value["usage_ended_at"]),
            attestation_evidence_hash=_bytes32(
                value["attestation_evidence_hash"],
                "attestation evidence hash",
                allow_zero=False,
            ),
            receipt_expiry=_timestamp(value["receipt_expiry"]),
            metering_receipt_digest=_bytes32(
                value["metering_receipt_digest"],
                "metering receipt digest",
                allow_zero=False,
            ),
            metering_qvl_receipt_digest=_bytes32(
                value["metering_qvl_receipt_digest"],
                "metering QVL receipt digest",
                allow_zero=False,
            ),
            metering_verifier=_address(value["metering_verifier"], allow_zero=False),
            metering_qvl_verifier=_address(
                value["metering_qvl_verifier"], allow_zero=False
            ),
            tee_identity=_address(value["tee_identity"], allow_zero=False),
            compose_hash=_bytes32(
                value["compose_hash"], "compose hash", allow_zero=False
            ),
            raw_secret_egress=False,
            verifier_signature=_canonical_personal_signature(
                value["verifier_signature"], raw_digest=True
            ),
            qvl_signature=_canonical_personal_signature(
                value["qvl_signature"], raw_digest=True
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": METERING_DECISION_SCHEMA,
            "classification": self.classification,
            "provider_authoritative_invoice": False,
            "chain_id": self.chain_id,
            "vault_address": self.vault_address,
            "pinned_block_number": self.pinned_block_number,
            "pinned_block_hash": self.pinned_block_hash,
            "policy_set_hash": self.policy_set_hash,
            "rate_policy_commitment": self.rate_policy_commitment,
            "workload_commitment": self.workload_commitment,
            "manifest_commitment": self.manifest_commitment,
            "dispatch_intent_commitment": self.dispatch_intent_commitment,
            "asset": self.asset,
            "job_id": self.job_id,
            "usage_commitment": self.usage_commitment,
            "onchain_usage_commitment": self.onchain_usage_commitment,
            "actual_asset_debit": str(self.actual_asset_debit),
            "billable_compute_units": str(self.billable_compute_units),
            "usage_started_at": self.usage_started_at,
            "usage_ended_at": self.usage_ended_at,
            "attestation_evidence_hash": self.attestation_evidence_hash,
            "receipt_expiry": self.receipt_expiry,
            "metering_receipt_digest": self.metering_receipt_digest,
            "metering_qvl_receipt_digest": self.metering_qvl_receipt_digest,
            "metering_verifier": self.metering_verifier,
            "metering_qvl_verifier": self.metering_qvl_verifier,
            "tee_identity": self.tee_identity,
            "compose_hash": self.compose_hash,
            "raw_secret_egress": False,
            "verifier_signature": self.verifier_signature,
            "qvl_signature": self.qvl_signature,
        }


class ComputeExecutionIdentity(Protocol):
    address: str
    custody: str

    def sign_transaction(self, transaction: dict[str, Any]) -> Any: ...

    def sign_eip191(self, digest: str) -> str: ...


class DstackComputeExecutionIdentity:
    """Purpose-separated Ethereum identity derived only inside real dstack."""

    custody = "dstack_derived_compute_execution"

    def __init__(self, private_key: bytes):
        self._account = Account.from_key(private_key)
        self.address = self._account.address.lower()

    @classmethod
    def from_key_path(cls, key_path: str) -> "DstackComputeExecutionIdentity":
        normalized = str(key_path).strip()
        if not normalized or len(normalized) > 256 or not normalized.isascii():
            raise ComputeRuntimePolicyError("compute execution key path is invalid")
        key_material = derive_storage_key(normalized)
        return cls(derive_ethereum_private_key(key_material, normalized))

    def sign_transaction(self, transaction: dict[str, Any]) -> Any:
        return self._account.sign_transaction(transaction)

    def sign_eip191(self, digest: str) -> str:
        normalized = _bytes32(digest, "usage digest", allow_zero=False)
        signed = self._account.sign_message(encode_defunct(hexstr=normalized))
        return "0x" + bytes(signed.signature).hex()

    def __repr__(self) -> str:
        return "DstackComputeExecutionIdentity(custody='dstack_derived')"


class ComputeVaultGateway(Protocol):
    chain_id: int
    vault_address: str
    runtime_code_hash: str

    def snapshot(
        self,
        *,
        job_id: str,
        rate_policy_commitment: str,
        tee_identity: str,
        compose_hash: str,
        block_number: int | None = None,
    ) -> VaultSnapshot: ...

    def prepare_start(
        self,
        *,
        job_id: str,
        compose_hash: str,
    ) -> PreparedTransaction: ...

    def prepare_settlement(
        self,
        *,
        job_id: str,
        actual_asset_debit: int,
        compose_hash: str,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
        verifier_signature: str,
        qvl_signature: str,
    ) -> PreparedTransaction: ...

    def broadcast(self, transaction: PreparedTransaction) -> None: ...

    def confirmed_snapshot(
        self,
        transaction: PreparedTransaction,
        *,
        confirmations: int,
        job_id: str,
        rate_policy_commitment: str,
        tee_identity: str,
        compose_hash: str,
    ) -> VaultSnapshot | None: ...

    def metering_receipt_digest(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
    ) -> str: ...

    def metering_qvl_receipt_digest(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
        receipt_expiry: int,
    ) -> str: ...

    def usage_commitment(
        self,
        *,
        block_number: int,
        block_hash: str,
        job_id: str,
        actual_asset_debit: int,
        billable_compute_units: int,
        usage_started_at: int,
        usage_ended_at: int,
        attestation_evidence_hash: str,
    ) -> str: ...

    def close(self) -> None: ...


class CompiledRecipeExecutor(Protocol):
    supports_idempotent_dispatch: bool

    def execute(
        self,
        intent: ComputeDispatchIntent,
        policy: CompiledRecipePolicy,
        *,
        dispatch_id: str,
    ) -> ProviderUsage: ...


class ComputeMeteringClient(Protocol):
    def decide(self, signed_usage: SignedUsageEnvelope) -> MeteringDecision: ...

    def close(self) -> None: ...


class ComputeExecutionPolicyAuthorizer(Protocol):
    """Open one anchored PASS lease for an exact canonical Compute job ID."""

    def authorized_execution_lease(
        self, *, job_id: str, execution_context_hash: str, now: int
    ) -> ContextManager[Mapping[str, Any]]: ...


class ComputeExecutionJournal:
    """HMAC-authenticated, cross-process-safe exact-asset execution journal."""

    _RECORD_FIELDS = {
        "intent",
        "stage",
        "start_commitment",
        "dispatch_id",
        "start_transaction",
        "usage",
        "signed_usage",
        "metering_decision",
        "settlement_transaction",
        "last_reason",
        "created_at",
        "updated_at",
        "provider_authoritative",
        "legacy_credit_ledger_mutated",
    }

    def __init__(self, path: str | Path, *, integrity_key: bytes):
        self.path = Path(path)
        if not str(self.path) or "\x00" in str(self.path):
            raise ComputeRuntimeStateError("execution journal path is invalid")
        if len(integrity_key) < 32:
            raise ComputeRuntimeStateError("execution journal integrity key is too short")
        self._integrity_key = bytes(integrity_key)
        self._thread_lock = threading.RLock()
        self._cycle_thread_lock = threading.RLock()
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._cycle_lock_path = self.path.with_name(
            self.path.name + ".execution-cycle.lock"
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure_lock_file(self._lock_path)
        self._ensure_lock_file(self._cycle_lock_path)
        with self._exclusive_lock():
            if not self.path.exists():
                self._write_unlocked(self._empty_body())
            else:
                self._load_unlocked()

    def enqueue(
        self,
        intent: ComputeDispatchIntent,
        *,
        idempotency_key: str,
        created_at: int,
    ) -> tuple[dict[str, Any], bool]:
        key = str(idempotency_key)
        if not _IDEMPOTENCY.fullmatch(key):
            raise ComputeRuntimePolicyError("dispatch idempotency key is invalid")
        timestamp = _timestamp(created_at)
        with self._exclusive_lock():
            body = self._load_unlocked()
            existing = body["records"].get(intent.job_id)
            if existing is not None:
                parsed = self._validate_record(existing)
                if parsed["intent"] != intent.to_dict():
                    raise ComputeIntentConflict("canonical job ID already binds a different intent")
                if existing.get("idempotency_key_hash") not in (None, _hash_text("compute_dispatch_idempotency", key)):
                    raise ComputeIntentConflict("dispatch idempotency key does not match")
                return self._public_record(parsed), False
            if len(body["records"]) >= MAX_RECORDS:
                raise ComputeRuntimeStateError("execution journal capacity reached")
            record = {
                "intent": intent.to_dict(),
                "stage": ExecutionStage.INTENT_CREATED.value,
                "start_commitment": None,
                "dispatch_id": None,
                "start_transaction": None,
                "usage": None,
                "signed_usage": None,
                "metering_decision": None,
                "settlement_transaction": None,
                "last_reason": "metadata_intent_authenticated",
                "created_at": timestamp,
                "updated_at": timestamp,
                "provider_authoritative": False,
                "legacy_credit_ledger_mutated": False,
                "idempotency_key_hash": _hash_text("compute_dispatch_idempotency", key),
            }
            body["records"][intent.job_id] = record
            body["sequence"] += 1
            self._write_unlocked(body)
            return self._public_record(record), True

    def get(self, job_id: str) -> dict[str, Any]:
        normalized = _bytes32(job_id, "job ID", allow_zero=False)
        with self._exclusive_lock():
            body = self._load_unlocked()
            record = body["records"].get(normalized)
            if record is None:
                raise ComputeIntentNotFound("dispatch intent not found")
            return copy.deepcopy(self._validate_record(record))

    def public_get(self, job_id: str) -> dict[str, Any]:
        return self._public_record(self.get(job_id))

    def next_actionable(self) -> dict[str, Any] | None:
        with self._exclusive_lock():
            body = self._load_unlocked()
            records = [
                self._validate_record(record)
                for record in body["records"].values()
                if ExecutionStage(record["stage"]) not in TERMINAL_STAGES
            ]
            if not records:
                return None
            records.sort(key=lambda value: (value["created_at"], value["intent"]["job_id"]))
            return copy.deepcopy(records[0])

    def transition(
        self,
        job_id: str,
        *,
        expected_stage: ExecutionStage,
        new_stage: ExecutionStage,
        updates: Mapping[str, Any],
        reason: str,
        updated_at: int,
    ) -> dict[str, Any]:
        normalized = _bytes32(job_id, "job ID", allow_zero=False)
        if not isinstance(updates, Mapping) or any(
            key not in self._RECORD_FIELDS for key in updates
        ):
            raise ComputeRuntimeStateError("execution journal update is invalid")
        if not re.fullmatch(r"^[a-z][a-z0-9_]{2,95}$", str(reason)):
            raise ComputeRuntimeStateError("execution reason is invalid")
        timestamp = _timestamp(updated_at)
        with self._exclusive_lock():
            body = self._load_unlocked()
            current = body["records"].get(normalized)
            if current is None:
                raise ComputeRuntimeStateError("dispatch intent not found")
            parsed = self._validate_record(current)
            if ExecutionStage(parsed["stage"]) != expected_stage:
                raise ComputeRuntimeStateError("execution stage changed concurrently")
            candidate = copy.deepcopy(current)
            candidate.update(copy.deepcopy(dict(updates)))
            candidate["stage"] = new_stage.value
            candidate["last_reason"] = reason
            candidate["updated_at"] = timestamp
            self._validate_record(candidate)
            body["records"][normalized] = candidate
            body["sequence"] += 1
            self._write_unlocked(body)
            return copy.deepcopy(candidate)

    def note_retryable(
        self,
        job_id: str,
        *,
        stage: ExecutionStage,
        reason: str,
        updated_at: int,
    ) -> None:
        self.transition(
            job_id,
            expected_stage=stage,
            new_stage=stage,
            updates={},
            reason=reason,
            updated_at=updated_at,
        )

    def _public_record(self, record: Mapping[str, Any]) -> dict[str, Any]:
        intent = ComputeDispatchIntent.from_dict(record["intent"])
        return {
            "surface": "compute_dispatch_intent",
            "schema_version": 2,
            "project_reference": intent.project_reference,
            "job_reference": intent.job_reference,
            "project_id": intent.project_id,
            "job_id": intent.job_id,
            "user": intent.user,
            "asset": intent.asset,
            "authorization_nonce": intent.authorization_nonce,
            "max_asset_debit": intent.max_asset_debit,
            "authorization_expiry": intent.authorization_expiry,
            "rate_policy_commitment": intent.rate_policy_commitment,
            "compose_hash": intent.compose_hash,
            "operation": intent.operation,
            "model": intent.model,
            "recipe": intent.recipe,
            "result_policy": intent.result_policy,
            "resource_limits": {
                "max_prefill_tokens": intent.max_prefill_tokens,
                "max_sample_tokens": intent.max_sample_tokens,
                "max_train_tokens": intent.max_train_tokens,
            },
            "workload_id": intent.workload_id,
            "workload_schema": intent.workload_schema,
            "manifest_commitment": intent.manifest_commitment,
            "workload_commitment": intent.workload_commitment,
            "intent_commitment": intent.commitment,
            "execution_policy_context_hash": (
                compute_execution_policy_context_hash(intent)
            ),
            "stage": record["stage"],
            "provider_authoritative": False,
            "legacy_credit_ledger_mutated": False,
            # The provider call begins only after PROVIDER_DISPATCHING is
            # durably committed. A crash at that boundary makes completion
            # unknown until the same provider idempotency key is replayed.
            "provider_dispatch_status": (
                "usage_finalized"
                if record["usage"] is not None
                else "may_have_started"
                if record["dispatch_id"] is not None
                else "not_started"
            ),
            "provider_dispatch_may_have_occurred": record["dispatch_id"]
            is not None,
            "provider_usage_finalized": record["usage"] is not None,
            "raw_prompt_accepted": False,
            "raw_examples_accepted": False,
            "arbitrary_program_accepted": False,
            "exact_timing_egress": False,
        }

    def _empty_body(self) -> dict[str, Any]:
        return {
            "schema": STORE_SCHEMA,
            "schema_version": 1,
            "sequence": 0,
            "records": {},
            "raw_prompt_persisted": False,
            "raw_examples_persisted": False,
            "raw_output_persisted": False,
            "legacy_credit_ledger_mutated": False,
        }

    def _load_unlocked(self) -> dict[str, Any]:
        try:
            details = self.path.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_nlink != 1
                or details.st_size < 2
                or details.st_size > MAX_STORE_BYTES
            ):
                raise ComputeRuntimeStateError("execution journal file metadata is invalid")
            root = _strict_json_object(self.path.read_bytes())
            if set(root) != {"body", "mac"} or not isinstance(root["body"], dict):
                raise ComputeRuntimeStateError("execution journal envelope is invalid")
            expected = hmac.new(
                self._integrity_key,
                STORE_MAC_DOMAIN + _canonical_json(root["body"]),
                hashlib.sha256,
            ).hexdigest()
            if not isinstance(root["mac"], str) or not hmac.compare_digest(root["mac"], expected):
                raise ComputeRuntimeStateError("execution journal authentication failed")
            body = root["body"]
            if set(body) != set(self._empty_body()):
                raise ComputeRuntimeStateError("execution journal body schema is invalid")
            if (
                body["schema"] != STORE_SCHEMA
                or body["schema_version"] != 1
                or not isinstance(body["sequence"], int)
                or body["sequence"] < 0
                or not isinstance(body["records"], dict)
                or len(body["records"]) > MAX_RECORDS
                or body["raw_prompt_persisted"] is not False
                or body["raw_examples_persisted"] is not False
                or body["raw_output_persisted"] is not False
                or body["legacy_credit_ledger_mutated"] is not False
            ):
                raise ComputeRuntimeStateError("execution journal body is invalid")
            for job_id, record in body["records"].items():
                if job_id != self._validate_record(record)["intent"]["job_id"]:
                    raise ComputeRuntimeStateError("execution journal record key mismatch")
            return body
        except ComputeRuntimeStateError:
            raise
        except Exception:
            raise ComputeRuntimeStateError("execution journal is unreadable") from None

    def _validate_record(self, value: Mapping[str, Any]) -> dict[str, Any]:
        expected = self._RECORD_FIELDS | {"idempotency_key_hash"}
        if not isinstance(value, Mapping) or set(value) != expected:
            raise ComputeRuntimeStateError("execution record schema is invalid")
        intent = ComputeDispatchIntent.from_dict(value["intent"])
        try:
            stage = ExecutionStage(value["stage"])
        except (TypeError, ValueError) as exc:
            raise ComputeRuntimeStateError("execution stage is invalid") from exc
        _timestamp(value["created_at"])
        _timestamp(value["updated_at"])
        if value["provider_authoritative"] is not False or value["legacy_credit_ledger_mutated"] is not False:
            raise ComputeRuntimeStateError("forbidden execution authority flag")
        if not isinstance(value["last_reason"], str) or not re.fullmatch(
            r"^[a-z][a-z0-9_]{2,95}$", value["last_reason"]
        ):
            raise ComputeRuntimeStateError("execution reason is invalid")
        if not isinstance(value["idempotency_key_hash"], str) or not re.fullmatch(
            r"^[0-9a-f]{64}$", value["idempotency_key_hash"]
        ):
            raise ComputeRuntimeStateError("execution idempotency binding is invalid")
        if value["start_commitment"] is not None:
            _bytes32(value["start_commitment"], "start commitment", allow_zero=False)
        if value["dispatch_id"] is not None:
            _bytes32(value["dispatch_id"], "dispatch ID", allow_zero=False)
        if value["start_transaction"] is not None:
            tx = PreparedTransaction.from_dict(value["start_transaction"])
            if tx.purpose != "start":
                raise ComputeRuntimeStateError("start transaction purpose mismatch")
        if value["usage"] is not None:
            ProviderUsage.from_dict(value["usage"]).validate_for(intent)
        if value["signed_usage"] is not None:
            SignedUsageEnvelope.from_dict(value["signed_usage"])
        if value["metering_decision"] is not None:
            MeteringDecision.from_dict(value["metering_decision"])
        if value["settlement_transaction"] is not None:
            tx = PreparedTransaction.from_dict(value["settlement_transaction"])
            if tx.purpose != "settlement":
                raise ComputeRuntimeStateError("settlement transaction purpose mismatch")
        required_by_stage = {
            ExecutionStage.START_PREPARED: ("start_transaction",),
            ExecutionStage.START_BROADCAST: ("start_transaction",),
            ExecutionStage.START_CONFIRMED: ("start_commitment", "start_transaction"),
            ExecutionStage.PROVIDER_DISPATCHING: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
            ),
            ExecutionStage.USAGE_FINALIZED: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
            ),
            ExecutionStage.METERING_PENDING: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
                "signed_usage",
            ),
            ExecutionStage.METERING_DECIDED: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
                "signed_usage",
                "metering_decision",
            ),
            ExecutionStage.SETTLEMENT_PREPARED: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
                "signed_usage",
                "metering_decision",
                "settlement_transaction",
            ),
            ExecutionStage.SETTLEMENT_BROADCAST: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
                "signed_usage",
                "metering_decision",
                "settlement_transaction",
            ),
            ExecutionStage.SETTLED: (
                "start_commitment",
                "start_transaction",
                "dispatch_id",
                "usage",
                "signed_usage",
                "metering_decision",
                "settlement_transaction",
            ),
        }
        for field in required_by_stage.get(stage, ()):
            if value[field] is None:
                raise ComputeRuntimeStateError("execution stage checkpoint is incomplete")
        return copy.deepcopy(dict(value))

    def _write_unlocked(self, body: Mapping[str, Any]) -> None:
        encoded_body = _canonical_json(body)
        root = {
            "body": copy.deepcopy(dict(body)),
            "mac": hmac.new(
                self._integrity_key,
                STORE_MAC_DOMAIN + encoded_body,
                hashlib.sha256,
            ).hexdigest(),
        }
        encoded = _canonical_json(root) + b"\n"
        if len(encoded) > MAX_STORE_BYTES:
            raise ComputeRuntimeStateError("execution journal exceeds size limit")
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.",
            suffix=".tmp",
            dir=str(self.path.parent),
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=True) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
            _fsync_directory(self.path.parent)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise

    def _ensure_lock_file(self, path: Path) -> None:
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    class _Lock:
        def __init__(
            self,
            owner: "ComputeExecutionJournal",
            *,
            path: Path,
            thread_lock: threading.RLock,
        ):
            self.owner = owner
            self.path = path
            self.thread_lock = thread_lock
            self.fd: int | None = None

        def __enter__(self):
            self.thread_lock.acquire()
            self.fd = os.open(self.path, os.O_RDWR)
            fcntl.flock(self.fd, fcntl.LOCK_EX)
            return self

        def __exit__(self, exc_type, exc, traceback):
            try:
                if self.fd is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                    os.close(self.fd)
            finally:
                self.thread_lock.release()

    def _exclusive_lock(self) -> "ComputeExecutionJournal._Lock":
        return self._Lock(
            self,
            path=self._lock_path,
            thread_lock=self._thread_lock,
        )

    def execution_cycle_lease(self) -> "ComputeExecutionJournal._Lock":
        """Serialize one full irreversible execution cycle across processes."""

        return self._Lock(
            self,
            path=self._cycle_lock_path,
            thread_lock=self._cycle_thread_lock,
        )


@dataclass(frozen=True)
class ComputeCycleResult:
    state: str
    job_id: str | None
    reason: str
    provider_dispatched: bool
    settled: bool
    execution_policy_authorized: bool = False
    provider_dispatch_may_have_occurred: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "schema": PUBLIC_STATUS_SCHEMA,
            "state": self.state,
            "job_id": self.job_id,
            "reason": self.reason,
            "provider_dispatched": self.provider_dispatched,
            "provider_dispatch_may_have_occurred": (
                self.provider_dispatch_may_have_occurred
            ),
            "settled": self.settled,
            "execution_policy_anchor_gate_integrated": True,
            "execution_policy_authorized": self.execution_policy_authorized,
            "provider_authoritative": False,
            "legacy_credit_ledger_mutated": False,
            "raw_prompt_egress": False,
            "raw_examples_egress": False,
            "raw_output_egress": False,
            "exception_detail_egress": False,
        }


class ComputeExecutionWorker:
    """Crash-resumable, policy-leased exact-asset execution state machine.

    Every actionable cycle is serialized by the execution journal and then
    authorized for the intent's exact canonical ``bytes32`` job ID. The
    authorizer must keep its rollback-resistant policy lease through this
    method's complete chain/provider/metering boundary. There is no unguarded
    constructor mode; tests supply an explicitly named test-only authorizer.
    """

    def __init__(
        self,
        *,
        journal: ComputeExecutionJournal,
        gateway: ComputeVaultGateway,
        identity: ComputeExecutionIdentity,
        provider: CompiledRecipeExecutor,
        metering: ComputeMeteringClient,
        policy_authorizer: ComputeExecutionPolicyAuthorizer,
        metering_policy_set_hash: str,
        confirmations: int = 2,
        max_block_age_seconds: int = 300,
        max_future_block_skew_seconds: int = 30,
        clock: Callable[[], float] = time.time,
    ):
        if confirmations < 2:
            raise ComputeRuntimePolicyError("Base Sepolia requires at least two confirmations")
        if not 30 <= max_block_age_seconds <= 3_600:
            raise ComputeRuntimePolicyError("maximum chain snapshot age is invalid")
        if not 0 <= max_future_block_skew_seconds <= 120:
            raise ComputeRuntimePolicyError("maximum future block skew is invalid")
        if not callable(
            getattr(policy_authorizer, "authorized_execution_lease", None)
        ):
            raise ComputeRuntimePolicyError(
                "execution policy authorizer is required"
            )
        self.journal = journal
        self.gateway = gateway
        self.identity = identity
        self.provider = provider
        self.metering = metering
        self.policy_authorizer = policy_authorizer
        self.metering_policy_set_hash = _bytes32(
            metering_policy_set_hash,
            "metering policy set hash",
            allow_zero=False,
        )
        self.confirmations = confirmations
        self.max_block_age_seconds = max_block_age_seconds
        self.max_future_block_skew_seconds = max_future_block_skew_seconds
        self.clock = clock

    def run_once(self) -> ComputeCycleResult:
        # The dedicated cycle lease is distinct from the journal's short
        # mutation lock. It prevents two worker processes from concurrently
        # crossing the provider boundary for the same selected intent while
        # allowing the API to enqueue metadata-only work.
        with self.journal.execution_cycle_lease():
            record = self.journal.next_actionable()
            if record is None:
                return ComputeCycleResult(
                    "idle", None, "no_actionable_intent", False, False
                )
            job_id = record["intent"]["job_id"]
            try:
                intent = ComputeDispatchIntent.from_dict(record["intent"])
                policy = intent.validate_compiled_recipe()
                with self.policy_authorizer.authorized_execution_lease(
                    job_id=job_id,
                    execution_context_hash=(
                        compute_execution_policy_context_hash(intent, policy)
                    ),
                    now=self._now(),
                ):
                    result = self._run_authorized_job(job_id)
                current = self.journal.get(job_id)
                return ComputeCycleResult(
                    state=result.state,
                    job_id=result.job_id,
                    reason=result.reason,
                    provider_dispatched=result.provider_dispatched,
                    settled=result.settled,
                    execution_policy_authorized=True,
                    provider_dispatch_may_have_occurred=(
                        current["dispatch_id"] is not None
                    ),
                )
            except ComputeExecutionPolicyNotPassed:
                current = self.journal.get(job_id)
                return ComputeCycleResult(
                    "blocked",
                    job_id,
                    "execution_policy_not_passed",
                    current["usage"] is not None,
                    False,
                    provider_dispatch_may_have_occurred=(
                        current["dispatch_id"] is not None
                    ),
                )
            except ComputeExecutionPolicyUnavailable:
                current = self.journal.get(job_id)
                return ComputeCycleResult(
                    "retryable",
                    job_id,
                    "execution_policy_anchor_unavailable",
                    current["usage"] is not None,
                    False,
                    provider_dispatch_may_have_occurred=(
                        current["dispatch_id"] is not None
                    ),
                )

    def _run_authorized_job(self, job_id: str) -> ComputeCycleResult:
        """Advance only ``job_id`` while the caller holds its exact PASS lease."""

        try:
            for _ in range(16):
                record = self.journal.get(job_id)
                stage = ExecutionStage(record["stage"])
                if stage == ExecutionStage.SETTLED:
                    return ComputeCycleResult(
                        stage.value,
                        job_id,
                        "settlement_confirmed",
                        True,
                        True,
                    )
                if stage == ExecutionStage.BLOCKED:
                    return ComputeCycleResult(
                        stage.value,
                        job_id,
                        record["last_reason"],
                        record["usage"] is not None,
                        False,
                    )
                progressed = self._advance(record)
                if not progressed:
                    current = self.journal.get(job_id)
                    return ComputeCycleResult(
                        current["stage"],
                        job_id,
                        current["last_reason"],
                        current["usage"] is not None,
                        current["stage"] == ExecutionStage.SETTLED.value,
                    )
            raise ComputeRuntimeStateError("execution cycle transition bound exceeded")
        except ComputeRuntimePolicyError:
            current = self.journal.get(job_id)
            stage = ExecutionStage(current["stage"])
            reason = "exact_execution_policy_rejected"
            if current["usage"] is not None:
                reason = "post_dispatch_policy_rejected"
            self.journal.transition(
                job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.BLOCKED,
                updates={},
                reason=reason,
                updated_at=self._now(),
            )
            return ComputeCycleResult(
                ExecutionStage.BLOCKED.value,
                job_id,
                reason,
                current["usage"] is not None,
                False,
            )
        except ComputeRuntimeRetryable:
            current = self.journal.get(job_id)
            stage = ExecutionStage(current["stage"])
            self.journal.note_retryable(
                job_id,
                stage=stage,
                reason="bounded_dependency_unavailable",
                updated_at=self._now(),
            )
            return ComputeCycleResult(
                stage.value,
                job_id,
                "bounded_dependency_unavailable",
                current["usage"] is not None,
                False,
            )

    def _advance(self, record: Mapping[str, Any]) -> bool:
        intent = ComputeDispatchIntent.from_dict(record["intent"])
        policy = intent.validate_compiled_recipe()
        stage = ExecutionStage(record["stage"])
        now = self._now()

        if stage == ExecutionStage.INTENT_CREATED:
            # This is a startup/release capability, not a provider assertion.
            # Refuse before the irreversible startJob boundary unless replaying
            # one dispatch identifier is guaranteed by the compiled adapter.
            if getattr(self.provider, "supports_idempotent_dispatch", False) is not True:
                raise ComputeRuntimePolicyError(
                    "provider lacks exact idempotent dispatch"
                )
            snapshot = self.gateway.snapshot(
                job_id=intent.job_id,
                rate_policy_commitment=intent.rate_policy_commitment,
                tee_identity=self.identity.address,
                compose_hash=intent.compose_hash,
            )
            self._validate_snapshot(intent, snapshot, expected_state=1)
            prepared = self.gateway.prepare_start(
                job_id=intent.job_id,
                compose_hash=intent.compose_hash,
            )
            if prepared.purpose != "start":
                raise ComputeRuntimePolicyError("gateway prepared wrong transaction purpose")
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.START_PREPARED,
                updates={
                    "start_transaction": prepared.to_dict(),
                },
                reason="chain_start_checkpointed",
                updated_at=now,
            )
            return True

        if stage in {ExecutionStage.START_PREPARED, ExecutionStage.START_BROADCAST}:
            prepared = PreparedTransaction.from_dict(record["start_transaction"])
            confirmed = self.gateway.confirmed_snapshot(
                prepared,
                confirmations=self.confirmations,
                job_id=intent.job_id,
                rate_policy_commitment=intent.rate_policy_commitment,
                tee_identity=self.identity.address,
                compose_hash=intent.compose_hash,
            )
            if confirmed is not None:
                self._validate_snapshot(
                    intent,
                    confirmed,
                    expected_state=2,
                    require_fresh=False,
                )
                self.journal.transition(
                    intent.job_id,
                    expected_stage=stage,
                    new_stage=ExecutionStage.START_CONFIRMED,
                    updates={"start_commitment": confirmed.job.start_commitment},
                    reason="chain_start_confirmed",
                    updated_at=now,
                )
                return True
            # The exact signed transaction is persisted before this call. If a
            # node accepted it and then disconnected, recovery checks its known
            # hash before rebroadcasting these identical bytes.
            self.gateway.broadcast(prepared)
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.START_BROADCAST,
                updates={},
                reason="chain_start_broadcast",
                updated_at=now,
            )
            return False

        if stage == ExecutionStage.START_CONFIRMED:
            dispatch_id = _domain_hash(
                DISPATCH_ID_DOMAIN,
                {
                    "job_id": intent.job_id,
                    "start_commitment": record["start_commitment"],
                    "recipe_policy_commitment": policy.commitment,
                },
            )
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.PROVIDER_DISPATCHING,
                updates={"dispatch_id": dispatch_id},
                reason="provider_dispatch_checkpointed",
                updated_at=now,
            )
            return True

        if stage == ExecutionStage.PROVIDER_DISPATCHING:
            if getattr(self.provider, "supports_idempotent_dispatch", False) is not True:
                raise ComputeRuntimePolicyError("provider lacks exact idempotent dispatch")
            usage = self.provider.execute(
                intent,
                policy,
                dispatch_id=record["dispatch_id"],
            )
            if not isinstance(usage, ProviderUsage):
                raise ComputeRuntimePolicyError("provider returned invalid bounded usage")
            usage.validate_for(intent)
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.USAGE_FINALIZED,
                updates={"usage": usage.to_dict()},
                reason="bounded_usage_finalized",
                updated_at=now,
            )
            return True

        if stage == ExecutionStage.USAGE_FINALIZED:
            usage = ProviderUsage.from_dict(record["usage"])
            snapshot = self.gateway.snapshot(
                job_id=intent.job_id,
                rate_policy_commitment=intent.rate_policy_commitment,
                tee_identity=self.identity.address,
                compose_hash=intent.compose_hash,
            )
            self._validate_snapshot(
                intent,
                snapshot,
                expected_state=2,
                expected_start_commitment=record["start_commitment"],
            )
            signed = SignedUsageEnvelope.create(
                intent=intent,
                usage=usage,
                tee_identity=self.identity,
                start_commitment=record["start_commitment"],
                usage_started_at=snapshot.job.started_at,
                block_number=snapshot.block_number,
                block_hash=snapshot.block_hash,
                usage_observed_at=now,
            )
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.METERING_PENDING,
                updates={"signed_usage": signed.to_dict()},
                reason="signed_usage_checkpointed",
                updated_at=now,
            )
            return True

        if stage == ExecutionStage.METERING_PENDING:
            signed = SignedUsageEnvelope.from_dict(record["signed_usage"])
            signed.validate_for(
                intent=intent,
                tee_identity=self.identity.address,
                start_commitment=record["start_commitment"],
                usage_started_at=_timestamp(signed.envelope["usage_started_at"]),
            )
            decision = self.metering.decide(signed)
            self._validate_metering_decision(intent, signed, decision, now=now)
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.METERING_DECIDED,
                updates={"metering_decision": decision.to_dict()},
                reason="metering_decision_checkpointed",
                updated_at=now,
            )
            return True

        if stage == ExecutionStage.METERING_DECIDED:
            signed = SignedUsageEnvelope.from_dict(record["signed_usage"])
            signed.validate_for(
                intent=intent,
                tee_identity=self.identity.address,
                start_commitment=record["start_commitment"],
                usage_started_at=_timestamp(signed.envelope["usage_started_at"]),
            )
            decision = MeteringDecision.from_dict(record["metering_decision"])
            # Rebind the authenticated journal entry before preparing an
            # irreversible settlement. This keeps recovery fail-closed even if
            # a future journal migration accidentally weakens its field-level
            # validation.
            self._validate_metering_decision(intent, signed, decision, now=now)
            snapshot = self.gateway.snapshot(
                job_id=intent.job_id,
                rate_policy_commitment=intent.rate_policy_commitment,
                tee_identity=self.identity.address,
                compose_hash=intent.compose_hash,
                block_number=signed.block_number,
            )
            if snapshot.block_hash != signed.block_hash:
                raise ComputeRuntimePolicyError(
                    "metering pinned block is no longer canonical"
                )
            self._validate_snapshot(
                intent,
                snapshot,
                expected_state=2,
                expected_start_commitment=record["start_commitment"],
            )
            expected_digest = self.gateway.metering_receipt_digest(
                block_number=snapshot.block_number,
                block_hash=snapshot.block_hash,
                job_id=intent.job_id,
                actual_asset_debit=decision.actual_asset_debit,
                billable_compute_units=decision.billable_compute_units,
                usage_started_at=decision.usage_started_at,
                usage_ended_at=decision.usage_ended_at,
                attestation_evidence_hash=decision.attestation_evidence_hash,
                receipt_expiry=decision.receipt_expiry,
            )
            if expected_digest != decision.metering_receipt_digest:
                raise ComputeRuntimePolicyError("metering receipt digest mismatch")
            expected_qvl_digest = self.gateway.metering_qvl_receipt_digest(
                block_number=snapshot.block_number,
                block_hash=snapshot.block_hash,
                job_id=intent.job_id,
                actual_asset_debit=decision.actual_asset_debit,
                billable_compute_units=decision.billable_compute_units,
                usage_started_at=decision.usage_started_at,
                usage_ended_at=decision.usage_ended_at,
                attestation_evidence_hash=decision.attestation_evidence_hash,
                receipt_expiry=decision.receipt_expiry,
            )
            if expected_qvl_digest != decision.metering_qvl_receipt_digest:
                raise ComputeRuntimePolicyError("metering QVL receipt digest mismatch")
            expected_usage_commitment = self.gateway.usage_commitment(
                block_number=snapshot.block_number,
                block_hash=snapshot.block_hash,
                job_id=intent.job_id,
                actual_asset_debit=decision.actual_asset_debit,
                billable_compute_units=decision.billable_compute_units,
                usage_started_at=decision.usage_started_at,
                usage_ended_at=decision.usage_ended_at,
                attestation_evidence_hash=decision.attestation_evidence_hash,
            )
            if expected_usage_commitment != decision.onchain_usage_commitment:
                raise ComputeRuntimePolicyError("onchain usage commitment mismatch")
            if (
                decision.metering_verifier != snapshot.metering_verifier
                or decision.metering_qvl_verifier
                != snapshot.metering_qvl_verifier
                or snapshot.metering_verifier == snapshot.metering_qvl_verifier
                or _recover_raw_digest(
                    decision.metering_receipt_digest,
                    decision.verifier_signature,
                )
                != snapshot.metering_verifier
                or _recover_raw_digest(
                    decision.metering_qvl_receipt_digest,
                    decision.qvl_signature,
                )
                != snapshot.metering_qvl_verifier
            ):
                raise ComputeRuntimePolicyError(
                    "metering verifier or QVL signature mismatch"
                )
            prepared = self.gateway.prepare_settlement(
                job_id=intent.job_id,
                actual_asset_debit=decision.actual_asset_debit,
                compose_hash=intent.compose_hash,
                billable_compute_units=decision.billable_compute_units,
                usage_started_at=decision.usage_started_at,
                usage_ended_at=decision.usage_ended_at,
                attestation_evidence_hash=decision.attestation_evidence_hash,
                receipt_expiry=decision.receipt_expiry,
                verifier_signature=decision.verifier_signature,
                qvl_signature=decision.qvl_signature,
            )
            if prepared.purpose != "settlement":
                raise ComputeRuntimePolicyError("gateway prepared wrong transaction purpose")
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.SETTLEMENT_PREPARED,
                updates={"settlement_transaction": prepared.to_dict()},
                reason="settlement_checkpointed",
                updated_at=now,
            )
            return True

        if stage in {
            ExecutionStage.SETTLEMENT_PREPARED,
            ExecutionStage.SETTLEMENT_BROADCAST,
        }:
            signed = SignedUsageEnvelope.from_dict(record["signed_usage"])
            signed.validate_for(
                intent=intent,
                tee_identity=self.identity.address,
                start_commitment=record["start_commitment"],
                usage_started_at=_timestamp(signed.envelope["usage_started_at"]),
            )
            decision = MeteringDecision.from_dict(record["metering_decision"])
            prepared = PreparedTransaction.from_dict(record["settlement_transaction"])
            confirmed = self.gateway.confirmed_snapshot(
                prepared,
                confirmations=self.confirmations,
                job_id=intent.job_id,
                rate_policy_commitment=intent.rate_policy_commitment,
                tee_identity=self.identity.address,
                compose_hash=intent.compose_hash,
            )
            if confirmed is not None:
                self._validate_snapshot(
                    intent,
                    confirmed,
                    expected_state=3,
                    expected_start_commitment=record["start_commitment"],
                    expected_usage_commitment=decision.onchain_usage_commitment,
                    expected_actual_debit=decision.actual_asset_debit,
                    expected_billable_compute_units=decision.billable_compute_units,
                    expected_usage_ended_at=decision.usage_ended_at,
                    expected_receipt_expiry=decision.receipt_expiry,
                    expected_attestation_evidence_hash=decision.attestation_evidence_hash,
                    require_fresh=False,
                )
                self.journal.transition(
                    intent.job_id,
                    expected_stage=stage,
                    new_stage=ExecutionStage.SETTLED,
                    updates={},
                    reason="settlement_confirmed",
                    updated_at=now,
                )
                return True
            self.gateway.broadcast(prepared)
            self.journal.transition(
                intent.job_id,
                expected_stage=stage,
                new_stage=ExecutionStage.SETTLEMENT_BROADCAST,
                updates={},
                reason="settlement_broadcast",
                updated_at=now,
            )
            return False

        raise ComputeRuntimeStateError("execution stage is not actionable")

    def _validate_snapshot(
        self,
        intent: ComputeDispatchIntent,
        snapshot: VaultSnapshot,
        *,
        expected_state: int,
        expected_start_commitment: str | None = None,
        expected_usage_commitment: str | None = None,
        expected_actual_debit: int | None = None,
        expected_billable_compute_units: int | None = None,
        expected_usage_ended_at: int | None = None,
        expected_receipt_expiry: int | None = None,
        expected_attestation_evidence_hash: str | None = None,
        require_fresh: bool = True,
    ) -> None:
        job = snapshot.job
        _bytes32(snapshot.block_hash, "snapshot block hash", allow_zero=False)
        if (
            snapshot.chain_id != BASE_SEPOLIA_CHAIN_ID
            or snapshot.chain_id != self.gateway.chain_id
            or snapshot.vault_address != self.gateway.vault_address
            or snapshot.vault_runtime_code_hash != self.gateway.runtime_code_hash
            or snapshot.paused
            or not snapshot.developer_fee_frozen
            or not snapshot.asset_additions_frozen
            or not snapshot.rate_policy_additions_frozen
            or not snapshot.compose_policy_frozen
            or not snapshot.tee_identity_additions_frozen
            or not snapshot.metering_binding_frozen
            or snapshot.metering_policy_set_hash != self.metering_policy_set_hash
            or snapshot.allowed_asset_count != 1
            or snapshot.active_rate_policy_count != 2
            or snapshot.approved_compose_count != 1
            or snapshot.approved_tee_identity_count != 1
            or snapshot.pending_developer_fee_activates_at != 0
            or snapshot.pending_asset_count != 0
            or snapshot.pending_rate_policy_count != 0
            or snapshot.pending_compose_count != 0
            or snapshot.pending_tee_identity_count != 0
            or snapshot.pending_metering_verifier != ZERO_ADDRESS
            or snapshot.pending_metering_qvl_verifier != ZERO_ADDRESS
            or snapshot.pending_metering_policy_set_hash != "0x" + "00" * 32
            or snapshot.pending_metering_binding_activates_at != 0
            or not snapshot.compose_approved
            or snapshot.registered_tee_compose_hash != intent.compose_hash
            or not snapshot.rate_policy_active
            or snapshot.rate_policy_asset != intent.asset
            or snapshot.rate_policy_provider == ZERO_ADDRESS
            or not 0 <= snapshot.rate_policy_developer_fee_bps <= 2_000
            or snapshot.metering_verifier == ZERO_ADDRESS
            or snapshot.metering_verifier
            == _address(self.identity.address, allow_zero=False)
            or snapshot.metering_qvl_verifier == ZERO_ADDRESS
            or snapshot.metering_qvl_verifier == snapshot.metering_verifier
            or snapshot.metering_qvl_verifier
            == _address(self.identity.address, allow_zero=False)
            or job.project_id != intent.project_id
            or job.user != intent.user
            or job.asset != intent.asset
            or job.authorization_nonce != intent.authorization_nonce
            or job.max_asset_debit != intent.max_asset_debit
            or job.authorization_expiry != intent.authorization_expiry
            or job.rate_policy_commitment != intent.rate_policy_commitment
            or job.workload_commitment != intent.workload_commitment
            or job.manifest_commitment != intent.manifest_commitment
            or job.dispatch_intent_commitment != intent.commitment
            or job.state != expected_state
        ):
            raise ComputeRuntimePolicyError("pinned vault snapshot does not match exact intent")
        if snapshot.block_timestamp > intent.authorization_expiry:
            raise ComputeRuntimePolicyError("job authorization expired")
        if require_fresh:
            now = self._now()
            if (
                snapshot.block_timestamp < now - self.max_block_age_seconds
                or snapshot.block_timestamp > now + self.max_future_block_skew_seconds
            ):
                raise ComputeRuntimePolicyError("vault snapshot is stale or future-dated")
            if now > intent.authorization_expiry:
                raise ComputeRuntimePolicyError("job authorization expired")
        if expected_state == 1 and (
            job.actual_asset_debit != 0
            or job.started_at != 0
            or job.usage_ended_at != 0
            or job.receipt_expiry != 0
            or job.compose_hash != "0x" + "00" * 32
            or job.start_commitment != "0x" + "00" * 32
            or job.usage_commitment != "0x" + "00" * 32
            or job.attestation_evidence_hash != "0x" + "00" * 32
            or job.billable_compute_units != 0
            or job.tee_identity != ZERO_ADDRESS
        ):
            raise ComputeRuntimePolicyError("authorized job contains execution state")
        if expected_state >= 2 and (
            job.tee_identity != _address(self.identity.address, allow_zero=False)
            or job.compose_hash != intent.compose_hash
            or job.started_at == 0
            or job.start_commitment == "0x" + "00" * 32
            or (
                expected_start_commitment is not None
                and job.start_commitment != expected_start_commitment
            )
        ):
            raise ComputeRuntimePolicyError("started job execution identity mismatch")
        if expected_state == 2 and (
            job.actual_asset_debit != 0
            or job.usage_ended_at != 0
            or job.receipt_expiry != 0
            or job.usage_commitment != "0x" + "00" * 32
            or job.attestation_evidence_hash != "0x" + "00" * 32
            or job.billable_compute_units != 0
        ):
            raise ComputeRuntimePolicyError("started job contains settlement state")
        if expected_state == 3 and (
            job.usage_commitment != expected_usage_commitment
            or job.actual_asset_debit != expected_actual_debit
            or job.billable_compute_units != expected_billable_compute_units
            or job.usage_ended_at != expected_usage_ended_at
            or job.receipt_expiry != expected_receipt_expiry
            or job.attestation_evidence_hash
            != expected_attestation_evidence_hash
        ):
            raise ComputeRuntimePolicyError("settled job receipt mismatch")

    def _validate_metering_decision(
        self,
        intent: ComputeDispatchIntent,
        signed: SignedUsageEnvelope,
        decision: MeteringDecision,
        *,
        now: int,
    ) -> None:
        if (
            decision.chain_id != self.gateway.chain_id
            or decision.vault_address != self.gateway.vault_address
            or decision.pinned_block_number != signed.block_number
            or decision.pinned_block_hash != signed.block_hash
            or decision.policy_set_hash != self.metering_policy_set_hash
            or decision.rate_policy_commitment != intent.rate_policy_commitment
            or decision.workload_commitment != intent.workload_commitment
            or decision.manifest_commitment != intent.manifest_commitment
            or decision.dispatch_intent_commitment != intent.commitment
            or decision.asset != intent.asset
            or decision.job_id != intent.job_id
            or decision.usage_commitment != signed.usage_commitment
            or decision.billable_compute_units <= 0
            or decision.usage_started_at
            != _timestamp(signed.envelope["usage_started_at"])
            or decision.usage_ended_at
            != _timestamp(signed.envelope["usage_observed_at"])
            or decision.usage_ended_at < decision.usage_started_at
            or decision.tee_identity
            != _address(self.identity.address, allow_zero=False)
            or decision.compose_hash != intent.compose_hash
            or decision.actual_asset_debit > intent.max_asset_debit
            or decision.receipt_expiry < now
            or decision.receipt_expiry > now + MAX_METERING_RECEIPT_LIFETIME
            or decision.receipt_expiry > intent.authorization_expiry
            or decision.metering_verifier == decision.metering_qvl_verifier
            or decision.metering_verifier
            == _address(self.identity.address, allow_zero=False)
            or decision.metering_qvl_verifier
            == _address(self.identity.address, allow_zero=False)
        ):
            raise ComputeRuntimePolicyError("metering decision does not match exact job")

    def _now(self) -> int:
        return _timestamp(int(self.clock()))


def compute_execution_integrity_key(settings: Any) -> bytes:
    """Resolve the journal key; explicit values are local-development only."""

    explicit = str(getattr(settings, "compute_dispatch_store_integrity_key", "") or "")
    if explicit:
        if is_dstack_enabled():
            raise ComputeRuntimePolicyError(
                "explicit Compute dispatch integrity keys are local-development only"
            )
        raw = explicit.encode("utf-8")
        if len(raw) < 32:
            raise ComputeRuntimePolicyError("compute dispatch integrity key is too short")
        return hashlib.sha256(b"compute-dispatch-local-v1\0" + raw).digest()
    path = str(
        getattr(
            settings,
            "compute_dispatch_store_integrity_key_path",
            "tinker/compute_dispatch_store_integrity",
        )
    ).strip()
    if not path:
        raise ComputeRuntimePolicyError("compute dispatch integrity key path is missing")
    return derive_storage_key(path)


def _recover_raw_digest(digest: str, signature: str) -> str:
    raw_digest = bytes.fromhex(_bytes32(digest, "receipt digest", allow_zero=False)[2:])
    raw_signature = bytes.fromhex(_signature(signature)[2:])
    r = int.from_bytes(raw_signature[:32], "big")
    s = int.from_bytes(raw_signature[32:64], "big")
    v = raw_signature[64]
    half_order = int(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        16,
    )
    if v not in (27, 28) or r == 0 or s == 0 or s > half_order:
        raise ComputeRuntimePolicyError("metering signature is non-canonical")
    try:
        public_key = keys.Signature(vrs=(v - 27, r, s)).recover_public_key_from_msg_hash(
            raw_digest
        )
    except Exception:
        raise ComputeRuntimePolicyError("metering signature recovery failed") from None
    return public_key.to_checksum_address().lower()


def _bounded_reference(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ComputeRuntimePolicyError(f"{label} is invalid")
    normalized = value.strip()
    if re.fullmatch(r"^0x[0-9a-fA-F]{64}$", normalized):
        lowered = normalized.lower()
        if lowered == "0x" + "00" * 32:
            raise ComputeRuntimePolicyError(f"{label} is invalid")
        return lowered
    if not _REFERENCE.fullmatch(normalized):
        raise ComputeRuntimePolicyError(f"{label} is invalid")
    return normalized


def _workload_id(value: Any) -> str:
    normalized = str(value)
    if not _WORKLOAD_ID.fullmatch(normalized):
        raise ComputeRuntimePolicyError("workload ID is malformed")
    return normalized


def _address(value: Any, *, allow_zero: bool) -> str:
    try:
        normalized = normalize_wallet_address(str(value)).lower()
    except WalletAuthError as exc:
        raise ComputeRuntimePolicyError("Ethereum address is invalid") from exc
    if not _ADDRESS.fullmatch(normalized) or (not allow_zero and normalized == ZERO_ADDRESS):
        raise ComputeRuntimePolicyError("Ethereum address is invalid")
    return normalized


def _bytes32(value: Any, label: str, *, allow_zero: bool) -> str:
    if not isinstance(value, str):
        raise ComputeRuntimePolicyError(f"{label} is invalid")
    normalized = value.lower()
    if not _BYTES32.fullmatch(normalized) or (
        not allow_zero and normalized == "0x" + "00" * 32
    ):
        raise ComputeRuntimePolicyError(f"{label} is invalid")
    return normalized


def _signature(value: Any) -> str:
    if not isinstance(value, str):
        raise ComputeRuntimePolicyError("ECDSA signature is invalid")
    normalized = value.lower()
    if not _SIGNATURE.fullmatch(normalized):
        raise ComputeRuntimePolicyError("ECDSA signature is invalid")
    return normalized


def _canonical_personal_signature(value: Any, *, raw_digest: bool = False) -> str:
    """Validate the low-s 65-byte form shared by both metering signatures."""

    normalized = _signature(value)
    raw = bytes.fromhex(normalized[2:])
    r = int.from_bytes(raw[:32], "big")
    s = int.from_bytes(raw[32:64], "big")
    v = raw[64]
    half_order = int(
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        16,
    )
    if r == 0 or s == 0 or s > half_order or v not in (27, 28):
        kind = "raw digest" if raw_digest else "personal message"
        raise ComputeRuntimePolicyError(f"{kind} signature is non-canonical")
    return normalized


def _tx_hash(value: Any) -> str:
    if not isinstance(value, str) or not _TX_HASH.fullmatch(value.lower()):
        raise ComputeRuntimeStateError("transaction hash is invalid")
    return value.lower()


def _uint256(value: Any, label: str, *, minimum: int = 0) -> int:
    return _integer(value, label, minimum=minimum, maximum=MAX_UINT256)


def _decimal_uint256(value: Any, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(
        r"^(0|[1-9][0-9]{0,77})$", value
    ):
        raise ComputeRuntimePolicyError(f"{label} decimal uint256 is invalid")
    integer = int(value)
    if integer > MAX_UINT256:
        raise ComputeRuntimePolicyError(f"{label} decimal uint256 is invalid")
    return integer


def _counter(value: Any, label: str) -> int:
    return _integer(value, label, minimum=0, maximum=MAX_COUNTER)


def _timestamp(value: Any) -> int:
    return _integer(value, "timestamp", minimum=1, maximum=MAX_TIMESTAMP)


def _integer(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ComputeRuntimePolicyError(f"{label} is outside supported bounds")
    return value


def _ascii_choice(value: Any, choices: set[str], label: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ComputeRuntimePolicyError(f"{label} is unsupported")
    return value


def _label(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or not re.fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$", value)
    ):
        raise ComputeRuntimePolicyError(f"{label} is invalid")
    return value


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
        raise ComputeRuntimeStateError("value is not canonical JSON") from None


def _strict_json_object(raw: bytes) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise ComputeRuntimeStateError("execution journal JSON is invalid") from None
    if not isinstance(value, dict):
        raise ComputeRuntimeStateError("execution journal root is invalid")
    return value


def _domain_hash(domain: bytes, value: Any) -> str:
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(_canonical_json(value))
    return "0x" + digest.hexdigest()


def _usage_commitment(claims: Mapping[str, Any]) -> str:
    return _domain_hash(USAGE_COMMITMENT_DOMAIN, claims)


def _hash_text(domain: str, value: str) -> str:
    return hashlib.sha256(domain.encode("ascii") + b"\0" + value.encode("ascii")).hexdigest()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
