"""Pinned Base Sepolia state/code validation and exact integer metering."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from collections.abc import Callable
from typing import Protocol

from eth_utils import keccak

from .errors import ChainStateRejected, PolicyRejected, UpstreamUnavailable
from .evm import (
    checked_add,
    checked_mul,
    compute_metering_receipt_digest,
    compute_metering_qvl_receipt_digest,
    compute_onchain_usage_commitment,
    decode_call_result,
    encode_call,
    normalize_decoded_address,
    normalize_decoded_bytes32,
)
from .models import AssetRatePolicy, ComputeUsageEnvelope, PinnedBlock, RateEntry, ZERO_ADDRESS, ZERO_BYTES32
from .policy import LoadedPolicySet
from .rpc import LATEST, BlockSnapshot


JOB_OUTPUT_TYPES = (
    "bytes32",
    "address",
    "address",
    "uint256",
    "uint256",
    "uint256",
    "uint64",
    "uint64",
    "uint64",
    "uint64",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
    "bytes32",
    "uint256",
    "address",
    "uint8",
)


class ChainRpc(Protocol):
    async def chain_id(self) -> int: ...

    async def block_by_number(self, number: object) -> BlockSnapshot: ...

    async def block_by_hash(self, block_hash: str) -> BlockSnapshot: ...

    async def get_code(self, address: str, block_hash: str) -> bytes: ...

    async def eth_call(self, address: str, data: str, block_hash: str) -> object: ...


@dataclass(frozen=True)
class ChainJob:
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
class VerifiedMeteringContext:
    project_id: str
    job_id: str
    user: str
    asset: str
    authorization_nonce: int
    max_asset_debit: int
    authorization_expiry: int
    rate_policy_commitment: str
    workload_commitment: str
    manifest_commitment: str
    dispatch_intent_commitment: str
    tee_identity: str
    compose_hash: str
    start_commitment: str
    actual_asset_debit: int
    billable_compute_units: int
    usage_started_at: int
    usage_ended_at: int
    onchain_usage_commitment: str
    attestation_evidence_hash: str
    receipt_expiry: int
    metering_receipt_digest: str
    metering_qvl_receipt_digest: str


def _decode_one(result: object, abi_type: str) -> object:
    return decode_call_result(result, (abi_type,))[0]


def _as_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise UpstreamUnavailable
    return value


def _as_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise UpstreamUnavailable
    return value


def _decode_job(result: object) -> ChainJob:
    values = decode_call_result(result, JOB_OUTPUT_TYPES)
    return ChainJob(
        project_id=normalize_decoded_bytes32(values[0]),
        user=normalize_decoded_address(values[1]),
        asset=normalize_decoded_address(values[2]),
        authorization_nonce=_as_int(values[3]),
        max_asset_debit=_as_int(values[4]),
        actual_asset_debit=_as_int(values[5]),
        authorization_expiry=_as_int(values[6]),
        started_at=_as_int(values[7]),
        usage_ended_at=_as_int(values[8]),
        receipt_expiry=_as_int(values[9]),
        rate_policy_commitment=normalize_decoded_bytes32(values[10]),
        workload_commitment=normalize_decoded_bytes32(values[11]),
        manifest_commitment=normalize_decoded_bytes32(values[12]),
        dispatch_intent_commitment=normalize_decoded_bytes32(values[13]),
        compose_hash=normalize_decoded_bytes32(values[14]),
        start_commitment=normalize_decoded_bytes32(values[15]),
        usage_commitment=normalize_decoded_bytes32(values[16]),
        attestation_evidence_hash=normalize_decoded_bytes32(values[17]),
        billable_compute_units=_as_int(values[18]),
        tee_identity=normalize_decoded_address(values[19]),
        state=_as_int(values[20]),
    )


def _find_rate(asset_policy: AssetRatePolicy, usage: ComputeUsageEnvelope) -> RateEntry:
    for entry in asset_policy.rates:
        if entry.model == usage.model and entry.recipe == usage.recipe:
            return entry
    raise ChainStateRejected


def compute_exact_debit(asset_policy: AssetRatePolicy, usage: ComputeUsageEnvelope) -> int:
    rate = _find_rate(asset_policy, usage)
    counters = (
        int(usage.prefill_tokens),
        int(usage.sample_tokens),
        int(usage.training_tokens),
    )
    maxima = (
        int(asset_policy.limits.max_prefill_tokens),
        int(asset_policy.limits.max_sample_tokens),
        int(asset_policy.limits.max_training_tokens),
    )
    if any(value > maximum for value, maximum in zip(counters, maxima, strict=True)):
        raise ChainStateRejected
    rates = (
        int(rate.prefill_units_per_million),
        int(rate.sample_units_per_million),
        int(rate.training_units_per_million),
    )
    numerator = 0
    for counter, unit_rate in zip(counters, rates, strict=True):
        numerator = checked_add(numerator, checked_mul(counter, unit_rate))
    quotient, remainder = divmod(numerator, 1_000_000)
    debit = checked_add(quotient, 1 if remainder else 0)
    if debit > int(asset_policy.limits.max_total_debit):
        raise ChainStateRejected
    return debit


def compute_billable_units(usage: ComputeUsageEnvelope) -> int:
    total = 0
    for value in (
        int(usage.prefill_tokens),
        int(usage.sample_tokens),
        int(usage.training_tokens),
    ):
        total = checked_add(total, value)
    if total == 0:
        raise ChainStateRejected
    return total


@dataclass
class BaseSepoliaStateVerifier:
    release: LoadedPolicySet
    rpc: ChainRpc
    metering_verifier: str
    metering_qvl_verifier: str
    clock: Callable[[], float] = time.time

    async def verify(
        self,
        *,
        block: PinnedBlock,
        usage: ComputeUsageEnvelope,
        attestation_evidence_hash: str,
        receipt_expiry_cap: int,
    ) -> VerifiedMeteringContext:
        policy = self.release.policy
        now = int(self.clock())
        if (
            attestation_evidence_hash == ZERO_BYTES32
            or not isinstance(receipt_expiry_cap, int)
            or isinstance(receipt_expiry_cap, bool)
            or receipt_expiry_cap < now
            or receipt_expiry_cap > now + 600
        ):
            raise ChainStateRejected
        if not policy.valid_from <= now <= policy.valid_until:
            raise PolicyRejected
        try:
            chain_id, pinned, latest = await asyncio.gather(
                self.rpc.chain_id(),
                self.rpc.block_by_number(block.number),
                self.rpc.block_by_number(LATEST),
            )
        except (PolicyRejected, ChainStateRejected):
            raise
        except Exception as exc:
            raise UpstreamUnavailable from exc
        if chain_id != policy.chain_id or pinned.number != block.number or pinned.hash != block.hash:
            raise ChainStateRejected
        if latest.number < pinned.number:
            raise ChainStateRejected
        confirmations = latest.number - pinned.number + 1
        if confirmations < policy.min_confirmations:
            raise ChainStateRejected
        if pinned.timestamp > now + policy.max_future_skew_seconds:
            raise ChainStateRejected
        if now - pinned.timestamp > policy.max_pinned_block_age_seconds:
            raise ChainStateRejected
        if not policy.valid_from <= pinned.timestamp <= policy.valid_until:
            raise PolicyRejected
        if usage.usage_observed_at > pinned.timestamp + policy.max_future_skew_seconds:
            raise ChainStateRejected
        if pinned.timestamp - usage.usage_observed_at > policy.max_usage_age_seconds:
            raise ChainStateRejected

        vault = policy.vault_address
        block_hash = pinned.hash
        calls = {
            "code": self.rpc.get_code(vault, block_hash),
            "owner": self.rpc.eth_call(vault, encode_call("owner()"), block_hash),
            "developer": self.rpc.eth_call(vault, encode_call("developer()"), block_hash),
            "metering": self.rpc.eth_call(vault, encode_call("meteringVerifier()"), block_hash),
            "metering_qvl": self.rpc.eth_call(
                vault, encode_call("meteringQvlVerifier()"), block_hash
            ),
            "metering_policy_set_hash": self.rpc.eth_call(
                vault, encode_call("meteringPolicySetHash()"), block_hash
            ),
            "metering_binding_frozen": self.rpc.eth_call(
                vault, encode_call("meteringBindingFrozen()"), block_hash
            ),
            "pending_metering_verifier": self.rpc.eth_call(
                vault, encode_call("pendingMeteringVerifier()"), block_hash
            ),
            "pending_metering_qvl_verifier": self.rpc.eth_call(
                vault, encode_call("pendingMeteringQvlVerifier()"), block_hash
            ),
            "pending_metering_policy_set_hash": self.rpc.eth_call(
                vault, encode_call("pendingMeteringPolicySetHash()"), block_hash
            ),
            "pending_metering_binding_activates_at": self.rpc.eth_call(
                vault, encode_call("pendingMeteringBindingActivatesAt()"), block_hash
            ),
            "paused": self.rpc.eth_call(vault, encode_call("paused()"), block_hash),
            "fee": self.rpc.eth_call(vault, encode_call("developerFeeBps()"), block_hash),
            "fee_frozen": self.rpc.eth_call(vault, encode_call("developerFeeFrozen()"), block_hash),
            "rate_frozen": self.rpc.eth_call(vault, encode_call("ratePolicyAdditionsFrozen()"), block_hash),
            "asset_frozen": self.rpc.eth_call(vault, encode_call("assetAdditionsFrozen()"), block_hash),
            "compose_frozen": self.rpc.eth_call(vault, encode_call("composePolicyFrozen()"), block_hash),
            "tee_identity_additions_frozen": self.rpc.eth_call(
                vault, encode_call("teeIdentityAdditionsFrozen()"), block_hash
            ),
            "allowed_asset_count": self.rpc.eth_call(vault, encode_call("allowedAssetCount()"), block_hash),
            "active_rate_policy_count": self.rpc.eth_call(
                vault, encode_call("activeRatePolicyCount()"), block_hash
            ),
            "approved_compose_count": self.rpc.eth_call(
                vault, encode_call("approvedComposeCount()"), block_hash
            ),
            "approved_tee_identity_count": self.rpc.eth_call(
                vault, encode_call("approvedTeeIdentityCount()"), block_hash
            ),
            "pending_asset_count": self.rpc.eth_call(
                vault, encode_call("pendingAssetCount()"), block_hash
            ),
            "pending_rate_policy_count": self.rpc.eth_call(
                vault, encode_call("pendingRatePolicyCount()"), block_hash
            ),
            "pending_compose_count": self.rpc.eth_call(
                vault, encode_call("pendingComposeCount()"), block_hash
            ),
            "pending_tee_identity_count": self.rpc.eth_call(
                vault, encode_call("pendingTeeIdentityCount()"), block_hash
            ),
            "pending_developer_fee_activates_at": self.rpc.eth_call(
                vault, encode_call("pendingDeveloperFeeActivatesAt()"), block_hash
            ),
            "compose_approved": self.rpc.eth_call(
                vault,
                encode_call(
                    "approvedComposeHashes(bytes32)",
                    ("bytes32",),
                    (bytes.fromhex(policy.compose_hash[2:]),),
                ),
                block_hash,
            ),
            "tee_compose": self.rpc.eth_call(
                vault,
                encode_call("teeIdentityComposeHash(address)", ("address",), (policy.tee_identity,)),
                block_hash,
            ),
            "job": self.rpc.eth_call(
                vault,
                encode_call("getJob(bytes32)", ("bytes32",), (bytes.fromhex(usage.job_id[2:]),)),
                block_hash,
            ),
        }
        try:
            keys = tuple(calls)
            values = await asyncio.gather(*(calls[key] for key in keys))
            state = dict(zip(keys, values, strict=True))
        except Exception as exc:
            raise UpstreamUnavailable from exc

        code = state["code"]
        if not isinstance(code, bytes) or not code:
            raise ChainStateRejected
        if "0x" + keccak(code).hex() != policy.vault_runtime_code_hash:
            raise ChainStateRejected
        owner = normalize_decoded_address(_decode_one(state["owner"], "address"))
        developer = normalize_decoded_address(_decode_one(state["developer"], "address"))
        verifier = normalize_decoded_address(_decode_one(state["metering"], "address"))
        qvl_verifier = normalize_decoded_address(
            _decode_one(state["metering_qvl"], "address")
        )
        metering_policy_set_hash = normalize_decoded_bytes32(
            _decode_one(state["metering_policy_set_hash"], "bytes32")
        )
        metering_binding_frozen = _as_bool(
            _decode_one(state["metering_binding_frozen"], "bool")
        )
        pending_metering_verifier = normalize_decoded_address(
            _decode_one(state["pending_metering_verifier"], "address")
        )
        pending_metering_qvl_verifier = normalize_decoded_address(
            _decode_one(state["pending_metering_qvl_verifier"], "address")
        )
        pending_metering_policy_set_hash = normalize_decoded_bytes32(
            _decode_one(state["pending_metering_policy_set_hash"], "bytes32")
        )
        pending_metering_binding_activates_at = _as_int(
            _decode_one(state["pending_metering_binding_activates_at"], "uint64")
        )
        paused = _as_bool(_decode_one(state["paused"], "bool"))
        fee = _as_int(_decode_one(state["fee"], "uint16"))
        fee_frozen = _as_bool(_decode_one(state["fee_frozen"], "bool"))
        rate_frozen = _as_bool(_decode_one(state["rate_frozen"], "bool"))
        asset_frozen = _as_bool(_decode_one(state["asset_frozen"], "bool"))
        compose_frozen = _as_bool(_decode_one(state["compose_frozen"], "bool"))
        tee_identity_additions_frozen = _as_bool(
            _decode_one(state["tee_identity_additions_frozen"], "bool")
        )
        allowed_asset_count = _as_int(_decode_one(state["allowed_asset_count"], "uint256"))
        active_rate_policy_count = _as_int(
            _decode_one(state["active_rate_policy_count"], "uint256")
        )
        approved_compose_count = _as_int(
            _decode_one(state["approved_compose_count"], "uint256")
        )
        approved_tee_identity_count = _as_int(
            _decode_one(state["approved_tee_identity_count"], "uint256")
        )
        pending_asset_count = _as_int(_decode_one(state["pending_asset_count"], "uint256"))
        pending_rate_policy_count = _as_int(
            _decode_one(state["pending_rate_policy_count"], "uint256")
        )
        pending_compose_count = _as_int(_decode_one(state["pending_compose_count"], "uint256"))
        pending_tee_identity_count = _as_int(
            _decode_one(state["pending_tee_identity_count"], "uint256")
        )
        pending_developer_fee_activates_at = _as_int(
            _decode_one(state["pending_developer_fee_activates_at"], "uint64")
        )
        compose_approved = _as_bool(_decode_one(state["compose_approved"], "bool"))
        tee_compose = normalize_decoded_bytes32(_decode_one(state["tee_compose"], "bytes32"))
        if (
            owner != policy.owner
            or developer != policy.developer
            or verifier != self.metering_verifier
            or qvl_verifier != self.metering_qvl_verifier
            or qvl_verifier != policy.metering_qvl_verifier
            or qvl_verifier == verifier
            or metering_policy_set_hash != self.release.policy_set_hash
            or metering_binding_frozen is not policy.metering_binding_frozen
            or pending_metering_verifier != policy.pending_metering_verifier
            or pending_metering_qvl_verifier != policy.pending_metering_qvl_verifier
            or pending_metering_policy_set_hash != policy.pending_metering_policy_set_hash
            or pending_metering_binding_activates_at != policy.pending_metering_binding_activates_at
            or paused is not policy.paused
            or fee != policy.developer_fee_bps
            or fee_frozen is not policy.developer_fee_frozen
            or rate_frozen is not policy.rate_policy_additions_frozen
            or asset_frozen is not policy.asset_additions_frozen
            or compose_frozen is not policy.compose_policy_frozen
            or tee_identity_additions_frozen is not policy.tee_identity_additions_frozen
            or allowed_asset_count != policy.allowed_asset_count
            or active_rate_policy_count != policy.active_rate_policy_count
            or approved_compose_count != policy.approved_compose_count
            or approved_tee_identity_count != policy.approved_tee_identity_count
            or pending_asset_count != policy.pending_asset_count
            or pending_rate_policy_count != policy.pending_rate_policy_count
            or pending_compose_count != policy.pending_compose_count
            or pending_tee_identity_count != policy.pending_tee_identity_count
            or pending_developer_fee_activates_at != policy.pending_developer_fee_activates_at
            or not compose_approved
            or tee_compose != policy.compose_hash
        ):
            raise ChainStateRejected

        job = _decode_job(state["job"])
        asset_policy = policy.select_asset_policy(job.asset, job.rate_policy_commitment)
        if asset_policy is None:
            raise ChainStateRejected
        if (
            job.project_id != usage.project_id
            or job.user != usage.user
            or job.asset != usage.asset
            or job.authorization_nonce != int(usage.authorization_nonce)
            or job.max_asset_debit != int(usage.max_asset_debit)
            or job.actual_asset_debit != 0
            or job.authorization_expiry != usage.authorization_expiry
            or job.rate_policy_commitment != usage.rate_policy_commitment
            or job.workload_commitment != usage.workload_commitment
            or job.manifest_commitment != usage.manifest_commitment
            or job.dispatch_intent_commitment != usage.dispatch_intent_commitment
            or job.compose_hash != usage.compose_hash
            or job.start_commitment != usage.start_commitment
            or job.usage_commitment != ZERO_BYTES32
            or job.attestation_evidence_hash != ZERO_BYTES32
            or job.billable_compute_units != 0
            or job.usage_ended_at != 0
            or job.receipt_expiry != 0
            or job.started_at != usage.usage_started_at
            or job.tee_identity != usage.tee_identity
            or job.state != 2
            or usage.compose_hash != policy.compose_hash
        ):
            raise ChainStateRejected

        asset_calls = {
            "rate": self.rpc.eth_call(
                vault,
                encode_call(
                    "ratePolicies(bytes32)",
                    ("bytes32",),
                    (bytes.fromhex(job.rate_policy_commitment[2:]),),
                ),
                block_hash,
            )
        }
        if job.asset != ZERO_ADDRESS:
            asset_calls["asset_allowed"] = self.rpc.eth_call(
                vault,
                encode_call("allowedAssets(address)", ("address",), (job.asset,)),
                block_hash,
            )
        try:
            asset_keys = tuple(asset_calls)
            asset_values = await asyncio.gather(*(asset_calls[key] for key in asset_keys))
            asset_state = dict(zip(asset_keys, asset_values, strict=True))
        except Exception as exc:
            raise UpstreamUnavailable from exc
        rate_values = decode_call_result(asset_state["rate"], ("address", "address", "uint16", "bool"))
        rate_asset = normalize_decoded_address(rate_values[0])
        rate_provider = normalize_decoded_address(rate_values[1])
        rate_fee = _as_int(rate_values[2])
        rate_active = _as_bool(rate_values[3])
        if (
            rate_asset != asset_policy.asset
            or rate_provider != asset_policy.provider
            or rate_fee != policy.developer_fee_bps
            or not rate_active
        ):
            raise ChainStateRejected
        if job.asset != ZERO_ADDRESS and not _as_bool(_decode_one(asset_state["asset_allowed"], "bool")):
            raise ChainStateRejected

        debit = compute_exact_debit(asset_policy, usage)
        billable_compute_units = compute_billable_units(usage)
        if debit > job.max_asset_debit:
            raise ChainStateRejected
        receipt_expiry = min(
            pinned.timestamp + policy.receipt_ttl_seconds,
            job.authorization_expiry,
            receipt_expiry_cap,
            now + 600,
        )
        if receipt_expiry < now + policy.min_submission_window_seconds:
            raise ChainStateRejected
        exact_fields = dict(
            chain_id=policy.chain_id,
            vault_address=vault,
            project_id=job.project_id,
            job_id=usage.job_id,
            user=job.user,
            asset=job.asset,
            authorization_nonce=job.authorization_nonce,
            max_asset_debit=job.max_asset_debit,
            actual_asset_debit=debit,
            authorization_expiry=job.authorization_expiry,
            rate_policy_commitment=job.rate_policy_commitment,
            workload_commitment=job.workload_commitment,
            manifest_commitment=job.manifest_commitment,
            dispatch_intent_commitment=job.dispatch_intent_commitment,
            tee_identity=job.tee_identity,
            compose_hash=job.compose_hash,
            start_commitment=job.start_commitment,
            billable_compute_units=billable_compute_units,
            usage_started_at=usage.usage_started_at,
            usage_ended_at=usage.usage_observed_at,
            metering_policy_set_hash=self.release.policy_set_hash,
            attestation_evidence_hash=attestation_evidence_hash,
        )
        onchain_usage_commitment = compute_onchain_usage_commitment(**exact_fields)
        digest = compute_metering_receipt_digest(
            **exact_fields,
            usage_commitment=onchain_usage_commitment,
            receipt_expiry=receipt_expiry,
        )
        qvl_digest = compute_metering_qvl_receipt_digest(
            **exact_fields,
            usage_commitment=onchain_usage_commitment,
            receipt_expiry=receipt_expiry,
        )
        common_types = (
            "bytes32", "uint256", "uint256", "uint256", "uint256", "bytes32"
        )
        common_values = (
            bytes.fromhex(usage.job_id[2:]),
            debit,
            billable_compute_units,
            usage.usage_started_at,
            usage.usage_observed_at,
            bytes.fromhex(attestation_evidence_hash[2:]),
        )
        usage_call = encode_call(
            "usageCommitmentFor(bytes32,uint256,uint256,uint256,uint256,bytes32)",
            common_types,
            common_values,
        )
        digest_call = encode_call(
            "meteringReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)",
            common_types + ("uint256",),
            common_values + (receipt_expiry,),
        )
        qvl_digest_call = encode_call(
            "meteringQvlReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)",
            common_types + ("uint256",),
            (
                *common_values,
                receipt_expiry,
            ),
        )
        (
            onchain_usage_result,
            onchain_digest_result,
            onchain_qvl_digest_result,
            final_by_number,
            final_by_hash,
        ) = await asyncio.gather(
            self.rpc.eth_call(vault, usage_call, block_hash),
            self.rpc.eth_call(vault, digest_call, block_hash),
            self.rpc.eth_call(vault, qvl_digest_call, block_hash),
            self.rpc.block_by_number(block.number),
            self.rpc.block_by_hash(block_hash),
        )
        onchain_usage = normalize_decoded_bytes32(
            _decode_one(onchain_usage_result, "bytes32")
        )
        onchain_digest = normalize_decoded_bytes32(_decode_one(onchain_digest_result, "bytes32"))
        onchain_qvl_digest = normalize_decoded_bytes32(
            _decode_one(onchain_qvl_digest_result, "bytes32")
        )
        if (
            onchain_usage != onchain_usage_commitment
            or onchain_digest != digest
            or onchain_qvl_digest != qvl_digest
            or final_by_number != pinned
            or final_by_hash != pinned
        ):
            raise ChainStateRejected
        completed_at = int(self.clock())
        if completed_at < now:
            raise ChainStateRejected
        if not policy.valid_from <= completed_at <= policy.valid_until:
            raise PolicyRejected
        if receipt_expiry < completed_at + policy.min_submission_window_seconds:
            raise ChainStateRejected
        return VerifiedMeteringContext(
            project_id=job.project_id,
            job_id=usage.job_id,
            user=job.user,
            asset=job.asset,
            authorization_nonce=job.authorization_nonce,
            max_asset_debit=job.max_asset_debit,
            authorization_expiry=job.authorization_expiry,
            rate_policy_commitment=job.rate_policy_commitment,
            workload_commitment=job.workload_commitment,
            manifest_commitment=job.manifest_commitment,
            dispatch_intent_commitment=job.dispatch_intent_commitment,
            tee_identity=job.tee_identity,
            compose_hash=job.compose_hash,
            start_commitment=job.start_commitment,
            actual_asset_debit=debit,
            billable_compute_units=billable_compute_units,
            usage_started_at=usage.usage_started_at,
            usage_ended_at=usage.usage_observed_at,
            onchain_usage_commitment=onchain_usage_commitment,
            attestation_evidence_hash=attestation_evidence_hash,
            receipt_expiry=receipt_expiry,
            metering_receipt_digest=digest,
            metering_qvl_receipt_digest=qvl_digest,
        )
