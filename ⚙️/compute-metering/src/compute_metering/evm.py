"""Minimal ABI and ComputeCreditVault EIP-712 primitives."""

from __future__ import annotations

import re
from typing import Sequence

from eth_abi import decode, encode
from eth_utils import keccak

from .errors import ChainStateRejected, UpstreamUnavailable
from .models import UINT256_MAX


DOMAIN_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
METERING_RECEIPT_TYPE = (
    "ComputeMeteringReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,"
    "uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,"
    "uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,"
    "bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,"
    "bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,"
    "uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,"
    "bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
)
METERING_QVL_RECEIPT_TYPE = METERING_RECEIPT_TYPE.replace(
    "ComputeMeteringReceipt", "ComputeMeteringQvlReceipt", 1
)
USAGE_COMMITMENT_TYPE = (
    "ComputeMeteredUsage(uint256 chainId,address verifyingContract,bytes32 projectId,"
    "bytes32 jobId,address user,address asset,uint256 authorizationNonce,"
    "uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,"
    "bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,"
    "bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,"
    "bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,"
    "uint256 usageEndedAt,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash)"
)
DOMAIN_TYPEHASH = keccak(text=DOMAIN_TYPE)
NAME_HASH = keccak(text="DNAI Compute Credit Vault")
VERSION_HASH = keccak(text="2")
METERING_RECEIPT_TYPEHASH = keccak(text=METERING_RECEIPT_TYPE)
METERING_QVL_RECEIPT_TYPEHASH = keccak(text=METERING_QVL_RECEIPT_TYPE)
USAGE_COMMITMENT_TYPEHASH = keccak(text=USAGE_COMMITMENT_TYPE)
QUANTITY_RE = re.compile(r"^0x(?:0|[1-9a-f][0-9a-f]*)$")
DATA_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")


def selector(signature: str) -> bytes:
    return keccak(text=signature)[:4]


def encode_call(signature: str, input_types: Sequence[str] = (), values: Sequence[object] = ()) -> str:
    if len(input_types) != len(values):
        raise ValueError("ABI input arity mismatch")
    return "0x" + (selector(signature) + encode(list(input_types), list(values))).hex()


def decode_call_result(result: object, output_types: Sequence[str]) -> tuple[object, ...]:
    if not isinstance(result, str) or len(result) > 32_768 or not DATA_RE.fullmatch(result):
        raise UpstreamUnavailable
    raw = bytes.fromhex(result[2:])
    try:
        values = decode(list(output_types), raw, strict=True)
        if encode(list(output_types), list(values)) != raw:
            raise UpstreamUnavailable
        return tuple(values)
    except UpstreamUnavailable:
        raise
    except Exception as exc:
        raise UpstreamUnavailable from exc


def decode_quantity(value: object) -> int:
    if not isinstance(value, str) or not QUANTITY_RE.fullmatch(value):
        raise UpstreamUnavailable
    result = int(value, 16)
    if result > UINT256_MAX:
        raise UpstreamUnavailable
    return result


def normalize_decoded_address(value: object) -> str:
    if not isinstance(value, str):
        raise UpstreamUnavailable
    lowered = value.lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", lowered):
        raise UpstreamUnavailable
    return lowered


def normalize_decoded_bytes32(value: object) -> str:
    if not isinstance(value, bytes) or len(value) != 32:
        raise UpstreamUnavailable
    return "0x" + value.hex()


def checked_mul(left: int, right: int) -> int:
    if not 0 <= left <= UINT256_MAX or not 0 <= right <= UINT256_MAX:
        raise ChainStateRejected
    if left and right > UINT256_MAX // left:
        raise ChainStateRejected
    return left * right


def checked_add(left: int, right: int) -> int:
    if not 0 <= left <= UINT256_MAX or not 0 <= right <= UINT256_MAX:
        raise ChainStateRejected
    if right > UINT256_MAX - left:
        raise ChainStateRejected
    return left + right


def compute_metering_receipt_digest(
    *,
    chain_id: int,
    vault_address: str,
    project_id: str,
    job_id: str,
    user: str,
    asset: str,
    authorization_nonce: int,
    max_asset_debit: int,
    actual_asset_debit: int,
    authorization_expiry: int,
    rate_policy_commitment: str,
    workload_commitment: str,
    manifest_commitment: str,
    dispatch_intent_commitment: str,
    tee_identity: str,
    compose_hash: str,
    start_commitment: str,
    billable_compute_units: int,
    usage_started_at: int,
    usage_ended_at: int,
    usage_commitment: str,
    metering_policy_set_hash: str,
    attestation_evidence_hash: str,
    receipt_expiry: int,
    receipt_typehash: bytes = METERING_RECEIPT_TYPEHASH,
) -> str:
    try:
        domain_separator = keccak(
            encode(
                ["bytes32", "bytes32", "bytes32", "uint256", "address"],
                [DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, chain_id, vault_address],
            )
        )
        struct_hash = keccak(
            encode(
                [
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "address",
                    "address",
                    "uint256",
                    "uint256",
                    "uint256",
                    "uint256",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "address",
                    "bytes32",
                    "bytes32",
                    "uint256",
                    "uint256",
                    "uint256",
                    "bytes32",
                    "bytes32",
                    "bytes32",
                    "uint256",
                ],
                [
                    receipt_typehash,
                    bytes.fromhex(project_id[2:]),
                    bytes.fromhex(job_id[2:]),
                    user,
                    asset,
                    authorization_nonce,
                    max_asset_debit,
                    actual_asset_debit,
                    authorization_expiry,
                    bytes.fromhex(rate_policy_commitment[2:]),
                    bytes.fromhex(workload_commitment[2:]),
                    bytes.fromhex(manifest_commitment[2:]),
                    bytes.fromhex(dispatch_intent_commitment[2:]),
                    tee_identity,
                    bytes.fromhex(compose_hash[2:]),
                    bytes.fromhex(start_commitment[2:]),
                    billable_compute_units,
                    usage_started_at,
                    usage_ended_at,
                    bytes.fromhex(usage_commitment[2:]),
                    bytes.fromhex(metering_policy_set_hash[2:]),
                    bytes.fromhex(attestation_evidence_hash[2:]),
                    receipt_expiry,
                ],
            )
        )
        return "0x" + keccak(b"\x19\x01" + domain_separator + struct_hash).hex()
    except Exception as exc:
        raise ChainStateRejected from exc


def compute_metering_qvl_receipt_digest(**fields: object) -> str:
    return compute_metering_receipt_digest(
        **fields,
        receipt_typehash=METERING_QVL_RECEIPT_TYPEHASH,
    )


def compute_onchain_usage_commitment(
    *,
    chain_id: int,
    vault_address: str,
    project_id: str,
    job_id: str,
    user: str,
    asset: str,
    authorization_nonce: int,
    max_asset_debit: int,
    actual_asset_debit: int,
    authorization_expiry: int,
    rate_policy_commitment: str,
    workload_commitment: str,
    manifest_commitment: str,
    dispatch_intent_commitment: str,
    tee_identity: str,
    compose_hash: str,
    start_commitment: str,
    billable_compute_units: int,
    usage_started_at: int,
    usage_ended_at: int,
    metering_policy_set_hash: str,
    attestation_evidence_hash: str,
) -> str:
    try:
        types = [
            "bytes32", "uint256", "address", "bytes32", "bytes32", "address",
            "address", "uint256", "uint256", "uint256", "uint256", "bytes32",
            "bytes32", "bytes32", "bytes32", "address", "bytes32", "bytes32",
            "uint256", "uint256", "uint256", "bytes32", "bytes32",
        ]
        values = [
            USAGE_COMMITMENT_TYPEHASH,
            chain_id,
            vault_address,
            bytes.fromhex(project_id[2:]),
            bytes.fromhex(job_id[2:]),
            user,
            asset,
            authorization_nonce,
            max_asset_debit,
            actual_asset_debit,
            authorization_expiry,
            bytes.fromhex(rate_policy_commitment[2:]),
            bytes.fromhex(workload_commitment[2:]),
            bytes.fromhex(manifest_commitment[2:]),
            bytes.fromhex(dispatch_intent_commitment[2:]),
            tee_identity,
            bytes.fromhex(compose_hash[2:]),
            bytes.fromhex(start_commitment[2:]),
            billable_compute_units,
            usage_started_at,
            usage_ended_at,
            bytes.fromhex(metering_policy_set_hash[2:]),
            bytes.fromhex(attestation_evidence_hash[2:]),
        ]
        return "0x" + keccak(encode(types, values)).hex()
    except Exception as exc:
        raise ChainStateRejected from exc
