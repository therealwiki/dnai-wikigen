"""dstack-derived, policy-rotating EIP-191 verdict signing."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from typing import Protocol

from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account_secure
from eth_account.messages import encode_defunct
from eth_account.signers.local import LocalAccount
from eth_hash.auto import keccak

from .errors import VerifierUnavailable
from .models import IndependentTdxVerdict


VERDICT_DOMAIN = b"dnai-wikigen/independent-tdx-verdict/v4\x00"
SIGNER_PATH_PREFIX = "dnai-wikigen/attestation-qvl/verdict-signer/v1"
BYTES32_RE = re.compile(r"^0x[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^0x[0-9a-f]{40}$")
QVL_RESULT_AUTHORIZATION_TYPEHASH = keccak(
    b"DiligenceRoomQVLAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,bytes32 attestationEvidenceHash,uint256 authorizationExpiry)"
)
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
COMPUTE_VAULT_NAME_HASH = keccak(b"DNAI Compute Credit Vault")
COMPUTE_VAULT_VERSION_HASH = keccak(b"2")
COMPUTE_METERING_QVL_RECEIPT_TYPEHASH = keccak(
    b"ComputeMeteringQvlReceipt(bytes32 projectId,bytes32 jobId,address user,address asset,uint256 authorizationNonce,uint256 maxAssetDebit,uint256 actualAssetDebit,uint256 authorizationExpiry,bytes32 ratePolicyCommitment,bytes32 workloadCommitment,bytes32 manifestCommitment,bytes32 dispatchIntentCommitment,address teeIdentity,bytes32 composeHash,bytes32 startCommitment,uint256 billableComputeUnits,uint256 usageStartedAt,uint256 usageEndedAt,bytes32 usageCommitment,bytes32 meteringPolicySetHash,bytes32 attestationEvidenceHash,uint256 receiptExpiry)"
)


class VerdictSigner(Protocol):
    address: str
    custody: str

    def sign_digest(self, digest: str) -> str:
        """Sign one bytes32 digest as an Ethereum EIP-191 message."""

    def sign_raw_digest(self, digest: str) -> str:
        """Raw-sign one EIP-712 digest for direct contract recovery."""


def normalize_address(value: str) -> str:
    lowered = value.lower()
    if not re.fullmatch(r"0x[0-9a-f]{40}", lowered):
        raise VerifierUnavailable
    return lowered


def _word_uint(value: int) -> bytes:
    if value < 0 or value >= 2**256:
        raise VerifierUnavailable
    return value.to_bytes(32, "big")


def _word_address(value: str) -> bytes:
    normalized = normalize_address(value)
    return bytes.fromhex(normalized[2:]).rjust(32, b"\x00")


def _word_bytes32(value: str) -> bytes:
    if not BYTES32_RE.fullmatch(value) or int(value[2:], 16) == 0:
        raise VerifierUnavailable
    return bytes.fromhex(value[2:])


def diligence_qvl_result_authorization_digest(
    *,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    tee_identity: str,
    compose_hash: str,
    evaluator_policy_commitment: str,
    result_hash: str,
    attestation_release_policy_hash: str,
    attestation_evidence_hash: str,
    authorization_expiry: int,
) -> str:
    """Exact digest consumed by DiligenceRoom.submitResult's QVL branch."""

    payload = b"".join(
        (
            QVL_RESULT_AUTHORIZATION_TYPEHASH,
            _word_uint(chain_id),
            _word_address(contract_address),
            _word_uint(deal_id),
            _word_address(tee_identity),
            _word_bytes32(compose_hash),
            _word_bytes32(evaluator_policy_commitment),
            _word_bytes32(result_hash),
            _word_bytes32(attestation_release_policy_hash),
            _word_bytes32(attestation_evidence_hash),
            _word_uint(authorization_expiry),
        )
    )
    return "0x" + keccak(payload).hex()


def compute_metering_qvl_authorization_digest(
    *,
    chain_id: int,
    contract_address: str,
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
) -> str:
    """Exact EIP-712 digest consumed by ComputeCreditVault's QVL branch."""

    domain_separator = keccak(
        b"".join(
            (
                EIP712_DOMAIN_TYPEHASH,
                COMPUTE_VAULT_NAME_HASH,
                COMPUTE_VAULT_VERSION_HASH,
                _word_uint(chain_id),
                _word_address(contract_address),
            )
        )
    )
    struct_hash = keccak(
        b"".join(
            (
                COMPUTE_METERING_QVL_RECEIPT_TYPEHASH,
                _word_bytes32(project_id),
                _word_bytes32(job_id),
                _word_address(user),
                _word_address(asset),
                _word_uint(authorization_nonce),
                _word_uint(max_asset_debit),
                _word_uint(actual_asset_debit),
                _word_uint(authorization_expiry),
                _word_bytes32(rate_policy_commitment),
                _word_bytes32(workload_commitment),
                _word_bytes32(manifest_commitment),
                _word_bytes32(dispatch_intent_commitment),
                _word_address(tee_identity),
                _word_bytes32(compose_hash),
                _word_bytes32(start_commitment),
                _word_uint(billable_compute_units),
                _word_uint(usage_started_at),
                _word_uint(usage_ended_at),
                _word_bytes32(usage_commitment),
                _word_bytes32(metering_policy_set_hash),
                _word_bytes32(attestation_evidence_hash),
                _word_uint(receipt_expiry),
            )
        )
    )
    return "0x" + keccak(b"\x19\x01" + domain_separator + struct_hash).hex()


def independent_verdict_digest(verdict: IndependentTdxVerdict | dict[str, object]) -> str:
    payload = (
        verdict.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(verdict, IndependentTdxVerdict)
        else dict(verdict)
    )
    payload.pop("verifier_signature", None)
    expected = {
        "app_id",
        "activation_evidence_lease_expires_at",
        "ceremony_nonce",
        "chain_id",
        "challenge_digest",
        "challenge_expires_at",
        "challenge_id",
        "challenge_issued_at",
        "compose_hash",
        "contract_address",
        "cvm_id",
        "deployment_intent_sha256",
        "domain",
        "expires_at",
        "issued_at",
        "os_image_hash",
        "profile",
        "quote_hash",
        "release_policy_hash",
        "release_authority_sha256",
        "report_data",
        "schema",
        "signer_address",
        "verification_method",
        "verified",
        "verifier_address",
        "measurement_policy_sha256",
    }
    qvl_fields = {
        "qvl_deal_id",
        "qvl_evaluator_policy_commitment",
        "qvl_result_hash",
        "qvl_attestation_evidence_hash",
        "qvl_authorization_expiry",
        "qvl_authorization_digest",
        "qvl_authorization_signature",
    }
    compute_qvl_fields = {
        "qvl_compute_attestation_evidence_hash",
        "qvl_compute_authorization_expiry",
        "qvl_compute_authorization_digest",
        "qvl_compute_authorization_signature",
    }
    supplied_qvl_fields = set(payload).intersection(qvl_fields)
    supplied_compute_qvl_fields = set(payload).intersection(compute_qvl_fields)
    if supplied_qvl_fields and supplied_qvl_fields != qvl_fields:
        raise VerifierUnavailable
    if supplied_compute_qvl_fields and supplied_compute_qvl_fields != compute_qvl_fields:
        raise VerifierUnavailable
    if supplied_qvl_fields and supplied_compute_qvl_fields:
        raise VerifierUnavailable
    if set(payload) != expected | supplied_qvl_fields | supplied_compute_qvl_fields:
        raise VerifierUnavailable
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "0x" + hashlib.sha256(VERDICT_DOMAIN + encoded).hexdigest()


@dataclass(frozen=True)
class DstackVerdictSigner:
    _account: LocalAccount = field(repr=False)
    key_path: str

    custody = "dstack_derived_separate_cvm"

    def __post_init__(self) -> None:
        object.__setattr__(self, "address", normalize_address(self._account.address))

    @classmethod
    def from_policy_hash(cls, policy_hash: str) -> "DstackVerdictSigner":
        if any(
            os.environ.get(name, "").strip()
            for name in ("DSTACK_SIMULATOR_ENDPOINT", "TAPPD_SIMULATOR_ENDPOINT")
        ):
            raise VerifierUnavailable
        if not BYTES32_RE.fullmatch(policy_hash) or int(policy_hash[2:], 16) == 0:
            raise VerifierUnavailable
        key_path = f"{SIGNER_PATH_PREFIX}/{policy_hash[2:]}"
        try:
            client = DstackClient()
            if not client.is_reachable():
                raise VerifierUnavailable
            key_result = client.get_key(key_path, "ethereum-signing")
            account = to_account_secure(key_result)
        except VerifierUnavailable:
            raise
        except Exception as exc:
            raise VerifierUnavailable from exc
        return cls(_account=account, key_path=key_path)

    def sign_digest(self, digest: str) -> str:
        if not BYTES32_RE.fullmatch(digest):
            raise VerifierUnavailable
        try:
            signed = self._account.sign_message(encode_defunct(hexstr=digest))
            signature = "0x" + bytes(signed.signature).hex()
        except Exception as exc:
            raise VerifierUnavailable from exc
        if not re.fullmatch(r"0x[0-9a-f]{130}", signature):
            raise VerifierUnavailable
        return signature

    def sign_raw_digest(self, digest: str) -> str:
        if not BYTES32_RE.fullmatch(digest):
            raise VerifierUnavailable
        try:
            signed = self._account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
            signature = "0x" + bytes(signed.signature).hex()
        except Exception as exc:
            raise VerifierUnavailable from exc
        if not re.fullmatch(r"0x[0-9a-f]{130}", signature):
            raise VerifierUnavailable
        return signature
