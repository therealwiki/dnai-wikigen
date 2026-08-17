"""TEE-held DiligenceRoom result submission.

This module signs ``submitResult`` transactions with an Ethereum key derived
inside dstack. It intentionally has no raw-private-key configuration path.
Tests may inject a signer object, but production construction goes through
``DstackEthereumSigner.from_settings`` and fails closed outside dstack mode.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Protocol

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_utils import to_checksum_address

from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import (
    derive_storage_key,
    get_attestation_details,
    is_dstack_enabled,
)
from tinker_delegate.run_metadata_store import value_band


SECP256K1_N = int(
    "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    16,
)

SUBMIT_RESULT_SELECTOR = keccak(
    b"submitResult(uint256,uint8,uint256,bytes32,uint256,bytes32,uint256,bytes,bytes)"
)[:4]
DEALS_SELECTOR = keccak(b"deals(uint256)")[:4]
COMPOSE_APPROVAL_REQUIRED_SELECTOR = keccak(b"composeApprovalRequired()")[:4]
APPROVED_COMPOSE_HASHES_SELECTOR = keccak(b"approvedComposeHashes(bytes32)")[:4]
FEE_BPS_SELECTOR = keccak(b"feeBps()")[:4]
COMPUTE_SETTLEMENT_POLICY_ENABLED_SELECTOR = keccak(
    b"computeSettlementPolicyEnabled()"
)[:4]
RESULT_VERIFIER_SELECTOR = keccak(b"resultVerifier()")[:4]
ATTESTATION_VERIFIER_SELECTOR = keccak(b"attestationVerifier()")[:4]
ATTESTATION_RELEASE_POLICY_HASH_SELECTOR = keccak(
    b"attestationReleasePolicyHash()"
)[:4]
ATTESTATION_BINDING_FROZEN_SELECTOR = keccak(b"attestationBindingFrozen()")[:4]
RESULT_AUTHORIZATION_TYPEHASH = keccak(
    b"DiligenceRoomResultAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,uint256 authorizationExpiry)"
)
ATTESTATION_AUTHORIZATION_TYPEHASH = keccak(
    b"DiligenceRoomQVLAuthorization(uint256 chainId,address contractAddress,uint256 dealId,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,bytes32 resultHash,bytes32 attestationReleasePolicyHash,bytes32 attestationEvidenceHash,uint256 authorizationExpiry)"
)
PUBLIC_RESULT_TYPEHASH = keccak(
    b"DiligenceRoomPublicResult(uint256 chainId,address contractAddress,uint256 dealId,address seller,address buyer,uint256 reservePrice,uint256 budgetCap,uint256 expiry,bytes32 artifactHash,address teeIdentity,bytes32 composeHash,bytes32 evaluatorPolicyCommitment,uint8 scoreBand,uint256 computeCost)"
)
MAX_RESULT_AUTHORIZATION_TTL_SECONDS = 600
LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT = (
    "0x" + keccak(b"dnai-wikigen/evaluator-policy/legacy-local-only/v1").hex()
)

SCORE_BAND_TO_CONTRACT = {
    "negligible": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "exceptional": 4,
}
CONTRACT_SCORE_BANDS = {
    value: key for key, value in SCORE_BAND_TO_CONTRACT.items()
}


class ChainSubmitterError(ValueError):
    """Raised when result submission cannot proceed safely."""


class SignerUnavailable(ChainSubmitterError):
    """Raised when no TEE-held signer is available."""


class EthereumSigner(Protocol):
    """Minimal signer interface for production dstack and test signers."""

    address: str
    custody: str

    def sign_transaction(self, transaction: dict[str, Any]):
        """Return an eth-account signed transaction object."""


@dataclass(frozen=True)
class DealRead:
    """Public subset of ``DiligenceRoom.deals(dealId)`` used for guardrails."""

    seller: str
    buyer: str
    reserve_price: int
    budget_cap: int
    expiry: int
    state: int
    artifact_hash: str
    tee_identity: str
    score_band: int
    compute_cost: int
    fee: int
    result_hash: str
    result_compose_hash: str = "0x" + "00" * 32
    payment_token: str = "0x" + "00" * 20
    evaluator_policy_commitment: str = LEGACY_LOCAL_EVALUATOR_POLICY_COMMITMENT
    attestation_evidence_hash: str = "0x" + "00" * 32
    result_authorization_expiry: int = 0
    attestation_authorization_expiry: int = 0


@dataclass(frozen=True)
class SubmitResultReceipt:
    """Bounded receipt for a signed result submission."""

    submitted: bool
    tx_hash: str
    deal_id: int
    score_band: str
    score_band_value: int
    compute_cost_band: str
    result_hash: str
    compose_hash: str
    expiry: int
    authorization_expiry: int
    verifier_signature_hash: str
    result_verifier_address: str
    result_authorization_authenticated: bool
    result_authorization_verdict: str
    evaluator_policy_commitment: str
    attestation_release_policy_hash: str
    attestation_evidence_hash: str
    attestation_authorization_expiry: int
    attestation_verifier_signature_hash: str
    attestation_verifier_address: str
    attestation_authorization_authenticated: bool
    attestation_authorization_verdict: str
    signer_address: str
    contract_address: str
    chain_id: int
    nonce: int
    gas_limit: int
    custody: str
    signer_attestation_hash: str
    signer_attestation_report_data: str
    signer_attestation_quote_size: int
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        payload = {
            "submitted": self.submitted,
            "tx_hash": self.tx_hash,
            "deal_id": self.deal_id,
            "score_band": self.score_band,
            "score_band_value": self.score_band_value,
            "compute_cost_band": self.compute_cost_band,
            "result_hash": self.result_hash,
            "compose_hash": self.compose_hash,
            "expiry": self.expiry,
            "authorization_expiry": self.authorization_expiry,
            "verifier_signature_hash": self.verifier_signature_hash,
            "result_verifier_address": self.result_verifier_address,
            "result_authorization_authenticated": self.result_authorization_authenticated,
            "result_authorization_verdict": self.result_authorization_verdict,
            "evaluator_policy_commitment": self.evaluator_policy_commitment,
            "attestation_release_policy_hash": self.attestation_release_policy_hash,
            "attestation_evidence_hash": self.attestation_evidence_hash,
            "attestation_authorization_expiry": self.attestation_authorization_expiry,
            "attestation_verifier_signature_hash": self.attestation_verifier_signature_hash,
            "attestation_verifier_address": self.attestation_verifier_address,
            "attestation_authorization_authenticated": self.attestation_authorization_authenticated,
            "attestation_authorization_verdict": self.attestation_authorization_verdict,
            "signer_address": self.signer_address,
            "contract_address": self.contract_address,
            "chain_id": self.chain_id,
            "nonce": self.nonce,
            "gas_limit": self.gas_limit,
            "custody": self.custody,
            "signer_attestation_hash": self.signer_attestation_hash,
            "signer_attestation_report_data": self.signer_attestation_report_data,
            "signer_attestation_quote_size": self.signer_attestation_quote_size,
            "raw_secret_egress": self.raw_secret_egress,
        }
        return payload


@dataclass(frozen=True)
class PreparedSubmissionAttempt:
    """Public metadata durably journaled before raw transaction broadcast.

    The raw signed transaction is intentionally absent.  Its Keccak hash,
    signer nonce, and canonical bounded-result hash are enough to reconcile an
    ambiguous send without creating a second signing or broadcast path.
    """

    tx_hash: str
    nonce: int
    result_hash: str
    prepared_at: int


class DstackEthereumSigner:
    """Ethereum signer derived from dstack-held key material."""

    custody = "dstack_derived"

    def __init__(self, private_key: bytes):
        self._account = Account.from_key(private_key)
        self.address = self._account.address

    @classmethod
    def from_settings(cls, settings: Settings) -> "DstackEthereumSigner":
        if not is_dstack_enabled():
            raise SignerUnavailable("dstack mode is required for TEE chain signing")
        key_material = derive_storage_key(settings.chain_signer_key_path)
        return cls(derive_ethereum_private_key(key_material, settings.chain_signer_key_path))

    def sign_transaction(self, transaction: dict[str, Any]):
        return self._account.sign_transaction(transaction)


@dataclass(frozen=True)
class SignerAttestationEvidence:
    """Bounded signer attestation evidence for off-chain verification."""

    mode: str
    signer_address: str
    chain_id: int
    contract_address: str
    report_data: str
    quote_report_data: str
    quote_hash: str
    quote_size: int
    compose_hash: str
    app_id: str = ""
    os_image_hash: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "signer_address": normalize_address(self.signer_address),
            "chain_id": self.chain_id,
            "contract_address": normalize_address(self.contract_address),
            "report_data": normalize_bytes32(self.report_data),
            "quote_report_data": normalize_bytes32(self.quote_report_data),
            "quote_hash": normalize_bytes32(self.quote_hash),
            "quote_size": self.quote_size,
            "compose_hash": normalize_bytes32(self.compose_hash),
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "raw_secret_egress": False,
        }


def derive_ethereum_private_key(key_material: bytes, path: str) -> bytes:
    """Map dstack key material to a valid secp256k1 private key."""

    if not key_material:
        raise SignerUnavailable("empty dstack key material")
    seed = hashlib.sha256(
        b"dnai-wikigen/dstack/ethereum-signer/v1" + path.encode() + key_material
    ).digest()
    value = (int.from_bytes(seed, "big") % (SECP256K1_N - 1)) + 1
    return value.to_bytes(32, "big")


def normalize_address(address: str) -> str:
    raw = address.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 40:
        raise ChainSubmitterError("expected 20-byte Ethereum address")
    int(raw, 16)
    return "0x" + raw


def normalize_bytes32(value: str) -> str:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    if len(raw) != 64:
        raise ChainSubmitterError("expected bytes32 hex value")
    int(raw, 16)
    if int(raw, 16) == 0:
        raise ChainSubmitterError("result hash must be non-zero")
    return "0x" + raw


def normalize_optional_bytes32(value: str) -> str:
    if not value:
        raise ChainSubmitterError("compose hash is required for result commitment")
    return normalize_bytes32(value)


def normalize_signature(value: str) -> str:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise ChainSubmitterError("verifier signature must be hex") from exc
    if len(decoded) != 65:
        raise ChainSubmitterError("verifier signature must be 65 bytes")
    return "0x" + raw


def _hex_bytes(value: str, *, field: str) -> bytes:
    raw = value.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise ChainSubmitterError(f"{field} must be hex") from exc
    if not decoded:
        raise ChainSubmitterError(f"{field} must be non-empty")
    return decoded


def _normalize_quote_report_data(value: str, *, expected_report_data: str) -> str:
    """Return the 32-byte binding from a TDX quote report-data field.

    TDX report data is 64 bytes. dstack may expose our 32-byte report binding
    padded with zero bytes, while local bounded receipts keep only the binding.
    """

    raw = _hex_bytes(value, field="quote_report_data")
    expected = bytes.fromhex(normalize_bytes32(expected_report_data)[2:])
    if len(raw) == 32 and raw == expected:
        return "0x" + raw.hex()
    if len(raw) == 64 and raw[:32] == expected and raw[32:] == b"\x00" * 32:
        return "0x" + raw[:32].hex()
    raise ChainSubmitterError("signer quote report data mismatch")


def encode_uint256(value: int) -> bytes:
    if value < 0:
        raise ChainSubmitterError("uint256 value cannot be negative")
    if value >= 2**256:
        # Fail with the module's error, not a raw OverflowError from to_bytes.
        raise ChainSubmitterError("uint256 value exceeds 2**256-1")
    return value.to_bytes(32, "big")


def encode_address_word(address: str) -> bytes:
    return bytes.fromhex(normalize_address(address)[2:]).rjust(32, b"\x00")


def _pad_dynamic(data: bytes) -> bytes:
    padding = (32 - (len(data) % 32)) % 32
    return data + (b"\x00" * padding)


def score_band_to_contract_value(score_band: str | int) -> tuple[int, str]:
    if isinstance(score_band, int):
        if score_band not in CONTRACT_SCORE_BANDS:
            raise ChainSubmitterError("unknown score band value")
        return score_band, CONTRACT_SCORE_BANDS[score_band]
    key = str(score_band).strip().lower()
    if key not in SCORE_BAND_TO_CONTRACT:
        raise ChainSubmitterError("unknown score band")
    return SCORE_BAND_TO_CONTRACT[key], key


def _mul_bps(value: int, bps: int) -> int:
    if value < 0 or bps < 0:
        raise ChainSubmitterError("basis-point inputs cannot be negative")
    quotient, remainder = divmod(value, 10_000)
    return quotient * bps + (remainder * bps) // 10_000


def policy_compute_cost(deal: DealRead, fee_bps: int) -> int:
    """Mirror DiligenceRoom's deterministic public compute tariff exactly."""

    if fee_bps < 0 or fee_bps > 1_000:
        raise ChainSubmitterError("on-chain fee bps is outside the contract bound")
    if deal.reserve_price < 0 or deal.budget_cap < 0:
        raise ChainSubmitterError("deal settlement fields cannot be negative")
    target = deal.budget_cap // 100
    available = max(0, deal.budget_cap - deal.reserve_price)
    denominator = 10_000 + fee_bps
    quotient, remainder = divmod(available, denominator)
    maximum = quotient * 10_000 + (remainder * 10_000) // denominator
    return min(target, maximum)


def canonical_public_result_hash(
    *,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    deal: DealRead,
    compose_hash: str,
    score_band: str | int,
    compute_cost_wei: int,
) -> str:
    """Canonical on-chain result commitment from public, policy-bound fields only."""

    band_value, _ = score_band_to_contract_value(score_band)
    payload = b"".join(
        [
            PUBLIC_RESULT_TYPEHASH,
            encode_uint256(chain_id),
            encode_address_word(contract_address),
            encode_uint256(deal_id),
            encode_address_word(deal.seller),
            encode_address_word(deal.buyer),
            encode_uint256(deal.reserve_price),
            encode_uint256(deal.budget_cap),
            encode_uint256(deal.expiry),
            bytes.fromhex(normalize_bytes32(deal.artifact_hash)[2:]),
            encode_address_word(deal.tee_identity),
            bytes.fromhex(normalize_optional_bytes32(compose_hash)[2:]),
            bytes.fromhex(normalize_bytes32(deal.evaluator_policy_commitment)[2:]),
            encode_uint256(band_value),
            encode_uint256(compute_cost_wei),
        ]
    )
    return "0x" + keccak(payload).hex()


def encode_submit_result_calldata(
    *,
    deal_id: int,
    score_band: str | int,
    compute_cost_wei: int,
    compose_hash: str,
    authorization_expiry: int,
    attestation_evidence_hash: str,
    attestation_authorization_expiry: int,
    verifier_signature: str,
    attestation_verifier_signature: str,
) -> str:
    band_value, _ = score_band_to_contract_value(score_band)
    compose_hash_hex = normalize_optional_bytes32(compose_hash)[2:]
    signature = bytes.fromhex(normalize_signature(verifier_signature)[2:])
    attestation_signature = bytes.fromhex(
        normalize_signature(attestation_verifier_signature)[2:]
    )
    signature_tail = encode_uint256(len(signature)) + _pad_dynamic(signature)
    attestation_signature_tail = (
        encode_uint256(len(attestation_signature))
        + _pad_dynamic(attestation_signature)
    )
    head_size = 9 * 32
    payload = b"".join(
        [
            SUBMIT_RESULT_SELECTOR,
            encode_uint256(deal_id),
            encode_uint256(band_value),
            encode_uint256(compute_cost_wei),
            bytes.fromhex(compose_hash_hex),
            encode_uint256(authorization_expiry),
            bytes.fromhex(normalize_bytes32(attestation_evidence_hash)[2:]),
            encode_uint256(attestation_authorization_expiry),
            encode_uint256(head_size),
            encode_uint256(head_size + len(signature_tail)),
            signature_tail,
            attestation_signature_tail,
        ]
    )
    return "0x" + payload.hex()


def result_authorization_digest(
    *,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    deal: DealRead,
    compose_hash: str,
    score_band: str | int,
    compute_cost_wei: int,
    authorization_expiry: int,
    attestation_release_policy_hash: str,
) -> str:
    band_value, _ = score_band_to_contract_value(score_band)
    result_hash = canonical_public_result_hash(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=band_value,
        compute_cost_wei=compute_cost_wei,
    )
    payload = b"".join(
        [
            RESULT_AUTHORIZATION_TYPEHASH,
            encode_uint256(chain_id),
            encode_address_word(contract_address),
            encode_uint256(deal_id),
            encode_address_word(deal.tee_identity),
            bytes.fromhex(normalize_optional_bytes32(compose_hash)[2:]),
            bytes.fromhex(normalize_bytes32(deal.evaluator_policy_commitment)[2:]),
            bytes.fromhex(normalize_bytes32(result_hash)[2:]),
            bytes.fromhex(normalize_bytes32(attestation_release_policy_hash)[2:]),
            encode_uint256(authorization_expiry),
        ]
    )
    return "0x" + keccak(payload).hex()


def attestation_authorization_digest(
    *,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    deal: DealRead,
    compose_hash: str,
    score_band: str | int,
    compute_cost_wei: int,
    attestation_release_policy_hash: str,
    attestation_evidence_hash: str,
    authorization_expiry: int,
) -> str:
    result_hash = canonical_public_result_hash(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=score_band,
        compute_cost_wei=compute_cost_wei,
    )
    payload = b"".join(
        [
            ATTESTATION_AUTHORIZATION_TYPEHASH,
            encode_uint256(chain_id),
            encode_address_word(contract_address),
            encode_uint256(deal_id),
            encode_address_word(deal.tee_identity),
            bytes.fromhex(normalize_optional_bytes32(compose_hash)[2:]),
            bytes.fromhex(normalize_bytes32(deal.evaluator_policy_commitment)[2:]),
            bytes.fromhex(normalize_bytes32(result_hash)[2:]),
            bytes.fromhex(normalize_bytes32(attestation_release_policy_hash)[2:]),
            bytes.fromhex(normalize_bytes32(attestation_evidence_hash)[2:]),
            encode_uint256(authorization_expiry),
        ]
    )
    return "0x" + keccak(payload).hex()


def eth_signed_message_digest(digest: str) -> str:
    raw = bytes.fromhex(normalize_bytes32(digest)[2:])
    return "0x" + keccak(b"\x19Ethereum Signed Message:\n32" + raw).hex()


def signer_attestation_report_data(
    *,
    signer_address: str,
    chain_id: int,
    contract_address: str,
) -> bytes:
    """Report data binding dstack quote evidence to a result signer context."""

    payload = json.dumps(
        {
            "service": "dnai-wikigen",
            "context": "diligence-room-submit-result",
            "signer_address": normalize_address(signer_address),
            "chain_id": chain_id,
            "contract_address": normalize_address(contract_address),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).digest()


def get_dstack_signer_attestation(
    *,
    signer_address: str,
    chain_id: int,
    contract_address: str,
) -> SignerAttestationEvidence:
    """Fetch quote evidence binding the current CVM to the result signer."""

    if not is_dstack_enabled():
        raise SignerUnavailable("dstack mode is required for signer attestation")
    report_data = signer_attestation_report_data(
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
    )
    details = get_attestation_details(report_data)
    quote = _hex_bytes(str(details.get("quote") or ""), field="quote")
    quote_hash = "0x" + hashlib.sha256(quote).hexdigest()
    expected_report_data = "0x" + report_data.hex()
    quote_report_data = _normalize_quote_report_data(
        str(details.get("quote_report_data") or ""),
        expected_report_data=expected_report_data,
    )
    return SignerAttestationEvidence(
        mode="tdx",
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
        report_data=expected_report_data,
        quote_report_data=quote_report_data,
        quote_hash=quote_hash,
        quote_size=len(quote),
        compose_hash=normalize_bytes32(str(details.get("compose_hash") or "")),
        app_id=str(details.get("app_id") or ""),
        os_image_hash=str(details.get("os_image_hash") or ""),
    )


def verify_signer_attestation_evidence(
    evidence: SignerAttestationEvidence,
    *,
    signer_address: str,
    chain_id: int,
    contract_address: str,
    expected_compose_hash: str = "",
) -> None:
    """Check that a signer-produced evidence envelope is internally consistent.

    This function deliberately does *not* claim Intel TDX verification.  The
    signer is also the evidence producer, so quote presence and matching
    report-data are not an independent cryptographic verdict.  Production
    authorization is enforced separately by an authenticated signature from
    the contract's distinct ``resultVerifier`` identity.
    """

    if evidence.mode != "tdx":
        raise ChainSubmitterError("signer attestation mode must be tdx")
    if normalize_address(evidence.signer_address) != normalize_address(signer_address):
        raise ChainSubmitterError("signer attestation address mismatch")
    if int(evidence.chain_id) != int(chain_id):
        raise ChainSubmitterError("signer attestation chain id mismatch")
    if normalize_address(evidence.contract_address) != normalize_address(contract_address):
        raise ChainSubmitterError("signer attestation contract mismatch")
    expected_report_data = "0x" + signer_attestation_report_data(
        signer_address=signer_address,
        chain_id=chain_id,
        contract_address=contract_address,
    ).hex()
    if normalize_bytes32(evidence.report_data) != expected_report_data:
        raise ChainSubmitterError("signer attestation report data mismatch")
    if normalize_bytes32(evidence.quote_report_data) != expected_report_data:
        raise ChainSubmitterError("signer quote report data mismatch")
    if (
        expected_compose_hash
        and normalize_bytes32(evidence.compose_hash) != normalize_bytes32(expected_compose_hash)
    ):
        raise ChainSubmitterError("signer attestation compose hash mismatch")
    if evidence.quote_size <= 0:
        raise ChainSubmitterError("signer attestation quote is missing")


def encode_deals_calldata(deal_id: int) -> str:
    return "0x" + (DEALS_SELECTOR + encode_uint256(deal_id)).hex()


def encode_fee_bps_calldata() -> str:
    return "0x" + FEE_BPS_SELECTOR.hex()


def encode_result_verifier_calldata() -> str:
    return "0x" + RESULT_VERIFIER_SELECTOR.hex()


def encode_attestation_verifier_calldata() -> str:
    return "0x" + ATTESTATION_VERIFIER_SELECTOR.hex()


def encode_attestation_release_policy_hash_calldata() -> str:
    return "0x" + ATTESTATION_RELEASE_POLICY_HASH_SELECTOR.hex()


def encode_attestation_binding_frozen_calldata() -> str:
    return "0x" + ATTESTATION_BINDING_FROZEN_SELECTOR.hex()


def encode_compute_settlement_policy_enabled_calldata() -> str:
    return "0x" + COMPUTE_SETTLEMENT_POLICY_ENABLED_SELECTOR.hex()


def decode_uint256_call_result(raw: str) -> int:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ChainSubmitterError("invalid uint256 response")
    body = raw[2:]
    if len(body) < 64:
        raise ChainSubmitterError("short uint256 response")
    return int(body[:64], 16)


def decode_address_call_result(raw: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ChainSubmitterError("invalid address response")
    body = raw[2:]
    if len(body) < 64:
        raise ChainSubmitterError("short address response")
    word = body[:64]
    if any(char != "0" for char in word[:24]):
        raise ChainSubmitterError("invalid ABI-encoded address response")
    return normalize_address("0x" + word[24:])


def decode_bytes32_call_result(raw: str) -> str:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ChainSubmitterError("invalid bytes32 response")
    body = raw[2:]
    if len(body) < 64:
        raise ChainSubmitterError("short bytes32 response")
    return "0x" + body[:64].lower()


def authenticate_result_authorization(
    *,
    verifier_address: str,
    tee_identity: str,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    deal: DealRead,
    compose_hash: str,
    score_band: str | int,
    compute_cost_wei: int,
    authorization_expiry: int,
    attestation_release_policy_hash: str,
    verifier_signature: str,
    now: int | None = None,
) -> str:
    """Authenticate the exact result authorization against the on-chain verifier.

    This is the production trust boundary. A signer-produced quote envelope is
    never sufficient: the 65-byte authorization must recover to the immutable
    ``resultVerifier`` read from the target contract, and that key must be
    distinct from the deal's TEE signing key.
    """

    checked_at = int(time.time() if now is None else now)
    if authorization_expiry <= checked_at:
        raise ChainSubmitterError("result verifier authorization is expired")
    if authorization_expiry > checked_at + MAX_RESULT_AUTHORIZATION_TTL_SECONDS:
        raise ChainSubmitterError("result verifier authorization lifetime exceeds 10 minutes")
    normalized_verifier = normalize_address(verifier_address)
    normalized_tee = normalize_address(tee_identity)
    if normalized_verifier == "0x" + ("00" * 20):
        raise ChainSubmitterError("on-chain result verifier is not configured")
    if normalized_verifier == normalized_tee:
        raise ChainSubmitterError("result verifier must be independent from teeIdentity")
    if normalize_address(deal.tee_identity) != normalized_tee:
        raise ChainSubmitterError("authorization deal teeIdentity mismatch")

    digest = result_authorization_digest(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=score_band,
        compute_cost_wei=compute_cost_wei,
        authorization_expiry=authorization_expiry,
        attestation_release_policy_hash=attestation_release_policy_hash,
    )
    signature = normalize_signature(verifier_signature)
    signature_bytes = bytes.fromhex(signature[2:])
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:64], "big")
    v = signature_bytes[64]
    if not (1 <= r < SECP256K1_N) or not (1 <= s <= SECP256K1_N // 2):
        raise ChainSubmitterError(
            "result verifier authorization signature is not canonical low-s ECDSA"
        )
    if v not in (27, 28):
        raise ChainSubmitterError("result verifier authorization signature v is invalid")
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr=digest),
            signature=signature_bytes,
        )
    except Exception as exc:
        raise ChainSubmitterError("result verifier authorization signature is invalid") from exc
    if normalize_address(recovered) != normalized_verifier:
        raise ChainSubmitterError(
            "result verifier authorization was not signed by the on-chain verifier"
        )
    return normalized_verifier


def authenticate_attestation_authorization(
    *,
    verifier_address: str,
    result_verifier_address: str,
    tee_identity: str,
    chain_id: int,
    contract_address: str,
    deal_id: int,
    deal: DealRead,
    compose_hash: str,
    score_band: str | int,
    compute_cost_wei: int,
    attestation_release_policy_hash: str,
    attestation_evidence_hash: str,
    authorization_expiry: int,
    verifier_signature: str,
    now: int | None = None,
) -> str:
    """Authenticate the independent QVL authorization required on chain."""

    checked_at = int(time.time() if now is None else now)
    if authorization_expiry <= checked_at:
        raise ChainSubmitterError("attestation verifier authorization is expired")
    if authorization_expiry > checked_at + MAX_RESULT_AUTHORIZATION_TTL_SECONDS:
        raise ChainSubmitterError(
            "attestation verifier authorization lifetime exceeds 10 minutes"
        )
    normalized_verifier = normalize_address(verifier_address)
    normalized_result_verifier = normalize_address(result_verifier_address)
    normalized_tee = normalize_address(tee_identity)
    if normalized_verifier == "0x" + ("00" * 20):
        raise ChainSubmitterError("on-chain attestation verifier is not configured")
    if normalized_verifier in (normalized_result_verifier, normalized_tee):
        raise ChainSubmitterError(
            "attestation verifier must be independent from result verifier and teeIdentity"
        )
    if normalize_address(deal.tee_identity) != normalized_tee:
        raise ChainSubmitterError("attestation authorization deal teeIdentity mismatch")

    digest = attestation_authorization_digest(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=deal_id,
        deal=deal,
        compose_hash=compose_hash,
        score_band=score_band,
        compute_cost_wei=compute_cost_wei,
        attestation_release_policy_hash=attestation_release_policy_hash,
        attestation_evidence_hash=attestation_evidence_hash,
        authorization_expiry=authorization_expiry,
    )
    signature = normalize_signature(verifier_signature)
    signature_bytes = bytes.fromhex(signature[2:])
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:64], "big")
    v = signature_bytes[64]
    if not (1 <= r < SECP256K1_N) or not (1 <= s <= SECP256K1_N // 2):
        raise ChainSubmitterError(
            "attestation verifier authorization signature is not canonical low-s ECDSA"
        )
    if v not in (27, 28):
        raise ChainSubmitterError(
            "attestation verifier authorization signature v is invalid"
        )
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr=digest),
            signature=signature_bytes,
        )
    except Exception as exc:
        raise ChainSubmitterError(
            "attestation verifier authorization signature is invalid"
        ) from exc
    if normalize_address(recovered) != normalized_verifier:
        raise ChainSubmitterError(
            "attestation authorization was not signed by the on-chain verifier"
        )
    return normalized_verifier


def encode_compose_approval_required_calldata() -> str:
    return "0x" + COMPOSE_APPROVAL_REQUIRED_SELECTOR.hex()


def encode_approved_compose_hashes_calldata(compose_hash: str) -> str:
    word = bytes.fromhex(normalize_optional_bytes32(compose_hash)[2:])
    return "0x" + (APPROVED_COMPOSE_HASHES_SELECTOR + word).hex()


def decode_bool_call_result(raw: str) -> bool:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ChainSubmitterError("invalid bool response")
    body = raw[2:]
    if len(body) < 64:
        raise ChainSubmitterError("short bool response")
    return int(body[:64], 16) != 0


def _quantity(value: int) -> str:
    return hex(value)


def _parse_quantity(value: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ChainSubmitterError("JSON-RPC quantity must be hex")
    return int(value, 16)


def _word_to_address(word: str) -> str:
    return "0x" + word[-40:].lower()


def _word_to_bytes32(word: str) -> str:
    return "0x" + word.lower()


def decode_deal_call_result(raw: str) -> DealRead:
    if not isinstance(raw, str) or not raw.startswith("0x"):
        raise ChainSubmitterError("invalid deals() response")
    body = raw[2:]
    words = [body[index:index + 64] for index in range(0, len(body), 64)]
    if len(words) < 18 or any(len(word) != 64 for word in words[:18]):
        raise ChainSubmitterError("short deals() response")
    return DealRead(
        seller=_word_to_address(words[0]),
        buyer=_word_to_address(words[1]),
        reserve_price=int(words[2], 16),
        budget_cap=int(words[3], 16),
        expiry=int(words[4], 16),
        state=int(words[5], 16),
        artifact_hash=_word_to_bytes32(words[6]),
        tee_identity=_word_to_address(words[7]),
        score_band=int(words[8], 16),
        compute_cost=int(words[9], 16),
        fee=int(words[10], 16),
        result_hash=_word_to_bytes32(words[11]),
        result_compose_hash=_word_to_bytes32(words[12]),
        payment_token=_word_to_address(words[13]),
        evaluator_policy_commitment=normalize_bytes32(_word_to_bytes32(words[14])),
        attestation_evidence_hash=_word_to_bytes32(words[15]),
        result_authorization_expiry=int(words[16], 16),
        attestation_authorization_expiry=int(words[17], 16),
    )


def read_deal_from_chain(rpc: Any, contract_address: str, deal_id: int) -> DealRead:
    raw = rpc.eth_call(
        {
            "to": normalize_address(contract_address),
            "data": encode_deals_calldata(deal_id),
        }
    )
    return decode_deal_call_result(raw)


def read_fee_bps_from_chain(rpc: Any, contract_address: str) -> int:
    raw = rpc.eth_call(
        {
            "to": normalize_address(contract_address),
            "data": encode_fee_bps_calldata(),
        }
    )
    value = decode_uint256_call_result(raw)
    if value > 1_000:
        raise ChainSubmitterError("on-chain fee bps exceeds contract maximum")
    return value


def read_compute_settlement_policy_enabled_from_chain(
    rpc: Any,
    contract_address: str,
) -> bool:
    raw = rpc.eth_call(
        {
            "to": normalize_address(contract_address),
            "data": encode_compute_settlement_policy_enabled_calldata(),
        }
    )
    return decode_bool_call_result(raw)


class JsonRpcClient:
    """Small synchronous JSON-RPC client for chain submission."""

    def __init__(self, rpc_url: str, *, timeout: float = 20.0):
        if not rpc_url:
            raise ChainSubmitterError("chain RPC URL is required")
        self.rpc_url = rpc_url
        self._client = httpx.Client(timeout=timeout)
        self._next_id = 1

    def close(self) -> None:
        self._client.close()

    def call(self, method: str, params: list[Any]) -> Any:
        request_id = self._next_id
        self._next_id += 1
        response = self._client.post(
            self.rpc_url,
            json={"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("error"):
            message = payload["error"].get("message", "JSON-RPC error")
            raise ChainSubmitterError(str(message))
        return payload.get("result")

    def chain_id(self) -> int:
        return _parse_quantity(self.call("eth_chainId", []))

    def nonce(self, address: str, block_tag: str = "latest") -> int:
        if block_tag not in {"latest", "pending"}:
            raise ChainSubmitterError("transaction-count block tag is invalid")
        return _parse_quantity(
            self.call("eth_getTransactionCount", [address, block_tag])
        )

    def gas_price(self) -> int:
        return _parse_quantity(self.call("eth_gasPrice", []))

    def estimate_gas(self, tx: dict[str, Any]) -> int:
        return _parse_quantity(self.call("eth_estimateGas", [tx]))

    def eth_call(self, tx: dict[str, Any]) -> str:
        return str(self.call("eth_call", [tx, "latest"]))

    def send_raw_transaction(self, raw_transaction: bytes) -> str:
        return str(self.call("eth_sendRawTransaction", ["0x" + raw_transaction.hex()]))

    def transaction_receipt(self, tx_hash: str) -> dict[str, Any] | None:
        result = self.call("eth_getTransactionReceipt", [normalize_bytes32(tx_hash)])
        if result is None:
            return None
        if not isinstance(result, dict):
            raise ChainSubmitterError("transaction receipt response is invalid")
        return result

    def transaction_by_hash(self, tx_hash: str) -> dict[str, Any] | None:
        result = self.call("eth_getTransactionByHash", [normalize_bytes32(tx_hash)])
        if result is None:
            return None
        if not isinstance(result, dict):
            raise ChainSubmitterError("transaction response is invalid")
        return result


class DiligenceRoomSubmitter:
    """Broadcast bounded evaluation results from a TEE-held signer."""

    def __init__(
        self,
        rpc: JsonRpcClient,
        contract_address: str,
        signer: EthereumSigner,
        *,
        gas_limit: int = 0,
    ):
        self.rpc = rpc
        self.contract_address = normalize_address(contract_address)
        self.signer = signer
        self.gas_limit = gas_limit

    def read_deal(self, deal_id: int) -> DealRead:
        return read_deal_from_chain(self.rpc, self.contract_address, deal_id)

    def read_fee_bps(self) -> int:
        """Read the exact governed fee; fresh-suite submission has no fallback."""

        return read_fee_bps_from_chain(self.rpc, self.contract_address)

    def read_compute_settlement_policy_enabled(self) -> bool:
        return read_compute_settlement_policy_enabled_from_chain(
            self.rpc,
            self.contract_address,
        )

    def read_result_verifier(self) -> str:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_result_verifier_calldata(),
            }
        )
        return decode_address_call_result(raw)

    def read_attestation_verifier(self) -> str:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_attestation_verifier_calldata(),
            }
        )
        return decode_address_call_result(raw)

    def read_attestation_release_policy_hash(self) -> str:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_attestation_release_policy_hash_calldata(),
            }
        )
        return decode_bytes32_call_result(raw)

    def read_attestation_binding_frozen(self) -> bool:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_attestation_binding_frozen_calldata(),
            }
        )
        return decode_bool_call_result(raw)

    def read_compose_approval_required(self) -> bool:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_compose_approval_required_calldata(),
            }
        )
        return decode_bool_call_result(raw)

    def read_compose_hash_approved(self, compose_hash: str) -> bool:
        raw = self.rpc.eth_call(
            {
                "to": self.contract_address,
                "data": encode_approved_compose_hashes_calldata(compose_hash),
            }
        )
        return decode_bool_call_result(raw)

    def submit_result(
        self,
        *,
        deal_id: int,
        score_band: str | int,
        compute_cost_wei: int,
        authorization_expiry: int,
        verifier_signature: str,
        attestation_evidence_hash: str,
        attestation_authorization_expiry: int,
        attestation_verifier_signature: str,
        compose_hash: str = "",
        signer_attestation: SignerAttestationEvidence | None = None,
        before_broadcast: Callable[[PreparedSubmissionAttempt], None] | None = None,
    ) -> SubmitResultReceipt:
        if deal_id < 0:
            raise ChainSubmitterError("deal ID cannot be negative")
        if compute_cost_wei < 0:
            raise ChainSubmitterError("compute cost cannot be negative")
        if authorization_expiry <= 0:
            raise ChainSubmitterError("authorization expiry must be positive")
        if attestation_authorization_expiry <= 0:
            raise ChainSubmitterError("attestation authorization expiry must be positive")

        band_value, band_label = score_band_to_contract_value(score_band)
        normalized_verifier_signature = normalize_signature(verifier_signature)
        normalized_attestation_signature = normalize_signature(
            attestation_verifier_signature
        )
        normalized_attestation_evidence_hash = normalize_bytes32(
            attestation_evidence_hash
        )
        signer_address = normalize_address(self.signer.address)
        deal = self.read_deal(deal_id)
        if deal.state != 1:
            raise ChainSubmitterError("deal is not in Funded state")
        if normalize_address(deal.tee_identity) != signer_address:
            raise ChainSubmitterError("TEE signer does not match deal teeIdentity")
        if not self.read_compute_settlement_policy_enabled():
            raise ChainSubmitterError(
                "on-chain deterministic compute settlement policy is not enabled"
            )
        fee_bps = self.read_fee_bps()
        expected_compute_cost = policy_compute_cost(deal, fee_bps)
        if compute_cost_wei != expected_compute_cost:
            raise ChainSubmitterError(
                "compute cost does not match deterministic on-chain settlement policy"
            )
        fee = _mul_bps(compute_cost_wei, fee_bps)
        if compute_cost_wei + fee > deal.budget_cap:
            raise ChainSubmitterError("compute cost exceeds deal budget cap")

        chain_id = self.rpc.chain_id()
        nonce = self.rpc.nonce(signer_address)
        if signer_attestation is not None:
            verify_signer_attestation_evidence(
                signer_attestation,
                signer_address=signer_address,
                chain_id=chain_id,
                contract_address=self.contract_address,
                expected_compose_hash=compose_hash,
            )
            normalized_compose_hash = normalize_optional_bytes32(signer_attestation.compose_hash)
            if (
                normalize_bytes32(signer_attestation.quote_hash)
                != normalized_attestation_evidence_hash
            ):
                raise ChainSubmitterError(
                    "attestation evidence hash does not match the submitted TDX quote"
                )
        elif compose_hash:
            normalized_compose_hash = normalize_optional_bytes32(compose_hash)
        else:
            raise ChainSubmitterError("signer attestation or compose hash is required")
        # Fail closed against the on-chain compose-approval gate before signing or
        # broadcasting: if DiligenceRoom requires approved measurements and this
        # compose hash is not developer-approved on-chain, the transaction would
        # revert ComposeHashNotApproved — refuse locally instead of spending gas
        # and to keep the bounded receipt honest.
        if self.read_compose_approval_required():
            if not self.read_compose_hash_approved(normalized_compose_hash):
                raise ChainSubmitterError("compose hash is not approved on-chain")
        submission_result_hash = canonical_public_result_hash(
            chain_id=chain_id,
            contract_address=self.contract_address,
            deal_id=deal_id,
            deal=deal,
            compose_hash=normalized_compose_hash,
            score_band=band_value,
            compute_cost_wei=compute_cost_wei,
        )
        if not self.read_attestation_binding_frozen():
            raise ChainSubmitterError("on-chain attestation binding is not frozen")
        result_verifier_address = self.read_result_verifier()
        attestation_verifier_address = self.read_attestation_verifier()
        attestation_release_policy_hash = self.read_attestation_release_policy_hash()
        authenticate_result_authorization(
            verifier_address=result_verifier_address,
            tee_identity=signer_address,
            chain_id=chain_id,
            contract_address=self.contract_address,
            deal_id=deal_id,
            deal=deal,
            compose_hash=normalized_compose_hash,
            score_band=band_value,
            compute_cost_wei=compute_cost_wei,
            authorization_expiry=authorization_expiry,
            attestation_release_policy_hash=attestation_release_policy_hash,
            verifier_signature=normalized_verifier_signature,
        )
        authenticate_attestation_authorization(
            verifier_address=attestation_verifier_address,
            result_verifier_address=result_verifier_address,
            tee_identity=signer_address,
            chain_id=chain_id,
            contract_address=self.contract_address,
            deal_id=deal_id,
            deal=deal,
            compose_hash=normalized_compose_hash,
            score_band=band_value,
            compute_cost_wei=compute_cost_wei,
            attestation_release_policy_hash=attestation_release_policy_hash,
            attestation_evidence_hash=normalized_attestation_evidence_hash,
            authorization_expiry=attestation_authorization_expiry,
            verifier_signature=normalized_attestation_signature,
        )
        result_authorization_authenticated = True
        result_authorization_verdict = (
            "authenticated_onchain_result_verifier_signature"
        )
        attestation_authorization_authenticated = True
        attestation_authorization_verdict = (
            "authenticated_onchain_independent_qvl_signature"
        )
        calldata = encode_submit_result_calldata(
            deal_id=deal_id,
            score_band=band_value,
            compute_cost_wei=compute_cost_wei,
            compose_hash=normalized_compose_hash,
            authorization_expiry=authorization_expiry,
            attestation_evidence_hash=normalized_attestation_evidence_hash,
            attestation_authorization_expiry=attestation_authorization_expiry,
            verifier_signature=normalized_verifier_signature,
            attestation_verifier_signature=normalized_attestation_signature,
        )
        gas_price = self.rpc.gas_price()
        base_tx = {
            "from": signer_address,
            "to": self.contract_address,
            "value": "0x0",
            "data": calldata,
        }
        gas_limit = self.gas_limit or self.rpc.estimate_gas(base_tx)
        tx = {
            "chainId": chain_id,
            "nonce": nonce,
            "gas": gas_limit,
            "gasPrice": gas_price,
            "to": to_checksum_address(self.contract_address),
            "value": 0,
            "data": calldata,
        }
        signed = self.signer.sign_transaction(tx)
        raw = getattr(signed, "raw_transaction", None)
        if raw is None:
            raw = getattr(signed, "rawTransaction", None)
        if raw is None:
            raise ChainSubmitterError("signer did not return a raw transaction")
        raw_bytes = bytes(raw)
        expected_tx_hash = "0x" + keccak(raw_bytes).hex()
        if before_broadcast is not None:
            before_broadcast(
                PreparedSubmissionAttempt(
                    tx_hash=expected_tx_hash,
                    nonce=nonce,
                    result_hash=submission_result_hash,
                    prepared_at=int(time.time()),
                )
            )
        returned_tx_hash = normalize_bytes32(
            self.rpc.send_raw_transaction(raw_bytes)
        )
        if returned_tx_hash != expected_tx_hash:
            raise ChainSubmitterError(
                "JSON-RPC transaction hash does not match signed transaction"
            )
        tx_hash = expected_tx_hash
        return SubmitResultReceipt(
            submitted=True,
            tx_hash=tx_hash,
            deal_id=deal_id,
            score_band=band_label,
            score_band_value=band_value,
            compute_cost_band=value_band(compute_cost_wei),
            result_hash=submission_result_hash,
            compose_hash=normalized_compose_hash,
            expiry=deal.expiry,
            authorization_expiry=authorization_expiry,
            verifier_signature_hash="0x" + hashlib.sha256(
                bytes.fromhex(normalized_verifier_signature[2:])
            ).hexdigest(),
            result_verifier_address=result_verifier_address,
            result_authorization_authenticated=result_authorization_authenticated,
            result_authorization_verdict=result_authorization_verdict,
            evaluator_policy_commitment=normalize_bytes32(
                deal.evaluator_policy_commitment
            ),
            attestation_release_policy_hash=attestation_release_policy_hash,
            attestation_evidence_hash=normalized_attestation_evidence_hash,
            attestation_authorization_expiry=attestation_authorization_expiry,
            attestation_verifier_signature_hash="0x"
            + hashlib.sha256(
                bytes.fromhex(normalized_attestation_signature[2:])
            ).hexdigest(),
            attestation_verifier_address=attestation_verifier_address,
            attestation_authorization_authenticated=attestation_authorization_authenticated,
            attestation_authorization_verdict=attestation_authorization_verdict,
            signer_address=signer_address,
            contract_address=self.contract_address,
            chain_id=chain_id,
            nonce=nonce,
            gas_limit=gas_limit,
            custody=getattr(self.signer, "custody", "unknown"),
            signer_attestation_hash=(
                signer_attestation.quote_hash if signer_attestation is not None else ""
            ),
            signer_attestation_report_data=(
                signer_attestation.report_data if signer_attestation is not None else ""
            ),
            signer_attestation_quote_size=(
                signer_attestation.quote_size if signer_attestation is not None else 0
            ),
        )


def build_dstack_submitter(settings: Settings, *, rpc_url: str = "", contract_address: str = "") -> DiligenceRoomSubmitter:
    """Build the production submitter from dstack-held key material."""

    signer = DstackEthereumSigner.from_settings(settings)
    rpc = JsonRpcClient(rpc_url or settings.chain_rpc_url)
    return DiligenceRoomSubmitter(
        rpc,
        contract_address or settings.chain_contract_address,
        signer,
        gas_limit=settings.chain_submit_gas_limit,
    )
