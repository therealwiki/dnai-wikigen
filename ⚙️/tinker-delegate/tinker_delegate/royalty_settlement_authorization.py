"""Purpose-separated RoyaltyDistributor v3 settlement authorization core.

This module owns only deterministic policy and EIP-712 construction.  It does
not call a provider, write an on-chain anchor, fund a distribution, broadcast a
transaction, or claim a finalized receipt/withdrawal.  The HTTPS/QVL transport
lives in :mod:`tinker_delegate.royalty_qvl_client`.

The ordering matters: the fresh TDX quote hash participates in the bounded
attestation evidence commitment, which participates in the settlement decision
and both contract signatures.  A main-runtime signature therefore cannot be
issued before the fresh quote has been collected.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence

from eth_account import Account
from eth_hash.auto import keccak

from tinker_delegate import dstack_utils
from tinker_delegate.chain_submitter import derive_ethereum_private_key
from tinker_delegate.royalty_distribution_plan import (
    SETTLE_RESERVED_FUNCTION,
    SETTLE_RESERVED_SELECTOR,
    DistributionRecipient,
    RoyaltyDistributionPlan,
    SettlementAuthorization,
    build_royalty_distribution_plan,
)


BASE_SEPOLIA_CHAIN_ID = 84_532
ROYALTY_SETTLEMENT_SIGNER_KEY_PATH = (
    "tinker/collaboration_royalty_settlement_signer"
)
ROYALTY_SETTLEMENT_SIGNER_CUSTODY = (
    "dstack_derived_main_runtime_royalty_settlement_signer"
)
ROYALTY_AUTHORIZATION_REQUEST_SCHEMA = (
    "dnai.royalty-settlement-qvl-authorization-request.v2"
)
ROYALTY_PLAN_SCHEMA = "dnai.royalty-settlement-authorization-plan.v2"
ROYALTY_BINDING_KIND = "royalty_settlement_qvl_v2"
MAX_AUTHORIZATION_LIFETIME_SECONDS = 600

ROYALTY_SETTLEMENT_POLICY_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-qvl-policy/v2\x00"
)
ROYALTY_SETTLEMENT_REPORT_DATA_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-signer-attestation/v1\x00"
)
ROYALTY_SETTLEMENT_EVIDENCE_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-attestation-evidence/v1\x00"
)
ROYALTY_SETTLEMENT_ANCHOR_EVIDENCE_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-anchor-evidence/v2\x00"
)
ROYALTY_SETTLEMENT_SCOPE_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-plan-scope/v2\x00"
)
ROYALTY_SETTLEMENT_PLAN_DOMAIN = (
    b"dnai-wikigen/royalty-settlement-plan/v2\x00"
)

_ADDRESS = re.compile(r"^0x[0-9a-f]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-f]{64}$")
_SHA256 = re.compile(r"^sha256:(?!0{64}$)[0-9a-f]{64}$")
_APP_ID = re.compile(r"^(?!0{40}$)[0-9a-f]{40}$")
_BARE_SHA256 = re.compile(r"^(?!0{64}$)[0-9a-f]{64}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_SIGNATURE = re.compile(r"^0x[0-9a-f]{130}$")

SECP256K1_HALF_ORDER = (
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
)
EIP712_DOMAIN_TYPEHASH = keccak(
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
)
ROYALTY_DISTRIBUTOR_NAME_HASH = keccak(b"DNAI Royalty Distributor")
ROYALTY_DISTRIBUTOR_VERSION_HASH = keccak(b"3")
ROYALTY_RELEASE_POLICY_TYPEHASH = keccak(
    b"RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)"
)
ROYALTY_COLLABORATION_RESOURCE_TYPEHASH = keccak(
    b"RoyaltyCollaborationResource(uint256 chainId,address distributor,bytes32 roomCommitment,bytes32 queryCommitment)"
)
ROYALTY_SETTLEMENT_DECISION_TYPEHASH = keccak(
    b"RoyaltySettlementDecision(uint256 chainId,address distributor,bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,uint256 expiry)"
)
ROYALTY_SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH = keccak(
    b"RoyaltySettlementQvlAuthorization(bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,bytes32 anchorDecisionHash,uint256 anchorSequence,uint256 expiry)"
)
ROYALTY_SETTLEMENT_AUTHORIZATION_TYPEHASH = keccak(
    b"RoyaltySettlementAuthorization(bytes32 settlementId,uint256 settlementNonce,bytes32 fundingReservationId,bytes32 releasePolicyCommitment,bytes32 roomCommitment,bytes32 roomStateCommitment,bytes32 queryCommitment,bytes32 grantSetCommitment,bytes32 allocationCommitment,bytes32 ownersAmountsHash,address asset,uint256 total,bytes32 executionCommitment,bytes32 resultCommitment,bytes32 usageCommitment,bytes32 attestationEvidenceHash,bytes32 anchorResourceHash,bytes32 anchorDecisionHash,uint256 anchorSequence,uint256 expiry)"
)


class RoyaltySettlementAuthorizationError(ValueError):
    """Fail-closed malformed or policy-drifted settlement authorization."""


class RoyaltySettlementSignerUnavailable(RuntimeError):
    """The production dstack-only settlement signer cannot be used."""


class RoyaltySettlementReplayConflict(RoyaltySettlementAuthorizationError):
    """One settlement scope was rebound to a different signed plan."""


class RoyaltySettlementSigner(Protocol):
    address: str
    key_path: str
    custody: str

    def sign_raw_digest(self, digest: str) -> str:
        """Raw-sign one EIP-712 digest for direct contract recovery."""


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except Exception:
        raise RoyaltySettlementAuthorizationError(
            "royalty settlement value is not canonical JSON"
        ) from None


def _canonical_commitment(domain: bytes, payload: Mapping[str, Any]) -> str:
    return "0x" + hashlib.sha256(domain + _canonical_json(dict(payload))).hexdigest()


def _address(value: Any, *, field_name: str, allow_zero: bool = False) -> str:
    if not isinstance(value, str):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be an address")
    result = value.strip().lower()
    if not _ADDRESS.fullmatch(result) or (
        not allow_zero and int(result[2:], 16) == 0
    ):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be a valid address")
    return result


def _bytes32(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be bytes32")
    result = value.strip().lower()
    if not _BYTES32.fullmatch(result) or int(result[2:], 16) == 0:
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be nonzero bytes32")
    return result


def _sha256(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be sha256")
    result = value.strip().lower()
    if not _SHA256.fullmatch(result):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be nonzero sha256")
    return result


def _uint256(
    value: Any,
    *,
    field_name: str,
    positive: bool = False,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be uint256")
    if value < (1 if positive else 0) or value >= 2**256:
        raise RoyaltySettlementAuthorizationError(f"{field_name} is outside uint256")
    return value


def _signature(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be a signature")
    result = value.strip().lower()
    if not _SIGNATURE.fullmatch(result):
        raise RoyaltySettlementAuthorizationError(f"{field_name} must be 65-byte hex")
    encoded = bytes.fromhex(result[2:])
    r = int.from_bytes(encoded[:32], "big")
    s = int.from_bytes(encoded[32:64], "big")
    if r == 0 or s == 0 or s > SECP256K1_HALF_ORDER or encoded[64] not in (27, 28):
        raise RoyaltySettlementAuthorizationError(
            f"{field_name} must be canonical low-s Ethereum signature"
        )
    return result


def _word_uint(value: int) -> bytes:
    return _uint256(value, field_name="uint256 word").to_bytes(32, "big")


def _word_address(value: str, *, allow_zero: bool = False) -> bytes:
    return bytes.fromhex(
        _address(value, field_name="address word", allow_zero=allow_zero)[2:]
    ).rjust(32, b"\x00")


def _word_bytes32(value: str) -> bytes:
    return bytes.fromhex(_bytes32(value, field_name="bytes32 word")[2:])


@dataclass(frozen=True)
class RoyaltySettlementReleaseBinding:
    """Complete reviewed main-runtime and Diligence-QVL royalty policy."""

    distributor_address: str
    distributor_runtime_code_hash: str
    owner_address: str
    authority_nonce: int
    settlement_verifier_address: str
    royalty_qvl_verifier_address: str
    execution_policy_anchor_address: str
    anchor_writer_release_commitment: str
    release_policy_commitment: str
    royalty_qvl_policy_commitment: str
    royalty_qvl_signer_key_id: str
    qvl_release_policy_hash: str
    main_runtime_cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    measurement_policy_sha256: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    chain_id: int = BASE_SEPOLIA_CHAIN_ID
    max_authorization_lifetime_seconds: int = MAX_AUTHORIZATION_LIFETIME_SECONDS

    def __post_init__(self) -> None:
        normalized: dict[str, Any] = {
            "distributor_address": _address(
                self.distributor_address, field_name="distributor address"
            ),
            "distributor_runtime_code_hash": _bytes32(
                self.distributor_runtime_code_hash,
                field_name="distributor runtime code hash",
            ),
            "owner_address": _address(
                self.owner_address,
                field_name="RoyaltyDistributor owner address",
            ),
            "authority_nonce": _uint256(
                self.authority_nonce, field_name="authority nonce", positive=True
            ),
            "settlement_verifier_address": _address(
                self.settlement_verifier_address,
                field_name="settlement verifier address",
            ),
            "royalty_qvl_verifier_address": _address(
                self.royalty_qvl_verifier_address,
                field_name="royalty QVL verifier address",
            ),
            "execution_policy_anchor_address": _address(
                self.execution_policy_anchor_address,
                field_name="execution policy anchor address",
            ),
            "anchor_writer_release_commitment": _bytes32(
                self.anchor_writer_release_commitment,
                field_name="anchor writer release commitment",
            ),
            "release_policy_commitment": _bytes32(
                self.release_policy_commitment,
                field_name="release policy commitment",
            ),
            "royalty_qvl_policy_commitment": _bytes32(
                self.royalty_qvl_policy_commitment,
                field_name="royalty QVL policy commitment",
            ),
            "royalty_qvl_signer_key_id": _bytes32(
                self.royalty_qvl_signer_key_id,
                field_name="royalty QVL signer key ID",
            ),
            "qvl_release_policy_hash": _bytes32(
                self.qvl_release_policy_hash,
                field_name="QVL release policy hash",
            ),
            "deployment_intent_sha256": _sha256(
                self.deployment_intent_sha256,
                field_name="deployment intent sha256",
            ),
            "release_authority_sha256": _sha256(
                self.release_authority_sha256,
                field_name="release authority sha256",
            ),
            "ceremony_nonce": _bytes32(
                self.ceremony_nonce,
                field_name="release ceremony nonce",
            ),
            "measurement_policy_sha256": _sha256(
                self.measurement_policy_sha256,
                field_name="measurement policy sha256",
            ),
            "compose_hash": _bytes32(self.compose_hash, field_name="compose hash"),
        }
        if self.chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise RoyaltySettlementAuthorizationError(
                "royalty settlement release must target Base Sepolia"
            )
        if self.max_authorization_lifetime_seconds != MAX_AUTHORIZATION_LIFETIME_SECONDS:
            raise RoyaltySettlementAuthorizationError(
                "royalty settlement authorization lifetime policy drifted"
            )
        if not isinstance(self.main_runtime_cvm_id, str) or not _CVM_ID.fullmatch(
            self.main_runtime_cvm_id
        ):
            raise RoyaltySettlementAuthorizationError("main runtime CVM ID is invalid")
        app_id = str(self.app_id).strip().lower()
        os_image_hash = str(self.os_image_hash).strip().lower()
        if not _APP_ID.fullmatch(app_id):
            raise RoyaltySettlementAuthorizationError("Phala app ID is invalid")
        if not _BARE_SHA256.fullmatch(os_image_hash):
            raise RoyaltySettlementAuthorizationError("OS image hash is invalid")
        normalized["app_id"] = app_id
        normalized["os_image_hash"] = os_image_hash
        for name, value in normalized.items():
            object.__setattr__(self, name, value)

        roles = (
            self.distributor_address,
            self.owner_address,
            self.settlement_verifier_address,
            self.royalty_qvl_verifier_address,
            self.execution_policy_anchor_address,
        )
        if len(set(roles)) != len(roles):
            raise RoyaltySettlementAuthorizationError(
                "royalty settlement release roles must be distinct"
            )
        computed_release = royalty_release_policy_commitment(self)
        if computed_release != self.release_policy_commitment:
            raise RoyaltySettlementAuthorizationError(
                "royalty release policy commitment does not match its fields"
            )
        computed_qvl_policy = derive_royalty_qvl_policy_commitment(self)
        if computed_qvl_policy != self.royalty_qvl_policy_commitment:
            raise RoyaltySettlementAuthorizationError(
                "royalty QVL policy commitment does not match its fields"
            )

    def qvl_binding_dict(self) -> dict[str, Any]:
        """Exact JSON shape committed by the Diligence QVL release policy."""

        return {
            "kind": ROYALTY_BINDING_KIND,
            "distributor_address": self.distributor_address,
            "distributor_runtime_code_hash": self.distributor_runtime_code_hash,
            "owner": self.owner_address,
            "settlement_verifier": self.settlement_verifier_address,
            "settlement_verifier_key_path": ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
            "settlement_verifier_custody": ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
            "execution_policy_anchor": self.execution_policy_anchor_address,
            "anchor_writer_release_commitment": (
                self.anchor_writer_release_commitment
            ),
            "release_policy_commitment": self.release_policy_commitment,
            "authority_nonce": str(self.authority_nonce),
            "qvl_signer_key_id": self.royalty_qvl_signer_key_id,
            "main_runtime_cvm_id": self.main_runtime_cvm_id,
            "deployment_intent_sha256": self.deployment_intent_sha256,
            "release_authority_sha256": self.release_authority_sha256,
            "measurement_policy_sha256": self.measurement_policy_sha256,
            "max_authorization_lifetime_seconds": (
                self.max_authorization_lifetime_seconds
            ),
        }


@dataclass(frozen=True)
class RoyaltySettlementIntent:
    """Credential-free source fields for one settlement authorization."""

    settlement_id: str
    settlement_nonce: int
    royalty_reservation_id: str
    room_commitment: str
    room_state_commitment: str
    query_commitment: str
    grant_set_commitment: str
    allocation_commitment: str
    owners_amounts_hash: str
    asset_address: str
    total: int
    execution_commitment: str
    result_commitment: str
    usage_commitment: str
    anchor_sequence: int
    expiry: int

    def __post_init__(self) -> None:
        bytes32_fields = (
            "settlement_id",
            "royalty_reservation_id",
            "room_commitment",
            "room_state_commitment",
            "query_commitment",
            "grant_set_commitment",
            "allocation_commitment",
            "owners_amounts_hash",
            "execution_commitment",
            "result_commitment",
            "usage_commitment",
        )
        for name in bytes32_fields:
            object.__setattr__(
                self,
                name,
                _bytes32(getattr(self, name), field_name=name.replace("_", " ")),
            )
        object.__setattr__(
            self,
            "asset_address",
            _address(self.asset_address, field_name="asset", allow_zero=True),
        )
        for name in ("settlement_nonce", "total", "anchor_sequence"):
            object.__setattr__(
                self,
                name,
                _uint256(getattr(self, name), field_name=name.replace("_", " "), positive=True),
            )
        expiry = _uint256(self.expiry, field_name="expiry", positive=True)
        if expiry > 4_102_444_800:
            raise RoyaltySettlementAuthorizationError("expiry is outside the supported epoch")
        object.__setattr__(self, "expiry", expiry)


@dataclass(frozen=True)
class RoyaltySettlementAuthorizationPacket:
    """Strict QVL request packet containing all 20 contract fields."""

    authorization: SettlementAuthorization
    settlement_authorization_digest: str
    settlement_authorization_signature: str
    settlement_verifier_address: str
    settlement_verifier_key_path: str = ROYALTY_SETTLEMENT_SIGNER_KEY_PATH
    settlement_verifier_custody: str = ROYALTY_SETTLEMENT_SIGNER_CUSTODY

    def __post_init__(self) -> None:
        digest = _bytes32(
            self.settlement_authorization_digest,
            field_name="settlement authorization digest",
        )
        signature = _signature(
            self.settlement_authorization_signature,
            field_name="settlement authorization signature",
        )
        address = _address(
            self.settlement_verifier_address,
            field_name="settlement verifier address",
        )
        if self.settlement_verifier_key_path != ROYALTY_SETTLEMENT_SIGNER_KEY_PATH:
            raise RoyaltySettlementAuthorizationError(
                "settlement signer key path is not purpose separated"
            )
        if self.settlement_verifier_custody != ROYALTY_SETTLEMENT_SIGNER_CUSTODY:
            raise RoyaltySettlementAuthorizationError(
                "settlement signer custody is not production dstack"
            )
        object.__setattr__(self, "settlement_authorization_digest", digest)
        object.__setattr__(self, "settlement_authorization_signature", signature)
        object.__setattr__(self, "settlement_verifier_address", address)

    def to_qvl_dict(self) -> dict[str, Any]:
        authorization = self.authorization
        return {
            "schema": ROYALTY_AUTHORIZATION_REQUEST_SCHEMA,
            "settlement_id": authorization.settlement_id,
            "settlement_nonce": str(authorization.settlement_nonce),
            "funding_reservation_id": authorization.funding_reservation_id,
            "release_policy_commitment": authorization.release_policy_commitment,
            "room_commitment": authorization.room_commitment,
            "room_state_commitment": authorization.room_state_commitment,
            "query_commitment": authorization.query_commitment,
            "grant_set_commitment": authorization.grant_set_commitment,
            "allocation_commitment": authorization.allocation_commitment,
            "owners_amounts_hash": authorization.owners_amounts_hash,
            "asset": authorization.asset_address,
            "total": str(authorization.total),
            "execution_commitment": authorization.execution_commitment,
            "result_commitment": authorization.result_commitment,
            "usage_commitment": authorization.usage_commitment,
            "attestation_evidence_hash": authorization.attestation_evidence_hash,
            "anchor_resource_hash": authorization.anchor_resource_hash,
            "anchor_decision_hash": authorization.anchor_decision_hash,
            "anchor_sequence": str(authorization.anchor_sequence),
            "expiry": authorization.expiry,
            "settlement_authorization_digest": (
                self.settlement_authorization_digest
            ),
            "settlement_authorization_signature": (
                self.settlement_authorization_signature
            ),
        }


@dataclass(frozen=True)
class AuthorizedRoyaltySettlementPlan:
    """Dual-authorized, idempotency-bindable plan with no chain side effects."""

    chain_id: int
    distributor_address: str
    authorization: SettlementAuthorization
    settlement_verifier_address: str
    settlement_authorization_digest: str
    settlement_authorization_signature: str
    qvl_verifier_address: str
    qvl_policy_commitment: str
    qvl_authorization_digest: str
    qvl_authorization_signature: str
    qvl_anchor_evidence_commitment: str
    qvl_verdict_verifier_address: str
    qvl_verdict_digest: str
    qvl_release_policy_hash: str
    quote_hash: str
    report_data: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    authorization_expires_at: int
    settlement_scope: str = field(init=False)
    plan_commitment: str = field(init=False)

    def __post_init__(self) -> None:
        if self.chain_id != BASE_SEPOLIA_CHAIN_ID:
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan must target Base Sepolia"
            )
        distributor = _address(
            self.distributor_address,
            field_name="authorized plan distributor",
        )
        settlement_verifier = _address(
            self.settlement_verifier_address,
            field_name="authorized plan settlement verifier",
        )
        qvl_verifier = _address(
            self.qvl_verifier_address,
            field_name="authorized plan QVL verifier",
        )
        verdict_verifier = _address(
            self.qvl_verdict_verifier_address,
            field_name="authorized plan verdict verifier",
        )
        if len({distributor, settlement_verifier, qvl_verifier, verdict_verifier}) != 4:
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan roles must be distinct"
            )
        normalized_bytes32 = {
            "settlement_authorization_digest": _bytes32(
                self.settlement_authorization_digest,
                field_name="settlement authorization digest",
            ),
            "qvl_policy_commitment": _bytes32(
                self.qvl_policy_commitment,
                field_name="QVL policy commitment",
            ),
            "qvl_authorization_digest": _bytes32(
                self.qvl_authorization_digest,
                field_name="QVL authorization digest",
            ),
            "qvl_anchor_evidence_commitment": _bytes32(
                self.qvl_anchor_evidence_commitment,
                field_name="QVL anchor evidence commitment",
            ),
            "qvl_verdict_digest": _bytes32(
                self.qvl_verdict_digest,
                field_name="QVL verdict digest",
            ),
            "qvl_release_policy_hash": _bytes32(
                self.qvl_release_policy_hash,
                field_name="QVL release policy hash",
            ),
            "quote_hash": _bytes32(self.quote_hash, field_name="quote hash"),
            "report_data": _bytes32(self.report_data, field_name="report data"),
            "compose_hash": _bytes32(self.compose_hash, field_name="compose hash"),
        }
        main_signature = _signature(
            self.settlement_authorization_signature,
            field_name="settlement authorization signature",
        )
        qvl_signature = _signature(
            self.qvl_authorization_signature,
            field_name="QVL authorization signature",
        )
        app_id = str(self.app_id).strip().lower()
        os_image_hash = str(self.os_image_hash).strip().lower()
        if not _APP_ID.fullmatch(app_id) or not _BARE_SHA256.fullmatch(os_image_hash):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan release identity is invalid"
            )
        if self.authorization_expires_at != self.authorization.expiry:
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan expiry does not match authorization"
            )
        expected_resource = royalty_collaboration_resource_hash(
            chain_id=self.chain_id,
            distributor_address=distributor,
            room_commitment=self.authorization.room_commitment,
            query_commitment=self.authorization.query_commitment,
        )
        expected_decision = royalty_settlement_decision_hash(
            chain_id=self.chain_id,
            distributor_address=distributor,
            authorization=self.authorization,
        )
        expected_main_digest = royalty_settlement_authorization_digest(
            chain_id=self.chain_id,
            distributor_address=distributor,
            authorization=self.authorization,
        )
        expected_qvl_digest = royalty_settlement_qvl_authorization_digest(
            chain_id=self.chain_id,
            distributor_address=distributor,
            authorization=self.authorization,
        )
        if (
            self.authorization.anchor_resource_hash != expected_resource
            or self.authorization.anchor_decision_hash != expected_decision
            or normalized_bytes32["settlement_authorization_digest"]
            != expected_main_digest
            or normalized_bytes32["qvl_authorization_digest"]
            != expected_qvl_digest
            or recover_raw_digest_address(
                digest=expected_main_digest,
                signature=main_signature,
            )
            != settlement_verifier
            or recover_raw_digest_address(
                digest=expected_qvl_digest,
                signature=qvl_signature,
            )
            != qvl_verifier
        ):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan signature or anchor binding is invalid"
            )
        object.__setattr__(self, "distributor_address", distributor)
        object.__setattr__(self, "settlement_verifier_address", settlement_verifier)
        object.__setattr__(self, "qvl_verifier_address", qvl_verifier)
        object.__setattr__(self, "qvl_verdict_verifier_address", verdict_verifier)
        object.__setattr__(self, "settlement_authorization_signature", main_signature)
        object.__setattr__(self, "qvl_authorization_signature", qvl_signature)
        object.__setattr__(self, "app_id", app_id)
        object.__setattr__(self, "os_image_hash", os_image_hash)
        for name, value in normalized_bytes32.items():
            object.__setattr__(self, name, value)
        payload = self._commitment_payload()
        object.__setattr__(
            self,
            "settlement_scope",
            _canonical_commitment(
                ROYALTY_SETTLEMENT_SCOPE_DOMAIN,
                {
                    "schema": "dnai.royalty-settlement-plan-scope.v2",
                    "chain_id": self.chain_id,
                    "distributor_address": self.distributor_address,
                    "settlement_id": self.authorization.settlement_id,
                    "settlement_nonce": self.authorization.settlement_nonce,
                    "funding_reservation_id": (
                        self.authorization.funding_reservation_id
                    ),
                    "release_policy_commitment": (
                        self.authorization.release_policy_commitment
                    ),
                },
            ),
        )
        object.__setattr__(
            self,
            "plan_commitment",
            _canonical_commitment(ROYALTY_SETTLEMENT_PLAN_DOMAIN, payload),
        )

    def _authorization_dict(self) -> dict[str, Any]:
        return {
            "settlement_id": self.authorization.settlement_id,
            "settlement_nonce": self.authorization.settlement_nonce,
            "funding_reservation_id": self.authorization.funding_reservation_id,
            "release_policy_commitment": self.authorization.release_policy_commitment,
            "room_commitment": self.authorization.room_commitment,
            "room_state_commitment": self.authorization.room_state_commitment,
            "query_commitment": self.authorization.query_commitment,
            "grant_set_commitment": self.authorization.grant_set_commitment,
            "allocation_commitment": self.authorization.allocation_commitment,
            "owners_amounts_hash": self.authorization.owners_amounts_hash,
            "asset_address": self.authorization.asset_address,
            "total": self.authorization.total,
            "execution_commitment": self.authorization.execution_commitment,
            "result_commitment": self.authorization.result_commitment,
            "usage_commitment": self.authorization.usage_commitment,
            "attestation_evidence_hash": self.authorization.attestation_evidence_hash,
            "anchor_resource_hash": self.authorization.anchor_resource_hash,
            "anchor_decision_hash": self.authorization.anchor_decision_hash,
            "anchor_sequence": self.authorization.anchor_sequence,
            "expiry": self.authorization.expiry,
        }

    def _commitment_payload(self) -> dict[str, Any]:
        return {
            "schema": ROYALTY_PLAN_SCHEMA,
            "chain_id": self.chain_id,
            "distributor_address": self.distributor_address,
            "authorization": self._authorization_dict(),
            "settlement_verifier_address": self.settlement_verifier_address,
            "settlement_authorization_digest": self.settlement_authorization_digest,
            "settlement_authorization_signature": (
                self.settlement_authorization_signature
            ),
            "qvl_verifier_address": self.qvl_verifier_address,
            "qvl_policy_commitment": self.qvl_policy_commitment,
            "qvl_authorization_digest": self.qvl_authorization_digest,
            "qvl_authorization_signature": self.qvl_authorization_signature,
            "qvl_anchor_evidence_commitment": self.qvl_anchor_evidence_commitment,
            "qvl_verdict_verifier_address": self.qvl_verdict_verifier_address,
            "qvl_verdict_digest": self.qvl_verdict_digest,
            "qvl_release_policy_hash": self.qvl_release_policy_hash,
            "quote_hash": self.quote_hash,
            "report_data": self.report_data,
            "compose_hash": self.compose_hash,
            "app_id": self.app_id,
            "os_image_hash": self.os_image_hash,
            "authorization_expires_at": self.authorization_expires_at,
        }

    def to_public_dict(self) -> dict[str, Any]:
        payload = self._commitment_payload()
        payload.update(
            {
                "settlement_scope": self.settlement_scope,
                "plan_commitment": self.plan_commitment,
                "status": "dual_authorized_not_broadcast",
                "independent_qvl_tdx_verified": True,
                "anchor_hashes_recomputed": True,
                "anchor_finality_evidence_supplied": False,
                "claim_funding_performed": False,
                "funding_evidence_supplied": False,
                "contract_broadcast_performed": False,
                "finalized_chain_receipt_supplied": False,
                "withdrawal_performed": False,
                "requires_exact_plan_persistence_for_replay": True,
                "durable_replay_protection_claimed": False,
                "raw_quote_egress": False,
                "raw_artifact_egress": False,
                "provider_credential_egress": False,
                "raw_secret_egress": False,
            }
        )
        return payload

    @classmethod
    def from_public_dict(
        cls,
        payload: Mapping[str, Any],
    ) -> "AuthorizedRoyaltySettlementPlan":
        """Strictly restore one persisted dual-authorized plan.

        The parser reconstructs every digest/signature binding and then demands
        byte-for-byte canonical JSON equivalence with ``to_public_dict``. This
        rejects missing fields, extra fields, stale schemas, truth-status drift,
        and forged scope/plan commitments instead of silently normalizing them.
        """

        if not isinstance(payload, Mapping):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan must be a JSON object"
            )
        serialized = dict(payload)
        authorization_payload = serialized.get("authorization")
        if not isinstance(authorization_payload, Mapping):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan authorization must be a JSON object"
            )
        try:
            authorization = SettlementAuthorization(**dict(authorization_payload))
            restored = cls(
                chain_id=serialized["chain_id"],
                distributor_address=serialized["distributor_address"],
                authorization=authorization,
                settlement_verifier_address=serialized[
                    "settlement_verifier_address"
                ],
                settlement_authorization_digest=serialized[
                    "settlement_authorization_digest"
                ],
                settlement_authorization_signature=serialized[
                    "settlement_authorization_signature"
                ],
                qvl_verifier_address=serialized["qvl_verifier_address"],
                qvl_policy_commitment=serialized["qvl_policy_commitment"],
                qvl_authorization_digest=serialized["qvl_authorization_digest"],
                qvl_authorization_signature=serialized[
                    "qvl_authorization_signature"
                ],
                qvl_anchor_evidence_commitment=serialized[
                    "qvl_anchor_evidence_commitment"
                ],
                qvl_verdict_verifier_address=serialized[
                    "qvl_verdict_verifier_address"
                ],
                qvl_verdict_digest=serialized["qvl_verdict_digest"],
                qvl_release_policy_hash=serialized["qvl_release_policy_hash"],
                quote_hash=serialized["quote_hash"],
                report_data=serialized["report_data"],
                compose_hash=serialized["compose_hash"],
                app_id=serialized["app_id"],
                os_image_hash=serialized["os_image_hash"],
                authorization_expires_at=serialized[
                    "authorization_expires_at"
                ],
            )
        except (KeyError, TypeError):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan serialization is incomplete"
            ) from None
        if _canonical_json(serialized) != _canonical_json(restored.to_public_dict()):
            raise RoyaltySettlementAuthorizationError(
                "authorized royalty plan serialization drifted"
            )
        return restored

    def build_settle_reserved_broadcast_plan(
        self,
        *,
        recipients: Sequence[DistributionRecipient],
        keystore_account: str = "dev",
        rpc_url_placeholder: str = "$BASE_SEPOLIA_RPC_URL",
    ) -> RoyaltyDistributionPlan:
        """Encode only the exact prefunded ``settleReserved`` transaction."""

        plan = build_royalty_distribution_plan(
            contract_address=self.distributor_address,
            authorization=self.authorization,
            recipients=recipients,
            settlement_signature=self.settlement_authorization_signature,
            qvl_signature=self.qvl_authorization_signature,
            keystore_account=keystore_account,
            rpc_url_placeholder=rpc_url_placeholder,
        )
        try:
            selector = bytes.fromhex(plan.calldata[2:10])
        except (TypeError, ValueError):
            raise RoyaltySettlementAuthorizationError(
                "reserved settlement calldata is malformed"
            ) from None
        if (
            not plan.prefunded
            or plan.function != SETTLE_RESERVED_FUNCTION
            or selector != SETTLE_RESERVED_SELECTOR
            or plan.funding_reservation_id
            != self.authorization.funding_reservation_id
            or "--value" in plan.cast_command
        ):
            raise RoyaltySettlementAuthorizationError(
                "authorized plan did not encode exact settleReserved calldata"
            )
        return plan

    def require_unexpired(self, *, now: int) -> None:
        if isinstance(now, bool) or not isinstance(now, int) or now < 1:
            raise RoyaltySettlementAuthorizationError("current time is invalid")
        if self.authorization_expires_at <= now:
            raise RoyaltySettlementAuthorizationError(
                "royalty settlement authorization plan is expired"
            )


class RoyaltySettlementReplayBinder:
    """In-memory exact-replay conflict detector, not a durable-store claim.

    API integration must persist ``settlement_scope -> plan_commitment`` before
    returning a plan.  This helper captures the required semantics for tests and
    adapters: an exact replay is accepted; any drift under the same settlement
    ID/nonce scope is rejected.
    """

    def __init__(self) -> None:
        self._plans: dict[str, str] = {}

    def bind(self, plan: AuthorizedRoyaltySettlementPlan) -> bool:
        existing = self._plans.get(plan.settlement_scope)
        if existing is None:
            self._plans[plan.settlement_scope] = plan.plan_commitment
            return False
        if existing != plan.plan_commitment:
            raise RoyaltySettlementReplayConflict(
                "royalty settlement scope already binds a different plan"
            )
        return True


@dataclass(frozen=True)
class DstackRoyaltySettlementSigner:
    """Raw EIP-712 signer derived only from production dstack key custody."""

    _account: Any = field(repr=False)
    key_path: str = ROYALTY_SETTLEMENT_SIGNER_KEY_PATH
    custody: str = ROYALTY_SETTLEMENT_SIGNER_CUSTODY
    address: str = field(init=False)

    def __post_init__(self) -> None:
        if self.key_path != ROYALTY_SETTLEMENT_SIGNER_KEY_PATH:
            raise RoyaltySettlementSignerUnavailable
        if self.custody != ROYALTY_SETTLEMENT_SIGNER_CUSTODY:
            raise RoyaltySettlementSignerUnavailable
        try:
            object.__setattr__(
                self,
                "address",
                _address(self._account.address, field_name="settlement verifier"),
            )
        except Exception:
            raise RoyaltySettlementSignerUnavailable from None

    @classmethod
    def from_dstack(cls) -> "DstackRoyaltySettlementSigner":
        if (
            not dstack_utils.is_dstack_enabled()
            or dstack_utils.is_dstack_simulator()
        ):
            raise RoyaltySettlementSignerUnavailable(
                "production dstack is required for royalty settlement signing"
            )
        try:
            material = dstack_utils.derive_storage_key(
                ROYALTY_SETTLEMENT_SIGNER_KEY_PATH
            )
            private_key = derive_ethereum_private_key(
                material,
                ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
            )
            return cls(_account=Account.from_key(private_key))
        except RoyaltySettlementSignerUnavailable:
            raise
        except Exception:
            raise RoyaltySettlementSignerUnavailable(
                "royalty settlement signer is unavailable"
            ) from None

    def sign_raw_digest(self, digest: str) -> str:
        normalized = _bytes32(digest, field_name="settlement authorization digest")
        try:
            signed = self._account.unsafe_sign_hash(bytes.fromhex(normalized[2:]))
            signature = "0x" + bytes(signed.signature).hex()
            return _signature(signature, field_name="settlement authorization signature")
        except RoyaltySettlementAuthorizationError:
            raise
        except Exception:
            raise RoyaltySettlementSignerUnavailable(
                "royalty settlement signer is unavailable"
            ) from None


def royalty_release_policy_commitment(
    release: RoyaltySettlementReleaseBinding,
) -> str:
    return "0x" + keccak(
        b"".join(
            (
                ROYALTY_RELEASE_POLICY_TYPEHASH,
                _word_uint(release.chain_id),
                _word_address(release.distributor_address),
                _word_uint(release.authority_nonce),
                _word_address(release.settlement_verifier_address),
                _word_address(release.royalty_qvl_verifier_address),
                _word_address(release.execution_policy_anchor_address),
                _word_bytes32(release.anchor_writer_release_commitment),
            )
        )
    ).hex()


def derive_royalty_qvl_policy_commitment(
    release: RoyaltySettlementReleaseBinding,
) -> str:
    return _canonical_commitment(
        ROYALTY_SETTLEMENT_POLICY_DOMAIN,
        {
            "schema": "dnai.royalty-settlement-qvl-policy.v2",
            "authorization_schema": ROYALTY_AUTHORIZATION_REQUEST_SCHEMA,
            "qvl_release_policy_hash": release.qvl_release_policy_hash,
            "chain_id": release.chain_id,
            "compose_hash": release.compose_hash,
            "app_id": release.app_id,
            "os_image_hash": release.os_image_hash,
            "royalty_qvl_verifier": release.royalty_qvl_verifier_address,
            "binding": release.qvl_binding_dict(),
        },
    )


def derive_royalty_settlement_report_data(
    release: RoyaltySettlementReleaseBinding,
) -> str:
    return _canonical_commitment(
        ROYALTY_SETTLEMENT_REPORT_DATA_DOMAIN,
        {
            "schema": "dnai.royalty-settlement-signer-attestation.v1",
            "chain_id": release.chain_id,
            "main_runtime_cvm_id": release.main_runtime_cvm_id,
            "deployment_intent_sha256": release.deployment_intent_sha256,
            "release_authority_sha256": release.release_authority_sha256,
            "measurement_policy_sha256": release.measurement_policy_sha256,
            "compose_hash": release.compose_hash,
            "app_id": release.app_id,
            "os_image_hash": release.os_image_hash,
            "distributor_address": release.distributor_address,
            "distributor_runtime_code_hash": (
                release.distributor_runtime_code_hash
            ),
            "settlement_verifier": release.settlement_verifier_address,
            "settlement_verifier_key_path": ROYALTY_SETTLEMENT_SIGNER_KEY_PATH,
            "settlement_verifier_custody": ROYALTY_SETTLEMENT_SIGNER_CUSTODY,
            "release_policy_commitment": release.release_policy_commitment,
            "royalty_qvl_verifier": release.royalty_qvl_verifier_address,
            "royalty_policy_commitment": release.royalty_qvl_policy_commitment,
        },
    )


def derive_royalty_settlement_attestation_evidence_hash(
    *,
    release: RoyaltySettlementReleaseBinding,
    challenge: Mapping[str, Any],
    expectation: Mapping[str, Any],
) -> str:
    required_challenge = {
        "chain_id",
        "domain",
        "profile",
        "cvm_id",
        "deployment_intent_sha256",
        "release_authority_sha256",
        "ceremony_nonce",
        "measurement_policy_sha256",
        "release_policy_hash",
        "challenge_id",
        "challenge_digest",
    }
    required_expectation = {
        "quote_hash",
        "report_data",
        "quote_report_data",
        "compose_hash",
        "app_id",
        "os_image_hash",
        "signer_address",
        "contract_address",
    }
    if not required_challenge.issubset(challenge) or not required_expectation.issubset(
        expectation
    ):
        raise RoyaltySettlementAuthorizationError(
            "royalty attestation evidence fields are incomplete"
        )
    return _canonical_commitment(
        ROYALTY_SETTLEMENT_EVIDENCE_DOMAIN,
        {
            "schema": "dnai.royalty-settlement-attestation-evidence.v1",
            "chain_id": challenge["chain_id"],
            "domain": challenge["domain"],
            "profile": challenge["profile"],
            "cvm_id": challenge["cvm_id"],
            "deployment_intent_sha256": challenge[
                "deployment_intent_sha256"
            ],
            "release_authority_sha256": challenge[
                "release_authority_sha256"
            ],
            "ceremony_nonce": challenge["ceremony_nonce"],
            "measurement_policy_sha256": challenge[
                "measurement_policy_sha256"
            ],
            "qvl_release_policy_hash": challenge["release_policy_hash"],
            "challenge_id": challenge["challenge_id"],
            "challenge_digest": challenge["challenge_digest"],
            "quote_hash": expectation["quote_hash"],
            "report_data": expectation["report_data"],
            "quote_report_data": expectation["quote_report_data"],
            "compose_hash": expectation["compose_hash"],
            "app_id": expectation["app_id"],
            "os_image_hash": expectation["os_image_hash"],
            "settlement_verifier": expectation["signer_address"],
            "distributor_address": expectation["contract_address"],
            "distributor_runtime_code_hash": (
                release.distributor_runtime_code_hash
            ),
            "release_policy_commitment": release.release_policy_commitment,
            "execution_policy_anchor": release.execution_policy_anchor_address,
            "anchor_writer_release_commitment": (
                release.anchor_writer_release_commitment
            ),
            "royalty_qvl_verifier": release.royalty_qvl_verifier_address,
            "royalty_policy_commitment": release.royalty_qvl_policy_commitment,
        },
    )


def royalty_collaboration_resource_hash(
    *,
    chain_id: int,
    distributor_address: str,
    room_commitment: str,
    query_commitment: str,
) -> str:
    return "0x" + keccak(
        b"".join(
            (
                ROYALTY_COLLABORATION_RESOURCE_TYPEHASH,
                _word_uint(chain_id),
                _word_address(distributor_address),
                _word_bytes32(room_commitment),
                _word_bytes32(query_commitment),
            )
        )
    ).hex()


def royalty_settlement_decision_hash(
    *,
    chain_id: int,
    distributor_address: str,
    authorization: SettlementAuthorization,
) -> str:
    return "0x" + keccak(
        b"".join(
            (
                ROYALTY_SETTLEMENT_DECISION_TYPEHASH,
                _word_uint(chain_id),
                _word_address(distributor_address),
                _word_bytes32(authorization.settlement_id),
                _word_uint(authorization.settlement_nonce),
                _word_bytes32(authorization.funding_reservation_id),
                _word_bytes32(authorization.release_policy_commitment),
                _word_bytes32(authorization.room_commitment),
                _word_bytes32(authorization.room_state_commitment),
                _word_bytes32(authorization.query_commitment),
                _word_bytes32(authorization.grant_set_commitment),
                _word_bytes32(authorization.allocation_commitment),
                _word_bytes32(authorization.owners_amounts_hash),
                _word_address(authorization.asset_address, allow_zero=True),
                _word_uint(authorization.total),
                _word_bytes32(authorization.execution_commitment),
                _word_bytes32(authorization.result_commitment),
                _word_bytes32(authorization.usage_commitment),
                _word_bytes32(authorization.attestation_evidence_hash),
                _word_bytes32(authorization.anchor_resource_hash),
                _word_uint(authorization.expiry),
            )
        )
    ).hex()


def _royalty_authorization_words(authorization: SettlementAuthorization) -> bytes:
    return b"".join(
        (
            _word_bytes32(authorization.settlement_id),
            _word_uint(authorization.settlement_nonce),
            _word_bytes32(authorization.funding_reservation_id),
            _word_bytes32(authorization.release_policy_commitment),
            _word_bytes32(authorization.room_commitment),
            _word_bytes32(authorization.room_state_commitment),
            _word_bytes32(authorization.query_commitment),
            _word_bytes32(authorization.grant_set_commitment),
            _word_bytes32(authorization.allocation_commitment),
            _word_bytes32(authorization.owners_amounts_hash),
            _word_address(authorization.asset_address, allow_zero=True),
            _word_uint(authorization.total),
            _word_bytes32(authorization.execution_commitment),
            _word_bytes32(authorization.result_commitment),
            _word_bytes32(authorization.usage_commitment),
            _word_bytes32(authorization.attestation_evidence_hash),
            _word_bytes32(authorization.anchor_resource_hash),
            _word_bytes32(authorization.anchor_decision_hash),
            _word_uint(authorization.anchor_sequence),
            _word_uint(authorization.expiry),
        )
    )


def _eip712_digest(
    *,
    chain_id: int,
    distributor_address: str,
    typehash: bytes,
    authorization: SettlementAuthorization,
) -> str:
    domain_separator = keccak(
        b"".join(
            (
                EIP712_DOMAIN_TYPEHASH,
                ROYALTY_DISTRIBUTOR_NAME_HASH,
                ROYALTY_DISTRIBUTOR_VERSION_HASH,
                _word_uint(chain_id),
                _word_address(distributor_address),
            )
        )
    )
    struct_hash = keccak(typehash + _royalty_authorization_words(authorization))
    return "0x" + keccak(b"\x19\x01" + domain_separator + struct_hash).hex()


def royalty_settlement_authorization_digest(
    *,
    chain_id: int,
    distributor_address: str,
    authorization: SettlementAuthorization,
) -> str:
    return _eip712_digest(
        chain_id=chain_id,
        distributor_address=distributor_address,
        typehash=ROYALTY_SETTLEMENT_AUTHORIZATION_TYPEHASH,
        authorization=authorization,
    )


def royalty_settlement_qvl_authorization_digest(
    *,
    chain_id: int,
    distributor_address: str,
    authorization: SettlementAuthorization,
) -> str:
    return _eip712_digest(
        chain_id=chain_id,
        distributor_address=distributor_address,
        typehash=ROYALTY_SETTLEMENT_QVL_AUTHORIZATION_TYPEHASH,
        authorization=authorization,
    )


def derive_royalty_settlement_anchor_evidence_commitment(
    *,
    release: RoyaltySettlementReleaseBinding,
    authorization: SettlementAuthorization,
) -> str:
    return _canonical_commitment(
        ROYALTY_SETTLEMENT_ANCHOR_EVIDENCE_DOMAIN,
        {
            "schema": "dnai.royalty-settlement-anchor-evidence.v2",
            "execution_policy_anchor": release.execution_policy_anchor_address,
            "anchor_writer_release_commitment": (
                release.anchor_writer_release_commitment
            ),
            "release_policy_commitment": authorization.release_policy_commitment,
            "funding_reservation_id": authorization.funding_reservation_id,
            "anchor_resource_hash": authorization.anchor_resource_hash,
            "anchor_decision_hash": authorization.anchor_decision_hash,
            "anchor_sequence": str(authorization.anchor_sequence),
            "attestation_evidence_hash": authorization.attestation_evidence_hash,
        },
    )


def recover_raw_digest_address(*, digest: str, signature: str) -> str:
    normalized_digest = _bytes32(digest, field_name="raw signature digest")
    normalized_signature = _signature(signature, field_name="raw signature")
    try:
        recovered = Account._recover_hash(  # noqa: SLF001
            bytes.fromhex(normalized_digest[2:]),
            signature=bytes.fromhex(normalized_signature[2:]),
        )
    except Exception:
        raise RoyaltySettlementAuthorizationError(
            "raw royalty settlement signature is invalid"
        ) from None
    return _address(recovered, field_name="recovered royalty signer")


def build_royalty_settlement_authorization_packet(
    *,
    release: RoyaltySettlementReleaseBinding,
    intent: RoyaltySettlementIntent,
    attestation_evidence_hash: str,
    signer: RoyaltySettlementSigner,
) -> RoyaltySettlementAuthorizationPacket:
    """Recompute all contract hashes and raw-sign the exact 20-field packet."""

    evidence_hash = _bytes32(
        attestation_evidence_hash,
        field_name="attestation evidence hash",
    )
    if (
        signer.key_path != ROYALTY_SETTLEMENT_SIGNER_KEY_PATH
        or signer.custody != ROYALTY_SETTLEMENT_SIGNER_CUSTODY
        or _address(signer.address, field_name="settlement signer")
        != release.settlement_verifier_address
    ):
        raise RoyaltySettlementAuthorizationError(
            "settlement signer does not match the purpose-separated release role"
        )
    resource_hash = royalty_collaboration_resource_hash(
        chain_id=release.chain_id,
        distributor_address=release.distributor_address,
        room_commitment=intent.room_commitment,
        query_commitment=intent.query_commitment,
    )
    incomplete = SettlementAuthorization(
        settlement_id=intent.settlement_id,
        settlement_nonce=intent.settlement_nonce,
        funding_reservation_id=intent.royalty_reservation_id,
        release_policy_commitment=release.release_policy_commitment,
        room_commitment=intent.room_commitment,
        room_state_commitment=intent.room_state_commitment,
        query_commitment=intent.query_commitment,
        grant_set_commitment=intent.grant_set_commitment,
        allocation_commitment=intent.allocation_commitment,
        owners_amounts_hash=intent.owners_amounts_hash,
        asset_address=intent.asset_address,
        total=intent.total,
        execution_commitment=intent.execution_commitment,
        result_commitment=intent.result_commitment,
        usage_commitment=intent.usage_commitment,
        attestation_evidence_hash=evidence_hash,
        anchor_resource_hash=resource_hash,
        anchor_decision_hash="0x" + "01" * 32,
        anchor_sequence=intent.anchor_sequence,
        expiry=intent.expiry,
    )
    decision_hash = royalty_settlement_decision_hash(
        chain_id=release.chain_id,
        distributor_address=release.distributor_address,
        authorization=incomplete,
    )
    authorization = SettlementAuthorization(
        **{
            **incomplete.__dict__,
            "anchor_decision_hash": decision_hash,
        }
    )
    digest = royalty_settlement_authorization_digest(
        chain_id=release.chain_id,
        distributor_address=release.distributor_address,
        authorization=authorization,
    )
    signature = signer.sign_raw_digest(digest)
    recovered = recover_raw_digest_address(digest=digest, signature=signature)
    if recovered != release.settlement_verifier_address:
        raise RoyaltySettlementAuthorizationError(
            "settlement authorization signature recovered the wrong role"
        )
    return RoyaltySettlementAuthorizationPacket(
        authorization=authorization,
        settlement_authorization_digest=digest,
        settlement_authorization_signature=signature,
        settlement_verifier_address=recovered,
        settlement_verifier_key_path=signer.key_path,
        settlement_verifier_custody=signer.custody,
    )
