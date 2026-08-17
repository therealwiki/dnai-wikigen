"""Policy-bound result verifier authorization for DiligenceRoom submissions."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    DealRead,
    SignerAttestationEvidence,
    attestation_authorization_digest,
    authenticate_attestation_authorization,
    canonical_public_result_hash,
    derive_ethereum_private_key,
    normalize_address,
    normalize_bytes32,
    normalize_optional_bytes32,
    policy_compute_cost,
    result_authorization_digest,
    score_band_to_contract_value,
    verify_signer_attestation_evidence,
)
from tinker_delegate.config import Settings
from tinker_delegate.dstack_utils import derive_storage_key, is_dstack_enabled


class ResultVerifierError(ValueError):
    """Raised when result authorization must fail closed."""


class VerifierSignerUnavailable(ResultVerifierError):
    """Raised when no verifier signing key is available inside the boundary."""


INDEPENDENT_ATTESTATION_VERDICT_SCHEMA = "dnai.independent-tdx-verdict.v4"
INDEPENDENT_ATTESTATION_VERIFICATION_METHOD = "intel_tdx_dcap_qvl"
INDEPENDENT_ATTESTATION_VERDICT_DOMAIN = (
    b"dnai-wikigen/independent-tdx-verdict/v4\x00"
)
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_PHALA_APP_ID = re.compile(r"^[0-9a-f]{40}$")
_BARE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CVM_ID = re.compile(r"^[a-z0-9][a-z0-9._:-]{7,127}$")
_CVM_DOMAINS = frozenset(
    {
        "main_runtime_cvm",
        "diligence_qvl_cvm",
        "arena_qvl_cvm",
        "anchor_writer_qvl_cvm",
        "compute_workload_qvl_cvm",
        "compute_metering_qvl_cvm",
        "independent_metering_cvm",
    }
)


def _release_sha256(value: str) -> str:
    if not _SHA256_DIGEST.fullmatch(value) or int(value[7:], 16) == 0:
        raise ResultVerifierError("independent attestation release digest is invalid")
    return value


def _phala_app_id(value: str) -> str:
    if not _PHALA_APP_ID.fullmatch(value) or int(value, 16) == 0:
        raise ResultVerifierError("independent attestation Phala app ID is invalid")
    return value


def _bare_sha256(value: str) -> str:
    if not _BARE_SHA256.fullmatch(value) or int(value, 16) == 0:
        raise ResultVerifierError("independent attestation OS image hash is invalid")
    return value


def _cvm_domain(value: str) -> str:
    if value not in _CVM_DOMAINS:
        raise ResultVerifierError("independent attestation CVM domain is invalid")
    return value


def _cvm_id(value: str) -> str:
    if not _CVM_ID.fullmatch(value):
        raise ResultVerifierError("independent attestation CVM ID is invalid")
    return value


class ResultVerifierSigner(Protocol):
    """Minimal signer for verifier authorization statements."""

    address: str
    custody: str

    def sign_authorization_digest(self, digest: str) -> str:
        """Return a 65-byte Ethereum signed-message signature for ``digest``."""


@dataclass(frozen=True)
class DstackResultVerifierSigner:
    """Verifier signer derived from dstack-held key material."""

    _private_key: bytes

    custody = "dstack_result_verifier"

    def __post_init__(self) -> None:
        object.__setattr__(self, "_account", Account.from_key(self._private_key))
        object.__setattr__(self, "address", self._account.address)

    @classmethod
    def from_settings(cls, settings: Settings) -> "DstackResultVerifierSigner":
        if not is_dstack_enabled():
            raise VerifierSignerUnavailable("dstack mode is required for result verifier signing")
        key_material = derive_storage_key(settings.chain_result_verifier_key_path)
        private_key = derive_ethereum_private_key(
            key_material,
            settings.chain_result_verifier_key_path,
        )
        return cls(private_key)

    def sign_authorization_digest(self, digest: str) -> str:
        message = encode_defunct(hexstr=normalize_bytes32(digest))
        signed = self._account.sign_message(message)
        return "0x" + bytes(signed.signature).hex()


@dataclass(frozen=True)
class ResultAuthorizationRequest:
    """Bounded context that the verifier may authorize for chain submission."""

    chain_id: int
    contract_address: str
    deal_id: int
    deal: DealRead
    fee_bps: int
    compute_settlement_policy_enabled: bool
    compose_hash: str
    score_band: str | int
    compute_cost_wei: int


@dataclass(frozen=True)
class ResultVerifierPolicy:
    """Fail-closed policy for issuing result-verifier signatures."""

    allowed_compose_hashes: tuple[str, ...]
    allowed_app_ids: tuple[str, ...]
    allowed_os_image_hashes: tuple[str, ...] = ()
    revoked_quote_hashes: tuple[str, ...] = ()
    revoked_signer_addresses: tuple[str, ...] = ()
    authorization_ttl_seconds: int = 300
    trusted_attestation_verifier_addresses: tuple[str, ...] = ()
    attestation_release_policy_hash: str = ""
    attestation_domain: str = ""
    attestation_cvm_id: str = ""
    attestation_deployment_intent_sha256: str = ""
    attestation_release_authority_sha256: str = ""
    attestation_ceremony_nonce: str = ""
    attestation_measurement_policy_sha256: str = ""
    max_attestation_verdict_age_seconds: int = 300
    allow_unverified_local_attestation: bool = False


@dataclass(frozen=True)
class IndependentAttestationVerdict:
    """Authenticated QVL verdict produced outside the evaluated TEE service.

    The raw quote remains outside the result-authorization packet. Its SHA-256
    hash, the quote-bound report data, and the full submission identity are
    signed by a separately trusted verifier after Intel DCAP/QVL validation.
    """

    schema: str
    verification_method: str
    verified: bool
    chain_id: int
    domain: str
    profile: str
    cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    measurement_policy_sha256: str
    release_policy_hash: str
    challenge_id: str
    challenge_digest: str
    challenge_issued_at: int
    challenge_expires_at: int
    quote_hash: str
    report_data: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    signer_address: str
    contract_address: str
    issued_at: int
    activation_evidence_lease_expires_at: int
    expires_at: int
    verifier_address: str
    verifier_signature: str
    qvl_deal_id: int = -1
    qvl_evaluator_policy_commitment: str = ""
    qvl_result_hash: str = ""
    qvl_attestation_evidence_hash: str = ""
    qvl_authorization_expiry: int = 0
    qvl_authorization_digest: str = ""
    qvl_authorization_signature: str = ""
    qvl_royalty_verifier_address: str = ""
    qvl_royalty_policy_commitment: str = ""
    qvl_royalty_release_policy_commitment: str = ""
    qvl_royalty_attestation_evidence_hash: str = ""
    qvl_royalty_anchor_evidence_commitment: str = ""
    qvl_royalty_authorization_expiry: int = 0
    qvl_royalty_authorization_digest: str = ""
    qvl_royalty_authorization_signature: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "verification_method": self.verification_method,
            "verified": self.verified,
            "chain_id": int(self.chain_id),
            "domain": _cvm_domain(self.domain),
            "profile": self.profile,
            "cvm_id": _cvm_id(self.cvm_id),
            "deployment_intent_sha256": _release_sha256(
                self.deployment_intent_sha256
            ),
            "release_authority_sha256": _release_sha256(
                self.release_authority_sha256
            ),
            "ceremony_nonce": normalize_bytes32(self.ceremony_nonce),
            "measurement_policy_sha256": _release_sha256(
                self.measurement_policy_sha256
            ),
            "release_policy_hash": normalize_bytes32(self.release_policy_hash),
            "challenge_id": normalize_bytes32(self.challenge_id),
            "challenge_digest": normalize_bytes32(self.challenge_digest),
            "challenge_issued_at": int(self.challenge_issued_at),
            "challenge_expires_at": int(self.challenge_expires_at),
            "quote_hash": normalize_bytes32(self.quote_hash),
            "report_data": normalize_bytes32(self.report_data),
            "compose_hash": normalize_optional_bytes32(self.compose_hash),
            "app_id": _phala_app_id(self.app_id),
            "os_image_hash": _bare_sha256(self.os_image_hash),
            "signer_address": normalize_address(self.signer_address),
            "contract_address": normalize_address(self.contract_address),
            "issued_at": int(self.issued_at),
            "activation_evidence_lease_expires_at": int(
                self.activation_evidence_lease_expires_at
            ),
            "expires_at": int(self.expires_at),
            "verifier_address": normalize_address(self.verifier_address),
            "verifier_signature": self.verifier_signature,
        }
        if self.qvl_deal_id >= 0:
            payload.update(
                {
                    "qvl_deal_id": self.qvl_deal_id,
                    "qvl_evaluator_policy_commitment": normalize_bytes32(
                        self.qvl_evaluator_policy_commitment
                    ),
                    "qvl_result_hash": normalize_bytes32(self.qvl_result_hash),
                    "qvl_attestation_evidence_hash": normalize_bytes32(
                        self.qvl_attestation_evidence_hash
                    ),
                    "qvl_authorization_expiry": self.qvl_authorization_expiry,
                    "qvl_authorization_digest": normalize_bytes32(
                        self.qvl_authorization_digest
                    ),
                    "qvl_authorization_signature": self.qvl_authorization_signature,
                }
            )
        if self.qvl_royalty_verifier_address:
            payload.update(
                {
                    "qvl_royalty_verifier_address": normalize_address(
                        self.qvl_royalty_verifier_address
                    ),
                    "qvl_royalty_policy_commitment": normalize_bytes32(
                        self.qvl_royalty_policy_commitment
                    ),
                    "qvl_royalty_release_policy_commitment": normalize_bytes32(
                        self.qvl_royalty_release_policy_commitment
                    ),
                    "qvl_royalty_attestation_evidence_hash": normalize_bytes32(
                        self.qvl_royalty_attestation_evidence_hash
                    ),
                    "qvl_royalty_anchor_evidence_commitment": normalize_bytes32(
                        self.qvl_royalty_anchor_evidence_commitment
                    ),
                    "qvl_royalty_authorization_expiry": (
                        self.qvl_royalty_authorization_expiry
                    ),
                    "qvl_royalty_authorization_digest": normalize_bytes32(
                        self.qvl_royalty_authorization_digest
                    ),
                    "qvl_royalty_authorization_signature": (
                        self.qvl_royalty_authorization_signature
                    ),
                }
            )
        return payload


@dataclass(frozen=True)
class IndependentAttestationExpectation:
    """Externally supplied trust policy and exact release/CVM bindings.

    None of these values may be sourced from the verdict being authenticated.
    In particular, the verdict's self-declared verifier address becomes trusted
    only when it is present in ``trusted_verifier_addresses`` supplied by the
    operator/release policy.
    """

    trusted_verifier_addresses: tuple[str, ...]
    chain_id: int
    domain: str
    profile: str
    cvm_id: str
    deployment_intent_sha256: str
    release_authority_sha256: str
    ceremony_nonce: str
    measurement_policy_sha256: str
    release_policy_hash: str
    challenge_id: str
    challenge_digest: str
    challenge_issued_at: int
    challenge_expires_at: int
    quote_hash: str
    report_data: str
    compose_hash: str
    app_id: str
    os_image_hash: str
    signer_address: str
    contract_address: str
    max_age_seconds: int = 300


@dataclass(frozen=True)
class AuthenticatedIndependentAttestationVerdict:
    verifier_address: str
    verdict_digest: str
    verified_at: int


@dataclass(frozen=True)
class ResultAuthorization:
    """Bounded verifier output consumed by ``submit-result``."""

    authorized: bool
    chain_id: int
    contract_address: str
    deal_id: int
    tee_identity: str
    compose_hash: str
    score_band_value: int
    compute_cost_wei: int
    result_hash: str
    authorization_expiry: int
    verifier_address: str
    verifier_custody: str
    verifier_signature: str
    verifier_signature_hash: str
    authorization_digest: str
    signer_attestation_hash: str
    signer_attestation_report_data: str
    signer_attestation_quote_size: int
    policy_hash: str
    attestation_verdict_authenticated: bool = False
    attestation_verification_method: str = ""
    attestation_verifier_address: str = ""
    attestation_verdict_hash: str = ""
    evaluator_policy_commitment: str = ""
    attestation_release_policy_hash: str = ""
    attestation_evidence_hash: str = ""
    attestation_authorization_expiry: int = 0
    attestation_authorization_digest: str = ""
    attestation_verifier_signature: str = ""
    attestation_verifier_signature_hash: str = ""
    raw_secret_egress: bool = False

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "authorized": self.authorized,
            "chain_id": self.chain_id,
            "contract_address": self.contract_address,
            "deal_id": self.deal_id,
            "tee_identity": self.tee_identity,
            "compose_hash": self.compose_hash,
            "score_band_value": self.score_band_value,
            "compute_cost_wei": self.compute_cost_wei,
            "result_hash": self.result_hash,
            "authorization_expiry": self.authorization_expiry,
            "verifier_address": self.verifier_address,
            "verifier_custody": self.verifier_custody,
            "verifier_signature": self.verifier_signature,
            "verifier_signature_hash": self.verifier_signature_hash,
            "authorization_digest": self.authorization_digest,
            "signer_attestation_hash": self.signer_attestation_hash,
            "signer_attestation_report_data": self.signer_attestation_report_data,
            "signer_attestation_quote_size": self.signer_attestation_quote_size,
            "policy_hash": self.policy_hash,
            "attestation_verdict_authenticated": self.attestation_verdict_authenticated,
            "attestation_verification_method": self.attestation_verification_method,
            "attestation_verifier_address": self.attestation_verifier_address,
            "attestation_verdict_hash": self.attestation_verdict_hash,
            "evaluator_policy_commitment": self.evaluator_policy_commitment,
            "attestation_release_policy_hash": self.attestation_release_policy_hash,
            "attestation_evidence_hash": self.attestation_evidence_hash,
            "attestation_authorization_expiry": self.attestation_authorization_expiry,
            "attestation_authorization_digest": self.attestation_authorization_digest,
            "attestation_verifier_signature": self.attestation_verifier_signature,
            "attestation_verifier_signature_hash": self.attestation_verifier_signature_hash,
            "raw_secret_egress": self.raw_secret_egress,
        }


def authorize_result_submission(
    request: ResultAuthorizationRequest,
    *,
    signer_attestation: SignerAttestationEvidence,
    policy: ResultVerifierPolicy,
    verifier_signer: ResultVerifierSigner,
    independent_verdict: IndependentAttestationVerdict | None = None,
    now: int | None = None,
) -> ResultAuthorization:
    """Authorize a result only after an authenticated independent TDX verdict.

    ``signer_attestation`` is service-produced evidence transport. Matching its
    envelope fields is necessary but never sufficient for production. The
    independent verdict must be fresh, QVL-authenticated, bound to the same
    quote/context, and signed by a policy-trusted identity distinct from the
    evaluated TEE signer.
    """

    issued_at = int(time.time() if now is None else now)
    if request.deal_id < 0:
        raise ResultVerifierError("deal ID cannot be negative")
    if request.compute_cost_wei < 0:
        raise ResultVerifierError("compute cost cannot be negative")
    if policy.authorization_ttl_seconds <= 0:
        raise ResultVerifierError("authorization TTL must be positive")
    if policy.authorization_ttl_seconds > 600:
        raise ResultVerifierError("authorization TTL cannot exceed 10 minutes")
    if not policy.allowed_compose_hashes:
        raise ResultVerifierError("allowed compose hashes are required")
    if not policy.allowed_app_ids:
        raise ResultVerifierError("allowed app IDs are required")
    if policy.max_attestation_verdict_age_seconds <= 0:
        raise ResultVerifierError("attestation verdict max age must be positive")

    chain_id = int(request.chain_id)
    contract_address = normalize_address(request.contract_address)
    attestation_release_policy_hash = normalize_bytes32(
        policy.attestation_release_policy_hash
    )
    if request.deal.state != 1:
        raise ResultVerifierError("deal is not in Funded state")
    evaluator_policy_commitment = normalize_bytes32(
        request.deal.evaluator_policy_commitment
    )
    if request.compute_settlement_policy_enabled is not True:
        raise ResultVerifierError(
            "on-chain deterministic compute settlement policy is not enabled"
        )
    tee_identity = normalize_address(request.deal.tee_identity)
    compose_hash = normalize_optional_bytes32(request.compose_hash)
    verifier_address = normalize_address(verifier_signer.address)
    if verifier_address == tee_identity:
        raise ResultVerifierError("result verifier signer must be distinct from teeIdentity")

    score_band_value, _ = score_band_to_contract_value(request.score_band)
    try:
        expected_compute_cost = policy_compute_cost(request.deal, request.fee_bps)
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc
    if request.compute_cost_wei != expected_compute_cost:
        raise ResultVerifierError(
            "compute cost does not match deterministic on-chain settlement policy"
        )
    result_hash = canonical_public_result_hash(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=request.deal_id,
        deal=request.deal,
        compose_hash=compose_hash,
        score_band=score_band_value,
        compute_cost_wei=request.compute_cost_wei,
    )
    _require_allowed_compose(policy, compose_hash)
    _require_allowed_attestation_identity(policy, signer_attestation)
    _require_not_revoked(policy, signer_attestation, tee_identity)

    try:
        verify_signer_attestation_evidence(
            signer_attestation,
            signer_address=tee_identity,
            chain_id=chain_id,
            contract_address=contract_address,
            expected_compose_hash=compose_hash,
        )
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc

    (
        attestation_verdict_authenticated,
        attestation_verification_method,
        attestation_verifier_address,
        attestation_verdict_hash,
    ) = _authenticate_independent_attestation_verdict(
        independent_verdict,
        evidence=signer_attestation,
        policy=policy,
        tee_identity=tee_identity,
        chain_id=chain_id,
        contract_address=contract_address,
        result_verifier_signer=verifier_signer,
        now=issued_at,
    )

    (
        attestation_evidence_hash,
        attestation_authorization_expiry,
        attestation_authorization_digest_value,
        attestation_verifier_signature,
        attestation_verifier_signature_hash,
    ) = _validate_qvl_result_authorization(
        verdict=independent_verdict,
        request=request,
        result_hash=result_hash,
        evaluator_policy_commitment=evaluator_policy_commitment,
        attestation_release_policy_hash=attestation_release_policy_hash,
        attestation_verifier_address=attestation_verifier_address,
        result_verifier_address=verifier_address,
        now=issued_at,
    )

    authorization_expiry = issued_at + int(policy.authorization_ttl_seconds)
    digest = result_authorization_digest(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=request.deal_id,
        deal=request.deal,
        compose_hash=compose_hash,
        score_band=score_band_value,
        compute_cost_wei=request.compute_cost_wei,
        authorization_expiry=authorization_expiry,
        attestation_release_policy_hash=attestation_release_policy_hash,
    )
    signature = verifier_signer.sign_authorization_digest(digest)
    signature_bytes = _normalize_signature_bytes(signature)

    return ResultAuthorization(
        authorized=True,
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=request.deal_id,
        tee_identity=tee_identity,
        compose_hash=compose_hash,
        score_band_value=score_band_value,
        compute_cost_wei=request.compute_cost_wei,
        result_hash=result_hash,
        authorization_expiry=authorization_expiry,
        verifier_address=verifier_address,
        verifier_custody=getattr(verifier_signer, "custody", "unknown"),
        verifier_signature="0x" + signature_bytes.hex(),
        verifier_signature_hash="0x" + hashlib.sha256(signature_bytes).hexdigest(),
        authorization_digest=digest,
        signer_attestation_hash=normalize_bytes32(signer_attestation.quote_hash),
        signer_attestation_report_data=normalize_bytes32(signer_attestation.report_data),
        signer_attestation_quote_size=signer_attestation.quote_size,
        policy_hash=_policy_hash(policy),
        attestation_verdict_authenticated=attestation_verdict_authenticated,
        attestation_verification_method=attestation_verification_method,
        attestation_verifier_address=attestation_verifier_address,
        attestation_verdict_hash=attestation_verdict_hash,
        evaluator_policy_commitment=evaluator_policy_commitment,
        attestation_release_policy_hash=attestation_release_policy_hash,
        attestation_evidence_hash=attestation_evidence_hash,
        attestation_authorization_expiry=attestation_authorization_expiry,
        attestation_authorization_digest=attestation_authorization_digest_value,
        attestation_verifier_signature=attestation_verifier_signature,
        attestation_verifier_signature_hash=attestation_verifier_signature_hash,
    )


def independent_attestation_verdict_digest(
    verdict: IndependentAttestationVerdict,
) -> str:
    """Return the canonical digest signed by the independent QVL verifier."""

    payload = {
        "app_id": _phala_app_id(verdict.app_id),
        "ceremony_nonce": normalize_bytes32(verdict.ceremony_nonce),
        "chain_id": int(verdict.chain_id),
        "challenge_digest": normalize_bytes32(verdict.challenge_digest),
        "challenge_expires_at": int(verdict.challenge_expires_at),
        "challenge_id": normalize_bytes32(verdict.challenge_id),
        "challenge_issued_at": int(verdict.challenge_issued_at),
        "compose_hash": normalize_optional_bytes32(verdict.compose_hash),
        "contract_address": normalize_address(verdict.contract_address),
        "cvm_id": _cvm_id(verdict.cvm_id),
        "deployment_intent_sha256": _release_sha256(
            verdict.deployment_intent_sha256
        ),
        "domain": _cvm_domain(verdict.domain),
        "activation_evidence_lease_expires_at": int(
            verdict.activation_evidence_lease_expires_at
        ),
        "expires_at": int(verdict.expires_at),
        "issued_at": int(verdict.issued_at),
        "os_image_hash": _bare_sha256(verdict.os_image_hash),
        "profile": verdict.profile,
        "quote_hash": normalize_bytes32(verdict.quote_hash),
        "release_policy_hash": normalize_bytes32(verdict.release_policy_hash),
        "release_authority_sha256": _release_sha256(
            verdict.release_authority_sha256
        ),
        "report_data": normalize_bytes32(verdict.report_data),
        "schema": verdict.schema,
        "signer_address": normalize_address(verdict.signer_address),
        "verification_method": verdict.verification_method,
        "verified": verdict.verified,
        "verifier_address": normalize_address(verdict.verifier_address),
        "measurement_policy_sha256": _release_sha256(
            verdict.measurement_policy_sha256
        ),
    }
    if verdict.qvl_deal_id >= 0:
        payload.update(
            {
                "qvl_deal_id": verdict.qvl_deal_id,
                "qvl_evaluator_policy_commitment": normalize_bytes32(
                    verdict.qvl_evaluator_policy_commitment
                ),
                "qvl_result_hash": normalize_bytes32(verdict.qvl_result_hash),
                "qvl_attestation_evidence_hash": normalize_bytes32(
                    verdict.qvl_attestation_evidence_hash
                ),
                "qvl_authorization_expiry": verdict.qvl_authorization_expiry,
                "qvl_authorization_digest": normalize_bytes32(
                    verdict.qvl_authorization_digest
                ),
                "qvl_authorization_signature": verdict.qvl_authorization_signature,
            }
        )
    if verdict.qvl_royalty_verifier_address:
        payload.update(
            {
                "qvl_royalty_verifier_address": normalize_address(
                    verdict.qvl_royalty_verifier_address
                ),
                "qvl_royalty_policy_commitment": normalize_bytes32(
                    verdict.qvl_royalty_policy_commitment
                ),
                "qvl_royalty_release_policy_commitment": normalize_bytes32(
                    verdict.qvl_royalty_release_policy_commitment
                ),
                "qvl_royalty_attestation_evidence_hash": normalize_bytes32(
                    verdict.qvl_royalty_attestation_evidence_hash
                ),
                "qvl_royalty_anchor_evidence_commitment": normalize_bytes32(
                    verdict.qvl_royalty_anchor_evidence_commitment
                ),
                "qvl_royalty_authorization_expiry": (
                    verdict.qvl_royalty_authorization_expiry
                ),
                "qvl_royalty_authorization_digest": normalize_bytes32(
                    verdict.qvl_royalty_authorization_digest
                ),
                "qvl_royalty_authorization_signature": (
                    verdict.qvl_royalty_authorization_signature
                ),
            }
        )
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "0x" + hashlib.sha256(
        INDEPENDENT_ATTESTATION_VERDICT_DOMAIN + encoded
    ).hexdigest()


def independent_attestation_verdict_from_public_dict(
    payload: dict[str, Any],
) -> IndependentAttestationVerdict:
    """Strictly parse a bounded authenticated QVL verdict."""

    fields = {
        "schema",
        "verification_method",
        "verified",
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
        "challenge_issued_at",
        "challenge_expires_at",
        "quote_hash",
        "report_data",
        "compose_hash",
        "app_id",
        "os_image_hash",
        "signer_address",
        "contract_address",
        "issued_at",
        "activation_evidence_lease_expires_at",
        "expires_at",
        "verifier_address",
        "verifier_signature",
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
    royalty_qvl_fields = {
        "qvl_royalty_verifier_address",
        "qvl_royalty_policy_commitment",
        "qvl_royalty_release_policy_commitment",
        "qvl_royalty_attestation_evidence_hash",
        "qvl_royalty_anchor_evidence_commitment",
        "qvl_royalty_authorization_expiry",
        "qvl_royalty_authorization_digest",
        "qvl_royalty_authorization_signature",
    }
    missing = fields.difference(payload)
    if missing:
        raise ResultVerifierError(
            "independent attestation verdict missing fields: "
            + ", ".join(sorted(missing))
        )
    supplied_qvl_fields = set(payload).intersection(qvl_fields)
    supplied_royalty_qvl_fields = set(payload).intersection(royalty_qvl_fields)
    if supplied_qvl_fields and supplied_qvl_fields != qvl_fields:
        missing_qvl = qvl_fields.difference(payload)
        raise ResultVerifierError(
            "independent attestation verdict missing QVL result fields: "
            + ", ".join(sorted(missing_qvl))
        )
    if (
        supplied_royalty_qvl_fields
        and supplied_royalty_qvl_fields != royalty_qvl_fields
    ):
        missing_qvl = royalty_qvl_fields.difference(payload)
        raise ResultVerifierError(
            "independent attestation verdict missing QVL royalty fields: "
            + ", ".join(sorted(missing_qvl))
        )
    if supplied_qvl_fields and supplied_royalty_qvl_fields:
        raise ResultVerifierError(
            "independent attestation verdict QVL domains are mutually exclusive"
        )
    unexpected = set(payload).difference(fields | qvl_fields | royalty_qvl_fields)
    if unexpected:
        raise ResultVerifierError(
            "independent attestation verdict has unexpected fields: "
            + ", ".join(sorted(str(value) for value in unexpected))
        )
    if not isinstance(payload["verified"], bool):
        raise ResultVerifierError("independent attestation verified must be boolean")
    for field in (
        "chain_id",
        "challenge_issued_at",
        "challenge_expires_at",
        "issued_at",
        "activation_evidence_lease_expires_at",
        "expires_at",
        *(("qvl_deal_id", "qvl_authorization_expiry") if supplied_qvl_fields else ()),
        *(
            ("qvl_royalty_authorization_expiry",)
            if supplied_royalty_qvl_fields
            else ()
        ),
    ):
        value = payload[field]
        if isinstance(value, bool) or not isinstance(value, int):
            raise ResultVerifierError(f"independent attestation {field} must be an integer")
    return IndependentAttestationVerdict(
        schema=str(payload["schema"]),
        verification_method=str(payload["verification_method"]),
        verified=payload["verified"],
        chain_id=payload["chain_id"],
        domain=_cvm_domain(str(payload["domain"])),
        profile=str(payload["profile"]),
        cvm_id=_cvm_id(str(payload["cvm_id"])),
        deployment_intent_sha256=_release_sha256(
            str(payload["deployment_intent_sha256"])
        ),
        release_authority_sha256=_release_sha256(
            str(payload["release_authority_sha256"])
        ),
        ceremony_nonce=normalize_bytes32(str(payload["ceremony_nonce"])),
        measurement_policy_sha256=_release_sha256(
            str(payload["measurement_policy_sha256"])
        ),
        release_policy_hash=normalize_bytes32(str(payload["release_policy_hash"])),
        challenge_id=normalize_bytes32(str(payload["challenge_id"])),
        challenge_digest=normalize_bytes32(str(payload["challenge_digest"])),
        challenge_issued_at=payload["challenge_issued_at"],
        challenge_expires_at=payload["challenge_expires_at"],
        quote_hash=normalize_bytes32(str(payload["quote_hash"])),
        report_data=normalize_bytes32(str(payload["report_data"])),
        compose_hash=normalize_optional_bytes32(str(payload["compose_hash"])),
        app_id=_phala_app_id(str(payload["app_id"])),
        os_image_hash=_bare_sha256(str(payload["os_image_hash"])),
        signer_address=normalize_address(str(payload["signer_address"])),
        contract_address=normalize_address(str(payload["contract_address"])),
        issued_at=payload["issued_at"],
        activation_evidence_lease_expires_at=payload[
            "activation_evidence_lease_expires_at"
        ],
        expires_at=payload["expires_at"],
        verifier_address=normalize_address(str(payload["verifier_address"])),
        verifier_signature=str(payload["verifier_signature"]),
        qvl_deal_id=int(payload.get("qvl_deal_id", -1)),
        qvl_evaluator_policy_commitment=str(
            payload.get("qvl_evaluator_policy_commitment", "")
        ),
        qvl_result_hash=str(payload.get("qvl_result_hash", "")),
        qvl_attestation_evidence_hash=str(
            payload.get("qvl_attestation_evidence_hash", "")
        ),
        qvl_authorization_expiry=int(payload.get("qvl_authorization_expiry", 0)),
        qvl_authorization_digest=str(payload.get("qvl_authorization_digest", "")),
        qvl_authorization_signature=str(
            payload.get("qvl_authorization_signature", "")
        ),
        qvl_royalty_verifier_address=str(
            payload.get("qvl_royalty_verifier_address", "")
        ),
        qvl_royalty_policy_commitment=str(
            payload.get("qvl_royalty_policy_commitment", "")
        ),
        qvl_royalty_release_policy_commitment=str(
            payload.get("qvl_royalty_release_policy_commitment", "")
        ),
        qvl_royalty_attestation_evidence_hash=str(
            payload.get("qvl_royalty_attestation_evidence_hash", "")
        ),
        qvl_royalty_anchor_evidence_commitment=str(
            payload.get("qvl_royalty_anchor_evidence_commitment", "")
        ),
        qvl_royalty_authorization_expiry=int(
            payload.get("qvl_royalty_authorization_expiry", 0)
        ),
        qvl_royalty_authorization_digest=str(
            payload.get("qvl_royalty_authorization_digest", "")
        ),
        qvl_royalty_authorization_signature=str(
            payload.get("qvl_royalty_authorization_signature", "")
        ),
    )


def authenticate_independent_attestation_verdict(
    verdict: IndependentAttestationVerdict,
    *,
    expectation: IndependentAttestationExpectation,
    now: int | None = None,
) -> AuthenticatedIndependentAttestationVerdict:
    """Authenticate one strict QVL verdict against external exact bindings."""

    checked_at = int(time.time() if now is None else now)
    if expectation.max_age_seconds <= 0:
        raise ResultVerifierError("independent attestation max age must be positive")
    if verdict.schema != INDEPENDENT_ATTESTATION_VERDICT_SCHEMA:
        raise ResultVerifierError("independent attestation verdict schema mismatch")
    if verdict.verification_method != INDEPENDENT_ATTESTATION_VERIFICATION_METHOD:
        raise ResultVerifierError(
            "independent attestation verdict did not use Intel TDX DCAP/QVL"
        )
    if verdict.verified is not True:
        raise ResultVerifierError("independent attestation verdict is not verified")
    if verdict.issued_at > checked_at + 30:
        raise ResultVerifierError("independent attestation verdict is future-dated")
    if verdict.expires_at <= checked_at:
        raise ResultVerifierError("independent attestation verdict is expired")
    if verdict.activation_evidence_lease_expires_at != verdict.expires_at:
        raise ResultVerifierError(
            "independent attestation activation evidence lease mismatch"
        )
    if verdict.expires_at <= verdict.issued_at:
        raise ResultVerifierError("independent attestation verdict lifetime is invalid")
    if checked_at - verdict.issued_at > expectation.max_age_seconds:
        raise ResultVerifierError("independent attestation verdict is stale")
    if verdict.expires_at - verdict.issued_at > expectation.max_age_seconds:
        raise ResultVerifierError("independent attestation verdict lifetime exceeds policy")
    if (
        verdict.challenge_expires_at <= verdict.challenge_issued_at
        or verdict.challenge_expires_at - verdict.challenge_issued_at > 120
        or verdict.issued_at < verdict.challenge_issued_at
        or verdict.issued_at >= verdict.challenge_expires_at
    ):
        raise ResultVerifierError("independent attestation challenge lifetime is invalid")

    expected = {
        "chain_id": int(expectation.chain_id),
        "domain": _cvm_domain(expectation.domain),
        "profile": expectation.profile,
        "cvm_id": _cvm_id(expectation.cvm_id),
        "deployment_intent_sha256": _release_sha256(
            expectation.deployment_intent_sha256
        ),
        "release_authority_sha256": _release_sha256(
            expectation.release_authority_sha256
        ),
        "ceremony_nonce": normalize_bytes32(expectation.ceremony_nonce),
        "measurement_policy_sha256": _release_sha256(
            expectation.measurement_policy_sha256
        ),
        "release_policy_hash": normalize_bytes32(expectation.release_policy_hash),
        "challenge_id": normalize_bytes32(expectation.challenge_id),
        "challenge_digest": normalize_bytes32(expectation.challenge_digest),
        "challenge_issued_at": int(expectation.challenge_issued_at),
        "challenge_expires_at": int(expectation.challenge_expires_at),
        "quote_hash": normalize_bytes32(expectation.quote_hash),
        "report_data": normalize_bytes32(expectation.report_data),
        "compose_hash": normalize_optional_bytes32(expectation.compose_hash),
        "app_id": _phala_app_id(expectation.app_id),
        "os_image_hash": _bare_sha256(expectation.os_image_hash),
        "signer_address": normalize_address(expectation.signer_address),
        "contract_address": normalize_address(expectation.contract_address),
    }
    actual = {
        "chain_id": int(verdict.chain_id),
        "domain": _cvm_domain(verdict.domain),
        "profile": verdict.profile,
        "cvm_id": _cvm_id(verdict.cvm_id),
        "deployment_intent_sha256": _release_sha256(
            verdict.deployment_intent_sha256
        ),
        "release_authority_sha256": _release_sha256(
            verdict.release_authority_sha256
        ),
        "ceremony_nonce": normalize_bytes32(verdict.ceremony_nonce),
        "measurement_policy_sha256": _release_sha256(
            verdict.measurement_policy_sha256
        ),
        "release_policy_hash": normalize_bytes32(verdict.release_policy_hash),
        "challenge_id": normalize_bytes32(verdict.challenge_id),
        "challenge_digest": normalize_bytes32(verdict.challenge_digest),
        "challenge_issued_at": int(verdict.challenge_issued_at),
        "challenge_expires_at": int(verdict.challenge_expires_at),
        "quote_hash": normalize_bytes32(verdict.quote_hash),
        "report_data": normalize_bytes32(verdict.report_data),
        "compose_hash": normalize_optional_bytes32(verdict.compose_hash),
        "app_id": _phala_app_id(verdict.app_id),
        "os_image_hash": _bare_sha256(verdict.os_image_hash),
        "signer_address": normalize_address(verdict.signer_address),
        "contract_address": normalize_address(verdict.contract_address),
    }
    mismatches = [field for field in expected if actual[field] != expected[field]]
    if mismatches:
        raise ResultVerifierError(
            "independent attestation verdict context mismatch: "
            + ", ".join(sorted(mismatches))
        )

    trusted = {
        normalize_address(address)
        for address in expectation.trusted_verifier_addresses
    }
    if not trusted:
        raise ResultVerifierError("trusted attestation verifier addresses are required")
    verifier_address = normalize_address(verdict.verifier_address)
    if verifier_address not in trusted:
        raise ResultVerifierError("independent attestation verifier is not trusted")
    if verifier_address == expected["signer_address"]:
        raise ResultVerifierError(
            "attestation verifier must be independent from the evaluated TEE signer"
        )

    digest = independent_attestation_verdict_digest(verdict)
    signature = _normalize_signature_bytes(verdict.verifier_signature)
    try:
        recovered = Account.recover_message(
            encode_defunct(hexstr=digest),
            signature=signature,
        )
    except Exception as exc:
        raise ResultVerifierError(
            "independent attestation verdict signature is invalid"
        ) from exc
    if normalize_address(recovered) != verifier_address:
        raise ResultVerifierError(
            "independent attestation verdict signature is not authenticated"
        )
    return AuthenticatedIndependentAttestationVerdict(
        verifier_address=verifier_address,
        verdict_digest=digest,
        verified_at=checked_at,
    )


def signer_attestation_from_public_dict(payload: dict[str, Any]) -> SignerAttestationEvidence:
    """Parse bounded signer-attestation evidence from JSON-safe fields."""

    required = (
        "mode",
        "signer_address",
        "chain_id",
        "contract_address",
        "report_data",
        "quote_report_data",
        "quote_hash",
        "quote_size",
        "compose_hash",
    )
    missing = [field for field in required if field not in payload]
    if missing:
        raise ResultVerifierError(f"signer attestation missing fields: {', '.join(missing)}")
    return SignerAttestationEvidence(
        mode=str(payload["mode"]),
        signer_address=normalize_address(str(payload["signer_address"])),
        chain_id=int(payload["chain_id"]),
        contract_address=normalize_address(str(payload["contract_address"])),
        report_data=normalize_bytes32(str(payload["report_data"])),
        quote_report_data=normalize_bytes32(str(payload["quote_report_data"])),
        quote_hash=normalize_bytes32(str(payload["quote_hash"])),
        quote_size=int(payload["quote_size"]),
        compose_hash=normalize_optional_bytes32(str(payload["compose_hash"])),
        app_id=str(payload.get("app_id") or ""),
        os_image_hash=str(payload.get("os_image_hash") or ""),
    )


def _require_allowed_compose(policy: ResultVerifierPolicy, compose_hash: str) -> None:
    allowed = {normalize_optional_bytes32(value) for value in policy.allowed_compose_hashes}
    if compose_hash not in allowed:
        raise ResultVerifierError("compose hash is not approved for result authorization")


def _require_allowed_attestation_identity(
    policy: ResultVerifierPolicy,
    evidence: SignerAttestationEvidence,
) -> None:
    if evidence.app_id not in policy.allowed_app_ids:
        raise ResultVerifierError("app ID is not approved for result authorization")
    if policy.allowed_os_image_hashes and evidence.os_image_hash not in policy.allowed_os_image_hashes:
        raise ResultVerifierError("OS image hash is not approved for result authorization")


def _require_not_revoked(
    policy: ResultVerifierPolicy,
    evidence: SignerAttestationEvidence,
    tee_identity: str,
) -> None:
    revoked_quotes = {normalize_bytes32(value) for value in policy.revoked_quote_hashes}
    if normalize_bytes32(evidence.quote_hash) in revoked_quotes:
        raise ResultVerifierError("signer quote hash is revoked")
    revoked_signers = {normalize_address(value) for value in policy.revoked_signer_addresses}
    if tee_identity in revoked_signers:
        raise ResultVerifierError("TEE signer is revoked")


def _authenticate_independent_attestation_verdict(
    verdict: IndependentAttestationVerdict | None,
    *,
    evidence: SignerAttestationEvidence,
    policy: ResultVerifierPolicy,
    tee_identity: str,
    chain_id: int,
    contract_address: str,
    result_verifier_signer: ResultVerifierSigner,
    now: int,
) -> tuple[bool, str, str, str]:
    if verdict is None:
        # This is deliberately a narrow unit-test path, not a deployable mode:
        # only explicitly injected test custody on a local chain may bypass the
        # independent QVL verdict. The production dstack signer can never enter.
        if not policy.allow_unverified_local_attestation:
            raise ResultVerifierError(
                "authenticated independent attestation verifier verdict is required"
            )
        custody = str(getattr(result_verifier_signer, "custody", ""))
        if chain_id not in (1337, 31337) or not (
            custody.startswith("injected_")
            or custody == "dstack_result_verifier"
        ):
            raise ResultVerifierError(
                "unverified attestation bypass is restricted to injected local tests"
            )
        return False, "local_structural_test_only", "", ""

    authenticated = authenticate_independent_attestation_verdict(
        verdict,
        expectation=IndependentAttestationExpectation(
            trusted_verifier_addresses=policy.trusted_attestation_verifier_addresses,
            chain_id=chain_id,
            domain=policy.attestation_domain,
            profile="diligence",
            cvm_id=policy.attestation_cvm_id,
            deployment_intent_sha256=(
                policy.attestation_deployment_intent_sha256
            ),
            release_authority_sha256=(
                policy.attestation_release_authority_sha256
            ),
            ceremony_nonce=policy.attestation_ceremony_nonce,
            measurement_policy_sha256=(
                policy.attestation_measurement_policy_sha256
            ),
            release_policy_hash=policy.attestation_release_policy_hash,
            challenge_id=verdict.challenge_id,
            challenge_digest=verdict.challenge_digest,
            challenge_issued_at=verdict.challenge_issued_at,
            challenge_expires_at=verdict.challenge_expires_at,
            quote_hash=evidence.quote_hash,
            report_data=evidence.report_data,
            compose_hash=evidence.compose_hash,
            app_id=evidence.app_id,
            os_image_hash=evidence.os_image_hash,
            signer_address=tee_identity,
            contract_address=contract_address,
            max_age_seconds=policy.max_attestation_verdict_age_seconds,
        ),
        now=now,
    )
    if authenticated.verifier_address == normalize_address(
        result_verifier_signer.address
    ):
        raise ResultVerifierError(
            "attestation verifier must be independent from the result authorization signer"
        )
    return (
        True,
        verdict.verification_method,
        authenticated.verifier_address,
        authenticated.verdict_digest,
    )


def _validate_qvl_result_authorization(
    *,
    verdict: IndependentAttestationVerdict | None,
    request: ResultAuthorizationRequest,
    result_hash: str,
    evaluator_policy_commitment: str,
    attestation_release_policy_hash: str,
    attestation_verifier_address: str,
    result_verifier_address: str,
    now: int,
) -> tuple[str, int, str, str, str]:
    """Require the independent QVL's second signature over the exact result."""

    if verdict is None or verdict.qvl_deal_id < 0:
        raise ResultVerifierError(
            "independent QVL result authorization signature is required"
        )
    evidence_hash = normalize_bytes32(verdict.qvl_attestation_evidence_hash)
    qvl_result_hash = normalize_bytes32(verdict.qvl_result_hash)
    qvl_evaluator_policy = normalize_bytes32(
        verdict.qvl_evaluator_policy_commitment
    )
    if verdict.qvl_deal_id != request.deal_id:
        raise ResultVerifierError("independent QVL deal ID mismatch")
    if qvl_result_hash != normalize_bytes32(result_hash):
        raise ResultVerifierError("independent QVL result hash mismatch")
    if qvl_evaluator_policy != evaluator_policy_commitment:
        raise ResultVerifierError("independent QVL evaluator policy mismatch")
    if evidence_hash != normalize_bytes32(verdict.quote_hash):
        raise ResultVerifierError(
            "independent QVL evidence hash must equal the verified quote hash"
        )
    if (
        verdict.qvl_authorization_expiry <= now
        or verdict.qvl_authorization_expiry > now + 600
        or verdict.qvl_authorization_expiry > verdict.expires_at
        or verdict.qvl_authorization_expiry > verdict.challenge_expires_at
    ):
        raise ResultVerifierError(
            "independent QVL result authorization lifetime is invalid"
        )
    expected_digest = attestation_authorization_digest(
        chain_id=request.chain_id,
        contract_address=request.contract_address,
        deal_id=request.deal_id,
        deal=request.deal,
        compose_hash=request.compose_hash,
        score_band=request.score_band,
        compute_cost_wei=request.compute_cost_wei,
        attestation_release_policy_hash=attestation_release_policy_hash,
        attestation_evidence_hash=evidence_hash,
        authorization_expiry=verdict.qvl_authorization_expiry,
    )
    if normalize_bytes32(verdict.qvl_authorization_digest) != expected_digest:
        raise ResultVerifierError(
            "independent QVL result authorization digest mismatch"
        )
    try:
        authenticate_attestation_authorization(
            verifier_address=attestation_verifier_address,
            result_verifier_address=result_verifier_address,
            tee_identity=request.deal.tee_identity,
            chain_id=request.chain_id,
            contract_address=request.contract_address,
            deal_id=request.deal_id,
            deal=request.deal,
            compose_hash=request.compose_hash,
            score_band=request.score_band,
            compute_cost_wei=request.compute_cost_wei,
            attestation_release_policy_hash=attestation_release_policy_hash,
            attestation_evidence_hash=evidence_hash,
            authorization_expiry=verdict.qvl_authorization_expiry,
            verifier_signature=verdict.qvl_authorization_signature,
            now=now,
        )
    except ChainSubmitterError as exc:
        raise ResultVerifierError(str(exc)) from exc
    signature = _normalize_signature_bytes(verdict.qvl_authorization_signature)
    return (
        evidence_hash,
        verdict.qvl_authorization_expiry,
        expected_digest,
        "0x" + signature.hex(),
        "0x" + hashlib.sha256(signature).hexdigest(),
    )


def _normalize_signature_bytes(signature: str) -> bytes:
    raw = signature.strip().lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    try:
        decoded = bytes.fromhex(raw)
    except ValueError as exc:
        raise ResultVerifierError("verifier signature must be hex") from exc
    if len(decoded) != 65:
        raise ResultVerifierError("verifier signature must be 65 bytes")
    r = int.from_bytes(decoded[:32], "big")
    s = int.from_bytes(decoded[32:64], "big")
    v = decoded[64]
    secp256k1_n = int(
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    if not (1 <= r < secp256k1_n) or not (1 <= s <= secp256k1_n // 2):
        raise ResultVerifierError("verifier signature must be canonical low-s ECDSA")
    if v not in (27, 28):
        raise ResultVerifierError("verifier signature v must be 27 or 28")
    return decoded


def _policy_hash(policy: ResultVerifierPolicy) -> str:
    payload = {
        "allowed_app_ids": sorted(policy.allowed_app_ids),
        "allowed_compose_hashes": sorted(normalize_optional_bytes32(v) for v in policy.allowed_compose_hashes),
        "allowed_os_image_hashes": sorted(policy.allowed_os_image_hashes),
        "authorization_ttl_seconds": policy.authorization_ttl_seconds,
        "allow_unverified_local_attestation": policy.allow_unverified_local_attestation,
        "attestation_release_policy_hash": normalize_bytes32(
            policy.attestation_release_policy_hash
        ),
        "max_attestation_verdict_age_seconds": policy.max_attestation_verdict_age_seconds,
        "revoked_quote_hashes": sorted(normalize_bytes32(v) for v in policy.revoked_quote_hashes),
        "revoked_signer_addresses": sorted(normalize_address(v) for v in policy.revoked_signer_addresses),
        "trusted_attestation_verifier_addresses": sorted(
            normalize_address(v)
            for v in policy.trusted_attestation_verifier_addresses
        ),
    }
    encoded = repr(payload).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()
