"""Policy-bound result verifier authorization for DiligenceRoom submissions."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Any, Protocol

from eth_account import Account
from eth_account.messages import encode_defunct

from tinker_delegate.chain_submitter import (
    ChainSubmitterError,
    SignerAttestationEvidence,
    derive_ethereum_private_key,
    normalize_address,
    normalize_bytes32,
    normalize_optional_bytes32,
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
    tee_identity: str
    compose_hash: str
    score_band: str | int
    compute_cost_wei: int
    result_hash: str


@dataclass(frozen=True)
class ResultVerifierPolicy:
    """Fail-closed policy for issuing result-verifier signatures."""

    allowed_compose_hashes: tuple[str, ...]
    allowed_app_ids: tuple[str, ...]
    allowed_os_image_hashes: tuple[str, ...] = ()
    revoked_quote_hashes: tuple[str, ...] = ()
    revoked_signer_addresses: tuple[str, ...] = ()
    authorization_ttl_seconds: int = 300


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
            "raw_secret_egress": self.raw_secret_egress,
        }


def authorize_result_submission(
    request: ResultAuthorizationRequest,
    *,
    signer_attestation: SignerAttestationEvidence,
    policy: ResultVerifierPolicy,
    verifier_signer: ResultVerifierSigner,
    now: int | None = None,
) -> ResultAuthorization:
    """Authorize a DiligenceRoom result only when policy and quote evidence match."""

    issued_at = int(time.time() if now is None else now)
    if request.deal_id < 0:
        raise ResultVerifierError("deal ID cannot be negative")
    if request.compute_cost_wei < 0:
        raise ResultVerifierError("compute cost cannot be negative")
    if policy.authorization_ttl_seconds <= 0:
        raise ResultVerifierError("authorization TTL must be positive")
    if not policy.allowed_compose_hashes:
        raise ResultVerifierError("allowed compose hashes are required")
    if not policy.allowed_app_ids:
        raise ResultVerifierError("allowed app IDs are required")

    chain_id = int(request.chain_id)
    contract_address = normalize_address(request.contract_address)
    tee_identity = normalize_address(request.tee_identity)
    compose_hash = normalize_optional_bytes32(request.compose_hash)
    result_hash = normalize_bytes32(request.result_hash)
    verifier_address = normalize_address(verifier_signer.address)
    if verifier_address == tee_identity:
        raise ResultVerifierError("result verifier signer must be distinct from teeIdentity")

    score_band_value, _ = score_band_to_contract_value(request.score_band)
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

    authorization_expiry = issued_at + int(policy.authorization_ttl_seconds)
    digest = result_authorization_digest(
        chain_id=chain_id,
        contract_address=contract_address,
        deal_id=request.deal_id,
        tee_identity=tee_identity,
        compose_hash=compose_hash,
        score_band=score_band_value,
        compute_cost_wei=request.compute_cost_wei,
        result_hash=result_hash,
        authorization_expiry=authorization_expiry,
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
    return decoded


def _policy_hash(policy: ResultVerifierPolicy) -> str:
    payload = {
        "allowed_app_ids": sorted(policy.allowed_app_ids),
        "allowed_compose_hashes": sorted(normalize_optional_bytes32(v) for v in policy.allowed_compose_hashes),
        "allowed_os_image_hashes": sorted(policy.allowed_os_image_hashes),
        "authorization_ttl_seconds": policy.authorization_ttl_seconds,
        "revoked_quote_hashes": sorted(normalize_bytes32(v) for v in policy.revoked_quote_hashes),
        "revoked_signer_addresses": sorted(normalize_address(v) for v in policy.revoked_signer_addresses),
    }
    encoded = repr(payload).encode("utf-8")
    return "0x" + hashlib.sha256(encoded).hexdigest()
