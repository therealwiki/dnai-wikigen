"""Strict public protocol and canonical rate-policy models."""

from __future__ import annotations

import re
from typing import Annotated, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


MAX_BODY_BYTES = 24 * 1024
MAX_POLICY_BYTES = 64 * 1024
MIN_QUOTE_BYTES = 1024
MAX_QUOTE_BYTES = 16 * 1024
UINT256_MAX = 2**256 - 1
ZERO_ADDRESS = "0x" + "00" * 20
ZERO_BYTES32 = "0x" + "00" * 32
BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"


def _nonzero_bytes32(value: str) -> str:
    if value == ZERO_BYTES32:
        raise ValueError("bytes32 value must be nonzero")
    return value


def _uint256_string(value: str) -> str:
    if int(value) > UINT256_MAX:
        raise ValueError("decimal value exceeds uint256")
    return value


Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{40}$")]
Bytes32 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
Bytes64 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{128}$")]
NonzeroBytes32 = Annotated[
    str,
    StringConstraints(pattern=r"^0x[0-9a-f]{64}$"),
    AfterValidator(_nonzero_bytes32),
]
Signature65 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]
RawQuoteHex = Annotated[
    str,
    StringConstraints(
        min_length=2 + MIN_QUOTE_BYTES * 2,
        max_length=2 + MAX_QUOTE_BYTES * 2,
        pattern=r"^0x[0-9a-f]+$",
    ),
]
DecimalUint256 = Annotated[
    str,
    StringConstraints(pattern=r"^(0|[1-9][0-9]{0,77})$"),
    AfterValidator(_uint256_string),
]
Label = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_bytes32("0x" + value[7:]) and value),
]
BareSha256 = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
    AfterValidator(lambda value: _nonzero_bytes32("0x" + value) and value),
]
PhalaAppId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{40}$"),
    AfterValidator(
        lambda value: _nonzero_bytes32("0x" + "0" * 24 + value) and value
    ),
]
CvmId = Annotated[
    str,
    StringConstraints(
        min_length=8,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9._:-]{7,127}$",
    ),
]


def validate_rpc_origin(value: str) -> str:
    """Reject anything except a lowercase HTTPS origin with no hidden components."""
    pattern = r"^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[1-9][0-9]{0,4})?$"
    if not re.fullmatch(pattern, value):
        raise ValueError("RPC origin must be a canonical HTTPS origin")
    if value.endswith(":443"):
        raise ValueError("default HTTPS port must be omitted")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RateEntry(StrictModel):
    model: Label
    recipe: Label
    prefill_units_per_million: DecimalUint256
    sample_units_per_million: DecimalUint256
    training_units_per_million: DecimalUint256

    @model_validator(mode="after")
    def require_nonzero_rate(self) -> "RateEntry":
        if not any(
            int(value)
            for value in (
                self.prefill_units_per_million,
                self.sample_units_per_million,
                self.training_units_per_million,
            )
        ):
            raise ValueError("rate entry cannot be entirely zero")
        return self


class MeteringLimits(StrictModel):
    max_prefill_tokens: DecimalUint256
    max_sample_tokens: DecimalUint256
    max_training_tokens: DecimalUint256
    max_total_debit: DecimalUint256

    @model_validator(mode="after")
    def require_useful_limits(self) -> "MeteringLimits":
        if not any(
            int(value)
            for value in (
                self.max_prefill_tokens,
                self.max_sample_tokens,
                self.max_training_tokens,
            )
        ):
            raise ValueError("all token limits cannot be zero")
        if int(self.max_total_debit) == 0:
            raise ValueError("maximum debit must be nonzero")
        return self


class AssetRatePolicy(StrictModel):
    asset: Address
    provider: Address
    rate_policy_commitment: NonzeroBytes32
    rates: tuple[RateEntry, ...] = Field(min_length=1, max_length=128)
    limits: MeteringLimits

    @field_validator("rates", mode="before")
    @classmethod
    def require_json_rate_array(cls, value: object) -> object:
        if not isinstance(value, list):
            raise ValueError("rates must be a JSON array")
        return tuple(value)

    @model_validator(mode="after")
    def validate_rate_matrix(self) -> "AssetRatePolicy":
        keys = [(entry.model, entry.recipe) for entry in self.rates]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError("rate entries must be unique and sorted")
        if self.provider == ZERO_ADDRESS:
            raise ValueError("provider must be nonzero")
        return self


class MeteringPolicySet(StrictModel):
    schema_id: Literal["dnai.compute-metering-policy-set.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    chain_id: Literal[84532]
    rpc_origin: Annotated[str, StringConstraints(min_length=9, max_length=255)]
    vault_address: Address
    vault_runtime_code_hash: NonzeroBytes32
    owner: Address
    developer: Address
    paused: Literal[False]
    developer_fee_bps: int = Field(ge=0, le=2_000)
    developer_fee_frozen: Literal[True]
    rate_policy_additions_frozen: Literal[True]
    asset_additions_frozen: Literal[True]
    compose_policy_frozen: Literal[True]
    tee_identity_additions_frozen: Literal[True]
    metering_binding_frozen: Literal[True]
    allowed_asset_count: Literal[1]
    active_rate_policy_count: Literal[2]
    approved_compose_count: Literal[1]
    approved_tee_identity_count: Literal[1]
    pending_asset_count: Literal[0]
    pending_rate_policy_count: Literal[0]
    pending_compose_count: Literal[0]
    pending_tee_identity_count: Literal[0]
    pending_developer_fee_activates_at: Literal[0]
    pending_metering_verifier: Address
    metering_qvl_verifier: Address
    pending_metering_qvl_verifier: Address
    pending_metering_policy_set_hash: Bytes32
    pending_metering_binding_activates_at: Literal[0]
    tee_identity: Address
    compose_hash: NonzeroBytes32
    asset_policies: tuple[AssetRatePolicy, ...] = Field(min_length=2, max_length=2)
    min_confirmations: int = Field(ge=1, le=256)
    max_pinned_block_age_seconds: int = Field(ge=5, le=7_200)
    max_usage_age_seconds: int = Field(ge=5, le=86_400)
    max_future_skew_seconds: int = Field(ge=0, le=300)
    receipt_ttl_seconds: int = Field(ge=30, le=600)
    min_submission_window_seconds: int = Field(ge=5, le=300)
    valid_from: int = Field(ge=1, le=4_102_444_800)
    valid_until: int = Field(ge=1, le=4_102_444_800)

    @field_validator("rpc_origin")
    @classmethod
    def require_canonical_rpc_origin(cls, value: str) -> str:
        return validate_rpc_origin(value)

    @field_validator("asset_policies", mode="before")
    @classmethod
    def require_json_asset_policy_array(cls, value: object) -> object:
        if not isinstance(value, list):
            raise ValueError("asset_policies must be a JSON array")
        return tuple(value)

    @model_validator(mode="after")
    def validate_release_invariants(self) -> "MeteringPolicySet":
        if self.valid_until <= self.valid_from:
            raise ValueError("policy validity window is invalid")
        if self.valid_until - self.valid_from < self.receipt_ttl_seconds:
            raise ValueError("policy validity is shorter than receipt TTL")
        if self.min_submission_window_seconds >= self.receipt_ttl_seconds:
            raise ValueError("submission window must be shorter than receipt TTL")
        if (
            self.pending_metering_verifier != ZERO_ADDRESS
            or self.pending_metering_qvl_verifier != ZERO_ADDRESS
            or self.pending_metering_policy_set_hash != ZERO_BYTES32
        ):
            raise ValueError("pending metering binding must be empty")
        asset_keys = [(entry.asset, entry.rate_policy_commitment) for entry in self.asset_policies]
        if asset_keys != sorted(asset_keys):
            raise ValueError("asset policies must be sorted")
        assets = [entry.asset for entry in self.asset_policies]
        commitments = [entry.rate_policy_commitment for entry in self.asset_policies]
        if len(set(assets)) != len(assets) or len(set(commitments)) != len(commitments):
            raise ValueError("asset policies must have unique assets and commitments")
        supported_assets = {ZERO_ADDRESS, BASE_SEPOLIA_USDC}
        if set(assets) != supported_assets:
            raise ValueError("policy set must contain native ETH and canonical Base Sepolia USDC")
        service_roles = {
            self.vault_address,
            self.owner,
            self.developer,
            self.tee_identity,
            self.metering_qvl_verifier,
        }
        if ZERO_ADDRESS in service_roles or len(service_roles) != 5:
            raise ValueError("service roles must be nonzero and distinct")
        for entry in self.asset_policies:
            if entry.provider in service_roles:
                raise ValueError("provider must be separate from vault and service roles")
        return self

    def select_asset_policy(self, asset: str, commitment: str) -> AssetRatePolicy | None:
        for entry in self.asset_policies:
            if entry.asset == asset and entry.rate_policy_commitment == commitment:
                return entry
        return None


class PinnedBlock(StrictModel):
    number: int = Field(ge=1, le=2**63 - 1)
    hash: NonzeroBytes32


class ComputeUsageEnvelope(StrictModel):
    schema_id: Literal["dnai.compute-usage-envelope.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    job_id: NonzeroBytes32
    project_id: NonzeroBytes32
    user: Address
    asset: Address
    authorization_nonce: DecimalUint256
    max_asset_debit: DecimalUint256
    authorization_expiry: int = Field(ge=1, le=4_102_444_800)
    rate_policy_commitment: NonzeroBytes32
    workload_commitment: NonzeroBytes32
    manifest_commitment: NonzeroBytes32
    dispatch_intent_commitment: NonzeroBytes32
    tee_identity: Address
    compose_hash: NonzeroBytes32
    start_commitment: NonzeroBytes32
    model: Label
    recipe: Label
    outcome: Literal["succeeded", "failed"]
    prefill_tokens: DecimalUint256
    sample_tokens: DecimalUint256
    training_tokens: DecimalUint256
    usage_started_at: int = Field(ge=1, le=4_102_444_800)
    usage_observed_at: int = Field(ge=1, le=4_102_444_800)
    raw_secret_egress: Literal[False]
    usage_commitment: NonzeroBytes32
    tee_signature: Signature65

    @model_validator(mode="after")
    def require_success_usage(self) -> "ComputeUsageEnvelope":
        if self.outcome == "succeeded" and not any(
            int(value)
            for value in (self.prefill_tokens, self.sample_tokens, self.training_tokens)
        ):
            raise ValueError("a successful usage envelope cannot have zero usage")
        if self.usage_observed_at < self.usage_started_at:
            raise ValueError("usage cannot end before it starts")
        return self


class MeteringRequest(StrictModel):
    schema_id: Literal["dnai.compute-metering-request.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    block: PinnedBlock
    usage: ComputeUsageEnvelope


class MeteringDecision(StrictModel):
    schema_id: Literal["dnai.compute-metering-decision.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    classification: Literal["attested_dual_verified_metering"]
    provider_authoritative_invoice: Literal[False]
    chain_id: Literal[84532]
    vault_address: Address
    pinned_block_number: int = Field(ge=1, le=2**63 - 1)
    pinned_block_hash: NonzeroBytes32
    policy_set_hash: NonzeroBytes32
    rate_policy_commitment: NonzeroBytes32
    workload_commitment: NonzeroBytes32
    manifest_commitment: NonzeroBytes32
    dispatch_intent_commitment: NonzeroBytes32
    asset: Address
    job_id: NonzeroBytes32
    usage_commitment: NonzeroBytes32
    onchain_usage_commitment: NonzeroBytes32
    actual_asset_debit: DecimalUint256
    billable_compute_units: DecimalUint256
    usage_started_at: int = Field(ge=1, le=4_102_444_800)
    usage_ended_at: int = Field(ge=1, le=4_102_444_800)
    attestation_evidence_hash: NonzeroBytes32
    receipt_expiry: int = Field(ge=1, le=4_102_444_800)
    metering_receipt_digest: NonzeroBytes32
    metering_qvl_receipt_digest: NonzeroBytes32
    metering_verifier: Address
    metering_qvl_verifier: Address
    tee_identity: Address
    compose_hash: NonzeroBytes32
    raw_secret_egress: Literal[False]
    verifier_signature: Signature65
    qvl_signature: Signature65


class ComputeMeteringAuthorizationRequest(StrictModel):
    """Exact fields independently raw-signed by the attestation QVL."""

    schema_id: Literal["dnai.compute-metering-qvl-authorization-request.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    project_id: NonzeroBytes32
    job_id: NonzeroBytes32
    user: Address
    asset: Address
    authorization_nonce: DecimalUint256
    max_asset_debit: DecimalUint256
    actual_asset_debit: DecimalUint256
    authorization_expiry: int = Field(ge=1, le=4_102_444_800)
    rate_policy_commitment: NonzeroBytes32
    workload_commitment: NonzeroBytes32
    manifest_commitment: NonzeroBytes32
    dispatch_intent_commitment: NonzeroBytes32
    tee_identity: Address
    compose_hash: NonzeroBytes32
    start_commitment: NonzeroBytes32
    billable_compute_units: DecimalUint256
    usage_started_at: int = Field(ge=1, le=4_102_444_800)
    usage_ended_at: int = Field(ge=1, le=4_102_444_800)
    usage_commitment: NonzeroBytes32
    metering_policy_set_hash: NonzeroBytes32
    attestation_evidence_hash: NonzeroBytes32
    receipt_expiry: int = Field(ge=1, le=4_102_444_800)


class MeteringAssetIdentity(StrictModel):
    asset: Address
    provider: Address
    rate_policy_commitment: NonzeroBytes32


class MeteringIdentity(StrictModel):
    schema_id: Literal["dnai.compute-metering-identity.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    classification: Literal["attested_dual_verified_metering"]
    provider_authoritative_invoice: Literal[False]
    chain_id: Literal[84532]
    vault_address: Address
    policy_set_hash: NonzeroBytes32
    assets: tuple[MeteringAssetIdentity, ...] = Field(min_length=1, max_length=2)
    metering_verifier: Address
    metering_qvl_verifier: Address
    signer_custody: Literal["dstack_derived_independent_cvm"]
    raw_secret_egress: Literal[False]


class MeteringIdentityAttestation(StrictModel):
    """A real-CVM quote packet for independent verification of the meter signer."""

    schema_id: Literal["dnai.compute-metering-identity-attestation.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    challenge: "ComputeQvlChallenge"
    mode: Literal["tdx"]
    metering_verifier: Address
    chain_id: Literal[84532]
    vault_address: Address
    policy_set_hash: NonzeroBytes32
    signer_custody: Literal["dstack_derived_independent_cvm"]
    report_data: NonzeroBytes32
    quote_report_data: Bytes64
    quote: RawQuoteHex
    quote_hash: NonzeroBytes32
    quote_size: int = Field(ge=MIN_QUOTE_BYTES, le=MAX_QUOTE_BYTES)
    app_id: PhalaAppId
    compose_hash: NonzeroBytes32
    os_image_hash: BareSha256
    raw_secret_egress: Literal[False]

    @model_validator(mode="after")
    def require_exact_quote_binding(self) -> "MeteringIdentityAttestation":
        if self.quote_report_data != self.report_data + self.challenge.challenge_digest[2:]:
            raise ValueError("quote report data must bind static policy and QVL challenge")
        return self


class ComputeQvlChallenge(StrictModel):
    schema_id: Literal["dnai.attestation-qvl-challenge.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    chain_id: Literal[84532]
    domain: Literal["independent_metering_cvm"]
    profile: Literal["compute_metering"]
    cvm_id: CvmId
    deployment_intent_sha256: Sha256Digest
    release_authority_sha256: Sha256Digest
    ceremony_nonce: NonzeroBytes32
    measurement_policy_sha256: Sha256Digest
    release_policy_hash: NonzeroBytes32
    challenge_id: NonzeroBytes32
    challenge_digest: NonzeroBytes32
    issued_at: int = Field(ge=1, le=4_102_444_800)
    expires_at: int = Field(ge=1, le=4_102_444_800)
    verifier_address: Address
    verifier_signature: Signature65

    @model_validator(mode="after")
    def require_positive_lifetime(self) -> "ComputeQvlChallenge":
        if self.expires_at <= self.issued_at:
            raise ValueError("challenge lifetime is invalid")
        return self


class ComputeMeteringQvlVerdict(StrictModel):
    schema_id: Literal["dnai.independent-tdx-verdict.v4"] = Field(
        alias="schema", serialization_alias="schema"
    )
    verification_method: Literal["intel_tdx_dcap_qvl"]
    verified: Literal[True]
    chain_id: Literal[84532]
    domain: Literal["independent_metering_cvm"]
    profile: Literal["compute_metering"]
    cvm_id: CvmId
    deployment_intent_sha256: Sha256Digest
    release_authority_sha256: Sha256Digest
    ceremony_nonce: NonzeroBytes32
    measurement_policy_sha256: Sha256Digest
    release_policy_hash: NonzeroBytes32
    challenge_id: NonzeroBytes32
    challenge_digest: NonzeroBytes32
    challenge_issued_at: int = Field(ge=1, le=4_102_444_800)
    challenge_expires_at: int = Field(ge=1, le=4_102_444_800)
    quote_hash: NonzeroBytes32
    report_data: NonzeroBytes32
    compose_hash: NonzeroBytes32
    app_id: PhalaAppId
    os_image_hash: BareSha256
    signer_address: Address
    contract_address: Address
    issued_at: int = Field(ge=1, le=4_102_444_800)
    activation_evidence_lease_expires_at: int = Field(
        ge=1, le=4_102_444_800
    )
    expires_at: int = Field(ge=1, le=4_102_444_800)
    verifier_address: Address
    verifier_signature: Signature65
    qvl_compute_attestation_evidence_hash: NonzeroBytes32 | None = None
    qvl_compute_authorization_expiry: int | None = Field(
        default=None, ge=1, le=4_102_444_800
    )
    qvl_compute_authorization_digest: NonzeroBytes32 | None = None
    qvl_compute_authorization_signature: Signature65 | None = None

    @model_validator(mode="after")
    def require_complete_compute_authorization(self) -> "ComputeMeteringQvlVerdict":
        if (
            self.challenge_expires_at <= self.challenge_issued_at
            or self.challenge_expires_at - self.challenge_issued_at > 120
            or self.issued_at < self.challenge_issued_at
            or self.issued_at >= self.challenge_expires_at
            or self.activation_evidence_lease_expires_at != self.expires_at
            or self.expires_at <= self.issued_at
            or self.expires_at - self.issued_at > 900
        ):
            raise ValueError(
                "verdict challenge deadline or activation-evidence lease is invalid"
            )
        values = (
            self.qvl_compute_attestation_evidence_hash,
            self.qvl_compute_authorization_expiry,
            self.qvl_compute_authorization_digest,
            self.qvl_compute_authorization_signature,
        )
        if any(value is not None for value in values) and any(value is None for value in values):
            raise ValueError("compute QVL authorization fields must be supplied together")
        return self


MeteringIdentityAttestation.model_rebuild()
