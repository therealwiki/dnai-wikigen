"""Strict wire and release-policy schemas."""

from __future__ import annotations

import hashlib
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


MAX_BODY_BYTES = 96 * 1024
MIN_QUOTE_BYTES = 1024
MAX_QUOTE_BYTES = 16 * 1024
MAX_POLICY_BYTES = 64 * 1024

Address = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{40}$")]
Bytes32 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{64}$")]
Bytes64 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{128}$")]


def _nonzero_bytes32(value: str) -> str:
    if int(value[2:], 16) == 0:
        raise ValueError("bytes32 value must be nonzero")
    return value


def _uint256_string(value: str) -> str:
    if int(value) >= 2**256:
        raise ValueError("decimal value exceeds uint256")
    return value


NonzeroBytes32 = Annotated[
    str,
    StringConstraints(pattern=r"^0x[0-9a-f]{64}$"),
    AfterValidator(_nonzero_bytes32),
]
Signature65 = Annotated[str, StringConstraints(pattern=r"^0x[0-9a-f]{130}$")]
DecimalUint256 = Annotated[
    str,
    StringConstraints(pattern=r"^(0|[1-9][0-9]{0,77})$"),
    AfterValidator(_uint256_string),
]
QvlProfile = Literal[
    "diligence",
    "arena",
    "execution_policy_anchor_writer",
    "compute_workload",
    "compute_metering",
    "email_oracle_kms_restart",
]
Label = Annotated[
    str,
    StringConstraints(min_length=1, max_length=160, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$"),
]
Hex16 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
Hex8 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16}$")]
Hex48 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{96}$")]
Hex32Raw = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Sha256KeyId = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
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
    AfterValidator(lambda value: _nonzero_bytes32("0x" + "0" * 24 + value) and value),
]
CvmId = Annotated[
    str,
    StringConstraints(min_length=8, max_length=128, pattern=r"^[a-z0-9][a-z0-9._:-]{7,127}$"),
]
CvmDomain = Literal[
    "main_runtime_cvm",
    "diligence_qvl_cvm",
    "arena_qvl_cvm",
    "anchor_writer_qvl_cvm",
    "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm",
    "independent_metering_cvm",
]
QvlIdentityDomain = Literal[
    "diligence_qvl_cvm",
    "arena_qvl_cvm",
    "anchor_writer_qvl_cvm",
    "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm",
]
RawQuoteHex = Annotated[
    str,
    StringConstraints(
        min_length=2 + MIN_QUOTE_BYTES * 2,
        max_length=2 + MAX_QUOTE_BYTES * 2,
        pattern=r"^0x[0-9a-f]+$",
    ),
]
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SignerAttestationExpectation(StrictModel):
    """Exact public shape emitted by ``SignerAttestationEvidence.to_public_dict``."""

    mode: Literal["tdx"]
    signer_address: Address
    chain_id: int = Field(gt=0, le=2**63 - 1)
    contract_address: Address
    report_data: NonzeroBytes32
    quote_report_data: Bytes64
    quote_hash: NonzeroBytes32
    quote_size: int = Field(ge=MIN_QUOTE_BYTES, le=MAX_QUOTE_BYTES)
    compose_hash: NonzeroBytes32
    app_id: PhalaAppId
    os_image_hash: BareSha256
    raw_secret_egress: Literal[False]


class DiligenceResultAuthorizationRequest(StrictModel):
    """Exact bounded result context for the QVL's independent on-chain signature."""

    schema_id: Literal["dnai.diligence-qvl-result-authorization-request.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    deal_id: int = Field(ge=0, le=2**63 - 1)
    evaluator_policy_commitment: NonzeroBytes32
    result_hash: NonzeroBytes32
    authorization_expiry: int = Field(ge=1, le=4_102_444_800)


class ComputeMeteringAuthorizationRequest(StrictModel):
    """Exact ComputeCreditVault receipt fields for an independent raw signature."""

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

    @model_validator(mode="after")
    def require_coherent_usage_and_cap(self) -> "ComputeMeteringAuthorizationRequest":
        if (
            int(self.actual_asset_debit) > int(self.max_asset_debit)
            or int(self.billable_compute_units) == 0
            or self.usage_ended_at < self.usage_started_at
            or self.receipt_expiry > self.authorization_expiry
        ):
            raise ValueError("compute metering authorization is incoherent")
        return self


class ComputeWorkloadRecipientAttestation(StrictModel):
    """Dynamic main-CVM recipient identity bound into one fresh TDX quote.

    The dedicated Compute-workload QVL release pins the main CVM measurements,
    compose hash, app ID, and OS image.  These dynamic public values are sent
    with the quote so the QVL can independently rederive report data without
    pre-live injection of a recipient key or activation signer.
    """

    schema_id: Literal["dnai.compute-workload-recipient-attestation.v1"] = Field(
        alias="schema", serialization_alias="schema"
    )
    context: Literal["compute_workload"]
    audience: Literal["dnai-wikigen:compute-workload-recipient"]
    service: Literal["dnai-wikigen"]
    protocol: Literal["compute_workload_ingress_v1"]
    encryption_public_key: Hex32Raw
    key_id: Sha256KeyId
    activation_signer_address: Address
    activation_signer_key_path: Literal[
        "tinker/compute_workload_activation_signer"
    ]
    activation_signer_custody: Literal[
        "dstack_derived_compute_workload_activation_signer"
    ]
    chain_id: Literal[84_532]
    compute_vault_address: Address
    compute_vault_runtime_code_hash: NonzeroBytes32
    fresh_contract_deployment_receipt_sha256: NonzeroBytes32

    @model_validator(mode="after")
    def verify_key_and_addresses(self) -> "ComputeWorkloadRecipientAttestation":
        expected = "sha256:" + hashlib.sha256(
            bytes.fromhex(self.encryption_public_key)
        ).hexdigest()
        if self.key_id != expected:
            raise ValueError("Compute workload recipient key ID does not match public key")
        if any(
            int(address[2:], 16) == 0
            for address in (
                self.activation_signer_address,
                self.compute_vault_address,
            )
        ):
            raise ValueError("Compute workload recipient addresses must be nonzero")
        return self


class IndependentVerificationRequest(StrictModel):
    schema_id: Literal["dnai.independent-tdx-verification-request.v2"] = Field(alias="schema", serialization_alias="schema")
    challenge: "QvlChallenge"
    quote: RawQuoteHex
    expectation: SignerAttestationExpectation
    result_authorization: DiligenceResultAuthorizationRequest | None = None
    compute_authorization: ComputeMeteringAuthorizationRequest | None = None
    compute_workload_recipient: ComputeWorkloadRecipientAttestation | None = None

    @model_validator(mode="after")
    def require_one_authorization_domain(self) -> "IndependentVerificationRequest":
        domains = (
            self.result_authorization,
            self.compute_authorization,
            self.compute_workload_recipient,
        )
        if sum(value is not None for value in domains) > 1:
            raise ValueError("authorization domains are mutually exclusive")
        return self


class QvlChallengeRequest(StrictModel):
    schema_id: Literal["dnai.attestation-qvl-challenge-request.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    chain_id: int = Field(gt=0, le=2**63 - 1)
    domain: CvmDomain
    profile: QvlProfile
    cvm_id: CvmId
    deployment_intent_sha256: Sha256Digest
    release_authority_sha256: Sha256Digest
    ceremony_nonce: NonzeroBytes32
    measurement_policy_sha256: Sha256Digest


class QvlChallenge(StrictModel):
    schema_id: Literal["dnai.attestation-qvl-challenge.v2"] = Field(
        alias="schema", serialization_alias="schema"
    )
    chain_id: int = Field(gt=0, le=2**63 - 1)
    domain: CvmDomain
    profile: QvlProfile
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
    def require_positive_lifetime(self) -> "QvlChallenge":
        if self.expires_at <= self.issued_at:
            raise ValueError("challenge lifetime is invalid")
        return self


class TdxMeasurements(StrictModel):
    tee_tcb_svn: Hex16
    mr_seam: Hex48
    mr_signer_seam: Hex48
    seam_attributes: Hex8
    td_attributes: Hex8
    xfam: Hex8
    mr_td: Hex48
    mr_config_id: Hex48
    mr_owner: Hex48
    mr_owner_config: Hex48
    rt_mr0: Hex48
    rt_mr1: Hex48
    rt_mr2: Hex48
    rt_mr3: Hex48
    tee_tcb_svn2: Hex16 | None = None
    mr_service_td: Hex48 | None = None

    @model_validator(mode="after")
    def require_complete_v15_pair(self) -> "TdxMeasurements":
        if (self.tee_tcb_svn2 is None) != (self.mr_service_td is None):
            raise ValueError("TDX 1.5 measurements must be supplied together")
        return self


class DiligenceResultSignerBinding(StrictModel):
    kind: Literal["diligence_result_signer_v1"]


class ArenaCandidateIngressBinding(StrictModel):
    kind: Literal["arena_candidate_ingress_v1"]
    encryption_public_key: Hex32Raw
    key_id: Sha256KeyId

    @model_validator(mode="after")
    def verify_canonical_key_id(self) -> "ArenaCandidateIngressBinding":
        expected = "sha256:" + hashlib.sha256(bytes.fromhex(self.encryption_public_key)).hexdigest()
        if self.key_id != expected:
            raise ValueError("Arena ingress key ID does not match the public key")
        return self


class ExecutionPolicyAnchorWriterBinding(StrictModel):
    """Purpose-separated writer context committed into quote report data."""

    kind: Literal["execution_policy_anchor_writer_v1"]
    writer_release_commitment: NonzeroBytes32
    writer_key_path: Literal["tinker/execution_policy_anchor_writer"]
    writer_custody: Literal["dstack_derived_execution_policy_anchor_writer"]


class ComputeMeteringSignerBinding(StrictModel):
    """Purpose-separated ComputeCreditVault metering signer context."""

    kind: Literal["compute_metering_signer_v1"]
    policy_set_hash: NonzeroBytes32
    signer_custody: Literal["dstack_derived_independent_cvm"]


class ComputeWorkloadRecipientBinding(StrictModel):
    """Dynamic recipient report-data semantics for the main Compute CVM."""

    kind: Literal["compute_workload_recipient_v1"]


class EmailOracleKmsRestartBinding(StrictModel):
    """Exact main-CVM restart/KMS evidence authorized by the Diligence QVL."""

    kind: Literal["email_oracle_kms_restart_v1"]
    email_oracle_auth_address: Address
    email_oracle_auth_runtime_code_hash: NonzeroBytes32
    kms_proxy_address: Address
    kms_proxy_runtime_code_hash: NonzeroBytes32
    kms_implementation_address: Address
    kms_implementation_runtime_code_hash: NonzeroBytes32
    kms_eip1967_implementation_slot_word: NonzeroBytes32
    registration_tx_hash: NonzeroBytes32
    registration_block_number: int = Field(ge=1, le=2**63 - 1)
    registration_block_hash: NonzeroBytes32
    target_boot_tuple_hash: NonzeroBytes32
    restart_proof_hash: NonzeroBytes32

    @model_validator(mode="after")
    def require_slot_word_to_pin_implementation(self) -> "EmailOracleKmsRestartBinding":
        expected = "0x" + "00" * 12 + self.kms_implementation_address[2:]
        if self.kms_eip1967_implementation_slot_word != expected:
            raise ValueError(
                "EIP-1967 implementation slot word does not match implementation address"
            )
        return self


ReportDataBinding = Annotated[
    DiligenceResultSignerBinding
    | ArenaCandidateIngressBinding
    | ExecutionPolicyAnchorWriterBinding
    | ComputeWorkloadRecipientBinding
    | ComputeMeteringSignerBinding,
    Field(discriminator="kind"),
]


class ReleasePolicy(StrictModel):
    schema_id: Literal["dnai.attestation-qvl-release-policy.v1"] = Field(alias="schema", serialization_alias="schema")
    chain_id: int = Field(gt=0, le=2**63 - 1)
    contract_address: Address
    compose_hash: NonzeroBytes32
    app_id: PhalaAppId
    os_image_hash: BareSha256
    allowed_signer_addresses: tuple[Address, ...] = Field(max_length=64)
    report_data_binding: ReportDataBinding
    email_oracle_kms_restart_binding: EmailOracleKmsRestartBinding | None = None
    measurements: TdxMeasurements
    allowed_tcb_statuses: tuple[Literal["OK"], ...] = Field(default=("OK",), min_length=1, max_length=1)
    valid_from: int = Field(ge=1, le=4_102_444_800)
    valid_until: int = Field(ge=1, le=4_102_444_800)
    max_verdict_ttl_seconds: int = Field(ge=30, le=900)

    @field_validator("allowed_signer_addresses", "allowed_tcb_statuses", mode="before")
    @classmethod
    def require_json_array(cls, value: object) -> object:
        """Accept JSON arrays without weakening strict validation of their contents."""
        if not isinstance(value, list):
            raise ValueError("release-policy set fields must be JSON arrays")
        return tuple(value)

    @model_validator(mode="after")
    def validate_policy_sets_and_window(self) -> "ReleasePolicy":
        if self.valid_until <= self.valid_from:
            raise ValueError("release-policy validity window is invalid")
        if self.valid_until - self.valid_from < self.max_verdict_ttl_seconds:
            raise ValueError("release-policy validity is shorter than its verdict TTL")
        if len(set(self.allowed_signer_addresses)) != len(self.allowed_signer_addresses):
            raise ValueError("release-policy signer allowlist contains duplicates")
        if int(self.contract_address[2:], 16) == 0 or any(
            int(address[2:], 16) == 0 for address in self.allowed_signer_addresses
        ):
            raise ValueError("release-policy contract and signer addresses must be nonzero")
        if self.allowed_tcb_statuses != ("OK",):
            raise ValueError("this release accepts only the exact DCAP status OK")
        if isinstance(self.report_data_binding, ComputeWorkloadRecipientBinding):
            if self.chain_id != 84_532:
                raise ValueError("compute workload attestation is Base Sepolia only")
            if self.allowed_signer_addresses:
                raise ValueError(
                    "compute workload release must not pre-pin a dynamic activation signer"
                )
        elif not self.allowed_signer_addresses:
            raise ValueError("release-policy signer allowlist must not be empty")
        if isinstance(self.report_data_binding, ComputeMeteringSignerBinding):
            if self.chain_id != 84_532:
                raise ValueError("compute metering attestation is Base Sepolia only")
            if int(self.contract_address[2:], 16) == 0:
                raise ValueError("compute metering vault must be nonzero")
            if len(self.allowed_signer_addresses) != 1:
                raise ValueError("compute metering release must pin exactly one signer")
        if self.email_oracle_kms_restart_binding is not None:
            if not isinstance(self.report_data_binding, DiligenceResultSignerBinding):
                raise ValueError("email/KMS restart binding is restricted to the Diligence QVL")
            if self.chain_id != 84_532 or len(self.allowed_signer_addresses) != 1:
                raise ValueError("email/KMS restart release must pin Base Sepolia and one signer")
            binding = self.email_oracle_kms_restart_binding
            if any(
                int(address[2:], 16) == 0
                for address in (
                    binding.email_oracle_auth_address,
                    binding.kms_proxy_address,
                    binding.kms_implementation_address,
                )
            ):
                raise ValueError("email/KMS restart addresses must be nonzero")
        return self


class IndependentTdxVerdict(StrictModel):
    schema_id: Literal["dnai.independent-tdx-verdict.v4"] = Field(alias="schema", serialization_alias="schema")
    verification_method: Literal["intel_tdx_dcap_qvl"]
    verified: Literal[True]
    chain_id: int = Field(gt=0, le=2**63 - 1)
    domain: CvmDomain
    profile: QvlProfile
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
    activation_evidence_lease_expires_at: int = Field(ge=1, le=4_102_444_800)
    expires_at: int = Field(ge=1, le=4_102_444_800)
    verifier_address: Address
    verifier_signature: Signature65
    qvl_deal_id: int | None = Field(default=None, ge=0, le=2**63 - 1)
    qvl_evaluator_policy_commitment: NonzeroBytes32 | None = None
    qvl_result_hash: NonzeroBytes32 | None = None
    qvl_attestation_evidence_hash: NonzeroBytes32 | None = None
    qvl_authorization_expiry: int | None = Field(default=None, ge=1, le=4_102_444_800)
    qvl_authorization_digest: NonzeroBytes32 | None = None
    qvl_authorization_signature: Signature65 | None = None
    qvl_compute_attestation_evidence_hash: NonzeroBytes32 | None = None
    qvl_compute_authorization_expiry: int | None = Field(
        default=None, ge=1, le=4_102_444_800
    )
    qvl_compute_authorization_digest: NonzeroBytes32 | None = None
    qvl_compute_authorization_signature: Signature65 | None = None

    @model_validator(mode="after")
    def require_complete_qvl_result_authorization(self) -> "IndependentTdxVerdict":
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
            self.qvl_deal_id,
            self.qvl_evaluator_policy_commitment,
            self.qvl_result_hash,
            self.qvl_attestation_evidence_hash,
            self.qvl_authorization_expiry,
            self.qvl_authorization_digest,
            self.qvl_authorization_signature,
        )
        if any(value is not None for value in values) and any(value is None for value in values):
            raise ValueError("QVL result authorization fields must be supplied together")
        compute_values = (
            self.qvl_compute_attestation_evidence_hash,
            self.qvl_compute_authorization_expiry,
            self.qvl_compute_authorization_digest,
            self.qvl_compute_authorization_signature,
        )
        if any(value is not None for value in compute_values) and any(
            value is None for value in compute_values
        ):
            raise ValueError("QVL compute authorization fields must be supplied together")
        if any(value is not None for value in values) and any(
            value is not None for value in compute_values
        ):
            raise ValueError("QVL authorization domains are mutually exclusive")
        return self


class IdentityResponse(StrictModel):
    schema_id: Literal["dnai.attestation-qvl-identity.v1"] = Field(alias="schema", serialization_alias="schema")
    verifier_address: Address
    release_policy_hash: NonzeroBytes32
    signer_custody: Literal["dstack_derived_separate_cvm"]
    raw_secret_egress: Literal[False]


class IdentityAttestationRequest(StrictModel):
    """Externally generated activation-verifier challenge.

    The authenticated caller chooses a cryptographically random challenge ID.
    The digest is deterministic so the QVL cannot substitute a different
    second-half report-data binding while retaining the caller's envelope.
    """

    schema_id: Literal["dnai.qvl-identity-attestation-request.v3"] = Field(
        alias="schema", serialization_alias="schema"
    )
    chain_id: int = Field(gt=0, le=2**63 - 1)
    domain: QvlIdentityDomain
    profile: QvlProfile
    cvm_id: CvmId
    deployment_intent_sha256: Sha256Digest
    release_authority_sha256: Sha256Digest
    ceremony_nonce: NonzeroBytes32
    measurement_policy_sha256: Sha256Digest
    app_id: PhalaAppId
    compose_hash: BareSha256
    os_image_hash: BareSha256
    challenge_id: NonzeroBytes32
    challenge_digest: NonzeroBytes32
    issued_at: int = Field(ge=1, le=4_102_444_800)
    expires_at: int = Field(ge=1, le=4_102_444_800)

    @model_validator(mode="after")
    def require_positive_lifetime(self) -> "IdentityAttestationRequest":
        if self.expires_at <= self.issued_at:
            raise ValueError("activation challenge lifetime is invalid")
        return self


class IdentityAttestationResponse(StrictModel):
    schema_id: Literal["dnai.qvl-identity-attestation-response.v3"] = Field(alias="schema", serialization_alias="schema")
    chain_id: int = Field(gt=0, le=2**63 - 1)
    domain: QvlIdentityDomain
    profile: QvlProfile
    cvm_id: CvmId
    deployment_intent_sha256: Sha256Digest
    release_authority_sha256: Sha256Digest
    ceremony_nonce: NonzeroBytes32
    measurement_policy_sha256: Sha256Digest
    verifier_address: Address
    release_policy_hash: NonzeroBytes32
    report_data: NonzeroBytes32
    quote_report_data: Bytes64
    challenge_id: NonzeroBytes32
    challenge_digest: NonzeroBytes32
    challenge_issued_at: int = Field(ge=1, le=4_102_444_800)
    challenge_expires_at: int = Field(ge=1, le=4_102_444_800)
    quote: RawQuoteHex
    quote_hash: NonzeroBytes32
    quote_size: int = Field(ge=MIN_QUOTE_BYTES, le=MAX_QUOTE_BYTES)
    app_id: PhalaAppId
    compose_hash: BareSha256
    os_image_hash: BareSha256
    raw_secret_egress: Literal[False]
