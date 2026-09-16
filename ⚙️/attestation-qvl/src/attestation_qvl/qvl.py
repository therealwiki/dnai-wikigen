"""Production DCAP-QVL adapter and independent release-policy enforcement."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Protocol

import dcap_qvl

from .errors import VerificationRejected, VerifierUnavailable
from .challenge import qvl_profiles
from .models import (
    ArenaCandidateIngressBinding,
    ComputeMeteringSignerBinding,
    ComputeWorkloadRecipientAttestation,
    ComputeWorkloadRecipientBinding,
    DiligenceResultSignerBinding,
    EmailOracleKmsRestartBinding,
    ExecutionPolicyAnchorWriterBinding,
    IndependentTdxVerdict,
    IndependentVerificationRequest,
    MAX_QUOTE_BYTES,
    MIN_QUOTE_BYTES,
    RoyaltySettlementAuthorizationRequest,
    RoyaltySettlementQvlBinding,
)
from .policy import LoadedReleasePolicy
from .signing import (
    VerdictSigner,
    compute_metering_qvl_authorization_digest,
    diligence_qvl_result_authorization_digest,
    independent_verdict_digest,
    RoyaltySettlementSigner,
    royalty_collaboration_resource_hash,
    recover_raw_digest_address,
    royalty_release_policy_commitment,
    royalty_settlement_authorization_digest,
    royalty_settlement_decision_hash,
    royalty_settlement_qvl_authorization_digest,
)


BASE_MEASUREMENT_FIELDS = (
    "tee_tcb_svn",
    "mr_seam",
    "mr_signer_seam",
    "seam_attributes",
    "td_attributes",
    "xfam",
    "mr_td",
    "mr_config_id",
    "mr_owner",
    "mr_owner_config",
    "rt_mr0",
    "rt_mr1",
    "rt_mr2",
    "rt_mr3",
)
V15_MEASUREMENT_FIELDS = ("tee_tcb_svn2", "mr_service_td")
COMPUTE_METERING_REPORT_DATA_DOMAIN = (
    b"dnai-wikigen/compute-metering-signer-attestation/v1\x00"
)
COMPUTE_METERING_CUSTODY = "dstack_derived_independent_cvm"
COMPUTE_METERING_EVIDENCE_DOMAIN = (
    b"dnai-wikigen/compute-metering-attestation-evidence/v1\x00"
)
EMAIL_ORACLE_KMS_RESTART_DOMAIN = (
    b"dnai-wikigen/email-oracle-kms-restart-attestation/v1\x00"
)
COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN = (
    b"dnai-wikigen/compute-workload-recipient-attestation/v1\x00"
)
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


@dataclass(frozen=True)
class VerifiedQuote:
    quote_type: str
    status: str
    report_data: bytes
    measurements: dict[str, bytes]


class QuoteVerificationBackend(Protocol):
    async def verify(self, raw_quote: bytes) -> VerifiedQuote:
        """Cryptographically verify and parse one immutable quote byte string."""


class DcapQvlBackend:
    """Official Phala dcap-qvl 0.5.2 adapter."""

    def __init__(self, pccs_url: str):
        self._pccs_url = pccs_url

    async def verify(self, raw_quote: bytes) -> VerifiedQuote:
        try:
            parsed = dcap_qvl.parse_quote(raw_quote)
            if not parsed.is_tdx() or parsed.quote_type() != "TDX":
                raise VerificationRejected
            verified = await dcap_qvl.get_collateral_and_verify(raw_quote, self._pccs_url)
            report = parsed.report
            fields = list(BASE_MEASUREMENT_FIELDS)
            has_v15 = hasattr(report, "tee_tcb_svn2") or hasattr(report, "mr_service_td")
            if has_v15:
                if not all(hasattr(report, field) for field in V15_MEASUREMENT_FIELDS):
                    raise VerificationRejected
                fields.extend(V15_MEASUREMENT_FIELDS)
            measurements = {field: bytes(getattr(report, field)) for field in fields}
            report_data = bytes(report.report_data)
            if not isinstance(verified.status, str):
                raise VerificationRejected
            status = verified.status
        except VerificationRejected:
            raise
        except RuntimeError as exc:
            raise VerifierUnavailable from exc
        except Exception as exc:
            raise VerificationRejected from exc
        return VerifiedQuote(
            quote_type="TDX",
            status=status,
            report_data=report_data,
            measurements=measurements,
        )


def derive_signer_report_data(*, signer_address: str, chain_id: int, contract_address: str) -> bytes:
    encoded = json.dumps(
        {
            "service": "dnai-wikigen",
            "context": "diligence-room-submit-result",
            "signer_address": signer_address.lower(),
            "chain_id": chain_id,
            "contract_address": contract_address.lower(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def derive_compute_metering_attestation_evidence_hash(
    request: IndependentVerificationRequest,
    binding: ComputeMeteringSignerBinding,
) -> str:
    """Match the meter's hash of the complete bounded quote packet."""

    challenge = request.challenge
    expectation = request.expectation
    payload = {
        "schema": "dnai.compute-metering-attestation-evidence.v1",
        "chain_id": challenge.chain_id,
        "domain": challenge.domain,
        "profile": challenge.profile,
        "cvm_id": challenge.cvm_id,
        "deployment_intent_sha256": challenge.deployment_intent_sha256,
        "release_authority_sha256": challenge.release_authority_sha256,
        "ceremony_nonce": challenge.ceremony_nonce,
        "measurement_policy_sha256": challenge.measurement_policy_sha256,
        "release_policy_hash": challenge.release_policy_hash,
        "challenge_id": challenge.challenge_id,
        "challenge_digest": challenge.challenge_digest,
        "quote_hash": expectation.quote_hash,
        "report_data": expectation.report_data,
        "quote_report_data": expectation.quote_report_data,
        "compose_hash": expectation.compose_hash,
        "app_id": expectation.app_id,
        "os_image_hash": expectation.os_image_hash,
        "signer_address": expectation.signer_address,
        "contract_address": expectation.contract_address,
        "policy_set_hash": binding.policy_set_hash,
        "signer_custody": binding.signer_custody,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "0x" + hashlib.sha256(COMPUTE_METERING_EVIDENCE_DOMAIN + encoded).hexdigest()


def _canonical_commitment(domain: bytes, payload: dict[str, object]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return "0x" + hashlib.sha256(domain + encoded).hexdigest()


def derive_royalty_settlement_policy_commitment(
    *,
    release: LoadedReleasePolicy,
    binding: RoyaltySettlementQvlBinding,
    royalty_verifier_address: str,
) -> str:
    """Commit the complete reviewed secondary policy and its derived signer."""

    payload = {
        "schema": "dnai.royalty-settlement-qvl-policy.v2",
        "authorization_schema": (
            "dnai.royalty-settlement-qvl-authorization-request.v2"
        ),
        "qvl_release_policy_hash": release.policy_hash,
        "chain_id": release.policy.chain_id,
        "compose_hash": release.policy.compose_hash,
        "app_id": release.policy.app_id,
        "os_image_hash": release.policy.os_image_hash,
        "royalty_qvl_verifier": royalty_verifier_address,
        "binding": binding.model_dump(mode="json"),
    }
    return _canonical_commitment(ROYALTY_SETTLEMENT_POLICY_DOMAIN, payload)


def derive_royalty_settlement_report_data(
    *,
    release: LoadedReleasePolicy,
    binding: RoyaltySettlementQvlBinding,
    royalty_verifier_address: str,
    royalty_policy_commitment: str,
) -> bytes:
    """Purpose-separate the main-runtime royalty signer quote from Diligence."""

    payload = {
        "schema": "dnai.royalty-settlement-signer-attestation.v1",
        "chain_id": release.policy.chain_id,
        "main_runtime_cvm_id": binding.main_runtime_cvm_id,
        "deployment_intent_sha256": binding.deployment_intent_sha256,
        "release_authority_sha256": binding.release_authority_sha256,
        "measurement_policy_sha256": binding.measurement_policy_sha256,
        "compose_hash": release.policy.compose_hash,
        "app_id": release.policy.app_id,
        "os_image_hash": release.policy.os_image_hash,
        "distributor_address": binding.distributor_address,
        "distributor_runtime_code_hash": binding.distributor_runtime_code_hash,
        "settlement_verifier": binding.settlement_verifier,
        "settlement_verifier_key_path": binding.settlement_verifier_key_path,
        "settlement_verifier_custody": binding.settlement_verifier_custody,
        "release_policy_commitment": binding.release_policy_commitment,
        "royalty_qvl_verifier": royalty_verifier_address,
        "royalty_policy_commitment": royalty_policy_commitment,
    }
    return bytes.fromhex(
        _canonical_commitment(ROYALTY_SETTLEMENT_REPORT_DATA_DOMAIN, payload)[2:]
    )


def derive_royalty_settlement_attestation_evidence_hash(
    *,
    request: IndependentVerificationRequest,
    binding: RoyaltySettlementQvlBinding,
    royalty_verifier_address: str,
    royalty_policy_commitment: str,
) -> str:
    """Commit the fresh quote packet without creating a self-hash cycle."""

    challenge = request.challenge
    expectation = request.expectation
    payload = {
        "schema": "dnai.royalty-settlement-attestation-evidence.v1",
        "chain_id": challenge.chain_id,
        "domain": challenge.domain,
        "profile": challenge.profile,
        "cvm_id": challenge.cvm_id,
        "deployment_intent_sha256": challenge.deployment_intent_sha256,
        "release_authority_sha256": challenge.release_authority_sha256,
        "ceremony_nonce": challenge.ceremony_nonce,
        "measurement_policy_sha256": challenge.measurement_policy_sha256,
        "qvl_release_policy_hash": challenge.release_policy_hash,
        "challenge_id": challenge.challenge_id,
        "challenge_digest": challenge.challenge_digest,
        "quote_hash": expectation.quote_hash,
        "report_data": expectation.report_data,
        "quote_report_data": expectation.quote_report_data,
        "compose_hash": expectation.compose_hash,
        "app_id": expectation.app_id,
        "os_image_hash": expectation.os_image_hash,
        "settlement_verifier": expectation.signer_address,
        "distributor_address": expectation.contract_address,
        "distributor_runtime_code_hash": binding.distributor_runtime_code_hash,
        "release_policy_commitment": binding.release_policy_commitment,
        "execution_policy_anchor": binding.execution_policy_anchor,
        "anchor_writer_release_commitment": (
            binding.anchor_writer_release_commitment
        ),
        "royalty_qvl_verifier": royalty_verifier_address,
        "royalty_policy_commitment": royalty_policy_commitment,
    }
    return _canonical_commitment(ROYALTY_SETTLEMENT_EVIDENCE_DOMAIN, payload)


def derive_royalty_settlement_anchor_evidence_commitment(
    *,
    authorization: RoyaltySettlementAuthorizationRequest,
    binding: RoyaltySettlementQvlBinding,
    attestation_evidence_hash: str,
) -> str:
    """Bounded commitment to the exact policy-pinned on-chain anchor tuple."""

    payload = {
        "schema": "dnai.royalty-settlement-anchor-evidence.v2",
        "execution_policy_anchor": binding.execution_policy_anchor,
        "anchor_writer_release_commitment": (
            binding.anchor_writer_release_commitment
        ),
        "release_policy_commitment": authorization.release_policy_commitment,
        "funding_reservation_id": authorization.funding_reservation_id,
        "anchor_resource_hash": authorization.anchor_resource_hash,
        "anchor_decision_hash": authorization.anchor_decision_hash,
        "anchor_sequence": authorization.anchor_sequence,
        "attestation_evidence_hash": attestation_evidence_hash,
    }
    return _canonical_commitment(
        ROYALTY_SETTLEMENT_ANCHOR_EVIDENCE_DOMAIN, payload
    )


def derive_arena_report_data(*, encryption_public_key: str, key_id: str) -> bytes:
    public_key = bytes.fromhex(encryption_public_key)
    expected_key_id = "sha256:" + hashlib.sha256(public_key).hexdigest()
    if len(public_key) != 32 or key_id != expected_key_id:
        raise VerificationRejected
    encoded = json.dumps(
        {
            "context": "arena",
            "encryption_public_key": encryption_public_key,
            "key_id": key_id,
            "protocol": "arena_candidate_ingress_v1",
            "service": "dnai-wikigen",
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def derive_execution_policy_anchor_writer_report_data(
    *,
    writer_address: str,
    chain_id: int,
    anchor_address: str,
    writer_release_commitment: str,
    writer_key_path: str,
    writer_custody: str,
) -> bytes:
    """Derive the exact release/writer context expected from the bootstrap CVM."""

    payload = {
        "schema": "dnai.execution-policy-anchor-writer-qvl-evidence.v1",
        "chain_id": chain_id,
        "anchor_address": anchor_address.lower(),
        "writer_address": writer_address.lower(),
        "writer_release_commitment": writer_release_commitment.lower(),
        "writer_key_path": writer_key_path,
        "writer_custody": writer_custody,
    }
    return hashlib.sha256(
        b"dnai-wikigen/execution-policy-anchor-writer-evidence/v1\x00"
        + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).digest()


def derive_compute_metering_report_data(
    *,
    metering_verifier: str,
    chain_id: int,
    vault_address: str,
    policy_set_hash: str,
    signer_custody: str,
) -> bytes:
    """Reproduce the metering CVM's purpose-separated quote binding exactly."""

    verifier = metering_verifier.lower()
    vault = vault_address.lower()
    policy_hash = policy_set_hash.lower()
    if (
        type(chain_id) is not int
        or chain_id != 84_532
        or signer_custody != COMPUTE_METERING_CUSTODY
        or not re.fullmatch(r"0x(?!0{40}$)[0-9a-f]{40}", verifier)
        or not re.fullmatch(r"0x(?!0{40}$)[0-9a-f]{40}", vault)
        or not re.fullmatch(r"0x(?!0{64}$)[0-9a-f]{64}", policy_hash)
    ):
        raise VerificationRejected
    payload = {
        "schema": "dnai.compute-metering-signer-attestation.v1",
        "chain_id": chain_id,
        "vault_address": vault,
        "metering_verifier": verifier,
        "policy_set_hash": policy_hash,
        "signer_custody": signer_custody,
    }
    return hashlib.sha256(
        COMPUTE_METERING_REPORT_DATA_DOMAIN
        + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).digest()


def derive_compute_workload_recipient_report_data(
    attestation: ComputeWorkloadRecipientAttestation,
) -> bytes:
    """Reproduce the main CVM's dynamic recipient/activation quote binding."""

    if not isinstance(attestation, ComputeWorkloadRecipientAttestation):
        raise VerificationRejected
    encoded = json.dumps(
        attestation.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(
        COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN + encoded
    ).digest()


def derive_email_oracle_kms_restart_report_data(
    *,
    signer_address: str,
    chain_id: int,
    binding: EmailOracleKmsRestartBinding,
) -> bytes:
    """Commit the exact reviewed main-CVM KMS/restart evidence tuple."""

    payload = {
        "schema": "dnai.email-oracle-kms-restart-attestation.v1",
        "chain_id": chain_id,
        "main_cvm_signer": signer_address.lower(),
        **binding.model_dump(mode="json", exclude={"kind"}),
    }
    return hashlib.sha256(
        EMAIL_ORACLE_KMS_RESTART_DOMAIN
        + json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).digest()


def derive_release_report_data(
    binding: (
        DiligenceResultSignerBinding
        | ArenaCandidateIngressBinding
        | ExecutionPolicyAnchorWriterBinding
        | ComputeWorkloadRecipientBinding
        | ComputeMeteringSignerBinding
    ),
    *,
    signer_address: str,
    chain_id: int,
    contract_address: str,
) -> bytes:
    if isinstance(binding, DiligenceResultSignerBinding):
        return derive_signer_report_data(
            signer_address=signer_address,
            chain_id=chain_id,
            contract_address=contract_address,
        )
    if isinstance(binding, ArenaCandidateIngressBinding):
        return derive_arena_report_data(
            encryption_public_key=binding.encryption_public_key,
            key_id=binding.key_id,
        )
    if isinstance(binding, ExecutionPolicyAnchorWriterBinding):
        return derive_execution_policy_anchor_writer_report_data(
            writer_address=signer_address,
            chain_id=chain_id,
            anchor_address=contract_address,
            writer_release_commitment=binding.writer_release_commitment,
            writer_key_path=binding.writer_key_path,
            writer_custody=binding.writer_custody,
        )
    if isinstance(binding, ComputeMeteringSignerBinding):
        return derive_compute_metering_report_data(
            metering_verifier=signer_address,
            chain_id=chain_id,
            vault_address=contract_address,
            policy_set_hash=binding.policy_set_hash,
            signer_custody=binding.signer_custody,
        )
    # This binding is request-dynamic and must be handled explicitly by
    # ``IndependentQuoteVerifier.verify``.  It has no safe static derivation.
    if isinstance(binding, ComputeWorkloadRecipientBinding):
        raise VerificationRejected
    raise VerificationRejected


def decode_quote(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value[2:])
    except (ValueError, TypeError) as exc:
        raise VerificationRejected from exc
    if len(raw) < MIN_QUOTE_BYTES or len(raw) > MAX_QUOTE_BYTES:
        raise VerificationRejected
    return raw


class IndependentQuoteVerifier:
    def __init__(
        self,
        *,
        release: LoadedReleasePolicy,
        backend: QuoteVerificationBackend,
        signer: VerdictSigner,
        royalty_signer: RoyaltySettlementSigner | None = None,
        clock: Callable[[], int] | None = None,
    ):
        self.release = release
        self.backend = backend
        self.signer = signer
        self.royalty_signer = royalty_signer
        self._clock = clock or (lambda: int(time.time()))
        if signer.address in release.policy.allowed_signer_addresses:
            raise VerifierUnavailable
        royalty_binding = release.policy.royalty_settlement_binding
        if (royalty_binding is None) != (royalty_signer is None):
            raise VerifierUnavailable
        self.royalty_policy_commitment: str | None = None
        if royalty_binding is not None and royalty_signer is not None:
            forbidden_roles = {
                signer.address,
                release.policy.contract_address,
                royalty_binding.owner,
                royalty_binding.distributor_address,
                royalty_binding.settlement_verifier,
                royalty_binding.execution_policy_anchor,
            }
            if royalty_signer.address in forbidden_roles:
                raise VerifierUnavailable
            expected_release = royalty_release_policy_commitment(
                chain_id=release.policy.chain_id,
                distributor_address=royalty_binding.distributor_address,
                authority_nonce=int(royalty_binding.authority_nonce),
                settlement_verifier=royalty_binding.settlement_verifier,
                qvl_verifier=royalty_signer.address,
                execution_policy_anchor=royalty_binding.execution_policy_anchor,
                anchor_writer_release_commitment=(
                    royalty_binding.anchor_writer_release_commitment
                ),
            )
            if expected_release != royalty_binding.release_policy_commitment:
                raise VerifierUnavailable
            self.royalty_policy_commitment = (
                derive_royalty_settlement_policy_commitment(
                    release=release,
                    binding=royalty_binding,
                    royalty_verifier_address=royalty_signer.address,
                )
            )

    async def verify(self, request: IndependentVerificationRequest) -> IndependentTdxVerdict:
        policy = self.release.policy
        started_at = int(self._clock())
        if started_at < policy.valid_from or started_at >= policy.valid_until:
            raise VerificationRejected

        raw_quote = decode_quote(request.quote)
        quote_hash = "0x" + hashlib.sha256(raw_quote).hexdigest()
        expectation = request.expectation
        if expectation.quote_size != len(raw_quote) or expectation.quote_hash != quote_hash:
            raise VerificationRejected

        challenge = request.challenge
        royalty_binding = policy.royalty_settlement_binding
        royalty_profile = challenge.profile == "royalty_settlement"
        if royalty_profile:
            if (
                royalty_binding is None
                or self.royalty_signer is None
                or self.royalty_policy_commitment is None
                or request.royalty_authorization is None
                or request.compute_workload_recipient is not None
                or challenge.cvm_id != royalty_binding.main_runtime_cvm_id
                or challenge.deployment_intent_sha256
                != royalty_binding.deployment_intent_sha256
                or challenge.release_authority_sha256
                != royalty_binding.release_authority_sha256
                or challenge.measurement_policy_sha256
                != royalty_binding.measurement_policy_sha256
            ):
                raise VerificationRejected
            signer_address = royalty_binding.settlement_verifier
            expected_contract_address = royalty_binding.distributor_address
            expected_report_data = derive_royalty_settlement_report_data(
                release=self.release,
                binding=royalty_binding,
                royalty_verifier_address=self.royalty_signer.address,
                royalty_policy_commitment=self.royalty_policy_commitment,
            )
        elif isinstance(policy.report_data_binding, ComputeWorkloadRecipientBinding):
            recipient_attestation = request.compute_workload_recipient
            if (
                recipient_attestation is None
                or challenge.profile != "compute_workload"
                or recipient_attestation.chain_id != policy.chain_id
                or recipient_attestation.compute_vault_address
                != policy.contract_address
                or recipient_attestation.activation_signer_address
                != expectation.signer_address
            ):
                raise VerificationRejected
            signer_address = recipient_attestation.activation_signer_address
            expected_contract_address = policy.contract_address
            expected_report_data = derive_compute_workload_recipient_report_data(
                recipient_attestation
            )
        else:
            if request.compute_workload_recipient is not None:
                raise VerificationRejected
            allowed_signers = {
                value: value for value in policy.allowed_signer_addresses
            }
            signer_address = allowed_signers.get(expectation.signer_address)
            if signer_address is None:
                raise VerificationRejected
            expected_contract_address = policy.contract_address
        if challenge.profile == "email_oracle_kms_restart":
            binding = policy.email_oracle_kms_restart_binding
            if binding is None:
                raise VerificationRejected
            expected_report_data = derive_email_oracle_kms_restart_report_data(
                signer_address=signer_address,
                chain_id=policy.chain_id,
                binding=binding,
            )
        elif royalty_profile:
            pass
        elif not isinstance(
            policy.report_data_binding, ComputeWorkloadRecipientBinding
        ):
            expected_report_data = derive_release_report_data(
                policy.report_data_binding,
                signer_address=signer_address,
                chain_id=policy.chain_id,
                contract_address=policy.contract_address,
            )
        report_data_hex = "0x" + expected_report_data.hex()
        profile = challenge.profile
        if profile not in qvl_profiles(policy):
            raise VerificationRejected
        if request.result_authorization is not None and profile != "diligence":
            raise VerificationRejected
        if request.compute_authorization is not None and profile != "compute_metering":
            raise VerificationRejected
        if request.royalty_authorization is not None and profile != "royalty_settlement":
            raise VerificationRejected
        expected_quote_report_data = (
            "0x" + expected_report_data.hex() + challenge.challenge_digest[2:]
        )
        if (
            challenge.profile != profile
            or challenge.chain_id != policy.chain_id
            or challenge.release_policy_hash != self.release.policy_hash
            or challenge.verifier_address != self.signer.address
            or challenge.expires_at <= started_at
            or expectation.mode != "tdx"
            or expectation.chain_id != policy.chain_id
            or expectation.contract_address != expected_contract_address
            or expectation.compose_hash != policy.compose_hash
            or expectation.app_id != policy.app_id
            or expectation.os_image_hash != policy.os_image_hash
            or expectation.report_data != report_data_hex
            or expectation.quote_report_data != expected_quote_report_data
            or expectation.raw_secret_egress is not False
        ):
            raise VerificationRejected

        verified = await self.backend.verify(raw_quote)
        if verified.quote_type != "TDX" or verified.status not in policy.allowed_tcb_statuses:
            raise VerificationRejected
        if len(verified.report_data) != 64:
            raise VerificationRejected
        if (
            verified.report_data[:32] != expected_report_data
            or verified.report_data[32:] != bytes.fromhex(challenge.challenge_digest[2:])
        ):
            raise VerificationRejected

        actual_measurements = {key: value.hex() for key, value in verified.measurements.items()}
        expected_measurements = policy.measurements.model_dump(mode="json", exclude_none=True)
        if actual_measurements != expected_measurements:
            raise VerificationRejected
        td_attributes = verified.measurements.get("td_attributes", b"")
        if len(td_attributes) != 8 or int.from_bytes(td_attributes, "little") & 1:
            raise VerificationRejected

        completed_at = int(self._clock())
        if (
            completed_at < started_at
            or completed_at >= challenge.expires_at
            or completed_at >= policy.valid_until
        ):
            raise VerificationRejected
        expires_at = min(
            completed_at + policy.max_verdict_ttl_seconds,
            policy.valid_until,
        )
        if expires_at <= completed_at:
            raise VerificationRejected
        unsigned: dict[str, object] = {
            "schema": "dnai.independent-tdx-verdict.v4",
            "verification_method": "intel_tdx_dcap_qvl",
            "verified": True,
            "chain_id": challenge.chain_id,
            "domain": challenge.domain,
            "profile": profile,
            "cvm_id": challenge.cvm_id,
            "deployment_intent_sha256": challenge.deployment_intent_sha256,
            "release_authority_sha256": challenge.release_authority_sha256,
            "ceremony_nonce": challenge.ceremony_nonce,
            "measurement_policy_sha256": challenge.measurement_policy_sha256,
            "release_policy_hash": self.release.policy_hash,
            "challenge_id": challenge.challenge_id,
            "challenge_digest": challenge.challenge_digest,
            "challenge_issued_at": challenge.issued_at,
            "challenge_expires_at": challenge.expires_at,
            "quote_hash": quote_hash,
            "report_data": report_data_hex,
            "compose_hash": policy.compose_hash,
            "app_id": policy.app_id,
            "os_image_hash": policy.os_image_hash,
            "signer_address": signer_address,
            "contract_address": expected_contract_address,
            "issued_at": completed_at,
            "activation_evidence_lease_expires_at": expires_at,
            "expires_at": expires_at,
            "verifier_address": self.signer.address,
        }
        result_authorization = request.result_authorization
        if result_authorization is not None:
            # The settlement signature is deliberately unavailable to every
            # other QVL profile.  Those profiles can still obtain a generic
            # quote verdict, but they cannot authorize a DiligenceRoom result.
            if profile != "diligence":
                raise VerificationRejected
            if (
                result_authorization.authorization_expiry <= completed_at
                or result_authorization.authorization_expiry > completed_at + 600
                or result_authorization.authorization_expiry > expires_at
                or result_authorization.authorization_expiry > challenge.expires_at
            ):
                raise VerificationRejected
            authorization_digest = diligence_qvl_result_authorization_digest(
                chain_id=policy.chain_id,
                contract_address=policy.contract_address,
                deal_id=result_authorization.deal_id,
                tee_identity=signer_address,
                compose_hash=policy.compose_hash,
                evaluator_policy_commitment=(
                    result_authorization.evaluator_policy_commitment
                ),
                result_hash=result_authorization.result_hash,
                attestation_release_policy_hash=self.release.policy_hash,
                attestation_evidence_hash=quote_hash,
                authorization_expiry=result_authorization.authorization_expiry,
            )
            unsigned.update(
                {
                    "qvl_deal_id": result_authorization.deal_id,
                    "qvl_evaluator_policy_commitment": (
                        result_authorization.evaluator_policy_commitment
                    ),
                    "qvl_result_hash": result_authorization.result_hash,
                    "qvl_attestation_evidence_hash": quote_hash,
                    "qvl_authorization_expiry": (
                        result_authorization.authorization_expiry
                    ),
                    "qvl_authorization_digest": authorization_digest,
                    "qvl_authorization_signature": self.signer.sign_digest(
                        authorization_digest
                    ),
                }
            )
        compute_authorization = request.compute_authorization
        if compute_authorization is not None:
            binding = policy.report_data_binding
            if profile != "compute_metering" or not isinstance(
                binding, ComputeMeteringSignerBinding
            ):
                raise VerificationRejected
            evidence_hash = derive_compute_metering_attestation_evidence_hash(
                request, binding
            )
            if (
                compute_authorization.metering_policy_set_hash
                != binding.policy_set_hash
                or compute_authorization.compose_hash != policy.compose_hash
                or compute_authorization.attestation_evidence_hash != evidence_hash
                or compute_authorization.receipt_expiry <= completed_at
                or compute_authorization.receipt_expiry > completed_at + 600
                or compute_authorization.receipt_expiry > expires_at
                or compute_authorization.receipt_expiry > challenge.expires_at
                or compute_authorization.usage_ended_at > completed_at + 5
            ):
                raise VerificationRejected
            authorization_digest = compute_metering_qvl_authorization_digest(
                chain_id=policy.chain_id,
                contract_address=policy.contract_address,
                project_id=compute_authorization.project_id,
                job_id=compute_authorization.job_id,
                user=compute_authorization.user,
                asset=compute_authorization.asset,
                authorization_nonce=int(compute_authorization.authorization_nonce),
                max_asset_debit=int(compute_authorization.max_asset_debit),
                actual_asset_debit=int(compute_authorization.actual_asset_debit),
                authorization_expiry=compute_authorization.authorization_expiry,
                rate_policy_commitment=compute_authorization.rate_policy_commitment,
                workload_commitment=compute_authorization.workload_commitment,
                manifest_commitment=compute_authorization.manifest_commitment,
                dispatch_intent_commitment=(
                    compute_authorization.dispatch_intent_commitment
                ),
                tee_identity=compute_authorization.tee_identity,
                compose_hash=compute_authorization.compose_hash,
                start_commitment=compute_authorization.start_commitment,
                billable_compute_units=int(
                    compute_authorization.billable_compute_units
                ),
                usage_started_at=compute_authorization.usage_started_at,
                usage_ended_at=compute_authorization.usage_ended_at,
                usage_commitment=compute_authorization.usage_commitment,
                metering_policy_set_hash=(
                    compute_authorization.metering_policy_set_hash
                ),
                attestation_evidence_hash=evidence_hash,
                receipt_expiry=compute_authorization.receipt_expiry,
            )
            unsigned.update(
                {
                    "qvl_compute_attestation_evidence_hash": evidence_hash,
                    "qvl_compute_authorization_expiry": (
                        compute_authorization.receipt_expiry
                    ),
                    "qvl_compute_authorization_digest": authorization_digest,
                    "qvl_compute_authorization_signature": self.signer.sign_raw_digest(
                        authorization_digest
                    ),
                }
            )
        royalty_authorization = request.royalty_authorization
        if royalty_authorization is not None:
            binding = policy.royalty_settlement_binding
            royalty_signer = self.royalty_signer
            royalty_policy_commitment = self.royalty_policy_commitment
            if (
                profile != "royalty_settlement"
                or binding is None
                or royalty_signer is None
                or royalty_policy_commitment is None
            ):
                raise VerificationRejected
            evidence_hash = derive_royalty_settlement_attestation_evidence_hash(
                request=request,
                binding=binding,
                royalty_verifier_address=royalty_signer.address,
                royalty_policy_commitment=royalty_policy_commitment,
            )
            resource_hash = royalty_collaboration_resource_hash(
                chain_id=policy.chain_id,
                distributor_address=binding.distributor_address,
                room_commitment=royalty_authorization.room_commitment,
                query_commitment=royalty_authorization.query_commitment,
            )
            decision_hash = royalty_settlement_decision_hash(
                chain_id=policy.chain_id,
                distributor_address=binding.distributor_address,
                settlement_id=royalty_authorization.settlement_id,
                settlement_nonce=int(royalty_authorization.settlement_nonce),
                funding_reservation_id=(
                    royalty_authorization.funding_reservation_id
                ),
                release_policy_commitment=(
                    royalty_authorization.release_policy_commitment
                ),
                room_commitment=royalty_authorization.room_commitment,
                room_state_commitment=(
                    royalty_authorization.room_state_commitment
                ),
                query_commitment=royalty_authorization.query_commitment,
                grant_set_commitment=royalty_authorization.grant_set_commitment,
                allocation_commitment=(
                    royalty_authorization.allocation_commitment
                ),
                owners_amounts_hash=royalty_authorization.owners_amounts_hash,
                asset=royalty_authorization.asset,
                total=int(royalty_authorization.total),
                execution_commitment=royalty_authorization.execution_commitment,
                result_commitment=royalty_authorization.result_commitment,
                usage_commitment=royalty_authorization.usage_commitment,
                attestation_evidence_hash=evidence_hash,
                anchor_resource_hash=resource_hash,
                expiry=royalty_authorization.expiry,
            )
            settlement_authorization_digest = (
                royalty_settlement_authorization_digest(
                    chain_id=policy.chain_id,
                    distributor_address=binding.distributor_address,
                    settlement_id=royalty_authorization.settlement_id,
                    settlement_nonce=int(royalty_authorization.settlement_nonce),
                    funding_reservation_id=(
                        royalty_authorization.funding_reservation_id
                    ),
                    release_policy_commitment=(
                        royalty_authorization.release_policy_commitment
                    ),
                    room_commitment=royalty_authorization.room_commitment,
                    room_state_commitment=(
                        royalty_authorization.room_state_commitment
                    ),
                    query_commitment=royalty_authorization.query_commitment,
                    grant_set_commitment=(
                        royalty_authorization.grant_set_commitment
                    ),
                    allocation_commitment=(
                        royalty_authorization.allocation_commitment
                    ),
                    owners_amounts_hash=(
                        royalty_authorization.owners_amounts_hash
                    ),
                    asset=royalty_authorization.asset,
                    total=int(royalty_authorization.total),
                    execution_commitment=(
                        royalty_authorization.execution_commitment
                    ),
                    result_commitment=royalty_authorization.result_commitment,
                    usage_commitment=royalty_authorization.usage_commitment,
                    attestation_evidence_hash=evidence_hash,
                    anchor_resource_hash=resource_hash,
                    anchor_decision_hash=decision_hash,
                    anchor_sequence=int(royalty_authorization.anchor_sequence),
                    expiry=royalty_authorization.expiry,
                )
            )
            try:
                recovered_settlement_verifier = recover_raw_digest_address(
                    digest=settlement_authorization_digest,
                    signature=(
                        royalty_authorization.settlement_authorization_signature
                    ),
                )
            except VerifierUnavailable as exc:
                raise VerificationRejected from exc
            if (
                royalty_authorization.release_policy_commitment
                != binding.release_policy_commitment
                or royalty_authorization.attestation_evidence_hash != evidence_hash
                or royalty_authorization.anchor_resource_hash != resource_hash
                or royalty_authorization.anchor_decision_hash != decision_hash
                or royalty_authorization.settlement_authorization_digest
                != settlement_authorization_digest
                or recovered_settlement_verifier != binding.settlement_verifier
                or royalty_authorization.expiry <= completed_at
                or royalty_authorization.expiry
                > completed_at + binding.max_authorization_lifetime_seconds
                or royalty_authorization.expiry > expires_at
                or royalty_authorization.expiry > challenge.expires_at
            ):
                raise VerificationRejected
            anchor_evidence_commitment = (
                derive_royalty_settlement_anchor_evidence_commitment(
                    authorization=royalty_authorization,
                    binding=binding,
                    attestation_evidence_hash=evidence_hash,
                )
            )
            authorization_digest = royalty_settlement_qvl_authorization_digest(
                chain_id=policy.chain_id,
                distributor_address=binding.distributor_address,
                settlement_id=royalty_authorization.settlement_id,
                settlement_nonce=int(royalty_authorization.settlement_nonce),
                funding_reservation_id=(
                    royalty_authorization.funding_reservation_id
                ),
                release_policy_commitment=(
                    royalty_authorization.release_policy_commitment
                ),
                room_commitment=royalty_authorization.room_commitment,
                room_state_commitment=(
                    royalty_authorization.room_state_commitment
                ),
                query_commitment=royalty_authorization.query_commitment,
                grant_set_commitment=royalty_authorization.grant_set_commitment,
                allocation_commitment=(
                    royalty_authorization.allocation_commitment
                ),
                owners_amounts_hash=royalty_authorization.owners_amounts_hash,
                asset=royalty_authorization.asset,
                total=int(royalty_authorization.total),
                execution_commitment=royalty_authorization.execution_commitment,
                result_commitment=royalty_authorization.result_commitment,
                usage_commitment=royalty_authorization.usage_commitment,
                attestation_evidence_hash=evidence_hash,
                anchor_resource_hash=resource_hash,
                anchor_decision_hash=decision_hash,
                anchor_sequence=int(royalty_authorization.anchor_sequence),
                expiry=royalty_authorization.expiry,
            )
            unsigned.update(
                {
                    "qvl_royalty_verifier_address": royalty_signer.address,
                    "qvl_royalty_policy_commitment": royalty_policy_commitment,
                    "qvl_royalty_release_policy_commitment": (
                        binding.release_policy_commitment
                    ),
                    "qvl_royalty_attestation_evidence_hash": evidence_hash,
                    "qvl_royalty_anchor_evidence_commitment": (
                        anchor_evidence_commitment
                    ),
                    "qvl_royalty_authorization_expiry": (
                        royalty_authorization.expiry
                    ),
                    "qvl_royalty_authorization_digest": authorization_digest,
                    "qvl_royalty_authorization_signature": (
                        royalty_signer.sign_raw_digest(authorization_digest)
                    ),
                }
            )
        signature = self.signer.sign_digest(independent_verdict_digest(unsigned))
        return IndependentTdxVerdict.model_validate(
            {**unsigned, "verifier_signature": signature},
            strict=True,
        )


Clock = Callable[[], int]
AsyncVerifier = Callable[[IndependentVerificationRequest], Awaitable[IndependentTdxVerdict]]
