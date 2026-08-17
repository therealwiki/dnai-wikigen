from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct

from attestation_qvl.challenge import (
    OneTimeChallengeStore,
    challenge_digest,
    qvl_profile,
    qvl_profiles,
)
from attestation_qvl.models import (
    IndependentVerificationRequest,
    QvlChallenge,
    QvlChallengeRequest,
)
from attestation_qvl.models import ComputeWorkloadRecipientAttestation
from attestation_qvl.policy import LoadedReleasePolicy, load_release_policy
from attestation_qvl.qvl import (
    IndependentQuoteVerifier,
    VerifiedQuote,
    derive_compute_workload_recipient_report_data,
    derive_email_oracle_kms_restart_report_data,
    derive_release_report_data,
    derive_royalty_settlement_policy_commitment,
    derive_royalty_settlement_report_data,
)
from attestation_qvl.signing import royalty_release_policy_commitment


NOW = 1_800_000_000
TOKEN = "test-runtime-bearer-token-0123456789abcdef"
CONTRACT = "0x1111111111111111111111111111111111111111"
SIGNER_ADDRESS = "0x2222222222222222222222222222222222222222"
COMPOSE_HASH = "0x" + "aa" * 32
APP_ID = "bb" * 20
OS_IMAGE_HASH = "cc" * 32
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
MAIN_RUNTIME_CVM_ID = "cvm-main-runtime-0001"
METERING_CVM_ID = "cvm-independent-metering-0001"
ROYALTY_DISTRIBUTOR = "0x5555555555555555555555555555555555555555"
ROYALTY_OWNER = "0x7777777777777777777777777777777777777777"
ROYALTY_ANCHOR = "0x6666666666666666666666666666666666666666"
ROYALTY_SETTLEMENT_PRIVATE_KEY = bytes.fromhex("13" * 32)
ROYALTY_SETTLEMENT_ADDRESS = Account.from_key(
    ROYALTY_SETTLEMENT_PRIVATE_KEY
).address.lower()
ROYALTY_QVL_PRIVATE_KEY = bytes.fromhex("12" * 32)
ROYALTY_QVL_ADDRESS = Account.from_key(ROYALTY_QVL_PRIVATE_KEY).address.lower()
ROYALTY_QVL_KEY_ID = "0x" + "67" * 32
ROYALTY_ANCHOR_WRITER_RELEASE = "0x" + "68" * 32
WORKLOAD_RECIPIENT_PUBLIC_KEY = "33" * 32
WORKLOAD_RECIPIENT_KEY_ID = (
    "sha256:"
    + hashlib.sha256(bytes.fromhex(WORKLOAD_RECIPIENT_PUBLIC_KEY)).hexdigest()
)


def measurement_bytes(*, v15: bool = False) -> dict[str, bytes]:
    fields = {
        "tee_tcb_svn": bytes.fromhex("01" * 16),
        "mr_seam": bytes.fromhex("02" * 48),
        "mr_signer_seam": bytes.fromhex("03" * 48),
        "seam_attributes": bytes.fromhex("04" * 8),
        "td_attributes": bytes(8),
        "xfam": bytes.fromhex("06" * 8),
        "mr_td": bytes.fromhex("07" * 48),
        "mr_config_id": bytes.fromhex("08" * 48),
        "mr_owner": bytes.fromhex("09" * 48),
        "mr_owner_config": bytes.fromhex("0a" * 48),
        "rt_mr0": bytes.fromhex("0b" * 48),
        "rt_mr1": bytes.fromhex("0c" * 48),
        "rt_mr2": bytes.fromhex("0d" * 48),
        "rt_mr3": bytes.fromhex("0e" * 48),
    }
    if v15:
        fields["tee_tcb_svn2"] = bytes.fromhex("0f" * 16)
        fields["mr_service_td"] = bytes.fromhex("10" * 48)
    return fields


def policy_payload(
    *,
    v15: bool = False,
    include_statuses: bool = True,
    arena: bool = False,
    anchor_writer: bool = False,
    compute_workload: bool = False,
    compute_metering: bool = False,
    email_restart: bool = False,
    royalty: bool = False,
) -> dict[str, object]:
    if sum((arena, anchor_writer, compute_workload, compute_metering)) > 1:
        raise ValueError("report-data bindings are mutually exclusive")
    if royalty and any((arena, anchor_writer, compute_workload, compute_metering)):
        raise ValueError("royalty settlement is a secondary Diligence profile")
    arena_key = bytes.fromhex("33" * 32)
    binding: dict[str, str] = {"kind": "diligence_result_signer_v1"}
    if arena:
        binding = {
            "kind": "arena_candidate_ingress_v1",
            "encryption_public_key": arena_key.hex(),
            "key_id": "sha256:" + hashlib.sha256(arena_key).hexdigest(),
        }
    if anchor_writer:
        binding = {
            "kind": "execution_policy_anchor_writer_v1",
            "writer_release_commitment": "0x" + "55" * 32,
            "writer_key_path": "tinker/execution_policy_anchor_writer",
            "writer_custody": "dstack_derived_execution_policy_anchor_writer",
        }
    if compute_metering:
        binding = {
            "kind": "compute_metering_signer_v1",
            "policy_set_hash": "0x" + "44" * 32,
            "signer_custody": "dstack_derived_independent_cvm",
        }
    if compute_workload:
        binding = {"kind": "compute_workload_recipient_v1"}
    payload: dict[str, object] = {
        "schema": "dnai.attestation-qvl-release-policy.v1",
        "chain_id": 84_532,
        "contract_address": CONTRACT,
        "compose_hash": COMPOSE_HASH,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE_HASH,
        "allowed_signer_addresses": [] if compute_workload else [SIGNER_ADDRESS],
        "report_data_binding": binding,
        "measurements": {key: value.hex() for key, value in measurement_bytes(v15=v15).items()},
        "valid_from": NOW - 600,
        "valid_until": NOW + 3_600,
        "max_verdict_ttl_seconds": 300,
    }
    if include_statuses:
        payload["allowed_tcb_statuses"] = ["OK"]
    if email_restart:
        implementation = "0x" + "77" * 20
        payload["email_oracle_kms_restart_binding"] = {
            "kind": "email_oracle_kms_restart_v1",
            "email_oracle_auth_address": "0x" + "33" * 20,
            "email_oracle_auth_runtime_code_hash": "0x" + "34" * 32,
            "kms_proxy_address": "0x" + "44" * 20,
            "kms_proxy_runtime_code_hash": "0x" + "45" * 32,
            "kms_implementation_address": implementation,
            "kms_implementation_runtime_code_hash": "0x" + "78" * 32,
            "kms_eip1967_implementation_slot_word": (
                "0x" + "00" * 12 + implementation[2:]
            ),
            "registration_tx_hash": "0x" + "89" * 32,
            "registration_block_number": 12_345_678,
            "registration_block_hash": "0x" + "9a" * 32,
            "target_boot_tuple_hash": "0x" + "bc" * 32,
            "restart_proof_hash": "0x" + "de" * 32,
        }
    if royalty:
        payload["allowed_signer_addresses"] = [ROYALTY_SETTLEMENT_ADDRESS]
        release_commitment = royalty_release_policy_commitment(
            chain_id=84_532,
            distributor_address=ROYALTY_DISTRIBUTOR,
            authority_nonce=7,
            settlement_verifier=ROYALTY_SETTLEMENT_ADDRESS,
            qvl_verifier=ROYALTY_QVL_ADDRESS,
            execution_policy_anchor=ROYALTY_ANCHOR,
            anchor_writer_release_commitment=ROYALTY_ANCHOR_WRITER_RELEASE,
        )
        payload["royalty_settlement_binding"] = {
            "kind": "royalty_settlement_qvl_v2",
            "owner": ROYALTY_OWNER,
            "distributor_address": ROYALTY_DISTRIBUTOR,
            "distributor_runtime_code_hash": "0x" + "56" * 32,
            "settlement_verifier": ROYALTY_SETTLEMENT_ADDRESS,
            "settlement_verifier_key_path": (
                "tinker/collaboration_royalty_settlement_signer"
            ),
            "settlement_verifier_custody": (
                "dstack_derived_main_runtime_royalty_settlement_signer"
            ),
            "execution_policy_anchor": ROYALTY_ANCHOR,
            "anchor_writer_release_commitment": ROYALTY_ANCHOR_WRITER_RELEASE,
            "release_policy_commitment": release_commitment,
            "authority_nonce": "7",
            "qvl_signer_key_id": ROYALTY_QVL_KEY_ID,
            "main_runtime_cvm_id": MAIN_RUNTIME_CVM_ID,
            "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
            "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
            "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
            "max_authorization_lifetime_seconds": 600,
        }
    return payload


def write_policy(path: Path, payload: dict[str, object] | None = None) -> LoadedReleasePolicy:
    path.write_text(json.dumps(payload or policy_payload(), separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return load_release_policy(str(path.resolve()))


class FakeBackend:
    def __init__(self, result: VerifiedQuote):
        self.result = result
        self.calls: list[bytes] = []
        self.error: Exception | None = None

    async def verify(self, raw_quote: bytes) -> VerifiedQuote:
        self.calls.append(raw_quote)
        if self.error:
            raise self.error
        return self.result


class FakeVerdictSigner:
    custody = "test_injected"

    def __init__(self) -> None:
        self.account = Account.from_key(bytes.fromhex("11" * 32))
        self.address = self.account.address.lower()
        self.digests: list[str] = []

    def sign_digest(self, digest: str) -> str:
        self.digests.append(digest)
        signed = self.account.sign_message(encode_defunct(hexstr=digest))
        return "0x" + bytes(signed.signature).hex()

    def sign_raw_digest(self, digest: str) -> str:
        self.digests.append(digest)
        signed = self.account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
        return "0x" + bytes(signed.signature).hex()


class FakeRoyaltySigner:
    custody = "test_injected_royalty"
    key_path = "test/royalty-settlement"

    def __init__(self) -> None:
        self.account = Account.from_key(ROYALTY_QVL_PRIVATE_KEY)
        self.address = self.account.address.lower()
        self.digests: list[str] = []

    def sign_raw_digest(self, digest: str) -> str:
        self.digests.append(digest)
        signed = self.account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
        return "0x" + bytes(signed.signature).hex()


@dataclass
class Context:
    release: LoadedReleasePolicy
    raw_quote: bytes
    report_data: bytes
    backend: FakeBackend
    signer: FakeVerdictSigner
    royalty_signer: FakeRoyaltySigner | None
    verifier: IndependentQuoteVerifier
    challenge: QvlChallenge
    challenge_request: QvlChallengeRequest
    challenge_store: OneTimeChallengeStore
    request_payload: dict[str, object]

    def request(self, payload: dict[str, object] | None = None) -> IndependentVerificationRequest:
        return IndependentVerificationRequest.model_validate(payload or self.request_payload, strict=True)


def make_context(
    tmp_path: Path,
    *,
    v15: bool = False,
    arena: bool = False,
    anchor_writer: bool = False,
    compute_workload: bool = False,
    compute_metering: bool = False,
    email_restart: bool = False,
    royalty: bool = False,
    policy_valid_until: int | None = None,
    challenge_expires_at: int | None = None,
    max_verdict_ttl_seconds: int | None = None,
) -> Context:
    payload = policy_payload(
        v15=v15,
        arena=arena,
        anchor_writer=anchor_writer,
        compute_workload=compute_workload,
        compute_metering=compute_metering,
        email_restart=email_restart,
        royalty=royalty,
    )
    if policy_valid_until is not None:
        payload["valid_until"] = policy_valid_until
    if max_verdict_ttl_seconds is not None:
        payload["max_verdict_ttl_seconds"] = max_verdict_ttl_seconds
    release = write_policy(
        tmp_path / "release-policy.json",
        payload,
    )
    royalty_signer = FakeRoyaltySigner() if royalty else None
    raw_quote = bytes((index % 251 for index in range(2048)))
    workload_attestation = None
    if royalty:
        binding = release.policy.royalty_settlement_binding
        assert binding is not None and royalty_signer is not None
        royalty_policy_commitment = derive_royalty_settlement_policy_commitment(
            release=release,
            binding=binding,
            royalty_verifier_address=royalty_signer.address,
        )
        report_data = derive_royalty_settlement_report_data(
            release=release,
            binding=binding,
            royalty_verifier_address=royalty_signer.address,
            royalty_policy_commitment=royalty_policy_commitment,
        )
    elif compute_workload:
        workload_attestation = ComputeWorkloadRecipientAttestation.model_validate(
            {
                "schema": "dnai.compute-workload-recipient-attestation.v1",
                "context": "compute_workload",
                "audience": "dnai-wikigen:compute-workload-recipient",
                "service": "dnai-wikigen",
                "protocol": "compute_workload_ingress_v1",
                "encryption_public_key": WORKLOAD_RECIPIENT_PUBLIC_KEY,
                "key_id": WORKLOAD_RECIPIENT_KEY_ID,
                "activation_signer_address": SIGNER_ADDRESS,
                "activation_signer_key_path": (
                    "tinker/compute_workload_activation_signer"
                ),
                "activation_signer_custody": (
                    "dstack_derived_compute_workload_activation_signer"
                ),
                "chain_id": 84_532,
                "compute_vault_address": CONTRACT,
                "compute_vault_runtime_code_hash": "0x" + "45" * 32,
                "fresh_contract_deployment_receipt_sha256": "0x" + "46" * 32,
            },
            strict=True,
        )
        report_data = derive_compute_workload_recipient_report_data(
            workload_attestation
        )
    elif email_restart:
        report_data = derive_email_oracle_kms_restart_report_data(
            signer_address=SIGNER_ADDRESS,
            chain_id=release.policy.chain_id,
            binding=release.policy.email_oracle_kms_restart_binding,
        )
    else:
        report_data = derive_release_report_data(
            release.policy.report_data_binding,
            signer_address=SIGNER_ADDRESS,
            chain_id=release.policy.chain_id,
            contract_address=release.policy.contract_address,
        )
    signer = FakeVerdictSigner()
    target_domain = (
        "independent_metering_cvm" if compute_metering else "main_runtime_cvm"
    )
    target_cvm_id = METERING_CVM_ID if compute_metering else MAIN_RUNTIME_CVM_ID
    challenge_request = QvlChallengeRequest.model_validate(
        {
            "schema": "dnai.attestation-qvl-challenge-request.v2",
            "chain_id": release.policy.chain_id,
            "domain": target_domain,
            "profile": (
                "royalty_settlement"
                if royalty
                else (
                    "email_oracle_kms_restart"
                    if email_restart
                    else qvl_profile(release.policy.report_data_binding)
                )
            ),
            "cvm_id": target_cvm_id,
            "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
            "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
            "ceremony_nonce": CEREMONY_NONCE,
            "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        },
        strict=True,
    )
    unsigned_challenge = {
        "schema": "dnai.attestation-qvl-challenge.v2",
        **challenge_request.model_dump(mode="json", by_alias=True, exclude={"schema_id"}),
        "release_policy_hash": release.policy_hash,
        "challenge_id": "0x" + "ab" * 32,
        "issued_at": NOW,
        "expires_at": challenge_expires_at or NOW + 60,
        "verifier_address": signer.address,
    }
    freshness_digest = challenge_digest(unsigned_challenge)
    challenge = QvlChallenge.model_validate(
        {
            **unsigned_challenge,
            "challenge_digest": freshness_digest,
            "verifier_signature": signer.sign_digest(freshness_digest),
        },
        strict=True,
    )
    random_counter = [0]

    def test_random_bytes(size: int) -> bytes:
        value = (0xAB + random_counter[0]) % 256
        random_counter[0] += 1
        return bytes([value]) * size

    challenge_store = OneTimeChallengeStore(
        profiles=qvl_profiles(release.policy),
        policy_hash=release.policy_hash,
        signer=signer,
        ttl_seconds=60,
        maximum=32,
        clock=lambda: NOW,
        random_bytes=test_random_bytes,
    )
    backend = FakeBackend(VerifiedQuote(
        quote_type="TDX",
        status="OK",
        report_data=report_data + bytes.fromhex(freshness_digest[2:]),
        measurements=measurement_bytes(v15=v15),
    ))
    verifier = IndependentQuoteVerifier(
        release=release,
        backend=backend,
        signer=signer,
        royalty_signer=royalty_signer,
        clock=lambda: NOW,
    )
    quote_hash = "0x" + hashlib.sha256(raw_quote).hexdigest()
    report_data_hex = "0x" + report_data.hex()
    request_payload: dict[str, object] = {
        "schema": "dnai.independent-tdx-verification-request.v2",
        "challenge": challenge.model_dump(mode="json", by_alias=True),
        "quote": "0x" + raw_quote.hex(),
        "expectation": {
            "mode": "tdx",
            "signer_address": (
                ROYALTY_SETTLEMENT_ADDRESS if royalty else SIGNER_ADDRESS
            ),
            "chain_id": release.policy.chain_id,
            "contract_address": (
                release.policy.royalty_settlement_binding.distributor_address
                if royalty and release.policy.royalty_settlement_binding is not None
                else release.policy.contract_address
            ),
            "report_data": report_data_hex,
            "quote_report_data": report_data_hex + freshness_digest[2:],
            "quote_hash": quote_hash,
            "quote_size": len(raw_quote),
            "compose_hash": release.policy.compose_hash,
            "app_id": release.policy.app_id,
            "os_image_hash": release.policy.os_image_hash,
            "raw_secret_egress": False,
        },
    }
    if workload_attestation is not None:
        request_payload["compute_workload_recipient"] = (
            workload_attestation.model_dump(mode="json", by_alias=True)
        )
    return Context(
        release=release,
        raw_quote=raw_quote,
        report_data=report_data,
        backend=backend,
        signer=signer,
        royalty_signer=royalty_signer,
        verifier=verifier,
        challenge=challenge,
        challenge_request=challenge_request,
        challenge_store=challenge_store,
        request_payload=request_payload,
    )
