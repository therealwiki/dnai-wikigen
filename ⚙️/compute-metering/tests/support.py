from __future__ import annotations

import json
import hashlib
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path

from eth_abi import decode, encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from compute_metering.chain import BaseSepoliaStateVerifier, JOB_OUTPUT_TYPES
from compute_metering.evm import (
    compute_metering_qvl_receipt_digest,
    compute_metering_receipt_digest,
    compute_onchain_usage_commitment,
    selector,
)
from compute_metering.meter import ComputeMeter
from compute_metering.models import (
    BASE_SEPOLIA_USDC,
    AssetRatePolicy,
    ComputeUsageEnvelope,
    ComputeMeteringQvlVerdict,
    ComputeQvlChallenge,
    MeteringIdentityAttestation,
    MeteringDecision,
    MeteringPolicySet,
    MeteringRequest,
    ZERO_ADDRESS,
    ZERO_BYTES32,
)
from compute_metering.identity_attestation import (
    compute_metering_attestation_evidence_hash,
    compute_qvl_challenge_digest,
    compute_qvl_verdict_digest,
)
from compute_metering.policy import (
    LoadedPolicySet,
    canonical_json_bytes,
    compute_rate_policy_commitment,
    load_policy_set,
)
from compute_metering.replay import DurableReplayStore
from compute_metering.rpc import LATEST, BlockSnapshot


NOW = 1_800_000_000
TOKEN = "test-metering-bearer-token-0123456789abcdef"
PINNED_NUMBER = 44_000_000
PINNED_HASH = "0x" + "ab" * 32
LATEST_HASH = "0x" + "ac" * 32
CODE = bytes.fromhex("6080604052348015600e575f80fd5b506001")
VAULT = "0x1111111111111111111111111111111111111111"
OWNER = "0x2222222222222222222222222222222222222222"
DEVELOPER = "0x3333333333333333333333333333333333333333"
PROVIDER = "0x4444444444444444444444444444444444444444"
TEE_ACCOUNT = Account.from_key(bytes.fromhex("55" * 32))
TEE = TEE_ACCOUNT.address.lower()
USER = "0x6666666666666666666666666666666666666666"
METER_ACCOUNT = Account.from_key(bytes.fromhex("77" * 32))
METER = METER_ACCOUNT.address.lower()
QVL_ACCOUNT = Account.from_key(bytes.fromhex("88" * 32))
QVL = QVL_ACCOUNT.address.lower()
ASSET = "0x0000000000000000000000000000000000000000"
USDC = BASE_SEPOLIA_USDC
COMPOSE_HASH = "0x" + "bb" * 32
PROJECT_ID = "0x" + "10" * 32
JOB_ID = "0x" + "20" * 32
START_COMMITMENT = "0x" + "30" * 32
WORKLOAD_COMMITMENT = "0x" + "31" * 32
MANIFEST_COMMITMENT = "0x" + "32" * 32
DISPATCH_INTENT_COMMITMENT = "0x" + "33" * 32
ATTESTATION_EVIDENCE_HASH = "0x" + "34" * 32
METERING_CVM_ID = "cvm-independent-metering-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
METERING_APP_ID = "45" * 20
METERING_OS_IMAGE_HASH = "46" * 32


def policy_payload(**overrides: object) -> dict[str, object]:
    native: dict[str, object] = {
        "asset": ASSET,
        "provider": PROVIDER,
        "rate_policy_commitment": "0x" + "c1" * 32,
        "rates": [
            {
                "model": "tinker-model-v1",
                "recipe": "inference.v1",
                "prefill_units_per_million": "250",
                "sample_units_per_million": "1000",
                "training_units_per_million": "5000",
            }
        ],
        "limits": {
            "max_prefill_tokens": "10000000",
            "max_sample_tokens": "2000000",
            "max_training_tokens": "100000000",
            "max_total_debit": "2000",
        },
    }
    usdc = deepcopy(native)
    usdc["asset"] = USDC
    usdc["rate_policy_commitment"] = "0x" + "c2" * 32
    payload: dict[str, object] = {
        "schema": "dnai.compute-metering-policy-set.v1",
        "chain_id": 84_532,
        "rpc_origin": "https://sepolia.base.org",
        "vault_address": VAULT,
        "vault_runtime_code_hash": "0x" + keccak(CODE).hex(),
        "owner": OWNER,
        "developer": DEVELOPER,
        "paused": False,
        "developer_fee_bps": 500,
        "developer_fee_frozen": True,
        "rate_policy_additions_frozen": True,
        "asset_additions_frozen": True,
        "compose_policy_frozen": True,
        "tee_identity_additions_frozen": True,
        "metering_binding_frozen": True,
        "allowed_asset_count": 1,
        "active_rate_policy_count": 2,
        "approved_compose_count": 1,
        "approved_tee_identity_count": 1,
        "pending_asset_count": 0,
        "pending_rate_policy_count": 0,
        "pending_compose_count": 0,
        "pending_tee_identity_count": 0,
        "pending_developer_fee_activates_at": 0,
        "pending_metering_verifier": "0x" + "00" * 20,
        "metering_qvl_verifier": QVL,
        "pending_metering_qvl_verifier": "0x" + "00" * 20,
        "pending_metering_policy_set_hash": "0x" + "00" * 32,
        "pending_metering_binding_activates_at": 0,
        "tee_identity": TEE,
        "compose_hash": COMPOSE_HASH,
        "asset_policies": [native, usdc],
        "min_confirmations": 3,
        "max_pinned_block_age_seconds": 300,
        "max_usage_age_seconds": 3600,
        "max_future_skew_seconds": 30,
        "receipt_ttl_seconds": 300,
        "min_submission_window_seconds": 30,
        "valid_from": NOW - 3600,
        "valid_until": NOW + 3600,
    }
    payload.update(overrides)
    provisional = MeteringPolicySet.model_validate(payload, strict=True)
    for item, entry in zip(payload["asset_policies"], provisional.asset_policies, strict=True):
        item["rate_policy_commitment"] = compute_rate_policy_commitment(
            entry, developer_fee_bps=provisional.developer_fee_bps
        )
    return payload


def write_policy(path: Path, payload: dict[str, object] | None = None) -> LoadedPolicySet:
    path.write_text(json.dumps(payload or policy_payload(), separators=(",", ":")), encoding="utf-8")
    path.chmod(0o600)
    return load_policy_set(str(path.resolve()))


def unsigned_usage_payload(release: LoadedPolicySet, **overrides: object) -> dict[str, object]:
    requested_asset = str(overrides.get("asset", ASSET))
    asset_policy = next(entry for entry in release.policy.asset_policies if entry.asset == requested_asset)
    payload: dict[str, object] = {
        "schema": "dnai.compute-usage-envelope.v2",
        "job_id": JOB_ID,
        "project_id": PROJECT_ID,
        "user": USER,
        "asset": asset_policy.asset,
        "authorization_nonce": "7",
        "max_asset_debit": "1000",
        "authorization_expiry": NOW + 600,
        "rate_policy_commitment": asset_policy.rate_policy_commitment,
        "workload_commitment": WORKLOAD_COMMITMENT,
        "manifest_commitment": MANIFEST_COMMITMENT,
        "dispatch_intent_commitment": DISPATCH_INTENT_COMMITMENT,
        "tee_identity": release.policy.tee_identity,
        "compose_hash": release.policy.compose_hash,
        "start_commitment": START_COMMITMENT,
        "model": "tinker-model-v1",
        "recipe": "inference.v1",
        "outcome": "succeeded",
        "prefill_tokens": "1000000",
        "sample_tokens": "500000",
        "training_tokens": "0",
        "usage_started_at": NOW - 60,
        "usage_observed_at": NOW - 30,
        "raw_secret_egress": False,
        "usage_commitment": "0x" + "cc" * 32,
        "tee_signature": "0x" + "11" * 64 + "1b",
    }
    payload.update(overrides)
    return payload


def sign_usage_payload(
    payload: dict[str, object],
    *,
    account=TEE_ACCOUNT,
) -> dict[str, object]:
    from compute_metering.usage import compute_usage_commitment

    provisional = ComputeUsageEnvelope.model_validate(payload, strict=True)
    commitment = compute_usage_commitment(provisional)
    signed = account.sign_message(encode_defunct(hexstr=commitment))
    result = dict(payload)
    result["usage_commitment"] = commitment
    result["tee_signature"] = "0x" + bytes(signed.signature).hex()
    return result


def usage_payload(release: LoadedPolicySet, **overrides: object) -> dict[str, object]:
    return sign_usage_payload(unsigned_usage_payload(release, **overrides))


def request_payload(release: LoadedPolicySet, **usage_overrides: object) -> dict[str, object]:
    return {
        "schema": "dnai.compute-metering-request.v2",
        "block": {"number": PINNED_NUMBER, "hash": PINNED_HASH},
        "usage": usage_payload(release, **usage_overrides),
    }


def encode_result(types: tuple[str, ...], values: tuple[object, ...]) -> str:
    return "0x" + encode(list(types), list(values)).hex()


class FakeRpc:
    def __init__(self, release: LoadedPolicySet, usage: ComputeUsageEnvelope):
        self.release = release
        self.usage = usage
        self.chain_id_value = 84_532
        self.pinned = BlockSnapshot(PINNED_NUMBER, PINNED_HASH, NOW - 20)
        self.latest = BlockSnapshot(PINNED_NUMBER + 2, LATEST_HASH, NOW)
        self.final_number_block: BlockSnapshot | None = None
        self.final_hash_block: BlockSnapshot | None = None
        self.number_calls = 0
        self.state: dict[str, object] = {}
        self.eth_call_blocks: list[str] = []
        self.code_blocks: list[str] = []
        self.chain_id_calls = 0
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def close(self) -> None:
        self.closed = True

    async def chain_id(self) -> int:
        self.chain_id_calls += 1
        return self.chain_id_value

    async def block_by_number(self, number: object) -> BlockSnapshot:
        if number is LATEST:
            return self.latest
        self.number_calls += 1
        if self.number_calls > 1 and self.final_number_block is not None:
            return self.final_number_block
        return self.pinned

    async def block_by_hash(self, _block_hash: str) -> BlockSnapshot:
        return self.final_hash_block or self.pinned

    async def get_code(self, _address: str, block_hash: str) -> bytes:
        self.code_blocks.append(block_hash)
        return self.state.get("code", CODE)  # type: ignore[return-value]

    def _selected_asset_policy(self) -> AssetRatePolicy:
        selected = self.release.policy.select_asset_policy(
            self.usage.asset,
            self.usage.rate_policy_commitment,
        )
        assert selected is not None
        return selected

    def _job_values(self) -> tuple[object, ...]:
        usage = self.usage
        default = (
            bytes.fromhex(usage.project_id[2:]),
            usage.user,
            usage.asset,
            int(usage.authorization_nonce),
            int(usage.max_asset_debit),
            0,
            usage.authorization_expiry,
            usage.usage_started_at,
            0,
            0,
            bytes.fromhex(usage.rate_policy_commitment[2:]),
            bytes.fromhex(usage.workload_commitment[2:]),
            bytes.fromhex(usage.manifest_commitment[2:]),
            bytes.fromhex(usage.dispatch_intent_commitment[2:]),
            bytes.fromhex(usage.compose_hash[2:]),
            bytes.fromhex(usage.start_commitment[2:]),
            bytes(32),
            bytes(32),
            0,
            usage.tee_identity,
            2,
        )
        return self.state.get("job", default)  # type: ignore[return-value]

    async def eth_call(self, _address: str, data: str, block_hash: str) -> object:
        self.eth_call_blocks.append(block_hash)
        call_selector = data[:10]
        mapping: dict[str, tuple[str, tuple[str, ...], tuple[object, ...]]] = {
            "owner": ("owner()", ("address",), (self.state.get("owner", self.release.policy.owner),)),
            "developer": (
                "developer()",
                ("address",),
                (self.state.get("developer", self.release.policy.developer),),
            ),
            "metering": ("meteringVerifier()", ("address",), (self.state.get("metering", METER),)),
            "metering_qvl": (
                "meteringQvlVerifier()",
                ("address",),
                (self.state.get("metering_qvl", QVL),),
            ),
            "metering_policy_set_hash": (
                "meteringPolicySetHash()",
                ("bytes32",),
                (
                    bytes.fromhex(
                        str(self.state.get("metering_policy_set_hash", self.release.policy_set_hash))[2:]
                    ),
                ),
            ),
            "metering_binding_frozen": (
                "meteringBindingFrozen()",
                ("bool",),
                (self.state.get("metering_binding_frozen", True),),
            ),
            "pending_metering_verifier": (
                "pendingMeteringVerifier()",
                ("address",),
                (self.state.get("pending_metering_verifier", ZERO_ADDRESS),),
            ),
            "pending_metering_qvl_verifier": (
                "pendingMeteringQvlVerifier()",
                ("address",),
                (self.state.get("pending_metering_qvl_verifier", ZERO_ADDRESS),),
            ),
            "pending_metering_policy_set_hash": (
                "pendingMeteringPolicySetHash()",
                ("bytes32",),
                (
                    bytes.fromhex(
                        str(self.state.get("pending_metering_policy_set_hash", ZERO_BYTES32))[2:]
                    ),
                ),
            ),
            "pending_metering_binding_activates_at": (
                "pendingMeteringBindingActivatesAt()",
                ("uint64",),
                (self.state.get("pending_metering_binding_activates_at", 0),),
            ),
            "paused": ("paused()", ("bool",), (self.state.get("paused", False),)),
            "fee": ("developerFeeBps()", ("uint16",), (self.state.get("fee", 500),)),
            "fee_frozen": (
                "developerFeeFrozen()",
                ("bool",),
                (self.state.get("fee_frozen", True),),
            ),
            "rate_frozen": (
                "ratePolicyAdditionsFrozen()",
                ("bool",),
                (self.state.get("rate_frozen", True),),
            ),
            "asset_frozen": (
                "assetAdditionsFrozen()",
                ("bool",),
                (self.state.get("asset_frozen", True),),
            ),
            "compose_frozen": (
                "composePolicyFrozen()",
                ("bool",),
                (self.state.get("compose_frozen", True),),
            ),
            "tee_identity_additions_frozen": (
                "teeIdentityAdditionsFrozen()",
                ("bool",),
                (self.state.get("tee_identity_additions_frozen", True),),
            ),
            "allowed_asset_count": (
                "allowedAssetCount()",
                ("uint256",),
                (self.state.get("allowed_asset_count", 1),),
            ),
            "active_rate_policy_count": (
                "activeRatePolicyCount()",
                ("uint256",),
                (self.state.get("active_rate_policy_count", 2),),
            ),
            "approved_compose_count": (
                "approvedComposeCount()",
                ("uint256",),
                (self.state.get("approved_compose_count", 1),),
            ),
            "approved_tee_identity_count": (
                "approvedTeeIdentityCount()",
                ("uint256",),
                (self.state.get("approved_tee_identity_count", 1),),
            ),
            "pending_asset_count": (
                "pendingAssetCount()",
                ("uint256",),
                (self.state.get("pending_asset_count", 0),),
            ),
            "pending_rate_policy_count": (
                "pendingRatePolicyCount()",
                ("uint256",),
                (self.state.get("pending_rate_policy_count", 0),),
            ),
            "pending_compose_count": (
                "pendingComposeCount()",
                ("uint256",),
                (self.state.get("pending_compose_count", 0),),
            ),
            "pending_tee_identity_count": (
                "pendingTeeIdentityCount()",
                ("uint256",),
                (self.state.get("pending_tee_identity_count", 0),),
            ),
            "pending_developer_fee_activates_at": (
                "pendingDeveloperFeeActivatesAt()",
                ("uint64",),
                (self.state.get("pending_developer_fee_activates_at", 0),),
            ),
            "compose_approved": (
                "approvedComposeHashes(bytes32)",
                ("bool",),
                (self.state.get("compose_approved", True),),
            ),
            "tee_compose": (
                "teeIdentityComposeHash(address)",
                ("bytes32",),
                (bytes.fromhex(str(self.state.get("tee_compose", COMPOSE_HASH))[2:]),),
            ),
            "rate": (
                "ratePolicies(bytes32)",
                ("address", "address", "uint16", "bool"),
                self.state.get(
                    "rate",
                    (self.usage.asset, self._selected_asset_policy().provider, 500, True),
                ),  # type: ignore[arg-type]
            ),
            "asset_allowed": (
                "allowedAssets(address)",
                ("bool",),
                (self.state.get("asset_allowed", True),),
            ),
            "job": ("getJob(bytes32)", JOB_OUTPUT_TYPES, self._job_values()),
        }
        for _name, (signature, types, values) in mapping.items():
            if call_selector == "0x" + selector(signature).hex():
                return encode_result(types, values)
        meter_signature = (
            "meteringReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)"
        )
        qvl_signature = (
            "meteringQvlReceiptDigest(bytes32,uint256,uint256,uint256,uint256,bytes32,uint256)"
        )
        usage_signature = (
            "usageCommitmentFor(bytes32,uint256,uint256,uint256,uint256,bytes32)"
        )
        if call_selector in {
            "0x" + selector(meter_signature).hex(),
            "0x" + selector(qvl_signature).hex(),
            "0x" + selector(usage_signature).hex(),
        }:
            is_usage = call_selector == "0x" + selector(usage_signature).hex()
            types = ["bytes32", "uint256", "uint256", "uint256", "uint256", "bytes32"]
            if not is_usage:
                types.append("uint256")
            args = decode(types, bytes.fromhex(data[10:]))
            job = self._job_values()
            exact = dict(
                chain_id=84_532,
                vault_address=VAULT,
                project_id="0x" + bytes(job[0]).hex(),
                job_id="0x" + bytes(args[0]).hex(),
                user=str(job[1]).lower(),
                asset=str(job[2]).lower(),
                authorization_nonce=int(job[3]),
                max_asset_debit=int(job[4]),
                actual_asset_debit=int(args[1]),
                authorization_expiry=int(job[6]),
                rate_policy_commitment="0x" + bytes(job[10]).hex(),
                workload_commitment="0x" + bytes(job[11]).hex(),
                manifest_commitment="0x" + bytes(job[12]).hex(),
                dispatch_intent_commitment="0x" + bytes(job[13]).hex(),
                tee_identity=str(job[19]).lower(),
                compose_hash="0x" + bytes(job[14]).hex(),
                start_commitment="0x" + bytes(job[15]).hex(),
                billable_compute_units=int(args[2]),
                usage_started_at=int(args[3]),
                usage_ended_at=int(args[4]),
                metering_policy_set_hash=self.release.policy_set_hash,
                attestation_evidence_hash="0x" + bytes(args[5]).hex(),
            )
            onchain_usage = compute_onchain_usage_commitment(**exact)
            if is_usage:
                result = self.state.get("usage_digest", onchain_usage)
            else:
                receipt_fields = {
                    **exact,
                    "usage_commitment": onchain_usage,
                    "receipt_expiry": int(args[6]),
                }
                if call_selector == "0x" + selector(qvl_signature).hex():
                    result = self.state.get(
                        "qvl_digest",
                        compute_metering_qvl_receipt_digest(**receipt_fields),
                    )
                else:
                    result = self.state.get(
                        "digest",
                        compute_metering_receipt_digest(**receipt_fields),
                    )
            return encode_result(("bytes32",), (bytes.fromhex(str(result)[2:]),))
        raise AssertionError(f"unexpected selector {call_selector}")


class FakeMeteringSigner:
    custody = "dstack_derived_independent_cvm"

    def __init__(self):
        self.account = METER_ACCOUNT
        self.address = METER
        self.digests: list[str] = []

    def sign_digest(self, digest: str) -> str:
        self.digests.append(digest)
        signed = self.account.unsafe_sign_hash(bytes.fromhex(digest[2:]))
        return "0x" + bytes(signed.signature).hex()


class FakeIdentityAttestor:
    def attest(
        self,
        *,
        metering_verifier,
        chain_id,
        vault_address,
        policy_set_hash,
        signer_custody,
        challenge,
    ):
        quote = bytes.fromhex("42" * 1024)
        report_data = "0x" + "43" * 32
        return MeteringIdentityAttestation(
            schema="dnai.compute-metering-identity-attestation.v2",
            challenge=challenge,
            mode="tdx",
            metering_verifier=metering_verifier,
            chain_id=chain_id,
            vault_address=vault_address,
            policy_set_hash=policy_set_hash,
            signer_custody=signer_custody,
            report_data=report_data,
            quote_report_data=report_data + challenge.challenge_digest[2:],
            quote="0x" + quote.hex(),
            quote_hash="0x" + hashlib.sha256(quote).hexdigest(),
            quote_size=len(quote),
            app_id=METERING_APP_ID,
            compose_hash=COMPOSE_HASH,
            os_image_hash=METERING_OS_IMAGE_HASH,
            raw_secret_egress=False,
        )


class FakeQvlClient:
    def __init__(self):
        self.verifier_address = QVL

    def issue_challenge(self):
        provisional = ComputeQvlChallenge(
            schema="dnai.attestation-qvl-challenge.v2",
            chain_id=84_532,
            domain="independent_metering_cvm",
            profile="compute_metering",
            cvm_id=METERING_CVM_ID,
            deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            ceremony_nonce=CEREMONY_NONCE,
            measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
            release_policy_hash="0x" + "45" * 32,
            challenge_id="0x" + "46" * 32,
            challenge_digest="0x" + "47" * 32,
            issued_at=NOW - 1,
            expires_at=NOW + 119,
            verifier_address=QVL,
            verifier_signature="0x" + "11" * 64 + "1b",
        )
        digest = compute_qvl_challenge_digest(provisional)
        signature = QVL_ACCOUNT.sign_message(encode_defunct(hexstr=digest)).signature
        return provisional.model_copy(
            update={
                "challenge_digest": digest,
                "verifier_signature": "0x" + bytes(signature).hex(),
            }
        )

    def verify(self, attestation, authorization):
        evidence = compute_metering_attestation_evidence_hash(attestation)
        assert evidence == authorization.attestation_evidence_hash
        digest = compute_metering_qvl_receipt_digest(
            chain_id=84_532,
            vault_address=VAULT,
            project_id=authorization.project_id,
            job_id=authorization.job_id,
            user=authorization.user,
            asset=authorization.asset,
            authorization_nonce=int(authorization.authorization_nonce),
            max_asset_debit=int(authorization.max_asset_debit),
            actual_asset_debit=int(authorization.actual_asset_debit),
            authorization_expiry=authorization.authorization_expiry,
            rate_policy_commitment=authorization.rate_policy_commitment,
            workload_commitment=authorization.workload_commitment,
            manifest_commitment=authorization.manifest_commitment,
            dispatch_intent_commitment=authorization.dispatch_intent_commitment,
            tee_identity=authorization.tee_identity,
            compose_hash=authorization.compose_hash,
            start_commitment=authorization.start_commitment,
            billable_compute_units=int(authorization.billable_compute_units),
            usage_started_at=authorization.usage_started_at,
            usage_ended_at=authorization.usage_ended_at,
            usage_commitment=authorization.usage_commitment,
            metering_policy_set_hash=authorization.metering_policy_set_hash,
            attestation_evidence_hash=evidence,
            receipt_expiry=authorization.receipt_expiry,
        )
        raw_signature = QVL_ACCOUNT.unsafe_sign_hash(bytes.fromhex(digest[2:])).signature
        values = dict(
            schema="dnai.independent-tdx-verdict.v4",
            verification_method="intel_tdx_dcap_qvl",
            verified=True,
            chain_id=attestation.challenge.chain_id,
            domain=attestation.challenge.domain,
            profile="compute_metering",
            cvm_id=attestation.challenge.cvm_id,
            deployment_intent_sha256=(
                attestation.challenge.deployment_intent_sha256
            ),
            release_authority_sha256=(
                attestation.challenge.release_authority_sha256
            ),
            ceremony_nonce=attestation.challenge.ceremony_nonce,
            measurement_policy_sha256=(
                attestation.challenge.measurement_policy_sha256
            ),
            release_policy_hash=attestation.challenge.release_policy_hash,
            challenge_id=attestation.challenge.challenge_id,
            challenge_digest=attestation.challenge.challenge_digest,
            challenge_issued_at=attestation.challenge.issued_at,
            challenge_expires_at=attestation.challenge.expires_at,
            quote_hash=attestation.quote_hash,
            report_data=attestation.report_data,
            compose_hash=attestation.compose_hash,
            app_id=attestation.app_id,
            os_image_hash=attestation.os_image_hash,
            signer_address=attestation.metering_verifier,
            contract_address=VAULT,
            issued_at=NOW,
            activation_evidence_lease_expires_at=NOW + 100,
            expires_at=NOW + 100,
            verifier_address=QVL,
            verifier_signature="0x" + "11" * 64 + "1b",
            qvl_compute_attestation_evidence_hash=evidence,
            qvl_compute_authorization_expiry=authorization.receipt_expiry,
            qvl_compute_authorization_digest=digest,
            qvl_compute_authorization_signature="0x" + bytes(raw_signature).hex(),
        )
        provisional = ComputeMeteringQvlVerdict(**values)
        verdict_digest = compute_qvl_verdict_digest(provisional)
        verdict_signature = QVL_ACCOUNT.sign_message(
            encode_defunct(hexstr=verdict_digest)
        ).signature
        return provisional.model_copy(
            update={"verifier_signature": "0x" + bytes(verdict_signature).hex()}
        )


@dataclass
class Context:
    release: LoadedPolicySet
    request_payload: dict[str, object]
    request: MeteringRequest
    rpc: FakeRpc
    signer: FakeMeteringSigner
    chain: BaseSepoliaStateVerifier
    replay: DurableReplayStore
    meter: ComputeMeter

    def close(self) -> None:
        self.replay.close()


def make_context(tmp_path: Path) -> Context:
    release = write_policy(tmp_path / "policy-set.json")
    raw_request = request_payload(release)
    request = MeteringRequest.model_validate(raw_request, strict=True)
    rpc = FakeRpc(release, request.usage)
    signer = FakeMeteringSigner()
    chain = BaseSepoliaStateVerifier(
        release=release,
        rpc=rpc,
        metering_verifier=signer.address,
        metering_qvl_verifier=QVL,
        clock=lambda: NOW,
    )
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    state_dir.chmod(0o700)
    replay = DurableReplayStore(
        path=str(state_dir / "replay.sqlite3"),
        policy_set_hash=release.policy_set_hash,
        _integrity_key=b"k" * 32,
    )
    meter = ComputeMeter(
        release=release,
        signer=signer,
        chain=chain,
        replay=replay,
        identity_attestor=FakeIdentityAttestor(),
        qvl_client=FakeQvlClient(),  # type: ignore[arg-type]
    )
    return Context(release, raw_request, request, rpc, signer, chain, replay, meter)


def decision_bytes(release: LoadedPolicySet) -> bytes:
    asset_policy = release.policy.asset_policies[0]
    digest = "0x" + "dd" * 32
    qvl_digest = "0x" + "dc" * 32
    signature = "0x" + bytes(METER_ACCOUNT.unsafe_sign_hash(bytes.fromhex(digest[2:])).signature).hex()
    qvl_signature = "0x" + bytes(QVL_ACCOUNT.unsafe_sign_hash(bytes.fromhex(qvl_digest[2:])).signature).hex()
    decision = MeteringDecision(
        schema="dnai.compute-metering-decision.v2",
        classification="attested_dual_verified_metering",
        provider_authoritative_invoice=False,
        chain_id=84_532,
        vault_address=release.policy.vault_address,
        pinned_block_number=PINNED_NUMBER,
        pinned_block_hash=PINNED_HASH,
        policy_set_hash=release.policy_set_hash,
        rate_policy_commitment=asset_policy.rate_policy_commitment,
        workload_commitment=WORKLOAD_COMMITMENT,
        manifest_commitment=MANIFEST_COMMITMENT,
        dispatch_intent_commitment=DISPATCH_INTENT_COMMITMENT,
        asset=asset_policy.asset,
        job_id=JOB_ID,
        usage_commitment="0x" + "ee" * 32,
        onchain_usage_commitment="0x" + "ef" * 32,
        actual_asset_debit="750",
        billable_compute_units="1500000",
        usage_started_at=NOW - 60,
        usage_ended_at=NOW - 30,
        attestation_evidence_hash=ATTESTATION_EVIDENCE_HASH,
        receipt_expiry=NOW + 100,
        metering_receipt_digest=digest,
        metering_qvl_receipt_digest=qvl_digest,
        metering_verifier=METER,
        metering_qvl_verifier=QVL,
        tee_identity=TEE,
        compose_hash=COMPOSE_HASH,
        raw_secret_egress=False,
        verifier_signature=signature,
        qvl_signature=qvl_signature,
    )
    return canonical_json_bytes(decision.model_dump(mode="json", by_alias=True))
