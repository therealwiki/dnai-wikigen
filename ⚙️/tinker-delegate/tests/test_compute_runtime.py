import copy
import hashlib
import hmac
import inspect
import json
import os
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak
from eth_keys import keys

from tinker_delegate.compute_runtime import (
    BASE_SEPOLIA_CHAIN_ID,
    COMPILED_RECIPES,
    CompiledRecipePolicy,
    ComputeCancellationUnavailable,
    ComputeDispatchIntent,
    ComputeExecutionPolicyNotPassed,
    ComputeExecutionJournal,
    ComputeExecutionWorker,
    ComputeIntentConflict,
    ComputeIntentNotFound,
    ComputeProviderDispatchFailure,
    ComputeRuntimePolicyError,
    ComputeRuntimeRetryable,
    ComputeRuntimeStateError,
    ComputeUsageReceiptNotReady,
    ExecutionStage,
    MeteringDecision,
    PreparedTransaction,
    ProviderUsage,
    VaultJob,
    VaultSnapshot,
    canonical_compute_job_id,
    canonical_compute_project_id,
    compute_collaboration_one_shot_authorization_context_commitment,
    compute_execution_policy_context_hash,
    compute_standalone_authorization_context_commitment,
)
from tinker_delegate.compute_runtime_cli import AnchoredComputeExecutionAuthorizer
from tinker_delegate.config import Settings
from tinker_delegate.execution_policy_anchor import (
    AnchoredExecutionPolicyCoordinator,
)
from tinker_delegate.execution_policy_store import (
    ExecutionPolicyStore,
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
    execution_policy_trust_context,
)
from tinker_delegate.policy_kernel import PolicyDecision, PolicyGateResult
from tests.execution_policy_anchor_fakes import (
    MemoryExecutionPolicyAnchorGateway,
    WRITER_RELEASE,
)


NOW = 1_800_000_000
ZERO32 = "0x" + "00" * 32
ZERO_ADDRESS = "0x" + "00" * 20
ASSET = ZERO_ADDRESS
VAULT = "0x" + "44" * 20
PROVIDER = "0x" + "55" * 20
RATE = "0x" + "66" * 32
COMPOSE = "0x" + "77" * 32
RESULT = "0x" + "88" * 32
POLICY_SET = "0x" + "89" * 32
BLOCK_HASH = "0x" + "8a" * 32
WORKLOAD_ID = "wrk_" + "ab" * 16
WORKLOAD_SCHEMA = "dnai.compute.workload.inference.v1"
WORKLOAD_MANIFEST = "0x" + "91" * 32
WORKLOAD_COMMITMENT = "0x" + "92" * 32
WORKLOAD_EXECUTION_BINDING = "sha256:" + "94" * 32
WORKLOAD_RECIPIENT_RELEASE = "sha256:" + "95" * 32
WORKLOAD_CLAIM = "sha256:" + "96" * 32
ATTESTATION_EVIDENCE = "0x" + "93" * 32
QVL_PRIVATE_KEY = bytes.fromhex("7a" * 32)


class TestOnlyExecutionIdentity:
    custody = "test_only_in_memory_key"

    def __init__(self, private_key: str = "0x" + "11" * 32):
        self.account = Account.from_key(private_key)
        self.address = self.account.address.lower()

    def sign_transaction(self, transaction):
        return self.account.sign_transaction(transaction)

    def sign_eip191(self, digest: str) -> str:
        signed = self.account.sign_message(encode_defunct(hexstr=digest))
        return "0x" + bytes(signed.signature).hex()


def _intent(identity: TestOnlyExecutionIdentity, **updates) -> ComputeDispatchIntent:
    values = {
        "project_reference": "prj_alpha",
        "job_reference": "job_alpha",
        "user": identity.address,
        "asset": ASSET,
        "authorization_nonce": 4,
        "max_asset_debit": 25,
        "authorization_expiry": NOW + 600,
        "rate_policy_commitment": RATE,
        "compose_hash": COMPOSE,
        "operation": "inference",
        "model": "qwen3_8b",
        "recipe": "qwen3_8b_bounded",
        "result_policy": "bounded_summary_receipt",
        "max_prefill_tokens": 100,
        "max_sample_tokens": 20,
        "max_train_tokens": 0,
        "workload_id": WORKLOAD_ID,
        "workload_schema": WORKLOAD_SCHEMA,
        "manifest_commitment": WORKLOAD_MANIFEST,
        "workload_commitment": WORKLOAD_COMMITMENT,
        "workload_source_kind": "wallet",
        "workload_execution_binding_commitment": (
            WORKLOAD_EXECUTION_BINDING
        ),
        "workload_recipient_release_commitment": (
            WORKLOAD_RECIPIENT_RELEASE
        ),
    }
    values.update(updates)
    return ComputeDispatchIntent.create(**values)


class TestOnlyVaultGateway:
    chain_id = BASE_SEPOLIA_CHAIN_ID
    vault_address = VAULT
    runtime_code_hash = "0x" + "99" * 32

    def __init__(self, intent, identity, verifier_private_key: bytes):
        self.intent = intent
        self.identity = identity
        self.verifier_private_key = keys.PrivateKey(verifier_private_key)
        self.verifier_address = (
            self.verifier_private_key.public_key.to_checksum_address().lower()
        )
        self.qvl_private_key = keys.PrivateKey(QVL_PRIVATE_KEY)
        self.qvl_verifier_address = (
            self.qvl_private_key.public_key.to_checksum_address().lower()
        )
        self.broadcasted = set()
        self.events = []
        self.state = 1
        self.start_commitment = ZERO32
        self.settled_usage_commitment = ZERO32
        self.actual_debit = 0
        self.billable_compute_units = 0
        self.usage_started_at = 0
        self.usage_ended_at = 0
        self.receipt_expiry = 0
        self.attestation_evidence_hash = ZERO32

    def snapshot(self, **_kwargs):
        return self._snapshot()

    def prepare_start(self, **_kwargs):
        self.events.append("start_prepared")
        return self._prepared("start", b"\x01start")

    def prepare_settlement(self, *, actual_asset_debit, **kwargs):
        self.events.append("settlement_prepared")
        self.actual_debit = actual_asset_debit
        self.billable_compute_units = kwargs["billable_compute_units"]
        self.usage_started_at = kwargs["usage_started_at"]
        self.usage_ended_at = kwargs["usage_ended_at"]
        self.receipt_expiry = kwargs["receipt_expiry"]
        self.attestation_evidence_hash = kwargs["attestation_evidence_hash"]
        self.settled_usage_commitment = self.usage_commitment_for(
            job_id=kwargs["job_id"],
            actual_asset_debit=actual_asset_debit,
            billable_compute_units=self.billable_compute_units,
            usage_started_at=self.usage_started_at,
            usage_ended_at=self.usage_ended_at,
            attestation_evidence_hash=self.attestation_evidence_hash,
        )
        return self._prepared("settlement", b"\x02settle")

    def broadcast(self, transaction):
        self.events.append(f"{transaction.purpose}_broadcast")
        self.broadcasted.add(transaction.tx_hash)

    def confirmed_snapshot(self, transaction, **_kwargs):
        if transaction.tx_hash not in self.broadcasted:
            return None
        if transaction.purpose == "start":
            self.state = 2
            self.start_commitment = "0x" + keccak(
                b"derived-start|"
                + bytes.fromhex(self.intent.job_id[2:])
                + bytes.fromhex(self.intent.commitment[2:])
            ).hex()
            self.events.append("start_confirmed")
        else:
            self.state = 3
            self.events.append("settlement_confirmed")
        return self._snapshot()

    def metering_receipt_digest(
        self,
        *,
        job_id,
        actual_asset_debit,
        billable_compute_units,
        usage_started_at,
        usage_ended_at,
        attestation_evidence_hash,
        receipt_expiry,
        **_kwargs,
    ):
        payload = "|".join(
            (
                job_id,
                str(actual_asset_debit),
                str(billable_compute_units),
                str(usage_started_at),
                str(usage_ended_at),
                attestation_evidence_hash,
                str(receipt_expiry),
            )
        ).encode()
        return "0x" + keccak(payload).hex()

    def metering_qvl_receipt_digest(self, **kwargs):
        meter_digest = self.metering_receipt_digest(**kwargs)
        return "0x" + keccak(b"qvl|" + bytes.fromhex(meter_digest[2:])).hex()

    def usage_commitment_for(
        self,
        *,
        job_id,
        actual_asset_debit,
        billable_compute_units,
        usage_started_at,
        usage_ended_at,
        attestation_evidence_hash,
        **_kwargs,
    ):
        payload = "|".join(
            (
                "usage",
                job_id,
                str(actual_asset_debit),
                str(billable_compute_units),
                str(usage_started_at),
                str(usage_ended_at),
                attestation_evidence_hash,
            )
        ).encode()
        return "0x" + keccak(payload).hex()

    # Match the production protocol spelling.
    usage_commitment = usage_commitment_for

    @staticmethod
    def _raw_signature(private_key: keys.PrivateKey, digest: str) -> str:
        signed = private_key.sign_msg_hash(bytes.fromhex(digest[2:]))
        raw = bytearray(signed.to_bytes())
        raw[64] += 27
        return "0x" + bytes(raw).hex()

    def raw_signature(self, digest: str) -> str:
        return self._raw_signature(self.verifier_private_key, digest)

    def qvl_raw_signature(self, digest: str) -> str:
        return self._raw_signature(self.qvl_private_key, digest)

    def close(self):
        return None

    def _prepared(self, purpose, raw):
        return PreparedTransaction(
            purpose=purpose,
            tx_hash="0x" + keccak(raw).hex(),
            raw_transaction="0x" + raw.hex(),
        )

    def _snapshot(self):
        job = VaultJob(
            project_id=self.intent.project_id,
            user=self.intent.user,
            asset=self.intent.asset,
            authorization_nonce=self.intent.authorization_nonce,
            max_asset_debit=self.intent.max_asset_debit,
            actual_asset_debit=self.actual_debit if self.state == 3 else 0,
            authorization_expiry=self.intent.authorization_expiry,
            started_at=NOW if self.state >= 2 else 0,
            usage_ended_at=self.usage_ended_at if self.state == 3 else 0,
            receipt_expiry=self.receipt_expiry if self.state == 3 else 0,
            rate_policy_commitment=self.intent.rate_policy_commitment,
            workload_commitment=self.intent.workload_commitment,
            manifest_commitment=self.intent.manifest_commitment,
            dispatch_intent_commitment=self.intent.commitment,
            compose_hash=self.intent.compose_hash if self.state >= 2 else ZERO32,
            start_commitment=self.start_commitment if self.state >= 2 else ZERO32,
            usage_commitment=(
                self.settled_usage_commitment if self.state == 3 else ZERO32
            ),
            attestation_evidence_hash=(
                self.attestation_evidence_hash if self.state == 3 else ZERO32
            ),
            billable_compute_units=(
                self.billable_compute_units if self.state == 3 else 0
            ),
            tee_identity=self.identity.address if self.state >= 2 else ZERO_ADDRESS,
            state=self.state,
        )
        return VaultSnapshot(
            chain_id=self.chain_id,
            block_number=100,
            block_hash=BLOCK_HASH,
            block_timestamp=NOW,
            vault_address=self.vault_address,
            vault_runtime_code_hash=self.runtime_code_hash,
            paused=False,
            developer_fee_frozen=True,
            asset_additions_frozen=True,
            rate_policy_additions_frozen=True,
            compose_policy_frozen=True,
            tee_identity_additions_frozen=True,
            metering_binding_frozen=True,
            metering_policy_set_hash=POLICY_SET,
            allowed_asset_count=1,
            active_rate_policy_count=2,
            approved_compose_count=1,
            approved_tee_identity_count=1,
            pending_developer_fee_activates_at=0,
            pending_asset_count=0,
            pending_rate_policy_count=0,
            pending_compose_count=0,
            pending_tee_identity_count=0,
            pending_metering_verifier=ZERO_ADDRESS,
            pending_metering_qvl_verifier=ZERO_ADDRESS,
            pending_metering_policy_set_hash=ZERO32,
            pending_metering_binding_activates_at=0,
            compose_approved=True,
            registered_tee_compose_hash=self.intent.compose_hash,
            metering_verifier=self.verifier_address,
            metering_qvl_verifier=self.qvl_verifier_address,
            rate_policy_asset=self.intent.asset,
            rate_policy_provider=PROVIDER,
            rate_policy_developer_fee_bps=500,
            rate_policy_active=True,
            job=job,
        )


class TestOnlyIdempotentRecipeExecutor:
    supports_idempotent_dispatch = False
    supports_at_most_once_dispatch = True
    supports_checkpointed_workload_release = True

    def __init__(self, gateway):
        self.gateway = gateway
        self.calls = []
        self.results = {}
        self.release_calls = []

    def _execute(self, intent, policy, *, dispatch_id):
        self.gateway.events.append("provider_called")
        self.calls.append(dispatch_id)
        if dispatch_id not in self.results:
            self.results[dispatch_id] = ProviderUsage(
                outcome="succeeded",
                prefill_tokens=80,
                sample_tokens=10,
                training_tokens=0,
                result_commitment=RESULT,
                provider_authoritative_invoice=False,
            )
        return self.results[dispatch_id]

    @contextmanager
    def prepare_attempt(self, intent, policy, *, dispatch_id):
        owner = self

        class Attempt:
            provider_boundary_crossed = False

            def execute(self):
                self.provider_boundary_crossed = True
                return owner._execute(intent, policy, dispatch_id=dispatch_id)

        yield Attempt()

    def release_after_usage_checkpoint(
        self,
        intent,
        policy,
        *,
        dispatch_id,
        usage,
        release_checkpoint_commitment,
    ):
        self.release_calls.append(
            (dispatch_id, usage.result_commitment, release_checkpoint_commitment)
        )


class TestOnlyMeteringClient:
    def __init__(self, gateway, *, fail_first=True):
        self.gateway = gateway
        self.fail_first = fail_first
        self.envelopes = []

    def decide(self, signed_usage):
        self.envelopes.append(copy.deepcopy(signed_usage.to_dict()))
        if self.fail_first and len(self.envelopes) == 1:
            raise ComputeRuntimeRetryable("test-only outage")
        expiry = NOW + 300
        billable_units = sum(
            int(signed_usage.envelope[name])
            for name in ("prefill_tokens", "sample_tokens", "training_tokens")
        )
        usage_started_at = signed_usage.envelope["usage_started_at"]
        usage_ended_at = signed_usage.envelope["usage_observed_at"]
        digest = self.gateway.metering_receipt_digest(
            block_number=100,
            job_id=signed_usage.envelope["job_id"],
            actual_asset_debit=5,
            billable_compute_units=billable_units,
            usage_started_at=usage_started_at,
            usage_ended_at=usage_ended_at,
            attestation_evidence_hash=ATTESTATION_EVIDENCE,
            receipt_expiry=expiry,
        )
        qvl_digest = self.gateway.metering_qvl_receipt_digest(
            block_number=100,
            job_id=signed_usage.envelope["job_id"],
            actual_asset_debit=5,
            billable_compute_units=billable_units,
            usage_started_at=usage_started_at,
            usage_ended_at=usage_ended_at,
            attestation_evidence_hash=ATTESTATION_EVIDENCE,
            receipt_expiry=expiry,
        )
        onchain_usage = self.gateway.usage_commitment_for(
            block_number=100,
            job_id=signed_usage.envelope["job_id"],
            actual_asset_debit=5,
            billable_compute_units=billable_units,
            usage_started_at=usage_started_at,
            usage_ended_at=usage_ended_at,
            attestation_evidence_hash=ATTESTATION_EVIDENCE,
        )
        return MeteringDecision(
            classification="attested_dual_verified_metering",
            provider_authoritative_invoice=False,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            vault_address=VAULT,
            pinned_block_number=signed_usage.block_number,
            pinned_block_hash=signed_usage.block_hash,
            policy_set_hash=POLICY_SET,
            rate_policy_commitment=RATE,
            workload_commitment=signed_usage.envelope["workload_commitment"],
            manifest_commitment=signed_usage.envelope["manifest_commitment"],
            dispatch_intent_commitment=signed_usage.envelope[
                "dispatch_intent_commitment"
            ],
            asset=ASSET,
            job_id=signed_usage.envelope["job_id"],
            usage_commitment=signed_usage.usage_commitment,
            onchain_usage_commitment=onchain_usage,
            actual_asset_debit=5,
            billable_compute_units=billable_units,
            usage_started_at=usage_started_at,
            usage_ended_at=usage_ended_at,
            attestation_evidence_hash=ATTESTATION_EVIDENCE,
            receipt_expiry=expiry,
            metering_receipt_digest=digest,
            metering_qvl_receipt_digest=qvl_digest,
            metering_verifier=self.gateway.verifier_address,
            metering_qvl_verifier=self.gateway.qvl_verifier_address,
            tee_identity=signed_usage.envelope["tee_identity"],
            compose_hash=COMPOSE,
            raw_secret_egress=False,
            verifier_signature=self.gateway.raw_signature(digest),
            qvl_signature=self.gateway.qvl_raw_signature(qvl_digest),
        )

    def close(self):
        return None


class TestOnlyExecutionPolicyAuthorizer:
    def __init__(self):
        self.calls = []
        self.allowed = True

    @contextmanager
    def authorized_execution_lease(
        self, *, job_id, execution_context_hash, now
    ):
        self.calls.append((job_id, execution_context_hash, now))
        if not self.allowed:
            raise ComputeExecutionPolicyNotPassed(
                "test-only policy revocation"
            )
        yield {"decision": "pass"}


class ComputeRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.identity = TestOnlyExecutionIdentity()
        self.intent = _intent(self.identity)
        self.journal = ComputeExecutionJournal(
            Path(self.temporary.name) / "dispatch.json",
            integrity_key=b"j" * 32,
        )
        self.journal.enqueue(
            self.intent,
            idempotency_key="dispatch-create-0001",
            created_at=NOW,
        )
        self.journal.confirm_workload_claim(
            self.intent.job_id,
            claim_commitment=WORKLOAD_CLAIM,
            updated_at=NOW,
        )

    def tearDown(self):
        self.temporary.cleanup()

    def _anchored_authorizer_for_context(self, execution_context_hash: str):
        approver = Account.create()
        approver_hash = execution_policy_approver_hash(approver.address)
        approver_root = execution_policy_approver_root_hash([approver_hash])
        approval_domain = (
            "base-sepolia:84532:"
            + "5a" * 32
            + ":0x"
            + "6b" * 32
            + ":"
            + "7c" * 32
            + ":"
            + approver_root
        )
        settings = Settings(
            execution_policy_approved_signers=approver.address,
            execution_policy_approver_root_hash=approver_root,
            execution_policy_approval_domain=approval_domain,
        )
        policy_path = Path(self.temporary.name) / (
            f"execution-policy-{execution_context_hash[:12]}.json"
        )
        policy_key = b"q" * 32
        writer_gateway = MemoryExecutionPolicyAnchorGateway()
        writer = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(policy_path, integrity_key=policy_key),
            writer_gateway,
        )
        domain_hash, approver_hashes, observed_root = (
            execution_policy_trust_context(settings)
        )
        writer.append_and_anchor(
            surface="compute_dispatch",
            resource_id=self.intent.job_id,
            result=PolicyGateResult(
                decision=PolicyDecision.PASS,
                corpus_ref="corpus://compute-exact-asset",
                stage=4,
                reason_code="policy_passed",
                request_hash="1" * 64,
                policy_hash="2" * 64,
                execution_context_hash=execution_context_hash,
            ),
            recorded_at=NOW,
            expires_at=NOW + 600,
            expected_previous_decision_hash="0" * 64,
            approver_hash=next(iter(approver_hashes)),
            approval_hash="3" * 64,
            approval_domain_hash=domain_hash,
            approver_root_hash=observed_root,
            now=NOW,
        )
        reader_gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        reader_gateway.records = writer_gateway.records
        reader = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(policy_path, integrity_key=policy_key),
            reader_gateway,
        )
        return AnchoredComputeExecutionAuthorizer(settings, reader)

    def test_canonical_identifiers_match_web_formula(self):
        project = "alpha:project"
        job = "job.0001"
        self.assertEqual(
            canonical_compute_project_id(project),
            "0x"
            + keccak(
                ("dnai.wikigen.compute.project.v1:" + project).encode("utf-8")
            ).hex(),
        )
        self.assertEqual(
            canonical_compute_job_id(job),
            "0x"
            + keccak(
                ("dnai.wikigen.compute.job.v1:" + job).encode("utf-8")
            ).hex(),
        )
        existing = "0x" + "aB" * 32
        self.assertEqual(canonical_compute_job_id(existing), existing.lower())
        with self.assertRaises(ComputeRuntimePolicyError):
            canonical_compute_job_id("contains spaces")
        with self.assertRaises(ComputeRuntimePolicyError):
            canonical_compute_job_id("0x" + "00" * 32)

    def test_collaboration_one_shot_context_is_non_circular_and_field_complete(self):
        parameters = tuple(
            inspect.signature(
                compute_collaboration_one_shot_authorization_context_commitment
            ).parameters
        )
        self.assertEqual(
            parameters,
            (
                "collaboration_execution_basis_commitment",
                "collaboration_execution_grant_set_commitment",
                "project_id",
                "job_id",
                "user",
                "asset",
                "authorization_nonce",
                "max_asset_debit",
                "authorization_expiry",
                "rate_policy_commitment",
                "workload_commitment",
                "manifest_commitment",
            ),
        )
        self.assertNotIn("compute_dispatch_intent_commitment", parameters)
        fields = {
            "collaboration_execution_basis_commitment": "sha256:" + "b1" * 32,
            "collaboration_execution_grant_set_commitment": "sha256:" + "b2" * 32,
            "project_id": "0x" + "11" * 32,
            "job_id": "0x" + "22" * 32,
            "user": "0x" + "33" * 20,
            "asset": ZERO_ADDRESS,
            "authorization_nonce": 7,
            "max_asset_debit": 123_456,
            "authorization_expiry": NOW + 3_600,
            "rate_policy_commitment": "0x" + "44" * 32,
            "workload_commitment": "0x" + "55" * 32,
            "manifest_commitment": "0x" + "66" * 32,
        }
        context = compute_collaboration_one_shot_authorization_context_commitment(
            **fields
        )
        self.assertEqual(
            context,
            "sha256:e1e6a62d78894cccfee48f506b8bc658d498dd922c9a6c2c371784a597e21c4e",
        )
        substitutions = (
            {"collaboration_execution_basis_commitment": "sha256:" + "b3" * 32},
            {"collaboration_execution_grant_set_commitment": "sha256:" + "b4" * 32},
            {"project_id": "0x" + "12" * 32},
            {"job_id": "0x" + "23" * 32},
            {"user": "0x" + "34" * 20},
            {"asset": "0x" + "35" * 20},
            {"authorization_nonce": 8},
            {"max_asset_debit": 123_457},
            {"authorization_expiry": NOW + 3_601},
            {"rate_policy_commitment": "0x" + "45" * 32},
            {"workload_commitment": "0x" + "56" * 32},
            {"manifest_commitment": "0x" + "67" * 32},
        )
        for substitution in substitutions:
            self.assertNotEqual(
                compute_collaboration_one_shot_authorization_context_commitment(
                    **(fields | substitution)
                ),
                context,
            )
        standalone = compute_standalone_authorization_context_commitment(
            **{
                key: value
                for key, value in fields.items()
                if not key.startswith("collaboration_execution_")
            }
        )
        self.assertNotEqual(standalone, context)
        with self.assertRaises(ComputeRuntimePolicyError):
            compute_collaboration_one_shot_authorization_context_commitment(
                **(
                    fields
                    | {"collaboration_execution_basis_commitment": "sha256:" + "0" * 64}
                )
            )
        with self.assertRaises(TypeError):
            compute_collaboration_one_shot_authorization_context_commitment(
                **(fields | {"compute_dispatch_intent_commitment": "0x" + "99" * 32})
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                authorization_kind="collaboration_one_shot",
                authorization_context_commitment=None,
            )

    def test_cross_language_execution_context_vector_normalizes_0x_inputs_to_bare_hex(self):
        vector_path = (
            Path(__file__).resolve().parents[3]
            / "web"
            / "src"
            / "lib"
            / "computeDispatchIntentV3Vectors.json"
        )
        payload = json.loads(vector_path.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["schema"],
            "dnai.compute.dispatch-intent-v3-vectors.v1",
        )
        vector = payload["vectors"][0]
        intent = ComputeDispatchIntent.create(**vector["intent"])
        self.assertEqual(intent.project_id, vector["project_id"])
        self.assertEqual(intent.job_id, vector["job_id"])
        self.assertEqual(intent.commitment, vector["intent_commitment"])
        self.assertEqual(
            intent.validate_compiled_recipe().commitment,
            vector["recipe_policy_commitment"],
        )
        observed = compute_execution_policy_context_hash(intent)
        self.assertFalse(observed.startswith("0x"))
        self.assertEqual(observed, vector["execution_context_hash"])

    def test_compiled_recipe_rejects_unbounded_or_cross_operation_limits(self):
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(self.identity, max_prefill_tokens=32_769)
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(self.identity, max_train_tokens=1)
        self.assertIn(
            ("training", "qwen3_8b", "qwen3_8b_lora_r32"), COMPILED_RECIPES
        )

    def test_exact_workload_authority_is_nonzero_and_changes_every_context(self):
        baseline = self.intent
        for update in (
            {"workload_id": "wrk_" + "cd" * 16},
            {"manifest_commitment": "0x" + "a1" * 32},
            {"workload_commitment": "0x" + "a2" * 32},
            {"workload_source_kind": "credential"},
            {
                "workload_execution_binding_commitment": (
                    "sha256:" + "a3" * 32
                )
            },
            {
                "workload_recipient_release_commitment": (
                    "sha256:" + "a4" * 32
                )
            },
            {
                "authorization_kind": "collaboration_one_shot",
                "authorization_context_commitment": (
                    "sha256:" + "a5" * 32
                ),
            },
        ):
            substituted = _intent(self.identity, **update)
            self.assertEqual(substituted.job_id, baseline.job_id)
            self.assertNotEqual(substituted.commitment, baseline.commitment)
            self.assertNotEqual(
                compute_execution_policy_context_hash(substituted),
                compute_execution_policy_context_hash(baseline),
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(self.identity, manifest_commitment=ZERO32)
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(self.identity, workload_commitment=ZERO32)
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(self.identity, workload_source_kind="device")
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                workload_execution_binding_commitment="sha256:" + "0" * 64,
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                workload_recipient_release_commitment="sha256:" + "0" * 64,
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                authorization_context_commitment="sha256:" + "a5" * 32,
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                authorization_kind="collaboration_one_shot",
                authorization_context_commitment="sha256:" + "0" * 64,
            )
        with self.assertRaises(ComputeRuntimePolicyError):
            _intent(
                self.identity,
                workload_schema="dnai.compute.workload.sft-jsonl.v1",
            )

    def test_pass_for_same_job_id_cannot_replay_onto_substituted_intent_metadata(self):
        approved_context = compute_execution_policy_context_hash(self.intent)
        authorizer = self._anchored_authorizer_for_context(approved_context)
        substituted = _intent(self.identity, max_asset_debit=26)
        self.assertEqual(substituted.job_id, self.intent.job_id)
        self.assertNotEqual(substituted.commitment, self.intent.commitment)
        substituted_journal = ComputeExecutionJournal(
            Path(self.temporary.name) / "substituted-dispatch.json",
            integrity_key=b"s" * 32,
        )
        substituted_journal.enqueue(
            substituted,
            idempotency_key="substituted-dispatch-0001",
            created_at=NOW,
        )
        substituted_journal.confirm_workload_claim(
            substituted.job_id,
            claim_commitment=WORKLOAD_CLAIM,
            updated_at=NOW,
        )
        gateway = TestOnlyVaultGateway(
            substituted, self.identity, bytes.fromhex("25" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        result = ComputeExecutionWorker(
            journal=substituted_journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=TestOnlyMeteringClient(gateway),
            policy_authorizer=authorizer,
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        ).run_once()

        self.assertEqual(result.state, "blocked")
        self.assertEqual(result.reason, "execution_policy_not_passed")
        self.assertFalse(result.execution_policy_authorized)
        self.assertEqual(gateway.events, [])
        self.assertEqual(provider.calls, [])
        self.assertEqual(
            substituted_journal.get(substituted.job_id)["stage"],
            ExecutionStage.INTENT_CREATED.value,
        )

    def test_pass_for_same_intent_cannot_replay_after_compiled_recipe_drift(self):
        approved_context = compute_execution_policy_context_hash(self.intent)
        authorizer = self._anchored_authorizer_for_context(approved_context)
        key = (self.intent.operation, self.intent.model, self.intent.recipe)
        original = COMPILED_RECIPES[key]
        drifted = CompiledRecipePolicy(
            operation=original.operation,
            model=original.model,
            recipe=original.recipe,
            allowed_result_policies=original.allowed_result_policies,
            max_prefill_tokens=original.max_prefill_tokens + 1,
            max_sample_tokens=original.max_sample_tokens,
            max_train_tokens=original.max_train_tokens,
        )
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("26" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        try:
            COMPILED_RECIPES[key] = drifted
            result = ComputeExecutionWorker(
                journal=self.journal,
                gateway=gateway,
                identity=self.identity,
                provider=provider,
                metering=TestOnlyMeteringClient(gateway),
                policy_authorizer=authorizer,
                metering_policy_set_hash=POLICY_SET,
                confirmations=2,
                clock=lambda: NOW,
            ).run_once()
        finally:
            COMPILED_RECIPES[key] = original

        self.assertEqual(result.state, "blocked")
        self.assertEqual(result.reason, "execution_policy_not_passed")
        self.assertEqual(gateway.events, [])
        self.assertEqual(provider.calls, [])

    def test_journal_is_authenticated_private_and_idempotent(self):
        mode = os.stat(self.journal.path).st_mode & 0o777
        self.assertEqual(mode, 0o600)
        raw = self.journal.path.read_text()
        self.assertNotIn("private user prompt", raw)
        self.assertNotIn("private training example", raw)
        replay, created = self.journal.enqueue(
            self.intent,
            idempotency_key="dispatch-create-0001",
            created_at=NOW + 1,
        )
        self.assertFalse(created)
        self.assertFalse(replay["legacy_credit_ledger_mutated"])
        different = _intent(self.identity, max_asset_debit=26)
        with self.assertRaises(ComputeIntentConflict):
            self.journal.enqueue(
                different,
                idempotency_key="dispatch-create-0001",
                created_at=NOW + 2,
            )
        envelope = json.loads(raw)
        envelope["body"]["sequence"] += 1
        self.journal.path.write_text(json.dumps(envelope))
        os.chmod(self.journal.path, 0o600)
        with self.assertRaises(ComputeRuntimeStateError):
            self.journal.get(self.intent.job_id)

    def test_workload_claim_pending_is_recoverable_exact_and_non_actionable(self):
        path = Path(self.temporary.name) / "pending-dispatch.json"
        journal = ComputeExecutionJournal(path, integrity_key=b"p" * 32)
        pending, created = journal.enqueue(
            self.intent,
            idempotency_key="pending-dispatch-0001",
            created_at=NOW,
        )
        self.assertTrue(created)
        self.assertEqual(
            pending["stage"], ExecutionStage.WORKLOAD_CLAIM_PENDING.value
        )
        self.assertFalse(pending["workload_claim_confirmed"])
        self.assertIsNone(journal.next_actionable())

        restarted = ComputeExecutionJournal(path, integrity_key=b"p" * 32)
        replay, replay_created = restarted.enqueue(
            self.intent,
            idempotency_key="pending-dispatch-0001",
            created_at=NOW + 1,
        )
        self.assertFalse(replay_created)
        self.assertEqual(
            replay["stage"], ExecutionStage.WORKLOAD_CLAIM_PENDING.value
        )
        confirmed, changed = restarted.confirm_workload_claim(
            self.intent.job_id,
            claim_commitment=WORKLOAD_CLAIM,
            updated_at=NOW + 2,
        )
        self.assertTrue(changed)
        self.assertEqual(confirmed["stage"], ExecutionStage.INTENT_CREATED.value)
        self.assertEqual(confirmed["workload_claim_commitment"], WORKLOAD_CLAIM)
        self.assertTrue(confirmed["workload_claim_confirmed"])

        exact, changed = restarted.confirm_workload_claim(
            self.intent.job_id,
            claim_commitment=WORKLOAD_CLAIM,
            updated_at=NOW + 3,
        )
        self.assertFalse(changed)
        self.assertEqual(exact, confirmed)
        with self.assertRaises(ComputeIntentConflict):
            restarted.confirm_workload_claim(
                self.intent.job_id,
                claim_commitment="sha256:" + "97" * 32,
                updated_at=NOW + 4,
            )

    def test_workload_claim_failure_and_one_workload_one_job_fail_closed(self):
        path = Path(self.temporary.name) / "claim-failed-dispatch.json"
        journal = ComputeExecutionJournal(path, integrity_key=b"f" * 32)
        journal.enqueue(
            self.intent,
            idempotency_key="claim-failed-dispatch-0001",
            created_at=NOW,
        )
        failed = journal.fail_workload_claim(
            self.intent.job_id,
            updated_at=NOW + 1,
        )
        self.assertEqual(failed["stage"], ExecutionStage.BLOCKED.value)
        self.assertFalse(failed["workload_claim_confirmed"])
        self.assertIsNone(journal.next_actionable())
        self.assertEqual(
            journal.fail_workload_claim(
                self.intent.job_id,
                updated_at=NOW + 2,
            ),
            failed,
        )
        with self.assertRaises(ComputeRuntimeStateError):
            journal.confirm_workload_claim(
                self.intent.job_id,
                claim_commitment=WORKLOAD_CLAIM,
                updated_at=NOW + 3,
            )

        other_job = _intent(self.identity, job_reference="job_beta")
        with self.assertRaises(ComputeIntentConflict):
            journal.enqueue(
                other_job,
                idempotency_key="claim-failed-dispatch-0002",
                created_at=NOW + 4,
            )

    def test_authenticated_v1_journal_is_not_opened_as_v2_state(self):
        path = Path(self.temporary.name) / "legacy-dispatch.json"
        journal = ComputeExecutionJournal(path, integrity_key=b"l" * 32)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        envelope["body"]["schema"] = "dnai.compute.execution-journal.v1"
        envelope["body"]["schema_version"] = 1
        encoded = json.dumps(
            envelope["body"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        envelope["mac"] = hmac.new(
            b"l" * 32,
            b"dnai-wikigen/compute-execution-journal/v2\0" + encoded,
            hashlib.sha256,
        ).hexdigest()
        path.write_text(
            json.dumps(envelope, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        os.chmod(path, 0o600)
        with self.assertRaises(ComputeRuntimeStateError):
            journal.next_actionable()

    def test_pre_start_cancellation_is_serialized_idempotent_and_bounded(self):
        receipt, changed = self.journal.cancel_before_start(
            self.intent.job_id,
            user=self.identity.address,
            idempotency_key="dispatch-cancel-0001",
            canceled_at=NOW + 1,
        )
        self.assertTrue(changed)
        self.assertEqual(receipt["surface"], "compute_dispatch_cancellation")
        self.assertTrue(receipt["journal_execution_prevented"])
        self.assertFalse(receipt["provider_dispatch_performed"])
        self.assertFalse(receipt["provider_dispatch_may_have_occurred"])
        self.assertFalse(receipt["workload_ciphertext_released"])
        self.assertFalse(receipt["vault_authorization_released"])
        self.assertTrue(receipt["onchain_cancel_required"])
        self.assertFalse(receipt["exact_asset_capacity_released"])
        self.assertRegex(
            receipt["cancellation_checkpoint_commitment"],
            r"^sha256:[0-9a-f]{64}$",
        )
        self.assertIsNone(self.journal.next_actionable())

        confirmed = self.journal.confirm_cancellation_workload_release(
            self.intent.job_id,
            checkpoint_commitment=receipt[
                "cancellation_checkpoint_commitment"
            ],
            updated_at=NOW + 2,
        )
        self.assertTrue(confirmed["workload_ciphertext_released"])
        replay, replay_changed = self.journal.cancel_before_start(
            self.intent.job_id,
            user=self.identity.address,
            idempotency_key="dispatch-cancel-0001",
            canceled_at=NOW + 50,
        )
        self.assertFalse(replay_changed)
        self.assertEqual(replay, confirmed)
        self.assertEqual(replay["canceled_at"], NOW + 1)

        with self.assertRaises(ComputeIntentConflict):
            self.journal.cancel_before_start(
                self.intent.job_id,
                user=self.identity.address,
                idempotency_key="dispatch-cancel-other",
                canceled_at=NOW + 3,
            )
        with self.assertRaises(ComputeIntentNotFound):
            self.journal.cancel_before_start(
                self.intent.job_id,
                user=TestOnlyExecutionIdentity("0x" + "12" * 32).address,
                idempotency_key="dispatch-cancel-0001",
                canceled_at=NOW + 3,
            )

    def test_cancellation_cannot_cross_start_preparation_boundary(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("21" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=TestOnlyMeteringClient(gateway),
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )
        first = worker.run_once()
        self.assertEqual(first.state, ExecutionStage.START_BROADCAST.value)
        with self.assertRaises(ComputeCancellationUnavailable):
            self.journal.cancel_before_start(
                self.intent.job_id,
                user=self.identity.address,
                idempotency_key="dispatch-cancel-0001",
                canceled_at=NOW + 1,
            )
        self.assertEqual(provider.calls, [])
        self.assertFalse(
            self.journal.public_get(self.intent.job_id)[
                "provider_dispatch_may_have_occurred"
            ]
        )

    def test_cancellation_waits_for_the_same_cross_process_cycle_lease(self):
        started = threading.Event()
        finished = threading.Event()
        errors: list[Exception] = []

        def cancel():
            started.set()
            try:
                self.journal.cancel_before_start(
                    self.intent.job_id,
                    user=self.identity.address,
                    idempotency_key="dispatch-cancel-0001",
                    canceled_at=NOW + 1,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                finished.set()

        with self.journal.execution_cycle_lease():
            thread = threading.Thread(target=cancel)
            thread.start()
            self.assertTrue(started.wait(1))
            self.assertFalse(finished.wait(0.2))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(errors)
        self.assertTrue(finished.is_set())
        self.assertIsNone(self.journal.next_actionable())

    def test_worker_reuses_provider_id_and_identical_usage_after_retry(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("22" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        metering = TestOnlyMeteringClient(gateway, fail_first=True)
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=metering,
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )

        first = worker.run_once()
        self.assertEqual(first.state, ExecutionStage.START_BROADCAST.value)
        self.assertNotIn("provider_called", gateway.events)
        second = worker.run_once()
        self.assertEqual(second.state, ExecutionStage.METERING_PENDING.value)
        self.assertEqual(len(provider.calls), 1)
        third = worker.run_once()
        self.assertEqual(third.state, ExecutionStage.SETTLEMENT_BROADCAST.value)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(len(metering.envelopes), 2)
        self.assertEqual(metering.envelopes[0], metering.envelopes[1])
        fourth = worker.run_once()
        self.assertTrue(fourth.settled)
        self.assertEqual(len(provider.calls), 1)
        self.assertLess(
            gateway.events.index("start_confirmed"),
            gateway.events.index("provider_called"),
        )
        record = self.journal.get(self.intent.job_id)
        self.assertEqual(record["stage"], ExecutionStage.SETTLED.value)
        self.assertFalse(record["provider_authoritative"])
        self.assertFalse(record["legacy_credit_ledger_mutated"])
        signed = record["signed_usage"]["usage"]
        recovered = Account.recover_message(
            encode_defunct(hexstr=signed["usage_commitment"]),
            signature=signed["tee_signature"],
        )
        self.assertEqual(recovered.lower(), self.identity.address)
        receipt = self.journal.public_usage_receipt(self.intent.job_id)
        self.assertEqual(
            receipt["surface"],
            "compute_exact_asset_usage_receipt",
        )
        self.assertEqual(receipt["job_id"], self.intent.job_id)
        self.assertTrue(receipt["settlement"]["confirmed"])
        self.assertEqual(
            receipt["settlement"]["transaction_hash"],
            record["settlement_transaction"]["tx_hash"],
        )
        self.assertEqual(
            receipt["provider_usage"]["result_commitment"],
            RESULT,
        )
        self.assertFalse(receipt["provider_authoritative_invoice"])
        self.assertFalse(receipt["raw_prompt_egress"])
        self.assertFalse(receipt["raw_examples_egress"])
        self.assertFalse(receipt["raw_output_egress"])
        self.assertFalse(receipt["provider_identifier_egress"])
        self.assertFalse(receipt["raw_transaction_egress"])
        self.assertNotIn(
            record["settlement_transaction"]["raw_transaction"],
            json.dumps(receipt, sort_keys=True),
        )

    def test_blocked_post_usage_status_preserves_provider_boundary(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("24" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)

        class RejectingMetering(TestOnlyMeteringClient):
            def decide(self, signed_usage):
                self.envelopes.append(copy.deepcopy(signed_usage.to_dict()))
                raise ComputeRuntimePolicyError("test-only metering rejection")

        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=RejectingMetering(gateway, fail_first=False),
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )
        self.assertEqual(
            worker.run_once().state,
            ExecutionStage.START_BROADCAST.value,
        )
        self.assertEqual(worker.run_once().state, ExecutionStage.BLOCKED.value)

        public = self.journal.public_get(self.intent.job_id)
        self.assertEqual(public["provider_dispatch_status"], "usage_finalized")
        self.assertTrue(public["provider_dispatch_may_have_occurred"])
        self.assertTrue(public["provider_usage_finalized"])
        self.assertIsNotNone(public["bounded_result"])
        self.assertTrue(public["workload_ciphertext_released"])

    def test_usage_receipt_fails_closed_before_settlement_and_on_cross_binding_drift(self):
        with self.assertRaises(ComputeUsageReceiptNotReady):
            self.journal.public_usage_receipt(self.intent.job_id)

        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("23" * 32)
        )
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=TestOnlyIdempotentRecipeExecutor(gateway),
            metering=TestOnlyMeteringClient(gateway),
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )
        for _ in range(4):
            result = worker.run_once()
        self.assertTrue(result.settled)
        self.journal.public_usage_receipt(self.intent.job_id)

        # Simulate an authenticated-writer regression rather than an external
        # file attacker: the envelope MAC remains valid, but the receipt's
        # independent cross-binding must still reject a different job.
        with self.journal._exclusive_lock():
            body = self.journal._load_unlocked()
            body["records"][self.intent.job_id]["metering_decision"][
                "job_id"
            ] = "0x" + "fe" * 32
            self.journal._write_unlocked(body)
        with self.assertRaises(ComputeRuntimeStateError):
            self.journal.public_usage_receipt(self.intent.job_id)

    def test_snapshot_mismatch_blocks_before_start_or_provider(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("33" * 32)
        )
        gateway.runtime_code_hash = "0x" + "aa" * 32
        original_snapshot = gateway.snapshot

        def mismatch(**kwargs):
            snapshot = original_snapshot(**kwargs)
            return VaultSnapshot(
                **{
                    **snapshot.__dict__,
                    "registered_tee_compose_hash": "0x" + "bb" * 32,
                }
            )

        gateway.snapshot = mismatch
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=TestOnlyMeteringClient(gateway, fail_first=False),
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            clock=lambda: NOW,
        )
        result = worker.run_once()
        self.assertEqual(result.state, ExecutionStage.BLOCKED.value)
        self.assertEqual(provider.calls, [])
        self.assertEqual(gateway.broadcasted, set())

    def test_provider_without_at_most_once_hold_is_rejected_before_start_job(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("44" * 32)
        )

        class TestOnlyUnsafeProvider:
            supports_idempotent_dispatch = False
            supports_at_most_once_dispatch = False

        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=TestOnlyUnsafeProvider(),
            metering=TestOnlyMeteringClient(gateway, fail_first=False),
            policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
            metering_policy_set_hash=POLICY_SET,
            clock=lambda: NOW,
        )
        result = worker.run_once()
        self.assertEqual(result.state, ExecutionStage.BLOCKED.value)
        self.assertEqual(gateway.events, [])
        self.assertEqual(gateway.broadcasted, set())
        public = self.journal.public_get(self.intent.job_id)
        self.assertEqual(public["provider_dispatch_status"], "not_started")
        self.assertFalse(public["provider_dispatch_may_have_occurred"])

    def test_crossed_provider_boundary_is_held_and_never_auto_redispatched(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("4a" * 32)
        )

        class AmbiguousProvider:
            supports_idempotent_dispatch = False
            supports_at_most_once_dispatch = True
            supports_checkpointed_workload_release = True

            def __init__(self):
                self.calls = 0

            @contextmanager
            def prepare_attempt(self, intent, policy, *, dispatch_id):
                owner = self

                class Attempt:
                    provider_boundary_crossed = False

                    def execute(self):
                        owner.calls += 1
                        self.provider_boundary_crossed = True
                        raise ComputeProviderDispatchFailure(
                            provider_boundary_crossed=True
                        )

                yield Attempt()

            def release_after_usage_checkpoint(self, *args, **kwargs):
                raise AssertionError("ambiguous provider usage cannot be released")

        provider = AmbiguousProvider()

        def worker():
            return ComputeExecutionWorker(
                journal=self.journal,
                gateway=gateway,
                identity=self.identity,
                provider=provider,
                metering=TestOnlyMeteringClient(gateway, fail_first=False),
                policy_authorizer=TestOnlyExecutionPolicyAuthorizer(),
                metering_policy_set_hash=POLICY_SET,
                confirmations=2,
                clock=lambda: NOW,
            )

        self.assertEqual(
            worker().run_once().state,
            ExecutionStage.START_BROADCAST.value,
        )
        ambiguous = worker().run_once()
        self.assertEqual(
            ambiguous.state,
            ExecutionStage.PROVIDER_OUTCOME_AMBIGUOUS.value,
        )
        self.assertTrue(ambiguous.provider_dispatch_may_have_occurred)
        self.assertEqual(provider.calls, 1)

        recovered = worker().run_once()
        self.assertEqual(recovered.state, "idle")
        self.assertEqual(provider.calls, 1)
        public = self.journal.public_get(self.intent.job_id)
        self.assertFalse(public["automatic_provider_redispatch"])
        self.assertTrue(public["ambiguous_outcome_hold"])
        self.assertTrue(public["workload_ciphertext_retained_for_reconciliation"])
        self.assertFalse(public["workload_ciphertext_released"])

    def test_revocation_before_dispatch_id_does_not_overclaim_provider_call(self):
        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("45" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        authorizer = TestOnlyExecutionPolicyAuthorizer()
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=TestOnlyMeteringClient(gateway, fail_first=False),
            policy_authorizer=authorizer,
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )

        started = worker.run_once()
        self.assertEqual(started.state, ExecutionStage.START_BROADCAST.value)
        self.assertFalse(started.provider_dispatched)
        self.assertFalse(started.provider_dispatch_may_have_occurred)
        self.assertIsNone(self.journal.get(self.intent.job_id)["dispatch_id"])

        authorizer.allowed = False
        blocked = worker.run_once()
        self.assertEqual(blocked.reason, "execution_policy_not_passed")
        self.assertFalse(blocked.provider_dispatched)
        self.assertFalse(blocked.provider_dispatch_may_have_occurred)
        self.assertEqual(provider.calls, [])
        self.assertEqual(
            self.journal.get(self.intent.job_id)["stage"],
            ExecutionStage.START_BROADCAST.value,
        )

    def test_revocation_waits_for_provider_boundary_then_blocks_recovery(self):
        approver = Account.from_key("0x" + "5a" * 32)
        approver_hash = execution_policy_approver_hash(approver.address)
        approver_root = execution_policy_approver_root_hash({approver_hash})
        approval_domain = (
            "base-sepolia:84532:"
            + WRITER_RELEASE[2:]
            + ":0x"
            + "6b" * 32
            + ":"
            + "7c" * 32
            + ":"
            + approver_root
        )
        settings = Settings(
            execution_policy_approved_signers=approver.address,
            execution_policy_approver_root_hash=approver_root,
            execution_policy_approval_domain=approval_domain,
        )
        policy_path = Path(self.temporary.name) / "execution-policy.json"
        policy_key = b"p" * 32
        writer_gateway = MemoryExecutionPolicyAnchorGateway()
        writer = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(policy_path, integrity_key=policy_key),
            writer_gateway,
        )
        domain_hash, approver_hashes, observed_root = (
            execution_policy_trust_context(settings)
        )
        now = NOW
        passed = writer.append_and_anchor(
            surface="compute_dispatch",
            resource_id=self.intent.job_id,
            result=PolicyGateResult(
                decision=PolicyDecision.PASS,
                corpus_ref="corpus://compute-exact-asset",
                stage=4,
                reason_code="policy_passed",
                request_hash="1" * 64,
                policy_hash="2" * 64,
                execution_context_hash=(
                    compute_execution_policy_context_hash(self.intent)
                ),
            ),
            recorded_at=now,
            expires_at=now + 600,
            expected_previous_decision_hash="0" * 64,
            approver_hash=next(iter(approver_hashes)),
            approval_hash="3" * 64,
            approval_domain_hash=domain_hash,
            approver_root_hash=observed_root,
            now=now,
        )
        reader_gateway = MemoryExecutionPolicyAnchorGateway(read_only=True)
        reader_gateway.records = writer_gateway.records
        reader = AnchoredExecutionPolicyCoordinator(
            ExecutionPolicyStore(policy_path, integrity_key=policy_key),
            reader_gateway,
        )

        gateway = TestOnlyVaultGateway(
            self.intent, self.identity, bytes.fromhex("66" * 32)
        )
        provider = TestOnlyIdempotentRecipeExecutor(gateway)
        provider_entered = threading.Event()
        release_provider = threading.Event()
        original_execute = provider._execute

        def blocking_execute(intent, policy, *, dispatch_id):
            provider_entered.set()
            if not release_provider.wait(5):
                raise AssertionError("test provider release timed out")
            return original_execute(
                intent,
                policy,
                dispatch_id=dispatch_id,
            )

        provider._execute = blocking_execute
        worker = ComputeExecutionWorker(
            journal=self.journal,
            gateway=gateway,
            identity=self.identity,
            provider=provider,
            metering=TestOnlyMeteringClient(gateway, fail_first=True),
            policy_authorizer=AnchoredComputeExecutionAuthorizer(
                settings,
                reader,
            ),
            metering_policy_set_hash=POLICY_SET,
            confirmations=2,
            clock=lambda: NOW,
        )

        first = worker.run_once()
        self.assertEqual(first.state, ExecutionStage.START_BROADCAST.value)
        self.assertTrue(first.execution_policy_authorized)

        worker_result = {}
        revocation_started = threading.Event()
        revocation_finished = threading.Event()
        errors = []

        def run_provider_cycle():
            try:
                worker_result["result"] = worker.run_once()
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def revoke():
            revocation_started.set()
            try:
                writer.append_and_anchor(
                    surface="compute_dispatch",
                    resource_id=self.intent.job_id,
                    result=PolicyGateResult(
                        decision=PolicyDecision.HOLD,
                        corpus_ref="corpus://compute-exact-asset",
                        stage=4,
                        reason_code="human_review_required",
                        request_hash="4" * 64,
                        policy_hash="5" * 64,
                    ),
                    recorded_at=now + 1,
                    expires_at=now + 601,
                    expected_previous_decision_hash=passed["decision_hash"],
                    now=now + 1,
                )
            except Exception as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                revocation_finished.set()

        worker_thread = threading.Thread(target=run_provider_cycle)
        worker_thread.start()
        self.assertTrue(provider_entered.wait(2))
        revocation_thread = threading.Thread(target=revoke)
        revocation_thread.start()
        self.assertTrue(revocation_started.wait(1))
        self.assertFalse(revocation_finished.wait(0.2))
        self.assertEqual(
            reader.store.latest(
                surface="compute_dispatch",
                resource_id=self.intent.job_id,
            )["decision"],
            "pass",
        )
        release_provider.set()
        worker_thread.join(timeout=5)
        revocation_thread.join(timeout=5)

        self.assertFalse(worker_thread.is_alive())
        self.assertFalse(revocation_thread.is_alive())
        self.assertFalse(errors)
        self.assertTrue(worker_result["result"].execution_policy_authorized)
        self.assertTrue(worker_result["result"].provider_dispatched)
        self.assertTrue(
            worker_result["result"].provider_dispatch_may_have_occurred
        )
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(
            writer.store.latest(
                surface="compute_dispatch",
                resource_id=self.intent.job_id,
            )["decision"],
            "hold",
        )

        blocked = worker.run_once()
        self.assertEqual(blocked.state, "blocked")
        self.assertEqual(blocked.reason, "execution_policy_not_passed")
        self.assertFalse(blocked.execution_policy_authorized)
        self.assertTrue(blocked.provider_dispatched)
        self.assertTrue(blocked.provider_dispatch_may_have_occurred)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(
            self.journal.get(self.intent.job_id)["stage"],
            ExecutionStage.METERING_PENDING.value,
        )
        reader.close()
        writer.close()


if __name__ == "__main__":
    unittest.main()
