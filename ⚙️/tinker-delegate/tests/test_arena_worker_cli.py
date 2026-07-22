import hashlib
import io
import json
import os
import tempfile
import tomllib
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import httpx
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_hash.auto import keccak

from tinker_delegate.arena_ingress import ArenaIngressRecipient
from tinker_delegate.arena_safe_worker import (
    ArenaAttestationPacket,
    ArenaRegistryClaimRequest,
)
from tinker_delegate.arena_release_approval import (
    release_approved_challenge_set_sha256,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    SAFE_IR_RUNTIME,
)
from tinker_delegate.arena_store import (
    BIO_SAFE_IR_CHALLENGE_ID,
    BIO_SAFE_IR_CHALLENGE_VERSION,
    default_challenge_catalog,
)
from tinker_delegate.arena_worker_cli import (
    BASE_SEPOLIA_CHAIN_ID,
    EVALUATOR_SCHEMA,
    MAX_SECURE_JSON_BYTES,
    QVL_AUTH_TOKEN_ENV,
    RELEASE_SCHEMA,
    ArenaRegistryBlock,
    ArenaRegistryChallengeState,
    ArenaRegistryVersionState,
    ArenaWorkerBootstrapError,
    HttpsArenaRegistryReader,
    HttpsArenaQvlClient,
    RefreshingArenaRegistryClaimGate,
    _decode_version,
    build_arena_worker_service_from_settings,
    build_parser,
    compute_arena_release_policy_commitment,
    load_independent_qvl_verdict,
    load_release_manifest,
    load_sealed_evaluator,
    main,
    sealed_evaluator_commitment,
    validate_fresh_challenge_registry,
    write_bounded_bootstrap_failure,
)
from tinker_delegate.arena_worker_service import (
    EXIT_ACTIVATION_UNAVAILABLE,
    ArenaSafeWorkerService,
)
from tinker_delegate.config import Settings
from tinker_delegate.chain_submitter import SignerAttestationEvidence
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.execution_policy_store import (
    execution_policy_approval_domain_hash,
    execution_policy_approver_hash,
    execution_policy_approver_root_hash,
)
from tinker_delegate.result_verifier import (
    INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
    INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
    IndependentAttestationVerdict,
    independent_attestation_verdict_digest,
)
from tinker_delegate.qvl_freshness import (
    CHALLENGE_SCHEMA,
    QvlChallenge,
    qvl_challenge_digest,
)


NOW = 1_800_000_000
REGISTRY = "0x" + "99" * 20
TEE = "0x" + "88" * 20
COMPOSE = "22" * 32
OS_IMAGE = "33" * 32
QUOTE_BYTES = bytes.fromhex("44" * 1_024)
QUOTE_HASH = hashlib.sha256(QUOTE_BYTES).hexdigest()
APP_ID = "34" * 20
CODE = bytes.fromhex("6000600055")
POLICY_MANIFEST_COMMITMENT = "55" * 32
POLICY_ANCHOR = "0x" + "66" * 20
POLICY_ANCHOR_RUNTIME_CODE_HASH = "0x" + "77" * 32
POLICY_ANCHOR_EVIDENCE_SHA256 = "sha256:" + "aa" * 32
POLICY_ANCHOR_WRITER = "0x" + "bb" * 20
QVL_POLICY = "0x" + "cc" * 32
QVL_TOKEN = "release-specific-token-" + "x" * 32
CVM_ID = "cvm-main-runtime-0001"
DEPLOYMENT_INTENT_SHA256 = "sha256:" + "41" * 32
RELEASE_AUTHORITY_SHA256 = "sha256:" + "42" * 32
CEREMONY_NONCE = "0x" + "43" * 32
MEASUREMENT_POLICY_SHA256 = "sha256:" + "44" * 32
ARENA_QVL_CLIENT_LINEAGE = {
    "chain_id": BASE_SEPOLIA_CHAIN_ID,
    "cvm_id": CVM_ID,
    "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
    "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
    "ceremony_nonce": CEREMONY_NONCE,
    "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
}


def _canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _write_0600(path: Path, value, *, raw=False):
    encoded = value if raw else _canonical(value)
    path.write_bytes(encoded)
    path.chmod(0o600)
    return encoded


def _signed_challenge(qvl, **overrides):
    values = {
        "schema": CHALLENGE_SCHEMA,
        "chain_id": BASE_SEPOLIA_CHAIN_ID,
        "domain": "main_runtime_cvm",
        "profile": "arena",
        "cvm_id": CVM_ID,
        "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
        "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
        "ceremony_nonce": CEREMONY_NONCE,
        "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
        "release_policy_hash": QVL_POLICY,
        "challenge_id": "0x" + "dd" * 32,
        "challenge_digest": "0x" + "01" * 32,
        "issued_at": NOW - 10,
        "expires_at": NOW + 110,
        "verifier_address": qvl.address.lower(),
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    unsigned = QvlChallenge(**values)
    digest = qvl_challenge_digest(unsigned)
    signed = qvl.sign_message(encode_defunct(hexstr=digest))
    return replace(
        unsigned,
        challenge_digest=digest,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )


def _signed_verdict(recipient, qvl, *, challenge=None, signer=None, **overrides):
    challenge = challenge or _signed_challenge(qvl)
    values = {
        "schema": INDEPENDENT_ATTESTATION_VERDICT_SCHEMA,
        "verification_method": INDEPENDENT_ATTESTATION_VERIFICATION_METHOD,
        "verified": True,
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
        "challenge_issued_at": challenge.issued_at,
        "challenge_expires_at": challenge.expires_at,
        "quote_hash": "0x" + QUOTE_HASH,
        "report_data": "0x" + recipient.report_data.hex(),
        "compose_hash": "0x" + COMPOSE,
        "app_id": APP_ID,
        "os_image_hash": OS_IMAGE,
        "signer_address": TEE,
        "contract_address": REGISTRY,
        "issued_at": NOW - 10,
        "verifier_address": qvl.address,
        "verifier_signature": "0x" + "00" * 65,
    }
    values.update(overrides)
    values.setdefault("expires_at", NOW + 120)
    values.setdefault("activation_evidence_lease_expires_at", values["expires_at"])
    unsigned = IndependentAttestationVerdict(**values)
    signed = (signer or qvl).sign_message(
        encode_defunct(hexstr=independent_attestation_verdict_digest(unsigned))
    )
    return replace(
        unsigned,
        verifier_signature="0x" + bytes(signed.signature).hex(),
    )


def _attestation_packet(recipient, quote=QUOTE_BYTES):
    return ArenaAttestationPacket(
        evidence=SignerAttestationEvidence(
            mode="tdx",
            signer_address=TEE,
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            contract_address=REGISTRY,
            report_data="0x" + recipient.report_data.hex(),
            quote_report_data="0x" + recipient.report_data.hex(),
            quote_hash="0x" + hashlib.sha256(quote).hexdigest(),
            quote_size=len(quote),
            compose_hash="0x" + COMPOSE,
            app_id=APP_ID,
            os_image_hash=OS_IMAGE,
        ),
        quote="0x" + quote.hex(),
    )


class FakeRegistryReader:
    def __init__(self, release, *, now=NOW):
        self.release = release
        self.now = now
        self.chain = BASE_SEPOLIA_CHAIN_ID
        self.block_number = 1_234_567
        self.block_hash = "0x" + "12" * 32
        self.block_timestamp = now - 2
        self.code = CODE
        self.paused = False
        self.exists = True
        self.challenge_state = ArenaRegistryChallengeState(
            controller="0x" + "77" * 20,
            pending_controller="0x" + "00" * 20,
            lifecycle=1,
            latest_version=release.challenge_binding.registry_version,
            paused=False,
            configuration_frozen=True,
        )
        binding = release.challenge_binding
        self.version_state = ArenaRegistryVersionState(
            metadata_uri=binding.metadata_uri,
            metadata_hash=binding.metadata_hash,
            sealed_artifact_commitment=binding.sealed_artifact_commitment,
            evaluator_commitment=binding.evaluator_commitment,
            release_policy_commitment=binding.release_policy_commitment,
        )
        self.closed = False
        self.finalized_reads = 0
        self.block_reads = 0
        self.finalized_after = None
        self.block_after = None

    def chain_id(self):
        return self.chain

    def latest_block(self):
        return self.block_number, self.block_timestamp

    def _current_block(self):
        return ArenaRegistryBlock(
            number=self.block_number,
            block_hash=self.block_hash,
            timestamp=self.block_timestamp,
        )

    def finalized_block(self):
        self.finalized_reads += 1
        if self.finalized_reads > 1 and self.finalized_after is not None:
            return self.finalized_after
        return self._current_block()

    def block(self, _block_number):
        self.block_reads += 1
        if self.block_reads > 1 and self.block_after is not None:
            return self.block_after
        return self._current_block()

    def bytecode(self, _address, _block_number):
        return self.code

    def registry_paused(self, _address, _block_number):
        return self.paused

    def challenge_exists(self, _address, _challenge_id, _block_number):
        return self.exists

    def challenge(self, _address, _challenge_id, _block_number):
        return self.challenge_state

    def version(self, _address, _challenge_id, _version, _block_number):
        return self.version_state

    def close(self):
        self.closed = True


def _registry_claim_request(harness, **overrides):
    values = {
        "submission_id": "sub_" + "ab" * 12,
        "encrypted_reference": "sealed://arena/candidate-ab",
        "challenge_id": harness.challenge.challenge_id,
        "challenge_version": harness.challenge.version,
        "challenge_manifest_hash": harness.challenge.manifest_hash,
        "submission_manifest_hash": "sha256:" + "cd" * 32,
        "candidate_commitment": "sha256:" + "de" * 32,
        "ingress_binding_sha256": "sha256:" + "ef" * 32,
        "ingress_registry_authorization_sha256": "sha256:" + "f1" * 32,
    }
    values.update(overrides)
    return ArenaRegistryClaimRequest(**values)


class FakeReadOnlyExecutionPolicyAnchorGateway:
    read_only = True
    contract_address = POLICY_ANCHOR
    writer_address = POLICY_ANCHOR_WRITER
    writer_release_commitment = "0x" + POLICY_MANIFEST_COMMITMENT

    def __init__(self):
        self.closed = False
        self.finalized_reads = 0
        self.latest_reads = 0
        self.snapshot = object()

    def finalized_snapshot(self, *_, **__):
        self.finalized_reads += 1
        return self.snapshot

    def latest_snapshot(self, *_, **__):
        self.latest_reads += 1
        return self.snapshot

    def close(self):
        self.closed = True


class ArenaWorkerCliHarness:
    def __init__(self, root: str):
        self.root = Path(root)
        self.challenge = default_challenge_catalog().get(
            BIO_SAFE_IR_CHALLENGE_ID,
            BIO_SAFE_IR_CHALLENGE_VERSION,
        )
        self.recipient = ArenaIngressRecipient.from_keypair(
            TEEKeyPair.from_private_key_hex("12" * 32),
            custody_mode="dstack",
        )
        self.qvl = Account.create("arena-cli-qvl")
        self.approver = Account.create("arena-cli-policy-approver")
        self.approver_hashes = (
            execution_policy_approver_hash(self.approver.address),
        )
        self.approver_root_hash = execution_policy_approver_root_hash(
            self.approver_hashes
        )
        self.approval_domain = ":".join(
            (
                "base-sepolia",
                str(BASE_SEPOLIA_CHAIN_ID),
                POLICY_MANIFEST_COMMITMENT,
                "0x" + COMPOSE,
                hashlib.sha256(APP_ID.encode("ascii")).hexdigest(),
                self.approver_root_hash,
            )
        )
        self.evaluator_payload = {
            "schema": EVALUATOR_SCHEMA,
            "challenge_id": BIO_SAFE_IR_CHALLENGE_ID,
            "challenge_version": BIO_SAFE_IR_CHALLENGE_VERSION,
            "challenge_manifest_hash": self.challenge.manifest_hash,
            "runtime": SAFE_IR_RUNTIME,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "synthetic_only": True,
            "positive_controls": [100.0, 101.0, 99.0, 100.5],
            "negative_controls": [10.0, 11.0, 9.0, 10.5],
        }
        self.evaluator_path = self.root / "sealed-evaluator.json"
        _write_0600(self.evaluator_path, self.evaluator_payload)
        self.approval_domain_hash = execution_policy_approval_domain_hash(
            self.approval_domain
        )
        self.rollback_anchor = {
            "schema": "dnai.execution-policy-rollback-anchor.v1",
            "status": "verified_active_frozen_release_writer",
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "contract_address": POLICY_ANCHOR,
            "runtime_code_hash": POLICY_ANCHOR_RUNTIME_CODE_HASH,
            "release_manifest_commitment": POLICY_MANIFEST_COMMITMENT,
            "evidence_sha256": POLICY_ANCHOR_EVIDENCE_SHA256,
            "writer_address": POLICY_ANCHOR_WRITER,
            "writer_release_commitment": "0x" + POLICY_MANIFEST_COMMITMENT,
            "writer_custody": "dstack_derived_execution_policy_anchor_writer",
            "writer_key_path": "tinker/execution_policy_anchor_writer",
            "confirmations": 12,
            "max_block_age_seconds": 3_600,
            "max_future_block_skew_seconds": 30,
            "verification_model": (
                "single_rpc_reported_finalized_with_confirmation_depth"
            ),
            "independent_rpc_quorum_verified": False,
            "consensus_proof_verified": False,
        }
        self.binding = {
            "catalog_challenge_id": BIO_SAFE_IR_CHALLENGE_ID,
            "catalog_challenge_version": BIO_SAFE_IR_CHALLENGE_VERSION,
            "catalog_manifest_hash": self.challenge.manifest_hash,
            "runtime": SAFE_IR_RUNTIME,
            "runtime_policy_commitment": SAFE_IR_POLICY_COMMITMENT,
            "registry_challenge_id": "7",
            "registry_version": 1,
            "metadata_uri": "ipfs://synthetic-safe-ir-test",
            "metadata_hash": "0x" + self.challenge.manifest_hash,
            "sealed_artifact_commitment": sealed_evaluator_commitment(
                self.evaluator_payload
            ),
            "evaluator_commitment": "0x"
            + SAFE_IR_POLICY_COMMITMENT.removeprefix("sha256:"),
        }
        self.approved_bindings = {
            f"{BIO_SAFE_IR_CHALLENGE_ID}@{BIO_SAFE_IR_CHALLENGE_VERSION}": {
                "registry_challenge_id": self.binding["registry_challenge_id"],
                "registry_version": self.binding["registry_version"],
                "controller_address": "0x" + "77" * 20,
                "pending_controller_address": "0x" + "00" * 20,
                "lifecycle": "open",
                "paused": False,
                "configuration_frozen": True,
                "catalog_manifest_hash": self.binding["catalog_manifest_hash"],
                "metadata_uri": self.binding["metadata_uri"],
                "metadata_hash": self.binding["metadata_hash"],
                "sealed_artifact_commitment": self.binding[
                    "sealed_artifact_commitment"
                ],
                "evaluator_commitment": self.binding["evaluator_commitment"],
            }
        }
        self.approved_set_sha256 = release_approved_challenge_set_sha256(
            self.approved_bindings
        )
        self.tee_release = {
            "compose_hash": COMPOSE,
            "app_id": APP_ID,
            "os_image_hash": OS_IMAGE,
            "tee_signer_address": TEE,
        }
        self.trusted = [self.qvl.address.lower()]
        release_policy_commitment = compute_arena_release_policy_commitment(
            chain_id=BASE_SEPOLIA_CHAIN_ID,
            challenge_registry_address=REGISTRY,
            challenge_registry_runtime_code_hash="0x" + keccak(CODE).hex(),
            approved_challenge_set_sha256=self.approved_set_sha256,
            binding=self.binding,
            tee_release=self.tee_release,
            trusted_qvl_verifier_addresses=self.trusted,
            max_qvl_verdict_age_seconds=300,
            execution_policy_canonicalization_version=(
                "policy-kernel-canonicalization/v2"
            ),
            execution_policy_approval_schema=(
                "dnai-wikigen/execution-policy-approval/v3"
            ),
            execution_policy_api_schema_version=3,
            execution_policy_store_schema_version=5,
            execution_policy_approval_domain=self.approval_domain,
            execution_policy_approval_domain_hash=self.approval_domain_hash,
            execution_policy_approver_hashes=self.approver_hashes,
            execution_policy_approver_root_hash=self.approver_root_hash,
            execution_policy_rollback_anchor=self.rollback_anchor,
        )
        self.release_payload = {
            "schema": RELEASE_SCHEMA,
            "chain_id": BASE_SEPOLIA_CHAIN_ID,
            "challenge_registry_address": REGISTRY,
            "challenge_registry_runtime_code_hash": "0x" + keccak(CODE).hex(),
            "approved_challenge_bindings": self.approved_bindings,
            "approved_challenge_set_sha256": self.approved_set_sha256,
            "challenge_binding": {
                **self.binding,
                "release_policy_commitment": release_policy_commitment,
            },
            "tee_release": self.tee_release,
            "trusted_qvl_verifier_addresses": self.trusted,
            "max_qvl_verdict_age_seconds": 300,
            "execution_policy_canonicalization_version": (
                "policy-kernel-canonicalization/v2"
            ),
            "execution_policy_approval_schema": (
                "dnai-wikigen/execution-policy-approval/v3"
            ),
            "execution_policy_api_schema_version": 3,
            "execution_policy_store_schema_version": 5,
            "execution_policy_approval_domain": self.approval_domain,
            "execution_policy_approval_domain_hash": self.approval_domain_hash,
            "execution_policy_approver_hashes": list(self.approver_hashes),
            "execution_policy_approver_root_hash": self.approver_root_hash,
            "execution_policy_rollback_anchor": self.rollback_anchor,
        }
        self.release_path = self.root / "arena-release.json"
        release_raw = _write_0600(self.release_path, self.release_payload)
        self.verdict_path = self.root / "arena-qvl-verdict.json"
        _write_0600(
            self.verdict_path,
            _signed_verdict(self.recipient, self.qvl).to_public_dict(),
        )
        self.settings = Settings(
            arena_store_path=str(self.root / "arena-store.json"),
            arena_candidate_ingress_store_path=str(self.root / "arena-ingress"),
            execution_policy_store_path=str(self.root / "execution-policy.json"),
            chain_rpc_url="https://rpc.example.test/base-sepolia",
            execution_policy_anchor_rpc_url=(
                "https://rpc.example.test/base-sepolia"
            ),
            execution_policy_anchor_address=POLICY_ANCHOR,
            execution_policy_anchor_runtime_code_hash=(
                POLICY_ANCHOR_RUNTIME_CODE_HASH
            ),
            execution_policy_anchor_writer_address=POLICY_ANCHOR_WRITER,
            execution_policy_anchor_writer_release_commitment=(
                "0x" + POLICY_MANIFEST_COMMITMENT
            ),
            execution_policy_anchor_writer_key_path=(
                "tinker/execution_policy_anchor_writer"
            ),
            execution_policy_anchor_confirmations=12,
            execution_policy_anchor_max_block_age_seconds=3_600,
            execution_policy_anchor_max_future_block_skew_seconds=30,
            arena_worker_release_manifest_path=str(self.release_path),
            arena_worker_release_manifest_sha256=(
                "sha256:" + hashlib.sha256(release_raw).hexdigest()
            ),
            arena_worker_evaluator_path=str(self.evaluator_path),
            arena_worker_qvl_verdict_path="",
            arena_worker_qvl_verdict_url="https://qvl.example.test/verify",
            arena_worker_qvl_release_policy_hash=QVL_POLICY,
            main_runtime_cvm_id=CVM_ID,
            release_deployment_intent_sha256=DEPLOYMENT_INTENT_SHA256,
            release_authority_sha256=RELEASE_AUTHORITY_SHA256,
            release_ceremony_nonce=CEREMONY_NONCE,
            arena_qvl_measurement_policy_sha256=MEASUREMENT_POLICY_SHA256,
            arena_worker_poll_interval_seconds=0.05,
            execution_policy_approval_domain=self.approval_domain,
            execution_policy_approved_signers=self.approver.address,
            execution_policy_approver_root_hash=self.approver_root_hash,
        )
        self.release = load_release_manifest(self.settings)
        self.reader = FakeRegistryReader(self.release)

    def rewrite_release(self):
        raw = _write_0600(self.release_path, self.release_payload)
        self.settings = self.settings.model_copy(
            update={
                "arena_worker_release_manifest_sha256": (
                    "sha256:" + hashlib.sha256(raw).hexdigest()
                )
            }
        )


class ArenaWorkerCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.harness = ArenaWorkerCliHarness(self.temp.name)

    def test_console_surface_has_no_unsafe_activation_or_runtime_selector(self):
        parser = build_parser()
        self.assertEqual(
            {action.dest for action in parser._actions},
            {"help", "once"},
        )
        with self.assertRaises(SystemExit):
            parser.parse_args(["--verified", "--runtime", "python3.11"])
        project = tomllib.loads(
            (Path(__file__).parents[1] / "pyproject.toml").read_text()
        )
        self.assertEqual(
            project["project"]["scripts"]["tinker-arena-worker"],
            "tinker_delegate.arena_worker_cli:main",
        )

    def test_release_manifest_requires_exact_hash_and_0600_regular_file(self):
        changed = self.harness.settings.model_copy(
            update={"arena_worker_release_manifest_sha256": "sha256:" + "aa" * 32}
        )
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "release_manifest_invalid"):
            load_release_manifest(changed)

        self.harness.release_path.chmod(0o640)
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "release_manifest_invalid"):
            load_release_manifest(self.harness.settings)

    def test_release_manifest_pins_execution_policy_versions_roots_and_anchor(self):
        baseline = json.loads(json.dumps(self.harness.release_payload))
        def drift_domain(payload):
            payload["execution_policy_approval_domain"] = payload[
                "execution_policy_approval_domain"
            ].replace("0x" + COMPOSE, "0x" + "44" * 32)
            payload["execution_policy_approval_domain_hash"] = (
                execution_policy_approval_domain_hash(
                    payload["execution_policy_approval_domain"]
                )
            )

        mutations = (
            lambda payload: payload.__setitem__(
                "approved_challenge_set_sha256", "sha256:" + "0" * 64
            ),
            lambda payload: payload["approved_challenge_bindings"][
                f"{BIO_SAFE_IR_CHALLENGE_ID}@{BIO_SAFE_IR_CHALLENGE_VERSION}"
            ].__setitem__("registry_version", 2),
            lambda payload: payload.__setitem__(
                "execution_policy_canonicalization_version",
                "policy-kernel-canonicalization/v1",
            ),
            lambda payload: payload.__setitem__(
                "execution_policy_approval_schema",
                "dnai-wikigen/execution-policy-approval/v1",
            ),
            lambda payload: payload.__setitem__(
                "execution_policy_api_schema_version", 1
            ),
            lambda payload: payload.__setitem__(
                "execution_policy_store_schema_version", 2
            ),
            lambda payload: payload.__setitem__(
                "execution_policy_approval_domain_hash", "11" * 32
            ),
            drift_domain,
            lambda payload: payload.__setitem__(
                "execution_policy_approver_hashes",
                payload["execution_policy_approver_hashes"] * 2,
            ),
            lambda payload: payload.__setitem__(
                "execution_policy_approver_root_hash", "22" * 32
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "status", "unavailable"
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "status", "verified"
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "evidence_sha256", "sha256:" + "0" * 64
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "writer_release_commitment", "0x" + "ff" * 32
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "writer_custody", "operator_key"
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "writer_key_path", "tinker/shared"
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "confirmations", 1
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "max_block_age_seconds", 3_601
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "max_future_block_skew_seconds", 301
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "verification_model", "consensus_finalized"
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "independent_rpc_quorum_verified", True
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "consensus_proof_verified", True
            ),
            lambda payload: payload["execution_policy_rollback_anchor"].__setitem__(
                "operator_note", "self asserted"
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=repr(mutate)):
                self.harness.release_payload = json.loads(json.dumps(baseline))
                mutate(self.harness.release_payload)
                self.harness.rewrite_release()
                with self.assertRaisesRegex(
                    ArenaWorkerBootstrapError,
                    "release_manifest_invalid",
                ):
                    load_release_manifest(self.harness.settings)
        self.harness.release_payload = baseline
        self.harness.rewrite_release()
        loaded = load_release_manifest(self.harness.settings)
        self.assertEqual(
            loaded.execution_policy_approver_root_hash,
            self.harness.approver_root_hash,
        )
        self.assertEqual(
            loaded.execution_policy_rollback_anchor.status,
            "verified_active_frozen_release_writer",
        )
        self.assertEqual(
            loaded.approved_challenge_set_sha256,
            self.harness.approved_set_sha256,
        )
        self.assertEqual(
            loaded.execution_policy_rollback_anchor.writer_address,
            POLICY_ANCHOR_WRITER,
        )
        self.assertEqual(
            loaded.execution_policy_rollback_anchor.writer_release_commitment,
            "0x" + POLICY_MANIFEST_COMMITMENT,
        )
        self.assertEqual(
            loaded.execution_policy_rollback_anchor.confirmations,
            12,
        )
        self.assertEqual(
            loaded.execution_policy_rollback_anchor.verification_model,
            "single_rpc_reported_finalized_with_confirmation_depth",
        )
        self.assertFalse(
            loaded.execution_policy_rollback_anchor.independent_rpc_quorum_verified
        )
        self.assertFalse(
            loaded.execution_policy_rollback_anchor.consensus_proof_verified
        )

        target = Path(self.temp.name) / "release-target.json"
        self.harness.release_path.rename(target)
        self.harness.release_path.symlink_to(target)
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "release_manifest_invalid"):
            load_release_manifest(self.harness.settings)

    def test_settings_load_exact_worker_environment_names(self):
        values = {
            "TINKER_ARENA_WORKER_RELEASE_MANIFEST_PATH": "/sealed/release.json",
            "TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256": "sha256:" + "11" * 32,
            "TINKER_ARENA_WORKER_EVALUATOR_PATH": "/sealed/evaluator.json",
            "TINKER_ARENA_WORKER_QVL_VERDICT_PATH": "/sealed/verdict.json",
            "TINKER_ARENA_WORKER_QVL_VERDICT_URL": "",
            "TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH": QVL_POLICY,
            "TINKER_ARENA_WORKER_POLL_INTERVAL_SECONDS": "2.5",
            "TINKER_EXECUTION_POLICY_ANCHOR_RPC_URL": "https://rpc.example.test/base-sepolia",
            "TINKER_EXECUTION_POLICY_ANCHOR_ADDRESS": POLICY_ANCHOR,
            "TINKER_EXECUTION_POLICY_ANCHOR_RUNTIME_CODE_HASH": (
                POLICY_ANCHOR_RUNTIME_CODE_HASH
            ),
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_ADDRESS": (
                POLICY_ANCHOR_WRITER
            ),
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT": (
                "0x" + POLICY_MANIFEST_COMMITMENT
            ),
            "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH": (
                "tinker/execution_policy_anchor_writer"
            ),
            "TINKER_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS": "12",
            "TINKER_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS": "3600",
            "TINKER_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS": "30",
        }
        with patch.dict(os.environ, values):
            settings = Settings()
        self.assertEqual(
            settings.arena_worker_release_manifest_path,
            "/sealed/release.json",
        )
        self.assertEqual(
            settings.arena_worker_release_manifest_sha256,
            "sha256:" + "11" * 32,
        )
        self.assertEqual(settings.arena_worker_evaluator_path, "/sealed/evaluator.json")
        self.assertEqual(settings.arena_worker_qvl_verdict_path, "/sealed/verdict.json")
        self.assertEqual(settings.arena_worker_qvl_release_policy_hash, QVL_POLICY)
        self.assertEqual(settings.arena_worker_poll_interval_seconds, 2.5)
        self.assertEqual(settings.execution_policy_anchor_address, POLICY_ANCHOR)
        self.assertEqual(
            settings.execution_policy_anchor_writer_address,
            POLICY_ANCHOR_WRITER,
        )
        self.assertEqual(settings.execution_policy_anchor_confirmations, 12)
        self.assertEqual(
            settings.execution_policy_anchor_max_block_age_seconds,
            3_600,
        )

    def test_qvl_file_requires_0600_and_exactly_one_source(self):
        both = self.harness.settings.model_copy(
            update={"arena_worker_qvl_verdict_path": str(self.harness.verdict_path)}
        )
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "configuration_missing"):
            load_independent_qvl_verdict(both)

        offline = both.model_copy(update={"arena_worker_qvl_verdict_url": ""})
        self.assertTrue(load_independent_qvl_verdict(offline).verified)
        self.harness.verdict_path.chmod(0o644)
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "independent_qvl_unavailable"):
            load_independent_qvl_verdict(offline)

    def test_sealed_evaluator_is_pinned_to_safe_ir_and_registry_commitment(self):
        evaluator = load_sealed_evaluator(
            self.harness.settings,
            pins=self.harness.release,
        )
        self.assertEqual(len(evaluator.positive_controls), 4)
        self.assertNotIn("100.0", repr(evaluator))

        changed = dict(self.harness.evaluator_payload)
        changed["runtime"] = "python3.11"
        _write_0600(self.harness.evaluator_path, changed)
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "sealed_evaluator_invalid"):
            load_sealed_evaluator(
                self.harness.settings,
                pins=self.harness.release,
            )

    def test_https_qvl_post_uses_exact_protocol_auth_and_body_cap(self):
        challenge = _signed_challenge(self.harness.qvl)
        verdict = _signed_verdict(
            self.harness.recipient,
            self.harness.qvl,
            challenge=challenge,
        ).to_public_dict()
        seen = []

        def handler(request):
            seen.append(
                (request.headers.get("authorization"), json.loads(request.content))
            )
            body = challenge.to_public_dict() if request.url.path == "/challenge" else verdict
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                content=_canonical(body),
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(client.close)
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "qvl_unavailable"):
            HttpsArenaQvlClient(
                "https://qvl.example.test/verify",
                auth_token="",
                client=client,
            )
        qvl_client = HttpsArenaQvlClient(
            "https://qvl.example.test/verify",
            auth_token=QVL_TOKEN,
            client=client,
            trusted_verifier_addresses=(self.harness.qvl.address,),
            expected_policy_hash=QVL_POLICY,
            **ARENA_QVL_CLIENT_LINEAGE,
        )
        with patch("tinker_delegate.qvl_freshness.time.time", return_value=NOW):
            issued = qvl_client.issue_challenge()
        loaded = qvl_client.verify(
            _attestation_packet(self.harness.recipient), issued
        )
        self.assertEqual(loaded.verifier_address.lower(), self.harness.qvl.address.lower())
        self.assertEqual(seen[0][0], f"Bearer {QVL_TOKEN}")
        self.assertEqual(
            seen[0][1],
            {
                "schema": "dnai.attestation-qvl-challenge-request.v2",
                "chain_id": BASE_SEPOLIA_CHAIN_ID,
                "domain": "main_runtime_cvm",
                "profile": "arena",
                "cvm_id": CVM_ID,
                "deployment_intent_sha256": DEPLOYMENT_INTENT_SHA256,
                "release_authority_sha256": RELEASE_AUTHORITY_SHA256,
                "ceremony_nonce": CEREMONY_NONCE,
                "measurement_policy_sha256": MEASUREMENT_POLICY_SHA256,
            },
        )
        request_payload = seen[1][1]
        self.assertEqual(
            set(request_payload),
            {"schema", "challenge", "quote", "expectation"},
        )
        self.assertEqual(
            request_payload["schema"],
            "dnai.independent-tdx-verification-request.v2",
        )
        self.assertEqual(request_payload["challenge"], challenge.to_public_dict())
        self.assertEqual(request_payload["quote"], "0x" + QUOTE_BYTES.hex())
        self.assertEqual(request_payload["expectation"]["quote_hash"], "0x" + QUOTE_HASH)
        self.assertEqual(
            request_payload["expectation"]["report_data"],
            "0x" + self.harness.recipient.report_data.hex(),
        )
        self.assertEqual(
            request_payload["expectation"]["quote_report_data"],
            "0x"
            + self.harness.recipient.report_data.hex()
            + challenge.challenge_digest[2:],
        )
        self.assertFalse(request_payload["expectation"]["raw_secret_egress"])
        self.assertNotIn(QVL_TOKEN, repr(qvl_client))
        self.assertNotIn(QUOTE_BYTES.hex(), repr(qvl_client))
        for invalid_quote in (b"q" * 1_023, b"q" * 16_385):
            with self.subTest(quote_bytes=len(invalid_quote)):
                with self.assertRaisesRegex(
                    ArenaWorkerBootstrapError,
                    "qvl_unavailable",
                ):
                    qvl_client.verify(
                        _attestation_packet(
                            self.harness.recipient,
                            invalid_quote,
                        ),
                        issued,
                    )

        def leaking_transport(request):
            raise RuntimeError(f"{request.content!r} {request.headers!r}")

        transport_client = httpx.Client(
            transport=httpx.MockTransport(leaking_transport)
        )
        self.addCleanup(transport_client.close)
        leak_safe_client = HttpsArenaQvlClient(
            "https://qvl.example.test/verify",
            auth_token=QVL_TOKEN,
            client=transport_client,
            trusted_verifier_addresses=(self.harness.qvl.address,),
            expected_policy_hash=QVL_POLICY,
            **ARENA_QVL_CLIENT_LINEAGE,
        )
        with self.assertRaises(ArenaWorkerBootstrapError) as captured:
            leak_safe_client.verify(_attestation_packet(self.harness.recipient), issued)
        rendered_error = "".join(
            traceback.format_exception(captured.exception)
        )
        self.assertNotIn(QUOTE_BYTES.hex(), rendered_error)
        self.assertNotIn(QVL_TOKEN, rendered_error)

        large_client = httpx.Client(
            transport=httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-type": "application/json"},
                    content=b"{" + b"x" * MAX_SECURE_JSON_BYTES + b"}",
                )
            )
        )
        self.addCleanup(large_client.close)
        bounded_client = HttpsArenaQvlClient(
            "https://qvl.example.test/verify",
            auth_token=QVL_TOKEN,
            client=large_client,
            trusted_verifier_addresses=(self.harness.qvl.address,),
            expected_policy_hash=QVL_POLICY,
            **ARENA_QVL_CLIENT_LINEAGE,
        )
        with self.assertRaisesRegex(ArenaWorkerBootstrapError, "qvl_unavailable"):
            bounded_client.verify(_attestation_packet(self.harness.recipient), issued)

    def test_fresh_registry_authorization_checks_finalized_identity_code_and_state(self):
        request = _registry_claim_request(self.harness)
        authorized = validate_fresh_challenge_registry(
            self.harness.release,
            self.harness.reader,
            now=NOW,
            request=request,
        )
        self.assertEqual(authorized.block_number, self.harness.reader.block_number)
        self.assertEqual(authorized.block_hash, self.harness.reader.block_hash)
        self.assertEqual(authorized.claim_request_sha256, request.sha256)
        self.assertEqual(self.harness.reader.finalized_reads, 2)
        self.assertEqual(self.harness.reader.block_reads, 2)

        differently_bound = validate_fresh_challenge_registry(
            self.harness.release,
            FakeRegistryReader(self.harness.release),
            now=NOW,
            request=_registry_claim_request(
                self.harness,
                ingress_registry_authorization_sha256="sha256:" + "f2" * 32,
            ),
        )
        self.assertNotEqual(
            differently_bound.registry_snapshot_sha256,
            authorized.registry_snapshot_sha256,
        )

        mutations = (
            ("chain", 1),
            ("block_timestamp", NOW - 301),
            ("code", b"\x60\x01"),
            ("paused", True),
            ("exists", False),
            (
                "challenge_state",
                replace(self.harness.reader.challenge_state, configuration_frozen=False),
            ),
            (
                "version_state",
                replace(self.harness.reader.version_state, metadata_uri="ipfs://changed"),
            ),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                reader = FakeRegistryReader(self.harness.release)
                setattr(reader, field, value)
                with self.assertRaisesRegex(
                    ArenaWorkerBootstrapError,
                    "challenge_registry_unavailable",
                ):
                    validate_fresh_challenge_registry(
                        self.harness.release,
                        reader,
                        now=NOW,
                        request=request,
                    )

        for field, value in (
            (
                "block_after",
                ArenaRegistryBlock(
                    number=self.harness.reader.block_number,
                    block_hash="0x" + "13" * 32,
                    timestamp=self.harness.reader.block_timestamp,
                ),
            ),
            (
                "finalized_after",
                ArenaRegistryBlock(
                    number=self.harness.reader.block_number + 1,
                    block_hash="0x" + "14" * 32,
                    timestamp=self.harness.reader.block_timestamp,
                ),
            ),
        ):
            with self.subTest(field=field):
                reader = FakeRegistryReader(self.harness.release)
                setattr(reader, field, value)
                with self.assertRaisesRegex(
                    ArenaWorkerBootstrapError,
                    "challenge_registry_unavailable",
                ):
                    validate_fresh_challenge_registry(
                        self.harness.release,
                        reader,
                        now=NOW,
                        request=request,
                    )

    def test_full_bootstrap_constructs_live_qvl_provider_and_rejects_file_mode(self):
        anchor_gateway = FakeReadOnlyExecutionPolicyAnchorGateway()
        with patch(
            "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
            return_value=False,
        ):
            with self.assertRaisesRegex(ArenaWorkerBootstrapError, "real_dstack_required"):
                build_arena_worker_service_from_settings(
                    self.harness.settings,
                    now=NOW,
                    registry_reader=self.harness.reader,
                )

        with (
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.resolve_arena_recipient",
                return_value=self.harness.recipient,
            ) as resolve,
            patch(
                "tinker_delegate.arena_worker_cli.execution_policy_integrity_key",
                return_value=b"p" * 32,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.HttpsExecutionPolicyAnchorGateway.from_settings",
                return_value=anchor_gateway,
            ),
            patch.dict(
                os.environ,
                {
                    "DSTACK_SIMULATOR_ENDPOINT": "",
                    QVL_AUTH_TOKEN_ENV: QVL_TOKEN,
                },
            ),
        ):
            service = build_arena_worker_service_from_settings(
                self.harness.settings,
                now=NOW,
                registry_reader=self.harness.reader,
            )
        self.assertIsInstance(service, ArenaSafeWorkerService)
        self.assertEqual(anchor_gateway.finalized_reads, 1)
        self.assertEqual(self.harness.reader.finalized_reads, 0)
        self.assertIsInstance(
            service.worker._registry_claim_gate,
            RefreshingArenaRegistryClaimGate,
        )
        authorization = service.worker._registry_claim_gate.authorize_arena_claim(
            _registry_claim_request(self.harness),
            occurred_at=NOW,
        )
        self.assertEqual(
            authorization.registry_address,
            self.harness.release.challenge_registry_address,
        )
        self.assertEqual(self.harness.reader.finalized_reads, 2)
        resolve.assert_called_once_with(
            self.harness.settings,
            root_path=self.harness.settings.arena_candidate_ingress_store_path,
        )
        service.close()
        self.assertTrue(anchor_gateway.closed)

        offline_only = self.harness.settings.model_copy(
            update={
                "arena_worker_qvl_verdict_path": str(self.harness.verdict_path),
                "arena_worker_qvl_verdict_url": "",
            }
        )
        with (
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.resolve_arena_recipient",
                return_value=self.harness.recipient,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.execution_policy_integrity_key",
                return_value=b"p" * 32,
            ),
            patch.dict(
                os.environ,
                {
                    "DSTACK_SIMULATOR_ENDPOINT": "",
                    QVL_AUTH_TOKEN_ENV: QVL_TOKEN,
                },
            ),
        ):
            with self.assertRaisesRegex(
                ArenaWorkerBootstrapError,
                "independent_qvl_unavailable",
            ):
                build_arena_worker_service_from_settings(
                    offline_only,
                    now=NOW,
                    registry_reader=self.harness.reader,
                )

    def test_simulator_and_approval_domain_drift_fail_closed(self):
        with (
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=True,
            ),
            patch.dict(
                os.environ,
                {"DSTACK_SIMULATOR_ENDPOINT": "http://127.0.0.1:8090"},
            ),
        ):
            with self.assertRaisesRegex(ArenaWorkerBootstrapError, "real_dstack_required"):
                build_arena_worker_service_from_settings(
                    self.harness.settings,
                    now=NOW,
                    registry_reader=self.harness.reader,
                )

        changed = self.harness.settings.model_copy(
            update={
                "execution_policy_approval_domain": (
                    "base-sepolia:different-suite:compose-33"
                )
            }
        )
        with (
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch.dict(os.environ, {"DSTACK_SIMULATOR_ENDPOINT": ""}),
        ):
            with self.assertRaisesRegex(
                ArenaWorkerBootstrapError,
                "execution_policy_unavailable",
            ):
                build_arena_worker_service_from_settings(
                    changed,
                    now=NOW,
                    registry_reader=self.harness.reader,
                )

        changed_root = self.harness.settings.model_copy(
            update={"execution_policy_approver_root_hash": "11" * 32}
        )
        with (
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch.dict(os.environ, {"DSTACK_SIMULATOR_ENDPOINT": ""}),
        ):
            with self.assertRaisesRegex(
                ArenaWorkerBootstrapError,
                "execution_policy_unavailable",
            ):
                build_arena_worker_service_from_settings(
                    changed_root,
                    now=NOW,
                    registry_reader=self.harness.reader,
                )

    def test_abi_decoder_rejects_noncanonical_version_data(self):
        uri = self.harness.release.challenge_binding.metadata_uri.encode("ascii")
        padded = uri + b"\0" * ((-len(uri)) % 32)
        binding = self.harness.release.challenge_binding
        encoded = b"".join(
            (
                (32).to_bytes(32, "big"),
                (6 * 32).to_bytes(32, "big"),
                bytes.fromhex(binding.metadata_hash[2:]),
                bytes.fromhex(binding.sealed_artifact_commitment[2:]),
                bytes.fromhex(binding.evaluator_commitment[2:]),
                bytes.fromhex(binding.release_policy_commitment[2:]),
                NOW.to_bytes(32, "big"),
                len(uri).to_bytes(32, "big"),
                padded,
            )
        )
        self.assertEqual(
            _decode_version(encoded).metadata_uri,
            self.harness.release.challenge_binding.metadata_uri,
        )
        with self.assertRaises(ValueError):
            _decode_version(encoded + b"\0" * 32)

    def test_https_registry_reader_rejects_non_https_rpc(self):
        with self.assertRaises(ValueError):
            HttpsArenaRegistryReader("http://127.0.0.1:8545")

    def test_https_registry_reader_preserves_finalized_block_identity(self):
        tags = []

        def handler(request):
            payload = json.loads(request.content)
            self.assertEqual(payload["method"], "eth_getBlockByNumber")
            tag = payload["params"][0]
            tags.append(tag)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": payload["id"],
                    "result": {
                        "number": hex(self.harness.reader.block_number),
                        "hash": self.harness.reader.block_hash,
                        "timestamp": hex(self.harness.reader.block_timestamp),
                    },
                },
            )

        client = httpx.Client(transport=httpx.MockTransport(handler))
        self.addCleanup(client.close)
        reader = HttpsArenaRegistryReader(
            "https://base-sepolia.example.test",
            client=client,
        )
        finalized = reader.finalized_block()
        numbered = reader.block(self.harness.reader.block_number)
        self.assertEqual(finalized, numbered)
        self.assertEqual(finalized.block_hash, self.harness.reader.block_hash)
        self.assertEqual(
            tags,
            ["finalized", hex(self.harness.reader.block_number)],
        )

    def test_bootstrap_failure_output_is_bounded_and_never_contains_detail(self):
        output = io.StringIO()
        write_bounded_bootstrap_failure("secret=/sealed/evaluator", output)
        encoded = output.getvalue()
        self.assertLess(len(encoded), 1_024)
        self.assertNotIn("secret", encoded)
        payload = json.loads(encoded)
        self.assertEqual(payload["reason"], "worker_initialization_failed")
        self.assertFalse(payload["exception_detail_egress"])
        self.assertFalse(payload["sealed_evaluator_egress"])

    def test_main_emits_only_bounded_startup_failure(self):
        output = io.StringIO()
        with (
            patch(
                "tinker_delegate.arena_worker_cli.Settings",
                return_value=self.harness.settings,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.build_arena_worker_service_from_settings",
                side_effect=RuntimeError("token=do-not-log /secret/path"),
            ),
            patch("sys.stdout", output),
        ):
            result = main(["--once"])
        self.assertEqual(result, EXIT_ACTIVATION_UNAVAILABLE)
        self.assertNotIn("do-not-log", output.getvalue())
        self.assertEqual(
            json.loads(output.getvalue())["reason"],
            "worker_initialization_failed",
        )

    def test_console_once_bootstraps_without_qvl_request_when_queue_is_idle(self):
        output = io.StringIO()
        anchor_gateway = FakeReadOnlyExecutionPolicyAnchorGateway()
        with (
            patch(
                "tinker_delegate.arena_worker_cli.Settings",
                return_value=self.harness.settings,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_enabled",
                return_value=True,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.dstack_utils.is_dstack_simulator",
                return_value=False,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.resolve_arena_recipient",
                return_value=self.harness.recipient,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.execution_policy_integrity_key",
                return_value=b"p" * 32,
            ),
            patch(
                "tinker_delegate.execution_policy_anchor.HttpsExecutionPolicyAnchorGateway.from_settings",
                return_value=anchor_gateway,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.HttpsArenaRegistryReader",
                return_value=self.harness.reader,
            ),
            patch(
                "tinker_delegate.arena_worker_cli.time.time",
                return_value=NOW,
            ),
            patch(
                "tinker_delegate.arena_worker_service.time.time",
                return_value=NOW,
            ),
            patch.dict(
                os.environ,
                {
                    "DSTACK_SIMULATOR_ENDPOINT": "",
                    QVL_AUTH_TOKEN_ENV: QVL_TOKEN,
                },
            ),
            patch("sys.stdout", output),
        ):
            result = main(["--once"])
        self.assertEqual(result, 0)
        status = json.loads(output.getvalue())
        self.assertEqual(status["state"], "idle")
        self.assertEqual(status["runtime"], SAFE_IR_RUNTIME)
        self.assertFalse(status["raw_candidate_egress"])
        self.assertTrue(self.harness.reader.closed)
        self.assertEqual(anchor_gateway.finalized_reads, 1)
        self.assertEqual(self.harness.reader.finalized_reads, 0)
        self.assertTrue(anchor_gateway.closed)


if __name__ == "__main__":
    unittest.main()
