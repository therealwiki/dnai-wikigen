import base64
import copy
import hashlib
import io
import json
import unittest

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_hash.auto import keccak

from tinker_delegate.arena_ingress import (
    INGRESS_HKDF_INFO,
    ArenaCandidateEnvelope,
    ArenaIngressRecipient,
    arena_candidate_aad,
    arena_candidate_browser_contract,
    build_arena_candidate_binding,
)
from tinker_delegate.arena_safe_ir import (
    SAFE_IR_POLICY_COMMITMENT,
    encode_safe_ir_program,
)
from tinker_delegate.arena_store import (
    DNASEQ_SAFE_IR_CHALLENGE_ID,
    DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    SubmissionIdentity,
    SubmissionManifest,
    default_challenge_catalog,
)
from tinker_delegate.arena_submission_client import (
    SUBMISSION_CLIENT_CLASSIFICATION,
    TOKEN_ENV,
    ArenaAgentTokenClaims,
    ArenaSubmissionClient,
    ArenaSubmissionClientError,
    HttpsArenaSubmissionTransport,
    TrustedArenaRelease,
    _parse_submission_receipt,
    _submission_identity,
    main,
    read_arena_agent_token,
)
from tinker_delegate.arena_worker_cli import (
    BASE_SEPOLIA_CHAIN_ID,
    ArenaChallengeReleaseBinding,
    ArenaExecutionPolicyRollbackAnchorPins,
    ArenaRegistryBlock,
    ArenaRegistryChallengeState,
    ArenaRegistryVersionState,
    ArenaTeeReleasePins,
    ArenaWorkerReleasePins,
)
from tinker_delegate.arena_worker_evidence import (
    EVIDENCE_CLASSIFICATION,
    arena_worker_heartbeat_binding_sha256,
    arena_worker_release_binding_sha256,
)
from tinker_delegate.crypto import TEEKeyPair
from tinker_delegate.api import ArenaSubmissionCreateRequest


NOW = 1_800_000_000
OWNER = "0x" + "11" * 20
CONTROLLER = "0x" + "22" * 20
REGISTRY = "0x" + "33" * 20
ZERO_ADDRESS = "0x" + "0" * 40
CODE = bytes.fromhex("6000600055")
BLOCK = ArenaRegistryBlock(
    number=12_345,
    block_hash="0x" + "44" * 32,
    timestamp=NOW - 3,
)
QUOTE = bytes.fromhex("55" * 1_024)
RECIPIENT_PRIVATE = bytes.fromhex("66" * 32)
EPHEMERAL_PRIVATE = bytes(range(1, 33))
NONCE = bytes(range(12))
RELEASE_SHA = "77" * 20
IMAGE_DIGEST = "sha256:" + "88" * 32
RELEASE_MANIFEST_SHA256 = "sha256:" + "99" * 32
QUOTE_SHA256 = "sha256:" + hashlib.sha256(QUOTE).hexdigest()


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def token_payload(**overrides):
    value = {
        "iss": "dnai-wikigen:arena-agent-credential",
        "aud": "dnai-wikigen:arena-agent",
        "sub": "acred_" + "a" * 24,
        "device_id": "adev_" + "b" * 24,
        "owner_address": OWNER,
        "challenge_id": DNASEQ_SAFE_IR_CHALLENGE_ID,
        "challenge_version": DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        "generation": 1,
        "scope": "challenge:submissions:read challenge:submit",
        "daily_submission_cap": 8,
        "iat": NOW - 10,
        "nbf": NOW - 10,
        "exp": NOW + 3_590,
        "jti": "c" * 32,
    }
    value.update(overrides)
    return value


def agent_token(payload=None, header=None, signature=None):
    return ".".join(
        (
            b64(canonical(header or {"alg": "HS256", "kid": "dstack-arena-agent-v1", "typ": "JWT"})),
            b64(canonical(payload or token_payload())),
            b64(signature or bytes.fromhex("dd" * 32)),
        )
    )


def make_release():
    challenge = default_challenge_catalog().get(
        DNASEQ_SAFE_IR_CHALLENGE_ID,
        DNASEQ_SAFE_IR_CHALLENGE_VERSION,
    )
    sealed = "0x" + "aa" * 32
    evaluator = "0x" + SAFE_IR_POLICY_COMMITMENT.removeprefix("sha256:")
    release_policy = "0x" + "bb" * 32
    approved_set = "sha256:" + "cc" * 32
    challenge_binding = ArenaChallengeReleaseBinding(
        catalog_challenge_id=challenge.challenge_id,
        catalog_challenge_version=challenge.version,
        catalog_manifest_hash=challenge.manifest_hash,
        runtime=challenge.runtime,
        runtime_policy_commitment=SAFE_IR_POLICY_COMMITMENT,
        registry_challenge_id=1,
        registry_version=1,
        metadata_uri="ipfs://bafy-arena-v1",
        metadata_hash="0x" + challenge.manifest_hash,
        sealed_artifact_commitment=sealed,
        evaluator_commitment=evaluator,
        release_policy_commitment=release_policy,
        controller_address=CONTROLLER,
        pending_controller_address=ZERO_ADDRESS,
    )
    tee_release = ArenaTeeReleasePins(
        compose_hash="de" * 32,
        app_id="arena-cvm-app-v1",
        os_image_hash="ef" * 32,
        tee_signer_address="0x" + "12" * 20,
    )
    anchor = ArenaExecutionPolicyRollbackAnchorPins(
        schema="dnai.execution-policy-rollback-anchor.v1",
        status="verified_active_frozen_release_writer",
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        contract_address="0x" + "13" * 20,
        runtime_code_hash="0x" + "14" * 32,
        release_manifest_commitment="15" * 32,
        evidence_sha256="sha256:" + "16" * 32,
        writer_address="0x" + "17" * 20,
        writer_release_commitment="0x" + "15" * 32,
        writer_custody="dstack_derived_execution_policy_anchor_writer",
        writer_key_path="tinker/execution_policy_anchor_writer",
        confirmations=2,
        max_block_age_seconds=300,
        max_future_block_skew_seconds=30,
        verification_model="single_rpc_reported_finalized_with_confirmation_depth",
        independent_rpc_quorum_verified=False,
        consensus_proof_verified=False,
    )
    pins = ArenaWorkerReleasePins(
        chain_id=BASE_SEPOLIA_CHAIN_ID,
        challenge_registry_address=REGISTRY,
        challenge_registry_runtime_code_hash="0x" + keccak(CODE).hex(),
        approved_challenge_bindings={
            f"{challenge.challenge_id}@{challenge.version}": {
                "registry_challenge_id": "1",
                "registry_version": 1,
                "controller_address": CONTROLLER,
                "pending_controller_address": ZERO_ADDRESS,
                "lifecycle": "open",
                "paused": False,
                "configuration_frozen": True,
                "catalog_manifest_hash": challenge.manifest_hash,
                "metadata_uri": challenge_binding.metadata_uri,
                "metadata_hash": challenge_binding.metadata_hash,
                "sealed_artifact_commitment": sealed,
                "evaluator_commitment": evaluator,
            }
        },
        approved_challenge_set_sha256=approved_set,
        challenge_binding=challenge_binding,
        tee_release=tee_release,
        trusted_qvl_verifier_addresses=("0x" + "18" * 20,),
        max_qvl_verdict_age_seconds=120,
        execution_policy_canonicalization_version="rfc8785-jcs-v1",
        execution_policy_approval_schema="dnai-wikigen/execution-policy-approval/v3",
        execution_policy_api_schema_version=3,
        execution_policy_store_schema_version=6,
        execution_policy_approval_domain="test",
        execution_policy_approval_domain_hash="19" * 32,
        execution_policy_approver_hashes=("1a" * 32,),
        execution_policy_approver_root_hash="1b" * 32,
        execution_policy_rollback_anchor=anchor,
    )
    return TrustedArenaRelease(
        pins=pins,
        release_manifest_sha256=RELEASE_MANIFEST_SHA256,
        release_sha=RELEASE_SHA,
        image_digest=IMAGE_DIGEST,
        verified_quote_sha256=QUOTE_SHA256,
    )


class FakeRegistryReader:
    def __init__(self, release):
        self.release = release
        self.closed = False
        self.finalized_reads = 0
        self.code = CODE

    def chain_id(self):
        return BASE_SEPOLIA_CHAIN_ID

    def finalized_block(self):
        self.finalized_reads += 1
        return BLOCK

    def block(self, _number):
        return BLOCK

    def bytecode(self, _address, _number):
        return self.code

    def registry_paused(self, _address, _number):
        return False

    def challenge_exists(self, _address, _challenge_id, _number):
        return True

    def challenge(self, _address, _challenge_id, _number):
        binding = self.release.pins.challenge_binding
        return ArenaRegistryChallengeState(
            controller=binding.controller_address,
            pending_controller=binding.pending_controller_address,
            lifecycle=1,
            latest_version=binding.registry_version,
            paused=False,
            configuration_frozen=True,
        )

    def version(self, _address, _challenge_id, _version, _number):
        binding = self.release.pins.challenge_binding
        return ArenaRegistryVersionState(
            metadata_uri=binding.metadata_uri,
            metadata_hash=binding.metadata_hash,
            sealed_artifact_commitment=binding.sealed_artifact_commitment,
            evaluator_commitment=binding.evaluator_commitment,
            release_policy_commitment=binding.release_policy_commitment,
        )

    def close(self):
        self.closed = True


def modeled_execution_provenance(challenge):
    return {
        "status": "not_executed",
        "outcome": None,
        "runtime": challenge.runtime,
        "runtime_policy_commitment": None,
        "challenge_manifest_hash": None,
        "compose_hash": None,
        "app_id": None,
        "os_image_hash": None,
        "quote_sha256": None,
        "verifier_address": None,
        "verdict_digest": None,
        "tee_signer_address": None,
        "chain_id": None,
        "challenge_registry_address": None,
        "evidence_classification": "none",
        "independently_verified_by_client": False,
        "raw_tdx_quote_egress": False,
        "exact_score_egress": False,
        "exact_timing_egress": False,
    }


def public_submission(payload, challenge, submission_id="sub_" + "ab" * 12):
    identity = _submission_identity(OWNER).to_public_dict()
    return {
        "surface": "arena_submission",
        "schema_version": 2,
        "submission_id": submission_id,
        "challenge_id": challenge.challenge_id,
        "challenge_version": challenge.version,
        "identity": identity,
        "candidate_commitment": payload["candidate_commitment"],
        "manifest": {
            key: value
            for key, value in payload["manifest"].items()
            if key != "source_bytes"
        }
        | {"private_size_egress": False},
        "state": "submitted",
        "queue_events": [
            {
                "sequence": 1,
                "from_state": None,
                "to_state": "submitted",
                "reason": "caller_submitted",
            }
        ],
        "ladder_release": None,
        "execution_capability": challenge.execution_capability.to_public_dict(),
        "execution_provenance": modeled_execution_provenance(challenge),
        "product_status": "modeled",
        "execution_assurance": "projection_only_no_hardened_executor",
        "exact_timing_egress": False,
        "encrypted_reference_public": False,
        "raw_candidate_accepted": False,
        "raw_secret_egress": False,
    }


def owner_submission(public):
    return {
        "surface": "arena_owner_submission",
        "schema_version": public["schema_version"],
        "submission_id": public["submission_id"],
        "challenge_id": public["challenge_id"],
        "challenge_version": public["challenge_version"],
        "identity": copy.deepcopy(public["identity"]),
        "candidate_commitment": public["candidate_commitment"],
        "manifest": copy.deepcopy(public["manifest"]),
        "state": public["state"],
        "bounded_result": None,
        "execution_capability": copy.deepcopy(public["execution_capability"]),
        "execution_provenance": copy.deepcopy(public["execution_provenance"]),
        "product_status": public["product_status"],
        "execution_assurance": public["execution_assurance"],
        "raw_candidate_egress": False,
        "encrypted_reference_egress": False,
        "exact_score_egress": False,
        "exact_reward_egress": False,
        "exact_timing_egress": False,
        "internal_error_egress": False,
    }


class FakeTransport:
    def __init__(self, release):
        self.release = release
        self.challenge = default_challenge_catalog().get(
            DNASEQ_SAFE_IR_CHALLENGE_ID,
            DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        )
        keypair = TEEKeyPair.from_private_key_hex(RECIPIENT_PRIVATE.hex())
        self.recipient = ArenaIngressRecipient.from_keypair(
            keypair,
            custody_mode="dstack",
        )
        self.contract = arena_candidate_browser_contract(self.recipient)
        tee = release.pins.tee_release
        self.attestation = {
            "mode": "tdx",
            "quote": QUOTE.hex(),
            "encryption_public_key": self.recipient.public_key.hex(),
            "report_context": "arena",
            "report_data": self.recipient.report_data.hex(),
            "quote_report_data": self.recipient.report_data.hex() + "00" * 32,
            "app_id": tee.app_id,
            "compose_hash": tee.compose_hash,
            "os_image_hash": tee.os_image_hash,
            "verified": False,
        }
        binding = release.expected_worker_binding
        release_binding_sha = arena_worker_release_binding_sha256(binding)
        heartbeat_sha = arena_worker_heartbeat_binding_sha256(
            challenge_id=self.challenge.challenge_id,
            challenge_version=self.challenge.version,
            heartbeat_observed_at=NOW - 1,
            release_binding_sha256=release_binding_sha,
        )
        self.capability = {
            "surface": "arena_worker_capability",
            "schema_version": 2,
            "challenge_id": self.challenge.challenge_id,
            "challenge_version": self.challenge.version,
            "status": "live",
            "backend": "release_bound_safe_ir_worker",
            "isolation": "independent_job_gate_required",
            "live_execution": True,
            "worker_connected": True,
            "safe_ir_execution_ready": True,
            "hostile_general_code_ready": False,
            "python_preview_live": False,
            "freshness": "fresh",
            "evidence_authenticity": "hmac_verified",
            "evidence_classification": EVIDENCE_CLASSIFICATION,
            "gate_reason": "ready",
            "heartbeat_observed_at": NOW - 1,
            "heartbeat_binding_sha256": heartbeat_sha,
            "release_binding_sha256": release_binding_sha,
            "release_binding": binding.to_dict(),
            "warning": "Authenticated presence is not TDX attestation.",
            "product_status": "live",
            "exact_timing_egress": False,
            "internal_error_egress": False,
            "raw_candidate_egress": False,
            "tdx_attestation_egress": False,
        }
        self.posts = []
        self.gets = []
        self.public = None
        self.owner = None
        self.receipt_mutator = None
        self.closed = False

    def get_json(self, path, *, authorized=False):
        self.gets.append((path, authorized))
        if path.endswith("/worker-capability"):
            return copy.deepcopy(self.capability)
        if path == "/attestation?context=arena":
            return copy.deepcopy(self.attestation)
        if path == "/arena/candidate-encryption-contract":
            return copy.deepcopy(self.contract)
        if path.endswith("/versions/1.0.0"):
            return self.challenge.to_public_dict()
        if path.startswith("/arena/submissions/"):
            return copy.deepcopy(self.public)
        if "/submissions/mine?" in path:
            return {
                "surface": "arena_owner_submissions",
                "schema_version": 2,
                "challenge_id": self.challenge.challenge_id,
                "challenge_version": self.challenge.version,
                "owner_identity": _submission_identity(OWNER).to_public_dict()["wallet_address_hash"],
                "page_count": 1,
                "submissions": [copy.deepcopy(self.owner)],
                "has_more": False,
                "next_cursor": None,
                "scope": "authenticated_wallet_challenge_version",
                "product_status": "per_row",
                "execution_assurance": "per_submission_execution_provenance",
                "raw_candidate_egress": False,
                "encrypted_reference_egress": False,
                "exact_score_egress": False,
                "exact_reward_egress": False,
                "exact_timing_egress": False,
                "internal_error_egress": False,
            }
        raise AssertionError(path)

    def post_json(self, path, payload, *, idempotency_key):
        self.posts.append((path, copy.deepcopy(payload), idempotency_key))
        self.public = public_submission(payload, self.challenge)
        self.owner = owner_submission(self.public)
        envelope = payload["envelope"]
        ciphertext = base64.urlsafe_b64decode(
            envelope["ciphertext"] + "=" * ((-len(envelope["ciphertext"])) % 4)
        )
        receipt = {
            "surface": "arena_submission_result",
            "created": True,
            "idempotent_replay": False,
            "registry_ingress_boundary": {
                "surface": "arena_registry_ingress_boundary",
                "schema_version": 1,
                "status": "proxy_independently_verified_at_finalized_block",
                "verification_model": "single_rpc_reported_finalized_pinned_block",
                "browser_preflight_accepted_as_authority": False,
                "proxy_registry_authorized": True,
                "worker_registry_authorized": False,
                "registry_authorization_sha256": "sha256:" + hashlib.sha256(
                    b"dnai-wikigen/arena-registry-authorization-snapshot/v1\0"
                    + canonical(payload["registry_authorization"])
                ).hexdigest(),
                "chain_id": BASE_SEPOLIA_CHAIN_ID,
                "block_number": payload["registry_authorization"]["block_number"],
                "block_hash": payload["registry_authorization"]["block_hash"],
                "registry_address": payload["registry_authorization"]["registry_address"],
                "registry_challenge_id": payload["registry_authorization"]["registry_challenge_id"],
                "registry_version": payload["registry_authorization"]["registry_version"],
                "independent_rpc_quorum_verified": False,
                "consensus_proof_verified": False,
            },
            "candidate_ingress": {
                "surface": "arena_candidate_ingress_receipt",
                "schema_version": 1,
                "blob_sha256": "sha256:" + "ee" * 32,
                "ciphertext_sha256": "sha256:" + hashlib.sha256(ciphertext).hexdigest(),
                "key_id": envelope["key_id"],
                "created": True,
                "idempotent_replay": False,
                "sealed_reference_public": False,
                "plaintext_candidate_accepted": False,
                "product_status": "modeled",
                "execution_assurance": "projection_only_no_hardened_executor",
                "raw_secret_egress": False,
                "private_size_egress": False,
            },
            "submission": copy.deepcopy(self.public),
            "raw_candidate_accepted": False,
            "encrypted_reference_egress": False,
            "raw_secret_egress": False,
        }
        if self.receipt_mutator is not None:
            self.receipt_mutator(receipt)
        return receipt

    def close(self):
        self.closed = True


def make_claims():
    return ArenaAgentTokenClaims(
        owner_address=OWNER,
        credential_id="acred_" + "a" * 24,
        device_id="adev_" + "b" * 24,
        challenge_id=DNASEQ_SAFE_IR_CHALLENGE_ID,
        challenge_version=DNASEQ_SAFE_IR_CHALLENGE_VERSION,
        generation=1,
        daily_submission_cap=8,
        issued_at=NOW - 10,
        not_before=NOW - 10,
        expires_at=NOW + 3_590,
    )


def make_harness():
    release = make_release()
    transport = FakeTransport(release)
    registry = FakeRegistryReader(release)
    client = ArenaSubmissionClient(
        transport=transport,
        registry_reader=registry,
        trusted_release=release,
        token_claims=make_claims(),
        clock=lambda: NOW,
        sleeper=lambda _seconds: None,
    )
    return release, transport, registry, client


class ArenaAgentTokenProjectionTest(unittest.TestCase):
    def test_reads_only_the_named_environment_variable_and_projects_exact_claims(self):
        raw = agent_token()
        token, claims = read_arena_agent_token(
            {TOKEN_ENV: raw, "UNRELATED_TOKEN": "do-not-use"},
            now=NOW,
        )
        self.assertEqual(token, raw)
        self.assertEqual(claims.owner_address, OWNER)
        self.assertEqual(claims.challenge_id, DNASEQ_SAFE_IR_CHALLENGE_ID)
        self.assertNotIn(raw, repr(claims))

    def test_rejects_missing_expired_cross_version_or_extra_claim_tokens(self):
        with self.assertRaisesRegex(ArenaSubmissionClientError, "token_unavailable"):
            read_arena_agent_token({}, now=NOW)
        cases = (
            token_payload(exp=NOW),
            token_payload(challenge_version="2.0.0"),
            token_payload(scope="challenge:submit"),
            token_payload(generation=True),
            token_payload(extra_authority=True),
        )
        for payload in cases:
            with self.subTest(payload=sorted(payload)):
                with self.assertRaisesRegex(ArenaSubmissionClientError, "token_invalid"):
                    read_arena_agent_token({TOKEN_ENV: agent_token(payload)}, now=NOW)

    def test_failure_output_never_echoes_a_present_malformed_token(self):
        secret = "secret-bearer-that-must-not-appear"
        stdout = io.StringIO()
        stderr = io.StringIO()
        code = main(
            [
                "--delegate-url", "https://delegate.example",
                "--rpc-url", "https://rpc.example",
                "--release-manifest", "/missing/release.json",
                "--release-manifest-sha256", RELEASE_MANIFEST_SHA256,
                "--release-sha", RELEASE_SHA,
                "--image-digest", IMAGE_DIGEST,
                "--verified-quote-sha256", QUOTE_SHA256,
                "preflight",
            ],
            stdout=stdout,
            stderr=stderr,
            environment={TOKEN_ENV: secret},
        )
        self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        self.assertNotEqual(code, 0)


class ArenaSubmissionPreflightTest(unittest.TestCase):
    def test_preflight_binds_manifest_registry_recipient_and_worker_release(self):
        _release, transport, registry, client = make_harness()
        result = client.preflight()
        summary = result.public_summary()
        self.assertEqual(summary["classification"], SUBMISSION_CLIENT_CLASSIFICATION)
        self.assertEqual(summary["challenge_id"], DNASEQ_SAFE_IR_CHALLENGE_ID)
        self.assertTrue(summary["quote_digest_pin_matched"])
        self.assertFalse(summary["tdx_verified"])
        self.assertFalse(summary["worker_execution_authorized_by_client"])
        self.assertFalse(summary["independent_rpc_quorum_verified"])
        self.assertGreaterEqual(registry.finalized_reads, 2)
        self.assertTrue(all(not authorized for _, authorized in transport.gets))

    def test_modeled_or_release_drift_capability_fails_closed(self):
        _release, transport, _registry, client = make_harness()
        transport.capability.update(
            {
                "status": "modeled",
                "backend": "source_ready_preview",
                "isolation": "not_connected",
                "live_execution": False,
                "worker_connected": False,
                "safe_ir_execution_ready": False,
                "freshness": "unavailable",
                "evidence_authenticity": "unverified",
                "gate_reason": "live_release_not_enabled",
                "heartbeat_observed_at": None,
                "heartbeat_binding_sha256": None,
                "release_binding_sha256": None,
                "release_binding": None,
                "product_status": "modeled",
            }
        )
        with self.assertRaisesRegex(ArenaSubmissionClientError, "release_binding"):
            client.preflight()

        _release, transport, _registry, client = make_harness()
        transport.capability["release_binding"]["release_sha"] = "0" * 40
        with self.assertRaisesRegex(ArenaSubmissionClientError, "release_binding"):
            client.preflight()

    def test_registry_code_and_recipient_quote_drift_fail_closed(self):
        _release, _transport, registry, client = make_harness()
        registry.code = b"different"
        with self.assertRaisesRegex(ArenaSubmissionClientError, "registry_preflight"):
            client.preflight()

        _release, transport, _registry, client = make_harness()
        transport.attestation["quote"] = (QUOTE[:-1] + b"\x00").hex()
        with self.assertRaisesRegex(ArenaSubmissionClientError, "recipient_preflight"):
            client.preflight()

    def test_recipient_contract_report_data_and_api_verified_claim_are_exact(self):
        _release, transport, _registry, client = make_harness()
        transport.contract["recipient"]["report_data"] = "00" * 32
        with self.assertRaisesRegex(ArenaSubmissionClientError, "recipient_preflight"):
            client.preflight()

        _release, transport, _registry, client = make_harness()
        transport.attestation["verified"] = True
        with self.assertRaisesRegex(ArenaSubmissionClientError, "recipient_preflight"):
            client.preflight()


class ArenaCandidateEncryptionKatTest(unittest.TestCase):
    def test_fixed_x25519_hkdf_aes_gcm_vector_matches_existing_ingress(self):
        _release, _transport, _registry, client = make_harness()
        source = encode_safe_ir_program(
            positive_pipeline=[{"op": "sort"}, {"op": "trim", "low": 1, "high": 1}],
            negative_pipeline=[{"op": "mad_filter", "threshold_milli": 3000}],
        )
        preflight = client.preflight()
        prepared = client.prepare_submission(
            source,
            idempotency_key="arena-kat-001",
            preflight=preflight,
            ephemeral_private_key=EPHEMERAL_PRIVATE,
            nonce=NONCE,
        )
        envelope = prepared.payload["envelope"]
        aad = base64.urlsafe_b64decode(envelope["aad"] + "=" * ((-len(envelope["aad"])) % 4))
        ephemeral = base64.urlsafe_b64decode(
            envelope["ephemeral_public_key"]
            + "=" * ((-len(envelope["ephemeral_public_key"])) % 4)
        )
        ciphertext = base64.urlsafe_b64decode(
            envelope["ciphertext"] + "=" * ((-len(envelope["ciphertext"])) % 4)
        )
        recipient_private = X25519PrivateKey.from_private_bytes(RECIPIENT_PRIVATE)
        shared = recipient_private.exchange(
            X25519PrivateKey.from_private_bytes(EPHEMERAL_PRIVATE).public_key()
        )
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(aad).digest(),
            info=INGRESS_HKDF_INFO,
        ).derive(shared)
        self.assertEqual(AESGCM(key).decrypt(NONCE, ciphertext, aad), source)
        self.assertEqual(
            ephemeral,
            X25519PrivateKey.from_private_bytes(EPHEMERAL_PRIVATE).public_key().public_bytes_raw(),
        )
        self.assertEqual(prepared.ciphertext_sha256, "sha256:" + hashlib.sha256(ciphertext).hexdigest())
        # The exact request is accepted by the current FastAPI schema, and the
        # backend's own binding builder reconstructs the same canonical AAD.
        ArenaSubmissionCreateRequest.model_validate(prepared.payload)
        backend_binding = build_arena_candidate_binding(
            challenge=preflight.challenge,
            identity=_submission_identity(OWNER),
            candidate_commitment=prepared.candidate_commitment,
            manifest=SubmissionManifest.from_mapping(prepared.payload["manifest"]),
            recipient=ArenaIngressRecipient.from_keypair(
                TEEKeyPair.from_private_key_hex(RECIPIENT_PRIVATE.hex()),
                custody_mode="dstack",
            ),
            idempotency_key="arena-kat-001",
            registry_authorization_sha256=preflight.registry_authorization_sha256,
        )
        self.assertEqual(arena_candidate_aad(backend_binding), aad)
        ArenaCandidateEnvelope.from_mapping(envelope)
        # Fixed vector pins canonical AAD, HKDF salt, nonce, tag placement, and
        # base64url-no-padding together.  Fill the constants from this reviewed
        # protocol rather than from a second implementation.
        self.assertEqual(
            hashlib.sha256(aad).hexdigest(),
            "52336dda6ea5fef720e3bcc54c7c5b1415efb6033756dbbc7cca844a504da6e3",
        )
        self.assertEqual(
            hashlib.sha256(ciphertext).hexdigest(),
            "de468e5019e6c1ec602dd6b7e8c0ca5b5be1dadf1b567b342baf035da19d5633",
        )
        self.assertNotIn("arena-kat-001", repr(prepared))
        self.assertNotIn(source.decode("ascii"), repr(prepared))

    def test_rejects_noncanonical_safe_ir_and_malformed_idempotency(self):
        _release, _transport, _registry, client = make_harness()
        preflight = client.preflight()
        with self.assertRaisesRegex(ArenaSubmissionClientError, "candidate_invalid"):
            client.prepare_submission(
                b'{"schema":"dnai.dnaseq-variant-qc-safe-ir.v1", "positive_pipeline":[],"negative_pipeline":[]}',
                idempotency_key="ok",
                preflight=preflight,
            )
        with self.assertRaisesRegex(ArenaSubmissionClientError, "candidate_invalid"):
            client.prepare_submission(
                encode_safe_ir_program(positive_pipeline=[], negative_pipeline=[]),
                idempotency_key="contains space",
                preflight=preflight,
            )


class ArenaSubmissionWorkflowTest(unittest.TestCase):
    def test_submit_rechecks_every_gate_posts_explicit_key_and_reads_owner_metadata(self):
        _release, transport, registry, client = make_harness()
        source = bytearray(encode_safe_ir_program(positive_pipeline=[], negative_pipeline=[]))
        status = client.submit(
            source,
            idempotency_key="arena-retry-001",
            poll_attempts=1,
            poll_interval_seconds=0,
        )
        self.assertEqual(status.state, "submitted")
        self.assertFalse(status.terminal)
        self.assertEqual(status.owner_metadata["raw_candidate_egress"], False)
        self.assertEqual(len(transport.posts), 1)
        path, payload, key = transport.posts[0]
        self.assertTrue(path.endswith("/submissions"))
        self.assertEqual(key, "arena-retry-001")
        self.assertNotIn("candidate_source", json.dumps(payload))
        self.assertNotIn(source.decode("ascii"), json.dumps(payload))
        owner_gets = [entry for entry in transport.gets if "/submissions/mine?" in entry[0]]
        self.assertEqual(owner_gets, [(owner_gets[0][0], True)])
        self.assertGreaterEqual(registry.finalized_reads, 4)
        output = canonical(status.public_summary()).decode("ascii")
        self.assertNotIn("ciphertext", output)
        self.assertNotIn("arena-retry-001", output)

    def test_receipt_commitment_or_owner_status_drift_is_rejected(self):
        _release, transport, _registry, client = make_harness()
        transport.receipt_mutator = lambda receipt: receipt["candidate_ingress"].update(
            {"ciphertext_sha256": "sha256:" + "00" * 32}
        )
        with self.assertRaisesRegex(ArenaSubmissionClientError, "submission_receipt"):
            client.submit(
                encode_safe_ir_program(positive_pipeline=[], negative_pipeline=[]),
                idempotency_key="arena-retry-002",
            )

        _release, transport, _registry, client = make_harness()
        source = encode_safe_ir_program(positive_pipeline=[], negative_pipeline=[])
        preflight = client.preflight()
        prepared = client.prepare_submission(
            source,
            idempotency_key="arena-retry-003",
            preflight=preflight,
        )
        receipt = transport.post_json(
            "/arena/challenges/x/versions/y/submissions",
            prepared.payload,
            idempotency_key="arena-retry-003",
        )
        _parse_submission_receipt(receipt, prepared)
        transport.owner["state"] = "failed"
        with self.assertRaisesRegex(ArenaSubmissionClientError, "owner_metadata"):
            client.poll_submission(
                receipt["submission"]["submission_id"],
                expected_commitment=prepared.candidate_commitment,
            )

        _release, transport, _registry, client = make_harness()
        prepared = client.prepare_submission(
            source,
            idempotency_key="arena-retry-004",
            preflight=client.preflight(),
        )
        receipt = transport.post_json(
            "/arena/challenges/x/versions/y/submissions",
            prepared.payload,
            idempotency_key="arena-retry-004",
        )
        transport.owner["identity"] = SubmissionIdentity(
            wallet_address="0x" + "ff" * 20,
            project_id="personal-outsider",
        ).to_public_dict()
        with self.assertRaisesRegex(ArenaSubmissionClientError, "owner_metadata"):
            client.poll_submission(receipt["submission"]["submission_id"])

    def test_worker_reported_status_must_remain_on_the_pinned_release(self):
        release, _transport, _registry, client = make_harness()
        tee = release.pins.tee_release
        evidence = {
            "status": "worker_reported",
            "compose_hash": tee.compose_hash,
            "app_id": tee.app_id,
            "os_image_hash": tee.os_image_hash,
            "tee_signer_address": tee.tee_signer_address,
            "challenge_registry_address": release.pins.challenge_registry_address,
            "verifier_address": release.pins.trusted_qvl_verifier_addresses[0],
        }
        client._validate_worker_reported_release({"execution_provenance": evidence})
        evidence["compose_hash"] = "00" * 32
        with self.assertRaisesRegex(ArenaSubmissionClientError, "status_unavailable"):
            client._validate_worker_reported_release({"execution_provenance": evidence})

    def test_close_closes_both_read_only_transports(self):
        _release, transport, registry, client = make_harness()
        client.close()
        self.assertTrue(transport.closed)
        self.assertTrue(registry.closed)


class BoundedHttpsTransportTest(unittest.TestCase):
    def test_offline_httpx_client_sends_auth_only_when_requested_and_hides_token(self):
        token = agent_token()
        observed = []

        def handler(request):
            observed.append(request)
            return httpx.Response(200, json={"ok": True})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        transport = HttpsArenaSubmissionTransport(
            "https://delegate.example",
            token=token,
            client=client,
        )
        self.assertEqual(transport.get_json("/public"), {"ok": True})
        self.assertEqual(transport.get_json("/owner", authorized=True), {"ok": True})
        transport.post_json("/submit", {"safe": True}, idempotency_key="retry-1")
        self.assertNotIn(token, repr(transport))
        self.assertNotIn("authorization", {key.lower() for key in observed[0].headers})
        self.assertEqual(observed[1].headers["authorization"], f"Bearer {token}")
        self.assertEqual(observed[2].headers["idempotency-key"], "retry-1")

    def test_oversized_response_and_redirect_fail_without_body_echo(self):
        secret = "body-secret-that-must-not-escape"

        def oversized(_request):
            return httpx.Response(
                200,
                content=b"{}",
                headers={"Content-Length": str(600 * 1024)},
            )

        transport = HttpsArenaSubmissionTransport(
            "https://delegate.example",
            token=agent_token(),
            client=httpx.Client(transport=httpx.MockTransport(oversized)),
        )
        with self.assertRaises(ArenaSubmissionClientError) as caught:
            transport.get_json("/public")
        self.assertNotIn(secret, str(caught.exception))

        def redirect(_request):
            return httpx.Response(302, content=secret.encode("ascii"), headers={"Location": "https://evil.example"})

        transport = HttpsArenaSubmissionTransport(
            "https://delegate.example",
            token=agent_token(),
            client=httpx.Client(transport=httpx.MockTransport(redirect)),
        )
        with self.assertRaises(ArenaSubmissionClientError) as caught:
            transport.get_json("/public")
        self.assertNotIn(secret, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
