import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  FINAL_RELEASE_AUTHORITY_CORE_DOMAIN,
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES,
  FinalReleaseAuthorityCoreValidationError,
  canonicalFinalReleaseAuthorityCoreArtifactText,
  canonicalFinalReleaseAuthorityCoreBytes,
  diligenceEvaluatorPolicySetRoot,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core.mjs";
import {
  assertReleaseCoreMatchesCeremony,
  executionPolicyWriterReleaseCommitment,
  parseArgs,
  readCanonicalExecutionPolicyReleaseCoreArtifact,
} from "./execution-policy-release-core-cli.mjs";
import {
  LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  finalReleaseAuthorityCoreFromCandidate,
  validateFinalReleaseAuthorityCoreBinding,
} from "../web/scripts/execution-policy-release-core-binding.mjs";
import {
  describeAuthorityReviewSubjectText,
} from "./operator-policy-packet-core.mjs";
import {
  syntheticPreCeremonyRuntimeAuthorityFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";

const KNOWN_VECTOR_ID = "dnai.final-release-authority-core.v2/known-answer-1";
// Domain-separated KAT for the exact v2 canonical value below.
const KNOWN_DIGEST = "d1bab06a461597c4b0d12d9bbf50ea37549c2023b8c37b3e8ef7638b8c874fce";
const RELEASE_SHA = "0123456789abcdef0123456789abcdef01234567";
const APPROVER_ROOT = "013c34f9ab123ac6d7bb6ed0711bddb94806f04c02885cb9c2eeb7af2ac739d7";
const USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function word(pair, prefixed = true) {
  return `${prefixed ? "0x" : ""}${pair.repeat(32)}`;
}

function image(service, repository, digestPair) {
  return {
    service,
    image: `ghcr.io/therealwiki/dnai-wikigen/${repository}@sha256:${digestPair.repeat(32)}`,
    source_digest: RELEASE_SHA,
    source_ref: "refs/heads/main",
    repo: "therealwiki/dnai-wikigen",
    signer_workflow:
      "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    provenance_attestation: "verified",
    sbom_attestation: "verified",
  };
}

function knownVector() {
  return {
    schema: "dnai.final-release-authority-core.v2",
    release_sha: RELEASE_SHA,
    network: {
      chain_id: 84_532,
      public_rpc_url: "https://sepolia.base.org",
    },
    operator_address: address(1),
    deployment_intent_sha256: `sha256:${"b1".repeat(32)}`,
    cvm_launch_intent_sha256: `sha256:${"e2".repeat(32)}`,
    contracts: {
      diligence_room: {
        address: address(2),
        runtime_code_hash: word("01"),
        developer: address(1),
        result_verifier: address(8),
        attestation_verifier: address(9),
        attestation_release_policy_hash: word("11"),
        attestation_binding_frozen: true,
        evaluator_policy_commitments: [word("b4"), word("b5"), word("b6")],
        evaluator_policy_set_root: diligenceEvaluatorPolicySetRoot([
          word("b4"), word("b5"), word("b6"),
        ]),
        release_admission: {
          tee_identity: address(12),
          compose_hash: word("33", false),
          approved_tee_identity_count: 1,
          approved_compose_count: 1,
          additions_frozen: true,
        },
      },
      challenge_registry: {
        address: address(3),
        runtime_code_hash: word("02"),
        owner: address(1),
        pending_owner: address(0),
        registry_paused: false,
        minimum_version_review_delay_seconds: 172_800,
        expected_challenge_count: 1,
      },
      royalty_distributor: {
        address: address(4),
        runtime_code_hash: word("03"),
      },
      tinker_account_encumbrance: {
        address: address(5),
        runtime_code_hash: word("04"),
        owner: address(1),
        account_commitment: word("22"),
        max_add_balance_wei: "1000000000000000000",
        max_spend_wei: "250000000000000000",
        approved_compose_hashes: [word("33")],
        approved_compose_root: word("23"),
        approved_compose_count: 1,
        managers: [address(12)],
        manager_root: word("24"),
        manager_count: 1,
        release_policy_commitment: word("25"),
        release_max_add_balance_wei: "1000000000000000000",
        release_max_spend_wei: "250000000000000000",
        release_compose_root: word("23"),
        release_compose_count: 1,
        release_manager_root: word("24"),
        release_manager_count: 1,
        release_policy_frozen: true,
        emergency_halted: false,
        per_operation_caps: true,
        custodies_funds: false,
      },
      compute_credit_vault: {
        address: address(6),
        runtime_code_hash: word("05"),
        owner: address(1),
        developer: address(10),
        metering_verifier: address(11),
        metering_qvl_verifier: address(20),
        metering_policy_set_hash: word("56"),
        metering_binding_frozen: true,
        developer_fee_bps: 500,
        tee_identity: address(12),
        compose_hash: word("33", false),
        rate_policies: {
          native: {
            commitment: word("44"),
            asset: address(0),
            provider: address(18),
            developer_fee_bps: 500,
          },
          erc20: {
            commitment: word("55"),
            asset: USDC,
            provider: address(19),
            developer_fee_bps: 500,
          },
        },
      },
      email_oracle_auth: {
        address: address(7),
        runtime_code_hash: word("06"),
        owner: address(1),
        consumer_address: address(12),
        upgrade_delay_seconds: 172_800,
        release: {
          oracle_compose_hash: word("33"),
          consumer_compose_hash: word("33"),
          device_id: word("a1"),
          kms_contract_address: address(15),
          kms_runtime_code_hash: word("a2"),
          kms_implementation_address: address(16),
          kms_implementation_runtime_code_hash: word("a3"),
          kms_registration_tx_hash: word("a4"),
          kms_registration_block: 12_345_678,
          kms_registration_block_hash: word("a5"),
          target_boot: {
            instance_id: address(17),
            mr_aggregated: word("a6"),
            mr_system: word("a7"),
            os_image_hash: word("88"),
            tcb_status: "UpToDate",
            advisory_ids: [],
            info_hash: word("a8"),
          },
          restart_key_derivation_proof_hash: word("aa"),
          external_evidence_sha256: word("a9"),
        },
      },
      usdc: {
        address: USDC,
        runtime_code_hash: word("07"),
        symbol: "USDC",
        decimals: 6,
      },
    },
    cvm: {
      app_id: "app_release_core_vector_1_🧬",
      cvm_id: "cvm_release_core_vector_1",
      compose_hash: word("33", false),
      local_compose_hash: word("66", false),
      rendered_compose_sha256: word("77", false),
      os_image_hash: word("88", false),
      os_is_dev: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
      tee_identity: address(12),
      delegate_url: "https://delegate.example.com",
      images: [
        image("oracle", "tee-email-oracle", "c3"),
        image("delegate", "tinker-delegate", "a1"),
        image("neko", "neko-chrome", "b2"),
      ],
      allowed_browser_origins: [
        "https://www.wikigen.me",
        "https://wikigen.me",
        "https://wikigenme.pages.dev",
      ],
      compute_workload_ingress: {
        max_verdict_age_seconds: 300,
        revoked_quote_hashes: [],
      },
      runtime_controls: {
        wallet_auth_required: true,
        runtime_bearer_required: true,
        durable_compute_store: true,
        durable_arena_store: true,
        durable_arena_ingress_store: true,
        artifact_ciphertext_only: true,
        plaintext_artifact_endpoint_disabled: true,
        plaintext_card_endpoint_disabled: true,
        bootstrap_fail_open_disabled: true,
        browser_ports_internal_only: true,
        nondefault_browser_credentials_required: true,
        project_owned_browser_images: true,
        oracle_internal_only: true,
        oracle_runtime_auth_required: true,
        oracle_health_liveness_only: true,
        oracle_pin_response_minimized: true,
        oracle_private_metadata_egress_prohibited: true,
        oracle_replay_fail_closed: true,
        provider_dispatch_enabled: false,
        hostile_candidate_execution_enabled: false,
        deal_settlement_enabled: false,
        remote_artifact_evaluator_enabled: false,
        raw_secret_egress_prohibited: true,
      },
    },
    arena_registry_bindings: {
      "synthetic-bio-assay-qc@1.0.0": {
        registry_challenge_id: "1",
        registry_version: 1,
        controller_address: address(1),
        pending_controller_address: address(0),
        lifecycle: "open",
        paused: false,
        configuration_frozen: true,
        catalog_manifest_hash: word("d1", false),
        metadata_uri: "ipfs://bafy-arena-release-core-vector",
        metadata_hash: word("d1"),
        sealed_artifact_commitment: word("d2"),
        evaluator_commitment: word("d3"),
        release_policy_commitment: word("d4"),
      },
    },
    wallet_auth: {
      domain: "www.wikigen.me",
      uri: "https://www.wikigen.me",
      walletconnect_project_id: "12".repeat(16),
    },
    requested_features: {
      contract_writes: true,
      artifact_upload: true,
      compute_console: true,
      compute_vault_funding: true,
      compute_vault_authorization: true,
      compute_workload_upload: true,
      arena_submission: true,
    },
    execution_policy: {
      canonicalization_version: "policy-kernel-canonicalization/v2",
      approval_schema: "dnai-wikigen/execution-policy-approval/v3",
      api_schema_version: 3,
      store_schema_version: 5,
      approver_hashes: [word("91", false), word("a2", false)],
      approver_root_hash: APPROVER_ROOT,
      rollback_anchor_target: {
        schema: "dnai.execution-policy-rollback-anchor.v1",
        chain_id: 84_532,
        contract_address: address(13),
        runtime_code_hash: word("99"),
        writer_address: address(14),
        writer_release_commitment: word("e2"),
        writer_custody: "dstack_derived_execution_policy_anchor_writer",
        writer_key_path: "tinker/execution_policy_anchor_writer",
        confirmations: 12,
        max_block_age_seconds: 3_600,
        max_future_block_skew_seconds: 30,
        verification_model:
          "single_rpc_reported_finalized_with_confirmation_depth",
        independent_rpc_quorum_verified: false,
        consensus_proof_verified: false,
      },
    },
  };
}

function clone(value) {
  return structuredClone(value);
}

function finalCandidate(coreValue, digest = finalReleaseAuthorityCoreDigest(coreValue)) {
  const core = normalizeFinalReleaseAuthorityCore(coreValue);
  const anchor = core.execution_policy.rollback_anchor_target;
  const contracts = structuredClone(core.contracts);
  delete contracts.diligence_room.release_admission;
  const ratePolicies = contracts.compute_credit_vault.rate_policies;
  delete contracts.compute_credit_vault.rate_policies;
  contracts.compute_credit_vault.native_rate_policy_commitment =
    ratePolicies.native.commitment;
  contracts.compute_credit_vault.native_provider = ratePolicies.native.provider;
  contracts.compute_credit_vault.erc20_asset_address = ratePolicies.erc20.asset;
  contracts.compute_credit_vault.erc20_rate_policy_commitment =
    ratePolicies.erc20.commitment;
  contracts.compute_credit_vault.erc20_provider = ratePolicies.erc20.provider;
  delete contracts.email_oracle_auth.release.oracle_compose_hash;
  delete contracts.email_oracle_auth.release.consumer_compose_hash;
  return {
    release_sha: core.release_sha,
    network: core.network,
    operator_address: core.operator_address,
    deployment_intent_sha256: core.deployment_intent_sha256,
    cvm_launch_intent_sha256: core.cvm_launch_intent_sha256,
    operator_policy: {
      schema: LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
      ceremony_authorization_sha256: `sha256:${"b2".repeat(32)}`,
      live_activation_authority_sha256: `sha256:${"b3".repeat(32)}`,
      runtime_authority_dependency_sha256: `sha256:${digest}`,
    },
    contracts,
    cvm: core.cvm,
    arena_registry_bindings: core.arena_registry_bindings,
    wallet_auth: core.wallet_auth,
    requested_features: core.requested_features,
    execution_policy: {
      canonicalization_version: core.execution_policy.canonicalization_version,
      approval_schema: core.execution_policy.approval_schema,
      api_schema_version: core.execution_policy.api_schema_version,
      store_schema_version: core.execution_policy.store_schema_version,
      approval_domain: "post-anchor-field-deliberately-not-committed",
      approval_domain_hash: word("de", false),
      approver_hashes: core.execution_policy.approver_hashes,
      approver_root_hash: core.execution_policy.approver_root_hash,
      rollback_anchor: {
        ...anchor,
        status: "verified_active_frozen_release_writer",
        release_manifest_commitment: digest,
        evidence_sha256: `sha256:${"ef".repeat(32)}`,
        writer_release_commitment: anchor.writer_release_commitment,
      },
    },
  };
}

test(`${KNOWN_VECTOR_ID} matches the cross-language digest`, () => {
  assert.equal(FINAL_RELEASE_AUTHORITY_CORE_SCHEMA, knownVector().schema);
  assert.equal(
    FINAL_RELEASE_AUTHORITY_CORE_DOMAIN,
    "dnai-wikigen/final-release-authority-core/v2\0",
  );
  const normalized = normalizeFinalReleaseAuthorityCore(knownVector());
  assert.deepEqual(
    normalized.cvm.images.map(({ service }) => service),
    ["delegate", "neko", "oracle"],
  );
  assert.deepEqual(
    normalized.cvm.allowed_browser_origins,
    [
      "https://wikigen.me",
      "https://wikigenme.pages.dev",
      "https://www.wikigen.me",
    ],
  );
  assert.deepEqual(Object.keys(normalized.arena_registry_bindings), [
    "synthetic-bio-assay-qc@1.0.0",
  ]);
  assert.equal(normalized.contracts.challenge_registry.expected_challenge_count, 1);
  const canonical = canonicalFinalReleaseAuthorityCoreBytes(knownVector());
  assert.ok(canonical.length < MAX_FINAL_RELEASE_AUTHORITY_CORE_BYTES);
  assert.equal(canonical.at(-1), "}".charCodeAt(0));
  assert.ok(!canonical.includes("\n"));
  assert.ok(canonical.includes("app_release_core_vector_1_\\ud83e\\uddec"));
  assert.equal(finalReleaseAuthorityCoreDigest(knownVector()), KNOWN_DIGEST);
  const reviewSubject = describeAuthorityReviewSubjectText(
    canonicalFinalReleaseAuthorityCoreArtifactText(knownVector()),
  );
  assert.equal(reviewSubject.ok, true);
  assert.equal(reviewSubject.semanticValidation, "final_release_authority_validated");
  assert.equal(reviewSubject.subjectSha256, `sha256:${KNOWN_DIGEST}`);
});

test("final release candidate is exactly bound to the separate non-cyclic core", () => {
  const core = knownVector();
  const runtimeAuthority = syntheticPreCeremonyRuntimeAuthorityFixture({
    releaseSha: core.release_sha,
    deploymentIntentSha256: core.deployment_intent_sha256,
    cvmLaunchIntentSha256: core.cvm_launch_intent_sha256,
  });
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(
    runtimeAuthority,
  );
  const candidate = finalCandidate(
    core,
    runtimeAuthoritySha256.slice("sha256:".length),
  );
  assert.deepEqual(finalReleaseAuthorityCoreFromCandidate(candidate), normalizeFinalReleaseAuthorityCore(core));
  const binding = validateFinalReleaseAuthorityCoreBinding(
    candidate,
    core,
    runtimeAuthority,
  );
  assert.equal(binding.digest, KNOWN_DIGEST);
  assert.equal(binding.runtimeAuthoritySha256, runtimeAuthoritySha256);
  assert.notEqual(binding.runtimeAuthoritySha256, `sha256:${binding.digest}`);

  const upstreamDrift = structuredClone(candidate);
  upstreamDrift.contracts.royalty_distributor.runtime_code_hash = word("ab");
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      upstreamDrift,
      core,
      runtimeAuthority,
    ),
    /does not exactly match/,
  );

  const launchIntentDrift = structuredClone(candidate);
  launchIntentDrift.cvm_launch_intent_sha256 = `sha256:${"b5".repeat(32)}`;
  launchIntentDrift.execution_policy.rollback_anchor.writer_release_commitment =
    word("b5");
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      launchIntentDrift,
      core,
      runtimeAuthority,
    ),
    /does not exactly match/,
  );

  const renewedReview = structuredClone(candidate);
  renewedReview.operator_policy.live_activation_authority_sha256 =
    `sha256:${"b4".repeat(32)}`;
  renewedReview.operator_policy.ceremony_authorization_sha256 =
    `sha256:${"b5".repeat(32)}`;
  assert.equal(
    validateFinalReleaseAuthorityCoreBinding(
      renewedReview,
      core,
      runtimeAuthority,
    ).digest,
    KNOWN_DIGEST,
  );

  const emailDelayDrift = structuredClone(candidate);
  emailDelayDrift.contracts.email_oracle_auth.upgrade_delay_seconds = 172_801;
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      emailDelayDrift,
      core,
      runtimeAuthority,
    ),
    /does not exactly match/,
  );

  const candidateCommitmentDrift = structuredClone(candidate);
  candidateCommitmentDrift.operator_policy.runtime_authority_dependency_sha256 =
    `sha256:${"ab".repeat(32)}`;
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      candidateCommitmentDrift,
      core,
      runtimeAuthority,
    ),
    /runtime-authority dependency does not equal/,
  );

  const anchorCommitmentDrift = structuredClone(candidate);
  anchorCommitmentDrift.execution_policy.rollback_anchor.release_manifest_commitment =
    "ab".repeat(32);
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      anchorCommitmentDrift,
      core,
      runtimeAuthority,
    ),
    /release-manifest commitment does not equal/,
  );

  const writerCommitmentDrift = structuredClone(candidate);
  writerCommitmentDrift.execution_policy.rollback_anchor.writer_release_commitment =
    `0x${"ab".repeat(32)}`;
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      writerCommitmentDrift,
      core,
      runtimeAuthority,
    ),
    /launch-intent digest/,
  );

  const obsoleteFinalDigestWriter = structuredClone(candidate);
  obsoleteFinalDigestWriter.execution_policy.rollback_anchor.writer_release_commitment =
    `0x${KNOWN_DIGEST}`;
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      obsoleteFinalDigestWriter,
      core,
      runtimeAuthority,
    ),
    /launch-intent digest/,
  );

  const malformedReview = structuredClone(candidate);
  malformedReview.operator_policy.ceremony_authorization_sha256 = "b2".repeat(32);
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      malformedReview,
      core,
      runtimeAuthority,
    ),
    /ceremony-authorization SHA-256/,
  );

  const coreSubstitutedForRuntime = finalCandidate(core, KNOWN_DIGEST);
  assert.throws(
    () => validateFinalReleaseAuthorityCoreBinding(
      coreSubstitutedForRuntime,
      core,
      runtimeAuthority,
    ),
    /runtime-authority dependency does not equal/,
  );
});

test("valid upstream mutations change the final-authority digest", () => {
  const baseline = finalReleaseAuthorityCoreDigest(knownVector());

  const sourceMutation = clone(knownVector());
  sourceMutation.release_sha = "1123456789abcdef0123456789abcdef01234567";
  for (const entry of sourceMutation.cvm.images) {
    entry.source_digest = sourceMutation.release_sha;
  }
  assert.notEqual(finalReleaseAuthorityCoreDigest(sourceMutation), baseline);

  const contractMutation = clone(knownVector());
  contractMutation.contracts.royalty_distributor.runtime_code_hash = word("ab");
  assert.notEqual(finalReleaseAuthorityCoreDigest(contractMutation), baseline);

  const anchorMutation = clone(knownVector());
  anchorMutation.execution_policy.rollback_anchor_target.contract_address = address(21);
  assert.notEqual(finalReleaseAuthorityCoreDigest(anchorMutation), baseline);

  const meteringPolicyMutation = clone(knownVector());
  meteringPolicyMutation.contracts.compute_credit_vault.metering_policy_set_hash = word("57");
  assert.notEqual(finalReleaseAuthorityCoreDigest(meteringPolicyMutation), baseline);

  const tinkerPolicyMutation = clone(knownVector());
  tinkerPolicyMutation.contracts.tinker_account_encumbrance.max_spend_wei =
    "249999999999999999";
  tinkerPolicyMutation.contracts.tinker_account_encumbrance.release_max_spend_wei =
    "249999999999999999";
  assert.notEqual(finalReleaseAuthorityCoreDigest(tinkerPolicyMutation), baseline);

  const deploymentIntentMutation = clone(knownVector());
  deploymentIntentMutation.deployment_intent_sha256 = `sha256:${"b4".repeat(32)}`;
  assert.notEqual(finalReleaseAuthorityCoreDigest(deploymentIntentMutation), baseline);

  const launchIntentMutation = clone(knownVector());
  launchIntentMutation.cvm_launch_intent_sha256 = `sha256:${"b5".repeat(32)}`;
  launchIntentMutation.execution_policy.rollback_anchor_target.writer_release_commitment =
    word("b5");
  assert.notEqual(finalReleaseAuthorityCoreDigest(launchIntentMutation), baseline);

  const emailDelayMutation = clone(knownVector());
  emailDelayMutation.contracts.email_oracle_auth.upgrade_delay_seconds = 172_801;
  assert.notEqual(finalReleaseAuthorityCoreDigest(emailDelayMutation), baseline);

  const emailRestartProofMutation = clone(knownVector());
  emailRestartProofMutation.contracts.email_oracle_auth.release
    .restart_key_derivation_proof_hash = word("ab");
  assert.notEqual(finalReleaseAuthorityCoreDigest(emailRestartProofMutation), baseline);

  const arenaCatalogMutation = clone(knownVector());
  arenaCatalogMutation.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"]
    .release_policy_commitment = word("d5");
  assert.notEqual(finalReleaseAuthorityCoreDigest(arenaCatalogMutation), baseline);

  const workloadRevocationMutation = clone(knownVector());
  workloadRevocationMutation.cvm.compute_workload_ingress.revoked_quote_hashes = [
    word("f1"),
  ];
  assert.notEqual(
    finalReleaseAuthorityCoreDigest(workloadRevocationMutation),
    baseline,
  );
});

test("compute workload ingress policy is bounded and canonical", () => {
  const mutations = [
    (value) => { value.cvm.compute_workload_ingress.max_verdict_age_seconds = 0; },
    (value) => { value.cvm.compute_workload_ingress.max_verdict_age_seconds = 301; },
    (value) => {
      value.cvm.compute_workload_ingress.revoked_quote_hashes = [
        word("f2"), word("f1"),
      ];
    },
    (value) => {
      value.cvm.compute_workload_ingress.revoked_quote_hashes = [
        word("f1"), word("f1"),
      ];
    },
    (value) => {
      value.cvm.compute_workload_ingress.revoked_quote_hashes = [
        `0x${"0".repeat(64)}`,
      ];
    },
  ];
  for (const mutate of mutations) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("Arena genesis catalog is exact, active, frozen, contiguous, and commitment-bound", () => {
  const mutations = [
    (value) => { value.contracts.challenge_registry.pending_owner = address(2); },
    (value) => { value.contracts.challenge_registry.registry_paused = true; },
    (value) => {
      value.contracts.challenge_registry.minimum_version_review_delay_seconds = 172_799;
    },
    (value) => { value.contracts.challenge_registry.expected_challenge_count = 2; },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].registry_challenge_id = "2";
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].pending_controller_address = address(2);
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].lifecycle = "draft";
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].paused = true;
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].configuration_frozen = false;
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].metadata_hash = word("d5");
    },
    (value) => {
      value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"].evaluator_commitment = word("d2");
    },
    (value) => {
      value.arena_registry_bindings["Synthetic@1.0.0"] =
        value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"];
      delete value.arena_registry_bindings["synthetic-bio-assay-qc@1.0.0"];
    },
  ];
  for (const mutate of mutations) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("unordered release sets normalize to one commitment", () => {
  const permuted = clone(knownVector());
  permuted.cvm.images.reverse();
  permuted.cvm.allowed_browser_origins.reverse();
  assert.equal(
    finalReleaseAuthorityCoreDigest(permuted),
    finalReleaseAuthorityCoreDigest(knownVector()),
  );
});

test("Diligence evaluator-policy root matches Solidity abi.encode Keccak-256", () => {
  assert.equal(
    diligenceEvaluatorPolicySetRoot([word("b6"), word("b4"), word("b5")]),
    "0x24d034ce2bdfb43484ddbb0c37427872c59e047fd9fab10e548f0bc5a9151230",
  );
});

test("extra fields are rejected at every commitment boundary", () => {
  for (const mutate of [
    (value) => { value.release_manifest_commitment = word("fe", false); },
    (value) => { value.operator_policy = { review_evidence_sha256: `sha256:${"b2".repeat(32)}` }; },
    (value) => { value.execution_policy.approval_domain = "forbidden"; },
    (value) => { value.execution_policy.rollback_anchor_target.evidence_sha256 = word("fe"); },
  ]) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => finalReleaseAuthorityCoreDigest(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("deployment intent authority is exact, lowercase, and nonzero", () => {
  for (const mutate of [
    (value) => { delete value.deployment_intent_sha256; },
    (value) => { value.deployment_intent_sha256 = `sha256:${"0".repeat(64)}`; },
    (value) => { value.deployment_intent_sha256 = `sha256:${"AB".repeat(32)}`; },
    (value) => { value.deployment_intent_sha256 = "b2".repeat(32); },
  ]) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("CVM launch intent authority and anchor-writer release are exact and cross-bound", () => {
  for (const mutate of [
    (value) => { delete value.cvm_launch_intent_sha256; },
    (value) => { value.cvm_launch_intent_sha256 = `sha256:${"0".repeat(64)}`; },
    (value) => { value.cvm_launch_intent_sha256 = `sha256:${"AB".repeat(32)}`; },
    (value) => { value.cvm_launch_intent_sha256 = "e2".repeat(32); },
    (value) => {
      value.execution_policy.rollback_anchor_target.writer_release_commitment =
        word("e3");
    },
    (value) => {
      value.execution_policy.rollback_anchor_target.writer_release_commitment =
        value.deployment_intent_sha256.replace("sha256:", "0x");
    },
  ]) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("EmailOracleAuth upgrade delay is bounded and release-bound", () => {
  for (const invalid of [172_799, 31_536_001, 172_800.5, "172800"]) {
    const candidate = clone(knownVector());
    candidate.contracts.email_oracle_auth.upgrade_delay_seconds = invalid;
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("floating-point and non-JSON numeric values are rejected", () => {
  for (const invalid of [500.5, Number.NaN, Number.POSITIVE_INFINITY, -0]) {
    const candidate = clone(knownVector());
    candidate.contracts.compute_credit_vault.developer_fee_bps = invalid;
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("lowercase, approver-set, control-character, and field bounds are strict", () => {
  const uppercase = clone(knownVector());
  uppercase.operator_address = uppercase.operator_address.toUpperCase();
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(uppercase),
    FinalReleaseAuthorityCoreValidationError,
  );

  const unsortedApprovers = clone(knownVector());
  unsortedApprovers.execution_policy.approver_hashes.reverse();
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(unsortedApprovers),
    FinalReleaseAuthorityCoreValidationError,
  );

  const badRoot = clone(knownVector());
  badRoot.execution_policy.approver_root_hash = word("ff", false);
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(badRoot),
    FinalReleaseAuthorityCoreValidationError,
  );

  const control = clone(knownVector());
  control.cvm.app_id = "bad\napp";
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(control),
    FinalReleaseAuthorityCoreValidationError,
  );

  const oversized = clone(knownVector());
  oversized.cvm.app_id = "x".repeat(129);
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(oversized),
    FinalReleaseAuthorityCoreValidationError,
  );

  for (const invalid of ["1".repeat(31), "1".repeat(33), "AB".repeat(16), "zz".repeat(16), null]) {
    const walletConnect = clone(knownVector());
    walletConnect.wallet_auth.walletconnect_project_id = invalid;
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(walletConnect),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
  const noWalletConnectField = clone(knownVector());
  delete noWalletConnectField.wallet_auth.walletconnect_project_id;
  assert.throws(
    () => normalizeFinalReleaseAuthorityCore(noWalletConnectField),
    FinalReleaseAuthorityCoreValidationError,
  );
  const noWalletConnect = clone(knownVector());
  noWalletConnect.wallet_auth.walletconnect_project_id = "";
  assert.equal(
    normalizeFinalReleaseAuthorityCore(noWalletConnect).wallet_auth.walletconnect_project_id,
    "",
  );
});

test("frozen production roots, Deal posture, and control-plane role separation are mandatory", () => {
  for (const mutate of [
    (value) => { value.contracts.diligence_room.attestation_binding_frozen = false; },
    (value) => { value.contracts.diligence_room.release_admission.compose_hash = word("34", false); },
    (value) => { value.contracts.email_oracle_auth.release.oracle_compose_hash = word("34"); },
    (value) => { value.contracts.compute_credit_vault.metering_binding_frozen = false; },
    (value) => { value.contracts.compute_credit_vault.rate_policies.native.provider = value.operator_address; },
    (value) => {
      value.contracts.compute_credit_vault.rate_policies.erc20.provider =
        value.contracts.compute_credit_vault.rate_policies.native.provider;
    },
    (value) => { value.contracts.tinker_account_encumbrance.release_policy_frozen = false; },
    (value) => { value.contracts.tinker_account_encumbrance.emergency_halted = true; },
    (value) => { value.contracts.tinker_account_encumbrance.max_spend_wei = "01"; },
    (value) => { value.contracts.tinker_account_encumbrance.managers[0] = address(20); },
    (value) => { value.cvm.runtime_controls.deal_settlement_enabled = true; },
    (value) => { value.cvm.runtime_controls.remote_artifact_evaluator_enabled = true; },
    (value) => {
      value.execution_policy.rollback_anchor_target.writer_address =
        value.contracts.diligence_room.result_verifier;
    },
    (value) => {
      value.contracts.diligence_room.attestation_verifier =
        value.contracts.compute_credit_vault.metering_verifier;
    },
    (value) => {
      value.contracts.compute_credit_vault.metering_qvl_verifier =
        value.contracts.compute_credit_vault.metering_verifier;
    },
    (value) => {
      value.execution_policy.rollback_anchor_target.writer_address =
        value.contracts.royalty_distributor.address;
    },
  ]) {
    const candidate = clone(knownVector());
    mutate(candidate);
    assert.throws(
      () => normalizeFinalReleaseAuthorityCore(candidate),
      FinalReleaseAuthorityCoreValidationError,
    );
  }
});

test("ensure-ASCII canonicalization escapes non-ASCII text", () => {
  const candidate = clone(knownVector());
  candidate.cvm.app_id = "app-é";
  const canonical = canonicalFinalReleaseAuthorityCoreBytes(candidate).toString("ascii");
  assert.ok(canonical.includes("app-\\u00e9"));
  assert.ok(!canonical.includes("é"));

  const astral = canonicalFinalReleaseAuthorityCoreBytes(knownVector()).toString("ascii");
  assert.ok(astral.includes("app_release_core_vector_1_\\ud83e\\uddec"));
  assert.ok(!astral.includes("🧬"));
});

test("canonical artifact reader rejects aliases and noncanonical bytes", async () => {
  const scriptsDirectory = path.dirname(fileURLToPath(import.meta.url));
  const directory = await mkdtemp(path.join(scriptsDirectory, ".release-core-test-"));
  try {
    const artifactPath = path.join(directory, "release-core.json");
    const normalized = normalizeFinalReleaseAuthorityCore(knownVector());
    await writeFile(
      artifactPath,
      canonicalFinalReleaseAuthorityCoreArtifactText(normalized),
      "utf8",
    );
    const artifact = await readCanonicalExecutionPolicyReleaseCoreArtifact(artifactPath);
    assert.equal(artifact.digest, KNOWN_DIGEST);
    assert.equal(artifact.core.cvm.app_id, "app_release_core_vector_1_🧬");

    const aliasPath = path.join(directory, "release-core-alias.json");
    await symlink(artifactPath, aliasPath);
    await assert.rejects(
      readCanonicalExecutionPolicyReleaseCoreArtifact(aliasPath),
      /must not contain symbolic links/,
    );

    await writeFile(artifactPath, JSON.stringify(normalized), "utf8");
    await assert.rejects(
      readCanonicalExecutionPolicyReleaseCoreArtifact(artifactPath),
      /canonical normalized pretty JSON/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("ceremony pins and CLI arguments are exact", () => {
  const core = normalizeFinalReleaseAuthorityCore(knownVector());
  assert.equal(executionPolicyWriterReleaseCommitment(core), word("e2"));
  assert.notEqual(
    executionPolicyWriterReleaseCommitment(core),
    `0x${finalReleaseAuthorityCoreDigest(core)}`,
  );
  const expected = {
    releaseSha: RELEASE_SHA,
    operator: address(1),
    anchor: address(13),
    anchorCodeHash: word("99"),
    writer: address(14),
  };
  assert.doesNotThrow(() => assertReleaseCoreMatchesCeremony(core, expected));
  for (const [key, replacement] of [
    ["releaseSha", "1123456789abcdef0123456789abcdef01234567"],
    ["operator", address(15)],
    ["anchor", address(15)],
    ["anchorCodeHash", word("98")],
    ["writer", address(15)],
  ]) {
    assert.throws(
      () => assertReleaseCoreMatchesCeremony(core, { ...expected, [key]: replacement }),
      /release-core artifact does not match/,
    );
  }

  const artifact = "/absolute/release-core.json";
  assert.deepEqual(parseArgs([
    "--artifact", artifact,
    "--release-sha", RELEASE_SHA,
    "--operator", address(1),
    "--anchor", address(13),
    "--anchor-code-hash", word("99"),
    "--writer", address(14),
  ]), { artifact, ...expected });
  assert.throws(() => parseArgs(["--artifact", "relative.json"]), /required|absolute/);
  assert.throws(() => parseArgs(["--unknown", "value"]), /unknown argument/);
});
