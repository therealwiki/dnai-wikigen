import assert from "node:assert/strict";
import test from "node:test";

import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  cvmLaunchEnvironmentKeysDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
  PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS,
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  canonicalPhalaPostMeasurementActivationPlanText,
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationInjectedEnvironmentKeys,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation.mjs";
import {
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture as
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./current-cvm-authority-v4.fixture.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";

const sha = (digit) => `sha256:${digit.repeat(64)}`;

function injectedKeys() {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  const classification = policy.public_environment_key_classification;
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return [...new Set([
    ...classification.descriptor_static_keys.filter((key) => allowed.has(key)),
    ...classification.provisioning_result_keys,
    ...classification.post_measurement_deferred_keys,
    ...classification.post_measurement_phase_control_keys,
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.encrypted_secret_environment_keys_by_phase.final_authority_runtime,
  ])].sort();
}

function planFixture() {
  const cvmId = "cvm-main-0001";
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  const injected = injectedKeys();
  const releaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha: "a".repeat(40),
      deploymentIntentSha256: sha("2"),
      ceremonyNonce: `0x${"1".repeat(64)}`,
      releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
        mainRuntime: {
          descriptor_sha256: sha("a"),
          app_id: "b".repeat(40),
          cvm_id: cvmId,
          compose_hash: "c".repeat(64),
          os_image_hash: "d".repeat(64),
        },
      }),
    });
  const releaseAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  return {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
    chain_id: 84_532,
    release_sha: "a".repeat(40),
    batch_id: sha("1"),
    deployment_intent_sha256: sha("2"),
    cvm_launch_intent_sha256: sha("3"),
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256: sha("5"),
    seven_cvm_launch_completion_receipt_sha256: sha("6"),
    phala_recovery_directory_identity_anchor_sha256: sha("b"),
    bootstrap_public_environment_authority_sha256: sha("7"),
    postcommit_provisioning_authority_sha256: sha("8"),
    deferred_public_environment_authority_sha256: sha("9"),
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: sha("a"),
      app_id: "b".repeat(40),
      cvm_id: cvmId,
      compose_hash: "c".repeat(64),
      os_image_hash: "d".repeat(64),
    },
    runtime_commitments: {
      TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"1".repeat(64)}`,
      TINKER_COMPUTE_WORKLOAD_CVM_ID: cvmId,
      TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: sha("2"),
      TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: sha("e"),
      TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:
        releaseAuthority.qvl_measurement_policy_set_sha256,
      TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
        phalaQvlMeasurementPolicySha256(
          releaseAuthority.qvl_measurement_policies.find(
            (entry) => entry.domain === "compute_workload_qvl_cvm",
          ),
        ),
      TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: releaseAuthoritySha256,
    },
    runtime_commitment_key_names_sha256:
      cvmLaunchEnvironmentKeysDigest(
        [...PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS],
      ),
    allowed_environment_key_names_sha256:
      policy.exact_allowed_environment_keys_sha256,
    allowed_environment_key_count: policy.exact_allowed_environment_keys.length,
    injected_environment_key_names: injected,
    injected_environment_key_names_sha256:
      cvmLaunchEnvironmentKeysDigest(injected),
    profile_activation: {
      profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
      compose_profiles_value:
        CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    },
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    environment_update: {
      sdk_action: "updateCvmEnvs",
      http_method: "PATCH",
      request_path: `/api/v1/cvms/${cvmId}/envs`,
      exact_body_fields: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
    },
    restart: {
      sdk_action: "restartCvm",
      http_method: "POST",
      request_path: `/api/v1/cvms/${cvmId}/restart`,
      force: false,
    },
    post_restart_evidence: {
      authenticated_get_cvm_info_required: true,
      authenticated_get_cvm_attestation_required: true,
      arena_worker_presence_schema: PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
      arena_worker_presence_evidence_classification:
        PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
      arena_runtime_authenticated_worker_presence_required: true,
      compute_workload_recipient_activation_v3_required: true,
      independent_tdx_verdict_v4_required: true,
      pre_injection_attestation_sufficient: false,
    },
    created_at: "2026-07-21T12:00:00Z",
    activation_evidence_lease_expires_at: 4_000_000_000,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    live_traffic_authorized: false,
  };
}

test("post-measurement plan freezes the exact main-runtime PATCH/restart proof boundary", () => {
  const plan = planFixture();
  const normalized = normalizePhalaPostMeasurementActivationPlan(plan);
  assert.deepEqual(normalized, plan);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.runtime_commitments), true);
  assert.equal(Object.isFrozen(normalized.target), true);
  assert.throws(() => {
    normalized.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256 = sha("f");
  }, TypeError);
  assert.equal(canonicalPhalaPostMeasurementActivationPlanText(plan).endsWith("\n"), true);
  assert.equal(
    phalaPostMeasurementActivationPlanSha256(plan),
    "sha256:c5aad909c9bd318386c7ec807784521baf4fb9e95082c9e648724ad670387086",
  );
  const runtimeAuthority =
    plan.release_verification_authority.cvm_descriptor_runtime_authority;
  const mainRuntime = runtimeAuthority.descriptors.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  assert.deepEqual(
    mainRuntime.service_images.map(({ service }) => service),
    [
      "neko",
      "oracle",
      "delegate",
      "diligence-policy-init",
      "tinker-customer-authority-init",
      "arena-policy-init",
      "arena-worker",
      "anchor-writer-evidence",
      "deal-runtime",
      "compute-execution-worker",
      "review-operations",
      "mailbox-genesis",
      "tinker-account-genesis",
    ],
  );
  assert.equal(
    plan.release_verification_authority
      .tinker_account_binding_ceremony_receipt_sha256,
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  );
  assert.equal(
    runtimeAuthority.tinker_account_binding_ceremony_receipt_sha256,
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  );
  assert.equal(plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CVM_ID,
    plan.target.cvm_id);
  assert.equal(plan.environment_update.allowed_environment_keys_mutated, false);
  assert.equal(plan.post_restart_evidence.pre_injection_attestation_sufficient, false);
  assert.deepEqual(plan.profile_activation, {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  });
  assert.equal(
    plan.post_restart_evidence.arena_worker_presence_evidence_classification,
    "authenticated_worker_presence_not_tdx_attestation",
  );
  assert.deepEqual(
    phalaPostMeasurementActivationInjectedEnvironmentKeys(),
    injectedKeys(),
  );
  for (const key of [
    "TINKER_ARENA_REGISTRY_ADDRESS",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
    "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
    "TINKER_ARENA_REGISTRY_RPC_URL",
    "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
    "TINKER_COLLABORATION_ENABLED",
    "TINKER_CUSTOMER_AUTHORITY_SHA256",
    "TINKER_CUSTOMER_ENABLED",
  ]) {
    assert.equal(plan.injected_environment_key_names.includes(key), true);
  }
  assert.throws(
    () => assertFreshBrandedPhalaPostMeasurementActivationPlan(plan),
    /fresh dependency-reconstructed activation plan/,
  );
});

test("post-measurement plan rejects retries, target drift, env-key widening, and weak proof", () => {
  const mutations = [
    (value) => { value.automatic_retry_authorized = true; },
    (value) => { value.target.cvm_id = "cvm-other-0002"; },
    (value) => { value.environment_update.exact_body_fields.push("env_keys"); },
    (value) => { value.environment_update.allowed_environment_keys_mutated = true; },
    (value) => { value.profile_activation.profile_names = ["compute-execution"]; },
    (value) => { value.profile_activation.profile_names.reverse(); },
    (value) => { value.profile_activation.profile_names.push("deal-settlement"); },
    (value) => { value.profile_activation.profile_names.push("arena-runtime"); },
    (value) => {
      value.profile_activation.profile_names = ["anchor-writer-ceremony"];
    },
    (value) => {
      value.profile_activation.compose_profiles_value = "compute-execution";
    },
    (value) => { value.restart.force = true; },
    (value) => {
      value.post_restart_evidence.arena_runtime_authenticated_worker_presence_required =
        false;
    },
    (value) => { value.post_restart_evidence.pre_injection_attestation_sufficient = true; },
    (value) => { value.injected_environment_key_names.pop(); },
    (value) => { value.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CVM_ID = "cvm-other-0002"; },
    (value) => { value.release_verification_authority_sha256 = sha("4"); },
    (value) => {
      value.release_verification_authority = structuredClone(
        value.release_verification_authority,
      );
      value.release_verification_authority.descriptors[0].disk_size += 1;
    },
    (value) => {
      value.release_verification_authority = structuredClone(
        value.release_verification_authority,
      );
      value.release_verification_authority
        .tinker_account_binding_ceremony_receipt_sha256 = sha("f");
    },
    (value) => {
      value.release_verification_authority = structuredClone(
        value.release_verification_authority,
      );
      value.release_verification_authority.cvm_descriptor_runtime_authority
        .tinker_account_binding_ceremony_receipt_sha256 = sha("f");
    },
    (value) => {
      value.release_verification_authority = structuredClone(
        value.release_verification_authority,
      );
      const services = value.release_verification_authority
        .cvm_descriptor_runtime_authority.descriptors
        .find(({ domain }) => domain === "main_runtime_cvm").service_images;
      services.splice(
        services.findIndex(({ service }) => service === "mailbox-genesis"),
        1,
      );
    },
    (value) => {
      value.release_verification_authority = structuredClone(
        value.release_verification_authority,
      );
      value.release_verification_authority
        .cvm_descriptor_runtime_authority.descriptors
        .find(({ domain }) => domain === "main_runtime_cvm").service_images
        .find(({ service }) => service === "tinker-account-genesis").service =
          "tinker-account-genesis-substituted";
    },
  ];
  for (const mutate of mutations) {
    const plan = planFixture();
    mutate(plan);
    assert.throws(
      () => normalizePhalaPostMeasurementActivationPlan(plan),
      undefined,
      `mutation must be rejected: ${mutate.toString()}`,
    );
  }
});
