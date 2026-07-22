import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
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
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_DOMAIN,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
  canonicalPhalaPostMeasurementActivationPlanText,
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationInjectedEnvironmentKeys,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";
import {
  normalizePhalaPostMeasurementActivationPlan as normalizeProductionPlan,
  phalaPostMeasurementActivationPlanSha256 as productionPlanSha256,
} from "./phala-post-measurement-activation.mjs";
import {
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";

const sha = (byte) => `sha256:${byte.repeat(32)}`;
const word = (byte) => `0x${byte.repeat(32)}`;

function planFixture() {
  const releaseSha = "a".repeat(40);
  const deploymentIntentSha256 = sha("22");
  const cvmId = "cvm-main-0001";
  const authority = syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
    releaseSha,
    deploymentIntentSha256,
    ceremonyNonce: word("11"),
    releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
      mainRuntime: {
        descriptor_sha256: sha("aa"),
        app_id: "bb".repeat(20),
        cvm_id: cvmId,
        compose_hash: "cc".repeat(32),
        os_image_hash: "dd".repeat(32),
      },
    }),
  });
  const authoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(authority);
  const main = authority.descriptors.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  const computeQvl = authority.qvl_measurement_policies.find(
    (entry) => entry.domain === "compute_workload_qvl_cvm",
  );
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  const injected = phalaPostMeasurementActivationInjectedEnvironmentKeys();
  return {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
    chain_id: 84_532,
    release_sha: releaseSha,
    batch_id: sha("01"),
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: sha("03"),
    release_verification_authority: authority,
    release_verification_authority_sha256: authoritySha256,
    seven_cvm_verified_evidence_set_sha256: sha("05"),
    seven_cvm_launch_completion_receipt_sha256: sha("06"),
    phala_recovery_directory_identity_anchor_sha256: sha("0b"),
    bootstrap_public_environment_authority_sha256: sha("07"),
    postcommit_provisioning_authority_sha256: sha("08"),
    deferred_public_environment_authority_sha256: sha("09"),
    target: {
      domain: main.domain,
      descriptor_sha256: main.descriptor_sha256,
      app_id: main.app_id,
      cvm_id: main.cvm_id,
      compose_hash: main.compose_hash,
      os_image_hash: main.os_image_hash,
    },
    runtime_commitments: {
      TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: authority.ceremony_nonce,
      TINKER_COMPUTE_WORKLOAD_CVM_ID: main.cvm_id,
      TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:
        deploymentIntentSha256,
      TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: sha("0e"),
      TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:
        authority.qvl_measurement_policy_set_sha256,
      TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
        phalaQvlMeasurementPolicySha256(computeQvl),
      TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: authoritySha256,
    },
    runtime_commitment_key_names_sha256: cvmLaunchEnvironmentKeysDigest(
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
      request_path: `/api/v1/cvms/${main.cvm_id}/envs`,
      exact_body_fields: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
    },
    restart: {
      sdk_action: "restartCvm",
      http_method: "POST",
      request_path: `/api/v1/cvms/${main.cvm_id}/restart`,
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

test("activation-plan core binds one complete release authority and exact target", () => {
  const fixture = planFixture();
  const normalized = normalizePhalaPostMeasurementActivationPlan(fixture);
  assert.deepEqual(normalized, fixture);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.runtime_commitments), true);
  assert.equal(Object.isFrozen(normalized.profile_activation), true);
  assert.equal(Object.isFrozen(normalized.profile_activation.profile_names), true);
  assert.deepEqual(normalized.profile_activation, {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  });
  assert.equal(Object.isFrozen(normalized.release_verification_authority), true);
  assert.equal(Object.isFrozen(normalized.release_verification_authority.descriptors), true);
  assert.throws(() => {
    normalized.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256 = sha("f");
  }, TypeError);
  assert.equal(
    PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_DOMAIN,
    "dnai-wikigen/phala-post-measurement-activation-plan/v4\0",
  );
  assert.deepEqual(JSON.parse(canonicalPhalaPostMeasurementActivationPlanText(
    normalized,
  )), normalized);
  assert.match(
    phalaPostMeasurementActivationPlanSha256(normalized),
    /^sha256:[0-9a-f]{64}$/,
  );
});

test("activation-plan core rejects target, nonce, authority, and evidence drift", () => {
  const mutations = [
    (value) => { value.target.kms_id = "caller-injected"; },
    (value) => { value.target.cvm_id = "cvm-main-drifted"; },
    (value) => {
      value.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE =
        word("12");
    },
    (value) => { value.release_verification_authority_sha256 = sha("13"); },
    (value) => { value.post_restart_evidence.pre_injection_attestation_sufficient = true; },
    (value) => { value.live_traffic_authorized = true; },
  ];
  for (const mutate of mutations) {
    const fixture = planFixture();
    mutate(fixture);
    assert.throws(() => normalizePhalaPostMeasurementActivationPlan(fixture));
  }
});

test("activation-plan core rejects every non-exact combined profile set", () => {
  const mutations = [
    (value) => { value.profile_activation.profile_names.reverse(); },
    (value) => { value.profile_activation.profile_names.pop(); },
    (value) => { value.profile_activation.profile_names.push("compute-execution"); },
    (value) => { value.profile_activation.profile_names.push("deal-settlement"); },
    (value) => {
      value.profile_activation.profile_names = ["anchor-writer-ceremony"];
    },
    (value) => {
      value.profile_activation.compose_profiles_value = "compute-execution";
    },
    (value) => {
      value.profile_activation.compose_profiles_value =
        "compute-execution,arena-runtime";
    },
    (value) => { value.profile_activation.unreviewed = true; },
  ];
  for (const mutate of mutations) {
    const fixture = planFixture();
    mutate(fixture);
    assert.throws(
      () => normalizePhalaPostMeasurementActivationPlan(fixture),
      /combined profile activation|frozen fields/,
    );
  }
});

test("activation-plan core rejects getters before reading nested authority", () => {
  const fixture = planFixture();
  Object.defineProperty(fixture, "release_sha", {
    enumerable: true,
    get() { return "a".repeat(40); },
  });
  assert.throws(
    () => normalizePhalaPostMeasurementActivationPlan(fixture),
    /canonical plain-data graph/,
  );
});

test("activation-plan core rejects a sequential-get Proxy before any trap runs", () => {
  const fixture = planFixture();
  let evidenceReads = 0;
  fixture.runtime_commitments = new Proxy(fixture.runtime_commitments, {
    get(target, key, receiver) {
      if (key === "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256") {
        evidenceReads += 1;
        return evidenceReads === 1
          ? Reflect.get(target, key, receiver)
          : sha("ff");
      }
      return Reflect.get(target, key, receiver);
    },
  });
  assert.throws(
    () => normalizePhalaPostMeasurementActivationPlan(fixture),
    /canonical plain-data graph: Proxy objects are forbidden/,
  );
  assert.equal(evidenceReads, 0);
});

test("activation-plan core rejects impossible UTC dates and accepts a real leap day", () => {
  for (const impossible of [
    "2025-02-29T12:00:00Z",
    "2026-04-31T12:00:00Z",
    "2024-02-29T23:59:60Z",
  ]) {
    const fixture = planFixture();
    fixture.created_at = impossible;
    assert.throws(
      () => normalizePhalaPostMeasurementActivationPlan(fixture),
      /canonical UTC second/,
    );
  }

  const leapDay = planFixture();
  leapDay.created_at = "2024-02-29T23:59:59Z";
  assert.equal(
    normalizePhalaPostMeasurementActivationPlan(leapDay).created_at,
    "2024-02-29T23:59:59Z",
  );
});

test("activation-plan leaf stays digest-compatible with production facade", () => {
  const fixture = planFixture();
  const core = normalizePhalaPostMeasurementActivationPlan(fixture);
  const production = normalizeProductionPlan(fixture);
  assert.deepEqual(core, production);
  assert.equal(
    phalaPostMeasurementActivationPlanSha256(core),
    productionPlanSha256(production),
  );
});

test("activation-plan leaf has no effectful production imports or authority brand", async () => {
  const source = await readFile(
    new URL("./phala-post-measurement-activation-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:child_process",
    "Date.now(",
    "WeakMap",
    "WeakSet",
    "import(",
    "phala-seven-cvm-verifier-evidence.mjs",
    "phala-seven-cvm-launch-completion.mjs",
    "phala-production-environment-authority.mjs",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
