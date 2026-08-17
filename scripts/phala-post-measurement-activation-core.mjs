import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  cvmLaunchEnvironmentKeysDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    currentPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA as
    LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";

/**
 * Deterministic, unbranded activation-plan structure.
 *
 * This leaf verifies carried values and their cross-commitments. It cannot
 * prove that dependencies are fresh production objects, cannot read a current
 * clock, and cannot authorize a Phala mutation or live traffic. Those powers
 * remain exclusively in the production activation facade.
 */
export const PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA =
  "dnai.phala-post-measurement-activation-plan.v4";
export const PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS =
  "main_runtime_arena_and_compute_activation_pending_signed_b_with_activation_evidence_lease";
export const PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH =
  "exact_release_verification_authority_target_activation_evidence_lease_and_combined_arena_compute_profile_set_bound_patch_restart_plan_not_authorization_execution_post_restart_evidence_or_live_traffic";
export const PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_DOMAIN =
  "dnai-wikigen/phala-post-measurement-activation-plan/v4\0";

export const PHALA_ARENA_WORKER_PRESENCE_SCHEMA =
  "dnai.arena.safe-worker-heartbeat.v1";
export const PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION =
  "authenticated_worker_presence_not_tdx_attestation";

export const PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE = Object.freeze([
  "updateCvmEnvs:main_runtime_cvm:encrypted_env_only",
  "restartCvm:main_runtime_cvm:force_false",
  "getCvmInfo:main_runtime_cvm:post_restart",
  "getCvmAttestation:main_runtime_cvm:post_restart",
  "verifyArenaRuntimeAuthenticatedWorkerPresence:main_runtime_cvm:post_restart",
  "verifyComputeWorkloadRecipientActivation:main_runtime_cvm:post_restart",
]);

export const PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS = Object.freeze([
  "TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE",
  "TINKER_COMPUTE_WORKLOAD_CVM_ID",
  "TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
  "TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
  "TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
  "TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256",
  "TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
]);

const CHAIN_ID = 84_532;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function normalizeVersionedReleaseVerificationAuthority(value) {
  const descriptor = isRecord(value)
    ? Object.getOwnPropertyDescriptor(value, "schema")
    : null;
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    throw new TypeError(
      "post-measurement plan release authority requires one own data schema",
    );
  }
  if (descriptor.value
      === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    const authority =
      normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority(value);
    return Object.freeze({
      authority,
      sha256:
        currentPhalaSevenCvmReleaseVerificationAuthoritySha256(authority),
    });
  }
  if (descriptor.value
      === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    const authority =
      normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(value);
    return Object.freeze({
      authority,
      sha256:
        legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(authority),
    });
  }
  throw new TypeError(
    "post-measurement plan release authority schema version is unsupported",
  );
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactString(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new Error(`${label} is not canonical`);
  }
  return value;
}

function exactSecond(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function exactEnvironmentKeys(value, label) {
  if (!Array.isArray(value) || value.some((key) => (
    typeof key !== "string" || !ENVIRONMENT_KEY.test(key)
  ))) {
    throw new Error(`${label} must contain canonical environment names`);
  }
  const sorted = [...value].sort();
  if (new Set(sorted).size !== sorted.length
    || JSON.stringify(sorted) !== JSON.stringify(value)) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return sorted;
}

function exactCombinedProfileActivation(value) {
  const parsed = exactRecord(value, [
    "profile_names",
    "compose_profiles_value",
  ], "main-runtime combined profile activation");
  if (JSON.stringify(parsed.profile_names)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES)
    || parsed.compose_profiles_value
      !== CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE) {
    throw new Error(
      "main-runtime combined profile activation is omitted, reordered, duplicated, substituted, or widened",
    );
  }
  return {
    profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
    compose_profiles_value:
      CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
}

function exactCommitments(value) {
  const parsed = exactRecord(
    value,
    PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS,
    "compute-workload runtime commitments",
  );
  return {
    TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: exactString(
      parsed.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE,
      BYTES32,
      "compute-workload ceremony nonce",
    ),
    TINKER_COMPUTE_WORKLOAD_CVM_ID: exactString(
      parsed.TINKER_COMPUTE_WORKLOAD_CVM_ID,
      CVM_ID,
      "compute-workload CVM ID",
    ),
    TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: sha256(
      parsed.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256,
      "compute-workload deployment intent",
    ),
    TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: sha256(
      parsed.TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
      "compute-workload main-runtime evidence",
    ),
    TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: sha256(
      parsed.TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256,
      "compute-workload measurement-policy set",
    ),
    TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256: sha256(
      parsed.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
      "compute-workload QVL measurement policy",
    ),
    TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: sha256(
      parsed.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256,
      "compute-workload release verification authority",
    ),
  };
}

export function phalaPostMeasurementActivationInjectedEnvironmentKeys() {
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

export function normalizePhalaPostMeasurementActivationPlan(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "post-measurement activation plan",
  });
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "chain_id",
    "release_sha",
    "batch_id",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "release_verification_authority",
    "release_verification_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "bootstrap_public_environment_authority_sha256",
    "postcommit_provisioning_authority_sha256",
    "deferred_public_environment_authority_sha256",
    "target",
    "runtime_commitments",
    "runtime_commitment_key_names_sha256",
    "allowed_environment_key_names_sha256",
    "allowed_environment_key_count",
    "injected_environment_key_names",
    "injected_environment_key_names_sha256",
    "profile_activation",
    "mutation_sequence",
    "environment_update",
    "restart",
    "post_restart_evidence",
    "created_at",
    "activation_evidence_lease_expires_at",
    "automatic_retry_authorized",
    "ambiguous_outcome_quarantine_required",
    "live_traffic_authorized",
  ], "post-measurement activation plan");
  if (parsed.schema !== PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA
    || parsed.status !== PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS
    || parsed.truth_status !== PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH
    || parsed.chain_id !== CHAIN_ID
    || parsed.automatic_retry_authorized !== false
    || parsed.ambiguous_outcome_quarantine_required !== true
    || parsed.live_traffic_authorized !== false) {
    throw new Error("post-measurement activation plan boundary is invalid");
  }
  const target = exactRecord(parsed.target, [
    "domain",
    "descriptor_sha256",
    "app_id",
    "cvm_id",
    "compose_hash",
    "os_image_hash",
  ], "post-measurement activation target");
  if (target.domain !== "main_runtime_cvm") {
    throw new Error("post-measurement activation target is not main runtime");
  }
  const update = exactRecord(parsed.environment_update, [
    "sdk_action",
    "http_method",
    "request_path",
    "exact_body_fields",
    "encrypted_environment_only",
    "allowed_environment_keys_mutated",
  ], "post-measurement environment update");
  const restart = exactRecord(parsed.restart, [
    "sdk_action",
    "http_method",
    "request_path",
    "force",
  ], "post-measurement restart");
  const evidence = exactRecord(parsed.post_restart_evidence, [
    "authenticated_get_cvm_info_required",
    "authenticated_get_cvm_attestation_required",
    "arena_worker_presence_schema",
    "arena_worker_presence_evidence_classification",
    "arena_runtime_authenticated_worker_presence_required",
    "compute_workload_recipient_activation_v3_required",
    "independent_tdx_verdict_v4_required",
    "pre_injection_attestation_sufficient",
  ], "post-restart evidence requirements");
  const allowed = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
    .exact_allowed_environment_keys;
  const injected = exactEnvironmentKeys(
    parsed.injected_environment_key_names,
    "injected_environment_key_names",
  );
  const profileActivation = exactCombinedProfileActivation(
    parsed.profile_activation,
  );
  const commitments = exactCommitments(parsed.runtime_commitments);
  const {
    authority: releaseAuthority,
    sha256: releaseAuthoritySha256,
  } = normalizeVersionedReleaseVerificationAuthority(
    parsed.release_verification_authority,
  );
  const mainReleaseDescriptor = releaseAuthority.descriptors.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  const computeWorkloadQvlPolicy = releaseAuthority.qvl_measurement_policies.find(
    (entry) => entry.domain === "compute_workload_qvl_cvm",
  );
  if (JSON.stringify(injected)
      !== JSON.stringify(phalaPostMeasurementActivationInjectedEnvironmentKeys())
    || parsed.injected_environment_key_names_sha256
      !== cvmLaunchEnvironmentKeysDigest(injected)
    || parsed.allowed_environment_key_count !== allowed.length
    || parsed.allowed_environment_key_names_sha256
      !== CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
        .exact_allowed_environment_keys_sha256
    || parsed.runtime_commitment_key_names_sha256
      !== cvmLaunchEnvironmentKeysDigest(
        [...PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS],
      )
    || commitments.TINKER_COMPUTE_WORKLOAD_CVM_ID !== target.cvm_id
    || commitments.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
      !== parsed.deployment_intent_sha256
    || commitments.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256
      !== parsed.release_verification_authority_sha256
    || parsed.release_verification_authority_sha256 !== releaseAuthoritySha256
    || releaseAuthority.release_sha !== parsed.release_sha
    || releaseAuthority.deployment_intent_sha256
      !== parsed.deployment_intent_sha256
    || !mainReleaseDescriptor || !computeWorkloadQvlPolicy
    || mainReleaseDescriptor.descriptor_sha256 !== target.descriptor_sha256
    || mainReleaseDescriptor.app_id !== target.app_id
    || mainReleaseDescriptor.cvm_id !== target.cvm_id
    || mainReleaseDescriptor.compose_hash !== target.compose_hash
    || mainReleaseDescriptor.os_image_hash !== target.os_image_hash
    || commitments.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE
      !== releaseAuthority.ceremony_nonce
    || commitments.TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
      !== releaseAuthority.qvl_measurement_policy_set_sha256
    || commitments.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
      !== phalaQvlMeasurementPolicySha256(computeWorkloadQvlPolicy)
    || JSON.stringify(parsed.mutation_sequence)
      !== JSON.stringify(PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE)
    || update.sdk_action !== "updateCvmEnvs"
    || update.http_method !== "PATCH"
    || update.request_path !== `/api/v1/cvms/${target.cvm_id}/envs`
    || JSON.stringify(update.exact_body_fields)
      !== JSON.stringify(["encrypted_env"])
    || update.encrypted_environment_only !== true
    || update.allowed_environment_keys_mutated !== false
    || restart.sdk_action !== "restartCvm"
    || restart.http_method !== "POST"
    || restart.request_path !== `/api/v1/cvms/${target.cvm_id}/restart`
    || restart.force !== false
    || evidence.authenticated_get_cvm_info_required !== true
    || evidence.authenticated_get_cvm_attestation_required !== true
    || evidence.arena_worker_presence_schema
      !== PHALA_ARENA_WORKER_PRESENCE_SCHEMA
    || evidence.arena_worker_presence_evidence_classification
      !== PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION
    || evidence.arena_runtime_authenticated_worker_presence_required !== true
    || evidence.compute_workload_recipient_activation_v3_required !== true
    || evidence.independent_tdx_verdict_v4_required !== true
    || evidence.pre_injection_attestation_sufficient !== false) {
    throw new Error("post-measurement mutation or post-restart proof plan drifted");
  }
  const createdAt = exactSecond(parsed.created_at, "activation plan created_at");
  if (!Number.isSafeInteger(parsed.activation_evidence_lease_expires_at)
    || parsed.activation_evidence_lease_expires_at
      <= Math.floor(Date.parse(createdAt) / 1_000)) {
    throw new Error("activation plan activation-evidence lease is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
    chain_id: CHAIN_ID,
    release_sha: exactString(parsed.release_sha, SHA40, "release SHA"),
    batch_id: sha256(parsed.batch_id, "launch batch"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "deployment intent",
    ),
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "CVM launch intent",
    ),
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "seven-CVM evidence set",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "seven-CVM launch completion receipt",
    ),
    phala_recovery_directory_identity_anchor_sha256: sha256(
      parsed.phala_recovery_directory_identity_anchor_sha256,
      "Phala recovery-directory identity anchor",
    ),
    bootstrap_public_environment_authority_sha256: sha256(
      parsed.bootstrap_public_environment_authority_sha256,
      "bootstrap public environment authority",
    ),
    postcommit_provisioning_authority_sha256: sha256(
      parsed.postcommit_provisioning_authority_sha256,
      "post-commit provisioning authority",
    ),
    deferred_public_environment_authority_sha256: sha256(
      parsed.deferred_public_environment_authority_sha256,
      "deferred public environment authority",
    ),
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: sha256(target.descriptor_sha256, "main descriptor"),
      app_id: exactString(target.app_id, APP_ID, "main app ID"),
      cvm_id: exactString(target.cvm_id, CVM_ID, "main CVM ID"),
      compose_hash: exactString(
        target.compose_hash,
        BARE_SHA256,
        "main compose hash",
      ),
      os_image_hash: exactString(
        target.os_image_hash,
        BARE_SHA256,
        "main OS image hash",
      ),
    },
    runtime_commitments: commitments,
    runtime_commitment_key_names_sha256:
      parsed.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256:
      parsed.allowed_environment_key_names_sha256,
    allowed_environment_key_count: parsed.allowed_environment_key_count,
    injected_environment_key_names: injected,
    injected_environment_key_names_sha256:
      parsed.injected_environment_key_names_sha256,
    profile_activation: profileActivation,
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    environment_update: {
      sdk_action: "updateCvmEnvs",
      http_method: "PATCH",
      request_path: update.request_path,
      exact_body_fields: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
    },
    restart: {
      sdk_action: "restartCvm",
      http_method: "POST",
      request_path: restart.request_path,
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
    created_at: createdAt,
    activation_evidence_lease_expires_at:
      parsed.activation_evidence_lease_expires_at,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    live_traffic_authorized: false,
  }, { label: "normalized post-measurement activation plan" });
}

export function phalaPostMeasurementActivationPlanSha256(value) {
  const normalized = normalizePhalaPostMeasurementActivationPlan(value);
  return `sha256:${createHash("sha256")
    .update(PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_DOMAIN, "utf8")
    .update(JSON.stringify(sortedObject(normalized)), "utf8")
    .digest("hex")}`;
}

export function canonicalPhalaPostMeasurementActivationPlanText(value) {
  return canonicalText(normalizePhalaPostMeasurementActivationPlan(value));
}
