// Synthetic test-only fixture. It contains no production brands or authority.
import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
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
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
  PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
  futureActivationAuthorizationTranscriptPolicy,
  normalizePreCeremonyRuntimeAuthority,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";

const pin = (pair) => `sha256:${pair.repeat(32)}`;

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

export function syntheticPostMeasurementActivationPlanFixture({
  releaseSha = "a".repeat(40),
  deploymentIntentSha256 = pin("22"),
  cvmLaunchIntentSha256 = pin("33"),
  releaseVerificationAuthority,
  sevenCvmLaunchCompletionReceiptSha256 = pin("66"),
  createdAt = "2026-07-21T12:00:00Z",
  activationEvidenceLeaseExpiresAt = 4_000_000_000,
} = {}) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  const injected = injectedKeys();
  const embeddedReleaseAuthority = releaseVerificationAuthority
    ?? syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha,
      deploymentIntentSha256,
      ceremonyNonce: `0x${"11".repeat(32)}`,
      releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
        mainRuntime: {
          descriptor_sha256: pin("aa"),
          app_id: "bb".repeat(20),
          cvm_id: "cvm-main-0001",
          compose_hash: "cc".repeat(32),
          os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
        },
      }),
    });
  const mainReleaseDescriptor = embeddedReleaseAuthority.descriptors.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  const computeWorkloadQvlPolicy =
    embeddedReleaseAuthority.qvl_measurement_policies.find(
      (entry) => entry.domain === "compute_workload_qvl_cvm",
    );
  if (!mainReleaseDescriptor || !computeWorkloadQvlPolicy) {
    throw new TypeError(
      "synthetic activation plan requires main-runtime and compute-QVL authority entries",
    );
  }
  const releaseVerificationAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(
      embeddedReleaseAuthority,
    );
  return normalizePhalaPostMeasurementActivationPlan({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
    chain_id: 84_532,
    release_sha: releaseSha,
    batch_id: pin("11"),
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    release_verification_authority: embeddedReleaseAuthority,
    release_verification_authority_sha256:
      releaseVerificationAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256: pin("55"),
    seven_cvm_launch_completion_receipt_sha256:
      sevenCvmLaunchCompletionReceiptSha256,
    phala_recovery_directory_identity_anchor_sha256: pin("ab"),
    bootstrap_public_environment_authority_sha256: pin("77"),
    postcommit_provisioning_authority_sha256: pin("88"),
    deferred_public_environment_authority_sha256: pin("99"),
    target: {
      domain: mainReleaseDescriptor.domain,
      descriptor_sha256: mainReleaseDescriptor.descriptor_sha256,
      app_id: mainReleaseDescriptor.app_id,
      cvm_id: mainReleaseDescriptor.cvm_id,
      compose_hash: mainReleaseDescriptor.compose_hash,
      os_image_hash: mainReleaseDescriptor.os_image_hash,
    },
    runtime_commitments: {
      TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:
        embeddedReleaseAuthority.ceremony_nonce,
      TINKER_COMPUTE_WORKLOAD_CVM_ID: mainReleaseDescriptor.cvm_id,
      TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:
        deploymentIntentSha256,
      TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: pin("ee"),
      TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:
        embeddedReleaseAuthority.qvl_measurement_policy_set_sha256,
      TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
        phalaQvlMeasurementPolicySha256(computeWorkloadQvlPolicy),
      TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:
        releaseVerificationAuthoritySha256,
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
      request_path: `/api/v1/cvms/${mainReleaseDescriptor.cvm_id}/envs`,
      exact_body_fields: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
    },
    restart: {
      sdk_action: "restartCvm",
      http_method: "POST",
      request_path: `/api/v1/cvms/${mainReleaseDescriptor.cvm_id}/restart`,
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
      activationEvidenceLeaseExpiresAt,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    live_traffic_authorized: false,
  });
}

export function syntheticHistoricalTranscriptFileSetFixture() {
  return createPhalaSevenCvmHistoricalTranscriptFileSet(Object.fromEntries(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag, index) => [
      flag,
      {
        sha256:
          `sha256:${(index + 17).toString(16).padStart(2, "0").repeat(32)}`,
        size: 1_000 + index,
      },
    ]),
  ));
}

export function syntheticPreCeremonyRuntimeAuthorityFromPlanFixture({
  postMeasurementActivationPlan,
  historicalTranscriptFileSetSha256 =
    phalaSevenCvmHistoricalTranscriptFileSetSha256(
      syntheticHistoricalTranscriptFileSetFixture(),
    ),
  issuedAt = Math.floor(
    Date.parse(postMeasurementActivationPlan?.created_at) / 1_000,
  ),
  machineVerifierEvidenceIssuedAt = Math.floor(
    Date.parse(postMeasurementActivationPlan?.created_at) / 1_000,
  ),
} = {}) {
  const plan = normalizePhalaPostMeasurementActivationPlan(
    postMeasurementActivationPlan,
  );
  return normalizePreCeremonyRuntimeAuthority({
    schema: PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
    status: PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
    truth_status: PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
    release_sha: plan.release_sha,
    chain_id: 84_532,
    issued_at: issuedAt,
    machine_verifier_evidence_issued_at: machineVerifierEvidenceIssuedAt,
    activation_evidence_lease_expires_at:
      plan.activation_evidence_lease_expires_at,
    proofs_valid_at_issuance: true,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    cvm_launch_intent_sha256: plan.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      plan.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    historical_transcript_file_set_sha256: historicalTranscriptFileSetSha256,
    post_measurement_activation_plan_sha256:
      phalaPostMeasurementActivationPlanSha256(plan),
    post_measurement_activation_plan: plan,
    future_activation_authorization_transcript_policy:
      futureActivationAuthorizationTranscriptPolicy(),
    activation_execution_authorized: false,
    live_traffic_authorized: false,
    contains_activation_observation: false,
    contains_activation_execution_receipt: false,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  });
}

export function syntheticPreCeremonyRuntimeAuthorityFixture(options = {}) {
  const {
    issuedAt = 1_784_635_200,
    machineVerifierEvidenceIssuedAt,
    ...planOptions
  } = options;
  const provisionalPlan = syntheticPostMeasurementActivationPlanFixture(
    planOptions,
  );
  const releaseVerificationAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority({
      ...structuredClone(provisionalPlan.release_verification_authority),
      evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    });
  const plan = syntheticPostMeasurementActivationPlanFixture({
    ...planOptions,
    releaseVerificationAuthority,
  });
  return syntheticPreCeremonyRuntimeAuthorityFromPlanFixture({
    postMeasurementActivationPlan: plan,
    issuedAt,
    machineVerifierEvidenceIssuedAt:
      machineVerifierEvidenceIssuedAt
        ?? Math.floor(Date.parse(plan.created_at) / 1_000),
  });
}
