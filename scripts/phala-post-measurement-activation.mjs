import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  cvmLaunchEnvironmentKeysDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
  PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS,
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
  canonicalPhalaPostMeasurementActivationPlanText,
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationInjectedEnvironmentKeys,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";

export {
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
  assertPostCommitProvisioningEnvironmentAuthority,
  bootstrapPublicEnvironmentAuthorityDigest,
  assertProjectedPhalaDeferredPublicEnvironmentAuthority,
  deferredPublicEnvironmentAuthorityDigest,
  normalizeBootstrapPublicEnvironmentAuthority,
  postCommitProvisioningEnvironmentAuthorityDigest,
} from "./phala-production-environment-authority.mjs";
import {
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
const CHAIN_ID = 84_532;
const PLANS = new WeakMap();
const PLAN_EXPECTATIONS = new WeakMap();

function domainEntry(value, domain) {
  return value?.domains?.find((entry) => entry.domain === domain);
}

function assertPlanStillMatchesProductionDependencies(plan, dependencies, expected) {
  const releaseAuthority = dependencies.release_authority;
  const evidenceSet = dependencies.evidence_set;
  const completion = dependencies.launch_completion;
  const mainEvidence = domainEntry(evidenceSet, "main_runtime_cvm");
  const computeQvl = domainEntry(evidenceSet, "compute_workload_qvl_cvm");
  const mainCompletion = domainEntry(completion, "main_runtime_cvm");
  const bootstrapMain = domainEntry(
    dependencies.bootstrap_authority,
    "main_runtime_cvm",
  );
  const postcommitMain = domainEntry(
    dependencies.postcommit_authority,
    "main_runtime_cvm",
  );
  const deferredMain = domainEntry(
    dependencies.deferred_authority,
    "main_runtime_cvm",
  );
  const bootstrapSha256 = bootstrapPublicEnvironmentAuthorityDigest(
    dependencies.bootstrap_authority,
  );
  const postcommitSha256 = postCommitProvisioningEnvironmentAuthorityDigest(
    dependencies.postcommit_authority,
  );
  const deferredSha256 = deferredPublicEnvironmentAuthorityDigest(
    dependencies.deferred_authority,
  );
  if (!mainEvidence || !computeQvl || !mainCompletion
    || !bootstrapMain || !postcommitMain || !deferredMain
    || phalaPostMeasurementActivationPlanSha256(plan)
      !== expected.plan_sha256
    || phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority)
      !== expected.release_authority_sha256
    || bootstrapSha256 !== expected.bootstrap_authority_sha256
    || postcommitSha256 !== expected.postcommit_authority_sha256
    || deferredSha256 !== expected.deferred_authority_sha256
    || plan.release_verification_authority_sha256
      !== expected.release_authority_sha256
    || plan.seven_cvm_verified_evidence_set_sha256
      !== expected.evidence_set_sha256
    || plan.seven_cvm_launch_completion_receipt_sha256
      !== expected.launch_completion_sha256
    || evidenceSet.release_authority_sha256
      !== expected.release_authority_sha256
    || evidenceSet.deployment_intent_sha256
      !== plan.deployment_intent_sha256
    || evidenceSet.release_sha !== plan.release_sha
    || completion.machine_verifier_evidence_set_sha256
      !== expected.evidence_set_sha256
    || completion.release_verification_authority_sha256
      !== expected.release_authority_sha256
    || completion.deployment_intent_sha256
      !== plan.deployment_intent_sha256
    || completion.cvm_launch_intent_sha256 !== plan.cvm_launch_intent_sha256
    || completion.release_sha !== plan.release_sha
    || completion.phala_recovery_directory_identity_anchor_sha256
      !== plan.phala_recovery_directory_identity_anchor_sha256
    || evidenceSet.minimum_activation_evidence_lease_expires_at
      !== plan.activation_evidence_lease_expires_at
    || dependencies.postcommit_authority.bootstrap_authority_sha256
      !== bootstrapSha256
    || dependencies.postcommit_authority.batch_id !== plan.batch_id
    || dependencies.postcommit_authority.cvm_launch_intent_sha256
      !== plan.cvm_launch_intent_sha256
    || dependencies.deferred_authority.batch_id !== plan.batch_id
    || dependencies.deferred_authority.cvm_launch_intent_sha256
      !== plan.cvm_launch_intent_sha256
    || dependencies.deferred_authority.deployment_intent_sha256
      !== plan.deployment_intent_sha256
    || dependencies.deferred_authority.release_verification_authority_sha256
      !== expected.release_authority_sha256
    || dependencies.deferred_authority.seven_cvm_verified_evidence_set_sha256
      !== expected.evidence_set_sha256
    || dependencies.deferred_authority
      .seven_cvm_launch_completion_receipt_sha256
      !== expected.launch_completion_sha256
    || plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256
      !== mainEvidence.evidence_sha256
    || plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
      !== computeQvl.tdx_measurement_policy_sha256
    || bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE
      !== plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE
    || bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
      !== plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
    || bootstrapMain.values
      .TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
      !== plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
    || bootstrapMain.values
      .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
      !== plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
    || postcommitMain.values.TINKER_COMPUTE_WORKLOAD_CVM_ID
      !== plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_CVM_ID
    || deferredMain.values.TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256
      !== plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256
    || deferredMain.values.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256
      !== plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256
    || deferredMain.measured_cvm_authority_sha256
      !== mainEvidence.evidence_sha256
    || plan.target.descriptor_sha256 !== mainCompletion.descriptor_sha256
    || plan.target.app_id !== mainCompletion.app_id
    || plan.target.cvm_id !== mainCompletion.cvm_id
    || plan.target.compose_hash !== mainCompletion.committed_compose_hash
    || plan.target.os_image_hash !== mainCompletion.os_image_hash) {
    throw new Error(
      "activation plan no longer matches its production evidence and source authorities",
    );
  }
}

export async function createPhalaPostMeasurementActivationPlan({
  releaseAuthority: releaseAuthorityValue,
  verifiedEvidenceSet: verifiedEvidenceSetValue,
  launchCompletionReceipt: launchCompletionValue,
  bootstrapPublicEnvironmentAuthority: bootstrapValue,
  postcommitProvisioningAuthority: postcommitValue,
  deferredPublicEnvironmentAuthority: deferredValue,
} = {}) {
  const verifier = await import("./phala-seven-cvm-verifier-evidence.mjs");
  const completionModule = await import("./phala-seven-cvm-launch-completion.mjs");
  const releaseAuthority =
    verifier.assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
      releaseAuthorityValue,
    );
  const evidenceSet = verifier.assertProductionPhalaSevenCvmEvidenceSet(
    verifiedEvidenceSetValue,
  );
  const completion =
    completionModule.assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
      launchCompletionValue,
    );
  const bootstrap = deepFreezeCanonicalPlainDataGraph(
    normalizeBootstrapPublicEnvironmentAuthority(bootstrapValue),
    { label: "activation-plan bootstrap public authority snapshot" },
  );
  const postcommit = deepFreezeCanonicalPlainDataGraph(
    assertPostCommitProvisioningEnvironmentAuthority(postcommitValue),
    { label: "activation-plan postcommit authority dependency" },
  );
  const deferred = assertProjectedPhalaDeferredPublicEnvironmentAuthority(
    deferredValue,
  );
  const normalizedReleaseAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority(releaseAuthority);
  const releaseAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(normalizedReleaseAuthority);
  const evidenceSetSha256 =
    verifier.phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet);
  const completionSha256 =
    completionModule.phalaSevenCvmLaunchCompletionReceiptSha256(completion);
  const mainRelease = releaseAuthority.descriptors.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const computeQvl = evidenceSet.domains.find(
    ({ domain }) => domain === "compute_workload_qvl_cvm",
  );
  const mainEvidence = evidenceSet.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const mainCompletion = completion.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const bootstrapMain = bootstrap.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const postcommitMain = postcommit.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const deferredMain = deferred.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  if (!mainRelease || !computeQvl || !mainEvidence || !mainCompletion
    || !bootstrapMain || !postcommitMain || !deferredMain
    || releaseAuthority.release_sha !== completion.release_sha
    || releaseAuthority.deployment_intent_sha256
      !== completion.deployment_intent_sha256
    || evidenceSet.release_authority_sha256 !== releaseAuthoritySha256
    || evidenceSetSha256 !== completion.machine_verifier_evidence_set_sha256
    || postcommit.batch_id !== completion.batch_id
    || postcommit.cvm_launch_intent_sha256 !== completion.cvm_launch_intent_sha256
    || postcommit.executor_final_state_sha256 !== completion.executor_final_state_sha256
    || deferred.batch_id !== completion.batch_id
    || deferred.cvm_launch_intent_sha256 !== completion.cvm_launch_intent_sha256
    || mainRelease.cvm_id !== mainCompletion.cvm_id
    || mainRelease.cvm_id !== postcommitMain.values.TINKER_COMPUTE_WORKLOAD_CVM_ID
    || mainRelease.app_id !== mainCompletion.app_id
    || mainRelease.compose_hash !== mainCompletion.committed_compose_hash
    || mainRelease.os_image_hash !== mainCompletion.os_image_hash
    || mainEvidence.evidence_sha256 !== mainCompletion.machine_evidence_sha256) {
    throw new Error("post-measurement activation dependencies do not share one main-runtime lineage");
  }
  const commitments = {
    TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE:
      bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE,
    TINKER_COMPUTE_WORKLOAD_CVM_ID:
      postcommitMain.values.TINKER_COMPUTE_WORKLOAD_CVM_ID,
    TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:
      bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256,
    TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256:
      deferredMain.values.TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
    TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:
      bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256,
    TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
      bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
    TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:
      deferredMain.values.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256,
  };
  if (commitments.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
      !== releaseAuthority.deployment_intent_sha256
    || commitments.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE
      !== releaseAuthority.ceremony_nonce
    || commitments.TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
      !== releaseAuthority.qvl_measurement_policy_set_sha256
    || commitments.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
      !== computeQvl.tdx_measurement_policy_sha256
    || commitments.TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256
      !== releaseAuthoritySha256
    || commitments.TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256
      !== mainEvidence.evidence_sha256) {
    throw new Error("public runtime commitments differ from verified release dependencies");
  }
  const now = new Date(Math.floor(Date.now() / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
  const injectedKeys = phalaPostMeasurementActivationInjectedEnvironmentKeys();
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  const candidate = {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_TRUTH,
    chain_id: CHAIN_ID,
    release_sha: completion.release_sha,
    batch_id: completion.batch_id,
    deployment_intent_sha256: completion.deployment_intent_sha256,
    cvm_launch_intent_sha256: completion.cvm_launch_intent_sha256,
    release_verification_authority: normalizedReleaseAuthority,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
    seven_cvm_launch_completion_receipt_sha256: completionSha256,
    phala_recovery_directory_identity_anchor_sha256:
      completion.phala_recovery_directory_identity_anchor_sha256,
    bootstrap_public_environment_authority_sha256:
      bootstrapPublicEnvironmentAuthorityDigest(bootstrap),
    postcommit_provisioning_authority_sha256:
      postCommitProvisioningEnvironmentAuthorityDigest(postcommit),
    deferred_public_environment_authority_sha256:
      deferredPublicEnvironmentAuthorityDigest(deferred),
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: mainRelease.descriptor_sha256,
      app_id: mainRelease.app_id,
      cvm_id: mainRelease.cvm_id,
      compose_hash: mainRelease.compose_hash,
      os_image_hash: mainRelease.os_image_hash,
    },
    runtime_commitments: commitments,
    runtime_commitment_key_names_sha256:
      cvmLaunchEnvironmentKeysDigest(
        [...PHALA_COMPUTE_WORKLOAD_RUNTIME_COMMITMENT_KEYS],
      ),
    allowed_environment_key_names_sha256:
      policy.exact_allowed_environment_keys_sha256,
    allowed_environment_key_count: policy.exact_allowed_environment_keys.length,
    injected_environment_key_names: injectedKeys,
    injected_environment_key_names_sha256:
      cvmLaunchEnvironmentKeysDigest(injectedKeys),
    profile_activation: {
      profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
      compose_profiles_value:
        CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    },
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    environment_update: {
      sdk_action: "updateCvmEnvs",
      http_method: "PATCH",
      request_path: `/api/v1/cvms/${mainRelease.cvm_id}/envs`,
      exact_body_fields: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
    },
    restart: {
      sdk_action: "restartCvm",
      http_method: "POST",
      request_path: `/api/v1/cvms/${mainRelease.cvm_id}/restart`,
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
    created_at: now,
    activation_evidence_lease_expires_at:
      evidenceSet.minimum_activation_evidence_lease_expires_at,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    live_traffic_authorized: false,
  };
  const normalized = Object.freeze(normalizePhalaPostMeasurementActivationPlan(candidate));
  PLANS.set(normalized, Object.freeze({
    release_authority: releaseAuthority,
    evidence_set: evidenceSet,
    launch_completion: completion,
    bootstrap_authority: bootstrap,
    postcommit_authority: postcommit,
    deferred_authority: deferred,
  }));
  PLAN_EXPECTATIONS.set(normalized, Object.freeze({
    plan_sha256: phalaPostMeasurementActivationPlanSha256(normalized),
    release_authority_sha256: releaseAuthoritySha256,
    evidence_set_sha256: evidenceSetSha256,
    launch_completion_sha256: completionSha256,
    bootstrap_authority_sha256:
      bootstrapPublicEnvironmentAuthorityDigest(bootstrap),
    postcommit_authority_sha256:
      postCommitProvisioningEnvironmentAuthorityDigest(postcommit),
    deferred_authority_sha256:
      deferredPublicEnvironmentAuthorityDigest(deferred),
  }));
  return normalized;
}

export function assertFreshBrandedPhalaPostMeasurementActivationPlan(value) {
  const dependencies = value && PLANS.get(value);
  const expected = value && PLAN_EXPECTATIONS.get(value);
  const normalized = normalizePhalaPostMeasurementActivationPlan(value);
  if (!dependencies || !expected
    || canonicalPhalaPostMeasurementActivationPlanText(normalized)
      !== canonicalPhalaPostMeasurementActivationPlanText(value)
    || Math.floor(Date.now() / 1_000)
      >= normalized.activation_evidence_lease_expires_at) {
    throw new Error("a fresh dependency-reconstructed activation plan is required");
  }
  assertPlanStillMatchesProductionDependencies(normalized, dependencies, expected);
  return value;
}

export function readPhalaPostMeasurementActivationPlanDependencies(value) {
  assertFreshBrandedPhalaPostMeasurementActivationPlan(value);
  return PLANS.get(value);
}
