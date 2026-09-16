import {
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
  readPhalaPostMeasurementActivationPlanDependencies,
} from "./phala-post-measurement-activation.mjs";
import {
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt,
  phalaSevenCvmLaunchCompletionReceiptSha256,
} from "./phala-seven-cvm-launch-completion.mjs";
import {
  assertCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  assertProductionPhalaSevenCvmEvidenceSet,
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
  PRE_CEREMONY_REQUIRED_ACTIVATION_EXECUTION_RECEIPT_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_CLI_FLAG,
  PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
  PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
  PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
  REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  REQUIRED_ACTIVATION_OBSERVATION_SCHEMA,
  REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA,
  REQUIRED_SIGNED_B_SCHEMA,
  REQUIRED_SIGNED_B_STATUS,
  REQUIRED_SOURCE_ACTIVATION_SCHEMA,
  assertPersistedPreCeremonyRuntimeAuthority as assertPersistedRuntimeAuthorityCore,
  canonicalPreCeremonyRuntimeAuthorityText,
  futureActivationAuthorizationTranscriptPolicy,
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority-core.mjs";

export {
  FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
  PRE_CEREMONY_REQUIRED_ACTIVATION_EXECUTION_RECEIPT_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_CLI_FLAG,
  PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
  PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
  PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
  REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  REQUIRED_ACTIVATION_OBSERVATION_SCHEMA,
  REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA,
  REQUIRED_SIGNED_B_SCHEMA,
  REQUIRED_SIGNED_B_STATUS,
  REQUIRED_SOURCE_ACTIVATION_SCHEMA,
  canonicalPreCeremonyRuntimeAuthorityText,
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
};

const CHAIN_ID = 84_532;
const AUTHORITIES = new WeakMap();

function fail(message) {
  throw new TypeError(message);
}

function assertProductionPlanDependencies(plan) {
  const dependencies = readPhalaPostMeasurementActivationPlanDependencies(plan);
  const evidenceSet = assertProductionPhalaSevenCvmEvidenceSet(
    dependencies.evidence_set,
  );
  const launchCompletion =
    assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
      dependencies.launch_completion,
    );
  if (phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet)
      !== plan.seven_cvm_verified_evidence_set_sha256
    || evidenceSet.release_authority_sha256
      !== plan.release_verification_authority_sha256
    || evidenceSet.minimum_activation_evidence_lease_expires_at
      !== plan.activation_evidence_lease_expires_at
    || phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletion)
      !== plan.seven_cvm_launch_completion_receipt_sha256) {
    fail(
      "R production plan differs from its branded L or seven-CVM evidence dependency",
    );
  }
  return { dependencies, evidenceSet, launchCompletion };
}

/**
 * Mint the live, branded pre-ceremony authority only from a fresh branded
 * activation plan and its same-process production dependencies.
 *
 * All deterministic schema, canonicalization, and digest behavior lives in
 * pre-ceremony-runtime-authority-core.mjs. This facade owns only current-clock
 * freshness and same-process production brands.
 */
export function createPreCeremonyRuntimeAuthority(input = {}) {
  assertCanonicalPlainDataGraph(input, {
    label: "pre-ceremony runtime authority constructor input",
  });
  const keys = Object.keys(input);
  if (keys.length !== 1 || keys[0] !== "postMeasurementActivationPlan") {
    fail(
      "pre-ceremony runtime authority constructor input must contain exactly postMeasurementActivationPlan",
    );
  }
  const postMeasurementActivationPlan =
    Object.getOwnPropertyDescriptor(
      input,
      "postMeasurementActivationPlan",
    ).value;
  const plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(
    postMeasurementActivationPlan,
  );
  const {
    dependencies,
    evidenceSet,
    launchCompletion,
  } = assertProductionPlanDependencies(plan);
  const issuedAt = Math.floor(Date.now() / 1_000);
  if (evidenceSet.issued_at > issuedAt) {
    fail("R cannot be issued before its machine-verifier evidence set");
  }
  const authority = normalizePreCeremonyRuntimeAuthority({
    schema: PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
    status: PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
    truth_status: PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
    release_sha: plan.release_sha,
    chain_id: CHAIN_ID,
    issued_at: issuedAt,
    machine_verifier_evidence_issued_at: evidenceSet.issued_at,
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
    historical_transcript_file_set_sha256:
      evidenceSet.historical_transcript_file_set_sha256,
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
  AUTHORITIES.set(authority, Object.freeze({
    authority_sha256: preCeremonyRuntimeAuthoritySha256(authority),
    post_measurement_activation_plan: plan,
    seven_cvm_launch_completion_receipt: launchCompletion,
    seven_cvm_verified_evidence_set: evidenceSet,
    release_verification_authority: dependencies.release_authority,
  }));
  return authority;
}

export function assertFreshBrandedPreCeremonyRuntimeAuthority(value) {
  const dependencies = value && AUTHORITIES.get(value);
  if (!dependencies
    || preCeremonyRuntimeAuthoritySha256(value)
      !== dependencies.authority_sha256) {
    fail("a fresh dependency-reconstructed pre-ceremony runtime authority is required");
  }
  const plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(
    dependencies.post_measurement_activation_plan,
  );
  const evidenceSet = assertProductionPhalaSevenCvmEvidenceSet(
    dependencies.seven_cvm_verified_evidence_set,
  );
  const launchCompletion =
    assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
      dependencies.seven_cvm_launch_completion_receipt,
    );
  if (phalaPostMeasurementActivationPlanSha256(plan)
      !== value.post_measurement_activation_plan_sha256
    || phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet)
      !== plan.seven_cvm_verified_evidence_set_sha256
    || phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletion)
      !== value.seven_cvm_launch_completion_receipt_sha256
    || Math.floor(Date.now() / 1_000)
      >= value.activation_evidence_lease_expires_at) {
    fail(
      "pre-ceremony runtime authority dependencies or activation-evidence lease drifted",
    );
  }
  return value;
}

export function readPreCeremonyRuntimeAuthorityDependencies(value) {
  assertFreshBrandedPreCeremonyRuntimeAuthority(value);
  return AUTHORITIES.get(value);
}

export function assertPersistedPreCeremonyRuntimeAuthority(input = {}) {
  return assertPersistedRuntimeAuthorityCore(input);
}
