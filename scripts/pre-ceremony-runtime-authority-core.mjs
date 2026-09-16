import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";
import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  normalizePhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";

/**
 * Deterministic, unbranded structure for the exact pre-ceremony runtime
 * authority reviewed by signed B.
 *
 * This leaf validates persisted values and their cross-commitments only. It
 * never consults a current clock, reads files, verifies a production brand, or
 * authorizes activation. The production facade owns those effects.
 */
export const PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA =
  "dnai.pre-ceremony-runtime-authority.v4";
export const PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS =
  "exact_launch_and_combined_main_runtime_activation_plan_committed_pending_signed_b";
export const PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH =
  "nonauthorizing_pre_ceremony_combined_arena_compute_profile_and_activation_evidence_lease_dependency_not_activation_execution_observation_or_live_traffic";
export const PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN =
  "dnai-wikigen/pre-ceremony-runtime-authority/v4\0";
export const PRE_CEREMONY_RUNTIME_AUTHORITY_CLI_FLAG =
  "--runtime-authority-dependency";

export const FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA =
  "dnai.future-workload-activation-authorization-transcript-policy.v4";
export const REQUIRED_SOURCE_ACTIVATION_SCHEMA =
  "dnai.compute.workload-recipient-activation.v3";
export const REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA =
  "dnai.independent-tdx-verdict.v4";
export const REQUIRED_ACTIVATION_OBSERVATION_SCHEMA =
  "dnai.compute-workload-activation-observation.v3";
export const REQUIRED_SIGNED_B_SCHEMA =
  "dnai.ceremony-authorization-core.v1";
export const REQUIRED_SIGNED_B_STATUS = "pre_ceremony_authorized";
export const REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA =
  "dnai.phala-post-measurement-activation-execution-receipt.v3";

export const PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS = Object.freeze([
  "deployment_intent_sha256",
  "release_verification_authority_sha256",
  "ceremony_nonce",
  "qvl_measurement_policy_set_sha256",
  "historical_transcript_file_set_sha256",
  "fresh_contract_deployment_receipt_sha256",
  "nonlive_bootstrap_authorization_receipt_sha256",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "pre_ceremony_runtime_authority_sha256",
  "post_measurement_activation_plan_sha256",
  "post_measurement_activation_execution_receipt_sha256",
  "ceremony_authorization_sha256",
]);

export const PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS =
  Object.freeze([
    "activation_verification_sha256",
    "activation_artifact_sha256",
    "challenge_id",
    "challenge_digest",
    "challenge_issued_at",
    "challenge_expires_at",
    "tdx_quote_sha256",
    "qvl_verdict_signing_digest",
    "qvl_verdict_artifact_sha256",
    "qvl_verdict_verifier_signature_sha256",
    "raw_transcript_sha256",
    "verdict_issued_at",
    "verdict_expires_at",
    "verdict_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "activation_verification_expires_at",
    "authenticated_at",
    "verified_at",
  ]);

export const PRE_CEREMONY_REQUIRED_ACTIVATION_EXECUTION_RECEIPT_LINEAGE_FIELDS =
  Object.freeze([
    "ceremony_authorization_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "post_measurement_activation_plan_sha256",
  ]);

const CHAIN_ID = 84_532;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function second(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    throw new TypeError(`${label} must be a bounded Unix second`);
  }
  return value;
}

function exactFrozenArray(value, expected, label) {
  if (!Array.isArray(value)
    || JSON.stringify(value) !== JSON.stringify(expected)) {
    throw new TypeError(`${label} is omitted, reordered, substituted, or extended`);
  }
  return [...expected];
}

function exactCombinedProfileActivation(value) {
  const parsed = exactRecord(value, [
    "profile_names",
    "compose_profiles_value",
  ], "future combined main-runtime profile activation");
  if (JSON.stringify(parsed.profile_names)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES)
    || parsed.compose_profiles_value
      !== CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE) {
    throw new TypeError(
      "future combined main-runtime profile activation is omitted, reordered, duplicated, substituted, or widened",
    );
  }
  return {
    profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
    compose_profiles_value:
      CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
}

export function normalizeFutureActivationAuthorizationTranscriptPolicy(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "future workload activation authorization/transcript policy input",
  });
  const parsed = exactRecord(value, [
    "schema",
    "post_measurement_activation_plan_schema",
    "required_main_runtime_profile_activation",
    "signed_ceremony_authorization_schema",
    "signed_ceremony_authorization_status",
    "signed_ceremony_authorization_dependency_kind",
    "activation_execution_receipt_schema",
    "activation_observation_schema",
    "source_activation_schema",
    "arena_worker_presence_schema",
    "arena_worker_presence_evidence_classification",
    "independent_tdx_verdict_schema",
    "historical_transcript_file_set_schema",
    "historical_transcript_flag_order",
    "required_activation_execution_receipt_lineage_fields",
    "required_observation_lineage_fields",
    "required_observation_verification_fields",
    "signed_ceremony_authorization_required",
    "activation_execution_receipt_required",
    "post_restart_compute_workload_source_activation_required",
    "post_restart_arena_runtime_authenticated_worker_presence_required",
    "post_restart_attestation_required",
    "pre_injection_attestation_sufficient",
    "embedded_compute_workload_source_activation_required",
    "fresh_at_observation_issuance_required",
    "historical_replay_may_refresh_freshness",
    "persisted_raw_transcript_commitment_required",
    "persisted_verifier_signature_commitment_required",
    "automatic_retry_authorized",
    "ambiguous_outcome_quarantine_required",
    "private_historical_identity_response_quote_bytes_persistence_required",
    "raw_quote_external_egress_allowed",
    "raw_private_artifact_egress_allowed",
    "raw_secret_egress_allowed",
    "live_traffic_authorized",
  ], "future workload activation authorization/transcript policy");
  if (parsed.schema
      !== FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA
    || parsed.post_measurement_activation_plan_schema
      !== PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA
    || parsed.signed_ceremony_authorization_schema !== REQUIRED_SIGNED_B_SCHEMA
    || parsed.signed_ceremony_authorization_status !== REQUIRED_SIGNED_B_STATUS
    || parsed.signed_ceremony_authorization_dependency_kind
      !== "pre_ceremony_runtime_authority"
    || parsed.activation_execution_receipt_schema
      !== REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA
    || parsed.activation_observation_schema
      !== REQUIRED_ACTIVATION_OBSERVATION_SCHEMA
    || parsed.source_activation_schema !== REQUIRED_SOURCE_ACTIVATION_SCHEMA
    || parsed.arena_worker_presence_schema
      !== PHALA_ARENA_WORKER_PRESENCE_SCHEMA
    || parsed.arena_worker_presence_evidence_classification
      !== PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION
    || parsed.independent_tdx_verdict_schema
      !== REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA
    || parsed.historical_transcript_file_set_schema
      !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA
    || parsed.signed_ceremony_authorization_required !== true
    || parsed.activation_execution_receipt_required !== true
    || parsed.post_restart_compute_workload_source_activation_required !== true
    || parsed.post_restart_arena_runtime_authenticated_worker_presence_required
      !== true
    || parsed.post_restart_attestation_required !== true
    || parsed.pre_injection_attestation_sufficient !== false
    || parsed.embedded_compute_workload_source_activation_required !== true
    || parsed.fresh_at_observation_issuance_required !== true
    || parsed.historical_replay_may_refresh_freshness !== false
    || parsed.persisted_raw_transcript_commitment_required !== true
    || parsed.persisted_verifier_signature_commitment_required !== true
    || parsed.automatic_retry_authorized !== false
    || parsed.ambiguous_outcome_quarantine_required !== true
    || parsed.private_historical_identity_response_quote_bytes_persistence_required
      !== true
    || parsed.raw_quote_external_egress_allowed !== false
    || parsed.raw_private_artifact_egress_allowed !== false
    || parsed.raw_secret_egress_allowed !== false
    || parsed.live_traffic_authorized !== false) {
    throw new TypeError(
      "future workload activation authorization/transcript policy is downgraded or unsafe",
    );
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
    post_measurement_activation_plan_schema:
      PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    required_main_runtime_profile_activation: exactCombinedProfileActivation(
      parsed.required_main_runtime_profile_activation,
    ),
    signed_ceremony_authorization_schema: REQUIRED_SIGNED_B_SCHEMA,
    signed_ceremony_authorization_status: REQUIRED_SIGNED_B_STATUS,
    signed_ceremony_authorization_dependency_kind:
      "pre_ceremony_runtime_authority",
    activation_execution_receipt_schema:
      REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    activation_observation_schema: REQUIRED_ACTIVATION_OBSERVATION_SCHEMA,
    source_activation_schema: REQUIRED_SOURCE_ACTIVATION_SCHEMA,
    arena_worker_presence_schema: PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
    arena_worker_presence_evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    independent_tdx_verdict_schema: REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA,
    historical_transcript_file_set_schema:
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
    historical_transcript_flag_order: exactFrozenArray(
      parsed.historical_transcript_flag_order,
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
      "historical transcript flag order",
    ),
    required_activation_execution_receipt_lineage_fields: exactFrozenArray(
      parsed.required_activation_execution_receipt_lineage_fields,
      PRE_CEREMONY_REQUIRED_ACTIVATION_EXECUTION_RECEIPT_LINEAGE_FIELDS,
      "required activation execution receipt lineage field order",
    ),
    required_observation_lineage_fields: exactFrozenArray(
      parsed.required_observation_lineage_fields,
      PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
      "required O lineage field order",
    ),
    required_observation_verification_fields: exactFrozenArray(
      parsed.required_observation_verification_fields,
      PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
      "required O verification field order",
    ),
    signed_ceremony_authorization_required: true,
    activation_execution_receipt_required: true,
    post_restart_compute_workload_source_activation_required: true,
    post_restart_arena_runtime_authenticated_worker_presence_required: true,
    post_restart_attestation_required: true,
    pre_injection_attestation_sufficient: false,
    embedded_compute_workload_source_activation_required: true,
    fresh_at_observation_issuance_required: true,
    historical_replay_may_refresh_freshness: false,
    persisted_raw_transcript_commitment_required: true,
    persisted_verifier_signature_commitment_required: true,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    private_historical_identity_response_quote_bytes_persistence_required:
      true,
    raw_quote_external_egress_allowed: false,
    raw_private_artifact_egress_allowed: false,
    raw_secret_egress_allowed: false,
    live_traffic_authorized: false,
  }, { label: "future workload activation authorization/transcript policy" });
}

export function futureActivationAuthorizationTranscriptPolicy() {
  return normalizeFutureActivationAuthorizationTranscriptPolicy({
    schema: FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
    post_measurement_activation_plan_schema:
      PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
    required_main_runtime_profile_activation: {
      profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
      compose_profiles_value:
        CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    },
    signed_ceremony_authorization_schema: REQUIRED_SIGNED_B_SCHEMA,
    signed_ceremony_authorization_status: REQUIRED_SIGNED_B_STATUS,
    signed_ceremony_authorization_dependency_kind:
      "pre_ceremony_runtime_authority",
    activation_execution_receipt_schema:
      REQUIRED_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    activation_observation_schema: REQUIRED_ACTIVATION_OBSERVATION_SCHEMA,
    source_activation_schema: REQUIRED_SOURCE_ACTIVATION_SCHEMA,
    arena_worker_presence_schema: PHALA_ARENA_WORKER_PRESENCE_SCHEMA,
    arena_worker_presence_evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    independent_tdx_verdict_schema: REQUIRED_INDEPENDENT_TDX_VERDICT_SCHEMA,
    historical_transcript_file_set_schema:
      PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FILE_SET_SCHEMA,
    historical_transcript_flag_order:
      [...PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER],
    required_activation_execution_receipt_lineage_fields:
      [...PRE_CEREMONY_REQUIRED_ACTIVATION_EXECUTION_RECEIPT_LINEAGE_FIELDS],
    required_observation_lineage_fields:
      [...PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS],
    required_observation_verification_fields:
      [...PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS],
    signed_ceremony_authorization_required: true,
    activation_execution_receipt_required: true,
    post_restart_compute_workload_source_activation_required: true,
    post_restart_arena_runtime_authenticated_worker_presence_required: true,
    post_restart_attestation_required: true,
    pre_injection_attestation_sufficient: false,
    embedded_compute_workload_source_activation_required: true,
    fresh_at_observation_issuance_required: true,
    historical_replay_may_refresh_freshness: false,
    persisted_raw_transcript_commitment_required: true,
    persisted_verifier_signature_commitment_required: true,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    private_historical_identity_response_quote_bytes_persistence_required:
      true,
    raw_quote_external_egress_allowed: false,
    raw_private_artifact_egress_allowed: false,
    raw_secret_egress_allowed: false,
    live_traffic_authorized: false,
  });
}

export function normalizePreCeremonyRuntimeAuthority(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "pre-ceremony runtime authority input",
  });
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "release_sha",
    "chain_id",
    "issued_at",
    "machine_verifier_evidence_issued_at",
    "activation_evidence_lease_expires_at",
    "proofs_valid_at_issuance",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "historical_transcript_file_set_sha256",
    "post_measurement_activation_plan_sha256",
    "post_measurement_activation_plan",
    "future_activation_authorization_transcript_policy",
    "activation_execution_authorized",
    "live_traffic_authorized",
    "contains_activation_observation",
    "contains_activation_execution_receipt",
    "private_historical_identity_response_quote_bytes_persisted",
    "raw_quote_external_egress",
    "raw_private_artifact_egress",
    "raw_secret_egress",
  ], "pre-ceremony runtime authority");
  if (parsed.schema !== PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA
    || parsed.status !== PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS
    || parsed.truth_status !== PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH
    || parsed.chain_id !== CHAIN_ID
    || typeof parsed.release_sha !== "string"
    || !SHA40.test(parsed.release_sha)
    || parsed.proofs_valid_at_issuance !== true
    || parsed.activation_execution_authorized !== false
    || parsed.live_traffic_authorized !== false
    || parsed.contains_activation_observation !== false
    || parsed.contains_activation_execution_receipt !== false
    || parsed.private_historical_identity_response_quote_bytes_persisted
      !== true
    || parsed.raw_quote_external_egress !== false
    || parsed.raw_private_artifact_egress !== false
    || parsed.raw_secret_egress !== false) {
    throw new TypeError(
      "pre-ceremony runtime authority truth or authorization boundary is invalid",
    );
  }

  const plan = normalizePhalaPostMeasurementActivationPlan(
    parsed.post_measurement_activation_plan,
  );
  const issuedAt = second(parsed.issued_at, "R issued_at");
  const activationEvidenceLeaseExpiresAt = second(
    parsed.activation_evidence_lease_expires_at,
    "R activation-evidence lease expires_at",
  );
  const machineVerifierEvidenceIssuedAt = second(
    parsed.machine_verifier_evidence_issued_at,
    "R machine-verifier evidence issued_at",
  );
  const planCreatedAt = Math.floor(Date.parse(plan.created_at) / 1_000);
  if (issuedAt < planCreatedAt
    || issuedAt >= activationEvidenceLeaseExpiresAt
    || machineVerifierEvidenceIssuedAt > planCreatedAt
    || machineVerifierEvidenceIssuedAt > issuedAt
    || machineVerifierEvidenceIssuedAt >= activationEvidenceLeaseExpiresAt
    || activationEvidenceLeaseExpiresAt
      !== plan.activation_evidence_lease_expires_at) {
    throw new TypeError(
      "R issuance is outside the exact activation-plan evidence lease",
    );
  }

  const planSha256 = phalaPostMeasurementActivationPlanSha256(plan);
  const deploymentIntentSha256 = sha256(
    parsed.deployment_intent_sha256,
    "R deployment intent",
  );
  const launchIntentSha256 = sha256(
    parsed.cvm_launch_intent_sha256,
    "R CVM launch intent",
  );
  const releaseAuthoritySha256 = sha256(
    parsed.release_verification_authority_sha256,
    "R release verification authority",
  );
  const launchCompletionSha256 = sha256(
    parsed.seven_cvm_launch_completion_receipt_sha256,
    "R seven-CVM launch completion receipt",
  );
  const historicalTranscriptFileSetSha256 = sha256(
    parsed.historical_transcript_file_set_sha256,
    "R historical transcript file set",
  );
  const recoveryDirectoryIdentityAnchorSha256 = sha256(
    parsed.phala_recovery_directory_identity_anchor_sha256,
    "R Phala recovery-directory identity anchor",
  );
  if (parsed.release_sha !== plan.release_sha
    || deploymentIntentSha256 !== plan.deployment_intent_sha256
    || launchIntentSha256 !== plan.cvm_launch_intent_sha256
    || releaseAuthoritySha256
      !== plan.release_verification_authority_sha256
    || launchCompletionSha256
      !== plan.seven_cvm_launch_completion_receipt_sha256
    || recoveryDirectoryIdentityAnchorSha256
      !== plan.phala_recovery_directory_identity_anchor_sha256
    || sha256(
      parsed.post_measurement_activation_plan_sha256,
      "R post-measurement activation plan",
    ) !== planSha256
    || new Set([
      deploymentIntentSha256,
      launchIntentSha256,
      releaseAuthoritySha256,
      launchCompletionSha256,
      historicalTranscriptFileSetSha256,
      recoveryDirectoryIdentityAnchorSha256,
      planSha256,
    ]).size !== 7) {
    throw new TypeError(
      "pre-ceremony runtime authority plan or launch lineage drifted",
    );
  }

  return deepFreezeCanonicalPlainDataGraph({
    schema: PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
    status: PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
    truth_status: PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
    release_sha: parsed.release_sha,
    chain_id: CHAIN_ID,
    issued_at: issuedAt,
    machine_verifier_evidence_issued_at: machineVerifierEvidenceIssuedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    proofs_valid_at_issuance: true,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: launchIntentSha256,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_launch_completion_receipt_sha256: launchCompletionSha256,
    phala_recovery_directory_identity_anchor_sha256:
      recoveryDirectoryIdentityAnchorSha256,
    historical_transcript_file_set_sha256:
      historicalTranscriptFileSetSha256,
    post_measurement_activation_plan_sha256: planSha256,
    post_measurement_activation_plan: plan,
    future_activation_authorization_transcript_policy:
      normalizeFutureActivationAuthorizationTranscriptPolicy(
        parsed.future_activation_authorization_transcript_policy,
      ),
    activation_execution_authorized: false,
    live_traffic_authorized: false,
    contains_activation_observation: false,
    contains_activation_execution_receipt: false,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  }, { label: "pre-ceremony runtime authority" });
}

export function canonicalPreCeremonyRuntimeAuthorityText(value) {
  return canonicalText(normalizePreCeremonyRuntimeAuthority(value));
}

export function preCeremonyRuntimeAuthoritySha256(value) {
  return `sha256:${createHash("sha256")
    .update(PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN, "utf8")
    .update(canonicalPreCeremonyRuntimeAuthorityText(value), "utf8")
    .digest("hex")}`;
}

export function projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(value) {
  const authority = normalizePreCeremonyRuntimeAuthority(value);
  const plan = authority.post_measurement_activation_plan;
  return normalizePhalaSevenCvmHistoricalRuntimeBinding({
    schema: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
    release_sha: authority.release_sha,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    cvm_launch_intent_sha256: authority.cvm_launch_intent_sha256,
    release_verification_authority: plan.release_verification_authority,
    release_verification_authority_sha256:
      authority.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      authority.seven_cvm_launch_completion_receipt_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      authority.phala_recovery_directory_identity_anchor_sha256,
    batch_id: plan.batch_id,
    seven_cvm_verified_evidence_set_sha256:
      plan.seven_cvm_verified_evidence_set_sha256,
    main_runtime_target: plan.target,
    activation_plan_created_at: plan.created_at,
    machine_verifier_evidence_issued_at:
      authority.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      authority.activation_evidence_lease_expires_at,
  });
}

export function assertPersistedPreCeremonyRuntimeAuthority(input = {}) {
  assertCanonicalPlainDataGraph(input, {
    label: "persisted R reconstruction input",
  });
  const parsed = exactRecord(input, [
    "persistedAuthority",
    "reconstructedLaunchCompletionReceiptSha256",
    "reconstructedHistoricalTranscriptFileSet",
    "signedAtMs",
    "reviewExpiresAtMs",
  ], "persisted R reconstruction input");
  const authority = normalizePreCeremonyRuntimeAuthority(
    parsed.persistedAuthority,
  );
  const launchCompletionSha256 = sha256(
    parsed.reconstructedLaunchCompletionReceiptSha256,
    "reconstructed historical L receipt",
  );
  const transcriptFileSet = normalizePhalaSevenCvmHistoricalTranscriptFileSet(
    parsed.reconstructedHistoricalTranscriptFileSet,
  );
  const transcriptSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(
    transcriptFileSet,
  );
  if (!Number.isSafeInteger(parsed.signedAtMs)
    || !Number.isSafeInteger(parsed.reviewExpiresAtMs)) {
    throw new TypeError(
      "persisted R reconstruction requires original signed-B timing",
    );
  }
  const authorityIssuedAtMs = authority.issued_at * 1_000;
  const activationEvidenceLeaseExpiresAtMs =
    authority.activation_evidence_lease_expires_at * 1_000;
  if (launchCompletionSha256
      !== authority.seven_cvm_launch_completion_receipt_sha256
    || transcriptSha256 !== authority.historical_transcript_file_set_sha256
    || parsed.signedAtMs < authorityIssuedAtMs
    || parsed.signedAtMs >= activationEvidenceLeaseExpiresAtMs
    || parsed.reviewExpiresAtMs <= parsed.signedAtMs
    || parsed.reviewExpiresAtMs > activationEvidenceLeaseExpiresAtMs) {
    throw new TypeError(
      "persisted R does not match exact L/transcript dependencies or signed-B activation-evidence lease",
    );
  }
  // Intentionally unbranded historical data. This authenticates the original
  // signed-B dependency without refreshing QVL, L, or posture freshness.
  return authority;
}
