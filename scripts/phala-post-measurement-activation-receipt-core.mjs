import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
} from "./cvm-launch-intent-core.mjs";

export const PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA =
  "dnai.phala-post-measurement-activation-execution-receipt.v3";
export const PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS =
  "main_runtime_arena_and_compute_post_measurement_activation_verified_not_live_traffic";
export const PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH =
  "signed_b_authorized_exact_combined_profile_encrypted_only_patch_restart_authenticated_arena_worker_presence_initial_and_recipient_evidence_leases_verified_no_live_traffic_claim";
export const PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-post-measurement-activation-execution-receipt/v3\0";
export const PHALA_POST_MEASUREMENT_RUNTIME_COMMITMENTS_DOMAIN =
  "dnai-wikigen/phala-post-measurement-runtime-commitments/v1\0";
export const PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA =
  "dnai.phala-arena-worker-presence-activation-proof.v1";
export const PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA =
  "dnai.arena.safe-worker-heartbeat.v1";
export const PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION =
  "authenticated_worker_presence_not_tdx_attestation";
export const PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_DOMAIN =
  "dnai-wikigen/phala-arena-worker-presence-activation-proof/v1\0";
export const PHALA_COMBINED_ARENA_COMPUTE_ACTIVATION_VERIFICATION_DOMAIN =
  "dnai-wikigen/combined-arena-compute-activation-verification/v1\0";

export const PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE = Object.freeze([
  "updateCvmEnvs:main_runtime_cvm:encrypted_env_only",
  "restartCvm:main_runtime_cvm:force_false",
  "getCvmInfo:main_runtime_cvm:post_restart",
  "getCvmAttestation:main_runtime_cvm:post_restart",
  "verifyArenaRuntimeAuthenticatedWorkerPresence:main_runtime_cvm:post_restart",
  "verifyComputeWorkloadRecipientActivation:main_runtime_cvm:post_restart",
]);

const CHAIN_ID = 84_532;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const CHALLENGE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const CHALLENGE_VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
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

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sorted(value)), "utf8")
    .digest("hex")}`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} is not canonical`);
  }
  return value;
}

function second(value, label) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (!ISO_SECOND.test(String(value)) || !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a canonical UTC second`);
  }
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail(`${label} must be a positive safe integer`);
  }
  return value;
}

function exactProfileActivation(value) {
  const parsed = exactRecord(value, [
    "profile_names",
    "compose_profiles_value",
  ], "activation execution profile set");
  if (JSON.stringify(parsed.profile_names)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES)
    || parsed.compose_profiles_value
      !== CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE) {
    fail("activation execution profile set is omitted, reordered, substituted, or widened");
  }
  return {
    profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
    compose_profiles_value: CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
}

export function normalizePhalaArenaWorkerPresenceActivationProof(value) {
  const parsed = exactRecord(value, [
    "schema",
    "heartbeat_schema",
    "evidence_classification",
    "endpoint_commitment_sha256",
    "challenge_id",
    "challenge_version",
    "response_sha256",
    "release_binding_sha256",
    "heartbeat_observed_at",
    "verified_at",
  ], "Arena worker presence activation proof");
  if (parsed.schema !== PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA
    || parsed.heartbeat_schema !== PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA
    || parsed.evidence_classification
      !== PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION
    || !Number.isSafeInteger(parsed.heartbeat_observed_at)
    || !Number.isSafeInteger(parsed.verified_at)
    || parsed.heartbeat_observed_at < 1
    || parsed.verified_at < parsed.heartbeat_observed_at) {
    fail("Arena worker presence proof boundary is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: sha256(
      parsed.endpoint_commitment_sha256,
      "Arena worker endpoint commitment",
    ),
    challenge_id: fixed(
      parsed.challenge_id,
      CHALLENGE_ID,
      "Arena worker challenge ID",
    ),
    challenge_version: fixed(
      parsed.challenge_version,
      CHALLENGE_VERSION,
      "Arena worker challenge version",
    ),
    response_sha256: sha256(
      parsed.response_sha256,
      "Arena worker bounded response",
    ),
    release_binding_sha256: sha256(
      parsed.release_binding_sha256,
      "Arena worker release binding",
    ),
    heartbeat_observed_at: parsed.heartbeat_observed_at,
    verified_at: parsed.verified_at,
  }, { label: "normalized Arena worker presence activation proof" });
}

export function phalaArenaWorkerPresenceActivationProofSha256(value) {
  return domainDigest(
    PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_DOMAIN,
    normalizePhalaArenaWorkerPresenceActivationProof(value),
  );
}

export function phalaCombinedArenaComputeActivationVerificationSha256({
  profileActivation,
  arenaWorkerPresenceSha256,
  computeRecipientActivationSha256,
} = {}) {
  return domainDigest(
    PHALA_COMBINED_ARENA_COMPUTE_ACTIVATION_VERIFICATION_DOMAIN,
    {
      profile_activation: exactProfileActivation(profileActivation),
      arena_worker_presence_sha256: sha256(
        arenaWorkerPresenceSha256,
        "combined Arena worker presence proof",
      ),
      compute_recipient_activation_sha256: sha256(
        computeRecipientActivationSha256,
        "combined Compute recipient activation proof",
      ),
    },
  );
}

function normalizeTarget(value) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "descriptor_sha256", "domain",
    "os_image_hash",
  ], "activation execution target");
  if (parsed.domain !== "main_runtime_cvm") {
    fail("activation execution target is not main runtime");
  }
  return {
    domain: "main_runtime_cvm",
    descriptor_sha256: sha256(parsed.descriptor_sha256, "main descriptor"),
    app_id: fixed(parsed.app_id, APP_ID, "main app ID"),
    cvm_id: fixed(parsed.cvm_id, CVM_ID, "main CVM ID"),
    compose_hash: fixed(parsed.compose_hash, BARE_SHA256, "main compose hash"),
    os_image_hash: fixed(parsed.os_image_hash, BARE_SHA256, "main OS image hash"),
  };
}

function normalizeFinalizedReadiness(value, label) {
  const parsed = exactRecord(value, [
    "finalized_block_hash", "finalized_block_number", "readiness_sha256",
  ], label);
  return {
    readiness_sha256: sha256(parsed.readiness_sha256, `${label} readiness`),
    finalized_block_number: positiveInteger(
      parsed.finalized_block_number,
      `${label} finalized block number`,
    ),
    finalized_block_hash: fixed(
      parsed.finalized_block_hash,
      BYTES32,
      `${label} finalized block hash`,
    ),
  };
}

function normalizePatch(value) {
  const parsed = exactRecord(value, [
    "allowed_environment_keys_mutated", "attempt_recorded_at", "body_field_names",
    "call_sequence", "encrypted_environment_only", "finalized_readiness",
    "observation_sha256", "observed_at", "request_semantics_sha256",
    "response_sha256", "sdk_action",
  ], "activation PATCH receipt");
  if (parsed.sdk_action !== "updateCvmEnvs"
    || parsed.call_sequence !== 4
    || JSON.stringify(parsed.body_field_names) !== JSON.stringify(["encrypted_env"])
    || parsed.encrypted_environment_only !== true
    || parsed.allowed_environment_keys_mutated !== false) {
    fail("activation PATCH receipt is widened or reordered");
  }
  return {
    sdk_action: "updateCvmEnvs",
    call_sequence: 4,
    request_semantics_sha256: sha256(
      parsed.request_semantics_sha256,
      "PATCH request semantics",
    ),
    observation_sha256: sha256(parsed.observation_sha256, "PATCH observation"),
    response_sha256: sha256(parsed.response_sha256, "PATCH response"),
    body_field_names: ["encrypted_env"],
    encrypted_environment_only: true,
    allowed_environment_keys_mutated: false,
    attempt_recorded_at: second(
      parsed.attempt_recorded_at,
      "PATCH durable-attempt time",
    ),
    observed_at: second(parsed.observed_at, "PATCH observed_at"),
    finalized_readiness: normalizeFinalizedReadiness(
      parsed.finalized_readiness,
      "PATCH finalized readiness",
    ),
  };
}

function normalizeRestart(value) {
  const parsed = exactRecord(value, [
    "attempt_recorded_at", "call_sequence", "finalized_readiness", "force",
    "observation_sha256", "observed_at", "request_semantics_sha256",
    "response_sha256", "sdk_action",
  ], "activation restart receipt");
  if (parsed.sdk_action !== "restartCvm"
    || parsed.call_sequence !== 5 || parsed.force !== false) {
    fail("activation restart receipt is widened or reordered");
  }
  return {
    sdk_action: "restartCvm",
    call_sequence: 5,
    request_semantics_sha256: sha256(
      parsed.request_semantics_sha256,
      "restart request semantics",
    ),
    observation_sha256: sha256(parsed.observation_sha256, "restart observation"),
    response_sha256: sha256(parsed.response_sha256, "restart response"),
    force: false,
    attempt_recorded_at: second(
      parsed.attempt_recorded_at,
      "restart durable-attempt time",
    ),
    observed_at: second(parsed.observed_at, "restart observed_at"),
    finalized_readiness: normalizeFinalizedReadiness(
      parsed.finalized_readiness,
      "restart finalized readiness",
    ),
  };
}

function normalizePostRestartEvidence(value) {
  const parsed = exactRecord(value, [
    "app_certificate_quote_present", "attestation_error_absent", "cvm_online",
    "get_cvm_attestation_call_sequence", "get_cvm_attestation_observation_sha256",
    "get_cvm_attestation_observed_at", "get_cvm_attestation_response_sha256",
    "get_cvm_info_call_sequence", "get_cvm_info_observation_sha256",
    "get_cvm_info_observed_at", "get_cvm_info_response_sha256",
    "pre_injection_attestation_sufficient", "tcb_info_present",
  ], "post-restart Phala evidence");
  if (parsed.get_cvm_info_call_sequence !== 6
    || parsed.get_cvm_attestation_call_sequence !== 7
    || parsed.cvm_online !== true
    || parsed.attestation_error_absent !== true
    || parsed.tcb_info_present !== true
    || parsed.app_certificate_quote_present !== true
    || parsed.pre_injection_attestation_sufficient !== false) {
    fail("post-restart authenticated evidence is incomplete or weakened");
  }
  return {
    get_cvm_info_call_sequence: 6,
    get_cvm_info_observation_sha256: sha256(
      parsed.get_cvm_info_observation_sha256,
      "post-restart getCvmInfo observation",
    ),
    get_cvm_info_response_sha256: sha256(
      parsed.get_cvm_info_response_sha256,
      "post-restart getCvmInfo response",
    ),
    get_cvm_info_observed_at: second(
      parsed.get_cvm_info_observed_at,
      "post-restart getCvmInfo observed_at",
    ),
    get_cvm_attestation_call_sequence: 7,
    get_cvm_attestation_observation_sha256: sha256(
      parsed.get_cvm_attestation_observation_sha256,
      "post-restart getCvmAttestation observation",
    ),
    get_cvm_attestation_response_sha256: sha256(
      parsed.get_cvm_attestation_response_sha256,
      "post-restart getCvmAttestation response",
    ),
    get_cvm_attestation_observed_at: second(
      parsed.get_cvm_attestation_observed_at,
      "post-restart getCvmAttestation observed_at",
    ),
    cvm_online: true,
    attestation_error_absent: true,
    tcb_info_present: true,
    app_certificate_quote_present: true,
    pre_injection_attestation_sufficient: false,
  };
}

function normalizeRecipientActivation(value) {
  const parsed = exactRecord(value, [
    "activation_verification_sha256", "authenticated_at",
    "challenge_id", "expires_at", "post_restart_source_activation",
    "qvl_verdict_verifier_signature_sha256", "raw_transcript_sha256",
    "recipient_evidence_lease_expires_at",
    "recipient_key_id", "recipient_release_commitment", "report_data",
    "source_activation_sha256", "tdx_quote_sha256",
    "verdict_activation_evidence_lease_expires_at", "verified_at",
  ], "post-restart recipient activation");
  if (parsed.post_restart_source_activation !== true
    || !Number.isSafeInteger(parsed.authenticated_at)
    || !Number.isSafeInteger(parsed.verified_at)
    || !Number.isSafeInteger(parsed.expires_at)
    || !Number.isSafeInteger(parsed.recipient_evidence_lease_expires_at)
    || !Number.isSafeInteger(
      parsed.verdict_activation_evidence_lease_expires_at,
    )
    || parsed.authenticated_at < 1
    || parsed.verified_at < parsed.authenticated_at
    || parsed.expires_at <= parsed.verified_at
    || parsed.recipient_evidence_lease_expires_at < parsed.expires_at
    || parsed.verdict_activation_evidence_lease_expires_at
      !== parsed.recipient_evidence_lease_expires_at) {
    fail("recipient activation freshness boundary is invalid");
  }
  return {
    activation_verification_sha256: sha256(
      parsed.activation_verification_sha256,
      "recipient activation verification",
    ),
    source_activation_sha256: sha256(
      parsed.source_activation_sha256,
      "recipient source activation",
    ),
    raw_transcript_sha256: sha256(
      parsed.raw_transcript_sha256,
      "recipient raw transcript commitment",
    ),
    qvl_verdict_verifier_signature_sha256: sha256(
      parsed.qvl_verdict_verifier_signature_sha256,
      "recipient QVL verdict signature",
    ),
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, "recipient TDX quote"),
    challenge_id: fixed(parsed.challenge_id, BYTES32, "recipient challenge ID"),
    report_data: fixed(parsed.report_data, BYTES32, "recipient report data"),
    recipient_key_id: sha256(parsed.recipient_key_id, "recipient key ID"),
    recipient_release_commitment: sha256(
      parsed.recipient_release_commitment,
      "recipient release commitment",
    ),
    authenticated_at: parsed.authenticated_at,
    verified_at: parsed.verified_at,
    verdict_activation_evidence_lease_expires_at:
      parsed.verdict_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      parsed.recipient_evidence_lease_expires_at,
    expires_at: parsed.expires_at,
    post_restart_source_activation: true,
  };
}

export function normalizePhalaPostMeasurementActivationExecutionReceipt(value) {
  const parsed = exactRecord(value, [
    "activation_journal_sha256", "activation_journal_state_sha256",
    "adapter_identity_sha256", "allowed_environment_key_count",
    "allowed_environment_key_names_sha256", "ambiguous_outcome_quarantine_required",
    "arena_worker_presence", "arena_worker_presence_sha256",
    "automatic_retry_authorized", "batch_id", "ceremony_authorization_sha256",
    "chain_id", "ciphertext_persisted", "completed_at", "cvm_launch_intent_sha256",
    "combined_activation_verification_sha256",
    "compute_recipient_activation_sha256",
    "deployment_intent_sha256", "injected_environment_key_count",
    "initial_activation_evidence_lease_expires_at",
    "injected_environment_key_names_sha256", "live_traffic_authorized",
    "mutation_sequence", "patch", "phala_recovery_directory_identity_anchor_sha256",
    "post_measurement_activation_plan_sha256", "post_restart_evidence",
    "pre_ceremony_runtime_authority_sha256", "pre_injection_attestation_sufficient",
    "profile_activation",
    "private_environment_assembly_receipt_sha256", "raw_quote_persisted",
    "raw_secret_egress", "recipient_activation", "release_sha",
    "release_verification_authority_sha256", "restart",
    "runtime_commitment_key_names_sha256", "runtime_commitments_sha256", "schema",
    "seven_cvm_launch_completion_receipt_sha256",
    "seven_cvm_verified_evidence_set_sha256", "status", "target",
    "recipient_evidence_lease_expires_at",
    "terminal_evidence_lease_expires_at",
    "truth_status",
  ], "post-measurement activation execution receipt");
  if (parsed.schema !== PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA
    || parsed.status !== PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS
    || parsed.truth_status !== PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH
    || parsed.chain_id !== CHAIN_ID
    || typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || JSON.stringify(parsed.mutation_sequence)
      !== JSON.stringify(PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE)
    || parsed.automatic_retry_authorized !== false
    || parsed.ambiguous_outcome_quarantine_required !== true
    || parsed.pre_injection_attestation_sufficient !== false
    || parsed.raw_quote_persisted !== false
    || parsed.raw_secret_egress !== false
    || parsed.ciphertext_persisted !== false
    || parsed.live_traffic_authorized !== false) {
    fail("post-measurement activation execution truth boundary is invalid");
  }
  const patch = normalizePatch(parsed.patch);
  const restart = normalizeRestart(parsed.restart);
  const evidence = normalizePostRestartEvidence(parsed.post_restart_evidence);
  const profileActivation = exactProfileActivation(parsed.profile_activation);
  const arenaWorkerPresence =
    normalizePhalaArenaWorkerPresenceActivationProof(
      parsed.arena_worker_presence,
    );
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const activation = normalizeRecipientActivation(parsed.recipient_activation);
  const computeRecipientActivationSha256 = sha256(
    parsed.compute_recipient_activation_sha256,
    "Compute recipient activation proof",
  );
  const initialActivationEvidenceLeaseExpiresAt = positiveInteger(
    parsed.initial_activation_evidence_lease_expires_at,
    "initial activation-evidence lease expiry",
  );
  const recipientEvidenceLeaseExpiresAt = positiveInteger(
    parsed.recipient_evidence_lease_expires_at,
    "recipient evidence lease expiry",
  );
  const terminalEvidenceLeaseExpiresAt = positiveInteger(
    parsed.terminal_evidence_lease_expires_at,
    "terminal evidence lease expiry",
  );
  if (computeRecipientActivationSha256
      !== activation.activation_verification_sha256
    || parsed.arena_worker_presence_sha256 !== arenaWorkerPresenceSha256
    || parsed.combined_activation_verification_sha256
      !== phalaCombinedArenaComputeActivationVerificationSha256({
        profileActivation,
        arenaWorkerPresenceSha256,
        computeRecipientActivationSha256,
      })
    || recipientEvidenceLeaseExpiresAt
      !== activation.recipient_evidence_lease_expires_at
    || terminalEvidenceLeaseExpiresAt !== Math.min(
      initialActivationEvidenceLeaseExpiresAt,
      recipientEvidenceLeaseExpiresAt,
    )) {
    fail("activation proof digests do not bind the exact Arena and Compute proofs");
  }
  const completedAt = second(
    parsed.completed_at,
    "activation execution completed_at",
  );
  const completedAtSeconds = Math.floor(Date.parse(completedAt) / 1_000);
  if (Date.parse(patch.attempt_recorded_at) > Date.parse(patch.observed_at)
    || Date.parse(patch.observed_at) > Date.parse(restart.attempt_recorded_at)
    || Date.parse(restart.attempt_recorded_at) > Date.parse(restart.observed_at)
    || Date.parse(restart.observed_at) > Date.parse(evidence.get_cvm_info_observed_at)
    || Date.parse(evidence.get_cvm_info_observed_at)
      > Date.parse(evidence.get_cvm_attestation_observed_at)
    || arenaWorkerPresence.heartbeat_observed_at
      <= Math.floor(Date.parse(evidence.get_cvm_attestation_observed_at) / 1_000)
    || arenaWorkerPresence.verified_at
      < arenaWorkerPresence.heartbeat_observed_at
    || activation.authenticated_at
      < arenaWorkerPresence.verified_at
    || completedAtSeconds < activation.verified_at
    || completedAtSeconds >= terminalEvidenceLeaseExpiresAt
    || patch.finalized_readiness.finalized_block_number
      > restart.finalized_readiness.finalized_block_number) {
    fail("activation receipt does not prove journal-before-mutation and post-restart evidence");
  }
  const allowedCount = positiveInteger(
    parsed.allowed_environment_key_count,
    "activation allowed environment key count",
  );
  const injectedCount = positiveInteger(
    parsed.injected_environment_key_count,
    "activation injected environment key count",
  );
  if (injectedCount > allowedCount) {
    fail("activation injected environment count exceeds the reviewed allowlist");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: CHAIN_ID,
    release_sha: parsed.release_sha,
    batch_id: sha256(parsed.batch_id, "activation batch"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "activation deployment intent",
    ),
    cvm_launch_intent_sha256: sha256(
      parsed.cvm_launch_intent_sha256,
      "activation CVM launch intent",
    ),
    release_verification_authority_sha256: sha256(
      parsed.release_verification_authority_sha256,
      "activation release verification authority",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "activation seven-CVM launch completion",
    ),
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "activation seven-CVM verified evidence set",
    ),
    phala_recovery_directory_identity_anchor_sha256: sha256(
      parsed.phala_recovery_directory_identity_anchor_sha256,
      "activation recovery-directory identity anchor",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "activation pre-ceremony runtime authority",
    ),
    post_measurement_activation_plan_sha256: sha256(
      parsed.post_measurement_activation_plan_sha256,
      "activation plan",
    ),
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "signed ceremony authorization",
    ),
    target: normalizeTarget(parsed.target),
    profile_activation: profileActivation,
    runtime_commitments_sha256: sha256(
      parsed.runtime_commitments_sha256,
      "activation runtime commitments",
    ),
    runtime_commitment_key_names_sha256: sha256(
      parsed.runtime_commitment_key_names_sha256,
      "activation runtime commitment key names",
    ),
    allowed_environment_key_names_sha256: sha256(
      parsed.allowed_environment_key_names_sha256,
      "activation allowed environment key names",
    ),
    allowed_environment_key_count: allowedCount,
    injected_environment_key_names_sha256: sha256(
      parsed.injected_environment_key_names_sha256,
      "activation injected environment key names",
    ),
    injected_environment_key_count: injectedCount,
    private_environment_assembly_receipt_sha256: sha256(
      parsed.private_environment_assembly_receipt_sha256,
      "activation private assembly receipt",
    ),
    adapter_identity_sha256: sha256(
      parsed.adapter_identity_sha256,
      "activation pinned SDK adapter identity",
    ),
    activation_journal_state_sha256: sha256(
      parsed.activation_journal_state_sha256,
      "activation durable journal state",
    ),
    activation_journal_sha256: sha256(
      parsed.activation_journal_sha256,
      "activation durable journal",
    ),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch,
    restart,
    post_restart_evidence: evidence,
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: activation,
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      parsed.combined_activation_verification_sha256,
    initial_activation_evidence_lease_expires_at:
      initialActivationEvidenceLeaseExpiresAt,
    recipient_evidence_lease_expires_at: recipientEvidenceLeaseExpiresAt,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpiresAt,
    completed_at: completedAt,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  }, { label: "normalized post-measurement activation execution receipt" });
}

export function canonicalPhalaPostMeasurementActivationExecutionReceiptText(value) {
  return canonicalText(normalizePhalaPostMeasurementActivationExecutionReceipt(value));
}

export function phalaPostMeasurementRuntimeCommitmentsSha256(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "post-measurement runtime commitments",
  });
  if (!isRecord(value)) {
    fail("runtime commitments must be an object");
  }
  for (const [key, entry] of Object.entries(value)) {
    if (!/^[A-Z][A-Z0-9_]{0,127}$/.test(key) || typeof entry !== "string") {
      fail("runtime commitments are not canonical environment entries");
    }
  }
  return domainDigest(PHALA_POST_MEASUREMENT_RUNTIME_COMMITMENTS_DOMAIN, value);
}

export function phalaPostMeasurementActivationExecutionReceiptSha256(value) {
  return domainDigest(
    PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_DOMAIN,
    normalizePhalaPostMeasurementActivationExecutionReceipt(value),
  );
}
