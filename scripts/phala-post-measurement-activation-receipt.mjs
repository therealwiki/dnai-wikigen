import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
} from "./cvm-launch-intent-core.mjs";
import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  normalizePhalaPostMeasurementActivationPlan,
  phalaPostMeasurementActivationPlanSha256,
  readPhalaPostMeasurementActivationPlanDependencies,
} from "./phala-post-measurement-activation.mjs";
import {
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  normalizePhalaArenaWorkerPresenceActivationProof as
    normalizePhalaArenaWorkerPresenceActivationProofCore,
  phalaArenaWorkerPresenceActivationProofSha256 as
    phalaArenaWorkerPresenceActivationProofCoreSha256,
  phalaCombinedArenaComputeActivationVerificationSha256 as
    phalaCombinedArenaComputeActivationVerificationCoreSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal,
  normalizePhalaPostMeasurementActivationJournal,
  normalizePhalaPostMeasurementActivationState,
  phalaPostMeasurementActivationJournalSha256,
  phalaPostMeasurementActivationStateSha256,
  projectPhalaPostMeasurementActivationJournal,
} from "./phala-post-measurement-activation-journal.mjs";
import {
  assertFreshBrandedPreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  assertAuthenticatedPhalaSdkObservation,
  authenticatedPhalaSdkObservationSha256,
  encryptExactEnvironmentWithPinnedDstack,
  phalaAuthenticatedSdkRequestSemanticsSha256,
  pinnedPhalaProductionSdkAdapterIdentitySha256,
  readAuthenticatedPhalaSdkObservationResponse,
} from "./phala-production-sdk-adapter.mjs";
import {
  assertProductionPhalaComputeWorkloadRecipientActivation,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  ceremonyAuthorizationCoreSha256,
  normalizeCeremonyAuthorizationCore,
} from "./release-ceremony-authorization.mjs";
import {
  assertPrivatePostMeasurementEnvironmentAssemblyReceipt,
  privatePostMeasurementEnvironmentAssemblyReceipt,
  privatePostMeasurementEnvironmentEntries,
} from "./phala-production-environment-authority.mjs";
import {
  assertFreshProductionFinalizedReadiness,
  productionFinalizedReadinessSha256,
} from "./phala-production-finalized-readiness.mjs";
import {
  readReviewedFinalAuthorityRuntimeDependencies,
} from "./reviewed-final-authority-runtime.mjs";

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
export const PHALA_POST_MEASUREMENT_PRIVATE_ASSEMBLY_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-private-post-measurement-environment-assembly-receipt/v2\0";
export const PHALA_COMPUTE_WORKLOAD_OBSERVATION_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-compute-workload-observation-authority/v1\0";
export const PHALA_ARENA_WORKER_RELEASE_BINDING_SCHEMA =
  "dnai.arena.safe-worker-release-binding.v1";
export const PHALA_ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA =
  "dnai.arena.safe-worker-presence-binding.v1";
export const PHALA_ARENA_WORKER_RELEASE_BINDING_DOMAIN =
  "dnai-wikigen/arena-worker-release-binding/v1\0";
export const PHALA_ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN =
  "dnai-wikigen/arena-worker-presence-binding/v1\0";
export const PHALA_ARENA_WORKER_ENDPOINT_COMMITMENT_DOMAIN =
  "dnai-wikigen/arena-worker-presence-endpoint/v1\0";
export const PHALA_ARENA_SAFE_IR_RUNTIME_POLICY_COMMITMENT =
  "sha256:9fcffd04eeece1398970e4a144807df95f31408b2337d71cc8377048b2ec114e";
export const PHALA_ARENA_WORKER_LIVE_CAPABILITY_WARNING =
  "Fresh authenticated worker presence matches the exact release pins. This heartbeat is not TDX evidence; every job still requires its independent quote, QVL, registry, and execution-policy gates.";
export const PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS = Object.freeze([
  "surface",
  "schema_version",
  "challenge_id",
  "challenge_version",
  "status",
  "backend",
  "isolation",
  "live_execution",
  "worker_connected",
  "safe_ir_execution_ready",
  "hostile_general_code_ready",
  "python_preview_live",
  "freshness",
  "evidence_authenticity",
  "evidence_classification",
  "gate_reason",
  "heartbeat_observed_at",
  "heartbeat_binding_sha256",
  "release_binding_sha256",
  "release_binding",
  "warning",
  "product_status",
  "exact_timing_egress",
  "internal_error_egress",
  "raw_candidate_egress",
  "tdx_attestation_egress",
]);
export {
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
};

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
const RECEIPTS = new WeakMap();
const RECEIPT_PREFLIGHTS = new WeakMap();
const ARENA_WORKER_PRESENCE_PROOFS = new WeakMap();
const MUTATION_READINESS_PROJECTIONS = new WeakMap();
const PRIVATE_ENCRYPTED_UPDATES = new WeakMap();
const MAX_ARENA_WORKER_RESPONSE_BYTES = 64 * 1024;
const MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS = 300;
const MAX_ARENA_WORKER_CLOCK_SKEW_SECONDS = 5;
const CAPTURED_NATIVE_FETCH = globalThis.fetch;

export const PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_PREPARE_FIELDS =
  Object.freeze([
    "plan",
    "preCeremonyRuntimeAuthority",
    "ceremonyAuthorization",
    "ceremonyAuthorizationDependencies",
    "privateEnvironmentAssemblyReceipt",
    "privateEncryptedUpdate",
    "adapter",
    "observations",
    "patchFinalizedReadiness",
    "restartFinalizedReadiness",
    "arenaWorkerPresence",
    "recipientActivation",
    "proposedCompletedState",
    "projectedJournal",
  ]);
export const PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_FINALIZE_FIELDS =
  Object.freeze([
    "preflightToken",
    "journal",
    "journalDirectory",
    "journalState",
    "journalLock",
  ]);

export const PHALA_PRIVATE_POST_MEASUREMENT_ENCRYPTED_UPDATE_SCHEMA =
  "dnai.phala-private-post-measurement-encrypted-update.v1";

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
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

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(JSON.stringify(sortedObject(value)), "utf8")
    .digest("hex")}`;
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
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function normalizeProfileActivation(value) {
  const parsed = exactRecord(value, [
    "profile_names",
    "compose_profiles_value",
  ], "activation execution profile set");
  if (JSON.stringify(parsed.profile_names)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES)
    || parsed.compose_profiles_value
      !== CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE) {
    throw new Error(
      "activation execution profile set is omitted, reordered, substituted, or widened",
    );
  }
  return {
    profile_names: [...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES],
    compose_profiles_value: CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
}

export function normalizePhalaArenaWorkerPresenceActivationProof(value) {
  return normalizePhalaArenaWorkerPresenceActivationProofCore(value);
}

export function phalaArenaWorkerPresenceActivationProofSha256(value) {
  return phalaArenaWorkerPresenceActivationProofCoreSha256(value);
}

export function phalaCombinedArenaComputeActivationVerificationSha256(value) {
  return phalaCombinedArenaComputeActivationVerificationCoreSha256(value);
}

function canonicalArenaWorkerEndpoint(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Arena worker presence endpoint must be an absolute HTTPS URL");
  }
  if (parsed.protocol !== "https:"
    || parsed.username !== ""
    || parsed.password !== ""
    || parsed.hash !== ""
    || parsed.search !== ""
    || parsed.pathname === "/"
    || parsed.href !== value) {
    throw new Error("Arena worker presence endpoint is not canonical bounded HTTPS");
  }
  return parsed.href;
}

export function phalaArenaWorkerPresenceEndpointCommitmentSha256(value) {
  return digest(PHALA_ARENA_WORKER_ENDPOINT_COMMITMENT_DOMAIN, {
    endpoint: canonicalArenaWorkerEndpoint(value),
  });
}

function normalizeArenaWorkerReleaseBinding(value, {
  challengeId,
  challengeVersion,
} = {}) {
  const parsed = exactRecord(value, [
    "release_sha",
    "image_digest",
    "release_manifest_sha256",
    "approved_challenge_set_sha256",
    "approved_challenge_key",
    "release_policy_commitment",
    "catalog_manifest_hash",
    "runtime",
    "runtime_policy_commitment",
    "compose_hash",
    "app_id",
    "os_image_hash",
  ], "Arena worker release binding");
  const expectedChallengeKey = `${challengeId}@${challengeVersion}`;
  if (parsed.approved_challenge_key !== expectedChallengeKey
    || parsed.runtime !== "dnai-safe-ir-v1"
    || parsed.runtime_policy_commitment
      !== PHALA_ARENA_SAFE_IR_RUNTIME_POLICY_COMMITMENT) {
    throw new Error("Arena worker release binding is not the requested safe-IR release");
  }
  return {
    release_sha: exactString(parsed.release_sha, SHA40, "Arena worker release SHA"),
    image_digest: sha256(parsed.image_digest, "Arena worker image digest"),
    release_manifest_sha256: sha256(
      parsed.release_manifest_sha256,
      "Arena worker release manifest",
    ),
    approved_challenge_set_sha256: sha256(
      parsed.approved_challenge_set_sha256,
      "Arena worker approved challenge set",
    ),
    approved_challenge_key: expectedChallengeKey,
    release_policy_commitment: exactString(
      parsed.release_policy_commitment,
      BYTES32,
      "Arena worker release policy commitment",
    ),
    catalog_manifest_hash: exactString(
      parsed.catalog_manifest_hash,
      BARE_SHA256,
      "Arena worker catalog manifest hash",
    ),
    runtime: "dnai-safe-ir-v1",
    runtime_policy_commitment:
      PHALA_ARENA_SAFE_IR_RUNTIME_POLICY_COMMITMENT,
    compose_hash: exactString(
      parsed.compose_hash,
      BARE_SHA256,
      "Arena worker compose hash",
    ),
    app_id: exactString(parsed.app_id, APP_ID, "Arena worker app ID"),
    os_image_hash: exactString(
      parsed.os_image_hash,
      BARE_SHA256,
      "Arena worker OS image hash",
    ),
  };
}

export function phalaArenaWorkerReleaseBindingSha256(value, {
  challengeId,
  challengeVersion,
} = {}) {
  const normalizedChallengeId = exactString(
    challengeId,
    CHALLENGE_ID,
    "Arena worker challenge ID",
  );
  const normalizedChallengeVersion = exactString(
    challengeVersion,
    CHALLENGE_VERSION,
    "Arena worker challenge version",
  );
  return digest(PHALA_ARENA_WORKER_RELEASE_BINDING_DOMAIN, {
    schema: PHALA_ARENA_WORKER_RELEASE_BINDING_SCHEMA,
    release_binding: normalizeArenaWorkerReleaseBinding(value, {
      challengeId: normalizedChallengeId,
      challengeVersion: normalizedChallengeVersion,
    }),
  });
}

export function phalaArenaWorkerHeartbeatBindingSha256({
  challengeId,
  challengeVersion,
  heartbeatObservedAt,
  releaseBindingSha256,
} = {}) {
  const normalizedChallengeId = exactString(
    challengeId,
    CHALLENGE_ID,
    "Arena worker heartbeat challenge ID",
  );
  const normalizedChallengeVersion = exactString(
    challengeVersion,
    CHALLENGE_VERSION,
    "Arena worker heartbeat challenge version",
  );
  if (!Number.isSafeInteger(heartbeatObservedAt) || heartbeatObservedAt < 1) {
    throw new Error("Arena worker heartbeat observed_at must be a positive second");
  }
  return digest(PHALA_ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN, {
    schema: PHALA_ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    challenge_id: normalizedChallengeId,
    challenge_version: normalizedChallengeVersion,
    heartbeat_observed_at: heartbeatObservedAt,
    release_binding_sha256: sha256(
      releaseBindingSha256,
      "Arena worker heartbeat release binding",
    ),
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  });
}

function normalizeLiveArenaWorkerCapability(value, {
  challengeId,
  challengeVersion,
  expectedReleaseBindingSha256,
  checkedAt,
} = {}) {
  const parsed = exactRecord(
    value,
    PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS,
    "Arena worker live capability response",
  );
  if (parsed.surface !== "arena_worker_capability"
    || parsed.schema_version !== 2
    || parsed.challenge_id !== challengeId
    || parsed.challenge_version !== challengeVersion
    || parsed.status !== "live"
    || parsed.backend !== "release_bound_safe_ir_worker"
    || parsed.isolation !== "independent_job_gate_required"
    || parsed.live_execution !== true
    || parsed.worker_connected !== true
    || parsed.safe_ir_execution_ready !== true
    || parsed.hostile_general_code_ready !== false
    || parsed.python_preview_live !== false
    || parsed.freshness !== "fresh"
    || parsed.evidence_authenticity !== "hmac_verified"
    || parsed.evidence_classification
      !== PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION
    || parsed.gate_reason !== "ready"
    || parsed.product_status !== "live"
    || parsed.exact_timing_egress !== false
    || parsed.internal_error_egress !== false
    || parsed.raw_candidate_egress !== false
    || parsed.tdx_attestation_egress !== false
    || parsed.warning !== PHALA_ARENA_WORKER_LIVE_CAPABILITY_WARNING
    || !Number.isSafeInteger(parsed.heartbeat_observed_at)
    || parsed.heartbeat_observed_at < 1
    || parsed.heartbeat_observed_at > checkedAt + MAX_ARENA_WORKER_CLOCK_SKEW_SECONDS
    || checkedAt - parsed.heartbeat_observed_at
      > MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS) {
    throw new Error(
      "Arena worker capability is not fresh authenticated safe-IR presence",
    );
  }
  const releaseBindingSha256 = phalaArenaWorkerReleaseBindingSha256(
    parsed.release_binding,
    { challengeId, challengeVersion },
  );
  if (parsed.release_binding_sha256 !== releaseBindingSha256
    || releaseBindingSha256 !== expectedReleaseBindingSha256
    || parsed.heartbeat_binding_sha256
      !== phalaArenaWorkerHeartbeatBindingSha256({
        challengeId,
        challengeVersion,
        heartbeatObservedAt: parsed.heartbeat_observed_at,
        releaseBindingSha256,
      })) {
    throw new Error("Arena worker capability binding digests drifted");
  }
  return {
    heartbeat_observed_at: parsed.heartbeat_observed_at,
    release_binding_sha256: releaseBindingSha256,
    heartbeat_binding_sha256: parsed.heartbeat_binding_sha256,
  };
}

/**
 * Fetch and reduce the exact public Arena capability response. The endpoint's
 * v2 response is authenticated to the expected HTTPS authority and reports a
 * fresh HMAC-verified heartbeat. Only hashes and bounded public facts survive
 * this function; URL, response bytes, heartbeat MAC, and key material do not.
 */
export async function verifyProductionPhalaArenaWorkerPresenceActivation({
  endpoint,
  expectedEndpointCommitmentSha256,
  expectedReleaseBindingSha256,
  challengeId,
  challengeVersion,
} = {}) {
  const canonicalEndpoint = canonicalArenaWorkerEndpoint(endpoint);
  const endpointCommitmentSha256 =
    phalaArenaWorkerPresenceEndpointCommitmentSha256(canonicalEndpoint);
  if (endpointCommitmentSha256 !== sha256(
    expectedEndpointCommitmentSha256,
    "expected Arena worker endpoint commitment",
  )) {
    throw new Error("Arena worker endpoint differs from reviewed authority");
  }
  const normalizedExpectedReleaseBindingSha256 = sha256(
    expectedReleaseBindingSha256,
    "expected Arena worker release binding",
  );
  const normalizedChallengeId = exactString(
    challengeId,
    CHALLENGE_ID,
    "Arena worker challenge ID",
  );
  const normalizedChallengeVersion = exactString(
    challengeVersion,
    CHALLENGE_VERSION,
    "Arena worker challenge version",
  );
  if (typeof CAPTURED_NATIVE_FETCH !== "function") {
    throw new Error("the native HTTPS fetch implementation is unavailable");
  }
  const response = await CAPTURED_NATIVE_FETCH(canonicalEndpoint, {
    method: "GET",
    redirect: "error",
    headers: Object.freeze({ accept: "application/json" }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response || response.ok !== true || response.status !== 200
    || response.redirected !== false || response.url !== canonicalEndpoint
    || typeof response.arrayBuffer !== "function"
    || typeof response.headers?.get !== "function"
    || response.headers.get("content-type") !== "application/json"
    || ![null, "identity"].includes(response.headers.get("content-encoding"))) {
    throw new Error("Arena worker capability endpoint did not return exact HTTPS 200 evidence");
  }
  const responseBytes = Buffer.from(await response.arrayBuffer());
  if (responseBytes.length < 2
    || responseBytes.length > MAX_ARENA_WORKER_RESPONSE_BYTES) {
    throw new Error("Arena worker capability response exceeds its byte boundary");
  }
  let parsed;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(responseBytes);
    if ([...responseBytes].some((byte) => byte > 0x7f)) {
      throw new Error("Arena worker capability response is not ASCII");
    }
    parsed = JSON.parse(text);
    if (text !== JSON.stringify(parsed)) {
      throw new Error(
        "Arena worker capability response is not canonical compact duplicate-free JSON",
      );
    }
  } catch {
    throw new Error(
      "Arena worker capability response is not canonical compact duplicate-free ASCII JSON",
    );
  }
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null
    && (!/^(0|[1-9][0-9]*)$/.test(contentLength)
      || Number(contentLength) !== responseBytes.length)) {
    throw new Error("Arena worker capability content length differs from response bytes");
  }
  const verifiedAt = Math.floor(Date.now() / 1_000);
  const capability = normalizeLiveArenaWorkerCapability(parsed, {
    challengeId: normalizedChallengeId,
    challengeVersion: normalizedChallengeVersion,
    expectedReleaseBindingSha256:
      normalizedExpectedReleaseBindingSha256,
    checkedAt: verifiedAt,
  });
  const responseSha256 = `sha256:${createHash("sha256")
    .update(responseBytes)
    .digest("hex")}`;
  const proof = Object.freeze(normalizePhalaArenaWorkerPresenceActivationProof({
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: endpointCommitmentSha256,
    challenge_id: normalizedChallengeId,
    challenge_version: normalizedChallengeVersion,
    response_sha256: responseSha256,
    release_binding_sha256: capability.release_binding_sha256,
    heartbeat_observed_at: capability.heartbeat_observed_at,
    verified_at: verifiedAt,
  }));
  ARENA_WORKER_PRESENCE_PROOFS.set(proof, Object.freeze({
    endpoint_commitment_sha256: endpointCommitmentSha256,
    response_sha256: responseSha256,
    release_binding_sha256: capability.release_binding_sha256,
    heartbeat_binding_sha256: capability.heartbeat_binding_sha256,
  }));
  return proof;
}

export function assertFreshProductionPhalaArenaWorkerPresenceActivationProof(value) {
  const provenance = value && ARENA_WORKER_PRESENCE_PROOFS.get(value);
  const proof = normalizePhalaArenaWorkerPresenceActivationProof(value);
  const now = Math.floor(Date.now() / 1_000);
  if (!provenance
    || canonicalText(proof) !== canonicalText(value)
    || proof.endpoint_commitment_sha256
      !== provenance.endpoint_commitment_sha256
    || proof.response_sha256 !== provenance.response_sha256
    || proof.release_binding_sha256 !== provenance.release_binding_sha256
    || proof.verified_at > now + MAX_ARENA_WORKER_CLOCK_SKEW_SECONDS
    || now - proof.heartbeat_observed_at
      > MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS
    || now - proof.verified_at > MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS) {
    throw new Error(
      "a fresh locally verified Arena worker presence activation proof is required",
    );
  }
  return value;
}

function normalizeTarget(value) {
  const parsed = exactRecord(value, [
    "domain",
    "descriptor_sha256",
    "app_id",
    "cvm_id",
    "compose_hash",
    "os_image_hash",
  ], "activation execution target");
  if (parsed.domain !== "main_runtime_cvm") {
    throw new Error("activation execution target is not main runtime");
  }
  return {
    domain: "main_runtime_cvm",
    descriptor_sha256: sha256(parsed.descriptor_sha256, "main descriptor"),
    app_id: exactString(parsed.app_id, APP_ID, "main app ID"),
    cvm_id: exactString(parsed.cvm_id, CVM_ID, "main CVM ID"),
    compose_hash: exactString(parsed.compose_hash, BARE_SHA256, "main compose hash"),
    os_image_hash: exactString(parsed.os_image_hash, BARE_SHA256, "main OS image hash"),
  };
}

function normalizeFinalizedReadiness(value, label) {
  const parsed = exactRecord(value, [
    "readiness_sha256",
    "finalized_block_number",
    "finalized_block_hash",
  ], label);
  return {
    readiness_sha256: sha256(parsed.readiness_sha256, `${label} readiness`),
    finalized_block_number: exactPositiveInteger(
      parsed.finalized_block_number,
      `${label} finalized block number`,
    ),
    finalized_block_hash: exactString(
      parsed.finalized_block_hash,
      BYTES32,
      `${label} finalized block hash`,
    ),
  };
}

export function projectProductionPhalaPostMeasurementMutationReadiness({
  readiness: readinessValue,
  action,
  activationPlanSha256,
  preCeremonyRuntimeAuthoritySha256,
  ceremonyAuthorizationSha256,
} = {}) {
  if (!["updateCvmEnvs", "restartCvm"].includes(action)) {
    throw new Error("post-measurement readiness action is not an exact mutation");
  }
  const readiness = assertFreshProductionFinalizedReadiness(readinessValue);
  const projection = Object.freeze(normalizeFinalizedReadiness({
    readiness_sha256: productionFinalizedReadinessSha256(readiness),
    finalized_block_number: readiness.common_finalized_block_number,
    finalized_block_hash: readiness.common_finalized_block_hash,
  }, `${action} finalized readiness`));
  MUTATION_READINESS_PROJECTIONS.set(projection, Object.freeze({
    action,
    activation_plan_sha256: sha256(
      activationPlanSha256,
      "mutation-readiness activation plan",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      preCeremonyRuntimeAuthoritySha256,
      "mutation-readiness pre-ceremony runtime authority",
    ),
    ceremony_authorization_sha256: sha256(
      ceremonyAuthorizationSha256,
      "mutation-readiness signed B",
    ),
  }));
  return projection;
}

function assertProductionMutationReadinessProjection(value, {
  action,
  activationPlanSha256,
  preCeremonyRuntimeAuthoritySha256,
  ceremonyAuthorizationSha256,
} = {}) {
  const provenance = value && MUTATION_READINESS_PROJECTIONS.get(value);
  if (!provenance || provenance.action !== action
    || provenance.activation_plan_sha256 !== activationPlanSha256
    || provenance.pre_ceremony_runtime_authority_sha256
      !== preCeremonyRuntimeAuthoritySha256
    || provenance.ceremony_authorization_sha256 !== ceremonyAuthorizationSha256) {
    throw new Error("a fresh lineage-bound dual-RPC mutation readiness projection is required");
  }
  normalizeFinalizedReadiness(value, `${action} finalized readiness`);
  return value;
}

function normalizePatch(value) {
  const parsed = exactRecord(value, [
    "sdk_action",
    "call_sequence",
    "request_semantics_sha256",
    "observation_sha256",
    "response_sha256",
    "body_field_names",
    "encrypted_environment_only",
    "allowed_environment_keys_mutated",
    "attempt_recorded_at",
    "observed_at",
    "finalized_readiness",
  ], "activation PATCH receipt");
  if (parsed.sdk_action !== "updateCvmEnvs"
    || parsed.call_sequence !== 4
    || JSON.stringify(parsed.body_field_names) !== JSON.stringify(["encrypted_env"])
    || parsed.encrypted_environment_only !== true
    || parsed.allowed_environment_keys_mutated !== false) {
    throw new Error("activation PATCH receipt is widened or reordered");
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
    attempt_recorded_at: exactSecond(
      parsed.attempt_recorded_at,
      "PATCH durable-attempt time",
    ),
    observed_at: exactSecond(parsed.observed_at, "PATCH observed_at"),
    finalized_readiness: normalizeFinalizedReadiness(
      parsed.finalized_readiness,
      "PATCH finalized readiness",
    ),
  };
}

function normalizeRestart(value) {
  const parsed = exactRecord(value, [
    "sdk_action",
    "call_sequence",
    "request_semantics_sha256",
    "observation_sha256",
    "response_sha256",
    "force",
    "attempt_recorded_at",
    "observed_at",
    "finalized_readiness",
  ], "activation restart receipt");
  if (parsed.sdk_action !== "restartCvm"
    || parsed.call_sequence !== 5
    || parsed.force !== false) {
    throw new Error("activation restart receipt is widened or reordered");
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
    attempt_recorded_at: exactSecond(
      parsed.attempt_recorded_at,
      "restart durable-attempt time",
    ),
    observed_at: exactSecond(parsed.observed_at, "restart observed_at"),
    finalized_readiness: normalizeFinalizedReadiness(
      parsed.finalized_readiness,
      "restart finalized readiness",
    ),
  };
}

function normalizePostRestartEvidence(value) {
  const parsed = exactRecord(value, [
    "get_cvm_info_call_sequence",
    "get_cvm_info_observation_sha256",
    "get_cvm_info_response_sha256",
    "get_cvm_info_observed_at",
    "get_cvm_attestation_call_sequence",
    "get_cvm_attestation_observation_sha256",
    "get_cvm_attestation_response_sha256",
    "get_cvm_attestation_observed_at",
    "cvm_online",
    "attestation_error_absent",
    "tcb_info_present",
    "app_certificate_quote_present",
    "pre_injection_attestation_sufficient",
  ], "post-restart Phala evidence");
  if (parsed.get_cvm_info_call_sequence !== 6
    || parsed.get_cvm_attestation_call_sequence !== 7
    || parsed.cvm_online !== true
    || parsed.attestation_error_absent !== true
    || parsed.tcb_info_present !== true
    || parsed.app_certificate_quote_present !== true
    || parsed.pre_injection_attestation_sufficient !== false) {
    throw new Error("post-restart authenticated evidence is incomplete or weakened");
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
    get_cvm_info_observed_at: exactSecond(
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
    get_cvm_attestation_observed_at: exactSecond(
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
    "activation_verification_sha256",
    "source_activation_sha256",
    "raw_transcript_sha256",
    "qvl_verdict_verifier_signature_sha256",
    "tdx_quote_sha256",
    "challenge_id",
    "report_data",
    "recipient_key_id",
    "recipient_release_commitment",
    "authenticated_at",
    "verified_at",
    "verdict_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "expires_at",
    "post_restart_source_activation",
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
    throw new Error("recipient activation freshness boundary is invalid");
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
    challenge_id: exactString(parsed.challenge_id, BYTES32, "recipient challenge ID"),
    report_data: exactString(parsed.report_data, BYTES32, "recipient report data"),
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

export function phalaPostMeasurementRuntimeCommitmentsSha256(value) {
  if (!isRecord(value)) throw new Error("runtime commitments must be an object");
  for (const [key, entry] of Object.entries(value)) {
    if (typeof key !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(key)
      || typeof entry !== "string") {
      throw new Error("runtime commitments are not canonical environment entries");
    }
  }
  return digest(PHALA_POST_MEASUREMENT_RUNTIME_COMMITMENTS_DOMAIN, value);
}

export function phalaPrivatePostMeasurementAssemblyReceiptSha256(value) {
  if (!isRecord(value)) throw new Error("private assembly receipt is not an object");
  return digest(PHALA_POST_MEASUREMENT_PRIVATE_ASSEMBLY_RECEIPT_DOMAIN, value);
}

export async function createPrivatePostMeasurementEncryptedUpdate({
  assembly,
  pinnedDstackIdentity,
  publicKey,
  activationPlanSha256,
  targetCvmId,
} = {}) {
  const assemblyReceipt = privatePostMeasurementEnvironmentAssemblyReceipt(assembly);
  const entriesObject = privatePostMeasurementEnvironmentEntries(assembly);
  const entries = Object.keys(entriesObject).sort().map((key) => ({
    key,
    value: entriesObject[key],
  }));
  const ciphertext = await encryptExactEnvironmentWithPinnedDstack({
    identity: pinnedDstackIdentity,
    entries,
    publicKey,
  });
  const handle = Object.freeze({
    schema: PHALA_PRIVATE_POST_MEASUREMENT_ENCRYPTED_UPDATE_SCHEMA,
    activation_plan_sha256: sha256(
      activationPlanSha256,
      "private encrypted-update activation plan",
    ),
    private_environment_assembly_receipt_sha256:
      phalaPrivatePostMeasurementAssemblyReceiptSha256(assemblyReceipt),
    target_cvm_id: exactString(
      targetCvmId,
      CVM_ID,
      "private encrypted-update target CVM",
    ),
    environment_key_names_sha256: assemblyReceipt.environment_key_names_sha256,
    value_count: assemblyReceipt.value_count,
    ciphertext_exposed_in_handle: false,
    ciphertext_persisted: false,
    patch_observation_registered: false,
  });
  PRIVATE_ENCRYPTED_UPDATES.set(handle, {
    ciphertext,
    registered: false,
    patch_observation_sha256: null,
    patch_request_semantics_sha256: null,
  });
  return handle;
}

export function readPrivatePostMeasurementEncryptedUpdateCiphertext(value) {
  const privateState = value && PRIVATE_ENCRYPTED_UPDATES.get(value);
  if (!privateState || privateState.registered || typeof privateState.ciphertext !== "string") {
    throw new Error("an unregistered local private encrypted update is required");
  }
  return privateState.ciphertext;
}

export function destroyPrivatePostMeasurementEncryptedUpdate(value) {
  const privateState = value && PRIVATE_ENCRYPTED_UPDATES.get(value);
  if (!privateState) return;
  privateState.ciphertext = null;
  PRIVATE_ENCRYPTED_UPDATES.delete(value);
}

export function registerPrivatePostMeasurementEncryptedUpdateObservation({
  encryptedUpdate,
  adapter,
  patchObservation,
} = {}) {
  const privateState = encryptedUpdate
    && PRIVATE_ENCRYPTED_UPDATES.get(encryptedUpdate);
  if (!privateState || privateState.registered
    || typeof privateState.ciphertext !== "string") {
    throw new Error("an unregistered private encrypted update is required");
  }
  const observation = assertAuthenticatedPhalaSdkObservation(patchObservation, {
    adapter,
    method: "updateCvmEnvs",
    domain: "main_runtime_cvm",
  });
  const expectedSemantics = phalaAuthenticatedSdkRequestSemanticsSha256({
    httpMethod: "PATCH",
    pathAndQuery: `/api/v1/cvms/${encryptedUpdate.target_cvm_id}/envs`,
    body: { encrypted_env: privateState.ciphertext },
  });
  if (observation.request_semantics_sha256 !== expectedSemantics) {
    throw new Error("observed PATCH ciphertext differs from the private exact assembly encryption");
  }
  privateState.registered = true;
  privateState.patch_observation_sha256 =
    authenticatedPhalaSdkObservationSha256(observation, {
      adapter,
      method: "updateCvmEnvs",
      domain: "main_runtime_cvm",
    });
  privateState.patch_request_semantics_sha256 = expectedSemantics;
  privateState.ciphertext = null;
  return encryptedUpdate;
}

function assertRegisteredPrivatePostMeasurementEncryptedUpdate(value, {
  activationPlanSha256,
  assemblyReceiptSha256,
  targetCvmId,
  patchObservationSha256,
  patchRequestSemanticsSha256,
} = {}) {
  const privateState = value && PRIVATE_ENCRYPTED_UPDATES.get(value);
  if (!privateState || privateState.registered !== true
    || privateState.ciphertext !== null
    || value.activation_plan_sha256 !== activationPlanSha256
    || value.private_environment_assembly_receipt_sha256 !== assemblyReceiptSha256
    || value.target_cvm_id !== targetCvmId
    || privateState.patch_observation_sha256 !== patchObservationSha256
    || privateState.patch_request_semantics_sha256 !== patchRequestSemanticsSha256) {
    throw new Error("a registered assembly-bound encrypted PATCH observation is required");
  }
  return value;
}

export function normalizePhalaPostMeasurementActivationExecutionReceipt(value) {
  const parsed = exactRecord(value, [
    "schema",
    "status",
    "truth_status",
    "chain_id",
    "release_sha",
    "batch_id",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "post_measurement_activation_plan_sha256",
    "ceremony_authorization_sha256",
    "target",
    "runtime_commitments_sha256",
    "runtime_commitment_key_names_sha256",
    "allowed_environment_key_names_sha256",
    "allowed_environment_key_count",
    "arena_worker_presence",
    "arena_worker_presence_sha256",
    "injected_environment_key_names_sha256",
    "injected_environment_key_count",
    "private_environment_assembly_receipt_sha256",
    "adapter_identity_sha256",
    "activation_journal_state_sha256",
    "activation_journal_sha256",
    "mutation_sequence",
    "patch",
    "restart",
    "post_restart_evidence",
    "recipient_activation",
    "compute_recipient_activation_sha256",
    "combined_activation_verification_sha256",
    "initial_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "terminal_evidence_lease_expires_at",
    "profile_activation",
    "completed_at",
    "automatic_retry_authorized",
    "ambiguous_outcome_quarantine_required",
    "pre_injection_attestation_sufficient",
    "raw_quote_persisted",
    "raw_secret_egress",
    "ciphertext_persisted",
    "live_traffic_authorized",
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
    throw new Error("post-measurement activation execution truth boundary is invalid");
  }
  const patch = normalizePatch(parsed.patch);
  const restart = normalizeRestart(parsed.restart);
  const evidence = normalizePostRestartEvidence(parsed.post_restart_evidence);
  const profileActivation = normalizeProfileActivation(parsed.profile_activation);
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
  const initialActivationEvidenceLeaseExpiresAt = exactPositiveInteger(
    parsed.initial_activation_evidence_lease_expires_at,
    "initial activation-evidence lease expiry",
  );
  const recipientEvidenceLeaseExpiresAt = exactPositiveInteger(
    parsed.recipient_evidence_lease_expires_at,
    "recipient evidence lease expiry",
  );
  const terminalEvidenceLeaseExpiresAt = exactPositiveInteger(
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
    throw new Error(
      "activation proof digests do not bind the exact Arena and Compute proofs",
    );
  }
  const completedAt = exactSecond(parsed.completed_at, "activation execution completed_at");
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
    || Math.floor(Date.parse(completedAt) / 1_000) < activation.verified_at
    || Math.floor(Date.parse(completedAt) / 1_000)
      >= terminalEvidenceLeaseExpiresAt
    || patch.finalized_readiness.finalized_block_number
      > restart.finalized_readiness.finalized_block_number) {
    throw new Error("activation receipt does not prove journal-before-mutation and post-restart evidence");
  }
  const allowedCount = exactPositiveInteger(
    parsed.allowed_environment_key_count,
    "activation allowed environment key count",
  );
  const injectedCount = exactPositiveInteger(
    parsed.injected_environment_key_count,
    "activation injected environment key count",
  );
  if (injectedCount > allowedCount) {
    throw new Error("activation injected environment count exceeds the reviewed allowlist");
  }
  return {
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
  };
}

export function canonicalPhalaPostMeasurementActivationExecutionReceiptText(value) {
  return canonicalText(normalizePhalaPostMeasurementActivationExecutionReceipt(value));
}

export function phalaPostMeasurementActivationExecutionReceiptSha256(value) {
  return digest(
    PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_DOMAIN,
    normalizePhalaPostMeasurementActivationExecutionReceipt(value),
  );
}

function exactObservationProjection(observation, adapter, method, expectedSequence) {
  const branded = assertAuthenticatedPhalaSdkObservation(observation, {
    adapter,
    method,
    domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
  });
  if (branded.call_sequence !== expectedSequence) {
    throw new Error("activation SDK observation sequence is not exact");
  }
  return {
    method,
    call_sequence: expectedSequence,
    observation_sha256: authenticatedPhalaSdkObservationSha256(branded, {
      adapter,
      method,
      domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
    }),
    request_semantics_sha256: branded.request_semantics_sha256,
    response_sha256: branded.sdk_response_sha256,
    observed_at: branded.observed_at,
    response: readAuthenticatedPhalaSdkObservationResponse(branded, {
      adapter,
      method,
      domain: method === "getCurrentUser" ? null : "main_runtime_cvm",
    }),
  };
}

function hasQuotedCertificate(value) {
  return Array.isArray(value?.app_certificates)
    && value.app_certificates.some((certificate) => (
      typeof certificate?.quote === "string" && certificate.quote.length > 0
    ));
}

function reviewedComputeWorkloadObservationAuthority(reviewedProjection) {
  const reviewedDependencies =
    readReviewedFinalAuthorityRuntimeDependencies(reviewedProjection);
  const cvm = reviewedDependencies.final_authority?.cvm;
  const policy = cvm?.compute_workload_ingress;
  if (!isRecord(cvm) || typeof cvm.delegate_url !== "string"
    || !isRecord(policy)
    || !Number.isSafeInteger(policy.max_verdict_age_seconds)
    || policy.max_verdict_age_seconds < 1
    || policy.max_verdict_age_seconds > 300
    || !Array.isArray(policy.revoked_quote_hashes)
    || policy.revoked_quote_hashes.length > 256
    || policy.revoked_quote_hashes.some((value) => (
      typeof value !== "string"
      || !/^0x(?!0{64}$)[0-9a-f]{64}$/.test(value)
    ))
    || JSON.stringify([...new Set(policy.revoked_quote_hashes)].sort())
      !== JSON.stringify(policy.revoked_quote_hashes)) {
    throw new Error(
      "reviewed final authority lacks an exact Compute observation policy",
    );
  }
  let capabilityEndpoint;
  try {
    capabilityEndpoint = new URL(
      "/compute/workload-encryption-contract",
      cvm.delegate_url,
    ).href;
  } catch {
    throw new Error(
      "reviewed final authority Compute observation endpoint is invalid",
    );
  }
  const parsedEndpoint = new URL(capabilityEndpoint);
  const reviewedOrigin = new URL(cvm.delegate_url);
  if (parsedEndpoint.protocol !== "https:"
    || parsedEndpoint.origin !== reviewedOrigin.origin
    || parsedEndpoint.username || parsedEndpoint.password
    || parsedEndpoint.search || parsedEndpoint.hash || parsedEndpoint.port
    || parsedEndpoint.pathname !== "/compute/workload-encryption-contract") {
    throw new Error(
      "reviewed final authority Compute observation endpoint is widened",
    );
  }
  const authority = deepFreezeCanonicalPlainDataGraph({
    capabilityEndpoint,
    ingressPolicy: {
      max_verdict_age_seconds: policy.max_verdict_age_seconds,
      revoked_quote_hashes: [...policy.revoked_quote_hashes],
    },
  }, { label: "reviewed Compute workload observation authority" });
  return Object.freeze({
    authority,
    authority_sha256: digest(
      PHALA_COMPUTE_WORKLOAD_OBSERVATION_AUTHORITY_DOMAIN,
      {
        capability_endpoint: authority.capabilityEndpoint,
        ingress_policy: authority.ingressPolicy,
      },
    ),
  });
}

function canonicalSecondFromEpoch(value) {
  return new Date(value * 1_000).toISOString().replace(".000Z", "Z");
}

export async function prepareProductionPhalaPostMeasurementActivationExecutionReceipt(
  input = {},
) {
  const parsedInput = exactRecord(
    input,
    PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_PREPARE_FIELDS,
    "post-measurement activation receipt preflight input",
  );
  const {
    plan: planValue,
    preCeremonyRuntimeAuthority: runtimeAuthorityValue,
    ceremonyAuthorization: ceremonyAuthorizationValue,
    ceremonyAuthorizationDependencies,
    privateEnvironmentAssemblyReceipt,
    privateEncryptedUpdate,
    adapter,
    observations,
    patchFinalizedReadiness,
    restartFinalizedReadiness,
    arenaWorkerPresence: arenaWorkerPresenceValue,
    recipientActivation: recipientActivationValue,
    proposedCompletedState: proposedCompletedStateValue,
    projectedJournal: projectedJournalValue,
  } = parsedInput;
  const {
    assertVerifiedArenaWorkerActivationProof,
    readVerifiedArenaWorkerActivationProofDependencies,
  } = await import("./arena-worker-activation-verification.mjs");
  const stronglyVerifiedArenaWorkerPresence =
    assertVerifiedArenaWorkerActivationProof(arenaWorkerPresenceValue);
  const plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(planValue);
  const runtimeAuthority = assertFreshBrandedPreCeremonyRuntimeAuthority(
    runtimeAuthorityValue,
  );
  const dependencies = exactRecord(ceremonyAuthorizationDependencies, [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "stageBReviewerStatusHistory",
  ], "activation signed-B dependency set");
  if (!Array.isArray(dependencies.stageBReviewerStatusHistory)) {
    throw new TypeError(
      "activation signed-B dependency set requires an exact Stage-B reviewer history array",
    );
  }
  const ceremonyOptions = {
    deploymentIntent: dependencies.deploymentIntent,
    freshContractDeploymentReceipt: dependencies.freshContractDeploymentReceipt,
    reviewerGenesis: dependencies.reviewerGenesis,
    reviewerGenesisAcceptance: dependencies.reviewerGenesisAcceptance,
    reviewerStatusHistory: dependencies.stageBReviewerStatusHistory,
    preCeremonyRuntimeAuthority: runtimeAuthority,
  };
  const ceremonyAuthorization = normalizeCeremonyAuthorizationCore(
    ceremonyAuthorizationValue,
    ceremonyOptions,
  );
  const planSha256 = phalaPostMeasurementActivationPlanSha256(plan);
  const runtimeAuthoritySha256 = preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  const ceremonyAuthorizationSha256 = ceremonyAuthorizationCoreSha256(
    ceremonyAuthorization,
    ceremonyOptions,
  );
  if (runtimeAuthority.post_measurement_activation_plan_sha256 !== planSha256
    || runtimeAuthority.seven_cvm_launch_completion_receipt_sha256
      !== plan.seven_cvm_launch_completion_receipt_sha256
    || runtimeAuthority.phala_recovery_directory_identity_anchor_sha256
      !== plan.phala_recovery_directory_identity_anchor_sha256
    || ceremonyAuthorization.pre_ceremony_runtime_authority_sha256
      !== runtimeAuthoritySha256
    || ceremonyAuthorization.cvm_launch_intent_sha256
      !== plan.cvm_launch_intent_sha256) {
    throw new Error("signed B, R, L, and activation plan do not share one lineage");
  }
  const state = normalizePhalaPostMeasurementActivationState(
    proposedCompletedStateValue,
  );
  if (state.status !== "complete") {
    throw new Error(
      "receipt preflight requires the proposed completed activation state before durable publication",
    );
  }
  const completedJournal = normalizePhalaPostMeasurementActivationJournal(
    projectedJournalValue,
  );
  const exactProjectedJournal =
    projectPhalaPostMeasurementActivationJournal(state);
  if (canonicalText(completedJournal) !== canonicalText(exactProjectedJournal)) {
    throw new Error(
      "receipt preflight projected journal differs from the exact proposed completed state",
    );
  }
  const adapterIdentitySha256 = pinnedPhalaProductionSdkAdapterIdentitySha256(adapter);
  const assemblyReceipt =
    assertPrivatePostMeasurementEnvironmentAssemblyReceipt(
      privateEnvironmentAssemblyReceipt,
    );
  const assemblySha256 = phalaPrivatePostMeasurementAssemblyReceiptSha256(
    assemblyReceipt,
  );
  if (state.activation_plan_sha256 !== planSha256
    || state.pre_ceremony_runtime_authority_sha256 !== runtimeAuthoritySha256
    || state.ceremony_authorization_sha256 !== ceremonyAuthorizationSha256
    || state.adapter_identity_sha256 !== adapterIdentitySha256
    || state.assembly_receipt_sha256 !== assemblySha256
    || state.target.app_id !== plan.target.app_id
    || state.target.cvm_id !== plan.target.cvm_id
    || canonicalText(state.profile_activation)
      !== canonicalText(plan.profile_activation)
    || state.allowed_environment_key_names_sha256
      !== plan.allowed_environment_key_names_sha256
    || state.injected_environment_key_names_sha256
      !== plan.injected_environment_key_names_sha256) {
    throw new Error("durable activation journal authority differs from signed execution inputs");
  }
  const observationSet = exactRecord(observations, [
    "getCurrentUser",
    "firstEnvironmentKey",
    "refetchedEnvironmentKey",
    "patch",
    "restart",
    "postRestartInfo",
    "postRestartAttestation",
  ], "activation authenticated observation set");
  const projected = [
    exactObservationProjection(observationSet.getCurrentUser, adapter, "getCurrentUser", 1),
    exactObservationProjection(observationSet.firstEnvironmentKey, adapter, "getAppEnvEncryptPubKey", 2),
    exactObservationProjection(observationSet.refetchedEnvironmentKey, adapter, "getAppEnvEncryptPubKey", 3),
    exactObservationProjection(observationSet.patch, adapter, "updateCvmEnvs", 4),
    exactObservationProjection(observationSet.restart, adapter, "restartCvm", 5),
    exactObservationProjection(observationSet.postRestartInfo, adapter, "getCvmInfo", 6),
    exactObservationProjection(observationSet.postRestartAttestation, adapter, "getCvmAttestation", 7),
  ];
  for (let index = 0; index < projected.length; index += 1) {
    const expected = state.sdk_observations[index];
    if (projected[index].observation_sha256 !== expected.observation_sha256
      || projected[index].request_semantics_sha256
        !== expected.request_semantics_sha256
      || projected[index].observed_at !== expected.observed_at) {
      throw new Error("durable activation journal differs from authenticated SDK replay");
    }
  }
  const patch = projected[3];
  const restart = projected[4];
  const info = projected[5];
  const attestation = projected[6];
  if (!isRecord(info.response)
    || String(info.response.id) !== plan.target.cvm_id
    || String(info.response.app_id).replace(/^0x/, "").toLowerCase()
      !== plan.target.app_id
    || info.response.compose_hash !== plan.target.compose_hash
    || info.response.os?.os_image_hash !== plan.target.os_image_hash
    || !isRecord(attestation.response)
    || attestation.response.is_online !== true
    || attestation.response.error !== null
    || !isRecord(attestation.response.tcb_info)
    || !hasQuotedCertificate(attestation.response)) {
    throw new Error("fresh post-restart Phala status or attestation differs from main target");
  }
  const activation = assertProductionPhalaComputeWorkloadRecipientActivation(
    recipientActivationValue,
  );
  const arenaWorkerPresence =
    assertFreshProductionPhalaArenaWorkerPresenceActivationProof(
      stronglyVerifiedArenaWorkerPresence,
    );
  const verifiedArenaDependencies =
    readVerifiedArenaWorkerActivationProofDependencies(arenaWorkerPresence);
  if (verifiedArenaDependencies.post_measurement_activation_plan !== plan
    || phalaPostMeasurementActivationPlanSha256(
      verifiedArenaDependencies.post_measurement_activation_plan,
    ) !== planSha256) {
    throw new Error(
      "reviewed Arena worker proof is not bound to the exact activation plan",
    );
  }
  const computeWorkloadObservationAuthority =
    reviewedComputeWorkloadObservationAuthority(
      verifiedArenaDependencies.reviewed_final_authority_runtime_projection,
    );
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const computeRecipientActivationSha256 =
    phalaComputeWorkloadRecipientActivationVerificationSha256(activation);
  const combinedActivationVerificationSha256 =
    phalaCombinedArenaComputeActivationVerificationSha256({
      profileActivation: plan.profile_activation,
      arenaWorkerPresenceSha256,
      computeRecipientActivationSha256,
    });
  const normalizedActivation =
    normalizePhalaComputeWorkloadRecipientActivationVerification(activation);
  if (activation.release_authority_sha256
      !== plan.release_verification_authority_sha256
    || activation.deployment_intent_sha256 !== plan.deployment_intent_sha256
    || activation.app_id !== plan.target.app_id
    || activation.cvm_id !== plan.target.cvm_id
    || activation.compose_hash !== plan.target.compose_hash
    || activation.os_image_hash !== plan.target.os_image_hash
    || arenaWorkerPresence.heartbeat_observed_at
      <= Math.floor(Date.parse(attestation.observed_at) / 1_000)
    || arenaWorkerPresence.verified_at
      < arenaWorkerPresence.heartbeat_observed_at
    || activation.authenticated_at
      < arenaWorkerPresence.verified_at
    || activation.recipient_evidence_lease_expires_at
      !== activation.source_activation.recipient_evidence_lease_expires_at
    || state.arena_worker_presence_sha256 !== arenaWorkerPresenceSha256
    || state.arena_worker_presence_verified_at
      !== canonicalSecondFromEpoch(arenaWorkerPresence.verified_at)
    || state.compute_recipient_activation_sha256
      !== computeRecipientActivationSha256
    || state.compute_recipient_activation_verified_at
      !== canonicalSecondFromEpoch(activation.verified_at)
    || state.combined_activation_verification_sha256
      !== combinedActivationVerificationSha256) {
    throw new Error(
      "Arena worker presence and Compute recipient activation are not ordered post-restart proofs for this plan",
    );
  }
  const patchAttempt = state.mutation_attempts[0];
  const restartAttempt = state.mutation_attempts[1];
  const patchReadiness = assertProductionMutationReadinessProjection(
    patchFinalizedReadiness,
    {
      action: "updateCvmEnvs",
      activationPlanSha256: planSha256,
      preCeremonyRuntimeAuthoritySha256: runtimeAuthoritySha256,
      ceremonyAuthorizationSha256,
    },
  );
  const restartReadiness = assertProductionMutationReadinessProjection(
    restartFinalizedReadiness,
    {
      action: "restartCvm",
      activationPlanSha256: planSha256,
      preCeremonyRuntimeAuthoritySha256: runtimeAuthoritySha256,
      ceremonyAuthorizationSha256,
    },
  );
  assertRegisteredPrivatePostMeasurementEncryptedUpdate(privateEncryptedUpdate, {
    activationPlanSha256: planSha256,
    assemblyReceiptSha256: assemblySha256,
    targetCvmId: plan.target.cvm_id,
    patchObservationSha256: patch.observation_sha256,
    patchRequestSemanticsSha256: patch.request_semantics_sha256,
  });
  const candidate = normalizePhalaPostMeasurementActivationExecutionReceipt({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: CHAIN_ID,
    release_sha: plan.release_sha,
    batch_id: plan.batch_id,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    cvm_launch_intent_sha256: plan.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      plan.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    seven_cvm_verified_evidence_set_sha256:
      plan.seven_cvm_verified_evidence_set_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    pre_ceremony_runtime_authority_sha256: runtimeAuthoritySha256,
    post_measurement_activation_plan_sha256: planSha256,
    ceremony_authorization_sha256: ceremonyAuthorizationSha256,
    target: plan.target,
    profile_activation: plan.profile_activation,
    runtime_commitments_sha256:
      phalaPostMeasurementRuntimeCommitmentsSha256(plan.runtime_commitments),
    runtime_commitment_key_names_sha256:
      plan.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256:
      plan.allowed_environment_key_names_sha256,
    allowed_environment_key_count: plan.allowed_environment_key_count,
    injected_environment_key_names_sha256:
      plan.injected_environment_key_names_sha256,
    injected_environment_key_count: plan.injected_environment_key_names.length,
    private_environment_assembly_receipt_sha256: assemblySha256,
    adapter_identity_sha256: adapterIdentitySha256,
    activation_journal_state_sha256:
      phalaPostMeasurementActivationStateSha256(state),
    activation_journal_sha256:
      phalaPostMeasurementActivationJournalSha256(completedJournal),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch: {
      sdk_action: "updateCvmEnvs",
      call_sequence: 4,
      request_semantics_sha256: patch.request_semantics_sha256,
      observation_sha256: patch.observation_sha256,
      response_sha256: patch.response_sha256,
      body_field_names: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
      attempt_recorded_at: patchAttempt.recorded_at,
      observed_at: patch.observed_at,
      finalized_readiness: patchReadiness,
    },
    restart: {
      sdk_action: "restartCvm",
      call_sequence: 5,
      request_semantics_sha256: restart.request_semantics_sha256,
      observation_sha256: restart.observation_sha256,
      response_sha256: restart.response_sha256,
      force: false,
      attempt_recorded_at: restartAttempt.recorded_at,
      observed_at: restart.observed_at,
      finalized_readiness: restartReadiness,
    },
    post_restart_evidence: {
      get_cvm_info_call_sequence: 6,
      get_cvm_info_observation_sha256: info.observation_sha256,
      get_cvm_info_response_sha256: info.response_sha256,
      get_cvm_info_observed_at: info.observed_at,
      get_cvm_attestation_call_sequence: 7,
      get_cvm_attestation_observation_sha256: attestation.observation_sha256,
      get_cvm_attestation_response_sha256: attestation.response_sha256,
      get_cvm_attestation_observed_at: attestation.observed_at,
      cvm_online: true,
      attestation_error_absent: true,
      tcb_info_present: true,
      app_certificate_quote_present: true,
      pre_injection_attestation_sufficient: false,
    },
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: {
      activation_verification_sha256:
        computeRecipientActivationSha256,
      source_activation_sha256: normalizedActivation.activation_artifact_sha256,
      raw_transcript_sha256: activation.raw_transcript_sha256,
      qvl_verdict_verifier_signature_sha256:
        activation.qvl_verdict_verifier_signature_sha256,
      tdx_quote_sha256: activation.tdx_quote_sha256,
      challenge_id: activation.challenge_id,
      report_data: activation.report_data,
      recipient_key_id: activation.recipient_key_id,
      recipient_release_commitment: activation.recipient_release_commitment,
      authenticated_at: activation.authenticated_at,
      verified_at: activation.verified_at,
      verdict_activation_evidence_lease_expires_at:
        activation.verdict_activation_evidence_lease_expires_at,
      recipient_evidence_lease_expires_at:
        activation.recipient_evidence_lease_expires_at,
      expires_at: activation.expires_at,
      post_restart_source_activation: true,
    },
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      combinedActivationVerificationSha256,
    initial_activation_evidence_lease_expires_at:
      plan.activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      activation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at: Math.min(
      plan.activation_evidence_lease_expires_at,
      activation.recipient_evidence_lease_expires_at,
    ),
    completed_at: state.completed_at,
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  });
  const frozen = deepFreezeCanonicalPlainDataGraph(candidate, {
    label: "prepared production activation execution receipt",
  });
  const provenance = Object.freeze({
    plan_sha256: planSha256,
    runtime_authority_sha256: runtimeAuthoritySha256,
    ceremony_authorization_sha256: ceremonyAuthorizationSha256,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      combinedActivationVerificationSha256,
    plan,
    pre_ceremony_runtime_authority: runtimeAuthority,
    ceremony_authorization: ceremonyAuthorization,
    arena_worker_presence: arenaWorkerPresence,
    recipient_activation: activation,
    release_verification_authority:
      readPhalaPostMeasurementActivationPlanDependencies(plan).release_authority,
    compute_workload_observation_authority:
      computeWorkloadObservationAuthority.authority,
    compute_workload_observation_authority_sha256:
      computeWorkloadObservationAuthority.authority_sha256,
  });
  const preflightToken = Object.freeze({});
  RECEIPT_PREFLIGHTS.set(preflightToken, Object.freeze({
    receipt: frozen,
    provenance,
    proposed_state_sha256:
      phalaPostMeasurementActivationStateSha256(state),
    projected_journal_sha256:
      phalaPostMeasurementActivationJournalSha256(completedJournal),
  }));
  return preflightToken;
}

export function readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies(
  preflightToken,
) {
  const prepared = preflightToken && RECEIPT_PREFLIGHTS.get(preflightToken);
  if (!prepared) {
    throw new Error(
      "an opaque locally prepared activation receipt preflight token is required",
    );
  }
  const authority = prepared.provenance.compute_workload_observation_authority;
  const receiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(prepared.receipt);
  const computeWorkloadObservationBinding =
    deepFreezeCanonicalPlainDataGraph({
      capability_endpoint: authority.capabilityEndpoint,
      historical_transcript_file_set_sha256:
        prepared.provenance.pre_ceremony_runtime_authority
          .historical_transcript_file_set_sha256,
      seven_cvm_launch_completion_receipt_sha256:
        prepared.receipt.seven_cvm_launch_completion_receipt_sha256,
      seven_cvm_verified_evidence_set_sha256:
        prepared.receipt.seven_cvm_verified_evidence_set_sha256,
      pre_ceremony_runtime_authority_sha256:
        prepared.receipt.pre_ceremony_runtime_authority_sha256,
      post_measurement_activation_plan_sha256:
        prepared.receipt.post_measurement_activation_plan_sha256,
      post_measurement_activation_execution_receipt_sha256: receiptSha256,
      ceremony_authorization_sha256:
        prepared.receipt.ceremony_authorization_sha256,
      initial_activation_evidence_lease_expires_at:
        prepared.receipt.initial_activation_evidence_lease_expires_at,
      recipient_evidence_lease_expires_at:
        prepared.receipt.recipient_evidence_lease_expires_at,
      terminal_evidence_lease_expires_at:
        prepared.receipt.terminal_evidence_lease_expires_at,
      ingress_policy: authority.ingressPolicy,
    }, { label: "prepared Compute workload observation binding" });
  return Object.freeze({
    post_measurement_activation_execution_receipt_sha256:
      receiptSha256,
    release_verification_authority_sha256:
      prepared.receipt.release_verification_authority_sha256,
    compute_recipient_activation_sha256:
      prepared.receipt.compute_recipient_activation_sha256,
    compute_workload_observation_authority:
      authority,
    compute_workload_observation_authority_sha256:
      prepared.provenance.compute_workload_observation_authority_sha256,
    compute_workload_observation_binding: computeWorkloadObservationBinding,
  });
}

export function finalizeProductionPhalaPostMeasurementActivationExecutionReceipt(
  input = {},
) {
  const parsed = exactRecord(
    input,
    PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_FINALIZE_FIELDS,
    "post-measurement activation receipt finalization input",
  );
  const prepared = parsed.preflightToken
    && RECEIPT_PREFLIGHTS.get(parsed.preflightToken);
  if (!prepared) {
    throw new Error(
      "an opaque locally prepared activation receipt preflight token is required",
    );
  }
  const durableJournal =
    assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal({
      journal: parsed.journal,
      directory: parsed.journalDirectory,
      state: parsed.journalState,
      lock: parsed.journalLock,
    });
  const durableStateSha256 =
    phalaPostMeasurementActivationStateSha256(parsed.journalState);
  const durableJournalSha256 =
    phalaPostMeasurementActivationJournalSha256(durableJournal);
  if (durableStateSha256 !== prepared.proposed_state_sha256
    || durableJournalSha256 !== prepared.projected_journal_sha256
    || durableJournal.state_sha256 !== prepared.proposed_state_sha256
    || prepared.receipt.activation_journal_state_sha256
      !== durableStateSha256
    || prepared.receipt.activation_journal_sha256
      !== durableJournalSha256) {
    throw new Error(
      "durably completed activation state or journal differs from receipt preflight",
    );
  }
  if (prepared.test_only === true) {
    throw new Error("test-only receipt preflights cannot mint production authority");
  }
  if (Math.floor(Date.now() / 1_000)
      >= prepared.receipt.terminal_evidence_lease_expires_at) {
    throw new Error(
      "activation receipt terminal evidence lease expired before finalization",
    );
  }
  RECEIPTS.set(prepared.receipt, prepared.provenance);
  RECEIPT_PREFLIGHTS.delete(parsed.preflightToken);
  return prepared.receipt;
}

// Kept only so older import graphs fail closed while the runtime migrates to
// the mandatory prepare -> durable journal -> finalize sequence.
export function createProductionPhalaPostMeasurementActivationExecutionReceipt() {
  throw new Error(
    "single-phase production receipt creation is disabled; prepare and finalize around durable completion",
  );
}

function isExactNodeTestEntrypoint() {
  const entrypoint = process.argv[1];
  if (process.env.NODE_TEST_CONTEXT !== "child-v8"
    || typeof entrypoint !== "string" || !entrypoint.endsWith(".test.mjs")) {
    return false;
  }
  try {
    return path.resolve(entrypoint) === fs.realpathSync.native(entrypoint);
  } catch {
    return false;
  }
}

function createTestReceiptPreflightForDurabilityChecks(input = {}) {
  if (!isExactNodeTestEntrypoint()) {
    throw new Error("synthetic receipt preflights are available only inside node --test");
  }
  const parsed = exactRecord(input, [
    "receipt",
    "proposedStateSha256",
    "projectedJournalSha256",
  ], "test-only receipt preflight input");
  const proposedStateSha256 = sha256(
    parsed.proposedStateSha256,
    "test-only proposed activation state",
  );
  const projectedJournalSha256 = sha256(
    parsed.projectedJournalSha256,
    "test-only projected activation journal",
  );
  const receipt = deepFreezeCanonicalPlainDataGraph(
    normalizePhalaPostMeasurementActivationExecutionReceipt({
      ...parsed.receipt,
      activation_journal_state_sha256: proposedStateSha256,
      activation_journal_sha256: projectedJournalSha256,
    }),
    { label: "test-only prepared activation receipt" },
  );
  const token = Object.freeze({});
  RECEIPT_PREFLIGHTS.set(token, Object.freeze({
    receipt,
    provenance: null,
    proposed_state_sha256: proposedStateSha256,
    projected_journal_sha256: projectedJournalSha256,
    test_only: true,
  }));
  return token;
}

export const __test = Object.freeze({
  createReceiptPreflightForDurabilityChecks:
    createTestReceiptPreflightForDurabilityChecks,
});

export function assertFinalizedProductionPhalaPostMeasurementActivationExecutionReceipt(value) {
  const provenance = value && RECEIPTS.get(value);
  const normalized = normalizePhalaPostMeasurementActivationExecutionReceipt(value);
  if (!provenance
    || canonicalText(normalized) !== canonicalText(value)
    || normalized.post_measurement_activation_plan_sha256 !== provenance.plan_sha256
    || normalized.pre_ceremony_runtime_authority_sha256
      !== provenance.runtime_authority_sha256
    || normalized.ceremony_authorization_sha256
      !== provenance.ceremony_authorization_sha256
    || normalized.arena_worker_presence_sha256
      !== provenance.arena_worker_presence_sha256
    || normalized.compute_recipient_activation_sha256
      !== provenance.compute_recipient_activation_sha256
    || normalized.combined_activation_verification_sha256
      !== provenance.combined_activation_verification_sha256) {
    throw new Error("a locally finalized production activation receipt is required");
  }
  return value;
}

export function assertProductionPhalaPostMeasurementActivationExecutionReceipt(value) {
  const finalized =
    assertFinalizedProductionPhalaPostMeasurementActivationExecutionReceipt(value);
  if (Math.floor(Date.now() / 1_000)
      >= finalized.terminal_evidence_lease_expires_at) {
    throw new Error("a fresh locally replayed production activation receipt is required");
  }
  return finalized;
}

export function readFinalizedProductionPhalaPostMeasurementActivationExecutionIdentity(
  value,
) {
  const receipt =
    assertFinalizedProductionPhalaPostMeasurementActivationExecutionReceipt(value);
  const provenance = RECEIPTS.get(receipt);
  return Object.freeze({
    post_measurement_activation_execution_receipt_sha256:
      phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
    compute_workload_observation_authority_sha256:
      provenance.compute_workload_observation_authority_sha256,
  });
}

export function readFinalizedProductionPhalaPostMeasurementActivationExecutionDependencies(
  value,
) {
  const receipt =
    assertFinalizedProductionPhalaPostMeasurementActivationExecutionReceipt(value);
  const provenance = RECEIPTS.get(value);
  const authority = provenance.compute_workload_observation_authority;
  const receiptSha256 = phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  return Object.freeze({
    plan: provenance.plan,
    pre_ceremony_runtime_authority:
      provenance.pre_ceremony_runtime_authority,
    ceremony_authorization: provenance.ceremony_authorization,
    arena_worker_presence: provenance.arena_worker_presence,
    recipient_activation: provenance.recipient_activation,
    release_verification_authority:
      provenance.release_verification_authority,
    compute_workload_observation_authority: authority,
    compute_workload_observation_authority_sha256:
      provenance.compute_workload_observation_authority_sha256,
    compute_workload_observation_binding:
      deepFreezeCanonicalPlainDataGraph({
        capability_endpoint: authority.capabilityEndpoint,
        historical_transcript_file_set_sha256:
          provenance.pre_ceremony_runtime_authority
            .historical_transcript_file_set_sha256,
        seven_cvm_launch_completion_receipt_sha256:
          receipt.seven_cvm_launch_completion_receipt_sha256,
        seven_cvm_verified_evidence_set_sha256:
          receipt.seven_cvm_verified_evidence_set_sha256,
        pre_ceremony_runtime_authority_sha256:
          receipt.pre_ceremony_runtime_authority_sha256,
        post_measurement_activation_plan_sha256:
          receipt.post_measurement_activation_plan_sha256,
        post_measurement_activation_execution_receipt_sha256: receiptSha256,
        ceremony_authorization_sha256:
          receipt.ceremony_authorization_sha256,
        initial_activation_evidence_lease_expires_at:
          receipt.initial_activation_evidence_lease_expires_at,
        recipient_evidence_lease_expires_at:
          receipt.recipient_evidence_lease_expires_at,
        terminal_evidence_lease_expires_at:
          receipt.terminal_evidence_lease_expires_at,
        ingress_policy: authority.ingressPolicy,
      }, { label: "finalized Compute workload observation binding" }),
  });
}

export function readProductionPhalaPostMeasurementActivationExecutionDependencies(value) {
  assertProductionPhalaPostMeasurementActivationExecutionReceipt(value);
  return readFinalizedProductionPhalaPostMeasurementActivationExecutionDependencies(
    value,
  );
}
