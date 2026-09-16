import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  normalizePhalaArenaWorkerPresenceActivationProof,
  phalaArenaWorkerPresenceActivationProofSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  PHALA_ARENA_WORKER_ENDPOINT_COMMITMENT_DOMAIN,
  assertFreshProductionPhalaArenaWorkerPresenceActivationProof,
  phalaArenaWorkerPresenceEndpointCommitmentSha256,
  phalaArenaWorkerReleaseBindingSha256,
  verifyProductionPhalaArenaWorkerPresenceActivation,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  assertReviewedFinalAuthorityRuntimeProjection,
  readReviewedFinalAuthorityRuntimeDependencies,
} from "./reviewed-final-authority-runtime.mjs";
import {
  assertFreshBrandedPhalaPostMeasurementActivationPlan,
  readPhalaPostMeasurementActivationPlanDependencies,
} from "./phala-post-measurement-activation.mjs";

export const ARENA_WORKER_CAPABILITY_SCHEMA_VERSION = 2;
export const ARENA_WORKER_CHALLENGE_ID = "dnaseq-variant-qc-safe-ir";
export const ARENA_WORKER_CHALLENGE_VERSION = "1.0.0";
export const ARENA_WORKER_CHALLENGE_KEY =
  `${ARENA_WORKER_CHALLENGE_ID}@${ARENA_WORKER_CHALLENGE_VERSION}`;
export const ARENA_WORKER_SAFE_IR_RUNTIME = "dnai-safe-ir-v1";
export const ARENA_WORKER_SAFE_IR_POLICY_COMMITMENT =
  "sha256:9fcffd04eeece1398970e4a144807df95f31408b2337d71cc8377048b2ec114e";
export const ARENA_WORKER_CATALOG_MANIFEST_HASH =
  "0812d8ab6cb26d60f1c28f6696773bd05a47e89fecc0ac6f28447ab0624f058f";
export const ARENA_WORKER_RELEASE_BINDING_SCHEMA =
  "dnai.arena.safe-worker-release-binding.v1";
export const ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA =
  "dnai.arena.safe-worker-presence-binding.v1";
export const ARENA_WORKER_RELEASE_BINDING_DOMAIN =
  "dnai-wikigen/arena-worker-release-binding/v1\0";
export const ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN =
  "dnai-wikigen/arena-worker-presence-binding/v1\0";
export const ARENA_WORKER_CAPABILITY_ENDPOINT_DOMAIN =
  PHALA_ARENA_WORKER_ENDPOINT_COMMITMENT_DOMAIN;
export const ARENA_WORKER_CAPABILITY_WARNING =
  "Fresh authenticated worker presence matches the exact release pins. "
  + "This heartbeat is not TDX evidence; every job still requires its "
  + "independent quote, QVL, registry, and execution-policy gates.";
export const MAX_ARENA_WORKER_CAPABILITY_RESPONSE_BYTES = 64 * 1024;
export const MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS = 300;
export const MAX_ARENA_WORKER_FUTURE_SKEW_SECONDS = 5;

const MAX_EPOCH_SECOND = 4_102_444_800;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^[\x21-\x7e]{1,128}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CAPABILITY_PATH =
  `/arena/challenges/${ARENA_WORKER_CHALLENGE_ID}`
  + `/versions/${ARENA_WORKER_CHALLENGE_VERSION}/worker-capability`;
const VERIFIED_PROOFS = new WeakMap();
const TEST_ACTIVATION_PLANS = new WeakMap();
const TEST_ACTIVATION_PLAN_DOMAIN =
  "dnai-wikigen/test-only-arena-activation-plan/v1\0";

const RELEASE_BINDING_FIELDS = Object.freeze([
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
]);

const CAPABILITY_FIELDS = Object.freeze([
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

const VERIFY_FIELDS = Object.freeze([
  "postMeasurementActivationPlan",
  "postRestartAttestationObservedAt",
  "reviewedFinalAuthorityRuntimeProjection",
]);

export class ArenaWorkerActivationVerificationError extends TypeError {}

function fail(message) {
  throw new ArenaWorkerActivationVerificationError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  try {
    assertCanonicalPlainDataGraph(value, {
      label,
      maximumDepth: 64,
      maximumNodes: 100_000,
    });
  } catch {
    fail(`${label} is not canonical plain data`);
  }
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields are not exact`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} is not the required live value`);
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    fail(`${label} is not canonical`);
  }
  return value;
}

function boundedSecond(value, label, { allowZero = false } = {}) {
  const minimum = allowZero ? 0 : 1;
  if (!Number.isSafeInteger(value) || value < minimum
    || value > MAX_EPOCH_SECOND) {
    fail(`${label} must be a bounded Unix second`);
  }
  return value;
}

function canonicalIsoSecond(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    fail(`${label} must be a canonical UTC second`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a canonical UTC second`);
  }
  return milliseconds / 1_000;
}

function internalSecond() {
  return boundedSecond(
    Math.floor(Date.now() / 1_000),
    "Arena worker verification wall clock",
  );
}

function asciiJsonString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function canonicalAsciiJson(value) {
  if (typeof value === "string") return asciiJsonString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (value === null) return "null";
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalAsciiJson(entry)).join(",")}]`;
  }
  return `{${Object.keys(value).sort().map((key) => (
    `${asciiJsonString(key)}:${canonicalAsciiJson(value[key])}`
  )).join(",")}}`;
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalAsciiJson(value), "ascii")
    .digest("hex")}`;
}

function byteSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function normalizeReleaseBinding(value) {
  const parsed = exactRecord(
    value,
    RELEASE_BINDING_FIELDS,
    "Arena worker release binding",
  );
  return {
    release_sha: fixed(parsed.release_sha, SHA40, "Arena worker release SHA"),
    image_digest: fixed(
      parsed.image_digest,
      SHA256,
      "Arena worker image digest",
    ),
    release_manifest_sha256: fixed(
      parsed.release_manifest_sha256,
      SHA256,
      "Arena worker release-manifest digest",
    ),
    approved_challenge_set_sha256: fixed(
      parsed.approved_challenge_set_sha256,
      SHA256,
      "Arena worker approved challenge-set digest",
    ),
    approved_challenge_key: exactString(
      parsed.approved_challenge_key,
      ARENA_WORKER_CHALLENGE_KEY,
      "Arena worker approved challenge key",
    ),
    release_policy_commitment: fixed(
      parsed.release_policy_commitment,
      BYTES32,
      "Arena worker release-policy commitment",
    ),
    catalog_manifest_hash: exactString(
      parsed.catalog_manifest_hash,
      ARENA_WORKER_CATALOG_MANIFEST_HASH,
      "Arena worker catalog manifest hash",
    ),
    runtime: exactString(
      parsed.runtime,
      ARENA_WORKER_SAFE_IR_RUNTIME,
      "Arena worker runtime",
    ),
    runtime_policy_commitment: exactString(
      parsed.runtime_policy_commitment,
      ARENA_WORKER_SAFE_IR_POLICY_COMMITMENT,
      "Arena worker runtime-policy commitment",
    ),
    compose_hash: fixed(
      parsed.compose_hash,
      BARE_SHA256,
      "Arena worker compose hash",
    ),
    app_id: fixed(parsed.app_id, APP_ID, "Arena worker app ID"),
    os_image_hash: fixed(
      parsed.os_image_hash,
      BARE_SHA256,
      "Arena worker OS image hash",
    ),
  };
}

export function arenaWorkerReleaseBindingSha256(value) {
  const releaseBinding = normalizeReleaseBinding(value);
  return domainSha256(ARENA_WORKER_RELEASE_BINDING_DOMAIN, {
    schema: ARENA_WORKER_RELEASE_BINDING_SCHEMA,
    release_binding: releaseBinding,
  });
}

export function arenaWorkerHeartbeatBindingSha256(input = {}) {
  const parsed = exactRecord(input, [
    "challengeId",
    "challengeVersion",
    "heartbeatObservedAt",
    "releaseBindingSha256",
  ], "Arena worker heartbeat-binding input");
  const challengeId = exactString(
    parsed.challengeId,
    ARENA_WORKER_CHALLENGE_ID,
    "Arena worker heartbeat challenge",
  );
  const challengeVersion = exactString(
    parsed.challengeVersion,
    ARENA_WORKER_CHALLENGE_VERSION,
    "Arena worker heartbeat challenge version",
  );
  const heartbeatObservedAt = boundedSecond(
    parsed.heartbeatObservedAt,
    "Arena worker heartbeat time",
    { allowZero: true },
  );
  const releaseBindingSha256 = fixed(
    parsed.releaseBindingSha256,
    SHA256,
    "Arena worker heartbeat release binding",
  );
  return domainSha256(ARENA_WORKER_HEARTBEAT_BINDING_DOMAIN, {
    schema: ARENA_WORKER_HEARTBEAT_BINDING_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    challenge_id: challengeId,
    challenge_version: challengeVersion,
    heartbeat_observed_at: heartbeatObservedAt,
    release_binding_sha256: releaseBindingSha256,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  });
}

export function normalizeArenaWorkerCapabilityV2(value) {
  const parsed = exactRecord(
    value,
    CAPABILITY_FIELDS,
    "Arena worker capability v2",
  );
  const releaseBinding = normalizeReleaseBinding(parsed.release_binding);
  const releaseBindingSha256 = arenaWorkerReleaseBindingSha256(releaseBinding);
  if (parsed.schema_version !== ARENA_WORKER_CAPABILITY_SCHEMA_VERSION
    || parsed.live_execution !== true
    || parsed.worker_connected !== true
    || parsed.safe_ir_execution_ready !== true
    || parsed.hostile_general_code_ready !== false
    || parsed.python_preview_live !== false
    || parsed.exact_timing_egress !== false
    || parsed.internal_error_egress !== false
    || parsed.raw_candidate_egress !== false
    || parsed.tdx_attestation_egress !== false) {
    fail("Arena worker capability is not the exact live bounded v2 posture");
  }
  const heartbeatObservedAt = boundedSecond(
    parsed.heartbeat_observed_at,
    "Arena worker capability heartbeat time",
    { allowZero: true },
  );
  exactString(parsed.surface, "arena_worker_capability", "Arena worker surface");
  exactString(parsed.challenge_id, ARENA_WORKER_CHALLENGE_ID, "Arena challenge ID");
  exactString(
    parsed.challenge_version,
    ARENA_WORKER_CHALLENGE_VERSION,
    "Arena challenge version",
  );
  exactString(parsed.status, "live", "Arena worker status");
  exactString(
    parsed.backend,
    "release_bound_safe_ir_worker",
    "Arena worker backend",
  );
  exactString(
    parsed.isolation,
    "independent_job_gate_required",
    "Arena worker isolation",
  );
  exactString(parsed.freshness, "fresh", "Arena worker freshness");
  exactString(
    parsed.evidence_authenticity,
    "hmac_verified",
    "Arena worker evidence authenticity",
  );
  exactString(
    parsed.evidence_classification,
    PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    "Arena worker evidence classification",
  );
  exactString(parsed.gate_reason, "ready", "Arena worker gate reason");
  exactString(parsed.warning, ARENA_WORKER_CAPABILITY_WARNING, "Arena worker warning");
  exactString(parsed.product_status, "live", "Arena worker product status");
  if (parsed.release_binding_sha256 !== releaseBindingSha256) {
    fail("Arena worker release-binding digest does not recompute");
  }
  const heartbeatBindingSha256 = arenaWorkerHeartbeatBindingSha256({
    challengeId: parsed.challenge_id,
    challengeVersion: parsed.challenge_version,
    heartbeatObservedAt,
    releaseBindingSha256,
  });
  if (parsed.heartbeat_binding_sha256 !== heartbeatBindingSha256) {
    fail("Arena worker heartbeat-binding digest does not recompute");
  }
  return deepFreezeCanonicalPlainDataGraph({
    surface: "arena_worker_capability",
    schema_version: ARENA_WORKER_CAPABILITY_SCHEMA_VERSION,
    challenge_id: ARENA_WORKER_CHALLENGE_ID,
    challenge_version: ARENA_WORKER_CHALLENGE_VERSION,
    status: "live",
    backend: "release_bound_safe_ir_worker",
    isolation: "independent_job_gate_required",
    live_execution: true,
    worker_connected: true,
    safe_ir_execution_ready: true,
    hostile_general_code_ready: false,
    python_preview_live: false,
    freshness: "fresh",
    evidence_authenticity: "hmac_verified",
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    gate_reason: "ready",
    heartbeat_observed_at: heartbeatObservedAt,
    heartbeat_binding_sha256: heartbeatBindingSha256,
    release_binding_sha256: releaseBindingSha256,
    release_binding: releaseBinding,
    warning: ARENA_WORKER_CAPABILITY_WARNING,
    product_status: "live",
    exact_timing_egress: false,
    internal_error_egress: false,
    raw_candidate_egress: false,
    tdx_attestation_egress: false,
  }, { label: "normalized Arena worker capability v2" });
}

export function canonicalArenaWorkerCapabilityV2Text(value) {
  return JSON.stringify(normalizeArenaWorkerCapabilityV2(value));
}

export function normalizeArenaWorkerCapabilityV2Text(value) {
  if (typeof value !== "string") {
    fail("Arena worker capability response must be text");
  }
  const bytes = Buffer.from(value, "utf8");
  if (bytes.length < 2 || bytes.length > MAX_ARENA_WORKER_CAPABILITY_RESPONSE_BYTES
    || bytes.some((byte) => byte > 0x7f)
    || bytes.toString("utf8") !== value) {
    fail("Arena worker capability response is outside its canonical ASCII byte bound");
  }
  let decoded;
  try {
    decoded = JSON.parse(value);
  } catch {
    fail("Arena worker capability response is malformed JSON");
  }
  const normalized = normalizeArenaWorkerCapabilityV2(decoded);
  if (JSON.stringify(normalized) !== value) {
    fail("Arena worker capability response is not exact canonical compact JSON");
  }
  return normalized;
}

function reviewWindow(dependencies, checkedAt) {
  const approvedAt = canonicalIsoSecond(
    dependencies.review_envelope.approved_at,
    "reviewed final-authority approval time",
  );
  const expiresAt = canonicalIsoSecond(
    dependencies.review_envelope.expires_at,
    "reviewed final-authority expiry time",
  );
  if (checkedAt < approvedAt || checkedAt >= expiresAt) {
    fail("reviewed final-authority approval is not current");
  }
  return { approvedAt, expiresAt };
}

function activationPlanAuthority(planValue, checkedAt, { allowTestPlan = false } = {}) {
  if (allowTestPlan) {
    const synthetic = planValue && TEST_ACTIVATION_PLANS.get(planValue);
    if (synthetic) {
      if (synthetic.digest !== domainSha256(TEST_ACTIVATION_PLAN_DOMAIN, planValue)
        || checkedAt >= planValue.activation_evidence_lease_expires_at
        || checkedAt < synthetic.reviewed_at
        || checkedAt >= synthetic.valid_until) {
        fail("test-only Arena activation plan is stale or was mutated");
      }
      return Object.freeze({
        plan: planValue,
        deferredAuthority: synthetic.deferred_authority,
      });
    }
  }
  let plan;
  let dependencies;
  try {
    plan = assertFreshBrandedPhalaPostMeasurementActivationPlan(planValue);
    dependencies = readPhalaPostMeasurementActivationPlanDependencies(plan);
  } catch {
    fail("a fresh dependency-reconstructed activation plan is required");
  }
  return Object.freeze({
    plan,
    deferredAuthority: dependencies.deferred_authority,
  });
}

function expectedAuthorityFromReviewedProjectionAndPlan(
  projectionValue,
  planValue,
  checkedAt,
  { allowTestPlan = false } = {},
) {
  const projection = assertReviewedFinalAuthorityRuntimeProjection(projectionValue);
  const dependencies = readReviewedFinalAuthorityRuntimeDependencies(projection);
  reviewWindow(dependencies, checkedAt);
  const planAuthority = activationPlanAuthority(
    planValue,
    checkedAt,
    { allowTestPlan },
  );
  const plan = planAuthority.plan;
  const deferredAuthority = planAuthority.deferredAuthority;
  const finalAuthority = dependencies.final_authority;
  const launch = dependencies.cvm_launch_intent;
  const challengeProjection =
    dependencies.challenge_registry_runtime_environment_projection;
  const deferredMainEntries = deferredAuthority.domains.filter(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  const deferredMain = deferredMainEntries[0];
  if (deferredMainEntries.length !== 1 || !isRecord(deferredMain?.values)) {
    fail("activation plan deferred authority lacks one exact main-runtime domain");
  }
  const workerReleaseManifestSha256 = fixed(
    deferredMain.values.TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256,
    SHA256,
    "deferred Arena worker release-manifest digest",
  );
  const deferredReviewedAt = canonicalIsoSecond(
    deferredAuthority.reviewed_at,
    "deferred Arena authority review time",
  );
  const deferredValidUntil = canonicalIsoSecond(
    deferredAuthority.valid_until,
    "deferred Arena authority expiry time",
  );
  if (checkedAt < deferredReviewedAt || checkedAt >= deferredValidUntil
    || finalAuthority.release_sha !== projection.release_sha
    || finalAuthority.deployment_intent_sha256
      !== projection.deployment_intent_sha256
    || finalAuthority.cvm_launch_intent_sha256
      !== projection.cvm_launch_intent_sha256
    || launch.release_sha !== projection.release_sha
    || challengeProjection.releaseSha !== projection.release_sha
    || challengeProjection.finalAuthoritySha256
      !== projection.final_authority_sha256
    || plan.chain_id !== projection.chain_id
    || plan.release_sha !== projection.release_sha
    || plan.deployment_intent_sha256 !== projection.deployment_intent_sha256
    || plan.cvm_launch_intent_sha256 !== projection.cvm_launch_intent_sha256
    || plan.target.domain !== "main_runtime_cvm"
    || plan.target.app_id !== finalAuthority.cvm.app_id
    || plan.target.cvm_id !== finalAuthority.cvm.cvm_id
    || plan.target.compose_hash !== finalAuthority.cvm.compose_hash
    || plan.target.os_image_hash !== finalAuthority.cvm.os_image_hash
    || deferredAuthority.release_sha !== plan.release_sha
    || deferredAuthority.batch_id !== plan.batch_id
    || deferredAuthority.deployment_intent_sha256
      !== plan.deployment_intent_sha256
    || deferredAuthority.cvm_launch_intent_sha256
      !== plan.cvm_launch_intent_sha256
    || deferredAuthority.final_release_authority_sha256
      !== projection.final_authority_sha256) {
    fail("reviewed final authority, activation plan, and deferred Arena authority drifted");
  }
  const challengeBinding =
    finalAuthority.arena_registry_bindings[ARENA_WORKER_CHALLENGE_KEY];
  if (!isRecord(challengeBinding)) {
    fail("reviewed final authority does not approve the safe-IR Arena challenge");
  }
  const delegateImages = finalAuthority.cvm.images.filter(
    (entry) => entry.service === "delegate",
  );
  if (delegateImages.length !== 1) {
    fail("reviewed final authority lacks one exact delegate image");
  }
  const imageParts = delegateImages[0].image.split("@");
  if (imageParts.length !== 2 || !SHA256.test(imageParts[1])) {
    fail("reviewed final authority delegate image digest is malformed");
  }
  const environment = challengeProjection.environment;
  const deferredReleasePolicyCommitment = fixed(
    deferredMain.values.TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT,
    BYTES32,
    "deferred Arena worker release-policy commitment",
  );
  const deferredApprovedChallengeSetSha256 = fixed(
    deferredMain.values.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    SHA256,
    "deferred Arena approved challenge-set digest",
  );
  if (deferredReleasePolicyCommitment
      !== challengeBinding.release_policy_commitment
    || deferredApprovedChallengeSetSha256
      !== environment.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256) {
    fail("deferred Arena worker policy pins differ from reviewed authority");
  }
  const expectedReleaseBinding = normalizeReleaseBinding({
    release_sha: finalAuthority.release_sha,
    image_digest: imageParts[1],
    release_manifest_sha256: workerReleaseManifestSha256,
    approved_challenge_set_sha256:
      environment.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    approved_challenge_key: ARENA_WORKER_CHALLENGE_KEY,
    release_policy_commitment: challengeBinding.release_policy_commitment,
    catalog_manifest_hash: challengeBinding.catalog_manifest_hash,
    runtime: ARENA_WORKER_SAFE_IR_RUNTIME,
    runtime_policy_commitment: ARENA_WORKER_SAFE_IR_POLICY_COMMITMENT,
    compose_hash: finalAuthority.cvm.compose_hash,
    app_id: finalAuthority.cvm.app_id,
    os_image_hash: finalAuthority.cvm.os_image_hash,
  });
  let endpoint;
  try {
    endpoint = new URL(CAPABILITY_PATH, finalAuthority.cvm.delegate_url).href;
  } catch {
    fail("reviewed Arena worker capability endpoint is malformed");
  }
  const parsedEndpoint = new URL(endpoint);
  const reviewedOrigin = new URL(finalAuthority.cvm.delegate_url);
  if (parsedEndpoint.protocol !== "https:"
    || parsedEndpoint.origin !== reviewedOrigin.origin
    || parsedEndpoint.username || parsedEndpoint.password
    || parsedEndpoint.search || parsedEndpoint.hash
    || parsedEndpoint.pathname !== CAPABILITY_PATH) {
    fail("reviewed Arena worker capability endpoint is widened");
  }
  const endpointCommitmentSha256 =
    phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint);
  const expectedReleaseBindingSha256 =
    arenaWorkerReleaseBindingSha256(expectedReleaseBinding);
  const receiptReleaseBindingSha256 = phalaArenaWorkerReleaseBindingSha256(
    expectedReleaseBinding,
    {
      challengeId: ARENA_WORKER_CHALLENGE_ID,
      challengeVersion: ARENA_WORKER_CHALLENGE_VERSION,
    },
  );
  if (receiptReleaseBindingSha256 !== expectedReleaseBindingSha256) {
    fail("Arena worker cross-module release-binding digests disagree");
  }
  return deepFreezeCanonicalPlainDataGraph({
    projection,
    plan,
    endpoint,
    endpointCommitmentSha256,
    expectedReleaseBinding,
    expectedReleaseBindingSha256,
    globalImageReleaseManifestSha256: launch.image_release_manifest_sha256,
    workerReleaseManifestSha256,
  }, { label: "reviewed Arena worker activation authority" });
}

function responseSha256FromCanonicalText(value) {
  return byteSha256(Buffer.from(value, "ascii"));
}

function verifyCanonicalResponse({
  authority,
  checkedAt,
  postRestartAttestationObservedAt,
  responseText,
}) {
  const capability = normalizeArenaWorkerCapabilityV2Text(responseText);
  const postRestartAt = canonicalIsoSecond(
    postRestartAttestationObservedAt,
    "authenticated Phala post-restart attestation observation time",
  );
  if (capability.release_binding_sha256
      !== authority.expectedReleaseBindingSha256
    || canonicalAsciiJson(capability.release_binding)
      !== canonicalAsciiJson(authority.expectedReleaseBinding)) {
    fail("Arena worker capability differs from the reviewed release authority");
  }
  if (capability.heartbeat_observed_at <= postRestartAt) {
    fail(
      "Arena worker heartbeat is not strictly later than the authenticated Phala attestation observation",
    );
  }
  if (capability.heartbeat_observed_at > checkedAt
    || checkedAt - capability.heartbeat_observed_at
      > MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS) {
    fail("Arena worker heartbeat is not fresh at independent verification time");
  }
  const proof = normalizePhalaArenaWorkerPresenceActivationProof({
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: authority.endpointCommitmentSha256,
    challenge_id: ARENA_WORKER_CHALLENGE_ID,
    challenge_version: ARENA_WORKER_CHALLENGE_VERSION,
    response_sha256: responseSha256FromCanonicalText(responseText),
    release_binding_sha256: capability.release_binding_sha256,
    heartbeat_observed_at: capability.heartbeat_observed_at,
    verified_at: checkedAt,
  });
  const digest = phalaArenaWorkerPresenceActivationProofSha256(proof);
  VERIFIED_PROOFS.set(proof, Object.freeze({
    digest,
    reviewed_final_authority_runtime_projection: authority.projection,
    post_measurement_activation_plan: authority.plan,
    heartbeat_binding_sha256: capability.heartbeat_binding_sha256,
    expected_release_binding: authority.expectedReleaseBinding,
    receipt_production_brand: false,
  }));
  return proof;
}

/**
 * Fetch and verify one post-restart Arena worker presence report. The supplied
 * observation is authenticated Phala control-plane evidence with a quote
 * present, not an independently DCAP/QVL-verified TDX result. The caller
 * supplies no endpoint, response, clock, transport, HMAC key, or MAC. The URL
 * is derived only from the branded, reviewed final-authority dependency graph.
 */
export async function verifyArenaWorkerActivationCapability(input = {}) {
  const parsed = exactRecord(
    input,
    VERIFY_FIELDS,
    "Arena worker production verification input",
  );
  canonicalIsoSecond(
    parsed.postRestartAttestationObservedAt,
    "authenticated Phala post-restart attestation observation time",
  );
  const before = internalSecond();
  const authority = expectedAuthorityFromReviewedProjectionAndPlan(
    parsed.reviewedFinalAuthorityRuntimeProjection,
    parsed.postMeasurementActivationPlan,
    before,
  );
  const proof = await verifyProductionPhalaArenaWorkerPresenceActivation({
    endpoint: authority.endpoint,
    expectedEndpointCommitmentSha256: authority.endpointCommitmentSha256,
    expectedReleaseBindingSha256: authority.expectedReleaseBindingSha256,
    challengeId: ARENA_WORKER_CHALLENGE_ID,
    challengeVersion: ARENA_WORKER_CHALLENGE_VERSION,
  });
  assertFreshProductionPhalaArenaWorkerPresenceActivationProof(proof);
  const checkedAt = internalSecond();
  const recheckedAuthority = expectedAuthorityFromReviewedProjectionAndPlan(
    parsed.reviewedFinalAuthorityRuntimeProjection,
    parsed.postMeasurementActivationPlan,
    checkedAt,
  );
  if (recheckedAuthority.endpoint !== authority.endpoint
    || recheckedAuthority.endpointCommitmentSha256
      !== authority.endpointCommitmentSha256
    || recheckedAuthority.expectedReleaseBindingSha256
      !== authority.expectedReleaseBindingSha256) {
    fail("reviewed Arena worker authority changed during verification");
  }
  const postRestartAt = canonicalIsoSecond(
    parsed.postRestartAttestationObservedAt,
    "authenticated Phala post-restart attestation observation time",
  );
  if (proof.heartbeat_observed_at <= postRestartAt
    || proof.endpoint_commitment_sha256
      !== recheckedAuthority.endpointCommitmentSha256
    || proof.release_binding_sha256
      !== recheckedAuthority.expectedReleaseBindingSha256) {
    fail("Arena worker presence is not strictly post-restart and authority-bound");
  }
  const heartbeatBindingSha256 = arenaWorkerHeartbeatBindingSha256({
    challengeId: proof.challenge_id,
    challengeVersion: proof.challenge_version,
    heartbeatObservedAt: proof.heartbeat_observed_at,
    releaseBindingSha256: proof.release_binding_sha256,
  });
  VERIFIED_PROOFS.set(proof, Object.freeze({
    digest: phalaArenaWorkerPresenceActivationProofSha256(proof),
    reviewed_final_authority_runtime_projection:
      recheckedAuthority.projection,
    post_measurement_activation_plan: recheckedAuthority.plan,
    heartbeat_binding_sha256: heartbeatBindingSha256,
    expected_release_binding: recheckedAuthority.expectedReleaseBinding,
    receipt_production_brand: true,
  }));
  return proof;
}

export function assertVerifiedArenaWorkerActivationProof(value) {
  const provenance = value && VERIFIED_PROOFS.get(value);
  if (!provenance
    || provenance.digest !== phalaArenaWorkerPresenceActivationProofSha256(value)) {
    fail("Arena worker activation proof lacks live production provenance");
  }
  if (provenance.receipt_production_brand) {
    assertFreshProductionPhalaArenaWorkerPresenceActivationProof(value);
  }
  const checkedAt = internalSecond();
  const authority = expectedAuthorityFromReviewedProjectionAndPlan(
    provenance.reviewed_final_authority_runtime_projection,
    provenance.post_measurement_activation_plan,
    checkedAt,
    { allowTestPlan: !provenance.receipt_production_brand },
  );
  if (authority.endpointCommitmentSha256 !== value.endpoint_commitment_sha256
    || authority.expectedReleaseBindingSha256 !== value.release_binding_sha256
    || arenaWorkerReleaseBindingSha256(provenance.expected_release_binding)
      !== value.release_binding_sha256
    || arenaWorkerHeartbeatBindingSha256({
      challengeId: value.challenge_id,
      challengeVersion: value.challenge_version,
      heartbeatObservedAt: value.heartbeat_observed_at,
      releaseBindingSha256: value.release_binding_sha256,
    }) !== provenance.heartbeat_binding_sha256
    || value.verified_at > checkedAt + MAX_ARENA_WORKER_FUTURE_SKEW_SECONDS
    || value.heartbeat_observed_at > checkedAt
    || checkedAt - value.heartbeat_observed_at
      > MAX_ARENA_WORKER_HEARTBEAT_AGE_SECONDS) {
    fail("Arena worker activation proof is no longer current or authority-bound");
  }
  return value;
}

export function readVerifiedArenaWorkerActivationProofDependencies(value) {
  const proof = assertVerifiedArenaWorkerActivationProof(value);
  const provenance = VERIFIED_PROOFS.get(proof);
  return Object.freeze({
    reviewed_final_authority_runtime_projection:
      provenance.reviewed_final_authority_runtime_projection,
    post_measurement_activation_plan:
      provenance.post_measurement_activation_plan,
    heartbeat_binding_sha256: provenance.heartbeat_binding_sha256,
    expected_release_binding: provenance.expected_release_binding,
  });
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

function createTestActivationPlan(input = {}) {
  if (!isExactNodeTestEntrypoint()) {
    fail("synthetic Arena worker verification is available only inside node --test");
  }
  const parsed = exactRecord(input, [
    "checkedAt",
    "reviewedFinalAuthorityRuntimeProjection",
    "workerReleaseManifestSha256",
  ], "test-only Arena activation-plan input");
  const checkedAt = boundedSecond(parsed.checkedAt, "test activation-plan time");
  const projection = assertReviewedFinalAuthorityRuntimeProjection(
    parsed.reviewedFinalAuthorityRuntimeProjection,
  );
  const reviewedDependencies =
    readReviewedFinalAuthorityRuntimeDependencies(projection);
  reviewWindow(reviewedDependencies, checkedAt);
  const finalAuthority = reviewedDependencies.final_authority;
  const challengeProjection =
    reviewedDependencies.challenge_registry_runtime_environment_projection;
  const challengeBinding =
    finalAuthority.arena_registry_bindings[ARENA_WORKER_CHALLENGE_KEY];
  if (!isRecord(challengeBinding)) {
    fail("test reviewed authority omits the safe-IR Arena challenge");
  }
  const workerReleaseManifestSha256 = fixed(
    parsed.workerReleaseManifestSha256,
    SHA256,
    "test Arena worker release-manifest digest",
  );
  const reviewedAt = checkedAt - 1;
  const validUntil = checkedAt + 600;
  const batchId = `sha256:${"fe".repeat(32)}`;
  const plan = deepFreezeCanonicalPlainDataGraph({
    schema: "dnai.test-only.arena-post-measurement-activation-plan.v1",
    chain_id: projection.chain_id,
    release_sha: projection.release_sha,
    batch_id: batchId,
    deployment_intent_sha256: projection.deployment_intent_sha256,
    cvm_launch_intent_sha256: projection.cvm_launch_intent_sha256,
    target: {
      domain: "main_runtime_cvm",
      app_id: finalAuthority.cvm.app_id,
      cvm_id: finalAuthority.cvm.cvm_id,
      compose_hash: finalAuthority.cvm.compose_hash,
      os_image_hash: finalAuthority.cvm.os_image_hash,
    },
    activation_evidence_lease_expires_at: validUntil,
  }, { label: "test-only Arena activation plan" });
  const deferredAuthority = deepFreezeCanonicalPlainDataGraph({
    schema: "dnai.test-only.arena-deferred-authority.v1",
    release_sha: projection.release_sha,
    batch_id: batchId,
    deployment_intent_sha256: projection.deployment_intent_sha256,
    cvm_launch_intent_sha256: projection.cvm_launch_intent_sha256,
    final_release_authority_sha256: projection.final_authority_sha256,
    reviewed_at: instantFromSecond(reviewedAt),
    valid_until: instantFromSecond(validUntil),
    domains: [{
      domain: "main_runtime_cvm",
      values: {
        TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
          challengeProjection.environment
            .TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
        TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256:
          workerReleaseManifestSha256,
        TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT:
          challengeBinding.release_policy_commitment,
      },
    }],
  }, { label: "test-only Arena deferred authority" });
  TEST_ACTIVATION_PLANS.set(plan, Object.freeze({
    digest: domainSha256(TEST_ACTIVATION_PLAN_DOMAIN, plan),
    reviewed_at: reviewedAt,
    valid_until: validUntil,
    deferred_authority: deferredAuthority,
  }));
  return plan;
}

function instantFromSecond(value) {
  return new Date(value * 1_000).toISOString().replace(".000Z", "Z");
}

function testAuthority(projection, plan, checkedAt) {
  if (!isExactNodeTestEntrypoint()) {
    fail("synthetic Arena worker verification is available only inside node --test");
  }
  return expectedAuthorityFromReviewedProjectionAndPlan(
    projection,
    plan,
    checkedAt,
    { allowTestPlan: true },
  );
}

function testVerifyCanonicalResponse(input = {}) {
  if (!isExactNodeTestEntrypoint()) {
    fail("synthetic Arena worker verification is available only inside node --test");
  }
  const parsed = exactRecord(input, [
    "checkedAt",
    "postMeasurementActivationPlan",
    "postRestartAttestationObservedAt",
    "responseText",
    "reviewedFinalAuthorityRuntimeProjection",
  ], "synthetic Arena worker verification input");
  const checkedAt = boundedSecond(parsed.checkedAt, "synthetic verification time");
  const authority = expectedAuthorityFromReviewedProjectionAndPlan(
    parsed.reviewedFinalAuthorityRuntimeProjection,
    parsed.postMeasurementActivationPlan,
    checkedAt,
    { allowTestPlan: true },
  );
  return verifyCanonicalResponse({
    authority,
    checkedAt,
    postRestartAttestationObservedAt:
      parsed.postRestartAttestationObservedAt,
    responseText: parsed.responseText,
  });
}

export const __test = Object.freeze({
  createTestActivationPlan,
  expectedAuthorityFromReviewedProjectionAndPlan: testAuthority,
  verifyCanonicalResponse: testVerifyCanonicalResponse,
});
