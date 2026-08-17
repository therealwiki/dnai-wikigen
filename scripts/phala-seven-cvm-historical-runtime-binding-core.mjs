import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

/**
 * Clock-free projection of the launch facts carried by a separately
 * authenticated pre-ceremony runtime authority (R).
 *
 * The value is deliberately unbranded. Normalizing or hashing it does not
 * refresh machine evidence, establish a production dependency, or authorize
 * a Phala mutation. Historical L reconstruction may consume it only after the
 * enclosing signed-B/signed-C verifier authenticates the complete persisted R.
 */
export const PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA =
  "dnai.phala-seven-cvm-historical-runtime-binding.v3";
export const PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-historical-runtime-binding/v3\0";
export const PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH =
  "projected_from_separately_normalized_persisted_r_with_exact_release_authority_and_activation_evidence_lease_not_standalone_authority_or_freshness";

const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const RUNTIME_CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

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

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`${label} is not canonical fixed-width lowercase data`);
  }
  return value;
}

function timestamp(value, label) {
  const milliseconds = typeof value === "string" ? Date.parse(value) : NaN;
  if (typeof value !== "string" || !ISO_SECOND.test(value)
    || !Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    throw new TypeError(`${label} must be a canonical UTC second`);
  }
  return value;
}

function epochSecond(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    throw new TypeError(`${label} must be a bounded Unix second`);
  }
  return value;
}

export function normalizePhalaSevenCvmHistoricalRuntimeBinding(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "historical R launch binding input",
  });
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "release_sha",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "release_verification_authority",
    "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "batch_id",
    "seven_cvm_verified_evidence_set_sha256",
    "main_runtime_target",
    "activation_plan_created_at",
    "machine_verifier_evidence_issued_at",
    "activation_evidence_lease_expires_at",
  ], "historical R launch binding");
  if (parsed.schema !== PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA
    || parsed.truth_status !== PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH) {
    throw new TypeError("historical R launch binding boundary is invalid");
  }

  const releaseSha = fixed(
    parsed.release_sha,
    SHA40,
    "historical R release SHA",
  );
  const deploymentIntentSha256 = digest(
    parsed.deployment_intent_sha256,
    "historical R deployment intent",
  );
  const releaseAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority(
      parsed.release_verification_authority,
    );
  const releaseAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  if (releaseAuthority.evidence_mode
      !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE
    || digest(
    parsed.release_verification_authority_sha256,
    "historical R release verification authority",
  ) !== releaseAuthoritySha256
    || releaseAuthority.release_sha !== releaseSha
    || releaseAuthority.deployment_intent_sha256 !== deploymentIntentSha256) {
    throw new TypeError(
      "historical R release verification authority is nonproduction or its lineage drifted",
    );
  }

  const target = exactRecord(parsed.main_runtime_target, [
    "domain",
    "descriptor_sha256",
    "app_id",
    "cvm_id",
    "compose_hash",
    "os_image_hash",
  ], "historical R main-runtime target");
  if (target.domain !== "main_runtime_cvm") {
    throw new TypeError("historical R main-runtime target is invalid");
  }
  const normalizedTarget = {
    domain: "main_runtime_cvm",
    descriptor_sha256: digest(
      target.descriptor_sha256,
      "historical R main descriptor",
    ),
    app_id: fixed(target.app_id, APP_ID, "historical R main app ID"),
    cvm_id: fixed(target.cvm_id, RUNTIME_CVM_ID, "historical R main CVM ID"),
    compose_hash: fixed(
      target.compose_hash,
      BARE_SHA256,
      "historical R main compose hash",
    ),
    os_image_hash: fixed(
      target.os_image_hash,
      BARE_SHA256,
      "historical R main OS image hash",
    ),
  };
  if (normalizedTarget.os_image_hash
      !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash) {
    throw new TypeError(
      "historical R main-runtime target OS image is outside the reviewed catalog",
    );
  }
  const mainReleaseDescriptor = releaseAuthority.descriptors.find(
    (descriptor) => descriptor.domain === "main_runtime_cvm",
  );
  if (!mainReleaseDescriptor
    || mainReleaseDescriptor.descriptor_sha256
      !== normalizedTarget.descriptor_sha256
    || mainReleaseDescriptor.app_id !== normalizedTarget.app_id
    || mainReleaseDescriptor.cvm_id !== normalizedTarget.cvm_id
    || mainReleaseDescriptor.compose_hash !== normalizedTarget.compose_hash
    || mainReleaseDescriptor.os_image_hash !== normalizedTarget.os_image_hash) {
    throw new TypeError(
      "historical R main-runtime target differs from embedded release authority",
    );
  }

  const activationPlanCreatedAt = timestamp(
    parsed.activation_plan_created_at,
    "historical R activation-plan created_at",
  );
  const activationEvidenceLeaseExpiresAt = epochSecond(
    parsed.activation_evidence_lease_expires_at,
    "historical R activation-evidence lease expires_at",
  );
  const machineVerifierEvidenceIssuedAt = epochSecond(
    parsed.machine_verifier_evidence_issued_at,
    "historical R machine-verifier evidence issued_at",
  );
  if (activationEvidenceLeaseExpiresAt
      <= Math.floor(Date.parse(activationPlanCreatedAt) / 1_000)
    || machineVerifierEvidenceIssuedAt >= activationEvidenceLeaseExpiresAt) {
    throw new TypeError("historical R activation-evidence lease is invalid");
  }

  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: digest(
      parsed.cvm_launch_intent_sha256,
      "historical R CVM launch intent",
    ),
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256: releaseAuthoritySha256,
    seven_cvm_launch_completion_receipt_sha256: digest(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "historical R seven-CVM completion receipt",
    ),
    phala_recovery_directory_identity_anchor_sha256: digest(
      parsed.phala_recovery_directory_identity_anchor_sha256,
      "historical R recovery-directory identity anchor",
    ),
    batch_id: digest(parsed.batch_id, "historical R launch batch"),
    seven_cvm_verified_evidence_set_sha256: digest(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "historical R seven-CVM evidence set",
    ),
    main_runtime_target: normalizedTarget,
    activation_plan_created_at: activationPlanCreatedAt,
    machine_verifier_evidence_issued_at: machineVerifierEvidenceIssuedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
  }, { label: "historical R launch binding" });
}

export function canonicalPhalaSevenCvmHistoricalRuntimeBindingText(value) {
  return `${JSON.stringify(
    sorted(normalizePhalaSevenCvmHistoricalRuntimeBinding(value)),
    null,
    2,
  )}\n`;
}

export function phalaSevenCvmHistoricalRuntimeBindingSha256(value) {
  return `sha256:${createHash("sha256")
    .update(PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_DOMAIN, "utf8")
    .update(canonicalPhalaSevenCvmHistoricalRuntimeBindingText(value), "utf8")
    .digest("hex")}`;
}
