import {
  FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";

export const COLLABORATION_EXECUTION_RELEASE_ENV_KEYS = Object.freeze([
  "VITE_FINAL_RELEASE_AUTHORITY_SHA256",
  "VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256",
  "VITE_COLLABORATION_EXECUTION_SERVICE",
  "VITE_COLLABORATION_EXECUTION_PROFILE",
  "VITE_COLLABORATION_EXECUTION_RELEASE_SHA",
  "VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID",
  "VITE_COLLABORATION_EXECUTION_ENABLED",
  "VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256",
  "VITE_ROYALTY_RELEASE_HISTORY_SHA256",
  "VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256",
  "VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED",
]);

const RELEASE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;

function fail(message) {
  throw new TypeError(message);
}

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...keys].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function pin(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero SHA-256 pin`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function booleanString(value, label) {
  if (value !== "true" && value !== "false") {
    fail(`${label} must be a canonical boolean string`);
  }
  return value;
}

export function projectCollaborationExecutionReleaseEnv(value) {
  const core = normalizeFinalReleaseAuthorityCore(value);
  if (core.schema !== FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA) {
    fail("Collaboration execution release env requires current final authority v4");
  }
  return Object.freeze({
    VITE_FINAL_RELEASE_AUTHORITY_SHA256:
      `sha256:${finalReleaseAuthorityCoreDigest(core)}`,
    VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256:
      core.collaboration_execution.release_verification_sha256,
    VITE_COLLABORATION_EXECUTION_SERVICE:
      core.collaboration_execution.service,
    VITE_COLLABORATION_EXECUTION_PROFILE:
      core.collaboration_execution.profile,
    VITE_COLLABORATION_EXECUTION_RELEASE_SHA:
      core.collaboration_execution.release_sha,
    VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID: core.cvm.cvm_id,
    VITE_COLLABORATION_EXECUTION_ENABLED:
      String(core.collaboration_execution.enabled),
    VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256:
      core.royalty_release_active_state_sha256,
    VITE_ROYALTY_RELEASE_HISTORY_SHA256:
      core.royalty_release_history_sha256,
    VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256:
      core.royalty_release_history_receipt_sha256,
    VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED:
      String(core.compute_workload_wallet_adoption.enabled),
  });
}

export function normalizeCollaborationExecutionReleaseEnv(env, expected = {}) {
  const parsed = exact(
    Object.fromEntries(COLLABORATION_EXECUTION_RELEASE_ENV_KEYS.map((key) => [
      key,
      env?.[key],
    ])),
    COLLABORATION_EXECUTION_RELEASE_ENV_KEYS,
    "Collaboration execution release env",
  );
  const normalized = {
    VITE_FINAL_RELEASE_AUTHORITY_SHA256: pin(
      parsed.VITE_FINAL_RELEASE_AUTHORITY_SHA256,
      "final release authority digest",
    ),
    VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256: pin(
      parsed.VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256,
      "Collaboration release verification digest",
    ),
    VITE_COLLABORATION_EXECUTION_SERVICE: exactString(
      parsed.VITE_COLLABORATION_EXECUTION_SERVICE,
      "collaboration-execution-worker",
      "Collaboration execution service",
    ),
    VITE_COLLABORATION_EXECUTION_PROFILE: exactString(
      parsed.VITE_COLLABORATION_EXECUTION_PROFILE,
      "collaboration-execution",
      "Collaboration execution profile",
    ),
    VITE_COLLABORATION_EXECUTION_RELEASE_SHA:
      parsed.VITE_COLLABORATION_EXECUTION_RELEASE_SHA,
    VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID:
      parsed.VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID,
    VITE_COLLABORATION_EXECUTION_ENABLED: booleanString(
      parsed.VITE_COLLABORATION_EXECUTION_ENABLED,
      "Collaboration execution feature decision",
    ),
    VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256: pin(
      parsed.VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256,
      "Royalty active-state digest",
    ),
    VITE_ROYALTY_RELEASE_HISTORY_SHA256: pin(
      parsed.VITE_ROYALTY_RELEASE_HISTORY_SHA256,
      "Royalty history digest",
    ),
    VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256: pin(
      parsed.VITE_ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256,
      "Royalty H receipt digest",
    ),
    VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED: booleanString(
      parsed.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED,
      "compute-workload wallet-adoption decision",
    ),
  };
  if (!RELEASE_SHA.test(String(normalized.VITE_COLLABORATION_EXECUTION_RELEASE_SHA || ""))
    || !CVM_ID.test(String(normalized.VITE_COLLABORATION_EXECUTION_MAIN_RUNTIME_CVM_ID || ""))) {
    fail("Collaboration execution release SHA or main-runtime CVM ID is invalid");
  }
  for (const [key, expectedValue] of Object.entries(expected)) {
    if (!COLLABORATION_EXECUTION_RELEASE_ENV_KEYS.includes(key)
      || expectedValue !== undefined && normalized[key] !== expectedValue) {
      fail(`Collaboration execution release env ${key} drifted from current semantic authority`);
    }
  }
  return Object.freeze(normalized);
}
