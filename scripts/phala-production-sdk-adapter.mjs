import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";

import {
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  buildPhalaContractKmsProjection,
  normalizePhalaKmsContract,
  assertPhalaWorkspaceActiveBilling,
} from "./phala-contract-kms-core.mjs";
import { projectPhalaAppComposeWire } from "./phala-app-compose-wire-core.mjs";
import { assertProductionCvmPosture } from "./phala-production-posture-core.mjs";
import { assertVerifiedProductionCvmPostureReceipt } from "./phala-production-posture-receipt.mjs";
import {
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_POLICY,
} from "./phala-production-execution-policy.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertImmediateSignedEnvironmentKeyRefetch,
  assertPreparedCvmObservation,
  assertRecoveredSignedEnvironmentKey,
  dstackCanonicalComposeHash,
  normalizeSignedEnvironmentKeyResponse,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_API_CANDIDATE_VERSIONS,
  PHALA_CLOUD_SDK_VERSION,
  PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
  PHALA_DSTACK_SDK_VERSION,
  PHALA_READ_ONLY_COMPATIBILITY_CALLS,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
  canonicalPhalaSdkWireTransformStagingReceiptText,
  assertSecretFreePhalaAuthorityArtifact,
} from "./phala-production-target-authority.mjs";
import {
  assertPinnedPhalaPrivateDirectoryPathIdentity,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  listPhalaPinnedPrivateEntries,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY,
  PHALA_SDK_ACTION_REQUEST_POLICY_SHA256,
  assertReviewedPhalaSdkRuntimeCapsuleIdentity,
  importReviewedPhalaSdkRuntimeCapsule,
  loadReviewedPhalaSdkRuntimeCapsule,
} from "./phala-sdk-runtime-capsule.mjs";

export const PHALA_PINNED_PACKAGE_IDENTITY_SCHEMA =
  "dnai.phala-pinned-sdk-runtime-capsule-identity.v2";
export const PHALA_PINNED_CLOUD_NPM_DIST_INTEGRITY =
  "sha512-Fp8C/dTXZgG/wcAGU1lOcShPciqd0dFwgDeLXZDUTG/uOcNMl+P4yOzS+KYR84GUI8+f68VcoMLAg/RInC2ygQ==";
export const PHALA_PINNED_CLOUD_NPM_DIST_SHASUM =
  "03edbbb7b9955498b11146377c6e47d99000da8b";
export const PHALA_PINNED_CLIENT_TRANSPORT = Object.freeze({
  timeout_ms: 20_000,
  retry: 0,
  redirect: "error",
});
export const PHALA_AUTHENTICATED_ACCOUNT_SUBJECT_SCHEMA =
  "dnai.phala-authenticated-account-subject.v1";
export const PHALA_AUTHENTICATED_ACCOUNT_SUBJECT_DOMAIN =
  "dnai-wikigen/phala-authenticated-account-subject/v1\0";
export const PHALA_PRODUCTION_SDK_ADAPTER_IDENTITY_SCHEMA =
  "dnai.phala-production-sdk-adapter-identity.v1";
export const PHALA_PRODUCTION_SDK_ADAPTER_IDENTITY_DOMAIN =
  "dnai-wikigen/phala-production-sdk-adapter-identity/v1\0";
export const PHALA_AUTHENTICATED_SDK_OBSERVATION_SCHEMA =
  "dnai.phala-authenticated-sdk-observation.v1";
export const PHALA_AUTHENTICATED_SDK_OBSERVATION_DOMAIN =
  "dnai-wikigen/phala-authenticated-sdk-observation/v1\0";
export const PHALA_AUTHENTICATED_SDK_REQUEST_DOMAIN =
  "dnai-wikigen/phala-authenticated-sdk-request/v1\0";
export const PHALA_PRODUCTION_MUTATION_METHODS = Object.freeze([
  // Despite its GET transport, this action reserves identifiers remotely.
  "nextAppIds",
  "provisionCvm",
  "commitCvmProvision",
  "updateCvmEnvs",
  "restartCvm",
]);
export const PHALA_PRODUCTION_READ_ONLY_METHODS = Object.freeze([
  "getCurrentUser",
  "getCvmList",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
  "getKmsContract",
  "listKmsContracts",
  "listKmsContractNodes",
  "getWorkspace",
  "getAppEnvEncryptPubKey",
  "getCvmInfo",
  "getCvmAttestation",
]);
export const PHALA_SDK_ACTION_REQUEST_POLICY_DOMAIN =
  "dnai-wikigen/phala-sdk-action-request-policy/v1\0";
const PHALA_SDK_ACTION_VERSION_OVERRIDES = Object.freeze({
  getAppEnvEncryptPubKey: "2026-05-22",
  getKmsInfo: "2026-05-22",
  getKmsList: "2026-05-22",
  getKmsContract: "2026-06-23",
  listKmsContracts: "2026-06-23",
  listKmsContractNodes: "2026-06-23",
});
export const PHALA_SDK_ACTION_REQUEST_POLICY = Object.freeze([
  Object.freeze({ action: "commitCvmProvision", http_method: "POST", request_target: "/api/v1/cvms", body_policy: "exact_projected_action_argument" }),
  Object.freeze({ action: "getAppEnvEncryptPubKey", http_method: "GET", request_target: "/api/v1/kms/{kms}/pubkey/{app_id}", body_policy: "absent" }),
  Object.freeze({ action: "getCvmAttestation", http_method: "GET", request_target: "/api/v1/cvms/{sdk_normalized_cvm_id}/attestation", body_policy: "absent" }),
  Object.freeze({ action: "getCvmCreateResources", http_method: "GET", request_target: "/api/v1/teepods/cvm-create-resources", body_policy: "absent" }),
  Object.freeze({ action: "getCvmInfo", http_method: "GET", request_target: "/api/v1/cvms/{sdk_normalized_cvm_id}", body_policy: "absent" }),
  Object.freeze({ action: "getCvmList", http_method: "GET", request_target: "/api/v1/cvms/paginated?page=1&page_size=100", body_policy: "absent" }),
  Object.freeze({ action: "getCurrentUser", http_method: "GET", request_target: "/api/v1/auth/me", body_policy: "absent" }),
  Object.freeze({ action: "getKmsContract", http_method: "GET", request_target: "/api/v1/kms/{slug}", body_policy: "absent" }),
  Object.freeze({ action: "getKmsInfo", http_method: "GET", request_target: "/api/v1/kms/{kms_id}", body_policy: "absent" }),
  Object.freeze({ action: "getKmsList", http_method: "GET", request_target: "/api/v1/kms?page=1&page_size=100&is_onchain=false", body_policy: "absent" }),
  Object.freeze({ action: "getOsImages", http_method: "GET", request_target: "/api/v1/os-images?page=1&page_size=100&is_dev=false", body_policy: "absent" }),
  Object.freeze({ action: "getWorkspace", http_method: "GET", request_target: "/api/v1/workspaces/{workspace_slug}", body_policy: "absent" }),
  Object.freeze({ action: "listKmsContractNodes", http_method: "GET", request_target: "/api/v1/kms/{slug}/nodes", body_policy: "absent" }),
  Object.freeze({ action: "listKmsContracts", http_method: "GET", request_target: "/api/v1/kms?page=1&page_size=100&is_onchain=false", body_policy: "absent" }),
  Object.freeze({ action: "nextAppIds", http_method: "GET", request_target: "/api/v1/kms/phala/next_app_id?counts=7", body_policy: "absent" }),
  Object.freeze({ action: "provisionCvm", http_method: "POST", request_target: "/api/v1/cvms/provision", body_policy: "exact_reviewed_gateway_transform" }),
  Object.freeze({ action: "restartCvm", http_method: "POST", request_target: "/api/v1/cvms/{sdk_normalized_cvm_id}/restart", body_policy: "exact_force_false" }),
  Object.freeze({ action: "updateCvmEnvs", http_method: "PATCH", request_target: "/api/v1/cvms/{sdk_normalized_cvm_id}/envs", body_policy: "exact_encrypted_env_only" }),
].map((entry) => Object.freeze({
  ...entry,
  api_version_header: PHALA_SDK_ACTION_VERSION_OVERRIDES[entry.action] ?? null,
})));

const MAX_MANIFEST_BYTES = 65_536;
const MAX_CREDENTIAL_BYTES = 65_536;
const MAX_HTTP_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_HTTP_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_JSON_NODES = 100_000;
const MAX_JSON_DEPTH = 64;
const PINNED_IDENTITY = new WeakSet();
const PINNED_RUNTIME_STATE = new WeakMap();
const PHALA_ORIGIN = "https://cloud-api.phala.network/api/v1";
const PHALA_HOST = "cloud-api.phala.network";
const PRODUCTION_ADAPTERS = new WeakMap();
const AUTHENTICATED_OBSERVATIONS = new WeakMap();
const PRE_PROVISION_STAGING_SESSIONS = new WeakMap();
const REQUIRED_CLOUD_ACTION_EXPORTS = Object.freeze([
  "getCurrentUser",
  "getCvmList",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
  "getKmsContract",
  "listKmsContracts",
  "listKmsContractNodes",
  "getWorkspace",
  "nextAppIds",
  "provisionCvm",
  "getAppEnvEncryptPubKey",
  "commitCvmProvision",
  "updateCvmEnvs",
  "restartCvm",
  "getCvmInfo",
  "getCvmAttestation",
]);
const HISTORICAL_CONTINUITY_READ_ONLY_METHODS = Object.freeze([
  "getCurrentUser",
  "getAppEnvEncryptPubKey",
  "getCvmInfo",
  "getCvmAttestation",
]);

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function resolvePinnedPhalaPackageIdentity() {
  if (phalaSdkActionRequestPolicySha256()
      !== PHALA_SDK_ACTION_REQUEST_POLICY_SHA256) {
    throw new Error("Phala SDK action request policy differs from its reviewed static pin");
  }
  const capsule = loadReviewedPhalaSdkRuntimeCapsule();
  assertReviewedPhalaSdkRuntimeCapsuleIdentity(capsule);
  const identity = Object.freeze({
    schema: PHALA_PINNED_PACKAGE_IDENTITY_SCHEMA,
    source:
      "reviewed_static_capsule_bytes_loaded_by_data_url_no_path_or_global_package_resolution",
    sdk_identity: PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY,
    cloud: Object.freeze({
      module_sha256:
        PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY.phala_cloud_source_module_sha256,
      npm_dist_integrity_sha512:
        PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY.phala_cloud_npm_dist_integrity_sha512,
    }),
    dstack: Object.freeze({
      compose_hash_module_sha256:
        PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY.dstack_source_compose_hash_module_sha256,
      encryption_module_sha256:
        PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY.dstack_source_encryption_module_sha256,
    }),
  });
  PINNED_IDENTITY.add(identity);
  PINNED_RUNTIME_STATE.set(identity, Object.freeze({
    capsule,
    httpsRequest: https.request.bind(https),
    now: Date.now.bind(Date),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
  }));
  return identity;
}

function requirePinnedIdentity(identity) {
  if (!identity || !PINNED_IDENTITY.has(identity)
    || !PINNED_RUNTIME_STATE.has(identity)) {
    throw new Error("a locally verified reviewed SDK runtime capsule is required");
  }
  return PINNED_RUNTIME_STATE.get(identity);
}

export function projectPinnedSdkCompatibilityIdentity(identity) {
  requirePinnedIdentity(identity);
  return PHALA_REVIEWED_SDK_COMPATIBILITY_IDENTITY;
}

export function assertSafePhalaSdkProcessEnvironment(environment = process.env) {
  if (!isRecord(environment)) throw new Error("process environment is invalid");
  const forbidden = [
    "DEBUG",
    "DEBUG_FD",
    "NODE_DEBUG",
    "NODE_DEBUG_NATIVE",
    "NODE_OPTIONS",
    "PHALA_DEBUG",
    "PHALA_CLOUD_API_KEY",
    "PHALA_CLOUD_API_PREFIX",
    "PHALA_CLOUD_DIR",
  ];
  if (forbidden.some((name) => (
    typeof environment[name] === "string" && environment[name].trim() !== ""
  ))) {
    throw new Error(
      "SDK debug, instrumentation, credential, origin, and credential-directory environment overrides must be absent",
    );
  }
  return true;
}

export function assertPinnedPhalaClientTransport(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify(["baseURL", "redirect", "retry", "timeout", "version"].sort())
    || value.baseURL !== PHALA_ORIGIN
    || value.timeout !== PHALA_PINNED_CLIENT_TRANSPORT.timeout_ms
    || value.retry !== 0 || value.redirect !== "error"
    || !PHALA_API_CANDIDATE_VERSIONS.includes(value.version)) {
    throw new Error("Phala client transport is not exact, no-redirect, and no-retry");
  }
  return Object.freeze({ ...value });
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain the exact pinned fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalCompact(value) {
  return JSON.stringify(sortedObject(value));
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from(canonicalCompact(value), "utf8"))
    .digest("hex")}`;
}

export function phalaSdkActionRequestPolicySha256() {
  return domainDigest(
    PHALA_SDK_ACTION_REQUEST_POLICY_DOMAIN,
    PHALA_SDK_ACTION_REQUEST_POLICY,
  );
}

function canonicalInternalTimestamp(nowMs = Date.now()) {
  if (!Number.isFinite(nowMs)) throw new Error("internal clock is unavailable");
  return new Date(Math.floor(nowMs / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function assertBoundedJsonGraph(value, {
  label = "JSON value",
  maxNodes = MAX_JSON_NODES,
  maxDepth = MAX_JSON_DEPTH,
} = {}) {
  let nodes = 0;
  let stringBytes = 0;
  const ancestors = new WeakSet();

  function visit(current, depth) {
    nodes += 1;
    if (nodes > maxNodes || depth > maxDepth) {
      throw new Error(`${label} exceeds the bounded JSON graph policy`);
    }
    if (current === null || typeof current === "boolean") return;
    if (typeof current === "number") {
      if (!Number.isFinite(current) || Object.is(current, -0)) {
        throw new Error(`${label} contains a non-canonical JSON number`);
      }
      return;
    }
    if (typeof current === "string") {
      stringBytes += Buffer.byteLength(current, "utf8");
      if (stringBytes > MAX_HTTP_RESPONSE_BYTES) {
        throw new Error(`${label} contains too much string data`);
      }
      return;
    }
    if (typeof current !== "object") {
      throw new Error(`${label} contains a non-JSON value`);
    }
    if (ancestors.has(current)) throw new Error(`${label} contains a cycle`);
    const prototype = Object.getPrototypeOf(current);
    if (Array.isArray(current)) {
      if (prototype !== Array.prototype || current.length > maxNodes) {
        throw new Error(`${label} contains a non-canonical or oversized array`);
      }
    } else if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`${label} contains a non-plain object`);
    }
    const reflectedKeys = Reflect.ownKeys(current);
    const keys = Array.isArray(current)
      ? reflectedKeys.filter((key) => key !== "length")
      : reflectedKeys;
    if (keys.some((key) => typeof key !== "string")
      || keys.length > maxNodes
      || (Array.isArray(current)
        && (keys.length !== current.length
          || keys.some((key, index) => key !== String(index))))
      || (!Array.isArray(current)
        && keys.some((key) => key === "__proto__" || key === "prototype"
          || key === "constructor"))) {
      throw new Error(`${label} contains forbidden object keys`);
    }
    ancestors.add(current);
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(current, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
        throw new Error(`${label} contains an accessor or hidden property`);
      }
      visit(descriptor.value, depth + 1);
    }
    ancestors.delete(current);
  }

  visit(value, 0);
  return value;
}

function exactSafeText(value, label, maximum = 512) {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${label} must be bounded nonempty text`);
  }
  return value;
}

function exactCanonicalIdentifier(value, label) {
  if (typeof value !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(value)) {
    throw new Error(`${label} must be a canonical identifier`);
  }
  return value;
}

function exactDomain(value, label) {
  if (!PHALA_EXECUTION_ORDER.includes(value)) {
    throw new Error(`${label} is not an exact seven-CVM domain`);
  }
  return value;
}

function exactAppId(value, label) {
  const normalized = typeof value === "string"
    ? value.replace(/^0x/, "").toLowerCase()
    : "";
  if (!/^(?!0{40}$)[0-9a-f]{40}$/.test(normalized)) {
    throw new Error(`${label} must be an exact nonzero app id`);
  }
  return normalized;
}

function exactSortedEnvironmentKeys(value, label) {
  if (!Array.isArray(value) || value.length > 512) {
    throw new Error(`${label} must be a bounded array`);
  }
  const normalized = value.map((entry, index) => {
    if (typeof entry !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(entry)) {
      throw new Error(`${label}[${index}] is invalid`);
    }
    return entry;
  });
  if (canonicalCompact(normalized) !== canonicalCompact([...new Set(normalized)].sort())) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return normalized;
}

function sameSecret(left, right) {
  const leftBytes = Buffer.from(left, "utf8");
  const rightBytes = Buffer.from(right, "utf8");
  return leftBytes.length === rightBytes.length
    && timingSafeEqual(leftBytes, rightBytes);
}

function statFingerprint(stat) {
  return [stat.dev, stat.ino, stat.uid, stat.gid, stat.mode, stat.size,
    stat.mtimeMs, stat.ctimeMs].join(":");
}

function assertPrivateDirectory(directory) {
  const before = fs.lstatSync(directory);
  if (before.isSymbolicLink() || !before.isDirectory()
    || before.uid !== process.getuid()
    || (before.mode & 0o777) !== 0o700
    || fs.realpathSync(directory) !== path.resolve(directory)) {
    throw new Error("canonical Phala credential directory must be owned, 0700, and non-symlinked");
  }
  return before;
}

function normalizeCredentialProfile(profile, profileName) {
  const parsed = exactRecord(profile, [
    "token",
    "api_prefix",
    "workspace",
    "user",
    "updated_at",
  ], `canonical Phala credential profile ${profileName}`);
  if (typeof parsed.token !== "string"
    || !/^phak_[A-Za-z0-9_-]{16,512}$/.test(parsed.token)) {
    throw new Error("canonical Phala credential profile has no valid API credential");
  }
  if (parsed.api_prefix !== PHALA_ORIGIN) {
    throw new Error("canonical Phala credential profile API origin is not exact");
  }
  const workspace = exactRecord(parsed.workspace, ["name", "slug"],
    "canonical Phala credential workspace");
  const user = exactRecord(parsed.user, ["username", "email"],
    "canonical Phala credential user");
  const updatedAt = exactSafeText(parsed.updated_at, "credential updated_at", 64);
  if (!Number.isFinite(Date.parse(updatedAt))) {
    throw new Error("credential updated_at is invalid");
  }
  return Object.freeze({
    profile_name: profileName,
    api_key: parsed.token,
    api_origin: PHALA_ORIGIN,
    workspace: Object.freeze({
      name: exactSafeText(workspace.name, "credential workspace.name", 256),
      slug: exactCanonicalIdentifier(workspace.slug, "credential workspace.slug"),
    }),
    user: Object.freeze({
      username: exactSafeText(user.username, "credential user.username", 256),
      email: exactSafeText(user.email, "credential user.email", 512),
    }),
    updated_at: updatedAt,
  });
}

function readCanonicalPhalaCurrentProfile(directory = path.join(os.homedir(), ".phala-cloud")) {
  if (directory !== path.join(os.homedir(), ".phala-cloud")) {
    throw new Error("only the canonical Phala credential directory is accepted");
  }
  const directoryBefore = assertPrivateDirectory(directory);
  const credentialPath = path.join(directory, "credentials.json");
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = fs.openSync(credentialPath, flags);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.uid !== process.getuid()
      || (before.mode & 0o777) !== 0o600
      || before.size < 2 || before.size > MAX_CREDENTIAL_BYTES) {
      throw new Error("canonical Phala credentials must be an owned bounded 0600 regular file");
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    const directoryAfter = fs.lstatSync(directory);
    if (statFingerprint(before) !== statFingerprint(after)
      || statFingerprint(directoryBefore) !== statFingerprint(directoryAfter)
      || bytes.length !== before.size
      || fs.realpathSync(credentialPath) !== credentialPath) {
      throw new Error("canonical Phala credentials changed during their stable read");
    }
    let document;
    try {
      document = JSON.parse(bytes.toString("utf8"));
    } catch {
      throw new Error("canonical Phala credentials are not valid JSON");
    }
    assertBoundedJsonGraph(document, { label: "canonical Phala credentials" });
    const parsed = exactRecord(document, [
      "schema_version",
      "current_profile",
      "profiles",
    ], "canonical Phala credentials");
    if (parsed.schema_version !== 1) {
      throw new Error("canonical Phala credential schema is not exact");
    }
    const profileName = exactCanonicalIdentifier(
      parsed.current_profile,
      "canonical current Phala profile",
    );
    if (!isRecord(parsed.profiles)
      || !Object.hasOwn(parsed.profiles, profileName)) {
      throw new Error("canonical current Phala profile is unavailable");
    }
    const profile = normalizeCredentialProfile(parsed.profiles[profileName], profileName);
    return Object.freeze({
      directory,
      credential_path: credentialPath,
      credential_file_sha256: sha256(bytes),
      ...profile,
    });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function assertSameCanonicalCredential(expected, observed) {
  if (expected.directory !== observed.directory
    || expected.credential_path !== observed.credential_path
    || expected.credential_file_sha256 !== observed.credential_file_sha256
    || expected.profile_name !== observed.profile_name
    || expected.api_origin !== observed.api_origin
    || canonicalCompact(expected.workspace) !== canonicalCompact(observed.workspace)
    || canonicalCompact(expected.user) !== canonicalCompact(observed.user)
    || !sameSecret(expected.api_key, observed.api_key)) {
    throw new Error("canonical Phala current profile changed after adapter creation");
  }
  return true;
}

export function normalizePhalaAuthenticatedAccountSubject(currentUser) {
  assertBoundedJsonGraph(currentUser, { label: "authenticated Phala account response" });
  if (!isRecord(currentUser) || !isRecord(currentUser.user)
    || !isRecord(currentUser.workspace)) {
    throw new Error("authenticated Phala account response is invalid");
  }
  const user = currentUser.user;
  const workspace = currentUser.workspace;
  return Object.freeze({
    schema: PHALA_AUTHENTICATED_ACCOUNT_SUBJECT_SCHEMA,
    user: Object.freeze({
      username: exactSafeText(user.username, "authenticated username", 256),
      email: exactSafeText(user.email, "authenticated email", 512),
      role: exactCanonicalIdentifier(user.role, "authenticated user role"),
    }),
    workspace: Object.freeze({
      id: exactCanonicalIdentifier(workspace.id, "authenticated workspace id"),
      name: exactSafeText(workspace.name, "authenticated workspace name", 256),
      slug: workspace.slug === null
        ? null
        : exactCanonicalIdentifier(workspace.slug, "authenticated workspace slug"),
      role: exactCanonicalIdentifier(workspace.role, "authenticated workspace role"),
    }),
  });
}

export function phalaAuthenticatedAccountSubjectSha256(currentUser) {
  return domainDigest(
    PHALA_AUTHENTICATED_ACCOUNT_SUBJECT_DOMAIN,
    normalizePhalaAuthenticatedAccountSubject(currentUser),
  );
}

export function phalaSdkJsonBodySemanticDigest(value) {
  if (!isRecord(value)) throw new Error("SDK JSON body semantics must be an object");
  assertBoundedJsonGraph(value, { label: "SDK JSON body semantics" });
  return `sha256:${createHash("sha256")
    .update(Buffer.from(PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.digest.domain, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(value)), "utf8"))
    .digest("hex")}`;
}

export function phalaAuthenticatedSdkRequestSemanticsSha256({
  httpMethod,
  pathAndQuery,
  body = null,
} = {}) {
  if (!["GET", "POST", "PATCH"].includes(httpMethod)
    || typeof pathAndQuery !== "string"
    || !pathAndQuery.startsWith("/api/v1/")
    || pathAndQuery.length > 8_192
    || (body !== null && !isRecord(body))) {
    throw new Error("authenticated SDK request semantics are invalid");
  }
  if (body !== null) assertBoundedJsonGraph(body, { label: "SDK request body semantics" });
  return domainDigest(PHALA_AUTHENTICATED_SDK_REQUEST_DOMAIN, {
    http_method: httpMethod,
    path_and_query: pathAndQuery,
    body,
  });
}

export function projectPinnedProvisionWireBody(request) {
  const parsed = exactRecord(request, [
    "name",
    "instance_type",
    "disk_size",
    "image",
    "compose_file",
    "listed",
    "kms",
    "kms_contract_id",
    "key_provider_mode",
    "skip_gateway",
    "env_keys",
    "nonce",
    "app_id",
  ], "pre-transform provision request");
  if (parsed.kms !== "PHALA" || typeof parsed.kms_contract_id !== "string"
    || !/^kc_[A-Za-z0-9]{1,128}$/.test(parsed.kms_contract_id)) {
    throw new Error("provision request must bind the exact reviewed Phala KMS contract");
  }
  const compose = exactRecord(
    parsed.compose_file,
    PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS,
    "pre-transform provision request.compose_file",
  );
  if (typeof compose.gateway_enabled !== "boolean"
    || typeof compose.tproxy_enabled !== "boolean"
    || PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.provision_transform.rule
      !== "when_compose_file_gateway_enabled_and_tproxy_enabled_are_both_boolean_delete_compose_file_tproxy_enabled"
    || PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY
      .provision_transform.additional_transform_allowed !== false) {
    throw new Error("provision request does not enter the exact pinned SDK transform branch");
  }
  const wireCompose = projectPhalaAppComposeWire(compose);
  return {
    ...structuredClone(parsed),
    compose_file: wireCompose,
  };
}

export function projectPinnedProvisionWireEvidence(request) {
  const wireBody = projectPinnedProvisionWireBody(request);
  return Object.freeze({
    schema: "dnai.phala-pinned-provision-wire-projection.v1",
    truth_status:
      "pure_expected_sdk_transform_projection_not_captured_http_body_server_observation_or_staging_receipt",
    package_name: PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.package.name,
    package_version: PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.package.version,
    npm_dist_integrity_sha512:
      PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.package.npm_dist_integrity_sha512,
    transform_function:
      PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.provision_transform.function,
    pre_transform_request_sha256: phalaSdkJsonBodySemanticDigest(request),
    expected_post_transform_body_sha256: phalaSdkJsonBodySemanticDigest(wireBody),
    pre_transform_compose_hash: dstackCanonicalComposeHash(request.compose_file),
    expected_post_transform_compose_hash:
      dstackCanonicalComposeHash(wireBody.compose_file),
    captured_post_transform_body_sha256: null,
    prepare_server_compose_hash: null,
    authenticated_staging_receipt_sha256: null,
    evidence_complete: false,
    mutation_authorized: false,
  });
}

export async function loadPinnedDstackPurePrimitives(identity) {
  const runtime = requirePinnedIdentity(identity);
  const module = await importReviewedPhalaSdkRuntimeCapsule(runtime.capsule);
  if (typeof module.verifyEnvEncryptPublicKeyLegacy !== "function"
    || typeof module.verifyEnvEncryptPublicKey !== "function"
    || typeof module.getComposeHash !== "function"
    || typeof module.encryptEnvVars !== "function") {
    throw new Error("reviewed SDK runtime capsule lacks exact dstack primitives");
  }
  return Object.freeze({
    verifyEnvEncryptPublicKeyLegacy: module.verifyEnvEncryptPublicKeyLegacy,
    verifyEnvEncryptPublicKey: module.verifyEnvEncryptPublicKey,
    getComposeHash: module.getComposeHash,
    encryptEnvVars: module.encryptEnvVars,
  });
}

export async function assertPinnedDstackComposeHash({
  identity,
  appCompose,
  observedComposeHash,
} = {}) {
  const primitives = await loadPinnedDstackPurePrimitives(identity);
  const sdkHash = primitives.getComposeHash(appCompose);
  const independentHash = dstackCanonicalComposeHash(appCompose);
  if (typeof observedComposeHash !== "string"
    || sdkHash !== independentHash || observedComposeHash !== sdkHash) {
    throw new Error("prepared compose hash does not match the pinned dstack canonical hash");
  }
  return sdkHash;
}

export async function verifyPinnedLegacyEnvironmentKey({
  identity,
  appId,
  response,
  pinnedSigner,
} = {}) {
  const primitives = await loadPinnedDstackPurePrimitives(identity);
  const normalized = normalizeSignedEnvironmentKeyResponse(response);
  const canonicalAppId = typeof appId === "string" ? appId.replace(/^0x/, "") : "";
  const recovered = primitives.verifyEnvEncryptPublicKeyLegacy(
    Buffer.from(normalized.public_key, "hex"),
    Buffer.from(normalized.signature, "hex"),
    canonicalAppId,
  );
  return assertRecoveredSignedEnvironmentKey({
    appId: canonicalAppId,
    response: normalized,
    recoveredSigner: recovered,
    pinnedSigner,
  });
}

export async function verifyImmediatePinnedLegacyEnvironmentKeyRefetch({
  identity,
  appId,
  firstResponse,
  secondResponse,
  pinnedSigner,
} = {}) {
  const first = await verifyPinnedLegacyEnvironmentKey({
    identity,
    appId,
    response: firstResponse,
    pinnedSigner,
  });
  const second = await verifyPinnedLegacyEnvironmentKey({
    identity,
    appId,
    response: secondResponse,
    pinnedSigner,
  });
  return assertImmediateSignedEnvironmentKeyRefetch(first, second);
}

export async function encryptExactEnvironmentWithPinnedDstack({
  identity,
  entries,
  publicKey,
} = {}) {
  requirePinnedIdentity(identity);
  if (!Array.isArray(entries) || entries.length > 512) {
    throw new Error("environment entries must be a bounded array");
  }
  const normalized = entries.map((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)
      || JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(["key", "value"])
      || typeof entry.key !== "string" || !/^[A-Z][A-Z0-9_]{0,127}$/.test(entry.key)
      || typeof entry.value !== "string"
      || Buffer.byteLength(entry.value, "utf8") > 65_536) {
      throw new Error(`environment entry ${index} is invalid`);
    }
    return { key: entry.key, value: entry.value };
  });
  if (JSON.stringify(normalized.map(({ key }) => key))
      !== JSON.stringify([...new Set(normalized.map(({ key }) => key))].sort())) {
    throw new Error("environment entries must be sorted and duplicate-free");
  }
  const normalizedPublicKey = typeof publicKey === "string"
    ? publicKey.replace(/^0x/, "").toLowerCase()
    : "";
  if (!/^(?!0{64}$)[0-9a-f]{64}$/.test(normalizedPublicKey)) {
    throw new Error("environment encryption key must be exactly 32 nonzero bytes");
  }
  const primitives = await loadPinnedDstackPurePrimitives(identity);
  const encrypted = await primitives.encryptEnvVars(normalized, normalizedPublicKey);
  if (typeof encrypted !== "string" || !/^[0-9a-f]+$/.test(encrypted)
    || encrypted.length < 2 * (32 + 12 + 16)) {
    throw new Error("pinned dstack environment encryption returned invalid ciphertext");
  }
  return encrypted;
}

function assertAdapterAuthorityFresh(state) {
  if (state.historical_continuity_read_only === true) {
    const compatibilitySha256 = phalaCompatibilityReceiptDigest(
      state.compatibility,
    );
    const stagingSha256 = phalaSdkWireTransformStagingReceiptDigest(
      state.staging,
      { compatibilityReceipt: state.compatibility },
    );
    const targetSha256 = phalaProductionTargetAuthorityDigest(
      state.target,
      {
        compatibilityReceipt: state.compatibility,
        sdkWireTransformStagingReceipt: state.staging,
      },
    );
    if (compatibilitySha256 !== state.identity.compatibility_receipt_sha256
      || stagingSha256
        !== state.identity.sdk_wire_transform_staging_receipt_sha256
      || targetSha256 !== state.identity.production_target_authority_sha256) {
      throw new Error("historical read-only Phala authority drifted after observer creation");
    }
    return true;
  }
  const now = state.now();
  const windows = [
    [state.compatibility.checked_at, state.compatibility.expires_at],
    [state.staging.captured_at, state.staging.expires_at],
    [state.target.reviewed_at, state.target.expires_at],
  ];
  if (windows.some(([from, until]) => (
    now < Date.parse(from) || now >= Date.parse(until)
  ))) {
    throw new Error("fresh compatibility, staging, and target authority are required for every SDK call");
  }
  return true;
}

function exactAuthorityInputs(value) {
  const parsed = exactRecord(value, [
    "targetAuthority",
    "compatibilityReceipt",
    "sdkWireTransformStagingReceipt",
  ], "production SDK adapter constructor");
  assertBoundedJsonGraph(parsed.targetAuthority, { label: "target authority" });
  assertBoundedJsonGraph(parsed.compatibilityReceipt, { label: "compatibility receipt" });
  assertBoundedJsonGraph(parsed.sdkWireTransformStagingReceipt, {
    label: "SDK wire-transform staging receipt",
  });
  const compatibility = normalizePhalaCompatibilityReceipt(parsed.compatibilityReceipt);
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    parsed.sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const target = normalizePhalaProductionTargetAuthority(parsed.targetAuthority, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt: staging,
  });
  for (const [label, input, normalized] of [
    ["compatibility receipt", parsed.compatibilityReceipt, compatibility],
    ["SDK wire-transform staging receipt", parsed.sdkWireTransformStagingReceipt, staging],
    ["target authority", parsed.targetAuthority, target],
  ]) {
    if (canonicalCompact(input) !== canonicalCompact(normalized)) {
      throw new Error(`${label} must already be normalized before adapter creation`);
    }
  }
  return { compatibility, staging, target };
}

async function loadPinnedCloudActions(identity) {
  const runtime = requirePinnedIdentity(identity);
  const module = await importReviewedPhalaSdkRuntimeCapsule(runtime.capsule);
  const actions = {};
  for (const name of REQUIRED_CLOUD_ACTION_EXPORTS) {
    if (typeof module[name] !== "function") {
      throw new Error(`pinned Phala Cloud SDK does not export required action ${name}`);
    }
    actions[name] = module[name];
  }
  return Object.freeze(actions);
}

function appendExactQuery(requestPath, options) {
  if (options === undefined) return requestPath;
  const parsed = exactRecord(options, ["params"], "pinned SDK GET options");
  if (!isRecord(parsed.params)) {
    throw new Error("pinned SDK GET query parameters must be an object");
  }
  assertBoundedJsonGraph(parsed.params, { label: "pinned SDK GET query parameters" });
  const url = new URL(`${PHALA_ORIGIN}${requestPath}`);
  for (const [key, value] of Object.entries(parsed.params)) {
    if (typeof value !== "string" && typeof value !== "number"
      && typeof value !== "boolean") {
      throw new Error("pinned SDK GET query parameters must be scalar");
    }
    url.searchParams.append(key, String(value));
  }
  return `${url.pathname.slice("/api/v1".length)}${url.search}`;
}

/** The SDK may override only the exact version reviewed for this action. */
export function assertPinnedSdkActionVersionHeaders({ action, headers } = {}) {
  if (!REQUIRED_CLOUD_ACTION_EXPORTS.includes(action)) {
    throw new Error("SDK action is outside the reviewed request policy");
  }
  const expected = PHALA_SDK_ACTION_VERSION_OVERRIDES[action] ?? null;
  if (expected === null) {
    if (headers !== undefined) {
      throw new Error("SDK action headers are outside its reviewed policy");
    }
    return null;
  }
  const parsed = exactRecord(headers, ["X-Phala-Version"], "pinned SDK version headers");
  if (parsed["X-Phala-Version"] !== expected) {
    throw new Error("SDK action version header is outside its reviewed policy");
  }
  return expected;
}

function projectPinnedJsonWireBody(value) {
  if (value === undefined) return undefined;
  if (!isRecord(value)) {
    throw new Error("pinned SDK JSON request body must be an object");
  }
  function project(entry, inArray = false) {
    if (entry === undefined) {
      if (inArray) {
        throw new Error("pinned SDK JSON request arrays cannot contain undefined");
      }
      return undefined;
    }
    if (entry === null || typeof entry === "string" || typeof entry === "boolean") {
      return entry;
    }
    if (typeof entry === "number" && Number.isFinite(entry)) return entry;
    if (Array.isArray(entry)) return entry.map((item) => project(item, true));
    if (!isRecord(entry)) {
      throw new Error("pinned SDK JSON request body contains a non-JSON value");
    }
    return Object.fromEntries(Object.entries(entry)
      .filter(([, item]) => item !== undefined)
      .map(([key, item]) => [key, project(item)]));
  }
  const projected = project(value);
  assertBoundedJsonGraph(projected, { label: "pinned SDK projected JSON body" });
  return projected;
}

function exactActionArguments(value, length, action) {
  if (!Array.isArray(value) || value.length !== length) {
    throw new Error(`${action} must receive exactly ${length} reviewed action arguments`);
  }
  return value;
}

function exactRequestPathSegment(value, label) {
  if (typeof value !== "string" || value.length < 1 || value.length > 256
    || !/^[A-Za-z0-9._@-]+$/u.test(value)
    || encodeURIComponent(value) !== value) {
    throw new Error(`${label} is not one exact request-path segment`);
  }
  return value;
}

function sdkNormalizedCvmId(value, label) {
  const parsed = exactRecord(value, ["id"], label);
  const raw = exactRequestPathSegment(parsed.id, `${label}.id`);
  if (/^[0-9a-f]{40}$/iu.test(raw)) return `app_${raw}`;
  if (/^[0-9a-f]{8}-?[0-9a-f]{4}-?4[0-9a-f]{3}-?[89ab][0-9a-f]{3}-?[0-9a-f]{12}$/iu
    .test(raw)) {
    return raw.replaceAll("-", "");
  }
  return raw;
}

/**
 * Projects the sole method, request target, and JSON body that the reviewed
 * capsule action is allowed to emit for these exact arguments. This is the
 * independent capability boundary below the SDK action implementation.
 */
export function projectPinnedSdkActionRequest(action, actionArguments = []) {
  if (!REQUIRED_CLOUD_ACTION_EXPORTS.includes(action)) {
    throw new Error("SDK action is outside the reviewed request policy");
  }
  let httpMethod;
  let pathAndQuery;
  let body = null;
  switch (action) {
    case "getCurrentUser":
      exactActionArguments(actionArguments, 0, action);
      httpMethod = "GET";
      pathAndQuery = "/api/v1/auth/me";
      break;
    case "getCvmCreateResources":
      exactActionArguments(actionArguments, 0, action);
      httpMethod = "GET";
      pathAndQuery = "/api/v1/teepods/cvm-create-resources";
      break;
    case "getKmsList":
    case "listKmsContracts": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(
        request,
        ["page", "page_size", "is_onchain"],
        `${action} request`,
      );
      if (parsed.page !== 1 || parsed.page_size !== 100
        || parsed.is_onchain !== false) {
        throw new Error(`${action} request differs from the reviewed fixed query`);
      }
      httpMethod = "GET";
      pathAndQuery = "/api/v1/kms?page=1&page_size=100&is_onchain=false";
      break;
    }
    case "getKmsInfo": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["kms_id"], "getKmsInfo request");
      httpMethod = "GET";
      pathAndQuery = `/api/v1/kms/${exactRequestPathSegment(
        parsed.kms_id,
        "getKmsInfo kms_id",
      )}`;
      break;
    }
    case "getKmsContract":
    case "listKmsContractNodes": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["slug"], `${action} request`);
      const slug = exactRequestPathSegment(parsed.slug, `${action} slug`);
      if (!/^kc_[A-Za-z0-9]+$/.test(slug)
        && !(action === "getKmsContract" && slug === "phala")) {
        throw new Error(`${action} requires an exact contract ID or the reviewed discovery alias`);
      }
      httpMethod = "GET";
      pathAndQuery = `/api/v1/kms/${slug}${action === "listKmsContractNodes" ? "/nodes" : ""}`;
      break;
    }
    case "getWorkspace": {
      const [slug] = exactActionArguments(actionArguments, 1, action);
      httpMethod = "GET";
      pathAndQuery = `/api/v1/workspaces/${exactRequestPathSegment(slug, "workspace slug")}`;
      break;
    }
    case "getOsImages": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(
        request,
        ["page", "page_size", "is_dev"],
        "getOsImages request",
      );
      if (parsed.page !== 1 || parsed.page_size !== 100 || parsed.is_dev !== false) {
        throw new Error("getOsImages request differs from the reviewed fixed query");
      }
      httpMethod = "GET";
      pathAndQuery = "/api/v1/os-images?page=1&page_size=100&is_dev=false";
      break;
    }
    case "getCvmList": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["page", "page_size"], "getCvmList request");
      if (parsed.page !== 1 || parsed.page_size !== 100) {
        throw new Error("getCvmList request differs from the reviewed fixed query");
      }
      httpMethod = "GET";
      pathAndQuery = "/api/v1/cvms/paginated?page=1&page_size=100";
      break;
    }
    case "nextAppIds": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["counts"], "nextAppIds request");
      if (parsed.counts !== CVM_LAUNCH_DOMAINS.length) {
        throw new Error("nextAppIds request must reserve exactly seven ids");
      }
      httpMethod = "GET";
      pathAndQuery = "/api/v1/kms/phala/next_app_id?counts=7";
      break;
    }
    case "provisionCvm": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      httpMethod = "POST";
      pathAndQuery = "/api/v1/cvms/provision";
      body = projectPinnedJsonWireBody(projectPinnedProvisionWireBody(request));
      break;
    }
    case "getAppEnvEncryptPubKey": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(
        request,
        ["kms", "app_id"],
        "getAppEnvEncryptPubKey request",
      );
      const kms = exactRequestPathSegment(parsed.kms, "environment key KMS id");
      const appId = exactAppId(parsed.app_id, "environment key app id");
      httpMethod = "GET";
      pathAndQuery = `/api/v1/kms/${kms}/pubkey/${appId}`;
      break;
    }
    case "commitCvmProvision": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      httpMethod = "POST";
      pathAndQuery = "/api/v1/cvms";
      body = projectPinnedJsonWireBody(request);
      break;
    }
    case "updateCvmEnvs": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["id", "encrypted_env"], "updateCvmEnvs request");
      const cvmId = sdkNormalizedCvmId({ id: parsed.id }, "updateCvmEnvs request");
      httpMethod = "PATCH";
      pathAndQuery = `/api/v1/cvms/${cvmId}/envs`;
      body = projectPinnedJsonWireBody({ encrypted_env: parsed.encrypted_env });
      break;
    }
    case "restartCvm": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const parsed = exactRecord(request, ["id", "force"], "restartCvm request");
      if (parsed.force !== false) throw new Error("restartCvm force must be false");
      const cvmId = sdkNormalizedCvmId({ id: parsed.id }, "restartCvm request");
      httpMethod = "POST";
      pathAndQuery = `/api/v1/cvms/${cvmId}/restart`;
      body = { force: false };
      break;
    }
    case "getCvmInfo":
    case "getCvmAttestation": {
      const [request] = exactActionArguments(actionArguments, 1, action);
      const cvmId = sdkNormalizedCvmId(request, `${action} request`);
      httpMethod = "GET";
      pathAndQuery = `/api/v1/cvms/${cvmId}${action === "getCvmAttestation"
        ? "/attestation" : ""}`;
      break;
    }
    default:
      throw new Error("SDK action lacks an exact request projection");
  }
  return Object.freeze({
    action,
    http_method: httpMethod,
    path_and_query: pathAndQuery,
    body,
    api_version_header: PHALA_SDK_ACTION_VERSION_OVERRIDES[action] ?? null,
  });
}

export function assertPinnedSdkActionRequestMatches({
  action,
  actionArguments,
  httpMethod,
  pathAndQuery,
  body,
  headers,
} = {}) {
  const expected = projectPinnedSdkActionRequest(action, actionArguments);
  const observed = {
    action,
    http_method: httpMethod,
    path_and_query: pathAndQuery,
    body: body ?? null,
    api_version_header: assertPinnedSdkActionVersionHeaders({ action, headers }),
  };
  if (canonicalCompact(expected) !== canonicalCompact(observed)) {
    throw new Error("SDK action emitted a method, target, query, or body outside its reviewed policy");
  }
  return expected;
}

function exactRequestUrl(requestPath) {
  if (typeof requestPath !== "string" || !requestPath.startsWith("/")
    || requestPath.length > 4_096 || /[\\\u0000-\u001f\u007f]/.test(requestPath)) {
    throw new Error("pinned SDK action emitted an invalid relative request path");
  }
  const url = new URL(`${PHALA_ORIGIN}${requestPath}`);
  if (url.protocol !== "https:" || url.hostname !== PHALA_HOST
    || url.port !== "" || url.username || url.password || url.hash
    || !url.pathname.startsWith("/api/v1/")) {
    throw new Error("pinned SDK action attempted origin or path drift");
  }
  return url;
}

function parseBoundedJsonResponse(bytes) {
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("pinned Phala HTTPS response is not valid JSON");
  }
  assertBoundedJsonGraph(value, { label: "pinned Phala HTTPS response" });
  return value;
}

/**
 * Check fields that SDK defaults/transforms would otherwise erase. This is a
 * transport fact only, not active-workspace or placement authorization.
 */
export function projectPinnedSdkRawIdentityFields(action, response) {
  if (action === "getWorkspace") {
    if (!isRecord(response) || !Object.hasOwn(response, "billing_status")
      || !["active", "suspended", "abandoned"].includes(response.billing_status)) {
      throw new Error("workspace response must explicitly report a known billing_status before SDK parsing");
    }
    return Object.freeze({ billing_status: response.billing_status });
  }
  if (action === "provisionCvm") {
    if (!isRecord(response)) throw new Error("prepare response must be an object");
    const placement = {};
    for (const field of ["node_id", "teepod_id"]) {
      // Preserve absence distinctly. The SDK aliases teepod_id to node_id.
      if (!Object.hasOwn(response, field)) continue;
      if (response[field] !== null && (!Number.isSafeInteger(response[field]) || response[field] < 1)) {
        throw new Error(`prepare raw ${field} is not a positive canonical identity or explicit null`);
      }
      placement[field] = response[field];
    }
    return Object.freeze(placement);
  }
  if (action === "getCvmInfo") {
    if (!isRecord(response)) throw new Error("CVM response must be an object");
    const posture = {};
    for (const field of ["listed", "public_logs", "public_sysinfo", "public_tcbinfo"]) {
      if (!Object.hasOwn(response, field) || typeof response[field] !== "boolean") {
        throw new Error(`CVM response must explicitly report ${field} before SDK parsing`);
      }
      posture[field] = response[field];
    }
    return Object.freeze(posture);
  }
  return null;
}

function performPinnedHttpsRequest({
  httpsRequest,
  setTimeoutIntrinsic,
  clearTimeoutIntrinsic,
  apiKey,
  apiVersion,
  httpMethod,
  requestPath,
  body,
}) {
  const url = exactRequestUrl(requestPath);
  const bodyText = body === undefined ? null : JSON.stringify(
    assertBoundedJsonGraph(body, { label: "pinned Phala HTTPS request body" }),
  );
  const bodyBytes = bodyText === null ? null : Buffer.from(bodyText, "utf8");
  if (bodyBytes && bodyBytes.length > MAX_HTTP_REQUEST_BYTES) {
    throw new Error("pinned Phala HTTPS request body exceeds its bound");
  }
  const headers = {
    Accept: "application/json",
    "Content-Type": "application/json",
    "X-API-Key": apiKey,
    "X-Phala-Version": apiVersion,
  };
  if (bodyBytes) headers["Content-Length"] = String(bodyBytes.length);

  return new Promise((resolve, reject) => {
    let settled = false;
    let wallTimer;
    const fail = (message) => {
      if (settled) return;
      settled = true;
      if (wallTimer) clearTimeoutIntrinsic(wallTimer);
      reject(new Error(message));
    };
    const request = httpsRequest({
      protocol: "https:",
      hostname: PHALA_HOST,
      port: 443,
      method: httpMethod,
      path: `${url.pathname}${url.search}`,
      headers,
      timeout: PHALA_PINNED_CLIENT_TRANSPORT.timeout_ms,
      agent: false,
    }, (response) => {
      const status = response.statusCode;
      const contentType = response.headers?.["content-type"];
      const contentLength = Number(response.headers?.["content-length"] ?? 0);
      if (!Number.isInteger(status)
        || typeof contentType !== "string"
        || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)
        || !Number.isFinite(contentLength) || contentLength < 0
        || contentLength > MAX_HTTP_RESPONSE_BYTES) {
        response.resume();
        fail("pinned Phala HTTPS response metadata is invalid");
        return;
      }
      const chunks = [];
      let length = 0;
      response.on("data", (chunk) => {
        if (settled) return;
        const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        length += bytes.length;
        if (length > MAX_HTTP_RESPONSE_BYTES) {
          request.destroy();
          fail("pinned Phala HTTPS response exceeds its bound");
          return;
        }
        chunks.push(bytes);
      });
      response.once("aborted", () => fail("pinned Phala HTTPS response aborted"));
      response.once("error", () => fail("pinned Phala HTTPS response stream failed"));
      response.once("end", () => {
        if (settled) return;
        if (status < 200 || status >= 300) {
          fail(`pinned Phala HTTPS request returned status ${status}`);
          return;
        }
        const rawBytes = Buffer.concat(chunks, length);
        let parsed;
        try {
          parsed = parseBoundedJsonResponse(rawBytes);
        } catch (error) {
          fail(error.message);
          return;
        }
        settled = true;
        if (wallTimer) clearTimeoutIntrinsic(wallTimer);
        resolve(Object.freeze({
          response: parsed,
          capture: Object.freeze({
            api_version: apiVersion,
            http_method: httpMethod,
            request_target_sha256: domainDigest(
              "dnai-wikigen/phala-authenticated-sdk-request-target/v1\0",
              { path_and_query: `${url.pathname}${url.search}` },
            ),
            request_semantics_sha256:
              phalaAuthenticatedSdkRequestSemanticsSha256({
                httpMethod,
                pathAndQuery: `${url.pathname}${url.search}`,
                body: body ?? null,
              }),
            captured_post_transform_body_sha256: body === undefined
              ? null
              : phalaSdkJsonBodySemanticDigest(body),
            serialized_http_body_sha256: bodyBytes === null ? null : sha256(bodyBytes),
            raw_response_sha256: sha256(rawBytes),
            http_status: status,
          }),
        }));
      });
    });
    request.once("timeout", () => {
      request.destroy();
      fail("pinned Phala HTTPS request timed out");
    });
    request.once("error", () => fail("pinned Phala HTTPS request failed"));
    wallTimer = setTimeoutIntrinsic(() => {
      request.destroy();
      fail("pinned Phala HTTPS request exceeded its wall-clock timeout");
    }, PHALA_PINNED_CLIENT_TRANSPORT.timeout_ms);
    wallTimer.unref?.();
    if (bodyBytes) request.write(bodyBytes);
    request.end();
  });
}

function createPinnedSdkActionClient({
  apiKey,
  apiVersion,
  httpsRequest,
  setTimeoutIntrinsic,
  clearTimeoutIntrinsic,
}) {
  let invocationOpen = false;
  let capture = null;
  let requestStarted = false;
  let expectedRequest = null;

  async function perform(httpMethod, requestPath, body, headers) {
    if (!invocationOpen || requestStarted || capture !== null
      || expectedRequest === null) {
      throw new Error("pinned SDK action emitted more than one HTTP request");
    }
    requestStarted = true;
    const rawPathAndQuery = `/api/v1${requestPath}`;
    assertPinnedSdkActionRequestMatches({
      action: expectedRequest.action,
      actionArguments: expectedRequest.actionArguments,
      httpMethod,
      pathAndQuery: rawPathAndQuery,
      body,
      headers,
    });
    const url = exactRequestUrl(requestPath);
    if (`${url.pathname}${url.search}` !== rawPathAndQuery) {
      throw new Error("SDK action request target changed under URL normalization");
    }
    const result = await performPinnedHttpsRequest({
      httpsRequest,
      setTimeoutIntrinsic,
      clearTimeoutIntrinsic,
      apiKey,
      apiVersion: PHALA_SDK_ACTION_VERSION_OVERRIDES[expectedRequest.action] ?? apiVersion,
      httpMethod,
      requestPath,
      body,
    });
    const rawIdentityFields = projectPinnedSdkRawIdentityFields(
      expectedRequest.action, result.response,
    );
    capture = Object.freeze({ ...result.capture, raw_identity_fields: rawIdentityFields });
    return result.response;
  }

  const client = Object.freeze({
    config: Object.freeze({ version: apiVersion }),
    async get(requestPath, options) {
      if (options !== undefined && (!isRecord(options)
        || Object.keys(options).some((key) => !["params", "headers"].includes(key)))) {
        throw new Error("pinned SDK GET options are outside the reviewed policy");
      }
      const queryOptions = options && Object.hasOwn(options, "params")
        ? { params: options.params } : undefined;
      return perform("GET", appendExactQuery(requestPath, queryOptions), undefined,
        options?.headers);
    },
    async post(requestPath, body, options) {
      if (options !== undefined) {
        throw new Error("pinned SDK POST options are not accepted");
      }
      return perform("POST", requestPath, projectPinnedJsonWireBody(body));
    },
    async patch(requestPath, body, options) {
      if (options !== undefined) {
        throw new Error("pinned SDK PATCH options are not accepted");
      }
      return perform("PATCH", requestPath, projectPinnedJsonWireBody(body));
    },
  });

  return Object.freeze({
    client,
    begin(action, actionArguments) {
      if (invocationOpen) throw new Error("pinned SDK adapter forbids concurrent calls");
      projectPinnedSdkActionRequest(action, actionArguments);
      invocationOpen = true;
      capture = null;
      requestStarted = false;
      expectedRequest = Object.freeze({ action, actionArguments });
    },
    finish() {
      if (!invocationOpen || !requestStarted || capture === null) {
        throw new Error("pinned SDK action did not emit exactly one HTTP request");
      }
      const result = capture;
      invocationOpen = false;
      capture = null;
      requestStarted = false;
      expectedRequest = null;
      return result;
    },
    abort() {
      invocationOpen = false;
      capture = null;
      requestStarted = false;
      expectedRequest = null;
    },
  });
}

function samePinnedCompatibilityIdentity(expected, observed) {
  return canonicalCompact(projectPinnedSdkCompatibilityIdentity(expected))
    === canonicalCompact(projectPinnedSdkCompatibilityIdentity(observed));
}

function assertCredentialMatchesAuthenticatedSubject(credential, response) {
  const subject = normalizePhalaAuthenticatedAccountSubject(response);
  if (subject.workspace.name !== credential.workspace.name
    || subject.workspace.slug !== credential.workspace.slug
    || subject.user.username !== credential.user.username
    || subject.user.email !== credential.user.email) {
    throw new Error("authenticated Phala account does not match the canonical current profile");
  }
  return subject;
}

async function invokePreProvisionSdkAction(state, method, actionArguments = []) {
  assertSafePhalaSdkProcessEnvironment();
  const installed = resolvePinnedPhalaPackageIdentity();
  if (!samePinnedCompatibilityIdentity(state.identity, installed)) {
    throw new Error("reviewed Phala SDK runtime capsule identity drifted during observation");
  }
  assertSameCanonicalCredential(
    state.credential,
    readCanonicalPhalaCurrentProfile(state.credential.directory),
  );
  if (state.in_flight) {
    throw new Error("pre-provision Phala observer forbids concurrent calls");
  }
  const action = state.actions[method];
  if (typeof action !== "function") {
    throw new Error("pinned Phala SDK observation action is unavailable");
  }
  state.in_flight = true;
  state.transport.begin(method, actionArguments);
  try {
    const response = await action(state.transport.client, ...actionArguments);
    assertBoundedJsonGraph(response, { label: `${method} SDK response` });
    const capture = state.transport.finish();
    return Object.freeze({ response, capture });
  } catch (error) {
    state.transport.abort();
    throw error;
  } finally {
    state.in_flight = false;
  }
}

function exactUniqueCentralizedKms(kmsList) {
  if (!isRecord(kmsList) || !Array.isArray(kmsList.items)
    || kmsList.items.length < 1 || kmsList.items.length > 100
    || kmsList.total !== kmsList.items.length || kmsList.page !== 1
    || kmsList.page_size !== 100 || kmsList.pages !== 1) {
    throw new Error("authenticated Phala KMS catalog is invalid");
  }
  const matches = kmsList.items.filter((entry) => isRecord(entry)
    && entry.slug === "phala"
    && entry.chain_id === 0
    && entry.contract_address === "phala");
  if (matches.length !== 1
    || kmsList.items.filter((entry) => entry?.id === matches[0].id).length !== 1) {
    throw new Error("authenticated Phala KMS catalog is not uniquely centralized");
  }
  return normalizePhalaKmsContract(matches[0]);
}

function reviewedCompatibilityResourceTargets() {
  return Object.fromEntries(CVM_LAUNCH_DOMAINS.map((domain) => [domain, {
    ...PHALA_CVM_RESOURCE_TARGETS[domain],
    gateway_required: CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate.gateway_enabled,
  }]));
}

function exactSelectedOsImage(osImages) {
  if (!isRecord(osImages) || !Array.isArray(osImages.items)) {
    throw new Error("authenticated Phala OS-image catalog is invalid");
  }
  const matches = osImages.items.filter((entry) => isRecord(entry)
    && entry.name === PHALA_OS_IMAGE_CATALOG_ENTRY.name
    && entry.slug === PHALA_OS_IMAGE_CATALOG_ENTRY.slug
    && entry.version === PHALA_OS_IMAGE_CATALOG_ENTRY.version
    && entry.os_image_hash === PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    && entry.is_dev === false
    && entry.requires_gpu === false);
  if (matches.length !== 1) {
    throw new Error("reviewed Phala OS image is not unique in the authenticated catalog");
  }
  return { ...PHALA_OS_IMAGE_CATALOG_ENTRY };
}

function projectCompatibilityResourceAuthority(resources) {
  if (!isRecord(resources) || !isRecord(resources.capacity)
    || !Array.isArray(resources.instance_types)) {
    throw new Error("authenticated Phala resource catalog is invalid");
  }
  const requiredTypes = [...new Set(Object.values(PHALA_CVM_RESOURCE_TARGETS)
    .map(({ instance_type: name }) => name))].sort();
  const maxInstances = resources.capacity.max_instances;
  const maxDisk = resources.capacity.max_disk;
  if (!Number.isSafeInteger(maxInstances) || maxInstances < 1
    || !Number.isSafeInteger(maxDisk) || maxDisk < 1) {
    throw new Error("authenticated Phala quota is incomplete");
  }
  const resourceCatalog = requiredTypes.map((name) => {
    const matches = resources.instance_types.filter((entry) => (
      // Provider IDs are canonical instance types; names are display labels.
      isRecord(entry) && entry.id === name
    ));
    if (matches.length !== 1
      || !Number.isSafeInteger(matches[0].default_disk_size_gb)
      || matches[0].default_disk_size_gb < 1
      || matches[0].requires_gpu !== false) {
      throw new Error("reviewed Phala instance type is unavailable or ambiguous");
    }
    return {
      name,
      default_disk_size_gb: matches[0].default_disk_size_gb,
      maximum_disk_size_gb: maxDisk,
      requires_gpu: false,
    };
  });
  const requiredDisk = Object.values(PHALA_CVM_RESOURCE_TARGETS)
    .reduce((total, { disk_size: size }) => total + size, 0);
  const sufficient = maxInstances >= CVM_LAUNCH_DOMAINS.length
    && maxDisk >= requiredDisk
    && Object.values(PHALA_CVM_RESOURCE_TARGETS).every(({ instance_type, disk_size }) => {
      const entry = resourceCatalog.find(({ name }) => name === instance_type);
      return entry && disk_size >= entry.default_disk_size_gb
        && disk_size <= entry.maximum_disk_size_gb;
    });
  return Object.freeze({
    resource_catalog: resourceCatalog,
    quota: {
      max_instances: maxInstances,
      max_disk_gb: maxDisk,
      catalog_reports_sufficient_capacity: sufficient,
    },
  });
}

function validateCompatibilityCandidateData(credential, data) {
  const subject = assertCredentialMatchesAuthenticatedSubject(
    credential,
    data.getCurrentUser?.response,
  );
  const workspace = data.getWorkspace?.response;
  if (workspace?.id !== subject.workspace.id || workspace?.slug !== subject.workspace.slug
    || workspace?.billing_status !== data.getWorkspace?.capture.raw_identity_fields?.billing_status
    || !["active", "suspended", "abandoned"].includes(workspace?.billing_status)) {
    throw new Error("explicit workspace billing observation differs from the authenticated account");
  }
  const kmsCatalog = exactUniqueCentralizedKms(data.listKmsContracts?.response);
  const kmsContract = normalizePhalaKmsContract(data.getKmsContract?.response);
  if (canonicalCompact(kmsContract) !== canonicalCompact(kmsCatalog)) {
    throw new Error("authenticated Phala KMS contract detail differs from its catalog entry");
  }
  const osImage = exactSelectedOsImage(data.getOsImages?.response);
  return Object.freeze({
    subject,
    billing_status: workspace.billing_status,
    kms: buildPhalaContractKmsProjection({
      contract: kmsContract,
      contractNodes: data.listKmsContractNodes?.response,
      resources: data.getCvmCreateResources?.response,
      osImage,
      resourceTargets: reviewedCompatibilityResourceTargets(),
    }),
    resource: projectCompatibilityResourceAuthority(
      data.getCvmCreateResources?.response,
    ),
    os_image: osImage,
  });
}

/**
 * Perform the exact two-version, read-only compatibility plan with the pinned
 * reviewed SDK runtime capsule and the canonical current CLI profile. The returned
 * artifact contains hashes and public catalog facts only; credential bytes and
 * account identifiers other than the reviewed workspace id never leave this
 * function.
 */
export async function observePinnedPhalaCompatibility() {
  assertProductionExecutionPolicyAvailable();
  assertSafePhalaSdkProcessEnvironment();
  const identity = resolvePinnedPhalaPackageIdentity();
  const sdkIdentity = projectPinnedSdkCompatibilityIdentity(identity);
  const credential = readCanonicalPhalaCurrentProfile();
  const actions = await loadPinnedCloudActions(identity);
  const runtime = requirePinnedIdentity(identity);
  const observations = [];
  let selectedData = null;
  let selectedProjection = null;
  for (const apiVersion of PHALA_API_CANDIDATE_VERSIONS) {
    const state = {
      actions,
      credential,
      identity,
      in_flight: false,
      transport: createPinnedSdkActionClient({
        apiKey: credential.api_key,
        apiVersion,
        httpsRequest: runtime.httpsRequest,
        setTimeoutIntrinsic: runtime.setTimeout,
        clearTimeoutIntrinsic: runtime.clearTimeout,
      }),
    };
    const data = {};
    const completed = [];
    const invoke = async (method, args = []) => {
      try {
        data[method] = await invokePreProvisionSdkAction(state, method, args);
        completed.push(method);
        return true;
      } catch {
        return false;
      }
    };
    await invoke("getCurrentUser");
    const account = data.getCurrentUser?.response;
    if (account?.workspace?.slug) await invoke("getWorkspace", [account.workspace.slug]);
    await invoke("getCvmCreateResources");
    await invoke("listKmsContracts", [{ page: 1, page_size: 100, is_onchain: false }]);
    let kmsId;
    try {
      kmsId = exactUniqueCentralizedKms(data.listKmsContracts?.response).id;
    } catch {
      // Still complete the fixed read-only action plan without borrowing state
      // from a different candidate-version observation.
    }
    await invoke("getKmsContract", [{ slug: kmsId ?? "phala" }]);
    const contractId = data.getKmsContract?.response?.id;
    if (typeof contractId === "string") {
      await invoke("listKmsContractNodes", [{ slug: contractId }]);
    }
    await invoke("getOsImages", [{ page: 1, page_size: 100, is_dev: false }]);
    let accountValid = false;
    try {
      assertCredentialMatchesAuthenticatedSubject(
        credential,
        data.getCurrentUser?.response,
      );
      accountValid = true;
    } catch {
      accountValid = false;
    }
    const allComplete = completed.length === PHALA_READ_ONLY_COMPATIBILITY_CALLS.length
      && canonicalCompact(completed) === canonicalCompact(PHALA_READ_ONLY_COMPATIBILITY_CALLS);
    let projection = null;
    if (allComplete) {
      try {
        projection = validateCompatibilityCandidateData(credential, data);
      } catch {
        projection = null;
      }
    }
    const candidate = {
      version: apiVersion,
      authenticated: accountValid,
      strict_schema_valid: projection !== null,
      response_origin_valid: allComplete,
      read_only_calls_complete: allComplete,
    };
    observations.push(candidate);
    if (apiVersion === PHALA_CONTROL_PLANE_AUTHORITY.api_version) {
      if (candidate.authenticated !== true
        || candidate.strict_schema_valid !== true
        || candidate.response_origin_valid !== true
        || candidate.read_only_calls_complete !== true) {
        throw new Error("reviewed Phala API version failed the exact compatibility plan");
      }
      selectedData = data;
      selectedProjection = projection;
    }
  }
  if (!selectedData || !selectedProjection) {
    throw new Error("reviewed Phala API compatibility observation is unavailable");
  }
  const subject = selectedProjection.subject;
  const resource = selectedProjection.resource;
  const checkedAtMs = Math.floor(runtime.now() / 1_000) * 1_000;
  const checkedAt = new Date(checkedAtMs).toISOString().replace(".000Z", "Z");
  const expiresAt = new Date(checkedAtMs + 30 * 60 * 1_000)
    .toISOString().replace(".000Z", "Z");
  return normalizePhalaCompatibilityReceipt({
    schema: PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_read_only_compatibility_observation_not_launch_authority",
    checked_at: checkedAt,
    expires_at: expiresAt,
    api_origin: PHALA_ORIGIN,
    probed_versions: observations,
    selected_api_version: PHALA_CONTROL_PLANE_AUTHORITY.api_version,
    read_only_calls: [...PHALA_READ_ONLY_COMPATIBILITY_CALLS],
    workspace: {
      workspace_id: subject.workspace.id,
      account_subject_sha256:
        phalaAuthenticatedAccountSubjectSha256(selectedData.getCurrentUser.response),
      authenticated: true,
      billing_status: selectedProjection.billing_status,
    },
    sdk_identity: sdkIdentity,
    kms: selectedProjection.kms,
    os_image: selectedProjection.os_image,
    resource_catalog: resource.resource_catalog,
    quota: resource.quota,
    staging_provision_performed: false,
    mutation_calls: [],
  });
}

function exactReservationResponse(response) {
  if (!isRecord(response) || !Array.isArray(response.app_ids)
    || response.app_ids.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging app-id reservation did not return exactly seven entries");
  }
  return CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const item = response.app_ids[index];
    if (!isRecord(item) || !Number.isSafeInteger(item.nonce) || item.nonce < 0) {
      throw new Error("staging app-id reservation is invalid");
    }
    return Object.freeze({
      domain,
      app_id: exactAppId(item.app_id, `${domain} staging app id`),
      nonce: item.nonce,
    });
  });
}

const PHALA_STAGING_JOURNAL_RECORD_SCHEMA =
  "dnai.phala-pre-provision-staging-journal-record.v1";
const PHALA_STAGING_OUTPUT_RESERVATION_SCHEMA =
  "dnai.phala-pre-provision-staging-output-reservation.v1";
const PHALA_STAGING_BATCH_DOMAIN =
  "dnai-wikigen/phala-pre-provision-staging-batch/v1\0";
const PHALA_STAGING_SOURCE_MANIFEST_DOMAIN =
  "dnai-wikigen/phala-pre-provision-staging-source-manifest/v1\0";
const TARGET_SOURCE_MANIFEST_FIELDS = Object.freeze([
  "cvm_launch_intent",
  "deployment_intent",
  "fresh_contract_deployment_receipt",
  "tinker_account_binding_ceremony_receipt",
  "cvm_launch_review_envelope",
  "cvm_launch_review_evidence",
  "kms_signer_provenance",
  "target_review_input",
]);

function exactNonzeroSha256(value, label) {
  if (typeof value !== "string"
    || !/^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be an exact nonzero SHA-256 digest`);
  }
  return value;
}

function canonicalJournalText(value) {
  assertBoundedJsonGraph(value, { label: "pre-provision staging journal record" });
  assertSecretFreePhalaAuthorityArtifact(value, "pre-provision staging journal record");
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function normalizeStagingSourceManifest(value) {
  const parsed = exactRecord(
    value,
    ["target_sources", "descriptor_materials"],
    "staging source manifest",
  );
  const targetSources = exactRecord(
    parsed.target_sources,
    TARGET_SOURCE_MANIFEST_FIELDS,
    "staging target source manifest",
  );
  const normalizedTargetSources = Object.fromEntries(
    TARGET_SOURCE_MANIFEST_FIELDS.map((field) => [
      field,
      exactNonzeroSha256(
        targetSources[field],
        `staging target source ${field}`,
      ),
    ]),
  );
  if (!Array.isArray(parsed.descriptor_materials)
    || parsed.descriptor_materials.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging source manifest must bind seven descriptor materials");
  }
  const descriptorMaterials = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(
      parsed.descriptor_materials[index],
      ["domain", "descriptor_material_sha256"],
      `staging source manifest descriptor ${index}`,
    );
    if (entry.domain !== domain) {
      throw new Error("staging source manifest descriptors are not in canonical order");
    }
    return {
      domain,
      descriptor_material_sha256: exactNonzeroSha256(
        entry.descriptor_material_sha256,
        `staging descriptor material ${domain}`,
      ),
    };
  });
  const normalized = {
    target_sources: normalizedTargetSources,
    descriptor_materials: descriptorMaterials,
  };
  assertSecretFreePhalaAuthorityArtifact(normalized, "staging source manifest");
  return normalized;
}

function initializeStagingJournal({
  compatibility,
  outputPath,
  releaseSha,
  targetReviewInputSha256,
  sourceManifest,
  operatorAssertedDedicatedWorkspace,
}) {
  if (typeof outputPath !== "string" || !path.isAbsolute(outputPath)
    || path.resolve(outputPath) !== outputPath
    || path.normalize(outputPath) !== outputPath) {
    throw new Error("staging output path must be canonical and absolute");
  }
  const outputDirectory = path.dirname(outputPath);
  if (fs.realpathSync.native(outputDirectory) !== outputDirectory) {
    throw new Error("staging output directory must not traverse an alias");
  }
  const outputBasename = path.basename(outputPath);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$/.test(outputBasename)
    || outputBasename.startsWith("phala-staging-journal.")) {
    throw new Error("staging output basename is invalid or reserved");
  }
  if (typeof releaseSha !== "string"
    || !/^(?!0{40}$)[0-9a-f]{40}$/.test(releaseSha)) {
    throw new Error("staging journal release SHA is invalid");
  }
  const targetDigest = exactNonzeroSha256(
    targetReviewInputSha256,
    "staging target review input",
  );
  if (operatorAssertedDedicatedWorkspace !== true) {
    throw new Error("staging requires an explicit operator designation of the dedicated workspace");
  }
  const normalizedSources = normalizeStagingSourceManifest(sourceManifest);
  const sourceManifestSha256 = domainDigest(
    PHALA_STAGING_SOURCE_MANIFEST_DOMAIN,
    normalizedSources,
  );
  const compatibilitySha256 = phalaCompatibilityReceiptDigest(compatibility);
  const batchId = domainDigest(PHALA_STAGING_BATCH_DOMAIN, {
    release_sha: releaseSha,
    compatibility_receipt_sha256: compatibilitySha256,
    target_review_input_sha256: targetDigest,
    source_manifest_sha256: sourceManifestSha256,
  });
  const handle = pinPhalaPrivateDirectory(outputDirectory);
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    if (listPhalaPinnedPrivateEntries(handle).length !== 0) {
      throw new Error(
        "staging journal/output directory is not empty; automatic retry is forbidden and operator reconciliation is required",
      );
    }
    const reservationText = canonicalJournalText({
      schema: PHALA_STAGING_OUTPUT_RESERVATION_SCHEMA,
      truth_status:
        "durable_output_path_reserved_before_remote_staging_calls_not_authority",
      batch_id: batchId,
      output_basename: outputBasename,
      automatic_retry_authorized: false,
      automatic_resume_authorized: false,
    });
    const outputReservationIdentity = createExclusivePhalaPinnedPrivateFile(
      handle,
      outputBasename,
      Buffer.from(reservationText, "utf8"),
      { mode: 0o600, maximum: MAX_MANIFEST_BYTES },
    );
    let sequence = 0;
    let previousRecordSha256 = outputReservationIdentity.sha256;
    const state = {
      handle,
      outputBasename,
      outputReservationIdentity,
      batchId,
      sequence,
      previousRecordSha256,
      sourceManifestSha256,
      sourceManifest: normalizedSources,
      targetReviewInputSha256: targetDigest,
      successfulDomains: [],
      workspacePreflight: null,
      terminal: false,
    };
    const header = {
      release_sha: releaseSha,
      compatibility_receipt_sha256: compatibilitySha256,
      target_review_input_sha256: targetDigest,
      source_manifest_sha256: sourceManifestSha256,
      source_manifest: normalizedSources,
      workspace_id: compatibility.workspace.workspace_id,
      account_subject_sha256: compatibility.workspace.account_subject_sha256,
      api_origin: compatibility.api_origin,
      api_version: compatibility.selected_api_version,
      sdk_identity: structuredClone(compatibility.sdk_identity),
      commit_call_count: 0,
      automatic_retry_authorized: false,
      automatic_resume_authorized: false,
    };
    appendStagingJournalRecord(state, "attempt_header", header);
    return state;
  } catch (error) {
    closePhalaPinnedPrivateDirectory(handle);
    throw error;
  }
}

function appendStagingJournalRecord(state, event, payload) {
  if (state.terminal) {
    throw new Error("staging journal is terminal and append-only");
  }
  assertPinnedPhalaPrivateDirectoryPathIdentity(state.handle);
  const record = {
    schema: PHALA_STAGING_JOURNAL_RECORD_SCHEMA,
    batch_id: state.batchId,
    sequence: state.sequence,
    event,
    previous_record_sha256: state.previousRecordSha256,
    payload,
  };
  const text = canonicalJournalText(record);
  const fileName = `phala-staging-journal.${String(state.sequence).padStart(6, "0")}.json`;
  const identity = createExclusivePhalaPinnedPrivateFile(
    state.handle,
    fileName,
    Buffer.from(text, "utf8"),
    { mode: 0o600, maximum: MAX_MANIFEST_BYTES },
  );
  const reread = readPhalaPinnedPrivateFile(state.handle, fileName, {
    mode: 0o600,
    minimum: 2,
    maximum: MAX_MANIFEST_BYTES,
    expectedIdentity: identity,
  });
  if (!timingSafeEqual(Buffer.from(text, "utf8"), reread)) {
    throw new Error("staging journal record reread differs from durable bytes");
  }
  state.sequence += 1;
  state.previousRecordSha256 = identity.sha256;
  assertPinnedPhalaPrivateDirectoryPathIdentity(state.handle);
  return identity;
}

function terminateStagingJournal(state, failedAction) {
  if (state.terminal) return;
  try {
    appendStagingJournalRecord(state, "partial_prepare_failure", {
      failed_action: failedAction,
      successful_domains: [...state.successfulDomains],
      successful_prepare_count: state.successfulDomains.length,
      commit_call_count: 0,
      pending_server_state: "pending_server_state_unknown",
      server_cleanup_claimed: false,
      automatic_retry_authorized: false,
      automatic_resume_authorized: false,
      operator_reconciliation_required: true,
    });
  } finally {
    state.terminal = true;
    closePhalaPinnedPrivateDirectory(state.handle);
  }
}

function exactEmptyCommittedCvmList(response) {
  if (!isRecord(response) || !Array.isArray(response.items)
    || response.items.length !== 0 || response.total !== 0
    || response.page !== 1 || response.page_size !== 100
    || ![0, 1].includes(response.pages)) {
    throw new Error(
      "authenticated staging workspace is not an exact complete empty committed-CVM listing",
    );
  }
  return {
    authenticated_committed_cvm_count_before_prepare: 0,
    page: 1,
    page_size: 100,
    pages: response.pages,
    items_count: 0,
    total: 0,
    operator_asserted_dedicated_workspace: true,
    exclusive_workspace_control_proven: false,
  };
}

function stagingDescriptorMaterialSha256(domain, request) {
  const compose = request?.compose_file;
  if (!isRecord(compose) || typeof compose.docker_compose_file !== "string"
    || !Array.isArray(compose.allowed_envs)) {
    throw new Error("staging provision request lacks exact descriptor material");
  }
  return sha256(Buffer.from(`${JSON.stringify(sortedObject({
    domain,
    docker_compose_file: compose.docker_compose_file,
    allowed_environment_keys: compose.allowed_envs,
  }), null, 2)}\n`, "utf8"));
}

/**
 * Construct a one-use prepare-only staging session. Its public surface has no
 * commit, update, restart, generic request, client, transport, or credential
 * accessor. It authenticates the compatibility-bound workspace, reserves
 * seven app ids once, captures exactly seven provision transforms once, and
 * is then permanently closed.
 */
export async function createPinnedPhalaPreProvisionStagingSession({
  compatibilityReceipt,
  outputPath,
  releaseSha,
  targetReviewInputSha256,
  sourceManifest,
  operatorAssertedDedicatedWorkspace,
} = {}) {
  assertProductionExecutionPolicyAvailable();
  assertSafePhalaSdkProcessEnvironment();
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const identity = resolvePinnedPhalaPackageIdentity();
  const runtime = requirePinnedIdentity(identity);
  const now = runtime.now();
  if (now < Date.parse(compatibility.checked_at)
    || now >= Date.parse(compatibility.expires_at)) {
    throw new Error("fresh authenticated compatibility is required for staging capture");
  }
  if (canonicalCompact(projectPinnedSdkCompatibilityIdentity(identity))
      !== canonicalCompact(compatibility.sdk_identity)) {
    throw new Error("reviewed SDK runtime capsule identity differs from compatibility");
  }
  const credential = readCanonicalPhalaCurrentProfile();
  const actions = await loadPinnedCloudActions(identity);
  const journal = initializeStagingJournal({
    compatibility,
    outputPath,
    releaseSha,
    targetReviewInputSha256,
    sourceManifest,
    operatorAssertedDedicatedWorkspace,
  });
  const state = {
    actions,
    compatibility,
    credential,
    identity,
    journal,
    in_flight: false,
    phase: "created",
    transport: createPinnedSdkActionClient({
      apiKey: credential.api_key,
      apiVersion: compatibility.selected_api_version,
      httpsRequest: runtime.httpsRequest,
      setTimeoutIntrinsic: runtime.setTimeout,
      clearTimeoutIntrinsic: runtime.clearTimeout,
    }),
  };
  const session = Object.freeze({
    async reserveAppIds() {
      if (state.phase !== "created") {
        throw new Error("staging app ids can be reserved exactly once");
      }
      let activeAction = "getCurrentUser";
      try {
        appendStagingJournalRecord(journal, "before_getCurrentUser", {
          method: "getCurrentUser",
        });
        const account = await invokePreProvisionSdkAction(state, "getCurrentUser");
        appendStagingJournalRecord(journal, "after_getCurrentUser", {
          method: "getCurrentUser",
          http_method: account.capture.http_method,
          request_target_sha256: account.capture.request_target_sha256,
          request_semantics_sha256: account.capture.request_semantics_sha256,
          response_sha256: account.capture.raw_response_sha256,
        });
        const subject = assertCredentialMatchesAuthenticatedSubject(
          credential,
          account.response,
        );
        if (subject.workspace.id !== compatibility.workspace.workspace_id
          || phalaAuthenticatedAccountSubjectSha256(account.response)
            !== compatibility.workspace.account_subject_sha256) {
          throw new Error("staging account differs from authenticated compatibility");
        }
        activeAction = "getWorkspace";
        appendStagingJournalRecord(journal, "before_getWorkspace", { method: activeAction });
        const workspace = await invokePreProvisionSdkAction(state, "getWorkspace", [subject.workspace.slug]);
        assertPhalaWorkspaceActiveBilling({ workspace: workspace.response, authenticatedSubject: subject });
        appendStagingJournalRecord(journal, "after_getWorkspace", {
          method: activeAction,
          http_method: workspace.capture.http_method,
          request_target_sha256: workspace.capture.request_target_sha256,
          request_semantics_sha256: workspace.capture.request_semantics_sha256,
          response_sha256: workspace.capture.raw_response_sha256,
        });
        activeAction = "getCvmList";
        appendStagingJournalRecord(journal, "before_getCvmList", {
          method: "getCvmList",
          page: 1,
          page_size: 100,
        });
        const cvmList = await invokePreProvisionSdkAction(
          state,
          "getCvmList",
          [{ page: 1, page_size: 100 }],
        );
        appendStagingJournalRecord(journal, "after_getCvmList", {
          method: "getCvmList",
          http_method: cvmList.capture.http_method,
          request_target_sha256: cvmList.capture.request_target_sha256,
          request_semantics_sha256: cvmList.capture.request_semantics_sha256,
          response_sha256: cvmList.capture.raw_response_sha256,
        });
        const empty = exactEmptyCommittedCvmList(cvmList.response);
        journal.workspacePreflight = Object.freeze({
          ...empty,
          response_sha256: cvmList.capture.raw_response_sha256,
        });
        appendStagingJournalRecord(journal, "validated_getCvmList", {
          method: "getCvmList",
          response_sha256: cvmList.capture.raw_response_sha256,
          ...empty,
        });
        activeAction = "nextAppIds";
        appendStagingJournalRecord(journal, "before_nextAppIds", {
          method: "nextAppIds",
          counts: CVM_LAUNCH_DOMAINS.length,
        });
        const reserved = await invokePreProvisionSdkAction(
          state,
          "nextAppIds",
          [{ counts: CVM_LAUNCH_DOMAINS.length }],
        );
        appendStagingJournalRecord(journal, "after_nextAppIds", {
          method: "nextAppIds",
          http_method: reserved.capture.http_method,
          request_target_sha256: reserved.capture.request_target_sha256,
          request_semantics_sha256: reserved.capture.request_semantics_sha256,
          response_sha256: reserved.capture.raw_response_sha256,
        });
        const reservations = exactReservationResponse(reserved.response);
        appendStagingJournalRecord(journal, "validated_nextAppIds", {
          method: "nextAppIds",
          response_sha256: reserved.capture.raw_response_sha256,
          reservations: reservations.map(({ domain, app_id: appId, nonce }) => ({
            domain,
            app_id: appId,
            nonce,
          })),
        });
        state.phase = "reserved";
        return reservations;
      } catch (error) {
        state.phase = "closed";
        terminateStagingJournal(journal, activeAction);
        throw error;
      }
    },
    async captureProvisionBatch(invocations) {
      if (state.phase !== "reserved") {
        throw new Error("staging provision capture requires one fresh reservation");
      }
      if (!Array.isArray(invocations)
        || invocations.length !== CVM_LAUNCH_DOMAINS.length) {
        throw new Error("staging capture requires exactly seven provision requests");
      }
      state.phase = "capturing";
      const domains = [];
      try {
        for (let index = 0; index < CVM_LAUNCH_DOMAINS.length; index += 1) {
          const domain = CVM_LAUNCH_DOMAINS[index];
          const invocation = exactRecord(
            invocations[index],
            ["domain", "request"],
            `staging invocation ${index}`,
          );
          if (invocation.domain !== domain) {
            throw new Error("staging provision requests are not in canonical domain order");
          }
          const projection = projectPinnedProvisionWireEvidence(invocation.request);
          const expectedSdkRequest = projectPinnedSdkActionRequest(
            "provisionCvm",
            [invocation.request],
          );
          const expectedRequestTargetSha256 = domainDigest(
            "dnai-wikigen/phala-authenticated-sdk-request-target/v1\0",
            { path_and_query: expectedSdkRequest.path_and_query },
          );
          const expectedRequestSemanticsSha256 =
            phalaAuthenticatedSdkRequestSemanticsSha256({
              httpMethod: expectedSdkRequest.http_method,
              pathAndQuery: expectedSdkRequest.path_and_query,
              body: expectedSdkRequest.body,
            });
          const expectedMaterial = journal.sourceManifest.descriptor_materials[index];
          if (expectedMaterial.domain !== domain
            || stagingDescriptorMaterialSha256(domain, invocation.request)
              !== expectedMaterial.descriptor_material_sha256) {
            throw new Error(
              "staging provision request descriptor material differs from the durable source manifest",
            );
          }
          appendStagingJournalRecord(journal, "before_provisionCvm", {
            method: "provisionCvm",
            domain,
            index,
            app_id: invocation.request.app_id,
            nonce: invocation.request.nonce,
            pre_transform_request_sha256: projection.pre_transform_request_sha256,
            expected_post_transform_body_sha256:
              projection.expected_post_transform_body_sha256,
            pre_transform_compose_hash: projection.pre_transform_compose_hash,
            expected_post_transform_compose_hash:
              projection.expected_post_transform_compose_hash,
            expected_http_method: expectedSdkRequest.http_method,
            expected_request_target_sha256: expectedRequestTargetSha256,
            expected_request_semantics_sha256: expectedRequestSemanticsSha256,
          });
          const observed = await invokePreProvisionSdkAction(
            state,
            "provisionCvm",
            [invocation.request],
          );
          const response = observed.response;
          journal.successfulDomains.push(domain);
          appendStagingJournalRecord(journal, "after_provisionCvm", {
            method: "provisionCvm",
            domain,
            index,
            app_id: invocation.request.app_id,
            nonce: invocation.request.nonce,
            http_method: observed.capture.http_method,
            request_target_sha256: observed.capture.request_target_sha256,
            request_semantics_sha256: observed.capture.request_semantics_sha256,
            response_sha256: observed.capture.raw_response_sha256,
            remote_prepare_response_count: journal.successfulDomains.length,
          });
          if (observed.capture.captured_post_transform_body_sha256
                !== projection.expected_post_transform_body_sha256
            || observed.capture.http_method !== expectedSdkRequest.http_method
            || observed.capture.request_target_sha256 !== expectedRequestTargetSha256
            || observed.capture.request_semantics_sha256
              !== expectedRequestSemanticsSha256
            || response?.app_id !== invocation.request.app_id
            || response?.compose_hash !== projection.expected_post_transform_compose_hash
            || response?.os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash) {
            throw new Error("staging provision response differs from exact wire projection");
          }
          assertPreparedCvmObservation({
            response, rawPlacement: observed.capture.raw_identity_fields, domain,
            appId: invocation.request.app_id,
            expectedComposeHash: projection.expected_post_transform_compose_hash,
            expectedKmsProjection: compatibility.kms,
            expectedInstanceType: invocation.request.instance_type,
          });
          const domainEvidence = Object.freeze({
            domain,
            http_method: observed.capture.http_method,
            request_target_sha256: observed.capture.request_target_sha256,
            request_semantics_sha256: observed.capture.request_semantics_sha256,
            pre_transform_request_sha256: projection.pre_transform_request_sha256,
            expected_post_transform_body_sha256:
              projection.expected_post_transform_body_sha256,
            captured_post_transform_body_sha256:
              observed.capture.captured_post_transform_body_sha256,
            pre_transform_compose_hash: projection.pre_transform_compose_hash,
            expected_post_transform_compose_hash:
              projection.expected_post_transform_compose_hash,
            prepare_server_compose_hash: response.compose_hash,
            prepare_response_sha256: observed.capture.raw_response_sha256,
          });
          domains.push(domainEvidence);
          appendStagingJournalRecord(journal, "validated_provisionCvm", {
            method: "provisionCvm",
            index,
            ...domainEvidence,
            app_id: invocation.request.app_id,
            nonce: invocation.request.nonce,
            successful_prepare_count: journal.successfulDomains.length,
          });
        }
        const finalRecord = appendStagingJournalRecord(
          journal,
          "prepare_batch_complete",
          {
            successful_domains: [...journal.successfulDomains],
            successful_prepare_count: CVM_LAUNCH_DOMAINS.length,
            commit_call_count: 0,
            workspace_preflight: journal.workspacePreflight,
            pending_server_state:
              "seven_prepares_succeeded_uncommitted_operator_reconciliation_required",
            server_cleanup_claimed: false,
            automatic_retry_authorized: false,
            automatic_resume_authorized: false,
          },
        );
        journal.terminal = true;
        state.phase = "closed";
        state.completedCapture = Object.freeze({
          domains: Object.freeze(structuredClone(domains)),
          workspace_preflight: journal.workspacePreflight,
          journal_final_sha256: finalRecord.sha256,
          journal_successful_prepare_count: CVM_LAUNCH_DOMAINS.length,
          completed_at_ms: Math.floor(runtime.now() / 1_000) * 1_000,
        });
        return state.completedCapture;
      } catch (error) {
        state.phase = "closed";
        terminateStagingJournal(journal, "provisionCvm");
        throw error;
      }
    },
  });
  PRE_PROVISION_STAGING_SESSIONS.set(session, state);
  return session;
}

export function publishPinnedPhalaPreProvisionStagingReceipt({
  stagingSession,
  canonicalReceiptText,
} = {}) {
  const state = PRE_PROVISION_STAGING_SESSIONS.get(stagingSession);
  if (!state || state.phase !== "closed" || state.journal.terminal !== true
    || state.journal.successfulDomains.length !== CVM_LAUNCH_DOMAINS.length
    || !state.completedCapture) {
    throw new Error("a completed local staging session is required for publication");
  }
  let parsed;
  try {
    parsed = JSON.parse(canonicalReceiptText);
  } catch {
    throw new Error("staging receipt publication requires canonical JSON");
  }
  const normalized = normalizePhalaSdkWireTransformStagingReceipt(parsed, {
    compatibilityReceipt: state.compatibility,
  });
  const expectedCapturedAt = new Date(state.completedCapture.completed_at_ms)
    .toISOString().replace(".000Z", "Z");
  const expectedExpiresAt = new Date(Math.min(
    state.completedCapture.completed_at_ms + 10 * 60 * 1_000,
    Date.parse(state.compatibility.expires_at),
  )).toISOString().replace(".000Z", "Z");
  const expectedText = canonicalPhalaSdkWireTransformStagingReceiptText(
    normalized,
    { compatibilityReceipt: state.compatibility },
  );
  if (canonicalReceiptText !== expectedText
    || normalized.target_review_input_sha256
      !== state.journal.targetReviewInputSha256
    || normalized.journal_final_sha256 !== state.journal.previousRecordSha256
    || normalized.workspace_preflight.response_sha256
      !== state.journal.workspacePreflight.response_sha256
    || normalized.captured_at !== expectedCapturedAt
    || normalized.expires_at !== expectedExpiresAt
    || canonicalCompact(normalized.domains)
      !== canonicalCompact(state.completedCapture.domains)) {
    throw new Error("staging receipt differs from the completed durable journal");
  }
  try {
    assertPinnedPhalaPrivateDirectoryPathIdentity(state.journal.handle);
    const identity = publishPhalaPinnedPrivateFile(
      state.journal.handle,
      state.journal.outputBasename,
      Buffer.from(canonicalReceiptText, "utf8"),
      {
        publishMode: "replace",
        mode: 0o600,
        maximum: MAX_MANIFEST_BYTES,
        expectedExistingIdentity: state.journal.outputReservationIdentity,
      },
    );
    assertPinnedPhalaPrivateDirectoryPathIdentity(state.journal.handle);
    return Object.freeze({
      artifact_sha256: identity.sha256,
      bytes: identity.size,
      status:
        "canonical_private_reserved_path_atomically_finalized_without_clobber",
    });
  } finally {
    closePhalaPinnedPrivateDirectory(state.journal.handle);
  }
}

export function assertPinnedPhalaPreProvisionStagingSession(value) {
  const state = PRE_PROVISION_STAGING_SESSIONS.get(value);
  if (!state || !["created", "reserved", "capturing", "closed"].includes(state.phase)
    || Object.keys(value).sort().join(",")
      !== "captureProvisionBatch,reserveAppIds") {
    throw new Error("a locally created pinned prepare-only staging session is required");
  }
  return value;
}

function normalizeProvisionInvocation(value, target) {
  assertBoundedJsonGraph(value, { label: "provisionCvm invocation" });
  const parsed = exactRecord(value, ["domain", "request"], "provisionCvm invocation");
  const domain = exactDomain(parsed.domain, "provisionCvm domain");
  const request = parsed.request;
  const wireBody = projectPinnedProvisionWireBody(request);
  const profile = target.app_compose_profiles[domain];
  const resource = target.resource_targets[domain];
  const compose = request.compose_file;
  if (request.name !== profile.name
    || request.instance_type !== resource.instance_type
    || request.disk_size !== resource.disk_size
    || request.image !== target.os_image.name
    || request.listed !== false
    || request.kms !== "PHALA" || request.kms_contract_id !== target.kms.contract.id
    || request.key_provider_mode !== "kms"
    || request.skip_gateway !== profile.skip_gateway
    || compose.name !== profile.name
    || compose.manifest_version !== profile.manifest_version
    || compose.runner !== profile.runner
    || compose.kms_enabled !== profile.kms_enabled
    || compose.gateway_enabled !== profile.gateway_enabled
    || compose.tproxy_enabled !== profile.tproxy_enabled
    || compose.storage_fs !== profile.storage_fs
    || compose.secure_time !== profile.secure_time
    || compose.public_logs !== profile.public_logs
    || compose.public_sysinfo !== profile.public_sysinfo
    || compose.public_tcbinfo !== profile.public_tcbinfo
    || canonicalCompact(request.env_keys)
      !== canonicalCompact(exactSortedEnvironmentKeys(compose.allowed_envs, "compose allowed_envs"))
    || canonicalCompact(request.env_keys)
      !== canonicalCompact(exactSortedEnvironmentKeys(request.env_keys, "provision env_keys"))
    || !Number.isSafeInteger(request.nonce) || request.nonce < 0) {
    throw new Error(`${domain} provision request differs from exact target authority`);
  }
  exactAppId(request.app_id, "provision app id");
  return { domain, request, wireBody };
}

function normalizeCommitInvocation(value, target) {
  assertBoundedJsonGraph(value, { label: "commitCvmProvision invocation" });
  const parsed = exactRecord(value, ["domain", "request"], "commitCvmProvision invocation");
  const domain = exactDomain(parsed.domain, "commitCvmProvision domain");
  const request = exactRecord(parsed.request, [
    "app_id",
    "compose_hash",
    "kms_contract_id",
    "env_keys",
    "encrypted_env",
  ], "commitCvmProvision request");
  const appId = exactAppId(request.app_id, "commit app id");
  if (typeof request.compose_hash !== "string"
    || !/^(?!0{64}$)[0-9a-f]{64}$/.test(request.compose_hash)
    || request.kms_contract_id !== target.kms.contract.id) {
    throw new Error(`${domain} commit metadata differs from exact target authority`);
  }
  const environmentKeys = exactSortedEnvironmentKeys(request.env_keys, "commit env_keys");
  if (typeof request.encrypted_env !== "string"
    || request.encrypted_env.length < 120
    || request.encrypted_env.length > MAX_HTTP_REQUEST_BYTES * 2
    || request.encrypted_env.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(request.encrypted_env)) {
    throw new Error("commit encrypted environment is invalid");
  }
  return {
    domain,
    request: {
      app_id: appId,
      compose_hash: request.compose_hash,
      kms_contract_id: target.kms.contract.id,
      env_keys: environmentKeys,
      encrypted_env: request.encrypted_env,
    },
  };
}

function normalizeUpdateCvmEnvsInvocation(value) {
  assertBoundedJsonGraph(value, { label: "updateCvmEnvs invocation" });
  const parsed = exactRecord(
    value,
    ["domain", "cvmId", "request"],
    "updateCvmEnvs invocation",
  );
  const domain = exactDomain(parsed.domain, "updateCvmEnvs domain");
  const cvmId = exactCanonicalIdentifier(parsed.cvmId, "updateCvmEnvs CVM id");
  const request = exactRecord(
    parsed.request,
    ["encrypted_env"],
    "updateCvmEnvs request",
  );
  if (typeof request.encrypted_env !== "string"
    || request.encrypted_env.length < 120
    || request.encrypted_env.length > MAX_HTTP_REQUEST_BYTES * 2
    || request.encrypted_env.length % 2 !== 0
    || !/^[0-9a-f]+$/.test(request.encrypted_env)) {
    throw new Error("updateCvmEnvs encrypted environment is invalid");
  }
  return {
    domain,
    cvmId,
    request: {
      id: cvmId,
      encrypted_env: request.encrypted_env,
    },
    wireBody: {
      encrypted_env: request.encrypted_env,
    },
  };
}

function normalizeRestartCvmInvocation(value) {
  assertBoundedJsonGraph(value, { label: "restartCvm invocation" });
  const parsed = exactRecord(
    value,
    ["domain", "cvmId", "force"],
    "restartCvm invocation",
  );
  if (parsed.force !== false) {
    throw new Error("production restartCvm requires force=false");
  }
  return {
    domain: exactDomain(parsed.domain, "restartCvm domain"),
    cvmId: exactCanonicalIdentifier(parsed.cvmId, "restartCvm CVM id"),
    force: false,
  };
}

function validateAuthenticatedAccount(response, state) {
  const subject = normalizePhalaAuthenticatedAccountSubject(response);
  const credential = state.credential;
  if (subject.workspace.id !== state.target.workspace.workspace_id
    || phalaAuthenticatedAccountSubjectSha256(response)
      !== state.target.workspace.account_subject_sha256
    || subject.workspace.name !== credential.workspace.name
    || subject.workspace.slug !== credential.workspace.slug
    || subject.user.username !== credential.user.username
    || subject.user.email !== credential.user.email) {
    throw new Error("authenticated Phala account does not match reviewed target and current profile");
  }
  return subject;
}

function makeObservation(state, method, domain, capture, response, observedAt) {
  const callSequence = state.next_call_sequence;
  if (!Number.isSafeInteger(callSequence) || callSequence < 1) {
    throw new Error("authenticated SDK observation call sequence is exhausted or invalid");
  }
  const observation = Object.freeze({
    schema: PHALA_AUTHENTICATED_SDK_OBSERVATION_SCHEMA,
    truth_status:
      "authenticated_exact_origin_sdk_action_observation_not_tdx_attestation_or_launch_completion",
    method,
    target_domain: domain,
    call_sequence: callSequence,
    observed_at: observedAt,
    api_origin: PHALA_ORIGIN,
    api_version: capture.api_version,
    workspace_id: state.target.workspace.workspace_id,
    adapter_identity_sha256: state.identity_sha256,
    target_authority_sha256: state.identity.production_target_authority_sha256,
    sdk_runtime_capsule_sha256: state.identity.sdk_runtime_capsule_sha256,
    transport_authentication: "canonical_current_profile_x_api_key_over_tls",
    http_method: capture.http_method,
    http_status: capture.http_status,
    request_target_sha256: capture.request_target_sha256,
    request_semantics_sha256: capture.request_semantics_sha256,
    captured_post_transform_body_sha256:
      capture.captured_post_transform_body_sha256,
    serialized_http_body_sha256: capture.serialized_http_body_sha256,
    raw_response_sha256: capture.raw_response_sha256,
    sdk_response_sha256: domainDigest(
      "dnai-wikigen/phala-authenticated-sdk-response/v1\0",
      response,
    ),
  });
  AUTHENTICATED_OBSERVATIONS.set(observation, Object.freeze({
    adapter: state.adapter,
    call_sequence: callSequence,
    response: structuredClone(response),
    raw_identity_fields: structuredClone(capture.raw_identity_fields),
  }));
  state.next_call_sequence = callSequence + 1;
  return observation;
}

async function invokeSdkAction(state, {
  method,
  domain = null,
  actionArguments = [],
  beforeObservation,
  expectedPostTransformBodySha256,
} = {}) {
  if (state.historical_continuity_read_only === true
    && !HISTORICAL_CONTINUITY_READ_ONLY_METHODS.includes(method)) {
    throw new Error("historical continuity observer forbids every non-continuity SDK action");
  }
  if (state.in_flight) throw new Error("pinned SDK adapter forbids concurrent calls");
  assertSafePhalaSdkProcessEnvironment();
  assertAdapterAuthorityFresh(state);
  const reread = readCanonicalPhalaCurrentProfile(state.credential.directory);
  assertSameCanonicalCredential(state.credential, reread);
  if (method !== "getCurrentUser" && state.workspace_verified !== true) {
    throw new Error("getCurrentUser must authenticate the reviewed workspace before any other call");
  }
  if (PHALA_PRODUCTION_MUTATION_METHODS.includes(method) && state.billing_verified !== true) {
    throw new Error("explicit active workspace billing must be verified before any Phala mutation or reservation");
  }
  const action = state.actions[method];
  if (typeof action !== "function") throw new Error("pinned SDK action is unavailable");
  state.in_flight = true;
  state.transport.begin(method, actionArguments);
  try {
    if (method === "getCurrentUser") {
      state.workspace_verified = false;
      state.billing_verified = false;
    }
    const response = await action(state.transport.client, ...actionArguments);
    assertBoundedJsonGraph(response, { label: `${method} SDK response` });
    const capture = state.transport.finish();
    if (expectedPostTransformBodySha256 !== undefined
      && capture.captured_post_transform_body_sha256
        !== expectedPostTransformBodySha256) {
      throw new Error("captured SDK post-transform body differs from exact local projection");
    }
    if (beforeObservation) beforeObservation(response, capture);
    assertAdapterAuthorityFresh(state);
    const observedAt = canonicalInternalTimestamp(state.now());
    const observation = makeObservation(
      state,
      method,
      domain,
      capture,
      response,
      observedAt,
    );
    if (method === "getCurrentUser") state.workspace_verified = true;
    return observation;
  } catch (error) {
    state.transport.abort();
    throw error;
  } finally {
    state.in_flight = false;
  }
}

function adapterIdentityDigest(identity) {
  return domainDigest(PHALA_PRODUCTION_SDK_ADAPTER_IDENTITY_DOMAIN, identity);
}

export function assertPinnedPhalaProductionSdkAdapter(value) {
  const state = PRODUCTION_ADAPTERS.get(value);
  if (!state || state.adapter !== value) {
    throw new Error("a locally created pinned Phala production SDK adapter is required");
  }
  return value;
}

export function assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver(value) {
  const adapter = assertPinnedPhalaProductionSdkAdapter(value);
  if (PRODUCTION_ADAPTERS.get(adapter).historical_continuity_read_only !== true
    || Object.keys(adapter).sort().join(",")
      !== [...HISTORICAL_CONTINUITY_READ_ONLY_METHODS].sort().join(",")) {
    throw new Error("a locally created historical-continuity read-only Phala observer is required");
  }
  return adapter;
}

export function projectPinnedPhalaProductionSdkAdapterIdentity(value) {
  const adapter = assertPinnedPhalaProductionSdkAdapter(value);
  return structuredClone(PRODUCTION_ADAPTERS.get(adapter).identity);
}

export function pinnedPhalaProductionSdkAdapterIdentitySha256(value) {
  return adapterIdentityDigest(projectPinnedPhalaProductionSdkAdapterIdentity(value));
}

export function assertAuthenticatedPhalaSdkObservation(value, {
  adapter,
  method,
  domain,
} = {}) {
  assertPinnedPhalaProductionSdkAdapter(adapter);
  const state = AUTHENTICATED_OBSERVATIONS.get(value);
  if (!state || state.adapter !== adapter
    || value?.schema !== PHALA_AUTHENTICATED_SDK_OBSERVATION_SCHEMA
    || value.method !== method
    || value.target_domain !== (domain ?? null)
    || !Number.isSafeInteger(value.call_sequence)
    || value.call_sequence < 1
    || value.call_sequence !== state.call_sequence) {
    throw new Error("a matching locally authenticated Phala SDK observation is required");
  }
  return value;
}

export function authenticatedPhalaSdkObservationSha256(value, options) {
  const observation = assertAuthenticatedPhalaSdkObservation(value, options);
  return domainDigest(PHALA_AUTHENTICATED_SDK_OBSERVATION_DOMAIN, observation);
}

export function readAuthenticatedPhalaSdkObservationResponse(value, options) {
  const observation = assertAuthenticatedPhalaSdkObservation(value, options);
  return structuredClone(AUTHENTICATED_OBSERVATIONS.get(observation).response);
}

export function readAuthenticatedPhalaSdkObservationRawIdentityFields(value, options) {
  const observation = assertAuthenticatedPhalaSdkObservation(value, options);
  return structuredClone(AUTHENTICATED_OBSERVATIONS.get(observation).raw_identity_fields);
}

/** Restore only a read-only replica lookup after current authenticated readback.
 * A serialized receipt alone cannot restore authority. Its caller must have
 * reverified the historical launch lineage and reconstructed current posture;
 * this boundary additionally checks the actual branded SDK response itself.
 */
export function bindPinnedPhalaCommittedEnvironmentKeyLookup({
  adapter, cvmInfoObservation, postureReceipt,
} = {}) {
  const state = PRODUCTION_ADAPTERS.get(adapter);
  if (!state) throw new Error("committed key lookup requires a pinned Phala adapter");
  const posture = assertVerifiedProductionCvmPostureReceipt(postureReceipt);
  if (!posture.prepared_binding || !posture.environment_public_key) {
    throw new Error("committed key lookup requires durable contract-KMS prepare authority");
  }
  const raw = readAuthenticatedPhalaSdkObservationResponse(cvmInfoObservation, {
    adapter, method: "getCvmInfo", domain: posture.domain,
  });
  if (String(raw.id) !== posture.cvm_id) {
    throw new Error("committed key lookup CVM differs from authenticated readback");
  }
  const kmsProjection = Object.fromEntries([
    "contract", "replicas", "eligible_placements", "gateways",
  ].map((key) => [key, state.target.kms[key]]));
  assertProductionCvmPosture(raw, {
    domain: posture.domain, appId: posture.app_id, composeHash: posture.compose_hash,
    instanceType: posture.instance_type, diskSize: posture.disk_size,
    kmsProjection, preparedBinding: posture.prepared_binding,
    environmentPublicKey: posture.environment_public_key,
  });
  const binding = {
    app_id: posture.app_id, compose_hash: posture.compose_hash,
    ...posture.prepared_binding,
  };
  const previous = state.prepared_by_domain.get(posture.domain);
  if (previous && Object.keys(binding).some((key) => previous[key] !== binding[key])) {
    throw new Error("committed key lookup conflicts with the existing prepared binding");
  }
  state.prepared_by_domain.set(posture.domain, Object.freeze(binding));
  return adapter;
}

/**
 * Creates the only mutation-capable Phala adapter. The constructor has no
 * credential, client, transport, callback, origin, version, or clock inputs.
 * Its credential source is the stable-read canonical current CLI profile and
 * its SDK actions come only from the exact reviewed data-URL runtime capsule.
 */
async function createPinnedPhalaSdkAdapter(value, {
  historicalContinuityReadOnly = false,
} = {}) {
  assertProductionExecutionPolicyAvailable();
  assertSafePhalaSdkProcessEnvironment();
  const { compatibility, staging, target } = exactAuthorityInputs(value);
  const identity = resolvePinnedPhalaPackageIdentity();
  const compatibilityIdentity = projectPinnedSdkCompatibilityIdentity(identity);
  if (canonicalCompact(compatibilityIdentity)
      !== canonicalCompact(compatibility.sdk_identity)
    || canonicalCompact(compatibilityIdentity)
      !== canonicalCompact(target.sdk_identity)) {
    throw new Error("reviewed SDK runtime capsule identity differs from target authority");
  }
  assertPinnedPhalaClientTransport({
    baseURL: target.api.origin,
    version: target.api.version,
    timeout: target.api.timeout_ms,
    retry: target.api.retry,
    redirect: target.api.redirect,
  });
  const credential = readCanonicalPhalaCurrentProfile();
  const actions = await loadPinnedCloudActions(identity);
  const runtime = requirePinnedIdentity(identity);
  const transport = createPinnedSdkActionClient({
    apiKey: credential.api_key,
    apiVersion: target.api.version,
    httpsRequest: runtime.httpsRequest,
    setTimeoutIntrinsic: runtime.setTimeout,
    clearTimeoutIntrinsic: runtime.clearTimeout,
  });
  const adapterIdentity = Object.freeze({
    schema: PHALA_PRODUCTION_SDK_ADAPTER_IDENTITY_SCHEMA,
    truth_status:
      "exact_reviewed_data_url_sdk_runtime_capsule_and_target_bound_no_path_or_sdk_environment_fallback",
    api_origin: PHALA_ORIGIN,
    api_version: target.api.version,
    transport: Object.freeze({
      implementation: "node_https_internal_exact_origin",
      timeout_ms: PHALA_PINNED_CLIENT_TRANSPORT.timeout_ms,
      retry: 0,
      redirect: "error",
    }),
    credential_source: "canonical_owned_0700_directory_0600_current_profile_file",
    workspace_id: target.workspace.workspace_id,
    account_subject_sha256: target.workspace.account_subject_sha256,
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    sdk_wire_transform_staging_receipt_sha256:
      phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      }),
    production_target_authority_sha256:
      phalaProductionTargetAuthorityDigest(target, {
        compatibilityReceipt: compatibility,
        sdkWireTransformStagingReceipt: staging,
      }),
    sdk_runtime_capsule_authority_sha256:
      compatibilityIdentity.sdk_runtime_capsule_authority_sha256,
    sdk_runtime_capsule_sha256:
      compatibilityIdentity.sdk_runtime_capsule_sha256,
    sdk_action_request_policy_sha256:
      compatibilityIdentity.sdk_action_request_policy_sha256,
    node_runtime_executable_sha256:
      compatibilityIdentity.node_runtime_executable_sha256,
  });
  const adapterMethods = {
    async getCurrentUser() {
      return invokeSdkAction(state, {
        method: "getCurrentUser",
        beforeObservation(response) {
          state.authenticated_subject = validateAuthenticatedAccount(response, state);
        },
      });
    },
    async getWorkspace() {
      return invokeSdkAction(state, {
        method: "getWorkspace",
        actionArguments: [credential.workspace.slug],
        beforeObservation(response) {
          assertPhalaWorkspaceActiveBilling({ workspace: response, authenticatedSubject: state.authenticated_subject });
          state.billing_verified = true;
        },
      });
    },
    async getCvmCreateResources() {
      return invokeSdkAction(state, { method: "getCvmCreateResources" });
    },
    async getOsImages() {
      return invokeSdkAction(state, {
        method: "getOsImages",
        actionArguments: [{ page: 1, page_size: 100, is_dev: false }],
      });
    },
    async getKmsList() {
      return invokeSdkAction(state, {
        method: "getKmsList",
        actionArguments: [{ page: 1, page_size: 100, is_onchain: false }],
      });
    },
    async getKmsInfo(invocation) {
      const { kmsId } = exactRecord(invocation, ["kmsId"], "KMS replica detail invocation");
      if (target.kms.replicas.filter((entry) => entry.id === kmsId).length !== 1) {
        throw new Error("KMS replica detail requires an exact reviewed member");
      }
      return invokeSdkAction(state, {
        method: "getKmsInfo",
        actionArguments: [{ kms_id: kmsId }],
      });
    },
    async listKmsContracts() {
      return invokeSdkAction(state, {
        method: "listKmsContracts", actionArguments: [{ page: 1, page_size: 100, is_onchain: false }],
      });
    },
    async getKmsContract() {
      return invokeSdkAction(state, {
        method: "getKmsContract", actionArguments: [{ slug: target.kms.contract.id }],
      });
    },
    async listKmsContractNodes() {
      return invokeSdkAction(state, {
        method: "listKmsContractNodes", actionArguments: [{ slug: target.kms.contract.id }],
      });
    },
    async nextAppIds() {
      return invokeSdkAction(state, {
        method: "nextAppIds",
        actionArguments: [{ counts: PHALA_EXECUTION_ORDER.length }],
      });
    },
    async provisionCvm(invocation) {
      const normalized = normalizeProvisionInvocation(invocation, target);
      if (state.prepared_by_domain.has(normalized.domain)) {
        throw new Error("domain already has a validated prepare; automatic repetition is forbidden");
      }
      return invokeSdkAction(state, {
        method: "provisionCvm",
        domain: normalized.domain,
        actionArguments: [normalized.request],
        expectedPostTransformBodySha256:
          phalaSdkJsonBodySemanticDigest(normalized.wireBody),
        beforeObservation(response, capture) {
          const projection = projectPinnedProvisionWireEvidence(normalized.request);
          const prepared = assertPreparedCvmObservation({
            response, rawPlacement: capture.raw_identity_fields, domain: normalized.domain,
            appId: normalized.request.app_id,
            expectedComposeHash: projection.expected_post_transform_compose_hash,
            expectedKmsProjection: {
              contract: target.kms.contract, replicas: target.kms.replicas,
              eligible_placements: target.kms.eligible_placements, gateways: target.kms.gateways,
            },
            expectedInstanceType: normalized.request.instance_type,
          });
          state.prepared_by_domain.set(normalized.domain, prepared);
        },
      });
    },
    async getAppEnvEncryptPubKey(invocation) {
      assertBoundedJsonGraph(invocation, {
        label: "getAppEnvEncryptPubKey invocation",
      });
      const parsed = exactRecord(invocation, ["domain", "appId"],
        "getAppEnvEncryptPubKey invocation");
      const domain = exactDomain(parsed.domain, "environment key domain");
      const appId = exactAppId(parsed.appId, "environment key app id");
      const prepared = state.prepared_by_domain.get(domain);
      if (!prepared || prepared.app_id !== appId) {
        throw new Error("environment key lookup requires a validated prepared or committed replica binding");
      }
      return invokeSdkAction(state, {
        method: "getAppEnvEncryptPubKey",
        domain,
        actionArguments: [{ kms: prepared.kms_id, app_id: appId }],
      });
    },
    async commitCvmProvision(invocation) {
      const normalized = normalizeCommitInvocation(invocation, target);
      const prepared = state.prepared_by_domain.get(normalized.domain);
      if (!prepared || normalized.request.app_id !== prepared.app_id
        || normalized.request.compose_hash !== prepared.compose_hash
        || normalized.request.kms_contract_id !== prepared.kms_contract_id) {
        throw new Error("commit requires the exact validated prepare binding");
      }
      return invokeSdkAction(state, {
        method: "commitCvmProvision",
        domain: normalized.domain,
        actionArguments: [normalized.request],
      });
    },
    async updateCvmEnvs(invocation) {
      const normalized = normalizeUpdateCvmEnvsInvocation(invocation);
      return invokeSdkAction(state, {
        method: "updateCvmEnvs",
        domain: normalized.domain,
        actionArguments: [normalized.request],
        expectedPostTransformBodySha256:
          phalaSdkJsonBodySemanticDigest(normalized.wireBody),
      });
    },
    async restartCvm(invocation) {
      const normalized = normalizeRestartCvmInvocation(invocation);
      return invokeSdkAction(state, {
        method: "restartCvm",
        domain: normalized.domain,
        actionArguments: [{ id: normalized.cvmId, force: false }],
        expectedPostTransformBodySha256:
          phalaSdkJsonBodySemanticDigest({ force: false }),
      });
    },
    async getCvmInfo(invocation) {
      assertBoundedJsonGraph(invocation, { label: "getCvmInfo invocation" });
      const parsed = exactRecord(invocation, ["domain", "cvmId"],
        "getCvmInfo invocation");
      const domain = exactDomain(parsed.domain, "CVM info domain");
      const cvmId = exactCanonicalIdentifier(parsed.cvmId, "CVM info id");
      return invokeSdkAction(state, {
        method: "getCvmInfo",
        domain,
        actionArguments: [{ id: cvmId }],
      });
    },
    async getCvmAttestation(invocation) {
      assertBoundedJsonGraph(invocation, { label: "getCvmAttestation invocation" });
      const parsed = exactRecord(invocation, ["domain", "cvmId"],
        "getCvmAttestation invocation");
      const domain = exactDomain(parsed.domain, "CVM attestation domain");
      const cvmId = exactCanonicalIdentifier(parsed.cvmId, "CVM attestation id");
      return invokeSdkAction(state, {
        method: "getCvmAttestation",
        domain,
        actionArguments: [{ id: cvmId }],
      });
    },
  };
  const adapter = Object.freeze(historicalContinuityReadOnly
    ? Object.fromEntries(HISTORICAL_CONTINUITY_READ_ONLY_METHODS.map(
      (method) => [method, adapterMethods[method]],
    ))
    : adapterMethods);
  const state = {
    adapter,
    actions,
    compatibility,
    staging,
    target,
    identity: adapterIdentity,
    identity_sha256: adapterIdentityDigest(adapterIdentity),
    credential,
    transport,
    workspace_verified: false,
    billing_verified: false,
    authenticated_subject: null,
    prepared_by_domain: new Map(),
    in_flight: false,
    next_call_sequence: 1,
    historical_continuity_read_only: historicalContinuityReadOnly,
    now: runtime.now,
  };
  assertAdapterAuthorityFresh(state);
  PRODUCTION_ADAPTERS.set(adapter, state);
  return adapter;
}

export async function createPinnedPhalaProductionSdkAdapter(value) {
  return createPinnedPhalaSdkAdapter(value, {
    historicalContinuityReadOnly: false,
  });
}

/**
 * Reopens an expired launch target only as historical identity authority for
 * current, authenticated reconciliation. The returned object exposes exactly
 * four GET-backed methods and cannot reserve, provision, commit, update, or
 * restart a CVM. Historical timestamps are not renewed by this constructor.
 */
export async function createPinnedPhalaHistoricalContinuityReadOnlySdkObserver(
  value,
) {
  const observer = await createPinnedPhalaSdkAdapter(value, {
    historicalContinuityReadOnly: true,
  });
  return assertPinnedPhalaHistoricalContinuityReadOnlySdkObserver(observer);
}

export function assertProductionExecutionRemainsSealed() {
  throw new Error(
    "legacy sealed adapter entrypoint is retired; use the exact production executor runtime",
  );
}

export function assertProductionExecutionPolicyAvailable() {
  if (PHALA_PRODUCTION_EXECUTION_POLICY.availability !== true
    || PHALA_PRODUCTION_EXECUTION_POLICY.reason_code !== null
    || PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.length !== 0
    || PHALA_PRODUCTION_EXECUTION_POLICY.blocker_codes.length !== 0
    || PHALA_PRODUCTION_EXECUTION_POLICY.caller_supplied_callbacks_accepted !== false
    || PHALA_PRODUCTION_EXECUTION_POLICY.caller_supplied_clients_accepted !== false
    || PHALA_PRODUCTION_EXECUTION_POLICY.manual_cli_or_sdk_bypass_authorized !== false) {
    throw new Error("canonical production executor policy is unavailable or widened");
  }
  return PHALA_PRODUCTION_EXECUTION_POLICY;
}

/**
 * This is intentionally the only production-adapter constructor. It cannot
 * return a client while canonical policy is sealed, and it performs the seal
 * check before reading credentials or dynamically importing @phala/cloud.
 */
export async function createSealedPhalaProductionAdapter() {
  assertProductionExecutionRemainsSealed();
}
