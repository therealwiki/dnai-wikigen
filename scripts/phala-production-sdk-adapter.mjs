import { createHash, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  PHALA_DSTACK_APP_COMPOSE_HASH_INPUT_KEYS,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_POLICY,
} from "./phala-production-execution-policy.mjs";
import {
  PHALA_EXECUTION_ORDER,
  assertImmediateSignedEnvironmentKeyRefetch,
  assertRecoveredSignedEnvironmentKey,
  dstackCanonicalComposeHash,
  normalizeSignedEnvironmentKeyResponse,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_CLI_PACKAGE_VERSION,
  PHALA_CLOUD_SDK_VERSION,
  PHALA_DSTACK_SDK_VERSION,
  normalizePhalaCompatibilityReceipt,
  normalizePhalaProductionTargetAuthority,
  normalizePhalaSdkWireTransformStagingReceipt,
  phalaCompatibilityReceiptDigest,
  phalaProductionTargetAuthorityDigest,
  phalaSdkWireTransformStagingReceiptDigest,
} from "./phala-production-target-authority.mjs";

export const PHALA_PINNED_PACKAGE_IDENTITY_SCHEMA =
  "dnai.phala-pinned-package-identity.v1";
export const PHALA_PINNED_CLOUD_NPM_DIST_INTEGRITY =
  "sha512-eQXJxbBlJ8xA4e+MmB3AZd9jgdbO3tFh+qu7KL6CS5Ta64LNKlrV3vdke3oUvB22xbc/qqKQ6dIkJx5pTdY7gA==";
export const PHALA_PINNED_CLOUD_NPM_DIST_SHASUM =
  "ed23f01ef54220b996092301283b5a2b7790f4cf";
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
  "provisionCvm",
  "commitCvmProvision",
  "updateCvmEnvs",
  "restartCvm",
]);
export const PHALA_PRODUCTION_READ_ONLY_METHODS = Object.freeze([
  "getCurrentUser",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
  "nextAppIds",
  "getAppEnvEncryptPubKey",
  "getCvmInfo",
  "getCvmAttestation",
]);

const MAX_MANIFEST_BYTES = 65_536;
const MAX_PATH_BYTES = 32_768;
const MAX_CREDENTIAL_BYTES = 65_536;
const MAX_HTTP_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_HTTP_REQUEST_BYTES = 4 * 1024 * 1024;
const MAX_JSON_NODES = 100_000;
const MAX_JSON_DEPTH = 64;
const PINNED_IDENTITY = new WeakSet();
const PHALA_ORIGIN = "https://cloud-api.phala.network/api/v1";
const PHALA_HOST = "cloud-api.phala.network";
const PRODUCTION_ADAPTERS = new WeakMap();
const AUTHENTICATED_OBSERVATIONS = new WeakMap();
const REQUIRED_CLOUD_ACTION_EXPORTS = Object.freeze([
  "getCurrentUser",
  "getCvmCreateResources",
  "getOsImages",
  "getKmsList",
  "getKmsInfo",
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

function readStableRegularFile(filePath, label, maxBytes = MAX_MANIFEST_BYTES) {
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size < 2 || before.size > maxBytes) {
      throw new Error(`${label} is not a bounded regular file`);
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || bytes.length !== before.size) {
      throw new Error(`${label} changed during its bounded read`);
    }
    return { bytes, sha256: sha256(bytes) };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseExactPackage(directory, expectedName, expectedVersion, label) {
  const manifestPath = path.join(directory, "package.json");
  const file = readStableRegularFile(manifestPath, `${label} package manifest`);
  let manifest;
  try {
    manifest = JSON.parse(file.bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} package manifest is not valid JSON`);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || manifest.name !== expectedName || manifest.version !== expectedVersion) {
    throw new Error(`${label} package identity is not exact`);
  }
  return { directory, manifest, manifestPath, manifestSha256: file.sha256 };
}

function resolveExecutable(command) {
  const pathValue = process.env.PATH ?? "";
  if (Buffer.byteLength(pathValue, "utf8") > MAX_PATH_BYTES
    || pathValue.split(path.delimiter).length > 128) {
    throw new Error("PATH is outside the bounded package-resolution policy");
  }
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory || !path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, command);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return fs.realpathSync(candidate);
    } catch {
      // Continue across the bounded PATH without executing a candidate.
    }
  }
  throw new Error("the pinned Phala package executable is unavailable");
}

function exactModuleFile(filePath, label) {
  const original = fs.lstatSync(filePath);
  if (original.isSymbolicLink() || !original.isFile()) {
    throw new Error(`${label} must be a non-symlink regular file`);
  }
  const real = fs.realpathSync(filePath);
  if (real !== path.resolve(filePath)) {
    throw new Error(`${label} path must not traverse a module-file symlink`);
  }
  const file = readStableRegularFile(real, label, 8 * 1024 * 1024);
  return Object.freeze({ path: real, sha256: file.sha256 });
}

export function resolvePinnedPhalaPackageIdentity() {
  const executable = resolveExecutable("phala");
  let directory = path.dirname(executable);
  for (let depth = 0; depth < 7; depth += 1) {
    try {
      const cli = parseExactPackage(
        directory,
        "phala",
        PHALA_CLI_PACKAGE_VERSION,
        "Phala CLI",
      );
      if (path.resolve(directory, cli.manifest.bin?.phala ?? "") !== executable) {
        throw new Error("Phala CLI manifest does not bind the resolved executable");
      }
      const cloud = parseExactPackage(
        path.join(directory, "node_modules", "@phala", "cloud"),
        "@phala/cloud",
        PHALA_CLOUD_SDK_VERSION,
        "Phala Cloud SDK",
      );
      const dstack = parseExactPackage(
        path.join(directory, "node_modules", "@phala", "dstack-sdk"),
        "@phala/dstack-sdk",
        PHALA_DSTACK_SDK_VERSION,
        "Phala dstack SDK",
      );
      const cloudModule = exactModuleFile(
        path.join(cloud.directory, "dist", "index.mjs"),
        "Phala Cloud SDK module",
      );
      const dstackVerifyModule = exactModuleFile(
        path.join(dstack.directory, "dist", "index.mjs"),
        "dstack verifier module",
      );
      const dstackComposeHashModule = exactModuleFile(
        path.join(dstack.directory, "dist", "get-compose-hash.mjs"),
        "dstack compose-hash module",
      );
      const dstackEncryptionModule = exactModuleFile(
        path.join(dstack.directory, "dist", "encrypt-env-vars.mjs"),
        "dstack environment-encryption module",
      );
      const identity = Object.freeze({
        schema: PHALA_PINNED_PACKAGE_IDENTITY_SCHEMA,
        source: "installed_package_manifests_and_module_files_no_executable_probe",
        cli: Object.freeze({
          version: PHALA_CLI_PACKAGE_VERSION,
          manifest_sha256: cli.manifestSha256,
        }),
        cloud: Object.freeze({
          version: PHALA_CLOUD_SDK_VERSION,
          manifest_sha256: cloud.manifestSha256,
          npm_dist_integrity_sha512: PHALA_PINNED_CLOUD_NPM_DIST_INTEGRITY,
          npm_dist_shasum: PHALA_PINNED_CLOUD_NPM_DIST_SHASUM,
          module_path: cloudModule.path,
          module_sha256: cloudModule.sha256,
        }),
        dstack: Object.freeze({
          version: PHALA_DSTACK_SDK_VERSION,
          manifest_sha256: dstack.manifestSha256,
          verify_module_path: dstackVerifyModule.path,
          verify_module_sha256: dstackVerifyModule.sha256,
          compose_hash_module_path: dstackComposeHashModule.path,
          compose_hash_module_sha256: dstackComposeHashModule.sha256,
          encryption_module_path: dstackEncryptionModule.path,
          encryption_module_sha256: dstackEncryptionModule.sha256,
        }),
      });
      PINNED_IDENTITY.add(identity);
      return identity;
    } catch {
      // Only an ancestor satisfying the whole CLI -> cloud -> dstack graph is accepted.
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error("exact pinned Phala CLI/cloud/dstack package graph is unavailable");
}

function requirePinnedIdentity(identity) {
  if (!identity || !PINNED_IDENTITY.has(identity)) {
    throw new Error("a locally resolved pinned package identity is required");
  }
}

export function projectPinnedSdkCompatibilityIdentity(identity) {
  requirePinnedIdentity(identity);
  return Object.freeze({
    phala_cli_version: PHALA_CLI_PACKAGE_VERSION,
    phala_cli_manifest_sha256: identity.cli.manifest_sha256,
    phala_cloud_version: PHALA_CLOUD_SDK_VERSION,
    phala_cloud_manifest_sha256: identity.cloud.manifest_sha256,
    phala_cloud_npm_dist_integrity_sha512:
      identity.cloud.npm_dist_integrity_sha512,
    phala_cloud_module_sha256: identity.cloud.module_sha256,
    dstack_sdk_version: PHALA_DSTACK_SDK_VERSION,
    dstack_sdk_manifest_sha256: identity.dstack.manifest_sha256,
    dstack_verify_module_sha256: identity.dstack.verify_module_sha256,
    dstack_compose_hash_module_sha256:
      identity.dstack.compose_hash_module_sha256,
    dstack_encryption_module_sha256:
      identity.dstack.encryption_module_sha256,
  });
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
    || !["2026-01-21", "2026-05-22"].includes(value.version)) {
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
    "kms_id",
    "key_provider_mode",
    "skip_gateway",
    "env_keys",
    "nonce",
    "app_id",
  ], "pre-transform provision request");
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
  const wireCompose = structuredClone(compose);
  delete wireCompose.tproxy_enabled;
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
  requirePinnedIdentity(identity);
  const [verifier, compose, encryption] = await Promise.all([
    import(pathToFileURL(identity.dstack.verify_module_path).href),
    import(pathToFileURL(identity.dstack.compose_hash_module_path).href),
    import(pathToFileURL(identity.dstack.encryption_module_path).href),
  ]);
  if (typeof verifier.verifyEnvEncryptPublicKeyLegacy !== "function"
    || typeof verifier.verifyEnvEncryptPublicKey !== "function"
    || typeof compose.getComposeHash !== "function"
    || typeof encryption.encryptEnvVars !== "function") {
    throw new Error("pinned dstack modules do not expose the exact required primitives");
  }
  return Object.freeze({
    verifyEnvEncryptPublicKeyLegacy: verifier.verifyEnvEncryptPublicKeyLegacy,
    verifyEnvEncryptPublicKey: verifier.verifyEnvEncryptPublicKey,
    getComposeHash: compose.getComposeHash,
    encryptEnvVars: encryption.encryptEnvVars,
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
  const now = Date.now();
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
  requirePinnedIdentity(identity);
  const module = await import(pathToFileURL(identity.cloud.module_path).href);
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

function performPinnedHttpsRequest({
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
      if (wallTimer) clearTimeout(wallTimer);
      reject(new Error(message));
    };
    const request = https.request({
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
        if (wallTimer) clearTimeout(wallTimer);
        resolve(Object.freeze({
          response: parsed,
          capture: Object.freeze({
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
    wallTimer = setTimeout(() => {
      request.destroy();
      fail("pinned Phala HTTPS request exceeded its wall-clock timeout");
    }, PHALA_PINNED_CLIENT_TRANSPORT.timeout_ms);
    wallTimer.unref?.();
    if (bodyBytes) request.write(bodyBytes);
    request.end();
  });
}

function createPinnedSdkActionClient({ apiKey, apiVersion }) {
  let invocationOpen = false;
  let capture = null;

  function projectJsonWireBody(value) {
    if (value === undefined) return undefined;
    if (!isRecord(value)) {
      throw new Error("pinned SDK JSON request body must be an object");
    }
    function project(entry, inArray = false) {
      if (entry === undefined) {
        if (inArray) throw new Error("pinned SDK JSON request arrays cannot contain undefined");
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

  async function perform(httpMethod, requestPath, body) {
    if (!invocationOpen || capture !== null) {
      throw new Error("pinned SDK action emitted more than one HTTP request");
    }
    const result = await performPinnedHttpsRequest({
      apiKey,
      apiVersion,
      httpMethod,
      requestPath,
      body,
    });
    capture = result.capture;
    return result.response;
  }

  const client = Object.freeze({
    config: Object.freeze({ version: apiVersion }),
    async get(requestPath, options) {
      return perform("GET", appendExactQuery(requestPath, options));
    },
    async post(requestPath, body, options) {
      if (options !== undefined) {
        throw new Error("pinned SDK POST options are not accepted");
      }
      return perform("POST", requestPath, projectJsonWireBody(body));
    },
    async patch(requestPath, body, options) {
      if (options !== undefined) {
        throw new Error("pinned SDK PATCH options are not accepted");
      }
      return perform("PATCH", requestPath, projectJsonWireBody(body));
    },
  });

  return Object.freeze({
    client,
    begin() {
      if (invocationOpen) throw new Error("pinned SDK adapter forbids concurrent calls");
      invocationOpen = true;
      capture = null;
    },
    finish() {
      if (!invocationOpen || capture === null) {
        throw new Error("pinned SDK action did not emit exactly one HTTP request");
      }
      const result = capture;
      invocationOpen = false;
      capture = null;
      return result;
    },
    abort() {
      invocationOpen = false;
      capture = null;
    },
  });
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
    || request.kms_id !== target.kms.id
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
    "kms_id",
    "env_keys",
    "encrypted_env",
  ], "commitCvmProvision request");
  const appId = exactAppId(request.app_id, "commit app id");
  if (typeof request.compose_hash !== "string"
    || !/^(?!0{64}$)[0-9a-f]{64}$/.test(request.compose_hash)
    || request.kms_id !== target.kms.id) {
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
      kms_id: target.kms.id,
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
    api_version: state.target.api.version,
    workspace_id: state.target.workspace.workspace_id,
    adapter_identity_sha256: state.identity_sha256,
    target_authority_sha256: state.identity.production_target_authority_sha256,
    sdk_module_sha256: state.identity.sdk_module_sha256,
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
  const action = state.actions[method];
  if (typeof action !== "function") throw new Error("pinned SDK action is unavailable");
  state.in_flight = true;
  state.transport.begin();
  try {
    if (method === "getCurrentUser") state.workspace_verified = false;
    const response = await action(state.transport.client, ...actionArguments);
    assertBoundedJsonGraph(response, { label: `${method} SDK response` });
    const capture = state.transport.finish();
    if (expectedPostTransformBodySha256 !== undefined
      && capture.captured_post_transform_body_sha256
        !== expectedPostTransformBodySha256) {
      throw new Error("captured SDK post-transform body differs from exact local projection");
    }
    if (beforeObservation) beforeObservation(response);
    assertAdapterAuthorityFresh(state);
    const observedAt = canonicalInternalTimestamp();
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

/**
 * Creates the only mutation-capable Phala adapter. The constructor has no
 * credential, client, transport, callback, origin, version, or clock inputs.
 * Its credential source is the stable-read canonical current CLI profile and
 * its SDK action module is the exact locally pinned file graph.
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
    throw new Error("installed pinned package identity differs from reviewed target authority");
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
  const transport = createPinnedSdkActionClient({
    apiKey: credential.api_key,
    apiVersion: target.api.version,
  });
  const adapterIdentity = Object.freeze({
    schema: PHALA_PRODUCTION_SDK_ADAPTER_IDENTITY_SCHEMA,
    truth_status:
      "exact_installed_package_graph_and_reviewed_target_bound_no_sdk_environment_fallback",
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
    sdk_module_sha256: identity.cloud.module_sha256,
    sdk_manifest_sha256: identity.cloud.manifest_sha256,
    sdk_npm_dist_integrity_sha512: identity.cloud.npm_dist_integrity_sha512,
  });
  const adapterMethods = {
    async getCurrentUser() {
      return invokeSdkAction(state, {
        method: "getCurrentUser",
        beforeObservation(response) {
          validateAuthenticatedAccount(response, state);
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
    async getKmsInfo() {
      return invokeSdkAction(state, {
        method: "getKmsInfo",
        actionArguments: [{ kms_id: target.kms.id }],
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
      return invokeSdkAction(state, {
        method: "provisionCvm",
        domain: normalized.domain,
        actionArguments: [normalized.request],
        expectedPostTransformBodySha256:
          phalaSdkJsonBodySemanticDigest(normalized.wireBody),
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
      return invokeSdkAction(state, {
        method: "getAppEnvEncryptPubKey",
        domain,
        actionArguments: [{ kms: target.kms.id, app_id: appId }],
      });
    },
    async commitCvmProvision(invocation) {
      const normalized = normalizeCommitInvocation(invocation, target);
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
    in_flight: false,
    next_call_sequence: 1,
    historical_continuity_read_only: historicalContinuityReadOnly,
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
