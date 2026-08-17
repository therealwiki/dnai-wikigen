import { createHash } from "node:crypto";

import {
  CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS,
  CVM_MAIN_LATE_INPUT_FAIL_CLOSED_DEFAULTS,
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_CVM_RESOURCE_TARGETS,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  parseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";

export const PHALA_COMPATIBILITY_PROBE_PLAN_SCHEMA =
  "dnai.phala-compatibility-probe-plan.v1";
export const PHALA_COMPATIBILITY_RECEIPT_SCHEMA =
  "dnai.phala-compatibility-receipt.v1";
export const PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA =
  "dnai.phala-production-target-authority.v2";
export const PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA =
  "dnai.phala-sdk-wire-transform-staging-receipt.v2";
export const PHALA_PRODUCTION_TARGET_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-production-target-authority/v2\0";
export const PHALA_COMPATIBILITY_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-compatibility-receipt/v1\0";
export const PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_DOMAIN =
  "dnai-wikigen/phala-sdk-wire-transform-staging-receipt/v2\0";
export const PHALA_CLOUD_SDK_VERSION = "0.2.10";
export const PHALA_DSTACK_SDK_VERSION = "0.5.8";
export const PHALA_CLI_PACKAGE_VERSION = "1.1.19";
export const PHALA_API_CANDIDATE_VERSIONS = Object.freeze([
  "2026-01-21",
  "2026-05-22",
]);
export const PHALA_READ_ONLY_COMPATIBILITY_CALLS = Object.freeze([
  "getCurrentUser",
  "getCvmCreateResources",
  "getKmsList",
  "getKmsInfo",
  "getOsImages",
]);

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const COMPRESSED_K256 = /^0x0[23][0-9a-f]{64}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/;
const INSTANCE_TYPE = /^[a-z][a-z0-9.-]{1,63}$/;
const MAX_RECEIPT_LIFETIME_MS = 60 * 60 * 1_000;
export const MAX_PHALA_PRODUCTION_TARGET_LIFETIME_MS = 10 * 60 * 1_000;
export const PHALA_TARGET_FRESHNESS_CHECKPOINTS = Object.freeze([
  "before_prediction",
  "before_each_prepare",
  "before_each_provision",
  "before_each_commit",
]);
const FORBIDDEN_SECRET_KEY = /(?:api[_-]?key|secret|password|private[_-]?key|bearer|credential|token|encrypted[_-]?env|ciphertext)/i;
const FORBIDDEN_SECRET_VALUE = /(?:phak_[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;

export const PHALA_COLLABORATION_LAUNCH_GATE_POLICY = Object.freeze({
  environment_key: "TINKER_COLLABORATION_ENABLED",
  bootstrap_default: "false",
  runtime_authority:
    "current_final_release_authority_v3_requested_features_collaboration",
  operator_mutable: false,
});

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain exactly the reviewed fields`);
  }
  return value;
}

export function assertPhalaProductionTargetCollaborationLaunchGatePolicy() {
  const key = PHALA_COLLABORATION_LAUNCH_GATE_POLICY.environment_key;
  const mainPolicy = CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm;
  if (
    CVM_MAIN_LATE_INPUT_FAIL_CLOSED_DEFAULTS[key]
      !== PHALA_COLLABORATION_LAUNCH_GATE_POLICY.bootstrap_default
    || !CVM_MAIN_ACTIVE_SERVICE_LATE_INPUT_KEYS.includes(key)
    || !mainPolicy.public_environment_key_classification
      .post_measurement_deferred_keys.includes(key)
    || !mainPolicy.exact_allowed_environment_keys.includes(key)
    || mainPolicy.public_environment_key_classification
      .descriptor_static_keys.includes(key)
    || mainPolicy.public_environment_key_classification
      .descriptor_defaulted_keys.includes(key)
  ) {
    throw new Error(
      "production target Collaboration gate is not the exact fail-closed launch-intent policy",
    );
  }
  return PHALA_COLLABORATION_LAUNCH_GATE_POLICY;
}

function nonempty(value, label, max = 256) {
  if (typeof value !== "string" || value.length < 1 || value.length > max
    || /[\u0000-\u001f\u007f]/.test(value)) {
    throw new Error(`${label} must be a bounded nonempty string`);
  }
  return value;
}

function exactIdentifier(value, label) {
  if (typeof value !== "string" || !SAFE_IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a canonical identifier`);
  }
  return value;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactBareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function safePositiveInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new Error(`${label} must be a bounded positive integer`);
  }
  return value;
}

function canonicalTimestamp(value, label) {
  const parsedMs = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsedMs)
    || new Date(parsedMs).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactHttpsUrl(value, label, { originOnly = false } = {}) {
  const parsed = parseCanonicalPublicHttpsUrl(value, {
    label,
    requirePath: originOnly,
  });
  if (originOnly && parsed.pathname !== "/api/v1") {
    throw new Error(`${label} must end at the reviewed /api/v1 root`);
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

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(value)), "utf8"))
    .digest("hex")}`;
}

function assertSecretFree(value, label = "artifact", path = []) {
  if (typeof value === "string") {
    if (FORBIDDEN_SECRET_VALUE.test(value)) {
      throw new Error(`${label} contains a forbidden secret-shaped value`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertSecretFree(entry, label, [...path, index]));
    return;
  }
  if (!isRecord(value)) return;
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_SECRET_KEY.test(key)) {
      throw new Error(`${label} contains a forbidden secret-bearing field`);
    }
    assertSecretFree(entry, label, [...path, key]);
  }
}

function normalizeOsEntry(value, label) {
  const entry = exactRecord(value, [
    "name",
    "slug",
    "version",
    "os_image_hash",
    "is_dev",
    "requires_gpu",
  ], label);
  const normalized = {
    name: nonempty(entry.name, `${label}.name`, 128),
    slug: nonempty(entry.slug, `${label}.slug`, 128),
    version: nonempty(entry.version, `${label}.version`, 64),
    os_image_hash: exactBareSha256(entry.os_image_hash, `${label}.os_image_hash`),
    is_dev: entry.is_dev,
    requires_gpu: entry.requires_gpu,
  };
  if (typeof normalized.is_dev !== "boolean"
    || typeof normalized.requires_gpu !== "boolean") {
    throw new Error(`${label} boolean posture is invalid`);
  }
  return normalized;
}

function normalizeInstanceCatalog(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 64) {
    throw new Error("resource instance catalog must be a bounded nonempty array");
  }
  const normalized = value.map((raw, index) => {
    const item = exactRecord(raw, [
      "name",
      "default_disk_size_gb",
      "maximum_disk_size_gb",
      "requires_gpu",
    ], `instance catalog[${index}]`);
    if (typeof item.name !== "string" || !INSTANCE_TYPE.test(item.name)) {
      throw new Error(`instance catalog[${index}].name is invalid`);
    }
    const defaultDisk = safePositiveInteger(
      item.default_disk_size_gb,
      `instance catalog[${index}].default_disk_size_gb`,
      16_384,
    );
    const maximumDisk = safePositiveInteger(
      item.maximum_disk_size_gb,
      `instance catalog[${index}].maximum_disk_size_gb`,
      16_384,
    );
    if (maximumDisk < defaultDisk || typeof item.requires_gpu !== "boolean") {
      throw new Error(`instance catalog[${index}] disk or GPU posture is invalid`);
    }
    return {
      name: item.name,
      default_disk_size_gb: defaultDisk,
      maximum_disk_size_gb: maximumDisk,
      requires_gpu: item.requires_gpu,
    };
  });
  if (new Set(normalized.map(({ name }) => name)).size !== normalized.length) {
    throw new Error("resource instance catalog contains duplicate names");
  }
  return normalized.sort((left, right) => left.name.localeCompare(right.name));
}

function normalizeProbeVersion(value, index) {
  const entry = exactRecord(value, [
    "version",
    "authenticated",
    "strict_schema_valid",
    "response_origin_valid",
    "read_only_calls_complete",
  ], `probed_versions[${index}]`);
  if (entry.version !== PHALA_API_CANDIDATE_VERSIONS[index]) {
    throw new Error("compatibility probe versions must use the exact candidate order");
  }
  for (const field of [
    "authenticated",
    "strict_schema_valid",
    "response_origin_valid",
    "read_only_calls_complete",
  ]) {
    if (typeof entry[field] !== "boolean") {
      throw new Error(`probed_versions[${index}].${field} must be boolean`);
    }
  }
  return { ...entry };
}

export function createPhalaCompatibilityProbePlan() {
  const plan = {
    schema: PHALA_COMPATIBILITY_PROBE_PLAN_SCHEMA,
    truth_status:
      "read_only_plan_no_authentication_result_catalog_result_or_phala_mutation",
    api_origin: PHALA_CONTROL_PLANE_AUTHORITY.api_origin,
    candidate_api_versions: [...PHALA_API_CANDIDATE_VERSIONS],
    request_policy: {
      timeout_ms: 20_000,
      retry: 0,
      redirect: "error",
      authentication_material_in_output: false,
      debug_logging_allowed: false,
    },
    read_only_calls_per_version: [...PHALA_READ_ONLY_COMPATIBILITY_CALLS],
    mutation_calls: [],
    automatic_version_selection: false,
    reviewer_selection_required: true,
  };
  assertSecretFree(plan, "compatibility probe plan");
  return plan;
}

export function normalizePhalaCompatibilityReceipt(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "checked_at",
    "expires_at",
    "api_origin",
    "probed_versions",
    "selected_api_version",
    "read_only_calls",
    "workspace",
    "sdk_identity",
    "kms",
    "os_image",
    "resource_catalog",
    "quota",
    "staging_provision_performed",
    "mutation_calls",
  ], "Phala compatibility receipt");
  if (parsed.schema !== PHALA_COMPATIBILITY_RECEIPT_SCHEMA
    || parsed.truth_status
      !== "authenticated_read_only_compatibility_observation_not_launch_authority") {
    throw new Error("Phala compatibility receipt schema or truth status is invalid");
  }
  const checkedAt = canonicalTimestamp(parsed.checked_at, "checked_at");
  const expiresAt = canonicalTimestamp(parsed.expires_at, "expires_at");
  const lifetime = Date.parse(expiresAt) - Date.parse(checkedAt);
  if (lifetime < 1 || lifetime > MAX_RECEIPT_LIFETIME_MS) {
    throw new Error("compatibility receipt lifetime is outside the one-hour bound");
  }
  const apiOrigin = exactHttpsUrl(parsed.api_origin, "api_origin", { originOnly: true });
  if (apiOrigin !== PHALA_CONTROL_PLANE_AUTHORITY.api_origin) {
    throw new Error("compatibility receipt API origin differs from launch authority");
  }
  if (!Array.isArray(parsed.probed_versions)
    || parsed.probed_versions.length !== PHALA_API_CANDIDATE_VERSIONS.length) {
    throw new Error("compatibility receipt must contain both exact candidate versions");
  }
  const probedVersions = parsed.probed_versions.map(normalizeProbeVersion);
  if (!PHALA_API_CANDIDATE_VERSIONS.includes(parsed.selected_api_version)) {
    throw new Error("selected API version is not a reviewed candidate");
  }
  const selected = probedVersions.find(({ version }) => (
    version === parsed.selected_api_version
  ));
  if (!selected || [
    "authenticated",
    "strict_schema_valid",
    "response_origin_valid",
    "read_only_calls_complete",
  ].some((field) => selected[field] !== true)) {
    throw new Error("selected API version did not pass every read-only compatibility check");
  }
  if (parsed.selected_api_version !== PHALA_CONTROL_PLANE_AUTHORITY.api_version) {
    throw new Error("selected API version differs from the reviewed launch authority");
  }
  if (JSON.stringify(parsed.read_only_calls)
      !== JSON.stringify(PHALA_READ_ONLY_COMPATIBILITY_CALLS)
    || !Array.isArray(parsed.mutation_calls)
    || parsed.mutation_calls.length !== 0
    || parsed.staging_provision_performed !== false) {
    throw new Error("compatibility receipt must prove the exact read-only call boundary");
  }
  const workspace = exactRecord(parsed.workspace, [
    "workspace_id",
    "account_subject_sha256",
    "authenticated",
  ], "compatibility workspace");
  if (workspace.authenticated !== true) {
    throw new Error("compatibility workspace is not authenticated");
  }
  const sdk = exactRecord(parsed.sdk_identity, [
    "phala_cli_version",
    "phala_cli_manifest_sha256",
    "phala_cloud_version",
    "phala_cloud_manifest_sha256",
    "phala_cloud_npm_dist_integrity_sha512",
    "phala_cloud_module_sha256",
    "dstack_sdk_version",
    "dstack_sdk_manifest_sha256",
    "dstack_verify_module_sha256",
    "dstack_compose_hash_module_sha256",
    "dstack_encryption_module_sha256",
  ], "compatibility SDK identity");
  if (sdk.phala_cli_version !== PHALA_CLI_PACKAGE_VERSION
    || sdk.phala_cloud_version !== PHALA_CLOUD_SDK_VERSION
    || sdk.dstack_sdk_version !== PHALA_DSTACK_SDK_VERSION
    || sdk.phala_cloud_npm_dist_integrity_sha512
      !== PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.package
        .npm_dist_integrity_sha512) {
    throw new Error("compatibility SDK versions are not the exact pinned versions");
  }
  const kms = exactRecord(parsed.kms, [
    "id",
    "slug",
    "url",
    "version",
    "chain_id",
    "kms_contract_address",
    "gateway_app_id",
    "catalog_match_count",
  ], "compatibility KMS");
  if (kms.slug !== "phala" || kms.chain_id !== null
    || kms.kms_contract_address !== null || kms.catalog_match_count !== 1) {
    throw new Error("compatibility KMS is not the unique centralized Phala KMS");
  }
  if (kms.gateway_app_id !== null && (typeof kms.gateway_app_id !== "string"
      || !APP_ID.test(kms.gateway_app_id.replace(/^0x/, "")))) {
    throw new Error("compatibility KMS gateway app id is invalid");
  }
  const quota = exactRecord(parsed.quota, [
    "max_instances",
    "max_disk_gb",
    "catalog_reports_sufficient_capacity",
  ], "compatibility quota");
  if (typeof quota.catalog_reports_sufficient_capacity !== "boolean") {
    throw new Error("compatibility quota posture must be boolean");
  }
  const resourceCatalog = normalizeInstanceCatalog(parsed.resource_catalog);
  const normalized = {
    schema: PHALA_COMPATIBILITY_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_read_only_compatibility_observation_not_launch_authority",
    checked_at: checkedAt,
    expires_at: expiresAt,
    api_origin: apiOrigin,
    probed_versions: probedVersions,
    selected_api_version: parsed.selected_api_version,
    read_only_calls: [...PHALA_READ_ONLY_COMPATIBILITY_CALLS],
    workspace: {
      workspace_id: exactIdentifier(workspace.workspace_id, "workspace_id"),
      account_subject_sha256: exactSha256(
        workspace.account_subject_sha256,
        "account_subject_sha256",
      ),
      authenticated: true,
    },
    sdk_identity: {
      phala_cli_version: PHALA_CLI_PACKAGE_VERSION,
      phala_cli_manifest_sha256: exactSha256(
        sdk.phala_cli_manifest_sha256,
        "phala_cli_manifest_sha256",
      ),
      phala_cloud_version: PHALA_CLOUD_SDK_VERSION,
      phala_cloud_manifest_sha256: exactSha256(
        sdk.phala_cloud_manifest_sha256,
        "phala_cloud_manifest_sha256",
      ),
      phala_cloud_npm_dist_integrity_sha512:
        PHALA_CLOUD_SDK_WIRE_TRANSFORM_AUTHORITY.package
          .npm_dist_integrity_sha512,
      phala_cloud_module_sha256: exactSha256(
        sdk.phala_cloud_module_sha256,
        "phala_cloud_module_sha256",
      ),
      dstack_sdk_version: PHALA_DSTACK_SDK_VERSION,
      dstack_sdk_manifest_sha256: exactSha256(
        sdk.dstack_sdk_manifest_sha256,
        "dstack_sdk_manifest_sha256",
      ),
      dstack_verify_module_sha256: exactSha256(
        sdk.dstack_verify_module_sha256,
        "dstack_verify_module_sha256",
      ),
      dstack_compose_hash_module_sha256: exactSha256(
        sdk.dstack_compose_hash_module_sha256,
        "dstack_compose_hash_module_sha256",
      ),
      dstack_encryption_module_sha256: exactSha256(
        sdk.dstack_encryption_module_sha256,
        "dstack_encryption_module_sha256",
      ),
    },
    kms: {
      id: exactIdentifier(kms.id, "kms.id"),
      slug: "phala",
      url: exactHttpsUrl(kms.url, "kms.url"),
      version: nonempty(kms.version, "kms.version", 64),
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: kms.gateway_app_id,
      catalog_match_count: 1,
    },
    os_image: normalizeOsEntry(parsed.os_image, "compatibility OS image"),
    resource_catalog: resourceCatalog,
    quota: {
      max_instances: safePositiveInteger(quota.max_instances, "quota.max_instances", 10_000),
      max_disk_gb: safePositiveInteger(quota.max_disk_gb, "quota.max_disk_gb", 1_000_000),
      catalog_reports_sufficient_capacity: quota.catalog_reports_sufficient_capacity,
    },
    staging_provision_performed: false,
    mutation_calls: [],
  };
  assertSecretFree(normalized, "compatibility receipt");
  return normalized;
}

export function phalaCompatibilityReceiptDigest(value) {
  return domainDigest(
    PHALA_COMPATIBILITY_RECEIPT_DOMAIN,
    normalizePhalaCompatibilityReceipt(value),
  );
}

function normalizeResourceTargets(value, compatibility) {
  const record = exactRecord(value, CVM_LAUNCH_DOMAINS, "resource targets");
  const byType = new Map(compatibility.resource_catalog.map((entry) => [entry.name, entry]));
  let totalDisk = 0;
  const normalized = {};
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const entry = exactRecord(record[domain], [
      "authority_status",
      "instance_type",
      "disk_size",
      "placement",
    ], `resource target ${domain}`);
    const placement = exactRecord(entry.placement, [
      "selection_mode",
      "node_id",
      "region",
    ], `resource target ${domain}.placement`);
    const candidate = PHALA_CVM_RESOURCE_TARGETS[domain];
    if (entry.authority_status !== "reviewed_authenticated_catalog_and_quota_validated"
      || entry.instance_type !== candidate.instance_type
      || entry.disk_size !== candidate.disk_size
      || placement.selection_mode !== candidate.placement.selection_mode
      || placement.node_id !== null || placement.region !== null) {
      throw new Error(`resource target ${domain} differs from the reviewed candidate`);
    }
    const catalog = byType.get(entry.instance_type);
    if (!catalog || catalog.requires_gpu !== false
      || entry.disk_size < catalog.default_disk_size_gb
      || entry.disk_size > catalog.maximum_disk_size_gb) {
      throw new Error(`resource target ${domain} is not supported by the authenticated catalog`);
    }
    totalDisk += entry.disk_size;
    normalized[domain] = {
      authority_status: "reviewed_authenticated_catalog_and_quota_validated",
      instance_type: entry.instance_type,
      disk_size: entry.disk_size,
      placement: {
        selection_mode: "automatic_best_match",
        node_id: null,
        region: null,
      },
    };
  }
  if (compatibility.quota.max_instances < CVM_LAUNCH_DOMAINS.length
    || compatibility.quota.max_disk_gb < totalDisk
    || compatibility.quota.catalog_reports_sufficient_capacity !== true) {
    throw new Error("reviewed seven-CVM resource targets exceed authenticated quota");
  }
  return normalized;
}

function normalizeComposeProfiles(value) {
  const record = exactRecord(value, CVM_LAUNCH_DOMAINS, "AppCompose profiles");
  const normalized = {};
  for (const domain of CVM_LAUNCH_DOMAINS) {
    const profile = exactRecord(record[domain], [
      "name",
      "manifest_version",
      "runner",
      "kms_enabled",
      "gateway_enabled",
      "tproxy_enabled",
      "skip_gateway",
      "storage_fs",
      "secure_time",
      "public_logs",
      "public_sysinfo",
      "public_tcbinfo",
    ], `AppCompose profile ${domain}`);
    const candidate = CVM_LAUNCH_DESCRIPTOR_POLICY[domain].app_compose_candidate;
    if (profile.name !== candidate.name
      || profile.manifest_version !== 2 || profile.runner !== "docker-compose"
      || profile.kms_enabled !== true || typeof profile.gateway_enabled !== "boolean"
      || profile.gateway_enabled !== candidate.gateway_enabled
      || profile.tproxy_enabled !== candidate.tproxy_enabled
      || profile.skip_gateway !== !profile.gateway_enabled
      || profile.storage_fs !== "ext4" || profile.secure_time !== true
      || profile.public_logs !== false || profile.public_sysinfo !== false
      || profile.public_tcbinfo !== false) {
      throw new Error(`AppCompose profile ${domain} leaves a mutable or unsafe default`);
    }
    normalized[domain] = {
      name: exactIdentifier(profile.name, `AppCompose profile ${domain}.name`),
      manifest_version: 2,
      runner: "docker-compose",
      kms_enabled: true,
      gateway_enabled: profile.gateway_enabled,
      tproxy_enabled: false,
      skip_gateway: profile.skip_gateway,
      storage_fs: "ext4",
      secure_time: true,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
    };
  }
  if (new Set(Object.values(normalized).map(({ name }) => name)).size
      !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("AppCompose profile names must be pairwise distinct");
  }
  return normalized;
}

export function normalizePhalaSdkWireTransformStagingReceipt(value, {
  compatibilityReceipt,
} = {}) {
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "compatibility_receipt_sha256",
    "captured_at",
    "expires_at",
    "api_origin",
    "api_version",
    "workspace",
    "sdk_identity",
    "capture_method",
    "staging_account_isolated",
    "provision_call_count",
    "commit_calls",
    "cleanup_receipt_sha256",
    "domains",
  ], "Phala SDK wire-transform staging receipt");
  if (parsed.schema !== PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA
    || parsed.truth_status
      !== "authenticated_staging_wire_capture_not_production_cvm_commit_tdx_attestation_or_launch_authority") {
    throw new Error("Phala SDK wire-transform staging receipt identity is invalid");
  }
  if (parsed.compatibility_receipt_sha256
      !== phalaCompatibilityReceiptDigest(compatibility)) {
    throw new Error("staging wire-transform receipt does not bind compatibility");
  }
  const capturedAt = canonicalTimestamp(parsed.captured_at, "staging captured_at");
  const expiresAt = canonicalTimestamp(parsed.expires_at, "staging expires_at");
  if (Date.parse(capturedAt) < Date.parse(compatibility.checked_at)
    || Date.parse(capturedAt) > Date.parse(compatibility.expires_at)
    || Date.parse(expiresAt) <= Date.parse(capturedAt)
    || Date.parse(expiresAt) > Date.parse(compatibility.expires_at)) {
    throw new Error("staging wire-transform receipt is stale against compatibility");
  }
  if (parsed.api_origin !== compatibility.api_origin
    || parsed.api_version !== compatibility.selected_api_version) {
    throw new Error("staging wire-transform receipt API authority drifted");
  }
  const workspace = exactRecord(parsed.workspace, [
    "workspace_id",
    "account_subject_sha256",
  ], "staging workspace");
  if (workspace.workspace_id !== compatibility.workspace.workspace_id
    || workspace.account_subject_sha256
      !== compatibility.workspace.account_subject_sha256) {
    throw new Error("staging wire-transform receipt workspace drifted");
  }
  if (JSON.stringify(sortedObject(parsed.sdk_identity))
      !== JSON.stringify(sortedObject(compatibility.sdk_identity))) {
    throw new Error("staging wire-transform receipt SDK identity drifted");
  }
  if (parsed.capture_method
      !== "authenticated_transport_interceptor_after_sdk_transform_before_http_serialization"
    || parsed.staging_account_isolated !== true
    || parsed.provision_call_count !== CVM_LAUNCH_DOMAINS.length
    || !Array.isArray(parsed.commit_calls) || parsed.commit_calls.length !== 0) {
    throw new Error("staging receipt does not prove the bounded prepare-only capture boundary");
  }
  if (!Array.isArray(parsed.domains)
    || parsed.domains.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("staging receipt must contain all seven wire captures");
  }
  const domains = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(parsed.domains[index], [
      "domain",
      "pre_transform_request_sha256",
      "expected_post_transform_body_sha256",
      "captured_post_transform_body_sha256",
      "pre_transform_compose_hash",
      "expected_post_transform_compose_hash",
      "prepare_server_compose_hash",
      "prepare_response_sha256",
    ], `staging domains[${index}]`);
    if (entry.domain !== domain) {
      throw new Error("staging wire captures must use canonical seven-domain order");
    }
    const preRequest = exactSha256(
      entry.pre_transform_request_sha256,
      `staging domains[${index}].pre_transform_request_sha256`,
    );
    const expectedBody = exactSha256(
      entry.expected_post_transform_body_sha256,
      `staging domains[${index}].expected_post_transform_body_sha256`,
    );
    const capturedBody = exactSha256(
      entry.captured_post_transform_body_sha256,
      `staging domains[${index}].captured_post_transform_body_sha256`,
    );
    const preCompose = exactBareSha256(
      entry.pre_transform_compose_hash,
      `staging domains[${index}].pre_transform_compose_hash`,
    );
    const expectedCompose = exactBareSha256(
      entry.expected_post_transform_compose_hash,
      `staging domains[${index}].expected_post_transform_compose_hash`,
    );
    const serverCompose = exactBareSha256(
      entry.prepare_server_compose_hash,
      `staging domains[${index}].prepare_server_compose_hash`,
    );
    if (preRequest === expectedBody || preCompose === expectedCompose
      || capturedBody !== expectedBody || serverCompose !== expectedCompose) {
      throw new Error(
        `${domain} staging capture does not prove exact SDK transform and server hash semantics`,
      );
    }
    return {
      domain,
      pre_transform_request_sha256: preRequest,
      expected_post_transform_body_sha256: expectedBody,
      captured_post_transform_body_sha256: capturedBody,
      pre_transform_compose_hash: preCompose,
      expected_post_transform_compose_hash: expectedCompose,
      prepare_server_compose_hash: serverCompose,
      prepare_response_sha256: exactSha256(
        entry.prepare_response_sha256,
        `staging domains[${index}].prepare_response_sha256`,
      ),
    };
  });
  for (const field of [
    "pre_transform_request_sha256",
    "expected_post_transform_body_sha256",
    "pre_transform_compose_hash",
    "expected_post_transform_compose_hash",
    "prepare_response_sha256",
  ]) {
    if (new Set(domains.map((entry) => entry[field])).size !== domains.length) {
      throw new Error(`staging ${field} values must be pairwise distinct`);
    }
  }
  const normalized = {
    schema: PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_SCHEMA,
    truth_status:
      "authenticated_staging_wire_capture_not_production_cvm_commit_tdx_attestation_or_launch_authority",
    compatibility_receipt_sha256: parsed.compatibility_receipt_sha256,
    captured_at: capturedAt,
    expires_at: expiresAt,
    api_origin: compatibility.api_origin,
    api_version: compatibility.selected_api_version,
    workspace: {
      workspace_id: workspace.workspace_id,
      account_subject_sha256: workspace.account_subject_sha256,
    },
    sdk_identity: structuredClone(compatibility.sdk_identity),
    capture_method:
      "authenticated_transport_interceptor_after_sdk_transform_before_http_serialization",
    staging_account_isolated: true,
    provision_call_count: CVM_LAUNCH_DOMAINS.length,
    commit_calls: [],
    cleanup_receipt_sha256: exactSha256(
      parsed.cleanup_receipt_sha256,
      "staging cleanup_receipt_sha256",
    ),
    domains,
  };
  assertSecretFree(normalized, "SDK wire-transform staging receipt");
  return normalized;
}

export function phalaSdkWireTransformStagingReceiptDigest(value, options) {
  return domainDigest(
    PHALA_SDK_WIRE_TRANSFORM_STAGING_RECEIPT_DOMAIN,
    normalizePhalaSdkWireTransformStagingReceipt(value, options),
  );
}

export function normalizePhalaProductionTargetAuthority(value, {
  compatibilityReceipt,
  sdkWireTransformStagingReceipt,
} = {}) {
  assertPhalaProductionTargetCollaborationLaunchGatePolicy();
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "release_sha",
    "cvm_launch_intent_sha256",
    "review_envelope_sha256",
    "review_evidence_sha256",
    "compatibility_receipt_sha256",
    "staging_compose_hash_receipt_sha256",
    "api",
    "workspace",
    "sdk_identity",
    "kms",
    "os_image",
    "resource_targets",
    "app_compose_profiles",
    "reviewed_at",
    "expires_at",
  ], "Phala production target authority");
  if (parsed.schema !== PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA
    || parsed.truth_status
      !== "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt") {
    throw new Error("Phala production target schema or truth status is invalid");
  }
  if (typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || parsed.release_sha === "0".repeat(40)) {
    throw new Error("target authority release SHA is invalid");
  }
  if (parsed.compatibility_receipt_sha256
      !== phalaCompatibilityReceiptDigest(compatibility)) {
    throw new Error("target authority does not bind the exact compatibility receipt");
  }
  if (parsed.staging_compose_hash_receipt_sha256
      !== phalaSdkWireTransformStagingReceiptDigest(staging, {
        compatibilityReceipt: compatibility,
      })) {
    throw new Error("target authority does not bind exact SDK wire-transform staging proof");
  }
  const api = exactRecord(parsed.api, [
    "origin",
    "version",
    "timeout_ms",
    "retry",
    "redirect",
  ], "target API");
  if (api.origin !== compatibility.api_origin
    || api.origin !== PHALA_CONTROL_PLANE_AUTHORITY.api_origin
    || api.version !== compatibility.selected_api_version
    || api.version !== PHALA_CONTROL_PLANE_AUTHORITY.api_version
    || api.timeout_ms !== 20_000 || api.retry !== 0 || api.redirect !== "error") {
    throw new Error("target API does not enforce the reviewed no-drift client policy");
  }
  const workspace = exactRecord(parsed.workspace, [
    "workspace_id",
    "account_subject_sha256",
  ], "target workspace");
  if (workspace.workspace_id !== compatibility.workspace.workspace_id
    || workspace.account_subject_sha256
      !== compatibility.workspace.account_subject_sha256) {
    throw new Error("target workspace differs from the authenticated compatibility observation");
  }
  const sdk = exactRecord(parsed.sdk_identity, [
    "phala_cli_version",
    "phala_cli_manifest_sha256",
    "phala_cloud_version",
    "phala_cloud_manifest_sha256",
    "phala_cloud_npm_dist_integrity_sha512",
    "phala_cloud_module_sha256",
    "dstack_sdk_version",
    "dstack_sdk_manifest_sha256",
    "dstack_verify_module_sha256",
    "dstack_compose_hash_module_sha256",
    "dstack_encryption_module_sha256",
  ], "target SDK identity");
  if (JSON.stringify(sortedObject(sdk))
      !== JSON.stringify(sortedObject(compatibility.sdk_identity))) {
    throw new Error("target SDK identity differs from the compatibility receipt");
  }
  const kms = exactRecord(parsed.kms, [
    "id",
    "slug",
    "url",
    "version",
    "chain_id",
    "kms_contract_address",
    "gateway_app_id",
    "env_encrypt_signer_k256",
    "signer_provenance_sha256",
    "valid_from",
    "valid_until",
  ], "target KMS");
  for (const field of [
    "id", "slug", "url", "version", "chain_id", "kms_contract_address", "gateway_app_id",
  ]) {
    if (kms[field] !== compatibility.kms[field]) {
      throw new Error(`target KMS ${field} differs from the authenticated catalog`);
    }
  }
  if (typeof kms.env_encrypt_signer_k256 !== "string"
    || !COMPRESSED_K256.test(kms.env_encrypt_signer_k256)) {
    throw new Error("target KMS signer must be an independently pinned compressed k256 key");
  }
  const signerValidFrom = canonicalTimestamp(kms.valid_from, "target KMS valid_from");
  const signerValidUntil = canonicalTimestamp(kms.valid_until, "target KMS valid_until");
  if (Date.parse(signerValidUntil) <= Date.parse(signerValidFrom)) {
    throw new Error("target KMS signer validity interval is invalid");
  }
  const osImage = normalizeOsEntry(parsed.os_image, "target OS image");
  if (JSON.stringify(osImage) !== JSON.stringify(PHALA_OS_IMAGE_CATALOG_ENTRY)
    || JSON.stringify(osImage) !== JSON.stringify(compatibility.os_image)) {
    throw new Error("target OS image differs from reviewed and authenticated catalogs");
  }
  const reviewedAt = canonicalTimestamp(parsed.reviewed_at, "reviewed_at");
  const expiresAt = canonicalTimestamp(parsed.expires_at, "expires_at");
  const targetLifetime = Date.parse(expiresAt) - Date.parse(reviewedAt);
  if (Date.parse(reviewedAt) < Date.parse(compatibility.checked_at)
    || Date.parse(reviewedAt) > Date.parse(compatibility.expires_at)
    || Date.parse(reviewedAt) < Date.parse(staging.captured_at)
    || Date.parse(expiresAt) <= Date.parse(reviewedAt)
    || Date.parse(expiresAt) > Date.parse(compatibility.expires_at)
    || Date.parse(expiresAt) > Date.parse(staging.expires_at)
    || targetLifetime > MAX_PHALA_PRODUCTION_TARGET_LIFETIME_MS
    || Date.parse(expiresAt) > Date.parse(signerValidUntil)) {
    throw new Error(
      "target review interval is invalid, too long, stale against compatibility, or outlives the KMS signer pin",
    );
  }
  const normalized = {
    schema: PHALA_PRODUCTION_TARGET_AUTHORITY_SCHEMA,
    truth_status:
      "reviewed_target_authority_not_phala_deployment_attestation_or_execution_receipt",
    release_sha: parsed.release_sha,
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    review_envelope_sha256: exactSha256(
      parsed.review_envelope_sha256,
      "review_envelope_sha256",
    ),
    review_evidence_sha256: exactSha256(
      parsed.review_evidence_sha256,
      "review_evidence_sha256",
    ),
    compatibility_receipt_sha256: parsed.compatibility_receipt_sha256,
    staging_compose_hash_receipt_sha256: exactSha256(
      parsed.staging_compose_hash_receipt_sha256,
      "staging_compose_hash_receipt_sha256",
    ),
    api: {
      origin: api.origin,
      version: api.version,
      timeout_ms: 20_000,
      retry: 0,
      redirect: "error",
    },
    workspace: {
      workspace_id: workspace.workspace_id,
      account_subject_sha256: workspace.account_subject_sha256,
    },
    sdk_identity: { ...sdk },
    kms: {
      id: kms.id,
      slug: "phala",
      url: kms.url,
      version: kms.version,
      chain_id: null,
      kms_contract_address: null,
      gateway_app_id: kms.gateway_app_id,
      env_encrypt_signer_k256: kms.env_encrypt_signer_k256,
      signer_provenance_sha256: exactSha256(
        kms.signer_provenance_sha256,
        "signer_provenance_sha256",
      ),
      valid_from: signerValidFrom,
      valid_until: signerValidUntil,
    },
    os_image: osImage,
    resource_targets: normalizeResourceTargets(parsed.resource_targets, compatibility),
    app_compose_profiles: normalizeComposeProfiles(parsed.app_compose_profiles),
    reviewed_at: reviewedAt,
    expires_at: expiresAt,
  };
  assertSecretFree(normalized, "production target authority");
  return normalized;
}

export function phalaProductionTargetAuthorityDigest(value, options) {
  return domainDigest(
    PHALA_PRODUCTION_TARGET_AUTHORITY_DOMAIN,
    normalizePhalaProductionTargetAuthority(value, options),
  );
}

export function assertPhalaTargetFreshForCheckpoint({
  targetAuthority,
  compatibilityReceipt,
  sdkWireTransformStagingReceipt,
  checkpoint,
  now,
} = {}) {
  if (!PHALA_TARGET_FRESHNESS_CHECKPOINTS.includes(checkpoint)) {
    throw new Error("Phala target freshness checkpoint is not exact");
  }
  const compatibility = normalizePhalaCompatibilityReceipt(compatibilityReceipt);
  const target = normalizePhalaProductionTargetAuthority(targetAuthority, {
    compatibilityReceipt: compatibility,
    sdkWireTransformStagingReceipt,
  });
  const staging = normalizePhalaSdkWireTransformStagingReceipt(
    sdkWireTransformStagingReceipt,
    { compatibilityReceipt: compatibility },
  );
  const checkedAt = canonicalTimestamp(now, "freshness check time");
  const checkedTime = Date.parse(checkedAt);
  if (checkedTime < Date.parse(compatibility.checked_at)
    || checkedTime >= Date.parse(compatibility.expires_at)
    || checkedTime < Date.parse(staging.captured_at)
    || checkedTime >= Date.parse(staging.expires_at)
    || checkedTime < Date.parse(target.reviewed_at)
    || checkedTime >= Date.parse(target.expires_at)) {
    throw new Error(
      `fresh authenticated compatibility and target authority are required ${checkpoint}`,
    );
  }
  return Object.freeze({
    schema: "dnai.phala-target-freshness-check.v1",
    truth_status:
      "local_time_window_and_digest_revalidation_not_new_authentication_or_phala_observation",
    checkpoint,
    checked_at: checkedAt,
    compatibility_receipt_sha256: phalaCompatibilityReceiptDigest(compatibility),
    target_authority_sha256: phalaProductionTargetAuthorityDigest(target, {
      compatibilityReceipt: compatibility,
      sdkWireTransformStagingReceipt: staging,
    }),
    fresh: true,
    mutation_performed: false,
  });
}

export function canonicalPhalaCompatibilityReceiptText(value) {
  return canonicalText(normalizePhalaCompatibilityReceipt(value));
}

export function canonicalPhalaSdkWireTransformStagingReceiptText(value, options) {
  return canonicalText(normalizePhalaSdkWireTransformStagingReceipt(value, options));
}

export function canonicalPhalaProductionTargetAuthorityText(value, options) {
  return canonicalText(normalizePhalaProductionTargetAuthority(value, options));
}

export function assertSecretFreePhalaAuthorityArtifact(value, label) {
  assertSecretFree(value, label);
  return true;
}
