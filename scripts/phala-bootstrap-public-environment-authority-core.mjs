import { createHash } from "node:crypto";

import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
} from "./cvm-launch-intent-core.mjs";

export const PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA =
  "dnai.phala-bootstrap-public-environment-authority.v3";
export const PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH =
  "reviewed_non_live_public_bootstrap_values_not_stage_1_stage_2_secrets_platform_observation_tdx_measurement_or_runtime";

const BOOTSTRAP_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-bootstrap-public-environment-authority/v3\0";
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const CVM_IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const FORBIDDEN_SECRET_VALUE =
  /(?:phak_[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const PLACEHOLDER_VALUE =
  /^(?:change[-_ ]?me|replace[-_ ]?me|todo|tbd|example|placeholder|null|undefined|0x\.\.\.|\.\.\.)$/i;
const MAX_PUBLIC_VALUE_BYTES = 8_192;
const EXACT_RELEASE_PUBLIC_VALUES = Object.freeze({
  TINKER_CORS_ALLOWED_ORIGINS:
    "https://wikigen.me,https://wikigenme.pages.dev,https://www.wikigen.me",
  TINKER_WALLET_AUTH_DOMAIN: "www.wikigen.me",
  TINKER_WALLET_AUTH_URI: "https://www.wikigen.me",
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

function digest(value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(BOOTSTRAP_AUTHORITY_DOMAIN, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(value)), "utf8"))
    .digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactReleaseSha(value, label) {
  if (typeof value !== "string" || !SHA40.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase 40-hex release SHA`);
  }
  return value;
}

function canonicalTimestamp(value, label) {
  if (typeof value !== "string" || !ISO_SECOND.test(value)) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must round-trip as a canonical UTC second`);
  }
  return value;
}

function bootstrapKeys(domain) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const allowed = new Set(policy.exact_allowed_environment_keys);
  return policy.public_environment_key_classification.descriptor_static_keys
    .filter((key) => allowed.has(key));
}

function exactPublicValueMap(value, expectedKeys, label) {
  const parsed = exactRecord(value, expectedKeys, label);
  const normalized = {};
  for (const key of expectedKeys) {
    const item = parsed[key];
    if (typeof item !== "string" || item.length < 1
      || Buffer.byteLength(item, "utf8") > MAX_PUBLIC_VALUE_BYTES
      || /[\u0000\r\n]/.test(item)
      || PLACEHOLDER_VALUE.test(item.trim())) {
      throw new Error(`${label}.${key} must be a bounded non-placeholder single-line value`);
    }
    if (FORBIDDEN_SECRET_VALUE.test(item)) {
      throw new Error(`${label}.${key} contains a secret-shaped value`);
    }
    if (Object.hasOwn(EXACT_RELEASE_PUBLIC_VALUES, key)
      && item !== EXACT_RELEASE_PUBLIC_VALUES[key]) {
      const releaseBinding = key === "TINKER_CORS_ALLOWED_ORIGINS"
        ? "browser-origin value"
        : "wallet-auth value";
      throw new Error(`${label}.${key} must equal the final-release ${releaseBinding}`);
    }
    if (key.endsWith("_ADDRESS") && !ADDRESS.test(item)) {
      throw new Error(`${label}.${key} must be a nonzero canonical EVM address`);
    }
    if (key.endsWith("_APP_ID") && !SHA40.test(item)) {
      throw new Error(`${label}.${key} must be a nonzero bare lowercase app ID`);
    }
    if (key.endsWith("_CVM_ID") && !CVM_IDENTIFIER.test(item)) {
      throw new Error(`${label}.${key} must be a canonical bounded CVM ID`);
    }
    if ((key.endsWith("_COMPOSE_HASH") || key.endsWith("_OS_IMAGE_HASH"))
      && !BARE_SHA256.test(item)) {
      throw new Error(`${label}.${key} must be a nonzero bare lowercase hash`);
    }
    if (key.endsWith("_URL")) {
      let endpoint;
      try { endpoint = new URL(item); } catch {
        throw new Error(`${label}.${key} must be a canonical HTTPS endpoint`);
      }
      if (endpoint.protocol !== "https:" || endpoint.origin === "null"
        || endpoint.username || endpoint.password || endpoint.hash
        || endpoint.search || endpoint.href !== item) {
        throw new Error(`${label}.${key} must be a canonical HTTPS endpoint`);
      }
    }
    normalized[key] = item;
  }
  return normalized;
}

function normalizeDescriptorBindings(value) {
  if (!Array.isArray(value) || value.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("domains must bind all seven launch descriptors");
  }
  return value.map((raw, index) => {
    const domain = CVM_LAUNCH_DOMAINS[index];
    const entry = exactRecord(raw, [
      "domain",
      "descriptor_sha256",
      "values",
    ], `domains[${index}]`);
    if (entry.domain !== domain) {
      throw new Error("domains must use canonical seven-domain order");
    }
    return {
      domain,
      descriptor_sha256: exactSha256(
        entry.descriptor_sha256,
        `domains[${index}].descriptor_sha256`,
      ),
      values: exactPublicValueMap(
        entry.values,
        bootstrapKeys(domain),
        `domains[${index}].values`,
      ),
    };
  });
}

export function normalizeBootstrapPublicEnvironmentAuthority(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "projector_schema",
    "release_sha",
    "deployment_intent_sha256",
    "deployment_transaction_plan_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "image_release_manifest_sha256",
    "image_release_sigstore_verification_receipt_sha256",
    "topology_sha256",
    "cvm_launch_intent_sha256",
    "cvm_launch_review_receipt_sha256",
    "production_target_authority_sha256",
    "sdk_wire_transform_staging_receipt_sha256",
    "qvl_measurement_policy_set_sha256",
    "reviewed_at",
    "valid_until",
    "domains",
  ], "bootstrap public environment authority");
  if (parsed.schema !== PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA
    || parsed.truth_status !== PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH
    || parsed.projector_schema !== CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA) {
    throw new Error("bootstrap public environment authority identity is invalid");
  }
  const reviewedAt = canonicalTimestamp(parsed.reviewed_at, "reviewed_at");
  const validUntil = canonicalTimestamp(parsed.valid_until, "valid_until");
  if (Date.parse(validUntil) <= Date.parse(reviewedAt)) {
    throw new Error("bootstrap public environment authority validity window is invalid");
  }
  return {
    schema: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: exactReleaseSha(parsed.release_sha, "release_sha"),
    deployment_intent_sha256: exactSha256(
      parsed.deployment_intent_sha256,
      "deployment_intent_sha256",
    ),
    deployment_transaction_plan_sha256: exactSha256(
      parsed.deployment_transaction_plan_sha256,
      "deployment_transaction_plan_sha256",
    ),
    fresh_contract_deployment_receipt_sha256: exactSha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "fresh_contract_deployment_receipt_sha256",
    ),
    image_release_manifest_sha256: exactSha256(
      parsed.image_release_manifest_sha256,
      "image_release_manifest_sha256",
    ),
    image_release_sigstore_verification_receipt_sha256: exactSha256(
      parsed.image_release_sigstore_verification_receipt_sha256,
      "image_release_sigstore_verification_receipt_sha256",
    ),
    topology_sha256: exactSha256(parsed.topology_sha256, "topology_sha256"),
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    cvm_launch_review_receipt_sha256: exactSha256(
      parsed.cvm_launch_review_receipt_sha256,
      "cvm_launch_review_receipt_sha256",
    ),
    production_target_authority_sha256: exactSha256(
      parsed.production_target_authority_sha256,
      "production_target_authority_sha256",
    ),
    sdk_wire_transform_staging_receipt_sha256: exactSha256(
      parsed.sdk_wire_transform_staging_receipt_sha256,
      "sdk_wire_transform_staging_receipt_sha256",
    ),
    qvl_measurement_policy_set_sha256: exactSha256(
      parsed.qvl_measurement_policy_set_sha256,
      "qvl_measurement_policy_set_sha256",
    ),
    reviewed_at: reviewedAt,
    valid_until: validUntil,
    domains: normalizeDescriptorBindings(parsed.domains),
  };
}

export function bootstrapPublicEnvironmentAuthorityDigest(value) {
  return digest(normalizeBootstrapPublicEnvironmentAuthority(value));
}

export function canonicalBootstrapPublicEnvironmentAuthorityText(value) {
  return canonicalText(normalizeBootstrapPublicEnvironmentAuthority(value));
}
