import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  CVM_LAUNCH_DESCRIPTOR_POLICY,
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES,
  CVM_MAIN_ACCOUNT_GENESIS_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_NAMES,
  CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
  CVM_MAIN_DISABLED_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_DISABLED_PROFILE_NAMES,
  CVM_MAIN_DISABLED_PROFILE_POLICY,
  CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES,
  CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY,
  CVM_MAIN_LIVE_DEAL_COMPOSE_PROFILES_VALUE,
  CVM_MAIN_LIVE_DEAL_PROFILE_NAMES,
  CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
  CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
  cvmLaunchEnvironmentKeysDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core.mjs";
import { parseCanonicalArtifactText } from "./operator-policy-packet-core.mjs";
import {
  assertProvenanceVerifiedCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-production-executor-core.mjs";
import {
  MAX_ARENA_CHALLENGE_BINDINGS_JSON_BYTES,
  assertProjectedChallengeRegistryRuntimeEnvironment,
  normalizeChallengeRegistryRuntimeEnvironmentValues,
} from "./challenge-registry-authority-projector.mjs";

export {
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
  PHALA_BOOTSTRAP_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
  bootstrapPublicEnvironmentAuthorityDigest,
  canonicalBootstrapPublicEnvironmentAuthorityText,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
export const PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA =
  "dnai.phala-provisioning-environment-authority.v3";
export const PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA =
  "dnai.phala-postcommit-provisioning-environment-authority.v1";
export const PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA =
  "dnai.phala-deferred-public-environment-authority.v4";
export const PHALA_PHASE_SECRET_INPUT_SCHEMA =
  "dnai.phala-phase-secret-input.v1";
export const PHALA_PRIVATE_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA =
  "dnai.phala-private-environment-assembly-receipt.v1";
export const PHALA_PRIVATE_POST_MEASUREMENT_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA =
  "dnai.phala-private-post-measurement-environment-assembly-receipt.v2";
export const PHALA_PRIVATE_MAIN_PROFILE_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA =
  "dnai.phala-private-main-profile-environment-assembly-receipt.v1";

export const PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH =
  "derived_from_exact_all_seven_prepare_observations_with_commit_result_keys_explicitly_pending_not_operator_supplied";
export const PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH =
  "derived_from_provenance_replayed_exact_seven_commit_observations_not_operator_supplied_or_live_activation";
export const PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH =
  "machine_evidence_and_reviewed_final_authority_projected_post_measurement_public_values_pre_signed_b_activation_not_secret_values_or_environment_update_receipt";
export const PHALA_PRIVATE_ENVIRONMENT_ASSEMBLY_TRUTH =
  "private_in_memory_exact_key_assembly_not_encryption_commit_service_start_or_tdx_evidence";
export const PHALA_PRIVATE_POST_MEASUREMENT_ENVIRONMENT_ASSEMBLY_TRUTH =
  "private_in_memory_full_environment_reassembly_for_reviewed_profile_activation_not_encryption_mutation_restart_or_live_authority";
export const PHALA_PRIVATE_MAIN_PROFILE_ENVIRONMENT_ASSEMBLY_TRUTH =
  "private_in_memory_code_owned_complete_profile_replacement_not_encryption_mutation_restart_or_service_presence";

const PROVISIONING_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-provisioning-environment-authority/v3\0";
const POSTCOMMIT_PROVISIONING_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-postcommit-provisioning-environment-authority/v1\0";
const DEFERRED_AUTHORITY_DOMAIN =
  "dnai-wikigen/phala-deferred-public-environment-authority/v4\0";

const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const ISO_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;
const CVM_IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const FORBIDDEN_SECRET_VALUE =
  /(?:phak_[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/;
const PLACEHOLDER_VALUE =
  /^(?:change[-_ ]?me|replace[-_ ]?me|todo|tbd|example|placeholder|null|undefined|0x\.\.\.|\.\.\.)$/i;
const MAX_PUBLIC_VALUE_BYTES = 8_192;
const MAX_SECRET_VALUE_BYTES = 64 * 1_024;
const MAX_SECRET_FILE_BYTES = 256 * 1_024;
const MAX_ARENA_REGISTRY_RPC_URL_BYTES = 4_096;
const MAX_ARENA_REGISTRY_RPC_HOST_BYTES = 253;
const MAX_ARENA_REGISTRY_RPC_PATH_BYTES = 2_048;
const DNASEQ_SAFE_IR_CHALLENGE_KEY =
  "dnaseq-variant-qc-safe-ir@1.0.0";
const ARENA_POLICY_PROVISION_AUTH_DOMAIN =
  "dnai-wikigen/arena-sealed-policy-provision/v1\0";
const ARENA_POLICY_PROVISION_SCHEMA =
  "dnai.arena.sealed-policy-provision.v1";
const BASE64URL_NOPAD = /^[A-Za-z0-9_-]+$/;
const HMAC_SHA256 = /^hmac-sha256:[0-9a-f]{64}$/;

const PRIVATE_ASSEMBLIES = new WeakSet();
const PRIVATE_POST_MEASUREMENT_ASSEMBLIES = new WeakSet();
const PRIVATE_POST_MEASUREMENT_ASSEMBLY_RECEIPTS = new WeakSet();
const POSTCOMMIT_PROVISIONING_AUTHORITIES = new WeakMap();
const PROJECTED_DEFERRED_AUTHORITIES = new WeakMap();
const SIGNED_B_AUTHORIZED_DEFERRED_AUTHORITIES = new WeakMap();

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

function digest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(Buffer.from(domain, "utf8"))
    .update(Buffer.from(JSON.stringify(sortedObject(value)), "utf8"))
    .digest("hex")}`;
}

function exactSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function exactBareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero bare lowercase SHA-256 digest`);
  }
  return value;
}

function exactBytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    throw new Error(`${label} must be a nonzero canonical bytes32 value`);
  }
  return value;
}

function decodeCanonicalBase64Url(value, label, {
  minimum = 2,
  maximum = MAX_SECRET_VALUE_BYTES,
  exactLength,
} = {}) {
  if (typeof value !== "string" || !BASE64URL_NOPAD.test(value)
    || value.length % 4 === 1
    || Buffer.byteLength(value, "ascii") > MAX_SECRET_VALUE_BYTES) {
    throw new Error(`${label} is not bounded canonical base64url`);
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    throw new Error(`${label} is not bounded canonical base64url`);
  }
  if (bytes.toString("base64url") !== value
    || bytes.length < minimum || bytes.length > maximum
    || (exactLength !== undefined && bytes.length !== exactLength)) {
    bytes.fill(0);
    throw new Error(`${label} is not bounded canonical base64url`);
  }
  return bytes;
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function assertArenaSealedPolicyProvisionEnvelope({
  bootstrapValues,
  deferredValues,
  finalSecretValues,
}) {
  const expectedReleaseSha256 = exactSha256(
    deferredValues.TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256,
    "reviewed Arena worker release manifest",
  );
  const expectedEvaluatorSha256 = exactSha256(
    bootstrapValues.TINKER_ARENA_PROVISION_EVALUATOR_SHA256,
    "reviewed Arena evaluator payload",
  );
  const release = decodeCanonicalBase64Url(
    finalSecretValues.TINKER_ARENA_PROVISION_RELEASE_B64,
    "Arena release payload",
  );
  const evaluator = decodeCanonicalBase64Url(
    finalSecretValues.TINKER_ARENA_PROVISION_EVALUATOR_B64,
    "Arena evaluator payload",
  );
  const authenticationKey = decodeCanonicalBase64Url(
    finalSecretValues.TINKER_ARENA_PROVISION_AUTH_KEY_B64,
    "Arena provision authentication key",
    { minimum: 32, maximum: 32, exactLength: 32 },
  );
  try {
    const releaseSha256 = sha256Bytes(release);
    const evaluatorSha256 = sha256Bytes(evaluator);
    const suppliedTag = finalSecretValues.TINKER_ARENA_PROVISION_AUTH_TAG;
    if (releaseSha256 !== expectedReleaseSha256
      || evaluatorSha256 !== expectedEvaluatorSha256
      || typeof suppliedTag !== "string" || !HMAC_SHA256.test(suppliedTag)) {
      throw new Error("Arena sealed policy payload does not match reviewed commitments");
    }
    const envelope = {
      schema: ARENA_POLICY_PROVISION_SCHEMA,
      release_filename: "release-v2.json",
      release_sha256: releaseSha256,
      release_size: release.length,
      evaluator_filename: "sealed-evaluator-v1.json",
      evaluator_sha256: evaluatorSha256,
      evaluator_size: evaluator.length,
    };
    const expectedTag = `hmac-sha256:${createHmac(
      "sha256",
      authenticationKey,
    ).update(ARENA_POLICY_PROVISION_AUTH_DOMAIN, "utf8")
      .update(JSON.stringify(sortedObject(envelope)), "ascii")
      .digest("hex")}`;
    if (!timingSafeEqual(
      Buffer.from(expectedTag, "ascii"),
      Buffer.from(suppliedTag, "ascii"),
    )) {
      throw new Error("Arena sealed policy payload authentication failed");
    }
    return Object.freeze({
      payload_hashes_verified: true,
      authentication_tag_verified: true,
    });
  } finally {
    release.fill(0);
    evaluator.fill(0);
    authenticationKey.fill(0);
  }
}

export function verifyArenaSealedPolicyProvisionEnvelopeCommitments(
  input = {},
) {
  const parsed = exactRecord(input, [
    "authenticationKeyBase64url",
    "authenticationTag",
    "evaluatorPayloadBase64url",
    "releasePayloadBase64url",
    "reviewedEvaluatorSha256",
    "reviewedReleaseManifestSha256",
  ], "Arena sealed policy provision verification input");
  return assertArenaSealedPolicyProvisionEnvelope({
    bootstrapValues: {
      TINKER_ARENA_PROVISION_EVALUATOR_SHA256:
        parsed.reviewedEvaluatorSha256,
    },
    deferredValues: {
      TINKER_ARENA_WORKER_RELEASE_MANIFEST_SHA256:
        parsed.reviewedReleaseManifestSha256,
    },
    finalSecretValues: {
      TINKER_ARENA_PROVISION_RELEASE_B64:
        parsed.releasePayloadBase64url,
      TINKER_ARENA_PROVISION_EVALUATOR_B64:
        parsed.evaluatorPayloadBase64url,
      TINKER_ARENA_PROVISION_AUTH_KEY_B64:
        parsed.authenticationKeyBase64url,
      TINKER_ARENA_PROVISION_AUTH_TAG: parsed.authenticationTag,
    },
  });
}

function exactReleaseSha(value, label) {
  if (typeof value !== "string" || !SHA40.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase 40-hex release SHA`);
  }
  return value;
}

function exactBatchId(value, label = "batch_id") {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical launch-batch digest`);
  }
  return value;
}

function canonicalTimestamp(value, label) {
  const parsed = typeof value === "string" && ISO_SECOND.test(value)
    ? Date.parse(value)
    : Number.NaN;
  if (!Number.isFinite(parsed)
    || new Date(parsed).toISOString().replace(".000Z", "Z") !== value) {
    throw new Error(`${label} must be a canonical UTC second`);
  }
  return value;
}

function exactDomain(value, label = "domain") {
  if (!CVM_LAUNCH_DOMAINS.includes(value)) {
    throw new Error(`${label} is not a canonical CVM launch trust domain`);
  }
  return value;
}

function exactPhase(value, label = "phase") {
  if (!CVM_LAUNCH_SECRET_PHASES.includes(value)) {
    throw new Error(`${label} is not a canonical environment phase`);
  }
  return value;
}

function canonicalEnvironmentNames(values, label) {
  if (!Array.isArray(values) || values.some((value) => (
    typeof value !== "string" || !ENVIRONMENT_KEY.test(value)
  ))) {
    throw new Error(`${label} must be an array of canonical environment names`);
  }
  const sorted = [...values].sort();
  if (new Set(sorted).size !== sorted.length
    || JSON.stringify(values) !== JSON.stringify(sorted)) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  return sorted;
}

function expectedPublicKeys(domain, classification) {
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  if (classification === "bootstrap_static") {
    const allowed = new Set(policy.exact_allowed_environment_keys);
    return policy.public_environment_key_classification.descriptor_static_keys
      .filter((key) => allowed.has(key));
  }
  if (classification === "provisioning_results") {
    return [...policy.public_environment_key_classification.provisioning_result_keys];
  }
  if (classification === "post_measurement_deferred") {
    return [...policy.public_environment_key_classification.post_measurement_deferred_keys];
  }
  throw new Error("unknown public environment classification");
}

function precommitProvisioningKeys(domain) {
  return expectedPublicKeys(domain, "provisioning_results")
    .filter((key) => !key.endsWith("_CVM_ID"));
}

function postcommitProvisioningKeys(domain) {
  return expectedPublicKeys(domain, "provisioning_results")
    .filter((key) => key.endsWith("_CVM_ID"));
}

function exactValueMap(value, expectedKeys, label, { secret = false } = {}) {
  const parsed = exactRecord(value, expectedKeys, label);
  const normalized = {};
  for (const key of expectedKeys) {
    const item = parsed[key];
    const maximum = secret
      ? MAX_SECRET_VALUE_BYTES
      : key === "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON"
        ? MAX_ARENA_CHALLENGE_BINDINGS_JSON_BYTES
        : MAX_PUBLIC_VALUE_BYTES;
    if (typeof item !== "string" || item.length < 1
      || Buffer.byteLength(item, "utf8") > maximum
      || /[\u0000\r\n]/.test(item)
      || PLACEHOLDER_VALUE.test(item.trim())) {
      throw new Error(`${label}.${key} must be a bounded non-placeholder single-line value`);
    }
    if (!secret && FORBIDDEN_SECRET_VALUE.test(item)) {
      throw new Error(`${label}.${key} contains a secret-shaped value`);
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
    if (!secret && key.endsWith("_SHA256") && !SHA256.test(item)) {
      throw new Error(`${label}.${key} must be a nonzero canonical SHA-256 digest`);
    }
    if (!secret && key.endsWith("_EPOCH")) {
      if (!/^[1-9][0-9]{0,9}$/.test(item)
        || Number(item) > 4_294_967_295) {
        throw new Error(`${label}.${key} must be a canonical uint32 epoch`);
      }
    }
    if (!secret && key === "TINKER_CUSTOMER_ENABLED" && item !== "true") {
      throw new Error(
        `${label}.${key} must be the exact reviewed final-authority enable marker`,
      );
    }
    if (!secret && key === "TINKER_COLLABORATION_ENABLED"
      && item !== "false" && item !== "true") {
      throw new Error(
        `${label}.${key} must be the exact canonical false or true final-authority feature marker`,
      );
    }
    if (key.endsWith("_RUNTIME_CODE_HASH") && !/^0x(?!0{64}$)[0-9a-f]{64}$/.test(item)) {
      throw new Error(`${label}.${key} must be a nonzero lowercase bytes32 hash`);
    }
    if (!secret && key.endsWith("_URL")) {
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

function exactWalletAuthRpcEndpoint(value, label) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 9
    || Buffer.byteLength(value, "utf8") > MAX_SECRET_VALUE_BYTES
    || /[\u0000-\u0020\u007f]/.test(value)) {
    throw new Error(`${label} must be a bounded exact HTTPS endpoint`);
  }
  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTPS endpoint`);
  }
  if (endpoint.protocol !== "https:" || endpoint.origin === "null"
    || endpoint.username || endpoint.password || endpoint.hash
    || !endpoint.hostname || endpoint.port === "80"
    || endpoint.href !== value) {
    throw new Error(`${label} must be an exact credential-free HTTPS endpoint`);
  }
  return endpoint;
}

function assertIndependentWalletAuthRpcSecrets(values) {
  const primary = exactWalletAuthRpcEndpoint(
    values.TINKER_WALLET_AUTH_RPC_URL,
    "primary wallet-auth RPC URL",
  );
  const secondary = exactWalletAuthRpcEndpoint(
    values.TINKER_WALLET_AUTH_RPC_URL_SECONDARY,
    "secondary wallet-auth RPC URL",
  );
  if (primary.href === secondary.href
    || primary.origin.toLowerCase() === secondary.origin.toLowerCase()) {
    throw new Error(
      "wallet-auth primary and secondary RPC URLs must have distinct canonical HTTPS origins",
    );
  }
}

function assertArenaRegistryRpcSecret(values) {
  const value = values.TINKER_ARENA_REGISTRY_RPC_URL;
  if (typeof value !== "string"
    || Buffer.byteLength(value, "utf8") < 9
    || Buffer.byteLength(value, "utf8") > MAX_ARENA_REGISTRY_RPC_URL_BYTES
    || /[\u0000-\u0020\u007f]/.test(value)
    || value.includes("?")
    || value.includes("#")) {
    throw new Error(
      "Arena registry RPC URL must be a bounded exact credential-free HTTPS endpoint",
    );
  }
  let endpoint;
  try {
    endpoint = new URL(value);
  } catch {
    throw new Error("Arena registry RPC URL must be a valid HTTPS endpoint");
  }
  const port = endpoint.port === "" ? undefined : Number(endpoint.port);
  if (endpoint.protocol !== "https:" || endpoint.origin === "null"
    || endpoint.username || endpoint.password || !endpoint.hostname
    || endpoint.search || endpoint.hash || endpoint.href !== value
    || Buffer.byteLength(endpoint.hostname, "utf8") > MAX_ARENA_REGISTRY_RPC_HOST_BYTES
    || Buffer.byteLength(endpoint.pathname, "utf8") > MAX_ARENA_REGISTRY_RPC_PATH_BYTES
    || (port !== undefined && (!Number.isSafeInteger(port) || port < 1 || port > 65_535))) {
    throw new Error(
      "Arena registry RPC URL must be a bounded exact credential-free HTTPS endpoint",
    );
  }
}

function normalizePrepareObservation(value, domain, index) {
  const entry = exactRecord(value, [
    "domain",
    "app_id",
    "compose_hash",
    "os_image_hash",
    "prepare_response_sha256",
  ], `prepare_observations[${index}]`);
  if (entry.domain !== domain) {
    throw new Error("prepare observations must use canonical seven-domain order");
  }
  return {
    domain,
    app_id: exactReleaseSha(entry.app_id, `prepare_observations[${index}].app_id`),
    compose_hash: exactBareSha256(
      entry.compose_hash,
      `prepare_observations[${index}].compose_hash`,
    ),
    os_image_hash: exactBareSha256(
      entry.os_image_hash,
      `prepare_observations[${index}].os_image_hash`,
    ),
    prepare_response_sha256: exactSha256(
      entry.prepare_response_sha256,
      `prepare_observations[${index}].prepare_response_sha256`,
    ),
  };
}

function provisioningValuesForDomain(domain, observationsByDomain) {
  const expected = precommitProvisioningKeys(domain);
  if (expected.length === 0) return {};
  if (domain !== "main_runtime_cvm") {
    throw new Error(`no reviewed provisioning value projection exists for ${domain}`);
  }
  const main = observationsByDomain.main_runtime_cvm;
  const projected = {
    EMAIL_ORACLE_CONSUMER_APP_ID: main.app_id,
    EMAIL_ORACLE_CONSUMER_COMPOSE_HASH: main.compose_hash,
    TINKER_ARENA_WORKER_APP_ID: main.app_id,
    TINKER_ARENA_WORKER_COMPOSE_HASH: main.compose_hash,
    TINKER_ARENA_WORKER_OS_IMAGE_HASH: main.os_image_hash,
    TINKER_COMPUTE_VAULT_COMPOSE_HASH: main.compose_hash,
    TINKER_DILIGENCE_ALLOWED_APP_ID: main.app_id,
    TINKER_DILIGENCE_ALLOWED_COMPOSE_HASH: main.compose_hash,
    TINKER_DILIGENCE_ALLOWED_OS_IMAGE_HASH: main.os_image_hash,
  };
  return exactValueMap(projected, expected, `${domain}.projected_values`);
}

export function projectProvisioningEnvironmentAuthority({
  batchId,
  targetAuthoritySha256,
  cvmLaunchIntentSha256,
  bootstrapAuthoritySha256,
  preparedAt,
  prepareObservations,
} = {}) {
  if (!Array.isArray(prepareObservations)
    || prepareObservations.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("all seven prepare observations are required before projection");
  }
  const observations = CVM_LAUNCH_DOMAINS.map((domain, index) => (
    normalizePrepareObservation(prepareObservations[index], domain, index)
  ));
  if (new Set(observations.map(({ app_id }) => app_id)).size !== observations.length) {
    throw new Error("the seven prepared CVM app IDs must be pairwise distinct");
  }
  const observationsByDomain = Object.fromEntries(
    observations.map((entry) => [entry.domain, entry]),
  );
  const projected = {
    schema: PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    batch_id: exactBatchId(batchId),
    target_authority_sha256: exactSha256(
      targetAuthoritySha256,
      "target_authority_sha256",
    ),
    cvm_launch_intent_sha256: exactSha256(
      cvmLaunchIntentSha256,
      "cvm_launch_intent_sha256",
    ),
    bootstrap_authority_sha256: exactSha256(
      bootstrapAuthoritySha256,
      "bootstrap_authority_sha256",
    ),
    prepared_at: canonicalTimestamp(preparedAt, "prepared_at"),
    prepare_observations: observations,
    domains: CVM_LAUNCH_DOMAINS.map((domain) => ({
      domain,
      pending_post_commit_keys: postcommitProvisioningKeys(domain),
      values: provisioningValuesForDomain(domain, observationsByDomain),
    })),
  };
  return normalizeProvisioningEnvironmentAuthority(projected);
}

export function normalizeProvisioningEnvironmentAuthority(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "projector_schema",
    "batch_id",
    "target_authority_sha256",
    "cvm_launch_intent_sha256",
    "bootstrap_authority_sha256",
    "prepared_at",
    "prepare_observations",
    "domains",
  ], "provisioning environment authority");
  if (parsed.schema !== PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA
    || parsed.truth_status !== PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH
    || parsed.projector_schema !== CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA) {
    throw new Error("provisioning environment authority identity is invalid");
  }
  if (!Array.isArray(parsed.prepare_observations)
    || parsed.prepare_observations.length !== CVM_LAUNCH_DOMAINS.length
    || !Array.isArray(parsed.domains)
    || parsed.domains.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("provisioning environment authority must contain all seven domains");
  }
  const observations = CVM_LAUNCH_DOMAINS.map((domain, index) => (
    normalizePrepareObservation(parsed.prepare_observations[index], domain, index)
  ));
  if (new Set(observations.map(({ app_id }) => app_id)).size !== observations.length) {
    throw new Error("the seven prepared CVM app IDs must be pairwise distinct");
  }
  const observationsByDomain = Object.fromEntries(
    observations.map((entry) => [entry.domain, entry]),
  );
  const domains = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(
      parsed.domains[index],
      ["domain", "pending_post_commit_keys", "values"],
      `domains[${index}]`,
    );
    if (entry.domain !== domain) {
      throw new Error("provisioning domains must use canonical seven-domain order");
    }
    const pendingPostCommitKeys = canonicalEnvironmentNames(
      entry.pending_post_commit_keys,
      `domains[${index}].pending_post_commit_keys`,
    );
    if (JSON.stringify(pendingPostCommitKeys)
      !== JSON.stringify(postcommitProvisioningKeys(domain))) {
      throw new Error(`${domain} pending post-commit provisioning keys are not exact`);
    }
    const values = exactValueMap(
      entry.values,
      precommitProvisioningKeys(domain),
      `domains[${index}].values`,
    );
    if (JSON.stringify(values)
      !== JSON.stringify(provisioningValuesForDomain(domain, observationsByDomain))) {
      throw new Error(`${domain} provisioning values were not exactly derived from prepare`);
    }
    return { domain, pending_post_commit_keys: pendingPostCommitKeys, values };
  });
  return {
    schema: PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    batch_id: exactBatchId(parsed.batch_id),
    target_authority_sha256: exactSha256(
      parsed.target_authority_sha256,
      "target_authority_sha256",
    ),
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    bootstrap_authority_sha256: exactSha256(
      parsed.bootstrap_authority_sha256,
      "bootstrap_authority_sha256",
    ),
    prepared_at: canonicalTimestamp(parsed.prepared_at, "prepared_at"),
    prepare_observations: observations,
    domains,
  };
}

export function provisioningEnvironmentAuthorityDigest(value) {
  return digest(
    PROVISIONING_AUTHORITY_DOMAIN,
    normalizeProvisioningEnvironmentAuthority(value),
  );
}

export function canonicalProvisioningEnvironmentAuthorityText(value) {
  return canonicalText(normalizeProvisioningEnvironmentAuthority(value));
}

function postcommitValuesForDomain(domain, committedByDomain) {
  const keys = postcommitProvisioningKeys(domain);
  if (keys.length === 0) return {};
  if (keys.length !== 1) {
    throw new Error(`${domain} post-commit provisioning projection is ambiguous`);
  }
  return exactValueMap(
    { [keys[0]]: committedByDomain[domain].cvm_id },
    keys,
    `${domain}.postcommit_projected_values`,
  );
}

export function projectPostCommitProvisioningEnvironmentAuthority({
  executorFinalState,
  provisioningAuthority,
  observedAt,
} = {}) {
  const executor = assertProvenanceVerifiedCompletedPhalaExecutorState(
    executorFinalState,
  );
  const provisioning = normalizeProvisioningEnvironmentAuthority(
    provisioningAuthority,
  );
  if (executor.batch_id !== provisioning.batch_id
    || executor.launch_intent_sha256 !== provisioning.cvm_launch_intent_sha256
    || executor.target_authority_sha256 !== provisioning.target_authority_sha256) {
    throw new Error("post-commit provisioning dependencies do not share one launch lineage");
  }
  const committedByDomain = Object.fromEntries(
    executor.committed_prefix.map((entry) => [entry.domain, entry]),
  );
  const candidate = {
    schema: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    batch_id: executor.batch_id,
    target_authority_sha256: executor.target_authority_sha256,
    cvm_launch_intent_sha256: executor.launch_intent_sha256,
    bootstrap_authority_sha256: provisioning.bootstrap_authority_sha256,
    provisioning_authority_sha256:
      provisioningEnvironmentAuthorityDigest(provisioning),
    executor_final_state_sha256: phalaExecutorStateDigest(executor),
    observed_at: canonicalTimestamp(observedAt, "observed_at"),
    domains: CVM_LAUNCH_DOMAINS.map((domain) => ({
      domain,
      commit_observation_sha256: committedByDomain[domain].observation_sha256,
      values: postcommitValuesForDomain(domain, committedByDomain),
    })),
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizePostCommitProvisioningEnvironmentAuthority(candidate),
    { label: "post-commit provisioning environment authority" },
  );
  POSTCOMMIT_PROVISIONING_AUTHORITIES.set(
    normalized,
    phalaExecutorStateDigest(executor),
  );
  return normalized;
}

export function normalizePostCommitProvisioningEnvironmentAuthority(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "projector_schema",
    "batch_id",
    "target_authority_sha256",
    "cvm_launch_intent_sha256",
    "bootstrap_authority_sha256",
    "provisioning_authority_sha256",
    "executor_final_state_sha256",
    "observed_at",
    "domains",
  ], "post-commit provisioning environment authority");
  if (parsed.schema !== PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA
    || parsed.truth_status !== PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH
    || parsed.projector_schema !== CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA
    || !Array.isArray(parsed.domains)
    || parsed.domains.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("post-commit provisioning environment authority identity is invalid");
  }
  const domains = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(parsed.domains[index], [
      "domain",
      "commit_observation_sha256",
      "values",
    ], `domains[${index}]`);
    if (entry.domain !== domain) {
      throw new Error("post-commit domains must use canonical seven-domain order");
    }
    return {
      domain,
      commit_observation_sha256: exactSha256(
        entry.commit_observation_sha256,
        `domains[${index}].commit_observation_sha256`,
      ),
      values: exactValueMap(
        entry.values,
        postcommitProvisioningKeys(domain),
        `domains[${index}].values`,
      ),
    };
  });
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_POSTCOMMIT_PROVISIONING_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    batch_id: exactBatchId(parsed.batch_id),
    target_authority_sha256: exactSha256(
      parsed.target_authority_sha256,
      "target_authority_sha256",
    ),
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    bootstrap_authority_sha256: exactSha256(
      parsed.bootstrap_authority_sha256,
      "bootstrap_authority_sha256",
    ),
    provisioning_authority_sha256: exactSha256(
      parsed.provisioning_authority_sha256,
      "provisioning_authority_sha256",
    ),
    executor_final_state_sha256: exactSha256(
      parsed.executor_final_state_sha256,
      "executor_final_state_sha256",
    ),
    observed_at: canonicalTimestamp(parsed.observed_at, "observed_at"),
    domains,
  }, { label: "post-commit provisioning environment authority" });
}

export function assertPostCommitProvisioningEnvironmentAuthority(value) {
  const expectedExecutorSha256 = value
    && POSTCOMMIT_PROVISIONING_AUTHORITIES.get(value);
  const normalized = normalizePostCommitProvisioningEnvironmentAuthority(value);
  if (!expectedExecutorSha256
    || normalized.executor_final_state_sha256 !== expectedExecutorSha256
    || canonicalText(normalized) !== canonicalText(value)) {
    throw new Error("post-commit provisioning authority lacks replayed executor provenance");
  }
  return value;
}

export function postCommitProvisioningEnvironmentAuthorityDigest(value) {
  return digest(
    POSTCOMMIT_PROVISIONING_AUTHORITY_DOMAIN,
    assertPostCommitProvisioningEnvironmentAuthority(value),
  );
}

export function assemblePrivatePostMeasurementEnvironment(options = {}) {
  const parsed = exactRecord(options, [
    "domain",
    "now",
    "activationPlanSha256",
    "bootstrapAuthority",
    "provisioningAuthority",
    "postcommitProvisioningAuthority",
    "deferredAuthority",
    "bootstrapSecretInput",
    "finalSecretInput",
  ], "post-measurement environment assembly input");
  const domain = exactDomain(parsed.domain);
  if (domain !== "main_runtime_cvm") {
    throw new Error("the first post-measurement activation is main-runtime-only");
  }
  const now = canonicalTimestamp(parsed.now, "now");
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    parsed.bootstrapAuthority,
  );
  const provisioning = normalizeProvisioningEnvironmentAuthority(
    parsed.provisioningAuthority,
  );
  const postcommit = assertPostCommitProvisioningEnvironmentAuthority(
    parsed.postcommitProvisioningAuthority,
  );
  const deferred = assertSignedBAuthorizedPhalaDeferredPublicEnvironmentAuthority(
    parsed.deferredAuthority,
  );
  if (Date.parse(now) < Date.parse(bootstrap.reviewed_at)
    || Date.parse(now) < Date.parse(deferred.reviewed_at)
    || Date.parse(now) >= Date.parse(deferred.valid_until)) {
    throw new Error("post-measurement environment authorities are outside their review window");
  }
  const bootstrapSha256 = bootstrapPublicEnvironmentAuthorityDigest(bootstrap);
  const provisioningSha256 = provisioningEnvironmentAuthorityDigest(provisioning);
  if (provisioning.cvm_launch_intent_sha256 !== bootstrap.cvm_launch_intent_sha256
    || provisioning.bootstrap_authority_sha256 !== bootstrapSha256
    || postcommit.batch_id !== provisioning.batch_id
    || postcommit.cvm_launch_intent_sha256 !== provisioning.cvm_launch_intent_sha256
    || postcommit.bootstrap_authority_sha256 !== bootstrapSha256
    || postcommit.provisioning_authority_sha256 !== provisioningSha256
    || deferred.batch_id !== provisioning.batch_id
    || deferred.target_authority_sha256 !== provisioning.target_authority_sha256
    || deferred.cvm_launch_intent_sha256 !== provisioning.cvm_launch_intent_sha256) {
    throw new Error("post-measurement environment authorities do not share one launch lineage");
  }
  const bootstrapSecret = normalizePhaseSecretInput(parsed.bootstrapSecretInput, {
    expectedDomain: domain,
    expectedPhase: "bootstrap_provision",
    expectedBatchId: provisioning.batch_id,
    expectedCvmLaunchIntentSha256: provisioning.cvm_launch_intent_sha256,
  });
  const finalSecret = normalizePhaseSecretInput(parsed.finalSecretInput, {
    expectedDomain: domain,
    expectedPhase: "final_authority_runtime",
    expectedBatchId: provisioning.batch_id,
    expectedCvmLaunchIntentSha256: provisioning.cvm_launch_intent_sha256,
  });
  const arenaSealedPolicyProvision = assertArenaSealedPolicyProvisionEnvelope({
    bootstrapValues: authorityDomainEntry(bootstrap, domain).values,
    deferredValues: authorityDomainEntry(deferred, domain).values,
    finalSecretValues: finalSecret.values,
  });
  const entries = {
    ...authorityDomainEntry(bootstrap, domain).values,
    ...authorityDomainEntry(provisioning, domain).values,
    ...authorityDomainEntry(postcommit, domain).values,
    ...authorityDomainEntry(deferred, domain).values,
    ...bootstrapSecret.values,
    ...finalSecret.values,
    COMPOSE_PROFILES: CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
  };
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const expectedKeys = [
    ...expectedPublicKeys(domain, "bootstrap_static"),
    ...precommitProvisioningKeys(domain),
    ...postcommitProvisioningKeys(domain),
    ...expectedPublicKeys(domain, "post_measurement_deferred"),
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...policy.encrypted_secret_environment_keys_by_phase.final_authority_runtime,
    ...policy.public_environment_key_classification.post_measurement_phase_control_keys,
  ].sort();
  const actualKeys = Object.keys(entries).sort();
  if (new Set(actualKeys).size !== actualKeys.length
    || JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error("post-measurement environment does not contain the exact full phase keys");
  }
  const receipt = Object.freeze({
    schema: PHALA_PRIVATE_POST_MEASUREMENT_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA,
    truth_status: PHALA_PRIVATE_POST_MEASUREMENT_ENVIRONMENT_ASSEMBLY_TRUTH,
    domain,
    phase: "final_authority_runtime",
    profile_activation: Object.freeze({
      profile_names: Object.freeze([...CVM_MAIN_FINAL_ACTIVATION_PROFILE_NAMES]),
      compose_profiles_value:
        CVM_MAIN_FINAL_ACTIVATION_COMPOSE_PROFILES_VALUE,
    }),
    batch_id: provisioning.batch_id,
    cvm_launch_intent_sha256: provisioning.cvm_launch_intent_sha256,
    activation_plan_sha256: exactSha256(
      parsed.activationPlanSha256,
      "activationPlanSha256",
    ),
    bootstrap_authority_sha256: bootstrapSha256,
    provisioning_authority_sha256: provisioningSha256,
    postcommit_provisioning_authority_sha256:
      postCommitProvisioningEnvironmentAuthorityDigest(postcommit),
    deferred_authority_sha256: deferredPublicEnvironmentAuthorityDigest(deferred),
    arena_sealed_policy_payload_hashes_verified:
      arenaSealedPolicyProvision.payload_hashes_verified,
    arena_sealed_policy_authentication_tag_verified:
      arenaSealedPolicyProvision.authentication_tag_verified,
    environment_key_names: actualKeys,
    environment_key_names_sha256: cvmLaunchEnvironmentKeysDigest(actualKeys),
    value_count: actualKeys.length,
    values_present_in_receipt: false,
    value_hashes_present_in_receipt: false,
    ciphertext_present_in_receipt: false,
    encryption_performed: false,
    phala_sdk_call_performed: false,
    mutation_performed: false,
    restart_performed: false,
    live_traffic_authorized: false,
  });
  if (JSON.stringify(receipt.profile_activation)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY)) {
    throw new Error("post-measurement profile policy drifted from the launch authority");
  }
  const assembly = Object.freeze({
    entries: Object.freeze({ ...entries }),
    receipt,
  });
  PRIVATE_POST_MEASUREMENT_ASSEMBLIES.add(assembly);
  PRIVATE_POST_MEASUREMENT_ASSEMBLY_RECEIPTS.add(receipt);
  return assembly;
}

export function privatePostMeasurementEnvironmentEntries(value) {
  if (!value || !PRIVATE_POST_MEASUREMENT_ASSEMBLIES.has(value)) {
    throw new Error("a validated private post-measurement assembly is required");
  }
  return value.entries;
}

export function privatePostMeasurementEnvironmentAssemblyReceipt(value) {
  if (!value || !PRIVATE_POST_MEASUREMENT_ASSEMBLIES.has(value)) {
    throw new Error("a validated private post-measurement assembly is required");
  }
  return value.receipt;
}

export function assertPrivatePostMeasurementEnvironmentAssemblyReceipt(value) {
  if (!value || !PRIVATE_POST_MEASUREMENT_ASSEMBLY_RECEIPTS.has(value)) {
    throw new Error("a locally assembled secret-invariant post-measurement receipt is required");
  }
  return value;
}

const MAIN_PROFILE_ASSEMBLY_POLICIES = Object.freeze({
  account_genesis: Object.freeze({
    phase: "post_measurement_policy_bootstrap",
    profile: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_POLICY,
    profileNames: CVM_MAIN_ACCOUNT_GENESIS_PROFILE_NAMES,
    composeProfilesValue: CVM_MAIN_ACCOUNT_GENESIS_COMPOSE_PROFILES_VALUE,
    secretPhase: "post_measurement_policy_bootstrap",
    liveTrafficAuthorized: false,
  }),
  account_genesis_retired: Object.freeze({
    phase: "post_measurement_policy_bootstrap_retired",
    profile: CVM_MAIN_DISABLED_PROFILE_POLICY,
    profileNames: CVM_MAIN_DISABLED_PROFILE_NAMES,
    composeProfilesValue: CVM_MAIN_DISABLED_COMPOSE_PROFILES_VALUE,
    secretPhase: null,
    liveTrafficAuthorized: false,
  }),
  live_deal_runtime: Object.freeze({
    phase: "post_ceremony_live_deal_runtime",
    profile: CVM_MAIN_LIVE_DEAL_PROFILE_POLICY,
    profileNames: CVM_MAIN_LIVE_DEAL_PROFILE_NAMES,
    composeProfilesValue: CVM_MAIN_LIVE_DEAL_COMPOSE_PROFILES_VALUE,
    secretPhase: null,
    liveTrafficAuthorized: false,
  }),
});

function createPrivateMainProfileEnvironmentAssembly({
  accountGenesisAuthoritySha256,
  baseAssembly,
  profileKind,
  secretInput,
} = {}) {
  const policy = MAIN_PROFILE_ASSEMBLY_POLICIES[profileKind];
  if (!policy) {
    throw new Error("main profile environment assembly kind is unsupported");
  }
  if (!baseAssembly || !PRIVATE_POST_MEASUREMENT_ASSEMBLIES.has(baseAssembly)) {
    throw new Error(
      "main profile environment assembly requires the exact local full post-measurement base",
    );
  }
  const baseReceipt = privatePostMeasurementEnvironmentAssemblyReceipt(
    baseAssembly,
  );
  if (baseReceipt.schema
      !== PHALA_PRIVATE_POST_MEASUREMENT_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA
    || JSON.stringify(baseReceipt.profile_activation)
      !== JSON.stringify(CVM_MAIN_FINAL_ACTIVATION_PROFILE_POLICY)) {
    throw new Error("main profile environment base is not the canonical Arena/Compute assembly");
  }
  const normalizedGenesisAuthoritySha256 = exactSha256(
    accountGenesisAuthoritySha256,
    "account-genesis activation authority",
  );
  const baseEntries = privatePostMeasurementEnvironmentEntries(baseAssembly);
  if (baseEntries.TINKER_ACCOUNT_GENESIS_AUTHORIZATION_SHA256
      !== normalizedGenesisAuthoritySha256) {
    throw new Error(
      "main profile environment does not bind the signed account-genesis authority digest",
    );
  }
  let phaseSecretValues = {};
  if (policy.secretPhase !== null) {
    const normalizedSecret = normalizePhaseSecretInput(secretInput, {
      expectedDomain: "main_runtime_cvm",
      expectedPhase: policy.secretPhase,
      expectedBatchId: baseReceipt.batch_id,
      expectedCvmLaunchIntentSha256: baseReceipt.cvm_launch_intent_sha256,
    });
    phaseSecretValues = normalizedSecret.values;
  } else if (secretInput !== undefined) {
    throw new Error(
      "retired or deal main profile environment rejects account-genesis shares",
    );
  }
  const entries = {
    ...baseEntries,
    ...phaseSecretValues,
    COMPOSE_PROFILES: policy.composeProfilesValue,
  };
  const expectedKeys = [
    ...baseReceipt.environment_key_names,
    ...(policy.secretPhase === null
      ? []
      : CVM_LAUNCH_DESCRIPTOR_POLICY.main_runtime_cvm
        .encrypted_secret_environment_keys_by_phase[policy.secretPhase]),
  ].sort();
  const actualKeys = Object.keys(entries).sort();
  if (new Set(actualKeys).size !== actualKeys.length
    || JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)
    || JSON.stringify(policy.profile)
      !== JSON.stringify({
        profile_names: policy.profileNames,
        compose_profiles_value: policy.composeProfilesValue,
      })) {
    throw new Error(
      "main profile environment assembly keys or code-owned profile set drifted",
    );
  }
  const receipt = Object.freeze({
    schema: PHALA_PRIVATE_MAIN_PROFILE_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA,
    truth_status: PHALA_PRIVATE_MAIN_PROFILE_ENVIRONMENT_ASSEMBLY_TRUTH,
    domain: "main_runtime_cvm",
    phase: policy.phase,
    profile_kind: profileKind,
    profile_activation: Object.freeze({
      profile_names: Object.freeze([...policy.profileNames]),
      compose_profiles_value: policy.composeProfilesValue,
    }),
    batch_id: baseReceipt.batch_id,
    cvm_launch_intent_sha256: baseReceipt.cvm_launch_intent_sha256,
    activation_plan_sha256: baseReceipt.activation_plan_sha256,
    account_genesis_activation_authority_sha256:
      normalizedGenesisAuthoritySha256,
    base_environment_assembly_receipt_sha256: digest(
      "dnai-wikigen/phala-private-post-measurement-environment-assembly-receipt/v2\0",
      baseReceipt,
    ),
    environment_key_names: actualKeys,
    environment_key_names_sha256: cvmLaunchEnvironmentKeysDigest(actualKeys),
    value_count: actualKeys.length,
    account_genesis_private_share_count:
      policy.secretPhase === null ? 0 : Object.keys(phaseSecretValues).length,
    values_present_in_receipt: false,
    value_hashes_present_in_receipt: false,
    ciphertext_present_in_receipt: false,
    encryption_performed: false,
    phala_sdk_call_performed: false,
    mutation_performed: false,
    restart_performed: false,
    live_traffic_authorized: policy.liveTrafficAuthorized,
  });
  const assembly = Object.freeze({
    entries: Object.freeze({ ...entries }),
    receipt,
  });
  PRIVATE_POST_MEASUREMENT_ASSEMBLIES.add(assembly);
  PRIVATE_POST_MEASUREMENT_ASSEMBLY_RECEIPTS.add(receipt);
  return assembly;
}

/**
 * Add the two private account-binding shares only for the exact measured
 * one-shot profile pair. The signed authority digest is already a reviewed
 * deferred public value; this function refuses any caller-selected profile.
 */
export function assemblePrivateAccountGenesisEnvironment(options = {}) {
  const parsed = exactRecord(options, [
    "accountGenesisAuthoritySha256",
    "baseAssembly",
    "secretInput",
  ], "private account-genesis environment assembly input");
  return createPrivateMainProfileEnvironmentAssembly({
    ...parsed,
    profileKind: "account_genesis",
  });
}

/**
 * Remove both private shares and replace COMPOSE_PROFILES with the empty set.
 * This is the only valid terminal state of the one-shot account-genesis
 * sequence; the ordinary Arena/Compute activator runs separately afterward.
 */
export function assemblePrivateAccountGenesisRetirementEnvironment(
  options = {},
) {
  const parsed = exactRecord(options, [
    "accountGenesisAuthoritySha256",
    "baseAssembly",
  ], "private account-genesis retirement environment assembly input");
  return createPrivateMainProfileEnvironmentAssembly({
    ...parsed,
    profileKind: "account_genesis_retired",
  });
}

/**
 * Build the complete long-running profile replacement for the later live-deal
 * transition. The caller must still supply and validate the separate signed
 * live authority / completed ceremony gate before any SDK mutation.
 */
export function assemblePrivateLiveDealEnvironment(options = {}) {
  const parsed = exactRecord(options, [
    "accountGenesisAuthoritySha256",
    "baseAssembly",
  ], "private live-deal environment assembly input");
  return createPrivateMainProfileEnvironmentAssembly({
    ...parsed,
    profileKind: "live_deal_runtime",
  });
}

export function normalizeDeferredPublicEnvironmentAuthority(value) {
  const parsed = exactRecord(value, [
    "schema",
    "truth_status",
    "projector_schema",
    "release_sha",
    "batch_id",
    "target_authority_sha256",
    "cvm_launch_intent_sha256",
    "bootstrap_authorization_sha256",
    "deployment_intent_sha256",
    "final_release_authority_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "reviewed_at",
    "valid_until",
    "domains",
  ], "deferred public environment authority");
  if (parsed.schema !== PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA
    || parsed.truth_status !== PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH
    || parsed.projector_schema !== CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA) {
    throw new Error("deferred public environment authority identity is invalid");
  }
  const reviewedAt = canonicalTimestamp(parsed.reviewed_at, "reviewed_at");
  const validUntil = canonicalTimestamp(parsed.valid_until, "valid_until");
  if (Date.parse(validUntil) <= Date.parse(reviewedAt)) {
    throw new Error("deferred public environment authority validity window is invalid");
  }
  if (!Array.isArray(parsed.domains)
    || parsed.domains.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("deferred public environment authority must bind all seven domains");
  }
  const domains = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(parsed.domains[index], [
      "domain",
      "measured_cvm_authority_sha256",
      "values",
    ], `domains[${index}]`);
    if (entry.domain !== domain) {
      throw new Error("deferred authority domains must use canonical seven-domain order");
    }
    return {
      domain,
      measured_cvm_authority_sha256: exactSha256(
        entry.measured_cvm_authority_sha256,
        `domains[${index}].measured_cvm_authority_sha256`,
      ),
      values: exactValueMap(
        entry.values,
        expectedPublicKeys(domain, "post_measurement_deferred"),
        `domains[${index}].values`,
      ),
    };
  });
  if (new Set(domains.map(({ measured_cvm_authority_sha256: value }) => value))
      .size !== domains.length) {
    throw new Error(
      "measured CVM authority receipts must be pairwise distinct across trust domains",
    );
  }
  const mainValues = domains.find(({ domain }) => domain === "main_runtime_cvm").values;
  const registryValues = normalizeChallengeRegistryRuntimeEnvironmentValues({
    TINKER_ARENA_REGISTRY_ADDRESS: mainValues.TINKER_ARENA_REGISTRY_ADDRESS,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON:
      mainValues.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
      mainValues.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH:
      mainValues.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH,
  });
  if (JSON.stringify(registryValues) !== JSON.stringify({
    TINKER_ARENA_REGISTRY_ADDRESS: mainValues.TINKER_ARENA_REGISTRY_ADDRESS,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON:
      mainValues.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
      mainValues.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH:
      mainValues.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH,
  })) {
    throw new Error("deferred ChallengeRegistry environment is not canonical");
  }
  return {
    schema: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
    truth_status: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
    projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
    release_sha: exactReleaseSha(parsed.release_sha, "release_sha"),
    batch_id: exactBatchId(parsed.batch_id),
    target_authority_sha256: exactSha256(
      parsed.target_authority_sha256,
      "target_authority_sha256",
    ),
    cvm_launch_intent_sha256: exactSha256(
      parsed.cvm_launch_intent_sha256,
      "cvm_launch_intent_sha256",
    ),
    bootstrap_authorization_sha256: exactSha256(
      parsed.bootstrap_authorization_sha256,
      "bootstrap_authorization_sha256",
    ),
    deployment_intent_sha256: exactSha256(
      parsed.deployment_intent_sha256,
      "deployment_intent_sha256",
    ),
    final_release_authority_sha256: exactSha256(
      parsed.final_release_authority_sha256,
      "final_release_authority_sha256",
    ),
    release_verification_authority_sha256: exactSha256(
      parsed.release_verification_authority_sha256,
      "release_verification_authority_sha256",
    ),
    seven_cvm_verified_evidence_set_sha256: exactSha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "seven_cvm_verified_evidence_set_sha256",
    ),
    seven_cvm_launch_completion_receipt_sha256: exactSha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "seven_cvm_launch_completion_receipt_sha256",
    ),
    reviewed_at: reviewedAt,
    valid_until: validUntil,
    domains,
  };
}

export function deferredPublicEnvironmentAuthorityDigest(value) {
  return digest(
    DEFERRED_AUTHORITY_DOMAIN,
    normalizeDeferredPublicEnvironmentAuthority(value),
  );
}

export function canonicalDeferredPublicEnvironmentAuthorityText(value) {
  return canonicalText(normalizeDeferredPublicEnvironmentAuthority(value));
}

function evidenceDomainMap(evidenceSet) {
  return new Map(evidenceSet.domains.map((entry) => [entry.domain, entry]));
}

/**
 * Project runtime feature markers only from the current normalized final
 * authority. The launch descriptor supplies an immutable `false` bootstrap
 * default; this projection is the only path that may later install `true`.
 */
export function projectFinalReleaseAuthorityRuntimeFeatureValues(value) {
  const authority = normalizeFinalReleaseAuthorityCore(value);
  return Object.freeze({
    TINKER_COLLABORATION_ENABLED:
      authority.requested_features.collaboration === true ? "true" : "false",
  });
}

function deferredDerivedValues(
  releaseAuthoritySha256,
  evidenceSet,
  challengeRegistryRuntimeEnvironment,
  reviewedFinalAuthorityDependencies,
) {
  const byDomain = evidenceDomainMap(evidenceSet);
  const qvl = (domain) => {
    const value = byDomain.get(domain);
    if (!value || value.evidence_kind !== "qvl_identity_local_dcap_verification") {
      throw new Error(`${domain} machine evidence is not a verified QVL identity`);
    }
    return value;
  };
  const main = byDomain.get("main_runtime_cvm");
  if (!main || main.evidence_kind !== "workload_independent_signed_qvl_verdict") {
    throw new Error("main-runtime machine evidence is not an independent signed verdict");
  }
  const finalAuthority = reviewedFinalAuthorityDependencies?.final_authority;
  const dnaSeqBinding = finalAuthority?.arena_registry_bindings?.[
    DNASEQ_SAFE_IR_CHALLENGE_KEY
  ];
  if (!isRecord(finalAuthority)
    || !isRecord(dnaSeqBinding)
    || typeof dnaSeqBinding.release_policy_commitment !== "string") {
    throw new Error(
      "reviewed final authority omits the exact DNASeq worker release binding",
    );
  }
  const runtimeFeatureValues =
    projectFinalReleaseAuthorityRuntimeFeatureValues(finalAuthority);
  const policyHash = (domain) => `0x${qvl(domain).qvl_release_policy_sha256.slice(7)}`;
  return {
    main_runtime_cvm: {
      ...challengeRegistryRuntimeEnvironment.environment,
      ...runtimeFeatureValues,
      TINKER_ARENA_WORKER_QVL_RELEASE_POLICY_HASH: policyHash("arena_qvl_cvm"),
      TINKER_ARENA_WORKER_RELEASE_POLICY_COMMITMENT:
        exactBytes32(
          dnaSeqBinding.release_policy_commitment,
          "reviewed DNASeq worker release policy commitment",
        ),
      TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: main.evidence_sha256,
      TINKER_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH:
        policyHash("compute_workload_qvl_cvm"),
      TINKER_COMPUTE_WORKLOAD_QVL_VERIFIER_ADDRESS:
        qvl("compute_workload_qvl_cvm").tee_identity,
      TINKER_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: releaseAuthoritySha256,
      TINKER_DILIGENCE_QVL_RELEASE_POLICY_HASH: policyHash("diligence_qvl_cvm"),
      TINKER_DILIGENCE_QVL_VERIFIER_ADDRESS: qvl("diligence_qvl_cvm").tee_identity,
      TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_RELEASE_POLICY_HASH:
        policyHash("anchor_writer_qvl_cvm"),
      TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_VERIFIER_ADDRESS:
        qvl("anchor_writer_qvl_cvm").tee_identity,
    },
    diligence_qvl_cvm: {},
    arena_qvl_cvm: {},
    anchor_writer_qvl_cvm: {},
    compute_workload_qvl_cvm: {},
    compute_metering_qvl_cvm: {},
    independent_metering_cvm: {
      METERING_QVL_RELEASE_POLICY_HASH: policyHash("compute_metering_qvl_cvm"),
      METERING_QVL_VERIFIER_ADDRESS: qvl("compute_metering_qvl_cvm").tee_identity,
      METERING_RELEASE_AUTHORITY_SHA256: releaseAuthoritySha256,
    },
  };
}

function normalizeReviewedUnresolvedDeferredValues(value, derivedByDomain) {
  if (!Array.isArray(value) || value.length !== CVM_LAUNCH_DOMAINS.length) {
    throw new Error("reviewed unresolved deferred values must bind all seven domains");
  }
  return CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const entry = exactRecord(value[index], ["domain", "values"],
      `reviewed unresolved deferred values[${index}]`);
    if (entry.domain !== domain) {
      throw new Error("reviewed unresolved deferred values must use canonical domain order");
    }
    const expected = expectedPublicKeys(domain, "post_measurement_deferred")
      .filter((key) => !Object.hasOwn(derivedByDomain[domain], key));
    return {
      domain,
      values: exactValueMap(entry.values, expected,
        `reviewed unresolved deferred values[${index}].values`),
    };
  });
}

/**
 * Project the pre-B deferred value candidate from branded L/evidence/release
 * dependencies. Only values that cannot be derived from machine evidence
 * (principally reviewed HTTPS endpoints and release-specific commitments) are
 * accepted as input. The resulting digest is committed by the activation plan,
 * R, and signed B before it can acquire mutation authority.
 */
export async function projectPhalaDeferredPublicEnvironmentAuthority({
  releaseAuthority: releaseAuthorityValue,
  verifiedEvidenceSet: evidenceSetValue,
  launchCompletionReceipt: launchCompletionValue,
  reviewedFinalAuthorityRuntimeProjection:
    reviewedFinalAuthorityRuntimeProjectionValue,
  reviewedUnresolvedValuesByDomain,
  reviewedAt,
  validUntil,
} = {}) {
  const verifier = await import("./phala-seven-cvm-verifier-evidence.mjs");
  const completionModule = await import("./phala-seven-cvm-launch-completion.mjs");
  const reviewedAuthorityModule = await import(
    "./reviewed-final-authority-runtime.mjs"
  );
  const releaseAuthority =
    verifier.assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
      releaseAuthorityValue,
    );
  const evidenceSet = verifier.assertProductionPhalaSevenCvmEvidenceSet(
    evidenceSetValue,
  );
  const launchCompletion =
    completionModule.assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(
      launchCompletionValue,
    );
  const reviewedFinalAuthorityRuntimeProjection =
    reviewedAuthorityModule.assertReviewedFinalAuthorityRuntimeProjection(
      reviewedFinalAuthorityRuntimeProjectionValue,
    );
  const reviewedFinalAuthorityDependencies =
    reviewedAuthorityModule.readReviewedFinalAuthorityRuntimeDependencies(
      reviewedFinalAuthorityRuntimeProjection,
    );
  const releaseBootstrapAuthority =
    verifier.readPhalaSevenCvmReleaseVerificationAuthorityBootstrapAuthority(
      releaseAuthority,
    );
  const challengeRegistryRuntimeEnvironment =
    assertProjectedChallengeRegistryRuntimeEnvironment(
      reviewedFinalAuthorityDependencies
        .challenge_registry_runtime_environment_projection,
    );
  const releaseAuthoritySha256 =
    verifier.phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const evidenceSetSha256 = verifier.phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet);
  const launchCompletionSha256 =
    completionModule.phalaSevenCvmLaunchCompletionReceiptSha256(launchCompletion);
  if (releaseAuthority.release_sha !== launchCompletion.release_sha
    || releaseAuthority.deployment_intent_sha256
      !== launchCompletion.deployment_intent_sha256
    || evidenceSet.release_authority_sha256 !== releaseAuthoritySha256
    || evidenceSetSha256 !== launchCompletion.machine_verifier_evidence_set_sha256
    || releaseAuthority.bootstrap_authorization_receipt_sha256
      !== launchCompletion.nonlive_bootstrap_authorization_receipt_sha256
    || challengeRegistryRuntimeEnvironment.releaseSha !== releaseAuthority.release_sha
    || challengeRegistryRuntimeEnvironment.deploymentIntentSha256
      !== releaseAuthority.deployment_intent_sha256
    || challengeRegistryRuntimeEnvironment.cvmLaunchIntentSha256
      !== launchCompletion.cvm_launch_intent_sha256
    || reviewedFinalAuthorityRuntimeProjection.release_sha
      !== releaseAuthority.release_sha
    || reviewedFinalAuthorityRuntimeProjection.deployment_intent_sha256
      !== releaseAuthority.deployment_intent_sha256
    || reviewedFinalAuthorityRuntimeProjection.cvm_launch_intent_sha256
      !== launchCompletion.cvm_launch_intent_sha256
    || reviewedFinalAuthorityRuntimeProjection.final_authority_sha256
      !== challengeRegistryRuntimeEnvironment.finalAuthoritySha256) {
    throw new Error("deferred authority producer dependencies do not form one L lineage");
  }
  const mainReleaseDescriptor = releaseAuthority.descriptors.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const mainBootstrap = releaseBootstrapAuthority.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const reviewedFinalAuthority = reviewedFinalAuthorityDependencies.final_authority;
  const reviewedMainCvm = reviewedFinalAuthority?.cvm;
  const reviewedDelegateImage = Array.isArray(reviewedMainCvm?.images)
    ? reviewedMainCvm.images.find(({ service }) => service === "delegate")
    : null;
  const reviewedDelegateImageDigest =
    typeof reviewedDelegateImage?.image === "string"
      ? reviewedDelegateImage.image.split("@")[1]
      : null;
  if (!mainReleaseDescriptor || !mainBootstrap || !isRecord(reviewedMainCvm)
    || !isRecord(reviewedDelegateImage)
    || mainBootstrap.values.TINKER_ARENA_WORKER_RELEASE_SHA
      !== releaseAuthority.release_sha
    || mainBootstrap.values.TINKER_ARENA_WORKER_IMAGE_DIGEST
      !== reviewedDelegateImageDigest
    || reviewedDelegateImage.source_digest !== releaseAuthority.release_sha
    || reviewedMainCvm.app_id !== mainReleaseDescriptor.app_id
    || reviewedMainCvm.cvm_id !== mainReleaseDescriptor.cvm_id
    || reviewedMainCvm.compose_hash !== mainReleaseDescriptor.compose_hash
    || reviewedMainCvm.os_image_hash !== mainReleaseDescriptor.os_image_hash) {
    throw new Error(
      "reviewed final authority, bootstrap Arena pins, and main-runtime L descriptor drifted",
    );
  }
  const completionByDomain = new Map(
    launchCompletion.domains.map((entry) => [entry.domain, entry]),
  );
  const evidenceByDomain = evidenceDomainMap(evidenceSet);
  for (const descriptor of releaseAuthority.descriptors) {
    const completion = completionByDomain.get(descriptor.domain);
    const evidence = evidenceByDomain.get(descriptor.domain);
    if (!completion || !evidence
      || completion.app_id !== descriptor.app_id
      || completion.cvm_id !== descriptor.cvm_id
      || completion.machine_evidence_sha256 !== evidence.evidence_sha256
      || completion.committed_compose_hash !== descriptor.compose_hash
      || evidence.app_id !== descriptor.app_id
      || evidence.cvm_id !== descriptor.cvm_id) {
      throw new Error(`${descriptor.domain} deferred producer lineage drifted from L`);
    }
  }
  const reviewedAtValue = canonicalTimestamp(reviewedAt, "deferred reviewed_at");
  const validUntilValue = canonicalTimestamp(validUntil, "deferred valid_until");
  if (Date.parse(validUntilValue)
      > evidenceSet.minimum_activation_evidence_lease_expires_at * 1_000) {
    throw new Error(
      "deferred authority cannot outlive its minimum activation-evidence lease",
    );
  }
  const derived = deferredDerivedValues(
    releaseAuthoritySha256,
    evidenceSet,
    challengeRegistryRuntimeEnvironment,
    reviewedFinalAuthorityDependencies,
  );
  const unresolved = normalizeReviewedUnresolvedDeferredValues(
    reviewedUnresolvedValuesByDomain,
    derived,
  );
  const unresolvedByDomain = new Map(unresolved.map((entry) => [entry.domain, entry.values]));
  const candidate = deepFreezeCanonicalPlainDataGraph(
    normalizeDeferredPublicEnvironmentAuthority({
      schema: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_SCHEMA,
      truth_status: PHALA_DEFERRED_PUBLIC_ENVIRONMENT_AUTHORITY_TRUTH,
      projector_schema: CVM_PUBLIC_ENVIRONMENT_VALUE_PROJECTOR_SCHEMA,
      release_sha: releaseAuthority.release_sha,
      batch_id: launchCompletion.batch_id,
      target_authority_sha256: launchCompletion.production_target_authority_sha256,
      cvm_launch_intent_sha256: launchCompletion.cvm_launch_intent_sha256,
      bootstrap_authorization_sha256:
        launchCompletion.nonlive_bootstrap_authorization_receipt_sha256,
      deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
      final_release_authority_sha256:
        reviewedFinalAuthorityRuntimeProjection.final_authority_sha256,
      release_verification_authority_sha256: releaseAuthoritySha256,
      seven_cvm_verified_evidence_set_sha256: evidenceSetSha256,
      seven_cvm_launch_completion_receipt_sha256: launchCompletionSha256,
      reviewed_at: reviewedAtValue,
      valid_until: validUntilValue,
      domains: CVM_LAUNCH_DOMAINS.map((domain) => ({
        domain,
        measured_cvm_authority_sha256: evidenceByDomain.get(domain).evidence_sha256,
        values: {
          ...derived[domain],
          ...unresolvedByDomain.get(domain),
        },
      })),
    }),
    { label: "projected deferred public environment authority" },
  );
  PROJECTED_DEFERRED_AUTHORITIES.set(candidate, Object.freeze({
    digest: deferredPublicEnvironmentAuthorityDigest(candidate),
    releaseAuthority,
    evidenceSet,
    launchCompletion,
    reviewedFinalAuthorityRuntimeProjection,
    challengeRegistryRuntimeEnvironment,
  }));
  return candidate;
}

export function assertProjectedPhalaDeferredPublicEnvironmentAuthority(value) {
  const provenance = value && PROJECTED_DEFERRED_AUTHORITIES.get(value);
  if (!provenance
    || provenance.digest !== deferredPublicEnvironmentAuthorityDigest(value)) {
    throw new Error("deferred authority was not projected from branded L and machine evidence");
  }
  return value;
}

/**
 * Add signed-B authority to the exact projected candidate. This operation does
 * not mutate Phala; it proves B commits R, R commits the activation plan, and
 * the plan commits these exact deferred bytes.
 */
export async function authorizePhalaDeferredPublicEnvironmentAuthority({
  deferredAuthority,
  preCeremonyRuntimeAuthority: runtimeAuthorityValue,
  ceremonyAuthorization,
  ceremonyAuthorizationDependencies,
} = {}) {
  const runtimeModule = await import("./pre-ceremony-runtime-authority.mjs");
  const stageModule = await import("./release-authority-stages.mjs");
  const authority = assertProjectedPhalaDeferredPublicEnvironmentAuthority(
    deferredAuthority,
  );
  const runtimeAuthority = runtimeModule.assertFreshBrandedPreCeremonyRuntimeAuthority(
    runtimeAuthorityValue,
  );
  const dependencies = exactRecord(ceremonyAuthorizationDependencies, [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "stageBReviewerStatusHistory",
  ], "signed-B dependency set");
  if (!Array.isArray(dependencies.stageBReviewerStatusHistory)) {
    throw new TypeError(
      "signed-B dependency set requires the complete Stage-B reviewer status history",
    );
  }
  const stageOptions = {
    deploymentIntent: dependencies.deploymentIntent,
    freshContractDeploymentReceipt: dependencies.freshContractDeploymentReceipt,
    reviewerGenesis: dependencies.reviewerGenesis,
    reviewerGenesisAcceptance: dependencies.reviewerGenesisAcceptance,
    reviewerStatusHistory: dependencies.stageBReviewerStatusHistory,
    preCeremonyRuntimeAuthority: runtimeAuthority,
    checkedAtMs: Date.now(),
    enforceFreshness: true,
  };
  const signedB = stageModule.normalizeCeremonyAuthorizationCore(
    ceremonyAuthorization,
    stageOptions,
  );
  const signedBSha256 = stageModule.ceremonyAuthorizationCoreSha256(
    ceremonyAuthorization,
    stageOptions,
  );
  const runtimeSha256 = runtimeModule.preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  const plan = runtimeAuthority.post_measurement_activation_plan;
  const provenance = PROJECTED_DEFERRED_AUTHORITIES.get(authority);
  const reviewedAuthorityModule = await import(
    "./reviewed-final-authority-runtime.mjs"
  );
  const reviewedFinalAuthorityRuntimeProjection =
    reviewedAuthorityModule.assertReviewedFinalAuthorityRuntimeProjection(
      provenance.reviewedFinalAuthorityRuntimeProjection,
    );
  if (Date.parse(reviewedFinalAuthorityRuntimeProjection.review_expires_at)
      <= Date.now()) {
    throw new Error("reviewed final-authority runtime projection expired before signed B");
  }
  if (signedB.pre_ceremony_runtime_authority_sha256 !== runtimeSha256
    || signedB.cvm_launch_intent_sha256 !== authority.cvm_launch_intent_sha256
    || signedB.deployment_authority.deployment_intent_sha256
      !== authority.deployment_intent_sha256
    || runtimeAuthority.post_measurement_activation_plan_sha256
      !== (await import("./phala-post-measurement-activation.mjs"))
        .phalaPostMeasurementActivationPlanSha256(plan)
    || plan.deferred_public_environment_authority_sha256
      !== deferredPublicEnvironmentAuthorityDigest(authority)
    || plan.release_verification_authority_sha256
      !== authority.release_verification_authority_sha256
    || plan.seven_cvm_verified_evidence_set_sha256
      !== authority.seven_cvm_verified_evidence_set_sha256
    || plan.seven_cvm_launch_completion_receipt_sha256
      !== authority.seven_cvm_launch_completion_receipt_sha256
    || runtimeAuthority.seven_cvm_launch_completion_receipt_sha256
      !== authority.seven_cvm_launch_completion_receipt_sha256
    || provenance.launchCompletion.batch_id !== authority.batch_id
    || reviewedFinalAuthorityRuntimeProjection.final_authority_sha256
      !== authority.final_release_authority_sha256) {
    throw new Error("signed B, R, activation plan, L, and deferred authority do not share one lineage");
  }
  SIGNED_B_AUTHORIZED_DEFERRED_AUTHORITIES.set(authority, Object.freeze({
    digest: deferredPublicEnvironmentAuthorityDigest(authority),
    signed_b_sha256: signedBSha256,
    runtime_authority_sha256: runtimeSha256,
  }));
  return authority;
}

export function assertSignedBAuthorizedPhalaDeferredPublicEnvironmentAuthority(value) {
  const provenance = value && SIGNED_B_AUTHORIZED_DEFERRED_AUTHORITIES.get(value);
  if (!provenance
    || provenance.digest !== deferredPublicEnvironmentAuthorityDigest(value)) {
    throw new Error("deferred authority lacks exact signed-B and R authorization");
  }
  return value;
}

export function readSignedBDeferredPublicEnvironmentAuthorityProvenance(value) {
  assertSignedBAuthorizedPhalaDeferredPublicEnvironmentAuthority(value);
  return SIGNED_B_AUTHORIZED_DEFERRED_AUTHORITIES.get(value);
}

export function normalizePhaseSecretInput(value, {
  expectedDomain,
  expectedPhase,
  expectedBatchId,
  expectedCvmLaunchIntentSha256,
} = {}) {
  const parsed = exactRecord(value, [
    "schema",
    "domain",
    "phase",
    "batch_id",
    "cvm_launch_intent_sha256",
    "values",
  ], "phase secret input");
  if (parsed.schema !== PHALA_PHASE_SECRET_INPUT_SCHEMA) {
    throw new Error("phase secret input schema is invalid");
  }
  const domain = exactDomain(parsed.domain);
  const phase = exactPhase(parsed.phase);
  const batchId = exactBatchId(parsed.batch_id);
  const launchSha = exactSha256(
    parsed.cvm_launch_intent_sha256,
    "cvm_launch_intent_sha256",
  );
  if (expectedDomain !== undefined && domain !== expectedDomain) {
    throw new Error("phase secret input domain does not match the requested CVM");
  }
  if (expectedPhase !== undefined && phase !== expectedPhase) {
    throw new Error("phase secret input does not match the requested phase");
  }
  if (expectedBatchId !== undefined && batchId !== expectedBatchId) {
    throw new Error("phase secret input batch_id does not match the launch batch");
  }
  if (expectedCvmLaunchIntentSha256 !== undefined
    && launchSha !== expectedCvmLaunchIntentSha256) {
    throw new Error("phase secret input launch digest does not match launch authority");
  }
  const expectedKeys = CVM_LAUNCH_DESCRIPTOR_POLICY[domain]
    .encrypted_secret_environment_keys_by_phase[phase];
  const values = exactValueMap(parsed.values, expectedKeys, "values", {
    secret: true,
  });
  if (domain === "main_runtime_cvm" && phase === "bootstrap_provision") {
    assertIndependentWalletAuthRpcSecrets(values);
  }
  if (domain === "main_runtime_cvm" && phase === "final_authority_runtime") {
    assertArenaRegistryRpcSecret(values);
  }
  return {
    schema: PHALA_PHASE_SECRET_INPUT_SCHEMA,
    domain,
    phase,
    batch_id: batchId,
    cvm_launch_intent_sha256: launchSha,
    values,
  };
}

function readStablePrivateFile(filePath, { expectedRawSha256 } = {}) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)) {
    throw new Error("phase secret input path must be absolute");
  }
  const expectedDigest = expectedRawSha256 === undefined
    ? null
    : exactSha256(expectedRawSha256, "phase secret input raw file digest");
  const flags = fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = fs.openSync(filePath, flags);
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.uid !== process.getuid()
      || (before.mode & 0o777) !== 0o600
      || before.size < 2 || before.size > MAX_SECRET_FILE_BYTES) {
      throw new Error("phase secret input must be a current-owner mode-0600 bounded regular file");
    }
    const bytes = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    const observedDigest = `sha256:${createHash("sha256")
      .update(bytes)
      .digest("hex")}`;
    if (before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs
      || bytes.length !== before.size
      || (expectedDigest !== null && observedDigest !== expectedDigest)) {
      throw new Error("phase secret input changed during its bounded read");
    }
    return bytes.toString("utf8");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function readExactPhaseSecretInputFile(filePath, expected = {}) {
  const parsed = parseCanonicalArtifactText(readStablePrivateFile(filePath), {
    label: "phase secret input",
  });
  if (!parsed.ok) {
    throw new Error(parsed.errors[0]?.message || "phase secret input is invalid");
  }
  return normalizePhaseSecretInput(parsed.artifact, expected);
}

/**
 * Reopen and parse a phase-secret input only when the exact bytes still match
 * an earlier private file binding. The digest is recomputed from the same
 * opened descriptor used for parsing, so a pathname replacement between
 * ceremony preparation and the mutation runtime cannot substitute new secret
 * values. The binding and its raw digest remain private operator inputs.
 */
export function readExactBoundPhaseSecretInputFile(bindingValue, expected = {}) {
  const binding = exactRecord(
    bindingValue,
    ["path", "sha256"],
    "phase secret input file binding",
  );
  if (typeof binding.path !== "string" || !path.isAbsolute(binding.path)
    || path.resolve(binding.path) !== binding.path
    || path.normalize(binding.path) !== binding.path) {
    throw new Error("phase secret input binding path must be canonical and absolute");
  }
  const sha256 = exactSha256(
    binding.sha256,
    "phase secret input binding raw file digest",
  );
  const parsed = parseCanonicalArtifactText(readStablePrivateFile(binding.path, {
    expectedRawSha256: sha256,
  }), { label: "phase secret input" });
  if (!parsed.ok) {
    throw new Error(parsed.errors[0]?.message || "phase secret input is invalid");
  }
  return normalizePhaseSecretInput(parsed.artifact, expected);
}

function authorityDomainEntry(authority, domain) {
  return authority.domains[CVM_LAUNCH_DOMAINS.indexOf(domain)];
}

export function assemblePrivateBootstrapEnvironment(options = {}) {
  const parsed = exactRecord(options, [
    "domain",
    "now",
    "bootstrapAuthority",
    "provisioningAuthority",
    "secretInput",
  ], "bootstrap environment assembly input");
  const domain = exactDomain(parsed.domain);
  const now = canonicalTimestamp(parsed.now, "now");
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    parsed.bootstrapAuthority,
  );
  const provisioning = normalizeProvisioningEnvironmentAuthority(
    parsed.provisioningAuthority,
  );
  if (Date.parse(now) < Date.parse(bootstrap.reviewed_at)
    || Date.parse(now) >= Date.parse(bootstrap.valid_until)) {
    throw new Error("bootstrap public environment authority is outside its review window");
  }
  if (provisioning.cvm_launch_intent_sha256 !== bootstrap.cvm_launch_intent_sha256
    || provisioning.bootstrap_authority_sha256
      !== bootstrapPublicEnvironmentAuthorityDigest(bootstrap)) {
    throw new Error("bootstrap and provisioning environment authorities are not bound");
  }
  const secret = normalizePhaseSecretInput(parsed.secretInput, {
    expectedDomain: domain,
    expectedPhase: "bootstrap_provision",
    expectedBatchId: provisioning.batch_id,
    expectedCvmLaunchIntentSha256: bootstrap.cvm_launch_intent_sha256,
  });
  const entries = {
    ...authorityDomainEntry(bootstrap, domain).values,
    ...authorityDomainEntry(provisioning, domain).values,
    ...secret.values,
  };
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[domain];
  const expectedKeys = [
    ...expectedPublicKeys(domain, "bootstrap_static"),
    ...precommitProvisioningKeys(domain),
    ...policy.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
  ].sort();
  const actualKeys = Object.keys(entries).sort();
  if (new Set(actualKeys).size !== actualKeys.length
    || JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error("assembled bootstrap environment does not contain the exact phase keys");
  }
  const receipt = Object.freeze({
    schema: PHALA_PRIVATE_ENVIRONMENT_ASSEMBLY_RECEIPT_SCHEMA,
    truth_status: PHALA_PRIVATE_ENVIRONMENT_ASSEMBLY_TRUTH,
    domain,
    phase: "bootstrap_provision",
    batch_id: provisioning.batch_id,
    cvm_launch_intent_sha256: bootstrap.cvm_launch_intent_sha256,
    bootstrap_authority_sha256: bootstrapPublicEnvironmentAuthorityDigest(bootstrap),
    provisioning_authority_sha256:
      provisioningEnvironmentAuthorityDigest(provisioning),
    environment_key_names: actualKeys,
    environment_key_names_sha256: cvmLaunchEnvironmentKeysDigest(actualKeys),
    value_count: actualKeys.length,
    values_present_in_receipt: false,
    value_hashes_present_in_receipt: false,
    ciphertext_present_in_receipt: false,
    encryption_performed: false,
    phala_sdk_call_performed: false,
    mutation_performed: false,
    live_traffic_authorized: false,
  });
  const assembly = Object.freeze({
    entries: Object.freeze({ ...entries }),
    receipt,
  });
  PRIVATE_ASSEMBLIES.add(assembly);
  return assembly;
}

function requirePrivateAssembly(assembly) {
  if (!assembly || !PRIVATE_ASSEMBLIES.has(assembly)) {
    throw new Error("a validated private environment assembly is required");
  }
}

export function privateEnvironmentEntries(assembly) {
  requirePrivateAssembly(assembly);
  return { ...assembly.entries };
}

export function privateEnvironmentAssemblyReceipt(assembly) {
  requirePrivateAssembly(assembly);
  return structuredClone(assembly.receipt);
}

export function canonicalPrivateEnvironmentAssemblyReceiptText(assembly) {
  return canonicalText(privateEnvironmentAssemblyReceipt(assembly));
}

export function createDeferredEnvironmentAssemblyPlan(options = {}) {
  const {
    domain,
    phase,
    deferredAuthority,
  } = exactRecord(options, [
    "domain",
    "phase",
    "deferredAuthority",
  ], "deferred environment assembly plan input");
  const normalizedDomain = exactDomain(domain);
  const normalizedPhase = exactPhase(phase);
  if (normalizedPhase === "bootstrap_provision") {
    throw new Error("deferred authority must never be used for bootstrap provision");
  }
  const deferred = normalizeDeferredPublicEnvironmentAuthority(deferredAuthority);
  const policy = CVM_LAUNCH_DESCRIPTOR_POLICY[normalizedDomain];
  return Object.freeze({
    schema: "dnai.phala-deferred-environment-assembly-plan.v1",
    availability: "blocked",
    reason:
      "reviewed_exact_compose_profiles_value_and_encrypted_environment_update_adapter_not_implemented",
    domain: normalizedDomain,
    phase: normalizedPhase,
    deferred_authority_sha256: deferredPublicEnvironmentAuthorityDigest(deferred),
    public_value_keys: Object.keys(authorityDomainEntry(deferred, normalizedDomain).values),
    phase_control_keys: [
      ...policy.public_environment_key_classification
        .post_measurement_phase_control_keys,
    ],
    secret_value_keys: [
      ...policy.encrypted_secret_environment_keys_by_phase[normalizedPhase],
    ],
    environment_values_present: false,
    mutation_authorized: false,
  });
}
