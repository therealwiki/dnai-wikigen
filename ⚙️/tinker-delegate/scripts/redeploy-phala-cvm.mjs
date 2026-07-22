#!/usr/bin/env node

/**
 * Reviewed, fresh-only Phala CVM launch planner with hard-disabled execution.
 *
 * The command-line entry point is deliberately plan-only.  It never imports the
 * Phala SDK, reads PHALA_CLOUD_API_KEY, or calls a Phala API.  This module has no
 * caller-injected client/collector surface.  Production execution is hard
 * blocked until every authority and confidentiality dependency listed below is
 * implemented by a sealed adapter.
 */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, open, realpath } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { TextDecoder } from "node:util";

import {
  CVM_LAUNCH_DOMAINS,
  CVM_LAUNCH_SECRET_PHASES,
  MAX_CVM_LAUNCH_INTENT_BYTES,
  PHALA_CONTROL_PLANE_AUTHORITY,
  PHALA_OS_IMAGE_CATALOG_ENTRY,
  canonicalCvmLaunchIntentCoreArtifactText,
  cvmLaunchEnvironmentKeysDigest,
  cvmLaunchIntentCoreDigest,
  cvmLaunchIntentValidationReceipt,
  parseCvmLaunchIntentCoreText,
  phalaOsImageCatalogEntryDigest,
  rawSha256,
} from "../../../scripts/cvm-launch-intent-core.mjs";
import {
  canonicalArtifactSha256,
  describeAuthorityReviewSubjectText,
  parseAuthorityReviewEnvelopeText,
  parseDeploymentIntentCoreText,
  parseFreshContractDeploymentReceiptText,
} from "../../../scripts/operator-policy-packet-core.mjs";
import {
  ACTIVATION_READINESS_AUTHORIZED_ACTIONS,
  ACTIVATION_READINESS_EXECUTION_BOUNDARY,
  ACTIVATION_READINESS_MAX_LIFETIME_MS,
  activationReadinessSnapshotDigest,
  normalizeActivationReadinessSnapshot,
} from "../../../scripts/activation-preflight-core.mjs";
import {
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES as CANONICAL_PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES as CANONICAL_PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
  PHALA_PRODUCTION_EXECUTION_DISABLED_CODE as CANONICAL_PHALA_PRODUCTION_EXECUTION_DISABLED_CODE,
} from "../../../scripts/phala-production-execution-policy.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS,
  readReverifyDescriptorSetAndCheckpointPhalaBootstrap,
} from "../../../scripts/phala-nonlive-bootstrap-authorization.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  assertTrackedDescriptorMaterializationSources,
  validateCanonicalGeneratedCvmDescriptorSet,
  verifyExactTrackedSourceDescriptorReproduction,
} from "../../../scripts/cvm-release-descriptor-set.mjs";

export const PHALA_CVM_LAUNCH_RECEIPT_SCHEMA =
  "dnai.phala-cvm-launch-receipt.v1";
export const PHALA_FRESH_CREATE_COMMAND_PLAN_SCHEMA =
  "dnai.phala-fresh-create-command-plan.v2";
export const PHALA_CLI_VERSION = "v1.1.19+d2300dd";
export const PHALA_CLI_PACKAGE_VERSION = "1.1.19";
export const PHALA_CLOUD_SDK_VERSION = "0.2.10";
export const PHALA_CLOUD_API_ORIGIN = PHALA_CONTROL_PLANE_AUTHORITY.api_origin;
export const PHALA_CLOUD_API_VERSION = PHALA_CONTROL_PLANE_AUTHORITY.api_version;
export const PHALA_FRESH_CLI_DEPLOY_FORBIDDEN = true;
export const PHALA_PRODUCTION_EXECUTION_DISABLED_CODE =
  CANONICAL_PHALA_PRODUCTION_EXECUTION_DISABLED_CODE;
export const PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES =
  CANONICAL_PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES;
export const PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES =
  CANONICAL_PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES;
export const PHALA_FUTURE_SEALED_AUTHORITY_SEQUENCE = Object.freeze([
  "stable_read_verify_bootstrap_target_wire_staging_contract_anchor_sigstore_and_clean_ci_seven_descriptor_set:before_prediction",
  "nextAppIds(counts=7)",
  "compute_exact_seven_compose_hashes",
  "project_exact_reviewed_static_public_environment_values",
  "persist_non_atomic_recovery_journal_before_first_remote_mutation",
  "fsync_recovery_journal_parent_directory_and_verify_complete_writes",
  "for_each_domain_stable_read_verify_bootstrap_target_wire_staging_contract_anchor_sigstore_and_clean_ci_seven_descriptor_set:before_each_prepare",
  "compute_and_capture_exact_post_sdk_wire_body_for_each_domain",
  "immediate_finalized_read_only_readiness_recheck_before_each_provision",
  "fsync_provision_attempt_before_each_remote_provision",
  "for_each_domain_stable_read_verify_bootstrap_target_wire_staging_contract_anchor_sigstore_and_clean_ci_seven_descriptor_set:before_each_provision",
  "provisionCvm_supporting_six_then_main_with_reviewed_non_dev_os_image",
  "fsync_observed_provision_prefix_after_each_remote_provision",
  "validate_all_seven_preparations_before_any_commit",
  "resolve_exact_provisioning_results_from_validated_seven_preparations",
  "project_exact_provisioning_environment_authority",
  "record_post_measurement_projection_requirements_without_assembling_late_values",
  "pin_exact_reviewed_phala_kms_k256_identity_and_catalog_entry",
  "safeGetAppEnvEncryptPubKey_signed_fetch_for_each_exact_predicted_app_id",
  "dstack_verifyEnvEncryptPublicKeyLegacy_recover_and_compare_exact_kms_identity",
  "reject_zero_invalid_duplicate_substituted_or_unbound_app_env_pubkeys",
  "require_review_margin_for_full_non_atomic_commit_batch",
  "for_each_domain_stable_read_verify_bootstrap_target_wire_staging_contract_anchor_sigstore_and_clean_ci_seven_descriptor_set:before_each_commit",
  "immediate_finalized_read_only_readiness_recheck_before_each_commit",
  "immediate_repeat_signed_kms_pubkey_fetch_and_cryptographic_identity_check_before_encrypt_and_commit",
  "fsync_commit_attempt_before_each_remote_commit",
  "assemble_and_encrypt_exact_bootstrap_phase_environment_values",
  "commitCvmProvision_supporting_six_then_main",
  "fsync_observed_commit_prefix_after_each_remote_commit",
  "assert_private_production_posture_all_seven",
]);

export const HARDENED_CVM_COMPOSE_FLAGS = Object.freeze({
  public_logs: false,
  public_sysinfo: false,
  public_tcbinfo: false,
});

const ENVIRONMENT_KEY = /^[A-Z][A-Z0-9_]{0,127}$/;
const NONZERO_SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const FILE_LIMITS = Object.freeze({
  deploymentIntent: 65_536,
  contractDeploymentReceipt: 65_536,
  launchIntent: MAX_CVM_LAUNCH_INTENT_BYTES,
  launchIntentReceipt: 65_536,
  reviewEnvelope: 65_536,
  reviewEvidence: 1_048_576,
  readinessEvidence: 65_536,
  compose: 204_800,
  runtimeEnv: 262_144,
  keyFile: 32_768,
  packageManifest: 65_536,
});
const PLACEHOLDER_VALUE = /^(?:change[-_ ]?me|replace[-_ ]?me|placeholder|todo|tbd|null|undefined|none|example|<[^>]+>)$/i;
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

const ARGUMENTS = Object.freeze({
  "deployment-intent": "deploymentIntent",
  "contract-deployment-receipt": "contractDeploymentReceipt",
  "launch-intent": "launchIntent",
  "launch-intent-receipt": "launchIntentReceipt",
  "review-envelope": "reviewEnvelope",
  "review-evidence": "reviewEvidence",
  "readiness-evidence": "readinessEvidence",
  domain: "domain",
  phase: "phase",
  compose: "compose",
  "runtime-env": "runtimeEnv",
  "descriptor-static-keys": "descriptorStaticKeys",
  "descriptor-defaulted-keys": "descriptorDefaultedKeys",
  "provisioning-result-keys": "provisioningResultKeys",
  "post-measurement-deferred-keys": "postMeasurementDeferredKeys",
  "post-measurement-phase-control-keys": "postMeasurementPhaseControlKeys",
  "encrypted-secret-keys": "encryptedSecretKeys",
});

const REQUIRED_ARGUMENTS = Object.freeze(Object.values(ARGUMENTS));
const VALIDATED_INPUT_STATE = new WeakMap();
const INSTALLED_PACKAGE_IDENTITY_STATE = new WeakSet();

function usage() {
  console.error([
    "Usage:",
    "  node scripts/redeploy-phala-cvm.mjs \\",
    "    --deployment-intent FILE --contract-deployment-receipt FILE \\",
    "    --launch-intent FILE --launch-intent-receipt FILE \\",
    "    --review-envelope FILE --review-evidence FILE \\",
    "    --readiness-evidence FILE --domain CANONICAL_DOMAIN \\",
    "    --phase CANONICAL_PHASE --compose FILE --runtime-env FILE \\",
    "    --descriptor-static-keys FILE --descriptor-defaulted-keys FILE \\",
    "    --provisioning-result-keys FILE --post-measurement-deferred-keys FILE \\",
    "    --post-measurement-phase-control-keys FILE --encrypted-secret-keys FILE",
    "",
    "This command validates and prints a secret-free plan. It never deploys.",
    "Fresh `phala deploy --prepare-only` is forbidden because CLI 1.1.19 commits.",
  ].join("\n"));
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortedObject(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function exactJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)
    || Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function requireBrandedValidatedInput(value) {
  const state = value && VALIDATED_INPUT_STATE.get(value);
  if (!state) {
    throw new Error("launch input was not produced by full stable-file validation");
  }
  return state;
}

function boundedMessage(error) {
  return String(error?.message || error || "validation failed")
    .replace(/[\r\n]+/g, " ")
    .slice(0, 300);
}

function requireEnvironmentKey(value, label = "environment key") {
  if (typeof value !== "string" || !ENVIRONMENT_KEY.test(value)) {
    throw new Error(`${label} is not a canonical uppercase environment key`);
  }
  return value;
}

function fileIdentity(stat) {
  return ["dev", "ino", "size", "mtimeNs", "ctimeNs"]
    .map((field) => String(stat[field]))
    .join(":");
}

export async function readStableBoundedFile(filePath, {
  label = "input",
  maxBytes,
  minBytes = 0,
  requireMode0600 = false,
} = {}) {
  if (typeof filePath !== "string" || !filePath || !Number.isSafeInteger(maxBytes)) {
    throw new Error(`${label} path or size policy is invalid`);
  }
  const absolutePath = path.resolve(filePath);
  let handle;
  try {
    handle = await open(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const before = await handle.stat({ bigint: true });
    const mode = Number(before.mode & 0o777n);
    if (!before.isFile()
      || before.size < BigInt(minBytes)
      || before.size > BigInt(maxBytes)) {
      throw new Error(`${label} is not a bounded regular file`);
    }
    if (requireMode0600 && mode !== 0o600) {
      throw new Error(`${label} must have mode 0600`);
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (fileIdentity(before) !== fileIdentity(after)
      || BigInt(bytes.length) !== before.size) {
      throw new Error(`${label} changed while it was being read`);
    }
    let text;
    try {
      text = UTF8_DECODER.decode(bytes);
    } catch {
      throw new Error(`${label} is not valid UTF-8`);
    }
    return Object.freeze({
      path: absolutePath,
      bytes,
      text,
      mode,
      sha256: rawSha256(bytes),
      identity: fileIdentity(after),
    });
  } catch (error) {
    throw new Error(`${label} could not be read safely: ${boundedMessage(error)}`);
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

async function resolveExecutableWithoutRunning(command, environment) {
  const pathValue = typeof environment?.PATH === "string" ? environment.PATH : "";
  const directories = pathValue.split(path.delimiter);
  if (directories.length > 128 || Buffer.byteLength(pathValue, "utf8") > 32_768) {
    throw new Error("diagnostic PATH is outside the bounded policy");
  }
  for (const directory of directories) {
    if (!directory || !path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, command);
    try {
      await access(candidate, constants.X_OK);
      return await realpath(candidate);
    } catch {
      // Continue across the bounded PATH without executing a candidate.
    }
  }
  throw new Error("the diagnostic Phala package executable is unavailable");
}

function parsePackageManifest(file, expectedName, expectedVersion, label) {
  let manifest;
  try {
    manifest = JSON.parse(file.text);
  } catch {
    throw new Error(`${label} package manifest is not valid JSON`);
  }
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)
    || manifest.name !== expectedName || manifest.version !== expectedVersion) {
    throw new Error(`${label} package manifest identity is not exact`);
  }
  return manifest;
}

export async function inspectInstalledPhalaPackageIdentity(
  environment = process.env,
) {
  const executable = await resolveExecutableWithoutRunning("phala", environment);
  let directory = path.dirname(executable);
  for (let depth = 0; depth < 6; depth += 1) {
    try {
      const cliFile = await readStableBoundedFile(path.join(directory, "package.json"), {
        label: "Phala CLI package manifest",
        maxBytes: FILE_LIMITS.packageManifest,
        minBytes: 2,
      });
      const cliManifest = parsePackageManifest(
        cliFile,
        "phala",
        PHALA_CLI_PACKAGE_VERSION,
        "Phala CLI",
      );
      const cliBin = cliManifest?.bin?.phala;
      if (typeof cliBin !== "string"
        || path.resolve(directory, cliBin) !== executable) {
        throw new Error("Phala CLI package manifest does not bind the resolved executable");
      }
      const sdkFile = await readStableBoundedFile(
        path.join(directory, "node_modules", "@phala", "cloud", "package.json"),
        {
          label: "Phala Cloud SDK package manifest",
          maxBytes: FILE_LIMITS.packageManifest,
          minBytes: 2,
        },
      );
      parsePackageManifest(
        sdkFile,
        "@phala/cloud",
        PHALA_CLOUD_SDK_VERSION,
        "Phala Cloud SDK",
      );
      const identity = deepFreeze({
        schema: "dnai.phala-installed-package-identity.v1",
        source: "installed_package_manifests_no_executable_probe",
        cli: {
          name: "phala",
          version: PHALA_CLI_PACKAGE_VERSION,
          manifest_sha256: cliFile.sha256,
        },
        sdk: {
          name: "@phala/cloud",
          version: PHALA_CLOUD_SDK_VERSION,
          manifest_sha256: sdkFile.sha256,
        },
      });
      INSTALLED_PACKAGE_IDENTITY_STATE.add(identity);
      return identity;
    } catch {
      // A candidate ancestor must satisfy the whole exact package relationship.
    }
    const parent = path.dirname(directory);
    if (parent === directory) break;
    directory = parent;
  }
  throw new Error("exact installed Phala CLI and SDK package manifests are unavailable");
}

export function parseArgs(argv) {
  if (!Array.isArray(argv)) throw new Error("arguments must be an array");
  const result = {};
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === "--help") {
      if (argv.length !== 1) throw new Error("--help must be used alone");
      return { help: true };
    }
    if (typeof token !== "string" || !token.startsWith("--") || token.includes("=")) {
      throw new Error("all arguments must use separate --flag value tokens");
    }
    const flag = token.slice(2);
    const property = ARGUMENTS[flag];
    if (!property) throw new Error(`unknown flag: --${flag}`);
    if (seen.has(flag)) throw new Error(`duplicate flag: --${flag}`);
    const value = argv[index + 1];
    if (typeof value !== "string" || !value || value.startsWith("--")) {
      throw new Error(`missing value for --${flag}`);
    }
    seen.add(flag);
    result[property] = value;
    index += 1;
  }
  const missing = REQUIRED_ARGUMENTS.filter((property) => !(property in result));
  if (missing.length) throw new Error("missing required reviewed launch inputs");
  if (!CVM_LAUNCH_DOMAINS.includes(result.domain)) {
    throw new Error("--domain must be one canonical CVM launch domain");
  }
  if (!CVM_LAUNCH_SECRET_PHASES.includes(result.phase)) {
    throw new Error("--phase must be one canonical CVM launch phase");
  }
  return result;
}

export function parseStrictEnvText(text) {
  if (typeof text !== "string") throw new Error("runtime environment must be text");
  if (text.includes("\r") || text.includes("\0")) {
    throw new Error("runtime environment must use canonical UTF-8 LF records");
  }
  if (text && !text.endsWith("\n")) {
    throw new Error("runtime environment must end with one newline");
  }
  const lines = text ? text.slice(0, -1).split("\n") : [];
  const entries = [];
  const seen = new Set();
  for (const line of lines) {
    if (!line || line.startsWith("#") || line.startsWith("export ") || /^\s|\s$/.test(line)) {
      throw new Error("runtime environment contains a non-canonical record");
    }
    const equals = line.indexOf("=");
    if (equals <= 0) throw new Error("runtime environment contains a malformed record");
    const key = requireEnvironmentKey(line.slice(0, equals), "runtime environment key");
    if (seen.has(key)) throw new Error(`duplicate runtime environment key: ${key}`);
    const value = line.slice(equals + 1);
    if (!value || PLACEHOLDER_VALUE.test(value.trim())) {
      throw new Error(`runtime environment value for ${key} is empty or a placeholder`);
    }
    if (/\p{Cc}/u.test(value)) {
      throw new Error(`runtime environment value for ${key} contains a control character`);
    }
    seen.add(key);
    entries.push({ key, value });
  }
  const keys = entries.map(({ key }) => key);
  if (!exactJson(keys, [...keys].sort())) {
    throw new Error("runtime environment keys must be sorted");
  }
  return new Map(entries.map(({ key, value }) => [key, value]));
}

export function parseCanonicalKeyFileText(text, label = "environment key file") {
  if (typeof text !== "string" || text.includes("\r") || text.includes("\0")) {
    throw new Error(`${label} must be canonical UTF-8 LF text`);
  }
  if (text && !text.endsWith("\n")) {
    throw new Error(`${label} must end with one newline`);
  }
  const keys = text ? text.slice(0, -1).split("\n") : [];
  keys.forEach((key, index) => requireEnvironmentKey(key, `${label}[${index}]`));
  if (!exactJson(keys, sortedUnique(keys))) {
    throw new Error(`${label} must be sorted and duplicate-free`);
  }
  const expectedText = keys.length ? `${keys.join("\n")}\n` : "";
  if (text !== expectedText) throw new Error(`${label} is not canonical`);
  return keys;
}

export function extractComposeEnvironmentReferences(composeText) {
  if (typeof composeText !== "string") throw new Error("compose descriptor must be text");
  const values = [];
  const pattern = /\$\{([A-Z][A-Z0-9_]{0,127})(?:(?::[-+?])?[^}]*)?\}/g;
  let match;
  while ((match = pattern.exec(composeText)) !== null) values.push(match[1]);
  return sortedUnique(values);
}

function classifyComposeInterpolations(composeText) {
  const strict = new Set();
  const emptyDefault = new Set();
  const fallbackDefault = new Set();
  const pattern = /(?<!\$)\$\{([A-Z][A-Z0-9_]{0,127})([^}]*)\}/g;
  let match;
  while ((match = pattern.exec(composeText)) !== null) {
    const [, key, suffix] = match;
    if (suffix.startsWith(":?")) strict.add(key);
    else if (suffix === ":-" || suffix === "-") emptyDefault.add(key);
    else fallbackDefault.add(key);
  }
  return {
    strict: [...strict].sort(),
    emptyDefault: [...emptyDefault].sort(),
    fallbackDefault: [...fallbackDefault].sort(),
  };
}

// Compatibility spelling retained for read-only callers; semantics are strict.
export const extractComposeEnvNames = extractComposeEnvironmentReferences;

function allSecretKeys(descriptor) {
  return sortedUnique(CVM_LAUNCH_SECRET_PHASES.flatMap(
    (phase) => descriptor.encrypted_secret_environment_keys_by_phase[phase],
  ));
}

function activeEnvironmentKeys(descriptor, phase) {
  const classification = descriptor.public_environment_key_classification;
  const injectableStatic = classification.descriptor_static_keys.filter(
    (key) => descriptor.exact_allowed_environment_keys.includes(key),
  );
  const active = [
    ...injectableStatic,
    ...classification.provisioning_result_keys,
  ];
  const phaseIndex = CVM_LAUNCH_SECRET_PHASES.indexOf(phase);
  for (let index = 0; index <= phaseIndex; index += 1) {
    active.push(...descriptor.encrypted_secret_environment_keys_by_phase[
      CVM_LAUNCH_SECRET_PHASES[index]
    ]);
  }
  const domain = descriptor.trust_domain;
  const policyPhaseReached = phaseIndex
    >= CVM_LAUNCH_SECRET_PHASES.indexOf("post_measurement_policy_bootstrap");
  const finalPhaseReached = phaseIndex
    >= CVM_LAUNCH_SECRET_PHASES.indexOf("final_authority_runtime");
  if ((domain !== "main_runtime_cvm" && policyPhaseReached)
    || (domain === "main_runtime_cvm" && finalPhaseReached)) {
    active.push(...classification.post_measurement_deferred_keys);
    active.push(...classification.post_measurement_phase_control_keys);
  }
  return sortedUnique(active);
}

export function validateRuntimeEnvironmentLifecycle({
  runtimeEnv,
  descriptor,
  phase,
  launchIntentSha256,
}) {
  if (!(runtimeEnv instanceof Map)) {
    if (Array.isArray(runtimeEnv)) {
      runtimeEnv = new Map(runtimeEnv.map((entry) => [entry.key, entry.value]));
    } else {
      throw new Error("runtime environment must be a strict key/value map");
    }
  }
  if (!CVM_LAUNCH_SECRET_PHASES.includes(phase)) {
    throw new Error("runtime environment phase is invalid");
  }
  const keys = [...runtimeEnv.keys()];
  if (keys.includes("PHALA_CLOUD_API_KEY")) {
    throw new Error("PHALA_CLOUD_API_KEY must never enter a CVM runtime environment");
  }
  const expectedKeys = activeEnvironmentKeys(descriptor, phase);
  const derivedProvisioningKeys = phase === "bootstrap_provision"
    ? descriptor.public_environment_key_classification.provisioning_result_keys
    : [];
  const expectedInputKeys = expectedKeys.filter(
    (key) => !derivedProvisioningKeys.includes(key),
  );
  if (!exactJson(keys, expectedInputKeys)) {
    throw new Error("runtime environment keys do not equal the exact active lifecycle set");
  }
  for (const key of keys) {
    const value = runtimeEnv.get(key);
    if (typeof value !== "string" || !value || PLACEHOLDER_VALUE.test(value.trim())) {
      throw new Error(`runtime environment value for ${key} is not provisionable`);
    }
  }
  const commitmentKey = "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT";
  if (runtimeEnv.has(commitmentKey)) {
    if (typeof launchIntentSha256 !== "string" || !NONZERO_SHA256.test(launchIntentSha256)) {
      throw new Error("launch digest is required for the anchor-writer release commitment");
    }
    const expected = `0x${launchIntentSha256.slice("sha256:".length)}`;
    if (runtimeEnv.get(commitmentKey) !== expected) {
      throw new Error("anchor-writer release commitment does not bind the launch digest");
    }
  }
  if (phase !== "bootstrap_provision") {
    for (const key of descriptor.public_environment_key_classification.provisioning_result_keys) {
      const value = runtimeEnv.get(key);
      if (typeof value !== "string" || !value || PLACEHOLDER_VALUE.test(value.trim())) {
        throw new Error(`provisioning result ${key} must be resolved after prepare`);
      }
    }
  }
  return {
    keys: expectedKeys,
    inputKeys: expectedInputKeys,
    derivedProvisioningKeys,
    entries: expectedInputKeys.map((key) => ({ key, value: runtimeEnv.get(key) })),
    phase,
    keyNamesSha256: `sha256:${runtimeEnvKeyHash(expectedKeys)}`,
  };
}

function profilesForPhase(descriptor, phase) {
  if (phase === "bootstrap_provision") return [];
  if (descriptor.trust_domain !== "main_runtime_cvm") {
    return descriptor.launch_settings.initially_disabled_profiles.slice();
  }
  if (phase === "post_measurement_policy_bootstrap") return [];
  if (phase === "final_authority_runtime") {
    return descriptor.launch_settings.initially_disabled_profiles.filter(
      (profile) => profile !== "anchor-writer-ceremony",
    );
  }
  return descriptor.launch_settings.initially_disabled_profiles.slice();
}

function phasePlanStructuralCommitment({
  domain,
  descriptorRawBytesSha256,
  activeEnvironmentKeys,
  fromPhase,
  toPhase,
  profiles,
}) {
  // This commitment is deliberately derived only from reviewed public
  // structure.  In particular, neither rendered descriptor bytes nor runtime
  // values (or hashes of either) are inputs.  Secret-bearing rendering belongs
  // exclusively inside a future local 0600 executor boundary and must never be
  // serialized into a public plan or receipt.
  return rawSha256(Buffer.from(canonicalText({
    domain_separator:
      "dnai.phala-cvm-phase-transition-plan.structural-commitment.v1",
    active_environment_key_names: activeEnvironmentKeys,
    compose_profiles: profiles,
    descriptor_raw_bytes_sha256: descriptorRawBytesSha256,
    domain,
    from_phase: fromPhase,
    to_phase: toPhase,
  }), "utf8"));
}

export function buildReviewedPhaseTransitionPlan({
  validated,
  nextPhase,
  runtimeEnv,
}) {
  requireBrandedValidatedInput(validated);
  const currentIndex = CVM_LAUNCH_SECRET_PHASES.indexOf(validated.phase);
  const nextIndex = CVM_LAUNCH_SECRET_PHASES.indexOf(nextPhase);
  if (currentIndex < 0 || nextIndex !== currentIndex + 1) {
    throw new Error("phase transition must advance exactly one canonical phase");
  }
  const lifecycle = validateRuntimeEnvironmentLifecycle({
    runtimeEnv,
    descriptor: validated.descriptor,
    phase: nextPhase,
    launchIntentSha256: validated.launchSha256,
  });
  const profiles = profilesForPhase(validated.descriptor, nextPhase);
  const expectedProfileValue = profiles.join(",");
  const controls = validated.descriptor.public_environment_key_classification
    .post_measurement_phase_control_keys;
  if (controls.includes("COMPOSE_PROFILES")) {
    const active = lifecycle.keys.includes("COMPOSE_PROFILES");
    if (active && runtimeEnv.get("COMPOSE_PROFILES") !== expectedProfileValue) {
      throw new Error("COMPOSE_PROFILES does not equal the exact reviewed phase profile set");
    }
    if (!active && runtimeEnv.has("COMPOSE_PROFILES")) {
      throw new Error("COMPOSE_PROFILES is premature for this phase");
    }
  }
  const structuralCommitment = phasePlanStructuralCommitment({
    domain: validated.domain,
    descriptorRawBytesSha256: validated.descriptor.descriptor_sha256,
    activeEnvironmentKeys: lifecycle.keys,
    fromPhase: validated.phase,
    toPhase: nextPhase,
    profiles,
  });
  return deepFreeze({
    schema: "dnai.phala-cvm-phase-transition-plan.v1",
    status: "validated_key_lifecycle_plan_only_service_start_forbidden",
    truth_status:
      "phase_key_lifecycle_and_non_secret_structure_only_runtime_values_not_review_bound_or_authorized",
    domain: validated.domain,
    from_phase: validated.phase,
    to_phase: nextPhase,
    compose_profiles: profiles,
    descriptor_raw_bytes_sha256: validated.descriptor.descriptor_sha256,
    public_structural_commitment_sha256: structuralCommitment,
    active_environment_key_names_sha256:
      `sha256:${runtimeEnvKeyHash(lifecycle.keys)}`,
    active_environment_key_count: lifecycle.keys.length,
    environment_values_in_plan: false,
    environment_value_hashes_in_plan: false,
    runtime_value_authority_bound: false,
    static_public_environment_authority_projection_bound: false,
    deferred_public_environment_final_authority_projection_bound: false,
    execution_blocker_codes: [...PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES],
    service_start_authorized: false,
    phala_api_called: false,
  });
}

export function validateComposeEnvironmentContract({
  composeText,
  runtimeEnv,
  descriptor,
}) {
  const references = extractComposeEnvironmentReferences(composeText);
  if (references.includes("PHALA_CLOUD_API_KEY")) {
    throw new Error("compose descriptor references the Phala control-plane credential");
  }
  const classification = descriptor.public_environment_key_classification;
  const expectedReferences = sortedUnique([
    ...descriptor.exact_allowed_environment_keys.filter(
      (key) => !classification.post_measurement_phase_control_keys.includes(key),
    ),
    ...classification.descriptor_defaulted_keys,
  ]);
  if (!exactJson(references, expectedReferences)) {
    throw new Error("compose environment references do not equal the reviewed descriptor contract");
  }
  const interpolation = classifyComposeInterpolations(composeText);
  const strictInputs = sortedUnique([
    ...descriptor.encrypted_secret_environment_keys_by_phase.bootstrap_provision,
    ...classification.provisioning_result_keys,
  ]);
  const lateInputs = sortedUnique([
    ...classification.post_measurement_deferred_keys,
    ...CVM_LAUNCH_SECRET_PHASES
      .filter((phase) => phase !== "bootstrap_provision")
      .flatMap((phase) => descriptor.encrypted_secret_environment_keys_by_phase[phase]),
  ]);
  if (strictInputs.some((key) => !interpolation.strict.includes(key)
      || interpolation.emptyDefault.includes(key)
      || interpolation.fallbackDefault.includes(key))) {
    throw new Error("bootstrap and derived provisioning inputs must use only ${KEY:?}");
  }
  if (lateInputs.some((key) => !interpolation.emptyDefault.includes(key)
      || interpolation.strict.includes(key)
      || interpolation.fallbackDefault.includes(key))) {
    throw new Error("late profile inputs must use only exact empty ${KEY:-} fallback");
  }
  for (const profile of descriptor.launch_settings.initially_disabled_profiles) {
    if (!composeText.includes(profile)) {
      throw new Error(`compose descriptor omits reviewed disabled profile ${profile}`);
    }
  }
  const runtimeKeys = runtimeEnv instanceof Map
    ? [...runtimeEnv.keys()]
    : runtimeEnv.map((entry) => entry.key);
  if (runtimeKeys.some((key) => !descriptor.exact_allowed_environment_keys.includes(key))) {
    throw new Error("runtime environment contains a key outside exact_allowed_environment_keys");
  }
  return { references, expectedReferences };
}

export function runtimeEnvKeyHash(envEntriesOrKeys) {
  const keys = envEntriesOrKeys instanceof Map
    ? [...envEntriesOrKeys.keys()]
    : envEntriesOrKeys.map((entry) => (
      typeof entry === "string" ? entry : entry.key
    ));
  keys.forEach((key, index) => requireEnvironmentKey(key, `runtime key[${index}]`));
  const normalized = sortedUnique(keys);
  if (normalized.length !== keys.length) {
    throw new Error("runtime environment keys must be duplicate-free");
  }
  return createHash("sha256")
    .update(Buffer.from("dnai-wikigen/phala-runtime-environment-key-names/v1\0", "utf8"))
    .update(Buffer.from(normalized.length ? `${normalized.join("\n")}\n` : "", "utf8"))
    .digest("hex");
}

function exactKeyFileBindings(descriptor) {
  const classification = descriptor.public_environment_key_classification;
  return {
    descriptorStaticKeys: classification.descriptor_static_keys,
    descriptorDefaultedKeys: classification.descriptor_defaulted_keys,
    provisioningResultKeys: classification.provisioning_result_keys,
    postMeasurementDeferredKeys: classification.post_measurement_deferred_keys,
    postMeasurementPhaseControlKeys: classification.post_measurement_phase_control_keys,
    encryptedSecretKeys: allSecretKeys(descriptor),
  };
}

function validateStoredReadinessEvidence(snapshot, launch, checkedAtMs) {
  const launchSha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  const descriptorHashes = Object.fromEntries(
    launch.descriptors.map((descriptor) => [
      descriptor.trust_domain,
      descriptor.descriptor_sha256,
    ]),
  );
  // activation-preflight's historical field name denotes the separately
  // reviewed Stage 2 live-activation authority. A pre-Phala cvm_launch
  // snapshot must prove that later authority does not exist yet.
  if (snapshot.stage !== "cvm_launch"
    || snapshot.release_sha !== launch.release_sha
    || snapshot.deployment_intent_sha256 !== launch.deployment_intent_sha256
    || snapshot.contract_deployment_receipt_sha256
      !== launch.contract_deployment_receipt_sha256
    || snapshot.cvm_launch_intent_sha256 !== launchSha256
    || snapshot.final_authority_sha256 !== null
    || !exactJson(snapshot.descriptor_raw_bytes_sha256_by_domain, descriptorHashes)
    || !exactJson(
      snapshot.authorized_next_actions,
      ACTIVATION_READINESS_AUTHORIZED_ACTIONS.cvm_launch,
    )
    || !exactJson(
      snapshot.execution_boundary,
      ACTIVATION_READINESS_EXECUTION_BOUNDARY.cvm_launch,
    )) {
    throw new Error("readiness evidence does not bind the reviewed CVM launch");
  }
  const checked = Date.parse(snapshot.checked_at);
  const expires = Date.parse(snapshot.expires_at);
  if (!Number.isSafeInteger(checkedAtMs)
    || checked > checkedAtMs + 5_000
    || checkedAtMs >= expires
    || checkedAtMs - checked > ACTIVATION_READINESS_MAX_LIFETIME_MS) {
    throw new Error("readiness evidence is stale or not yet valid");
  }
  return snapshot;
}

async function parseCanonicalJsonFile(file, normalizer, label) {
  let parsed;
  try {
    parsed = JSON.parse(file.text);
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
  const normalized = normalizer(parsed);
  if (file.text !== canonicalText(normalized)) {
    throw new Error(`${label} must use sorted two-space JSON with one trailing newline`);
  }
  return normalized;
}

export async function validateLaunchInputsFromFiles(args, {
  checkedAtMs = Date.now(),
  allowExpiredStoredReadinessForAuthorityRecheck = false,
} = {}) {
  if (!args || args.help) throw new Error("reviewed launch inputs are required");
  if (!CVM_LAUNCH_DOMAINS.includes(args.domain)
    || !CVM_LAUNCH_SECRET_PHASES.includes(args.phase)) {
    throw new Error("domain or phase is not canonical");
  }
  const keyFileProperties = [
    "descriptorStaticKeys",
    "descriptorDefaultedKeys",
    "provisioningResultKeys",
    "postMeasurementDeferredKeys",
    "postMeasurementPhaseControlKeys",
    "encryptedSecretKeys",
  ];
  const [
    deploymentIntentFile,
    contractDeploymentReceiptFile,
    launchFile,
    launchReceiptFile,
    reviewEnvelopeFile,
    reviewEvidenceFile,
    readinessEvidenceFile,
    composeFile,
    runtimeEnvFile,
    ...keyFiles
  ] = await Promise.all([
    readStableBoundedFile(args.deploymentIntent, {
      label: "deployment intent", maxBytes: FILE_LIMITS.deploymentIntent, minBytes: 1,
    }),
    readStableBoundedFile(args.contractDeploymentReceipt, {
      label: "fresh-contract deployment receipt",
      maxBytes: FILE_LIMITS.contractDeploymentReceipt,
      minBytes: 1,
    }),
    readStableBoundedFile(args.launchIntent, {
      label: "launch intent", maxBytes: FILE_LIMITS.launchIntent, minBytes: 1,
    }),
    readStableBoundedFile(args.launchIntentReceipt, {
      label: "launch intent receipt", maxBytes: FILE_LIMITS.launchIntentReceipt, minBytes: 1,
    }),
    readStableBoundedFile(args.reviewEnvelope, {
      label: "review envelope", maxBytes: FILE_LIMITS.reviewEnvelope, minBytes: 1,
    }),
    readStableBoundedFile(args.reviewEvidence, {
      label: "review evidence", maxBytes: FILE_LIMITS.reviewEvidence, minBytes: 1,
    }),
    readStableBoundedFile(args.readinessEvidence, {
      label: "readiness evidence", maxBytes: FILE_LIMITS.readinessEvidence, minBytes: 1,
    }),
    readStableBoundedFile(args.compose, {
      label: "compose descriptor", maxBytes: FILE_LIMITS.compose, minBytes: 1,
    }),
    readStableBoundedFile(args.runtimeEnv, {
      label: "runtime environment", maxBytes: FILE_LIMITS.runtimeEnv, minBytes: 0,
      requireMode0600: true,
    }),
    ...keyFileProperties.map((property) => readStableBoundedFile(args[property], {
      label: property, maxBytes: FILE_LIMITS.keyFile, minBytes: 0,
    })),
  ]);

  const launch = parseCvmLaunchIntentCoreText(launchFile.text);
  if (launchFile.text !== canonicalCvmLaunchIntentCoreArtifactText(launch)) {
    throw new Error("launch intent canonical bytes changed during validation");
  }
  const launchSha256 = `sha256:${cvmLaunchIntentCoreDigest(launch)}`;
  const descriptor = launch.descriptors.find(
    (entry) => entry.trust_domain === args.domain,
  );
  if (!descriptor) throw new Error("selected launch descriptor is missing");
  if (path.basename(composeFile.path) !== descriptor.descriptor_file
    || composeFile.sha256 !== descriptor.descriptor_sha256) {
    throw new Error("compose descriptor filename or raw bytes do not match the launch intent");
  }

  const expectedLaunchReceipt = cvmLaunchIntentValidationReceipt(launch);
  const expectedLaunchReceiptText = `${JSON.stringify(expectedLaunchReceipt, null, 2)}\n`;
  if (launchReceiptFile.text !== expectedLaunchReceiptText) {
    throw new Error("launch validation receipt is not the exact canonical receipt");
  }

  const parsedDeploymentIntent = parseDeploymentIntentCoreText(deploymentIntentFile.text);
  if (!parsedDeploymentIntent.ok) {
    throw new Error("deployment intent dependency is not canonical or valid");
  }
  const parsedContractReceipt = parseFreshContractDeploymentReceiptText(
    contractDeploymentReceiptFile.text,
    {
      expectedDeploymentIntentSha256:
        parsedDeploymentIntent.receipt.deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        parsedDeploymentIntent.intent.release
          .reviewerAuthorityGenesisAcceptanceSha256,
    },
  );
  if (!parsedContractReceipt.ok) {
    throw new Error("fresh-contract deployment receipt dependency is not canonical or valid");
  }

  const subjectDescriptor = describeAuthorityReviewSubjectText(launchFile.text);
  if (!subjectDescriptor.ok) throw new Error("launch intent is not a reviewable subject");
  const parsedReview = parseAuthorityReviewEnvelopeText(reviewEnvelopeFile.text, {
    subjectDescriptor,
    checkedAtMs,
    authorityDependencies: {
      deploymentIntent: parsedDeploymentIntent.intent,
      freshContractDeploymentReceipt: parsedContractReceipt.receipt,
    },
  });
  if (!parsedReview.ok) throw new Error("review envelope does not authorize the launch intent");
  if (reviewEvidenceFile.sha256 !== parsedReview.receipt.reviewEvidenceSha256) {
    throw new Error("review evidence bytes do not match the review envelope");
  }

  const readinessEvidence = await parseCanonicalJsonFile(
    readinessEvidenceFile,
    normalizeActivationReadinessSnapshot,
    "readiness evidence",
  );
  validateStoredReadinessEvidence(
    readinessEvidence,
    launch,
    allowExpiredStoredReadinessForAuthorityRecheck
      ? Date.parse(readinessEvidence.checked_at)
      : checkedAtMs,
  );

  const expectedKeyBindings = exactKeyFileBindings(descriptor);
  const parsedKeyBindings = {};
  const keyFileSha256 = {};
  for (let index = 0; index < keyFileProperties.length; index += 1) {
    const property = keyFileProperties[index];
    parsedKeyBindings[property] = parseCanonicalKeyFileText(
      keyFiles[index].text,
      property,
    );
    keyFileSha256[property] = keyFiles[index].sha256;
    if (!exactJson(parsedKeyBindings[property], expectedKeyBindings[property])) {
      throw new Error(`${property} does not equal the reviewed classification`);
    }
  }

  const runtimeEnv = parseStrictEnvText(runtimeEnvFile.text);
  const lifecycle = validateRuntimeEnvironmentLifecycle({
    runtimeEnv,
    descriptor,
    phase: args.phase,
    launchIntentSha256: launchSha256,
  });
  validateComposeEnvironmentContract({
    composeText: composeFile.text,
    runtimeEnv,
    descriptor,
  });

  const validated = {
    domain: args.domain,
    phase: args.phase,
    launch,
    launchSha256,
    deploymentIntent: parsedDeploymentIntent.intent,
    deploymentIntentSha256: canonicalArtifactSha256(parsedDeploymentIntent.intent),
    freshContractDeploymentReceipt: parsedContractReceipt.receipt,
    freshContractDeploymentReceiptSha256: parsedContractReceipt.receiptSha256,
    descriptor,
    descriptorFile: composeFile,
    runtimeEntries: lifecycle.entries,
    activeEnvironmentKeys: lifecycle.keys,
    launchReceipt: expectedLaunchReceipt,
    launchReceiptSha256: launchReceiptFile.sha256,
    reviewReceipt: parsedReview.receipt,
    reviewEnvelopeSha256: canonicalArtifactSha256(parsedReview.envelope),
    reviewEvidenceSha256: reviewEvidenceFile.sha256,
    readinessEvidence,
    readinessEvidenceSha256:
      `sha256:${activationReadinessSnapshotDigest(readinessEvidence)}`,
    keyFileSha256,
    paths: Object.freeze({
      compose: composeFile.path,
      runtimeEnv: runtimeEnvFile.path,
    }),
  };
  deepFreeze(validated);
  VALIDATED_INPUT_STATE.set(validated, Object.freeze({
    sourceArgs: Object.freeze(Object.fromEntries(
      REQUIRED_ARGUMENTS.map((property) => [property, args[property]]),
    )),
    runtimeEnvText: runtimeEnvFile.text,
    runtimeEnvIdentity: runtimeEnvFile.identity,
    reviewEnvelopeText: reviewEnvelopeFile.text,
    reviewExpiresAtMs: Date.parse(parsedReview.envelope.expires_at),
  }));
  return validated;
}

function whitelistedComposeMetadata(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return {};
  const result = {};
  if (typeof input.name === "string") result.name = input.name;
  if (Number.isSafeInteger(input.manifest_version)) {
    result.manifest_version = input.manifest_version;
  }
  if (input.kms_enabled === true) result.kms_enabled = true;
  if (input.gateway_enabled === true) result.gateway_enabled = true;
  if (input.storage_fs === "ext4" || input.storage_fs === "zfs") {
    result.storage_fs = input.storage_fs;
  }
  return result;
}

export function buildHardenedAppCompose(
  reviewedMetadata,
  composeText,
  envEntriesOrKeys,
) {
  if (typeof composeText !== "string"
    || Buffer.byteLength(composeText, "utf8") < 1
    || Buffer.byteLength(composeText, "utf8") > FILE_LIMITS.compose) {
    throw new Error("compose descriptor is empty or over 200 KiB");
  }
  const keys = envEntriesOrKeys.map((entry) => (
    typeof entry === "string" ? entry : entry.key
  ));
  keys.forEach((key, index) => requireEnvironmentKey(key, `allowed_envs[${index}]`));
  if (!exactJson(keys, sortedUnique(keys))) {
    throw new Error("allowed_envs must be sorted and duplicate-free");
  }
  return {
    ...whitelistedComposeMetadata(reviewedMetadata),
    docker_compose_file: composeText,
    allowed_envs: [...keys],
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  };
}

export function assertProductionCvmInfo(cvmInfo, {
  appId,
  composeHash,
} = {}) {
  if (cvmInfo?.os?.is_dev !== false
    || cvmInfo?.listed !== false
    || cvmInfo?.public_logs !== false
    || cvmInfo?.public_sysinfo !== false
    || cvmInfo?.public_tcbinfo !== false) {
    throw new Error("created CVM does not satisfy the complete production privacy posture");
  }
  const kmsType = String(cvmInfo?.kms_type ?? cvmInfo?.kms_info?.slug ?? "").toLowerCase();
  if (kmsType !== "phala") throw new Error("created CVM is not using Phala KMS");
  if (appId !== undefined && cvmInfo.app_id !== appId) {
    throw new Error("created CVM app id differs from the prepared identity");
  }
  const reportedComposeHash = cvmInfo.compose_hash ?? cvmInfo.app_compose_hash;
  if (composeHash !== undefined && reportedComposeHash !== composeHash) {
    throw new Error("created CVM compose hash differs from the prepared hash");
  }
  return cvmInfo;
}

function secretFreePlanReceipt(validated) {
  const secretKeys = allSecretKeys(validated.descriptor);
  return {
    schema: PHALA_CVM_LAUNCH_RECEIPT_SCHEMA,
    status: "validated_fresh_create_plan_not_executed",
    truth_status:
      "reviewed_plan_only_not_phala_provision_commit_tdx_quote_or_runtime_measurement",
    domain: validated.domain,
    phase: validated.phase,
    deployment_intent_sha256: validated.deploymentIntentSha256,
    contract_deployment_receipt_sha256:
      validated.freshContractDeploymentReceiptSha256,
    launch_intent_sha256: validated.launchSha256,
    launch_validation_receipt_sha256: validated.launchReceiptSha256,
    review_envelope_sha256: validated.reviewEnvelopeSha256,
    review_evidence_sha256: validated.reviewEvidenceSha256,
    readiness_evidence_sha256: validated.readinessEvidenceSha256,
    descriptor_raw_bytes_sha256: validated.descriptor.descriptor_sha256,
    classification_key_file_sha256: { ...validated.keyFileSha256 },
    exact_allowed_environment_keys_sha256:
      validated.descriptor.exact_allowed_environment_keys_sha256,
    exact_allowed_environment_key_count:
      validated.descriptor.exact_allowed_environment_keys.length,
    active_environment_key_names_sha256:
      `sha256:${runtimeEnvKeyHash(validated.activeEnvironmentKeys)}`,
    active_environment_key_count: validated.activeEnvironmentKeys.length,
    encrypted_secret_environment_key_name_count: secretKeys.length,
    phala_cli_version: PHALA_CLI_VERSION,
    phala_cloud_sdk_version: PHALA_CLOUD_SDK_VERSION,
    phala_cloud_api_origin: PHALA_CLOUD_API_ORIGIN,
    phala_cloud_api_version: PHALA_CLOUD_API_VERSION,
    phala_workspace_account_target_bound: false,
    phala_sdk_debug_secret_logging_guard_complete: false,
    phala_sdk_wire_transform_capture_complete: false,
    phala_provision_request_final_authority_complete: false,
    phala_os_image: validated.descriptor.launch_settings.phala_os_image,
    phala_os_image_hash:
      validated.descriptor.launch_settings.phala_os_image_hash,
    phala_os_image_catalog_entry_sha256:
      validated.descriptor.launch_settings.phala_os_image_catalog_entry_sha256,
    production_execution_available: false,
    production_execution_blocker_codes:
      [...PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES],
    runtime_value_authority_bound: false,
    fresh_cli_deploy_forbidden: true,
    command_executed: false,
    phala_api_called: false,
    remote_state_mutated: false,
    secret_values_in_receipt: false,
    ciphertext_in_receipt: false,
  };
}

export function canonicalPhalaCvmLaunchReceiptText(receipt) {
  if (!receipt || typeof receipt !== "object" || Array.isArray(receipt)
    || receipt.schema !== PHALA_CVM_LAUNCH_RECEIPT_SCHEMA) {
    throw new Error("Phala CVM launch receipt schema is invalid");
  }
  const planFields = [
    "schema", "status", "truth_status", "domain", "phase",
    "deployment_intent_sha256", "contract_deployment_receipt_sha256",
    "launch_intent_sha256", "launch_validation_receipt_sha256",
    "review_envelope_sha256", "review_evidence_sha256",
    "readiness_evidence_sha256", "descriptor_raw_bytes_sha256",
    "classification_key_file_sha256", "exact_allowed_environment_keys_sha256",
    "exact_allowed_environment_key_count", "active_environment_key_names_sha256",
    "active_environment_key_count", "encrypted_secret_environment_key_name_count",
    "phala_cli_version", "phala_cloud_sdk_version", "phala_cloud_api_origin",
    "phala_cloud_api_version",
    "phala_workspace_account_target_bound",
    "phala_sdk_debug_secret_logging_guard_complete",
    "phala_sdk_wire_transform_capture_complete",
    "phala_provision_request_final_authority_complete",
    "phala_os_image", "phala_os_image_hash",
    "phala_os_image_catalog_entry_sha256",
    "production_execution_available", "production_execution_blocker_codes",
    "runtime_value_authority_bound",
    "fresh_cli_deploy_forbidden", "command_executed", "phala_api_called",
    "remote_state_mutated", "secret_values_in_receipt", "ciphertext_in_receipt",
  ];
  const expectedFields = receipt.status === "validated_fresh_create_plan_not_executed"
    ? planFields
    : null;
  if (!expectedFields
    || !exactJson(Object.keys(receipt).sort(), [...expectedFields].sort())
    || !CVM_LAUNCH_DOMAINS.includes(receipt.domain)) {
    throw new Error("Phala CVM launch receipt fields or status are invalid");
  }
  const hashFields = expectedFields.filter((field) => (
    field.endsWith("_sha256") && field !== "classification_key_file_sha256"
  ));
  if (hashFields.some((field) => !NONZERO_SHA256.test(receipt[field]))) {
    throw new Error("Phala CVM launch receipt contains an invalid digest");
  }
  if (receipt.secret_values_in_receipt !== false
    || receipt.ciphertext_in_receipt !== false) {
    throw new Error("Phala CVM launch receipt must be secret-free");
  }
  if (receipt.status === "validated_fresh_create_plan_not_executed") {
    const keyHashFields = [
      "descriptorStaticKeys",
      "descriptorDefaultedKeys",
      "provisioningResultKeys",
      "postMeasurementDeferredKeys",
      "postMeasurementPhaseControlKeys",
      "encryptedSecretKeys",
    ];
    if (!CVM_LAUNCH_SECRET_PHASES.includes(receipt.phase)
      || !receipt.classification_key_file_sha256
      || !exactJson(
        Object.keys(receipt.classification_key_file_sha256).sort(),
        [...keyHashFields].sort(),
      )
      || keyHashFields.some(
        (field) => !NONZERO_SHA256.test(receipt.classification_key_file_sha256[field]),
      )
      || receipt.phala_cli_version !== PHALA_CLI_VERSION
      || receipt.phala_cloud_sdk_version !== PHALA_CLOUD_SDK_VERSION
      || receipt.phala_cloud_api_origin !== PHALA_CLOUD_API_ORIGIN
      || receipt.phala_cloud_api_version !== PHALA_CLOUD_API_VERSION
      || receipt.phala_workspace_account_target_bound !== false
      || receipt.phala_sdk_debug_secret_logging_guard_complete !== false
      || receipt.phala_sdk_wire_transform_capture_complete !== false
      || receipt.phala_provision_request_final_authority_complete !== false
      || receipt.phala_os_image !== PHALA_OS_IMAGE_CATALOG_ENTRY.name
      || receipt.phala_os_image_hash !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
      || receipt.production_execution_available !== false
      || !exactJson(
        receipt.production_execution_blocker_codes,
        PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES,
      )
      || receipt.runtime_value_authority_bound !== false
      || receipt.fresh_cli_deploy_forbidden !== true
      || receipt.command_executed !== false
      || receipt.phala_api_called !== false
      || receipt.remote_state_mutated !== false) {
      throw new Error("Phala plan receipt weakens the reviewed no-mutation boundary");
    }
  }
  return canonicalText(receipt);
}

function sealedFutureAuthorityDependencyReceipt() {
  const dependencies = [
    ["readReverifyDescriptorSetAndCheckpointPhalaBootstrap",
      readReverifyDescriptorSetAndCheckpointPhalaBootstrap],
    ["assertTrackedDescriptorMaterializationSources",
      assertTrackedDescriptorMaterializationSources],
    ["validateCanonicalGeneratedCvmDescriptorSet",
      validateCanonicalGeneratedCvmDescriptorSet],
    ["verifyExactTrackedSourceDescriptorReproduction",
      verifyExactTrackedSourceDescriptorReproduction],
  ];
  if (dependencies.some(([, dependency]) => typeof dependency !== "function")
    || !exactJson(PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS, [
      "before_prediction",
      "before_each_prepare",
      "before_each_provision",
      "before_each_commit",
    ])) {
    throw new Error("sealed bootstrap authority dependencies are not exact");
  }
  return Object.freeze({
    schema: "dnai.phala-future-sealed-authority-dependencies.v1",
    status: "linked_not_invoked_execution_still_disabled",
    bootstrap_authorization_receipt_schema:
      PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    descriptor_set_receipt_schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    stable_file_recheck_checkpoints: [
      ...PHALA_NONLIVE_BOOTSTRAP_RECHECK_CHECKPOINTS,
    ],
    dependencies: dependencies.map(([name]) => name),
    independently_anchored_reviewer_genesis_required: true,
    exact_clean_ci_seven_descriptor_set_required: true,
    exact_target_compatibility_wire_staging_stable_reread_required: true,
    fresh_contract_anchor_receipt_required: true,
    production_sigstore_receipt_rerun_required: true,
    dependency_invoked: false,
    phala_sdk_imported: false,
    network_call_performed: false,
    remote_state_mutated: false,
  });
}

export function buildFreshCreateCommandPlan(validated, {
  installedPackageIdentity,
} = {}) {
  requireBrandedValidatedInput(validated);
  if (!installedPackageIdentity
    || !INSTALLED_PACKAGE_IDENTITY_STATE.has(installedPackageIdentity)
    || !exactJson(Object.keys(installedPackageIdentity).sort(), [
      "cli", "schema", "sdk", "source",
    ])
    || installedPackageIdentity.schema
      !== "dnai.phala-installed-package-identity.v1"
    || installedPackageIdentity.source
      !== "installed_package_manifests_no_executable_probe"
    || !exactJson(Object.keys(installedPackageIdentity.cli ?? {}).sort(), [
      "manifest_sha256", "name", "version",
    ])
    || installedPackageIdentity.cli.name !== "phala"
    || installedPackageIdentity.cli.version !== PHALA_CLI_PACKAGE_VERSION
    || !NONZERO_SHA256.test(installedPackageIdentity.cli.manifest_sha256)
    || !exactJson(Object.keys(installedPackageIdentity.sdk ?? {}).sort(), [
      "manifest_sha256", "name", "version",
    ])
    || installedPackageIdentity.sdk.name !== "@phala/cloud"
    || installedPackageIdentity.sdk.version !== PHALA_CLOUD_SDK_VERSION
    || !NONZERO_SHA256.test(installedPackageIdentity.sdk.manifest_sha256)) {
    throw new Error("exact installed Phala package-manifest identity is required");
  }
  if (validated.descriptor.launch_settings.phala_cli_version !== PHALA_CLI_VERSION
    || validated.descriptor.launch_settings.phala_cloud_sdk_version
      !== PHALA_CLOUD_SDK_VERSION
    || validated.descriptor.launch_settings.phala_os_image
      !== PHALA_OS_IMAGE_CATALOG_ENTRY.name
    || validated.descriptor.launch_settings.phala_os_image_hash
      !== PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash
    || validated.descriptor.launch_settings.phala_os_image_catalog_entry_sha256
      !== phalaOsImageCatalogEntryDigest(PHALA_OS_IMAGE_CATALOG_ENTRY)
    || validated.descriptor.launch_settings.fresh_cli_deploy_forbidden !== true
    || validated.descriptor.launch_settings.provisioning_api
      !== "provisionCvm_validate_all_seven_then_commitCvmProvision") {
    throw new Error("launch intent does not contain the exact safe Phala execution policy");
  }
  const receipt = secretFreePlanReceipt(validated);
  const sealedAuthorityDependencies = sealedFutureAuthorityDependencyReceipt();
  return {
    schema: PHALA_FRESH_CREATE_COMMAND_PLAN_SCHEMA,
    status: "validated_plan_only_no_external_call",
    truth_status:
      "non_executable_secret_free_plan_not_phala_or_tdx_evidence",
    domain: validated.domain,
    phase: validated.phase,
    application_name: validated.descriptor.app_compose_candidate.name,
    cli: {
      launch_intent_pinned_build_identity: PHALA_CLI_VERSION,
      installed_package_version: PHALA_CLI_PACKAGE_VERSION,
      installed_package_manifest_sha256:
        installedPackageIdentity.cli.manifest_sha256,
      role: "diagnostic_compatibility_only",
      identity_source: installedPackageIdentity.source,
      installed_manifest_proves_build_suffix: false,
      executable_version_probe_argv: null,
      executable_probe_used: false,
      deploy_argv: null,
      fresh_deploy_forbidden: true,
      prepare_only_is_not_safe_for_fresh_create: true,
    },
    sdk: {
      package: "@phala/cloud",
      exact_version: PHALA_CLOUD_SDK_VERSION,
      installed_package_manifest_sha256:
        installedPackageIdentity.sdk.manifest_sha256,
      api_origin: PHALA_CLOUD_API_ORIGIN,
      api_version: PHALA_CLOUD_API_VERSION,
      redirects_allowed: false,
      origin_drift_allowed: false,
      phala_cloud_api_prefix_environment_override_allowed: false,
      wire_transform_authority: structuredClone(
        validated.launch.phala_cloud_sdk_wire_transform_authority,
      ),
      sealed_authority_dependencies: sealedAuthorityDependencies,
      proposed_future_sequence_not_executable: [
        ...PHALA_FUTURE_SEALED_AUTHORITY_SEQUENCE,
      ],
    },
    production_execution: {
      available: false,
      reason_code: PHALA_PRODUCTION_EXECUTION_DISABLED_CODE,
      blocker_codes: [...PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES],
      bootstrap_blocker_codes: [
        ...PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
      ],
      caller_supplied_callbacks_accepted: false,
      caller_supplied_clients_accepted: false,
      test_harness_present_in_production_module: false,
      seven_commit_batch_is_atomic: false,
      automatic_cleanup_authorized: false,
    },
    all_seven_domains_required_for_execution: [...CVM_LAUNCH_DOMAINS],
    launch_receipt: receipt,
  };
}

export async function executeReviewedFreshCvmBatch() {
  throw new Error(
    `${PHALA_PRODUCTION_EXECUTION_DISABLED_CODE}:`
      + PHALA_PRODUCTION_EXECUTION_BLOCKER_CODES.join(","),
  );
}

export const executeReviewedPostCreateCommit = executeReviewedFreshCvmBatch;

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  if (args.help) {
    usage();
    return;
  }
  const validated = await validateLaunchInputsFromFiles(args);
  const installedPackageIdentity = await inspectInstalledPhalaPackageIdentity();
  const plan = buildFreshCreateCommandPlan(validated, {
    installedPackageIdentity,
  });
  process.stdout.write(canonicalText(plan));
}

if (import.meta.url === pathToFileURL(process.argv[1] || "").href) {
  main().catch((error) => {
    console.error(`Phala launch plan blocked: ${boundedMessage(error)}`);
    process.exitCode = 1;
  });
}
