#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, http } from "viem";
import {
  BASE_SEPOLIA_CHAIN_ID,
  CANONICAL_PUBLIC_RPC,
  buildReleaseEnv,
  canonicalPreLiveActivationReleaseCandidateText,
  githubAttestationCommands,
  liveReleaseCandidatePrebuildProjectionSha256,
  normalizeReleaseCandidate,
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
  serializeEnv,
} from "./release-env-core.mjs";
import {
  validateExecutionPolicyReleaseCoreBinding,
} from "./execution-policy-release-core-binding.mjs";
import {
  readCanonicalExecutionPolicyReleaseCoreArtifact,
} from "../../scripts/execution-policy-release-core-cli.mjs";
import {
  MAX_PACKET_BYTES,
  parseDeploymentIntentCoreText,
} from "../../scripts/operator-policy-packet-core.mjs";
import {
  exactDistinctPublicHttpsEndpoints,
} from "./public-https-origin-core.mjs";
import { durablyWritePrivateFile } from "./durable-private-file-core.mjs";
import { PINNED_GH_TOOL } from "../../scripts/release-manifest-sigstore-verifier.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "../../scripts/phala-seven-cvm-historical-transcript.mjs";
import {
  FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS,
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS,
  createFrontendBuildPreDPrivateInputs,
} from "./frontend-build-candidate-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rootDir = path.resolve(webDir, "..");
const defaultOutput = path.join(webDir, ".env.production.local");
const PINNED_GIT_EXECUTABLE = "/usr/bin/git";
const PINNED_GIT_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
});
export const SEMANTIC_VALIDATOR_INPUT_FLAGS = Object.freeze([
  "--release",
  "--release-core",
  "--runtime-authority-dependency",
  "--deployment-intent",
  "--contract-receipt",
  "--reviewer-authority-genesis",
  "--reviewer-authority-genesis-acceptance",
  "--bootstrap-authority",
  "--bootstrap-authorization",
  "--bootstrap-authorization-receipt",
  "--seven-cvm-launch-completion-receipt",
  "--main-runtime-qvl-challenge",
  "--main-runtime-independent-tdx-verdict",
  "--diligence-qvl-identity-request",
  "--diligence-qvl-identity-response",
  "--arena-qvl-identity-request",
  "--arena-qvl-identity-response",
  "--anchor-writer-qvl-identity-request",
  "--anchor-writer-qvl-identity-response",
  "--compute-workload-qvl-identity-request",
  "--compute-workload-qvl-identity-response",
  "--compute-metering-qvl-identity-request",
  "--compute-metering-qvl-identity-response",
  "--independent-metering-qvl-challenge",
  "--independent-metering-independent-tdx-verdict",
  "--image-release-sigstore-verification-receipt",
  "--cvm-descriptor-set-receipt",
  "--phala-executor-final-state",
  "--ceremony-authorization",
  "--ledger",
  "--artifact-evidence",
  "--arena-evidence",
  "--anchor-writer-evidence",
  "--email-oracle-evidence",
  "--live-activation-authority",
  "--compute-workload-activation-observation",
  "--frontend-build-candidate-receipt",
]);
export const PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS = Object.freeze([
  ...FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
]);
const SEMANTIC_VALIDATOR_INPUT_FLAG_SET = new Set(
  SEMANTIC_VALIDATOR_INPUT_FLAGS,
);
const PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAG_SET = new Set(
  PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS,
);
const expectedPreDPrivateInputFlags = SEMANTIC_VALIDATOR_INPUT_FLAGS.filter(
  (flag) => !FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS.includes(flag),
);
if (JSON.stringify(expectedPreDPrivateInputFlags)
  !== JSON.stringify(FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS)) {
  throw new Error("semantic validator and frontend D pre-input flag recipes drifted");
}
const SEMANTIC_VALIDATOR_MAX_INPUT_BYTES = 4 * 1024 * 1024;
const SEMANTIC_VALIDATOR_MAX_TOTAL_BYTES = 32 * 1024 * 1024;
export const SEMANTIC_VALIDATOR_WRAPPER_FLAGS = Object.freeze([
  "--check-only",
]);
export {
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
};

/* Retired while the exact-37 Model-A handoff is fail-closed.
  console.error([
    "Usage:",
    "  TRUSTED_ATTESTATION_VERIFIER_ADDRESSES=0x<diligence-qvl>,0x<arena-qvl>,0x<anchor-writer-qvl>,0x<compute-workload-qvl>,0x<compute-metering-qvl> \\",
    "  BASE_SEPOLIA_RPC_URL=https://... \\",
    "  BASE_SEPOLIA_SECONDARY_RPC_URL=https://... \\",
    "  node scripts/build-release-env.mjs [--check-only] \\",
    ...SEMANTIC_VALIDATOR_INPUT_FLAGS.map((flag, index) => (
      `    ${flag} /absolute/private/path/${flag.slice(2)}.json${
        index === SEMANTIC_VALIDATOR_INPUT_FLAGS.length - 1 ? "" : " \u005c"}`
    )),
    "",
    "Without --check-only, the only output is the ignored web/.env.production.local file.",
    "The command refuses missing/extra evidence, dirty or mismatched source trees, dev/public CVMs,",
    "mutable images, incomplete independent-CVM descriptors, untrusted QVL",
    "verdicts, stale verdicts, and any live-chain bytecode, role, measurement,",
    "registry, token, policy-set, or approval mismatch.",
  ].join("\n"));
*/

export function parseArgs(argv) {
  return parseSemanticArgs(argv, {
    inputFlags: SEMANTIC_VALIDATOR_INPUT_FLAGS,
    inputFlagSet: SEMANTIC_VALIDATOR_INPUT_FLAG_SET,
    allowCheckOnly: true,
  });
}

export function parsePrebuildArgs(argv) {
  return parseSemanticArgs(argv, {
    inputFlags: PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS,
    inputFlagSet: PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAG_SET,
    allowCheckOnly: false,
  });
}

function parseSemanticArgs(argv, {
  inputFlags,
  inputFlagSet,
  allowCheckOnly,
}) {
  if (!Array.isArray(argv)) {
    throw new TypeError("release evidence arguments must be an array");
  }
  const args = { output: defaultOutput, checkOnly: false };
  const seenValueFlags = new Set();
  let cursor = 0;
  if (argv[cursor] === "--check-only") {
    if (!allowCheckOnly) throw new Error("unknown argument: --check-only");
    args.checkOnly = true;
    cursor += 1;
  }
  for (const expectedFlag of inputFlags) {
    const flag = argv[cursor];
    if (flag !== expectedFlag) {
      if (flag === undefined) {
        throw new Error(`missing required argument: ${expectedFlag}`);
      }
      if (flag === "--check-only") {
        if (!allowCheckOnly) throw new Error("unknown argument: --check-only");
        throw new Error(
          args.checkOnly
            ? "duplicate argument: --check-only"
            : "--check-only must be the first argument",
        );
      }
      if (seenValueFlags.has(flag)) {
        throw new Error(`duplicate argument: ${flag}`);
      }
      if (inputFlagSet.has(flag)) {
        const remainingFlags = argv.slice(cursor)
          .filter((_value, index) => index % 2 === 0);
        if (!remainingFlags.includes(expectedFlag)) {
          throw new Error(`missing required argument: ${expectedFlag}`);
        }
        throw new Error(
          `release evidence arguments are out of order: expected ${expectedFlag}, received ${flag}`,
        );
      }
      if (typeof flag === "string" && flag.startsWith("--")) {
        throw new Error(`unknown argument: ${flag}`);
      }
      throw new Error(`unexpected positional argument where ${expectedFlag} was required`);
    }
    seenValueFlags.add(flag);
    const value = argv[cursor + 1];
    if (value === undefined
      || (typeof value === "string" && value.startsWith("--"))) {
      throw new Error(`missing value for ${flag}`);
    }
    if (typeof value !== "string") {
      throw new Error(`${flag} must be a canonical absolute file path`);
    }
    if (!path.isAbsolute(value) || path.resolve(value) !== value
      || path.normalize(value) !== value) {
      throw new Error(`${flag} must be a canonical absolute file path`);
    }
    const key = semanticValidatorInputKey(flag);
    args[key] = value;
    cursor += 2;
  }
  if (cursor !== argv.length) {
    const extra = argv[cursor];
    if (extra === "--check-only") {
      if (!allowCheckOnly) throw new Error("unknown argument: --check-only");
      throw new Error(
        args.checkOnly
          ? "duplicate argument: --check-only"
          : "--check-only must be the first argument",
      );
    }
    if (inputFlagSet.has(extra)) {
      throw new Error(`duplicate argument: ${extra}`);
    }
    if (typeof extra === "string" && extra.startsWith("--")) {
      throw new Error(`unknown argument: ${extra}`);
    }
    throw new Error("unexpected positional argument after exact release evidence");
  }
  return Object.freeze(args);
}

export function semanticValidatorInputKey(flag) {
  if (!SEMANTIC_VALIDATOR_INPUT_FLAG_SET.has(flag)) {
    throw new Error(`unknown semantic validator input flag: ${flag}`);
  }
  return flag.slice(2).replace(/-([a-z])/g, (_match, letter) => (
    letter.toUpperCase()
  ));
}

export function semanticValidationReceipt(
  releaseSha,
  serializedEnv,
  authorityBinding,
) {
  if (!/^[0-9a-f]{40}$/.test(String(releaseSha))) {
    throw new Error("semantic validation receipt requires a lowercase release SHA");
  }
  if (typeof serializedEnv !== "string" || serializedEnv.length < 2) {
    throw new Error("semantic validation receipt requires the serialized release env");
  }
  const binding = authorityBinding || {};
  for (const [key, label] of [
    ["deploymentIntentSha256", "deployment-intent"],
    ["reviewerAuthorityGenesisAcceptanceSha256", "reviewer-genesis-acceptance"],
    ["ceremonyAuthorizationSha256", "ceremony-authorization"],
    ["liveActivationAuthoritySha256", "live-activation-authority"],
    ["runtimeAuthorityDependencySha256", "runtime-authority-dependency"],
    ["releaseInputsSha256", "release-inputs"],
    ["computeWorkloadActivationObservationSha256", "compute-workload-activation-observation"],
    ["computeWorkloadBrowserBindingSha256", "compute-workload-browser-binding"],
    ["frontendBuildCandidateReceiptSha256", "frontend-build-candidate-receipt"],
    ["frontendBuildSha256", "frontend-build"],
  ]) {
    if (
      !/^sha256:[0-9a-f]{64}$/.test(String(binding[key]))
      || binding[key] === `sha256:${"0".repeat(64)}`
    ) {
      throw new Error(`semantic validation receipt requires a nonzero ${label} SHA-256`);
    }
  }
  if (binding.frontendBuildCandidateReceiptSha256
      === binding.frontendBuildSha256) {
    throw new Error("semantic validation receipt must keep D distinct from the deterministic dist manifest");
  }
  return {
    schema: SEMANTIC_VALIDATION_SCHEMA,
    status: SEMANTIC_VALIDATION_STATUS,
    truth_status: SEMANTIC_VALIDATION_TRUTH_STATUS,
    release_sha: releaseSha,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    deployment_intent_sha256: binding.deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      binding.reviewerAuthorityGenesisAcceptanceSha256,
    ceremony_authorization_sha256: binding.ceremonyAuthorizationSha256,
    live_activation_authority_sha256: binding.liveActivationAuthoritySha256,
    runtime_authority_dependency_sha256: binding.runtimeAuthorityDependencySha256,
    release_inputs_sha256: binding.releaseInputsSha256,
    compute_workload_activation_observation_sha256:
      binding.computeWorkloadActivationObservationSha256,
    compute_workload_browser_binding_sha256:
      binding.computeWorkloadBrowserBindingSha256,
    frontend_build_candidate_receipt_sha256:
      binding.frontendBuildCandidateReceiptSha256,
    release_env_sha256: `sha256:${createHash("sha256")
      .update(serializedEnv, "utf8").digest("hex")}`,
    frontend_build_sha256: binding.frontendBuildSha256,
    raw_secret_egress: false,
  };
}

export function assertLiveActivationAuthorityEvidenceBinding(
  candidate,
  deploymentIntent,
  authorityValidation,
) {
  if (!deploymentIntent?.ok || !deploymentIntent.intent || !deploymentIntent.receipt) {
    throw new Error("deployment intent was not valid at semantic validation time");
  }
  if (!authorityValidation?.ok) {
    throw new Error("signed live activation authority chain was not valid at semantic validation time");
  }
  const candidatePolicy = candidate?.operator_policy;
  const intentReceipt = deploymentIntent.receipt;
  if (
    candidate?.deployment_intent_sha256 !== intentReceipt.deploymentIntentSha256
    || authorityValidation.deploymentIntentSha256 !== intentReceipt.deploymentIntentSha256
    || candidatePolicy?.schema !== "dnai.live-activation-authority-evidence.v1"
    || candidatePolicy?.ceremony_authorization_sha256
      !== authorityValidation.ceremonyAuthorizationSha256
    || candidatePolicy?.live_activation_authority_sha256
      !== authorityValidation.liveActivationAuthoritySha256
    || candidatePolicy?.runtime_authority_dependency_sha256
      !== authorityValidation.runtimeAuthorityDependencySha256
  ) {
    throw new Error("live activation authority evidence does not exactly match the normalized release candidate");
  }
  if (
    intentReceipt.releaseSha !== candidate.release_sha
    || authorityValidation.releaseSha !== candidate.release_sha
  ) {
    throw new Error("authority-chain release SHA does not match the normalized release candidate");
  }
  return {
    deploymentIntentSha256: intentReceipt.deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      authorityValidation.reviewerAuthorityGenesisAcceptanceSha256,
    ceremonyAuthorizationSha256: authorityValidation.ceremonyAuthorizationSha256,
    liveActivationAuthoritySha256: authorityValidation.liveActivationAuthoritySha256,
    runtimeAuthorityDependencySha256: authorityValidation.runtimeAuthorityDependencySha256,
    releaseInputsSha256: authorityValidation.releaseInputsSha256,
    computeWorkloadActivationObservationSha256:
      authorityValidation.computeWorkloadActivationObservationSha256,
    computeWorkloadBrowserBindingSha256:
      authorityValidation.computeWorkloadBrowserBindingSha256,
    frontendBuildCandidateReceiptSha256:
      authorityValidation.frontendBuildCandidateReceiptSha256,
    frontendBuildSha256: authorityValidation.frontendBuildSha256,
  };
}

export async function loadDeploymentIntent(filePath) {
  const bytes = await readStableRegularFile(filePath, "deployment intent", {
    maximum: MAX_PACKET_BYTES,
  });
  const parsed = parseDeploymentIntentCoreText(bytes.toString("utf8"));
  if (!parsed.ok) {
    throw new Error("deployment intent is not a canonical valid predeployment artifact");
  }
  return parsed;
}

const STABLE_FILE_METADATA_FIELDS = Object.freeze([
  "dev", "ino", "uid", "gid", "mode", "nlink", "size", "mtimeNs", "ctimeNs",
]);

function stableFileMetadata(stat) {
  return Object.freeze(Object.fromEntries(
    STABLE_FILE_METADATA_FIELDS.map((field) => [field, stat[field].toString()]),
  ));
}

function sameStableFileMetadata(left, right) {
  return STABLE_FILE_METADATA_FIELDS.every((field) => left[field] === right[field]);
}

function effectiveUserId() {
  const uid = typeof process.geteuid === "function"
    ? process.geteuid()
    : process.getuid?.();
  if (!Number.isSafeInteger(uid) || uid < 0) {
    throw new Error("effective user identity is unavailable");
  }
  return BigInt(uid);
}

async function readStableRegularFileSnapshot(
  filePath,
  label,
  { minimum = 2, maximum },
) {
  let handle;
  try {
    if (!Number.isSafeInteger(maximum) || maximum < minimum) {
      throw new Error(`${label} byte bound is invalid`);
    }
    if (
      typeof filePath !== "string"
      || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath
      || path.normalize(filePath) !== filePath
      || await realpath(filePath) !== filePath
    ) {
      throw new Error(
        `${label} could not be read as a stable no-follow regular file: noncanonical or aliased path`,
      );
    }
    const named = await lstat(filePath, { bigint: true });
    if (!named.isFile()
      || named.isSymbolicLink()
      || named.nlink !== 1n
      || named.uid !== effectiveUserId()
      || (named.mode & 0o022n) !== 0n) {
      throw new Error(
        `${label} could not be read as a stable no-follow regular file: unsafe ownership, mode, or link identity`,
      );
    }
    handle = await open(
      filePath,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
    );
    const before = await handle.stat({ bigint: true });
    if (
      !before.isFile()
      || before.nlink !== 1n
      || before.dev !== named.dev
      || before.ino !== named.ino
      || before.uid !== named.uid
      || before.gid !== named.gid
      || before.mode !== named.mode
      || before.size < BigInt(minimum)
      || before.size > BigInt(maximum)
    ) {
      throw new Error(`${label} is not a bounded regular file`);
    }
    const raw = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const stable = STABLE_FILE_METADATA_FIELDS
      .every((field) => before[field] === after[field]);
    if (!stable || BigInt(raw.length) !== before.size) {
      throw new Error(`${label} changed during its bounded read`);
    }
    return Object.freeze({
      bytes: raw,
      metadata: stableFileMetadata(after),
      rawSha256: `sha256:${createHash("sha256").update(raw).digest("hex")}`,
    });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(`${label} `)) throw error;
    throw new Error(`${label} could not be read as a stable no-follow regular file`);
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

export async function readStableRegularFile(filePath, label, options) {
  const snapshot = await readStableRegularFileSnapshot(filePath, label, options);
  return snapshot.bytes;
}

export async function loadJson(filePath, label) {
  const bytes = await readStableRegularFile(filePath, label, {
    maximum: 2 * 1024 * 1024,
  });
  const raw = bytes.toString("utf8");
  let value;
  try {
    value = JSON.parse(raw);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (`${JSON.stringify(value, null, 2)}\n` !== raw) {
    throw new Error(`${label} is not canonical duplicate-free release JSON`);
  }
  return value;
}

export async function loadExactSemanticValidatorInputs(args) {
  return loadExactSemanticInputsForFlags(
    args,
    SEMANTIC_VALIDATOR_INPUT_FLAGS,
    "semantic validator",
  );
}

export function exactSemanticValidatorArtifactPaths(args) {
  return exactSemanticArtifactPathsForFlags(
    args,
    SEMANTIC_VALIDATOR_INPUT_FLAGS,
    "semantic validator",
    { allowCheckOnly: true },
  );
}

export async function loadExactPrebuildSemanticValidatorInputs(args) {
  return loadExactSemanticInputsForFlags(
    args,
    PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS,
    "prebuild semantic validator",
  );
}

function exactSemanticArtifactPathsForFlags(
  args,
  inputFlags,
  label,
  { allowCheckOnly = false } = {},
) {
  if (!args || typeof args !== "object" || Array.isArray(args)) {
    throw new Error(`${label} requires the exact parsed input arguments`);
  }
  const expectedKeys = [
    "checkOnly",
    "output",
    ...inputFlags.map((flag) => semanticValidatorInputKey(flag)),
  ].sort();
  const actualKeys = Object.keys(args).sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    throw new Error(`${label} requires only the exact parsed input arguments`);
  }
  if (args.output !== defaultOutput) {
    throw new Error(`${label} output path is not the fixed private release-env path`);
  }
  if (typeof args.checkOnly !== "boolean"
    || (!allowCheckOnly && args.checkOnly)) {
    throw new Error(`${label} check-only state is invalid`);
  }
  const entries = inputFlags.map((flag) => {
    const key = semanticValidatorInputKey(flag);
    const filePath = args[key];
    if (typeof filePath !== "string"
      || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath
      || path.normalize(filePath) !== filePath) {
      throw new Error(`${label} has an invalid canonical path for ${flag}`);
    }
    return Object.freeze({ flag, key, filePath });
  });
  if (new Set(entries.map(({ filePath }) => filePath)).size !== entries.length) {
    throw new Error(`${label} requires ${inputFlags.length} distinct private input files`);
  }
  return Object.freeze({
    entries: Object.freeze(entries),
    byFlag: Object.freeze(Object.fromEntries(entries.map((entry) => [
      entry.flag,
      entry.filePath,
    ]))),
    byKey: Object.freeze(Object.fromEntries(entries.map((entry) => [
      entry.key,
      entry.filePath,
    ]))),
  });
}

function deepFreezeJson(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreezeJson(child);
  return Object.freeze(value);
}

async function loadExactSemanticInputsForFlags(args, inputFlags, label) {
  const artifactPaths = exactSemanticArtifactPathsForFlags(
    args,
    inputFlags,
    label,
    { allowCheckOnly: inputFlags === SEMANTIC_VALIDATOR_INPUT_FLAGS },
  );
  const entries = await Promise.all(artifactPaths.entries.map(async ({
    flag,
    key,
    filePath,
  }) => {
    const snapshot = await readStableRegularFileSnapshot(
      filePath,
      `${label} input ${flag}`,
      { maximum: SEMANTIC_VALIDATOR_MAX_INPUT_BYTES },
    );
    const { bytes } = snapshot;
    const text = bytes.toString("utf8");
    if (!Buffer.from(text, "utf8").equals(bytes) || text.includes("\0")) {
      throw new Error(`${label} input ${flag} is not canonical UTF-8 JSON`);
    }
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`${label} input ${flag} is not valid JSON`);
    }
    if (`${JSON.stringify(value, null, 2)}\n` !== text) {
      throw new Error(
        `${label} input ${flag} is not canonical duplicate-free release JSON`,
      );
    }
    deepFreezeJson(value);
    const entry = {
      flag,
      key,
      filePath,
      text,
      byteLength: bytes.length,
      value,
      metadata: snapshot.metadata,
      rawSha256: snapshot.rawSha256,
    };
    Object.defineProperty(entry, "bytes", {
      enumerable: true,
      get: () => Buffer.from(text, "utf8"),
    });
    return Object.freeze(entry);
  }));
  const totalBytes = entries.reduce((sum, { byteLength }) => sum + byteLength, 0);
  if (totalBytes > SEMANTIC_VALIDATOR_MAX_TOTAL_BYTES) {
    throw new Error(`${label} private input set exceeds its total byte bound`);
  }
  const inputs = Object.freeze({
    artifactPaths,
    entries: Object.freeze(entries),
    byFlag: Object.freeze(Object.fromEntries(entries.map((entry) => [
      entry.flag,
      entry,
    ]))),
    byKey: Object.freeze(Object.fromEntries(entries.map((entry) => [
      entry.key,
      entry,
    ]))),
    totalBytes,
  });
  await assertExactSemanticInputsUnchangedForFlags(inputs, inputFlags, label);
  return inputs;
}

export async function assertExactSemanticValidatorInputsUnchanged(inputs) {
  await assertExactSemanticInputsUnchangedForFlags(
    inputs,
    SEMANTIC_VALIDATOR_INPUT_FLAGS,
    "semantic validator",
  );
  return inputs;
}

async function assertExactSemanticInputsUnchangedForFlags(
  inputs,
  inputFlags,
  label,
) {
  if (!inputs || !Array.isArray(inputs.entries)
    || inputs.entries.length !== inputFlags.length) {
    throw new Error(`${label} stable input set is incomplete`);
  }
  for (let index = 0; index < inputFlags.length; index += 1) {
    if (inputs.entries[index]?.flag !== inputFlags[index]) {
      throw new Error(`${label} stable input set order is invalid`);
    }
  }
  await Promise.all(inputs.entries.map(async (entry) => {
    const current = await readStableRegularFileSnapshot(
      entry.filePath,
      `${label} revalidation ${entry.flag}`,
      { maximum: SEMANTIC_VALIDATOR_MAX_INPUT_BYTES },
    );
    if (current.rawSha256 !== entry.rawSha256
      || !sameStableFileMetadata(current.metadata, entry.metadata)) {
      throw new Error(`${label} input ${entry.flag} changed after its exact read`);
    }
  }));
}

export function historicalTranscriptCorroborationFromSemanticInputs(inputs) {
  if (!inputs?.byKey || !Array.isArray(inputs.entries)) {
    throw new Error("historical transcript corroboration requires stable exact-37 inputs");
  }
  const byFlag = new Map(inputs.entries.map((entry) => [entry.flag, entry]));
  const transcriptFileIdentityByFlag = Object.fromEntries(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag) => {
      const entry = byFlag.get(flag);
      if (!entry) {
        throw new Error(`historical transcript is missing ${flag}`);
      }
      return [flag, Object.freeze({
        sha256: entry.rawSha256,
        size: entry.byteLength,
      })];
    }),
  );
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSet(
    transcriptFileIdentityByFlag,
  );
  return Object.freeze({
    fileSet,
    historicalTranscriptFileSetSha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet),
    truthStatus:
      "historical_audit_corroboration_not_current_tdx_or_challenge_freshness",
  });
}

export function frontendBuildPreDPrivateInputsFromSemanticInputs(inputs) {
  if (!inputs?.byKey || !Array.isArray(inputs.entries)) {
    throw new Error("frontend D input projection requires stable exact-37 inputs");
  }
  const byFlag = new Map(inputs.entries.map((entry) => [entry.flag, entry]));
  const actualFlags = [...byFlag.keys()].sort();
  const liveFlags = [...SEMANTIC_VALIDATOR_INPUT_FLAGS].sort();
  const prebuildFlags = [...PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS].sort();
  if (JSON.stringify(actualFlags) !== JSON.stringify(liveFlags)
    && JSON.stringify(actualFlags) !== JSON.stringify(prebuildFlags)) {
    throw new Error("frontend D input projection requires exactly the live-37 or acyclic prebuild-35 flags");
  }
  const releaseEntry = byFlag.get("--release");
  if (!releaseEntry) {
    throw new Error("frontend D input projection is missing the final release candidate");
  }
  const prebuild = JSON.stringify(actualFlags) === JSON.stringify(prebuildFlags);
  let releaseProjectionSha256;
  if (prebuild) {
    const canonicalPrebuild = canonicalPreLiveActivationReleaseCandidateText(
      releaseEntry.value,
    );
    if (!releaseEntry.bytes.equals(Buffer.from(canonicalPrebuild, "utf8"))) {
      throw new Error(
        "frontend D prebuild release must equal the exact canonical pre-live candidate bytes",
      );
    }
    releaseProjectionSha256 = releaseEntry.rawSha256;
  } else {
    releaseProjectionSha256 =
      liveReleaseCandidatePrebuildProjectionSha256(releaseEntry.value);
  }
  const rawSha256ByFlag = Object.fromEntries(
    FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag) => {
      const entry = byFlag.get(flag);
      if (!entry) throw new Error(`frontend D input projection is missing ${flag}`);
      return [flag, entry.rawSha256];
    }),
  );
  return createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256: releaseProjectionSha256,
    rawSha256ByFlag,
  });
}

export async function loadBoundedArtifact(filePath, label) {
  const raw = await readStableRegularFile(filePath, label, {
    maximum: 64 * 1024,
  });
  let value;
  try {
    value = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  return { value, raw };
}

function git(args) {
  return execFileSync(PINNED_GIT_EXECUTABLE, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-C",
    rootDir,
    ...args,
  ], {
    encoding: "utf8",
    env: PINNED_GIT_ENVIRONMENT,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export function assertCleanReleaseSource(expectedSha) {
  const actualSha = git(["rev-parse", "HEAD"]);
  if (actualSha !== expectedSha) {
    throw new Error(`release commit ${expectedSha} does not match current HEAD ${actualSha}`);
  }
  const dirty = git(["status", "--porcelain", "--untracked-files=normal"]);
  if (dirty) {
    throw new Error("refusing to generate a production environment from a dirty source tree");
  }
}

function trustedVerifierAddresses() {
  const raw = process.env.TRUSTED_ATTESTATION_VERIFIER_ADDRESSES || "";
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  if (!values.length) {
    throw new Error("TRUSTED_ATTESTATION_VERIFIER_ADDRESSES is required and cannot come from the release manifest");
  }
  return values;
}

export function releaseRpcEndpoints(env = process.env) {
  const primary = String(env.BASE_SEPOLIA_RPC_URL || "").trim();
  const secondary = String(env.BASE_SEPOLIA_SECONDARY_RPC_URL || "").trim();
  if (!primary) {
    throw new Error("BASE_SEPOLIA_RPC_URL is required for live release verification");
  }
  if (!secondary) {
    throw new Error(
      "BASE_SEPOLIA_SECONDARY_RPC_URL is required for independently hosted browser read failover",
    );
  }
  if (primary !== CANONICAL_PUBLIC_RPC) {
    throw new Error(
      `BASE_SEPOLIA_RPC_URL must equal the reviewed canonical ${CANONICAL_PUBLIC_RPC} endpoint`,
    );
  }
  try {
    return exactDistinctPublicHttpsEndpoints(primary, secondary, {
      primaryLabel: "BASE_SEPOLIA_RPC_URL",
      secondaryLabel: "BASE_SEPOLIA_SECONDARY_RPC_URL",
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`Base Sepolia RPC release endpoints are invalid: ${detail}`);
  }
}

function verifyGithubAttestations(candidate) {
  for (const command of githubAttestationCommands(candidate)) {
    try {
      execFileSync(PINNED_GH_TOOL.path, command, {
        cwd: rootDir,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (error) {
      const stderr = error && typeof error === "object" && "stderr" in error
        ? String(error.stderr || "").trim().split("\n").at(-1)
        : "";
      throw new Error(`GitHub image attestation verification failed${stderr ? `: ${stderr}` : ""}`);
    }
  }
}

function assertSafeOutput(output) {
  if (path.resolve(output) !== defaultOutput) {
    throw new Error(`release output must be the ignored file ${defaultOutput}`);
  }
  git(["check-ignore", "-q", output]);
}

function atomicWriteOutput(output, content) {
  return durablyWritePrivateFile({
    outputPath: output,
    allowedOutputPath: defaultOutput,
    content,
  });
}

export async function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  await loadExactSemanticValidatorInputs(args);
  throw new Error(
    "Model-A exact-37 semantic validator integration is incomplete",
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
