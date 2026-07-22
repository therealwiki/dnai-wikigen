#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MAX_PACKET_BYTES,
  describeAuthorityReviewSubjectText,
} from "./operator-policy-packet-core.mjs";
import {
  assertReviewedCeremonyAuthorityProjection,
} from "./ceremony-authority-projector.mjs";

export const CHALLENGE_REGISTRY_AUTHORITY_PROJECTION_SCHEMA =
  "dnai.challenge-registry-authority-projection.v1";
export const CHALLENGE_REGISTRY_RUNTIME_ENVIRONMENT_PROJECTION_SCHEMA =
  "dnai.challenge-registry-runtime-environment-projection.v1";
export const ARENA_APPROVED_CHALLENGE_SET_SCHEMA =
  "dnai.arena.release-approved-challenge-set.v1";
export const ARENA_APPROVED_CHALLENGE_SET_DOMAIN =
  "dnai-wikigen/arena-release-approved-challenge-set/v1\0";
export const MAX_ARENA_CHALLENGE_BINDINGS_JSON_BYTES = 64 * 1024;
export const CHALLENGE_REGISTRY_RUNTIME_PUBLIC_ENVIRONMENT_KEYS = Object.freeze([
  "TINKER_ARENA_REGISTRY_ADDRESS",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON",
  "TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256",
  "TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH",
]);

const SHA256_PIN = /^sha256:[0-9a-f]{64}$/;
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const UINT = /^[1-9][0-9]{0,77}$/;
const CHALLENGE_KEY = /^[a-z0-9][a-z0-9-]{0,63}@(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const RUNTIME_PROJECTIONS = new WeakMap();
const RUNTIME_BINDING_FIELDS = Object.freeze([
  "catalog_manifest_hash",
  "configuration_frozen",
  "controller_address",
  "evaluator_commitment",
  "lifecycle",
  "metadata_hash",
  "metadata_uri",
  "paused",
  "pending_controller_address",
  "registry_challenge_id",
  "registry_version",
  "release_policy_commitment",
  "sealed_artifact_commitment",
]);

export class ChallengeRegistryAuthorityProjectionError extends TypeError {}

function fail(message) {
  throw new ChallengeRegistryAuthorityProjectionError(message);
}

function same(actual, expected, label) {
  if (actual !== expected) fail(`${label} does not match the reviewed final authority`);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields are not exact`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalCompact(value) {
  return JSON.stringify(sorted(value));
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function runtimeBindings(finalAuthority) {
  return Object.fromEntries(Object.entries(finalAuthority.arena_registry_bindings)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([catalogKey, binding]) => [catalogKey, {
      registry_challenge_id: binding.registry_challenge_id,
      registry_version: binding.registry_version,
      controller_address: binding.controller_address,
      pending_controller_address: binding.pending_controller_address,
      lifecycle: binding.lifecycle,
      paused: binding.paused,
      configuration_frozen: binding.configuration_frozen,
      catalog_manifest_hash: binding.catalog_manifest_hash,
      metadata_uri: binding.metadata_uri,
      metadata_hash: binding.metadata_hash,
      sealed_artifact_commitment: binding.sealed_artifact_commitment,
      evaluator_commitment: binding.evaluator_commitment,
      release_policy_commitment: binding.release_policy_commitment,
    }]));
}

function approvedSetSha256(bindings) {
  const committed = Object.fromEntries(Object.entries(bindings).map(([key, binding]) => [
    key,
    Object.fromEntries(Object.entries(binding).filter(
      ([field]) => field !== "release_policy_commitment",
    )),
  ]));
  return `sha256:${createHash("sha256")
    .update(ARENA_APPROVED_CHALLENGE_SET_DOMAIN, "utf8")
    .update(canonicalCompact({
      schema: ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
      bindings: committed,
    }), "utf8")
    .digest("hex")}`;
}

function normalizeRuntimeBindingsJson(value) {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") < 2
    || Buffer.byteLength(value, "utf8") > MAX_ARENA_CHALLENGE_BINDINGS_JSON_BYTES
    || /[\u0000\r\n]/.test(value)) {
    fail("ChallengeRegistry bindings JSON is outside its canonical byte bound");
  }
  let decoded;
  try {
    decoded = JSON.parse(value);
  } catch {
    fail("ChallengeRegistry bindings JSON is malformed");
  }
  if (!isRecord(decoded) || Object.keys(decoded).length < 1
    || Object.keys(decoded).length > 32 || canonicalCompact(decoded) !== value) {
    fail("ChallengeRegistry bindings JSON is not the canonical finite catalog");
  }
  const ids = new Set();
  const normalized = {};
  for (const [catalogKey, raw] of Object.entries(decoded).sort(([left], [right]) => (
    left.localeCompare(right)
  ))) {
    if (!CHALLENGE_KEY.test(catalogKey)) fail("ChallengeRegistry catalog key is invalid");
    const binding = exactRecord(raw, RUNTIME_BINDING_FIELDS, `ChallengeRegistry ${catalogKey}`);
    if (typeof binding.registry_challenge_id !== "string"
      || !UINT.test(binding.registry_challenge_id)
      || BigInt(binding.registry_challenge_id) >= 2n ** 256n
      || ids.has(binding.registry_challenge_id)) {
      fail(`ChallengeRegistry ${catalogKey} challenge id is invalid`);
    }
    ids.add(binding.registry_challenge_id);
    if (!Number.isInteger(binding.registry_version)
      || binding.registry_version < 1 || binding.registry_version >= 2 ** 32
      || !ADDRESS.test(binding.controller_address)
      || binding.controller_address === ZERO_ADDRESS
      || binding.pending_controller_address !== ZERO_ADDRESS
      || binding.lifecycle !== "open" || binding.paused !== false
      || binding.configuration_frozen !== true
      || !BARE_SHA256.test(binding.catalog_manifest_hash)
      || binding.catalog_manifest_hash === "0".repeat(64)
      || typeof binding.metadata_uri !== "string"
      || Buffer.byteLength(binding.metadata_uri, "ascii") < 1
      || Buffer.byteLength(binding.metadata_uri, "ascii") > 256
      || /[^\x21-\x7e]/.test(binding.metadata_uri)
      || binding.metadata_hash !== `0x${binding.catalog_manifest_hash}`) {
      fail(`ChallengeRegistry ${catalogKey} release binding is invalid`);
    }
    const commitments = [
      binding.metadata_hash,
      binding.sealed_artifact_commitment,
      binding.evaluator_commitment,
      binding.release_policy_commitment,
    ];
    if (commitments.some((item) => !BYTES32.test(item) || item === ZERO_BYTES32)
      || new Set(commitments).size !== commitments.length) {
      fail(`ChallengeRegistry ${catalogKey} commitments are invalid`);
    }
    normalized[catalogKey] = { ...binding };
  }
  const expectedIds = Array.from({ length: ids.size }, (_unused, index) => String(index + 1));
  const actualIds = [...ids].sort((left, right) => (
    BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0
  ));
  if (JSON.stringify(actualIds) !== JSON.stringify(expectedIds)) {
    fail("ChallengeRegistry bindings must use contiguous genesis ids 1..N");
  }
  return normalized;
}

export function projectChallengeRegistryAuthority(finalAuthority) {
  const registry = finalAuthority.contracts.challenge_registry;
  const entries = Object.entries(finalAuthority.arena_registry_bindings)
    .map(([catalogKey, binding]) => ({
      catalogKey,
      challengeId: Number(binding.registry_challenge_id),
      version: binding.registry_version,
      controller: binding.controller_address,
      pendingController: binding.pending_controller_address,
      lifecycle: binding.lifecycle,
      paused: binding.paused,
      configurationFrozen: binding.configuration_frozen,
      catalogManifestHash: `0x${binding.catalog_manifest_hash}`,
      metadataURI: binding.metadata_uri,
      metadataHash: binding.metadata_hash,
      sealedArtifactCommitment: binding.sealed_artifact_commitment,
      evaluatorCommitment: binding.evaluator_commitment,
      releasePolicyCommitment: binding.release_policy_commitment,
    }))
    .sort((left, right) => left.challengeId - right.challengeId);

  if (
    entries.length !== registry.expected_challenge_count
    || entries.some((entry, index) => entry.challengeId !== index + 1)
  ) {
    fail("internal ChallengeRegistry projection is not the exact contiguous genesis catalog");
  }

  return {
    schema: CHALLENGE_REGISTRY_AUTHORITY_PROJECTION_SCHEMA,
    releaseSha: finalAuthority.release_sha,
    chainId: finalAuthority.network.chain_id,
    registry: {
      address: registry.address,
      runtimeCodeHash: registry.runtime_code_hash,
      owner: registry.owner,
      pendingOwner: registry.pending_owner,
      registryPaused: registry.registry_paused,
      minimumVersionReviewDelaySeconds:
        registry.minimum_version_review_delay_seconds,
      expectedChallengeCount: registry.expected_challenge_count,
    },
    entries,
  };
}

export function projectCanonicalChallengeRegistryAuthorityText(
  finalAuthorityText,
  { finalAuthoritySha256, releaseSha } = {},
) {
  const descriptor = describeAuthorityReviewSubjectText(finalAuthorityText);
  if (
    !descriptor.ok
    || descriptor.subjectKind !== "final_release_authority"
    || descriptor.semanticValidation !== "final_release_authority_validated"
  ) {
    fail(
      `final authority is invalid: ${descriptor.errors?.[0]?.message || "unsupported subject"}`,
    );
  }
  if (finalAuthoritySha256 !== undefined) {
    same(descriptor.subjectSha256, finalAuthoritySha256, "final-authority SHA-256 pin");
  }
  if (releaseSha !== undefined) {
    same(descriptor.subject.release_sha, releaseSha, "release SHA");
  }
  return {
    ...projectChallengeRegistryAuthority(descriptor.subject),
    finalAuthoritySha256: descriptor.subjectSha256,
  };
}

export function normalizeChallengeRegistryRuntimeEnvironmentValues(value) {
  const parsed = exactRecord(
    value,
    CHALLENGE_REGISTRY_RUNTIME_PUBLIC_ENVIRONMENT_KEYS,
    "ChallengeRegistry runtime environment",
  );
  if (!ADDRESS.test(parsed.TINKER_ARENA_REGISTRY_ADDRESS)
    || parsed.TINKER_ARENA_REGISTRY_ADDRESS === ZERO_ADDRESS
    || !BYTES32.test(parsed.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH)
    || parsed.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH === ZERO_BYTES32
    || !SHA256_PIN.test(parsed.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256)
    || parsed.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256
      === `sha256:${"0".repeat(64)}`) {
    fail("ChallengeRegistry runtime environment pins are malformed");
  }
  const bindings = normalizeRuntimeBindingsJson(
    parsed.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON,
  );
  if (approvedSetSha256(bindings)
      !== parsed.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256) {
    fail("ChallengeRegistry approved challenge-set digest does not match its bindings");
  }
  return {
    TINKER_ARENA_REGISTRY_ADDRESS: parsed.TINKER_ARENA_REGISTRY_ADDRESS,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON:
      canonicalCompact(bindings),
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
      parsed.TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256,
    TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH:
      parsed.TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH,
  };
}

/**
 * Derive the exact public main-runtime pins from canonical final-authority
 * bytes and the branded, current review of those same bytes. The returned
 * object carries an in-process provenance brand; callers cannot upgrade an
 * operator-authored environment map or an unreviewed final authority by
 * normalizing it or supplying matching pins themselves.
 */
export function projectCanonicalChallengeRegistryRuntimeEnvironmentText(
  finalAuthorityText,
  { reviewedCeremonyAuthorityProjection } = {},
) {
  const reviewedCeremony = assertReviewedCeremonyAuthorityProjection(
    reviewedCeremonyAuthorityProjection,
  );
  const descriptor = describeAuthorityReviewSubjectText(finalAuthorityText);
  if (!descriptor.ok || descriptor.subjectKind !== "final_release_authority"
    || descriptor.semanticValidation !== "final_release_authority_validated") {
    fail(
      `final authority is invalid: ${descriptor.errors?.[0]?.message || "unsupported subject"}`,
    );
  }
  same(
    descriptor.subjectSha256,
    reviewedCeremony.finalAuthoritySha256,
    "final-authority SHA-256 pin",
  );
  same(descriptor.subject.release_sha, reviewedCeremony.releaseSha, "release SHA");
  same(descriptor.subject.network.chain_id, reviewedCeremony.chainId, "chain ID");
  same(
    descriptor.subject.deployment_intent_sha256,
    reviewedCeremony.deploymentIntentSha256,
    "deployment-intent SHA-256 pin",
  );
  same(
    descriptor.subject.cvm_launch_intent_sha256,
    reviewedCeremony.cvmLaunchIntentSha256,
    "CVM launch-intent SHA-256 pin",
  );
  const bindings = runtimeBindings(descriptor.subject);
  const environment = normalizeChallengeRegistryRuntimeEnvironmentValues({
    TINKER_ARENA_REGISTRY_ADDRESS:
      descriptor.subject.contracts.challenge_registry.address,
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_BINDINGS_JSON:
      canonicalCompact(bindings),
    TINKER_ARENA_REGISTRY_APPROVED_CHALLENGE_SET_SHA256:
      approvedSetSha256(bindings),
    TINKER_ARENA_REGISTRY_RUNTIME_CODE_HASH:
      descriptor.subject.contracts.challenge_registry.runtime_code_hash,
  });
  const projection = deepFreeze({
    schema: CHALLENGE_REGISTRY_RUNTIME_ENVIRONMENT_PROJECTION_SCHEMA,
    finalAuthoritySha256: descriptor.subjectSha256,
    releaseSha: descriptor.subject.release_sha,
    chainId: descriptor.subject.network.chain_id,
    deploymentIntentSha256: descriptor.subject.deployment_intent_sha256,
    cvmLaunchIntentSha256: descriptor.subject.cvm_launch_intent_sha256,
    environment,
  });
  RUNTIME_PROJECTIONS.set(projection, canonicalCompact(projection));
  return projection;
}

export function assertProjectedChallengeRegistryRuntimeEnvironment(value) {
  const expected = value && RUNTIME_PROJECTIONS.get(value);
  if (!expected || expected !== canonicalCompact(value)
    || value.schema !== CHALLENGE_REGISTRY_RUNTIME_ENVIRONMENT_PROJECTION_SCHEMA
    || value.chainId !== 84_532 || !RELEASE_SHA.test(value.releaseSha)
    || !SHA256_PIN.test(value.finalAuthoritySha256)
    || !SHA256_PIN.test(value.deploymentIntentSha256)
    || !SHA256_PIN.test(value.cvmLaunchIntentSha256)) {
    fail("ChallengeRegistry runtime environment lacks final-authority provenance");
  }
  normalizeChallengeRegistryRuntimeEnvironmentValues(value.environment);
  return value;
}

async function readAuthorityFile(filePath) {
  if (!path.isAbsolute(filePath)) fail("final authority path must be absolute");
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink()) {
    fail("final authority must be a non-symlink regular file");
  }
  if (info.size <= 0 || info.size > MAX_PACKET_BYTES) {
    fail("final authority size is outside the supported bound");
  }
  return readFile(filePath, "utf8");
}

function parseCliArgs(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      fail(
        "usage: challenge-registry-authority-projector.mjs --final-authority FILE --final-authority-sha256 SHA --release-sha SHA",
      );
    }
    if (options.has(name)) fail(`duplicate argument ${name}`);
    options.set(name, value);
  }
  const allowed = new Set([
    "--final-authority",
    "--final-authority-sha256",
    "--release-sha",
  ]);
  if (options.size !== allowed.size || [...options.keys()].some((key) => !allowed.has(key))) {
    fail("all three exact ChallengeRegistry projector arguments are required");
  }
  return Object.fromEntries([...options].map(([key, value]) => [key.slice(2), value]));
}

export async function runChallengeRegistryAuthorityProjectorCli(argv) {
  const options = parseCliArgs(argv);
  if (
    !SHA256_PIN.test(options["final-authority-sha256"])
    || options["final-authority-sha256"] === `sha256:${"0".repeat(64)}`
  ) {
    fail("final-authority SHA-256 pin is malformed");
  }
  if (!RELEASE_SHA.test(options["release-sha"]) || options["release-sha"] === "0".repeat(40)) {
    fail("release SHA is malformed");
  }
  const authorityText = await readAuthorityFile(options["final-authority"]);
  return projectCanonicalChallengeRegistryAuthorityText(authorityText, {
    finalAuthoritySha256: options["final-authority-sha256"],
    releaseSha: options["release-sha"],
  });
}

const isEntrypoint = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isEntrypoint) {
  try {
    const projection = await runChallengeRegistryAuthorityProjectorCli(
      process.argv.slice(2),
    );
    process.stdout.write(`${JSON.stringify(projection)}\n`);
  } catch (error) {
    process.stderr.write(
      `ChallengeRegistry authority projection failed: ${String(error?.message || error).replace(/[\r\n]+/g, " ").slice(0, 512)}\n`,
    );
    process.exitCode = 1;
  }
}
