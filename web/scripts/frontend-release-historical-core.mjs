import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "../../scripts/canonical-authority-graph.mjs";
import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  canonicalFinalReleaseAuthorityCoreBytes,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";
import {
  normalizeHistoricalLiveActivationFrontendBinding,
} from "../../scripts/release-authority-historical-core.mjs";

/**
 * Pure historical replay for the final frontend candidate and D receipt.
 *
 * This module intentionally has no filesystem, path, process, clock, network,
 * dynamic-import, wallet, or production-brand capability. It validates only
 * values already supplied as canonical JSON and explicit authenticated roots.
 */

export const HISTORICAL_FRONTEND_RELEASE_CANDIDATE_SCHEMA =
  "dnai.web-release.v4";
export const HISTORICAL_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.live-activation-authority-evidence.v1";
export const HISTORICAL_PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.pre-live-activation-authority-evidence.v1";

export const FRONTEND_BUILD_CANDIDATE_SCHEMA =
  "dnai.frontend-build-candidate.v2";
export const FRONTEND_BUILD_CANDIDATE_STATUS =
  "pre_live_activation_candidate";
export const FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS =
  "pre_live_activation_candidate_not_deploy_authority";
export const FRONTEND_BUILD_CANDIDATE_DOMAIN =
  "dnai-wikigen/frontend-build-candidate/v2\0";
export const FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA =
  "dnai.frontend-build-candidate-input-manifest.v2";
export const FRONTEND_BUILD_INPUT_MANIFEST_DOMAIN =
  "dnai-wikigen/frontend-build-candidate-input-manifest/v2\0";
export const FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS =
  "deterministic_pre_D_inputs_excluding_signed_C_D_and_dist_not_deploy_authority";
export const FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION =
  "live_candidate_prebuild_projection_v1";
export const FRONTEND_BUILD_RAW_INPUT_PROJECTION =
  "raw_canonical_file_bytes";

export const FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS = Object.freeze([
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
  "--compute-workload-activation-observation",
]);

export const FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS = Object.freeze([
  "--live-activation-authority",
  "--frontend-build-candidate-receipt",
]);
export const FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS = Object.freeze(
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS.filter((flag) => flag !== "--release"),
);
export const FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS = Object.freeze([
  "release_core_sha256",
  "deployment_intent_sha256",
  "fresh_contract_deployment_receipt_sha256",
  "reviewer_authority_genesis_sha256",
  "reviewer_authority_genesis_acceptance_sha256",
  "bootstrap_authority_sha256",
  "bootstrap_authorization_sha256",
  "bootstrap_authorization_receipt_sha256",
  "seven_cvm_launch_completion_receipt_sha256",
  "historical_transcript_file_set_sha256",
  "qvl_measurement_policy_set_sha256",
  "runtime_authority_dependency_sha256",
  "ceremony_authorization_sha256",
  "compute_workload_activation_observation_sha256",
]);
export const FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS = Object.freeze([
  "contract_release_set_sha256",
  "cvm_release_set_sha256",
  "qvl_measurement_policy_set_sha256",
]);

// These are protocol constants, not filesystem discoveries. The effectful
// producer owns discovery and byte hashing; historical replay only verifies
// that D carries the exact frozen recipe and its aggregate commitment.
export const HISTORICAL_CLOUDFLARE_D_BUILD_CONTROL_PATHS = Object.freeze([
  "web/functions/_middleware.js",
  "web/index.html",
  "web/package-lock.json",
  "web/package.json",
  "web/public/wikigen-bootstrap-v3.js",
  "web/scripts/build-release-env.mjs",
  "web/scripts/build-security-headers.mjs",
  "web/scripts/cloudflare-build-sandbox-core.mjs",
  "web/scripts/cloudflare-external-build-closure-core.mjs",
  "web/scripts/cloudflare-release-artifact-core.mjs",
  "web/scripts/deploy-cloudflare-core.mjs",
  "web/scripts/deploy-cloudflare.mjs",
  "web/scripts/durable-private-file-core.mjs",
  "web/scripts/execution-policy-release-core-binding.mjs",
  "web/scripts/frontend-build-candidate-core.mjs",
  "web/scripts/frontend-build-candidate-producer-core.mjs",
  "web/scripts/public-https-origin-core.mjs",
  "web/scripts/release-build-home-core.mjs",
  "web/scripts/release-runtime-pins-core.mjs",
  "web/scripts/release-env-core.mjs",
  "web/scripts/security-headers-core.mjs",
  "web/tsconfig.json",
  "web/vite.config.ts",
  "web/wrangler.toml",
]);

export const HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA =
  "dnai.cloudflare-external-build-closure.v1";
export const HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS =
  "exact_external_build_inputs";

const EXTERNAL_ENTRYPOINTS = Object.freeze([
  ["sandbox_config", ".gitignore"],
  ["verification_input", "ARCHITECTURE.md"],
  ["verification_input", "PROJECT.md"],
  ["verification_input", "README.md"],
  ["build_asset", "outputs/wikigen-pitch-assets/attested-network.webp"],
  ["build_asset", "outputs/wikigen-pitch-assets/private-reward-oracle.webp"],
  ["module", "scripts/canonical-authority-graph.mjs"],
  ["module", "scripts/compute-workload-activation-observation-core.mjs"],
  ["module", "scripts/execution-policy-release-core-cli.mjs"],
  ["module", "scripts/execution-policy-release-core.fixture.mjs"],
  ["module", "scripts/execution-policy-release-core.mjs"],
  ["module", "scripts/operator-policy-packet-core.mjs"],
  ["module", "scripts/phala-seven-cvm-historical-transcript.mjs"],
  ["module", "scripts/pre-ceremony-runtime-authority-core.mjs"],
  ["module", "scripts/release-authority-historical-core.mjs"],
  ["module", "scripts/release-manifest-sigstore-verifier.mjs"],
  ["verification_input", "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq"],
].map(([kind, path]) => Object.freeze({ kind, path })));

const EXTERNAL_FILES = Object.freeze([
  ["sandbox_config", ".gitignore", 64 * 1024],
  ["verification_input", "ARCHITECTURE.md", 4 * 1024 * 1024],
  ["verification_input", "PROJECT.md", 4 * 1024 * 1024],
  ["verification_input", "README.md", 4 * 1024 * 1024],
  ["build_asset", "outputs/wikigen-pitch-assets/attested-network.webp", 8 * 1024 * 1024],
  ["build_asset", "outputs/wikigen-pitch-assets/private-reward-oracle.webp", 8 * 1024 * 1024],
  ["module", "scripts/canonical-authority-graph.mjs", 4 * 1024 * 1024],
  ["module", "scripts/compute-workload-activation-observation-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/cvm-descriptor-runtime-authority-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/cvm-launch-intent-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/cvm-release-descriptor-set-constants.mjs", 4 * 1024 * 1024],
  ["module", "scripts/ethereum-keccak.mjs", 4 * 1024 * 1024],
  ["module", "scripts/execution-policy-release-core-cli.mjs", 4 * 1024 * 1024],
  ["module", "scripts/execution-policy-release-core.fixture.mjs", 4 * 1024 * 1024],
  ["module", "scripts/execution-policy-release-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/operator-policy-packet-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-post-measurement-activation-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-post-measurement-activation-receipt-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-production-execution-policy.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-seven-cvm-historical-evidence-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-seven-cvm-historical-transcript.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-seven-cvm-measurement-policy.mjs", 4 * 1024 * 1024],
  ["module", "scripts/phala-seven-cvm-release-verification-authority-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/pre-ceremony-runtime-authority-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/release-authority-historical-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/release-authority-signature-verifier-core.mjs", 4 * 1024 * 1024],
  ["module", "scripts/release-manifest-sigstore-verifier.mjs", 4 * 1024 * 1024],
  ["verification_input", "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq", 1024 * 1024],
].map(([kind, path, maximumBytes]) => Object.freeze({
  kind,
  path,
  maximumBytes,
})));

const RELEASE_CANDIDATE_KEYS = Object.freeze([
  "schema",
  "release_sha",
  "network",
  "operator_address",
  "deployment_intent_sha256",
  "cvm_launch_intent_sha256",
  "operator_policy",
  "contracts",
  "cvm",
  "trust_domains",
  "wallet_auth",
  "execution_policy",
  "attestations",
  "arena_registry_bindings",
  "requested_features",
]);
const CONTRACT_KEYS = Object.freeze([
  "diligence_room",
  "challenge_registry",
  "royalty_distributor",
  "tinker_account_encumbrance",
  "compute_credit_vault",
  "email_oracle_auth",
  "usdc",
]);
const TRUST_DOMAIN_KEYS = Object.freeze([
  "diligence_qvl",
  "arena_qvl",
  "anchor_writer_qvl",
  "compute_metering_qvl",
  "compute_workload_qvl",
  "compute_metering",
]);
const BASE_SEPOLIA_CHAIN_ID = 84_532;
const CANONICAL_PRIMARY_RPC = "https://sepolia.base.org";
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const GIT_TREE_OID = /^sha1:[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const BARE_WORD = /^(?!0{64}$)[0-9a-f]{64}$/;
const MAX_ENV_BYTES = 128 * 1024;
const FORBIDDEN_POST_BUILD_AUTHORITY_INPUT =
  /(?:live[-_]activation[-_]authority|semantic[-_]live[-_]activation|frontend[-_]build[-_]candidate[-_]receipt|compute[-_]workload[-_]activation[-_]observation)/i;
const EXTERNAL_AGGREGATE_DOMAIN =
  "dnai.cloudflare-external-build-closure.aggregate.v1";

function fail(message) {
  throw new TypeError(message);
}

function assertGraph(value, label) {
  try {
    return assertCanonicalPlainDataGraph(value, { label });
  } catch (error) {
    fail(error.message);
  }
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== "string")
    || JSON.stringify(keys.sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be a record`);
  }
  return value;
}

function cloneCanonical(value) {
  if (Array.isArray(value)) return value.map(cloneCanonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).map((key) => [key, cloneCanonical(value[key])]),
  );
}

function freeze(value, label) {
  return deepFreezeCanonicalPlainDataGraph(value, { label });
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function byteLength(value) {
  return new TextEncoder().encode(value).byteLength;
}

function rawSha256(value) {
  return `sha256:${createHash("sha256").update(value, "utf8").digest("hex")}`;
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function nonzeroSha256(value, label) {
  if (!SHA256.test(String(value || ""))) {
    fail(`${label} must be a nonzero sha256:<64 lowercase hex> pin`);
  }
  return value;
}

function releaseSha(value, label) {
  if (!SHA40.test(String(value || ""))) {
    fail(`${label} must be a nonzero lowercase 40-character Git SHA`);
  }
  return value;
}

function address(value, label) {
  if (!ADDRESS.test(String(value || ""))) {
    fail(`${label} must be a nonzero lowercase Ethereum address`);
  }
  return value;
}

function bareWord(value, label) {
  if (!BARE_WORD.test(String(value || ""))) {
    fail(`${label} must be a nonzero lowercase bare bytes32`);
  }
  return value;
}

function appId(value, label) {
  if (!APP_ID.test(String(value || ""))) {
    fail(`${label} must be a nonzero lowercase 20-byte app ID`);
  }
  return value;
}

function canonicalRepoPath(value, label) {
  if (typeof value !== "string"
    || value.length < 1
    || value.length > 512
    || value.startsWith("/")
    || value.startsWith("./")
    || value.endsWith("/")
    || value.includes("\\")
    || value.includes("\0")
    || value.split("/").some((part) => !part || part === "." || part === "..")) {
    fail(`${label} must be a canonical repo-relative POSIX path`);
  }
  return value;
}

function safeMode(value) {
  return Number.isSafeInteger(value)
    && value >= 0
    && value <= 0o777
    && (value & 0o400) !== 0
    && (value & 0o133) === 0;
}

function exactDigestRecord(value, fields, label) {
  const parsed = exact(value, fields, label);
  return Object.fromEntries(fields.map((field) => [
    field,
    nonzeroSha256(parsed[field], `${label} ${field}`),
  ]));
}

function strictPublicHttpsEndpoint(value, label) {
  if (typeof value !== "string"
    || value !== value.trim()
    || value.length < 9
    || byteLength(value) > 4_096
    || /[^\x21-\x7e]/u.test(value)
    || value.includes("*")) {
    fail(`${label} must be a bounded exact public HTTPS endpoint`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be a bounded exact public HTTPS endpoint`);
  }
  const hostname = parsed.hostname.toLowerCase();
  const labels = hostname.split(".");
  const privateSuffixes = [
    "localhost", "local", "localdomain", "internal", "lan", "home.arpa",
    "onion", "test", "invalid", "example", "alt",
  ];
  if (parsed.protocol !== "https:"
    || parsed.username
    || parsed.password
    || parsed.search
    || parsed.hash
    || hostname.includes(":")
    || /^\d+(?:\.\d+){3}$/.test(hostname)
    || labels.length < 2
    || hostname.endsWith(".")
    || hostname.length > 253
    || labels.some((entry) => (
      !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(entry)
    ))
    || privateSuffixes.some((suffix) => (
      hostname === suffix || hostname.endsWith(`.${suffix}`)
    ))) {
    fail(`${label} must be a bounded exact public HTTPS endpoint`);
  }
  return parsed.pathname === "/" ? parsed.origin : parsed.href;
}

function distinctPublicHttpsEndpoints(primaryValue, secondaryValue) {
  const primary = strictPublicHttpsEndpoint(primaryValue, "frontend build primary RPC");
  const secondary = strictPublicHttpsEndpoint(secondaryValue, "frontend build secondary RPC");
  if (primary === secondary
    || new URL(primary).origin.toLowerCase()
      === new URL(secondary).origin.toLowerCase()) {
    fail("frontend build secondary RPC must use a different public provider origin");
  }
  return { primary, secondary };
}

export function normalizeHistoricalCloudflareExternalBuildClosure(value) {
  assertGraph(value, "historical Cloudflare external build closure");
  const parsed = exact(value, [
    "aggregate_sha256",
    "entrypoints",
    "files",
    "raw_secret_egress",
    "schema",
    "truth_status",
  ], "historical Cloudflare external build closure");
  if (parsed.schema !== HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA
    || parsed.truth_status
      !== HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS
    || parsed.raw_secret_egress !== false
    || !Array.isArray(parsed.entrypoints)
    || parsed.entrypoints.length !== EXTERNAL_ENTRYPOINTS.length
    || !Array.isArray(parsed.files)
    || parsed.files.length !== EXTERNAL_FILES.length) {
    fail("historical Cloudflare external build closure truth boundary is invalid");
  }
  const entrypoints = parsed.entrypoints.map((valueEntry, index) => {
    const entry = exact(
      valueEntry,
      ["kind", "path"],
      `historical external build entrypoint ${index}`,
    );
    const expected = EXTERNAL_ENTRYPOINTS[index];
    if (entry.kind !== expected.kind || entry.path !== expected.path) {
      fail("historical external build entrypoints are not exact and ordered");
    }
    return { kind: expected.kind, path: expected.path };
  });
  const files = parsed.files.map((valueEntry, index) => {
    const entry = exact(
      valueEntry,
      ["kind", "mode", "path", "sha256", "size"],
      `historical external build file ${index}`,
    );
    const expected = EXTERNAL_FILES[index];
    if (entry.kind !== expected.kind
      || entry.path !== expected.path
      || !safeMode(entry.mode)
      || !Number.isSafeInteger(entry.size)
      || entry.size < 1
      || entry.size > expected.maximumBytes) {
      fail("historical external build files are unsafe or not exact and ordered");
    }
    return {
      kind: expected.kind,
      path: expected.path,
      mode: entry.mode,
      size: entry.size,
      sha256: nonzeroSha256(entry.sha256, `historical external build ${entry.path}`),
    };
  });
  const payload = {
    schema: HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: HISTORICAL_CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints,
    files,
    raw_secret_egress: false,
  };
  const aggregate = `sha256:${createHash("sha256")
    .update(EXTERNAL_AGGREGATE_DOMAIN, "utf8")
    .update("\0", "ascii")
    .update(canonicalText(payload), "utf8")
    .digest("hex")}`;
  if (parsed.aggregate_sha256 !== aggregate) {
    fail("historical Cloudflare external build closure aggregate is invalid");
  }
  return freeze({
    schema: payload.schema,
    truth_status: payload.truth_status,
    entrypoints: payload.entrypoints,
    files: payload.files,
    aggregate_sha256: aggregate,
    raw_secret_egress: false,
  }, "normalized historical Cloudflare external build closure");
}

function normalizePreDPrivateInputs(value) {
  if (!Array.isArray(value)
    || value.length !== FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS.length) {
    fail("frontend build manifest requires the exact acyclic pre-D private input set");
  }
  const normalized = value.map((valueEntry, index) => {
    const entry = exact(
      valueEntry,
      ["flag", "projection", "sha256"],
      `frontend build private input ${index}`,
    );
    const expectedFlag = FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS[index];
    const expectedProjection = expectedFlag === "--release"
      ? FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION
      : FRONTEND_BUILD_RAW_INPUT_PROJECTION;
    if (entry.flag !== expectedFlag || entry.projection !== expectedProjection
      || FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS.includes(entry.flag)) {
      fail(`frontend build private input ${index} is not the exact acyclic ${expectedFlag} projection`);
    }
    return {
      flag: expectedFlag,
      projection: expectedProjection,
      sha256: nonzeroSha256(entry.sha256, `frontend build private input ${expectedFlag}`),
    };
  });
  if (new Set(normalized.map((entry) => entry.sha256)).size !== normalized.length) {
    fail("frontend build private inputs cannot collapse distinct evidence files");
  }
  return normalized;
}

export function createFrontendBuildPreDPrivateInputs({
  liveCandidatePrebuildProjectionSha256,
  rawSha256ByFlag,
}) {
  assertGraph(rawSha256ByFlag, "frontend build raw private inputs");
  const actual = Object.keys(record(rawSha256ByFlag, "frontend build raw private inputs")).sort();
  const expected = [...FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail("frontend build raw private inputs contain an omission, extra, release, C, or D input");
  }
  return freeze(normalizePreDPrivateInputs([
    {
      flag: "--release",
      projection: FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION,
      sha256: liveCandidatePrebuildProjectionSha256,
    },
    ...FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag) => ({
      flag,
      projection: FRONTEND_BUILD_RAW_INPUT_PROJECTION,
      sha256: rawSha256ByFlag[flag],
    })),
  ]), "frontend build pre-D private inputs");
}

function normalizeBuildControls(value) {
  if (!Array.isArray(value)
    || value.length !== HISTORICAL_CLOUDFLARE_D_BUILD_CONTROL_PATHS.length) {
    fail("frontend build manifest requires the exact Cloudflare build-control file set");
  }
  return value.map((valueEntry, index) => {
    const entry = exact(
      valueEntry,
      ["path", "sha256"],
      `frontend build control ${index}`,
    );
    const expectedPath = HISTORICAL_CLOUDFLARE_D_BUILD_CONTROL_PATHS[index];
    if (canonicalRepoPath(entry.path, `frontend build control ${index} path`)
        !== expectedPath
      || FORBIDDEN_POST_BUILD_AUTHORITY_INPUT.test(entry.path)) {
      fail(`frontend build control ${index} must be the frozen ${expectedPath}`);
    }
    return {
      path: expectedPath,
      sha256: nonzeroSha256(entry.sha256, `frontend build control ${expectedPath}`),
    };
  });
}

export function frontendBuildProjectedEnvSha256(serializedEnv) {
  if (typeof serializedEnv !== "string"
    || serializedEnv.length < 2
    || byteLength(serializedEnv) > MAX_ENV_BYTES
    || serializedEnv.includes("\r")
    || !serializedEnv.endsWith("\n")
    || serializedEnv.includes("\n\n")) {
    fail("frontend build candidate env must be bounded normalized LF bytes");
  }
  if (FORBIDDEN_POST_BUILD_AUTHORITY_INPUT.test(serializedEnv)) {
    fail("signed live authority and post-build receipts cannot be frontend env inputs");
  }
  return rawSha256(serializedEnv);
}

export function normalizeFrontendBuildInputManifest(value) {
  assertGraph(value, "frontend build input manifest");
  const parsed = exact(value, [
    "authority_roots",
    "build_controls",
    "frontend_dist_included",
    "git_source",
    "external_build_closure",
    "pre_D_private_inputs",
    "primary_rpc_url",
    "projected_env_sha256",
    "qvl_verifier_roots",
    "raw_secret_egress",
    "release_sha",
    "schema",
    "secondary_rpc_url",
    "semantic_lineage",
    "truth_status",
  ], "frontend build input manifest");
  if (parsed.schema !== FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA
    || parsed.truth_status !== FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS
    || parsed.frontend_dist_included !== false
    || parsed.raw_secret_egress !== false) {
    fail("frontend build input manifest schema or acyclic truth boundary is invalid");
  }
  const git = exact(parsed.git_source, [
    "clean_worktree",
    "git_tree_oid",
    "source_fingerprint_sha256",
  ], "frontend build Git source");
  if (git.clean_worktree !== true
    || !GIT_TREE_OID.test(String(git.git_tree_oid || ""))) {
    fail("frontend build Git source must be one clean SHA-1 object-format tree");
  }
  const privateInputs = normalizePreDPrivateInputs(parsed.pre_D_private_inputs);
  const semanticLineage = exactDigestRecord(
    parsed.semantic_lineage,
    FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS,
    "frontend build semantic lineage",
  );
  if (new Set(Object.values(semanticLineage)).size
      !== FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS.length) {
    fail("frontend build semantic lineage roots must remain distinct");
  }
  const authorityRoots = exactDigestRecord(
    parsed.authority_roots,
    FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS,
    "frontend build authority roots",
  );
  if (authorityRoots.contract_release_set_sha256
        !== semanticLineage.fresh_contract_deployment_receipt_sha256
    || authorityRoots.cvm_release_set_sha256
        !== semanticLineage.seven_cvm_launch_completion_receipt_sha256
    || authorityRoots.qvl_measurement_policy_set_sha256
        !== semanticLineage.qvl_measurement_policy_set_sha256) {
    fail("frontend build contract, CVM, or QVL root drifted from semantic lineage");
  }
  const rpc = distinctPublicHttpsEndpoints(
    parsed.primary_rpc_url,
    parsed.secondary_rpc_url,
  );
  if (rpc.primary !== CANONICAL_PRIMARY_RPC) {
    fail(`frontend build primary RPC must equal ${CANONICAL_PRIMARY_RPC}`);
  }
  if (!Array.isArray(parsed.qvl_verifier_roots)
    || parsed.qvl_verifier_roots.length !== 5) {
    fail("frontend build input manifest requires exactly five verifier roots");
  }
  const verifierRoots = parsed.qvl_verifier_roots.map((entry, index) =>
    address(entry, `frontend build verifier root ${index}`));
  for (let index = 1; index < verifierRoots.length; index += 1) {
    if (verifierRoots[index - 1] >= verifierRoots[index]) {
      fail("frontend build verifier roots must be strictly sorted and distinct");
    }
  }
  return freeze({
    schema: FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
    truth_status: FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
    release_sha: releaseSha(parsed.release_sha, "frontend build release SHA"),
    git_source: {
      clean_worktree: true,
      git_tree_oid: git.git_tree_oid,
      source_fingerprint_sha256: nonzeroSha256(
        git.source_fingerprint_sha256,
        "frontend build source fingerprint",
      ),
    },
    pre_D_private_inputs: privateInputs,
    semantic_lineage: semanticLineage,
    projected_env_sha256: nonzeroSha256(
      parsed.projected_env_sha256,
      "frontend build projected environment digest",
    ),
    primary_rpc_url: rpc.primary,
    secondary_rpc_url: rpc.secondary,
    qvl_verifier_roots: verifierRoots,
    authority_roots: authorityRoots,
    build_controls: normalizeBuildControls(parsed.build_controls),
    external_build_closure:
      normalizeHistoricalCloudflareExternalBuildClosure(
        parsed.external_build_closure,
      ),
    frontend_dist_included: false,
    raw_secret_egress: false,
  }, "normalized frontend build input manifest");
}

export function frontendBuildInputManifestSha256(value) {
  return domainSha256(
    FRONTEND_BUILD_INPUT_MANIFEST_DOMAIN,
    normalizeFrontendBuildInputManifest(value),
  );
}

export function normalizeFrontendBuildCandidateReceipt(value) {
  assertGraph(value, "frontend build candidate receipt");
  const parsed = exact(value, [
    "ceremony_authorization_sha256",
    "chain_id",
    "compute_workload_activation_observation_sha256",
    "deployment_intent_sha256",
    "frontend_build_sha256",
    "raw_secret_egress",
    "release_env_sha256",
    "release_inputs_sha256",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "runtime_authority_dependency_sha256",
    "schema",
    "status",
    "truth_status",
  ], "frontend build candidate receipt");
  if (parsed.schema !== FRONTEND_BUILD_CANDIDATE_SCHEMA
    || parsed.status !== FRONTEND_BUILD_CANDIDATE_STATUS
    || parsed.truth_status !== FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || parsed.raw_secret_egress !== false) {
    fail("frontend build candidate receipt does not carry the exact non-deploy truth label");
  }
  return freeze({
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: releaseSha(parsed.release_sha, "frontend build receipt release SHA"),
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    deployment_intent_sha256: nonzeroSha256(
      parsed.deployment_intent_sha256,
      "frontend build deployment intent digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: nonzeroSha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "frontend build reviewer genesis acceptance digest",
    ),
    ceremony_authorization_sha256: nonzeroSha256(
      parsed.ceremony_authorization_sha256,
      "frontend build ceremony authorization digest",
    ),
    runtime_authority_dependency_sha256: nonzeroSha256(
      parsed.runtime_authority_dependency_sha256,
      "frontend build runtime authority dependency digest",
    ),
    compute_workload_activation_observation_sha256: nonzeroSha256(
      parsed.compute_workload_activation_observation_sha256,
      "frontend build compute-workload activation observation digest",
    ),
    frontend_build_sha256: nonzeroSha256(
      parsed.frontend_build_sha256,
      "frontend build deterministic dist-manifest digest",
    ),
    release_inputs_sha256: nonzeroSha256(
      parsed.release_inputs_sha256,
      "frontend build release-input digest",
    ),
    release_env_sha256: nonzeroSha256(
      parsed.release_env_sha256,
      "frontend build release-env digest",
    ),
    raw_secret_egress: false,
  }, "normalized frontend build candidate receipt");
}

export function frontendBuildCandidateReceiptSha256(value) {
  return domainSha256(
    FRONTEND_BUILD_CANDIDATE_DOMAIN,
    normalizeFrontendBuildCandidateReceipt(value),
  );
}

export function assertFrontendBuildCandidateLineage({
  receipt,
  serializedEnv,
  inputManifest,
  authorityBinding,
}) {
  assertGraph(authorityBinding, "frontend build authenticated authority binding");
  const normalized = normalizeFrontendBuildCandidateReceipt(receipt);
  const manifest = normalizeFrontendBuildInputManifest(inputManifest);
  const binding = exact(authorityBinding, [
    "ceremonyAuthorizationSha256",
    "computeWorkloadActivationObservationSha256",
    "deploymentIntentSha256",
    "frontendBuildSha256",
    "reviewerAuthorityGenesisAcceptanceSha256",
    "runtimeAuthorityDependencySha256",
  ], "frontend build authenticated authority binding");
  const expected = {
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: normalized.release_sha,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    deployment_intent_sha256: nonzeroSha256(
      binding.deploymentIntentSha256,
      "frontend build bound deployment intent",
    ),
    reviewer_authority_genesis_acceptance_sha256: nonzeroSha256(
      binding.reviewerAuthorityGenesisAcceptanceSha256,
      "frontend build bound reviewer genesis acceptance",
    ),
    ceremony_authorization_sha256: nonzeroSha256(
      binding.ceremonyAuthorizationSha256,
      "frontend build bound ceremony authorization",
    ),
    runtime_authority_dependency_sha256: nonzeroSha256(
      binding.runtimeAuthorityDependencySha256,
      "frontend build bound runtime authority",
    ),
    compute_workload_activation_observation_sha256: nonzeroSha256(
      binding.computeWorkloadActivationObservationSha256,
      "frontend build bound compute-workload observation",
    ),
    frontend_build_sha256: nonzeroSha256(
      binding.frontendBuildSha256,
      "frontend build bound dist-manifest",
    ),
    release_inputs_sha256: frontendBuildInputManifestSha256(manifest),
    release_env_sha256: frontendBuildProjectedEnvSha256(serializedEnv),
    raw_secret_egress: false,
  };
  if (manifest.release_sha !== normalized.release_sha
    || manifest.semantic_lineage.deployment_intent_sha256
      !== expected.deployment_intent_sha256
    || manifest.semantic_lineage.reviewer_authority_genesis_acceptance_sha256
      !== expected.reviewer_authority_genesis_acceptance_sha256
    || manifest.semantic_lineage.ceremony_authorization_sha256
      !== expected.ceremony_authorization_sha256
    || manifest.semantic_lineage.runtime_authority_dependency_sha256
      !== expected.runtime_authority_dependency_sha256
    || manifest.semantic_lineage.compute_workload_activation_observation_sha256
      !== expected.compute_workload_activation_observation_sha256
    || manifest.projected_env_sha256 !== expected.release_env_sha256
    || canonicalText(normalized) !== canonicalText(expected)) {
    fail("frontend build candidate receipt does not match the independently reprojected lineage");
  }
  return normalized;
}

function normalizeCandidateTrustDomains(value, expectedReleaseSha) {
  const trust = exact(value, TRUST_DOMAIN_KEYS, "historical release candidate trust domains");
  const output = {};
  for (const key of TRUST_DOMAIN_KEYS) {
    const domain = record(trust[key], `historical release candidate ${key}`);
    if (domain.release_sha !== expectedReleaseSha) {
      fail(`historical release candidate ${key} release SHA drifted`);
    }
    appId(domain.app_id, `historical release candidate ${key} app ID`);
    if (typeof domain.cvm_id !== "string"
      || !/^[a-z0-9][a-z0-9._:-]{7,127}$/.test(domain.cvm_id)) {
      fail(`historical release candidate ${key} CVM ID is invalid`);
    }
    bareWord(domain.compose_hash, `historical release candidate ${key} compose hash`);
    bareWord(domain.os_image_hash, `historical release candidate ${key} OS image hash`);
    const identity = record(domain.identity, `historical release candidate ${key} identity`);
    if (key === "compute_metering") {
      address(identity.metering_verifier, "historical compute-metering signer");
    } else {
      address(identity.verifier_address, `historical release candidate ${key} verifier`);
    }
    output[key] = cloneCanonical(domain);
  }
  return output;
}

/**
 * Normalize the canonical release envelope used by historical exact-37 replay.
 *
 * Stable on-chain/CVM facts are fully normalized again by the independently
 * supplied final release authority core in
 * validateHistoricalFinalReleaseAuthorityCoreBinding. Trust-domain and
 * external-attestation semantics remain separate proof layers; this function
 * authenticates their canonical shape and the fields used by C/D projection.
 */
export function normalizeHistoricalFrontendReleaseCandidate(value, {
  authorityStage = "live",
} = {}) {
  assertGraph(value, "historical frontend release candidate");
  const parsed = exact(value, RELEASE_CANDIDATE_KEYS, "historical frontend release candidate");
  if (parsed.schema !== HISTORICAL_FRONTEND_RELEASE_CANDIDATE_SCHEMA) {
    fail("historical frontend release candidate schema is invalid");
  }
  const sha = releaseSha(parsed.release_sha, "historical release SHA");
  const network = exact(parsed.network, ["chain_id", "public_rpc_url"], "historical release network");
  if (network.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || network.public_rpc_url !== CANONICAL_PRIMARY_RPC) {
    fail("historical release candidate is not pinned to canonical Base Sepolia");
  }
  address(parsed.operator_address, "historical release operator");
  nonzeroSha256(parsed.deployment_intent_sha256, "historical deployment intent");
  nonzeroSha256(parsed.cvm_launch_intent_sha256, "historical CVM launch intent");
  const policyFields = authorityStage === "live"
    ? [
      "ceremony_authorization_sha256",
      "live_activation_authority_sha256",
      "runtime_authority_dependency_sha256",
      "schema",
    ]
    : [
      "ceremony_authorization_sha256",
      "runtime_authority_dependency_sha256",
      "schema",
    ];
  const policy = exact(parsed.operator_policy, policyFields, "historical release operator policy");
  const expectedPolicySchema = authorityStage === "live"
    ? HISTORICAL_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA
    : HISTORICAL_PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  if (policy.schema !== expectedPolicySchema) {
    fail("historical release operator policy stage is invalid");
  }
  nonzeroSha256(policy.ceremony_authorization_sha256, "historical signed B digest");
  nonzeroSha256(policy.runtime_authority_dependency_sha256, "historical R digest");
  if (authorityStage === "live") {
    nonzeroSha256(policy.live_activation_authority_sha256, "historical signed C digest");
  } else if (authorityStage !== "prebuild") {
    fail("historical release authority stage must be live or prebuild");
  }
  exact(parsed.contracts, CONTRACT_KEYS, "historical release candidate contracts");
  record(parsed.cvm, "historical release candidate main CVM");
  appId(parsed.cvm.app_id, "historical main-runtime app ID");
  if (typeof parsed.cvm.cvm_id !== "string"
    || !/^[a-z0-9][a-z0-9._:-]{7,127}$/.test(parsed.cvm.cvm_id)) {
    fail("historical main-runtime CVM ID is invalid");
  }
  bareWord(parsed.cvm.compose_hash, "historical main-runtime compose hash");
  address(parsed.cvm.tee_identity, "historical main-runtime TEE identity");
  exact(parsed.attestations, [
    "artifact",
    "arena",
    "compute_metering",
  ], "historical release candidate attestations");
  const normalized = {
    schema: HISTORICAL_FRONTEND_RELEASE_CANDIDATE_SCHEMA,
    release_sha: sha,
    network: cloneCanonical(network),
    operator_address: parsed.operator_address,
    deployment_intent_sha256: parsed.deployment_intent_sha256,
    cvm_launch_intent_sha256: parsed.cvm_launch_intent_sha256,
    operator_policy: cloneCanonical(policy),
    contracts: cloneCanonical(parsed.contracts),
    cvm: cloneCanonical(parsed.cvm),
    trust_domains: normalizeCandidateTrustDomains(parsed.trust_domains, sha),
    wallet_auth: cloneCanonical(record(parsed.wallet_auth, "historical wallet auth")),
    execution_policy: cloneCanonical(record(parsed.execution_policy, "historical execution policy")),
    attestations: cloneCanonical(parsed.attestations),
    arena_registry_bindings: cloneCanonical(record(
      parsed.arena_registry_bindings,
      "historical Arena registry bindings",
    )),
    requested_features: cloneCanonical(record(
      parsed.requested_features,
      "historical requested features",
    )),
  };
  return freeze(normalized, "normalized historical frontend release candidate");
}

export function projectHistoricalLiveReleaseCandidateToPrebuild(value) {
  const candidate = normalizeHistoricalFrontendReleaseCandidate(value, {
    authorityStage: "live",
  });
  return freeze({
    ...cloneCanonical(candidate),
    operator_policy: {
      schema: HISTORICAL_PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
      ceremony_authorization_sha256:
        candidate.operator_policy.ceremony_authorization_sha256,
      runtime_authority_dependency_sha256:
        candidate.operator_policy.runtime_authority_dependency_sha256,
    },
  }, "historical live release candidate prebuild projection");
}

export function historicalLiveReleaseCandidatePrebuildProjectionSha256(value) {
  return rawSha256(canonicalText(projectHistoricalLiveReleaseCandidateToPrebuild(value)));
}

function projectContracts(contractsValue, cvmValue) {
  const contracts = record(contractsValue, "historical release candidate contracts");
  const cvm = record(cvmValue, "historical release candidate main CVM");
  const diligence = record(contracts.diligence_room, "historical DiligenceRoom descriptor");
  const challenge = record(contracts.challenge_registry, "historical ChallengeRegistry descriptor");
  const royalty = record(contracts.royalty_distributor, "historical RoyaltyDistributor descriptor");
  const encumbrance = record(contracts.tinker_account_encumbrance, "historical TinkerAccountEncumbrance descriptor");
  const compute = record(contracts.compute_credit_vault, "historical ComputeCreditVault descriptor");
  const email = record(contracts.email_oracle_auth, "historical EmailOracleAuth descriptor");
  const usdc = record(contracts.usdc, "historical USDC descriptor");
  return {
    diligence_room: {
      address: diligence.address,
      runtime_code_hash: diligence.runtime_code_hash,
      developer: diligence.developer,
      result_verifier: diligence.result_verifier,
      attestation_verifier: diligence.attestation_verifier,
      attestation_release_policy_hash: diligence.attestation_release_policy_hash,
      attestation_binding_frozen: diligence.attestation_binding_frozen,
      evaluator_policy_commitments: diligence.evaluator_policy_commitments,
      evaluator_policy_set_root: diligence.evaluator_policy_set_root,
      release_admission: {
        tee_identity: cvm.tee_identity,
        compose_hash: cvm.compose_hash,
        approved_tee_identity_count: 1,
        approved_compose_count: 1,
        additions_frozen: true,
      },
    },
    challenge_registry: {
      address: challenge.address,
      runtime_code_hash: challenge.runtime_code_hash,
      owner: challenge.owner,
      pending_owner: challenge.pending_owner,
      registry_paused: challenge.registry_paused,
      minimum_version_review_delay_seconds:
        challenge.minimum_version_review_delay_seconds,
      expected_challenge_count: challenge.expected_challenge_count,
    },
    royalty_distributor: {
      address: royalty.address,
      runtime_code_hash: royalty.runtime_code_hash,
    },
    tinker_account_encumbrance: cloneCanonical(encumbrance),
    compute_credit_vault: {
      address: compute.address,
      runtime_code_hash: compute.runtime_code_hash,
      owner: compute.owner,
      developer: compute.developer,
      metering_verifier: compute.metering_verifier,
      metering_qvl_verifier: compute.metering_qvl_verifier,
      metering_policy_set_hash: compute.metering_policy_set_hash,
      metering_binding_frozen: compute.metering_binding_frozen,
      developer_fee_bps: compute.developer_fee_bps,
      tee_identity: compute.tee_identity,
      compose_hash: compute.compose_hash,
      rate_policies: {
        native: {
          commitment: compute.native_rate_policy_commitment,
          asset: "0x0000000000000000000000000000000000000000",
          provider: compute.native_provider,
          developer_fee_bps: compute.developer_fee_bps,
        },
        erc20: {
          commitment: compute.erc20_rate_policy_commitment,
          asset: compute.erc20_asset_address,
          provider: compute.erc20_provider,
          developer_fee_bps: compute.developer_fee_bps,
        },
      },
    },
    email_oracle_auth: {
      address: email.address,
      runtime_code_hash: email.runtime_code_hash,
      owner: email.owner,
      consumer_address: email.consumer_address,
      upgrade_delay_seconds: email.upgrade_delay_seconds,
      release: {
        ...cloneCanonical(record(email.release, "historical EmailOracleAuth release descriptor")),
        oracle_compose_hash: `0x${cvm.compose_hash}`,
        consumer_compose_hash: `0x${cvm.compose_hash}`,
      },
    },
    usdc: cloneCanonical(usdc),
  };
}

function projectCvm(value) {
  const cvm = record(value, "historical release candidate main CVM");
  return {
    app_id: cvm.app_id,
    cvm_id: cvm.cvm_id,
    compose_hash: cvm.compose_hash,
    local_compose_hash: cvm.local_compose_hash,
    rendered_compose_sha256: cvm.rendered_compose_sha256,
    os_image_hash: cvm.os_image_hash,
    os_is_dev: cvm.os_is_dev,
    public_logs: cvm.public_logs,
    public_sysinfo: cvm.public_sysinfo,
    public_tcbinfo: cvm.public_tcbinfo,
    tee_identity: cvm.tee_identity,
    delegate_url: cvm.delegate_url,
    images: cvm.images,
    allowed_browser_origins: cvm.allowed_browser_origins,
    compute_workload_ingress: cvm.compute_workload_ingress,
    runtime_controls: cvm.runtime_controls,
  };
}

function projectExecutionPolicy(value) {
  const policy = record(value, "historical release candidate execution policy");
  const anchor = record(policy.rollback_anchor, "historical release candidate rollback anchor");
  return {
    canonicalization_version: policy.canonicalization_version,
    approval_schema: policy.approval_schema,
    api_schema_version: policy.api_schema_version,
    store_schema_version: policy.store_schema_version,
    approver_hashes: policy.approver_hashes,
    approver_root_hash: policy.approver_root_hash,
    rollback_anchor_target: {
      schema: anchor.schema,
      chain_id: anchor.chain_id,
      contract_address: anchor.contract_address,
      runtime_code_hash: anchor.runtime_code_hash,
      writer_address: anchor.writer_address,
      writer_release_commitment: anchor.writer_release_commitment,
      writer_custody: anchor.writer_custody,
      writer_key_path: anchor.writer_key_path,
      confirmations: anchor.confirmations,
      max_block_age_seconds: anchor.max_block_age_seconds,
      max_future_block_skew_seconds: anchor.max_future_block_skew_seconds,
      verification_model: anchor.verification_model,
      independent_rpc_quorum_verified: anchor.independent_rpc_quorum_verified,
      consensus_proof_verified: anchor.consensus_proof_verified,
    },
  };
}

export function finalReleaseAuthorityCoreFromHistoricalCandidate(candidateValue) {
  const candidate = normalizeHistoricalFrontendReleaseCandidate(candidateValue, {
    authorityStage: "live",
  });
  assertGraph(candidate, "normalized historical release candidate");
  return normalizeFinalReleaseAuthorityCore({
    schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    release_sha: candidate.release_sha,
    network: candidate.network,
    operator_address: candidate.operator_address,
    deployment_intent_sha256: candidate.deployment_intent_sha256,
    cvm_launch_intent_sha256: candidate.cvm_launch_intent_sha256,
    contracts: projectContracts(candidate.contracts, candidate.cvm),
    cvm: projectCvm(candidate.cvm),
    arena_registry_bindings: candidate.arena_registry_bindings,
    wallet_auth: candidate.wallet_auth,
    requested_features: candidate.requested_features,
    execution_policy: projectExecutionPolicy(candidate.execution_policy),
  });
}

export function historicalFinalReleaseAuthorityCoreSha256(value) {
  assertGraph(value, "historical final release authority core");
  return `sha256:${finalReleaseAuthorityCoreDigest(value)}`;
}

export function validateHistoricalFinalReleaseAuthorityCoreBinding({
  candidateValue,
  coreValue,
  runtimeAuthorityValue,
  authenticatedRuntimeAuthoritySha256,
}) {
  assertGraph(coreValue, "historical final release authority core");
  assertGraph(runtimeAuthorityValue, "authenticated historical R value");
  const candidate = normalizeHistoricalFrontendReleaseCandidate(candidateValue, {
    authorityStage: "live",
  });
  const suppliedCore = normalizeFinalReleaseAuthorityCore(coreValue);
  const projectedCore = finalReleaseAuthorityCoreFromHistoricalCandidate(candidate);
  const suppliedBytes = canonicalFinalReleaseAuthorityCoreBytes(suppliedCore);
  const projectedBytes = canonicalFinalReleaseAuthorityCoreBytes(projectedCore);
  if (suppliedBytes.length !== projectedBytes.length
    || !suppliedBytes.equals(projectedBytes)) {
    fail("final release authority core does not exactly match the final release candidate's pre-anchor facts");
  }
  const runtime = record(runtimeAuthorityValue, "authenticated historical R value");
  const runtimeSha256 = nonzeroSha256(
    authenticatedRuntimeAuthoritySha256,
    "authenticated historical R digest",
  );
  if (runtime.release_sha !== suppliedCore.release_sha
    || runtime.deployment_intent_sha256 !== suppliedCore.deployment_intent_sha256
    || runtime.cvm_launch_intent_sha256 !== suppliedCore.cvm_launch_intent_sha256) {
    fail("authenticated historical R does not match the release/deployment/CVM-launch lineage");
  }
  const coreSha256 = historicalFinalReleaseAuthorityCoreSha256(suppliedCore);
  if (runtimeSha256 === coreSha256) {
    fail("release core and R must remain distinct domain roots");
  }
  if (candidate.operator_policy.runtime_authority_dependency_sha256 !== runtimeSha256
    || candidate.execution_policy.rollback_anchor.release_manifest_commitment
      !== runtimeSha256.slice("sha256:".length)
    || candidate.execution_policy.rollback_anchor.writer_release_commitment
      !== `0x${suppliedCore.cvm_launch_intent_sha256.slice("sha256:".length)}`) {
    fail("candidate execution policy does not exact-bind authenticated R and the reviewed launch intent");
  }
  return freeze({
    candidate,
    core: suppliedCore,
    coreSha256,
    runtimeAuthoritySha256: runtimeSha256,
  }, "historical final release authority core binding");
}

export function assertHistoricalLiveActivationFinalCvmsMatchCandidate(
  liveActivationFrontendBinding,
  candidateValue,
) {
  assertGraph(liveActivationFrontendBinding, "historical signed-C frontend binding");
  const frontendBinding = normalizeHistoricalLiveActivationFrontendBinding(
    liveActivationFrontendBinding,
  );
  const candidate = normalizeHistoricalFrontendReleaseCandidate(candidateValue, {
    authorityStage: "live",
  });
  if (frontendBinding.release_sha !== candidate.release_sha
    || frontendBinding.deployment_intent_sha256
      !== candidate.deployment_intent_sha256
    || frontendBinding.ceremony_authorization_sha256
      !== candidate.operator_policy.ceremony_authorization_sha256
    || frontendBinding.runtime_authority_dependency_sha256
      !== candidate.operator_policy.runtime_authority_dependency_sha256
    || frontendBinding.live_activation_authority_sha256
      !== candidate.operator_policy.live_activation_authority_sha256) {
    fail("signed live activation frontend binding does not match the candidate release, B, R, and C roots");
  }
  return assertHistoricalFinalCvmTopologyMatchesCandidate(
    frontendBinding.final_cvms,
    candidate,
  );
}

/**
 * Replay only the seven-CVM identity portion of signed C against a normalized
 * historical release candidate. This is intentionally nonauthorizing: callers
 * that need the signed-C roots must use
 * assertHistoricalLiveActivationFinalCvmsMatchCandidate above.
 */
export function assertHistoricalFinalCvmTopologyMatchesCandidate(
  finalCvmsValue,
  candidateValue,
) {
  assertGraph(finalCvmsValue, "historical signed-C final CVM topology");
  const candidate = normalizeHistoricalFrontendReleaseCandidate(candidateValue, {
    authorityStage: "live",
  });
  const finalCvms = finalCvmsValue;
  const topology = [
    ["main_runtime_cvm", candidate.cvm, candidate.cvm.tee_identity],
    ["diligence_qvl_cvm", candidate.trust_domains.diligence_qvl,
      candidate.trust_domains.diligence_qvl.identity.verifier_address],
    ["arena_qvl_cvm", candidate.trust_domains.arena_qvl,
      candidate.trust_domains.arena_qvl.identity.verifier_address],
    ["anchor_writer_qvl_cvm", candidate.trust_domains.anchor_writer_qvl,
      candidate.trust_domains.anchor_writer_qvl.identity.verifier_address],
    ["compute_workload_qvl_cvm", candidate.trust_domains.compute_workload_qvl,
      candidate.trust_domains.compute_workload_qvl.identity.verifier_address],
    ["compute_metering_qvl_cvm", candidate.trust_domains.compute_metering_qvl,
      candidate.trust_domains.compute_metering_qvl.identity.verifier_address],
    ["independent_metering_cvm", candidate.trust_domains.compute_metering,
      candidate.trust_domains.compute_metering.identity.metering_verifier],
  ];
  if (!Array.isArray(finalCvms) || finalCvms.length !== topology.length) {
    fail("signed live activation does not contain the exact seven-CVM topology");
  }
  const evidence = [];
  for (const [index, [key, descriptor, teeIdentity]] of topology.entries()) {
    const observed = exact(finalCvms[index], [
      "app_id",
      "attestation_evidence_sha256",
      "compose_hash_sha256",
      "cvm_id",
      "cvm_key",
      "tee_identity",
    ], `historical signed-C final CVM ${index}`);
    if (observed.cvm_key !== key
      || observed.app_id !== descriptor.app_id
      || observed.cvm_id !== descriptor.cvm_id
      || observed.compose_hash_sha256 !== `sha256:${descriptor.compose_hash}`
      || observed.tee_identity !== teeIdentity) {
      fail(`signed live activation ${key} identity does not match the normalized historical release candidate`);
    }
    evidence.push(nonzeroSha256(
      observed.attestation_evidence_sha256,
      `historical signed-C ${key} attestation evidence`,
    ));
  }
  if (new Set(evidence).size !== evidence.length) {
    fail("signed live activation must bind distinct attestation evidence for all seven CVMs");
  }
  return true;
}

export const __historicalFrontendReleaseCoreTest = Object.freeze({
  EXTERNAL_AGGREGATE_DOMAIN,
  EXTERNAL_ENTRYPOINTS,
  EXTERNAL_FILES,
  MAX_ENV_BYTES,
});
