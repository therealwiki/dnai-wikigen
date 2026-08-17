import { createHash } from "node:crypto";
import path from "node:path";

import {
  exactDistinctPublicHttpsEndpoints,
} from "./public-https-origin-core.mjs";
import {
  CLOUDFLARE_D_BUILD_CONTROL_PATHS,
} from "./cloudflare-release-artifact-core.mjs";
import {
  normalizeCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";

export const FRONTEND_BUILD_CANDIDATE_SCHEMA =
  "dnai.frontend-build-candidate.v3";
export const FRONTEND_BUILD_CANDIDATE_STATUS =
  "pre_live_activation_candidate";
export const FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS =
  "pre_live_activation_candidate_not_deploy_authority";
export const FRONTEND_BUILD_CANDIDATE_DOMAIN =
  "dnai-wikigen/frontend-build-candidate/v3\0";
export const FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA =
  "dnai.frontend-build-candidate-input-manifest.v3";
export const FRONTEND_BUILD_INPUT_MANIFEST_DOMAIN =
  "dnai-wikigen/frontend-build-candidate-input-manifest/v3\0";
export const FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS =
  "deterministic_pre_D_inputs_including_independent_H_excluding_signed_C_D_and_dist_not_deploy_authority";

export const FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION =
  "live_candidate_prebuild_projection_v1";
export const FRONTEND_BUILD_RAW_INPUT_PROJECTION =
  "raw_canonical_file_bytes";

// D is produced before separately signed C and cannot commit either its own
// bytes or the final live candidate bytes (the latter embeds C's digest).
// Every other exact validator input is committed by its stable raw bytes. The
// final validator independently projects --release back to its canonical
// prebuild form and reproduces the first entry.
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
  "--royalty-release-history-receipt",
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
  "royalty_release_history_sha256",
  "royalty_release_history_receipt_sha256",
  "compute_workload_activation_observation_sha256",
]);

export const FRONTEND_BUILD_ROYALTY_RELEASE_HISTORY_FIELDS = Object.freeze([
  "history_receipt_raw_sha256",
  "history_sha256",
  "receipt_sha256",
]);

export const FRONTEND_BUILD_AUTHORITY_ROOT_FIELDS = Object.freeze([
  "contract_release_set_sha256",
  "cvm_release_set_sha256",
  "qvl_measurement_policy_set_sha256",
]);

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const CANONICAL_PRIMARY_RPC = "https://sepolia.base.org";
const SHA40 = /^[0-9a-f]{40}$/;
const GIT_TREE_OID = /^sha1:[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const MAX_ENV_BYTES = 128 * 1024;
const FORBIDDEN_POST_BUILD_AUTHORITY_INPUT =
  /(?:live[-_]activation[-_]authority|semantic[-_]live[-_]activation|frontend[-_]build[-_]candidate[-_]receipt|compute[-_]workload[-_]activation[-_]observation)/i;

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function sha256(value, label) {
  if (!SHA256.test(String(value || "")) || value === ZERO_SHA256) {
    fail(`${label} must be a nonzero sha256:<64 lowercase hex> pin`);
  }
  return value;
}

function repoRelativePosixPath(value, label) {
  if (
    typeof value !== "string"
    || value.length < 1
    || value.length > 512
    || value.startsWith("/")
    || value.startsWith("./")
    || value.endsWith("/")
    || value.includes("\\")
    || value.includes("\0")
    || value.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    fail(`${label} must be a canonical repo-relative POSIX path`);
  }
  return value;
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function hashWithDomain(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

export function frontendBuildProjectedEnvSha256(serializedEnv) {
  if (
    typeof serializedEnv !== "string"
    || serializedEnv.length < 2
    || Buffer.byteLength(serializedEnv, "utf8") > MAX_ENV_BYTES
    || serializedEnv.includes("\r")
    || !serializedEnv.endsWith("\n")
    || serializedEnv.includes("\n\n")
  ) {
    fail("frontend build candidate env must be bounded normalized LF bytes");
  }
  if (FORBIDDEN_POST_BUILD_AUTHORITY_INPUT.test(serializedEnv)) {
    fail("signed live authority and post-build receipts cannot be frontend env inputs");
  }
  return `sha256:${createHash("sha256").update(serializedEnv, "utf8").digest("hex")}`;
}

function exactDigestRecord(value, fields, label) {
  const parsed = exact(value, fields, label);
  return Object.fromEntries(fields.map((field) => [
    field,
    sha256(parsed[field], `${label} ${field}`),
  ]));
}

function normalizePreDPrivateInputs(value) {
  if (!Array.isArray(value)
    || value.length !== FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS.length) {
    fail("frontend build manifest requires the exact acyclic pre-D private input set");
  }
  const normalized = value.map((entry, index) => {
    const parsed = exact(
      entry,
      ["flag", "projection", "sha256"],
      `frontend build private input ${index}`,
    );
    const expectedFlag = FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS[index];
    if (parsed.flag !== expectedFlag) {
      fail(`frontend build private input ${index} must be ${expectedFlag}`);
    }
    const expectedProjection = expectedFlag === "--release"
      ? FRONTEND_BUILD_LIVE_CANDIDATE_PROJECTION
      : FRONTEND_BUILD_RAW_INPUT_PROJECTION;
    if (parsed.projection !== expectedProjection) {
      fail(`frontend build private input ${expectedFlag} uses an invalid projection`);
    }
    if (FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS.includes(parsed.flag)) {
      fail("frontend build manifest cannot include raw C or D inputs");
    }
    return {
      flag: expectedFlag,
      projection: expectedProjection,
      sha256: sha256(parsed.sha256, `frontend build private input ${expectedFlag}`),
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
  if (!isRecord(rawSha256ByFlag)) {
    fail("frontend build raw private inputs must be an exact flag-to-digest record");
  }
  const actualFlags = Object.keys(rawSha256ByFlag).sort();
  const expectedFlags = [...FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS].sort();
  if (JSON.stringify(actualFlags) !== JSON.stringify(expectedFlags)) {
    fail("frontend build raw private inputs contain an omission, extra, release, C, or D input");
  }
  return normalizePreDPrivateInputs([
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
  ]);
}

function normalizeBuildControls(value) {
  if (!Array.isArray(value)
    || value.length !== CLOUDFLARE_D_BUILD_CONTROL_PATHS.length) {
    fail("frontend build manifest requires the exact Cloudflare build-control file set");
  }
  return value.map((entry, index) => {
    const parsed = exact(
      entry,
      ["path", "sha256"],
      `frontend build control ${index}`,
    );
    const expectedPath = CLOUDFLARE_D_BUILD_CONTROL_PATHS[index];
    const inputPath = repoRelativePosixPath(
      parsed.path,
      `frontend build control ${index} path`,
    );
    if (inputPath !== expectedPath) {
      fail(`frontend build control ${index} must be ${expectedPath}`);
    }
    if (FORBIDDEN_POST_BUILD_AUTHORITY_INPUT.test(inputPath)) {
      fail("signed live authority and post-build receipts cannot be build-control inputs");
    }
    return {
      path: expectedPath,
      sha256: sha256(parsed.sha256, `frontend build control ${expectedPath}`),
    };
  });
}

export function frontendBuildInputFile({ repoRoot, filePath, bytes }) {
  if (
    typeof repoRoot !== "string"
    || !path.isAbsolute(repoRoot)
    || path.resolve(repoRoot) !== repoRoot
    || path.normalize(repoRoot) !== repoRoot
    || typeof filePath !== "string"
    || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath
    || path.normalize(filePath) !== filePath
  ) {
    fail("frontend build input paths must be canonical absolute paths before projection");
  }
  const relative = path.relative(repoRoot, filePath).split(path.sep).join("/");
  const projectedPath = repoRelativePosixPath(relative, "frontend build input file path");
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 4 * 1024 * 1024) {
    fail("frontend build input file bytes are missing or unbounded");
  }
  return Object.freeze({
    path: projectedPath,
    sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
  });
}

export function normalizeFrontendBuildInputManifest(value) {
  const parsed = exact(value, [
    "authority_roots", "build_controls", "frontend_dist_included", "git_source",
    "external_build_closure", "pre_D_private_inputs", "primary_rpc_url",
    "projected_env_sha256", "qvl_verifier_roots", "raw_secret_egress",
    "release_sha", "royalty_release_history", "schema", "secondary_rpc_url", "semantic_lineage",
    "truth_status",
  ], "frontend build input manifest");
  if (parsed.schema !== FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA
    || parsed.truth_status !== FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS
    || !SHA40.test(String(parsed.release_sha || ""))
    || parsed.frontend_dist_included !== false
    || parsed.raw_secret_egress !== false) {
    fail("frontend build input manifest schema or acyclic truth boundary is invalid");
  }
  const gitSource = exact(parsed.git_source, [
    "clean_worktree", "git_tree_oid", "source_fingerprint_sha256",
  ], "frontend build Git source");
  if (gitSource.clean_worktree !== true
    || !GIT_TREE_OID.test(String(gitSource.git_tree_oid || ""))) {
    fail("frontend build Git source must be one clean SHA-1 object-format tree");
  }
  const source = {
    clean_worktree: true,
    git_tree_oid: gitSource.git_tree_oid,
    source_fingerprint_sha256: sha256(
      gitSource.source_fingerprint_sha256,
      "frontend build source fingerprint",
    ),
  };
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
  const royaltyReleaseHistory = exactDigestRecord(
    parsed.royalty_release_history,
    FRONTEND_BUILD_ROYALTY_RELEASE_HISTORY_FIELDS,
    "frontend build Royalty release history binding",
  );
  const royaltyReceiptInput = privateInputs.find(
    (entry) => entry.flag === "--royalty-release-history-receipt",
  );
  if (!royaltyReceiptInput
    || royaltyReleaseHistory.history_receipt_raw_sha256 !== royaltyReceiptInput.sha256
    || royaltyReleaseHistory.history_sha256
      !== semanticLineage.royalty_release_history_sha256
    || royaltyReleaseHistory.receipt_sha256
      !== semanticLineage.royalty_release_history_receipt_sha256
    || new Set(Object.values(royaltyReleaseHistory)).size
      !== FRONTEND_BUILD_ROYALTY_RELEASE_HISTORY_FIELDS.length) {
    fail("frontend build Royalty H raw bytes, receipt digest, and history digest are not exact-bound");
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
  const buildControls = normalizeBuildControls(parsed.build_controls);
  let externalBuildClosure;
  try {
    externalBuildClosure = normalizeCloudflareExternalBuildClosure(
      parsed.external_build_closure,
    );
  } catch (error) {
    fail(`frontend build external closure is invalid: ${error.message}`);
  }

  let rpc;
  try {
    rpc = exactDistinctPublicHttpsEndpoints(
      parsed.primary_rpc_url,
      parsed.secondary_rpc_url,
      {
        primaryLabel: "frontend build primary RPC",
        secondaryLabel: "frontend build secondary RPC",
      },
    );
  } catch (error) {
    fail(`frontend build candidate RPC endpoints are invalid: ${error.message}`);
  }
  if (rpc.primary !== CANONICAL_PRIMARY_RPC) {
    fail(`frontend build primary RPC must equal ${CANONICAL_PRIMARY_RPC}`);
  }

  if (!Array.isArray(parsed.qvl_verifier_roots)
    || parsed.qvl_verifier_roots.length !== 5) {
    fail("frontend build input manifest requires exactly five verifier roots");
  }
  const verifierRoots = parsed.qvl_verifier_roots.map((value, index) => {
    if (!ADDRESS.test(String(value || "")) || /^0x0+$/.test(value)) {
      fail(`frontend build verifier root ${index} must be a nonzero lowercase address`);
    }
    return value;
  });
  for (let index = 1; index < verifierRoots.length; index += 1) {
    if (verifierRoots[index - 1] >= verifierRoots[index]) {
      fail("frontend build verifier roots must be strictly sorted and distinct");
    }
  }

  return {
    schema: FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
    truth_status: FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
    release_sha: parsed.release_sha,
    git_source: source,
    pre_D_private_inputs: privateInputs,
    semantic_lineage: semanticLineage,
    royalty_release_history: royaltyReleaseHistory,
    projected_env_sha256: sha256(
      parsed.projected_env_sha256,
      "frontend build projected environment digest",
    ),
    primary_rpc_url: rpc.primary,
    secondary_rpc_url: rpc.secondary,
    qvl_verifier_roots: verifierRoots,
    authority_roots: authorityRoots,
    build_controls: buildControls,
    external_build_closure: externalBuildClosure,
    frontend_dist_included: false,
    raw_secret_egress: false,
  };
}

export function createFrontendBuildInputManifest({
  releaseSha,
  gitTreeOid,
  sourceFingerprintSha256,
  preDPrivateInputs,
  semanticLineage,
  royaltyReleaseHistoryBinding,
  serializedEnv,
  primaryRpcUrl,
  secondaryRpcUrl,
  qvlVerifierRoots,
  authorityRoots,
  buildControls,
  externalBuildClosure,
}) {
  return normalizeFrontendBuildInputManifest({
    schema: FRONTEND_BUILD_INPUT_MANIFEST_SCHEMA,
    truth_status: FRONTEND_BUILD_INPUT_MANIFEST_TRUTH_STATUS,
    release_sha: releaseSha,
    git_source: {
      clean_worktree: true,
      git_tree_oid: gitTreeOid,
      source_fingerprint_sha256: sourceFingerprintSha256,
    },
    pre_D_private_inputs: preDPrivateInputs,
    semantic_lineage: semanticLineage,
    royalty_release_history: royaltyReleaseHistoryBinding,
    projected_env_sha256: frontendBuildProjectedEnvSha256(serializedEnv),
    primary_rpc_url: primaryRpcUrl,
    secondary_rpc_url: secondaryRpcUrl,
    qvl_verifier_roots: qvlVerifierRoots,
    authority_roots: authorityRoots,
    build_controls: buildControls,
    external_build_closure: externalBuildClosure,
    frontend_dist_included: false,
    raw_secret_egress: false,
  });
}

export function canonicalFrontendBuildInputManifestText(value) {
  return canonicalText(normalizeFrontendBuildInputManifest(value));
}

export function frontendBuildInputManifestSha256(value) {
  return hashWithDomain(
    FRONTEND_BUILD_INPUT_MANIFEST_DOMAIN,
    normalizeFrontendBuildInputManifest(value),
  );
}

export function createFrontendBuildCandidateReceipt({
  releaseSha,
  serializedEnv,
  deploymentIntentSha256,
  reviewerAuthorityGenesisAcceptanceSha256,
  ceremonyAuthorizationSha256,
  runtimeAuthorityDependencySha256,
  computeWorkloadActivationObservationSha256,
  frontendBuildSha256,
  inputManifest,
}) {
  if (!SHA40.test(String(releaseSha || ""))) {
    fail("frontend build candidate requires a full lowercase release SHA");
  }
  const normalizedInputManifest = normalizeFrontendBuildInputManifest(inputManifest);
  const observationSha256 = sha256(
    computeWorkloadActivationObservationSha256,
    "frontend build compute-workload activation observation digest",
  );
  const deploymentIntent = sha256(
    deploymentIntentSha256,
    "frontend build deployment intent digest",
  );
  const reviewerAcceptance = sha256(
    reviewerAuthorityGenesisAcceptanceSha256,
    "frontend build reviewer genesis acceptance digest",
  );
  const ceremonyAuthorization = sha256(
    ceremonyAuthorizationSha256,
    "frontend build ceremony authorization digest",
  );
  const runtimeAuthority = sha256(
    runtimeAuthorityDependencySha256,
    "frontend build runtime authority dependency digest",
  );
  const projectedEnvSha256 = frontendBuildProjectedEnvSha256(serializedEnv);
  if (normalizedInputManifest.release_sha !== releaseSha
    || normalizedInputManifest.semantic_lineage.deployment_intent_sha256
      !== deploymentIntent
    || normalizedInputManifest.semantic_lineage
      .reviewer_authority_genesis_acceptance_sha256 !== reviewerAcceptance
    || normalizedInputManifest.semantic_lineage.ceremony_authorization_sha256
      !== ceremonyAuthorization
    || normalizedInputManifest.semantic_lineage.runtime_authority_dependency_sha256
      !== runtimeAuthority
    || normalizedInputManifest.semantic_lineage
      .compute_workload_activation_observation_sha256 !== observationSha256
    || normalizedInputManifest.projected_env_sha256 !== projectedEnvSha256) {
    fail("frontend build input manifest does not exact-bind the release, L-R-B-O lineage, and projected environment");
  }
  return normalizeFrontendBuildCandidateReceipt({
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: releaseSha,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    deployment_intent_sha256: deploymentIntent,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAcceptance,
    ceremony_authorization_sha256: ceremonyAuthorization,
    runtime_authority_dependency_sha256: runtimeAuthority,
    royalty_release_history_sha256:
      normalizedInputManifest.royalty_release_history.history_sha256,
    royalty_release_history_receipt_sha256:
      normalizedInputManifest.royalty_release_history.receipt_sha256,
    compute_workload_activation_observation_sha256: observationSha256,
    frontend_build_sha256: sha256(
      frontendBuildSha256,
      "frontend build deterministic dist-manifest digest",
    ),
    release_inputs_sha256: frontendBuildInputManifestSha256(normalizedInputManifest),
    release_env_sha256: projectedEnvSha256,
    raw_secret_egress: false,
  });
}

export function normalizeFrontendBuildCandidateReceipt(value) {
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "chain_id",
    "compute_workload_activation_observation_sha256", "deployment_intent_sha256",
    "frontend_build_sha256", "raw_secret_egress", "release_env_sha256", "release_inputs_sha256",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256", "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256",
    "runtime_authority_dependency_sha256", "schema", "status", "truth_status",
  ], "frontend build candidate receipt");
  if (
    parsed.schema !== FRONTEND_BUILD_CANDIDATE_SCHEMA
    || parsed.status !== FRONTEND_BUILD_CANDIDATE_STATUS
    || parsed.truth_status !== FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS
    || !SHA40.test(String(parsed.release_sha || ""))
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || parsed.raw_secret_egress !== false
  ) {
    fail("frontend build candidate receipt does not carry the exact non-deploy truth label");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "frontend build deployment intent digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: sha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "frontend build reviewer genesis acceptance digest",
    ),
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "frontend build ceremony authorization digest",
    ),
    runtime_authority_dependency_sha256: sha256(
      parsed.runtime_authority_dependency_sha256,
      "frontend build runtime authority dependency digest",
    ),
    royalty_release_history_sha256: sha256(
      parsed.royalty_release_history_sha256,
      "frontend build Royalty release history digest",
    ),
    royalty_release_history_receipt_sha256: sha256(
      parsed.royalty_release_history_receipt_sha256,
      "frontend build Royalty H receipt digest",
    ),
    compute_workload_activation_observation_sha256: sha256(
      parsed.compute_workload_activation_observation_sha256,
      "frontend build compute-workload activation observation digest",
    ),
    frontend_build_sha256: sha256(
      parsed.frontend_build_sha256,
      "frontend build deterministic dist-manifest digest",
    ),
    release_inputs_sha256: sha256(
      parsed.release_inputs_sha256,
      "frontend build release-input digest",
    ),
    release_env_sha256: sha256(
      parsed.release_env_sha256,
      "frontend build release-env digest",
    ),
    raw_secret_egress: false,
  };
}

export function canonicalFrontendBuildCandidateReceiptText(value) {
  return canonicalText(normalizeFrontendBuildCandidateReceipt(value));
}

export function frontendBuildCandidateReceiptSha256(value) {
  return hashWithDomain(
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
  const normalized = normalizeFrontendBuildCandidateReceipt(receipt);
  const binding = authorityBinding || {};
  const expected = createFrontendBuildCandidateReceipt({
    releaseSha: normalized.release_sha,
    serializedEnv,
    deploymentIntentSha256: binding.deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      binding.reviewerAuthorityGenesisAcceptanceSha256,
    ceremonyAuthorizationSha256: binding.ceremonyAuthorizationSha256,
    runtimeAuthorityDependencySha256: binding.runtimeAuthorityDependencySha256,
    computeWorkloadActivationObservationSha256:
      binding.computeWorkloadActivationObservationSha256,
    frontendBuildSha256: binding.frontendBuildSha256,
    inputManifest,
  });
  if (JSON.stringify(normalized) !== JSON.stringify(expected)) {
    fail("frontend build candidate receipt does not match the independently reprojected lineage");
  }
  return normalized;
}

export const __test = Object.freeze({
  BASE_SEPOLIA_CHAIN_ID,
  CANONICAL_PRIMARY_RPC,
  MAX_ENV_BYTES,
  FORBIDDEN_POST_BUILD_AUTHORITY_INPUT,
});

// Additive compatibility exports for historical exact-37 replay. Production
// producer behavior above remains unchanged; the validator must import the
// pure module directly so this facade's filesystem/path closure is not pulled
// into the authority graph.
export {
  assertFrontendBuildCandidateLineage as assertHistoricalFrontendBuildCandidateLineage,
  createFrontendBuildPreDPrivateInputs as createHistoricalFrontendBuildPreDPrivateInputs,
  frontendBuildCandidateReceiptSha256 as historicalFrontendBuildCandidateReceiptSha256,
  frontendBuildInputManifestSha256 as historicalFrontendBuildInputManifestSha256,
  frontendBuildProjectedEnvSha256 as historicalFrontendBuildProjectedEnvSha256,
  normalizeFrontendBuildCandidateReceipt as normalizeHistoricalFrontendBuildCandidateReceipt,
  normalizeFrontendBuildInputManifest as normalizeHistoricalFrontendBuildInputManifest,
} from "./frontend-release-historical-core.mjs";
