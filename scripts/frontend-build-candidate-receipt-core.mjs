import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

export const FRONTEND_BUILD_CANDIDATE_SCHEMA =
  "dnai.frontend-build-candidate.v3";
export const FRONTEND_BUILD_CANDIDATE_STATUS =
  "pre_live_activation_candidate";
export const FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS =
  "pre_live_activation_candidate_not_deploy_authority";
export const FRONTEND_BUILD_CANDIDATE_DOMAIN =
  "dnai-wikigen/frontend-build-candidate/v3\0";

const BASE_SEPOLIA_CHAIN_ID = 84_532;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
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

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function normalizeFrontendBuildCandidateReceipt(value) {
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "chain_id",
    "compute_workload_activation_observation_sha256",
    "deployment_intent_sha256", "frontend_build_sha256",
    "raw_secret_egress", "release_env_sha256", "release_inputs_sha256",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256", "runtime_authority_dependency_sha256",
    "schema", "status", "truth_status",
  ], "frontend build candidate receipt");
  if (parsed.schema !== FRONTEND_BUILD_CANDIDATE_SCHEMA
    || parsed.status !== FRONTEND_BUILD_CANDIDATE_STATUS
    || parsed.truth_status !== FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS
    || !SHA40.test(String(parsed.release_sha || ""))
    || parsed.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || parsed.raw_secret_egress !== false) {
    fail("frontend build candidate receipt does not carry the exact non-deploy truth label");
  }
  return deepFreezeCanonicalPlainDataGraph({
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
  }, { label: "normalized frontend build candidate receipt" });
}

export function canonicalFrontendBuildCandidateReceiptText(value) {
  return canonicalText(normalizeFrontendBuildCandidateReceipt(value));
}

export function frontendBuildCandidateReceiptSha256(value) {
  return `sha256:${createHash("sha256")
    .update(FRONTEND_BUILD_CANDIDATE_DOMAIN, "utf8")
    .update(canonicalText(normalizeFrontendBuildCandidateReceipt(value)), "utf8")
    .digest("hex")}`;
}
