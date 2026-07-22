import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

export const EXACT_MODEL_A_DEPENDENCY_GRAPH_SCHEMA =
  "dnai.exact-model-a-dependency-graph.v1";
export const EXACT_MODEL_A_DEPENDENCY_GRAPH_DOMAIN =
  "dnai-wikigen/exact-model-a-dependency-graph/v1\0";
export const EXACT_MODEL_A_DEPENDENCY_GRAPH_CHAIN_ID = 84_532;

export const EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS = Object.freeze([
  "deployment_intent_sha256",
  "bootstrap_authorization_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "seven_cvm_launch_completion_receipt_sha256",
  "historical_transcript_file_set_sha256",
  "descriptor_runtime_authority_sha256",
  "release_verification_authority_sha256",
  "runtime_authority_dependency_sha256",
  "ceremony_authorization_sha256",
  "post_measurement_activation_execution_receipt_sha256",
  "compute_workload_activation_observation_sha256",
  "frontend_build_candidate_receipt_sha256",
  "live_activation_authority_sha256",
  "final_release_raw_sha256",
]);

export const EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES = deepFreezeCanonicalPlainDataGraph([
  ["deployment_intent", "bootstrap_authorization_receipt"],
  ["bootstrap_authorization_receipt", "seven_cvm_launch_completion_receipt"],
  ["seven_cvm_verified_evidence_set", "seven_cvm_launch_completion_receipt"],
  ["seven_cvm_launch_completion_receipt", "pre_ceremony_runtime_authority"],
  ["historical_transcript_file_set", "pre_ceremony_runtime_authority"],
  ["descriptor_runtime_authority", "release_verification_authority"],
  ["release_verification_authority", "pre_ceremony_runtime_authority"],
  ["pre_ceremony_runtime_authority", "ceremony_authorization"],
  ["ceremony_authorization", "post_measurement_activation_execution_receipt"],
  ["post_measurement_activation_execution_receipt", "compute_workload_activation_observation"],
  ["compute_workload_activation_observation", "frontend_build_candidate_receipt"],
  ["frontend_build_candidate_receipt", "live_activation_authority"],
  ["live_activation_authority", "final_release"],
], { label: "exact Model-A dependency edges" });

const GRAPH_FIELDS = Object.freeze([
  "chain_id",
  "edges",
  "final_release_raw_sha256",
  "frontend_build_candidate_receipt_sha256",
  "live_activation_authority_sha256",
  "live_activation_review_subject_sha256",
  "nodes",
  "pre_d_release_inputs_sha256",
  "release_sha",
  "schema",
]);
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;

function fail(message) {
  throw new TypeError(message);
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function releaseSha(value) {
  if (typeof value !== "string" || !SHA40.test(value)) {
    fail("exact Model-A dependency graph release SHA is invalid");
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function normalizeEdges(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "exact Model-A dependency graph edges",
  });
  if (JSON.stringify(value) !== JSON.stringify(EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES)) {
    fail("exact Model-A dependency graph edges differ from the frozen authority chain");
  }
  return EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES.map((edge) => [...edge]);
}

export function normalizeExactModelADependencyGraph(value) {
  const parsed = exactRecord(
    value,
    GRAPH_FIELDS,
    "exact Model-A dependency graph",
  );
  if (parsed.schema !== EXACT_MODEL_A_DEPENDENCY_GRAPH_SCHEMA) {
    fail("exact Model-A dependency graph schema is invalid");
  }
  if (parsed.chain_id !== EXACT_MODEL_A_DEPENDENCY_GRAPH_CHAIN_ID) {
    fail("exact Model-A dependency graph chain ID must be Base Sepolia");
  }
  const nodes = exactRecord(
    parsed.nodes,
    EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS,
    "exact Model-A dependency graph nodes",
  );
  const normalizedNodes = Object.fromEntries(
    EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS.map((key) => [
      key,
      sha256(nodes[key], `exact Model-A dependency node ${key}`),
    ]),
  );
  const normalized = {
    schema: EXACT_MODEL_A_DEPENDENCY_GRAPH_SCHEMA,
    chain_id: EXACT_MODEL_A_DEPENDENCY_GRAPH_CHAIN_ID,
    release_sha: releaseSha(parsed.release_sha),
    pre_d_release_inputs_sha256: sha256(
      parsed.pre_d_release_inputs_sha256,
      "exact Model-A pre-D release inputs",
    ),
    frontend_build_candidate_receipt_sha256: sha256(
      parsed.frontend_build_candidate_receipt_sha256,
      "exact Model-A frontend D receipt",
    ),
    live_activation_review_subject_sha256: sha256(
      parsed.live_activation_review_subject_sha256,
      "exact Model-A signed-C review subject",
    ),
    live_activation_authority_sha256: sha256(
      parsed.live_activation_authority_sha256,
      "exact Model-A signed-C authority",
    ),
    final_release_raw_sha256: sha256(
      parsed.final_release_raw_sha256,
      "exact Model-A final release raw bytes",
    ),
    nodes: normalizedNodes,
    edges: normalizeEdges(parsed.edges),
  };
  if (normalized.frontend_build_candidate_receipt_sha256
      !== normalizedNodes.frontend_build_candidate_receipt_sha256
    || normalized.live_activation_authority_sha256
      !== normalizedNodes.live_activation_authority_sha256
    || normalized.final_release_raw_sha256
      !== normalizedNodes.final_release_raw_sha256) {
    fail("exact Model-A dependency graph duplicate roots drifted from their nodes");
  }
  if (new Set(Object.values(normalizedNodes)).size
      !== EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS.length) {
    fail("exact Model-A dependency graph nodes must have pairwise-distinct digest roots");
  }
  return deepFreezeCanonicalPlainDataGraph(normalized, {
    label: "normalized exact Model-A dependency graph",
  });
}

export function createExactModelADependencyGraph(value) {
  return normalizeExactModelADependencyGraph({
    schema: EXACT_MODEL_A_DEPENDENCY_GRAPH_SCHEMA,
    chain_id: EXACT_MODEL_A_DEPENDENCY_GRAPH_CHAIN_ID,
    ...value,
    edges: EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES,
  });
}

export function exactModelADependencyGraphSha256(value) {
  const normalized = normalizeExactModelADependencyGraph(value);
  return `sha256:${createHash("sha256")
    .update(EXACT_MODEL_A_DEPENDENCY_GRAPH_DOMAIN, "utf8")
    .update(canonicalText(normalized), "utf8")
    .digest("hex")}`;
}
