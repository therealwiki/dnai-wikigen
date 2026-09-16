import assert from "node:assert/strict";
import test from "node:test";

import {
  EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES,
  EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS,
  createExactModelADependencyGraph,
  exactModelADependencyGraphSha256,
  normalizeExactModelADependencyGraph,
} from "./exact-model-a-dependency-graph.mjs";

const digest = (index) => `sha256:${index.toString(16).padStart(64, "0")}`;

function fixture() {
  const nodes = Object.fromEntries(
    EXACT_MODEL_A_DEPENDENCY_GRAPH_NODE_KEYS.map((key, index) => [key, digest(index + 1)]),
  );
  return {
    release_sha: "1".repeat(40),
    pre_d_release_inputs_sha256: digest(90),
    frontend_build_candidate_receipt_sha256:
      nodes.frontend_build_candidate_receipt_sha256,
    live_activation_review_subject_sha256: digest(91),
    live_activation_authority_sha256: nodes.live_activation_authority_sha256,
    final_release_raw_sha256: nodes.final_release_raw_sha256,
    nodes,
  };
}

test("creates a frozen, domain-separated graph for the complete historical chain", () => {
  const graph = createExactModelADependencyGraph(fixture());
  assert.equal(Object.isFrozen(graph), true);
  assert.equal(Object.isFrozen(graph.nodes), true);
  assert.equal(Object.isFrozen(graph.edges), true);
  assert.equal(Object.isFrozen(graph.edges[0]), true);
  assert.equal(
    exactModelADependencyGraphSha256(graph),
    "sha256:745f8a487b9131474093c50d9a15e092889473a0659a15365f2900534a24acf2",
  );
  assert.equal(
    graph.nodes.post_measurement_activation_execution_receipt_sha256,
    digest(10),
  );
  assert.deepEqual(graph.edges, EXACT_MODEL_A_DEPENDENCY_GRAPH_EDGES);
});

test("refuses to omit the activation receipt or descriptor authority", () => {
  for (const missing of [
    "post_measurement_activation_execution_receipt_sha256",
    "descriptor_runtime_authority_sha256",
  ]) {
    const value = fixture();
    delete value.nodes[missing];
    assert.throws(
      () => createExactModelADependencyGraph(value),
      /nodes must contain exactly the frozen fields/,
    );
  }
});

test("refuses opaque, zero, aliased, or mismatched roots", () => {
  const zero = fixture();
  zero.nodes.post_measurement_activation_execution_receipt_sha256 =
    `sha256:${"0".repeat(64)}`;
  assert.throws(
    () => createExactModelADependencyGraph(zero),
    /nonzero canonical SHA-256/,
  );

  const aliased = fixture();
  aliased.nodes.release_verification_authority_sha256 =
    aliased.nodes.descriptor_runtime_authority_sha256;
  assert.throws(
    () => createExactModelADependencyGraph(aliased),
    /pairwise-distinct digest roots/,
  );

  const mismatch = fixture();
  mismatch.frontend_build_candidate_receipt_sha256 = digest(92);
  assert.throws(
    () => createExactModelADependencyGraph(mismatch),
    /duplicate roots drifted/,
  );
});

test("refuses edge drift, extra fields, accessors, and custom prototypes", () => {
  const graph = createExactModelADependencyGraph(fixture());
  const reordered = structuredClone(graph);
  [reordered.edges[0], reordered.edges[1]] = [reordered.edges[1], reordered.edges[0]];
  assert.throws(
    () => normalizeExactModelADependencyGraph(reordered),
    /edges differ from the frozen authority chain/,
  );

  const extra = structuredClone(graph);
  extra.nodes.unreviewed_sha256 = digest(93);
  assert.throws(
    () => normalizeExactModelADependencyGraph(extra),
    /nodes must contain exactly the frozen fields/,
  );

  const accessor = structuredClone(graph);
  Object.defineProperty(accessor, "release_sha", {
    enumerable: true,
    get: () => "1".repeat(40),
  });
  assert.throws(
    () => normalizeExactModelADependencyGraph(accessor),
    /accessors and non-enumerable data fields are forbidden/,
  );

  const custom = structuredClone(graph);
  Object.setPrototypeOf(custom.nodes, { untrusted: true });
  assert.throws(
    () => normalizeExactModelADependencyGraph(custom),
    /custom prototypes are forbidden/,
  );
});
