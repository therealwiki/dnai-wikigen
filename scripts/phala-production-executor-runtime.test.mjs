import assert from "node:assert/strict";
import test from "node:test";

import {
  PHALA_EXECUTION_ORDER,
} from "./phala-production-executor-core.mjs";
import {
  adoptCompletedPhalaSevenCvmLaunchContinuation,
  executePhalaSevenCvmProductionLaunch,
  readPhalaProductionExecutorRuntimeDependencies,
  validateAuthenticatedPhalaReadinessCatalog,
} from "./phala-production-executor-runtime.mjs";
import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  createSyntheticPhalaContractKmsFixture,
  createSyntheticPhalaContractKmsProjection,
} from "./phala-contract-kms-test-fixture.mjs";
import { phalaAuthenticatedAccountSubjectSha256 } from "./phala-production-sdk-adapter.mjs";

function fixture() {
  const graph = createSyntheticPhalaContractKmsFixture();
  const authenticatedSubject = {
    user: { username: "synthetic", email: "synthetic@example.test", role: "admin" },
    workspace: { id: "workspace-production-1", name: "Synthetic", slug: "synthetic", role: "owner" },
  };
  const targetAuthority = {
    workspace: {
      workspace_id: authenticatedSubject.workspace.id,
      account_subject_sha256: phalaAuthenticatedAccountSubjectSha256(authenticatedSubject),
    },
    kms: createSyntheticPhalaContractKmsProjection(),
    os_image: structuredClone(PHALA_OS_IMAGE_CATALOG_ENTRY),
    resource_targets: Object.fromEntries(PHALA_EXECUTION_ORDER.map((domain) => [
      domain,
      {
        instance_type: domain === "main_runtime_cvm" ? "tdx.large" : "tdx.small",
        disk_size: domain === "main_runtime_cvm" ? 40 : 20,
      },
    ])),
  };
  return {
    targetAuthority,
    authenticatedSubject,
    workspace: { ...authenticatedSubject.workspace, billing_status: "active" },
    resources: graph.resources,
    osImages: { items: [structuredClone(PHALA_OS_IMAGE_CATALOG_ENTRY)] },
    kmsContracts: { items: [graph.contract], page: 1, page_size: 100, pages: 1, total: 1 },
    kmsContract: structuredClone(graph.contract),
    kmsContractNodes: graph.contractNodes,
  };
}

test("fresh authenticated catalog projection binds exact seven resources, OS, KMS, and quota", () => {
  const value = fixture();
  const projected = validateAuthenticatedPhalaReadinessCatalog(value);
  assert.equal(projected.kms.contract.id, value.targetAuthority.kms.contract.id);
  assert.equal(projected.billing_status, "active");
  assert.equal(projected.os_image_hash, PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash);
  assert.equal(Object.keys(projected.resource_targets).length, 7);
  assert.equal(projected.capacity.reviewed_launch_disk, 160);
  assert.throws(() => { projected.capacity.max_disk = 1; }, TypeError);
});

test("catalog validation rejects capacity, resource, KMS, and dev-image drift", () => {
  const mutations = [
    (value) => { value.resources.capacity.max_instances = 6; },
    (value) => { value.resources.capacity.max_disk = 159; },
    (value) => { value.resources.instance_types[0].requires_gpu = true; },
    (value) => { value.resources.kms_nodes.push(structuredClone(value.resources.kms_nodes[0])); },
    (value) => { value.kmsContractNodes.items[0].version = "v0.6.0-rc1 (git:abcdef1234567890)"; },
    (value) => { value.osImages.items[0].is_dev = true; },
    (value) => { value.osImages.items[0].os_image_hash = "f".repeat(64); },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    assert.throws(() => validateAuthenticatedPhalaReadinessCatalog(value));
  }
});

test("fresh readiness catalog selects canonical IDs independently of display labels", () => {
  const value = fixture();
  value.resources.instance_types.forEach((entry) => { entry.name = "Shared display label"; });
  value.resources.instance_types.push({
    ...value.resources.instance_types[0],
    id: "tdx.unreviewed",
    name: "tdx.large",
    requires_gpu: true,
  });
  const projected = validateAuthenticatedPhalaReadinessCatalog(value);
  assert.deepEqual(projected.resource_targets, value.targetAuthority.resource_targets);
});

test("fresh reviewed placement capacity can change without reauthorizing its identity", () => {
  const value = fixture();
  value.resources.nodes[0].remaining_memory -= 2048;
  value.resources.nodes[1].remaining_cvm_slots = 0;
  const projected = validateAuthenticatedPhalaReadinessCatalog(value);
  assert.equal(projected.kms.eligible_placements.length, 1);
  assert.equal(projected.kms.eligible_placements[0].capacity.remaining_memory_mb, 63_488);
  assert.equal(projected.kms.eligible_placements[0].kms_id, "kms_Synthetic1");
  assert.equal(Object.isFrozen(projected.kms.eligible_placements[0]), true);
});

for (const [label, mutate] of [
  ["missing raw billing", (value) => { delete value.workspace.billing_status; }],
  ["suspended billing", (value) => { value.workspace.billing_status = "suspended"; }],
  ["abandoned billing", (value) => { value.workspace.billing_status = "abandoned"; }],
  ["billing from another workspace", (value) => { value.workspace.id = "other-workspace"; }],
  ["authenticated subject drift", (value) => { value.authenticatedSubject.user.username = "other-user"; }],
  ["incomplete contract catalog", (value) => { value.kmsContracts.total = 2; }],
  ["ambiguous contract catalog", (value) => {
    value.kmsContracts.items.push(structuredClone(value.kmsContracts.items[0]));
    value.kmsContracts.total = 2;
  }],
  ["contract catalog/detail mismatch", (value) => { value.kmsContract.label = "different detail"; }],
  ["unreviewed contract identity", (value) => {
    value.kmsContract.label = "unreviewed contract";
    value.kmsContracts.items[0].label = "unreviewed contract";
  }],
  ["incomplete replica inventory", (value) => { value.kmsContractNodes.total = 3; }],
  ["unreviewed replica endpoint", (value) => {
    value.kmsContractNodes.items[0].url = "https://other.phala.network/";
    value.resources.kms_nodes[0].url = "https://other.phala.network/";
  }],
  ["unreviewed gateway endpoint", (value) => {
    value.resources.gateway_nodes[0].rpc_url = "https://other-gateway.phala.network/";
  }],
  ["unreviewed node identity", (value) => { value.resources.nodes[1].node_id = 99; }],
  ["unreviewed enabled device", (value) => {
    value.resources.nodes[0].device_ids[0].device_id = "9".repeat(64);
    value.resources.nodes[0].device_id = "9".repeat(64);
  }],
  ["unreviewed instance CPU semantics", (value) => { value.resources.instance_types[0].vcpu += 1; }],
  ["no remaining host placement", (value) => {
    value.resources.nodes.forEach((entry) => { entry.remaining_cvm_slots = 0; });
  }],
]) {
  test(`fresh readiness rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => validateAuthenticatedPhalaReadinessCatalog(value));
  });
}

for (const [label, mutate] of [
  ["missing canonical ID", (value) => {
    value.resources.instance_types[0].name = "tdx.large";
    delete value.resources.instance_types[0].id;
  }],
  ["duplicate canonical ID", (value) => {
    value.resources.instance_types.push({
      ...value.resources.instance_types[0],
      name: "Another large display label",
    });
  }],
  ["display-name spoofing", (value) => {
    value.resources.instance_types.forEach((entry) => { entry.name = entry.id; });
    value.resources.instance_types[0].id = "tdx.unreviewed";
  }],
]) {
  test(`fresh readiness catalog rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => validateAuthenticatedPhalaReadinessCatalog(value),
      /absent from the fresh authenticated resource catalog/);
  });
}

test("production runtime rejects caller hooks before reading files or credentials", async () => {
  await assert.rejects(executePhalaSevenCvmProductionLaunch({
    client: {},
    nowMs: 1,
    phaseSecretInputPaths: {},
  }), /exactly the frozen fields/);
});

test("runtime dependency reader rejects unbranded and JSON-cloned result shapes", () => {
  const forged = Object.freeze({
    schema: "dnai.phala-production-executor-runtime-result.v3",
    executor_final_state_sha256: `sha256:${"1".repeat(64)}`,
  });
  assert.throws(
    () => readPhalaProductionExecutorRuntimeDependencies(forged),
    /completed locally replayed production executor result is required/,
  );
  assert.throws(
    () => readPhalaProductionExecutorRuntimeDependencies(
      JSON.parse(JSON.stringify(forged)),
    ),
    /completed locally replayed production executor result is required/,
  );
});

test("completed-launch runtime adoption rejects an unbranded or serialized capability", async () => {
  await assert.rejects(
    adoptCompletedPhalaSevenCvmLaunchContinuation(Object.freeze({})),
    /completed-launch continuation capability is required/,
  );
  await assert.rejects(
    adoptCompletedPhalaSevenCvmLaunchContinuation(JSON.parse(JSON.stringify({
      schema: "dnai.phala-completed-seven-cvm-launch-continuation-capability.v1",
      one_shot: true,
    }))),
    /completed-launch continuation capability is required/,
  );
});
