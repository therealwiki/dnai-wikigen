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

function fixture() {
  const kms = {
    id: "kms-production-1",
    slug: "phala",
    url: "https://kms.phala.network/",
    version: "0.5.8",
    chain_id: null,
    kms_contract_address: null,
    gateway_app_id: "1".repeat(40),
    env_encrypt_signer_k256: `0x02${"9".repeat(64)}`,
    signer_provenance_sha256: `sha256:${"a".repeat(64)}`,
    valid_from: "2026-07-21T00:00:00Z",
    valid_until: "2027-07-21T00:00:00Z",
  };
  const targetAuthority = {
    workspace: { workspace_id: "workspace-production-1" },
    kms,
    os_image: structuredClone(PHALA_OS_IMAGE_CATALOG_ENTRY),
    resource_targets: Object.fromEntries(PHALA_EXECUTION_ORDER.map((domain) => [
      domain,
      {
        instance_type: domain === "main_runtime_cvm" ? "tdx.large" : "tdx.small",
        disk_size: domain === "main_runtime_cvm" ? 40 : 20,
      },
    ])),
  };
  const observedKms = {
    id: kms.id,
    slug: kms.slug,
    url: kms.url,
    version: kms.version,
    chain_id: null,
    kms_contract_address: null,
    gateway_app_id: `0x${kms.gateway_app_id}`,
  };
  return {
    targetAuthority,
    resources: {
      capacity: { max_instances: 7, max_disk: 2_048 },
      instance_types: ["tdx.large", "tdx.small"].map((id) => ({
        id,
        name: id === "tdx.large" ? "Large TDX Instance" : "Small TDX Instance",
        vcpu: id === "tdx.large" ? 4 : 1,
        memory_mb: id === "tdx.large" ? 8192 : 2048,
        default_disk_size_gb: 20,
        requires_gpu: false,
        requires_gpu_count: 0,
        family: "cpu",
        display_order: null,
      })),
      kms_nodes: [observedKms],
    },
    osImages: { items: [structuredClone(PHALA_OS_IMAGE_CATALOG_ENTRY)] },
    kmsList: { items: [structuredClone(observedKms)] },
    kmsInfo: structuredClone(observedKms),
  };
}

test("fresh authenticated catalog projection binds exact seven resources, OS, KMS, and quota", () => {
  const value = fixture();
  const projected = validateAuthenticatedPhalaReadinessCatalog(value);
  assert.equal(projected.kms_id, value.targetAuthority.kms.id);
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
    (value) => { value.kmsInfo.version = "0.5.9"; },
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
