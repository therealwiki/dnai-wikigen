import assert from "node:assert/strict";
import test from "node:test";

import {
  PHALA_EXECUTION_ORDER,
} from "./phala-production-executor-core.mjs";
import {
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
      instance_types: [
        { name: "tdx.large", default_disk_size_gb: 20, requires_gpu: false },
        { name: "tdx.small", default_disk_size_gb: 20, requires_gpu: false },
      ],
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
