import assert from "node:assert/strict";
import test from "node:test";

import {
  assertPhalaPreparedKmsBinding,
  assertPhalaWorkspaceActiveBilling,
  buildPhalaContractKmsProjection,
  normalizePhalaContractKmsProjection,
  normalizePhalaKmsContract,
  normalizePhalaKmsContractNodes,
} from "./phala-contract-kms-core.mjs";

// Public SEC/NIST generator points, not deployed identities or trust anchors.
const K256 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const CA_DER = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
  + "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  + "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

function fixture() {
  const contract = {
    id: "kc_TestRoot",
    slug: "phala",
    label: "Phala KMS",
    contract_address: "phala",
    chain_id: 0,
    k256_pubkey: K256,
    ca_pubkey: CA_DER,
    node_count: 2,
  };
  const replicas = [1, 2].map((index) => ({
    id: `kms_Test${index}`,
    slug: `phala-test${index}`,
    url: `https://kms-${index}.phala.network`,
    version: "v0.6.0-rc0 (git:abcdef1234567890)",
    kms_type: "phala",
  }));
  const osImage = {
    name: "dstack-0.5.9",
    slug: "dstack-0.5.9-aaaaaaaa",
    version: "0.5.9",
    os_image_hash: "a".repeat(64),
    is_dev: false,
    requires_gpu: false,
  };
  const resourceTargets = {
    main_runtime_cvm: {
      instance_type: "tdx.large",
      disk_size: 40,
      gateway_required: true,
      placement: { selection_mode: "automatic_best_match", node_id: null, region: null },
    },
    private_oracle_cvm: {
      instance_type: "tdx.small",
      disk_size: 20,
      gateway_required: false,
    },
  };
  const resources = {
    capacity: {
      max_instances: 16,
      max_vcpu: 32,
      max_memory: 65_536,
      max_disk: 1_024,
      max_memory_each: 65_536,
      max_disk_each: 256,
    },
    instance_types: [
      { id: "tdx.large", name: "Large instance", vcpu: 4, memory_mb: 8_192,
        default_disk_size_gb: 20, requires_gpu: false, requires_gpu_count: 0 },
      { id: "tdx.small", name: "Small instance", vcpu: 1, memory_mb: 2_048,
        default_disk_size_gb: 20, requires_gpu: false, requires_gpu_count: 0 },
    ],
    kms_nodes: replicas.map((entry) => ({
      ...entry,
      chain_id: null,
      kms_contract_id: contract.id,
      kms_contract_address: "",
      gateway_app_id: `0x${"Ab".repeat(20)}`,
      supported_os_images: [osImage.name],
    })),
    nodes: [1, 2].map((index) => ({
      node_id: index + 3,
      teepod_id: index + 20,
      name: `prod${index}`,
      listed: true,
      remaining_vcpu: 8,
      remaining_memory: 16_384,
      remaining_cvm_slots: 4,
      images: [{ ...osImage, version: [0, 5, 9], supports_cpu: true, enabled: true }],
      device_id: String(index).repeat(64),
      device_ids: [
        { device_id: String(index).repeat(64), algorithm_version: "v3.0.0", enabled: true },
        { device_id: String(index + 2).repeat(64), algorithm_version: "v2.0.0", enabled: true },
      ],
    })),
    node_kms_relations: replicas.map((entry, index) => ({
      teepod_id: index + 21,
      kms_id: entry.id,
      kms_type: "phala",
      kms_contract_id: contract.id,
      kms_contract_address: "",
      supported_os_images: [osImage.name],
    })),
    gateway_nodes: [{
      id: "gn_Test1",
      node_id: 4,
      teepod_id: 21,
      kms_contract_id: contract.id,
      enabled: true,
      rpc_url: "https://gateway-rpc.phala.network",
      domain_suffix: "gateway.phala.network",
    }],
  };
  return { contract, contractNodes: { items: replicas, total: 2 }, resources, osImage, resourceTargets };
}

test("contract normalizer validates public-key encodings without hardcoding a live authority", () => {
  const value = fixture().contract;
  value.k256_pubkey = `0x${K256.toUpperCase()}`;
  value.ca_pubkey = `0x${CA_DER.toUpperCase()}`;
  const result = normalizePhalaKmsContract(value);
  assert.equal(result.id, "kc_TestRoot");
  assert.equal(result.k256_pubkey, `0x${K256}`);
  assert.equal(result.ca_pubkey, CA_DER);
  assert.equal(Object.isFrozen(result), true);
});

for (const [label, mutate] of [
  ["node id used as contract id", (value) => { value.id = "kms_TestRoot"; }],
  ["chain null", (value) => { value.chain_id = null; }],
  ["on-chain contract", (value) => { value.contract_address = `0x${"1".repeat(40)}`; }],
  ["node slug", (value) => { value.slug = "phala-prod7"; }],
  ["uncompressed key", (value) => { value.k256_pubkey = `04${"1".repeat(128)}`; }],
  ["off-curve key", (value) => { value.k256_pubkey = `02${"f".repeat(64)}`; }],
  ["malformed DER", (value) => { value.ca_pubkey = "12".repeat(91); }],
  ["trailing DER bytes", (value) => { value.ca_pubkey += "00"; }],
  ["empty inventory", (value) => { value.node_count = 0; }],
  ["excessive inventory", (value) => { value.node_count = 513; }],
]) {
  test(`contract rejects ${label}`, () => {
    const value = fixture().contract;
    mutate(value);
    assert.throws(() => normalizePhalaKmsContract(value));
  });
}

test("node inventory is complete, unique, canonical, sorted, and immutable", () => {
  const value = fixture();
  value.contractNodes.items.reverse();
  const result = normalizePhalaKmsContractNodes(value.contractNodes, { contract: value.contract });
  assert.deepEqual(result.map((entry) => entry.id), ["kms_Test1", "kms_Test2"]);
  assert.equal(result[0].url, "https://kms-1.phala.network/");
  assert.throws(() => { result[0].slug = "changed"; }, TypeError);
});

test("complete inventory preserves multiple unavailable replicas with nullable SDK slugs", () => {
  const value = fixture();
  for (const index of [3, 4]) {
    value.contractNodes.items.push({ ...value.contractNodes.items[0],
      id: `kms_Test${index}`, slug: null, url: `https://kms-${index}.phala.network` });
  }
  value.contract.node_count = value.contractNodes.total = 4;
  const result = buildPhalaContractKmsProjection(value);
  assert.deepEqual(result.replicas.slice(2).map((entry) => entry.slug), [null, null]);
  assert.equal(result.eligible_placements.length, 2);
});

test("nullable inventory slug matches resource schema's absent optional slug without inventing an alias", () => {
  const value = fixture();
  value.contractNodes.items[0].slug = null;
  delete value.resources.kms_nodes[0].slug;
  const result = buildPhalaContractKmsProjection(value);
  assert.equal(result.replicas[0].slug, null);
});

for (const [label, mutate] of [
  ["truncated total", (value) => { value.contractNodes.total = 3; }],
  ["contract count drift", (value) => { value.contract.node_count = 3; }],
  ["duplicate node id", (value) => { value.contractNodes.items[1].id = value.contractNodes.items[0].id; }],
  ["duplicate slug", (value) => { value.contractNodes.items[1].slug = value.contractNodes.items[0].slug; }],
  ["equivalent duplicate endpoint", (value) => { value.contractNodes.items[1].url = `${value.contractNodes.items[0].url}/`; }],
  ["private endpoint", (value) => { value.contractNodes.items[0].url = "https://127.0.0.1"; }],
  ["endpoint credentials", (value) => { value.contractNodes.items[0].url = "https://user@phala.network"; }],
  ["non-phala replica", (value) => { value.contractNodes.items[0].kms_type = "base"; }],
]) {
  test(`node inventory rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => normalizePhalaKmsContractNodes(value.contractNodes, { contract: value.contract }));
  });
}

test("projection joins exact contract replicas to separate node/teepod namespaces and device matrices", () => {
  const value = fixture();
  const result = buildPhalaContractKmsProjection(value);
  assert.deepEqual(Object.keys(result), ["contract", "replicas", "eligible_placements", "gateways"]);
  assert.deepEqual(result.eligible_placements.map(({ node_id, teepod_id, kms_id }) => ({ node_id, teepod_id, kms_id })), [
    { node_id: 4, teepod_id: 21, kms_id: "kms_Test1" },
    { node_id: 5, teepod_id: 22, kms_id: "kms_Test2" },
  ]);
  assert.deepEqual(result.eligible_placements[0].target_domains, ["main_runtime_cvm", "private_oracle_cvm"]);
  assert.equal(result.eligible_placements[0].gateway_app_id, `0x${"ab".repeat(20)}`);
  assert.equal(result.eligible_placements[0].device_ids.length, 2);
  assert.equal(result.eligible_placements[0].capacity.remaining_memory_mb, 16_384);
  assert.equal(result.gateways[0].kms_contract_id, value.contract.id);
  assert.throws(() => { result.eligible_placements[0].device_ids.pop(); }, TypeError);
  assert.equal(value.contract.k256_pubkey, K256, "does not mutate caller input");
});

test("irrelevant unrelated catalog records do not become Phala authority or block valid candidates", () => {
  const value = fixture();
  value.resources.kms_nodes.push({ id: "kms_Other", kms_contract_id: "kc_Other", kms_type: "base" });
  value.resources.node_kms_relations.push({ teepod_id: 99, kms_id: "kms_Other", kms_contract_id: "kc_Other", kms_type: "base" });
  value.resources.gateway_nodes.push({ id: "gn_Other", kms_contract_id: "kc_Other" });
  value.resources.instance_types.push({ id: "gpu.other", name: "tdx.large", requires_gpu: true });
  const result = buildPhalaContractKmsProjection(value);
  assert.equal(result.replicas.length, 2);
  assert.equal(result.eligible_placements.length, 2);
  assert.equal(result.gateways.length, 1);
});

test("catalog membership alone does not create an eligible host; one unavailable replica may remain cataloged", () => {
  const value = fixture();
  value.resources.node_kms_relations.splice(1, 1);
  const result = buildPhalaContractKmsProjection(value);
  assert.equal(result.replicas.length, 2);
  assert.equal(result.eligible_placements.length, 1);
});

test("capacity and gateways determine eligibility per target rather than assigning a preferred replica", () => {
  const value = fixture();
  value.resources.nodes[0].remaining_memory = 2_048;
  const result = buildPhalaContractKmsProjection(value);
  assert.deepEqual(result.eligible_placements[0].target_domains, ["private_oracle_cvm"]);
  assert.equal(result.eligible_placements[0].gateway_app_id, null);
  assert.deepEqual(result.eligible_placements[1].target_domains, ["main_runtime_cvm", "private_oracle_cvm"]);
});

test("explicit gateway-free targets can omit gateways without inventing a gateway authority", () => {
  const value = fixture();
  value.resourceTargets.main_runtime_cvm.gateway_required = false;
  value.resources.gateway_nodes = [];
  value.resources.kms_nodes.forEach((entry) => { entry.gateway_app_id = null; });
  const result = buildPhalaContractKmsProjection(value);
  assert.deepEqual(result.gateways, []);
  assert.equal(result.eligible_placements[0].gateway_app_id, null);
});

for (const [label, mutate] of [
  ["missing gateway requirement", (value) => { delete value.resourceTargets.main_runtime_cvm.gateway_required; }],
  ["hidden placement override", (value) => { value.resourceTargets.main_runtime_cvm.placement.node_id = 4; }],
  ["display name substituted for type id", (value) => { value.resources.instance_types[0].id = "Large instance"; }],
  ["duplicate instance type", (value) => { value.resources.instance_types.push(structuredClone(value.resources.instance_types[0])); }],
  ["GPU instance", (value) => { value.resources.instance_types[0].requires_gpu = true; }],
  ["insufficient quota", (value) => { value.resources.capacity.max_instances = 1; }],
  ["per-instance disk overflow", (value) => { value.resources.capacity.max_disk_each = 39; }],
  ["insufficient host capacity", (value) => { value.resources.nodes.forEach((host) => { host.remaining_vcpu = 0; }); }],
  ["resource replica id collision", (value) => { value.resources.kms_nodes.push(structuredClone(value.resources.kms_nodes[0])); }],
  ["resource replica URL substitution", (value) => { value.resources.kms_nodes[0].url = "https://substitute.phala.network"; }],
  ["resource contract drift", (value) => { value.resources.kms_nodes[0].kms_contract_id = "kc_Other"; }],
  ["on-chain resource", (value) => { value.resources.kms_nodes[0].chain_id = 8453; }],
  ["unknown contract member", (value) => { value.resources.kms_nodes.push({ ...value.resources.kms_nodes[0], id: "kms_Unknown" }); }],
  ["legacy numeric KMS id", (value) => { value.resources.kms_nodes[0].id = 0; }],
  ["duplicate host node id", (value) => { value.resources.nodes[1].node_id = value.resources.nodes[0].node_id; }],
  ["duplicate host teepod id", (value) => { value.resources.nodes[1].teepod_id = value.resources.nodes[0].teepod_id; }],
  ["node id passed as teepod relation", (value) => { value.resources.node_kms_relations[0].teepod_id = value.resources.nodes[0].node_id; }],
  ["relation contract substitution", (value) => { value.resources.node_kms_relations[0].kms_contract_id = "kc_Other"; }],
  ["duplicate relation", (value) => { value.resources.node_kms_relations.push(structuredClone(value.resources.node_kms_relations[0])); }],
  ["no supported OS relation", (value) => { value.resources.node_kms_relations.forEach((relation) => { relation.supported_os_images = []; }); }],
  ["OS hash substitution", (value) => { value.resources.nodes[0].images[0].os_image_hash = "b".repeat(64); }],
  ["development OS", (value) => { value.resources.nodes[0].images[0].is_dev = true; }],
  ["non-CPU OS", (value) => { value.resources.nodes[0].images[0].supports_cpu = false; }],
  ["disabled OS", (value) => { value.resources.nodes[0].images[0].enabled = false; }],
  ["ambiguous OS entry", (value) => { value.resources.nodes[0].images.push(structuredClone(value.resources.nodes[0].images[0])); }],
  ["missing device matrix", (value) => { delete value.resources.nodes[0].device_ids; }],
  ["array-coerced device digest", (value) => { value.resources.nodes[0].device_ids[0].device_id = ["1".repeat(64)]; }],
  ["array-coerced reviewed OS digest", (value) => { value.osImage.os_image_hash = ["a".repeat(64)]; }],
  ["disabled device matrix", (value) => { value.resources.nodes[0].device_ids.forEach((device) => { device.enabled = false; }); }],
  ["duplicate device identity", (value) => { value.resources.nodes[0].device_ids.push(structuredClone(value.resources.nodes[0].device_ids[0])); }],
  ["duplicate device algorithm version", (value) => { value.resources.nodes[0].device_ids[1].algorithm_version = "v3.0.0"; }],
  ["device identity assigned to two hosts", (value) => { value.resources.nodes[1].device_ids[1].device_id = "3".repeat(64); }],
  ["legacy device drift", (value) => { value.resources.nodes[0].device_id = "f".repeat(64); }],
  ["malformed supported OS image", (value) => { value.resources.kms_nodes[0].supported_os_images.push(["dstack-0.5.9"]); }],
  ["missing required gateway", (value) => { value.resources.gateway_nodes = []; }],
  ["disabled gateway", (value) => { value.resources.gateway_nodes[0].enabled = false; }],
  ["gateway from another contract", (value) => { value.resources.gateway_nodes[0].kms_contract_id = "kc_Other"; }],
  ["private gateway RPC", (value) => { value.resources.gateway_nodes[0].rpc_url = "https://gateway.local"; }],
  ["gateway domain path injection", (value) => { value.resources.gateway_nodes[0].domain_suffix = "gateway.phala.network/path"; }],
  ["duplicate gateway identity", (value) => { value.resources.gateway_nodes.push(structuredClone(value.resources.gateway_nodes[0])); }],
  ["gateway node/teepod namespace swap", (value) => { value.resources.gateway_nodes[0].node_id = 5; }],
  ["conflicting gateway app identity", (value) => { value.resources.kms_nodes[1].gateway_app_id = `0x${"c".repeat(40)}`; }],
]) {
  test(`projection rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => buildPhalaContractKmsProjection(value));
  });
}

function persistedFixture() {
  const raw = fixture();
  return {
    projection: structuredClone(buildPhalaContractKmsProjection(raw)),
    options: { osImage: raw.osImage, resourceTargets: raw.resourceTargets },
  };
}

test("persisted projection round-trips canonical authority and ignores object key order only", () => {
  const { projection, options } = persistedFixture();
  const reordered = Object.fromEntries(Object.entries(projection).reverse());
  const result = normalizePhalaContractKmsProjection(reordered, options);
  assert.deepEqual(result, projection);
  assert.equal(Object.isFrozen(result.eligible_placements[0].target_requirements[0]), true);
  assert.deepEqual(result.eligible_placements[0].target_requirements[0], {
    domain: "main_runtime_cvm", instance_type: "tdx.large", disk_size: 40,
    vcpu: 4, memory_mb: 8_192, gateway_required: true,
  });
});

test("persisted projection optionally binds independently reviewed CPU/memory requirements", () => {
  const { projection, options } = persistedFixture();
  Object.assign(options.resourceTargets.main_runtime_cvm, { vcpu: 4, memory_mb: 8_192 });
  assert.deepEqual(normalizePhalaContractKmsProjection(projection, options), projection);
  options.resourceTargets.main_runtime_cvm.vcpu = 8;
  assert.throws(() => normalizePhalaContractKmsProjection(projection, options), /reviewed target/);
});

for (const [label, mutate] of [
  ["extra top-level authority", (value) => { value.projection.ready = true; }],
  ["missing contract root", (value) => { delete value.projection.contract.k256_pubkey; }],
  ["extra replica identity", (value) => { value.projection.replicas[0].trusted = true; }],
  ["missing capacity", (value) => { delete value.projection.eligible_placements[0].capacity; }],
  ["unsorted replicas", (value) => { value.projection.replicas.reverse(); }],
  ["unsorted placements", (value) => { value.projection.eligible_placements.reverse(); }],
  ["unsorted target requirements", (value) => { value.projection.eligible_placements[0].target_requirements.reverse(); }],
  ["unsorted device identities", (value) => { value.projection.eligible_placements[0].device_ids.reverse(); }],
  ["noncanonical K256 encoding", (value) => { value.projection.contract.k256_pubkey = K256; }],
  ["noncanonical DER encoding", (value) => { value.projection.contract.ca_pubkey = `0x${CA_DER}`; }],
  ["noncanonical endpoint", (value) => { value.projection.replicas[0].url = "https://kms-1.phala.network"; }],
  ["unknown replica", (value) => { value.projection.eligible_placements[0].kms_id = "kms_Other"; }],
  ["contract mismatch", (value) => { value.projection.eligible_placements[0].kms_contract_id = "kc_Other"; }],
  ["reviewed OS mismatch", (value) => { value.options.osImage.os_image_hash = "b".repeat(64); }],
  ["target disk mismatch", (value) => { value.projection.eligible_placements[0].target_requirements[0].disk_size = 41; }],
  ["target instance mismatch", (value) => { value.projection.eligible_placements[0].target_requirements[0].instance_type = "tdx.small"; }],
  ["target gateway mismatch", (value) => { value.projection.eligible_placements[0].target_requirements[0].gateway_required = false; }],
  ["target domains mismatch", (value) => { value.projection.eligible_placements[0].target_domains.pop(); }],
  ["duplicate target requirement", (value) => { value.projection.eligible_placements[0].target_requirements.push(structuredClone(value.projection.eligible_placements[0].target_requirements[0])); }],
  ["inconsistent target CPU", (value) => { value.projection.eligible_placements[1].target_requirements[0].vcpu = 2; }],
  ["insufficient CPU capacity", (value) => { value.projection.eligible_placements[0].capacity.remaining_vcpu = 3; }],
  ["insufficient memory capacity", (value) => { value.projection.eligible_placements[0].capacity.remaining_memory_mb = 8_191; }],
  ["zero CVM slots", (value) => { value.projection.eligible_placements[0].capacity.remaining_cvm_slots = 0; }],
  ["missing target coverage", (value) => { value.options.resourceTargets.extra_cvm = { instance_type: "tdx.small", disk_size: 20, gateway_required: false }; }],
  ["duplicate placement", (value) => { value.projection.eligible_placements.push(structuredClone(value.projection.eligible_placements[0])); }],
  ["two teepods share node id", (value) => { value.projection.eligible_placements[1].node_id = 4; }],
  ["two hosts share device id", (value) => { value.projection.eligible_placements[1].device_ids[0].device_id = "1".repeat(64); }],
  ["disabled projected device", (value) => { value.projection.eligible_placements[0].device_ids[1].enabled = false; }],
  ["array-valued projected device", (value) => { value.projection.eligible_placements[0].device_ids[0].device_id = ["1".repeat(64)]; }],
  ["missing gateways", (value) => { value.projection.gateways = []; }],
  ["noncanonical gateway app", (value) => { value.projection.eligible_placements[0].gateway_app_id = `0x${"AB".repeat(20)}`; }],
  ["gateway contract mismatch", (value) => { value.projection.gateways[0].kms_contract_id = "kc_Other"; }],
  ["gateway disabled", (value) => { value.projection.gateways[0].enabled = false; }],
  ["gateway node namespace mismatch", (value) => { value.projection.gateways[0].node_id = 5; }],
]) {
  test(`persisted projection rejects ${label}`, () => {
    const value = persistedFixture();
    mutate(value);
    assert.throws(() => normalizePhalaContractKmsProjection(value.projection, value.options));
  });
}

function preparedFixture() {
  const raw = fixture();
  const kmsProjection = structuredClone(buildPhalaContractKmsProjection(raw));
  const info = { ...raw.contractNodes.items[0], chain_id: null, kms_contract_address: "",
    gateway_app_id: `0x${"Ab".repeat(20)}`, k256_pubkey: K256 };
  delete info.kms_type;
  return {
    response: {
      app_id: "1".repeat(40), compose_hash: "b".repeat(64),
      kms_contract_id: raw.contract.id, kms_id: info.id, kms_info: info,
      node_id: 21, device_id: "1".repeat(64), os_image_hash: raw.osImage.os_image_hash,
      instance_type: "tdx.large", app_env_encrypt_pubkey: "c".repeat(64),
    },
    rawPlacement: { node_id: 4, teepod_id: 21 },
    domain: "main_runtime_cvm",
    kmsProjection,
  };
}

test("prepared binding preserves distinct provider node and legacy teepod identities", () => {
  const value = preparedFixture();
  const binding = assertPhalaPreparedKmsBinding(value);
  assert.deepEqual(binding, {
    kms_contract_id: "kc_TestRoot", kms_id: "kms_Test1", kms_url: "https://kms-1.phala.network/",
    node_id: 4, teepod_id: 21, device_id: "1".repeat(64), gateway_app_id: `0x${"ab".repeat(20)}`,
  });
  assert.equal(Object.isFrozen(binding), true);
  assert.equal(value.response.node_id, 21, "does not relabel the SDK response as the provider node id");
});

for (const rawPlacement of [{ node_id: 4 }, { teepod_id: 21 }, { node_id: 4, teepod_id: 21 },
  { node_id: null, teepod_id: 21 }, { node_id: 4, teepod_id: null }]) {
  test(`prepared binding accepts exact raw placement namespace ${Object.keys(rawPlacement).join("+")}`, () => {
    const value = preparedFixture();
    value.rawPlacement = rawPlacement;
    value.response.node_id = Object.hasOwn(rawPlacement, "teepod_id") ? rawPlacement.teepod_id : rawPlacement.node_id;
    assert.equal(assertPhalaPreparedKmsBinding(value).node_id, 4);
  });
}

test("prepared binding is compatible with the actual pinned SDK transform using an offline fake client", async () => {
  const { provisionCvm } = await import("./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs");
  const value = preparedFixture();
  const rawResponse = { ...value.response, ...value.rawPlacement };
  value.response = await provisionCvm({ post: async (path, body) => {
    assert.equal(path, "/cvms/provision");
    assert.equal(body.kms_contract_id, "kc_TestRoot");
    assert.equal(Object.hasOwn(body, "kms_id"), false);
    return structuredClone(rawResponse);
  } }, { name: "test-only", kms: "PHALA", kms_contract_id: "kc_TestRoot", compose_file: {} });
  assert.equal(value.response.node_id, 21);
  assert.equal(Object.hasOwn(value.response, "teepod_id"), false);
  assert.equal(assertPhalaPreparedKmsBinding(value).node_id, 4);
});

test("actual pinned SDK preserves a positive raw node despite null teepod overwriting transformed node", async () => {
  const { provisionCvm } = await import("./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs");
  const value = preparedFixture();
  value.rawPlacement = { node_id: 4, teepod_id: null };
  value.response = await provisionCvm({ post: async () => ({ ...value.response, ...value.rawPlacement }) },
    { name: "test-only", kms: "PHALA", kms_contract_id: "kc_TestRoot", compose_file: {} });
  assert.equal(value.response.node_id, null);
  assert.equal(assertPhalaPreparedKmsBinding(value).node_id, 4);
});

test("missing optional prepare root is non-evidence and does not skip other identity checks", () => {
  const value = preparedFixture();
  delete value.response.kms_info.k256_pubkey;
  assert.equal(assertPhalaPreparedKmsBinding(value).kms_contract_id, "kc_TestRoot");
  value.response.device_id = "f".repeat(64);
  assert.throws(() => assertPhalaPreparedKmsBinding(value), /device identity/);
});

test("SDK nullable prepare root is also non-evidence; independently signed env-key checks remain external", () => {
  const value = preparedFixture();
  value.response.kms_info.k256_pubkey = null;
  assert.equal(assertPhalaPreparedKmsBinding(value).kms_contract_id, "kc_TestRoot");
  value.response.kms_info.k256_pubkey = "not-a-key";
  assert.throws(() => assertPhalaPreparedKmsBinding(value), /compressed secp256k1/);
});

test("gateway-free domain does not invent gateway binding even on a gateway-capable host", () => {
  const value = preparedFixture();
  value.domain = "private_oracle_cvm";
  value.response.kms_info.gateway_app_id = null;
  assert.equal(assertPhalaPreparedKmsBinding(value).gateway_app_id, null);
});

test("any reviewed enabled device algorithm may bind the exact prepared host", () => {
  const value = preparedFixture();
  value.response.device_id = "3".repeat(64);
  assert.equal(assertPhalaPreparedKmsBinding(value).device_id, "3".repeat(64));
});

for (const [label, mutate] of [
  ["missing raw placement", (value) => { value.rawPlacement = {}; }],
  ["extra raw placement field", (value) => { value.rawPlacement.device_id = "1".repeat(64); }],
  ["all-null raw namespaces", (value) => { value.rawPlacement = { node_id: null, teepod_id: null }; value.response.node_id = null; }],
  ["only null raw node", (value) => { value.rawPlacement = { node_id: null }; value.response.node_id = null; }],
  ["only null raw teepod", (value) => { value.rawPlacement = { teepod_id: null }; value.response.node_id = null; }],
  ["string raw namespace", (value) => { value.rawPlacement.teepod_id = "21"; }],
  ["swapped raw namespaces", (value) => { value.rawPlacement = { node_id: 21, teepod_id: 4 }; value.response.node_id = 4; }],
  ["conflicting raw namespaces", (value) => { value.rawPlacement.node_id = 5; }],
  ["wrong transformed node", (value) => { value.response.node_id = 4; }],
  ["untransformed response", (value) => { value.response.teepod_id = 21; }],
  ["unknown target", (value) => { value.domain = "other_cvm"; }],
  ["wrong contract", (value) => { value.response.kms_contract_id = "kc_Other"; }],
  ["numeric contract id", (value) => { value.response.kms_contract_id = 0; }],
  ["unknown replica", (value) => { value.response.kms_id = value.response.kms_info.id = "kms_Other"; }],
  ["generic alias as replica", (value) => { value.response.kms_id = value.response.kms_info.id = "phala"; }],
  ["conflicting replica id", (value) => { value.response.kms_info.id = "kms_Test2"; }],
  ["wrong replica slug", (value) => { value.response.kms_info.slug = "phala"; }],
  ["missing nullable slug", (value) => { delete value.response.kms_info.slug; }],
  ["wrong replica URL", (value) => { value.response.kms_info.url = "https://substitute.phala.network"; }],
  ["wrong replica version", (value) => { value.response.kms_info.version = "different"; }],
  ["wrong optional replica type", (value) => { value.response.kms_info.kms_type = "base"; }],
  ["wrong optional replica contract", (value) => { value.response.kms_info.kms_contract_id = "kc_Other"; }],
  ["chain 0 in legacy node info", (value) => { value.response.kms_info.chain_id = 0; }],
  ["contract address in legacy node info", (value) => { value.response.kms_info.kms_contract_address = "phala"; }],
  ["different valid K256 root", (value) => { value.response.kms_info.k256_pubkey = `03${K256.slice(2)}`; }],
  ["non-string supplied K256 root", (value) => { value.response.kms_info.k256_pubkey = [K256]; }],
  ["unknown prepared device", (value) => { value.response.device_id = "f".repeat(64); }],
  ["device from another host", (value) => { value.response.device_id = "2".repeat(64); }],
  ["array-coerced prepared device", (value) => { value.response.device_id = ["1".repeat(64)]; }],
  ["missing required gateway app", (value) => { value.response.kms_info.gateway_app_id = null; }],
  ["wrong gateway app", (value) => { value.response.kms_info.gateway_app_id = `0x${"c".repeat(40)}`; }],
  ["conflicting top-level gateway app", (value) => { value.response.gateway_app_id = `0x${"c".repeat(40)}`; }],
  ["noncanonical reviewed projection", (value) => { value.kmsProjection.replicas.reverse(); }],
  ["duplicate reviewed placement", (value) => { value.kmsProjection.eligible_placements.push(structuredClone(value.kmsProjection.eligible_placements[0])); }],
]) {
  test(`prepared binding rejects ${label}`, () => {
    const value = preparedFixture();
    mutate(value);
    assert.throws(() => assertPhalaPreparedKmsBinding(value));
  });
}

function billingFixture() {
  return {
    workspace: { id: "ws_Test1", slug: "test-projects", billing_status: "active" },
    authenticatedSubject: { workspace: { id: "ws_Test1", slug: "test-projects" } },
  };
}

test("raw active billing binds workspace id and slug and outputs no credentials", () => {
  const result = assertPhalaWorkspaceActiveBilling(billingFixture());
  assert.deepEqual(result, { workspace_id: "ws_Test1", workspace_slug: "test-projects", billing_status: "active" });
  assert.equal(Object.isFrozen(result), true);
});

for (const status of [null, "", "suspended", "abandoned", "active ", "ACTIVE", true]) {
  test(`raw billing rejects explicit non-active value ${String(status)}`, () => {
    const value = billingFixture();
    value.workspace.billing_status = status;
    assert.throws(() => assertPhalaWorkspaceActiveBilling(value));
  });
}

test("missing raw billing status is rejected before an SDK default could imply active", () => {
  const value = billingFixture();
  delete value.workspace.billing_status;
  assert.throws(() => assertPhalaWorkspaceActiveBilling(value), /missing explicit billing_status/);
});

for (const key of ["id", "slug"]) {
  test(`raw billing rejects mismatched authenticated workspace ${key}`, () => {
    const value = billingFixture();
    value.authenticatedSubject.workspace[key] = "different";
    assert.throws(() => assertPhalaWorkspaceActiveBilling(value), /identity differs/);
  });
}

test("authority functions reject proxies and accessors without invoking them", () => {
  let called = false;
  const value = fixture();
  Object.defineProperty(value.contract, "id", { enumerable: true, get() { called = true; return "kc_TestRoot"; } });
  assert.throws(() => buildPhalaContractKmsProjection(value), /accessors/);
  assert.equal(called, false);
  const billing = billingFixture();
  billing.workspace = new Proxy(billing.workspace, { get() { called = true; return "active"; } });
  assert.throws(() => assertPhalaWorkspaceActiveBilling(billing), /Proxy/);
  assert.equal(called, false);
});
