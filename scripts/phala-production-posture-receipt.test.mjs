import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { PHALA_OS_IMAGE_CATALOG_ENTRY } from "./cvm-launch-intent-core.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  normalizeProductionCvmPostureVerificationReceipt,
  productionCvmPostureVerificationReceiptSha256,
  verifyProductionCvmPostureObservation,
} from "./phala-production-posture-receipt.mjs";
import {
  assertProductionCvmPreparedBinding,
  assertSecretFreeExecutorStructure,
  normalizeProductionCvmPreparedBinding,
  projectProductionCvmPostureReadback,
} from "./phala-production-posture-core.mjs";
import { createSyntheticPhalaContractKmsProjection } from "./phala-contract-kms-test-fixture.mjs";

const kmsProjection = createSyntheticPhalaContractKmsProjection();
const preparedBinding = {
  kms_contract_id: kmsProjection.contract.id,
  kms_id: kmsProjection.replicas[0].id,
  kms_url: kmsProjection.replicas[0].url,
  node_id: 7,
  teepod_id: 21,
  device_id: "1".repeat(64),
  gateway_app_id: `0x${"1".repeat(40)}`,
};

const expected = {
  appId: "1".repeat(40),
  composeHash: "2".repeat(64),
  instanceType: "tdx.large",
  diskSize: 40,
  kmsProjection,
  preparedBinding,
  environmentPublicKey: "3".repeat(64),
};

function info() {
  return {
    id: "cvm-production-main",
    name: "synthetic-main",
    status: "running",
    gateway: {},
    app_id: expected.appId,
    compose_hash: expected.composeHash,
    kms_type: "phala",
    kms_info: {
      chain_id: null,
      dstack_kms_address: null,
      dstack_app_address: null,
      deployer_address: null,
      rpc_endpoint: preparedBinding.kms_url,
      encrypted_env_pubkey: expected.environmentPublicKey,
    },
    node_info: {
      object_type: "node",
      id: preparedBinding.node_id,
      device_ids: [{ device_id: preparedBinding.device_id, algorithm_version: "v3.0.0", enabled: true }],
    },
    os: {
      is_dev: false,
      os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    },
    resource: { instance_type: expected.instanceType, disk_in_gb: expected.diskSize },
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
  };
}

function expectedAuthority() {
  return {
    domain: "main_runtime_cvm",
    app_id: expected.appId,
    cvm_id: "cvm-production-main",
    compose_hash: expected.composeHash,
    kms_id: preparedBinding.kms_id,
    instance_type: expected.instanceType,
    disk_size: expected.diskSize,
    prepared_binding: structuredClone(preparedBinding),
    environment_public_key: expected.environmentPublicKey,
  };
}

test("fresh getCvmInfo produces one immutable branded production posture receipt KAT", (t) => {
  t.mock.method(Date, "now", () => Date.parse("2026-07-21T12:01:00Z"));
  const receipt = verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm",
    cvmId: "cvm-production-main",
    cvmInfo: info(),
    expected,
  });
  assert.equal(assertVerifiedProductionCvmPostureReceipt(receipt), receipt);
  assert.equal(
    productionCvmPostureVerificationReceiptSha256(receipt),
    "sha256:0f97cf0ca03fe48e72ff6e5b6c1c4ddc7866ad5d47f3edb660be65e86b4875f6",
  );
  const before = productionCvmPostureVerificationReceiptSha256(receipt);
  assert.throws(() => { receipt.compose_hash = "3".repeat(64); }, TypeError);
  assert.equal(productionCvmPostureVerificationReceiptSha256(receipt), before);
  assert.deepEqual(receipt.prepared_binding, preparedBinding);
  assert.equal(receipt.environment_public_key, expected.environmentPublicKey);
  assert.match(receipt.truth_status, /not_fresh_contract_or_replica_id_evidence$/);
  assert.throws(() => assertVerifiedProductionCvmPostureReceipt(
    structuredClone(receipt),
  ), /not reconstructed/);
});

test("historical v1 posture receipt bytes retain the original digest without acquiring prepared authority", () => {
  const oldExpected = {
    domain: "main_runtime_cvm", app_id: expected.appId, cvm_id: "cvm-production-main",
    compose_hash: expected.composeHash, kms_id: "kms-production-1", instance_type: "tdx.large", disk_size: 40,
  };
  const oldInfo = {
    id: oldExpected.cvm_id, app_id: oldExpected.app_id, compose_hash: oldExpected.compose_hash,
    kms_type: "phala", kms_info: { id: oldExpected.kms_id },
    os: { is_dev: false, os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash },
    resource: { instance_type: "tdx.large", disk_in_gb: 40 },
    listed: false, public_logs: false, public_sysinfo: false, public_tcbinfo: false,
  };
  const sort = (value) => Array.isArray(value) ? value.map(sort)
    : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, sort(value[key])])) : value;
  const legacy = {
    schema: "dnai.phala-production-cvm-posture-verification-receipt.v1",
    status: "private_production_posture_verified",
    truth_status: "fresh_getCvmInfo_observation_matches_exact_committed_app_compose_kms_os_resource_and_privacy_posture",
    ...oldExpected,
    os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
    kms_type: "phala", listed: false, public_logs: false, public_sysinfo: false, public_tcbinfo: false,
    cvm_info_observation_sha256: `sha256:${createHash("sha256")
      .update("dnai-wikigen/phala-cvm-info-observation/v1\0")
      .update(`${JSON.stringify(sort(oldInfo), null, 2)}\n`).digest("hex")}`,
    observed_at: "2026-07-21T12:01:00Z", raw_secret_egress: false,
  };
  assert.deepEqual(normalizeProductionCvmPostureVerificationReceipt(legacy, {
    expectedAuthority: oldExpected,
  }), legacy);
  assert.equal(productionCvmPostureVerificationReceiptSha256(legacy, {
    expectedAuthority: oldExpected,
  }), "sha256:3f8505d0e0df7f39b9c6d435ea39b58d1870adac68824639f78fb0b69bc5531d");
  assert.throws(() => assertVerifiedProductionCvmPostureReceipt(legacy), /not reconstructed/);
  assert.throws(() => normalizeProductionCvmPostureVerificationReceipt(legacy, {
    expectedAuthority: expectedAuthority(),
  }), /exactly/);
  assert.throws(() => verifyProductionCvmPostureObservation({
    domain: oldExpected.domain, cvmId: oldExpected.cvm_id, cvmInfo: oldInfo,
    expected: { appId: expected.appId, composeHash: expected.composeHash, kmsId: oldExpected.kms_id,
      instanceType: "tdx.large", diskSize: 40 },
  }), /exactly/);
});

test("actual pinned SDK CVM details can verify posture without invented contract or replica ID fields", async () => {
  const { getCvmInfo } = await import("./vendor/phala-sdk-runtime-capsule-0.4.0-0.5.8.mjs");
  const raw = info();
  // Unknown node-style identity fields are stripped by the real SDK parser.
  raw.kms_info.id = "kms_NotReadbackAuthority";
  raw.kms_info.kms_contract_id = "kc_NotReadbackAuthority";
  const parsed = await getCvmInfo({ config: { version: "2026-06-23" }, get: async () => raw }, {
    id: "cvm-production-main",
  });
  assert.equal(Object.hasOwn(parsed.kms_info, "id"), false);
  assert.equal(Object.hasOwn(parsed.kms_info, "kms_contract_id"), false);
  const receipt = verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm", cvmId: "cvm-production-main", cvmInfo: parsed, expected,
  });
  assert.deepEqual(receipt.prepared_binding, preparedBinding);
});

for (const [label, mutate] of [
  ["missing RPC", (value) => { delete value.kms_info.rpc_endpoint; }],
  ["alternate reviewed replica RPC", (value) => { value.kms_info.rpc_endpoint = kmsProjection.replicas[1].url; }],
  ["private RPC", (value) => { value.kms_info.rpc_endpoint = "https://127.0.0.1/"; }],
  ["wrong environment key", (value) => { value.kms_info.encrypted_env_pubkey = "4".repeat(64); }],
  ["missing environment key", (value) => { delete value.kms_info.encrypted_env_pubkey; }],
  ["zero environment key", (value) => { value.kms_info.encrypted_env_pubkey = "0".repeat(64); }],
  ["wrong node namespace", (value) => { value.node_info.id = preparedBinding.teepod_id; }],
  ["wrong node", (value) => { value.node_info.id = 8; }],
  ["wrong device", (value) => { value.node_info.device_ids[0].device_id = "2".repeat(64); }],
  ["disabled device", (value) => { value.node_info.device_ids[0].enabled = false; }],
  ["unreviewed device algorithm", (value) => { value.node_info.device_ids[0].algorithm_version = "unreviewed"; }],
  ["missing device matrix", (value) => { delete value.node_info.device_ids; }],
  ["duplicate device", (value) => { value.node_info.device_ids.push({ ...value.node_info.device_ids[0] }); }],
  ["on-chain KMS", (value) => { value.kms_info.chain_id = 8453; }],
  ["non-Phala KMS", (value) => { value.kms_type = "base"; }],
  ["wrong app", (value) => { value.app_id = "4".repeat(40); }],
  ["wrong disk", (value) => { value.resource.disk_in_gb = 80; }],
  ["wrong image", (value) => { value.os.os_image_hash = "4".repeat(64); }],
  ["public sysinfo", (value) => { value.public_sysinfo = true; }],
  ["public TCB info", (value) => { value.public_tcbinfo = true; }],
  ["listed CVM", (value) => { value.listed = true; }],
]) {
  test(`posture readback rejects ${label}`, () => {
    const cvmInfo = info();
    mutate(cvmInfo);
    assert.throws(() => verifyProductionCvmPostureObservation({
      domain: "main_runtime_cvm", cvmId: "cvm-production-main", cvmInfo, expected,
    }));
  });
}

test("durable prepared binding revalidates exact graph identity and preserves equivalent replica choices", () => {
  const options = { preparedBinding, kmsProjection, domain: "main_runtime_cvm" };
  assert.deepEqual(assertProductionCvmPreparedBinding(options), preparedBinding);
  const second = { ...preparedBinding, kms_id: kmsProjection.replicas[1].id,
    kms_url: kmsProjection.replicas[1].url, node_id: 8, teepod_id: 22, device_id: "2".repeat(64) };
  assert.deepEqual(assertProductionCvmPreparedBinding({ ...options, preparedBinding: second }), second);
  for (const changes of [
    { kms_contract_id: "kc_Substitute" }, { kms_id: "kms_Substitute" },
    { kms_url: "https://substitute.phala.network/" }, { node_id: 8 }, { teepod_id: 22 },
    { device_id: "2".repeat(64) }, { gateway_app_id: `0x${"2".repeat(40)}` },
    { extra_field: true },
  ]) {
    assert.throws(() => assertProductionCvmPreparedBinding({
      ...options, preparedBinding: { ...preparedBinding, ...changes },
    }));
  }
  assert.throws(() => assertProductionCvmPreparedBinding({ ...options, domain: "invented" }));
});

test("durable prepared binding rejects coercible non-string contract and replica identifiers", () => {
  for (const field of ["kms_contract_id", "kms_id"]) {
    for (const value of [[preparedBinding[field]], [[preparedBinding[field]]], null, 1, {}]) {
      assert.throws(() => normalizeProductionCvmPreparedBinding({ ...preparedBinding, [field]: value }),
        /prepared binding identity is invalid/);
    }
  }
});

test("persisted v2 receipt binds every retained prepare field and the actual environment public key", () => {
  const receipt = verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm", cvmId: "cvm-production-main", cvmInfo: info(), expected,
  });
  assert.deepEqual(normalizeProductionCvmPostureVerificationReceipt(JSON.parse(JSON.stringify(receipt)), {
    expectedAuthority: expectedAuthority(),
  }), receipt);
  for (const mutate of [
    (value) => { value.prepared_binding.kms_contract_id = "kc_Substitute"; },
    (value) => { value.prepared_binding.device_id = "2".repeat(64); },
    (value) => { value.environment_public_key = "4".repeat(64); },
    (value) => { delete value.prepared_binding; },
    (value) => { value.schema = "dnai.phala-production-cvm-posture-verification-receipt.v1"; },
  ]) {
    const changed = structuredClone(receipt);
    mutate(changed);
    assert.throws(() => normalizeProductionCvmPostureVerificationReceipt(changed, {
      expectedAuthority: expectedAuthority(),
    }));
  }
});

test("secret guard permits only an exactly encoded SDK environment public key, never environment contents", () => {
  assert.equal(assertSecretFreeExecutorStructure({ encrypted_env_pubkey: expected.environmentPublicKey }), true);
  for (const value of [
    { encrypted_env_pubkey: "private contents" },
    { encrypted_env_pubkey: { secret: "not allowed" } },
    { encrypted_env: "3".repeat(64) },
    { encrypted_env_pubkey_backup: "3".repeat(64) },
  ]) assert.throws(() => assertSecretFreeExecutorStructure(value));
});

test("shared readback projection includes only actual public fields and cannot invent a missing CVM ID", () => {
  const raw = info();
  raw.compose_file = "private compose content excluded from posture";
  raw.kms_info.id = "kms_NotAnActualSdkField";
  raw.kms_info.kms_contract_id = "kc_NotAnActualSdkField";
  raw.node_info.extra = "unrelated";
  const projected = projectProductionCvmPostureReadback(raw, raw.id);
  assert.equal(Object.hasOwn(projected, "compose_file"), false);
  assert.equal(Object.hasOwn(projected.kms_info, "id"), false);
  assert.equal(Object.hasOwn(projected.kms_info, "kms_contract_id"), false);
  assert.equal(Object.hasOwn(projected.node_info, "extra"), false);
  assert.equal(Object.isFrozen(projected.node_info.device_ids[0]), true);
  verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm", cvmId: raw.id, cvmInfo: projected, expected,
  });
  for (const id of [undefined, null, "", 7, "other-cvm"]) {
    const changed = info();
    if (id === undefined) delete changed.id;
    else changed.id = id;
    assert.throws(() => projectProductionCvmPostureReadback(changed, raw.id), /explicitly identify/);
  }
  const missing = info();
  delete missing.kms_info.rpc_endpoint;
  const missingProjected = projectProductionCvmPostureReadback(missing, raw.id);
  assert.equal(Object.hasOwn(missingProjected.kms_info, "rpc_endpoint"), false);
  assert.throws(() => verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm", cvmId: raw.id, cvmInfo: missingProjected, expected,
  }));
});

test("posture receipt requires a real calendar second and accepts leap-day and month-boundary seconds", (t) => {
  t.mock.method(Date, "now", () => Date.parse("2026-07-21T12:01:00Z"));
  const receipt = structuredClone(verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm",
    cvmId: "cvm-production-main",
    cvmInfo: info(),
    expected,
  }));
  for (const valid of [
    "2024-02-29T23:59:59Z",
    "2024-03-01T00:00:00Z",
  ]) {
    receipt.observed_at = valid;
    assert.equal(
      normalizeProductionCvmPostureVerificationReceipt(receipt, {
        expectedAuthority: expectedAuthority(),
      }).observed_at,
      valid,
    );
  }
  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2026-02-30T12:00:00Z",
  ]) {
    receipt.observed_at = impossible;
    assert.throws(
      () => normalizeProductionCvmPostureVerificationReceipt(receipt, {
        expectedAuthority: expectedAuthority(),
      }),
      /canonical UTC second/,
    );
  }
});

test("posture verifier rejects public, dev, drifted, secret-bearing, or caller-dated observations", (t) => {
  t.mock.method(Date, "now", () => Date.parse("2026-07-21T12:01:00Z"));
  for (const mutate of [
    (value) => { value.public_logs = true; },
    (value) => { value.os.is_dev = true; },
    (value) => { value.compose_hash = "3".repeat(64); },
    (value) => { value.api_key = "phak_secret"; },
  ]) {
    const value = info();
    mutate(value);
    assert.throws(() => verifyProductionCvmPostureObservation({
      domain: "main_runtime_cvm",
      cvmId: "cvm-production-main",
      cvmInfo: value,
      expected,
    }));
  }
  assert.throws(() => verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm",
    cvmId: "cvm-production-main",
    cvmInfo: info(),
    expected,
    observedAt: "2026-07-21T12:01:00Z",
  }), /exactly the frozen fields/);
  assert.throws(() => verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm",
    cvmId: "cvm-production-other",
    cvmInfo: info(),
    expected,
  }), /does not identify the requested CVM ID/);
});
