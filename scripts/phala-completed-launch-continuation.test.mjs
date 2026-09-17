import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { CVM_LAUNCH_DOMAINS, PHALA_CVM_RESOURCE_TARGETS, PHALA_OS_IMAGE_CATALOG_ENTRY } from "./cvm-launch-intent-core.mjs";
import { createSyntheticPhalaContractKmsProjection } from "./phala-contract-kms-test-fixture.mjs";
import {
  revalidateHistoricalPhalaContinuationPreparedBindings,
  snapshotPhalaContinuationTargetEvidence,
} from "./phala-completed-launch-continuation.mjs";
import {
  verifyProductionCvmPostureObservation,
  productionCvmPostureVerificationReceiptSha256,
} from "./phala-production-posture-receipt.mjs";

const sha = (value) => `sha256:${createHash("sha256").update(value).digest("hex")}`;

function fixture() {
  const kms = createSyntheticPhalaContractKmsProjection();
  const targetSha256 = sha("synthetic target");
  const target = {
    release_sha: "a".repeat(40), cvm_launch_intent_sha256: sha("synthetic launch"),
    kms, os_image: structuredClone(PHALA_OS_IMAGE_CATALOG_ENTRY),
    resource_targets: structuredClone(PHALA_CVM_RESOURCE_TARGETS),
  };
  const state = {
    target_authority_sha256: targetSha256, release_sha: target.release_sha,
    launch_intent_sha256: target.cvm_launch_intent_sha256,
    signed_key_bindings: [], posture_receipts: [],
  };
  const launch = { production_target_authority_sha256: targetSha256, domains: [] };
  const historicalPostureReceipts = CVM_LAUNCH_DOMAINS.map((domain, index) => {
    const replica = index % 2;
    const placement = kms.eligible_placements[replica];
    const binding = {
      kms_contract_id: kms.contract.id, kms_id: kms.replicas[replica].id,
      kms_url: kms.replicas[replica].url, node_id: placement.node_id,
      teepod_id: placement.teepod_id, device_id: placement.device_ids[0].device_id,
      gateway_app_id: placement.gateway_app_id,
    };
    const resource = PHALA_CVM_RESOURCE_TARGETS[domain];
    const appId = String(index + 1).repeat(40);
    const composeHash = String(index + 1).repeat(64);
    const publicKey = String(index + 1).repeat(64);
    const cvmId = `cvm-synthetic-${index}`;
    const receipt = verifyProductionCvmPostureObservation({
      domain, cvmId,
      cvmInfo: {
        id: cvmId, app_id: appId, compose_hash: composeHash, kms_type: "phala",
        kms_info: { chain_id: null, rpc_endpoint: binding.kms_url, encrypted_env_pubkey: publicKey },
        node_info: { id: binding.node_id, device_ids: structuredClone(placement.device_ids) },
        os: { is_dev: false, os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash },
        resource: { instance_type: resource.instance_type, disk_in_gb: resource.disk_size },
        listed: false, public_logs: false, public_sysinfo: false, public_tcbinfo: false,
      },
      expected: {
        appId, composeHash, instanceType: resource.instance_type, diskSize: resource.disk_size,
        kmsProjection: kms, preparedBinding: binding, environmentPublicKey: publicKey,
      },
    });
    const receiptSha256 = productionCvmPostureVerificationReceiptSha256(receipt);
    launch.domains.push({
      domain, app_id: appId, cvm_id: cvmId, committed_compose_hash: composeHash,
      kms_id: binding.kms_id, instance_type: resource.instance_type, disk_size: resource.disk_size,
      os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
      production_posture_verification_receipt_sha256: receiptSha256,
    });
    state.posture_receipts.push({ domain, receipt_sha256: receiptSha256 });
    state.signed_key_bindings.push({ domain, public_key_sha256: sha(Buffer.from(publicKey, "hex")) });
    return structuredClone(receipt);
  });
  return { target, targetSha256, state, launch, historicalPostureReceipts };
}

test("continuation cross-check retains each historically selected replica without inventing CVM IDs", () => {
  const value = fixture();
  const result = revalidateHistoricalPhalaContinuationPreparedBindings(value);
  assert.deepEqual(Object.keys(result).sort(), [...CVM_LAUNCH_DOMAINS].sort());
  assert.equal(new Set(Object.values(result).map((entry) => entry.kms_id)).size, 2);
  for (const receipt of value.historicalPostureReceipts) assert.deepEqual(result[receipt.domain], receipt);
  assert.equal(Object.isFrozen(result.main_runtime_cvm.prepared_binding), true);
});

test("continuation cross-check rejects accessor authority before executing it", () => {
  const value = fixture();
  let calls = 0;
  Object.defineProperty(value, "target", { enumerable: true, get() { calls += 1; return {}; } });
  assert.throws(() => revalidateHistoricalPhalaContinuationPreparedBindings(value), /accessor/);
  assert.equal(calls, 0);
});

test("continuation target evidence snapshot detaches and freezes every retained nested graph", async () => {
  const { target, targetSha256 } = fixture();
  // This helper only snapshots data that its production caller already
  // normalized. These minimal synthetic wrappers are not authority fixtures.
  const source = {
    compatibilityReceipt: { kms: target.kms, workspace: { billing_status: "active" } },
    sdkWireTransformStagingReceipt: { domains: [{ domain: "main_runtime_cvm", facts: ["reviewed"] }] },
    productionTargetAuthority: target,
    productionTargetAuthoritySha256: targetSha256,
  };
  const snapshot = snapshotPhalaContinuationTargetEvidence(source);
  const retained = JSON.stringify(snapshot);
  for (const mutate of [
    (value) => { value.productionTargetAuthority.kms.contract.k256_pubkey = "substitute"; },
    (value) => { value.productionTargetAuthority.kms.contract.ca_pubkey = "substitute"; },
    (value) => { value.productionTargetAuthority.kms.replicas[0].url = "https://substitute.example/"; },
    (value) => { value.productionTargetAuthority.kms.eligible_placements[0].device_ids[0].device_id = "substitute"; },
    (value) => { value.productionTargetAuthority.kms.eligible_placements.push({}); },
    (value) => { value.compatibilityReceipt.workspace.billing_status = "abandoned"; },
    (value) => { value.compatibilityReceipt.kms.contract.id = "kc_Substitute"; },
    (value) => { value.sdkWireTransformStagingReceipt.domains[0].facts[0] = "substitute"; },
  ]) assert.throws(() => mutate(snapshot), TypeError);
  await Promise.resolve();
  source.productionTargetAuthority.kms.contract.k256_pubkey = "caller substitution";
  source.compatibilityReceipt.kms.eligible_placements[0].device_ids[0].device_id = "caller substitution";
  source.sdkWireTransformStagingReceipt.domains[0].facts.push("caller substitution");
  assert.equal(JSON.stringify(snapshot), retained);
  assert.notEqual(snapshot.productionTargetAuthority, source.productionTargetAuthority);
  assert.notEqual(snapshot.productionTargetAuthority.kms, source.productionTargetAuthority.kms);
  assert.notEqual(snapshot.compatibilityReceipt, source.compatibilityReceipt);
  assert.notEqual(snapshot.sdkWireTransformStagingReceipt, source.sdkWireTransformStagingReceipt);
});

test("continuation target evidence snapshot rejects accessor data before executing it", () => {
  let calls = 0;
  const source = {};
  Object.defineProperty(source, "productionTargetAuthority", {
    enumerable: true, get() { calls += 1; return {}; },
  });
  assert.throws(() => snapshotPhalaContinuationTargetEvidence(source), /accessor/);
  assert.equal(calls, 0);
});

for (const [label, mutate] of [
  ["old v1 posture", (value) => { value.historicalPostureReceipts[0].schema = "dnai.phala-production-cvm-posture-verification-receipt.v1"; }],
  ["missing durable binding", (value) => { delete value.historicalPostureReceipts[0].prepared_binding; }],
  ["missing historical posture", (value) => { value.historicalPostureReceipts.pop(); }],
  ["duplicate historical posture", (value) => { value.historicalPostureReceipts[1] = value.historicalPostureReceipts[0]; }],
  ["wrong target digest", (value) => { value.targetSha256 = sha("wrong"); }],
  ["wrong selected replica", (value) => { value.historicalPostureReceipts[0].prepared_binding.kms_id = "kms_Substitute"; }],
  ["wrong historical posture digest", (value) => { value.launch.domains[0].production_posture_verification_receipt_sha256 = sha("wrong"); }],
  ["wrong journal posture digest", (value) => { value.state.posture_receipts[0].receipt_sha256 = sha("wrong"); }],
  ["wrong journal environment key", (value) => { value.state.signed_key_bindings[0].public_key_sha256 = sha("wrong"); }],
  ["wrong historical app", (value) => { value.launch.domains[0].app_id = "9".repeat(40); }],
  ["wrong historical OS", (value) => { value.launch.domains[0].os_image_hash = "9".repeat(64); }],
]) {
  test(`continuation prepare authority rejects ${label}`, () => {
    const value = fixture();
    mutate(value);
    assert.throws(() => revalidateHistoricalPhalaContinuationPreparedBindings(value));
  });
}
