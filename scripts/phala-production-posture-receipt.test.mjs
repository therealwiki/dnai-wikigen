import assert from "node:assert/strict";
import test from "node:test";

import { PHALA_OS_IMAGE_CATALOG_ENTRY } from "./cvm-launch-intent-core.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  normalizeProductionCvmPostureVerificationReceipt,
  productionCvmPostureVerificationReceiptSha256,
  verifyProductionCvmPostureObservation,
} from "./phala-production-posture-receipt.mjs";

const expected = {
  appId: "1".repeat(40),
  composeHash: "2".repeat(64),
  kmsId: "kms-production-1",
  instanceType: "tdx.large",
  diskSize: 40,
};

function info() {
  return {
    id: "cvm-production-main",
    app_id: expected.appId,
    compose_hash: expected.composeHash,
    kms_type: "phala",
    kms_info: { id: expected.kmsId },
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
    kms_id: expected.kmsId,
    instance_type: expected.instanceType,
    disk_size: expected.diskSize,
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
    "sha256:8b7714f14c3755224e7d91ee7d4c0c195948ca1e185ae3b1b48b9099befbf72d",
  );
  const before = productionCvmPostureVerificationReceiptSha256(receipt);
  assert.throws(() => { receipt.compose_hash = "3".repeat(64); }, TypeError);
  assert.equal(productionCvmPostureVerificationReceiptSha256(receipt), before);
  assert.throws(() => assertVerifiedProductionCvmPostureReceipt(
    structuredClone(receipt),
  ), /not reconstructed/);
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
