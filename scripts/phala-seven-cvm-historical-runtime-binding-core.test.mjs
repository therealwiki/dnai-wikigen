import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_DOMAIN,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  canonicalPhalaSevenCvmHistoricalRuntimeBindingText,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
  phalaSevenCvmHistoricalRuntimeBindingSha256,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";

const sha = (byte) => `sha256:${byte.repeat(32)}`;

function bindingFixture() {
  const releaseSha = "ab".repeat(20);
  const deploymentIntentSha256 = sha("b4");
  const syntheticReleaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha,
      deploymentIntentSha256,
      releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
        mainRuntime: {
          descriptor_sha256: sha("21"),
          app_id: "22".repeat(20),
          cvm_id: "synthetic-main-runtime-01",
          compose_hash: "23".repeat(32),
          os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
        },
      }),
    });
  const releaseAuthority = normalizePhalaSevenCvmReleaseVerificationAuthority({
    ...structuredClone(syntheticReleaseAuthority),
    evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  });
  const main = releaseAuthority.descriptors.find(
    (descriptor) => descriptor.domain === "main_runtime_cvm",
  );
  return {
    schema: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
    release_sha: releaseSha,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: sha("31"),
    release_verification_authority: releaseAuthority,
    release_verification_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    seven_cvm_launch_completion_receipt_sha256: sha("32"),
    phala_recovery_directory_identity_anchor_sha256: sha("33"),
    batch_id: sha("34"),
    seven_cvm_verified_evidence_set_sha256: sha("35"),
    main_runtime_target: {
      domain: main.domain,
      descriptor_sha256: main.descriptor_sha256,
      app_id: main.app_id,
      cvm_id: main.cvm_id,
      compose_hash: main.compose_hash,
      os_image_hash: main.os_image_hash,
    },
    activation_plan_created_at: "2026-07-21T12:00:00Z",
    machine_verifier_evidence_issued_at: 1_784_635_100,
    activation_evidence_lease_expires_at: 4_000_000_000,
  };
}

test("historical R binding v3 embeds and authenticates the complete release authority and activation lease", () => {
  const fixture = bindingFixture();
  const normalized = normalizePhalaSevenCvmHistoricalRuntimeBinding(fixture);
  assert.deepEqual(normalized, fixture);
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_DOMAIN,
    "dnai-wikigen/phala-seven-cvm-historical-runtime-binding/v3\0",
  );
  assert.deepEqual(
    normalized.release_verification_authority,
    fixture.release_verification_authority,
  );
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(Object.isFrozen(normalized.release_verification_authority), true);
  assert.deepEqual(
    JSON.parse(canonicalPhalaSevenCvmHistoricalRuntimeBindingText(normalized)),
    normalized,
  );
  assert.match(
    phalaSevenCvmHistoricalRuntimeBindingSha256(normalized),
    /^sha256:[0-9a-f]{64}$/,
  );
});

test("historical R binding rejects release-authority digest, lineage, and target drift", () => {
  const mutations = [
    (value) => { value.release_verification_authority_sha256 = sha("41"); },
    (value) => { value.release_sha = "cd".repeat(20); },
    (value) => { value.deployment_intent_sha256 = sha("42"); },
    (value) => { value.main_runtime_target.descriptor_sha256 = sha("43"); },
    (value) => { value.main_runtime_target.app_id = "44".repeat(20); },
    (value) => { value.main_runtime_target.cvm_id = "synthetic-main-runtime-02"; },
    (value) => { value.main_runtime_target.compose_hash = "45".repeat(32); },
    (value) => { value.main_runtime_target.os_image_hash = "46".repeat(32); },
    (value) => {
      value.machine_verifier_evidence_issued_at =
        value.activation_evidence_lease_expires_at;
    },
    (value) => { value.activation_plan_created_at = "2026-02-31T00:00:00Z"; },
    (value) => { value.activation_plan_created_at = "2026-01-01T24:00:00Z"; },
    (value) => { value.unknown = true; },
  ];
  for (const mutate of mutations) {
    const fixture = structuredClone(bindingFixture());
    mutate(fixture);
    assert.throws(
      () => normalizePhalaSevenCvmHistoricalRuntimeBinding(fixture),
    );
  }
});

test("historical R binding rejects structurally valid synthetic release authority", () => {
  const fixture = structuredClone(bindingFixture());
  fixture.release_verification_authority.evidence_mode =
    PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE;
  fixture.release_verification_authority_sha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(
      fixture.release_verification_authority,
    );
  assert.throws(
    () => normalizePhalaSevenCvmHistoricalRuntimeBinding(fixture),
    /nonproduction/,
  );
});

test("historical R binding rejects accessors before reading embedded authority", () => {
  const fixture = bindingFixture();
  Object.defineProperty(fixture, "release_sha", {
    enumerable: true,
    get() { return "ab".repeat(20); },
  });
  assert.throws(
    () => normalizePhalaSevenCvmHistoricalRuntimeBinding(fixture),
    /canonical plain-data graph/,
  );
});

test("historical R binding leaf has no clock, effectful import, or authority brand", async () => {
  const source = await readFile(
    new URL("./phala-seven-cvm-historical-runtime-binding-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:os",
    "node:child_process",
    "Date.now(",
    "WeakMap",
    "process.",
    "import(",
    "phala-seven-cvm-launch-completion.mjs",
    "phala-seven-cvm-verifier-evidence.mjs",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
