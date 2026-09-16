import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  CVM_LAUNCH_DOMAINS as HISTORICAL_CVM_LAUNCH_DOMAINS,
  CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA as
    HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256 as
    historicalCvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt as
    normalizeHistoricalCvmReleaseDescriptorSetReceipt,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  cvmReleaseDescriptorSetReceiptSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
} from "./cvm-release-descriptor-set-v3.mjs";
import {
  cvmDescriptorRuntimeFactsSha256 as
    legacyCvmDescriptorRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256 as
    legacyCvmDescriptorRuntimeAuthoritySha256,
  normalizeCvmDescriptorRuntimeAuthority as
    normalizeLegacyCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-core.mjs";
import {
  CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  cvmDescriptorRuntimeFactsSha256,
  cvmDescriptorRuntimeAuthoritySha256,
  normalizeCvmDescriptorRuntimeAuthority,
} from "./cvm-descriptor-runtime-authority-v2-core.mjs";
import {
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  freshContractDeploymentReceiptDigest,
  historicalFreshContractDeploymentReceiptV3Digest,
} from "./cvm-launch-intent-core.mjs";
import {
  syntheticFreshContractDeploymentReceiptFixture,
  syntheticHistoricalFreshContractDeploymentReceiptV3Fixture,
} from "./fresh-contract-deployment-receipt.fixture.mjs";
import {
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./current-cvm-authority-v4.fixture.mjs";
import {
  normalizeRecordedCvmAuthorityTuple,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";
import * as verifier from "./phala-seven-cvm-verifier-evidence.mjs";

const LEGACY_DESCRIPTOR_KAT =
  "sha256:03723b438e637c4bab1861fe970404e3d85e8b89cf6eee56fb2f9bb063a6b6d5";
const LEGACY_RUNTIME_KAT =
  "sha256:41dd30d5daff5af03c4efe5c603acec0bf62a0e90f4aac7f3b49f91ad4e94ecd";
const LEGACY_RELEASE_KAT =
  "sha256:ed04263edac1de5ce2eb185a918e33f89a485c58a4a1237922e5c380f2117125";

function historicalDescriptorReceipt() {
  const imageNames = [
    "tinker-delegate",
    "tee-email-oracle",
    "neko-chrome",
    "attestation-qvl",
    "compute-metering",
  ];
  return {
    schema: HISTORICAL_CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status:
      "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: structuredClone(
      HISTORICAL_CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    ),
    release_sha: "a".repeat(40),
    source_ref: "refs/heads/main",
    image_manifest_sha256: `sha256:${"b".repeat(64)}`,
    image_manifest_sigstore_bundle_sha256: `sha256:${"c".repeat(64)}`,
    topology_sha256: `sha256:${"f".repeat(64)}`,
    descriptor_sha256_by_domain: Object.fromEntries(
      HISTORICAL_CVM_LAUNCH_DOMAINS.map((domain, index) => [
        domain,
        `sha256:${(index + 1).toString(16).repeat(64)}`,
      ]),
    ),
    service_matrix: structuredClone(
      HISTORICAL_CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
    ),
    image_references: imageNames.map((name, index) => (
      `ghcr.io/therealwiki/dnai-wikigen/${name}@sha256:${(index + 8)
        .toString(16).repeat(64)}`
    )),
    invariants: {
      all_seven_generated_files_present: true,
      exact_raw_hashes_bound_by_topology: true,
      exact_service_matrices: true,
      exact_clean_ci_image_digests: true,
      embedded_secret_values: false,
      deployment_claimed: false,
      tdx_attestation_claimed: false,
    },
  };
}

function currentDescriptorReceipt() {
  const value = historicalDescriptorReceipt();
  value.schema = CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA;
  value.tinker_account_binding_ceremony_receipt_sha256 =
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256;
  value.service_matrix = structuredClone(
    CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  );
  return value;
}

function authorityForTuple({
  authority,
  descriptorSetReceiptSha256,
  freshContractDeploymentReceiptSha256,
  current,
}) {
  const value = structuredClone(authority);
  value.cvm_descriptor_runtime_authority.descriptor_set_receipt_sha256 =
    descriptorSetReceiptSha256;
  value.cvm_descriptor_runtime_authority.descriptor_runtime_facts_sha256 =
    current
      ? cvmDescriptorRuntimeFactsSha256(
        value.cvm_descriptor_runtime_authority,
      )
      : legacyCvmDescriptorRuntimeFactsSha256(
        value.cvm_descriptor_runtime_authority,
      );
  value.cvm_descriptor_runtime_authority_sha256 = current
    ? cvmDescriptorRuntimeAuthoritySha256(
      value.cvm_descriptor_runtime_authority,
    )
    : legacyCvmDescriptorRuntimeAuthoritySha256(
      value.cvm_descriptor_runtime_authority,
    );
  value.contracts.fresh_contract_deployment_receipt_sha256 =
    freshContractDeploymentReceiptSha256;
  return current
    ? normalizePhalaSevenCvmReleaseVerificationAuthority(value)
    : normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(value);
}

test("current authority chain is exactly descriptor v3 to runtime v2 to release v4", () => {
  const current = syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture();
  assert.equal(
    current.schema,
    PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  );
  assert.equal(
    current.cvm_descriptor_runtime_authority.schema,
    CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  );
  assert.equal(
    current.cvm_descriptor_runtime_authority.descriptor_set_receipt_schema,
    CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  );
  assert.equal(
    current.cvm_descriptor_runtime_authority
      .tinker_account_binding_ceremony_receipt_sha256,
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  );
  assert.equal(
    current.tinker_account_binding_ceremony_receipt_sha256,
    CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  );
  assert.deepEqual(
    current.cvm_descriptor_runtime_authority.descriptors[0]
      .service_images.slice(-2).map(({ service }) => service),
    ["mailbox-genesis", "tinker-account-genesis"],
  );
});

test("descriptor, runtime, and release authority versions reject cross-version substitution", () => {
  const historicalDescriptor = normalizeHistoricalCvmReleaseDescriptorSetReceipt(
    historicalDescriptorReceipt(),
  );
  const currentDescriptor = normalizeCvmReleaseDescriptorSetReceipt(
    currentDescriptorReceipt(),
  );
  assert.throws(
    () => normalizeCvmReleaseDescriptorSetReceipt(historicalDescriptor),
    /(?:fields are not exact|authority is invalid)/,
  );
  assert.throws(
    () => normalizeHistoricalCvmReleaseDescriptorSetReceipt(currentDescriptor),
    /(?:authority(?: is|_)invalid|receipt_fields_invalid)/,
  );

  const legacy =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const current =
    syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture();
  assert.throws(
    () => normalizeCvmDescriptorRuntimeAuthority(
      legacy.cvm_descriptor_runtime_authority,
    ),
    /(?:must contain exactly the frozen fields|identity or evidence boundary is invalid)/,
  );
  assert.throws(
    () => normalizeLegacyCvmDescriptorRuntimeAuthority(
      current.cvm_descriptor_runtime_authority,
    ),
    /(?:must contain exactly the frozen fields|identity or evidence boundary is invalid)/,
  );
  assert.throws(
    () => normalizePhalaSevenCvmReleaseVerificationAuthority(legacy),
    /(?:must contain exactly the frozen fields|release verification authority is invalid)/,
  );
  assert.throws(
    () => normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(current),
    /(?:must contain exactly the frozen fields|release verification authority is invalid)/,
  );

  const substitutedCurrent = structuredClone(current);
  substitutedCurrent.tinker_account_binding_ceremony_receipt_sha256 =
    `sha256:${"92".repeat(32)}`;
  assert.throws(
    () => normalizePhalaSevenCvmReleaseVerificationAuthority(
      substitutedCurrent,
    ),
    /descriptor runtime authority object or digest drifted/,
  );
});

test("legacy descriptor v2, runtime v1, and release v3 KATs do not rotate", () => {
  const legacy =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  assert.equal(
    historicalCvmReleaseDescriptorSetReceiptSha256(
      historicalDescriptorReceipt(),
    ),
    LEGACY_DESCRIPTOR_KAT,
  );
  assert.equal(
    legacyCvmDescriptorRuntimeAuthoritySha256(
      legacy.cvm_descriptor_runtime_authority,
    ),
    LEGACY_RUNTIME_KAT,
  );
  assert.equal(
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(legacy),
    LEGACY_RELEASE_KAT,
  );
});

test("verifier uses explicit v4 current and v3 legacy branches without fallback", async () => {
  const legacy =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture();
  const current =
    syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture();
  assert.deepEqual(
    verifier.normalizePhalaSevenCvmReleaseVerificationAuthority(legacy),
    legacy,
  );
  assert.deepEqual(
    verifier.normalizePhalaSevenCvmReleaseVerificationAuthority(current),
    current,
  );
  assert.equal(
    verifier.phalaSevenCvmReleaseVerificationAuthoritySha256(legacy),
    LEGACY_RELEASE_KAT,
  );
  assert.equal(
    verifier.phalaSevenCvmReleaseVerificationAuthoritySha256(current),
    phalaSevenCvmReleaseVerificationAuthoritySha256(current),
  );
  assert.notEqual(
    cvmReleaseDescriptorSetReceiptSha256(currentDescriptorReceipt()),
    LEGACY_DESCRIPTOR_KAT,
  );
  assert.notEqual(
    cvmDescriptorRuntimeAuthoritySha256(
      current.cvm_descriptor_runtime_authority,
    ),
    LEGACY_RUNTIME_KAT,
  );

  const source = await readFile(
    new URL("./phala-seven-cvm-verifier-evidence.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /from "\.\/cvm-descriptor-runtime-authority-v2\.mjs"/,
  );
  assert.match(
    source,
    /from "\.\/phala-seven-cvm-release-verification-authority-v4-core\.mjs"/,
  );
  assert.match(
    source,
    /normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority/,
  );
  assert.doesNotMatch(source, /try\s*\{[\s\S]{0,300}normalizeCurrent/);
});

test("current preflight topology imports only the descriptor v3 service authority", async () => {
  const source = await readFile(
    new URL("./activation-preflight-core.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /from "\.\/cvm-release-descriptor-set-constants-v3\.mjs"/,
  );
  assert.doesNotMatch(
    source,
    /from "\.\/cvm-release-descriptor-set-constants\.mjs"/,
  );
  assert.deepEqual(
    CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX.main_runtime_cvm.slice(-2),
    ["mailbox-genesis", "tinker-account-genesis"],
  );
});

test("recorded-time authority tuples accept only v3/v4/v2/v4 or v2/v3/v1/v3", () => {
  const releaseSha = "a".repeat(40);
  const deploymentIntentSha256 = `sha256:${"b".repeat(64)}`;
  const reviewerAcceptanceSha256 = `sha256:${"c".repeat(64)}`;
  const currentDescriptor = normalizeCvmReleaseDescriptorSetReceipt(
    currentDescriptorReceipt(),
  );
  const historicalDescriptor =
    normalizeHistoricalCvmReleaseDescriptorSetReceipt(
      historicalDescriptorReceipt(),
    );
  const currentReceiptFixture = syntheticFreshContractDeploymentReceiptFixture({
    releaseSha,
    deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256: reviewerAcceptanceSha256,
    tinkerAccountBindingCeremonyReceiptSha256:
      CURRENT_TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  });
  const historicalReceiptFixture =
    syntheticHistoricalFreshContractDeploymentReceiptV3Fixture({
      releaseSha,
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256: reviewerAcceptanceSha256,
    });
  const currentReceiptSha256 =
    `sha256:${freshContractDeploymentReceiptDigest(
      currentReceiptFixture.receipt,
      currentReceiptFixture.authorityPins,
    )}`;
  const historicalReceiptSha256 =
    `sha256:${historicalFreshContractDeploymentReceiptV3Digest(
      historicalReceiptFixture.receipt,
      historicalReceiptFixture.authorityPins,
    )}`;
  const currentAuthority = authorityForTuple({
    authority:
      syntheticCurrentPhalaSevenCvmReleaseVerificationAuthorityFixture({
        releaseSha,
        deploymentIntentSha256,
      }),
    descriptorSetReceiptSha256:
      cvmReleaseDescriptorSetReceiptSha256(currentDescriptor),
    freshContractDeploymentReceiptSha256: currentReceiptSha256,
    current: true,
  });
  const historicalAuthority = authorityForTuple({
    authority: syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha,
      deploymentIntentSha256,
    }),
    descriptorSetReceiptSha256:
      historicalCvmReleaseDescriptorSetReceiptSha256(historicalDescriptor),
    freshContractDeploymentReceiptSha256: historicalReceiptSha256,
    current: false,
  });
  const base = {
    expectedDeploymentIntentSha256: deploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerAcceptanceSha256,
  };

  const current = normalizeRecordedCvmAuthorityTuple({
    ...base,
    releaseVerificationAuthority: currentAuthority,
    descriptorSetReceipt: currentDescriptor,
    freshContractDeploymentReceipt: currentReceiptFixture.receipt,
  });
  assert.equal(current.current_tuple, true);
  assert.equal(
    current.release_verification_authority.schema,
    PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  );
  assert.equal(
    current.release_verification_authority
      .cvm_descriptor_runtime_authority.schema,
    CVM_DESCRIPTOR_RUNTIME_AUTHORITY_SCHEMA,
  );

  const historical = normalizeRecordedCvmAuthorityTuple({
    ...base,
    releaseVerificationAuthority: historicalAuthority,
    descriptorSetReceipt: historicalDescriptor,
    freshContractDeploymentReceipt: historicalReceiptFixture.receipt,
  });
  assert.equal(historical.current_tuple, false);

  assert.throws(
    () => normalizeRecordedCvmAuthorityTuple({
      ...base,
      releaseVerificationAuthority: currentAuthority,
      descriptorSetReceipt: currentDescriptor,
      freshContractDeploymentReceipt: historicalReceiptFixture.receipt,
    }),
    /fresh contract deployment receipt/,
  );
  assert.throws(
    () => normalizeRecordedCvmAuthorityTuple({
      ...base,
      releaseVerificationAuthority: historicalAuthority,
      descriptorSetReceipt: historicalDescriptor,
      freshContractDeploymentReceipt: currentReceiptFixture.receipt,
    }),
    /fresh contract deployment receipt/,
  );
});
