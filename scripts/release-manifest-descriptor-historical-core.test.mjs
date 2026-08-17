import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CVM_LAUNCH_DOMAINS,
  CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
  CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
  CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
  HistoricalReleaseManifestDescriptorEvidenceError,
  PINNED_GH_TOOL,
  RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_DOMAIN,
  RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_SCHEMA,
  RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUST_BOUNDARY,
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
  canonicalCvmReleaseDescriptorSetReceiptText,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  cvmReleaseDescriptorSetReceiptSha256,
  historicalReleaseManifestDescriptorEvidenceSha256,
  normalizeCvmReleaseDescriptorSetReceipt,
  normalizeHistoricalReleaseManifestDescriptorEvidence,
  normalizeReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationReceiptSha256,
} from "./release-manifest-descriptor-historical-core.mjs";
import {
  canonicalReleaseManifestSigstoreVerificationReceiptText as productionCanonicalSigstoreText,
  normalizeReleaseManifestSigstoreVerificationReceipt as productionNormalizeSigstore,
  releaseManifestSigstoreVerificationReceiptSha256 as productionSigstoreSha256,
} from "./release-manifest-sigstore-verifier.mjs";
import {
  canonicalCvmReleaseDescriptorSetReceiptText as productionCanonicalDescriptorText,
  cvmReleaseDescriptorSetReceiptSha256 as productionDescriptorSha256,
  normalizeCvmReleaseDescriptorSetReceipt as productionNormalizeDescriptor,
} from "./cvm-release-descriptor-set.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CORE_FILE = path.join(HERE, "release-manifest-descriptor-historical-core.mjs");
const RELEASE_SHA = "a".repeat(40);
const MANIFEST_SHA256 = `sha256:${"b".repeat(64)}`;
const BUNDLE_SHA256 = `sha256:${"c".repeat(64)}`;

function sha(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function lengthPrefixedDomainDigest(domain, value) {
  const bytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return sha(Buffer.concat([
    Buffer.from(`${domain}\0`, "utf8"),
    length,
    bytes,
  ]));
}

function sigstoreFixture() {
  const identityText = `${JSON.stringify({
    repository: "therealwiki/dnai-wikigen",
    signer_workflow:
      "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    source_digest: RELEASE_SHA,
    source_ref: "refs/heads/main",
    subject_name: "dnai-tee-image-release.json",
    subject_sha256: MANIFEST_SHA256,
  })}\n`;
  return {
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
    status: "verified_by_pinned_gh_sigstore",
    blocker_code: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    blocker_status: "cleared_by_this_receipt",
    release_sha: RELEASE_SHA,
    release_manifest_sha256: MANIFEST_SHA256,
    release_manifest_sigstore_bundle_sha256: BUNDLE_SHA256,
    gh_executable_sha256: PINNED_GH_TOOL.sha256,
    gh_executable_path_sha256: lengthPrefixedDomainDigest(
      "dnai.pinned-gh-executable-path.v1",
      PINNED_GH_TOOL.path,
    ),
    gh_version_output_sha256:
      "sha256:b854454a206472d98565ff7c406ff085b3df45b833044782c099302a09c280d9",
    verification_command_sha256: `sha256:${"d".repeat(64)}`,
    verification_output_sha256: `sha256:${"e".repeat(64)}`,
    verified_identity_sha256: lengthPrefixedDomainDigest(
      "dnai.tee-image-release-manifest-sigstore-identity.v1",
      identityText,
    ),
  };
}

function descriptorFixture() {
  const imageNames = [
    "tinker-delegate",
    "tee-email-oracle",
    "neko-chrome",
    "attestation-qvl",
    "compute-metering",
  ];
  return {
    schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status:
      "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: structuredClone(
      CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    ),
    release_sha: RELEASE_SHA,
    source_ref: "refs/heads/main",
    image_manifest_sha256: MANIFEST_SHA256,
    image_manifest_sigstore_bundle_sha256: BUNDLE_SHA256,
    topology_sha256: `sha256:${"f".repeat(64)}`,
    descriptor_sha256_by_domain: Object.fromEntries(
      CVM_LAUNCH_DOMAINS.map((domain, index) => [
        domain,
        `sha256:${(index + 1).toString(16).repeat(64)}`,
      ]),
    ),
    service_matrix: structuredClone(CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX),
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

function evidenceFixture() {
  return {
    sigstoreReceipt: sigstoreFixture(),
    descriptorSetReceipt: descriptorFixture(),
    expectedReleaseSha: RELEASE_SHA,
  };
}

test("pure historical normalizers preserve production receipt bytes and digests", () => {
  const sigstore = sigstoreFixture();
  const descriptors = descriptorFixture();
  const normalizedSigstore = normalizeReleaseManifestSigstoreVerificationReceipt(
    sigstore,
  );
  const normalizedDescriptors = normalizeCvmReleaseDescriptorSetReceipt(descriptors);

  assert.deepEqual(normalizedSigstore, productionNormalizeSigstore(sigstore));
  assert.deepEqual(normalizedDescriptors, productionNormalizeDescriptor(descriptors));
  assert.equal(
    canonicalReleaseManifestSigstoreVerificationReceiptText(sigstore),
    productionCanonicalSigstoreText(sigstore),
  );
  assert.equal(
    canonicalCvmReleaseDescriptorSetReceiptText(descriptors),
    productionCanonicalDescriptorText(descriptors),
  );
  assert.equal(
    releaseManifestSigstoreVerificationReceiptSha256(sigstore),
    productionSigstoreSha256(sigstore),
  );
  assert.equal(
    cvmReleaseDescriptorSetReceiptSha256(descriptors),
    productionDescriptorSha256(descriptors),
  );
  assert.equal(Object.isFrozen(normalizedSigstore), true);
  assert.equal(Object.isFrozen(normalizedDescriptors), true);
  assert.equal(Object.isFrozen(normalizedDescriptors.service_matrix), true);
});

test("historical projector binds release, manifest, bundle, and exact receipt digests", () => {
  const input = evidenceFixture();
  const result = normalizeHistoricalReleaseManifestDescriptorEvidence(input);
  assert.equal(result.schema, RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_SCHEMA);
  assert.equal(
    result.status,
    "historical_receipt_semantics_and_cross_bindings_validated",
  );
  assert.equal(result.release_sha, RELEASE_SHA);
  assert.equal(result.image_manifest_sha256, MANIFEST_SHA256);
  assert.equal(result.image_manifest_sigstore_bundle_sha256, BUNDLE_SHA256);
  assert.equal(
    result.release_manifest_sigstore_verification_receipt_sha256,
    releaseManifestSigstoreVerificationReceiptSha256(input.sigstoreReceipt),
  );
  assert.equal(
    result.cvm_release_descriptor_set_receipt_sha256,
    cvmReleaseDescriptorSetReceiptSha256(input.descriptorSetReceipt),
  );
  assert.deepEqual(
    result.trust_boundary,
    RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUST_BOUNDARY,
  );
  assert.match(
    historicalReleaseManifestDescriptorEvidenceSha256(input),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(Object.isFrozen(result.trust_boundary), true);
});

test("historical trust labels never imply current Sigstore, network, deployment, or TDX verification", () => {
  assert.deepEqual(RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUST_BOUNDARY, {
    historical_receipt_semantics_validated: true,
    outer_exact_file_identity_and_lineage_required: true,
    sigstore_bundle_cryptographic_verification_rerun: false,
    sigstore_transparency_log_or_network_queried: false,
    pinned_gh_executable_invoked: false,
    raw_manifest_or_bundle_bytes_reread: false,
    descriptor_bytes_or_topology_reread: false,
    descriptor_reproduction_rerun: false,
    cvm_creation_or_runtime_observed: false,
    tdx_attestation_verified: false,
    current_freshness_claimed: false,
  });
  assert.equal(
    RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY.status,
    "verified_by_pinned_gh_sigstore",
  );
  assert.equal(
    normalizeHistoricalReleaseManifestDescriptorEvidence(evidenceFixture())
      .truth_status,
    "persisted_receipt_semantics_and_cross_bindings_validated_without_rerunning_sigstore_descriptor_reproduction_deployment_or_tdx",
  );
});

test("receipt and cross-binding tampering fails closed", async (t) => {
  const mutations = [
    ["Sigstore receipt brand", (value) => {
      value.sigstoreReceipt.status = "test_adapter_verified_not_release_authority";
    }],
    ["Sigstore verified identity", (value) => {
      value.sigstoreReceipt.verified_identity_sha256 = `sha256:${"1".repeat(64)}`;
    }],
    ["Sigstore zero digest", (value) => {
      value.sigstoreReceipt.verification_output_sha256 = `sha256:${"0".repeat(64)}`;
    }],
    ["expected release", (value) => {
      value.expectedReleaseSha = "9".repeat(40);
    }],
    ["descriptor release", (value) => {
      value.descriptorSetReceipt.release_sha = "9".repeat(40);
    }],
    ["manifest cross-binding", (value) => {
      value.descriptorSetReceipt.image_manifest_sha256 = `sha256:${"9".repeat(64)}`;
    }],
    ["bundle cross-binding", (value) => {
      value.descriptorSetReceipt.image_manifest_sigstore_bundle_sha256 =
        `sha256:${"9".repeat(64)}`;
    }],
    ["duplicate descriptor", (value) => {
      value.descriptorSetReceipt.descriptor_sha256_by_domain.diligence_qvl_cvm =
        value.descriptorSetReceipt.descriptor_sha256_by_domain.main_runtime_cvm;
    }],
    ["deployment claim", (value) => {
      value.descriptorSetReceipt.invariants.deployment_claimed = true;
    }],
    ["extra semantic field", (value) => {
      value.descriptorSetReceipt.runtime_verified = true;
    }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      const candidate = evidenceFixture();
      mutate(candidate);
      assert.throws(
        () => normalizeHistoricalReleaseManifestDescriptorEvidence(candidate),
        (error) => error instanceof Error,
      );
    });
  }
});

test("accessors are rejected without executing them", () => {
  let topLevelGetterCalls = 0;
  const topLevel = evidenceFixture();
  Object.defineProperty(topLevel, "sigstoreReceipt", {
    enumerable: true,
    get() {
      topLevelGetterCalls += 1;
      throw new Error("getter executed");
    },
  });
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(topLevel),
    /accessors and non-enumerable data fields are forbidden/,
  );
  assert.equal(topLevelGetterCalls, 0);

  let nestedGetterCalls = 0;
  const nested = evidenceFixture();
  Object.defineProperty(nested.descriptorSetReceipt.invariants, "deployment_claimed", {
    enumerable: true,
    get() {
      nestedGetterCalls += 1;
      throw new Error("nested getter executed");
    },
  });
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(nested),
    /accessors and non-enumerable data fields are forbidden/,
  );
  assert.equal(nestedGetterCalls, 0);
});

test("custom prototypes, cycles, sparse arrays, and symbols are rejected", () => {
  const custom = evidenceFixture();
  Object.setPrototypeOf(custom.sigstoreReceipt, { forged: true });
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(custom),
    /custom prototypes are forbidden/,
  );

  const cyclic = evidenceFixture();
  cyclic.descriptorSetReceipt.invariants.loop = cyclic;
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(cyclic),
    /cycles are forbidden/,
  );

  const sparse = evidenceFixture();
  sparse.descriptorSetReceipt.image_references.length += 1;
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(sparse),
    /arrays must be dense/,
  );

  const symbol = evidenceFixture();
  symbol.descriptorSetReceipt[Symbol("forged")] = true;
  assert.throws(
    () => normalizeHistoricalReleaseManifestDescriptorEvidence(symbol),
    /symbol keys are forbidden/,
  );
});

test("canonical digest KATs are deterministic and order-independent", () => {
  const input = evidenceFixture();
  const reversedSigstore = Object.fromEntries(
    Object.entries(input.sigstoreReceipt).reverse(),
  );
  const reversedDescriptors = Object.fromEntries(
    Object.entries(input.descriptorSetReceipt).reverse(),
  );
  assert.equal(
    releaseManifestSigstoreVerificationReceiptSha256(reversedSigstore),
    releaseManifestSigstoreVerificationReceiptSha256(input.sigstoreReceipt),
  );
  assert.equal(
    cvmReleaseDescriptorSetReceiptSha256(reversedDescriptors),
    cvmReleaseDescriptorSetReceiptSha256(input.descriptorSetReceipt),
  );
  assert.equal(
    RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN,
    "dnai-wikigen/tee-image-release-manifest-sigstore-verification/v1\0",
  );
  assert.equal(
    CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN,
    "dnai-wikigen/cvm-release-descriptor-set-validation/v2\0",
  );
  assert.equal(
    RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_DOMAIN,
    "dnai-wikigen/release-manifest-descriptor-historical-evidence/v1\0",
  );
});

function staticImports(source) {
  const imports = [];
  const pattern = /(?:^|\n)\s*(?:import|export)\s+(?:[^;"']*?\sfrom\s+)?["']([^"']+)["']/g;
  for (const match of source.matchAll(pattern)) imports.push(match[1]);
  return imports;
}

async function localImportGraph(entry) {
  const graph = new Map();
  async function visit(file) {
    if (graph.has(file)) return;
    const source = await readFile(file, "utf8");
    assert.doesNotMatch(source, /\bimport\s*\(/, `${file} has dynamic import`);
    const specifiers = staticImports(source);
    graph.set(file, specifiers);
    for (const specifier of specifiers) {
      if (specifier.startsWith("node:")) continue;
      if (!specifier.startsWith(".")) {
        assert.fail(`${file} imports external package ${specifier}`);
      }
      await visit(path.resolve(path.dirname(file), specifier));
    }
  }
  await visit(entry);
  return graph;
}

function assertAcyclic(graph, entry) {
  const active = new Set();
  const visited = new Set();
  function visit(file) {
    if (active.has(file)) assert.fail(`cycle reaches ${file}`);
    if (visited.has(file)) return;
    active.add(file);
    for (const specifier of graph.get(file) || []) {
      if (!specifier.startsWith(".")) continue;
      visit(path.resolve(path.dirname(file), specifier));
    }
    active.delete(file);
    visited.add(file);
  }
  visit(entry);
}

test("pure core has a two-module acyclic Cloudflare-safe import closure", async () => {
  const graph = await localImportGraph(CORE_FILE);
  assert.deepEqual(
    [...graph.keys()].map((file) => path.basename(file)).sort(),
    ["canonical-authority-graph.mjs", "release-manifest-descriptor-historical-core.mjs"],
  );
  assert.deepEqual(
    [...new Set([...graph.values()].flat().filter((item) => item.startsWith("node:")))],
    ["node:crypto", "node:util"],
  );
  assertAcyclic(graph, CORE_FILE);
  for (const file of graph.keys()) {
    const source = await readFile(file, "utf8");
    assert.doesNotMatch(
      source,
      /node:(?:fs|path|os|child_process|net|https)|\bDate\.now\s*\(|\bfetch\s*\(|\bprocess\s*\./,
    );
  }
});

test("historical core rejects malformed inputs with a stable typed error", () => {
  assert.throws(
    () => normalizeReleaseManifestSigstoreVerificationReceipt({}),
    (error) => error instanceof HistoricalReleaseManifestDescriptorEvidenceError
      && error.code === "release_manifest_sigstore_receipt_fields_invalid",
  );
});
