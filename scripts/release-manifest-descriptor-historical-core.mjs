import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";

// This module is the pure, replay-only half of two production adapters:
// release-manifest-sigstore-verifier.mjs and cvm-release-descriptor-set.mjs.
// It validates the exact semantics and domain-separated digests carried by
// already-persisted receipts. It deliberately does not read artifacts, invoke
// `gh`, contact Sigstore, reproduce descriptors, or make deployment/TDX claims.

export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA =
  "dnai.tee-image-release-manifest-sigstore-verification.v1";
export const RELEASE_MANIFEST_SIGSTORE_BLOCKER =
  "release_manifest_sigstore_bundle_not_cryptographically_verified";
export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN =
  "dnai-wikigen/tee-image-release-manifest-sigstore-verification/v1\0";

export const RELEASE_MANIFEST_SIGSTORE_AUTHORITY = Object.freeze({
  repository: "therealwiki/dnai-wikigen",
  source_ref: "refs/heads/main",
  signer_workflow:
    "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
  predicate_type: "https://slsa.dev/provenance/v1",
  subject_filename: "dnai-tee-image-release.json",
  bundle_filename: "dnai-tee-image-release.bundle.json",
});

export const PINNED_GH_TOOL = Object.freeze({
  path: "/opt/homebrew/Cellar/gh/2.87.3/bin/gh",
  version: "2.87.3",
  sha256:
    "sha256:67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70",
});

export const CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA =
  "dnai.cvm-release-descriptor-set-validation.v2";
export const CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN =
  "dnai-wikigen/cvm-release-descriptor-set-validation/v2\0";

export const CVM_LAUNCH_DOMAINS = Object.freeze([
  "main_runtime_cvm",
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
  "independent_metering_cvm",
]);

export const CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY = Object.freeze({
  tracked_source_status: "reviewed_repo_sources_only",
  generated_output_status: "ignored_release_evidence_not_source_controlled",
  generated_output_directory: ".release",
  deployment_claimed: false,
  tdx_attestation_claimed: false,
});

export const CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX = deepFreezeCanonicalPlainDataGraph({
  main_runtime_cvm: [
    "neko",
    "oracle",
    "delegate",
    "diligence-policy-init",
    "arena-policy-init",
    "arena-worker",
    "anchor-writer-evidence",
    "deal-runtime",
    "compute-execution-worker",
  ],
  diligence_qvl_cvm: ["policy-init", "qvl"],
  arena_qvl_cvm: ["policy-init", "qvl"],
  anchor_writer_qvl_cvm: ["policy-init", "qvl"],
  compute_workload_qvl_cvm: ["policy-init", "qvl"],
  compute_metering_qvl_cvm: ["policy-init", "qvl"],
  independent_metering_cvm: ["policy-init", "state-init", "metering"],
}, { label: "historical descriptor service matrix" });

export const RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_SCHEMA =
  "dnai.release-manifest-descriptor-historical-evidence.v1";
export const RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_DOMAIN =
  "dnai-wikigen/release-manifest-descriptor-historical-evidence/v1\0";
export const RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUTH_STATUS =
  "persisted_receipt_semantics_and_cross_bindings_validated_without_rerunning_sigstore_descriptor_reproduction_deployment_or_tdx";

export const RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUST_BOUNDARY =
  deepFreezeCanonicalPlainDataGraph({
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
  }, { label: "historical release-manifest/descriptor trust boundary" });

const PRODUCTION_SIGSTORE_RECEIPT_KEYS = Object.freeze([
  "schema",
  "status",
  "blocker_code",
  "blocker_status",
  "release_sha",
  "release_manifest_sha256",
  "release_manifest_sigstore_bundle_sha256",
  "gh_executable_sha256",
  "gh_executable_path_sha256",
  "gh_version_output_sha256",
  "verification_command_sha256",
  "verification_output_sha256",
  "verified_identity_sha256",
]);

const DESCRIPTOR_SET_RECEIPT_KEYS = Object.freeze([
  "schema",
  "status",
  "truth_status",
  "materialization_boundary",
  "release_sha",
  "source_ref",
  "image_manifest_sha256",
  "image_manifest_sigstore_bundle_sha256",
  "topology_sha256",
  "descriptor_sha256_by_domain",
  "service_matrix",
  "image_references",
  "invariants",
]);

const DESCRIPTOR_INVARIANT_KEYS = Object.freeze([
  "all_seven_generated_files_present",
  "exact_raw_hashes_bound_by_topology",
  "exact_service_matrices",
  "exact_clean_ci_image_digests",
  "embedded_secret_values",
  "deployment_claimed",
  "tdx_attestation_claimed",
]);

const HISTORICAL_EVIDENCE_INPUT_KEYS = Object.freeze([
  "sigstoreReceipt",
  "descriptorSetReceipt",
  "expectedReleaseSha",
]);

const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const DESCRIPTOR_RELEASE_SHA = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const IMAGE_REFERENCE =
  /^ghcr\.io\/therealwiki\/dnai-wikigen\/([a-z0-9-]+)@sha256:([0-9a-f]{64})$/;
const RELEASE_SOURCE_REF =
  /^refs\/(?:heads\/main|tags\/v[0-9][0-9A-Za-z._-]*)$/;
const UTF8 = new TextEncoder();

export class HistoricalReleaseManifestDescriptorEvidenceError extends TypeError {
  constructor(code) {
    super(code);
    this.name = "HistoricalReleaseManifestDescriptorEvidenceError";
    this.code = code;
  }
}

function reject(code) {
  throw new HistoricalReleaseManifestDescriptorEvidenceError(code);
}

function exactRecord(value, fields, code) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    reject(code);
  }
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify([...ownKeys].sort()) !== JSON.stringify([...fields].sort())
    || Object.values(descriptors).some((descriptor) => (
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true
    ))) {
    reject(code);
  }
  return value;
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalSortedJsonText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function sha256() {
  return createHash("sha256");
}

function prefixedDigest(hash) {
  return `sha256:${hash.digest("hex")}`;
}

function canonicalSha256(value, code) {
  if (typeof value !== "string" || !SHA256.test(value)) reject(code);
  return value;
}

function unsignedBigEndian64(value) {
  if (!Number.isSafeInteger(value) || value < 0) reject("byte_length_invalid");
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

function lengthPrefixedDomainDigest(domain, text) {
  const bytes = UTF8.encode(text);
  return prefixedDigest(
    sha256()
      .update(`${domain}\0`, "utf8")
      .update(unsignedBigEndian64(bytes.byteLength))
      .update(bytes),
  );
}

function releaseManifestVerifiedIdentitySha256(releaseSha, manifestSha256) {
  return lengthPrefixedDomainDigest(
    "dnai.tee-image-release-manifest-sigstore-identity.v1",
    `${JSON.stringify({
      repository: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository,
      signer_workflow: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.signer_workflow,
      source_digest: releaseSha,
      source_ref: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.source_ref,
      subject_name: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
      subject_sha256: manifestSha256,
    })}\n`,
  );
}

const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY = Object.freeze({
  schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
  status: "verified_by_pinned_gh_sigstore",
  blocker_code: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  blocker_status: "cleared_by_this_receipt",
  gh_executable_sha256: PINNED_GH_TOOL.sha256,
  gh_executable_path_sha256: lengthPrefixedDomainDigest(
    "dnai.pinned-gh-executable-path.v1",
    PINNED_GH_TOOL.path,
  ),
  gh_version_output_sha256:
    "sha256:b854454a206472d98565ff7c406ff085b3df45b833044782c099302a09c280d9",
});

export { RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY };

/**
 * Normalize the exact semantics of a persisted receipt carrying the production
 * verifier's status vocabulary.
 * Acceptance here means the historical receipt is structurally canonical and
 * self-consistent. It does not rerun the verification operation represented by
 * the receipt's `verified_by_pinned_gh_sigstore` status.
 */
export function normalizeHistoricalReleaseManifestSigstoreVerificationReceipt(
  value,
) {
  assertCanonicalPlainDataGraph(value, {
    label: "historical release-manifest Sigstore verification receipt",
  });
  const parsed = exactRecord(
    value,
    PRODUCTION_SIGSTORE_RECEIPT_KEYS,
    "release_manifest_sigstore_receipt_fields_invalid",
  );
  const authority = RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY;
  if (parsed.schema !== authority.schema
    || parsed.status !== authority.status
    || parsed.blocker_code !== authority.blocker_code
    || parsed.blocker_status !== authority.blocker_status
    || parsed.gh_executable_sha256 !== authority.gh_executable_sha256
    || parsed.gh_executable_path_sha256 !== authority.gh_executable_path_sha256
    || parsed.gh_version_output_sha256 !== authority.gh_version_output_sha256) {
    reject("release_manifest_sigstore_receipt_authority_invalid");
  }
  if (typeof parsed.release_sha !== "string" || !RELEASE_SHA.test(parsed.release_sha)) {
    reject("expected_release_sha_invalid");
  }
  for (const field of [
    "release_manifest_sha256",
    "release_manifest_sigstore_bundle_sha256",
    "verification_command_sha256",
    "verification_output_sha256",
    "verified_identity_sha256",
  ]) {
    canonicalSha256(parsed[field], "release_manifest_sigstore_receipt_digest_invalid");
  }
  if (parsed.verified_identity_sha256 !== releaseManifestVerifiedIdentitySha256(
    parsed.release_sha,
    parsed.release_manifest_sha256,
  )) {
    reject("release_manifest_sigstore_receipt_identity_invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: authority.schema,
    status: authority.status,
    blocker_code: authority.blocker_code,
    blocker_status: authority.blocker_status,
    release_sha: parsed.release_sha,
    release_manifest_sha256: parsed.release_manifest_sha256,
    release_manifest_sigstore_bundle_sha256:
      parsed.release_manifest_sigstore_bundle_sha256,
    gh_executable_sha256: authority.gh_executable_sha256,
    gh_executable_path_sha256: authority.gh_executable_path_sha256,
    gh_version_output_sha256: authority.gh_version_output_sha256,
    verification_command_sha256: parsed.verification_command_sha256,
    verification_output_sha256: parsed.verification_output_sha256,
    verified_identity_sha256: parsed.verified_identity_sha256,
  }, { label: "normalized historical Sigstore receipt" });
}

export function canonicalHistoricalReleaseManifestSigstoreVerificationReceiptText(
  value,
) {
  return `${JSON.stringify(
    normalizeHistoricalReleaseManifestSigstoreVerificationReceipt(value),
    null,
    2,
  )}\n`;
}

export function historicalReleaseManifestSigstoreVerificationReceiptSha256(value) {
  return prefixedDigest(
    sha256()
      .update(RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN, "utf8")
      .update(
        canonicalHistoricalReleaseManifestSigstoreVerificationReceiptText(value),
        "utf8",
      ),
  );
}

/**
 * Normalize a persisted receipt emitted by the descriptor materialization
 * adapter. This validates its exact historical claims; it does not reread or
 * reproduce the descriptor, topology, manifest, or bundle bytes.
 */
export function normalizeHistoricalCvmReleaseDescriptorSetReceipt(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "historical CVM release descriptor-set receipt",
  });
  const parsed = exactRecord(
    value,
    DESCRIPTOR_SET_RECEIPT_KEYS,
    "cvm_descriptor_set_receipt_fields_invalid",
  );
  if (parsed.schema !== CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA
    || parsed.status !== "validated_rendered_not_deployed"
    || parsed.truth_status
      !== "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence"
    || !same(parsed.materialization_boundary,
      CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY)
    || typeof parsed.release_sha !== "string"
    || !DESCRIPTOR_RELEASE_SHA.test(parsed.release_sha)
    || typeof parsed.source_ref !== "string"
    || !RELEASE_SOURCE_REF.test(parsed.source_ref)) {
    reject("cvm_descriptor_set_receipt_authority_invalid");
  }

  const descriptorMap = exactRecord(
    parsed.descriptor_sha256_by_domain,
    CVM_LAUNCH_DOMAINS,
    "cvm_descriptor_set_receipt_descriptor_map_invalid",
  );
  const normalizedDescriptorMap = Object.fromEntries(
    CVM_LAUNCH_DOMAINS.map((domain) => [
      domain,
      canonicalSha256(
        descriptorMap[domain],
        `cvm_descriptor_set_receipt_${domain}_digest_invalid`,
      ),
    ]),
  );
  if (new Set(Object.values(normalizedDescriptorMap)).size !== CVM_LAUNCH_DOMAINS.length
    || !same(parsed.service_matrix, CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX)
    || !Array.isArray(parsed.image_references)
    || parsed.image_references.length !== 5
    || parsed.image_references.some((reference) => (
      typeof reference !== "string" || !IMAGE_REFERENCE.test(reference)
    ))
    || new Set(parsed.image_references).size !== 5) {
    reject("cvm_descriptor_set_receipt_domain_or_image_set_invalid");
  }

  const invariants = exactRecord(
    parsed.invariants,
    DESCRIPTOR_INVARIANT_KEYS,
    "cvm_descriptor_set_receipt_invariants_invalid",
  );
  if (invariants.all_seven_generated_files_present !== true
    || invariants.exact_raw_hashes_bound_by_topology !== true
    || invariants.exact_service_matrices !== true
    || invariants.exact_clean_ci_image_digests !== true
    || invariants.embedded_secret_values !== false
    || invariants.deployment_claimed !== false
    || invariants.tdx_attestation_claimed !== false) {
    reject("cvm_descriptor_set_receipt_invariants_invalid");
  }

  return deepFreezeCanonicalPlainDataGraph({
    schema: CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_SCHEMA,
    status: "validated_rendered_not_deployed",
    truth_status:
      "descriptor_consistency_not_cvm_creation_tdx_or_runtime_evidence",
    materialization_boundary: {
      ...CVM_RELEASE_DESCRIPTOR_MATERIALIZATION_BOUNDARY,
    },
    release_sha: parsed.release_sha,
    source_ref: parsed.source_ref,
    image_manifest_sha256: canonicalSha256(
      parsed.image_manifest_sha256,
      "cvm_descriptor_set_receipt_manifest_digest_invalid",
    ),
    image_manifest_sigstore_bundle_sha256: canonicalSha256(
      parsed.image_manifest_sigstore_bundle_sha256,
      "cvm_descriptor_set_receipt_bundle_digest_invalid",
    ),
    topology_sha256: canonicalSha256(
      parsed.topology_sha256,
      "cvm_descriptor_set_receipt_topology_digest_invalid",
    ),
    descriptor_sha256_by_domain: normalizedDescriptorMap,
    service_matrix: Object.fromEntries(
      CVM_LAUNCH_DOMAINS.map((domain) => [
        domain,
        [...CVM_RELEASE_DESCRIPTOR_SERVICE_MATRIX[domain]],
      ]),
    ),
    image_references: [...parsed.image_references],
    invariants: {
      all_seven_generated_files_present: true,
      exact_raw_hashes_bound_by_topology: true,
      exact_service_matrices: true,
      exact_clean_ci_image_digests: true,
      embedded_secret_values: false,
      deployment_claimed: false,
      tdx_attestation_claimed: false,
    },
  }, { label: "normalized historical descriptor-set receipt" });
}

export function canonicalHistoricalCvmReleaseDescriptorSetReceiptText(value) {
  return canonicalSortedJsonText(
    normalizeHistoricalCvmReleaseDescriptorSetReceipt(value),
  );
}

export function historicalCvmReleaseDescriptorSetReceiptSha256(value) {
  return prefixedDigest(
    sha256()
      .update(CVM_RELEASE_DESCRIPTOR_SET_RECEIPT_DOMAIN, "utf8")
      .update(canonicalHistoricalCvmReleaseDescriptorSetReceiptText(value), "utf8"),
  );
}

export function normalizeHistoricalReleaseManifestDescriptorEvidence(input) {
  assertCanonicalPlainDataGraph(input, {
    label: "historical release-manifest/descriptor evidence input",
  });
  const parsed = exactRecord(
    input,
    HISTORICAL_EVIDENCE_INPUT_KEYS,
    "historical_release_manifest_descriptor_input_invalid",
  );
  if (typeof parsed.expectedReleaseSha !== "string"
    || !RELEASE_SHA.test(parsed.expectedReleaseSha)) {
    reject("historical_release_manifest_descriptor_expected_release_invalid");
  }
  const sigstoreReceipt =
    normalizeHistoricalReleaseManifestSigstoreVerificationReceipt(
      parsed.sigstoreReceipt,
    );
  const descriptorSetReceipt =
    normalizeHistoricalCvmReleaseDescriptorSetReceipt(parsed.descriptorSetReceipt);
  if (sigstoreReceipt.release_sha !== parsed.expectedReleaseSha
    || descriptorSetReceipt.release_sha !== parsed.expectedReleaseSha) {
    reject("historical_release_manifest_descriptor_release_binding_invalid");
  }
  if (sigstoreReceipt.release_manifest_sha256
      !== descriptorSetReceipt.image_manifest_sha256) {
    reject("historical_release_manifest_descriptor_manifest_binding_invalid");
  }
  if (sigstoreReceipt.release_manifest_sigstore_bundle_sha256
      !== descriptorSetReceipt.image_manifest_sigstore_bundle_sha256) {
    reject("historical_release_manifest_descriptor_bundle_binding_invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_SCHEMA,
    status: "historical_receipt_semantics_and_cross_bindings_validated",
    truth_status: RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUTH_STATUS,
    release_sha: parsed.expectedReleaseSha,
    image_manifest_sha256: sigstoreReceipt.release_manifest_sha256,
    image_manifest_sigstore_bundle_sha256:
      sigstoreReceipt.release_manifest_sigstore_bundle_sha256,
    release_manifest_sigstore_verification_receipt_sha256:
      historicalReleaseManifestSigstoreVerificationReceiptSha256(sigstoreReceipt),
    cvm_release_descriptor_set_receipt_sha256:
      historicalCvmReleaseDescriptorSetReceiptSha256(descriptorSetReceipt),
    trust_boundary: {
      ...RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_TRUST_BOUNDARY,
    },
  }, { label: "historical release-manifest/descriptor evidence" });
}

export function historicalReleaseManifestDescriptorEvidenceSha256(value) {
  const normalized = normalizeHistoricalReleaseManifestDescriptorEvidence(value);
  return prefixedDigest(
    sha256()
      .update(RELEASE_MANIFEST_DESCRIPTOR_HISTORICAL_EVIDENCE_DOMAIN, "utf8")
      .update(canonicalSortedJsonText(normalized), "utf8"),
  );
}

// Compatibility aliases let exact37 switch only its import source while the
// effectful production adapters retain their existing public behavior.
export const normalizeReleaseManifestSigstoreVerificationReceipt =
  normalizeHistoricalReleaseManifestSigstoreVerificationReceipt;
export const canonicalReleaseManifestSigstoreVerificationReceiptText =
  canonicalHistoricalReleaseManifestSigstoreVerificationReceiptText;
export const releaseManifestSigstoreVerificationReceiptSha256 =
  historicalReleaseManifestSigstoreVerificationReceiptSha256;
export const normalizeCvmReleaseDescriptorSetReceipt =
  normalizeHistoricalCvmReleaseDescriptorSetReceipt;
export const canonicalCvmReleaseDescriptorSetReceiptText =
  canonicalHistoricalCvmReleaseDescriptorSetReceiptText;
export const cvmReleaseDescriptorSetReceiptSha256 =
  historicalCvmReleaseDescriptorSetReceiptSha256;
