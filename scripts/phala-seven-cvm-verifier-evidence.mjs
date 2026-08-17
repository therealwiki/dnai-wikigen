import { createHash, randomBytes as cryptoRandomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  OPENED_FD_RUNTIME_AUTHORITY_MODES,
  computePythonRuntimeTreeSha256,
  createPinnedSevenCvmOpenedFdRuntime,
} from "./phala-seven-cvm-opened-fd-runtime-core.mjs";
export { computePythonRuntimeTreeSha256 };
import {
  normalizeFreshContractDeploymentReceipt,
  freshContractDeploymentReceiptDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization.mjs";
import {
  bootstrapPublicEnvironmentAuthorityDigest,
  normalizeBootstrapPublicEnvironmentAuthority,
} from "./phala-bootstrap-public-environment-authority-core.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  normalizeProductionCvmPostureVerificationReceipt,
  productionCvmPostureVerificationReceiptSha256,
} from "./phala-production-posture-receipt.mjs";
import {
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  PHALA_QVL_MEASUREMENT_POLICY_ORDER,
  appraisePhalaQvlMeasurementsAgainstPolicy,
  normalizePhalaQvlMeasurementPolicy,
  normalizePhalaQvlMeasurementPolicySet,
  phalaQvlMeasurementPolicySetSha256,
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";
import {
  assertFreshCvmDescriptorRuntimeAuthority,
  cvmDescriptorRuntimeAuthoritySha256,
} from "./cvm-descriptor-runtime-authority-v2.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText as
    canonicalCurrentPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    currentPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA as
    LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  canonicalPhalaSevenCvmReleaseVerificationAuthorityText as
    canonicalLegacyPhalaSevenCvmReleaseVerificationAuthorityText,
  normalizePhalaSevenCvmReleaseVerificationAuthority as
    normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
export {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_DOMAIN,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES as
    MAX_HISTORICAL_TRANSCRIPT_SET_BYTES,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES as
    MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority,
  historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata,
} from "./phala-seven-cvm-historical-release-verification-authority.mjs";

export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA =
  "dnai.phala-qvl-identity-launch-verification.v5";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-qvl-identity-launch-verification/v5\0";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS =
  "fresh_challenge_bound_identity_quote_intel_tdx_dcap_verified_activation_appraisal_lease_issued_and_private_replay_transcript_prepared";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH =
  "release_authorized_measurement_policy_appraised_non_debug_identity_quote_fresh_challenge_report_data_and_authenticated_pccs_collateral_verified_with_policy_bounded_activation_evidence_lease_and_private_restart_replay_material_prepared_without_public_quote_or_collateral_disclosure";
export const PHALA_QVL_IDENTITY_ATTESTATION_REQUEST_SCHEMA =
  "dnai.qvl-identity-attestation-request.v3";
export const PHALA_QVL_IDENTITY_ATTESTATION_RESPONSE_SCHEMA =
  "dnai.qvl-identity-attestation-response.v3";
export const PHALA_WORKLOAD_QVL_CHALLENGE_SCHEMA =
  "dnai.attestation-qvl-challenge.v2";
export const PHALA_INDEPENDENT_TDX_VERDICT_SCHEMA =
  "dnai.independent-tdx-verdict.v4";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA =
  "dnai.phala-workload-tdx-verdict-verification.v5";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-workload-tdx-verdict-verification/v5\0";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS =
  "fresh_independent_qvl_signed_intel_tdx_verdict_activation_appraisal_lease_verified_and_private_replay_transcript_prepared";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_TRUTH =
  "release_lineage_qvl_challenge_and_verdict_signatures_policy_report_data_quote_and_policy_bounded_activation_evidence_lease_verified_with_private_restart_replay_material_prepared_without_public_quote_or_collateral_disclosure";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA =
  "dnai.phala-compute-workload-recipient-activation-verification.v4";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-compute-workload-recipient-activation-verification/v4\0";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS =
  "fresh_main_runtime_recipient_quote_independent_compute_workload_qvl_signature_and_recipient_evidence_lease_verified";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH =
  "release_lineage_signed_compute_workload_qvl_verdict_recipient_report_data_branded_main_runtime_fresh_vault_and_recipient_evidence_lease_verified_without_public_quote_or_collateral_disclosure";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA =
  "dnai.phala-seven-cvm-verified-evidence-set.v5";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-verified-evidence-set/v5\0";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS =
  "exact_seven_cvm_machine_verifier_evidence_activation_appraisal_leases_and_exact14_private_replay_transcript_prepared";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH =
  "five_policy_appraised_qvl_identities_and_two_release_lineage_bound_workloads_verified_with_policy_bounded_activation_evidence_leases_and_exact14_private_replay_material_required_without_public_quote_or_collateral_disclosure";
export const PHALA_SEVEN_CVM_MAX_COLLECTION_SKEW_SECONDS = 300;
export const PHALA_RELEASE_POSTURE_MAX_AGE_SECONDS = 300;
export const PHALA_RELEASE_POSTURE_MAX_FUTURE_SKEW_SECONDS = 30;
export const REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA =
  "dnai.phala-six-cvm-verified-evidence-set.v1";
export const REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_AUTHORITY =
  deepFreezeCanonicalPlainDataGraph({
    schema: REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
    domain: "dnai-wikigen/phala-six-cvm-verified-evidence-set/v1\0",
    status: "revoked_never_authoritative_after_exact_seven_cvm_topology",
  });
export const PHALA_VERIFIER_HISTORICAL_TRANSCRIPT_ARTIFACT_SCHEMA =
  "dnai.phala-verifier-historical-transcript-artifact.v2";
export const PHALA_VERIFIER_HISTORICAL_DCAP_REPLAY_RECORD_SCHEMA =
  "dnai.phala-verifier-historical-dcap-replay-record.v2";
export const PHALA_VERIFIER_HISTORICAL_SIGNATURE_REPLAY_RECORD_SCHEMA =
  "dnai.phala-verifier-historical-signature-replay-record.v2";
export const PHALA_SEVEN_CVM_HISTORICAL_CORROBORATION_SCHEMA =
  "dnai.phala-seven-cvm-historical-corroboration.v2";

export const PHALA_QVL_IDENTITY_DOMAIN_PROFILE = Object.freeze({
  diligence_qvl_cvm: "diligence",
  arena_qvl_cvm: "arena",
  anchor_writer_qvl_cvm: "execution_policy_anchor_writer",
  compute_workload_qvl_cvm: "compute_workload",
  compute_metering_qvl_cvm: "compute_metering",
});
export const PHALA_SEVEN_CVM_EXECUTION_ORDER = Object.freeze([
  "main_runtime_cvm",
  "diligence_qvl_cvm",
  "arena_qvl_cvm",
  "anchor_writer_qvl_cvm",
  "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm",
  "independent_metering_cvm",
]);

function releaseVerificationAuthoritySchema(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(
      "release verification authority version routing requires one object",
    );
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, "schema");
  if (!descriptor || !Object.hasOwn(descriptor, "value")
    || typeof descriptor.value !== "string") {
    throw new TypeError(
      "release verification authority version routing requires one own data schema",
    );
  }
  return descriptor.value;
}

/**
 * Pure version router for non-authorizing normalization and digest projection.
 *
 * Fresh production branding never enters through this router: the production
 * constructor below calls the v4 normalizer directly. The legacy v3 branch
 * exists only for the immutable synthetic fixtures and the explicitly
 * authenticated historical replay path. There is deliberately no
 * try-current-then-legacy fallback.
 */
export function normalizePhalaSevenCvmReleaseVerificationAuthority(value) {
  const schema = releaseVerificationAuthoritySchema(value);
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority(value);
  }
  if (schema === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(value);
  }
  throw new TypeError("seven-CVM release verification authority is invalid");
}

export function canonicalPhalaSevenCvmReleaseVerificationAuthorityText(value) {
  const schema = releaseVerificationAuthoritySchema(value);
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return canonicalCurrentPhalaSevenCvmReleaseVerificationAuthorityText(value);
  }
  if (schema === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return canonicalLegacyPhalaSevenCvmReleaseVerificationAuthorityText(value);
  }
  throw new TypeError("seven-CVM release verification authority is invalid");
}

export function phalaSevenCvmReleaseVerificationAuthoritySha256(value) {
  const schema = releaseVerificationAuthoritySchema(value);
  if (schema === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return currentPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  if (schema === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  throw new TypeError("seven-CVM release verification authority is invalid");
}

export const PHALA_WORKLOAD_DOMAIN_QVL_LINK = Object.freeze({
  main_runtime_cvm: Object.freeze({
    profile: "diligence",
    qvl_domain: "diligence_qvl_cvm",
    expected_contract_key: "diligence_room",
  }),
  independent_metering_cvm: Object.freeze({
    profile: "compute_metering",
    qvl_domain: "compute_metering_qvl_cvm",
    expected_contract_key: "compute_credit_vault",
  }),
});
export const PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS = deepFreezeCanonicalPlainDataGraph({
  main_runtime_cvm: {
    challenge: "--main-runtime-qvl-challenge",
    verdict: "--main-runtime-independent-tdx-verdict",
  },
  diligence_qvl_cvm: {
    request: "--diligence-qvl-identity-request",
    response: "--diligence-qvl-identity-response",
  },
  arena_qvl_cvm: {
    request: "--arena-qvl-identity-request",
    response: "--arena-qvl-identity-response",
  },
  anchor_writer_qvl_cvm: {
    request: "--anchor-writer-qvl-identity-request",
    response: "--anchor-writer-qvl-identity-response",
  },
  compute_workload_qvl_cvm: {
    request: "--compute-workload-qvl-identity-request",
    response: "--compute-workload-qvl-identity-response",
  },
  compute_metering_qvl_cvm: {
    request: "--compute-metering-qvl-identity-request",
    response: "--compute-metering-qvl-identity-response",
  },
  independent_metering_cvm: {
    challenge: "--independent-metering-qvl-challenge",
    verdict: "--independent-metering-independent-tdx-verdict",
  },
});

const DCAP_SCRIPT = fileURLToPath(new URL(
  "./phala-seven-cvm-dcap-verify.py",
  import.meta.url,
));
const ROOT = path.resolve(path.dirname(DCAP_SCRIPT), "..");
const ROOT_OWNED_PYTHON_EXECUTABLE = "/usr/bin/python3";
const ROOT_OWNED_CODESIGN_EXECUTABLE = "/usr/bin/codesign";
const DCAP_NATIVE_EXTENSION = path.join(
  "/Library",
  "Application Support",
  "dnai-wikigen",
  "dcap-qvl",
  "0.5.2",
  "_dcap_qvl.abi3.so",
);
const SYSTEM_PYTHON_REPORTED_EXECUTABLE =
  "/Library/Developer/CommandLineTools/usr/bin/python3";
const SYSTEM_PYTHON_REPORTED_EXECUTABLE_LINK =
  "../../Library/Frameworks/Python3.framework/Versions/3.9/bin/python3";
const SYSTEM_PYTHON_RUNTIME_ROOT =
  "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9";
const SYSTEM_PYTHON_RESOLVED_EXECUTABLE = path.join(
  SYSTEM_PYTHON_RUNTIME_ROOT,
  "bin",
  "python3.9",
);
const SYSTEM_VERSION_PLIST = "/System/Library/CoreServices/SystemVersion.plist";
export const PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER = deepFreezeCanonicalPlainDataGraph({
  verifier: "dcap-qvl",
  verifier_version: "0.5.2",
  pccs_url: "https://pccs.phala.network",
  collateral_mode: "authenticated_online_pccs",
  invocation:
    "root_owned_system_python_I_S_B_root_protected_abi3_fd3_to_read_only_unlinked_snapshot_source_fd4",
  platform: "darwin",
  architecture: "arm64",
  system_python_launcher: ROOT_OWNED_PYTHON_EXECUTABLE,
  system_python_launcher_sha256:
    "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818",
  system_python_reported_executable: SYSTEM_PYTHON_REPORTED_EXECUTABLE,
  system_python_reported_executable_link:
    SYSTEM_PYTHON_REPORTED_EXECUTABLE_LINK,
  system_python_resolved_executable: SYSTEM_PYTHON_RESOLVED_EXECUTABLE,
  system_python_resolved_executable_sha256:
    "1e78c38b861b64659075942e1d9bdfa083dbb1eb23bd96bd5d166756c1795524",
  system_python_version: "3.9.6",
  system_python_runtime_root: SYSTEM_PYTHON_RUNTIME_ROOT,
  system_python_runtime_tree_sha256:
    "sha256:c5aedcee4a43ab33ede0734a667243048d3097fffd7435de8ae4f6530a217277",
  python_flags:
    "isolated_ignore_environment_no_site_no_user_site_no_bytecode_exact_system_path",
  user_writable_import_path: false,
  darwin_release: "25.5.0",
  macos_version: "26.5.2",
  macos_build: "25F84",
  system_version_plist: SYSTEM_VERSION_PLIST,
  system_version_plist_sha256:
    "cbf534776ca9200252e5637787e5d4fc26cf527fb354c19bcbac9688341c7a58",
  codesign_executable: ROOT_OWNED_CODESIGN_EXECUTABLE,
  codesign_executable_sha256:
    "214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7",
  dcap_qvl_abi3_path: DCAP_NATIVE_EXTENSION,
  dcap_qvl_abi3_owner_uid: 0,
  dcap_qvl_abi3_mode: "0555",
  dcap_qvl_abi3_signature: "adhoc_linker_signed",
  dcap_qvl_abi3_cdhash_full_sha256:
    "758692e2a484440e6fd2a7bb4b3b74112647e9acd8c1a6f9750a0350a895d29f",
  bootstrap_sha256:
    "b6e79f5ca1b214036d7e11e26aac0a249a26faa1ed702ef908ad27d0cdebb968",
  isolated_runtime_environment_sha256:
    "sha256:0acd40fb80dd000f367583017643ac07fe31becd2372bc20ceca3e91aa8b8beb",
  verifier_script_sha256:
    "77f83590ec8812574cf74c96a84e3b28466c54337bdde336b94621e2baef5261",
  dcap_qvl_abi3_sha256:
    "6f86d8b8ed99c74663418d15150906cea4025352c49889e841ac68b387e04e7f",
});

const PRODUCTION_OPENED_FD_DCAP_RUNTIME = createPinnedSevenCvmOpenedFdRuntime({
  authority: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
  host: { platform: process.platform, architecture: process.arch },
  nativeAuthorityMode: OPENED_FD_RUNTIME_AUTHORITY_MODES.rootOwnedProduction,
  nativePath: DCAP_NATIVE_EXTENSION,
  sourcePath: DCAP_SCRIPT,
});

const CHAIN_ID = 84_532;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const REPORT_DATA_64 = /^0x[0-9a-f]{128}$/;
const INDEPENDENT_VERDICT_DOMAIN =
  "dnai-wikigen/independent-tdx-verdict/v4\0";
const QVL_CHALLENGE_DOMAIN = "dnai-wikigen/attestation-qvl/challenge/v2\0";
const QVL_CHALLENGE_ARTIFACT_DOMAIN =
  "dnai-wikigen/attestation-qvl/challenge-artifact/v2\0";
const INDEPENDENT_VERDICT_ARTIFACT_DOMAIN =
  "dnai-wikigen/independent-tdx-verdict-artifact/v4\0";
const QVL_REQUEST_ARTIFACT_DOMAIN =
  "dnai-wikigen/qvl-identity-attestation-request/v3\0";
const QVL_RESPONSE_ARTIFACT_DOMAIN =
  "dnai-wikigen/qvl-identity-attestation-response/v3\0";
const LOCAL_DCAP_RECEIPT_DOMAIN =
  "dnai-wikigen/local-dcap-qvl-verification-receipt/v2\0";
const QVL_IDENTITY_REPORT_DATA_DOMAIN =
  "dnai-wikigen/qvl-identity-report-data/v3\0";
const QVL_IDENTITY_CHALLENGE_DOMAIN =
  "dnai-wikigen/qvl-identity-challenge/v3\0";
const PCCS_AUTHORITY_DOMAIN = "dnai-wikigen/pccs-collateral-authority/v1\0";
const PCCS_VERIFICATION_RECEIPT_DOMAIN =
  "dnai-wikigen/pccs-collateral-verification-receipt/v1\0";
const TDX_MEASUREMENTS_DOMAIN = "dnai-wikigen/tdx-measurements/v1\0";
const PHALA_RAW_VERIFIER_TRANSCRIPT_DOMAIN =
  "dnai-wikigen/phala-raw-verifier-transcript/v1\0";
const PHALA_SEVEN_CVM_RAW_TRANSCRIPT_SET_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-raw-transcript-set/v1\0";
const PYTHON_RUNTIME_TREE_DOMAIN = "dnai-wikigen/python-runtime-tree/v1\0";
const DILIGENCE_REPORT_DATA_DOMAINLESS_CONTEXT = "diligence-room-submit-result";
const COMPUTE_REPORT_DATA_DOMAIN =
  "dnai-wikigen/compute-metering-signer-attestation/v1\0";
const COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-attestation/v1\0";
const COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-release/v2\0";
const COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-activation-artifact/v4\0";
const COMPUTE_SIGNER_CUSTODY = "dstack_derived_independent_cvm";
const MAX_ARTIFACT_BYTES = 128 * 1024;
const MAX_HISTORICAL_COLLATERAL_BYTES = 512 * 1024;

const VERIFIED_QVL_IDENTITIES = new WeakMap();
const VERIFIED_WORKLOAD_VERDICTS = new WeakMap();
const VERIFIED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS = new WeakMap();
const VERIFIED_SEVEN_CVM_SETS = new WeakMap();
const HISTORICALLY_REPLAYED_QVL_IDENTITIES = new WeakMap();
const HISTORICALLY_REPLAYED_WORKLOAD_VERDICTS = new WeakMap();
const HISTORICALLY_REPLAYED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS = new WeakMap();
const HISTORICALLY_REPLAYED_SEVEN_CVM_SETS = new WeakMap();
const LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF = new WeakMap();
const LIVE_POSTURE_CONTEXT_BY_RELEASE_AUTHORITY = new WeakMap();
const BRANDED_RELEASE_AUTHORITIES = new WeakMap();

/**
 * Atomically consume the exact seven in-memory capabilities which retain the
 * private exact-14 verifier envelopes. This stateful helper intentionally
 * lives in the production verifier rather than the pure historical transcript
 * module imported by R and O reconstruction.
 */
export function consumePhalaSevenCvmHistoricalTranscriptCapabilities(
  capabilityStore,
  proofObjects,
) {
  if (!(capabilityStore instanceof WeakMap)
    || !Array.isArray(proofObjects)
    || proofObjects.length !== 7
    || new Set(proofObjects).size !== 7
    || proofObjects.some((proof) =>
      (typeof proof !== "object" && typeof proof !== "function") || proof === null)) {
    throw new TypeError(
      "historical transcript export requires exactly seven distinct proof capabilities",
    );
  }
  if (proofObjects.some((proof) => !capabilityStore.has(proof))) {
    throw new TypeError(
      "historical transcript export capability is unavailable or already consumed",
    );
  }
  for (const proof of proofObjects) capabilityStore.delete(proof);
}

function brandReleaseVerificationAuthority(candidate, {
  bootstrapAuthority,
  signedAReceipt,
} = {}) {
  const normalized =
    normalizeCurrentPhalaSevenCvmReleaseVerificationAuthority(candidate);
  const bootstrap = deepFreezeCanonicalPlainDataGraph(
    normalizeBootstrapPublicEnvironmentAuthority(bootstrapAuthority),
    { label: "release-authority bootstrap dependency" },
  );
  const signedA =
    assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
      signedAReceipt,
    );
  if (normalized.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("only reconstructed production authority can receive a production brand");
  }
  BRANDED_RELEASE_AUTHORITIES.set(
    normalized,
    Object.freeze({
      digest:
        currentPhalaSevenCvmReleaseVerificationAuthoritySha256(normalized),
      bootstrap_authority: bootstrap,
      signed_a_receipt: signedA,
    }),
  );
  return normalized;
}

export function assertBrandedPhalaSevenCvmReleaseVerificationAuthority(value) {
  const provenance = BRANDED_RELEASE_AUTHORITIES.get(value);
  if (!provenance
    || value.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE
    || currentPhalaSevenCvmReleaseVerificationAuthoritySha256(value)
      !== provenance.digest) {
    throw new Error("release verification authority was not reconstructed from signed dependencies");
  }
  return value;
}

export function readPhalaSevenCvmReleaseVerificationAuthorityBootstrapAuthority(
  value,
) {
  const authority = assertBrandedPhalaSevenCvmReleaseVerificationAuthority(value);
  const provenance = BRANDED_RELEASE_AUTHORITIES.get(authority);
  const signedA =
    assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
      provenance.signed_a_receipt,
    );
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(
    provenance.bootstrap_authority,
  );
  if (bootstrapPublicEnvironmentAuthorityDigest(bootstrap)
      !== signedA.bootstrap_public_environment_authority_sha256
    || phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA)
      !== authority.bootstrap_authorization_receipt_sha256
    || bootstrap.release_sha !== authority.release_sha
    || bootstrap.deployment_intent_sha256
      !== authority.deployment_intent_sha256) {
    throw new Error(
      "release verification authority bootstrap provenance drifted",
    );
  }
  return provenance.bootstrap_authority;
}

function assertReleaseVerificationAuthorityForEvidence(value) {
  if (BRANDED_RELEASE_AUTHORITIES.has(value)) {
    return assertBrandedPhalaSevenCvmReleaseVerificationAuthority(value);
  }
  const normalized = normalizePhalaSevenCvmReleaseVerificationAuthority(value);
  if (normalized.evidence_mode !== PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    throw new Error("unbranded production release verification authority is forbidden");
  }
  return normalized;
}

export function assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(value) {
  const authority = assertBrandedPhalaSevenCvmReleaseVerificationAuthority(value);
  if (authority.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("synthetic release verification authority can never authorize production");
  }
  const now = Math.floor(Date.now() / 1_000);
  for (const descriptor of authority.descriptors) {
    const observedAt = Math.floor(Date.parse(descriptor.posture_observed_at) / 1_000);
    if (observedAt > now + PHALA_RELEASE_POSTURE_MAX_FUTURE_SKEW_SECONDS
      || now - observedAt > PHALA_RELEASE_POSTURE_MAX_AGE_SECONDS) {
      throw new Error(`${descriptor.domain} production posture observation is no longer fresh`);
    }
  }
  return authority;
}

function contractAddressFromReceipt(receipt, name) {
  const found = receipt.contracts.find((entry) => entry.name === name);
  if (!found) throw new Error(`fresh contract deployment receipt omits ${name}`);
  return found.address;
}

function contractRuntimeCodeHashFromReceipt(receipt, name) {
  const found = receipt.contracts.find((entry) => entry.name === name);
  if (!found) throw new Error(`fresh contract deployment receipt omits ${name}`);
  return found.runtime_code_hash;
}

export function projectMainRuntimeQvlMeasurementPolicyCommitments(
  measurementPolicySet,
) {
  const policies = normalizePhalaQvlMeasurementPolicySet(measurementPolicySet);
  const byDomain = new Map(
    policies.policies.map((policy) => [policy.domain, policy]),
  );
  const arena = byDomain.get("arena_qvl_cvm");
  const computeWorkload = byDomain.get("compute_workload_qvl_cvm");
  if (!arena || !computeWorkload) {
    throw new Error(
      "QVL measurement policy set omits a main-runtime consumer policy",
    );
  }
  return Object.freeze({
    TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256:
      phalaQvlMeasurementPolicySha256(arena),
    TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
      phalaQvlMeasurementPolicySha256(computeWorkload),
  });
}

export function createPhalaSevenCvmReleaseVerificationAuthority({
  signedAReceipt,
  bootstrapAuthority,
  descriptorRuntimeAuthority,
  measurementPolicySet,
  productionPostureReceipts,
  freshContractDeploymentReceipt,
  reviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  const signedA = assertCryptographicallyVerifiedPhalaNonLiveBootstrapAuthorizationReceipt(
    signedAReceipt,
  );
  const bootstrap = normalizeBootstrapPublicEnvironmentAuthority(bootstrapAuthority);
  const bootstrapSha256 = bootstrapPublicEnvironmentAuthorityDigest(bootstrap);
  if (signedA.bootstrap_public_environment_authority_sha256 !== bootstrapSha256
    || signedA.release_sha !== bootstrap.release_sha
    || signedA.deployment_intent_sha256 !== bootstrap.deployment_intent_sha256
    || signedA.fresh_contract_deployment_receipt_sha256
      !== bootstrap.fresh_contract_deployment_receipt_sha256
    || signedA.qvl_measurement_policy_set_sha256
      !== bootstrap.qvl_measurement_policy_set_sha256
    || PHALA_SEVEN_CVM_EXECUTION_ORDER.some((domain, index) =>
      signedA.descriptor_sha256_by_domain[domain]
        !== bootstrap.domains[index].descriptor_sha256)) {
    throw new Error("signed A does not bind the supplied bootstrap public authority");
  }
  const mainBootstrap = bootstrap.domains.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  if (!mainBootstrap) {
    throw new Error("bootstrap public authority omits the main runtime domain");
  }
  const ceremonyNonce = bytes32(
    mainBootstrap.values.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE,
    "bootstrap main-runtime ceremony nonce",
  );
  const descriptorRuntime = assertFreshCvmDescriptorRuntimeAuthority(
    descriptorRuntimeAuthority,
    { expectedReleaseSha: signedA.release_sha },
  );
  const policies = normalizePhalaQvlMeasurementPolicySet(measurementPolicySet);
  const policySetSha = phalaQvlMeasurementPolicySetSha256(policies);
  if (policies.deployment_intent_sha256 !== signedA.deployment_intent_sha256
    || policySetSha !== signedA.qvl_measurement_policy_set_sha256) {
    throw new Error("signed A does not authorize the exact QVL measurement policy set");
  }
  const mainRuntimeQvlPolicyCommitments =
    projectMainRuntimeQvlMeasurementPolicyCommitments(policies);
  if (mainBootstrap.values.TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256
      !== mainRuntimeQvlPolicyCommitments
        .TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256
    || mainBootstrap.values.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
      !== mainRuntimeQvlPolicyCommitments
        .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256
  ) {
    throw new Error(
      "bootstrap main-runtime QVL policy commitments drifted from the authorized policy set",
    );
  }
  const reviewerAcceptance = sha256(
    reviewerAuthorityGenesisAcceptanceSha256,
    "release reviewer genesis acceptance",
  );
  const contractReceiptPins = {
    expectedDeploymentIntentSha256: signedA.deployment_intent_sha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256: reviewerAcceptance,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      descriptorRuntime
        .tinker_account_binding_ceremony_receipt_sha256,
  };
  const contractReceipt = normalizeFreshContractDeploymentReceipt(
    freshContractDeploymentReceipt,
    contractReceiptPins,
  );
  const contractReceiptSha = `sha256:${freshContractDeploymentReceiptDigest(
    contractReceipt,
    contractReceiptPins,
  )}`;
  if (contractReceiptSha !== signedA.fresh_contract_deployment_receipt_sha256
    || !Array.isArray(productionPostureReceipts)
    || productionPostureReceipts.length !== PHALA_SEVEN_CVM_EXECUTION_ORDER.length) {
    throw new Error("release authority contract receipt or seven posture receipts are invalid");
  }
  if (mainBootstrap.values.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
      !== signedA.deployment_intent_sha256
    || mainBootstrap.values.TINKER_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256
      !== contractReceiptSha
    || mainBootstrap.values.TINKER_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
      !== policySetSha
    || mainBootstrap.values.TINKER_COMPUTE_VAULT_ADDRESS
      !== contractAddressFromReceipt(contractReceipt, "ComputeCreditVault")
    || mainBootstrap.values.TINKER_COMPUTE_VAULT_RUNTIME_CODE_HASH
      !== contractRuntimeCodeHashFromReceipt(contractReceipt, "ComputeCreditVault")) {
    throw new Error("bootstrap main-runtime values drifted from release dependencies");
  }
  const postureMap = new Map(productionPostureReceipts.map((value) => {
    const receipt = assertVerifiedProductionCvmPostureReceipt(value);
    return [receipt.domain, receipt];
  }));
  if (postureMap.size !== PHALA_SEVEN_CVM_EXECUTION_ORDER.length
    || PHALA_SEVEN_CVM_EXECUTION_ORDER.some((domain) => !postureMap.has(domain))) {
    throw new Error("release authority posture receipts are omitted or duplicated");
  }
  if (PHALA_SEVEN_CVM_EXECUTION_ORDER.some((domain) =>
    descriptorRuntime.descriptor_sha256_by_domain[domain]
      !== signedA.descriptor_sha256_by_domain[domain]
    || descriptorRuntime.app_compose_hash_by_domain[domain]
      !== postureMap.get(domain).compose_hash)) {
    throw new Error("stable descriptor bytes drifted from signed A or observed CVM compose hashes");
  }
  const authority = assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
    brandReleaseVerificationAuthority({
    schema: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
    status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_STATUS,
    truth_status: PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_TRUTH,
    evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    chain_id: CHAIN_ID,
    release_sha: signedA.release_sha,
    deployment_intent_sha256: signedA.deployment_intent_sha256,
    activation_evidence_lease_seconds:
      policies.activation_evidence_lease_seconds,
    bootstrap_authorization_receipt_sha256:
      phalaNonLiveBootstrapAuthorizationReceiptSha256(signedA),
    cvm_descriptor_runtime_authority_sha256:
      cvmDescriptorRuntimeAuthoritySha256(descriptorRuntime),
    cvm_descriptor_runtime_authority: descriptorRuntime,
    tinker_account_binding_ceremony_receipt_sha256:
      descriptorRuntime
        .tinker_account_binding_ceremony_receipt_sha256,
    ceremony_nonce: ceremonyNonce,
    qvl_measurement_policy_set_sha256: policySetSha,
    qvl_measurement_policies: policies.policies,
    contracts: {
      fresh_contract_deployment_receipt_sha256: contractReceiptSha,
      diligence_room: contractAddressFromReceipt(contractReceipt, "DiligenceRoom"),
      compute_credit_vault: contractAddressFromReceipt(contractReceipt, "ComputeCreditVault"),
      compute_credit_vault_runtime_code_hash:
        contractRuntimeCodeHashFromReceipt(contractReceipt, "ComputeCreditVault"),
    },
    descriptors: PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) => {
      const posture = postureMap.get(domain);
      return {
        domain,
        descriptor_sha256: signedA.descriptor_sha256_by_domain[domain],
        app_id: posture.app_id,
        cvm_id: posture.cvm_id,
        compose_hash: posture.compose_hash,
        os_image_hash: posture.os_image_hash,
        posture_receipt_sha256: productionCvmPostureVerificationReceiptSha256(posture),
        posture_observed_at: posture.observed_at,
        kms_id: posture.kms_id,
        instance_type: posture.instance_type,
        disk_size: posture.disk_size,
      };
    }),
    }, {
      bootstrapAuthority: bootstrap,
      signedAReceipt: signedA,
    }),
  );
  LIVE_POSTURE_CONTEXT_BY_RELEASE_AUTHORITY.set(authority, new Map(
    PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) => {
      const posture = postureMap.get(domain);
      return [domain, Object.freeze({
        expectedAuthority: Object.freeze({
          domain,
          app_id: posture.app_id,
          cvm_id: posture.cvm_id,
          compose_hash: posture.compose_hash,
          kms_id: posture.kms_id,
          instance_type: posture.instance_type,
          disk_size: posture.disk_size,
        }),
        receipt: posture,
      })];
    }),
  ));
  return authority;
}

export class PhalaWorkloadVerdictChallengeLedger {
  #consumed = new Set();

  constructor(maximum = 8) {
    if (!Number.isSafeInteger(maximum) || maximum < 2 || maximum > 65_536) {
      throw new Error("workload challenge ledger capacity is invalid");
    }
    this.maximum = maximum;
  }

  consume({ releaseAuthoritySha256, deploymentIntentSha256, ceremonyNonce, domain, challengeId }) {
    const scope = compactCanonicalText({
      chain_id: CHAIN_ID,
      release_authority_sha256: sha256(releaseAuthoritySha256, "challenge release authority"),
      deployment_intent_sha256: sha256(deploymentIntentSha256, "challenge deployment intent"),
      ceremony_nonce: bytes32(ceremonyNonce, "challenge ceremony nonce"),
      domain,
      challenge_id: bytes32(challengeId, "workload QVL challenge ID"),
    });
    if (this.#consumed.has(scope)) {
      throw new Error("workload QVL challenge was already consumed");
    }
    if (this.#consumed.size >= this.maximum) {
      throw new Error("workload QVL challenge ledger capacity exceeded");
    }
    this.#consumed.add(scope);
  }
}

const DURABLE_LEDGER_OPENAT_HELPER = String.raw`import json
import os
import stat
import sys

try:
    raw = sys.stdin.buffer.read(131073)
    if len(raw) < 2 or len(raw) > 131072:
        raise ValueError
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"body", "dev", "ino", "name", "uid"}:
        raise ValueError
    name = value["name"]
    body = value["body"]
    if (
        not isinstance(name, str)
        or len(name) != 69
        or not name.endswith(".json")
        or any(character not in "0123456789abcdef" for character in name[:-5])
        or not isinstance(body, str)
        or not body.endswith("\n")
        or len(body.encode("utf-8")) > 65536
    ):
        raise ValueError
    directory = os.fstat(3)
    if (
        not stat.S_ISDIR(directory.st_mode)
        or directory.st_dev != int(value["dev"])
        or directory.st_ino != int(value["ino"])
        or directory.st_uid != int(value["uid"])
        or stat.S_IMODE(directory.st_mode) & 0o077
    ):
        raise ValueError
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(name, flags, 0o600, dir_fd=3)
    except FileExistsError:
        raise SystemExit(17)
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != directory.st_uid
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            raise ValueError
        encoded = body.encode("utf-8")
        offset = 0
        while offset < len(encoded):
            written = os.write(fd, encoded[offset:])
            if written < 1:
                raise ValueError
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(3)
    sys.stdout.write('{"ok":true}\n')
except SystemExit:
    raise
except Exception:
    sys.stderr.write("durable challenge ledger openat write failed safely\n")
    raise SystemExit(1)
`;

function assertRootOwnedRestrictedPython() {
  const resolved = path.resolve(ROOT_OWNED_PYTHON_EXECUTABLE);
  if (fs.realpathSync.native(resolved) !== resolved) {
    throw new Error("durable ledger Python helper must be a canonical root-owned executable");
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.uid !== 0 || (stat.mode & 0o022) !== 0
    || (stat.mode & 0o111) === 0
    || (typeof process.geteuid === "function" && process.geteuid() === 0)) {
    throw new Error("durable ledger Python helper lacks a root-owned privilege boundary");
  }
  return resolved;
}

export class PhalaDurableReleaseChallengeLedger {
  #directoryFd;
  #directoryIdentity;
  #consumed = new Set();
  #closed = false;

  constructor(directory, { expectedDevice = null, expectedInode = null, expectedUid = null } = {}) {
    if (typeof directory !== "string" || !path.isAbsolute(directory)) {
      throw new Error("durable challenge ledger requires one absolute directory");
    }
    const identityProvided = [expectedDevice, expectedInode, expectedUid]
      .some((value) => value !== null);
    if (identityProvided && (![expectedDevice, expectedInode, expectedUid]
      .every((value) => typeof value === "string" && /^[0-9]+$/.test(value)))) {
      throw new Error("durable challenge ledger expected directory identity is incomplete");
    }
    const resolved = path.resolve(directory);
    if (fs.realpathSync.native(resolved) !== resolved) {
      throw new Error("durable challenge ledger directory must be symlink-free");
    }
    const before = fs.lstatSync(resolved, { bigint: true });
    const operatorUid = typeof process.getuid === "function"
      ? BigInt(process.getuid())
      : before.uid;
    if (!before.isDirectory() || before.isSymbolicLink() || (Number(before.mode) & 0o077) !== 0
      || before.uid !== operatorUid) {
      throw new Error("durable challenge ledger directory must be private and caller-owned");
    }
    const fd = fs.openSync(
      resolved,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0)
        | (fs.constants.O_NOFOLLOW || 0),
    );
    const opened = fs.fstatSync(fd, { bigint: true });
    if (!opened.isDirectory() || opened.dev !== before.dev || opened.ino !== before.ino
      || opened.uid !== before.uid || opened.mode !== before.mode
      || (identityProvided && (String(opened.dev) !== expectedDevice
        || String(opened.ino) !== expectedInode
        || String(opened.uid) !== expectedUid))) {
      fs.closeSync(fd);
      throw new Error(
        "durable challenge ledger directory changed or differs from retained authority while opening",
      );
    }
    try {
      assertRootOwnedRestrictedPython();
    } catch (error) {
      fs.closeSync(fd);
      throw error;
    }
    this.directory = resolved;
    this.#directoryFd = fd;
    this.#directoryIdentity = Object.freeze({
      dev: opened.dev.toString(10),
      ino: opened.ino.toString(10),
      uid: opened.uid.toString(10),
    });
    Object.freeze(this);
  }

  close() {
    if (this.#closed) return;
    fs.closeSync(this.#directoryFd);
    this.#directoryFd = -1;
    this.#closed = true;
  }

  consume({ releaseAuthoritySha256, deploymentIntentSha256, ceremonyNonce, domain, challengeId }) {
    if (this.#closed) {
      throw new Error("durable challenge ledger is closed");
    }
    if (!PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(domain)) {
      throw new Error("durable challenge ledger domain is invalid");
    }
    const record = {
      schema: "dnai.phala-release-challenge-consumption.v1",
      chain_id: CHAIN_ID,
      release_authority_sha256: sha256(releaseAuthoritySha256, "challenge release authority"),
      deployment_intent_sha256: sha256(deploymentIntentSha256, "challenge deployment intent"),
      ceremony_nonce: bytes32(ceremonyNonce, "challenge ceremony nonce"),
      domain,
      challenge_id: bytes32(challengeId, "challenge ID"),
      consumed: true,
    };
    const name = createHash("sha256")
      .update("dnai-wikigen/phala-release-challenge-consumption/v1\0", "utf8")
      .update(compactCanonicalText(record), "ascii")
      .digest("hex");
    if (this.#consumed.has(name)) {
      throw new Error("release-scoped challenge was already consumed");
    }
    const directory = fs.fstatSync(this.#directoryFd, { bigint: true });
    if (!directory.isDirectory()
      || directory.dev.toString(10) !== this.#directoryIdentity.dev
      || directory.ino.toString(10) !== this.#directoryIdentity.ino
      || directory.uid.toString(10) !== this.#directoryIdentity.uid
      || (Number(directory.mode) & 0o077) !== 0) {
      throw new Error("durable challenge ledger opened directory authority drifted");
    }
    const result = spawnSync(
      assertRootOwnedRestrictedPython(),
      ["-I", "-S", "-B", "-c", DURABLE_LEDGER_OPENAT_HELPER],
      {
        cwd: "/",
        encoding: "utf8",
        input: JSON.stringify({
          ...this.#directoryIdentity,
          name: `${name}.json`,
          body: canonicalText(record),
        }),
        stdio: ["pipe", "pipe", "pipe", this.#directoryFd],
        timeout: 10_000,
        maxBuffer: 4 * 1024,
        env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      },
    );
    if (result.status === 17) {
      this.#consumed.add(name);
      throw new Error("release-scoped challenge was already consumed");
    }
    if (result.error || result.status !== 0 || result.stdout !== '{"ok":true}\n') {
      throw new Error("durable challenge ledger descriptor-relative write failed");
    }
    this.#consumed.add(name);
  }
}

function consumeReleaseScopedChallenge(ledger, authority, domain, challengeId) {
  const releaseAuthority = assertReleaseVerificationAuthorityForEvidence(authority);
  const isProduction = releaseAuthority.evidence_mode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE;
  if (isProduction && !(ledger instanceof PhalaDurableReleaseChallengeLedger)) {
    throw new Error("production verification requires a durable release-scoped challenge ledger");
  }
  if (!isProduction && !(ledger instanceof PhalaWorkloadVerdictChallengeLedger)) {
    throw new Error("synthetic verification requires its in-memory fixture challenge ledger");
  }
  ledger.consume({
    releaseAuthoritySha256: phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    deploymentIntentSha256: releaseAuthority.deployment_intent_sha256,
    ceremonyNonce: releaseAuthority.ceremony_nonce,
    domain,
    challengeId,
  });
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const ownKeys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify(ownKeys.sort()) !== JSON.stringify([...keys].sort())
    || Object.values(descriptors).some((descriptor) =>
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true)) {
    throw new Error(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function compactCanonicalText(value) {
  return JSON.stringify(sorted(value));
}

function domainSha256(domain, value, { compact = false } = {}) {
  const text = compact ? compactCanonicalText(value) : canonicalText(value);
  if (Buffer.byteLength(text, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new Error("seven-CVM verifier artifact is too large");
  }
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(text, "utf8")
    .digest("hex")}`;
}

function rawVerifierTranscriptSha256(domain, kind, artifactSha256) {
  if (!PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(domain)
    || ![
      "qvl_identity_request_response",
      "workload_challenge_verdict",
      "compute_workload_recipient_activation",
    ].includes(kind)
    || !Array.isArray(artifactSha256) || artifactSha256.length !== 2) {
    throw new Error("raw verifier transcript commitment shape is invalid");
  }
  return domainSha256(PHALA_RAW_VERIFIER_TRANSCRIPT_DOMAIN, {
    schema: "dnai.phala-raw-verifier-transcript.v1",
    chain_id: CHAIN_ID,
    domain,
    kind,
    artifact_sha256: artifactSha256.map((digest, index) =>
      sha256(digest, `${domain} raw transcript artifact[${index}]`)),
  });
}

function rawArtifactFileSize(value, label, maximum = MAX_ARTIFACT_BYTES) {
  if (!Number.isSafeInteger(value) || value < 2 || value > maximum) {
    throw new Error(`${label} must be a bounded positive byte size`);
  }
  return value;
}

function canonicalRawArtifactFileIdentity(text, normalized, label) {
  const size = typeof text === "string" ? Buffer.byteLength(text, "utf8") : 0;
  if (typeof text !== "string" || size < 2 || size > MAX_ARTIFACT_BYTES
    || text !== canonicalText(normalized)) {
    throw new Error(`${label} must be the exact canonical stable file bytes`);
  }
  return Object.freeze({
    sha256: `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`,
    size,
  });
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function bytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase bytes32`);
  }
  return value;
}

function address(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function bareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    throw new Error(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function appId(value, label) {
  if (typeof value !== "string" || !APP_ID.test(value)) {
    throw new Error(`${label} must be an exact nonzero lowercase Phala app ID`);
  }
  return value;
}

function cvmId(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} must be a canonical CVM ID`);
  }
  return value;
}

function second(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    throw new Error(`${label} must be a bounded Unix second`);
  }
  return value;
}

function shaFromBytes32(value, label) {
  return `sha256:${bytes32(value, label).slice(2)}`;
}

function bytes32FromBare(value, label) {
  return `0x${bareSha256(value, label)}`;
}

function bytes32FromSha(value, label) {
  return `0x${sha256(value, label).slice(7)}`;
}

const SYNTHETIC_HISTORICAL_POSTURE_RECEIPT_SCHEMA =
  "dnai.synthetic-historical-phala-production-cvm-posture-receipt.v2";

function rawHistoricalFileIdentity(text, label) {
  const size = typeof text === "string" ? Buffer.byteLength(text, "utf8") : 0;
  if (typeof text !== "string" || size < 2
    || size > MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES || text.includes("\0")) {
    throw new Error(`${label} is outside the private historical file bound`);
  }
  return Object.freeze({
    sha256: `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`,
    size,
  });
}

function historicalTranscriptRoleAuthority(flag) {
  for (const [domain, roles] of Object.entries(PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS)) {
    for (const [role, candidateFlag] of Object.entries(roles)) {
      if (candidateFlag === flag) return Object.freeze({ domain, role });
    }
  }
  throw new Error(`${flag} is not an exact seven-CVM transcript flag`);
}

function normalizeHistoricalPostureExpectedAuthority(value, expectedDomain) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "disk_size", "domain", "instance_type", "kms_id",
  ], `${expectedDomain} historical posture expected authority`);
  if (parsed.domain !== expectedDomain || !PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(expectedDomain)
    || typeof parsed.instance_type !== "string" || !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(parsed.instance_type)
    || !Number.isSafeInteger(parsed.disk_size) || parsed.disk_size < 20
    || parsed.disk_size > 16_384) {
    throw new Error(`${expectedDomain} historical posture expected authority is invalid`);
  }
  return {
    domain: expectedDomain,
    app_id: appId(parsed.app_id, `${expectedDomain} historical posture app ID`),
    cvm_id: cvmId(parsed.cvm_id, `${expectedDomain} historical posture CVM ID`),
    compose_hash: bareSha256(
      parsed.compose_hash,
      `${expectedDomain} historical posture compose hash`,
    ),
    kms_id: cvmId(parsed.kms_id, `${expectedDomain} historical posture KMS ID`),
    instance_type: parsed.instance_type,
    disk_size: parsed.disk_size,
  };
}

function syntheticHistoricalPostureReceipt(descriptor) {
  return deepFreezeCanonicalPlainDataGraph({
    schema: SYNTHETIC_HISTORICAL_POSTURE_RECEIPT_SCHEMA,
    status: "private_posture_fixture_prepared",
    truth_status: "synthetic_node_test_posture_never_production_authority",
    domain: descriptor.domain,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    kms_id: descriptor.kms_id,
    instance_type: descriptor.instance_type,
    disk_size: descriptor.disk_size,
    listed: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    observed_at: descriptor.posture_observed_at,
    receipt_sha256: descriptor.posture_receipt_sha256,
    raw_secret_egress: false,
  }, { label: `${descriptor.domain} synthetic historical posture receipt` });
}

function normalizeSyntheticHistoricalPostureReceipt(value, descriptor) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "disk_size", "domain", "instance_type", "kms_id",
    "listed", "observed_at", "os_image_hash", "public_logs", "public_sysinfo",
    "public_tcbinfo", "raw_secret_egress", "receipt_sha256", "schema", "status",
    "truth_status",
  ], `${descriptor.domain} synthetic historical posture receipt`);
  const expected = syntheticHistoricalPostureReceipt(descriptor);
  if (canonicalText(parsed) !== canonicalText(expected)) {
    throw new Error(`${descriptor.domain} synthetic historical posture receipt drifted`);
  }
  return { receipt: expected, receiptSha256: descriptor.posture_receipt_sha256 };
}

function historicalPostureAuditForReleaseAuthority(releaseAuthority, domain) {
  const descriptor = releaseAuthority.descriptors.find((entry) => entry.domain === domain);
  if (!descriptor) throw new Error(`${domain} is absent from release posture authority`);
  const expectedAuthority = Object.freeze({
    domain,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    kms_id: descriptor.kms_id,
    instance_type: descriptor.instance_type,
    disk_size: descriptor.disk_size,
  });
  if (releaseAuthority.evidence_mode === PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    return Object.freeze({
      expected_authority: expectedAuthority,
      receipt: syntheticHistoricalPostureReceipt(descriptor),
      receipt_sha256: descriptor.posture_receipt_sha256,
    });
  }
  const context = LIVE_POSTURE_CONTEXT_BY_RELEASE_AUTHORITY.get(releaseAuthority)?.get(domain);
  if (!context || canonicalText(context.expectedAuthority) !== canonicalText(expectedAuthority)
    || productionCvmPostureVerificationReceiptSha256(context.receipt, {
      expectedAuthority,
    }) !== descriptor.posture_receipt_sha256) {
    throw new Error(`${domain} live production posture context is unavailable or drifted`);
  }
  return Object.freeze({
    expected_authority: expectedAuthority,
    receipt: context.receipt,
    receipt_sha256: descriptor.posture_receipt_sha256,
  });
}

function normalizeHistoricalPostureAudit({
  evidenceMode,
  domain,
  expectedAuthority,
  receipt,
  receiptSha256,
  releaseDescriptor,
}) {
  const expected = normalizeHistoricalPostureExpectedAuthority(expectedAuthority, domain);
  for (const field of [
    "app_id", "cvm_id", "compose_hash", "kms_id", "instance_type", "disk_size",
  ]) {
    if (expected[field] !== releaseDescriptor[field]) {
      throw new Error(`${domain} persisted posture tuple differs from release authority`);
    }
  }
  if (receiptSha256 !== releaseDescriptor.posture_receipt_sha256) {
    throw new Error(`${domain} persisted posture digest differs from release authority`);
  }
  if (evidenceMode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    const normalized = normalizeProductionCvmPostureVerificationReceipt(receipt, {
      expectedAuthority: expected,
    });
    const digest = productionCvmPostureVerificationReceiptSha256(normalized, {
      expectedAuthority: expected,
    });
    if (digest !== receiptSha256 || normalized.os_image_hash !== releaseDescriptor.os_image_hash
      || normalized.observed_at !== releaseDescriptor.posture_observed_at) {
      throw new Error(`${domain} persisted production posture receipt bytes drifted`);
    }
    return { expectedAuthority: expected, receipt: normalized, receiptSha256: digest };
  }
  if (evidenceMode !== PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    throw new Error(`${domain} historical posture evidence mode is invalid`);
  }
  const synthetic = normalizeSyntheticHistoricalPostureReceipt(receipt, releaseDescriptor);
  return { expectedAuthority: expected, ...synthetic };
}

function normalizeHistoricalDcapReplayRecord(value, {
  expectedVerifiedAt,
  expectedLeaseExpiresAt,
  expectedLocalReceiptSha256,
  expectedDomain,
  releaseAuthority,
} = {}) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "activation_evidence_lease_issued_at",
    "collateral_json", "collateral_sha256", "local_dcap_verification_receipt_sha256",
    "posture_expected_authority", "production_posture_receipt",
    "production_posture_receipt_sha256", "runtime_environment_sha256", "schema",
    "verification_time",
  ], "historical local DCAP replay record");
  const collateralBytes = typeof parsed.collateral_json === "string"
    ? Buffer.from(parsed.collateral_json, "utf8") : Buffer.alloc(0);
  if (parsed.schema !== PHALA_VERIFIER_HISTORICAL_DCAP_REPLAY_RECORD_SCHEMA
    || collateralBytes.length < 2 || collateralBytes.length > MAX_HISTORICAL_COLLATERAL_BYTES
    || [...parsed.collateral_json].some((character) => {
      const code = character.codePointAt(0);
      return code < 0x20 || code > 0x7e;
    })) {
    throw new Error("historical local DCAP replay collateral is invalid or unbounded");
  }
  const verificationTime = second(parsed.verification_time, "historical DCAP verification time");
  const leaseIssuedAt = second(
    parsed.activation_evidence_lease_issued_at,
    "historical activation lease issued_at",
  );
  const leaseExpiresAt = second(
    parsed.activation_evidence_lease_expires_at,
    "historical activation lease expires_at",
  );
  const collateralSha = `sha256:${createHash("sha256")
    .update(parsed.collateral_json, "utf8").digest("hex")}`;
  const localReceiptSha = sha256(
    parsed.local_dcap_verification_receipt_sha256,
    "historical local DCAP receipt digest",
  );
  if (parsed.collateral_sha256 !== collateralSha || leaseIssuedAt !== verificationTime
    || leaseExpiresAt - leaseIssuedAt !== PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || parsed.runtime_environment_sha256
      !== PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256
    || (expectedVerifiedAt !== undefined && verificationTime !== expectedVerifiedAt)
    || (expectedLeaseExpiresAt !== undefined && leaseExpiresAt !== expectedLeaseExpiresAt)
    || (expectedLocalReceiptSha256 !== undefined
      && localReceiptSha !== expectedLocalReceiptSha256)) {
    throw new Error("historical local DCAP replay record drifted from recorded authority");
  }
  const output = {
    schema: PHALA_VERIFIER_HISTORICAL_DCAP_REPLAY_RECORD_SCHEMA,
    verification_time: verificationTime,
    activation_evidence_lease_issued_at: leaseIssuedAt,
    activation_evidence_lease_expires_at: leaseExpiresAt,
    runtime_environment_sha256:
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    collateral_sha256: collateralSha,
    collateral_json: parsed.collateral_json,
    local_dcap_verification_receipt_sha256: localReceiptSha,
    posture_expected_authority: normalizeHistoricalPostureExpectedAuthority(
      parsed.posture_expected_authority,
      expectedDomain,
    ),
    production_posture_receipt: parsed.production_posture_receipt,
    production_posture_receipt_sha256: sha256(
      parsed.production_posture_receipt_sha256,
      `${expectedDomain} production posture receipt digest`,
    ),
  };
  if (releaseAuthority !== undefined) {
    const descriptor = releaseAuthority.descriptors.find((entry) => entry.domain === expectedDomain);
    normalizeHistoricalPostureAudit({
      evidenceMode: releaseAuthority.evidence_mode,
      domain: expectedDomain,
      expectedAuthority: output.posture_expected_authority,
      receipt: output.production_posture_receipt,
      receiptSha256: output.production_posture_receipt_sha256,
      releaseDescriptor: descriptor,
    });
    if (leaseExpiresAt - leaseIssuedAt !== releaseAuthority.activation_evidence_lease_seconds) {
      throw new Error("historical activation lease differs from signed release policy");
    }
  }
  return output;
}

function normalizeHistoricalSignatureReplayRecord(value, {
  expectedVerifiedAt,
  expectedActivationLeaseExpiresAt,
  expectedDomain,
  releaseAuthority,
} = {}) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "posture_expected_authority",
    "production_posture_receipt", "production_posture_receipt_sha256",
    "report_data_binding", "schema", "verification_time",
    "verdict_activation_evidence_lease_expires_at",
  ], "historical signature replay record");
  const verificationTime = second(
    parsed.verification_time,
    "historical signature verification time",
  );
  const verdictLeaseExpiresAt = second(
    parsed.verdict_activation_evidence_lease_expires_at,
    "historical verdict activation lease expires_at",
  );
  const activationLeaseExpiresAt = second(
    parsed.activation_evidence_lease_expires_at,
    "historical workload activation lease expires_at",
  );
  if (parsed.schema !== PHALA_VERIFIER_HISTORICAL_SIGNATURE_REPLAY_RECORD_SCHEMA
    || !PHALA_WORKLOAD_DOMAIN_QVL_LINK[expectedDomain]
    || activationLeaseExpiresAt > verdictLeaseExpiresAt
    || verificationTime >= activationLeaseExpiresAt
    || (expectedVerifiedAt !== undefined && verificationTime !== expectedVerifiedAt)
    || (expectedActivationLeaseExpiresAt !== undefined
      && activationLeaseExpiresAt !== expectedActivationLeaseExpiresAt)) {
    throw new Error("historical signature replay lease or time is invalid");
  }
  const output = {
    schema: PHALA_VERIFIER_HISTORICAL_SIGNATURE_REPLAY_RECORD_SCHEMA,
    verification_time: verificationTime,
    verdict_activation_evidence_lease_expires_at: verdictLeaseExpiresAt,
    activation_evidence_lease_expires_at: activationLeaseExpiresAt,
    report_data_binding: normalizeReportDataBinding(parsed.report_data_binding, expectedDomain),
    posture_expected_authority: normalizeHistoricalPostureExpectedAuthority(
      parsed.posture_expected_authority,
      expectedDomain,
    ),
    production_posture_receipt: parsed.production_posture_receipt,
    production_posture_receipt_sha256: sha256(
      parsed.production_posture_receipt_sha256,
      `${expectedDomain} production posture receipt digest`,
    ),
  };
  if (releaseAuthority !== undefined) {
    const descriptor = releaseAuthority.descriptors.find((entry) => entry.domain === expectedDomain);
    normalizeHistoricalPostureAudit({
      evidenceMode: releaseAuthority.evidence_mode,
      domain: expectedDomain,
      expectedAuthority: output.posture_expected_authority,
      receipt: output.production_posture_receipt,
      receiptSha256: output.production_posture_receipt_sha256,
      releaseDescriptor: descriptor,
    });
  }
  return output;
}

function normalizeHistoricalTranscriptArtifact(domain, role, value) {
  if (role === "request") return normalizeQvlIdentityRequest(value);
  if (role === "response") return normalizeQvlIdentityResponse(value);
  if (role === "challenge") return normalizeQvlChallenge(value);
  if (role === "verdict") return normalizeIndependentVerdict(value);
  throw new Error(`${domain} historical transcript role is invalid`);
}

function historicalTranscriptArtifactSha256(role, artifact) {
  if (role === "request") return domainSha256(QVL_REQUEST_ARTIFACT_DOMAIN, artifact);
  if (role === "response") return domainSha256(QVL_RESPONSE_ARTIFACT_DOMAIN, artifact);
  if (role === "challenge") return qvlChallengeArtifactSha256(artifact);
  if (role === "verdict") return independentTdxVerdictArtifactSha256(artifact);
  throw new Error("historical transcript artifact role is invalid");
}

function createHistoricalTranscriptEnvelopeText({
  flag,
  rawArtifactText,
  artifact,
  verificationRecord,
}) {
  const authority = historicalTranscriptRoleAuthority(flag);
  const normalizedArtifact = normalizeHistoricalTranscriptArtifact(
    authority.domain,
    authority.role,
    artifact,
  );
  const rawArtifact = canonicalRawArtifactFileIdentity(
    rawArtifactText,
    normalizedArtifact,
    `${authority.domain} ${authority.role} source artifact`,
  );
  let normalizedRecord = null;
  if (authority.role === "response") {
    normalizedRecord = normalizeHistoricalDcapReplayRecord(verificationRecord, {
      expectedDomain: authority.domain,
    });
  } else if (authority.role === "verdict") {
    normalizedRecord = normalizeHistoricalSignatureReplayRecord(verificationRecord, {
      expectedDomain: authority.domain,
    });
  } else if (verificationRecord !== null) {
    throw new Error("historical challenge/request transcript cannot carry verification state");
  }
  const text = canonicalText({
    schema: PHALA_VERIFIER_HISTORICAL_TRANSCRIPT_ARTIFACT_SCHEMA,
    chain_id: CHAIN_ID,
    flag,
    domain: authority.domain,
    role: authority.role,
    artifact_sha256: historicalTranscriptArtifactSha256(authority.role, normalizedArtifact),
    raw_artifact_sha256: rawArtifact.sha256,
    raw_artifact_size: rawArtifact.size,
    raw_artifact_text: rawArtifactText,
    verification_record: normalizedRecord,
  });
  rawHistoricalFileIdentity(text, `${flag} historical transcript envelope`);
  return text;
}

function parseHistoricalTranscriptEnvelopeText(text, expectedFlag) {
  const transcriptIdentity = rawHistoricalFileIdentity(
    text,
    `${expectedFlag} historical transcript envelope`,
  );
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(`${expectedFlag} historical transcript envelope is not JSON`);
  }
  const parsed = exactRecord(value, [
    "artifact_sha256", "chain_id", "domain", "flag", "raw_artifact_sha256",
    "raw_artifact_size", "raw_artifact_text", "role", "schema", "verification_record",
  ], `${expectedFlag} historical transcript envelope`);
  const authority = historicalTranscriptRoleAuthority(expectedFlag);
  if (parsed.schema !== PHALA_VERIFIER_HISTORICAL_TRANSCRIPT_ARTIFACT_SCHEMA
    || parsed.chain_id !== CHAIN_ID || parsed.flag !== expectedFlag
    || parsed.domain !== authority.domain || parsed.role !== authority.role) {
    throw new Error("historical transcript envelopes are reordered, substituted, or cross-domain");
  }
  let rawArtifact;
  try {
    rawArtifact = JSON.parse(parsed.raw_artifact_text);
  } catch {
    throw new Error(`${expectedFlag} raw artifact is not JSON`);
  }
  const artifact = normalizeHistoricalTranscriptArtifact(
    authority.domain,
    authority.role,
    rawArtifact,
  );
  const rawIdentity = canonicalRawArtifactFileIdentity(
    parsed.raw_artifact_text,
    artifact,
    `${expectedFlag} raw artifact`,
  );
  const artifactSha = historicalTranscriptArtifactSha256(authority.role, artifact);
  if (parsed.raw_artifact_sha256 !== rawIdentity.sha256
    || parsed.raw_artifact_size !== rawIdentity.size
    || parsed.artifact_sha256 !== artifactSha) {
    throw new Error(`${expectedFlag} historical transcript bytes or artifact digest drifted`);
  }
  let verificationRecord = null;
  if (authority.role === "response") {
    verificationRecord = normalizeHistoricalDcapReplayRecord(parsed.verification_record, {
      expectedDomain: authority.domain,
    });
  } else if (authority.role === "verdict") {
    verificationRecord = normalizeHistoricalSignatureReplayRecord(parsed.verification_record, {
      expectedDomain: authority.domain,
    });
  } else if (parsed.verification_record !== null) {
    throw new Error("historical request/challenge envelope carries unauthorized verification state");
  }
  const normalizedText = canonicalText({
    schema: PHALA_VERIFIER_HISTORICAL_TRANSCRIPT_ARTIFACT_SCHEMA,
    chain_id: CHAIN_ID,
    flag: expectedFlag,
    domain: authority.domain,
    role: authority.role,
    artifact_sha256: artifactSha,
    raw_artifact_sha256: rawIdentity.sha256,
    raw_artifact_size: rawIdentity.size,
    raw_artifact_text: parsed.raw_artifact_text,
    verification_record: verificationRecord,
  });
  if (text !== normalizedText) {
    throw new Error(`${expectedFlag} historical transcript envelope is not canonical`);
  }
  return Object.freeze({
    ...authority,
    flag: expectedFlag,
    artifact,
    artifact_sha256: artifactSha,
    raw_artifact_sha256: rawIdentity.sha256,
    raw_artifact_size: rawIdentity.size,
    raw_artifact_text: parsed.raw_artifact_text,
    verification_record: verificationRecord,
    transcript_file_sha256: transcriptIdentity.sha256,
    transcript_file_size: transcriptIdentity.size,
    transcript_text: text,
  });
}

function normalizeMeasurements(value) {
  const base = [
    "tee_tcb_svn", "mr_seam", "mr_signer_seam", "seam_attributes",
    "td_attributes", "xfam", "mr_td", "mr_config_id", "mr_owner",
    "mr_owner_config", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3",
  ];
  const v15 = ["tee_tcb_svn2", "mr_service_td"];
  if (!isRecord(value)) throw new Error("TDX measurements must be an exact object");
  const keys = Object.keys(value).sort();
  const expected = (Object.hasOwn(value, "tee_tcb_svn2") ? [...base, ...v15] : base).sort();
  if (JSON.stringify(keys) !== JSON.stringify(expected)) {
    throw new Error("TDX measurement fields are incomplete or unexpected");
  }
  const lengths = {
    tee_tcb_svn: 32,
    seam_attributes: 16,
    td_attributes: 16,
    xfam: 16,
    tee_tcb_svn2: 32,
  };
  const normalized = {};
  for (const field of expected) {
    const length = lengths[field] || 96;
    const pattern = new RegExp(`^[0-9a-f]{${length}}$`);
    if (typeof value[field] !== "string" || !pattern.test(value[field])) {
      throw new Error(`TDX measurement ${field} is malformed`);
    }
    normalized[field] = value[field];
  }
  return Object.fromEntries(base.concat(Object.hasOwn(value, "tee_tcb_svn2") ? v15 : [])
    .map((field) => [field, normalized[field]]));
}

function tdxMeasurementsSha256(measurements) {
  return domainSha256(TDX_MEASUREMENTS_DOMAIN, normalizeMeasurements(measurements), {
    compact: true,
  });
}

function pccsAuthority() {
  const authority = {
    schema: "dnai.pccs-collateral-authority.v1",
    url: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.pccs_url,
    transport: "https_system_trust_store",
    verifier: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.verifier,
    verifier_version: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.verifier_version,
  };
  return {
    authority,
    sha256: domainSha256(PCCS_AUTHORITY_DOMAIN, authority),
  };
}

function normalizeLocalDcapResult(value, {
  verifiedAt,
  evidenceMode,
  quoteSha256,
  measurementPolicy,
} = {}) {
  const parsed = exactRecord(value, [
    "collateral_source", "debug", "measurement_policy_matched",
    "measurement_policy_reference_id", "measurement_policy_sha256", "measurements",
    "measurements_sha256", "quote_type", "report_data", "runtime_environment_sha256",
    "status", "verified",
  ], "local DCAP verification result");
  const policy = normalizePhalaQvlMeasurementPolicy(measurementPolicy);
  const policyDigest = phalaQvlMeasurementPolicySha256(policy);
  const measurements = normalizeMeasurements(parsed.measurements);
  const measurementSha = tdxMeasurementsSha256(measurements);
  const appraisal = appraisePhalaQvlMeasurementsAgainstPolicy(measurements, policy);
  if (parsed.verified !== true || parsed.quote_type !== "TDX" || parsed.status !== "OK"
    || typeof parsed.report_data !== "string" || !REPORT_DATA_64.test(parsed.report_data)
    || parsed.measurements_sha256 !== measurementSha
    || parsed.collateral_source !== PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.pccs_url
    || parsed.debug !== false || parsed.measurement_policy_matched !== true
    || parsed.measurement_policy_sha256 !== policyDigest
    || parsed.measurement_policy_reference_id !== policy.reference_id
    || appraisal.measurement_policy_sha256 !== policyDigest
    || appraisal.measurement_policy_reference_id !== policy.reference_id
    || appraisal.measurement_policy_matched !== true || appraisal.debug_td !== false) {
    throw new Error(
      "local DCAP verification result is not exact policy-appraised non-debug Intel TDX evidence",
    );
  }
  if (![PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE, PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE]
    .includes(evidenceMode)) {
    throw new Error("local DCAP evidence mode is invalid");
  }
  const quoteSha = sha256(quoteSha256, "local DCAP quote digest");
  const runtimeSha = sha256(
    parsed.runtime_environment_sha256,
    "isolated DCAP runtime environment digest",
  );
  if (runtimeSha
      !== PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256) {
    throw new Error("isolated DCAP runtime does not match the frozen distribution closure");
  }
  const collateral = pccsAuthority();
  const collateralVerification = {
    schema: "dnai.pccs-collateral-verification-receipt.v1",
    collateral_authority_sha256: collateral.sha256,
    tdx_quote_sha256: quoteSha,
    runtime_environment_sha256: runtimeSha,
    status: "OK",
    verified_at: second(verifiedAt, "local DCAP verified_at"),
  };
  return {
    schema: "dnai.local-dcap-qvl-verification-receipt.v2",
    verification_method: "intel_tdx_dcap_qvl",
    evidence_mode: evidenceMode,
    verifier_authority: structuredClone(PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER),
    collateral_source: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.pccs_url,
    collateral_authority: collateral.authority,
    collateral_authority_sha256: collateral.sha256,
    collateral_verification: collateralVerification,
    collateral_verification_receipt_sha256:
      domainSha256(PCCS_VERIFICATION_RECEIPT_DOMAIN, collateralVerification),
    runtime_environment_sha256: runtimeSha,
    tdx_quote_sha256: quoteSha,
    verified: true,
    quote_type: "TDX",
    status: "OK",
    report_data: parsed.report_data,
    measurements,
    measurements_sha256: measurementSha,
    measurement_policy_sha256: policyDigest,
    measurement_policy_reference_id: policy.reference_id,
    measurement_policy_matched: true,
    debug: false,
    verified_at: second(verifiedAt, "local DCAP verified_at"),
  };
}

function assertSyntheticDcapAdapter(value) {
  if (typeof value !== "function") {
    throw new Error("synthetic DCAP fixture adapter must be a function");
  }
}

export function assertPinnedSevenCvmLocalDcapVerifierRuntime(...runtimeOverrides) {
  if (runtimeOverrides.length !== 0) {
    throw new TypeError("production opened-FD verifier does not accept runtime overrides");
  }
  return PRODUCTION_OPENED_FD_DCAP_RUNTIME.assertRuntime();
}

export function verifyPinnedSevenCvmIsolatedRuntimeEnvironment(...runtimeOverrides) {
  if (runtimeOverrides.length !== 0) {
    throw new TypeError("production opened-FD verifier does not accept runtime overrides");
  }
  const parsed = exactRecord(
    PRODUCTION_OPENED_FD_DCAP_RUNTIME.probe(),
    [
      "native_snapshot_authenticated", "native_snapshot_link_count",
      "native_snapshot_mode", "runtime_environment_sha256",
    ],
    "opened-FD DCAP runtime probe",
  );
  if (parsed.runtime_environment_sha256
      !== PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256
    || parsed.native_snapshot_authenticated !== true
    || parsed.native_snapshot_link_count !== 0
    || parsed.native_snapshot_mode !== "0500") {
    throw new Error("opened-FD DCAP runtime does not match the frozen authority manifest");
  }
  return parsed.runtime_environment_sha256;
}

function verifyPinnedSevenCvmLocalDcapQuoteAt(
  rawQuote,
  measurementPolicy,
  verificationTime,
  replayRecord,
) {
  if (!Buffer.isBuffer(rawQuote) || rawQuote.length < 1_024 || rawQuote.length > 16 * 1_024) {
    throw new Error("seven-CVM quote is outside the bounded DCAP input size");
  }
  const policy = normalizePhalaQvlMeasurementPolicy(measurementPolicy);
  const verifiedAt = second(verificationTime, "opened-FD DCAP verification time");
  verifyPinnedSevenCvmIsolatedRuntimeEnvironment();
  const input = {
    quote: `0x${rawQuote.toString("hex")}`,
    measurement_policy: policy,
    measurement_policy_sha256: phalaQvlMeasurementPolicySha256(policy),
    verification_time: verifiedAt,
  };
  if (replayRecord !== undefined) {
    const replay = normalizeHistoricalDcapReplayRecord(replayRecord, {
      expectedVerifiedAt: verifiedAt,
      expectedDomain: policy.domain,
    });
    input.collateral_json = replay.collateral_json;
    input.collateral_sha256 = replay.collateral_sha256;
  }
  const parsed = PRODUCTION_OPENED_FD_DCAP_RUNTIME.run(input);
  if (parsed.runtime_environment_sha256
      !== PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256) {
    throw new Error("quote verifier ran in an alternate opened-FD runtime authority");
  }
  return parsed;
}

export function verifyPinnedSevenCvmLocalDcapQuote(rawQuote, measurementPolicy) {
  if (arguments.length !== 2) {
    throw new TypeError("production opened-FD verifier does not accept runtime overrides");
  }
  return verifyPinnedSevenCvmLocalDcapQuoteAt(
    rawQuote,
    measurementPolicy,
    Math.floor(Date.now() / 1_000),
  );
}

function splitLocalDcapVerifierOutput(value, {
  evidenceMode,
  verifiedAt,
  domain,
} = {}) {
  const resultFields = [
    "collateral_source", "debug", "measurement_policy_matched",
    "measurement_policy_reference_id", "measurement_policy_sha256", "measurements",
    "measurements_sha256", "quote_type", "report_data", "runtime_environment_sha256",
    "status", "verified",
  ];
  if (evidenceMode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    const parsed = exactRecord(value, [
      ...resultFields,
      "historical_dcap_replay",
    ], "production local DCAP verifier output");
    const replay = exactRecord(parsed.historical_dcap_replay, [
      "collateral_json", "collateral_sha256", "verification_time",
    ], "opened-FD local DCAP replay output");
    const collateralSize = typeof replay.collateral_json === "string"
      ? Buffer.byteLength(replay.collateral_json, "utf8") : 0;
    if (replay.verification_time !== verifiedAt || collateralSize < 2
      || collateralSize > MAX_HISTORICAL_COLLATERAL_BYTES
      || [...replay.collateral_json].some((character) => {
        const code = character.codePointAt(0);
        return code < 0x20 || code > 0x7e;
      })
      || replay.collateral_sha256 !== `sha256:${createHash("sha256")
        .update(replay.collateral_json, "utf8").digest("hex")}`) {
      throw new Error("opened-FD verifier did not return exact recorded-time collateral");
    }
    return {
      result: Object.fromEntries(resultFields.map((field) => [field, parsed[field]])),
      replay: Object.freeze({
        verification_time: verifiedAt,
        collateral_json: replay.collateral_json,
        collateral_sha256: replay.collateral_sha256,
      }),
    };
  }
  if (evidenceMode !== PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    throw new Error("local DCAP verifier evidence mode is invalid");
  }
  const parsed = exactRecord(value, resultFields, "synthetic local DCAP verifier output");
  const collateralJson = compactCanonicalText({
    schema: "dnai.synthetic-historical-dcap-collateral.v2",
    domain,
    verification_time: verifiedAt,
    never_production_authority: true,
  });
  return {
    result: parsed,
    replay: Object.freeze({
      verification_time: verifiedAt,
      collateral_json: collateralJson,
      collateral_sha256: `sha256:${createHash("sha256")
        .update(collateralJson, "utf8").digest("hex")}`,
    }),
  };
}

function releaseDescriptorFromAssertedAuthority(authority, domain) {
  const descriptor = authority.descriptors.find((entry) => entry.domain === domain);
  if (!descriptor) throw new Error(`${domain} is absent from the signed release authority`);
  return descriptor;
}

function releaseDescriptor(authorityValue, domain) {
  return releaseDescriptorFromAssertedAuthority(
    assertReleaseVerificationAuthorityForEvidence(authorityValue),
    domain,
  );
}

function releaseMeasurementPolicyFromAssertedAuthority(authority, domain) {
  const policy = authority.qvl_measurement_policies.find((entry) => entry.domain === domain);
  if (!policy || !Object.hasOwn(PHALA_QVL_IDENTITY_DOMAIN_PROFILE, domain)) {
    throw new Error(`${domain} is not an authorized QVL measurement-policy role`);
  }
  return policy;
}

function releaseMeasurementPolicy(authorityValue, domain) {
  return releaseMeasurementPolicyFromAssertedAuthority(
    assertReleaseVerificationAuthorityForEvidence(authorityValue),
    domain,
  );
}

function verificationSecond(authorityValue, testOnlyNow, label) {
  const authority = assertReleaseVerificationAuthorityForEvidence(authorityValue);
  if (authority.evidence_mode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(authority);
    if (testOnlyNow !== undefined) {
      throw new Error(`${label} production clock cannot be injected or backdated`);
    }
    return second(Math.floor(Date.now() / 1_000), `${label} current time`);
  }
  if (testOnlyNow === undefined) {
    throw new Error(`${label} synthetic fixture requires an explicit clock`);
  }
  return second(testOnlyNow, `${label} synthetic time`);
}

function activationLeaseSecond(authorityValue, testOnlyNow, label) {
  const authority = assertReleaseVerificationAuthorityForEvidence(authorityValue);
  if (authority.evidence_mode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    assertBrandedPhalaSevenCvmReleaseVerificationAuthority(authority);
    if (testOnlyNow !== undefined) {
      throw new Error(`${label} production clock cannot be injected or backdated`);
    }
    return second(Math.floor(Date.now() / 1_000), `${label} current time`);
  }
  if (testOnlyNow === undefined) {
    throw new Error(`${label} synthetic fixture requires an explicit clock`);
  }
  return second(testOnlyNow, `${label} synthetic time`);
}

function normalizeQvlIdentityRequest(value) {
  const request = exactRecord(value, [
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest", "challenge_id",
    "compose_hash", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "measurement_policy_sha256", "os_image_hash", "profile",
    "release_authority_sha256", "schema",
  ], "QVL identity attestation request");
  const profile = PHALA_QVL_IDENTITY_DOMAIN_PROFILE[request.domain];
  const issuedAt = second(request.issued_at, "QVL identity challenge issued_at");
  const expiresAt = second(request.expires_at, "QVL identity challenge expires_at");
  if (request.schema !== PHALA_QVL_IDENTITY_ATTESTATION_REQUEST_SCHEMA
    || !profile || request.profile !== profile || request.chain_id !== CHAIN_ID
    || expiresAt <= issuedAt || expiresAt - issuedAt > 120) {
    throw new Error("QVL identity attestation request role or lifetime is invalid");
  }
  return {
    schema: request.schema,
    chain_id: CHAIN_ID,
    domain: request.domain,
    profile,
    cvm_id: cvmId(request.cvm_id, "QVL identity request CVM ID"),
    deployment_intent_sha256: sha256(
      request.deployment_intent_sha256,
      "QVL identity request deployment intent",
    ),
    release_authority_sha256: sha256(
      request.release_authority_sha256,
      "QVL identity request release authority",
    ),
    ceremony_nonce: bytes32(request.ceremony_nonce, "QVL identity request ceremony nonce"),
    measurement_policy_sha256: sha256(
      request.measurement_policy_sha256,
      "QVL identity request measurement policy",
    ),
    app_id: appId(request.app_id, "QVL identity request app ID"),
    compose_hash: bareSha256(request.compose_hash, "QVL identity request compose hash"),
    os_image_hash: bareSha256(request.os_image_hash, "QVL identity request OS image hash"),
    challenge_id: bytes32(request.challenge_id, "QVL identity request challenge ID"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    challenge_digest: bytes32(
      request.challenge_digest,
      "QVL identity request challenge digest",
    ),
  };
}

export function phalaQvlIdentityChallengeDigest(value) {
  const request = normalizeQvlIdentityRequest(value);
  const unsigned = Object.fromEntries(
    Object.entries(request).filter(([key]) => key !== "challenge_digest"),
  );
  return `0x${createHash("sha256")
    .update(QVL_IDENTITY_CHALLENGE_DOMAIN, "utf8")
    .update(compactCanonicalText(unsigned), "ascii")
    .digest("hex")}`;
}

export function createPhalaQvlIdentityChallenge({
  domain,
  releaseAuthority: releaseAuthorityValue,
  ttlSeconds = 90,
  testOnlyNow,
  testOnlyChallengeIdBytes,
} = {}) {
  const authority = assertReleaseVerificationAuthorityForEvidence(
    releaseAuthorityValue,
  );
  const descriptor = releaseDescriptor(authority, domain);
  const policy = releaseMeasurementPolicy(authority, domain);
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 120) {
    throw new Error("QVL identity challenge lifetime must be between 1 and 120 seconds");
  }
  const issuedAt = verificationSecond(authority, testOnlyNow, "QVL identity challenge");
  let random = cryptoRandomBytes(32);
  if (authority.evidence_mode === PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    if (!Buffer.isBuffer(testOnlyChallengeIdBytes) || testOnlyChallengeIdBytes.length !== 32) {
      throw new Error("synthetic fixture challenge bytes must be an exact 32-byte buffer");
    }
    random = Buffer.from(testOnlyChallengeIdBytes);
  } else if (testOnlyChallengeIdBytes !== undefined) {
    throw new Error("production challenge randomness cannot be injected");
  }
  if (random.every((byte) => byte === 0)) throw new Error("challenge ID cannot be zero");
  const request = {
    schema: PHALA_QVL_IDENTITY_ATTESTATION_REQUEST_SCHEMA,
    chain_id: CHAIN_ID,
    domain,
    profile: PHALA_QVL_IDENTITY_DOMAIN_PROFILE[domain],
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    release_authority_sha256: phalaSevenCvmReleaseVerificationAuthoritySha256(authority),
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_sha256: phalaQvlMeasurementPolicySha256(policy),
    app_id: descriptor.app_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    challenge_id: `0x${random.toString("hex")}`,
    issued_at: issuedAt,
    expires_at: issuedAt + ttlSeconds,
    challenge_digest: `0x${"01".repeat(32)}`,
  };
  request.challenge_digest = phalaQvlIdentityChallengeDigest(request);
  return deepFreezeCanonicalPlainDataGraph(normalizeQvlIdentityRequest(request), {
    label: `${domain} QVL identity challenge`,
  });
}

export function normalizePhalaQvlIdentityAttestationRequest(value) {
  return normalizeQvlIdentityRequest(value);
}

function qvlIdentityReportData({ request: requestValue, verifierAddress, releasePolicyHash }) {
  const request = normalizeQvlIdentityRequest(requestValue);
  const payload = {
    schema: "dnai.qvl-identity-report-data.v3",
    service: "dnai-attestation-qvl",
    context: "qvl-verifier-identity",
    chain_id: CHAIN_ID,
    domain: request.domain,
    profile: request.profile,
    cvm_id: request.cvm_id,
    deployment_intent_sha256: request.deployment_intent_sha256,
    release_authority_sha256: request.release_authority_sha256,
    ceremony_nonce: request.ceremony_nonce,
    measurement_policy_sha256: request.measurement_policy_sha256,
    app_id: request.app_id,
    compose_hash: request.compose_hash,
    os_image_hash: request.os_image_hash,
    verifier_address: address(verifierAddress, "QVL identity verifier address"),
    release_policy_hash: bytes32(releasePolicyHash, "QVL identity release policy hash"),
  };
  return `0x${createHash("sha256")
    .update(QVL_IDENTITY_REPORT_DATA_DOMAIN, "utf8")
    .update(compactCanonicalText(payload), "ascii")
    .digest("hex")}`;
}

export function phalaQvlIdentityReportData(value) {
  const parsed = exactRecord(value, [
    "releasePolicyHash", "request", "verifierAddress",
  ], "QVL identity report-data input");
  return qvlIdentityReportData(parsed);
}

function normalizeQvlIdentityResponse(value) {
  const response = exactRecord(value, [
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest", "challenge_expires_at",
    "challenge_id", "challenge_issued_at", "compose_hash", "cvm_id",
    "deployment_intent_sha256", "domain", "measurement_policy_sha256", "os_image_hash",
    "profile", "quote", "quote_hash", "quote_report_data", "quote_size", "raw_secret_egress",
    "release_authority_sha256", "release_policy_hash", "report_data", "schema",
    "verifier_address",
  ], "QVL identity attestation response");
  const profile = PHALA_QVL_IDENTITY_DOMAIN_PROFILE[response.domain];
  if (response.schema !== PHALA_QVL_IDENTITY_ATTESTATION_RESPONSE_SCHEMA
    || response.chain_id !== CHAIN_ID || !profile || response.profile !== profile
    || response.raw_secret_egress !== false || typeof response.quote !== "string"
    || !/^0x[0-9a-f]+$/.test(response.quote) || response.quote.length % 2 !== 0
    || !Number.isSafeInteger(response.quote_size)
    || response.quote_size < 1_024 || response.quote_size > 16 * 1_024
    || response.quote.length !== 2 + response.quote_size * 2) {
    throw new Error("QVL identity attestation response schema or quote bounds are invalid");
  }
  return {
    schema: response.schema,
    chain_id: CHAIN_ID,
    domain: response.domain,
    profile,
    cvm_id: cvmId(response.cvm_id, "QVL identity response CVM ID"),
    deployment_intent_sha256: sha256(
      response.deployment_intent_sha256,
      "QVL identity response deployment intent",
    ),
    release_authority_sha256: sha256(
      response.release_authority_sha256,
      "QVL identity response release authority",
    ),
    ceremony_nonce: bytes32(response.ceremony_nonce, "QVL identity response ceremony nonce"),
    measurement_policy_sha256: sha256(
      response.measurement_policy_sha256,
      "QVL identity response measurement policy",
    ),
    verifier_address: address(response.verifier_address, "QVL identity verifier address"),
    release_policy_hash: bytes32(response.release_policy_hash, "QVL release policy hash"),
    report_data: bytes32(response.report_data, "QVL identity report data"),
    quote_report_data: (() => {
      if (typeof response.quote_report_data !== "string"
        || !REPORT_DATA_64.test(response.quote_report_data)) {
        throw new Error("QVL quote report-data must be exact 64-byte lowercase hex");
      }
      return response.quote_report_data;
    })(),
    challenge_id: bytes32(response.challenge_id, "QVL identity response challenge ID"),
    challenge_digest: bytes32(
      response.challenge_digest,
      "QVL identity response challenge digest",
    ),
    challenge_issued_at: second(
      response.challenge_issued_at,
      "QVL identity response challenge issued_at",
    ),
    challenge_expires_at: second(
      response.challenge_expires_at,
      "QVL identity response challenge expires_at",
    ),
    quote: response.quote,
    quote_hash: bytes32(response.quote_hash, "QVL identity response quote hash"),
    quote_size: response.quote_size,
    app_id: appId(response.app_id, "QVL identity response app ID"),
    compose_hash: bareSha256(response.compose_hash, "QVL identity response compose hash"),
    os_image_hash: bareSha256(response.os_image_hash, "QVL identity response OS image hash"),
    raw_secret_egress: false,
  };
}

export function normalizePhalaQvlIdentityAttestationResponse(value) {
  return normalizeQvlIdentityResponse(value);
}

function normalizeQvlIdentityVerification(value) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "activation_evidence_lease_issued_at",
    "activation_evidence_lease_seconds", "app_id", "ceremony_nonce", "chain_id",
    "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at", "compose_hash",
    "cvm_id", "deployment_intent_sha256", "descriptor_sha256", "domain", "evidence_mode",
    "expires_at",
    "identity_attestation_request_sha256", "identity_attestation_response_sha256",
    "identity_attestation_request_file_sha256",
    "identity_attestation_request_file_size",
    "identity_attestation_response_file_sha256",
    "identity_attestation_response_file_size",
    "local_dcap_verification", "local_dcap_verification_receipt_sha256",
    "measurement_policy", "measurement_policy_set_sha256", "measurement_policy_sha256",
    "os_image_hash", "posture_receipt_sha256", "private_historical_transcript_required",
    "profile", "raw_collateral_publicly_disclosed", "raw_quote_publicly_disclosed",
    "raw_secret_egress", "raw_transcript_sha256", "release_authority_sha256",
    "release_policy_sha256", "schema",
    "status", "tdx_measurements_sha256", "tdx_quote_sha256", "tee_identity",
    "truth_status", "verified_at",
  ], "QVL identity launch verification");
  const profile = PHALA_QVL_IDENTITY_DOMAIN_PROFILE[parsed.domain];
  if (!profile || parsed.schema !== PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA
    || parsed.status !== PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS
    || parsed.truth_status !== PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH
    || parsed.chain_id !== CHAIN_ID || parsed.profile !== profile
    || parsed.private_historical_transcript_required !== true
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false) {
    throw new Error("QVL identity launch verification authority is invalid");
  }
  const verifiedAt = second(parsed.verified_at, `${parsed.domain} verified_at`);
  const proofExpiresAt = second(parsed.expires_at, `${parsed.domain} expires_at`);
  const leaseIssuedAt = second(
    parsed.activation_evidence_lease_issued_at,
    `${parsed.domain} activation evidence lease issued_at`,
  );
  const leaseExpiresAt = second(
    parsed.activation_evidence_lease_expires_at,
    `${parsed.domain} activation evidence lease expires_at`,
  );
  const policy = normalizePhalaQvlMeasurementPolicy(parsed.measurement_policy);
  const policySha = phalaQvlMeasurementPolicySha256(policy);
  const local = normalizeLocalDcapResult(
    Object.fromEntries([
      "collateral_source", "debug", "measurement_policy_matched",
      "measurement_policy_reference_id", "measurement_policy_sha256", "measurements",
      "measurements_sha256", "quote_type", "report_data", "runtime_environment_sha256",
      "status", "verified",
    ].map((key) => [key, parsed.local_dcap_verification[key]])),
    {
      verifiedAt,
      evidenceMode: parsed.evidence_mode,
      quoteSha256: parsed.tdx_quote_sha256,
      measurementPolicy: policy,
    },
  );
  const carriedLocal = exactRecord(parsed.local_dcap_verification, [
    "collateral_authority", "collateral_authority_sha256", "collateral_source",
    "collateral_verification", "collateral_verification_receipt_sha256",
    "debug", "evidence_mode", "measurement_policy_matched",
    "measurement_policy_reference_id", "measurement_policy_sha256", "measurements",
    "measurements_sha256", "quote_type", "report_data", "runtime_environment_sha256",
    "schema", "status",
    "tdx_quote_sha256", "verification_method", "verified", "verified_at",
    "verifier_authority",
  ], "carried local DCAP verification");
  if (canonicalText(carriedLocal) !== canonicalText(local)) {
    throw new Error("carried local DCAP verification receipt drifted");
  }
  const localSha = domainSha256(LOCAL_DCAP_RECEIPT_DOMAIN, local);
  const issuedAt = second(parsed.challenge_issued_at, `${parsed.domain} challenge issued_at`);
  const challengeExpiresAt = second(
    parsed.challenge_expires_at,
    `${parsed.domain} challenge expires_at`,
  );
  if (challengeExpiresAt <= issuedAt || challengeExpiresAt - issuedAt > 120
    || verifiedAt < issuedAt || verifiedAt >= challengeExpiresAt
    || parsed.activation_evidence_lease_seconds
      !== PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || leaseIssuedAt !== verifiedAt
    || leaseExpiresAt !== verifiedAt + PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || proofExpiresAt !== leaseExpiresAt
    || parsed.local_dcap_verification_receipt_sha256 !== localSha
    || parsed.tdx_measurements_sha256 !== local.measurements_sha256
    || parsed.measurement_policy_sha256 !== policySha
    || local.measurement_policy_sha256 !== policySha
    || policy.domain !== parsed.domain || policy.profile !== profile
    || policy.deployment_intent_sha256 !== parsed.deployment_intent_sha256) {
    throw new Error(
      "QVL identity freshness, policy-bounded appraisal lease, local receipt, or measurements drifted",
    );
  }
  const requestSha = sha256(
    parsed.identity_attestation_request_sha256,
    `${parsed.domain} identity request digest`,
  );
  const responseSha = sha256(
    parsed.identity_attestation_response_sha256,
    `${parsed.domain} identity response digest`,
  );
  const requestFileSha = sha256(
    parsed.identity_attestation_request_file_sha256,
    `${parsed.domain} identity request file digest`,
  );
  const requestFileSize = rawArtifactFileSize(
    parsed.identity_attestation_request_file_size,
    `${parsed.domain} identity request file size`,
    MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
  );
  const responseFileSha = sha256(
    parsed.identity_attestation_response_file_sha256,
    `${parsed.domain} identity response file digest`,
  );
  const responseFileSize = rawArtifactFileSize(
    parsed.identity_attestation_response_file_size,
    `${parsed.domain} identity response file size`,
    MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
  );
  const transcriptSha = rawVerifierTranscriptSha256(
    parsed.domain,
    "qvl_identity_request_response",
    [requestFileSha, responseFileSha],
  );
  if (parsed.raw_transcript_sha256 !== transcriptSha) {
    throw new Error("QVL identity raw transcript commitment drifted");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    evidence_mode: parsed.evidence_mode,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile,
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      `${parsed.domain} release authority digest`,
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      `${parsed.domain} deployment intent`,
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, `${parsed.domain} ceremony nonce`),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      `${parsed.domain} measurement policy set`,
    ),
    measurement_policy_sha256: policySha,
    measurement_policy: policy,
    descriptor_sha256: sha256(parsed.descriptor_sha256, `${parsed.domain} descriptor digest`),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      `${parsed.domain} posture receipt digest`,
    ),
    app_id: appId(parsed.app_id, `${parsed.domain} app ID`),
    cvm_id: cvmId(parsed.cvm_id, `${parsed.domain} CVM ID`),
    compose_hash: bareSha256(parsed.compose_hash, `${parsed.domain} compose hash`),
    os_image_hash: bareSha256(parsed.os_image_hash, `${parsed.domain} OS image hash`),
    tee_identity: address(parsed.tee_identity, `${parsed.domain} TEE identity`),
    release_policy_sha256: sha256(
      parsed.release_policy_sha256,
      `${parsed.domain} release policy digest`,
    ),
    challenge_id: bytes32(parsed.challenge_id, `${parsed.domain} challenge ID`),
    challenge_digest: bytes32(parsed.challenge_digest, `${parsed.domain} challenge digest`),
    challenge_issued_at: issuedAt,
    challenge_expires_at: challengeExpiresAt,
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, `${parsed.domain} quote digest`),
    tdx_measurements_sha256: local.measurements_sha256,
    identity_attestation_request_sha256: requestSha,
    identity_attestation_response_sha256: responseSha,
    identity_attestation_request_file_sha256: requestFileSha,
    identity_attestation_request_file_size: requestFileSize,
    identity_attestation_response_file_sha256: responseFileSha,
    identity_attestation_response_file_size: responseFileSize,
    raw_transcript_sha256: transcriptSha,
    local_dcap_verification: local,
    local_dcap_verification_receipt_sha256: localSha,
    verified_at: verifiedAt,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    activation_evidence_lease_issued_at: leaseIssuedAt,
    activation_evidence_lease_expires_at: leaseExpiresAt,
    expires_at: proofExpiresAt,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

export async function verifyPhalaQvlIdentityLaunchEvidence({
  domain,
  releaseAuthority: releaseAuthorityValue,
  request,
  response,
  rawRequestText,
  rawResponseText,
  ledger,
  testOnlyNow,
  testOnlyVerifyQuote,
} = {}) {
  const releaseAuthority = assertReleaseVerificationAuthorityForEvidence(
    releaseAuthorityValue,
  );
  const descriptor = releaseDescriptor(releaseAuthority, domain);
  const policy = releaseMeasurementPolicy(releaseAuthority, domain);
  const policySha = phalaQvlMeasurementPolicySha256(policy);
  const releaseAuthoritySha = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const evidenceMode = releaseAuthority.evidence_mode;
  if ((evidenceMode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE)
      !== (testOnlyVerifyQuote === undefined)) {
    throw new Error("synthetic and production DCAP verifier authority cannot be mixed");
  }
  if (testOnlyVerifyQuote !== undefined) assertSyntheticDcapAdapter(testOnlyVerifyQuote);
  const normalizedRequest = normalizeQvlIdentityRequest(request);
  const normalizedResponse = normalizeQvlIdentityResponse(response);
  canonicalRawArtifactFileIdentity(
    rawRequestText,
    normalizedRequest,
    `${domain} QVL identity request file`,
  );
  canonicalRawArtifactFileIdentity(
    rawResponseText,
    normalizedResponse,
    `${domain} QVL identity response file`,
  );
  if (normalizedRequest.challenge_digest !== phalaQvlIdentityChallengeDigest(normalizedRequest)) {
    throw new Error("QVL identity challenge digest is invalid");
  }
  const expectedLineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: PHALA_QVL_IDENTITY_DOMAIN_PROFILE[domain],
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256: releaseAuthoritySha,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: policySha,
    app_id: descriptor.app_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
  };
  for (const [field, expectedValue] of Object.entries(expectedLineage)) {
    if (normalizedRequest[field] !== expectedValue || normalizedResponse[field] !== expectedValue) {
      throw new Error(`QVL identity ${field} drifted from signed release authority`);
    }
  }
  for (const [requestField, responseField] of [
    ["challenge_id", "challenge_id"],
    ["challenge_digest", "challenge_digest"],
    ["issued_at", "challenge_issued_at"],
    ["expires_at", "challenge_expires_at"],
  ]) {
    if (normalizedRequest[requestField] !== normalizedResponse[responseField]) {
      throw new Error("QVL identity response is not bound to the exact challenge");
    }
  }
  const expectedReportData = qvlIdentityReportData({
    request: normalizedRequest,
    verifierAddress: normalizedResponse.verifier_address,
    releasePolicyHash: normalizedResponse.release_policy_hash,
  });
  if (normalizedResponse.report_data !== expectedReportData
    || normalizedResponse.quote_report_data
      !== `${expectedReportData}${normalizedRequest.challenge_digest.slice(2)}`) {
    throw new Error("QVL identity report data does not bind the release lineage and challenge");
  }
  const rawQuote = Buffer.from(normalizedResponse.quote.slice(2), "hex");
  const quoteSha = `sha256:${createHash("sha256").update(rawQuote).digest("hex")}`;
  if (quoteSha !== shaFromBytes32(normalizedResponse.quote_hash, `${domain} quote hash`)) {
    throw new Error("QVL identity response quote digest drifted");
  }
  const verifiedAt = verificationSecond(
    releaseAuthority,
    testOnlyNow,
    `${domain} QVL identity verification`,
  );
  const localVerifierOutput = testOnlyVerifyQuote === undefined
    ? verifyPinnedSevenCvmLocalDcapQuoteAt(rawQuote, policy, verifiedAt)
    : await testOnlyVerifyQuote(rawQuote, policy);
  const splitLocal = splitLocalDcapVerifierOutput(localVerifierOutput, {
    evidenceMode,
    verifiedAt,
    domain,
  });
  const local = normalizeLocalDcapResult(splitLocal.result, {
    verifiedAt,
    evidenceMode,
    quoteSha256: quoteSha,
    measurementPolicy: policy,
  });
  if (quoteSha !== local.tdx_quote_sha256 || local.report_data !== normalizedResponse.quote_report_data
    || verifiedAt < normalizedRequest.issued_at || verifiedAt >= normalizedRequest.expires_at) {
    throw new Error("local DCAP receipt is stale or not bound to the identity response quote");
  }
  const localReceiptSha = domainSha256(LOCAL_DCAP_RECEIPT_DOMAIN, local);
  const postureAudit = historicalPostureAuditForReleaseAuthority(releaseAuthority, domain);
  const historicalReplayRecord = normalizeHistoricalDcapReplayRecord({
    schema: PHALA_VERIFIER_HISTORICAL_DCAP_REPLAY_RECORD_SCHEMA,
    verification_time: verifiedAt,
    activation_evidence_lease_issued_at: verifiedAt,
    activation_evidence_lease_expires_at:
      verifiedAt + releaseAuthority.activation_evidence_lease_seconds,
    runtime_environment_sha256:
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    collateral_sha256: splitLocal.replay.collateral_sha256,
    collateral_json: splitLocal.replay.collateral_json,
    local_dcap_verification_receipt_sha256: localReceiptSha,
    posture_expected_authority: postureAudit.expected_authority,
    production_posture_receipt: postureAudit.receipt,
    production_posture_receipt_sha256: postureAudit.receipt_sha256,
  }, { expectedDomain: domain, releaseAuthority });
  const transcriptFlags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[domain];
  const historicalRequestText = createHistoricalTranscriptEnvelopeText({
    flag: transcriptFlags.request,
    rawArtifactText: rawRequestText,
    artifact: normalizedRequest,
    verificationRecord: null,
  });
  const historicalResponseText = createHistoricalTranscriptEnvelopeText({
    flag: transcriptFlags.response,
    rawArtifactText: rawResponseText,
    artifact: normalizedResponse,
    verificationRecord: historicalReplayRecord,
  });
  const requestFile = rawHistoricalFileIdentity(
    historicalRequestText,
    `${domain} private historical request transcript`,
  );
  const responseFile = rawHistoricalFileIdentity(
    historicalResponseText,
    `${domain} private historical response transcript`,
  );
  const candidate = {
    schema: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA,
    status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS,
    truth_status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH,
    evidence_mode: evidenceMode,
    chain_id: CHAIN_ID,
    domain,
    profile: expectedLineage.profile,
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: policySha,
    measurement_policy: policy,
    descriptor_sha256: descriptor.descriptor_sha256,
    posture_receipt_sha256: descriptor.posture_receipt_sha256,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    tee_identity: normalizedResponse.verifier_address,
    release_policy_sha256: shaFromBytes32(
      normalizedResponse.release_policy_hash,
      `${domain} QVL release policy`,
    ),
    challenge_id: normalizedRequest.challenge_id,
    challenge_digest: normalizedRequest.challenge_digest,
    challenge_issued_at: normalizedRequest.issued_at,
    challenge_expires_at: normalizedRequest.expires_at,
    tdx_quote_sha256: quoteSha,
    tdx_measurements_sha256: local.measurements_sha256,
    identity_attestation_request_sha256:
      domainSha256(QVL_REQUEST_ARTIFACT_DOMAIN, normalizedRequest),
    identity_attestation_response_sha256:
      domainSha256(QVL_RESPONSE_ARTIFACT_DOMAIN, normalizedResponse),
    identity_attestation_request_file_sha256: requestFile.sha256,
    identity_attestation_request_file_size: requestFile.size,
    identity_attestation_response_file_sha256: responseFile.sha256,
    identity_attestation_response_file_size: responseFile.size,
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      domain,
      "qvl_identity_request_response",
      [
        requestFile.sha256,
        responseFile.sha256,
      ],
    ),
    local_dcap_verification: local,
    local_dcap_verification_receipt_sha256: localReceiptSha,
    verified_at: verifiedAt,
    activation_evidence_lease_seconds:
      releaseAuthority.activation_evidence_lease_seconds,
    activation_evidence_lease_issued_at: verifiedAt,
    activation_evidence_lease_expires_at:
      verifiedAt + releaseAuthority.activation_evidence_lease_seconds,
    // Transitional exact alias for downstream evidence-set consumers. New
    // consumers must use activation_evidence_lease_expires_at explicitly.
    expires_at: verifiedAt + releaseAuthority.activation_evidence_lease_seconds,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizeQvlIdentityVerification(candidate),
    { label: `${domain} verified QVL identity evidence` },
  );
  consumeReleaseScopedChallenge(
    ledger,
    releaseAuthority,
    domain,
    normalizedRequest.challenge_id,
  );
  VERIFIED_QVL_IDENTITIES.set(
    normalized,
    domainSha256(PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN, normalized),
  );
  LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF.set(normalized, Object.freeze([
    Object.freeze({ flag: transcriptFlags.request, text: historicalRequestText }),
    Object.freeze({ flag: transcriptFlags.response, text: historicalResponseText }),
  ]));
  return normalized;
}

export function canonicalPhalaQvlIdentityLaunchEvidenceText(value) {
  return canonicalText(normalizeQvlIdentityVerification(value));
}

export function phalaQvlIdentityLaunchEvidenceSha256(value) {
  return domainSha256(
    PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN,
    normalizeQvlIdentityVerification(value),
  );
}

export function assertVerifiedPhalaQvlIdentityLaunchEvidence(value) {
  const expected = VERIFIED_QVL_IDENTITIES.get(value);
  if (!expected || phalaQvlIdentityLaunchEvidenceSha256(value) !== expected) {
    throw new Error("QVL identity evidence was not machine-verified in this process");
  }
  return value;
}

function diligenceReportData({ teeIdentity, contractAddress }) {
  return `0x${createHash("sha256").update(JSON.stringify({
    service: "dnai-wikigen",
    context: DILIGENCE_REPORT_DATA_DOMAINLESS_CONTEXT,
    signer_address: teeIdentity,
    chain_id: CHAIN_ID,
    contract_address: contractAddress,
  }, Object.keys({
    service: 0,
    context: 0,
    signer_address: 0,
    chain_id: 0,
    contract_address: 0,
  }).sort())).digest("hex")}`;
}

function computeMeteringReportData({ teeIdentity, contractAddress, policySetHash }) {
  const payload = {
    schema: "dnai.compute-metering-signer-attestation.v1",
    chain_id: CHAIN_ID,
    vault_address: contractAddress,
    metering_verifier: teeIdentity,
    policy_set_hash: policySetHash,
    signer_custody: COMPUTE_SIGNER_CUSTODY,
  };
  return `0x${createHash("sha256")
    .update(COMPUTE_REPORT_DATA_DOMAIN, "utf8")
    .update(compactCanonicalText(payload), "ascii")
    .digest("hex")}`;
}

function normalizeReportDataBinding(value, domain) {
  if (domain === "main_runtime_cvm") {
    const binding = exactRecord(value, ["kind"], "main runtime report-data binding");
    if (binding.kind !== "diligence_result_signer_v1") {
      throw new Error("main runtime report-data binding is invalid");
    }
    return { kind: binding.kind };
  }
  const binding = exactRecord(value, [
    "kind", "policy_set_hash", "signer_custody",
  ], "independent metering report-data binding");
  if (binding.kind !== "compute_metering_signer_v1"
    || binding.signer_custody !== COMPUTE_SIGNER_CUSTODY) {
    throw new Error("independent metering report-data binding is invalid");
  }
  return {
    kind: binding.kind,
    policy_set_hash: bytes32(binding.policy_set_hash, "metering policy-set hash"),
    signer_custody: COMPUTE_SIGNER_CUSTODY,
  };
}

function normalizeWorkloadExpectedFromAssertedAuthority(
  value,
  domain,
  linkedQvl,
  releaseAuthority,
) {
  const expected = exactRecord(value, [
    "reportDataBinding",
  ], `${domain} workload verdict report-data authority`);
  const binding = normalizeReportDataBinding(expected.reportDataBinding, domain);
  const descriptor = releaseDescriptorFromAssertedAuthority(releaseAuthority, domain);
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
  return {
    domain,
    profile: link.profile,
    qvl_domain: link.qvl_domain,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    descriptor_sha256: descriptor.descriptor_sha256,
    posture_receipt_sha256: descriptor.posture_receipt_sha256,
    contract_address: releaseAuthority.contracts[link.expected_contract_key],
    report_data_binding: binding,
    verifier_address: linkedQvl.tee_identity,
    release_policy_sha256: linkedQvl.release_policy_sha256,
    measurement_policy_sha256: linkedQvl.measurement_policy_sha256,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    release_authority_sha256:
      phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority),
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    qvl_identity_evidence_sha256: phalaQvlIdentityLaunchEvidenceSha256(linkedQvl),
  };
}

function normalizeWorkloadExpected(value, domain, linkedQvl, releaseAuthorityValue) {
  return normalizeWorkloadExpectedFromAssertedAuthority(
    value,
    domain,
    linkedQvl,
    assertReleaseVerificationAuthorityForEvidence(releaseAuthorityValue),
  );
}

function normalizeIndependentVerdict(value) {
  const verdict = exactRecord(value, [
    "activation_evidence_lease_expires_at", "app_id", "ceremony_nonce", "chain_id", "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at", "compose_hash",
    "contract_address", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "release_authority_sha256", "release_policy_hash", "report_data", "schema",
    "signer_address", "verification_method", "verified", "verifier_address",
    "verifier_signature",
  ], "independent TDX verdict");
  if (verdict.schema !== PHALA_INDEPENDENT_TDX_VERDICT_SCHEMA
    || verdict.verification_method !== "intel_tdx_dcap_qvl"
    || verdict.verified !== true || verdict.chain_id !== CHAIN_ID
    || !PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(verdict.domain)
    || !Object.values(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).includes(verdict.profile)
    || typeof verdict.verifier_signature !== "string"
    || !SIGNATURE.test(verdict.verifier_signature)) {
    throw new Error("independent TDX verdict schema or method is invalid");
  }
  const issuedAt = second(verdict.issued_at, "verdict issued_at");
  const leaseExpiresAt = second(
    verdict.activation_evidence_lease_expires_at,
    "verdict activation evidence lease expires_at",
  );
  const expiresAt = second(verdict.expires_at, "verdict expires_at");
  if (leaseExpiresAt !== expiresAt || expiresAt <= issuedAt
    || expiresAt - issuedAt > PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS) {
    throw new Error("independent TDX verdict activation evidence lease is invalid");
  }
  return {
    schema: verdict.schema,
    verification_method: verdict.verification_method,
    verified: true,
    chain_id: CHAIN_ID,
    domain: verdict.domain,
    profile: verdict.profile,
    cvm_id: cvmId(verdict.cvm_id, "verdict target CVM ID"),
    deployment_intent_sha256: sha256(
      verdict.deployment_intent_sha256,
      "verdict deployment intent",
    ),
    release_authority_sha256: sha256(
      verdict.release_authority_sha256,
      "verdict release authority",
    ),
    ceremony_nonce: bytes32(verdict.ceremony_nonce, "verdict ceremony nonce"),
    measurement_policy_sha256: sha256(
      verdict.measurement_policy_sha256,
      "verdict QVL measurement policy",
    ),
    release_policy_hash: bytes32(verdict.release_policy_hash, "verdict release policy hash"),
    challenge_id: bytes32(verdict.challenge_id, "verdict challenge ID"),
    challenge_digest: bytes32(verdict.challenge_digest, "verdict challenge digest"),
    challenge_issued_at: second(verdict.challenge_issued_at, "verdict challenge issued_at"),
    challenge_expires_at: second(verdict.challenge_expires_at, "verdict challenge expires_at"),
    quote_hash: bytes32(verdict.quote_hash, "verdict quote hash"),
    report_data: bytes32(verdict.report_data, "verdict report data"),
    compose_hash: bytes32(verdict.compose_hash, "verdict compose hash"),
    app_id: appId(verdict.app_id, "verdict app ID"),
    os_image_hash: bareSha256(verdict.os_image_hash, "verdict OS image hash"),
    signer_address: address(verdict.signer_address, "verdict signer address"),
    contract_address: address(verdict.contract_address, "verdict contract address"),
    issued_at: issuedAt,
    activation_evidence_lease_expires_at: leaseExpiresAt,
    expires_at: expiresAt,
    verifier_address: address(verdict.verifier_address, "verdict verifier address"),
    verifier_signature: verdict.verifier_signature,
  };
}

function normalizeQvlChallenge(value) {
  const challenge = exactRecord(value, [
    "ceremony_nonce", "chain_id", "challenge_digest", "challenge_id", "cvm_id",
    "deployment_intent_sha256", "domain", "expires_at", "issued_at",
    "measurement_policy_sha256", "profile", "release_authority_sha256",
    "release_policy_hash", "schema", "verifier_address", "verifier_signature",
  ], "workload QVL challenge");
  if (challenge.schema !== PHALA_WORKLOAD_QVL_CHALLENGE_SCHEMA
    || challenge.chain_id !== CHAIN_ID
    || !PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(challenge.domain)
    || !Object.values(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).includes(challenge.profile)
    || typeof challenge.verifier_signature !== "string"
    || !SIGNATURE.test(challenge.verifier_signature)) {
    throw new Error("workload QVL challenge schema or profile is invalid");
  }
  const issuedAt = second(challenge.issued_at, "workload challenge issued_at");
  const expiresAt = second(challenge.expires_at, "workload challenge expires_at");
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 120) {
    throw new Error("workload QVL challenge lifetime is invalid");
  }
  return {
    schema: challenge.schema,
    chain_id: CHAIN_ID,
    domain: challenge.domain,
    profile: challenge.profile,
    cvm_id: cvmId(challenge.cvm_id, "workload challenge target CVM ID"),
    deployment_intent_sha256: sha256(
      challenge.deployment_intent_sha256,
      "workload challenge deployment intent",
    ),
    release_authority_sha256: sha256(
      challenge.release_authority_sha256,
      "workload challenge release authority",
    ),
    ceremony_nonce: bytes32(challenge.ceremony_nonce, "workload challenge ceremony nonce"),
    measurement_policy_sha256: sha256(
      challenge.measurement_policy_sha256,
      "workload challenge QVL measurement policy",
    ),
    release_policy_hash: bytes32(
      challenge.release_policy_hash,
      "workload challenge release policy hash",
    ),
    challenge_id: bytes32(challenge.challenge_id, "workload challenge ID"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    verifier_address: address(
      challenge.verifier_address,
      "workload challenge verifier address",
    ),
    challenge_digest: bytes32(challenge.challenge_digest, "workload challenge digest"),
    verifier_signature: challenge.verifier_signature,
  };
}

export function qvlChallengeSigningDigest(value) {
  const challenge = normalizeQvlChallenge(value);
  const unsigned = Object.fromEntries(
    Object.entries(challenge).filter(([key]) =>
      !["challenge_digest", "verifier_signature"].includes(key)),
  );
  return `0x${createHash("sha256")
    .update(QVL_CHALLENGE_DOMAIN, "utf8")
    .update(compactCanonicalText(unsigned), "ascii")
    .digest("hex")}`;
}

function qvlChallengeArtifactSha256(value) {
  return domainSha256(QVL_CHALLENGE_ARTIFACT_DOMAIN, normalizeQvlChallenge(value));
}

export function independentTdxVerdictSigningDigest(value) {
  const verdict = normalizeIndependentVerdict(value);
  const unsigned = Object.fromEntries(
    Object.entries(verdict).filter(([key]) => key !== "verifier_signature"),
  );
  return `0x${createHash("sha256")
    .update(INDEPENDENT_VERDICT_DOMAIN, "utf8")
    .update(compactCanonicalText(unsigned), "ascii")
    .digest("hex")}`;
}

function independentTdxVerdictArtifactSha256(value) {
  return domainSha256(INDEPENDENT_VERDICT_ARTIFACT_DOMAIN, normalizeIndependentVerdict(value));
}

function normalizeWorkloadVerification(value) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "app_id", "ceremony_nonce", "chain_id",
    "challenge_digest", "challenge_expires_at",
    "challenge_id", "challenge_issued_at", "compose_hash", "contract_address", "cvm_id",
    "deployment_intent_sha256", "descriptor_sha256", "domain", "evidence_mode",
    "expires_at", "measurement_policy_set_sha256", "measurement_policy_sha256",
    "os_image_hash", "posture_receipt_sha256", "profile",
    "qvl_challenge_artifact_sha256", "qvl_challenge_signing_digest",
    "qvl_challenge_file_sha256",
    "qvl_challenge_file_size",
    "qvl_challenge_verifier_signature_sha256",
    "qvl_identity_evidence_sha256", "qvl_release_policy_sha256",
    "qvl_verdict_artifact_sha256", "qvl_verdict_signing_digest",
    "qvl_verdict_file_sha256",
    "qvl_verdict_file_size",
    "qvl_verdict_verifier_address", "qvl_verdict_verifier_signature_sha256",
    "private_historical_transcript_required", "raw_collateral_publicly_disclosed",
    "raw_quote_publicly_disclosed", "raw_secret_egress", "raw_transcript_sha256",
    "release_authority_sha256", "report_data",
    "report_data_binding", "schema", "status", "tdx_quote_sha256",
    "tee_identity", "truth_status", "verdict_activation_evidence_lease_expires_at",
    "verdict_expires_at", "verdict_issued_at", "verified_at",
  ], "workload TDX verdict verification");
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[parsed.domain];
  if (!link || parsed.schema !== PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA
    || parsed.status !== PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS
    || parsed.truth_status !== PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_TRUTH
    || parsed.chain_id !== CHAIN_ID
    || parsed.profile !== link.profile
    || parsed.private_historical_transcript_required !== true
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false) {
    throw new Error("workload verdict verification authority is invalid");
  }
  if (![PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE, PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE]
    .includes(parsed.evidence_mode)) {
    throw new Error("workload verdict evidence mode is invalid");
  }
  const challengeIssued = second(parsed.challenge_issued_at, "workload challenge issued_at");
  const challengeExpires = second(parsed.challenge_expires_at, "workload challenge expires_at");
  const verdictIssued = second(parsed.verdict_issued_at, "workload verdict issued_at");
  const verdictExpires = second(parsed.verdict_expires_at, "workload verdict expires_at");
  const verdictLeaseExpires = second(
    parsed.verdict_activation_evidence_lease_expires_at,
    "workload verdict activation evidence lease expires_at",
  );
  const activationLeaseExpires = second(
    parsed.activation_evidence_lease_expires_at,
    "workload activation evidence lease expires_at",
  );
  const verifiedAt = second(parsed.verified_at, "workload verdict verified_at");
  const proofExpiresAt = second(parsed.expires_at, "workload proof expires_at");
  if (challengeExpires <= challengeIssued || challengeExpires - challengeIssued > 120
    || verdictIssued < challengeIssued || verdictIssued >= challengeExpires
    || verdictExpires <= verdictIssued
    || verdictExpires - verdictIssued > PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS
    || verdictLeaseExpires !== verdictExpires
    || activationLeaseExpires > verdictLeaseExpires
    || verifiedAt < verdictIssued || verifiedAt >= activationLeaseExpires
    || proofExpiresAt !== activationLeaseExpires) {
    throw new Error("workload verdict freshness is invalid");
  }
  const binding = normalizeReportDataBinding(parsed.report_data_binding, parsed.domain);
  const challengeArtifactSha = sha256(
    parsed.qvl_challenge_artifact_sha256,
    "QVL challenge artifact digest",
  );
  const verdictArtifactSha = sha256(
    parsed.qvl_verdict_artifact_sha256,
    "QVL verdict artifact digest",
  );
  const challengeFileSha = sha256(
    parsed.qvl_challenge_file_sha256,
    "QVL challenge file digest",
  );
  const challengeFileSize = rawArtifactFileSize(
    parsed.qvl_challenge_file_size,
    "QVL challenge file size",
    MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
  );
  const verdictFileSha = sha256(parsed.qvl_verdict_file_sha256, "QVL verdict file digest");
  const verdictFileSize = rawArtifactFileSize(
    parsed.qvl_verdict_file_size,
    "QVL verdict file size",
    MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
  );
  const transcriptSha = rawVerifierTranscriptSha256(
    parsed.domain,
    "workload_challenge_verdict",
    [challengeFileSha, verdictFileSha],
  );
  if (parsed.raw_transcript_sha256 !== transcriptSha) {
    throw new Error("workload raw transcript commitment drifted");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    evidence_mode: parsed.evidence_mode,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile: parsed.profile,
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      "workload release authority digest",
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "workload deployment intent",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "workload ceremony nonce"),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      "workload measurement policy set",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "workload QVL measurement policy",
    ),
    descriptor_sha256: sha256(parsed.descriptor_sha256, "workload descriptor digest"),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      "workload posture receipt digest",
    ),
    app_id: appId(parsed.app_id, "workload app ID"),
    cvm_id: cvmId(parsed.cvm_id, "workload CVM ID"),
    compose_hash: bareSha256(parsed.compose_hash, "workload compose hash"),
    os_image_hash: bareSha256(parsed.os_image_hash, "workload OS image hash"),
    tee_identity: address(parsed.tee_identity, "workload TEE identity"),
    contract_address: address(parsed.contract_address, "workload contract address"),
    report_data_binding: binding,
    report_data: bytes32(parsed.report_data, "workload report data"),
    qvl_release_policy_sha256: sha256(parsed.qvl_release_policy_sha256, "QVL policy digest"),
    qvl_identity_evidence_sha256: sha256(
      parsed.qvl_identity_evidence_sha256,
      "QVL identity evidence digest",
    ),
    qvl_challenge_signing_digest: bytes32(
      parsed.qvl_challenge_signing_digest,
      "QVL challenge signing digest",
    ),
    qvl_challenge_artifact_sha256: challengeArtifactSha,
    qvl_challenge_file_sha256: challengeFileSha,
    qvl_challenge_file_size: challengeFileSize,
    qvl_challenge_verifier_signature_sha256: sha256(
      parsed.qvl_challenge_verifier_signature_sha256,
      "QVL challenge signature digest",
    ),
    challenge_id: bytes32(parsed.challenge_id, "workload challenge ID"),
    challenge_digest: bytes32(parsed.challenge_digest, "workload challenge digest"),
    challenge_issued_at: challengeIssued,
    challenge_expires_at: challengeExpires,
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, "workload quote digest"),
    qvl_verdict_signing_digest: bytes32(
      parsed.qvl_verdict_signing_digest,
      "QVL verdict signing digest",
    ),
    qvl_verdict_artifact_sha256: verdictArtifactSha,
    qvl_verdict_file_sha256: verdictFileSha,
    qvl_verdict_file_size: verdictFileSize,
    raw_transcript_sha256: transcriptSha,
    qvl_verdict_verifier_address: address(
      parsed.qvl_verdict_verifier_address,
      "QVL verdict verifier address",
    ),
    qvl_verdict_verifier_signature_sha256: sha256(
      parsed.qvl_verdict_verifier_signature_sha256,
      "QVL verdict verifier signature digest",
    ),
    verdict_issued_at: verdictIssued,
    verdict_activation_evidence_lease_expires_at: verdictLeaseExpires,
    verdict_expires_at: verdictExpires,
    verified_at: verifiedAt,
    activation_evidence_lease_expires_at: activationLeaseExpires,
    expires_at: proofExpiresAt,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

export function verifyPhalaWorkloadIndependentTdxVerdict({
  domain,
  releaseAuthority: releaseAuthorityValue,
  challenge: challengeValue,
  verdict: verdictValue,
  rawChallengeText,
  rawVerdictText,
  expected,
  qvlIdentityEvidence,
  challengeLedger,
  testOnlyNow,
} = {}) {
  const releaseAuthority = assertReleaseVerificationAuthorityForEvidence(
    releaseAuthorityValue,
  );
  const linked = assertVerifiedPhalaQvlIdentityLaunchEvidence(qvlIdentityEvidence);
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
  if (!link || linked.domain !== link.qvl_domain) {
    throw new Error("workload verdict is not linked to its exact independently verified QVL");
  }
  const releaseAuthoritySha = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  if (linked.release_authority_sha256 !== releaseAuthoritySha
    || linked.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
    || linked.ceremony_nonce !== releaseAuthority.ceremony_nonce
    || linked.measurement_policy_set_sha256
      !== releaseAuthority.qvl_measurement_policy_set_sha256) {
    throw new Error("linked QVL identity belongs to another release ceremony");
  }
  const authority = normalizeWorkloadExpected(
    expected,
    domain,
    linked,
    releaseAuthority,
  );
  const challenge = normalizeQvlChallenge(challengeValue);
  const verdict = normalizeIndependentVerdict(verdictValue);
  canonicalRawArtifactFileIdentity(
    rawChallengeText,
    challenge,
    `${domain} QVL challenge file`,
  );
  canonicalRawArtifactFileIdentity(
    rawVerdictText,
    verdict,
    `${domain} QVL verdict file`,
  );
  const binding = authority.report_data_binding;
  const expectedReportData = domain === "main_runtime_cvm"
    ? diligenceReportData({
      teeIdentity: verdict.signer_address,
      contractAddress: authority.contract_address,
    })
    : computeMeteringReportData({
      teeIdentity: verdict.signer_address,
      contractAddress: authority.contract_address,
      policySetHash: binding.policy_set_hash,
    });
  const lineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: authority.profile,
    cvm_id: authority.cvm_id,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    release_authority_sha256: authority.release_authority_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_sha256: authority.measurement_policy_sha256,
  };
  if (Object.entries(lineage).some(([field, expectedValue]) =>
    challenge[field] !== expectedValue || verdict[field] !== expectedValue)
    || challenge.release_policy_hash
      !== bytes32FromSha(authority.release_policy_sha256, "challenge release policy")
    || challenge.verifier_address !== authority.verifier_address
    || challenge.challenge_id !== verdict.challenge_id
    || challenge.challenge_digest !== verdict.challenge_digest
    || challenge.issued_at !== verdict.challenge_issued_at
    || challenge.expires_at !== verdict.challenge_expires_at
    || verdict.app_id !== authority.app_id
    || verdict.compose_hash !== bytes32FromBare(authority.compose_hash, "workload compose")
    || verdict.os_image_hash !== authority.os_image_hash
    || verdict.signer_address === authority.verifier_address
    || verdict.contract_address !== authority.contract_address
    || verdict.verifier_address !== authority.verifier_address
    || shaFromBytes32(verdict.release_policy_hash, "verdict release policy")
      !== authority.release_policy_sha256
    || verdict.report_data !== expectedReportData) {
    throw new Error("signed workload verdict drifted from CVM, contract, policy, or report-data authority");
  }
  const challengeDigest = qvlChallengeSigningDigest(challenge);
  if (challenge.challenge_digest !== challengeDigest) {
    throw new Error("workload QVL challenge digest is invalid");
  }
  const challengeSignatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: challenge.verifier_address,
    digest: challengeDigest,
    signature: challenge.verifier_signature,
  });
  const verifiedSecond = verificationSecond(
    releaseAuthority,
    testOnlyNow,
    `${domain} workload verdict verification`,
  );
  const activationEvidenceLeaseExpiresAt = Math.min(
    verdict.activation_evidence_lease_expires_at,
    linked.activation_evidence_lease_expires_at,
  );
  if (verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at
      > releaseAuthority.activation_evidence_lease_seconds
    || verifiedSecond < verdict.issued_at
    || verifiedSecond >= activationEvidenceLeaseExpiresAt) {
    throw new Error(
      "signed workload verdict is expired or outside its policy-bounded activation evidence lease",
    );
  }
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const signatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest: signingDigest,
    signature: verdict.verifier_signature,
  });
  const postureAudit = historicalPostureAuditForReleaseAuthority(releaseAuthority, domain);
  const transcriptFlags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[domain];
  const historicalChallengeText = createHistoricalTranscriptEnvelopeText({
    flag: transcriptFlags.challenge,
    rawArtifactText: rawChallengeText,
    artifact: challenge,
    verificationRecord: null,
  });
  const historicalVerdictText = createHistoricalTranscriptEnvelopeText({
    flag: transcriptFlags.verdict,
    rawArtifactText: rawVerdictText,
    artifact: verdict,
    verificationRecord: {
      schema: PHALA_VERIFIER_HISTORICAL_SIGNATURE_REPLAY_RECORD_SCHEMA,
      verification_time: verifiedSecond,
      verdict_activation_evidence_lease_expires_at:
        verdict.activation_evidence_lease_expires_at,
      activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
      report_data_binding: binding,
      posture_expected_authority: postureAudit.expected_authority,
      production_posture_receipt: postureAudit.receipt,
      production_posture_receipt_sha256: postureAudit.receipt_sha256,
    },
  });
  const challengeFile = rawHistoricalFileIdentity(
    historicalChallengeText,
    `${domain} private historical challenge transcript`,
  );
  const verdictFile = rawHistoricalFileIdentity(
    historicalVerdictText,
    `${domain} private historical verdict transcript`,
  );
  const candidate = {
    schema: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA,
    status: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS,
    truth_status: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_TRUTH,
    evidence_mode: linked.evidence_mode,
    chain_id: CHAIN_ID,
    domain,
    profile: authority.profile,
    release_authority_sha256: authority.release_authority_sha256,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_set_sha256: authority.measurement_policy_set_sha256,
    measurement_policy_sha256: authority.measurement_policy_sha256,
    descriptor_sha256: authority.descriptor_sha256,
    posture_receipt_sha256: authority.posture_receipt_sha256,
    app_id: authority.app_id,
    cvm_id: authority.cvm_id,
    compose_hash: authority.compose_hash,
    os_image_hash: authority.os_image_hash,
    tee_identity: verdict.signer_address,
    contract_address: authority.contract_address,
    report_data_binding: binding,
    report_data: verdict.report_data,
    qvl_release_policy_sha256: authority.release_policy_sha256,
    qvl_identity_evidence_sha256: authority.qvl_identity_evidence_sha256,
    qvl_challenge_signing_digest: challengeDigest,
    qvl_challenge_artifact_sha256: qvlChallengeArtifactSha256(challenge),
    qvl_challenge_file_sha256: challengeFile.sha256,
    qvl_challenge_file_size: challengeFile.size,
    qvl_challenge_verifier_signature_sha256:
      challengeSignatureReceipt.signature_sha256,
    challenge_id: verdict.challenge_id,
    challenge_digest: verdict.challenge_digest,
    challenge_issued_at: verdict.challenge_issued_at,
    challenge_expires_at: verdict.challenge_expires_at,
    tdx_quote_sha256: shaFromBytes32(verdict.quote_hash, "workload quote hash"),
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: independentTdxVerdictArtifactSha256(verdict),
    qvl_verdict_file_sha256: verdictFile.sha256,
    qvl_verdict_file_size: verdictFile.size,
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      domain,
      "workload_challenge_verdict",
      [challengeFile.sha256, verdictFile.sha256],
    ),
    qvl_verdict_verifier_address: verdict.verifier_address,
    qvl_verdict_verifier_signature_sha256: signatureReceipt.signature_sha256,
    verdict_issued_at: verdict.issued_at,
    verdict_activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    verdict_expires_at: verdict.expires_at,
    verified_at: verifiedSecond,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    expires_at: activationEvidenceLeaseExpiresAt,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizeWorkloadVerification(candidate),
    { label: `${domain} verified workload verdict evidence` },
  );
  consumeReleaseScopedChallenge(
    challengeLedger,
    releaseAuthority,
    domain,
    challenge.challenge_id,
  );
  VERIFIED_WORKLOAD_VERDICTS.set(
    normalized,
    domainSha256(PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN, normalized),
  );
  LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF.set(normalized, Object.freeze([
    Object.freeze({ flag: transcriptFlags.challenge, text: historicalChallengeText }),
    Object.freeze({ flag: transcriptFlags.verdict, text: historicalVerdictText }),
  ]));
  return normalized;
}

export function canonicalPhalaWorkloadTdxVerdictVerificationText(value) {
  return canonicalText(normalizeWorkloadVerification(value));
}

export function phalaWorkloadTdxVerdictVerificationSha256(value) {
  return domainSha256(
    PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN,
    normalizeWorkloadVerification(value),
  );
}

export function assertVerifiedPhalaWorkloadTdxVerdict(value) {
  const expected = VERIFIED_WORKLOAD_VERDICTS.get(value);
  if (!expected || phalaWorkloadTdxVerdictVerificationSha256(value) !== expected) {
    throw new Error("workload TDX verdict was not independently signature-verified in this process");
  }
  return value;
}

function normalizeComputeWorkloadRecipientAttestation(value) {
  const attestation = exactRecord(value, [
    "activation_signer_address", "activation_signer_custody",
    "activation_signer_key_path", "audience", "chain_id",
    "compute_vault_address", "compute_vault_runtime_code_hash",
    "context", "encryption_public_key", "fresh_contract_deployment_receipt_sha256",
    "key_id", "protocol", "schema", "service",
  ], "compute-workload recipient attestation");
  if (attestation.schema !== "dnai.compute-workload-recipient-attestation.v1"
    || attestation.context !== "compute_workload"
    || attestation.audience !== "dnai-wikigen:compute-workload-recipient"
    || attestation.service !== "dnai-wikigen"
    || attestation.protocol !== "compute_workload_ingress_v1"
    || attestation.activation_signer_key_path
      !== "tinker/compute_workload_activation_signer"
    || attestation.activation_signer_custody
      !== "dstack_derived_compute_workload_activation_signer"
    || attestation.chain_id !== CHAIN_ID
    || typeof attestation.encryption_public_key !== "string"
    || !BARE_SHA256.test(attestation.encryption_public_key)) {
    throw new Error("compute-workload recipient attestation semantics are invalid");
  }
  const expectedKeyId = `sha256:${createHash("sha256")
    .update(Buffer.from(attestation.encryption_public_key, "hex"))
    .digest("hex")}`;
  if (attestation.key_id !== expectedKeyId) {
    throw new Error("compute-workload recipient key ID does not match its public key");
  }
  return {
    schema: attestation.schema,
    context: attestation.context,
    audience: attestation.audience,
    service: attestation.service,
    protocol: attestation.protocol,
    encryption_public_key: attestation.encryption_public_key,
    key_id: sha256(attestation.key_id, "compute-workload recipient key ID"),
    activation_signer_address: address(
      attestation.activation_signer_address,
      "compute-workload activation signer",
    ),
    activation_signer_key_path: attestation.activation_signer_key_path,
    activation_signer_custody: attestation.activation_signer_custody,
    chain_id: CHAIN_ID,
    compute_vault_address: address(
      attestation.compute_vault_address,
      "compute-workload ComputeCreditVault address",
    ),
    compute_vault_runtime_code_hash: bytes32(
      attestation.compute_vault_runtime_code_hash,
      "compute-workload ComputeCreditVault runtime code hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      attestation.fresh_contract_deployment_receipt_sha256,
      "compute-workload fresh contract deployment receipt digest",
    ),
  };
}

function computeWorkloadRecipientReportData(attestation) {
  return `0x${createHash("sha256")
    .update(COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN, "utf8")
    .update(compactCanonicalText(normalizeComputeWorkloadRecipientAttestation(attestation)), "ascii")
    .digest("hex")}`;
}

export function phalaComputeWorkloadRecipientReportData(attestation) {
  return computeWorkloadRecipientReportData(attestation);
}

function normalizeComputeWorkloadRecipientActivation(value) {
  const activation = exactRecord(value, [
    "app_id", "authenticated_at", "authenticated_verdict", "ceremony_nonce", "chain_id",
    "compose_hash", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "main_runtime_evidence_sha256", "measurement_policy_set_sha256",
    "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "recipient_attestation", "recipient_evidence_lease_expires_at",
    "recipient_key_id", "recipient_release_commitment",
    "release_authority_sha256", "release_policy_hash", "report_data", "schema",
    "verdict_digest", "verifier_address",
  ], "compute-workload recipient activation");
  if (activation.schema !== "dnai.compute.workload-recipient-activation.v3"
    || activation.chain_id !== CHAIN_ID || activation.domain !== "main_runtime_cvm"
    || activation.profile !== "compute_workload") {
    throw new Error("compute-workload recipient activation schema is invalid");
  }
  const issuedAt = second(activation.issued_at, "activation issued_at");
  const recipientLeaseExpiresAt = second(
    activation.recipient_evidence_lease_expires_at,
    "activation recipient evidence lease expires_at",
  );
  const expiresAt = second(activation.expires_at, "activation expires_at");
  if (recipientLeaseExpiresAt !== expiresAt || expiresAt <= issuedAt
    || expiresAt - issuedAt > 300) {
    throw new Error("compute-workload recipient evidence lease is invalid");
  }
  return {
    schema: activation.schema,
    chain_id: CHAIN_ID,
    domain: activation.domain,
    profile: activation.profile,
    cvm_id: cvmId(activation.cvm_id, "activation main runtime CVM ID"),
    deployment_intent_sha256: sha256(
      activation.deployment_intent_sha256,
      "activation deployment intent",
    ),
    release_authority_sha256: sha256(
      activation.release_authority_sha256,
      "activation release authority",
    ),
    ceremony_nonce: bytes32(activation.ceremony_nonce, "activation ceremony nonce"),
    measurement_policy_set_sha256: sha256(
      activation.measurement_policy_set_sha256,
      "activation measurement policy set",
    ),
    measurement_policy_sha256: sha256(
      activation.measurement_policy_sha256,
      "activation compute-workload QVL measurement policy",
    ),
    main_runtime_evidence_sha256: sha256(
      activation.main_runtime_evidence_sha256,
      "activation main runtime proof",
    ),
    recipient_key_id: sha256(activation.recipient_key_id, "activation recipient key ID"),
    report_data: bytes32(activation.report_data, "activation report data"),
    compose_hash: bytes32(activation.compose_hash, "activation compose hash"),
    app_id: appId(activation.app_id, "activation app ID"),
    os_image_hash: bareSha256(activation.os_image_hash, "activation OS image hash"),
    release_policy_hash: bytes32(
      activation.release_policy_hash,
      "activation release policy hash",
    ),
    quote_hash: bytes32(activation.quote_hash, "activation quote hash"),
    verifier_address: address(activation.verifier_address, "activation QVL verifier"),
    verdict_digest: bytes32(activation.verdict_digest, "activation verdict digest"),
    issued_at: issuedAt,
    recipient_evidence_lease_expires_at: recipientLeaseExpiresAt,
    expires_at: expiresAt,
    authenticated_at: second(activation.authenticated_at, "activation authenticated_at"),
    recipient_release_commitment: sha256(
      activation.recipient_release_commitment,
      "activation recipient release commitment",
    ),
    recipient_attestation: normalizeComputeWorkloadRecipientAttestation(
      activation.recipient_attestation,
    ),
    authenticated_verdict: normalizeIndependentVerdict(activation.authenticated_verdict),
  };
}

export function normalizePhalaComputeWorkloadRecipientSourceActivation(value) {
  return normalizeComputeWorkloadRecipientActivation(value);
}

export function canonicalPhalaComputeWorkloadRecipientSourceActivationText(value) {
  return canonicalText(normalizeComputeWorkloadRecipientActivation(value));
}

export function phalaComputeWorkloadRecipientSourceActivationSha256(value) {
  return domainSha256(
    COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN,
    normalizeComputeWorkloadRecipientActivation(value),
  );
}

function computeWorkloadChallengeDigestFromVerdict(verdict) {
  const payload = {
    schema: PHALA_WORKLOAD_QVL_CHALLENGE_SCHEMA,
    chain_id: CHAIN_ID,
    domain: verdict.domain,
    profile: verdict.profile,
    cvm_id: verdict.cvm_id,
    deployment_intent_sha256: verdict.deployment_intent_sha256,
    release_authority_sha256: verdict.release_authority_sha256,
    ceremony_nonce: verdict.ceremony_nonce,
    measurement_policy_sha256: verdict.measurement_policy_sha256,
    release_policy_hash: verdict.release_policy_hash,
    challenge_id: verdict.challenge_id,
    issued_at: verdict.challenge_issued_at,
    expires_at: verdict.challenge_expires_at,
    verifier_address: verdict.verifier_address,
  };
  return `0x${createHash("sha256")
    .update(QVL_CHALLENGE_DOMAIN, "utf8")
    .update(compactCanonicalText(payload), "ascii")
    .digest("hex")}`;
}

function computeWorkloadRecipientReleaseCommitment(activation) {
  const verdict = activation.authenticated_verdict;
  const payload = {
    schema: "dnai.compute.workload-recipient-release.v2",
    chain_id: CHAIN_ID,
    domain: activation.domain,
    profile: "compute_workload",
    cvm_id: activation.cvm_id,
    deployment_intent_sha256: activation.deployment_intent_sha256,
    release_authority_sha256: activation.release_authority_sha256,
    ceremony_nonce: activation.ceremony_nonce,
    measurement_policy_set_sha256: activation.measurement_policy_set_sha256,
    measurement_policy_sha256: activation.measurement_policy_sha256,
    main_runtime_evidence_sha256: activation.main_runtime_evidence_sha256,
    recipient_key_id: activation.recipient_key_id,
    report_data: activation.report_data,
    compose_hash: activation.compose_hash,
    app_id: activation.app_id,
    os_image_hash: activation.os_image_hash,
    release_policy_hash: activation.release_policy_hash,
    verifier_address: activation.verifier_address,
    verification_method: verdict.verification_method,
    signer_address: verdict.signer_address,
    contract_address: verdict.contract_address,
    recipient_attestation: activation.recipient_attestation,
  };
  return domainSha256(COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN, payload, { compact: true });
}

function normalizeComputeWorkloadRecipientActivationVerification(value) {
  const parsed = exactRecord(value, [
    "activation_artifact_sha256", "activation_signer_address", "activation_signer_custody",
    "activation_signer_key_path", "app_id", "authenticated_at", "ceremony_nonce",
    "chain_id", "challenge_digest", "challenge_expires_at", "challenge_id",
    "challenge_issued_at", "compose_hash", "compute_vault_address",
    "compute_vault_runtime_code_hash", "cvm_id", "deployment_intent_sha256",
    "descriptor_sha256", "domain", "encryption_public_key", "evidence_mode", "expires_at",
    "fresh_contract_deployment_receipt_sha256", "main_runtime_evidence_sha256",
    "initial_compute_workload_qvl_activation_evidence_lease_expires_at",
    "initial_main_runtime_activation_evidence_lease_expires_at",
    "main_runtime_signer_address", "measurement_policy_set_sha256",
    "measurement_policy_sha256", "os_image_hash", "posture_receipt_sha256", "profile",
    "qvl_identity_evidence_sha256", "qvl_release_policy_sha256",
    "qvl_verdict_artifact_sha256", "qvl_verdict_signing_digest",
    "qvl_verdict_verifier_address", "qvl_verdict_verifier_signature_sha256",
    "raw_collateral_publicly_disclosed", "raw_quote_publicly_disclosed",
    "raw_secret_egress", "raw_transcript_sha256",
    "recipient_evidence_lease_expires_at", "recipient_key_id",
    "recipient_release_commitment", "release_authority_sha256",
    "report_data", "schema", "source_activation", "status", "tdx_quote_sha256",
    "truth_status", "verdict_activation_evidence_lease_expires_at",
    "verdict_expires_at", "verdict_issued_at", "verified_at",
    "terminal_evidence_lease_expires_at",
  ], "compute-workload recipient activation verification");
  if (parsed.schema !== PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA
    || parsed.status !== PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS
    || parsed.truth_status
      !== PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH
    || parsed.chain_id !== CHAIN_ID || parsed.domain !== "main_runtime_cvm"
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false) {
    throw new Error("compute-workload recipient activation verification authority is invalid");
  }
  if (![PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE, PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE]
    .includes(parsed.evidence_mode)) {
    throw new Error("compute-workload activation evidence mode is invalid");
  }
  if (parsed.profile !== "compute_workload"
    || parsed.activation_signer_key_path !== "tinker/compute_workload_activation_signer"
    || parsed.activation_signer_custody
      !== "dstack_derived_compute_workload_activation_signer") {
    throw new Error("compute-workload activation purpose or custody is invalid");
  }
  const challengeIssued = second(parsed.challenge_issued_at, "activation challenge issued_at");
  const challengeExpires = second(parsed.challenge_expires_at, "activation challenge expires_at");
  const verdictIssued = second(parsed.verdict_issued_at, "activation verdict issued_at");
  const verdictExpires = second(parsed.verdict_expires_at, "activation verdict expires_at");
  const verdictLeaseExpires = second(
    parsed.verdict_activation_evidence_lease_expires_at,
    "activation verdict evidence lease expires_at",
  );
  const recipientLeaseExpires = second(
    parsed.recipient_evidence_lease_expires_at,
    "activation recipient evidence lease expires_at",
  );
  const initialMainRuntimeLeaseExpires = second(
    parsed.initial_main_runtime_activation_evidence_lease_expires_at,
    "activation initial main-runtime evidence lease expires_at",
  );
  const initialComputeQvlLeaseExpires = second(
    parsed.initial_compute_workload_qvl_activation_evidence_lease_expires_at,
    "activation initial compute-QVL evidence lease expires_at",
  );
  const terminalEvidenceLeaseExpires = second(
    parsed.terminal_evidence_lease_expires_at,
    "activation terminal evidence lease expires_at",
  );
  const authenticatedAt = second(parsed.authenticated_at, "activation authenticated_at");
  const verifiedAt = second(parsed.verified_at, "activation verified_at");
  const proofExpiresAt = second(parsed.expires_at, "activation proof expires_at");
  if (challengeExpires <= challengeIssued || challengeExpires - challengeIssued > 120
    || verdictIssued < challengeIssued || verdictIssued >= challengeExpires
    || verdictExpires <= verdictIssued || verdictExpires - verdictIssued > 300
    || verdictLeaseExpires !== verdictExpires
    || recipientLeaseExpires !== verdictLeaseExpires
    || authenticatedAt < verdictIssued - 30 || authenticatedAt >= verdictExpires
    || verifiedAt < authenticatedAt
    || verifiedAt >= initialMainRuntimeLeaseExpires
    || verifiedAt >= initialComputeQvlLeaseExpires
    || verifiedAt >= recipientLeaseExpires
    || terminalEvidenceLeaseExpires !== Math.min(
      initialMainRuntimeLeaseExpires,
      initialComputeQvlLeaseExpires,
      recipientLeaseExpires,
    )
    || proofExpiresAt !== terminalEvidenceLeaseExpires) {
    throw new Error("compute-workload recipient activation freshness is invalid");
  }
  const sourceActivation = normalizeComputeWorkloadRecipientActivation(parsed.source_activation);
  const activationArtifactSha = domainSha256(
    COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN,
    sourceActivation,
  );
  const verdictArtifactSha = independentTdxVerdictArtifactSha256(
    sourceActivation.authenticated_verdict,
  );
  const transcriptSha = rawVerifierTranscriptSha256(
    "main_runtime_cvm",
    "compute_workload_recipient_activation",
    [activationArtifactSha, verdictArtifactSha],
  );
  if (parsed.activation_artifact_sha256 !== activationArtifactSha
    || parsed.qvl_verdict_artifact_sha256 !== verdictArtifactSha
    || parsed.raw_transcript_sha256 !== transcriptSha) {
    throw new Error("compute-workload source activation transcript commitment drifted");
  }
  const sourceVerdict = sourceActivation.authenticated_verdict;
  const sourceAttestation = sourceActivation.recipient_attestation;
  if (sourceActivation.release_authority_sha256 !== parsed.release_authority_sha256
    || sourceActivation.deployment_intent_sha256 !== parsed.deployment_intent_sha256
    || sourceActivation.ceremony_nonce !== parsed.ceremony_nonce
    || sourceActivation.measurement_policy_set_sha256
      !== parsed.measurement_policy_set_sha256
    || sourceActivation.measurement_policy_sha256 !== parsed.measurement_policy_sha256
    || sourceActivation.main_runtime_evidence_sha256 !== parsed.main_runtime_evidence_sha256
    || sourceActivation.cvm_id !== parsed.cvm_id || sourceActivation.app_id !== parsed.app_id
    || sourceActivation.compose_hash
      !== bytes32FromBare(parsed.compose_hash, "activation source compose hash")
    || sourceActivation.os_image_hash !== parsed.os_image_hash
    || sourceActivation.recipient_key_id !== parsed.recipient_key_id
    || sourceActivation.report_data !== parsed.report_data
    || sourceActivation.recipient_release_commitment
      !== parsed.recipient_release_commitment
    || sourceVerdict.signer_address !== parsed.activation_signer_address
    || sourceVerdict.verifier_address !== parsed.qvl_verdict_verifier_address
    || sourceAttestation.compute_vault_address !== parsed.compute_vault_address
    || sourceAttestation.compute_vault_runtime_code_hash
      !== parsed.compute_vault_runtime_code_hash
    || sourceAttestation.fresh_contract_deployment_receipt_sha256
      !== parsed.fresh_contract_deployment_receipt_sha256
    || sourceVerdict.issued_at !== verdictIssued
    || sourceVerdict.activation_evidence_lease_expires_at !== verdictLeaseExpires
    || sourceVerdict.expires_at !== verdictExpires
    || sourceActivation.recipient_evidence_lease_expires_at !== recipientLeaseExpires
    || sourceActivation.authenticated_at !== authenticatedAt) {
    throw new Error("compute-workload source activation differs from projected O fields");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    evidence_mode: parsed.evidence_mode,
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: parsed.profile,
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      "activation release authority digest",
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "activation deployment intent",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "activation ceremony nonce"),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      "activation measurement policy set",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "activation compute-workload QVL measurement policy",
    ),
    descriptor_sha256: sha256(parsed.descriptor_sha256, "activation main descriptor"),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      "activation main posture receipt",
    ),
    qvl_identity_evidence_sha256: sha256(
      parsed.qvl_identity_evidence_sha256,
      "compute-workload QVL identity digest",
    ),
    app_id: appId(parsed.app_id, "activation main runtime app ID"),
    cvm_id: cvmId(parsed.cvm_id, "activation main runtime CVM ID"),
    compose_hash: bareSha256(parsed.compose_hash, "activation main runtime compose hash"),
    os_image_hash: bareSha256(parsed.os_image_hash, "activation main runtime OS image hash"),
    encryption_public_key: bareSha256(
      parsed.encryption_public_key,
      "activation recipient public key",
    ),
    recipient_key_id: sha256(parsed.recipient_key_id, "activation recipient key ID"),
    activation_signer_address: address(
      parsed.activation_signer_address,
      "activation signer address",
    ),
    activation_signer_key_path: parsed.activation_signer_key_path,
    activation_signer_custody: parsed.activation_signer_custody,
    main_runtime_signer_address: address(
      parsed.main_runtime_signer_address,
      "main runtime signer address",
    ),
    main_runtime_evidence_sha256: sha256(
      parsed.main_runtime_evidence_sha256,
      "activation main runtime evidence",
    ),
    initial_main_runtime_activation_evidence_lease_expires_at:
      initialMainRuntimeLeaseExpires,
    initial_compute_workload_qvl_activation_evidence_lease_expires_at:
      initialComputeQvlLeaseExpires,
    compute_vault_address: address(parsed.compute_vault_address, "activation vault address"),
    compute_vault_runtime_code_hash: bytes32(
      parsed.compute_vault_runtime_code_hash,
      "activation vault runtime code hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      parsed.fresh_contract_deployment_receipt_sha256,
      "activation fresh deployment receipt digest",
    ),
    report_data: bytes32(parsed.report_data, "activation report data"),
    recipient_release_commitment: sha256(
      parsed.recipient_release_commitment,
      "activation recipient release commitment",
    ),
    qvl_release_policy_sha256: sha256(
      parsed.qvl_release_policy_sha256,
      "activation QVL release policy digest",
    ),
    qvl_verdict_verifier_address: address(
      parsed.qvl_verdict_verifier_address,
      "activation QVL verifier address",
    ),
    challenge_id: bytes32(parsed.challenge_id, "activation challenge ID"),
    challenge_digest: bytes32(parsed.challenge_digest, "activation challenge digest"),
    challenge_issued_at: challengeIssued,
    challenge_expires_at: challengeExpires,
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, "activation quote digest"),
    qvl_verdict_signing_digest: bytes32(
      parsed.qvl_verdict_signing_digest,
      "activation verdict signing digest",
    ),
    qvl_verdict_artifact_sha256: verdictArtifactSha,
    qvl_verdict_verifier_signature_sha256: sha256(
      parsed.qvl_verdict_verifier_signature_sha256,
      "activation verdict signature digest",
    ),
    activation_artifact_sha256: activationArtifactSha,
    raw_transcript_sha256: transcriptSha,
    source_activation: sourceActivation,
    verdict_issued_at: verdictIssued,
    verdict_activation_evidence_lease_expires_at: verdictLeaseExpires,
    verdict_expires_at: verdictExpires,
    recipient_evidence_lease_expires_at: recipientLeaseExpires,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpires,
    authenticated_at: authenticatedAt,
    verified_at: verifiedAt,
    expires_at: proofExpiresAt,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

export function verifyPhalaComputeWorkloadRecipientActivation({
  activation: activationValue,
  releaseAuthority: releaseAuthorityValue,
  qvlIdentityEvidence,
  mainRuntimeEvidence,
  challengeLedger,
  minimumAuthenticatedAt,
  testOnlyNow,
} = {}) {
  const releaseAuthority = assertReleaseVerificationAuthorityForEvidence(
    releaseAuthorityValue,
  );
  const computeQvl = assertVerifiedPhalaQvlIdentityLaunchEvidence(qvlIdentityEvidence);
  const mainProof = assertVerifiedPhalaWorkloadTdxVerdict(mainRuntimeEvidence);
  const activation = normalizeComputeWorkloadRecipientActivation(activationValue);
  const authenticatedAtNotBefore = minimumAuthenticatedAt === undefined
    ? undefined
    : second(
      minimumAuthenticatedAt,
      "compute-workload recipient activation minimum authenticated_at",
    );
  if (authenticatedAtNotBefore !== undefined
    && activation.authenticated_at < authenticatedAtNotBefore) {
    throw new Error(
      "compute-workload recipient activation predates its required runtime authority",
    );
  }
  if (computeQvl.domain !== "compute_workload_qvl_cvm"
    || computeQvl.profile !== "compute_workload") {
    throw new Error("recipient activation is not linked to the dedicated compute-workload QVL");
  }
  if (mainProof.domain !== "main_runtime_cvm" || mainProof.profile !== "diligence") {
    throw new Error("recipient activation requires the branded main-runtime diligence proof");
  }
  const releaseAuthoritySha = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const mainDescriptor = releaseDescriptor(releaseAuthority, "main_runtime_cvm");
  const mainProofSha = phalaWorkloadTdxVerdictVerificationSha256(mainProof);
  for (const proof of [computeQvl, mainProof]) {
    if (proof.release_authority_sha256 !== releaseAuthoritySha
      || proof.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
      || proof.ceremony_nonce !== releaseAuthority.ceremony_nonce
      || proof.measurement_policy_set_sha256
        !== releaseAuthority.qvl_measurement_policy_set_sha256) {
      throw new Error("recipient activation proof belongs to another release ceremony");
    }
  }
  const attestation = activation.recipient_attestation;
  const verdict = activation.authenticated_verdict;
  const expectedReportData = computeWorkloadRecipientReportData(attestation);
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const challengeDigest = computeWorkloadChallengeDigestFromVerdict(verdict);
  const releaseCommitment = computeWorkloadRecipientReleaseCommitment(activation);
  const checked = activationLeaseSecond(
    releaseAuthority,
    testOnlyNow,
    "compute-workload recipient activation verification",
  );
  const lineage = {
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: mainDescriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256: releaseAuthoritySha,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: computeQvl.measurement_policy_sha256,
  };
  if (Object.entries(lineage).some(([field, expectedValue]) =>
    activation[field] !== expectedValue || verdict[field] !== expectedValue)
    || activation.measurement_policy_set_sha256
      !== releaseAuthority.qvl_measurement_policy_set_sha256
    || activation.main_runtime_evidence_sha256 !== mainProofSha
    || verdict.release_policy_hash
      !== bytes32FromSha(computeQvl.release_policy_sha256, "compute-workload QVL policy")
    || verdict.verifier_address !== computeQvl.tee_identity
    || verdict.app_id !== mainDescriptor.app_id
    || verdict.compose_hash !== bytes32FromBare(mainDescriptor.compose_hash, "main runtime compose")
    || verdict.os_image_hash !== mainDescriptor.os_image_hash
    || verdict.signer_address !== attestation.activation_signer_address
    || verdict.signer_address === computeQvl.tee_identity
    || verdict.signer_address === mainProof.tee_identity
    || verdict.contract_address !== attestation.compute_vault_address
    || verdict.contract_address !== releaseAuthority.contracts.compute_credit_vault
    || attestation.compute_vault_runtime_code_hash
      !== releaseAuthority.contracts.compute_credit_vault_runtime_code_hash
    || attestation.fresh_contract_deployment_receipt_sha256
      !== bytes32FromSha(
        releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
        "fresh deployment receipt",
      )
    || activation.recipient_key_id !== attestation.key_id
    || activation.report_data !== expectedReportData
    || verdict.report_data !== expectedReportData
    || activation.compose_hash !== verdict.compose_hash
    || activation.app_id !== verdict.app_id
    || activation.os_image_hash !== verdict.os_image_hash
    || activation.release_policy_hash !== verdict.release_policy_hash
    || activation.quote_hash !== verdict.quote_hash
    || activation.verifier_address !== verdict.verifier_address
    || activation.verdict_digest !== signingDigest
    || activation.issued_at !== verdict.issued_at
    || activation.recipient_evidence_lease_expires_at
      !== verdict.activation_evidence_lease_expires_at
    || activation.expires_at !== verdict.expires_at
    || activation.recipient_release_commitment !== releaseCommitment
    || verdict.challenge_digest !== challengeDigest) {
    throw new Error("compute-workload activation drifted from QVL, main runtime, recipient, or fresh vault authority");
  }
  if (verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at > 300
    || activation.authenticated_at < verdict.issued_at - 30
    || activation.authenticated_at >= verdict.expires_at
    || checked < activation.authenticated_at || checked >= verdict.expires_at
    || checked >= computeQvl.activation_evidence_lease_expires_at
    || checked >= mainProof.activation_evidence_lease_expires_at) {
    throw new Error(
      "compute-workload activation is expired or outside its recipient evidence lease",
    );
  }
  const signatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest: signingDigest,
    signature: verdict.verifier_signature,
  });
  const activationArtifactSha = domainSha256(
    COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN,
    activation,
  );
  const verdictArtifactSha = independentTdxVerdictArtifactSha256(verdict);
  const candidate = {
    schema: PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA,
    status: PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS,
    truth_status:
      PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH,
    evidence_mode: computeQvl.evidence_mode,
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: computeQvl.measurement_policy_sha256,
    descriptor_sha256: mainDescriptor.descriptor_sha256,
    posture_receipt_sha256: mainDescriptor.posture_receipt_sha256,
    qvl_identity_evidence_sha256: phalaQvlIdentityLaunchEvidenceSha256(computeQvl),
    main_runtime_evidence_sha256: mainProofSha,
    initial_main_runtime_activation_evidence_lease_expires_at:
      mainProof.activation_evidence_lease_expires_at,
    initial_compute_workload_qvl_activation_evidence_lease_expires_at:
      computeQvl.activation_evidence_lease_expires_at,
    app_id: mainDescriptor.app_id,
    cvm_id: mainDescriptor.cvm_id,
    compose_hash: mainDescriptor.compose_hash,
    os_image_hash: mainDescriptor.os_image_hash,
    encryption_public_key: attestation.encryption_public_key,
    recipient_key_id: attestation.key_id,
    activation_signer_address: attestation.activation_signer_address,
    activation_signer_key_path: attestation.activation_signer_key_path,
    activation_signer_custody: attestation.activation_signer_custody,
    main_runtime_signer_address: mainProof.tee_identity,
    compute_vault_address: attestation.compute_vault_address,
    compute_vault_runtime_code_hash: attestation.compute_vault_runtime_code_hash,
    fresh_contract_deployment_receipt_sha256:
      attestation.fresh_contract_deployment_receipt_sha256,
    report_data: expectedReportData,
    recipient_release_commitment: releaseCommitment,
    qvl_release_policy_sha256: computeQvl.release_policy_sha256,
    qvl_verdict_verifier_address: verdict.verifier_address,
    challenge_id: verdict.challenge_id,
    challenge_digest: verdict.challenge_digest,
    challenge_issued_at: verdict.challenge_issued_at,
    challenge_expires_at: verdict.challenge_expires_at,
    tdx_quote_sha256: shaFromBytes32(verdict.quote_hash, "compute-workload quote hash"),
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: verdictArtifactSha,
    qvl_verdict_verifier_signature_sha256: signatureReceipt.signature_sha256,
    activation_artifact_sha256: activationArtifactSha,
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      "main_runtime_cvm",
      "compute_workload_recipient_activation",
      [activationArtifactSha, verdictArtifactSha],
    ),
    source_activation: activation,
    verdict_issued_at: verdict.issued_at,
    verdict_activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    verdict_expires_at: verdict.expires_at,
    recipient_evidence_lease_expires_at:
      activation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at: Math.min(
      mainProof.activation_evidence_lease_expires_at,
      computeQvl.activation_evidence_lease_expires_at,
      activation.recipient_evidence_lease_expires_at,
    ),
    authenticated_at: activation.authenticated_at,
    verified_at: checked,
    expires_at: Math.min(
      mainProof.activation_evidence_lease_expires_at,
      computeQvl.activation_evidence_lease_expires_at,
      activation.recipient_evidence_lease_expires_at,
    ),
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizeComputeWorkloadRecipientActivationVerification(candidate),
    { label: "verified compute-workload recipient activation" },
  );
  VERIFIED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS.set(
    normalized,
    domainSha256(
      PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN,
      normalized,
    ),
  );
  consumeReleaseScopedChallenge(
    challengeLedger,
    releaseAuthority,
    "main_runtime_cvm",
    verdict.challenge_id,
  );
  return normalized;
}

export function phalaComputeWorkloadRecipientActivationVerificationSha256(value) {
  return domainSha256(
    PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN,
    normalizeComputeWorkloadRecipientActivationVerification(value),
  );
}

export function canonicalPhalaComputeWorkloadRecipientActivationVerificationText(value) {
  return canonicalText(normalizeComputeWorkloadRecipientActivationVerification(value));
}

export function assertVerifiedPhalaComputeWorkloadRecipientActivation(value) {
  const expected = VERIFIED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS.get(value);
  if (!expected
    || phalaComputeWorkloadRecipientActivationVerificationSha256(value) !== expected) {
    throw new Error("compute-workload recipient activation was not signature-verified in this process");
  }
  return value;
}

export function assertProductionPhalaComputeWorkloadRecipientActivation(value) {
  const verified = assertVerifiedPhalaComputeWorkloadRecipientActivation(value);
  if (verified.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("synthetic compute-workload activation can never authorize a live ceremony");
  }
  if (Math.floor(Date.now() / 1_000)
      >= verified.terminal_evidence_lease_expires_at) {
    throw new Error("compute-workload activation has expired and cannot mint fresh O");
  }
  return verified;
}

export function assertHistoricallyVerifiedProductionPhalaComputeWorkloadRecipientActivation(
  value,
) {
  const expected = VERIFIED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS.get(value)
    || HISTORICALLY_REPLAYED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS.get(value);
  if (!expected
    || phalaComputeWorkloadRecipientActivationVerificationSha256(value) !== expected) {
    throw new Error(
      "compute-workload activation lacks a verified live or restart-safe historical brand",
    );
  }
  const verified = value;
  if (verified.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("synthetic activation has no production historical authority");
  }
  return verified;
}

export function replayPersistedHistoricalPhalaComputeWorkloadRecipientActivation({
  activation: persistedActivation,
  releaseAuthority: releaseAuthorityValue,
  qvlIdentityEvidence,
  mainRuntimeEvidence,
} = {}) {
  const { authority: releaseAuthority } =
    resolveHistoricalReplayReleaseAuthority(releaseAuthorityValue);
  const computeQvl = assertHistoricallyReplayedPhalaQvlIdentity(qvlIdentityEvidence);
  const mainProof = assertHistoricallyReplayedPhalaWorkloadVerdict(mainRuntimeEvidence);
  const persisted = normalizeComputeWorkloadRecipientActivationVerification(
    persistedActivation,
  );
  const activation = persisted.source_activation;
  if (computeQvl.domain !== "compute_workload_qvl_cvm"
    || computeQvl.profile !== "compute_workload"
    || mainProof.domain !== "main_runtime_cvm" || mainProof.profile !== "diligence") {
    throw new Error(
      "historical recipient activation is not linked to its exact replayed QVL/main proofs",
    );
  }
  const releaseAuthoritySha =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const mainDescriptor = releaseDescriptorFromAssertedAuthority(
    releaseAuthority,
    "main_runtime_cvm",
  );
  const mainProofSha = phalaWorkloadTdxVerdictVerificationSha256(mainProof);
  for (const proof of [computeQvl, mainProof]) {
    if (proof.release_authority_sha256 !== releaseAuthoritySha
      || proof.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
      || proof.ceremony_nonce !== releaseAuthority.ceremony_nonce
      || proof.measurement_policy_set_sha256
        !== releaseAuthority.qvl_measurement_policy_set_sha256) {
      throw new Error("historical recipient activation proof belongs to another release");
    }
  }
  const attestation = activation.recipient_attestation;
  const verdict = activation.authenticated_verdict;
  const expectedReportData = computeWorkloadRecipientReportData(attestation);
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const challengeDigest = computeWorkloadChallengeDigestFromVerdict(verdict);
  const releaseCommitment = computeWorkloadRecipientReleaseCommitment(activation);
  const checked = persisted.verified_at;
  const lineage = {
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: mainDescriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256: releaseAuthoritySha,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: computeQvl.measurement_policy_sha256,
  };
  if (Object.entries(lineage).some(([field, expectedValue]) =>
    activation[field] !== expectedValue || verdict[field] !== expectedValue)
    || activation.measurement_policy_set_sha256
      !== releaseAuthority.qvl_measurement_policy_set_sha256
    || activation.main_runtime_evidence_sha256 !== mainProofSha
    || verdict.release_policy_hash
      !== bytes32FromSha(computeQvl.release_policy_sha256, "historical compute QVL policy")
    || verdict.verifier_address !== computeQvl.tee_identity
    || verdict.app_id !== mainDescriptor.app_id
    || verdict.compose_hash
      !== bytes32FromBare(mainDescriptor.compose_hash, "historical main compose")
    || verdict.os_image_hash !== mainDescriptor.os_image_hash
    || verdict.signer_address !== attestation.activation_signer_address
    || verdict.signer_address === computeQvl.tee_identity
    || verdict.signer_address === mainProof.tee_identity
    || verdict.contract_address !== attestation.compute_vault_address
    || verdict.contract_address !== releaseAuthority.contracts.compute_credit_vault
    || attestation.compute_vault_runtime_code_hash
      !== releaseAuthority.contracts.compute_credit_vault_runtime_code_hash
    || attestation.fresh_contract_deployment_receipt_sha256
      !== bytes32FromSha(
        releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
        "historical fresh deployment receipt",
      )
    || activation.recipient_key_id !== attestation.key_id
    || activation.report_data !== expectedReportData || verdict.report_data !== expectedReportData
    || activation.compose_hash !== verdict.compose_hash || activation.app_id !== verdict.app_id
    || activation.os_image_hash !== verdict.os_image_hash
    || activation.release_policy_hash !== verdict.release_policy_hash
    || activation.quote_hash !== verdict.quote_hash
    || activation.verifier_address !== verdict.verifier_address
    || activation.verdict_digest !== signingDigest
    || activation.issued_at !== verdict.issued_at
    || activation.recipient_evidence_lease_expires_at
      !== verdict.activation_evidence_lease_expires_at
    || activation.expires_at !== verdict.expires_at
    || activation.recipient_release_commitment !== releaseCommitment
    || verdict.challenge_digest !== challengeDigest) {
    throw new Error("historical compute-workload activation lineage or report data drifted");
  }
  const terminalEvidenceLeaseExpiresAt = Math.min(
    mainProof.activation_evidence_lease_expires_at,
    computeQvl.activation_evidence_lease_expires_at,
    activation.recipient_evidence_lease_expires_at,
  );
  if (verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at > 300
    || activation.authenticated_at < verdict.issued_at - 30
    || activation.authenticated_at >= verdict.expires_at
    || checked < activation.authenticated_at || checked >= verdict.expires_at
    || checked >= computeQvl.activation_evidence_lease_expires_at
    || checked >= mainProof.activation_evidence_lease_expires_at
    || persisted.terminal_evidence_lease_expires_at !== terminalEvidenceLeaseExpiresAt) {
    throw new Error(
      "historical compute-workload activation was invalid at recorded verification time",
    );
  }
  const signatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest: signingDigest,
    signature: verdict.verifier_signature,
  });
  const activationArtifactSha = domainSha256(
    COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN,
    activation,
  );
  const verdictArtifactSha = independentTdxVerdictArtifactSha256(verdict);
  const candidate = {
    schema: PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA,
    status: PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS,
    truth_status: PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH,
    evidence_mode: computeQvl.evidence_mode,
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: computeQvl.measurement_policy_sha256,
    descriptor_sha256: mainDescriptor.descriptor_sha256,
    posture_receipt_sha256: mainDescriptor.posture_receipt_sha256,
    qvl_identity_evidence_sha256: phalaQvlIdentityLaunchEvidenceSha256(computeQvl),
    main_runtime_evidence_sha256: mainProofSha,
    initial_main_runtime_activation_evidence_lease_expires_at:
      mainProof.activation_evidence_lease_expires_at,
    initial_compute_workload_qvl_activation_evidence_lease_expires_at:
      computeQvl.activation_evidence_lease_expires_at,
    app_id: mainDescriptor.app_id,
    cvm_id: mainDescriptor.cvm_id,
    compose_hash: mainDescriptor.compose_hash,
    os_image_hash: mainDescriptor.os_image_hash,
    encryption_public_key: attestation.encryption_public_key,
    recipient_key_id: attestation.key_id,
    activation_signer_address: attestation.activation_signer_address,
    activation_signer_key_path: attestation.activation_signer_key_path,
    activation_signer_custody: attestation.activation_signer_custody,
    main_runtime_signer_address: mainProof.tee_identity,
    compute_vault_address: attestation.compute_vault_address,
    compute_vault_runtime_code_hash: attestation.compute_vault_runtime_code_hash,
    fresh_contract_deployment_receipt_sha256:
      attestation.fresh_contract_deployment_receipt_sha256,
    report_data: expectedReportData,
    recipient_release_commitment: releaseCommitment,
    qvl_release_policy_sha256: computeQvl.release_policy_sha256,
    qvl_verdict_verifier_address: verdict.verifier_address,
    challenge_id: verdict.challenge_id,
    challenge_digest: verdict.challenge_digest,
    challenge_issued_at: verdict.challenge_issued_at,
    challenge_expires_at: verdict.challenge_expires_at,
    tdx_quote_sha256: shaFromBytes32(verdict.quote_hash, "historical activation quote hash"),
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: verdictArtifactSha,
    qvl_verdict_verifier_signature_sha256: signatureReceipt.signature_sha256,
    activation_artifact_sha256: activationArtifactSha,
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      "main_runtime_cvm",
      "compute_workload_recipient_activation",
      [activationArtifactSha, verdictArtifactSha],
    ),
    source_activation: activation,
    verdict_issued_at: verdict.issued_at,
    verdict_activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    verdict_expires_at: verdict.expires_at,
    recipient_evidence_lease_expires_at:
      activation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpiresAt,
    authenticated_at: activation.authenticated_at,
    verified_at: checked,
    expires_at: terminalEvidenceLeaseExpiresAt,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const reconstructed = normalizeComputeWorkloadRecipientActivationVerification(candidate);
  if (canonicalText(reconstructed) !== canonicalText(persisted)) {
    throw new Error(
      "persisted compute-workload activation differs from historical reconstruction",
    );
  }
  const normalized = deepFreezeCanonicalPlainDataGraph(reconstructed, {
    label: "historically replayed compute-workload recipient activation",
  });
  HISTORICALLY_REPLAYED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS.set(
    normalized,
    domainSha256(
      PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN,
      normalized,
    ),
  );
  return normalized;
}

export function normalizePhalaComputeWorkloadRecipientActivationVerification(value) {
  return normalizeComputeWorkloadRecipientActivationVerification(value);
}

function projectDomainEvidence(proof) {
  const isIdentity = Object.hasOwn(PHALA_QVL_IDENTITY_DOMAIN_PROFILE, proof.domain);
  const proofSha = isIdentity
    ? phalaQvlIdentityLaunchEvidenceSha256(proof)
    : phalaWorkloadTdxVerdictVerificationSha256(proof);
  const transcriptFiles = isIdentity
    ? [
      proof.identity_attestation_request_file_sha256,
      proof.identity_attestation_response_file_sha256,
    ]
    : [proof.qvl_challenge_file_sha256, proof.qvl_verdict_file_sha256];
  const transcriptFileSizes = isIdentity
    ? [
      proof.identity_attestation_request_file_size,
      proof.identity_attestation_response_file_size,
    ]
    : [proof.qvl_challenge_file_size, proof.qvl_verdict_file_size];
  return {
    domain: proof.domain,
    evidence_kind: isIdentity
      ? "qvl_identity_local_dcap_verification"
      : "workload_independent_signed_qvl_verdict",
    evidence_sha256: proofSha,
    release_authority_sha256: proof.release_authority_sha256,
    deployment_intent_sha256: proof.deployment_intent_sha256,
    ceremony_nonce: proof.ceremony_nonce,
    measurement_policy_set_sha256: proof.measurement_policy_set_sha256,
    measurement_policy_sha256: proof.measurement_policy_sha256,
    descriptor_sha256: proof.descriptor_sha256,
    posture_receipt_sha256: proof.posture_receipt_sha256,
    app_id: proof.app_id,
    cvm_id: proof.cvm_id,
    compose_hash: proof.compose_hash,
    os_image_hash: proof.os_image_hash,
    tee_identity: proof.tee_identity,
    contract_address: isIdentity ? null : proof.contract_address,
    tdx_quote_sha256: proof.tdx_quote_sha256,
    tdx_measurements_sha256: isIdentity ? proof.tdx_measurements_sha256 : null,
    tdx_measurement_policy_sha256: proof.measurement_policy_sha256,
    tdx_attestation_evidence_sha256: isIdentity
      ? proof.identity_attestation_response_sha256
      : proof.qvl_verdict_artifact_sha256,
    tdx_attestation_verification_receipt_sha256: proofSha,
    qvl_release_policy_sha256: isIdentity
      ? proof.release_policy_sha256
      : proof.qvl_release_policy_sha256,
    qvl_verification_receipt_sha256: proofSha,
    qvl_identity_sha256: isIdentity ? proofSha : proof.qvl_identity_evidence_sha256,
    raw_transcript_file_sha256: transcriptFiles,
    raw_transcript_file_size: transcriptFileSizes,
    raw_transcript_sha256: proof.raw_transcript_sha256,
    verified_at: proof.verified_at,
    activation_evidence_lease_expires_at:
      proof.activation_evidence_lease_expires_at,
    expires_at: proof.expires_at,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

function normalizeDomainProjection(value, expectedDomain) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "app_id", "compose_hash",
    "contract_address", "cvm_id", "domain", "evidence_kind",
    "evidence_sha256", "expires_at", "os_image_hash", "qvl_identity_sha256",
    "qvl_release_policy_sha256", "qvl_verification_receipt_sha256",
    "private_historical_transcript_required", "raw_collateral_publicly_disclosed",
    "raw_quote_publicly_disclosed", "raw_secret_egress",
    "tdx_attestation_evidence_sha256",
    "tdx_attestation_verification_receipt_sha256", "tdx_measurement_policy_sha256",
    "tdx_measurements_sha256", "tdx_quote_sha256", "tee_identity", "verified_at",
    "ceremony_nonce", "deployment_intent_sha256", "descriptor_sha256",
    "measurement_policy_set_sha256", "measurement_policy_sha256",
    "posture_receipt_sha256", "raw_transcript_file_sha256", "raw_transcript_sha256",
    "raw_transcript_file_size",
    "release_authority_sha256",
  ], `${expectedDomain} seven-CVM evidence projection`);
  const identity = Object.hasOwn(PHALA_QVL_IDENTITY_DOMAIN_PROFILE, expectedDomain);
  if (parsed.domain !== expectedDomain
    || parsed.evidence_kind !== (identity
      ? "qvl_identity_local_dcap_verification"
      : "workload_independent_signed_qvl_verdict")
    || parsed.private_historical_transcript_required !== true
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false
    || (identity ? parsed.contract_address !== null : !ADDRESS.test(parsed.contract_address || ""))
    || (identity ? typeof parsed.tdx_measurements_sha256 !== "string"
      : parsed.tdx_measurements_sha256 !== null)) {
    throw new Error(`${expectedDomain} seven-CVM evidence projection is invalid`);
  }
  const normalized = {
    domain: expectedDomain,
    evidence_kind: parsed.evidence_kind,
    evidence_sha256: sha256(parsed.evidence_sha256, `${expectedDomain} evidence digest`),
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      `${expectedDomain} release authority`,
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      `${expectedDomain} deployment intent`,
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, `${expectedDomain} ceremony nonce`),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      `${expectedDomain} measurement policy set`,
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      `${expectedDomain} measurement policy`,
    ),
    descriptor_sha256: sha256(parsed.descriptor_sha256, `${expectedDomain} descriptor`),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      `${expectedDomain} posture receipt`,
    ),
    app_id: appId(parsed.app_id, `${expectedDomain} app ID`),
    cvm_id: cvmId(parsed.cvm_id, `${expectedDomain} CVM ID`),
    compose_hash: bareSha256(parsed.compose_hash, `${expectedDomain} compose hash`),
    os_image_hash: bareSha256(parsed.os_image_hash, `${expectedDomain} OS image hash`),
    tee_identity: address(parsed.tee_identity, `${expectedDomain} TEE identity`),
    contract_address: identity
      ? null
      : address(parsed.contract_address, `${expectedDomain} bound contract address`),
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, `${expectedDomain} quote digest`),
    tdx_measurements_sha256: identity
      ? sha256(parsed.tdx_measurements_sha256, `${expectedDomain} measurements digest`)
      : null,
    tdx_measurement_policy_sha256: sha256(
      parsed.tdx_measurement_policy_sha256,
      `${expectedDomain} measurement policy authority`,
    ),
    tdx_attestation_evidence_sha256: sha256(
      parsed.tdx_attestation_evidence_sha256,
      `${expectedDomain} attestation evidence`,
    ),
    tdx_attestation_verification_receipt_sha256: sha256(
      parsed.tdx_attestation_verification_receipt_sha256,
      `${expectedDomain} attestation verification receipt`,
    ),
    qvl_release_policy_sha256: sha256(
      parsed.qvl_release_policy_sha256,
      `${expectedDomain} QVL policy`,
    ),
    qvl_verification_receipt_sha256: sha256(
      parsed.qvl_verification_receipt_sha256,
      `${expectedDomain} QVL verification receipt`,
    ),
    qvl_identity_sha256: sha256(
      parsed.qvl_identity_sha256,
      `${expectedDomain} QVL identity`,
    ),
    raw_transcript_file_sha256: (() => {
      if (!Array.isArray(parsed.raw_transcript_file_sha256)
        || parsed.raw_transcript_file_sha256.length !== 2) {
        throw new Error(`${expectedDomain} raw transcript must contain exactly two files`);
      }
      const files = parsed.raw_transcript_file_sha256.map((digest, index) =>
        sha256(digest, `${expectedDomain} raw transcript file[${index}]`));
      if (files[0] === files[1]) {
        throw new Error(`${expectedDomain} raw transcript files must be distinct`);
      }
      return files;
    })(),
    raw_transcript_file_size: (() => {
      if (!Array.isArray(parsed.raw_transcript_file_size)
        || parsed.raw_transcript_file_size.length !== 2) {
        throw new Error(`${expectedDomain} raw transcript must contain exactly two file sizes`);
      }
      return parsed.raw_transcript_file_size.map((fileSize, index) =>
        rawArtifactFileSize(
          fileSize,
          `${expectedDomain} raw transcript file size[${index}]`,
          MAX_HISTORICAL_TRANSCRIPT_FILE_BYTES,
        ));
    })(),
    raw_transcript_sha256: sha256(
      parsed.raw_transcript_sha256,
      `${expectedDomain} raw transcript commitment`,
    ),
    verified_at: second(parsed.verified_at, `${expectedDomain} verified_at`),
    activation_evidence_lease_expires_at: second(
      parsed.activation_evidence_lease_expires_at,
      `${expectedDomain} activation evidence lease expires_at`,
    ),
    expires_at: second(parsed.expires_at, `${expectedDomain} expires_at`),
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const expectedTranscriptSha = rawVerifierTranscriptSha256(
    expectedDomain,
    identity ? "qvl_identity_request_response" : "workload_challenge_verdict",
    normalized.raw_transcript_file_sha256,
  );
  if (normalized.raw_transcript_sha256 !== expectedTranscriptSha
    || normalized.tdx_measurement_policy_sha256 !== normalized.measurement_policy_sha256
    || normalized.activation_evidence_lease_expires_at !== normalized.expires_at
    || normalized.verified_at >= normalized.activation_evidence_lease_expires_at) {
    throw new Error(`${expectedDomain} transcript, measurement policy, or expiry drifted`);
  }
  return normalized;
}

function historicalTranscriptFileSetFromDomains(domains) {
  const rawIdentityByFlag = {};
  for (const projection of domains) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[projection.domain];
    const orderedFlags = Object.values(flags);
    if (orderedFlags.length !== 2) {
      throw new Error(`${projection.domain} raw transcript flag mapping is invalid`);
    }
    orderedFlags.forEach((flag, index) => {
      rawIdentityByFlag[flag] = {
        sha256: projection.raw_transcript_file_sha256[index],
        size: projection.raw_transcript_file_size[index],
      };
    });
  }
  if (JSON.stringify(Object.keys(rawIdentityByFlag).sort())
      !== JSON.stringify([...PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER].sort())) {
    throw new Error("seven-CVM raw transcript flag set is incomplete");
  }
  return createPhalaSevenCvmHistoricalTranscriptFileSet(rawIdentityByFlag);
}

/**
 * Export the exact fourteen canonical verifier envelopes retained by the same
 * in-process production verification operations that minted the supplied
 * proof objects. Raw texts are private WeakMap provenance: they are not
 * accepted from the caller and normalized or copied proof objects cannot
 * acquire them. The complete byte set is rehashed against the branded
 * production aggregate before any transcript text is returned.
 */
export function exportPhalaSevenCvmHistoricalTranscriptFiles(options = {}) {
  assertCanonicalPlainDataGraph(options, {
    label: "production seven-CVM historical transcript export input",
  });
  const parsed = exactRecord(options, [
    "qvlIdentityEvidence",
    "verifiedEvidenceSet",
    "workloadVerdictEvidence",
  ], "production seven-CVM historical transcript export input");
  const evidenceSet = assertProductionPhalaSevenCvmEvidenceSet(
    parsed.verifiedEvidenceSet,
  );
  if (!Array.isArray(parsed.qvlIdentityEvidence)
    || parsed.qvlIdentityEvidence.length !== 5
    || !Array.isArray(parsed.workloadVerdictEvidence)
    || parsed.workloadVerdictEvidence.length !== 2) {
    throw new Error(
      "production transcript export requires five QVL identities and two workload verdicts",
    );
  }

  const proofByDomain = new Map();
  const textByFlag = new Map();
  for (const candidate of parsed.qvlIdentityEvidence) {
    const proof = assertVerifiedPhalaQvlIdentityLaunchEvidence(candidate);
    if (proof.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
      throw new Error("synthetic QVL identity evidence cannot export production transcripts");
    }
    const retained = LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF.get(proof);
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[proof.domain];
    if (!retained || retained.length !== 2 || !flags?.request || !flags?.response
      || proofByDomain.has(proof.domain)) {
      throw new Error(
        "QVL identity transcript provenance is missing, duplicated, or unavailable",
      );
    }
    proofByDomain.set(proof.domain, proof);
    for (const entry of retained) {
      if (entry.flag !== flags.request && entry.flag !== flags.response) {
        throw new Error(`${proof.domain} retained historical envelope flag drifted`);
      }
      parseHistoricalTranscriptEnvelopeText(entry.text, entry.flag);
      textByFlag.set(entry.flag, entry.text);
    }
  }
  for (const candidate of parsed.workloadVerdictEvidence) {
    const proof = assertVerifiedPhalaWorkloadTdxVerdict(candidate);
    if (proof.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
      throw new Error("synthetic workload evidence cannot export production transcripts");
    }
    const retained = LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF.get(proof);
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[proof.domain];
    if (!retained || retained.length !== 2 || !flags?.challenge || !flags?.verdict
      || proofByDomain.has(proof.domain)) {
      throw new Error(
        "workload transcript provenance is missing, duplicated, or unavailable",
      );
    }
    proofByDomain.set(proof.domain, proof);
    for (const entry of retained) {
      if (entry.flag !== flags.challenge && entry.flag !== flags.verdict) {
        throw new Error(`${proof.domain} retained historical envelope flag drifted`);
      }
      parseHistoricalTranscriptEnvelopeText(entry.text, entry.flag);
      textByFlag.set(entry.flag, entry.text);
    }
  }
  if (proofByDomain.size !== PHALA_SEVEN_CVM_EXECUTION_ORDER.length
    || textByFlag.size !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length) {
    throw new Error("production transcript export omitted or substituted a CVM domain");
  }

  for (const projection of evidenceSet.domains) {
    const proof = proofByDomain.get(projection.domain);
    if (!proof) {
      throw new Error(
        `${projection.domain} transcript proof differs from the production aggregate`,
      );
    }
    const identity = Object.hasOwn(
      PHALA_QVL_IDENTITY_DOMAIN_PROFILE,
      projection.domain,
    );
    const proofSha256 = identity
      ? phalaQvlIdentityLaunchEvidenceSha256(proof)
      : phalaWorkloadTdxVerdictVerificationSha256(proof);
    const flags = Object.values(
      PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[projection.domain],
    );
    if (projection.evidence_sha256 !== proofSha256 || flags.length !== 2) {
      throw new Error(
        `${projection.domain} transcript proof differs from the production aggregate`,
      );
    }
  }

  const entries = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
    (flag) => ({ flag, text: textByFlag.get(flag) }),
  );
  const totalBytes = entries.reduce(
    (total, entry) => total + Buffer.byteLength(entry.text, "utf8"),
    0,
  );
  if (totalBytes > MAX_HISTORICAL_TRANSCRIPT_SET_BYTES) {
    throw new Error("production historical transcript export exceeds the byte budget");
  }
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
    entries,
  );
  if (phalaSevenCvmHistoricalTranscriptFileSetSha256(fileSet)
      !== evidenceSet.historical_transcript_file_set_sha256) {
    throw new Error(
      "exported exact-14 verifier bytes differ from the production aggregate",
    );
  }
  const exportedEntries = deepFreezeCanonicalPlainDataGraph(entries, {
    label: "production seven-CVM historical transcript export",
  });
  consumePhalaSevenCvmHistoricalTranscriptCapabilities(
    LIVE_HISTORICAL_TRANSCRIPTS_BY_PROOF,
    PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) => proofByDomain.get(domain)),
  );
  return exportedEntries;
}

function parseExactPhalaSevenCvmHistoricalTranscriptFiles(value) {
  if (!Array.isArray(value)
    || value.length !== PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.length) {
    throw new Error("historical replay requires exactly 14 transcript files");
  }
  let totalBytes = 0;
  const files = value.map((entry, index) => {
    const file = exactRecord(
      entry,
      ["flag", "text"],
      `historical transcript file[${index}]`,
    );
    const expectedFlag = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER[index];
    if (file.flag !== expectedFlag) {
      throw new Error(
        "historical transcript files are omitted, extra, reordered, or substituted",
      );
    }
    totalBytes += Buffer.byteLength(
      typeof file.text === "string" ? file.text : "",
      "utf8",
    );
    return parseHistoricalTranscriptEnvelopeText(file.text, expectedFlag);
  });
  if (totalBytes > MAX_HISTORICAL_TRANSCRIPT_SET_BYTES) {
    throw new Error("historical transcript set exceeds its exact aggregate byte bound");
  }
  if (new Set(files.map(({ transcript_file_sha256: digest }) => digest)).size !== 14) {
    throw new Error("historical transcript files must have pairwise-distinct exact bytes");
  }
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(value);
  const postureAudits = files
    .filter((file) => file.verification_record !== null)
    .map((file) => ({
      domain: file.domain,
      expectedAuthority: file.verification_record.posture_expected_authority,
      receipt: file.verification_record.production_posture_receipt,
      receiptSha256: file.verification_record.production_posture_receipt_sha256,
    }));
  if (postureAudits.length !== PHALA_SEVEN_CVM_EXECUTION_ORDER.length) {
    throw new Error("exact 14-file transcript set omits a second-envelope posture audit");
  }
  return {
    files,
    byFlag: new Map(files.map((file) => [file.flag, file])),
    fileSet,
    postureAudits,
  };
}

function resolveHistoricalReplayReleaseAuthority(value) {
  const normalized =
    normalizeLegacyPhalaSevenCvmReleaseVerificationAuthority(value);
  if (normalized.evidence_mode === PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    return Object.freeze({
      authority: normalized,
      metadata: null,
    });
  }
  const authority =
    assertHistoricallyReconstructedPhalaSevenCvmReleaseVerificationAuthority(
      value,
    );
  return Object.freeze({
    authority,
    metadata:
      historicallyReconstructedPhalaSevenCvmReleaseVerificationAuthorityMetadata(
        authority,
      ),
  });
}

export function reconstructPersistedPhalaSevenCvmHistoricalCorroboration({
  releaseAuthority: releaseAuthorityValue,
  historicalPostureAudits,
  executorFinalState,
} = {}) {
  const { authority: releaseAuthority, metadata } =
    resolveHistoricalReplayReleaseAuthority(releaseAuthorityValue);
  const executorOrder = [
    ...PHALA_SEVEN_CVM_EXECUTION_ORDER.slice(1),
    PHALA_SEVEN_CVM_EXECUTION_ORDER[0],
  ];
  if (!Array.isArray(historicalPostureAudits)
    || historicalPostureAudits.length !== executorOrder.length) {
    throw new Error(
      "historical replay requires exactly seven transcript-embedded posture audits",
    );
  }
  const rawPostureByDomain = new Map(historicalPostureAudits.map((audit) => [
    audit?.domain,
    audit,
  ]));
  if (rawPostureByDomain.size !== executorOrder.length
    || executorOrder.some((domain) => !rawPostureByDomain.has(domain))) {
    throw new Error(
      "historical transcript posture audits are omitted, duplicated, or cross-domain",
    );
  }
  const postureByDomain = new Map();
  const normalizedPostures = executorOrder.map((expectedDomain) => {
    const descriptor = releaseDescriptorFromAssertedAuthority(
      releaseAuthority,
      expectedDomain,
    );
    const audit = rawPostureByDomain.get(expectedDomain);
    const normalized = normalizeHistoricalPostureAudit({
      evidenceMode: releaseAuthority.evidence_mode,
      domain: expectedDomain,
      expectedAuthority: audit.expectedAuthority,
      receipt: audit.receipt,
      receiptSha256: audit.receiptSha256,
      releaseDescriptor: descriptor,
    });
    postureByDomain.set(expectedDomain, normalized);
    return normalized.receipt;
  });
  const executor = normalizeCompletedPhalaExecutorState(executorFinalState);
  if (canonicalText(executor) !== canonicalText(executorFinalState)) {
    throw new Error("persisted executor terminal state is not already exact and normalized");
  }
  const executorSha256 = phalaExecutorStateDigest(executor);
  const releaseAuthoritySha =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  if ((metadata !== null
      && executorSha256 !== metadata.executor_final_state_sha256)
    || executor.release_sha !== releaseAuthority.release_sha
    || executor.bootstrap_authorization_receipt_sha256
      !== releaseAuthority.bootstrap_authorization_receipt_sha256
    || bytes32FromSha(executor.bootstrap_authorization_id, "executor authorization ID")
      !== releaseAuthority.ceremony_nonce
    || executor.reservations.length !== 7 || executor.committed_prefix.length !== 7
    || executor.posture_receipts.length !== 7) {
    throw new Error("persisted executor terminal state belongs to another release authority");
  }
  for (let index = 0; index < executorOrder.length; index += 1) {
    const domain = executorOrder[index];
    const descriptor = releaseDescriptorFromAssertedAuthority(releaseAuthority, domain);
    const posture = postureByDomain.get(domain);
    const reservation = executor.reservations[index];
    const committed = executor.committed_prefix[index];
    const executorPosture = executor.posture_receipts[index];
    if (reservation.domain !== domain || committed.domain !== domain
      || executorPosture.domain !== domain || reservation.app_id !== descriptor.app_id
      || committed.cvm_id !== descriptor.cvm_id
      || executorPosture.receipt_sha256 !== posture.receiptSha256
      || Math.floor(Date.parse(committed.observed_at) / 1_000)
        > Math.floor(Date.parse(descriptor.posture_observed_at) / 1_000)) {
      throw new Error(`${domain} persisted executor/posture lineage is invalid`);
    }
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_CORROBORATION_SCHEMA,
    status: "actual_seven_posture_receipts_and_terminal_executor_state_revalidated",
    evidence_mode: releaseAuthority.evidence_mode,
    release_authority_sha256: releaseAuthoritySha,
    executor_final_state_sha256: executorSha256,
    executor_final_state: executor,
    posture_receipts: normalizedPostures,
    posture_receipt_sha256_by_domain: Object.fromEntries(
      PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) => [
        domain,
        postureByDomain.get(domain).receiptSha256,
      ]),
    ),
    raw_secret_egress: false,
  }, { label: "historically reconstructed seven-CVM posture/executor corroboration" });
}

async function replayHistoricalQvlIdentityPair({
  releaseAuthority,
  requestFile,
  responseFile,
  testOnlyVerifyQuote,
}) {
  const domain = requestFile.domain;
  if (responseFile.domain !== domain || requestFile.role !== "request"
    || responseFile.role !== "response") {
    throw new Error("historical QVL identity transcript pair is cross-domain or reordered");
  }
  const descriptor = releaseDescriptorFromAssertedAuthority(releaseAuthority, domain);
  const policy = releaseMeasurementPolicyFromAssertedAuthority(releaseAuthority, domain);
  const policySha = phalaQvlMeasurementPolicySha256(policy);
  const releaseAuthoritySha =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const evidenceMode = releaseAuthority.evidence_mode;
  if ((evidenceMode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE)
      !== (testOnlyVerifyQuote === undefined)) {
    throw new Error("historical production and synthetic DCAP verifier authority cannot be mixed");
  }
  if (testOnlyVerifyQuote !== undefined) {
    assertSyntheticDcapAdapter(testOnlyVerifyQuote);
  }
  const request = requestFile.artifact;
  const response = responseFile.artifact;
  if (request.challenge_digest !== phalaQvlIdentityChallengeDigest(request)) {
    throw new Error("historical QVL identity challenge digest is invalid");
  }
  const expectedLineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: PHALA_QVL_IDENTITY_DOMAIN_PROFILE[domain],
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    release_authority_sha256: releaseAuthoritySha,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: policySha,
    app_id: descriptor.app_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
  };
  for (const [field, expectedValue] of Object.entries(expectedLineage)) {
    if (request[field] !== expectedValue || response[field] !== expectedValue) {
      throw new Error(`historical QVL identity ${field} drifted from release authority`);
    }
  }
  for (const [requestField, responseField] of [
    ["challenge_id", "challenge_id"],
    ["challenge_digest", "challenge_digest"],
    ["issued_at", "challenge_issued_at"],
    ["expires_at", "challenge_expires_at"],
  ]) {
    if (request[requestField] !== response[responseField]) {
      throw new Error("historical QVL identity response is not bound to its exact challenge");
    }
  }
  const expectedReportData = qvlIdentityReportData({
    request,
    verifierAddress: response.verifier_address,
    releasePolicyHash: response.release_policy_hash,
  });
  if (response.report_data !== expectedReportData
    || response.quote_report_data !== `${expectedReportData}${request.challenge_digest.slice(2)}`) {
    throw new Error("historical QVL identity report data is not release/challenge bound");
  }
  const rawQuote = Buffer.from(response.quote.slice(2), "hex");
  const quoteSha = `sha256:${createHash("sha256").update(rawQuote).digest("hex")}`;
  if (quoteSha !== shaFromBytes32(response.quote_hash, `${domain} historical quote hash`)) {
    throw new Error("historical QVL identity quote digest drifted");
  }
  const replayRecord = normalizeHistoricalDcapReplayRecord(
    responseFile.verification_record,
    {
      expectedDomain: domain,
      releaseAuthority,
    },
  );
  const verifiedAt = replayRecord.verification_time;
  const verifierOutput = testOnlyVerifyQuote === undefined
    ? verifyPinnedSevenCvmLocalDcapQuoteAt(rawQuote, policy, verifiedAt, replayRecord)
    : await testOnlyVerifyQuote(rawQuote, policy, replayRecord);
  const splitLocal = splitLocalDcapVerifierOutput(verifierOutput, {
    evidenceMode,
    verifiedAt,
    domain,
  });
  if (splitLocal.replay.collateral_sha256 !== replayRecord.collateral_sha256) {
    throw new Error("historical DCAP replay used collateral other than the persisted exact bytes");
  }
  const local = normalizeLocalDcapResult(splitLocal.result, {
    verifiedAt,
    evidenceMode,
    quoteSha256: quoteSha,
    measurementPolicy: policy,
  });
  const localReceiptSha = domainSha256(LOCAL_DCAP_RECEIPT_DOMAIN, local);
  normalizeHistoricalDcapReplayRecord(replayRecord, {
    expectedVerifiedAt: verifiedAt,
    expectedLeaseExpiresAt: replayRecord.activation_evidence_lease_expires_at,
    expectedLocalReceiptSha256: localReceiptSha,
    expectedDomain: domain,
    releaseAuthority,
  });
  if (quoteSha !== local.tdx_quote_sha256 || local.report_data !== response.quote_report_data
    || verifiedAt < request.issued_at || verifiedAt >= request.expires_at) {
    throw new Error("historical QVL identity evidence was not valid at recorded verification time");
  }
  const candidate = {
    schema: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA,
    status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS,
    truth_status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH,
    evidence_mode: evidenceMode,
    chain_id: CHAIN_ID,
    domain,
    profile: expectedLineage.profile,
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: policySha,
    measurement_policy: policy,
    descriptor_sha256: descriptor.descriptor_sha256,
    posture_receipt_sha256: descriptor.posture_receipt_sha256,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    tee_identity: response.verifier_address,
    release_policy_sha256: shaFromBytes32(
      response.release_policy_hash,
      `${domain} historical QVL release policy`,
    ),
    challenge_id: request.challenge_id,
    challenge_digest: request.challenge_digest,
    challenge_issued_at: request.issued_at,
    challenge_expires_at: request.expires_at,
    tdx_quote_sha256: quoteSha,
    tdx_measurements_sha256: local.measurements_sha256,
    identity_attestation_request_sha256: requestFile.artifact_sha256,
    identity_attestation_response_sha256: responseFile.artifact_sha256,
    identity_attestation_request_file_sha256: requestFile.transcript_file_sha256,
    identity_attestation_request_file_size: Buffer.byteLength(
      requestFile.transcript_text,
      "utf8",
    ),
    identity_attestation_response_file_sha256: responseFile.transcript_file_sha256,
    identity_attestation_response_file_size: Buffer.byteLength(
      responseFile.transcript_text,
      "utf8",
    ),
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      domain,
      "qvl_identity_request_response",
      [requestFile.transcript_file_sha256, responseFile.transcript_file_sha256],
    ),
    local_dcap_verification: local,
    local_dcap_verification_receipt_sha256: localReceiptSha,
    verified_at: verifiedAt,
    activation_evidence_lease_seconds:
      releaseAuthority.activation_evidence_lease_seconds,
    activation_evidence_lease_issued_at:
      replayRecord.activation_evidence_lease_issued_at,
    activation_evidence_lease_expires_at:
      replayRecord.activation_evidence_lease_expires_at,
    expires_at: replayRecord.activation_evidence_lease_expires_at,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizeQvlIdentityVerification(candidate),
    { label: `${domain} historically replayed QVL identity evidence` },
  );
  HISTORICALLY_REPLAYED_QVL_IDENTITIES.set(
    normalized,
    domainSha256(PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN, normalized),
  );
  return normalized;
}

function assertHistoricallyReplayedPhalaQvlIdentity(value) {
  const expected = HISTORICALLY_REPLAYED_QVL_IDENTITIES.get(value);
  if (!expected || phalaQvlIdentityLaunchEvidenceSha256(value) !== expected) {
    throw new Error("QVL identity lacks a restart-safe historical transcript replay brand");
  }
  return value;
}

function replayHistoricalWorkloadPair({
  releaseAuthority,
  challengeFile,
  verdictFile,
  expected,
  qvlIdentityEvidence,
}) {
  const domain = challengeFile.domain;
  if (verdictFile.domain !== domain || challengeFile.role !== "challenge"
    || verdictFile.role !== "verdict") {
    throw new Error("historical workload transcript pair is cross-domain or reordered");
  }
  const linked = assertHistoricallyReplayedPhalaQvlIdentity(qvlIdentityEvidence);
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
  if (!link || linked.domain !== link.qvl_domain) {
    throw new Error("historical workload verdict is not linked to its exact replayed QVL");
  }
  const releaseAuthoritySha =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  if (linked.release_authority_sha256 !== releaseAuthoritySha
    || linked.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
    || linked.ceremony_nonce !== releaseAuthority.ceremony_nonce
    || linked.measurement_policy_set_sha256
      !== releaseAuthority.qvl_measurement_policy_set_sha256) {
    throw new Error("historical workload-linked QVL identity is cross-release");
  }
  const authority = normalizeWorkloadExpectedFromAssertedAuthority(
    expected,
    domain,
    linked,
    releaseAuthority,
  );
  const challenge = challengeFile.artifact;
  const verdict = verdictFile.artifact;
  const replayRecord = normalizeHistoricalSignatureReplayRecord(
    verdictFile.verification_record,
    {
      expectedDomain: domain,
      releaseAuthority,
    },
  );
  const binding = replayRecord.report_data_binding;
  if (canonicalText(binding) !== canonicalText(authority.report_data_binding)) {
    throw new Error("historical workload report-data binding drifted from replay record");
  }
  const expectedReportData = domain === "main_runtime_cvm"
    ? diligenceReportData({
      teeIdentity: verdict.signer_address,
      contractAddress: authority.contract_address,
    })
    : computeMeteringReportData({
      teeIdentity: verdict.signer_address,
      contractAddress: authority.contract_address,
      policySetHash: binding.policy_set_hash,
    });
  const lineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: authority.profile,
    cvm_id: authority.cvm_id,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    release_authority_sha256: authority.release_authority_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_sha256: authority.measurement_policy_sha256,
  };
  if (Object.entries(lineage).some(([field, expectedValue]) =>
    challenge[field] !== expectedValue || verdict[field] !== expectedValue)
    || challenge.release_policy_hash
      !== bytes32FromSha(authority.release_policy_sha256, "historical challenge policy")
    || challenge.verifier_address !== authority.verifier_address
    || challenge.challenge_id !== verdict.challenge_id
    || challenge.challenge_digest !== verdict.challenge_digest
    || challenge.issued_at !== verdict.challenge_issued_at
    || challenge.expires_at !== verdict.challenge_expires_at
    || verdict.app_id !== authority.app_id
    || verdict.compose_hash
      !== bytes32FromBare(authority.compose_hash, "historical workload compose")
    || verdict.os_image_hash !== authority.os_image_hash
    || verdict.signer_address === authority.verifier_address
    || verdict.contract_address !== authority.contract_address
    || verdict.verifier_address !== authority.verifier_address
    || shaFromBytes32(verdict.release_policy_hash, "historical verdict policy")
      !== authority.release_policy_sha256
    || verdict.report_data !== expectedReportData) {
    throw new Error("historical signed workload verdict drifted from release authority");
  }
  const challengeDigest = qvlChallengeSigningDigest(challenge);
  if (challenge.challenge_digest !== challengeDigest) {
    throw new Error("historical workload challenge digest is invalid");
  }
  const challengeSignatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: challenge.verifier_address,
    digest: challengeDigest,
    signature: challenge.verifier_signature,
  });
  const verifiedAt = replayRecord.verification_time;
  const activationEvidenceLeaseExpiresAt = Math.min(
    verdict.activation_evidence_lease_expires_at,
    linked.activation_evidence_lease_expires_at,
  );
  if (replayRecord.verdict_activation_evidence_lease_expires_at
      !== verdict.activation_evidence_lease_expires_at
    || replayRecord.activation_evidence_lease_expires_at
      !== activationEvidenceLeaseExpiresAt
    || verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at
      > releaseAuthority.activation_evidence_lease_seconds
    || verdict.expires_at !== verdict.activation_evidence_lease_expires_at
    || verifiedAt < verdict.issued_at
    || verifiedAt >= activationEvidenceLeaseExpiresAt) {
    throw new Error("historical workload verdict was invalid at recorded verification time");
  }
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const signatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest: signingDigest,
    signature: verdict.verifier_signature,
  });
  const candidate = {
    schema: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA,
    status: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS,
    truth_status: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_TRUTH,
    evidence_mode: linked.evidence_mode,
    chain_id: CHAIN_ID,
    domain,
    profile: authority.profile,
    release_authority_sha256: authority.release_authority_sha256,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_set_sha256: authority.measurement_policy_set_sha256,
    measurement_policy_sha256: authority.measurement_policy_sha256,
    descriptor_sha256: authority.descriptor_sha256,
    posture_receipt_sha256: authority.posture_receipt_sha256,
    app_id: authority.app_id,
    cvm_id: authority.cvm_id,
    compose_hash: authority.compose_hash,
    os_image_hash: authority.os_image_hash,
    tee_identity: verdict.signer_address,
    contract_address: authority.contract_address,
    report_data_binding: binding,
    report_data: verdict.report_data,
    qvl_release_policy_sha256: authority.release_policy_sha256,
    qvl_identity_evidence_sha256: authority.qvl_identity_evidence_sha256,
    qvl_challenge_signing_digest: challengeDigest,
    qvl_challenge_artifact_sha256: challengeFile.artifact_sha256,
    qvl_challenge_file_sha256: challengeFile.transcript_file_sha256,
    qvl_challenge_file_size: Buffer.byteLength(challengeFile.transcript_text, "utf8"),
    qvl_challenge_verifier_signature_sha256:
      challengeSignatureReceipt.signature_sha256,
    challenge_id: verdict.challenge_id,
    challenge_digest: verdict.challenge_digest,
    challenge_issued_at: verdict.challenge_issued_at,
    challenge_expires_at: verdict.challenge_expires_at,
    tdx_quote_sha256: shaFromBytes32(verdict.quote_hash, "historical workload quote hash"),
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: verdictFile.artifact_sha256,
    qvl_verdict_file_sha256: verdictFile.transcript_file_sha256,
    qvl_verdict_file_size: Buffer.byteLength(verdictFile.transcript_text, "utf8"),
    raw_transcript_sha256: rawVerifierTranscriptSha256(
      domain,
      "workload_challenge_verdict",
      [challengeFile.transcript_file_sha256, verdictFile.transcript_file_sha256],
    ),
    qvl_verdict_verifier_address: verdict.verifier_address,
    qvl_verdict_verifier_signature_sha256: signatureReceipt.signature_sha256,
    verdict_issued_at: verdict.issued_at,
    verdict_activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    verdict_expires_at: verdict.expires_at,
    verified_at: verifiedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    expires_at: activationEvidenceLeaseExpiresAt,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(
    normalizeWorkloadVerification(candidate),
    { label: `${domain} historically replayed workload verdict` },
  );
  HISTORICALLY_REPLAYED_WORKLOAD_VERDICTS.set(
    normalized,
    domainSha256(PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN, normalized),
  );
  return normalized;
}

function assertHistoricallyReplayedPhalaWorkloadVerdict(value) {
  const expected = HISTORICALLY_REPLAYED_WORKLOAD_VERDICTS.get(value);
  if (!expected || phalaWorkloadTdxVerdictVerificationSha256(value) !== expected) {
    throw new Error("workload verdict lacks a restart-safe historical transcript replay brand");
  }
  return value;
}

function normalizeSevenCvmSet(value) {
  if (isRecord(value)
    && value.schema === REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA) {
    throw new Error("the retired six-CVM evidence schema is explicitly revoked");
  }
  const parsed = exactRecord(value, [
    "all_seven_machine_verified", "chain_id", "domains", "evidence_mode",
    "execution_order", "private_historical_transcript_required",
    "raw_collateral_publicly_disclosed", "raw_quote_publicly_disclosed",
    "raw_secret_egress", "schema",
    "status", "truth_status", "verified_at", "release_authority_sha256",
    "release_sha", "deployment_intent_sha256", "ceremony_nonce",
    "measurement_policy_set_sha256", "historical_transcript_file_set_sha256",
    "issued_at", "first_verified_at", "last_verified_at",
    "minimum_activation_evidence_lease_expires_at",
    "proof_collection_skew_seconds", "proofs_valid_at_issuance",
  ], "seven-CVM verified evidence set");
  if (parsed.schema !== PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA
    || parsed.status !== PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS
    || parsed.truth_status !== PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH
    || parsed.chain_id !== CHAIN_ID || parsed.all_seven_machine_verified !== true
    || parsed.private_historical_transcript_required !== true
    || parsed.raw_quote_publicly_disclosed !== false
    || parsed.raw_collateral_publicly_disclosed !== false
    || parsed.raw_secret_egress !== false
    || JSON.stringify(parsed.execution_order) !== JSON.stringify(PHALA_SEVEN_CVM_EXECUTION_ORDER)
    || !Array.isArray(parsed.domains) || parsed.domains.length !== 7) {
    throw new Error("seven-CVM verified evidence set authority is invalid");
  }
  const domains = parsed.domains.map((entry, index) =>
    normalizeDomainProjection(entry, PHALA_SEVEN_CVM_EXECUTION_ORDER[index]));
  for (const field of ["app_id", "cvm_id", "compose_hash", "tee_identity", "evidence_sha256"]) {
    if (new Set(domains.map((entry) => entry[field])).size !== 7) {
      throw new Error(`seven-CVM ${field} values must be pairwise distinct`);
    }
  }
  const firstVerifiedAt = Math.min(...domains.map((entry) => entry.verified_at));
  const lastVerifiedAt = Math.max(...domains.map((entry) => entry.verified_at));
  const minimumActivationEvidenceLeaseExpiresAt = Math.min(
    ...domains.map((entry) => entry.activation_evidence_lease_expires_at),
  );
  const issuedAt = second(parsed.issued_at, "seven-CVM evidence issued_at");
  const skew = lastVerifiedAt - firstVerifiedAt;
  const common = {
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      "seven-CVM release authority",
    ),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "seven-CVM deployment intent",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "seven-CVM ceremony nonce"),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      "seven-CVM measurement policy set",
    ),
  };
  if (domains.some((entry) => Object.entries(common).some(
    ([field, expected]) => entry[field] !== expected,
  ))
    || parsed.first_verified_at !== firstVerifiedAt
    || parsed.last_verified_at !== lastVerifiedAt
    || parsed.verified_at !== lastVerifiedAt
    || parsed.minimum_activation_evidence_lease_expires_at
      !== minimumActivationEvidenceLeaseExpiresAt
    || parsed.proof_collection_skew_seconds !== skew
    || parsed.proofs_valid_at_issuance !== true
    || skew > PHALA_SEVEN_CVM_MAX_COLLECTION_SKEW_SECONDS
    || issuedAt < lastVerifiedAt
    || issuedAt >= minimumActivationEvidenceLeaseExpiresAt
    || parsed.historical_transcript_file_set_sha256
      !== phalaSevenCvmHistoricalTranscriptFileSetSha256(
        historicalTranscriptFileSetFromDomains(domains),
      )) {
    throw new Error("seven-CVM evidence lineage, transcript, issuance, skew, or expiry is invalid");
  }
  if (![PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE, PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE]
    .includes(parsed.evidence_mode)) {
    throw new Error("seven-CVM evidence mode is invalid");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    evidence_mode: parsed.evidence_mode,
    chain_id: CHAIN_ID,
    release_sha: (() => {
      if (typeof parsed.release_sha !== "string" || !/^[0-9a-f]{40}$/.test(parsed.release_sha)) {
        throw new Error("seven-CVM release SHA is invalid");
      }
      return parsed.release_sha;
    })(),
    ...common,
    execution_order: [...PHALA_SEVEN_CVM_EXECUTION_ORDER],
    domains,
    historical_transcript_file_set_sha256: parsed.historical_transcript_file_set_sha256,
    issued_at: issuedAt,
    first_verified_at: firstVerifiedAt,
    last_verified_at: lastVerifiedAt,
    minimum_activation_evidence_lease_expires_at:
      minimumActivationEvidenceLeaseExpiresAt,
    proof_collection_skew_seconds: skew,
    proofs_valid_at_issuance: true,
    verified_at: lastVerifiedAt,
    all_seven_machine_verified: true,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
}

export async function replayPersistedHistoricalPhalaSevenCvmEvidence({
  releaseAuthority: releaseAuthorityValue,
  rawTranscriptFiles,
  executorFinalState,
  persistedEvidenceSet,
  testOnlyHistoricalReplayCommitments,
  testOnlyVerifyQuote,
} = {}) {
  const {
    authority: releaseAuthority,
    metadata: historicalAuthorityMetadata,
  } = resolveHistoricalReplayReleaseAuthority(releaseAuthorityValue);
  if (releaseAuthority.evidence_mode === PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    if (testOnlyVerifyQuote !== undefined
      || testOnlyHistoricalReplayCommitments !== undefined) {
      throw new Error(
        "production historical replay cannot inject a DCAP verifier or commitments",
      );
    }
  } else {
    assertSyntheticDcapAdapter(testOnlyVerifyQuote);
  }
  const replayCommitments = historicalAuthorityMetadata ?? (() => {
    const parsed = exactRecord(testOnlyHistoricalReplayCommitments, [
      "executor_final_state_sha256",
      "historical_transcript_file_set_sha256",
      "seven_cvm_verified_evidence_set_sha256",
    ], "synthetic historical replay commitments");
    return Object.freeze({
      executor_final_state_sha256: sha256(
        parsed.executor_final_state_sha256,
        "synthetic historical executor final state",
      ),
      historical_transcript_file_set_sha256: sha256(
        parsed.historical_transcript_file_set_sha256,
        "synthetic historical transcript file set",
      ),
      seven_cvm_verified_evidence_set_sha256: sha256(
        parsed.seven_cvm_verified_evidence_set_sha256,
        "synthetic historical evidence set",
      ),
    });
  })();
  const persisted = persistedEvidenceSet === undefined
    ? null
    : normalizeSevenCvmSet(persistedEvidenceSet);
  if (persisted !== null) {
    if (canonicalText(persisted) !== canonicalText(persistedEvidenceSet)) {
      throw new Error("persisted seven-CVM evidence set is not already exact and normalized");
    }
    if (phalaSevenCvmVerifiedEvidenceSetSha256(persisted)
        !== replayCommitments.seven_cvm_verified_evidence_set_sha256) {
      throw new Error(
        "persisted seven-CVM evidence set drifted from reconstructed release authority metadata",
      );
    }
  }
  const transcript = parseExactPhalaSevenCvmHistoricalTranscriptFiles(rawTranscriptFiles);
  const transcriptFileSetSha256 =
    phalaSevenCvmHistoricalTranscriptFileSetSha256(transcript.fileSet);
  if (transcriptFileSetSha256
      !== replayCommitments.historical_transcript_file_set_sha256
    || (persisted !== null
      && transcriptFileSetSha256
        !== persisted.historical_transcript_file_set_sha256)) {
    throw new Error(
      "historical transcript file set drifted from persisted evidence and release authority",
    );
  }
  const normalizedExecutorFinalState = normalizeCompletedPhalaExecutorState(
    executorFinalState,
  );
  if (canonicalText(normalizedExecutorFinalState) !== canonicalText(executorFinalState)) {
    throw new Error("persisted executor terminal state is not already exact and normalized");
  }
  if (phalaExecutorStateDigest(normalizedExecutorFinalState)
      !== replayCommitments.executor_final_state_sha256) {
    throw new Error(
      "historical executor terminal state drifted from reconstructed release authority",
    );
  }
  const corroboration = reconstructPersistedPhalaSevenCvmHistoricalCorroboration({
    releaseAuthority,
    historicalPostureAudits: transcript.postureAudits,
    executorFinalState: normalizedExecutorFinalState,
  });
  const qvlIdentityEvidence = [];
  for (const domain of Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE)) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[domain];
    qvlIdentityEvidence.push(await replayHistoricalQvlIdentityPair({
      releaseAuthority,
      requestFile: transcript.byFlag.get(flags.request),
      responseFile: transcript.byFlag.get(flags.response),
      testOnlyVerifyQuote,
    }));
  }
  const qvlByDomain = new Map(
    qvlIdentityEvidence.map((proof) => [proof.domain, proof]),
  );
  const workloadVerdictEvidence = [];
  for (const domain of Object.keys(PHALA_WORKLOAD_DOMAIN_QVL_LINK)) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[domain];
    const linkedDomain = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain].qvl_domain;
    const verdictFile = transcript.byFlag.get(flags.verdict);
    workloadVerdictEvidence.push(replayHistoricalWorkloadPair({
      releaseAuthority,
      challengeFile: transcript.byFlag.get(flags.challenge),
      verdictFile,
      expected: {
        reportDataBinding: verdictFile.verification_record.report_data_binding,
      },
      qvlIdentityEvidence: qvlByDomain.get(linkedDomain),
    }));
  }
  const allProofs = PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) =>
    qvlIdentityEvidence.find((proof) => proof.domain === domain)
      || workloadVerdictEvidence.find((proof) => proof.domain === domain));
  if (allProofs.some((proof) => !proof)) {
    throw new Error("historical replay omitted a seven-CVM proof domain");
  }
  const challengeIds = allProofs.map(({ challenge_id: challengeId }) => challengeId);
  if (new Set(challengeIds).size !== challengeIds.length) {
    throw new Error("historical replay contains a cross-domain challenge replay");
  }
  const modes = new Set(allProofs.map(({ evidence_mode: mode }) => mode));
  if (modes.size !== 1 || !modes.has(releaseAuthority.evidence_mode)) {
    throw new Error("historical replay mixed production and synthetic verifier evidence");
  }
  const domains = allProofs.map(projectDomainEvidence);
  const releaseAuthoritySha =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  for (let index = 0; index < domains.length; index += 1) {
    const projection = domains[index];
    const descriptor = releaseAuthority.descriptors[index];
    const postureSecond = Math.floor(Date.parse(descriptor.posture_observed_at) / 1_000);
    if (projection.release_authority_sha256 !== releaseAuthoritySha
      || projection.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
      || projection.ceremony_nonce !== releaseAuthority.ceremony_nonce
      || projection.measurement_policy_set_sha256
        !== releaseAuthority.qvl_measurement_policy_set_sha256
      || projection.descriptor_sha256 !== descriptor.descriptor_sha256
      || projection.posture_receipt_sha256 !== descriptor.posture_receipt_sha256
      || projection.app_id !== descriptor.app_id || projection.cvm_id !== descriptor.cvm_id
      || projection.compose_hash !== descriptor.compose_hash
      || projection.os_image_hash !== descriptor.os_image_hash
      || projection.verified_at < postureSecond) {
      throw new Error(`${projection.domain} historical proof/posture/release lineage is invalid`);
    }
  }
  for (const [workloadDomain, { qvl_domain: qvlDomain }] of
    Object.entries(PHALA_WORKLOAD_DOMAIN_QVL_LINK)) {
    const workload = domains.find((entry) => entry.domain === workloadDomain);
    const qvl = domains.find((entry) => entry.domain === qvlDomain);
    if (workload.qvl_identity_sha256 !== qvl.evidence_sha256) {
      throw new Error(`${workloadDomain} historical proof does not chain to ${qvlDomain}`);
    }
  }
  const firstVerifiedAt = Math.min(...allProofs.map((proof) => proof.verified_at));
  const lastVerifiedAt = Math.max(...allProofs.map((proof) => proof.verified_at));
  const minimumActivationEvidenceLeaseExpiresAt = Math.min(
    ...allProofs.map((proof) => proof.activation_evidence_lease_expires_at),
  );
  const candidateForIssuedAt = (issuedAt) => normalizeSevenCvmSet({
    schema: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
    status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS,
    truth_status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH,
    evidence_mode: releaseAuthority.evidence_mode,
    chain_id: CHAIN_ID,
    release_sha: releaseAuthority.release_sha,
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    execution_order: [...PHALA_SEVEN_CVM_EXECUTION_ORDER],
    domains,
    historical_transcript_file_set_sha256: transcriptFileSetSha256,
    issued_at: issuedAt,
    first_verified_at: firstVerifiedAt,
    last_verified_at: lastVerifiedAt,
    minimum_activation_evidence_lease_expires_at:
      minimumActivationEvidenceLeaseExpiresAt,
    proof_collection_skew_seconds: lastVerifiedAt - firstVerifiedAt,
    proofs_valid_at_issuance: true,
    verified_at: lastVerifiedAt,
    all_seven_machine_verified: true,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  });
  let reconstructed;
  if (persisted !== null) {
    reconstructed = candidateForIssuedAt(persisted.issued_at);
    if (canonicalText(reconstructed) !== canonicalText(persisted)) {
      throw new Error(
        "persisted seven-CVM evidence set differs from exact historical reconstruction",
      );
    }
  } else {
    const matchingCandidates = [];
    for (let issuedAt = lastVerifiedAt;
      issuedAt < minimumActivationEvidenceLeaseExpiresAt;
      issuedAt += 1) {
      const candidate = candidateForIssuedAt(issuedAt);
      if (phalaSevenCvmVerifiedEvidenceSetSha256(candidate)
          === replayCommitments.seven_cvm_verified_evidence_set_sha256) {
        matchingCandidates.push(candidate);
      }
    }
    if (matchingCandidates.length !== 1) {
      throw new Error(
        "release authority does not select exactly one historical evidence-set issuance second",
      );
    }
    [reconstructed] = matchingCandidates;
  }
  const evidenceSet = deepFreezeCanonicalPlainDataGraph(reconstructed, {
    label: "historically replayed seven-CVM evidence set",
  });
  const evidenceSetSha256 = phalaSevenCvmVerifiedEvidenceSetSha256(evidenceSet);
  if (evidenceSetSha256
      !== replayCommitments.seven_cvm_verified_evidence_set_sha256) {
    throw new Error(
      "historically reconstructed seven-CVM evidence set drifted from release authority metadata",
    );
  }
  HISTORICALLY_REPLAYED_SEVEN_CVM_SETS.set(evidenceSet, evidenceSetSha256);
  return Object.freeze({
    evidenceSet,
    qvlIdentityEvidence: Object.freeze(qvlIdentityEvidence),
    workloadVerdictEvidence: Object.freeze(workloadVerdictEvidence),
    corroboration,
  });
}

export function createPhalaSevenCvmVerifiedEvidenceSet({
  releaseAuthority: releaseAuthorityValue,
  qvlIdentityEvidence,
  workloadVerdictEvidence,
  testOnlyNow,
} = {}) {
  const releaseAuthority = assertReleaseVerificationAuthorityForEvidence(
    releaseAuthorityValue,
  );
  if (!Array.isArray(qvlIdentityEvidence) || qvlIdentityEvidence.length !== 5
    || !Array.isArray(workloadVerdictEvidence) || workloadVerdictEvidence.length !== 2) {
    throw new Error("seven-CVM evidence producer requires five QVL identities and two workload verdicts");
  }
  const identities = new Map(qvlIdentityEvidence.map((entry) => {
    const verified = assertVerifiedPhalaQvlIdentityLaunchEvidence(entry);
    return [verified.domain, verified];
  }));
  const workloads = new Map(workloadVerdictEvidence.map((entry) => {
    const verified = assertVerifiedPhalaWorkloadTdxVerdict(entry);
    return [verified.domain, verified];
  }));
  if (identities.size !== 5 || workloads.size !== 2
    || Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).some((domain) => !identities.has(domain))
    || Object.keys(PHALA_WORKLOAD_DOMAIN_QVL_LINK).some((domain) => !workloads.has(domain))) {
    throw new Error("seven-CVM evidence domains are omitted, duplicated, or substituted");
  }
  const proofs = PHALA_SEVEN_CVM_EXECUTION_ORDER
    .map((domain) => identities.get(domain) || workloads.get(domain));
  const modes = new Set(proofs.map((entry) => entry.evidence_mode));
  if (modes.size !== 1) throw new Error("production and synthetic verifier evidence cannot be mixed");
  const domains = proofs.map(projectDomainEvidence);
  const releaseAuthoritySha = phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  for (let index = 0; index < domains.length; index += 1) {
    const projection = domains[index];
    const descriptor = releaseAuthority.descriptors[index];
    if (projection.release_authority_sha256 !== releaseAuthoritySha
      || projection.deployment_intent_sha256 !== releaseAuthority.deployment_intent_sha256
      || projection.ceremony_nonce !== releaseAuthority.ceremony_nonce
      || projection.measurement_policy_set_sha256
        !== releaseAuthority.qvl_measurement_policy_set_sha256
      || projection.descriptor_sha256 !== descriptor.descriptor_sha256
      || projection.posture_receipt_sha256 !== descriptor.posture_receipt_sha256
      || projection.app_id !== descriptor.app_id || projection.cvm_id !== descriptor.cvm_id
      || projection.compose_hash !== descriptor.compose_hash
      || projection.os_image_hash !== descriptor.os_image_hash) {
      throw new Error(`${projection.domain} proof does not match the branded release authority`);
    }
  }
  for (const [workloadDomain, { qvl_domain: qvlDomain }] of
    Object.entries(PHALA_WORKLOAD_DOMAIN_QVL_LINK)) {
    const workload = domains.find((entry) => entry.domain === workloadDomain);
    const qvl = domains.find((entry) => entry.domain === qvlDomain);
    if (workload.qvl_identity_sha256 !== qvl.evidence_sha256) {
      throw new Error(`${workloadDomain} does not chain to the exact DCAP-verified ${qvlDomain}`);
    }
  }
  const issuedAt = verificationSecond(
    releaseAuthority,
    testOnlyNow,
    "seven-CVM evidence-set issuance",
  );
  const transcriptSet = historicalTranscriptFileSetFromDomains(domains);
  const candidate = {
    schema: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
    status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS,
    truth_status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH,
    evidence_mode: proofs[0].evidence_mode,
    chain_id: CHAIN_ID,
    release_sha: releaseAuthority.release_sha,
    release_authority_sha256: releaseAuthoritySha,
    deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256: releaseAuthority.qvl_measurement_policy_set_sha256,
    execution_order: [...PHALA_SEVEN_CVM_EXECUTION_ORDER],
    domains,
    historical_transcript_file_set_sha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptSet),
    issued_at: issuedAt,
    first_verified_at: Math.min(...proofs.map((entry) => entry.verified_at)),
    last_verified_at: Math.max(...proofs.map((entry) => entry.verified_at)),
    minimum_activation_evidence_lease_expires_at: Math.min(
      ...proofs.map((entry) => entry.activation_evidence_lease_expires_at),
    ),
    proof_collection_skew_seconds:
      Math.max(...proofs.map((entry) => entry.verified_at))
      - Math.min(...proofs.map((entry) => entry.verified_at)),
    proofs_valid_at_issuance: true,
    verified_at: Math.max(...proofs.map((entry) => entry.verified_at)),
    all_seven_machine_verified: true,
    private_historical_transcript_required: true,
    raw_quote_publicly_disclosed: false,
    raw_collateral_publicly_disclosed: false,
    raw_secret_egress: false,
  };
  const normalized = deepFreezeCanonicalPlainDataGraph(normalizeSevenCvmSet(candidate), {
    label: "verified seven-CVM evidence set",
  });
  VERIFIED_SEVEN_CVM_SETS.set(
    normalized,
    domainSha256(PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_DOMAIN, normalized),
  );
  return normalized;
}

export function canonicalPhalaSevenCvmVerifiedEvidenceSetText(value) {
  return canonicalText(normalizeSevenCvmSet(value));
}

export function phalaSevenCvmVerifiedEvidenceSetSha256(value) {
  return domainSha256(
    PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_DOMAIN,
    normalizeSevenCvmSet(value),
  );
}

export function assertVerifiedPhalaSevenCvmEvidenceSet(value) {
  const expected = VERIFIED_SEVEN_CVM_SETS.get(value);
  if (!expected || phalaSevenCvmVerifiedEvidenceSetSha256(value) !== expected) {
    throw new Error("seven-CVM evidence set was not reconstructed from seven machine-verifier proofs");
  }
  return value;
}

export function assertProductionPhalaSevenCvmEvidenceSet(value) {
  const verified = assertVerifiedPhalaSevenCvmEvidenceSet(value);
  if (verified.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("synthetic seven-CVM evidence can never authorize a live release");
  }
  if (Math.floor(Date.now() / 1_000)
      >= verified.minimum_activation_evidence_lease_expires_at) {
    throw new Error("seven-CVM evidence proof window has expired and cannot mint fresh L");
  }
  return verified;
}

export function assertHistoricallyVerifiedProductionPhalaSevenCvmEvidenceSet(value) {
  const expected = VERIFIED_SEVEN_CVM_SETS.get(value)
    || HISTORICALLY_REPLAYED_SEVEN_CVM_SETS.get(value);
  if (!expected || phalaSevenCvmVerifiedEvidenceSetSha256(value) !== expected) {
    throw new Error(
      "seven-CVM evidence lacks a verified live or restart-safe historical brand",
    );
  }
  const verified = value;
  if (verified.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new Error("synthetic seven-CVM evidence has no production historical authority");
  }
  return verified;
}

export function normalizePhalaQvlIdentityLaunchEvidence(value) {
  return normalizeQvlIdentityVerification(value);
}

export function normalizePhalaWorkloadTdxVerdictVerification(value) {
  return normalizeWorkloadVerification(value);
}

export function normalizePhalaSevenCvmVerifiedEvidenceSet(value) {
  return normalizeSevenCvmSet(value);
}
