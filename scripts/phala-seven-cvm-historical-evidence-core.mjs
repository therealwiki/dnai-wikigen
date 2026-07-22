import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  appraisePhalaQvlMeasurementsAgainstPolicy,
  normalizePhalaQvlMeasurementPolicy,
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER,
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
  phalaSevenCvmHistoricalRuntimeBindingSha256,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  recoverIndependentEip191PersonalSignerFromRawDigest,
} from "../web/scripts/independent-eip191-replay-core.mjs";
export {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  recoverIndependentEip191PersonalSignerFromRawDigest,
} from "../web/scripts/independent-eip191-replay-core.mjs";

export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA =
  "dnai.phala-qvl-identity-launch-verification.v4";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-qvl-identity-launch-verification/v4\0";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS =
  "fresh_challenge_bound_identity_quote_intel_tdx_dcap_verified_and_activation_appraisal_lease_issued";
export const PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH =
  "release_authorized_measurement_policy_appraised_non_debug_identity_quote_fresh_challenge_report_data_and_authenticated_pccs_collateral_verified_with_policy_bounded_activation_evidence_lease";
export const PHALA_QVL_IDENTITY_ATTESTATION_REQUEST_SCHEMA =
  "dnai.qvl-identity-attestation-request.v3";
export const PHALA_QVL_IDENTITY_ATTESTATION_RESPONSE_SCHEMA =
  "dnai.qvl-identity-attestation-response.v3";
export const PHALA_WORKLOAD_QVL_CHALLENGE_SCHEMA =
  "dnai.attestation-qvl-challenge.v2";
export const PHALA_INDEPENDENT_TDX_VERDICT_SCHEMA =
  "dnai.independent-tdx-verdict.v4";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA =
  "dnai.phala-workload-tdx-verdict-verification.v4";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-workload-tdx-verdict-verification/v4\0";
export const PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS =
  "fresh_independent_qvl_signed_intel_tdx_verdict_and_activation_appraisal_lease_verified";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA =
  "dnai.phala-compute-workload-recipient-activation-verification.v3";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN =
  "dnai-wikigen/phala-compute-workload-recipient-activation-verification/v3\0";
export const PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS =
  "fresh_main_runtime_recipient_quote_independent_compute_workload_qvl_signature_and_recipient_evidence_lease_verified";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA =
  "dnai.phala-seven-cvm-verified-evidence-set.v4";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_DOMAIN =
  "dnai-wikigen/phala-seven-cvm-verified-evidence-set/v4\0";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS =
  "exact_seven_cvm_machine_verifier_evidence_and_activation_appraisal_leases_complete";
export const PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH =
  "five_policy_appraised_qvl_identities_and_two_release_lineage_bound_workloads_verified_with_policy_bounded_activation_evidence_leases";
export const PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_RECONSTRUCTION_SCHEMA =
  "dnai.phala-seven-cvm-historical-evidence-reconstruction.v1";
export const PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_RECONSTRUCTION_TRUTH =
  "raw14_protocol_and_signatures_replayed_against_authenticated_historical_L_R_roots_without_dcap_collateral_or_freshness_renewal";

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
export const PHALA_WORKLOAD_DOMAIN_QVL_LINK = Object.freeze({
  main_runtime_cvm: Object.freeze({
    profile: "diligence",
    qvl_domain: "diligence_qvl_cvm",
    contract_key: "diligence_room",
  }),
  independent_metering_cvm: Object.freeze({
    profile: "compute_metering",
    qvl_domain: "compute_metering_qvl_cvm",
    contract_key: "compute_credit_vault",
  }),
});
export const PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS = deepFreezeCanonicalPlainDataGraph({
  main_runtime_cvm: {
    first: "--main-runtime-qvl-challenge",
    second: "--main-runtime-independent-tdx-verdict",
  },
  diligence_qvl_cvm: {
    first: "--diligence-qvl-identity-request",
    second: "--diligence-qvl-identity-response",
  },
  arena_qvl_cvm: {
    first: "--arena-qvl-identity-request",
    second: "--arena-qvl-identity-response",
  },
  anchor_writer_qvl_cvm: {
    first: "--anchor-writer-qvl-identity-request",
    second: "--anchor-writer-qvl-identity-response",
  },
  compute_workload_qvl_cvm: {
    first: "--compute-workload-qvl-identity-request",
    second: "--compute-workload-qvl-identity-response",
  },
  compute_metering_qvl_cvm: {
    first: "--compute-metering-qvl-identity-request",
    second: "--compute-metering-qvl-identity-response",
  },
  independent_metering_cvm: {
    first: "--independent-metering-qvl-challenge",
    second: "--independent-metering-independent-tdx-verdict",
  },
});

// Historical receipt reconstruction needs the exact authority bytes that were
// included in the original local-DCAP receipts. This is data only. It does not
// inspect or execute the historical Python/native verifier distribution.
export const PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY =
  deepFreezeCanonicalPlainDataGraph({
    verifier: "dcap-qvl",
    verifier_version: "0.5.2",
    pccs_url: "https://pccs.phala.network",
    collateral_mode: "authenticated_online_pccs",
    invocation:
      "root_owned_system_python_I_S_B_root_protected_abi3_fd3_authenticated_source_fd4",
    platform: "darwin",
    architecture: "arm64",
    system_python_launcher: "/usr/bin/python3",
    system_python_launcher_sha256:
      "179301dcb41ea78accc3fa0048a7e6f6710d891945a751a34addd622020c1818",
    system_python_reported_executable:
      "/Library/Developer/CommandLineTools/usr/bin/python3",
    system_python_reported_executable_link:
      "../../Library/Frameworks/Python3.framework/Versions/3.9/bin/python3",
    system_python_resolved_executable:
      "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9",
    system_python_resolved_executable_sha256:
      "1e78c38b861b64659075942e1d9bdfa083dbb1eb23bd96bd5d166756c1795524",
    system_python_version: "3.9.6",
    system_python_runtime_root:
      "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9",
    system_python_runtime_tree_sha256:
      "sha256:c5aedcee4a43ab33ede0734a667243048d3097fffd7435de8ae4f6530a217277",
    python_flags:
      "isolated_ignore_environment_no_site_no_user_site_no_bytecode_exact_system_path",
    user_writable_import_path: false,
    darwin_release: "25.5.0",
    macos_version: "26.5.1",
    macos_build: "25F80",
    system_version_plist: "/System/Library/CoreServices/SystemVersion.plist",
    system_version_plist_sha256:
      "d90b1755e5dbb837d2ca1e11083c6e36e6219193a0fcf036d0f7cfe5366e031e",
    codesign_executable: "/usr/bin/codesign",
    codesign_executable_sha256:
      "214d455584d19abc0d74d02b9cbc7d3da6bdcb0596c235e6156dd9ed2f4e1ba7",
    dcap_qvl_abi3_path:
      "/Library/Application Support/dnai-wikigen/dcap-qvl/0.5.2/_dcap_qvl.abi3.so",
    dcap_qvl_abi3_owner_uid: 0,
    dcap_qvl_abi3_mode: "0555",
    dcap_qvl_abi3_signature: "adhoc_linker_signed",
    dcap_qvl_abi3_cdhash_full_sha256:
      "758692e2a484440e6fd2a7bb4b3b74112647e9acd8c1a6f9750a0350a895d29f",
    bootstrap_sha256:
      "9bdc99d17e92ca311326dc21e9ee82093962d05894a326b98f4df9970e930d92",
    isolated_runtime_environment_sha256:
      "sha256:62be45b60bcf7ad7434ad78247997256ab7282bb91d829ee87c301a3b55a146d",
    verifier_script_sha256:
      "baa62561c958026ae783f2d93da3ddf1ad7f2964d9b294aeb4f683ca98475b05",
    dcap_qvl_abi3_sha256:
      "6f86d8b8ed99c74663418d15150906cea4025352c49889e841ac68b387e04e7f",
  }, { label: "historical DCAP verifier authority" });

const CHAIN_ID = 84_532;
const MAX_ARTIFACT_BYTES = 128 * 1024;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const REPORT_DATA_64 = /^0x[0-9a-f]{128}$/;
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_N = SECP256K1_N / 2n;

const INDEPENDENT_VERDICT_DOMAIN =
  "dnai-wikigen/independent-tdx-verdict/v4\0";
const QVL_CHALLENGE_DOMAIN =
  "dnai-wikigen/attestation-qvl/challenge/v2\0";
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
const PCCS_AUTHORITY_DOMAIN =
  "dnai-wikigen/pccs-collateral-authority/v1\0";
const PCCS_VERIFICATION_RECEIPT_DOMAIN =
  "dnai-wikigen/pccs-collateral-verification-receipt/v1\0";
const TDX_MEASUREMENTS_DOMAIN = "dnai-wikigen/tdx-measurements/v1\0";
const RAW_TRANSCRIPT_DOMAIN =
  "dnai-wikigen/phala-raw-verifier-transcript/v1\0";
const SIGNATURE_BYTES_DOMAIN =
  "dnai-wikigen/release-authority-signature/v1\0";
const DILIGENCE_REPORT_CONTEXT = "diligence-room-submit-result";
const COMPUTE_REPORT_DATA_DOMAIN =
  "dnai-wikigen/compute-metering-signer-attestation/v1\0";
const COMPUTE_SIGNER_CUSTODY = "dstack_derived_independent_cvm";
const COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-attestation/v1\0";
const COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-release/v2\0";
const COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-activation-artifact/v3\0";

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  if (!isRecord(value)) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  const prototype = Object.getPrototypeOf(value);
  const keys = Reflect.ownKeys(value);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if ((prototype !== Object.prototype && prototype !== null)
    || keys.some((key) => typeof key !== "string")
    || JSON.stringify(keys.sort()) !== JSON.stringify([...fields].sort())
    || Object.values(descriptors).some((descriptor) => (
      !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true
    ))) {
    throw new TypeError(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function compactText(value) {
  return JSON.stringify(sorted(value));
}

function domainSha256(domain, value, { compact = false } = {}) {
  const text = compact ? compactText(value) : canonicalText(value);
  if (Buffer.byteLength(text, "utf8") > MAX_ARTIFACT_BYTES) {
    throw new TypeError("historical verifier artifact exceeds its byte bound");
  }
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(text, "utf8")
    .digest("hex")}`;
}

function fixed(value, pattern, label) {
  if (typeof value !== "string" || !pattern.test(value)) {
    throw new TypeError(`${label} is not canonical fixed-width lowercase data`);
  }
  return value;
}

function digest(value, label) {
  return fixed(value, SHA256, label);
}

function bytes32(value, label) {
  return fixed(value, BYTES32, label);
}

function address(value, label) {
  return fixed(value, ADDRESS, label);
}

function bareDigest(value, label) {
  return fixed(value, BARE_SHA256, label);
}

function appId(value, label) {
  return fixed(value, APP_ID, label);
}

function cvmId(value, label) {
  return fixed(value, IDENTIFIER, label);
}

function second(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    throw new TypeError(`${label} must be a bounded Unix second`);
  }
  return value;
}

function shaFromBytes32(value, label) {
  return `sha256:${bytes32(value, label).slice(2)}`;
}

function bytes32FromSha(value, label) {
  return `0x${digest(value, label).slice(7)}`;
}

function bytes32FromBare(value, label) {
  return `0x${bareDigest(value, label)}`;
}

function signatureSha256(value, label) {
  if (typeof value !== "string" || !SIGNATURE.test(value)) {
    throw new TypeError(`${label} must be canonical lowercase 65-byte hex`);
  }
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = Number.parseInt(value.slice(130), 16);
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s > SECP256K1_HALF_N
    || (v !== 27 && v !== 28)) {
    throw new TypeError(`${label} must use canonical low-s secp256k1`);
  }
  return `sha256:${createHash("sha256")
    .update(SIGNATURE_BYTES_DOMAIN, "utf8")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex")}`;
}

function rawTranscriptSha256(domain, kind, fileDigests) {
  if (!PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(domain)
    || ![
      "qvl_identity_request_response",
      "workload_challenge_verdict",
      "compute_workload_recipient_activation",
    ].includes(kind)
    || !Array.isArray(fileDigests) || fileDigests.length !== 2) {
    throw new TypeError("historical raw transcript commitment shape is invalid");
  }
  return domainSha256(RAW_TRANSCRIPT_DOMAIN, {
    schema: "dnai.phala-raw-verifier-transcript.v1",
    chain_id: CHAIN_ID,
    domain,
    kind,
    artifact_sha256: fileDigests.map((value, index) => (
      digest(value, `${domain} transcript file ${index}`)
    )),
  });
}

function normalizedRawFile(entry, normalizedValue, flag) {
  const parsed = exactRecord(
    entry,
    ["sha256", "size", "value"],
    `${flag} historical raw artifact`,
  );
  assertCanonicalPlainDataGraph(parsed.value, { label: `${flag} raw value` });
  if (canonicalText(parsed.value) !== canonicalText(normalizedValue)) {
    throw new TypeError(`${flag} raw value differs from its normalized protocol object`);
  }
  const text = canonicalText(normalizedValue);
  const size = Buffer.byteLength(text, "utf8");
  const sha256 = `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
  if (size < 2 || size > MAX_ARTIFACT_BYTES
    || parsed.size !== size || parsed.sha256 !== sha256) {
    throw new TypeError(`${flag} canonical bytes, size, or SHA-256 drifted`);
  }
  return Object.freeze({ flag, value: normalizedValue, sha256, size });
}

function normalizeRaw14(value) {
  assertCanonicalPlainDataGraph(value, { label: "historical raw14 input map" });
  const map = exactRecord(
    value,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
    "historical raw14 input map",
  );
  return map;
}

function normalizeQvlIdentityRequest(value) {
  const parsed = exactRecord(value, [
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest", "challenge_id",
    "compose_hash", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "measurement_policy_sha256", "os_image_hash", "profile",
    "release_authority_sha256", "schema",
  ], "QVL identity request");
  const profile = PHALA_QVL_IDENTITY_DOMAIN_PROFILE[parsed.domain];
  const issuedAt = second(parsed.issued_at, "QVL identity issued_at");
  const expiresAt = second(parsed.expires_at, "QVL identity expires_at");
  if (parsed.schema !== PHALA_QVL_IDENTITY_ATTESTATION_REQUEST_SCHEMA
    || parsed.chain_id !== CHAIN_ID || !profile || parsed.profile !== profile
    || expiresAt <= issuedAt || expiresAt - issuedAt > 120) {
    throw new TypeError("QVL identity request schema, role, or lifetime is invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile,
    cvm_id: cvmId(parsed.cvm_id, "QVL identity request CVM ID"),
    deployment_intent_sha256: digest(
      parsed.deployment_intent_sha256,
      "QVL identity request deployment intent",
    ),
    release_authority_sha256: digest(
      parsed.release_authority_sha256,
      "QVL identity request release authority",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "QVL identity ceremony nonce"),
    measurement_policy_sha256: digest(
      parsed.measurement_policy_sha256,
      "QVL identity measurement policy",
    ),
    app_id: appId(parsed.app_id, "QVL identity request app ID"),
    compose_hash: bareDigest(parsed.compose_hash, "QVL identity request compose hash"),
    os_image_hash: bareDigest(parsed.os_image_hash, "QVL identity request OS hash"),
    challenge_id: bytes32(parsed.challenge_id, "QVL identity challenge ID"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    challenge_digest: bytes32(parsed.challenge_digest, "QVL identity challenge digest"),
  };
}

export function phalaQvlIdentityChallengeDigest(value) {
  const request = normalizeQvlIdentityRequest(value);
  const unsigned = Object.fromEntries(
    Object.entries(request).filter(([key]) => key !== "challenge_digest"),
  );
  return `0x${createHash("sha256")
    .update(QVL_IDENTITY_CHALLENGE_DOMAIN, "utf8")
    .update(compactText(unsigned), "ascii")
    .digest("hex")}`;
}

function normalizeQvlIdentityResponse(value) {
  const parsed = exactRecord(value, [
    "app_id", "ceremony_nonce", "chain_id", "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at", "compose_hash",
    "cvm_id", "deployment_intent_sha256", "domain", "measurement_policy_sha256",
    "os_image_hash", "profile", "quote", "quote_hash", "quote_report_data",
    "quote_size", "raw_secret_egress", "release_authority_sha256",
    "release_policy_hash", "report_data", "schema", "verifier_address",
  ], "QVL identity response");
  const profile = PHALA_QVL_IDENTITY_DOMAIN_PROFILE[parsed.domain];
  if (parsed.schema !== PHALA_QVL_IDENTITY_ATTESTATION_RESPONSE_SCHEMA
    || parsed.chain_id !== CHAIN_ID || !profile || parsed.profile !== profile
    || parsed.raw_secret_egress !== false || typeof parsed.quote !== "string"
    || !/^0x[0-9a-f]+$/.test(parsed.quote) || parsed.quote.length % 2 !== 0
    || !Number.isSafeInteger(parsed.quote_size) || parsed.quote_size < 1_024
    || parsed.quote_size > 16 * 1_024
    || parsed.quote.length !== 2 + parsed.quote_size * 2
    || typeof parsed.quote_report_data !== "string"
    || !REPORT_DATA_64.test(parsed.quote_report_data)) {
    throw new TypeError("QVL identity response schema or quote bounds are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile,
    cvm_id: cvmId(parsed.cvm_id, "QVL identity response CVM ID"),
    deployment_intent_sha256: digest(
      parsed.deployment_intent_sha256,
      "QVL identity response deployment intent",
    ),
    release_authority_sha256: digest(
      parsed.release_authority_sha256,
      "QVL identity response release authority",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "QVL identity response ceremony nonce"),
    measurement_policy_sha256: digest(
      parsed.measurement_policy_sha256,
      "QVL identity response measurement policy",
    ),
    verifier_address: address(parsed.verifier_address, "QVL identity verifier"),
    release_policy_hash: bytes32(parsed.release_policy_hash, "QVL release policy"),
    report_data: bytes32(parsed.report_data, "QVL identity report data"),
    quote_report_data: parsed.quote_report_data,
    challenge_id: bytes32(parsed.challenge_id, "QVL identity response challenge ID"),
    challenge_digest: bytes32(
      parsed.challenge_digest,
      "QVL identity response challenge digest",
    ),
    challenge_issued_at: second(
      parsed.challenge_issued_at,
      "QVL identity response challenge issued_at",
    ),
    challenge_expires_at: second(
      parsed.challenge_expires_at,
      "QVL identity response challenge expires_at",
    ),
    quote: parsed.quote,
    quote_hash: bytes32(parsed.quote_hash, "QVL identity quote hash"),
    quote_size: parsed.quote_size,
    app_id: appId(parsed.app_id, "QVL identity response app ID"),
    compose_hash: bareDigest(parsed.compose_hash, "QVL identity response compose hash"),
    os_image_hash: bareDigest(parsed.os_image_hash, "QVL identity response OS hash"),
    raw_secret_egress: false,
  };
}

function qvlIdentityReportData(request, response) {
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
    verifier_address: response.verifier_address,
    release_policy_hash: response.release_policy_hash,
  };
  return `0x${createHash("sha256")
    .update(QVL_IDENTITY_REPORT_DATA_DOMAIN, "utf8")
    .update(compactText(payload), "ascii")
    .digest("hex")}`;
}

function normalizeQvlChallenge(value) {
  const parsed = exactRecord(value, [
    "ceremony_nonce", "chain_id", "challenge_digest", "challenge_id", "cvm_id",
    "deployment_intent_sha256", "domain", "expires_at", "issued_at",
    "measurement_policy_sha256", "profile", "release_authority_sha256",
    "release_policy_hash", "schema", "verifier_address", "verifier_signature",
  ], "workload QVL challenge");
  const issuedAt = second(parsed.issued_at, "workload challenge issued_at");
  const expiresAt = second(parsed.expires_at, "workload challenge expires_at");
  if (parsed.schema !== PHALA_WORKLOAD_QVL_CHALLENGE_SCHEMA
    || parsed.chain_id !== CHAIN_ID
    || !PHALA_WORKLOAD_DOMAIN_QVL_LINK[parsed.domain]
    || parsed.profile !== PHALA_WORKLOAD_DOMAIN_QVL_LINK[parsed.domain].profile
    || expiresAt <= issuedAt || expiresAt - issuedAt > 120
    || typeof parsed.verifier_signature !== "string"
    || !SIGNATURE.test(parsed.verifier_signature)) {
    throw new TypeError("workload QVL challenge schema, role, or lifetime is invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile: parsed.profile,
    cvm_id: cvmId(parsed.cvm_id, "workload challenge CVM ID"),
    deployment_intent_sha256: digest(
      parsed.deployment_intent_sha256,
      "workload challenge deployment intent",
    ),
    release_authority_sha256: digest(
      parsed.release_authority_sha256,
      "workload challenge release authority",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "workload challenge ceremony nonce"),
    measurement_policy_sha256: digest(
      parsed.measurement_policy_sha256,
      "workload challenge measurement policy",
    ),
    release_policy_hash: bytes32(parsed.release_policy_hash, "workload release policy"),
    challenge_id: bytes32(parsed.challenge_id, "workload challenge ID"),
    issued_at: issuedAt,
    expires_at: expiresAt,
    verifier_address: address(parsed.verifier_address, "workload challenge verifier"),
    challenge_digest: bytes32(parsed.challenge_digest, "workload challenge digest"),
    verifier_signature: parsed.verifier_signature,
  };
}

export function qvlChallengeSigningDigest(value) {
  const challenge = normalizeQvlChallenge(value);
  const unsigned = Object.fromEntries(
    Object.entries(challenge).filter(([key]) => (
      !["challenge_digest", "verifier_signature"].includes(key)
    )),
  );
  return `0x${createHash("sha256")
    .update(QVL_CHALLENGE_DOMAIN, "utf8")
    .update(compactText(unsigned), "ascii")
    .digest("hex")}`;
}

function qvlChallengeArtifactSha256(value) {
  return domainSha256(QVL_CHALLENGE_ARTIFACT_DOMAIN, normalizeQvlChallenge(value));
}

function normalizeIndependentVerdict(value) {
  const parsed = exactRecord(value, [
    "activation_evidence_lease_expires_at", "app_id", "ceremony_nonce", "chain_id",
    "challenge_digest",
    "challenge_expires_at", "challenge_id", "challenge_issued_at", "compose_hash",
    "contract_address", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "release_authority_sha256", "release_policy_hash", "report_data", "schema",
    "signer_address", "verification_method", "verified", "verifier_address",
    "verifier_signature",
  ], "independent TDX verdict");
  if (parsed.schema !== PHALA_INDEPENDENT_TDX_VERDICT_SCHEMA
    || parsed.verification_method !== "intel_tdx_dcap_qvl"
    || parsed.verified !== true || parsed.chain_id !== CHAIN_ID
    || !PHALA_SEVEN_CVM_EXECUTION_ORDER.includes(parsed.domain)
    || !Object.values(PHALA_QVL_IDENTITY_DOMAIN_PROFILE).includes(parsed.profile)
    || typeof parsed.verifier_signature !== "string"
    || !SIGNATURE.test(parsed.verifier_signature)) {
    throw new TypeError("independent TDX verdict schema or method is invalid");
  }
  const issuedAt = second(parsed.issued_at, "verdict issued_at");
  const leaseExpiresAt = second(
    parsed.activation_evidence_lease_expires_at,
    "verdict activation evidence lease expires_at",
  );
  const expiresAt = second(parsed.expires_at, "verdict expires_at");
  if (leaseExpiresAt !== expiresAt || expiresAt <= issuedAt
    || expiresAt - issuedAt > PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS) {
    throw new TypeError("independent TDX verdict activation evidence lease is invalid");
  }
  return {
    schema: parsed.schema,
    verification_method: parsed.verification_method,
    verified: true,
    chain_id: CHAIN_ID,
    domain: parsed.domain,
    profile: parsed.profile,
    cvm_id: cvmId(parsed.cvm_id, "verdict CVM ID"),
    deployment_intent_sha256: digest(parsed.deployment_intent_sha256, "verdict intent"),
    release_authority_sha256: digest(parsed.release_authority_sha256, "verdict authority"),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "verdict ceremony nonce"),
    measurement_policy_sha256: digest(parsed.measurement_policy_sha256, "verdict policy"),
    release_policy_hash: bytes32(parsed.release_policy_hash, "verdict release policy"),
    challenge_id: bytes32(parsed.challenge_id, "verdict challenge ID"),
    challenge_digest: bytes32(parsed.challenge_digest, "verdict challenge digest"),
    challenge_issued_at: second(parsed.challenge_issued_at, "verdict challenge issued_at"),
    challenge_expires_at: second(parsed.challenge_expires_at, "verdict challenge expires_at"),
    quote_hash: bytes32(parsed.quote_hash, "verdict quote hash"),
    report_data: bytes32(parsed.report_data, "verdict report data"),
    compose_hash: bytes32(parsed.compose_hash, "verdict compose hash"),
    app_id: appId(parsed.app_id, "verdict app ID"),
    os_image_hash: bareDigest(parsed.os_image_hash, "verdict OS hash"),
    signer_address: address(parsed.signer_address, "verdict signer"),
    contract_address: address(parsed.contract_address, "verdict contract"),
    issued_at: issuedAt,
    activation_evidence_lease_expires_at: leaseExpiresAt,
    expires_at: expiresAt,
    verifier_address: address(parsed.verifier_address, "verdict verifier"),
    verifier_signature: parsed.verifier_signature,
  };
}

export function independentTdxVerdictSigningDigest(value) {
  const verdict = normalizeIndependentVerdict(value);
  const unsigned = Object.fromEntries(
    Object.entries(verdict).filter(([key]) => key !== "verifier_signature"),
  );
  return `0x${createHash("sha256")
    .update(INDEPENDENT_VERDICT_DOMAIN, "utf8")
    .update(compactText(unsigned), "ascii")
    .digest("hex")}`;
}

function independentTdxVerdictArtifactSha256(value) {
  return domainSha256(
    INDEPENDENT_VERDICT_ARTIFACT_DOMAIN,
    normalizeIndependentVerdict(value),
  );
}

function normalizeComputeWorkloadRecipientAttestation(value) {
  const parsed = exactRecord(value, [
    "activation_signer_address", "activation_signer_custody",
    "activation_signer_key_path", "audience", "chain_id",
    "compute_vault_address", "compute_vault_runtime_code_hash",
    "context", "encryption_public_key", "fresh_contract_deployment_receipt_sha256",
    "key_id", "protocol", "schema", "service",
  ], "compute-workload recipient attestation");
  if (parsed.schema !== "dnai.compute-workload-recipient-attestation.v1"
    || parsed.context !== "compute_workload"
    || parsed.audience !== "dnai-wikigen:compute-workload-recipient"
    || parsed.service !== "dnai-wikigen"
    || parsed.protocol !== "compute_workload_ingress_v1"
    || parsed.activation_signer_key_path
      !== "tinker/compute_workload_activation_signer"
    || parsed.activation_signer_custody
      !== "dstack_derived_compute_workload_activation_signer"
    || parsed.chain_id !== CHAIN_ID
    || typeof parsed.encryption_public_key !== "string"
    || !BARE_SHA256.test(parsed.encryption_public_key)) {
    throw new TypeError("compute-workload recipient attestation semantics are invalid");
  }
  const expectedKeyId = `sha256:${createHash("sha256")
    .update(Buffer.from(parsed.encryption_public_key, "hex"))
    .digest("hex")}`;
  if (parsed.key_id !== expectedKeyId) {
    throw new TypeError("compute-workload recipient key ID does not match its key");
  }
  return {
    schema: parsed.schema,
    context: parsed.context,
    audience: parsed.audience,
    service: parsed.service,
    protocol: parsed.protocol,
    encryption_public_key: parsed.encryption_public_key,
    key_id: digest(parsed.key_id, "compute-workload recipient key ID"),
    activation_signer_address: address(
      parsed.activation_signer_address,
      "compute-workload activation signer",
    ),
    activation_signer_key_path: parsed.activation_signer_key_path,
    activation_signer_custody: parsed.activation_signer_custody,
    chain_id: CHAIN_ID,
    compute_vault_address: address(
      parsed.compute_vault_address,
      "compute-workload vault address",
    ),
    compute_vault_runtime_code_hash: bytes32(
      parsed.compute_vault_runtime_code_hash,
      "compute-workload vault runtime code hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      parsed.fresh_contract_deployment_receipt_sha256,
      "compute-workload fresh deployment receipt",
    ),
  };
}

export function phalaComputeWorkloadRecipientReportData(attestation) {
  return `0x${createHash("sha256")
    .update(COMPUTE_WORKLOAD_RECIPIENT_REPORT_DATA_DOMAIN, "utf8")
    .update(compactText(normalizeComputeWorkloadRecipientAttestation(attestation)), "ascii")
    .digest("hex")}`;
}

function normalizeComputeWorkloadRecipientActivation(value) {
  const parsed = exactRecord(value, [
    "app_id", "authenticated_at", "authenticated_verdict", "ceremony_nonce", "chain_id",
    "compose_hash", "cvm_id", "deployment_intent_sha256", "domain", "expires_at",
    "issued_at", "main_runtime_evidence_sha256", "measurement_policy_set_sha256",
    "measurement_policy_sha256", "os_image_hash", "profile", "quote_hash",
    "recipient_attestation", "recipient_evidence_lease_expires_at",
    "recipient_key_id", "recipient_release_commitment",
    "release_authority_sha256", "release_policy_hash", "report_data", "schema",
    "verdict_digest", "verifier_address",
  ], "compute-workload recipient activation");
  if (parsed.schema !== "dnai.compute.workload-recipient-activation.v3"
    || parsed.chain_id !== CHAIN_ID || parsed.domain !== "main_runtime_cvm"
    || parsed.profile !== "compute_workload") {
    throw new TypeError("compute-workload recipient activation schema is invalid");
  }
  const issuedAt = second(parsed.issued_at, "activation issued_at");
  const recipientLeaseExpiresAt = second(
    parsed.recipient_evidence_lease_expires_at,
    "activation recipient evidence lease expires_at",
  );
  const expiresAt = second(parsed.expires_at, "activation expires_at");
  if (recipientLeaseExpiresAt !== expiresAt || expiresAt <= issuedAt
    || expiresAt - issuedAt > 300) {
    throw new TypeError("compute-workload recipient evidence lease is invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: cvmId(parsed.cvm_id, "activation main runtime CVM ID"),
    deployment_intent_sha256: digest(parsed.deployment_intent_sha256, "activation intent"),
    release_authority_sha256: digest(parsed.release_authority_sha256, "activation authority"),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "activation ceremony nonce"),
    measurement_policy_set_sha256: digest(
      parsed.measurement_policy_set_sha256,
      "activation measurement policy set",
    ),
    measurement_policy_sha256: digest(
      parsed.measurement_policy_sha256,
      "activation measurement policy",
    ),
    main_runtime_evidence_sha256: digest(
      parsed.main_runtime_evidence_sha256,
      "activation main runtime proof",
    ),
    recipient_key_id: digest(parsed.recipient_key_id, "activation recipient key ID"),
    report_data: bytes32(parsed.report_data, "activation report data"),
    compose_hash: bytes32(parsed.compose_hash, "activation compose hash"),
    app_id: appId(parsed.app_id, "activation app ID"),
    os_image_hash: bareDigest(parsed.os_image_hash, "activation OS hash"),
    release_policy_hash: bytes32(parsed.release_policy_hash, "activation release policy"),
    quote_hash: bytes32(parsed.quote_hash, "activation quote hash"),
    verifier_address: address(parsed.verifier_address, "activation verifier"),
    verdict_digest: bytes32(parsed.verdict_digest, "activation verdict digest"),
    issued_at: issuedAt,
    recipient_evidence_lease_expires_at: recipientLeaseExpiresAt,
    expires_at: expiresAt,
    authenticated_at: second(parsed.authenticated_at, "activation authenticated_at"),
    recipient_release_commitment: digest(
      parsed.recipient_release_commitment,
      "activation recipient release commitment",
    ),
    recipient_attestation: normalizeComputeWorkloadRecipientAttestation(
      parsed.recipient_attestation,
    ),
    authenticated_verdict: normalizeIndependentVerdict(parsed.authenticated_verdict),
  };
}

export function normalizePhalaComputeWorkloadRecipientSourceActivation(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "compute-workload recipient source activation input",
  });
  return deepFreezeCanonicalPlainDataGraph(
    normalizeComputeWorkloadRecipientActivation(value),
    { label: "compute-workload recipient source activation" },
  );
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
    "raw_quote_persisted", "raw_secret_egress", "raw_transcript_sha256",
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
      !== "release_lineage_signed_compute_workload_qvl_verdict_recipient_report_data_branded_main_runtime_fresh_vault_and_recipient_evidence_lease_verified"
    || parsed.chain_id !== CHAIN_ID || parsed.domain !== "main_runtime_cvm"
    || parsed.profile !== "compute_workload"
    || parsed.raw_quote_persisted !== false || parsed.raw_secret_egress !== false
    || parsed.activation_signer_key_path
      !== "tinker/compute_workload_activation_signer"
    || parsed.activation_signer_custody
      !== "dstack_derived_compute_workload_activation_signer"
    || ![
      PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
      PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
    ].includes(parsed.evidence_mode)) {
    throw new TypeError("compute-workload activation verification authority is invalid");
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
    "historical activation initial main-runtime evidence lease expires_at",
  );
  const initialComputeQvlLeaseExpires = second(
    parsed.initial_compute_workload_qvl_activation_evidence_lease_expires_at,
    "historical activation initial compute-QVL evidence lease expires_at",
  );
  const terminalEvidenceLeaseExpires = second(
    parsed.terminal_evidence_lease_expires_at,
    "historical activation terminal evidence lease expires_at",
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
    throw new TypeError("compute-workload activation historical times are invalid");
  }
  const sourceActivation = normalizeComputeWorkloadRecipientActivation(
    parsed.source_activation,
  );
  const activationArtifactSha256 = domainSha256(
    COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_ARTIFACT_DOMAIN,
    sourceActivation,
  );
  const verdictArtifactSha256 = independentTdxVerdictArtifactSha256(
    sourceActivation.authenticated_verdict,
  );
  const transcriptSha256 = rawTranscriptSha256(
    "main_runtime_cvm",
    "compute_workload_recipient_activation",
    [activationArtifactSha256, verdictArtifactSha256],
  );
  if (parsed.activation_artifact_sha256 !== activationArtifactSha256
    || parsed.qvl_verdict_artifact_sha256 !== verdictArtifactSha256
    || parsed.raw_transcript_sha256 !== transcriptSha256) {
    throw new TypeError("compute-workload source activation transcript drifted");
  }
  const verdict = sourceActivation.authenticated_verdict;
  const attestation = sourceActivation.recipient_attestation;
  if (sourceActivation.release_authority_sha256 !== parsed.release_authority_sha256
    || sourceActivation.deployment_intent_sha256 !== parsed.deployment_intent_sha256
    || sourceActivation.ceremony_nonce !== parsed.ceremony_nonce
    || sourceActivation.measurement_policy_set_sha256
      !== parsed.measurement_policy_set_sha256
    || sourceActivation.measurement_policy_sha256 !== parsed.measurement_policy_sha256
    || sourceActivation.main_runtime_evidence_sha256
      !== parsed.main_runtime_evidence_sha256
    || sourceActivation.cvm_id !== parsed.cvm_id || sourceActivation.app_id !== parsed.app_id
    || sourceActivation.compose_hash !== bytes32FromBare(parsed.compose_hash, "source compose")
    || sourceActivation.os_image_hash !== parsed.os_image_hash
    || sourceActivation.recipient_key_id !== parsed.recipient_key_id
    || sourceActivation.report_data !== parsed.report_data
    || sourceActivation.recipient_release_commitment
      !== parsed.recipient_release_commitment
    || verdict.signer_address !== parsed.activation_signer_address
    || verdict.verifier_address !== parsed.qvl_verdict_verifier_address
    || attestation.compute_vault_address !== parsed.compute_vault_address
    || attestation.compute_vault_runtime_code_hash
      !== parsed.compute_vault_runtime_code_hash
    || attestation.fresh_contract_deployment_receipt_sha256
      !== parsed.fresh_contract_deployment_receipt_sha256
    || verdict.issued_at !== verdictIssued
    || verdict.activation_evidence_lease_expires_at !== verdictLeaseExpires
    || verdict.expires_at !== verdictExpires
    || sourceActivation.recipient_evidence_lease_expires_at !== recipientLeaseExpires
    || sourceActivation.authenticated_at !== authenticatedAt) {
    throw new TypeError("compute-workload source activation differs from projection");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    evidence_mode: parsed.evidence_mode,
    chain_id: CHAIN_ID,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    release_authority_sha256: digest(parsed.release_authority_sha256, "activation authority"),
    deployment_intent_sha256: digest(parsed.deployment_intent_sha256, "activation intent"),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "activation ceremony nonce"),
    measurement_policy_set_sha256: digest(
      parsed.measurement_policy_set_sha256,
      "activation policy set",
    ),
    measurement_policy_sha256: digest(parsed.measurement_policy_sha256, "activation policy"),
    descriptor_sha256: digest(parsed.descriptor_sha256, "activation descriptor"),
    posture_receipt_sha256: digest(parsed.posture_receipt_sha256, "activation posture"),
    qvl_identity_evidence_sha256: digest(
      parsed.qvl_identity_evidence_sha256,
      "activation QVL identity",
    ),
    app_id: appId(parsed.app_id, "activation app ID"),
    cvm_id: cvmId(parsed.cvm_id, "activation CVM ID"),
    compose_hash: bareDigest(parsed.compose_hash, "activation compose hash"),
    os_image_hash: bareDigest(parsed.os_image_hash, "activation OS hash"),
    encryption_public_key: bareDigest(parsed.encryption_public_key, "activation public key"),
    recipient_key_id: digest(parsed.recipient_key_id, "activation recipient key ID"),
    activation_signer_address: address(parsed.activation_signer_address, "activation signer"),
    activation_signer_key_path: parsed.activation_signer_key_path,
    activation_signer_custody: parsed.activation_signer_custody,
    main_runtime_signer_address: address(
      parsed.main_runtime_signer_address,
      "main runtime signer",
    ),
    main_runtime_evidence_sha256: digest(
      parsed.main_runtime_evidence_sha256,
      "main runtime evidence",
    ),
    initial_main_runtime_activation_evidence_lease_expires_at:
      initialMainRuntimeLeaseExpires,
    initial_compute_workload_qvl_activation_evidence_lease_expires_at:
      initialComputeQvlLeaseExpires,
    compute_vault_address: address(parsed.compute_vault_address, "activation vault"),
    compute_vault_runtime_code_hash: bytes32(
      parsed.compute_vault_runtime_code_hash,
      "activation vault code hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      parsed.fresh_contract_deployment_receipt_sha256,
      "activation fresh deployment receipt",
    ),
    report_data: bytes32(parsed.report_data, "activation report data"),
    recipient_release_commitment: digest(
      parsed.recipient_release_commitment,
      "activation recipient release commitment",
    ),
    qvl_release_policy_sha256: digest(parsed.qvl_release_policy_sha256, "activation QVL policy"),
    qvl_verdict_verifier_address: address(
      parsed.qvl_verdict_verifier_address,
      "activation QVL verifier",
    ),
    challenge_id: bytes32(parsed.challenge_id, "activation challenge ID"),
    challenge_digest: bytes32(parsed.challenge_digest, "activation challenge digest"),
    challenge_issued_at: challengeIssued,
    challenge_expires_at: challengeExpires,
    tdx_quote_sha256: digest(parsed.tdx_quote_sha256, "activation quote"),
    qvl_verdict_signing_digest: bytes32(
      parsed.qvl_verdict_signing_digest,
      "activation verdict digest",
    ),
    qvl_verdict_artifact_sha256: verdictArtifactSha256,
    qvl_verdict_verifier_signature_sha256: digest(
      parsed.qvl_verdict_verifier_signature_sha256,
      "activation verdict signature",
    ),
    activation_artifact_sha256: activationArtifactSha256,
    raw_transcript_sha256: transcriptSha256,
    source_activation: sourceActivation,
    verdict_issued_at: verdictIssued,
    verdict_activation_evidence_lease_expires_at: verdictLeaseExpires,
    verdict_expires_at: verdictExpires,
    recipient_evidence_lease_expires_at: recipientLeaseExpires,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpires,
    authenticated_at: authenticatedAt,
    verified_at: verifiedAt,
    expires_at: proofExpiresAt,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
}

export function normalizePhalaComputeWorkloadRecipientActivationVerification(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "compute-workload activation verification input",
  });
  return deepFreezeCanonicalPlainDataGraph(
    normalizeComputeWorkloadRecipientActivationVerification(value),
    { label: "compute-workload activation verification" },
  );
}

export function canonicalPhalaComputeWorkloadRecipientActivationVerificationText(value) {
  return canonicalText(normalizeComputeWorkloadRecipientActivationVerification(value));
}

export function phalaComputeWorkloadRecipientActivationVerificationSha256(value) {
  return domainSha256(
    PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_DOMAIN,
    normalizeComputeWorkloadRecipientActivationVerification(value),
  );
}

export const PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_CONTEXT_SCHEMA =
  "dnai.phala-seven-cvm-historical-evidence-context.v1";

const HISTORICAL_DOMAIN_CONTEXT_FIELDS = Object.freeze([
  "bound_contract_address",
  "domain",
  "machine_evidence_kind",
  "machine_evidence_sha256",
  "machine_evidence_verified_at",
  "qvl_identity_sha256",
  "qvl_release_policy_sha256",
  "qvl_verification_receipt_sha256",
  "tdx_attestation_evidence_sha256",
  "tdx_attestation_verification_receipt_sha256",
  "tdx_measurement_authority_sha256",
  "tee_identity",
]);

function normalizeHistoricalDomainContext(value, expectedDomain) {
  const parsed = exactRecord(
    value,
    HISTORICAL_DOMAIN_CONTEXT_FIELDS,
    `${expectedDomain} historical evidence context`,
  );
  const identity = Object.hasOwn(PHALA_QVL_IDENTITY_DOMAIN_PROFILE, expectedDomain);
  if (parsed.domain !== expectedDomain
    || parsed.machine_evidence_kind !== (identity
      ? "qvl_identity_local_dcap_verification"
      : "workload_independent_signed_qvl_verdict")
    || (identity ? parsed.bound_contract_address !== null
      : !ADDRESS.test(parsed.bound_contract_address || ""))) {
    throw new TypeError(`${expectedDomain} historical evidence context is invalid`);
  }
  return {
    domain: expectedDomain,
    machine_evidence_kind: parsed.machine_evidence_kind,
    machine_evidence_sha256: digest(
      parsed.machine_evidence_sha256,
      `${expectedDomain} machine evidence`,
    ),
    machine_evidence_verified_at: second(
      parsed.machine_evidence_verified_at,
      `${expectedDomain} machine evidence verified_at`,
    ),
    tdx_attestation_evidence_sha256: digest(
      parsed.tdx_attestation_evidence_sha256,
      `${expectedDomain} attestation evidence`,
    ),
    tdx_attestation_verification_receipt_sha256: digest(
      parsed.tdx_attestation_verification_receipt_sha256,
      `${expectedDomain} attestation receipt`,
    ),
    tdx_measurement_authority_sha256: digest(
      parsed.tdx_measurement_authority_sha256,
      `${expectedDomain} measurement authority`,
    ),
    qvl_release_policy_sha256: digest(
      parsed.qvl_release_policy_sha256,
      `${expectedDomain} QVL release policy`,
    ),
    qvl_verification_receipt_sha256: digest(
      parsed.qvl_verification_receipt_sha256,
      `${expectedDomain} QVL verification receipt`,
    ),
    qvl_identity_sha256: digest(
      parsed.qvl_identity_sha256,
      `${expectedDomain} QVL identity`,
    ),
    tee_identity: address(parsed.tee_identity, `${expectedDomain} TEE identity`),
    bound_contract_address: identity
      ? null
      : address(parsed.bound_contract_address, `${expectedDomain} bound contract`),
  };
}

export function normalizePhalaSevenCvmHistoricalEvidenceContext(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "seven-CVM historical evidence context input",
  });
  const parsed = exactRecord(value, [
    "domains", "historical_runtime_binding", "historical_transcript_file_set_sha256",
    "independent_metering_policy_set_hash", "launch_completed_at",
    "release_core_sha256", "schema",
  ], "seven-CVM historical evidence context");
  if (parsed.schema !== PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_CONTEXT_SCHEMA
    || !Array.isArray(parsed.domains) || parsed.domains.length !== 7) {
    throw new TypeError("seven-CVM historical evidence context shape is invalid");
  }
  const binding = normalizePhalaSevenCvmHistoricalRuntimeBinding(
    parsed.historical_runtime_binding,
  );
  const domains = parsed.domains.map((entry, index) => (
    normalizeHistoricalDomainContext(entry, PHALA_SEVEN_CVM_EXECUTION_ORDER[index])
  ));
  const launchCompletedAt = second(parsed.launch_completed_at, "historical L completed_at");
  if (launchCompletedAt !== Math.max(...domains.map((entry) => (
    entry.machine_evidence_verified_at
  )))) {
    throw new TypeError("historical L completed_at differs from its seven proof times");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_CONTEXT_SCHEMA,
    historical_runtime_binding: binding,
    release_core_sha256: digest(parsed.release_core_sha256, "historical release core"),
    independent_metering_policy_set_hash: bytes32(
      parsed.independent_metering_policy_set_hash,
      "historical metering policy-set hash",
    ),
    historical_transcript_file_set_sha256: digest(
      parsed.historical_transcript_file_set_sha256,
      "historical transcript file set",
    ),
    launch_completed_at: launchCompletedAt,
    domains,
  }, { label: "seven-CVM historical evidence context" });
}

function extractTdxV4Measurements(quote, { td15 }) {
  const read = (offset, size) => quote.subarray(offset, offset + size).toString("hex");
  const measurements = {
    tee_tcb_svn: read(48, 16),
    mr_seam: read(64, 48),
    mr_signer_seam: read(112, 48),
    seam_attributes: read(160, 8),
    td_attributes: read(168, 8),
    xfam: read(176, 8),
    mr_td: read(184, 48),
    mr_config_id: read(232, 48),
    mr_owner: read(280, 48),
    mr_owner_config: read(328, 48),
    rt_mr0: read(376, 48),
    rt_mr1: read(424, 48),
    rt_mr2: read(472, 48),
    rt_mr3: read(520, 48),
  };
  if (td15) {
    measurements.tee_tcb_svn2 = read(632, 16);
    measurements.mr_service_td = read(648, 48);
  }
  return measurements;
}

/**
 * Structurally parses the TDX v4 report body only. It does not validate the
 * quote signature, certificate chain, Intel collateral, QE identity, or TCB.
 * Both TD10 and TD15 candidates are returned because the v4 header does not
 * independently authenticate which report-body variant the historical local
 * verifier decoded; the signed-L proof root selects the exact old receipt.
 */
export function parsePhalaHistoricalTdxV4QuoteCandidates(value) {
  const quote = Buffer.isBuffer(value) ? Buffer.from(value) : Buffer.from(value || []);
  if (quote.length < 1_024 || quote.length > 16 * 1_024
    || quote.readUInt16LE(0) !== 4 || quote.readUInt32LE(4) !== 0x81) {
    throw new TypeError("historical quote is not a bounded Intel TDX quote-v4 body");
  }
  const reportData = `0x${quote.subarray(568, 632).toString("hex")}`;
  const candidates = [
    { body_type: "td10", measurements: extractTdxV4Measurements(quote, { td15: false }) },
  ];
  if (quote.length >= 696) {
    candidates.push({
      body_type: "td15",
      measurements: extractTdxV4Measurements(quote, { td15: true }),
    });
  }
  return deepFreezeCanonicalPlainDataGraph({ report_data: reportData, candidates }, {
    label: "historical TDX quote structural candidates",
  });
}

function tdxMeasurementsSha256(measurements) {
  return domainSha256(TDX_MEASUREMENTS_DOMAIN, measurements, { compact: true });
}

function pccsAuthority() {
  const authority = {
    schema: "dnai.pccs-collateral-authority.v1",
    url: PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY.pccs_url,
    transport: "https_system_trust_store",
    verifier: PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY.verifier,
    verifier_version:
      PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY.verifier_version,
  };
  return { authority, sha256: domainSha256(PCCS_AUTHORITY_DOMAIN, authority) };
}

function reconstructedHistoricalLocalDcapReceipt({
  evidenceMode,
  measurements,
  measurementPolicy,
  quoteSha256,
  quoteReportData,
  verifiedAt,
}) {
  const policy = normalizePhalaQvlMeasurementPolicy(measurementPolicy);
  const policySha256 = phalaQvlMeasurementPolicySha256(policy);
  const appraisal = appraisePhalaQvlMeasurementsAgainstPolicy(measurements, policy);
  if (appraisal.measurement_policy_sha256 !== policySha256
    || appraisal.measurement_policy_matched !== true || appraisal.debug_td !== false) {
    throw new TypeError("historical TDX measurements do not match release policy");
  }
  const measurementSha256 = tdxMeasurementsSha256(measurements);
  const collateral = pccsAuthority();
  const collateralVerification = {
    schema: "dnai.pccs-collateral-verification-receipt.v1",
    collateral_authority_sha256: collateral.sha256,
    tdx_quote_sha256: quoteSha256,
    runtime_environment_sha256:
      PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY
        .isolated_runtime_environment_sha256,
    status: "OK",
    verified_at: verifiedAt,
  };
  return {
    schema: "dnai.local-dcap-qvl-verification-receipt.v2",
    verification_method: "intel_tdx_dcap_qvl",
    evidence_mode: evidenceMode,
    verifier_authority: structuredClone(
      PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY,
    ),
    collateral_source:
      PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY.pccs_url,
    collateral_authority: collateral.authority,
    collateral_authority_sha256: collateral.sha256,
    collateral_verification: collateralVerification,
    collateral_verification_receipt_sha256:
      domainSha256(PCCS_VERIFICATION_RECEIPT_DOMAIN, collateralVerification),
    runtime_environment_sha256:
      PINNED_SEVEN_CVM_HISTORICAL_DCAP_VERIFIER_AUTHORITY
        .isolated_runtime_environment_sha256,
    tdx_quote_sha256: quoteSha256,
    verified: true,
    quote_type: "TDX",
    status: "OK",
    report_data: quoteReportData,
    measurements,
    measurements_sha256: measurementSha256,
    measurement_policy_sha256: policySha256,
    measurement_policy_reference_id: policy.reference_id,
    measurement_policy_matched: true,
    debug: false,
    verified_at: verifiedAt,
  };
}

function descriptorFor(authority, domain) {
  const descriptor = authority.descriptors.find((entry) => entry.domain === domain);
  if (!descriptor) throw new TypeError(`${domain} is absent from release authority`);
  return descriptor;
}

function policyFor(authority, domain) {
  const policy = authority.qvl_measurement_policies.find((entry) => entry.domain === domain);
  if (!policy) throw new TypeError(`${domain} measurement policy is absent`);
  return policy;
}

function assertFieldsEqual(left, right, fields, label) {
  for (const field of fields) {
    if (left[field] !== right[field]) {
      throw new TypeError(`${label} ${field} drifted`);
    }
  }
}

function identityProjection(proof, proofSha256) {
  return {
    domain: proof.domain,
    evidence_kind: "qvl_identity_local_dcap_verification",
    evidence_sha256: proofSha256,
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
    contract_address: null,
    tdx_quote_sha256: proof.tdx_quote_sha256,
    tdx_measurements_sha256: proof.tdx_measurements_sha256,
    tdx_measurement_policy_sha256: proof.measurement_policy_sha256,
    tdx_attestation_evidence_sha256:
      proof.identity_attestation_response_sha256,
    tdx_attestation_verification_receipt_sha256: proofSha256,
    qvl_release_policy_sha256: proof.release_policy_sha256,
    qvl_verification_receipt_sha256: proofSha256,
    qvl_identity_sha256: proofSha256,
    raw_transcript_file_sha256: [
      proof.identity_attestation_request_file_sha256,
      proof.identity_attestation_response_file_sha256,
    ],
    raw_transcript_file_size: [
      proof.identity_attestation_request_file_size,
      proof.identity_attestation_response_file_size,
    ],
    raw_transcript_sha256: proof.raw_transcript_sha256,
    verified_at: proof.verified_at,
    activation_evidence_lease_expires_at:
      proof.activation_evidence_lease_expires_at,
    expires_at: proof.expires_at,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
}

function reconstructIdentityCandidates({
  domain,
  raw,
  authority,
  authoritySha256,
  domainContext,
}) {
  const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[domain];
  const requestValue = normalizeQvlIdentityRequest(raw[flags.first].value);
  const responseValue = normalizeQvlIdentityResponse(raw[flags.second].value);
  const requestFile = normalizedRawFile(raw[flags.first], requestValue, flags.first);
  const responseFile = normalizedRawFile(raw[flags.second], responseValue, flags.second);
  const descriptor = descriptorFor(authority, domain);
  const policy = policyFor(authority, domain);
  const policySha256 = phalaQvlMeasurementPolicySha256(policy);
  if (requestValue.challenge_digest !== phalaQvlIdentityChallengeDigest(requestValue)) {
    throw new TypeError(`${domain} identity challenge digest is invalid`);
  }
  const lineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: PHALA_QVL_IDENTITY_DOMAIN_PROFILE[domain],
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    release_authority_sha256: authoritySha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_sha256: policySha256,
    app_id: descriptor.app_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
  };
  for (const [field, expected] of Object.entries(lineage)) {
    if (requestValue[field] !== expected || responseValue[field] !== expected) {
      throw new TypeError(`${domain} identity ${field} differs from release authority`);
    }
  }
  assertFieldsEqual(requestValue, {
    challenge_id: responseValue.challenge_id,
    challenge_digest: responseValue.challenge_digest,
    issued_at: responseValue.challenge_issued_at,
    expires_at: responseValue.challenge_expires_at,
  }, ["challenge_id", "challenge_digest", "issued_at", "expires_at"], `${domain} response`);
  if (domainContext.machine_evidence_verified_at < requestValue.issued_at
    || domainContext.machine_evidence_verified_at >= requestValue.expires_at) {
    throw new TypeError(`${domain} historical verification time is outside its challenge`);
  }
  const expectedReportData = qvlIdentityReportData(requestValue, responseValue);
  if (responseValue.report_data !== expectedReportData
    || responseValue.quote_report_data
      !== `${expectedReportData}${requestValue.challenge_digest.slice(2)}`) {
    throw new TypeError(`${domain} identity report data is not release/challenge bound`);
  }
  const quote = Buffer.from(responseValue.quote.slice(2), "hex");
  const quoteSha256 = `sha256:${createHash("sha256").update(quote).digest("hex")}`;
  if (quoteSha256 !== shaFromBytes32(responseValue.quote_hash, `${domain} quote`)) {
    throw new TypeError(`${domain} identity quote hash drifted`);
  }
  const parsedQuote = parsePhalaHistoricalTdxV4QuoteCandidates(quote);
  if (parsedQuote.report_data !== responseValue.quote_report_data) {
    throw new TypeError(`${domain} carried quote report data differs from quote bytes`);
  }
  const requestArtifactSha256 = domainSha256(QVL_REQUEST_ARTIFACT_DOMAIN, requestValue);
  const responseArtifactSha256 = domainSha256(QVL_RESPONSE_ARTIFACT_DOMAIN, responseValue);
  const rawTranscript = rawTranscriptSha256(
    domain,
    "qvl_identity_request_response",
    [requestFile.sha256, responseFile.sha256],
  );
  const candidates = [];
  for (const quoteCandidate of parsedQuote.candidates) {
    let localReceipt;
    try {
      localReceipt = reconstructedHistoricalLocalDcapReceipt({
        evidenceMode: authority.evidence_mode,
        measurements: quoteCandidate.measurements,
        measurementPolicy: policy,
        quoteSha256,
        quoteReportData: responseValue.quote_report_data,
        verifiedAt: domainContext.machine_evidence_verified_at,
      });
    } catch {
      continue;
    }
    const localReceiptSha256 = domainSha256(LOCAL_DCAP_RECEIPT_DOMAIN, localReceipt);
    const proof = {
      schema: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_SCHEMA,
      status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_STATUS,
      truth_status: PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_TRUTH,
      evidence_mode: authority.evidence_mode,
      chain_id: CHAIN_ID,
      domain,
      profile: lineage.profile,
      release_authority_sha256: authoritySha256,
      deployment_intent_sha256: authority.deployment_intent_sha256,
      ceremony_nonce: authority.ceremony_nonce,
      measurement_policy_set_sha256: authority.qvl_measurement_policy_set_sha256,
      measurement_policy_sha256: policySha256,
      measurement_policy: policy,
      descriptor_sha256: descriptor.descriptor_sha256,
      posture_receipt_sha256: descriptor.posture_receipt_sha256,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      compose_hash: descriptor.compose_hash,
      os_image_hash: descriptor.os_image_hash,
      tee_identity: responseValue.verifier_address,
      release_policy_sha256: shaFromBytes32(
        responseValue.release_policy_hash,
        `${domain} release policy`,
      ),
      challenge_id: requestValue.challenge_id,
      challenge_digest: requestValue.challenge_digest,
      challenge_issued_at: requestValue.issued_at,
      challenge_expires_at: requestValue.expires_at,
      tdx_quote_sha256: quoteSha256,
      tdx_measurements_sha256: localReceipt.measurements_sha256,
      identity_attestation_request_sha256: requestArtifactSha256,
      identity_attestation_response_sha256: responseArtifactSha256,
      identity_attestation_request_file_sha256: requestFile.sha256,
      identity_attestation_request_file_size: requestFile.size,
      identity_attestation_response_file_sha256: responseFile.sha256,
      identity_attestation_response_file_size: responseFile.size,
      raw_transcript_sha256: rawTranscript,
      local_dcap_verification: localReceipt,
      local_dcap_verification_receipt_sha256: localReceiptSha256,
      verified_at: domainContext.machine_evidence_verified_at,
      activation_evidence_lease_seconds:
        authority.activation_evidence_lease_seconds,
      activation_evidence_lease_issued_at:
        domainContext.machine_evidence_verified_at,
      activation_evidence_lease_expires_at:
        domainContext.machine_evidence_verified_at
          + authority.activation_evidence_lease_seconds,
      expires_at:
        domainContext.machine_evidence_verified_at
          + authority.activation_evidence_lease_seconds,
      raw_quote_persisted: false,
      raw_secret_egress: false,
    };
    const proofSha256 = domainSha256(
      PHALA_QVL_IDENTITY_LAUNCH_VERIFICATION_DOMAIN,
      proof,
    );
    if (proofSha256 === domainContext.machine_evidence_sha256) {
      candidates.push({
        body_type: quoteCandidate.body_type,
        proof,
        proof_sha256: proofSha256,
        projection: identityProjection(proof, proofSha256),
      });
    }
  }
  if (candidates.length !== 1) {
    throw new TypeError(
      `${domain} raw quote cannot uniquely reconstruct the signed-L identity proof root`,
    );
  }
  const selected = candidates[0];
  if (domainContext.tdx_attestation_evidence_sha256 !== responseArtifactSha256
    || domainContext.tdx_attestation_verification_receipt_sha256
      !== selected.proof_sha256
    || domainContext.tdx_measurement_authority_sha256 !== policySha256
    || domainContext.qvl_release_policy_sha256 !== selected.proof.release_policy_sha256
    || domainContext.qvl_verification_receipt_sha256 !== selected.proof_sha256
    || domainContext.qvl_identity_sha256 !== selected.proof_sha256
    || domainContext.tee_identity !== selected.proof.tee_identity) {
    throw new TypeError(`${domain} reconstructed identity differs from signed L`);
  }
  return selected;
}

function reportDataBinding(domain, meteringPolicySetHash) {
  if (domain === "main_runtime_cvm") {
    return { kind: "diligence_result_signer_v1" };
  }
  return {
    kind: "compute_metering_signer_v1",
    policy_set_hash: meteringPolicySetHash,
    signer_custody: COMPUTE_SIGNER_CUSTODY,
  };
}

function workloadReportData(domain, verdict, binding) {
  if (domain === "main_runtime_cvm") {
    return `0x${createHash("sha256")
      .update(compactText({
        service: "dnai-wikigen",
        context: DILIGENCE_REPORT_CONTEXT,
        signer_address: verdict.signer_address,
        chain_id: CHAIN_ID,
        contract_address: verdict.contract_address,
      }), "utf8")
      .digest("hex")}`;
  }
  return `0x${createHash("sha256")
    .update(COMPUTE_REPORT_DATA_DOMAIN, "utf8")
    .update(compactText({
      schema: "dnai.compute-metering-signer-attestation.v1",
      chain_id: CHAIN_ID,
      vault_address: verdict.contract_address,
      metering_verifier: verdict.signer_address,
      policy_set_hash: binding.policy_set_hash,
      signer_custody: COMPUTE_SIGNER_CUSTODY,
    }), "ascii")
    .digest("hex")}`;
}

function replayRawBytes32Signature({
  recoverPersonalSigner,
  expectedAddress,
  digest: signingDigest,
  signature,
  label,
}) {
  const recover = recoverPersonalSigner
    ?? (({ digest: value, signature: bytes }) => (
      recoverIndependentEip191PersonalSignerFromRawDigest({
        digest: value,
        signature: bytes,
      })
    ));
  if (typeof recover !== "function") {
    throw new TypeError("historical reconstruction signer recovery is invalid");
  }
  const signatureSha = signatureSha256(signature, label);
  const recovered = recover({
    digest: bytes32(signingDigest, `${label} signing digest`),
    signature,
    message_mode: "eip191_personal_sign_raw_bytes32",
  });
  if (recovered !== null
    && ["object", "function"].includes(typeof recovered)
    && typeof recovered.then === "function") {
    throw new TypeError(`${label} signer recovery must be synchronous and static`);
  }
  if (recovered !== expectedAddress) {
    throw new TypeError(`${label} EIP-191 signer does not match verifier address`);
  }
  return signatureSha;
}

/**
 * Replay one historical QVL EIP-191 signature over the digest's 32 raw bytes.
 *
 * This deliberately remains a non-authorizing historical primitive.  The
 * optional recovery callback is an injection seam for a statically bundled
 * implementation; asynchronous, RPC-backed recovery is rejected so callers
 * cannot accidentally turn exact reconstruction into a live observation.
 */
export function verifyPhalaHistoricalRawDigestSignature({
  digest: signingDigest,
  signature,
  expectedAddress,
  recoverPersonalSigner,
} = {}) {
  const normalizedExpectedAddress = address(
    expectedAddress,
    "historical raw-digest expected signer",
  );
  const signatureSha256 = replayRawBytes32Signature({
    recoverPersonalSigner,
    expectedAddress: normalizedExpectedAddress,
    digest: signingDigest,
    signature,
    label: "historical raw-digest signature",
  });
  return deepFreezeCanonicalPlainDataGraph({
    message_mode: "eip191_personal_sign_raw_bytes32",
    expected_address: normalizedExpectedAddress,
    signing_digest: bytes32(signingDigest, "historical raw-digest signing digest"),
    signature_sha256: signatureSha256,
    verified: true,
    current_operation_authorized: false,
  }, { label: "historical raw-digest signature replay result" });
}

function workloadProjection(proof, proofSha256) {
  return {
    domain: proof.domain,
    evidence_kind: "workload_independent_signed_qvl_verdict",
    evidence_sha256: proofSha256,
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
    contract_address: proof.contract_address,
    tdx_quote_sha256: proof.tdx_quote_sha256,
    tdx_measurements_sha256: null,
    tdx_measurement_policy_sha256: proof.measurement_policy_sha256,
    tdx_attestation_evidence_sha256: proof.qvl_verdict_artifact_sha256,
    tdx_attestation_verification_receipt_sha256: proofSha256,
    qvl_release_policy_sha256: proof.qvl_release_policy_sha256,
    qvl_verification_receipt_sha256: proofSha256,
    qvl_identity_sha256: proof.qvl_identity_evidence_sha256,
    raw_transcript_file_sha256: [
      proof.qvl_challenge_file_sha256,
      proof.qvl_verdict_file_sha256,
    ],
    raw_transcript_file_size: [
      proof.qvl_challenge_file_size,
      proof.qvl_verdict_file_size,
    ],
    raw_transcript_sha256: proof.raw_transcript_sha256,
    verified_at: proof.verified_at,
    activation_evidence_lease_expires_at:
      proof.activation_evidence_lease_expires_at,
    expires_at: proof.expires_at,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
}

function reconstructWorkloadProof({
  domain,
  raw,
  authority,
  authoritySha256,
  domainContext,
  linkedIdentity,
  meteringPolicySetHash,
  recoverPersonalSigner,
}) {
  const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[domain];
  const challenge = normalizeQvlChallenge(raw[flags.first].value);
  const verdict = normalizeIndependentVerdict(raw[flags.second].value);
  const challengeFile = normalizedRawFile(raw[flags.first], challenge, flags.first);
  const verdictFile = normalizedRawFile(raw[flags.second], verdict, flags.second);
  const descriptor = descriptorFor(authority, domain);
  const link = PHALA_WORKLOAD_DOMAIN_QVL_LINK[domain];
  const binding = reportDataBinding(domain, meteringPolicySetHash);
  const expectedContract = authority.contracts[link.contract_key];
  const lineage = {
    chain_id: CHAIN_ID,
    domain,
    profile: link.profile,
    cvm_id: descriptor.cvm_id,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    release_authority_sha256: authoritySha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_sha256: linkedIdentity.proof.measurement_policy_sha256,
  };
  for (const [field, expected] of Object.entries(lineage)) {
    if (challenge[field] !== expected || verdict[field] !== expected) {
      throw new TypeError(`${domain} workload ${field} differs from release authority`);
    }
  }
  if (challenge.release_policy_hash
      !== bytes32FromSha(linkedIdentity.proof.release_policy_sha256, `${domain} policy`)
    || challenge.verifier_address !== linkedIdentity.proof.tee_identity
    || challenge.challenge_id !== verdict.challenge_id
    || challenge.challenge_digest !== verdict.challenge_digest
    || challenge.issued_at !== verdict.challenge_issued_at
    || challenge.expires_at !== verdict.challenge_expires_at
    || verdict.release_policy_hash !== challenge.release_policy_hash
    || verdict.verifier_address !== challenge.verifier_address
    || verdict.app_id !== descriptor.app_id
    || verdict.compose_hash !== bytes32FromBare(descriptor.compose_hash, `${domain} compose`)
    || verdict.os_image_hash !== descriptor.os_image_hash
    || verdict.contract_address !== expectedContract
    || verdict.signer_address === verdict.verifier_address
    || verdict.report_data !== workloadReportData(domain, verdict, binding)) {
    throw new TypeError(`${domain} workload verdict authority or report data drifted`);
  }
  const challengeDigest = qvlChallengeSigningDigest(challenge);
  if (challenge.challenge_digest !== challengeDigest) {
    throw new TypeError(`${domain} workload challenge digest is invalid`);
  }
  const challengeSignatureSha256 = replayRawBytes32Signature({
    recoverPersonalSigner,
    expectedAddress: challenge.verifier_address,
    digest: challengeDigest,
    signature: challenge.verifier_signature,
    label: `${domain} challenge`,
  });
  const verdictDigest = independentTdxVerdictSigningDigest(verdict);
  const verdictSignatureSha256 = replayRawBytes32Signature({
    recoverPersonalSigner,
    expectedAddress: verdict.verifier_address,
    digest: verdictDigest,
    signature: verdict.verifier_signature,
    label: `${domain} verdict`,
  });
  const verifiedAt = domainContext.machine_evidence_verified_at;
  const activationEvidenceLeaseExpiresAt = Math.min(
    verdict.activation_evidence_lease_expires_at,
    linkedIdentity.proof.activation_evidence_lease_expires_at,
  );
  if (verdict.challenge_expires_at <= verdict.challenge_issued_at
    || verdict.challenge_expires_at - verdict.challenge_issued_at > 120
    || verdict.issued_at < verdict.challenge_issued_at
    || verdict.issued_at >= verdict.challenge_expires_at
    || verdict.expires_at <= verdict.issued_at
    || verdict.expires_at - verdict.issued_at
      > authority.activation_evidence_lease_seconds
    || verifiedAt < verdict.issued_at
    || verifiedAt >= activationEvidenceLeaseExpiresAt) {
    throw new TypeError(`${domain} historical workload verdict time is invalid`);
  }
  const challengeArtifactSha256 = qvlChallengeArtifactSha256(challenge);
  const verdictArtifactSha256 = independentTdxVerdictArtifactSha256(verdict);
  const transcriptSha256 = rawTranscriptSha256(
    domain,
    "workload_challenge_verdict",
    [challengeFile.sha256, verdictFile.sha256],
  );
  const proof = {
    schema: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_SCHEMA,
    status: PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_STATUS,
    truth_status:
      "release_lineage_qvl_challenge_and_verdict_signatures_policy_report_data_quote_and_policy_bounded_activation_evidence_lease_verified",
    evidence_mode: authority.evidence_mode,
    chain_id: CHAIN_ID,
    domain,
    profile: link.profile,
    release_authority_sha256: authoritySha256,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_set_sha256: authority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: linkedIdentity.proof.measurement_policy_sha256,
    descriptor_sha256: descriptor.descriptor_sha256,
    posture_receipt_sha256: descriptor.posture_receipt_sha256,
    app_id: descriptor.app_id,
    cvm_id: descriptor.cvm_id,
    compose_hash: descriptor.compose_hash,
    os_image_hash: descriptor.os_image_hash,
    tee_identity: verdict.signer_address,
    contract_address: expectedContract,
    report_data_binding: binding,
    report_data: verdict.report_data,
    qvl_release_policy_sha256: linkedIdentity.proof.release_policy_sha256,
    qvl_identity_evidence_sha256: linkedIdentity.proof_sha256,
    qvl_challenge_signing_digest: challengeDigest,
    qvl_challenge_artifact_sha256: challengeArtifactSha256,
    qvl_challenge_file_sha256: challengeFile.sha256,
    qvl_challenge_file_size: challengeFile.size,
    qvl_challenge_verifier_signature_sha256: challengeSignatureSha256,
    challenge_id: verdict.challenge_id,
    challenge_digest: verdict.challenge_digest,
    challenge_issued_at: verdict.challenge_issued_at,
    challenge_expires_at: verdict.challenge_expires_at,
    tdx_quote_sha256: shaFromBytes32(verdict.quote_hash, `${domain} quote`),
    qvl_verdict_signing_digest: verdictDigest,
    qvl_verdict_artifact_sha256: verdictArtifactSha256,
    qvl_verdict_file_sha256: verdictFile.sha256,
    qvl_verdict_file_size: verdictFile.size,
    raw_transcript_sha256: transcriptSha256,
    qvl_verdict_verifier_address: verdict.verifier_address,
    qvl_verdict_verifier_signature_sha256: verdictSignatureSha256,
    verdict_issued_at: verdict.issued_at,
    verdict_activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    verdict_expires_at: verdict.expires_at,
    verified_at: verifiedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    expires_at: activationEvidenceLeaseExpiresAt,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
  const proofSha256 = domainSha256(
    PHALA_WORKLOAD_TDX_VERDICT_VERIFICATION_DOMAIN,
    proof,
  );
  if (proofSha256 !== domainContext.machine_evidence_sha256
    || domainContext.tdx_attestation_evidence_sha256 !== verdictArtifactSha256
    || domainContext.tdx_attestation_verification_receipt_sha256 !== proofSha256
    || domainContext.tdx_measurement_authority_sha256
      !== linkedIdentity.proof.measurement_policy_sha256
    || domainContext.qvl_release_policy_sha256
      !== linkedIdentity.proof.release_policy_sha256
    || domainContext.qvl_verification_receipt_sha256 !== proofSha256
    || domainContext.qvl_identity_sha256 !== linkedIdentity.proof_sha256
    || domainContext.tee_identity !== verdict.signer_address
    || domainContext.bound_contract_address !== expectedContract) {
    throw new TypeError(`${domain} reconstructed workload proof differs from signed L`);
  }
  return { proof, proof_sha256: proofSha256, projection: workloadProjection(proof, proofSha256) };
}

function historicalTranscriptFromProjections(projections) {
  const byFlag = {};
  for (const projection of projections) {
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[projection.domain];
    byFlag[flags.first] = {
      sha256: projection.raw_transcript_file_sha256[0],
      size: projection.raw_transcript_file_size[0],
    };
    byFlag[flags.second] = {
      sha256: projection.raw_transcript_file_sha256[1],
      size: projection.raw_transcript_file_size[1],
    };
  }
  return createPhalaSevenCvmHistoricalTranscriptFileSet(byFlag);
}

function historicalEvidenceSetCandidate({ authority, authoritySha256, projections, issuedAt }) {
  const firstVerifiedAt = Math.min(...projections.map((entry) => entry.verified_at));
  const lastVerifiedAt = Math.max(...projections.map((entry) => entry.verified_at));
  const minimumActivationEvidenceLeaseExpiresAt = Math.min(
    ...projections.map((entry) => entry.activation_evidence_lease_expires_at),
  );
  const transcript = historicalTranscriptFromProjections(projections);
  return {
    schema: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
    status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_STATUS,
    truth_status: PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_TRUTH,
    evidence_mode: authority.evidence_mode,
    chain_id: CHAIN_ID,
    release_sha: authority.release_sha,
    release_authority_sha256: authoritySha256,
    deployment_intent_sha256: authority.deployment_intent_sha256,
    ceremony_nonce: authority.ceremony_nonce,
    measurement_policy_set_sha256: authority.qvl_measurement_policy_set_sha256,
    execution_order: [...PHALA_SEVEN_CVM_EXECUTION_ORDER],
    domains: projections,
    historical_transcript_file_set_sha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(transcript),
    issued_at: issuedAt,
    first_verified_at: firstVerifiedAt,
    last_verified_at: lastVerifiedAt,
    minimum_activation_evidence_lease_expires_at:
      minimumActivationEvidenceLeaseExpiresAt,
    proof_collection_skew_seconds: lastVerifiedAt - firstVerifiedAt,
    proofs_valid_at_issuance: true,
    verified_at: lastVerifiedAt,
    all_seven_machine_verified: true,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
}

export function phalaSevenCvmHistoricalEvidenceSetSha256(value) {
  assertCanonicalPlainDataGraph(value, {
    label: "historical seven-CVM evidence-set digest input",
  });
  return domainSha256(PHALA_SEVEN_CVM_VERIFIED_EVIDENCE_SET_DOMAIN, value);
}

/**
 * Reconstructs the exact historical v4 evidence bytes committed by signed R.
 *
 * `historicalEvidenceContext` is deliberately injectable: the enclosing
 * exact-37 validator must derive it from a separately authenticated L receipt,
 * the signed-R historical binding, and release-core policy. This function does
 * not authenticate B/C, mint a production brand, consult a clock, execute a
 * QVL, fetch Intel collateral, or authorize traffic.
 */
export function reconstructPhalaSevenCvmHistoricalEvidenceSet({
  rawArtifacts,
  historicalEvidenceContext,
  recoverPersonalSigner,
} = {}) {
  const raw = normalizeRaw14(rawArtifacts);
  for (const domain of Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE)) {
    const responseFlag = PHALA_SEVEN_CVM_VERIFIER_RAW_FLAGS[domain].second;
    const response = normalizeQvlIdentityResponse(raw[responseFlag].value);
    normalizedRawFile(raw[responseFlag], response, responseFlag);
    parsePhalaHistoricalTdxV4QuoteCandidates(
      Buffer.from(response.quote.slice(2), "hex"),
    );
  }
  const context = normalizePhalaSevenCvmHistoricalEvidenceContext(
    historicalEvidenceContext,
  );
  const binding = context.historical_runtime_binding;
  const authority = normalizePhalaSevenCvmReleaseVerificationAuthority(
    binding.release_verification_authority,
  );
  if (authority.evidence_mode !== PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE) {
    throw new TypeError(
      "historical evidence reconstruction requires production release authority",
    );
  }
  const authoritySha256 = phalaSevenCvmReleaseVerificationAuthoritySha256(authority);
  if (authoritySha256 !== binding.release_verification_authority_sha256
    || JSON.stringify(PHALA_SEVEN_CVM_RELEASE_VERIFICATION_EXECUTION_ORDER)
      !== JSON.stringify(PHALA_SEVEN_CVM_EXECUTION_ORDER)) {
    throw new TypeError("historical release-authority execution order drifted");
  }
  const contextByDomain = new Map(context.domains.map((entry) => [entry.domain, entry]));
  const identityByDomain = new Map();
  for (const domain of Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE)) {
    identityByDomain.set(domain, reconstructIdentityCandidates({
      domain,
      raw,
      authority,
      authoritySha256,
      domainContext: contextByDomain.get(domain),
    }));
  }
  const workloadByDomain = new Map();
  for (const [domain, link] of Object.entries(PHALA_WORKLOAD_DOMAIN_QVL_LINK)) {
    workloadByDomain.set(domain, reconstructWorkloadProof({
      domain,
      raw,
      authority,
      authoritySha256,
      domainContext: contextByDomain.get(domain),
      linkedIdentity: identityByDomain.get(link.qvl_domain),
      meteringPolicySetHash: context.independent_metering_policy_set_hash,
      recoverPersonalSigner,
    }));
  }
  const reconstructed = PHALA_SEVEN_CVM_EXECUTION_ORDER.map((domain) => (
    identityByDomain.get(domain) || workloadByDomain.get(domain)
  ));
  const projections = reconstructed.map((entry) => entry.projection);
  for (const field of ["app_id", "cvm_id", "compose_hash", "tee_identity", "evidence_sha256"]) {
    if (new Set(projections.map((entry) => entry[field])).size !== 7) {
      throw new TypeError(`historical seven-CVM ${field} values are not pairwise distinct`);
    }
  }
  const challengeIds = [];
  for (const identity of identityByDomain.values()) challengeIds.push(identity.proof.challenge_id);
  for (const workload of workloadByDomain.values()) challengeIds.push(workload.proof.challenge_id);
  if (new Set(challengeIds).size !== challengeIds.length) {
    throw new TypeError("historical raw14 challenge IDs are duplicated within the ceremony");
  }
  const transcript = historicalTranscriptFromProjections(projections);
  const transcriptSha256 = phalaSevenCvmHistoricalTranscriptFileSetSha256(transcript);
  if (transcriptSha256 !== context.historical_transcript_file_set_sha256) {
    throw new TypeError("historical raw14 file set differs from authenticated L");
  }
  const firstVerifiedAt = Math.min(...projections.map((entry) => entry.verified_at));
  const lastVerifiedAt = Math.max(...projections.map((entry) => entry.verified_at));
  const minimumActivationEvidenceLeaseExpiresAt = Math.min(
    ...projections.map((entry) => entry.activation_evidence_lease_expires_at),
  );
  if (lastVerifiedAt !== context.launch_completed_at
    || minimumActivationEvidenceLeaseExpiresAt
      !== binding.activation_evidence_lease_expires_at
    || lastVerifiedAt - firstVerifiedAt > 300
    || minimumActivationEvidenceLeaseExpiresAt <= lastVerifiedAt
    || minimumActivationEvidenceLeaseExpiresAt - lastVerifiedAt
      > PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS) {
    throw new TypeError("historical evidence timing differs from authenticated L/R");
  }
  const expectedEvidenceSetSha256 = binding.seven_cvm_verified_evidence_set_sha256;
  const matchingCandidates = [];
  for (let issuedAt = lastVerifiedAt;
    issuedAt < minimumActivationEvidenceLeaseExpiresAt;
    issuedAt += 1) {
    const candidate = historicalEvidenceSetCandidate({
      authority,
      authoritySha256,
      projections,
      issuedAt,
    });
    if (phalaSevenCvmHistoricalEvidenceSetSha256(candidate)
      === expectedEvidenceSetSha256) {
      matchingCandidates.push(candidate);
    }
  }
  if (matchingCandidates.length !== 1) {
    throw new TypeError(
      "signed R does not select one unique historical seven-CVM evidence-set issuance second",
    );
  }
  const evidenceSet = matchingCandidates[0];
  return deepFreezeCanonicalPlainDataGraph({
    schema: PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_RECONSTRUCTION_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_EVIDENCE_RECONSTRUCTION_TRUTH,
    historical_runtime_binding_sha256:
      phalaSevenCvmHistoricalRuntimeBindingSha256(binding),
    launch_completion_receipt_sha256:
      binding.seven_cvm_launch_completion_receipt_sha256,
    release_core_sha256: context.release_core_sha256,
    release_authority_sha256: authoritySha256,
    seven_cvm_verified_evidence_set_sha256: expectedEvidenceSetSha256,
    historical_transcript_file_set_sha256: transcriptSha256,
    evidence_set: evidenceSet,
    qvl_identity_evidence: Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE)
      .map((domain) => identityByDomain.get(domain).proof),
    workload_verdict_evidence: Object.keys(PHALA_WORKLOAD_DOMAIN_QVL_LINK)
      .map((domain) => workloadByDomain.get(domain).proof),
    identity_quote_body_types: Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE)
      .map((domain) => ({ domain, body_type: identityByDomain.get(domain).body_type })),
    all_seven_historical_evidence_roots_reconstructed: true,
    raw14_canonical_bytes_recomputed: true,
    workload_eip191_signatures_replayed: true,
    workload_signature_message_mode: "eip191_personal_sign_raw_bytes32",
    independent_signature_replay_verifier: INDEPENDENT_EIP191_REPLAY_VERIFIER,
    original_pinned_cast_verifier_reexecuted: false,
    raw_quote_present_in_private_input_files: true,
    raw_quote_not_embedded_in_derived_evidence_objects: true,
    legacy_raw_quote_persisted_field_is_not_a_global_persistence_claim: true,
    current_clock_consulted: false,
    dcap_reverified: false,
    intel_collateral_revalidated: false,
    freshness_renewed: false,
    production_brand_minted: false,
    live_traffic_authorized: false,
  }, { label: "seven-CVM historical evidence reconstruction" });
}
