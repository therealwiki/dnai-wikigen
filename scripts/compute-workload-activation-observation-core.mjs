import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  parseCanonicalPublicHttpsUrl,
} from "./canonical-public-https-url-core.mjs";
import {
  independentTdxVerdictSigningDigest,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  normalizePhalaComputeWorkloadRecipientSourceActivation,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientSourceActivationSha256,
} from "./phala-seven-cvm-historical-evidence-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    currentPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-v4-core.mjs";
import {
  PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA as
    LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA,
  phalaSevenCvmReleaseVerificationAuthoritySha256 as
    legacyPhalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";

export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA =
  "dnai.compute-workload-activation-observation.v3";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_DOMAIN =
  "dnai-wikigen/compute-workload-activation-observation/v3\0";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_STATUS =
  "compute_workload_recipient_activation_machine_verified";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_TRUTH =
  "private_nonauthorizing_initial_and_recipient_evidence_lease_bounded_prebuild_observation_not_live_traffic_or_deploy_authority";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_CLI_FLAG =
  "--compute-workload-activation-observation";
export const COMPUTE_WORKLOAD_CAPABILITY_PATH =
  "/compute/workload-encryption-contract";
export const COMPUTE_WORKLOAD_BROWSER_BINDING_DOMAIN =
  "dnai-wikigen/compute-workload-browser-binding/v2\0";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_SCHEMA =
  "dnai.compute-workload-activation-observation-historical-replay.v2";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_TRUTH =
  "persisted_observation_signature_and_caller_authenticated_signed_c_lineage_replayed_at_recorded_time_without_current_freshness_or_authority";
export const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_AUTHORITY_DOMAIN =
  "dnai-wikigen/compute-workload-activation-observation-historical-authority/v2\0";

export const COMPUTE_WORKLOAD_BROWSER_ENV_KEYS = Object.freeze([
  "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD",
  "VITE_COMPUTE_WORKLOAD_QVL_VERIFIER",
  "VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
  "VITE_COMPUTE_WORKLOAD_COMPOSE_HASH",
  "VITE_COMPUTE_WORKLOAD_APP_ID",
  "VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH",
  "VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER",
  "VITE_COMPUTE_WORKLOAD_CHAIN_ID",
  "VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS",
  "VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH",
  "VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
  "VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS",
  "VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON",
  "VITE_COMPUTE_WORKLOAD_CVM_ID",
  "VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
  "VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
  "VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE",
  "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
  "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256",
  "VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
]);

const CHAIN_ID = 84_532;
const SHA40 = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const MAX_ARTIFACT_BYTES = 256 * 1024;
const HISTORICAL_OBSERVATION_EXPECTATION_FIELDS = Object.freeze([
  "ceremonyAuthorizationSha256",
  "ceremonyNonce",
  "computeVaultAddress",
  "computeVaultRuntimeCodeHash",
  "computeWorkloadQvlAppId",
  "computeWorkloadQvlComposeHash",
  "computeWorkloadQvlCvmId",
  "computeWorkloadQvlIdentityEvidenceSha256",
  "computeWorkloadQvlMeasurementPolicySha256",
  "computeWorkloadQvlOsImageHash",
  "computeWorkloadQvlReleasePolicySha256",
  "computeWorkloadQvlVerifierAddress",
  "deploymentIntentSha256",
  "freshContractDeploymentReceiptSha256",
  "historicalTranscriptFileSetSha256",
  "mainRuntimeAppId",
  "mainRuntimeComposeHash",
  "mainRuntimeCvmId",
  "mainRuntimeDescriptorSha256",
  "mainRuntimeEvidenceSha256",
  "mainRuntimeOsImageHash",
  "mainRuntimePostureReceiptSha256",
  "mainRuntimeTeeIdentity",
  "nonliveBootstrapAuthorizationReceiptSha256",
  "postMeasurementActivationExecutionReceiptSha256",
  "postMeasurementActivationPlanSha256",
  "preCeremonyRuntimeAuthoritySha256",
  "qvlMeasurementPolicySetSha256",
  "releaseSha",
  "releaseVerificationAuthoritySha256",
  "sevenCvmLaunchCompletionReceiptSha256",
  "sevenCvmVerifiedEvidenceSetSha256",
  "initialActivationEvidenceLeaseExpiresAt",
  "recipientEvidenceLeaseExpiresAt",
  "terminalEvidenceLeaseExpiresAt",
]);
const INDEPENDENT_VERDICT_ARTIFACT_DOMAIN =
  "dnai-wikigen/independent-tdx-verdict-artifact/v4\0";
const PHALA_RAW_VERIFIER_TRANSCRIPT_DOMAIN =
  "dnai-wikigen/phala-raw-verifier-transcript/v1\0";

function fail(message) {
  throw new Error(message);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function versionedReleaseVerificationAuthoritySha256(value) {
  const descriptor = isRecord(value)
    ? Object.getOwnPropertyDescriptor(value, "schema")
    : null;
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    fail("O producer release authority requires one own data schema");
  }
  if (descriptor.value
      === PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return currentPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  if (descriptor.value
      === LEGACY_PHALA_SEVEN_CVM_RELEASE_VERIFICATION_AUTHORITY_SCHEMA) {
    return legacyPhalaSevenCvmReleaseVerificationAuthoritySha256(value);
  }
  fail("O producer release authority schema version is unsupported");
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
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
  const text = `${JSON.stringify(sorted(value), null, 2)}\n`;
  if (Buffer.byteLength(text, "utf8") > MAX_ARTIFACT_BYTES) {
    fail("compute-workload activation observation exceeds the byte bound");
  }
  return text;
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function bytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    fail(`${label} must be a nonzero lowercase bytes32`);
  }
  return value;
}

function address(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function bareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    fail(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function appId(value, label) {
  if (typeof value !== "string" || !APP_ID.test(value)) {
    fail(`${label} must be a nonzero bare lowercase Phala app ID`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    fail(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function second(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_102_444_800) {
    fail(`${label} must be a bounded Unix second`);
  }
  return value;
}

function shaToBytes32(value, label) {
  return `0x${sha256(value, label).slice("sha256:".length)}`;
}

function normalizeCapabilityEndpoint(value) {
  if (typeof value !== "string" || value.length > 512) {
    fail("compute-workload capability endpoint is invalid");
  }
  let parsed;
  try {
    parsed = parseCanonicalPublicHttpsUrl(value, {
      label: "compute-workload capability endpoint",
      requirePath: true,
      maximumBytes: 512,
    });
  } catch {
    fail("compute-workload capability endpoint is invalid");
  }
  if (parsed.pathname !== COMPUTE_WORKLOAD_CAPABILITY_PATH
    || parsed.port
    || parsed.href !== value) {
    fail("compute-workload capability endpoint must be one exact public HTTPS origin and path");
  }
  return parsed.href;
}

function normalizeLineage(value) {
  const parsed = exactRecord(value, [
    "ceremony_nonce",
    "ceremony_authorization_sha256",
    "deployment_intent_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "historical_transcript_file_set_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "post_measurement_activation_execution_receipt_sha256",
    "post_measurement_activation_plan_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "qvl_measurement_policy_set_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
  ], "compute-workload observation lineage");
  return {
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "compute-workload observation deployment intent",
    ),
    release_verification_authority_sha256: sha256(
      parsed.release_verification_authority_sha256,
      "compute-workload observation release verification authority",
    ),
    ceremony_nonce: bytes32(
      parsed.ceremony_nonce,
      "compute-workload observation ceremony nonce",
    ),
    qvl_measurement_policy_set_sha256: sha256(
      parsed.qvl_measurement_policy_set_sha256,
      "compute-workload observation QVL measurement policy set",
    ),
    historical_transcript_file_set_sha256: sha256(
      parsed.historical_transcript_file_set_sha256,
      "compute-workload observation historical transcript file set",
    ),
    fresh_contract_deployment_receipt_sha256: sha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "compute-workload observation fresh contract receipt",
    ),
    nonlive_bootstrap_authorization_receipt_sha256: sha256(
      parsed.nonlive_bootstrap_authorization_receipt_sha256,
      "compute-workload observation non-live bootstrap receipt",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "compute-workload observation seven-CVM launch completion",
    ),
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "compute-workload observation seven-CVM verified evidence set",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "compute-workload observation pre-ceremony runtime authority",
    ),
    post_measurement_activation_plan_sha256: sha256(
      parsed.post_measurement_activation_plan_sha256,
      "compute-workload observation post-measurement activation plan",
    ),
    post_measurement_activation_execution_receipt_sha256: sha256(
      parsed.post_measurement_activation_execution_receipt_sha256,
      "compute-workload observation post-measurement activation execution receipt",
    ),
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "compute-workload observation ceremony authorization",
    ),
  };
}

function normalizeMainRuntime(value) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "descriptor_sha256", "os_image_hash",
    "posture_receipt_sha256", "seven_cvm_domain_evidence_sha256", "tee_identity",
  ], "compute-workload observation main runtime");
  return {
    app_id: appId(parsed.app_id, "main runtime app ID"),
    cvm_id: identifier(parsed.cvm_id, "main runtime CVM ID"),
    compose_hash: bareSha256(parsed.compose_hash, "main runtime compose hash"),
    os_image_hash: bareSha256(parsed.os_image_hash, "main runtime OS image hash"),
    descriptor_sha256: sha256(
      parsed.descriptor_sha256,
      "main runtime descriptor digest",
    ),
    posture_receipt_sha256: sha256(
      parsed.posture_receipt_sha256,
      "main runtime posture receipt digest",
    ),
    tee_identity: address(parsed.tee_identity, "main runtime TEE identity"),
    seven_cvm_domain_evidence_sha256: sha256(
      parsed.seven_cvm_domain_evidence_sha256,
      "main runtime seven-CVM evidence digest",
    ),
  };
}

function normalizeComputeWorkloadQvl(value) {
  const parsed = exactRecord(value, [
    "app_id", "compose_hash", "cvm_id", "identity_evidence_sha256",
    "measurement_policy_sha256", "os_image_hash", "release_policy_sha256",
    "seven_cvm_domain_evidence_sha256", "verifier_address",
  ], "compute-workload observation QVL");
  return {
    app_id: appId(parsed.app_id, "compute-workload QVL app ID"),
    cvm_id: identifier(parsed.cvm_id, "compute-workload QVL CVM ID"),
    compose_hash: bareSha256(parsed.compose_hash, "compute-workload QVL compose hash"),
    os_image_hash: bareSha256(parsed.os_image_hash, "compute-workload QVL OS image hash"),
    verifier_address: address(parsed.verifier_address, "compute-workload QVL verifier"),
    release_policy_sha256: sha256(
      parsed.release_policy_sha256,
      "compute-workload QVL release policy",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "compute-workload QVL measurement policy",
    ),
    identity_evidence_sha256: sha256(
      parsed.identity_evidence_sha256,
      "compute-workload QVL identity evidence",
    ),
    seven_cvm_domain_evidence_sha256: sha256(
      parsed.seven_cvm_domain_evidence_sha256,
      "compute-workload QVL seven-CVM evidence digest",
    ),
  };
}

function normalizeComputeVault(value) {
  const parsed = exactRecord(value, ["address", "runtime_code_hash"],
    "compute-workload observation vault");
  return {
    address: address(parsed.address, "ComputeCreditVault address"),
    runtime_code_hash: bytes32(
      parsed.runtime_code_hash,
      "ComputeCreditVault runtime code hash",
    ),
  };
}

function normalizeRecipient(value) {
  const parsed = exactRecord(value, [
    "activation_signer_address", "activation_signer_custody",
    "activation_signer_key_path", "encryption_public_key", "recipient_key_id",
    "recipient_release_commitment", "report_data",
  ], "compute-workload observation recipient");
  if (parsed.activation_signer_key_path !== "tinker/compute_workload_activation_signer"
    || parsed.activation_signer_custody
      !== "dstack_derived_compute_workload_activation_signer") {
    fail("compute-workload activation signer purpose or custody is invalid");
  }
  return {
    encryption_public_key: bareSha256(
      parsed.encryption_public_key,
      "compute-workload recipient encryption public key",
    ),
    recipient_key_id: sha256(parsed.recipient_key_id, "compute-workload recipient key ID"),
    report_data: bytes32(parsed.report_data, "compute-workload recipient report data"),
    recipient_release_commitment: sha256(
      parsed.recipient_release_commitment,
      "compute-workload recipient release commitment",
    ),
    activation_signer_address: address(
      parsed.activation_signer_address,
      "compute-workload activation signer",
    ),
    activation_signer_key_path: parsed.activation_signer_key_path,
    activation_signer_custody: parsed.activation_signer_custody,
  };
}

function normalizeVerification(value) {
  const parsed = exactRecord(value, [
    "activation_artifact_sha256", "activation_verification_sha256",
    "authenticated_at", "challenge_digest", "challenge_expires_at",
    "challenge_id", "challenge_issued_at", "qvl_verdict_artifact_sha256",
    "qvl_verdict_signing_digest", "qvl_verdict_verifier_signature_sha256",
    "raw_transcript_sha256", "tdx_quote_sha256", "verdict_expires_at",
    "verdict_issued_at", "verified_at",
    "verdict_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "activation_verification_expires_at",
  ], "compute-workload observation verification");
  const challengeIssued = second(parsed.challenge_issued_at, "workload challenge issued_at");
  const challengeExpires = second(parsed.challenge_expires_at, "workload challenge expires_at");
  const verdictIssued = second(parsed.verdict_issued_at, "workload verdict issued_at");
  const verdictExpires = second(parsed.verdict_expires_at, "workload verdict expires_at");
  const verdictActivationEvidenceLeaseExpires = second(
    parsed.verdict_activation_evidence_lease_expires_at,
    "workload verdict activation-evidence lease expires_at",
  );
  const recipientEvidenceLeaseExpires = second(
    parsed.recipient_evidence_lease_expires_at,
    "workload recipient evidence lease expires_at",
  );
  const activationVerificationExpires = second(
    parsed.activation_verification_expires_at,
    "workload activation verification expires_at",
  );
  const authenticatedAt = second(parsed.authenticated_at, "workload authenticated_at");
  const verifiedAt = second(parsed.verified_at, "workload verified_at");
  if (challengeExpires <= challengeIssued || challengeExpires - challengeIssued > 120
    || verdictIssued < challengeIssued || verdictIssued >= challengeExpires
    || verdictExpires <= verdictIssued || verdictExpires - verdictIssued > 300
    || verdictActivationEvidenceLeaseExpires !== verdictExpires
    || recipientEvidenceLeaseExpires !== verdictActivationEvidenceLeaseExpires
    || activationVerificationExpires > recipientEvidenceLeaseExpires
    || authenticatedAt < verdictIssued - 30 || authenticatedAt >= verdictExpires
    || verifiedAt < authenticatedAt
    || verifiedAt >= activationVerificationExpires) {
    fail("compute-workload observation freshness chain is invalid");
  }
  return {
    activation_verification_sha256: sha256(
      parsed.activation_verification_sha256,
      "compute-workload activation verification digest",
    ),
    activation_artifact_sha256: sha256(
      parsed.activation_artifact_sha256,
      "compute-workload activation artifact digest",
    ),
    challenge_id: bytes32(parsed.challenge_id, "compute-workload challenge ID"),
    challenge_digest: bytes32(parsed.challenge_digest, "compute-workload challenge digest"),
    challenge_issued_at: challengeIssued,
    challenge_expires_at: challengeExpires,
    tdx_quote_sha256: sha256(parsed.tdx_quote_sha256, "compute-workload quote digest"),
    qvl_verdict_signing_digest: bytes32(
      parsed.qvl_verdict_signing_digest,
      "compute-workload verdict signing digest",
    ),
    qvl_verdict_artifact_sha256: sha256(
      parsed.qvl_verdict_artifact_sha256,
      "compute-workload verdict artifact digest",
    ),
    qvl_verdict_verifier_signature_sha256: sha256(
      parsed.qvl_verdict_verifier_signature_sha256,
      "compute-workload verdict signature digest",
    ),
    raw_transcript_sha256: sha256(
      parsed.raw_transcript_sha256,
      "compute-workload activation raw transcript commitment",
    ),
    verdict_issued_at: verdictIssued,
    verdict_activation_evidence_lease_expires_at:
      verdictActivationEvidenceLeaseExpires,
    verdict_expires_at: verdictExpires,
    recipient_evidence_lease_expires_at: recipientEvidenceLeaseExpires,
    activation_verification_expires_at: activationVerificationExpires,
    authenticated_at: authenticatedAt,
    verified_at: verifiedAt,
  };
}

function normalizeIngressPolicy(value) {
  const parsed = exactRecord(value, [
    "max_verdict_age_seconds", "revoked_quote_hashes",
  ], "compute-workload observation ingress policy");
  if (!Number.isSafeInteger(parsed.max_verdict_age_seconds)
    || parsed.max_verdict_age_seconds < 1 || parsed.max_verdict_age_seconds > 300) {
    fail("compute-workload maximum verdict age must be 1 through 300 seconds");
  }
  if (!Array.isArray(parsed.revoked_quote_hashes)
    || parsed.revoked_quote_hashes.length > 256) {
    fail("compute-workload revoked quote list is incomplete or unbounded");
  }
  const revoked = parsed.revoked_quote_hashes.map((entry, index) =>
    bytes32(entry, `compute-workload revoked quote hash ${index}`));
  if (new Set(revoked).size !== revoked.length
    || revoked.some((entry, index) => index > 0 && revoked[index - 1] >= entry)) {
    fail("compute-workload revoked quote hashes must be strictly sorted and unique");
  }
  return {
    max_verdict_age_seconds: parsed.max_verdict_age_seconds,
    revoked_quote_hashes: revoked,
  };
}

function assertSourceActivationProjection({
  lineage,
  mainRuntime,
  qvl,
  vault,
  recipient,
  verification,
  sourceActivation,
}) {
  const verdict = sourceActivation.authenticated_verdict;
  const attestation = sourceActivation.recipient_attestation;
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const activationArtifactSha256 =
    phalaComputeWorkloadRecipientSourceActivationSha256(sourceActivation);
  if (
    lineage.deployment_intent_sha256
      !== sourceActivation.deployment_intent_sha256
    || lineage.release_verification_authority_sha256
      !== sourceActivation.release_authority_sha256
    || lineage.ceremony_nonce !== sourceActivation.ceremony_nonce
    || lineage.qvl_measurement_policy_set_sha256
      !== sourceActivation.measurement_policy_set_sha256
    || mainRuntime.cvm_id !== sourceActivation.cvm_id
    || mainRuntime.app_id !== sourceActivation.app_id
    || `0x${mainRuntime.compose_hash}` !== sourceActivation.compose_hash
    || mainRuntime.os_image_hash !== sourceActivation.os_image_hash
    || mainRuntime.seven_cvm_domain_evidence_sha256
      !== sourceActivation.main_runtime_evidence_sha256
    || qvl.verifier_address !== sourceActivation.verifier_address
    || qvl.measurement_policy_sha256
      !== sourceActivation.measurement_policy_sha256
    || shaToBytes32(qvl.release_policy_sha256, "compute-workload QVL policy")
      !== sourceActivation.release_policy_hash
    || vault.address !== attestation.compute_vault_address
    || vault.runtime_code_hash !== attestation.compute_vault_runtime_code_hash
    || shaToBytes32(
      lineage.fresh_contract_deployment_receipt_sha256,
      "fresh contract deployment receipt",
    ) !== attestation.fresh_contract_deployment_receipt_sha256
    || recipient.encryption_public_key !== attestation.encryption_public_key
    || recipient.recipient_key_id !== sourceActivation.recipient_key_id
    || recipient.recipient_key_id !== attestation.key_id
    || recipient.report_data !== sourceActivation.report_data
    || recipient.recipient_release_commitment
      !== sourceActivation.recipient_release_commitment
    || recipient.activation_signer_address !== attestation.activation_signer_address
    || recipient.activation_signer_address !== verdict.signer_address
    || recipient.activation_signer_key_path !== attestation.activation_signer_key_path
    || recipient.activation_signer_custody !== attestation.activation_signer_custody
    || verification.activation_artifact_sha256 !== activationArtifactSha256
    || verification.challenge_id !== verdict.challenge_id
    || verification.challenge_digest !== verdict.challenge_digest
    || verification.challenge_issued_at !== verdict.challenge_issued_at
    || verification.challenge_expires_at !== verdict.challenge_expires_at
    || shaToBytes32(verification.tdx_quote_sha256, "compute-workload quote")
      !== sourceActivation.quote_hash
    || sourceActivation.quote_hash !== verdict.quote_hash
    || verification.qvl_verdict_signing_digest !== signingDigest
    || sourceActivation.verdict_digest !== signingDigest
    || sourceActivation.verifier_address !== verdict.verifier_address
    || sourceActivation.report_data !== verdict.report_data
    || sourceActivation.compose_hash !== verdict.compose_hash
    || sourceActivation.app_id !== verdict.app_id
    || sourceActivation.os_image_hash !== verdict.os_image_hash
    || sourceActivation.release_policy_hash !== verdict.release_policy_hash
    || sourceActivation.issued_at !== verdict.issued_at
    || sourceActivation.recipient_evidence_lease_expires_at
      !== verdict.activation_evidence_lease_expires_at
    || sourceActivation.expires_at !== verdict.expires_at
    || verification.verdict_issued_at !== verdict.issued_at
    || verification.verdict_activation_evidence_lease_expires_at
      !== verdict.activation_evidence_lease_expires_at
    || verification.verdict_expires_at !== verdict.expires_at
    || verification.recipient_evidence_lease_expires_at
      !== sourceActivation.recipient_evidence_lease_expires_at
    || verification.authenticated_at !== sourceActivation.authenticated_at
  ) {
    fail("compute-workload source activation differs from the exact O projection");
  }
}

export function normalizeComputeWorkloadActivationObservation(value) {
  const parsed = exactRecord(value, [
    "capability_endpoint", "chain_id", "compute_vault", "compute_workload_qvl",
    "deploy_authorized", "ingress_policy", "lineage", "live_traffic_authorized",
    "main_runtime", "raw_quote_persisted", "raw_secret_egress", "recipient",
    "release_sha", "schema", "source_activation", "status", "truth_status",
    "verification", "initial_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "terminal_evidence_lease_expires_at",
  ], "compute-workload activation observation");
  if (parsed.schema !== COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA
    || parsed.status !== COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_STATUS
    || parsed.truth_status !== COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_TRUTH
    || parsed.chain_id !== CHAIN_ID || !SHA40.test(String(parsed.release_sha || ""))
    || parsed.live_traffic_authorized !== false || parsed.deploy_authorized !== false
    || parsed.raw_quote_persisted !== false || parsed.raw_secret_egress !== false) {
    fail("compute-workload activation observation truth or release boundary is invalid");
  }
  const lineage = normalizeLineage(parsed.lineage);
  const mainRuntime = normalizeMainRuntime(parsed.main_runtime);
  const qvl = normalizeComputeWorkloadQvl(parsed.compute_workload_qvl);
  const vault = normalizeComputeVault(parsed.compute_vault);
  const recipient = normalizeRecipient(parsed.recipient);
  const verification = normalizeVerification(parsed.verification);
  const sourceActivation =
    normalizePhalaComputeWorkloadRecipientSourceActivation(
      parsed.source_activation,
    );
  const policy = normalizeIngressPolicy(parsed.ingress_policy);
  const initialActivationEvidenceLeaseExpiresAt = second(
    parsed.initial_activation_evidence_lease_expires_at,
    "compute-workload O initial activation-evidence lease expires_at",
  );
  const recipientEvidenceLeaseExpiresAt = second(
    parsed.recipient_evidence_lease_expires_at,
    "compute-workload O recipient evidence lease expires_at",
  );
  const terminalEvidenceLeaseExpiresAt = second(
    parsed.terminal_evidence_lease_expires_at,
    "compute-workload O terminal evidence lease expires_at",
  );
  if (qvl.verifier_address === recipient.activation_signer_address
    || mainRuntime.tee_identity === recipient.activation_signer_address
    || mainRuntime.tee_identity === qvl.verifier_address) {
    fail("compute-workload main signer, activation signer, and QVL verifier must be distinct");
  }
  if (new Set([
    qvl.identity_evidence_sha256,
    verification.activation_verification_sha256,
    verification.activation_artifact_sha256,
  ]).size !== 3) {
    fail("compute-workload QVL identity, activation proof, and source artifact cannot collapse");
  }
  if (verification.verified_at - verification.verdict_issued_at
      > policy.max_verdict_age_seconds
    || policy.revoked_quote_hashes.includes(
      shaToBytes32(verification.tdx_quote_sha256, "compute-workload quote digest"),
    )) {
    fail("compute-workload observation is stale or its quote is revoked");
  }
  if (recipientEvidenceLeaseExpiresAt
      !== verification.recipient_evidence_lease_expires_at
    || terminalEvidenceLeaseExpiresAt !== Math.min(
      initialActivationEvidenceLeaseExpiresAt,
      recipientEvidenceLeaseExpiresAt,
    )
    || terminalEvidenceLeaseExpiresAt
      > verification.activation_verification_expires_at
    || verification.verified_at >= terminalEvidenceLeaseExpiresAt) {
    fail("compute-workload observation evidence-lease chain is invalid");
  }
  if (shaToBytes32(
    lineage.fresh_contract_deployment_receipt_sha256,
    "fresh contract deployment receipt",
  ) === vault.runtime_code_hash) {
    fail("fresh deployment receipt and vault runtime hash must remain distinct roots");
  }
  assertSourceActivationProjection({
    lineage,
    mainRuntime,
    qvl,
    vault,
    recipient,
    verification,
    sourceActivation,
  });
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    chain_id: CHAIN_ID,
    capability_endpoint: normalizeCapabilityEndpoint(parsed.capability_endpoint),
    lineage,
    main_runtime: mainRuntime,
    compute_workload_qvl: qvl,
    compute_vault: vault,
    recipient,
    verification,
    source_activation: sourceActivation,
    initial_activation_evidence_lease_expires_at:
      initialActivationEvidenceLeaseExpiresAt,
    recipient_evidence_lease_expires_at: recipientEvidenceLeaseExpiresAt,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpiresAt,
    ingress_policy: policy,
    live_traffic_authorized: false,
    deploy_authorized: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  };
}

export function canonicalComputeWorkloadActivationObservationText(value) {
  return canonicalText(normalizeComputeWorkloadActivationObservation(value));
}

export function computeWorkloadActivationObservationSha256(value) {
  return domainSha256(
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_DOMAIN,
    normalizeComputeWorkloadActivationObservation(value),
  );
}

function normalizeHistoricalObservationExpectations(value) {
  const parsed = exactRecord(
    value,
    HISTORICAL_OBSERVATION_EXPECTATION_FIELDS,
    "historical compute-workload O expectations",
  );
  if (typeof parsed.releaseSha !== "string" || !SHA40.test(parsed.releaseSha)) {
    fail("historical compute-workload O release SHA is invalid");
  }
  const initialActivationEvidenceLeaseExpiresAt = second(
    parsed.initialActivationEvidenceLeaseExpiresAt,
    "historical O initial activation-evidence lease expiry",
  );
  const recipientEvidenceLeaseExpiresAt = second(
    parsed.recipientEvidenceLeaseExpiresAt,
    "historical O recipient evidence lease expiry",
  );
  const terminalEvidenceLeaseExpiresAt = second(
    parsed.terminalEvidenceLeaseExpiresAt,
    "historical O terminal evidence lease expiry",
  );
  if (terminalEvidenceLeaseExpiresAt !== Math.min(
    initialActivationEvidenceLeaseExpiresAt,
    recipientEvidenceLeaseExpiresAt,
  )) {
    fail("historical O terminal evidence lease is not the exact source minimum");
  }
  return {
    releaseSha: parsed.releaseSha,
    deploymentIntentSha256: sha256(
      parsed.deploymentIntentSha256,
      "historical O deployment intent",
    ),
    releaseVerificationAuthoritySha256: sha256(
      parsed.releaseVerificationAuthoritySha256,
      "historical O release verification authority",
    ),
    ceremonyNonce: bytes32(parsed.ceremonyNonce, "historical O ceremony nonce"),
    qvlMeasurementPolicySetSha256: sha256(
      parsed.qvlMeasurementPolicySetSha256,
      "historical O QVL measurement policy set",
    ),
    historicalTranscriptFileSetSha256: sha256(
      parsed.historicalTranscriptFileSetSha256,
      "historical O transcript file set",
    ),
    freshContractDeploymentReceiptSha256: sha256(
      parsed.freshContractDeploymentReceiptSha256,
      "historical O fresh contract receipt",
    ),
    nonliveBootstrapAuthorizationReceiptSha256: sha256(
      parsed.nonliveBootstrapAuthorizationReceiptSha256,
      "historical O non-live bootstrap receipt",
    ),
    sevenCvmLaunchCompletionReceiptSha256: sha256(
      parsed.sevenCvmLaunchCompletionReceiptSha256,
      "historical O seven-CVM launch completion",
    ),
    sevenCvmVerifiedEvidenceSetSha256: sha256(
      parsed.sevenCvmVerifiedEvidenceSetSha256,
      "historical O seven-CVM verified evidence set",
    ),
    initialActivationEvidenceLeaseExpiresAt,
    recipientEvidenceLeaseExpiresAt,
    terminalEvidenceLeaseExpiresAt,
    preCeremonyRuntimeAuthoritySha256: sha256(
      parsed.preCeremonyRuntimeAuthoritySha256,
      "historical O pre-ceremony runtime authority",
    ),
    postMeasurementActivationPlanSha256: sha256(
      parsed.postMeasurementActivationPlanSha256,
      "historical O activation plan",
    ),
    postMeasurementActivationExecutionReceiptSha256: sha256(
      parsed.postMeasurementActivationExecutionReceiptSha256,
      "historical O activation execution receipt",
    ),
    ceremonyAuthorizationSha256: sha256(
      parsed.ceremonyAuthorizationSha256,
      "historical O ceremony authorization",
    ),
    mainRuntimeAppId: appId(parsed.mainRuntimeAppId, "historical O main app ID"),
    mainRuntimeCvmId: identifier(
      parsed.mainRuntimeCvmId,
      "historical O main CVM ID",
    ),
    mainRuntimeComposeHash: bareSha256(
      parsed.mainRuntimeComposeHash,
      "historical O main compose hash",
    ),
    mainRuntimeOsImageHash: bareSha256(
      parsed.mainRuntimeOsImageHash,
      "historical O main OS image hash",
    ),
    mainRuntimeDescriptorSha256: sha256(
      parsed.mainRuntimeDescriptorSha256,
      "historical O main descriptor",
    ),
    mainRuntimePostureReceiptSha256: sha256(
      parsed.mainRuntimePostureReceiptSha256,
      "historical O main posture receipt",
    ),
    mainRuntimeTeeIdentity: address(
      parsed.mainRuntimeTeeIdentity,
      "historical O main TEE identity",
    ),
    mainRuntimeEvidenceSha256: sha256(
      parsed.mainRuntimeEvidenceSha256,
      "historical O main launch evidence",
    ),
    computeWorkloadQvlAppId: appId(
      parsed.computeWorkloadQvlAppId,
      "historical O compute-workload QVL app ID",
    ),
    computeWorkloadQvlCvmId: identifier(
      parsed.computeWorkloadQvlCvmId,
      "historical O compute-workload QVL CVM ID",
    ),
    computeWorkloadQvlComposeHash: bareSha256(
      parsed.computeWorkloadQvlComposeHash,
      "historical O compute-workload QVL compose hash",
    ),
    computeWorkloadQvlOsImageHash: bareSha256(
      parsed.computeWorkloadQvlOsImageHash,
      "historical O compute-workload QVL OS image hash",
    ),
    computeWorkloadQvlVerifierAddress: address(
      parsed.computeWorkloadQvlVerifierAddress,
      "historical O compute-workload QVL verifier",
    ),
    computeWorkloadQvlReleasePolicySha256: sha256(
      parsed.computeWorkloadQvlReleasePolicySha256,
      "historical O compute-workload QVL release policy",
    ),
    computeWorkloadQvlMeasurementPolicySha256: sha256(
      parsed.computeWorkloadQvlMeasurementPolicySha256,
      "historical O compute-workload QVL measurement policy",
    ),
    computeWorkloadQvlIdentityEvidenceSha256: sha256(
      parsed.computeWorkloadQvlIdentityEvidenceSha256,
      "historical O compute-workload QVL identity evidence",
    ),
    computeVaultAddress: address(
      parsed.computeVaultAddress,
      "historical O ComputeCreditVault address",
    ),
    computeVaultRuntimeCodeHash: bytes32(
      parsed.computeVaultRuntimeCodeHash,
      "historical O ComputeCreditVault runtime hash",
    ),
  };
}

function historicalObservationAuthoritySha256({
  expectedAuthority,
  authorizedAt,
}) {
  return domainSha256(
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_AUTHORITY_DOMAIN,
    {
      authorized_at: authorizedAt,
      expected_authority: expectedAuthority,
    },
  );
}

function reconstructHistoricalObservationReplay({
  persistedObservation,
  expectedAuthority,
  authorizedAt,
}) {
  const observation = normalizeComputeWorkloadActivationObservation(
    persistedObservation,
  );
  const authority = normalizeHistoricalObservationExpectations(expectedAuthority);
  second(authorizedAt, "historical compute-workload O signed-C time");
  const lineage = observation.lineage;
  const main = observation.main_runtime;
  const qvl = observation.compute_workload_qvl;
  const vault = observation.compute_vault;
  if (
    observation.release_sha !== authority.releaseSha
    || lineage.deployment_intent_sha256 !== authority.deploymentIntentSha256
    || lineage.release_verification_authority_sha256
      !== authority.releaseVerificationAuthoritySha256
    || lineage.ceremony_nonce !== authority.ceremonyNonce
    || lineage.qvl_measurement_policy_set_sha256
      !== authority.qvlMeasurementPolicySetSha256
    || lineage.historical_transcript_file_set_sha256
      !== authority.historicalTranscriptFileSetSha256
    || lineage.fresh_contract_deployment_receipt_sha256
      !== authority.freshContractDeploymentReceiptSha256
    || lineage.nonlive_bootstrap_authorization_receipt_sha256
      !== authority.nonliveBootstrapAuthorizationReceiptSha256
    || lineage.seven_cvm_launch_completion_receipt_sha256
      !== authority.sevenCvmLaunchCompletionReceiptSha256
    || lineage.seven_cvm_verified_evidence_set_sha256
      !== authority.sevenCvmVerifiedEvidenceSetSha256
    || lineage.pre_ceremony_runtime_authority_sha256
      !== authority.preCeremonyRuntimeAuthoritySha256
    || lineage.post_measurement_activation_plan_sha256
      !== authority.postMeasurementActivationPlanSha256
    || lineage.post_measurement_activation_execution_receipt_sha256
      !== authority.postMeasurementActivationExecutionReceiptSha256
    || lineage.ceremony_authorization_sha256
      !== authority.ceremonyAuthorizationSha256
    || main.app_id !== authority.mainRuntimeAppId
    || main.cvm_id !== authority.mainRuntimeCvmId
    || main.compose_hash !== authority.mainRuntimeComposeHash
    || main.os_image_hash !== authority.mainRuntimeOsImageHash
    || main.descriptor_sha256 !== authority.mainRuntimeDescriptorSha256
    || main.posture_receipt_sha256
      !== authority.mainRuntimePostureReceiptSha256
    || main.tee_identity !== authority.mainRuntimeTeeIdentity
    || main.seven_cvm_domain_evidence_sha256
      !== authority.mainRuntimeEvidenceSha256
    || qvl.app_id !== authority.computeWorkloadQvlAppId
    || qvl.cvm_id !== authority.computeWorkloadQvlCvmId
    || qvl.compose_hash !== authority.computeWorkloadQvlComposeHash
    || qvl.os_image_hash !== authority.computeWorkloadQvlOsImageHash
    || qvl.verifier_address !== authority.computeWorkloadQvlVerifierAddress
    || qvl.release_policy_sha256
      !== authority.computeWorkloadQvlReleasePolicySha256
    || qvl.measurement_policy_sha256
      !== authority.computeWorkloadQvlMeasurementPolicySha256
    || qvl.identity_evidence_sha256
      !== authority.computeWorkloadQvlIdentityEvidenceSha256
    || qvl.seven_cvm_domain_evidence_sha256
      !== authority.computeWorkloadQvlIdentityEvidenceSha256
    || vault.address !== authority.computeVaultAddress
    || vault.runtime_code_hash !== authority.computeVaultRuntimeCodeHash
    || observation.initial_activation_evidence_lease_expires_at
      !== authority.initialActivationEvidenceLeaseExpiresAt
    || observation.recipient_evidence_lease_expires_at
      !== authority.recipientEvidenceLeaseExpiresAt
    || observation.terminal_evidence_lease_expires_at
      !== authority.terminalEvidenceLeaseExpiresAt
    || authorizedAt < observation.verification.verified_at
    || authorizedAt >= observation.terminal_evidence_lease_expires_at
  ) {
    fail("persisted compute-workload O differs from signed-C historical authority");
  }

  const verdict = observation.source_activation.authenticated_verdict;
  const signingDigest = independentTdxVerdictSigningDigest(verdict);
  const verdictArtifactSha256 = domainSha256(
    INDEPENDENT_VERDICT_ARTIFACT_DOMAIN,
    verdict,
  );
  const rawTranscriptSha256 = domainSha256(
    PHALA_RAW_VERIFIER_TRANSCRIPT_DOMAIN,
    {
      schema: "dnai.phala-raw-verifier-transcript.v1",
      chain_id: CHAIN_ID,
      domain: "main_runtime_cvm",
      kind: "compute_workload_recipient_activation",
      artifact_sha256: [
        observation.verification.activation_artifact_sha256,
        verdictArtifactSha256,
      ],
    },
  );
  const signatureReceipt = verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest: signingDigest,
    signature: verdict.verifier_signature,
  });
  if (
    signingDigest !== observation.verification.qvl_verdict_signing_digest
    || verdictArtifactSha256
      !== observation.verification.qvl_verdict_artifact_sha256
    || rawTranscriptSha256 !== observation.verification.raw_transcript_sha256
    || signatureReceipt.signature_sha256
      !== observation.verification.qvl_verdict_verifier_signature_sha256
  ) {
    fail("persisted compute-workload O signature or transcript digest is invalid");
  }
  return deepFreezeCanonicalPlainDataGraph({
    schema:
      COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_SCHEMA,
    truth_status:
      COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_TRUTH,
    observation,
    observation_sha256:
      computeWorkloadActivationObservationSha256(observation),
    expected_authority: authority,
    expected_authority_sha256: historicalObservationAuthoritySha256({
      expectedAuthority: authority,
      authorizedAt,
    }),
    authorized_at: authorizedAt,
    qvl_verdict_signing_digest: signingDigest,
    qvl_verdict_artifact_sha256: verdictArtifactSha256,
    qvl_verdict_signature_sha256: signatureReceipt.signature_sha256,
    raw_transcript_sha256: rawTranscriptSha256,
    signature_message_mode: "eip191_personal_sign_raw_bytes32",
    independent_signature_replay_verifier:
      INDEPENDENT_EIP191_REPLAY_VERIFIER,
    independent_signature_replay_performed: true,
    original_pinned_cast_verifier_reexecuted: false,
    current_clock_consulted: false,
    freshness_renewed: false,
    production_brand_minted: false,
    deploy_authorized: false,
    live_traffic_authorized: false,
  }, { label: "historical compute-workload activation replay result" });
}

/**
 * Revalidate persisted O as historical signed-C evidence.
 *
 * This verifies the embedded QVL signature and every available digest and
 * lineage projection at the original Stage-C signing instant. It deliberately
 * does not compare against the current clock, refresh a QVL challenge, rerun
 * DCAP, or turn O into live-traffic/deployment authority. The returned plain
 * result is serializable and can be revalidated after cloning; it is not a
 * process-local identity brand.
 */
export function assertHistoricallyVerifiedComputeWorkloadActivationObservation(
  input = {},
) {
  const parsed = exactRecord(input, [
    "authorizedAtMs", "expected", "persistedObservation",
  ], "historical compute-workload O replay input");
  if (!Number.isSafeInteger(parsed.authorizedAtMs)
    || parsed.authorizedAtMs < 1 || parsed.authorizedAtMs % 1_000 !== 0) {
    fail("historical compute-workload O requires the exact signed-C second");
  }
  return reconstructHistoricalObservationReplay({
    persistedObservation: parsed.persistedObservation,
    expectedAuthority: parsed.expected,
    authorizedAt: parsed.authorizedAtMs / 1_000,
  });
}

export function normalizeComputeWorkloadActivationObservationHistoricalReplay(
  value,
) {
  const parsed = exactRecord(value, [
    "authorized_at", "current_clock_consulted", "deploy_authorized",
    "expected_authority", "expected_authority_sha256", "freshness_renewed",
    "independent_signature_replay_performed",
    "independent_signature_replay_verifier", "live_traffic_authorized",
    "observation", "observation_sha256",
    "original_pinned_cast_verifier_reexecuted", "production_brand_minted",
    "qvl_verdict_artifact_sha256", "qvl_verdict_signature_sha256",
    "qvl_verdict_signing_digest", "raw_transcript_sha256", "schema",
    "signature_message_mode", "truth_status",
  ], "historical compute-workload O replay result");
  if (parsed.schema
      !== COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_SCHEMA
    || parsed.truth_status
      !== COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_TRUTH
    || parsed.signature_message_mode
      !== "eip191_personal_sign_raw_bytes32"
    || parsed.independent_signature_replay_performed !== true
    || parsed.original_pinned_cast_verifier_reexecuted !== false
    || parsed.current_clock_consulted !== false
    || parsed.freshness_renewed !== false
    || parsed.production_brand_minted !== false
    || parsed.deploy_authorized !== false
    || parsed.live_traffic_authorized !== false
    || JSON.stringify(parsed.independent_signature_replay_verifier)
      !== JSON.stringify(INDEPENDENT_EIP191_REPLAY_VERIFIER)) {
    fail("historical compute-workload O replay truth boundary is invalid");
  }
  const reconstructed = reconstructHistoricalObservationReplay({
    persistedObservation: parsed.observation,
    expectedAuthority: parsed.expected_authority,
    authorizedAt: parsed.authorized_at,
  });
  if (canonicalText(parsed) !== canonicalText(reconstructed)) {
    fail("historical compute-workload O replay result differs from reconstruction");
  }
  return reconstructed;
}

function normalizeBrowserBinding(value) {
  const parsed = exactRecord(value, [
    "activation_signer_address", "app_id", "chain_id", "compose_hash",
    "ceremony_nonce", "cvm_id", "deployment_intent_sha256",
    "compute_vault_address", "compute_vault_runtime_code_hash",
    "fresh_contract_deployment_receipt_sha256", "max_verdict_age_seconds",
    "main_runtime_evidence_sha256", "measurement_policy_set_sha256",
    "measurement_policy_sha256",
    "os_image_hash", "qvl_release_policy_hash", "qvl_verifier",
    "release_authority_sha256", "revoked_quote_hashes",
  ], "compute-workload browser binding");
  const policy = normalizeIngressPolicy({
    max_verdict_age_seconds: parsed.max_verdict_age_seconds,
    revoked_quote_hashes: parsed.revoked_quote_hashes,
  });
  return {
    qvl_verifier: address(parsed.qvl_verifier, "browser QVL verifier"),
    qvl_release_policy_hash: bytes32(
      parsed.qvl_release_policy_hash,
      "browser QVL release policy hash",
    ),
    compose_hash: bytes32(parsed.compose_hash, "browser main runtime compose hash"),
    app_id: appId(parsed.app_id, "browser main runtime app ID"),
    os_image_hash: bareSha256(parsed.os_image_hash, "browser main runtime OS image hash"),
    activation_signer_address: address(
      parsed.activation_signer_address,
      "browser activation signer",
    ),
    cvm_id: identifier(parsed.cvm_id, "browser main runtime CVM ID"),
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "browser deployment intent",
    ),
    release_authority_sha256: sha256(
      parsed.release_authority_sha256,
      "browser release verification authority",
    ),
    ceremony_nonce: bytes32(parsed.ceremony_nonce, "browser ceremony nonce"),
    measurement_policy_set_sha256: sha256(
      parsed.measurement_policy_set_sha256,
      "browser measurement-policy set",
    ),
    measurement_policy_sha256: sha256(
      parsed.measurement_policy_sha256,
      "browser compute-workload QVL measurement policy",
    ),
    main_runtime_evidence_sha256: sha256(
      parsed.main_runtime_evidence_sha256,
      "browser main-runtime evidence",
    ),
    chain_id: parsed.chain_id === CHAIN_ID
      ? CHAIN_ID
      : fail("browser compute-workload chain must be Base Sepolia"),
    compute_vault_address: address(
      parsed.compute_vault_address,
      "browser ComputeCreditVault address",
    ),
    compute_vault_runtime_code_hash: bytes32(
      parsed.compute_vault_runtime_code_hash,
      "browser ComputeCreditVault runtime hash",
    ),
    fresh_contract_deployment_receipt_sha256: bytes32(
      parsed.fresh_contract_deployment_receipt_sha256,
      "browser fresh deployment receipt digest",
    ),
    max_verdict_age_seconds: policy.max_verdict_age_seconds,
    revoked_quote_hashes: policy.revoked_quote_hashes,
  };
}

export function projectNormalizedComputeWorkloadBrowserBinding(value) {
  const observation = normalizeComputeWorkloadActivationObservation(value);
  return normalizeBrowserBinding({
    qvl_verifier: observation.compute_workload_qvl.verifier_address,
    qvl_release_policy_hash: shaToBytes32(
      observation.compute_workload_qvl.release_policy_sha256,
      "compute-workload QVL release policy",
    ),
    compose_hash: `0x${observation.main_runtime.compose_hash}`,
    app_id: observation.main_runtime.app_id,
    os_image_hash: observation.main_runtime.os_image_hash,
    activation_signer_address: observation.recipient.activation_signer_address,
    cvm_id: observation.main_runtime.cvm_id,
    deployment_intent_sha256:
      observation.lineage.deployment_intent_sha256,
    release_authority_sha256:
      observation.lineage.release_verification_authority_sha256,
    ceremony_nonce: observation.lineage.ceremony_nonce,
    measurement_policy_set_sha256:
      observation.lineage.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256:
      observation.compute_workload_qvl.measurement_policy_sha256,
    main_runtime_evidence_sha256:
      observation.main_runtime.seven_cvm_domain_evidence_sha256,
    chain_id: CHAIN_ID,
    compute_vault_address: observation.compute_vault.address,
    compute_vault_runtime_code_hash: observation.compute_vault.runtime_code_hash,
    fresh_contract_deployment_receipt_sha256: shaToBytes32(
      observation.lineage.fresh_contract_deployment_receipt_sha256,
      "fresh deployment receipt",
    ),
    max_verdict_age_seconds: observation.ingress_policy.max_verdict_age_seconds,
    revoked_quote_hashes: observation.ingress_policy.revoked_quote_hashes,
  });
}

export function normalizeComputeWorkloadBrowserBinding(value) {
  return normalizeBrowserBinding(value);
}

export function canonicalComputeWorkloadBrowserBindingText(value) {
  return canonicalText(normalizeBrowserBinding(value));
}

export function computeWorkloadBrowserBindingSha256(value) {
  return domainSha256(
    COMPUTE_WORKLOAD_BROWSER_BINDING_DOMAIN,
    normalizeBrowserBinding(value),
  );
}

export function projectComputeWorkloadBrowserEnvFromBinding(binding) {
  const normalized = normalizeBrowserBinding(binding);
  return deepFreezeCanonicalPlainDataGraph({
    VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
    VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: normalized.qvl_verifier,
    VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH:
      normalized.qvl_release_policy_hash,
    VITE_COMPUTE_WORKLOAD_COMPOSE_HASH: normalized.compose_hash,
    VITE_COMPUTE_WORKLOAD_APP_ID: normalized.app_id,
    VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: normalized.os_image_hash,
    VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER:
      normalized.activation_signer_address,
    VITE_COMPUTE_WORKLOAD_CHAIN_ID: String(normalized.chain_id),
    VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS:
      normalized.compute_vault_address,
    VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH:
      normalized.compute_vault_runtime_code_hash,
    VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256:
      normalized.fresh_contract_deployment_receipt_sha256,
    VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS:
      String(normalized.max_verdict_age_seconds),
    VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON:
      JSON.stringify(normalized.revoked_quote_hashes),
    VITE_COMPUTE_WORKLOAD_CVM_ID: normalized.cvm_id,
    VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256:
      normalized.deployment_intent_sha256,
    VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256:
      normalized.release_authority_sha256,
    VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: normalized.ceremony_nonce,
    VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256:
      normalized.measurement_policy_set_sha256,
    VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256:
      normalized.measurement_policy_sha256,
    VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256:
      normalized.main_runtime_evidence_sha256,
  }, { label: "compute-workload browser environment" });
}

export function projectComputeWorkloadBrowserBindingFromHistoricalObservation(value) {
  const replay = normalizeComputeWorkloadActivationObservationHistoricalReplay(
    value,
  );
  return deepFreezeCanonicalPlainDataGraph(
    projectNormalizedComputeWorkloadBrowserBinding(
      replay.observation,
    ),
    { label: "historical compute-workload browser binding" },
  );
}

export function projectComputeWorkloadBrowserEnvFromHistoricalObservation(value) {
  return projectComputeWorkloadBrowserEnvFromBinding(
    projectComputeWorkloadBrowserBindingFromHistoricalObservation(value),
  );
}

const OBSERVATION_AUTHORITY_BINDING_FIELDS = Object.freeze([
  "capability_endpoint",
  "ceremony_authorization_sha256",
  "historical_transcript_file_set_sha256",
  "initial_activation_evidence_lease_expires_at",
  "ingress_policy",
  "post_measurement_activation_execution_receipt_sha256",
  "post_measurement_activation_plan_sha256",
  "pre_ceremony_runtime_authority_sha256",
  "recipient_evidence_lease_expires_at",
  "seven_cvm_launch_completion_receipt_sha256",
  "seven_cvm_verified_evidence_set_sha256",
  "terminal_evidence_lease_expires_at",
]);

function normalizeObservationAuthorityBinding(value) {
  const parsed = exactRecord(
    value,
    OBSERVATION_AUTHORITY_BINDING_FIELDS,
    "compute-workload O producer authority binding",
  );
  const initialActivationEvidenceLeaseExpiresAt = second(
    parsed.initial_activation_evidence_lease_expires_at,
    "O producer initial activation-evidence lease expiry",
  );
  const recipientEvidenceLeaseExpiresAt = second(
    parsed.recipient_evidence_lease_expires_at,
    "O producer recipient evidence lease expiry",
  );
  const terminalEvidenceLeaseExpiresAt = second(
    parsed.terminal_evidence_lease_expires_at,
    "O producer terminal evidence lease expiry",
  );
  if (terminalEvidenceLeaseExpiresAt !== Math.min(
    initialActivationEvidenceLeaseExpiresAt,
    recipientEvidenceLeaseExpiresAt,
  )) {
    fail("O producer terminal evidence lease is not the exact source minimum");
  }
  return {
    capability_endpoint: normalizeCapabilityEndpoint(parsed.capability_endpoint),
    historical_transcript_file_set_sha256: sha256(
      parsed.historical_transcript_file_set_sha256,
      "O producer historical transcript file set",
    ),
    seven_cvm_launch_completion_receipt_sha256: sha256(
      parsed.seven_cvm_launch_completion_receipt_sha256,
      "O producer seven-CVM launch completion receipt",
    ),
    seven_cvm_verified_evidence_set_sha256: sha256(
      parsed.seven_cvm_verified_evidence_set_sha256,
      "O producer seven-CVM verified evidence set",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "O producer pre-ceremony runtime authority",
    ),
    post_measurement_activation_plan_sha256: sha256(
      parsed.post_measurement_activation_plan_sha256,
      "O producer post-measurement activation plan",
    ),
    post_measurement_activation_execution_receipt_sha256: sha256(
      parsed.post_measurement_activation_execution_receipt_sha256,
      "O producer post-measurement activation execution receipt",
    ),
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "O producer ceremony authorization",
    ),
    initial_activation_evidence_lease_expires_at:
      initialActivationEvidenceLeaseExpiresAt,
    recipient_evidence_lease_expires_at: recipientEvidenceLeaseExpiresAt,
    terminal_evidence_lease_expires_at: terminalEvidenceLeaseExpiresAt,
    ingress_policy: normalizeIngressPolicy(parsed.ingress_policy),
  };
}

function descriptorFor(authority, domain) {
  const descriptor = authority.descriptors.find((entry) => entry.domain === domain);
  if (!descriptor) fail(`O producer release authority omits ${domain}`);
  return descriptor;
}

export function createUnbrandedComputeWorkloadActivationObservationCandidate(
  input = {},
) {
  const parsed = exactRecord(input, [
    "activationVerification", "authorityBinding", "releaseVerificationAuthority",
  ], "unbranded compute-workload O candidate input");
  const {
    activationVerification,
    releaseVerificationAuthority,
    authorityBinding,
  } = parsed;
  const activation = normalizePhalaComputeWorkloadRecipientActivationVerification(
    activationVerification,
  );
  const releaseAuthority = releaseVerificationAuthority;
  const binding = normalizeObservationAuthorityBinding(authorityBinding);
  const releaseAuthoritySha256 =
    versionedReleaseVerificationAuthoritySha256(releaseAuthority);
  if (
    activation.release_authority_sha256 !== releaseAuthoritySha256
    || activation.deployment_intent_sha256
      !== releaseAuthority.deployment_intent_sha256
    || activation.ceremony_nonce !== releaseAuthority.ceremony_nonce
    || activation.measurement_policy_set_sha256
      !== releaseAuthority.qvl_measurement_policy_set_sha256
    || binding.recipient_evidence_lease_expires_at
      !== activation.recipient_evidence_lease_expires_at
    || binding.terminal_evidence_lease_expires_at
      > activation.terminal_evidence_lease_expires_at
  ) {
    fail("O producer activation proof belongs to another release authority");
  }
  const main = descriptorFor(releaseAuthority, "main_runtime_cvm");
  const computeQvl = descriptorFor(
    releaseAuthority,
    "compute_workload_qvl_cvm",
  );
  const source = normalizePhalaComputeWorkloadRecipientSourceActivation(
    activation.source_activation,
  );
  const lineageDigests = [
    releaseAuthority.deployment_intent_sha256,
    releaseAuthoritySha256,
    releaseAuthority.qvl_measurement_policy_set_sha256,
    binding.historical_transcript_file_set_sha256,
    releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
    releaseAuthority.bootstrap_authorization_receipt_sha256,
    binding.seven_cvm_launch_completion_receipt_sha256,
    binding.seven_cvm_verified_evidence_set_sha256,
    binding.pre_ceremony_runtime_authority_sha256,
    binding.post_measurement_activation_plan_sha256,
    binding.post_measurement_activation_execution_receipt_sha256,
    binding.ceremony_authorization_sha256,
  ];
  if (new Set(lineageDigests).size !== lineageDigests.length) {
    fail("O producer authority lineage roots must remain pairwise distinct");
  }
  return deepFreezeCanonicalPlainDataGraph(normalizeComputeWorkloadActivationObservation({
    schema: COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA,
    status: COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_STATUS,
    truth_status: COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_TRUTH,
    release_sha: releaseAuthority.release_sha,
    chain_id: CHAIN_ID,
    capability_endpoint: binding.capability_endpoint,
    lineage: {
      deployment_intent_sha256: releaseAuthority.deployment_intent_sha256,
      release_verification_authority_sha256: releaseAuthoritySha256,
      ceremony_nonce: releaseAuthority.ceremony_nonce,
      qvl_measurement_policy_set_sha256:
        releaseAuthority.qvl_measurement_policy_set_sha256,
      historical_transcript_file_set_sha256:
        binding.historical_transcript_file_set_sha256,
      fresh_contract_deployment_receipt_sha256:
        releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
      nonlive_bootstrap_authorization_receipt_sha256:
        releaseAuthority.bootstrap_authorization_receipt_sha256,
      seven_cvm_launch_completion_receipt_sha256:
        binding.seven_cvm_launch_completion_receipt_sha256,
      seven_cvm_verified_evidence_set_sha256:
        binding.seven_cvm_verified_evidence_set_sha256,
      pre_ceremony_runtime_authority_sha256:
        binding.pre_ceremony_runtime_authority_sha256,
      post_measurement_activation_plan_sha256:
        binding.post_measurement_activation_plan_sha256,
      post_measurement_activation_execution_receipt_sha256:
        binding.post_measurement_activation_execution_receipt_sha256,
      ceremony_authorization_sha256: binding.ceremony_authorization_sha256,
    },
    main_runtime: {
      app_id: main.app_id,
      cvm_id: main.cvm_id,
      compose_hash: main.compose_hash,
      os_image_hash: main.os_image_hash,
      descriptor_sha256: activation.descriptor_sha256,
      posture_receipt_sha256: activation.posture_receipt_sha256,
      tee_identity: activation.main_runtime_signer_address,
      seven_cvm_domain_evidence_sha256:
        activation.main_runtime_evidence_sha256,
    },
    compute_workload_qvl: {
      app_id: computeQvl.app_id,
      cvm_id: computeQvl.cvm_id,
      compose_hash: computeQvl.compose_hash,
      os_image_hash: computeQvl.os_image_hash,
      verifier_address: activation.qvl_verdict_verifier_address,
      release_policy_sha256: activation.qvl_release_policy_sha256,
      measurement_policy_sha256: activation.measurement_policy_sha256,
      identity_evidence_sha256: activation.qvl_identity_evidence_sha256,
      seven_cvm_domain_evidence_sha256:
        activation.qvl_identity_evidence_sha256,
    },
    compute_vault: {
      address: activation.compute_vault_address,
      runtime_code_hash: activation.compute_vault_runtime_code_hash,
    },
    recipient: {
      encryption_public_key: activation.encryption_public_key,
      recipient_key_id: activation.recipient_key_id,
      report_data: activation.report_data,
      recipient_release_commitment: activation.recipient_release_commitment,
      activation_signer_address: activation.activation_signer_address,
      activation_signer_key_path: activation.activation_signer_key_path,
      activation_signer_custody: activation.activation_signer_custody,
    },
    verification: {
      activation_verification_sha256:
        phalaComputeWorkloadRecipientActivationVerificationSha256(activation),
      activation_artifact_sha256:
        phalaComputeWorkloadRecipientSourceActivationSha256(source),
      challenge_id: activation.challenge_id,
      challenge_digest: activation.challenge_digest,
      challenge_issued_at: activation.challenge_issued_at,
      challenge_expires_at: activation.challenge_expires_at,
      tdx_quote_sha256: activation.tdx_quote_sha256,
      qvl_verdict_signing_digest: activation.qvl_verdict_signing_digest,
      qvl_verdict_artifact_sha256: activation.qvl_verdict_artifact_sha256,
      qvl_verdict_verifier_signature_sha256:
        activation.qvl_verdict_verifier_signature_sha256,
      raw_transcript_sha256: activation.raw_transcript_sha256,
      verdict_issued_at: activation.verdict_issued_at,
      verdict_activation_evidence_lease_expires_at:
        activation.verdict_activation_evidence_lease_expires_at,
      verdict_expires_at: activation.verdict_expires_at,
      recipient_evidence_lease_expires_at:
        activation.recipient_evidence_lease_expires_at,
      activation_verification_expires_at:
        activation.terminal_evidence_lease_expires_at,
      authenticated_at: activation.authenticated_at,
      verified_at: activation.verified_at,
    },
    source_activation: source,
    initial_activation_evidence_lease_expires_at:
      binding.initial_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      binding.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at:
      binding.terminal_evidence_lease_expires_at,
    ingress_policy: binding.ingress_policy,
    live_traffic_authorized: false,
    deploy_authorized: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
  }), { label: "unbranded compute-workload activation observation candidate" });
}

export const __coreTest = Object.freeze({
  CHAIN_ID,
  projectNormalizedBrowserBinding:
    projectNormalizedComputeWorkloadBrowserBinding,
});
