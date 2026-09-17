import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  CEREMONY_AUTHORIZATION_CORE_STATUS,
  DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_STATUS,
  LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
  LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
  ROYALTY_RELEASE_HISTORY_RECEIPT_SCHEMA,
  ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA,
  ROYALTY_RELEASE_HISTORY_RECEIPT_TRUTH_STATUS,
  ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
  canonicalCeremonyAuthorizationCoreArtifactText,
  canonicalLiveActivationAuthorityArtifactText,
  ceremonyReceiptRpcObservationSha256,
  ceremonyTransactionRpcObservationSha256,
  ceremonyAuthorizationCoreSha256,
  commonFinalizedBlockRpcObservationSha256,
  executionPolicyAnchorRpcReadSha256,
  liveActivationAuthoritySha256,
  liveActivationReviewSigningPayload,
  liveActivationFrontendBindingSha256,
  normalizeCeremonyAuthorizationCore,
  normalizeDeprecatedFinalReleaseAuthorityWrapper,
  normalizeLiveActivationAuthority,
  normalizeLiveActivationFrontendBinding,
  normalizeRoyaltyReleaseHistoryReceipt,
  normalizedRoyaltyReleaseHistorySha256,
  projectLiveActivationFrontendBinding,
  projectRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
  frontendBuildCandidateAuthorityBindingFromLiveActivation,
  frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization,
  assertLiveActivationFinalCvmsMatchAuthenticatedLaunch,
  assertHistoricalLiveActivationComputeWorkloadObservationBinding,
  assertLiveActivationFrontendBuildSha256,
  ceremonyAuthorizationReviewSigningPayload,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
} from "./release-authority-stages.mjs";
import {
  assertFreshProductionCeremonyAuthorizationCore,
  ceremonyAuthorizationReviewSigningPayloadForProduction,
} from "./release-ceremony-authorization-production.mjs";
import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
} from "./execution-policy-release-core.mjs";
import {
  syntheticReleaseAuthorityStagesFixture,
} from "./release-authority-current-stages.fixture.mjs";
import {
  syntheticPreCeremonyRuntimeAuthorityFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaCombinedArenaComputeActivationVerificationSha256,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-v4-core.mjs";
import {
  FRONTEND_BUILD_CANDIDATE_SCHEMA,
  FRONTEND_BUILD_CANDIDATE_STATUS,
  FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
  frontendBuildCandidateReceiptSha256,
} from "./frontend-build-candidate-receipt-core.mjs";
import {
  assertHistoricallyVerifiedComputeWorkloadActivationObservation,
  assertPrebuildVerifiedComputeWorkloadActivationObservation,
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  createUnbrandedComputeWorkloadActivationObservationCandidate,
  projectComputeWorkloadBrowserBindingFromHistoricalObservation,
} from "./compute-workload-activation-observation-core.mjs";
import {
  PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA,
  PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS,
  PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH,
  independentTdxVerdictSigningDigest,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientReportData,
  phalaComputeWorkloadRecipientSourceActivationSha256,
} from "./phala-seven-cvm-historical-evidence-core.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  normalizePhalaSevenCvmLaunchCompletionReceipt,
} from "./phala-seven-cvm-launch-completion-core.mjs";
import {
  syntheticPhalaSevenCvmLaunchCompletionFixture,
} from "./phala-seven-cvm-launch-completion.fixture.mjs";

const FORGED = privateKeyToAccount(`0x${"33".repeat(32)}`);
const TEST_COMPUTE_QVL = privateKeyToAccount(`0x${"88".repeat(32)}`);
const TEST_COMPUTE_ACTIVATION_SIGNER =
  privateKeyToAccount(`0x${"77".repeat(32)}`);

function pin(pair) {
  return `sha256:${pair.repeat(32)}`;
}

function word(pair) {
  return `0x${pair.repeat(32)}`;
}

async function resignSyntheticStageOne(value, {
  runtimeAuthority = value.runtimeAuthority,
  signedAt,
  expiresAt,
} = {}) {
  const body = structuredClone(value.stageOne);
  delete body.review;
  body.pre_ceremony_runtime_authority_sha256 =
    preCeremonyRuntimeAuthoritySha256(runtimeAuthority);
  const prior = value.stageOne.review;
  const payload = ceremonyAuthorizationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256:
      prior.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      prior.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      prior.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      prior.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: prior.approved_reviewer_hashes,
    reviewer_root_hash: prior.reviewer_root_hash,
    reviewer_set_sha256: prior.reviewer_set_sha256,
    signed_at: signedAt,
    expires_at: expiresAt,
  });
  const message = releaseAuthorityReviewSigningMessage(payload);
  const accounts = new Map(
    value.accounts.map((account) => [account.address.toLowerCase(), account]),
  );
  return {
    ...body,
    review: {
      ...payload,
      schema: prior.schema,
      signing_payload_sha256:
        releaseAuthorityReviewSigningPayloadSha256(payload),
      signatures: await Promise.all(value.reviewers.map(async (reviewer) => ({
        ...reviewer,
        signature: (await accounts.get(reviewer.address)
          .signMessage({ message })).toLowerCase(),
      }))),
    },
  };
}

async function resignSyntheticStageTwo(value, {
  signedAt,
  expiresAt,
  options = value.stageTwoOptions,
} = {}) {
  const body = structuredClone(value.stageTwo);
  delete body.review;
  const prior = value.stageTwo.review;
  const payload = liveActivationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256:
      prior.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      prior.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      prior.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      prior.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: prior.approved_reviewer_hashes,
    reviewer_root_hash: prior.reviewer_root_hash,
    reviewer_set_sha256: prior.reviewer_set_sha256,
    signed_at: signedAt,
    expires_at: expiresAt,
  }, options);
  const message = releaseAuthorityReviewSigningMessage(payload);
  const accounts = new Map(
    value.accounts.map((account) => [account.address.toLowerCase(), account]),
  );
  return {
    ...body,
    review: {
      ...payload,
      schema: prior.schema,
      signing_payload_sha256:
        releaseAuthorityReviewSigningPayloadSha256(payload),
      signatures: await Promise.all(value.reviewers.map(async (reviewer) => ({
        ...reviewer,
        signature: (await accounts.get(reviewer.address)
          .signMessage({ message })).toLowerCase(),
      }))),
    },
  };
}

const INDEPENDENT_VERDICT_ARTIFACT_DOMAIN =
  "dnai-wikigen/independent-tdx-verdict-artifact/v4\0";
const RAW_VERIFIER_TRANSCRIPT_DOMAIN =
  "dnai-wikigen/phala-raw-verifier-transcript/v1\0";
const RELEASE_AUTHORITY_SIGNATURE_DOMAIN =
  "dnai-wikigen/release-authority-signature/v1\0";
const COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN =
  "dnai-wikigen/compute-workload-recipient-release/v2\0";

function sortedGraph(value) {
  if (Array.isArray(value)) return value.map(sortedGraph);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedGraph(value[key])]),
  );
}

function domainSha256(domain, value, { compact = false } = {}) {
  const json = JSON.stringify(sortedGraph(value), null, compact ? 0 : 2);
  const text = compact ? json : `${json}\n`;
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(text, "utf8")
    .digest("hex")}`;
}

function verifierSignatureSha256(signature) {
  return `sha256:${createHash("sha256")
    .update(RELEASE_AUTHORITY_SIGNATURE_DOMAIN, "utf8")
    .update(Buffer.from(signature.slice(2), "hex"))
    .digest("hex")}`;
}

function recipientReleaseCommitment(source) {
  const verdict = source.authenticated_verdict;
  return domainSha256(COMPUTE_WORKLOAD_RECIPIENT_RELEASE_DOMAIN, {
    schema: "dnai.compute.workload-recipient-release.v2",
    chain_id: source.chain_id,
    domain: source.domain,
    profile: source.profile,
    cvm_id: source.cvm_id,
    deployment_intent_sha256: source.deployment_intent_sha256,
    release_authority_sha256: source.release_authority_sha256,
    ceremony_nonce: source.ceremony_nonce,
    measurement_policy_set_sha256: source.measurement_policy_set_sha256,
    measurement_policy_sha256: source.measurement_policy_sha256,
    main_runtime_evidence_sha256: source.main_runtime_evidence_sha256,
    recipient_key_id: source.recipient_key_id,
    report_data: source.report_data,
    compose_hash: source.compose_hash,
    app_id: source.app_id,
    os_image_hash: source.os_image_hash,
    release_policy_hash: source.release_policy_hash,
    verifier_address: source.verifier_address,
    verification_method: verdict.verification_method,
    signer_address: verdict.signer_address,
    contract_address: verdict.contract_address,
    recipient_attestation: source.recipient_attestation,
  }, { compact: true });
}

async function currentStageComputeActivation(value) {
  const plan = value.runtimeAuthority.post_measurement_activation_plan;
  const releaseAuthority = plan.release_verification_authority;
  const mainDescriptor = releaseAuthority.descriptors.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  const computeQvlDescriptor = releaseAuthority.descriptors.find(
    (entry) => entry.domain === "compute_workload_qvl_cvm",
  );
  const mainFinalCvm = value.stageTwo.post_ceremony_evidence.final_cvms.find(
    (entry) => entry.cvm_key === "main_runtime_cvm",
  );
  const computeQvlFinalCvm =
    value.stageTwo.post_ceremony_evidence.final_cvms.find(
      (entry) => entry.cvm_key === "compute_workload_qvl_cvm",
    );
  assert.ok(mainDescriptor && computeQvlDescriptor);
  assert.ok(mainFinalCvm && computeQvlFinalCvm);

  const baseReceipt = value.stageTwo.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  const authenticatedAt = baseReceipt.recipient_activation.authenticated_at;
  const verifiedAt = baseReceipt.recipient_activation.verified_at;
  const expiresAt = baseReceipt.recipient_activation.expires_at;
  const challengeIssuedAt = authenticatedAt - 2;
  const challengeExpiresAt = authenticatedAt + 30;
  const verdictIssuedAt = authenticatedAt - 1;
  const encryptionPublicKey = "e6".repeat(32);
  const recipientKeyId = `sha256:${createHash("sha256")
    .update(Buffer.from(encryptionPublicKey, "hex"))
    .digest("hex")}`;
  const freshContractReceiptBytes32 =
    `0x${releaseAuthority.contracts
      .fresh_contract_deployment_receipt_sha256.slice(7)}`;
  const recipientAttestation = {
    schema: "dnai.compute-workload-recipient-attestation.v1",
    context: "compute_workload",
    audience: "dnai-wikigen:compute-workload-recipient",
    service: "dnai-wikigen",
    protocol: "compute_workload_ingress_v1",
    encryption_public_key: encryptionPublicKey,
    key_id: recipientKeyId,
    activation_signer_address:
      TEST_COMPUTE_ACTIVATION_SIGNER.address.toLowerCase(),
    activation_signer_key_path:
      "tinker/compute_workload_activation_signer",
    activation_signer_custody:
      "dstack_derived_compute_workload_activation_signer",
    chain_id: 84_532,
    compute_vault_address: releaseAuthority.contracts.compute_credit_vault,
    compute_vault_runtime_code_hash:
      releaseAuthority.contracts.compute_credit_vault_runtime_code_hash,
    fresh_contract_deployment_receipt_sha256:
      freshContractReceiptBytes32,
  };
  const reportData =
    phalaComputeWorkloadRecipientReportData(recipientAttestation);
  const measurementPolicySha256 = plan.runtime_commitments
    .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256;
  const qvlReleasePolicySha256 = pin("b1");
  const challengeId = word("b2");
  const challengeDigest = word("b3");
  const quoteSha256 = pin("b4");
  const verdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    chain_id: 84_532,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: plan.target.cvm_id,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    release_authority_sha256: plan.release_verification_authority_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_sha256: measurementPolicySha256,
    release_policy_hash: `0x${qvlReleasePolicySha256.slice(7)}`,
    challenge_id: challengeId,
    challenge_digest: challengeDigest,
    challenge_issued_at: challengeIssuedAt,
    challenge_expires_at: challengeExpiresAt,
    quote_hash: `0x${quoteSha256.slice(7)}`,
    report_data: reportData,
    compose_hash: `0x${plan.target.compose_hash}`,
    app_id: plan.target.app_id,
    os_image_hash: plan.target.os_image_hash,
    signer_address: TEST_COMPUTE_ACTIVATION_SIGNER.address.toLowerCase(),
    contract_address: releaseAuthority.contracts.compute_credit_vault,
    issued_at: verdictIssuedAt,
    activation_evidence_lease_expires_at: expiresAt,
    expires_at: expiresAt,
    verifier_address: TEST_COMPUTE_QVL.address.toLowerCase(),
    verifier_signature: `0x${"00".repeat(64)}1b`,
  };
  const verdictDigest = independentTdxVerdictSigningDigest(verdict);
  verdict.verifier_signature = (await TEST_COMPUTE_QVL.signMessage({
    message: { raw: verdictDigest },
  })).toLowerCase();
  const sourceBase = {
    schema: "dnai.compute.workload-recipient-activation.v4",
    chain_id: 84_532,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: plan.target.cvm_id,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    release_authority_sha256: plan.release_verification_authority_sha256,
    ceremony_nonce: releaseAuthority.ceremony_nonce,
    measurement_policy_set_sha256:
      releaseAuthority.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256: measurementPolicySha256,
    main_runtime_evidence_sha256: plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
    recipient_key_id: recipientKeyId,
    report_data: reportData,
    compose_hash: `0x${plan.target.compose_hash}`,
    app_id: plan.target.app_id,
    os_image_hash: plan.target.os_image_hash,
    release_policy_hash: `0x${qvlReleasePolicySha256.slice(7)}`,
    quote_hash: `0x${quoteSha256.slice(7)}`,
    verifier_address: TEST_COMPUTE_QVL.address.toLowerCase(),
    verdict_digest: verdictDigest,
    issued_at: verdictIssuedAt,
    recipient_evidence_lease_expires_at: expiresAt,
    expires_at: expiresAt,
    authenticated_at: authenticatedAt,
    recipient_attestation: recipientAttestation,
    authenticated_verdict: verdict,
  };
  const sourceActivation = {
    ...sourceBase,
    recipient_release_commitment: recipientReleaseCommitment(sourceBase),
  };
  const activationArtifactSha256 =
    phalaComputeWorkloadRecipientSourceActivationSha256(sourceActivation);
  const verdictArtifactSha256 = domainSha256(
    INDEPENDENT_VERDICT_ARTIFACT_DOMAIN,
    verdict,
  );
  const rawTranscriptSha256 = domainSha256(
    RAW_VERIFIER_TRANSCRIPT_DOMAIN,
    {
      schema: "dnai.phala-raw-verifier-transcript.v1",
      chain_id: 84_532,
      domain: "main_runtime_cvm",
      kind: "compute_workload_recipient_activation",
      artifact_sha256: [activationArtifactSha256, verdictArtifactSha256],
    },
  );
  const activationVerification =
    normalizePhalaComputeWorkloadRecipientActivationVerification({
      schema:
        PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_SCHEMA,
      status:
        PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_STATUS,
      truth_status:
        PHALA_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATION_VERIFICATION_TRUTH,
      evidence_mode: PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
      chain_id: 84_532,
      domain: "main_runtime_cvm",
      profile: "compute_workload",
      release_authority_sha256: plan.release_verification_authority_sha256,
      deployment_intent_sha256: plan.deployment_intent_sha256,
      ceremony_nonce: releaseAuthority.ceremony_nonce,
      measurement_policy_set_sha256:
        releaseAuthority.qvl_measurement_policy_set_sha256,
      measurement_policy_sha256: measurementPolicySha256,
      descriptor_sha256: plan.target.descriptor_sha256,
      posture_receipt_sha256: mainDescriptor.posture_receipt_sha256,
      qvl_identity_evidence_sha256:
        computeQvlFinalCvm.attestation_evidence_sha256,
      app_id: plan.target.app_id,
      cvm_id: plan.target.cvm_id,
      compose_hash: plan.target.compose_hash,
      os_image_hash: plan.target.os_image_hash,
      encryption_public_key: encryptionPublicKey,
      recipient_key_id: recipientKeyId,
      activation_signer_address:
        TEST_COMPUTE_ACTIVATION_SIGNER.address.toLowerCase(),
      activation_signer_key_path:
        "tinker/compute_workload_activation_signer",
      activation_signer_custody:
        "dstack_derived_compute_workload_activation_signer",
      main_runtime_signer_address: mainFinalCvm.tee_identity,
      main_runtime_evidence_sha256: plan.runtime_commitments
        .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
      initial_main_runtime_activation_evidence_lease_expires_at:
        baseReceipt.initial_activation_evidence_lease_expires_at,
      initial_compute_workload_qvl_activation_evidence_lease_expires_at:
        baseReceipt.initial_activation_evidence_lease_expires_at,
      compute_vault_address: releaseAuthority.contracts.compute_credit_vault,
      compute_vault_runtime_code_hash:
        releaseAuthority.contracts.compute_credit_vault_runtime_code_hash,
      fresh_contract_deployment_receipt_sha256:
        freshContractReceiptBytes32,
      report_data: reportData,
      recipient_release_commitment:
        sourceActivation.recipient_release_commitment,
      qvl_release_policy_sha256: qvlReleasePolicySha256,
      qvl_verdict_verifier_address: TEST_COMPUTE_QVL.address.toLowerCase(),
      challenge_id: challengeId,
      challenge_digest: challengeDigest,
      challenge_issued_at: challengeIssuedAt,
      challenge_expires_at: challengeExpiresAt,
      tdx_quote_sha256: quoteSha256,
      qvl_verdict_signing_digest: verdictDigest,
      qvl_verdict_artifact_sha256: verdictArtifactSha256,
      qvl_verdict_verifier_signature_sha256:
        verifierSignatureSha256(verdict.verifier_signature),
      activation_artifact_sha256: activationArtifactSha256,
      raw_transcript_sha256: rawTranscriptSha256,
      source_activation: sourceActivation,
      verdict_issued_at: verdictIssuedAt,
      verdict_activation_evidence_lease_expires_at: expiresAt,
      verdict_expires_at: expiresAt,
      recipient_evidence_lease_expires_at: expiresAt,
      terminal_evidence_lease_expires_at:
        baseReceipt.terminal_evidence_lease_expires_at,
      authenticated_at: authenticatedAt,
      verified_at: verifiedAt,
      expires_at: baseReceipt.terminal_evidence_lease_expires_at,
      raw_quote_publicly_disclosed: false,
      raw_collateral_publicly_disclosed: false,
      raw_secret_egress: false,
    });
  return {
    activationVerification,
    computeQvlDescriptor,
    computeQvlFinalCvm,
    mainDescriptor,
    mainFinalCvm,
    qvlReleasePolicySha256,
  };
}

function historicalExpectationsFromSignedStages({
  value,
  activationReceipt,
  activation,
}) {
  const plan = value.runtimeAuthority.post_measurement_activation_plan;
  const releaseAuthority = plan.release_verification_authority;
  return {
    ceremonyAuthorizationSha256:
      activationReceipt.ceremony_authorization_sha256,
    ceremonyNonce: releaseAuthority.ceremony_nonce,
    computeVaultAddress: releaseAuthority.contracts.compute_credit_vault,
    computeVaultRuntimeCodeHash:
      releaseAuthority.contracts.compute_credit_vault_runtime_code_hash,
    computeWorkloadQvlAppId: activation.computeQvlDescriptor.app_id,
    computeWorkloadQvlComposeHash:
      activation.computeQvlDescriptor.compose_hash,
    computeWorkloadQvlCvmId: activation.computeQvlDescriptor.cvm_id,
    computeWorkloadQvlIdentityEvidenceSha256:
      activation.computeQvlFinalCvm.attestation_evidence_sha256,
    computeWorkloadQvlMeasurementPolicySha256: plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
    computeWorkloadQvlOsImageHash:
      activation.computeQvlDescriptor.os_image_hash,
    computeWorkloadQvlReleasePolicySha256:
      activation.qvlReleasePolicySha256,
    computeWorkloadQvlVerifierAddress:
      TEST_COMPUTE_QVL.address.toLowerCase(),
    deploymentIntentSha256: plan.deployment_intent_sha256,
    freshContractDeploymentReceiptSha256:
      releaseAuthority.contracts.fresh_contract_deployment_receipt_sha256,
    historicalTranscriptFileSetSha256:
      value.runtimeAuthority.historical_transcript_file_set_sha256,
    mainRuntimeAppId: plan.target.app_id,
    mainRuntimeComposeHash: plan.target.compose_hash,
    mainRuntimeCvmId: plan.target.cvm_id,
    mainRuntimeDescriptorSha256: plan.target.descriptor_sha256,
    mainRuntimeEvidenceSha256: plan.runtime_commitments
      .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
    mainRuntimeOsImageHash: plan.target.os_image_hash,
    mainRuntimePostureReceiptSha256:
      activation.mainDescriptor.posture_receipt_sha256,
    mainRuntimeTeeIdentity: activation.mainFinalCvm.tee_identity,
    nonliveBootstrapAuthorizationReceiptSha256:
      releaseAuthority.bootstrap_authorization_receipt_sha256,
    postMeasurementActivationExecutionReceiptSha256:
      phalaPostMeasurementActivationExecutionReceiptSha256(
        activationReceipt,
      ),
    postMeasurementActivationPlanSha256:
      value.runtimeAuthority.post_measurement_activation_plan_sha256,
    preCeremonyRuntimeAuthoritySha256:
      preCeremonyRuntimeAuthoritySha256(value.runtimeAuthority),
    qvlMeasurementPolicySetSha256:
      releaseAuthority.qvl_measurement_policy_set_sha256,
    releaseSha: plan.release_sha,
    releaseVerificationAuthoritySha256:
      plan.release_verification_authority_sha256,
    sevenCvmLaunchCompletionReceiptSha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    sevenCvmVerifiedEvidenceSetSha256:
      plan.seven_cvm_verified_evidence_set_sha256,
    initialActivationEvidenceLeaseExpiresAt:
      activationReceipt.initial_activation_evidence_lease_expires_at,
    recipientEvidenceLeaseExpiresAt:
      activationReceipt.recipient_evidence_lease_expires_at,
    terminalEvidenceLeaseExpiresAt:
      activationReceipt.terminal_evidence_lease_expires_at,
  };
}

async function historicalStageCBindingFixture() {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const activation = await currentStageComputeActivation(value);
  const activationVerificationSha256 =
    phalaComputeWorkloadRecipientActivationVerificationSha256(
      activation.activationVerification,
    );
  const baseReceipt = structuredClone(
    value.stageTwo.post_ceremony_evidence
      .post_measurement_activation_execution_receipt,
  );
  baseReceipt.recipient_activation = {
    activation_verification_sha256: activationVerificationSha256,
    source_activation_sha256:
      activation.activationVerification.activation_artifact_sha256,
    raw_transcript_sha256:
      activation.activationVerification.raw_transcript_sha256,
    qvl_verdict_verifier_signature_sha256:
      activation.activationVerification.qvl_verdict_verifier_signature_sha256,
    tdx_quote_sha256: activation.activationVerification.tdx_quote_sha256,
    challenge_id: activation.activationVerification.challenge_id,
    report_data: activation.activationVerification.report_data,
    recipient_key_id: activation.activationVerification.recipient_key_id,
    recipient_release_commitment:
      activation.activationVerification.recipient_release_commitment,
    authenticated_at: activation.activationVerification.authenticated_at,
    verified_at: activation.activationVerification.verified_at,
    verdict_activation_evidence_lease_expires_at:
      activation.activationVerification
        .verdict_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      activation.activationVerification.recipient_evidence_lease_expires_at,
    expires_at: activation.activationVerification.expires_at,
    post_restart_source_activation: true,
  };
  baseReceipt.compute_recipient_activation_sha256 =
    activationVerificationSha256;
  baseReceipt.combined_activation_verification_sha256 =
    phalaCombinedArenaComputeActivationVerificationSha256({
      profileActivation: baseReceipt.profile_activation,
      arenaWorkerPresenceSha256: baseReceipt.arena_worker_presence_sha256,
      computeRecipientActivationSha256: activationVerificationSha256,
    });
  const activationReceipt =
    normalizePhalaPostMeasurementActivationExecutionReceipt(baseReceipt);
  const activationReceiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(activationReceipt);
  const plan = value.runtimeAuthority.post_measurement_activation_plan;
  const observation =
    createUnbrandedComputeWorkloadActivationObservationCandidate({
      activationVerification: activation.activationVerification,
      releaseVerificationAuthority: plan.release_verification_authority,
      authorityBinding: {
        capability_endpoint:
          "https://compute.release.wikigen.me/compute/workload-encryption-contract",
        historical_transcript_file_set_sha256:
          value.runtimeAuthority.historical_transcript_file_set_sha256,
        seven_cvm_launch_completion_receipt_sha256:
          plan.seven_cvm_launch_completion_receipt_sha256,
        seven_cvm_verified_evidence_set_sha256:
          plan.seven_cvm_verified_evidence_set_sha256,
        pre_ceremony_runtime_authority_sha256:
          preCeremonyRuntimeAuthoritySha256(value.runtimeAuthority),
        post_measurement_activation_plan_sha256:
          value.runtimeAuthority.post_measurement_activation_plan_sha256,
        post_measurement_activation_execution_receipt_sha256:
          activationReceiptSha256,
        ceremony_authorization_sha256:
          activationReceipt.ceremony_authorization_sha256,
        initial_activation_evidence_lease_expires_at:
          activationReceipt.initial_activation_evidence_lease_expires_at,
        recipient_evidence_lease_expires_at:
          activationReceipt.recipient_evidence_lease_expires_at,
        terminal_evidence_lease_expires_at:
          activationReceipt.terminal_evidence_lease_expires_at,
        ingress_policy: {
          max_verdict_age_seconds: 120,
          revoked_quote_hashes: [],
        },
      },
    });
  const expected = historicalExpectationsFromSignedStages({
    value,
    activationReceipt,
    activation,
  });
  const signedAtMs = Date.parse(value.stageTwo.review.signed_at);
  const replay =
    assertHistoricallyVerifiedComputeWorkloadActivationObservation({
      persistedObservation: observation,
      expected,
      authorizedAtMs: signedAtMs,
    });
  const serializedEnv = "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD=true\n";
  const releaseEnvSha256 = `sha256:${createHash("sha256")
    .update(serializedEnv, "utf8")
    .digest("hex")}`;
  const observationSha256 =
    computeWorkloadActivationObservationSha256(observation);
  const frontendBuildSha256 = pin("f1");
  const buildReceipt = {
    schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
    status: FRONTEND_BUILD_CANDIDATE_STATUS,
    truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
    release_sha: value.stageTwo.release_sha,
    chain_id: 84_532,
    deployment_intent_sha256:
      value.stageTwo.contract_state.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      value.stageTwo.contract_state
        .reviewer_authority_genesis_acceptance_sha256,
    ceremony_authorization_sha256:
      value.stageTwo.ceremony_authorization_sha256,
    runtime_authority_dependency_sha256:
      value.stageTwoOptions.ceremonyAuthorization
        .pre_ceremony_runtime_authority_sha256,
    royalty_release_history_sha256:
      value.stageTwo.contract_state.royalty_release_history_sha256,
    royalty_release_history_receipt_sha256:
      value.stageTwo.contract_state.royalty_release_history_receipt_sha256,
    post_measurement_activation_execution_receipt_sha256:
      activationReceiptSha256,
    compute_workload_activation_observation_sha256: observationSha256,
    frontend_build_sha256: frontendBuildSha256,
    release_inputs_sha256: pin("f2"),
    release_env_sha256: releaseEnvSha256,
    raw_secret_egress: false,
  };
  const stageTwoBody = structuredClone(value.stageTwo);
  delete stageTwoBody.review;
  Object.assign(stageTwoBody.post_ceremony_evidence, {
    post_measurement_activation_execution_receipt: activationReceipt,
    post_measurement_activation_execution_receipt_sha256:
      activationReceiptSha256,
    compute_workload_activation_observation_sha256: observationSha256,
    compute_workload_browser_binding:
      projectComputeWorkloadBrowserBindingFromHistoricalObservation(replay),
    frontend_release_env_sha256: releaseEnvSha256,
    frontend_build_candidate_receipt_sha256:
      frontendBuildCandidateReceiptSha256(buildReceipt),
    frontend_build_sha256: frontendBuildSha256,
  });
  const liveActivationAuthority = await resignSyntheticStageTwo({
    ...value,
    stageTwo: { ...stageTwoBody, review: value.stageTwo.review },
  }, {
    signedAt: value.stageTwo.review.signed_at,
    expiresAt: value.stageTwo.review.expires_at,
  });
  return {
    activationReceiptSha256,
    buildReceipt,
    expected,
    frontendBuildSha256,
    liveActivationAuthority,
    observation,
    observationSha256,
    releaseEnvSha256,
    replay,
    serializedEnv,
    signedAtMs,
    value,
  };
}

test("deprecated compatibility wrapper has a schema distinct from the v3 authority core", () => {
  assert.notEqual(
    DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_SCHEMA,
    FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  );
  const wrapper = {
    schema: DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_SCHEMA,
    status: CEREMONY_AUTHORIZATION_CORE_STATUS,
    truth_status:
      "deprecated_pre_ceremony_compatibility_wrapper_not_final_or_live_authority",
    pre_ceremony_runtime_authority_sha256: pin("a1"),
    ceremony_authorization_sha256: pin("a2"),
  };
  assert.deepEqual(normalizeDeprecatedFinalReleaseAuthorityWrapper(wrapper), wrapper);
  assert.throws(
    () => normalizeDeprecatedFinalReleaseAuthorityWrapper({
      ...wrapper,
      schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    }),
    /deprecated wrapper schema/,
  );
});

test("signed Stage 1 flows into separately signed Stage 2 without digest cycles", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const stageOne = normalizeCeremonyAuthorizationCore(value.stageOne, value.stageOneOptions);
  const stageTwo = normalizeLiveActivationAuthority(value.stageTwo, value.stageTwoOptions);
  const activationReceipt = stageTwo.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  assert.equal(stageOne.status, CEREMONY_AUTHORIZATION_CORE_STATUS);
  assert.equal(stageTwo.status, LIVE_ACTIVATION_AUTHORITY_STATUS);
  assert.equal(stageTwo.schema, "dnai.live-activation-authority.v6");
  assert.equal(
    activationReceipt.schema,
    PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  );
  assert.deepEqual([
    activationReceipt.patch.call_sequence,
    activationReceipt.restart.call_sequence,
    activationReceipt.post_restart_evidence.get_cvm_info_call_sequence,
    activationReceipt.post_restart_evidence.get_cvm_attestation_call_sequence,
  ], [6, 7, 8, 9]);
  assert.equal(
    stageTwo.post_ceremony_evidence
      .post_measurement_activation_execution_receipt_sha256,
    phalaPostMeasurementActivationExecutionReceiptSha256(
      stageTwo.post_ceremony_evidence
        .post_measurement_activation_execution_receipt,
    ),
  );
  assert.equal(
    stageTwo.review.dependencies.some((entry) =>
      entry.kind === "post_measurement_activation_execution_receipt"),
    true,
  );
  assert.equal(stageTwo.ceremony_authorization_sha256, ceremonyAuthorizationCoreSha256(
    value.stageOne,
    value.stageOneOptions,
  ));
  assert.match(liveActivationAuthoritySha256(value.stageTwo, value.stageTwoOptions), /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    canonicalCeremonyAuthorizationCoreArtifactText(value.stageOne, value.stageOneOptions),
    canonicalCeremonyAuthorizationCoreArtifactText(stageOne, value.stageOneOptions),
  );
  assert.equal(
    canonicalLiveActivationAuthorityArtifactText(value.stageTwo, value.stageTwoOptions),
    canonicalLiveActivationAuthorityArtifactText(stageTwo, value.stageTwoOptions),
  );
  assert.equal(JSON.stringify(value.stageTwo).includes("liveActivationAuthoritySha256"), false);
  assert.throws(
    () => normalizeLiveActivationAuthority(value.stageTwo, {
      ...value.stageTwoOptions,
      reviewerStatusHistory: [],
    }),
    /ambiguous legacy reviewerStatusHistory/,
  );
});

test("signed current C exact-binds authenticated current L and newer main receipt evidence", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const launchFixture = syntheticPhalaSevenCvmLaunchCompletionFixture();
  const launchReceipt = normalizePhalaSevenCvmLaunchCompletionReceipt(
    launchFixture.receipt,
    { expectedAuthority: launchFixture.expectedAuthority },
  );
  const body = structuredClone(value.stageTwo);
  const receipt = normalizePhalaPostMeasurementActivationExecutionReceipt({
    ...body.post_ceremony_evidence
      .post_measurement_activation_execution_receipt,
    target: {
      domain: launchReceipt.domains[0].domain,
      descriptor_sha256: launchReceipt.domains[0].descriptor_sha256,
      app_id: launchReceipt.domains[0].app_id,
      cvm_id: launchReceipt.domains[0].cvm_id,
      compose_hash: launchReceipt.domains[0].committed_compose_hash,
      os_image_hash: launchReceipt.domains[0].os_image_hash,
    },
  });
  body.post_ceremony_evidence.post_measurement_activation_execution_receipt =
    receipt;
  body.post_ceremony_evidence
    .post_measurement_activation_execution_receipt_sha256 =
      phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  body.post_ceremony_evidence.final_cvms = launchReceipt.domains.map(
    (domain, index) => ({
      cvm_key: domain.domain,
      app_id: domain.app_id,
      cvm_id: domain.cvm_id,
      compose_hash_sha256: `sha256:${domain.committed_compose_hash}`,
      tee_identity: domain.tee_identity,
      attestation_evidence_sha256: index === 0
        ? receipt.post_restart_evidence
          .get_cvm_attestation_observation_sha256
        : domain.machine_evidence_sha256,
    }),
  );
  const signed = await resignSyntheticStageTwo({
    ...value,
    stageTwo: body,
  }, {
    signedAt: value.stageTwo.review.signed_at,
    expiresAt: value.stageTwo.review.expires_at,
  });
  const normalized = normalizeLiveActivationAuthority(
    signed,
    value.stageTwoOptions,
  );
  const standaloneReceipt = normalized.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  assert.notEqual(
    launchReceipt.domains[0].machine_evidence_sha256,
    standaloneReceipt.post_restart_evidence
      .get_cvm_attestation_observation_sha256,
    "main final state must be newer receipt evidence, not historical L evidence",
  );
  assert.equal(assertLiveActivationFinalCvmsMatchAuthenticatedLaunch({
    liveActivationAuthority: signed,
    liveActivationOptions: value.stageTwoOptions,
    authenticatedLaunchReceipt: launchReceipt,
    activationExecutionReceipt: standaloneReceipt,
  }), true);

  const historicalMain = structuredClone(signed);
  historicalMain.post_ceremony_evidence.final_cvms[0]
    .attestation_evidence_sha256 =
      launchReceipt.domains[0].machine_evidence_sha256;
  await assert.rejects(
    resignSyntheticStageTwo({ ...value, stageTwo: historicalMain }, {
      signedAt: signed.review.signed_at,
      expiresAt: signed.review.expires_at,
    }),
    /activation execution receipt drifted/,
  );

  const alteredNonMain = structuredClone(signed);
  alteredNonMain.post_ceremony_evidence.final_cvms[5]
    .attestation_evidence_sha256 = pin("fe");
  const resignedAlteredNonMain = await resignSyntheticStageTwo({
    ...value,
    stageTwo: alteredNonMain,
  }, {
    signedAt: signed.review.signed_at,
    expiresAt: signed.review.expires_at,
  });
  assert.doesNotThrow(() => normalizeLiveActivationAuthority(
    resignedAlteredNonMain,
    value.stageTwoOptions,
  ));
  assert.throws(
    () => assertLiveActivationFinalCvmsMatchAuthenticatedLaunch({
      liveActivationAuthority: resignedAlteredNonMain,
      liveActivationOptions: value.stageTwoOptions,
      authenticatedLaunchReceipt: launchReceipt,
      activationExecutionReceipt: standaloneReceipt,
    }),
    /compute_metering_qvl_cvm drifted from authenticated current L\/receipt evidence/,
  );
});

test("historical final C binds a genuine replay wrapper at the signed-C second", async () => {
  const fixture = await historicalStageCBindingFixture();
  const result =
    assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: structuredClone(fixture.replay),
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    });
  assert.deepEqual(result, {
    computeWorkloadActivationObservationSha256: fixture.observationSha256,
    computeWorkloadBrowserBindingSha256: computeWorkloadBrowserBindingSha256(
      fixture.liveActivationAuthority.post_ceremony_evidence
        .compute_workload_browser_binding,
    ),
    postMeasurementActivationExecutionReceiptSha256:
      fixture.activationReceiptSha256,
    frontendReleaseEnvSha256: fixture.releaseEnvSha256,
    frontendBuildCandidateReceiptSha256:
      frontendBuildCandidateReceiptSha256(fixture.buildReceipt),
    frontendBuildSha256: fixture.frontendBuildSha256,
    liveActivationAuthoritySha256: liveActivationAuthoritySha256(
      fixture.liveActivationAuthority,
      { ...fixture.value.stageTwoOptions, enforceFreshness: false },
    ),
  });

  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: fixture.observation,
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    }),
    /historical compute-workload O replay result/,
  );

  const mutatedReplay = structuredClone(fixture.replay);
  mutatedReplay.observation.recipient.recipient_key_id = pin("fa");
  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: mutatedReplay,
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    }),
  );

  const forgedReplay = structuredClone(fixture.replay);
  forgedReplay.observation_sha256 = pin("fb");
  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: forgedReplay,
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    }),
    /differs from reconstruction/,
  );

  const replayForAnotherSecond =
    assertHistoricallyVerifiedComputeWorkloadActivationObservation({
      persistedObservation: fixture.observation,
      expected: fixture.expected,
      authorizedAtMs: fixture.signedAtMs - 1_000,
    });
  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: replayForAnotherSecond,
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    }),
    /replay time differs from signed C/,
  );

  const prebuildReplay =
    assertPrebuildVerifiedComputeWorkloadActivationObservation({
      persistedObservation: fixture.observation,
      expected: fixture.expected,
      completedAtMs: Date.parse(
        fixture.liveActivationAuthority.post_ceremony_evidence
          .post_measurement_activation_execution_receipt.completed_at,
      ),
    });
  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: fixture.liveActivationAuthority,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: prebuildReplay,
      frontendBuildCandidateReceipt: fixture.buildReceipt,
      serializedEnv: fixture.serializedEnv,
    }),
    /historical compute-workload O replay result/,
  );

  const wrongReceiptBuild = {
    ...fixture.buildReceipt,
    post_measurement_activation_execution_receipt_sha256: pin("fc"),
  };
  const wrongReceiptStageBody = structuredClone(
    fixture.liveActivationAuthority,
  );
  wrongReceiptStageBody.post_ceremony_evidence
    .frontend_build_candidate_receipt_sha256 =
      frontendBuildCandidateReceiptSha256(wrongReceiptBuild);
  const wrongReceiptStage = await resignSyntheticStageTwo({
    ...fixture.value,
    stageTwo: wrongReceiptStageBody,
  }, {
    signedAt: fixture.liveActivationAuthority.review.signed_at,
    expiresAt: fixture.liveActivationAuthority.review.expires_at,
  });
  assert.throws(
    () => assertHistoricalLiveActivationComputeWorkloadObservationBinding({
      liveActivationAuthority: wrongReceiptStage,
      liveActivationOptions: fixture.value.stageTwoOptions,
      historicallyVerifiedObservation: fixture.replay,
      frontendBuildCandidateReceipt: wrongReceiptBuild,
      serializedEnv: fixture.serializedEnv,
    }),
    /historical final C does not exact-bind/,
  );
});

test("Stage B requires original reviewer/R timing and production signing requires a live R brand", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const body = structuredClone(value.stageOne);
  delete body.review;
  const reviewMetadata = {
    reviewer_authority_genesis_sha256:
      value.stageOne.review.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      value.stageOne.review.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      value.stageOne.review.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      value.stageOne.review.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: value.stageOne.review.approved_reviewer_hashes,
    reviewer_root_hash: value.stageOne.review.reviewer_root_hash,
    reviewer_set_sha256: value.stageOne.review.reviewer_set_sha256,
    signed_at: value.stageOne.review.signed_at,
    expires_at: value.stageOne.review.expires_at,
  };
  assert.throws(
    () => ceremonyAuthorizationReviewSigningPayloadForProduction(
      body,
      reviewMetadata,
      { preCeremonyRuntimeAuthority: value.runtimeAuthority },
    ),
    /fresh dependency-reconstructed pre-ceremony runtime authority/,
  );
  assert.throws(
    () => assertFreshProductionCeremonyAuthorizationCore(
      value.stageOne,
      value.stageOneOptions,
    ),
    /fresh dependency-reconstructed pre-ceremony runtime authority/,
  );

  const beforeIssuance = await resignSyntheticStageOne(value, {
    signedAt: "2026-07-21T11:59:00.000Z",
    expiresAt: "2026-07-21T12:05:00.000Z",
  });
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(
      beforeIssuance,
      value.stageOneOptions,
    ),
    /outside the pre-ceremony runtime-authority proof window/,
  );

  const shortRuntimeAuthority = syntheticPreCeremonyRuntimeAuthorityFixture({
    releaseSha: value.runtimeAuthority.release_sha,
    deploymentIntentSha256:
      value.runtimeAuthority.deployment_intent_sha256,
    cvmLaunchIntentSha256:
      value.runtimeAuthority.cvm_launch_intent_sha256,
    activationEvidenceLeaseExpiresAt:
      Date.parse("2026-07-21T12:06:00.000Z") / 1_000,
  });
  const expiryExtension = await resignSyntheticStageOne(value, {
    runtimeAuthority: shortRuntimeAuthority,
    signedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2026-07-21T12:10:00.000Z",
  });
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(expiryExtension, {
      ...value.stageOneOptions,
      preCeremonyRuntimeAuthority: shortRuntimeAuthority,
    }),
    /outside the pre-ceremony runtime-authority proof window/,
  );

  // Equality at the selected status expiry is valid and is exercised by the
  // fixture's original review. Any extension beyond it is not.
  assert.equal(
    normalizeCeremonyAuthorizationCore(
      value.stageOne,
      value.stageOneOptions,
    ).review.expires_at,
    value.currentStatus.expires_at.replace("Z", ".000Z"),
  );
  const statusExpiryExtension = await resignSyntheticStageOne(value, {
    signedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2026-07-21T12:10:00.001Z",
  });
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(
      statusExpiryExtension,
      value.stageOneOptions,
    ),
    /selected reviewer-status validity window/,
  );
  const signedAtStatusExpiry = await resignSyntheticStageOne(value, {
    signedAt: "2026-07-21T12:10:00.000Z",
    expiresAt: "2026-07-21T12:10:00.001Z",
  });
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(
      signedAtStatusExpiry,
      value.stageOneOptions,
    ),
    /selected reviewer-status validity window/,
  );
});

test("Stage C review expiry is capped by its independently selected reviewer head", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const statusExpiryExtension = await resignSyntheticStageTwo(value, {
    signedAt: "2026-07-21T12:00:10.000Z",
    expiresAt: "2026-07-21T12:10:00.001Z",
  });
  assert.throws(
    () => normalizeLiveActivationAuthority(
      statusExpiryExtension,
      value.stageTwoOptions,
    ),
    /selected reviewer-status validity window/,
  );
});

test("signed Stage 2 projects one exact frontend candidate and audited-build binding", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const binding = projectLiveActivationFrontendBinding(
    value.stageTwo,
    value.stageTwoOptions,
  );
  assert.equal(binding.schema, LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA);
  assert.equal(
    binding.truth_status,
    LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
  );
  assert.equal(
    binding.live_activation_authority_sha256,
    liveActivationAuthoritySha256(value.stageTwo, value.stageTwoOptions),
  );
  assert.equal(
    binding.deployment_intent_sha256,
    value.stageOne.deployment_authority.deployment_intent_sha256,
  );
  assert.equal(
    binding.frontend_build_candidate_receipt_sha256,
    value.stageTwo.post_ceremony_evidence
      .frontend_build_candidate_receipt_sha256,
  );
  assert.equal(
    binding.frontend_build_sha256,
    value.stageTwo.post_ceremony_evidence.frontend_build_sha256,
  );
  assert.equal(binding.contracts.length, 7);
  assert.deepEqual(
    binding.royalty_release_authority,
    value.stageTwo.contract_state.royalty_release_history.authority,
  );
  assert.deepEqual(
    binding.royalty_release_active_state,
    value.stageTwo.contract_state.royalty_release_history.phase_two
      .poststate.primary_rpc_state,
  );
  assert.equal(binding.royalty_release_active_state.paused, false);
  assert.equal(binding.royalty_release_active_state.pending_authority_nonce, 0);
  assert.equal(
    binding.royalty_release_history_receipt_sha256,
    value.stageTwo.contract_state.royalty_release_history_receipt_sha256,
  );
  assert.equal(
    binding.execution_policy_anchor_commitment.primary_rpc_read_sha256,
    value.stageTwo.contract_state.execution_policy_anchor_commitment
      .primary_rpc_read_sha256,
  );
  assert.deepEqual(binding.final_cvms.map(({ cvm_key: key }) => key), [
    "main_runtime_cvm",
    "diligence_qvl_cvm",
    "arena_qvl_cvm",
    "anchor_writer_qvl_cvm",
    "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm",
    "independent_metering_cvm",
  ]);
  assert.match(liveActivationFrontendBindingSha256(binding), /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(normalizeLiveActivationFrontendBinding(binding), binding);
  assert.deepEqual(
    frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization(
      value.stageOne,
      value.stageOneOptions,
    ),
    {
      releaseSha: binding.release_sha,
      deploymentIntentSha256: binding.deployment_intent_sha256,
      reviewerAuthorityGenesisAcceptanceSha256:
        binding.reviewer_authority_genesis_acceptance_sha256,
      ceremonyAuthorizationSha256: binding.ceremony_authorization_sha256,
      runtimeAuthorityDependencySha256:
        binding.runtime_authority_dependency_sha256,
      computeWorkloadActivationObservationSha256:
        binding.compute_workload_activation_observation_sha256,
    },
  );
  assert.deepEqual(
    frontendBuildCandidateAuthorityBindingFromLiveActivation(
      value.stageTwo,
      value.stageTwoOptions,
    ),
    {
      releaseSha: binding.release_sha,
      deploymentIntentSha256: binding.deployment_intent_sha256,
      reviewerAuthorityGenesisAcceptanceSha256:
        binding.reviewer_authority_genesis_acceptance_sha256,
      ceremonyAuthorizationSha256: binding.ceremony_authorization_sha256,
      runtimeAuthorityDependencySha256:
        binding.runtime_authority_dependency_sha256,
      computeWorkloadActivationObservationSha256:
        binding.compute_workload_activation_observation_sha256,
      frontendReleaseEnvSha256: binding.frontend_release_env_sha256,
      frontendBuildCandidateReceiptSha256:
        binding.frontend_build_candidate_receipt_sha256,
      frontendBuildSha256: binding.frontend_build_sha256,
    },
  );
  assert.deepEqual(
    assertLiveActivationFrontendBuildSha256(
      value.stageTwo,
      binding.frontend_build_sha256,
      value.stageTwoOptions,
    ),
    binding,
  );
  assert.throws(
    () => assertLiveActivationFrontendBuildSha256(
      value.stageTwo,
      pin("ff"),
      value.stageTwoOptions,
    ),
    /exact audited frontend build/,
  );

  const activeStateExtraField = structuredClone(binding);
  activeStateExtraField.royalty_release_active_state.attacker = true;
  assert.throws(
    () => normalizeLiveActivationFrontendBinding(activeStateExtraField),
    /exact schema/,
  );

  const pausedRoyalty = structuredClone(binding);
  pausedRoyalty.royalty_release_active_state.paused = true;
  assert.throws(
    () => normalizeLiveActivationFrontendBinding(pausedRoyalty),
    /phase-two RoyaltyDistributor state must be active/,
  );

  const royaltyBlockDrift = structuredClone(binding);
  royaltyBlockDrift.royalty_release_active_state.block_hash = word("fb");
  assert.throws(
    () => normalizeLiveActivationFrontendBinding(royaltyBlockDrift),
    /active poststate drifted/,
  );
});

test("Royalty release history digest normalizes exact phase shapes and dual-RPC authority", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const history = value.stageTwo.contract_state.royalty_release_history;
  const options = {
    contracts: value.stageTwo.contract_state.contracts,
    commonFinalizedState: value.stageTwo.common_finalized_state,
  };
  assert.equal(
    normalizedRoyaltyReleaseHistorySha256(history, options),
    value.stageTwo.contract_state.royalty_release_history_sha256,
  );
  const receipt = projectRoyaltyReleaseHistoryReceipt({
    contracts: options.contracts,
    commonFinalizedState: options.commonFinalizedState,
    royaltyReleaseHistory: history,
  });
  assert.equal(receipt.schema, ROYALTY_RELEASE_HISTORY_RECEIPT_SCHEMA);
  assert.equal(
    receipt.truth_status,
    ROYALTY_RELEASE_HISTORY_RECEIPT_TRUTH_STATUS,
  );
  assert.deepEqual(normalizeRoyaltyReleaseHistoryReceipt(receipt), receipt);
  assert.equal(
    royaltyReleaseHistoryReceiptSha256(receipt),
    value.stageTwo.contract_state.royalty_release_history_receipt_sha256,
  );

  const receiptProjectionDrift = structuredClone(receipt);
  receiptProjectionDrift.royalty_release_active_state.paused = true;
  assert.throws(
    () => normalizeRoyaltyReleaseHistoryReceipt(receiptProjectionDrift),
    /phase-two RoyaltyDistributor state must be active/,
  );

  const receiptCommonDigestDrift = structuredClone(receipt);
  receiptCommonDigestDrift.common_finalized_state_sha256 = pin("fa");
  assert.throws(
    () => normalizeRoyaltyReleaseHistoryReceipt(receiptCommonDigestDrift),
    /common finalized state digest is invalid/,
  );

  const extraTopLevelField = structuredClone(history);
  extraTopLevelField.attacker = true;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(extraTopLevelField, options),
    /exact schema/,
  );

  const extraPhaseField = structuredClone(history);
  extraPhaseField.phase_two.attacker = true;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(extraPhaseField, options),
    /phase-two history fields do not match the exact schema/,
  );

  const missingMutation = structuredClone(history);
  delete missingMutation.phase_two.unpause_transaction;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(missingMutation, options),
    /phase-two history fields do not match the exact schema/,
  );

  const wrongPhaseState = structuredClone(history);
  wrongPhaseState.phase_one.poststate = structuredClone(history.fresh_state);
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(wrongPhaseState, options),
    /phase_one_pending evidence phase|phase-one RoyaltyDistributor state/,
  );

  const aliasedRpc = structuredClone(history);
  aliasedRpc.phase_two.activation_transaction.secondary_rpc_id_sha256 =
    aliasedRpc.phase_two.activation_transaction.primary_rpc_id_sha256;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(aliasedRpc, options),
    /does not use the common dual-RPC authority/,
  );
});

test("Royalty H v2 proves a finalized reverted unpause and one contiguous recovery retry", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture({
    royaltyExecutionMode: "recover_reverted_unpause",
  });
  const live = normalizeLiveActivationAuthority(
    value.stageTwo,
    value.stageTwoOptions,
  );
  const history = live.contract_state.royalty_release_history;
  const options = {
    contracts: live.contract_state.contracts,
    commonFinalizedState: live.common_finalized_state,
  };
  const activation = history.phase_two.activation_transaction;
  const reverted = history.phase_two.reverted_unpause_transaction;
  const recovery = history.phase_two.unpause_transaction;
  assert.equal(history.schema, ROYALTY_RELEASE_HISTORY_V2_SCHEMA);
  assert.equal(history.execution_mode, "recover_reverted_unpause");
  assert.equal(reverted.primary_rpc_receipt.status, 0);
  assert.equal(reverted.primary_rpc_receipt.logs.length, 0);
  assert.equal(
    BigInt(reverted.primary_rpc_transaction.nonce),
    BigInt(activation.primary_rpc_transaction.nonce) + 1n,
  );
  assert.equal(
    BigInt(recovery.primary_rpc_transaction.nonce),
    BigInt(reverted.primary_rpc_transaction.nonce) + 1n,
  );

  const receipt = projectRoyaltyReleaseHistoryReceipt({
    contracts: options.contracts,
    commonFinalizedState: options.commonFinalizedState,
    royaltyReleaseHistory: history,
  });
  assert.equal(receipt.schema, ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA);
  assert.equal(receipt.execution_mode, "recover_reverted_unpause");
  assert.deepEqual(normalizeRoyaltyReleaseHistoryReceipt(receipt), receipt);
  assert.equal(
    royaltyReleaseHistoryReceiptSha256(receipt),
    live.contract_state.royalty_release_history_receipt_sha256,
  );

  const wrongStatus = structuredClone(history);
  wrongStatus.phase_two.reverted_unpause_transaction
    .primary_rpc_receipt.status = 1;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(wrongStatus, options),
    /receipt status/,
  );

  const missingRevert = structuredClone(history);
  delete missingRevert.phase_two.reverted_unpause_transaction;
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(missingRevert, options),
    /phase-two history fields do not match the exact schema/,
  );

  const disguisedNormalMode = structuredClone(history);
  disguisedNormalMode.execution_mode = "activate_and_unpause";
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(disguisedNormalMode, options),
    /phase-two history fields do not match the exact schema/,
  );

  const skippedNonce = structuredClone(history);
  const skippedRecovery = skippedNonce.phase_two.unpause_transaction;
  for (const rpc of ["primary", "secondary"]) {
    const transaction = skippedRecovery[`${rpc}_rpc_transaction`];
    transaction.nonce = String(BigInt(transaction.nonce) + 1n);
    skippedRecovery[`${rpc}_rpc_transaction_sha256`] =
      ceremonyTransactionRpcObservationSha256(transaction);
  }
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(skippedNonce, options),
    /contiguous retry/,
  );

  const revertedWithLogs = structuredClone(history);
  const revertedMutation =
    revertedWithLogs.phase_two.reverted_unpause_transaction;
  const successLogs = history.phase_two.unpause_transaction
    .primary_rpc_receipt.logs;
  for (const rpc of ["primary", "secondary"]) {
    const failedReceipt = revertedMutation[`${rpc}_rpc_receipt`];
    failedReceipt.logs = structuredClone(successLogs);
    revertedMutation[`${rpc}_rpc_receipt_sha256`] =
      ceremonyReceiptRpcObservationSha256(failedReceipt, {
        expectedStatus: 0,
      });
  }
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(revertedWithLogs, options),
    /one finalized reverted unpause/,
  );

  const receiptModeDrift = structuredClone(receipt);
  receiptModeDrift.execution_mode = "activate_and_unpause";
  assert.throws(
    () => normalizeRoyaltyReleaseHistoryReceipt(receiptModeDrift),
    /execution mode drifts/,
  );
});

test("Royalty H v2 keeps normal activation and unpause contiguous", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture({
    royaltyExecutionMode: "activate_and_unpause",
  });
  const history = value.stageTwo.contract_state.royalty_release_history;
  const options = {
    contracts: value.stageTwo.contract_state.contracts,
    commonFinalizedState: value.stageTwo.common_finalized_state,
  };
  assert.equal(history.schema, ROYALTY_RELEASE_HISTORY_V2_SCHEMA);
  assert.equal(history.execution_mode, "activate_and_unpause");
  assert.equal(
    normalizedRoyaltyReleaseHistorySha256(history, options),
    value.stageTwo.contract_state.royalty_release_history_sha256,
  );
  const skippedNonce = structuredClone(history);
  const unpause = skippedNonce.phase_two.unpause_transaction;
  for (const rpc of ["primary", "secondary"]) {
    const transaction = unpause[`${rpc}_rpc_transaction`];
    transaction.nonce = String(BigInt(transaction.nonce) + 1n);
    unpause[`${rpc}_rpc_transaction_sha256`] =
      ceremonyTransactionRpcObservationSha256(transaction);
  }
  assert.throws(
    () => normalizedRoyaltyReleaseHistorySha256(skippedNonce, options),
    /activation and unpause must be contiguous/,
  );
});

test("missing, self-selected, or forged transitive reviewer dependencies fail", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(value.stageOne),
    /deployment intent dependency/,
  );
  const forgedGenesis = structuredClone(value.genesis);
  forgedGenesis.status_guardians[0].address =
    value.intent.deploymentControl.operatorAddress;
  forgedGenesis.status_guardians.sort((left, right) =>
    left.address.localeCompare(right.address));
  forgedGenesis.status_guardian_hashes = forgedGenesis.status_guardians
    .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  forgedGenesis.status_guardian_root_hash = executionPolicyReviewerRootHash(
    forgedGenesis.status_guardian_hashes,
  );
  forgedGenesis.status_guardian_set_sha256 = reviewerSetSha256(
    forgedGenesis.status_guardians,
  );
  assert.throws(() => normalizeCeremonyAuthorizationCore(value.stageOne, {
    ...value.stageOneOptions,
    reviewerGenesis: forgedGenesis,
  }), /status guardians.*deployment-role identities/);
  const driftedRuntime = structuredClone(value.runtimeAuthority);
  driftedRuntime.cvm_launch_intent_sha256 = pin("ab");
  assert.throws(() => normalizeCeremonyAuthorizationCore(value.stageOne, {
    ...value.stageOneOptions,
    preCeremonyRuntimeAuthority: driftedRuntime,
  }), /runtime.*invalid|plan or launch lineage drifted|transitive.*drifted/);
});

test("Stage 2 rejects Stage-1 substitution, RPC disagreement, wrong stage, and replay expiry", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const wrongStage = structuredClone(value.stageTwo);
  wrongStage.review.stage = CEREMONY_AUTHORIZATION_CORE_STATUS;
  assert.throws(() => normalizeLiveActivationAuthority(wrongStage, value.stageTwoOptions), /review stage/);

  const rpcDisagreement = structuredClone(value.stageTwo);
  rpcDisagreement.ceremony_transactions[0].secondary_rpc_receipt.cumulative_gas_used =
    "500001";
  rpcDisagreement.ceremony_transactions[0].secondary_rpc_receipt_sha256 =
    ceremonyReceiptRpcObservationSha256(
      rpcDisagreement.ceremony_transactions[0].secondary_rpc_receipt,
    );
  assert.throws(
    () => normalizeLiveActivationAuthority(rpcDisagreement, value.stageTwoOptions),
    /independent RPC observations disagree/,
  );

  const stateDisagreement = structuredClone(value.stageTwo);
  stateDisagreement.common_finalized_state.secondary_state_sha256 = pin("fe");
  assert.throws(
    () => normalizeLiveActivationAuthority(stateDisagreement, value.stageTwoOptions),
    /finalized state observations disagree/,
  );

  assert.throws(() => normalizeLiveActivationAuthority(value.stageTwo, {
    ...value.stageTwoOptions,
    checkedAtMs: Date.parse("2026-07-21T14:00:00.000Z"),
  }), /expired/);
});

test("Stage 2 rejects an omitted, opaque, or target-drifted activation execution receipt", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();

  const omitted = structuredClone(value.stageTwo);
  delete omitted.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  assert.throws(
    () => normalizeLiveActivationAuthority(omitted, value.stageTwoOptions),
    /post-ceremony evidence fields do not match/,
  );

  const opaque = structuredClone(value.stageTwo);
  opaque.post_ceremony_evidence
    .post_measurement_activation_execution_receipt_sha256 = pin("ff");
  assert.throws(
    () => normalizeLiveActivationAuthority(opaque, value.stageTwoOptions),
    /activation execution receipt drifted/,
  );

  const historicalReceipt = structuredClone(value.stageTwo);
  historicalReceipt.post_ceremony_evidence
    .post_measurement_activation_execution_receipt.schema =
      "dnai.phala-post-measurement-activation-execution-receipt.v3";
  assert.throws(
    () => normalizeLiveActivationAuthority(
      historicalReceipt,
      value.stageTwoOptions,
    ),
    /post-measurement activation execution truth boundary is invalid/,
  );

  const targetDrift = structuredClone(value.stageTwo);
  targetDrift.post_ceremony_evidence
    .post_measurement_activation_execution_receipt.target.app_id = "f".repeat(40);
  targetDrift.post_ceremony_evidence
    .post_measurement_activation_execution_receipt_sha256 =
      phalaPostMeasurementActivationExecutionReceiptSha256(
        targetDrift.post_ceremony_evidence
          .post_measurement_activation_execution_receipt,
      );
  assert.throws(
    () => normalizeLiveActivationAuthority(targetDrift, value.stageTwoOptions),
    /activation execution receipt drifted/,
  );

  const postRestartAttestationDrift = structuredClone(value.stageTwo);
  postRestartAttestationDrift.post_ceremony_evidence.final_cvms[0]
    .attestation_evidence_sha256 = pin("fe");
  assert.throws(
    () => normalizeLiveActivationAuthority(
      postRestartAttestationDrift,
      value.stageTwoOptions,
    ),
    /activation execution receipt drifted/,
  );

  const preauthorizedMutation = structuredClone(value.stageTwo);
  const receipt = preauthorizedMutation.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  receipt.patch.attempt_recorded_at = "2026-07-21T11:59:58Z";
  receipt.patch.observed_at = "2026-07-21T11:59:59Z";
  preauthorizedMutation.post_ceremony_evidence
    .post_measurement_activation_execution_receipt_sha256 =
      phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  assert.throws(
    () => normalizeLiveActivationAuthority(
      preauthorizedMutation,
      value.stageTwoOptions,
    ),
    /activation execution receipt drifted/,
  );
});

test("Stage 1 requires the exact externally pinned fresh receipt and anchor commitments", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const missingReceipt = { ...value.stageOneOptions };
  delete missingReceipt.freshContractDeploymentReceipt;
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(value.stageOne, missingReceipt),
    /fresh deployment receipt is invalid/,
  );

  const forgedReceipt = structuredClone(
    value.stageOneOptions.freshContractDeploymentReceipt,
  );
  forgedReceipt.contracts.find((entry) =>
    entry.name === "ExecutionPolicyAnchor")
    .reviewer_authority_genesis_acceptance_sha256_bytes32 = word("ff");
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(value.stageOne, {
      ...value.stageOneOptions,
      freshContractDeploymentReceipt: forgedReceipt,
    }),
    /fresh deployment receipt is invalid/,
  );
});

test("Stage 2 rejects opaque observation hashes, cumulative-gas drift, block forks, and anchor drift", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();

  const opaqueDigest = structuredClone(value.stageTwo);
  opaqueDigest.ceremony_transactions[0].primary_rpc_transaction_sha256 = pin("ff");
  assert.throws(
    () => normalizeLiveActivationAuthority(opaqueDigest, value.stageTwoOptions),
    /RPC observation digest is invalid/,
  );

  const rpcIdentityDrift = structuredClone(value.stageTwo);
  rpcIdentityDrift.ceremony_transactions[0].secondary_rpc_id_sha256 = pin("52");
  assert.throws(
    () => normalizeLiveActivationAuthority(rpcIdentityDrift, value.stageTwoOptions),
    /does not use the common independent RPC authority/,
  );

  const impossibleCumulativeGas = structuredClone(value.stageTwo);
  impossibleCumulativeGas.ceremony_transactions[0]
    .primary_rpc_receipt.cumulative_gas_used = "499999";
  assert.throws(
    () => normalizeLiveActivationAuthority(impossibleCumulativeGas, value.stageTwoOptions),
    /receipt gas observations are invalid/,
  );

  const historicalFork = structuredClone(value.stageTwo);
  historicalFork.ceremony_transactions[0].secondary_rpc_block.state_root = word("fe");
  historicalFork.ceremony_transactions[0].secondary_rpc_block_sha256 =
    commonFinalizedBlockRpcObservationSha256(
      historicalFork.ceremony_transactions[0].secondary_rpc_block,
    );
  assert.throws(
    () => normalizeLiveActivationAuthority(historicalFork, value.stageTwoOptions),
    /independent RPC observations disagree/,
  );

  const finalizedFork = structuredClone(value.stageTwo);
  finalizedFork.common_finalized_state.secondary_rpc_block.receipts_root = word("fd");
  finalizedFork.common_finalized_state.secondary_rpc_block_sha256 =
    commonFinalizedBlockRpcObservationSha256(
      finalizedFork.common_finalized_state.secondary_rpc_block,
    );
  assert.throws(
    () => normalizeLiveActivationAuthority(finalizedFork, value.stageTwoOptions),
    /common finalized state observations disagree/,
  );

  const anchorDrift = structuredClone(value.stageTwo);
  for (const side of ["primary_rpc_read", "secondary_rpc_read"]) {
    anchorDrift.contract_state.execution_policy_anchor_commitment[side]
      .deployment_intent_sha256_bytes32 = word("fc");
  }
  anchorDrift.contract_state.execution_policy_anchor_commitment
    .primary_rpc_read_sha256 = executionPolicyAnchorRpcReadSha256(
      anchorDrift.contract_state.execution_policy_anchor_commitment.primary_rpc_read,
    );
  anchorDrift.contract_state.execution_policy_anchor_commitment
    .secondary_rpc_read_sha256 = executionPolicyAnchorRpcReadSha256(
      anchorDrift.contract_state.execution_policy_anchor_commitment.secondary_rpc_read,
    );
  assert.throws(
    () => normalizeLiveActivationAuthority(anchorDrift, value.stageTwoOptions),
    /does not match the signed deployment authority/,
  );

  const directAuthorityDrift = structuredClone(value.stageTwo);
  directAuthorityDrift.contract_state.reviewer_authority_genesis_acceptance_sha256 =
    pin("fb");
  assert.throws(
    () => normalizeLiveActivationAuthority(directAuthorityDrift, value.stageTwoOptions),
    /contract state deployment authority commitments drifted from Stage 1/,
  );
});
