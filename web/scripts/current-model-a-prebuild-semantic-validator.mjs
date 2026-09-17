import { types as utilTypes } from "node:util";
import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "../../scripts/canonical-authority-graph.mjs";
import {
  CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS,
} from "../../scripts/current-model-a-input-recipe-core.mjs";
import {
  normalizeModelAStableInputSet,
  reconstructModelARecordedLaunchAuthority,
} from "../../scripts/exact37-model-a-semantic-validator.mjs";
import {
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../scripts/execution-policy-release-core.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
  phalaPostMeasurementRuntimeCommitmentsSha256,
} from "../../scripts/phala-post-measurement-activation-receipt-v4-core.mjs";
import {
  assertPrebuildVerifiedComputeWorkloadActivationObservation,
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  projectComputeWorkloadBrowserBindingFromPrebuildObservation,
} from "../../scripts/compute-workload-activation-observation-core.mjs";
import {
  normalizeRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "../../scripts/royalty-release-history-receipt-core.mjs";
import { normalizeReleaseCandidate } from "./release-env-core.mjs";
import {
  validateExecutionPolicyReleaseCoreBinding,
} from "./execution-policy-release-core-binding.mjs";

export { CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS };

export const CURRENT_MODEL_A_PREBUILD_VALIDATION_SCHEMA =
  "dnai.current-model-a-prebuild-semantic-validation.v1";
export const CURRENT_MODEL_A_PREBUILD_VALIDATION_STATUS =
  "current_l_r_signed_b_standalone_activation_receipt_and_prebuild_o_validated_current_release_checks_pending";

function fail(message) {
  throw new TypeError(`current Model-A prebuild: ${message}`);
}

function exact(value, keys, label) {
  // Stable file inputs contain a deliberately unread bytes accessor. Inspect
  // only this options envelope; the shared loader snapshots input data without
  // evaluating that accessor. Reject option proxies/getters before reading any.
  if (!value || typeof value !== "object" || utilTypes.isProxy(value)
    || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    fail(`${label} must be a plain data record`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string")
    || JSON.stringify(ownKeys.sort()) !== JSON.stringify([...keys].sort())
    || Object.values(descriptors).some((descriptor) => !descriptor.enumerable
      || !Object.hasOwn(descriptor, "value"))) {
    fail(`${label} must contain exactly the required fields`);
  }
  return value;
}

function equal(actual, expected, label) {
  if (actual !== expected) fail(`${label} differs from independently authenticated authority`);
}

function second(value, label) {
  const result = typeof value === "string" ? Date.parse(value) : NaN;
  if (!Number.isSafeInteger(result) || result < 1 || result % 1_000 !== 0
    || new Date(result).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a canonical UTC second`);
  }
  return result;
}

function uniqueDomain(entries, domain, label) {
  const matches = Array.isArray(entries) ? entries.filter((entry) => entry.domain === domain) : [];
  if (matches.length !== 1) fail(`${label} must contain exactly one ${domain}`);
  return matches[0];
}

/** Pure comparison only. The caller obtains this graph from recorded replay. */
function bindStandaloneActivationReceipt(receipt, authority) {
  const runtime = authority.runtimeAuthority;
  const plan = runtime.post_measurement_activation_plan;
  const launch = authority.launchReceipt;
  const expected = {
    release_sha: runtime.release_sha,
    deployment_intent_sha256: authority.intentSha256,
    cvm_launch_intent_sha256: runtime.cvm_launch_intent_sha256,
    release_verification_authority_sha256: runtime.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256: authority.launchSha256,
    seven_cvm_verified_evidence_set_sha256:
      authority.historicalMachineEvidence.seven_cvm_verified_evidence_set_sha256,
    initial_activation_evidence_lease_expires_at: runtime.activation_evidence_lease_expires_at,
    phala_recovery_directory_identity_anchor_sha256:
      runtime.phala_recovery_directory_identity_anchor_sha256,
    pre_ceremony_runtime_authority_sha256: authority.runtimeAuthoritySha256,
    post_measurement_activation_plan_sha256: runtime.post_measurement_activation_plan_sha256,
    ceremony_authorization_sha256: authority.stageOneSha256,
    batch_id: launch.batch_id,
    runtime_commitments_sha256: phalaPostMeasurementRuntimeCommitmentsSha256(plan.runtime_commitments),
    runtime_commitment_key_names_sha256: plan.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256: plan.allowed_environment_key_names_sha256,
    allowed_environment_key_count: plan.allowed_environment_key_count,
    injected_environment_key_names_sha256: plan.injected_environment_key_names_sha256,
    injected_environment_key_count: plan.injected_environment_key_names.length,
  };
  for (const [field, value] of Object.entries(expected)) {
    equal(receipt[field], value, `standalone receipt ${field}`);
  }
  const main = uniqueDomain(launch.domains, "main_runtime_cvm", "authenticated L");
  const mainTarget = {
    domain: "main_runtime_cvm",
    descriptor_sha256: main.descriptor_sha256,
    app_id: main.app_id,
    cvm_id: main.cvm_id,
    compose_hash: main.committed_compose_hash,
    os_image_hash: main.os_image_hash,
  };
  for (const [field, value] of Object.entries(mainTarget)) {
    equal(receipt.target[field], value, `standalone receipt target ${field}`);
    equal(plan.target[field], value, `authenticated activation plan target ${field}`);
  }
  equal(plan.seven_cvm_verified_evidence_set_sha256,
    expected.seven_cvm_verified_evidence_set_sha256, "activation plan evidence set");
  equal(plan.activation_evidence_lease_expires_at,
    receipt.initial_activation_evidence_lease_expires_at, "activation plan initial lease");
  equal(plan.batch_id, receipt.batch_id, "activation plan batch");
  equal(JSON.stringify(receipt.profile_activation), JSON.stringify(plan.profile_activation),
    "standalone receipt activated profiles");
  equal(receipt.terminal_evidence_lease_expires_at, Math.min(
    runtime.activation_evidence_lease_expires_at,
    receipt.recipient_activation.recipient_evidence_lease_expires_at,
  ), "terminal evidence lease minimum");
  const completedAtMs = second(receipt.completed_at, "receipt completion");
  const bSignedAtMs = Date.parse(authority.stageOne.review.signed_at);
  const bExpiresAtMs = Date.parse(authority.stageOne.review.expires_at);
  if (!Number.isSafeInteger(bSignedAtMs) || !Number.isSafeInteger(bExpiresAtMs)
    || second(receipt.patch.attempt_recorded_at, "receipt PATCH attempt") < bSignedAtMs
    || completedAtMs >= bExpiresAtMs
    || completedAtMs >= receipt.terminal_evidence_lease_expires_at * 1_000) {
    fail("standalone receipt execution is outside signed B or its terminal evidence lease");
  }
  return completedAtMs;
}

/** Bind the independently normalized execution receipt to O's actual proof. */
function bindReceiptRecipientProof(receipt, observation) {
  const verification = observation.verification;
  const recipient = observation.recipient;
  const expected = {
    activation_verification_sha256: verification.activation_verification_sha256,
    source_activation_sha256: verification.activation_artifact_sha256,
    raw_transcript_sha256: verification.raw_transcript_sha256,
    qvl_verdict_verifier_signature_sha256: verification.qvl_verdict_verifier_signature_sha256,
    tdx_quote_sha256: verification.tdx_quote_sha256,
    challenge_id: verification.challenge_id,
    report_data: recipient.report_data,
    recipient_key_id: recipient.recipient_key_id,
    recipient_release_commitment: recipient.recipient_release_commitment,
    authenticated_at: verification.authenticated_at,
    verified_at: verification.verified_at,
    verdict_activation_evidence_lease_expires_at:
      verification.verdict_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at: verification.recipient_evidence_lease_expires_at,
    expires_at: verification.activation_verification_expires_at,
  };
  for (const [field, value] of Object.entries(expected)) {
    equal(receipt.recipient_activation[field], value, `receipt/O recipient ${field}`);
  }
}

function workloadExpectations(authority, receipt, receiptSha256) {
  const { runtimeAuthority: runtime, launchReceipt: launch } = authority;
  const main = uniqueDomain(launch.domains, "main_runtime_cvm", "authenticated L");
  const qvl = uniqueDomain(launch.domains, "compute_workload_qvl_cvm", "authenticated L");
  const reconstructedMain = uniqueDomain(authority.historicalMachineEvidence.evidence_set.domains,
    "main_runtime_cvm", "recorded-time machine evidence");
  equal(reconstructedMain.evidence_sha256, main.machine_evidence_sha256, "main runtime machine evidence");
  equal(runtime.post_measurement_activation_plan.runtime_commitments
    .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
  main.machine_evidence_sha256, "activation-plan main runtime commitment");
  const bootstrapMain = uniqueDomain(authority.bootstrapAuthority.domains,
    "main_runtime_cvm", "signed bootstrap authority");
  const ceremonyNonce = bootstrapMain.values.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE;
  equal(ceremonyNonce, runtime.post_measurement_activation_plan.runtime_commitments
    .TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE, "bootstrap/activation-plan ceremony nonce");
  const vaults = authority.contract.contracts.filter(({ name }) => name === "ComputeCreditVault");
  if (vaults.length !== 1) fail("authenticated contract receipt must contain one ComputeCreditVault");
  return deepFreezeCanonicalPlainDataGraph({
    releaseSha: runtime.release_sha,
    deploymentIntentSha256: authority.intentSha256,
    releaseVerificationAuthoritySha256: runtime.release_verification_authority_sha256,
    ceremonyNonce,
    qvlMeasurementPolicySetSha256: authority.signedAReceipt.qvl_measurement_policy_set_sha256,
    historicalTranscriptFileSetSha256: authority.transcriptSha256,
    freshContractDeploymentReceiptSha256: authority.contractSha256,
    nonliveBootstrapAuthorizationReceiptSha256: authority.signedAReceiptSha256,
    sevenCvmLaunchCompletionReceiptSha256: authority.launchSha256,
    sevenCvmVerifiedEvidenceSetSha256: receipt.seven_cvm_verified_evidence_set_sha256,
    preCeremonyRuntimeAuthoritySha256: authority.runtimeAuthoritySha256,
    postMeasurementActivationPlanSha256: runtime.post_measurement_activation_plan_sha256,
    postMeasurementActivationExecutionReceiptSha256: receiptSha256,
    ceremonyAuthorizationSha256: authority.stageOneSha256,
    initialActivationEvidenceLeaseExpiresAt: runtime.activation_evidence_lease_expires_at,
    recipientEvidenceLeaseExpiresAt: receipt.recipient_activation.recipient_evidence_lease_expires_at,
    terminalEvidenceLeaseExpiresAt: receipt.terminal_evidence_lease_expires_at,
    mainRuntimeAppId: main.app_id,
    mainRuntimeCvmId: main.cvm_id,
    mainRuntimeComposeHash: main.committed_compose_hash,
    mainRuntimeOsImageHash: main.os_image_hash,
    mainRuntimeDescriptorSha256: main.descriptor_sha256,
    mainRuntimePostureReceiptSha256: main.production_posture_verification_receipt_sha256,
    mainRuntimeTeeIdentity: main.tee_identity,
    mainRuntimeEvidenceSha256: main.machine_evidence_sha256,
    computeWorkloadQvlAppId: qvl.app_id,
    computeWorkloadQvlCvmId: qvl.cvm_id,
    computeWorkloadQvlComposeHash: qvl.committed_compose_hash,
    computeWorkloadQvlOsImageHash: qvl.os_image_hash,
    computeWorkloadQvlVerifierAddress: qvl.tee_identity,
    computeWorkloadQvlReleasePolicySha256: qvl.qvl_release_policy_sha256,
    computeWorkloadQvlMeasurementPolicySha256: qvl.tdx_measurement_authority_sha256,
    computeWorkloadQvlIdentityEvidenceSha256: qvl.machine_evidence_sha256,
    computeVaultAddress: vaults[0].address,
    computeVaultRuntimeCodeHash: vaults[0].runtime_code_hash,
  }, { label: "independently derived current prebuild O expectations" });
}

/**
 * Current acyclic 37-input prebuild validation. Historical 35/37 authority
 * contracts remain separate; this entry requires current core-v4/receipt-v4.
 * No future signed C, D, production brand, live mutation or caller verifier is
 * accepted. Recorded-time DCAP is supplied only by the shared real replay.
 */
export async function validateCurrentModelAPrebuildAuthority(options = {}) {
  exact(options, ["inputs", "validationTimeMs", "reviewerStatusHistory"], "current prebuild options");
  const { inputs, validationTimeMs, reviewerStatusHistory } = options;
  if (!Number.isSafeInteger(validationTimeMs) || validationTimeMs < 1
    || validationTimeMs > 4_102_444_800_000 || validationTimeMs % 1_000 !== 0) {
    fail("validationTimeMs must be an explicit bounded whole UTC second");
  }
  if (utilTypes.isProxy(reviewerStatusHistory)
    || !Array.isArray(reviewerStatusHistory) || reviewerStatusHistory.length !== 0) {
    fail("only the explicit empty epoch-one reviewer history is supported");
  }
  assertCanonicalPlainDataGraph(reviewerStatusHistory, { label: "epoch-one reviewer history" });
  const exactInputs = normalizeModelAStableInputSet(inputs,
    CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS, "current Model-A prebuild-37");
  const input = Object.fromEntries(Object.entries(exactInputs.byKey)
    .map(([key, entry]) => [key, entry.value]));
  const releaseCore = normalizeFinalReleaseAuthorityCore(input.releaseCore);
  const coreSha256 = `sha256:${finalReleaseAuthorityCoreDigest(releaseCore)}`;
  const activationExecutionReceipt = normalizePhalaPostMeasurementActivationExecutionReceipt(
    input.postMeasurementActivationExecutionReceipt,
  );
  const activationExecutionReceiptSha256 = phalaPostMeasurementActivationExecutionReceiptSha256(
    activationExecutionReceipt,
  );
  const royaltyReleaseHistoryReceipt = normalizeRoyaltyReleaseHistoryReceipt(input.royaltyReleaseHistoryReceipt);
  const royaltyReceiptSha256 = royaltyReleaseHistoryReceiptSha256(royaltyReleaseHistoryReceipt);
  const royaltyHistorySha256 = royaltyReleaseHistoryReceipt.royalty_release_history_sha256;
  if (new Set([exactInputs.byKey.royaltyReleaseHistoryReceipt.rawSha256,
    royaltyReceiptSha256, royaltyHistorySha256]).size !== 3) {
    fail("Royalty H raw bytes, receipt and history commitments must remain distinct");
  }
  const authority = await reconstructModelARecordedLaunchAuthority({
    exactInputs, validationTimeMs, reviewerStatusHistory,
  });
  if (authority.freshContractDescriptorTuple.authority_tuple !== "current"
    || authority.historicalReleaseVerificationAuthority.schema
      !== "dnai.phala-seven-cvm-release-verification-authority.v5"
    || authority.historicalReleaseVerificationAuthority.cvm_descriptor_runtime_authority.schema
      !== "dnai.cvm-descriptor-runtime-authority.v3") {
    fail("recorded launch must use the current contract/descriptor-v3/release-v5 tuple");
  }
  const completedAtMs = bindStandaloneActivationReceipt(activationExecutionReceipt, authority);
  const computeWorkloadObservationExpectations = workloadExpectations(authority,
    activationExecutionReceipt, activationExecutionReceiptSha256);
  const prebuildObservationReplay = assertPrebuildVerifiedComputeWorkloadActivationObservation({
    persistedObservation: input.computeWorkloadActivationObservation,
    expected: computeWorkloadObservationExpectations,
    completedAtMs,
  });
  const observation = prebuildObservationReplay.observation;
  bindReceiptRecipientProof(activationExecutionReceipt, observation);
  const observationSha256 = computeWorkloadActivationObservationSha256(observation);
  const browserBinding = projectComputeWorkloadBrowserBindingFromPrebuildObservation(prebuildObservationReplay);
  const candidate = normalizeReleaseCandidate(input.release, { authorityStage: "prebuild" });
  equal(candidate.release_sha, authority.runtimeAuthority.release_sha, "candidate release");
  equal(candidate.deployment_intent_sha256, authority.intentSha256, "candidate deployment intent");
  equal(candidate.operator_policy.runtime_authority_dependency_sha256,
    authority.runtimeAuthoritySha256, "candidate R");
  equal(candidate.operator_policy.ceremony_authorization_sha256,
    authority.stageOneSha256, "candidate signed B");
  const coreBinding = validateExecutionPolicyReleaseCoreBinding(candidate, releaseCore,
    authority.persistedRuntimeAuthority, {
      authorityStage: "prebuild",
      authenticatedRuntimeAuthoritySha256: authority.runtimeAuthoritySha256,
      royaltyReleaseHistoryReceipt,
    });
  equal(`sha256:${coreBinding.digest}`, coreSha256, "current release-core digest");
  equal(coreBinding.runtimeAuthoritySha256, authority.runtimeAuthoritySha256, "bound current R digest");
  const semanticLineage = {
    release_core_sha256: coreSha256,
    deployment_intent_sha256: authority.intentSha256,
    fresh_contract_deployment_receipt_sha256: authority.contractSha256,
    reviewer_authority_genesis_sha256: authority.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256: authority.acceptanceSha256,
    bootstrap_authority_sha256: authority.bootstrapAuthoritySha256,
    bootstrap_authorization_sha256: authority.bootstrapAuthorizationSha256,
    bootstrap_authorization_receipt_sha256: authority.signedAReceiptSha256,
    seven_cvm_launch_completion_receipt_sha256: authority.launchSha256,
    historical_transcript_file_set_sha256: authority.transcriptSha256,
    qvl_measurement_policy_set_sha256: computeWorkloadObservationExpectations.qvlMeasurementPolicySetSha256,
    runtime_authority_dependency_sha256: authority.runtimeAuthoritySha256,
    ceremony_authorization_sha256: authority.stageOneSha256,
    royalty_release_history_sha256: royaltyHistorySha256,
    royalty_release_history_receipt_sha256: royaltyReceiptSha256,
    post_measurement_activation_execution_receipt_sha256: activationExecutionReceiptSha256,
    compute_workload_activation_observation_sha256: observationSha256,
  };
  return deepFreezeCanonicalPlainDataGraph({
    schema: CURRENT_MODEL_A_PREBUILD_VALIDATION_SCHEMA,
    status: CURRENT_MODEL_A_PREBUILD_VALIDATION_STATUS,
    releaseSha: candidate.release_sha,
    candidate,
    authorityBinding: {
      deploymentIntentSha256: authority.intentSha256,
      reviewerAuthorityGenesisAcceptanceSha256: authority.acceptanceSha256,
      ceremonyAuthorizationSha256: authority.stageOneSha256,
      runtimeAuthorityDependencySha256: authority.runtimeAuthoritySha256,
      postMeasurementActivationExecutionReceiptSha256: activationExecutionReceiptSha256,
      computeWorkloadActivationObservationSha256: observationSha256,
      computeWorkloadBrowserBindingSha256: computeWorkloadBrowserBindingSha256(browserBinding),
    },
    semanticLineage,
    authorityRoots: {
      contract_release_set_sha256: authority.contractSha256,
      cvm_release_set_sha256: authority.launchSha256,
      qvl_measurement_policy_set_sha256: computeWorkloadObservationExpectations.qvlMeasurementPolicySetSha256,
    },
    computeWorkloadObservationExpectations,
    prebuildObservationReplay,
    normalizedArtifacts: {
      intent: authority.intent,
      genesis: authority.genesis,
      acceptance: authority.acceptance,
      contract: authority.contract,
      bootstrapAuthority: authority.bootstrapAuthority,
      signedAReceipt: authority.signedAReceipt,
      executor: authority.executor,
      launchReceipt: authority.launchReceipt,
      runtimeAuthority: authority.runtimeAuthority,
      stageOne: authority.stageOne,
      historicalO: observation,
      prebuildObservationReplay,
      activationExecutionReceipt,
      royaltyReleaseHistoryReceipt,
      reviewerReconstruction: authority.reviewerReconstruction,
      historicalMachineEvidence: authority.historicalMachineEvidence,
      historicalReleaseVerificationAuthority: authority.historicalReleaseVerificationAuthority,
      releaseCore,
    },
    historicalTranscript: authority.historicalTranscript,
    persistenceReceiptSha256: authority.persistenceReceiptSha256,
    current_clock_consulted_for_historical_a_l_r_o: false,
    historical_freshness_renewed: false,
    production_brand_minted_for_historical_a_l_r: false,
    signed_c_authorization_verified: false,
    liveTrafficAuthorized: false,
    downstreamLiveEvidenceBoundary: {
      required: true,
      truth_status: "current_chain_external_evidence_reproducible_D_and_signed_C_time_O_replay_must_still_validate",
    },
  }, { label: "current acyclic prebuild semantic result" });
}
