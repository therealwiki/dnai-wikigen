import assert from "node:assert/strict";
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
} from "./release-authority-stages.fixture.mjs";
import {
  syntheticPreCeremonyRuntimeAuthorityFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";

const FORGED = privateKeyToAccount(`0x${"33".repeat(32)}`);

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
  assert.equal(stageOne.status, CEREMONY_AUTHORIZATION_CORE_STATUS);
  assert.equal(stageTwo.status, LIVE_ACTIVATION_AUTHORITY_STATUS);
  assert.equal(stageTwo.schema, "dnai.live-activation-authority.v6");
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
