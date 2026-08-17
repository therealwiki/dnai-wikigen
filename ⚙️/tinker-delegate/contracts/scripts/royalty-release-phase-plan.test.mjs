import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { privateKeyToAccount } from "../../../../web/node_modules/viem/_esm/accounts/index.js";

import {
  canonicalArtifactSha256,
  createDraftDeploymentIntentCore,
} from "../../../../scripts/operator-policy-packet-core.mjs";
import {
  normalizeStageBSuccessorReviewerAuthority,
} from "../../../../scripts/release-authority-current-reviewer-facade.mjs";
import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "../../../../scripts/release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  reviewerControllerSetSha256,
} from "../../../../scripts/release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "../../../../scripts/release-reviewer-authority-genesis-acceptance.mjs";
import {
  syntheticFreshContractDeploymentReceiptFixture,
} from "../../../../scripts/fresh-contract-deployment-receipt.fixture.mjs";
import {
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "../../../../scripts/execution-policy-release-core.mjs";
import {
  knownVector,
} from "../../../../scripts/execution-policy-release-core.fixture.mjs";
import {
  syntheticReleaseAuthorityStagesFixture,
} from "../../../../scripts/release-authority-stages.fixture.mjs";
import {
  projectRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "../../../../scripts/royalty-release-history-receipt-core.mjs";
import {
  royaltyReleasePolicyCommitment as canonicalRoyaltyReleasePolicyCommitment,
  royaltyReleaseStateSha256,
} from "../../../../scripts/royalty-release-authority-core.mjs";
import {
  REQUIRED_FINAL_RELEASE_AUTHORITY_V4_SCHEMA,
  REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA,
  ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_SCHEMA,
  ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_TRUTH_STATUS,
  ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA,
  ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA,
  ROYALTY_RELEASE_PHASE_PLAN_SIGNATURES_SCHEMA,
  attachRoyaltyReleasePhasePlan,
  createRoyaltyReleaseReviewerContext,
  deriveRoyaltyFreshDeploymentContext,
  generateRoyaltyReleasePhasePlanCore,
  normalizeRoyaltyReleasePhasePlanCore,
  normalizeRoyaltyReleasePrescriptiveAuthority,
  normalizeRoyaltySettlementReleaseBinding,
  projectRoyaltySettlementReleaseBinding,
  reconcileRoyaltySettlementReleaseBinding,
  royaltyReleaseActionCalldata,
  royaltyReleaseActionCalldataSha256,
  royaltyReleasePhasePlanSha256,
  royaltyReleasePhasePlanSigningMessage,
  royaltyReleasePolicyCommitment,
  royaltyReleasePrescriptiveAuthoritySha256,
  royaltySettlementReleaseBindingSha256,
  verifyRoyaltyReleasePhasePlan,
} from "./royalty-release-phase-plan.mjs";
import {
  ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
  royaltyUnpauseRecoveryEvidenceSha256,
} from "./royalty-release-finality.mjs";

const CLI = fileURLToPath(new URL("./royalty-release-phase-plan.mjs", import.meta.url));

const ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const GUARDIAN_ALPHA = privateKeyToAccount(`0x${"44".repeat(32)}`);
const GUARDIAN_BRAVO = privateKeyToAccount(`0x${"55".repeat(32)}`);
const CHECKED_AT_MS = Date.now();
const RELEASE_SHA = "ab".repeat(20);
const TINKER_BINDING_RECEIPT_SHA256 = `sha256:${"d1".repeat(32)}`;

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function word(pair) {
  return `0x${pair.repeat(32)}`;
}

function secondsTimestamp(offsetMs) {
  return new Date(Math.floor((CHECKED_AT_MS + offsetMs) / 1_000) * 1_000)
    .toISOString().replace(".000Z", "Z");
}

function millisecondsTimestamp(offsetMs) {
  return new Date(CHECKED_AT_MS + offsetMs).toISOString();
}

function validQvlPolicy() {
  return {
    challengeCapacity: 1_024,
    challengeTtlSeconds: 60,
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    verificationTimeoutSeconds: "20",
  };
}

function reviewer(account, controllerId) {
  return { address: account.address.toLowerCase(), controller_id: controllerId };
}

const REVIEWER_ACCOUNTS = [ALPHA, BRAVO];
const REVIEWERS = [
  reviewer(ALPHA, "reviewer-alpha"),
  reviewer(BRAVO, "reviewer-bravo"),
].sort((left, right) => left.address.localeCompare(right.address));
const REVIEWER_CONTROLLERS = REVIEWERS.map((entry) => ({
  controller_id: entry.controller_id,
  preauthorized_addresses: [entry.address],
})).sort((left, right) => left.controller_id.localeCompare(right.controller_id));
const GUARDIAN_ACCOUNTS = [GUARDIAN_ALPHA, GUARDIAN_BRAVO];
const STATUS_GUARDIANS = GUARDIAN_ACCOUNTS.map((account, index) => ({
  address: account.address.toLowerCase(),
  controller_id: `status-guardian-${index + 1}`,
})).sort((left, right) => left.address.localeCompare(right.address));
const GUARDIAN_HASHES = STATUS_GUARDIANS
  .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
const REVIEWER_GENESIS = {
  schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  release_sha: RELEASE_SHA,
  chain_id: 84_532,
  minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  reviewer_controllers: REVIEWER_CONTROLLERS,
  reviewer_controller_set_sha256: reviewerControllerSetSha256(REVIEWER_CONTROLLERS),
  status_guardians: STATUS_GUARDIANS,
  status_guardian_hashes: GUARDIAN_HASHES,
  status_guardian_root_hash: executionPolicyReviewerRootHash(GUARDIAN_HASHES),
  status_guardian_set_sha256: reviewerSetSha256(STATUS_GUARDIANS),
};
const CURRENT_STATUS_PAYLOAD = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
  epoch: 1,
  not_before: secondsTimestamp(-60_000),
  expires_at: secondsTimestamp(14 * 60_000),
  previous_status_sha256: `sha256:${"0".repeat(64)}`,
  active_reviewers: REVIEWERS,
  revoked_controller_ids: [],
  revoked_reviewer_addresses: [],
}, { reviewerGenesis: REVIEWER_GENESIS });
const CURRENT_STATUS_MESSAGE = releaseReviewerAuthorityCurrentStatusSigningMessage(
  CURRENT_STATUS_PAYLOAD,
  { reviewerGenesis: REVIEWER_GENESIS },
);
const GUARDIAN_BY_ADDRESS = new Map(
  GUARDIAN_ACCOUNTS.map((account) => [account.address.toLowerCase(), account]),
);
const REVIEWER_CURRENT_STATUS = {
  ...CURRENT_STATUS_PAYLOAD,
  schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  signing_payload_sha256: releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
    CURRENT_STATUS_PAYLOAD,
    { reviewerGenesis: REVIEWER_GENESIS },
  ),
  guardian_signatures: await Promise.all(STATUS_GUARDIANS.map(async (guardian) => ({
    ...guardian,
    signature: (await GUARDIAN_BY_ADDRESS.get(guardian.address).signMessage({
      message: CURRENT_STATUS_MESSAGE,
    })).toLowerCase(),
  }))),
};
const ACCEPTANCE_PAYLOAD = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
  REVIEWER_GENESIS,
  { reviewerCurrentStatus: REVIEWER_CURRENT_STATUS },
);
const ACCEPTANCE_MESSAGE = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
  ACCEPTANCE_PAYLOAD,
  { reviewerGenesis: REVIEWER_GENESIS },
);
const REVIEWER_BY_ADDRESS = new Map(
  REVIEWER_ACCOUNTS.map((account) => [account.address.toLowerCase(), account]),
);
const REVIEWER_GENESIS_ACCEPTANCE = {
  ...ACCEPTANCE_PAYLOAD,
  schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  signing_payload_sha256: releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
    ACCEPTANCE_PAYLOAD,
    { reviewerGenesis: REVIEWER_GENESIS },
  ),
  acceptances: await Promise.all(REVIEWERS.map(async (entry) => ({
    ...entry,
    signature: (await REVIEWER_BY_ADDRESS.get(entry.address).signMessage({
      message: ACCEPTANCE_MESSAGE,
    })).toLowerCase(),
  }))),
};
const DEPLOYMENT_INTENT = createDraftDeploymentIntentCore();
DEPLOYMENT_INTENT.release.releaseSha = RELEASE_SHA;
DEPLOYMENT_INTENT.release.reviewerAuthorityGenesisAcceptanceSha256 =
  releaseReviewerAuthorityGenesisAcceptanceSha256(
    REVIEWER_GENESIS_ACCEPTANCE,
    { reviewerGenesis: REVIEWER_GENESIS },
  );
DEPLOYMENT_INTENT.release.reviewerAuthorityCurrentStatusEpoch =
  REVIEWER_CURRENT_STATUS.epoch;
DEPLOYMENT_INTENT.release.reviewerAuthorityCurrentStatusSha256 =
  releaseReviewerAuthorityCurrentStatusSha256(
    REVIEWER_CURRENT_STATUS,
    { reviewerGenesis: REVIEWER_GENESIS },
  );
DEPLOYMENT_INTENT.deploymentControl.controllerId = "deployment-operator-01";
DEPLOYMENT_INTENT.deploymentControl.operatorAddress = address(1);
DEPLOYMENT_INTENT.staticContractInputs.diligenceRoom.governanceController = address(19);
DEPLOYMENT_INTENT.staticContractInputs.computeCreditVault.developer = address(20);
DEPLOYMENT_INTENT.staticContractInputs.tinkerAccountEncumbrance.accountCommitment = word("03");
DEPLOYMENT_INTENT.numericPolicy.contract = {
  computeDeveloperFeeBps: 100,
  emailOracleUpgradeDelaySeconds: 172_800,
  tinkerMaxAddBalanceWei: "5000000000000000000",
  tinkerMaxSpendWei: "2000000000000000000",
};
DEPLOYMENT_INTENT.numericPolicy.metering = {
  maxConcurrency: 4,
  rateCapacity: 30,
  rateRefillPerSecond: "0.5",
  requestBodyTimeoutSeconds: "5",
  rpcTimeoutSeconds: "8",
};
for (const name of Object.keys(DEPLOYMENT_INTENT.numericPolicy.qvl)) {
  DEPLOYMENT_INTENT.numericPolicy.qvl[name] = validQvlPolicy();
}

const LINEAGE = normalizeStageBSuccessorReviewerAuthority({
  reviewerGenesis: REVIEWER_GENESIS,
  reviewerGenesisAcceptance: REVIEWER_GENESIS_ACCEPTANCE,
  reviewerStatusHistory: [],
  deploymentIntent: DEPLOYMENT_INTENT,
  checkedAtMs: CHECKED_AT_MS,
  enforceFreshness: true,
});
const CURRENT_CORE_FIXTURE = knownVector();
const FRESH_FIXTURE = syntheticFreshContractDeploymentReceiptFixture({
  releaseSha: RELEASE_SHA,
  deploymentIntentSha256: canonicalArtifactSha256(DEPLOYMENT_INTENT),
  reviewerAuthorityGenesisAcceptanceSha256: LINEAGE.acceptanceSha256,
  tinkerAccountBindingCeremonyReceiptSha256: TINKER_BINDING_RECEIPT_SHA256,
  contractOverrides: {
    emailOracleAuth: { address: address(14) },
    executionPolicyAnchor: {
      address:
        CURRENT_CORE_FIXTURE.execution_policy.rollback_anchor_target
          .contract_address,
      runtimeCodeHash:
        CURRENT_CORE_FIXTURE.execution_policy.rollback_anchor_target
          .runtime_code_hash,
    },
    royaltyDistributor: {
      address: CURRENT_CORE_FIXTURE.contracts.royalty_distributor.address,
      runtimeCodeHash:
        CURRENT_CORE_FIXTURE.contracts.royalty_distributor.runtime_code_hash,
    },
  },
});
const FRESH_CONTEXT = deriveRoyaltyFreshDeploymentContext({
  deploymentIntent: DEPLOYMENT_INTENT,
  reviewerLineage: LINEAGE,
  freshDeploymentManifest: FRESH_FIXTURE.ledger,
  tinkerAccountBindingCeremonyReceiptSha256: TINKER_BINDING_RECEIPT_SHA256,
});

function replaceScalar(value, before, after) {
  if (Array.isArray(value)) {
    return value.map((entry) => replaceScalar(entry, before, after));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
      key,
      replaceScalar(entry, before, after),
    ]));
  }
  return value === before ? after : value;
}

function currentFinalAuthorityV4() {
  const fixture = knownVector();
  const oldRelease = fixture.release_sha;
  const oldIntent = fixture.deployment_intent_sha256;
  let value = replaceScalar(fixture, oldRelease, RELEASE_SHA);
  value = replaceScalar(
    value,
    oldIntent,
    canonicalArtifactSha256(DEPLOYMENT_INTENT),
  );
  Object.assign(value.requested_features, {
    collaboration: true,
    collaboration_execution: true,
    royalty_settlement: true,
  });
  value.collaboration_execution.enabled = true;

  const distributor = FRESH_CONTEXT.royaltyDistributor;
  const anchor = FRESH_CONTEXT.executionPolicyAnchor;
  const anchorWriter =
    value.execution_policy.rollback_anchor_target.writer_address;
  Object.assign(value.contracts.royalty_distributor, {
    address: distributor.address,
    runtime_code_hash: distributor.runtimeCodeHash,
  });
  Object.assign(value.execution_policy.rollback_anchor_target, {
    contract_address: anchor.address,
    runtime_code_hash: anchor.runtimeCodeHash,
  });
  const royalty = value.royalty_release_authority;
  Object.assign(royalty, {
    distributor_address: distributor.address,
    owner: DEPLOYMENT_INTENT.deploymentControl.operatorAddress,
    settlement_verifier: address(30),
    qvl_verifier: address(31),
    execution_policy_anchor: anchor.address,
    anchor_writer: anchorWriter,
  });
  royalty.release_policy_commitment = canonicalRoyaltyReleasePolicyCommitment({
    chainId: royalty.chain_id,
    distributorAddress: royalty.distributor_address,
    authorityNonce: royalty.authority_nonce,
    settlementVerifier: royalty.settlement_verifier,
    qvlVerifier: royalty.qvl_verifier,
    executionPolicyAnchor: royalty.execution_policy_anchor,
    anchorWriterReleaseCommitment:
      royalty.anchor_writer_release_commitment,
  });
  Object.assign(value.royalty_release_active_state, {
    contract_address: distributor.address,
    owner: royalty.owner,
    settlement_verifier: royalty.settlement_verifier,
    qvl_verifier: royalty.qvl_verifier,
    execution_policy_anchor: royalty.execution_policy_anchor,
    anchor_writer_release_commitment:
      royalty.anchor_writer_release_commitment,
    release_policy_commitment: royalty.release_policy_commitment,
    authority_nonce: royalty.authority_nonce,
    computed_release_policy_commitment: royalty.release_policy_commitment,
  });
  value.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
    value.royalty_release_active_state,
    { authority: royalty, phase: "phase_two_active" },
  );
  Object.assign(value.royalty_settlement_release_binding_template, {
    distributor_address: distributor.address,
    distributor_runtime_code_hash: distributor.runtimeCodeHash,
    authority_nonce: royalty.authority_nonce,
    settlement_verifier_address: royalty.settlement_verifier,
    royalty_qvl_verifier_address: royalty.qvl_verifier,
    execution_policy_anchor_address: royalty.execution_policy_anchor,
    anchor_writer_release_commitment:
      royalty.anchor_writer_release_commitment,
    release_policy_commitment: royalty.release_policy_commitment,
  });
  return normalizeFinalReleaseAuthorityCore(value);
}

const FINAL_RELEASE_AUTHORITY_V4 = currentFinalAuthorityV4();
const FINAL_RELEASE_AUTHORITY_V4_SHA256 =
  `sha256:${finalReleaseAuthorityCoreDigest(FINAL_RELEASE_AUTHORITY_V4)}`;
const ROYALTY_SETTLEMENT_RELEASE_BINDING =
  projectRoyaltySettlementReleaseBinding(FINAL_RELEASE_AUTHORITY_V4);
const ROYALTY_SETTLEMENT_RELEASE_BINDING_SHA256 =
  royaltySettlementReleaseBindingSha256(
    ROYALTY_SETTLEMENT_RELEASE_BINDING,
    { finalReleaseAuthorityV4: FINAL_RELEASE_AUTHORITY_V4 },
  );

function contextInputs() {
  return {
    deploymentIntent: DEPLOYMENT_INTENT,
    freshDeploymentManifest: FRESH_FIXTURE.ledger,
    royaltyReleasePrescriptiveAuthority: prescription(),
    tinkerAccountBindingCeremonyReceiptSha256:
      TINKER_BINDING_RECEIPT_SHA256,
    reviewerGenesis: REVIEWER_GENESIS,
    reviewerGenesisAcceptance: REVIEWER_GENESIS_ACCEPTANCE,
    reviewerCurrentStatus: REVIEWER_CURRENT_STATUS,
    reviewerStatusHistory: [],
    checkedAtMs: CHECKED_AT_MS,
  };
}

function authority() {
  const royalty = FINAL_RELEASE_AUTHORITY_V4.royalty_release_authority;
  const anchor = FINAL_RELEASE_AUTHORITY_V4.execution_policy.rollback_anchor_target;
  const draft = {
    distributor_address: FRESH_CONTEXT.royaltyDistributor.address,
    distributor_runtime_code_hash: FRESH_CONTEXT.royaltyDistributor.runtimeCodeHash,
    owner: DEPLOYMENT_INTENT.deploymentControl.operatorAddress,
    settlement_verifier: royalty.settlement_verifier,
    qvl_verifier: royalty.qvl_verifier,
    anchor_address: FRESH_CONTEXT.executionPolicyAnchor.address,
    anchor_runtime_code_hash: FRESH_CONTEXT.executionPolicyAnchor.runtimeCodeHash,
    anchor_writer: anchor.writer_address,
    anchor_writer_release_commitment: anchor.writer_release_commitment,
    authority_nonce: "1",
    release_policy_commitment: royalty.release_policy_commitment,
  };
  assert.equal(draft.release_policy_commitment, royaltyReleasePolicyCommitment(draft));
  return draft;
}

function prescription() {
  return normalizeRoyaltyReleasePrescriptiveAuthority({
    schema: ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA,
    release_sha: RELEASE_SHA,
    deployment_intent_sha256: canonicalArtifactSha256(DEPLOYMENT_INTENT),
    fresh_contract_deployment_receipt_sha256:
      FRESH_CONTEXT.freshContractDeploymentReceiptSha256,
    authority: authority(),
    royalty_settlement_release_binding_template:
      FINAL_RELEASE_AUTHORITY_V4.royalty_settlement_release_binding_template,
  });
}

function finalAuthorityForHistoryReceipt(historyReceipt) {
  const value = knownVector();
  const royalty = historyReceipt.royalty_release_authority;
  const activeState = historyReceipt.royalty_release_active_state;
  const distributor = historyReceipt.contracts.find(
    (entry) => entry.contract_key === "royalty_distributor",
  );
  const anchor = historyReceipt.contracts.find(
    (entry) => entry.contract_key === "execution_policy_anchor",
  );
  Object.assign(value.requested_features, {
    collaboration: true,
    collaboration_execution: true,
    royalty_settlement: true,
  });
  value.collaboration_execution.enabled = true;
  value.operator_address = royalty.owner;
  Object.assign(value.contracts.royalty_distributor, {
    address: distributor.address,
    runtime_code_hash: distributor.runtime_code_hash,
  });
  Object.assign(value.execution_policy.rollback_anchor_target, {
    contract_address: anchor.address,
    runtime_code_hash: anchor.runtime_code_hash,
    writer_address: royalty.anchor_writer,
    writer_release_commitment: royalty.anchor_writer_release_commitment,
  });
  value.royalty_release_authority = royalty;
  value.royalty_release_active_state = activeState;
  value.royalty_release_active_state_sha256 = royaltyReleaseStateSha256(
    activeState,
    { authority: royalty, phase: "phase_two_active" },
  );
  value.royalty_release_history_sha256 =
    historyReceipt.royalty_release_history_sha256;
  value.royalty_release_history_receipt_sha256 =
    royaltyReleaseHistoryReceiptSha256(historyReceipt);
  Object.assign(value.royalty_settlement_release_binding_template, {
    distributor_address: distributor.address,
    distributor_runtime_code_hash: distributor.runtime_code_hash,
    authority_nonce: royalty.authority_nonce,
    settlement_verifier_address: royalty.settlement_verifier,
    royalty_qvl_verifier_address: royalty.qvl_verifier,
    execution_policy_anchor_address: royalty.execution_policy_anchor,
    anchor_writer_release_commitment:
      royalty.anchor_writer_release_commitment,
    release_policy_commitment: royalty.release_policy_commitment,
  });
  return normalizeFinalReleaseAuthorityCore(value);
}

function prescriptionForFinalAuthority(finalAuthority) {
  const royalty = finalAuthority.royalty_release_authority;
  const anchor = finalAuthority.execution_policy.rollback_anchor_target;
  return normalizeRoyaltyReleasePrescriptiveAuthority({
    schema: ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA,
    release_sha: finalAuthority.release_sha,
    deployment_intent_sha256: finalAuthority.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256: `sha256:${"ed".repeat(32)}`,
    authority: {
      distributor_address: royalty.distributor_address,
      distributor_runtime_code_hash:
        finalAuthority.contracts.royalty_distributor.runtime_code_hash,
      owner: royalty.owner,
      settlement_verifier: royalty.settlement_verifier,
      qvl_verifier: royalty.qvl_verifier,
      anchor_address: royalty.execution_policy_anchor,
      anchor_runtime_code_hash: anchor.runtime_code_hash,
      anchor_writer: royalty.anchor_writer,
      anchor_writer_release_commitment:
        royalty.anchor_writer_release_commitment,
      release_policy_commitment: royalty.release_policy_commitment,
      authority_nonce: String(royalty.authority_nonce),
    },
    royalty_settlement_release_binding_template:
      finalAuthority.royalty_settlement_release_binding_template,
  });
}

function phaseOnePrerequisite() {
  return {
    phase_one_plan_sha256: `sha256:${"b1".repeat(32)}`,
    phase_one_history_record_sha256: `sha256:${"b2".repeat(32)}`,
    phase_one_finalized_at: millisecondsTimestamp(-2_500),
    finalized_authority_receipt_sha256: `sha256:${"b3".repeat(32)}`,
    ledger_sha256: `sha256:${"b4".repeat(32)}`,
    ledger_revision: 3,
    ledger_revision_receipt_sha256: `sha256:${"b5".repeat(32)}`,
    proposal_tx_hash: `0x${"b6".repeat(32)}`,
    proposal_block_number: "1234567",
    proposal_block_hash: `0x${"b7".repeat(32)}`,
    pending_authority_activates_at: String(Math.floor((CHECKED_AT_MS - 3_000) / 1_000)),
  };
}

function phaseTwoRecovery() {
  return {
    prior_phase_two_plan_sha256: `sha256:${"c1".repeat(32)}`,
    finalized_recovery_evidence_sha256: `sha256:${"c2".repeat(32)}`,
    activation_tx_hash: `0x${"c3".repeat(32)}`,
    activation_block_number: "1239999",
    activation_block_hash: `0x${"c4".repeat(32)}`,
    reverted_unpause_tx_hash: `0x${"c5".repeat(32)}`,
    reverted_unpause_block_number: "1240000",
    reverted_unpause_block_hash: `0x${"c6".repeat(32)}`,
    prior_unpause_nonce: "42",
  };
}

function core(phase = 1, executionMode = phase === 1 ? "stage_authority" : "activate_and_unpause") {
  const exactAuthority = authority();
  const actions = executionMode === "stage_authority"
    ? ["propose_authority_binding"]
    : executionMode === "activate_and_unpause"
      ? ["activate_authority_proposal", "unpause"]
      : ["unpause"];
  const recovery = executionMode === "recover_reverted_unpause" ? phaseTwoRecovery() : null;
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA,
    status: "proposed_for_review",
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    phase,
    execution_mode: executionMode,
    phase_one_prerequisite: phase === 1 ? null : phaseOnePrerequisite(),
    phase_two_recovery: recovery,
    valid_after: millisecondsTimestamp(-1_000),
    expires_at: millisecondsTimestamp(10 * 60_000),
    deployment_intent_sha256: canonicalArtifactSha256(DEPLOYMENT_INTENT),
    fresh_contract_deployment_receipt_sha256:
      FRESH_CONTEXT.freshContractDeploymentReceiptSha256,
    royalty_release_prescriptive_authority_sha256:
      royaltyReleasePrescriptiveAuthoritySha256(prescription()),
    reviewer_authority_genesis_sha256: LINEAGE.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256: LINEAGE.acceptanceSha256,
    reviewer_authority_current_status_epoch: LINEAGE.currentStatus.epoch,
    reviewer_authority_current_status_sha256: LINEAGE.currentStatusSha256,
    reviewer_root_hash: LINEAGE.authority.reviewer_root_hash,
    reviewer_set_sha256: LINEAGE.authority.reviewer_set_sha256,
    authority: exactAuthority,
    transactions: actions.map((action, sequence) => ({
      sequence,
      action,
      signer_address: exactAuthority.owner,
      nonce: recovery === null
        ? String(41 + sequence)
        : String(BigInt(recovery.prior_unpause_nonce) + 1n),
      to: exactAuthority.distributor_address,
      value_wei: "0",
      calldata: royaltyReleaseActionCalldata(action, exactAuthority),
      calldata_sha256: royaltyReleaseActionCalldataSha256(action, exactAuthority),
    })),
  };
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function rawSha256Text(text) {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

function generationRequest(
  phase = 1,
  executionMode = phase === 1 ? "stage_authority" : "activate_and_unpause",
  firstTransactionNonce = "41",
) {
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_SCHEMA,
    truth_status: ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_TRUTH_STATUS,
    phase,
    execution_mode: executionMode,
    first_transaction_nonce: firstTransactionNonce,
    valid_after: millisecondsTimestamp(-1_000),
    expires_at: millisecondsTimestamp(10 * 60_000),
  };
}

function phaseOneLedgerRecord() {
  return {
    kind: "royalty_distributor_exact_authority_release_phase",
    royaltyDistributorAddress: authority().distributor_address,
    phase: 1,
    executionMode: "stage_authority",
    phasePlanSha256: `sha256:${"b1".repeat(32)}`,
    recordedAt: millisecondsTimestamp(-4_000),
    transactionReceipts: [{
      transactionHash: `0x${"b6".repeat(32)}`,
      blockNumber: 1_234_567,
      blockHash: `0x${"b7".repeat(32)}`,
    }],
    finalizedAuthority: {
      schema: "dnai.base-sepolia-royalty-finalized-authority.v1",
      finalizedBlockNumber: 1_234_568,
      finalizedBlockHash: `0x${"b8".repeat(32)}`,
      finalizedBlockTimestamp: Math.floor((CHECKED_AT_MS - 3_000) / 1_000),
    },
    postState: {
      pendingAuthorityActivatesAt: Math.floor((CHECKED_AT_MS - 2_000) / 1_000),
    },
  };
}

function generationLedger(phase = 1) {
  return {
    schemaVersion: 2,
    freshDeployment: { contractSuite: { sourceCommit: RELEASE_SHA } },
    contracts: {
      royaltyDistributor: {
        address: FRESH_CONTEXT.royaltyDistributor.address,
        runtimeCodeHash: FRESH_CONTEXT.royaltyDistributor.runtimeCodeHash,
        owner: authority().owner,
        sourceCommit: RELEASE_SHA,
        latestReleasePhase: phase === 1 ? 0 : 1,
      },
    },
    royaltyReleaseHistory: phase === 1 ? [] : [phaseOneLedgerRecord()],
  };
}

function generationLedgerReplay(ledger, revisionCount = 3) {
  const text = canonicalText(ledger);
  return {
    protocol: "dnai.release-ceremony-ledger.v1",
    release_sha: RELEASE_SHA,
    initialization_receipt_sha256: `sha256:${"91".repeat(32)}`,
    revision_count: revisionCount,
    revision_chain_sha256: `sha256:${"92".repeat(32)}`,
    last_revision_receipt_sha256:
      revisionCount === 0 ? null : `sha256:${"93".repeat(32)}`,
    current_ledger_sha256: rawSha256Text(text),
    current_ledger_bytes: Buffer.byteLength(text, "utf8"),
    ledger_mode: "0600",
    finalized: false,
    finalization_receipt_sha256: null,
    recovery_receipt_count: 0,
  };
}

function recoveryEvidence() {
  const exactAuthority = authority();
  const receipt = (action, sequence, status, nonce, blockNumber, pair) => ({
    sequence,
    action,
    sender: exactAuthority.owner,
    target: exactAuthority.distributor_address,
    nonce,
    valueWei: "0",
    calldata: royaltyReleaseActionCalldata(action, exactAuthority),
    calldataSha256: royaltyReleaseActionCalldataSha256(action, exactAuthority),
    transactionHash: `0x${pair.repeat(32)}`,
    status,
    blockNumber,
    blockHash: `0x${(blockNumber === 1_239_999 ? "c4" : "c6").repeat(32)}`,
    blockTimestamp: Math.floor(CHECKED_AT_MS / 1_000),
    transactionIndex: sequence,
  });
  const evidence = {
    schema: ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
    evidenceSha256: `sha256:${"00".repeat(32)}`,
    priorPhaseTwoPlanSha256: `sha256:${"c1".repeat(32)}`,
    activationReceipt: receipt(
      "activate_authority_proposal", 0, "success", "41", 1_239_999, "c3",
    ),
    revertedUnpauseReceipt: receipt("unpause", 1, "reverted", "42", 1_240_000, "c5"),
  };
  evidence.evidenceSha256 = royaltyUnpauseRecoveryEvidenceSha256(evidence);
  return evidence;
}

function generateCore({
  request = generationRequest(),
  ledger = generationLedger(request.phase),
  replay = generationLedgerReplay(ledger),
  recovery,
} = {}) {
  return generateRoyaltyReleasePhasePlanCore({
    generationRequest: request,
    ledger,
    ledgerReplay: replay,
    recoveryEvidence: recovery,
    reviewerContext: createRoyaltyReleaseReviewerContext(contextInputs()),
    checkedAtMs: CHECKED_AT_MS,
  });
}

async function externalSignatures(value) {
  const message = royaltyReleasePhasePlanSigningMessage(value);
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_SIGNATURES_SCHEMA,
    plan_sha256: royaltyReleasePhasePlanSha256(value),
    signatures: (await Promise.all(REVIEWER_ACCOUNTS.map(async (account) => ({
      ...REVIEWERS.find((entry) => entry.address === account.address.toLowerCase()),
      signature: (await account.signMessage({ message })).toLowerCase(),
    })))).sort((left, right) => left.address.localeCompare(right.address)),
  };
}

function assertCoreRejected(value, expected) {
  assert.throws(
    () => normalizeRoyaltyReleasePhasePlanCore(value, { checkedAtMs: CHECKED_AT_MS }),
    expected,
  );
}

test("phase plans recompute policy and exact ordered calldata", () => {
  assert.throws(() => normalizeRoyaltyReleasePhasePlanCore(core(1)), /requires checkedAtMs/);
  const phaseOne = normalizeRoyaltyReleasePhasePlanCore(core(1), {
    checkedAtMs: CHECKED_AT_MS,
  });
  assert.equal(phaseOne.authority.authority_nonce, "1");
  assert.equal(
    phaseOne.authority.release_policy_commitment,
    royaltyReleasePolicyCommitment(phaseOne.authority),
  );
  assert.deepEqual(phaseOne.transactions.map((entry) => entry.action), [
    "propose_authority_binding",
  ]);

  const phaseTwo = normalizeRoyaltyReleasePhasePlanCore(core(2), {
    checkedAtMs: CHECKED_AT_MS,
  });
  assert.deepEqual(phaseTwo.transactions.map((entry) => entry.action), [
    "activate_authority_proposal",
    "unpause",
  ]);
  assert.equal(BigInt(phaseTwo.transactions[1].nonce), BigInt(phaseTwo.transactions[0].nonce) + 1n);

  const recovery = normalizeRoyaltyReleasePhasePlanCore(
    core(2, "recover_reverted_unpause"),
    { checkedAtMs: CHECKED_AT_MS },
  );
  assert.deepEqual(recovery.transactions.map((entry) => entry.action), ["unpause"]);
  assert.equal(recovery.transactions[0].nonce, "43");
});

test("generate-core derives every authority, lineage, action, calldata, and phase-one prerequisite", async () => {
  const phaseOne = generateCore();
  assert.deepEqual(phaseOne.authority, authority());
  assert.equal(phaseOne.release_sha, RELEASE_SHA);
  assert.equal(
    phaseOne.fresh_contract_deployment_receipt_sha256,
    FRESH_CONTEXT.freshContractDeploymentReceiptSha256,
  );
  assert.deepEqual(phaseOne.transactions.map((entry) => ({
    action: entry.action,
    nonce: entry.nonce,
    calldata: entry.calldata,
  })), [{
    action: "propose_authority_binding",
    nonce: "41",
    calldata: royaltyReleaseActionCalldata("propose_authority_binding", authority()),
  }]);

  const phaseTwoRequest = generationRequest(2, "activate_and_unpause", "42");
  const ledger = generationLedger(2);
  const phaseTwo = generateCore({
    request: phaseTwoRequest,
    ledger,
    replay: generationLedgerReplay(ledger, 4),
  });
  assert.deepEqual(phaseTwo.transactions.map((entry) => [entry.action, entry.nonce]), [
    ["activate_authority_proposal", "42"],
    ["unpause", "43"],
  ]);
  assert.equal(
    phaseTwo.phase_one_prerequisite.phase_one_plan_sha256,
    ledger.royaltyReleaseHistory[0].phasePlanSha256,
  );
  assert.equal(phaseTwo.phase_one_prerequisite.ledger_revision, 4);
  assert.equal(
    phaseTwo.phase_one_prerequisite.proposal_tx_hash,
    ledger.royaltyReleaseHistory[0].transactionReceipts[0].transactionHash,
  );

  const signatures = await externalSignatures(phaseOne);
  const reviewerContext = createRoyaltyReleaseReviewerContext(contextInputs());
  const reviewed = attachRoyaltyReleasePhasePlan({
    core: phaseOne,
    externalSignatures: signatures,
    reviewerContext,
    checkedAtMs: CHECKED_AT_MS,
  });
  assert.equal(
    verifyRoyaltyReleasePhasePlan({
      plan: reviewed,
      reviewerContext,
      checkedAtMs: CHECKED_AT_MS,
    }).plan_sha256,
    royaltyReleasePhasePlanSha256(phaseOne),
  );
});

test("generate-core derives recovery only from exact finalized evidence", () => {
  const request = generationRequest(2, "recover_reverted_unpause", "43");
  const ledger = generationLedger(2);
  const evidence = recoveryEvidence();
  const generated = generateCore({
    request,
    ledger,
    replay: generationLedgerReplay(ledger, 5),
    recovery: evidence,
  });
  assert.equal(generated.transactions.length, 1);
  assert.equal(generated.transactions[0].nonce, "43");
  assert.equal(
    generated.phase_two_recovery.finalized_recovery_evidence_sha256,
    evidence.evidenceSha256,
  );

  const drifted = structuredClone(evidence);
  drifted.revertedUnpauseReceipt.status = "success";
  assert.throws(() => generateCore({
    request,
    ledger,
    replay: generationLedgerReplay(ledger, 5),
    recovery: drifted,
  }), /status must equal reverted/);

  const wrongNonce = generationRequest(2, "recover_reverted_unpause", "44");
  assert.throws(() => generateCore({
    request: wrongNonce,
    ledger,
    replay: generationLedgerReplay(ledger, 5),
    recovery: evidence,
  }), /nonce is not exactly one after/);
});

test("generate-core rejects ledger, replay, phase, and post-ceremony authority drift", () => {
  const ledger = generationLedger(1);
  const staleReplay = generationLedgerReplay(ledger);
  staleReplay.current_ledger_sha256 = `sha256:${"ee".repeat(32)}`;
  assert.throws(() => generateCore({ ledger, replay: staleReplay }), /exact canonical working-ledger bytes/);

  const wrongRuntime = generationLedger(1);
  wrongRuntime.contracts.royaltyDistributor.runtimeCodeHash = word("ee");
  assert.throws(() => generateCore({
    ledger: wrongRuntime,
    replay: generationLedgerReplay(wrongRuntime),
  }), /drifts from the immutable fresh receipt/);

  const skipped = generationLedger(2);
  skipped.royaltyReleaseHistory = [];
  assert.throws(() => generateCore({
    request: generationRequest(2),
    ledger: skipped,
    replay: generationLedgerReplay(skipped),
  }), /exactly one recorded Royalty phase one/);

  const finalAuthority = structuredClone(generationRequest());
  finalAuthority.final_release_authority_v4_sha256 = `sha256:${"ef".repeat(32)}`;
  assert.throws(() => generateCore({ request: finalAuthority }), /fields do not match the exact schema/);
});

test("recovery plans reject prior unpause nonce zero before reviewer authorization", () => {
  const value = core(2, "recover_reverted_unpause");
  value.phase_two_recovery.prior_unpause_nonce = "0";
  value.transactions[0].nonce = "1";
  assertCoreRejected(value, /prior unpause transaction nonce is out of range/);
});

test("pre-ceremony Royalty prescription brands one exact attach and verify context", async () => {
  const reviewerContext = createRoyaltyReleaseReviewerContext(contextInputs());
  const value = core(1);
  const signatures = await externalSignatures(value);
  const reviewed = attachRoyaltyReleasePhasePlan({
    core: value,
    externalSignatures: signatures,
    reviewerContext,
    checkedAtMs: CHECKED_AT_MS,
  });
  const receipt = verifyRoyaltyReleasePhasePlan({
    plan: reviewed,
    reviewerContext,
    checkedAtMs: CHECKED_AT_MS,
  });
  assert.equal(receipt.royalty_release_prescriptive_authority_sha256,
    royaltyReleasePrescriptiveAuthoritySha256(prescription()));
  assert.deepEqual(receipt.authority, authority());

  assert.throws(
    () => createRoyaltyReleaseReviewerContext({
      ...contextInputs(),
      checkedAtMs: CHECKED_AT_MS - 31_000,
    }),
    /stale or future-dated/,
  );
  assert.throws(
    () => createRoyaltyReleaseReviewerContext({
      ...contextInputs(),
      royaltyReleasePrescriptiveAuthority: {
        ...prescription(),
        schema: "dnai.royalty-release-prescriptive-authority.v0",
      },
    }),
    /prescriptive-authority schema/,
  );
  const collidingDeploymentIntent = structuredClone(DEPLOYMENT_INTENT);
  collidingDeploymentIntent.deploymentControl.controllerId =
    REVIEWER_GENESIS.reviewer_controllers[0].controller_id;
  assert.throws(
    () => createRoyaltyReleaseReviewerContext({
      ...contextInputs(),
      deploymentIntent: collidingDeploymentIntent,
    }),
    /must not reuse the deployment controller identity/,
  );
  assert.throws(() => attachRoyaltyReleasePhasePlan({
    core: value,
    externalSignatures: signatures,
    reviewerContext: {},
    checkedAtMs: CHECKED_AT_MS,
  }), /re-derived reviewer context/);
});

test("post-ceremony v4 H and pre-ceremony contract, runtime, and role drift fail closed", () => {
  assert.throws(
    () => reconcileRoyaltySettlementReleaseBinding({
      finalReleaseAuthorityV4: FINAL_RELEASE_AUTHORITY_V4,
      royaltySettlementReleaseBinding: ROYALTY_SETTLEMENT_RELEASE_BINDING,
      royaltyReleaseHistoryReceipt: {},
      royaltyReleasePrescriptiveAuthority: prescription(),
    }),
    /Royalty H receipt is invalid/,
  );
  const wrongH = structuredClone(ROYALTY_SETTLEMENT_RELEASE_BINDING);
  wrongH.royalty_release_history_receipt_sha256 = `sha256:${"ef".repeat(32)}`;
  assert.throws(
    () => normalizeRoyaltySettlementReleaseBinding(wrongH, {
      finalReleaseAuthorityV4: FINAL_RELEASE_AUTHORITY_V4,
    }),
    /differs from current final-authority v4 or H/,
  );

  const wrongContract = structuredClone(prescription());
  wrongContract.authority.distributor_address = address(777);
  wrongContract.royalty_settlement_release_binding_template.distributor_address =
    address(777);
  assert.throws(
    () => createRoyaltyReleaseReviewerContext({
      ...contextInputs(),
      royaltyReleasePrescriptiveAuthority: wrongContract,
    }),
    /release-policy commitment|differs from the fresh deployment/,
  );

  const wrongRuntime = structuredClone(prescription());
  wrongRuntime.authority.distributor_runtime_code_hash = word("fe");
  wrongRuntime.royalty_settlement_release_binding_template
    .distributor_runtime_code_hash = word("fe");
  assert.throws(
    () => createRoyaltyReleaseReviewerContext({
      ...contextInputs(),
      royaltyReleasePrescriptiveAuthority: wrongRuntime,
    }),
    /differs from the fresh deployment/,
  );

  const wrongRoles = structuredClone(prescription());
  wrongRoles.authority.qvl_verifier = wrongRoles.authority.settlement_verifier;
  wrongRoles.royalty_settlement_release_binding_template.royalty_qvl_verifier_address =
    wrongRoles.authority.settlement_verifier;
  assert.throws(
    () => normalizeRoyaltyReleasePrescriptiveAuthority(wrongRoles),
    /must all be distinct/,
  );
});

test("post-ceremony reconciliation binds raw H to current v4 and the signed prescription", async () => {
  const stages = await syntheticReleaseAuthorityStagesFixture({
    royaltyExecutionMode: "activate_and_unpause",
  });
  const historyReceipt = projectRoyaltyReleaseHistoryReceipt({
    contracts: stages.stageTwo.contract_state.contracts,
    commonFinalizedState: stages.stageTwo.common_finalized_state,
    royaltyReleaseHistory:
      stages.stageTwo.contract_state.royalty_release_history,
  });
  const finalAuthority = finalAuthorityForHistoryReceipt(historyReceipt);
  const prescriptiveAuthority = prescriptionForFinalAuthority(finalAuthority);
  const binding = projectRoyaltySettlementReleaseBinding(finalAuthority);
  const receipt = reconcileRoyaltySettlementReleaseBinding({
    finalReleaseAuthorityV4: finalAuthority,
    royaltySettlementReleaseBinding: binding,
    royaltyReleaseHistoryReceipt: historyReceipt,
    royaltyReleasePrescriptiveAuthority: prescriptiveAuthority,
  });
  assert.equal(
    receipt.royalty_release_history_receipt_sha256,
    royaltyReleaseHistoryReceiptSha256(historyReceipt),
  );
  assert.equal(
    receipt.royalty_release_prescriptive_authority_sha256,
    royaltyReleasePrescriptiveAuthoritySha256(prescriptiveAuthority),
  );

  const driftedPrescription = structuredClone(prescriptiveAuthority);
  driftedPrescription.royalty_settlement_release_binding_template.main_runtime_cvm_id =
    "different-main-runtime";
  assert.throws(
    () => reconcileRoyaltySettlementReleaseBinding({
      finalReleaseAuthorityV4: finalAuthority,
      royaltySettlementReleaseBinding: binding,
      royaltyReleaseHistoryReceipt: historyReceipt,
      royaltyReleasePrescriptiveAuthority: driftedPrescription,
    }),
    /v4, H, fresh prescription/,
  );
});

test("authority, calldata, ordering, digest, and nonce drift fail closed", () => {
  const cases = [
    [(value) => { value.authority.authority_nonce = "2"; }, /nonce 1/],
    [(value) => { value.authority.release_policy_commitment = `0x${"ee".repeat(32)}`; },
      /release-policy commitment/],
    [(value) => { value.transactions[0].calldata = "0x552d3bd4"; }, /calldata differs/],
    [(value) => { value.transactions[0].calldata_sha256 = `sha256:${"ee".repeat(32)}`; },
      /calldata digest/],
    [(value) => { value.transactions[0].action = "unpause"; }, /order or action/],
    [(value) => { value.transactions[0].sequence = 1; }, /order or action/],
    [(value) => { value.execution_mode = "activate_and_unpause"; },
      /phase and execution mode are incompatible/],
  ];
  for (const [mutate, expected] of cases) {
    const value = core(1);
    mutate(value);
    assertCoreRejected(value, expected);
  }

  const noncontiguous = core(2);
  noncontiguous.transactions[1].nonce = "99";
  assertCoreRejected(noncontiguous, /nonces must be contiguous/);

  const recoveryNonce = core(2, "recover_reverted_unpause");
  recoveryNonce.transactions[0].nonce = "44";
  assertCoreRejected(recoveryNonce, /exactly one after/);

  const replayedEvidence = core(2, "recover_reverted_unpause");
  replayedEvidence.phase_two_recovery.reverted_unpause_tx_hash =
    replayedEvidence.phase_two_recovery.activation_tx_hash;
  assertCoreRejected(replayedEvidence, /hashes must differ/);
});

test("phase 2 cannot predate the timelock or finalized phase-one evidence", () => {
  const beforeActivation = core(2);
  beforeActivation.phase_one_prerequisite.pending_authority_activates_at =
    String(Math.floor((CHECKED_AT_MS + 1_000) / 1_000));
  assertCoreRejected(beforeActivation, /cannot become valid before timelock activation/);

  const beforeFinality = core(2);
  beforeFinality.phase_one_prerequisite.phase_one_finalized_at =
    millisecondsTimestamp(1_000);
  assertCoreRejected(beforeFinality, /cannot become valid before timelock activation/);
});

test("recovery evidence rejects impossible block and proposal ordering", () => {
  const activationAfterRevert = core(2, "recover_reverted_unpause");
  activationAfterRevert.phase_two_recovery.activation_block_number = "1240001";
  assertCoreRejected(activationAfterRevert, /block order or hash identity is impossible/);

  const equalHeightDifferentHash = core(2, "recover_reverted_unpause");
  equalHeightDifferentHash.phase_two_recovery.activation_block_number = "1240000";
  assertCoreRejected(equalHeightDifferentHash, /block order or hash identity is impossible/);

  const differentHeightSameHash = core(2, "recover_reverted_unpause");
  differentHeightSameHash.phase_two_recovery.activation_block_hash =
    differentHeightSameHash.phase_two_recovery.reverted_unpause_block_hash;
  assertCoreRejected(differentHeightSameHash, /block order or hash identity is impossible/);

  const proposalAfterActivation = core(2, "recover_reverted_unpause");
  proposalAfterActivation.phase_one_prerequisite.proposal_block_number = "1239999";
  assertCoreRejected(proposalAfterActivation, /proposal block must precede/);
});

test("expiry and exact new authority digests are enforced structurally", () => {
  const expired = core(1);
  expired.expires_at = millisecondsTimestamp(119_999);
  assertCoreRejected(expired, /currently valid with required headroom/);

  for (const field of [
    "fresh_contract_deployment_receipt_sha256",
    "royalty_release_prescriptive_authority_sha256",
  ]) {
    const value = core(1);
    delete value[field];
    assertCoreRejected(value, /fields do not match the exact schema/);
  }
});

test("generate-core CLI writes one canonical private core and rejects overwrite or forbidden authority", (context) => {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-royalty-core-")),
  );
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  fs.chmodSync(directory, 0o700);
  const inputs = {
    "deployment-intent.json": DEPLOYMENT_INTENT,
    "fresh-manifest.json": FRESH_FIXTURE.ledger,
    "reviewer-genesis.json": REVIEWER_GENESIS,
    "reviewer-genesis-acceptance.json": REVIEWER_GENESIS_ACCEPTANCE,
    "reviewer-current-status.json": REVIEWER_CURRENT_STATUS,
    "reviewer-status-history.json": [],
    "royalty-prescription.json": prescription(),
    "generation-request.json": generationRequest(),
  };
  const ledger = generationLedger(1);
  inputs["ledger.json"] = ledger;
  inputs["ledger-replay.json"] = generationLedgerReplay(ledger);
  for (const [name, value] of Object.entries(inputs)) {
    fs.writeFileSync(path.join(directory, name), canonicalText(value), { mode: 0o600 });
  }
  const output = path.join(directory, "phase-core.json");
  const args = [
    CLI,
    "generate-core",
    "--deployment-intent", path.join(directory, "deployment-intent.json"),
    "--fresh-deployment-manifest", path.join(directory, "fresh-manifest.json"),
    "--reviewer-genesis", path.join(directory, "reviewer-genesis.json"),
    "--reviewer-genesis-acceptance", path.join(directory, "reviewer-genesis-acceptance.json"),
    "--reviewer-current-status", path.join(directory, "reviewer-current-status.json"),
    "--reviewer-status-history", path.join(directory, "reviewer-status-history.json"),
    "--royalty-release-prescription", path.join(directory, "royalty-prescription.json"),
    "--tinker-account-binding-ceremony-receipt-sha256", TINKER_BINDING_RECEIPT_SHA256,
    "--generation-request", path.join(directory, "generation-request.json"),
    "--ledger", path.join(directory, "ledger.json"),
    "--ledger-replay", path.join(directory, "ledger-replay.json"),
    "--out", output,
  ];
  const created = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.equal(created.status, 0, created.stderr);
  const summary = JSON.parse(created.stdout);
  assert.equal(summary.status, "phase_plan_core_written_for_two_reviewer_review");
  assert.equal(summary.output_path, output);
  assert.equal(fs.statSync(output).mode & 0o777, 0o600);
  const generated = JSON.parse(fs.readFileSync(output, "utf8"));
  assert.equal(fs.readFileSync(output, "utf8"), canonicalText(generated));
  assert.equal(summary.plan_sha256, royaltyReleasePhasePlanSha256(generated));

  const overwrite = spawnSync(process.execPath, args, { encoding: "utf8" });
  assert.notEqual(overwrite.status, 0);
  assert.match(overwrite.stderr, /output path must be absolute, canonical, and absent/);

  const forbidden = spawnSync(process.execPath, [
    ...args.slice(0, -2),
    "--final-release-authority-v4", path.join(directory, "fresh-manifest.json"),
    "--out", path.join(directory, "forbidden.json"),
  ], { encoding: "utf8" });
  assert.notEqual(forbidden.status, 0);
  assert.match(forbidden.stderr, /unexpected arguments for generate-core/);

  const link = path.join(directory, "ledger-link.json");
  fs.symlinkSync(path.join(directory, "ledger.json"), link);
  const symlinked = [...args];
  symlinked[symlinked.indexOf("--ledger") + 1] = link;
  symlinked[symlinked.indexOf("--out") + 1] = path.join(directory, "symlinked.json");
  const rejectedLink = spawnSync(process.execPath, symlinked, { encoding: "utf8" });
  assert.notEqual(rejectedLink.status, 0);
  assert.match(rejectedLink.stderr, /canonical and symlink-free/);
});
