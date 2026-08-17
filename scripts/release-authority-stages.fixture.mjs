// Synthetic cryptographic fixture only. It is deliberately deterministic and
// includes public test keys; no artifact produced here is live release authority.
export const SYNTHETIC_RELEASE_AUTHORITY_STAGES_FIXTURE_TRUTH =
  "synthetic_test_fixture_never_live_release_authority";
import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  canonicalArtifactSha256,
  createDraftDeploymentIntentCore,
  DEPLOYMENT_TOOLCHAIN_AUTHORITY,
} from "./operator-policy-packet-core.mjs";
import { RELEASE_SHA } from "./execution-policy-release-core.fixture.mjs";
import {
  syntheticPreCeremonyRuntimeAuthorityFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  preCeremonyRuntimeAuthoritySha256,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
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
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA,
  CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA,
  CEREMONY_AUTHORIZATION_CORE_SCHEMA,
  CEREMONY_AUTHORIZATION_CORE_STATUS,
  COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA,
  EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_STATUS,
  LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
  LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  RELEASE_AUTHORITY_SIGNATURE_SCHEME,
  RELEASE_AUTHORITY_SIGNATURE_VERIFIER,
  RELEASE_CEREMONY_MUTATION_WRITERS,
  RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
  RELEASE_CONTRACT_STATE_KEYS,
  ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  ROYALTY_RELEASE_AUTHORITY_SCHEMA,
  ROYALTY_RELEASE_HISTORY_SCHEMA,
  ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
  ROYALTY_RELEASE_STATE_SCHEMA,
  canonicalCeremonyAuthorizationCoreArtifactText,
  canonicalLiveActivationAuthorityArtifactText,
  ceremonyReceiptRpcObservationSha256,
  ceremonyTransactionRpcObservationSha256,
  ceremonyAuthorizationCoreSha256,
  ceremonyAuthorizationReviewSigningPayload,
  commonFinalizedBlockRpcObservationSha256,
  executionPolicyAnchorRpcReadSha256,
  liveActivationAuthoritySha256,
  liveActivationFrontendBindingSha256,
  liveActivationReviewSigningPayload,
  liveContractConfigurationSetSha256,
  normalizedRoyaltyReleaseHistorySha256,
  royaltyReleaseMutationCalldataSha256,
  royaltyReleaseMutationEvent,
  royaltyReleasePolicyCommitment,
  royaltyReleaseStateSha256,
  normalizeCeremonyAuthorizationCore,
  normalizeLiveActivationAuthority,
  normalizeLiveActivationFrontendBinding,
  projectRoyaltyReleaseHistoryReceipt,
  projectLiveActivationFrontendBinding,
  royaltyReleaseHistoryReceiptSha256,
  frontendBuildCandidateAuthorityBindingFromLiveActivation,
  frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization,
  assertLiveActivationFrontendBuildSha256,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
  releaseCeremonyTransactionPlanSha256,
} from "./release-authority-stages.mjs";
import { RELEASE_CEREMONY_LOCK_PROTOCOL } from "./release-ceremony-lock.mjs";
import { freshContractDeploymentReceiptDigest } from "./cvm-launch-intent-core.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaArenaWorkerPresenceActivationProofSha256,
  phalaCombinedArenaComputeActivationVerificationSha256,
  phalaPostMeasurementActivationExecutionReceiptSha256,
  phalaPostMeasurementRuntimeCommitmentsSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  syntheticFreshContractDeploymentReceiptFixture,
} from "./fresh-contract-deployment-receipt.fixture.mjs";

const CHECKED_AT = Date.parse("2026-07-21T12:00:00.000Z");
const ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const ALPHA_SUCCESSOR = privateKeyToAccount(`0x${"12".repeat(32)}`);
const BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const BRAVO_SUCCESSOR = privateKeyToAccount(`0x${"23".repeat(32)}`);
const GUARDIAN_ALPHA = privateKeyToAccount(`0x${"44".repeat(32)}`);
const GUARDIAN_BRAVO = privateKeyToAccount(`0x${"55".repeat(32)}`);
const FORGED = privateKeyToAccount(`0x${"33".repeat(32)}`);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

function pin(pair) {
  return `sha256:${pair.repeat(32)}`;
}

function word(pair) {
  return `0x${pair.repeat(32)}`;
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function blockObservation({ blockNumber, blockHash, blockTimestamp, seed }) {
  return {
    schema: COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA,
    chain_id: 84_532,
    block_number: blockNumber,
    block_hash: blockHash,
    parent_hash: word(seed.toString(16).padStart(2, "0")),
    block_timestamp: blockTimestamp,
    state_root: word((seed + 1).toString(16).padStart(2, "0")),
    transactions_root: word((seed + 2).toString(16).padStart(2, "0")),
    receipts_root: word((seed + 3).toString(16).padStart(2, "0")),
    gas_limit: "30000000",
    gas_used: "1000000",
    base_fee_per_gas_wei: "1000000000",
  };
}

function transactionObservation(planEntry, index, block) {
  return {
    schema: CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA,
    chain_id: 84_532,
    transaction_hash: word((60 + index).toString(16).padStart(2, "0")),
    block_number: block.block_number,
    block_hash: block.block_hash,
    transaction_index: index,
    from: planEntry.signer_address,
    to: planEntry.to,
    nonce: planEntry.nonce,
    value_wei: planEntry.value_wei,
    input_sha256: planEntry.calldata_sha256,
    gas_limit: "1000000",
    transaction_type: 2,
    max_fee_per_gas_wei: "2000000000",
    max_priority_fee_per_gas_wei: "1000000000",
    access_list_sha256: pin("a1"),
  };
}

function receiptObservation(transaction, logs = [], status = 1) {
  return {
    schema: CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA,
    chain_id: 84_532,
    transaction_hash: transaction.transaction_hash,
    block_number: transaction.block_number,
    block_hash: transaction.block_hash,
    transaction_index: transaction.transaction_index,
    from: transaction.from,
    to: transaction.to,
    contract_address: address(0),
    status,
    transaction_type: transaction.transaction_type,
    cumulative_gas_used: "500000",
    gas_used: "500000",
    effective_gas_price_wei: "1000000000",
    logs_bloom: `0x${"00".repeat(256)}`,
    logs,
  };
}

function royaltyState({ phase, block, authority, pendingActivatesAt = 0 }) {
  const zeroAddress = address(0);
  const zeroWord = word("00");
  const freshOrPending = phase !== "phase_two_active";
  const pending = phase === "phase_one_pending";
  return {
    schema: ROYALTY_RELEASE_STATE_SCHEMA,
    chain_id: 84_532,
    contract_address: authority.distributor_address,
    block_number: block.block_number,
    block_hash: block.block_hash,
    block_timestamp: block.block_timestamp,
    owner: authority.owner,
    pending_owner: zeroAddress,
    paused: phase !== "phase_two_active",
    settlement_verifier: freshOrPending
      ? zeroAddress
      : authority.settlement_verifier,
    qvl_verifier: freshOrPending ? zeroAddress : authority.qvl_verifier,
    execution_policy_anchor: freshOrPending
      ? zeroAddress
      : authority.execution_policy_anchor,
    anchor_writer_release_commitment: freshOrPending
      ? zeroWord
      : authority.anchor_writer_release_commitment,
    release_policy_commitment: freshOrPending
      ? zeroWord
      : authority.release_policy_commitment,
    authority_nonce: freshOrPending ? 0 : authority.authority_nonce,
    pending_settlement_verifier: pending
      ? authority.settlement_verifier
      : zeroAddress,
    pending_qvl_verifier: pending ? authority.qvl_verifier : zeroAddress,
    pending_execution_policy_anchor: pending
      ? authority.execution_policy_anchor
      : zeroAddress,
    pending_anchor_writer_release_commitment: pending
      ? authority.anchor_writer_release_commitment
      : zeroWord,
    pending_release_policy_commitment: pending
      ? authority.release_policy_commitment
      : zeroWord,
    pending_authority_nonce: pending ? authority.authority_nonce : 0,
    pending_authority_activates_at: pending ? pendingActivatesAt : 0,
    pending_authority_revocation: false,
    settlement_verifier_ever_configured: phase === "phase_two_active",
    qvl_verifier_ever_configured: phase === "phase_two_active",
    anchor_writer_ever_configured: phase === "phase_two_active",
    computed_release_policy_commitment: authority.release_policy_commitment,
  };
}

function royaltyStateEvidence({ phase, block, authority, pendingActivatesAt = 0 }) {
  const state = royaltyState({ phase, block, authority, pendingActivatesAt });
  const blockSha = commonFinalizedBlockRpcObservationSha256(block);
  const stateSha = royaltyReleaseStateSha256(state, { authority, phase });
  return {
    phase,
    primary_rpc_id_sha256: pin("52"),
    secondary_rpc_id_sha256: pin("53"),
    primary_rpc_block: block,
    primary_rpc_block_sha256: blockSha,
    secondary_rpc_block: structuredClone(block),
    secondary_rpc_block_sha256: blockSha,
    primary_rpc_state: state,
    primary_rpc_state_sha256: stateSha,
    secondary_rpc_state: structuredClone(state),
    secondary_rpc_state_sha256: stateSha,
  };
}

function royaltyMutationEvidence({
  operation,
  authority,
  block,
  nonce,
  observationIndex,
  pendingActivatesAt = 0,
  receiptStatus = 1,
}) {
  const planned = {
    signer_address: authority.owner,
    to: authority.distributor_address,
    nonce: String(nonce),
    value_wei: "0",
    calldata_sha256: royaltyReleaseMutationCalldataSha256(operation, authority),
  };
  const transaction = transactionObservation(planned, observationIndex, block);
  const logs = [];
  if (receiptStatus === 1) {
    const event = royaltyReleaseMutationEvent(operation, authority, {
      pendingAuthorityActivatesAt: pendingActivatesAt,
    });
    logs.push({
      address: event.address,
      topics: [...event.topics],
      data: event.data,
      log_index: 0,
      removed: false,
    });
  }
  const receipt = receiptObservation(transaction, logs, receiptStatus);
  const transactionSha = ceremonyTransactionRpcObservationSha256(transaction);
  const receiptSha = ceremonyReceiptRpcObservationSha256(receipt, {
    expectedStatus: receiptStatus,
  });
  const blockSha = commonFinalizedBlockRpcObservationSha256(block);
  return {
    operation,
    primary_rpc_id_sha256: pin("52"),
    secondary_rpc_id_sha256: pin("53"),
    primary_rpc_transaction: transaction,
    primary_rpc_transaction_sha256: transactionSha,
    secondary_rpc_transaction: structuredClone(transaction),
    secondary_rpc_transaction_sha256: transactionSha,
    primary_rpc_receipt: receipt,
    primary_rpc_receipt_sha256: receiptSha,
    secondary_rpc_receipt: structuredClone(receipt),
    secondary_rpc_receipt_sha256: receiptSha,
    primary_rpc_block: block,
    primary_rpc_block_sha256: blockSha,
    secondary_rpc_block: structuredClone(block),
    secondary_rpc_block_sha256: blockSha,
  };
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

function reviewerFixture() {
  const accounts = [
    ALPHA, ALPHA_SUCCESSOR, BRAVO, BRAVO_SUCCESSOR,
  ].sort((left, right) =>
    left.address.toLowerCase().localeCompare(right.address.toLowerCase()));
  const reviewers = [ALPHA, BRAVO].map((account) => ({
    address: account.address.toLowerCase(),
    controller_id: account.address.toLowerCase() === ALPHA.address.toLowerCase()
      ? "reviewer-alpha"
      : "reviewer-bravo",
  })).sort((left, right) => left.address.localeCompare(right.address));
  const successorReviewers = [ALPHA_SUCCESSOR, BRAVO_SUCCESSOR]
    .map((account) => ({
      address: account.address.toLowerCase(),
      controller_id: account.address.toLowerCase()
        === ALPHA_SUCCESSOR.address.toLowerCase()
        ? "reviewer-alpha"
        : "reviewer-bravo",
    })).sort((left, right) => left.address.localeCompare(right.address));
  const reviewerControllers = [
    {
      controller_id: "reviewer-alpha",
      preauthorized_addresses: [ALPHA, ALPHA_SUCCESSOR]
        .map((account) => account.address.toLowerCase()).sort(),
    },
    {
      controller_id: "reviewer-bravo",
      preauthorized_addresses: [BRAVO, BRAVO_SUCCESSOR]
        .map((account) => account.address.toLowerCase()).sort(),
    },
  ];
  const guardianAccounts = [GUARDIAN_ALPHA, GUARDIAN_BRAVO];
  const statusGuardians = guardianAccounts.map((account, index) => ({
    address: account.address.toLowerCase(),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const guardianHashes = statusGuardians
    .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
  const genesis = {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: reviewerControllers,
    reviewer_controller_set_sha256: reviewerControllerSetSha256(reviewerControllers),
    status_guardians: statusGuardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(statusGuardians),
  };
  return {
    accounts, genesis, guardianAccounts, reviewers, successorReviewers,
  };
}

function validIntent(genesis, currentStatus, genesisAcceptance) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = RELEASE_SHA;
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      genesisAcceptance,
      { reviewerGenesis: genesis },
    );
  intent.release.reviewerAuthorityCurrentStatusEpoch = currentStatus.epoch;
  intent.release.reviewerAuthorityCurrentStatusSha256 =
    releaseReviewerAuthorityCurrentStatusSha256(
      currentStatus,
      { reviewerGenesis: genesis },
    );
  intent.deploymentControl.controllerId = "deployment-operator-01";
  intent.deploymentControl.operatorAddress = address(1);
  intent.staticContractInputs.diligenceRoom.governanceController = address(19);
  intent.staticContractInputs.computeCreditVault.developer = address(20);
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment = word("03");
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "5000000000000000000",
    tinkerMaxSpendWei: "2000000000000000000",
  };
  intent.numericPolicy.metering = {
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    rpcTimeoutSeconds: "8",
  };
  for (const name of Object.keys(intent.numericPolicy.qvl)) {
    intent.numericPolicy.qvl[name] = validQvlPolicy();
  }
  return intent;
}

function reviewMetadata(genesis, genesisAcceptance, {
  signedAt = "2026-07-21T12:00:00.000Z",
  expiresAt = "2026-07-21T12:10:00.000Z",
} = {}) {
  const status = genesisAcceptance.reviewer_authority_current_status;
  return {
    reviewer_authority_genesis_sha256: releaseReviewerAuthorityGenesisSha256(genesis),
    reviewer_authority_genesis_acceptance_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSha256(
        genesisAcceptance,
        { reviewerGenesis: genesis },
      ),
    reviewer_authority_current_status_epoch: status.epoch,
    reviewer_authority_current_status_sha256:
      releaseReviewerAuthorityCurrentStatusSha256(
        status,
        { reviewerGenesis: genesis },
      ),
    approved_reviewer_hashes: status.approved_reviewer_hashes,
    reviewer_root_hash: status.reviewer_root_hash,
    reviewer_set_sha256: status.reviewer_set_sha256,
    signed_at: signedAt,
    expires_at: expiresAt,
  };
}

function activationExecutionReceiptFixture({
  runtimeAuthority,
  ceremonyAuthorizationSha256,
}) {
  const plan = runtimeAuthority.post_measurement_activation_plan;
  const arenaWorkerPresence = {
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: pin("87"),
    challenge_id: "dnaseq-variant-qc-safe-ir",
    challenge_version: "1.0.0",
    response_sha256: pin("88"),
    release_binding_sha256: pin("89"),
    heartbeat_observed_at: Date.parse("2026-07-21T12:00:07Z") / 1_000,
    verified_at: Date.parse("2026-07-21T12:00:07Z") / 1_000,
  };
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const computeRecipientActivationSha256 = pin("80");
  return normalizePhalaPostMeasurementActivationExecutionReceipt({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: 84_532,
    release_sha: plan.release_sha,
    batch_id: plan.batch_id,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    cvm_launch_intent_sha256: plan.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      plan.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    seven_cvm_verified_evidence_set_sha256:
      plan.seven_cvm_verified_evidence_set_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    pre_ceremony_runtime_authority_sha256:
      preCeremonyRuntimeAuthoritySha256(runtimeAuthority),
    post_measurement_activation_plan_sha256:
      runtimeAuthority.post_measurement_activation_plan_sha256,
    ceremony_authorization_sha256: ceremonyAuthorizationSha256,
    target: plan.target,
    profile_activation: plan.profile_activation,
    runtime_commitments_sha256:
      phalaPostMeasurementRuntimeCommitmentsSha256(plan.runtime_commitments),
    runtime_commitment_key_names_sha256:
      plan.runtime_commitment_key_names_sha256,
    allowed_environment_key_names_sha256:
      plan.allowed_environment_key_names_sha256,
    allowed_environment_key_count: plan.allowed_environment_key_count,
    injected_environment_key_names_sha256:
      plan.injected_environment_key_names_sha256,
    injected_environment_key_count: plan.injected_environment_key_names.length,
    private_environment_assembly_receipt_sha256: pin("70"),
    adapter_identity_sha256: pin("71"),
    activation_journal_state_sha256: pin("72"),
    activation_journal_sha256: pin("73"),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch: {
      sdk_action: "updateCvmEnvs",
      call_sequence: 4,
      request_semantics_sha256: pin("74"),
      observation_sha256: pin("75"),
      response_sha256: pin("76"),
      body_field_names: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
      attempt_recorded_at: "2026-07-21T12:00:01Z",
      observed_at: "2026-07-21T12:00:02Z",
      finalized_readiness: {
        readiness_sha256: pin("77"),
        finalized_block_number: 30_000_000,
        finalized_block_hash: word("70"),
      },
    },
    restart: {
      sdk_action: "restartCvm",
      call_sequence: 5,
      request_semantics_sha256: pin("78"),
      observation_sha256: pin("79"),
      response_sha256: pin("7a"),
      force: false,
      attempt_recorded_at: "2026-07-21T12:00:03Z",
      observed_at: "2026-07-21T12:00:04Z",
      finalized_readiness: {
        readiness_sha256: pin("7b"),
        finalized_block_number: 30_000_001,
        finalized_block_hash: word("71"),
      },
    },
    post_restart_evidence: {
      get_cvm_info_call_sequence: 6,
      get_cvm_info_observation_sha256: pin("7c"),
      get_cvm_info_response_sha256: pin("7d"),
      get_cvm_info_observed_at: "2026-07-21T12:00:05Z",
      get_cvm_attestation_call_sequence: 7,
      get_cvm_attestation_observation_sha256: pin("7e"),
      get_cvm_attestation_response_sha256: pin("7f"),
      get_cvm_attestation_observed_at: "2026-07-21T12:00:06Z",
      cvm_online: true,
      attestation_error_absent: true,
      tcb_info_present: true,
      app_certificate_quote_present: true,
      pre_injection_attestation_sufficient: false,
    },
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: {
      activation_verification_sha256: computeRecipientActivationSha256,
      source_activation_sha256: pin("81"),
      raw_transcript_sha256: pin("82"),
      qvl_verdict_verifier_signature_sha256: pin("83"),
      tdx_quote_sha256: pin("84"),
      challenge_id: word("72"),
      report_data: word("73"),
      recipient_key_id: pin("85"),
      recipient_release_commitment: pin("86"),
      authenticated_at: Date.parse("2026-07-21T12:00:07Z") / 1_000,
      verified_at: Date.parse("2026-07-21T12:00:08Z") / 1_000,
      verdict_activation_evidence_lease_expires_at:
        Date.parse("2026-07-21T12:01:00Z") / 1_000,
      recipient_evidence_lease_expires_at:
        Date.parse("2026-07-21T12:01:00Z") / 1_000,
      expires_at: Date.parse("2026-07-21T12:01:00Z") / 1_000,
      post_restart_source_activation: true,
    },
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      phalaCombinedArenaComputeActivationVerificationSha256({
        profileActivation: plan.profile_activation,
        arenaWorkerPresenceSha256,
        computeRecipientActivationSha256,
      }),
    initial_activation_evidence_lease_expires_at:
      plan.activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      Date.parse("2026-07-21T12:01:00Z") / 1_000,
    terminal_evidence_lease_expires_at:
      Date.parse("2026-07-21T12:01:00Z") / 1_000,
    completed_at: "2026-07-21T12:00:08Z",
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  });
}

async function signCurrentStatus(genesis, reviewers, guardianAccounts) {
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 1,
    not_before: "2026-07-21T11:55:00Z",
    expires_at: "2026-07-21T12:10:00Z",
    previous_status_sha256: ZERO_SHA256,
    active_reviewers: reviewers,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, { reviewerGenesis: genesis });
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    { reviewerGenesis: genesis },
  );
  const byAddress = new Map(
    guardianAccounts.map((account) => [account.address.toLowerCase(), account]),
  );
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
        payload,
        { reviewerGenesis: genesis },
      ),
    guardian_signatures: await Promise.all(genesis.status_guardians.map(async (guardian) => ({
      ...guardian,
      signature: (await byAddress.get(guardian.address)
        .signMessage({ message })).toLowerCase(),
    }))),
  };
}

async function signGenesisAcceptance(genesis, currentStatus, reviewers, accounts) {
  const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    genesis,
    { reviewerCurrentStatus: currentStatus },
  );
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    { reviewerGenesis: genesis },
  );
  const byAddress = new Map(accounts.map((account) => [account.address.toLowerCase(), account]));
  const acceptances = [];
  for (const reviewer of reviewers) {
    acceptances.push({
      ...reviewer,
      signature: (await byAddress.get(reviewer.address).signMessage({ message })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        { reviewerGenesis: genesis },
      ),
    acceptances,
  };
}

async function signReview(payload, reviewers, accounts) {
  const message = releaseAuthorityReviewSigningMessage(payload);
  const byAddress = new Map(accounts.map((account) => [account.address.toLowerCase(), account]));
  const signatures = [];
  for (const reviewer of reviewers) {
    signatures.push({
      ...reviewer,
      signature: (await byAddress.get(reviewer.address).signMessage({ message })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
    signing_payload_sha256: releaseAuthorityReviewSigningPayloadSha256(payload),
    signatures,
  };
}

export async function syntheticReleaseAuthorityStagesFixture({
  royaltyExecutionMode = "legacy_v1",
} = {}) {
  if (!["legacy_v1", "activate_and_unpause", "recover_reverted_unpause"]
    .includes(royaltyExecutionMode)) {
    throw new TypeError("synthetic royalty execution mode is unsupported");
  }
  const reviewers = reviewerFixture();
  const currentStatus = await signCurrentStatus(
    reviewers.genesis,
    reviewers.reviewers,
    reviewers.guardianAccounts,
  );
  const genesisAcceptance = await signGenesisAcceptance(
    reviewers.genesis,
    currentStatus,
    reviewers.reviewers,
    reviewers.accounts,
  );
  const intent = validIntent(reviewers.genesis, currentStatus, genesisAcceptance);
  const deploymentIntentSha = canonicalArtifactSha256(intent);
  const reviewerGenesisAcceptanceSha =
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      genesisAcceptance,
      { reviewerGenesis: reviewers.genesis },
    );
  const freshReceiptFixture = syntheticFreshContractDeploymentReceiptFixture({
    releaseSha: RELEASE_SHA,
    deploymentIntentSha256: deploymentIntentSha,
    reviewerAuthorityGenesisAcceptanceSha256: reviewerGenesisAcceptanceSha,
  });
  const freshContractDeploymentReceiptSha =
    `sha256:${freshContractDeploymentReceiptDigest(
      freshReceiptFixture.receipt,
      freshReceiptFixture.authorityPins,
    )}`;
  const runtimeAuthority = syntheticPreCeremonyRuntimeAuthorityFixture({
    releaseSha: RELEASE_SHA,
    deploymentIntentSha256: deploymentIntentSha,
    cvmLaunchIntentSha256: pin("aa"),
  });
  const signer = address(1);
  const planTransactions = RELEASE_CEREMONY_MUTATION_WRITERS.map((writerId, index) => ({
    sequence: index,
    writer_id: writerId,
    signer_address: signer,
    nonce: String(100 + index),
    to: address(100 + index),
    value_wei: "0",
    calldata_sha256: `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
  }));
  const plan = {
    schema: RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
    transactions: planTransactions,
    plan_sha256: releaseCeremonyTransactionPlanSha256({
      releaseSha: RELEASE_SHA,
      chainId: 84_532,
      transactions: planTransactions,
    }),
  };
  const manifestSha = pin("31");
  const stageOneBody = {
    schema: CEREMONY_AUTHORIZATION_CORE_SCHEMA,
    status: CEREMONY_AUTHORIZATION_CORE_STATUS,
    truth_status: "pre_ceremony_authorization_not_finalized_ceremony_or_live_activation",
    release_sha: RELEASE_SHA,
    network: { chain_id: 84_532, name: "base-sepolia" },
    deployment_authority: {
      deployment_intent_sha256: deploymentIntentSha,
      reviewer_authority_genesis_sha256: releaseReviewerAuthorityGenesisSha256(reviewers.genesis),
      reviewer_authority_genesis_acceptance_sha256:
        releaseReviewerAuthorityGenesisAcceptanceSha256(
          genesisAcceptance,
          { reviewerGenesis: reviewers.genesis },
        ),
      fresh_contract_deployment_receipt_sha256: freshContractDeploymentReceiptSha,
      immutable_deployment_manifest: {
        path: "/private/tmp/dnai-release/deployment-manifest.json",
        sha256: manifestSha,
        bytes: 12_345,
        mode: 0o444,
        schema_version: 2,
      },
      toolchain: structuredClone(DEPLOYMENT_TOOLCHAIN_AUTHORITY),
    },
    cvm_launch_intent_sha256: pin("aa"),
    cvm_bootstrap_authorization_receipt_sha256: pin("33"),
    pre_ceremony_runtime_authority_sha256:
      preCeremonyRuntimeAuthoritySha256(runtimeAuthority),
    ceremony_ledger_initialization: {
      initialization_receipt_path: "/private/tmp/dnai-release/ceremony/initialization.json",
      initialization_receipt_sha256: pin("34"),
      ledger_path: "/private/tmp/dnai-release/ceremony/ledger.json",
      ledger_initial_sha256: manifestSha,
      ledger_initial_bytes: 12_345,
      ledger_mode: 0o600,
      source_manifest_sha256: manifestSha,
      lock_protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    },
    ceremony_transaction_plan: plan,
    lock_protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
  };
  const stageOnePayload = ceremonyAuthorizationReviewSigningPayload(
    stageOneBody,
    reviewMetadata(reviewers.genesis, genesisAcceptance),
  );
  const stageOne = {
    ...stageOneBody,
    review: await signReview(stageOnePayload, reviewers.reviewers, reviewers.accounts),
  };
  const stageOneOptions = {
    deploymentIntent: intent,
    freshContractDeploymentReceipt: freshReceiptFixture.receipt,
    reviewerGenesis: reviewers.genesis,
    reviewerGenesisAcceptance: genesisAcceptance,
    preCeremonyRuntimeAuthority: runtimeAuthority,
    computeWorkloadActivationObservationSha256: pin("65"),
    checkedAtMs: CHECKED_AT,
  };
  const stageOneSha = ceremonyAuthorizationCoreSha256(stageOne, stageOneOptions);

  const contracts = RELEASE_CONTRACT_STATE_KEYS.map((key, index) => ({
    contract_key: key,
    address: address(200 + index),
    runtime_code_hash: word((40 + index).toString(16).padStart(2, "0")),
    control_role: key === "diligence_room"
      ? "developer"
      : "owner",
    control_address: address(1),
    configuration_sha256: `sha256:${(80 + index).toString(16).padStart(64, "0")}`,
  }));
  const challengeGenesisSha = pin("41");
  const commonBlock = blockObservation({
    blockNumber: 11_000,
    blockHash: word("79"),
    blockTimestamp: Math.floor(CHECKED_AT / 1_000) + 11,
    seed: 180,
  });
  const commonStatePin = pin("51");
  const commonFinalizedState = {
    independent_rpc_count: 2,
    primary_rpc_id_sha256: pin("52"),
    secondary_rpc_id_sha256: pin("53"),
    primary_rpc_block: commonBlock,
    primary_rpc_block_sha256: commonFinalizedBlockRpcObservationSha256(commonBlock),
    secondary_rpc_block: structuredClone(commonBlock),
    secondary_rpc_block_sha256: commonFinalizedBlockRpcObservationSha256(commonBlock),
    primary_state_sha256: commonStatePin,
    secondary_state_sha256: commonStatePin,
    canonical_state_sha256: commonStatePin,
    latest_state_recheck_sha256: pin("54"),
  };
  const anchorRead = {
    schema: EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA,
    chain_id: 84_532,
    contract_address: contracts.find((entry) =>
      entry.contract_key === "execution_policy_anchor").address,
    block_number: commonBlock.block_number,
    block_hash: commonBlock.block_hash,
    deployment_intent_sha256_bytes32: `0x${deploymentIntentSha.slice(7)}`,
    reviewer_authority_genesis_acceptance_sha256_bytes32:
      `0x${reviewerGenesisAcceptanceSha.slice(7)}`,
  };
  const anchorReadSha = executionPolicyAnchorRpcReadSha256(anchorRead);
  const executionPolicyAnchorCommitment = {
    primary_rpc_read: anchorRead,
    primary_rpc_read_sha256: anchorReadSha,
    secondary_rpc_read: structuredClone(anchorRead),
    secondary_rpc_read_sha256: anchorReadSha,
  };
  const royaltyDistributor = contracts.find((entry) =>
    entry.contract_key === "royalty_distributor");
  const executionPolicyAnchor = contracts.find((entry) =>
    entry.contract_key === "execution_policy_anchor");
  const royaltyAuthorityBase = {
    schema: ROYALTY_RELEASE_AUTHORITY_SCHEMA,
    chain_id: 84_532,
    distributor_address: royaltyDistributor.address,
    owner: address(1),
    settlement_verifier: address(410),
    qvl_verifier: address(411),
    execution_policy_anchor: executionPolicyAnchor.address,
    anchor_writer: address(412),
    anchor_writer_release_commitment: word("e2"),
    authority_nonce: 1,
    authority_timelock_seconds: ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  };
  const royaltyAuthority = {
    ...royaltyAuthorityBase,
    release_policy_commitment: royaltyReleasePolicyCommitment({
      chainId: royaltyAuthorityBase.chain_id,
      distributorAddress: royaltyAuthorityBase.distributor_address,
      authorityNonce: royaltyAuthorityBase.authority_nonce,
      settlementVerifier: royaltyAuthorityBase.settlement_verifier,
      qvlVerifier: royaltyAuthorityBase.qvl_verifier,
      executionPolicyAnchor: royaltyAuthorityBase.execution_policy_anchor,
      anchorWriterReleaseCommitment:
        royaltyAuthorityBase.anchor_writer_release_commitment,
    }),
  };
  const proposalTimestamp = Math.floor(CHECKED_AT / 1_000)
    - ROYALTY_AUTHORITY_TIMELOCK_SECONDS + 8;
  const pendingActivatesAt = proposalTimestamp
    + ROYALTY_AUTHORITY_TIMELOCK_SECONDS;
  const freshRoyaltyBlock = blockObservation({
    blockNumber: 9_000,
    blockHash: word("75"),
    blockTimestamp: proposalTimestamp - 1,
    seed: 160,
  });
  const proposalBlock = blockObservation({
    blockNumber: 9_001,
    blockHash: word("76"),
    blockTimestamp: proposalTimestamp,
    seed: 164,
  });
  const activationBlock = blockObservation({
    blockNumber: 10_006,
    blockHash: word("77"),
    blockTimestamp: pendingActivatesAt,
    seed: 168,
  });
  const unpauseBlock = blockObservation({
    blockNumber: 10_007,
    blockHash: word("78"),
    blockTimestamp: pendingActivatesAt + 1,
    seed: 172,
  });
  const recoveryUnpauseBlock = blockObservation({
    blockNumber: 10_008,
    blockHash: word("7a"),
    blockTimestamp: pendingActivatesAt + 2,
    seed: 176,
  });
  const recovery = royaltyExecutionMode === "recover_reverted_unpause";
  const phaseTwo = {
    activation_transaction: royaltyMutationEvidence({
      operation: "activate_authority_proposal",
      authority: royaltyAuthority,
      block: activationBlock,
      nonce: 21,
      observationIndex: 21,
    }),
    unpause_transaction: royaltyMutationEvidence({
      operation: "unpause",
      authority: royaltyAuthority,
      block: recovery ? recoveryUnpauseBlock : unpauseBlock,
      nonce: recovery ? 23 : 22,
      observationIndex: recovery ? 23 : 22,
    }),
    poststate: royaltyStateEvidence({
      phase: "phase_two_active",
      block: commonBlock,
      authority: royaltyAuthority,
    }),
  };
  if (recovery) {
    phaseTwo.reverted_unpause_transaction = royaltyMutationEvidence({
      operation: "unpause",
      authority: royaltyAuthority,
      block: unpauseBlock,
      nonce: 22,
      observationIndex: 22,
      receiptStatus: 0,
    });
  }
  const royaltyReleaseHistory = {
    schema: royaltyExecutionMode === "legacy_v1"
      ? ROYALTY_RELEASE_HISTORY_SCHEMA
      : ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
    authority: royaltyAuthority,
    fresh_state: royaltyStateEvidence({
      phase: "fresh",
      block: freshRoyaltyBlock,
      authority: royaltyAuthority,
    }),
    phase_one: {
      proposal_transaction: royaltyMutationEvidence({
        operation: "propose_authority_binding",
        authority: royaltyAuthority,
        block: proposalBlock,
        nonce: 20,
        observationIndex: 20,
        pendingActivatesAt,
      }),
      poststate: royaltyStateEvidence({
        phase: "phase_one_pending",
        block: proposalBlock,
        authority: royaltyAuthority,
        pendingActivatesAt,
      }),
    },
    phase_two: phaseTwo,
  };
  if (royaltyExecutionMode !== "legacy_v1") {
    royaltyReleaseHistory.execution_mode = royaltyExecutionMode;
  }
  const royaltyReleaseHistoryDigest = normalizedRoyaltyReleaseHistorySha256(
    royaltyReleaseHistory,
    { contracts, commonFinalizedState },
  );
  const royaltyReleaseHistoryReceiptDigest =
    royaltyReleaseHistoryReceiptSha256(projectRoyaltyReleaseHistoryReceipt({
      contracts,
      commonFinalizedState,
      royaltyReleaseHistory,
    }));
  const contractState = {
    contracts,
    challenge_genesis_sha256: challengeGenesisSha,
    deployment_intent_sha256: deploymentIntentSha,
    reviewer_authority_genesis_acceptance_sha256: reviewerGenesisAcceptanceSha,
    execution_policy_anchor_commitment: executionPolicyAnchorCommitment,
    royalty_release_history: royaltyReleaseHistory,
    royalty_release_history_sha256: royaltyReleaseHistoryDigest,
    royalty_release_history_receipt_sha256:
      royaltyReleaseHistoryReceiptDigest,
    configuration_set_sha256: liveContractConfigurationSetSha256({
      contracts,
      challengeGenesisSha256: challengeGenesisSha,
      deploymentIntentSha256: deploymentIntentSha,
      reviewerGenesisAcceptanceSha256: reviewerGenesisAcceptanceSha,
      executionPolicyAnchorCommitment,
      royaltyReleaseHistory,
      commonFinalizedState,
    }),
  };
  const activationPlan = runtimeAuthority.post_measurement_activation_plan;
  const activationExecutionReceipt = activationExecutionReceiptFixture({
    runtimeAuthority,
    ceremonyAuthorizationSha256: stageOneSha,
  });
  const finalCvms = [
    "main_runtime_cvm", "diligence_qvl_cvm", "arena_qvl_cvm",
    "anchor_writer_qvl_cvm", "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm", "independent_metering_cvm",
  ].map((key, index) => ({
    cvm_key: key,
    app_id: key === "main_runtime_cvm"
      ? activationPlan.target.app_id
      : `app-${String(index).padStart(8, "0")}`,
    cvm_id: key === "main_runtime_cvm"
      ? activationPlan.target.cvm_id
      : `cvm-${String(index).padStart(8, "0")}`,
    compose_hash_sha256: key === "main_runtime_cvm"
      ? `sha256:${activationPlan.target.compose_hash}`
      : pin((120 + index).toString(16).padStart(2, "0")),
    tee_identity: address(300 + index),
    attestation_evidence_sha256: key === "main_runtime_cvm"
      ? activationExecutionReceipt.post_restart_evidence
        .get_cvm_attestation_observation_sha256
      : pin((130 + index).toString(16).padStart(2, "0")),
  }));
  const stageTwoBody = {
    schema: LIVE_ACTIVATION_AUTHORITY_SCHEMA,
    status: LIVE_ACTIVATION_AUTHORITY_STATUS,
    truth_status: "separately_signed_post_ceremony_live_activation_authority",
    release_sha: RELEASE_SHA,
    network: { chain_id: 84_532, name: "base-sepolia" },
    ceremony_authorization_sha256: stageOneSha,
    ceremony_finalization: {
      immutable_deployment_manifest_sha256: manifestSha,
      initialization_receipt_sha256: pin("34"),
      ledger_path: "/private/tmp/dnai-release/ceremony/ledger.json",
      frozen_final_ledger_sha256: pin("35"),
      frozen_final_ledger_bytes: 45_678,
      frozen_final_ledger_mode: 0o444,
      finalization_receipt_sha256: pin("36"),
      revision_chain_sha256: pin("37"),
      revision_count: 6,
      lock_protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    },
    ceremony_transactions: planTransactions.map((entry, index) => {
      const block = blockObservation({
        blockNumber: 10_000 + index,
        blockHash: word((70 + index).toString(16).padStart(2, "0")),
        blockTimestamp: Math.floor(CHECKED_AT / 1_000),
        seed: 140 + index * 4,
      });
      const transaction = transactionObservation(entry, index, block);
      const receipt = receiptObservation(transaction);
      const transactionSha = ceremonyTransactionRpcObservationSha256(transaction);
      const receiptSha = ceremonyReceiptRpcObservationSha256(receipt);
      const blockSha = commonFinalizedBlockRpcObservationSha256(block);
      return {
        sequence: index,
        writer_id: entry.writer_id,
        primary_rpc_id_sha256: pin("52"),
        secondary_rpc_id_sha256: pin("53"),
        primary_rpc_transaction: transaction,
        primary_rpc_transaction_sha256: transactionSha,
        secondary_rpc_transaction: structuredClone(transaction),
        secondary_rpc_transaction_sha256: transactionSha,
        primary_rpc_receipt: receipt,
        primary_rpc_receipt_sha256: receiptSha,
        secondary_rpc_receipt: structuredClone(receipt),
        secondary_rpc_receipt_sha256: receiptSha,
        primary_rpc_block: block,
        primary_rpc_block_sha256: blockSha,
        secondary_rpc_block: structuredClone(block),
        secondary_rpc_block_sha256: blockSha,
      };
    }),
    common_finalized_state: commonFinalizedState,
    contract_state: contractState,
    post_ceremony_evidence: {
      final_cvms: finalCvms,
      cvm_measurements_sha256: pin("61"),
      tdx_attestation_bundle_sha256: pin("62"),
      qvl_policy_bundle_sha256: pin("63"),
      post_measurement_activation_execution_receipt:
        activationExecutionReceipt,
      post_measurement_activation_execution_receipt_sha256:
        phalaPostMeasurementActivationExecutionReceiptSha256(
          activationExecutionReceipt,
        ),
      compute_workload_activation_observation_sha256: pin("65"),
      compute_workload_browser_binding: {
        qvl_verifier: address(401),
        qvl_release_policy_hash: word("66"),
        compose_hash: word("67"),
        app_id: "68".repeat(20),
        os_image_hash: "69".repeat(32),
        activation_signer_address: address(402),
        cvm_id: activationPlan.target.cvm_id,
        deployment_intent_sha256: activationPlan.deployment_intent_sha256,
        release_authority_sha256:
          activationPlan.release_verification_authority_sha256,
        ceremony_nonce:
          activationPlan.release_verification_authority.ceremony_nonce,
        measurement_policy_set_sha256:
          activationPlan.release_verification_authority
            .qvl_measurement_policy_set_sha256,
        measurement_policy_sha256:
          activationPlan.runtime_commitments
            .TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
        main_runtime_evidence_sha256:
          activationPlan.runtime_commitments
            .TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256,
        chain_id: 84_532,
        compute_vault_address: address(403),
        compute_vault_runtime_code_hash: word("6a"),
        fresh_contract_deployment_receipt_sha256: word("6b"),
        max_verdict_age_seconds: 120,
        revoked_quote_hashes: [],
      },
      frontend_release_env_sha256: pin("6c"),
      frontend_build_candidate_receipt_sha256: pin("6d"),
      frontend_build_sha256: pin("64"),
    },
  };
  const stageTwoOptions = {
    ...stageOneOptions,
    ceremonyAuthorization: stageOne,
    stageBReviewerStatusHistory: [],
    stageCReviewerStatusHistory: [],
  };
  const stageTwoPayload = liveActivationReviewSigningPayload(
    stageTwoBody,
    reviewMetadata(reviewers.genesis, genesisAcceptance, {
      signedAt: "2026-07-21T12:00:10.000Z",
      expiresAt: "2026-07-21T12:10:00.000Z",
    }),
    stageTwoOptions,
  );
  const stageTwo = {
    ...stageTwoBody,
    review: await signReview(stageTwoPayload, reviewers.reviewers, reviewers.accounts),
  };
  return {
    ...reviewers,
    currentStatus,
    genesisAcceptance,
    intent,
    runtimeAuthority,
    stageOne,
    stageOneOptions,
    stageTwo,
    stageTwoOptions,
  };
}
