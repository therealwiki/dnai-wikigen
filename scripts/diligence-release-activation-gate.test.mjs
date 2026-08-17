import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS,
  diligenceOperatorTransactionsSha256,
  inspectCompletedDiligenceReleaseCeremony,
} from "./diligence-release-activation-gate.mjs";

const releaseSha = "a".repeat(40);
const address = (value) => `0x${value.toString(16).padStart(40, "0")}`;
const word = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const sha256 = (value) =>
  `sha256:${value.toString(16).padStart(64, "0")}`;
const zeroAddress = address(0);
const zeroWord = word(0);
const operator = address(1);
const controller = address(2);
const roomAddress = address(3);
const teeIdentity = address(4);
const resultVerifier = address(5);
const attestationVerifier = address(6);
const runtimeCodeHash = word(10);
const composeHash = word(11);
const evaluatorPolicyCommitments = [word(12), word(13), word(14)];
const evaluatorPolicySetRoot = word(15);
const attestationReleasePolicyHash = word(16);
const deploymentIntentSha256 = sha256(17);
const finalAuthoritySha256 = sha256(18);
const deploymentTx = word(19);

const expected = Object.freeze({
  chainId: 84_532,
  releaseSha,
  deploymentIntentSha256,
  finalAuthoritySha256,
  deploymentOperator: operator,
  governanceController: controller,
  diligenceRoomAddress: roomAddress,
  runtimeCodeHash,
  teeIdentity,
  composeHash,
  resultVerifier,
  evaluatorPolicyCommitments,
  evaluatorPolicySetRoot,
  attestationVerifier,
  attestationReleasePolicyHash,
});

const phaseFunctions = Object.freeze([
  [
    "proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
    "proposeResultVerifier(address)",
    "proposeAttestationBinding(address,bytes32)",
  ],
  [
    "activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
    "activateResultVerifier()",
    "freezeResultVerifier()",
    "activateAttestationBinding()",
    "freezeAttestationBinding()",
    "proposeTeeIdentity(address,bytes32)",
  ],
  [
    "activateTeeIdentity(address)",
    "freezeComposeAndEvaluatorPolicySets()",
    "freezeTeeIdentityAdditions()",
    "proposeDeveloper(address)",
  ],
  [],
]);

const phaseStatus = Object.freeze([
  [
    "deployed_diligence_compose_and_qvl_pending_timelock",
    "fail_closed_pending_compose_and_attestation_timelocks",
  ],
  [
    "deployed_diligence_tee_identity_pending_timelock",
    "fail_closed_pending_tee_identity_timelock",
  ],
  [
    "deployed_exact_diligence_release_policy_frozen_pending_governance_timelock",
    "fail_closed_exact_policy_pending_governance_acceptance",
  ],
  [
    "deployed_exact_diligence_release_policy_frozen_active",
    "exact_timelocked_diligence_release_policy_frozen_active",
  ],
]);

function recordedAt(timestamp) {
  return new Date(timestamp * 1_000).toISOString().replace(".000Z", "Z");
}

function reviewReceipt(phase) {
  return {
    phase,
    valid: true,
    schema: "dnai.authority-review-envelope-validation-receipt.v1",
    status: "valid",
    truthStatus:
      "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx",
    subjectKind: "final_release_authority",
    subjectSha256: finalAuthoritySha256,
    reviewEnvelopeSha256: sha256(100 + phase),
    reviewEvidenceSha256: sha256(200 + phase),
    checkpoint: "after_measured_cvms_before_any_release_ceremony_transaction",
    actionScopeCount: 8,
    reviewerDeclarationCount: 2,
    subjectSemanticValidation: "final_release_authority_validated",
  };
}

function commonPoststate() {
  return {
    developer: operator,
    pendingDeveloper: zeroAddress,
    pendingDeveloperActivatesAt: 0,
    developerTransferDelaySeconds: 172_800,
    approvedComposeCount: 1,
    approvedTeeIdentityCount: 1,
    pendingComposeCount: 0,
    pendingTeeIdentityCount: 0,
    pendingComposeActivatesAt: 0,
    pendingTeeIdentityActivatesAt: 0,
    activeTeeIdentityComposeHash: composeHash,
    pendingTeeIdentityComposeHash: zeroWord,
    resultVerifier,
    pendingResultVerifier: zeroAddress,
    pendingResultVerifierActivatesAt: 0,
    resultVerifierFrozen: true,
    evaluatorPolicyCommitments: [...evaluatorPolicyCommitments],
    evaluatorPolicySetRoot,
    approvedEvaluatorPolicyCount: 3,
    pendingEvaluatorPolicyCount: 0,
    evaluatorPolicySetFrozen: true,
    pendingEvaluatorPolicy1ActivatesAt: 0,
    pendingEvaluatorPolicy2ActivatesAt: 0,
    pendingEvaluatorPolicy3ActivatesAt: 0,
    attestationVerifier,
    attestationReleasePolicyHash,
    pendingAttestationVerifier: zeroAddress,
    pendingAttestationReleasePolicyHash: zeroWord,
    pendingAttestationBindingActivatesAt: 0,
    attestationBindingFrozen: true,
    composeAdditionsFrozen: true,
    teeIdentityAdditionsFrozen: true,
  };
}

function phasePoststate(phase, blockTimestamp) {
  if (phase === 1) {
    return {
      ...commonPoststate(),
      approvedComposeCount: 0,
      approvedTeeIdentityCount: 0,
      pendingComposeCount: 1,
      pendingTeeIdentityCount: 0,
      pendingComposeActivatesAt: blockTimestamp + 100,
      activeTeeIdentityComposeHash: zeroWord,
      resultVerifier: zeroAddress,
      pendingResultVerifier: resultVerifier,
      pendingResultVerifierActivatesAt: blockTimestamp + 100,
      resultVerifierFrozen: false,
      evaluatorPolicySetRoot: zeroWord,
      approvedEvaluatorPolicyCount: 0,
      pendingEvaluatorPolicyCount: 3,
      evaluatorPolicySetFrozen: false,
      pendingEvaluatorPolicy1ActivatesAt: blockTimestamp + 100,
      pendingEvaluatorPolicy2ActivatesAt: blockTimestamp + 100,
      pendingEvaluatorPolicy3ActivatesAt: blockTimestamp + 100,
      attestationVerifier: zeroAddress,
      attestationReleasePolicyHash: zeroWord,
      pendingAttestationVerifier: attestationVerifier,
      pendingAttestationReleasePolicyHash: attestationReleasePolicyHash,
      pendingAttestationBindingActivatesAt: blockTimestamp + 100,
      attestationBindingFrozen: false,
      composeAdditionsFrozen: false,
      teeIdentityAdditionsFrozen: false,
    };
  }
  if (phase === 2) {
    return {
      ...commonPoststate(),
      approvedTeeIdentityCount: 0,
      pendingTeeIdentityCount: 1,
      pendingTeeIdentityActivatesAt: blockTimestamp + 100,
      activeTeeIdentityComposeHash: zeroWord,
      pendingTeeIdentityComposeHash: composeHash,
      evaluatorPolicySetRoot: zeroWord,
      evaluatorPolicySetFrozen: false,
      composeAdditionsFrozen: false,
      teeIdentityAdditionsFrozen: false,
    };
  }
  if (phase === 3) {
    return {
      ...commonPoststate(),
      pendingDeveloper: controller,
      pendingDeveloperActivatesAt: blockTimestamp + 172_800,
    };
  }
  return {
    ...commonPoststate(),
    developer: controller,
  };
}

function operatorTransactions(phase, blockNumber, seed) {
  return phaseFunctions[phase - 1].map((functionSignature, sequence, values) => ({
    sequence,
    transactionHash: word(seed + sequence),
    sender: operator,
    target: roomAddress,
    functionSignature,
    calldataSha256: sha256(seed + 100 + sequence),
    receiptStatus: "success",
    blockNumber: blockNumber - (values.length - sequence - 1),
    blockHash: word(seed + 200 + sequence),
  }));
}

function phaseEntry(phase, {
  blockNumber,
  blockTimestamp,
  seed,
  reviewEnvelopeSha256,
}) {
  const transactions = operatorTransactions(phase, blockNumber, seed);
  const phaseFour = phase === 4;
  const transactionHash = phaseFour
    ? word(seed)
    : transactions.at(-1).transactionHash;
  return {
    kind: "diligence_exact_release_policy_phase",
    chainId: 84_532,
    diligenceRoomAddress: roomAddress,
    runtimeCodeHash,
    sourceCommit: releaseSha,
    deploymentIntentSha256,
    diligenceRoomDeploymentTx: deploymentTx,
    reviewEnvelopeSha256,
    finalAuthoritySha256,
    phase,
    transactionHash,
    blockNumber,
    blockTimestamp,
    recordedAt: recordedAt(blockTimestamp + 1),
    status: phaseStatus[phase - 1][0],
    policyState: phaseStatus[phase - 1][1],
    governanceAcceptanceEvidenceMode: phaseFour
      ? "eoa_direct_call"
      : "not_applicable",
    governanceAcceptanceEvidenceClaim: phaseFour
      ? "finalized_direct_eoa_call_event_and_state"
      : "operator_forge_broadcast_receipt",
    governanceAcceptanceFinalizedThroughBlock: phaseFour
      ? blockNumber + 8
      : 0,
    operatorTransactionCount: transactions.length,
    operatorTransactionsSha256: phaseFour
      ? null
      : diligenceOperatorTransactionsSha256(transactions),
    operatorTransactions: transactions,
    deploymentOperator: operator,
    governanceController: controller,
    teeIdentity,
    composeHash,
    resultVerifier,
    evaluatorPolicyCommitments: [...evaluatorPolicyCommitments],
    evaluatorPolicySetRoot,
    attestationVerifier,
    attestationReleasePolicyHash,
    postState: phasePoststate(phase, blockTimestamp),
  };
}

function fixture() {
  const reviews = [1, 2, 3, 4].map(reviewReceipt);
  const timestamps = [1_000_000, 1_000_200, 1_000_400, 1_173_300];
  const history = [1, 2, 3, 4].map((phase) => phaseEntry(phase, {
    blockNumber: phase * 100,
    blockTimestamp: timestamps[phase - 1],
    seed: 1_000 + (phase * 100),
    reviewEnvelopeSha256: reviews[phase - 1].reviewEnvelopeSha256,
  }));
  const phaseFour = history[3];
  const ledger = {
    schemaVersion: 2,
    status: "fresh_contract_suite_deployed_pending_cvm_binding",
    network: { chainId: 84_532 },
    currentOperatorDeployer: { address: operator },
    freshDeployment: {
      contractSuite: {
        sourceCommit: releaseSha,
        deploymentIntentSha256,
        broadcastTransactions: [{
          sequence: 0,
          contractKey: "diligenceRoom",
          contractName: "DiligenceRoom",
          transactionType: "CREATE",
          functionSignature: "constructor(bool,address)",
          transactionHash: deploymentTx,
          transactionFrom: operator,
          receiptContractAddress: roomAddress,
          receiptStatus: "success",
        }],
      },
    },
    contracts: {
      diligenceRoom: {
        address: roomAddress,
        runtimeCodeHash,
        sourceCommit: releaseSha,
        deploymentTx,
        initialDeveloper: operator,
        releaseGovernanceController: controller,
        protocolFeeRecipient: controller,
        governanceController: controller,
        developer: controller,
        pendingDeveloper: zeroAddress,
        pendingDeveloperActivatesAt: 0,
        currentOperatorControlled: false,
        latestReleasePhase: 4,
        latestReleaseTx: phaseFour.transactionHash,
        latestReleaseBlock: phaseFour.blockNumber,
        latestReleaseRecordedAt: phaseFour.recordedAt,
        latestReleaseSourceCommit: releaseSha,
        latestReleaseReviewEnvelopeSha256:
          phaseFour.reviewEnvelopeSha256,
        latestReleaseFinalAuthoritySha256: finalAuthoritySha256,
        status: phaseStatus[3][0],
        policyState: phaseStatus[3][1],
        governanceHandoffStatus: "accepted_complete",
        governanceAcceptanceEvidenceMode:
          phaseFour.governanceAcceptanceEvidenceMode,
        governanceAcceptanceEvidenceClaim:
          phaseFour.governanceAcceptanceEvidenceClaim,
        governanceAcceptanceFinalizedThroughBlock:
          phaseFour.governanceAcceptanceFinalizedThroughBlock,
        latestReleaseOperatorTransactionCount: 0,
        latestReleaseOperatorTransactionsSha256: null,
      },
    },
    deploymentHistory: [],
    diligenceReleaseHistory: history,
  };
  const ledgerFileSha256 = sha256(900);
  return {
    ledger,
    ledgerFileSha256,
    replay: {
      protocol: "dnai.release-ceremony-ledger.v1",
      release_sha: releaseSha,
      initialization_receipt_sha256: sha256(901),
      revision_count: 4,
      revision_chain_sha256: sha256(902),
      last_revision_receipt_sha256: sha256(903),
      current_ledger_sha256: ledgerFileSha256,
      current_ledger_bytes: 12_345,
      ledger_mode: "0444",
      finalized: true,
      finalization_receipt_sha256: sha256(904),
      recovery_receipt_count: 0,
    },
    expected: structuredClone(expected),
    reviewReceipts: reviews,
    chainEvidence: {
      valid: true,
      chainId: 84_532,
      secondaryChainId: 84_532,
      poststateMode: "final_active_frozen",
      poststateValid: true,
      secondaryPoststateValid: true,
      poststateRpcAgreement: true,
      snapshotFinality: "rpc_finalized",
      finalizedTagRechecked: true,
      secondaryFinalizedTagRechecked: true,
      snapshotBlockHashVerified: true,
      snapshotBlockNumber: 500,
      poststates: [{
        name: "DiligenceRoom",
        valid: true,
        assertions: [
          "developer_matches_final_authority",
          "developer_transfer_complete_and_delayed",
          "constructor_bound_production_posture",
        ],
      }],
    },
  };
}

test("completed Diligence ceremony requires frozen replay, four reviews, 13 operator transactions, and controller acceptance", () => {
  const result = inspectCompletedDiligenceReleaseCeremony(fixture());
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.status, DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS);
  assert.equal(result.phaseCount, 4);
  assert.equal(result.reviewEnvelopeCount, 4);
  assert.equal(result.distinctReviewEnvelopeCount, 4);
  assert.equal(result.operatorTransactionCount, 13);
  assert.equal(result.governanceAcceptanceMode, "eoa_direct_call");
});

test("operator bundle digest reproduces jq -cS trailing-newline bytes", () => {
  const transactions = fixture().ledger.diligenceReleaseHistory[0]
    .operatorTransactions;
  const sorted = (value) => Array.isArray(value)
    ? value.map(sorted)
    : value && typeof value === "object"
      ? Object.fromEntries(Object.keys(value).sort().map(
        (key) => [key, sorted(value[key])],
      ))
      : value;
  const withNewline = `sha256:${createHash("sha256")
    .update(`${JSON.stringify(sorted(transactions))}\n`, "utf8")
    .digest("hex")}`;
  const withoutNewline = `sha256:${createHash("sha256")
    .update(JSON.stringify(sorted(transactions)), "utf8")
    .digest("hex")}`;
  assert.equal(diligenceOperatorTransactionsSha256(transactions), withNewline);
  assert.notEqual(withNewline, withoutNewline);
});

for (const [name, mutate, reason] of [
  [
    "generic replay without finalization",
    (value) => {
      value.replay.finalized = false;
      value.replay.ledger_mode = "0600";
      value.replay.finalization_receipt_sha256 = null;
    },
    "durable_replay_not_finalized_or_lineage_drifted",
  ],
  [
    "finalized replay does not contain all four durable revisions",
    (value) => {
      value.replay.revision_count = 3;
    },
    "durable_replay_not_finalized_or_lineage_drifted",
  ],
  [
    "verification-only phase 4 omitted from the ledger",
    (value) => {
      value.ledger.diligenceReleaseHistory.pop();
    },
    "completed_four_phase_history_required",
  ],
  [
    "phase 4 left in the default non-applicable evidence mode",
    (value) => {
      const entry = value.ledger.diligenceReleaseHistory[3];
      entry.governanceAcceptanceEvidenceMode = "not_applicable";
      entry.governanceAcceptanceEvidenceClaim =
        "operator_forge_broadcast_receipt";
    },
    "external_governance_acceptance_evidence_invalid",
  ],
  [
    "phase 4 evidence mode and claim disagree",
    (value) => {
      const entry = value.ledger.diligenceReleaseHistory[3];
      entry.governanceAcceptanceEvidenceMode =
        "contract_event_and_state";
    },
    "external_governance_acceptance_evidence_invalid",
  ],
  [
    "one review envelope reused for two phases",
    (value) => {
      value.reviewReceipts[1].reviewEnvelopeSha256 =
        value.reviewReceipts[0].reviewEnvelopeSha256;
      value.ledger.diligenceReleaseHistory[1].reviewEnvelopeSha256 =
        value.reviewReceipts[0].reviewEnvelopeSha256;
    },
    "phase_review_envelopes_not_independent",
  ],
  [
    "phase review digest differs from the recorded ledger",
    (value) => {
      value.ledger.diligenceReleaseHistory[2].reviewEnvelopeSha256 =
        sha256(999);
    },
    "diligence_release_phase_invalid",
  ],
  [
    "phase review targets a different release authority",
    (value) => {
      value.reviewReceipts[2].subjectSha256 = sha256(999);
    },
    "phase_review_receipt_invalid",
  ],
  [
    "phase review was issued at the wrong checkpoint",
    (value) => {
      value.reviewReceipts[0].checkpoint =
        "after_release_ceremony_transaction";
    },
    "phase_review_receipt_invalid",
  ],
  [
    "operator transaction bundle digest is forged",
    (value) => {
      value.ledger.diligenceReleaseHistory[0]
        .operatorTransactionsSha256 = sha256(998);
    },
    "operator_transaction_bundle_invalid",
  ],
  [
    "operator transaction order is changed",
    (value) => {
      const transactions =
        value.ledger.diligenceReleaseHistory[1].operatorTransactions;
      [transactions[0], transactions[1]] = [transactions[1], transactions[0]];
      value.ledger.diligenceReleaseHistory[1]
        .operatorTransactionsSha256 =
        diligenceOperatorTransactionsSha256(transactions);
    },
    "operator_transaction_evidence_invalid",
  ],
  [
    "phase history accepts an unreviewed extra field",
    (value) => {
      value.ledger.diligenceReleaseHistory[0].unreviewed = true;
    },
    "diligence_release_history_schema_invalid",
  ],
  [
    "phase 4 carries operator transactions",
    (value) => {
      const entry = value.ledger.diligenceReleaseHistory[3];
      entry.operatorTransactions = structuredClone(
        value.ledger.diligenceReleaseHistory[0].operatorTransactions,
      );
      entry.operatorTransactionCount = entry.operatorTransactions.length;
      entry.operatorTransactionsSha256 =
        diligenceOperatorTransactionsSha256(entry.operatorTransactions);
    },
    "phase_four_operator_transactions_must_be_empty",
  ],
  [
    "source lineage drifts",
    (value) => {
      value.ledger.diligenceReleaseHistory[2].sourceCommit =
        "b".repeat(40);
    },
    "diligence_release_phase_invalid",
  ],
  [
    "controller lineage drifts",
    (value) => {
      value.ledger.diligenceReleaseHistory[1].governanceController =
        address(99);
    },
    "diligence_release_phase_invalid",
  ],
  [
    "phase timelock is bypassed",
    (value) => {
      value.ledger.diligenceReleaseHistory[3].blockTimestamp =
        value.ledger.diligenceReleaseHistory[2]
          .postState.pendingDeveloperActivatesAt - 1;
      value.ledger.diligenceReleaseHistory[3].recordedAt =
        recordedAt(value.ledger.diligenceReleaseHistory[3].blockTimestamp + 1);
    },
    "phase_timelock_order_invalid",
  ],
  [
    "phase 4 acceptance is not finalized through its transaction block",
    (value) => {
      value.ledger.diligenceReleaseHistory[3]
        .governanceAcceptanceFinalizedThroughBlock = 399;
    },
    "external_governance_acceptance_evidence_invalid",
  ],
  [
    "current ledger latest review does not match phase 4",
    (value) => {
      value.ledger.contracts.diligenceRoom
        .latestReleaseReviewEnvelopeSha256 = sha256(997);
    },
    "current_diligence_contract_state_invalid",
  ],
  [
    "current dual-RPC finalized state predates phase 4",
    (value) => {
      value.chainEvidence.snapshotBlockNumber = 399;
    },
    "current_dual_rpc_diligence_state_invalid",
  ],
]) {
  test(`Diligence activation gate rejects ${name}`, () => {
    const value = fixture();
    mutate(value);
    const result = inspectCompletedDiligenceReleaseCeremony(value);
    assert.equal(result.valid, false);
    assert.equal(result.reason, reason);
  });
}
