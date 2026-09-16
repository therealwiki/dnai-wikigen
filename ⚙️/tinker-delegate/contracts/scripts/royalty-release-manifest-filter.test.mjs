import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const FILTER = path.join(SCRIPT_DIR, "update-royalty-release-manifest.jq");
const SOURCE = "a".repeat(40);
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const RECORDED_AT = "2026-07-24T12:00:00Z";

const address = (character) => `0x${character.repeat(40)}`;
const bytes32 = (character) => `0x${character.repeat(64)}`;
const sha256 = (character) => `sha256:${character.repeat(64)}`;
const clone = (value) => structuredClone(value);

const AUTHORITY = Object.freeze({
  distributor_address: address("1"),
  distributor_runtime_code_hash: bytes32("a"),
  owner: address("2"),
  settlement_verifier: address("3"),
  qvl_verifier: address("4"),
  anchor_address: address("5"),
  anchor_runtime_code_hash: bytes32("b"),
  anchor_writer: address("6"),
  anchor_writer_release_commitment: bytes32("c"),
  release_policy_commitment: bytes32("d"),
  authority_nonce: "1",
});

const SIGNATURE_VERIFIER = Object.freeze({
  build_profile: "maxperf",
  commit_sha: "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
  executable_sha256: "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d",
  executable_user_relative_path: ".foundry/bin/cast",
  tool: "cast wallet verify",
  version: "1.5.1-stable",
});

const ACTIVATE_CALLDATA = "0x552d3bd4";
const ACTIVATE_CALLDATA_SHA256 =
  "sha256:121da2d6091ae01d0a21eb03956de5fe8642babcf8134727e1ce265c9f3deac9";
const UNPAUSE_CALLDATA =
  `0x16c38b3c${"0".repeat(64)}`;
const UNPAUSE_CALLDATA_SHA256 =
  "sha256:8ee19acc401145c6b99643561186700e09db3d978937442d134be39de863e254";

function addressWord(value) {
  return `${"0".repeat(24)}${value.slice(2)}`;
}

function proposalCalldata() {
  return `0x2e974627${addressWord(AUTHORITY.settlement_verifier)}`
    + addressWord(AUTHORITY.qvl_verifier)
    + addressWord(AUTHORITY.anchor_address)
    + AUTHORITY.anchor_writer_release_commitment.slice(2);
}

function phaseOnePrerequisite(phaseOneRecord) {
  const proposal = phaseOneRecord.transactionReceipts[0];
  return {
    phase_one_plan_sha256: phaseOneRecord.phasePlanSha256,
    phase_one_history_record_sha256: sha256("1"),
    phase_one_finalized_at: "2026-07-24T12:00:00.000Z",
    finalized_authority_receipt_sha256: sha256("2"),
    ledger_sha256: sha256("3"),
    ledger_revision: 11,
    ledger_revision_receipt_sha256: sha256("4"),
    proposal_tx_hash: proposal.transactionHash,
    proposal_block_number: String(proposal.blockNumber),
    proposal_block_hash: proposal.blockHash,
    pending_authority_activates_at:
      String(phaseOneRecord.postState.pendingAuthorityActivatesAt),
  };
}

function reviewedTransaction(action, sequence, nonce) {
  const calldata = action === "propose_authority_binding"
    ? proposalCalldata()
    : action === "activate_authority_proposal"
      ? ACTIVATE_CALLDATA
      : UNPAUSE_CALLDATA;
  const calldataSha256 = action === "activate_authority_proposal"
    ? ACTIVATE_CALLDATA_SHA256
    : action === "unpause"
      ? UNPAUSE_CALLDATA_SHA256
      : sha256("5");
  return {
    sequence,
    action,
    signer_address: AUTHORITY.owner,
    nonce: String(nonce),
    to: AUTHORITY.distributor_address,
    value_wei: "0",
    calldata,
    calldata_sha256: calldataSha256,
  };
}

function plan({ phase, mode, prerequisite = null, recovery = null, nonce = 7 }) {
  const actions = mode === "stage_authority"
    ? ["propose_authority_binding"]
    : mode === "activate_and_unpause"
      ? ["activate_authority_proposal", "unpause"]
      : ["unpause"];
  return {
    schema: "dnai.royalty-release-phase-plan.v2",
    status: "reviewed_for_exact_phase",
    plan_sha256: phase === 1 ? sha256("6")
      : mode === "activate_and_unpause" ? sha256("7") : sha256("8"),
    core: {
      schema: "dnai.royalty-release-phase-plan-core.v2",
      status: "proposed_for_review",
      release_sha: SOURCE,
      chain_id: 84532,
      phase,
      execution_mode: mode,
      phase_one_prerequisite: prerequisite,
      phase_two_recovery: recovery,
      valid_after: "2026-07-24T11:55:00.000Z",
      expires_at: "2026-07-24T12:10:00.000Z",
      deployment_intent_sha256: sha256("9"),
      fresh_contract_deployment_receipt_sha256: sha256("8"),
      royalty_release_prescriptive_authority_sha256: sha256("7"),
      reviewer_authority_genesis_sha256: sha256("a"),
      reviewer_authority_genesis_acceptance_sha256: sha256("b"),
      reviewer_authority_current_status_epoch: 3,
      reviewer_authority_current_status_sha256: sha256("c"),
      reviewer_root_hash: "d".repeat(64),
      reviewer_set_sha256: sha256("e"),
      authority: clone(AUTHORITY),
      transactions: actions.map((action, index) =>
        reviewedTransaction(action, index, nonce + index)),
    },
    review: {
      schema: "dnai.royalty-release-phase-plan-review.v2",
      signing_payload_sha256: sha256("f"),
      signature_scheme: "eip191_personal_sign_secp256k1_low_s_65_byte",
      signature_verifier: clone(SIGNATURE_VERIFIER),
      signatures: [
        {
          address: address("7"),
          controller_id: "reviewer.alpha",
          signature: `0x${"1".repeat(130)}`,
        },
        {
          address: address("8"),
          controller_id: "reviewer.beta",
          signature: `0x${"2".repeat(130)}`,
        },
      ],
      verified_signers: [
        {
          address: address("7"),
          controller_id: "reviewer.alpha",
          signature_sha256: sha256("1"),
        },
        {
          address: address("8"),
          controller_id: "reviewer.beta",
          signature_sha256: sha256("2"),
        },
      ],
    },
  };
}

function transactionReceipt(reviewed, character, blockNumber, status = "success") {
  return {
    sequence: reviewed.sequence,
    action: reviewed.action,
    sender: reviewed.signer_address,
    target: reviewed.to,
    nonce: reviewed.nonce,
    valueWei: reviewed.value_wei,
    calldata: reviewed.calldata,
    calldataSha256: reviewed.calldata_sha256,
    transactionHash: bytes32(character),
    status,
    blockNumber,
    blockHash: bytes32(character === "f" ? "e" : character),
    blockTimestamp: 1_721_822_400 + blockNumber,
    transactionIndex: reviewed.sequence,
  };
}

function anchorState() {
  return {
    address: AUTHORITY.anchor_address,
    runtimeCodeHash: AUTHORITY.anchor_runtime_code_hash,
    owner: AUTHORITY.owner,
    pendingOwner: ZERO_ADDRESS,
    deploymentIntentSha256: bytes32("9"),
    reviewerAuthorityGenesisAcceptanceSha256: bytes32("b"),
    writer: AUTHORITY.anchor_writer,
    writerReleaseCommitment: AUTHORITY.anchor_writer_release_commitment,
    pendingWriter: ZERO_ADDRESS,
    pendingWriterReleaseCommitment: ZERO_BYTES32,
    pendingWriterActivatesAt: 0,
    writerRotationsFrozen: true,
    paused: false,
    globalSequence: 0,
    globalHead: ZERO_BYTES32,
  };
}

function royaltyState(phase) {
  const phaseOne = phase === 1;
  return {
    address: AUTHORITY.distributor_address,
    runtimeCodeHash: AUTHORITY.distributor_runtime_code_hash,
    owner: AUTHORITY.owner,
    pendingOwner: ZERO_ADDRESS,
    paused: phaseOne,
    settlementVerifier: phaseOne ? ZERO_ADDRESS : AUTHORITY.settlement_verifier,
    qvlVerifier: phaseOne ? ZERO_ADDRESS : AUTHORITY.qvl_verifier,
    executionPolicyAnchor: phaseOne ? ZERO_ADDRESS : AUTHORITY.anchor_address,
    anchorWriterReleaseCommitment:
      phaseOne ? ZERO_BYTES32 : AUTHORITY.anchor_writer_release_commitment,
    releasePolicyCommitment:
      phaseOne ? ZERO_BYTES32 : AUTHORITY.release_policy_commitment,
    authorityNonce: phaseOne ? 0 : 1,
    pendingSettlementVerifier:
      phaseOne ? AUTHORITY.settlement_verifier : ZERO_ADDRESS,
    pendingQvlVerifier: phaseOne ? AUTHORITY.qvl_verifier : ZERO_ADDRESS,
    pendingExecutionPolicyAnchor: phaseOne ? AUTHORITY.anchor_address : ZERO_ADDRESS,
    pendingAnchorWriterReleaseCommitment:
      phaseOne ? AUTHORITY.anchor_writer_release_commitment : ZERO_BYTES32,
    pendingReleasePolicyCommitment:
      phaseOne ? AUTHORITY.release_policy_commitment : ZERO_BYTES32,
    pendingAuthorityNonce: phaseOne ? 1 : 0,
    pendingAuthorityActivatesAt: phaseOne ? 1_721_995_200 : 0,
    pendingAuthorityRevocation: false,
    settlementVerifierEverConfigured: !phaseOne,
    qvlVerifierEverConfigured: !phaseOne,
    anchorWriterEverConfigured: !phaseOne,
  };
}

function recoveryEvidence(recovery, currentReviewed, currentReceipt) {
  const activationReviewed = reviewedTransaction("activate_authority_proposal", 0, 9);
  const revertedReviewed = reviewedTransaction("unpause", 1, 10);
  const activationReceipt = transactionReceipt(activationReviewed, "b", 150);
  const revertedUnpauseReceipt = transactionReceipt(revertedReviewed, "c", 151, "reverted");
  recovery.activation_tx_hash = activationReceipt.transactionHash;
  recovery.activation_block_number = String(activationReceipt.blockNumber);
  recovery.activation_block_hash = activationReceipt.blockHash;
  recovery.reverted_unpause_tx_hash = revertedUnpauseReceipt.transactionHash;
  recovery.reverted_unpause_block_number = String(revertedUnpauseReceipt.blockNumber);
  recovery.reverted_unpause_block_hash = revertedUnpauseReceipt.blockHash;
  recovery.prior_unpause_nonce = revertedUnpauseReceipt.nonce;
  assert.equal(currentReviewed.nonce, "11");
  assert.notEqual(currentReceipt.transactionHash, revertedUnpauseReceipt.transactionHash);
  return {
    schema: "dnai.base-sepolia-royalty-unpause-recovery-evidence.v1",
    evidenceSha256: recovery.finalized_recovery_evidence_sha256,
    priorPhaseTwoPlanSha256: recovery.prior_phase_two_plan_sha256,
    activationReceipt,
    revertedUnpauseReceipt,
  };
}

function finalizedAuthority(phasePlan, receipts, phaseTwoRecoveryEvidence = null) {
  const recoveryDigest = phaseTwoRecoveryEvidence?.evidenceSha256 ?? null;
  const blockNumber = Math.max(...receipts.map((entry) => entry.blockNumber), 200);
  const blockTimestamp = 1_721_822_400 + blockNumber;
  const authorityStateSha256 = phasePlan.core.phase === 1 ? sha256("3") : sha256("4");
  const transactionReceiptsSha256 = phasePlan.core.phase === 1 ? sha256("5") : sha256("6");
  const common = {
    chainId: 84532,
    finalizedBlockNumber: blockNumber,
    finalizedBlockHash: bytes32("f"),
    finalizedBlockTimestamp: blockTimestamp,
    distributorRuntimeCodeHash: AUTHORITY.distributor_runtime_code_hash,
    anchorRuntimeCodeHash: AUTHORITY.anchor_runtime_code_hash,
    authorityStateSha256,
    transactionReceiptsSha256,
    phaseTwoRecoveryEvidenceSha256: recoveryDigest,
  };
  return {
    schema: "dnai.base-sepolia-royalty-finalized-authority.v1",
    proof:
      "two_distinct_https_rpcs_exact_same_finalized_numeric_block_runtime_eth_call_and_transaction_receipt_agreement",
    chainId: 84532,
    finalizedBlockNumber: blockNumber,
    finalizedBlockHash: bytes32("f"),
    finalizedBlockTimestamp: blockTimestamp,
    authorityStateSha256,
    transactionReceiptsSha256,
    phaseTwoRecoveryEvidence,
    providerConfirmations: [
      { label: "primary", rpcOrigin: "https://rpc-one.example", ...common },
      { label: "secondary", rpcOrigin: "https://rpc-two.example", ...common },
    ],
    authorityState: {
      executionPolicyAnchor: anchorState(),
      royaltyDistributor: royaltyState(phasePlan.core.phase),
    },
    transactionReceipts: clone(receipts),
  };
}

function freshLedger() {
  return {
    schemaVersion: 2,
    customField: { mustSurvive: true },
    network: { chainId: 84532, customNetworkField: "must-survive" },
    freshDeployment: { contractSuite: { sourceCommit: SOURCE }, preserve: true },
    contracts: {
      royaltyDistributor: {
        address: AUTHORITY.distributor_address,
        runtimeCodeHash: AUTHORITY.distributor_runtime_code_hash,
        sourceCommit: SOURCE,
        owner: AUTHORITY.owner,
        pendingOwner: ZERO_ADDRESS,
        paused: true,
        settlementVerifier: ZERO_ADDRESS,
        qvlVerifier: ZERO_ADDRESS,
        executionPolicyAnchor: ZERO_ADDRESS,
        anchorWriterReleaseCommitment: ZERO_BYTES32,
        releasePolicyCommitment: ZERO_BYTES32,
        authorityNonce: 0,
        pendingAuthorityActivatesAt: 0,
        preserveContractField: "must-survive",
      },
      executionPolicyAnchor: {
        address: AUTHORITY.anchor_address,
        runtimeCodeHash: AUTHORITY.anchor_runtime_code_hash,
        sourceCommit: SOURCE,
        preserveAnchorField: "must-survive",
      },
      unrelatedContract: { preserve: true },
    },
  };
}

function runFilter(ledger, phasePlan, receipts, finality, { expectSuccess = true } = {}) {
  const result = spawnSync("jq", [
    "--argjson", "chainId", "84532",
    "--arg", "sourceCommit", SOURCE,
    "--arg", "recordedAt", RECORDED_AT,
    "--argjson", "phasePlan", JSON.stringify(phasePlan),
    "--argjson", "transactionReceipts", JSON.stringify(receipts),
    "--argjson", "finalizedAuthority", JSON.stringify(finality),
    "-f", FILTER,
  ], {
    input: `${JSON.stringify(ledger)}\n`,
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  if (expectSuccess) {
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout);
  }
  assert.notEqual(result.status, 0, "malformed release evidence unexpectedly passed");
  return result.stderr;
}

function executePhaseOne() {
  const phasePlan = plan({ phase: 1, mode: "stage_authority", nonce: 7 });
  const receipts = [transactionReceipt(phasePlan.core.transactions[0], "9", 100)];
  const finality = finalizedAuthority(phasePlan, receipts);
  return {
    phasePlan,
    receipts,
    finality,
    ledger: runFilter(freshLedger(), phasePlan, receipts, finality),
  };
}

test("phase 1 appends exact staged authority and preserves unrelated ledger state", () => {
  const { ledger, phasePlan, receipts } = executePhaseOne();
  assert.deepEqual(ledger.customField, { mustSurvive: true });
  assert.equal(ledger.network.customNetworkField, "must-survive");
  assert.deepEqual(ledger.contracts.unrelatedContract, { preserve: true });
  assert.equal(ledger.contracts.royaltyDistributor.preserveContractField, "must-survive");
  assert.equal(ledger.contracts.executionPolicyAnchor.preserveAnchorField, "must-survive");
  assert.equal(ledger.contracts.royaltyDistributor.latestReleasePhase, 1);
  assert.equal(ledger.contracts.royaltyDistributor.paused, true);
  assert.equal(ledger.contracts.royaltyDistributor.pendingAuthorityNonce, 1);
  assert.equal(ledger.royaltyReleaseHistory.length, 1);
  assert.equal(ledger.royaltyReleaseHistory[0].phasePlanSha256, phasePlan.plan_sha256);
  assert.deepEqual(ledger.royaltyReleaseHistory[0].transactionReceipts, receipts);
  assert.equal(Object.hasOwn(ledger.royaltyReleaseHistory[0].reviewEvidence, "signatures"), false);
});

test("normal phase 2 requires exact phase-one lineage and finalized dual-provider state", () => {
  const phaseOne = executePhaseOne();
  const prerequisite = phaseOnePrerequisite(phaseOne.ledger.royaltyReleaseHistory[0]);
  const phasePlan = plan({
    phase: 2,
    mode: "activate_and_unpause",
    prerequisite,
    nonce: 8,
  });
  const receipts = phasePlan.core.transactions.map((entry, index) =>
    transactionReceipt(entry, index === 0 ? "b" : "c", 150 + index));
  const finality = finalizedAuthority(phasePlan, receipts);
  const ledger = runFilter(phaseOne.ledger, phasePlan, receipts, finality);
  assert.equal(ledger.contracts.royaltyDistributor.latestReleasePhase, 2);
  assert.equal(ledger.contracts.royaltyDistributor.latestReleaseExecutionMode,
    "activate_and_unpause");
  assert.equal(ledger.contracts.royaltyDistributor.paused, false);
  assert.equal(ledger.contracts.royaltyDistributor.authorityNonce, 1);
  assert.equal(ledger.royaltyReleaseHistory.length, 2);
  assert.deepEqual(ledger.royaltyReleaseHistory.map((entry) => entry.phase), [1, 2]);
});

test("recovery phase 2 records finalized activation and reverted-unpause evidence only on success", () => {
  const phaseOne = executePhaseOne();
  const prerequisite = phaseOnePrerequisite(phaseOne.ledger.royaltyReleaseHistory[0]);
  const recovery = {
    prior_phase_two_plan_sha256: sha256("3"),
    finalized_recovery_evidence_sha256: sha256("a"),
    activation_tx_hash: bytes32("b"),
    activation_block_number: "150",
    activation_block_hash: bytes32("b"),
    reverted_unpause_tx_hash: bytes32("c"),
    reverted_unpause_block_number: "151",
    reverted_unpause_block_hash: bytes32("c"),
    prior_unpause_nonce: "10",
  };
  const phasePlan = plan({
    phase: 2,
    mode: "recover_reverted_unpause",
    prerequisite,
    recovery,
    nonce: 11,
  });
  const receipts = [transactionReceipt(phasePlan.core.transactions[0], "d", 152)];
  const recoveryReceipt = recoveryEvidence(
    phasePlan.core.phase_two_recovery,
    phasePlan.core.transactions[0],
    receipts[0],
  );
  const finality = finalizedAuthority(phasePlan, receipts, recoveryReceipt);
  const ledger = runFilter(phaseOne.ledger, phasePlan, receipts, finality);
  const record = ledger.royaltyReleaseHistory[1];
  assert.equal(record.executionMode, "recover_reverted_unpause");
  assert.equal(record.phaseTwoRecovery.reverted_unpause_tx_hash,
    recoveryReceipt.revertedUnpauseReceipt.transactionHash);
  assert.equal(record.finalizedAuthority.phaseTwoRecoveryEvidence.revertedUnpauseReceipt.status,
    "reverted");
  assert.equal(record.postState.paused, false);
});

test("filter rejects history gaps, transaction replay, pin drift, and provider disagreement", () => {
  const phaseOne = executePhaseOne();
  const prerequisite = phaseOnePrerequisite(phaseOne.ledger.royaltyReleaseHistory[0]);
  const phasePlan = plan({
    phase: 2,
    mode: "activate_and_unpause",
    prerequisite,
    nonce: 8,
  });
  const receipts = phasePlan.core.transactions.map((entry, index) =>
    transactionReceipt(entry, index === 0 ? "b" : "c", 150 + index));
  const finality = finalizedAuthority(phasePlan, receipts);

  runFilter(freshLedger(), phasePlan, receipts, finality, { expectSuccess: false });

  const replayReceipts = clone(receipts);
  replayReceipts[0].transactionHash = phaseOne.receipts[0].transactionHash;
  const replayFinality = finalizedAuthority(phasePlan, replayReceipts);
  runFilter(phaseOne.ledger, phasePlan, replayReceipts, replayFinality,
    { expectSuccess: false });

  const driftedLedger = clone(phaseOne.ledger);
  driftedLedger.contracts.royaltyDistributor.runtimeCodeHash = bytes32("e");
  runFilter(driftedLedger, phasePlan, receipts, finality, { expectSuccess: false });

  const disagreeingFinality = clone(finality);
  disagreeingFinality.providerConfirmations[1].finalizedBlockHash = bytes32("e");
  runFilter(phaseOne.ledger, phasePlan, receipts, disagreeingFinality,
    { expectSuccess: false });

  const wrongCalldataPlan = clone(phasePlan);
  wrongCalldataPlan.core.transactions[0].calldata = UNPAUSE_CALLDATA;
  wrongCalldataPlan.core.transactions[0].calldata_sha256 = UNPAUSE_CALLDATA_SHA256;
  const wrongCalldataReceipts = clone(receipts);
  wrongCalldataReceipts[0].calldata = UNPAUSE_CALLDATA;
  wrongCalldataReceipts[0].calldataSha256 = UNPAUSE_CALLDATA_SHA256;
  const wrongCalldataFinality = finalizedAuthority(
    wrongCalldataPlan,
    wrongCalldataReceipts,
  );
  runFilter(phaseOne.ledger, wrongCalldataPlan, wrongCalldataReceipts,
    wrongCalldataFinality, { expectSuccess: false });
});

test("recovery rejects an unfinalized or non-reverted prior unpause receipt", () => {
  const phaseOne = executePhaseOne();
  const prerequisite = phaseOnePrerequisite(phaseOne.ledger.royaltyReleaseHistory[0]);
  const recovery = {
    prior_phase_two_plan_sha256: sha256("3"),
    finalized_recovery_evidence_sha256: sha256("a"),
    activation_tx_hash: bytes32("b"),
    activation_block_number: "150",
    activation_block_hash: bytes32("b"),
    reverted_unpause_tx_hash: bytes32("c"),
    reverted_unpause_block_number: "151",
    reverted_unpause_block_hash: bytes32("c"),
    prior_unpause_nonce: "10",
  };
  const phasePlan = plan({
    phase: 2,
    mode: "recover_reverted_unpause",
    prerequisite,
    recovery,
    nonce: 11,
  });
  const receipts = [transactionReceipt(phasePlan.core.transactions[0], "d", 152)];
  const evidence = recoveryEvidence(
    phasePlan.core.phase_two_recovery,
    phasePlan.core.transactions[0],
    receipts[0],
  );
  evidence.revertedUnpauseReceipt.status = "success";
  const finality = finalizedAuthority(phasePlan, receipts, evidence);
  runFilter(phaseOne.ledger, phasePlan, receipts, finality, { expectSuccess: false });
});
