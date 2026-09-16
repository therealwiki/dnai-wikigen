import { createHash } from "node:crypto";

export const DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA =
  "dnai.diligence-release-activation-gate.v1";
export const DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS =
  "completed_frozen_diligence_release_ceremony_verified";
export const DILIGENCE_RELEASE_ACTIVATION_GATE_TRUTH_STATUS =
  "durable_revision_chain_four_independent_reviews_ordered_operator_transactions_and_external_controller_acceptance_verified";

export const DILIGENCE_RELEASE_PHASES = Object.freeze([
  Object.freeze({
    phase: 1,
    status: "deployed_diligence_compose_and_qvl_pending_timelock",
    policyState: "fail_closed_pending_compose_and_attestation_timelocks",
    functions: Object.freeze([
      "proposeComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
      "proposeResultVerifier(address)",
      "proposeAttestationBinding(address,bytes32)",
    ]),
  }),
  Object.freeze({
    phase: 2,
    status: "deployed_diligence_tee_identity_pending_timelock",
    policyState: "fail_closed_pending_tee_identity_timelock",
    functions: Object.freeze([
      "activateComposeAndEvaluatorPolicySet(bytes32,bytes32[3])",
      "activateResultVerifier()",
      "freezeResultVerifier()",
      "activateAttestationBinding()",
      "freezeAttestationBinding()",
      "proposeTeeIdentity(address,bytes32)",
    ]),
  }),
  Object.freeze({
    phase: 3,
    status:
      "deployed_exact_diligence_release_policy_frozen_pending_governance_timelock",
    policyState: "fail_closed_exact_policy_pending_governance_acceptance",
    functions: Object.freeze([
      "activateTeeIdentity(address)",
      "freezeComposeAndEvaluatorPolicySets()",
      "freezeTeeIdentityAdditions()",
      "proposeDeveloper(address)",
    ]),
  }),
  Object.freeze({
    phase: 4,
    status: "deployed_exact_diligence_release_policy_frozen_active",
    policyState: "exact_timelocked_diligence_release_policy_frozen_active",
    functions: Object.freeze([]),
  }),
]);

export const DILIGENCE_RELEASE_HISTORY_ENTRY_FIELDS = Object.freeze([
  "kind",
  "chainId",
  "diligenceRoomAddress",
  "runtimeCodeHash",
  "sourceCommit",
  "deploymentIntentSha256",
  "diligenceRoomDeploymentTx",
  "reviewEnvelopeSha256",
  "finalAuthoritySha256",
  "phase",
  "transactionHash",
  "blockNumber",
  "blockTimestamp",
  "recordedAt",
  "status",
  "policyState",
  "governanceAcceptanceEvidenceMode",
  "governanceAcceptanceEvidenceClaim",
  "governanceAcceptanceFinalizedThroughBlock",
  "operatorTransactionCount",
  "operatorTransactionsSha256",
  "operatorTransactions",
  "deploymentOperator",
  "governanceController",
  "teeIdentity",
  "composeHash",
  "resultVerifier",
  "evaluatorPolicyCommitments",
  "evaluatorPolicySetRoot",
  "attestationVerifier",
  "attestationReleasePolicyHash",
  "postState",
]);

export const DILIGENCE_RELEASE_POSTSTATE_FIELDS = Object.freeze([
  "developer",
  "pendingDeveloper",
  "pendingDeveloperActivatesAt",
  "developerTransferDelaySeconds",
  "approvedComposeCount",
  "approvedTeeIdentityCount",
  "pendingComposeCount",
  "pendingTeeIdentityCount",
  "pendingComposeActivatesAt",
  "pendingTeeIdentityActivatesAt",
  "activeTeeIdentityComposeHash",
  "pendingTeeIdentityComposeHash",
  "resultVerifier",
  "pendingResultVerifier",
  "pendingResultVerifierActivatesAt",
  "resultVerifierFrozen",
  "evaluatorPolicyCommitments",
  "evaluatorPolicySetRoot",
  "approvedEvaluatorPolicyCount",
  "pendingEvaluatorPolicyCount",
  "evaluatorPolicySetFrozen",
  "pendingEvaluatorPolicy1ActivatesAt",
  "pendingEvaluatorPolicy2ActivatesAt",
  "pendingEvaluatorPolicy3ActivatesAt",
  "attestationVerifier",
  "attestationReleasePolicyHash",
  "pendingAttestationVerifier",
  "pendingAttestationReleasePolicyHash",
  "pendingAttestationBindingActivatesAt",
  "attestationBindingFrozen",
  "composeAdditionsFrozen",
  "teeIdentityAdditionsFrozen",
]);

export const DILIGENCE_OPERATOR_TRANSACTION_FIELDS = Object.freeze([
  "sequence",
  "transactionHash",
  "sender",
  "target",
  "functionSignature",
  "calldataSha256",
  "receiptStatus",
  "blockNumber",
  "blockHash",
]);

const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const REVIEW_RECEIPT_TRUTH =
  "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx";
const REVIEW_CHECKPOINT =
  "after_measured_cvms_before_any_release_ceremony_transaction";
const OPERATOR_TX_CLAIM = "operator_forge_broadcast_receipt";
const PHASE_FOUR_CLAIMS = Object.freeze({
  eoa_direct_call: "finalized_direct_eoa_call_event_and_state",
  contract_event_and_state:
    "finalized_contract_controller_event_and_state_no_trace_claim",
});
const COMPLETED_DILIGENCE_RELEASE_GATES = new WeakSet();

class GateError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

function fail(code) {
  throw new GateError(code);
}

function exactObject(value, fields, code) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(code);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(code);
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function lower(value) {
  return typeof value === "string" ? value.toLowerCase() : "";
}

function isAddress(value, { nonzero = false } = {}) {
  return typeof value === "string"
    && ADDRESS.test(value)
    && (!nonzero || lower(value) !== ZERO_ADDRESS);
}

function isBytes32(value, { nonzero = false } = {}) {
  return typeof value === "string"
    && BYTES32.test(value)
    && (!nonzero || lower(value) !== ZERO_BYTES32);
}

function isSha256(value, { nonzero = false } = {}) {
  return typeof value === "string"
    && SHA256.test(value)
    && (!nonzero || value !== `sha256:${"0".repeat(64)}`);
}

function isSafeUint(value, { positive = false } = {}) {
  return Number.isSafeInteger(value)
    && value >= (positive ? 1 : 0);
}

function isCanonicalUtcSecond(value) {
  return typeof value === "string"
    && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)
    && Number.isFinite(Date.parse(value))
    && new Date(Date.parse(value)).toISOString().replace(".000Z", "Z") === value;
}

function equalAddress(left, right) {
  return isAddress(left) && isAddress(right) && lower(left) === lower(right);
}

function equalBytes32(left, right) {
  return isBytes32(left) && isBytes32(right) && lower(left) === lower(right);
}

function bytes32(value) {
  if (typeof value !== "string") return "";
  const candidate = value.startsWith("0x") ? value : `0x${value}`;
  return isBytes32(candidate) ? lower(candidate) : "";
}

function sameStringArray(left, right, normalizer = (value) => value) {
  return Array.isArray(left)
    && Array.isArray(right)
    && left.length === right.length
    && left.every((value, index) => (
      normalizer(value) === normalizer(right[index])
    ));
}

export function diligenceOperatorTransactionsSha256(transactions) {
  if (!Array.isArray(transactions)) fail("operator_transactions_not_array");
  const compactSortedJsonWithJqNewline =
    `${JSON.stringify(sortedObject(transactions))}\n`;
  return `sha256:${createHash("sha256")
    .update(compactSortedJsonWithJqNewline, "utf8")
    .digest("hex")}`;
}

function normalizeExpected(value) {
  exactObject(value, [
    "chainId",
    "releaseSha",
    "deploymentIntentSha256",
    "finalAuthoritySha256",
    "deploymentOperator",
    "governanceController",
    "diligenceRoomAddress",
    "runtimeCodeHash",
    "teeIdentity",
    "composeHash",
    "resultVerifier",
    "evaluatorPolicyCommitments",
    "evaluatorPolicySetRoot",
    "attestationVerifier",
    "attestationReleasePolicyHash",
  ], "expected_lineage_schema_invalid");
  if (value.chainId !== 84_532
    || !RELEASE_SHA.test(value.releaseSha)
    || !isSha256(value.deploymentIntentSha256, { nonzero: true })
    || !isSha256(value.finalAuthoritySha256, { nonzero: true })
    || !isAddress(value.deploymentOperator, { nonzero: true })
    || !isAddress(value.governanceController, { nonzero: true })
    || equalAddress(value.deploymentOperator, value.governanceController)
    || !isAddress(value.diligenceRoomAddress, { nonzero: true })
    || !isBytes32(value.runtimeCodeHash, { nonzero: true })
    || !isAddress(value.teeIdentity, { nonzero: true })
    || !isBytes32(bytes32(value.composeHash), { nonzero: true })
    || !isAddress(value.resultVerifier, { nonzero: true })
    || !Array.isArray(value.evaluatorPolicyCommitments)
    || value.evaluatorPolicyCommitments.length !== 3
    || !value.evaluatorPolicyCommitments.every((item) => (
      isBytes32(item, { nonzero: true })
    ))
    || new Set(value.evaluatorPolicyCommitments.map(lower)).size !== 3
    || !isBytes32(value.evaluatorPolicySetRoot, { nonzero: true })
    || !isAddress(value.attestationVerifier, { nonzero: true })
    || !isBytes32(value.attestationReleasePolicyHash, { nonzero: true })) {
    fail("expected_lineage_invalid");
  }
  return {
    ...value,
    deploymentOperator: lower(value.deploymentOperator),
    governanceController: lower(value.governanceController),
    diligenceRoomAddress: lower(value.diligenceRoomAddress),
    runtimeCodeHash: lower(value.runtimeCodeHash),
    teeIdentity: lower(value.teeIdentity),
    composeHash: bytes32(value.composeHash),
    resultVerifier: lower(value.resultVerifier),
    evaluatorPolicyCommitments: value.evaluatorPolicyCommitments.map(lower),
    evaluatorPolicySetRoot: lower(value.evaluatorPolicySetRoot),
    attestationVerifier: lower(value.attestationVerifier),
    attestationReleasePolicyHash: lower(value.attestationReleasePolicyHash),
  };
}

function validateReplay(replay, expected, ledgerFileSha256) {
  const fields = [
    "protocol",
    "release_sha",
    "initialization_receipt_sha256",
    "revision_count",
    "revision_chain_sha256",
    "last_revision_receipt_sha256",
    "current_ledger_sha256",
    "current_ledger_bytes",
    "ledger_mode",
    "finalized",
    "finalization_receipt_sha256",
    "recovery_receipt_count",
  ];
  exactObject(replay, fields, "durable_replay_schema_invalid");
  if (replay.protocol !== "dnai.release-ceremony-ledger.v1"
    || replay.release_sha !== expected.releaseSha
    || replay.finalized !== true
    || replay.ledger_mode !== "0444"
    || !isSha256(replay.initialization_receipt_sha256, { nonzero: true })
    || !isSafeUint(replay.revision_count, { positive: true })
    || replay.revision_count < 4
    || !isSha256(replay.revision_chain_sha256, { nonzero: true })
    || !isSha256(replay.last_revision_receipt_sha256, { nonzero: true })
    || !isSha256(replay.current_ledger_sha256, { nonzero: true })
    || replay.current_ledger_sha256 !== ledgerFileSha256
    || !isSafeUint(replay.current_ledger_bytes, { positive: true })
    || !isSha256(replay.finalization_receipt_sha256, { nonzero: true })
    || !isSafeUint(replay.recovery_receipt_count)) {
    fail("durable_replay_not_finalized_or_lineage_drifted");
  }
}

function validateReviewReceipts(receipts, expected) {
  if (!Array.isArray(receipts) || receipts.length !== 4) {
    fail("four_phase_reviews_required");
  }
  const digests = [];
  receipts.forEach((entry, index) => {
    exactObject(entry, [
      "phase",
      "valid",
      "schema",
      "status",
      "truthStatus",
      "subjectKind",
      "subjectSha256",
      "reviewEnvelopeSha256",
      "reviewEvidenceSha256",
      "checkpoint",
      "actionScopeCount",
      "reviewerDeclarationCount",
      "subjectSemanticValidation",
    ], "phase_review_receipt_schema_invalid");
    if (entry.phase !== index + 1
      || entry.valid !== true
      || entry.schema
        !== "dnai.authority-review-envelope-validation-receipt.v1"
      || entry.status !== "valid"
      || entry.truthStatus !== REVIEW_RECEIPT_TRUTH
      || entry.subjectKind !== "final_release_authority"
      || entry.subjectSha256 !== expected.finalAuthoritySha256
      || !isSha256(entry.reviewEnvelopeSha256, { nonzero: true })
      || !isSha256(entry.reviewEvidenceSha256, { nonzero: true })
      || entry.checkpoint !== REVIEW_CHECKPOINT
      || entry.actionScopeCount !== 8
      || entry.reviewerDeclarationCount !== 2
      || entry.subjectSemanticValidation
        !== "final_release_authority_validated") {
      fail("phase_review_receipt_invalid");
    }
    digests.push(entry.reviewEnvelopeSha256);
  });
  if (new Set(digests).size !== 4) {
    fail("phase_review_envelopes_not_independent");
  }
  return digests;
}

function validateSharedEntry(entry, expected, deploymentTx) {
  return entry.kind === "diligence_exact_release_policy_phase"
    && entry.chainId === expected.chainId
    && equalAddress(entry.diligenceRoomAddress, expected.diligenceRoomAddress)
    && equalBytes32(entry.runtimeCodeHash, expected.runtimeCodeHash)
    && entry.sourceCommit === expected.releaseSha
    && entry.deploymentIntentSha256 === expected.deploymentIntentSha256
    && equalBytes32(entry.diligenceRoomDeploymentTx, deploymentTx)
    && entry.finalAuthoritySha256 === expected.finalAuthoritySha256
    && equalAddress(entry.deploymentOperator, expected.deploymentOperator)
    && equalAddress(entry.governanceController, expected.governanceController)
    && equalAddress(entry.teeIdentity, expected.teeIdentity)
    && equalBytes32(entry.composeHash, expected.composeHash)
    && equalAddress(entry.resultVerifier, expected.resultVerifier)
    && sameStringArray(
      entry.evaluatorPolicyCommitments,
      expected.evaluatorPolicyCommitments,
      lower,
    )
    && equalBytes32(
      entry.evaluatorPolicySetRoot,
      expected.evaluatorPolicySetRoot,
    )
    && equalAddress(entry.attestationVerifier, expected.attestationVerifier)
    && equalBytes32(
      entry.attestationReleasePolicyHash,
      expected.attestationReleasePolicyHash,
    );
}

function validateOperatorTransactions(entry, phase, expected, allTxHashes) {
  if (phase.functions.length === 0) {
    if (entry.operatorTransactionCount !== 0
      || !Array.isArray(entry.operatorTransactions)
      || entry.operatorTransactions.length !== 0
      || entry.operatorTransactionsSha256 !== null) {
      fail("phase_four_operator_transactions_must_be_empty");
    }
    return;
  }
  if (!Array.isArray(entry.operatorTransactions)
    || entry.operatorTransactions.length !== phase.functions.length
    || entry.operatorTransactionCount !== phase.functions.length
    || entry.operatorTransactionsSha256
      !== diligenceOperatorTransactionsSha256(entry.operatorTransactions)) {
    fail("operator_transaction_bundle_invalid");
  }
  let priorBlock = 0;
  entry.operatorTransactions.forEach((transaction, index) => {
    exactObject(
      transaction,
      DILIGENCE_OPERATOR_TRANSACTION_FIELDS,
      "operator_transaction_schema_invalid",
    );
    const hash = lower(transaction.transactionHash);
    if (transaction.sequence !== index
      || transaction.functionSignature !== phase.functions[index]
      || !isBytes32(transaction.transactionHash, { nonzero: true })
      || allTxHashes.has(hash)
      || !equalAddress(transaction.sender, expected.deploymentOperator)
      || !equalAddress(transaction.target, expected.diligenceRoomAddress)
      || !isSha256(transaction.calldataSha256, { nonzero: true })
      || transaction.receiptStatus !== "success"
      || !isSafeUint(transaction.blockNumber, { positive: true })
      || transaction.blockNumber < priorBlock
      || transaction.blockNumber > entry.blockNumber
      || !isBytes32(transaction.blockHash, { nonzero: true })) {
      fail("operator_transaction_evidence_invalid");
    }
    priorBlock = transaction.blockNumber;
    allTxHashes.add(hash);
  });
  const last = entry.operatorTransactions.at(-1);
  if (!equalBytes32(last.transactionHash, entry.transactionHash)
    || last.blockNumber !== entry.blockNumber) {
    fail("operator_transaction_terminal_binding_invalid");
  }
}

function commonClosedPoststate(postState, expected) {
  return postState.approvedComposeCount === 1
    && postState.approvedTeeIdentityCount === 1
    && postState.pendingComposeCount === 0
    && postState.pendingTeeIdentityCount === 0
    && postState.pendingComposeActivatesAt === 0
    && postState.pendingTeeIdentityActivatesAt === 0
    && equalBytes32(
      postState.activeTeeIdentityComposeHash,
      expected.composeHash,
    )
    && equalBytes32(postState.pendingTeeIdentityComposeHash, ZERO_BYTES32)
    && equalAddress(postState.resultVerifier, expected.resultVerifier)
    && equalAddress(postState.pendingResultVerifier, ZERO_ADDRESS)
    && postState.pendingResultVerifierActivatesAt === 0
    && postState.resultVerifierFrozen === true
    && sameStringArray(
      postState.evaluatorPolicyCommitments,
      expected.evaluatorPolicyCommitments,
      lower,
    )
    && equalBytes32(
      postState.evaluatorPolicySetRoot,
      expected.evaluatorPolicySetRoot,
    )
    && postState.approvedEvaluatorPolicyCount === 3
    && postState.pendingEvaluatorPolicyCount === 0
    && postState.evaluatorPolicySetFrozen === true
    && postState.pendingEvaluatorPolicy1ActivatesAt === 0
    && postState.pendingEvaluatorPolicy2ActivatesAt === 0
    && postState.pendingEvaluatorPolicy3ActivatesAt === 0
    && equalAddress(
      postState.attestationVerifier,
      expected.attestationVerifier,
    )
    && equalBytes32(
      postState.attestationReleasePolicyHash,
      expected.attestationReleasePolicyHash,
    )
    && equalAddress(postState.pendingAttestationVerifier, ZERO_ADDRESS)
    && equalBytes32(
      postState.pendingAttestationReleasePolicyHash,
      ZERO_BYTES32,
    )
    && postState.pendingAttestationBindingActivatesAt === 0
    && postState.attestationBindingFrozen === true
    && postState.composeAdditionsFrozen === true
    && postState.teeIdentityAdditionsFrozen === true;
}

function validatePoststate(entry, expected) {
  const postState = exactObject(
    entry.postState,
    DILIGENCE_RELEASE_POSTSTATE_FIELDS,
    "phase_poststate_schema_invalid",
  );
  if (postState.developerTransferDelaySeconds !== 172_800
    || !sameStringArray(
      postState.evaluatorPolicyCommitments,
      expected.evaluatorPolicyCommitments,
      lower,
    )) {
    fail("phase_poststate_shared_policy_invalid");
  }
  if (entry.phase === 1) {
    if (!equalAddress(postState.developer, expected.deploymentOperator)
      || !equalAddress(postState.pendingDeveloper, ZERO_ADDRESS)
      || postState.pendingDeveloperActivatesAt !== 0
      || postState.approvedComposeCount !== 0
      || postState.approvedTeeIdentityCount !== 0
      || postState.pendingComposeCount !== 1
      || postState.pendingTeeIdentityCount !== 0
      || !isSafeUint(postState.pendingComposeActivatesAt, { positive: true })
      || postState.pendingComposeActivatesAt <= entry.blockTimestamp
      || postState.pendingTeeIdentityActivatesAt !== 0
      || !equalBytes32(postState.activeTeeIdentityComposeHash, ZERO_BYTES32)
      || !equalBytes32(postState.pendingTeeIdentityComposeHash, ZERO_BYTES32)
      || !equalAddress(postState.resultVerifier, ZERO_ADDRESS)
      || !equalAddress(postState.pendingResultVerifier, expected.resultVerifier)
      || !isSafeUint(
        postState.pendingResultVerifierActivatesAt,
        { positive: true },
      )
      || postState.pendingResultVerifierActivatesAt <= entry.blockTimestamp
      || postState.resultVerifierFrozen !== false
      || !equalBytes32(postState.evaluatorPolicySetRoot, ZERO_BYTES32)
      || postState.approvedEvaluatorPolicyCount !== 0
      || postState.pendingEvaluatorPolicyCount !== 3
      || postState.evaluatorPolicySetFrozen !== false
      || ![
        postState.pendingEvaluatorPolicy1ActivatesAt,
        postState.pendingEvaluatorPolicy2ActivatesAt,
        postState.pendingEvaluatorPolicy3ActivatesAt,
      ].every((value) => (
        isSafeUint(value, { positive: true })
        && value > entry.blockTimestamp
      ))
      || !equalAddress(postState.attestationVerifier, ZERO_ADDRESS)
      || !equalBytes32(postState.attestationReleasePolicyHash, ZERO_BYTES32)
      || !equalAddress(
        postState.pendingAttestationVerifier,
        expected.attestationVerifier,
      )
      || !equalBytes32(
        postState.pendingAttestationReleasePolicyHash,
        expected.attestationReleasePolicyHash,
      )
      || !isSafeUint(
        postState.pendingAttestationBindingActivatesAt,
        { positive: true },
      )
      || postState.pendingAttestationBindingActivatesAt
        <= entry.blockTimestamp
      || postState.attestationBindingFrozen !== false
      || postState.composeAdditionsFrozen !== false
      || postState.teeIdentityAdditionsFrozen !== false) {
      fail("phase_one_poststate_invalid");
    }
    return;
  }
  if (entry.phase === 2) {
    if (!equalAddress(postState.developer, expected.deploymentOperator)
      || !equalAddress(postState.pendingDeveloper, ZERO_ADDRESS)
      || postState.pendingDeveloperActivatesAt !== 0
      || postState.approvedComposeCount !== 1
      || postState.approvedTeeIdentityCount !== 0
      || postState.pendingComposeCount !== 0
      || postState.pendingTeeIdentityCount !== 1
      || postState.pendingComposeActivatesAt !== 0
      || !isSafeUint(
        postState.pendingTeeIdentityActivatesAt,
        { positive: true },
      )
      || postState.pendingTeeIdentityActivatesAt <= entry.blockTimestamp
      || !equalBytes32(postState.activeTeeIdentityComposeHash, ZERO_BYTES32)
      || !equalBytes32(
        postState.pendingTeeIdentityComposeHash,
        expected.composeHash,
      )
      || !equalAddress(postState.resultVerifier, expected.resultVerifier)
      || !equalAddress(postState.pendingResultVerifier, ZERO_ADDRESS)
      || postState.pendingResultVerifierActivatesAt !== 0
      || postState.resultVerifierFrozen !== true
      || !equalBytes32(postState.evaluatorPolicySetRoot, ZERO_BYTES32)
      || postState.approvedEvaluatorPolicyCount !== 3
      || postState.pendingEvaluatorPolicyCount !== 0
      || postState.evaluatorPolicySetFrozen !== false
      || postState.pendingEvaluatorPolicy1ActivatesAt !== 0
      || postState.pendingEvaluatorPolicy2ActivatesAt !== 0
      || postState.pendingEvaluatorPolicy3ActivatesAt !== 0
      || !equalAddress(
        postState.attestationVerifier,
        expected.attestationVerifier,
      )
      || !equalBytes32(
        postState.attestationReleasePolicyHash,
        expected.attestationReleasePolicyHash,
      )
      || !equalAddress(postState.pendingAttestationVerifier, ZERO_ADDRESS)
      || !equalBytes32(
        postState.pendingAttestationReleasePolicyHash,
        ZERO_BYTES32,
      )
      || postState.pendingAttestationBindingActivatesAt !== 0
      || postState.attestationBindingFrozen !== true
      || postState.composeAdditionsFrozen !== false
      || postState.teeIdentityAdditionsFrozen !== false) {
      fail("phase_two_poststate_invalid");
    }
    return;
  }
  if (!commonClosedPoststate(postState, expected)) {
    fail(entry.phase === 3
      ? "phase_three_poststate_invalid"
      : "phase_four_poststate_invalid");
  }
  if (entry.phase === 3) {
    if (!equalAddress(postState.developer, expected.deploymentOperator)
      || !equalAddress(
        postState.pendingDeveloper,
        expected.governanceController,
      )
      || postState.pendingDeveloperActivatesAt
        !== entry.blockTimestamp + 172_800) {
      fail("phase_three_governance_handoff_invalid");
    }
  } else if (!equalAddress(postState.developer, expected.governanceController)
    || !equalAddress(postState.pendingDeveloper, ZERO_ADDRESS)
    || postState.pendingDeveloperActivatesAt !== 0) {
    fail("phase_four_governance_handoff_invalid");
  }
}

function validatePhaseTiming(history) {
  const first = history[0].postState;
  const phaseOneDeadlines = [
    first.pendingComposeActivatesAt,
    first.pendingResultVerifierActivatesAt,
    first.pendingEvaluatorPolicy1ActivatesAt,
    first.pendingEvaluatorPolicy2ActivatesAt,
    first.pendingEvaluatorPolicy3ActivatesAt,
    first.pendingAttestationBindingActivatesAt,
  ];
  if (history[1].blockTimestamp < Math.max(...phaseOneDeadlines)
    || history[2].blockTimestamp
      < history[1].postState.pendingTeeIdentityActivatesAt
    || history[3].blockTimestamp
      < history[2].postState.pendingDeveloperActivatesAt) {
    fail("phase_timelock_order_invalid");
  }
  for (let index = 1; index < history.length; index += 1) {
    if (history[index].blockNumber < history[index - 1].blockNumber
      || history[index].blockTimestamp < history[index - 1].blockTimestamp
      || Date.parse(history[index].recordedAt)
        < Date.parse(history[index - 1].recordedAt)) {
      fail("phase_chronology_invalid");
    }
  }
}

function validateCurrentContractState(room, history, expected) {
  const phaseFour = history[3];
  const currentFields = [
    ["initialDeveloper", expected.deploymentOperator, equalAddress],
    ["releaseGovernanceController", expected.governanceController, equalAddress],
    ["protocolFeeRecipient", expected.governanceController, equalAddress],
    ["governanceController", expected.governanceController, equalAddress],
    ["developer", expected.governanceController, equalAddress],
    ["pendingDeveloper", ZERO_ADDRESS, equalAddress],
    ["latestReleaseTx", phaseFour.transactionHash, equalBytes32],
  ];
  if (!currentFields.every(([key, value, compare]) => compare(room[key], value))
    || room.pendingDeveloperActivatesAt !== 0
    || room.currentOperatorControlled !== false
    || room.latestReleasePhase !== 4
    || room.latestReleaseBlock !== phaseFour.blockNumber
    || room.latestReleaseRecordedAt !== phaseFour.recordedAt
    || room.latestReleaseSourceCommit !== expected.releaseSha
    || room.latestReleaseReviewEnvelopeSha256
      !== phaseFour.reviewEnvelopeSha256
    || room.latestReleaseFinalAuthoritySha256
      !== expected.finalAuthoritySha256
    || room.status !== DILIGENCE_RELEASE_PHASES[3].status
    || room.policyState !== DILIGENCE_RELEASE_PHASES[3].policyState
    || room.governanceHandoffStatus !== "accepted_complete"
    || room.governanceAcceptanceEvidenceMode
      !== phaseFour.governanceAcceptanceEvidenceMode
    || room.governanceAcceptanceEvidenceClaim
      !== phaseFour.governanceAcceptanceEvidenceClaim
    || room.governanceAcceptanceFinalizedThroughBlock
      !== phaseFour.governanceAcceptanceFinalizedThroughBlock
    || room.latestReleaseOperatorTransactionCount !== 0
    || room.latestReleaseOperatorTransactionsSha256 !== null) {
    fail("current_diligence_contract_state_invalid");
  }
}

function validateChainEvidence(chainEvidence, phaseFourBlock) {
  if (!chainEvidence
    || chainEvidence.valid !== true
    || chainEvidence.chainId !== 84_532
    || chainEvidence.secondaryChainId !== 84_532
    || chainEvidence.poststateMode !== "final_active_frozen"
    || chainEvidence.poststateValid !== true
    || chainEvidence.secondaryPoststateValid !== true
    || chainEvidence.poststateRpcAgreement !== true
    || chainEvidence.snapshotFinality !== "rpc_finalized"
    || chainEvidence.finalizedTagRechecked !== true
    || chainEvidence.secondaryFinalizedTagRechecked !== true
    || chainEvidence.snapshotBlockHashVerified !== true
    || !isSafeUint(chainEvidence.snapshotBlockNumber, { positive: true })
    || chainEvidence.snapshotBlockNumber < phaseFourBlock
    || !Array.isArray(chainEvidence.poststates)
    || !chainEvidence.poststates.some((entry) => (
      entry?.name === "DiligenceRoom"
      && entry.valid === true
      && Array.isArray(entry.assertions)
      && entry.assertions.includes("developer_matches_final_authority")
      && entry.assertions.includes("developer_transfer_complete_and_delayed")
      && entry.assertions.includes("constructor_bound_production_posture")
    ))) {
    fail("current_dual_rpc_diligence_state_invalid");
  }
}

export function validateCompletedDiligenceReleaseCeremony({
  ledger,
  ledgerFileSha256,
  replay,
  expected: rawExpected,
  reviewReceipts,
  chainEvidence,
}) {
  const expected = normalizeExpected(rawExpected);
  if (!isSha256(ledgerFileSha256, { nonzero: true })) {
    fail("ceremony_ledger_file_digest_invalid");
  }
  validateReplay(replay, expected, ledgerFileSha256);
  const reviewDigests = validateReviewReceipts(reviewReceipts, expected);
  if (!ledger || typeof ledger !== "object" || Array.isArray(ledger)) {
    fail("ceremony_ledger_invalid");
  }
  const room = ledger.contracts?.diligenceRoom;
  const suite = ledger.freshDeployment?.contractSuite;
  const broadcast = suite?.broadcastTransactions;
  const deploymentTx = room?.deploymentTx;
  if (ledger.network?.chainId !== expected.chainId
    || suite?.sourceCommit !== expected.releaseSha
    || suite?.deploymentIntentSha256 !== expected.deploymentIntentSha256
    || room?.sourceCommit !== expected.releaseSha
    || !equalAddress(room?.address, expected.diligenceRoomAddress)
    || !equalBytes32(room?.runtimeCodeHash, expected.runtimeCodeHash)
    || !isBytes32(deploymentTx, { nonzero: true })
    || !Array.isArray(broadcast)
    || broadcast.length < 1) {
    fail("ceremony_ledger_release_lineage_invalid");
  }
  const deployment = broadcast[0];
  if (deployment.sequence !== 0
    || deployment.contractKey !== "diligenceRoom"
    || deployment.contractName !== "DiligenceRoom"
    || deployment.transactionType !== "CREATE"
    || deployment.functionSignature !== "constructor(bool,address)"
    || !equalBytes32(deployment.transactionHash, deploymentTx)
    || !equalAddress(deployment.transactionFrom, expected.deploymentOperator)
    || !equalAddress(
      deployment.receiptContractAddress,
      expected.diligenceRoomAddress,
    )
    || deployment.receiptStatus !== "success") {
    fail("diligence_deployment_transaction_lineage_invalid");
  }

  const history = ledger.diligenceReleaseHistory;
  if (!Array.isArray(history) || history.length !== 4) {
    fail("completed_four_phase_history_required");
  }
  const allTxHashes = new Set([lower(deploymentTx)]);
  history.forEach((entry, index) => {
    const phase = DILIGENCE_RELEASE_PHASES[index];
    exactObject(
      entry,
      DILIGENCE_RELEASE_HISTORY_ENTRY_FIELDS,
      "diligence_release_history_schema_invalid",
    );
    if (entry.phase !== phase.phase
      || entry.status !== phase.status
      || entry.policyState !== phase.policyState
      || entry.reviewEnvelopeSha256 !== reviewDigests[index]
      || !validateSharedEntry(entry, expected, deploymentTx)
      || !isBytes32(entry.transactionHash, { nonzero: true })
      || !isSafeUint(entry.blockNumber, { positive: true })
      || !isSafeUint(entry.blockTimestamp, { positive: true })
      || !isCanonicalUtcSecond(entry.recordedAt)
      || Date.parse(entry.recordedAt) < entry.blockTimestamp * 1_000) {
      fail("diligence_release_phase_invalid");
    }
    if (index < 3) {
      if (entry.governanceAcceptanceEvidenceMode !== "not_applicable"
        || entry.governanceAcceptanceEvidenceClaim !== OPERATOR_TX_CLAIM
        || entry.governanceAcceptanceFinalizedThroughBlock !== 0) {
        fail("operator_phase_evidence_mode_invalid");
      }
    } else {
      const claim = PHASE_FOUR_CLAIMS[
        entry.governanceAcceptanceEvidenceMode
      ];
      if (!claim
        || entry.governanceAcceptanceEvidenceClaim !== claim
        || !isSafeUint(
          entry.governanceAcceptanceFinalizedThroughBlock,
          { positive: true },
        )
        || entry.governanceAcceptanceFinalizedThroughBlock
          < entry.blockNumber) {
        fail("external_governance_acceptance_evidence_invalid");
      }
    }
    validateOperatorTransactions(entry, phase, expected, allTxHashes);
    if (allTxHashes.has(lower(entry.transactionHash))
      && phase.functions.length === 0) {
      fail("release_transaction_hash_reused");
    }
    allTxHashes.add(lower(entry.transactionHash));
    validatePoststate(entry, expected);
  });
  validatePhaseTiming(history);
  validateCurrentContractState(room, history, expected);
  validateChainEvidence(chainEvidence, history[3].blockNumber);

  const gate = Object.freeze({
    schema: DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA,
    status: DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS,
    truthStatus: DILIGENCE_RELEASE_ACTIVATION_GATE_TRUTH_STATUS,
    valid: true,
    releaseSha: expected.releaseSha,
    chainId: expected.chainId,
    diligenceRoomAddress: expected.diligenceRoomAddress,
    governanceController: expected.governanceController,
    currentLedgerSha256: replay.current_ledger_sha256,
    revisionChainSha256: replay.revision_chain_sha256,
    finalizationReceiptSha256: replay.finalization_receipt_sha256,
    phaseCount: 4,
    reviewEnvelopeCount: 4,
    distinctReviewEnvelopeCount: 4,
    operatorTransactionCount: 13,
    governanceAcceptanceMode:
      history[3].governanceAcceptanceEvidenceMode,
    governanceAcceptanceClaim:
      history[3].governanceAcceptanceEvidenceClaim,
    governanceAcceptanceTransactionHash:
      lower(history[3].transactionHash),
    finalizedThroughBlock:
      history[3].governanceAcceptanceFinalizedThroughBlock,
  });
  COMPLETED_DILIGENCE_RELEASE_GATES.add(gate);
  return gate;
}

export function inspectCompletedDiligenceReleaseCeremony(input) {
  try {
    return validateCompletedDiligenceReleaseCeremony(input);
  } catch (error) {
    return Object.freeze({
      schema: DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA,
      status: "rejected",
      truthStatus: "no_live_activation_authority_created",
      valid: false,
      reason: error instanceof GateError
        ? error.code
        : "unexpected_diligence_release_gate_failure",
    });
  }
}

export function assertLocallyVerifiedCompletedDiligenceReleaseGate(value) {
  if (!value || !COMPLETED_DILIGENCE_RELEASE_GATES.has(value)
    || value.valid !== true
    || value.schema !== DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA
    || value.status !== DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS
    || value.truthStatus
      !== DILIGENCE_RELEASE_ACTIVATION_GATE_TRUTH_STATUS) {
    throw new TypeError(
      "a locally replayed completed Diligence release gate is required",
    );
  }
  return value;
}
