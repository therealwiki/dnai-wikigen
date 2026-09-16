import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  ACTIVATION_READINESS_SNAPSHOT_DOMAIN,
  BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS,
  CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE,
  CVM_TOPOLOGY_DOMAINS,
  CVM_TOPOLOGY_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS,
  PREFLIGHT_EXACT_CHECK_COUNT,
  PREFLIGHT_ROOT_CAUSE_PROJECTION_SCHEMA,
  PREFLIGHT_SCHEMA,
  PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
  activationReadinessAnchorWriterGasObservationDigest,
  activationReadinessRpcEndpointDigest,
  activationReadinessRpcOriginDigest,
  activationReadinessSnapshotDigest,
  buildPreflightReport,
  createActivationReadinessSnapshot,
  normalizeActivationReadinessSnapshot,
  projectPreflightRootCauses,
} from "./activation-preflight-core.mjs";
import {
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  CVM_LAUNCH_DOMAINS,
  CVM_TOPOLOGY_SCHEMA as CVM_LAUNCH_TOPOLOGY_SCHEMA,
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  freshContractDeploymentReceiptDigest,
  projectFreshContractDeploymentReceipt,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";
import {
  EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY,
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
} from "./execution-policy-release-core.mjs";
import {
  DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA,
  DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS,
  DILIGENCE_RELEASE_ACTIVATION_GATE_TRUTH_STATUS,
} from "./diligence-release-activation-gate.mjs";
import {
  PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES,
} from "./phala-production-execution-policy.mjs";

const RELEASE_SHA = "1".repeat(40);
const INTENT_SHA256 = `sha256:${"2".repeat(64)}`;
const REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 = `sha256:${"6".repeat(64)}`;
const REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256 = `sha256:${"61".repeat(32)}`;
const TINKER_ACCOUNT_BINDING_COMMITMENT = `0x${"62".repeat(32)}`;
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256 =
  `sha256:${"63".repeat(32)}`;
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_FILE_SHA256 =
  "65".repeat(32);
const TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_SHA256 =
  `sha256:${"64".repeat(32)}`;
const FINAL_AUTHORITY_SHA256 = `sha256:${"3".repeat(64)}`;
const ANCHOR_WRITER_ADDRESS = "0x000000000000000000000000000000000000000e";
const CEREMONY_AUTHORIZATION_SHA256 = `sha256:${"a".repeat(64)}`;
const LIVE_ACTIVATION_AUTHORITY_SHA256 = `sha256:${"b".repeat(64)}`;
const RELEASE_INPUTS_SHA256 = `sha256:${"c".repeat(64)}`;
const RELEASE_ENV_SHA256 = `sha256:${"d".repeat(64)}`;
const FRONTEND_BUILD_SHA256 = `sha256:${"e".repeat(64)}`;
const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256 =
  `sha256:${"f1".repeat(32)}`;
const COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256 = `sha256:${"f2".repeat(32)}`;
const FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256 = `sha256:${"f3".repeat(32)}`;
const ROYALTY_RELEASE_HISTORY_SHA256 = `sha256:${"f4".repeat(32)}`;
const ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256 = `sha256:${"f5".repeat(32)}`;
const REVIEW_ENVELOPE_SHA256 = `sha256:${"4".repeat(64)}`;
const REVIEW_EVIDENCE_SHA256 = `sha256:${"5".repeat(64)}`;
const CVM_LAUNCH_INTENT_SHA256 = `sha256:${"7".repeat(64)}`;
const CVM_REVIEW_ENVELOPE_SHA256 = `sha256:${"8".repeat(64)}`;
const CVM_REVIEW_EVIDENCE_SHA256 = `sha256:${"9".repeat(64)}`;
const IMAGE_RELEASE_FILE_SHA256 = "b".repeat(64);
const IMAGE_BUNDLE_FILE_SHA256 = "c".repeat(64);
const TOPOLOGY_FILE_SHA256 = "d".repeat(64);
const CHECKED_AT_MS = Date.parse("2026-07-21T12:00:00Z");
const OPERATOR_ADDRESS = `0x${"a1".repeat(20)}`;
const RPC_ENDPOINT_SHA256 = activationReadinessRpcEndpointDigest(
  "https://base-sepolia.invalid/read-only-test",
);
const SECONDARY_RPC_ENDPOINT_SHA256 = activationReadinessRpcEndpointDigest(
  "https://secondary-base-sepolia.invalid/read-only-test",
);
const RPC_ORIGIN_SHA256 = activationReadinessRpcOriginDigest(
  "https://base-sepolia.invalid",
);
const SECONDARY_RPC_ORIGIN_SHA256 = activationReadinessRpcOriginDigest(
  "https://secondary-base-sepolia.invalid",
);

function diligenceReleaseCeremonyFixture() {
  return {
    schema: DILIGENCE_RELEASE_ACTIVATION_GATE_SCHEMA,
    status: DILIGENCE_RELEASE_ACTIVATION_GATE_STATUS,
    truthStatus: DILIGENCE_RELEASE_ACTIVATION_GATE_TRUTH_STATUS,
    valid: true,
    releaseSha: RELEASE_SHA,
    chainId: 84_532,
    diligenceRoomAddress: `0x${"71".repeat(20)}`,
    governanceController: `0x${"72".repeat(20)}`,
    currentLedgerSha256: `sha256:${"73".repeat(32)}`,
    revisionChainSha256: `sha256:${"74".repeat(32)}`,
    finalizationReceiptSha256: `sha256:${"75".repeat(32)}`,
    phaseCount: 4,
    reviewEnvelopeCount: 4,
    distinctReviewEnvelopeCount: 4,
    operatorTransactionCount: 13,
    governanceAcceptanceMode: "eoa_direct_call",
    governanceAcceptanceClaim:
      "finalized_direct_eoa_call_event_and_state",
    governanceAcceptanceTransactionHash: `0x${"76".repeat(32)}`,
    finalizedThroughBlock: 2_000,
  };
}

const DESCRIPTOR_SHA256_BY_DOMAIN = Object.freeze(Object.fromEntries(
  CVM_TOPOLOGY_DOMAINS.map((domain, index) => [
    domain,
    `sha256:${String(index + 1).repeat(64)}`,
  ]),
));

function authorityChecks(report) {
  return Object.fromEntries(
    report.checks
      .filter((item) => item.id.startsWith("authority."))
      .map((item) => [item.id, item]),
  );
}

function contractLedgerFixture() {
  const bytes32 = (value) => `0x${value.toString(16).padStart(64, "0")}`;
  const sha256 = (value) => `sha256:${value.toString(16).padStart(64, "0")}`;
  const sortedObject = (value) => {
    if (Array.isArray(value)) return value.map((item) => sortedObject(item));
    if (!value || typeof value !== "object") return value;
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
    );
  };
  const contracts = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key }, index) => {
      const address = `0x${String(index + 1).repeat(40)}`;
      return [ledger_key, {
        sourceCommit: RELEASE_SHA,
        address,
        runtimeCodeHash: `0x${String(index + 1).repeat(64)}`,
        deploymentTx: bytes32(100 + index),
        deploymentBlock: 1_000 + index,
        deploymentBlockHash: bytes32(200 + index),
        deploymentReceiptStatus: "success",
        deploymentTxFrom: OPERATOR_ADDRESS,
        deploymentReceiptContractAddress: address,
      }];
    }),
  );
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: OPERATOR_ADDRESS,
    registryPaused: false,
    challengeCount: 0,
    nextChallengeId: 1,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32: `0x${INTENT_SHA256.slice("sha256:".length)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
    authorityCommitmentReadProof: FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock: contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash:
      contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcastTransactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
    (spec, sequence) => {
      const contract = contracts[spec.contract_key];
      const create = spec.transaction_type === "CREATE";
      const transactionInputSha256 = sha256(300 + sequence);
      if (create) contract.creationInputSha256 = transactionInputSha256;
      return {
        sequence,
        contractKey: spec.contract_key,
        contractName: spec.name,
        transactionType: spec.transaction_type,
        functionSignature: spec.function_signature,
        transactionHash: create ? contract.deploymentTx : bytes32(400 + sequence),
        transactionFrom: OPERATOR_ADDRESS,
        transactionTo: create ? null : contract.address,
        transactionNonce: 500 + sequence,
        transactionInputSha256,
        receiptStatus: "success",
        receiptContractAddress: create ? contract.address : null,
        blockNumber: create ? contract.deploymentBlock : 2_000 + sequence,
        blockHash: create ? contract.deploymentBlockHash : bytes32(600 + sequence),
      };
    },
  );
  const normalizedBroadcastTransactions = broadcastTransactions.map((entry) => ({
    sequence: entry.sequence,
    contract_key: entry.contractKey,
    contract_name: entry.contractName,
    transaction_type: entry.transactionType,
    function_signature: entry.functionSignature,
    transaction_hash: entry.transactionHash,
    transaction_from: entry.transactionFrom,
    transaction_to: entry.transactionTo,
    transaction_nonce: entry.transactionNonce,
    transaction_input_sha256: entry.transactionInputSha256,
    receipt_status: entry.receiptStatus,
    receipt_contract_address: entry.receiptContractAddress,
    block_number: entry.blockNumber,
    block_hash: entry.blockHash,
  }));
  const broadcastTransactionsSha256 = rawSha256(Buffer.from(
    JSON.stringify(sortedObject(normalizedBroadcastTransactions)),
    "utf8",
  ));
  return {
    schemaVersion: 2,
    status: "fresh_contract_suite_deployed_pending_cvm_binding",
    network: {
      chainId: 84_532,
      explorerBaseUrl: "https://sepolia.basescan.org",
      name: "Base Sepolia",
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
    },
    currentOperatorDeployer: {
      address: OPERATOR_ADDRESS,
      keystoreAccount: "dev",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        sourceCommit: RELEASE_SHA,
        deploymentIntentSha256: INTENT_SHA256,
        reviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
        tinkerAccountBindingCeremonyReceiptSha256:
          TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
        keystoreAccount: "dev",
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        exactCreationInputProof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
        broadcastTransactionProof: FRESH_CONTRACT_BROADCAST_PROOF,
        broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
        broadcastTransactionsSha256,
        broadcastTransactions,
      },
    },
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: RELEASE_SHA,
      deploymentIntentSha256: INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      tinkerAccountBindingCeremonyReceiptSha256:
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
      broadcastTransactionsSha256,
    }],
    contracts,
  };
}

function contractDeploymentReceiptSha256(ledger) {
  const authorityPins = {
    expectedDeploymentIntentSha256: INTENT_SHA256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  };
  const receipt = projectFreshContractDeploymentReceipt(ledger, {
    releaseSha: RELEASE_SHA,
    ...authorityPins,
  });
  return `sha256:${freshContractDeploymentReceiptDigest(receipt, authorityPins)}`;
}

function anchorWriterGasReadiness({
  blockNumber = 2_000,
  blockHash = `0x${"ab".repeat(32)}`,
  balanceWei = EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY.minimum_reserve_wei,
} = {}) {
  const observationSha256 = activationReadinessAnchorWriterGasObservationDigest({
    rpc_method: "eth_getBalance",
    writer_address: ANCHOR_WRITER_ADDRESS,
    balance_wei: balanceWei,
    block_number: blockNumber,
    block_hash: blockHash,
  });
  return {
    schema: "dnai.activation-readiness-anchor-writer-gas.v1",
    rpc_method: "eth_getBalance",
    writer_address: ANCHOR_WRITER_ADDRESS,
    primary_balance_wei: balanceWei,
    secondary_balance_wei: balanceWei,
    canonical_balance_wei: balanceWei,
    minimum_reserve_wei:
      EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY.minimum_reserve_wei,
    release_marker_transaction_count: 1,
    expected_subsequent_anchor_count: 32,
    maximum_gas_per_transaction: 500_000,
    reviewed_max_fee_per_gas_wei: "2000000000",
    balance_block_number: blockNumber,
    balance_block_hash: blockHash,
    primary_observation_sha256: observationSha256,
    secondary_observation_sha256: observationSha256,
    dual_rpc_agreement: true,
    reserve_satisfied: true,
    readiness_claim:
      "bounded_reserve_for_one_release_marker_and_32_subsequent_anchors_not_indefinite_funding",
  };
}

function contractDeploymentChainEvidence({
  poststateMode = "final_active_frozen",
  includeAnchorWriterGas = true,
} = {}) {
  const contractCount = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.length;
  const immutableProvenance = CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ name }) => ({
    name,
    ...Object.fromEntries(
      CONTRACT_CHAIN_PROVENANCE_BOOLEAN_FIELDS.map((field) => [field, true]),
    ),
  }));
  const poststates = Object.entries(
    CONTRACT_POSTSTATE_ASSERTIONS_BY_MODE[poststateMode],
  ).map(([name, assertions]) => ({ name, valid: true, assertions: [...assertions] }));
  const receipt = projectFreshContractDeploymentReceipt(contractLedgerFixture(), {
    releaseSha: RELEASE_SHA,
    expectedDeploymentIntentSha256: INTENT_SHA256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    expectedTinkerAccountBindingCeremonyReceiptSha256:
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  });
  const broadcastTransactionProvenance = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
    (entry, sequence) => ({
      sequence,
      contractKey: entry.contract_key,
      transactionType: entry.transaction_type,
      ...Object.fromEntries(
        BROADCAST_TRANSACTION_PROVENANCE_BOOLEAN_FIELDS.map(
          (field) => [field, true],
        ),
      ),
    }),
  );
  return {
    evidenceSource: "production_collector",
    valid: true,
    readOnly: true,
    chainId: 84_532,
    secondaryChainId: 84_532,
    rpcEndpointSha256: RPC_ENDPOINT_SHA256,
    secondaryRpcEndpointSha256: SECONDARY_RPC_ENDPOINT_SHA256,
    rpcOriginSha256: RPC_ORIGIN_SHA256,
    secondaryRpcOriginSha256: SECONDARY_RPC_ORIGIN_SHA256,
    rpcEndpointsDistinct: true,
    secondaryFinalizedSnapshotVerified: true,
    secondaryFinalizedTagRechecked: true,
    snapshotBlockNumber: 2_000,
    snapshotBlockHash: `0x${"ab".repeat(32)}`,
    snapshotFinality: "rpc_finalized",
    finalizedTagRechecked: true,
    finalizedRecheckBlockNumber: 2_000,
    finalizedRecheckBlockHash: `0x${"ab".repeat(32)}`,
    snapshotBlockHashVerified: true,
    commonSnapshotBlock: true,
    anchorWriterGasReadiness: includeAnchorWriterGas
      ? anchorWriterGasReadiness()
      : null,
    contractCount,
    transactionCount: contractCount,
    deployerMatchCount: contractCount,
    creationTransactionCount: contractCount,
    receiptCount: contractCount,
    successfulReceiptCount: contractCount,
    contractAddressMatchCount: contractCount,
    deploymentBlockMatchCount: contractCount,
    deploymentBlockHashMatchCount: contractCount,
    runtimeCodeMatchCount: contractCount,
    immutableProvenanceContractCount: contractCount,
    immutableProvenanceValid: true,
    immutableProvenance,
    broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcastTransactionValidCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
    broadcastTransactionsSha256: receipt.broadcast_transactions_sha256,
    broadcastTransactionProvenanceValid: true,
    broadcastTransactionProvenance,
    primaryBroadcastTransactionObservationsSha256: `sha256:${"e".repeat(64)}`,
    secondaryBroadcastTransactionObservationsSha256: `sha256:${"e".repeat(64)}`,
    broadcastTransactionRpcAgreement: true,
    independentReconstructionValid: true,
    independentReconstructionSha256: `sha256:${"6".repeat(64)}`,
    independentReconstructionRpcAgreement: true,
    secondaryRuntimeCodeMatchCount: contractCount,
    poststateMode,
    poststateContractCount: 7,
    poststateValid: true,
    poststates,
    primaryPoststateObservationsSha256: `sha256:${"f".repeat(64)}`,
    secondaryPoststateContractCount: 7,
    secondaryPoststateValid: true,
    secondaryPoststateObservationsSha256: `sha256:${"f".repeat(64)}`,
    poststateRpcAgreement: true,
  };
}

function attachActivationReadinessSnapshot(snapshot) {
  const stage = snapshot.authorityStage;
  if (stage === "fresh_deployment") {
    delete snapshot.activationReadinessSnapshot;
    delete snapshot.activationReadinessSnapshotSha256;
    delete snapshot.activationReadinessValidationNowMs;
    return snapshot;
  }
  const value = createActivationReadinessSnapshot({
    stage,
    releaseSha: RELEASE_SHA,
    rpcEndpointSha256: snapshot.contractDeploymentChainEvidence.rpcEndpointSha256,
    deploymentIntentSha256: INTENT_SHA256,
    contractDeploymentReceiptSha256:
      snapshot.cvmLaunchAuthority.contractDeploymentReceiptSha256,
    cvmLaunchIntentSha256: CVM_LAUNCH_INTENT_SHA256,
    finalAuthoritySha256: stage === "cvm_launch" ? null : FINAL_AUTHORITY_SHA256,
    chainEvidence: snapshot.contractDeploymentChainEvidence,
    descriptorSha256ByDomain: snapshot.cvmLaunchAuthority.descriptorSha256ByDomain,
    checkedAt: "2026-07-21T12:00:00Z",
    expiresAt: "2026-07-21T12:02:00Z",
  });
  snapshot.activationReadinessSnapshot = value;
  snapshot.activationReadinessSnapshotSha256 =
    `sha256:${activationReadinessSnapshotDigest(value)}`;
  snapshot.activationReadinessValidationNowMs = CHECKED_AT_MS;
  return snapshot;
}

function rehashActivationReadinessSnapshot(snapshot) {
  snapshot.activationReadinessSnapshotSha256 =
    `sha256:${activationReadinessSnapshotDigest(snapshot.activationReadinessSnapshot)}`;
  return snapshot;
}

function liveSnapshot() {
  const ledger = contractLedgerFixture();
  const deploymentReceiptSha256 = contractDeploymentReceiptSha256(ledger);
  const topologyDomains = Object.fromEntries(
    Object.entries(DESCRIPTOR_SHA256_BY_DOMAIN).map(([domain, digest]) => [
      domain,
      { sha256: digest.slice("sha256:".length) },
    ]),
  );
  return attachActivationReadinessSnapshot({
    authorityStage: "live_activation",
    diligenceReleaseCeremony: diligenceReleaseCeremonyFixture(),
    env: {
      RELEASE_SHA,
      TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT:
        TINKER_ACCOUNT_BINDING_COMMITMENT,
    },
    git: { head: RELEASE_SHA, dirty: false },
    files: {
      releaseCandidate: {
        valid: true,
        value: {
          schema: "dnai.web-release.v4",
          deployment_intent_sha256: INTENT_SHA256,
          cvm_launch_intent_sha256: CVM_LAUNCH_INTENT_SHA256,
          operator_policy: {
            schema: LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
            ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
            live_activation_authority_sha256:
              LIVE_ACTIVATION_AUTHORITY_SHA256,
            runtime_authority_dependency_sha256: FINAL_AUTHORITY_SHA256,
          },
        },
      },
      releaseCore: {
        valid: true,
        value: {
          schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
          deployment_intent_sha256: INTENT_SHA256,
          cvm_launch_intent_sha256: CVM_LAUNCH_INTENT_SHA256,
          execution_policy: {
            rollback_anchor_target: {
              writer_address: ANCHOR_WRITER_ADDRESS,
              writer_gas_reserve_policy:
                EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY,
            },
          },
        },
      },
      ledger: {
        valid: true,
        value: ledger,
      },
      imageRelease: {
        valid: true,
        sha256: IMAGE_RELEASE_FILE_SHA256,
      },
      imageReleaseAttestationBundle: {
        valid: true,
        sha256: IMAGE_BUNDLE_FILE_SHA256,
      },
      topology: {
        valid: true,
        sha256: TOPOLOGY_FILE_SHA256,
      },
      tinkerAccountBindingCeremonyReceipt: {
        valid: true,
        sha256: TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_FILE_SHA256,
      },
    },
    releaseAuthority: {
      deploymentIntentValid: true,
      deploymentIntentFileHashBound: true,
      deploymentIntentFreshChallengeStateValid: true,
      deploymentIntentSha256: INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      reviewerAuthorityCurrentStatusEpoch: 1,
      reviewerAuthorityCurrentStatusSha256:
        REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256,
      tinkerAccountBindingCeremony: {
        accountCommitment: TINKER_ACCOUNT_BINDING_COMMITMENT,
        deploymentIntentSha256: INTENT_SHA256,
        historicalReplay: true,
        persistedCeremonyReceiptSha256:
          TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
        replayCeremonyReceiptSha256:
          TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_SHA256,
        reviewerAuthorityCurrentStatusSha256:
          REVIEWER_AUTHORITY_CURRENT_STATUS_SHA256,
        reviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
        truthStatus:
          "historical_signature_replay_proves_the_signed_declared_ceremony_timestamp_was_inside_the_authenticated_status_window_not_that_the_status_is_current_now_or_that_wall_clock_signing_time_was_independently_observed",
        valid: true,
        verificationMode: "authenticated_historical_two_reviewer_replay",
      },
      releaseSha: RELEASE_SHA,
      gitObjectIsCommit: true,
      commitTime: Math.floor(Date.parse("2026-07-20T00:00:00Z") / 1_000),
      deploymentIntentEnvironmentProjection: {
        ok: true,
        checkedKeys: ["RELEASE_SHA", "EMAIL_ORACLE_UPGRADE_DELAY"],
        mismatchKeys: [],
      },
      finalAuthorityValid: true,
      finalAuthorityFileHashBound: true,
      finalAuthoritySha256: FINAL_AUTHORITY_SHA256,
      finalAuthorityDeploymentIntentSha256: INTENT_SHA256,
      finalAuthorityCvmLaunchIntentSha256: CVM_LAUNCH_INTENT_SHA256,
      finalAuthorityCollaborationRequested: false,
      finalAuthorityCollaborationEnvironmentValue: "false",
      reviewEnvelopeValid: true,
      reviewEnvelopeFileHashBound: true,
      reviewEnvelopeSha256: REVIEW_ENVELOPE_SHA256,
      reviewSubjectKind: "final_release_authority",
      reviewSubjectSha256: FINAL_AUTHORITY_SHA256,
      reviewEvidenceValid: true,
      reviewEvidenceFileHashBound: true,
      reviewEvidenceSha256: REVIEW_EVIDENCE_SHA256,
      approvedAt: "2026-07-21T00:00:00Z",
      expiresAt: "2026-07-25T00:00:00Z",
      checkedAtMs: CHECKED_AT_MS,
    },
    cvmLaunchAuthority: {
      valid: true,
      fileHashBound: true,
      sha256: CVM_LAUNCH_INTENT_SHA256,
      deploymentIntentSha256: INTENT_SHA256,
      releaseSha: RELEASE_SHA,
      reviewEnvelopeValid: true,
      reviewEnvelopeFileHashBound: true,
      reviewEnvelopeSha256: CVM_REVIEW_ENVELOPE_SHA256,
      reviewSubjectKind: "cvm_launch_intent",
      reviewSubjectSha256: CVM_LAUNCH_INTENT_SHA256,
      reviewEvidenceValid: true,
      reviewEvidenceFileHashBound: true,
      reviewEvidenceSha256: CVM_REVIEW_EVIDENCE_SHA256,
      approvedAt: "2026-07-21T00:00:00Z",
      expiresAt: "2026-07-25T00:00:00Z",
      checkedAtMs: CHECKED_AT_MS,
      contractDeploymentReceiptValid: true,
      contractDeploymentReceiptSha256: deploymentReceiptSha256,
      contractDeploymentContractCount: 7,
      imageReleaseManifestSha256: `sha256:${IMAGE_RELEASE_FILE_SHA256}`,
      imageAttestationBundleSha256: `sha256:${IMAGE_BUNDLE_FILE_SHA256}`,
      topologySha256: `sha256:${TOPOLOGY_FILE_SHA256}`,
      descriptorSha256ByDomain: { ...DESCRIPTOR_SHA256_BY_DOMAIN },
      artifactBindingsValid: true,
      imageReleaseValid: true,
      imageCount: 5,
      topologyValid: true,
      descriptorCount: 7,
      descriptorHashesDistinct: true,
      productionPostureValid: true,
      collaborationGatePolicyValid: true,
      collaborationGateBootstrapDefault: "false",
    },
    imageRelease: {
      valid: true,
      images: Array.from({ length: 5 }, (_, index) => `image-${index}`),
    },
    topology: {
      valid: true,
      tinkerAccountBindingCeremonyReceipt: {
        file: "tinker-account-binding-ceremony.receipt.json",
        sha256: TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_FILE_SHA256,
        schema: "dnai.tinker-account-binding-ceremony-receipt.v1",
        tinkerAccountBindingCeremonyReceiptSha256:
          TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
        validation:
          "python_structural_and_domain_digest_binding_requires_node_ceremony_check_replay",
      },
      domains: topologyDomains,
    },
    contractDeploymentChainEvidence: contractDeploymentChainEvidence(),
    semanticEvidenceValidated: true,
    semanticEvidenceReason: "canonical_semantic_validator_authenticated_release",
    semanticValidationReceipt: {
      schema: SEMANTIC_VALIDATION_SCHEMA,
      status: SEMANTIC_VALIDATION_STATUS,
      truth_status: SEMANTIC_VALIDATION_TRUTH_STATUS,
      release_sha: RELEASE_SHA,
      chain_id: 84_532,
      deployment_intent_sha256: INTENT_SHA256,
      reviewer_authority_genesis_acceptance_sha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
      live_activation_authority_sha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
      runtime_authority_dependency_sha256: FINAL_AUTHORITY_SHA256,
      compute_workload_activation_observation_sha256:
        COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
      compute_workload_browser_binding_sha256:
        COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
      frontend_build_candidate_receipt_sha256:
        FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
      royalty_release_history_sha256: ROYALTY_RELEASE_HISTORY_SHA256,
      royalty_release_history_receipt_sha256:
        ROYALTY_RELEASE_HISTORY_RECEIPT_SHA256,
      release_inputs_sha256: RELEASE_INPUTS_SHA256,
      release_env_sha256: RELEASE_ENV_SHA256,
      frontend_build_sha256: FRONTEND_BUILD_SHA256,
      raw_secret_egress: false,
    },
  });
}

function freshSnapshot() {
  const snapshot = liveSnapshot();
  snapshot.authorityStage = "fresh_deployment";
  snapshot.files = {};
  Object.assign(snapshot.releaseAuthority, {
    finalAuthorityValid: false,
    finalAuthorityFileHashBound: false,
    finalAuthoritySha256: "",
    finalAuthorityDeploymentIntentSha256: "",
    finalAuthorityCvmLaunchIntentSha256: "",
    finalAuthorityCollaborationRequested: null,
    finalAuthorityCollaborationEnvironmentValue: null,
    reviewSubjectKind: "deployment_intent",
    reviewSubjectSha256: INTENT_SHA256,
    tinkerAccountBindingCeremony: {
      ...snapshot.releaseAuthority.tinkerAccountBindingCeremony,
      historicalReplay: false,
      replayCeremonyReceiptSha256:
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
      truthStatus:
        "opaque_attested_account_binding_handle_not_provider_identifier_proof_requires_later_measured_provider_binding",
      verificationMode: "fresh_current_two_reviewer_ceremony",
    },
  });
  snapshot.cvmLaunchAuthority = {};
  snapshot.imageRelease = undefined;
  snapshot.topology = undefined;
  delete snapshot.contractDeploymentChainEvidence;
  attachActivationReadinessSnapshot(snapshot);
  snapshot.semanticEvidenceValidated = false;
  snapshot.semanticValidationReceipt = null;
  return snapshot;
}

function cvmLaunchSnapshot() {
  const snapshot = liveSnapshot();
  snapshot.authorityStage = "cvm_launch";
  delete snapshot.files.releaseCandidate;
  delete snapshot.files.releaseCore;
  Object.assign(snapshot.releaseAuthority, {
    finalAuthorityValid: false,
    finalAuthorityFileHashBound: false,
    finalAuthoritySha256: "",
    finalAuthorityDeploymentIntentSha256: "",
    finalAuthorityCvmLaunchIntentSha256: "",
    finalAuthorityCollaborationRequested: null,
    finalAuthorityCollaborationEnvironmentValue: null,
  });
  snapshot.semanticEvidenceValidated = false;
  snapshot.semanticValidationReceipt = null;
  snapshot.contractDeploymentChainEvidence = contractDeploymentChainEvidence({
    poststateMode: "fresh_fail_closed",
    includeAnchorWriterGas: false,
  });
  return attachActivationReadinessSnapshot(snapshot);
}

function releaseCeremonySnapshot() {
  const snapshot = liveSnapshot();
  snapshot.authorityStage = "release_ceremony";
  snapshot.files.releaseCandidate.value.operator_policy = {
    schema: PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
    ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
    runtime_authority_dependency_sha256: FINAL_AUTHORITY_SHA256,
  };
  snapshot.contractDeploymentChainEvidence = contractDeploymentChainEvidence({
    poststateMode: "fresh_fail_closed",
  });
  snapshot.semanticEvidenceValidated = false;
  snapshot.semanticValidationReceipt = null;
  return attachActivationReadinessSnapshot(snapshot);
}

test("live activation requires one exact staged authority chain and signed-live receipt", () => {
  const report = buildPreflightReport(liveSnapshot());
  const checks = authorityChecks(report);
  assert.deepEqual(
    Object.keys(checks),
    [
      "authority.stage",
      "authority.deployment_intent",
      "authority.deployment_intent_source",
      "authority.deployment_intent_environment_projection",
      "authority.cvm_launch_intent",
      "authority.cvm_execution_boundary_availability",
      "authority.final_release_authority",
      "authority.diligence_release_ceremony",
      "authority.current_stage_signature",
      "authority.current_stage_evidence",
      "authority.contract_deployment_chain_evidence",
      "authority.release_artifact_binding",
    ],
  );
  assert.equal(
    checks["authority.cvm_execution_boundary_availability"].status,
    "pass",
  );
  assert.equal(report.verdict, "BLOCKED");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.status,
    "pass",
  );
  const rawCheckCount = Object.values(report.summary).reduce((total, count) => total + count, 0);
  assert.equal(rawCheckCount, PREFLIGHT_EXACT_CHECK_COUNT);
  assert.equal(report.checks.length, rawCheckCount);
  assert.equal(report.checks.at(-1)?.id, "image.provenance_sbom");
});

test("fresh deployment proves reviewed intent only and does not require final authority", () => {
  const report = buildPreflightReport(freshSnapshot());
  const checks = authorityChecks(report);
  assert.equal(checks["authority.deployment_intent"].status, "pass");
  assert.equal(checks["authority.final_release_authority"].status, "pass");
  assert.match(
    checks["authority.final_release_authority"].message,
    /not accepted or required at the fresh-deployment stage/,
  );
  assert.equal(checks["authority.current_stage_signature"].status, "pass");
  assert.equal(
    checks["authority.cvm_execution_boundary_availability"].status,
    "pass",
  );
  assert.equal(checks["authority.release_artifact_binding"].status, "pass");
  assert.equal(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.status,
    "pass",
  );
  assert.match(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.message,
    /not accepted or required before measured CVM state/,
  );
});

test("live activation requires the completed Diligence ceremony while earlier stages do not", () => {
  const missing = liveSnapshot();
  delete missing.diligenceReleaseCeremony;
  let report = buildPreflightReport(missing);
  let ceremony = report.checks.find(
    ({ id }) => id === "authority.diligence_release_ceremony",
  );
  assert.equal(ceremony?.status, "fail");
  assert.match(ceremony?.message || "", /four-phase DiligenceRoom ledger/);

  const verificationOnly = liveSnapshot();
  verificationOnly.diligenceReleaseCeremony.governanceAcceptanceMode =
    "not_applicable";
  verificationOnly.diligenceReleaseCeremony.governanceAcceptanceClaim =
    "operator_forge_broadcast_receipt";
  report = buildPreflightReport(verificationOnly);
  ceremony = report.checks.find(
    ({ id }) => id === "authority.diligence_release_ceremony",
  );
  assert.equal(ceremony?.status, "fail");

  for (const snapshot of [
    freshSnapshot(),
    cvmLaunchSnapshot(),
    releaseCeremonySnapshot(),
  ]) {
    delete snapshot.diligenceReleaseCeremony;
    ceremony = buildPreflightReport(snapshot).checks.find(
      ({ id }) => id === "authority.diligence_release_ceremony",
    );
    assert.equal(ceremony?.status, "pass", snapshot.authorityStage);
    assert.match(ceremony?.message || "", /not accepted before live activation/);
  }
});

test("fresh deployment intent must project the exact empty ChallengeRegistry state", () => {
  const snapshot = freshSnapshot();
  snapshot.releaseAuthority.deploymentIntentFreshChallengeStateValid = false;
  const checks = authorityChecks(buildPreflightReport(snapshot));
  assert.equal(checks["authority.deployment_intent"].status, "fail");
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");
});

test("CVM launch requires one reviewed intent-bound seven-contract and seven-descriptor bundle", () => {
  const report = buildPreflightReport(cvmLaunchSnapshot());
  const checks = authorityChecks(report);
  assert.equal(
    checks["authority.cvm_execution_boundary_availability"].status,
    "pass",
  );
  assert.equal(report.verdict, "BLOCKED");
  assert.match(
    checks["authority.final_release_authority"].message,
    /not accepted or required before CVMs launch/,
  );
  assert.equal(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.status,
    "pass",
  );
  assert.equal(
    report.checks.find((item) => item.id === "evidence.canonical_seven_cvm_authority")?.status,
    "warn",
  );
});

test("release ceremony requires measured final authority while contracts remain fail closed", () => {
  const report = buildPreflightReport(releaseCeremonySnapshot());
  const checks = authorityChecks(report);
  assert.equal(
    checks["authority.cvm_execution_boundary_availability"].status,
    "pass",
  );
  assert.equal(report.verdict, "BLOCKED");
  assert.match(
    checks["authority.stage"].message,
    /before any release-ceremony contract mutation/,
  );
  assert.match(
    checks["authority.contract_deployment_chain_evidence"].message,
    /fresh fail-closed state/,
  );
  assert.equal(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.status,
    "pass",
  );
  assert.match(
    report.checks.find((item) => item.id === "evidence.semantic_release_authority")?.message,
    /intentionally deferred/,
  );
});

test("role requirements follow constructor and post-measurement authority stages", () => {
  const constructorRoles = {
    DEPLOYMENT_OPERATOR: `0x${"11".repeat(20)}`,
    COMPUTE_VAULT_DEVELOPER: `0x${"22".repeat(20)}`,
  };
  const deferredRoleKeys = [
    "DILIGENCE_RESULT_VERIFIER",
    "COMPUTE_VAULT_METERING_VERIFIER",
    "COMPUTE_VAULT_METERING_QVL_VERIFIER",
  ];

  for (const snapshot of [freshSnapshot(), cvmLaunchSnapshot()]) {
    Object.assign(snapshot.env, constructorRoles);
    const report = buildPreflightReport(snapshot);
    for (const key of deferredRoleKeys) {
      assert.equal(
        report.checks.find(
          (item) => item.id === `contract_input.${key.toLowerCase()}`,
        )?.status,
        "pass",
        `${snapshot.authorityStage}:${key}`,
      );
    }
    const roleCheck = report.checks.find(
      (item) => item.id === "roles.pairwise_distinct",
    );
    assert.equal(roleCheck?.status, "pass", snapshot.authorityStage);
    assert.match(roleCheck?.message ?? "", /two constructor-stage contract roles/);
  }

  for (const snapshot of [releaseCeremonySnapshot(), liveSnapshot()]) {
    Object.assign(snapshot.env, constructorRoles);
    const report = buildPreflightReport(snapshot);
    for (const key of deferredRoleKeys) {
      assert.equal(
        report.checks.find(
          (item) => item.id === `contract_input.${key.toLowerCase()}`,
        )?.status,
        "fail",
        `${snapshot.authorityStage}:${key}`,
      );
    }
    assert.equal(
      report.checks.find((item) => item.id === "roles.pairwise_distinct")?.status,
      "fail",
      snapshot.authorityStage,
    );
  }
});

test("release ceremony and live activation require all five roles to be distinct", () => {
  const roles = Object.fromEntries([
    "DEPLOYMENT_OPERATOR",
    "DILIGENCE_RESULT_VERIFIER",
    "COMPUTE_VAULT_DEVELOPER",
    "COMPUTE_VAULT_METERING_VERIFIER",
    "COMPUTE_VAULT_METERING_QVL_VERIFIER",
  ].map((key, index) => [key, `0x${String(index + 1).repeat(40)}`]));

  for (const snapshot of [releaseCeremonySnapshot(), liveSnapshot()]) {
    Object.assign(snapshot.env, roles);
    let roleCheck = buildPreflightReport(snapshot).checks.find(
      (item) => item.id === "roles.pairwise_distinct",
    );
    assert.equal(roleCheck?.status, "pass", snapshot.authorityStage);
    assert.match(roleCheck?.message ?? "", /All five mandatory/);

    snapshot.env.COMPUTE_VAULT_METERING_QVL_VERIFIER =
      snapshot.env.DILIGENCE_RESULT_VERIFIER;
    roleCheck = buildPreflightReport(snapshot).checks.find(
      (item) => item.id === "roles.pairwise_distinct",
    );
    assert.equal(roleCheck?.status, "fail", snapshot.authorityStage);
    assert.match(
      roleCheck?.message ?? "",
      /DILIGENCE_RESULT_VERIFIER \+ COMPUTE_VAULT_METERING_QVL_VERIFIER/,
    );
  }
});

test("all four stage reports stay bounded to the exact 110-check contract", () => {
  assert.equal(PREFLIGHT_SCHEMA, "dnai.activation-preflight.v4");
  assert.equal(
    PREFLIGHT_ROOT_CAUSE_PROJECTION_SCHEMA,
    "dnai.activation-preflight-root-causes.v1",
  );
  for (const snapshot of [
    freshSnapshot(),
    cvmLaunchSnapshot(),
    releaseCeremonySnapshot(),
    liveSnapshot(),
  ]) {
    const report = buildPreflightReport(snapshot);
    const rawCheckCount = Object.values(report.summary)
      .reduce((total, count) => total + count, 0);
    assert.equal(
      rawCheckCount,
      PREFLIGHT_EXACT_CHECK_COUNT,
      snapshot.authorityStage,
    );
    assert.equal(
      report.checks.length,
      PREFLIGHT_EXACT_CHECK_COUNT,
      snapshot.authorityStage,
    );
    assert.equal(report.checks.at(-1)?.id, "image.provenance_sbom");
    const failedIds = report.checks
      .filter((item) => item.status === "fail")
      .map((item) => item.id);
    assert.equal(report.schema, PREFLIGHT_SCHEMA);
    assert.deepEqual(Object.keys(report), [
      "schema",
      "verdict",
      "summary",
      "invariants",
      "checks",
      "root_cause_projection",
      "root_causes",
      "blocked_by",
      "next_actions",
    ]);
    assert.equal(
      report.root_cause_projection.schema,
      PREFLIGHT_ROOT_CAUSE_PROJECTION_SCHEMA,
    );
    assert.equal(report.root_cause_projection.stage, snapshot.authorityStage);
    assert.equal(report.root_cause_projection.stage_valid, true);
    assert.equal(
      report.root_cause_projection.source_check_count,
      PREFLIGHT_EXACT_CHECK_COUNT,
    );
    assert.equal(report.root_cause_projection.source_fail_count, report.summary.fail);
    assert.equal(report.root_cause_projection.mapping_complete, true);
    assert.deepEqual(
      report.blocked_by.map((entry) => entry.check_id),
      failedIds,
    );
    assert.equal(new Set(report.blocked_by.map((entry) => entry.check_id)).size,
      failedIds.length);
  }
});

test("root-cause diagnosis coalesces only the exact clean-CI release family", () => {
  assert.equal(PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS.length, 31);
  assert.equal(new Set(PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS).size, 31);
  const secretSentinel = "must-not-enter-root-cause-projection";
  const checks = [
    ...PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS.map((id) => ({
      id,
      status: "fail",
      message: secretSentinel,
      action: secretSentinel,
    })),
    {
      id: "contract_policy.verify",
      status: "fail",
      message: secretSentinel,
      action: secretSentinel,
    },
    { id: "safety.read_only", status: "pass", message: secretSentinel },
    { id: "keystore.operator_match", status: "warn", message: secretSentinel },
  ];
  const diagnosis = projectPreflightRootCauses(checks, "fresh_deployment");
  const failedIds = checks
    .filter((item) => item.status === "fail")
    .map((item) => item.id);
  assert.deepEqual(
    diagnosis.root_cause_projection,
    {
      schema: PREFLIGHT_ROOT_CAUSE_PROJECTION_SCHEMA,
      stage: "fresh_deployment",
      stage_valid: true,
      source_check_count: checks.length,
      source_fail_count: failedIds.length,
      mapping_complete: true,
    },
  );
  assert.deepEqual(
    diagnosis.blocked_by.map((entry) => entry.check_id),
    failedIds,
  );
  assert.equal(
    new Set(diagnosis.blocked_by.map((entry) => entry.check_id)).size,
    failedIds.length,
  );
  const ciRoot = diagnosis.root_causes.find(
    (root) => root.id === "clean_ci_five_image_seven_cvm_bundle",
  );
  assert.deepEqual(ciRoot, {
    id: "clean_ci_five_image_seven_cvm_bundle",
    classification: "ci_external_state",
    failed_check_ids: [...PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS],
  });
  assert.deepEqual(
    diagnosis.blocked_by
      .filter((entry) => entry.root_cause_ids.includes(ciRoot.id))
      .map((entry) => entry.check_id),
    PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS,
  );
  const verifyRoot = diagnosis.root_causes.find(
    (root) => root.failed_check_ids.includes("contract_policy.verify"),
  );
  assert.deepEqual(verifyRoot, {
    id: "check.contract_policy.verify",
    classification: "reviewed_release_source",
    failed_check_ids: ["contract_policy.verify"],
  });
  assert.equal(JSON.stringify(diagnosis).includes(secretSentinel), false);
  assert.ok(diagnosis.root_causes.length <= PREFLIGHT_EXACT_CHECK_COUNT);
  assert.ok(diagnosis.blocked_by.length <= PREFLIGHT_EXACT_CHECK_COUNT);
  assert.ok(diagnosis.root_causes.every(
    (root) => root.failed_check_ids.length <= PREFLIGHT_EXACT_CHECK_COUNT,
  ));
});

test("root-cause diagnosis preserves partial CI drift and unknown failures", () => {
  const checks = [
    { id: "phala.compose_security", status: "fail", message: "x" },
    { id: "auth.phala", status: "fail", message: "x" },
    { id: "future.new_independent_gate", status: "fail", message: "x" },
    { id: "safety.read_only", status: "pass", message: "x" },
  ];
  const diagnosis = projectPreflightRootCauses(checks, "live_activation");
  assert.deepEqual(
    diagnosis.root_causes.find(
      (root) => root.id === "check.phala.compose_security",
    ),
    {
      id: "check.phala.compose_security",
      classification: "independent_check_failure",
      failed_check_ids: ["phala.compose_security"],
    },
  );
  assert.deepEqual(
    diagnosis.root_causes.find(
      (root) => root.id === "check.auth.phala",
    ),
    {
      id: "check.auth.phala",
      classification: "secure_interactive_authority",
      failed_check_ids: ["auth.phala"],
    },
  );
  assert.deepEqual(
    diagnosis.root_causes.find(
      (root) => root.id === "check.future.new_independent_gate",
    )?.failed_check_ids,
    ["future.new_independent_gate"],
  );

  const reorderedProperties = checks.map(({ id, status, message }) => ({
    message,
    status,
    id,
  }));
  assert.deepEqual(
    projectPreflightRootCauses(reorderedProperties, "live_activation"),
    diagnosis,
  );

  const unsupported = projectPreflightRootCauses(checks, "future_stage");
  assert.equal(unsupported.root_cause_projection.stage_valid, false);
  assert.equal(unsupported.root_cause_projection.stage, "unsupported");
  assert.equal(
    unsupported.root_causes.some(
      (root) => root.id === "clean_ci_five_image_seven_cvm_bundle",
    ),
    false,
  );
  assert.deepEqual(
    unsupported.blocked_by.map((entry) => entry.check_id),
    checks.filter((item) => item.status === "fail").map((item) => item.id),
  );
});

test("root-cause diagnosis classifies both Base Sepolia RPC inputs as chain state", () => {
  const rpcCheckIds = [
    "contract_input.base_sepolia_rpc_url",
    "contract_input.base_sepolia_secondary_rpc_url",
  ];
  const diagnosis = projectPreflightRootCauses(
    rpcCheckIds.map((id) => ({ id, status: "fail" })),
    "fresh_deployment",
  );
  assert.deepEqual(
    diagnosis.root_causes.map((root) => ({
      classification: root.classification,
      failed_check_ids: root.failed_check_ids,
    })),
    rpcCheckIds.map((id) => ({
      classification: "external_chain_state",
      failed_check_ids: [id],
    })),
  );
});

test("root-cause diagnosis never reflects unsupported stage bytes", () => {
  const sentinel = "SECRET_STAGE_SENTINEL_".repeat(10_000);
  const diagnosis = projectPreflightRootCauses([
    { id: "future.failure", status: "fail", message: "x" },
  ], sentinel);
  const serialized = JSON.stringify(diagnosis);
  assert.equal(diagnosis.root_cause_projection.stage, "unsupported");
  assert.equal(diagnosis.root_cause_projection.stage_valid, false);
  assert.equal(diagnosis.root_cause_projection.mapping_complete, true);
  assert.equal(serialized.includes("SECRET_STAGE_SENTINEL_"), false);
  assert.ok(Buffer.byteLength(serialized, "utf8") < 4_096);
});

test("report diagnosis uses the same normalized default and trimmed stage", () => {
  const defaulted = liveSnapshot();
  delete defaulted.authorityStage;
  const defaultedReport = buildPreflightReport(defaulted);
  assert.deepEqual(
    defaultedReport.root_cause_projection,
    {
      schema: PREFLIGHT_ROOT_CAUSE_PROJECTION_SCHEMA,
      stage: "live_activation",
      stage_valid: true,
      source_check_count: PREFLIGHT_EXACT_CHECK_COUNT,
      source_fail_count: defaultedReport.summary.fail,
      mapping_complete: true,
    },
  );

  const trimmed = liveSnapshot();
  trimmed.authorityStage = "  live_activation  ";
  const trimmedReport = buildPreflightReport(trimmed);
  assert.equal(trimmedReport.root_cause_projection.stage, "live_activation");
  assert.equal(trimmedReport.root_cause_projection.stage_valid, true);
  assert.equal(
    trimmedReport.checks.find((item) => item.id === "authority.stage")?.status,
    "pass",
  );
});

test("root-cause diagnosis rejects duplicate or unbounded check sets", () => {
  assert.throws(
    () => projectPreflightRootCauses([
      { id: "duplicate", status: "fail" },
      { id: "duplicate", status: "pass" },
    ], "fresh_deployment"),
    /invalid or duplicate checks/,
  );
  assert.throws(
    () => projectPreflightRootCauses(
      Array.from({ length: PREFLIGHT_EXACT_CHECK_COUNT + 1 }, (_, index) => ({
        id: `check-${index}`,
        status: "fail",
      })),
      "fresh_deployment",
    ),
    /at most 110 checks/,
  );
});

test("root-cause diagnosis rejects accessors, proxies, and control IDs before projection", () => {
  let getterReads = 0;
  const accessorCheck = { status: "fail" };
  Object.defineProperty(accessorCheck, "id", {
    enumerable: true,
    get() {
      getterReads += 1;
      return getterReads < 2 ? "safe.failure" : "secret.control";
    },
  });
  assert.throws(
    () => projectPreflightRootCauses([accessorCheck], "fresh_deployment"),
    /canonical plain-data graph/,
  );
  assert.equal(getterReads, 0);

  let proxyTraps = 0;
  const proxyCheck = new Proxy(
    { id: "safe.failure", status: "fail" },
    {
      get(target, key, receiver) {
        proxyTraps += 1;
        return Reflect.get(target, key, receiver);
      },
      ownKeys(target) {
        proxyTraps += 1;
        return Reflect.ownKeys(target);
      },
    },
  );
  assert.throws(
    () => projectPreflightRootCauses([proxyCheck], "fresh_deployment"),
    /Proxy objects are forbidden/,
  );
  assert.equal(proxyTraps, 0);

  let arrayProxyTraps = 0;
  const proxiedChecks = new Proxy(
    [{ id: "safe.failure", status: "fail" }],
    {
      get(target, key, receiver) {
        arrayProxyTraps += 1;
        return Reflect.get(target, key, receiver);
      },
    },
  );
  assert.throws(
    () => projectPreflightRootCauses(proxiedChecks, "fresh_deployment"),
    /Proxy objects are forbidden/,
  );
  assert.equal(arrayProxyTraps, 0);

  const revoked = Proxy.revocable(
    { id: "safe.failure", status: "fail" },
    {},
  );
  revoked.revoke();
  assert.throws(
    () => projectPreflightRootCauses([revoked.proxy], "fresh_deployment"),
    /Proxy objects are forbidden/,
  );

  let inheritedGetterReads = 0;
  const inheritedCheck = Object.create({
    get id() {
      inheritedGetterReads += 1;
      return "safe.failure";
    },
  });
  inheritedCheck.status = "fail";
  assert.throws(
    () => projectPreflightRootCauses([inheritedCheck], "fresh_deployment"),
    /custom prototypes are forbidden/,
  );
  assert.equal(inheritedGetterReads, 0);

  assert.throws(
    () => projectPreflightRootCauses(new Array(1), "fresh_deployment"),
    /arrays must be dense/,
  );

  assert.throws(
    () => projectPreflightRootCauses([
      { id: "safe.failure\nsecret-control", status: "fail" },
    ], "fresh_deployment"),
    /invalid or duplicate checks/,
  );
});

test("a missing clean-CI bundle maps the exact 31 raw failures without hiding them", () => {
  const report = buildPreflightReport(freshSnapshot());
  const ciRoot = report.root_causes.find(
    (root) => root.id === "clean_ci_five_image_seven_cvm_bundle",
  );
  assert.deepEqual(ciRoot?.failed_check_ids, PREFLIGHT_CLEAN_CI_RELEASE_CHECK_IDS);
  assert.equal(
    report.root_causes.flatMap((root) => root.failed_check_ids).length,
    report.summary.fail,
  );
  assert.ok(Buffer.byteLength(JSON.stringify(report), "utf8") <= 131_072);
});

test("legacy review-envelope fields cannot substitute for current stage authority", () => {
  const fresh = freshSnapshot();
  fresh.releaseAuthority.deploymentIntentFileHashBound = false;
  fresh.releaseAuthority.reviewSubjectKind = "final_release_authority";
  fresh.releaseAuthority.reviewSubjectSha256 = FINAL_AUTHORITY_SHA256;
  assert.equal(
    authorityChecks(buildPreflightReport(fresh))["authority.current_stage_signature"].status,
    "fail",
  );

  const launch = cvmLaunchSnapshot();
  launch.cvmLaunchAuthority.artifactBindingsValid = false;
  launch.cvmLaunchAuthority.reviewSubjectKind = "deployment_intent";
  launch.cvmLaunchAuthority.reviewSubjectSha256 = INTENT_SHA256;
  assert.equal(
    authorityChecks(buildPreflightReport(launch))["authority.current_stage_signature"].status,
    "fail",
  );

  const live = liveSnapshot();
  live.semanticValidationReceipt.live_activation_authority_sha256 =
    `sha256:${"f".repeat(64)}`;
  live.releaseAuthority.reviewSubjectKind = "deployment_intent";
  live.releaseAuthority.reviewSubjectSha256 = INTENT_SHA256;
  assert.equal(
    authorityChecks(buildPreflightReport(live))["authority.current_stage_signature"].status,
    "fail",
  );

  const ceremony = releaseCeremonySnapshot();
  ceremony.canonicalSevenCvmAuthorityValidation = null;
  ceremony.releaseAuthority.reviewSubjectKind = "cvm_launch_intent";
  ceremony.releaseAuthority.reviewSubjectSha256 = CVM_LAUNCH_INTENT_SHA256;
  assert.equal(
    authorityChecks(buildPreflightReport(ceremony))["authority.current_stage_signature"].status,
    "fail",
  );
});

test("live authority fails closed on intent drift or incomplete environment projection", () => {
  const linked = liveSnapshot();
  linked.releaseAuthority.finalAuthorityDeploymentIntentSha256 = `sha256:${"7".repeat(64)}`;
  let checks = authorityChecks(buildPreflightReport(linked));
  assert.equal(checks["authority.final_release_authority"].status, "fail");
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");

  const uncovered = liveSnapshot();
  uncovered.releaseAuthority.deploymentIntentEnvironmentProjection = {
    ok: false,
    checkedKeys: [],
    mismatchKeys: ["authority_projection_coverage_incomplete"],
  };
  checks = authorityChecks(buildPreflightReport(uncovered));
  assert.equal(
    checks["authority.deployment_intent_environment_projection"].status,
    "fail",
  );
});

test("CVM launch fails closed on every retained artifact or production-posture drift", () => {
  const cases = [
    (value) => { value.cvmLaunchAuthority.deploymentIntentSha256 = `sha256:${"e".repeat(64)}`; },
    (value) => {
      value.cvmLaunchAuthority.contractDeploymentReceiptSha256 =
        `sha256:${"e".repeat(64)}`;
    },
    (value) => { value.cvmLaunchAuthority.imageCount = 4; },
    (value) => { value.cvmLaunchAuthority.contractDeploymentContractCount = 6; },
    (value) => { value.cvmLaunchAuthority.descriptorCount = 5; },
    (value) => { value.cvmLaunchAuthority.descriptorHashesDistinct = false; },
    (value) => { value.cvmLaunchAuthority.productionPostureValid = false; },
    (value) => { value.cvmLaunchAuthority.collaborationGatePolicyValid = false; },
    (value) => { value.cvmLaunchAuthority.collaborationGateBootstrapDefault = ""; },
    (value) => { value.cvmLaunchAuthority.collaborationGateBootstrapDefault = "False"; },
    (value) => { value.cvmLaunchAuthority.collaborationGateBootstrapDefault = "true"; },
    (value) => { value.cvmLaunchAuthority.collaborationGateBootstrapDefault = "0"; },
    (value) => { value.cvmLaunchAuthority.artifactBindingsValid = false; },
    (value) => {
      value.cvmLaunchAuthority.descriptorSha256ByDomain.main_runtime_cvm =
        `sha256:${"e".repeat(64)}`;
    },
  ];
  for (const mutate of cases) {
    const snapshot = cvmLaunchSnapshot();
    mutate(snapshot);
    const checks = authorityChecks(buildPreflightReport(snapshot));
    assert.equal(checks["authority.release_artifact_binding"].status, "fail");
  }
});

test("mutable ledger review and CVM history cannot change launch authority", () => {
  const snapshot = cvmLaunchSnapshot();
  const ledger = snapshot.files.ledger.value;
  const originalDigest = snapshot.cvmLaunchAuthority.contractDeploymentReceiptSha256;

  ledger.freshDeployment.contractSuite.deploymentReviewEnvelopeSha256 =
    `sha256:${"a".repeat(64)}`;
  ledger.freshDeployment.contractSuite.deploymentReviewEvidenceSha256 =
    `sha256:${"b".repeat(64)}`;
  ledger.deploymentHistory[0].deploymentReviewEnvelopeSha256 =
    `sha256:${"c".repeat(64)}`;
  ledger.deploymentHistory.push({ kind: "unrelated_review_renewal" });
  ledger.phala = { cvmId: "mutable-cvm", appId: "mutable-app" };
  ledger.reviewHistory = [{ envelope: "renewed" }];
  snapshot.files.ledger.sha256 = "d".repeat(64);

  assert.equal(contractDeploymentReceiptSha256(ledger), originalDigest);
  let checks = authorityChecks(buildPreflightReport(snapshot));
  assert.equal(checks["authority.release_artifact_binding"].status, "pass");

  snapshot.files.ledger.sha256 = "e".repeat(64);
  checks = authorityChecks(buildPreflightReport(snapshot));
  assert.equal(checks["authority.release_artifact_binding"].status, "pass");
});

test("immutable deployment fact drift changes or invalidates the projected receipt", () => {
  const runtimeDrift = cvmLaunchSnapshot();
  runtimeDrift.files.ledger.value.contracts.challengeRegistry.runtimeCodeHash =
    `0x${"f".repeat(64)}`;
  let checks = authorityChecks(buildPreflightReport(runtimeDrift));
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");

  const reverted = cvmLaunchSnapshot();
  reverted.files.ledger.value.contracts.challengeRegistry.deploymentReceiptStatus =
    "reverted";
  checks = authorityChecks(buildPreflightReport(reverted));
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");
});

test("online chain evidence rejects omissions, substitutions, offline mode, and raw fields", () => {
  const cases = [
    (value) => { value.valid = false; },
    (value) => { value.readOnly = false; },
    (value) => { value.evidenceSource = "test_adapter_not_release_authority"; },
    (value) => { value.secondaryChainId = 1; },
    (value) => { value.rpcEndpointsDistinct = false; },
    (value) => { value.secondaryRpcEndpointSha256 = value.rpcEndpointSha256; },
    (value) => { value.secondaryFinalizedSnapshotVerified = false; },
    (value) => { value.secondaryFinalizedTagRechecked = false; },
    (value) => { value.independentReconstructionRpcAgreement = false; },
    (value) => { value.secondaryRuntimeCodeMatchCount = 6; },
    (value) => { value.runtimeCodeMatchCount = 6; },
    (value) => { value.immutableProvenanceContractCount = 6; },
    (value) => { value.immutableProvenanceValid = false; },
    (value) => { value.immutableProvenance.pop(); },
    (value) => {
      [value.immutableProvenance[0], value.immutableProvenance[1]] =
        [value.immutableProvenance[1], value.immutableProvenance[0]];
    },
    (value) => { value.immutableProvenance[0].transactionFound = false; },
    (value) => { value.poststateContractCount = 5; },
    (value) => { value.poststateValid = false; },
    (value) => { value.poststates.pop(); },
    (value) => { value.poststates[0].name = "RoyaltyDistributor"; },
    (value) => { value.poststates[0].assertions.pop(); },
    (value) => { value.poststates[0].assertions[2] = "registry_paused"; },
    (value) => { value.rpcError = "private provider failure"; },
  ];
  for (const mutate of cases) {
    const snapshot = cvmLaunchSnapshot();
    mutate(snapshot.contractDeploymentChainEvidence);
    const report = buildPreflightReport(snapshot);
    const checks = authorityChecks(report);
    assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");
    assert.equal(checks["authority.release_artifact_binding"].status, "fail");
    assert.equal(JSON.stringify(report).includes("private provider failure"), false);
  }
});

test("each online stage requires its exact seven-contract poststate mode", () => {
  const launch = cvmLaunchSnapshot();
  launch.contractDeploymentChainEvidence = contractDeploymentChainEvidence({
    poststateMode: "final_active_frozen",
  });
  assert.equal(
    authorityChecks(buildPreflightReport(launch))[
      "authority.contract_deployment_chain_evidence"
    ].status,
    "fail",
  );

  const ceremony = releaseCeremonySnapshot();
  ceremony.contractDeploymentChainEvidence = contractDeploymentChainEvidence({
    poststateMode: "final_active_frozen",
  });
  assert.equal(
    authorityChecks(buildPreflightReport(ceremony))[
      "authority.contract_deployment_chain_evidence"
    ].status,
    "fail",
  );

  const live = liveSnapshot();
  live.contractDeploymentChainEvidence = contractDeploymentChainEvidence({
    poststateMode: "fresh_fail_closed",
  });
  assert.equal(
    authorityChecks(buildPreflightReport(live))[
      "authority.contract_deployment_chain_evidence"
    ].status,
    "fail",
  );
});

test("readiness snapshots are domain-separated, short lived, and bind the pinned mutation path", () => {
  const snapshot = cvmLaunchSnapshot();
  const readiness = normalizeActivationReadinessSnapshot(
    snapshot.activationReadinessSnapshot,
  );
  assert.equal(readiness.schema, "dnai.activation-readiness-snapshot.v5");
  assert.equal(ACTIVATION_READINESS_SNAPSHOT_DOMAIN.endsWith("\0"), true);
  assert.equal(
    activationReadinessSnapshotDigest(
      Object.fromEntries(Object.entries(readiness).reverse()),
    ),
    activationReadinessSnapshotDigest(readiness),
  );
  assert.deepEqual(readiness.authorized_next_actions, [
    "phala.nextAppIds.predict_exact_seven",
    "phala.provisionCvm.prepare_exact_seven_supporting_then_main",
    "phala.commitCvmProvision.bootstrap_exact_seven_supporting_then_main",
  ]);
  assert.equal(readiness.execution_boundary.availability, true);
  assert.equal(
    readiness.execution_boundary.transport,
    "pinned_authenticated_phala_sdk_exact_origin_durable_replay",
  );
  assert.equal(
    readiness.execution_boundary.prepare_method,
    "provisionCvm_supporting_six_then_main",
  );
  assert.equal(
    readiness.execution_boundary.commit_method,
    "commitCvmProvision_supporting_six_then_main",
  );
  assert.equal(
    readiness.execution_boundary.reason_code,
    null,
  );
  assert.deepEqual(
    readiness.execution_boundary.blocker_codes,
    [...PHALA_PRODUCTION_BOOTSTRAP_EXECUTION_BLOCKER_CODES],
  );
  assert.equal(
    readiness.execution_boundary.phala_cli_role,
    "authentication_and_diagnostics_only_no_mutation_bypass",
  );
  assert.equal(readiness.immediate_recheck.before_first_mutation, true);
  assert.equal(
    readiness.immediate_recheck.repeat_before_each_mutation_after_expiry,
    true,
  );
  assert.equal(
    JSON.stringify(readiness).includes("base-sepolia.invalid"),
    false,
  );
  assert.notEqual(readiness.rpc_origin_sha256, readiness.secondary_rpc_origin_sha256);
  assert.equal(readiness.dual_rpc_broadcast_transaction_agreement, true);
  assert.equal(readiness.dual_rpc_poststate_agreement, true);
  assert.equal(
    readiness.primary_broadcast_transaction_observations_sha256,
    readiness.secondary_broadcast_transaction_observations_sha256,
  );
  assert.equal(
    readiness.primary_poststate_observations_sha256,
    readiness.secondary_poststate_observations_sha256,
  );
  assert.throws(
    () => activationReadinessRpcOriginDigest("https://user:secret@rpc.invalid"),
    /credential-free HTTPS origin/,
  );
  assert.throws(
    () => activationReadinessRpcOriginDigest("https://rpc.invalid/path"),
    /credential-free HTTPS origin/,
  );

  const overlong = structuredClone(readiness);
  overlong.expires_at = "2026-07-21T12:02:01Z";
  assert.throws(
    () => normalizeActivationReadinessSnapshot(overlong),
    /lifetime/,
  );

  const cliPrepare = structuredClone(readiness);
  cliPrepare.execution_boundary.transport = "phala-cli";
  assert.throws(
    () => normalizeActivationReadinessSnapshot(cliPrepare),
    /execution boundary/,
  );
});

test("measured readiness fails closed on missing, divergent, or underfunded writer gas", () => {
  const baseline = liveSnapshot();
  const gasCheck = (snapshot) =>
    buildPreflightReport(snapshot).checks.find(
      ({ id }) => id === "chain.anchor_writer_gas_reserve",
    );
  let checks = authorityChecks(buildPreflightReport(baseline));
  assert.equal(gasCheck(baseline)?.status, "pass");

  const missing = liveSnapshot();
  missing.contractDeploymentChainEvidence.anchorWriterGasReadiness = null;
  checks = authorityChecks(buildPreflightReport(missing));
  assert.equal(gasCheck(missing)?.status, "fail");
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");

  const underfunded = liveSnapshot();
  const underfundedGas = underfunded.contractDeploymentChainEvidence
    .anchorWriterGasReadiness;
  const lowBalance = (
    BigInt(EXECUTION_POLICY_ANCHOR_WRITER_GAS_RESERVE_POLICY.minimum_reserve_wei)
    - 1n
  ).toString(10);
  const lowObservation = activationReadinessAnchorWriterGasObservationDigest({
    rpc_method: "eth_getBalance",
    writer_address: ANCHOR_WRITER_ADDRESS,
    balance_wei: lowBalance,
    block_number: underfundedGas.balance_block_number,
    block_hash: underfundedGas.balance_block_hash,
  });
  Object.assign(underfundedGas, {
    primary_balance_wei: lowBalance,
    secondary_balance_wei: lowBalance,
    canonical_balance_wei: lowBalance,
    primary_observation_sha256: lowObservation,
    secondary_observation_sha256: lowObservation,
    reserve_satisfied: false,
  });
  assert.equal(gasCheck(underfunded)?.status, "fail");

  const divergent = liveSnapshot();
  divergent.contractDeploymentChainEvidence
    .anchorWriterGasReadiness.secondary_balance_wei =
      "33000000000000001";
  divergent.contractDeploymentChainEvidence
    .anchorWriterGasReadiness.dual_rpc_agreement = false;
  divergent.contractDeploymentChainEvidence
    .anchorWriterGasReadiness.reserve_satisfied = false;
  assert.equal(gasCheck(divergent)?.status, "fail");

  const weakenedSnapshot = structuredClone(
    baseline.activationReadinessSnapshot,
  );
  weakenedSnapshot.anchor_writer_gas_readiness.reserve_satisfied = false;
  assert.throws(
    () => normalizeActivationReadinessSnapshot(weakenedSnapshot),
    /gas readiness/,
  );
});

test("Phala CLI identity is diagnostic-only and package-manifest pinned", () => {
  const snapshot = liveSnapshot();
  snapshot.tools = { phala: true };
  snapshot.toolVersions = {
    phala: {
      valid: true,
      version: "1.1.19",
      source: "installed_package_manifest",
    },
  };
  let phala = buildPreflightReport(snapshot).checks.find(
    (item) => item.id === "tool.phala",
  );
  assert.equal(phala?.status, "pass");
  assert.match(phala?.message, /diagnostics only/);

  snapshot.toolVersions.phala.version = "1.1.20";
  phala = buildPreflightReport(snapshot).checks.find(
    (item) => item.id === "tool.phala",
  );
  assert.equal(phala?.status, "fail");
});

test("readiness snapshot rejects TOCTOU drift after preparation", () => {
  const blockDrift = cvmLaunchSnapshot();
  blockDrift.contractDeploymentChainEvidence.snapshotBlockNumber += 1;
  blockDrift.contractDeploymentChainEvidence.snapshotBlockHash =
    `0x${"bc".repeat(32)}`;
  let checks = authorityChecks(buildPreflightReport(blockDrift));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");

  const finalityDrift = cvmLaunchSnapshot();
  finalityDrift.contractDeploymentChainEvidence.finalizedRecheckBlockNumber = 1_999;
  checks = authorityChecks(buildPreflightReport(finalityDrift));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");

  const descriptorDrift = cvmLaunchSnapshot();
  descriptorDrift.activationReadinessSnapshot
    .descriptor_raw_bytes_sha256_by_domain.main_runtime_cvm =
      `sha256:${"f".repeat(64)}`;
  rehashActivationReadinessSnapshot(descriptorDrift);
  checks = authorityChecks(buildPreflightReport(descriptorDrift));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");

  const expired = cvmLaunchSnapshot();
  expired.activationReadinessValidationNowMs = Date.parse("2026-07-21T12:02:00Z");
  checks = authorityChecks(buildPreflightReport(expired));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");

  const digestDrift = cvmLaunchSnapshot();
  digestDrift.activationReadinessSnapshotSha256 = `sha256:${"f".repeat(64)}`;
  checks = authorityChecks(buildPreflightReport(digestDrift));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");

  const broadcastDrift = cvmLaunchSnapshot();
  broadcastDrift.contractDeploymentChainEvidence
    .broadcastTransactionProvenance[8].inputMatches = false;
  checks = authorityChecks(buildPreflightReport(broadcastDrift));
  assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");
});

test("readiness snapshot rejects weakened recheck policy and action expansion", () => {
  for (const mutate of [
    (value) => { value.immediate_recheck.before_first_mutation = false; },
    (value) => {
      value.immediate_recheck.repeat_before_each_mutation_after_expiry = false;
    },
    (value) => { value.authorized_next_actions.push("phala.delete.any_cvm"); },
    (value) => { value.read_only = false; },
    (value) => { value.remote_state_mutated = true; },
    (value) => { value.raw_secret_egress = true; },
    (value) => { value.execution_boundary.raw_private_key_allowed = true; },
    (value) => { value.execution_boundary.availability = false; },
    (value) => { value.execution_boundary.prepare_method = "provisionCvm"; },
    (value) => { value.execution_boundary.blocker_codes = ["unreviewed"]; },
  ]) {
    const snapshot = cvmLaunchSnapshot();
    mutate(snapshot.activationReadinessSnapshot);
    assert.throws(
      () => normalizeActivationReadinessSnapshot(snapshot.activationReadinessSnapshot),
    );
    const checks = authorityChecks(buildPreflightReport(snapshot));
    assert.equal(checks["authority.contract_deployment_chain_evidence"].status, "fail");
  }
});

test("live final authority transitively binds the retained CVM-launch intent", () => {
  const snapshot = liveSnapshot();
  snapshot.releaseAuthority.finalAuthorityCvmLaunchIntentSha256 =
    `sha256:${"e".repeat(64)}`;
  const checks = authorityChecks(buildPreflightReport(snapshot));
  assert.equal(checks["authority.cvm_launch_intent"].status, "pass");
  assert.equal(checks["authority.final_release_authority"].status, "fail");
  assert.equal(checks["authority.release_artifact_binding"].status, "fail");
});

test("measured authority rejects every Collaboration feature projection mismatch", () => {
  for (const mutate of [
    (value) => {
      value.releaseAuthority.finalAuthorityCollaborationRequested = true;
      value.releaseAuthority.finalAuthorityCollaborationEnvironmentValue = "false";
    },
    (value) => {
      value.releaseAuthority.finalAuthorityCollaborationRequested = false;
      value.releaseAuthority.finalAuthorityCollaborationEnvironmentValue = "true";
    },
    (value) => {
      value.releaseAuthority.finalAuthorityCollaborationEnvironmentValue = "";
    },
    (value) => {
      value.releaseAuthority.finalAuthorityCollaborationEnvironmentValue = "TRUE";
    },
    (value) => {
      value.releaseAuthority.finalAuthorityCollaborationEnvironmentValue = "0";
    },
  ]) {
    const snapshot = liveSnapshot();
    mutate(snapshot);
    const report = buildPreflightReport(snapshot);
    const checks = authorityChecks(report);
    assert.equal(report.checks.length, PREFLIGHT_EXACT_CHECK_COUNT);
    assert.equal(checks["authority.final_release_authority"].status, "fail");
    assert.equal(checks["authority.release_artifact_binding"].status, "fail");
  }
});

test("retired renewable-review fields cannot mutate immutable live authority", () => {
  const snapshot = liveSnapshot();
  const renewedEnvelope = `sha256:${"8".repeat(64)}`;
  const renewedEvidence = `sha256:${"9".repeat(64)}`;
  snapshot.releaseAuthority.reviewEnvelopeSha256 = renewedEnvelope;
  snapshot.releaseAuthority.reviewEvidenceSha256 = renewedEvidence;
  const checks = authorityChecks(buildPreflightReport(snapshot));
  assert.equal(checks["authority.final_release_authority"].status, "pass");
  assert.equal(checks["authority.current_stage_signature"].status, "pass");
  assert.equal(checks["authority.current_stage_evidence"].status, "pass");
  assert.equal(checks["authority.release_artifact_binding"].status, "pass");
  assert.equal(snapshot.releaseAuthority.finalAuthoritySha256, FINAL_AUTHORITY_SHA256);
});

test("signed live-activation receipt is exact, lineage-bound, and rejects legacy fields", () => {
  for (const mutate of [
    (value) => { value.semanticValidationReceipt.operator_policy_packet_sha256 = INTENT_SHA256; },
    (value) => { value.semanticValidationReceipt.live_activation_authority_sha256 = `sha256:${"f".repeat(64)}`; },
    (value) => { value.semanticValidationReceipt.schema = "dnai.semantic-release-validation.v1"; },
    (value) => { value.semanticValidationReceipt.raw_secret_egress = true; },
    (value) => { value.semanticEvidenceValidated = false; },
  ]) {
    const snapshot = liveSnapshot();
    mutate(snapshot);
    const semantic = buildPreflightReport(snapshot).checks.find(
      (item) => item.id === "evidence.semantic_release_authority",
    );
    assert.equal(semantic?.status, "fail");
  }
});

test("invalid stage blocks while fresh deployment accepts only reviewed intent authority", () => {
  const invalid = freshSnapshot();
  invalid.authorityStage = "modeled";
  assert.equal(
    authorityChecks(buildPreflightReport(invalid))["authority.stage"].status,
    "fail",
  );

  const historical = freshSnapshot();
  historical.files.ledger = {
    valid: true,
    value: {
      freshDeployment: {
        contractSuite: { deploymentIntentSha256: `sha256:${"f".repeat(64)}` },
      },
    },
  };
  assert.equal(
    authorityChecks(buildPreflightReport(historical))[
      "authority.release_artifact_binding"
    ].status,
    "pass",
  );
});

test("preflight topology schema stays exactly aligned with the canonical renderer", () => {
  const renderer = readFileSync(
    new URL("../⚙️/tinker-delegate/tinker_delegate/release_composes.py", import.meta.url),
    "utf8",
  );
  const match = renderer.match(/^TOPOLOGY_SCHEMA = "([^"]+)"$/m);
  assert.ok(match);
  assert.equal(CVM_TOPOLOGY_SCHEMA, match[1]);
  assert.equal(CVM_TOPOLOGY_SCHEMA, CVM_LAUNCH_TOPOLOGY_SCHEMA);
  assert.equal(CVM_TOPOLOGY_SCHEMA, "dnai.cvm-topology.v6");
  assert.deepEqual(CVM_TOPOLOGY_DOMAINS, CVM_LAUNCH_DOMAINS);
});
