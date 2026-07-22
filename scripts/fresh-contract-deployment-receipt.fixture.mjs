// Synthetic, deterministic test fixture only. This module never reads a wallet,
// RPC endpoint, deployment ledger, or live authority artifact and MUST NOT be
// accepted as release evidence outside tests.

import {
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  projectFreshContractDeploymentReceipt,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function bytes32(index) {
  return `0x${index.toString(16).padStart(64, "0")}`;
}

function syntheticBroadcastEvidence(contracts, operatorAddress) {
  const transactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map((spec, sequence) => {
    const contract = contracts[spec.contract_key];
    const create = spec.transaction_type === "CREATE";
    const inputSha256 = `sha256:${(500 + sequence).toString(16).padStart(64, "0")}`;
    if (create) contract.creationInputSha256 = inputSha256;
    return {
      sequence,
      contractKey: spec.contract_key,
      contractName: spec.name,
      transactionType: spec.transaction_type,
      functionSignature: spec.function_signature,
      transactionHash: create ? contract.deploymentTx : bytes32(200 + sequence),
      transactionFrom: operatorAddress,
      transactionTo: create ? null : contract.address,
      transactionNonce: 700 + sequence,
      transactionInputSha256: inputSha256,
      receiptStatus: "success",
      receiptContractAddress: create ? contract.address : null,
      blockNumber: create ? contract.deploymentBlock : 12_346_000 + sequence,
      blockHash: create ? contract.deploymentBlockHash : bytes32(300 + sequence),
    };
  });
  const normalized = transactions.map((entry) => ({
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
  return {
    transactions,
    sha256: rawSha256(Buffer.from(JSON.stringify(sortedObject(normalized)), "utf8")),
  };
}

export function syntheticFreshContractDeploymentReceiptFixture({
  releaseSha,
  deploymentIntentSha256,
  reviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  const operatorAddress = address(1);
  const contractNames = [
    "challengeRegistry",
    "computeCreditVault",
    "diligenceRoom",
    "emailOracleAuth",
    "executionPolicyAnchor",
    "royaltyDistributor",
    "tinkerAccountEncumbrance",
  ];
  const contracts = Object.fromEntries(contractNames.map((name, index) => [name, {
    address: address(10 + index),
    runtimeCodeHash: bytes32(20 + index),
    sourceCommit: releaseSha,
    deploymentTx: bytes32(30 + index),
    deploymentBlock: 12_345_000 + index,
    deploymentBlockHash: bytes32(40 + index),
    deploymentReceiptStatus: "success",
    deploymentTxFrom: operatorAddress,
    deploymentReceiptContractAddress: address(10 + index),
  }]));
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: operatorAddress,
    registryPaused: false,
    challengeCount: 0,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32: `0x${deploymentIntentSha256.slice(7)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${reviewerAuthorityGenesisAcceptanceSha256.slice(7)}`,
    authorityCommitmentReadProof: FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock: contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash: contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcast = syntheticBroadcastEvidence(contracts, operatorAddress);
  const ledger = {
    schemaVersion: 2,
    status: "fresh_contract_suite_deployed_pending_cvm_binding",
    network: {
      name: "Base Sepolia",
      chainId: 84_532,
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
      explorerBaseUrl: "https://sepolia.basescan.org",
    },
    currentOperatorDeployer: {
      address: operatorAddress,
      keystoreAccount: "dev",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        sourceCommit: releaseSha,
        deploymentIntentSha256,
        reviewerAuthorityGenesisAcceptanceSha256,
        keystoreAccount: "dev",
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        exactCreationInputProof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
        broadcastTransactionProof: FRESH_CONTRACT_BROADCAST_PROOF,
        broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
        broadcastTransactionsSha256: broadcast.sha256,
        broadcastTransactions: broadcast.transactions,
      },
    },
    contracts,
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: releaseSha,
      deploymentIntentSha256,
      reviewerAuthorityGenesisAcceptanceSha256,
      broadcastTransactionsSha256: broadcast.sha256,
    }],
  };
  const authorityPins = {
    expectedDeploymentIntentSha256: deploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerAuthorityGenesisAcceptanceSha256,
  };
  return {
    truth_status: "synthetic_test_fixture_never_live_release_authority",
    authorityPins,
    ledger,
    receipt: projectFreshContractDeploymentReceipt(ledger, {
      releaseSha,
      ...authorityPins,
    }),
  };
}
