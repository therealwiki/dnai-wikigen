import { createHash } from "node:crypto";

import {
  ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  ROYALTY_RELEASE_EXECUTION_MODES,
  ROYALTY_RELEASE_HISTORY_DOMAIN,
  ROYALTY_RELEASE_HISTORY_SCHEMA,
  ROYALTY_RELEASE_HISTORY_V2_DOMAIN,
  ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
  normalizeRoyaltyReleaseAuthority,
  normalizeRoyaltyReleaseState,
  royaltyReleaseMutationCalldataSha256,
  royaltyReleaseMutationEvent,
  royaltyReleaseStateSha256,
} from "./royalty-release-authority-core.mjs";

export const ROYALTY_RELEASE_HISTORY_RECEIPT_SCHEMA =
  "dnai.royalty-release-history-receipt.v1";
export const ROYALTY_RELEASE_HISTORY_RECEIPT_DOMAIN =
  "dnai-wikigen/royalty-release-history-receipt/v1\0";
export const ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA =
  "dnai.royalty-release-history-receipt.v2";
export const ROYALTY_RELEASE_HISTORY_RECEIPT_V2_DOMAIN =
  "dnai-wikigen/royalty-release-history-receipt/v2\0";
export const ROYALTY_RELEASE_HISTORY_RECEIPT_TRUTH_STATUS =
  "observed_dual_rpc_release_evidence_not_signed_live_authority";

const CHAIN_ID = 84_532;
const MAX_BYTES = 4 * 1024 * 1024;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;
const LOGS_BLOOM = /^0x[0-9a-f]{512}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

function fail(message) {
  throw new TypeError(message);
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  if (JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function decimal(value, label) {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  try {
    if (BigInt(value) >= (1n << 256n)) fail(`${label} exceeds uint256`);
  } catch {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value) || value === ZERO_SHA256) {
    fail(`${label} must be a nonzero SHA-256 pin`);
  }
  return value;
}

function address(value, label, { allowZero = false } = {}) {
  if (typeof value !== "string" || !ADDRESS.test(value)
    || (!allowZero && value === ZERO_ADDRESS)) {
    fail(`${label} must be a canonical${allowZero ? "" : " nonzero"} address`);
  }
  return value;
}

function bytes32(value, label, { allowZero = false } = {}) {
  if (typeof value !== "string" || !BYTES32.test(value)
    || (!allowZero && value === ZERO_BYTES32)) {
    fail(`${label} must be canonical${allowZero ? "" : " nonzero"} bytes32`);
  }
  return value;
}

function hexData(value, label) {
  if (typeof value !== "string" || !HEX_DATA.test(value)
    || value.length > 131_074) {
    fail(`${label} must be bounded canonical lowercase hex data`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function domainDigest(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function assertBounded(value) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    fail("royalty release history receipt must be acyclic JSON");
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) {
    fail("royalty release history receipt exceeds the byte bound");
  }
}

function normalizeContracts(value) {
  const keys = [
    "diligence_room",
    "tinker_account_encumbrance",
    "royalty_distributor",
    "challenge_registry",
    "compute_credit_vault",
    "email_oracle_auth",
    "execution_policy_anchor",
  ];
  const roles = {
    diligence_room: "developer",
    tinker_account_encumbrance: "owner",
    royalty_distributor: "owner",
    challenge_registry: "owner",
    compute_credit_vault: "owner",
    email_oracle_auth: "owner",
    execution_policy_anchor: "owner",
  };
  if (!Array.isArray(value) || value.length !== keys.length) {
    fail("royalty release history receipt requires the exact seven-contract suite");
  }
  const contracts = value.map((entry, index) => {
    const parsed = exact(entry, [
      "address", "configuration_sha256", "contract_key", "control_address",
      "control_role", "runtime_code_hash",
    ], `royalty release receipt contract ${index}`);
    const key = keys[index];
    exactString(parsed.contract_key, key, `royalty release receipt contract ${index} key`);
    exactString(parsed.control_role, roles[key], `${key} control role`);
    return {
      contract_key: key,
      address: address(parsed.address, `${key} address`),
      runtime_code_hash: bytes32(parsed.runtime_code_hash, `${key} runtime code hash`),
      control_role: parsed.control_role,
      control_address: address(parsed.control_address, `${key} control address`),
      configuration_sha256: sha256(parsed.configuration_sha256, `${key} configuration digest`),
    };
  });
  if (new Set(contracts.map((entry) => entry.address)).size !== contracts.length) {
    fail("royalty release receipt contract addresses must be distinct");
  }
  return contracts;
}

const TX_SCHEMA = "dnai.base-sepolia-transaction-rpc-observation.v1";
const TX_DOMAIN = "dnai-wikigen/base-sepolia-transaction-rpc-observation/v1\0";
const RECEIPT_SCHEMA = "dnai.base-sepolia-receipt-rpc-observation.v1";
const RECEIPT_DOMAIN = "dnai-wikigen/base-sepolia-receipt-rpc-observation/v1\0";
const BLOCK_SCHEMA = "dnai.base-sepolia-finalized-block-rpc-observation.v1";
const BLOCK_DOMAIN = "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0";

function normalizeTransaction(value) {
  const parsed = exact(value, [
    "access_list_sha256", "block_hash", "block_number", "chain_id", "from",
    "gas_limit", "input_sha256", "max_fee_per_gas_wei",
    "max_priority_fee_per_gas_wei", "nonce", "schema", "to",
    "transaction_hash", "transaction_index", "transaction_type", "value_wei",
  ], "royalty mutation transaction observation");
  exactString(parsed.schema, TX_SCHEMA, "royalty mutation transaction schema");
  integer(parsed.chain_id, "royalty mutation transaction chain ID", CHAIN_ID, CHAIN_ID);
  integer(parsed.transaction_type, "royalty mutation transaction type", 2, 2);
  const gasLimit = decimal(parsed.gas_limit, "royalty mutation gas limit");
  const maxFee = decimal(parsed.max_fee_per_gas_wei, "royalty mutation max fee");
  const priority = decimal(
    parsed.max_priority_fee_per_gas_wei,
    "royalty mutation priority fee",
  );
  if (BigInt(gasLimit) === 0n || BigInt(maxFee) === 0n
    || BigInt(priority) > BigInt(maxFee)) {
    fail("royalty mutation gas and fee observations are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(parsed.transaction_hash, "royalty mutation transaction hash"),
    block_number: integer(parsed.block_number, "royalty mutation block number", 1),
    block_hash: bytes32(parsed.block_hash, "royalty mutation block hash"),
    transaction_index: integer(parsed.transaction_index, "royalty mutation index"),
    from: address(parsed.from, "royalty mutation signer"),
    to: address(parsed.to, "royalty mutation destination"),
    nonce: decimal(parsed.nonce, "royalty mutation nonce"),
    value_wei: decimal(parsed.value_wei, "royalty mutation value"),
    input_sha256: sha256(parsed.input_sha256, "royalty mutation calldata digest"),
    gas_limit: gasLimit,
    transaction_type: parsed.transaction_type,
    max_fee_per_gas_wei: maxFee,
    max_priority_fee_per_gas_wei: priority,
    access_list_sha256: sha256(parsed.access_list_sha256, "royalty mutation access list"),
  };
}

function transactionSha256(value) {
  return domainDigest(TX_DOMAIN, normalizeTransaction(value));
}

function normalizeLog(value, index) {
  const parsed = exact(value, [
    "address", "data", "log_index", "removed", "topics",
  ], `royalty mutation receipt log ${index}`);
  if (parsed.removed !== false || !Array.isArray(parsed.topics)
    || parsed.topics.length > 4) {
    fail(`royalty mutation receipt log ${index} is invalid`);
  }
  return {
    address: address(parsed.address, `royalty mutation log ${index} address`),
    topics: parsed.topics.map((topic, topicIndex) =>
      bytes32(topic, `royalty mutation log ${index} topic ${topicIndex}`)),
    data: hexData(parsed.data, `royalty mutation log ${index} data`),
    log_index: integer(parsed.log_index, `royalty mutation log ${index} index`),
    removed: false,
  };
}

function normalizeReceipt(value, { expectedStatus = 1 } = {}) {
  const parsed = exact(value, [
    "block_hash", "block_number", "chain_id", "contract_address",
    "cumulative_gas_used", "effective_gas_price_wei", "from", "gas_used",
    "logs", "logs_bloom", "schema", "status", "to", "transaction_hash",
    "transaction_index", "transaction_type",
  ], "royalty mutation receipt observation");
  exactString(parsed.schema, RECEIPT_SCHEMA, "royalty mutation receipt schema");
  integer(parsed.chain_id, "royalty mutation receipt chain ID", CHAIN_ID, CHAIN_ID);
  integer(expectedStatus, "expected royalty mutation receipt status", 0, 1);
  integer(
    parsed.status,
    "royalty mutation receipt status",
    expectedStatus,
    expectedStatus,
  );
  integer(parsed.transaction_type, "royalty mutation receipt type", 2, 2);
  const contractAddress = address(
    parsed.contract_address,
    "royalty mutation created contract",
    { allowZero: true },
  );
  if (contractAddress !== ZERO_ADDRESS) {
    fail("royalty configuration receipt must not create a contract");
  }
  const cumulative = decimal(parsed.cumulative_gas_used, "royalty cumulative gas");
  const gas = decimal(parsed.gas_used, "royalty gas used");
  const price = decimal(parsed.effective_gas_price_wei, "royalty effective gas price");
  if (BigInt(gas) === 0n || BigInt(cumulative) < BigInt(gas)
    || BigInt(price) === 0n || typeof parsed.logs_bloom !== "string"
    || !LOGS_BLOOM.test(parsed.logs_bloom)
    || !Array.isArray(parsed.logs) || parsed.logs.length > 256) {
    fail("royalty mutation receipt gas, bloom, or logs are invalid");
  }
  const logs = parsed.logs.map(normalizeLog);
  for (let index = 1; index < logs.length; index += 1) {
    if (logs[index].log_index <= logs[index - 1].log_index) {
      fail("royalty mutation receipt logs are not strictly ordered");
    }
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(parsed.transaction_hash, "royalty receipt transaction hash"),
    block_number: integer(parsed.block_number, "royalty receipt block number", 1),
    block_hash: bytes32(parsed.block_hash, "royalty receipt block hash"),
    transaction_index: integer(parsed.transaction_index, "royalty receipt transaction index"),
    from: address(parsed.from, "royalty receipt signer"),
    to: address(parsed.to, "royalty receipt destination"),
    contract_address: contractAddress,
    status: parsed.status,
    transaction_type: parsed.transaction_type,
    cumulative_gas_used: cumulative,
    gas_used: gas,
    effective_gas_price_wei: price,
    logs_bloom: parsed.logs_bloom,
    logs,
  };
}

function receiptSha256(value, options) {
  return domainDigest(RECEIPT_DOMAIN, normalizeReceipt(value, options));
}

function normalizeBlock(value) {
  const parsed = exact(value, [
    "base_fee_per_gas_wei", "block_hash", "block_number", "block_timestamp",
    "chain_id", "gas_limit", "gas_used", "parent_hash", "receipts_root",
    "schema", "state_root", "transactions_root",
  ], "royalty finalized block observation");
  exactString(parsed.schema, BLOCK_SCHEMA, "royalty finalized block schema");
  integer(parsed.chain_id, "royalty finalized block chain ID", CHAIN_ID, CHAIN_ID);
  const gasLimit = decimal(parsed.gas_limit, "royalty finalized block gas limit");
  const gasUsed = decimal(parsed.gas_used, "royalty finalized block gas used");
  const baseFee = decimal(parsed.base_fee_per_gas_wei, "royalty finalized block base fee");
  if (BigInt(gasLimit) === 0n || BigInt(gasUsed) > BigInt(gasLimit)
    || BigInt(baseFee) === 0n) {
    fail("royalty finalized block gas observations are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    block_number: integer(parsed.block_number, "royalty finalized block number", 1),
    block_hash: bytes32(parsed.block_hash, "royalty finalized block hash"),
    parent_hash: bytes32(parsed.parent_hash, "royalty finalized parent hash"),
    block_timestamp: integer(parsed.block_timestamp, "royalty finalized timestamp", 1),
    state_root: bytes32(parsed.state_root, "royalty finalized state root"),
    transactions_root: bytes32(parsed.transactions_root, "royalty finalized transactions root"),
    receipts_root: bytes32(parsed.receipts_root, "royalty finalized receipts root"),
    gas_limit: gasLimit,
    gas_used: gasUsed,
    base_fee_per_gas_wei: baseFee,
  };
}

function blockSha256(value) {
  return domainDigest(BLOCK_DOMAIN, normalizeBlock(value));
}

function normalizeCommonFinalizedState(value) {
  const parsed = exact(value, [
    "canonical_state_sha256", "independent_rpc_count", "latest_state_recheck_sha256",
    "primary_rpc_block", "primary_rpc_block_sha256", "primary_rpc_id_sha256",
    "primary_state_sha256", "secondary_rpc_block", "secondary_rpc_block_sha256",
    "secondary_rpc_id_sha256", "secondary_state_sha256",
  ], "royalty common finalized state");
  const primaryId = sha256(parsed.primary_rpc_id_sha256, "royalty primary RPC identity");
  const secondaryId = sha256(parsed.secondary_rpc_id_sha256, "royalty secondary RPC identity");
  if (primaryId === secondaryId) fail("royalty common state requires two RPC identities");
  const primaryBlock = normalizeBlock(parsed.primary_rpc_block);
  const secondaryBlock = normalizeBlock(parsed.secondary_rpc_block);
  const primaryBlockSha = blockSha256(primaryBlock);
  const secondaryBlockSha = blockSha256(secondaryBlock);
  const normalized = {
    independent_rpc_count: integer(parsed.independent_rpc_count, "royalty RPC count", 2, 2),
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha,
    primary_state_sha256: sha256(parsed.primary_state_sha256, "royalty primary state digest"),
    secondary_state_sha256: sha256(parsed.secondary_state_sha256, "royalty secondary state digest"),
    canonical_state_sha256: sha256(parsed.canonical_state_sha256, "royalty canonical state digest"),
    latest_state_recheck_sha256: sha256(parsed.latest_state_recheck_sha256, "royalty state recheck digest"),
  };
  if (parsed.primary_rpc_block_sha256 !== primaryBlockSha
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha
    || primaryBlockSha !== secondaryBlockSha
    || normalized.primary_state_sha256 !== normalized.secondary_state_sha256
    || normalized.primary_state_sha256 !== normalized.canonical_state_sha256) {
    fail("royalty common finalized dual-RPC observations disagree");
  }
  return normalized;
}

function commonFinalizedStateSha256(value) {
  return domainDigest(
    "dnai-wikigen/common-finalized-state/v2\0",
    normalizeCommonFinalizedState(value),
  );
}

function normalizeStateEvidence(value, { authority, phase, commonFinalizedState }) {
  const parsed = exact(value, [
    "phase", "primary_rpc_block", "primary_rpc_block_sha256",
    "primary_rpc_id_sha256", "primary_rpc_state", "primary_rpc_state_sha256",
    "secondary_rpc_block", "secondary_rpc_block_sha256",
    "secondary_rpc_id_sha256", "secondary_rpc_state",
    "secondary_rpc_state_sha256",
  ], `royalty ${phase} state evidence`);
  exactString(parsed.phase, phase, `royalty ${phase} evidence phase`);
  const primaryId = sha256(parsed.primary_rpc_id_sha256, `royalty ${phase} primary RPC`);
  const secondaryId = sha256(parsed.secondary_rpc_id_sha256, `royalty ${phase} secondary RPC`);
  if (primaryId === secondaryId
    || primaryId !== commonFinalizedState.primary_rpc_id_sha256
    || secondaryId !== commonFinalizedState.secondary_rpc_id_sha256) {
    fail(`royalty ${phase} state does not use the common dual-RPC authority`);
  }
  const primaryBlock = normalizeBlock(parsed.primary_rpc_block);
  const secondaryBlock = normalizeBlock(parsed.secondary_rpc_block);
  const primaryBlockSha = blockSha256(primaryBlock);
  const secondaryBlockSha = blockSha256(secondaryBlock);
  const primaryState = normalizeRoyaltyReleaseState(parsed.primary_rpc_state, {
    authority,
    phase,
  });
  const secondaryState = normalizeRoyaltyReleaseState(parsed.secondary_rpc_state, {
    authority,
    phase,
  });
  const primaryStateSha = royaltyReleaseStateSha256(primaryState, { authority, phase });
  const secondaryStateSha = royaltyReleaseStateSha256(secondaryState, { authority, phase });
  if (parsed.primary_rpc_block_sha256 !== primaryBlockSha
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha
    || primaryBlockSha !== secondaryBlockSha
    || parsed.primary_rpc_state_sha256 !== primaryStateSha
    || parsed.secondary_rpc_state_sha256 !== secondaryStateSha
    || primaryStateSha !== secondaryStateSha
    || canonicalText(primaryState) !== canonicalText(secondaryState)
    || primaryState.block_number !== primaryBlock.block_number
    || primaryState.block_hash !== primaryBlock.block_hash
    || primaryState.block_timestamp !== primaryBlock.block_timestamp
    || primaryBlock.block_number > commonFinalizedState.primary_rpc_block.block_number) {
    fail(`royalty ${phase} independent RPC state observations disagree`);
  }
  if (phase === "phase_two_active"
    && (primaryBlockSha !== commonFinalizedState.primary_rpc_block_sha256
      || secondaryBlockSha !== commonFinalizedState.secondary_rpc_block_sha256)) {
    fail("active RoyaltyDistributor state must use the exact common finalized block");
  }
  return {
    phase,
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha,
    primary_rpc_state: primaryState,
    primary_rpc_state_sha256: primaryStateSha,
    secondary_rpc_state: secondaryState,
    secondary_rpc_state_sha256: secondaryStateSha,
  };
}

function normalizeMutation(value, {
  authority,
  operation,
  commonFinalizedState,
  expectedReceiptStatus = 1,
}) {
  const parsed = exact(value, [
    "operation", "primary_rpc_block", "primary_rpc_block_sha256",
    "primary_rpc_id_sha256", "primary_rpc_receipt",
    "primary_rpc_receipt_sha256", "primary_rpc_transaction",
    "primary_rpc_transaction_sha256", "secondary_rpc_block",
    "secondary_rpc_block_sha256", "secondary_rpc_id_sha256",
    "secondary_rpc_receipt", "secondary_rpc_receipt_sha256",
    "secondary_rpc_transaction", "secondary_rpc_transaction_sha256",
  ], `royalty ${operation} mutation evidence`);
  exactString(parsed.operation, operation, `royalty ${operation} operation`);
  const primaryId = sha256(parsed.primary_rpc_id_sha256, `royalty ${operation} primary RPC`);
  const secondaryId = sha256(parsed.secondary_rpc_id_sha256, `royalty ${operation} secondary RPC`);
  if (primaryId === secondaryId
    || primaryId !== commonFinalizedState.primary_rpc_id_sha256
    || secondaryId !== commonFinalizedState.secondary_rpc_id_sha256) {
    fail(`royalty ${operation} does not use the common dual-RPC authority`);
  }
  const primaryTransaction = normalizeTransaction(parsed.primary_rpc_transaction);
  const secondaryTransaction = normalizeTransaction(parsed.secondary_rpc_transaction);
  const primaryReceipt = normalizeReceipt(parsed.primary_rpc_receipt, {
    expectedStatus: expectedReceiptStatus,
  });
  const secondaryReceipt = normalizeReceipt(parsed.secondary_rpc_receipt, {
    expectedStatus: expectedReceiptStatus,
  });
  const primaryBlock = normalizeBlock(parsed.primary_rpc_block);
  const secondaryBlock = normalizeBlock(parsed.secondary_rpc_block);
  const transactionSha = transactionSha256(primaryTransaction);
  const secondaryTransactionSha = transactionSha256(secondaryTransaction);
  const receiptSha = receiptSha256(primaryReceipt, {
    expectedStatus: expectedReceiptStatus,
  });
  const secondaryReceiptSha = receiptSha256(secondaryReceipt, {
    expectedStatus: expectedReceiptStatus,
  });
  const canonicalBlockSha = blockSha256(primaryBlock);
  const secondaryBlockSha = blockSha256(secondaryBlock);
  if (parsed.primary_rpc_transaction_sha256 !== transactionSha
    || parsed.secondary_rpc_transaction_sha256 !== secondaryTransactionSha
    || parsed.primary_rpc_receipt_sha256 !== receiptSha
    || parsed.secondary_rpc_receipt_sha256 !== secondaryReceiptSha
    || parsed.primary_rpc_block_sha256 !== canonicalBlockSha
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha
    || transactionSha !== secondaryTransactionSha
    || receiptSha !== secondaryReceiptSha
    || canonicalBlockSha !== secondaryBlockSha
    || primaryTransaction.from !== authority.owner
    || primaryTransaction.to !== authority.distributor_address
    || primaryTransaction.value_wei !== "0"
    || primaryTransaction.input_sha256
      !== royaltyReleaseMutationCalldataSha256(operation, authority)
    || primaryTransaction.transaction_hash !== primaryReceipt.transaction_hash
    || primaryTransaction.block_number !== primaryReceipt.block_number
    || primaryTransaction.block_hash !== primaryReceipt.block_hash
    || primaryTransaction.transaction_index !== primaryReceipt.transaction_index
    || primaryTransaction.from !== primaryReceipt.from
    || primaryTransaction.to !== primaryReceipt.to
    || primaryTransaction.block_number !== primaryBlock.block_number
    || primaryTransaction.block_hash !== primaryBlock.block_hash
    || primaryBlock.block_number > commonFinalizedState.primary_rpc_block.block_number) {
    fail(`royalty ${operation} dual-RPC mutation evidence is invalid`);
  }
  return {
    operation,
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_transaction: primaryTransaction,
    primary_rpc_transaction_sha256: transactionSha,
    secondary_rpc_transaction: secondaryTransaction,
    secondary_rpc_transaction_sha256: secondaryTransactionSha,
    primary_rpc_receipt: primaryReceipt,
    primary_rpc_receipt_sha256: receiptSha,
    secondary_rpc_receipt: secondaryReceipt,
    secondary_rpc_receipt_sha256: secondaryReceiptSha,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: canonicalBlockSha,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha,
  };
}

function precedes(left, right) {
  return left.primary_rpc_transaction.block_number
      < right.primary_rpc_transaction.block_number
    || (left.primary_rpc_transaction.block_number
        === right.primary_rpc_transaction.block_number
      && left.primary_rpc_transaction.transaction_index
        < right.primary_rpc_transaction.transaction_index);
}

function assertGloballyConsistentHistory({
  fresh,
  proposal,
  pending,
  activation,
  revertedUnpause,
  unpause,
  active,
}) {
  const mutations = [proposal, activation, revertedUnpause, unpause]
    .filter((entry) => entry !== null);
  const transactionHashes = mutations.map(
    (entry) => entry.primary_rpc_transaction.transaction_hash,
  );
  const nonces = mutations.map(
    (entry) => BigInt(entry.primary_rpc_transaction.nonce),
  );
  if (new Set(transactionHashes).size !== transactionHashes.length) {
    fail("royalty release history reuses a transaction hash across phases");
  }
  for (let index = 1; index < nonces.length; index += 1) {
    if (nonces[index] <= nonces[index - 1]) {
      fail("royalty release mutation nonces must strictly increase across phases");
    }
  }

  const citedBlocks = [
    fresh.primary_rpc_block,
    proposal.primary_rpc_block,
    pending.primary_rpc_block,
    activation.primary_rpc_block,
    ...(revertedUnpause ? [revertedUnpause.primary_rpc_block] : []),
    unpause.primary_rpc_block,
    active.primary_rpc_block,
  ];
  const byHeight = new Map();
  for (const block of citedBlocks) {
    const existing = byHeight.get(block.block_number);
    if (existing !== undefined && canonicalText(existing) !== canonicalText(block)) {
      fail("royalty release history cites conflicting blocks at one height");
    }
    byHeight.set(block.block_number, block);
  }
  for (let index = 1; index < citedBlocks.length; index += 1) {
    const previous = citedBlocks[index - 1];
    const current = citedBlocks[index];
    if (current.block_number < previous.block_number
      || current.block_timestamp < previous.block_timestamp) {
      fail("royalty release history block heights and timestamps must be monotone");
    }
  }
}

function requireEvent(mutation, authority, pendingAuthorityActivatesAt = 0) {
  const expected = royaltyReleaseMutationEvent(mutation.operation, authority, {
    pendingAuthorityActivatesAt,
  });
  const logs = mutation.primary_rpc_receipt.logs;
  if (logs.length !== 1 || logs[0].address !== expected.address
    || canonicalText(logs[0].topics) !== canonicalText(expected.topics)
    || logs[0].data !== expected.data) {
    fail(`royalty ${mutation.operation} receipt does not contain the exact event`);
  }
}

function normalizeHistory(value, { contracts, commonFinalizedState }) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("royalty release history must be an object");
  }
  const isV1 = value.schema === ROYALTY_RELEASE_HISTORY_SCHEMA;
  const isV2 = value.schema === ROYALTY_RELEASE_HISTORY_V2_SCHEMA;
  if (!isV1 && !isV2) fail("royalty history schema is unsupported");
  const parsed = exact(value, isV1 ? [
    "authority", "fresh_state", "phase_one", "phase_two", "schema",
  ] : [
    "authority", "execution_mode", "fresh_state", "phase_one", "phase_two",
    "schema",
  ], "royalty release history");
  const executionMode = isV1 ? "activate_and_unpause" : parsed.execution_mode;
  if (!ROYALTY_RELEASE_EXECUTION_MODES.includes(executionMode)) {
    fail("royalty release execution mode is unsupported");
  }
  const authority = normalizeRoyaltyReleaseAuthority(parsed.authority);
  const royalty = contracts.find((entry) => entry.contract_key === "royalty_distributor");
  const anchor = contracts.find((entry) => entry.contract_key === "execution_policy_anchor");
  if (!royalty || !anchor || royalty.address !== authority.distributor_address
    || royalty.control_role !== "owner" || royalty.control_address !== authority.owner
    || anchor.address !== authority.execution_policy_anchor) {
    fail("royalty release authority drifts from the seven-contract receipt");
  }
  const fresh = normalizeStateEvidence(parsed.fresh_state, {
    authority,
    phase: "fresh",
    commonFinalizedState,
  });
  const phaseOne = exact(parsed.phase_one, [
    "poststate", "proposal_transaction",
  ], "royalty phase-one history");
  const proposal = normalizeMutation(phaseOne.proposal_transaction, {
    authority,
    operation: "propose_authority_binding",
    commonFinalizedState,
  });
  const pending = normalizeStateEvidence(phaseOne.poststate, {
    authority,
    phase: "phase_one_pending",
    commonFinalizedState,
  });
  const recovering = executionMode === "recover_reverted_unpause";
  const phaseTwo = exact(parsed.phase_two, recovering ? [
    "activation_transaction", "poststate", "reverted_unpause_transaction",
    "unpause_transaction",
  ] : [
    "activation_transaction", "poststate", "unpause_transaction",
  ], "royalty phase-two history");
  const activation = normalizeMutation(phaseTwo.activation_transaction, {
    authority,
    operation: "activate_authority_proposal",
    commonFinalizedState,
  });
  const revertedUnpause = recovering
    ? normalizeMutation(phaseTwo.reverted_unpause_transaction, {
      authority,
      operation: "unpause",
      commonFinalizedState,
      expectedReceiptStatus: 0,
    })
    : null;
  const unpause = normalizeMutation(phaseTwo.unpause_transaction, {
    authority,
    operation: "unpause",
    commonFinalizedState,
  });
  const active = normalizeStateEvidence(phaseTwo.poststate, {
    authority,
    phase: "phase_two_active",
    commonFinalizedState,
  });
  const activatesAt = pending.primary_rpc_state.pending_authority_activates_at;
  if (fresh.primary_rpc_block.block_number >= proposal.primary_rpc_block.block_number
    || proposal.primary_rpc_block_sha256 !== pending.primary_rpc_block_sha256
    || activatesAt !== proposal.primary_rpc_block.block_timestamp
      + ROYALTY_AUTHORITY_TIMELOCK_SECONDS
    || !precedes(proposal, activation)
    || activation.primary_rpc_block.block_timestamp < activatesAt
    || unpause.primary_rpc_block.block_number > active.primary_rpc_block.block_number) {
    fail("royalty release history ordering, timelock, or boundary is invalid");
  }
  if (!recovering
    && (!precedes(activation, unpause)
      || BigInt(unpause.primary_rpc_transaction.nonce)
        !== BigInt(activation.primary_rpc_transaction.nonce) + 1n)) {
    fail("normal royalty activation and unpause must be contiguous");
  }
  if (recovering
    && (!precedes(activation, revertedUnpause)
      || !precedes(revertedUnpause, unpause)
      || BigInt(revertedUnpause.primary_rpc_transaction.nonce)
        !== BigInt(activation.primary_rpc_transaction.nonce) + 1n
      || BigInt(unpause.primary_rpc_transaction.nonce)
        !== BigInt(revertedUnpause.primary_rpc_transaction.nonce) + 1n
      || revertedUnpause.primary_rpc_receipt.logs.length !== 0
      || new Set([
        activation.primary_rpc_transaction.transaction_hash,
        revertedUnpause.primary_rpc_transaction.transaction_hash,
        unpause.primary_rpc_transaction.transaction_hash,
      ]).size !== 3)) {
    fail("royalty recovery must prove one finalized reverted unpause and its contiguous retry");
  }
  assertGloballyConsistentHistory({
    fresh,
    proposal,
    pending,
    activation,
    revertedUnpause,
    unpause,
    active,
  });
  requireEvent(proposal, authority, activatesAt);
  requireEvent(activation, authority);
  requireEvent(unpause, authority);
  const normalized = {
    schema: parsed.schema,
    authority,
    fresh_state: fresh,
    phase_one: { proposal_transaction: proposal, poststate: pending },
    phase_two: {
      activation_transaction: activation,
      unpause_transaction: unpause,
      poststate: active,
    },
  };
  if (isV2) normalized.execution_mode = executionMode;
  if (recovering) {
    normalized.phase_two = {
      activation_transaction: activation,
      reverted_unpause_transaction: revertedUnpause,
      unpause_transaction: unpause,
      poststate: active,
    };
  }
  return normalized;
}

function historySha256(value, options) {
  const history = normalizeHistory(value, options);
  return domainDigest(
    history.schema === ROYALTY_RELEASE_HISTORY_V2_SCHEMA
      ? ROYALTY_RELEASE_HISTORY_V2_DOMAIN
      : ROYALTY_RELEASE_HISTORY_DOMAIN,
    history,
  );
}

export function normalizeRoyaltyReleaseHistory(value, options) {
  return normalizeHistory(value, options);
}

export function royaltyReleaseHistorySha256(value, options) {
  return historySha256(value, options);
}

export function normalizeRoyaltyReleaseHistoryReceipt(value) {
  assertBounded(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("royalty release history receipt must be an object");
  }
  const isV1 = value.schema === ROYALTY_RELEASE_HISTORY_RECEIPT_SCHEMA;
  const isV2 = value.schema === ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA;
  if (!isV1 && !isV2) fail("H schema is unsupported");
  const parsed = exact(value, isV1 ? [
    "common_finalized_state", "common_finalized_state_sha256", "contracts",
    "royalty_release_active_state", "royalty_release_authority",
    "royalty_release_history", "royalty_release_history_sha256", "schema",
    "truth_status",
  ] : [
    "common_finalized_state", "common_finalized_state_sha256", "contracts",
    "execution_mode", "royalty_release_active_state",
    "royalty_release_authority", "royalty_release_history",
    "royalty_release_history_sha256", "schema", "truth_status",
  ], "royalty release history receipt");
  const executionMode = isV1 ? "activate_and_unpause" : parsed.execution_mode;
  if (!ROYALTY_RELEASE_EXECUTION_MODES.includes(executionMode)) {
    fail("H royalty release execution mode is unsupported");
  }
  exactString(
    parsed.truth_status,
    ROYALTY_RELEASE_HISTORY_RECEIPT_TRUTH_STATUS,
    "H truth status",
  );
  const contracts = normalizeContracts(parsed.contracts);
  const commonFinalizedState = normalizeCommonFinalizedState(
    parsed.common_finalized_state,
  );
  const commonSha = commonFinalizedStateSha256(commonFinalizedState);
  if (parsed.common_finalized_state_sha256 !== commonSha) {
    fail("H common finalized state digest is invalid");
  }
  const history = normalizeHistory(parsed.royalty_release_history, {
    contracts,
    commonFinalizedState,
  });
  if ((isV1 && history.schema !== ROYALTY_RELEASE_HISTORY_SCHEMA)
    || (isV2 && (history.schema !== ROYALTY_RELEASE_HISTORY_V2_SCHEMA
      || history.execution_mode !== executionMode))) {
    fail("H schema or execution mode drifts from its royalty release history");
  }
  const historySha = historySha256(history, { contracts, commonFinalizedState });
  if (parsed.royalty_release_history_sha256 !== historySha) {
    fail("H royalty release history digest is invalid");
  }
  const authority = normalizeRoyaltyReleaseAuthority(
    parsed.royalty_release_authority,
  );
  const activeState = normalizeRoyaltyReleaseState(
    parsed.royalty_release_active_state,
    { authority, phase: "phase_two_active" },
  );
  if (canonicalText(authority) !== canonicalText(history.authority)
    || canonicalText(activeState)
      !== canonicalText(history.phase_two.poststate.primary_rpc_state)) {
    fail("H authority or active-state projection drifted from its history");
  }
  const normalized = {
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    contracts,
    common_finalized_state: commonFinalizedState,
    common_finalized_state_sha256: commonSha,
    royalty_release_history: history,
    royalty_release_history_sha256: historySha,
    royalty_release_authority: authority,
    royalty_release_active_state: activeState,
  };
  if (isV2) normalized.execution_mode = executionMode;
  return normalized;
}

export function projectRoyaltyReleaseHistoryReceipt({
  contracts,
  commonFinalizedState,
  royaltyReleaseHistory,
}) {
  const normalizedContracts = normalizeContracts(contracts);
  const common = normalizeCommonFinalizedState(commonFinalizedState);
  const history = normalizeHistory(royaltyReleaseHistory, {
    contracts: normalizedContracts,
    commonFinalizedState: common,
  });
  const isV2 = history.schema === ROYALTY_RELEASE_HISTORY_V2_SCHEMA;
  const projected = {
    schema: isV2
      ? ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA
      : ROYALTY_RELEASE_HISTORY_RECEIPT_SCHEMA,
    truth_status: ROYALTY_RELEASE_HISTORY_RECEIPT_TRUTH_STATUS,
    contracts: normalizedContracts,
    common_finalized_state: common,
    common_finalized_state_sha256: commonFinalizedStateSha256(common),
    royalty_release_history: history,
    royalty_release_history_sha256: historySha256(history, {
      contracts: normalizedContracts,
      commonFinalizedState: common,
    }),
    royalty_release_authority: history.authority,
    royalty_release_active_state:
      history.phase_two.poststate.primary_rpc_state,
  };
  if (isV2) projected.execution_mode = history.execution_mode;
  return normalizeRoyaltyReleaseHistoryReceipt(projected);
}

export function royaltyReleaseHistoryReceiptSha256(value) {
  const receipt = normalizeRoyaltyReleaseHistoryReceipt(value);
  return domainDigest(
    receipt.schema === ROYALTY_RELEASE_HISTORY_RECEIPT_V2_SCHEMA
      ? ROYALTY_RELEASE_HISTORY_RECEIPT_V2_DOMAIN
      : ROYALTY_RELEASE_HISTORY_RECEIPT_DOMAIN,
    receipt,
  );
}

export function canonicalRoyaltyReleaseHistoryReceiptText(value) {
  return canonicalText(normalizeRoyaltyReleaseHistoryReceipt(value));
}
