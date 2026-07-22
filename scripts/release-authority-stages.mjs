#!/usr/bin/env node

import { createHash } from "node:crypto";
import path from "node:path";

import {
  RELEASE_CEREMONY_LOCK_PROTOCOL,
} from "./release-ceremony-lock.mjs";
import {
  CVM_LAUNCH_DOMAINS,
} from "./cvm-launch-intent-core.mjs";
import {
  CEREMONY_AUTHORIZATION_CORE_DOMAIN,
  CEREMONY_AUTHORIZATION_CORE_SCHEMA,
  CEREMONY_AUTHORIZATION_CORE_STATUS,
  CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN,
  CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
  LIVE_ACTIVATION_AUTHORITY_DOMAIN,
  LIVE_ACTIVATION_AUTHORITY_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_STATUS,
  LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN,
  LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
  MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS,
  MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS,
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX,
  RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN,
  RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
  RELEASE_AUTHORITY_SIGNATURE_SCHEME,
  RELEASE_AUTHORITY_SIGNATURE_VERIFIER,
  RELEASE_CEREMONY_MUTATION_WRITERS,
  RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
  ReleaseAuthorityValidationError,
  assertReviewSignedUnderAnchoredReviewerStatus,
  ceremonyAuthorizationCoreSha256,
  frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization,
  normalizeCeremonyAuthorizationCore,
  normalizeCryptographicReview,
  normalizeReleaseReviewerAuthorityForStage,
  reviewSigningPayload,
  timestamp,
} from "./release-ceremony-authorization.mjs";
export {
  CEREMONY_AUTHORIZATION_CORE_DOMAIN,
  CEREMONY_AUTHORIZATION_CORE_SCHEMA,
  CEREMONY_AUTHORIZATION_CORE_STATUS,
  CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_DOMAIN,
  CEREMONY_AUTHORIZATION_REVIEW_SUBJECT_KIND,
  LIVE_ACTIVATION_AUTHORITY_DOMAIN,
  LIVE_ACTIVATION_AUTHORITY_SCHEMA,
  LIVE_ACTIVATION_AUTHORITY_STATUS,
  LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN,
  LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
  MAX_RELEASE_AUTHORITY_REVIEW_LIFETIME_MS,
  MIN_RELEASE_AUTHORITY_REVIEW_HEADROOM_MS,
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX,
  RELEASE_AUTHORITY_REVIEW_SIGNING_DOMAIN,
  RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
  RELEASE_AUTHORITY_SIGNATURE_SCHEME,
  RELEASE_AUTHORITY_SIGNATURE_VERIFIER,
  RELEASE_CEREMONY_MUTATION_WRITERS,
  RELEASE_CEREMONY_TRANSACTION_PLAN_SCHEMA,
  ReleaseAuthorityValidationError,
  assertFreshProductionCeremonyAuthorizationCore,
  canonicalCeremonyAuthorizationCoreArtifactText,
  ceremonyAuthorizationCoreDigest,
  ceremonyAuthorizationCoreSha256,
  ceremonyAuthorizationReviewSigningPayload,
  ceremonyAuthorizationReviewSigningPayloadForProduction,
  ceremonyAuthorizationReviewSubjectSha256,
  frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization,
  normalizeCeremonyAuthorizationCore,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
  releaseCeremonyTransactionPlanSha256,
} from "./release-ceremony-authorization.mjs";
export {
  historicalLiveActivationAuthoritySha256,
  historicalLiveActivationFrontendBindingSha256,
  historicalLiveActivationReviewSigningPayload,
  historicalLiveActivationReviewSubjectSha256,
  normalizeHistoricalLiveActivationAuthority,
  normalizeHistoricalLiveActivationExpectedContext,
  normalizeHistoricalLiveActivationFrontendBinding,
  projectHistoricalLiveActivationExpectedContext,
  projectHistoricalLiveActivationFrontendBinding,
} from "./release-authority-historical-core.mjs";
export {
  assertExact37GenesisReviewerStatusCurrentForLiveActivation,
} from "./release-authority-current-reviewer-facade.mjs";
import {
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  normalizeComputeWorkloadActivationObservation,
  normalizeComputeWorkloadBrowserBinding,
  projectComputeWorkloadBrowserBindingFromHistoricalObservation,
} from "./compute-workload-activation-observation-core.mjs";
import {
  frontendBuildCandidateReceiptSha256,
  normalizeFrontendBuildCandidateReceipt,
} from "../web/scripts/frontend-build-candidate-core.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";

export const CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-transaction-rpc-observation.v1";
export const CEREMONY_TRANSACTION_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-transaction-rpc-observation/v1\0";
export const CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-receipt-rpc-observation.v1";
export const CEREMONY_RECEIPT_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-receipt-rpc-observation/v1\0";
export const COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA =
  "dnai.base-sepolia-finalized-block-rpc-observation.v1";
export const COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_DOMAIN =
  "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0";
export const EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA =
  "dnai.execution-policy-anchor-rpc-read.v1";
export const EXECUTION_POLICY_ANCHOR_RPC_READ_DOMAIN =
  "dnai-wikigen/execution-policy-anchor-rpc-read/v1\0";
export const LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA =
  "dnai.live-activation-frontend-binding.v3";
export const LIVE_ACTIVATION_FRONTEND_BINDING_DOMAIN =
  "dnai-wikigen/live-activation-frontend-binding/v3\0";
export const LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS =
  "derived_from_signed_live_activation_not_standalone_authority";

export const DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_SCHEMA =
  "dnai.final-release-authority-core.v3";
export const DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_STATUS =
  CEREMONY_AUTHORIZATION_CORE_STATUS;

const CHAIN_ID = 84_532;
const NETWORK_NAME = "base-sepolia";
const MAX_BYTES = 4 * 1024 * 1024;
const MAX_TRANSACTIONS = 512;
// Stage 1 authorizes irreversible on-chain mutations and Stage 2 authorizes
// opening the live service boundary.  These are short execution leases, not
// week-long review declarations.
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const HEX_DATA = /^0x(?:[0-9a-f]{2})*$/;
const LOGS_BLOOM = /^0x[0-9a-f]{512}$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;

export const RELEASE_CONTRACT_STATE_KEYS = Object.freeze([
  "diligence_room",
  "tinker_account_encumbrance",
  "royalty_distributor",
  "challenge_registry",
  "compute_credit_vault",
  "email_oracle_auth",
  "execution_policy_anchor",
]);

const CONTROL_ROLE_BY_CONTRACT = Object.freeze({
  diligence_room: "developer",
  tinker_account_encumbrance: "owner",
  royalty_distributor: "immutable_no_owner",
  challenge_registry: "owner",
  compute_credit_vault: "owner",
  email_oracle_auth: "owner",
  execution_policy_anchor: "owner",
});

const STAGE_TWO_DEPENDENCY_KINDS = Object.freeze([
  "ceremony_authorization",
  "immutable_deployment_manifest",
  "ceremony_ledger_initialization_receipt",
  "frozen_final_ceremony_ledger",
  "ceremony_ledger_finalization_receipt",
  "ceremony_ledger_revision_chain",
  "common_finalized_state",
  "contract_configuration_set",
  "challenge_genesis",
  "final_cvm_state",
  "cvm_measurements",
  "tdx_attestation_bundle",
  "qvl_policy_bundle",
  "post_measurement_activation_execution_receipt",
  "compute_workload_activation_observation",
  "compute_workload_browser_binding",
  "frontend_release_env",
  "frontend_build_candidate_receipt",
  "frontend_build",
]);

function fail(message) {
  throw new ReleaseAuthorityValidationError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, keys, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
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

function assertBoundedJson(value, label) {
  let text;
  try {
    text = JSON.stringify(value);
  } catch {
    fail(`${label} must be an acyclic JSON value`);
  }
  if (Buffer.byteLength(text, "utf8") > MAX_BYTES) fail(`${label} exceeds the byte bound`);
  const pending = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const entry = pending.pop();
    nodes += 1;
    if (nodes > 20_000 || entry.depth > 20) fail(`${label} exceeds structural bounds`);
    if (entry.value === null || typeof entry.value === "number") {
      if (entry.value === null || !Number.isSafeInteger(entry.value) || Object.is(entry.value, -0)) {
        fail(`${label} contains unsupported null or numeric values`);
      }
    } else if (typeof entry.value === "string" || typeof entry.value === "boolean") {
      // Accepted after field-specific normalization.
    } else if (Array.isArray(entry.value)) {
      if (entry.value.length > MAX_TRANSACTIONS * 4) fail(`${label} array is too large`);
      for (const child of entry.value) pending.push({ value: child, depth: entry.depth + 1 });
    } else if (isRecord(entry.value)) {
      if (Object.keys(entry.value).length > 128) fail(`${label} object is too large`);
      for (const child of Object.values(entry.value)) {
        pending.push({ value: child, depth: entry.depth + 1 });
      }
    } else {
      fail(`${label} contains non-JSON values`);
    }
  }
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function sha256(value, label) {
  if (!SHA256.test(value) || value === ZERO_SHA256) fail(`${label} must be a nonzero SHA-256 pin`);
  return value;
}

function bareSha256(value, label) {
  if (!BARE_SHA256.test(value) || value === "0".repeat(64)) fail(`${label} must be a nonzero bare SHA-256`);
  return value;
}

function address(value, label, { allowZero = false } = {}) {
  if (!ADDRESS.test(value) || (!allowZero && value === ZERO_ADDRESS)) fail(`${label} must be a canonical address`);
  return value;
}

function bytes32(value, label) {
  if (!BYTES32.test(value) || value === `0x${"0".repeat(64)}`) fail(`${label} must be nonzero bytes32`);
  return value;
}

function hexData(value, label, maximumBytes = 65_536) {
  if (!HEX_DATA.test(value) || (value.length - 2) / 2 > maximumBytes) {
    fail(`${label} must be bounded canonical lowercase hex data`);
  }
  return value;
}

function decimal(value, label) {
  if (!DECIMAL.test(value)) fail(`${label} must be a canonical uint256 decimal string`);
  try {
    if (BigInt(value) >= (1n << 256n)) fail(`${label} exceeds uint256`);
  } catch {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  return value;
}

function integer(value, label, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function canonicalPath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value) {
    fail(`${label} must be a canonical absolute path without aliases`);
  }
  return value;
}

function network(value, label) {
  const parsed = exact(value, ["chain_id", "name"], label);
  return {
    chain_id: integer(parsed.chain_id, `${label}.chain_id`, CHAIN_ID, CHAIN_ID),
    name: exactString(parsed.name, NETWORK_NAME, `${label}.name`),
  };
}

export function normalizeCeremonyTransactionRpcObservation(value) {
  const parsed = exact(value, [
    "access_list_sha256", "block_hash", "block_number", "chain_id", "from",
    "gas_limit", "input_sha256", "max_fee_per_gas_wei",
    "max_priority_fee_per_gas_wei", "nonce", "schema", "to",
    "transaction_hash", "transaction_index", "transaction_type", "value_wei",
  ], "ceremony transaction RPC observation");
  exactString(
    parsed.schema,
    CEREMONY_TRANSACTION_RPC_OBSERVATION_SCHEMA,
    "ceremony transaction observation schema",
  );
  integer(parsed.chain_id, "ceremony transaction chain ID", CHAIN_ID, CHAIN_ID);
  integer(parsed.transaction_type, "ceremony transaction type", 2, 2);
  const gasLimit = decimal(parsed.gas_limit, "ceremony transaction gas limit");
  const maxFee = decimal(parsed.max_fee_per_gas_wei, "ceremony transaction max fee");
  const maxPriorityFee = decimal(
    parsed.max_priority_fee_per_gas_wei,
    "ceremony transaction max priority fee",
  );
  if (BigInt(gasLimit) === 0n || BigInt(maxFee) === 0n || BigInt(maxPriorityFee) > BigInt(maxFee)) {
    fail("ceremony transaction gas and fee bounds are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(parsed.transaction_hash, "ceremony transaction hash"),
    block_number: integer(parsed.block_number, "ceremony transaction block number", 1),
    block_hash: bytes32(parsed.block_hash, "ceremony transaction block hash"),
    transaction_index: integer(parsed.transaction_index, "ceremony transaction index"),
    from: address(parsed.from, "ceremony transaction signer"),
    to: address(parsed.to, "ceremony transaction destination"),
    nonce: decimal(parsed.nonce, "ceremony transaction nonce"),
    value_wei: decimal(parsed.value_wei, "ceremony transaction value"),
    input_sha256: sha256(parsed.input_sha256, "ceremony transaction calldata"),
    gas_limit: gasLimit,
    transaction_type: parsed.transaction_type,
    max_fee_per_gas_wei: maxFee,
    max_priority_fee_per_gas_wei: maxPriorityFee,
    access_list_sha256: sha256(parsed.access_list_sha256, "ceremony transaction access list"),
  };
}

export function ceremonyTransactionRpcObservationSha256(value) {
  return domainDigest(
    CEREMONY_TRANSACTION_RPC_OBSERVATION_DOMAIN,
    normalizeCeremonyTransactionRpcObservation(value),
  );
}

function normalizeReceiptLog(value, index) {
  const parsed = exact(value, [
    "address", "data", "log_index", "removed", "topics",
  ], `ceremony receipt log ${index}`);
  if (parsed.removed !== false) fail(`ceremony receipt log ${index} must be canonical and not removed`);
  if (!Array.isArray(parsed.topics) || parsed.topics.length > 4) {
    fail(`ceremony receipt log ${index} topics are invalid`);
  }
  return {
    address: address(parsed.address, `ceremony receipt log ${index} address`),
    topics: parsed.topics.map((entry, topicIndex) =>
      bytes32(entry, `ceremony receipt log ${index} topic ${topicIndex}`)),
    data: hexData(parsed.data, `ceremony receipt log ${index} data`),
    log_index: integer(parsed.log_index, `ceremony receipt log ${index} index`),
    removed: false,
  };
}

export function normalizeCeremonyReceiptRpcObservation(value) {
  const parsed = exact(value, [
    "block_hash", "block_number", "chain_id", "contract_address",
    "cumulative_gas_used", "effective_gas_price_wei", "from", "gas_used",
    "logs", "logs_bloom", "schema", "status", "to", "transaction_hash",
    "transaction_index", "transaction_type",
  ], "ceremony receipt RPC observation");
  exactString(
    parsed.schema,
    CEREMONY_RECEIPT_RPC_OBSERVATION_SCHEMA,
    "ceremony receipt observation schema",
  );
  integer(parsed.chain_id, "ceremony receipt chain ID", CHAIN_ID, CHAIN_ID);
  integer(parsed.transaction_type, "ceremony receipt transaction type", 2, 2);
  integer(parsed.status, "ceremony receipt status", 1, 1);
  const contractAddress = address(
    parsed.contract_address,
    "ceremony receipt contract address",
    { allowZero: true },
  );
  if (contractAddress !== ZERO_ADDRESS) {
    fail("ceremony configuration receipts must not create contracts");
  }
  const cumulativeGasUsed = decimal(
    parsed.cumulative_gas_used,
    "ceremony receipt cumulative gas used",
  );
  const gasUsed = decimal(parsed.gas_used, "ceremony receipt gas used");
  const effectiveGasPrice = decimal(
    parsed.effective_gas_price_wei,
    "ceremony receipt effective gas price",
  );
  if (BigInt(gasUsed) === 0n || BigInt(cumulativeGasUsed) < BigInt(gasUsed)
    || BigInt(effectiveGasPrice) === 0n) {
    fail("ceremony receipt gas observations are invalid");
  }
  if (!Array.isArray(parsed.logs) || parsed.logs.length > 256) {
    fail("ceremony receipt logs exceed the exact bound");
  }
  const logs = parsed.logs.map(normalizeReceiptLog);
  for (let index = 1; index < logs.length; index += 1) {
    if (logs[index].log_index <= logs[index - 1].log_index) {
      fail("ceremony receipt logs must be strictly ordered by log index");
    }
  }
  if (!LOGS_BLOOM.test(parsed.logs_bloom)) {
    fail("ceremony receipt logs bloom must be canonical 256-byte lowercase hex");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    transaction_hash: bytes32(parsed.transaction_hash, "ceremony receipt transaction hash"),
    block_number: integer(parsed.block_number, "ceremony receipt block number", 1),
    block_hash: bytes32(parsed.block_hash, "ceremony receipt block hash"),
    transaction_index: integer(parsed.transaction_index, "ceremony receipt transaction index"),
    from: address(parsed.from, "ceremony receipt signer"),
    to: address(parsed.to, "ceremony receipt destination"),
    contract_address: contractAddress,
    status: parsed.status,
    transaction_type: parsed.transaction_type,
    cumulative_gas_used: cumulativeGasUsed,
    gas_used: gasUsed,
    effective_gas_price_wei: effectiveGasPrice,
    logs_bloom: parsed.logs_bloom,
    logs,
  };
}

export function ceremonyReceiptRpcObservationSha256(value) {
  return domainDigest(
    CEREMONY_RECEIPT_RPC_OBSERVATION_DOMAIN,
    normalizeCeremonyReceiptRpcObservation(value),
  );
}

export function normalizeCommonFinalizedBlockRpcObservation(value) {
  const parsed = exact(value, [
    "base_fee_per_gas_wei", "block_hash", "block_number", "block_timestamp",
    "chain_id", "gas_limit", "gas_used", "parent_hash", "receipts_root",
    "schema", "state_root", "transactions_root",
  ], "finalized block RPC observation");
  exactString(
    parsed.schema,
    COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_SCHEMA,
    "finalized block observation schema",
  );
  integer(parsed.chain_id, "finalized block chain ID", CHAIN_ID, CHAIN_ID);
  const gasLimit = decimal(parsed.gas_limit, "finalized block gas limit");
  const gasUsed = decimal(parsed.gas_used, "finalized block gas used");
  const baseFee = decimal(parsed.base_fee_per_gas_wei, "finalized block base fee");
  if (BigInt(gasLimit) === 0n || BigInt(gasUsed) > BigInt(gasLimit) || BigInt(baseFee) === 0n) {
    fail("finalized block gas observations are invalid");
  }
  return {
    schema: parsed.schema,
    chain_id: parsed.chain_id,
    block_number: integer(parsed.block_number, "finalized block number", 1),
    block_hash: bytes32(parsed.block_hash, "finalized block hash"),
    parent_hash: bytes32(parsed.parent_hash, "finalized block parent hash"),
    block_timestamp: integer(parsed.block_timestamp, "finalized block timestamp", 1),
    state_root: bytes32(parsed.state_root, "finalized block state root"),
    transactions_root: bytes32(parsed.transactions_root, "finalized block transactions root"),
    receipts_root: bytes32(parsed.receipts_root, "finalized block receipts root"),
    gas_limit: gasLimit,
    gas_used: gasUsed,
    base_fee_per_gas_wei: baseFee,
  };
}

export function commonFinalizedBlockRpcObservationSha256(value) {
  return domainDigest(
    COMMON_FINALIZED_BLOCK_RPC_OBSERVATION_DOMAIN,
    normalizeCommonFinalizedBlockRpcObservation(value),
  );
}

function normalizeCeremonyTransactionEvidence(value, index, plan, rpcAuthority) {
  const parsed = exact(value, [
    "primary_rpc_block", "primary_rpc_block_sha256", "primary_rpc_receipt",
    "primary_rpc_id_sha256", "primary_rpc_receipt_sha256", "primary_rpc_transaction",
    "primary_rpc_transaction_sha256", "secondary_rpc_block",
    "secondary_rpc_block_sha256", "secondary_rpc_id_sha256", "secondary_rpc_receipt",
    "secondary_rpc_receipt_sha256", "secondary_rpc_transaction",
    "secondary_rpc_transaction_sha256", "sequence", "writer_id",
  ], `ceremony transaction evidence ${index}`);
  const planned = plan.transactions[index];
  if (!planned || parsed.sequence !== index || parsed.writer_id !== planned.writer_id) {
    fail(`ceremony transaction evidence ${index} does not match the signed Stage-1 plan`);
  }
  const primaryRpcId = sha256(parsed.primary_rpc_id_sha256, "primary ceremony RPC identity");
  const secondaryRpcId = sha256(parsed.secondary_rpc_id_sha256, "secondary ceremony RPC identity");
  if (primaryRpcId === secondaryRpcId
    || primaryRpcId !== rpcAuthority.primary_rpc_id_sha256
    || secondaryRpcId !== rpcAuthority.secondary_rpc_id_sha256) {
    fail(`ceremony transaction ${index} does not use the common independent RPC authority`);
  }
  const primaryTransaction = normalizeCeremonyTransactionRpcObservation(
    parsed.primary_rpc_transaction,
  );
  const secondaryTransaction = normalizeCeremonyTransactionRpcObservation(
    parsed.secondary_rpc_transaction,
  );
  const primaryReceipt = normalizeCeremonyReceiptRpcObservation(parsed.primary_rpc_receipt);
  const secondaryReceipt = normalizeCeremonyReceiptRpcObservation(parsed.secondary_rpc_receipt);
  const primaryBlock = normalizeCommonFinalizedBlockRpcObservation(parsed.primary_rpc_block);
  const secondaryBlock = normalizeCommonFinalizedBlockRpcObservation(parsed.secondary_rpc_block);
  const primaryTransactionSha = ceremonyTransactionRpcObservationSha256(primaryTransaction);
  const secondaryTransactionSha = ceremonyTransactionRpcObservationSha256(secondaryTransaction);
  const primaryReceiptSha = ceremonyReceiptRpcObservationSha256(primaryReceipt);
  const secondaryReceiptSha = ceremonyReceiptRpcObservationSha256(secondaryReceipt);
  const primaryBlockSha = commonFinalizedBlockRpcObservationSha256(primaryBlock);
  const secondaryBlockSha = commonFinalizedBlockRpcObservationSha256(secondaryBlock);
  if (parsed.primary_rpc_transaction_sha256 !== primaryTransactionSha
    || parsed.secondary_rpc_transaction_sha256 !== secondaryTransactionSha
    || parsed.primary_rpc_receipt_sha256 !== primaryReceiptSha
    || parsed.secondary_rpc_receipt_sha256 !== secondaryReceiptSha
    || parsed.primary_rpc_block_sha256 !== primaryBlockSha
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha) {
    fail(`ceremony transaction ${index} RPC observation digest is invalid`);
  }
  if (primaryTransactionSha !== secondaryTransactionSha
    || primaryReceiptSha !== secondaryReceiptSha
    || primaryBlockSha !== secondaryBlockSha) {
    fail(`ceremony transaction ${index} independent RPC observations disagree`);
  }
  if (primaryTransaction.from !== planned.signer_address
    || primaryTransaction.nonce !== planned.nonce
    || primaryTransaction.to !== planned.to
    || primaryTransaction.value_wei !== planned.value_wei
    || primaryTransaction.input_sha256 !== planned.calldata_sha256) {
    fail(`ceremony transaction evidence ${index} does not match the signed Stage-1 plan`);
  }
  if (primaryReceipt.transaction_hash !== primaryTransaction.transaction_hash
    || primaryReceipt.block_number !== primaryTransaction.block_number
    || primaryReceipt.block_hash !== primaryTransaction.block_hash
    || primaryReceipt.transaction_index !== primaryTransaction.transaction_index
    || primaryReceipt.from !== primaryTransaction.from
    || primaryReceipt.to !== primaryTransaction.to
    || primaryReceipt.transaction_type !== primaryTransaction.transaction_type
    || primaryBlock.block_number !== primaryTransaction.block_number
    || primaryBlock.block_hash !== primaryTransaction.block_hash) {
    fail(`ceremony transaction ${index} transaction, receipt, and historical block disagree`);
  }
  return {
    sequence: index,
    writer_id: parsed.writer_id,
    primary_rpc_id_sha256: primaryRpcId,
    secondary_rpc_id_sha256: secondaryRpcId,
    primary_rpc_transaction: primaryTransaction,
    primary_rpc_transaction_sha256: primaryTransactionSha,
    secondary_rpc_transaction: secondaryTransaction,
    secondary_rpc_transaction_sha256: secondaryTransactionSha,
    primary_rpc_receipt: primaryReceipt,
    primary_rpc_receipt_sha256: primaryReceiptSha,
    secondary_rpc_receipt: secondaryReceipt,
    secondary_rpc_receipt_sha256: secondaryReceiptSha,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha,
  };
}

function normalizeCommonFinalizedState(value) {
  const parsed = exact(value, [
    "canonical_state_sha256", "independent_rpc_count", "latest_state_recheck_sha256",
    "primary_rpc_block", "primary_rpc_block_sha256", "primary_rpc_id_sha256",
    "primary_state_sha256", "secondary_rpc_block", "secondary_rpc_block_sha256",
    "secondary_rpc_id_sha256", "secondary_state_sha256",
  ], "common finalized state");
  const primaryId = sha256(parsed.primary_rpc_id_sha256, "primary RPC identity");
  const secondaryId = sha256(parsed.secondary_rpc_id_sha256, "secondary RPC identity");
  if (primaryId === secondaryId) fail("common finalized state requires two independent RPC identities");
  const primaryBlock = normalizeCommonFinalizedBlockRpcObservation(parsed.primary_rpc_block);
  const secondaryBlock = normalizeCommonFinalizedBlockRpcObservation(parsed.secondary_rpc_block);
  const primaryBlockSha = commonFinalizedBlockRpcObservationSha256(primaryBlock);
  const secondaryBlockSha = commonFinalizedBlockRpcObservationSha256(secondaryBlock);
  if (parsed.primary_rpc_block_sha256 !== primaryBlockSha
    || parsed.secondary_rpc_block_sha256 !== secondaryBlockSha) {
    fail("common finalized block observation digest is invalid");
  }
  const normalized = {
    independent_rpc_count: integer(parsed.independent_rpc_count, "independent RPC count", 2, 2),
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: primaryBlockSha,
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: secondaryBlockSha,
    primary_state_sha256: sha256(parsed.primary_state_sha256, "primary finalized state"),
    secondary_state_sha256: sha256(parsed.secondary_state_sha256, "secondary finalized state"),
    canonical_state_sha256: sha256(parsed.canonical_state_sha256, "canonical finalized state"),
    latest_state_recheck_sha256: sha256(parsed.latest_state_recheck_sha256, "latest state recheck"),
  };
  if (primaryBlockSha !== secondaryBlockSha
    || normalized.primary_state_sha256 !== normalized.secondary_state_sha256
    || normalized.primary_state_sha256 !== normalized.canonical_state_sha256) {
    fail("independent RPC common finalized state observations disagree");
  }
  return normalized;
}

function normalizeContractEntries(value) {
  if (!Array.isArray(value) || value.length !== RELEASE_CONTRACT_STATE_KEYS.length) {
    fail("contract state must contain the exact seven-contract suite");
  }
  const contracts = value.map((entry, index) => {
    const contract = exact(entry, [
      "address", "configuration_sha256", "contract_key", "control_address",
      "control_role", "runtime_code_hash",
    ], `contract state ${index}`);
    const key = RELEASE_CONTRACT_STATE_KEYS[index];
    exactString(contract.contract_key, key, `contract state ${index} key`);
    exactString(contract.control_role, CONTROL_ROLE_BY_CONTRACT[key], `contract state ${key} control role`);
    const allowZero = key === "royalty_distributor";
    const controlAddress = address(contract.control_address, `${key} control address`, { allowZero });
    if (allowZero !== (controlAddress === ZERO_ADDRESS)) fail("RoyaltyDistributor alone must use immutable_no_owner with zero control address");
    return {
      contract_key: key,
      address: address(contract.address, `${key} address`),
      runtime_code_hash: bytes32(contract.runtime_code_hash, `${key} runtime code hash`),
      control_role: contract.control_role,
      control_address: controlAddress,
      configuration_sha256: sha256(contract.configuration_sha256, `${key} configuration digest`),
    };
  });
  if (new Set(contracts.map((entry) => entry.address)).size !== contracts.length) {
    fail("contract state addresses must be distinct");
  }
  return contracts;
}

export function normalizeExecutionPolicyAnchorRpcRead(value) {
  const parsed = exact(value, [
    "block_hash", "block_number", "chain_id", "contract_address",
    "deployment_intent_sha256_bytes32", "reviewer_authority_genesis_acceptance_sha256_bytes32",
    "schema",
  ], "ExecutionPolicyAnchor RPC read");
  exactString(
    parsed.schema,
    EXECUTION_POLICY_ANCHOR_RPC_READ_SCHEMA,
    "ExecutionPolicyAnchor RPC read schema",
  );
  return {
    schema: parsed.schema,
    chain_id: integer(parsed.chain_id, "ExecutionPolicyAnchor read chain ID", CHAIN_ID, CHAIN_ID),
    contract_address: address(parsed.contract_address, "ExecutionPolicyAnchor read address"),
    block_number: integer(parsed.block_number, "ExecutionPolicyAnchor read block number", 1),
    block_hash: bytes32(parsed.block_hash, "ExecutionPolicyAnchor read block hash"),
    deployment_intent_sha256_bytes32: bytes32(
      parsed.deployment_intent_sha256_bytes32,
      "ExecutionPolicyAnchor deployment intent commitment",
    ),
    reviewer_authority_genesis_acceptance_sha256_bytes32: bytes32(
      parsed.reviewer_authority_genesis_acceptance_sha256_bytes32,
      "ExecutionPolicyAnchor signed genesis acceptance commitment",
    ),
  };
}

export function executionPolicyAnchorRpcReadSha256(value) {
  return domainDigest(
    EXECUTION_POLICY_ANCHOR_RPC_READ_DOMAIN,
    normalizeExecutionPolicyAnchorRpcRead(value),
  );
}

function normalizeExecutionPolicyAnchorCommitment(value, {
  contracts,
  deploymentIntentSha256,
  reviewerGenesisAcceptanceSha256,
  commonFinalizedState,
}) {
  const parsed = exact(value, [
    "primary_rpc_read", "primary_rpc_read_sha256", "secondary_rpc_read",
    "secondary_rpc_read_sha256",
  ], "ExecutionPolicyAnchor commitment proof");
  const primaryRead = normalizeExecutionPolicyAnchorRpcRead(parsed.primary_rpc_read);
  const secondaryRead = normalizeExecutionPolicyAnchorRpcRead(parsed.secondary_rpc_read);
  const primarySha = executionPolicyAnchorRpcReadSha256(primaryRead);
  const secondarySha = executionPolicyAnchorRpcReadSha256(secondaryRead);
  if (parsed.primary_rpc_read_sha256 !== primarySha
    || parsed.secondary_rpc_read_sha256 !== secondarySha) {
    fail("ExecutionPolicyAnchor RPC read digest is invalid");
  }
  if (primarySha !== secondarySha) {
    fail("independent RPC ExecutionPolicyAnchor reads disagree");
  }
  const anchor = contracts.find((entry) => entry.contract_key === "execution_policy_anchor");
  const expectedDeploymentBytes32 = `0x${deploymentIntentSha256.slice(7)}`;
  const expectedAcceptanceBytes32 = `0x${reviewerGenesisAcceptanceSha256.slice(7)}`;
  if (primaryRead.contract_address !== anchor.address
    || primaryRead.deployment_intent_sha256_bytes32 !== expectedDeploymentBytes32
    || primaryRead.reviewer_authority_genesis_acceptance_sha256_bytes32
      !== expectedAcceptanceBytes32) {
    fail("ExecutionPolicyAnchor read does not match the signed deployment authority");
  }
  if (commonFinalizedState
    && (primaryRead.block_number !== commonFinalizedState.primary_rpc_block.block_number
      || primaryRead.block_hash !== commonFinalizedState.primary_rpc_block.block_hash)) {
    fail("ExecutionPolicyAnchor read must use the exact common finalized block");
  }
  return {
    primary_rpc_read: primaryRead,
    primary_rpc_read_sha256: primarySha,
    secondary_rpc_read: secondaryRead,
    secondary_rpc_read_sha256: secondarySha,
  };
}

function contractConfigurationSetPayload({
  contracts,
  challengeGenesisSha256,
  deploymentIntentSha256,
  reviewerGenesisAcceptanceSha256,
  executionPolicyAnchorCommitment,
}) {
  return {
    contracts,
    challenge_genesis_sha256: challengeGenesisSha256,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256: reviewerGenesisAcceptanceSha256,
    execution_policy_anchor_commitment: executionPolicyAnchorCommitment,
  };
}

function normalizeContractState(value, {
  expectedDeploymentIntentSha256,
  expectedReviewerGenesisAcceptanceSha256,
  commonFinalizedState,
}) {
  const parsed = exact(value, [
    "challenge_genesis_sha256", "configuration_set_sha256", "contracts",
    "deployment_intent_sha256", "execution_policy_anchor_commitment",
    "reviewer_authority_genesis_acceptance_sha256",
  ], "contract state");
  const contracts = normalizeContractEntries(parsed.contracts);
  const challengeGenesis = sha256(parsed.challenge_genesis_sha256, "challenge genesis digest");
  const deploymentIntentSha = sha256(parsed.deployment_intent_sha256, "deployment intent digest");
  const reviewerAcceptanceSha = sha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "reviewer authority genesis acceptance digest",
  );
  if (deploymentIntentSha !== expectedDeploymentIntentSha256
    || reviewerAcceptanceSha !== expectedReviewerGenesisAcceptanceSha256) {
    fail("contract state deployment authority commitments drifted from Stage 1");
  }
  const anchorCommitment = normalizeExecutionPolicyAnchorCommitment(
    parsed.execution_policy_anchor_commitment,
    {
      contracts,
      deploymentIntentSha256: deploymentIntentSha,
      reviewerGenesisAcceptanceSha256: reviewerAcceptanceSha,
      commonFinalizedState,
    },
  );
  const expectedConfiguration = domainDigest(
    "dnai-wikigen/live-contract-configuration-set/v2\0",
    contractConfigurationSetPayload({
      contracts,
      challengeGenesisSha256: challengeGenesis,
      deploymentIntentSha256: deploymentIntentSha,
      reviewerGenesisAcceptanceSha256: reviewerAcceptanceSha,
      executionPolicyAnchorCommitment: anchorCommitment,
    }),
  );
  if (parsed.configuration_set_sha256 !== expectedConfiguration) {
    fail("contract configuration set digest is invalid");
  }
  return {
    contracts,
    challenge_genesis_sha256: challengeGenesis,
    deployment_intent_sha256: deploymentIntentSha,
    reviewer_authority_genesis_acceptance_sha256: reviewerAcceptanceSha,
    execution_policy_anchor_commitment: anchorCommitment,
    configuration_set_sha256: expectedConfiguration,
  };
}

function boundedIdentifier(value, label) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._:-]{7,127}$/.test(value)) {
    fail(`${label} must be a canonical bounded identifier`);
  }
  return value;
}

function normalizeFinalCvms(value) {
  if (!Array.isArray(value) || value.length !== CVM_LAUNCH_DOMAINS.length) {
    fail("final CVM state must contain the exact seven CVMs");
  }
  const cvms = value.map((entry, index) => {
    const parsed = exact(entry, [
      "app_id", "attestation_evidence_sha256", "compose_hash_sha256", "cvm_id",
      "cvm_key", "tee_identity",
    ], `final CVM state ${index}`);
    exactString(parsed.cvm_key, CVM_LAUNCH_DOMAINS[index], `final CVM state ${index} key`);
    return {
      cvm_key: parsed.cvm_key,
      app_id: boundedIdentifier(parsed.app_id, `${parsed.cvm_key} app ID`),
      cvm_id: boundedIdentifier(parsed.cvm_id, `${parsed.cvm_key} CVM ID`),
      compose_hash_sha256: sha256(parsed.compose_hash_sha256, `${parsed.cvm_key} compose hash`),
      tee_identity: address(parsed.tee_identity, `${parsed.cvm_key} TEE identity`),
      attestation_evidence_sha256: sha256(
        parsed.attestation_evidence_sha256,
        `${parsed.cvm_key} attestation evidence`,
      ),
    };
  });
  if (new Set(cvms.map((entry) => entry.app_id)).size !== cvms.length
    || new Set(cvms.map((entry) => entry.cvm_id)).size !== cvms.length
    || new Set(cvms.map((entry) => entry.tee_identity)).size !== cvms.length) {
    fail("final CVM app IDs, CVM IDs, and TEE identities must be distinct");
  }
  return cvms;
}

export function liveContractConfigurationSetSha256({
  contracts,
  challengeGenesisSha256,
  deploymentIntentSha256,
  reviewerGenesisAcceptanceSha256,
  executionPolicyAnchorCommitment,
}) {
  const normalizedContracts = normalizeContractEntries(contracts);
  const challengeGenesis = sha256(challengeGenesisSha256, "challenge genesis digest");
  const deploymentIntent = sha256(deploymentIntentSha256, "deployment intent digest");
  const reviewerAcceptance = sha256(
    reviewerGenesisAcceptanceSha256,
    "reviewer authority genesis acceptance digest",
  );
  const anchorCommitment = normalizeExecutionPolicyAnchorCommitment(
    executionPolicyAnchorCommitment,
    {
      contracts: normalizedContracts,
      deploymentIntentSha256: deploymentIntent,
      reviewerGenesisAcceptanceSha256: reviewerAcceptance,
    },
  );
  return domainDigest(
    "dnai-wikigen/live-contract-configuration-set/v2\0",
    contractConfigurationSetPayload({
      contracts: normalizedContracts,
      challengeGenesisSha256: challengeGenesis,
      deploymentIntentSha256: deploymentIntent,
      reviewerGenesisAcceptanceSha256: reviewerAcceptance,
      executionPolicyAnchorCommitment: anchorCommitment,
    }),
  );
}

function normalizeStageTwoBody(value, ceremonyAuthorization) {
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "ceremony_finalization", "ceremony_transactions",
    "common_finalized_state", "contract_state", "network", "post_ceremony_evidence",
    "release_sha", "schema", "status", "truth_status",
  ], "live activation body");
  exactString(parsed.schema, LIVE_ACTIVATION_AUTHORITY_SCHEMA, "live activation schema");
  exactString(parsed.status, LIVE_ACTIVATION_AUTHORITY_STATUS, "live activation status");
  exactString(
    parsed.truth_status,
    "separately_signed_post_ceremony_live_activation_authority",
    "live activation truth status",
  );
  if (parsed.release_sha !== ceremonyAuthorization.release_sha) fail("live activation release SHA drifted from Stage 1");
  const normalizedNetwork = network(parsed.network, "live activation network");
  const ceremonyAuthorizationSha = domainDigest(
    CEREMONY_AUTHORIZATION_CORE_DOMAIN,
    ceremonyAuthorization,
  );
  if (parsed.ceremony_authorization_sha256 !== ceremonyAuthorizationSha) {
    fail("live activation does not bind the exact Stage-1 ceremony authorization");
  }
  const finalization = exact(parsed.ceremony_finalization, [
    "finalization_receipt_sha256", "frozen_final_ledger_bytes", "frozen_final_ledger_mode",
    "frozen_final_ledger_sha256", "immutable_deployment_manifest_sha256",
    "initialization_receipt_sha256", "ledger_path", "lock_protocol",
    "revision_chain_sha256", "revision_count",
  ], "ceremony finalization");
  const normalizedFinalization = {
    immutable_deployment_manifest_sha256: sha256(finalization.immutable_deployment_manifest_sha256, "immutable manifest digest"),
    initialization_receipt_sha256: sha256(finalization.initialization_receipt_sha256, "ledger initialization receipt digest"),
    ledger_path: canonicalPath(finalization.ledger_path, "final ceremony ledger path"),
    frozen_final_ledger_sha256: sha256(finalization.frozen_final_ledger_sha256, "frozen final ledger digest"),
    frozen_final_ledger_bytes: integer(finalization.frozen_final_ledger_bytes, "frozen final ledger bytes", 2, MAX_BYTES),
    frozen_final_ledger_mode: integer(finalization.frozen_final_ledger_mode, "frozen final ledger mode", 0o444, 0o444),
    finalization_receipt_sha256: sha256(finalization.finalization_receipt_sha256, "ledger finalization receipt digest"),
    revision_chain_sha256: sha256(finalization.revision_chain_sha256, "ledger revision chain digest"),
    revision_count: integer(
      finalization.revision_count,
      "ledger revision count",
      RELEASE_CEREMONY_MUTATION_WRITERS.length,
      RELEASE_CEREMONY_MUTATION_WRITERS.length,
    ),
    lock_protocol: exactString(finalization.lock_protocol, RELEASE_CEREMONY_LOCK_PROTOCOL, "finalization lock protocol"),
  };
  const stageOneManifest = ceremonyAuthorization.deployment_authority.immutable_deployment_manifest;
  const stageOneLedger = ceremonyAuthorization.ceremony_ledger_initialization;
  if (normalizedFinalization.immutable_deployment_manifest_sha256 !== stageOneManifest.sha256
    || normalizedFinalization.initialization_receipt_sha256 !== stageOneLedger.initialization_receipt_sha256
    || normalizedFinalization.ledger_path !== stageOneLedger.ledger_path
    || normalizedFinalization.frozen_final_ledger_sha256 === stageOneLedger.ledger_initial_sha256) {
    fail("ceremony finalization does not continue the exact Stage-1 ledger lineage");
  }
  if (!Array.isArray(parsed.ceremony_transactions)
    || parsed.ceremony_transactions.length !== ceremonyAuthorization.ceremony_transaction_plan.transactions.length) {
    fail("live activation must contain evidence for every Stage-1 ceremony transaction");
  }
  const commonState = normalizeCommonFinalizedState(parsed.common_finalized_state);
  const transactions = parsed.ceremony_transactions.map((entry, index) =>
    normalizeCeremonyTransactionEvidence(
      entry,
      index,
      ceremonyAuthorization.ceremony_transaction_plan,
      commonState,
    ));
  const stageOneSignedAt = timestamp(
    ceremonyAuthorization.review.signed_at,
    "Stage-1 review signed_at",
  );
  const stageOneExpiresAt = timestamp(
    ceremonyAuthorization.review.expires_at,
    "Stage-1 review expires_at",
  );
  if (transactions.some((entry) => {
    const milliseconds = entry.primary_rpc_block.block_timestamp * 1_000;
    return milliseconds < stageOneSignedAt || milliseconds >= stageOneExpiresAt;
  })) {
    fail("every ceremony transaction must be mined during the signed Stage-1 authorization window");
  }
  if (transactions.some((entry) =>
    entry.primary_rpc_block.block_number > commonState.primary_rpc_block.block_number)) {
    fail("common finalized block must cover every ceremony receipt");
  }
  const contractState = normalizeContractState(parsed.contract_state, {
    expectedDeploymentIntentSha256:
      ceremonyAuthorization.deployment_authority.deployment_intent_sha256,
    expectedReviewerGenesisAcceptanceSha256:
      ceremonyAuthorization.deployment_authority.reviewer_authority_genesis_acceptance_sha256,
    commonFinalizedState: commonState,
  });
  const post = exact(parsed.post_ceremony_evidence, [
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding", "cvm_measurements_sha256", "final_cvms",
    "frontend_build_candidate_receipt_sha256", "frontend_build_sha256",
    "frontend_release_env_sha256", "post_measurement_activation_execution_receipt",
    "post_measurement_activation_execution_receipt_sha256",
    "qvl_policy_bundle_sha256", "tdx_attestation_bundle_sha256",
  ], "post-ceremony evidence");
  let activationExecutionReceipt;
  try {
    activationExecutionReceipt =
      normalizePhalaPostMeasurementActivationExecutionReceipt(
        post.post_measurement_activation_execution_receipt,
      );
  } catch (error) {
    fail(`post-ceremony activation execution receipt is invalid: ${error.message}`);
  }
  const activationExecutionReceiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(
      activationExecutionReceipt,
    );
  const carriedActivationExecutionReceiptSha256 = sha256(
    post.post_measurement_activation_execution_receipt_sha256,
    "post-measurement activation execution receipt digest",
  );
  const finalCvms = normalizeFinalCvms(post.final_cvms);
  const mainRuntimeCvm = finalCvms.find((entry) =>
    entry.cvm_key === "main_runtime_cvm");
  const activationCompletedAt = Date.parse(
    activationExecutionReceipt.completed_at,
  );
  const activationStartedAt = Date.parse(
    activationExecutionReceipt.patch.attempt_recorded_at,
  );
  if (carriedActivationExecutionReceiptSha256
      !== activationExecutionReceiptSha256
    || activationExecutionReceipt.release_sha !== parsed.release_sha
    || activationExecutionReceipt.deployment_intent_sha256
      !== ceremonyAuthorization.deployment_authority.deployment_intent_sha256
    || activationExecutionReceipt.cvm_launch_intent_sha256
      !== ceremonyAuthorization.cvm_launch_intent_sha256
    || activationExecutionReceipt.pre_ceremony_runtime_authority_sha256
      !== ceremonyAuthorization.pre_ceremony_runtime_authority_sha256
    || activationExecutionReceipt.ceremony_authorization_sha256
      !== ceremonyAuthorizationSha
    || activationExecutionReceipt.target.app_id !== mainRuntimeCvm?.app_id
    || activationExecutionReceipt.target.cvm_id !== mainRuntimeCvm?.cvm_id
    || `sha256:${activationExecutionReceipt.target.compose_hash}`
      !== mainRuntimeCvm?.compose_hash_sha256
    || activationExecutionReceipt.post_restart_evidence
      .get_cvm_attestation_observation_sha256
      !== mainRuntimeCvm?.attestation_evidence_sha256
    || activationStartedAt < stageOneSignedAt
    || activationCompletedAt >= stageOneExpiresAt) {
    fail("post-ceremony activation execution receipt drifted from signed B, its execution window, or final main runtime");
  }
  return {
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    network: normalizedNetwork,
    ceremony_authorization_sha256: ceremonyAuthorizationSha,
    ceremony_finalization: normalizedFinalization,
    ceremony_transactions: transactions,
    common_finalized_state: commonState,
    contract_state: contractState,
    post_ceremony_evidence: {
      final_cvms: finalCvms,
      cvm_measurements_sha256: sha256(post.cvm_measurements_sha256, "CVM measurements digest"),
      tdx_attestation_bundle_sha256: sha256(post.tdx_attestation_bundle_sha256, "TDX attestation bundle digest"),
      qvl_policy_bundle_sha256: sha256(post.qvl_policy_bundle_sha256, "QVL policy bundle digest"),
      post_measurement_activation_execution_receipt:
        activationExecutionReceipt,
      post_measurement_activation_execution_receipt_sha256:
        activationExecutionReceiptSha256,
      compute_workload_activation_observation_sha256: sha256(
        post.compute_workload_activation_observation_sha256,
        "compute-workload activation observation digest",
      ),
      compute_workload_browser_binding: normalizeComputeWorkloadBrowserBinding(
        post.compute_workload_browser_binding,
      ),
      frontend_release_env_sha256: sha256(
        post.frontend_release_env_sha256,
        "frontend release environment digest",
      ),
      frontend_build_candidate_receipt_sha256: sha256(
        post.frontend_build_candidate_receipt_sha256,
        "frontend build candidate receipt digest",
      ),
      frontend_build_sha256: sha256(post.frontend_build_sha256, "frontend build digest"),
    },
  };
}

function commonStateDependencySha256(commonState) {
  return domainDigest("dnai-wikigen/common-finalized-state/v2\0", commonState);
}

function stageTwoDependencies(body) {
  const finalCvmStateSha256 = domainDigest(
    "dnai-wikigen/final-cvm-state/v1\0",
    body.post_ceremony_evidence.final_cvms,
  );
  const map = {
    ceremony_authorization: body.ceremony_authorization_sha256,
    immutable_deployment_manifest: body.ceremony_finalization.immutable_deployment_manifest_sha256,
    ceremony_ledger_initialization_receipt: body.ceremony_finalization.initialization_receipt_sha256,
    frozen_final_ceremony_ledger: body.ceremony_finalization.frozen_final_ledger_sha256,
    ceremony_ledger_finalization_receipt: body.ceremony_finalization.finalization_receipt_sha256,
    ceremony_ledger_revision_chain: body.ceremony_finalization.revision_chain_sha256,
    common_finalized_state: commonStateDependencySha256(body.common_finalized_state),
    contract_configuration_set: body.contract_state.configuration_set_sha256,
    challenge_genesis: body.contract_state.challenge_genesis_sha256,
    final_cvm_state: finalCvmStateSha256,
    cvm_measurements: body.post_ceremony_evidence.cvm_measurements_sha256,
    tdx_attestation_bundle: body.post_ceremony_evidence.tdx_attestation_bundle_sha256,
    qvl_policy_bundle: body.post_ceremony_evidence.qvl_policy_bundle_sha256,
    post_measurement_activation_execution_receipt:
      body.post_ceremony_evidence
        .post_measurement_activation_execution_receipt_sha256,
    compute_workload_activation_observation:
      body.post_ceremony_evidence.compute_workload_activation_observation_sha256,
    compute_workload_browser_binding: computeWorkloadBrowserBindingSha256(
      body.post_ceremony_evidence.compute_workload_browser_binding,
    ),
    frontend_release_env: body.post_ceremony_evidence.frontend_release_env_sha256,
    frontend_build_candidate_receipt:
      body.post_ceremony_evidence.frontend_build_candidate_receipt_sha256,
    frontend_build: body.post_ceremony_evidence.frontend_build_sha256,
  };
  return STAGE_TWO_DEPENDENCY_KINDS.map((kind) => ({ kind, sha256: map[kind] }));
}

function liveActivationReviewerHistories(options) {
  if (!isRecord(options)) {
    fail("live activation authority options must be an object");
  }
  if (Object.prototype.hasOwnProperty.call(options, "reviewerStatusHistory")) {
    fail("live activation authority rejects the ambiguous legacy reviewerStatusHistory option");
  }
  if (!Object.prototype.hasOwnProperty.call(options, "stageBReviewerStatusHistory")
    || !Array.isArray(options.stageBReviewerStatusHistory)
    || !Object.prototype.hasOwnProperty.call(options, "stageCReviewerStatusHistory")
    || !Array.isArray(options.stageCReviewerStatusHistory)) {
    fail("live activation authority requires exact stageBReviewerStatusHistory and stageCReviewerStatusHistory arrays");
  }
  return {
    stageBReviewerStatusHistory: options.stageBReviewerStatusHistory,
    stageCReviewerStatusHistory: options.stageCReviewerStatusHistory,
  };
}

function liveActivationStageBCeremonyOptions(options, stageBReviewerStatusHistory) {
  return {
    deploymentIntent: options.deploymentIntent,
    freshContractDeploymentReceipt: options.freshContractDeploymentReceipt,
    reviewerGenesis: options.reviewerGenesis,
    reviewerGenesisAcceptance: options.reviewerGenesisAcceptance,
    reviewerStatusHistory: stageBReviewerStatusHistory,
    preCeremonyRuntimeAuthority: options.preCeremonyRuntimeAuthority,
    computeWorkloadActivationObservationSha256:
      options.computeWorkloadActivationObservationSha256,
    checkedAtMs: options.checkedAtMs,
    // B is historical at C. Its review and selected status are revalidated at
    // the immutable B signing instant, not against the later C wall clock.
    enforceFreshness: false,
  };
}

function assertCompleteReviewerLineagePrefix(stageBReviewer, stageCReviewer) {
  const stageBLineage = stageBReviewer.completeStatusLineage;
  const stageCLineage = stageCReviewer.completeStatusLineage;
  if (!Array.isArray(stageBLineage) || !Array.isArray(stageCLineage)
    || stageBLineage.length > stageCLineage.length
    || stageBLineage.some((status, index) => (
      JSON.stringify(status) !== JSON.stringify(stageCLineage[index])
    ))) {
    fail("Stage B complete reviewer-status lineage must be an exact prefix of Stage C");
  }
}

function normalizeLiveActivationReviewerContext(options) {
  const {
    stageBReviewerStatusHistory,
    stageCReviewerStatusHistory,
  } = liveActivationReviewerHistories(options);
  const ceremonyAuthorization = normalizeCeremonyAuthorizationCore(
    options.ceremonyAuthorization,
    liveActivationStageBCeremonyOptions(options, stageBReviewerStatusHistory),
  );
  let stageBReviewer;
  let stageCReviewer;
  try {
    stageBReviewer = normalizeReleaseReviewerAuthorityForStage({
      reviewerGenesis: options.reviewerGenesis,
      reviewerGenesisAcceptance: options.reviewerGenesisAcceptance,
      reviewerStatusHistory: stageBReviewerStatusHistory,
      deploymentIntent: options.deploymentIntent,
      checkedAtMs: timestamp(
        ceremonyAuthorization.review.signed_at,
        "ceremony authorization review signed_at",
      ),
      enforceFreshness: true,
    });
    stageCReviewer = normalizeReleaseReviewerAuthorityForStage({
      reviewerGenesis: stageBReviewer.genesis,
      reviewerGenesisAcceptance: stageBReviewer.acceptance,
      reviewerStatusHistory: stageCReviewerStatusHistory,
      deploymentIntent: options.deploymentIntent,
      checkedAtMs: options.checkedAtMs ?? Date.now(),
      enforceFreshness: options.enforceFreshness ?? true,
    });
  } catch (error) {
    fail(`live activation reviewer authority is invalid: ${error.message}`);
  }
  assertCompleteReviewerLineagePrefix(stageBReviewer, stageCReviewer);
  return {
    ceremonyAuthorization,
    stageBReviewer,
    stageCReviewer,
    stageBReviewerStatusHistory,
    stageCReviewerStatusHistory,
  };
}

export function liveActivationReviewSubjectSha256(unsignedBody, options) {
  const { ceremonyAuthorization } = normalizeLiveActivationReviewerContext(options);
  const body = normalizeStageTwoBody(unsignedBody, ceremonyAuthorization);
  return domainDigest(LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN, body);
}

export function liveActivationReviewSigningPayload(unsignedBody, reviewMetadata, options) {
  const { ceremonyAuthorization, stageCReviewer } =
    normalizeLiveActivationReviewerContext(options);
  const body = normalizeStageTwoBody(unsignedBody, ceremonyAuthorization);
  const payload = reviewSigningPayload({
    schema: RELEASE_AUTHORITY_REVIEW_SIGNING_PAYLOAD_SCHEMA,
    stage: LIVE_ACTIVATION_AUTHORITY_STATUS,
    subject_kind: LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
    release_sha: body.release_sha,
    chain_id: CHAIN_ID,
    subject_sha256: domainDigest(LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN, body),
    dependencies: stageTwoDependencies(body),
    ...reviewMetadata,
    signature_scheme: RELEASE_AUTHORITY_SIGNATURE_SCHEME,
    signature_verifier: RELEASE_AUTHORITY_SIGNATURE_VERIFIER,
  });
  if (payload.reviewer_authority_genesis_sha256 !== stageCReviewer.genesisSha256
    || payload.reviewer_authority_genesis_acceptance_sha256
      !== stageCReviewer.acceptanceSha256
    || payload.reviewer_authority_current_status_epoch
      !== stageCReviewer.currentStatus.epoch
    || payload.reviewer_authority_current_status_sha256
      !== stageCReviewer.currentStatusSha256
    || payload.reviewer_root_hash
      !== stageCReviewer.authority.reviewer_root_hash
    || payload.reviewer_set_sha256
      !== stageCReviewer.authority.reviewer_set_sha256
    || JSON.stringify(payload.approved_reviewer_hashes)
      !== JSON.stringify(stageCReviewer.authority.approved_reviewer_hashes)) {
    fail("live activation signing metadata does not match the exact Stage C reviewer head");
  }
  return payload;
}

export function normalizeLiveActivationAuthority(value, options = {}) {
  assertBoundedJson(value, "live activation authority");
  const {
    ceremonyAuthorization,
    stageCReviewer: reviewerStage,
    stageCReviewerStatusHistory,
  } = normalizeLiveActivationReviewerContext(options);
  const reviewerGenesis = reviewerStage.genesis;
  const reviewerGenesisAcceptance = reviewerStage.acceptance;
  const checkedAtMs = options.checkedAtMs ?? Date.now();
  const enforceFreshness = options.enforceFreshness ?? true;
  const {
    authority: reviewerAuthority,
    currentStatus: reviewerCurrentStatus,
    currentStatusSha256: reviewerCurrentStatusSha256,
  } = reviewerStage;
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "ceremony_finalization", "ceremony_transactions",
    "common_finalized_state", "contract_state", "network", "post_ceremony_evidence",
    "release_sha", "review", "schema", "status", "truth_status",
  ], "live activation authority");
  const body = normalizeStageTwoBody(
    Object.fromEntries(Object.entries(parsed).filter(([key]) => key !== "review")),
    ceremonyAuthorization,
  );
  const subjectSha = domainDigest(LIVE_ACTIVATION_REVIEW_SUBJECT_DOMAIN, body);
  const review = normalizeCryptographicReview(parsed.review, {
    stage: LIVE_ACTIVATION_AUTHORITY_STATUS,
    subjectKind: LIVE_ACTIVATION_REVIEW_SUBJECT_KIND,
    subjectSha256: subjectSha,
    releaseSha: body.release_sha,
    dependencies: stageTwoDependencies(body),
    reviewerAuthority,
    reviewerGenesis,
    reviewerGenesisAcceptanceSha256: reviewerStage.acceptanceSha256,
    reviewerCurrentStatus,
    reviewerCurrentStatusSha256,
    checkedAtMs,
    enforceFreshness,
  });
  const activationExecutionReceipt =
    body.post_ceremony_evidence.post_measurement_activation_execution_receipt;
  const reviewSignedAt = timestamp(review.signed_at, "live activation review signed_at");
  if (reviewSignedAt < Date.parse(activationExecutionReceipt.completed_at)
    || reviewSignedAt
      >= activationExecutionReceipt.terminal_evidence_lease_expires_at * 1_000) {
    fail("live activation review was not signed after receipt completion within the terminal evidence lease");
  }
  assertReviewSignedUnderAnchoredReviewerStatus(review, {
    reviewerGenesis,
    reviewerGenesisAcceptance,
    reviewerStatusHistory: stageCReviewerStatusHistory,
    deploymentIntent: options.deploymentIntent,
  });
  return { ...body, review };
}

export function canonicalLiveActivationAuthorityArtifactText(value, options) {
  return canonicalText(normalizeLiveActivationAuthority(value, {
    ...options,
    enforceFreshness: false,
  }));
}

export function liveActivationAuthorityDigest(value, options) {
  return domainDigest(LIVE_ACTIVATION_AUTHORITY_DOMAIN, normalizeLiveActivationAuthority(value, {
    ...options,
    enforceFreshness: false,
  })).slice(7);
}

export function liveActivationAuthoritySha256(value, options) {
  return `sha256:${liveActivationAuthorityDigest(value, options)}`;
}

export function assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
  activationExecutionReceipt: receiptValue,
  activationExecutionReceiptSha256: carriedReceiptSha256,
  observation: observationValue,
} = {}) {
  const receipt = normalizePhalaPostMeasurementActivationExecutionReceipt(
    receiptValue,
  );
  const receiptSha256 =
    phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
  const carriedSha256 = sha256(
    carriedReceiptSha256,
    "carried activation execution receipt digest",
  );
  const observation = normalizeComputeWorkloadActivationObservation(
    observationValue,
  );
  const lineage = observation.lineage;
  const mainRuntime = observation.main_runtime;
  const verification = observation.verification;
  const recipient = observation.recipient;
  const activation = receipt.recipient_activation;
  if (carriedSha256 !== receiptSha256
    || observation.release_sha !== receipt.release_sha
    || lineage.post_measurement_activation_execution_receipt_sha256
      !== receiptSha256
    || lineage.deployment_intent_sha256 !== receipt.deployment_intent_sha256
    || lineage.release_verification_authority_sha256
      !== receipt.release_verification_authority_sha256
    || lineage.seven_cvm_launch_completion_receipt_sha256
      !== receipt.seven_cvm_launch_completion_receipt_sha256
    || lineage.seven_cvm_verified_evidence_set_sha256
      !== receipt.seven_cvm_verified_evidence_set_sha256
    || lineage.pre_ceremony_runtime_authority_sha256
      !== receipt.pre_ceremony_runtime_authority_sha256
    || lineage.post_measurement_activation_plan_sha256
      !== receipt.post_measurement_activation_plan_sha256
    || lineage.ceremony_authorization_sha256
      !== receipt.ceremony_authorization_sha256
    || mainRuntime.app_id !== receipt.target.app_id
    || mainRuntime.cvm_id !== receipt.target.cvm_id
    || mainRuntime.compose_hash !== receipt.target.compose_hash
    || mainRuntime.os_image_hash !== receipt.target.os_image_hash
    || mainRuntime.descriptor_sha256 !== receipt.target.descriptor_sha256
    || verification.activation_verification_sha256
      !== activation.activation_verification_sha256
    || verification.activation_artifact_sha256
      !== activation.source_activation_sha256
    || verification.raw_transcript_sha256 !== activation.raw_transcript_sha256
    || verification.qvl_verdict_verifier_signature_sha256
      !== activation.qvl_verdict_verifier_signature_sha256
    || verification.tdx_quote_sha256 !== activation.tdx_quote_sha256
    || verification.challenge_id !== activation.challenge_id
    || recipient.report_data !== activation.report_data
    || recipient.recipient_key_id !== activation.recipient_key_id
    || recipient.recipient_release_commitment
      !== activation.recipient_release_commitment
    || verification.authenticated_at !== activation.authenticated_at
    || verification.verified_at !== activation.verified_at
    || verification.verdict_activation_evidence_lease_expires_at
      !== activation.verdict_activation_evidence_lease_expires_at
    || verification.recipient_evidence_lease_expires_at
      !== activation.recipient_evidence_lease_expires_at
    || verification.activation_verification_expires_at
      !== activation.expires_at
    || observation.initial_activation_evidence_lease_expires_at
      !== receipt.initial_activation_evidence_lease_expires_at
    || observation.recipient_evidence_lease_expires_at
      !== receipt.recipient_evidence_lease_expires_at
    || observation.terminal_evidence_lease_expires_at
      !== receipt.terminal_evidence_lease_expires_at) {
    fail("compute-workload O differs from the exact post-measurement activation execution receipt");
  }
  return receiptSha256;
}

/**
 * Bind persisted O to signed C without renewing O's challenge/verdict window.
 * The caller must first reconstruct O through the historical-only verifier;
 * the historical projector rejects ordinary normalized and fresh-only values.
 */
export function assertHistoricalLiveActivationComputeWorkloadObservationBinding({
  liveActivationAuthority,
  liveActivationOptions,
  historicallyVerifiedObservation,
  frontendBuildCandidateReceipt,
  serializedEnv,
} = {}) {
  const observation = historicallyVerifiedObservation;
  const browserBinding =
    projectComputeWorkloadBrowserBindingFromHistoricalObservation(observation);
  const authority = normalizeLiveActivationAuthority(
    liveActivationAuthority,
    liveActivationOptions,
  );
  const buildReceipt = normalizeFrontendBuildCandidateReceipt(
    frontendBuildCandidateReceipt,
  );
  if (typeof serializedEnv !== "string" || serializedEnv.length < 2
    || !serializedEnv.endsWith("\n") || serializedEnv.includes("\r")) {
    fail("historical final C workload binding requires exact normalized frontend environment bytes");
  }
  const observationSha256 = computeWorkloadActivationObservationSha256(observation);
  const releaseEnvSha256 = `sha256:${createHash("sha256")
    .update(serializedEnv, "utf8")
    .digest("hex")}`;
  const buildReceiptSha256 = frontendBuildCandidateReceiptSha256(buildReceipt);
  const post = authority.post_ceremony_evidence;
  const activationExecutionReceipt =
    post.post_measurement_activation_execution_receipt;
  const activationExecutionReceiptSha256 =
    assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
      activationExecutionReceipt,
      activationExecutionReceiptSha256:
        post.post_measurement_activation_execution_receipt_sha256,
      observation,
    });
  if (post.compute_workload_activation_observation_sha256 !== observationSha256
    || JSON.stringify(post.compute_workload_browser_binding)
      !== JSON.stringify(browserBinding)
    || post.frontend_release_env_sha256 !== releaseEnvSha256
    || post.frontend_build_candidate_receipt_sha256 !== buildReceiptSha256
    || post.frontend_build_sha256 !== buildReceipt.frontend_build_sha256
    || buildReceipt.compute_workload_activation_observation_sha256
      !== observationSha256
    || buildReceipt.release_env_sha256 !== releaseEnvSha256
    || buildReceipt.release_sha !== authority.release_sha
    || buildReceipt.ceremony_authorization_sha256
      !== authority.ceremony_authorization_sha256
    || buildReceipt.runtime_authority_dependency_sha256
      !== liveActivationOptions?.ceremonyAuthorization
        ?.pre_ceremony_runtime_authority_sha256) {
    fail("historical final C does not exact-bind replayed O, deterministic environment, and D receipt");
  }
  return Object.freeze({
    computeWorkloadActivationObservationSha256: observationSha256,
    computeWorkloadBrowserBindingSha256:
      computeWorkloadBrowserBindingSha256(browserBinding),
    postMeasurementActivationExecutionReceiptSha256:
      activationExecutionReceiptSha256,
    frontendReleaseEnvSha256: releaseEnvSha256,
    frontendBuildCandidateReceiptSha256: buildReceiptSha256,
    frontendBuildSha256: buildReceipt.frontend_build_sha256,
    liveActivationAuthoritySha256: liveActivationAuthoritySha256(
      liveActivationAuthority,
      { ...liveActivationOptions, enforceFreshness: false },
    ),
  });
}

export function normalizeLiveActivationFrontendBinding(value) {
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "chain_id", "challenge_genesis_sha256",
    "common_finalized_state_sha256", "contract_configuration_set_sha256",
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding", "contracts", "cvm_measurements_sha256",
    "deployment_intent_sha256",
    "execution_policy_anchor_commitment", "final_cvms",
    "frontend_build_candidate_receipt_sha256", "frontend_build_sha256",
    "frontend_release_env_sha256",
    "live_activation_authority_sha256",
    "qvl_policy_bundle_sha256", "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "runtime_authority_dependency_sha256", "schema", "tdx_attestation_bundle_sha256",
    "truth_status",
  ], "live activation frontend binding");
  exactString(
    parsed.schema,
    LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
    "live activation frontend binding schema",
  );
  exactString(
    parsed.truth_status,
    LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
    "live activation frontend binding truth status",
  );
  if (!SHA40.test(parsed.release_sha)) fail("live activation frontend release SHA is invalid");
  const deploymentIntentSha = sha256(
    parsed.deployment_intent_sha256,
    "frontend binding deployment intent digest",
  );
  const reviewerAcceptanceSha = sha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "frontend binding reviewer genesis acceptance digest",
  );
  const contracts = normalizeContractEntries(parsed.contracts);
  const challengeGenesisSha = sha256(
    parsed.challenge_genesis_sha256,
    "frontend binding challenge genesis digest",
  );
  const anchorCommitment = normalizeExecutionPolicyAnchorCommitment(
    parsed.execution_policy_anchor_commitment,
    {
      contracts,
      deploymentIntentSha256: deploymentIntentSha,
      reviewerGenesisAcceptanceSha256: reviewerAcceptanceSha,
    },
  );
  const expectedContractConfigurationSha = domainDigest(
    "dnai-wikigen/live-contract-configuration-set/v2\0",
    contractConfigurationSetPayload({
      contracts,
      challengeGenesisSha256: challengeGenesisSha,
      deploymentIntentSha256: deploymentIntentSha,
      reviewerGenesisAcceptanceSha256: reviewerAcceptanceSha,
      executionPolicyAnchorCommitment: anchorCommitment,
    }),
  );
  if (parsed.contract_configuration_set_sha256 !== expectedContractConfigurationSha) {
    fail("frontend binding contract configuration digest is invalid");
  }
  return {
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    chain_id: integer(parsed.chain_id, "live activation frontend chain ID", CHAIN_ID, CHAIN_ID),
    live_activation_authority_sha256: sha256(
      parsed.live_activation_authority_sha256,
      "live activation authority digest",
    ),
    deployment_intent_sha256: deploymentIntentSha,
    reviewer_authority_genesis_acceptance_sha256: reviewerAcceptanceSha,
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "frontend binding ceremony authorization digest",
    ),
    runtime_authority_dependency_sha256: sha256(
      parsed.runtime_authority_dependency_sha256,
      "frontend binding runtime authority dependency digest",
    ),
    frontend_build_candidate_receipt_sha256: sha256(
      parsed.frontend_build_candidate_receipt_sha256,
      "frontend binding candidate receipt digest",
    ),
    frontend_build_sha256: sha256(
      parsed.frontend_build_sha256,
      "frontend binding audited build digest",
    ),
    common_finalized_state_sha256: sha256(
      parsed.common_finalized_state_sha256,
      "frontend binding common finalized state digest",
    ),
    contract_configuration_set_sha256: expectedContractConfigurationSha,
    contracts,
    execution_policy_anchor_commitment: anchorCommitment,
    challenge_genesis_sha256: challengeGenesisSha,
    final_cvms: normalizeFinalCvms(parsed.final_cvms),
    cvm_measurements_sha256: sha256(
      parsed.cvm_measurements_sha256,
      "frontend binding CVM measurements digest",
    ),
    tdx_attestation_bundle_sha256: sha256(
      parsed.tdx_attestation_bundle_sha256,
      "frontend binding TDX attestation bundle digest",
    ),
    qvl_policy_bundle_sha256: sha256(
      parsed.qvl_policy_bundle_sha256,
      "frontend binding QVL policy bundle digest",
    ),
    compute_workload_activation_observation_sha256: sha256(
      parsed.compute_workload_activation_observation_sha256,
      "frontend binding compute-workload observation digest",
    ),
    compute_workload_browser_binding: normalizeComputeWorkloadBrowserBinding(
      parsed.compute_workload_browser_binding,
    ),
    frontend_release_env_sha256: sha256(
      parsed.frontend_release_env_sha256,
      "frontend binding release environment digest",
    ),
  };
}

export function projectLiveActivationFrontendBinding(value, options) {
  const liveActivation = normalizeLiveActivationAuthority(value, options);
  const { stageBReviewerStatusHistory } = liveActivationReviewerHistories(options);
  const ceremonyAuthorization = normalizeCeremonyAuthorizationCore(
    options.ceremonyAuthorization,
    liveActivationStageBCeremonyOptions(options, stageBReviewerStatusHistory),
  );
  return normalizeLiveActivationFrontendBinding({
    schema: LIVE_ACTIVATION_FRONTEND_BINDING_SCHEMA,
    truth_status: LIVE_ACTIVATION_FRONTEND_BINDING_TRUTH_STATUS,
    release_sha: liveActivation.release_sha,
    chain_id: CHAIN_ID,
    live_activation_authority_sha256: liveActivationAuthoritySha256(value, options),
    deployment_intent_sha256:
      liveActivation.contract_state.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      liveActivation.contract_state.reviewer_authority_genesis_acceptance_sha256,
    ceremony_authorization_sha256: liveActivation.ceremony_authorization_sha256,
    runtime_authority_dependency_sha256:
      ceremonyAuthorization.pre_ceremony_runtime_authority_sha256,
    frontend_build_candidate_receipt_sha256:
      liveActivation.post_ceremony_evidence
        .frontend_build_candidate_receipt_sha256,
    frontend_build_sha256: liveActivation.post_ceremony_evidence.frontend_build_sha256,
    common_finalized_state_sha256:
      commonStateDependencySha256(liveActivation.common_finalized_state),
    contract_configuration_set_sha256:
      liveActivation.contract_state.configuration_set_sha256,
    contracts: liveActivation.contract_state.contracts,
    execution_policy_anchor_commitment:
      liveActivation.contract_state.execution_policy_anchor_commitment,
    challenge_genesis_sha256: liveActivation.contract_state.challenge_genesis_sha256,
    final_cvms: liveActivation.post_ceremony_evidence.final_cvms,
    cvm_measurements_sha256:
      liveActivation.post_ceremony_evidence.cvm_measurements_sha256,
    tdx_attestation_bundle_sha256:
      liveActivation.post_ceremony_evidence.tdx_attestation_bundle_sha256,
    qvl_policy_bundle_sha256:
      liveActivation.post_ceremony_evidence.qvl_policy_bundle_sha256,
    compute_workload_activation_observation_sha256:
      liveActivation.post_ceremony_evidence
        .compute_workload_activation_observation_sha256,
    compute_workload_browser_binding:
      liveActivation.post_ceremony_evidence.compute_workload_browser_binding,
    frontend_release_env_sha256:
      liveActivation.post_ceremony_evidence.frontend_release_env_sha256,
  });
}

export function liveActivationFrontendBindingSha256(value) {
  return domainDigest(
    LIVE_ACTIVATION_FRONTEND_BINDING_DOMAIN,
    normalizeLiveActivationFrontendBinding(value),
  );
}

export function frontendBuildCandidateAuthorityBindingFromLiveActivation(value, options) {
  const binding = projectLiveActivationFrontendBinding(value, options);
  const { stageBReviewerStatusHistory } = liveActivationReviewerHistories(options);
  const ceremonyBinding =
    frontendBuildCandidateAuthorityBindingFromCeremonyAuthorization(
      options.ceremonyAuthorization,
      liveActivationStageBCeremonyOptions(options, stageBReviewerStatusHistory),
    );
  if (ceremonyBinding.releaseSha !== binding.release_sha
    || ceremonyBinding.deploymentIntentSha256 !== binding.deployment_intent_sha256
    || ceremonyBinding.reviewerAuthorityGenesisAcceptanceSha256
      !== binding.reviewer_authority_genesis_acceptance_sha256
    || ceremonyBinding.ceremonyAuthorizationSha256
      !== binding.ceremony_authorization_sha256
    || ceremonyBinding.runtimeAuthorityDependencySha256
      !== binding.runtime_authority_dependency_sha256
    || ceremonyBinding.computeWorkloadActivationObservationSha256
      !== binding.compute_workload_activation_observation_sha256) {
    fail("live activation frontend lineage drifted from the signed ceremony authorization");
  }
  return Object.freeze({
    ...ceremonyBinding,
    frontendReleaseEnvSha256: binding.frontend_release_env_sha256,
    frontendBuildCandidateReceiptSha256:
      binding.frontend_build_candidate_receipt_sha256,
    frontendBuildSha256: binding.frontend_build_sha256,
  });
}

export function assertLiveActivationFrontendBuildSha256(
  value,
  expectedFrontendBuildSha256,
  options,
) {
  const binding = projectLiveActivationFrontendBinding(value, options);
  const expected = sha256(expectedFrontendBuildSha256, "expected audited frontend build digest");
  if (binding.frontend_build_sha256 !== expected) {
    fail("signed live activation does not bind the exact audited frontend build");
  }
  return binding;
}

export function normalizeDeprecatedFinalReleaseAuthorityWrapper(value) {
  const parsed = exact(value, [
    "ceremony_authorization_sha256", "pre_ceremony_runtime_authority_sha256",
    "schema", "status", "truth_status",
  ], "deprecated final-release-authority wrapper");
  return {
    schema: exactString(parsed.schema, DEPRECATED_FINAL_RELEASE_AUTHORITY_WRAPPER_SCHEMA, "deprecated wrapper schema"),
    status: exactString(parsed.status, CEREMONY_AUTHORIZATION_CORE_STATUS, "deprecated wrapper status"),
    truth_status: exactString(
      parsed.truth_status,
      "deprecated_pre_ceremony_compatibility_wrapper_not_final_or_live_authority",
      "deprecated wrapper truth status",
    ),
    pre_ceremony_runtime_authority_sha256: sha256(
      parsed.pre_ceremony_runtime_authority_sha256,
      "deprecated wrapper runtime authority digest",
    ),
    ceremony_authorization_sha256: sha256(
      parsed.ceremony_authorization_sha256,
      "deprecated wrapper ceremony authorization digest",
    ),
  };
}
