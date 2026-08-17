#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { ethereumKeccak256Hex } from "./ethereum-keccak.mjs";
import {
  ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
  ROYALTY_RELEASE_AUTHORITY_SCHEMA,
  ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
  ROYALTY_RELEASE_STATE_SCHEMA,
  normalizeRoyaltyReleaseAuthority,
  royaltyReleaseStateSha256,
} from "./royalty-release-authority-core.mjs";
import {
  projectRoyaltyReleaseHistoryReceipt,
} from "./royalty-release-history-receipt-core.mjs";
import {
  normalizeRoyaltyReleasePrescriptiveAuthority,
  royaltyReleasePrescriptiveAuthoritySha256,
} from "../⚙️/tinker-delegate/contracts/scripts/royalty-release-phase-plan.mjs";
import {
  replayReleaseCeremonyLedgerRevisionChain,
} from "./release-ceremony-ledger.mjs";

export const ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA =
  "dnai.base-sepolia-royalty-finalized-history-evidence.v1";
export const ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS =
  "observed_dual_archive_rpc_finalized_history_not_signed_live_authority";
export const ROYALTY_FINALIZED_HISTORY_EVIDENCE_DOMAIN =
  "dnai-wikigen/base-sepolia-royalty-finalized-history-evidence/v1\0";

const WRITE_RECEIPT_SCHEMA =
  "dnai.base-sepolia-royalty-finalized-history-evidence-write-receipt.v1";
const FULL_SUITE_SCHEMA = "dnai.base-sepolia-royalty-full-suite-state.v1";
const COLLECTION_PROOF_SCHEMA =
  "dnai.base-sepolia-royalty-history-collection-proof.v1";
const BLOCK_SCHEMA = "dnai.base-sepolia-finalized-block-rpc-observation.v1";
const BLOCK_DOMAIN = "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0";
const TX_SCHEMA = "dnai.base-sepolia-transaction-rpc-observation.v1";
const TX_DOMAIN = "dnai-wikigen/base-sepolia-transaction-rpc-observation/v1\0";
const RECEIPT_SCHEMA = "dnai.base-sepolia-receipt-rpc-observation.v1";
const RECEIPT_DOMAIN = "dnai-wikigen/base-sepolia-receipt-rpc-observation/v1\0";
const CHAIN_ID = 84_532;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_RPC_BYTES = 2 * 1024 * 1024;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const MAX_ACCOUNT_NONCE = (1n << 64n) - 2n;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const HEX = /^0x(?:[0-9a-f]{2})*$/;
const QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const DECIMAL = /^(0|[1-9][0-9]*)$/;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const CONTRACTS = Object.freeze([
  ["diligence_room", "diligenceRoom", "developer"],
  ["tinker_account_encumbrance", "tinkerAccountEncumbrance", "owner"],
  ["royalty_distributor", "royaltyDistributor", "owner"],
  ["challenge_registry", "challengeRegistry", "owner"],
  ["compute_credit_vault", "computeCreditVault", "owner"],
  ["email_oracle_auth", "emailOracleAuth", "owner"],
  ["execution_policy_anchor", "executionPolicyAnchor", "owner"],
]);

// These no-argument getters form the code-owned, release-independent public
// configuration projection. Mapping membership is represented by the frozen,
// replayed ledger record plus its on-chain aggregate roots/counts; no final-v4
// artifact is consumed because H is upstream of final-v4.
const CONFIG_GETTERS = Object.freeze({
  diligence_room: Object.freeze([
    "developer()", "initialDeveloper()", "releaseGovernanceController()",
    "protocolFeeRecipient()", "productionRelease()", "dealCount()",
    "resultVerifier()", "resultVerifierFrozen()", "pendingResultVerifier()",
    "pendingResultVerifierActivatesAt()", "attestationVerifier()",
    "attestationReleasePolicyHash()", "attestationBindingFrozen()",
    "pendingAttestationVerifier()", "pendingAttestationReleasePolicyHash()",
    "pendingAttestationBindingActivatesAt()", "approvedEvaluatorPolicyCount()",
    "pendingEvaluatorPolicyCount()", "evaluatorPolicySetFrozen()",
    "evaluatorPolicySetRoot()", "approvedComposeCount()",
    "approvedTeeIdentityCount()", "composeApprovalRequired()",
    "teeIdentityApprovalRequired()", "approvalRequirementsFrozen()",
    "feeBpsFrozen()", "computeSettlementPolicyEnabled()",
    "composeAdditionsFrozen()", "teeIdentityAdditionsFrozen()",
    "pendingComposeCount()", "pendingTeeIdentityCount()", "pendingDeveloper()",
    "pendingDeveloperActivatesAt()", "DEVELOPER_TRANSFER_DELAY()",
  ]),
  tinker_account_encumbrance: Object.freeze([
    "owner()", "pendingOwner()", "accountCommitment()", "maxAddBalanceWei()",
    "maxSpendWei()", "approvedComposeRoot()", "approvedComposeCount()",
    "managerRoot()", "managerCount()", "releasePolicyCommitment()",
    "releaseMaxAddBalanceWei()", "releaseMaxSpendWei()", "releaseComposeRoot()",
    "releaseComposeCount()", "releaseManagerRoot()", "releaseManagerCount()",
    "releasePolicyFrozen()", "emergencyHalted()", "pendingAccountCommitment()",
    "pendingMaxAddBalanceWei()", "pendingMaxSpendWei()", "pendingComposeRoot()",
    "pendingComposeCount()", "pendingManagerRoot()", "pendingManagerCount()",
    "pendingReleasePolicyCommitment()", "pendingReleasePolicyActivatesAt()",
    "ACCOUNT_BINDING_TYPEHASH()", "TINKER_PROVIDER_NAMESPACE()",
  ]),
  royalty_distributor: Object.freeze([
    "owner()", "pendingOwner()", "paused()", "settlementVerifier()",
    "qvlVerifier()", "executionPolicyAnchor()", "anchorWriterReleaseCommitment()",
    "releasePolicyCommitment()", "authorityNonce()", "pendingSettlementVerifier()",
    "pendingQvlVerifier()", "pendingExecutionPolicyAnchor()",
    "pendingAnchorWriterReleaseCommitment()", "pendingReleasePolicyCommitment()",
    "pendingAuthorityNonce()", "pendingAuthorityActivatesAt()",
    "pendingAuthorityRevocation()", "AUTHORITY_TIMELOCK()",
  ]),
  challenge_registry: Object.freeze([
    "owner()", "pendingOwner()", "registryPaused()", "challengeCount()",
    "nextChallengeId()", "MIN_VERSION_REVIEW_DELAY()",
  ]),
  compute_credit_vault: Object.freeze([
    "owner()", "pendingOwner()", "developer()", "developerFeeBps()",
    "developerFeeFrozen()", "meteringVerifier()", "meteringQvlVerifier()",
    "meteringPolicySetHash()", "meteringBindingFrozen()", "allowedAssetCount()",
    "activeRatePolicyCount()", "approvedComposeCount()",
    "approvedTeeIdentityCount()", "assetAdditionsFrozen()",
    "ratePolicyAdditionsFrozen()", "composePolicyFrozen()",
    "teeIdentityAdditionsFrozen()", "paused()", "pendingAssetCount()",
    "pendingRatePolicyCount()", "pendingComposeCount()",
    "pendingTeeIdentityCount()", "pendingMeteringVerifier()",
    "pendingMeteringQvlVerifier()", "pendingMeteringPolicySetHash()",
    "pendingMeteringBindingActivatesAt()",
  ]),
  email_oracle_auth: Object.freeze([
    "owner()", "pendingOwner()", "productionRelease()", "ORACLE_UPGRADE_DELAY()",
    "allowAnyDevice()", "releaseOracleComposeHash()", "releaseDeviceId()",
    "releaseConsumerManager()", "releaseConsumerAppId()",
    "releaseConsumerComposeHash()", "kmsContract()", "kmsRuntimeCodeHash()",
    "kmsImplementation()", "kmsImplementationRuntimeCodeHash()",
    "kmsRegistrationTxHash()", "kmsRegistrationBlock()",
    "kmsRegistrationBlockHash()", "targetBootInfoHash()",
    "restartKeyDerivationProofHash()", "consumerManagerCount()",
    "totalConsumerComposeHashCount()", "allowedOracleComposeHashCount()",
    "allowedDeviceIdCount()", "oracleCodeFrozen()", "kmsBindingFrozen()",
    "consumerManagerAdditionsFrozen()", "consumerRegistryFrozen()",
    "releaseConfigurationReady()", "pendingOracleComposeHashCount()",
    "pendingKmsContract()", "pendingKmsRuntimeCodeHash()",
    "pendingKmsImplementation()", "pendingKmsImplementationRuntimeCodeHash()",
    "pendingKmsRegistrationTxHash()", "pendingKmsRegistrationBlock()",
    "pendingKmsRegistrationBlockHash()", "pendingTargetBootInfoHash()",
    "pendingRestartKeyDerivationProofHash()", "pendingKmsBindingActivatesAt()",
  ]),
  execution_policy_anchor: Object.freeze([
    "owner()", "pendingOwner()", "writer()", "writerReleaseCommitment()",
    "writerRotationsFrozen()", "paused()", "pendingWriter()",
    "pendingWriterReleaseCommitment()", "pendingWriterActivatesAt()",
    "globalSequence()", "globalHead()", "deploymentIntentSha256()",
    "reviewerAuthorityGenesisAcceptanceSha256()", "ANCHOR_TYPEHASH()",
  ]),
});

export const ROYALTY_HISTORY_CONFIGURATION_GETTERS = CONFIG_GETTERS;

let rpcId = 0;

export class RoyaltyFinalizedHistoryEvidenceError extends Error {}

function fail(message) {
  throw new RoyaltyFinalizedHistoryEvidenceError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
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

function canonicalEqual(left, right) {
  return canonicalText(left) === canonicalText(right);
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function rawSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

export function royaltyHistoryFrozenLedgerContractSha256(value) {
  if (!isRecord(value)) fail("frozen-ledger contract record must be an object");
  return domainSha256(
    "dnai-wikigen/frozen-ledger-contract-record/v1\0",
    value,
  );
}

function string(value, pattern, label, { nonzero = false } = {}) {
  if (typeof value !== "string" || !pattern.test(value)
    || (nonzero && /^0x?0+$/.test(value.replace(/^sha256:/, "")))) {
    fail(`${label} is invalid`);
  }
  return value;
}

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)
    || value === `sha256:${"0".repeat(64)}`) fail(`${label} must be a nonzero SHA-256 pin`);
  return value;
}

function address(value, label) {
  if (typeof value !== "string") fail(`${label} must be a canonical nonzero address`);
  const normalized = value.toLowerCase();
  if (!ADDRESS.test(normalized) || normalized === ZERO_ADDRESS) {
    fail(`${label} must be a canonical nonzero address`);
  }
  return normalized;
}

function bytes32(value, label) {
  if (typeof value !== "string") fail(`${label} must be canonical nonzero bytes32`);
  const normalized = value.toLowerCase();
  if (!BYTES32.test(normalized) || normalized === ZERO_BYTES32) {
    fail(`${label} must be canonical nonzero bytes32`);
  }
  return normalized;
}

function hex(value, label, { empty = true } = {}) {
  if (typeof value !== "string") fail(`${label} must be lowercase hex bytes`);
  const normalized = value.toLowerCase();
  if (!HEX.test(normalized) || (!empty && normalized === "0x")) {
    fail(`${label} must be lowercase hex bytes`);
  }
  return normalized;
}

function abiWord(value, label) {
  if (typeof value !== "string") fail(`${label} must be one canonical ABI word`);
  const normalized = value.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    fail(`${label} must be one canonical ABI word`);
  }
  return normalized;
}

function decimal(value, label) {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed >= (1n << 256n)) fail(`${label} exceeds uint256`);
  return value;
}

function quantity(value, label) {
  if (typeof value !== "string") fail(`${label} must be a hex quantity`);
  const normalized = value.toLowerCase();
  if (!QUANTITY.test(normalized)) fail(`${label} must be a canonical hex quantity`);
  return BigInt(normalized);
}

function safeQuantity(value, label, minimum = 0) {
  const parsed = quantity(value, label);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER) || parsed < BigInt(minimum)) {
    fail(`${label} exceeds the safe integer range`);
  }
  return Number(parsed);
}

function decimalQuantity(value, label) {
  const parsed = quantity(value, label);
  if (parsed >= (1n << 256n)) fail(`${label} exceeds uint256`);
  return parsed.toString(10);
}

function nonceQuantity(value, label) {
  const parsed = quantity(value, label);
  if (parsed > MAX_ACCOUNT_NONCE) {
    fail(`${label} exceeds the Ethereum account-nonce protocol limit`);
  }
  return parsed.toString(10);
}

function quantityHex(value) {
  return `0x${BigInt(value).toString(16)}`;
}

function selector(signature) {
  return ethereumKeccak256Hex(Buffer.from(signature, "utf8")).slice(0, 10);
}

function addressWord(value) {
  return address(value, "ABI address").slice(2).padStart(64, "0");
}

function decodeWord(value, label) {
  return abiWord(value, label).slice(2);
}

function decodeAddress(value, label, { allowZero = false } = {}) {
  const word = decodeWord(value, label);
  if (!word.startsWith("0".repeat(24))) fail(`${label} returned a malformed address`);
  const result = `0x${word.slice(24)}`;
  if (!ADDRESS.test(result) || (!allowZero && result === ZERO_ADDRESS)) {
    fail(`${label} returned an invalid address`);
  }
  return result;
}

function decodeBytes32(value, label, { allowZero = false } = {}) {
  const result = `0x${decodeWord(value, label)}`;
  if (!allowZero && result === ZERO_BYTES32) fail(`${label} returned zero bytes32`);
  return result;
}

function decodeUint(value, label) {
  const parsed = BigInt(`0x${decodeWord(value, label)}`);
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) fail(`${label} exceeds safe integer range`);
  return Number(parsed);
}

function decodeBool(value, label) {
  const parsed = decodeUint(value, label);
  if (parsed !== 0 && parsed !== 1) fail(`${label} returned a malformed bool`);
  return parsed === 1;
}

function normalizeEndpoint(value, label) {
  if (typeof value !== "string" || value !== value.trim()
    || Buffer.byteLength(value, "utf8") > 4096) fail(`${label} RPC URL is invalid`);
  let url;
  try {
    url = new URL(value);
  } catch {
    fail(`${label} RPC URL is invalid`);
  }
  if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.hash) {
    fail(`${label} RPC must be HTTPS without userinfo or a fragment`);
  }
  return {
    url: url.href,
    origin: url.origin.toLowerCase(),
    hostname: url.hostname.toLowerCase(),
  };
}

export function normalizeRoyaltyHistoryRpcEndpoints(primaryValue, secondaryValue) {
  const primary = normalizeEndpoint(primaryValue, "primary");
  const secondary = normalizeEndpoint(secondaryValue, "secondary");
  if (primary.url === secondary.url || primary.origin === secondary.origin
    || primary.hostname === secondary.hostname) {
    fail("primary and secondary RPCs must use distinct HTTPS host authorities");
  }
  return { primary, secondary };
}

export async function readRoyaltyHistoryBoundedResponseText(response, label = "RPC") {
  const reader = response?.body?.getReader?.();
  if (!reader) fail(`${label} response body is not stream-readable`);
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array) || value.byteLength === 0) {
        fail(`${label} response stream yielded an invalid chunk`);
      }
      total += value.byteLength;
      if (total > MAX_RPC_BYTES) {
        try { await reader.cancel("bounded RPC response exceeded limit"); } catch {}
        fail(`${label} response exceeds the byte bound`);
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  if (total < 2) fail(`${label} response is empty`);
  return Buffer.concat(chunks, total).toString("utf8");
}

async function rpc(fetchImpl, endpoint, method, params = []) {
  const id = ++rpcId;
  let response;
  try {
    response = await fetchImpl(endpoint.url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    fail(`RPC transport failed for ${method}`);
  }
  if (!response?.ok) fail(`RPC returned HTTP failure for ${method}`);
  const length = response.headers?.get?.("content-length");
  if (length !== null && length !== undefined
    && (!/^[0-9]+$/.test(length) || Number(length) > MAX_RPC_BYTES)) {
    fail(`RPC returned an oversized ${method} response`);
  }
  const text = await readRoyaltyHistoryBoundedResponseText(
    response,
    `RPC ${method}`,
  );
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    fail(`RPC returned malformed JSON for ${method}`);
  }
  if (!isRecord(payload) || payload.jsonrpc !== "2.0" || payload.id !== id
    || Object.hasOwn(payload, "error") || !Object.hasOwn(payload, "result")) {
    fail(`RPC returned an invalid JSON-RPC envelope for ${method}`);
  }
  return payload.result;
}

function normalizeBlockRpc(value, label) {
  if (!isRecord(value)) fail(`${label} block is absent`);
  return normalizeBlockObservation({
    schema: BLOCK_SCHEMA,
    chain_id: CHAIN_ID,
    block_number: safeQuantity(value.number, `${label} block number`, 1),
    block_hash: bytes32(value.hash, `${label} block hash`),
    parent_hash: bytes32(value.parentHash, `${label} parent hash`),
    block_timestamp: safeQuantity(value.timestamp, `${label} timestamp`, 1),
    state_root: bytes32(value.stateRoot, `${label} state root`),
    transactions_root: bytes32(value.transactionsRoot, `${label} transactions root`),
    receipts_root: bytes32(value.receiptsRoot, `${label} receipts root`),
    gas_limit: decimalQuantity(value.gasLimit, `${label} gas limit`),
    gas_used: decimalQuantity(value.gasUsed, `${label} gas used`),
    base_fee_per_gas_wei: decimalQuantity(value.baseFeePerGas, `${label} base fee`),
  }, label);
}

function normalizeBlockObservation(value, label) {
  const parsed = exact(value, [
    "base_fee_per_gas_wei", "block_hash", "block_number", "block_timestamp",
    "chain_id", "gas_limit", "gas_used", "parent_hash", "receipts_root",
    "schema", "state_root", "transactions_root",
  ], `${label} block observation`);
  if (parsed.schema !== BLOCK_SCHEMA || parsed.chain_id !== CHAIN_ID
    || !Number.isSafeInteger(parsed.block_number) || parsed.block_number < 1
    || !Number.isSafeInteger(parsed.block_timestamp) || parsed.block_timestamp < 1) {
    fail(`${label} block observation identity is invalid`);
  }
  const block = {
    schema: BLOCK_SCHEMA,
    chain_id: CHAIN_ID,
    block_number: parsed.block_number,
    block_hash: bytes32(parsed.block_hash, `${label} block hash`),
    parent_hash: bytes32(parsed.parent_hash, `${label} parent hash`),
    block_timestamp: parsed.block_timestamp,
    state_root: bytes32(parsed.state_root, `${label} state root`),
    transactions_root: bytes32(parsed.transactions_root, `${label} transactions root`),
    receipts_root: bytes32(parsed.receipts_root, `${label} receipts root`),
    gas_limit: decimal(parsed.gas_limit, `${label} gas limit`),
    gas_used: decimal(parsed.gas_used, `${label} gas used`),
    base_fee_per_gas_wei: decimal(parsed.base_fee_per_gas_wei, `${label} base fee`),
  };
  if (BigInt(block.gas_limit) === 0n
    || BigInt(block.gas_used) > BigInt(block.gas_limit)
    || BigInt(block.base_fee_per_gas_wei) === 0n) fail(`${label} gas fields are invalid`);
  return block;
}

function blockSha256(value) {
  return domainSha256(BLOCK_DOMAIN, normalizeBlockObservation(value, "finalized"));
}

async function readBlock(fetchImpl, endpoint, tag, label) {
  return normalizeBlockRpc(
    await rpc(fetchImpl, endpoint, "eth_getBlockByNumber", [tag, false]),
    label,
  );
}

async function ethCall(fetchImpl, endpoint, target, signature, args, blockNumber, label) {
  const data = `${selector(signature)}${args.join("")}`;
  return rpc(fetchImpl, endpoint, "eth_call", [
    { to: target, data },
    quantityHex(blockNumber),
  ]).then((value) => abiWord(value, label));
}

async function collectRoyaltyState(fetchImpl, endpoint, block, authority, label) {
  const target = authority.distributor_address;
  const getters = [
    ["owner", "owner()", [], decodeAddress],
    ["pending_owner", "pendingOwner()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["paused", "paused()", [], decodeBool],
    ["settlement_verifier", "settlementVerifier()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["qvl_verifier", "qvlVerifier()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["execution_policy_anchor", "executionPolicyAnchor()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["anchor_writer_release_commitment", "anchorWriterReleaseCommitment()", [], (v, l) => decodeBytes32(v, l, { allowZero: true })],
    ["release_policy_commitment", "releasePolicyCommitment()", [], (v, l) => decodeBytes32(v, l, { allowZero: true })],
    ["authority_nonce", "authorityNonce()", [], decodeUint],
    ["pending_settlement_verifier", "pendingSettlementVerifier()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["pending_qvl_verifier", "pendingQvlVerifier()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["pending_execution_policy_anchor", "pendingExecutionPolicyAnchor()", [], (v, l) => decodeAddress(v, l, { allowZero: true })],
    ["pending_anchor_writer_release_commitment", "pendingAnchorWriterReleaseCommitment()", [], (v, l) => decodeBytes32(v, l, { allowZero: true })],
    ["pending_release_policy_commitment", "pendingReleasePolicyCommitment()", [], (v, l) => decodeBytes32(v, l, { allowZero: true })],
    ["pending_authority_nonce", "pendingAuthorityNonce()", [], decodeUint],
    ["pending_authority_activates_at", "pendingAuthorityActivatesAt()", [], decodeUint],
    ["pending_authority_revocation", "pendingAuthorityRevocation()", [], decodeBool],
    ["settlement_verifier_ever_configured", "settlementVerifierEverConfigured(address)", [addressWord(authority.settlement_verifier)], decodeBool],
    ["qvl_verifier_ever_configured", "qvlVerifierEverConfigured(address)", [addressWord(authority.qvl_verifier)], decodeBool],
    ["anchor_writer_ever_configured", "anchorWriterEverConfigured(address)", [addressWord(authority.anchor_writer)], decodeBool],
  ];
  const values = await Promise.all(getters.map(async ([key, signature, args, decode]) => [
    key,
    decode(
      await ethCall(fetchImpl, endpoint, target, signature, args, block.block_number, `${label} ${key}`),
      `${label} ${key}`,
    ),
  ]));
  return {
    schema: ROYALTY_RELEASE_STATE_SCHEMA,
    chain_id: CHAIN_ID,
    contract_address: target,
    block_number: block.block_number,
    block_hash: block.block_hash,
    block_timestamp: block.block_timestamp,
    ...Object.fromEntries(values),
    computed_release_policy_commitment: authority.release_policy_commitment,
  };
}

function normalizeRpcTransaction(value, label) {
  if (!isRecord(value)) fail(`${label} transaction is absent`);
  const type = safeQuantity(value.type, `${label} type`);
  const chainId = safeQuantity(value.chainId, `${label} chain ID`);
  if (type !== 2 || !Array.isArray(value.accessList) || value.accessList.length > 1024) {
    fail(`${label} must be a bounded EIP-1559 transaction`);
  }
  if (chainId !== CHAIN_ID) fail(`${label} transaction is not Base Sepolia`);
  const input = hex(value.input, `${label} input`, { empty: false });
  return {
    schema: TX_SCHEMA,
    chain_id: chainId,
    transaction_hash: bytes32(value.hash, `${label} hash`),
    block_number: safeQuantity(value.blockNumber, `${label} block`, 1),
    block_hash: bytes32(value.blockHash, `${label} block hash`),
    transaction_index: safeQuantity(value.transactionIndex, `${label} index`),
    from: address(value.from, `${label} sender`),
    to: address(value.to, `${label} target`),
    nonce: nonceQuantity(value.nonce, `${label} nonce`),
    value_wei: decimalQuantity(value.value, `${label} value`),
    input_sha256: rawSha256(Buffer.from(input.slice(2), "hex")),
    gas_limit: decimalQuantity(value.gas, `${label} gas`),
    transaction_type: type,
    max_fee_per_gas_wei: decimalQuantity(value.maxFeePerGas, `${label} max fee`),
    max_priority_fee_per_gas_wei: decimalQuantity(
      value.maxPriorityFeePerGas,
      `${label} priority fee`,
    ),
    access_list_sha256: domainSha256(
      "dnai-wikigen/base-sepolia-access-list/v1\0",
      value.accessList,
    ),
  };
}

function normalizeRpcReceipt(value, label) {
  if (!isRecord(value) || !Array.isArray(value.logs) || value.logs.length > 256) {
    fail(`${label} receipt is absent or has too many logs`);
  }
  const type = safeQuantity(value.type, `${label} type`);
  if (type !== 2) fail(`${label} receipt must be EIP-1559`);
  const contractAddress = value.contractAddress === null
    ? ZERO_ADDRESS
    : address(value.contractAddress, `${label} created contract`);
  const logsBloom = hex(value.logsBloom, `${label} logs bloom`, { empty: false });
  if (!/^0x[0-9a-f]{512}$/.test(logsBloom)) fail(`${label} logs bloom is invalid`);
  const logs = value.logs.map((entry, index) => {
    if (!isRecord(entry) || !Array.isArray(entry.topics) || entry.topics.length > 4) {
      fail(`${label} log ${index} is invalid`);
    }
    return {
      address: address(entry.address, `${label} log ${index} address`),
      topics: entry.topics.map((topic) => bytes32(topic, `${label} log ${index} topic`)),
      data: hex(entry.data, `${label} log ${index} data`),
      log_index: safeQuantity(entry.logIndex, `${label} log ${index} index`),
      removed: entry.removed === false ? false : fail(`${label} log ${index} was removed`),
    };
  });
  return {
    schema: RECEIPT_SCHEMA,
    chain_id: CHAIN_ID,
    transaction_hash: bytes32(value.transactionHash, `${label} transaction hash`),
    block_number: safeQuantity(value.blockNumber, `${label} block`, 1),
    block_hash: bytes32(value.blockHash, `${label} block hash`),
    transaction_index: safeQuantity(value.transactionIndex, `${label} index`),
    from: address(value.from, `${label} sender`),
    to: address(value.to, `${label} target`),
    contract_address: contractAddress,
    status: safeQuantity(value.status, `${label} status`),
    transaction_type: type,
    cumulative_gas_used: decimalQuantity(value.cumulativeGasUsed, `${label} cumulative gas`),
    gas_used: decimalQuantity(value.gasUsed, `${label} gas used`),
    effective_gas_price_wei: decimalQuantity(value.effectiveGasPrice, `${label} gas price`),
    logs_bloom: logsBloom,
    logs,
  };
}

function transactionSha256(value) {
  return domainSha256(TX_DOMAIN, value);
}

function receiptSha256(value) {
  return domainSha256(RECEIPT_DOMAIN, value);
}

async function collectMutation(fetchImpl, endpoints, transactionHash, operation, commonBlock) {
  async function one(endpoint, label) {
    const [transactionValue, receiptValue] = await Promise.all([
      rpc(fetchImpl, endpoint, "eth_getTransactionByHash", [transactionHash]),
      rpc(fetchImpl, endpoint, "eth_getTransactionReceipt", [transactionHash]),
    ]);
    const transaction = normalizeRpcTransaction(transactionValue, `${label} ${operation}`);
    const receipt = normalizeRpcReceipt(receiptValue, `${label} ${operation}`);
    if (transaction.transaction_hash !== transactionHash
      || receipt.transaction_hash !== transactionHash
      || transaction.block_number !== receipt.block_number
      || transaction.block_hash !== receipt.block_hash
      || transaction.transaction_index !== receipt.transaction_index
      || transaction.from !== receipt.from || transaction.to !== receipt.to
      || receipt.block_number > commonBlock.block_number) {
      fail(`${label} ${operation} transaction and receipt disagree`);
    }
    const block = await readBlock(
      fetchImpl,
      endpoint,
      quantityHex(receipt.block_number),
      `${label} ${operation}`,
    );
    if (block.block_hash !== receipt.block_hash) fail(`${label} ${operation} block disagrees`);
    return { transaction, receipt, block };
  }
  const [primary, secondary] = await Promise.all([
    one(endpoints.primary, "primary"),
    one(endpoints.secondary, "secondary"),
  ]);
  if (!canonicalEqual(primary, secondary)) fail(`${operation} dual-RPC evidence disagrees`);
  const txSha = transactionSha256(primary.transaction);
  const receiptSha = receiptSha256(primary.receipt);
  const blockSha = blockSha256(primary.block);
  const primaryId = rpcIdentitySha256(endpoints.primary.origin);
  const secondaryId = rpcIdentitySha256(endpoints.secondary.origin);
  return {
    operation,
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_transaction: primary.transaction,
    primary_rpc_transaction_sha256: txSha,
    secondary_rpc_transaction: secondary.transaction,
    secondary_rpc_transaction_sha256: txSha,
    primary_rpc_receipt: primary.receipt,
    primary_rpc_receipt_sha256: receiptSha,
    secondary_rpc_receipt: secondary.receipt,
    secondary_rpc_receipt_sha256: receiptSha,
    primary_rpc_block: primary.block,
    primary_rpc_block_sha256: blockSha,
    secondary_rpc_block: secondary.block,
    secondary_rpc_block_sha256: blockSha,
  };
}

function rpcIdentitySha256(origin) {
  return domainSha256("dnai-wikigen/base-sepolia-rpc-origin/v1\0", { origin });
}

function royaltyAuthorityFromPrescription(prescription) {
  const source = prescription.authority;
  return normalizeRoyaltyReleaseAuthority({
    schema: ROYALTY_RELEASE_AUTHORITY_SCHEMA,
    chain_id: CHAIN_ID,
    distributor_address: source.distributor_address,
    owner: source.owner,
    settlement_verifier: source.settlement_verifier,
    qvl_verifier: source.qvl_verifier,
    execution_policy_anchor: source.anchor_address,
    anchor_writer: source.anchor_writer,
    anchor_writer_release_commitment: source.anchor_writer_release_commitment,
    authority_nonce: Number(source.authority_nonce),
    authority_timelock_seconds: ROYALTY_AUTHORITY_TIMELOCK_SECONDS,
    release_policy_commitment: source.release_policy_commitment,
  });
}

function ledgerContractProjection(ledger, liveEntries) {
  if (!isRecord(ledger.contracts)) fail("frozen ledger contracts are missing");
  const configurations = [];
  const contracts = CONTRACTS.map(([contractKey, ledgerKey, controlRole], index) => {
    const stored = ledger.contracts[ledgerKey];
    const live = liveEntries[index];
    if (!isRecord(stored)) fail(`frozen ledger ${ledgerKey} contract is missing`);
    const storedAddress = address(stored.address, `${ledgerKey} ledger address`);
    const storedRuntime = bytes32(stored.runtimeCodeHash, `${ledgerKey} ledger runtime`);
    const storedControl = address(stored[controlRole], `${ledgerKey} ledger ${controlRole}`);
    if (live.contract_key !== contractKey || live.address !== storedAddress
      || live.runtime_code_hash !== storedRuntime || live.control_role !== controlRole
      || live.control_address !== storedControl) {
      fail(`${ledgerKey} live identity or control differs from the frozen ledger`);
    }
    const configuration = {
      schema: "dnai.base-sepolia-frozen-ledger-contract-configuration.v1",
      contract_key: contractKey,
      address: storedAddress,
      runtime_code_hash: storedRuntime,
      control_role: controlRole,
      control_address: storedControl,
      frozen_ledger_contract_sha256:
        royaltyHistoryFrozenLedgerContractSha256(stored),
      getter_observations: live.getter_observations,
    };
    const configurationSha256 = domainSha256(
      "dnai-wikigen/base-sepolia-contract-configuration/v1\0",
      configuration,
    );
    configurations.push({ ...configuration, configuration_sha256: configurationSha256 });
    return {
      ...live,
      getter_observations: undefined,
      configuration_sha256: configurationSha256,
    };
  });
  return {
    contracts: contracts.map(({ getter_observations: _discard, ...entry }) => entry),
    configurations,
  };
}

async function collectFullSuiteState(fetchImpl, endpoint, block, ledger, authority, label) {
  const entries = await Promise.all(CONTRACTS.map(async ([contractKey, ledgerKey, role]) => {
    const stored = ledger.contracts?.[ledgerKey];
    if (!isRecord(stored)) fail(`${ledgerKey} is absent from the frozen ledger`);
    const target = address(stored.address, `${ledgerKey} address`);
    const getterSignatures = CONFIG_GETTERS[contractKey];
    if (!Array.isArray(getterSignatures) || getterSignatures.length === 0) {
      fail(`${ledgerKey} has no code-owned configuration getter projection`);
    }
    const [code, controlWord] = await Promise.all([
      rpc(fetchImpl, endpoint, "eth_getCode", [target, quantityHex(block.block_number)]),
      ethCall(fetchImpl, endpoint, target, `${role}()`, [], block.block_number, `${label} ${ledgerKey} ${role}`),
    ]);
    // Keep at most one configuration getter in flight per contract. Seven
    // contracts remain parallel, but an oversized/malicious RPC cannot force
    // hundreds of simultaneous near-limit response buffers.
    const getterResults = [];
    for (const signature of getterSignatures) {
      getterResults.push({
        signature,
        result: await ethCall(
          fetchImpl,
          endpoint,
          target,
          signature,
          [],
          block.block_number,
          `${label} ${ledgerKey} ${signature}`,
        ),
      });
    }
    const runtimeCode = hex(code, `${label} ${ledgerKey} runtime`, { empty: false });
    return {
      contract_key: contractKey,
      address: target,
      runtime_code_hash: ethereumKeccak256Hex(Buffer.from(runtimeCode.slice(2), "hex")),
      control_role: role,
      control_address: decodeAddress(controlWord, `${label} ${ledgerKey} ${role}`),
      getter_observations: getterResults,
    };
  }));
  const projection = ledgerContractProjection(ledger, entries);
  const royaltyState = await collectRoyaltyState(fetchImpl, endpoint, block, authority, label);
  return {
    schema: FULL_SUITE_SCHEMA,
    chain_id: CHAIN_ID,
    block_number: block.block_number,
    block_hash: block.block_hash,
    contracts: projection.contracts,
    contract_configurations: projection.configurations,
    royalty_release_active_state: royaltyState,
  };
}

function normalizeFullSuiteState(value) {
  const parsed = exact(value, [
    "block_hash", "block_number", "chain_id", "contract_configurations",
    "contracts", "royalty_release_active_state", "schema",
  ], "Royalty full-suite state");
  if (parsed.schema !== FULL_SUITE_SCHEMA || parsed.chain_id !== CHAIN_ID
    || !Number.isSafeInteger(parsed.block_number) || parsed.block_number < 1) {
    fail("Royalty full-suite state identity is invalid");
  }
  const blockHash = bytes32(parsed.block_hash, "Royalty full-suite block hash");
  if (!Array.isArray(parsed.contracts) || parsed.contracts.length !== CONTRACTS.length
    || !Array.isArray(parsed.contract_configurations)
    || parsed.contract_configurations.length !== CONTRACTS.length) {
    fail("Royalty full-suite state requires seven contracts and configurations");
  }
  const configurations = parsed.contract_configurations.map((entry, index) => {
    const [contractKey, , controlRole] = CONTRACTS[index];
    const config = exact(entry, [
      "address", "configuration_sha256", "contract_key", "control_address",
      "control_role", "frozen_ledger_contract_sha256", "getter_observations",
      "runtime_code_hash", "schema",
    ], `${contractKey} configuration`);
    if (config.schema !== "dnai.base-sepolia-frozen-ledger-contract-configuration.v1"
      || config.contract_key !== contractKey || config.control_role !== controlRole
      || !Array.isArray(config.getter_observations)
      || config.getter_observations.length !== CONFIG_GETTERS[contractKey].length) {
      fail(`${contractKey} configuration getter projection is invalid`);
    }
    const getters = config.getter_observations.map((observation, getterIndex) => {
      const item = exact(observation, ["result", "signature"], `${contractKey} getter`);
      if (item.signature !== CONFIG_GETTERS[contractKey][getterIndex]) {
        fail(`${contractKey} getter order or signature drifted`);
      }
      return {
        signature: item.signature,
        result: abiWord(item.result, `${contractKey} getter result`),
      };
    });
    const core = {
      schema: config.schema,
      contract_key: contractKey,
      address: address(config.address, `${contractKey} address`),
      runtime_code_hash: bytes32(config.runtime_code_hash, `${contractKey} runtime`),
      control_role: controlRole,
      control_address: address(config.control_address, `${contractKey} control`),
      frozen_ledger_contract_sha256: sha256(
        config.frozen_ledger_contract_sha256,
        `${contractKey} frozen-ledger record`,
      ),
      getter_observations: getters,
    };
    const controlGetter = getters.find((item) => item.signature === `${controlRole}()`);
    if (!controlGetter
      || decodeAddress(controlGetter.result, `${contractKey} control getter`)
        !== core.control_address) {
      fail(`${contractKey} control getter differs from its projected control address`);
    }
    const digest = domainSha256(
      "dnai-wikigen/base-sepolia-contract-configuration/v1\0",
      core,
    );
    if (config.configuration_sha256 !== digest) {
      fail(`${contractKey} configuration digest is invalid`);
    }
    return { ...core, configuration_sha256: digest };
  });
  const contracts = parsed.contracts.map((entry, index) => {
    const config = configurations[index];
    const contract = exact(entry, [
      "address", "configuration_sha256", "contract_key", "control_address",
      "control_role", "runtime_code_hash",
    ], `full-suite contract ${index}`);
    if (contract.contract_key !== config.contract_key
      || contract.address !== config.address
      || contract.runtime_code_hash !== config.runtime_code_hash
      || contract.control_role !== config.control_role
      || contract.control_address !== config.control_address
      || contract.configuration_sha256 !== config.configuration_sha256) {
      fail(`${config.contract_key} contract differs from its getter configuration`);
    }
    return { ...contract };
  });
  return {
    schema: parsed.schema,
    chain_id: CHAIN_ID,
    block_number: parsed.block_number,
    block_hash: blockHash,
    contracts,
    contract_configurations: configurations,
    royalty_release_active_state: parsed.royalty_release_active_state,
  };
}

function fullSuiteStateSha256(value) {
  return domainSha256(
    "dnai-wikigen/base-sepolia-royalty-full-suite-state/v1\0",
    normalizeFullSuiteState(value),
  );
}

export function royaltyHistoryFullSuiteStateSha256(value) {
  return fullSuiteStateSha256(value);
}

export function royaltyHistoryContractConfigurationSha256(value) {
  return domainSha256(
    "dnai-wikigen/base-sepolia-contract-configuration/v1\0",
    value,
  );
}

export function royaltyHistoryLatestStateRecheckSha256(
  primary,
  secondary,
  primaryFinalizedHead,
  secondaryFinalizedHead,
) {
  return domainSha256(
    "dnai-wikigen/base-sepolia-royalty-latest-state-recheck/v1\0",
    {
      primary_finalized_head: normalizeBlockObservation(
        primaryFinalizedHead,
        "primary finalized head",
      ),
      secondary_finalized_head: normalizeBlockObservation(
        secondaryFinalizedHead,
        "secondary finalized head",
      ),
      primary: normalizeFullSuiteState(primary),
      secondary: normalizeFullSuiteState(secondary),
    },
  );
}

function stateEvidence(phase, primaryId, secondaryId, primaryBlock, secondaryBlock, primary, secondary, authority) {
  const primarySha = royaltyReleaseStateSha256(primary, { authority, phase });
  const secondarySha = royaltyReleaseStateSha256(secondary, { authority, phase });
  if (!canonicalEqual(primary, secondary) || primarySha !== secondarySha) {
    fail(`${phase} dual-RPC state disagrees`);
  }
  return {
    phase,
    primary_rpc_id_sha256: primaryId,
    secondary_rpc_id_sha256: secondaryId,
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: blockSha256(primaryBlock),
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: blockSha256(secondaryBlock),
    primary_rpc_state: primary,
    primary_rpc_state_sha256: primarySha,
    secondary_rpc_state: secondary,
    secondary_rpc_state_sha256: secondarySha,
  };
}

function readStableCanonicalJson(filePath, label, expectedMode = null) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be canonical and absolute`);
  }
  let canonical;
  try { canonical = fs.realpathSync.native(filePath); } catch { fail(`${label} does not exist`); }
  if (canonical !== filePath) fail(`${label} path must be symlink-free`);
  const before = fs.lstatSync(filePath, { bigint: true });
  const uid = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : before.uid;
  const mode = Number(before.mode & 0o777n);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || before.uid !== uid || (mode & 0o022) !== 0
    || (expectedMode !== null && mode !== expectedMode)
    || before.size < 2n || before.size > BigInt(MAX_FILE_BYTES)) {
    fail(`${label} must be a bounded operator-owned single-link canonical file`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      fail(`${label} changed while opening`);
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) fail(`${label} ended during read`);
      offset += count;
    }
    const after = fs.fstatSync(fd, { bigint: true });
    const current = fs.lstatSync(filePath, { bigint: true });
    for (const key of ["dev", "ino", "size", "mtimeNs", "ctimeNs"]) {
      if (opened[key] !== after[key] || after[key] !== current[key]) {
        fail(`${label} changed during read`);
      }
    }
    let value;
    try { value = JSON.parse(bytes.toString("utf8")); } catch { fail(`${label} is not JSON`); }
    if (canonicalText(value) !== bytes.toString("utf8")) {
      fail(`${label} must be canonical recursively sorted JSON`);
    }
    return { value, bytes, sha256: rawSha256(bytes), mode };
  } finally {
    fs.closeSync(fd);
  }
}

function writeExclusiveImmutable(filePath, value) {
  const text = canonicalText(value);
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length > MAX_FILE_BYTES) fail("collector output exceeds the byte bound");
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath
    || fs.existsSync(filePath)) fail("collector output must be an absent canonical absolute path");
  const parent = path.dirname(filePath);
  if (fs.realpathSync.native(parent) !== parent) fail("collector output parent is not canonical");
  const stat = fs.lstatSync(parent);
  const uid = typeof process.geteuid === "function" ? process.geteuid() : stat.uid;
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid
    || (stat.mode & 0o077) !== 0) fail("collector output parent must be private and operator-owned");
  const staging = path.join(parent, `.royalty-history-${randomBytes(16).toString("hex")}.tmp`);
  let fd;
  try {
    fd = fs.openSync(staging, fs.constants.O_CREAT | fs.constants.O_EXCL
      | fs.constants.O_WRONLY | NOFOLLOW, 0o600);
    fs.writeFileSync(fd, bytes);
    fs.fsyncSync(fd);
    fs.fchmodSync(fd, 0o444);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(staging, filePath);
    fs.unlinkSync(staging);
    const parentFd = fs.openSync(parent, fs.constants.O_RDONLY);
    try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
    const stored = readStableCanonicalJson(filePath, "collector output", 0o444);
    if (!stored.bytes.equals(bytes)) fail("collector output verification failed");
    return stored.sha256;
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try { if (fs.existsSync(staging)) fs.unlinkSync(staging); } catch {}
    throw error;
  }
}

function frozenLedgerContext(options) {
  const replay = replayReleaseCeremonyLedgerRevisionChain({
    repositoryRoot: options.repositoryRoot,
    sourceManifestPath: options.sourceManifestPath,
    ledgerPath: options.ledgerPath,
    evidenceRoot: options.evidenceRoot,
    lockRoot: options.lockRoot,
    releaseSha: options.releaseSha,
    deploymentIntentSha256: options.deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      options.reviewerAuthorityGenesisAcceptanceSha256,
    tinkerAccountBindingCeremonyReceiptSha256:
      options.tinkerAccountBindingCeremonyReceiptSha256,
  });
  if (replay.finalized !== true || replay.ledger_mode !== "0444"
    || replay.finalization_receipt_sha256 === null || replay.revision_count < 2) {
    fail("Royalty H collection requires a replayed finalized 0444 ceremony ledger");
  }
  const ledger = readStableCanonicalJson(options.ledgerPath, "frozen ceremony ledger", 0o444);
  if (ledger.sha256 !== replay.current_ledger_sha256) {
    fail("frozen ceremony ledger changed after replay");
  }
  return { replay, ledger: ledger.value };
}

function normalizePhaseRecords(ledger, options, prescription) {
  if (!Array.isArray(ledger.royaltyReleaseHistory)
    || ledger.royaltyReleaseHistory.length !== 2) {
    fail("frozen ledger must contain exactly two Royalty release records");
  }
  const [phaseOne, phaseTwo] = ledger.royaltyReleaseHistory;
  for (const [index, record] of [phaseOne, phaseTwo].entries()) {
    if (!isRecord(record) || record.phase !== index + 1
      || record.sourceCommit !== options.releaseSha
      || typeof record.royaltyDistributorAddress !== "string"
      || record.royaltyDistributorAddress.toLowerCase()
        !== prescription.authority.distributor_address
      || typeof record.runtimeCodeHash !== "string"
      || record.runtimeCodeHash.toLowerCase()
        !== prescription.authority.distributor_runtime_code_hash
      || record.freshContractDeploymentReceiptSha256
        !== prescription.fresh_contract_deployment_receipt_sha256
      || record.royaltyReleasePrescriptiveAuthoritySha256
        !== royaltyReleasePrescriptiveAuthoritySha256(prescription)
      || record.reviewerAuthority?.deploymentIntentSha256
        !== options.deploymentIntentSha256
      || record.reviewerAuthority?.genesisAcceptanceSha256
        !== options.reviewerAuthorityGenesisAcceptanceSha256) {
      fail(`Royalty phase ${index + 1} frozen-ledger lineage is invalid`);
    }
  }
  if (phaseOne.executionMode !== "stage_authority"
    || !["activate_and_unpause", "recover_reverted_unpause"]
      .includes(phaseTwo.executionMode)
    || !Array.isArray(phaseOne.transactionReceipts)
    || phaseOne.transactionReceipts.length !== 1
    || !Array.isArray(phaseTwo.transactionReceipts)
    || phaseTwo.transactionReceipts.length !== (phaseTwo.executionMode === "activate_and_unpause" ? 2 : 1)) {
    fail("Royalty phase records do not contain one phase-one and one terminal phase-two execution");
  }
  return { phaseOne, phaseTwo };
}

function transactionHashFromReceipt(value, label) {
  return bytes32(value?.transactionHash, label);
}

export function normalizeRoyaltyFinalizedHistoryEvidence(value) {
  const parsed = exact(value, [
    "collection_proof", "common_finalized_state", "contracts",
    "deployment_intent_sha256", "execution_mode",
    "fresh_contract_deployment_receipt_sha256", "frozen_final_ledger_sha256",
    "ledger_finalization_receipt_sha256", "ledger_revision_chain_sha256",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "royalty_release_history", "royalty_release_prescriptive_authority",
    "royalty_release_prescriptive_authority_sha256", "schema",
    "tinker_account_binding_ceremony_receipt_sha256", "truth_status",
  ], "Royalty finalized-history evidence");
  if (parsed.schema !== ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA
    || parsed.truth_status !== ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS
    || typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || /^0+$/.test(parsed.release_sha)
    || !["activate_and_unpause", "recover_reverted_unpause"].includes(parsed.execution_mode)) {
    fail("Royalty finalized-history evidence identity or execution mode is invalid");
  }
  const prescription = normalizeRoyaltyReleasePrescriptiveAuthority(
    parsed.royalty_release_prescriptive_authority,
    { deploymentIntentSha256: parsed.deployment_intent_sha256 },
  );
  const prescriptionSha = royaltyReleasePrescriptiveAuthoritySha256(prescription);
  if (prescriptionSha !== parsed.royalty_release_prescriptive_authority_sha256
    || prescription.release_sha !== parsed.release_sha
    || prescription.fresh_contract_deployment_receipt_sha256
      !== parsed.fresh_contract_deployment_receipt_sha256) {
    fail("Royalty finalized-history prescription lineage is invalid");
  }
  for (const [field, label] of [
    ["deployment_intent_sha256", "deployment intent"],
    ["fresh_contract_deployment_receipt_sha256", "fresh receipt"],
    ["frozen_final_ledger_sha256", "frozen ledger"],
    ["ledger_finalization_receipt_sha256", "ledger finalization"],
    ["ledger_revision_chain_sha256", "ledger revision chain"],
    ["reviewer_authority_genesis_acceptance_sha256", "reviewer acceptance"],
    ["tinker_account_binding_ceremony_receipt_sha256", "Tinker ceremony"],
    ["royalty_release_prescriptive_authority_sha256", "Royalty prescription"],
  ]) sha256(parsed[field], label);
  const projected = projectRoyaltyReleaseHistoryReceipt({
    contracts: parsed.contracts,
    commonFinalizedState: parsed.common_finalized_state,
    royaltyReleaseHistory: parsed.royalty_release_history,
  });
  if (projected.schema !== "dnai.royalty-release-history-receipt.v2"
    || projected.execution_mode !== parsed.execution_mode) {
    fail("production Royalty finalized-history evidence must project exact H v2");
  }
  const proof = exact(parsed.collection_proof, [
    "latest_primary_full_suite_state", "latest_secondary_full_suite_state",
    "latest_state_recheck_sha256", "primary_finalized_head",
    "primary_finalized_head_sha256", "primary_full_suite_state",
    "primary_full_suite_state_sha256", "primary_rpc_id_sha256", "schema",
    "secondary_finalized_head", "secondary_finalized_head_sha256",
    "secondary_full_suite_state", "secondary_full_suite_state_sha256",
    "secondary_rpc_id_sha256",
  ], "Royalty collection proof");
  const primaryFullSuite = normalizeFullSuiteState(proof.primary_full_suite_state);
  const secondaryFullSuite = normalizeFullSuiteState(proof.secondary_full_suite_state);
  const latestPrimaryFullSuite = normalizeFullSuiteState(
    proof.latest_primary_full_suite_state,
  );
  const latestSecondaryFullSuite = normalizeFullSuiteState(
    proof.latest_secondary_full_suite_state,
  );
  const primaryFinalizedHead = normalizeBlockObservation(
    proof.primary_finalized_head,
    "primary finalized head",
  );
  const secondaryFinalizedHead = normalizeBlockObservation(
    proof.secondary_finalized_head,
    "secondary finalized head",
  );
  const common = projected.common_finalized_state;
  const checkpointNumber = Math.min(
    primaryFinalizedHead.block_number,
    secondaryFinalizedHead.block_number,
  );
  if (proof.schema !== COLLECTION_PROOF_SCHEMA
    || sha256(proof.primary_rpc_id_sha256, "primary RPC identity")
      !== common.primary_rpc_id_sha256
    || sha256(proof.secondary_rpc_id_sha256, "secondary RPC identity")
      !== common.secondary_rpc_id_sha256
    || proof.primary_finalized_head_sha256 !== blockSha256(primaryFinalizedHead)
    || proof.secondary_finalized_head_sha256 !== blockSha256(secondaryFinalizedHead)
    || common.primary_rpc_block.block_number !== checkpointNumber
    || common.secondary_rpc_block.block_number !== checkpointNumber
    || primaryFinalizedHead.block_timestamp
      < common.primary_rpc_block.block_timestamp
    || secondaryFinalizedHead.block_timestamp
      < common.secondary_rpc_block.block_timestamp
    || (primaryFinalizedHead.block_number === checkpointNumber
      && !canonicalEqual(primaryFinalizedHead, common.primary_rpc_block))
    || (secondaryFinalizedHead.block_number === checkpointNumber
      && !canonicalEqual(secondaryFinalizedHead, common.secondary_rpc_block))
    || proof.primary_full_suite_state_sha256 !== fullSuiteStateSha256(primaryFullSuite)
    || proof.secondary_full_suite_state_sha256 !== fullSuiteStateSha256(secondaryFullSuite)
    || proof.primary_full_suite_state_sha256 !== proof.secondary_full_suite_state_sha256
    || !canonicalEqual(primaryFullSuite, secondaryFullSuite)
    || !canonicalEqual(primaryFullSuite, latestPrimaryFullSuite)
    || !canonicalEqual(primaryFullSuite, latestSecondaryFullSuite)) {
    fail("Royalty collection full-suite observations disagree");
  }
  const recheckSha = royaltyHistoryLatestStateRecheckSha256(
    latestPrimaryFullSuite,
    latestSecondaryFullSuite,
    primaryFinalizedHead,
    secondaryFinalizedHead,
  );
  const suiteBindings = [
    [primaryFullSuite, common.primary_rpc_block],
    [secondaryFullSuite, common.secondary_rpc_block],
    [latestPrimaryFullSuite, common.primary_rpc_block],
    [latestSecondaryFullSuite, common.secondary_rpc_block],
  ];
  const suitesAtCheckpoint = suiteBindings.every(([suite, block]) => (
    suite.block_number === block.block_number
    && suite.block_hash === block.block_hash
    && suite.royalty_release_active_state?.block_number === suite.block_number
    && suite.royalty_release_active_state?.block_hash === suite.block_hash
  ));
  if (proof.latest_state_recheck_sha256 !== recheckSha
    || parsed.common_finalized_state.latest_state_recheck_sha256 !== recheckSha
    || parsed.common_finalized_state.canonical_state_sha256
      !== proof.primary_full_suite_state_sha256
    || parsed.common_finalized_state.primary_state_sha256
      !== proof.primary_full_suite_state_sha256
    || parsed.common_finalized_state.secondary_state_sha256
      !== proof.secondary_full_suite_state_sha256
    || !suitesAtCheckpoint
    || !canonicalEqual(projected.contracts, primaryFullSuite.contracts)
    || !canonicalEqual(
      projected.royalty_release_active_state,
      primaryFullSuite.royalty_release_active_state,
    )) {
    fail("Royalty collection proof is not bound to the H projection");
  }
  const authority = royaltyAuthorityFromPrescription(prescription);
  if (!canonicalEqual(authority, projected.royalty_release_authority)
    || prescription.authority.distributor_runtime_code_hash
      !== projected.contracts[2].runtime_code_hash
    || prescription.authority.anchor_runtime_code_hash
      !== projected.contracts[6].runtime_code_hash) {
    fail("Royalty prescription authority differs from finalized H evidence");
  }
  return {
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    deployment_intent_sha256: parsed.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      parsed.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    tinker_account_binding_ceremony_receipt_sha256:
      parsed.tinker_account_binding_ceremony_receipt_sha256,
    frozen_final_ledger_sha256: parsed.frozen_final_ledger_sha256,
    ledger_finalization_receipt_sha256: parsed.ledger_finalization_receipt_sha256,
    ledger_revision_chain_sha256: parsed.ledger_revision_chain_sha256,
    royalty_release_prescriptive_authority: prescription,
    royalty_release_prescriptive_authority_sha256: prescriptionSha,
    execution_mode: parsed.execution_mode,
    contracts: projected.contracts,
    common_finalized_state: projected.common_finalized_state,
    royalty_release_history: projected.royalty_release_history,
    collection_proof: {
      schema: COLLECTION_PROOF_SCHEMA,
      primary_rpc_id_sha256: proof.primary_rpc_id_sha256,
      secondary_rpc_id_sha256: proof.secondary_rpc_id_sha256,
      primary_finalized_head: primaryFinalizedHead,
      primary_finalized_head_sha256: proof.primary_finalized_head_sha256,
      secondary_finalized_head: secondaryFinalizedHead,
      secondary_finalized_head_sha256: proof.secondary_finalized_head_sha256,
      primary_full_suite_state: primaryFullSuite,
      primary_full_suite_state_sha256: proof.primary_full_suite_state_sha256,
      secondary_full_suite_state: secondaryFullSuite,
      secondary_full_suite_state_sha256: proof.secondary_full_suite_state_sha256,
      latest_primary_full_suite_state: latestPrimaryFullSuite,
      latest_secondary_full_suite_state: latestSecondaryFullSuite,
      latest_state_recheck_sha256: recheckSha,
    },
  };
}

export function verifyRoyaltyFinalizedHistoryEvidenceAgainstFrozenLedger(
  value,
  options,
) {
  const evidence = normalizeRoyaltyFinalizedHistoryEvidence(value);
  const expected = {
    releaseSha: string(options.releaseSha, SHA40, "release SHA", { nonzero: true }),
    deploymentIntentSha256: sha256(
      options.deploymentIntentSha256,
      "deployment intent",
    ),
    reviewerAuthorityGenesisAcceptanceSha256: sha256(
      options.reviewerAuthorityGenesisAcceptanceSha256,
      "reviewer genesis acceptance",
    ),
    tinkerAccountBindingCeremonyReceiptSha256: sha256(
      options.tinkerAccountBindingCeremonyReceiptSha256,
      "Tinker account-binding ceremony receipt",
    ),
  };
  if (evidence.release_sha !== expected.releaseSha
    || evidence.deployment_intent_sha256 !== expected.deploymentIntentSha256
    || evidence.reviewer_authority_genesis_acceptance_sha256
      !== expected.reviewerAuthorityGenesisAcceptanceSha256
    || evidence.tinker_account_binding_ceremony_receipt_sha256
      !== expected.tinkerAccountBindingCeremonyReceiptSha256) {
    fail("finalized-history evidence differs from the explicit ceremony replay pins");
  }
  const frozen = (options.frozenLedgerLoader ?? frozenLedgerContext)(options);
  if (!isRecord(frozen) || !isRecord(frozen.replay) || !isRecord(frozen.ledger)
    || frozen.replay.finalized !== true || frozen.replay.ledger_mode !== "0444"
    || frozen.replay.finalization_receipt_sha256 === null) {
    fail("H creation requires a replayed finalized 0444 ceremony ledger");
  }
  if (evidence.frozen_final_ledger_sha256
      !== frozen.replay.current_ledger_sha256
    || evidence.ledger_finalization_receipt_sha256
      !== frozen.replay.finalization_receipt_sha256
    || evidence.ledger_revision_chain_sha256
      !== frozen.replay.revision_chain_sha256) {
    fail("finalized-history evidence ledger digests differ from replay");
  }

  const prescription = evidence.royalty_release_prescriptive_authority;
  const { phaseOne, phaseTwo } = normalizePhaseRecords(
    frozen.ledger,
    options,
    prescription,
  );
  if (phaseTwo.executionMode !== evidence.execution_mode) {
    fail("finalized-history execution mode differs from the frozen ledger");
  }

  const configurations = evidence.collection_proof
    .primary_full_suite_state.contract_configurations;
  for (const [index, [contractKey, ledgerKey, controlRole]] of CONTRACTS.entries()) {
    const stored = frozen.ledger.contracts?.[ledgerKey];
    const contract = evidence.contracts[index];
    const configuration = configurations[index];
    if (!isRecord(stored)
      || contract.contract_key !== contractKey
      || contract.address !== address(stored.address, `${ledgerKey} ledger address`)
      || contract.runtime_code_hash
        !== bytes32(stored.runtimeCodeHash, `${ledgerKey} ledger runtime`)
      || contract.control_role !== controlRole
      || contract.control_address
        !== address(stored[controlRole], `${ledgerKey} ledger ${controlRole}`)
      || configuration.frozen_ledger_contract_sha256
        !== royaltyHistoryFrozenLedgerContractSha256(stored)) {
      fail(`${ledgerKey} evidence differs from the exact frozen-ledger record`);
    }
  }

  const history = evidence.royalty_release_history;
  const proposalHash = transactionHashFromReceipt(
    phaseOne.transactionReceipts[0],
    "frozen-ledger proposal transaction hash",
  );
  let activationHash;
  let revertedHash = null;
  let unpauseHash;
  if (phaseTwo.executionMode === "activate_and_unpause") {
    activationHash = transactionHashFromReceipt(
      phaseTwo.transactionReceipts[0],
      "frozen-ledger activation transaction hash",
    );
    unpauseHash = transactionHashFromReceipt(
      phaseTwo.transactionReceipts[1],
      "frozen-ledger unpause transaction hash",
    );
  } else {
    activationHash = bytes32(
      phaseTwo.phaseTwoRecovery?.activation_tx_hash,
      "frozen-ledger recovery activation transaction hash",
    );
    revertedHash = bytes32(
      phaseTwo.phaseTwoRecovery?.reverted_unpause_tx_hash,
      "frozen-ledger reverted unpause transaction hash",
    );
    unpauseHash = transactionHashFromReceipt(
      phaseTwo.transactionReceipts[0],
      "frozen-ledger recovery unpause transaction hash",
    );
  }
  const observedProposal = history.phase_one.proposal_transaction
    .primary_rpc_transaction.transaction_hash;
  const observedActivation = history.phase_two.activation_transaction
    .primary_rpc_transaction.transaction_hash;
  const observedUnpause = history.phase_two.unpause_transaction
    .primary_rpc_transaction.transaction_hash;
  const observedReverted = history.phase_two.reverted_unpause_transaction
    ?.primary_rpc_transaction.transaction_hash ?? null;
  if (proposalHash !== observedProposal || activationHash !== observedActivation
    || unpauseHash !== observedUnpause || revertedHash !== observedReverted) {
    fail("finalized-history transaction hashes differ from the frozen Royalty records");
  }
  const royaltyStored = frozen.ledger.contracts?.royaltyDistributor;
  if (!isRecord(royaltyStored)
    || royaltyStored.deploymentBlock
      !== history.fresh_state.primary_rpc_block.block_number
    || bytes32(
      royaltyStored.deploymentBlockHash,
      "Royalty frozen-ledger deployment block hash",
    ) !== history.fresh_state.primary_rpc_block.block_hash) {
    fail("finalized-history fresh Royalty state differs from the frozen deployment");
  }
  return {
    evidence,
    replay: frozen.replay,
  };
}

export function canonicalRoyaltyFinalizedHistoryEvidenceText(value) {
  return canonicalText(normalizeRoyaltyFinalizedHistoryEvidence(value));
}

export function royaltyFinalizedHistoryEvidenceSha256(value) {
  return domainSha256(
    ROYALTY_FINALIZED_HISTORY_EVIDENCE_DOMAIN,
    normalizeRoyaltyFinalizedHistoryEvidence(value),
  );
}

export async function collectRoyaltyFinalizedHistoryEvidence(options) {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") fail("fetch implementation is unavailable");
  string(options.releaseSha, SHA40, "release SHA", { nonzero: true });
  const endpoints = normalizeRoyaltyHistoryRpcEndpoints(options.primaryRpc, options.secondaryRpc);
  const frozen = (options.frozenLedgerLoader ?? frozenLedgerContext)(options);
  if (frozen.replay.finalized !== true || frozen.replay.ledger_mode !== "0444"
    || frozen.replay.finalization_receipt_sha256 === null) {
    fail("Royalty H collection requires a finalized frozen ledger");
  }
  const prescription = normalizeRoyaltyReleasePrescriptiveAuthority(
    options.royaltyReleasePrescription,
    { deploymentIntentSha256: options.deploymentIntentSha256 },
  );
  if (prescription.release_sha !== options.releaseSha) fail("Royalty prescription release mismatch");
  const { phaseOne, phaseTwo } = normalizePhaseRecords(
    frozen.ledger,
    options,
    prescription,
  );
  const authority = royaltyAuthorityFromPrescription(prescription);
  const [primaryChain, secondaryChain, primaryFinalized, secondaryFinalized] = await Promise.all([
    rpc(fetchImpl, endpoints.primary, "eth_chainId"),
    rpc(fetchImpl, endpoints.secondary, "eth_chainId"),
    readBlock(fetchImpl, endpoints.primary, "finalized", "primary finalized"),
    readBlock(fetchImpl, endpoints.secondary, "finalized", "secondary finalized"),
  ]);
  if (safeQuantity(primaryChain, "primary RPC chain ID") !== CHAIN_ID
    || safeQuantity(secondaryChain, "secondary RPC chain ID") !== CHAIN_ID) {
    fail("RPC authorities are not Base Sepolia");
  }
  const checkpointNumber = Math.min(primaryFinalized.block_number, secondaryFinalized.block_number);
  const [primaryBlock, secondaryBlock] = await Promise.all([
    readBlock(fetchImpl, endpoints.primary, quantityHex(checkpointNumber), "primary common finalized"),
    readBlock(fetchImpl, endpoints.secondary, quantityHex(checkpointNumber), "secondary common finalized"),
  ]);
  if (!canonicalEqual(primaryBlock, secondaryBlock)) fail("RPCs disagree on the common finalized block");
  const [primarySuite, secondarySuite] = await Promise.all([
    collectFullSuiteState(fetchImpl, endpoints.primary, primaryBlock, frozen.ledger, authority, "primary"),
    collectFullSuiteState(fetchImpl, endpoints.secondary, secondaryBlock, frozen.ledger, authority, "secondary"),
  ]);
  if (!canonicalEqual(primarySuite, secondarySuite)) fail("RPCs disagree on the finalized full-suite state");
  const contracts = primarySuite.contracts;
  const suiteSha = fullSuiteStateSha256(primarySuite);
  const commonFinalizedState = {
    independent_rpc_count: 2,
    primary_rpc_id_sha256: rpcIdentitySha256(endpoints.primary.origin),
    secondary_rpc_id_sha256: rpcIdentitySha256(endpoints.secondary.origin),
    primary_rpc_block: primaryBlock,
    primary_rpc_block_sha256: blockSha256(primaryBlock),
    secondary_rpc_block: secondaryBlock,
    secondary_rpc_block_sha256: blockSha256(secondaryBlock),
    primary_state_sha256: suiteSha,
    secondary_state_sha256: suiteSha,
    canonical_state_sha256: suiteSha,
    latest_state_recheck_sha256: `sha256:${"f".repeat(64)}`,
  };
  const royaltyStored = frozen.ledger.contracts?.royaltyDistributor;
  const freshBlockNumber = royaltyStored?.deploymentBlock;
  const freshBlockHash = typeof royaltyStored?.deploymentBlockHash === "string"
    ? royaltyStored.deploymentBlockHash.toLowerCase()
    : "";
  if (!Number.isSafeInteger(freshBlockNumber) || freshBlockNumber < 1) {
    fail("frozen ledger lacks the Royalty fresh deployment block");
  }
  const [freshPrimaryBlock, freshSecondaryBlock] = await Promise.all([
    readBlock(fetchImpl, endpoints.primary, quantityHex(freshBlockNumber), "primary fresh Royalty"),
    readBlock(fetchImpl, endpoints.secondary, quantityHex(freshBlockNumber), "secondary fresh Royalty"),
  ]);
  if (!canonicalEqual(freshPrimaryBlock, freshSecondaryBlock)
    || freshPrimaryBlock.block_hash !== freshBlockHash) {
    fail("fresh Royalty block disagrees with the immutable deployment receipt");
  }
  const [freshPrimaryState, freshSecondaryState] = await Promise.all([
    collectRoyaltyState(fetchImpl, endpoints.primary, freshPrimaryBlock, authority, "primary fresh"),
    collectRoyaltyState(fetchImpl, endpoints.secondary, freshSecondaryBlock, authority, "secondary fresh"),
  ]);
  const proposalHash = transactionHashFromReceipt(
    phaseOne.transactionReceipts[0],
    "phase-one proposal transaction hash",
  );
  const proposal = await collectMutation(
    fetchImpl,
    endpoints,
    proposalHash,
    "propose_authority_binding",
    primaryBlock,
  );
  const proposalBlockNumber = proposal.primary_rpc_block.block_number;
  const [pendingPrimaryState, pendingSecondaryState] = await Promise.all([
    collectRoyaltyState(fetchImpl, endpoints.primary, proposal.primary_rpc_block, authority, "primary pending"),
    collectRoyaltyState(fetchImpl, endpoints.secondary, proposal.secondary_rpc_block, authority, "secondary pending"),
  ]);
  if (freshBlockNumber >= proposalBlockNumber) fail("fresh Royalty state does not precede phase one");
  let activationHash;
  let revertedHash = null;
  let unpauseHash;
  if (phaseTwo.executionMode === "activate_and_unpause") {
    activationHash = transactionHashFromReceipt(phaseTwo.transactionReceipts[0], "activation hash");
    unpauseHash = transactionHashFromReceipt(phaseTwo.transactionReceipts[1], "unpause hash");
  } else {
    activationHash = bytes32(phaseTwo.phaseTwoRecovery?.activation_tx_hash, "recovery activation hash");
    revertedHash = bytes32(phaseTwo.phaseTwoRecovery?.reverted_unpause_tx_hash, "reverted unpause hash");
    unpauseHash = transactionHashFromReceipt(phaseTwo.transactionReceipts[0], "recovery unpause hash");
  }
  const activation = await collectMutation(
    fetchImpl, endpoints, activationHash, "activate_authority_proposal", primaryBlock,
  );
  const reverted = revertedHash === null ? null : await collectMutation(
    fetchImpl, endpoints, revertedHash, "unpause", primaryBlock,
  );
  const unpause = await collectMutation(fetchImpl, endpoints, unpauseHash, "unpause", primaryBlock);
  const primaryId = commonFinalizedState.primary_rpc_id_sha256;
  const secondaryId = commonFinalizedState.secondary_rpc_id_sha256;
  const history = {
    schema: ROYALTY_RELEASE_HISTORY_V2_SCHEMA,
    execution_mode: phaseTwo.executionMode,
    authority,
    fresh_state: stateEvidence(
      "fresh", primaryId, secondaryId, freshPrimaryBlock, freshSecondaryBlock,
      freshPrimaryState, freshSecondaryState, authority,
    ),
    phase_one: {
      proposal_transaction: proposal,
      poststate: stateEvidence(
        "phase_one_pending", primaryId, secondaryId,
        proposal.primary_rpc_block, proposal.secondary_rpc_block,
        pendingPrimaryState, pendingSecondaryState, authority,
      ),
    },
    phase_two: {
      activation_transaction: activation,
      unpause_transaction: unpause,
      poststate: stateEvidence(
        "phase_two_active", primaryId, secondaryId, primaryBlock, secondaryBlock,
        primarySuite.royalty_release_active_state,
        secondarySuite.royalty_release_active_state,
        authority,
      ),
    },
  };
  if (reverted !== null) history.phase_two.reverted_unpause_transaction = reverted;
  const [latestPrimaryBlock, latestSecondaryBlock] = await Promise.all([
    readBlock(fetchImpl, endpoints.primary, quantityHex(checkpointNumber), "primary common recheck"),
    readBlock(fetchImpl, endpoints.secondary, quantityHex(checkpointNumber), "secondary common recheck"),
  ]);
  if (!canonicalEqual(primaryBlock, latestPrimaryBlock)
    || !canonicalEqual(primaryBlock, latestSecondaryBlock)) fail("common finalized block changed during collection");
  const [latestPrimarySuite, latestSecondarySuite] = await Promise.all([
    collectFullSuiteState(fetchImpl, endpoints.primary, latestPrimaryBlock, frozen.ledger, authority, "primary recheck"),
    collectFullSuiteState(fetchImpl, endpoints.secondary, latestSecondaryBlock, frozen.ledger, authority, "secondary recheck"),
  ]);
  if (!canonicalEqual(primarySuite, latestPrimarySuite)
    || !canonicalEqual(primarySuite, latestSecondarySuite)) fail("full-suite state changed during collection");
  const recheckSha = royaltyHistoryLatestStateRecheckSha256(
    latestPrimarySuite,
    latestSecondarySuite,
    primaryFinalized,
    secondaryFinalized,
  );
  commonFinalizedState.latest_state_recheck_sha256 = recheckSha;
  const evidence = {
    schema: ROYALTY_FINALIZED_HISTORY_EVIDENCE_SCHEMA,
    truth_status: ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS,
    release_sha: options.releaseSha,
    deployment_intent_sha256: options.deploymentIntentSha256,
    fresh_contract_deployment_receipt_sha256:
      prescription.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      options.reviewerAuthorityGenesisAcceptanceSha256,
    tinker_account_binding_ceremony_receipt_sha256:
      options.tinkerAccountBindingCeremonyReceiptSha256,
    frozen_final_ledger_sha256: frozen.replay.current_ledger_sha256,
    ledger_finalization_receipt_sha256: frozen.replay.finalization_receipt_sha256,
    ledger_revision_chain_sha256: frozen.replay.revision_chain_sha256,
    royalty_release_prescriptive_authority: prescription,
    royalty_release_prescriptive_authority_sha256:
      royaltyReleasePrescriptiveAuthoritySha256(prescription),
    execution_mode: phaseTwo.executionMode,
    contracts,
    common_finalized_state: commonFinalizedState,
    royalty_release_history: history,
    collection_proof: {
      schema: COLLECTION_PROOF_SCHEMA,
      primary_rpc_id_sha256: primaryId,
      secondary_rpc_id_sha256: secondaryId,
      primary_finalized_head: primaryFinalized,
      primary_finalized_head_sha256: blockSha256(primaryFinalized),
      secondary_finalized_head: secondaryFinalized,
      secondary_finalized_head_sha256: blockSha256(secondaryFinalized),
      primary_full_suite_state: primarySuite,
      primary_full_suite_state_sha256: suiteSha,
      secondary_full_suite_state: secondarySuite,
      secondary_full_suite_state_sha256: suiteSha,
      latest_primary_full_suite_state: latestPrimarySuite,
      latest_secondary_full_suite_state: latestSecondarySuite,
      latest_state_recheck_sha256: recheckSha,
    },
  };
  // Replay and reread the frozen ledger again after the RPC cycle. Production
  // must fail if the supposedly immutable local ceremony evidence changed
  // while finalized history was being collected.
  return verifyRoyaltyFinalizedHistoryEvidenceAgainstFrozenLedger(
    evidence,
    options,
  ).evidence;
}

function parseArgs(argv) {
  if (argv[0] !== "collect") fail("command must be collect");
  const allowed = new Set([
    "--repository-root", "--source-manifest", "--ledger", "--evidence-root",
    "--lock-root", "--release-sha", "--deployment-intent-sha256",
    "--reviewer-genesis-acceptance-sha256",
    "--tinker-account-binding-ceremony-receipt-sha256",
    "--royalty-release-prescription", "--out",
  ]);
  const values = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(key) || value === undefined || values.has(key)) {
      fail("arguments must be unique supported --name value pairs");
    }
    values.set(key, value);
  }
  if ([...allowed].some((key) => !values.has(key))) fail("collect arguments are incomplete");
  return values;
}

async function main(argv) {
  const values = parseArgs(argv);
  const prescriptionRead = readStableCanonicalJson(
    values.get("--royalty-release-prescription"),
    "Royalty release prescription",
  );
  const evidence = await collectRoyaltyFinalizedHistoryEvidence({
    repositoryRoot: values.get("--repository-root"),
    sourceManifestPath: values.get("--source-manifest"),
    ledgerPath: values.get("--ledger"),
    evidenceRoot: values.get("--evidence-root"),
    lockRoot: values.get("--lock-root"),
    releaseSha: values.get("--release-sha"),
    deploymentIntentSha256: values.get("--deployment-intent-sha256"),
    reviewerAuthorityGenesisAcceptanceSha256:
      values.get("--reviewer-genesis-acceptance-sha256"),
    tinkerAccountBindingCeremonyReceiptSha256:
      values.get("--tinker-account-binding-ceremony-receipt-sha256"),
    royaltyReleasePrescription: prescriptionRead.value,
    primaryRpc: process.env.BASE_SEPOLIA_RPC_URL,
    secondaryRpc: process.env.BASE_SEPOLIA_SECONDARY_RPC_URL,
  });
  const rawOutputSha256 = writeExclusiveImmutable(values.get("--out"), evidence);
  process.stdout.write(`${JSON.stringify({
    schema: WRITE_RECEIPT_SCHEMA,
    status: "finalized_dual_rpc_history_evidence_written_create_only",
    truth_status: ROYALTY_FINALIZED_HISTORY_EVIDENCE_TRUTH_STATUS,
    release_sha: evidence.release_sha,
    execution_mode: evidence.execution_mode,
    evidence_sha256: royaltyFinalizedHistoryEvidenceSha256(evidence),
    raw_output_sha256: rawOutputSha256,
  })}\n`);
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked && import.meta.url === pathToFileURL(invoked).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
