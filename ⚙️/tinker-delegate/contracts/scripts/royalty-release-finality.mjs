#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import { ethereumKeccak256Hex } from "../../../../scripts/ethereum-keccak.mjs";

export const ROYALTY_STATE_CLASSIFICATION_SCHEMA =
  "dnai.base-sepolia-royalty-state-classification.v1";
export const ROYALTY_FINALIZED_AUTHORITY_SCHEMA =
  "dnai.base-sepolia-royalty-finalized-authority.v1";
export const ROYALTY_FINALIZED_AUTHORITY_WRITE_RECEIPT_SCHEMA =
  "dnai.base-sepolia-royalty-finalized-authority-write-receipt.v1";
export const ROYALTY_DRY_RUN_VERIFICATION_RECEIPT_SCHEMA =
  "dnai.royalty-release-dry-run-verification-receipt.v1";
export const ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA =
  "dnai.base-sepolia-royalty-unpause-recovery-evidence.v1";

const PLAN_RECEIPT_SCHEMA =
  "dnai.royalty-release-phase-plan-verification-receipt.v2";
const PLAN_RECEIPT_STATUS =
  "valid_current_two_reviewer_exact_royalty_phase_plan";
const PLAN_RECEIPT_TRUTH =
  "reviewer_signatures_and_exact_plan_validated_not_onchain_execution_finality_or_tdx_evidence";
const CHAIN_ID = 84_532;
const CHAIN_ID_HEX = "0x14a34";
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_RPC_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_URL_BYTES = 4_096;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SHA40 = /^[0-9a-f]{40}$/;
const DECIMAL = /^(?:0|[1-9][0-9]*)$/;
const HEX_BYTES = /^0x(?:[0-9a-f]{2})*$/;
const HEX_QUANTITY = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const PLAN_ACTIONS = Object.freeze({
  "1:stage_authority": ["propose_authority_binding"],
  "2:activate_and_unpause": ["activate_authority_proposal", "unpause"],
  "2:recover_reverted_unpause": ["unpause"],
});
const CLASSIFICATIONS = new Set([
  "fresh_empty",
  "phase1_exact_pending",
  "phase2_exact_active_paused",
  "phase2_exact_active_unpaused",
  "diverged",
]);
const RELEASE_POLICY_TYPE =
  "RoyaltyReleasePolicy(uint256 chainId,address distributor,uint256 authorityNonce,address settlementVerifier,address qvlVerifier,address executionPolicyAnchor,bytes32 anchorWriterReleaseCommitment)";
const FINALITY_PROOF =
  "two_distinct_https_rpcs_exact_same_finalized_numeric_block_runtime_eth_call_and_transaction_receipt_agreement";

let rpcId = 0;

export class RoyaltyReleaseFinalityError extends Error {}

function fail(message) {
  throw new RoyaltyReleaseFinalityError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
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

function rawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
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

function sha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)
    || value === `sha256:${"0".repeat(64)}`) {
    fail(`${label} must be a canonical nonzero SHA-256 digest`);
  }
  return value;
}

function decimal(value, label, maximum = (1n << 256n) - 1n) {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical decimal uint`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) fail(`${label} is out of range`);
  return parsed.toString(10);
}

function safeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a bounded safe integer`);
  }
  return value;
}

function bool(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be boolean`);
  return value;
}

function hexBytes(value, label, { empty = true } = {}) {
  if (typeof value !== "string" || !HEX_BYTES.test(value)
    || (!empty && value === "0x")) {
    fail(`${label} must be canonical lowercase hex bytes`);
  }
  return value;
}

function quantityToBigInt(value, label) {
  if (typeof value !== "string") fail(`${label} must be a hex quantity`);
  const normalized = value.toLowerCase();
  if (!HEX_QUANTITY.test(normalized)) fail(`${label} must be a canonical hex quantity`);
  return BigInt(normalized);
}

function quantityToSafeInteger(value, label, minimum = 0) {
  const parsed = quantityToBigInt(value, label);
  if (parsed > MAX_SAFE || parsed < BigInt(minimum)) {
    fail(`${label} is outside the exact JSON integer range`);
  }
  return Number(parsed);
}

function quantityToDecimal(value, label) {
  return quantityToBigInt(value, label).toString(10);
}

function quantityHex(value) {
  const parsed = typeof value === "bigint" ? value : BigInt(value);
  if (parsed < 0n) fail("negative JSON-RPC quantity is invalid");
  return `0x${parsed.toString(16)}`;
}

function selector(signature) {
  return ethereumKeccak256Hex(Buffer.from(signature, "utf8")).slice(0, 10);
}

function uintWord(value) {
  return BigInt(value).toString(16).padStart(64, "0");
}

function addressWord(value) {
  return address(value, "ABI address").slice(2).padStart(64, "0");
}

function calldata(signature, words = []) {
  return `${selector(signature)}${words.join("")}`;
}

function decodeWord(value, label) {
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    fail(`${label} must return exactly one ABI word`);
  }
  return normalized.slice(2);
}

function decodeAddress(value, label, options = {}) {
  const word = decodeWord(value, label);
  if (!/^0{24}/.test(word)) fail(`${label} returned a noncanonical ABI address`);
  return address(`0x${word.slice(24)}`, label, options);
}

function decodeBytes32(value, label, options = {}) {
  return bytes32(`0x${decodeWord(value, label)}`, label, options);
}

function decodeUintBigInt(value, label) {
  return BigInt(`0x${decodeWord(value, label)}`);
}

function decodeUintSafe(value, label) {
  const parsed = decodeUintBigInt(value, label);
  if (parsed > MAX_SAFE) fail(`${label} exceeds the exact JSON integer range`);
  return Number(parsed);
}

function decodeBool(value, label) {
  const parsed = decodeUintBigInt(value, label);
  if (parsed !== 0n && parsed !== 1n) fail(`${label} returned a noncanonical ABI bool`);
  return parsed === 1n;
}

function releasePolicyCommitment(authority) {
  const encoded = Buffer.concat([
    Buffer.from(ethereumKeccak256Hex(Buffer.from(RELEASE_POLICY_TYPE, "utf8")).slice(2), "hex"),
    Buffer.from(uintWord(CHAIN_ID), "hex"),
    Buffer.from(addressWord(authority.distributor_address), "hex"),
    Buffer.from(uintWord(authority.authority_nonce), "hex"),
    Buffer.from(addressWord(authority.settlement_verifier), "hex"),
    Buffer.from(addressWord(authority.qvl_verifier), "hex"),
    Buffer.from(addressWord(authority.anchor_address), "hex"),
    Buffer.from(authority.anchor_writer_release_commitment.slice(2), "hex"),
  ]);
  return ethereumKeccak256Hex(encoded);
}

function actionCalldata(action, authority) {
  if (action === "propose_authority_binding") {
    return calldata("proposeAuthorityBinding(address,address,address,bytes32)", [
      addressWord(authority.settlement_verifier),
      addressWord(authority.qvl_verifier),
      addressWord(authority.anchor_address),
      authority.anchor_writer_release_commitment.slice(2),
    ]);
  }
  if (action === "activate_authority_proposal") {
    return calldata("activateAuthorityProposal()");
  }
  if (action === "unpause") {
    return calldata("setPaused(bool)", [uintWord(0)]);
  }
  fail("unsupported Royalty release action");
}

function normalizeAuthority(value) {
  const parsed = exactRecord(value, [
    "anchor_address",
    "anchor_runtime_code_hash",
    "anchor_writer",
    "anchor_writer_release_commitment",
    "authority_nonce",
    "distributor_address",
    "distributor_runtime_code_hash",
    "owner",
    "qvl_verifier",
    "release_policy_commitment",
    "settlement_verifier",
  ], "Royalty phase authority");
  const normalized = {
    distributor_address: address(parsed.distributor_address, "distributor address"),
    distributor_runtime_code_hash: bytes32(
      parsed.distributor_runtime_code_hash,
      "distributor runtime code hash",
    ),
    owner: address(parsed.owner, "Royalty owner"),
    settlement_verifier: address(parsed.settlement_verifier, "settlement verifier"),
    qvl_verifier: address(parsed.qvl_verifier, "QVL verifier"),
    anchor_address: address(parsed.anchor_address, "execution-policy anchor"),
    anchor_runtime_code_hash: bytes32(
      parsed.anchor_runtime_code_hash,
      "anchor runtime code hash",
    ),
    anchor_writer: address(parsed.anchor_writer, "anchor writer"),
    anchor_writer_release_commitment: bytes32(
      parsed.anchor_writer_release_commitment,
      "anchor writer release commitment",
    ),
    release_policy_commitment: bytes32(
      parsed.release_policy_commitment,
      "release-policy commitment",
    ),
    authority_nonce: decimal(parsed.authority_nonce, "authority nonce"),
  };
  if (normalized.authority_nonce !== "1") {
    fail("the fresh Royalty release authority nonce must equal 1");
  }
  const roles = [
    normalized.distributor_address,
    normalized.owner,
    normalized.settlement_verifier,
    normalized.qvl_verifier,
    normalized.anchor_address,
    normalized.anchor_writer,
  ];
  if (new Set(roles).size !== roles.length) fail("Royalty release roles must be distinct");
  if (normalized.release_policy_commitment !== releasePolicyCommitment(normalized)) {
    fail("Royalty release-policy commitment is invalid");
  }
  return normalized;
}

function normalizePlanTransaction(value, index, action, authority) {
  const parsed = exactRecord(value, [
    "action", "calldata", "calldata_sha256", "nonce", "sequence",
    "signer_address", "to", "value_wei",
  ], `reviewed transaction ${index}`);
  if (parsed.sequence !== index || parsed.action !== action) {
    fail(`reviewed transaction ${index} has invalid order or action`);
  }
  const expectedCalldata = actionCalldata(action, authority);
  const normalizedCalldata = hexBytes(parsed.calldata, `reviewed transaction ${index} calldata`, {
    empty: false,
  });
  if (normalizedCalldata !== expectedCalldata
    || parsed.calldata_sha256 !== rawSha256(Buffer.from(expectedCalldata.slice(2), "hex"))) {
    fail(`reviewed transaction ${index} calldata or digest is invalid`);
  }
  const normalized = {
    sequence: index,
    action,
    signer_address: address(parsed.signer_address, `reviewed transaction ${index} signer`),
    nonce: decimal(parsed.nonce, `reviewed transaction ${index} nonce`),
    to: address(parsed.to, `reviewed transaction ${index} target`),
    value_wei: decimal(parsed.value_wei, `reviewed transaction ${index} value`),
    calldata: expectedCalldata,
    calldata_sha256: parsed.calldata_sha256,
  };
  if (normalized.signer_address !== authority.owner
    || normalized.to !== authority.distributor_address
    || normalized.value_wei !== "0") {
    fail(`reviewed transaction ${index} drifts from the exact owner, target, or zero value`);
  }
  return normalized;
}

function normalizePhaseOnePrerequisite(value, phase) {
  if (phase === 1) {
    if (value !== null) fail("phase 1 cannot carry a phase-one prerequisite");
    return null;
  }
  const parsed = exactRecord(value, [
    "finalized_authority_receipt_sha256", "ledger_revision",
    "ledger_revision_receipt_sha256", "ledger_sha256",
    "pending_authority_activates_at", "phase_one_finalized_at",
    "phase_one_history_record_sha256", "phase_one_plan_sha256",
    "proposal_block_hash", "proposal_block_number", "proposal_tx_hash",
  ], "phase-one prerequisite");
  return {
    phase_one_plan_sha256: sha256(parsed.phase_one_plan_sha256, "phase-one plan digest"),
    phase_one_history_record_sha256: sha256(
      parsed.phase_one_history_record_sha256,
      "phase-one history-record digest",
    ),
    phase_one_finalized_at: exactTimestamp(
      parsed.phase_one_finalized_at,
      "phase-one finalized timestamp",
    ),
    finalized_authority_receipt_sha256: sha256(
      parsed.finalized_authority_receipt_sha256,
      "phase-one finalized-authority digest",
    ),
    ledger_sha256: sha256(parsed.ledger_sha256, "phase-one ledger digest"),
    ledger_revision: safeInteger(parsed.ledger_revision, "phase-one ledger revision", 1),
    ledger_revision_receipt_sha256: sha256(
      parsed.ledger_revision_receipt_sha256,
      "phase-one ledger-revision receipt digest",
    ),
    proposal_tx_hash: bytes32(parsed.proposal_tx_hash, "proposal transaction hash"),
    proposal_block_number: decimal(parsed.proposal_block_number, "proposal block number"),
    proposal_block_hash: bytes32(parsed.proposal_block_hash, "proposal block hash"),
    pending_authority_activates_at: decimal(
      parsed.pending_authority_activates_at,
      "pending activation timestamp",
      (1n << 64n) - 1n,
    ),
  };
}

function normalizeRecovery(value, mode) {
  if (mode !== "recover_reverted_unpause") {
    if (value !== null) fail("non-recovery plan cannot carry recovery evidence");
    return null;
  }
  const parsed = exactRecord(value, [
    "activation_block_hash", "activation_block_number", "activation_tx_hash",
    "finalized_recovery_evidence_sha256", "prior_phase_two_plan_sha256",
    "prior_unpause_nonce", "reverted_unpause_block_hash",
    "reverted_unpause_block_number", "reverted_unpause_tx_hash",
  ], "phase-two recovery prerequisite");
  const normalized = {
    prior_phase_two_plan_sha256: sha256(
      parsed.prior_phase_two_plan_sha256,
      "prior phase-two plan digest",
    ),
    finalized_recovery_evidence_sha256: sha256(
      parsed.finalized_recovery_evidence_sha256,
      "recovery evidence digest",
    ),
    activation_tx_hash: bytes32(parsed.activation_tx_hash, "activation transaction hash"),
    activation_block_number: decimal(parsed.activation_block_number, "activation block number"),
    activation_block_hash: bytes32(parsed.activation_block_hash, "activation block hash"),
    reverted_unpause_tx_hash: bytes32(
      parsed.reverted_unpause_tx_hash,
      "reverted unpause transaction hash",
    ),
    reverted_unpause_block_number: decimal(
      parsed.reverted_unpause_block_number,
      "reverted unpause block number",
    ),
    reverted_unpause_block_hash: bytes32(
      parsed.reverted_unpause_block_hash,
      "reverted unpause block hash",
    ),
    prior_unpause_nonce: decimal(parsed.prior_unpause_nonce, "prior unpause nonce"),
  };
  if (normalized.activation_tx_hash === normalized.reverted_unpause_tx_hash
    || BigInt(normalized.activation_block_number)
      > BigInt(normalized.reverted_unpause_block_number)
    || BigInt(normalized.prior_unpause_nonce) < 1n
    || ((normalized.activation_block_number === normalized.reverted_unpause_block_number)
      !== (normalized.activation_block_hash === normalized.reverted_unpause_block_hash))) {
    fail("recovery activation and reverted-unpause lineage is invalid");
  }
  return normalized;
}

function exactTimestamp(value, label) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    || new Date(Date.parse(value)).toISOString() !== value) {
    fail(`${label} must be canonical millisecond UTC`);
  }
  return value;
}

export function normalizeRoyaltyPhasePlanReceipt(value) {
  const parsed = exactRecord(value, [
    "authority",
    "chain_id",
    "deployment_intent_sha256",
    "execution_mode",
    "expires_at",
    "fresh_contract_deployment_receipt_sha256",
    "phase",
    "phase_one_prerequisite",
    "phase_two_recovery",
    "plan_sha256",
    "release_sha",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "royalty_release_prescriptive_authority_sha256",
    "schema",
    "signing_payload_sha256",
    "status",
    "transactions",
    "truth_status",
    "valid_after",
    "verified_signers",
  ], "verified Royalty phase-plan receipt");
  exactString(parsed.schema, PLAN_RECEIPT_SCHEMA, "phase-plan receipt schema");
  exactString(parsed.status, PLAN_RECEIPT_STATUS, "phase-plan receipt status");
  exactString(parsed.truth_status, PLAN_RECEIPT_TRUTH, "phase-plan receipt truth status");
  if (parsed.chain_id !== CHAIN_ID) fail("phase-plan receipt must target Base Sepolia");
  if (!Number.isSafeInteger(parsed.phase) || ![1, 2].includes(parsed.phase)) {
    fail("phase-plan receipt phase is invalid");
  }
  const actions = PLAN_ACTIONS[`${parsed.phase}:${parsed.execution_mode}`];
  if (!actions) fail("phase-plan receipt execution mode is incompatible with its phase");
  const authority = normalizeAuthority(parsed.authority);
  if (!Array.isArray(parsed.transactions) || parsed.transactions.length !== actions.length) {
    fail("phase-plan receipt transaction count is invalid");
  }
  const transactions = parsed.transactions.map(
    (entry, index) => normalizePlanTransaction(entry, index, actions[index], authority),
  );
  for (let index = 1; index < transactions.length; index += 1) {
    if (BigInt(transactions[index].nonce) !== BigInt(transactions[index - 1].nonce) + 1n) {
      fail("phase-plan transaction nonces are not contiguous");
    }
  }
  const recovery = normalizeRecovery(parsed.phase_two_recovery, parsed.execution_mode);
  if (recovery
    && BigInt(transactions[0].nonce) !== BigInt(recovery.prior_unpause_nonce) + 1n) {
    fail("recovery transaction nonce does not follow the reverted unpause");
  }
  const phaseOnePrerequisite = normalizePhaseOnePrerequisite(
    parsed.phase_one_prerequisite,
    parsed.phase,
  );
  const validAfter = exactTimestamp(parsed.valid_after, "phase-plan valid-after");
  const expiresAt = exactTimestamp(parsed.expires_at, "phase-plan expiry");
  if (Date.parse(expiresAt) <= Date.parse(validAfter)) {
    fail("phase-plan validity window is empty or reversed");
  }
  if (phaseOnePrerequisite
    && (Date.parse(validAfter) / 1_000
      < Number(phaseOnePrerequisite.pending_authority_activates_at)
      || Date.parse(validAfter) < Date.parse(phaseOnePrerequisite.phase_one_finalized_at))) {
    fail("phase 2 valid-after predates the exact timelock or finalized phase-one evidence");
  }
  if (!Array.isArray(parsed.verified_signers) || parsed.verified_signers.length !== 2) {
    fail("phase-plan receipt must contain exactly two verified signers");
  }
  const verifiedSigners = parsed.verified_signers.map((entry, index) => {
    const signer = exactRecord(
      entry,
      ["address", "controller_id", "signature_sha256"],
      `verified signer ${index}`,
    );
    if (typeof signer.controller_id !== "string" || signer.controller_id.length < 1
      || signer.controller_id.length > 128) {
      fail(`verified signer ${index} controller ID is invalid`);
    }
    return {
      controller_id: signer.controller_id,
      address: address(signer.address, `verified signer ${index} address`),
      signature_sha256: sha256(
        signer.signature_sha256,
        `verified signer ${index} signature digest`,
      ),
    };
  });
  if (new Set(verifiedSigners.map((entry) => entry.address)).size !== 2
    || new Set(verifiedSigners.map((entry) => entry.controller_id)).size !== 2) {
    fail("phase-plan verified signers must be distinct controllers and addresses");
  }
  if (typeof parsed.release_sha !== "string" || !SHA40.test(parsed.release_sha)
    || /^0+$/.test(parsed.release_sha)) {
    fail("phase-plan release SHA is invalid");
  }
  if (typeof parsed.reviewer_root_hash !== "string"
    || !/^[0-9a-f]{64}$/.test(parsed.reviewer_root_hash)
    || /^0+$/.test(parsed.reviewer_root_hash)) {
    fail("phase-plan reviewer root hash is invalid");
  }
  return {
    schema: PLAN_RECEIPT_SCHEMA,
    status: PLAN_RECEIPT_STATUS,
    plan_sha256: sha256(parsed.plan_sha256, "phase-plan digest"),
    release_sha: parsed.release_sha,
    chain_id: CHAIN_ID,
    phase: parsed.phase,
    execution_mode: parsed.execution_mode,
    valid_after: validAfter,
    expires_at: expiresAt,
    deployment_intent_sha256: sha256(
      parsed.deployment_intent_sha256,
      "deployment-intent digest",
    ),
    fresh_contract_deployment_receipt_sha256: sha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "fresh contract deployment-receipt digest",
    ),
    royalty_release_prescriptive_authority_sha256: sha256(
      parsed.royalty_release_prescriptive_authority_sha256,
      "Royalty prescriptive-authority digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: sha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "reviewer genesis-acceptance digest",
    ),
    reviewer_authority_current_status_epoch: safeInteger(
      parsed.reviewer_authority_current_status_epoch,
      "reviewer status epoch",
      1,
    ),
    reviewer_authority_current_status_sha256: sha256(
      parsed.reviewer_authority_current_status_sha256,
      "reviewer current-status digest",
    ),
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: sha256(parsed.reviewer_set_sha256, "reviewer-set digest"),
    authority,
    phase_one_prerequisite: phaseOnePrerequisite,
    phase_two_recovery: recovery,
    transactions,
    signing_payload_sha256: sha256(
      parsed.signing_payload_sha256,
      "phase-plan signing-payload digest",
    ),
    verified_signers: verifiedSigners,
    truth_status: PLAN_RECEIPT_TRUTH,
  };
}

function stableReadJson(filePath, label) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be absolute and normalized`);
  }
  let canonical;
  try {
    canonical = fs.realpathSync.native(filePath);
  } catch {
    fail(`${label} path does not exist`);
  }
  if (canonical !== filePath) fail(`${label} path must be canonical and symlink-free`);
  const before = fs.lstatSync(filePath);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1
    || before.uid !== expectedUid || (before.mode & 0o022) !== 0
    || before.size < 2 || before.size > MAX_FILE_BYTES) {
    fail(`${label} must be an operator-owned bounded single-link non-writable regular file`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      fail(`${label} changed while opening`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) fail(`${label} ended during its bounded read`);
      offset += count;
    }
    const afterFd = fs.fstatSync(fd);
    const afterPath = fs.lstatSync(filePath);
    if (afterFd.dev !== opened.dev || afterFd.ino !== opened.ino
      || afterPath.dev !== opened.dev || afterPath.ino !== opened.ino
      || afterFd.size !== opened.size || afterFd.mtimeMs !== opened.mtimeMs
      || afterFd.ctimeMs !== opened.ctimeMs) {
      fail(`${label} changed during its bounded read`);
    }
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch {
      fail(`${label} is not valid JSON`);
    }
  } finally {
    fs.closeSync(fd);
  }
}

function writeExclusiveJson(filePath, value) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath
    || fs.existsSync(filePath)) {
    fail("output path must be absolute, normalized, and absent");
  }
  const parent = path.dirname(filePath);
  if (fs.realpathSync.native(parent) !== parent) fail("output parent must be canonical");
  const stat = fs.lstatSync(parent);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : stat.uid;
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedUid
    || (stat.mode & 0o022) !== 0) {
    fail("output parent must be operator-owned and not group/other writable");
  }
  const fd = fs.openSync(
    filePath,
    fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY,
    0o600,
  );
  try {
    fs.writeFileSync(fd, canonicalText(value), "utf8");
    fs.fchmodSync(fd, 0o600);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  const parentFd = fs.openSync(parent, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(parentFd);
  } finally {
    fs.closeSync(parentFd);
  }
}

export function normalizeRpcEndpoints(primaryValue, secondaryValue) {
  function normalize(value, label) {
    if (typeof value !== "string" || value !== value.trim()
      || Buffer.byteLength(value, "utf8") > MAX_URL_BYTES) {
      fail(`${label} RPC URL is invalid`);
    }
    let url;
    try {
      url = new URL(value);
    } catch {
      fail(`${label} RPC URL is invalid`);
    }
    if (url.protocol !== "https:" || !url.hostname || url.username || url.password
      || url.hash) {
      fail(`${label} RPC must be HTTPS without userinfo or a fragment`);
    }
    return { url: url.href, origin: url.origin.toLowerCase() };
  }
  const primary = normalize(primaryValue, "primary");
  const secondary = normalize(secondaryValue, "secondary");
  if (primary.url === secondary.url || primary.origin === secondary.origin) {
    fail("primary and secondary RPCs must use distinct HTTPS origins");
  }
  return { primary, secondary };
}

async function rpcCall(fetchImpl, endpoint, method, params = []) {
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
  } catch (error) {
    fail(`${endpoint.origin} rejected ${method}: ${error?.message || error}`);
  }
  if (!response?.ok) fail(`${endpoint.origin} returned HTTP failure for ${method}`);
  const length = response.headers?.get?.("content-length");
  if (length !== null && length !== undefined
    && (!/^\d+$/.test(length) || Number(length) > MAX_RPC_RESPONSE_BYTES)) {
    fail(`${endpoint.origin} returned an oversized ${method} response`);
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") < 2
    || Buffer.byteLength(text, "utf8") > MAX_RPC_RESPONSE_BYTES) {
    fail(`${endpoint.origin} returned an empty or oversized ${method} response`);
  }
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    fail(`${endpoint.origin} returned malformed JSON for ${method}`);
  }
  if (!isRecord(payload) || payload.jsonrpc !== "2.0" || payload.id !== id
    || Object.hasOwn(payload, "error") || !Object.hasOwn(payload, "result")) {
    fail(`${endpoint.origin} returned an invalid JSON-RPC envelope for ${method}`);
  }
  return payload.result;
}

function normalizeBlock(value, label) {
  if (!isRecord(value)) fail(`${label} block is missing`);
  return {
    number: quantityToSafeInteger(value.number, `${label} block number`, 1),
    hash: bytes32(String(value.hash || "").toLowerCase(), `${label} block hash`),
    timestamp: quantityToSafeInteger(value.timestamp, `${label} block timestamp`, 1),
  };
}

async function readBlock(fetchImpl, endpoint, tag, label) {
  return normalizeBlock(
    await rpcCall(fetchImpl, endpoint, "eth_getBlockByNumber", [tag, false]),
    label,
  );
}

async function readChainId(fetchImpl, endpoint, label) {
  const value = await rpcCall(fetchImpl, endpoint, "eth_chainId", []);
  const chainId = quantityToSafeInteger(value, `${label} chain ID`);
  if (chainId !== CHAIN_ID) fail(`${label} RPC is not Base Sepolia`);
  return chainId;
}

async function readCode(fetchImpl, endpoint, contractAddress, blockTag, label) {
  const value = await rpcCall(fetchImpl, endpoint, "eth_getCode", [contractAddress, blockTag]);
  const normalized = typeof value === "string" ? value.toLowerCase() : "";
  if (!/^0x(?:[0-9a-f]{2})+$/.test(normalized)) fail(`${label} runtime code is empty or malformed`);
  if (Buffer.byteLength(normalized, "utf8") > MAX_RPC_RESPONSE_BYTES) {
    fail(`${label} runtime code exceeds the bounded probe`);
  }
  return {
    code: normalized,
    codeHash: ethereumKeccak256Hex(Buffer.from(normalized.slice(2), "hex")),
  };
}

async function ethCall(fetchImpl, endpoint, target, data, blockTag, label) {
  return rpcCall(fetchImpl, endpoint, "eth_call", [{ to: target, data }, blockTag])
    .then((value) => `0x${decodeWord(value, label)}`);
}

async function collectProviderState(fetchImpl, endpoint, plan, checkpoint, label) {
  const authority = plan.authority;
  const blockTag = quantityHex(checkpoint.number);
  const distributorCalls = {
    owner: ["owner()", decodeAddress],
    pendingOwner: ["pendingOwner()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    paused: ["paused()", decodeBool],
    settlementVerifier: ["settlementVerifier()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    qvlVerifier: ["qvlVerifier()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    executionPolicyAnchor: ["executionPolicyAnchor()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    anchorWriterReleaseCommitment: ["anchorWriterReleaseCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    releasePolicyCommitment: ["releasePolicyCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    authorityNonce: ["authorityNonce()", decodeUintSafe],
    pendingSettlementVerifier: ["pendingSettlementVerifier()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    pendingQvlVerifier: ["pendingQvlVerifier()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    pendingExecutionPolicyAnchor: ["pendingExecutionPolicyAnchor()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    pendingAnchorWriterReleaseCommitment: ["pendingAnchorWriterReleaseCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    pendingReleasePolicyCommitment: ["pendingReleasePolicyCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    pendingAuthorityNonce: ["pendingAuthorityNonce()", decodeUintSafe],
    pendingAuthorityActivatesAt: ["pendingAuthorityActivatesAt()", decodeUintSafe],
    pendingAuthorityRevocation: ["pendingAuthorityRevocation()", decodeBool],
  };
  const historyCalls = {
    settlementVerifierEverConfigured: [
      "settlementVerifierEverConfigured(address)", authority.settlement_verifier,
    ],
    qvlVerifierEverConfigured: ["qvlVerifierEverConfigured(address)", authority.qvl_verifier],
    anchorWriterEverConfigured: ["anchorWriterEverConfigured(address)", authority.anchor_writer],
  };
  const anchorCalls = {
    owner: ["owner()", decodeAddress],
    pendingOwner: ["pendingOwner()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    deploymentIntentSha256: ["deploymentIntentSha256()", decodeBytes32],
    reviewerAuthorityGenesisAcceptanceSha256: [
      "reviewerAuthorityGenesisAcceptanceSha256()", decodeBytes32,
    ],
    writer: ["writer()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    writerReleaseCommitment: ["writerReleaseCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    pendingWriter: ["pendingWriter()", (value, name) => decodeAddress(value, name, { allowZero: true })],
    pendingWriterReleaseCommitment: ["pendingWriterReleaseCommitment()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
    pendingWriterActivatesAt: ["pendingWriterActivatesAt()", decodeUintSafe],
    writerRotationsFrozen: ["writerRotationsFrozen()", decodeBool],
    paused: ["paused()", decodeBool],
    globalSequence: ["globalSequence()", decodeUintSafe],
    globalHead: ["globalHead()", (value, name) => decodeBytes32(value, name, { allowZero: true })],
  };
  const [distributorCode, anchorCode, signerNonce, distributorEntries, historyEntries,
    anchorEntries] = await Promise.all([
    readCode(fetchImpl, endpoint, authority.distributor_address, blockTag, `${label} distributor`),
    readCode(fetchImpl, endpoint, authority.anchor_address, blockTag, `${label} anchor`),
    rpcCall(fetchImpl, endpoint, "eth_getTransactionCount", [authority.owner, blockTag])
      .then((value) => quantityToDecimal(value, `${label} finalized signer nonce`)),
    Promise.all(Object.entries(distributorCalls).map(async ([key, [signature, decoder]]) => {
      const result = await ethCall(
        fetchImpl,
        endpoint,
        authority.distributor_address,
        calldata(signature),
        blockTag,
        `${label} distributor ${key}`,
      );
      return [key, decoder(result, `${label} distributor ${key}`)];
    })),
    Promise.all(Object.entries(historyCalls).map(async ([key, [signature, role]]) => {
      const result = await ethCall(
        fetchImpl,
        endpoint,
        authority.distributor_address,
        calldata(signature, [addressWord(role)]),
        blockTag,
        `${label} distributor ${key}`,
      );
      return [key, decodeBool(result, `${label} distributor ${key}`)];
    })),
    Promise.all(Object.entries(anchorCalls).map(async ([key, [signature, decoder]]) => {
      const result = await ethCall(
        fetchImpl,
        endpoint,
        authority.anchor_address,
        calldata(signature),
        blockTag,
        `${label} anchor ${key}`,
      );
      return [key, decoder(result, `${label} anchor ${key}`)];
    })),
  ]);
  if (distributorCode.codeHash !== authority.distributor_runtime_code_hash
    || anchorCode.codeHash !== authority.anchor_runtime_code_hash) {
    fail(`${label} runtime code differs from the reviewed Royalty authority`);
  }
  const distributor = Object.fromEntries([...distributorEntries, ...historyEntries]);
  const anchor = Object.fromEntries(anchorEntries);
  return {
    signerNonce,
    authorityState: {
      executionPolicyAnchor: {
        address: authority.anchor_address,
        runtimeCodeHash: anchorCode.codeHash,
        ...anchor,
      },
      royaltyDistributor: {
        address: authority.distributor_address,
        runtimeCodeHash: distributorCode.codeHash,
        ...distributor,
      },
    },
  };
}

function exactAnchorState(state, plan) {
  const authority = plan.authority;
  return state.address === authority.anchor_address
    && state.runtimeCodeHash === authority.anchor_runtime_code_hash
    && state.owner === authority.owner
    && state.pendingOwner === ZERO_ADDRESS
    && state.deploymentIntentSha256
      === `0x${plan.deployment_intent_sha256.slice("sha256:".length)}`
    && state.reviewerAuthorityGenesisAcceptanceSha256
      === `0x${plan.reviewer_authority_genesis_acceptance_sha256.slice("sha256:".length)}`
    && state.writer === authority.anchor_writer
    && state.writerReleaseCommitment === authority.anchor_writer_release_commitment
    && state.pendingWriter === ZERO_ADDRESS
    && state.pendingWriterReleaseCommitment === ZERO_BYTES32
    && state.pendingWriterActivatesAt === 0
    && state.writerRotationsFrozen === true
    && state.paused === false
    && Number.isSafeInteger(state.globalSequence)
    && BYTES32.test(state.globalHead);
}

export function classifyRoyaltyAuthorityState(authorityState, planReceipt) {
  const plan = normalizeRoyaltyPhasePlanReceipt(planReceipt);
  if (!isRecord(authorityState)
    || !isRecord(authorityState.executionPolicyAnchor)
    || !isRecord(authorityState.royaltyDistributor)) {
    fail("Royalty authority state is malformed");
  }
  if (!exactAnchorState(authorityState.executionPolicyAnchor, plan)) return "diverged";
  const authority = plan.authority;
  const state = authorityState.royaltyDistributor;
  const common = state.address === authority.distributor_address
    && state.runtimeCodeHash === authority.distributor_runtime_code_hash
    && state.owner === authority.owner
    && state.pendingOwner === ZERO_ADDRESS
    && state.pendingAuthorityRevocation === false;
  if (!common) return "diverged";
  const activeEmpty = state.settlementVerifier === ZERO_ADDRESS
    && state.qvlVerifier === ZERO_ADDRESS
    && state.executionPolicyAnchor === ZERO_ADDRESS
    && state.anchorWriterReleaseCommitment === ZERO_BYTES32
    && state.releasePolicyCommitment === ZERO_BYTES32
    && state.authorityNonce === 0;
  const pendingEmpty = state.pendingSettlementVerifier === ZERO_ADDRESS
    && state.pendingQvlVerifier === ZERO_ADDRESS
    && state.pendingExecutionPolicyAnchor === ZERO_ADDRESS
    && state.pendingAnchorWriterReleaseCommitment === ZERO_BYTES32
    && state.pendingReleasePolicyCommitment === ZERO_BYTES32
    && state.pendingAuthorityNonce === 0
    && state.pendingAuthorityActivatesAt === 0;
  const activeExact = state.settlementVerifier === authority.settlement_verifier
    && state.qvlVerifier === authority.qvl_verifier
    && state.executionPolicyAnchor === authority.anchor_address
    && state.anchorWriterReleaseCommitment === authority.anchor_writer_release_commitment
    && state.releasePolicyCommitment === authority.release_policy_commitment
    && state.authorityNonce === Number(authority.authority_nonce);
  const pendingExact = state.pendingSettlementVerifier === authority.settlement_verifier
    && state.pendingQvlVerifier === authority.qvl_verifier
    && state.pendingExecutionPolicyAnchor === authority.anchor_address
    && state.pendingAnchorWriterReleaseCommitment === authority.anchor_writer_release_commitment
    && state.pendingReleasePolicyCommitment === authority.release_policy_commitment
    && state.pendingAuthorityNonce === Number(authority.authority_nonce)
    && Number.isSafeInteger(state.pendingAuthorityActivatesAt)
    && state.pendingAuthorityActivatesAt > 0
    && (plan.phase !== 2
      || state.pendingAuthorityActivatesAt
        === Number(plan.phase_one_prerequisite.pending_authority_activates_at));
  const historyEmpty = state.settlementVerifierEverConfigured === false
    && state.qvlVerifierEverConfigured === false
    && state.anchorWriterEverConfigured === false;
  const historyExact = state.settlementVerifierEverConfigured === true
    && state.qvlVerifierEverConfigured === true
    && state.anchorWriterEverConfigured === true;
  let classification = "diverged";
  if (state.paused === true && activeEmpty && pendingEmpty && historyEmpty) {
    classification = "fresh_empty";
  } else if (state.paused === true && activeEmpty && pendingExact && historyEmpty) {
    classification = "phase1_exact_pending";
  } else if (activeExact && pendingEmpty && historyExact) {
    classification = state.paused === true
      ? "phase2_exact_active_paused"
      : state.paused === false ? "phase2_exact_active_unpaused" : "diverged";
  }
  if (!CLASSIFICATIONS.has(classification)) fail("internal classification failure");
  return classification;
}

async function commonFinalizedObservation({ plan, endpoints, fetchImpl }) {
  const [primaryChain, secondaryChain, primaryFinalized, secondaryFinalized] =
    await Promise.all([
      readChainId(fetchImpl, endpoints.primary, "primary"),
      readChainId(fetchImpl, endpoints.secondary, "secondary"),
      readBlock(fetchImpl, endpoints.primary, "finalized", "primary finalized"),
      readBlock(fetchImpl, endpoints.secondary, "finalized", "secondary finalized"),
    ]);
  if (primaryChain !== CHAIN_ID || secondaryChain !== CHAIN_ID
    || !canonicalEqual(primaryFinalized, secondaryFinalized)) {
    fail("independent Base Sepolia RPCs do not agree on one finalized checkpoint");
  }
  const checkpoint = primaryFinalized;
  const [primaryState, secondaryState] = await Promise.all([
    collectProviderState(fetchImpl, endpoints.primary, plan, checkpoint, "primary"),
    collectProviderState(fetchImpl, endpoints.secondary, plan, checkpoint, "secondary"),
  ]);
  if (!canonicalEqual(primaryState, secondaryState)) {
    fail("independent Base Sepolia RPCs disagree on finalized Royalty state or signer nonce");
  }
  await recheckCheckpoint(fetchImpl, endpoints, checkpoint);
  const classification = classifyRoyaltyAuthorityState(primaryState.authorityState, plan);
  return {
    checkpoint,
    classification,
    signerNonce: primaryState.signerNonce,
    authorityState: primaryState.authorityState,
  };
}

async function recheckCheckpoint(fetchImpl, endpoints, checkpoint) {
  const tag = quantityHex(checkpoint.number);
  const [primary, secondary] = await Promise.all([
    readBlock(fetchImpl, endpoints.primary, tag, "primary finalized numeric recheck"),
    readBlock(fetchImpl, endpoints.secondary, tag, "secondary finalized numeric recheck"),
  ]);
  if (!canonicalEqual(primary, checkpoint) || !canonicalEqual(secondary, checkpoint)) {
    fail("common finalized numeric checkpoint changed during the proof");
  }
}

function normalizeForgeTransaction(value, index, reviewed) {
  if (!isRecord(value) || value.transactionType !== "CALL" || !isRecord(value.transaction)) {
    fail(`Forge transaction ${index} is not a CALL`);
  }
  const transaction = value.transaction;
  const hash = bytes32(String(value.hash || "").toLowerCase(), `Forge transaction ${index} hash`);
  const from = address(String(transaction.from || "").toLowerCase(), `Forge transaction ${index} sender`);
  const to = address(String(transaction.to || "").toLowerCase(), `Forge transaction ${index} target`);
  const input = hexBytes(
    String(transaction.input || "").toLowerCase(),
    `Forge transaction ${index} input`,
    { empty: false },
  );
  const nonce = typeof transaction.nonce === "number"
    ? safeInteger(transaction.nonce, `Forge transaction ${index} nonce`).toString(10)
    : quantityToDecimal(String(transaction.nonce || "").toLowerCase(), `Forge transaction ${index} nonce`);
  const valueWei = typeof transaction.value === "number"
    ? safeInteger(transaction.value, `Forge transaction ${index} value`).toString(10)
    : quantityToDecimal(String(transaction.value ?? "0x0").toLowerCase(), `Forge transaction ${index} value`);
  const chainId = transaction.chainId === CHAIN_ID
    ? CHAIN_ID
    : quantityToSafeInteger(String(transaction.chainId || "").toLowerCase(), `Forge transaction ${index} chain ID`);
  if (chainId !== CHAIN_ID || from !== reviewed.signer_address || to !== reviewed.to
    || nonce !== reviewed.nonce || valueWei !== reviewed.value_wei
    || input !== reviewed.calldata) {
    fail(`Forge transaction ${index} differs from the reviewed Base Sepolia transaction`);
  }
  return { hash, from, to, nonce, valueWei, input };
}

export function normalizeForgeBroadcastArtifact(value, reviewedTransactions) {
  if (!isRecord(value) || !Array.isArray(value.transactions)
    || value.transactions.length !== reviewedTransactions.length) {
    fail("Forge broadcast artifact has an unexpected transaction set");
  }
  const normalized = value.transactions.map(
    (entry, index) => normalizeForgeTransaction(entry, index, reviewedTransactions[index]),
  );
  if (new Set(normalized.map((entry) => entry.hash)).size !== normalized.length) {
    fail("Forge broadcast artifact repeats a transaction hash");
  }
  return normalized;
}

export function verifyForgeDryRunArtifact(value, reviewedTransactions) {
  if (!isRecord(value) || !Array.isArray(value.transactions)
    || value.transactions.length !== reviewedTransactions.length) {
    fail("Forge dry-run artifact has an unexpected transaction set");
  }
  const transactions = value.transactions.map((entry, index) => {
    if (!isRecord(entry) || entry.transactionType !== "CALL" || !isRecord(entry.transaction)) {
      fail(`Forge dry-run transaction ${index} is not a CALL`);
    }
    const reviewed = reviewedTransactions[index];
    const transaction = entry.transaction;
    const from = address(
      String(transaction.from || "").toLowerCase(),
      `Forge dry-run transaction ${index} sender`,
    );
    const to = address(
      String(transaction.to || "").toLowerCase(),
      `Forge dry-run transaction ${index} target`,
    );
    const input = hexBytes(
      String(transaction.input || "").toLowerCase(),
      `Forge dry-run transaction ${index} input`,
      { empty: false },
    );
    const nonce = typeof transaction.nonce === "number"
      ? safeInteger(transaction.nonce, `Forge dry-run transaction ${index} nonce`).toString(10)
      : quantityToDecimal(
        String(transaction.nonce || "").toLowerCase(),
        `Forge dry-run transaction ${index} nonce`,
      );
    const valueWei = typeof transaction.value === "number"
      ? safeInteger(transaction.value, `Forge dry-run transaction ${index} value`).toString(10)
      : quantityToDecimal(
        String(transaction.value ?? "0x0").toLowerCase(),
        `Forge dry-run transaction ${index} value`,
      );
    const chainId = transaction.chainId === CHAIN_ID
      ? CHAIN_ID
      : quantityToSafeInteger(
        String(transaction.chainId || "").toLowerCase(),
        `Forge dry-run transaction ${index} chain ID`,
      );
    if (from !== reviewed.signer_address || to !== reviewed.to
      || nonce !== reviewed.nonce || valueWei !== reviewed.value_wei
      || input !== reviewed.calldata || chainId !== CHAIN_ID) {
      fail(`Forge dry-run transaction ${index} differs from the classified reviewed transaction`);
    }
    return {
      sequence: reviewed.sequence,
      action: reviewed.action,
      signer_address: from,
      nonce,
      to,
      value_wei: valueWei,
      calldata: input,
      calldata_sha256: reviewed.calldata_sha256,
    };
  });
  for (let index = 1; index < transactions.length; index += 1) {
    if (BigInt(transactions[index].nonce) !== BigInt(transactions[index - 1].nonce) + 1n
      || transactions[index].sequence !== transactions[index - 1].sequence + 1) {
      fail("Forge dry-run transactions are not in reviewed nonce and sequence order");
    }
  }
  return transactions;
}

function normalizeRpcTransaction(value, label) {
  if (!isRecord(value)) fail(`${label} transaction is missing`);
  const blockNumber = quantityToSafeInteger(value.blockNumber, `${label} transaction block`, 1);
  return {
    hash: bytes32(String(value.hash || "").toLowerCase(), `${label} transaction hash`),
    from: address(String(value.from || "").toLowerCase(), `${label} transaction sender`),
    to: address(String(value.to || "").toLowerCase(), `${label} transaction target`),
    nonce: quantityToDecimal(value.nonce, `${label} transaction nonce`),
    valueWei: quantityToDecimal(value.value, `${label} transaction value`),
    input: hexBytes(String(value.input || "").toLowerCase(), `${label} transaction input`, {
      empty: false,
    }),
    blockNumber,
    blockHash: bytes32(String(value.blockHash || "").toLowerCase(), `${label} transaction block hash`),
    transactionIndex: quantityToSafeInteger(
      value.transactionIndex,
      `${label} transaction index`,
    ),
    chainId: value.chainId === undefined
      ? CHAIN_ID
      : quantityToSafeInteger(value.chainId, `${label} transaction chain ID`),
  };
}

function normalizeRpcReceipt(value, label) {
  if (!isRecord(value)) fail(`${label} receipt is missing`);
  const statusValue = quantityToBigInt(value.status, `${label} receipt status`);
  if (statusValue !== 0n && statusValue !== 1n) fail(`${label} receipt status is invalid`);
  return {
    transactionHash: bytes32(
      String(value.transactionHash || "").toLowerCase(),
      `${label} receipt transaction hash`,
    ),
    from: address(String(value.from || "").toLowerCase(), `${label} receipt sender`),
    to: address(String(value.to || "").toLowerCase(), `${label} receipt target`),
    status: statusValue === 1n ? "success" : "reverted",
    blockNumber: quantityToSafeInteger(value.blockNumber, `${label} receipt block`, 1),
    blockHash: bytes32(String(value.blockHash || "").toLowerCase(), `${label} receipt block hash`),
    transactionIndex: quantityToSafeInteger(
      value.transactionIndex,
      `${label} receipt transaction index`,
    ),
  };
}

function normalizeRecordedTransactionReceipt(value, reviewed, expectedStatus, label) {
  const parsed = exactRecord(value, [
    "action",
    "blockHash",
    "blockNumber",
    "blockTimestamp",
    "calldata",
    "calldataSha256",
    "nonce",
    "sender",
    "sequence",
    "status",
    "target",
    "transactionHash",
    "transactionIndex",
    "valueWei",
  ], label);
  const normalized = {
    sequence: safeInteger(parsed.sequence, `${label} sequence`),
    action: parsed.action,
    sender: address(parsed.sender, `${label} sender`),
    target: address(parsed.target, `${label} target`),
    nonce: decimal(parsed.nonce, `${label} nonce`),
    valueWei: decimal(parsed.valueWei, `${label} value`),
    calldata: hexBytes(parsed.calldata, `${label} calldata`, { empty: false }),
    calldataSha256: sha256(parsed.calldataSha256, `${label} calldata digest`),
    transactionHash: bytes32(parsed.transactionHash, `${label} transaction hash`),
    status: parsed.status,
    blockNumber: safeInteger(parsed.blockNumber, `${label} block number`, 1),
    blockHash: bytes32(parsed.blockHash, `${label} block hash`),
    blockTimestamp: safeInteger(parsed.blockTimestamp, `${label} block timestamp`, 1),
    transactionIndex: safeInteger(parsed.transactionIndex, `${label} transaction index`),
  };
  if (normalized.sequence !== reviewed.sequence
    || normalized.action !== reviewed.action
    || normalized.sender !== reviewed.signer_address
    || normalized.target !== reviewed.to
    || normalized.nonce !== reviewed.nonce
    || normalized.valueWei !== reviewed.value_wei
    || normalized.calldata !== reviewed.calldata
    || normalized.calldataSha256 !== reviewed.calldata_sha256
    || normalized.status !== expectedStatus) {
    fail(`${label} differs from the reviewed transaction or expected status`);
  }
  return normalized;
}

async function authenticateOneTransaction({
  fetchImpl,
  endpoints,
  checkpoint,
  reviewed,
  hash,
  expectedStatus,
}) {
  async function readProvider(endpoint, label) {
    const [transactionValue, receiptValue] = await Promise.all([
      rpcCall(fetchImpl, endpoint, "eth_getTransactionByHash", [hash]),
      rpcCall(fetchImpl, endpoint, "eth_getTransactionReceipt", [hash]),
    ]);
    const transaction = normalizeRpcTransaction(transactionValue, label);
    const receipt = normalizeRpcReceipt(receiptValue, label);
    if (transaction.hash !== hash || receipt.transactionHash !== hash
      || transaction.from !== reviewed.signer_address
      || transaction.to !== reviewed.to
      || transaction.nonce !== reviewed.nonce
      || transaction.valueWei !== reviewed.value_wei
      || transaction.input !== reviewed.calldata
      || transaction.chainId !== CHAIN_ID
      || receipt.from !== transaction.from || receipt.to !== transaction.to
      || receipt.status !== expectedStatus
      || receipt.blockNumber !== transaction.blockNumber
      || receipt.blockHash !== transaction.blockHash
      || receipt.transactionIndex !== transaction.transactionIndex
      || receipt.blockNumber > checkpoint.number) {
      fail(`${label} transaction or receipt differs from the reviewed finalized mutation`);
    }
    const block = await readBlock(
      fetchImpl,
      endpoint,
      quantityHex(receipt.blockNumber),
      `${label} receipt block`,
    );
    if (block.hash !== receipt.blockHash || block.number !== receipt.blockNumber
      || block.timestamp > checkpoint.timestamp) {
      fail(`${label} transaction receipt block is not canonical under the finalized checkpoint`);
    }
    return { transaction, receipt, block };
  }
  const [primary, secondary] = await Promise.all([
    readProvider(endpoints.primary, "primary"),
    readProvider(endpoints.secondary, "secondary"),
  ]);
  if (!canonicalEqual(primary, secondary)) {
    fail("independent Base Sepolia RPCs disagree on a reviewed transaction");
  }
  return {
    sequence: reviewed.sequence,
    action: reviewed.action,
    sender: reviewed.signer_address,
    target: reviewed.to,
    nonce: reviewed.nonce,
    valueWei: reviewed.value_wei,
    calldata: reviewed.calldata,
    calldataSha256: reviewed.calldata_sha256,
    transactionHash: hash,
    status: expectedStatus,
    blockNumber: primary.receipt.blockNumber,
    blockHash: primary.receipt.blockHash,
    blockTimestamp: primary.block.timestamp,
    transactionIndex: primary.receipt.transactionIndex,
  };
}

function transactionBefore(left, right) {
  return left.blockNumber < right.blockNumber
    || (left.blockNumber === right.blockNumber
      && left.transactionIndex < right.transactionIndex);
}

async function authenticateArtifactTransactions({
  artifact,
  plan,
  reviewedTransactions,
  fetchImpl,
  endpoints,
  checkpoint,
}) {
  const forgeTransactions = normalizeForgeBroadcastArtifact(artifact, reviewedTransactions);
  const receipts = [];
  for (let index = 0; index < reviewedTransactions.length; index += 1) {
    receipts.push(await authenticateOneTransaction({
      fetchImpl,
      endpoints,
      checkpoint,
      reviewed: reviewedTransactions[index],
      hash: forgeTransactions[index].hash,
      expectedStatus: "success",
    }));
  }
  for (let index = 1; index < receipts.length; index += 1) {
    if (!transactionBefore(receipts[index - 1], receipts[index])) {
      fail("reviewed transactions did not finalize in their reviewed order");
    }
  }
  const validAfter = Math.floor(Date.parse(plan.valid_after) / 1_000);
  const expiresAt = Math.floor(Date.parse(plan.expires_at) / 1_000);
  if (receipts.some((entry) => entry.blockTimestamp < validAfter
    || entry.blockTimestamp > expiresAt)) {
    fail("reviewed transaction finalized outside its signed validity window");
  }
  return receipts;
}

export function royaltyUnpauseRecoveryEvidenceSha256(value) {
  const core = {
    schema: value.schema,
    priorPhaseTwoPlanSha256: value.priorPhaseTwoPlanSha256,
    activationReceipt: value.activationReceipt,
    revertedUnpauseReceipt: value.revertedUnpauseReceipt,
  };
  return domainSha256(
    "dnai-wikigen/base-sepolia-royalty-unpause-recovery-evidence/v1\0",
    core,
  );
}

async function authenticateRecoveryEvidence({ plan, fetchImpl, endpoints, checkpoint }) {
  const recovery = plan.phase_two_recovery;
  if (!recovery) return null;
  const activationReviewed = {
    sequence: 0,
    action: "activate_authority_proposal",
    signer_address: plan.authority.owner,
    nonce: (BigInt(recovery.prior_unpause_nonce) - 1n).toString(10),
    to: plan.authority.distributor_address,
    value_wei: "0",
    calldata: actionCalldata("activate_authority_proposal", plan.authority),
  };
  activationReviewed.calldata_sha256 = rawSha256(
    Buffer.from(activationReviewed.calldata.slice(2), "hex"),
  );
  const revertedReviewed = {
    sequence: 1,
    action: "unpause",
    signer_address: plan.authority.owner,
    nonce: recovery.prior_unpause_nonce,
    to: plan.authority.distributor_address,
    value_wei: "0",
    calldata: actionCalldata("unpause", plan.authority),
  };
  revertedReviewed.calldata_sha256 = rawSha256(
    Buffer.from(revertedReviewed.calldata.slice(2), "hex"),
  );
  const activationReceipt = await authenticateOneTransaction({
    fetchImpl,
    endpoints,
    checkpoint,
    reviewed: activationReviewed,
    hash: recovery.activation_tx_hash,
    expectedStatus: "success",
  });
  const revertedUnpauseReceipt = await authenticateOneTransaction({
    fetchImpl,
    endpoints,
    checkpoint,
    reviewed: revertedReviewed,
    hash: recovery.reverted_unpause_tx_hash,
    expectedStatus: "reverted",
  });
  if (String(activationReceipt.blockNumber) !== recovery.activation_block_number
    || activationReceipt.blockHash !== recovery.activation_block_hash
    || String(revertedUnpauseReceipt.blockNumber) !== recovery.reverted_unpause_block_number
    || revertedUnpauseReceipt.blockHash !== recovery.reverted_unpause_block_hash
    || !transactionBefore(activationReceipt, revertedUnpauseReceipt)) {
    fail("recovery transactions differ from the reviewed recovery lineage");
  }
  const evidence = {
    schema: ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
    evidenceSha256: recovery.finalized_recovery_evidence_sha256,
    priorPhaseTwoPlanSha256: recovery.prior_phase_two_plan_sha256,
    activationReceipt,
    revertedUnpauseReceipt,
  };
  if (royaltyUnpauseRecoveryEvidenceSha256(evidence) !== evidence.evidenceSha256) {
    fail("reviewed recovery evidence digest does not match finalized chain evidence");
  }
  return evidence;
}

function expectedPreClassification(plan) {
  if (plan.phase === 1) return "fresh_empty";
  if (plan.execution_mode === "recover_reverted_unpause") {
    return "phase2_exact_active_paused";
  }
  return "phase1_exact_pending";
}

function expectedTerminalClassification(plan) {
  return plan.phase === 1 ? "phase1_exact_pending" : "phase2_exact_active_unpaused";
}

async function assertSignerNonceAvailable({
  plan,
  observation,
  endpoints,
  fetchImpl,
  expectedNonce,
}) {
  const normalizedExpected = decimal(expectedNonce, "first remaining reviewed nonce");
  const reads = [];
  for (const [label, endpoint] of [["primary", endpoints.primary], ["secondary", endpoints.secondary]]) {
    for (const tag of ["latest", "pending"]) {
      reads.push(rpcCall(fetchImpl, endpoint, "eth_getTransactionCount", [plan.authority.owner, tag])
        .then((value) => ({
          label,
          tag,
          nonce: quantityToDecimal(value, `${label} ${tag} signer nonce`),
        })));
    }
  }
  const results = await Promise.all(reads);
  if (observation.signerNonce !== normalizedExpected
    || results.some((entry) => entry.nonce !== normalizedExpected)) {
    fail("first remaining reviewed nonce is already mined, pending, replaced, or otherwise unavailable");
  }
}

function classifyProviderConfirmations({ endpoints, observation, authorityStateSha256 }) {
  return [
    {
      label: "primary",
      rpcOrigin: endpoints.primary.origin,
      chainId: CHAIN_ID,
      finalizedBlockNumber: observation.checkpoint.number,
      finalizedBlockHash: observation.checkpoint.hash,
      finalizedBlockTimestamp: observation.checkpoint.timestamp,
      authorityStateSha256,
      signerNonce: observation.signerNonce,
    },
    {
      label: "secondary",
      rpcOrigin: endpoints.secondary.origin,
      chainId: CHAIN_ID,
      finalizedBlockNumber: observation.checkpoint.number,
      finalizedBlockHash: observation.checkpoint.hash,
      finalizedBlockTimestamp: observation.checkpoint.timestamp,
      authorityStateSha256,
      signerNonce: observation.signerNonce,
    },
  ];
}

export async function classifyRoyaltyRelease({
  planReceipt,
  primaryRpc,
  secondaryRpc,
  broadcastArtifact,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof fetchImpl !== "function") fail("fetch implementation is unavailable");
  const plan = normalizeRoyaltyPhasePlanReceipt(planReceipt);
  const endpoints = normalizeRpcEndpoints(primaryRpc, secondaryRpc);
  const observation = await commonFinalizedObservation({ plan, endpoints, fetchImpl });
  const expectedPre = expectedPreClassification(plan);
  const expectedTerminal = expectedTerminalClassification(plan);
  let executionScope;
  let remainingTransactions;
  let reviewedActivationReceipt = null;
  if (observation.classification === expectedPre) {
    await assertSignerNonceAvailable({
      plan,
      observation,
      endpoints,
      fetchImpl,
      expectedNonce: plan.transactions[0].nonce,
    });
    executionScope = "full_plan";
    remainingTransactions = plan.transactions;
    if (broadcastArtifact !== undefined) {
      fail("a broadcast artifact is only accepted for the reviewed-unpause suffix");
    }
    if (plan.execution_mode === "recover_reverted_unpause") {
      await authenticateRecoveryEvidence({ plan, fetchImpl, endpoints, checkpoint: observation.checkpoint });
    }
  } else if (plan.execution_mode === "activate_and_unpause"
    && observation.classification === "phase2_exact_active_paused") {
    if (broadcastArtifact === undefined) {
      fail("active-paused phase 2 requires the prior activation Forge artifact");
    }
    [reviewedActivationReceipt] = await authenticateArtifactTransactions({
      artifact: broadcastArtifact,
      plan,
      reviewedTransactions: [plan.transactions[0]],
      fetchImpl,
      endpoints,
      checkpoint: observation.checkpoint,
    });
    await assertSignerNonceAvailable({
      plan,
      observation,
      endpoints,
      fetchImpl,
      expectedNonce: plan.transactions[1].nonce,
    });
    await recheckCheckpoint(fetchImpl, endpoints, observation.checkpoint);
    executionScope = "reviewed_unpause_suffix";
    remainingTransactions = [plan.transactions[1]];
  } else if (observation.classification === expectedTerminal
    && observation.signerNonce
      === (BigInt(plan.transactions.at(-1).nonce) + 1n).toString(10)) {
    if (broadcastArtifact !== undefined) {
      fail("already-complete classification does not accept a broadcast artifact");
    }
    executionScope = "already_complete";
    remainingTransactions = [];
  } else {
    executionScope = "none";
    remainingTransactions = [];
  }
  const authorityStateSha256 = domainSha256(
    "dnai-wikigen/base-sepolia-royalty-authority-state/v1\0",
    observation.authorityState,
  );
  return {
    schema: ROYALTY_STATE_CLASSIFICATION_SCHEMA,
    status: "valid_dual_rpc_common_finalized_state",
    planSha256: plan.plan_sha256,
    classification: observation.classification,
    executionScope,
    remainingTransactions,
    reviewedActivationReceipt,
    chainId: CHAIN_ID,
    finalizedBlockNumber: observation.checkpoint.number,
    finalizedBlockHash: observation.checkpoint.hash,
    finalizedBlockTimestamp: observation.checkpoint.timestamp,
    signerNonce: observation.signerNonce,
    authorityState: observation.authorityState,
    providerConfirmations: classifyProviderConfirmations({
      endpoints,
      observation,
      authorityStateSha256,
    }),
  };
}

function normalizeClassificationForDryRun(value, plan) {
  const parsed = exactRecord(value, [
    "authorityState",
    "chainId",
    "classification",
    "executionScope",
    "finalizedBlockHash",
    "finalizedBlockNumber",
    "finalizedBlockTimestamp",
    "planSha256",
    "providerConfirmations",
    "remainingTransactions",
    "reviewedActivationReceipt",
    "schema",
    "signerNonce",
    "status",
  ], "Royalty state classification");
  exactString(parsed.schema, ROYALTY_STATE_CLASSIFICATION_SCHEMA, "classification schema");
  exactString(
    parsed.status,
    "valid_dual_rpc_common_finalized_state",
    "classification status",
  );
  if (parsed.planSha256 !== plan.plan_sha256 || parsed.chainId !== CHAIN_ID
    || !CLASSIFICATIONS.has(parsed.classification)
    || !["full_plan", "reviewed_unpause_suffix", "already_complete", "none"]
      .includes(parsed.executionScope)) {
    fail("classification is not bound to the reviewed Base Sepolia plan");
  }
  safeInteger(parsed.finalizedBlockNumber, "classification finalized block", 1);
  bytes32(parsed.finalizedBlockHash, "classification finalized block hash");
  safeInteger(parsed.finalizedBlockTimestamp, "classification finalized timestamp", 1);
  decimal(parsed.signerNonce, "classification signer nonce");
  if (!Array.isArray(parsed.providerConfirmations)
    || parsed.providerConfirmations.length !== 2) {
    fail("classification lacks two distinct provider confirmations");
  }
  const derivedClassification = classifyRoyaltyAuthorityState(parsed.authorityState, plan);
  if (parsed.classification !== derivedClassification) {
    fail("stored classification differs from its exact authority state");
  }
  const authorityStateSha256 = domainSha256(
    "dnai-wikigen/base-sepolia-royalty-authority-state/v1\0",
    parsed.authorityState,
  );
  for (const [index, label] of ["primary", "secondary"].entries()) {
    const confirmation = exactRecord(parsed.providerConfirmations[index], [
      "authorityStateSha256",
      "chainId",
      "finalizedBlockHash",
      "finalizedBlockNumber",
      "finalizedBlockTimestamp",
      "label",
      "rpcOrigin",
      "signerNonce",
    ], `${label} classification confirmation`);
    if (confirmation.label !== label || confirmation.chainId !== CHAIN_ID
      || confirmation.finalizedBlockNumber !== parsed.finalizedBlockNumber
      || confirmation.finalizedBlockHash !== parsed.finalizedBlockHash
      || confirmation.finalizedBlockTimestamp !== parsed.finalizedBlockTimestamp
      || confirmation.authorityStateSha256 !== authorityStateSha256
      || confirmation.signerNonce !== parsed.signerNonce) {
      fail(`${label} classification confirmation differs from the common observation`);
    }
  }
  normalizeRpcEndpoints(
    parsed.providerConfirmations[0].rpcOrigin,
    parsed.providerConfirmations[1].rpcOrigin,
  );
  const expectedPre = expectedPreClassification(plan);
  const expectedTerminal = expectedTerminalClassification(plan);
  let derivedScope;
  let expectedRemaining;
  if (parsed.classification === expectedPre
    && parsed.signerNonce === plan.transactions[0].nonce) {
    derivedScope = "full_plan";
    expectedRemaining = plan.transactions;
    if (parsed.reviewedActivationReceipt !== null) {
      fail("full-plan classification cannot carry a prior activation receipt");
    }
  } else if (plan.execution_mode === "activate_and_unpause"
    && parsed.classification === "phase2_exact_active_paused") {
    if (plan.execution_mode !== "activate_and_unpause"
      || parsed.reviewedActivationReceipt === null
      || parsed.signerNonce !== plan.transactions[1].nonce) {
      fail("classification cannot authorize the reviewed-unpause suffix");
    }
    normalizeRecordedTransactionReceipt(
      parsed.reviewedActivationReceipt,
      plan.transactions[0],
      "success",
      "reviewed activation receipt",
    );
    derivedScope = "reviewed_unpause_suffix";
    expectedRemaining = [plan.transactions[1]];
  } else if (parsed.classification === expectedTerminal
    && parsed.signerNonce
      === (BigInt(plan.transactions.at(-1).nonce) + 1n).toString(10)) {
    if (parsed.reviewedActivationReceipt !== null) {
      fail("already-complete classification cannot carry a prior activation receipt");
    }
    derivedScope = "already_complete";
    expectedRemaining = [];
  } else {
    derivedScope = "none";
    expectedRemaining = [];
  }
  if (parsed.executionScope !== derivedScope) {
    fail("stored execution scope differs from the re-derived safe scope");
  }
  if (derivedScope === "none") {
    fail("diverged or non-executable classification cannot authorize a dry run");
  }
  if (!canonicalEqual(parsed.remainingTransactions, expectedRemaining)) {
    fail("classification remaining transactions differ from the reviewed plan");
  }
  return {
    executionScope: parsed.executionScope,
    classification: parsed.classification,
    remainingTransactions: expectedRemaining,
  };
}

export function verifyRoyaltyReleaseDryRun({ planReceipt, classification, broadcastArtifact }) {
  const plan = normalizeRoyaltyPhasePlanReceipt(planReceipt);
  const normalizedClassification = normalizeClassificationForDryRun(classification, plan);
  const transactions = verifyForgeDryRunArtifact(
    broadcastArtifact,
    normalizedClassification.remainingTransactions,
  );
  return {
    schema: ROYALTY_DRY_RUN_VERIFICATION_RECEIPT_SCHEMA,
    status: "dry_run_exactly_matches_classified_remaining_transactions",
    planSha256: plan.plan_sha256,
    classificationSha256: domainSha256(
      "dnai-wikigen/base-sepolia-royalty-state-classification/v1\0",
      classification,
    ),
    executionScope: normalizedClassification.executionScope,
    transactionCount: transactions.length,
    actions: transactions.map((entry) => entry.action),
    truthStatus: "local_forge_dry_run_structure_only_not_onchain_execution_or_finality",
  };
}

function finalizedProviderConfirmations({
  endpoints,
  observation,
  plan,
  authorityStateSha256,
  transactionReceiptsSha256,
  recoveryEvidence,
}) {
  const common = {
    chainId: CHAIN_ID,
    finalizedBlockNumber: observation.checkpoint.number,
    finalizedBlockHash: observation.checkpoint.hash,
    finalizedBlockTimestamp: observation.checkpoint.timestamp,
    distributorRuntimeCodeHash: plan.authority.distributor_runtime_code_hash,
    anchorRuntimeCodeHash: plan.authority.anchor_runtime_code_hash,
    authorityStateSha256,
    transactionReceiptsSha256,
    phaseTwoRecoveryEvidenceSha256: recoveryEvidence?.evidenceSha256 ?? null,
  };
  return [
    { label: "primary", rpcOrigin: endpoints.primary.origin, ...common },
    { label: "secondary", rpcOrigin: endpoints.secondary.origin, ...common },
  ];
}

export async function collectRoyaltyReleaseFinality({
  planReceipt,
  broadcastArtifact,
  priorBroadcastArtifact,
  primaryRpc,
  secondaryRpc,
  fetchImpl = globalThis.fetch,
}) {
  if (typeof fetchImpl !== "function") fail("fetch implementation is unavailable");
  const plan = normalizeRoyaltyPhasePlanReceipt(planReceipt);
  const endpoints = normalizeRpcEndpoints(primaryRpc, secondaryRpc);
  const observation = await commonFinalizedObservation({ plan, endpoints, fetchImpl });
  if (observation.classification !== expectedTerminalClassification(plan)) {
    fail("collect requires the exact finalized terminal Royalty state");
  }
  if (observation.signerNonce
    !== (BigInt(plan.transactions.at(-1).nonce) + 1n).toString(10)) {
    fail("collect finalized signer nonce is not exactly one past the reviewed plan");
  }
  let transactionReceipts;
  if (priorBroadcastArtifact !== undefined) {
    if (plan.execution_mode !== "activate_and_unpause") {
      fail("a prior broadcast artifact is valid only for activate-and-unpause suffix recovery");
    }
    const priorReceipts = await authenticateArtifactTransactions({
      artifact: priorBroadcastArtifact,
      plan,
      reviewedTransactions: [plan.transactions[0]],
      fetchImpl,
      endpoints,
      checkpoint: observation.checkpoint,
    });
    const currentReceipts = await authenticateArtifactTransactions({
      artifact: broadcastArtifact,
      plan,
      reviewedTransactions: [plan.transactions[1]],
      fetchImpl,
      endpoints,
      checkpoint: observation.checkpoint,
    });
    transactionReceipts = [...priorReceipts, ...currentReceipts];
  } else {
    transactionReceipts = await authenticateArtifactTransactions({
      artifact: broadcastArtifact,
      plan,
      reviewedTransactions: plan.transactions,
      fetchImpl,
      endpoints,
      checkpoint: observation.checkpoint,
    });
  }
  for (let index = 1; index < transactionReceipts.length; index += 1) {
    if (!transactionBefore(transactionReceipts[index - 1], transactionReceipts[index])) {
      fail("collected transactions do not preserve reviewed finalization order");
    }
  }
  if (plan.phase === 1
    && observation.authorityState.royaltyDistributor.pendingAuthorityActivatesAt
      !== transactionReceipts[0].blockTimestamp + 2 * 24 * 60 * 60) {
    fail("phase-one pending authority does not preserve the exact two-day contract timelock");
  }
  const recoveryEvidence = await authenticateRecoveryEvidence({
    plan,
    fetchImpl,
    endpoints,
    checkpoint: observation.checkpoint,
  });
  if (recoveryEvidence) {
    const current = transactionReceipts[0];
    if (!transactionBefore(recoveryEvidence.revertedUnpauseReceipt, current)
      || new Set([
        recoveryEvidence.activationReceipt.transactionHash,
        recoveryEvidence.revertedUnpauseReceipt.transactionHash,
        current.transactionHash,
      ]).size !== 3) {
      fail("recovery transactions do not precede the unique successful unpause");
    }
  }
  await recheckCheckpoint(fetchImpl, endpoints, observation.checkpoint);
  const authorityStateSha256 = domainSha256(
    "dnai-wikigen/base-sepolia-royalty-authority-state/v1\0",
    observation.authorityState,
  );
  const transactionReceiptsSha256 = domainSha256(
    "dnai-wikigen/base-sepolia-royalty-transaction-receipts/v1\0",
    transactionReceipts,
  );
  return {
    schema: ROYALTY_FINALIZED_AUTHORITY_SCHEMA,
    proof: FINALITY_PROOF,
    chainId: CHAIN_ID,
    finalizedBlockNumber: observation.checkpoint.number,
    finalizedBlockHash: observation.checkpoint.hash,
    finalizedBlockTimestamp: observation.checkpoint.timestamp,
    authorityStateSha256,
    transactionReceiptsSha256,
    phaseTwoRecoveryEvidence: recoveryEvidence,
    providerConfirmations: finalizedProviderConfirmations({
      endpoints,
      observation,
      plan,
      authorityStateSha256,
      transactionReceiptsSha256,
      recoveryEvidence,
    }),
    authorityState: observation.authorityState,
    transactionReceipts,
  };
}

function parseArgs(argv) {
  const command = argv[0];
  if (!new Set(["classify", "collect", "verify-dry-run"]).has(command)) {
    fail("expected classify, verify-dry-run, or collect command");
  }
  const values = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!key?.startsWith("--") || value === undefined || values.has(key)) {
      fail("arguments must be unique --name value pairs");
    }
    values.set(key, value);
  }
  const required = ["--plan-receipt", "--primary-rpc", "--secondary-rpc"];
  const allowed = new Set(required);
  if (command === "classify") allowed.add("--broadcast");
  if (command === "collect") {
    required.push("--broadcast", "--out");
    allowed.add("--broadcast");
    allowed.add("--prior-broadcast");
    allowed.add("--out");
  }
  if (command === "verify-dry-run") {
    required.splice(1, 2, "--classification", "--broadcast");
    allowed.clear();
    for (const key of required) allowed.add(key);
  }
  if (required.some((key) => !values.has(key))
    || [...values.keys()].some((key) => !allowed.has(key))) {
    fail(`unexpected arguments for ${command}`);
  }
  return { command, values };
}

async function main(argv) {
  const { command, values } = parseArgs(argv);
  const planReceipt = stableReadJson(values.get("--plan-receipt"), "phase-plan receipt");
  if (command === "verify-dry-run") {
    const receipt = verifyRoyaltyReleaseDryRun({
      planReceipt,
      classification: stableReadJson(
        values.get("--classification"),
        "Royalty state classification",
      ),
      broadcastArtifact: stableReadJson(
        values.get("--broadcast"),
        "Forge dry-run artifact",
      ),
    });
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    return;
  }
  const common = {
    planReceipt,
    primaryRpc: values.get("--primary-rpc"),
    secondaryRpc: values.get("--secondary-rpc"),
  };
  if (command === "classify") {
    const broadcastArtifact = values.has("--broadcast")
      ? stableReadJson(values.get("--broadcast"), "prior Forge broadcast artifact")
      : undefined;
    const receipt = await classifyRoyaltyRelease({ ...common, broadcastArtifact });
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    return;
  }
  const broadcastArtifact = stableReadJson(
    values.get("--broadcast"),
    "Forge broadcast artifact",
  );
  const priorBroadcastArtifact = values.has("--prior-broadcast")
    ? stableReadJson(values.get("--prior-broadcast"), "prior Forge broadcast artifact")
    : undefined;
  const artifact = await collectRoyaltyReleaseFinality({
    ...common,
    broadcastArtifact,
    priorBroadcastArtifact,
  });
  const out = values.get("--out");
  writeExclusiveJson(out, artifact);
  process.stdout.write(`${JSON.stringify({
    schema: ROYALTY_FINALIZED_AUTHORITY_WRITE_RECEIPT_SCHEMA,
    status: "finalized_authority_written_exclusive",
    outputPath: out,
    planSha256: planReceipt.plan_sha256,
    finalizedBlockNumber: artifact.finalizedBlockNumber,
    finalizedBlockHash: artifact.finalizedBlockHash,
    artifactSha256: domainSha256(
      "dnai-wikigen/base-sepolia-royalty-finalized-authority/v1\0",
      artifact,
    ),
  }, null, 2)}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
