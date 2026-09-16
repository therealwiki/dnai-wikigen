#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  canonicalArtifactSha256,
} from "../../../../scripts/operator-policy-packet-core.mjs";
import {
  freshContractDeploymentReceiptDigest,
  projectFreshContractDeploymentReceipt,
} from "../../../../scripts/cvm-launch-intent-core.mjs";
import {
  normalizeStageBSuccessorReviewerAuthority,
} from "../../../../scripts/release-authority-current-reviewer-facade.mjs";
import {
  FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA,
  ROYALTY_SETTLEMENT_RELEASE_BINDING_TEMPLATE_SCHEMA,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
  normalizeRoyaltySettlementReleaseBindingTemplate,
} from "../../../../scripts/execution-policy-release-core.mjs";
import {
  normalizeRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "../../../../scripts/royalty-release-history-receipt-core.mjs";
import {
  RELEASE_CEREMONY_LEDGER_PROTOCOL,
  canonicalReleaseCeremonyLedgerJsonText,
  releaseCeremonyLedgerRawSha256,
} from "../../../../scripts/release-ceremony-ledger.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  assertPinnedCastSignatureVerifier,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  normalizeExpectedReviewerAuthority,
  verifyPinnedTwoSignerAuthorization,
} from "../../../../scripts/release-authority-signature-verifier.mjs";
import {
  canonicalJsonSha256,
} from "./royalty-release-ledger-binding.mjs";
import {
  ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
  royaltyUnpauseRecoveryEvidenceSha256,
} from "./royalty-release-finality.mjs";

export const ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA =
  "dnai.royalty-release-phase-plan-core.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_SCHEMA =
  "dnai.royalty-release-phase-plan.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_SIGNATURES_SCHEMA =
  "dnai.royalty-release-phase-plan-signatures.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_REVIEW_SCHEMA =
  "dnai.royalty-release-phase-plan-review.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_SIGNING_PAYLOAD_SCHEMA =
  "dnai.royalty-release-phase-plan-signing-payload.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_VERIFICATION_RECEIPT_SCHEMA =
  "dnai.royalty-release-phase-plan-verification-receipt.v2";
export const ROYALTY_RELEASE_PHASE_PLAN_STATUS = "reviewed_for_exact_phase";
export const ROYALTY_RELEASE_EXECUTION_MODES = Object.freeze([
  "stage_authority",
  "activate_and_unpause",
  "recover_reverted_unpause",
]);
export const ROYALTY_RELEASE_PHASE_PLAN_DECLARATION =
  "two_distinct_current_reviewers_authorize_only_the_exact_base_sepolia_royalty_phase_contracts_roles_nonces_calldata_order_and_validity_window";
export const ROYALTY_RELEASE_PHASE_PLAN_SIGNING_DOMAIN =
  "dnai-wikigen/royalty-release-phase-plan-signing/v2\0";
export const ROYALTY_RELEASE_PHASE_PLAN_SIGNING_MESSAGE_PREFIX =
  "dnai-wikigen royalty-release phase-plan v2:";
export const ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_SCHEMA =
  "dnai.royalty-release-phase-plan-generation-request.v1";
export const ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_TRUTH_STATUS =
  "operator_supplied_window_and_nonce_only_not_reviewed_signed_or_chain_observed";
export const ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA =
  "dnai.royalty-release-prescriptive-authority.v1";
export const ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_DOMAIN =
  "dnai-wikigen/royalty-release-prescriptive-authority/v1\0";
export const REQUIRED_FINAL_RELEASE_AUTHORITY_V4_SCHEMA =
  FINAL_RELEASE_AUTHORITY_CORE_V4_SCHEMA;
export const REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA =
  "dnai.royalty-settlement-release-binding.v1";
export const ROYALTY_SETTLEMENT_RELEASE_BINDING_DOMAIN =
  "dnai-wikigen/royalty-settlement-release-binding/v1\0";
export const ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_RECEIPT_SCHEMA =
  "dnai.royalty-settlement-release-reconciliation-receipt.v1";
export const ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_STATUS =
  "current_final_authority_v4_and_h_reconciled_to_prescription";
export const ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_TRUTH_STATUS =
  "canonical_artifacts_reconciled_not_chain_access_or_transaction_finality_collection";

const CHAIN_ID = 84_532;
const MAX_FILE_BYTES = 4 * 1024 * 1024;
const MAX_PLAN_LIFETIME_MS = 15 * 60 * 1_000;
const MIN_PLAN_HEADROOM_MS = 2 * 60 * 1_000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const MAX_CONTEXT_WALL_CLOCK_SKEW_MS = 30 * 1_000;
const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const CALLDATA = /^0x(?:[0-9a-f]{2})+$/;
const DECIMAL = /^(?:0|[1-9][0-9]{0,77})$/;
const UTC_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const RELEASE_POLICY_TYPEHASH =
  "0x52ea595bfb36fbea11956e81e6cc1e6c8a72e57f6a45045c1b75494cd35cae3d";
const PROPOSE_AUTHORITY_BINDING_SELECTOR = "2e974627";
const ACTIVATE_AUTHORITY_PROPOSAL_CALLDATA = "0x552d3bd4";
const SET_PAUSED_FALSE_CALLDATA = `0x16c38b3c${"0".repeat(64)}`;
const CAST_OUTPUT_BYTES32 = /^0x[0-9a-f]{64}$/;
const POLICY_CACHE = new Map();
const AUTHENTICATED_REVIEWER_CONTEXTS = new WeakSet();

export class RoyaltyReleasePhasePlanError extends TypeError {}

function fail(message) {
  throw new RoyaltyReleasePhasePlanError(message);
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

function deepFreeze(value) {
  if (Array.isArray(value)) {
    for (const entry of value) deepFreeze(entry);
  } else if (isRecord(value)) {
    for (const entry of Object.values(value)) deepFreeze(entry);
  }
  return Object.freeze(value);
}

function canonicalSnapshot(value) {
  return deepFreeze(JSON.parse(canonicalText(value)));
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function exactString(value, expected, label) {
  if (value !== expected) fail(`${label} must equal ${expected}`);
  return value;
}

function nonzeroSha256(value, label) {
  if (!SHA256.test(value) || value === ZERO_SHA256) {
    fail(`${label} must be a nonzero lowercase SHA-256 digest`);
  }
  return value;
}

function bareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value) || /^0+$/.test(value)) {
    fail(`${label} must be a nonzero lowercase bare SHA-256 digest`);
  }
  return value;
}

function nonzeroBytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)
    || value.toLowerCase() === ZERO_BYTES32) {
    fail(`${label} must be a nonzero lowercase bytes32`);
  }
  return value.toLowerCase();
}

function nonzeroAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)
    || value.toLowerCase() === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value.toLowerCase();
}

function decimal(value, label) {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    fail(`${label} must be a canonical uint256 decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed >= 2n ** 256n) fail(`${label} exceeds uint256`);
  return parsed.toString(10);
}

function positiveDecimal(value, label, maximum = 2n ** 256n - 1n) {
  const normalized = decimal(value, label);
  const parsed = BigInt(normalized);
  if (parsed < 1n || parsed > maximum) fail(`${label} is out of range`);
  return normalized;
}

function abiUint256Word(value, label) {
  const normalized = decimal(value, label);
  return BigInt(normalized).toString(16).padStart(64, "0");
}

function abiAddressWord(value, label) {
  return nonzeroAddress(value, label).slice(2).padStart(64, "0");
}

function rawBytesSha256(value, label) {
  if (typeof value !== "string" || !CALLDATA.test(value)) {
    fail(`${label} must be lowercase even-length hex bytes`);
  }
  return `sha256:${createHash("sha256")
    .update(Buffer.from(value.slice(2), "hex"))
    .digest("hex")}`;
}

function runPinnedCastKeccak(hexData) {
  if (typeof hexData !== "string" || !CALLDATA.test(hexData)) {
    fail("release-policy ABI encoding must be lowercase even-length hex bytes");
  }
  assertPinnedCastSignatureVerifier();
  const executable = path.join(
    os.homedir(),
    PINNED_CAST_SIGNATURE_VERIFIER.executable_user_relative_path,
  );
  const before = fs.lstatSync(executable);
  const result = spawnSync(executable, ["keccak", hexData], {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 16 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      HOME: os.homedir(),
      LANG: "C",
      LC_ALL: "C",
      NO_COLOR: "1",
      PATH: "/usr/bin:/bin",
    },
  });
  const after = fs.lstatSync(executable);
  assertPinnedCastSignatureVerifier();
  if (result.error || result.status !== 0
    || before.dev !== after.dev || before.ino !== after.ino
    || before.size !== after.size || before.mtimeMs !== after.mtimeMs
    || before.ctimeMs !== after.ctimeMs) {
    fail("pinned cast release-policy commitment computation failed or changed identity");
  }
  const output = result.stdout.trim();
  if (!CAST_OUTPUT_BYTES32.test(output)) {
    fail("pinned cast returned an invalid release-policy commitment");
  }
  return output;
}

export function royaltyReleasePolicyCommitment(authority) {
  const normalized = normalizeAuthority(authority, { verifyPolicy: false });
  const encoded = `0x${[
    RELEASE_POLICY_TYPEHASH.slice(2),
    abiUint256Word(String(CHAIN_ID), "release-policy chain ID"),
    abiAddressWord(normalized.distributor_address, "release-policy distributor"),
    abiUint256Word(normalized.authority_nonce, "release-policy authority nonce"),
    abiAddressWord(normalized.settlement_verifier, "release-policy settlement verifier"),
    abiAddressWord(normalized.qvl_verifier, "release-policy QVL verifier"),
    abiAddressWord(normalized.anchor_address, "release-policy anchor"),
    normalized.anchor_writer_release_commitment.slice(2),
  ].join("")}`;
  const cached = POLICY_CACHE.get(encoded);
  if (cached !== undefined) return cached;
  const commitment = runPinnedCastKeccak(encoded);
  POLICY_CACHE.set(encoded, commitment);
  return commitment;
}

export function royaltyReleaseActionCalldata(action, authority) {
  const normalized = normalizeAuthority(authority, { verifyPolicy: false });
  if (action === "propose_authority_binding") {
    return `0x${PROPOSE_AUTHORITY_BINDING_SELECTOR}${[
      abiAddressWord(normalized.settlement_verifier, "proposal settlement verifier"),
      abiAddressWord(normalized.qvl_verifier, "proposal QVL verifier"),
      abiAddressWord(normalized.anchor_address, "proposal anchor"),
      normalized.anchor_writer_release_commitment.slice(2),
    ].join("")}`;
  }
  if (action === "activate_authority_proposal") {
    return ACTIVATE_AUTHORITY_PROPOSAL_CALLDATA;
  }
  if (action === "unpause") return SET_PAUSED_FALSE_CALLDATA;
  fail("unsupported royalty release action");
}

export function royaltyReleaseActionCalldataSha256(action, authority) {
  return rawBytesSha256(
    royaltyReleaseActionCalldata(action, authority),
    `${action} calldata`,
  );
}

function integer(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} is out of range`);
  }
  return value;
}

function timestamp(value, label) {
  if (typeof value !== "string" || !UTC_MILLISECONDS.test(value)) {
    fail(`${label} must be canonical millisecond UTC`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail(`${label} is invalid`);
  }
  return parsed;
}

function normalizeAuthority(value, { verifyPolicy = true } = {}) {
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
  ], "royalty phase authority");
  const authority = {
    distributor_address: nonzeroAddress(parsed.distributor_address, "distributor address"),
    distributor_runtime_code_hash: nonzeroBytes32(
      parsed.distributor_runtime_code_hash,
      "distributor runtime code hash",
    ),
    owner: nonzeroAddress(parsed.owner, "royalty owner"),
    settlement_verifier: nonzeroAddress(parsed.settlement_verifier, "settlement verifier"),
    qvl_verifier: nonzeroAddress(parsed.qvl_verifier, "QVL verifier"),
    anchor_address: nonzeroAddress(parsed.anchor_address, "execution-policy anchor"),
    anchor_runtime_code_hash: nonzeroBytes32(
      parsed.anchor_runtime_code_hash,
      "anchor runtime code hash",
    ),
    anchor_writer: nonzeroAddress(parsed.anchor_writer, "anchor writer"),
    anchor_writer_release_commitment: nonzeroBytes32(
      parsed.anchor_writer_release_commitment,
      "anchor writer release commitment",
    ),
    release_policy_commitment: nonzeroBytes32(
      parsed.release_policy_commitment,
      "royalty release-policy commitment",
    ),
    authority_nonce: decimal(parsed.authority_nonce, "royalty authority nonce"),
  };
  if (authority.authority_nonce !== "1") {
    fail("royalty phase-plan v2 authorizes only fresh authority nonce 1");
  }
  const addresses = [
    authority.distributor_address,
    authority.owner,
    authority.settlement_verifier,
    authority.qvl_verifier,
    authority.anchor_address,
    authority.anchor_writer,
  ];
  if (new Set(addresses).size !== addresses.length) {
    fail("royalty owner, distributor, verifiers, anchor, and anchor writer must all be distinct");
  }
  if (verifyPolicy
    && authority.release_policy_commitment !== royaltyReleasePolicyCommitment(authority)) {
    fail("royalty release-policy commitment does not match the exact v1 authority");
  }
  return authority;
}

function normalizePhaseOnePrerequisite(value, phase, executionMode) {
  if (phase === 1) {
    if (value !== null) fail("phase 1 must not claim prior Royalty release evidence");
    return null;
  }
  const parsed = exactRecord(value, [
    "finalized_authority_receipt_sha256",
    "ledger_revision",
    "ledger_revision_receipt_sha256",
    "ledger_sha256",
    "pending_authority_activates_at",
    "phase_one_history_record_sha256",
    "phase_one_finalized_at",
    "phase_one_plan_sha256",
    "proposal_block_hash",
    "proposal_block_number",
    "proposal_tx_hash",
  ], "phase-one prerequisite");
  const prerequisite = {
    phase_one_plan_sha256: nonzeroSha256(parsed.phase_one_plan_sha256, "phase-one plan digest"),
    phase_one_history_record_sha256: nonzeroSha256(
      parsed.phase_one_history_record_sha256,
      "phase-one history-record digest",
    ),
    phase_one_finalized_at: parsed.phase_one_finalized_at,
    finalized_authority_receipt_sha256: nonzeroSha256(
      parsed.finalized_authority_receipt_sha256,
      "phase-one finalized-authority receipt digest",
    ),
    ledger_sha256: nonzeroSha256(parsed.ledger_sha256, "phase-one ledger digest"),
    ledger_revision: integer(parsed.ledger_revision, "phase-one ledger revision", 1, 0xffff_ffff),
    ledger_revision_receipt_sha256: nonzeroSha256(
      parsed.ledger_revision_receipt_sha256,
      "phase-one ledger revision-receipt digest",
    ),
    proposal_tx_hash: nonzeroBytes32(parsed.proposal_tx_hash, "phase-one proposal transaction hash"),
    proposal_block_number: positiveDecimal(
      parsed.proposal_block_number,
      "phase-one proposal block number",
    ),
    proposal_block_hash: nonzeroBytes32(parsed.proposal_block_hash, "phase-one proposal block hash"),
    pending_authority_activates_at: positiveDecimal(
      parsed.pending_authority_activates_at,
      "pending authority activation timestamp",
      2n ** 64n - 1n,
    ),
  };
  timestamp(prerequisite.phase_one_finalized_at, "phase-one finalized timestamp");
  if (executionMode === "stage_authority") {
    fail("phase 2 cannot use the phase-one execution mode");
  }
  return prerequisite;
}

function normalizePhaseTwoRecovery(value, phase, executionMode) {
  if (executionMode !== "recover_reverted_unpause") {
    if (value !== null) fail("non-recovery Royalty plans must not claim recovery evidence");
    return null;
  }
  if (phase !== 2) fail("Royalty unpause recovery is phase 2 only");
  const parsed = exactRecord(value, [
    "activation_block_hash",
    "activation_block_number",
    "activation_tx_hash",
    "finalized_recovery_evidence_sha256",
    "prior_phase_two_plan_sha256",
    "prior_unpause_nonce",
    "reverted_unpause_block_hash",
    "reverted_unpause_block_number",
    "reverted_unpause_tx_hash",
  ], "phase-two recovery prerequisite");
  const recovery = {
    prior_phase_two_plan_sha256: nonzeroSha256(
      parsed.prior_phase_two_plan_sha256,
      "prior phase-two plan digest",
    ),
    finalized_recovery_evidence_sha256: nonzeroSha256(
      parsed.finalized_recovery_evidence_sha256,
      "finalized phase-two recovery evidence digest",
    ),
    activation_tx_hash: nonzeroBytes32(parsed.activation_tx_hash, "activation transaction hash"),
    activation_block_number: positiveDecimal(
      parsed.activation_block_number,
      "activation block number",
    ),
    activation_block_hash: nonzeroBytes32(parsed.activation_block_hash, "activation block hash"),
    reverted_unpause_tx_hash: nonzeroBytes32(
      parsed.reverted_unpause_tx_hash,
      "reverted unpause transaction hash",
    ),
    reverted_unpause_block_number: positiveDecimal(
      parsed.reverted_unpause_block_number,
      "reverted unpause block number",
    ),
    reverted_unpause_block_hash: nonzeroBytes32(
      parsed.reverted_unpause_block_hash,
      "reverted unpause block hash",
    ),
    prior_unpause_nonce: positiveDecimal(
      parsed.prior_unpause_nonce,
      "prior unpause transaction nonce",
    ),
  };
  if (recovery.activation_tx_hash === recovery.reverted_unpause_tx_hash) {
    fail("activation and reverted-unpause transaction hashes must differ");
  }
  const activationBlock = BigInt(recovery.activation_block_number);
  const revertedBlock = BigInt(recovery.reverted_unpause_block_number);
  if (activationBlock > revertedBlock
    || ((activationBlock === revertedBlock)
      !== (recovery.activation_block_hash === recovery.reverted_unpause_block_hash))) {
    fail("activation and reverted-unpause block order or hash identity is impossible");
  }
  return recovery;
}

function expectedActions(phase, executionMode) {
  if (phase === 1 && executionMode === "stage_authority") {
    return ["propose_authority_binding"];
  }
  if (phase === 2 && executionMode === "activate_and_unpause") {
    return ["activate_authority_proposal", "unpause"];
  }
  if (phase === 2 && executionMode === "recover_reverted_unpause") {
    return ["unpause"];
  }
  fail("royalty release phase and execution mode are incompatible");
}

function normalizeTransaction(value, index, phase, executionMode, authority) {
  const parsed = exactRecord(value, [
    "action",
    "calldata",
    "calldata_sha256",
    "nonce",
    "sequence",
    "signer_address",
    "to",
    "value_wei",
  ], `royalty phase transaction ${index}`);
  const expectedAction = expectedActions(phase, executionMode)[index];
  if (parsed.sequence !== index || parsed.action !== expectedAction) {
    fail("royalty phase transaction order or action is invalid");
  }
  const signer = nonzeroAddress(parsed.signer_address, `transaction ${index} signer`);
  const to = nonzeroAddress(parsed.to, `transaction ${index} target`);
  if (signer !== authority.owner || to !== authority.distributor_address) {
    fail("royalty phase transactions must use the exact owner and distributor");
  }
  if (parsed.value_wei !== "0") fail("royalty phase transactions must have zero value");
  const calldata = royaltyReleaseActionCalldata(expectedAction, authority);
  if (parsed.calldata !== calldata) {
    fail(`transaction ${index} calldata differs from the exact ${expectedAction} encoding`);
  }
  const calldataSha256 = rawBytesSha256(calldata, `transaction ${index} calldata`);
  if (parsed.calldata_sha256 !== calldataSha256) {
    fail(`transaction ${index} calldata digest is invalid`);
  }
  return {
    sequence: index,
    action: expectedAction,
    signer_address: signer,
    nonce: decimal(parsed.nonce, `transaction ${index} nonce`),
    to,
    value_wei: "0",
    calldata,
    calldata_sha256: calldataSha256,
  };
}

function normalizeGenerationRequest(value) {
  const parsed = exactRecord(value, [
    "execution_mode",
    "expires_at",
    "first_transaction_nonce",
    "phase",
    "schema",
    "truth_status",
    "valid_after",
  ], "royalty phase-plan generation request");
  exactString(
    parsed.schema,
    ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_SCHEMA,
    "phase-plan generation-request schema",
  );
  exactString(
    parsed.truth_status,
    ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_TRUTH_STATUS,
    "phase-plan generation-request truth status",
  );
  const phase = integer(parsed.phase, "generation-request phase", 1, 2);
  if (!ROYALTY_RELEASE_EXECUTION_MODES.includes(parsed.execution_mode)) {
    fail("generation-request execution mode is unsupported");
  }
  expectedActions(phase, parsed.execution_mode);
  timestamp(parsed.valid_after, "generation-request valid-after timestamp");
  timestamp(parsed.expires_at, "generation-request expiry timestamp");
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_SCHEMA,
    truth_status: ROYALTY_RELEASE_PHASE_PLAN_GENERATION_REQUEST_TRUTH_STATUS,
    phase,
    execution_mode: parsed.execution_mode,
    first_transaction_nonce: decimal(
      parsed.first_transaction_nonce,
      "generation-request first transaction nonce",
    ),
    valid_after: parsed.valid_after,
    expires_at: parsed.expires_at,
  };
}

function normalizeLedgerReplayForGeneration(value, { reviewerContext, ledger }) {
  const replay = exactRecord(value, [
    "current_ledger_bytes",
    "current_ledger_sha256",
    "finalization_receipt_sha256",
    "finalized",
    "initialization_receipt_sha256",
    "last_revision_receipt_sha256",
    "ledger_mode",
    "protocol",
    "recovery_receipt_count",
    "release_sha",
    "revision_chain_sha256",
    "revision_count",
  ], "release ceremony ledger replay");
  exactString(replay.protocol, RELEASE_CEREMONY_LEDGER_PROTOCOL, "ledger replay protocol");
  exactString(
    replay.release_sha,
    reviewerContext.freshDeployment.releaseSha,
    "ledger replay release SHA",
  );
  if (replay.finalized !== false || replay.finalization_receipt_sha256 !== null
    || replay.ledger_mode !== "0600") {
    fail("phase-core generation requires the active non-finalized 0600 ceremony ledger");
  }
  nonzeroSha256(replay.initialization_receipt_sha256, "ledger initialization receipt digest");
  nonzeroSha256(replay.revision_chain_sha256, "ledger revision-chain digest");
  const revisionCount = integer(
    replay.revision_count,
    "ledger replay revision count",
    0,
    0xffff_ffff,
  );
  integer(
    replay.recovery_receipt_count,
    "ledger replay recovery receipt count",
    0,
    0xffff_ffff,
  );
  const ledgerText = canonicalReleaseCeremonyLedgerJsonText(ledger);
  const ledgerBytes = Buffer.byteLength(ledgerText, "utf8");
  const ledgerSha256 = releaseCeremonyLedgerRawSha256(Buffer.from(ledgerText, "utf8"));
  if (replay.current_ledger_bytes !== ledgerBytes
    || replay.current_ledger_sha256 !== ledgerSha256) {
    fail("ledger replay does not bind the exact canonical working-ledger bytes");
  }
  if (revisionCount === 0) {
    if (replay.last_revision_receipt_sha256 !== null) {
      fail("zero-revision ledger replay cannot carry a revision receipt");
    }
  } else {
    nonzeroSha256(replay.last_revision_receipt_sha256, "last ledger revision-receipt digest");
  }
  return {
    current_ledger_sha256: ledgerSha256,
    revision_count: revisionCount,
    last_revision_receipt_sha256: replay.last_revision_receipt_sha256,
  };
}

function canonicalFinalizedTimestamp(value) {
  const seconds = integer(value, "phase-one finalized block timestamp", 1, 0xffff_ffff_ffff);
  const milliseconds = seconds * 1_000;
  if (!Number.isSafeInteger(milliseconds)) {
    fail("phase-one finalized block timestamp is outside the canonical date range");
  }
  const normalized = new Date(milliseconds).toISOString();
  timestamp(normalized, "phase-one finalized timestamp");
  return normalized;
}

function phaseOnePrerequisiteFromLedger({ record, replay }) {
  if (!isRecord(record) || !isRecord(record.finalizedAuthority)
    || !Array.isArray(record.transactionReceipts)
    || record.transactionReceipts.length !== 1 || !isRecord(record.transactionReceipts[0])
    || !isRecord(record.postState)) {
    fail("phase-two generation requires one complete finalized phase-one ledger record");
  }
  if (record.phase !== 1 || record.executionMode !== "stage_authority") {
    fail("phase-two generation predecessor is not the exact Royalty phase one");
  }
  const transaction = record.transactionReceipts[0];
  return {
    phase_one_plan_sha256: nonzeroSha256(
      record.phasePlanSha256,
      "phase-one recorded plan digest",
    ),
    phase_one_history_record_sha256: canonicalJsonSha256(record),
    phase_one_finalized_at: canonicalFinalizedTimestamp(
      record.finalizedAuthority.finalizedBlockTimestamp,
    ),
    finalized_authority_receipt_sha256: canonicalJsonSha256(record.finalizedAuthority),
    ledger_sha256: replay.current_ledger_sha256,
    ledger_revision: integer(
      replay.revision_count,
      "phase-two ledger revision",
      1,
      0xffff_ffff,
    ),
    ledger_revision_receipt_sha256: nonzeroSha256(
      replay.last_revision_receipt_sha256,
      "phase-two ledger revision-receipt digest",
    ),
    proposal_tx_hash: nonzeroBytes32(
      transaction.transactionHash,
      "phase-one proposal transaction hash",
    ),
    proposal_block_number: positiveDecimal(
      String(transaction.blockNumber),
      "phase-one proposal block number",
    ),
    proposal_block_hash: nonzeroBytes32(
      transaction.blockHash,
      "phase-one proposal block hash",
    ),
    pending_authority_activates_at: positiveDecimal(
      String(record.postState.pendingAuthorityActivatesAt),
      "phase-one pending authority activation timestamp",
      2n ** 64n - 1n,
    ),
  };
}

function normalizeRecoveryReceiptForGeneration(value, {
  authority,
  action,
  sequence,
  status,
  label,
}) {
  const parsed = exactRecord(value, [
    "action", "blockHash", "blockNumber", "blockTimestamp", "calldata",
    "calldataSha256", "nonce", "sender", "sequence", "status", "target",
    "transactionHash", "transactionIndex", "valueWei",
  ], label);
  const calldata = royaltyReleaseActionCalldata(action, authority);
  const calldataSha256 = royaltyReleaseActionCalldataSha256(action, authority);
  const receipt = {
    sequence: integer(parsed.sequence, `${label} sequence`, sequence, sequence),
    action: exactString(parsed.action, action, `${label} action`),
    sender: nonzeroAddress(parsed.sender, `${label} sender`),
    target: nonzeroAddress(parsed.target, `${label} target`),
    nonce: decimal(parsed.nonce, `${label} nonce`),
    valueWei: decimal(parsed.valueWei, `${label} value`),
    calldata: parsed.calldata,
    calldataSha256: parsed.calldataSha256,
    transactionHash: nonzeroBytes32(parsed.transactionHash, `${label} transaction hash`),
    status: exactString(parsed.status, status, `${label} status`),
    blockNumber: integer(parsed.blockNumber, `${label} block number`, 1, Number.MAX_SAFE_INTEGER),
    blockHash: nonzeroBytes32(parsed.blockHash, `${label} block hash`),
    blockTimestamp: integer(parsed.blockTimestamp, `${label} block timestamp`, 1, Number.MAX_SAFE_INTEGER),
    transactionIndex: integer(parsed.transactionIndex, `${label} transaction index`, 0, Number.MAX_SAFE_INTEGER),
  };
  if (receipt.sender !== authority.owner || receipt.target !== authority.distributor_address
    || receipt.valueWei !== "0" || receipt.calldata !== calldata
    || receipt.calldataSha256 !== calldataSha256) {
    fail(`${label} differs from the exact owner, distributor, zero value, or calldata`);
  }
  return receipt;
}

function recoveryPrerequisiteFromEvidence(value, authority) {
  const evidence = exactRecord(value, [
    "activationReceipt",
    "evidenceSha256",
    "priorPhaseTwoPlanSha256",
    "revertedUnpauseReceipt",
    "schema",
  ], "Royalty unpause recovery evidence");
  exactString(
    evidence.schema,
    ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
    "Royalty unpause recovery-evidence schema",
  );
  const activation = normalizeRecoveryReceiptForGeneration(evidence.activationReceipt, {
    authority,
    action: "activate_authority_proposal",
    sequence: 0,
    status: "success",
    label: "recovery activation receipt",
  });
  const reverted = normalizeRecoveryReceiptForGeneration(evidence.revertedUnpauseReceipt, {
    authority,
    action: "unpause",
    sequence: 1,
    status: "reverted",
    label: "reverted unpause receipt",
  });
  const normalizedEvidence = {
    schema: ROYALTY_UNPAUSE_RECOVERY_EVIDENCE_SCHEMA,
    evidenceSha256: nonzeroSha256(evidence.evidenceSha256, "recovery evidence digest"),
    priorPhaseTwoPlanSha256: nonzeroSha256(
      evidence.priorPhaseTwoPlanSha256,
      "prior phase-two plan digest",
    ),
    activationReceipt: activation,
    revertedUnpauseReceipt: reverted,
  };
  if (royaltyUnpauseRecoveryEvidenceSha256(normalizedEvidence)
      !== normalizedEvidence.evidenceSha256
    || BigInt(reverted.nonce) !== BigInt(activation.nonce) + 1n
    || activation.blockNumber > reverted.blockNumber
    || (activation.blockNumber === reverted.blockNumber
      && (activation.blockHash !== reverted.blockHash
        || activation.transactionIndex >= reverted.transactionIndex))
    || activation.transactionHash === reverted.transactionHash) {
    fail("Royalty recovery evidence digest, nonce, order, or transaction identity is invalid");
  }
  return {
    prior_phase_two_plan_sha256: normalizedEvidence.priorPhaseTwoPlanSha256,
    finalized_recovery_evidence_sha256: normalizedEvidence.evidenceSha256,
    activation_tx_hash: activation.transactionHash,
    activation_block_number: String(activation.blockNumber),
    activation_block_hash: activation.blockHash,
    reverted_unpause_tx_hash: reverted.transactionHash,
    reverted_unpause_block_number: String(reverted.blockNumber),
    reverted_unpause_block_hash: reverted.blockHash,
    prior_unpause_nonce: reverted.nonce,
  };
}

function normalizeRoyaltyReleasePhasePlanCoreStructural(value, { checkedAtMs } = {}) {
  const parsed = exactRecord(value, [
    "authority",
    "chain_id",
    "deployment_intent_sha256",
    "expires_at",
    "execution_mode",
    "fresh_contract_deployment_receipt_sha256",
    "phase",
    "phase_one_prerequisite",
    "phase_two_recovery",
    "release_sha",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "royalty_release_prescriptive_authority_sha256",
    "schema",
    "status",
    "transactions",
    "valid_after",
  ], "royalty release phase-plan core");
  exactString(parsed.schema, ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA, "phase-plan core schema");
  exactString(parsed.status, "proposed_for_review", "phase-plan core status");
  if (!SHA40.test(parsed.release_sha) || /^0+$/.test(parsed.release_sha)) {
    fail("phase-plan release SHA is invalid");
  }
  integer(parsed.chain_id, "phase-plan chain ID", CHAIN_ID, CHAIN_ID);
  const phase = integer(parsed.phase, "royalty release phase", 1, 2);
  if (!ROYALTY_RELEASE_EXECUTION_MODES.includes(parsed.execution_mode)) {
    fail("royalty release execution mode is unsupported");
  }
  const executionMode = parsed.execution_mode;
  expectedActions(phase, executionMode);
  const authority = normalizeAuthority(parsed.authority);
  const phaseOnePrerequisite = normalizePhaseOnePrerequisite(
    parsed.phase_one_prerequisite,
    phase,
    executionMode,
  );
  const phaseTwoRecovery = normalizePhaseTwoRecovery(
    parsed.phase_two_recovery,
    phase,
    executionMode,
  );
  const validAfterMs = timestamp(parsed.valid_after, "phase-plan valid-after timestamp");
  const expiresAtMs = timestamp(parsed.expires_at, "phase-plan expiry timestamp");
  if (expiresAtMs <= validAfterMs || expiresAtMs - validAfterMs > MAX_PLAN_LIFETIME_MS) {
    fail("royalty phase-plan validity window is invalid or exceeds fifteen minutes");
  }
  if (phaseOnePrerequisite !== null) {
    const activationMs = BigInt(phaseOnePrerequisite.pending_authority_activates_at) * 1_000n;
    const finalizedAtMs = BigInt(timestamp(
      phaseOnePrerequisite.phase_one_finalized_at,
      "phase-one finalized timestamp",
    ));
    if (BigInt(validAfterMs) < activationMs || BigInt(validAfterMs) < finalizedAtMs) {
      fail("phase 2 cannot become valid before timelock activation and finalized phase-one evidence");
    }
  }
  if (phaseTwoRecovery !== null
    && BigInt(phaseOnePrerequisite.proposal_block_number)
      >= BigInt(phaseTwoRecovery.activation_block_number)) {
    fail("phase-one proposal block must precede the recovered activation block");
  }
  if (checkedAtMs !== undefined) {
    if (!Number.isFinite(checkedAtMs) || checkedAtMs < 1) fail("checkedAtMs is invalid");
    if (validAfterMs > checkedAtMs + MAX_FUTURE_SKEW_MS
      || checkedAtMs < validAfterMs
      || expiresAtMs - checkedAtMs < MIN_PLAN_HEADROOM_MS) {
      fail("royalty phase-plan is not currently valid with required headroom");
    }
  }
  if (!Array.isArray(parsed.transactions)
    || parsed.transactions.length !== expectedActions(phase, executionMode).length) {
    fail("royalty phase-plan has an unexpected transaction count");
  }
  const transactions = parsed.transactions.map(
    (entry, index) => normalizeTransaction(entry, index, phase, executionMode, authority),
  );
  for (let index = 1; index < transactions.length; index += 1) {
    if (BigInt(transactions[index].nonce) !== BigInt(transactions[index - 1].nonce) + 1n) {
      fail("royalty phase transaction nonces must be contiguous");
    }
  }
  if (phaseTwoRecovery !== null
    && BigInt(transactions[0].nonce) !== BigInt(phaseTwoRecovery.prior_unpause_nonce) + 1n) {
    fail("recovery unpause nonce must be exactly one after the finalized reverted attempt");
  }
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA,
    status: "proposed_for_review",
    release_sha: parsed.release_sha,
    chain_id: CHAIN_ID,
    phase,
    execution_mode: executionMode,
    phase_one_prerequisite: phaseOnePrerequisite,
    phase_two_recovery: phaseTwoRecovery,
    valid_after: parsed.valid_after,
    expires_at: parsed.expires_at,
    deployment_intent_sha256: nonzeroSha256(
      parsed.deployment_intent_sha256,
      "deployment-intent digest",
    ),
    fresh_contract_deployment_receipt_sha256: nonzeroSha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "fresh contract deployment-receipt digest",
    ),
    royalty_release_prescriptive_authority_sha256: nonzeroSha256(
      parsed.royalty_release_prescriptive_authority_sha256,
      "Royalty prescriptive-authority digest",
    ),
    reviewer_authority_genesis_sha256: nonzeroSha256(
      parsed.reviewer_authority_genesis_sha256,
      "reviewer genesis digest",
    ),
    reviewer_authority_genesis_acceptance_sha256: nonzeroSha256(
      parsed.reviewer_authority_genesis_acceptance_sha256,
      "reviewer genesis-acceptance digest",
    ),
    reviewer_authority_current_status_epoch: integer(
      parsed.reviewer_authority_current_status_epoch,
      "reviewer current-status epoch",
      1,
      0xffff_ffff,
    ),
    reviewer_authority_current_status_sha256: nonzeroSha256(
      parsed.reviewer_authority_current_status_sha256,
      "reviewer current-status digest",
    ),
    reviewer_root_hash: bareSha256(parsed.reviewer_root_hash, "reviewer root hash"),
    reviewer_set_sha256: nonzeroSha256(parsed.reviewer_set_sha256, "reviewer set digest"),
    authority,
    transactions,
  };
}

export function normalizeRoyaltyReleasePhasePlanCore(value, { checkedAtMs } = {}) {
  if (!Number.isFinite(checkedAtMs) || checkedAtMs < 1) {
    fail("royalty phase-plan current validation requires checkedAtMs");
  }
  return normalizeRoyaltyReleasePhasePlanCoreStructural(value, { checkedAtMs });
}

export function royaltyReleasePhasePlanSha256(core) {
  const normalized = normalizeRoyaltyReleasePhasePlanCoreStructural(core);
  return domainSha256("dnai-wikigen/royalty-release-phase-plan-core/v2\0", normalized);
}

export function royaltyReleasePhasePlanSigningPayload(core) {
  const normalized = normalizeRoyaltyReleasePhasePlanCoreStructural(core);
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_SIGNING_PAYLOAD_SCHEMA,
    subject_kind: "royalty_release_phase_plan",
    plan_sha256: royaltyReleasePhasePlanSha256(normalized),
    release_sha: normalized.release_sha,
    chain_id: CHAIN_ID,
    phase: normalized.phase,
    execution_mode: normalized.execution_mode,
    valid_after: normalized.valid_after,
    expires_at: normalized.expires_at,
    deployment_intent_sha256: normalized.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      normalized.fresh_contract_deployment_receipt_sha256,
    royalty_release_prescriptive_authority_sha256:
      normalized.royalty_release_prescriptive_authority_sha256,
    reviewer_authority_genesis_sha256: normalized.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      normalized.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      normalized.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      normalized.reviewer_authority_current_status_sha256,
    reviewer_root_hash: normalized.reviewer_root_hash,
    reviewer_set_sha256: normalized.reviewer_set_sha256,
    declaration: ROYALTY_RELEASE_PHASE_PLAN_DECLARATION,
  };
}

export function royaltyReleasePhasePlanSigningPayloadSha256(core) {
  return eip191AuthorizationSigningDigest({
    domain: ROYALTY_RELEASE_PHASE_PLAN_SIGNING_DOMAIN,
    payload: royaltyReleasePhasePlanSigningPayload(core),
  });
}

export function royaltyReleasePhasePlanSigningMessage(core) {
  return eip191AuthorizationSigningMessage({
    prefix: ROYALTY_RELEASE_PHASE_PLAN_SIGNING_MESSAGE_PREFIX,
    digest: royaltyReleasePhasePlanSigningPayloadSha256(core),
  });
}

function normalizeExternalSignatures(value, expectedPlanSha256) {
  const parsed = exactRecord(value, ["plan_sha256", "schema", "signatures"], "external signatures");
  exactString(
    parsed.schema,
    ROYALTY_RELEASE_PHASE_PLAN_SIGNATURES_SCHEMA,
    "external-signatures schema",
  );
  if (parsed.plan_sha256 !== expectedPlanSha256) {
    fail("external signatures bind a different royalty phase plan");
  }
  if (!Array.isArray(parsed.signatures) || parsed.signatures.length !== 2) {
    fail("royalty phase-plan review requires exactly two signatures");
  }
  return parsed.signatures.map((entry, index) => {
    const signature = exactRecord(
      entry,
      ["address", "controller_id", "signature"],
      `external signature ${index}`,
    );
    return {
      address: nonzeroAddress(signature.address, `signature ${index} address`),
      controller_id: signature.controller_id,
      signature: signature.signature,
    };
  });
}

export function normalizeRoyaltyReleasePrescriptiveAuthority(value, {
  deploymentIntentSha256,
  freshDeployment,
} = {}) {
  const parsed = exactRecord(value, [
    "authority",
    "deployment_intent_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "release_sha",
    "royalty_settlement_release_binding_template",
    "schema",
  ], "Royalty prescriptive authority");
  exactString(
    parsed.schema,
    ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA,
    "Royalty prescriptive-authority schema",
  );
  if (!SHA40.test(parsed.release_sha) || /^0+$/.test(parsed.release_sha)) {
    fail("Royalty prescriptive-authority release SHA is invalid");
  }
  const normalized = {
    schema: ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_SCHEMA,
    release_sha: parsed.release_sha,
    deployment_intent_sha256: nonzeroSha256(
      parsed.deployment_intent_sha256,
      "Royalty prescription deployment-intent digest",
    ),
    fresh_contract_deployment_receipt_sha256: nonzeroSha256(
      parsed.fresh_contract_deployment_receipt_sha256,
      "Royalty prescription fresh-deployment receipt digest",
    ),
    authority: normalizeAuthority(parsed.authority),
    royalty_settlement_release_binding_template:
      normalizeRoyaltySettlementReleaseBindingTemplate(
        parsed.royalty_settlement_release_binding_template,
      ),
  };
  const template = normalized.royalty_settlement_release_binding_template;
  const authority = normalized.authority;
  if (template.schema !== ROYALTY_SETTLEMENT_RELEASE_BINDING_TEMPLATE_SCHEMA
    || template.chain_id !== CHAIN_ID
    || template.distributor_address !== authority.distributor_address
    || template.distributor_runtime_code_hash
      !== authority.distributor_runtime_code_hash
    || String(template.authority_nonce) !== authority.authority_nonce
    || template.settlement_verifier_address !== authority.settlement_verifier
    || template.royalty_qvl_verifier_address !== authority.qvl_verifier
    || template.execution_policy_anchor_address !== authority.anchor_address
    || template.anchor_writer_release_commitment
      !== authority.anchor_writer_release_commitment
    || template.release_policy_commitment !== authority.release_policy_commitment
    || template.deployment_intent_sha256
      !== normalized.deployment_intent_sha256) {
    fail("Royalty settlement template differs from the prescriptive contract, runtime, roles, policy, or deployment intent");
  }
  if (deploymentIntentSha256 !== undefined
    && normalized.deployment_intent_sha256 !== deploymentIntentSha256) {
    fail("Royalty prescription differs from the deployment-intent digest");
  }
  if (freshDeployment !== undefined
    && (normalized.release_sha !== freshDeployment.releaseSha
      || normalized.fresh_contract_deployment_receipt_sha256
        !== freshDeployment.freshContractDeploymentReceiptSha256
      || authority.distributor_address
        !== freshDeployment.royaltyDistributor.address
      || authority.distributor_runtime_code_hash
        !== freshDeployment.royaltyDistributor.runtimeCodeHash
      || authority.anchor_address !== freshDeployment.executionPolicyAnchor.address
      || authority.anchor_runtime_code_hash
        !== freshDeployment.executionPolicyAnchor.runtimeCodeHash
      || authority.owner !== freshDeployment.operatorAddress)) {
    fail("Royalty prescription differs from the fresh deployment contract, runtime, owner, or release");
  }
  return deepFreeze(normalized);
}

export function royaltyReleasePrescriptiveAuthoritySha256(value, options = {}) {
  return domainSha256(
    ROYALTY_RELEASE_PRESCRIPTIVE_AUTHORITY_DOMAIN,
    normalizeRoyaltyReleasePrescriptiveAuthority(value, options),
  );
}

export function normalizeCurrentFinalReleaseAuthorityV4(value) {
  let normalized;
  try {
    normalized = normalizeFinalReleaseAuthorityCore(value);
  } catch (error) {
    fail(`current final-authority v4 is invalid: ${error?.message || error}`);
  }
  if (normalized.schema !== REQUIRED_FINAL_RELEASE_AUTHORITY_V4_SCHEMA) {
    fail("Royalty phase plans require current final-authority v4");
  }
  if (normalized.requested_features?.collaboration !== true
    || normalized.requested_features?.collaboration_execution !== true
    || normalized.requested_features?.royalty_settlement !== true
    || normalized.collaboration_execution?.enabled !== true) {
    fail("current final-authority v4 does not enable the complete Collaboration Royalty path");
  }
  return normalized;
}

function phaseAuthorityFromFinalRelease(finalReleaseAuthorityV4) {
  const royalty = finalReleaseAuthorityV4.royalty_release_authority;
  const distributor = finalReleaseAuthorityV4.contracts.royalty_distributor;
  const anchor = finalReleaseAuthorityV4.execution_policy.rollback_anchor_target;
  return normalizeAuthority({
    distributor_address: distributor.address,
    distributor_runtime_code_hash: distributor.runtime_code_hash,
    owner: royalty.owner,
    settlement_verifier: royalty.settlement_verifier,
    qvl_verifier: royalty.qvl_verifier,
    anchor_address: royalty.execution_policy_anchor,
    anchor_runtime_code_hash: anchor.runtime_code_hash,
    anchor_writer: royalty.anchor_writer,
    anchor_writer_release_commitment:
      royalty.anchor_writer_release_commitment,
    release_policy_commitment: royalty.release_policy_commitment,
    authority_nonce: String(royalty.authority_nonce),
  });
}

export function projectRoyaltySettlementReleaseBinding(
  finalReleaseAuthorityV4,
) {
  const normalized = normalizeCurrentFinalReleaseAuthorityV4(
    finalReleaseAuthorityV4,
  );
  return deepFreeze({
    schema: REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA,
    final_release_authority_v4_sha256:
      `sha256:${finalReleaseAuthorityCoreDigest(normalized)}`,
    release_sha: normalized.release_sha,
    deployment_intent_sha256: normalized.deployment_intent_sha256,
    royalty_release_active_state_sha256:
      normalized.royalty_release_active_state_sha256,
    royalty_release_history_sha256:
      normalized.royalty_release_history_sha256,
    royalty_release_history_receipt_sha256:
      normalized.royalty_release_history_receipt_sha256,
    royalty_release_authority: normalized.royalty_release_authority,
    royalty_settlement_release_binding_template:
      normalized.royalty_settlement_release_binding_template,
  });
}

export function normalizeRoyaltySettlementReleaseBinding(
  value,
  { finalReleaseAuthorityV4 } = {},
) {
  const normalizedFinal = normalizeCurrentFinalReleaseAuthorityV4(
    finalReleaseAuthorityV4,
  );
  const parsed = exactRecord(value, [
    "deployment_intent_sha256",
    "final_release_authority_v4_sha256",
    "release_sha",
    "royalty_release_active_state_sha256",
    "royalty_release_authority",
    "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256",
    "royalty_settlement_release_binding_template",
    "schema",
  ], "Royalty settlement release binding");
  exactString(
    parsed.schema,
    REQUIRED_ROYALTY_SETTLEMENT_RELEASE_BINDING_SCHEMA,
    "Royalty settlement release-binding schema",
  );
  if (!SHA40.test(parsed.release_sha) || /^0+$/.test(parsed.release_sha)) {
    fail("Royalty settlement release-binding release SHA is invalid");
  }
  for (const [field, label] of [
    ["deployment_intent_sha256", "deployment-intent digest"],
    ["final_release_authority_v4_sha256", "final-authority v4 digest"],
    ["royalty_release_active_state_sha256", "Royalty active-state digest"],
    ["royalty_release_history_sha256", "Royalty history digest"],
    ["royalty_release_history_receipt_sha256", "Royalty H receipt digest"],
  ]) {
    nonzeroSha256(parsed[field], label);
  }
  const expected = projectRoyaltySettlementReleaseBinding(normalizedFinal);
  if (canonicalText(parsed) !== canonicalText(expected)) {
    fail("Royalty settlement release binding differs from current final-authority v4 or H");
  }
  return expected;
}

export function royaltySettlementReleaseBindingSha256(
  value,
  { finalReleaseAuthorityV4 } = {},
) {
  return domainSha256(
    ROYALTY_SETTLEMENT_RELEASE_BINDING_DOMAIN,
    normalizeRoyaltySettlementReleaseBinding(value, {
      finalReleaseAuthorityV4,
    }),
  );
}

export function reconcileRoyaltySettlementReleaseBinding({
  finalReleaseAuthorityV4,
  royaltySettlementReleaseBinding,
  royaltyReleaseHistoryReceipt,
  royaltyReleasePrescriptiveAuthority,
}) {
  const finalAuthority = normalizeCurrentFinalReleaseAuthorityV4(
    finalReleaseAuthorityV4,
  );
  const prescription = normalizeRoyaltyReleasePrescriptiveAuthority(
    royaltyReleasePrescriptiveAuthority,
  );
  const binding = normalizeRoyaltySettlementReleaseBinding(
    royaltySettlementReleaseBinding,
    { finalReleaseAuthorityV4: finalAuthority },
  );
  let historyReceipt;
  try {
    historyReceipt = normalizeRoyaltyReleaseHistoryReceipt(
      royaltyReleaseHistoryReceipt,
    );
  } catch (error) {
    fail(`Royalty H receipt is invalid: ${error?.message || error}`);
  }
  const historyReceiptSha256 = royaltyReleaseHistoryReceiptSha256(
    historyReceipt,
  );
  const finalPhaseAuthority = phaseAuthorityFromFinalRelease(finalAuthority);
  const receiptDistributor = historyReceipt.contracts.find(
    (entry) => entry.contract_key === "royalty_distributor",
  );
  const receiptAnchor = historyReceipt.contracts.find(
    (entry) => entry.contract_key === "execution_policy_anchor",
  );
  if (finalAuthority.release_sha !== prescription.release_sha
    || finalAuthority.deployment_intent_sha256
      !== prescription.deployment_intent_sha256
    || canonicalText(finalPhaseAuthority) !== canonicalText(prescription.authority)
    || canonicalText(finalAuthority.royalty_settlement_release_binding_template)
      !== canonicalText(prescription.royalty_settlement_release_binding_template)
    || finalAuthority.royalty_release_history_receipt_sha256
      !== historyReceiptSha256
    || finalAuthority.royalty_release_history_sha256
      !== historyReceipt.royalty_release_history_sha256
    || canonicalText(finalAuthority.royalty_release_authority)
      !== canonicalText(historyReceipt.royalty_release_authority)
    || canonicalText(finalAuthority.royalty_release_active_state)
      !== canonicalText(historyReceipt.royalty_release_active_state)
    || receiptDistributor?.address !== finalPhaseAuthority.distributor_address
    || receiptDistributor?.runtime_code_hash
      !== finalPhaseAuthority.distributor_runtime_code_hash
    || receiptAnchor?.address !== finalPhaseAuthority.anchor_address
    || receiptAnchor?.runtime_code_hash
      !== finalPhaseAuthority.anchor_runtime_code_hash) {
    fail("post-ceremony final-authority v4, H, fresh prescription, contracts, runtimes, roles, or active state disagree");
  }
  return normalizeRoyaltySettlementReleaseReconciliationReceipt({
    schema: ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_RECEIPT_SCHEMA,
    status: ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_STATUS,
    release_sha: finalAuthority.release_sha,
    deployment_intent_sha256: finalAuthority.deployment_intent_sha256,
    royalty_release_prescriptive_authority_sha256:
      royaltyReleasePrescriptiveAuthoritySha256(prescription),
    final_release_authority_v4_sha256:
      `sha256:${finalReleaseAuthorityCoreDigest(finalAuthority)}`,
    royalty_release_history_receipt_sha256: historyReceiptSha256,
    royalty_release_history_sha256:
      historyReceipt.royalty_release_history_sha256,
    royalty_settlement_release_binding_sha256:
      royaltySettlementReleaseBindingSha256(binding, {
        finalReleaseAuthorityV4: finalAuthority,
      }),
    truth_status:
      ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_TRUTH_STATUS,
  });
}

export function normalizeRoyaltySettlementReleaseReconciliationReceipt(value) {
  const parsed = exactRecord(value, [
    "deployment_intent_sha256",
    "final_release_authority_v4_sha256",
    "release_sha",
    "royalty_release_history_receipt_sha256",
    "royalty_release_history_sha256",
    "royalty_release_prescriptive_authority_sha256",
    "royalty_settlement_release_binding_sha256",
    "schema",
    "status",
    "truth_status",
  ], "Royalty settlement release reconciliation receipt");
  exactString(
    parsed.schema,
    ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_RECEIPT_SCHEMA,
    "Royalty settlement reconciliation schema",
  );
  exactString(
    parsed.status,
    ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_STATUS,
    "Royalty settlement reconciliation status",
  );
  exactString(
    parsed.truth_status,
    ROYALTY_SETTLEMENT_RELEASE_RECONCILIATION_TRUTH_STATUS,
    "Royalty settlement reconciliation truth status",
  );
  if (!SHA40.test(parsed.release_sha) || /^0+$/.test(parsed.release_sha)) {
    fail("Royalty settlement reconciliation release SHA is invalid");
  }
  return deepFreeze({
    schema: parsed.schema,
    status: parsed.status,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    deployment_intent_sha256: nonzeroSha256(
      parsed.deployment_intent_sha256,
      "reconciliation deployment-intent digest",
    ),
    royalty_release_prescriptive_authority_sha256: nonzeroSha256(
      parsed.royalty_release_prescriptive_authority_sha256,
      "reconciliation prescription digest",
    ),
    final_release_authority_v4_sha256: nonzeroSha256(
      parsed.final_release_authority_v4_sha256,
      "reconciliation final-authority v4 digest",
    ),
    royalty_release_history_receipt_sha256: nonzeroSha256(
      parsed.royalty_release_history_receipt_sha256,
      "reconciliation H receipt digest",
    ),
    royalty_release_history_sha256: nonzeroSha256(
      parsed.royalty_release_history_sha256,
      "reconciliation history digest",
    ),
    royalty_settlement_release_binding_sha256: nonzeroSha256(
      parsed.royalty_settlement_release_binding_sha256,
      "reconciliation settlement binding digest",
    ),
  });
}

export function createRoyaltyReleaseReviewerContext({
  deploymentIntent,
  freshDeploymentManifest,
  royaltyReleasePrescriptiveAuthority,
  tinkerAccountBindingCeremonyReceiptSha256,
  reviewerGenesis,
  reviewerGenesisAcceptance,
  reviewerCurrentStatus,
  reviewerStatusHistory,
  checkedAtMs,
}) {
  if (!Number.isFinite(checkedAtMs) || checkedAtMs < 1) {
    fail("royalty reviewer context requires wrapper-derived checkedAtMs");
  }
  if (Math.abs(Date.now() - checkedAtMs) > MAX_CONTEXT_WALL_CLOCK_SKEW_MS) {
    fail("royalty reviewer context checkedAtMs is stale or future-dated");
  }
  const deploymentIntentSnapshot = canonicalSnapshot(deploymentIntent);
  const reviewerGenesisSnapshot = canonicalSnapshot(reviewerGenesis);
  const unbrandedReviewerLineage = normalizeStageBSuccessorReviewerAuthority({
    reviewerGenesis: reviewerGenesisSnapshot,
    reviewerGenesisAcceptance: canonicalSnapshot(reviewerGenesisAcceptance),
    reviewerStatusHistory: canonicalSnapshot(reviewerStatusHistory),
    deploymentIntent: deploymentIntentSnapshot,
    checkedAtMs,
    enforceFreshness: true,
  });
  const reviewerLineage = deepFreeze({
    ...unbrandedReviewerLineage,
    authority: normalizeExpectedReviewerAuthority(
      unbrandedReviewerLineage.authority,
      {
        expectedReviewerRootHash:
          unbrandedReviewerLineage.authority.reviewer_root_hash,
        expectedReviewerSetSha256:
          unbrandedReviewerLineage.authority.reviewer_set_sha256,
      },
    ),
  });
  if (canonicalText(reviewerCurrentStatus) !== canonicalText(reviewerLineage.currentStatus)) {
    fail("current reviewer-status artifact is not the authenticated lineage head");
  }
  if (reviewerGenesisSnapshot.reviewer_controllers.some(
    (reviewer) => reviewer.controller_id
      === deploymentIntentSnapshot.deploymentControl.controllerId,
  )) {
    fail("royalty release reviewers must not reuse the deployment controller identity");
  }
  const freshDeployment = deriveRoyaltyFreshDeploymentContext({
    deploymentIntent: deploymentIntentSnapshot,
    reviewerLineage,
    freshDeploymentManifest,
    tinkerAccountBindingCeremonyReceiptSha256,
  });
  const expectedDeploymentIntentSha256 = canonicalArtifactSha256(
    deploymentIntentSnapshot,
  );
  const prescription = normalizeRoyaltyReleasePrescriptiveAuthority(
    canonicalSnapshot(royaltyReleasePrescriptiveAuthority),
    {
      deploymentIntentSha256: expectedDeploymentIntentSha256,
      freshDeployment,
    },
  );
  if (prescription.release_sha !== deploymentIntentSnapshot.release.releaseSha) {
    fail("Royalty prescription release differs from the deployment intent");
  }
  const prescriptionSha256 = royaltyReleasePrescriptiveAuthoritySha256(
    prescription,
    { deploymentIntentSha256: expectedDeploymentIntentSha256, freshDeployment },
  );
  const context = deepFreeze({
    checkedAtMs,
    deploymentIntent: deploymentIntentSnapshot,
    reviewerGenesis: reviewerGenesisSnapshot,
    reviewerLineage,
    freshDeployment,
    royaltyReleasePrescriptiveAuthority: prescription,
    royaltyReleasePrescriptiveAuthoritySha256: prescriptionSha256,
    phaseAuthority: prescription.authority,
  });
  AUTHENTICATED_REVIEWER_CONTEXTS.add(context);
  return context;
}

export function deriveRoyaltyFreshDeploymentContext({
  deploymentIntent,
  reviewerLineage,
  freshDeploymentManifest,
  tinkerAccountBindingCeremonyReceiptSha256,
}) {
  const deploymentIntentSha256 = canonicalArtifactSha256(deploymentIntent);
  const authorityPins = {
    expectedDeploymentIntentSha256: deploymentIntentSha256,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerLineage.acceptanceSha256,
    expectedTinkerAccountBindingCeremonyReceiptSha256: nonzeroSha256(
      tinkerAccountBindingCeremonyReceiptSha256,
      "Tinker account-binding ceremony receipt digest",
    ),
  };
  let receipt;
  try {
    receipt = projectFreshContractDeploymentReceipt(freshDeploymentManifest, {
      releaseSha: deploymentIntent.release.releaseSha,
      ...authorityPins,
    });
  } catch (error) {
    fail(`fresh contract deployment receipt reconstruction failed: ${error?.message || error}`);
  }
  if (receipt.operator_address !== deploymentIntent.deploymentControl.operatorAddress
    || receipt.release_sha !== deploymentIntent.release.releaseSha) {
    fail("fresh contract deployment receipt operator or release differs from deployment intent");
  }
  const royaltyDistributor = receipt.contracts.find(
    (entry) => entry.name === "RoyaltyDistributor",
  );
  const executionPolicyAnchor = receipt.contracts.find(
    (entry) => entry.name === "ExecutionPolicyAnchor",
  );
  if (!royaltyDistributor || !executionPolicyAnchor) {
    fail("fresh contract deployment receipt omits RoyaltyDistributor or ExecutionPolicyAnchor");
  }
  return deepFreeze({
    freshContractDeploymentReceiptSha256:
      `sha256:${freshContractDeploymentReceiptDigest(receipt, authorityPins)}`,
    royaltyDistributor: {
      address: royaltyDistributor.address,
      runtimeCodeHash: royaltyDistributor.runtime_code_hash,
    },
    executionPolicyAnchor: {
      address: executionPolicyAnchor.address,
      runtimeCodeHash: executionPolicyAnchor.runtime_code_hash,
    },
    operatorAddress: receipt.operator_address,
    releaseSha: receipt.release_sha,
  });
}

function assertReviewerContext(reviewerContext, checkedAtMs) {
  if (!reviewerContext || !AUTHENTICATED_REVIEWER_CONTEXTS.has(reviewerContext)) {
    fail("royalty phase-plan verification requires a re-derived reviewer context");
  }
  if (!Number.isFinite(checkedAtMs) || checkedAtMs < 1
    || checkedAtMs !== reviewerContext.checkedAtMs) {
    fail("royalty phase-plan verification requires the exact wrapper-derived checkedAtMs");
  }
  if (Math.abs(Date.now() - checkedAtMs) > MAX_CONTEXT_WALL_CLOCK_SKEW_MS) {
    fail("royalty reviewer context has expired against the process wall clock");
  }
  return reviewerContext;
}

function assertCoreReviewerLineage(core, reviewerContext) {
  const { deploymentIntent, reviewerLineage: lineage } = reviewerContext;
  if (core.deployment_intent_sha256 !== canonicalArtifactSha256(deploymentIntent)
    || core.release_sha !== deploymentIntent?.release?.releaseSha
    || core.royalty_release_prescriptive_authority_sha256
      !== reviewerContext.royaltyReleasePrescriptiveAuthoritySha256
    || canonicalText(core.authority)
      !== canonicalText(reviewerContext.phaseAuthority)
    || core.authority.owner !== deploymentIntent?.deploymentControl?.operatorAddress
    || core.fresh_contract_deployment_receipt_sha256
      !== reviewerContext.freshDeployment.freshContractDeploymentReceiptSha256
    || core.authority.distributor_address
      !== reviewerContext.freshDeployment.royaltyDistributor.address
    || core.authority.distributor_runtime_code_hash
      !== reviewerContext.freshDeployment.royaltyDistributor.runtimeCodeHash
    || core.authority.anchor_address
      !== reviewerContext.freshDeployment.executionPolicyAnchor.address
    || core.authority.anchor_runtime_code_hash
      !== reviewerContext.freshDeployment.executionPolicyAnchor.runtimeCodeHash
    || core.reviewer_authority_genesis_sha256 !== lineage.genesisSha256
    || core.reviewer_authority_genesis_acceptance_sha256 !== lineage.acceptanceSha256
    || core.reviewer_authority_current_status_epoch !== lineage.currentStatus.epoch
    || core.reviewer_authority_current_status_sha256 !== lineage.currentStatusSha256
    || core.reviewer_root_hash !== lineage.authority.reviewer_root_hash
    || core.reviewer_set_sha256 !== lineage.authority.reviewer_set_sha256) {
    fail("royalty phase-plan reviewer lineage differs from the deployment-rooted current authority");
  }
  const authorityAddresses = new Set([
    core.authority.distributor_address,
    core.authority.owner,
    core.authority.settlement_verifier,
    core.authority.qvl_verifier,
    core.authority.anchor_address,
    core.authority.anchor_writer,
  ]);
  const preauthorizedReviewerAddresses = new Set([
    ...reviewerContext.reviewerGenesis.reviewer_controllers
      .flatMap((controller) => controller.preauthorized_addresses),
    ...reviewerContext.reviewerGenesis.status_guardians
      .map((guardian) => guardian.address),
  ]);
  if (lineage.authority.approved_reviewers.some(
    (reviewer) => authorityAddresses.has(reviewer.address),
  ) || [...authorityAddresses].some((addressValue) =>
    preauthorizedReviewerAddresses.has(addressValue))) {
    fail("royalty release roles must not reuse a reviewer or status-guardian address");
  }
  if (reviewerContext.reviewerGenesis.reviewer_controllers.some(
    (reviewer) => reviewer.controller_id
      === deploymentIntent.deploymentControl.controllerId,
  )) {
    fail("royalty release reviewers must not reuse the deployment controller identity");
  }
  const expiresAtMs = Date.parse(core.expires_at);
  const reviewerExpiresAtMs = Date.parse(lineage.currentStatus.expires_at);
  if (!Number.isFinite(reviewerExpiresAtMs) || expiresAtMs > reviewerExpiresAtMs) {
    fail("royalty phase-plan outlives the authenticated reviewer authority");
  }
}

export function generateRoyaltyReleasePhasePlanCore({
  generationRequest,
  ledger,
  ledgerReplay,
  recoveryEvidence,
  reviewerContext,
  checkedAtMs,
}) {
  const context = assertReviewerContext(reviewerContext, checkedAtMs);
  const request = normalizeGenerationRequest(generationRequest);
  if (!isRecord(ledger) || !isRecord(ledger.contracts)
    || !isRecord(ledger.contracts.royaltyDistributor)
    || !Array.isArray(ledger.royaltyReleaseHistory ?? [])) {
    fail("phase-core generation requires the canonical working ceremony ledger");
  }
  const replay = normalizeLedgerReplayForGeneration(ledgerReplay, {
    reviewerContext: context,
    ledger,
  });
  const distributor = ledger.contracts.royaltyDistributor;
  if (distributor.address !== context.freshDeployment.royaltyDistributor.address
    || distributor.runtimeCodeHash
      !== context.freshDeployment.royaltyDistributor.runtimeCodeHash
    || distributor.owner !== context.phaseAuthority.owner
    || distributor.sourceCommit !== context.freshDeployment.releaseSha) {
    fail("working ledger RoyaltyDistributor drifts from the immutable fresh receipt");
  }
  const history = ledger.royaltyReleaseHistory.filter((entry) =>
    isRecord(entry)
      && entry.royaltyDistributorAddress === context.phaseAuthority.distributor_address);
  const latestReleasePhase = distributor.latestReleasePhase ?? 0;
  let phaseOnePrerequisite = null;
  if (request.phase === 1) {
    if (history.length !== 0 || latestReleasePhase !== 0) {
      fail("phase-one generation requires exact empty Royalty ledger history");
    }
  } else {
    if (history.length !== 1 || latestReleasePhase !== 1) {
      fail("phase-two generation requires exactly one recorded Royalty phase one");
    }
    phaseOnePrerequisite = phaseOnePrerequisiteFromLedger({
      record: history[0],
      replay,
    });
  }
  let phaseTwoRecovery = null;
  if (request.execution_mode === "recover_reverted_unpause") {
    if (recoveryEvidence === undefined) {
      fail("recovery phase-core generation requires finalized recovery evidence");
    }
    phaseTwoRecovery = recoveryPrerequisiteFromEvidence(
      recoveryEvidence,
      context.phaseAuthority,
    );
    if (BigInt(request.first_transaction_nonce)
      !== BigInt(phaseTwoRecovery.prior_unpause_nonce) + 1n) {
      fail("generation-request recovery nonce is not exactly one after the reverted attempt");
    }
  } else if (recoveryEvidence !== undefined) {
    fail("non-recovery phase-core generation rejects recovery evidence");
  }
  const actions = expectedActions(request.phase, request.execution_mode);
  const core = {
    schema: ROYALTY_RELEASE_PHASE_PLAN_CORE_SCHEMA,
    status: "proposed_for_review",
    release_sha: context.freshDeployment.releaseSha,
    chain_id: CHAIN_ID,
    phase: request.phase,
    execution_mode: request.execution_mode,
    phase_one_prerequisite: phaseOnePrerequisite,
    phase_two_recovery: phaseTwoRecovery,
    valid_after: request.valid_after,
    expires_at: request.expires_at,
    deployment_intent_sha256: canonicalArtifactSha256(context.deploymentIntent),
    fresh_contract_deployment_receipt_sha256:
      context.freshDeployment.freshContractDeploymentReceiptSha256,
    royalty_release_prescriptive_authority_sha256:
      context.royaltyReleasePrescriptiveAuthoritySha256,
    reviewer_authority_genesis_sha256: context.reviewerLineage.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      context.reviewerLineage.acceptanceSha256,
    reviewer_authority_current_status_epoch:
      context.reviewerLineage.currentStatus.epoch,
    reviewer_authority_current_status_sha256:
      context.reviewerLineage.currentStatusSha256,
    reviewer_root_hash: context.reviewerLineage.authority.reviewer_root_hash,
    reviewer_set_sha256: context.reviewerLineage.authority.reviewer_set_sha256,
    authority: context.phaseAuthority,
    transactions: actions.map((action, sequence) => ({
      sequence,
      action,
      signer_address: context.phaseAuthority.owner,
      nonce: (BigInt(request.first_transaction_nonce) + BigInt(sequence)).toString(10),
      to: context.phaseAuthority.distributor_address,
      value_wei: "0",
      calldata: royaltyReleaseActionCalldata(action, context.phaseAuthority),
      calldata_sha256: royaltyReleaseActionCalldataSha256(
        action,
        context.phaseAuthority,
      ),
    })),
  };
  const normalized = normalizeRoyaltyReleasePhasePlanCore(core, { checkedAtMs });
  assertCoreReviewerLineage(normalized, context);
  return deepFreeze(normalized);
}

export function attachRoyaltyReleasePhasePlan({
  core,
  externalSignatures,
  reviewerContext,
  checkedAtMs,
}) {
  const context = assertReviewerContext(reviewerContext, checkedAtMs);
  const normalizedCore = normalizeRoyaltyReleasePhasePlanCore(core, { checkedAtMs });
  assertCoreReviewerLineage(normalizedCore, context);
  const planSha256 = royaltyReleasePhasePlanSha256(normalizedCore);
  const signatures = normalizeExternalSignatures(externalSignatures, planSha256);
  const signingPayloadSha256 = royaltyReleasePhasePlanSigningPayloadSha256(normalizedCore);
  const verified = verifyPinnedTwoSignerAuthorization({
    signatures,
    message: royaltyReleasePhasePlanSigningMessage(normalizedCore),
    reviewerAuthority: context.reviewerLineage.authority,
  });
  assertReviewerContext(context, checkedAtMs);
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_SCHEMA,
    status: ROYALTY_RELEASE_PHASE_PLAN_STATUS,
    plan_sha256: planSha256,
    core: normalizedCore,
    review: {
      schema: ROYALTY_RELEASE_PHASE_PLAN_REVIEW_SCHEMA,
      signing_payload_sha256: signingPayloadSha256,
      signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
      signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
      signatures,
      verified_signers: verified.signers,
    },
  };
}

export function verifyRoyaltyReleasePhasePlan({
  plan,
  reviewerContext,
  checkedAtMs,
}) {
  const context = assertReviewerContext(reviewerContext, checkedAtMs);
  const parsed = exactRecord(
    plan,
    ["core", "plan_sha256", "review", "schema", "status"],
    "reviewed royalty phase plan",
  );
  exactString(parsed.schema, ROYALTY_RELEASE_PHASE_PLAN_SCHEMA, "reviewed plan schema");
  exactString(parsed.status, ROYALTY_RELEASE_PHASE_PLAN_STATUS, "reviewed plan status");
  const core = normalizeRoyaltyReleasePhasePlanCore(parsed.core, { checkedAtMs });
  assertCoreReviewerLineage(core, context);
  const planSha256 = royaltyReleasePhasePlanSha256(core);
  if (parsed.plan_sha256 !== planSha256) fail("reviewed plan digest is invalid");
  const review = exactRecord(parsed.review, [
    "schema",
    "signature_scheme",
    "signature_verifier",
    "signatures",
    "signing_payload_sha256",
    "verified_signers",
  ], "royalty phase-plan review");
  exactString(review.schema, ROYALTY_RELEASE_PHASE_PLAN_REVIEW_SCHEMA, "plan review schema");
  exactString(
    review.signature_scheme,
    PINNED_EIP191_SIGNATURE_SCHEME,
    "plan signature scheme",
  );
  if (canonicalText(review.signature_verifier)
    !== canonicalText(PINNED_CAST_SIGNATURE_VERIFIER)) {
    fail("plan signature verifier differs from the pinned cast authority");
  }
  const expectedPayloadSha256 = royaltyReleasePhasePlanSigningPayloadSha256(core);
  if (review.signing_payload_sha256 !== expectedPayloadSha256) {
    fail("plan signing-payload digest is invalid");
  }
  const verified = verifyPinnedTwoSignerAuthorization({
    signatures: review.signatures,
    message: royaltyReleasePhasePlanSigningMessage(core),
    reviewerAuthority: context.reviewerLineage.authority,
  });
  assertReviewerContext(context, checkedAtMs);
  if (canonicalText(review.verified_signers) !== canonicalText(verified.signers)) {
    fail("stored plan signer evidence is invalid");
  }
  return {
    schema: ROYALTY_RELEASE_PHASE_PLAN_VERIFICATION_RECEIPT_SCHEMA,
    status: "valid_current_two_reviewer_exact_royalty_phase_plan",
    plan_sha256: planSha256,
    release_sha: core.release_sha,
    chain_id: CHAIN_ID,
    phase: core.phase,
    execution_mode: core.execution_mode,
    valid_after: core.valid_after,
    expires_at: core.expires_at,
    deployment_intent_sha256: core.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      core.fresh_contract_deployment_receipt_sha256,
    royalty_release_prescriptive_authority_sha256:
      core.royalty_release_prescriptive_authority_sha256,
    reviewer_authority_current_status_epoch: core.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256: core.reviewer_authority_current_status_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      core.reviewer_authority_genesis_acceptance_sha256,
    reviewer_root_hash: core.reviewer_root_hash,
    reviewer_set_sha256: core.reviewer_set_sha256,
    authority: core.authority,
    phase_one_prerequisite: core.phase_one_prerequisite,
    phase_two_recovery: core.phase_two_recovery,
    transactions: core.transactions,
    signing_payload_sha256: expectedPayloadSha256,
    verified_signers: verified.signers,
    truth_status:
      "reviewer_signatures_and_exact_plan_validated_not_onchain_execution_finality_or_tdx_evidence",
  };
}

function readJsonFile(filePath, label) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be absolute`);
  }
  const canonical = fs.realpathSync.native(filePath);
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
    const afterOpen = fs.lstatSync(filePath);
    if (!opened.isFile() || opened.nlink !== 1 || opened.uid !== expectedUid
      || opened.dev !== before.dev || opened.ino !== before.ino
      || afterOpen.dev !== opened.dev || afterOpen.ino !== opened.ino
      || opened.size !== before.size || opened.mode !== before.mode) {
      fail(`${label} changed while it was opened`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) fail(`${label} changed or ended during its bounded read`);
      offset += count;
    }
    const finalFd = fs.fstatSync(fd);
    const finalPath = fs.lstatSync(filePath);
    if (finalFd.dev !== opened.dev || finalFd.ino !== opened.ino
      || finalPath.dev !== finalFd.dev || finalPath.ino !== finalFd.ino
      || finalFd.size !== opened.size || finalFd.mtimeMs !== opened.mtimeMs
      || finalFd.ctimeMs !== opened.ctimeMs) {
      fail(`${label} changed during its bounded read`);
    }
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail(`${label} is not JSON`);
    }
    if (canonicalText(value) !== bytes.toString("utf8")) {
      fail(`${label} must be recursively sorted canonical JSON with one final newline`);
    }
    return value;
  } finally {
    fs.closeSync(fd);
  }
}

function writeExclusiveJson(filePath, value) {
  if (!path.isAbsolute(filePath) || path.resolve(filePath) !== filePath
    || path.normalize(filePath) !== filePath || fs.existsSync(filePath)) {
    fail("output path must be absolute, canonical, and absent");
  }
  const parent = path.dirname(filePath);
  if (fs.realpathSync.native(parent) !== parent) fail("output parent must be canonical");
  const parentStat = fs.lstatSync(parent);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : parentStat.uid;
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()
    || parentStat.uid !== expectedUid || (parentStat.mode & 0o022) !== 0) {
    fail("output parent must be operator-owned and not group/other writable");
  }
  const fd = fs.openSync(filePath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
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

function parseArgs(argv) {
  if (argv.length < 1) {
    fail("expected generate-core, payload, attach, verify, or reconcile command");
  }
  const command = argv[0];
  if (!["generate-core", "payload", "attach", "verify", "reconcile"].includes(command)) {
    fail("unsupported command");
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
  const required = command === "reconcile" ? [
    "--final-release-authority-v4",
    "--royalty-release-history-receipt",
    "--royalty-release-prescription",
    "--royalty-settlement-release-binding",
  ] : [
    "--deployment-intent",
    "--fresh-deployment-manifest",
    "--reviewer-genesis",
    "--reviewer-genesis-acceptance",
    "--reviewer-current-status",
    "--reviewer-status-history",
    "--royalty-release-prescription",
    "--tinker-account-binding-ceremony-receipt-sha256",
  ];
  const allowed = new Set(required);
  if (command === "generate-core") {
    required.push(
      "--generation-request",
      "--ledger",
      "--ledger-replay",
      "--out",
    );
    for (const key of required) allowed.add(key);
    allowed.add("--recovery-evidence");
  } else if (command !== "reconcile") {
    required.push(command === "verify" ? "--plan" : "--core");
    if (command === "attach") required.push("--signatures", "--out");
    for (const key of required) allowed.add(key);
  }
  if (command === "reconcile") {
    for (const key of required) allowed.add(key);
  }
  if (required.some((key) => !values.has(key))
    || [...values.keys()].some((key) => !allowed.has(key))) {
    fail(`unexpected arguments for ${command}`);
  }
  return { command, values };
}

function loadReviewerContext(values, checkedAtMs) {
  const deploymentIntent = readJsonFile(values.get("--deployment-intent"), "deployment intent");
  const freshDeploymentManifest = readJsonFile(
    values.get("--fresh-deployment-manifest"),
    "fresh deployment manifest",
  );
  const royaltyReleasePrescriptiveAuthority = readJsonFile(
    values.get("--royalty-release-prescription"),
    "Royalty release prescriptive authority",
  );
  const reviewerGenesis = readJsonFile(values.get("--reviewer-genesis"), "reviewer genesis");
  const reviewerGenesisAcceptance = readJsonFile(
    values.get("--reviewer-genesis-acceptance"),
    "reviewer genesis acceptance",
  );
  const reviewerCurrentStatus = readJsonFile(
    values.get("--reviewer-current-status"),
    "reviewer current status",
  );
  const reviewerStatusHistory = readJsonFile(
    values.get("--reviewer-status-history"),
    "reviewer status history",
  );
  const reviewerContext = createRoyaltyReleaseReviewerContext({
    freshDeploymentManifest,
    royaltyReleasePrescriptiveAuthority,
    tinkerAccountBindingCeremonyReceiptSha256:
      values.get("--tinker-account-binding-ceremony-receipt-sha256"),
    reviewerGenesis,
    reviewerGenesisAcceptance,
    reviewerCurrentStatus,
    reviewerStatusHistory,
    deploymentIntent,
    checkedAtMs,
  });
  return reviewerContext;
}

async function main(argv) {
  const { command, values } = parseArgs(argv);
  if (command === "reconcile") {
    const receipt = reconcileRoyaltySettlementReleaseBinding({
      finalReleaseAuthorityV4: readJsonFile(
        values.get("--final-release-authority-v4"),
        "final release authority v4",
      ),
      royaltyReleaseHistoryReceipt: readJsonFile(
        values.get("--royalty-release-history-receipt"),
        "Royalty release history receipt",
      ),
      royaltyReleasePrescriptiveAuthority: readJsonFile(
        values.get("--royalty-release-prescription"),
        "Royalty release prescriptive authority",
      ),
      royaltySettlementReleaseBinding: readJsonFile(
        values.get("--royalty-settlement-release-binding"),
        "Royalty settlement release binding",
      ),
    });
    process.stdout.write(`${JSON.stringify(receipt, null, 2)}\n`);
    return;
  }
  const checkedAtMs = Date.now();
  const reviewerContext = loadReviewerContext(values, checkedAtMs);
  if (command === "generate-core") {
    const generated = generateRoyaltyReleasePhasePlanCore({
      generationRequest: readJsonFile(
        values.get("--generation-request"),
        "Royalty phase-plan generation request",
      ),
      ledger: readJsonFile(values.get("--ledger"), "working release ceremony ledger"),
      ledgerReplay: readJsonFile(
        values.get("--ledger-replay"),
        "release ceremony ledger replay",
      ),
      recoveryEvidence: values.has("--recovery-evidence")
        ? readJsonFile(
          values.get("--recovery-evidence"),
          "Royalty unpause recovery evidence",
        )
        : undefined,
      reviewerContext,
      checkedAtMs,
    });
    writeExclusiveJson(values.get("--out"), generated);
    process.stdout.write(`${JSON.stringify({
      status: "phase_plan_core_written_for_two_reviewer_review",
      plan_sha256: royaltyReleasePhasePlanSha256(generated),
      signing_payload_sha256: royaltyReleasePhasePlanSigningPayloadSha256(generated),
      output_path: values.get("--out"),
      truth_status:
        "canonical_unsigned_core_only_not_reviewer_authorization_chain_execution_or_finality",
    }, null, 2)}\n`);
    return;
  }
  if (command === "payload") {
    const core = readJsonFile(values.get("--core"), "royalty phase-plan core");
    const normalized = normalizeRoyaltyReleasePhasePlanCore(core, { checkedAtMs });
    assertCoreReviewerLineage(normalized, reviewerContext);
    process.stdout.write(`${JSON.stringify({
      plan_sha256: royaltyReleasePhasePlanSha256(normalized),
      signing_payload: royaltyReleasePhasePlanSigningPayload(normalized),
      signing_payload_sha256: royaltyReleasePhasePlanSigningPayloadSha256(normalized),
      eip191_message: royaltyReleasePhasePlanSigningMessage(normalized),
      status: "ready_for_two_current_reviewer_signatures",
    }, null, 2)}\n`);
    return;
  }
  if (command === "attach") {
    const core = readJsonFile(values.get("--core"), "royalty phase-plan core");
    const externalSignatures = readJsonFile(values.get("--signatures"), "external signatures");
    const reviewed = attachRoyaltyReleasePhasePlan({
      core,
      externalSignatures,
      reviewerContext,
      checkedAtMs,
    });
    writeExclusiveJson(values.get("--out"), reviewed);
    process.stdout.write(`${JSON.stringify({
      status: "reviewed_plan_written",
      plan_sha256: reviewed.plan_sha256,
      output_path: values.get("--out"),
    }, null, 2)}\n`);
    return;
  }
  const plan = readJsonFile(values.get("--plan"), "reviewed royalty phase plan");
  process.stdout.write(`${JSON.stringify(verifyRoyaltyReleasePhasePlan({
    plan,
    reviewerContext,
    checkedAtMs,
  }), null, 2)}\n`);
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
