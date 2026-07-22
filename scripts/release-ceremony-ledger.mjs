#!/usr/bin/env node

import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  freshContractDeploymentReceiptDigest,
  projectFreshContractDeploymentReceipt,
} from "./cvm-launch-intent-core.mjs";
import {
  RELEASE_CEREMONY_LOCK_PROTOCOL,
  RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA,
  RELEASE_CEREMONY_WRITERS,
  inspectReleaseCeremonyLock,
} from "./release-ceremony-lock.mjs";
import {
  durablyPublishJson,
  durablyRemoveJson,
} from "./durable-json-write.mjs";

export const RELEASE_CEREMONY_LEDGER_PROTOCOL =
  "dnai.release-ceremony-ledger.v1";
export const RELEASE_CEREMONY_LEDGER_INITIALIZATION_RECEIPT_SCHEMA =
  "dnai.release-ceremony-ledger-initialization.v1";
export const RELEASE_CEREMONY_LEDGER_REVISION_RECEIPT_SCHEMA =
  "dnai.release-ceremony-ledger-revision.v1";
export const RELEASE_CEREMONY_LEDGER_PENDING_JOURNAL_SCHEMA =
  "dnai.release-ceremony-ledger-pending.v1";
export const RELEASE_CEREMONY_LEDGER_RECOVERY_RECEIPT_SCHEMA =
  "dnai.release-ceremony-ledger-recovery.v1";
export const RELEASE_CEREMONY_LEDGER_FINALIZATION_RECEIPT_SCHEMA =
  "dnai.release-ceremony-ledger-finalization.v1";

// Short aliases are exported deliberately: callers should never duplicate a
// schema literal merely because the artifact happens to be a receipt.
export const RELEASE_CEREMONY_LEDGER_INITIALIZATION_SCHEMA =
  RELEASE_CEREMONY_LEDGER_INITIALIZATION_RECEIPT_SCHEMA;
export const RELEASE_CEREMONY_LEDGER_REVISION_SCHEMA =
  RELEASE_CEREMONY_LEDGER_REVISION_RECEIPT_SCHEMA;
export const RELEASE_CEREMONY_LEDGER_PENDING_SCHEMA =
  RELEASE_CEREMONY_LEDGER_PENDING_JOURNAL_SCHEMA;
export const RELEASE_CEREMONY_LEDGER_RECOVERY_SCHEMA =
  RELEASE_CEREMONY_LEDGER_RECOVERY_RECEIPT_SCHEMA;
export const RELEASE_CEREMONY_LEDGER_FINALIZATION_SCHEMA =
  RELEASE_CEREMONY_LEDGER_FINALIZATION_RECEIPT_SCHEMA;

export const RELEASE_CEREMONY_LEDGER_ACTIVE_MODE = 0o600;
export const RELEASE_CEREMONY_LEDGER_FROZEN_MODE = 0o444;
export const RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE = 0o444;
export const RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE = 0o700;
export const RELEASE_CEREMONY_LEDGER_MAX_BYTES = 2 * 1024 * 1024;
export const RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024;
export const RELEASE_CEREMONY_LEDGER_MAX_REVISION = 999_999_999_999;
export const RELEASE_CEREMONY_LEDGER_FAULT_POINTS = Object.freeze([
  "after-pending",
  "after-ledger-replace",
  "after-revision-receipt",
  "after-finalization-receipt",
  "before-recovery-receipt-publish",
  "after-recovery-receipt",
  "after-staging-cleanup",
]);
export const RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS = Object.freeze(
  RELEASE_CEREMONY_WRITERS.filter((writerId) => ![
    "ceremony_ledger_initialization",
    "ceremony_ledger_finalization",
    "ceremony_ledger_recovery",
  ].includes(writerId)),
);

export const RELEASE_CEREMONY_LEDGER_GENESIS_DOMAIN =
  "dnai-wikigen/release-ceremony-ledger/genesis/v1\0";
export const RELEASE_CEREMONY_LEDGER_REVISION_COMMITMENT_DOMAIN =
  "dnai-wikigen/release-ceremony-ledger/revision-commitment/v1\0";
export const RELEASE_CEREMONY_LEDGER_REVISION_CHAIN_DOMAIN =
  "dnai-wikigen/release-ceremony-ledger/revision-chain/v1\0";
export const RELEASE_CEREMONY_LEDGER_GLOBAL_RECONCILIATION_SCHEMA =
  "dnai.release-ceremony-ledger-global-reconciliation.v1";
export const RELEASE_CEREMONY_LEDGER_GLOBAL_RECONCILIATION_DOMAIN =
  "dnai-wikigen/release-ceremony-ledger/global-reconciliation/v1\0";

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const TOKEN = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const MAX_JSON_DEPTH = 128;
const MAX_JSON_NODES = 200_000;
const REVISION_FILE = /^([0-9]{12})\.json$/;

function fail(message) {
  throw new Error(`release ceremony ledger: ${message}`);
}

function assertSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a lowercase sha256: digest`);
  }
  return value;
}

function assertNonzeroSha256(value, label) {
  assertSha256(value, label);
  if (value === `sha256:${"0".repeat(64)}`) {
    fail(`${label} must not be the all-zero placeholder`);
  }
  return value;
}

function assertReleaseSha(value, label = "release SHA") {
  if (typeof value !== "string" || !SHA40.test(value)) {
    fail(`${label} must be lowercase 40-hex`);
  }
  return value;
}

function assertAbsolutePath(value, label) {
  if (typeof value !== "string"
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value) {
    fail(`${label} must be a lexically canonical absolute path`);
  }
  return value;
}

function exactRecord(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function assertSafeCount(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    fail(`${label} must be a bounded non-negative safe integer`);
  }
  return value;
}

function assertTimestamp(value, label) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
    || !Number.isFinite(Date.parse(value))
    || new Date(Date.parse(value)).toISOString() !== value) {
    fail(`${label} must be canonical millisecond UTC`);
  }
  return value;
}

function timestamp(now, label) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    fail(`${label} must be a valid Date`);
  }
  return now.toISOString();
}

function validateJsonTree(value) {
  let nodes = 0;
  const visit = (current, depth) => {
    nodes += 1;
    if (nodes > MAX_JSON_NODES) fail("JSON value exceeds the bounded node count");
    if (depth > MAX_JSON_DEPTH) fail("JSON value exceeds the bounded nesting depth");
    if (current === null || typeof current === "string" || typeof current === "boolean") {
      return;
    }
    if (typeof current === "number") {
      if (!Number.isFinite(current) || Object.is(current, -0)) {
        fail("JSON numbers must be finite and must not be negative zero");
      }
      return;
    }
    if (Array.isArray(current)) {
      if (Object.keys(current).length !== current.length) {
        fail("JSON arrays must not contain holes or named properties");
      }
      for (const item of current) visit(item, depth + 1);
      return;
    }
    if (!current || typeof current !== "object") {
      fail("value contains a non-JSON type");
    }
    const prototype = Object.getPrototypeOf(current);
    if (prototype !== Object.prototype && prototype !== null) {
      fail("JSON objects must have a plain prototype");
    }
    for (const key of Object.keys(current)) {
      if (typeof key !== "string") fail("JSON object keys must be strings");
      visit(current[key], depth + 1);
    }
  };
  visit(value, 0);
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

export function canonicalReleaseCeremonyLedgerJsonText(value) {
  validateJsonTree(value);
  const text = `${JSON.stringify(sortedObject(value), null, 2)}\n`;
  if (Buffer.byteLength(text, "utf8") > RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES) {
    fail("canonical JSON exceeds the bounded evidence size");
  }
  return text;
}

export const canonicalReleaseCeremonyLedgerText =
  canonicalReleaseCeremonyLedgerJsonText;

export function releaseCeremonyLedgerRawSha256(bytes) {
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function canonicalDigest(value, canonicalizer = canonicalReleaseCeremonyLedgerJsonText) {
  return releaseCeremonyLedgerRawSha256(Buffer.from(canonicalizer(value), "utf8"));
}

function parseCanonicalText(text, label, maxBytes = RELEASE_CEREMONY_LEDGER_MAX_BYTES) {
  if (typeof text !== "string") fail(`${label} must be UTF-8 JSON text`);
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length < 2 || bytes.length > maxBytes) {
    fail(`${label} must be between 2 and ${maxBytes} bytes`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    fail(`${label} is not JSON: ${error.message}`);
  }
  if (canonicalReleaseCeremonyLedgerJsonText(value) !== text) {
    fail(`${label} must be recursively sorted, two-space canonical JSON with one trailing newline`);
  }
  return { bytes, text, value };
}

function sha256Domain(domain, ...parts) {
  const hash = createHash("sha256").update(domain, "utf8");
  for (const part of parts) hash.update(part, "utf8");
  return `sha256:${hash.digest("hex")}`;
}

export function releaseCeremonyLedgerGenesisChainSha256(initializationReceiptSha256) {
  assertSha256(initializationReceiptSha256, "initialization receipt digest");
  return sha256Domain(
    RELEASE_CEREMONY_LEDGER_GENESIS_DOMAIN,
    initializationReceiptSha256,
  );
}

function normalizeLockBinding(value, label = "lock binding") {
  const lock = exactRecord(value, ["owner_sha256", "path", "protocol"], label);
  if (lock.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL) {
    fail(`${label} protocol mismatch`);
  }
  assertAbsolutePath(lock.path, `${label} path`);
  assertSha256(lock.owner_sha256, `${label} owner digest`);
  return sortedObject(lock);
}

function normalizeFileBinding(value, label, expectedMode) {
  const binding = exactRecord(value, ["bytes", "mode", "path", "sha256"], label);
  assertAbsolutePath(binding.path, `${label} path`);
  assertSha256(binding.sha256, `${label} digest`);
  assertSafeCount(binding.bytes, `${label} bytes`, {
    minimum: 2,
    maximum: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
  if (binding.mode !== expectedMode) fail(`${label} mode must be ${expectedMode}`);
  return sortedObject(binding);
}

function normalizeEvidencePaths(value) {
  const evidence = exactRecord(value, [
    "finalization_receipt_path",
    "initialization_receipt_path",
    "pending_journal_path",
    "recoveries_directory_path",
    "revisions_directory_path",
    "root_path",
    "staging_directory_path",
  ], "initialization evidence paths");
  for (const [key, filePath] of Object.entries(evidence)) {
    assertAbsolutePath(filePath, `initialization evidence ${key}`);
  }
  return sortedObject(evidence);
}

export function normalizeReleaseCeremonyLedgerInitializationReceipt(value) {
  const receipt = exactRecord(value, [
    "deployment_intent_sha256",
    "deployment_manifest",
    "evidence",
    "fresh_contract_deployment_receipt_sha256",
    "initialized_at",
    "ledger",
    "lock",
    "protocol",
    "release_sha",
    "repository_root",
    "schema",
    "status",
    "writer_id",
  ], "ledger initialization receipt");
  if (receipt.schema !== RELEASE_CEREMONY_LEDGER_INITIALIZATION_RECEIPT_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL
    || receipt.status !== "initialized_from_immutable_fresh_deployment_manifest"
    || receipt.writer_id !== "ceremony_ledger_initialization") {
    fail("ledger initialization receipt identity is invalid");
  }
  assertReleaseSha(receipt.release_sha);
  assertTimestamp(receipt.initialized_at, "initialization timestamp");
  assertAbsolutePath(receipt.repository_root, "initialization repository root");
  assertSha256(receipt.deployment_intent_sha256, "deployment intent digest");
  assertSha256(
    receipt.fresh_contract_deployment_receipt_sha256,
    "fresh contract deployment receipt digest",
  );
  const manifest = normalizeFileBinding(
    receipt.deployment_manifest,
    "immutable deployment manifest",
    "0444",
  );
  const ledger = normalizeFileBinding(receipt.ledger, "initial mutable ledger", "0600");
  if (manifest.sha256 !== ledger.sha256 || manifest.bytes !== ledger.bytes) {
    fail("initial ledger must bind the exact deployment-manifest bytes");
  }
  return sortedObject({
    ...receipt,
    deployment_manifest: manifest,
    ledger,
    evidence: normalizeEvidencePaths(receipt.evidence),
    lock: normalizeLockBinding(receipt.lock, "initialization lock"),
  });
}

export function canonicalReleaseCeremonyLedgerInitializationReceiptText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerInitializationReceipt(value),
  );
}

export function releaseCeremonyLedgerInitializationReceiptSha256(value) {
  return canonicalDigest(value, canonicalReleaseCeremonyLedgerInitializationReceiptText);
}

function revisionCommitmentCore(receipt) {
  return {
    schema: receipt.schema,
    protocol: receipt.protocol,
    status: receipt.status,
    release_sha: receipt.release_sha,
    revision: receipt.revision,
    committed_at: receipt.committed_at,
    writer_id: receipt.writer_id,
    initialization_receipt: receipt.initialization_receipt,
    ledger: receipt.ledger,
    revision_receipt_path: receipt.revision_receipt_path,
    previous_chain_sha256: receipt.previous_chain_sha256,
    lock: receipt.lock,
  };
}

export function releaseCeremonyLedgerRevisionCommitmentSha256(value) {
  const core = revisionCommitmentCore(value);
  return sha256Domain(
    RELEASE_CEREMONY_LEDGER_REVISION_COMMITMENT_DOMAIN,
    canonicalReleaseCeremonyLedgerJsonText(core),
  );
}

export function releaseCeremonyLedgerNextChainSha256(
  previousChainSha256,
  revisionCommitmentSha256,
) {
  assertSha256(previousChainSha256, "previous revision-chain digest");
  assertSha256(revisionCommitmentSha256, "revision commitment digest");
  return sha256Domain(
    RELEASE_CEREMONY_LEDGER_REVISION_CHAIN_DOMAIN,
    previousChainSha256,
    "\0",
    revisionCommitmentSha256,
  );
}

export function normalizeReleaseCeremonyLedgerRevisionReceipt(value) {
  const receipt = exactRecord(value, [
    "chain_sha256",
    "committed_at",
    "initialization_receipt",
    "ledger",
    "lock",
    "previous_chain_sha256",
    "protocol",
    "release_sha",
    "revision",
    "revision_commitment_sha256",
    "revision_receipt_path",
    "schema",
    "status",
    "writer_id",
  ], "ledger revision receipt");
  if (receipt.schema !== RELEASE_CEREMONY_LEDGER_REVISION_RECEIPT_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL
    || receipt.status !== "cas_revision_committed"
    || !RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS.includes(receipt.writer_id)) {
    fail("ledger revision receipt identity is invalid");
  }
  assertReleaseSha(receipt.release_sha);
  assertSafeCount(receipt.revision, "revision ordinal", {
    minimum: 1,
    maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
  });
  assertTimestamp(receipt.committed_at, "revision commit timestamp");
  assertAbsolutePath(receipt.revision_receipt_path, "revision receipt path");
  const initialization = exactRecord(
    receipt.initialization_receipt,
    ["path", "sha256"],
    "revision initialization receipt binding",
  );
  assertAbsolutePath(initialization.path, "revision initialization receipt path");
  assertSha256(initialization.sha256, "revision initialization receipt digest");
  const ledger = exactRecord(receipt.ledger, [
    "mode",
    "next_bytes",
    "next_sha256",
    "path",
    "previous_bytes",
    "previous_sha256",
  ], "revision ledger binding");
  assertAbsolutePath(ledger.path, "revision ledger path");
  if (ledger.mode !== "0600") fail("revision ledger mode must remain 0600");
  assertSha256(ledger.previous_sha256, "previous ledger digest");
  assertSha256(ledger.next_sha256, "next ledger digest");
  if (ledger.previous_sha256 === ledger.next_sha256) {
    fail("revision must change the ledger digest");
  }
  for (const [label, count] of [
    ["previous ledger bytes", ledger.previous_bytes],
    ["next ledger bytes", ledger.next_bytes],
  ]) {
    assertSafeCount(count, label, { minimum: 2, maximum: RELEASE_CEREMONY_LEDGER_MAX_BYTES });
  }
  assertSha256(receipt.previous_chain_sha256, "previous revision-chain digest");
  assertSha256(receipt.revision_commitment_sha256, "revision commitment digest");
  assertSha256(receipt.chain_sha256, "revision-chain digest");
  const normalized = sortedObject({
    ...receipt,
    initialization_receipt: initialization,
    ledger,
    lock: normalizeLockBinding(receipt.lock, "revision lock"),
  });
  const expectedCommitment = releaseCeremonyLedgerRevisionCommitmentSha256(normalized);
  if (normalized.revision_commitment_sha256 !== expectedCommitment) {
    fail("revision commitment digest mismatch");
  }
  const expectedChain = releaseCeremonyLedgerNextChainSha256(
    normalized.previous_chain_sha256,
    expectedCommitment,
  );
  if (normalized.chain_sha256 !== expectedChain) {
    fail("revision-chain digest mismatch");
  }
  return normalized;
}

export function canonicalReleaseCeremonyLedgerRevisionReceiptText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerRevisionReceipt(value),
  );
}

export function releaseCeremonyLedgerRevisionReceiptSha256(value) {
  return canonicalDigest(value, canonicalReleaseCeremonyLedgerRevisionReceiptText);
}

function normalizeRevisionChainBinding(value) {
  const chain = exactRecord(value, [
    "chain_sha256",
    "last_revision_receipt_sha256",
    "revision_count",
  ], "final revision-chain binding");
  assertSha256(chain.chain_sha256, "final revision-chain digest");
  assertSafeCount(chain.revision_count, "final revision count", {
    maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
  });
  if (chain.last_revision_receipt_sha256 !== null) {
    assertSha256(chain.last_revision_receipt_sha256, "last revision receipt digest");
  }
  if ((chain.revision_count === 0) !== (chain.last_revision_receipt_sha256 === null)) {
    fail("last revision receipt presence must match the final revision count");
  }
  return sortedObject(chain);
}

export function normalizeReleaseCeremonyLedgerFinalizationReceipt(value) {
  const receipt = exactRecord(value, [
    "deployment_manifest",
    "evidence",
    "finalized_at",
    "fresh_contract_deployment_receipt_sha256",
    "initialization_receipt",
    "ledger",
    "lock",
    "protocol",
    "release_sha",
    "repository_root",
    "revision_chain",
    "schema",
    "status",
    "writer_id",
  ], "ledger finalization receipt");
  if (receipt.schema !== RELEASE_CEREMONY_LEDGER_FINALIZATION_RECEIPT_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL
    || receipt.status !== "revision_chain_replayed_and_ledger_durably_frozen"
    || receipt.writer_id !== "ceremony_ledger_finalization") {
    fail("ledger finalization receipt identity is invalid");
  }
  assertReleaseSha(receipt.release_sha);
  assertTimestamp(receipt.finalized_at, "finalization timestamp");
  assertAbsolutePath(receipt.repository_root, "finalization repository root");
  assertSha256(
    receipt.fresh_contract_deployment_receipt_sha256,
    "final fresh contract deployment receipt digest",
  );
  const initialization = exactRecord(
    receipt.initialization_receipt,
    ["path", "sha256"],
    "final initialization receipt binding",
  );
  assertAbsolutePath(initialization.path, "final initialization receipt path");
  assertSha256(initialization.sha256, "final initialization receipt digest");
  return sortedObject({
    ...receipt,
    deployment_manifest: normalizeFileBinding(
      receipt.deployment_manifest,
      "final immutable deployment manifest",
      "0444",
    ),
    evidence: normalizeEvidencePaths(receipt.evidence),
    initialization_receipt: initialization,
    ledger: normalizeFileBinding(receipt.ledger, "final frozen ledger", "0444"),
    lock: normalizeLockBinding(receipt.lock, "finalization lock"),
    revision_chain: normalizeRevisionChainBinding(receipt.revision_chain),
  });
}

export function canonicalReleaseCeremonyLedgerFinalizationReceiptText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerFinalizationReceipt(value),
  );
}

export function releaseCeremonyLedgerFinalizationReceiptSha256(value) {
  return canonicalDigest(value, canonicalReleaseCeremonyLedgerFinalizationReceiptText);
}

function normalizePendingCommon(receipt) {
  if (receipt.schema !== RELEASE_CEREMONY_LEDGER_PENDING_JOURNAL_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL
    || receipt.status !== "prepared_requires_explicit_completion_or_abort") {
    fail("pending journal identity is invalid");
  }
  assertReleaseSha(receipt.release_sha);
  assertTimestamp(receipt.prepared_at, "pending journal timestamp");
  assertAbsolutePath(receipt.pending_journal_path, "pending journal path");
  assertSha256(receipt.initialization_receipt_sha256, "pending initialization receipt digest");
  return normalizeLockBinding(receipt.lock, "pending journal lock");
}

function normalizeRevisionPendingJournal(receipt) {
  exactRecord(receipt, [
    "candidate_ledger",
    "candidate_ledger_bytes",
    "candidate_ledger_sha256",
    "candidate_stage_path",
    "initialization_receipt_sha256",
    "lock",
    "operation",
    "pending_journal_path",
    "prepared_at",
    "protocol",
    "release_sha",
    "revision_receipt",
    "revision_receipt_path",
    "revision_receipt_sha256",
    "revision_receipt_stage_path",
    "schema",
    "status",
    "writer_id",
  ], "revision pending journal");
  if (!RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS.includes(receipt.writer_id)) {
    fail("revision pending journal writer is not a mutation writer");
  }
  const lock = normalizePendingCommon(receipt);
  assertAbsolutePath(receipt.candidate_stage_path, "pending candidate stage path");
  assertAbsolutePath(receipt.revision_receipt_stage_path, "pending receipt stage path");
  assertAbsolutePath(receipt.revision_receipt_path, "pending revision receipt path");
  assertSha256(receipt.candidate_ledger_sha256, "pending candidate ledger digest");
  assertSha256(receipt.revision_receipt_sha256, "pending revision receipt digest");
  assertSafeCount(receipt.candidate_ledger_bytes, "pending candidate ledger bytes", {
    minimum: 2,
    maximum: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
  const candidateText = canonicalReleaseCeremonyLedgerJsonText(receipt.candidate_ledger);
  const candidateBytes = Buffer.from(candidateText, "utf8");
  if (candidateBytes.length !== receipt.candidate_ledger_bytes
    || releaseCeremonyLedgerRawSha256(candidateBytes) !== receipt.candidate_ledger_sha256) {
    fail("pending candidate ledger bytes or digest mismatch");
  }
  const revision = normalizeReleaseCeremonyLedgerRevisionReceipt(receipt.revision_receipt);
  if (revision.writer_id !== receipt.writer_id
    || revision.release_sha !== receipt.release_sha
    || revision.initialization_receipt.sha256 !== receipt.initialization_receipt_sha256
    || revision.revision_receipt_path !== receipt.revision_receipt_path
    || revision.ledger.next_sha256 !== receipt.candidate_ledger_sha256
    || revision.ledger.next_bytes !== receipt.candidate_ledger_bytes
    || JSON.stringify(revision.lock) !== JSON.stringify(lock)
    || releaseCeremonyLedgerRevisionReceiptSha256(revision)
      !== receipt.revision_receipt_sha256) {
    fail("pending journal does not exactly bind its prepared revision receipt");
  }
  return sortedObject({ ...receipt, lock, revision_receipt: revision });
}

function normalizeFinalizationPendingJournal(receipt) {
  exactRecord(receipt, [
    "finalization_receipt",
    "finalization_receipt_path",
    "finalization_receipt_sha256",
    "finalization_receipt_stage_path",
    "initialization_receipt_sha256",
    "ledger_bytes",
    "ledger_sha256",
    "ledger_stage_path",
    "lock",
    "operation",
    "pending_journal_path",
    "prepared_at",
    "protocol",
    "release_sha",
    "schema",
    "status",
    "writer_id",
  ], "finalization pending journal");
  if (receipt.writer_id !== "ceremony_ledger_finalization") {
    fail("finalization pending journal writer mismatch");
  }
  const lock = normalizePendingCommon(receipt);
  assertAbsolutePath(receipt.ledger_stage_path, "pending final ledger stage path");
  assertAbsolutePath(
    receipt.finalization_receipt_stage_path,
    "pending finalization receipt stage path",
  );
  assertAbsolutePath(receipt.finalization_receipt_path, "pending finalization receipt path");
  assertSha256(receipt.ledger_sha256, "pending final ledger digest");
  assertSha256(receipt.finalization_receipt_sha256, "pending finalization receipt digest");
  assertSafeCount(receipt.ledger_bytes, "pending final ledger bytes", {
    minimum: 2,
    maximum: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
  const finalization = normalizeReleaseCeremonyLedgerFinalizationReceipt(
    receipt.finalization_receipt,
  );
  if (finalization.writer_id !== receipt.writer_id
    || finalization.release_sha !== receipt.release_sha
    || finalization.initialization_receipt.sha256 !== receipt.initialization_receipt_sha256
    || finalization.ledger.path === receipt.ledger_stage_path
    || finalization.ledger.sha256 !== receipt.ledger_sha256
    || finalization.ledger.bytes !== receipt.ledger_bytes
    || JSON.stringify(finalization.lock) !== JSON.stringify(lock)
    || releaseCeremonyLedgerFinalizationReceiptSha256(finalization)
      !== receipt.finalization_receipt_sha256) {
    fail("pending journal does not exactly bind its prepared finalization receipt");
  }
  return sortedObject({ ...receipt, lock, finalization_receipt: finalization });
}

export function normalizeReleaseCeremonyLedgerPendingJournal(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    fail("pending journal must be an object");
  }
  if (value.operation === "revision") return normalizeRevisionPendingJournal(value);
  if (value.operation === "finalization") return normalizeFinalizationPendingJournal(value);
  fail("pending journal operation must be revision or finalization");
}

export function canonicalReleaseCeremonyLedgerPendingJournalText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerPendingJournal(value),
  );
}

export function releaseCeremonyLedgerPendingJournalSha256(value) {
  return canonicalDigest(value, canonicalReleaseCeremonyLedgerPendingJournalText);
}

export function normalizeReleaseCeremonyLedgerGlobalReconciliation(value) {
  const reconciliation = exactRecord(value, [
    "current_ledger_sha256",
    "deployment_manifest_sha256",
    "initialization_receipt_sha256",
    "observed_stale_lock_owner_sha256",
    "onchain_signer_nonce_finalized_state_reconciliation_sha256",
    "pending_journal_sha256",
    "pending_operation",
    "pending_recovery_action",
    "pending_revision",
    "protocol",
    "release_sha",
    "revision_chain_head_sha256",
    "revision_chain_sha256",
    "revision_count",
    "schema",
  ], "global release-ledger reconciliation");
  if (reconciliation.schema !== RELEASE_CEREMONY_LEDGER_GLOBAL_RECONCILIATION_SCHEMA
    || reconciliation.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL) {
    fail("global release-ledger reconciliation identity is invalid");
  }
  assertReleaseSha(reconciliation.release_sha);
  for (const [label, digest] of [
    ["observed stale lock owner", reconciliation.observed_stale_lock_owner_sha256],
    ["deployment manifest", reconciliation.deployment_manifest_sha256],
    ["initialization receipt", reconciliation.initialization_receipt_sha256],
    ["current ledger", reconciliation.current_ledger_sha256],
    ["revision-chain head", reconciliation.revision_chain_head_sha256],
    ["revision-chain", reconciliation.revision_chain_sha256],
    ["pending journal", reconciliation.pending_journal_sha256],
  ]) assertSha256(digest, `${label} digest`);
  assertNonzeroSha256(
    reconciliation.onchain_signer_nonce_finalized_state_reconciliation_sha256,
    "on-chain signer nonce and finalized-state reconciliation digest",
  );
  assertSafeCount(reconciliation.revision_count, "global reconciliation revision count", {
    maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
  });
  if (!["revision", "finalization"].includes(reconciliation.pending_operation)
    || ![
      "aborted_before_ledger_replace",
      "completed_missing_revision_receipt",
      "completed_missing_finalization_receipt",
      "cleared_after_operation_was_complete",
    ].includes(reconciliation.pending_recovery_action)) {
    fail("global reconciliation pending operation or action is invalid");
  }
  if (reconciliation.pending_operation === "revision") {
    assertSafeCount(reconciliation.pending_revision, "global reconciliation pending revision", {
      minimum: 1,
      maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
    });
    if (reconciliation.pending_recovery_action
      === "completed_missing_finalization_receipt") {
      fail("revision reconciliation cannot complete a finalization receipt");
    }
  } else if (reconciliation.pending_revision !== null) {
    fail("global finalization reconciliation must use a null pending revision");
  } else if (reconciliation.pending_recovery_action
    === "completed_missing_revision_receipt") {
    fail("finalization reconciliation cannot complete a revision receipt");
  }
  return sortedObject(reconciliation);
}

export function projectReleaseCeremonyLedgerGlobalReconciliation({
  releaseSha,
  observedStaleLockOwnerSha256,
  deploymentManifestSha256,
  initializationReceiptSha256,
  currentLedgerSha256,
  revisionChainHeadSha256,
  revisionCount,
  revisionChainSha256,
  onchainSignerNonceFinalizedStateReconciliationSha256,
  pendingJournalSha256,
  pendingOperation,
  pendingRevision,
  pendingRecoveryAction,
}) {
  return normalizeReleaseCeremonyLedgerGlobalReconciliation({
    schema: RELEASE_CEREMONY_LEDGER_GLOBAL_RECONCILIATION_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    release_sha: releaseSha,
    observed_stale_lock_owner_sha256: observedStaleLockOwnerSha256,
    deployment_manifest_sha256: deploymentManifestSha256,
    initialization_receipt_sha256: initializationReceiptSha256,
    current_ledger_sha256: currentLedgerSha256,
    revision_chain_head_sha256: revisionChainHeadSha256,
    revision_count: revisionCount,
    revision_chain_sha256: revisionChainSha256,
    onchain_signer_nonce_finalized_state_reconciliation_sha256:
      onchainSignerNonceFinalizedStateReconciliationSha256,
    pending_journal_sha256: pendingJournalSha256,
    pending_operation: pendingOperation,
    pending_revision: pendingRevision,
    pending_recovery_action: pendingRecoveryAction,
  });
}

export function canonicalReleaseCeremonyLedgerGlobalReconciliationText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerGlobalReconciliation(value),
  );
}

export function releaseCeremonyLedgerGlobalReconciliationSha256(value) {
  return sha256Domain(
    RELEASE_CEREMONY_LEDGER_GLOBAL_RECONCILIATION_DOMAIN,
    canonicalReleaseCeremonyLedgerGlobalReconciliationText(value),
  );
}

export function normalizeSignedReleaseCeremonyLockRecoveryReceipt(value) {
  const receipt = exactRecord(value, [
    "approved_at",
    "chain_and_ledger_reconciliation_sha256",
    "expires_at",
    "observed_lock_owner_sha256",
    "protocol",
    "recovery_authority_sha256",
    "release_sha",
    "reviewer_authority_sha256",
    "reviewer_root_hash",
    "reviewers",
    "schema",
    "signed_payload_sha256",
    "status",
  ], "signed lock-recovery receipt");
  if (receipt.schema !== RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL
    || receipt.status !== "signed_recovery_verified_before_stale_lock_removal") {
    fail("signed lock-recovery receipt identity is invalid");
  }
  assertReleaseSha(receipt.release_sha, "lock-recovery release SHA");
  for (const [label, digest] of [
    ["observed lock owner", receipt.observed_lock_owner_sha256],
    ["chain and ledger reconciliation", receipt.chain_and_ledger_reconciliation_sha256],
    ["recovery authority", receipt.recovery_authority_sha256],
    ["reviewer authority", receipt.reviewer_authority_sha256],
    ["signed payload", receipt.signed_payload_sha256],
  ]) assertSha256(digest, `${label} digest`);
  assertNonzeroSha256(
    receipt.chain_and_ledger_reconciliation_sha256,
    "chain and ledger reconciliation digest",
  );
  if (typeof receipt.reviewer_root_hash !== "string"
    || !BARE_SHA256.test(receipt.reviewer_root_hash)
    || receipt.reviewer_root_hash === "0".repeat(64)) {
    fail("reviewer root digest must be a nonzero bare lowercase SHA-256 value");
  }
  const approved = assertTimestamp(receipt.approved_at, "lock-recovery approval timestamp");
  const expires = assertTimestamp(receipt.expires_at, "lock-recovery expiry timestamp");
  if (Date.parse(expires) <= Date.parse(approved)) {
    fail("signed lock-recovery receipt must expire after approval");
  }
  if (!Array.isArray(receipt.reviewers) || receipt.reviewers.length !== 2) {
    fail("signed lock-recovery receipt must bind exactly two reviewers");
  }
  const reviewers = receipt.reviewers.map((entry, index) => {
    const reviewer = exactRecord(
      entry,
      ["address", "controller_id", "signature_sha256"],
      `signed lock-recovery reviewer ${index}`,
    );
    if (typeof reviewer.address !== "string"
      || !ADDRESS.test(reviewer.address)
      || /^0x0+$/.test(reviewer.address)) {
      fail(`signed lock-recovery reviewer ${index} address is invalid`);
    }
    if (typeof reviewer.controller_id !== "string"
      || !CONTROLLER.test(reviewer.controller_id)) {
      fail(`signed lock-recovery reviewer ${index} controller is invalid`);
    }
    assertSha256(reviewer.signature_sha256, `signed lock-recovery reviewer ${index} signature`);
    return sortedObject(reviewer);
  });
  if (new Set(reviewers.map(({ address }) => address)).size !== 2
    || new Set(reviewers.map(({ controller_id }) => controller_id)).size !== 2) {
    fail("signed lock-recovery reviewers must have distinct identities and controllers");
  }
  return sortedObject({ ...receipt, reviewers });
}

export function normalizeReleaseCeremonyLedgerRecoveryReceipt(value) {
  const receipt = exactRecord(value, [
    "global_reconciliation",
    "global_reconciliation_sha256",
    "initialization_receipt_sha256",
    "lock",
    "lock_recovery_receipt",
    "operation",
    "operation_revision",
    "original_lock_owner_sha256",
    "pending_journal",
    "protocol",
    "recovered_at",
    "recovery_action",
    "recovery_receipt_path",
    "release_sha",
    "resulting_ledger_mode",
    "resulting_ledger_sha256",
    "resulting_revision_chain_sha256",
    "resulting_revision_count",
    "schema",
    "status",
    "writer_id",
  ], "ledger recovery receipt");
  if (receipt.schema !== RELEASE_CEREMONY_LEDGER_RECOVERY_RECEIPT_SCHEMA
    || receipt.protocol !== RELEASE_CEREMONY_LEDGER_PROTOCOL
    || receipt.status !== "explicit_signed_lock_recovery_reconciled_pending_operation"
    || receipt.writer_id !== "ceremony_ledger_recovery") {
    fail("ledger recovery receipt identity is invalid");
  }
  if (!["revision", "finalization"].includes(receipt.operation)
    || ![
      "aborted_before_ledger_replace",
      "completed_missing_revision_receipt",
      "completed_missing_finalization_receipt",
      "cleared_after_operation_was_complete",
    ].includes(receipt.recovery_action)) {
    fail("ledger recovery operation or action is invalid");
  }
  if (receipt.operation === "revision") {
    assertSafeCount(receipt.operation_revision, "recovered revision", {
      minimum: 1,
      maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
    });
    if (receipt.recovery_action === "completed_missing_finalization_receipt") {
      fail("revision recovery cannot complete a finalization receipt");
    }
  } else if (receipt.operation_revision !== null) {
    fail("finalization recovery must use a null operation revision");
  } else if (receipt.recovery_action === "completed_missing_revision_receipt") {
    fail("finalization recovery cannot complete a revision receipt");
  }
  assertReleaseSha(receipt.release_sha);
  assertTimestamp(receipt.recovered_at, "ledger recovery timestamp");
  assertAbsolutePath(receipt.recovery_receipt_path, "ledger recovery receipt path");
  assertSha256(receipt.initialization_receipt_sha256, "recovery initialization receipt digest");
  assertSha256(receipt.original_lock_owner_sha256, "recovery original lock owner digest");
  assertSha256(receipt.global_reconciliation_sha256, "global reconciliation digest");
  assertSha256(receipt.resulting_ledger_sha256, "recovery resulting ledger digest");
  assertSha256(receipt.resulting_revision_chain_sha256, "recovery resulting chain digest");
  assertSafeCount(receipt.resulting_revision_count, "recovery resulting revision count", {
    maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION,
  });
  if (!["0600", "0444"].includes(receipt.resulting_ledger_mode)) {
    fail("recovery resulting ledger mode is invalid");
  }
  const pending = exactRecord(
    receipt.pending_journal,
    ["path", "sha256"],
    "recovery pending journal binding",
  );
  assertAbsolutePath(pending.path, "recovery pending journal path");
  assertSha256(pending.sha256, "recovery pending journal digest");
  const globalReconciliation = normalizeReleaseCeremonyLedgerGlobalReconciliation(
    receipt.global_reconciliation,
  );
  if (receipt.global_reconciliation_sha256
      !== releaseCeremonyLedgerGlobalReconciliationSha256(globalReconciliation)
    || globalReconciliation.release_sha !== receipt.release_sha
    || globalReconciliation.initialization_receipt_sha256
      !== receipt.initialization_receipt_sha256
    || globalReconciliation.current_ledger_sha256 !== receipt.resulting_ledger_sha256
    || globalReconciliation.pending_journal_sha256 !== pending.sha256
    || globalReconciliation.pending_operation !== receipt.operation
    || globalReconciliation.pending_revision !== receipt.operation_revision
    || globalReconciliation.pending_recovery_action !== receipt.recovery_action) {
    fail("ledger recovery global reconciliation binding mismatch");
  }
  const signed = exactRecord(
    receipt.lock_recovery_receipt,
    ["path", "sha256"],
    "signed lock-recovery receipt binding",
  );
  assertAbsolutePath(signed.path, "signed lock-recovery receipt path");
  assertSha256(signed.sha256, "signed lock-recovery receipt digest");
  return sortedObject({
    ...receipt,
    global_reconciliation: globalReconciliation,
    lock: normalizeLockBinding(receipt.lock, "ledger recovery lock"),
    lock_recovery_receipt: signed,
    pending_journal: pending,
  });
}

export function canonicalReleaseCeremonyLedgerRecoveryReceiptText(value) {
  return canonicalReleaseCeremonyLedgerJsonText(
    normalizeReleaseCeremonyLedgerRecoveryReceipt(value),
  );
}

export function releaseCeremonyLedgerRecoveryReceiptSha256(value) {
  return canonicalDigest(value, canonicalReleaseCeremonyLedgerRecoveryReceiptText);
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertNoSymlinkComponents(absolutePath, { includeLeaf = true } = {}) {
  assertAbsolutePath(absolutePath, "filesystem path");
  const root = path.parse(absolutePath).root;
  const parts = path.relative(root, absolutePath).split(path.sep).filter(Boolean);
  let cursor = root;
  const count = includeLeaf ? parts.length : Math.max(0, parts.length - 1);
  for (let index = 0; index < count; index += 1) {
    cursor = path.join(cursor, parts[index]);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) fail(`filesystem path traverses symlink: ${cursor}`);
  }
}

function assertCanonicalExistingDirectory(directoryPath, label, expectedMode = null) {
  assertAbsolutePath(directoryPath, label);
  assertNoSymlinkComponents(directoryPath);
  if (fs.realpathSync.native(directoryPath) !== directoryPath) {
    fail(`${label} must use its canonical real path`);
  }
  const stat = fs.lstatSync(directoryPath);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(`${label} must be a non-symlink directory`);
  }
  const uid = typeof process.geteuid === "function" ? process.geteuid() : stat.uid;
  if (stat.uid !== uid) fail(`${label} must be owned by the current operator`);
  if (expectedMode !== null && (stat.mode & 0o777) !== expectedMode) {
    fail(`${label} mode must be ${expectedMode.toString(8).padStart(4, "0")}`);
  }
  if ((stat.mode & 0o022) !== 0) {
    fail(`${label} must not be group- or other-writable`);
  }
  return stat;
}

function assertAbsentCanonicalPath(filePath, label) {
  assertAbsolutePath(filePath, label);
  const parent = path.dirname(filePath);
  assertCanonicalExistingDirectory(parent, `${label} parent`);
  assertNoSymlinkComponents(filePath, { includeLeaf: false });
  try {
    fs.lstatSync(filePath);
    fail(`${label} must be absent`);
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function assertOutsideRepository(candidatePath, repositoryRoot, label) {
  if (candidatePath === repositoryRoot
    || candidatePath.startsWith(`${repositoryRoot}${path.sep}`)) {
    fail(`${label} must remain outside the source checkout`);
  }
}

function stableReadCanonicalJson(filePath, {
  label,
  expectedMode,
  maxBytes = RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES,
  normalizer = null,
} = {}) {
  assertAbsolutePath(filePath, label);
  assertNoSymlinkComponents(filePath);
  if (fs.realpathSync.native(filePath) !== filePath) {
    fail(`${label} must use its canonical real path`);
  }
  const before = fs.lstatSync(filePath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    fail(`${label} must be a single-link non-symlink regular file`);
  }
  const uid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (before.uid !== uid) fail(`${label} must be owned by the current operator`);
  if ((before.mode & 0o777) !== expectedMode) {
    fail(`${label} mode must be ${expectedMode.toString(8).padStart(4, "0")}`);
  }
  if (before.size < 2 || before.size > maxBytes) {
    fail(`${label} exceeds its bounded size`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || !sameInode(before, opened)) {
      fail(`${label} changed while it was opened`);
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) fail(`${label} ended during its bounded read`);
      offset += count;
    }
    const after = fs.fstatSync(fd);
    const current = fs.lstatSync(filePath);
    if (!sameInode(opened, after)
      || !sameInode(after, current)
      || after.size !== opened.size) {
      fail(`${label} changed during its bounded read`);
    }
    let parsed;
    try {
      parsed = JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      fail(`${label} is not JSON: ${error.message}`);
    }
    const value = normalizer ? normalizer(parsed) : validateJsonTree(parsed);
    const canonical = normalizer
      ? canonicalReleaseCeremonyLedgerJsonText(value)
      : canonicalReleaseCeremonyLedgerJsonText(parsed);
    if (bytes.toString("utf8") !== canonical) fail(`${label} is not canonical JSON`);
    return {
      bytes,
      mode: after.mode & 0o777,
      sha256: releaseCeremonyLedgerRawSha256(bytes),
      stat: after,
      value,
    };
  } finally {
    fs.closeSync(fd);
  }
}

function fsyncDirectoryChain(directoryPath) {
  let current = directoryPath;
  while (true) {
    assertAbsolutePath(current, "fsync directory");
    assertNoSymlinkComponents(current);
    if (fs.realpathSync.native(current) !== current) {
      fail("fsync directory must use its canonical real path");
    }
    const before = fs.lstatSync(current);
    if (!before.isDirectory() || before.isSymbolicLink()) {
      fail("fsync path must be a non-symlink directory");
    }
    const fd = fs.openSync(current, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
    try {
      const opened = fs.fstatSync(fd);
      const after = fs.lstatSync(current);
      if (!opened.isDirectory()
        || !sameInode(before, opened)
        || !sameInode(opened, after)) {
        fail("fsync directory changed while it was opened");
      }
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const written = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (!Number.isInteger(written) || written < 1) fail("staging write made no progress");
    offset += written;
  }
}

function createDurableStage(filePath, text) {
  const parsed = parseCanonicalText(
    text,
    "staged JSON",
    RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES,
  );
  assertAbsentCanonicalPath(filePath, "staged JSON path");
  const fd = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
    RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  );
  try {
    writeAll(fd, parsed.bytes);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size !== parsed.bytes.length) {
      fail("staged JSON is incomplete");
    }
    fs.fchmodSync(fd, RELEASE_CEREMONY_LEDGER_ACTIVE_MODE);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fsyncDirectoryChain(path.dirname(filePath));
  const reread = stableReadCanonicalJson(filePath, {
    label: "staged JSON",
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES,
  });
  if (!reread.bytes.equals(parsed.bytes)) fail("staged JSON bytes changed after fsync");
  return reread;
}

function removeStageIfExact(stagePath, digest) {
  if (!fs.existsSync(stagePath)) return;
  durablyRemoveJson({
    filePath: stagePath,
    expectedSha256: digest,
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  });
}

function mkdirDurable(directoryPath) {
  assertAbsentCanonicalPath(directoryPath, "evidence directory");
  fs.mkdirSync(directoryPath, { mode: RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE });
  fs.chmodSync(directoryPath, RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE);
  assertCanonicalExistingDirectory(
    directoryPath,
    "evidence directory",
    RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE,
  );
  fsyncDirectoryChain(path.dirname(directoryPath));
}

function evidencePaths(evidenceRoot) {
  return {
    root_path: evidenceRoot,
    initialization_receipt_path: path.join(evidenceRoot, "initialization.json"),
    finalization_receipt_path: path.join(evidenceRoot, "finalization.json"),
    pending_journal_path: path.join(evidenceRoot, "pending.json"),
    revisions_directory_path: path.join(evidenceRoot, "revisions"),
    recoveries_directory_path: path.join(evidenceRoot, "recoveries"),
    staging_directory_path: path.join(evidenceRoot, ".staging"),
  };
}

function revisionReceiptPath(paths, revision) {
  return path.join(
    paths.revisions_directory_path,
    `${String(revision).padStart(12, "0")}.json`,
  );
}

function normalizeSourcePath(options) {
  const source = options.sourceManifestPath ?? options.deploymentManifestPath;
  if (options.sourceManifestPath !== undefined
    && options.deploymentManifestPath !== undefined
    && options.sourceManifestPath !== options.deploymentManifestPath) {
    fail("sourceManifestPath and deploymentManifestPath aliases disagree");
  }
  return source;
}

function normalizePathContext(options, { initialization = false } = {}) {
  const repositoryRoot = options.repositoryRoot;
  const sourceManifestPath = normalizeSourcePath(options);
  const ledgerPath = options.ledgerPath;
  const evidenceRoot = options.evidenceRoot;
  assertCanonicalExistingDirectory(repositoryRoot, "repository root");
  assertAbsolutePath(sourceManifestPath, "deployment manifest path");
  assertAbsolutePath(ledgerPath, "release ledger path");
  assertCanonicalExistingDirectory(
    evidenceRoot,
    "release ledger evidence root",
    RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE,
  );
  assertOutsideRepository(evidenceRoot, repositoryRoot, "release ledger evidence root");
  assertOutsideRepository(ledgerPath, repositoryRoot, "release ledger");
  if (ledgerPath === sourceManifestPath) {
    fail("deployment manifest and mutable ledger paths must be distinct");
  }
  if (ledgerPath === evidenceRoot || ledgerPath.startsWith(`${evidenceRoot}${path.sep}`)) {
    fail("release ledger must remain separate from its evidence root");
  }
  assertCanonicalExistingDirectory(
    path.dirname(ledgerPath),
    "release ledger parent",
    RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE,
  );
  if (initialization) {
    assertAbsentCanonicalPath(ledgerPath, "release ledger target");
    const entries = fs.readdirSync(evidenceRoot);
    if (entries.length !== 0) fail("release ledger evidence root must be empty at initialization");
  } else {
    for (const directory of [
      evidencePaths(evidenceRoot).revisions_directory_path,
      evidencePaths(evidenceRoot).recoveries_directory_path,
      evidencePaths(evidenceRoot).staging_directory_path,
    ]) {
      assertCanonicalExistingDirectory(
        directory,
        "release ledger evidence subdirectory",
        RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE,
      );
    }
  }
  return {
    repositoryRoot,
    sourceManifestPath,
    ledgerPath,
    evidenceRoot,
    paths: evidencePaths(evidenceRoot),
  };
}

function freshReceiptAuthorityPins(options) {
  return {
    expectedDeploymentIntentSha256: assertNonzeroSha256(
      options.deploymentIntentSha256,
      "externally reviewed deployment-intent digest",
    ),
    expectedReviewerAuthorityGenesisAcceptanceSha256: assertNonzeroSha256(
      options.reviewerAuthorityGenesisAcceptanceSha256,
      "externally reviewed reviewer-genesis acceptance digest",
    ),
  };
}

function readFreshManifest(sourceManifestPath, releaseSha, authorityPins) {
  const source = stableReadCanonicalJson(sourceManifestPath, {
    label: "immutable deployment manifest",
    expectedMode: RELEASE_CEREMONY_LEDGER_FROZEN_MODE,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
  const deploymentIntentSha256 = source.value?.freshDeployment?.contractSuite
    ?.deploymentIntentSha256;
  assertSha256(deploymentIntentSha256, "deployment manifest deployment-intent digest");
  if (deploymentIntentSha256 !== authorityPins.expectedDeploymentIntentSha256) {
    fail("deployment manifest deployment-intent digest differs from the external reviewed pin");
  }
  const freshReceipt = projectFreshContractDeploymentReceipt(source.value, {
    releaseSha,
    ...authorityPins,
  });
  return {
    ...source,
    deploymentIntentSha256,
    reviewerAuthorityGenesisAcceptanceSha256:
      authorityPins.expectedReviewerAuthorityGenesisAcceptanceSha256,
    freshReceiptAuthorityPins: authorityPins,
    freshReceiptSha256:
      `sha256:${freshContractDeploymentReceiptDigest(freshReceipt, authorityPins)}`,
  };
}

function ownerTokenSha256(token) {
  if (typeof token !== "string" || !TOKEN.test(token)) {
    fail("lock owner token must be lowercase 32-byte hex");
  }
  return `sha256:${createHash("sha256")
    .update("dnai-wikigen/release-ceremony-lock/owner-token/v1\0", "utf8")
    .update(Buffer.from(token, "hex"))
    .digest("hex")}`;
}

function assertHeldLock({
  lockRoot,
  repositoryRoot,
  releaseSha,
  writerId,
  ownerToken,
}, expectedOwnerSha256 = null) {
  if (!RELEASE_CEREMONY_WRITERS.includes(writerId)) {
    fail("writer ID is not a supported shared-lock writer");
  }
  const inspected = inspectReleaseCeremonyLock({ lockRoot, repositoryRoot, releaseSha });
  const ownerDigest = ownerTokenSha256(ownerToken);
  if (inspected.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL
    || inspected.status !== "held_or_stale_requires_owner_release_or_reviewed_recovery"
    || !inspected.owner
    || inspected.owner.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL
    || inspected.owner.state !== "held"
    || inspected.owner.release_sha !== releaseSha
    || inspected.owner.writer_id !== writerId
    || inspected.owner.owner_token_sha256 !== ownerDigest
    || inspected.observed_lock_owner_sha256 === null) {
    fail("caller does not hold the exact shared release ceremony lock");
  }
  if (expectedOwnerSha256 !== null
    && inspected.observed_lock_owner_sha256 !== expectedOwnerSha256) {
    fail("shared release ceremony lock owner changed during the operation");
  }
  return {
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    path: inspected.lock_path,
    owner_sha256: inspected.observed_lock_owner_sha256,
  };
}

function assertFaultPoint(faultPoint) {
  if (faultPoint !== null && !RELEASE_CEREMONY_LEDGER_FAULT_POINTS.includes(faultPoint)) {
    fail("unknown ledger fault-injection point");
  }
}

function maybeFault(faultPoint, point) {
  if (faultPoint === point) fail(`injected crash at ${point}`);
}

function assertEvidenceBinding(receipt, context) {
  const expected = context.paths;
  if (receipt.repository_root !== context.repositoryRoot
    || JSON.stringify(receipt.evidence) !== JSON.stringify(sortedObject(expected))
    || receipt.deployment_manifest.path !== context.sourceManifestPath
    || receipt.ledger.path !== context.ledgerPath) {
    fail("initialization receipt path binding does not match this ceremony context");
  }
}

function readInitialization(context, source) {
  const read = stableReadCanonicalJson(context.paths.initialization_receipt_path, {
    label: "ledger initialization receipt",
    expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
    normalizer: normalizeReleaseCeremonyLedgerInitializationReceipt,
  });
  const receipt = read.value;
  assertEvidenceBinding(receipt, context);
  if (receipt.release_sha !== source.value.freshDeployment.contractSuite.sourceCommit
    || receipt.deployment_manifest.sha256 !== source.sha256
    || receipt.deployment_manifest.bytes !== source.bytes.length
    || receipt.deployment_intent_sha256 !== source.deploymentIntentSha256
    || receipt.fresh_contract_deployment_receipt_sha256 !== source.freshReceiptSha256) {
    fail("immutable deployment manifest no longer matches initialization evidence");
  }
  return { ...read, receipt };
}

function assertNoPending(context) {
  if (fs.existsSync(context.paths.pending_journal_path)) {
    fail("pending journal exists; explicit signed recovery is required");
  }
}

function assertStagingEmpty(context) {
  const entries = fs.readdirSync(context.paths.staging_directory_path);
  if (entries.length !== 0) {
    fail("staging directory is not empty; explicit reviewed reconciliation is required");
  }
}

function readRevisionReceipts(context, initialization) {
  const names = fs.readdirSync(context.paths.revisions_directory_path).sort();
  const receipts = [];
  let ledgerSha256 = initialization.receipt.ledger.sha256;
  let ledgerBytes = initialization.receipt.ledger.bytes;
  let chainSha256 = releaseCeremonyLedgerGenesisChainSha256(initialization.sha256);
  let lastRevisionReceiptSha256 = null;
  for (let index = 0; index < names.length; index += 1) {
    const name = names[index];
    const match = REVISION_FILE.exec(name);
    const revision = index + 1;
    if (!match || Number(match[1]) !== revision
      || name !== `${String(revision).padStart(12, "0")}.json`) {
      fail("revision evidence must contain one exact contiguous ordinal receipt sequence");
    }
    const receiptPath = path.join(context.paths.revisions_directory_path, name);
    const read = stableReadCanonicalJson(receiptPath, {
      label: `ledger revision receipt ${revision}`,
      expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      normalizer: normalizeReleaseCeremonyLedgerRevisionReceipt,
    });
    const receipt = read.value;
    if (receipt.release_sha !== initialization.receipt.release_sha
      || receipt.revision !== revision
      || receipt.revision_receipt_path !== receiptPath
      || receipt.initialization_receipt.path
        !== context.paths.initialization_receipt_path
      || receipt.initialization_receipt.sha256 !== initialization.sha256
      || receipt.ledger.path !== context.ledgerPath
      || receipt.ledger.previous_sha256 !== ledgerSha256
      || receipt.ledger.previous_bytes !== ledgerBytes
      || receipt.previous_chain_sha256 !== chainSha256) {
      fail(`revision receipt ${revision} does not extend the exact prior state`);
    }
    ledgerSha256 = receipt.ledger.next_sha256;
    ledgerBytes = receipt.ledger.next_bytes;
    chainSha256 = receipt.chain_sha256;
    lastRevisionReceiptSha256 = read.sha256;
    receipts.push({ ...read, receipt });
  }
  return {
    receipts,
    revisionCount: receipts.length,
    ledgerSha256,
    ledgerBytes,
    chainSha256,
    lastRevisionReceiptSha256,
  };
}

function readRecoveryReceipts(context, initialization, options) {
  const names = fs.readdirSync(context.paths.recoveries_directory_path).sort();
  const receipts = [];
  const lockRecoveryDigests = new Set();
  for (const name of names) {
    if (!/^[0-9a-f]{64}\.json$/.test(name)) {
      fail("recovery evidence must use exact lock-recovery digest filenames");
    }
    const receiptPath = path.join(context.paths.recoveries_directory_path, name);
    const read = stableReadCanonicalJson(receiptPath, {
      label: "ledger recovery receipt",
      expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      normalizer: normalizeReleaseCeremonyLedgerRecoveryReceipt,
    });
    const receipt = read.value;
    if (receipt.release_sha !== initialization.receipt.release_sha
      || receipt.initialization_receipt_sha256 !== initialization.sha256
      || receipt.recovery_receipt_path !== receiptPath
      || name !== `${receipt.lock_recovery_receipt.sha256.slice("sha256:".length)}.json`
      || lockRecoveryDigests.has(receipt.lock_recovery_receipt.sha256)) {
      fail("ledger recovery receipt path, release, or initialization binding is invalid");
    }
    const signedRecovery = readSignedLockRecoveryReceipt({
      lockRecoveryReceiptPath: receipt.lock_recovery_receipt.path,
      lockRecoveryReceiptSha256: receipt.lock_recovery_receipt.sha256,
      lockRoot: options.lockRoot,
      releaseSha: options.releaseSha,
      expectedObservedOwnerSha256: null,
      expectedReconciliationSha256: receipt.global_reconciliation_sha256,
    });
    if (signedRecovery.value.observed_lock_owner_sha256
      !== receipt.global_reconciliation.observed_stale_lock_owner_sha256) {
      fail("ledger recovery receipt global reconciliation stale-owner binding mismatch");
    }
    lockRecoveryDigests.add(receipt.lock_recovery_receipt.sha256);
    receipts.push({ ...read, receipt });
  }
  return receipts;
}

function readLedgerAtEitherMode(ledgerPath) {
  const stat = fs.lstatSync(ledgerPath);
  const mode = stat.mode & 0o777;
  if (![RELEASE_CEREMONY_LEDGER_ACTIVE_MODE, RELEASE_CEREMONY_LEDGER_FROZEN_MODE]
    .includes(mode)) {
    fail("release ledger mode must be 0600 while active or 0444 when finalized");
  }
  return stableReadCanonicalJson(ledgerPath, {
    label: "release ledger",
    expectedMode: mode,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
}

function validateFinalizationAgainstState(finalization, {
  context,
  source,
  initialization,
  chain,
  ledger,
}) {
  const receipt = finalization.value;
  if (receipt.release_sha !== initialization.receipt.release_sha
    || receipt.repository_root !== context.repositoryRoot
    || receipt.deployment_manifest.path !== context.sourceManifestPath
    || receipt.deployment_manifest.sha256 !== source.sha256
    || receipt.deployment_manifest.bytes !== source.bytes.length
    || receipt.initialization_receipt.path !== context.paths.initialization_receipt_path
    || receipt.initialization_receipt.sha256 !== initialization.sha256
    || receipt.ledger.path !== context.ledgerPath
    || receipt.ledger.sha256 !== ledger.sha256
    || receipt.ledger.bytes !== ledger.bytes.length
    || receipt.revision_chain.revision_count !== chain.revisionCount
    || receipt.revision_chain.chain_sha256 !== chain.chainSha256
    || receipt.revision_chain.last_revision_receipt_sha256
      !== chain.lastRevisionReceiptSha256
    || receipt.fresh_contract_deployment_receipt_sha256 !== source.freshReceiptSha256
    || JSON.stringify(receipt.evidence) !== JSON.stringify(sortedObject(context.paths))) {
    fail("finalization receipt does not bind the replayed ledger state");
  }
}

function loadCeremonyState(options, {
  allowPending = false,
  allowStaging = false,
  verifyLedger = true,
} = {}) {
  const context = normalizePathContext(options);
  assertReleaseSha(options.releaseSha);
  const source = readFreshManifest(
    context.sourceManifestPath,
    options.releaseSha,
    freshReceiptAuthorityPins(options),
  );
  const initialization = readInitialization(context, source);
  assertCanonicalExistingDirectory(
    options.lockRoot,
    "release ceremony lock root",
    RELEASE_CEREMONY_LEDGER_PRIVATE_DIRECTORY_MODE,
  );
  const expectedLockPath = path.join(
    options.lockRoot,
    `dnai-release-ceremony-${options.releaseSha}.lock`,
  );
  if (initialization.receipt.lock.path !== expectedLockPath) {
    fail("initialization receipt shared-lock path binding mismatch");
  }
  if (initialization.receipt.release_sha !== options.releaseSha) {
    fail("initialization receipt release SHA mismatch");
  }
  if (!allowPending) assertNoPending(context);
  if (!allowStaging) assertStagingEmpty(context);
  const chain = readRevisionReceipts(context, initialization);
  const recoveries = readRecoveryReceipts(context, initialization, options);
  let ledger = null;
  let finalized = false;
  let finalization = null;
  if (verifyLedger) {
    ledger = readLedgerAtEitherMode(context.ledgerPath);
    if (ledger.sha256 !== chain.ledgerSha256 || ledger.bytes.length !== chain.ledgerBytes) {
      fail("current ledger does not match the replayed revision chain");
    }
    if (fs.existsSync(context.paths.finalization_receipt_path)) {
      finalization = stableReadCanonicalJson(context.paths.finalization_receipt_path, {
        label: "ledger finalization receipt",
        expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
        normalizer: normalizeReleaseCeremonyLedgerFinalizationReceipt,
      });
      if (ledger.mode !== RELEASE_CEREMONY_LEDGER_FROZEN_MODE) {
        fail("finalized ledger must be frozen at mode 0444");
      }
      validateFinalizationAgainstState(finalization, {
        context,
        source,
        initialization,
        chain,
        ledger,
      });
      finalized = true;
    } else if (ledger.mode !== RELEASE_CEREMONY_LEDGER_ACTIVE_MODE) {
      fail("unfinalized ledger must remain mutable only by the ceremony at mode 0600");
    }
  }
  return {
    context,
    source,
    initialization,
    chain,
    recoveries,
    ledger,
    finalized,
    finalization,
  };
}

function publicReplay(state) {
  return {
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    release_sha: state.initialization.receipt.release_sha,
    initialization_receipt_sha256: state.initialization.sha256,
    revision_count: state.chain.revisionCount,
    revision_chain_sha256: state.chain.chainSha256,
    last_revision_receipt_sha256: state.chain.lastRevisionReceiptSha256,
    current_ledger_sha256: state.ledger.sha256,
    current_ledger_bytes: state.ledger.bytes.length,
    ledger_mode: state.ledger.mode === RELEASE_CEREMONY_LEDGER_FROZEN_MODE
      ? "0444"
      : "0600",
    finalized: state.finalized,
    finalization_receipt_sha256: state.finalization?.sha256 ?? null,
    recovery_receipt_count: state.recoveries.length,
  };
}

export function replayReleaseCeremonyLedgerRevisionChain(options) {
  return publicReplay(loadCeremonyState(options));
}

function stageAndPublish({ text, stagePath, outputPath, publishMode, fileMode }) {
  const staged = createDurableStage(stagePath, text);
  durablyPublishJson({ sourcePath: stagePath, outputPath, publishMode, fileMode });
  return staged;
}

export function initializeReleaseCeremonyLedger(options) {
  assertReleaseSha(options.releaseSha);
  const context = normalizePathContext(options, { initialization: true });
  const lock = assertHeldLock({
    ...options,
    repositoryRoot: context.repositoryRoot,
    releaseSha: options.releaseSha,
    writerId: options.writerId,
  });
  if (options.writerId !== "ceremony_ledger_initialization") {
    fail("ledger initialization requires the ceremony_ledger_initialization writer");
  }
  const source = readFreshManifest(
    context.sourceManifestPath,
    options.releaseSha,
    freshReceiptAuthorityPins(options),
  );
  for (const directoryPath of [
    context.paths.revisions_directory_path,
    context.paths.recoveries_directory_path,
    context.paths.staging_directory_path,
  ]) mkdirDurable(directoryPath);

  assertHeldLock({ ...options, repositoryRoot: context.repositoryRoot }, lock.owner_sha256);
  durablyPublishJson({
    sourcePath: context.sourceManifestPath,
    outputPath: context.ledgerPath,
    publishMode: "create",
    fileMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  });
  const ledger = stableReadCanonicalJson(context.ledgerPath, {
    label: "new release ledger",
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_BYTES,
  });
  if (!ledger.bytes.equals(source.bytes)) {
    fail("initialized ledger bytes differ from the immutable deployment manifest");
  }
  const receipt = normalizeReleaseCeremonyLedgerInitializationReceipt({
    schema: RELEASE_CEREMONY_LEDGER_INITIALIZATION_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "initialized_from_immutable_fresh_deployment_manifest",
    release_sha: options.releaseSha,
    initialized_at: timestamp(options.now ?? new Date(), "initialization time"),
    writer_id: "ceremony_ledger_initialization",
    repository_root: context.repositoryRoot,
    deployment_intent_sha256: source.deploymentIntentSha256,
    fresh_contract_deployment_receipt_sha256: source.freshReceiptSha256,
    deployment_manifest: {
      path: context.sourceManifestPath,
      sha256: source.sha256,
      bytes: source.bytes.length,
      mode: "0444",
    },
    ledger: {
      path: context.ledgerPath,
      sha256: ledger.sha256,
      bytes: ledger.bytes.length,
      mode: "0600",
    },
    evidence: context.paths,
    lock,
  });
  const stagePath = path.join(
    context.paths.staging_directory_path,
    "initialization-receipt.json",
  );
  const receiptText = canonicalReleaseCeremonyLedgerInitializationReceiptText(receipt);
  const staged = stageAndPublish({
    text: receiptText,
    stagePath,
    outputPath: context.paths.initialization_receipt_path,
    publishMode: "create",
    fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
  });
  assertHeldLock({ ...options, repositoryRoot: context.repositoryRoot }, lock.owner_sha256);
  removeStageIfExact(stagePath, staged.sha256);
  const replay = replayReleaseCeremonyLedgerRevisionChain({
    ...options,
    sourceManifestPath: context.sourceManifestPath,
  });
  return {
    ...replay,
    initialization_receipt_path: context.paths.initialization_receipt_path,
  };
}

function candidateLedger(options, state) {
  const candidateValue = options.candidateLedger ?? options.candidate;
  let parsed;
  if (options.candidateLedgerText !== undefined) {
    if (candidateValue !== undefined) {
      fail("provide candidateLedgerText or candidateLedger, not both");
    }
    parsed = parseCanonicalText(
      options.candidateLedgerText,
      "candidate ledger",
      RELEASE_CEREMONY_LEDGER_MAX_BYTES,
    );
  } else {
    if (candidateValue === undefined) fail("candidate ledger is required");
    const text = canonicalReleaseCeremonyLedgerJsonText(candidateValue);
    parsed = parseCanonicalText(text, "candidate ledger", RELEASE_CEREMONY_LEDGER_MAX_BYTES);
  }
  const freshReceipt = projectFreshContractDeploymentReceipt(parsed.value, {
    releaseSha: options.releaseSha,
    ...state.source.freshReceiptAuthorityPins,
  });
  const freshReceiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
    freshReceipt,
    state.source.freshReceiptAuthorityPins,
  )}`;
  if (freshReceiptSha256 !== state.source.freshReceiptSha256) {
    fail("candidate ledger changes immutable fresh contract deployment facts");
  }
  return {
    ...parsed,
    sha256: releaseCeremonyLedgerRawSha256(parsed.bytes),
  };
}

function expectedCasDigest(options) {
  const primary = options.expectedLedgerSha256;
  const alias = options.expectedPreviousLedgerSha256;
  if (primary !== undefined && alias !== undefined && primary !== alias) {
    fail("expected ledger digest aliases disagree");
  }
  return assertSha256(primary ?? alias, "expected previous ledger digest");
}

function revisionStagePaths(context, revision) {
  const ordinal = String(revision).padStart(12, "0");
  return {
    candidate: path.join(context.paths.staging_directory_path, `${ordinal}-candidate.json`),
    receipt: path.join(context.paths.staging_directory_path, `${ordinal}-revision-receipt.json`),
    pending: path.join(context.paths.staging_directory_path, `${ordinal}-pending.json`),
  };
}

function publishPending(context, pending, stagePath) {
  const text = canonicalReleaseCeremonyLedgerPendingJournalText(pending);
  const staged = stageAndPublish({
    text,
    stagePath,
    outputPath: context.paths.pending_journal_path,
    publishMode: "create",
    fileMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  });
  return { staged, sha256: releaseCeremonyLedgerPendingJournalSha256(pending) };
}

export function commitReleaseCeremonyLedgerRevision(options) {
  assertReleaseSha(options.releaseSha);
  assertFaultPoint(options.faultPoint ?? null);
  if (!RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS.includes(options.writerId)) {
    fail("ledger revisions require a release component mutation writer");
  }
  const state = loadCeremonyState(options);
  if (state.finalized) fail("finalized release ledger refuses all revisions");
  const lock = assertHeldLock(options);
  const expectedRevision = assertSafeCount(options.expectedRevision, "expected revision", {
    maximum: RELEASE_CEREMONY_LEDGER_MAX_REVISION - 1,
  });
  const expectedDigest = expectedCasDigest(options);
  if (state.chain.revisionCount !== expectedRevision
    || state.ledger.sha256 !== expectedDigest) {
    fail("CAS mismatch: expected revision or previous ledger digest is stale");
  }
  const candidate = candidateLedger(options, state);
  if (candidate.sha256 === state.ledger.sha256) fail("ledger revision must not be a no-op");
  const revision = expectedRevision + 1;
  const receiptPath = revisionReceiptPath(state.context.paths, revision);
  assertAbsentCanonicalPath(receiptPath, "next revision receipt");
  const stagePaths = revisionStagePaths(state.context, revision);
  const receiptWithoutCommitments = {
    schema: RELEASE_CEREMONY_LEDGER_REVISION_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "cas_revision_committed",
    release_sha: options.releaseSha,
    revision,
    committed_at: timestamp(options.now ?? new Date(), "revision time"),
    writer_id: options.writerId,
    initialization_receipt: {
      path: state.context.paths.initialization_receipt_path,
      sha256: state.initialization.sha256,
    },
    ledger: {
      path: state.context.ledgerPath,
      mode: "0600",
      previous_sha256: state.ledger.sha256,
      previous_bytes: state.ledger.bytes.length,
      next_sha256: candidate.sha256,
      next_bytes: candidate.bytes.length,
    },
    revision_receipt_path: receiptPath,
    previous_chain_sha256: state.chain.chainSha256,
    lock,
  };
  const revisionCommitmentSha256 = releaseCeremonyLedgerRevisionCommitmentSha256(
    receiptWithoutCommitments,
  );
  const receipt = normalizeReleaseCeremonyLedgerRevisionReceipt({
    ...receiptWithoutCommitments,
    revision_commitment_sha256: revisionCommitmentSha256,
    chain_sha256: releaseCeremonyLedgerNextChainSha256(
      state.chain.chainSha256,
      revisionCommitmentSha256,
    ),
  });
  const receiptText = canonicalReleaseCeremonyLedgerRevisionReceiptText(receipt);
  const receiptSha256 = releaseCeremonyLedgerRevisionReceiptSha256(receipt);
  const pending = normalizeReleaseCeremonyLedgerPendingJournal({
    schema: RELEASE_CEREMONY_LEDGER_PENDING_JOURNAL_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "prepared_requires_explicit_completion_or_abort",
    operation: "revision",
    release_sha: options.releaseSha,
    prepared_at: receipt.committed_at,
    writer_id: options.writerId,
    initialization_receipt_sha256: state.initialization.sha256,
    pending_journal_path: state.context.paths.pending_journal_path,
    candidate_ledger: candidate.value,
    candidate_ledger_sha256: candidate.sha256,
    candidate_ledger_bytes: candidate.bytes.length,
    candidate_stage_path: stagePaths.candidate,
    revision_receipt: receipt,
    revision_receipt_sha256: receiptSha256,
    revision_receipt_path: receiptPath,
    revision_receipt_stage_path: stagePaths.receipt,
    lock,
  });
  let pendingPublished = false;
  let candidateStage;
  let receiptStage;
  let pendingStage;
  try {
    candidateStage = createDurableStage(stagePaths.candidate, candidate.text);
    receiptStage = createDurableStage(stagePaths.receipt, receiptText);
    pendingStage = publishPending(state.context, pending, stagePaths.pending);
    pendingPublished = true;
    removeStageIfExact(stagePaths.pending, pendingStage.staged.sha256);
    maybeFault(options.faultPoint ?? null, "after-pending");
    assertHeldLock(options, lock.owner_sha256);
    durablyPublishJson({
      sourcePath: stagePaths.candidate,
      outputPath: state.context.ledgerPath,
      publishMode: "replace",
      fileMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    });
    maybeFault(options.faultPoint ?? null, "after-ledger-replace");
    assertHeldLock(options, lock.owner_sha256);
    durablyPublishJson({
      sourcePath: stagePaths.receipt,
      outputPath: receiptPath,
      publishMode: "create",
      fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
    });
    maybeFault(options.faultPoint ?? null, "after-revision-receipt");
    removeStageIfExact(stagePaths.candidate, candidateStage.sha256);
    removeStageIfExact(stagePaths.receipt, receiptStage.sha256);
    maybeFault(options.faultPoint ?? null, "after-staging-cleanup");
    assertHeldLock(options, lock.owner_sha256);
    durablyRemoveJson({
      filePath: state.context.paths.pending_journal_path,
      expectedSha256: pendingStage.sha256,
      expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    });
  } catch (error) {
    if (!pendingPublished) {
      if (pendingStage?.staged) removeStageIfExact(stagePaths.pending, pendingStage.staged.sha256);
      if (receiptStage) removeStageIfExact(stagePaths.receipt, receiptStage.sha256);
      if (candidateStage) removeStageIfExact(stagePaths.candidate, candidateStage.sha256);
    }
    throw error;
  }
  return replayReleaseCeremonyLedgerRevisionChain(options);
}

function finalizationStagePaths(context) {
  return {
    ledger: path.join(context.paths.staging_directory_path, "final-ledger.json"),
    receipt: path.join(context.paths.staging_directory_path, "finalization-receipt.json"),
    pending: path.join(context.paths.staging_directory_path, "finalization-pending.json"),
  };
}

export function finalizeReleaseCeremonyLedger(options) {
  assertReleaseSha(options.releaseSha);
  assertFaultPoint(options.faultPoint ?? null);
  if (options.writerId !== "ceremony_ledger_finalization") {
    fail("ledger finalization requires the ceremony_ledger_finalization writer");
  }
  const state = loadCeremonyState(options);
  if (state.finalized) fail("release ledger is already finalized");
  const lock = assertHeldLock(options);
  const finalization = normalizeReleaseCeremonyLedgerFinalizationReceipt({
    schema: RELEASE_CEREMONY_LEDGER_FINALIZATION_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "revision_chain_replayed_and_ledger_durably_frozen",
    release_sha: options.releaseSha,
    finalized_at: timestamp(options.now ?? new Date(), "finalization time"),
    writer_id: "ceremony_ledger_finalization",
    repository_root: state.context.repositoryRoot,
    deployment_manifest: {
      path: state.context.sourceManifestPath,
      sha256: state.source.sha256,
      bytes: state.source.bytes.length,
      mode: "0444",
    },
    initialization_receipt: {
      path: state.context.paths.initialization_receipt_path,
      sha256: state.initialization.sha256,
    },
    revision_chain: {
      revision_count: state.chain.revisionCount,
      chain_sha256: state.chain.chainSha256,
      last_revision_receipt_sha256: state.chain.lastRevisionReceiptSha256,
    },
    ledger: {
      path: state.context.ledgerPath,
      sha256: state.ledger.sha256,
      bytes: state.ledger.bytes.length,
      mode: "0444",
    },
    fresh_contract_deployment_receipt_sha256: state.source.freshReceiptSha256,
    evidence: state.context.paths,
    lock,
  });
  const stagePaths = finalizationStagePaths(state.context);
  const finalizationText = canonicalReleaseCeremonyLedgerFinalizationReceiptText(finalization);
  const finalizationSha256 = releaseCeremonyLedgerFinalizationReceiptSha256(finalization);
  const pending = normalizeReleaseCeremonyLedgerPendingJournal({
    schema: RELEASE_CEREMONY_LEDGER_PENDING_JOURNAL_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "prepared_requires_explicit_completion_or_abort",
    operation: "finalization",
    release_sha: options.releaseSha,
    prepared_at: finalization.finalized_at,
    writer_id: "ceremony_ledger_finalization",
    initialization_receipt_sha256: state.initialization.sha256,
    pending_journal_path: state.context.paths.pending_journal_path,
    ledger_sha256: state.ledger.sha256,
    ledger_bytes: state.ledger.bytes.length,
    ledger_stage_path: stagePaths.ledger,
    finalization_receipt: finalization,
    finalization_receipt_sha256: finalizationSha256,
    finalization_receipt_path: state.context.paths.finalization_receipt_path,
    finalization_receipt_stage_path: stagePaths.receipt,
    lock,
  });
  let pendingPublished = false;
  let ledgerStage;
  let receiptStage;
  let pendingStage;
  try {
    ledgerStage = createDurableStage(stagePaths.ledger, state.ledger.bytes.toString("utf8"));
    receiptStage = createDurableStage(stagePaths.receipt, finalizationText);
    pendingStage = publishPending(state.context, pending, stagePaths.pending);
    pendingPublished = true;
    removeStageIfExact(stagePaths.pending, pendingStage.staged.sha256);
    maybeFault(options.faultPoint ?? null, "after-pending");
    assertHeldLock(options, lock.owner_sha256);
    // This is intentionally a full durable replacement with the same reviewed
    // bytes and a new 0444 inode. chmod-only freezing is not an authority step.
    durablyPublishJson({
      sourcePath: stagePaths.ledger,
      outputPath: state.context.ledgerPath,
      publishMode: "replace",
      fileMode: RELEASE_CEREMONY_LEDGER_FROZEN_MODE,
    });
    maybeFault(options.faultPoint ?? null, "after-ledger-replace");
    assertHeldLock(options, lock.owner_sha256);
    durablyPublishJson({
      sourcePath: stagePaths.receipt,
      outputPath: state.context.paths.finalization_receipt_path,
      publishMode: "create",
      fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
    });
    maybeFault(options.faultPoint ?? null, "after-finalization-receipt");
    removeStageIfExact(stagePaths.ledger, ledgerStage.sha256);
    removeStageIfExact(stagePaths.receipt, receiptStage.sha256);
    maybeFault(options.faultPoint ?? null, "after-staging-cleanup");
    assertHeldLock(options, lock.owner_sha256);
    durablyRemoveJson({
      filePath: state.context.paths.pending_journal_path,
      expectedSha256: pendingStage.sha256,
      expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    });
  } catch (error) {
    if (!pendingPublished) {
      if (pendingStage?.staged) removeStageIfExact(stagePaths.pending, pendingStage.staged.sha256);
      if (receiptStage) removeStageIfExact(stagePaths.receipt, receiptStage.sha256);
      if (ledgerStage) removeStageIfExact(stagePaths.ledger, ledgerStage.sha256);
    }
    throw error;
  }
  return replayReleaseCeremonyLedgerRevisionChain(options);
}

function readPending(context) {
  const read = stableReadCanonicalJson(context.paths.pending_journal_path, {
    label: "pending ledger journal",
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES,
    normalizer: normalizeReleaseCeremonyLedgerPendingJournal,
  });
  if (read.value.pending_journal_path !== context.paths.pending_journal_path) {
    fail("pending journal path binding mismatch");
  }
  return { ...read, journal: read.value };
}

function readSignedLockRecoveryReceipt({
  lockRecoveryReceiptPath,
  lockRecoveryReceiptSha256,
  lockRoot,
  releaseSha,
  expectedObservedOwnerSha256,
  expectedReconciliationSha256,
}) {
  assertAbsolutePath(lockRecoveryReceiptPath, "signed lock-recovery receipt path");
  assertSha256(lockRecoveryReceiptSha256, "signed lock-recovery receipt digest");
  const read = stableReadCanonicalJson(lockRecoveryReceiptPath, {
    label: "signed lock-recovery receipt",
    expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
    maxBytes: 65_536,
    normalizer: normalizeSignedReleaseCeremonyLockRecoveryReceipt,
  });
  const expectedDirectory = path.join(
    lockRoot,
    `dnai-release-ceremony-${releaseSha}.recovery-receipts`,
  );
  const expectedPath = path.join(
    expectedDirectory,
    `${read.value.signed_payload_sha256.slice("sha256:".length)}.json`,
  );
  if (lockRecoveryReceiptPath !== expectedPath
    || read.sha256 !== lockRecoveryReceiptSha256
    || read.value.release_sha !== releaseSha
    || (expectedReconciliationSha256 !== null
      && read.value.chain_and_ledger_reconciliation_sha256
        !== expectedReconciliationSha256)
    || (expectedObservedOwnerSha256 !== null
      && read.value.observed_lock_owner_sha256 !== expectedObservedOwnerSha256)) {
    fail("signed lock-recovery receipt digest/path does not bind the exact preceding stale owner");
  }
  return read;
}

function pendingRecoveryOwnerTip(state, pending, options) {
  const names = fs.readdirSync(state.context.paths.recoveries_directory_path).sort();
  const transitions = new Map();
  let matchingReceipts = 0;
  for (const name of names) {
    if (!/^[0-9a-f]{64}\.json$/.test(name)) {
      fail("recovery evidence directory contains a noncanonical entry");
    }
    const receiptPath = path.join(state.context.paths.recoveries_directory_path, name);
    const ledgerRecovery = stableReadCanonicalJson(receiptPath, {
      label: "prior ledger recovery receipt",
      expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      normalizer: normalizeReleaseCeremonyLedgerRecoveryReceipt,
    });
    const receipt = ledgerRecovery.value;
    if (receipt.pending_journal.sha256 !== pending.sha256) continue;
    matchingReceipts += 1;
    if (receipt.release_sha !== options.releaseSha
      || receipt.initialization_receipt_sha256 !== state.initialization.sha256
      || receipt.original_lock_owner_sha256 !== pending.journal.lock.owner_sha256
      || receipt.pending_journal.path !== state.context.paths.pending_journal_path
      || receipt.recovery_receipt_path !== receiptPath
      || name !== `${receipt.lock_recovery_receipt.sha256.slice("sha256:".length)}.json`) {
      fail("prior ledger recovery receipt does not bind this pending operation");
    }
    const signed = readSignedLockRecoveryReceipt({
      lockRecoveryReceiptPath: receipt.lock_recovery_receipt.path,
      lockRecoveryReceiptSha256: receipt.lock_recovery_receipt.sha256,
      lockRoot: options.lockRoot,
      releaseSha: options.releaseSha,
      expectedReconciliationSha256: receipt.global_reconciliation_sha256,
      // The predecessor is checked by the complete owner-chain replay below.
      expectedObservedOwnerSha256: null,
    });
    const predecessor = signed.value.observed_lock_owner_sha256;
    if (predecessor
      !== receipt.global_reconciliation.observed_stale_lock_owner_sha256) {
      fail("prior recovery receipt global reconciliation stale-owner binding mismatch");
    }
    if (transitions.has(predecessor)
      || [...transitions.values()].includes(receipt.lock.owner_sha256)) {
      fail("prior ledger recovery receipts fork or merge the stale-owner chain");
    }
    transitions.set(predecessor, receipt.lock.owner_sha256);
  }
  let tip = pending.journal.lock.owner_sha256;
  const visited = new Set();
  while (transitions.has(tip)) {
    if (visited.has(tip)) fail("prior ledger recovery owner chain contains a cycle");
    visited.add(tip);
    tip = transitions.get(tip);
  }
  if (visited.size !== matchingReceipts) {
    fail("prior ledger recovery owner chain is disconnected from the pending writer");
  }
  return tip;
}

function reconcilePublishedRecoveryStages(state, pending, options, lock, plan) {
  const names = fs.readdirSync(state.context.paths.staging_directory_path)
    .filter((name) => /^recovery-[0-9a-f]{64}\.json$/.test(name));
  for (const name of names) {
    const stagePath = path.join(state.context.paths.staging_directory_path, name);
    const stage = stableReadCanonicalJson(stagePath, {
      label: "prior recovery receipt staging file",
      expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
      normalizer: normalizeReleaseCeremonyLedgerRecoveryReceipt,
    });
    const receipt = stage.value;
    const expectedReceiptPath = path.join(
      state.context.paths.recoveries_directory_path,
      `${receipt.lock_recovery_receipt.sha256.slice("sha256:".length)}.json`,
    );
    if (receipt.release_sha !== options.releaseSha
      || receipt.initialization_receipt_sha256 !== state.initialization.sha256
      || receipt.original_lock_owner_sha256 !== pending.journal.lock.owner_sha256
      || receipt.pending_journal.path !== state.context.paths.pending_journal_path
      || receipt.pending_journal.sha256 !== pending.sha256
      || receipt.recovery_receipt_path !== expectedReceiptPath) {
      fail("prior recovery staging file is not evidence for this pending operation");
    }
    if (receipt.resulting_ledger_sha256 !== plan.ledger.sha256
      || receipt.resulting_ledger_mode
        !== (plan.ledger.mode === RELEASE_CEREMONY_LEDGER_FROZEN_MODE ? "0444" : "0600")
      || receipt.resulting_revision_count !== state.chain.revisionCount
      || receipt.resulting_revision_chain_sha256 !== state.chain.chainSha256) {
      fail("prior recovery staging file does not reconcile to the current ledger and chain");
    }
    const priorSigned = readSignedLockRecoveryReceipt({
      lockRecoveryReceiptPath: receipt.lock_recovery_receipt.path,
      lockRecoveryReceiptSha256: receipt.lock_recovery_receipt.sha256,
      lockRoot: options.lockRoot,
      releaseSha: options.releaseSha,
      expectedObservedOwnerSha256:
        receipt.global_reconciliation.observed_stale_lock_owner_sha256,
      expectedReconciliationSha256: receipt.global_reconciliation_sha256,
    });
    if (priorSigned.value.chain_and_ledger_reconciliation_sha256
      !== receipt.global_reconciliation_sha256) {
      fail("prior recovery staging file lacks its exact signed global reconciliation");
    }
    assertHeldLock(options, lock.owner_sha256);
    if (!fs.existsSync(receipt.recovery_receipt_path)) {
      durablyPublishJson({
        sourcePath: stagePath,
        outputPath: receipt.recovery_receipt_path,
        publishMode: "create",
        fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      });
    } else {
      const published = stableReadCanonicalJson(receipt.recovery_receipt_path, {
        label: "published prior recovery receipt",
        expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
        normalizer: normalizeReleaseCeremonyLedgerRecoveryReceipt,
      });
      if (published.sha256 !== stage.sha256 || !published.bytes.equals(stage.bytes)) {
        fail("prior recovery staging file differs from its immutable published receipt");
      }
    }
    removeStageIfExact(stagePath, stage.sha256);
  }
}

function ensureStage(stagePath, text) {
  const expected = releaseCeremonyLedgerRawSha256(Buffer.from(text, "utf8"));
  if (!fs.existsSync(stagePath)) return createDurableStage(stagePath, text);
  const read = stableReadCanonicalJson(stagePath, {
    label: "recovery staging file",
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
    maxBytes: RELEASE_CEREMONY_LEDGER_MAX_EVIDENCE_BYTES,
  });
  if (read.sha256 !== expected || read.bytes.toString("utf8") !== text) {
    fail("existing recovery staging file differs from the pending journal");
  }
  return read;
}

function readOptionalReceipt(filePath, normalizer, label) {
  if (!fs.existsSync(filePath)) return null;
  return stableReadCanonicalJson(filePath, {
    label,
    expectedMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
    normalizer,
  });
}

function publishRecoveryEvidence({
  state,
  pending,
  signedRecovery,
  lock,
  options,
  action,
  resulting,
  globalReconciliation,
}) {
  const receiptPath = path.join(
    state.context.paths.recoveries_directory_path,
    `${signedRecovery.sha256.slice("sha256:".length)}.json`,
  );
  const receipt = normalizeReleaseCeremonyLedgerRecoveryReceipt({
    schema: RELEASE_CEREMONY_LEDGER_RECOVERY_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LEDGER_PROTOCOL,
    status: "explicit_signed_lock_recovery_reconciled_pending_operation",
    release_sha: options.releaseSha,
    recovered_at: timestamp(options.now ?? new Date(), "recovery time"),
    writer_id: "ceremony_ledger_recovery",
    operation: pending.journal.operation,
    operation_revision: pending.journal.operation === "revision"
      ? pending.journal.revision_receipt.revision
      : null,
    recovery_action: action,
    initialization_receipt_sha256: state.initialization.sha256,
    original_lock_owner_sha256: pending.journal.lock.owner_sha256,
    pending_journal: {
      path: state.context.paths.pending_journal_path,
      sha256: pending.sha256,
    },
    global_reconciliation: globalReconciliation,
    global_reconciliation_sha256:
      releaseCeremonyLedgerGlobalReconciliationSha256(globalReconciliation),
    lock_recovery_receipt: {
      path: options.lockRecoveryReceiptPath,
      sha256: signedRecovery.sha256,
    },
    resulting_ledger_sha256: resulting.ledgerSha256,
    resulting_ledger_mode: resulting.ledgerMode,
    resulting_revision_count: resulting.revisionCount,
    resulting_revision_chain_sha256: resulting.chainSha256,
    recovery_receipt_path: receiptPath,
    lock,
  });
  const stagePath = path.join(
    state.context.paths.staging_directory_path,
    `recovery-${signedRecovery.sha256.slice("sha256:".length)}.json`,
  );
  const receiptText = canonicalReleaseCeremonyLedgerRecoveryReceiptText(receipt);
  const stage = ensureStage(stagePath, receiptText);
  maybeFault(options.faultPoint ?? null, "before-recovery-receipt-publish");
  assertHeldLock(options, lock.owner_sha256);
  durablyPublishJson({
    sourcePath: stagePath,
    outputPath: receiptPath,
    publishMode: "create",
    fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
  });
  maybeFault(options.faultPoint ?? null, "after-recovery-receipt");
  removeStageIfExact(stagePath, stage.sha256);
  return { receipt, receiptPath };
}

function inspectRevisionPendingRecoveryState({ state, pending, options }) {
  const journal = pending.journal;
  const prepared = journal.revision_receipt;
  const expectedStages = revisionStagePaths(state.context, prepared.revision);
  if (journal.initialization_receipt_sha256 !== state.initialization.sha256
    || prepared.initialization_receipt.sha256 !== state.initialization.sha256
    || prepared.ledger.path !== state.context.ledgerPath
    || prepared.revision_receipt_path
      !== revisionReceiptPath(state.context.paths, prepared.revision)
    || journal.candidate_stage_path !== expectedStages.candidate
    || journal.revision_receipt_stage_path !== expectedStages.receipt) {
    fail("pending revision does not extend the replayed receipt chain");
  }
  const chainBeforePreparedReceipt = state.chain.revisionCount === prepared.revision - 1
    && prepared.ledger.previous_sha256 === state.chain.ledgerSha256
    && prepared.ledger.previous_bytes === state.chain.ledgerBytes
    && prepared.previous_chain_sha256 === state.chain.chainSha256;
  const chainIncludesPreparedReceipt = state.chain.revisionCount === prepared.revision
    && state.chain.lastRevisionReceiptSha256 === journal.revision_receipt_sha256
    && state.chain.ledgerSha256 === prepared.ledger.next_sha256
    && state.chain.ledgerBytes === prepared.ledger.next_bytes
    && state.chain.chainSha256 === prepared.chain_sha256;
  if (!chainBeforePreparedReceipt && !chainIncludesPreparedReceipt) {
    fail("pending revision is neither the next replay step nor the exact replayed tip");
  }
  candidateLedger({
    ...options,
    candidateLedger: journal.candidate_ledger,
    candidateLedgerText: undefined,
  }, state);
  const ledger = readLedgerAtEitherMode(state.context.ledgerPath);
  if (ledger.mode !== RELEASE_CEREMONY_LEDGER_ACTIVE_MODE) {
    fail("pending revision recovery requires an active 0600 ledger");
  }
  const existingReceipt = readOptionalReceipt(
    prepared.revision_receipt_path,
    normalizeReleaseCeremonyLedgerRevisionReceipt,
    "prepared revision receipt",
  );
  if (chainBeforePreparedReceipt
    && ledger.sha256 === prepared.ledger.previous_sha256
    && ledger.bytes.length === prepared.ledger.previous_bytes
    && existingReceipt === null) {
    return { action: "aborted_before_ledger_replace", ledger };
  }
  if (ledger.sha256 === prepared.ledger.next_sha256
    && ledger.bytes.length === prepared.ledger.next_bytes) {
    if (existingReceipt === null) {
      return { action: "completed_missing_revision_receipt", ledger };
    }
    if (!chainIncludesPreparedReceipt
      || existingReceipt.sha256 !== journal.revision_receipt_sha256
      || JSON.stringify(existingReceipt.value) !== JSON.stringify(prepared)) {
      fail("existing revision receipt differs from the pending journal or replayed tip");
    }
    return { action: "cleared_after_operation_was_complete", ledger };
  }
  fail("pending revision ledger/receipt state is ambiguous and cannot be recovered");
}

function inspectFinalizationPendingRecoveryState({ state, pending }) {
  const journal = pending.journal;
  const prepared = journal.finalization_receipt;
  const expectedStages = finalizationStagePaths(state.context);
  if (journal.initialization_receipt_sha256 !== state.initialization.sha256
    || prepared.initialization_receipt.sha256 !== state.initialization.sha256
    || prepared.revision_chain.revision_count !== state.chain.revisionCount
    || prepared.revision_chain.chain_sha256 !== state.chain.chainSha256
    || prepared.revision_chain.last_revision_receipt_sha256
      !== state.chain.lastRevisionReceiptSha256
    || prepared.ledger.path !== state.context.ledgerPath
    || prepared.ledger.sha256 !== state.chain.ledgerSha256
    || prepared.ledger.bytes !== state.chain.ledgerBytes
    || journal.finalization_receipt_path
      !== state.context.paths.finalization_receipt_path
    || journal.ledger_stage_path !== expectedStages.ledger
    || journal.finalization_receipt_stage_path !== expectedStages.receipt) {
    fail("pending finalization does not bind the replayed receipt chain");
  }
  const ledger = readLedgerAtEitherMode(state.context.ledgerPath);
  if (ledger.sha256 !== journal.ledger_sha256 || ledger.bytes.length !== journal.ledger_bytes) {
    fail("pending finalization ledger bytes changed");
  }
  validateFinalizationAgainstState({ value: prepared }, {
    context: state.context,
    source: state.source,
    initialization: state.initialization,
    chain: state.chain,
    ledger,
  });
  const existing = readOptionalReceipt(
    journal.finalization_receipt_path,
    normalizeReleaseCeremonyLedgerFinalizationReceipt,
    "prepared finalization receipt",
  );
  if (ledger.mode === RELEASE_CEREMONY_LEDGER_ACTIVE_MODE && existing === null) {
    return { action: "aborted_before_ledger_replace", ledger };
  }
  if (ledger.mode === RELEASE_CEREMONY_LEDGER_FROZEN_MODE) {
    if (existing === null) {
      return { action: "completed_missing_finalization_receipt", ledger };
    }
    if (existing.sha256 !== journal.finalization_receipt_sha256
      || JSON.stringify(existing.value) !== JSON.stringify(prepared)) {
      fail("existing finalization receipt differs from the pending journal");
    }
    return { action: "cleared_after_operation_was_complete", ledger };
  }
  fail("pending finalization ledger/receipt state is ambiguous and cannot be recovered");
}

function inspectPendingRecoveryState({ state, pending, options }) {
  return pending.journal.operation === "revision"
    ? inspectRevisionPendingRecoveryState({ state, pending, options })
    : inspectFinalizationPendingRecoveryState({ state, pending, options });
}

function assertKnownPendingStagingEntries(state, pending) {
  const expected = pending.journal.operation === "revision"
    ? revisionStagePaths(
      state.context,
      pending.journal.revision_receipt.revision,
    )
    : finalizationStagePaths(state.context);
  const allowed = new Set(Object.values(expected).map((filePath) => path.basename(filePath)));
  for (const name of fs.readdirSync(state.context.paths.staging_directory_path)) {
    if (!allowed.has(name) && !/^recovery-[0-9a-f]{64}\.json$/.test(name)) {
      fail("staging directory contains evidence unrelated to the pending operation");
    }
  }
}

function onchainReconciliationDigest(options) {
  const primary = options.onchainSignerNonceFinalizedStateReconciliationSha256;
  const alias = options.onChainSignerNonceFinalizedStateReconciliationSha256;
  if (primary !== undefined && alias !== undefined && primary !== alias) {
    fail("on-chain reconciliation digest aliases disagree");
  }
  return assertSha256(
    primary ?? alias,
    "on-chain signer nonce and finalized-state reconciliation digest",
  );
}

function globalReconciliationForState({ state, pending, options, observedOwnerSha256, plan }) {
  return projectReleaseCeremonyLedgerGlobalReconciliation({
    releaseSha: options.releaseSha,
    observedStaleLockOwnerSha256: observedOwnerSha256,
    deploymentManifestSha256: state.source.sha256,
    initializationReceiptSha256: state.initialization.sha256,
    currentLedgerSha256: plan.ledger.sha256,
    revisionChainHeadSha256:
      state.chain.lastRevisionReceiptSha256 ?? state.initialization.sha256,
    revisionCount: state.chain.revisionCount,
    revisionChainSha256: state.chain.chainSha256,
    onchainSignerNonceFinalizedStateReconciliationSha256:
      onchainReconciliationDigest(options),
    pendingJournalSha256: pending.sha256,
    pendingOperation: pending.journal.operation,
    pendingRevision: pending.journal.operation === "revision"
      ? pending.journal.revision_receipt.revision
      : null,
    pendingRecoveryAction: plan.action,
  });
}

export function projectCurrentReleaseCeremonyLedgerGlobalReconciliation(options) {
  assertReleaseSha(options.releaseSha);
  const observedOwnerSha256 = assertSha256(
    options.observedStaleLockOwnerSha256,
    "observed stale lock owner digest",
  );
  const state = loadCeremonyState(options, {
    allowPending: true,
    allowStaging: true,
    verifyLedger: false,
  });
  if (!fs.existsSync(state.context.paths.pending_journal_path)) {
    fail("global reconciliation projection requires an exact pending journal");
  }
  const pending = readPending(state.context);
  if (pending.journal.release_sha !== options.releaseSha
    || pending.journal.initialization_receipt_sha256 !== state.initialization.sha256) {
    fail("pending journal release or initialization binding mismatch");
  }
  assertKnownPendingStagingEntries(state, pending);
  const plan = inspectPendingRecoveryState({ state, pending, options });
  return globalReconciliationForState({
    state,
    pending,
    options,
    observedOwnerSha256,
    plan,
  });
}

function recoverRevisionPending({ state, pending, options, lock }) {
  const journal = pending.journal;
  const prepared = journal.revision_receipt;
  if (journal.initialization_receipt_sha256 !== state.initialization.sha256
    || prepared.initialization_receipt.sha256 !== state.initialization.sha256
    || prepared.ledger.path !== state.context.ledgerPath
    || prepared.revision_receipt_path
      !== revisionReceiptPath(state.context.paths, prepared.revision)) {
    fail("pending revision does not extend the replayed receipt chain");
  }
  const chainBeforePreparedReceipt = state.chain.revisionCount === prepared.revision - 1
    && prepared.ledger.previous_sha256 === state.chain.ledgerSha256
    && prepared.ledger.previous_bytes === state.chain.ledgerBytes
    && prepared.previous_chain_sha256 === state.chain.chainSha256;
  const chainIncludesPreparedReceipt = state.chain.revisionCount === prepared.revision
    && state.chain.lastRevisionReceiptSha256 === journal.revision_receipt_sha256
    && state.chain.ledgerSha256 === prepared.ledger.next_sha256
    && state.chain.ledgerBytes === prepared.ledger.next_bytes
    && state.chain.chainSha256 === prepared.chain_sha256;
  if (!chainBeforePreparedReceipt && !chainIncludesPreparedReceipt) {
    fail("pending revision is neither the next replay step nor the exact replayed tip");
  }
  candidateLedger({
    ...options,
    candidateLedger: journal.candidate_ledger,
    candidateLedgerText: undefined,
  }, state);
  const ledger = readLedgerAtEitherMode(state.context.ledgerPath);
  if (ledger.mode !== RELEASE_CEREMONY_LEDGER_ACTIVE_MODE) {
    fail("pending revision recovery requires an active 0600 ledger");
  }
  const existingReceipt = readOptionalReceipt(
    prepared.revision_receipt_path,
    normalizeReleaseCeremonyLedgerRevisionReceipt,
    "prepared revision receipt",
  );
  let action;
  let resultingChain = state.chain;
  if (chainBeforePreparedReceipt
    && ledger.sha256 === prepared.ledger.previous_sha256
    && ledger.bytes.length === prepared.ledger.previous_bytes
    && existingReceipt === null) {
    action = "aborted_before_ledger_replace";
  } else if (ledger.sha256 === prepared.ledger.next_sha256
    && ledger.bytes.length === prepared.ledger.next_bytes) {
    if (existingReceipt === null) {
      const receiptText = canonicalReleaseCeremonyLedgerRevisionReceiptText(prepared);
      ensureStage(journal.revision_receipt_stage_path, receiptText);
      assertHeldLock(options, lock.owner_sha256);
      durablyPublishJson({
        sourcePath: journal.revision_receipt_stage_path,
        outputPath: journal.revision_receipt_path,
        publishMode: "create",
        fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      });
      action = "completed_missing_revision_receipt";
    } else {
      if (existingReceipt.sha256 !== journal.revision_receipt_sha256
        || JSON.stringify(existingReceipt.value) !== JSON.stringify(prepared)) {
        fail("existing revision receipt differs from the pending journal");
      }
      action = "cleared_after_operation_was_complete";
    }
    resultingChain = chainIncludesPreparedReceipt
      ? state.chain
      : readRevisionReceipts(state.context, state.initialization);
    if (resultingChain.revisionCount !== prepared.revision
      || resultingChain.ledgerSha256 !== ledger.sha256
      || resultingChain.chainSha256 !== prepared.chain_sha256) {
      fail("completed pending revision does not replay to the current ledger");
    }
  } else {
    fail("pending revision ledger/receipt state is ambiguous and cannot be recovered");
  }
  return {
    action,
    resulting: {
      ledgerSha256: ledger.sha256,
      ledgerMode: "0600",
      revisionCount: resultingChain.revisionCount,
      chainSha256: resultingChain.chainSha256,
    },
    stageBindings: [
      [journal.candidate_stage_path, journal.candidate_ledger_sha256],
      [journal.revision_receipt_stage_path, journal.revision_receipt_sha256],
      [revisionStagePaths(state.context, prepared.revision).pending, pending.sha256],
    ],
  };
}

function recoverFinalizationPending({ state, pending, options, lock }) {
  const journal = pending.journal;
  const prepared = journal.finalization_receipt;
  if (journal.initialization_receipt_sha256 !== state.initialization.sha256
    || prepared.initialization_receipt.sha256 !== state.initialization.sha256
    || prepared.revision_chain.revision_count !== state.chain.revisionCount
    || prepared.revision_chain.chain_sha256 !== state.chain.chainSha256
    || prepared.revision_chain.last_revision_receipt_sha256
      !== state.chain.lastRevisionReceiptSha256
    || prepared.ledger.path !== state.context.ledgerPath
    || prepared.ledger.sha256 !== state.chain.ledgerSha256
    || prepared.ledger.bytes !== state.chain.ledgerBytes) {
    fail("pending finalization does not bind the replayed receipt chain");
  }
  const ledger = readLedgerAtEitherMode(state.context.ledgerPath);
  if (ledger.sha256 !== journal.ledger_sha256 || ledger.bytes.length !== journal.ledger_bytes) {
    fail("pending finalization ledger bytes changed");
  }
  const existing = readOptionalReceipt(
    journal.finalization_receipt_path,
    normalizeReleaseCeremonyLedgerFinalizationReceipt,
    "prepared finalization receipt",
  );
  let action;
  if (ledger.mode === RELEASE_CEREMONY_LEDGER_ACTIVE_MODE && existing === null) {
    action = "aborted_before_ledger_replace";
  } else if (ledger.mode === RELEASE_CEREMONY_LEDGER_FROZEN_MODE) {
    if (existing === null) {
      const receiptText = canonicalReleaseCeremonyLedgerFinalizationReceiptText(prepared);
      ensureStage(journal.finalization_receipt_stage_path, receiptText);
      assertHeldLock(options, lock.owner_sha256);
      durablyPublishJson({
        sourcePath: journal.finalization_receipt_stage_path,
        outputPath: journal.finalization_receipt_path,
        publishMode: "create",
        fileMode: RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
      });
      action = "completed_missing_finalization_receipt";
    } else {
      if (existing.sha256 !== journal.finalization_receipt_sha256
        || JSON.stringify(existing.value) !== JSON.stringify(prepared)) {
        fail("existing finalization receipt differs from the pending journal");
      }
      action = "cleared_after_operation_was_complete";
    }
  } else {
    fail("pending finalization ledger/receipt state is ambiguous and cannot be recovered");
  }
  return {
    action,
    resulting: {
      ledgerSha256: ledger.sha256,
      ledgerMode: ledger.mode === RELEASE_CEREMONY_LEDGER_FROZEN_MODE ? "0444" : "0600",
      revisionCount: state.chain.revisionCount,
      chainSha256: state.chain.chainSha256,
    },
    stageBindings: [
      [journal.ledger_stage_path, journal.ledger_sha256],
      [journal.finalization_receipt_stage_path, journal.finalization_receipt_sha256],
      [finalizationStagePaths(state.context).pending, pending.sha256],
    ],
  };
}

export function recoverPendingReleaseCeremonyLedgerOperation(options) {
  assertReleaseSha(options.releaseSha);
  assertFaultPoint(options.faultPoint ?? null);
  if (options.writerId !== "ceremony_ledger_recovery") {
    fail("pending recovery requires the ceremony_ledger_recovery writer");
  }
  const state = loadCeremonyState(options, {
    allowPending: true,
    allowStaging: true,
    verifyLedger: false,
  });
  if (!fs.existsSync(state.context.paths.pending_journal_path)) {
    fail("no pending journal exists; recovery refuses to invent work");
  }
  const pending = readPending(state.context);
  if (pending.journal.release_sha !== options.releaseSha
    || pending.journal.initialization_receipt_sha256 !== state.initialization.sha256) {
    fail("pending journal release or initialization binding mismatch");
  }
  assertKnownPendingStagingEntries(state, pending);
  // The new signed receipt is checked against the exact global reconciliation
  // projected from the current filesystem and caller-supplied on-chain
  // nonce/finality reconciliation digest.
  const plan = inspectPendingRecoveryState({ state, pending, options });
  const signedRecovery = readSignedLockRecoveryReceipt({
    lockRecoveryReceiptPath: options.lockRecoveryReceiptPath,
    lockRecoveryReceiptSha256: options.lockRecoveryReceiptSha256,
    lockRoot: options.lockRoot,
    releaseSha: options.releaseSha,
    expectedObservedOwnerSha256: null,
    expectedReconciliationSha256: null,
  });
  const globalReconciliation = globalReconciliationForState({
    state,
    pending,
    options,
    observedOwnerSha256: signedRecovery.value.observed_lock_owner_sha256,
    plan,
  });
  if (signedRecovery.value.chain_and_ledger_reconciliation_sha256
    !== releaseCeremonyLedgerGlobalReconciliationSha256(globalReconciliation)) {
    fail("signed lock-recovery receipt global reconciliation digest mismatch");
  }
  const lock = assertHeldLock(options);
  reconcilePublishedRecoveryStages(state, pending, options, lock, plan);
  // Publishing any exact durable receipt stage left by a previously crashed
  // recovery makes the complete stale-owner evidence chain replayable before
  // this recovery performs another pending-state transition.
  pendingRecoveryOwnerTip(state, pending, options);
  const reconciliation = pending.journal.operation === "revision"
    ? recoverRevisionPending({ state, pending, options, lock })
    : recoverFinalizationPending({ state, pending, options, lock });
  if (reconciliation.action !== plan.action
    || reconciliation.resulting.ledgerSha256 !== plan.ledger.sha256) {
    fail("pending recovery state changed after the signed global reconciliation check");
  }
  const recoveryEvidence = publishRecoveryEvidence({
    state,
    pending,
    signedRecovery,
    lock,
    options,
    action: reconciliation.action,
    resulting: reconciliation.resulting,
    globalReconciliation,
  });
  for (const [stagePath, digest] of reconciliation.stageBindings) {
    removeStageIfExact(stagePath, digest);
  }
  assertHeldLock(options, lock.owner_sha256);
  durablyRemoveJson({
    filePath: state.context.paths.pending_journal_path,
    expectedSha256: pending.sha256,
    expectedMode: RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  });
  const replay = replayReleaseCeremonyLedgerRevisionChain(options);
  return {
    ...replay,
    recovery_action: reconciliation.action,
    recovery_receipt_path: recoveryEvidence.receiptPath,
    recovery_receipt_sha256:
      releaseCeremonyLedgerRecoveryReceiptSha256(recoveryEvidence.receipt),
  };
}

export const recoverPendingReleaseCeremonyLedgerRevision =
  recoverPendingReleaseCeremonyLedgerOperation;
export const recoverPendingRevision = recoverPendingReleaseCeremonyLedgerOperation;
