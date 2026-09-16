#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  canonicalRoyaltyReleaseHistoryReceiptText,
  normalizeRoyaltyReleaseHistoryReceipt,
  projectRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "./royalty-release-history-receipt-core.mjs";
import {
  canonicalRoyaltyFinalizedHistoryEvidenceText,
  normalizeRoyaltyFinalizedHistoryEvidence,
  royaltyFinalizedHistoryEvidenceSha256,
  verifyRoyaltyFinalizedHistoryEvidenceAgainstFrozenLedger,
} from "./royalty-release-finalized-history-evidence.mjs";

export const ROYALTY_RELEASE_HISTORY_CREATE_RECEIPT_SCHEMA =
  "dnai.royalty-release-history-create-receipt.v1";
export const ROYALTY_RELEASE_HISTORY_VERIFY_RECEIPT_SCHEMA =
  "dnai.royalty-release-history-verification-receipt.v1";

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_BYTES = 4 * 1024 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

export class RoyaltyReleaseHistoryReceiptCliError extends Error {}

function fail(message) {
  throw new RoyaltyReleaseHistoryReceiptCliError(message);
}

function rawSha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function stableReadCanonical(filePath, label, normalizer, canonicalizer) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    fail(`${label} path must be canonical and absolute`);
  }
  let real;
  try { real = fs.realpathSync.native(filePath); } catch { fail(`${label} does not exist`); }
  if (real !== filePath) fail(`${label} path must be symlink-free`);
  const before = fs.lstatSync(filePath, { bigint: true });
  const uid = typeof process.geteuid === "function" ? BigInt(process.geteuid()) : before.uid;
  const mode = Number(before.mode & 0o777n);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n
    || before.uid !== uid || (mode & 0o022) !== 0
    || before.size < 2n || before.size > BigInt(MAX_BYTES)) {
    fail(`${label} must be a bounded operator-owned single-link non-writable file`);
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
    let parsed;
    try { parsed = JSON.parse(bytes.toString("utf8")); } catch { fail(`${label} is not JSON`); }
    let normalized;
    try { normalized = normalizer(parsed); } catch (error) {
      fail(`${label} is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    const canonical = canonicalizer(normalized);
    if (canonical !== bytes.toString("utf8")) {
      fail(`${label} must use canonical recursively sorted JSON with one final newline`);
    }
    return { value: normalized, bytes, raw_sha256: rawSha256(bytes) };
  } finally {
    fs.closeSync(fd);
  }
}

function writeExclusiveImmutable(filePath, text, inputPaths) {
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length < 2 || bytes.length > MAX_BYTES) fail("H output exceeds the byte bound");
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath
    || inputPaths.includes(filePath) || fs.existsSync(filePath)) {
    fail("H output must be an absent canonical absolute path distinct from every input");
  }
  const parent = path.dirname(filePath);
  if (fs.realpathSync.native(parent) !== parent) fail("H output parent must be canonical");
  const stat = fs.lstatSync(parent);
  const uid = typeof process.geteuid === "function" ? process.geteuid() : stat.uid;
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== uid
    || (stat.mode & 0o077) !== 0) {
    fail("H output parent must be operator-owned mode 0700 without symlinks");
  }
  const staging = path.join(parent, `.royalty-h-${randomBytes(16).toString("hex")}.tmp`);
  let fd;
  try {
    fd = fs.openSync(
      staging,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      0o600,
    );
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (count < 1) fail("H output write did not make progress");
      offset += count;
    }
    fs.fsyncSync(fd);
    fs.fchmodSync(fd, 0o444);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.linkSync(staging, filePath);
    fs.unlinkSync(staging);
    const parentFd = fs.openSync(parent, fs.constants.O_RDONLY);
    try { fs.fsyncSync(parentFd); } finally { fs.closeSync(parentFd); }
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try { if (fs.existsSync(staging)) fs.unlinkSync(staging); } catch {}
    throw error;
  }
  const stored = stableReadCanonical(
    filePath,
    "created H",
    normalizeRoyaltyReleaseHistoryReceipt,
    canonicalRoyaltyReleaseHistoryReceiptText,
  );
  if (!stored.bytes.equals(bytes) || (fs.statSync(filePath).mode & 0o777) !== 0o444) {
    fail("created H did not survive immutable reread verification");
  }
  return stored;
}

function projectFromEvidence(evidence, ledgerOptions) {
  const normalized = verifyRoyaltyFinalizedHistoryEvidenceAgainstFrozenLedger(
    evidence,
    ledgerOptions,
  ).evidence;
  const receipt = projectRoyaltyReleaseHistoryReceipt({
    contracts: normalized.contracts,
    commonFinalizedState: normalized.common_finalized_state,
    royaltyReleaseHistory: normalized.royalty_release_history,
  });
  if (receipt.schema !== "dnai.royalty-release-history-receipt.v2"
    || receipt.execution_mode !== normalized.execution_mode) {
    fail("production evidence did not project canonical Royalty H v2");
  }
  return { evidence: normalized, receipt };
}

function boundedReceipt(
  schema,
  status,
  evidence,
  receipt,
  rawOutputSha256,
  rawEvidenceSha256,
) {
  if (typeof rawOutputSha256 !== "string" || !SHA256.test(rawOutputSha256)
    || typeof rawEvidenceSha256 !== "string" || !SHA256.test(rawEvidenceSha256)) {
    fail("bounded receipt requires canonical raw artifact digests");
  }
  return {
    schema,
    status,
    truth_status:
      "canonical_h_structure_digest_and_replayed_frozen_ledger_lineage_verified_not_fresh_rpc_or_signed_live_authority",
    release_sha: evidence.release_sha,
    execution_mode: evidence.execution_mode,
    frozen_final_ledger_sha256: evidence.frozen_final_ledger_sha256,
    ledger_finalization_receipt_sha256:
      evidence.ledger_finalization_receipt_sha256,
    ledger_revision_chain_sha256: evidence.ledger_revision_chain_sha256,
    common_finalized_state_sha256: receipt.common_finalized_state_sha256,
    royalty_release_history_sha256: receipt.royalty_release_history_sha256,
    royalty_release_history_receipt_sha256:
      royaltyReleaseHistoryReceiptSha256(receipt),
    finalized_history_evidence_sha256:
      royaltyFinalizedHistoryEvidenceSha256(evidence),
    raw_finalized_history_evidence_sha256: rawEvidenceSha256,
    raw_output_sha256: rawOutputSha256,
  };
}

export function createRoyaltyReleaseHistoryReceipt({
  evidence,
  outputPath,
  inputPath,
  rawEvidenceSha256,
  ledgerOptions,
}) {
  const projected = projectFromEvidence(evidence, ledgerOptions);
  const text = canonicalRoyaltyReleaseHistoryReceiptText(projected.receipt);
  const written = writeExclusiveImmutable(outputPath, text, [inputPath]);
  return boundedReceipt(
    ROYALTY_RELEASE_HISTORY_CREATE_RECEIPT_SCHEMA,
    "canonical_royalty_release_history_receipt_v2_written_create_only",
    projected.evidence,
    projected.receipt,
    written.raw_sha256,
    rawEvidenceSha256,
  );
}

export function verifyRoyaltyReleaseHistoryReceipt({
  evidence,
  receipt,
  expectedRoyaltyReleaseHistoryReceiptSha256,
  rawReceiptSha256,
  rawEvidenceSha256,
  ledgerOptions,
}) {
  if (typeof expectedRoyaltyReleaseHistoryReceiptSha256 !== "string"
    || !SHA256.test(expectedRoyaltyReleaseHistoryReceiptSha256)
    || expectedRoyaltyReleaseHistoryReceiptSha256 === `sha256:${"0".repeat(64)}`) {
    fail("expected H digest must be a canonical nonzero SHA-256 pin");
  }
  const projected = projectFromEvidence(evidence, ledgerOptions);
  const normalizedReceipt = normalizeRoyaltyReleaseHistoryReceipt(receipt);
  if (canonicalRoyaltyReleaseHistoryReceiptText(projected.receipt)
      !== canonicalRoyaltyReleaseHistoryReceiptText(normalizedReceipt)) {
    fail("persisted H differs from the frozen finalized-history evidence projection");
  }
  const digest = royaltyReleaseHistoryReceiptSha256(normalizedReceipt);
  if (digest !== expectedRoyaltyReleaseHistoryReceiptSha256) {
    fail("persisted H digest differs from the required expected digest");
  }
  return boundedReceipt(
    ROYALTY_RELEASE_HISTORY_VERIFY_RECEIPT_SCHEMA,
    "canonical_royalty_release_history_receipt_v2_verified",
    projected.evidence,
    normalizedReceipt,
    rawReceiptSha256,
    rawEvidenceSha256,
  );
}

function parseArgs(argv) {
  const command = argv[0];
  if (!new Set(["create", "verify"]).has(command)) fail("command must be create or verify");
  const common = [
    "--repository-root", "--source-manifest", "--ledger", "--evidence-root",
    "--lock-root", "--release-sha", "--deployment-intent-sha256",
    "--reviewer-genesis-acceptance-sha256",
    "--tinker-account-binding-ceremony-receipt-sha256",
  ];
  const commandFlags = command === "create"
    ? ["--input", "--out"]
    : [
      "--input", "--in", "--expected-royalty-release-history-receipt-sha256",
    ];
  const allowed = new Set([...common, ...commandFlags]);
  const values = new Map();
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(key) || value === undefined || values.has(key)) {
      fail("arguments must be unique supported --name value pairs");
    }
    values.set(key, value);
  }
  if ([...allowed].some((key) => !values.has(key))) fail(`${command} arguments are incomplete`);
  return { command, values };
}

function ledgerOptions(values, frozenLedgerLoader) {
  return {
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
    ...(frozenLedgerLoader ? { frozenLedgerLoader } : {}),
  };
}

export function runRoyaltyReleaseHistoryReceiptCli(
  argv,
  { frozenLedgerLoader } = {},
) {
  const { command, values } = parseArgs(argv);
  const inputPath = values.get("--input");
  const evidenceRead = stableReadCanonical(
    inputPath,
    "finalized Royalty history evidence",
    normalizeRoyaltyFinalizedHistoryEvidence,
    canonicalRoyaltyFinalizedHistoryEvidenceText,
  );
  const lineageOptions = ledgerOptions(values, frozenLedgerLoader);
  if (command === "create") {
    return createRoyaltyReleaseHistoryReceipt({
      evidence: evidenceRead.value,
      outputPath: values.get("--out"),
      inputPath,
      rawEvidenceSha256: evidenceRead.raw_sha256,
      ledgerOptions: lineageOptions,
    });
  }
  const receiptRead = stableReadCanonical(
    values.get("--in"),
    "Royalty H",
    normalizeRoyaltyReleaseHistoryReceipt,
    canonicalRoyaltyReleaseHistoryReceiptText,
  );
  const result = verifyRoyaltyReleaseHistoryReceipt({
    evidence: evidenceRead.value,
    receipt: receiptRead.value,
    expectedRoyaltyReleaseHistoryReceiptSha256:
      values.get("--expected-royalty-release-history-receipt-sha256"),
    rawReceiptSha256: receiptRead.raw_sha256,
    rawEvidenceSha256: evidenceRead.raw_sha256,
    ledgerOptions: lineageOptions,
  });
  return result;
}

function main(argv) {
  process.stdout.write(`${JSON.stringify(
    runRoyaltyReleaseHistoryReceiptCli(argv),
  )}\n`);
}

const invoked = process.argv[1] ? path.resolve(process.argv[1]) : "";
if (invoked && import.meta.url === pathToFileURL(invoked).href) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
