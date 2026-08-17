#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import {
  canonicalReleaseCeremonyLedgerJsonText,
  commitReleaseCeremonyLedgerRevision,
  finalizeReleaseCeremonyLedger,
  initializeReleaseCeremonyLedger,
  recoverPendingReleaseCeremonyLedgerOperation,
  replayReleaseCeremonyLedgerRevisionChain,
  RELEASE_CEREMONY_LEDGER_MAX_BYTES,
} from "./release-ceremony-ledger.mjs";

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

function fail(message) {
  throw new Error(`release ceremony ledger CLI: ${message}`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!["initialize", "replay", "commit", "finalize", "recover"].includes(command)) {
    fail("command must be initialize, replay, commit, finalize, or recover");
  }
  const allowed = new Set([
    "--candidate",
    "--deployment-intent-sha256",
    "--evidence-root",
    "--fault-stage",
    "--ledger",
    "--lock-root",
    "--lock-recovery-receipt",
    "--lock-recovery-receipt-sha256",
    "--onchain-signer-nonce-finalized-state-reconciliation-sha256",
    "--owner-token",
    "--release-sha",
    "--repository-root",
    "--reviewer-genesis-acceptance-sha256",
    "--source-manifest",
    "--tinker-account-binding-ceremony-receipt-sha256",
    "--writer-id",
  ]);
  const values = new Map();
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!allowed.has(flag)) fail(`unknown argument: ${flag ?? "<missing>"}`);
    if (value === undefined || value.startsWith("--")) {
      fail(`missing value for ${flag}`);
    }
    if (values.has(flag)) fail(`duplicate argument: ${flag}`);
    values.set(flag, value);
  }
  const common = [
    "--deployment-intent-sha256",
    "--evidence-root",
    "--ledger",
    "--lock-root",
    "--release-sha",
    "--repository-root",
    "--reviewer-genesis-acceptance-sha256",
    "--source-manifest",
    "--tinker-account-binding-ceremony-receipt-sha256",
  ];
  const required = command === "replay"
    ? common
    : [...common, "--owner-token", "--writer-id"];
  if (command === "commit") required.push("--candidate");
  if (command === "recover") {
    required.push(
      "--lock-recovery-receipt",
      "--lock-recovery-receipt-sha256",
      "--onchain-signer-nonce-finalized-state-reconciliation-sha256",
    );
  }
  for (const flag of required) {
    if (!values.has(flag)) fail(`${flag} is required for ${command}`);
  }
  if (command !== "commit" && values.has("--candidate")) {
    fail(`--candidate is not accepted for ${command}`);
  }
  if (!["commit", "finalize"].includes(command) && values.has("--fault-stage")) {
    fail(`--fault-stage is not accepted for ${command}`);
  }
  if (command !== "recover" && [
    "--lock-recovery-receipt",
    "--lock-recovery-receipt-sha256",
    "--onchain-signer-nonce-finalized-state-reconciliation-sha256",
  ].some((flag) => values.has(flag))) {
    fail(`lock-recovery arguments are not accepted for ${command}`);
  }
  if (command === "replay"
    && (values.has("--owner-token") || values.has("--writer-id"))) {
    fail("replay does not accept lock-owner credentials");
  }
  return { command, values };
}

function readCandidate(candidatePath) {
  if (typeof candidatePath !== "string"
    || !path.isAbsolute(candidatePath)
    || path.resolve(candidatePath) !== candidatePath
    || path.normalize(candidatePath) !== candidatePath) {
    fail("candidate path must be canonical and absolute");
  }
  let canonicalPath;
  try {
    canonicalPath = fs.realpathSync.native(candidatePath);
  } catch {
    fail("candidate path does not exist");
  }
  if (canonicalPath !== candidatePath) {
    fail("candidate path must be canonical and symlink-free");
  }
  const before = fs.lstatSync(candidatePath, { bigint: true });
  const uid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    fail("candidate must be a single-link non-symlink regular file");
  }
  if (before.uid !== uid || (before.mode & 0o077n) !== 0n) {
    fail("candidate must be operator-owned and private");
  }
  if (before.size < 2n
    || before.size > BigInt(RELEASE_CEREMONY_LEDGER_MAX_BYTES)) {
    fail("candidate exceeds the bounded ledger size");
  }
  const snapshot = (stat) => ({
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  });
  const sameSnapshot = (left, right) => Object.keys(left)
    .every((key) => left[key] === right[key]);
  const beforeSnapshot = snapshot(before);
  const fd = fs.openSync(candidatePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const openedSnapshot = snapshot(opened);
    if (!opened.isFile() || opened.nlink !== 1n
      || !sameSnapshot(beforeSnapshot, openedSnapshot)) {
      fail("candidate changed while it was opened");
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) fail("candidate ended during read");
      offset += count;
    }
    const afterSnapshot = snapshot(fs.fstatSync(fd, { bigint: true }));
    const currentSnapshot = snapshot(fs.lstatSync(candidatePath, { bigint: true }));
    let finalCanonicalPath;
    try {
      finalCanonicalPath = fs.realpathSync.native(candidatePath);
    } catch {
      fail("candidate path changed during read");
    }
    if (!sameSnapshot(openedSnapshot, afterSnapshot)
      || !sameSnapshot(afterSnapshot, currentSnapshot)
      || finalCanonicalPath !== candidatePath) {
      fail("candidate changed during read");
    }
    const text = bytes.toString("utf8");
    let value;
    try {
      value = JSON.parse(text);
    } catch (error) {
      fail(`candidate is not JSON: ${error.message}`);
    }
    if (canonicalReleaseCeremonyLedgerJsonText(value) !== text) {
      fail(
        "candidate must be recursively sorted, two-space canonical JSON with one trailing newline",
      );
    }
    return text;
  } finally {
    fs.closeSync(fd);
  }
}

function commonOptions(values) {
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
  };
}

function run(argv) {
  const { command, values } = parseArgs(argv);
  const options = commonOptions(values);
  if (command === "replay") {
    return replayReleaseCeremonyLedgerRevisionChain(options);
  }
  Object.assign(options, {
    writerId: values.get("--writer-id"),
    ownerToken: values.get("--owner-token"),
  });
  if (command === "initialize") {
    return initializeReleaseCeremonyLedger(options);
  }
  if (command === "finalize") {
    return finalizeReleaseCeremonyLedger({
      ...options,
      faultPoint: values.get("--fault-stage") ?? null,
    });
  }
  if (command === "recover") {
    return recoverPendingReleaseCeremonyLedgerOperation({
      ...options,
      lockRecoveryReceiptPath: values.get("--lock-recovery-receipt"),
      lockRecoveryReceiptSha256:
        values.get("--lock-recovery-receipt-sha256"),
      onchainSignerNonceFinalizedStateReconciliationSha256:
        values.get("--onchain-signer-nonce-finalized-state-reconciliation-sha256"),
    });
  }
  const replay = replayReleaseCeremonyLedgerRevisionChain(options);
  return commitReleaseCeremonyLedgerRevision({
    ...options,
    candidateLedgerText: readCandidate(values.get("--candidate")),
    expectedRevision: replay.revision_count,
    expectedLedgerSha256: replay.current_ledger_sha256,
    faultPoint: values.get("--fault-stage") ?? null,
  });
}

try {
  process.stdout.write(`${JSON.stringify(run(process.argv.slice(2)))}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
}
