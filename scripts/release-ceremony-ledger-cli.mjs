#!/usr/bin/env node

import fs from "node:fs";
import process from "node:process";

import {
  commitReleaseCeremonyLedgerRevision,
  initializeReleaseCeremonyLedger,
  replayReleaseCeremonyLedgerRevisionChain,
  RELEASE_CEREMONY_LEDGER_MAX_BYTES,
} from "./release-ceremony-ledger.mjs";

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

function fail(message) {
  throw new Error(`release ceremony ledger CLI: ${message}`);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!["initialize", "replay", "commit"].includes(command)) {
    fail("command must be initialize, replay, or commit");
  }
  const allowed = new Set([
    "--candidate",
    "--deployment-intent-sha256",
    "--evidence-root",
    "--fault-stage",
    "--ledger",
    "--lock-root",
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
  for (const flag of required) {
    if (!values.has(flag)) fail(`${flag} is required for ${command}`);
  }
  if (command !== "commit" && values.has("--candidate")) {
    fail(`--candidate is not accepted for ${command}`);
  }
  if (command !== "commit" && values.has("--fault-stage")) {
    fail(`--fault-stage is not accepted for ${command}`);
  }
  if (command === "replay"
    && (values.has("--owner-token") || values.has("--writer-id"))) {
    fail("replay does not accept lock-owner credentials");
  }
  return { command, values };
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function readCandidate(candidatePath) {
  if (typeof candidatePath !== "string" || !candidatePath.startsWith("/")) {
    fail("candidate path must be absolute");
  }
  const before = fs.lstatSync(candidatePath);
  const uid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    fail("candidate must be a single-link non-symlink regular file");
  }
  if (before.uid !== uid || (before.mode & 0o077) !== 0) {
    fail("candidate must be operator-owned and private");
  }
  if (before.size < 2 || before.size > RELEASE_CEREMONY_LEDGER_MAX_BYTES) {
    fail("candidate exceeds the bounded ledger size");
  }
  const fd = fs.openSync(candidatePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.nlink !== 1 || !sameInode(before, opened)) {
      fail("candidate changed while it was opened");
    }
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) fail("candidate ended during read");
      offset += count;
    }
    const after = fs.fstatSync(fd);
    const current = fs.lstatSync(candidatePath);
    if (!sameInode(opened, after)
      || !sameInode(after, current)
      || after.size !== opened.size) {
      fail("candidate changed during read");
    }
    try {
      return JSON.parse(bytes.toString("utf8"));
    } catch (error) {
      fail(`candidate is not JSON: ${error.message}`);
    }
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
  const replay = replayReleaseCeremonyLedgerRevisionChain(options);
  return commitReleaseCeremonyLedgerRevision({
    ...options,
    candidateLedger: readCandidate(values.get("--candidate")),
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
