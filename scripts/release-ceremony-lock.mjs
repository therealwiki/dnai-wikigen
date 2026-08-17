#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  normalizeExpectedReviewerAuthority,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  RELEASE_CEREMONY_LOCK_PROTOCOL,
} from "./release-ceremony-lock-protocol-core.mjs";

export { RELEASE_CEREMONY_LOCK_PROTOCOL };
export const RELEASE_CEREMONY_LOCK_OWNER_SCHEMA =
  "dnai.release-ceremony-lock-owner.v1";
export const RELEASE_CEREMONY_LOCK_RECOVERY_SCHEMA =
  "dnai.release-ceremony-lock-recovery.v4";
export const RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA =
  "dnai.release-ceremony-lock-recovery-receipt.v3";
export const RELEASE_REVIEWER_GENESIS_ANCHOR_PROOF_SCHEMA =
  "dnai.release-reviewer-genesis-anchor-proof.v1";
export const RELEASE_CEREMONY_LOCK_RECOVERY_SIGNING_DOMAIN =
  "dnai-wikigen/release-ceremony-lock-recovery-signing-payload/v4\0";
export const RELEASE_CEREMONY_LOCK_RECOVERY_MESSAGE_PREFIX =
  "dnai-wikigen release-ceremony-lock recovery v4:";
export const RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_SCHEME =
  PINNED_EIP191_SIGNATURE_SCHEME;
export const RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_VERIFIER = Object.freeze({
  ...PINNED_CAST_SIGNATURE_VERIFIER,
});
export const RELEASE_CEREMONY_LOCK_RECOVERY_DECLARATION =
  "two_distinct_current_status_reviewers_confirm_dual_rpc_immutable_genesis_acceptance_anchor_chain_nonce_and_all_release_ledgers_reconciled_before_stale_lock_removal";
export const RELEASE_CEREMONY_LOCK_MISSING_OWNER_SHA256 = `sha256:${createHash("sha256")
  .update("dnai-wikigen/release-ceremony-lock/missing-owner/v1\0", "utf8")
  .digest("hex")}`;
export const RELEASE_CEREMONY_WRITERS = Object.freeze([
  "ceremony_ledger_finalization",
  "ceremony_ledger_initialization",
  "ceremony_ledger_recovery",
  "challenge_registry_release",
  "compute_release",
  "diligence_release",
  "email_oracle_release",
  "execution_policy_anchor_release",
  "tinker_release",
]);
// This legacy export is an immutable protocol-history surface. New writers
// belong in the separately named current allowlist so recovery artifacts and
// compatibility tests can continue to pin the historical value exactly.
export const CURRENT_RELEASE_CEREMONY_WRITERS = Object.freeze([
  ...RELEASE_CEREMONY_WRITERS,
  "royalty_release",
]);

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const BYTES32 = /^0x[0-9a-f]{64}$/;
const TOKEN = /^[0-9a-f]{64}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const MAX_OWNER_BYTES = 16_384;
const MAX_RECOVERY_BYTES = 65_536;
const MAX_RECOVERY_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function exactRecord(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} fields do not match the exact schema`);
  }
  return value;
}

function exactSignatureVerifier(value) {
  const verifier = exactRecord(
    value,
    [
      "build_profile", "commit_sha", "executable_sha256",
      "executable_user_relative_path", "tool", "version",
    ],
    "recovery signature verifier",
  );
  for (const [key, expected] of Object.entries(
    RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_VERIFIER,
  )) {
    if (verifier[key] !== expected) {
      throw new Error("release ceremony lock recovery signature verifier is not the pinned toolchain");
    }
  }
  return { ...verifier };
}

function sha256Bytes(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function ownerTokenSha256(token) {
  return `sha256:${createHash("sha256")
    .update("dnai-wikigen/release-ceremony-lock/owner-token/v1\0", "utf8")
    .update(Buffer.from(token, "hex"))
    .digest("hex")}`;
}

function parseTimestamp(value, label) {
  if (typeof value !== "string"
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    throw new Error(`${label} must be canonical millisecond UTC`);
  }
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new Error(`${label} is invalid`);
  }
  return parsed;
}

function assertNoSymlinkComponents(absolutePath, { includeLeaf = true } = {}) {
  const resolved = path.resolve(absolutePath);
  if (!path.isAbsolute(absolutePath) || resolved !== absolutePath) {
    throw new Error("lock paths must be absolute and lexically canonical");
  }
  const parsed = path.parse(resolved);
  const relativeParts = resolved.slice(parsed.root.length).split(path.sep).filter(Boolean);
  let cursor = parsed.root;
  const count = includeLeaf ? relativeParts.length : Math.max(0, relativeParts.length - 1);
  for (let index = 0; index < count; index += 1) {
    cursor = path.join(cursor, relativeParts[index]);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) throw new Error("lock paths must not traverse symlinks");
  }
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function openStableDirectory(directoryPath, label, { requirePrivate = false } = {}) {
  assertNoSymlinkComponents(directoryPath);
  const before = fs.lstatSync(directoryPath);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error(`${label} must be a non-symlink directory`);
  }
  if (before.uid !== expectedUid) {
    throw new Error(`${label} must be owned by the current operator`);
  }
  if (requirePrivate && (before.mode & 0o077) !== 0) {
    throw new Error(`${label} must not grant group or other permissions`);
  }
  const fd = fs.openSync(directoryPath, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    const after = fs.lstatSync(directoryPath);
    if (!opened.isDirectory() || opened.uid !== expectedUid
      || !sameInode(before, opened) || !sameInode(opened, after)
      || opened.mode !== before.mode || after.mode !== opened.mode) {
      throw new Error(`${label} changed while it was opened`);
    }
    return { fd, stat: opened };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertDirectoryStillBound(directoryPath, expected, label, { requirePrivate = false } = {}) {
  const opened = openStableDirectory(directoryPath, label, { requirePrivate });
  try {
    if (!sameInode(opened.stat, expected)) {
      throw new Error(`${label} changed during the lock operation`);
    }
  } finally {
    fs.closeSync(opened.fd);
  }
}

function normalizeLockContext({ lockRoot, repositoryRoot, releaseSha, writerId }) {
  if (!SHA40.test(releaseSha)) throw new Error("release SHA must be lowercase 40-hex");
  if (!CURRENT_RELEASE_CEREMONY_WRITERS.includes(writerId)) {
    throw new Error("writer ID is not a supported release ceremony writer");
  }
  assertNoSymlinkComponents(lockRoot);
  assertNoSymlinkComponents(repositoryRoot);
  const canonicalLockRoot = fs.realpathSync(lockRoot);
  const canonicalRepositoryRoot = fs.realpathSync(repositoryRoot);
  if (canonicalLockRoot !== lockRoot || canonicalRepositoryRoot !== repositoryRoot) {
    throw new Error("lock root and repository root must use their canonical paths");
  }
  if (canonicalLockRoot === canonicalRepositoryRoot
    || canonicalLockRoot.startsWith(`${canonicalRepositoryRoot}${path.sep}`)) {
    throw new Error("release ceremony lock root must remain outside the source repository");
  }
  const rootDirectory = openStableDirectory(
    canonicalLockRoot,
    "lock root",
    { requirePrivate: true },
  );
  const repositoryDirectory = openStableDirectory(
    canonicalRepositoryRoot,
    "repository root",
  );
  fs.closeSync(repositoryDirectory.fd);
  fs.closeSync(rootDirectory.fd);
  const lockPath = path.join(
    canonicalLockRoot,
    `dnai-release-ceremony-${releaseSha}.lock`,
  );
  return {
    lockRoot: canonicalLockRoot,
    repositoryRoot: canonicalRepositoryRoot,
    releaseSha,
    writerId,
    lockPath,
    ownerPath: path.join(lockPath, "owner.json"),
    lockRootStat: rootDirectory.stat,
  };
}

function fsyncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY);
  try {
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function writeAllAndSync(filePath, bytes, mode) {
  const fd = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    mode,
  );
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (written < 1) throw new Error("lock metadata full write made no progress");
      offset += written;
    }
    fs.fchmodSync(fd, mode);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function readBoundedRegularFile(filePath, maxBytes, label, { testHookAfterOpen = null } = {}) {
  assertNoSymlinkComponents(filePath);
  const before = fs.lstatSync(filePath);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
    throw new Error(`${label} must be a single-link non-symlink regular file`);
  }
  if (before.size < 1 || before.size > maxBytes) {
    throw new Error(`${label} exceeds its bounded size`);
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    const afterOpen = fs.lstatSync(filePath);
    if (!opened.isFile() || opened.nlink !== 1
      || !sameInode(before, opened) || !sameInode(opened, afterOpen)
      || opened.size !== before.size) {
      throw new Error(`${label} changed while it was opened`);
    }
    if (testHookAfterOpen !== null) testHookAfterOpen({ filePath, stat: opened });
    const bytes = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`${label} changed or ended during its bounded read`);
      }
      offset += count;
    }
    const finalFd = fs.fstatSync(fd);
    const finalPath = fs.lstatSync(filePath);
    if (finalFd.nlink !== 1 || !sameInode(opened, finalFd)
      || !sameInode(finalFd, finalPath) || finalFd.size !== opened.size
      || finalFd.mtimeMs !== opened.mtimeMs || finalFd.ctimeMs !== opened.ctimeMs) {
      throw new Error(`${label} changed during its bounded read`);
    }
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

function normalizeOwner(value) {
  const owner = exactRecord(value, [
    "acquired_at",
    "owner_pid",
    "owner_token_sha256",
    "protocol",
    "release_sha",
    "schema",
    "state",
    "writer_id",
  ], "release ceremony lock owner");
  if (owner.schema !== RELEASE_CEREMONY_LOCK_OWNER_SCHEMA
    || owner.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL
    || owner.state !== "held"
    || !SHA40.test(owner.release_sha)
    || !CURRENT_RELEASE_CEREMONY_WRITERS.includes(owner.writer_id)
    || !SHA256.test(owner.owner_token_sha256)
    || !Number.isSafeInteger(owner.owner_pid)
    || owner.owner_pid < 1) {
    throw new Error("release ceremony lock owner metadata is invalid");
  }
  parseTimestamp(owner.acquired_at, "lock acquired_at");
  return owner;
}

function readOwner(context, { allowMissing = false, testHookAfterOpen = null } = {}) {
  if (!fs.existsSync(context.ownerPath)) {
    if (allowMissing) return { bytes: null, owner: null, sha256: RELEASE_CEREMONY_LOCK_MISSING_OWNER_SHA256 };
    throw new Error("release ceremony lock owner metadata is missing; reviewed recovery is required");
  }
  assertNoSymlinkComponents(context.ownerPath);
  const bytes = readBoundedRegularFile(
    context.ownerPath,
    MAX_OWNER_BYTES,
    "lock owner metadata",
    { testHookAfterOpen },
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("release ceremony lock owner metadata is not JSON");
  }
  const owner = normalizeOwner(value);
  if (bytes.toString("utf8") !== canonicalText(owner)) {
    throw new Error("release ceremony lock owner metadata is not canonical");
  }
  return { bytes, owner, sha256: sha256Bytes(bytes) };
}

export function acquireReleaseCeremonyLock({
  lockRoot,
  repositoryRoot,
  releaseSha,
  writerId,
  ownerPid,
  now = new Date(),
  token = randomBytes(32).toString("hex"),
}) {
  const context = normalizeLockContext({ lockRoot, repositoryRoot, releaseSha, writerId });
  assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", { requirePrivate: true });
  if (!Number.isSafeInteger(ownerPid) || ownerPid < 1) {
    throw new Error("owner PID must be a positive safe integer");
  }
  if (!TOKEN.test(token)) throw new Error("owner token must be lowercase 32-byte hex");
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("lock time is invalid");
  try {
    fs.mkdirSync(context.lockPath, { mode: 0o700 });
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error("release ceremony lock is held or stale; explicit reviewed recovery is required");
    }
    throw error;
  }
  fsyncDirectory(context.lockRoot);
  const lockDirectory = openStableDirectory(context.lockPath, "release ceremony lock", {
    requirePrivate: true,
  });
  fs.closeSync(lockDirectory.fd);

  const owner = {
    schema: RELEASE_CEREMONY_LOCK_OWNER_SCHEMA,
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    state: "held",
    release_sha: releaseSha,
    writer_id: writerId,
    owner_pid: ownerPid,
    owner_token_sha256: ownerTokenSha256(token),
    acquired_at: now.toISOString(),
  };
  // Any failure after mkdir intentionally leaves a fail-closed stale lock.
  writeAllAndSync(context.ownerPath, Buffer.from(canonicalText(owner), "utf8"), 0o600);
  fsyncDirectory(context.lockPath);
  fsyncDirectory(context.lockRoot);
  return {
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    lock_path: context.lockPath,
    owner_token: token,
  };
}

export function releaseReleaseCeremonyLock({
  lockRoot,
  repositoryRoot,
  releaseSha,
  writerId,
  ownerToken,
}) {
  const context = normalizeLockContext({ lockRoot, repositoryRoot, releaseSha, writerId });
  assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", { requirePrivate: true });
  if (!TOKEN.test(ownerToken)) throw new Error("owner token must be lowercase 32-byte hex");
  assertNoSymlinkComponents(context.lockPath);
  const lockStat = fs.lstatSync(context.lockPath);
  if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) {
    throw new Error("release ceremony lock is not a non-symlink directory");
  }
  const lockDirectory = openStableDirectory(context.lockPath, "release ceremony lock", {
    requirePrivate: true,
  });
  try {
    const { owner } = readOwner(context);
    if (owner.release_sha !== releaseSha
      || owner.writer_id !== writerId
      || owner.owner_token_sha256 !== ownerTokenSha256(ownerToken)) {
      throw new Error("release ceremony lock ownership does not match; reviewed recovery is required");
    }
    const entries = fs.readdirSync(context.lockPath);
    if (entries.length !== 1 || entries[0] !== "owner.json") {
      throw new Error("release ceremony lock contains unexpected evidence; reviewed recovery is required");
    }
    assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", { requirePrivate: true });
    assertDirectoryStillBound(context.lockPath, lockDirectory.stat, "release ceremony lock", {
      requirePrivate: true,
    });
    fs.unlinkSync(context.ownerPath);
    fs.fsyncSync(lockDirectory.fd);
    fs.rmdirSync(context.lockPath);
    fsyncDirectory(context.lockRoot);
  } finally {
    fs.closeSync(lockDirectory.fd);
  }
  return { protocol: RELEASE_CEREMONY_LOCK_PROTOCOL, status: "released" };
}

function normalizeSigningReviewer(value, index) {
  const reviewer = exactRecord(
    value,
    ["address", "controller_id"],
    `recovery signing reviewer ${index}`,
  );
  if (!ADDRESS.test(reviewer.address) || /^0x0+$/.test(reviewer.address)
    || !CONTROLLER.test(reviewer.controller_id)) {
    throw new Error(`recovery signing reviewer ${index} identity is invalid`);
  }
  return {
    address: reviewer.address,
    controller_id: reviewer.controller_id,
  };
}

function nonzeroSha256(value, label) {
  if (!SHA256.test(value) || value === `sha256:${"0".repeat(64)}`) {
    throw new Error(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function normalizeAnchorRpcObservation(value, label) {
  const observation = exactRecord(value, [
    "authority_id",
    "block_hash",
    "block_number",
    "contract_address",
    "deployment_intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
  ], label);
  if (!CONTROLLER.test(observation.authority_id)
    || !Number.isSafeInteger(observation.block_number)
    || observation.block_number < 1
    || !BYTES32.test(observation.block_hash)
    || /^0x0+$/.test(observation.block_hash)
    || !ADDRESS.test(observation.contract_address)
    || /^0x0+$/.test(observation.contract_address)) {
    throw new Error(`${label} identity, block, or contract address is invalid`);
  }
  return {
    authority_id: observation.authority_id,
    block_number: observation.block_number,
    block_hash: observation.block_hash,
    contract_address: observation.contract_address,
    deployment_intent_sha256: nonzeroSha256(
      observation.deployment_intent_sha256,
      `${label}.deployment_intent_sha256`,
    ),
    reviewer_authority_genesis_acceptance_sha256: nonzeroSha256(
      observation.reviewer_authority_genesis_acceptance_sha256,
      `${label}.reviewer_authority_genesis_acceptance_sha256`,
    ),
  };
}

export function normalizeReleaseReviewerGenesisAnchorProof(value, {
  expectedReleaseSha,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  const proof = exactRecord(value, [
    "chain_id",
    "common_finalized_block_hash",
    "common_finalized_block_number",
    "deployment_intent_sha256",
    "execution_policy_anchor_address",
    "fresh_contract_deployment_receipt_sha256",
    "primary_rpc",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "schema",
    "secondary_rpc",
    "truth_status",
  ], "release reviewer genesis anchor proof");
  if (proof.schema !== RELEASE_REVIEWER_GENESIS_ANCHOR_PROOF_SCHEMA
    || proof.truth_status
      !== "dual_rpc_common_finalized_execution_policy_anchor_immutable_getters_observed"
    || proof.chain_id !== 84_532
    || !SHA40.test(expectedReleaseSha || "")
    || proof.release_sha !== expectedReleaseSha
    || !Number.isSafeInteger(proof.common_finalized_block_number)
    || proof.common_finalized_block_number < 1
    || !BYTES32.test(proof.common_finalized_block_hash)
    || /^0x0+$/.test(proof.common_finalized_block_hash)
    || !ADDRESS.test(proof.execution_policy_anchor_address)
    || /^0x0+$/.test(proof.execution_policy_anchor_address)) {
    throw new Error("release reviewer genesis anchor proof header is invalid");
  }
  const deploymentIntentSha256 = nonzeroSha256(
    proof.deployment_intent_sha256,
    "anchor proof deployment intent SHA-256",
  );
  const reviewerAuthorityGenesisAcceptanceSha256 = nonzeroSha256(
    proof.reviewer_authority_genesis_acceptance_sha256,
    "anchor proof signed reviewer genesis acceptance SHA-256",
  );
  if (!SHA256.test(expectedReviewerAuthorityGenesisAcceptanceSha256 || "")
    || reviewerAuthorityGenesisAcceptanceSha256
      !== expectedReviewerAuthorityGenesisAcceptanceSha256) {
    throw new Error("anchor proof does not match the externally supplied signed reviewer genesis acceptance digest");
  }
  const receiptSha256 = nonzeroSha256(
    proof.fresh_contract_deployment_receipt_sha256,
    "anchor proof fresh contract receipt SHA-256",
  );
  const primary = normalizeAnchorRpcObservation(proof.primary_rpc, "anchor proof primary RPC");
  const secondary = normalizeAnchorRpcObservation(proof.secondary_rpc, "anchor proof secondary RPC");
  const expectedObservation = {
    block_number: proof.common_finalized_block_number,
    block_hash: proof.common_finalized_block_hash,
    contract_address: proof.execution_policy_anchor_address,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityGenesisAcceptanceSha256,
  };
  if (primary.authority_id === secondary.authority_id
    || JSON.stringify({ ...primary, authority_id: undefined })
      !== JSON.stringify({ ...expectedObservation, authority_id: undefined })
    || JSON.stringify({ ...secondary, authority_id: undefined })
      !== JSON.stringify({ ...expectedObservation, authority_id: undefined })) {
    throw new Error("anchor proof RPC authorities must be distinct and agree at one finalized block");
  }
  return {
    schema: proof.schema,
    truth_status: proof.truth_status,
    release_sha: proof.release_sha,
    chain_id: proof.chain_id,
    fresh_contract_deployment_receipt_sha256: receiptSha256,
    execution_policy_anchor_address: proof.execution_policy_anchor_address,
    deployment_intent_sha256: deploymentIntentSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerAuthorityGenesisAcceptanceSha256,
    common_finalized_block_number: proof.common_finalized_block_number,
    common_finalized_block_hash: proof.common_finalized_block_hash,
    primary_rpc: primary,
    secondary_rpc: secondary,
  };
}

export function releaseReviewerGenesisAnchorProofSha256(value, options) {
  const normalized = normalizeReleaseReviewerGenesisAnchorProof(value, options);
  return `sha256:${createHash("sha256")
    .update("dnai-wikigen/release-reviewer-genesis-anchor-proof/v1\0", "utf8")
    .update(canonicalText(normalized), "utf8")
    .digest("hex")}`;
}

export function createReleaseCeremonyLockRecoverySigningPayload(value) {
  const payload = exactRecord(value, [
    "approved_at",
    "chain_and_ledger_reconciliation_sha256",
    "declaration",
    "expires_at",
    "fresh_contract_deployment_receipt_sha256",
    "observed_lock_owner_sha256",
    "protocol",
    "reason",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_genesis_anchor_proof_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "reviewers",
    "schema",
    "signature_scheme",
    "signature_verifier",
    "truth_status",
  ], "release ceremony lock recovery signing payload");
  if (payload.schema !== RELEASE_CEREMONY_LOCK_RECOVERY_SCHEMA
    || payload.protocol !== RELEASE_CEREMONY_LOCK_PROTOCOL
    || payload.truth_status
      !== "signed_stale_lock_recovery_after_dual_rpc_signed_reviewer_genesis_acceptance_anchor_not_live_release_authority"
    || payload.reason !== "crashed_writer_chain_nonce_and_all_release_ledgers_reconciled"
    || payload.declaration !== RELEASE_CEREMONY_LOCK_RECOVERY_DECLARATION
    || !SHA40.test(payload.release_sha)
    || !SHA256.test(payload.observed_lock_owner_sha256)
    || !SHA256.test(payload.chain_and_ledger_reconciliation_sha256)
    || payload.chain_and_ledger_reconciliation_sha256 === `sha256:${"0".repeat(64)}`
    || !SHA256.test(payload.fresh_contract_deployment_receipt_sha256)
    || payload.fresh_contract_deployment_receipt_sha256 === `sha256:${"0".repeat(64)}`
    || !SHA256.test(payload.reviewer_authority_genesis_sha256)
    || payload.reviewer_authority_genesis_sha256 === `sha256:${"0".repeat(64)}`
    || !SHA256.test(payload.reviewer_authority_genesis_acceptance_sha256)
    || payload.reviewer_authority_genesis_acceptance_sha256 === `sha256:${"0".repeat(64)}`
    || !Number.isSafeInteger(payload.reviewer_authority_current_status_epoch)
    || payload.reviewer_authority_current_status_epoch < 1
    || !SHA256.test(payload.reviewer_authority_current_status_sha256)
    || payload.reviewer_authority_current_status_sha256 === `sha256:${"0".repeat(64)}`
    || !SHA256.test(payload.reviewer_genesis_anchor_proof_sha256)
    || payload.reviewer_genesis_anchor_proof_sha256 === `sha256:${"0".repeat(64)}`
    || !BARE_SHA256.test(payload.reviewer_root_hash)
    || payload.reviewer_root_hash === "0".repeat(64)
    || !SHA256.test(payload.reviewer_set_sha256)
    || payload.reviewer_set_sha256 === `sha256:${"0".repeat(64)}`
    || payload.signature_scheme !== RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_SCHEME) {
    throw new Error("release ceremony lock recovery signing payload binding is invalid");
  }
  parseTimestamp(payload.approved_at, "recovery approved_at");
  parseTimestamp(payload.expires_at, "recovery expires_at");
  if (!Array.isArray(payload.reviewers) || payload.reviewers.length !== 2) {
    throw new Error("release ceremony lock recovery signing payload requires exactly two reviewers");
  }
  const reviewers = payload.reviewers.map(normalizeSigningReviewer);
  const signatureVerifier = exactSignatureVerifier(payload.signature_verifier);
  if (reviewers[0].address === reviewers[1].address
    || reviewers[0].controller_id === reviewers[1].controller_id) {
    throw new Error("release ceremony lock recovery signing reviewers must be distinct");
  }
  return {
    schema: payload.schema,
    protocol: payload.protocol,
    truth_status: payload.truth_status,
    release_sha: payload.release_sha,
    observed_lock_owner_sha256: payload.observed_lock_owner_sha256,
    reason: payload.reason,
    chain_and_ledger_reconciliation_sha256:
      payload.chain_and_ledger_reconciliation_sha256,
    approved_at: payload.approved_at,
    expires_at: payload.expires_at,
    declaration: payload.declaration,
    fresh_contract_deployment_receipt_sha256:
      payload.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_sha256:
      payload.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      payload.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      payload.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      payload.reviewer_authority_current_status_sha256,
    reviewer_genesis_anchor_proof_sha256:
      payload.reviewer_genesis_anchor_proof_sha256,
    reviewer_root_hash: payload.reviewer_root_hash,
    reviewer_set_sha256: payload.reviewer_set_sha256,
    reviewers,
    signature_scheme: payload.signature_scheme,
    signature_verifier: signatureVerifier,
  };
}

export function releaseCeremonyLockRecoverySigningPayloadSha256(value) {
  const payload = createReleaseCeremonyLockRecoverySigningPayload(value);
  return `sha256:${createHash("sha256")
    .update(RELEASE_CEREMONY_LOCK_RECOVERY_SIGNING_DOMAIN, "utf8")
    .update(canonicalText(payload), "utf8")
    .digest("hex")}`;
}

export function releaseCeremonyLockRecoverySigningMessage(value) {
  return `${RELEASE_CEREMONY_LOCK_RECOVERY_MESSAGE_PREFIX}${releaseCeremonyLockRecoverySigningPayloadSha256(value)}`;
}

function readReviewerGenesis(reviewerAuthorityGenesisPath) {
  assertNoSymlinkComponents(reviewerAuthorityGenesisPath);
  if (fs.realpathSync(reviewerAuthorityGenesisPath) !== reviewerAuthorityGenesisPath) {
    throw new Error("reviewer authority genesis path must be canonical");
  }
  const bytes = readBoundedRegularFile(
    reviewerAuthorityGenesisPath,
    MAX_RECOVERY_BYTES,
    "reviewer authority genesis",
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("reviewer authority genesis is not JSON");
  }
  let genesis;
  try {
    genesis = normalizeReleaseReviewerAuthorityGenesis(value);
  } catch (error) {
    throw new Error(`reviewer authority genesis is invalid: ${error.message}`);
  }
  if (bytes.toString("utf8") !== canonicalReleaseReviewerAuthorityGenesisArtifactText(genesis)) {
    throw new Error("reviewer authority genesis is not canonical");
  }
  return {
    genesis,
    sha256: releaseReviewerAuthorityGenesisSha256(genesis),
  };
}

function readReviewerGenesisAcceptance(reviewerAuthorityGenesisAcceptancePath, reviewerGenesis) {
  assertNoSymlinkComponents(reviewerAuthorityGenesisAcceptancePath);
  if (fs.realpathSync(reviewerAuthorityGenesisAcceptancePath)
    !== reviewerAuthorityGenesisAcceptancePath) {
    throw new Error("reviewer authority genesis acceptance path must be canonical");
  }
  const bytes = readBoundedRegularFile(
    reviewerAuthorityGenesisAcceptancePath,
    MAX_RECOVERY_BYTES,
    "reviewer authority genesis acceptance",
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("reviewer authority genesis acceptance is not JSON");
  }
  const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(value, {
    reviewerGenesis: reviewerGenesis.genesis,
  });
  if (bytes.toString("utf8")
    !== canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      acceptance,
      { reviewerGenesis: reviewerGenesis.genesis },
    )) {
    throw new Error("reviewer authority genesis acceptance is not canonical");
  }
  return {
    acceptance,
    sha256: releaseReviewerAuthorityGenesisAcceptanceSha256(
      acceptance,
      { reviewerGenesis: reviewerGenesis.genesis },
    ),
  };
}

function readReviewerGenesisAnchorProof(anchorProofPath, {
  releaseSha,
  reviewerAuthorityGenesisAcceptanceSha256,
}) {
  assertNoSymlinkComponents(anchorProofPath);
  if (fs.realpathSync(anchorProofPath) !== anchorProofPath) {
    throw new Error("reviewer genesis anchor proof path must be canonical");
  }
  const bytes = readBoundedRegularFile(
    anchorProofPath,
    MAX_RECOVERY_BYTES,
    "reviewer genesis anchor proof",
  );
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("reviewer genesis anchor proof is not JSON");
  }
  const options = {
    expectedReleaseSha: releaseSha,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      reviewerAuthorityGenesisAcceptanceSha256,
  };
  const proof = normalizeReleaseReviewerGenesisAnchorProof(value, options);
  if (bytes.toString("utf8") !== canonicalText(proof)) {
    throw new Error("reviewer genesis anchor proof is not canonical");
  }
  return {
    proof,
    sha256: releaseReviewerGenesisAnchorProofSha256(proof, options),
  };
}

function normalizeRecoveryAuthority(value, {
  releaseSha,
  ownerSha256,
  nowMs,
  reviewerGenesis,
  reviewerGenesisAcceptance,
  reviewerGenesisAnchorProof,
}) {
  const recovery = exactRecord(value, [
    "approved_at",
    "chain_and_ledger_reconciliation_sha256",
    "declaration",
    "expires_at",
    "observed_lock_owner_sha256",
    "protocol",
    "reason",
    "release_sha",
    "fresh_contract_deployment_receipt_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256",
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
    "reviewer_genesis_anchor_proof_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "reviewers",
    "schema",
    "signature_scheme",
    "signature_verifier",
    "signed_payload_sha256",
    "truth_status",
  ], "release ceremony lock recovery authority");
  if (!Array.isArray(recovery.reviewers) || recovery.reviewers.length !== 2) {
    throw new Error("release ceremony lock recovery requires exactly two signed reviewers");
  }
  const reviewers = recovery.reviewers.map((entry, index) => {
    const reviewer = exactRecord(
      entry,
      ["address", "controller_id", "signature"],
      `recovery reviewer ${index}`,
    );
    const identity = normalizeSigningReviewer({
      address: reviewer.address,
      controller_id: reviewer.controller_id,
    }, index);
    return { ...identity, signature: reviewer.signature };
  });
  if (reviewers[0].address === reviewers[1].address
    || reviewers[0].controller_id === reviewers[1].controller_id) {
    throw new Error("release ceremony lock recovery reviewers must be distinct signers");
  }
  const signingPayload = createReleaseCeremonyLockRecoverySigningPayload({
    schema: recovery.schema,
    protocol: recovery.protocol,
    truth_status: recovery.truth_status,
    release_sha: recovery.release_sha,
    observed_lock_owner_sha256: recovery.observed_lock_owner_sha256,
    reason: recovery.reason,
    chain_and_ledger_reconciliation_sha256:
      recovery.chain_and_ledger_reconciliation_sha256,
    approved_at: recovery.approved_at,
    expires_at: recovery.expires_at,
    declaration: recovery.declaration,
    fresh_contract_deployment_receipt_sha256:
      recovery.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_sha256:
      recovery.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      recovery.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      recovery.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      recovery.reviewer_authority_current_status_sha256,
    reviewer_genesis_anchor_proof_sha256:
      recovery.reviewer_genesis_anchor_proof_sha256,
    reviewer_root_hash: recovery.reviewer_root_hash,
    reviewer_set_sha256: recovery.reviewer_set_sha256,
    reviewers: reviewers.map(({ address, controller_id }) => ({ address, controller_id })),
    signature_scheme: recovery.signature_scheme,
    signature_verifier: recovery.signature_verifier,
  });
  const signedPayloadSha256 = releaseCeremonyLockRecoverySigningPayloadSha256(signingPayload);
  const genesis = reviewerGenesis.genesis;
  const acceptance = assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
    reviewerGenesisAcceptance.acceptance,
    {
      reviewerGenesis: genesis,
      now: new Date(Math.floor(nowMs / 1_000) * 1_000)
        .toISOString().replace(".000Z", "Z"),
      expectedCurrentStatusEpoch:
        recovery.reviewer_authority_current_status_epoch,
      expectedCurrentStatusSha256:
        recovery.reviewer_authority_current_status_sha256,
    },
  );
  const currentStatus = acceptance.reviewer_authority_current_status;
  const anchorProof = reviewerGenesisAnchorProof.proof;
  if (recovery.release_sha !== releaseSha
    || genesis.release_sha !== releaseSha
    || recovery.observed_lock_owner_sha256 !== ownerSha256
    || recovery.reviewer_authority_genesis_sha256 !== reviewerGenesis.sha256
    || recovery.reviewer_authority_genesis_acceptance_sha256
      !== reviewerGenesisAcceptance.sha256
    || recovery.reviewer_genesis_anchor_proof_sha256 !== reviewerGenesisAnchorProof.sha256
    || recovery.fresh_contract_deployment_receipt_sha256
      !== anchorProof.fresh_contract_deployment_receipt_sha256
    || anchorProof.reviewer_authority_genesis_acceptance_sha256
      !== reviewerGenesisAcceptance.sha256
    || acceptance.reviewer_authority_genesis_sha256 !== reviewerGenesis.sha256
    || recovery.reviewer_authority_current_status_epoch !== currentStatus.epoch
    || recovery.reviewer_authority_current_status_sha256
      !== acceptance.reviewer_authority_current_status_sha256
    || recovery.reviewer_root_hash !== currentStatus.reviewer_root_hash
    || recovery.reviewer_set_sha256 !== currentStatus.reviewer_set_sha256
    || recovery.signed_payload_sha256 !== signedPayloadSha256) {
    throw new Error("release ceremony lock recovery authority binding is invalid");
  }
  const approvedAt = parseTimestamp(recovery.approved_at, "recovery approved_at");
  const expiresAt = parseTimestamp(recovery.expires_at, "recovery expires_at");
  if (approvedAt > nowMs + MAX_FUTURE_SKEW_MS
    || expiresAt <= nowMs
    || expiresAt <= approvedAt
    || expiresAt - approvedAt > MAX_RECOVERY_LIFETIME_MS) {
    throw new Error("release ceremony lock recovery authority is expired or outside its bounded lifetime");
  }
  const reviewerAuthority = normalizeExpectedReviewerAuthority({
    approved_reviewers: currentStatus.active_reviewers,
    approved_reviewer_hashes: currentStatus.approved_reviewer_hashes,
    reviewer_root_hash: currentStatus.reviewer_root_hash,
    reviewer_set_sha256: currentStatus.reviewer_set_sha256,
  }, {
    expectedReviewerRootHash: currentStatus.reviewer_root_hash,
    expectedReviewerSetSha256: currentStatus.reviewer_set_sha256,
  });
  const message = releaseCeremonyLockRecoverySigningMessage(signingPayload);
  verifyPinnedTwoSignerAuthorization({ signatures: reviewers, message, reviewerAuthority });
  return {
    ...signingPayload,
    signed_payload_sha256: signedPayloadSha256,
    reviewers,
  };
}

export function inspectReleaseCeremonyLock({
  lockRoot,
  repositoryRoot,
  releaseSha,
  testHookAfterContext = null,
  testHookAfterOwnerOpen = null,
}) {
  const context = normalizeLockContext({
    lockRoot,
    repositoryRoot,
    releaseSha,
    writerId: RELEASE_CEREMONY_WRITERS[0],
  });
  if (testHookAfterContext !== null) testHookAfterContext(context);
  assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", { requirePrivate: true });
  if (!fs.existsSync(context.lockPath)) {
    return {
      protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
      status: "unlocked",
      lock_path: context.lockPath,
      observed_lock_owner_sha256: null,
      owner: null,
    };
  }
  assertNoSymlinkComponents(context.lockPath);
  const lockDirectory = openStableDirectory(context.lockPath, "release ceremony lock", {
    requirePrivate: true,
  });
  let ownerEvidence;
  try {
    ownerEvidence = readOwner(context, {
      allowMissing: true,
      testHookAfterOpen: testHookAfterOwnerOpen,
    });
    assertDirectoryStillBound(context.lockPath, lockDirectory.stat, "release ceremony lock", {
      requirePrivate: true,
    });
  } finally {
    fs.closeSync(lockDirectory.fd);
  }
  const { owner, sha256 } = ownerEvidence;
  return {
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    status: "held_or_stale_requires_owner_release_or_reviewed_recovery",
    lock_path: context.lockPath,
    observed_lock_owner_sha256: sha256,
    owner,
  };
}

function publishRecoveryReceipt(context, recovery, recoveryBytes) {
  const receiptDirectory = path.join(
    context.lockRoot,
    `dnai-release-ceremony-${context.releaseSha}.recovery-receipts`,
  );
  try {
    fs.mkdirSync(receiptDirectory, { mode: 0o700 });
    fs.chmodSync(receiptDirectory, 0o700);
    fsyncDirectory(context.lockRoot);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
  }
  assertNoSymlinkComponents(receiptDirectory);
  const directoryStat = fs.lstatSync(receiptDirectory);
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()
    || (directoryStat.mode & 0o077) !== 0) {
    throw new Error("release ceremony recovery receipt directory is not private and canonical");
  }
  const trustedReceiptDirectory = openStableDirectory(
    receiptDirectory,
    "release ceremony recovery receipt directory",
    { requirePrivate: true },
  );
  fs.closeSync(trustedReceiptDirectory.fd);
  const receipt = {
    schema: RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    status: "signed_recovery_verified_before_stale_lock_removal",
    release_sha: context.releaseSha,
    observed_lock_owner_sha256: recovery.observed_lock_owner_sha256,
    chain_and_ledger_reconciliation_sha256:
      recovery.chain_and_ledger_reconciliation_sha256,
    fresh_contract_deployment_receipt_sha256:
      recovery.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_sha256:
      recovery.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      recovery.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      recovery.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      recovery.reviewer_authority_current_status_sha256,
    reviewer_genesis_anchor_proof_sha256:
      recovery.reviewer_genesis_anchor_proof_sha256,
    reviewer_root_hash: recovery.reviewer_root_hash,
    reviewer_set_sha256: recovery.reviewer_set_sha256,
    signature_scheme: recovery.signature_scheme,
    signature_verifier: recovery.signature_verifier,
    signed_payload_sha256: recovery.signed_payload_sha256,
    recovery_authority_sha256: sha256Bytes(recoveryBytes),
    approved_at: recovery.approved_at,
    expires_at: recovery.expires_at,
    reviewers: recovery.reviewers.map((reviewer) => ({
      address: reviewer.address,
      controller_id: reviewer.controller_id,
      signature_sha256: sha256Bytes(Buffer.from(reviewer.signature.slice(2), "hex")),
    })),
  };
  const receiptBytes = Buffer.from(canonicalText(receipt), "utf8");
  const receiptPath = path.join(
    receiptDirectory,
    `${recovery.signed_payload_sha256.slice("sha256:".length)}.json`,
  );
  try {
    writeAllAndSync(receiptPath, receiptBytes, 0o444);
    fsyncDirectory(receiptDirectory);
    fsyncDirectory(context.lockRoot);
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    const existing = readBoundedRegularFile(
      receiptPath,
      MAX_RECOVERY_BYTES,
      "release ceremony recovery receipt",
    );
    if (!existing.equals(receiptBytes)
      || (fs.lstatSync(receiptPath).mode & 0o777) !== 0o444) {
      throw new Error("existing release ceremony recovery receipt does not match the signed recovery");
    }
  }
  return {
    path: receiptPath,
    sha256: sha256Bytes(receiptBytes),
  };
}

export function recoverReleaseCeremonyLock({
  lockRoot,
  repositoryRoot,
  releaseSha,
  recoveryAuthorityPath,
  reviewerAuthorityGenesisPath,
  reviewerAuthorityGenesisAcceptancePath,
  reviewerGenesisAnchorProofPath,
  nowMs = Date.now(),
}) {
  const context = normalizeLockContext({
    lockRoot,
    repositoryRoot,
    releaseSha,
    writerId: RELEASE_CEREMONY_WRITERS[0],
  });
  assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", {
    requirePrivate: true,
  });
  assertNoSymlinkComponents(context.lockPath);
  const lockStat = fs.lstatSync(context.lockPath);
  if (!lockStat.isDirectory() || lockStat.isSymbolicLink()) {
    throw new Error("release ceremony lock is not a non-symlink directory");
  }
  const lockDirectory = openStableDirectory(context.lockPath, "release ceremony lock", {
    requirePrivate: true,
  });
  try {
    const { sha256: ownerSha256 } = readOwner(context, { allowMissing: true });
    assertNoSymlinkComponents(recoveryAuthorityPath);
    const recoveryBytes = readBoundedRegularFile(
      recoveryAuthorityPath,
      MAX_RECOVERY_BYTES,
      "reviewed recovery authority",
    );
    let recoveryValue;
    try {
      recoveryValue = JSON.parse(recoveryBytes.toString("utf8"));
    } catch {
      throw new Error("reviewed recovery authority is not JSON");
    }
    const reviewerGenesis = readReviewerGenesis(reviewerAuthorityGenesisPath);
    const reviewerGenesisAcceptance = readReviewerGenesisAcceptance(
      reviewerAuthorityGenesisAcceptancePath,
      reviewerGenesis,
    );
    const reviewerGenesisAnchorProof = readReviewerGenesisAnchorProof(
      reviewerGenesisAnchorProofPath,
      {
        releaseSha,
        reviewerAuthorityGenesisAcceptanceSha256: reviewerGenesisAcceptance.sha256,
      },
    );
    const recovery = normalizeRecoveryAuthority(recoveryValue, {
      releaseSha,
      ownerSha256,
      nowMs,
      reviewerGenesis,
      reviewerGenesisAcceptance,
      reviewerGenesisAnchorProof,
    });
    if (recoveryBytes.toString("utf8") !== canonicalText(recovery)) {
      throw new Error("reviewed recovery authority is not canonical");
    }
    const entries = fs.readdirSync(context.lockPath);
    if (entries.some((entry) => entry !== "owner.json")) {
      throw new Error("release ceremony lock contains unexpected evidence and cannot be recovered automatically");
    }
    assertDirectoryStillBound(context.lockRoot, context.lockRootStat, "lock root", {
      requirePrivate: true,
    });
    assertDirectoryStillBound(context.lockPath, lockDirectory.stat, "release ceremony lock", {
      requirePrivate: true,
    });
    const recoveryReceipt = publishRecoveryReceipt(context, recovery, recoveryBytes);
    if (fs.existsSync(context.ownerPath)) fs.unlinkSync(context.ownerPath);
    fs.fsyncSync(lockDirectory.fd);
    fs.rmdirSync(context.lockPath);
    fsyncDirectory(context.lockRoot);
    return {
      protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
      status: "recovered_after_dual_rpc_signed_genesis_anchor_and_two_reviewer_authority",
      recovery_authority_sha256: sha256Bytes(recoveryBytes),
      recovery_receipt_path: recoveryReceipt.path,
      recovery_receipt_sha256: recoveryReceipt.sha256,
      signed_payload_sha256: recovery.signed_payload_sha256,
      observed_lock_owner_sha256: ownerSha256,
    };
  } finally {
    fs.closeSync(lockDirectory.fd);
  }
}

function parseFlags(args, expected) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || value === undefined || values.has(flag)) {
      throw new Error("lock arguments must be unique --flag value pairs");
    }
    values.set(flag, value);
  }
  if (values.size !== expected.length || expected.some((flag) => !values.has(flag))) {
    throw new Error(`lock command requires exactly: ${expected.join(", ")}`);
  }
  return Object.fromEntries(expected.map((flag) => [flag.slice(2), values.get(flag)]));
}

function cli(argv) {
  const [command, ...args] = argv;
  if (command === "acquire") {
    const flags = parseFlags(args, ["--lock-root", "--repository-root", "--release-sha", "--writer-id", "--owner-pid"]);
    const result = acquireReleaseCeremonyLock({
      lockRoot: flags["lock-root"],
      repositoryRoot: flags["repository-root"],
      releaseSha: flags["release-sha"],
      writerId: flags["writer-id"],
      ownerPid: Number(flags["owner-pid"]),
    });
    process.stdout.write(canonicalText(result));
    return;
  }
  if (command === "release") {
    const flags = parseFlags(args, ["--lock-root", "--repository-root", "--release-sha", "--writer-id", "--owner-token"]);
    process.stdout.write(canonicalText(releaseReleaseCeremonyLock({
      lockRoot: flags["lock-root"],
      repositoryRoot: flags["repository-root"],
      releaseSha: flags["release-sha"],
      writerId: flags["writer-id"],
      ownerToken: flags["owner-token"],
    })));
    return;
  }
  if (command === "inspect") {
    const flags = parseFlags(args, ["--lock-root", "--repository-root", "--release-sha"]);
    process.stdout.write(canonicalText(inspectReleaseCeremonyLock({
      lockRoot: flags["lock-root"],
      repositoryRoot: flags["repository-root"],
      releaseSha: flags["release-sha"],
    })));
    return;
  }
  if (command === "recover") {
    const flags = parseFlags(args, [
      "--lock-root",
      "--repository-root",
      "--release-sha",
      "--recovery-authority",
      "--reviewer-authority-genesis",
      "--reviewer-authority-genesis-acceptance",
      "--reviewer-genesis-anchor-proof",
    ]);
    process.stdout.write(canonicalText(recoverReleaseCeremonyLock({
      lockRoot: flags["lock-root"],
      repositoryRoot: flags["repository-root"],
      releaseSha: flags["release-sha"],
      recoveryAuthorityPath: flags["recovery-authority"],
      reviewerAuthorityGenesisPath: flags["reviewer-authority-genesis"],
      reviewerAuthorityGenesisAcceptancePath:
        flags["reviewer-authority-genesis-acceptance"],
      reviewerGenesisAnchorProofPath: flags["reviewer-genesis-anchor-proof"],
    })));
    return;
  }
  throw new Error("release ceremony lock command must be acquire, release, inspect, or recover");
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  try {
    cli(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`release ceremony lock failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
