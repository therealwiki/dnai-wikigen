import fs from "node:fs";
import path from "node:path";

import {
  assertPinnedPhalaPrivateDirectory,
  closePhalaPinnedPrivateDirectory,
  createExclusivePhalaPinnedPrivateFile,
  ensurePhalaPinnedPrivateDirectory,
  listPhalaPinnedPrivateEntries,
  phalaPinnedPrivatePathForDisplay,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
  publishPhalaPinnedPrivateFile,
  readPhalaPinnedPrivateFile,
  unlinkPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";
import {
  PHALA_EXECUTOR_STATE_SCHEMA,
  assertSecretFreeExecutorStructure,
  phalaExecutorStateDigest,
} from "./phala-production-executor-core.mjs";

export const PHALA_RECOVERY_JOURNAL_SCHEMA =
  "dnai.phala-production-recovery-journal.v2";
export const PHALA_RECOVERY_LOCK_SCHEMA =
  "dnai.phala-production-recovery-lock.v1";
export const PHALA_RECOVERY_AUTHORIZATION_CLAIM_SCHEMA =
  "dnai.phala-production-authorization-claim.v1";
export const PHALA_RECOVERY_TERMINAL_STATUSES = Object.freeze([
  "complete_seven_commits_posture_observed_attestation_unverified",
  "partial_commit_requires_operator_reconciliation",
  "reconciled_no_mutation_operator_review_required",
]);

const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const MAX_JOURNAL_BYTES = 768 * 1024;
const LOCKS = new WeakSet();
const DURABLY_PERSISTED_TERMINAL_JOURNALS = new WeakMap();

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, keys, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    throw new Error(`${label} must contain exactly the allowed fields`);
  }
  return value;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((entry) => sortedObject(entry));
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

function assertOwnedPrivateDirectory(directory) {
  if (!path.isAbsolute(directory)) {
    throw new Error("recovery journal directory must be absolute");
  }
  const stat = fs.lstatSync(directory);
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error("recovery journal directory must be a non-symlink directory");
  }
  if ((stat.mode & 0o777) !== 0o700) {
    throw new Error("recovery journal directory must have exact mode 0700");
  }
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error("recovery journal directory must be owned by the current user");
  }
  return directory;
}

export function ensurePhalaRecoveryJournalDirectory(directory) {
  ensurePhalaPinnedPrivateDirectory(directory);
  return assertOwnedPrivateDirectory(directory);
}

function batchStem(batchId) {
  if (typeof batchId !== "string" || !SHA256.test(batchId)) {
    throw new Error("recovery batch id must be a nonzero canonical SHA-256 digest");
  }
  return batchId.slice("sha256:".length);
}

export function phalaRecoveryJournalPaths(directory, batchId) {
  assertOwnedPrivateDirectory(directory);
  const stem = batchStem(batchId);
  return Object.freeze({
    journal: path.join(directory, `${stem}.journal.json`),
    lock: path.join(directory, `${stem}.lock.json`),
  });
}

export function phalaRecoveryAuthorizationClaimPath(directory, authorizationId) {
  assertOwnedPrivateDirectory(directory);
  return path.join(
    directory,
    `${batchStem(authorizationId)}.authorization-claim.json`,
  );
}

function recoveryJournalNames(batchId) {
  const stem = batchStem(batchId);
  return Object.freeze({
    journal: `${stem}.journal.json`,
    lock: `${stem}.lock.json`,
  });
}

function recoveryAuthorizationClaimName(authorizationId) {
  return `${batchStem(authorizationId)}.authorization-claim.json`;
}

export function acquirePhalaRecoveryJournalLock({
  directory,
  batchId,
  authorizationId,
  acquiredAt,
  directoryIdentityAnchorSha256 = null,
} = {}) {
  const names = recoveryJournalNames(batchId);
  batchStem(authorizationId);
  if (typeof acquiredAt !== "string" || !Number.isFinite(Date.parse(acquiredAt))) {
    throw new Error("recovery lock acquired_at is invalid");
  }
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: directoryIdentityAnchorSha256,
  });
  const pinnedDirectoryIdentityAnchorSha256 =
    phalaPinnedPrivateDirectoryIdentityAnchorSha256(pinnedDirectory);
  let handedOff = false;
  try {
    if (listPhalaPinnedPrivateEntries(pinnedDirectory).some(
      (entry) => entry.startsWith(`.${names.lock}.release-`),
    )) {
      throw new Error(
        "a quarantined recovery lock release exists; manual reconciliation is required",
      );
    }
  const claimName = recoveryAuthorizationClaimName(authorizationId);
  const claimPath = phalaPinnedPrivatePathForDisplay(pinnedDirectory, claimName);
  const claimDocument = {
    schema: PHALA_RECOVERY_AUTHORIZATION_CLAIM_SCHEMA,
    authorization_id: authorizationId,
    batch_id: batchId,
    first_claimed_at: acquiredAt,
    phala_recovery_directory_identity_anchor_sha256:
      pinnedDirectoryIdentityAnchorSha256,
    second_batch_authorized: false,
    automatic_claim_removal_authorized: false,
  };
  const claimBytes = Buffer.from(canonicalText(claimDocument), "utf8");
  try {
    createExclusivePhalaPinnedPrivateFile(pinnedDirectory, claimName, claimBytes, {
      mode: 0o600,
      maximum: MAX_JOURNAL_BYTES,
    });
  } catch (error) {
    if (error?.code !== "EEXIST") {
      throw error;
    }
    const existingBytes = readPhalaPinnedPrivateFile(pinnedDirectory, claimName, {
      mode: 0o600,
      maximum: MAX_JOURNAL_BYTES,
      minimum: 2,
    });
    let existing;
    try {
      existing = JSON.parse(existingBytes.toString("utf8"));
    } catch {
      throw new Error("bootstrap authorization claim is corrupt; manual recovery is required");
    }
    let exactExisting;
    try {
      exactExisting = exactRecord(existing, [
        "schema",
        "authorization_id",
        "batch_id",
        "first_claimed_at",
        "phala_recovery_directory_identity_anchor_sha256",
        "second_batch_authorized",
        "automatic_claim_removal_authorized",
      ], "bootstrap authorization claim");
    } catch {
      throw new Error("bootstrap authorization claim is corrupt; manual recovery is required");
    }
    if (canonicalText(exactExisting) !== existingBytes.toString("utf8")
      || exactExisting.schema !== PHALA_RECOVERY_AUTHORIZATION_CLAIM_SCHEMA
      || exactExisting.authorization_id !== authorizationId
      || exactExisting.batch_id !== batchId
      || typeof exactExisting.first_claimed_at !== "string"
      || !Number.isFinite(Date.parse(exactExisting.first_claimed_at))
      || exactExisting.phala_recovery_directory_identity_anchor_sha256
        !== pinnedDirectoryIdentityAnchorSha256
      || exactExisting.second_batch_authorized !== false
      || exactExisting.automatic_claim_removal_authorized !== false) {
      throw new Error("bootstrap authorization is already claimed by a different seven-CVM batch");
    }
  }
  const lockDocument = {
    schema: PHALA_RECOVERY_LOCK_SCHEMA,
    authorization_id: authorizationId,
    batch_id: batchId,
    acquired_at: acquiredAt,
    phala_recovery_directory_identity_anchor_sha256:
      pinnedDirectoryIdentityAnchorSha256,
    pid: process.pid,
    stale_lock_removal_automatic: false,
  };
  const bytes = Buffer.from(canonicalText(lockDocument), "utf8");
  const lockIdentity = createExclusivePhalaPinnedPrivateFile(
    pinnedDirectory,
    names.lock,
    bytes,
    { mode: 0o600, maximum: MAX_JOURNAL_BYTES },
  );
  const written = readPhalaPinnedPrivateFile(pinnedDirectory, names.lock, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    expectedIdentity: lockIdentity,
  });
  if (!written.equals(bytes)) throw new Error("recovery lock bytes are incomplete");
  const lock = Object.freeze({
    path: phalaPinnedPrivatePathForDisplay(pinnedDirectory, names.lock),
    directory,
    batchId,
    authorizationId,
    claimPath,
    lockName: names.lock,
    lockIdentity,
    pinnedDirectory,
  });
  LOCKS.add(lock);
  handedOff = true;
  return lock;
  } finally {
    if (!handedOff) closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

export function releasePhalaRecoveryJournalLock(lock) {
  if (!lock || !LOCKS.has(lock)) throw new Error("a live recovery lock is required");
  readPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    expectedIdentity: lock.lockIdentity,
  });
  unlinkPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    expectedSha256: lock.lockIdentity.sha256,
    expectedIdentity: lock.lockIdentity,
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
  });
  closePhalaPinnedPrivateDirectory(lock.pinnedDirectory);
  LOCKS.delete(lock);
}

function requireLiveLock(lock, directory, batchId, authorizationId) {
  if (!lock || !LOCKS.has(lock)
    || lock.directory !== directory || lock.batchId !== batchId
    || lock.authorizationId !== authorizationId) {
    throw new Error("the exact live batch recovery lock is required");
  }
  assertPinnedPhalaPrivateDirectory(lock.pinnedDirectory, directory);
  readPhalaPinnedPrivateFile(lock.pinnedDirectory, lock.lockName, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    expectedIdentity: lock.lockIdentity,
  });
  return lock.pinnedDirectory;
}

export function pinnedPhalaRecoveryDirectoryForLiveLock({
  lock,
  directory,
  batchId,
  authorizationId,
} = {}) {
  return requireLiveLock(lock, directory, batchId, authorizationId);
}

function journalDocument(state) {
  if (!isRecord(state) || state.schema !== PHALA_EXECUTOR_STATE_SCHEMA) {
    throw new Error("recovery journal requires a canonical executor state");
  }
  assertSecretFreeExecutorStructure(state, "recovery executor state");
  const document = {
    schema: PHALA_RECOVERY_JOURNAL_SCHEMA,
    truth_status:
      "private_recovery_metadata_no_secrets_ciphertext_or_phala_atomicity_claim",
    batch_id: state.batch_id,
    state_sha256: phalaExecutorStateDigest(state),
    state: structuredClone(state),
    seven_commit_batch_is_atomic: false,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  };
  assertSecretFreeExecutorStructure(document, "recovery journal");
  return document;
}

function loadPhalaRecoveryJournalFromPinnedDirectory(pinnedDirectory, batchId) {
  const names = recoveryJournalNames(batchId);
  const bytes = readPhalaPinnedPrivateFile(pinnedDirectory, names.journal, {
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    minimum: 2,
    allowMissing: true,
  });
  if (bytes === null) return null;
  return parsePhalaRecoveryJournalBytes(bytes, batchId);
}

export function loadPhalaRecoveryJournal({
  directory,
  batchId,
  directoryIdentityAnchorSha256 = null,
} = {}) {
  batchStem(batchId);
  const pinnedDirectory = pinPhalaPrivateDirectory(directory, {
    expectedIdentityAnchorSha256: directoryIdentityAnchorSha256,
  });
  try {
    return loadPhalaRecoveryJournalFromPinnedDirectory(pinnedDirectory, batchId);
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
}

function parsePhalaRecoveryJournalBytes(bytes, batchId) {
  let parsed;
  try {
    parsed = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("recovery journal is not valid JSON");
  }
  const document = exactRecord(parsed, [
    "schema",
    "truth_status",
    "batch_id",
    "state_sha256",
    "state",
    "seven_commit_batch_is_atomic",
    "automatic_retry_authorized",
    "automatic_cleanup_authorized",
  ], "recovery journal");
  if (document.schema !== PHALA_RECOVERY_JOURNAL_SCHEMA
    || document.truth_status
      !== "private_recovery_metadata_no_secrets_ciphertext_or_phala_atomicity_claim"
    || document.batch_id !== batchId
    || document.seven_commit_batch_is_atomic !== false
    || document.automatic_retry_authorized !== false
    || document.automatic_cleanup_authorized !== false
    || document.state_sha256 !== phalaExecutorStateDigest(document.state)
    || canonicalText(document) !== bytes.toString("utf8")) {
    throw new Error("recovery journal is noncanonical or its state digest is invalid");
  }
  assertSecretFreeExecutorStructure(document, "recovery journal");
  return document;
}

function assertMonotonicReplacement(previous, next) {
  if (!previous) {
    if (next.state.sequence !== 0 || next.state.status !== "initialized") {
      throw new Error("the first recovery journal state must be initialized sequence zero");
    }
    return;
  }
  const left = previous.state;
  const right = next.state;
  if (PHALA_RECOVERY_TERMINAL_STATUSES.includes(left.status)) {
    throw new Error("terminal recovery journals cannot be replaced automatically");
  }
  for (const field of [
    "batch_id",
    "bootstrap_authorization_id",
    "bootstrap_authorization_receipt_sha256",
    "release_sha",
    "launch_intent_sha256",
    "target_authority_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
  ]) {
    if (left[field] !== right[field]) {
      throw new Error(`recovery journal immutable field changed: ${field}`);
    }
  }
  if (right.sequence !== left.sequence + 1
    || right.reservations.length < left.reservations.length
    || right.preparations.length < left.preparations.length
    || right.signed_key_bindings.length < left.signed_key_bindings.length
    || right.committed_prefix.length < left.committed_prefix.length
    || right.posture_receipts.length < left.posture_receipts.length) {
    throw new Error("recovery journal sequence or observed prefixes regressed");
  }
  const prefix = (prior, current) => JSON.stringify(
    sortedObject(current.slice(0, prior.length)),
  ) === JSON.stringify(sortedObject(prior));
  if (!["reservations", "preparations", "signed_key_bindings", "committed_prefix"].every(
    (field) => prefix(left[field], right[field]),
  )) {
    throw new Error("recovery journal changed an already observed prefix");
  }
}

function publishDocument({ pinnedDirectory, journalName, document, publishMode, faultStage }) {
  const bytes = Buffer.from(canonicalText(document), "utf8");
  if (bytes.length > MAX_JOURNAL_BYTES) throw new Error("recovery journal exceeds size bound");
  return publishPhalaPinnedPrivateFile(pinnedDirectory, journalName, bytes, {
    publishMode,
    mode: 0o600,
    maximum: MAX_JOURNAL_BYTES,
    faultStage,
  });
}

export function persistPhalaRecoveryJournal({
  directory,
  state,
  lock,
  faultStage = null,
} = {}) {
  const document = journalDocument(state);
  const pinnedDirectory = requireLiveLock(
    lock,
    directory,
    state.batch_id,
    state.bootstrap_authorization_id,
  );
  if (state.phala_recovery_directory_identity_anchor_sha256
      !== phalaPinnedPrivateDirectoryIdentityAnchorSha256(pinnedDirectory)) {
    throw new Error(
      "recovery state is not bound to the exact pinned directory identity anchor",
    );
  }
  const names = recoveryJournalNames(state.batch_id);
  const previous = loadPhalaRecoveryJournalFromPinnedDirectory(pinnedDirectory, state.batch_id);
  assertMonotonicReplacement(previous, document);
  publishDocument({
    pinnedDirectory,
    journalName: names.journal,
    document,
    publishMode: previous ? "replace" : "create",
    faultStage,
  });
  const observed = loadPhalaRecoveryJournalFromPinnedDirectory(pinnedDirectory, state.batch_id);
  if (!observed || observed.state_sha256 !== document.state_sha256) {
    throw new Error("durably published recovery journal did not re-read exactly");
  }
  if (PHALA_RECOVERY_TERMINAL_STATUSES.includes(observed.state.status)) {
    DURABLY_PERSISTED_TERMINAL_JOURNALS.set(observed, Object.freeze({
      directory,
      journal_path: phalaPinnedPrivatePathForDisplay(pinnedDirectory, names.journal),
      state_sha256: observed.state_sha256,
      batch_id: observed.batch_id,
      authorization_id: observed.state.bootstrap_authorization_id,
    }));
  }
  return observed;
}

export function assertDurablyPersistedCompletedPhalaRecoveryJournal({
  journal,
  directory,
  state,
  lock,
} = {}) {
  const provenance = journal && DURABLY_PERSISTED_TERMINAL_JOURNALS.get(journal);
  if (!provenance
    || provenance.directory !== directory
    || provenance.batch_id !== state?.batch_id
    || provenance.authorization_id !== state?.bootstrap_authorization_id
    || journal.state.status
      !== "complete_seven_commits_posture_observed_attestation_unverified"
    || journal.state_sha256 !== phalaExecutorStateDigest(state)
    || provenance.state_sha256 !== journal.state_sha256) {
    throw new Error(
      "a durably persisted completed seven-CVM recovery journal is required",
    );
  }
  requireLiveLock(
    lock,
    directory,
    state.batch_id,
    state.bootstrap_authorization_id,
  );
  const reread = loadPhalaRecoveryJournalFromPinnedDirectory(
    lock.pinnedDirectory,
    state.batch_id,
  );
  if (!reread || reread.state_sha256 !== provenance.state_sha256
    || canonicalText(reread) !== canonicalText(journal)) {
    throw new Error("completed recovery journal changed after durable publication");
  }
  return journal;
}

export function classifyPhalaRecoveryRequirement(journal) {
  if (!journal) return Object.freeze({ action: "initialize_new_batch" });
  const status = journal.state.status;
  if (status === "provision_attempt_durable" || status === "commit_attempt_durable"
    || status === "ambiguous_reconcile_required") {
    return Object.freeze({
      action: "read_only_reconciliation_required",
      automatic_retry_authorized: false,
      automatic_cleanup_authorized: false,
      pending_mutation: structuredClone(journal.state.pending_mutation),
      committed_prefix: structuredClone(journal.state.committed_prefix),
    });
  }
  if (PHALA_RECOVERY_TERMINAL_STATUSES.includes(status)) {
    return Object.freeze({
      action: "terminal_operator_review_required",
      automatic_retry_authorized: false,
      automatic_cleanup_authorized: false,
      status,
    });
  }
  return Object.freeze({
    action: "same_authority_resume_review_required",
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
    status,
  });
}
