import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PHALA_EXECUTION_ORDER,
  createInitialPhalaExecutorState,
  transitionPhalaExecutorState,
} from "./phala-production-executor-core.mjs";
import {
  acquirePhalaRecoveryJournalLock,
  classifyPhalaRecoveryRequirement,
  ensurePhalaRecoveryJournalDirectory,
  loadPhalaRecoveryJournal,
  persistPhalaRecoveryJournal,
  phalaRecoveryAuthorizationClaimPath,
  phalaRecoveryJournalPaths,
  releasePhalaRecoveryJournalLock,
} from "./phala-production-recovery-journal.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;

function fixture(t) {
  const parent = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phala-journal-")),
  );
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "journal");
  ensurePhalaRecoveryJournalDirectory(directory);
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  return { parent, directory };
}

function initialState(directory) {
  const pinnedDirectory = pinPhalaPrivateDirectory(directory);
  let directoryIdentityAnchorSha256;
  try {
    directoryIdentityAnchorSha256 =
      phalaPinnedPrivateDirectoryIdentityAnchorSha256(pinnedDirectory);
  } finally {
    closePhalaPinnedPrivateDirectory(pinnedDirectory);
  }
  return createInitialPhalaExecutorState({
    batchId: digest("1"),
    bootstrapAuthorizationId: digest("f"),
    bootstrapAuthorizationReceiptSha256: digest("e"),
    releaseSha: "a".repeat(40),
    launchIntentSha256: digest("2"),
    targetAuthoritySha256: digest("3"),
    phalaRecoveryDirectoryIdentityAnchorSha256:
      directoryIdentityAnchorSha256,
  });
}

function reservationsEvent() {
  return {
    type: "app_ids_observed",
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: (index + 1).toString(16).repeat(40),
      nonce: 100 + index,
    })),
  };
}

test("journal directory and exclusive lock are owned, private, and no-clobber", (t) => {
  const { directory } = fixture(t);
  assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
  const state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  assert.equal(fs.statSync(lock.path).mode & 0o777, 0o600);
  assert.throws(() => acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:01Z",
  }), /EEXIST|exist/);
  releasePhalaRecoveryJournalLock(lock);
  assert.equal(fs.existsSync(lock.path), false);
});

test("recovery persistence and release remain on the pinned directory after cross-process replacement", (t) => {
  const { parent, directory } = fixture(t);
  const held = path.join(parent, "held-journal");
  let state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  let released = false;
  t.after(() => {
    if (!released) {
      try { releasePhalaRecoveryJournalLock(lock); } catch { /* Stale evidence is fail-closed. */ }
    }
  });
  persistPhalaRecoveryJournal({ directory, state, lock });

  const source = [
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "const [directory, held, lockName] = process.argv.slice(1);",
    "fs.renameSync(directory, held);",
    "fs.mkdirSync(directory, { mode: 0o700 });",
    "fs.writeFileSync(path.join(directory, lockName), '{\"owner\":\"replacement\"}\\n', { mode: 0o600 });",
    "fs.writeFileSync(path.join(directory, 'replacement.sentinel'), 'replacement\\n', { mode: 0o600 });",
  ].join("\n");
  const replacement = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    source,
    directory,
    held,
    path.basename(lock.path),
  ], { encoding: "utf8" });
  assert.equal(replacement.status, 0, replacement.stderr);

  state = transitionPhalaExecutorState(state, reservationsEvent());
  const journal = persistPhalaRecoveryJournal({ directory, state, lock });
  assert.equal(journal.state.sequence, 1);
  const journalName = `${state.batch_id.slice("sha256:".length)}.journal.json`;
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(held, journalName), "utf8")).state.sequence,
    1,
  );
  assert.equal(fs.existsSync(path.join(directory, journalName)), false);

  releasePhalaRecoveryJournalLock(lock);
  released = true;
  assert.equal(fs.existsSync(path.join(held, path.basename(lock.path))), false);
  assert.equal(
    fs.readFileSync(path.join(directory, path.basename(lock.path)), "utf8"),
    '{"owner":"replacement"}\n',
  );
  assert.equal(
    fs.readFileSync(path.join(directory, "replacement.sentinel"), "utf8"),
    "replacement\n",
  );
});

test("a crash-left lock-release quarantine blocks reacquisition", (t) => {
  const { directory } = fixture(t);
  const state = initialState(directory);
  const first = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  const lockName = path.basename(first.path);
  releasePhalaRecoveryJournalLock(first);
  fs.writeFileSync(
    path.join(directory, `.${lockName}.release-${"a".repeat(64)}`),
    "quarantined lock evidence\n",
    { mode: 0o600 },
  );
  assert.throws(
    () => acquirePhalaRecoveryJournalLock({
      directory,
      batchId: state.batch_id,
      authorizationId: state.bootstrap_authorization_id,
      acquiredAt: "2026-07-21T12:01:00Z",
    }),
    /quarantined recovery lock release/,
  );
});

test("one bootstrap authorization can recover one batch but can never start a second batch", (t) => {
  const { directory } = fixture(t);
  const state = initialState(directory);
  const first = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  releasePhalaRecoveryJournalLock(first);
  const claimPath = phalaRecoveryAuthorizationClaimPath(
    directory,
    state.bootstrap_authorization_id,
  );
  assert.equal(fs.existsSync(claimPath), true);

  const recovered = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:01:00Z",
  });
  releasePhalaRecoveryJournalLock(recovered);
  assert.equal(fs.existsSync(claimPath), true);

  assert.throws(
    () => acquirePhalaRecoveryJournalLock({
      directory,
      batchId: digest("e"),
      authorizationId: state.bootstrap_authorization_id,
      acquiredAt: "2026-07-21T12:02:00Z",
    }),
    /already claimed by a different seven-CVM batch/,
  );
  assert.equal(fs.existsSync(claimPath), true);
});

test("journal durably creates, replaces, and preserves monotonic observed prefixes", (t) => {
  const { directory } = fixture(t);
  let state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  let document = persistPhalaRecoveryJournal({ directory, state, lock });
  assert.equal(document.state.sequence, 0);
  const paths = phalaRecoveryJournalPaths(directory, state.batch_id);
  assert.equal(fs.statSync(paths.journal).mode & 0o777, 0o600);

  state = transitionPhalaExecutorState(state, reservationsEvent());
  document = persistPhalaRecoveryJournal({ directory, state, lock });
  assert.equal(document.state.sequence, 1);
  assert.equal(document.state.reservations.length, 7);
  assert.deepEqual(
    loadPhalaRecoveryJournal({ directory, batchId: state.batch_id }),
    document,
  );

  const regressed = structuredClone(state);
  regressed.sequence += 1;
  regressed.reservations = [];
  assert.throws(
    () => persistPhalaRecoveryJournal({ directory, state: regressed, lock }),
    /regressed|prefix/,
  );
});

for (const faultStage of ["partial-write", "complete-write", "file-fsync", "publish"]) {
  test(`journal replacement failure at ${faultStage} preserves the previous durable state`, (t) => {
    const { directory } = fixture(t);
    let state = initialState(directory);
    const lock = acquirePhalaRecoveryJournalLock({
      directory,
      batchId: state.batch_id,
      authorizationId: state.bootstrap_authorization_id,
      acquiredAt: "2026-07-21T12:00:00Z",
    });
    t.after(() => {
      if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
    });
    const initial = persistPhalaRecoveryJournal({ directory, state, lock });
    state = transitionPhalaExecutorState(state, reservationsEvent());
    assert.throws(
      () => persistPhalaRecoveryJournal({ directory, state, lock, faultStage }),
      /injected durable-write failure/,
    );
    const observed = loadPhalaRecoveryJournal({ directory, batchId: state.batch_id });
    assert.equal(observed.state_sha256, initial.state_sha256);
    assert.equal(observed.state.sequence, 0);
  });
}

test("directory fsync failure leaves a complete indeterminate publication for inspection", (t) => {
  const { directory } = fixture(t);
  let state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  persistPhalaRecoveryJournal({ directory, state, lock });
  state = transitionPhalaExecutorState(state, reservationsEvent());
  assert.throws(
    () => persistPhalaRecoveryJournal({
      directory,
      state,
      lock,
      faultStage: "directory-fsync",
    }),
    /injected durable-write failure/,
  );
  const observed = loadPhalaRecoveryJournal({ directory, batchId: state.batch_id });
  assert.equal(observed.state.sequence, 1);
  assert.equal(observed.state.reservations.length, 7);
});

test("attempt cursor always reloads as reconciliation-required, never automatic retry", (t) => {
  const { directory } = fixture(t);
  let state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  persistPhalaRecoveryJournal({ directory, state, lock });
  state = transitionPhalaExecutorState(state, reservationsEvent());
  persistPhalaRecoveryJournal({ directory, state, lock });
  state = transitionPhalaExecutorState(state, {
    type: "provision_attempt",
    domain: PHALA_EXECUTION_ORDER[0],
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
    attempted_at: "2026-07-21T12:00:02Z",
  });
  persistPhalaRecoveryJournal({ directory, state, lock });
  const requirement = classifyPhalaRecoveryRequirement(
    loadPhalaRecoveryJournal({ directory, batchId: state.batch_id }),
  );
  assert.equal(requirement.action, "read_only_reconciliation_required");
  assert.equal(requirement.automatic_retry_authorized, false);
  assert.equal(requirement.automatic_cleanup_authorized, false);
  assert.equal(requirement.pending_mutation.action, "provisionCvm");
});

test("ambiguous partial outcomes become terminal manual reconciliation journals", (t) => {
  const { directory } = fixture(t);
  let state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  const persist = () => persistPhalaRecoveryJournal({ directory, state, lock });
  persist();
  state = transitionPhalaExecutorState(state, reservationsEvent());
  persist();
  state = transitionPhalaExecutorState(state, {
    type: "provision_attempt",
    domain: PHALA_EXECUTION_ORDER[0],
    request_sha256: digest("4"),
    readiness_sha256: digest("5"),
    attempted_at: "2026-07-21T12:00:02Z",
  });
  persist();
  state = transitionPhalaExecutorState(state, {
    type: "mutation_outcome_ambiguous",
    action: "provisionCvm",
    domain: PHALA_EXECUTION_ORDER[0],
    reason_code: "timeout-after-send",
  });
  persist();
  state = transitionPhalaExecutorState(state, {
    type: "reconciliation_recorded",
    observed_committed_domains: [PHALA_EXECUTION_ORDER[0]],
    observation_sha256: digest("6"),
  });
  persist();
  const journal = loadPhalaRecoveryJournal({ directory, batchId: state.batch_id });
  const requirement = classifyPhalaRecoveryRequirement(journal);
  assert.equal(state.status, "partial_commit_requires_operator_reconciliation");
  assert.equal(requirement.action, "terminal_operator_review_required");

  const forgedContinuation = structuredClone(state);
  forgedContinuation.sequence += 1;
  assert.throws(
    () => persistPhalaRecoveryJournal({
      directory,
      state: forgedContinuation,
      lock,
    }),
    /terminal recovery journals/,
  );
});

test("journal serialization rejects secret-bearing fields and never stores ciphertext", (t) => {
  const { directory } = fixture(t);
  const state = initialState(directory);
  const lock = acquirePhalaRecoveryJournalLock({
    directory,
    batchId: state.batch_id,
    authorizationId: state.bootstrap_authorization_id,
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  t.after(() => {
    if (fs.existsSync(lock.path)) releasePhalaRecoveryJournalLock(lock);
  });
  const poisoned = structuredClone(state);
  poisoned.api_key = ["phak_", "should-never-be-written"].join("");
  assert.throws(
    () => persistPhalaRecoveryJournal({ directory, state: poisoned, lock }),
    /secret-bearing field/,
  );
  assert.equal(
    fs.existsSync(phalaRecoveryJournalPaths(directory, state.batch_id).journal),
    false,
  );
});

test("journal directory rejects permissive mode and symlink endpoints", (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phala-journal-bad-"));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const permissive = path.join(parent, "permissive");
  fs.mkdirSync(permissive, { mode: 0o755 });
  fs.chmodSync(permissive, 0o755);
  assert.throws(
    () => ensurePhalaRecoveryJournalDirectory(permissive),
    /exact mode 0700/,
  );
  const real = path.join(parent, "real");
  fs.mkdirSync(real, { mode: 0o700 });
  const linked = path.join(parent, "linked");
  fs.symlinkSync(real, linked);
  assert.throws(
    () => ensurePhalaRecoveryJournalDirectory(linked),
    /non-symlink directory/,
  );
});
