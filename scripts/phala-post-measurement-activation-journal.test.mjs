import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  acquirePhalaPostMeasurementActivationLock,
  assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal,
  classifyPhalaPostMeasurementActivationRecovery,
  createInitialPhalaPostMeasurementActivationState,
  loadPhalaPostMeasurementActivationJournal,
  normalizePhalaPostMeasurementActivationJournal,
  normalizePhalaPostMeasurementActivationState,
  persistPhalaPostMeasurementActivationJournal,
  phalaPostMeasurementActivationJournalSha256,
  phalaPostMeasurementActivationJournalPaths,
  phalaPostMeasurementActivationStateSha256,
  projectPhalaPostMeasurementActivationJournal,
  releasePhalaPostMeasurementActivationLock,
  transitionPhalaPostMeasurementActivationState,
} from "./phala-post-measurement-activation-journal.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
} from "./phala-pinned-private-directory.mjs";

const sha = (digit) => `sha256:${digit.repeat(64)}`;

function privateDirectory() {
  const parent = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-activation-journal-"),
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "state");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  return directory;
}

function initial() {
  return createInitialPhalaPostMeasurementActivationState({
    batchId: sha("1"),
    releaseSha: "a".repeat(40),
    activationPlanSha256: sha("2"),
    preCeremonyRuntimeAuthoritySha256: sha("3"),
    ceremonyAuthorizationSha256: sha("4"),
    target: {
      domain: "main_runtime_cvm",
      app_id: "b".repeat(40),
      cvm_id: "cvm-main-0001",
    },
    allowedEnvironmentKeyNamesSha256: sha("5"),
    injectedEnvironmentKeyNamesSha256: sha("6"),
    adapterIdentitySha256: sha("7"),
    assemblyReceiptSha256: sha("8"),
  });
}

function observation(method, callSequence, digit, observedAt) {
  return {
    method,
    call_sequence: callSequence,
    observation_sha256: sha(digit),
    request_semantics_sha256: sha(digit),
    observed_at: observedAt,
  };
}

function readPrefix() {
  return [
    observation("getCurrentUser", 1, "9", "2026-07-21T12:00:00Z"),
    observation("getAppEnvEncryptPubKey", 2, "a", "2026-07-21T12:00:01Z"),
    observation("getAppEnvEncryptPubKey", 3, "b", "2026-07-21T12:00:02Z"),
  ];
}

function completeState() {
  let state = initial();
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "pre_patch_reads_observed",
    observations: readPrefix(),
  });
  const patchSemantics = sha("c");
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_attempt_recorded",
    action: "updateCvmEnvs",
    requestSemanticsSha256: patchSemantics,
    recordedAt: "2026-07-21T12:00:03Z",
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_observed",
    action: "updateCvmEnvs",
    observation: {
      ...observation("updateCvmEnvs", 4, "d", "2026-07-21T12:00:04Z"),
      request_semantics_sha256: patchSemantics,
    },
  });
  const restartSemantics = sha("e");
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_attempt_recorded",
    action: "restartCvm",
    requestSemanticsSha256: restartSemantics,
    recordedAt: "2026-07-21T12:00:05Z",
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_observed",
    action: "restartCvm",
    observation: {
      ...observation("restartCvm", 5, "f", "2026-07-21T12:00:06Z"),
      request_semantics_sha256: restartSemantics,
    },
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "post_restart_authenticated_phala_attestation_observation_verified",
    observations: [
      observation("getCvmInfo", 6, "1", "2026-07-21T12:00:07Z"),
      observation("getCvmAttestation", 7, "2", "2026-07-21T12:00:08Z"),
    ],
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "arena_worker_activation_verified",
    arenaWorkerPresenceSha256: sha("3"),
    verifiedAt: "2026-07-21T12:00:09Z",
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "compute_recipient_activation_verified",
    computeRecipientActivationSha256: sha("4"),
    verifiedAt: "2026-07-21T12:00:10Z",
  });
  return transitionPhalaPostMeasurementActivationState(state, {
    type: "completed",
    completedAt: "2026-07-21T12:00:10Z",
  });
}

test("activation state freezes journal-before-PATCH, restart, fresh reads, proof, completion", () => {
  const state = completeState();
  assert.equal(state.status, "complete");
  assert.equal(state.sequence, 9);
  assert.deepEqual(state.profile_activation, {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  });
  assert.equal(state.arena_worker_presence_sha256, sha("3"));
  assert.equal(state.compute_recipient_activation_sha256, sha("4"));
  assert.match(
    state.combined_activation_verification_sha256,
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.deepEqual(state.sdk_observations.map(({ method }) => method), [
    "getCurrentUser",
    "getAppEnvEncryptPubKey",
    "getAppEnvEncryptPubKey",
    "updateCvmEnvs",
    "restartCvm",
    "getCvmInfo",
    "getCvmAttestation",
  ]);
  assert.deepEqual(state.mutation_attempts.map(({ action }) => action), [
    "updateCvmEnvs",
    "restartCvm",
  ]);
  assert.match(phalaPostMeasurementActivationStateSha256(state), /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(normalizePhalaPostMeasurementActivationState(state), state);
  assert.equal(JSON.stringify(state).includes("encrypted_env"), false);
});

test("pure journal projection is exact and deeply frozen but carries no durable brand", () => {
  const state = completeState();
  const projected = projectPhalaPostMeasurementActivationJournal(state);
  assert.deepEqual(
    normalizePhalaPostMeasurementActivationJournal(projected),
    projected,
  );
  assert.equal(Object.isFrozen(projected), true);
  assert.equal(Object.isFrozen(projected.state), true);
  assert.equal(Object.isFrozen(projected.state.sdk_observations), true);
  assert.equal(Object.isFrozen(projected.state.profile_activation), true);
  assert.match(
    phalaPostMeasurementActivationJournalSha256(projected),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.throws(
    () => assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal({
      journal: projected,
      directory: "/not-consulted-without-a-durable-brand",
      state,
      lock: null,
    }),
    /durably persisted completed activation journal/,
  );
});

test("activation journal requires real calendar seconds and accepts a leap-day month boundary", () => {
  const leapBoundary = structuredClone(completeState());
  const observationTimes = [
    "2024-02-29T23:59:51Z",
    "2024-02-29T23:59:52Z",
    "2024-02-29T23:59:53Z",
    "2024-02-29T23:59:55Z",
    "2024-02-29T23:59:57Z",
    "2024-02-29T23:59:58Z",
    "2024-02-29T23:59:59Z",
  ];
  leapBoundary.sdk_observations.forEach((entry, index) => {
    entry.observed_at = observationTimes[index];
  });
  leapBoundary.mutation_attempts[0].recorded_at = "2024-02-29T23:59:54Z";
  leapBoundary.mutation_attempts[1].recorded_at = "2024-02-29T23:59:56Z";
  leapBoundary.arena_worker_presence_verified_at = "2024-03-01T00:00:00Z";
  leapBoundary.compute_recipient_activation_verified_at = "2024-03-01T00:00:01Z";
  leapBoundary.completed_at = "2024-03-01T00:00:01Z";
  assert.deepEqual(
    normalizePhalaPostMeasurementActivationState(leapBoundary),
    leapBoundary,
  );

  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2026-02-30T12:00:00Z",
  ]) {
    const invalid = structuredClone(completeState());
    invalid.sdk_observations[0].observed_at = impossible;
    assert.throws(
      () => normalizePhalaPostMeasurementActivationState(invalid),
      /canonical UTC second/,
    );
  }
});

test("durable activation journal is mode-0600, monotonic, branded, and ciphertext-free", () => {
  const directory = privateDirectory();
  const planSha = sha("2");
  const lock = acquirePhalaPostMeasurementActivationLock({
    directory,
    activationPlanSha256: planSha,
    ceremonyAuthorizationSha256: sha("4"),
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  try {
    let state = initial();
    let journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "pre_patch_reads_observed",
      observations: readPrefix(),
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    const patchSemantics = sha("c");
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_attempt_recorded",
      action: "updateCvmEnvs",
      requestSemanticsSha256: patchSemantics,
      recordedAt: "2026-07-21T12:00:03Z",
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    assert.equal(journal.state.status, "patch_attempt_durable");

    // Continue from the pure complete state using each exact monotonic state.
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_observed",
      action: "updateCvmEnvs",
      observation: {
        ...observation("updateCvmEnvs", 4, "d", "2026-07-21T12:00:04Z"),
        request_semantics_sha256: patchSemantics,
      },
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    const restartSemantics = sha("e");
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_attempt_recorded",
      action: "restartCvm",
      requestSemanticsSha256: restartSemantics,
      recordedAt: "2026-07-21T12:00:05Z",
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_observed",
      action: "restartCvm",
      observation: {
        ...observation("restartCvm", 5, "f", "2026-07-21T12:00:06Z"),
        request_semantics_sha256: restartSemantics,
      },
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type:
        "post_restart_authenticated_phala_attestation_observation_verified",
      observations: [
        observation("getCvmInfo", 6, "1", "2026-07-21T12:00:07Z"),
        observation("getCvmAttestation", 7, "2", "2026-07-21T12:00:08Z"),
      ],
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "arena_worker_activation_verified",
      arenaWorkerPresenceSha256: sha("3"),
      verifiedAt: "2026-07-21T12:00:09Z",
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "compute_recipient_activation_verified",
      computeRecipientActivationSha256: sha("4"),
      verifiedAt: "2026-07-21T12:00:10Z",
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "completed",
      completedAt: "2026-07-21T12:00:10Z",
    });
    journal = persistPhalaPostMeasurementActivationJournal({ directory, state, lock });
    assert.equal(
      assertDurablyPersistedCompletedPhalaPostMeasurementActivationJournal({
        journal,
        directory,
        state,
        lock,
      }),
      journal,
    );
    const paths = phalaPostMeasurementActivationJournalPaths(directory, planSha);
    assert.equal(fs.statSync(paths.journal).mode & 0o777, 0o600);
    const text = fs.readFileSync(paths.journal, "utf8");
    assert.equal(text.includes('"encrypted_env"'), false);
    assert.deepEqual(
      loadPhalaPostMeasurementActivationJournal({
        directory,
        activationPlanSha256: planSha,
      }),
      journal,
    );
  } finally {
    releasePhalaPostMeasurementActivationLock(lock);
    fs.rmSync(path.dirname(directory), { recursive: true, force: true });
  }
});

test("activation lock source commits its plan digest exactly once", () => {
  const source = fs.readFileSync(
    new URL("./phala-post-measurement-activation-journal.mjs", import.meta.url),
    "utf8",
  );
  const acquireStart = source.indexOf(
    "export function acquirePhalaPostMeasurementActivationLock",
  );
  const documentStart = source.indexOf("const document = {", acquireStart);
  const documentEnd = source.indexOf("const bytes =", documentStart);
  assert.notEqual(acquireStart, -1);
  assert.notEqual(documentStart, -1);
  assert.notEqual(documentEnd, -1);
  const lockDocumentSource = source.slice(documentStart, documentEnd);
  assert.equal(
    [...lockDocumentSource.matchAll(/activation_plan_sha256\s*:/g)].length,
    1,
  );
});

test("activation persistence and lock release stay on the pinned directory after replacement", () => {
  const directory = privateDirectory();
  const parent = path.dirname(directory);
  const held = path.join(parent, "held-state");
  const lock = acquirePhalaPostMeasurementActivationLock({
    directory,
    activationPlanSha256: sha("2"),
    ceremonyAuthorizationSha256: sha("4"),
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  let released = false;
  try {
    const lockDocument = JSON.parse(fs.readFileSync(lock.path, "utf8"));
    assert.equal(
      lockDocument.phala_recovery_directory_identity_anchor_sha256,
      phalaPinnedPrivateDirectoryIdentityAnchorSha256(lock.pinnedDirectory),
    );
    let state = initial();
    persistPhalaPostMeasurementActivationJournal({ directory, state, lock });

    const replacement = spawnSync(process.execPath, [
      "--input-type=module",
      "-e",
      [
        "import fs from 'node:fs';",
        "import path from 'node:path';",
        "const [directory, held, lockName] = process.argv.slice(1);",
        "fs.renameSync(directory, held);",
        "fs.mkdirSync(directory, { mode: 0o700 });",
        "fs.writeFileSync(path.join(directory, lockName), 'replacement lock\\n', { mode: 0o600 });",
        "fs.writeFileSync(path.join(directory, 'replacement.sentinel'), 'replacement\\n', { mode: 0o600 });",
      ].join("\n"),
      directory,
      held,
      path.basename(lock.path),
    ], { encoding: "utf8" });
    assert.equal(replacement.status, 0, replacement.stderr);

    state = transitionPhalaPostMeasurementActivationState(state, {
      type: "pre_patch_reads_observed",
      observations: readPrefix(),
    });
    const journal = persistPhalaPostMeasurementActivationJournal({
      directory,
      state,
      lock,
    });
    assert.equal(journal.state.sequence, 1);
    const journalName = `${sha("2").slice("sha256:".length)}.activation.journal.json`;
    assert.equal(
      JSON.parse(fs.readFileSync(path.join(held, journalName), "utf8")).state.sequence,
      1,
    );
    assert.equal(fs.existsSync(path.join(directory, journalName)), false);

    releasePhalaPostMeasurementActivationLock(lock);
    released = true;
    assert.equal(fs.existsSync(path.join(held, path.basename(lock.path))), false);
    assert.equal(
      fs.readFileSync(path.join(directory, path.basename(lock.path)), "utf8"),
      "replacement lock\n",
    );
    assert.equal(
      fs.readFileSync(path.join(directory, "replacement.sentinel"), "utf8"),
      "replacement\n",
    );
  } finally {
    if (!released) {
      try { releasePhalaPostMeasurementActivationLock(lock); } catch {
        closePhalaPinnedPrivateDirectory(lock.pinnedDirectory);
      }
    }
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("an old activation lock cannot release an identical-byte replacement", () => {
  const directory = privateDirectory();
  const lock = acquirePhalaPostMeasurementActivationLock({
    directory,
    activationPlanSha256: sha("2"),
    ceremonyAuthorizationSha256: sha("4"),
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  const replacementBytes = fs.readFileSync(lock.path);
  const originalInode = fs.statSync(lock.path).ino;
  try {
    const source = [
      "import fs from 'node:fs';",
      "const [file, encoded] = process.argv.slice(1);",
      "fs.unlinkSync(file);",
      "fs.writeFileSync(file, Buffer.from(encoded, 'base64'), { mode: 0o600 });",
    ].join("\n");
    const replaced = spawnSync(process.execPath, [
      "--input-type=module",
      "-e",
      source,
      lock.path,
      replacementBytes.toString("base64"),
    ], { encoding: "utf8" });
    assert.equal(replaced.status, 0, replaced.stderr);
    const replacementInode = fs.statSync(lock.path).ino;
    assert.notEqual(replacementInode, originalInode);
    assert.throws(
      () => releasePhalaPostMeasurementActivationLock(lock),
      /identity differs/,
    );
    assert.deepEqual(fs.readFileSync(lock.path), replacementBytes);
    assert.equal(fs.statSync(lock.path).ino, replacementInode);
  } finally {
    closePhalaPinnedPrivateDirectory(lock.pinnedDirectory);
    fs.rmSync(path.dirname(directory), { recursive: true, force: true });
  }
});

test("a crash-left activation-lock quarantine blocks reacquisition", () => {
  const directory = privateDirectory();
  const first = acquirePhalaPostMeasurementActivationLock({
    directory,
    activationPlanSha256: sha("2"),
    ceremonyAuthorizationSha256: sha("4"),
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  const lockName = path.basename(first.path);
  try {
    releasePhalaPostMeasurementActivationLock(first);
    fs.writeFileSync(
      path.join(directory, `.${lockName}.release-${"b".repeat(64)}`),
      "quarantined activation lock evidence\n",
      { mode: 0o600 },
    );
    assert.throws(
      () => acquirePhalaPostMeasurementActivationLock({
        directory,
        activationPlanSha256: sha("2"),
        ceremonyAuthorizationSha256: sha("4"),
        acquiredAt: "2026-07-21T12:01:00Z",
      }),
      /quarantined activation lock release/,
    );
  } finally {
    fs.rmSync(path.dirname(directory), { recursive: true, force: true });
  }
});

test("a durable mutation attempt quarantines ambiguity and can never retry automatically", () => {
  let state = transitionPhalaPostMeasurementActivationState(initial(), {
    type: "pre_patch_reads_observed",
    observations: readPrefix(),
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_attempt_recorded",
    action: "updateCvmEnvs",
    requestSemanticsSha256: sha("c"),
    recordedAt: "2026-07-21T12:00:03Z",
  });
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "mutation_outcome_ambiguous",
  });
  assert.equal(state.status, "ambiguous_reconcile_required");
  assert.equal(state.pending_mutation.action, "updateCvmEnvs");
  const malformedAmbiguity = structuredClone(state);
  malformedAmbiguity.sdk_observations = [];
  assert.throws(
    () => normalizePhalaPostMeasurementActivationState(malformedAmbiguity),
    /status does not match its exact prefixes/,
  );
  assert.deepEqual(classifyPhalaPostMeasurementActivationRecovery({ state }), {
    action: "read_only_reconciliation_required",
    pending_mutation: state.pending_mutation,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  });
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "mutation_observed",
      action: "updateCvmEnvs",
      observation: observation("updateCvmEnvs", 4, "d", "2026-07-21T12:00:04Z"),
    }),
    /terminal/,
  );
});

test("post-restart authenticated Phala attestation observation still requires Arena then Compute proof or terminal review", () => {
  let state = completeState();
  state = structuredClone(state);
  state.status =
    "post_restart_authenticated_phala_attestation_observation_verified";
  state.sequence = 6;
  state.arena_worker_presence_sha256 = null;
  state.arena_worker_presence_verified_at = null;
  state.compute_recipient_activation_sha256 = null;
  state.compute_recipient_activation_verified_at = null;
  state.combined_activation_verification_sha256 = null;
  state.completed_at = null;
  state = normalizePhalaPostMeasurementActivationState(state);
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "arena_worker_activation_unavailable",
  });
  assert.equal(state.status, "post_restart_evidence_operator_review_required");
  assert.equal(state.failure_reason_code, "arena_worker_activation_unavailable");
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "arena_worker_activation_verified",
      arenaWorkerPresenceSha256: sha("3"),
      verifiedAt: "2026-07-21T12:00:09Z",
    }),
    /terminal/,
  );
});

test("journal completion requires both proof digests in post-restart temporal order", () => {
  const completed = structuredClone(completeState());
  completed.status =
    "post_restart_authenticated_phala_attestation_observation_verified";
  completed.sequence = 6;
  completed.arena_worker_presence_sha256 = null;
  completed.arena_worker_presence_verified_at = null;
  completed.compute_recipient_activation_sha256 = null;
  completed.compute_recipient_activation_verified_at = null;
  completed.combined_activation_verification_sha256 = null;
  completed.completed_at = null;
  let state = normalizePhalaPostMeasurementActivationState(completed);
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "completed",
      completedAt: "2026-07-21T12:00:09Z",
    }),
    /not authorized/,
  );
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "compute_recipient_activation_verified",
      computeRecipientActivationSha256: sha("4"),
      verifiedAt: "2026-07-21T12:00:09Z",
    }),
    /not authorized/,
  );
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "arena_worker_activation_verified",
      arenaWorkerPresenceSha256: sha("3"),
      verifiedAt: "2026-07-21T12:00:08Z",
    }),
    /after post-restart attestation/,
  );
  state = transitionPhalaPostMeasurementActivationState(state, {
    type: "arena_worker_activation_verified",
    arenaWorkerPresenceSha256: sha("3"),
    verifiedAt: "2026-07-21T12:00:09Z",
  });
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "completed",
      completedAt: "2026-07-21T12:00:09Z",
    }),
    /not authorized/,
  );
  assert.throws(
    () => transitionPhalaPostMeasurementActivationState(state, {
      type: "compute_recipient_activation_verified",
      computeRecipientActivationSha256: sha("4"),
      verifiedAt: "2026-07-21T12:00:08Z",
    }),
    /in order/,
  );
});

test("activation state rejects gaps, reversed timestamps, proof before restart reads, and drift", () => {
  const malformed = [
    (value) => { value.target.cvm_id = "CVM-NOT-CANONICAL"; },
    (value) => { value.sdk_observations[6].call_sequence = 8; },
    (value) => { value.sdk_observations[6].observed_at = "2026-07-21T11:59:59Z"; },
    (value) => { value.mutation_attempts[0].request_semantics_sha256 = sha("f"); },
    (value) => { value.profile_activation.profile_names.reverse(); },
    (value) => { value.arena_worker_presence_verified_at = "2026-07-21T12:00:07Z"; },
    (value) => { value.compute_recipient_activation_verified_at = "2026-07-21T12:00:08Z"; },
    (value) => { value.combined_activation_verification_sha256 = sha("f"); },
    (value) => { value.automatic_retry_authorized = true; },
    (value) => { value.completed_at = "2026-07-21T11:59:59Z"; },
  ];
  for (const mutate of malformed) {
    const value = structuredClone(completeState());
    mutate(value);
    assert.throws(() => normalizePhalaPostMeasurementActivationState(value));
  }
  let state = transitionPhalaPostMeasurementActivationState(initial(), {
    type: "pre_patch_reads_observed",
    observations: readPrefix(),
  });
  assert.throws(() => transitionPhalaPostMeasurementActivationState(state, {
    type: "compute_recipient_activation_verified",
    computeRecipientActivationSha256: sha("3"),
    verifiedAt: "2026-07-21T12:00:09Z",
  }));
});
