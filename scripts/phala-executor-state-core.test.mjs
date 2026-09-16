import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  PHALA_EXECUTOR_STATE_DOMAIN,
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
  normalizeCompletedPhalaExecutorState as normalizeProductionExecutorState,
  phalaExecutorStateDigest as productionExecutorStateDigest,
} from "./phala-production-executor-core.mjs";

const digest = (index) =>
  `sha256:${index.toString(16).padStart(64, "0")}`;
const at = (seconds) => new Date(Date.UTC(2026, 6, 21, 10, 0, seconds))
  .toISOString().replace(".000Z", "Z");

function completedStateFixture() {
  return {
    schema: PHALA_EXECUTOR_STATE_SCHEMA,
    status: "complete_seven_commits_posture_observed_attestation_unverified",
    sequence: 38,
    batch_id: digest(1),
    bootstrap_authorization_id: digest(2),
    bootstrap_authorization_receipt_sha256: digest(3),
    release_sha: "1".repeat(40),
    launch_intent_sha256: digest(4),
    target_authority_sha256: digest(5),
    phala_recovery_directory_identity_anchor_sha256: digest(6),
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: (100 + index).toString(16).padStart(40, "0"),
      nonce: index + 1,
    })),
    preparations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      request_sha256: digest(20 + index),
      readiness_sha256: digest(40 + index),
      attempted_at: at(index * 2),
      observed_at: at(index * 2 + 1),
      observation_sha256: digest(60 + index),
    })),
    signed_key_bindings: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      binding_sha256: digest(80 + index),
      public_key_sha256: digest(100 + index),
    })),
    committed_prefix: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      cvm_id: `cvm-${String(index + 1).padStart(2, "0")}-production`,
      request_sha256: digest(120 + index),
      readiness_sha256: digest(140 + index),
      attempted_at: at(30 + index * 2),
      observed_at: at(31 + index * 2),
      observation_sha256: digest(160 + index),
    })),
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      receipt_sha256: digest(180 + index),
    })),
    preparations_validation_sha256: digest(200),
  };
}

test("executor-state core round-trips exact persisted completion bytes", () => {
  const fixture = completedStateFixture();
  const normalized = normalizeCompletedPhalaExecutorState(fixture);
  assert.deepEqual(normalized, fixture);
  assert.equal(Object.isFrozen(normalized), true);
  assert.equal(
    PHALA_EXECUTOR_STATE_DOMAIN,
    "dnai-wikigen/phala-executor-state/v3\0",
  );
  assert.match(phalaExecutorStateDigest(normalized), /^sha256:[0-9a-f]{64}$/);
});

test("executor-state core rejects order, timing, lineage, and secret drift", () => {
  const mutations = [
    (value) => value.reservations.reverse(),
    (value) => { value.committed_prefix[0].attempted_at = at(1); },
    (value) => { value.sequence = 37; },
    (value) => { value.unknown = true; },
    (value) => { value.secret_token = ["phak_", "not-allowed-secret-value"].join(""); },
  ];
  for (const mutate of mutations) {
    const value = completedStateFixture();
    mutate(value);
    assert.throws(() => normalizeCompletedPhalaExecutorState(value));
  }
});

test("executor-state core rejects impossible UTC dates and accepts a real leap day", () => {
  for (const impossible of [
    "2025-02-29T10:00:00Z",
    "2026-04-31T10:00:00Z",
    "2024-02-29T23:59:60Z",
  ]) {
    const fixture = completedStateFixture();
    fixture.preparations[0].attempted_at = impossible;
    assert.throws(
      () => normalizeCompletedPhalaExecutorState(fixture),
      /canonical UTC second/,
    );
  }

  const leapDay = completedStateFixture();
  leapDay.preparations[0].attempted_at = "2024-02-29T23:59:58Z";
  leapDay.preparations[0].observed_at = "2024-02-29T23:59:59Z";
  assert.equal(
    normalizeCompletedPhalaExecutorState(leapDay)
      .preparations[0].attempted_at,
    "2024-02-29T23:59:58Z",
  );
});

test("executor-state core rejects a sequential-get Proxy before any trap runs", () => {
  const fixture = completedStateFixture();
  let attemptedAtReads = 0;
  fixture.preparations[0] = new Proxy(fixture.preparations[0], {
    get(target, key, receiver) {
      if (key === "attempted_at") {
        attemptedAtReads += 1;
        return attemptedAtReads === 1
          ? Reflect.get(target, key, receiver)
          : "2025-02-29T10:00:00Z";
      }
      return Reflect.get(target, key, receiver);
    },
  });
  assert.throws(
    () => normalizeCompletedPhalaExecutorState(fixture),
    /canonical plain-data graph: Proxy objects are forbidden/,
  );
  assert.equal(attemptedAtReads, 0);
});

test("executor-state leaf stays byte-compatible with the production facade", () => {
  const fixture = completedStateFixture();
  const core = normalizeCompletedPhalaExecutorState(fixture);
  const production = normalizeProductionExecutorState(fixture);
  assert.deepEqual(core, production);
  assert.equal(phalaExecutorStateDigest(core), productionExecutorStateDigest(production));
});

test("executor-state leaf has no effectful production imports or authority state", async () => {
  const source = await readFile(
    new URL("./phala-executor-state-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:child_process",
    "Date.now(",
    "WeakMap",
    "WeakSet",
    "import(",
    "phala-production-execution-replay",
    "phala-production-recovery-journal",
    "phala-production-sdk-adapter",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
});
