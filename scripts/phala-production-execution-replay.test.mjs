import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PHALA_EXACT_SDK_CALL_SEQUENCE,
  PHALA_EXECUTION_ORDER,
  createInitialPhalaExecutorState,
  normalizeCompletedPhalaExecutorState,
  registerProvenanceVerifiedCompletedPhalaExecutorState,
  transitionPhalaExecutorState,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE,
  PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA,
  assertDurablyPersistedProductionExecutionReplay,
  canonicalProductionExecutionReplayReceiptText,
  loadProductionExecutionReplayReceipt,
  normalizeProductionExecutionReplayReceipt,
  productionExecutionReplayReceiptPath,
  productionExecutionReplayReceiptSha256,
} from "./phala-production-execution-replay.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";

function digest(label) {
  return `sha256:${createHash("sha256").update(label).digest("hex")}`;
}

function second(offset) {
  return new Date(Date.UTC(2026, 6, 21, 12, 0, offset))
    .toISOString().replace(".000Z", "Z");
}

function receiptFixture() {
  // Deliberately use one second for every SDK call. The authenticated adapter
  // ordinal, rather than timestamp luck or caller array position, is the
  // authoritative exact ordering signal.
  const observedAt = second(30);
  const sdkCalls = PHALA_EXACT_AUTHENTICATED_SDK_REPLAY_SCHEDULE.map(
    ([phase, method, domain], index) => ({
      call_sequence: index + 1,
      phase,
      method,
      domain,
      observed_at: observedAt,
      observation_sha256: digest(`observation-${index}`),
      request_semantics_sha256: digest(`request-${index}`),
      sdk_response_sha256: digest(`response-${index}`),
    }),
  );
  const provisions = sdkCalls.filter(({ phase }) => phase === "provision");
  const commits = sdkCalls.filter(({ phase }) => phase === "commit");
  const mutationGates = [];
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length * 2; index += 1) {
    const isProvision = index < PHALA_EXECUTION_ORDER.length;
    const domainIndex = index % PHALA_EXECUTION_ORDER.length;
    const call = isProvision ? provisions[domainIndex] : commits[domainIndex];
    mutationGates.push({
      mutation_sequence: index + 1,
      action: isProvision ? "provisionCvm" : "commitCvmProvision",
      domain: PHALA_EXECUTION_ORDER[domainIndex],
      gate_sha256: digest(`gate-${index}`),
      readiness_sha256: digest(`readiness-${index}`),
      request_semantics_sha256: call.request_semantics_sha256,
      observation_sha256: call.observation_sha256,
      checked_at: second(29),
      expires_at: second(59),
    });
  }
  return {
    schema: PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA,
    truth_status:
      "durably_persisted_digest_only_replay_of_locally_authenticated_exact_order_phala_execution",
    batch_id: digest("batch"),
    bootstrap_authorization_id: digest("authorization"),
    release_sha: "a".repeat(40),
    target_authority_sha256: digest("target"),
    phala_recovery_directory_identity_anchor_sha256: digest("directory-anchor"),
    executor_state_sha256: digest("state"),
    terminal_recovery_journal_sha256: digest("journal"),
    adapter_identity_sha256: digest("adapter"),
    call_sequence_contract: [...PHALA_EXACT_SDK_CALL_SEQUENCE],
    sdk_call_count: sdkCalls.length,
    sdk_calls: sdkCalls,
    mutation_gate_count: mutationGates.length,
    mutation_gates: mutationGates,
    persisted_at: observedAt,
    payload_persistence: "digests_only_no_requests_responses_ciphertext_or_secrets",
    live_traffic_authorized: false,
  };
}

function completedState() {
  let state = createInitialPhalaExecutorState({
    batchId: digest("state-batch"),
    bootstrapAuthorizationId: digest("state-authorization"),
    bootstrapAuthorizationReceiptSha256: digest("state-authorization-receipt"),
    releaseSha: "b".repeat(40),
    launchIntentSha256: digest("launch-intent"),
    targetAuthoritySha256: digest("state-target"),
    phalaRecoveryDirectoryIdentityAnchorSha256: digest("state-directory-anchor"),
  });
  state = transitionPhalaExecutorState(state, {
    type: "app_ids_observed",
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: (index + 1).toString(16).repeat(40),
      nonce: 100 + index,
    })),
  });
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    state = transitionPhalaExecutorState(state, {
      type: "provision_attempt",
      domain,
      request_sha256: digest(`state-provision-request-${index}`),
      readiness_sha256: digest(`state-provision-readiness-${index}`),
      attempted_at: second(index * 2),
    });
    state = transitionPhalaExecutorState(state, {
      type: "provision_observed",
      domain,
      observation_sha256: digest(`state-provision-observation-${index}`),
      observed_at: second(index * 2 + 1),
    });
  }
  state = transitionPhalaExecutorState(state, {
    type: "preparations_validated",
    validation_sha256: digest("state-preparations-validation"),
  });
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    state = transitionPhalaExecutorState(state, {
      type: "signed_key_observed",
      domain: PHALA_EXECUTION_ORDER[index],
      binding_sha256: digest(`state-binding-${index}`),
      public_key_sha256: digest(`state-public-key-${index}`),
    });
  }
  for (let index = 0; index < PHALA_EXECUTION_ORDER.length; index += 1) {
    const domain = PHALA_EXECUTION_ORDER[index];
    state = transitionPhalaExecutorState(state, {
      type: "commit_attempt",
      domain,
      request_sha256: digest(`state-commit-request-${index}`),
      readiness_sha256: digest(`state-commit-readiness-${index}`),
      attempted_at: second(20 + index * 2),
    });
    state = transitionPhalaExecutorState(state, {
      type: "commit_observed",
      domain,
      cvm_id: `cvm-${index + 1}`,
      observation_sha256: digest(`state-commit-observation-${index}`),
      observed_at: second(21 + index * 2),
    });
  }
  state = transitionPhalaExecutorState(state, {
    type: "posture_validated",
    receipts: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      receipt_sha256: digest(`state-posture-${index}`),
    })),
  });
  return normalizeCompletedPhalaExecutorState(state);
}

test("digest-only replay receipt fixes all 48 calls and fourteen mutation gates", () => {
  const fixture = receiptFixture();
  const normalized = normalizeProductionExecutionReplayReceipt(fixture);
  assert.equal(normalized.sdk_call_count, 48);
  assert.equal(normalized.mutation_gate_count, 14);
  assert.deepEqual(
    normalized.sdk_calls.slice(20, 24).map(({ phase, domain }) => [phase, domain]),
    [
      ["immediate_environment_key_refetch", PHALA_EXECUTION_ORDER[0]],
      ["commit", PHALA_EXECUTION_ORDER[0]],
      ["immediate_environment_key_refetch", PHALA_EXECUTION_ORDER[1]],
      ["commit", PHALA_EXECUTION_ORDER[1]],
    ],
  );
  assert.equal(new Set(normalized.sdk_calls.map(({ observed_at }) => observed_at)).size, 1);
  assert.match(productionExecutionReplayReceiptSha256(normalized), SHA256_PATTERN);
  assert.equal(canonicalProductionExecutionReplayReceiptText(fixture).endsWith("\n"), true);
});

test("execution replay requires real calendar seconds and accepts a leap-day month boundary", () => {
  const leapBoundary = receiptFixture();
  for (const call of leapBoundary.sdk_calls) {
    call.observed_at = "2024-02-29T23:59:59Z";
  }
  for (const gate of leapBoundary.mutation_gates) {
    gate.checked_at = "2024-02-29T23:59:58Z";
    gate.expires_at = "2024-03-01T00:00:30Z";
  }
  leapBoundary.persisted_at = "2024-03-01T00:00:00Z";
  assert.deepEqual(normalizeProductionExecutionReplayReceipt(leapBoundary), leapBoundary);

  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2026-02-30T12:00:00Z",
  ]) {
    const invalid = receiptFixture();
    invalid.sdk_calls[0].observed_at = impossible;
    assert.throws(
      () => normalizeProductionExecutionReplayReceipt(invalid),
      /canonical UTC second/,
    );
  }
});

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

test("replay normalization rejects caller-order, gate, and payload-surface drift", () => {
  const wrongSequence = structuredClone(receiptFixture());
  wrongSequence.sdk_calls[1].call_sequence = 1;
  assert.throws(
    () => normalizeProductionExecutionReplayReceipt(wrongSequence),
    /exact authenticated call order/,
  );

  const wrongGate = structuredClone(receiptFixture());
  wrongGate.mutation_gates[0].observation_sha256 = digest("wrong-observation");
  assert.throws(
    () => normalizeProductionExecutionReplayReceipt(wrongGate),
    /does not bind its exact SDK call/,
  );

  const payload = structuredClone(receiptFixture());
  payload.raw_response = { secret: "must-not-persist" };
  assert.throws(
    () => normalizeProductionExecutionReplayReceipt(payload),
    /exactly the allowed fields/,
  );
});

test("stable load requires canonical owner-private mode-0600 receipt bytes", (t) => {
  const created = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-phala-replay-"));
  const parent = fs.realpathSync.native(created);
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "state");
  fs.mkdirSync(directory, { mode: 0o700 });
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const pinned = pinPhalaPrivateDirectory(directory);
  const identityAnchorSha256 = pinned.identity_anchor_sha256;
  closePhalaPinnedPrivateDirectory(pinned);
  const fixture = normalizeProductionExecutionReplayReceipt(receiptFixture());
  const filePath = productionExecutionReplayReceiptPath(directory, fixture.batch_id);
  fs.writeFileSync(filePath, canonicalProductionExecutionReplayReceiptText(fixture), {
    mode: 0o600,
  });
  const loaded = loadProductionExecutionReplayReceipt({
    directory,
    batchId: fixture.batch_id,
  });
  assert.deepEqual(loaded, fixture);

  const moduleUrl = new URL("./phala-production-execution-replay.mjs", import.meta.url).href;
  const source = [
    "const [moduleUrl, directory, batchId, anchor] = process.argv.slice(1);",
    "const { loadProductionExecutionReplayReceipt } = await import(moduleUrl);",
    "try {",
    "  const receipt = loadProductionExecutionReplayReceipt({",
    "    directory, batchId,",
    "    ...(anchor === '-' ? {} : { directoryIdentityAnchorSha256: anchor }),",
    "  });",
    "  process.stdout.write(`${receipt.schema}\\n`);",
    "} catch (error) { process.stderr.write(`${error.message}\\n`); process.exitCode = 23; }",
  ].join("\n");
  const unauthenticated = spawnSync(process.execPath, [
    "--input-type=module", "-e", source, moduleUrl, directory, fixture.batch_id, "-",
  ], { encoding: "utf8" });
  assert.equal(unauthenticated.status, 23);
  assert.match(unauthenticated.stderr, /externally authenticated directory identity anchor/);
  const authenticated = spawnSync(process.execPath, [
    "--input-type=module",
    "-e",
    source,
    moduleUrl,
    directory,
    fixture.batch_id,
    identityAnchorSha256,
  ], { encoding: "utf8" });
  assert.equal(authenticated.status, 0, authenticated.stderr);
  assert.equal(authenticated.stdout, `${PHALA_PRODUCTION_EXECUTION_REPLAY_SCHEMA}\n`);

  fs.chmodSync(filePath, 0o644);
  assert.throws(
    () => loadProductionExecutionReplayReceipt({
      directory,
      batchId: fixture.batch_id,
    }),
    /mode-0600/,
  );
});

test("unbranded receipt cannot reach replay assertion or core completion registrar", async () => {
  const receipt = normalizeProductionExecutionReplayReceipt(receiptFixture());
  const context = {
    directory: "/not/consulted/before/private-brand-check",
    state: null,
    journal: null,
    lock: null,
    adapter: null,
    provisionGates: [],
    commitGates: [],
    observations: null,
  };
  assert.throws(
    () => assertDurablyPersistedProductionExecutionReplay({ receipt, ...context }),
    /locally verified durably persisted/,
  );
  await assert.rejects(
    registerProvenanceVerifiedCompletedPhalaExecutorState({
      state: completedState(),
      replayReceipt: receipt,
      directory: context.directory,
      journal: null,
      lock: null,
      adapter: null,
      provisionGates: [],
      commitGates: [],
      observations: null,
    }),
    /locally verified durably persisted/,
  );
});
