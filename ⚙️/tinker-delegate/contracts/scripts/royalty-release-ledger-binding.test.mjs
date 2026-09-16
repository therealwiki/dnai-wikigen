import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  canonicalJsonSha256,
  RoyaltyReleaseLedgerBindingError,
  verifyPhaseOneLedgerBinding,
} from "./royalty-release-ledger-binding.mjs";

const ADDRESS = `0x${"1".repeat(40)}`;
const PLAN_SHA = `sha256:${"2".repeat(64)}`;
const PHASE_ONE_PLAN_SHA = `sha256:${"3".repeat(64)}`;
const CLI = fileURLToPath(new URL("./royalty-release-ledger-binding.mjs", import.meta.url));

function phaseOneRecord() {
  return {
    kind: "royalty_distributor_exact_authority_release_phase",
    royaltyDistributorAddress: ADDRESS,
    phase: 1,
    executionMode: "stage_authority",
    phasePlanSha256: PHASE_ONE_PLAN_SHA,
    recordedAt: "2026-07-25T12:00:01Z",
    transactionReceipts: [{ transactionHash: `0x${"4".repeat(64)}` }],
    finalizedAuthority: {
      schema: "dnai.base-sepolia-royalty-finalized-authority.v1",
      finalizedBlockNumber: 22_000_000,
      finalizedBlockHash: `0x${"5".repeat(64)}`,
      finalizedBlockTimestamp: 1_753_444_800,
      authorityState: { paused: true },
    },
  };
}

function plan(phase = 2, record = phaseOneRecord()) {
  const prerequisite = phase === 1 ? null : {
    phase_one_plan_sha256: PHASE_ONE_PLAN_SHA,
    phase_one_history_record_sha256: canonicalJsonSha256(record),
    phase_one_finalized_at: "2025-07-25T12:00:00.000Z",
    finalized_authority_receipt_sha256: canonicalJsonSha256(record.finalizedAuthority),
  };
  return {
    schema: "dnai.royalty-release-phase-plan.v2",
    plan_sha256: PLAN_SHA,
    core: {
      schema: "dnai.royalty-release-phase-plan-core.v2",
      phase,
      authority: { distributor_address: ADDRESS },
      phase_one_prerequisite: prerequisite,
    },
  };
}

function fixture() {
  const record = phaseOneRecord();
  return { phasePlan: plan(2, record), ledger: { royaltyReleaseHistory: [record] } };
}

function rejects(fixtureValue, pattern) {
  assert.throws(
    () => verifyPhaseOneLedgerBinding(fixtureValue),
    (error) => error instanceof RoyaltyReleaseLedgerBindingError && pattern.test(error.message),
  );
}

test("phase one accepts only an empty history for the reviewed distributor", () => {
  const receipt = verifyPhaseOneLedgerBinding({
    phasePlan: plan(1),
    ledger: { royaltyReleaseHistory: [] },
  });
  assert.equal(receipt.status, "phase_one_exact_empty_history_validated");

  rejects({ phasePlan: plan(1), ledger: { royaltyReleaseHistory: [phaseOneRecord()] } },
    /empty Royalty history/);
});

test("phase two binds exact canonical history, embedded finality, and finalized block time", () => {
  const value = fixture();
  const receipt = verifyPhaseOneLedgerBinding(value);
  assert.equal(receipt.status, "phase_two_exact_phase_one_record_and_finality_validated");
  assert.equal(receipt.phaseOneHistoryRecordSha256,
    value.phasePlan.core.phase_one_prerequisite.phase_one_history_record_sha256);
  assert.equal(receipt.finalizedAuthorityReceiptSha256,
    value.phasePlan.core.phase_one_prerequisite.finalized_authority_receipt_sha256);
  assert.equal(receipt.phaseOneFinalizedAt, "2025-07-25T12:00:00.000Z");
});

test("phase two rejects a signed history-record digest that does not bind the ledger", () => {
  const value = fixture();
  value.phasePlan.core.phase_one_prerequisite.phase_one_history_record_sha256 =
    `sha256:${"6".repeat(64)}`;
  rejects(value, /history-record digest does not match/);
});

test("phase two rejects a signed finality digest that does not bind the embedded receipt", () => {
  const value = fixture();
  value.phasePlan.core.phase_one_prerequisite.finalized_authority_receipt_sha256 =
    `sha256:${"7".repeat(64)}`;
  rejects(value, /finalized-authority digest does not match/);
});

test("phase two rejects a mutable publication time in place of finalized block time", () => {
  const value = fixture();
  value.phasePlan.core.phase_one_prerequisite.phase_one_finalized_at =
    "2026-07-25T12:00:01.000Z";
  rejects(value, /finalized timestamp does not match/);
});

test("phase two rejects record mutation under stale signed commitments", () => {
  const value = fixture();
  value.ledger.royaltyReleaseHistory[0].recordedAt = "2026-07-25T12:00:02Z";
  rejects(value, /history-record digest does not match/);
});

test("phase two rejects missing or duplicated predecessor history", () => {
  const missing = fixture();
  missing.ledger.royaltyReleaseHistory = [];
  rejects(missing, /exactly one prior/);

  const duplicated = fixture();
  duplicated.ledger.royaltyReleaseHistory.push(
    structuredClone(duplicated.ledger.royaltyReleaseHistory[0]),
  );
  rejects(duplicated, /exactly one prior/);
});

test("CLI rejects noncanonical and symlinked authority inputs", (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-royalty-ledger-binding-"));
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const planPath = path.join(directory, "plan.json");
  const ledgerPath = path.join(directory, "ledger.json");
  fs.writeFileSync(planPath, `${JSON.stringify(plan(1))}\n`, { mode: 0o600 });
  fs.writeFileSync(ledgerPath, `${JSON.stringify({ royaltyReleaseHistory: [] })}\n`, {
    mode: 0o600,
  });

  const noncanonical = spawnSync(process.execPath, [
    CLI,
    "verify",
    "--plan",
    `${directory}/./plan.json`,
    "--ledger",
    ledgerPath,
  ], { encoding: "utf8" });
  assert.notEqual(noncanonical.status, 0);
  assert.match(noncanonical.stderr, /absolute and normalized/);

  const symlinkPath = path.join(directory, "plan-link.json");
  fs.symlinkSync(planPath, symlinkPath);
  const symlinked = spawnSync(process.execPath, [
    CLI,
    "verify",
    "--plan",
    symlinkPath,
    "--ledger",
    ledgerPath,
  ], { encoding: "utf8" });
  assert.notEqual(symlinked.status, 0);
  assert.match(symlinked.stderr, /canonical and symlink-free/);
});
