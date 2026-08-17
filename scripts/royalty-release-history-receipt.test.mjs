import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  normalizeRoyaltyReleaseHistory,
  projectRoyaltyReleaseHistoryReceipt,
  royaltyReleaseHistoryReceiptSha256,
} from "./royalty-release-history-receipt-core.mjs";
import {
  canonicalRoyaltyFinalizedHistoryEvidenceText,
  royaltyFinalizedHistoryEvidenceSha256,
} from "./royalty-release-finalized-history-evidence.mjs";
import {
  syntheticRoyaltyFinalizedHistoryEvidence,
  syntheticRoyaltyFrozenLedgerContext,
} from "./royalty-release-history-receipt.fixture.mjs";
import {
  runRoyaltyReleaseHistoryReceiptCli,
} from "./royalty-release-history-receipt.mjs";

const ROOT = fs.realpathSync.native(path.resolve(import.meta.dirname, ".."));
const CLI = path.join(ROOT, "scripts", "royalty-release-history-receipt.mjs");

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function domainSha256(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update(`${JSON.stringify(sorted(value), null, 2)}\n`, "utf8")
    .digest("hex")}`;
}

function rewriteMutationDigests(mutation) {
  mutation.primary_rpc_transaction_sha256 = domainSha256(
    "dnai-wikigen/base-sepolia-transaction-rpc-observation/v1\0",
    mutation.primary_rpc_transaction,
  );
  mutation.secondary_rpc_transaction = structuredClone(mutation.primary_rpc_transaction);
  mutation.secondary_rpc_transaction_sha256 = mutation.primary_rpc_transaction_sha256;
  mutation.primary_rpc_receipt_sha256 = domainSha256(
    "dnai-wikigen/base-sepolia-receipt-rpc-observation/v1\0",
    mutation.primary_rpc_receipt,
  );
  mutation.secondary_rpc_receipt = structuredClone(mutation.primary_rpc_receipt);
  mutation.secondary_rpc_receipt_sha256 = mutation.primary_rpc_receipt_sha256;
  mutation.primary_rpc_block_sha256 = domainSha256(
    "dnai-wikigen/base-sepolia-finalized-block-rpc-observation/v1\0",
    mutation.primary_rpc_block,
  );
  mutation.secondary_rpc_block = structuredClone(mutation.primary_rpc_block);
  mutation.secondary_rpc_block_sha256 = mutation.primary_rpc_block_sha256;
}

function historyOptions(evidence) {
  return {
    contracts: evidence.contracts,
    commonFinalizedState: evidence.common_finalized_state,
  };
}

test("H core rejects scalar coercion across addresses, hashes, decimals, hex, and bloom", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const rejectedReceipt = (mutate, pattern) => {
    const value = structuredClone(evidence);
    mutate(value);
    assert.throws(() => projectRoyaltyReleaseHistoryReceipt({
      contracts: value.contracts,
      commonFinalizedState: value.common_finalized_state,
      royaltyReleaseHistory: value.royalty_release_history,
    }), pattern);
  };
  rejectedReceipt((value) => {
    value.contracts[1].address = [value.contracts[0].address];
  }, /address/);
  rejectedReceipt((value) => {
    value.royalty_release_history.phase_one.proposal_transaction
      .primary_rpc_transaction.gas_limit = 1_000_000;
  }, /decimal string/);
  rejectedReceipt((value) => {
    value.royalty_release_history.phase_one.proposal_transaction
      .primary_rpc_transaction.block_hash = [
        value.royalty_release_history.phase_one.proposal_transaction
          .primary_rpc_transaction.block_hash,
      ];
  }, /bytes32/);
  rejectedReceipt((value) => {
    value.royalty_release_history.phase_one.proposal_transaction
      .primary_rpc_transaction.input_sha256 = [
        value.royalty_release_history.phase_one.proposal_transaction
          .primary_rpc_transaction.input_sha256,
      ];
  }, /SHA-256/);
  rejectedReceipt((value) => {
    value.royalty_release_history.phase_one.proposal_transaction
      .primary_rpc_receipt.logs[0].data = 12;
  }, /hex data/);
  rejectedReceipt((value) => {
    value.royalty_release_history.phase_one.proposal_transaction
      .primary_rpc_receipt.logs_bloom = [
        value.royalty_release_history.phase_one.proposal_transaction
          .primary_rpc_receipt.logs_bloom,
      ];
  }, /bloom|invalid/);
});

test("H core rejects conflicting blocks at one height and nonmonotone cross-phase nonces", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const conflict = structuredClone(evidence.royalty_release_history);
  const proposal = conflict.phase_one.proposal_transaction;
  const activation = conflict.phase_two.activation_transaction;
  activation.primary_rpc_block.block_number = proposal.primary_rpc_block.block_number;
  activation.primary_rpc_block.block_hash = `0x${"ab".repeat(32)}`;
  activation.primary_rpc_transaction.block_number = proposal.primary_rpc_block.block_number;
  activation.primary_rpc_transaction.block_hash = activation.primary_rpc_block.block_hash;
  activation.primary_rpc_receipt.block_number = proposal.primary_rpc_block.block_number;
  activation.primary_rpc_receipt.block_hash = activation.primary_rpc_block.block_hash;
  rewriteMutationDigests(activation);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    conflict,
    historyOptions(evidence),
  ), /conflicting blocks/);

  const nonceDrift = structuredClone(evidence.royalty_release_history);
  nonceDrift.phase_one.proposal_transaction.primary_rpc_transaction.nonce = "22";
  rewriteMutationDigests(nonceDrift.phase_one.proposal_transaction);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    nonceDrift,
    historyOptions(evidence),
  ), /strictly increase/);
});

test("H core rejects transaction-hash reuse across phase one and phase two", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const history = structuredClone(evidence.royalty_release_history);
  const proposalHash = history.phase_one.proposal_transaction
    .primary_rpc_transaction.transaction_hash;
  const activation = history.phase_two.activation_transaction;
  activation.primary_rpc_transaction.transaction_hash = proposalHash;
  activation.primary_rpc_receipt.transaction_hash = proposalHash;
  rewriteMutationDigests(activation);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    history,
    historyOptions(evidence),
  ), /reuses a transaction hash/);
});

test("H core rejects impossible account nonces and incoherent gas observations", async () => {
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const impossibleNonce = structuredClone(evidence.royalty_release_history);
  const first = 1n << 255n;
  const mutations = [
    impossibleNonce.phase_one.proposal_transaction,
    impossibleNonce.phase_two.activation_transaction,
    impossibleNonce.phase_two.unpause_transaction,
  ];
  mutations.forEach((mutation, index) => {
    mutation.primary_rpc_transaction.nonce = (first + BigInt(index)).toString(10);
    rewriteMutationDigests(mutation);
  });
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    impossibleNonce,
    historyOptions(evidence),
  ), /account-nonce protocol limit/);

  const gasBeyondTransaction = structuredClone(evidence.royalty_release_history);
  const proposal = gasBeyondTransaction.phase_one.proposal_transaction;
  proposal.primary_rpc_receipt.gas_used = (
    BigInt(proposal.primary_rpc_transaction.gas_limit) + 1n
  ).toString(10);
  proposal.primary_rpc_receipt.cumulative_gas_used =
    proposal.primary_rpc_receipt.gas_used;
  rewriteMutationDigests(proposal);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    gasBeyondTransaction,
    historyOptions(evidence),
  ), /mutation evidence is invalid/);

  const transactionBeyondBlock = structuredClone(evidence.royalty_release_history);
  const activation = transactionBeyondBlock.phase_two.activation_transaction;
  activation.primary_rpc_transaction.gas_limit = (
    BigInt(activation.primary_rpc_block.gas_limit) + 1n
  ).toString(10);
  rewriteMutationDigests(activation);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    transactionBeyondBlock,
    historyOptions(evidence),
  ), /mutation evidence is invalid/);

  const cumulativeBeyondBlock = structuredClone(evidence.royalty_release_history);
  const unpause = cumulativeBeyondBlock.phase_two.unpause_transaction;
  unpause.primary_rpc_receipt.cumulative_gas_used = (
    BigInt(unpause.primary_rpc_block.gas_used) + 1n
  ).toString(10);
  rewriteMutationDigests(unpause);
  assert.throws(() => normalizeRoyaltyReleaseHistory(
    cumulativeBeyondBlock,
    historyOptions(evidence),
  ), /mutation evidence is invalid/);
});

function fixtureDirectory(t) {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-royalty-h-")),
  );
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function commonReplayArgs(evidence, directory) {
  return [
    "--repository-root", ROOT,
    "--source-manifest", path.join(directory, "deployment-manifest.json"),
    "--ledger", path.join(directory, "release-ledger.json"),
    "--evidence-root", path.join(directory, "ledger-evidence"),
    "--lock-root", path.join(directory, "locks"),
    "--release-sha", evidence.release_sha,
    "--deployment-intent-sha256", evidence.deployment_intent_sha256,
    "--reviewer-genesis-acceptance-sha256",
    evidence.reviewer_authority_genesis_acceptance_sha256,
    "--tinker-account-binding-ceremony-receipt-sha256",
    evidence.tinker_account_binding_ceremony_receipt_sha256,
  ];
}

function runFixtureCli(argv, frozenContext) {
  return runRoyaltyReleaseHistoryReceiptCli(argv, {
    frozenLedgerLoader: () => frozenContext,
  });
}

test("offline CLI creates immutable canonical H and independently verifies its domain digest", async (t) => {
  const directory = fixtureDirectory(t);
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const evidencePath = path.join(directory, "evidence.json");
  const receiptPath = path.join(directory, "H.json");
  fs.writeFileSync(
    evidencePath,
    canonicalRoyaltyFinalizedHistoryEvidenceText(evidence),
    { flag: "wx", mode: 0o444 },
  );
  fs.chmodSync(evidencePath, 0o444);
  const replayArgs = commonReplayArgs(evidence, directory);
  const frozenContext = syntheticRoyaltyFrozenLedgerContext(evidence);
  const createReceipt = runFixtureCli([
    "create", ...replayArgs, "--input", evidencePath, "--out", receiptPath,
  ], frozenContext);
  assert.equal(createReceipt.status,
    "canonical_royalty_release_history_receipt_v2_written_create_only");
  assert.equal(fs.statSync(receiptPath).mode & 0o777, 0o444);
  const persisted = JSON.parse(fs.readFileSync(receiptPath, "utf8"));
  const digest = royaltyReleaseHistoryReceiptSha256(persisted);
  assert.equal(createReceipt.royalty_release_history_receipt_sha256, digest);
  assert.notEqual(createReceipt.raw_output_sha256, digest);
  assert.equal(
    createReceipt.finalized_history_evidence_sha256,
    royaltyFinalizedHistoryEvidenceSha256(evidence),
  );
  assert.match(
    createReceipt.raw_finalized_history_evidence_sha256,
    /^sha256:[0-9a-f]{64}$/,
  );

  const verifyReceipt = runFixtureCli([
    "verify", ...replayArgs, "--input", evidencePath, "--in", receiptPath,
    "--expected-royalty-release-history-receipt-sha256", digest,
  ], frozenContext);
  assert.equal(verifyReceipt.status,
    "canonical_royalty_release_history_receipt_v2_verified");

  assert.throws(() => runFixtureCli([
    "verify", ...replayArgs, "--input", evidencePath, "--in", receiptPath,
    "--expected-royalty-release-history-receipt-sha256",
    createReceipt.raw_output_sha256,
  ], frozenContext), /expected digest/);

  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", evidencePath, "--out", receiptPath,
  ], frozenContext), /absent/);

  const missingReplay = spawnSync(process.execPath, [
    CLI, "create", "--input", evidencePath,
    "--out", path.join(directory, "missing-replay.json"),
  ], { encoding: "utf8" });
  assert.notEqual(missingReplay.status, 0);
  assert.match(missingReplay.stderr, /arguments are incomplete/);
});

test("offline H creation binds actual ledger digests, seven records, and Royalty transactions", async (t) => {
  const directory = fixtureDirectory(t);
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const replayArgs = commonReplayArgs(evidence, directory);
  const writeEvidence = (name, value) => {
    const filePath = path.join(directory, name);
    fs.writeFileSync(
      filePath,
      canonicalRoyaltyFinalizedHistoryEvidenceText(value),
      { mode: 0o444, flag: "wx" },
    );
    fs.chmodSync(filePath, 0o444);
    return filePath;
  };
  const evidencePath = writeEvidence("evidence.json", evidence);
  const frozenContext = syntheticRoyaltyFrozenLedgerContext(evidence);

  const forgedLedgerPin = structuredClone(evidence);
  forgedLedgerPin.frozen_final_ledger_sha256 = `sha256:${"9".repeat(64)}`;
  const forgedPath = writeEvidence("forged-ledger-pin.json", forgedLedgerPin);
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", forgedPath,
    "--out", path.join(directory, "forged-H.json"),
  ], frozenContext), /ledger digests differ from replay/);

  const recordDrift = structuredClone(frozenContext);
  recordDrift.ledger.contracts.diligenceRoom.syntheticFixtureIndex = 99;
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", evidencePath,
    "--out", path.join(directory, "record-drift-H.json"),
  ], recordDrift), /exact frozen-ledger record/);

  const transactionDrift = structuredClone(frozenContext);
  transactionDrift.ledger.royaltyReleaseHistory[0]
    .transactionReceipts[0].transactionHash = `0x${"99".repeat(32)}`;
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", evidencePath,
    "--out", path.join(directory, "transaction-drift-H.json"),
  ], transactionDrift), /transaction hashes differ/);
});

test("offline CLI rejects noncanonical, mutable, relative, and symlinked evidence", async (t) => {
  const directory = fixtureDirectory(t);
  const evidence = await syntheticRoyaltyFinalizedHistoryEvidence();
  const replayArgs = commonReplayArgs(evidence, directory);
  const frozenContext = syntheticRoyaltyFrozenLedgerContext(evidence);
  const canonical = canonicalRoyaltyFinalizedHistoryEvidenceText(evidence);
  const mutablePath = path.join(directory, "mutable.json");
  fs.writeFileSync(mutablePath, canonical, { mode: 0o666 });
  fs.chmodSync(mutablePath, 0o666);
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", mutablePath,
    "--out", path.join(directory, "a.json"),
  ], frozenContext), /non-writable/);

  const source = path.join(directory, "source.json");
  const link = path.join(directory, "link.json");
  fs.writeFileSync(source, canonical, { mode: 0o444 });
  fs.chmodSync(source, 0o444);
  fs.symlinkSync(source, link);
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", link,
    "--out", path.join(directory, "b.json"),
  ], frozenContext), /symlink-free/);

  const noncanonical = path.join(directory, "noncanonical.json");
  fs.writeFileSync(noncanonical, JSON.stringify(evidence), { mode: 0o444 });
  fs.chmodSync(noncanonical, 0o444);
  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", noncanonical,
    "--out", path.join(directory, "c.json"),
  ], frozenContext), /canonical recursively sorted/);

  assert.throws(() => runFixtureCli([
    "create", ...replayArgs, "--input", "source.json",
    "--out", path.join(directory, "d.json"),
  ], frozenContext), /canonical and absolute/);
});
