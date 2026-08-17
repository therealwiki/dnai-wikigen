import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS,
  FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
  FRESH_CONTRACT_BROADCAST_PROOF,
  FRESH_CONTRACT_CREATION_INPUT_PROOF,
  FRESH_DEPLOYMENT_TRANSACTION_SPEC,
  rawSha256,
} from "./cvm-launch-intent-core.mjs";
import {
  acquireReleaseCeremonyLock,
  inspectReleaseCeremonyLock,
  RELEASE_CEREMONY_LOCK_PROTOCOL,
  RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA,
  releaseReleaseCeremonyLock,
} from "./release-ceremony-lock.mjs";
import {
  canonicalReleaseCeremonyLedgerJsonText,
  commitReleaseCeremonyLedgerRevision,
  CURRENT_RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS,
  finalizeReleaseCeremonyLedger,
  initializeReleaseCeremonyLedger,
  normalizeReleaseCeremonyLedgerFinalizationReceipt,
  normalizeReleaseCeremonyLedgerInitializationReceipt,
  normalizeReleaseCeremonyLedgerPendingJournal,
  normalizeReleaseCeremonyLedgerRecoveryReceipt,
  normalizeReleaseCeremonyLedgerRevisionReceipt,
  projectCurrentReleaseCeremonyLedgerGlobalReconciliation,
  recoverPendingRevision,
  RELEASE_CEREMONY_LEDGER_ACTIVE_MODE,
  RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
  RELEASE_CEREMONY_LEDGER_FROZEN_MODE,
  RELEASE_CEREMONY_LEDGER_GENESIS_DOMAIN,
  RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS,
  RELEASE_CEREMONY_LEDGER_PROTOCOL,
  releaseCeremonyLedgerGenesisChainSha256,
  releaseCeremonyLedgerGlobalReconciliationSha256,
  releaseCeremonyLedgerRawSha256,
  replayReleaseCeremonyLedgerRevisionChain,
} from "./release-ceremony-ledger.mjs";

const ROOT = fs.realpathSync.native(path.resolve(import.meta.dirname, ".."));
const RELEASE_SHA = "1".repeat(40);
const INTENT_SHA256 = `sha256:${"2".repeat(64)}`;
const REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 = `sha256:${"3".repeat(64)}`;
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256 =
  `sha256:${"4".repeat(64)}`;
const OPERATOR_ADDRESS = `0x${"a1".repeat(20)}`;
const INITIALIZATION_TOKEN = "1".repeat(64);
const ONCHAIN_RECONCILIATION_SHA256 = `sha256:${"a".repeat(64)}`;

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

function contractLedgerFixture() {
  const bytes32 = (value) => `0x${value.toString(16).padStart(64, "0")}`;
  const sha256 = (value) => `sha256:${value.toString(16).padStart(64, "0")}`;
  const contracts = Object.fromEntries(
    CONTRACT_DEPLOYMENT_RECEIPT_CONTRACTS.map(({ ledger_key }, index) => {
      const address = `0x${String(index + 1).repeat(40)}`;
      return [ledger_key, {
        sourceCommit: RELEASE_SHA,
        address,
        runtimeCodeHash: `0x${String(index + 1).repeat(64)}`,
        deploymentTx: bytes32(100 + index),
        deploymentBlock: 1_000 + index,
        deploymentBlockHash: bytes32(200 + index),
        deploymentReceiptStatus: "success",
        deploymentTxFrom: OPERATOR_ADDRESS,
        deploymentReceiptContractAddress: address,
      }];
    }),
  );
  Object.assign(contracts.challengeRegistry, {
    status: "deployed_empty_active_registry",
    owner: OPERATOR_ADDRESS,
    registryPaused: false,
    challengeCount: 0,
    nextChallengeId: 1,
  });
  Object.assign(contracts.executionPolicyAnchor, {
    deploymentIntentSha256Bytes32: `0x${INTENT_SHA256.slice("sha256:".length)}`,
    reviewerAuthorityGenesisAcceptanceSha256Bytes32:
      `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
    authorityCommitmentReadProof: FRESH_CONTRACT_AUTHORITY_COMMITMENT_READ_PROOF,
    authorityCommitmentReadBlock: contracts.executionPolicyAnchor.deploymentBlock,
    authorityCommitmentReadBlockHash:
      contracts.executionPolicyAnchor.deploymentBlockHash,
  });
  const broadcastTransactions = FRESH_DEPLOYMENT_TRANSACTION_SPEC.map(
    (spec, sequence) => {
      const contract = contracts[spec.contract_key];
      const create = spec.transaction_type === "CREATE";
      const transactionInputSha256 = sha256(300 + sequence);
      if (create) contract.creationInputSha256 = transactionInputSha256;
      return {
        sequence,
        contractKey: spec.contract_key,
        contractName: spec.name,
        transactionType: spec.transaction_type,
        functionSignature: spec.function_signature,
        transactionHash: create ? contract.deploymentTx : bytes32(400 + sequence),
        transactionFrom: OPERATOR_ADDRESS,
        transactionTo: create ? null : contract.address,
        transactionNonce: 500 + sequence,
        transactionInputSha256,
        receiptStatus: "success",
        receiptContractAddress: create ? contract.address : null,
        blockNumber: create ? contract.deploymentBlock : 2_000 + sequence,
        blockHash: create ? contract.deploymentBlockHash : bytes32(600 + sequence),
      };
    },
  );
  const normalizedTransactions = broadcastTransactions.map((entry) => ({
    sequence: entry.sequence,
    contract_key: entry.contractKey,
    contract_name: entry.contractName,
    transaction_type: entry.transactionType,
    function_signature: entry.functionSignature,
    transaction_hash: entry.transactionHash,
    transaction_from: entry.transactionFrom,
    transaction_to: entry.transactionTo,
    transaction_nonce: entry.transactionNonce,
    transaction_input_sha256: entry.transactionInputSha256,
    receipt_status: entry.receiptStatus,
    receipt_contract_address: entry.receiptContractAddress,
    block_number: entry.blockNumber,
    block_hash: entry.blockHash,
  }));
  const broadcastTransactionsSha256 = rawSha256(Buffer.from(
    JSON.stringify(sortedObject(normalizedTransactions)),
    "utf8",
  ));
  return {
    schemaVersion: 2,
    status: "fresh_contract_suite_deployed_pending_cvm_binding",
    network: {
      chainId: 84_532,
      explorerBaseUrl: "https://sepolia.basescan.org",
      name: "Base Sepolia",
      rpcEnv: "BASE_SEPOLIA_RPC_URL",
    },
    currentOperatorDeployer: {
      address: OPERATOR_ADDRESS,
      keystoreAccount: "dev",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        sourceCommit: RELEASE_SHA,
        deploymentIntentSha256: INTENT_SHA256,
        reviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
        tinkerAccountBindingCeremonyReceiptSha256:
          TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
        keystoreAccount: "dev",
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        exactCreationInputProof: FRESH_CONTRACT_CREATION_INPUT_PROOF,
        broadcastTransactionProof: FRESH_CONTRACT_BROADCAST_PROOF,
        broadcastTransactionCount: FRESH_DEPLOYMENT_TRANSACTION_SPEC.length,
        broadcastTransactionsSha256,
        broadcastTransactions,
      },
    },
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: RELEASE_SHA,
      deploymentIntentSha256: INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      tinkerAccountBindingCeremonyReceiptSha256:
        TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
      broadcastTransactionsSha256,
    }],
    contracts,
  };
}

function mkdirPrivate(directory) {
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
}

function fixture(t) {
  const base = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-release-ledger-")),
  );
  const lockRoot = path.join(base, "locks");
  const ledgerRoot = path.join(base, "ledger");
  const evidenceRoot = path.join(base, "evidence");
  for (const directory of [lockRoot, ledgerRoot, evidenceRoot]) mkdirPrivate(directory);
  const sourceManifestPath = path.join(base, "deployment-manifest.json");
  const ledgerPath = path.join(ledgerRoot, "release-ledger.json");
  const sourceText = canonicalReleaseCeremonyLedgerJsonText(contractLedgerFixture());
  fs.writeFileSync(sourceManifestPath, sourceText, { mode: 0o444, flag: "wx" });
  fs.chmodSync(sourceManifestPath, 0o444);
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  return {
    base,
    lockRoot,
    ledgerRoot,
    evidenceRoot,
    sourceManifestPath,
    ledgerPath,
    repositoryRoot: ROOT,
    releaseSha: RELEASE_SHA,
    deploymentIntentSha256: INTENT_SHA256,
    reviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    tinkerAccountBindingCeremonyReceiptSha256:
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
  };
}

function acquire(f, writerId, ownerToken) {
  acquireReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: f.releaseSha,
    writerId,
    ownerPid: 12_345,
    token: ownerToken,
    now: new Date("2026-07-21T12:00:00.000Z"),
  });
  return { ...f, writerId, ownerToken };
}

function release(f, writerId, ownerToken) {
  releaseReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: f.releaseSha,
    writerId,
    ownerToken,
  });
}

function initialize(f) {
  const options = acquire(f, "ceremony_ledger_initialization", INITIALIZATION_TOKEN);
  try {
    return initializeReleaseCeremonyLedger({
      ...options,
      now: new Date("2026-07-21T12:01:00.000Z"),
    });
  } finally {
    release(f, "ceremony_ledger_initialization", INITIALIZATION_TOKEN);
  }
}

function rewriteSourceManifest(f, mutate) {
  const value = JSON.parse(fs.readFileSync(f.sourceManifestPath, "utf8"));
  mutate(value);
  fs.chmodSync(f.sourceManifestPath, 0o600);
  fs.writeFileSync(
    f.sourceManifestPath,
    canonicalReleaseCeremonyLedgerJsonText(value),
    { mode: 0o444 },
  );
  fs.chmodSync(f.sourceManifestPath, 0o444);
}

function assertInitializationRejected(f, expected) {
  const token = "6".repeat(64);
  const options = acquire(f, "ceremony_ledger_initialization", token);
  try {
    assert.throws(
      () => initializeReleaseCeremonyLedger(options),
      expected,
    );
  } finally {
    release(f, "ceremony_ledger_initialization", token);
  }
}

function candidateText(f, label = "arena-cvm-bound") {
  const candidate = JSON.parse(fs.readFileSync(f.ledgerPath, "utf8"));
  candidate.ceremonyState = {
    label,
    evidenceSha256: `sha256:${label.length.toString(16).padStart(64, "0")}`,
  };
  return canonicalReleaseCeremonyLedgerJsonText(candidate);
}

function currentReplay(f) {
  return replayReleaseCeremonyLedgerRevisionChain(f);
}

function inspectOwner(f) {
  return inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: f.releaseSha,
  }).observed_lock_owner_sha256;
}

function signedRecoveryReceipt(f, observedOwnerSha256, discriminator) {
  const signedPayloadSha256 = `sha256:${discriminator.repeat(64)}`;
  const directory = path.join(
    f.lockRoot,
    `dnai-release-ceremony-${f.releaseSha}.recovery-receipts`,
  );
  if (!fs.existsSync(directory)) mkdirPrivate(directory);
  const globalReconciliation =
    projectCurrentReleaseCeremonyLedgerGlobalReconciliation({
      ...f,
      observedStaleLockOwnerSha256: observedOwnerSha256,
      onchainSignerNonceFinalizedStateReconciliationSha256:
        ONCHAIN_RECONCILIATION_SHA256,
    });
  const receipt = {
    schema: RELEASE_CEREMONY_LOCK_RECOVERY_RECEIPT_SCHEMA,
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    status: "signed_recovery_verified_before_stale_lock_removal",
    release_sha: f.releaseSha,
    observed_lock_owner_sha256: observedOwnerSha256,
    chain_and_ledger_reconciliation_sha256:
      releaseCeremonyLedgerGlobalReconciliationSha256(globalReconciliation),
    reviewer_authority_sha256: `sha256:${"b".repeat(64)}`,
    reviewer_root_hash: "c".repeat(64),
    signed_payload_sha256: signedPayloadSha256,
    recovery_authority_sha256: `sha256:${"d".repeat(64)}`,
    approved_at: "2026-07-21T12:30:00.000Z",
    expires_at: "2026-07-21T13:30:00.000Z",
    reviewers: [
      {
        address: `0x${"11".repeat(20)}`,
        controller_id: "reviewer-alpha",
        signature_sha256: `sha256:${"e".repeat(64)}`,
      },
      {
        address: `0x${"22".repeat(20)}`,
        controller_id: "reviewer-bravo",
        signature_sha256: `sha256:${"f".repeat(64)}`,
      },
    ],
  };
  const text = canonicalReleaseCeremonyLedgerJsonText(receipt);
  const receiptPath = path.join(directory, `${signedPayloadSha256.slice(7)}.json`);
  fs.writeFileSync(receiptPath, text, { mode: 0o444, flag: "wx" });
  fs.chmodSync(receiptPath, 0o444);
  return {
    lockRecoveryReceiptPath: receiptPath,
    lockRecoveryReceiptSha256: releaseCeremonyLedgerRawSha256(Buffer.from(text, "utf8")),
    onchainSignerNonceFinalizedStateReconciliationSha256:
      ONCHAIN_RECONCILIATION_SHA256,
  };
}

test("initialization copies the immutable fresh manifest byte-for-byte exactly once", (t) => {
  const f = fixture(t);
  const sourceBytes = fs.readFileSync(f.sourceManifestPath);
  const initialized = initialize(f);
  assert.equal(initialized.protocol, RELEASE_CEREMONY_LEDGER_PROTOCOL);
  assert.equal(initialized.revision_count, 0);
  assert.equal(initialized.finalized, false);
  assert.deepEqual(fs.readFileSync(f.ledgerPath), sourceBytes);
  assert.equal(fs.statSync(f.ledgerPath).mode & 0o777, RELEASE_CEREMONY_LEDGER_ACTIVE_MODE);
  const initializationPath = path.join(f.evidenceRoot, "initialization.json");
  assert.equal(
    fs.statSync(initializationPath).mode & 0o777,
    RELEASE_CEREMONY_LEDGER_EVIDENCE_MODE,
  );
  const receipt = normalizeReleaseCeremonyLedgerInitializationReceipt(
    JSON.parse(fs.readFileSync(initializationPath, "utf8")),
  );
  assert.equal(receipt.deployment_manifest.path, f.sourceManifestPath);
  assert.equal(receipt.ledger.path, f.ledgerPath);
  assert.equal(receipt.deployment_manifest.sha256, receipt.ledger.sha256);
  assert.equal(receipt.deployment_manifest.bytes, receipt.ledger.bytes);
  assert.equal(receipt.deployment_manifest.mode, "0444");
  assert.equal(receipt.ledger.mode, "0600");
  assert.equal(receipt.lock.protocol, RELEASE_CEREMONY_LOCK_PROTOCOL);
  assert.equal(
    initialized.revision_chain_sha256,
    releaseCeremonyLedgerGenesisChainSha256(initialized.initialization_receipt_sha256),
  );
  assert.equal(RELEASE_CEREMONY_LEDGER_GENESIS_DOMAIN.endsWith("\0"), true);

  const secondToken = "2".repeat(64);
  const options = acquire(f, "ceremony_ledger_initialization", secondToken);
  try {
    assert.throws(
      () => initializeReleaseCeremonyLedger(options),
      /target must be absent|evidence root must be empty/,
    );
  } finally {
    release(f, "ceremony_ledger_initialization", secondToken);
  }
});

test("initialization requires the independent ceremony pin and both exact manifest copies", (t) => {
  const missingExternalPin = fixture(t);
  const token = "5".repeat(64);
  const options = acquire(
    missingExternalPin,
    "ceremony_ledger_initialization",
    token,
  );
  delete options.tinkerAccountBindingCeremonyReceiptSha256;
  try {
    assert.throws(
      () => initializeReleaseCeremonyLedger(options),
      /independently verified Tinker account-binding ceremony receipt digest/,
    );
  } finally {
    release(missingExternalPin, "ceremony_ledger_initialization", token);
  }

  for (const [label, mutate, expected] of [
    [
      "missing current-suite pin",
      (value) => {
        delete value.freshDeployment.contractSuite
          .tinkerAccountBindingCeremonyReceiptSha256;
      },
      /fresh fail-closed suite/,
    ],
    [
      "substituted current-suite pin",
      (value) => {
        value.freshDeployment.contractSuite
          .tinkerAccountBindingCeremonyReceiptSha256 =
            `sha256:${"e".repeat(64)}`;
      },
      /fresh fail-closed suite/,
    ],
    [
      "missing history pin",
      (value) => {
        delete value.deploymentHistory[0]
          .tinkerAccountBindingCeremonyReceiptSha256;
      },
      /account-binding ceremony receipt/,
    ],
    [
      "substituted history pin",
      (value) => {
        value.deploymentHistory[0]
          .tinkerAccountBindingCeremonyReceiptSha256 =
            `sha256:${"e".repeat(64)}`;
      },
      /account-binding ceremony receipt/,
    ],
  ]) {
    const f = fixture(t);
    rewriteSourceManifest(f, mutate);
    assertInitializationRejected(f, expected, label);
  }

  const substitutedExternalPin = fixture(t);
  substitutedExternalPin.tinkerAccountBindingCeremonyReceiptSha256 =
    `sha256:${"e".repeat(64)}`;
  assertInitializationRejected(
    substitutedExternalPin,
    /fresh fail-closed suite/,
  );
});

test("CLI initializes once and commits every helper candidate to the one external ledger", (t) => {
  const f = fixture(t);
  const cli = path.join(ROOT, "scripts", "release-ceremony-ledger-cli.mjs");
  const common = [
    "--repository-root", f.repositoryRoot,
    "--source-manifest", f.sourceManifestPath,
    "--ledger", f.ledgerPath,
    "--evidence-root", f.evidenceRoot,
    "--lock-root", f.lockRoot,
    "--release-sha", f.releaseSha,
    "--deployment-intent-sha256", f.deploymentIntentSha256,
    "--reviewer-genesis-acceptance-sha256",
    f.reviewerAuthorityGenesisAcceptanceSha256,
    "--tinker-account-binding-ceremony-receipt-sha256",
    f.tinkerAccountBindingCeremonyReceiptSha256,
  ];
  const sourceBefore = fs.readFileSync(f.sourceManifestPath);
  const missingCeremonyPin = common.slice(0, -2);
  const missingResult = spawnSync(process.execPath, [
    cli, "replay", ...missingCeremonyPin,
  ], { encoding: "utf8" });
  assert.notEqual(missingResult.status, 0);
  assert.match(
    missingResult.stderr,
    /--tinker-account-binding-ceremony-receipt-sha256 is required/,
  );
  const initializeToken = "7".repeat(64);
  acquire(f, "ceremony_ledger_initialization", initializeToken);
  try {
    const result = spawnSync(process.execPath, [
      cli, "initialize", ...common,
      "--writer-id", "ceremony_ledger_initialization",
      "--owner-token", initializeToken,
    ], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).ledger_mode, "0600");
  } finally {
    release(f, "ceremony_ledger_initialization", initializeToken);
  }

  const secondToken = "8".repeat(64);
  acquire(f, "ceremony_ledger_initialization", secondToken);
  try {
    const second = spawnSync(process.execPath, [
      cli, "initialize", ...common,
      "--writer-id", "ceremony_ledger_initialization",
      "--owner-token", secondToken,
    ], { encoding: "utf8" });
    assert.notEqual(second.status, 0);
    assert.match(second.stderr, /target must be absent|evidence root must be empty/);
  } finally {
    release(f, "ceremony_ledger_initialization", secondToken);
  }

  const candidatePath = path.join(f.ledgerRoot, "helper-candidate.json");
  fs.writeFileSync(candidatePath, candidateText(f, "diligence-release"), {
    flag: "wx",
    mode: 0o600,
  });
  fs.chmodSync(candidatePath, 0o600);
  const writerToken = "9".repeat(64);
  acquire(f, "diligence_release", writerToken);
  try {
    const committed = spawnSync(process.execPath, [
      cli, "commit", ...common,
      "--writer-id", "diligence_release",
      "--owner-token", writerToken,
      "--candidate", candidatePath,
    ], { encoding: "utf8" });
    assert.equal(committed.status, 0, committed.stderr);
    assert.equal(JSON.parse(committed.stdout).revision_count, 1);
  } finally {
    release(f, "diligence_release", writerToken);
  }

  assert.deepEqual(fs.readFileSync(f.sourceManifestPath), sourceBefore);
  assert.equal(fs.statSync(f.sourceManifestPath).mode & 0o777, 0o444);
  assert.equal(fs.statSync(f.ledgerPath).mode & 0o777, 0o600);
  assert.equal(currentReplay(f).revision_count, 1);
});

test("CAS commits canonical candidates and replay rejects stale or malformed writers", (t) => {
  const f = fixture(t);
  const initial = initialize(f);
  const ownerToken = "3".repeat(64);
  const options = acquire(f, "challenge_registry_release", ownerToken);
  try {
    const candidate = candidateText(f);
    const committed = commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 0,
      expectedLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidate,
      now: new Date("2026-07-21T12:10:00.000Z"),
    });
    assert.equal(committed.revision_count, 1);
    assert.equal(committed.current_ledger_sha256, releaseCeremonyLedgerRawSha256(candidate));
    assert.equal(fs.readFileSync(f.ledgerPath, "utf8"), candidate);
    const receiptPath = path.join(f.evidenceRoot, "revisions", "000000000001.json");
    assert.equal(fs.statSync(receiptPath).mode & 0o777, 0o444);
    const receipt = normalizeReleaseCeremonyLedgerRevisionReceipt(
      JSON.parse(fs.readFileSync(receiptPath, "utf8")),
    );
    assert.equal(receipt.revision, 1);
    assert.equal(receipt.writer_id, "challenge_registry_release");
    assert.equal(receipt.ledger.previous_sha256, initial.current_ledger_sha256);
    assert.equal(receipt.ledger.next_sha256, committed.current_ledger_sha256);
    assert.equal(receipt.chain_sha256, committed.revision_chain_sha256);
    assert.throws(() => commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 0,
      expectedLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidateText(f, "stale-update"),
    }), /CAS mismatch/);
    assert.throws(() => commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 1,
      expectedLedgerSha256: committed.current_ledger_sha256,
      candidateLedgerText: JSON.stringify(JSON.parse(candidateText(f, "not-canonical"))),
    }), /candidate ledger must be recursively sorted/);
  } finally {
    release(f, "challenge_registry_release", ownerToken);
  }
  const replay = currentReplay(f);
  assert.equal(replay.revision_count, 1);
  assert.equal(replay.finalized, false);
  assert.equal(fs.readdirSync(path.join(f.evidenceRoot, ".staging")).length, 0);
  assert.equal(fs.existsSync(path.join(f.evidenceRoot, "pending.json")), false);
});

test("legacy writer projection stays frozen while royalty release can commit and replay", (t) => {
  assert.deepEqual(RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS, [
    "challenge_registry_release",
    "compute_release",
    "diligence_release",
    "email_oracle_release",
    "execution_policy_anchor_release",
    "tinker_release",
  ]);
  assert.deepEqual(CURRENT_RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS, [
    ...RELEASE_CEREMONY_LEDGER_MUTATION_WRITERS,
    "royalty_release",
  ]);

  const f = fixture(t);
  const initial = initialize(f);
  const ownerToken = "a2".repeat(32);
  const options = acquire(f, "royalty_release", ownerToken);
  try {
    const committed = commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 0,
      expectedLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidateText(f, "royalty-phase-one-finalized"),
      now: new Date("2026-07-21T12:11:00.000Z"),
    });
    assert.equal(committed.revision_count, 1);
    const replayed = currentReplay(f);
    assert.equal(replayed.revision_count, 1);
    const receipt = normalizeReleaseCeremonyLedgerRevisionReceipt(
      JSON.parse(fs.readFileSync(
        path.join(f.evidenceRoot, "revisions", "000000000001.json"),
        "utf8",
      )),
    );
    assert.equal(receipt.writer_id, "royalty_release");
  } finally {
    release(f, "royalty_release", ownerToken);
  }
});

for (const [faultPoint, expectedAction] of [
  ["after-pending", "aborted_before_ledger_replace"],
  ["after-ledger-replace", "completed_missing_revision_receipt"],
  ["after-revision-receipt", "cleared_after_operation_was_complete"],
]) {
  test(`pending revision ${faultPoint} is fail-closed until signed explicit recovery`, (t) => {
    const f = fixture(t);
    const initial = initialize(f);
    const writerToken = faultPoint === "after-pending"
      ? "4".repeat(64)
      : faultPoint === "after-ledger-replace"
        ? "5".repeat(64)
        : "6".repeat(64);
    const options = acquire(f, "challenge_registry_release", writerToken);
    const originalOwnerSha256 = inspectOwner(f);
    assert.throws(() => commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 0,
      expectedLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidateText(f, faultPoint),
      faultPoint,
      now: new Date("2026-07-21T12:15:00.000Z"),
    }), new RegExp(`injected crash at ${faultPoint}`));
    const pendingPath = path.join(f.evidenceRoot, "pending.json");
    assert.equal(fs.existsSync(pendingPath), true);
    assert.equal(fs.statSync(pendingPath).mode & 0o777, 0o600);
    normalizeReleaseCeremonyLedgerPendingJournal(
      JSON.parse(fs.readFileSync(pendingPath, "utf8")),
    );
    assert.throws(() => commitReleaseCeremonyLedgerRevision({
      ...options,
      expectedRevision: 0,
      expectedLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidateText(f, "automatic-retry-forbidden"),
    }), /pending journal exists.*explicit signed recovery/);
    release(f, "challenge_registry_release", writerToken);

    const signed = signedRecoveryReceipt(
      f,
      originalOwnerSha256,
      faultPoint === "after-pending" ? "7"
        : faultPoint === "after-ledger-replace" ? "8" : "9",
    );
    const recoveryToken = faultPoint === "after-pending"
      ? "a".repeat(64)
      : faultPoint === "after-ledger-replace"
        ? "b".repeat(64)
        : "c".repeat(64);
    const recoveryOptions = acquire(f, "ceremony_ledger_recovery", recoveryToken);
    try {
      assert.throws(() => recoverPendingRevision({
        ...recoveryOptions,
        ...signed,
        lockRecoveryReceiptSha256: `sha256:${"0".repeat(64)}`,
      }), /does not bind this pending operation|digest/);
      assert.throws(() => recoverPendingRevision({
        ...recoveryOptions,
        ...signed,
        onchainSignerNonceFinalizedStateReconciliationSha256:
          `sha256:${"1".repeat(64)}`,
      }), /global reconciliation digest mismatch/);
      assert.equal(fs.existsSync(pendingPath), true);
      const recovered = recoverPendingRevision({
        ...recoveryOptions,
        ...signed,
        now: new Date("2026-07-21T12:40:00.000Z"),
      });
      assert.equal(recovered.recovery_action, expectedAction);
      assert.equal(fs.existsSync(pendingPath), false);
      assert.equal(fs.statSync(recovered.recovery_receipt_path).mode & 0o777, 0o444);
      const recoveryReceipt = normalizeReleaseCeremonyLedgerRecoveryReceipt(
        JSON.parse(fs.readFileSync(recovered.recovery_receipt_path, "utf8")),
      );
      assert.equal(
        recoveryReceipt.global_reconciliation
          .onchain_signer_nonce_finalized_state_reconciliation_sha256,
        ONCHAIN_RECONCILIATION_SHA256,
      );
      assert.equal(
        recoveryReceipt.global_reconciliation.pending_recovery_action,
        expectedAction,
      );
      assert.equal(
        recoveryReceipt.global_reconciliation.deployment_manifest_sha256,
        releaseCeremonyLedgerRawSha256(fs.readFileSync(f.sourceManifestPath)),
      );
      if (faultPoint === "after-pending") {
        assert.equal(recovered.revision_count, 0);
        assert.equal(recovered.current_ledger_sha256, initial.current_ledger_sha256);
      } else {
        assert.equal(recovered.revision_count, 1);
        assert.equal(
          fs.existsSync(path.join(f.evidenceRoot, "revisions", "000000000001.json")),
          true,
        );
      }
      assert.equal(fs.readdirSync(path.join(f.evidenceRoot, ".staging")).length, 0);
    } finally {
      release(f, "ceremony_ledger_recovery", recoveryToken);
    }
  });
}

test("finalization replays the chain, durably rewrites the inode, and freezes all updates", (t) => {
  const f = fixture(t);
  const initial = initialize(f);
  const mutationToken = "d".repeat(64);
  const mutationOptions = acquire(f, "compute_release", mutationToken);
  let committed;
  try {
    committed = commitReleaseCeremonyLedgerRevision({
      ...mutationOptions,
      expectedRevision: 0,
      expectedPreviousLedgerSha256: initial.current_ledger_sha256,
      candidateLedgerText: candidateText(f, "compute-cvm-bound"),
      now: new Date("2026-07-21T12:20:00.000Z"),
    });
  } finally {
    release(f, "compute_release", mutationToken);
  }
  const before = fs.statSync(f.ledgerPath);
  const beforeBytes = fs.readFileSync(f.ledgerPath);
  const finalizeToken = "e".repeat(64);
  const finalizeOptions = acquire(f, "ceremony_ledger_finalization", finalizeToken);
  try {
    const finalized = finalizeReleaseCeremonyLedger({
      ...finalizeOptions,
      now: new Date("2026-07-21T12:25:00.000Z"),
    });
    const after = fs.statSync(f.ledgerPath);
    assert.equal(finalized.finalized, true);
    assert.equal(finalized.revision_count, 1);
    assert.equal(finalized.revision_chain_sha256, committed.revision_chain_sha256);
    assert.equal(finalized.ledger_mode, "0444");
    assert.equal(after.mode & 0o777, RELEASE_CEREMONY_LEDGER_FROZEN_MODE);
    assert.notEqual(after.ino, before.ino);
    assert.deepEqual(fs.readFileSync(f.ledgerPath), beforeBytes);
    const finalPath = path.join(f.evidenceRoot, "finalization.json");
    assert.equal(fs.statSync(finalPath).mode & 0o777, 0o444);
    const finalReceipt = normalizeReleaseCeremonyLedgerFinalizationReceipt(
      JSON.parse(fs.readFileSync(finalPath, "utf8")),
    );
    assert.equal(finalReceipt.deployment_manifest.path, f.sourceManifestPath);
    assert.equal(finalReceipt.initialization_receipt.path, path.join(f.evidenceRoot, "initialization.json"));
    assert.equal(finalReceipt.revision_chain.chain_sha256, committed.revision_chain_sha256);
    assert.equal(finalReceipt.ledger.sha256, committed.current_ledger_sha256);
    assert.equal(finalReceipt.ledger.mode, "0444");
    assert.throws(
      () => finalizeReleaseCeremonyLedger(finalizeOptions),
      /already finalized/,
    );
  } finally {
    release(f, "ceremony_ledger_finalization", finalizeToken);
  }

  const refusedToken = "f".repeat(64);
  const refused = acquire(f, "challenge_registry_release", refusedToken);
  try {
    assert.throws(() => commitReleaseCeremonyLedgerRevision({
      ...refused,
      expectedRevision: 1,
      expectedLedgerSha256: committed.current_ledger_sha256,
      candidateLedgerText: canonicalReleaseCeremonyLedgerJsonText({
        ...JSON.parse(beforeBytes.toString("utf8")),
        forbiddenAfterFreeze: true,
      }),
    }), /finalized release ledger refuses all revisions/);
  } finally {
    release(f, "challenge_registry_release", refusedToken);
  }
});

test("crashed finalization is journaled and can only be completed by signed recovery", (t) => {
  const f = fixture(t);
  initialize(f);
  const finalizeToken = "a1".repeat(32);
  const finalizeOptions = acquire(f, "ceremony_ledger_finalization", finalizeToken);
  const originalOwnerSha256 = inspectOwner(f);
  assert.throws(() => finalizeReleaseCeremonyLedger({
    ...finalizeOptions,
    faultPoint: "after-ledger-replace",
    now: new Date("2026-07-21T12:25:00.000Z"),
  }), /injected crash at after-ledger-replace/);
  assert.equal(fs.statSync(f.ledgerPath).mode & 0o777, 0o444);
  assert.equal(fs.existsSync(path.join(f.evidenceRoot, "pending.json")), true);
  assert.equal(fs.existsSync(path.join(f.evidenceRoot, "finalization.json")), false);
  assert.throws(() => currentReplay(f), /pending journal exists.*explicit signed recovery/);
  release(f, "ceremony_ledger_finalization", finalizeToken);

  const signed = signedRecoveryReceipt(f, originalOwnerSha256, "1");
  const recoveryToken = "a2".repeat(32);
  const recoveryOptions = acquire(f, "ceremony_ledger_recovery", recoveryToken);
  try {
    const recovered = recoverPendingRevision({
      ...recoveryOptions,
      ...signed,
      now: new Date("2026-07-21T12:45:00.000Z"),
    });
    assert.equal(recovered.recovery_action, "completed_missing_finalization_receipt");
    assert.equal(recovered.finalized, true);
    assert.equal(recovered.ledger_mode, "0444");
    assert.equal(fs.existsSync(path.join(f.evidenceRoot, "pending.json")), false);
  } finally {
    release(f, "ceremony_ledger_recovery", recoveryToken);
  }
});

test("a recovery crash extends the signed stale-owner chain instead of auto-clearing evidence", (t) => {
  const f = fixture(t);
  const initial = initialize(f);
  const mutationToken = "c1".repeat(32);
  const mutation = acquire(f, "challenge_registry_release", mutationToken);
  const mutationOwnerSha256 = inspectOwner(f);
  assert.throws(() => commitReleaseCeremonyLedgerRevision({
    ...mutation,
    expectedRevision: 0,
    expectedLedgerSha256: initial.current_ledger_sha256,
    candidateLedgerText: candidateText(f, "recovery-itself-crashes"),
    faultPoint: "after-ledger-replace",
  }), /injected crash at after-ledger-replace/);
  release(f, "challenge_registry_release", mutationToken);

  const firstSigned = signedRecoveryReceipt(f, mutationOwnerSha256, "3");
  const firstRecoveryToken = "c2".repeat(32);
  const firstRecovery = acquire(f, "ceremony_ledger_recovery", firstRecoveryToken);
  const firstRecoveryOwnerSha256 = inspectOwner(f);
  assert.throws(() => recoverPendingRevision({
    ...firstRecovery,
    ...firstSigned,
    faultPoint: "before-recovery-receipt-publish",
  }), /injected crash at before-recovery-receipt-publish/);
  assert.equal(fs.existsSync(path.join(f.evidenceRoot, "pending.json")), true);
  assert.equal(
    fs.readdirSync(path.join(f.evidenceRoot, ".staging"))
      .some((name) => name.startsWith("recovery-")),
    true,
  );
  assert.equal(fs.readdirSync(path.join(f.evidenceRoot, "recoveries")).length, 0);
  release(f, "ceremony_ledger_recovery", firstRecoveryToken);

  const secondSigned = signedRecoveryReceipt(f, firstRecoveryOwnerSha256, "4");
  const secondRecoveryToken = "c3".repeat(32);
  const secondRecovery = acquire(f, "ceremony_ledger_recovery", secondRecoveryToken);
  try {
    const recovered = recoverPendingRevision({
      ...secondRecovery,
      ...secondSigned,
      now: new Date("2026-07-21T12:55:00.000Z"),
    });
    assert.equal(recovered.recovery_action, "cleared_after_operation_was_complete");
    assert.equal(recovered.revision_count, 1);
    assert.equal(fs.existsSync(path.join(f.evidenceRoot, "pending.json")), false);
    assert.deepEqual(fs.readdirSync(path.join(f.evidenceRoot, ".staging")), []);
    assert.equal(fs.readdirSync(path.join(f.evidenceRoot, "recoveries")).length, 2);
  } finally {
    release(f, "ceremony_ledger_recovery", secondRecoveryToken);
  }
});

test("source, ledger, evidence, and receipt filesystem boundaries fail closed", (t) => {
  const wrongMode = fixture(t);
  fs.chmodSync(wrongMode.sourceManifestPath, 0o644);
  const wrongModeToken = "b1".repeat(32);
  const wrongModeOptions = acquire(
    wrongMode,
    "ceremony_ledger_initialization",
    wrongModeToken,
  );
  try {
    assert.throws(
      () => initializeReleaseCeremonyLedger(wrongModeOptions),
      /immutable deployment manifest mode must be 0444/,
    );
  } finally {
    release(wrongMode, "ceremony_ledger_initialization", wrongModeToken);
  }

  const linked = fixture(t);
  const linkPath = path.join(linked.base, "linked-manifest.json");
  fs.symlinkSync(linked.sourceManifestPath, linkPath);
  const linkedToken = "b2".repeat(32);
  const linkedOptions = acquire(linked, "ceremony_ledger_initialization", linkedToken);
  try {
    assert.throws(() => initializeReleaseCeremonyLedger({
      ...linkedOptions,
      sourceManifestPath: linkPath,
    }), /symlink|canonical real path/);
  } finally {
    release(linked, "ceremony_ledger_initialization", linkedToken);
  }

  const noncanonical = fixture(t);
  const noncanonicalToken = "b3".repeat(32);
  const noncanonicalOptions = acquire(
    noncanonical,
    "ceremony_ledger_initialization",
    noncanonicalToken,
  );
  try {
    assert.throws(() => initializeReleaseCeremonyLedger({
      ...noncanonicalOptions,
      ledgerPath: `${noncanonical.ledgerRoot}/../ledger/release-ledger.json`,
    }), /lexically canonical absolute path/);
  } finally {
    release(noncanonical, "ceremony_ledger_initialization", noncanonicalToken);
  }

  const publicEvidence = fixture(t);
  fs.chmodSync(publicEvidence.evidenceRoot, 0o755);
  const publicToken = "b4".repeat(32);
  const publicOptions = acquire(
    publicEvidence,
    "ceremony_ledger_initialization",
    publicToken,
  );
  try {
    assert.throws(
      () => initializeReleaseCeremonyLedger(publicOptions),
      /evidence root mode must be 0700/,
    );
  } finally {
    release(publicEvidence, "ceremony_ledger_initialization", publicToken);
  }

  const postInit = fixture(t);
  initialize(postInit);
  fs.chmodSync(path.join(postInit.evidenceRoot, "initialization.json"), 0o644);
  assert.throws(
    () => currentReplay(postInit),
    /initialization receipt mode must be 0444/,
  );
});
