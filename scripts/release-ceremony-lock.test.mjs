import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  acquireReleaseCeremonyLock,
  createReleaseCeremonyLockRecoverySigningPayload,
  inspectReleaseCeremonyLock,
  recoverReleaseCeremonyLock,
  RELEASE_CEREMONY_LOCK_MISSING_OWNER_SHA256,
  RELEASE_CEREMONY_LOCK_PROTOCOL,
  RELEASE_CEREMONY_LOCK_RECOVERY_DECLARATION,
  RELEASE_CEREMONY_LOCK_RECOVERY_SCHEMA,
  RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_SCHEME,
  RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_VERIFIER,
  RELEASE_REVIEWER_GENESIS_ANCHOR_PROOF_SCHEMA,
  RELEASE_CEREMONY_WRITERS,
  releaseCeremonyLockRecoverySigningMessage,
  releaseCeremonyLockRecoverySigningPayloadSha256,
  normalizeReleaseReviewerGenesisAnchorProof,
  releaseReviewerGenesisAnchorProofSha256,
  releaseReleaseCeremonyLock,
} from "./release-ceremony-lock.mjs";
import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const CLI = path.join(ROOT, "scripts", "release-ceremony-lock.mjs");
const RELEASE_SHA = "ab".repeat(20);
const REVIEWER_ALPHA = privateKeyToAccount(`0x${"11".repeat(32)}`);
const REVIEWER_BRAVO = privateKeyToAccount(`0x${"22".repeat(32)}`);
const FORGED_REVIEWER = privateKeyToAccount(`0x${"33".repeat(32)}`);
const GUARDIAN_ALPHA = privateKeyToAccount(`0x${"44".repeat(32)}`);
const GUARDIAN_BRAVO = privateKeyToAccount(`0x${"55".repeat(32)}`);
const SECP256K1_N = BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

function malleateToHighS(signature) {
  const r = signature.slice(2, 66);
  const lowS = BigInt(`0x${signature.slice(66, 130)}`);
  const highS = (SECP256K1_N - lowS).toString(16).padStart(64, "0");
  const v = signature.slice(130, 132) === "1b" ? "1c" : "1b";
  return `0x${r}${highS}${v}`;
}

function sortedObject(value) {
  if (Array.isArray(value)) return value.map(sortedObject);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sortedObject(value), null, 2)}\n`;
}

const REVIEWERS = [
  { address: REVIEWER_ALPHA.address.toLowerCase(), controller_id: "reviewer-alpha" },
  { address: REVIEWER_BRAVO.address.toLowerCase(), controller_id: "reviewer-bravo" },
].sort((left, right) => left.address.localeCompare(right.address));
const REVIEWER_CONTROLLERS = REVIEWERS.map((entry) => ({
  controller_id: entry.controller_id,
  preauthorized_addresses: [entry.address],
})).sort((left, right) => left.controller_id.localeCompare(right.controller_id));
const GUARDIAN_ACCOUNTS = [GUARDIAN_ALPHA, GUARDIAN_BRAVO];
const STATUS_GUARDIANS = GUARDIAN_ACCOUNTS.map((account, index) => ({
  address: account.address.toLowerCase(),
  controller_id: `status-guardian-${index + 1}`,
})).sort((left, right) => left.address.localeCompare(right.address));
const GUARDIAN_HASHES = STATUS_GUARDIANS
  .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
const REVIEWER_GENESIS = {
  schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  release_sha: RELEASE_SHA,
  chain_id: 84_532,
  minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  reviewer_controllers: REVIEWER_CONTROLLERS,
  reviewer_controller_set_sha256: reviewerControllerSetSha256(REVIEWER_CONTROLLERS),
  status_guardians: STATUS_GUARDIANS,
  status_guardian_hashes: GUARDIAN_HASHES,
  status_guardian_root_hash: executionPolicyReviewerRootHash(GUARDIAN_HASHES),
  status_guardian_set_sha256: reviewerSetSha256(STATUS_GUARDIANS),
};
const CURRENT_STATUS_PAYLOAD =
  createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 1,
    not_before: "2026-07-21T12:55:00Z",
    expires_at: "2026-07-21T13:10:00Z",
    previous_status_sha256: `sha256:${"0".repeat(64)}`,
    active_reviewers: REVIEWERS,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, { reviewerGenesis: REVIEWER_GENESIS });
const CURRENT_STATUS_MESSAGE =
  releaseReviewerAuthorityCurrentStatusSigningMessage(
    CURRENT_STATUS_PAYLOAD,
    { reviewerGenesis: REVIEWER_GENESIS },
  );
const GUARDIAN_BY_ADDRESS = new Map(
  GUARDIAN_ACCOUNTS.map((account) => [account.address.toLowerCase(), account]),
);
const REVIEWER_CURRENT_STATUS = {
  ...CURRENT_STATUS_PAYLOAD,
  schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  signing_payload_sha256:
    releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
      CURRENT_STATUS_PAYLOAD,
      { reviewerGenesis: REVIEWER_GENESIS },
    ),
  guardian_signatures: await Promise.all(STATUS_GUARDIANS.map(async (guardian) => ({
    ...guardian,
    signature: (await GUARDIAN_BY_ADDRESS.get(guardian.address).signMessage({
      message: CURRENT_STATUS_MESSAGE,
    })).toLowerCase(),
  }))),
};
const GENESIS_ACCEPTANCE_PAYLOAD =
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    REVIEWER_GENESIS,
    { reviewerCurrentStatus: REVIEWER_CURRENT_STATUS },
  );
const GENESIS_ACCEPTANCE_MESSAGE =
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    GENESIS_ACCEPTANCE_PAYLOAD,
    { reviewerGenesis: REVIEWER_GENESIS },
  );
const ACCOUNTS_BY_ADDRESS = new Map(
  [REVIEWER_ALPHA, REVIEWER_BRAVO]
    .map((account) => [account.address.toLowerCase(), account]),
);
const REVIEWER_GENESIS_ACCEPTANCE = {
  ...GENESIS_ACCEPTANCE_PAYLOAD,
  schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  signing_payload_sha256:
    releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
      GENESIS_ACCEPTANCE_PAYLOAD,
      { reviewerGenesis: REVIEWER_GENESIS },
    ),
  acceptances: await Promise.all(REVIEWERS.map(async (reviewer) => ({
    ...reviewer,
    signature: (await ACCOUNTS_BY_ADDRESS.get(reviewer.address).signMessage({
      message: GENESIS_ACCEPTANCE_MESSAGE,
    })).toLowerCase(),
  }))),
};
const REVIEWER_GENESIS_SHA256 = releaseReviewerAuthorityGenesisSha256(REVIEWER_GENESIS);
const REVIEWER_GENESIS_ACCEPTANCE_SHA256 =
  releaseReviewerAuthorityGenesisAcceptanceSha256(
    REVIEWER_GENESIS_ACCEPTANCE,
    { reviewerGenesis: REVIEWER_GENESIS },
  );

function anchorProof() {
  const observation = {
    block_number: 12_345,
    block_hash: `0x${"44".repeat(32)}`,
    contract_address: `0x${"55".repeat(20)}`,
    deployment_intent_sha256: `sha256:${"66".repeat(32)}`,
    reviewer_authority_genesis_acceptance_sha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
  };
  return normalizeReleaseReviewerGenesisAnchorProof({
    schema: RELEASE_REVIEWER_GENESIS_ANCHOR_PROOF_SCHEMA,
    truth_status: "dual_rpc_common_finalized_execution_policy_anchor_immutable_getters_observed",
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    fresh_contract_deployment_receipt_sha256: `sha256:${"77".repeat(32)}`,
    execution_policy_anchor_address: observation.contract_address,
    deployment_intent_sha256: observation.deployment_intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
    common_finalized_block_number: observation.block_number,
    common_finalized_block_hash: observation.block_hash,
    primary_rpc: { authority_id: "primary-base-sepolia-rpc", ...observation },
    secondary_rpc: { authority_id: "secondary-independent-rpc", ...observation },
  }, {
    expectedReleaseSha: RELEASE_SHA,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
  });
}

function fixture(t) {
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "dnai-release-lock-")));
  const lockRoot = path.join(base, "locks");
  fs.mkdirSync(lockRoot, { mode: 0o700 });
  fs.chmodSync(lockRoot, 0o700);
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const reviewerAuthorityGenesisPath = path.join(base, "reviewer-genesis.json");
  fs.writeFileSync(
    reviewerAuthorityGenesisPath,
    canonicalReleaseReviewerAuthorityGenesisArtifactText(REVIEWER_GENESIS),
    { mode: 0o600 },
  );
  const reviewerAuthorityGenesisAcceptancePath =
    path.join(base, "reviewer-genesis-acceptance.json");
  fs.writeFileSync(
    reviewerAuthorityGenesisAcceptancePath,
    canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      REVIEWER_GENESIS_ACCEPTANCE,
      { reviewerGenesis: REVIEWER_GENESIS },
    ),
    { mode: 0o600 },
  );
  const proof = anchorProof();
  const reviewerGenesisAnchorProofPath = path.join(base, "reviewer-genesis-anchor-proof.json");
  fs.writeFileSync(reviewerGenesisAnchorProofPath, canonicalText(proof), { mode: 0o600 });
  return {
    anchorProof: proof,
    base,
    lockRoot,
    repositoryRoot: ROOT,
    reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath,
    reviewerGenesisAnchorProofPath,
    reviewerAuthorityGenesisSha256: REVIEWER_GENESIS_SHA256,
    reviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
    reviewerGenesisAnchorProofSha256: releaseReviewerGenesisAnchorProofSha256(
      proof,
      {
        expectedReleaseSha: RELEASE_SHA,
        expectedReviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_GENESIS_ACCEPTANCE_SHA256,
      },
    ),
  };
}

function context(f, writerId, token = "1".repeat(64)) {
  return {
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    writerId,
    ownerPid: 12_345,
    token,
    now: new Date("2026-07-21T12:00:00.000Z"),
  };
}

async function recoveryAuthority(ownerSha256, authorityFixture, {
  payloadOverrides = {},
  envelopeOverrides = {},
  identities = REVIEWERS,
  signers = null,
} = {}) {
  const payload = createReleaseCeremonyLockRecoverySigningPayload({
    schema: RELEASE_CEREMONY_LOCK_RECOVERY_SCHEMA,
    protocol: RELEASE_CEREMONY_LOCK_PROTOCOL,
    truth_status:
      "signed_stale_lock_recovery_after_dual_rpc_signed_reviewer_genesis_acceptance_anchor_not_live_release_authority",
    release_sha: RELEASE_SHA,
    observed_lock_owner_sha256: ownerSha256,
    reason: "crashed_writer_chain_nonce_and_all_release_ledgers_reconciled",
    chain_and_ledger_reconciliation_sha256: `sha256:${"2".repeat(64)}`,
    approved_at: "2026-07-21T13:00:00.000Z",
    expires_at: "2026-07-21T13:30:00.000Z",
    declaration: RELEASE_CEREMONY_LOCK_RECOVERY_DECLARATION,
    fresh_contract_deployment_receipt_sha256:
      authorityFixture.anchorProof.fresh_contract_deployment_receipt_sha256,
    reviewer_authority_genesis_sha256:
      authorityFixture.reviewerAuthorityGenesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      authorityFixture.reviewerAuthorityGenesisAcceptanceSha256,
    reviewer_authority_current_status_epoch: REVIEWER_CURRENT_STATUS.epoch,
    reviewer_authority_current_status_sha256:
      releaseReviewerAuthorityCurrentStatusSha256(
        REVIEWER_CURRENT_STATUS,
        { reviewerGenesis: REVIEWER_GENESIS },
      ),
    reviewer_genesis_anchor_proof_sha256:
      authorityFixture.reviewerGenesisAnchorProofSha256,
    reviewer_root_hash: REVIEWER_CURRENT_STATUS.reviewer_root_hash,
    reviewer_set_sha256: REVIEWER_CURRENT_STATUS.reviewer_set_sha256,
    reviewers: identities,
    signature_scheme: RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_SCHEME,
    signature_verifier: RELEASE_CEREMONY_LOCK_RECOVERY_SIGNATURE_VERIFIER,
    ...payloadOverrides,
  });
  const message = releaseCeremonyLockRecoverySigningMessage(payload);
  const actualSigners = signers
    ?? identities.map((identity) => ACCOUNTS_BY_ADDRESS.get(identity.address));
  const signatures = await Promise.all(
    actualSigners.map((signer) => signer.signMessage({ message })),
  );
  return {
    ...payload,
    signed_payload_sha256: releaseCeremonyLockRecoverySigningPayloadSha256(payload),
    reviewers: identities.map((identity, index) => ({
      ...identity,
      signature: signatures[index].toLowerCase(),
    })),
    ...envelopeOverrides,
  };
}

test("one release-wide lock excludes every pair of different ceremony writers", (t) => {
  const f = fixture(t);
  for (let firstIndex = 0; firstIndex < RELEASE_CEREMONY_WRITERS.length; firstIndex += 1) {
    for (let secondIndex = firstIndex + 1; secondIndex < RELEASE_CEREMONY_WRITERS.length; secondIndex += 1) {
      const firstWriter = RELEASE_CEREMONY_WRITERS[firstIndex];
      const secondWriter = RELEASE_CEREMONY_WRITERS[secondIndex];
      const token = firstIndex.toString(16).padStart(2, "0").repeat(32);
      const acquired = acquireReleaseCeremonyLock(context(f, firstWriter, token));
      assert.equal(acquired.protocol, RELEASE_CEREMONY_LOCK_PROTOCOL);
      assert.equal(acquired.lock_path.endsWith(`${RELEASE_SHA}.lock`), true);
      assert.throws(
        () => acquireReleaseCeremonyLock(context(f, secondWriter, "f".repeat(64))),
        /held or stale.*reviewed recovery/,
      );
      assert.throws(
        () => releaseReleaseCeremonyLock({
          ...context(f, firstWriter),
          ownerToken: "e".repeat(64),
        }),
        /ownership does not match/,
      );
      releaseReleaseCeremonyLock({
        ...context(f, firstWriter),
        ownerToken: token,
      });
    }
  }
});

function spawnCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      cwd: ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
    child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

test("two different helper processes racing acquire have exactly one winner", async (t) => {
  const f = fixture(t);
  const common = [
    "--lock-root", f.lockRoot,
    "--repository-root", f.repositoryRoot,
    "--release-sha", RELEASE_SHA,
  ];
  const [compute, diligence] = await Promise.all([
    spawnCli(["acquire", ...common, "--writer-id", "compute_release", "--owner-pid", "1001"]),
    spawnCli(["acquire", ...common, "--writer-id", "diligence_release", "--owner-pid", "1002"]),
  ]);
  assert.deepEqual([compute.status, diligence.status].sort(), [0, 1]);
  const winner = compute.status === 0 ? compute : diligence;
  const result = JSON.parse(winner.stdout);
  const inspected = inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
  });
  releaseReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    writerId: inspected.owner.writer_id,
    ownerToken: result.owner_token,
  });
});

test("crash-stale lock cannot be broken without fresh exact two-reviewer recovery authority", async (t) => {
  const f = fixture(t);
  acquireReleaseCeremonyLock(context(f, "email_oracle_release", "3".repeat(64)));
  const inspected = inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
  });
  assert.equal(inspected.status, "held_or_stale_requires_owner_release_or_reviewed_recovery");

  const recoveryPath = path.join(f.base, "recovery.json");
  const invalid = await recoveryAuthority(inspected.observed_lock_owner_sha256, f);
  invalid.reviewers = invalid.reviewers.slice(0, 1);
  fs.writeFileSync(recoveryPath, canonicalText(invalid), { mode: 0o600 });
  assert.throws(() => recoverReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    recoveryAuthorityPath: recoveryPath,
    reviewerAuthorityGenesisPath: f.reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath: f.reviewerAuthorityGenesisAcceptancePath,
    reviewerGenesisAnchorProofPath: f.reviewerGenesisAnchorProofPath,
    nowMs: Date.parse("2026-07-21T13:00:00.000Z"),
  }), /exactly two signed reviewers/);
  assert.equal(fs.existsSync(inspected.lock_path), true);

  fs.writeFileSync(
    recoveryPath,
    canonicalText(await recoveryAuthority(inspected.observed_lock_owner_sha256, f)),
    { mode: 0o600 },
  );
  const recovered = recoverReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    recoveryAuthorityPath: recoveryPath,
    reviewerAuthorityGenesisPath: f.reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath: f.reviewerAuthorityGenesisAcceptancePath,
    reviewerGenesisAnchorProofPath: f.reviewerGenesisAnchorProofPath,
    nowMs: Date.parse("2026-07-21T13:00:00.000Z"),
  });
  assert.equal(
    recovered.status,
    "recovered_after_dual_rpc_signed_genesis_anchor_and_two_reviewer_authority",
  );
  assert.match(recovered.recovery_receipt_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(fs.statSync(recovered.recovery_receipt_path).mode & 0o777, 0o444);
  assert.equal(fs.existsSync(inspected.lock_path), false);
});

test("orphaned pre-owner checkpoint also requires reviewed recovery bound to missing-owner marker", async (t) => {
  const f = fixture(t);
  const lockPath = path.join(f.lockRoot, `dnai-release-ceremony-${RELEASE_SHA}.lock`);
  fs.mkdirSync(lockPath, { mode: 0o700 });
  const inspected = inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
  });
  assert.equal(inspected.observed_lock_owner_sha256, RELEASE_CEREMONY_LOCK_MISSING_OWNER_SHA256);
  const recoveryPath = path.join(f.base, "orphan-recovery.json");
  fs.writeFileSync(
    recoveryPath,
    canonicalText(await recoveryAuthority(RELEASE_CEREMONY_LOCK_MISSING_OWNER_SHA256, f)),
    { mode: 0o600 },
  );
  recoverReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    recoveryAuthorityPath: recoveryPath,
    reviewerAuthorityGenesisPath: f.reviewerAuthorityGenesisPath,
    reviewerAuthorityGenesisAcceptancePath: f.reviewerAuthorityGenesisAcceptancePath,
    reviewerGenesisAnchorProofPath: f.reviewerGenesisAnchorProofPath,
    nowMs: Date.parse("2026-07-21T13:00:00.000Z"),
  });
  assert.equal(fs.existsSync(lockPath), false);
});

test("forged, unallowlisted, duplicate, expired, and altered signed recoveries fail closed", async (t) => {
  const f = fixture(t);
  const token = "4".repeat(64);
  acquireReleaseCeremonyLock(context(f, "ceremony_ledger_recovery", token));
  const inspected = inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
  });
  const recoveryPath = path.join(f.base, "adversarial-recovery.json");
  const attempt = (value, pattern) => {
    fs.writeFileSync(recoveryPath, canonicalText(value), { mode: 0o600 });
    assert.throws(() => recoverReleaseCeremonyLock({
      lockRoot: f.lockRoot,
      repositoryRoot: f.repositoryRoot,
      releaseSha: RELEASE_SHA,
      recoveryAuthorityPath: recoveryPath,
      reviewerAuthorityGenesisPath: f.reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath: f.reviewerAuthorityGenesisAcceptancePath,
      reviewerGenesisAnchorProofPath: f.reviewerGenesisAnchorProofPath,
      nowMs: Date.parse("2026-07-21T13:00:00.000Z"),
    }), pattern);
    assert.equal(fs.existsSync(inspected.lock_path), true);
  };

  const unsigned = await recoveryAuthority(inspected.observed_lock_owner_sha256, f);
  delete unsigned.reviewers[0].signature;
  attempt(unsigned, /fields do not match|signature/);

  const legacy = await recoveryAuthority(inspected.observed_lock_owner_sha256, f);
  legacy.schema = "dnai.release-ceremony-lock-recovery.v1";
  attempt(legacy, /signing payload binding/);

  const wrongOwner = await recoveryAuthority(`sha256:${"f".repeat(64)}`, f);
  attempt(wrongOwner, /authority binding/);

  const wrongRoot = await recoveryAuthority(inspected.observed_lock_owner_sha256, f, {
    payloadOverrides: { reviewer_root_hash: "f".repeat(64) },
  });
  attempt(wrongRoot, /authority binding/);

  const forkedStatus = await recoveryAuthority(
    inspected.observed_lock_owner_sha256,
    f,
    {
      payloadOverrides: {
        reviewer_authority_current_status_sha256: `sha256:${"8".repeat(64)}`,
      },
    },
  );
  attempt(forkedStatus, /stale or forked/);

  const expired = await recoveryAuthority(inspected.observed_lock_owner_sha256, f, {
    payloadOverrides: { expires_at: "2026-07-21T12:59:59.000Z" },
  });
  attempt(expired, /expired|bounded lifetime/);

  const alteredReconciliation = await recoveryAuthority(
    inspected.observed_lock_owner_sha256,
    f,
  );
  alteredReconciliation.chain_and_ledger_reconciliation_sha256 =
    `sha256:${"9".repeat(64)}`;
  attempt(alteredReconciliation, /authority binding/);

  const duplicate = await recoveryAuthority(inspected.observed_lock_owner_sha256, f);
  duplicate.reviewers[1].address = duplicate.reviewers[0].address;
  attempt(duplicate, /distinct signers/);

  const forgedSignature = await recoveryAuthority(
    inspected.observed_lock_owner_sha256,
    f,
    { signers: [FORGED_REVIEWER, REVIEWER_BRAVO] },
  );
  attempt(forgedSignature, /signature verification failed/);

  const highS = await recoveryAuthority(inspected.observed_lock_owner_sha256, f);
  highS.reviewers[0].signature = malleateToHighS(highS.reviewers[0].signature);
  attempt(highS, /canonical low-s/);

  const forgedIdentity = {
    address: FORGED_REVIEWER.address.toLowerCase(),
    controller_id: "reviewer-forged",
  };
  const unallowlisted = await recoveryAuthority(
    inspected.observed_lock_owner_sha256,
    f,
    {
      identities: [
        forgedIdentity,
        { address: REVIEWER_BRAVO.address.toLowerCase(), controller_id: "reviewer-bravo" },
      ],
      signers: [FORGED_REVIEWER, REVIEWER_BRAVO],
    },
  );
  attempt(unallowlisted, /not in the transitively pinned reviewer set/);

  releaseReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    writerId: "ceremony_ledger_recovery",
    ownerToken: token,
  });
});

test("lock root must be canonical, private, symlink-free, and outside the repository", (t) => {
  const f = fixture(t);
  fs.chmodSync(f.lockRoot, 0o755);
  assert.throws(() => acquireReleaseCeremonyLock(context(f, "tinker_release")), /group or other/);
  fs.chmodSync(f.lockRoot, 0o700);
  const link = path.join(f.base, "linked-locks");
  fs.symlinkSync(f.lockRoot, link);
  assert.throws(() => acquireReleaseCeremonyLock({
    ...context(f, "tinker_release"),
    lockRoot: link,
  }), /symlink|canonical/);
  assert.throws(() => acquireReleaseCeremonyLock({
    ...context(f, "tinker_release"),
    lockRoot: path.join(ROOT, "scripts"),
  }), /outside the source repository/);

  const foreignOwnedRoot = fs.realpathSync(os.tmpdir());
  if (typeof process.geteuid === "function"
    && fs.statSync(foreignOwnedRoot).uid !== process.geteuid()) {
    assert.throws(() => inspectReleaseCeremonyLock({
      lockRoot: foreignOwnedRoot,
      repositoryRoot: f.repositoryRoot,
      releaseSha: RELEASE_SHA,
    }), /owned by the current operator/);
  }
});

test("stable fd reads reject owner-path swaps and root inode replacement", (t) => {
  const f = fixture(t);
  const token = "8".repeat(64);
  const acquired = acquireReleaseCeremonyLock(context(f, "compute_release", token));
  const ownerPath = path.join(acquired.lock_path, "owner.json");
  const savedOwnerPath = path.join(acquired.lock_path, "saved-owner.json");
  assert.throws(() => inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    testHookAfterOwnerOpen: () => {
      fs.renameSync(ownerPath, savedOwnerPath);
      fs.writeFileSync(ownerPath, fs.readFileSync(savedOwnerPath), { mode: 0o600 });
    },
  }), /changed during its bounded read/);
  fs.unlinkSync(ownerPath);
  fs.renameSync(savedOwnerPath, ownerPath);

  const savedRoot = `${f.lockRoot}.saved`;
  assert.throws(() => inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    testHookAfterContext: () => {
      fs.renameSync(f.lockRoot, savedRoot);
      fs.mkdirSync(f.lockRoot, { mode: 0o700 });
    },
  }), /changed during the lock operation/);
  fs.rmdirSync(f.lockRoot);
  fs.renameSync(savedRoot, f.lockRoot);
  releaseReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
    writerId: "compute_release",
    ownerToken: token,
  });
});

test("dual RPC anchor proof and signed genesis acceptance are mandatory", (t) => {
  const f = fixture(t);
  const drifted = structuredClone(f.anchorProof);
  drifted.secondary_rpc.block_hash = `0x${"99".repeat(32)}`;
  assert.throws(() => normalizeReleaseReviewerGenesisAnchorProof(drifted, {
    expectedReleaseSha: RELEASE_SHA,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
  }), /must be distinct and agree/);

  const sameAuthority = structuredClone(f.anchorProof);
  sameAuthority.secondary_rpc.authority_id = sameAuthority.primary_rpc.authority_id;
  assert.throws(() => normalizeReleaseReviewerGenesisAnchorProof(sameAuthority, {
    expectedReleaseSha: RELEASE_SHA,
    expectedReviewerAuthorityGenesisAcceptanceSha256:
      REVIEWER_GENESIS_ACCEPTANCE_SHA256,
  }), /must be distinct and agree/);

  const forgedAcceptance = structuredClone(REVIEWER_GENESIS_ACCEPTANCE);
  forgedAcceptance.acceptances[0].signature = `0x${"00".repeat(65)}`;
  fs.writeFileSync(
    f.reviewerAuthorityGenesisAcceptancePath,
    canonicalText(forgedAcceptance),
    { mode: 0o600 },
  );
  acquireReleaseCeremonyLock(context(f, "diligence_release", "9".repeat(64)));
  const inspected = inspectReleaseCeremonyLock({
    lockRoot: f.lockRoot,
    repositoryRoot: f.repositoryRoot,
    releaseSha: RELEASE_SHA,
  });
  const recoveryPath = path.join(f.base, "forged-acceptance-recovery.json");
  return recoveryAuthority(inspected.observed_lock_owner_sha256, f).then((recovery) => {
    fs.writeFileSync(recoveryPath, canonicalText(recovery), { mode: 0o600 });
    assert.throws(() => recoverReleaseCeremonyLock({
      lockRoot: f.lockRoot,
      repositoryRoot: f.repositoryRoot,
      releaseSha: RELEASE_SHA,
      recoveryAuthorityPath: recoveryPath,
      reviewerAuthorityGenesisPath: f.reviewerAuthorityGenesisPath,
      reviewerAuthorityGenesisAcceptancePath: f.reviewerAuthorityGenesisAcceptancePath,
      reviewerGenesisAnchorProofPath: f.reviewerGenesisAnchorProofPath,
      nowMs: Date.parse("2026-07-21T13:00:00.000Z"),
    }), /canonical low-s|signature verification failed/);
  });
});
