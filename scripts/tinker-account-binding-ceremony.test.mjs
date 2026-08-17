import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
} from "./release-reviewer-authority-cli.mjs";
import {
  createDraftDeploymentIntentCore,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME,
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA,
  TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD,
  TINKER_ACCOUNT_BINDING_CEREMONY_SCHEMA,
  TINKER_ACCOUNT_BINDING_EXTERNAL_SIGNATURES_SCHEMA,
  TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_TRUTH_STATUS,
  TINKER_ACCOUNT_BINDING_INTENT_BASENAME,
  TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_BASENAME,
  TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_SCHEMA,
  TINKER_ACCOUNT_BINDING_INTENT_SCHEMA,
  TINKER_ACCOUNT_BINDING_REVIEWER_SIGNATURE_PURPOSE,
  TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
  parseTinkerAccountBindingCeremonyCliArgs,
  runTinkerAccountBindingCeremonyCli,
  tinkerAccountBindingArtifactPaths,
  tinkerAccountBindingCeremonyReceiptSha256,
  tinkerAccountBindingIntentSha256,
  tinkerAccountBindingSigningMessage,
  tinkerAccountBindingSigningPayloadSha256,
  verifyTinkerAccountBindingCeremonyArtifact,
  verifyTinkerAccountBindingCeremonyHistoricalReplay,
} from "./tinker-account-binding-ceremony.mjs";
import {
  deriveTinkerAccountBindingRoot,
  deriveTinkerAccountCommitment,
} from "./tinker-account-binding-core.mjs";

const RELEASE_SHA = "a".repeat(40);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const CEREMONY_TIME = "2026-07-22T12:05:00Z";
const STATUS_NOT_BEFORE = "2026-07-22T12:00:00Z";
const STATUS_EXPIRES = "2026-07-22T12:15:00Z";
const SHARE_ONE = Buffer.alloc(32, 0x11);
const SHARE_TWO = Buffer.alloc(32, 0x22);
const EXPECTED_ROOT = deriveTinkerAccountBindingRoot([SHARE_ONE, SHARE_TWO]);
const EXPECTED_COMMITMENT = deriveTinkerAccountCommitment(EXPECTED_ROOT);

const account = (byte) => privateKeyToAccount(`0x${byte.repeat(32)}`);
const REVIEWER_ACCOUNTS = [account("11"), account("22")];
const GUARDIAN_ACCOUNTS = [account("31"), account("32")];

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function writeCanonical(filePath, value, mode = 0o444) {
  fs.writeFileSync(filePath, canonicalText(value), { flag: "wx", mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

function addressOf(value) {
  return value.address.toLowerCase();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function address(byte) {
  return `0x${byte.toString(16).padStart(2, "0").repeat(20)}`;
}

function qvlPolicy() {
  return {
    challengeCapacity: 1024,
    challengeTtlSeconds: 60,
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    verificationTimeoutSeconds: "20",
  };
}

function createDeploymentIntent({
  accountCommitment,
  currentStatusEpoch,
  currentStatusSha256,
  genesisAcceptanceSha256,
  releaseSha = RELEASE_SHA,
}) {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = releaseSha;
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
    genesisAcceptanceSha256;
  intent.release.reviewerAuthorityCurrentStatusEpoch = currentStatusEpoch;
  intent.release.reviewerAuthorityCurrentStatusSha256 = currentStatusSha256;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress = address(1);
  intent.staticContractInputs.diligenceRoom.governanceController = address(29);
  intent.staticContractInputs.computeCreditVault.developer = address(30);
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    accountCommitment;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 100,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "5000000000000000000",
    tinkerMaxSpendWei: "2000000000000000000",
  };
  intent.numericPolicy.metering = {
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    rpcTimeoutSeconds: "8",
  };
  for (const name of Object.keys(intent.numericPolicy.qvl)) {
    intent.numericPolicy.qvl[name] = qvlPolicy();
  }
  const validation = validateDeploymentIntentCore(intent);
  assert.equal(validation.ok, true, JSON.stringify(validation.errors));
  return intent;
}

async function authorityArtifacts(directory, {
  expiresAt = STATUS_EXPIRES,
  notBefore = STATUS_NOT_BEFORE,
} = {}) {
  const reviewerControllers = [
    {
      controller_id: "reviewer-alpha",
      preauthorized_addresses: [addressOf(REVIEWER_ACCOUNTS[0])],
    },
    {
      controller_id: "reviewer-bravo",
      preauthorized_addresses: [addressOf(REVIEWER_ACCOUNTS[1])],
    },
  ];
  const statusGuardians = GUARDIAN_ACCOUNTS.map((entry, index) => ({
    address: addressOf(entry),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const guardianHashes = statusGuardians
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  const genesis = normalizeReleaseReviewerAuthorityGenesis({
    chain_id: 84_532,
    minimum_active_reviewers: 2,
    release_sha: RELEASE_SHA,
    reviewer_controller_set_sha256:
      reviewerControllerSetSha256(reviewerControllers),
    reviewer_controllers: reviewerControllers,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash:
      executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(statusGuardians),
    status_guardians: statusGuardians,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  });
  const activeReviewers = reviewerControllers.map((entry) => ({
    address: entry.preauthorized_addresses[0],
    controller_id: entry.controller_id,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const options = { reviewerGenesis: genesis, statusHistory: [] };
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    active_reviewers: activeReviewers,
    epoch: 1,
    expires_at: expiresAt,
    not_before: notBefore,
    previous_status_sha256: ZERO_SHA256,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, options);
  const digest = releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
    payload,
    options,
  );
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    options,
  );
  const guardianByAddress = new Map(
    GUARDIAN_ACCOUNTS.map((entry) => [addressOf(entry), entry]),
  );
  const guardianSignatures = [];
  for (const identity of statusGuardians) {
    guardianSignatures.push({
      ...identity,
      signature: (await guardianByAddress.get(identity.address)
        .signMessage({ message })).toLowerCase(),
    });
  }
  const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus({
    ...payload,
    guardian_signatures: guardianSignatures,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256: digest,
  }, options);
  const acceptancePayload =
    createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
      genesis,
      { reviewerCurrentStatus: currentStatus, statusHistory: [] },
    );
  const acceptanceMessage =
    releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
      acceptancePayload,
      { reviewerGenesis: genesis, statusHistory: [] },
    );
  const reviewerByAddress = new Map(
    REVIEWER_ACCOUNTS.map((entry) => [addressOf(entry), entry]),
  );
  const genesisAcceptance = {
    ...acceptancePayload,
    acceptances: await Promise.all(activeReviewers.map(async (reviewer) => ({
      ...reviewer,
      signature: (await reviewerByAddress.get(reviewer.address).signMessage({
        message: acceptanceMessage,
      })).toLowerCase(),
    }))),
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        acceptancePayload,
        { reviewerGenesis: genesis, statusHistory: [] },
      ),
  };
  const genesisAcceptanceSha256 =
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      genesisAcceptance,
      { reviewerGenesis: genesis, statusHistory: [] },
    );
  const genesisPath = writeCanonical(
    path.join(directory, "reviewer-genesis.json"),
    genesis,
  );
  const genesisAcceptancePath = path.join(
    directory,
    "reviewer-genesis-acceptance.json",
  );
  fs.writeFileSync(
    genesisAcceptancePath,
    canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      genesisAcceptance,
      { reviewerGenesis: genesis, statusHistory: [] },
    ),
    { flag: "wx", mode: 0o444 },
  );
  fs.chmodSync(genesisAcceptancePath, 0o444);
  const currentStatusPath = writeCanonical(
    path.join(directory, "reviewer-current-status.json"),
    currentStatus,
  );
  return {
    activeReviewers,
    currentStatus,
    currentStatusPath,
    currentStatusSha256: releaseReviewerAuthorityCurrentStatusSha256(
      currentStatus,
      options,
    ),
    genesis,
    genesisAcceptance,
    genesisAcceptancePath,
    genesisAcceptanceSha256,
    genesisPath,
    genesisSha256: releaseReviewerAuthorityGenesisSha256(genesis),
  };
}

async function advanceAuthority(value, {
  activeReviewers = value.activeReviewers,
  expiresAt = "2026-07-22T12:30:00Z",
  notBefore = "2026-07-22T12:16:00Z",
  revokedControllerIds = [],
  revokedReviewerAddresses = [],
} = {}) {
  const history = [value.currentStatus];
  const options = {
    reviewerGenesis: value.genesis,
    statusHistory: history,
  };
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    active_reviewers: activeReviewers,
    epoch: 2,
    expires_at: expiresAt,
    not_before: notBefore,
    previous_status_sha256: value.currentStatusSha256,
    revoked_controller_ids: revokedControllerIds,
    revoked_reviewer_addresses: revokedReviewerAddresses,
  }, options);
  const digest = releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
    payload,
    options,
  );
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    options,
  );
  const guardianByAddress = new Map(
    GUARDIAN_ACCOUNTS.map((entry) => [addressOf(entry), entry]),
  );
  const guardianSignatures = [];
  for (const identity of value.genesis.status_guardians) {
    guardianSignatures.push({
      ...identity,
      signature: (await guardianByAddress.get(identity.address)
        .signMessage({ message })).toLowerCase(),
    });
  }
  const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus({
    ...payload,
    guardian_signatures: guardianSignatures,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256: digest,
  }, options);
  const historyPath = writeCanonical(
    path.join(value.directory, "reviewer-status-history.json"),
    {
      schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
      statuses: history,
    },
  );
  const currentStatusPath = writeCanonical(
    path.join(value.directory, "reviewer-current-status-epoch-2.json"),
    currentStatus,
  );
  return {
    currentStatus,
    currentStatusPath,
    currentStatusSha256: releaseReviewerAuthorityCurrentStatusSha256(
      currentStatus,
      options,
    ),
    historyPath,
  };
}

function invoke(argv, {
  environment = {},
  now = CEREMONY_TIME,
  releaseDirectory,
} = {}) {
  let stdout = "";
  let stderr = "";
  const exitCode = runTinkerAccountBindingCeremonyCli(argv, {
    environment,
    now: () => new Date(now),
    releaseDirectory,
    stderr: (text) => { stderr += text; },
    stdout: (text) => { stdout += text; },
  });
  return { exitCode, stderr, stdout };
}

async function fixture(t, authorityOptions = {}) {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-tinker-binding-")),
  );
  fs.chmodSync(directory, 0o700);
  const releaseDirectory = path.join(directory, ".release");
  fs.mkdirSync(releaseDirectory, { mode: 0o700 });
  fs.chmodSync(releaseDirectory, 0o700);
  const authority = await authorityArtifacts(directory, authorityOptions);
  const shareOnePath = path.join(directory, "reviewer-a.share");
  const shareTwoPath = path.join(directory, "reviewer-b.share");
  fs.writeFileSync(shareOnePath, SHARE_ONE, { flag: "wx", mode: 0o600 });
  fs.writeFileSync(shareTwoPath, SHARE_TWO, { flag: "wx", mode: 0o600 });
  fs.chmodSync(shareOnePath, 0o600);
  fs.chmodSync(shareTwoPath, 0o600);
  const shareFds = [
    fs.openSync(shareOnePath, fs.constants.O_RDONLY),
    fs.openSync(shareTwoPath, fs.constants.O_RDONLY),
  ];
  t.after(() => {
    for (const fd of shareFds) {
      try {
        fs.closeSync(fd);
      } catch {
        // A posture test may close one deliberately.
      }
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return {
    ...authority,
    directory,
    releaseDirectory,
    shareFds,
    shareOnePath,
    shareTwoPath,
  };
}

function intentArgs(value) {
  return [
    "intent-create",
    "--release-sha", RELEASE_SHA,
    "--reviewer-genesis", value.genesisPath,
    "--genesis-acceptance", value.genesisAcceptancePath,
    "--current-status", value.currentStatusPath,
    "--share-fd", String(value.shareFds[0]),
    "--share-fd", String(value.shareFds[1]),
  ];
}

function postIntentArgs(value, command, deploymentIntentPath, extras = []) {
  return [
    command,
    "--reviewer-genesis", value.genesisPath,
    "--genesis-acceptance", value.genesisAcceptancePath,
    "--current-status", value.currentStatusPath,
    "--deployment-intent", deploymentIntentPath,
    ...extras,
  ];
}

function artifactPaths(value) {
  return tinkerAccountBindingArtifactPaths(value.releaseDirectory);
}

function readArtifact(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

async function externalSignatures(value, intentReceipt, {
  purpose = TINKER_ACCOUNT_BINDING_REVIEWER_SIGNATURE_PURPOSE,
  reverse = false,
} = {}) {
  const accountByAddress = new Map(
    REVIEWER_ACCOUNTS.map((entry) => [addressOf(entry), entry]),
  );
  const identities = [...value.activeReviewers];
  if (reverse) identities.reverse();
  const signatures = [];
  for (const identity of identities) {
    signatures.push({
      ...identity,
      signature: (await accountByAddress.get(identity.address).signMessage({
        message: intentReceipt.eip191.message,
      })).toLowerCase(),
    });
  }
  return {
    purpose,
    schema: TINKER_ACCOUNT_BINDING_EXTERNAL_SIGNATURES_SCHEMA,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signed_payload_sha256: intentReceipt.eip191.signed_payload_sha256,
    signatures,
  };
}

async function prepareSignedCeremony(t, value, {
  environmentCommitment = EXPECTED_COMMITMENT,
} = {}) {
  const created = invoke(intentArgs(value), {
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(created.exitCode, 0, created.stderr);
  const paths = artifactPaths(value);
  const intent = readArtifact(paths.intent);
  const intentReceipt = readArtifact(paths.intentReceipt);
  const deploymentIntent = createDeploymentIntent({
    accountCommitment: EXPECTED_COMMITMENT,
    currentStatusEpoch: value.currentStatus.epoch,
    currentStatusSha256: value.currentStatusSha256,
    genesisAcceptanceSha256: value.genesisAcceptanceSha256,
  });
  const deploymentIntentPath = writeCanonical(
    path.join(value.directory, "deployment-intent.json"),
    deploymentIntent,
    0o600,
  );
  const signaturesPath = writeCanonical(
    path.join(value.directory, "reviewer-signatures.json"),
    await externalSignatures(value, intentReceipt),
  );
  const environment = {
    TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: environmentCommitment,
  };
  const attached = invoke(
    postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
      "--reviewer-signatures", signaturesPath,
    ]),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  return {
    attached,
    deploymentIntent,
    deploymentIntentPath,
    environment,
    intent,
    intentReceipt,
    paths,
    signaturesPath,
  };
}

test("CLI rejects every secret/path/signer surface and requires exactly two inherited fds", () => {
  const secret = "de".repeat(32);
  for (const flag of [
    "--share",
    "--share-path",
    "--share-file",
    "--share-hex",
    "--share-base64",
    "--binding-root",
    "--root",
    "--root-hex",
    "--root-base64",
    "--stdin",
    "--private-key",
    "--mnemonic",
    "--credential-file",
    "--env",
    "--rpc-url",
    "--out",
    "--output",
  ]) {
    assert.throws(
      () => parseTinkerAccountBindingCeremonyCliArgs([
        "intent-create",
        `${flag}=${secret}`,
      ]),
      (error) => {
        assert.equal(error.message.includes(secret), false);
        assert.match(error.message, /forbidden/);
        return true;
      },
    );
  }
  assert.throws(
    () => parseTinkerAccountBindingCeremonyCliArgs([
      "intent-create",
      "--release-sha", RELEASE_SHA,
      "--reviewer-genesis", "/tmp/genesis.json",
      "--current-status", "/tmp/current.json",
      "--share-fd", "3",
      "--share-fd", "4",
    ]),
    /required argument is missing: --genesis-acceptance/,
  );
  assert.throws(
    () => parseTinkerAccountBindingCeremonyCliArgs([
      "intent-create",
      "--release-sha", RELEASE_SHA,
      "--reviewer-genesis", "/tmp/genesis.json",
      "--genesis-acceptance", "/tmp/acceptance.json",
      "--current-status", "/tmp/current.json",
      "--share-fd", "3",
    ]),
    /exactly two --share-fd/,
  );
  assert.throws(
    () => parseTinkerAccountBindingCeremonyCliArgs([
      "ceremony-check",
      "--reviewer-genesis", "/tmp/genesis.json",
      "--current-status", "/tmp/current.json",
      "--deployment-intent", "/tmp/intent.json",
      "--share-fd", "3",
    ]),
    /unsupported argument/,
  );
  assert.throws(
    () => parseTinkerAccountBindingCeremonyCliArgs([
      "intent-create",
      "--release-sha", RELEASE_SHA,
      "--release-sha", RELEASE_SHA,
      "--reviewer-genesis", "/tmp/genesis.json",
      "--current-status", "/tmp/current.json",
      "--share-fd", "3",
      "--share-fd", "4",
    ]),
    /duplicate argument/,
  );
});

test("complete two-reviewer ceremony is fixed-path, create-only, durable, and check is read-only", async (t) => {
  const value = await fixture(t);
  const created = invoke(intentArgs(value), {
    environment: {},
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(created.exitCode, 0, created.stderr);
  const paths = artifactPaths(value);
  assert.deepEqual(Object.values(paths).map((entry) => path.basename(entry)).sort(), [
    TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME,
    TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
    TINKER_ACCOUNT_BINDING_INTENT_BASENAME,
    TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_BASENAME,
  ].sort());
  const intent = readArtifact(paths.intent);
  const intentReceipt = readArtifact(paths.intentReceipt);
  assert.equal(intent.schema, TINKER_ACCOUNT_BINDING_INTENT_SCHEMA);
  assert.equal(intent.truth_status, TINKER_ACCOUNT_BINDING_TRUTH_STATUS);
  assert.equal(intent.account_commitment, EXPECTED_COMMITMENT);
  assert.equal(intent.privacy.provider_identifier_committed, false);
  assert.equal(intent.privacy.attested_provider_binding_required, true);
  assert.equal(intent.privacy.raw_share_egress, false);
  assert.equal(intent.privacy.raw_binding_root_egress, false);
  assert.equal(intent.privacy.share_or_root_digest_published, false);
  assert.equal(
    intent.privacy.root_or_share_must_never_enter_rpc_or_contract_calldata,
    true,
  );
  assert.equal(
    intent.privacy.same_chain_linkability_if_binding_root_reused,
    true,
  );
  assert.deepEqual(
    intent.reviewer_authority.reviewers.map(
      ({ address, controller_id, private_share_slot }) => ({
        address,
        controller_id,
        private_share_slot,
      }),
    ),
    value.activeReviewers.map((entry, index) => ({
      ...entry,
      private_share_slot: index + 1,
    })),
  );
  assert.equal(intentReceipt.schema, TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_SCHEMA);
  assert.equal(intentReceipt.required_signature_count, 2);
  assert.equal(intentReceipt.provider_identifier_committed, false);
  assert.equal(intentReceipt.share_or_root_digest_published, false);
  assert.equal(
    intentReceipt.intent_sha256,
    tinkerAccountBindingIntentSha256(intent),
  );
  for (const filePath of [paths.intent, paths.intentReceipt]) {
    const stat = fs.lstatSync(filePath);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(stat.nlink, 1);
  }

  const publicBytes = [
    created.stdout,
    created.stderr,
    fs.readFileSync(paths.intent, "utf8"),
    fs.readFileSync(paths.intentReceipt, "utf8"),
  ].join("\n");
  for (const secret of [
    SHARE_ONE.toString("hex"),
    SHARE_TWO.toString("hex"),
    EXPECTED_ROOT.toString("hex"),
    sha256(SHARE_ONE),
    sha256(SHARE_TWO),
    sha256(EXPECTED_ROOT),
  ]) {
    assert.equal(publicBytes.includes(secret), false);
  }

  const deploymentIntentPath = writeCanonical(
    path.join(value.directory, "deployment-intent.json"),
    createDeploymentIntent({
      accountCommitment: EXPECTED_COMMITMENT,
      currentStatusEpoch: value.currentStatus.epoch,
      currentStatusSha256: value.currentStatusSha256,
      genesisAcceptanceSha256: value.genesisAcceptanceSha256,
    }),
    0o600,
  );
  const signaturesPath = writeCanonical(
    path.join(value.directory, "reviewer-signatures.json"),
    await externalSignatures(value, intentReceipt),
  );
  const environment = {
    TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
  };
  const attached = invoke(
    postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
      "--reviewer-signatures", signaturesPath,
    ]),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  assert.equal(attached.exitCode, 0, attached.stderr);
  assert.equal(fs.existsSync(paths.ceremony), true);
  assert.equal(fs.existsSync(paths.ceremonyReceipt), false);
  const ceremony = readArtifact(paths.ceremony);
  assert.equal(ceremony.schema, TINKER_ACCOUNT_BINDING_CEREMONY_SCHEMA);
  assert.equal(ceremony.reviewer_signatures.length, 2);
  assert.equal(fs.lstatSync(paths.ceremony).mode & 0o777, 0o600);
  assert.equal(fs.lstatSync(paths.ceremony).nlink, 1);

  const prematureCheck = invoke(
    postIntentArgs(value, "ceremony-check", deploymentIntentPath),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  assert.equal(prematureCheck.exitCode, 1);
  assert.equal(fs.existsSync(paths.ceremonyReceipt), false);

  const verified = invoke(
    postIntentArgs(value, "ceremony-verify", deploymentIntentPath),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  assert.equal(verified.exitCode, 0, verified.stderr);
  const receiptBytes = fs.readFileSync(paths.ceremonyReceipt, "utf8");
  const receipt = JSON.parse(receiptBytes);
  assert.equal(receipt.schema, TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA);
  assert.equal(receipt.status, "tinker_account_binding_two_reviewer_ceremony_verified");
  assert.equal(receipt.verified_signature_count, 2);
  assert.equal(receipt.signature_verification_subprocess_invoked, true);
  assert.equal(receipt.deployment_intent_matched, true);
  assert.equal(receipt.environment_commitment_matched, true);
  assert.equal(receipt.provider_identifier_committed, false);
  assert.equal(receipt.attested_provider_binding_required, true);
  assert.equal(
    receipt[TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD],
    tinkerAccountBindingCeremonyReceiptSha256(receipt),
  );
  assert.match(
    receipt[TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD],
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(fs.lstatSync(paths.ceremonyReceipt).mode & 0o777, 0o600);
  assert.equal(fs.lstatSync(paths.ceremonyReceipt).nlink, 1);

  const before = Object.fromEntries(
    Object.values(paths).map((filePath) => [
      filePath,
      {
        bytes: fs.readFileSync(filePath),
        stat: fs.statSync(filePath, { bigint: true }),
      },
    ]),
  );
  const checked = invoke(
    postIntentArgs(value, "ceremony-check", deploymentIntentPath),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  assert.equal(checked.exitCode, 0, checked.stderr);
  assert.equal(checked.stdout, receiptBytes);
  assert.equal(checked.stdout.includes(value.directory), false);
  assert.equal(/"(?:path|fd|share_sha256|root_sha256|binding_root)"/.test(
    checked.stdout,
  ), false);
  for (const filePath of Object.values(paths)) {
    assert.deepEqual(fs.readFileSync(filePath), before[filePath].bytes);
    const after = fs.statSync(filePath, { bigint: true });
    assert.equal(after.dev, before[filePath].stat.dev);
    assert.equal(after.ino, before[filePath].stat.ino);
    assert.equal(after.size, before[filePath].stat.size);
    assert.equal(after.mtimeNs, before[filePath].stat.mtimeNs);
    assert.equal(after.ctimeNs, before[filePath].stat.ctimeNs);
  }

  const noClobber = invoke(
    postIntentArgs(value, "ceremony-verify", deploymentIntentPath),
    { environment, releaseDirectory: value.releaseDirectory },
  );
  assert.equal(noClobber.exitCode, 1);
  assert.match(noClobber.stderr, /already exists/);
  assert.equal(fs.readFileSync(paths.ceremonyReceipt, "utf8"), receiptBytes);
});

test("intent creation never requires or reads a preexisting deployment commitment", async (t) => {
  const value = await fixture(t);
  const result = invoke(intentArgs(value), {
    environment: {
      TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: `0x${"ff".repeat(32)}`,
    },
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(
    readArtifact(artifactPaths(value).intent).account_commitment,
    EXPECTED_COMMITMENT,
  );
});

test("intent creation authenticates the canonical signed genesis acceptance before reading shares", async (t) => {
  await t.test("forged acceptance signature", async (st) => {
    const value = await fixture(st);
    const forged = structuredClone(value.genesisAcceptance);
    const signature = forged.acceptances[0].signature;
    forged.acceptances[0].signature =
      `${signature.slice(0, 10)}${signature[10] === "0" ? "1" : "0"}${signature.slice(11)}`;
    fs.unlinkSync(value.genesisAcceptancePath);
    writeCanonical(value.genesisAcceptancePath, forged);
    fs.closeSync(value.shareFds[0]);
    const result = invoke(intentArgs(value), {
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /signature|recovered signer|verification failed/);
    assert.doesNotMatch(result.stderr, /descriptor is not open/);
    assert.equal(fs.existsSync(artifactPaths(value).intent), false);
  });

  await t.test("hard-linked acceptance file", async (st) => {
    const value = await fixture(st);
    fs.linkSync(
      value.genesisAcceptancePath,
      `${value.genesisAcceptancePath}.alias`,
    );
    const result = invoke(intentArgs(value), {
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /link|posture/);
    assert.equal(fs.existsSync(artifactPaths(value).intent), false);
  });
});

for (const scenario of [
  {
    name: "same descriptor twice",
    mutate(value) {
      value.shareFds[1] = value.shareFds[0];
    },
    pattern: /descriptors must be distinct/,
  },
  {
    name: "same bytes in distinct files",
    mutate(value) {
      fs.closeSync(value.shareFds[1]);
      fs.writeFileSync(value.shareTwoPath, SHARE_ONE);
      fs.chmodSync(value.shareTwoPath, 0o600);
      value.shareFds[1] = fs.openSync(value.shareTwoPath, fs.constants.O_RDONLY);
    },
    pattern: /distinct values/,
  },
  {
    name: "public file mode",
    mutate(value) {
      fs.chmodSync(value.shareOnePath, 0o644);
    },
    pattern: /mode-0600/,
  },
  {
    name: "short file",
    mutate(value) {
      fs.closeSync(value.shareFds[0]);
      fs.truncateSync(value.shareOnePath, 31);
      value.shareFds[0] = fs.openSync(value.shareOnePath, fs.constants.O_RDONLY);
    },
    pattern: /exactly 32 bytes/,
  },
  {
    name: "hard-linked file",
    mutate(value) {
      fs.linkSync(value.shareOnePath, `${value.shareOnePath}.alias`);
    },
    pattern: /single-link/,
  },
  {
    name: "closed descriptor",
    mutate(value) {
      fs.closeSync(value.shareFds[0]);
    },
    pattern: /descriptor is not open/,
  },
]) {
  test(`share posture rejects ${scenario.name} without publishing an intent`, async (t) => {
    const value = await fixture(t);
    scenario.mutate(value);
    const result = invoke(intentArgs(value), {
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, scenario.pattern);
    assert.equal(fs.existsSync(artifactPaths(value).intent), false);
    assert.equal(result.stderr.includes(SHARE_ONE.toString("hex")), false);
    assert.equal(result.stderr.includes(SHARE_TWO.toString("hex")), false);
    assert.equal(result.stderr.includes(EXPECTED_ROOT.toString("hex")), false);
  });
}

test("private release directory and fixed artifacts enforce exact modes and links", async (t) => {
  const value = await fixture(t);
  fs.chmodSync(value.releaseDirectory, 0o755);
  const directoryFailure = invoke(intentArgs(value), {
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(directoryFailure.exitCode, 1);
  assert.match(directoryFailure.stderr, /mode-0700/);
  fs.chmodSync(value.releaseDirectory, 0o700);
  const created = invoke(intentArgs(value), {
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(created.exitCode, 0, created.stderr);
  const paths = artifactPaths(value);
  fs.chmodSync(paths.intentReceipt, 0o644);
  const deploymentIntentPath = writeCanonical(
    path.join(value.directory, "deployment-intent.json"),
    createDeploymentIntent({
      accountCommitment: EXPECTED_COMMITMENT,
      currentStatusEpoch: value.currentStatus.epoch,
      currentStatusSha256: value.currentStatusSha256,
      genesisAcceptanceSha256: value.genesisAcceptanceSha256,
    }),
    0o600,
  );
  const signaturesPath = writeCanonical(
    path.join(value.directory, "reviewer-signatures.json"),
    await externalSignatures(value, readArtifact(paths.intentReceipt)),
  );
  const result = invoke(
    postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
      "--reviewer-signatures", signaturesPath,
    ]),
    {
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
      },
      releaseDirectory: value.releaseDirectory,
    },
  );
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /invalid ownership, link, mode, type, or size posture/);
  assert.equal(fs.existsSync(paths.ceremony), false);
});

test("post-intent commands require exact environment and canonical deployment-intent bindings", async (t) => {
  const cases = [
    {
      name: "missing environment",
      environment: {},
      mutate: () => {},
      pattern: /must be a nonzero canonical bytes32/,
    },
    {
      name: "wrong environment",
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: `0x${"ee".repeat(32)}`,
      },
      mutate: () => {},
      pattern: /does not match the account-binding intent/,
    },
    {
      name: "wrong deployment commitment",
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
      },
      mutate: (intent) => {
        intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
          `0x${"dd".repeat(32)}`;
      },
      pattern: /does not match the account-binding commitment/,
    },
    {
      name: "wrong deployment release",
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
      },
      mutate: (intent) => {
        intent.release.releaseSha = "b".repeat(40);
      },
      pattern: /does not match the account-binding commitment/,
    },
    {
      name: "wrong current-status digest",
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
      },
      mutate: (intent) => {
        intent.release.reviewerAuthorityCurrentStatusSha256 =
          `sha256:${"aa".repeat(32)}`;
      },
      pattern: /genesis acceptance differs from the immutable deployment-intent pins/,
    },
    {
      name: "wrong genesis-acceptance digest",
      environment: {
        TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
      },
      mutate: (intent) => {
        intent.release.reviewerAuthorityGenesisAcceptanceSha256 =
          `sha256:${"ab".repeat(32)}`;
      },
      pattern: /genesis acceptance differs from the immutable deployment-intent pins/,
    },
  ];
  for (const scenario of cases) {
    await t.test(scenario.name, async (st) => {
      const value = await fixture(st);
      const created = invoke(intentArgs(value), {
        releaseDirectory: value.releaseDirectory,
      });
      assert.equal(created.exitCode, 0, created.stderr);
      const paths = artifactPaths(value);
      const deploymentIntent = createDeploymentIntent({
        accountCommitment: EXPECTED_COMMITMENT,
        currentStatusEpoch: value.currentStatus.epoch,
        currentStatusSha256: value.currentStatusSha256,
        genesisAcceptanceSha256: value.genesisAcceptanceSha256,
      });
      scenario.mutate(deploymentIntent);
      assert.equal(validateDeploymentIntentCore(deploymentIntent).ok, true);
      const deploymentIntentPath = writeCanonical(
        path.join(value.directory, "deployment-intent.json"),
        deploymentIntent,
        0o600,
      );
      const signaturesPath = writeCanonical(
        path.join(value.directory, "reviewer-signatures.json"),
        await externalSignatures(value, readArtifact(paths.intentReceipt)),
      );
      const result = invoke(
        postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
          "--reviewer-signatures", signaturesPath,
        ]),
        {
          environment: scenario.environment,
          releaseDirectory: value.releaseDirectory,
        },
      );
      assert.equal(result.exitCode, 1);
      assert.match(result.stderr, scenario.pattern);
      assert.equal(fs.existsSync(paths.ceremony), false);
    });
  }
});

test("signature purpose, order, membership, and signature bytes are fail-closed", async (t) => {
  const scenarios = [
    {
      name: "wrong purpose",
      mutate(envelope) {
        envelope.purpose = "different_purpose";
      },
      pattern: /do not match the exact account-binding intent/,
    },
    {
      name: "reversed order",
      mutate(envelope) {
        envelope.signatures.reverse();
      },
      pattern: /exact canonical reviewer identity order/,
    },
    {
      name: "wrong controller",
      mutate(envelope) {
        envelope.signatures[0].controller_id = "reviewer-forged";
      },
      pattern: /exact canonical reviewer identity order/,
    },
    {
      name: "forged signature",
      async mutate(envelope, value, receipt) {
        envelope.signatures[0].signature = (await account("55").signMessage({
          message: receipt.eip191.message,
        })).toLowerCase();
      },
      pattern: /signature verification failed|recovered signer/,
    },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async (st) => {
      const value = await fixture(st);
      const created = invoke(intentArgs(value), {
        releaseDirectory: value.releaseDirectory,
      });
      assert.equal(created.exitCode, 0, created.stderr);
      const paths = artifactPaths(value);
      const receipt = readArtifact(paths.intentReceipt);
      const envelope = await externalSignatures(value, receipt);
      await scenario.mutate(envelope, value, receipt);
      const signaturesPath = writeCanonical(
        path.join(value.directory, "reviewer-signatures.json"),
        envelope,
      );
      const deploymentIntentPath = writeCanonical(
        path.join(value.directory, "deployment-intent.json"),
        createDeploymentIntent({
          accountCommitment: EXPECTED_COMMITMENT,
          currentStatusEpoch: value.currentStatus.epoch,
          currentStatusSha256: value.currentStatusSha256,
          genesisAcceptanceSha256: value.genesisAcceptanceSha256,
        }),
        0o600,
      );
      const attached = invoke(
        postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
          "--reviewer-signatures", signaturesPath,
        ]),
        {
          environment: {
            TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
          },
          releaseDirectory: value.releaseDirectory,
        },
      );
      assert.equal(attached.exitCode, 1);
      assert.match(attached.stderr, scenario.pattern);
      assert.equal(fs.existsSync(paths.ceremony), false);
    });
  }
});

test("every live ceremony operation rejects a not-yet-current or expired reviewer status", async (t) => {
  await t.test("intent-create before status", async (st) => {
    const value = await fixture(st);
    const result = invoke(intentArgs(value), {
      now: "2026-07-22T11:59:59Z",
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /not active yet/);
  });
  await t.test("intent-create after status", async (st) => {
    const value = await fixture(st);
    const result = invoke(intentArgs(value), {
      now: STATUS_EXPIRES,
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /expired/);
  });
  await t.test("attach after status", async (st) => {
    const value = await fixture(st);
    const created = invoke(intentArgs(value), {
      releaseDirectory: value.releaseDirectory,
    });
    assert.equal(created.exitCode, 0, created.stderr);
    const paths = artifactPaths(value);
    const deploymentIntentPath = writeCanonical(
      path.join(value.directory, "deployment-intent.json"),
      createDeploymentIntent({
        accountCommitment: EXPECTED_COMMITMENT,
        currentStatusEpoch: value.currentStatus.epoch,
        currentStatusSha256: value.currentStatusSha256,
        genesisAcceptanceSha256: value.genesisAcceptanceSha256,
      }),
      0o600,
    );
    const signaturesPath = writeCanonical(
      path.join(value.directory, "reviewer-signatures.json"),
      await externalSignatures(value, readArtifact(paths.intentReceipt)),
    );
    const attached = invoke(
      postIntentArgs(value, "ceremony-attach", deploymentIntentPath, [
        "--reviewer-signatures", signaturesPath,
      ]),
      {
        environment: {
          TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: EXPECTED_COMMITMENT,
        },
        now: STATUS_EXPIRES,
        releaseDirectory: value.releaseDirectory,
      },
    );
    assert.equal(attached.exitCode, 1);
    assert.match(attached.stderr, /expired/);
    assert.equal(fs.existsSync(paths.ceremony), false);
  });
});

test("historical replay verifies the signed in-window timestamp without authorizing a current deployment", async (t) => {
  const value = await fixture(t);
  const prepared = await prepareSignedCeremony(t, value);
  assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
  const ceremony = readArtifact(prepared.paths.ceremony);
  assert.throws(
    () => verifyTinkerAccountBindingCeremonyArtifact({
      ceremony,
      deploymentIntent: prepared.deploymentIntentPath,
      environment: prepared.environment,
      now: () => new Date(STATUS_EXPIRES),
      reviewerCurrentStatus: value.currentStatusPath,
      reviewerGenesis: value.genesisPath,
      reviewerGenesisAcceptance: value.genesisAcceptancePath,
    }),
    /expired/,
  );
  const replay = verifyTinkerAccountBindingCeremonyHistoricalReplay({
    ceremony,
    deploymentIntent: prepared.deploymentIntentPath,
    environment: {},
    reviewerCurrentStatus: value.currentStatusPath,
    reviewerGenesis: value.genesisPath,
    reviewerGenesisAcceptance: value.genesisAcceptancePath,
  });
  assert.equal(replay.receipt.historical_replay, true);
  assert.equal(
    replay.receipt.status,
    "historical_tinker_account_binding_ceremony_cryptographically_replayed",
  );
  assert.equal(
    replay.receipt.truth_status,
    TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_TRUTH_STATUS,
  );
  assert.equal(replay.receipt.environment_commitment_matched, false);

  const tampered = structuredClone(ceremony);
  tampered.intent.ceremony_timestamp = "2026-07-22T11:59:59Z";
  assert.throws(
    () => verifyTinkerAccountBindingCeremonyHistoricalReplay({
      ceremony: tampered,
      deploymentIntent: prepared.deploymentIntentPath,
      environment: {},
      reviewerCurrentStatus: value.currentStatusPath,
      reviewerGenesis: value.genesisPath,
      reviewerGenesisAcceptance: value.genesisAcceptancePath,
    }),
    /intent digests are invalid|outside the authenticated reviewer status window/,
  );
});

test("historical replay selects the exact intent-pinned predecessor from an authenticated advanced lineage", async (t) => {
  const value = await fixture(t);
  const prepared = await prepareSignedCeremony(t, value);
  assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
  const ceremony = readArtifact(prepared.paths.ceremony);
  const advanced = await advanceAuthority(value);
  const replay = verifyTinkerAccountBindingCeremonyHistoricalReplay({
    ceremony,
    deploymentIntent: prepared.deploymentIntentPath,
    environment: {},
    reviewerCurrentStatus: advanced.currentStatusPath,
    reviewerGenesis: value.genesisPath,
    reviewerGenesisAcceptance: value.genesisAcceptancePath,
    statusHistory: advanced.historyPath,
  });
  assert.equal(replay.receipt.historical_replay, true);
  assert.equal(
    replay.receipt.reviewer_authority_current_status_sha256,
    value.currentStatusSha256,
  );
  assert.notEqual(
    replay.receipt.reviewer_authority_current_status_sha256,
    advanced.currentStatusSha256,
  );
});

test("historical replay rejects lineage gaps, substitutions, illegal revocation state, and signed wrong-window timestamps", async (t) => {
  await t.test("gap", async (st) => {
    const value = await fixture(st);
    const prepared = await prepareSignedCeremony(st, value);
    assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
    const advanced = await advanceAuthority(value);
    const emptyHistoryPath = writeCanonical(
      path.join(value.directory, "empty-history.json"),
      {
        schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
        statuses: [],
      },
    );
    assert.throws(
      () => verifyTinkerAccountBindingCeremonyHistoricalReplay({
        ceremony: readArtifact(prepared.paths.ceremony),
        deploymentIntent: prepared.deploymentIntentPath,
        environment: {},
        reviewerCurrentStatus: advanced.currentStatusPath,
        reviewerGenesis: value.genesisPath,
        reviewerGenesisAcceptance: value.genesisAcceptancePath,
        statusHistory: emptyHistoryPath,
      }),
      /epoch|predecessor|history|rollback|fork/,
    );
  });

  await t.test("substitution", async (st) => {
    const value = await fixture(st);
    const prepared = await prepareSignedCeremony(st, value);
    assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
    const advanced = await advanceAuthority(value);
    const substituted = structuredClone(value.currentStatus);
    substituted.expires_at = "2026-07-22T12:14:59Z";
    const substitutedHistoryPath = writeCanonical(
      path.join(value.directory, "substituted-history.json"),
      {
        schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
        statuses: [substituted],
      },
    );
    assert.throws(
      () => verifyTinkerAccountBindingCeremonyHistoricalReplay({
        ceremony: readArtifact(prepared.paths.ceremony),
        deploymentIntent: prepared.deploymentIntentPath,
        environment: {},
        reviewerCurrentStatus: advanced.currentStatusPath,
        reviewerGenesis: value.genesisPath,
        reviewerGenesisAcceptance: value.genesisAcceptancePath,
        statusHistory: substitutedHistoryPath,
      }),
      /signature|payload|predecessor|substituted|fork/,
    );
  });

  await t.test("illegal revocation", async (st) => {
    const value = await fixture(st);
    const prepared = await prepareSignedCeremony(st, value);
    assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
    const advanced = await advanceAuthority(value);
    const revoked = structuredClone(advanced.currentStatus);
    revoked.revoked_controller_ids = [
      revoked.active_reviewers[0].controller_id,
    ].sort();
    const revokedCurrentPath = writeCanonical(
      path.join(value.directory, "revoked-current.json"),
      revoked,
    );
    assert.throws(
      () => verifyTinkerAccountBindingCeremonyHistoricalReplay({
        ceremony: readArtifact(prepared.paths.ceremony),
        deploymentIntent: prepared.deploymentIntentPath,
        environment: {},
        reviewerCurrentStatus: revokedCurrentPath,
        reviewerGenesis: value.genesisPath,
        reviewerGenesisAcceptance: value.genesisAcceptancePath,
        statusHistory: advanced.historyPath,
      }),
      /revoked|signature|payload/,
    );
  });

  await t.test("signed wrong-window timestamp", async (st) => {
    const value = await fixture(st);
    const prepared = await prepareSignedCeremony(st, value);
    assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
    const ceremony = structuredClone(readArtifact(prepared.paths.ceremony));
    ceremony.intent.ceremony_timestamp = "2026-07-22T11:59:59Z";
    ceremony.intent_sha256 =
      tinkerAccountBindingIntentSha256(ceremony.intent);
    ceremony.signing_payload_sha256 =
      tinkerAccountBindingSigningPayloadSha256(ceremony.intent);
    const message = tinkerAccountBindingSigningMessage(ceremony.intent);
    const accountByAddress = new Map(
      REVIEWER_ACCOUNTS.map((entry) => [addressOf(entry), entry]),
    );
    ceremony.reviewer_signatures = [];
    for (const identity of value.activeReviewers) {
      ceremony.reviewer_signatures.push({
        ...identity,
        signature: (await accountByAddress.get(identity.address)
          .signMessage({ message })).toLowerCase(),
      });
    }
    assert.throws(
      () => verifyTinkerAccountBindingCeremonyHistoricalReplay({
        ceremony,
        deploymentIntent: prepared.deploymentIntentPath,
        environment: {},
        reviewerCurrentStatus: value.currentStatusPath,
        reviewerGenesis: value.genesisPath,
        reviewerGenesisAcceptance: value.genesisAcceptancePath,
      }),
      /outside the authenticated reviewer status window/,
    );
  });
});

test("check rejects canonical receipt drift and never repairs it", async (t) => {
  const value = await fixture(t);
  const prepared = await prepareSignedCeremony(t, value);
  assert.equal(prepared.attached.exitCode, 0, prepared.attached.stderr);
  const verified = invoke(
    postIntentArgs(value, "ceremony-verify", prepared.deploymentIntentPath),
    {
      environment: prepared.environment,
      releaseDirectory: value.releaseDirectory,
    },
  );
  assert.equal(verified.exitCode, 0, verified.stderr);
  const original = readArtifact(prepared.paths.ceremonyReceipt);
  fs.chmodSync(prepared.paths.ceremonyReceipt, 0o600);
  fs.unlinkSync(prepared.paths.ceremonyReceipt);
  writeCanonical(
    prepared.paths.ceremonyReceipt,
    { ...original, verified_signature_count: 3 },
    0o600,
  );
  const before = fs.readFileSync(prepared.paths.ceremonyReceipt);
  const checked = invoke(
    postIntentArgs(value, "ceremony-check", prepared.deploymentIntentPath),
    {
      environment: prepared.environment,
      releaseDirectory: value.releaseDirectory,
    },
  );
  assert.equal(checked.exitCode, 1);
  assert.match(checked.stderr, /does not equal the independently recomputed/);
  assert.deepEqual(fs.readFileSync(prepared.paths.ceremonyReceipt), before);
});

test("existing intent-generation artifacts stop before any private share read or clobber", async (t) => {
  const value = await fixture(t);
  const paths = artifactPaths(value);
  const sentinel = Buffer.from('{"sentinel":true}\n');
  fs.writeFileSync(paths.intentReceipt, sentinel, { flag: "wx", mode: 0o600 });
  fs.chmodSync(paths.intentReceipt, 0o600);
  fs.closeSync(value.shareFds[0]);
  const result = invoke(intentArgs(value), {
    releaseDirectory: value.releaseDirectory,
  });
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /already exists/);
  assert.deepEqual(fs.readFileSync(paths.intentReceipt), sentinel);
  assert.equal(fs.existsSync(paths.intent), false);
  assert.doesNotMatch(result.stderr, /descriptor is not open/);
});
