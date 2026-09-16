import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  normalizeReleaseReviewerAuthorityGenesis,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DECLARATION,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PROPOSAL_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_EXTERNAL_SIGNATURES_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
  RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_SIGNING_DIAGNOSTIC_SCHEMA,
  RELEASE_REVIEWER_ROSTER_SCHEMA,
  parseReleaseReviewerAuthorityCliArgs,
  readStableCanonicalAuthorityJson,
  runReleaseReviewerAuthorityCli,
} from "./release-reviewer-authority-cli.mjs";

const RELEASE_SHA = "a".repeat(40);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const account = (byte) => privateKeyToAccount(`0x${byte.repeat(32)}`);
const REVIEWER_ACCOUNTS = ["11", "12", "21", "22", "31", "32"].map(account);
const GUARDIAN_ACCOUNTS = ["41", "42"].map(account);
const FORGED = account("55");

function addressOf(value) {
  return value.address.toLowerCase();
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function writeCanonical(filePath, value, mode = 0o444) {
  fs.writeFileSync(filePath, canonicalText(value), { flag: "wx", mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

function invoke(argv) {
  let stdout = "";
  let stderr = "";
  const exitCode = runReleaseReviewerAuthorityCli(argv, {
    stdout: (text) => { stdout += text; },
    stderr: (text) => { stderr += text; },
  });
  return { exitCode, stdout, stderr };
}

function fixture(t) {
  const directory = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-reviewer-authority-v2-")),
  );
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const reviewerControllers = [
    { controller_id: "reviewer-alpha", accounts: REVIEWER_ACCOUNTS.slice(0, 2) },
    { controller_id: "reviewer-bravo", accounts: REVIEWER_ACCOUNTS.slice(2, 4) },
    { controller_id: "reviewer-charlie", accounts: REVIEWER_ACCOUNTS.slice(4, 6) },
  ].map((entry) => ({
    controller_id: entry.controller_id,
    preauthorized_addresses: entry.accounts.map(addressOf).sort(),
  }));
  const statusGuardians = GUARDIAN_ACCOUNTS.map((entry, index) => ({
    address: addressOf(entry),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const activeReviewers = reviewerControllers.map((entry) => ({
    address: entry.preauthorized_addresses[0],
    controller_id: entry.controller_id,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const rosterPath = writeCanonical(path.join(directory, "reviewer-roster.json"), {
    reviewer_controllers: reviewerControllers,
    schema: RELEASE_REVIEWER_ROSTER_SCHEMA,
    status_guardians: statusGuardians,
  });
  const proposalPath = writeCanonical(path.join(directory, "status-proposal.json"), {
    active_reviewers: activeReviewers,
    epoch: 1,
    expires_at: "2026-07-21T12:15:00Z",
    not_before: "2026-07-21T12:00:00Z",
    previous_status_sha256: ZERO_SHA256,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PROPOSAL_SCHEMA,
  });
  const accountByAddress = new Map(
    [...REVIEWER_ACCOUNTS, ...GUARDIAN_ACCOUNTS, FORGED]
      .map((entry) => [addressOf(entry), entry]),
  );
  return {
    accountByAddress,
    activeReviewers,
    directory,
    proposalPath,
    reviewerControllers,
    rosterPath,
    statusGuardians,
  };
}

function createGenesis(value) {
  const genesisPath = path.join(value.directory, "reviewer-genesis.json");
  const result = invoke([
    "genesis-init", "--release-sha", RELEASE_SHA,
    "--roster", value.rosterPath, "--out", genesisPath,
  ]);
  assert.equal(result.exitCode, 0, result.stderr);
  return {
    genesis: normalizeReleaseReviewerAuthorityGenesis(
      JSON.parse(fs.readFileSync(genesisPath, "utf8")),
    ),
    genesisPath,
    receipt: JSON.parse(result.stdout),
  };
}

async function signatureEnvelope(value, diagnostic, identities, purpose, {
  forgedIndex = -1,
  omittedLast = false,
} = {}) {
  const signatures = [];
  for (const [index, identity] of identities.entries()) {
    if (omittedLast && index === identities.length - 1) continue;
    const signer = index === forgedIndex ? FORGED : value.accountByAddress.get(identity.address);
    signatures.push({
      ...identity,
      signature: (await signer.signMessage({ message: diagnostic.eip191.message })).toLowerCase(),
    });
  }
  return {
    purpose,
    schema: RELEASE_REVIEWER_AUTHORITY_EXTERNAL_SIGNATURES_SCHEMA,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signed_payload_sha256: diagnostic.eip191.signed_payload_sha256,
    signatures,
  };
}

async function createCurrentStatus(value, genesisPath) {
  const payloadPath = path.join(value.directory, "status-signing-payload.json");
  const payloadResult = invoke([
    "current-status-payload", "--reviewer-genesis", genesisPath,
    "--status-proposal", value.proposalPath, "--out", payloadPath,
  ]);
  assert.equal(payloadResult.exitCode, 0, payloadResult.stderr);
  const diagnostic = JSON.parse(payloadResult.stdout);
  const guardianEnvelope = await signatureEnvelope(
    value,
    diagnostic,
    value.statusGuardians,
    RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
  );
  const signaturesPath = writeCanonical(
    path.join(value.directory, "guardian-signatures.json"),
    guardianEnvelope,
  );
  const statusPath = path.join(value.directory, "current-status.json");
  const attachResult = invoke([
    "current-status-attach", "--reviewer-genesis", genesisPath,
    "--signing-payload", payloadPath, "--guardian-signatures", signaturesPath,
    "--out", statusPath,
  ]);
  assert.equal(attachResult.exitCode, 0, attachResult.stderr);
  return {
    attachReceipt: JSON.parse(attachResult.stdout),
    diagnostic,
    payloadPath,
    signaturesPath,
    statusPath,
  };
}

test("CLI rejects credentials, legacy aliases, duplicates, and incomplete ceremonies", () => {
  assert.throws(
    () => parseReleaseReviewerAuthorityCliArgs([
      "genesis-init", "--release-sha", RELEASE_SHA, "--roster", "/tmp/r.json",
      "--out", "/tmp/g.json", "--private-key", "secret",
    ]),
    /forbidden signer or credential flag/,
  );
  assert.throws(
    () => parseReleaseReviewerAuthorityCliArgs([
      "genesis-init", "--release-sha", RELEASE_SHA, "--reviewers", "/tmp/r.json",
      "--out", "/tmp/g.json",
    ]),
    /unsupported argument: --reviewers/,
  );
  assert.throws(
    () => parseReleaseReviewerAuthorityCliArgs([
      "current-status-verify", "--reviewer-genesis", "/tmp/g.json",
      "--current-status", "/tmp/s.json", "--status-history", "/tmp/h1.json",
      "--status-history", "/tmp/h2.json",
    ]),
    /duplicate argument/,
  );
  assert.throws(
    () => parseReleaseReviewerAuthorityCliArgs(["current-status-attach"]),
    /required argument is missing/,
  );
  const secret = `0x${"de".repeat(32)}`;
  const equalsCredential = invoke([`--private-key=${secret}`]);
  assert.equal(equalsCredential.exitCode, 1);
  assert.equal(equalsCredential.stderr.includes(secret), false);
  assert.match(equalsCredential.stderr, /forbidden signer or credential flag/);
  const commandCredential = invoke([`--mnemonic=alpha beta gamma delta`]);
  assert.equal(commandCredential.exitCode, 1);
  assert.equal(commandCredential.stderr.includes("alpha beta"), false);
  assert.equal(JSON.parse(commandCredential.stderr).command, "unknown");
});

test("operator completes v2 genesis, two-guardian status, and all-active-reviewer acceptance", async (t) => {
  const value = fixture(t);
  const { genesis, genesisPath, receipt } = createGenesis(value);
  assert.equal(receipt.schema, RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA);
  assert.equal(receipt.status, "reviewer_genesis_v2_created_not_self_authorizing");
  assert.equal(receipt.reviewer_controller_count, 3);
  assert.equal(receipt.preauthorized_reviewer_key_count, 6);
  assert.equal(receipt.status_guardian_count, 2);
  assert.equal(receipt.private_or_raw_key_input_accepted, false);
  assert.deepEqual(genesis.reviewer_controllers, value.reviewerControllers);
  assert.deepEqual(genesis.status_guardians, value.statusGuardians);
  assert.equal(fs.statSync(genesisPath).mode & 0o777, 0o444);

  const genesisVerify = invoke(["genesis-verify", "--reviewer-genesis", genesisPath]);
  assert.equal(genesisVerify.exitCode, 0, genesisVerify.stderr);

  const current = await createCurrentStatus(value, genesisPath);
  assert.equal(current.diagnostic.schema, RELEASE_REVIEWER_AUTHORITY_SIGNING_DIAGNOSTIC_SCHEMA);
  assert.equal(current.diagnostic.status, "ready_for_external_two_guardian_eip191_signatures");
  assert.equal(current.diagnostic.required_signature_count, 2);
  assert.equal(current.diagnostic.eip191.purpose, RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE);
  assert.match(
    current.attachReceipt.truth_status,
    /not_independently_anchored_head_or_time_freshness/,
  );
  assert.equal(current.attachReceipt.signature_verification_subprocess_invoked, true);
  const status = normalizeReleaseReviewerAuthorityCurrentStatus(
    JSON.parse(fs.readFileSync(current.statusPath, "utf8")),
    { reviewerGenesis: genesis },
  );
  assert.equal(status.guardian_signatures.length, 2);
  assert.equal(fs.statSync(current.statusPath).mode & 0o777, 0o444);
  const statusVerify = invoke([
    "current-status-verify", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath,
  ]);
  assert.equal(statusVerify.exitCode, 0, statusVerify.stderr);
  const statusVerifyReceipt = JSON.parse(statusVerify.stdout);
  assert.match(statusVerifyReceipt.truth_status, /not_independently_anchored_head_or_time_freshness/);
  assert.equal(statusVerifyReceipt.signature_verification_subprocess_invoked, true);

  const acceptancePayloadPath = path.join(value.directory, "acceptance-payload.json");
  const acceptancePayloadResult = invoke([
    "acceptance-payload", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath, "--out", acceptancePayloadPath,
  ]);
  assert.equal(acceptancePayloadResult.exitCode, 0, acceptancePayloadResult.stderr);
  const acceptanceDiagnostic = JSON.parse(acceptancePayloadResult.stdout);
  assert.equal(acceptanceDiagnostic.status, "ready_for_external_all_active_reviewer_eip191_signatures");
  assert.equal(acceptanceDiagnostic.required_signature_count, value.activeReviewers.length);
  assert.equal(acceptanceDiagnostic.eip191.purpose, RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE);
  assert.equal(acceptanceDiagnostic.signature_verification_subprocess_invoked, true);

  const reviewerSignaturesPath = writeCanonical(
    path.join(value.directory, "active-reviewer-signatures.json"),
    await signatureEnvelope(
      value,
      acceptanceDiagnostic,
      status.active_reviewers,
      RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
    ),
  );
  const acceptancePath = path.join(value.directory, "genesis-acceptance.json");
  const acceptanceAttach = invoke([
    "acceptance-attach", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath,
    "--signing-payload", acceptancePayloadPath,
    "--reviewer-signatures", reviewerSignaturesPath,
    "--out", acceptancePath,
  ]);
  assert.equal(acceptanceAttach.exitCode, 0, acceptanceAttach.stderr);
  const acceptanceReceipt = JSON.parse(acceptanceAttach.stdout);
  assert.equal(
    acceptanceReceipt.status,
    "all_active_reviewer_genesis_acceptance_cryptographically_verified_and_created",
  );
  assert.match(
    acceptanceReceipt.truth_status,
    /not_independently_anchored_head_or_time_freshness/,
  );
  assert.equal(acceptanceReceipt.verified_signature_count, status.active_reviewers.length);
  assert.equal(acceptanceReceipt.signature_verification_subprocess_invoked, true);
  assert.equal(acceptanceReceipt.signer_subprocess_invoked, false);
  assert.equal(fs.statSync(acceptancePath).mode & 0o777, 0o444);

  const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(
    JSON.parse(fs.readFileSync(acceptancePath, "utf8")),
    { reviewerGenesis: genesis },
  );
  assert.deepEqual(acceptance.reviewer_authority_current_status, status);
  assert.equal(acceptance.acceptances.length, status.active_reviewers.length);
  const acceptanceVerify = invoke([
    "acceptance-verify", "--reviewer-genesis", genesisPath,
    "--acceptance", acceptancePath,
  ]);
  assert.equal(acceptanceVerify.exitCode, 0, acceptanceVerify.stderr);
  const acceptanceVerifyReceipt = JSON.parse(acceptanceVerify.stdout);
  assert.match(
    acceptanceVerifyReceipt.truth_status,
    /not_independently_anchored_head_or_time_freshness/,
  );
  assert.equal(acceptanceVerifyReceipt.signature_verification_subprocess_invoked, true);

  const replacement = invoke([
    "acceptance-attach", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath,
    "--signing-payload", acceptancePayloadPath,
    "--reviewer-signatures", reviewerSignaturesPath,
    "--out", acceptancePath,
  ]);
  assert.equal(replacement.exitCode, 1);
  assert.match(replacement.stderr, /output already exists.*create-new/);
  const replacementFailure = JSON.parse(replacement.stderr);
  assert.equal(
    replacementFailure.signature_verification_subprocess_invocation_status,
    "not_attested_due_to_operation_failure",
  );
  assert.equal(
    Object.hasOwn(replacementFailure, "signature_verification_subprocess_invoked"),
    false,
  );
});

test("missing, forged, cross-purpose, or reordered guardian signatures cannot mint status", async (t) => {
  const value = fixture(t);
  const { genesisPath } = createGenesis(value);
  const payloadPath = path.join(value.directory, "status-payload.json");
  const payloadResult = invoke([
    "current-status-payload", "--reviewer-genesis", genesisPath,
    "--status-proposal", value.proposalPath, "--out", payloadPath,
  ]);
  assert.equal(payloadResult.exitCode, 0, payloadResult.stderr);
  const diagnostic = JSON.parse(payloadResult.stdout);
  const extraFieldEnvelope = await signatureEnvelope(
    value,
    diagnostic,
    value.statusGuardians,
    RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
  );
  extraFieldEnvelope.signatures[0].unexpected = "must-not-be-projected-away";
  for (const [name, envelope, pattern] of [
    ["missing", await signatureEnvelope(value, diagnostic, value.statusGuardians, RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE, { omittedLast: true }), /every required signer/],
    ["forged", await signatureEnvelope(value, diagnostic, value.statusGuardians, RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE, { forgedIndex: 0 }), /signature verification failed/],
    ["wrong-purpose", await signatureEnvelope(value, diagnostic, value.statusGuardians, RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE), /exact purpose/],
    ["reordered", { ...(await signatureEnvelope(value, diagnostic, value.statusGuardians, RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE)), signatures: [...(await signatureEnvelope(value, diagnostic, value.statusGuardians, RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE)).signatures].reverse() }, /canonical required signer set/],
    ["extra-field", extraFieldEnvelope, /external signature 0 fields do not match/],
  ]) {
    const signaturesPath = writeCanonical(path.join(value.directory, `${name}.json`), envelope);
    const outputPath = path.join(value.directory, `${name}-must-not-exist.json`);
    const result = invoke([
      "current-status-attach", "--reviewer-genesis", genesisPath,
      "--signing-payload", payloadPath, "--guardian-signatures", signaturesPath,
      "--out", outputPath,
    ]);
    assert.equal(result.exitCode, 1, `${name}: ${result.stderr}`);
    assert.equal(fs.existsSync(outputPath), false);
    assert.match(result.stderr, pattern);
    if (name === "forged") {
      const failure = JSON.parse(result.stderr);
      assert.equal(
        failure.signature_verification_subprocess_invocation_status,
        "not_attested_due_to_operation_failure",
      );
      assert.equal(
        Object.hasOwn(failure, "signature_verification_subprocess_invoked"),
        false,
      );
    }
  }
});

test("only the active reviewer set can sign acceptance and v1 envelopes have no fallback", async (t) => {
  const value = fixture(t);
  const { genesisPath } = createGenesis(value);
  const current = await createCurrentStatus(value, genesisPath);
  const payloadPath = path.join(value.directory, "acceptance-payload.json");
  const payloadResult = invoke([
    "acceptance-payload", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath, "--out", payloadPath,
  ]);
  assert.equal(payloadResult.exitCode, 0, payloadResult.stderr);
  const diagnostic = JSON.parse(payloadResult.stdout);
  const forgedEnvelope = await signatureEnvelope(
    value,
    diagnostic,
    value.activeReviewers,
    RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
    { forgedIndex: 1 },
  );
  const forgedPath = writeCanonical(path.join(value.directory, "forged-reviewer.json"), forgedEnvelope);
  const outputPath = path.join(value.directory, "must-not-exist.json");
  const forged = invoke([
    "acceptance-attach", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath, "--signing-payload", payloadPath,
    "--reviewer-signatures", forgedPath, "--out", outputPath,
  ]);
  assert.equal(forged.exitCode, 1);
  assert.equal(fs.existsSync(outputPath), false);
  assert.match(forged.stderr, /signature verification failed/);
  assert.equal(forged.stderr.includes(`0x${"55".repeat(32)}`), false);

  const legacyEnvelope = { ...forgedEnvelope, schema: "dnai.release-reviewer-authority-external-signatures.v1" };
  const legacyPath = writeCanonical(path.join(value.directory, "legacy-envelope.json"), legacyEnvelope);
  const legacy = invoke([
    "acceptance-attach", "--reviewer-genesis", genesisPath,
    "--current-status", current.statusPath, "--signing-payload", payloadPath,
    "--reviewer-signatures", legacyPath, "--out", outputPath,
  ]);
  assert.equal(legacy.exitCode, 1);
  assert.match(legacy.stderr, /exact purpose\/payload/);
});

test("successor status requires a complete canonical history and never treats history as an implicit head", async (t) => {
  const value = fixture(t);
  const { genesisPath } = createGenesis(value);
  const first = await createCurrentStatus(value, genesisPath);
  const firstStatus = JSON.parse(fs.readFileSync(first.statusPath, "utf8"));
  const historyPath = writeCanonical(path.join(value.directory, "history.json"), {
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
    statuses: [firstStatus],
  });
  const secondActive = value.reviewerControllers.slice(0, 2).map((entry) => ({
    address: entry.preauthorized_addresses[1],
    controller_id: entry.controller_id,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const firstReceipt = JSON.parse(invoke([
    "current-status-verify", "--reviewer-genesis", genesisPath,
    "--current-status", first.statusPath,
  ]).stdout);
  const secondProposalPath = writeCanonical(path.join(value.directory, "second-proposal.json"), {
    active_reviewers: secondActive,
    epoch: 2,
    expires_at: "2026-07-21T12:30:00Z",
    not_before: "2026-07-21T12:15:00Z",
    previous_status_sha256: firstReceipt.reviewer_authority_current_status_sha256,
    revoked_controller_ids: ["reviewer-charlie"],
    revoked_reviewer_addresses: [],
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PROPOSAL_SCHEMA,
  });
  const noHistoryOutput = path.join(value.directory, "no-history-must-not-exist.json");
  const noHistory = invoke([
    "current-status-payload", "--reviewer-genesis", genesisPath,
    "--status-proposal", secondProposalPath, "--out", noHistoryOutput,
  ]);
  assert.equal(noHistory.exitCode, 1);
  assert.equal(fs.existsSync(noHistoryOutput), false);
  assert.match(noHistory.stderr, /epoch must be strictly monotonic/);

  const secondPayloadPath = path.join(value.directory, "second-payload.json");
  const withHistory = invoke([
    "current-status-payload", "--reviewer-genesis", genesisPath,
    "--status-proposal", secondProposalPath, "--status-history", historyPath,
    "--out", secondPayloadPath,
  ]);
  assert.equal(withHistory.exitCode, 0, withHistory.stderr);
  const diagnostic = JSON.parse(withHistory.stdout);
  assert.equal(diagnostic.current_status_history_length, 1);
  assert.equal(diagnostic.status_epoch, 2);
  assert.match(diagnostic.truth_status, /not_current_status/);
});

test("all authority inputs must be canonical, opened-FD stable, owned, and symlink-free", (t) => {
  const value = fixture(t);
  const writable = path.join(value.directory, "owner-writable.json");
  fs.writeFileSync(writable, canonicalText({ schema: "example" }), { mode: 0o644 });
  fs.chmodSync(writable, 0o644);
  assert.throws(
    () => readStableCanonicalAuthorityJson(writable, "test input"),
    /read-only/,
  );
  const noncanonical = path.join(value.directory, "noncanonical.json");
  fs.writeFileSync(noncanonical, "{\"schema\":\"example\"}\n", { mode: 0o444 });
  assert.throws(
    () => readStableCanonicalAuthorityJson(noncanonical, "test input"),
    /canonical sorted two-space JSON/,
  );
  const symlink = path.join(value.directory, "symlink.json");
  fs.symlinkSync(value.rosterPath, symlink);
  assert.throws(
    () => readStableCanonicalAuthorityJson(symlink, "test input"),
    /canonical and symlink-free/,
  );

  const hardlinkSource = writeCanonical(
    path.join(value.directory, "hardlink-source.json"),
    { schema: "example" },
  );
  const hardlinkAlias = path.join(value.directory, "hardlink-alias.json");
  fs.linkSync(hardlinkSource, hardlinkAlias);
  assert.throws(
    () => readStableCanonicalAuthorityJson(hardlinkSource, "test input"),
    /single-link/,
  );

  const raceTarget = writeCanonical(
    path.join(value.directory, "race-target.json"),
    { schema: "first" },
  );
  const raceReplacement = writeCanonical(
    path.join(value.directory, "race-replacement.json"),
    { schema: "second" },
  );
  const raceBackup = path.join(value.directory, "race-backup.json");
  const originalOpenSync = fs.openSync;
  let swapped = false;
  fs.openSync = (candidate, ...rest) => {
    if (!swapped && candidate === raceTarget) {
      swapped = true;
      fs.renameSync(raceTarget, raceBackup);
      fs.renameSync(raceReplacement, raceTarget);
    }
    return originalOpenSync.call(fs, candidate, ...rest);
  };
  try {
    assert.throws(
      () => readStableCanonicalAuthorityJson(raceTarget, "test input"),
      /changed while opening its stable descriptor/,
    );
  } finally {
    fs.openSync = originalOpenSync;
  }

  const untrustedDirectory = path.join(value.directory, "untrusted-output");
  fs.mkdirSync(untrustedDirectory, { mode: 0o777 });
  fs.chmodSync(untrustedDirectory, 0o777);
  const untrustedOutput = path.join(untrustedDirectory, "genesis.json");
  const publication = invoke([
    "genesis-init", "--release-sha", RELEASE_SHA,
    "--roster", value.rosterPath, "--out", untrustedOutput,
  ]);
  assert.equal(publication.exitCode, 1);
  assert.equal(fs.existsSync(untrustedOutput), false);
  assert.match(publication.stderr, /must not be group- or other-writable/);
});

test("an interrupted authority write never publishes or strands the final create-new path", (t) => {
  const value = fixture(t);
  const output = path.join(value.directory, "interrupted-genesis.json");
  const originalWriteSync = fs.writeSync;
  let injected = false;
  fs.writeSync = (fd, buffer, offset, length, position) => {
    if (!injected) {
      injected = true;
      originalWriteSync.call(
        fs,
        fd,
        buffer,
        offset,
        Math.max(1, Math.floor(length / 2)),
        position,
      );
      throw new Error("injected reviewer authority partial write failure");
    }
    return originalWriteSync.call(fs, fd, buffer, offset, length, position);
  };
  let result;
  try {
    result = invoke([
      "genesis-init", "--release-sha", RELEASE_SHA,
      "--roster", value.rosterPath, "--out", output,
    ]);
  } finally {
    fs.writeSync = originalWriteSync;
  }
  assert.equal(result.exitCode, 1);
  assert.match(result.stderr, /partial write failure/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(
    fs.readdirSync(value.directory)
      .filter((entry) => entry.startsWith(`.${path.basename(output)}.`)),
    [],
  );
});

test("checked-in reviewer schemas and templates expose the exact migrated artifact fields", () => {
  const directory = path.resolve("deployments");
  const stems = [
    "release-reviewer-roster",
    "release-reviewer-authority-genesis",
    "release-reviewer-authority-current-status-proposal",
    "release-reviewer-authority-current-status-signing-payload",
    "release-reviewer-authority-current-status",
    "release-reviewer-authority-current-status-history",
    "release-reviewer-authority-external-signatures",
    "release-reviewer-authority-genesis-acceptance-signing-payload",
    "release-reviewer-authority-genesis-acceptance",
  ];
  for (const stem of stems) {
    const schemaPath = path.join(directory, `${stem}.schema.json`);
    const templatePath = path.join(directory, `${stem}.template.json`);
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
    const template = JSON.parse(fs.readFileSync(templatePath, "utf8"));
    assert.equal(schema.additionalProperties, false, stem);
    assert.deepEqual(
      [...schema.required].sort(),
      Object.keys(schema.properties).sort(),
      `${stem} must require every declared top-level field`,
    );
    assert.deepEqual(
      Object.keys(template).sort(),
      Object.keys(schema.properties).sort(),
      `${stem} template fields must match its schema exactly`,
    );
    assert.equal(template.schema, schema.properties.schema.const, stem);
    const refs = JSON.stringify(schema).match(/(?<=\"\$ref\":\")[^\"]+/g) ?? [];
    for (const reference of refs.filter((entry) => !entry.startsWith("#"))) {
      assert.equal(
        fs.existsSync(path.resolve(directory, reference)),
        true,
        `${stem} reference must resolve: ${reference}`,
      );
    }
  }

  const readPair = (stem) => ({
    schema: JSON.parse(fs.readFileSync(path.join(directory, `${stem}.schema.json`), "utf8")),
    template: JSON.parse(fs.readFileSync(path.join(directory, `${stem}.template.json`), "utf8")),
  });
  const genesis = readPair("release-reviewer-authority-genesis");
  assert.equal(genesis.schema.properties.schema.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA);
  assert.equal(genesis.schema.properties.truth_status.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS);
  assert.equal(genesis.template.truth_status, RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS);

  const statusPayload = readPair("release-reviewer-authority-current-status-signing-payload");
  assert.equal(statusPayload.schema.properties.schema.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA);
  assert.equal(statusPayload.schema.properties.truth_status.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS);
  assert.equal(statusPayload.schema.properties.declaration.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION);
  assert.equal(statusPayload.template.truth_status, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS);
  assert.equal(statusPayload.template.declaration, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION);
  assert.deepEqual(statusPayload.schema.$defs.signature_verifier.const, PINNED_CAST_SIGNATURE_VERIFIER);
  assert.deepEqual(statusPayload.template.signature_verifier, PINNED_CAST_SIGNATURE_VERIFIER);

  const status = readPair("release-reviewer-authority-current-status");
  assert.equal(status.schema.properties.schema.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA);
  assert.equal(status.schema.properties.truth_status.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS);
  assert.equal(status.schema.properties.declaration.const, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION);
  assert.equal(status.template.truth_status, RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS);
  assert.deepEqual(status.schema.$defs.signature_verifier.const, PINNED_CAST_SIGNATURE_VERIFIER);

  const acceptancePayload = readPair("release-reviewer-authority-genesis-acceptance-signing-payload");
  assert.equal(acceptancePayload.schema.properties.schema.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA);
  assert.equal(acceptancePayload.schema.properties.truth_status.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS);
  assert.equal(acceptancePayload.schema.properties.declaration.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DECLARATION);
  assert.equal(acceptancePayload.template.truth_status, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS);
  assert.deepEqual(acceptancePayload.schema.$defs.signature_verifier.const, PINNED_CAST_SIGNATURE_VERIFIER);

  const acceptance = readPair("release-reviewer-authority-genesis-acceptance");
  assert.equal(acceptance.schema.properties.schema.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA);
  assert.equal(acceptance.schema.properties.truth_status.const, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS);
  assert.equal(acceptance.template.truth_status, RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS);
  assert.deepEqual(acceptance.schema.$defs.signature_verifier.const, PINNED_CAST_SIGNATURE_VERIFIER);

  const signatures = readPair("release-reviewer-authority-external-signatures");
  assert.deepEqual(
    [...signatures.schema.properties.purpose.enum].sort(),
    [
      RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
      RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
    ].sort(),
  );
  assert.equal(
    signatures.template.purpose,
    RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
  );
});
