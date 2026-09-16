#!/usr/bin/env node

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  canonicalReleaseReviewerAuthorityCurrentStatusArtifactText,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import { durablyPublishJson } from "./durable-json-write.mjs";

export const RELEASE_REVIEWER_ROSTER_SCHEMA =
  "dnai.release-reviewer-roster.v2";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PROPOSAL_SCHEMA =
  "dnai.release-reviewer-authority-current-status-proposal.v1";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA =
  "dnai.release-reviewer-authority-current-status-history.v1";
export const RELEASE_REVIEWER_AUTHORITY_EXTERNAL_SIGNATURES_SCHEMA =
  "dnai.release-reviewer-authority-external-signatures.v2";
export const RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE =
  "reviewer_current_status_guardian_authorization";
export const RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE =
  "reviewer_genesis_acceptance_active_reviewer_authorization";
export const RELEASE_REVIEWER_AUTHORITY_SIGNING_DIAGNOSTIC_SCHEMA =
  "dnai.release-reviewer-authority-signing-diagnostic.v2";
export const RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA =
  "dnai.release-reviewer-authority-local-operation.v2";

const MAX_BYTES = 2 * 1024 * 1024;
const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const FORBIDDEN_FLAGS = new Set([
  "--account", "--api-key", "--api-token", "--credential",
  "--credential-file", "--env", "--key", "--keystore", "--mnemonic",
  "--password", "--private-key", "--raw-key", "--rpc-url", "--seed",
  "--signer", "--signer-command",
]);
const COMMAND_SPECS = Object.freeze({
  "genesis-init": Object.freeze({
    required: ["--release-sha", "--roster", "--out"],
    optional: [],
  }),
  "genesis-verify": Object.freeze({
    required: ["--reviewer-genesis"],
    optional: [],
  }),
  "current-status-payload": Object.freeze({
    required: ["--reviewer-genesis", "--status-proposal", "--out"],
    optional: ["--status-history"],
  }),
  "current-status-attach": Object.freeze({
    required: ["--reviewer-genesis", "--signing-payload", "--guardian-signatures", "--out"],
    optional: ["--status-history"],
  }),
  "current-status-verify": Object.freeze({
    required: ["--reviewer-genesis", "--current-status"],
    optional: ["--status-history"],
  }),
  "acceptance-payload": Object.freeze({
    required: ["--reviewer-genesis", "--current-status", "--out"],
    optional: ["--status-history"],
  }),
  "acceptance-attach": Object.freeze({
    required: [
      "--reviewer-genesis", "--current-status", "--signing-payload",
      "--reviewer-signatures", "--out",
    ],
    optional: ["--status-history"],
  }),
  "acceptance-verify": Object.freeze({
    required: ["--reviewer-genesis", "--acceptance"],
    optional: ["--status-history"],
  }),
});

export const RELEASE_REVIEWER_AUTHORITY_CLI_USAGE = `Usage:
  node scripts/release-reviewer-authority-cli.mjs genesis-init \\
    --release-sha SHA40 --roster FILE --out NEW_FILE
  node scripts/release-reviewer-authority-cli.mjs genesis-verify \\
    --reviewer-genesis FILE
  node scripts/release-reviewer-authority-cli.mjs current-status-payload \\
    --reviewer-genesis FILE --status-proposal FILE [--status-history FILE] --out NEW_FILE
  node scripts/release-reviewer-authority-cli.mjs current-status-attach \\
    --reviewer-genesis FILE --signing-payload FILE --guardian-signatures FILE \\
    [--status-history FILE] --out NEW_FILE
  node scripts/release-reviewer-authority-cli.mjs current-status-verify \\
    --reviewer-genesis FILE --current-status FILE [--status-history FILE]
  node scripts/release-reviewer-authority-cli.mjs acceptance-payload \\
    --reviewer-genesis FILE --current-status FILE [--status-history FILE] --out NEW_FILE
  node scripts/release-reviewer-authority-cli.mjs acceptance-attach \\
    --reviewer-genesis FILE --current-status FILE --signing-payload FILE \\
    --reviewer-signatures FILE [--status-history FILE] --out NEW_FILE
  node scripts/release-reviewer-authority-cli.mjs acceptance-verify \\
    --reviewer-genesis FILE --acceptance FILE [--status-history FILE]

Both genesis-pinned guardians must externally sign the current-status payload
before every guardian-selected active reviewer externally signs the full
status-bound acceptance payload. No command accepts signer credentials or
performs signing, a network request, or a remote mutation. Cryptographic
artifact verification is not current-head, fork, or time-freshness authority.
Genesis verification is structural; the sole final validator must separately
enforce guardian separation from authoritative deployment-role identities.`;

function fail(message) {
  throw new TypeError(message);
}

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

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function canonicalAbsolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || /[\0\r\n]/.test(value)) {
    fail(`${label} must be a canonical absolute path`);
  }
  return value;
}

export function parseReleaseReviewerAuthorityCliArgs(argv) {
  if (!Array.isArray(argv) || argv.length < 1) fail("command is required");
  const rawCommand = String(argv[0]);
  const commandFlag = rawCommand.split("=", 1)[0];
  if (FORBIDDEN_FLAGS.has(commandFlag)) {
    fail(`forbidden signer or credential flag: ${commandFlag}`);
  }
  const command = rawCommand === "--help" || rawCommand === "-h"
    ? "help"
    : rawCommand;
  if (command === "help") {
    if (argv.length !== 1) fail("help does not accept operation flags");
    return Object.freeze({ command, values: Object.freeze({}) });
  }
  const spec = COMMAND_SPECS[command];
  if (!spec) fail("unsupported command; use --help");
  const allowed = new Set([...spec.required, ...spec.optional]);
  const values = {};
  for (let index = 1; index < argv.length; index += 1) {
    const rawFlag = String(argv[index]);
    const flag = rawFlag.split("=", 1)[0];
    if (FORBIDDEN_FLAGS.has(flag)) fail(`forbidden signer or credential flag: ${flag}`);
    if (rawFlag.includes("=")) fail(`unsupported argument: ${flag}`);
    if (!allowed.has(flag)) fail(`unsupported argument: ${flag}`);
    if (Object.hasOwn(values, flag)) fail(`duplicate argument: ${flag}`);
    const value = argv[index + 1];
    if (typeof value !== "string" || value.length < 1 || value.startsWith("--")) {
      fail(`required argument is missing a value: ${flag}`);
    }
    values[flag] = value;
    index += 1;
  }
  for (const flag of spec.required) {
    if (!Object.hasOwn(values, flag)) fail(`required argument is missing: ${flag}`);
  }
  return Object.freeze({ command, values: Object.freeze(values) });
}

export function readStableCanonicalAuthorityJson(filePath, label) {
  const canonicalPath = canonicalAbsolutePath(filePath, `${label} path`);
  let fd;
  try {
    if (fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      fail(`${label} path must be canonical and symlink-free`);
    }
    const named = fs.lstatSync(canonicalPath, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink()) {
      fail(`${label} must be a regular canonical and symlink-free file`);
    }
    fd = fs.openSync(
      canonicalPath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const before = fs.fstatSync(fd, { bigint: true });
    const expectedUid = typeof process.geteuid === "function"
      ? BigInt(process.geteuid())
      : before.uid;
    if (!before.isFile() || before.nlink !== 1n || before.size < 2n
      || before.size > BigInt(MAX_BYTES)
      || (before.mode & 0o222n) !== 0n || before.uid !== expectedUid) {
      fail(`${label} must be operator-owned, bounded, single-link, read-only, and not writable by other principals`);
    }
    const snapshot = (stat) => ({
      dev: stat.dev,
      ino: stat.ino,
      uid: stat.uid,
      gid: stat.gid,
      mode: stat.mode,
      nlink: stat.nlink,
      size: stat.size,
      mtimeNs: stat.mtimeNs,
      ctimeNs: stat.ctimeNs,
    });
    const sameSnapshot = (left, right) => Object.keys(left)
      .every((key) => left[key] === right[key]);
    const namedSnapshot = snapshot(named);
    const beforeSnapshot = snapshot(before);
    if (!sameSnapshot(namedSnapshot, beforeSnapshot)) {
      fail(`${label} changed while opening its stable descriptor`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        fail(`${label} changed or ended during its exact bounded read`);
      }
      offset += count;
    }
    const afterSnapshot = snapshot(fs.fstatSync(fd, { bigint: true }));
    const pathAfterSnapshot = snapshot(fs.lstatSync(canonicalPath, { bigint: true }));
    if (!sameSnapshot(beforeSnapshot, afterSnapshot)
      || !sameSnapshot(afterSnapshot, pathAfterSnapshot)
      || fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      fail(`${label} changed during its opened-FD stable read`);
    }
    let value;
    try {
      value = JSON.parse(bytes.toString("utf8"));
    } catch {
      fail(`${label} is not JSON`);
    }
    if (canonicalText(value) !== bytes.toString("utf8")) {
      fail(`${label} must use canonical sorted two-space JSON`);
    }
    return Object.freeze({ bytes, value });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function durablyCreateAuthorityJson(filePath, value) {
  const output = canonicalAbsolutePath(filePath, "authority output path");
  const parent = path.dirname(output);
  if (fs.realpathSync.native(parent) !== parent) {
    fail("authority output parent must be canonical and symlink-free");
  }
  const temporary = path.join(
    parent,
    `.${path.basename(output)}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
  );
  let fd;
  let temporaryIdentity = null;
  try {
    fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL
        | (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    temporaryIdentity = fs.fstatSync(fd);
    const bytes = Buffer.from(canonicalText(value), "utf8");
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        fail("authority output temporary write made no forward progress");
      }
      offset += count;
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    try {
      durablyPublishJson({
        sourcePath: temporary,
        outputPath: output,
        publishMode: "create",
        fileMode: 0o444,
      });
    } catch (error) {
      if (String(error?.message || "").includes("already exists")) {
        fail("authority output already exists; create-new never replaces authority artifacts");
      }
      throw error;
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (temporaryIdentity) {
      try {
        const current = fs.lstatSync(temporary);
        if (current.isFile() && !current.isSymbolicLink()
          && current.dev === temporaryIdentity.dev
          && current.ino === temporaryIdentity.ino) {
          fs.unlinkSync(temporary);
        }
      } catch (error) {
        if (error?.code !== "ENOENT") {
          // Preserve the primary publication failure. A private-directory
          // orphan is safer than unlinking an identity-changed path.
        }
      }
    }
  }
}

function readGenesis(filePath) {
  const file = readStableCanonicalAuthorityJson(filePath, "reviewer genesis");
  const value = normalizeReleaseReviewerAuthorityGenesis(file.value);
  if (canonicalReleaseReviewerAuthorityGenesisArtifactText(value)
    !== file.bytes.toString("utf8")) {
    fail("reviewer genesis normalized bytes drifted");
  }
  return value;
}

function readHistory(filePath, genesis) {
  if (!filePath) return [];
  const file = readStableCanonicalAuthorityJson(filePath, "reviewer status history");
  const parsed = exact(file.value, ["schema", "statuses"], "reviewer status history");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA
    || !Array.isArray(parsed.statuses)) {
    fail("reviewer status history schema is invalid");
  }
  if (parsed.statuses.length > 0) {
    const finalIndex = parsed.statuses.length - 1;
    const normalizedFinal = normalizeReleaseReviewerAuthorityCurrentStatus(
      parsed.statuses[finalIndex],
      {
        reviewerGenesis: genesis,
        statusHistory: parsed.statuses.slice(0, finalIndex),
      },
    );
    if (canonicalText(normalizedFinal) !== canonicalText(parsed.statuses[finalIndex])) {
      fail("reviewer status history final normalized bytes drifted");
    }
  }
  // The module call above validates the complete predecessor sequence in one
  // pass. Returning the canonical raw values avoids the prior CLI loop that
  // reverified every prefix quadratically; each downstream module operation
  // will still validate the complete sequence before using it.
  return parsed.statuses;
}

function signingDiagnostic({ status, purpose, message, digest, count, extras = {} }) {
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_SIGNING_DIAGNOSTIC_SCHEMA,
    ...extras,
    eip191: {
      message,
      message_encoding: "utf8_eip191_personal_sign",
      purpose,
      signed_payload_sha256: digest,
      signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
      signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    },
    private_or_raw_key_input_accepted: false,
    required_signature_count: count,
    signer_subprocess_invoked: false,
    network_request_performed: false,
    remote_state_mutated: false,
    status,
  };
}

function readExternalSignatures(filePath, {
  purpose,
  digest,
  identities,
}) {
  const file = readStableCanonicalAuthorityJson(filePath, "external signatures");
  const parsed = exact(file.value, [
    "purpose", "schema", "signature_scheme", "signed_payload_sha256", "signatures",
  ], "external signature envelope");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_EXTERNAL_SIGNATURES_SCHEMA
    || parsed.purpose !== purpose
    || parsed.signature_scheme !== PINNED_EIP191_SIGNATURE_SCHEME
    || parsed.signed_payload_sha256 !== digest
    || !Array.isArray(parsed.signatures)) {
    fail("external signatures do not match the exact purpose/payload envelope");
  }
  const normalizedSignatures = parsed.signatures.map((entry, index) => exact(
    entry,
    ["address", "controller_id", "signature"],
    `external signature ${index}`,
  ));
  const expected = identities.map(({ address, controller_id }) => ({ address, controller_id }));
  const actual = normalizedSignatures.map((entry) => ({
    address: entry.address,
    controller_id: entry.controller_id,
  }));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail("external signatures must include every required signer in canonical required signer set order");
  }
  return normalizedSignatures.map((entry) => ({
    address: entry.address,
    controller_id: entry.controller_id,
    signature: entry.signature,
  }));
}

function receiptText(value) {
  return canonicalText(value);
}

function receiptSafety({ verificationInvoked = false } = {}) {
  return {
    private_or_raw_key_input_accepted: false,
    signer_subprocess_invoked: false,
    signature_verification_subprocess_invoked: verificationInvoked,
    network_request_performed: false,
    remote_state_mutated: false,
  };
}

function commandResult(parsed) {
  const args = parsed.values;
  switch (parsed.command) {
    case "genesis-init": {
      if (!RELEASE_SHA.test(args["--release-sha"])) fail("release SHA is invalid");
      const rosterFile = readStableCanonicalAuthorityJson(args["--roster"], "reviewer roster");
      const roster = exact(
        rosterFile.value,
        ["reviewer_controllers", "schema", "status_guardians"],
        "reviewer roster",
      );
      if (roster.schema !== RELEASE_REVIEWER_ROSTER_SCHEMA) {
        fail("reviewer roster v2 schema is required");
      }
      const guardianHashes = roster.status_guardians
        .map((entry) => executionPolicyReviewerHash(entry.address)).sort();
      const genesis = normalizeReleaseReviewerAuthorityGenesis({
        schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
        truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
        release_sha: args["--release-sha"],
        chain_id: 84_532,
        minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
        reviewer_controllers: roster.reviewer_controllers,
        reviewer_controller_set_sha256:
          reviewerControllerSetSha256(roster.reviewer_controllers),
        status_guardians: roster.status_guardians,
        status_guardian_hashes: guardianHashes,
        status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
        status_guardian_set_sha256: reviewerSetSha256(roster.status_guardians),
      });
      durablyCreateAuthorityJson(args["--out"], genesis);
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        preauthorized_reviewer_key_count: genesis.reviewer_controllers
          .reduce((sum, entry) => sum + entry.preauthorized_addresses.length, 0),
        reviewer_authority_genesis_sha256:
          releaseReviewerAuthorityGenesisSha256(genesis),
        reviewer_controller_count: genesis.reviewer_controllers.length,
        status: "reviewer_genesis_v2_created_not_self_authorizing",
        status_guardian_count: genesis.status_guardians.length,
        truth_status:
          "structural_genesis_only_deployment_role_separation_status_and_acceptance_remain_external",
        ...receiptSafety(),
      };
    }
    case "genesis-verify": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        reviewer_authority_genesis_sha256:
          releaseReviewerAuthorityGenesisSha256(genesis),
        status: "reviewer_genesis_v2_verified_not_self_authorizing",
        truth_status:
          "structural_genesis_only_deployment_role_separation_status_and_acceptance_remain_external",
        ...receiptSafety(),
      };
    }
    case "current-status-payload": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const proposalFile = readStableCanonicalAuthorityJson(
        args["--status-proposal"],
        "reviewer current-status proposal",
      );
      const proposal = exact(proposalFile.value, [
        "active_reviewers", "epoch", "expires_at", "not_before",
        "previous_status_sha256", "revoked_controller_ids",
        "revoked_reviewer_addresses", "schema",
      ], "reviewer current-status proposal");
      if (proposal.schema !== RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PROPOSAL_SCHEMA) {
        fail("reviewer current-status proposal v1 schema is required");
      }
      const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload(
        Object.fromEntries(
          Object.entries(proposal).filter(([key]) => key !== "schema"),
        ),
        { reviewerGenesis: genesis, statusHistory: history },
      );
      const digest = releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
        payload,
        { reviewerGenesis: genesis, statusHistory: history },
      );
      durablyCreateAuthorityJson(args["--out"], payload);
      return signingDiagnostic({
        status: "ready_for_external_two_guardian_eip191_signatures",
        purpose: RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
        message: releaseReviewerAuthorityCurrentStatusSigningMessage(
          payload,
          { reviewerGenesis: genesis, statusHistory: history },
        ),
        digest,
        count: 2,
        extras: {
          current_status_history_length: history.length,
          signature_verification_subprocess_invoked: history.length > 0,
          status_epoch: payload.epoch,
          truth_status:
            "unsigned_payload_not_current_status_or_release_authority",
        },
      });
    }
    case "current-status-attach": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const payload = readStableCanonicalAuthorityJson(
        args["--signing-payload"],
        "reviewer current-status signing payload",
      ).value;
      const digest = releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
        payload,
        { reviewerGenesis: genesis, statusHistory: history },
      );
      const signatures = readExternalSignatures(args["--guardian-signatures"], {
        purpose: RELEASE_REVIEWER_AUTHORITY_GUARDIAN_SIGNATURE_PURPOSE,
        digest,
        identities: genesis.status_guardians,
      });
      const status = normalizeReleaseReviewerAuthorityCurrentStatus({
        ...payload,
        schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
        signing_payload_sha256: digest,
        guardian_signatures: signatures,
      }, { reviewerGenesis: genesis, statusHistory: history });
      durablyCreateAuthorityJson(args["--out"], status);
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        reviewer_authority_current_status_sha256:
          releaseReviewerAuthorityCurrentStatusSha256(status, {
            reviewerGenesis: genesis,
            statusHistory: history,
          }),
        status: "two_guardian_current_status_cryptographically_verified_and_created",
        truth_status:
          "cryptographically_verified_status_not_independently_anchored_head_or_time_freshness",
        verified_signature_count: 2,
        ...receiptSafety({ verificationInvoked: true }),
      };
    }
    case "current-status-verify": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const status = normalizeReleaseReviewerAuthorityCurrentStatus(
        readStableCanonicalAuthorityJson(
          args["--current-status"],
          "reviewer current status",
        ).value,
        { reviewerGenesis: genesis, statusHistory: history },
      );
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        reviewer_authority_current_status_sha256:
          releaseReviewerAuthorityCurrentStatusSha256(status, {
            reviewerGenesis: genesis,
            statusHistory: history,
          }),
        status: "two_guardian_current_status_cryptographically_verified",
        truth_status:
          "cryptographically_verified_status_not_independently_anchored_head_or_time_freshness",
        ...receiptSafety({ verificationInvoked: true }),
      };
    }
    case "acceptance-payload": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
        readStableCanonicalAuthorityJson(
          args["--current-status"],
          "reviewer current status",
        ).value,
        { reviewerGenesis: genesis, statusHistory: history },
      );
      const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
        genesis,
        { reviewerCurrentStatus: currentStatus, statusHistory: history },
      );
      const options = { reviewerGenesis: genesis, statusHistory: history };
      const digest = releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        options,
      );
      durablyCreateAuthorityJson(args["--out"], payload);
      return signingDiagnostic({
        status: "ready_for_external_all_active_reviewer_eip191_signatures",
        purpose: RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
        message: releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
          payload,
          options,
        ),
        digest,
        count: currentStatus.active_reviewers.length,
        extras: {
          signature_verification_subprocess_invoked: true,
          truth_status:
            "unsigned_payload_not_genesis_acceptance_or_release_authority",
        },
      });
    }
    case "acceptance-attach": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
        readStableCanonicalAuthorityJson(
          args["--current-status"],
          "reviewer current status",
        ).value,
        { reviewerGenesis: genesis, statusHistory: history },
      );
      const payload = readStableCanonicalAuthorityJson(
        args["--signing-payload"],
        "reviewer genesis acceptance signing payload",
      ).value;
      const options = { reviewerGenesis: genesis, statusHistory: history };
      const digest = releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        options,
      );
      const signatures = readExternalSignatures(args["--reviewer-signatures"], {
        purpose: RELEASE_REVIEWER_AUTHORITY_ACCEPTANCE_SIGNATURE_PURPOSE,
        digest,
        identities: currentStatus.active_reviewers,
      });
      const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance({
        ...payload,
        schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
        signing_payload_sha256: digest,
        acceptances: signatures,
      }, options);
      if (releaseReviewerAuthorityCurrentStatusSha256(currentStatus, {
        reviewerGenesis: genesis,
        statusHistory: history,
      }) !== acceptance.reviewer_authority_current_status_sha256) {
        fail("acceptance signing payload substituted a different current status");
      }
      durablyCreateAuthorityJson(args["--out"], acceptance);
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        reviewer_authority_genesis_acceptance_sha256:
          releaseReviewerAuthorityGenesisAcceptanceSha256(acceptance, options),
        reviewer_authority_current_status_sha256:
          acceptance.reviewer_authority_current_status_sha256,
        status: "all_active_reviewer_genesis_acceptance_cryptographically_verified_and_created",
        truth_status:
          "cryptographic_acceptance_not_independently_anchored_head_or_time_freshness",
        verified_signature_count: acceptance.acceptances.length,
        ...receiptSafety({ verificationInvoked: true }),
      };
    }
    case "acceptance-verify": {
      const genesis = readGenesis(args["--reviewer-genesis"]);
      const history = readHistory(args["--status-history"], genesis);
      const options = { reviewerGenesis: genesis, statusHistory: history };
      const file = readStableCanonicalAuthorityJson(
        args["--acceptance"],
        "reviewer genesis acceptance",
      );
      const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(
        file.value,
        options,
      );
      if (canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
        acceptance,
        options,
      ) !== file.bytes.toString("utf8")) {
        fail("reviewer genesis acceptance normalized bytes drifted");
      }
      return {
        schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
        reviewer_authority_genesis_acceptance_sha256:
          releaseReviewerAuthorityGenesisAcceptanceSha256(acceptance, options),
        reviewer_authority_current_status_sha256:
          acceptance.reviewer_authority_current_status_sha256,
        status: "reviewer_genesis_acceptance_v2_cryptographically_verified",
        truth_status:
          "cryptographic_acceptance_not_independently_anchored_head_or_time_freshness",
        ...receiptSafety({ verificationInvoked: true }),
      };
    }
    default:
      fail("unsupported reviewer authority command");
  }
}

export function runReleaseReviewerAuthorityCli(argv, {
  stdout = (text) => process.stdout.write(text),
  stderr = (text) => process.stderr.write(text),
} = {}) {
  let parsed;
  try {
    parsed = parseReleaseReviewerAuthorityCliArgs(argv);
    if (parsed.command === "help") {
      stdout(`${RELEASE_REVIEWER_AUTHORITY_CLI_USAGE}\n`);
      return 0;
    }
    const receipt = commandResult(parsed);
    stdout(receiptText(receipt));
    return 0;
  } catch (error) {
    const command = (() => {
      const value = String(argv?.[0] ?? "unknown");
      const flag = value.split("=", 1)[0];
      return /^[a-z][a-z0-9-]{0,63}$/.test(flag) ? flag : "unknown";
    })();
    const message = String(error instanceof Error ? error.message : error)
      .replace(/[\r\n\t]+/g, " ")
      .replace(/0x[0-9a-fA-F]{130}/g, "[redacted-signature]")
      .replace(/0x[0-9a-fA-F]{64}/g, "[redacted-secret-like-hex]")
      .slice(0, 400);
    stderr(receiptText({
      schema: RELEASE_REVIEWER_AUTHORITY_OPERATION_RECEIPT_SCHEMA,
      status: "operation_failed",
      command: parsed?.command ?? command,
      message,
      private_or_raw_key_input_accepted: false,
      signer_subprocess_invoked: false,
      signature_verification_subprocess_invocation_status:
        "not_attested_due_to_operation_failure",
      network_request_performed: false,
      remote_state_mutated: false,
    }));
    return 1;
  }
}

if (process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runReleaseReviewerAuthorityCli(process.argv.slice(2));
}
