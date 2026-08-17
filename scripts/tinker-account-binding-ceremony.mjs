#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  reviewerSetSha256,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation,
  canonicalReleaseReviewerAuthorityGenesisArtifactText,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  assertReleaseReviewerAuthorityCurrentStatusAtTime,
  canonicalReleaseReviewerAuthorityCurrentStatusArtifactText,
  canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA,
  readStableCanonicalAuthorityJson,
} from "./release-reviewer-authority-cli.mjs";
import {
  canonicalArtifactSha256,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import { durablyPublishJson } from "./durable-json-write.mjs";
import {
  TINKER_ACCOUNT_BINDING_CHAIN_ID,
  TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
  TINKER_ACCOUNT_BINDING_SCHEMA,
  TINKER_ACCOUNT_BINDING_TYPE,
  TINKER_ACCOUNT_BINDING_TYPEHASH,
  TINKER_PROVIDER_NAMESPACE,
  TINKER_PROVIDER_NAMESPACE_LABEL,
  deriveTinkerAccountBindingRoot,
  deriveTinkerAccountCommitment,
} from "./tinker-account-binding-core.mjs";

export const TINKER_ACCOUNT_BINDING_INTENT_SCHEMA =
  "dnai.tinker-account-binding-intent.v1";
export const TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_SCHEMA =
  "dnai.tinker-account-binding-intent-receipt.v1";
export const TINKER_ACCOUNT_BINDING_EXTERNAL_SIGNATURES_SCHEMA =
  "dnai.tinker-account-binding-external-signatures.v1";
export const TINKER_ACCOUNT_BINDING_CEREMONY_SCHEMA =
  "dnai.tinker-account-binding-ceremony.v1";
export const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA =
  "dnai.tinker-account-binding-ceremony-receipt.v1";
export const TINKER_ACCOUNT_BINDING_ERROR_SCHEMA =
  "dnai.tinker-account-binding-ceremony-error.v1";
export const TINKER_ACCOUNT_BINDING_OPERATION_RECEIPT_SCHEMA =
  "dnai.tinker-account-binding-local-operation.v1";

export const TINKER_ACCOUNT_BINDING_INTENT_DOMAIN =
  "dnai-wikigen/tinker-account-binding-intent/v1\0";
export const TINKER_ACCOUNT_BINDING_INTENT_SIGNING_DOMAIN =
  "dnai-wikigen/tinker-account-binding-intent-signing/v1\0";
export const TINKER_ACCOUNT_BINDING_INTENT_SIGNING_PREFIX =
  "dnai-wikigen tinker account binding intent v1:";
export const TINKER_ACCOUNT_BINDING_REVIEWER_SIGNATURE_PURPOSE =
  "tinker_account_binding_intent_reviewer_authorization";
export const TINKER_ACCOUNT_BINDING_CEREMONY_DOMAIN =
  "dnai-wikigen/tinker-account-binding-ceremony/v1\0";
export const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_DOMAIN =
  "dnai-wikigen/tinker-account-binding-ceremony-receipt/v1\0";
export const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD =
  "tinker_account_binding_ceremony_receipt_sha256";

export const TINKER_ACCOUNT_BINDING_TRUTH_STATUS =
  "opaque_attested_account_binding_handle_not_provider_identifier_proof_requires_later_measured_provider_binding";
export const TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_TRUTH_STATUS =
  "historical_signature_replay_proves_the_signed_declared_ceremony_timestamp_was_inside_the_authenticated_status_window_not_that_the_status_is_current_now_or_that_wall_clock_signing_time_was_independently_observed";

export const TINKER_ACCOUNT_BINDING_INTENT_BASENAME =
  "tinker-account-binding-intent-core.json";
export const TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_BASENAME =
  "tinker-account-binding-intent.receipt.json";
export const TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME =
  "tinker-account-binding-ceremony.json";
export const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME =
  "tinker-account-binding-ceremony.receipt.json";

const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const SHA256 = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const BARE_SHA256 = /^(?!0{64}$)[0-9a-f]{64}$/;
const BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;
const ADDRESS = /^0x(?!0{40}$)[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const MAX_JSON_BYTES = 2 * 1024 * 1024;
const SHARE_BYTES = 32;
const SHARE_COUNT = 2;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "..");
export const TINKER_ACCOUNT_BINDING_RELEASE_DIRECTORY =
  path.join(REPOSITORY_ROOT, ".release");

const FORBIDDEN_FLAGS = new Set([
  "--account",
  "--api-key",
  "--api-token",
  "--binding-root",
  "--credential",
  "--credential-file",
  "--env",
  "--key",
  "--keystore",
  "--mnemonic",
  "--out",
  "--output",
  "--password",
  "--private-key",
  "--raw-key",
  "--root",
  "--root-base64",
  "--root-hex",
  "--rpc-url",
  "--seed",
  "--share",
  "--share-base64",
  "--share-file",
  "--share-hex",
  "--share-path",
  "--signer",
  "--signer-command",
  "--stdin",
]);

const COMMAND_SPECS = Object.freeze({
  "intent-create": Object.freeze({
    required: Object.freeze([
      "--release-sha",
      "--reviewer-genesis",
      "--genesis-acceptance",
      "--current-status",
    ]),
    optional: Object.freeze(["--status-history"]),
    shareFds: true,
  }),
  "ceremony-attach": Object.freeze({
    required: Object.freeze([
      "--reviewer-genesis",
      "--genesis-acceptance",
      "--current-status",
      "--deployment-intent",
      "--reviewer-signatures",
    ]),
    optional: Object.freeze(["--status-history"]),
    shareFds: false,
  }),
  "ceremony-verify": Object.freeze({
    required: Object.freeze([
      "--reviewer-genesis",
      "--genesis-acceptance",
      "--current-status",
      "--deployment-intent",
    ]),
    optional: Object.freeze(["--status-history"]),
    shareFds: false,
  }),
  "ceremony-check": Object.freeze({
    required: Object.freeze([
      "--reviewer-genesis",
      "--genesis-acceptance",
      "--current-status",
      "--deployment-intent",
    ]),
    optional: Object.freeze(["--status-history"]),
    shareFds: false,
  }),
});

export const TINKER_ACCOUNT_BINDING_CEREMONY_USAGE = `Usage:
  node scripts/tinker-account-binding-ceremony.mjs intent-create \\
    --release-sha SHA40 --reviewer-genesis ABSOLUTE_FILE \\
    --genesis-acceptance ABSOLUTE_FILE \\
    --current-status ABSOLUTE_FILE [--status-history ABSOLUTE_FILE] \\
    --share-fd FD --share-fd FD

  node scripts/tinker-account-binding-ceremony.mjs ceremony-attach \\
    --reviewer-genesis ABSOLUTE_FILE --genesis-acceptance ABSOLUTE_FILE \\
    --current-status ABSOLUTE_FILE \\
    [--status-history ABSOLUTE_FILE] --deployment-intent ABSOLUTE_FILE \\
    --reviewer-signatures ABSOLUTE_FILE

  node scripts/tinker-account-binding-ceremony.mjs ceremony-verify \\
    --reviewer-genesis ABSOLUTE_FILE --genesis-acceptance ABSOLUTE_FILE \\
    --current-status ABSOLUTE_FILE \\
    [--status-history ABSOLUTE_FILE] --deployment-intent ABSOLUTE_FILE

  node scripts/tinker-account-binding-ceremony.mjs ceremony-check \\
    --reviewer-genesis ABSOLUTE_FILE --genesis-acceptance ABSOLUTE_FILE \\
    --current-status ABSOLUTE_FILE \\
    [--status-history ABSOLUTE_FILE] --deployment-intent ABSOLUTE_FILE

The first command reads exactly two independently custodied, caller-opened
mode-0600 single-link 32-byte regular-file descriptors. It prints and persists
only the public commitment and reviewer-signable public evidence. It accepts no
share path, encoded share, binding root, signer credential, stdin, environment
file, RPC endpoint, or output-path override.

After intent creation, copy the public commitment into the canonical deployment
intent and TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT process environment value.
Attach, verify, and deployment-time check require both exact matches. Check is
strictly read-only; verify alone creates the final receipt.`;

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return Boolean(value)
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function exact(value, fields, label) {
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function literal(value, expected, label) {
  if (value !== expected) fail(`${label} is invalid`);
  return value;
}

function canonicalReleaseSha(value, label = "release SHA") {
  if (typeof value !== "string" || !RELEASE_SHA.test(value)) {
    fail(`${label} must be a nonzero lowercase 40-hex commit`);
  }
  return value;
}

function canonicalSha256(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    fail(`${label} must be a nonzero canonical SHA-256 digest`);
  }
  return value;
}

function canonicalBareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)) {
    fail(`${label} must be a nonzero bare lowercase SHA-256 digest`);
  }
  return value;
}

function canonicalBytes32(value, label) {
  if (typeof value !== "string" || !BYTES32.test(value)) {
    fail(`${label} must be a nonzero lowercase 0x-prefixed bytes32`);
  }
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function canonicalController(value, label) {
  if (typeof value !== "string" || !CONTROLLER.test(value)) {
    fail(`${label} must be a canonical controller ID`);
  }
  return value;
}

function canonicalInstant(value, label) {
  if (typeof value !== "string" || !INSTANT.test(value)) {
    fail(`${label} must be a canonical UTC whole-second instant`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a real canonical UTC whole-second instant`);
  }
  return { value, milliseconds };
}

function currentInstant(now) {
  const candidate = typeof now === "function" ? now() : now;
  const milliseconds = candidate instanceof Date
    ? candidate.getTime()
    : Date.parse(candidate);
  if (!Number.isFinite(milliseconds)) fail("trusted ceremony wall clock is invalid");
  return new Date(Math.floor(milliseconds / 1_000) * 1_000)
    .toISOString()
    .replace(".000Z", "Z");
}

function canonicalAbsolutePath(value, label) {
  if (typeof value !== "string"
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value
    || /[\0\r\n]/.test(value)) {
    fail(`${label} must be a canonical absolute path`);
  }
  return value;
}

function exactStatSnapshot(stat) {
  return {
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
    ctimeNs: stat.ctimeNs,
  };
}

function sameSnapshot(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readExactFd(fd, size, label) {
  const bytes = Buffer.alloc(size);
  let offset = 0;
  while (offset < bytes.length) {
    let count;
    try {
      count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
    } catch {
      fail(`${label} could not be read from its inherited descriptor`);
    }
    if (!Number.isInteger(count) || count < 1) {
      fail(`${label} changed or ended during its exact bounded read`);
    }
    offset += count;
  }
  return bytes;
}

function readPrivateShareFd(fd, slot) {
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 0x7fff_ffff) {
    fail(`private share slot ${slot} descriptor is invalid`);
  }
  let before;
  try {
    before = fs.fstatSync(fd, { bigint: true });
  } catch {
    fail(`private share slot ${slot} descriptor is not open`);
  }
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : before.uid;
  if (!before.isFile()
    || before.nlink !== 1n
    || before.uid !== expectedUid
    || (before.mode & 0o777n) !== 0o600n
    || before.size !== BigInt(SHARE_BYTES)) {
    fail(
      `private share slot ${slot} must be an operator-owned mode-0600 single-link regular file of exactly 32 bytes`,
    );
  }
  const snapshot = exactStatSnapshot(before);
  let bytes;
  try {
    bytes = readExactFd(fd, SHARE_BYTES, `private share slot ${slot}`);
    const after = fs.fstatSync(fd, { bigint: true });
    if (!sameSnapshot(snapshot, exactStatSnapshot(after))) {
      fail(`private share slot ${slot} changed during its inherited-descriptor read`);
    }
    return { bytes, stat: snapshot };
  } catch (error) {
    if (bytes) bytes.fill(0);
    throw error;
  }
}

function readPrivateShares(fds) {
  if (!Array.isArray(fds) || fds.length !== SHARE_COUNT) {
    fail("intent creation requires exactly two private share descriptors");
  }
  if (fds[0] === fds[1]) {
    fail("private share descriptors must be distinct");
  }
  const shares = [];
  try {
    for (const [index, fd] of fds.entries()) {
      shares.push(readPrivateShareFd(fd, index + 1));
    }
    if (shares[0].stat.dev === shares[1].stat.dev
      && shares[0].stat.ino === shares[1].stat.ino) {
      fail("private shares must be held in two separate files");
    }
    if (shares[0].bytes.equals(shares[1].bytes)) {
      fail("private shares must contain distinct values");
    }
    return shares.map((entry) => entry.bytes);
  } catch (error) {
    for (const share of shares) share.bytes.fill(0);
    throw error;
  }
}

function assertCanonicalReleaseDirectory(releaseDirectory) {
  const directory = canonicalAbsolutePath(
    releaseDirectory,
    "Tinker account-binding release directory",
  );
  let real;
  try {
    real = fs.realpathSync.native(directory);
  } catch {
    fail("Tinker account-binding release directory must already exist");
  }
  if (real !== directory) {
    fail("Tinker account-binding release directory must be canonical and symlink-free");
  }
  const stat = fs.lstatSync(directory, { bigint: true });
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : stat.uid;
  if (!stat.isDirectory()
    || stat.isSymbolicLink()
    || stat.uid !== expectedUid
    || (stat.mode & 0o777n) !== 0o700n) {
    fail(
      "Tinker account-binding release directory must be an operator-owned canonical mode-0700 directory",
    );
  }
  return directory;
}

export function tinkerAccountBindingArtifactPaths(
  releaseDirectory = TINKER_ACCOUNT_BINDING_RELEASE_DIRECTORY,
) {
  const directory = assertCanonicalReleaseDirectory(releaseDirectory);
  return Object.freeze({
    ceremony: path.join(directory, TINKER_ACCOUNT_BINDING_CEREMONY_BASENAME),
    ceremonyReceipt: path.join(
      directory,
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_BASENAME,
    ),
    intent: path.join(directory, TINKER_ACCOUNT_BINDING_INTENT_BASENAME),
    intentReceipt: path.join(
      directory,
      TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_BASENAME,
    ),
  });
}

function readStableCanonicalJson(filePath, label, {
  allowedModes = null,
  exactMode = null,
  maximumBytes = MAX_JSON_BYTES,
} = {}) {
  const canonicalPath = canonicalAbsolutePath(filePath, `${label} path`);
  let real;
  try {
    real = fs.realpathSync.native(canonicalPath);
  } catch {
    fail(`${label} does not exist`);
  }
  if (real !== canonicalPath) fail(`${label} must be canonical and symlink-free`);
  const named = fs.lstatSync(canonicalPath, { bigint: true });
  let fd;
  try {
    fd = fs.openSync(canonicalPath, fs.constants.O_RDONLY | NOFOLLOW);
  } catch {
    fail(`${label} could not be opened without following links`);
  }
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    const expectedUid = typeof process.geteuid === "function"
      ? BigInt(process.geteuid())
      : opened.uid;
    if (!named.isFile()
      || named.isSymbolicLink()
      || !opened.isFile()
      || named.nlink !== 1n
      || opened.nlink !== 1n
      || opened.uid !== expectedUid
      || opened.size < 2n
      || opened.size > BigInt(maximumBytes)
      || (exactMode !== null
        && (opened.mode & 0o777n) !== BigInt(exactMode))
      || (allowedModes !== null
        && !allowedModes.includes(Number(opened.mode & 0o777n)))) {
      fail(`${label} has an invalid ownership, link, mode, type, or size posture`);
    }
    const namedSnapshot = exactStatSnapshot(named);
    const openedSnapshot = exactStatSnapshot(opened);
    if (!sameSnapshot(namedSnapshot, openedSnapshot)) {
      fail(`${label} changed while its stable descriptor was opened`);
    }
    const bytes = readExactFd(fd, Number(opened.size), label);
    const after = exactStatSnapshot(fs.fstatSync(fd, { bigint: true }));
    const pathAfter = exactStatSnapshot(
      fs.lstatSync(canonicalPath, { bigint: true }),
    );
    if (!sameSnapshot(openedSnapshot, after)
      || !sameSnapshot(after, pathAfter)
      || fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      fail(`${label} changed during its stable bounded read`);
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
    fs.closeSync(fd);
  }
}

function safelyRemoveTemporary(temporaryPath, identity) {
  if (!identity) return;
  try {
    const current = fs.lstatSync(temporaryPath);
    if (current.isFile()
      && !current.isSymbolicLink()
      && current.dev === identity.dev
      && current.ino === identity.ino) {
      fs.unlinkSync(temporaryPath);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      // Preserve the primary publication error. An orphan in the private
      // release directory is safer than unlinking an identity-changed path.
    }
  }
}

function durablyCreateFixedJson(filePath, value) {
  const output = canonicalAbsolutePath(filePath, "account-binding output path");
  const releaseDirectory = assertCanonicalReleaseDirectory(path.dirname(output));
  const temporary = path.join(
    releaseDirectory,
    `.${path.basename(output)}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
  );
  let fd;
  let identity = null;
  try {
    fd = fs.openSync(
      temporary,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | NOFOLLOW,
      0o600,
    );
    identity = fs.fstatSync(fd);
    const bytes = Buffer.from(canonicalText(value), "utf8");
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(
        fd,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!Number.isInteger(count) || count < 1) {
        fail("account-binding temporary write made no forward progress");
      }
      offset += count;
    }
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    try {
      durablyPublishJson({
        fileMode: 0o600,
        outputPath: output,
        publishMode: "create",
        sourcePath: temporary,
      });
    } catch (error) {
      if (String(error?.message || "").includes("already exists")) {
        fail(
          "account-binding output already exists; create-only ceremony artifacts are never replaced",
        );
      }
      throw error;
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    safelyRemoveTemporary(temporary, identity);
  }
}

function requireOutputsAbsent(filePaths) {
  for (const filePath of filePaths) {
    try {
      fs.lstatSync(filePath);
      fail(
        "account-binding output already exists; create-only ceremony artifacts are never replaced",
      );
    } catch (error) {
      if (error instanceof TypeError) throw error;
      if (error?.code !== "ENOENT") {
        fail("account-binding output posture could not be established safely");
      }
    }
  }
}

function readStatusHistory(filePath, genesis) {
  if (!filePath) return [];
  const file = readStableCanonicalAuthorityJson(
    filePath,
    "reviewer current-status history",
  );
  const parsed = exact(
    file.value,
    ["schema", "statuses"],
    "reviewer current-status history",
  );
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_HISTORY_SCHEMA
    || !Array.isArray(parsed.statuses)) {
    fail("reviewer current-status history schema is invalid");
  }
  if (parsed.statuses.length > 0) {
    normalizeReleaseReviewerAuthorityCurrentStatus(
      parsed.statuses.at(-1),
      {
        reviewerGenesis: genesis,
        statusHistory: parsed.statuses.slice(0, -1),
      },
    );
  }
  return parsed.statuses;
}

function loadReviewerAuthority({
  currentStatusPath,
  genesisPath,
  historicalIntent = null,
  historyPath,
  now,
  requireCurrent,
}) {
  const genesisFile = readStableCanonicalAuthorityJson(
    genesisPath,
    "reviewer authority genesis",
  );
  const genesis = normalizeReleaseReviewerAuthorityGenesis(genesisFile.value);
  if (canonicalReleaseReviewerAuthorityGenesisArtifactText(genesis)
    !== genesisFile.bytes.toString("utf8")) {
    fail("reviewer authority genesis normalized bytes drifted");
  }
  const history = readStatusHistory(historyPath, genesis);
  const currentFile = readStableCanonicalAuthorityJson(
    currentStatusPath,
    "reviewer authority current status",
  );
  const latestCurrent = normalizeReleaseReviewerAuthorityCurrentStatus(
    currentFile.value,
    { reviewerGenesis: genesis, statusHistory: history },
  );
  if (canonicalReleaseReviewerAuthorityCurrentStatusArtifactText(
    latestCurrent,
    { reviewerGenesis: genesis, statusHistory: history },
  ) !== currentFile.bytes.toString("utf8")) {
    fail("reviewer authority current-status normalized bytes drifted");
  }
  const latestCurrentSha256 = releaseReviewerAuthorityCurrentStatusSha256(
    latestCurrent,
    { reviewerGenesis: genesis, statusHistory: history },
  );
  if (requireCurrent) {
    assertReleaseReviewerAuthorityCurrentStatusAtTime(
      latestCurrent,
      {
        expectedCurrentStatusEpoch: latestCurrent.epoch,
        expectedCurrentStatusSha256: latestCurrentSha256,
        now: currentInstant(now),
        reviewerGenesis: genesis,
        statusHistory: history,
      },
    );
  }
  let current = latestCurrent;
  let currentSha256 = latestCurrentSha256;
  if (historicalIntent !== null) {
    const intent = normalizeTinkerAccountBindingIntent(historicalIntent);
    const targetEpoch = intent.reviewer_authority.current_status_epoch;
    if (targetEpoch < 1 || targetEpoch > latestCurrent.epoch) {
      fail("historical account-binding reviewer status epoch is absent from the authenticated lineage");
    }
    if (targetEpoch <= history.length) {
      current = normalizeReleaseReviewerAuthorityCurrentStatus(
        history[targetEpoch - 1],
        {
          reviewerGenesis: genesis,
          statusHistory: history.slice(0, targetEpoch - 1),
        },
      );
      currentSha256 = releaseReviewerAuthorityCurrentStatusSha256(
        current,
        {
          reviewerGenesis: genesis,
          statusHistory: history.slice(0, targetEpoch - 1),
        },
      );
    } else if (targetEpoch !== latestCurrent.epoch) {
      fail("historical account-binding reviewer status lineage has an epoch gap");
    }
    if (current.epoch !== targetEpoch
      || currentSha256
        !== intent.reviewer_authority.current_status_sha256) {
      fail("historical account-binding reviewer status was substituted or forked");
    }
  }
  if (!Array.isArray(current.active_reviewers)
    || current.active_reviewers.length !== SHARE_COUNT) {
    fail(
      "Tinker account-binding ceremony requires exactly two active reviewers",
    );
  }
  const reviewers = current.active_reviewers.map((entry, index) => ({
    address: canonicalAddress(
      entry.address,
      `active reviewer ${index} address`,
    ),
    controller_id: canonicalController(
      entry.controller_id,
      `active reviewer ${index} controller`,
    ),
  }));
  for (let index = 1; index < reviewers.length; index += 1) {
    if (reviewers[index - 1].address >= reviewers[index].address) {
      fail("active reviewer identities must be strictly address-sorted");
    }
  }
  if (new Set(reviewers.map((entry) => entry.controller_id)).size
    !== reviewers.length) {
    fail("active reviewers must use distinct controllers");
  }
  const reviewerAuthority = normalizeExpectedReviewerAuthority({
    approved_reviewer_hashes: current.approved_reviewer_hashes,
    approved_reviewers: reviewers,
    reviewer_root_hash: current.reviewer_root_hash,
    reviewer_set_sha256: current.reviewer_set_sha256,
  }, {
    expectedReviewerRootHash: current.reviewer_root_hash,
    expectedReviewerSetSha256: current.reviewer_set_sha256,
  });
  return Object.freeze({
    current,
    currentSha256,
    genesis,
    genesisSha256: releaseReviewerAuthorityGenesisSha256(genesis),
    history,
    latestCurrent,
    latestCurrentSha256,
    reviewerAuthority,
    reviewers,
  });
}

function assertHistoricalCeremonyTimestamp(intent, authority) {
  const ceremony = canonicalInstant(
    intent.ceremony_timestamp,
    "signed ceremony timestamp",
  );
  const notBefore = canonicalInstant(
    authority.current.not_before,
    "reviewer status not_before",
  );
  const expiresAt = canonicalInstant(
    authority.current.expires_at,
    "reviewer status expires_at",
  );
  if (ceremony.milliseconds < notBefore.milliseconds
    || ceremony.milliseconds >= expiresAt.milliseconds) {
    fail(
      "signed ceremony timestamp is outside the authenticated reviewer status window",
    );
  }
}

function normalizeIntentReviewerAuthority(value) {
  const parsed = exact(value, [
    "current_status_epoch",
    "current_status_expires_at",
    "current_status_not_before",
    "current_status_sha256",
    "genesis_sha256",
    "reviewer_controller_set_sha256",
    "reviewer_root_hash",
    "reviewer_set_sha256",
    "reviewers",
  ], "Tinker account-binding reviewer authority");
  if (!Number.isSafeInteger(parsed.current_status_epoch)
    || parsed.current_status_epoch < 1) {
    fail("Tinker account-binding reviewer current-status epoch is invalid");
  }
  canonicalInstant(
    parsed.current_status_not_before,
    "Tinker account-binding reviewer status not_before",
  );
  canonicalInstant(
    parsed.current_status_expires_at,
    "Tinker account-binding reviewer status expires_at",
  );
  canonicalSha256(parsed.current_status_sha256, "reviewer current-status digest");
  canonicalSha256(parsed.genesis_sha256, "reviewer genesis digest");
  canonicalSha256(
    parsed.reviewer_controller_set_sha256,
    "reviewer controller-set digest",
  );
  canonicalBareSha256(parsed.reviewer_root_hash, "reviewer root hash");
  canonicalSha256(parsed.reviewer_set_sha256, "reviewer-set digest");
  if (!Array.isArray(parsed.reviewers)
    || parsed.reviewers.length !== SHARE_COUNT) {
    fail("Tinker account-binding intent requires exactly two reviewers");
  }
  const reviewers = parsed.reviewers.map((entry, index) => {
    const reviewer = exact(
      entry,
      ["address", "controller_id", "private_share_slot"],
      `Tinker account-binding reviewer ${index}`,
    );
    if (reviewer.private_share_slot !== index + 1) {
      fail("reviewer private-share slots must be canonical and contiguous");
    }
    return {
      address: canonicalAddress(
        reviewer.address,
        `Tinker account-binding reviewer ${index} address`,
      ),
      controller_id: canonicalController(
        reviewer.controller_id,
        `Tinker account-binding reviewer ${index} controller`,
      ),
      private_share_slot: reviewer.private_share_slot,
    };
  });
  for (let index = 1; index < reviewers.length; index += 1) {
    if (reviewers[index - 1].address >= reviewers[index].address) {
      fail("Tinker account-binding reviewers must be strictly address-sorted");
    }
  }
  if (new Set(reviewers.map((entry) => entry.controller_id)).size
    !== reviewers.length) {
    fail("Tinker account-binding reviewers must use distinct controllers");
  }
  return {
    current_status_epoch: parsed.current_status_epoch,
    current_status_expires_at: parsed.current_status_expires_at,
    current_status_not_before: parsed.current_status_not_before,
    current_status_sha256: parsed.current_status_sha256,
    genesis_sha256: parsed.genesis_sha256,
    reviewer_controller_set_sha256: parsed.reviewer_controller_set_sha256,
    reviewer_root_hash: parsed.reviewer_root_hash,
    reviewer_set_sha256: parsed.reviewer_set_sha256,
    reviewers,
  };
}

function normalizeBindingDescriptor(value) {
  const parsed = exact(value, [
    "chain_id",
    "commitment_type",
    "commitment_typehash",
    "hkdf_hash",
    "hkdf_info",
    "hkdf_salt_label",
    "provider_namespace",
    "provider_namespace_label",
    "scheme",
    "share_bytes",
    "share_count",
  ], "Tinker account-binding descriptor");
  literal(
    parsed.chain_id,
    Number(TINKER_ACCOUNT_BINDING_CHAIN_ID),
    "Tinker account-binding chain id",
  );
  literal(
    parsed.commitment_type,
    TINKER_ACCOUNT_BINDING_TYPE,
    "Tinker account-binding commitment type",
  );
  literal(
    parsed.commitment_typehash,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    "Tinker account-binding typehash",
  );
  literal(parsed.hkdf_hash, "sha256", "Tinker account-binding HKDF hash");
  literal(
    parsed.hkdf_info,
    "uint256_be_chain_id_then_provider_namespace_bytes32",
    "Tinker account-binding HKDF info encoding",
  );
  literal(
    parsed.hkdf_salt_label,
    TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
    "Tinker account-binding HKDF salt label",
  );
  literal(
    parsed.provider_namespace,
    TINKER_PROVIDER_NAMESPACE,
    "Tinker provider namespace",
  );
  literal(
    parsed.provider_namespace_label,
    TINKER_PROVIDER_NAMESPACE_LABEL,
    "Tinker provider namespace label",
  );
  literal(
    parsed.scheme,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    "Tinker account-binding scheme",
  );
  literal(parsed.share_bytes, SHARE_BYTES, "Tinker account-binding share size");
  literal(parsed.share_count, SHARE_COUNT, "Tinker account-binding share count");
  return { ...parsed };
}

function normalizePrivacyBoundary(value) {
  const parsed = exact(value, [
    "attested_provider_binding_required",
    "provider_identifier_committed",
    "raw_binding_root_egress",
    "raw_share_egress",
    "root_or_share_must_never_enter_rpc_or_contract_calldata",
    "same_chain_linkability_if_binding_root_reused",
    "share_generation_requirement",
    "share_or_root_digest_published",
  ], "Tinker account-binding privacy boundary");
  literal(
    parsed.attested_provider_binding_required,
    true,
    "attested provider-binding requirement",
  );
  literal(
    parsed.provider_identifier_committed,
    false,
    "provider identifier commitment claim",
  );
  literal(parsed.raw_binding_root_egress, false, "raw binding-root egress");
  literal(parsed.raw_share_egress, false, "raw share egress");
  literal(
    parsed.root_or_share_must_never_enter_rpc_or_contract_calldata,
    true,
    "private-material RPC/calldata prohibition",
  );
  literal(
    parsed.same_chain_linkability_if_binding_root_reused,
    true,
    "same-chain root-reuse linkability disclosure",
  );
  literal(
    parsed.share_generation_requirement,
    "each_reviewer_independently_generates_32_bytes_with_an_operating_system_csprng",
    "share generation requirement",
  );
  literal(
    parsed.share_or_root_digest_published,
    false,
    "share or root digest publication",
  );
  return { ...parsed };
}

export function normalizeTinkerAccountBindingIntent(value) {
  const parsed = exact(value, [
    "account_commitment",
    "binding",
    "ceremony_timestamp",
    "deployment_binding_required_before_signature_attachment",
    "privacy",
    "release_sha",
    "reviewer_authority",
    "schema",
    "truth_status",
  ], "Tinker account-binding intent");
  literal(
    parsed.schema,
    TINKER_ACCOUNT_BINDING_INTENT_SCHEMA,
    "Tinker account-binding intent schema",
  );
  literal(
    parsed.truth_status,
    TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
    "Tinker account-binding intent truth status",
  );
  literal(
    parsed.deployment_binding_required_before_signature_attachment,
    true,
    "post-intent deployment binding requirement",
  );
  const normalized = {
    account_commitment: canonicalBytes32(
      parsed.account_commitment,
      "Tinker account commitment",
    ),
    binding: normalizeBindingDescriptor(parsed.binding),
    ceremony_timestamp: canonicalInstant(
      parsed.ceremony_timestamp,
      "Tinker account-binding ceremony timestamp",
    ).value,
    deployment_binding_required_before_signature_attachment: true,
    privacy: normalizePrivacyBoundary(parsed.privacy),
    release_sha: canonicalReleaseSha(parsed.release_sha),
    reviewer_authority: normalizeIntentReviewerAuthority(
      parsed.reviewer_authority,
    ),
    schema: parsed.schema,
    truth_status: parsed.truth_status,
  };
  return Object.freeze(sorted(normalized));
}

export function tinkerAccountBindingIntentSha256(value) {
  const intent = normalizeTinkerAccountBindingIntent(value);
  return `sha256:${createHash("sha256")
    .update(TINKER_ACCOUNT_BINDING_INTENT_DOMAIN, "utf8")
    .update(canonicalText(intent), "utf8")
    .digest("hex")}`;
}

export function tinkerAccountBindingSigningPayloadSha256(value) {
  return eip191AuthorizationSigningDigest({
    domain: TINKER_ACCOUNT_BINDING_INTENT_SIGNING_DOMAIN,
    payload: normalizeTinkerAccountBindingIntent(value),
  });
}

export function tinkerAccountBindingSigningMessage(value) {
  return eip191AuthorizationSigningMessage({
    digest: tinkerAccountBindingSigningPayloadSha256(value),
    prefix: TINKER_ACCOUNT_BINDING_INTENT_SIGNING_PREFIX,
  });
}

function createIntent({
  accountCommitment,
  authority,
  releaseSha,
  timestamp,
}) {
  if (authority.genesis.release_sha !== releaseSha) {
    fail("reviewer authority genesis is for a different release SHA");
  }
  const intent = normalizeTinkerAccountBindingIntent({
    account_commitment: accountCommitment,
    binding: {
      chain_id: Number(TINKER_ACCOUNT_BINDING_CHAIN_ID),
      commitment_type: TINKER_ACCOUNT_BINDING_TYPE,
      commitment_typehash: TINKER_ACCOUNT_BINDING_TYPEHASH,
      hkdf_hash: "sha256",
      hkdf_info: "uint256_be_chain_id_then_provider_namespace_bytes32",
      hkdf_salt_label: TINKER_ACCOUNT_BINDING_ROOT_HKDF_SALT,
      provider_namespace: TINKER_PROVIDER_NAMESPACE,
      provider_namespace_label: TINKER_PROVIDER_NAMESPACE_LABEL,
      scheme: TINKER_ACCOUNT_BINDING_SCHEMA,
      share_bytes: SHARE_BYTES,
      share_count: SHARE_COUNT,
    },
    ceremony_timestamp: timestamp,
    deployment_binding_required_before_signature_attachment: true,
    privacy: {
      attested_provider_binding_required: true,
      provider_identifier_committed: false,
      raw_binding_root_egress: false,
      raw_share_egress: false,
      root_or_share_must_never_enter_rpc_or_contract_calldata: true,
      same_chain_linkability_if_binding_root_reused: true,
      share_generation_requirement:
        "each_reviewer_independently_generates_32_bytes_with_an_operating_system_csprng",
      share_or_root_digest_published: false,
    },
    release_sha: releaseSha,
    reviewer_authority: {
      current_status_epoch: authority.current.epoch,
      current_status_expires_at: authority.current.expires_at,
      current_status_not_before: authority.current.not_before,
      current_status_sha256: authority.currentSha256,
      genesis_sha256: authority.genesisSha256,
      reviewer_controller_set_sha256:
        authority.genesis.reviewer_controller_set_sha256,
      reviewer_root_hash: authority.current.reviewer_root_hash,
      reviewer_set_sha256: authority.current.reviewer_set_sha256,
      reviewers: authority.reviewers.map((reviewer, index) => ({
        ...reviewer,
        private_share_slot: index + 1,
      })),
    },
    schema: TINKER_ACCOUNT_BINDING_INTENT_SCHEMA,
    truth_status: TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
  });
  assertHistoricalCeremonyTimestamp(intent, authority);
  return intent;
}

function assertIntentMatchesAuthority(intent, authority) {
  const expected = intent.reviewer_authority;
  const actualReviewers = authority.reviewers.map((reviewer, index) => ({
    ...reviewer,
    private_share_slot: index + 1,
  }));
  if (intent.release_sha !== authority.genesis.release_sha
    || expected.current_status_epoch !== authority.current.epoch
    || expected.current_status_sha256 !== authority.currentSha256
    || expected.genesis_sha256 !== authority.genesisSha256
    || expected.reviewer_controller_set_sha256
      !== authority.genesis.reviewer_controller_set_sha256
    || expected.reviewer_root_hash !== authority.current.reviewer_root_hash
    || expected.reviewer_set_sha256 !== authority.current.reviewer_set_sha256
    || expected.current_status_not_before !== authority.current.not_before
    || expected.current_status_expires_at !== authority.current.expires_at
    || JSON.stringify(expected.reviewers) !== JSON.stringify(actualReviewers)) {
    fail("Tinker account-binding intent does not match exact reviewer authority");
  }
  assertHistoricalCeremonyTimestamp(intent, authority);
}

function createIntentReceipt(intent) {
  return Object.freeze(sorted({
    account_commitment: intent.account_commitment,
    attested_provider_binding_required: true,
    binding_chain_id: intent.binding.chain_id,
    binding_commitment_typehash: intent.binding.commitment_typehash,
    binding_scheme: intent.binding.scheme,
    eip191: {
      message: tinkerAccountBindingSigningMessage(intent),
      message_encoding: "utf8_eip191_personal_sign",
      purpose: TINKER_ACCOUNT_BINDING_REVIEWER_SIGNATURE_PURPOSE,
      signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
      signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
      signed_payload_sha256:
        tinkerAccountBindingSigningPayloadSha256(intent),
    },
    intent_sha256: tinkerAccountBindingIntentSha256(intent),
    network_request_performed: false,
    provider_namespace: intent.binding.provider_namespace,
    provider_identifier_committed: false,
    raw_binding_root_egress: false,
    raw_share_egress: false,
    remote_state_mutated: false,
    required_reviewers: intent.reviewer_authority.reviewers.map(
      ({ address, controller_id }) => ({ address, controller_id }),
    ),
    required_signature_count: SHARE_COUNT,
    release_sha: intent.release_sha,
    reviewer_authority_current_status_sha256:
      intent.reviewer_authority.current_status_sha256,
    reviewer_authority_genesis_sha256:
      intent.reviewer_authority.genesis_sha256,
    schema: TINKER_ACCOUNT_BINDING_INTENT_RECEIPT_SCHEMA,
    share_or_root_digest_published: false,
    signature_verification_subprocess_invoked: false,
    signer_credential_input_accepted: false,
    signer_subprocess_invoked: false,
    status: "ready_for_external_two_reviewer_eip191_signatures",
    truth_status: TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
  }));
}

function assertCanonicalReceiptBytes(file, expected, label) {
  const expectedBytes = canonicalText(expected);
  if (file.bytes.toString("utf8") !== expectedBytes) {
    fail(`${label} does not equal the independently recomputed canonical receipt`);
  }
}

function readFixedIntentArtifacts(paths) {
  const intentFile = readStableCanonicalJson(paths.intent, "account-binding intent", {
    exactMode: 0o600,
  });
  const intent = normalizeTinkerAccountBindingIntent(intentFile.value);
  if (canonicalText(intent) !== intentFile.bytes.toString("utf8")) {
    fail("account-binding intent normalized bytes drifted");
  }
  const receiptFile = readStableCanonicalJson(
    paths.intentReceipt,
    "account-binding intent receipt",
    { exactMode: 0o600 },
  );
  const receipt = createIntentReceipt(intent);
  assertCanonicalReceiptBytes(
    receiptFile,
    receipt,
    "account-binding intent receipt",
  );
  return { intent, intentFile, receipt, receiptFile };
}

function readDeploymentIntent(filePath) {
  const file = readStableCanonicalJson(
    filePath,
    "canonical deployment intent",
    { allowedModes: [0o444, 0o600] },
  );
  const validation = validateDeploymentIntentCore(file.value);
  if (!validation.ok) fail("canonical deployment intent failed semantic validation");
  return {
    digest: canonicalArtifactSha256(file.value),
    intent: file.value,
  };
}

function deploymentRoleSeparation(deploymentIntent) {
  return {
    deploymentRoleAddresses: [...new Set([
      deploymentIntent.deploymentControl.operatorAddress,
      deploymentIntent.staticContractInputs.diligenceRoom.governanceController,
      deploymentIntent.staticContractInputs.computeCreditVault.developer,
    ])].sort(),
    deploymentRoleControllerIds: [
      deploymentIntent.deploymentControl.controllerId,
    ],
  };
}

function authenticateReviewerGenesisAcceptance(filePath, {
  authority,
  deploymentIntent = null,
}) {
  const file = readStableCanonicalAuthorityJson(
    filePath,
    "reviewer authority genesis acceptance",
  );
  const rootEpoch =
    file.value?.reviewer_authority_current_status?.epoch;
  if (!Number.isSafeInteger(rootEpoch)
    || rootEpoch < 1
    || rootEpoch > 0xffff_ffff) {
    fail("reviewer genesis acceptance has no canonical root epoch");
  }
  if (rootEpoch !== authority.current.epoch) {
    fail(
      "reviewer genesis acceptance does not embed the exact ceremony reviewer status",
    );
  }
  const prefixLength = rootEpoch - 1;
  if (authority.history.length < prefixLength) {
    fail(
      "reviewer status history omits a predecessor before the genesis-acceptance root",
    );
  }
  const statusHistory = authority.history.slice(0, prefixLength);
  const roleSeparation = deploymentIntent === null
    ? {}
    : deploymentRoleSeparation(deploymentIntent);
  const reviewerGenesis = deploymentIntent === null
    ? authority.genesis
    : assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
      authority.genesis,
      roleSeparation,
    );
  const options = {
    reviewerGenesis,
    statusHistory,
    ...roleSeparation,
  };
  const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(
    file.value,
    options,
  );
  if (canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
    acceptance,
    options,
  ) !== file.bytes.toString("utf8")) {
    fail("reviewer authority genesis acceptance normalized bytes drifted");
  }
  const acceptanceCurrentStatusSha256 =
    releaseReviewerAuthorityCurrentStatusSha256(
      acceptance.reviewer_authority_current_status,
      {
        reviewerGenesis,
        statusHistory,
        ...roleSeparation,
      },
    );
  if (acceptanceCurrentStatusSha256 !== authority.currentSha256) {
    fail(
      "reviewer genesis acceptance does not authenticate the exact ceremony reviewer status",
    );
  }
  const acceptanceSha256 =
    releaseReviewerAuthorityGenesisAcceptanceSha256(acceptance, options);
  if (deploymentIntent !== null) {
    if (deploymentIntent.release.reviewerAuthorityCurrentStatusEpoch
        !== rootEpoch
      || deploymentIntent.release.reviewerAuthorityCurrentStatusSha256
        !== acceptanceCurrentStatusSha256
      || deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256
        !== acceptanceSha256) {
      fail(
        "reviewer genesis acceptance differs from the immutable deployment-intent pins",
      );
    }
  }
  return Object.freeze({
    acceptance,
    sha256: acceptanceSha256,
  });
}

function requireDeploymentBindings({
  authority,
  deploymentIntentPath,
  environment,
  genesisAcceptancePath,
  intent,
  requireEnvironment = true,
}) {
  const deployment = readDeploymentIntent(deploymentIntentPath);
  const deploymentIntent = deployment.intent;
  const genesisAcceptance = authenticateReviewerGenesisAcceptance(
    genesisAcceptancePath,
    { authority, deploymentIntent },
  );
  const environmentCommitment =
    environment?.TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT;
  if (requireEnvironment) {
    if (typeof environmentCommitment !== "string"
      || !BYTES32.test(environmentCommitment)) {
      fail(
        "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT must be a nonzero canonical bytes32 before signature attachment or verification",
      );
    }
    if (environmentCommitment !== intent.account_commitment) {
      fail(
        "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT does not match the account-binding intent",
      );
    }
  }
  if (deploymentIntent.release.releaseSha !== intent.release_sha
    || deploymentIntent.release.reviewerAuthorityCurrentStatusEpoch
      !== authority.current.epoch
    || deploymentIntent.release.reviewerAuthorityCurrentStatusSha256
      !== authority.currentSha256
    || deploymentIntent.staticContractInputs.tinkerAccountEncumbrance
      .accountCommitment !== intent.account_commitment) {
    fail(
      "canonical deployment intent does not match the account-binding commitment, release, and reviewer current-status authority",
    );
  }
  return Object.freeze({
    deploymentIntentSha256: deployment.digest,
    reviewerAuthorityGenesisAcceptanceSha256:
      genesisAcceptance.sha256,
  });
}

function readExternalSignatures(filePath, intent) {
  const file = readStableCanonicalAuthorityJson(
    filePath,
    "Tinker account-binding external reviewer signatures",
  );
  const parsed = exact(file.value, [
    "purpose",
    "schema",
    "signature_scheme",
    "signed_payload_sha256",
    "signatures",
  ], "Tinker account-binding external signature envelope");
  if (parsed.schema !== TINKER_ACCOUNT_BINDING_EXTERNAL_SIGNATURES_SCHEMA
    || parsed.purpose !== TINKER_ACCOUNT_BINDING_REVIEWER_SIGNATURE_PURPOSE
    || parsed.signature_scheme !== PINNED_EIP191_SIGNATURE_SCHEME
    || parsed.signed_payload_sha256
      !== tinkerAccountBindingSigningPayloadSha256(intent)
    || !Array.isArray(parsed.signatures)
    || parsed.signatures.length !== SHARE_COUNT) {
    fail("external signatures do not match the exact account-binding intent");
  }
  const signatures = parsed.signatures.map((entry, index) => {
    const normalized = exact(
      entry,
      ["address", "controller_id", "signature"],
      `Tinker account-binding signature ${index}`,
    );
    return {
      address: normalized.address,
      controller_id: normalized.controller_id,
      signature: normalized.signature,
    };
  });
  const expected = intent.reviewer_authority.reviewers.map(
    ({ address, controller_id }) => ({ address, controller_id }),
  );
  const actual = signatures.map(
    ({ address, controller_id }) => ({ address, controller_id }),
  );
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(
      "external signatures must use the exact canonical reviewer identity order",
    );
  }
  return signatures;
}

export function tinkerAccountBindingCeremonySha256(value) {
  return `sha256:${createHash("sha256")
    .update(TINKER_ACCOUNT_BINDING_CEREMONY_DOMAIN, "utf8")
    .update(
      canonicalText(normalizeCeremonyStructure(value)),
      "utf8",
    )
    .digest("hex")}`;
}

function createCeremony({
  deploymentBinding,
  intent,
  signatures,
}) {
  return Object.freeze(sorted({
    deployment_intent_sha256: deploymentBinding.deploymentIntentSha256,
    intent,
    intent_sha256: tinkerAccountBindingIntentSha256(intent),
    reviewer_authority_genesis_acceptance_sha256:
      deploymentBinding.reviewerAuthorityGenesisAcceptanceSha256,
    reviewer_signatures: signatures,
    schema: TINKER_ACCOUNT_BINDING_CEREMONY_SCHEMA,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signing_payload_sha256:
      tinkerAccountBindingSigningPayloadSha256(intent),
    truth_status: TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
  }));
}

function normalizeCeremonyStructure(value) {
  const parsed = exact(value, [
    "deployment_intent_sha256",
    "intent",
    "intent_sha256",
    "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_signatures",
    "schema",
    "signature_scheme",
    "signing_payload_sha256",
    "truth_status",
  ], "Tinker account-binding ceremony");
  literal(
    parsed.schema,
    TINKER_ACCOUNT_BINDING_CEREMONY_SCHEMA,
    "Tinker account-binding ceremony schema",
  );
  literal(
    parsed.truth_status,
    TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
    "Tinker account-binding ceremony truth status",
  );
  literal(
    parsed.signature_scheme,
    PINNED_EIP191_SIGNATURE_SCHEME,
    "Tinker account-binding ceremony signature scheme",
  );
  const intent = normalizeTinkerAccountBindingIntent(parsed.intent);
  if (parsed.intent_sha256 !== tinkerAccountBindingIntentSha256(intent)
    || parsed.signing_payload_sha256
      !== tinkerAccountBindingSigningPayloadSha256(intent)) {
    fail("Tinker account-binding ceremony intent digests are invalid");
  }
  canonicalSha256(
    parsed.deployment_intent_sha256,
    "Tinker account-binding deployment-intent digest",
  );
  canonicalSha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "reviewer genesis-acceptance digest",
  );
  if (!Array.isArray(parsed.reviewer_signatures)
    || parsed.reviewer_signatures.length !== SHARE_COUNT) {
    fail("Tinker account-binding ceremony requires exactly two signatures");
  }
  const signatures = parsed.reviewer_signatures.map((entry, index) => {
    const signature = exact(
      entry,
      ["address", "controller_id", "signature"],
      `Tinker account-binding ceremony signature ${index}`,
    );
    return {
      address: signature.address,
      controller_id: signature.controller_id,
      signature: signature.signature,
    };
  });
  return Object.freeze(sorted({
    deployment_intent_sha256: parsed.deployment_intent_sha256,
    intent,
    intent_sha256: parsed.intent_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      parsed.reviewer_authority_genesis_acceptance_sha256,
    reviewer_signatures: signatures,
    schema: parsed.schema,
    signature_scheme: parsed.signature_scheme,
    signing_payload_sha256: parsed.signing_payload_sha256,
    truth_status: parsed.truth_status,
  }));
}

export function normalizeTinkerAccountBindingCeremony(value, {
  reviewerAuthority,
  verifySignatures = true,
} = {}) {
  const ceremony = normalizeCeremonyStructure(value);
  if (verifySignatures) {
    if (!reviewerAuthority) {
      fail("Tinker account-binding signature verification requires reviewer authority");
    }
    verifyPinnedTwoSignerAuthorization({
      message: tinkerAccountBindingSigningMessage(ceremony.intent),
      reviewerAuthority,
      signatures: ceremony.reviewer_signatures,
    });
  }
  return ceremony;
}

function createCeremonyReceipt({
  ceremony,
  deploymentBinding,
  environmentMatched = true,
  verification,
  historicalReplay = false,
}) {
  const body = normalizeCeremonyReceiptBody({
    account_commitment: ceremony.intent.account_commitment,
    attested_provider_binding_required: true,
    binding_chain_id: ceremony.intent.binding.chain_id,
    binding_commitment_typehash:
      ceremony.intent.binding.commitment_typehash,
    binding_scheme: ceremony.intent.binding.scheme,
    ceremony_sha256: tinkerAccountBindingCeremonySha256(ceremony),
    deployment_intent_matched: true,
    deployment_intent_sha256: deploymentBinding.deploymentIntentSha256,
    environment_commitment_matched: environmentMatched,
    historical_replay: historicalReplay,
    intent_sha256: ceremony.intent_sha256,
    network_request_performed: false,
    provider_namespace: ceremony.intent.binding.provider_namespace,
    provider_identifier_committed: false,
    raw_binding_root_egress: false,
    raw_share_egress: false,
    remote_state_mutated: false,
    reviewer_authority_current_status_sha256:
      ceremony.intent.reviewer_authority.current_status_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      deploymentBinding.reviewerAuthorityGenesisAcceptanceSha256,
    reviewer_root_hash:
      ceremony.intent.reviewer_authority.reviewer_root_hash,
    reviewer_set_sha256:
      ceremony.intent.reviewer_authority.reviewer_set_sha256,
    schema: TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA,
    share_or_root_digest_published: false,
    signature_scheme: verification.signature_scheme,
    signature_verification_subprocess_invoked: true,
    signers: verification.signers.map((entry) => ({
      address: entry.address,
      controller_id: entry.controller_id,
      signature_sha256: entry.signature_sha256,
    })),
    status: historicalReplay
      ? "historical_tinker_account_binding_ceremony_cryptographically_replayed"
      : "tinker_account_binding_two_reviewer_ceremony_verified",
    truth_status: historicalReplay
      ? TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_TRUTH_STATUS
      : TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
    verified_signature_count: verification.signer_count,
  });
  return normalizeTinkerAccountBindingCeremonyReceipt({
    ...body,
    [TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD]:
      ceremonyReceiptBodySha256(body),
  });
}

const CEREMONY_RECEIPT_BODY_FIELDS = Object.freeze([
  "account_commitment",
  "attested_provider_binding_required",
  "binding_chain_id",
  "binding_commitment_typehash",
  "binding_scheme",
  "ceremony_sha256",
  "deployment_intent_matched",
  "deployment_intent_sha256",
  "environment_commitment_matched",
  "historical_replay",
  "intent_sha256",
  "network_request_performed",
  "provider_identifier_committed",
  "provider_namespace",
  "raw_binding_root_egress",
  "raw_share_egress",
  "remote_state_mutated",
  "reviewer_authority_current_status_sha256",
  "reviewer_authority_genesis_acceptance_sha256",
  "reviewer_root_hash",
  "reviewer_set_sha256",
  "schema",
  "share_or_root_digest_published",
  "signature_scheme",
  "signature_verification_subprocess_invoked",
  "signers",
  "status",
  "truth_status",
  "verified_signature_count",
]);

function normalizeCeremonyReceiptBody(value) {
  const parsed = exact(
    value,
    CEREMONY_RECEIPT_BODY_FIELDS,
    "Tinker account-binding ceremony receipt body",
  );
  canonicalBytes32(parsed.account_commitment, "receipt account commitment");
  literal(
    parsed.attested_provider_binding_required,
    true,
    "receipt attested provider-binding requirement",
  );
  literal(
    parsed.binding_chain_id,
    Number(TINKER_ACCOUNT_BINDING_CHAIN_ID),
    "receipt binding chain id",
  );
  literal(
    parsed.binding_commitment_typehash,
    TINKER_ACCOUNT_BINDING_TYPEHASH,
    "receipt binding typehash",
  );
  literal(
    parsed.binding_scheme,
    TINKER_ACCOUNT_BINDING_SCHEMA,
    "receipt binding scheme",
  );
  canonicalSha256(parsed.ceremony_sha256, "ceremony artifact digest");
  literal(
    parsed.deployment_intent_matched,
    true,
    "receipt deployment-intent match",
  );
  canonicalSha256(
    parsed.deployment_intent_sha256,
    "receipt deployment-intent digest",
  );
  if (typeof parsed.historical_replay !== "boolean") {
    fail("receipt historical-replay marker must be a literal boolean");
  }
  literal(
    parsed.environment_commitment_matched,
    !parsed.historical_replay,
    "receipt environment-commitment match",
  );
  canonicalSha256(parsed.intent_sha256, "receipt intent digest");
  literal(
    parsed.network_request_performed,
    false,
    "receipt network-request marker",
  );
  literal(
    parsed.provider_namespace,
    TINKER_PROVIDER_NAMESPACE,
    "receipt provider namespace",
  );
  literal(
    parsed.provider_identifier_committed,
    false,
    "receipt provider-identifier claim",
  );
  literal(parsed.raw_binding_root_egress, false, "receipt binding-root egress");
  literal(parsed.raw_share_egress, false, "receipt raw-share egress");
  literal(parsed.remote_state_mutated, false, "receipt remote-mutation marker");
  canonicalSha256(
    parsed.reviewer_authority_current_status_sha256,
    "receipt reviewer current-status digest",
  );
  canonicalSha256(
    parsed.reviewer_authority_genesis_acceptance_sha256,
    "receipt reviewer genesis-acceptance digest",
  );
  canonicalBareSha256(parsed.reviewer_root_hash, "receipt reviewer root hash");
  canonicalSha256(parsed.reviewer_set_sha256, "receipt reviewer-set digest");
  literal(
    parsed.schema,
    TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SCHEMA,
    "receipt schema",
  );
  literal(
    parsed.share_or_root_digest_published,
    false,
    "receipt share/root digest marker",
  );
  literal(
    parsed.signature_scheme,
    PINNED_EIP191_SIGNATURE_SCHEME,
    "receipt signature scheme",
  );
  literal(
    parsed.signature_verification_subprocess_invoked,
    true,
    "receipt signature-verification marker",
  );
  if (!Array.isArray(parsed.signers)
    || parsed.signers.length !== SHARE_COUNT) {
    fail("receipt requires exactly two verified signer identities");
  }
  const signers = parsed.signers.map((entry, index) => {
    const signer = exact(
      entry,
      ["address", "controller_id", "signature_sha256"],
      `receipt signer ${index}`,
    );
    return {
      address: canonicalAddress(
        signer.address,
        `receipt signer ${index} address`,
      ),
      controller_id: canonicalController(
        signer.controller_id,
        `receipt signer ${index} controller`,
      ),
      signature_sha256: canonicalSha256(
        signer.signature_sha256,
        `receipt signer ${index} signature digest`,
      ),
    };
  });
  for (let index = 1; index < signers.length; index += 1) {
    if (signers[index - 1].address >= signers[index].address) {
      fail("receipt signer identities must be strictly address-sorted");
    }
  }
  if (new Set(signers.map((entry) => entry.controller_id)).size
    !== signers.length) {
    fail("receipt signer identities must use distinct controllers");
  }
  const reviewerHashes = signers
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  if (executionPolicyReviewerRootHash(reviewerHashes)
      !== parsed.reviewer_root_hash
    || reviewerSetSha256(
      signers.map(({ address, controller_id }) => ({
        address,
        controller_id,
      })),
    ) !== parsed.reviewer_set_sha256) {
    fail("receipt signer identities do not match the reviewer root and set");
  }
  literal(
    parsed.verified_signature_count,
    SHARE_COUNT,
    "receipt verified-signature count",
  );
  const expectedStatus = parsed.historical_replay
    ? "historical_tinker_account_binding_ceremony_cryptographically_replayed"
    : "tinker_account_binding_two_reviewer_ceremony_verified";
  const expectedTruth = parsed.historical_replay
    ? TINKER_ACCOUNT_BINDING_HISTORICAL_REPLAY_TRUTH_STATUS
    : TINKER_ACCOUNT_BINDING_TRUTH_STATUS;
  literal(parsed.status, expectedStatus, "receipt status");
  literal(parsed.truth_status, expectedTruth, "receipt truth status");
  return Object.freeze(sorted({
    ...parsed,
    signers,
  }));
}

function ceremonyReceiptBodySha256(body) {
  const normalized = normalizeCeremonyReceiptBody(body);
  return `sha256:${createHash("sha256")
    .update(TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_DOMAIN, "utf8")
    .update(canonicalText(normalized), "utf8")
    .digest("hex")}`;
}

export function tinkerAccountBindingCeremonyReceiptSha256(value) {
  if (!isRecord(value)) {
    fail("Tinker account-binding ceremony receipt must be an object");
  }
  const body = Object.fromEntries(
    Object.entries(value).filter(
      ([key]) => key !== TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD,
    ),
  );
  return ceremonyReceiptBodySha256(body);
}

export function normalizeTinkerAccountBindingCeremonyReceipt(value) {
  const parsed = exact(
    value,
    [
      ...CEREMONY_RECEIPT_BODY_FIELDS,
      TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD,
    ],
    "Tinker account-binding ceremony receipt",
  );
  const body = Object.fromEntries(
    CEREMONY_RECEIPT_BODY_FIELDS.map((field) => [field, parsed[field]]),
  );
  const normalizedBody = normalizeCeremonyReceiptBody(body);
  const expected = ceremonyReceiptBodySha256(normalizedBody);
  if (parsed[TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD]
    !== expected) {
    fail("Tinker account-binding ceremony receipt digest is invalid");
  }
  return Object.freeze(sorted({
    ...normalizedBody,
    [TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256_FIELD]: expected,
  }));
}

function verifyCeremony({
  authority,
  ceremonyValue,
  deploymentIntentPath,
  environment,
  expectedIntent,
  genesisAcceptancePath,
  historicalReplay,
}) {
  const ceremony = normalizeCeremonyStructure(ceremonyValue);
  if (canonicalText(ceremony.intent) !== canonicalText(expectedIntent)) {
    fail("Tinker account-binding ceremony substituted a different intent");
  }
  assertIntentMatchesAuthority(ceremony.intent, authority);
  const deploymentBinding = requireDeploymentBindings({
    authority,
    deploymentIntentPath,
    environment,
    genesisAcceptancePath,
    intent: ceremony.intent,
    requireEnvironment: !historicalReplay,
  });
  if (ceremony.deployment_intent_sha256
      !== deploymentBinding.deploymentIntentSha256
    || ceremony.reviewer_authority_genesis_acceptance_sha256
      !== deploymentBinding.reviewerAuthorityGenesisAcceptanceSha256) {
    fail("Tinker account-binding ceremony deployment binding is invalid");
  }
  const verification = verifyPinnedTwoSignerAuthorization({
    message: tinkerAccountBindingSigningMessage(ceremony.intent),
    reviewerAuthority: authority.reviewerAuthority,
    signatures: ceremony.reviewer_signatures,
  });
  return {
    ceremony,
    deploymentBinding,
    receipt: createCeremonyReceipt({
      ceremony,
      deploymentBinding,
      environmentMatched: !historicalReplay,
      historicalReplay,
      verification,
    }),
    verification,
  };
}

export function verifyTinkerAccountBindingCeremonyArtifact({
  ceremony,
  deploymentIntent,
  environment = process.env,
  now = () => new Date(),
  reviewerCurrentStatus,
  reviewerGenesis,
  reviewerGenesisAcceptance,
  statusHistory,
}) {
  const normalized = normalizeCeremonyStructure(ceremony);
  const authority = loadReviewerAuthority({
    currentStatusPath: reviewerCurrentStatus,
    genesisPath: reviewerGenesis,
    historyPath: statusHistory,
    now,
    requireCurrent: true,
  });
  assertIntentMatchesAuthority(normalized.intent, authority);
  return verifyCeremony({
    authority,
    ceremonyValue: normalized,
    deploymentIntentPath: deploymentIntent,
    environment,
    expectedIntent: normalized.intent,
    genesisAcceptancePath: reviewerGenesisAcceptance,
    historicalReplay: false,
  });
}

export function verifyTinkerAccountBindingCeremonyHistoricalReplay({
  ceremony,
  deploymentIntent,
  environment = process.env,
  reviewerCurrentStatus,
  reviewerGenesis,
  reviewerGenesisAcceptance,
  statusHistory,
}) {
  const normalized = normalizeCeremonyStructure(ceremony);
  const authority = loadReviewerAuthority({
    currentStatusPath: reviewerCurrentStatus,
    genesisPath: reviewerGenesis,
    historicalIntent: normalized.intent,
    historyPath: statusHistory,
    now: null,
    requireCurrent: false,
  });
  assertIntentMatchesAuthority(normalized.intent, authority);
  return verifyCeremony({
    authority,
    ceremonyValue: normalized,
    deploymentIntentPath: deploymentIntent,
    environment,
    expectedIntent: normalized.intent,
    genesisAcceptancePath: reviewerGenesisAcceptance,
    historicalReplay: true,
  });
}

export function parseTinkerAccountBindingCeremonyCliArgs(argv) {
  if (!Array.isArray(argv) || argv.length < 1) fail("command is required");
  const rawCommand = String(argv[0]);
  const commandFlag = rawCommand.split("=", 1)[0];
  if (FORBIDDEN_FLAGS.has(commandFlag)) {
    fail(`forbidden credential, secret, path, or signer flag: ${commandFlag}`);
  }
  const command = rawCommand === "--help" || rawCommand === "-h"
    ? "help"
    : rawCommand;
  if (command === "help") {
    if (argv.length !== 1) fail("help does not accept operation flags");
    return Object.freeze({
      command,
      shareFds: Object.freeze([]),
      values: Object.freeze({}),
    });
  }
  const spec = COMMAND_SPECS[command];
  if (!spec) fail("unsupported command; use --help");
  const allowed = new Set([
    ...spec.required,
    ...spec.optional,
    ...(spec.shareFds ? ["--share-fd"] : []),
  ]);
  const values = {};
  const shareFds = [];
  for (let index = 1; index < argv.length; index += 1) {
    const rawFlag = String(argv[index]);
    const flag = rawFlag.split("=", 1)[0];
    if (FORBIDDEN_FLAGS.has(flag)) {
      fail(`forbidden credential, secret, path, or signer flag: ${flag}`);
    }
    if (rawFlag.includes("=")) fail(`unsupported argument: ${flag}`);
    if (!allowed.has(flag)) fail(`unsupported argument: ${flag}`);
    const value = argv[index + 1];
    if (typeof value !== "string"
      || value.length < 1
      || value.startsWith("--")) {
      fail(`required argument is missing a value: ${flag}`);
    }
    if (flag === "--share-fd") {
      if (!/^[0-9]+$/.test(value)) {
        fail("share descriptor must be a canonical decimal integer");
      }
      const descriptor = Number(value);
      if (!Number.isSafeInteger(descriptor)
        || descriptor < 3
        || descriptor > 0x7fff_ffff) {
        fail("share descriptor is outside the supported inherited-fd range");
      }
      shareFds.push(descriptor);
    } else {
      if (Object.hasOwn(values, flag)) fail(`duplicate argument: ${flag}`);
      values[flag] = value;
    }
    index += 1;
  }
  for (const flag of spec.required) {
    if (!Object.hasOwn(values, flag)) {
      fail(`required argument is missing: ${flag}`);
    }
  }
  if (spec.shareFds && shareFds.length !== SHARE_COUNT) {
    fail("intent creation requires exactly two --share-fd arguments");
  }
  if (!spec.shareFds && shareFds.length !== 0) {
    fail("this command does not accept share descriptors");
  }
  return Object.freeze({
    command,
    shareFds: Object.freeze([...shareFds]),
    values: Object.freeze({ ...values }),
  });
}

function commandAuthority(args, dependencies, { requireCurrent = true } = {}) {
  return loadReviewerAuthority({
    currentStatusPath: args["--current-status"],
    genesisPath: args["--reviewer-genesis"],
    historyPath: args["--status-history"],
    now: dependencies.now,
    requireCurrent,
  });
}

function commandResult(parsed, dependencies) {
  const args = parsed.values;
  const paths = tinkerAccountBindingArtifactPaths(
    dependencies.releaseDirectory,
  );
  switch (parsed.command) {
    case "intent-create": {
      requireOutputsAbsent([paths.intent, paths.intentReceipt]);
      const releaseSha = canonicalReleaseSha(args["--release-sha"]);
      const authority = commandAuthority(args, dependencies);
      authenticateReviewerGenesisAcceptance(
        args["--genesis-acceptance"],
        { authority },
      );
      const shares = readPrivateShares(parsed.shareFds);
      let root = null;
      let accountCommitment;
      try {
        root = deriveTinkerAccountBindingRoot(shares);
        accountCommitment = deriveTinkerAccountCommitment(root);
      } finally {
        for (const share of shares) share.fill(0);
        if (root) root.fill(0);
      }
      const timestamp = currentInstant(dependencies.now);
      const intent = createIntent({
        accountCommitment,
        authority,
        releaseSha,
        timestamp,
      });
      const receipt = createIntentReceipt(intent);
      durablyCreateFixedJson(paths.intent, intent);
      durablyCreateFixedJson(paths.intentReceipt, receipt);
      return receipt;
    }
    case "ceremony-attach": {
      requireOutputsAbsent([paths.ceremony, paths.ceremonyReceipt]);
      const authority = commandAuthority(args, dependencies);
      const { intent, receipt } = readFixedIntentArtifacts(paths);
      assertIntentMatchesAuthority(intent, authority);
      if (canonicalText(receipt) !== canonicalText(createIntentReceipt(intent))) {
        fail("account-binding intent receipt did not recompute exactly");
      }
      const deploymentBinding = requireDeploymentBindings({
        authority,
        deploymentIntentPath: args["--deployment-intent"],
        environment: dependencies.environment,
        genesisAcceptancePath: args["--genesis-acceptance"],
        intent,
      });
      const signatures = readExternalSignatures(
        args["--reviewer-signatures"],
        intent,
      );
      verifyPinnedTwoSignerAuthorization({
        message: tinkerAccountBindingSigningMessage(intent),
        reviewerAuthority: authority.reviewerAuthority,
        signatures,
      });
      const ceremony = createCeremony({
        deploymentBinding,
        intent,
        signatures,
      });
      durablyCreateFixedJson(paths.ceremony, ceremony);
      return Object.freeze(sorted({
        account_commitment: intent.account_commitment,
        ceremony_sha256: tinkerAccountBindingCeremonySha256(ceremony),
        deployment_intent_sha256:
          deploymentBinding.deploymentIntentSha256,
        network_request_performed: false,
        remote_state_mutated: false,
        schema: TINKER_ACCOUNT_BINDING_OPERATION_RECEIPT_SCHEMA,
        signature_verification_subprocess_invoked: true,
        status: "tinker_account_binding_two_reviewer_ceremony_created_pending_independent_receipt",
        truth_status: TINKER_ACCOUNT_BINDING_TRUTH_STATUS,
        verified_signature_count: SHARE_COUNT,
      }));
    }
    case "ceremony-verify":
    case "ceremony-check": {
      if (parsed.command === "ceremony-verify") {
        requireOutputsAbsent([paths.ceremonyReceipt]);
      }
      const authority = commandAuthority(args, dependencies);
      const { intent } = readFixedIntentArtifacts(paths);
      assertIntentMatchesAuthority(intent, authority);
      const ceremonyFile = readStableCanonicalJson(
        paths.ceremony,
        "account-binding ceremony",
        { exactMode: 0o600 },
      );
      const verified = verifyCeremony({
        authority,
        ceremonyValue: ceremonyFile.value,
        deploymentIntentPath: args["--deployment-intent"],
        environment: dependencies.environment,
        expectedIntent: intent,
        genesisAcceptancePath: args["--genesis-acceptance"],
        historicalReplay: false,
      });
      if (canonicalText(verified.ceremony)
        !== ceremonyFile.bytes.toString("utf8")) {
        fail("account-binding ceremony normalized bytes drifted");
      }
      if (parsed.command === "ceremony-verify") {
        durablyCreateFixedJson(paths.ceremonyReceipt, verified.receipt);
      } else {
        const receiptFile = readStableCanonicalJson(
          paths.ceremonyReceipt,
          "account-binding ceremony receipt",
          { exactMode: 0o600 },
        );
        assertCanonicalReceiptBytes(
          receiptFile,
          verified.receipt,
          "account-binding ceremony receipt",
        );
      }
      return verified.receipt;
    }
    default:
      fail("unsupported command; use --help");
  }
}

export function runTinkerAccountBindingCeremonyCli(argv, {
  environment = process.env,
  now = () => new Date(),
  releaseDirectory = TINKER_ACCOUNT_BINDING_RELEASE_DIRECTORY,
  stderr = (text) => process.stderr.write(text),
  stdout = (text) => process.stdout.write(text),
} = {}) {
  let command = "unknown";
  try {
    const parsed = parseTinkerAccountBindingCeremonyCliArgs(argv);
    command = parsed.command;
    if (parsed.command === "help") {
      stdout(`${TINKER_ACCOUNT_BINDING_CEREMONY_USAGE}\n`);
      return 0;
    }
    const result = commandResult(parsed, {
      environment,
      now,
      releaseDirectory,
    });
    stdout(canonicalText(result));
    return 0;
  } catch (error) {
    stderr(canonicalText({
      command,
      message: error instanceof Error
        ? error.message
        : "Tinker account-binding ceremony failed safely",
      schema: TINKER_ACCOUNT_BINDING_ERROR_SCHEMA,
      status: "error",
    }));
    return 1;
  }
}

if (process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  process.exitCode = runTinkerAccountBindingCeremonyCli(process.argv.slice(2));
}
