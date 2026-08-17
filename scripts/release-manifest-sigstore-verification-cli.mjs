#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

import {
  DurableJsonPublicationIndeterminateError,
  durablyPublishJson,
} from "./durable-json-write.mjs";
import {
  MAX_RELEASE_BUNDLE_BYTES,
  MAX_RELEASE_MANIFEST_BYTES,
  RELEASE_MANIFEST_SIGSTORE_AUTHORITY,
  ReleaseManifestSigstoreVerificationError,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  releaseManifestSigstoreVerificationReceiptSha256,
  verifyReleaseManifestSigstoreAttestation,
} from "./release-manifest-sigstore-verifier.mjs";

export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_CLI_SCHEMA =
  "dnai.tee-image-release-manifest-sigstore-verification-publication.v1";
export const RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME =
  "dnai-tee-image-release-manifest-sigstore-verification.json";

const RELEASE_SHA = /^(?!0{40}$)[0-9a-f]{40}$/;
const MAX_PATH_BYTES = 4_096;
const MAX_RECEIPT_BYTES = 256 * 1024;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

export class ReleaseManifestSigstoreVerificationCliError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseManifestSigstoreVerificationCliError";
    this.code = code;
  }
}

function reject(code) {
  throw new ReleaseManifestSigstoreVerificationCliError(code);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, expected, code) {
  if (!isRecord(value)) reject(code);
  const actual = Object.keys(value).sort();
  const required = [...expected].sort();
  if (
    actual.length !== required.length
    || actual.some((key, index) => key !== required[index])
  ) {
    reject(code);
  }
  return value;
}

function canonicalAbsolutePath(value, code) {
  if (
    typeof value !== "string"
    || value.length < 1
    || Buffer.byteLength(value, "utf8") > MAX_PATH_BYTES
    || value.includes("\0")
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value
  ) {
    reject(code);
  }
  return value;
}

function sameIdentity(left, right) {
  return [
    "dev",
    "ino",
    "mode",
    "nlink",
    "uid",
    "gid",
    "size",
    "mtimeNs",
    "ctimeNs",
    "birthtimeNs",
  ].every((field) => left[field] === right[field]);
}

function sameOwnedInode(left, right) {
  return ["dev", "ino", "uid", "gid", "birthtimeNs"]
    .every((field) => left[field] === right[field]);
}

function sameDirectoryBinding(left, right) {
  // APFS changes a directory's nlink count as entries are created, so the
  // descriptor binding deliberately excludes nlink, size, mtime, and ctime.
  // Device/inode, owner, type/mode, and birth identity must remain exact.
  return ["dev", "ino", "mode", "uid", "gid", "birthtimeNs"]
    .every((field) => left[field] === right[field]);
}

function assertCanonicalRepositoryRoot(repositoryRoot) {
  canonicalAbsolutePath(repositoryRoot, "repository_root_path_invalid");
  let canonical;
  let metadata;
  try {
    canonical = fs.realpathSync.native(repositoryRoot);
    metadata = fs.lstatSync(repositoryRoot, { bigint: true });
  } catch {
    reject("repository_root_invalid");
  }
  if (
    canonical !== repositoryRoot
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
  ) {
    reject("repository_root_invalid");
  }
  return repositoryRoot;
}

export function releaseManifestSigstoreVerificationOperatorPaths(
  repositoryRoot,
) {
  const root = assertCanonicalRepositoryRoot(repositoryRoot);
  const releaseDirectory = path.join(root, ".release");
  return Object.freeze({
    repositoryRoot: root,
    releaseDirectory,
    manifestPath: path.join(
      releaseDirectory,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    ),
    bundlePath: path.join(
      releaseDirectory,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    ),
    receiptPath: path.join(
      releaseDirectory,
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
    ),
  });
}

function assertPrivateReleaseDirectory(paths) {
  let canonical;
  let before;
  try {
    canonical = fs.realpathSync.native(paths.releaseDirectory);
    before = fs.lstatSync(paths.releaseDirectory, { bigint: true });
  } catch {
    reject("release_directory_invalid");
  }
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : before.uid;
  if (
    canonical !== paths.releaseDirectory
    || !before.isDirectory()
    || before.isSymbolicLink()
    || before.uid !== expectedUid
    || (before.mode & 0o777n) !== 0o700n
  ) {
    reject("release_directory_invalid");
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      paths.releaseDirectory,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | NOFOLLOW,
    );
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const after = fs.lstatSync(paths.releaseDirectory, { bigint: true });
    if (
      !opened.isDirectory()
      || !sameIdentity(before, opened)
      || !sameIdentity(opened, after)
    ) {
      reject("release_directory_changed");
    }
    return Object.freeze({ descriptor, identity: opened });
  } catch (error) {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (error instanceof ReleaseManifestSigstoreVerificationCliError) {
      throw error;
    }
    reject("release_directory_invalid");
  }
}

function assertReleaseDirectoryUnchanged(paths, initial) {
  try {
    const current = fs.lstatSync(paths.releaseDirectory, { bigint: true });
    const opened = fs.fstatSync(initial.descriptor, { bigint: true });
    if (
      fs.realpathSync.native(paths.releaseDirectory) !== paths.releaseDirectory
      || current.isSymbolicLink()
      || !current.isDirectory()
      || !sameDirectoryBinding(initial.identity, opened)
      || !sameDirectoryBinding(opened, current)
    ) {
      reject("release_directory_changed");
    }
  } catch (error) {
    if (error instanceof ReleaseManifestSigstoreVerificationCliError) {
      throw error;
    }
    reject("release_directory_changed");
  }
}

function readStableExactFile(filePath, { label, basename, maximum }) {
  canonicalAbsolutePath(filePath, `${label}_path_invalid`);
  if (path.basename(filePath) !== basename) reject(`${label}_path_invalid`);
  let before;
  try {
    before = fs.lstatSync(filePath, { bigint: true });
    if (fs.realpathSync.native(filePath) !== filePath) {
      reject(`${label}_path_invalid`);
    }
  } catch (error) {
    if (error instanceof ReleaseManifestSigstoreVerificationCliError) {
      throw error;
    }
    reject(`${label}_read_failed`);
  }
  if (
    before.isSymbolicLink()
    || !before.isFile()
    || before.nlink !== 1n
    || before.size < 1n
    || before.size > BigInt(maximum)
  ) {
    reject(`${label}_path_invalid`);
  }

  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
    const opened = fs.fstatSync(descriptor, { bigint: true });
    if (!opened.isFile() || !sameIdentity(before, opened)) {
      reject(`${label}_changed_during_read`);
    }
    const bytes = Buffer.alloc(Number(opened.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!Number.isInteger(count) || count < 1) {
        reject(`${label}_changed_during_read`);
      }
      offset += count;
    }
    const trailing = Buffer.alloc(1);
    if (fs.readSync(descriptor, trailing, 0, 1, bytes.length) !== 0) {
      reject(`${label}_changed_during_read`);
    }
    const afterDescriptor = fs.fstatSync(descriptor, { bigint: true });
    const afterPath = fs.lstatSync(filePath, { bigint: true });
    if (
      fs.realpathSync.native(filePath) !== filePath
      || !sameIdentity(opened, afterDescriptor)
      || !sameIdentity(afterDescriptor, afterPath)
    ) {
      reject(`${label}_changed_during_read`);
    }
    return Object.freeze({
      sha256: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
      identity: afterDescriptor,
    });
  } catch (error) {
    if (error instanceof ReleaseManifestSigstoreVerificationCliError) {
      throw error;
    }
    reject(`${label}_read_failed`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function assertSourceSnapshotsUnchanged(paths, manifest, bundle) {
  const currentManifest = readStableExactFile(paths.manifestPath, {
    label: "release_manifest",
    basename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    maximum: MAX_RELEASE_MANIFEST_BYTES,
  });
  const currentBundle = readStableExactFile(paths.bundlePath, {
    label: "release_bundle",
    basename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    maximum: MAX_RELEASE_BUNDLE_BYTES,
  });
  if (
    currentManifest.sha256 !== manifest.sha256
    || currentBundle.sha256 !== bundle.sha256
    || !sameIdentity(currentManifest.identity, manifest.identity)
    || !sameIdentity(currentBundle.identity, bundle.identity)
  ) {
    reject("release_inputs_changed_before_publication");
  }
}

function assertOutputAbsent(receiptPath) {
  try {
    fs.lstatSync(receiptPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    reject("release_receipt_target_check_failed");
  }
  // A create-only target may be residue from an interrupted prior publication.
  // Never describe an unreviewed survivor as a safe, definite precondition
  // failure: it is quarantined for explicit operator recovery.
  reject("release_receipt_publication_indeterminate");
}

function writePrivateStagingFile(directory, text) {
  const filePath = path.join(
    directory,
    `.${RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME}.${process.pid}.${randomBytes(16).toString("hex")}.tmp`,
  );
  const bytes = Buffer.from(text, "utf8");
  let descriptor;
  let identity;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_WRONLY
        | fs.constants.O_CREAT
        | fs.constants.O_EXCL
        | NOFOLLOW,
      0o600,
    );
    identity = fs.fstatSync(descriptor, { bigint: true });
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(
        descriptor,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!Number.isInteger(count) || count < 1) {
        reject("release_receipt_staging_failed");
      }
      offset += count;
    }
    fs.fchmodSync(descriptor, 0o600);
    fs.fsyncSync(descriptor);
    const written = fs.fstatSync(descriptor, { bigint: true });
    if (
      !written.isFile()
      || written.nlink !== 1n
      || !sameOwnedInode(identity, written)
      || written.size !== BigInt(bytes.length)
      || (written.mode & 0o777n) !== 0o600n
    ) {
      reject("release_receipt_staging_failed");
    }
    identity = written;
    fs.closeSync(descriptor);
    descriptor = undefined;
    if (fs.realpathSync.native(filePath) !== filePath) {
      reject("release_receipt_staging_failed");
    }
    return Object.freeze({ filePath, identity });
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {
        // Preserve the original failure.
      }
    }
    safeRemoveStagingFile({ filePath, identity });
    if (error instanceof ReleaseManifestSigstoreVerificationCliError) {
      throw error;
    }
    reject("release_receipt_staging_failed");
  }
}

function safeRemoveStagingFile(staging) {
  if (!staging?.filePath || !staging.identity) return;
  try {
    const current = fs.lstatSync(staging.filePath, { bigint: true });
    if (
      !current.isSymbolicLink()
      && current.isFile()
      && current.nlink === 1n
      && sameOwnedInode(current, staging.identity)
    ) {
      fs.unlinkSync(staging.filePath);
    }
  } catch {
    // Preserve the publication error. An uncertain private-directory orphan is
    // safer than unlinking a path whose inode is no longer ours.
  }
}

function stagingPathIsAbsent(filePath) {
  try {
    fs.lstatSync(filePath);
    return false;
  } catch (error) {
    if (error?.code === "ENOENT") return true;
    throw error;
  }
}

function durablyRemoveOwnedStagingFile(paths, releaseDirectory, staging) {
  if (!staging?.filePath || !staging.identity) {
    reject("release_receipt_staging_cleanup_failed");
  }

  let descriptor;
  let failed = false;
  try {
    assertReleaseDirectoryUnchanged(paths, releaseDirectory);
    const before = fs.lstatSync(staging.filePath, { bigint: true });
    if (
      before.isSymbolicLink()
      || !before.isFile()
      || fs.realpathSync.native(staging.filePath) !== staging.filePath
      || !sameIdentity(staging.identity, before)
    ) {
      throw new Error("staging identity changed before cleanup");
    }
    descriptor = fs.openSync(
      staging.filePath,
      fs.constants.O_RDONLY | NOFOLLOW,
    );
    const opened = fs.fstatSync(descriptor, { bigint: true });
    const bound = fs.lstatSync(staging.filePath, { bigint: true });
    if (
      !opened.isFile()
      || bound.isSymbolicLink()
      || !sameIdentity(staging.identity, opened)
      || !sameIdentity(opened, bound)
    ) {
      throw new Error("staging identity changed while opening for cleanup");
    }

    fs.unlinkSync(staging.filePath);
    const unlinked = fs.fstatSync(descriptor, { bigint: true });
    if (
      !unlinked.isFile()
      || unlinked.nlink !== 0n
      || !sameOwnedInode(opened, unlinked)
      || unlinked.size !== opened.size
      || (unlinked.mode & 0o777n) !== 0o600n
      || !stagingPathIsAbsent(staging.filePath)
    ) {
      throw new Error("exact staging inode was not removed");
    }

    // The durable writer's successful directory sync committed the staging
    // name as well as the receipt. Commit its exact unlink before success can
    // escape, using the already-authenticated .release directory descriptor.
    fs.fsyncSync(releaseDirectory.descriptor);
    assertReleaseDirectoryUnchanged(paths, releaseDirectory);
    if (!stagingPathIsAbsent(staging.filePath)) {
      throw new Error("staging path reappeared after cleanup commit");
    }
  } catch {
    failed = true;
  }
  if (descriptor !== undefined) {
    try {
      fs.closeSync(descriptor);
    } catch {
      failed = true;
    }
  }
  if (failed) reject("release_receipt_staging_cleanup_failed");
}

function rawSha256(text) {
  return `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`;
}

function publicationTargetExists(receiptPath) {
  try {
    fs.lstatSync(receiptPath);
    return true;
  } catch (error) {
    return error?.code !== "ENOENT";
  }
}

function persistProductionReleaseManifestSigstoreVerificationReceipt(
  input,
) {
  const normalizedInput = exactKeys(
    input,
    ["repositoryRoot", "expectedReleaseSha", "receipt"],
    "receipt_persistence_input_fields_invalid",
  );
  const expectedReleaseSha = normalizeReleaseSha(
    normalizedInput.expectedReleaseSha,
  );
  const paths = releaseManifestSigstoreVerificationOperatorPaths(
    normalizedInput.repositoryRoot,
  );
  const receipt = assertProductionReleaseManifestSigstoreVerificationReceipt(
    normalizedInput.receipt,
  );
  if (receipt.release_sha !== expectedReleaseSha) {
    reject("release_receipt_release_sha_mismatch");
  }
  const canonicalText =
    canonicalReleaseManifestSigstoreVerificationReceiptText(receipt);
  const releaseDirectory = assertPrivateReleaseDirectory(paths);
  let staging;
  let result;
  let failure;
  try {
    assertOutputAbsent(paths.receiptPath);
    const manifest = readStableExactFile(paths.manifestPath, {
      label: "release_manifest",
      basename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
      maximum: MAX_RELEASE_MANIFEST_BYTES,
    });
    const bundle = readStableExactFile(paths.bundlePath, {
      label: "release_bundle",
      basename: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
      maximum: MAX_RELEASE_BUNDLE_BYTES,
    });
    if (
      receipt.release_manifest_sha256 !== manifest.sha256
      || receipt.release_manifest_sigstore_bundle_sha256 !== bundle.sha256
    ) {
      reject("release_receipt_source_digest_mismatch");
    }
    assertReleaseDirectoryUnchanged(paths, releaseDirectory);
    staging = writePrivateStagingFile(paths.releaseDirectory, canonicalText);
    assertSourceSnapshotsUnchanged(paths, manifest, bundle);
    assertReleaseDirectoryUnchanged(paths, releaseDirectory);
    try {
      durablyPublishJson({
        sourcePath: staging.filePath,
        outputPath: paths.receiptPath,
        publishMode: "create",
        fileMode: 0o600,
      });
    } catch (error) {
      reject(
        error instanceof DurableJsonPublicationIndeterminateError
        || publicationTargetExists(paths.receiptPath)
        ? "release_receipt_publication_indeterminate"
        : "release_receipt_publication_failed",
      );
    }
    try {
      const published = readStableExactFile(paths.receiptPath, {
        label: "release_receipt",
        basename: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
        maximum: MAX_RECEIPT_BYTES,
      });
      if (
        (published.identity.mode & 0o777n) !== 0o600n
        || published.sha256 !== rawSha256(canonicalText)
      ) {
        reject("release_receipt_publication_indeterminate");
      }
      assertSourceSnapshotsUnchanged(paths, manifest, bundle);
      assertReleaseDirectoryUnchanged(paths, releaseDirectory);
    } catch {
      reject("release_receipt_publication_indeterminate");
    }
    result = Object.freeze({
      schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_CLI_SCHEMA,
      status: "persisted_no_clobber_mode_0600",
      release_sha: receipt.release_sha,
      release_manifest_sha256: receipt.release_manifest_sha256,
      release_manifest_sigstore_bundle_sha256:
        receipt.release_manifest_sigstore_bundle_sha256,
      receipt_sha256:
        releaseManifestSigstoreVerificationReceiptSha256(receipt),
      receipt_artifact_file_sha256: rawSha256(canonicalText),
    });
  } catch (error) {
    failure = error;
  }

  let finalizationFailed = false;
  if (staging) {
    try {
      durablyRemoveOwnedStagingFile(paths, releaseDirectory, staging);
    } catch {
      finalizationFailed = true;
    }
  } else if (result !== undefined) {
    finalizationFailed = true;
  }
  try {
    fs.closeSync(releaseDirectory.descriptor);
  } catch {
    finalizationFailed = true;
  }

  if (finalizationFailed) {
    if (
      result !== undefined
      || failure instanceof DurableJsonPublicationIndeterminateError
      || failure?.code === "release_receipt_publication_indeterminate"
      || publicationTargetExists(paths.receiptPath)
    ) {
      failure = new ReleaseManifestSigstoreVerificationCliError(
        "release_receipt_publication_indeterminate",
      );
    } else {
      failure = new ReleaseManifestSigstoreVerificationCliError(
        "release_receipt_staging_cleanup_failed",
      );
    }
  }
  if (failure) throw failure;
  return result;
}

function normalizeReleaseSha(value) {
  if (typeof value !== "string" || !RELEASE_SHA.test(value)) {
    reject("expected_release_sha_invalid");
  }
  return value;
}

export async function produceReleaseManifestSigstoreVerificationReceipt(
  input,
  ...forbiddenAdapters
) {
  if (forbiddenAdapters.length !== 0) {
    reject("production_adapter_injection_forbidden");
  }
  const normalizedInput = exactKeys(
    input,
    ["repositoryRoot", "expectedReleaseSha"],
    "producer_input_fields_invalid",
  );
  const expectedReleaseSha = normalizeReleaseSha(
    normalizedInput.expectedReleaseSha,
  );
  const paths = releaseManifestSigstoreVerificationOperatorPaths(
    normalizedInput.repositoryRoot,
  );
  const receipt = await verifyReleaseManifestSigstoreAttestation({
    manifestPath: paths.manifestPath,
    bundlePath: paths.bundlePath,
    expectedReleaseSha,
  });
  return persistProductionReleaseManifestSigstoreVerificationReceipt({
    repositoryRoot: paths.repositoryRoot,
    expectedReleaseSha,
    receipt,
  });
}

export function releaseManifestSigstoreVerificationCliUsage() {
  return [
    "Usage:",
    "  node scripts/release-manifest-sigstore-verification-cli.mjs \\",
    "    --repository-root /canonical/absolute/repository/path \\",
    "    --release-sha <40-lowercase-hex-git-sha>",
    "",
    "The command reads only the exact manifest and bundle filenames in the",
    "repository's existing operator-owned 0700 .release directory, verifies",
    "them with the source-pinned gh/Sigstore policy, and creates the exact",
    "activation-preflight receipt as a no-clobber mode-0600 file.",
  ].join("\n");
}

export function parseReleaseManifestSigstoreVerificationCliArgs(argv) {
  if (!Array.isArray(argv)) reject("cli_arguments_invalid");
  if (argv.length === 1 && argv[0] === "--help") {
    return Object.freeze({ help: true });
  }
  if (argv.includes("--help")) reject("cli_arguments_invalid");
  if (argv.length % 2 !== 0) reject("cli_arguments_invalid");
  const allowed = new Set(["--repository-root", "--release-sha"]);
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(flag)) reject("cli_argument_unknown");
    if (values.has(flag)) reject("cli_argument_duplicate");
    if (typeof value !== "string" || value.startsWith("--")) {
      reject("cli_argument_value_invalid");
    }
    values.set(flag, value);
  }
  if (!values.has("--repository-root") || !values.has("--release-sha")) {
    reject("cli_argument_missing");
  }
  return Object.freeze({
    help: false,
    repositoryRoot: values.get("--repository-root"),
    expectedReleaseSha: normalizeReleaseSha(values.get("--release-sha")),
  });
}

function safeErrorCode(error) {
  if (
    error instanceof ReleaseManifestSigstoreVerificationCliError
    || error instanceof ReleaseManifestSigstoreVerificationError
  ) {
    return error.code;
  }
  return "release_manifest_sigstore_verification_cli_failed";
}

export async function runReleaseManifestSigstoreVerificationCli(argv) {
  const parsed = parseReleaseManifestSigstoreVerificationCliArgs(argv);
  if (parsed.help) {
    return Object.freeze({ help: true, output: releaseManifestSigstoreVerificationCliUsage() });
  }
  const result = await produceReleaseManifestSigstoreVerificationReceipt({
    repositoryRoot: parsed.repositoryRoot,
    expectedReleaseSha: parsed.expectedReleaseSha,
  });
  return Object.freeze({ help: false, output: `${JSON.stringify(result)}\n` });
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;

if (isMain) {
  try {
    const result = await runReleaseManifestSigstoreVerificationCli(
      process.argv.slice(2),
    );
    process.stdout.write(result.help ? `${result.output}\n` : result.output);
  } catch (error) {
    process.stderr.write(
      `release manifest Sigstore receipt production failed: ${safeErrorCode(error)}\n`,
    );
    process.exitCode = 1;
  }
}
