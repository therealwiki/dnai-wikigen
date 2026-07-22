#!/usr/bin/env node

import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const MAX_JSON_BYTES = 4 * 1024 * 1024;
const FAULT_STAGES = new Set([
  "partial-write",
  "complete-write",
  "file-fsync",
  "publish",
  "directory-fsync",
]);
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;

function failAt(actual, expected) {
  if (actual === expected) {
    throw new Error(`injected durable-write failure at ${expected}`);
  }
}

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function assertLexicallyCanonicalAbsolute(filePath, label) {
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)) {
    throw new Error(`${label} must be absolute`);
  }
  if (path.resolve(filePath) !== filePath || path.normalize(filePath) !== filePath) {
    throw new Error(`${label} must be a lexically canonical absolute path without . or .. aliases`);
  }
  return filePath;
}

function assertCanonicalExistingPath(filePath, label) {
  assertLexicallyCanonicalAbsolute(filePath, label);
  let real;
  try {
    real = fs.realpathSync.native(filePath);
  } catch (error) {
    throw new Error(`${label} cannot be resolved: ${error.message}`);
  }
  if (real !== filePath) {
    throw new Error(`${label} must not traverse a symlink or filesystem alias`);
  }

  const root = path.parse(filePath).root;
  const relative = path.relative(root, filePath);
  let cursor = root;
  for (const component of relative.split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, component);
    const stat = fs.lstatSync(cursor);
    if (stat.isSymbolicLink()) {
      throw new Error(`${label} must not traverse a symlink`);
    }
  }
  return filePath;
}

function assertSingleLinkRegularStat(stat, label) {
  if (!stat.isFile()) {
    throw new Error(`${label} must be a non-symlink regular file`);
  }
  if (stat.nlink !== 1) {
    throw new Error(`${label} must have exactly one hard link`);
  }
  return stat;
}

function openStableRegular(filePath, label) {
  assertCanonicalExistingPath(filePath, label);
  const before = fs.lstatSync(filePath);
  if (before.isSymbolicLink()) {
    throw new Error(`${label} must be a non-symlink regular file`);
  }
  assertSingleLinkRegularStat(before, label);
  let fd;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | NOFOLLOW);
  } catch (error) {
    throw new Error(`${label} could not be opened without following links: ${error.message}`);
  }
  try {
    const opened = assertSingleLinkRegularStat(fs.fstatSync(fd), label);
    const after = fs.lstatSync(filePath);
    if (after.isSymbolicLink() || !sameInode(before, opened) || !sameInode(opened, after)) {
      throw new Error(`${label} changed while it was opened`);
    }
    return { fd, stat: opened };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function readStableJsonFile(filePath, label) {
  const opened = openStableRegular(filePath, label);
  try {
    if (opened.stat.size < 2 || opened.stat.size > MAX_JSON_BYTES) {
      throw new Error(`${label} must be between 2 and ${MAX_JSON_BYTES} bytes`);
    }
    const bytes = Buffer.alloc(opened.stat.size);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(opened.fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`${label} changed or ended during its bounded read`);
      }
      offset += count;
    }
    const after = assertSingleLinkRegularStat(fs.fstatSync(opened.fd), label);
    if (!sameInode(opened.stat, after) || after.size !== opened.stat.size) {
      throw new Error(`${label} changed during its bounded read`);
    }
    JSON.parse(bytes.toString("utf8"));
    return { bytes, stat: after };
  } finally {
    fs.closeSync(opened.fd);
  }
}

function openTrustedOutputDirectory(directoryPath) {
  assertCanonicalExistingPath(directoryPath, "durable JSON output directory");
  const before = fs.lstatSync(directoryPath);
  if (!before.isDirectory() || before.isSymbolicLink()) {
    throw new Error("durable JSON output directory must be a non-symlink directory");
  }
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (before.uid !== expectedUid) {
    throw new Error("durable JSON output directory must be owned by the current operator");
  }
  if ((before.mode & 0o022) !== 0) {
    throw new Error("durable JSON output directory must not be group- or other-writable");
  }
  const fd = fs.openSync(directoryPath, fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW);
  try {
    const opened = fs.fstatSync(fd);
    const after = fs.lstatSync(directoryPath);
    if (!opened.isDirectory() || !sameInode(before, opened) || !sameInode(opened, after)) {
      throw new Error("durable JSON output directory changed while it was opened");
    }
    return { fd, stat: opened };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function assertDirectoryStillBound(directoryPath, expected) {
  const current = fs.lstatSync(directoryPath);
  if (current.isSymbolicLink() || !current.isDirectory() || !sameInode(current, expected)) {
    throw new Error("durable JSON output directory changed before publication");
  }
  if (fs.realpathSync.native(directoryPath) !== directoryPath) {
    throw new Error("durable JSON output directory became a filesystem alias");
  }
}

function assertReplacementTargetUnchanged(outputPath, expectedStat) {
  const opened = openStableRegular(outputPath, "durable JSON replacement target");
  try {
    if (!sameInode(opened.stat, expectedStat)) {
      throw new Error("durable JSON replacement target changed before publication");
    }
  } finally {
    fs.closeSync(opened.fd);
  }
}

function writeAll(fd, bytes, faultStage) {
  let offset = 0;
  while (offset < bytes.length) {
    let length = bytes.length - offset;
    if (faultStage === "partial-write") {
      length = Math.max(1, Math.floor(length / 2));
    }
    const written = fs.writeSync(fd, bytes, offset, length, offset);
    if (!Number.isInteger(written) || written < 1) {
      throw new Error("durable JSON write made no forward progress");
    }
    offset += written;
    if (faultStage === "partial-write") {
      throw new Error("injected durable-write failure at partial-write");
    }
  }
}

function fsyncDirectoryChain(directoryPath, faultStage) {
  failAt(faultStage, "directory-fsync");
  let current = directoryPath;
  while (true) {
    assertCanonicalExistingPath(current, "durable JSON fsync directory");
    const directoryFd = fs.openSync(
      current,
      fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
    );
    try {
      if (!fs.fstatSync(directoryFd).isDirectory()) {
        throw new Error("durable JSON fsync path is not a directory");
      }
      fs.fsyncSync(directoryFd);
    } finally {
      fs.closeSync(directoryFd);
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

function safeRemoveOwnedTemporary(temporaryPath, temporaryStat) {
  if (!temporaryStat) return;
  try {
    const current = fs.lstatSync(temporaryPath);
    if (!current.isSymbolicLink() && current.isFile() && sameInode(current, temporaryStat)) {
      fs.unlinkSync(temporaryPath);
    }
  } catch (error) {
    if (error?.code !== "ENOENT") {
      // Preserve the original publication failure. Leaving a private-dir
      // orphan is safer than unlinking a path whose identity is uncertain.
    }
  }
}

/**
 * Publish canonical JSON bytes through a trusted, operator-owned directory.
 *
 * This is a local-filesystem authority primitive, not a generic arbitrary-path
 * writer. Every existing component must already be a canonical real path;
 * source and target files must be single-link regular files; and the output
 * directory must be owned by the current uid without group/other write bits.
 */
export function durablyPublishJson({
  sourcePath,
  outputPath,
  publishMode,
  fileMode,
  faultStage = null,
  // Deliberately not exposed by the CLI. It exists only to exercise the
  // pre-publish identity recheck in deterministic adversarial tests.
  testHookBeforePublish = null,
}) {
  assertLexicallyCanonicalAbsolute(sourcePath, "durable JSON source path");
  assertLexicallyCanonicalAbsolute(outputPath, "durable JSON output path");
  if (sourcePath === outputPath) {
    throw new Error("durable JSON source and output paths must be distinct");
  }
  if (publishMode !== "create" && publishMode !== "replace") {
    throw new Error("durable JSON publish mode must be create or replace");
  }
  if (!Number.isInteger(fileMode) || fileMode < 0o400 || fileMode > 0o777) {
    throw new Error("durable JSON file mode is invalid");
  }
  if (faultStage !== null && !FAULT_STAGES.has(faultStage)) {
    throw new Error("unknown durable JSON fault-injection stage");
  }
  if (testHookBeforePublish !== null && typeof testHookBeforePublish !== "function") {
    throw new Error("durable JSON test hook must be a function when supplied");
  }

  const source = readStableJsonFile(sourcePath, "durable JSON source");
  const bytes = source.bytes;
  const outputDirectory = path.dirname(outputPath);
  const directory = openTrustedOutputDirectory(outputDirectory);
  let targetStat = null;
  try {
    try {
      const existing = fs.lstatSync(outputPath);
      if (existing.isSymbolicLink()) {
        throw new Error("durable JSON output must not be a symlink");
      }
      if (publishMode === "create") {
        throw new Error("durable JSON create output already exists");
      }
      const opened = openStableRegular(outputPath, "durable JSON replacement target");
      try {
        targetStat = opened.stat;
      } finally {
        fs.closeSync(opened.fd);
      }
      if (sameInode(source.stat, targetStat)) {
        throw new Error("durable JSON source and output must not alias the same inode");
      }
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      if (publishMode === "replace") {
        throw new Error("durable JSON replacement target must already exist");
      }
    }

    const temporaryPath = path.join(
      outputDirectory,
      `.${path.basename(outputPath)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
    );
    let temporaryFd;
    let temporaryStat;
    let published = false;
    try {
      assertDirectoryStillBound(outputDirectory, directory.stat);
      temporaryFd = fs.openSync(
        temporaryPath,
        fs.constants.O_WRONLY
          | fs.constants.O_CREAT
          | fs.constants.O_EXCL
          | NOFOLLOW,
        fileMode,
      );
      temporaryStat = assertSingleLinkRegularStat(
        fs.fstatSync(temporaryFd),
        "durable JSON temporary file",
      );
      writeAll(temporaryFd, bytes, faultStage);
      failAt(faultStage, "complete-write");
      const writtenStat = assertSingleLinkRegularStat(
        fs.fstatSync(temporaryFd),
        "durable JSON temporary file",
      );
      if (!sameInode(temporaryStat, writtenStat) || writtenStat.size !== bytes.length) {
        throw new Error("durable JSON temporary file length or identity is incomplete");
      }
      fs.fchmodSync(temporaryFd, fileMode);
      failAt(faultStage, "file-fsync");
      fs.fsyncSync(temporaryFd);
      fs.closeSync(temporaryFd);
      temporaryFd = undefined;

      const written = readStableJsonFile(temporaryPath, "durable JSON temporary file");
      if (!sameInode(written.stat, temporaryStat) || !written.bytes.equals(bytes)) {
        throw new Error("durable JSON temporary bytes differ from the complete source");
      }
      failAt(faultStage, "publish");
      if (testHookBeforePublish) testHookBeforePublish();
      assertDirectoryStillBound(outputDirectory, directory.stat);

      if (publishMode === "create") {
        try {
          fs.lstatSync(outputPath);
          throw new Error("durable JSON create output appeared before publication");
        } catch (error) {
          if (error?.code !== "ENOENT") throw error;
        }
        // A hard link gives create-if-absent semantics without a rename race.
        fs.linkSync(temporaryPath, outputPath);
        fs.unlinkSync(temporaryPath);
      } else {
        assertReplacementTargetUnchanged(outputPath, targetStat);
        fs.renameSync(temporaryPath, outputPath);
      }
      published = true;

      const result = readStableJsonFile(outputPath, "durable JSON published output");
      if (!sameInode(result.stat, temporaryStat) || !result.bytes.equals(bytes)) {
        throw new Error("durable JSON published bytes or inode differ from the complete source");
      }
      if ((result.stat.mode & 0o777) !== fileMode) {
        throw new Error("durable JSON published file mode differs from the requested mode");
      }
      fsyncDirectoryChain(outputDirectory, faultStage);
      return { bytes: bytes.length, outputPath, publishMode };
    } finally {
      if (temporaryFd !== undefined) {
        try {
          fs.closeSync(temporaryFd);
        } catch {
          // Preserve the original failure.
        }
      }
      if (!published) safeRemoveOwnedTemporary(temporaryPath, temporaryStat);
    }
  } finally {
    fs.closeSync(directory.fd);
  }
}

/**
 * Remove one exact, previously committed JSON journal entry and durably commit
 * the directory mutation. The caller must provide the digest and mode it
 * already validated; an arbitrary path-only unlink is intentionally absent.
 */
export function durablyRemoveJson({
  filePath,
  expectedSha256,
  expectedMode = 0o600,
  faultStage = null,
  testHookBeforeRemove = null,
}) {
  assertLexicallyCanonicalAbsolute(filePath, "durable JSON removal path");
  if (typeof expectedSha256 !== "string" || !/^sha256:[0-9a-f]{64}$/.test(expectedSha256)) {
    throw new Error("durable JSON removal requires an exact sha256 digest");
  }
  if (!Number.isInteger(expectedMode) || expectedMode < 0o400 || expectedMode > 0o777) {
    throw new Error("durable JSON removal expected mode is invalid");
  }
  if (faultStage !== null && faultStage !== "directory-fsync") {
    throw new Error("durable JSON removal only supports directory-fsync fault injection");
  }
  if (testHookBeforeRemove !== null && typeof testHookBeforeRemove !== "function") {
    throw new Error("durable JSON removal test hook must be a function when supplied");
  }

  const directoryPath = path.dirname(filePath);
  const directory = openTrustedOutputDirectory(directoryPath);
  try {
    const opened = readStableJsonFile(filePath, "durable JSON removal target");
    const digest = `sha256:${createHash("sha256").update(opened.bytes).digest("hex")}`;
    if (digest !== expectedSha256) {
      throw new Error("durable JSON removal target digest does not match the reviewed digest");
    }
    if ((opened.stat.mode & 0o777) !== expectedMode) {
      throw new Error("durable JSON removal target mode does not match the reviewed mode");
    }
    if (testHookBeforeRemove) testHookBeforeRemove();
    assertDirectoryStillBound(directoryPath, directory.stat);
    assertReplacementTargetUnchanged(filePath, opened.stat);
    fs.unlinkSync(filePath);
    fsyncDirectoryChain(directoryPath, faultStage);
    return { bytes: opened.bytes.length, filePath, removedSha256: digest };
  } finally {
    fs.closeSync(directory.fd);
  }
}

function parseCli(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (!flag?.startsWith("--") || value === undefined || values.has(flag)) {
      throw new Error("durable JSON CLI arguments must be unique --flag value pairs");
    }
    values.set(flag, value);
  }
  const allowed = new Set(["--source", "--out", "--publish-mode", "--file-mode", "--fault-stage"]);
  for (const flag of values.keys()) {
    if (!allowed.has(flag)) throw new Error(`unknown durable JSON CLI argument: ${flag}`);
  }
  for (const required of ["--source", "--out", "--publish-mode", "--file-mode"]) {
    if (!values.has(required)) throw new Error(`missing durable JSON CLI argument: ${required}`);
  }
  const modeText = values.get("--file-mode");
  if (!/^[0-7]{3,4}$/.test(modeText)) throw new Error("file mode must be three or four octal digits");
  return {
    sourcePath: values.get("--source"),
    outputPath: values.get("--out"),
    publishMode: values.get("--publish-mode"),
    fileMode: Number.parseInt(modeText, 8),
    faultStage: values.get("--fault-stage") ?? null,
  };
}

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  try {
    const result = durablyPublishJson(parseCli(process.argv.slice(2)));
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`durable JSON publication failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}
