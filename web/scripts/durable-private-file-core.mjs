import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { randomBytes } from "node:crypto";

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const MAX_PRIVATE_FILE_BYTES = 256 * 1024;
const FAULT_STAGES = new Set(["after-write", "after-file-fsync", "before-publish"]);

function sameInode(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function canonicalAbsolute(value, label) {
  if (
    typeof value !== "string"
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value
  ) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return value;
}

function stableOwnedDirectory(directoryPath) {
  canonicalAbsolute(directoryPath, "private output directory");
  const real = fs.realpathSync.native(directoryPath);
  if (real !== directoryPath) {
    throw new Error("private output directory must not traverse a symlink or alias");
  }
  const before = fs.lstatSync(directoryPath);
  const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : before.uid;
  if (
    !before.isDirectory()
    || before.isSymbolicLink()
    || before.uid !== expectedUid
    || (before.mode & 0o022) !== 0
  ) {
    throw new Error("private output directory must be operator-owned and not group/other writable");
  }
  const fd = fs.openSync(
    directoryPath,
    fs.constants.O_RDONLY | DIRECTORY | NOFOLLOW,
  );
  const opened = fs.fstatSync(fd);
  const after = fs.lstatSync(directoryPath);
  if (!opened.isDirectory() || !sameInode(before, opened) || !sameInode(opened, after)) {
    fs.closeSync(fd);
    throw new Error("private output directory changed while opened");
  }
  return { fd, stat: opened };
}

function assertExistingTargetSafe(outputPath) {
  try {
    const metadata = fs.lstatSync(outputPath);
    const expectedUid = typeof process.geteuid === "function" ? process.geteuid() : metadata.uid;
    if (
      metadata.isSymbolicLink()
      || !metadata.isFile()
      || metadata.nlink !== 1
      || metadata.uid !== expectedUid
    ) {
      throw new Error("private output target must be an operator-owned single-link regular file");
    }
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
  }
}

function assertTargetAbsent(outputPath) {
  try {
    fs.lstatSync(outputPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error("private output target already exists and no-clobber publication was required");
}

function safeRemoveTemporary(temporaryPath, expectedStat) {
  if (!expectedStat) return;
  try {
    const current = fs.lstatSync(temporaryPath);
    if (!current.isSymbolicLink() && current.isFile() && sameInode(current, expectedStat)) {
      fs.unlinkSync(temporaryPath);
    }
  } catch {
    // Preserve the publication error. An orphan inside the private directory
    // is safer than unlinking a path whose identity can no longer be proved.
  }
}

export function durablyWritePrivateFile({
  outputPath,
  allowedOutputPath,
  content,
  faultStage = null,
  requireAbsent = false,
}) {
  canonicalAbsolute(outputPath, "private output path");
  canonicalAbsolute(allowedOutputPath, "allowed private output path");
  if (outputPath !== allowedOutputPath) {
    throw new Error("private output path is not the exact reviewed ignored path");
  }
  if (typeof content !== "string") {
    throw new Error("private output content must be text");
  }
  const bytes = Buffer.from(content, "utf8");
  if (bytes.length < 2 || bytes.length > MAX_PRIVATE_FILE_BYTES) {
    throw new Error("private output content is empty or exceeds the byte bound");
  }
  if (faultStage !== null && !FAULT_STAGES.has(faultStage)) {
    throw new Error("unknown private output fault stage");
  }
  if (typeof requireAbsent !== "boolean") {
    throw new Error("private output no-clobber policy must be boolean");
  }

  const directoryPath = path.dirname(outputPath);
  const directory = stableOwnedDirectory(directoryPath);
  let temporaryPath;
  let temporaryStat;
  let temporaryFd;
  try {
    if (requireAbsent) assertTargetAbsent(outputPath);
    else assertExistingTargetSafe(outputPath);
    temporaryPath = path.join(
      directoryPath,
      `.${path.basename(outputPath)}.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
    );
    temporaryFd = fs.openSync(
      temporaryPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      0o600,
    );
    temporaryStat = fs.fstatSync(temporaryFd);
    let offset = 0;
    while (offset < bytes.length) {
      const written = fs.writeSync(
        temporaryFd,
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!Number.isInteger(written) || written < 1) {
        throw new Error("private output write made no forward progress");
      }
      offset += written;
    }
    if (faultStage === "after-write") throw new Error("injected private output failure after-write");
    fs.fchmodSync(temporaryFd, 0o600);
    fs.fsyncSync(temporaryFd);
    if (faultStage === "after-file-fsync") {
      throw new Error("injected private output failure after-file-fsync");
    }
    const writtenStat = fs.fstatSync(temporaryFd);
    if (
      !writtenStat.isFile()
      || writtenStat.nlink !== 1
      || !sameInode(temporaryStat, writtenStat)
      || writtenStat.size !== bytes.length
    ) {
      throw new Error("private output temporary file changed or is incomplete");
    }
    fs.closeSync(temporaryFd);
    temporaryFd = undefined;

    const currentDirectory = fs.lstatSync(directoryPath);
    if (
      currentDirectory.isSymbolicLink()
      || !sameInode(currentDirectory, directory.stat)
      || fs.realpathSync.native(directoryPath) !== directoryPath
    ) {
      throw new Error("private output directory changed before publication");
    }
    if (requireAbsent) assertTargetAbsent(outputPath);
    else assertExistingTargetSafe(outputPath);
    if (faultStage === "before-publish") {
      throw new Error("injected private output failure before-publish");
    }
    if (requireAbsent) {
      // link(2) is an atomic no-clobber publication primitive. The temporary
      // name is removed before the published inode is accepted, restoring the
      // required single-link invariant.
      fs.linkSync(temporaryPath, outputPath);
      fs.unlinkSync(temporaryPath);
    } else {
      fs.renameSync(temporaryPath, outputPath);
    }
    temporaryPath = undefined;
    const published = fs.lstatSync(outputPath);
    if (
      !published.isFile()
      || published.isSymbolicLink()
      || !sameInode(published, temporaryStat)
      || published.size !== bytes.length
      || (published.mode & 0o777) !== 0o600
    ) {
      throw new Error("published private output differs from the complete private file");
    }
    fs.fsyncSync(directory.fd);
    return Object.freeze({ outputPath, bytes: bytes.length, mode: 0o600 });
  } finally {
    if (temporaryFd !== undefined) {
      try {
        fs.closeSync(temporaryFd);
      } catch {
        // Preserve the original error.
      }
    }
    if (temporaryPath) safeRemoveTemporary(temporaryPath, temporaryStat);
    fs.closeSync(directory.fd);
  }
}

export const __test = Object.freeze({
  MAX_PRIVATE_FILE_BYTES,
  FAULT_STAGES,
  assertTargetAbsent,
});
