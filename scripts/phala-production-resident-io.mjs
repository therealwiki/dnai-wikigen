import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  readPhalaPinnedPrivateFile,
} from "./phala-pinned-private-directory.mjs";

const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const MAXIMUM_JSON_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

export const PHALA_PRODUCTION_RESIDENT_MAXIMUM_JSON_BYTES =
  MAXIMUM_JSON_BYTES;

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function exactResidentRecord(value, fields, label) {
  if (!isRecord(value) || Object.getPrototypeOf(value) !== Object.prototype
    || Object.getOwnPropertySymbols(value).length !== 0
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    throw new Error(`${label} fields do not match the exact schema`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.values(descriptors).some((descriptor) => (
    !descriptor.enumerable || !Object.hasOwn(descriptor, "value")
    || typeof descriptor.get === "function"
    || typeof descriptor.set === "function"
  ))) {
    throw new Error(`${label} must contain only enumerable own data fields`);
  }
  return value;
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

export function canonicalResidentJsonText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

export function residentRawSha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

export function canonicalResidentAbsolutePath(value, label) {
  if (typeof value !== "string" || !path.isAbsolute(value)
    || path.resolve(value) !== value || path.normalize(value) !== value
    || /[\0\r\n]/.test(value)) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return value;
}

function expectedUid(stat) {
  return typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : stat.uid;
}

function snapshot(stat) {
  return Object.freeze({
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
}

function sameSnapshot(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function parseCanonicalJsonBytes(bytes, label) {
  let text;
  let value;
  try {
    text = UTF8.decode(bytes);
    value = JSON.parse(text);
  } catch {
    throw new Error(`${label} must contain bounded UTF-8 JSON`);
  }
  if (canonicalResidentJsonText(value) !== text) {
    throw new Error(`${label} must use canonical recursively sorted two-space JSON`);
  }
  return Object.freeze({ bytes, text, value });
}

/**
 * Read one caller-owned, single-link, exact-mode-0600 canonical JSON input.
 * The opened descriptor and pathname are compared before and after the exact
 * bounded read. This is the only production CLI request-file posture used by
 * the resident driver and its non-signing attachment helper.
 */
export function readStableCanonicalResident0600Json(
  filePath,
  label,
  { maximum = MAXIMUM_JSON_BYTES } = {},
) {
  const canonicalPath = canonicalResidentAbsolutePath(filePath, `${label} path`);
  if (!Number.isSafeInteger(maximum) || maximum < 2
    || maximum > MAXIMUM_JSON_BYTES) {
    throw new Error(`${label} maximum byte bound is invalid`);
  }
  let fd;
  try {
    if (fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      throw new Error(`${label} path must be canonical and symlink-free`);
    }
    const named = fs.lstatSync(canonicalPath, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
      || named.uid !== expectedUid(named)
      || (named.mode & 0o777n) !== 0o600n
      || named.size < 2n || named.size > BigInt(maximum)) {
      throw new Error(
        `${label} must be an owned, single-link, bounded, exact-mode-0600 regular file`,
      );
    }
    fd = fs.openSync(canonicalPath, fs.constants.O_RDONLY | NOFOLLOW);
    const before = fs.fstatSync(fd, { bigint: true });
    if (!sameSnapshot(snapshot(named), snapshot(before))) {
      throw new Error(`${label} changed while opening its stable descriptor`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`${label} ended during its exact bounded read`);
      }
      offset += count;
    }
    const after = snapshot(fs.fstatSync(fd, { bigint: true }));
    const current = snapshot(fs.lstatSync(canonicalPath, { bigint: true }));
    if (!sameSnapshot(snapshot(before), after)
      || !sameSnapshot(after, current)
      || fs.realpathSync.native(canonicalPath) !== canonicalPath) {
      throw new Error(`${label} changed during its stable read`);
    }
    return parseCanonicalJsonBytes(bytes, label);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function normalizeResidentFileBinding(value, label) {
  const binding = exactResidentRecord(value, ["path", "sha256"], `${label} binding`);
  const digest = binding.sha256;
  if (typeof digest !== "string" || !SHA256.test(digest)
    || digest === `sha256:${"0".repeat(64)}`) {
    throw new Error(`${label} binding requires a nonzero canonical SHA-256`);
  }
  return Object.freeze({
    path: canonicalResidentAbsolutePath(binding.path, `${label} path`),
    sha256: digest,
  });
}

/** Stable digest/mode preflight for activation dependencies before CVM launch. */
export function preflightResidentBoundFile(value, label, {
  exactMode,
  maximum = MAXIMUM_JSON_BYTES,
  minimum = 2,
} = {}) {
  const binding = normalizeResidentFileBinding(value, label);
  if (!Number.isSafeInteger(maximum) || maximum < minimum
    || !Number.isSafeInteger(minimum) || minimum < 1
    || (exactMode !== undefined
      && (!Number.isInteger(exactMode) || exactMode < 0o400 || exactMode > 0o700))) {
    throw new Error(`${label} stable-read bounds are invalid`);
  }
  let fd;
  try {
    if (fs.realpathSync.native(binding.path) !== binding.path) {
      throw new Error(`${label} path must be canonical and symlink-free`);
    }
    const named = fs.lstatSync(binding.path, { bigint: true });
    if (!named.isFile() || named.isSymbolicLink() || named.nlink !== 1n
      || named.uid !== expectedUid(named) || (named.mode & 0o022n) !== 0n
      || (exactMode !== undefined
        && (named.mode & 0o777n) !== BigInt(exactMode))
      || named.size < BigInt(minimum) || named.size > BigInt(maximum)) {
      throw new Error(`${label} file posture is not stable and operator-owned`);
    }
    fd = fs.openSync(binding.path, fs.constants.O_RDONLY | NOFOLLOW);
    const before = fs.fstatSync(fd, { bigint: true });
    if (!sameSnapshot(snapshot(named), snapshot(before))) {
      throw new Error(`${label} changed while opening`);
    }
    const bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(fd, bytes, offset, bytes.length - offset, offset);
      if (!Number.isInteger(count) || count < 1) {
        throw new Error(`${label} ended during its bounded read`);
      }
      offset += count;
    }
    const after = snapshot(fs.fstatSync(fd, { bigint: true }));
    const current = snapshot(fs.lstatSync(binding.path, { bigint: true }));
    if (!sameSnapshot(snapshot(before), after)
      || !sameSnapshot(after, current)
      || residentRawSha256(bytes) !== binding.sha256) {
      throw new Error(`${label} bytes or file identity changed`);
    }
    return Object.freeze({ binding, bytes });
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function assertNewResidentPrivateDirectoryPath(value, label) {
  const directory = canonicalResidentAbsolutePath(value, label);
  if (fs.existsSync(directory)) {
    throw new Error(`${label} must not already exist; restart/recovery is never automatic`);
  }
  const parent = path.dirname(directory);
  if (fs.realpathSync.native(parent) !== parent) {
    throw new Error(`${label} parent must be canonical and symlink-free`);
  }
  const stat = fs.lstatSync(parent, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()
    || stat.uid !== expectedUid(stat) || (stat.mode & 0o777n) !== 0o700n) {
    throw new Error(`${label} parent must be caller-owned exact-mode-0700`);
  }
  return directory;
}

export function parsePinnedCanonicalResident0600Json(
  handle,
  fileName,
  label,
  { maximum = MAXIMUM_JSON_BYTES, allowMissing = false } = {},
) {
  const bytes = readPhalaPinnedPrivateFile(handle, fileName, {
    mode: 0o600,
    maximum,
    minimum: 2,
    allowMissing,
  });
  if (bytes === null) return null;
  return parseCanonicalJsonBytes(bytes, label);
}

export async function waitForPinnedCanonicalResident0600Json({
  handle,
  fileName,
  label,
  deadlineMs,
  pollIntervalMilliseconds,
  maximum = MAXIMUM_JSON_BYTES,
} = {}) {
  if (!Number.isFinite(deadlineMs) || deadlineMs <= Date.now()
    || !Number.isSafeInteger(pollIntervalMilliseconds)
    || pollIntervalMilliseconds < 25 || pollIntervalMilliseconds > 1_000) {
    throw new Error(`${label} wait deadline or polling interval is invalid`);
  }
  while (true) {
    const observed = parsePinnedCanonicalResident0600Json(
      handle,
      fileName,
      label,
      { maximum, allowMissing: true },
    );
    if (observed !== null) return observed;
    const remaining = deadlineMs - Date.now();
    if (remaining <= 0) {
      throw new Error(
        `${label} was not supplied before the bounded deadline; automatic retry is forbidden`,
      );
    }
    await new Promise((resolve) => {
      setTimeout(resolve, Math.min(pollIntervalMilliseconds, remaining));
    });
  }
}
