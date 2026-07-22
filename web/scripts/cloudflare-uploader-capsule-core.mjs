import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { TextDecoder } from "node:util";

export const CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA =
  "dnai.cloudflare-uploader-capsule.v1";
export const CLOUDFLARE_UPLOADER_CAPSULE_TRUTH_STATUS =
  "exact_isolated_uploader_dependency_bytes_identity_projection";
export const CLOUDFLARE_UPLOADER_CAPSULE_DOMAIN =
  "dnai-wikigen/cloudflare-uploader-capsule/v1\0";

export const CLOUDFLARE_UPLOADER_CAPSULE_LIMITS = Object.freeze({
  maxDependencyEdges: 50_000,
  maxEntries: 30_000,
  maxFileBytes: 96 * 1024 * 1024,
  maxJsonDepth: 128,
  maxJsonFileBytes: 16 * 1024 * 1024,
  maxJsonTotalBytes: 32 * 1024 * 1024,
  maxLockPackages: 10_000,
  maxManifestBytes: 64 * 1024 * 1024,
  maxPathBytes: 768,
  maxSymlinkBytes: 4_096,
  maxTotalBytes: 512 * 1024 * 1024,
});

const EXPECTED_ROOT_ENTRIES = Object.freeze([
  "node_modules",
  "package-lock.json",
  "package.json",
]);
const EXPECTED_ROOT_PACKAGE_KEYS = Object.freeze([
  "dependencies",
  "engines",
  "name",
  "packageManager",
  "private",
  "version",
]);
const EXPECTED_RUNTIME_KEYS = Object.freeze([
  "architecture",
  "nodeVersion",
  "npmVersion",
  "osPlatform",
  "osRelease",
  "wranglerVersion",
]);
const EXPECTED_PIN_KEYS = Object.freeze([
  "architecture",
  "entryCount",
  "manifestByteLength",
  "manifestSha256",
  "nodeVersion",
  "npmVersion",
  "osPlatform",
  "osRelease",
  "schema",
  "totalBytes",
  "wranglerVersion",
]);
const FORBIDDEN_CREDENTIAL_COMPONENTS = new Set([
  ".aws",
  ".cloudflared",
  ".dev.vars",
  ".git",
  ".npmrc",
  ".pypirc",
  ".ssh",
  ".wrangler",
  "auth.json",
  "credentials",
  "credentials.json",
]);
const LIFECYCLE_SCRIPT_NAMES = new Set([
  "install",
  "postinstall",
  "postpack",
  "preinstall",
  "prepack",
  "prepare",
  "prepublish",
  "prepublishOnly",
]);
const INSTALL_EXECUTION_SCRIPT_NAMES = new Set([
  "install",
  "postinstall",
  "preinstall",
]);
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]+={0,2}$/;
const EXACT_SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const NODE_VERSION = /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const PACKAGE_NAME = /^(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)$/i;
const PACKAGE_ROOT_PATH = /^node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*)(?:\/node_modules\/(?:@[a-z0-9][a-z0-9._~-]*\/[a-z0-9][a-z0-9._~-]*|[a-z0-9][a-z0-9._~-]*))*$/;
const MAX_NPM_PACKAGE_NAME_BYTES = 214;
const MAX_FILESYSTEM_COMPONENT_BYTES = 255;
const BIN_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const EMPTY_SHA256 = sha256(Buffer.alloc(0));

function hasUnsafeUnicode(value) {
  return /[\p{Cc}\p{Cf}]/u.test(value);
}

function validSha512Integrity(value) {
  if (typeof value !== "string" || !SHA512_INTEGRITY.test(value)) return false;
  const encoded = value.slice("sha512-".length);
  const decoded = Buffer.from(encoded, "base64");
  return decoded.length === 64 && decoded.toString("base64") === encoded;
}

function validRegistryResolution(value) {
  if (typeof value !== "string") return false;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:"
      && parsed.hostname === "registry.npmjs.org"
      && parsed.port === ""
      && parsed.username === ""
      && parsed.password === ""
      && parsed.search === ""
      && parsed.hash === ""
      && parsed.pathname.startsWith("/");
  } catch {
    return false;
  }
}

function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object") return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function exactObjectKeys(value, expected, label) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...expected].sort())
  ) {
    throw new Error(`${label} does not have the exact reviewed fields`);
  }
}

function safeInteger(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${label} is outside its reviewed integer bound`);
  }
  return value;
}

function normalizeLimits(value = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Cloudflare uploader capsule limits must be an object");
  }
  for (const key of Object.keys(value)) {
    if (!Object.hasOwn(CLOUDFLARE_UPLOADER_CAPSULE_LIMITS, key)) {
      throw new Error("Cloudflare uploader capsule limits contain an unknown field");
    }
  }
  const minimums = {
    maxDependencyEdges: 1,
    maxEntries: 4,
    maxFileBytes: 1,
    maxJsonDepth: 4,
    maxJsonFileBytes: 1,
    maxJsonTotalBytes: 3,
    maxLockPackages: 2,
    maxManifestBytes: 1_024,
    maxPathBytes: 16,
    maxSymlinkBytes: 1,
    maxTotalBytes: 3,
  };
  const normalized = {};
  for (const [key, ceiling] of Object.entries(CLOUDFLARE_UPLOADER_CAPSULE_LIMITS)) {
    normalized[key] = safeInteger(value[key] ?? ceiling, `Cloudflare uploader ${key}`, {
      minimum: minimums[key],
      maximum: ceiling,
    });
  }
  return Object.freeze(normalized);
}

function expectedUid(value) {
  const fallback = typeof process.geteuid === "function" ? process.geteuid() : 0;
  return BigInt(safeInteger(value ?? fallback, "Cloudflare uploader expected owner"));
}

function relativePath(root, absolute) {
  if (absolute === root) return ".";
  const relative = path.relative(root, absolute).split(path.sep).join("/");
  if (
    !relative
    || relative.startsWith("../")
    || relative.startsWith("/")
    || relative.includes("\\")
    || relative.includes("\0")
  ) {
    throw new Error("Cloudflare uploader capsule entry escapes its root");
  }
  return relative;
}

function decodeEntryName(bytes) {
  let name;
  try {
    name = UTF8.decode(bytes);
  } catch {
    throw new Error("Cloudflare uploader capsule contains a non-UTF-8 path");
  }
  if (
    !name
    || name === "."
    || name === ".."
    || name.includes("/")
    || name.includes("\\")
    || name.includes("\0")
    || hasUnsafeUnicode(name)
    || name.normalize("NFC") !== name
    || Buffer.byteLength(name, "utf8") > 255
  ) {
    throw new Error("Cloudflare uploader capsule contains a noncanonical path component");
  }
  return name;
}

function assertPathBound(relative, limits) {
  if (
    relative !== "."
    && (
      path.posix.normalize(relative) !== relative
      || relative.startsWith("/")
      || relative.endsWith("/")
      || relative.split("/").some((part) => !part || part === "." || part === "..")
    )
  ) {
    throw new Error("Cloudflare uploader capsule contains a noncanonical path");
  }
  if (Buffer.byteLength(relative, "utf8") > limits.maxPathBytes) {
    throw new Error("Cloudflare uploader capsule exceeds its path-byte bound");
  }
}

function isCredentialPath(relative) {
  if (relative === ".") return false;
  return relative.split("/").some((component) => {
    const lower = component.toLowerCase();
    return lower === ".env"
      || lower.startsWith(".env.")
      || FORBIDDEN_CREDENTIAL_COMPONENTS.has(lower);
  });
}

function permissionMode(metadata) {
  return Number(metadata.mode & 0o7777n);
}

function safeOwnedMode(metadata, owner, { directory = false } = {}) {
  const mode = permissionMode(metadata);
  return metadata.uid === owner
    && (mode & 0o7000) === 0
    && (mode & 0o022) === 0
    && (mode & 0o400) !== 0
    && (!directory || (mode & 0o100) !== 0);
}

const STABLE_FIELDS = Object.freeze([
  "dev",
  "ino",
  "size",
  "nlink",
  "uid",
  "gid",
  "mode",
  "mtimeNs",
  "ctimeNs",
]);

function sameMetadata(left, right) {
  return STABLE_FIELDS.every((field) => left[field] === right[field]);
}

const IDENTITY_FIELDS = Object.freeze(["dev", "ino", "uid", "gid", "mode"]);

function sameIdentity(left, right) {
  return IDENTITY_FIELDS.every((field) => left[field] === right[field]);
}

function captureAncestorChain(capsuleRoot, owner) {
  const chain = [];
  let current = path.dirname(capsuleRoot);
  for (;;) {
    const metadata = fs.lstatSync(current, { bigint: true });
    const mode = permissionMode(metadata);
    const writableByOthers = (mode & 0o022) !== 0;
    const rootOwnedSticky = metadata.uid === 0n && (mode & 0o1000) !== 0;
    if (
      !metadata.isDirectory()
      || metadata.isSymbolicLink()
      || (metadata.uid !== 0n && metadata.uid !== owner)
      || (writableByOthers && !rootOwnedSticky)
      || fs.realpathSync.native(current) !== current
    ) {
      throw new Error("Cloudflare uploader capsule has an unsafe ancestor directory");
    }
    chain.push(Object.freeze({ metadata, path: current }));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return Object.freeze(chain);
}

function assertAncestorChainStable(chain) {
  for (const entry of chain) {
    const after = fs.lstatSync(entry.path, { bigint: true });
    if (!sameIdentity(entry.metadata, after)) {
      throw new Error("Cloudflare uploader capsule ancestor changed during projection");
    }
  }
}

function stableRegularFile(filePath, named, owner, limits, hooks, {
  retainBytes = false,
} = {}) {
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || !safeOwnedMode(named, owner)
    || named.size < 0n
    || named.size > BigInt(limits.maxFileBytes)
  ) {
    throw new Error(
      "Cloudflare uploader capsule contains an unsafe, hard-linked, or oversized file",
    );
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || !sameMetadata(named, before)) {
      throw new Error("Cloudflare uploader capsule file changed while opening");
    }
    const size = Number(before.size);
    const retained = retainBytes ? Buffer.allocUnsafe(size) : null;
    const header = Buffer.alloc(Math.min(size, 16));
    const chunk = Buffer.allocUnsafe(Math.min(Math.max(size, 1), 64 * 1024));
    const hash = createHash("sha256");
    let offset = 0;
    while (offset < size) {
      const length = Math.min(chunk.length, size - offset);
      const read = fs.readSync(descriptor, chunk, 0, length, offset);
      if (read < 1) {
        throw new Error("Cloudflare uploader capsule file was truncated during read");
      }
      const content = chunk.subarray(0, read);
      hash.update(content);
      if (offset < header.length) {
        content.copy(header, offset, 0, Math.min(read, header.length - offset));
      }
      if (retained) content.copy(retained, offset);
      offset += read;
    }
    hooks?.afterFileRead?.(filePath);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameMetadata(before, after) || BigInt(offset) !== before.size) {
      throw new Error("Cloudflare uploader capsule file changed during its stable read");
    }
    return Object.freeze({
      bytes: retained,
      header,
      sha256: `sha256:${hash.digest("hex")}`,
      size,
    });
  } finally {
    fs.closeSync(descriptor);
  }
}

function stableSymlink(linkPath, relative, named, owner, limits, hooks) {
  if (!named.isSymbolicLink() || named.nlink !== 1n || named.uid !== owner) {
    throw new Error("Cloudflare uploader capsule contains an unsafe symlink");
  }
  const targetBytes = fs.readlinkSync(linkPath, { encoding: "buffer" });
  let target;
  try {
    target = UTF8.decode(targetBytes);
  } catch {
    throw new Error("Cloudflare uploader capsule contains a non-UTF-8 symlink target");
  }
  hooks?.afterSymlinkRead?.(linkPath);
  const after = fs.lstatSync(linkPath, { bigint: true });
  if (!sameMetadata(named, after)) {
    throw new Error("Cloudflare uploader capsule symlink changed during projection");
  }
  if (
    !target
    || path.posix.isAbsolute(target)
    || target.includes("\\")
    || target.includes("\0")
    || hasUnsafeUnicode(target)
    || path.posix.normalize(target) !== target
    || target.split("/").some((component) => (
      !component
      || component === "."
      || (component !== ".." && component.normalize("NFC") !== component)
    ))
    || !Buffer.from(target, "utf8").equals(targetBytes)
    || targetBytes.length > limits.maxSymlinkBytes
  ) {
    throw new Error("Cloudflare uploader capsule contains an invalid symlink target");
  }
  const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(relative), target));
  if (
    resolved === "."
    || resolved === ".."
    || resolved.startsWith("../")
    || resolved.startsWith("/")
  ) {
    throw new Error("Cloudflare uploader capsule symlink escapes its root");
  }
  return { target, targetBytes, resolved };
}

function magicEquals(bytes, hex) {
  const magic = Buffer.from(hex, "hex");
  return bytes.length >= magic.length && bytes.subarray(0, magic.length).equals(magic);
}

function classifyFile(relative, bytes, mode) {
  const lower = relative.toLowerCase();
  const extension = path.posix.extname(lower);
  let kind = "data";
  if (magicEquals(bytes, "0061736d")) {
    kind = "wasm";
  } else if (magicEquals(bytes, "7f454c46")) {
    kind = "native_elf";
  } else if (magicEquals(bytes, "4d5a")) {
    kind = "native_pe";
  } else if (bytes.subarray(0, 8).toString("ascii") === "!<arch>\n") {
    kind = "native_archive";
  } else if ([
    "feedface",
    "feedfacf",
    "cefaedfe",
    "cffaedfe",
    "cafebabe",
    "bebafeca",
    "cafebabf",
    "bfbafeca",
  ].some((magic) => magicEquals(bytes, magic))) {
    kind = "native_mach_o";
  } else if (bytes.subarray(0, 2).toString("ascii") === "#!") {
    kind = "script";
  } else if ([".cjs", ".cts", ".js", ".jsx", ".mjs", ".mts", ".ts", ".tsx"].includes(extension)) {
    kind = "javascript_or_typescript";
  } else if (extension === ".json") {
    kind = "json";
  }

  if (extension === ".wasm" && kind !== "wasm") {
    throw new Error("Cloudflare uploader capsule has a WASM extension/magic mismatch");
  }
  if (
    extension === ".node"
    && !["native_elf", "native_mach_o", "native_pe"].includes(kind)
  ) {
    throw new Error("Cloudflare uploader capsule has a native addon extension/magic mismatch");
  }
  if (extension === ".dylib" && kind !== "native_mach_o") {
    throw new Error("Cloudflare uploader capsule has a Mach-O extension/magic mismatch");
  }
  if (extension === ".dll" && kind !== "native_pe") {
    throw new Error("Cloudflare uploader capsule has a PE extension/magic mismatch");
  }
  if (extension === ".exe" && kind !== "native_pe") {
    throw new Error("Cloudflare uploader capsule has a PE extension/magic mismatch");
  }
  if ([".a", ".lib"].includes(extension) && kind !== "native_archive") {
    throw new Error("Cloudflare uploader capsule has a native archive extension/magic mismatch");
  }
  if (extension === ".so" && !["native_elf", "native_mach_o"].includes(kind)) {
    throw new Error("Cloudflare uploader capsule has a shared-library extension/magic mismatch");
  }
  const executable = (mode & 0o111) !== 0;
  if (executable && kind === "data") {
    throw new Error("Cloudflare uploader capsule contains an unclassified executable file");
  }
  return { executable, kind };
}

function parseDuplicateFreeJson(bytes, label, {
  canonical = false,
  maxDepth = CLOUDFLARE_UPLOADER_CAPSULE_LIMITS.maxJsonDepth,
} = {}) {
  safeInteger(maxDepth, `${label} JSON depth`, {
    minimum: 1,
    maximum: CLOUDFLARE_UPLOADER_CAPSULE_LIMITS.maxJsonDepth,
  });
  let text;
  try {
    text = UTF8.decode(bytes);
  } catch {
    throw new Error(`${label} is not canonical UTF-8 JSON`);
  }
  if (!Buffer.from(text, "utf8").equals(bytes) || text.includes("\0")) {
    throw new Error(`${label} is not canonical UTF-8 JSON`);
  }

  let cursor = 0;
  const literalPattern = /(?:true|false|null)/y;
  const numberPattern = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  function whitespace() {
    while (/[\x20\x09\x0a\x0d]/.test(text[cursor] || "")) cursor += 1;
  }
  function stringToken() {
    if (text[cursor] !== '"') throw new Error(`${label} is not valid JSON`);
    const start = cursor;
    cursor += 1;
    while (cursor < text.length) {
      const code = text.charCodeAt(cursor);
      if (code === 0x22) {
        cursor += 1;
        try {
          return JSON.parse(text.slice(start, cursor));
        } catch {
          throw new Error(`${label} is not valid JSON`);
        }
      }
      if (code < 0x20) throw new Error(`${label} is not valid JSON`);
      if (code === 0x5c) {
        cursor += 1;
        if (cursor >= text.length || !/["\\/bfnrtu]/.test(text[cursor])) {
          throw new Error(`${label} is not valid JSON`);
        }
        if (text[cursor] === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(cursor + 1, cursor + 5))) {
            throw new Error(`${label} is not valid JSON`);
          }
          cursor += 4;
        }
      }
      cursor += 1;
    }
    throw new Error(`${label} is not valid JSON`);
  }
  function value(depth = 0) {
    if (depth > maxDepth) throw new Error(`${label} exceeds its JSON nesting bound`);
    whitespace();
    if (text[cursor] === "{") return object(depth);
    if (text[cursor] === "[") return array(depth);
    if (text[cursor] === '"') return void stringToken();
    literalPattern.lastIndex = cursor;
    const literal = literalPattern.exec(text);
    if (literal) {
      cursor += literal[0].length;
      return;
    }
    numberPattern.lastIndex = cursor;
    const number = numberPattern.exec(text);
    if (number) {
      cursor += number[0].length;
      return;
    }
    throw new Error(`${label} is not valid JSON`);
  }
  function object(depth) {
    cursor += 1;
    whitespace();
    const keys = new Set();
    if (text[cursor] === "}") {
      cursor += 1;
      return;
    }
    while (cursor < text.length) {
      whitespace();
      const key = stringToken();
      if (keys.has(key)) throw new Error(`${label} contains a duplicate object key`);
      keys.add(key);
      whitespace();
      if (text[cursor] !== ":") throw new Error(`${label} is not valid JSON`);
      cursor += 1;
      value(depth + 1);
      whitespace();
      if (text[cursor] === "}") {
        cursor += 1;
        return;
      }
      if (text[cursor] !== ",") throw new Error(`${label} is not valid JSON`);
      cursor += 1;
    }
    throw new Error(`${label} is not valid JSON`);
  }
  function array(depth) {
    cursor += 1;
    whitespace();
    if (text[cursor] === "]") {
      cursor += 1;
      return;
    }
    while (cursor < text.length) {
      value(depth + 1);
      whitespace();
      if (text[cursor] === "]") {
        cursor += 1;
        return;
      }
      if (text[cursor] !== ",") throw new Error(`${label} is not valid JSON`);
      cursor += 1;
    }
    throw new Error(`${label} is not valid JSON`);
  }

  value();
  whitespace();
  if (cursor !== text.length) throw new Error(`${label} is not valid JSON`);
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (canonical && canonicalText(parsed) !== text) {
    throw new Error(`${label} is not canonical duplicate-free JSON`);
  }
  return parsed;
}

function normalizeRuntimeIdentity(value, observedRuntimeIdentity = null) {
  exactObjectKeys(value, EXPECTED_RUNTIME_KEYS, "Cloudflare uploader runtime identity");
  const observed = observedRuntimeIdentity || {
    architecture: process.arch,
    nodeVersion: process.version,
    osPlatform: process.platform,
    osRelease: os.release(),
  };
  exactObjectKeys(
    observed,
    ["architecture", "nodeVersion", "osPlatform", "osRelease"],
    "observed Cloudflare uploader runtime identity",
  );
  for (const [key, expected] of Object.entries(observed)) {
    if (value[key] !== expected) {
      throw new Error(`Cloudflare uploader runtime ${key} does not match the executing host`);
    }
  }
  if (!NODE_VERSION.test(value.nodeVersion)) {
    throw new Error("Cloudflare uploader Node version is not exact");
  }
  for (const key of ["npmVersion", "wranglerVersion"]) {
    if (!EXACT_SEMVER.test(value[key])) {
      throw new Error(`Cloudflare uploader ${key} is not an exact version`);
    }
  }
  if (
    typeof value.osRelease !== "string"
    || !value.osRelease
    || /[\0\r\n]/.test(value.osRelease)
    || typeof value.osPlatform !== "string"
    || !value.osPlatform
    || typeof value.architecture !== "string"
    || !value.architecture
  ) {
    throw new Error("Cloudflare uploader host identity is invalid");
  }
  return Object.freeze({ ...value });
}

function canonicalLockPackagePath(value, limits) {
  if (value === "") return true;
  if (
    typeof value !== "string"
    || Buffer.byteLength(value, "utf8") > limits.maxPathBytes
  ) return false;
  const parts = value.split("/");
  if (parts.some((part) => (
    Buffer.byteLength(part, "utf8") > MAX_FILESYSTEM_COMPONENT_BYTES
  ))) return false;
  for (let index = 0; index < parts.length; index += 1) {
    if (parts[index] !== "node_modules") continue;
    const first = parts[index + 1];
    if (!first) return false;
    const packageName = first.startsWith("@")
      ? `${first}/${parts[index + 2] || ""}`
      : first;
    if (Buffer.byteLength(packageName, "utf8") > MAX_NPM_PACKAGE_NAME_BYTES) {
      return false;
    }
  }
  return (
    PACKAGE_ROOT_PATH.test(value)
    && !value.includes("\\")
    && !value.includes("\0")
    && !hasUnsafeUnicode(value)
    && value.normalize("NFC") === value
    && path.posix.normalize(value) === value
    && value.split("/").every((part) => part && part !== "." && part !== "..")
    && !isCredentialPath(value)
  );
}

function normalizeRootAndLock(packageBytes, lockBytes, runtime, limits) {
  const rootPackage = parseDuplicateFreeJson(packageBytes, "uploader package.json", {
    canonical: true,
    maxDepth: limits.maxJsonDepth,
  });
  exactObjectKeys(rootPackage, EXPECTED_ROOT_PACKAGE_KEYS, "uploader package.json");
  if (
    rootPackage.name !== "dnai-cloudflare-release-uploader"
    || rootPackage.version !== "0.0.0"
    || rootPackage.private !== true
    || !rootPackage.dependencies
    || typeof rootPackage.dependencies !== "object"
    || Array.isArray(rootPackage.dependencies)
    || JSON.stringify(Object.keys(rootPackage.dependencies)) !== JSON.stringify(["wrangler"])
    || rootPackage.dependencies.wrangler !== runtime.wranglerVersion
    || !rootPackage.engines
    || typeof rootPackage.engines !== "object"
    || Array.isArray(rootPackage.engines)
    || JSON.stringify(Object.keys(rootPackage.engines)) !== JSON.stringify(["node"])
    || rootPackage.engines.node !== runtime.nodeVersion.slice(1)
    || rootPackage.packageManager !== `npm@${runtime.npmVersion}`
  ) {
    throw new Error("uploader package.json is not the exact minimal Wrangler-only package");
  }

  const lock = parseDuplicateFreeJson(lockBytes, "uploader package-lock.json", {
    canonical: true,
    maxDepth: limits.maxJsonDepth,
  });
  exactObjectKeys(
    lock,
    ["lockfileVersion", "name", "packages", "requires", "version"],
    "uploader package-lock.json",
  );
  if (
    !lock
    || typeof lock !== "object"
    || Array.isArray(lock)
    || lock.name !== rootPackage.name
    || lock.version !== rootPackage.version
    || lock.lockfileVersion !== 3
    || lock.requires !== true
    || !lock.packages
    || typeof lock.packages !== "object"
    || Array.isArray(lock.packages)
  ) {
    throw new Error("uploader package-lock.json is not the reviewed npm lockfile-v3 shape");
  }
  const packagePaths = Object.keys(lock.packages);
  if (packagePaths.length - 1 > limits.maxLockPackages) {
    throw new Error("uploader package-lock.json exceeds its lock-package bound");
  }
  if (
    packagePaths.length < 2
    || packagePaths.some((entry) => !canonicalLockPackagePath(entry, limits))
    || JSON.stringify([...packagePaths].sort(compareUtf8))
      !== JSON.stringify(packagePaths)
  ) {
    throw new Error("uploader package-lock.json contains noncanonical package paths or ordering");
  }
  const lockRoot = lock.packages[""];
  if (
    !lockRoot
    || lockRoot.name !== rootPackage.name
    || lockRoot.version !== rootPackage.version
    || JSON.stringify(lockRoot.dependencies) !== JSON.stringify(rootPackage.dependencies)
  ) {
    throw new Error("uploader package-lock.json root does not match package.json");
  }
  const installScriptPackages = [];
  let dependencyEdgeCount = Object.keys(normalizeDependencyMap(
    lockRoot.dependencies,
    "uploader lock root",
  )).length;
  if (dependencyEdgeCount > limits.maxDependencyEdges) {
    throw new Error("uploader package-lock.json exceeds its dependency-edge bound");
  }
  for (const packagePath of packagePaths.slice(1)) {
    const descriptor = lock.packages[packagePath];
    if (
      !descriptor
      || typeof descriptor !== "object"
      || Array.isArray(descriptor)
      || descriptor.link === true
      || typeof descriptor.version !== "string"
      || !EXACT_SEMVER.test(descriptor.version)
      || !validRegistryResolution(descriptor.resolved)
      || !validSha512Integrity(descriptor.integrity)
      || (descriptor.hasInstallScript !== undefined && typeof descriptor.hasInstallScript !== "boolean")
      || (descriptor.optional !== undefined && typeof descriptor.optional !== "boolean")
    ) {
      throw new Error("uploader package-lock.json contains an unpinned dependency");
    }
    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      dependencyEdgeCount += Object.keys(normalizeDependencyMap(
        descriptor[field],
        `locked uploader dependency ${field}`,
      )).length;
      if (dependencyEdgeCount > limits.maxDependencyEdges) {
        throw new Error("uploader package-lock.json exceeds its dependency-edge bound");
      }
    }
    if (descriptor.hasInstallScript === true) installScriptPackages.push(packagePath);
  }
  const wranglerLock = lock.packages["node_modules/wrangler"];
  if (!wranglerLock || wranglerLock.version !== runtime.wranglerVersion) {
    throw new Error("uploader package-lock.json does not pin the declared Wrangler version");
  }
  return {
    dependencyEdgeCount,
    installScriptPackages: Object.freeze(installScriptPackages),
    lock,
    packagePaths: Object.freeze(packagePaths),
    rootPackage,
  };
}

function resolveManifestSymlink(recordsByPath, linkPath) {
  let current = linkPath;
  const seen = new Set();
  for (let depth = 0; depth < 32; depth += 1) {
    if (seen.has(current)) {
      throw new Error("Cloudflare uploader capsule contains a symlink cycle");
    }
    seen.add(current);
    const record = recordsByPath.get(current);
    if (!record) {
      throw new Error("Cloudflare uploader capsule symlink target is absent");
    }
    if (record.type === "file") return current;
    if (record.type !== "symlink") {
      throw new Error("Cloudflare uploader capsule symlink does not resolve to a file");
    }
    current = record.resolvedTarget;
  }
  throw new Error("Cloudflare uploader capsule symlink chain is too deep");
}

function packageNameFromPath(packagePath) {
  const parts = packagePath.split("/");
  const lastNodeModules = parts.lastIndexOf("node_modules");
  const first = parts[lastNodeModules + 1];
  return first.startsWith("@") ? `${first}/${parts[lastNodeModules + 2]}` : first;
}

function isRetainedJsonDescriptor(relative) {
  if (relative === "package.json" || relative === "package-lock.json") return true;
  if (!relative.endsWith("/package.json")) return false;
  return PACKAGE_ROOT_PATH.test(path.posix.dirname(relative));
}

function normalizePackageBins(value, packagePath, recordsByPath) {
  if (value === undefined) return [];
  const packageName = packageNameFromPath(packagePath);
  const raw = typeof value === "string" ? { [packageName.split("/").at(-1)]: value } : value;
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("installed uploader dependency declares an invalid bin field");
  }
  const entries = [];
  for (const [command, target] of Object.entries(raw)) {
    if (
      !BIN_NAME.test(command)
      || typeof target !== "string"
      || !target
      || target.includes("\\")
      || target.includes("\0")
      || path.posix.isAbsolute(target)
      || path.posix.normalize(target) !== target
    ) {
      throw new Error("installed uploader dependency declares an unsafe binary entrypoint");
    }
    const resolvedTarget = path.posix.normalize(path.posix.join(packagePath, target));
    if (
      resolvedTarget === packagePath
      || !resolvedTarget.startsWith(`${packagePath}/`)
      || recordsByPath.get(resolvedTarget)?.type !== "file"
    ) {
      throw new Error("installed uploader dependency binary entrypoint escapes or is absent");
    }
    entries.push(Object.freeze({ command, packagePath, target: resolvedTarget }));
  }
  return entries.sort((left, right) => (
    compareUtf8(left.command, right.command)
    || compareUtf8(left.packagePath, right.packagePath)
  ));
}

function owningPackagePath(relative, packagePaths) {
  let candidate = relative;
  for (;;) {
    if (packagePaths.has(candidate)) return candidate;
    const parent = path.posix.dirname(candidate);
    if (parent === "." || parent === candidate) return null;
    candidate = parent;
  }
}

function parentPackagePath(packagePath) {
  const marker = packagePath.lastIndexOf("/node_modules/");
  return marker === -1 ? "" : packagePath.slice(0, marker);
}

function dependencyPackagePath(packagePath, dependencyName, lockPackages) {
  let scope = packagePath;
  for (;;) {
    const candidate = scope
      ? `${scope}/node_modules/${dependencyName}`
      : `node_modules/${dependencyName}`;
    if (Object.hasOwn(lockPackages, candidate)) return candidate;
    if (!scope) return null;
    scope = parentPackagePath(scope);
  }
}

function normalizeDependencyMap(value, label) {
  if (value === undefined) return Object.freeze({});
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} dependencies are invalid`);
  }
  const entries = Object.entries(value).sort(([left], [right]) => compareUtf8(left, right));
  for (const [name, specifier] of entries) {
    if (
      !PACKAGE_NAME.test(name)
      || typeof specifier !== "string"
      || !specifier
      || hasUnsafeUnicode(specifier)
    ) {
      throw new Error(`${label} dependencies are invalid`);
    }
  }
  return Object.freeze(Object.fromEntries(entries));
}

function installedStructuralDirectories(installedPackagePaths) {
  const structural = new Set(["node_modules"]);
  for (const packagePath of installedPackagePaths) {
    const parts = packagePath.split("/");
    for (let index = 0; index < parts.length; index += 1) {
      if (parts[index] !== "node_modules") continue;
      structural.add(parts.slice(0, index + 1).join("/"));
      if (parts[index + 1]?.startsWith("@")) {
        structural.add(parts.slice(0, index + 2).join("/"));
      }
    }
  }
  return structural;
}

function nodeModulesStructure(
  relative,
  record,
  installedPackagePaths,
  structuralDirectories,
) {
  if (relative !== "node_modules" && !relative.startsWith("node_modules/")) {
    return Object.freeze({
      binCommand: null,
      binDirectory: false,
      binScope: null,
      structural: false,
    });
  }
  const parts = relative.split("/");
  let binCommand = null;
  let binDirectory = false;
  let binScope = null;
  let structural = relative === "node_modules";
  for (let index = 0; index < parts.length; index += 1) {
    if (parts[index] !== "node_modules") continue;
    const next = parts[index + 1];
    const prefix = parts.slice(0, index + 1).join("/");
    if (next === undefined) {
      if (
        record.type !== "directory"
        || !structuralDirectories.has(prefix)
      ) {
        throw new Error("installed uploader tree contains an undeclared node_modules directory");
      }
      structural = true;
      continue;
    }
    if (next === ".bin") {
      binScope = parts.slice(0, index).join("/");
      if (index + 2 === parts.length) {
        if (record.type !== "directory") {
          throw new Error("installed uploader .bin path is not a directory");
        }
        binDirectory = true;
        structural = true;
      } else if (index + 3 === parts.length) {
        binCommand = parts[index + 2];
        if (!BIN_NAME.test(binCommand)) {
          throw new Error("installed uploader .bin command path is invalid");
        }
        structural = true;
      } else {
        throw new Error("installed uploader .bin contains a nested path");
      }
      continue;
    }
    if (next.startsWith(".")) {
      if (relative !== "node_modules/.package-lock.json") {
        throw new Error("installed uploader tree contains an undeclared npm metadata path");
      }
      structural = true;
      continue;
    }
    let packageEnd = index + 1;
    if (next.startsWith("@")) {
      if (index + 2 >= parts.length) {
        if (
          record.type !== "directory"
          || !structuralDirectories.has(`${prefix}/${next}`)
        ) {
          throw new Error("installed uploader tree contains an empty or undeclared package scope");
        }
        structural = true;
        continue;
      }
      packageEnd = index + 2;
    }
    const packageRoot = parts.slice(0, packageEnd + 1).join("/");
    if (!installedPackagePaths.has(packageRoot)) {
      throw new Error("installed uploader tree contains an undeclared nested package");
    }
  }
  return Object.freeze({ binCommand, binDirectory, binScope, structural });
}

function lockPlatformAllows(descriptor, field, current) {
  const values = descriptor[field];
  if (values === undefined) return true;
  if (
    !Array.isArray(values)
    || values.length < 1
    || values.some((entry) => typeof entry !== "string" || !entry || /[\0\r\n]/.test(entry))
  ) {
    throw new Error(`uploader package-lock.json contains an invalid ${field} selector`);
  }
  if (values.includes(`!${current}`)) return false;
  const positive = values.filter((entry) => !entry.startsWith("!"));
  return positive.length === 0 || positive.includes(current);
}

function validateInstalledDependencyTree({
  bytesByPath,
  lock,
  packagePaths,
  records,
  recordsByPath,
  runtime,
  limits,
}) {
  const installedPackages = [];
  const installedDescriptors = new Map();
  const lifecycleScripts = [];
  const binaryEntrypoints = [];
  const existingPackagePaths = packagePaths.slice(1).filter((packagePath) => (
    recordsByPath.get(packagePath)?.type === "directory"
  ));
  const existingPackagePathSet = new Set(existingPackagePaths);
  const structuralDirectories = installedStructuralDirectories(existingPackagePathSet);

  for (const packagePath of packagePaths.slice(1)) {
    const descriptor = lock.packages[packagePath];
    const compatible = lockPlatformAllows(descriptor, "os", runtime.osPlatform)
      && lockPlatformAllows(descriptor, "cpu", runtime.architecture);
    const parent = packagePath.includes("/node_modules/")
      ? packagePath.slice(0, packagePath.lastIndexOf("/node_modules/"))
      : null;
    if (
      descriptor.optional !== true
      && compatible
      && (!parent || existingPackagePathSet.has(parent))
      && !existingPackagePathSet.has(packagePath)
    ) {
      throw new Error("installed uploader tree is missing a required locked package");
    }
  }

  for (const packagePath of existingPackagePaths) {
    const descriptorPath = `${packagePath}/package.json`;
    const descriptorBytes = bytesByPath.get(descriptorPath);
    if (!descriptorBytes) {
      throw new Error("installed uploader dependency is missing package.json");
    }
    const descriptor = parseDuplicateFreeJson(
      descriptorBytes,
      "installed uploader dependency package.json",
      { maxDepth: limits.maxJsonDepth },
    );
    const lockDescriptor = lock.packages[packagePath];
    const expectedName = packageNameFromPath(packagePath);
    if (
      !descriptor
      || typeof descriptor !== "object"
      || Array.isArray(descriptor)
      || typeof descriptor.name !== "string"
      || !PACKAGE_NAME.test(descriptor.name)
      || descriptor.name !== expectedName
      || descriptor.version !== lockDescriptor.version
    ) {
      throw new Error("installed uploader dependency identity does not match package-lock.json");
    }
    const installedDependencies = normalizeDependencyMap(
      descriptor.dependencies,
      "installed uploader dependency",
    );
    const lockedDependencies = normalizeDependencyMap(
      lockDescriptor.dependencies,
      "locked uploader dependency",
    );
    if (canonicalText(installedDependencies) !== canonicalText(lockedDependencies)) {
      throw new Error("installed uploader regular dependency map does not match package-lock.json");
    }
    installedDescriptors.set(packagePath, Object.freeze({
      dependencies: installedDependencies,
      descriptor,
    }));
    installedPackages.push(Object.freeze({
      name: descriptor.name,
      packageJsonSha256: recordsByPath.get(descriptorPath).sha256,
      path: packagePath,
      version: descriptor.version,
    }));
    if (descriptor.scripts !== undefined) {
      if (!descriptor.scripts || typeof descriptor.scripts !== "object" || Array.isArray(descriptor.scripts)) {
        throw new Error("installed uploader dependency scripts are invalid");
      }
      for (const [scriptName, command] of Object.entries(descriptor.scripts)) {
        if (
          typeof command !== "string"
          || !command
          || hasUnsafeUnicode(scriptName)
        ) {
          throw new Error("installed uploader dependency scripts are invalid");
        }
      }
      const names = Object.keys(descriptor.scripts)
        .filter((name) => LIFECYCLE_SCRIPT_NAMES.has(name))
        .sort(compareUtf8);
      if (names.length) lifecycleScripts.push(Object.freeze({ packagePath, scriptNames: names }));
      if (
        names.some((name) => INSTALL_EXECUTION_SCRIPT_NAMES.has(name))
        && lockDescriptor.hasInstallScript !== true
      ) {
        throw new Error("installed uploader install script is not declared by package-lock.json");
      }
    }
    binaryEntrypoints.push(...normalizePackageBins(descriptor.bin, packagePath, recordsByPath));
  }

  const dependencyOwners = [
    ["", normalizeDependencyMap(lock.packages[""].dependencies, "uploader lock root")],
    ...[...installedDescriptors.entries()].map(([packagePath, value]) => (
      [packagePath, value.dependencies]
    )),
  ];
  for (const [packagePath, dependencies] of dependencyOwners) {
    for (const dependencyName of Object.keys(dependencies)) {
      const target = dependencyPackagePath(packagePath, dependencyName, lock.packages);
      if (!target || !existingPackagePathSet.has(target)) {
        throw new Error("installed uploader tree is missing a required dependency edge");
      }
    }
  }

  for (const record of records) {
    if (record.path !== "node_modules" && !record.path.startsWith("node_modules/")) continue;
    const structure = nodeModulesStructure(
      record.path,
      record,
      existingPackagePathSet,
      structuralDirectories,
    );
    if (structure.structural) continue;
    if (!owningPackagePath(record.path, existingPackagePathSet)) {
      throw new Error("installed uploader tree contains bytes outside a locked package");
    }
  }

  const binByCommandAndTarget = new Map();
  for (const entry of binaryEntrypoints) {
    const key = `${entry.command}\0${entry.target}`;
    const values = binByCommandAndTarget.get(key) || [];
    values.push(entry);
    binByCommandAndTarget.set(key, values);
  }
  for (const record of records) {
    if (record.path !== "node_modules" && !record.path.startsWith("node_modules/")) continue;
    const structure = nodeModulesStructure(
      record.path,
      record,
      existingPackagePathSet,
      structuralDirectories,
    );
    if (!structure.binCommand) continue;
    if (record.type !== "symlink") {
      throw new Error("installed uploader .bin entry is not a manifest-bound symlink");
    }
    const command = structure.binCommand;
    const resolved = resolveManifestSymlink(recordsByPath, record.path);
    const matchingEntrypoint = (binByCommandAndTarget.get(`${command}\0${resolved}`) || [])
      .find((entry) => dependencyPackagePath(
        structure.binScope,
        packageNameFromPath(entry.packagePath),
        lock.packages,
      ) === entry.packagePath);
    if (!matchingEntrypoint) {
      throw new Error("installed uploader .bin symlink does not match a declared package binary");
    }
  }

  const wranglerPackage = installedPackages.find(({ path: packagePath }) => (
    packagePath === "node_modules/wrangler"
  ));
  const wranglerBin = binaryEntrypoints.find(({ command, packagePath }) => (
    command === "wrangler" && packagePath === "node_modules/wrangler"
  ));
  const wranglerShim = recordsByPath.get("node_modules/.bin/wrangler");
  if (
    !wranglerPackage
    || wranglerPackage.version !== runtime.wranglerVersion
    || !wranglerBin
    || !wranglerShim
    || wranglerShim.type !== "symlink"
    || resolveManifestSymlink(recordsByPath, wranglerShim.path) !== wranglerBin.target
  ) {
    throw new Error("installed uploader Wrangler executable identity is incomplete");
  }

  return {
    binaryEntrypoints: Object.freeze(binaryEntrypoints),
    installedPackages: Object.freeze(installedPackages),
    lifecycleScripts: Object.freeze(lifecycleScripts),
    wrangler: Object.freeze({
      executablePath: wranglerBin.target,
      packageJsonSha256: wranglerPackage.packageJsonSha256,
      packagePath: wranglerPackage.path,
      shimPath: wranglerShim.path,
      shimTarget: wranglerShim.target,
      version: wranglerPackage.version,
    }),
  };
}

function projectOnce({
  capsuleRoot,
  expectedOwner,
  limits,
  observedRuntimeIdentity,
  runtimeIdentity,
  hooks,
}) {
  if (
    typeof capsuleRoot !== "string"
    || !path.isAbsolute(capsuleRoot)
    || path.resolve(capsuleRoot) !== capsuleRoot
    || path.normalize(capsuleRoot) !== capsuleRoot
    || hasUnsafeUnicode(capsuleRoot)
    || fs.realpathSync.native(capsuleRoot) !== capsuleRoot
  ) {
    throw new Error("Cloudflare uploader capsule root is aliased or noncanonical");
  }
  const owner = expectedUid(expectedOwner);
  const normalizedLimits = normalizeLimits(limits);
  const runtime = normalizeRuntimeIdentity(runtimeIdentity, observedRuntimeIdentity);
  const rootMetadata = fs.lstatSync(capsuleRoot, { bigint: true });
  const rootMode = permissionMode(rootMetadata);
  if (
    !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || !safeOwnedMode(rootMetadata, owner, { directory: true })
    || (rootMode & 0o077) !== 0
  ) {
    throw new Error("Cloudflare uploader capsule root is not a private operator-owned directory");
  }
  const ancestorChain = captureAncestorChain(capsuleRoot, owner);

  const records = [];
  const bytesByPath = new Map();
  let jsonTotalBytes = 0;
  let totalBytes = 0;
  function addRecord(record) {
    if (records.length >= normalizedLimits.maxEntries) {
      throw new Error("Cloudflare uploader capsule exceeds its entry-count bound");
    }
    totalBytes += record.size || 0;
    if (totalBytes > normalizedLimits.maxTotalBytes) {
      throw new Error("Cloudflare uploader capsule exceeds its total-byte bound");
    }
    records.push(Object.freeze(record));
  }
  function visit(absolute, expectedMetadata = null) {
    if (records.length >= normalizedLimits.maxEntries) {
      throw new Error("Cloudflare uploader capsule exceeds its entry-count bound");
    }
    const relative = relativePath(capsuleRoot, absolute);
    assertPathBound(relative, normalizedLimits);
    if (isCredentialPath(relative)) {
      throw new Error("Cloudflare uploader capsule contains a forbidden credential-bearing path");
    }
    const named = fs.lstatSync(absolute, { bigint: true });
    if (expectedMetadata && !sameMetadata(expectedMetadata, named)) {
      throw new Error("Cloudflare uploader capsule root changed before traversal");
    }
    const mode = permissionMode(named);
    if (named.isDirectory() && !named.isSymbolicLink()) {
      if (!safeOwnedMode(named, owner, { directory: true })) {
        throw new Error("Cloudflare uploader capsule contains an unsafe directory");
      }
      const rawNames = fs.readdirSync(absolute, { encoding: "buffer" });
      hooks?.afterDirectoryRead?.(absolute);
      const names = rawNames.map(decodeEntryName);
      if (new Set(names.map((name) => name.toLowerCase())).size !== names.length) {
        throw new Error("Cloudflare uploader capsule contains a case-folding path collision");
      }
      names.sort(compareUtf8);
      if (relative === "." && JSON.stringify(names) !== JSON.stringify(EXPECTED_ROOT_ENTRIES)) {
        throw new Error("Cloudflare uploader capsule root contains undeclared files or configuration");
      }
      for (const name of names) {
        const childRelative = relative === "." ? name : `${relative}/${name}`;
        assertPathBound(childRelative, normalizedLimits);
        if (isCredentialPath(childRelative)) {
          throw new Error("Cloudflare uploader capsule contains a forbidden credential-bearing path");
        }
      }
      addRecord({
        mode,
        path: relative,
        sha256: EMPTY_SHA256,
        size: 0,
        type: "directory",
      });
      for (const name of names) visit(path.join(absolute, name));
      const after = fs.lstatSync(absolute, { bigint: true });
      if (!sameMetadata(named, after)) {
        throw new Error("Cloudflare uploader capsule directory changed during projection");
      }
      return;
    }
    if (named.isFile() && !named.isSymbolicLink()) {
      if (named.size > BigInt(normalizedLimits.maxFileBytes)) {
        throw new Error("Cloudflare uploader capsule exceeds its per-file byte bound");
      }
      if (totalBytes + Number(named.size) > normalizedLimits.maxTotalBytes) {
        throw new Error("Cloudflare uploader capsule exceeds its total-byte bound");
      }
      const retainBytes = isRetainedJsonDescriptor(relative);
      if (retainBytes) {
        if (named.size > BigInt(normalizedLimits.maxJsonFileBytes)) {
          throw new Error("Cloudflare uploader capsule exceeds its JSON descriptor byte bound");
        }
        jsonTotalBytes += Number(named.size);
        if (jsonTotalBytes > normalizedLimits.maxJsonTotalBytes) {
          throw new Error("Cloudflare uploader capsule exceeds its total JSON byte bound");
        }
      }
      const stable = stableRegularFile(
        absolute,
        named,
        owner,
        normalizedLimits,
        hooks,
        { retainBytes },
      );
      const classification = classifyFile(relative, stable.header, mode);
      if (retainBytes) bytesByPath.set(relative, stable.bytes);
      addRecord({
        executable: classification.executable,
        kind: classification.kind,
        mode,
        path: relative,
        sha256: stable.sha256,
        size: stable.size,
        type: "file",
      });
      return;
    }
    if (named.isSymbolicLink()) {
      const { resolved, target, targetBytes } = stableSymlink(
        absolute,
        relative,
        named,
        owner,
        normalizedLimits,
        hooks,
      );
      addRecord({
        mode,
        path: relative,
        resolvedTarget: resolved,
        sha256: sha256(targetBytes),
        size: targetBytes.length,
        target,
        type: "symlink",
      });
      return;
    }
    throw new Error("Cloudflare uploader capsule contains an unsupported filesystem entry");
  }
  hooks?.beforeTraversal?.(capsuleRoot);
  visit(capsuleRoot, rootMetadata);
  assertAncestorChainStable(ancestorChain);
  records.sort((left, right) => compareUtf8(left.path, right.path));
  const recordsByPath = new Map(records.map((record) => [record.path, record]));
  for (const record of records) {
    if (record.type === "symlink") resolveManifestSymlink(recordsByPath, record.path);
  }
  let packageBytes = bytesByPath.get("package.json");
  let lockBytes = bytesByPath.get("package-lock.json");
  if (!packageBytes || !lockBytes || recordsByPath.get("node_modules")?.type !== "directory") {
    throw new Error("Cloudflare uploader capsule is missing its exact root descriptors");
  }
  const root = normalizeRootAndLock(
    packageBytes,
    lockBytes,
    runtime,
    normalizedLimits,
  );
  bytesByPath.delete("package.json");
  bytesByPath.delete("package-lock.json");
  packageBytes = null;
  lockBytes = null;
  const lockPackageCount = root.packagePaths.length - 1;
  const installed = validateInstalledDependencyTree({
    bytesByPath,
    lock: root.lock,
    packagePaths: root.packagePaths,
    records,
    recordsByPath,
    runtime,
    limits: normalizedLimits,
  });
  bytesByPath.clear();
  root.lock = null;
  root.packagePaths = null;
  const nativeFiles = records
    .filter(({ kind }) => String(kind || "").startsWith("native_"))
    .map(({ kind, path: recordPath, sha256: digest, size }) => ({
      kind,
      path: recordPath,
      sha256: digest,
      size,
    }));
  const wasmFiles = records
    .filter(({ kind }) => kind === "wasm")
    .map(({ path: recordPath, sha256: digest, size }) => ({
      path: recordPath,
      sha256: digest,
      size,
    }));
  const executableFiles = records
    .filter(({ executable }) => executable)
    .map(({ kind, path: recordPath, sha256: digest, size }) => ({
      kind,
      path: recordPath,
      sha256: digest,
      size,
    }));
  const symlinks = records
    .filter(({ type }) => type === "symlink")
    .map(({ path: recordPath, resolvedTarget, target }) => ({
      path: recordPath,
      resolvedTarget,
      target,
    }));
  const kindCounts = Object.fromEntries([...new Set(
    records.filter(({ type }) => type === "file").map(({ kind }) => kind),
  )].sort().map((kind) => [kind, records.filter((entry) => entry.kind === kind).length]));

  const manifest = deepFreeze({
    capabilities: Object.freeze({
      binaryEntrypoints: installed.binaryEntrypoints,
      executableFiles: Object.freeze(executableFiles),
      installScriptPackages: root.installScriptPackages,
      kindCounts: Object.freeze(kindCounts),
      lifecycleScripts: installed.lifecycleScripts,
      nativeFiles: Object.freeze(nativeFiles),
      symlinks: Object.freeze(symlinks),
      wasmFiles: Object.freeze(wasmFiles),
    }),
    entryCount: records.length,
    installedPackageCount: installed.installedPackages.length,
    installedPackages: installed.installedPackages,
    jsonDescriptorBytes: jsonTotalBytes,
    limits: normalizedLimits,
    lockfile: Object.freeze({
      dependencyEdgeCount: root.dependencyEdgeCount,
      packageCount: lockPackageCount,
      sha256: recordsByPath.get("package-lock.json").sha256,
      size: recordsByPath.get("package-lock.json").size,
      version: 3,
    }),
    projectionPolicy: Object.freeze({
      allowedRootEntries: EXPECTED_ROOT_ENTRIES,
      ancestorTraversal: "canonical_directory_identity_chain_rechecked_not_descriptor_relative",
      credentialInputs: "no_external_credential_api_known_credential_paths_denied_dependency_content_not_semantically_classified",
      directoryStability: "lstat_metadata_before_and_after_recursive_scan",
      byteScope: "regular_file_contents_symlink_targets_paths_and_permission_modes",
      consumptionAtomicity: "not_provided_integrator_must_consume_the_same_pinned_snapshot",
      concurrentSameUidPathSwap: "out_of_scope_production_blocker_requires_immutable_snapshot_or_descriptor_relative_traversal",
      hardlinks: "rejected",
      nativeAndWasm: "leading_magic_classified_and_digest_bound_not_format_validated",
      nativeDynamicClosure: "not_projected_requires_external_platform_gate",
      npmRuntimeIdentity: "caller_supplied_version_bound_to_package_manager_external_runtime_proof_required",
      ordinaryFileMemory: "stream_hashed_with_leading_header_only_not_retained",
      registryIntegrity: "lock_declaration_only_external_offline_cache_integrity_and_npm_ci_proof_required",
      dependencySemantics: "installed_regular_dependency_maps_compared_and_required_targets_present_not_full_npm_resolution",
      regularFiles: "single_link_open_nofollow_fstat_stable_read",
      repetition: "two_identical_complete_projections",
      symlinks: "target_text_hashed_and_manifest_only_resolution",
      extendedAttributesAndAcl: "not_projected_requires_external_gate",
    }),
    records: Object.freeze(records),
    rootPackage: Object.freeze({
      name: root.rootPackage.name,
      nodeEngine: root.rootPackage.engines.node,
      packageManager: root.rootPackage.packageManager,
      sha256: recordsByPath.get("package.json").sha256,
      size: recordsByPath.get("package.json").size,
      version: root.rootPackage.version,
      wranglerSpec: root.rootPackage.dependencies.wrangler,
    }),
    runtime,
    schema: CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA,
    totalBytes,
    truthStatus: CLOUDFLARE_UPLOADER_CAPSULE_TRUTH_STATUS,
    wrangler: installed.wrangler,
  });
  const manifestText = canonicalText(manifest);
  const manifestByteLength = Buffer.byteLength(manifestText, "utf8");
  if (manifestByteLength > normalizedLimits.maxManifestBytes) {
    throw new Error("Cloudflare uploader capsule exceeds its manifest-byte bound");
  }
  return Object.freeze({
    manifest,
    manifestByteLength,
    manifestSha256: sha256(Buffer.from(
      `${CLOUDFLARE_UPLOADER_CAPSULE_DOMAIN}${manifestText}`,
      "utf8",
    )),
  });
}

function repeatedProjection(options, betweenProjections) {
  let first = projectOnce(options);
  betweenProjections?.(first);
  const firstManifestSha256 = first.manifestSha256;
  const firstManifestByteLength = first.manifestByteLength;
  first = null;
  const second = projectOnce(options);
  if (
    firstManifestSha256 !== second.manifestSha256
    || firstManifestByteLength !== second.manifestByteLength
  ) {
    throw new Error("Cloudflare uploader capsule changed between repeated projections");
  }
  return second;
}

function productionProjectionOptions(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Cloudflare uploader capsule projection options are invalid");
  }
  const allowed = new Set(["capsuleRoot", "expectedOwner", "limits", "runtimeIdentity"]);
  if (
    !Object.hasOwn(value, "capsuleRoot")
    || !Object.hasOwn(value, "runtimeIdentity")
    || Object.keys(value).some((key) => !allowed.has(key))
  ) {
    throw new Error("Cloudflare uploader capsule projection options are not exact");
  }
  return Object.freeze({
    capsuleRoot: value.capsuleRoot,
    ...(Object.hasOwn(value, "expectedOwner") ? { expectedOwner: value.expectedOwner } : {}),
    ...(Object.hasOwn(value, "limits") ? { limits: value.limits } : {}),
    runtimeIdentity: value.runtimeIdentity,
  });
}

export function projectCloudflareUploaderCapsule(options) {
  return repeatedProjection(productionProjectionOptions(options));
}

export function normalizeCloudflareUploaderCapsulePin(value) {
  exactObjectKeys(value, EXPECTED_PIN_KEYS, "Cloudflare uploader capsule pin");
  if (
    value.schema !== CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA
    || !SHA256.test(value.manifestSha256)
    || !NODE_VERSION.test(value.nodeVersion)
    || !EXACT_SEMVER.test(value.npmVersion)
    || !EXACT_SEMVER.test(value.wranglerVersion)
    || typeof value.osPlatform !== "string"
    || !value.osPlatform
    || typeof value.osRelease !== "string"
    || !value.osRelease
    || typeof value.architecture !== "string"
    || !value.architecture
    || hasUnsafeUnicode(value.osPlatform)
    || hasUnsafeUnicode(value.osRelease)
    || hasUnsafeUnicode(value.architecture)
  ) {
    throw new Error("Cloudflare uploader capsule pin is invalid");
  }
  safeInteger(value.entryCount, "Cloudflare uploader pinned entry count", {
    minimum: 4,
    maximum: CLOUDFLARE_UPLOADER_CAPSULE_LIMITS.maxEntries,
  });
  safeInteger(value.manifestByteLength, "Cloudflare uploader pinned manifest bytes", {
    minimum: 1,
    maximum: CLOUDFLARE_UPLOADER_CAPSULE_LIMITS.maxManifestBytes,
  });
  safeInteger(value.totalBytes, "Cloudflare uploader pinned total bytes", {
    minimum: 3,
    maximum: CLOUDFLARE_UPLOADER_CAPSULE_LIMITS.maxTotalBytes,
  });
  return Object.freeze({ ...value });
}

export function pinCloudflareUploaderCapsule(projection) {
  if (
    !projection
    || typeof projection !== "object"
    || Array.isArray(projection)
    || !projection.manifest
    || projection.manifest.schema !== CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA
    || projection.manifest.truthStatus !== CLOUDFLARE_UPLOADER_CAPSULE_TRUTH_STATUS
    || !SHA256.test(String(projection.manifestSha256 || ""))
    || !Number.isSafeInteger(projection.manifestByteLength)
  ) {
    throw new Error("Cloudflare uploader capsule projection is invalid");
  }
  const { manifest } = projection;
  const manifestText = canonicalText(manifest);
  const recomputed = sha256(Buffer.from(
    `${CLOUDFLARE_UPLOADER_CAPSULE_DOMAIN}${manifestText}`,
    "utf8",
  ));
  if (
    recomputed !== projection.manifestSha256
    || Buffer.byteLength(manifestText, "utf8") !== projection.manifestByteLength
  ) {
    throw new Error("Cloudflare uploader capsule manifest digest is invalid");
  }
  return normalizeCloudflareUploaderCapsulePin({
    architecture: manifest.runtime.architecture,
    entryCount: manifest.entryCount,
    manifestByteLength: projection.manifestByteLength,
    manifestSha256: projection.manifestSha256,
    nodeVersion: manifest.runtime.nodeVersion,
    npmVersion: manifest.runtime.npmVersion,
    osPlatform: manifest.runtime.osPlatform,
    osRelease: manifest.runtime.osRelease,
    schema: manifest.schema,
    totalBytes: manifest.totalBytes,
    wranglerVersion: manifest.runtime.wranglerVersion,
  });
}

export function assertPinnedCloudflareUploaderCapsule(options, expectedPin) {
  const pin = normalizeCloudflareUploaderCapsulePin(expectedPin);
  const projection = projectCloudflareUploaderCapsule(options);
  const actual = pinCloudflareUploaderCapsule(projection);
  if (canonicalText(actual) !== canonicalText(pin)) {
    throw new Error("Cloudflare uploader capsule does not match its exact reviewed pin");
  }
  return projection;
}

export const __test = Object.freeze({
  EMPTY_SHA256,
  classifyFile,
  normalizeLimits,
  parseDuplicateFreeJson,
  projectOnce,
  repeatedProjection,
  resolveManifestSymlink,
});
