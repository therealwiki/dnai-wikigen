import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const NPM_TREE_DOMAIN = "dnai.cloudflare-release-npm-runtime-tree.v1\0";
const NODE_DYLIB_DOMAIN = "dnai.cloudflare-release-node-dylib-closure.v1\0";
const EMPTY_SHA256 = createHash("sha256").update("").digest("hex");
const MAX_RUNTIME_FILE_BYTES = 96 * 1024 * 1024;
const MAX_NPM_TREE_ENTRIES = 10_000;
const MAX_NPM_TREE_BYTES = 128 * 1024 * 1024;

export const PINNED_NODE_RUNTIME = Object.freeze({
  version: "v24.9.0",
  executablePath: "/opt/homebrew/Cellar/node/24.9.0/bin/node",
  executableMode: 0o555,
  executableSize: 64_221_968,
  executableSha256:
    "3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7",
});

export const PINNED_NODE_HOMEBREW_DYLIBS = Object.freeze([
  ["/opt/homebrew/Cellar/brotli/1.1.0/lib/libbrotlicommon.1.1.0.dylib", 0o444, 167_264, "aaa328b3f04c1d14930d58814b2136b66e5bfe9044d6b58fbdf8ef3288cdeed7"],
  ["/opt/homebrew/Cellar/brotli/1.1.0/lib/libbrotlidec.1.1.0.dylib", 0o444, 87_680, "a04e56310579188f623d69c864f42a20c2d5bfdc24f754f06a2948de27c0e133"],
  ["/opt/homebrew/Cellar/brotli/1.1.0/lib/libbrotlienc.1.1.0.dylib", 0o444, 636_400, "af95ba6b409e89e68daee682220b7e97e9c40f24b624810c0a53355d107b3897"],
  ["/opt/homebrew/Cellar/c-ares/1.34.5/lib/libcares.2.19.4.dylib", 0o444, 243_312, "cae761b573c066f64804293a669b2ca0cdb51845934977a92c294d994d8ddef1"],
  ["/opt/homebrew/Cellar/icu4c@77/77.1/lib/libicudata.77.1.dylib", 0o444, 31_980_336, "780d2feeb6227ffcd9a62b0a9c782fbe42703b20fdb8247a8dc95803744d5b5a"],
  ["/opt/homebrew/Cellar/icu4c@77/77.1/lib/libicui18n.77.1.dylib", 0o444, 3_135_104, "d1b7ac6ba6501e96055ad276e2f6db7ff9d77acb2889c154eb09c49036147241"],
  ["/opt/homebrew/Cellar/icu4c@77/77.1/lib/libicuuc.77.1.dylib", 0o444, 1_830_208, "46c94b8b7b928983fe53fceb5cf2dfade2e9be9e19484d35563041e7b616ae5e"],
  ["/opt/homebrew/Cellar/libnghttp2/1.68.0/lib/libnghttp2.14.dylib", 0o444, 201_024, "eb958b5285712d474a6542d59be092361057e8abc7a03f0dccf0282417faacbf"],
  ["/opt/homebrew/Cellar/libnghttp3/1.12.0/lib/libnghttp3.9.4.0.dylib", 0o444, 199_376, "7207ada46a256dfabd3693837044bb06e9dbe82425183b037e69919e4ac10c85"],
  ["/opt/homebrew/Cellar/libngtcp2/1.16.0/lib/libngtcp2.16.dylib", 0o444, 344_704, "9ef6db487c21e94f32b9832e7bb8b30450aee2ff2968a07c8ed1cfcda6cc17df"],
  ["/opt/homebrew/Cellar/libuv/1.51.0/lib/libuv.1.0.0.dylib", 0o444, 206_000, "b8ce5e8e33c51db3a2d5ec5e21624b0116dde85b72bef5ce6a49279062b181b6"],
  ["/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libcrypto.3.dylib", 0o444, 4_856_256, "a12805a18cd5e4f733fa8727b91afa08b587f9da5a760517cd79cb508a3a3f71"],
  ["/opt/homebrew/Cellar/openssl@3/3.6.3/lib/libssl.3.dylib", 0o444, 872_080, "ffd8ac6981000def0928367924b6cb1e7a98712efbc06e2a2f3f750138bd89ca"],
  ["/opt/homebrew/Cellar/simdjson/3.13.0/lib/libsimdjson.26.0.0.dylib", 0o444, 112_448, "ae963b3fb0b996afdfb1f6c22ef16b32ab26613151e32eda2554189403758538"],
  ["/opt/homebrew/Cellar/sqlite/3.53.1/lib/libsqlite3.3.53.1.dylib", 0o444, 1_270_336, "e25fd720937eaeba7bc831164fb1a6d0b03430bec9524b153906189afcc09e1e"],
  ["/opt/homebrew/Cellar/uvwasi/0.0.23/lib/libuvwasi.dylib", 0o444, 83_232, "c922288c5179279316b32b2c83d5c50d7b87216b442473ada8c99ef4a58ba312"],
  ["/opt/homebrew/Cellar/zstd/1.5.7_1/lib/libzstd.1.5.7.dylib", 0o444, 649_648, "e2847c4613b386683c234913ae3b7b04299254096caf7616e3b3cd9bb97a39ab"],
].map(([filePath, mode, size, sha256]) => Object.freeze({
  path: filePath,
  type: "file",
  mode,
  size,
  sha256,
})));
export const PINNED_NODE_DYLIB_CLOSURE_SHA256 =
  "9d7a826fa8ec4a1f1a2d3d4f3b0f02e36312440234cd4ce45f9581a6771721c7";

export const PINNED_NPM_RUNTIME = Object.freeze({
  version: "11.6.0",
  executableSymlink: "/opt/homebrew/Cellar/node/24.9.0/bin/npm",
  executableTarget: "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
  treeRoot: "/opt/homebrew/lib/node_modules/npm",
  entryCount: 2_857,
  totalBytes: 11_960_560,
  treeSha256: "417ff144368776eeaf8651a00ec0e3933db96278b1a7efe9e7f53817634c6289",
});
export const PINNED_RELEASE_RUNTIME_PROOF = Object.freeze({
  nodeVersion: PINNED_NODE_RUNTIME.version,
  nodeExecutablePath: PINNED_NODE_RUNTIME.executablePath,
  nodeExecutableSha256: PINNED_NODE_RUNTIME.executableSha256,
  nodeDylibClosureSha256: PINNED_NODE_DYLIB_CLOSURE_SHA256,
  npmVersion: PINNED_NPM_RUNTIME.version,
  npmTreeSha256: PINNED_NPM_RUNTIME.treeSha256,
  npmEntryCount: PINNED_NPM_RUNTIME.entryCount,
  npmTotalBytes: PINNED_NPM_RUNTIME.totalBytes,
});

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function domainHash(domain, value) {
  return createHash("sha256")
    .update(domain, "utf8")
    .update(canonicalText(value), "utf8")
    .digest("hex");
}

function safeMode(mode, { directory = false } = {}) {
  return Number.isSafeInteger(mode)
    && mode >= 0
    && mode <= 0o777
    && (mode & 0o400) !== 0
    && (!directory || (mode & 0o100) !== 0)
    && (mode & 0o022) === 0;
}

function expectedOwner(expectedUid) {
  if (!Number.isSafeInteger(expectedUid) || expectedUid < 0) {
    throw new Error("release runtime expected owner is invalid");
  }
  return BigInt(expectedUid);
}

function stableRegularFile(filePath, {
  expectedUid,
  minimumBytes = 1,
  maximumBytes,
  label,
}) {
  if (
    typeof filePath !== "string"
    || !path.isAbsolute(filePath)
    || path.resolve(filePath) !== filePath
    || path.normalize(filePath) !== filePath
    || fs.realpathSync.native(filePath) !== filePath
  ) {
    throw new Error(`${label} path is aliased or noncanonical`);
  }
  const named = fs.lstatSync(filePath, { bigint: true });
  const mode = Number(named.mode & 0o777n);
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || named.uid !== expectedOwner(expectedUid)
    || !safeMode(mode)
    || named.size < BigInt(minimumBytes)
    || named.size > BigInt(maximumBytes)
  ) {
    throw new Error(`${label} is not a bounded owner-controlled single-link file`);
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ["dev", "ino", "size", "nlink", "uid", "gid", "mode"]) {
      if (before[field] !== named[field]) throw new Error(`${label} changed while opening`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) throw new Error(`${label} changed during read`);
    }
    if (BigInt(bytes.length) !== before.size) throw new Error(`${label} changed size during read`);
    return Object.freeze({
      bytes,
      mode,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
  } finally {
    fs.closeSync(descriptor);
  }
}

function stableDirectoryMetadata(directory, expectedUid, label) {
  const metadata = fs.lstatSync(directory, { bigint: true });
  const mode = Number(metadata.mode & 0o777n);
  if (
    !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedOwner(expectedUid)
    || !safeMode(mode, { directory: true })
  ) {
    throw new Error(`${label} is not an owner-controlled directory`);
  }
  return { metadata, mode };
}

function assertStableMetadata(before, after, label) {
  for (const field of [
    "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
  ]) {
    if (before[field] !== after[field]) throw new Error(`${label} changed during projection`);
  }
}

function relativeRuntimePath(root, absolute) {
  if (absolute === root) return ".";
  const relative = path.relative(root, absolute).split(path.sep).join("/");
  if (!relative || relative.startsWith("../") || relative.includes("\\")) {
    throw new Error("npm runtime entry escapes its canonical tree");
  }
  return relative;
}

export function projectNpmRuntimeTree(treeRoot, {
  expectedUid = typeof process.geteuid === "function" ? process.geteuid() : 0,
} = {}) {
  if (
    typeof treeRoot !== "string"
    || !path.isAbsolute(treeRoot)
    || path.resolve(treeRoot) !== treeRoot
    || path.normalize(treeRoot) !== treeRoot
    || fs.realpathSync.native(treeRoot) !== treeRoot
  ) {
    throw new Error("npm runtime tree root is aliased or noncanonical");
  }
  const records = [];
  let totalBytes = 0;
  function visit(absolute) {
    const relative = relativeRuntimePath(treeRoot, absolute);
    const named = fs.lstatSync(absolute, { bigint: true });
    const mode = Number(named.mode & 0o777n);
    if (named.uid !== expectedOwner(expectedUid) || !safeMode(mode, {
      directory: named.isDirectory(),
    })) {
      throw new Error("npm runtime tree entry has unsafe owner or mode");
    }
    if (named.isDirectory()) {
      const { metadata } = stableDirectoryMetadata(
        absolute,
        expectedUid,
        "npm runtime directory",
      );
      const entries = fs.readdirSync(absolute, { withFileTypes: true })
        .sort((left, right) => left.name.localeCompare(right.name, "en"));
      assertStableMetadata(
        metadata,
        fs.lstatSync(absolute, { bigint: true }),
        "npm runtime directory",
      );
      records.push({
        path: relative,
        type: "directory",
        mode,
        size: Number(named.size),
        sha256: EMPTY_SHA256,
      });
      for (const entry of entries) visit(path.join(absolute, entry.name));
    } else if (named.isFile()) {
      if (named.nlink !== 1n) throw new Error("npm runtime tree contains a hard-linked file");
      const stable = stableRegularFile(absolute, {
        expectedUid,
        minimumBytes: 0,
        maximumBytes: MAX_RUNTIME_FILE_BYTES,
        label: "npm runtime file",
      });
      records.push({
        path: relative,
        type: "file",
        mode: stable.mode,
        size: stable.size,
        sha256: stable.sha256,
      });
    } else if (named.isSymbolicLink()) {
      if (named.nlink !== 1n) throw new Error("npm runtime tree contains an unsafe symlink");
      const target = fs.readlinkSync(absolute, "utf8");
      const after = fs.lstatSync(absolute, { bigint: true });
      assertStableMetadata(named, after, "npm runtime symlink");
      if (path.isAbsolute(target) || target.includes("\0")) {
        throw new Error("npm runtime tree contains an absolute or invalid symlink");
      }
      const resolved = fs.realpathSync.native(absolute);
      if (!resolved.startsWith(`${treeRoot}${path.sep}`)) {
        throw new Error("npm runtime tree symlink escapes its canonical tree");
      }
      const targetMetadata = fs.lstatSync(resolved);
      if (!targetMetadata.isFile() || targetMetadata.isSymbolicLink()) {
        throw new Error("npm runtime tree symlink does not resolve to a regular file");
      }
      const targetBytes = Buffer.from(target, "utf8");
      records.push({
        path: relative,
        type: "symlink",
        mode,
        size: targetBytes.length,
        sha256: createHash("sha256").update(targetBytes).digest("hex"),
      });
    } else {
      throw new Error("npm runtime tree contains an unsupported filesystem entry");
    }
    if (records.length > MAX_NPM_TREE_ENTRIES) {
      throw new Error("npm runtime tree exceeds its entry bound");
    }
  }
  visit(treeRoot);
  records.sort((left, right) => left.path.localeCompare(right.path, "en"));
  totalBytes = records.reduce((sum, entry) => sum + entry.size, 0);
  if (totalBytes > MAX_NPM_TREE_BYTES) {
    throw new Error("npm runtime tree exceeds its byte bound");
  }
  const payload = Object.freeze({
    records: Object.freeze(records.map((entry) => Object.freeze(entry))),
  });
  return Object.freeze({
    ...payload,
    entryCount: records.length,
    totalBytes,
    treeSha256: domainHash(NPM_TREE_DOMAIN, payload),
  });
}

function readNpmPackageVersion(treeRoot, expectedUid) {
  const descriptor = stableRegularFile(path.join(treeRoot, "package.json"), {
    expectedUid,
    maximumBytes: 256 * 1024,
    label: "npm package descriptor",
  });
  let value;
  try {
    value = JSON.parse(descriptor.bytes.toString("utf8"));
  } catch {
    throw new Error("npm package descriptor is not JSON");
  }
  if (value?.name !== "npm" || typeof value.version !== "string") {
    throw new Error("npm package descriptor identity is invalid");
  }
  return value.version;
}

export function assertPinnedNpmRuntime({
  pin = PINNED_NPM_RUNTIME,
  expectedUid = typeof process.geteuid === "function" ? process.geteuid() : 0,
} = {}) {
  const symlink = fs.lstatSync(pin.executableSymlink, { bigint: true });
  const mode = Number(symlink.mode & 0o777n);
  const executableTarget = fs.readlinkSync(pin.executableSymlink, "utf8");
  const resolvedExecutable = fs.realpathSync.native(pin.executableSymlink);
  assertStableMetadata(
    symlink,
    fs.lstatSync(pin.executableSymlink, { bigint: true }),
    "npm executable symlink",
  );
  if (
    !symlink.isSymbolicLink()
    || symlink.nlink !== 1n
    || symlink.uid !== expectedOwner(expectedUid)
    || !safeMode(mode)
    || executableTarget !== pin.executableTarget
    || resolvedExecutable !== pin.executableTarget
  ) {
    throw new Error("npm executable symlink does not match the reviewed target");
  }
  const first = projectNpmRuntimeTree(pin.treeRoot, { expectedUid });
  const second = projectNpmRuntimeTree(pin.treeRoot, { expectedUid });
  if (canonicalText(first) !== canonicalText(second)) {
    throw new Error("npm runtime tree changed during its repeated projection");
  }
  const version = readNpmPackageVersion(pin.treeRoot, expectedUid);
  if (version !== pin.version) throw new Error(`npm runtime version must be exactly ${pin.version}`);
  if (
    first.entryCount !== pin.entryCount
    || first.totalBytes !== pin.totalBytes
    || first.treeSha256 !== pin.treeSha256
  ) {
    throw new Error("npm runtime tree does not match the reviewed exact manifest");
  }
  return Object.freeze({
    version,
    treeSha256: first.treeSha256,
    entryCount: first.entryCount,
    totalBytes: first.totalBytes,
  });
}

function defaultOtool(filePath) {
  try {
    return execFileSync("/usr/bin/otool", ["-L", filePath], {
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
      maxBuffer: 4 * 1024 * 1024,
    });
  } catch {
    throw new Error("Node dynamic dependency inventory could not be inspected safely");
  }
}

function homebrewDynamicDependencies(filePath, otool) {
  const output = otool(filePath);
  if (typeof output !== "string" || !output.startsWith(`${filePath}:\n`)) {
    throw new Error("Node dynamic dependency inventory returned an invalid header");
  }
  const dependencies = [];
  for (const line of output.split("\n").slice(1)) {
    if (!line.trim()) continue;
    const match = /^\s*(\S+) \(compatibility version [^)]+\)$/.exec(line);
    if (!match) throw new Error("Node dynamic dependency inventory is malformed");
    const requested = match[1];
    if (requested.startsWith("/usr/lib/") || requested.startsWith("/System/Library/")) {
      continue;
    }
    let requestedPath = requested;
    if (requested.startsWith("@loader_path/")) {
      requestedPath = path.join(
        path.dirname(filePath),
        requested.slice("@loader_path/".length),
      );
    } else if (!requested.startsWith("/opt/homebrew/")) {
      throw new Error("Node has an unreviewed non-system dynamic dependency");
    }
    let resolved;
    try {
      resolved = fs.realpathSync.native(requestedPath);
    } catch {
      throw new Error("Node Homebrew dynamic dependency cannot be resolved");
    }
    if (!resolved.startsWith("/opt/homebrew/Cellar/")) {
      throw new Error("Node Homebrew dynamic dependency does not resolve into Cellar");
    }
    dependencies.push(resolved);
  }
  return dependencies;
}

export function assertPinnedNodeRuntime({
  pin = PINNED_NODE_RUNTIME,
  dylibPins = PINNED_NODE_HOMEBREW_DYLIBS,
  executablePath = process.execPath,
  version = process.version,
  expectedUid = typeof process.geteuid === "function" ? process.geteuid() : 0,
  otool = defaultOtool,
} = {}) {
  if (version !== pin.version) {
    throw new Error(`Cloudflare release Node version must be exactly ${pin.version}`);
  }
  if (executablePath !== pin.executablePath) {
    throw new Error("Cloudflare release Node executable path is not reviewed");
  }
  const executable = stableRegularFile(executablePath, {
    expectedUid,
    maximumBytes: MAX_RUNTIME_FILE_BYTES,
    label: "Cloudflare release Node executable",
  });
  if (
    executable.mode !== pin.executableMode
    || executable.size !== pin.executableSize
    || executable.sha256 !== pin.executableSha256
  ) {
    throw new Error("Cloudflare release Node executable does not match the reviewed bytes");
  }

  const discovered = new Set();
  const queue = [executablePath];
  while (queue.length) {
    const current = queue.shift();
    for (const dependency of homebrewDynamicDependencies(current, otool)) {
      if (!discovered.has(dependency)) {
        discovered.add(dependency);
        queue.push(dependency);
      }
    }
  }
  const discoveredPaths = [...discovered].sort();
  const expectedPaths = dylibPins.map((entry) => entry.path).sort();
  if (JSON.stringify(discoveredPaths) !== JSON.stringify(expectedPaths)) {
    throw new Error("Node Homebrew dynamic dependency closure is not exact");
  }
  const records = dylibPins.map((entry) => {
    const stable = stableRegularFile(entry.path, {
      expectedUid,
      maximumBytes: MAX_RUNTIME_FILE_BYTES,
      label: "Node Homebrew dynamic dependency",
    });
    if (
      entry.type !== "file"
      || stable.mode !== entry.mode
      || stable.size !== entry.size
      || stable.sha256 !== entry.sha256
    ) {
      throw new Error("Node Homebrew dynamic dependency does not match its reviewed pin");
    }
    return entry;
  }).sort((left, right) => left.path.localeCompare(right.path, "en"));
  const dylibClosureSha256 = domainHash(NODE_DYLIB_DOMAIN, { records });
  if (dylibClosureSha256 !== PINNED_NODE_DYLIB_CLOSURE_SHA256) {
    throw new Error("Node Homebrew dynamic dependency manifest digest is not reviewed");
  }
  return Object.freeze({
    version: pin.version,
    executablePath: pin.executablePath,
    executableSha256: pin.executableSha256,
    dylibClosureSha256,
    dylibCount: records.length,
  });
}

export function normalizePinnedReleaseRuntimeProof(value) {
  const expectedKeys = [
    "nodeDylibClosureSha256", "nodeExecutablePath", "nodeExecutableSha256",
    "nodeVersion", "npmEntryCount", "npmTotalBytes", "npmTreeSha256", "npmVersion",
  ].sort();
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expectedKeys)
    || value.nodeVersion !== PINNED_NODE_RUNTIME.version
    || value.nodeExecutablePath !== PINNED_NODE_RUNTIME.executablePath
    || value.nodeExecutableSha256 !== PINNED_NODE_RUNTIME.executableSha256
    || value.nodeDylibClosureSha256 !== PINNED_NODE_DYLIB_CLOSURE_SHA256
    || value.npmVersion !== PINNED_NPM_RUNTIME.version
    || value.npmTreeSha256 !== PINNED_NPM_RUNTIME.treeSha256
    || value.npmEntryCount !== PINNED_NPM_RUNTIME.entryCount
    || value.npmTotalBytes !== PINNED_NPM_RUNTIME.totalBytes
  ) {
    throw new Error("Cloudflare release runtime proof is not the reviewed exact pin set");
  }
  return Object.freeze({ ...value });
}

export function assertPinnedReleaseRuntime() {
  const node = assertPinnedNodeRuntime();
  const npm = assertPinnedNpmRuntime();
  return normalizePinnedReleaseRuntimeProof({
    nodeVersion: node.version,
    nodeExecutablePath: node.executablePath,
    nodeExecutableSha256: node.executableSha256,
    nodeDylibClosureSha256: node.dylibClosureSha256,
    npmVersion: npm.version,
    npmTreeSha256: npm.treeSha256,
    npmEntryCount: npm.entryCount,
    npmTotalBytes: npm.totalBytes,
  });
}

export const __test = Object.freeze({
  EMPTY_SHA256,
  NODE_DYLIB_DOMAIN,
  NPM_TREE_DOMAIN,
  defaultOtool,
  stableRegularFile,
});
