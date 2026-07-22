import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import {
  cloudflareSourceFingerprint,
  cloudflareUploadControlFingerprint,
} from "./cloudflare-release-artifact-core.mjs";
import {
  canonicalCloudflareExternalBuildClosureText,
  cloudflareExternalBuildClosureSha256,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  normalizeCloudflareExternalBuildClosure,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";

export const CLOUDFLARE_BUILD_SANDBOX_EXECUTABLE = "/usr/bin/sandbox-exec";
export const CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA =
  "dnai.cloudflare-installed-dependency-tree.v1";
export const CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS =
  "pinned_npm_ci_offline_ignore_scripts_lock_projection";
const CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_DOMAIN =
  "dnai-wikigen/cloudflare-installed-dependency-tree/v1\0";
const PINNED_GIT_EXECUTABLE = "/usr/bin/git";
const MAX_SOURCE_FILES = 20_000;
const MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024;
const MAX_SOURCE_TOTAL_BYTES = 512 * 1024 * 1024;
const WEB_TOP_LEVEL_EXCLUSIONS = new Set([
  ".wrangler",
  "dist",
  "node_modules",
]);
const GENERATED_ENV_PATH = /(?:^|\/)\.env(?:\.|$)/;
const MAX_DEPENDENCY_LOCK_BYTES = 4 * 1024 * 1024;
const SHA512_INTEGRITY = /^sha512-[A-Za-z0-9+/]+={0,2}$/;

const GIT_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_AUTHOR_NAME: "Wikigen isolated release",
  GIT_AUTHOR_EMAIL: "release@invalid.local",
  GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "Wikigen isolated release",
  GIT_COMMITTER_EMAIL: "release@invalid.local",
  GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
});

function profileString(value, label) {
  const normalized = String(value || "");
  if (
    !path.isAbsolute(normalized)
    || path.resolve(normalized) !== normalized
    || path.normalize(normalized) !== normalized
    || /[\0\r\n]/.test(normalized)
  ) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return `"${normalized.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function canonicalNpmCacheRoot(value = path.join(homedir(), ".npm")) {
  return realpath(value).then((resolved) => {
    if (resolved !== path.resolve(value)) {
      throw new Error("Cloudflare build npm cache path is aliased");
    }
    return resolved;
  });
}

export function renderCloudflareBuildSandboxProfile({
  buildRoot,
  npmCacheRoot,
} = {}) {
  const build = profileString(buildRoot, "Cloudflare sandbox build root");
  const cache = profileString(npmCacheRoot, "Cloudflare sandbox npm cache root");
  const cacheContent = profileString(
    path.join(npmCacheRoot, "_cacache"),
    "Cloudflare sandbox npm content cache",
  );
  const home = profileString(path.dirname(npmCacheRoot), "Cloudflare sandbox cache owner home");
  return [
    "(version 1)",
    "(deny default)",
    '(import "system.sb")',
    "(allow process*)",
    "(allow signal)",
    // Only path-component metadata is exposed for the Homebrew toolchain and
    // the read-only npm content-addressed cache. No other operator-home bytes
    // are readable.
    `(allow file-read-metadata file-test-existence (subpath "/opt") (path-ancestors ${build}) (path-ancestors "/private/var/db/xcode_select_link") (path-ancestors "/Library/Developer/CommandLineTools") (literal "/Users") (literal ${home}) (literal ${cache}))`,
    // /usr/bin/git is Apple's immutable xcrun shim. Resolve it through the
    // root-owned Xcode-select link and read only the selected Command Line
    // Tools tree; do not expose the rest of /private/var/db or /Library.
    `(allow file-read* file-test-existence file-map-executable (subpath "/bin") (subpath "/sbin") (subpath "/usr/bin") (subpath "/private/var/select") (literal "/private/var/db/xcode_select_link") (subpath "/Library/Developer/CommandLineTools") (subpath "/opt/homebrew/Cellar") (subpath "/opt/homebrew/opt") (subpath "/opt/homebrew/lib/node_modules/npm") (subpath "/opt/homebrew/etc/openssl@3") (subpath ${build}) (subpath ${cacheContent}))`,
    `(allow file-write* (subpath ${build}))`,
    "(deny network*)",
    "",
  ].join("\n");
}

async function assertCanonicalPrivateDirectory(directory, label) {
  const canonical = await realpath(directory);
  const metadata = await lstat(directory);
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : metadata.uid;
  if (
    canonical !== directory
    || !metadata.isDirectory()
    || metadata.isSymbolicLink()
    || metadata.uid !== expectedUid
    || (metadata.mode & 0o077) !== 0
  ) {
    throw new Error(`${label} is not a private canonical operator-owned directory`);
  }
}

async function readStableSourceFile(source, metadata) {
  if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1
    || metadata.size > MAX_SOURCE_FILE_BYTES
    || (
      typeof process.geteuid === "function"
      && metadata.uid !== process.geteuid()
    )
    || (metadata.mode & 0o022) !== 0
  ) {
    throw new Error("isolated Cloudflare build source is not a bounded operator-owned file");
  }
  const handle = await open(
    source,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat({ bigint: true });
    if (
      before.dev !== BigInt(metadata.dev)
      || before.ino !== BigInt(metadata.ino)
      || before.size !== BigInt(metadata.size)
      || before.nlink !== BigInt(metadata.nlink)
      || before.mode !== BigInt(metadata.mode)
    ) {
      throw new Error("isolated Cloudflare build source changed while opening");
    }
    const content = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error("isolated Cloudflare build source changed during read");
      }
    }
    return content;
  } finally {
    await handle.close();
  }
}

function canonicalDependencyPath(value) {
  return (
    typeof value === "string"
    && value.startsWith("node_modules/")
    && !value.startsWith("node_modules//")
    && !value.endsWith("/")
    && !value.includes("\\")
    && !value.includes("\0")
    && value.split("/").every((part) => part && part !== "." && part !== "..")
  );
}

function parseDependencyLock(bytes, label) {
  if (
    !Buffer.isBuffer(bytes)
    || bytes.length < 2
    || bytes.length > MAX_DEPENDENCY_LOCK_BYTES
  ) {
    throw new Error(`${label} is not a bounded npm lock`);
  }
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || typeof value.name !== "string"
    || value.name.length < 1
    || typeof value.version !== "string"
    || value.version.length < 1
    || value.lockfileVersion !== 3
    || value.requires !== true
    || !value.packages
    || typeof value.packages !== "object"
    || Array.isArray(value.packages)
  ) {
    throw new Error(`${label} is not the reviewed npm lockfile-v3 tree`);
  }
  return value;
}

function dependencyDescriptor(value, dependencyPath, label) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || value.link === true
    || typeof value.version !== "string"
    || value.version.length < 1
    || typeof value.resolved !== "string"
    || !value.resolved.startsWith("https://registry.npmjs.org/")
    || !SHA512_INTEGRITY.test(String(value.integrity || ""))
  ) {
    throw new Error(`${label} dependency ${dependencyPath} is not registry- and integrity-pinned`);
  }
  return {
    path: dependencyPath,
    version: value.version,
    resolved: value.resolved,
    integrity: value.integrity,
  };
}

function dependencyProjection(sourceLock, installedLock) {
  const sourceRoot = sourceLock.packages[""];
  if (
    !sourceRoot
    || typeof sourceRoot !== "object"
    || Array.isArray(sourceRoot)
    || sourceRoot.name !== sourceLock.name
    || sourceRoot.version !== sourceLock.version
  ) {
    throw new Error("reviewed dependency lock is missing its exact root package");
  }
  const sourcePaths = Object.keys(sourceLock.packages)
    .filter((dependencyPath) => dependencyPath !== "")
    .sort((left, right) => left.localeCompare(right, "en"));
  const installedPaths = Object.keys(installedLock.packages)
    .sort((left, right) => left.localeCompare(right, "en"));
  if (
    sourcePaths.length < 1
    || JSON.stringify(sourcePaths) !== JSON.stringify(installedPaths)
    || sourceLock.name !== installedLock.name
    || sourceLock.version !== installedLock.version
  ) {
    throw new Error("installed dependency tree does not exactly project the reviewed lockfile");
  }
  return sourcePaths.map((dependencyPath) => {
    if (!canonicalDependencyPath(dependencyPath)) {
      throw new Error("reviewed dependency lock contains a noncanonical package path");
    }
    const source = dependencyDescriptor(
      sourceLock.packages[dependencyPath],
      dependencyPath,
      "reviewed",
    );
    const installed = dependencyDescriptor(
      installedLock.packages[dependencyPath],
      dependencyPath,
      "installed",
    );
    if (JSON.stringify(source) !== JSON.stringify(installed)) {
      throw new Error("installed dependency tree drifted from the reviewed version, URL, or integrity");
    }
    return source;
  });
}

/**
 * Project the npm-ci result without trusting mutable package code. npm's
 * hidden lock is compared to every exact registry URL and sha512 integrity in
 * the reviewed source lock. The resulting digest is compared across the
 * verification, artifact-build, and Wrangler workspaces.
 */
export async function projectCloudflareInstalledDependencyTree(webDirectory) {
  if (
    typeof webDirectory !== "string"
    || !path.isAbsolute(webDirectory)
    || path.resolve(webDirectory) !== webDirectory
    || path.normalize(webDirectory) !== webDirectory
    || await realpath(webDirectory) !== webDirectory
  ) {
    throw new Error("installed dependency tree requires a canonical absolute web directory");
  }
  const nodeModules = path.join(webDirectory, "node_modules");
  const nodeModulesMetadata = await lstat(nodeModules);
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : nodeModulesMetadata.uid;
  if (
    await realpath(nodeModules) !== nodeModules
    || !nodeModulesMetadata.isDirectory()
    || nodeModulesMetadata.isSymbolicLink()
    || nodeModulesMetadata.uid !== expectedUid
    || (nodeModulesMetadata.mode & 0o022) !== 0
  ) {
    throw new Error("installed dependency tree is not in an operator-owned canonical directory");
  }
  const sourcePath = path.join(webDirectory, "package-lock.json");
  const installedPath = path.join(nodeModules, ".package-lock.json");
  const [sourceMetadata, installedMetadata] = await Promise.all([
    lstat(sourcePath),
    lstat(installedPath),
  ]);
  if (
    installedMetadata.uid !== expectedUid
    || installedMetadata.size > MAX_DEPENDENCY_LOCK_BYTES
  ) {
    throw new Error("installed dependency lock is not bounded and operator-owned");
  }
  const [sourceBytes, installedBytes] = await Promise.all([
    readStableSourceFile(sourcePath, sourceMetadata),
    readStableSourceFile(installedPath, installedMetadata),
  ]);
  const projection = dependencyProjection(
    parseDependencyLock(sourceBytes, "reviewed package lock"),
    parseDependencyLock(installedBytes, "installed dependency lock"),
  );
  const payload = {
    schema: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
    truth_status: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
    package_count: projection.length,
    packages: projection,
  };
  return Object.freeze({
    schema: payload.schema,
    truth_status: payload.truth_status,
    packageCount: payload.package_count,
    sha256: `sha256:${createHash("sha256")
      .update(CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_DOMAIN, "utf8")
      .update(`${JSON.stringify(payload, null, 2)}\n`, "utf8")
      .digest("hex")}`,
  });
}

async function writeExclusiveFile(target, content, mode) {
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  const handle = await open(
    target,
    constants.O_WRONLY
      | constants.O_CREAT
      | constants.O_EXCL
      | (constants.O_NOFOLLOW || 0),
    mode & 0o777,
  );
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally {
    await handle.close();
  }
  await chmod(target, mode & 0o777);
}

async function copyStableTree(source, target, {
  exclude = () => false,
  counters,
  relativeRoot = "",
} = {}) {
  const sourceMetadata = await lstat(source);
  if (!sourceMetadata.isDirectory() || sourceMetadata.isSymbolicLink()) {
    throw new Error("isolated Cloudflare build source tree is not a real directory");
  }
  await mkdir(target, { recursive: false, mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const relative = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
    if (exclude(relative)) continue;
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    const metadata = await lstat(sourcePath);
    if (metadata.isSymbolicLink()) {
      throw new Error("isolated Cloudflare build source contains a symbolic link");
    }
    if (metadata.isDirectory()) {
      await copyStableTree(sourcePath, targetPath, {
        exclude,
        counters,
        relativeRoot: relative,
      });
      continue;
    }
    const content = await readStableSourceFile(sourcePath, metadata);
    counters.files += 1;
    counters.bytes += content.length;
    if (
      counters.files > MAX_SOURCE_FILES
      || counters.bytes > MAX_SOURCE_TOTAL_BYTES
    ) {
      throw new Error("isolated Cloudflare build source exceeds its bounded manifest");
    }
    await writeExclusiveFile(targetPath, content, metadata.mode);
  }
}

async function copyStableRelativeFile(repositoryRoot, workspaceRoot, relative, counters) {
  const source = path.join(repositoryRoot, ...relative.split("/"));
  const target = path.join(workspaceRoot, ...relative.split("/"));
  const metadata = await lstat(source);
  const content = await readStableSourceFile(source, metadata);
  counters.files += 1;
  counters.bytes += content.length;
  if (counters.files > MAX_SOURCE_FILES || counters.bytes > MAX_SOURCE_TOTAL_BYTES) {
    throw new Error("isolated Cloudflare build source exceeds its bounded manifest");
  }
  await writeExclusiveFile(target, content, metadata.mode);
}

async function assertOnlyDeclaredExternalFiles(workspaceRoot) {
  const actual = [];
  const expectedFiles = new Set(
    CLOUDFLARE_EXTERNAL_BUILD_FILES.map((entry) => entry.path),
  );
  const expectedDirectories = new Set();
  for (const filePath of expectedFiles) {
    let directory = path.posix.dirname(filePath);
    while (directory && directory !== ".") {
      expectedDirectories.add(directory);
      directory = path.posix.dirname(directory);
    }
  }
  async function visit(directory, relativeRoot = "") {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const relative = relativeRoot ? `${relativeRoot}/${entry.name}` : entry.name;
      if (!relativeRoot && new Set([".git", "web"]).has(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) {
        throw new Error("isolated Cloudflare external input tree contains a symbolic link");
      }
      if (metadata.isDirectory()) {
        if (!expectedDirectories.has(relative)) {
          throw new Error("isolated Cloudflare workspace contains an unbound external directory");
        }
        await visit(absolute, relative);
      } else if (metadata.isFile() && metadata.nlink === 1) {
        if (!expectedFiles.has(relative)) {
          throw new Error("isolated Cloudflare workspace contains an unbound external input");
        }
        actual.push(relative);
      } else {
        throw new Error("isolated Cloudflare external input tree contains an undeclared entry");
      }
    }
  }
  await visit(workspaceRoot);
  actual.sort((left, right) => left.localeCompare(right, "en"));
  const expected = [...expectedFiles]
    .sort((left, right) => left.localeCompare(right, "en"));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error("isolated Cloudflare workspace contains an unbound external input");
  }
}

function git(cwd, args, options = {}) {
  return execFileSync(PINNED_GIT_EXECUTABLE, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-C",
    cwd,
    ...args,
  ], {
    encoding: "utf8",
    env: GIT_ENVIRONMENT,
    stdio: [options.input ? "pipe" : "ignore", "pipe", "pipe"],
    input: options.input,
  }).trim();
}

async function initializeSyntheticSourceRepository(workspaceRoot) {
  git(workspaceRoot, ["init", "-q", "--initial-branch=main", "--template="]);
  git(workspaceRoot, ["add", "-A"]);
  const tree = git(workspaceRoot, ["write-tree"]);
  const commit = git(workspaceRoot, ["commit-tree", tree], {
    input: "isolated Cloudflare release build\n",
  });
  git(workspaceRoot, ["update-ref", "refs/heads/main", commit]);
  git(workspaceRoot, ["symbolic-ref", "HEAD", "refs/heads/main"]);
}

export async function createIsolatedCloudflareBuildWorkspace({
  repositoryRoot,
  buildRoot,
  expectedSourceSha256,
  expectedUploadControlManifestSha256,
  expectedExternalBuildClosure,
} = {}) {
  await assertCanonicalPrivateDirectory(buildRoot, "Cloudflare build root");
  const canonicalRepository = await realpath(repositoryRoot);
  if (canonicalRepository !== repositoryRoot || !path.isAbsolute(repositoryRoot)) {
    throw new Error("Cloudflare source repository root is not canonical");
  }
  const expectedClosure = normalizeCloudflareExternalBuildClosure(
    expectedExternalBuildClosure,
  );
  const sourceClosure = await projectCloudflareExternalBuildClosure(repositoryRoot);
  if (
    cloudflareExternalBuildClosureSha256(sourceClosure)
      !== cloudflareExternalBuildClosureSha256(expectedClosure)
    || canonicalCloudflareExternalBuildClosureText(sourceClosure)
      !== canonicalCloudflareExternalBuildClosureText(expectedClosure)
  ) {
    throw new Error("Cloudflare external build inputs changed before isolation");
  }
  const workspaceRoot = path.join(buildRoot, "workspace");
  await mkdir(workspaceRoot, { mode: 0o700 });
  const counters = { files: 0, bytes: 0 };
  try {
    for (const external of sourceClosure.files) {
      await copyStableRelativeFile(
        repositoryRoot,
        workspaceRoot,
        external.path,
        counters,
      );
    }
    await copyStableTree(
      path.join(repositoryRoot, "web"),
      path.join(workspaceRoot, "web"),
      {
        counters,
        exclude: (relative) => (
          WEB_TOP_LEVEL_EXCLUSIONS.has(relative.split("/", 1)[0])
          || GENERATED_ENV_PATH.test(relative)
        ),
      },
    );
    const isolatedWebDir = path.join(workspaceRoot, "web");
    const stagedSourceSha256 = await cloudflareSourceFingerprint(isolatedWebDir);
    if (stagedSourceSha256 !== expectedSourceSha256) {
      throw new Error("isolated Cloudflare source does not match the validated source fingerprint");
    }
    const stagedControlSha256 = await cloudflareUploadControlFingerprint(isolatedWebDir);
    if (stagedControlSha256 !== expectedUploadControlManifestSha256) {
      throw new Error("isolated Cloudflare source controls do not match the validated controls");
    }
    await assertOnlyDeclaredExternalFiles(workspaceRoot);
    const isolatedClosure = await projectCloudflareExternalBuildClosure(workspaceRoot);
    if (
      cloudflareExternalBuildClosureSha256(isolatedClosure)
        !== cloudflareExternalBuildClosureSha256(expectedClosure)
      || canonicalCloudflareExternalBuildClosureText(isolatedClosure)
        !== canonicalCloudflareExternalBuildClosureText(expectedClosure)
    ) {
      throw new Error("isolated Cloudflare external build closure drifted while copying");
    }
    await initializeSyntheticSourceRepository(workspaceRoot);
    return Object.freeze({
      rootDir: workspaceRoot,
      webDir: isolatedWebDir,
      sourceSha256: stagedSourceSha256,
      uploadControlManifestSha256: stagedControlSha256,
      externalBuildClosure: isolatedClosure,
      externalBuildClosureSha256:
        cloudflareExternalBuildClosureSha256(isolatedClosure),
    });
  } catch (error) {
    await rm(workspaceRoot, { recursive: true, force: true });
    throw error;
  }
}

export async function assertCloudflareBuildWorkspaceIntegrity({
  workspace,
  expectedSourceSha256,
  expectedUploadControlManifestSha256,
  expectedExternalBuildClosure,
} = {}) {
  if (
    !workspace
    || typeof workspace !== "object"
    || path.join(workspace.rootDir || "", "web") !== workspace.webDir
    || await realpath(workspace.rootDir) !== workspace.rootDir
    || await realpath(workspace.webDir) !== workspace.webDir
  ) {
    throw new Error("Cloudflare build workspace is not the exact canonical isolated tree");
  }
  const expectedClosure = normalizeCloudflareExternalBuildClosure(
    expectedExternalBuildClosure,
  );
  const [sourceSha256, uploadControlManifestSha256, externalBuildClosure] =
    await Promise.all([
      cloudflareSourceFingerprint(workspace.webDir),
      cloudflareUploadControlFingerprint(workspace.webDir),
      projectCloudflareExternalBuildClosure(workspace.rootDir),
    ]);
  await assertOnlyDeclaredExternalFiles(workspace.rootDir);
  if (
    sourceSha256 !== expectedSourceSha256
    || uploadControlManifestSha256 !== expectedUploadControlManifestSha256
    || cloudflareExternalBuildClosureSha256(externalBuildClosure)
      !== cloudflareExternalBuildClosureSha256(expectedClosure)
    || canonicalCloudflareExternalBuildClosureText(externalBuildClosure)
      !== canonicalCloudflareExternalBuildClosureText(expectedClosure)
  ) {
    throw new Error("Cloudflare isolated workspace source, controls, or closure changed");
  }
  return Object.freeze({
    sourceSha256,
    uploadControlManifestSha256,
    externalBuildClosureSha256:
      cloudflareExternalBuildClosureSha256(externalBuildClosure),
  });
}

export async function cloudflareBuildSandbox({ buildRoot } = {}) {
  if (process.platform !== "darwin") {
    throw new Error("Cloudflare release build requires the reviewed macOS sandbox-exec boundary");
  }
  await assertCanonicalPrivateDirectory(buildRoot, "Cloudflare build root");
  const executable = await lstat(CLOUDFLARE_BUILD_SANDBOX_EXECUTABLE);
  if (
    !executable.isFile()
    || executable.isSymbolicLink()
    || executable.uid !== 0
    || (executable.mode & 0o022) !== 0
  ) {
    throw new Error("Cloudflare release build sandbox executable is not reviewed");
  }
  const npmCacheRoot = await canonicalNpmCacheRoot();
  const profile = renderCloudflareBuildSandboxProfile({ buildRoot, npmCacheRoot });
  return Object.freeze({ npmCacheRoot, profile });
}

function sandboxExec({ profile, cwd, env, executable, args, stdio = "inherit" }) {
  return execFileSync(
    CLOUDFLARE_BUILD_SANDBOX_EXECUTABLE,
    ["-p", profile, executable, ...args],
    { cwd, env, stdio },
  );
}

export async function assertCloudflareBuildSandboxIsolation({
  buildRoot,
  profile,
  env,
} = {}) {
  const sentinel = path.join(path.dirname(buildRoot), `.dnai-sandbox-sentinel-${process.pid}`);
  const allowedProbe = path.join(buildRoot, ".sandbox-write-probe");
  const sentinelHandle = await open(
    sentinel,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
    0o600,
  );
  try {
    await sentinelHandle.writeFile("private host sentinel\n");
    await sentinelHandle.sync();
  } finally {
    await sentinelHandle.close();
  }
  const probe = [
    'const fs = require("node:fs");',
    'const net = require("node:net");',
    `let denied = false; try { fs.readFileSync(${JSON.stringify(sentinel)}); } catch (error) { denied = new Set(["EPERM", "EACCES"]).has(error.code); }`,
    "if (!denied) process.exit(71);",
    `fs.writeFileSync(${JSON.stringify(allowedProbe)}, "sandboxed\\n");`,
    'const socket = net.connect({ host: "127.0.0.1", port: 9 });',
    "socket.on(\"connect\", () => process.exit(72));",
    'socket.on("error", (error) => process.exit(new Set(["EPERM", "EACCES"]).has(error.code) ? 0 : 73));',
    "setTimeout(() => process.exit(74), 2_000);",
  ].join(" ");
  try {
    sandboxExec({
      profile,
      cwd: buildRoot,
      env,
      executable: process.execPath,
      args: ["-e", probe],
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch {
    throw new Error("Cloudflare build sandbox did not prove host-read and network isolation");
  } finally {
    await rm(sentinel, { force: true });
    await rm(allowedProbe, { force: true });
  }
}

export function installCloudflareBuildDependencies({
  sandbox,
  webDir,
  env,
} = {}) {
  const installEnv = {
    ...env,
    DNAI_BUILD_SANDBOX_ACTIVE: "true",
    NPM_CONFIG_CACHE: sandbox.npmCacheRoot,
    NPM_CONFIG_LOGS_DIR: path.join(env.HOME, "npm-logs"),
  };
  return sandboxExec({
    profile: sandbox.profile,
    cwd: webDir,
    env: installEnv,
    executable: "npm",
    args: [
      "ci",
      "--offline",
      "--ignore-scripts",
      "--include=dev",
      "--no-audit",
      "--no-fund",
    ],
  });
}

export function runCloudflareBuildNpmScript({
  sandbox,
  webDir,
  env,
  script,
} = {}) {
  if (!new Set(["check", "build"]).has(script)) {
    throw new Error("Cloudflare sandbox refuses an unreviewed npm script");
  }
  return sandboxExec({
    profile: sandbox.profile,
    cwd: webDir,
    env: { ...env, DNAI_BUILD_SANDBOX_ACTIVE: "true" },
    executable: "npm",
    args: ["run", script],
  });
}

export const __test = Object.freeze({
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_DOMAIN,
  GENERATED_ENV_PATH,
  GIT_ENVIRONMENT,
  MAX_DEPENDENCY_LOCK_BYTES,
  WEB_TOP_LEVEL_EXCLUSIONS,
  assertOnlyDeclaredExternalFiles,
  dependencyProjection,
});
