import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { TextDecoder } from "node:util";

import {
  assertPinnedCloudflareUploaderCapsule,
  normalizeCloudflareUploaderCapsulePin,
} from "./cloudflare-uploader-capsule-core.mjs";

export const CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_SCHEMA =
  "dnai.cloudflare-production-uploader-authority.v1";
export const CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS =
  "different_principal_read_only_exact_input_handoff_scoped_token_scope_reviewed_out_of_band_not_provider_verified";
export const CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_DOMAIN =
  "dnai-wikigen/cloudflare-production-uploader-authority-tree/v1\0";
export const CLOUDFLARE_PRODUCTION_UPLOAD_ROOT_ENV =
  "CLOUDFLARE_PRODUCTION_UPLOAD_AUTHORITY_ROOT";
export const CLOUDFLARE_PAGES_TOKEN_ENV = "CLOUDFLARE_API_TOKEN";

const EXPECTED_ROOT_ENTRIES = Object.freeze([
  "authority.json",
  "bundle",
  "uploader",
]);
const AUTHORITY_FIELDS = Object.freeze([
  "account_id",
  "branch",
  "bundle",
  "credential_scope",
  "executor_uid",
  "producer_uid",
  "project_name",
  "schema",
  "truth_status",
  "uploader_capsule_pin",
]);
const BUNDLE_FIELDS = Object.freeze([
  "bundle_manifest_sha256",
  "dist_manifest_sha256",
  "upload_control_manifest_sha256",
]);
const CREDENTIAL_SCOPE_FIELDS = Object.freeze([
  "account_resource_id",
  "global_api_key_allowed",
  "oauth_home_allowed",
  "permission",
  "review_status",
  "token_kind",
]);
const CREDENTIAL_REVIEW_STATUS =
  "out_of_band_cloudflare_dashboard_review_required_not_provider_verified_by_this_runner";
const CLOUDFLARE_PAGES_EDIT_PERMISSION = "Cloudflare Pages:Edit";
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const UTF8 = new TextDecoder("utf-8", { fatal: true });
const MAX_AUTHORITY_BYTES = 128 * 1024;
const MAX_TREE_ENTRIES = 40_000;
const MAX_FILE_BYTES = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES = 768 * 1024 * 1024;
const MAX_PATH_BYTES = 1_024;
const MAX_SYMLINK_BYTES = 4_096;

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function sha256(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function exactObject(value, fields, label) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())
  ) {
    throw new Error(`${label} does not have the exact reviewed fields`);
  }
  return value;
}

function safeUid(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function canonicalAbsolute(value, label) {
  if (
    typeof value !== "string"
    || !path.isAbsolute(value)
    || path.resolve(value) !== value
    || path.normalize(value) !== value
    || value === path.parse(value).root
  ) {
    throw new Error(`${label} must be a canonical absolute non-root path`);
  }
  let resolved;
  try {
    resolved = fs.realpathSync.native(value);
  } catch {
    throw new Error(`${label} is unavailable`);
  }
  if (resolved !== value) throw new Error(`${label} is aliased or noncanonical`);
  return value;
}

function bigintUid(value) {
  return BigInt(safeUid(value, "Cloudflare uploader UID"));
}

function permissionMode(metadata) {
  return Number(metadata.mode & 0o7777n);
}

function sameMetadata(left, right) {
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
  ].every((field) => left[field] === right[field]);
}

function isWritableByExecutor(metadata, executorUid) {
  const mode = permissionMode(metadata);
  if (metadata.uid === bigintUid(executorUid)) return true;
  return (mode & 0o022) !== 0;
}

function decodeName(bytes) {
  let value;
  try {
    value = UTF8.decode(bytes);
  } catch {
    throw new Error("Cloudflare production upload authority contains a non-UTF-8 path");
  }
  if (
    !value
    || value === "."
    || value === ".."
    || value.includes("/")
    || value.includes("\\")
    || /[\p{Cc}\p{Cf}]/u.test(value)
    || value.normalize("NFC") !== value
    || Buffer.byteLength(value, "utf8") > 255
  ) {
    throw new Error("Cloudflare production upload authority contains a noncanonical path");
  }
  return value;
}

function assertAncestorAuthority(
  root,
  executorUid,
  producerUid,
  hooks,
) {
  const chain = [];
  let current = path.dirname(root);
  while (true) {
    const named = fs.lstatSync(current, { bigint: true });
    if (
      !named.isDirectory()
      || named.isSymbolicLink()
      || fs.realpathSync.native(current) !== current
      || (named.uid !== 0n && named.uid !== bigintUid(producerUid))
      || isWritableByExecutor(named, executorUid)
    ) {
      throw new Error(
        "Cloudflare production upload authority has an executor-writable or aliased ancestor",
      );
    }
    chain.push(Object.freeze({ path: current, metadata: named }));
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  hooks?.afterAncestorRead?.(chain);
  return chain;
}

function assertAncestorChainStable(chain) {
  for (const entry of chain) {
    const current = fs.lstatSync(entry.path, { bigint: true });
    if (!sameMetadata(entry.metadata, current)) {
      throw new Error("Cloudflare production upload authority ancestor changed during projection");
    }
  }
}

function readStableFile(
  filePath,
  named,
  producerUid,
  maximumBytes,
  label,
  hooks,
  minimumBytes = 0,
  allowProducerWrite = false,
) {
  const mode = permissionMode(named);
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || named.uid !== bigintUid(producerUid)
    || (mode & 0o7000) !== 0
    || (mode & 0o004) === 0
    || (allowProducerWrite ? (mode & 0o022) !== 0 : (mode & 0o222) !== 0)
    || named.size < BigInt(minimumBytes)
    || named.size > BigInt(maximumBytes)
  ) {
    throw new Error(`${label} is not a frozen single-link producer-owned regular file`);
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!sameMetadata(named, before)) throw new Error(`${label} changed while opening`);
    hooks?.afterFileOpen?.(filePath, descriptor);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!sameMetadata(before, after) || BigInt(bytes.length) !== before.size) {
      throw new Error(`${label} changed during its stable read`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

function resolveInternalSymlink(root, filePath, target) {
  if (
    !target
    || path.isAbsolute(target)
    || target.includes("\0")
    || target.includes("\\")
  ) {
    throw new Error("Cloudflare production upload authority contains an unsafe symlink");
  }
  const resolved = path.resolve(path.dirname(filePath), target);
  const relative = path.relative(root, resolved);
  if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Cloudflare production upload authority symlink escapes its root");
  }
  return relative.split(path.sep).join("/");
}

function projectAuthorityTreeOnce({
  authorityRoot,
  executorUid,
  hooks,
}) {
  const root = canonicalAbsolute(
    authorityRoot,
    "Cloudflare production upload authority root",
  );
  const rootMetadata = fs.lstatSync(root, { bigint: true });
  const producerUid = Number(rootMetadata.uid);
  if (
    executorUid === 0
    || !Number.isSafeInteger(producerUid)
    || producerUid < 0
    || producerUid > Number.MAX_SAFE_INTEGER
    || !rootMetadata.isDirectory()
    || rootMetadata.isSymbolicLink()
    || producerUid === executorUid
    || (permissionMode(rootMetadata) & 0o7000) !== 0
    || (permissionMode(rootMetadata) & 0o555) !== 0o555
    || (permissionMode(rootMetadata) & 0o222) !== 0
  ) {
    throw new Error(
      "Cloudflare production upload authority root must be frozen and owned by a different principal",
    );
  }
  const ancestorChain = assertAncestorAuthority(
    root,
    executorUid,
    producerUid,
    hooks,
  );
  const records = [];
  let totalBytes = 0;

  function visit(absolute) {
    const relative = absolute === root
      ? "."
      : path.relative(root, absolute).split(path.sep).join("/");
    if (
      relative !== "."
      && (
        !relative
        || relative.startsWith("../")
        || path.posix.normalize(relative) !== relative
        || Buffer.byteLength(relative, "utf8") > MAX_PATH_BYTES
      )
    ) {
      throw new Error("Cloudflare production upload authority path escapes its root");
    }
    const named = fs.lstatSync(absolute, { bigint: true });
    const mode = permissionMode(named);
    if (named.uid !== bigintUid(producerUid)) {
      throw new Error("Cloudflare production upload authority mixes filesystem principals");
    }
    if (named.isDirectory() && !named.isSymbolicLink()) {
      if (
        (mode & 0o7000) !== 0
        || (mode & 0o555) !== 0o555
        || (mode & 0o222) !== 0
      ) {
        throw new Error("Cloudflare production upload authority contains a writable directory");
      }
      const rawNames = fs.readdirSync(absolute, { encoding: "buffer" });
      hooks?.afterDirectoryRead?.(absolute);
      const names = rawNames.map(decodeName).sort((left, right) => Buffer.compare(
        Buffer.from(left, "utf8"),
        Buffer.from(right, "utf8"),
      ));
      if (new Set(names).size !== names.length) {
        throw new Error("Cloudflare production upload authority contains duplicate paths");
      }
      if (
        relative === "."
        && JSON.stringify(names) !== JSON.stringify(EXPECTED_ROOT_ENTRIES)
      ) {
        throw new Error("Cloudflare production upload authority root shape is not exact");
      }
      records.push({ mode, path: relative, size: 0, type: "directory" });
      if (records.length > MAX_TREE_ENTRIES) {
        throw new Error("Cloudflare production upload authority exceeds its entry bound");
      }
      for (const name of names) visit(path.join(absolute, name));
      if (!sameMetadata(named, fs.lstatSync(absolute, { bigint: true }))) {
        throw new Error("Cloudflare production upload authority directory changed during projection");
      }
      return;
    }
    if (named.isFile() && !named.isSymbolicLink()) {
      if (named.size > BigInt(MAX_FILE_BYTES)) {
        throw new Error("Cloudflare production upload authority exceeds its file bound");
      }
      totalBytes += Number(named.size);
      if (totalBytes > MAX_TOTAL_BYTES) {
        throw new Error("Cloudflare production upload authority exceeds its total-byte bound");
      }
      const bytes = readStableFile(
        absolute,
        named,
        producerUid,
        MAX_FILE_BYTES,
        "Cloudflare production upload authority file",
        hooks,
        0,
        relative.startsWith("bundle/"),
      );
      records.push({
        mode,
        path: relative,
        sha256: sha256(bytes),
        size: bytes.length,
        type: "file",
      });
    } else if (named.isSymbolicLink()) {
      const targetBuffer = fs.readlinkSync(absolute, { encoding: "buffer" });
      if (targetBuffer.length < 1 || targetBuffer.length > MAX_SYMLINK_BYTES) {
        throw new Error("Cloudflare production upload authority symlink is outside its bound");
      }
      const target = UTF8.decode(targetBuffer);
      const resolvedTarget = resolveInternalSymlink(root, absolute, target);
      records.push({
        mode,
        path: relative,
        resolvedTarget,
        sha256: sha256(targetBuffer),
        size: targetBuffer.length,
        target,
        type: "symlink",
      });
      if (!sameMetadata(named, fs.lstatSync(absolute, { bigint: true }))) {
        throw new Error("Cloudflare production upload authority symlink changed during projection");
      }
    } else {
      throw new Error("Cloudflare production upload authority contains an unsupported entry");
    }
    if (records.length > MAX_TREE_ENTRIES) {
      throw new Error("Cloudflare production upload authority exceeds its entry bound");
    }
  }

  visit(root);
  assertAncestorChainStable(ancestorChain);
  records.sort((left, right) => Buffer.compare(
    Buffer.from(left.path, "utf8"),
    Buffer.from(right.path, "utf8"),
  ));
  const manifest = Object.freeze({
    entry_count: records.length,
    producer_uid: producerUid,
    records: Object.freeze(records.map((record) => Object.freeze(record))),
    root,
    total_bytes: totalBytes,
  });
  return Object.freeze({
    manifest,
    manifestSha256: sha256(Buffer.from(
      `${CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_DOMAIN}${canonicalText(manifest)}`,
      "utf8",
    )),
    producerUid,
  });
}

function projectAuthorityTree(options) {
  const first = projectAuthorityTreeOnce(options);
  options.hooks?.betweenProjections?.(first);
  const second = projectAuthorityTreeOnce(options);
  if (first.manifestSha256 !== second.manifestSha256) {
    throw new Error("Cloudflare production upload authority changed between projections");
  }
  return second;
}

function parseAuthority(filePath, producerUid) {
  const named = fs.lstatSync(filePath, { bigint: true });
  const bytes = readStableFile(
    filePath,
    named,
    producerUid,
    MAX_AUTHORITY_BYTES,
    "Cloudflare production upload authority descriptor",
    undefined,
    1,
  );
  let value;
  try {
    value = JSON.parse(UTF8.decode(bytes));
  } catch {
    throw new Error("Cloudflare production upload authority descriptor is not JSON");
  }
  if (canonicalText(value) !== bytes.toString("utf8")) {
    throw new Error(
      "Cloudflare production upload authority descriptor is not canonical duplicate-free JSON",
    );
  }
  return value;
}

function normalizeAuthority(value, {
  executorUid,
  expectedAccountId,
  expectedBranch,
  expectedProjectName,
  producerUid,
}) {
  const parsed = exactObject(
    value,
    AUTHORITY_FIELDS,
    "Cloudflare production upload authority descriptor",
  );
  const bundle = exactObject(
    parsed.bundle,
    BUNDLE_FIELDS,
    "Cloudflare production upload bundle authority",
  );
  const credentialScope = exactObject(
    parsed.credential_scope,
    CREDENTIAL_SCOPE_FIELDS,
    "Cloudflare production upload credential scope",
  );
  if (
    parsed.schema !== CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_SCHEMA
    || parsed.truth_status !== CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS
    || parsed.account_id !== expectedAccountId
    || parsed.branch !== expectedBranch
    || parsed.project_name !== expectedProjectName
    || parsed.executor_uid !== executorUid
    || parsed.producer_uid !== producerUid
    || !Object.values(bundle).every((digest) => SHA256.test(String(digest || "")))
  ) {
    throw new Error("Cloudflare production upload authority does not match this exact release");
  }
  if (
    credentialScope.account_resource_id !== expectedAccountId
    || credentialScope.permission !== CLOUDFLARE_PAGES_EDIT_PERMISSION
    || credentialScope.token_kind !== "api_token"
    || credentialScope.oauth_home_allowed !== false
    || credentialScope.global_api_key_allowed !== false
    || credentialScope.review_status !== CREDENTIAL_REVIEW_STATUS
  ) {
    throw new Error("Cloudflare production upload authority lacks the scoped Pages token declaration");
  }
  const capsulePin = normalizeCloudflareUploaderCapsulePin(
    parsed.uploader_capsule_pin,
  );
  return Object.freeze({
    ...parsed,
    bundle: Object.freeze({ ...bundle }),
    credential_scope: Object.freeze({ ...credentialScope }),
    uploader_capsule_pin: capsulePin,
  });
}

export function cloudflareUploaderRuntimeIdentity({
  nodeVersion,
  npmVersion,
  wranglerVersion,
} = {}) {
  return Object.freeze({
    architecture: process.arch,
    nodeVersion,
    npmVersion,
    osPlatform: process.platform,
    osRelease: os.release(),
    wranglerVersion,
  });
}

export function assertScopedCloudflarePagesToken(env = {}) {
  const token = String(env[CLOUDFLARE_PAGES_TOKEN_ENV] ?? "");
  if (
    token.length < 20
    || token.length > 4_096
    || !/^[A-Za-z0-9_-]+$/.test(token)
  ) {
    throw new Error(
      "live Cloudflare upload requires a bounded scoped CLOUDFLARE_API_TOKEN; OAuth HOME and global API keys are not release authority",
    );
  }
  if (
    String(env.CLOUDFLARE_API_KEY ?? "").length > 0
    || String(env.CLOUDFLARE_EMAIL ?? "").length > 0
  ) {
    throw new Error("live Cloudflare upload refuses global API-key authority");
  }
  return token;
}

export async function assertCloudflareProductionUploaderAuthority({
  auditBuild,
  auditStage,
  authorityRoot,
  credentialEnv,
  env,
  executorUid = typeof process.geteuid === "function" ? process.geteuid() : 0,
  expectedAccountId,
  expectedBranch,
  expectedBundleAudit,
  expectedDistAudit,
  expectedProjectName,
  privateReleaseAudit,
  runtimeIdentity,
  sensitiveEnv,
  hooks,
}) {
  if (typeof auditBuild !== "function" || typeof auditStage !== "function") {
    throw new Error("Cloudflare production uploader authority requires exact bundle auditors");
  }
  assertScopedCloudflarePagesToken(credentialEnv);
  const projection = projectAuthorityTree({
    authorityRoot,
    executorUid: safeUid(executorUid, "Cloudflare uploader executor UID"),
    hooks,
  });
  const authority = normalizeAuthority(
    parseAuthority(path.join(projection.manifest.root, "authority.json"), projection.producerUid),
    {
      executorUid,
      expectedAccountId,
      expectedBranch,
      expectedProjectName,
      producerUid: projection.producerUid,
    },
  );
  const bundleRoot = path.join(projection.manifest.root, "bundle");
  const uploaderCapsuleRoot = path.join(projection.manifest.root, "uploader");
  const capsuleProjection = assertPinnedCloudflareUploaderCapsule({
    capsuleRoot: uploaderCapsuleRoot,
    delegatedReadOnly: true,
    expectedOwner: projection.producerUid,
    runtimeIdentity,
  }, authority.uploader_capsule_pin);
  const distAudit = await auditBuild({
    distDir: path.join(bundleRoot, "dist"),
    env,
    mode: "live",
    releaseSha: String(env.VITE_RELEASE_SHA || ""),
    sensitiveEnv,
    privateReleaseAudit,
  });
  const bundleAudit = await auditStage({
    stageDir: bundleRoot,
    distAudit,
    mode: "live",
    sensitiveEnv,
    privateReleaseAudit,
  });
  if (
    distAudit.manifestSha256 !== expectedDistAudit.manifestSha256
    || bundleAudit.bundleManifestSha256 !== expectedBundleAudit.bundleManifestSha256
    || bundleAudit.distManifestSha256 !== expectedBundleAudit.distManifestSha256
    || bundleAudit.uploadControlManifestSha256
      !== expectedBundleAudit.uploadControlManifestSha256
    || authority.bundle.dist_manifest_sha256
      !== `sha256:${distAudit.manifestSha256}`
    || authority.bundle.bundle_manifest_sha256
      !== `sha256:${bundleAudit.bundleManifestSha256}`
    || authority.bundle.upload_control_manifest_sha256
      !== `sha256:${bundleAudit.uploadControlManifestSha256}`
  ) {
    throw new Error(
      "Cloudflare production upload authority does not contain the exact signed and staged build bytes",
    );
  }
  return Object.freeze({
    authority,
    authorityRoot: projection.manifest.root,
    authorityTreeManifestSha256: projection.manifestSha256,
    bundleAudit,
    bundleRoot,
    capsuleManifestSha256: capsuleProjection.manifestSha256,
    exactProductionInput: true,
    producerUid: projection.producerUid,
    truthStatus: CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
    uploaderCapsulePin: authority.uploader_capsule_pin,
    uploaderCapsuleRoot,
    uploaderRuntimeIdentity: runtimeIdentity,
  });
}

export const __test = Object.freeze({
  CREDENTIAL_REVIEW_STATUS,
  CLOUDFLARE_PAGES_EDIT_PERMISSION,
  EXPECTED_ROOT_ENTRIES,
  projectAuthorityTree,
  projectAuthorityTreeOnce,
});
