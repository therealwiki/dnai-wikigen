import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { renderProductionHeadersForEnv } from "./security-headers-core.mjs";

const MAX_BUILD_FILES = 4_096;
const MAX_BUILD_FILE_BYTES = 16 * 1024 * 1024;
const MAX_BUILD_TOTAL_BYTES = 64 * 1024 * 1024;
const SOURCE_EXCLUSIONS = new Set(["dist", "node_modules", ".wrangler"]);
const SOURCE_FINGERPRINT_SCHEMA = "dnai.cloudflare-web-source-fingerprint.v1";
const SOURCE_ENV_OUTPUT_PATH = /(?:^|\/)\.env(?:\.|$)/;
const FORBIDDEN_BUILD_PATH = /(?:^|\/)(?:\.env(?:\.|$)|[^/]*\.(?:map|pem|key)|credentials?(?:\.|$))/i;
// Wrangler interprets or ignores these paths instead of uploading them as
// ordinary immutable assets. D must describe the exact Pages artifact, so the
// only permitted Pages control file in dist is the byte-pinned `_headers`.
const FORBIDDEN_PAGES_BUILD_PATH = /^(?:_redirects|_routes\.json|_worker\.js(?:\/|$)|functions(?:\/|$)|node_modules(?:\/|$)|\.git(?:\/|$)|\.wrangler(?:\/|$))|(?:^|\/)\.DS_Store$/;
const TEXT_SECRET_PATTERNS = Object.freeze([
  /-----BEGIN (?:ENCRYPTED |OPENSSH |RSA |EC )?PRIVATE KEY-----/,
  /\bphak_[A-Za-z0-9_-]{16,}\b/,
  /\b(?:sk-or-v1-|sk-proj-)[A-Za-z0-9_-]{16,}\b/,
  /\b(?:ghp_|gho_|ghu_|ghs_|github_pat_)[A-Za-z0-9_]{16,}\b/,
  /\bAKIA[A-Z0-9]{16}\b/,
]);
const SENSITIVE_ENV_NAME = /(?:API_?KEY|AUTH_?TOKEN|CREDENTIAL|PASSWORD|PRIVATE_?KEY|SECRET|TOKEN)/i;
const PRIVATE_RELEASE_AUDIT_SCHEMA =
  "dnai.cloudflare-private-release-artifact-audit.v1";
const PRIVATE_FRONTEND_CANDIDATE_AUDIT_SCHEMA =
  "dnai.cloudflare-private-frontend-candidate-artifact-audit.v1";
const FORBIDDEN_PRIVATE_RELEASE_FLAGS = new Set([
  // The six-domain completion artifact predates the independent compute
  // workload verifier. Accepting it would let a stale launch topology reach
  // the final upload gate.
  "--six-cvm-launch-completion-receipt",
]);
const REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS = Object.freeze([
  "--release",
  "--release-core",
  "--runtime-authority-dependency",
  "--deployment-intent",
  "--contract-receipt",
  "--reviewer-authority-genesis",
  "--reviewer-authority-genesis-acceptance",
  "--bootstrap-authority",
  "--bootstrap-authorization",
  "--bootstrap-authorization-receipt",
  "--seven-cvm-launch-completion-receipt",
  "--main-runtime-qvl-challenge",
  "--main-runtime-independent-tdx-verdict",
  "--diligence-qvl-identity-request",
  "--diligence-qvl-identity-response",
  "--arena-qvl-identity-request",
  "--arena-qvl-identity-response",
  "--anchor-writer-qvl-identity-request",
  "--anchor-writer-qvl-identity-response",
  "--compute-workload-qvl-identity-request",
  "--compute-workload-qvl-identity-response",
  "--compute-metering-qvl-identity-request",
  "--compute-metering-qvl-identity-response",
  "--independent-metering-qvl-challenge",
  "--independent-metering-independent-tdx-verdict",
  "--image-release-sigstore-verification-receipt",
  "--cvm-descriptor-set-receipt",
  "--phala-executor-final-state",
  "--ceremony-authorization",
  "--ledger",
  "--artifact-evidence",
  "--arena-evidence",
  "--anchor-writer-evidence",
  "--email-oracle-evidence",
  "--live-activation-authority",
  "--royalty-release-history-receipt",
  "--compute-workload-activation-observation",
  "--frontend-build-candidate-receipt",
]);
const SORTED_REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS = Object.freeze(
  [...REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS]
    .sort((left, right) => left.localeCompare(right, "en")),
);
export const REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS = Object.freeze(
  REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.filter((flag) => !new Set([
    "--live-activation-authority",
    "--frontend-build-candidate-receipt",
  ]).has(flag)),
);
const SORTED_REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS = Object.freeze(
  [...REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS]
    .sort((left, right) => left.localeCompare(right, "en")),
);
const PRIVATE_RELEASE_INPUT_MAX_BYTES = 4 * 1024 * 1024;
const PRIVATE_RELEASE_INPUT_MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const EXPECTED_WRANGLER_CONFIG = [
  'name = "wikigenme"',
  'pages_build_output_dir = "./dist"',
  'compatibility_date = "2026-07-13"',
  "",
].join("\n");
const CLOUDFLARE_UPLOAD_CONTROL_PATHS = Object.freeze([
  "functions/_middleware.js",
  "package.json",
  "wrangler.toml",
]);
export const CLOUDFLARE_D_BUILD_CONTROL_PATHS = Object.freeze([
  "web/functions/_middleware.js",
  "web/index.html",
  "web/package-lock.json",
  "web/package.json",
  "web/public/wikigen-bootstrap-v3.js",
  "web/scripts/build-release-env.mjs",
  "web/scripts/build-security-headers.mjs",
  "web/scripts/cloudflare-build-sandbox-core.mjs",
  "web/scripts/collaboration-execution-release-env-core.mjs",
  "web/scripts/cloudflare-external-build-closure-core.mjs",
  "web/scripts/cloudflare-release-artifact-core.mjs",
  "web/scripts/deploy-cloudflare-core.mjs",
  "web/scripts/deploy-cloudflare.mjs",
  "web/scripts/durable-private-file-core.mjs",
  "web/scripts/execution-policy-release-core-binding.mjs",
  "web/scripts/frontend-build-candidate-core.mjs",
  "web/scripts/frontend-build-candidate-producer-core.mjs",
  "web/scripts/public-https-origin-core.mjs",
  "web/scripts/release-build-home-core.mjs",
  "web/scripts/release-runtime-pins-core.mjs",
  "web/scripts/release-env-core.mjs",
  "web/scripts/royalty-release-env-core.mjs",
  "web/scripts/security-headers-core.mjs",
  "web/tsconfig.json",
  "web/vite.config.ts",
  "web/wrangler.toml",
]);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function compactJsonBytes(value) {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function semanticCanonicalJsonValue(value) {
  if (Array.isArray(value)) return value.map((entry) => semanticCanonicalJsonValue(entry));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort((left, right) => left.localeCompare(right, "en"))
      .map((key) => [key, semanticCanonicalJsonValue(value[key])]),
  );
}

function parsePrivateReleaseInputArguments(
  argv,
  requiredFlags = REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS,
) {
  if (!Array.isArray(argv)) {
    throw new Error("private release artifact audit requires the exact validator arguments");
  }
  const entries = [];
  const seen = new Set();
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (typeof flag !== "string" || !flag.startsWith("--") || seen.has(flag)) {
      throw new Error("private release artifact audit received malformed or duplicate arguments");
    }
    seen.add(flag);
    if (FORBIDDEN_PRIVATE_RELEASE_FLAGS.has(flag)) {
      throw new Error("private release artifact audit refuses stale six-CVM launch evidence");
    }
    if (!requiredFlags.includes(flag)) {
      throw new Error("private release artifact audit refuses an unknown or legacy validator argument");
    }
    const filePath = argv[index + 1];
    if (
      typeof filePath !== "string"
      || filePath.startsWith("--")
      || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath
      || path.normalize(filePath) !== filePath
    ) {
      throw new Error("private release artifact audit requires canonical absolute input paths");
    }
    entries.push({ flag, filePath });
    index += 1;
  }
  for (const flag of requiredFlags) {
    if (!seen.has(flag)) {
      throw new Error("private release artifact audit is missing a required live input");
    }
  }
  return entries;
}

function collectPrivateJsonNeedles(value, addNeedle, key = "", depth = 0) {
  if (depth > 24 || value === null || value === undefined) return;
  if (typeof value === "string") {
    if (
      /signature/i.test(key)
      || /^0x[0-9a-fA-F]{130}$/.test(value)
    ) {
      addNeedle("signature", Buffer.from(value, "utf8"));
    }
    if (/path/i.test(key) && path.isAbsolute(value)) {
      addNeedle("private_path", Buffer.from(value, "utf8"));
      addNeedle("private_basename", Buffer.from(path.basename(value), "utf8"));
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectPrivateJsonNeedles(entry, addNeedle, key, depth + 1);
    }
    return;
  }
  if (typeof value !== "object") return;
  for (const [childKey, child] of Object.entries(value)) {
    collectPrivateJsonNeedles(child, addNeedle, childKey, depth + 1);
  }
}

function privateReleaseAuditPayload(value, {
  schema = PRIVATE_RELEASE_AUDIT_SCHEMA,
  sortedRequiredFlags = SORTED_REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS,
} = {}) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || value.schema !== schema
    || !Array.isArray(value.inputs)
    || !Array.isArray(value.needles)
  ) {
    throw new Error("live Cloudflare build requires a private release artifact audit");
  }
  const inputs = value.inputs.map((entry) => {
    if (
      !entry
      || typeof entry !== "object"
      || Array.isArray(entry)
      || JSON.stringify(Object.keys(entry).sort())
        !== JSON.stringify(["content_sha256", "flag", "semantic_sha256"].sort())
      || typeof entry.flag !== "string"
      || !entry.flag.startsWith("--")
      || !/^[0-9a-f]{64}$/.test(String(entry.content_sha256 || ""))
      || !/^[0-9a-f]{64}$/.test(String(entry.semantic_sha256 || ""))
    ) {
      throw new Error("private release artifact audit input manifest is invalid");
    }
    return {
      flag: entry.flag,
      content_sha256: entry.content_sha256,
      semantic_sha256: entry.semantic_sha256,
    };
  });
  const needles = value.needles.map((entry) => {
    if (
      !entry
      || typeof entry !== "object"
      || Array.isArray(entry)
      || JSON.stringify(Object.keys(entry).sort())
        !== JSON.stringify(["base64", "category", "sha256"].sort())
      || !new Set([
        "artifact_raw",
        "artifact_pretty",
        "artifact_compact",
        "live_wrapper_pretty",
        "live_wrapper_compact",
        "signature",
        "private_path",
        "private_basename",
      ]).has(entry.category)
      || !/^[0-9a-f]{64}$/.test(String(entry.sha256 || ""))
      || typeof entry.base64 !== "string"
    ) {
      throw new Error("private release artifact audit needle manifest is invalid");
    }
    const bytes = Buffer.from(entry.base64, "base64");
    if (
      bytes.length < 1
      || bytes.toString("base64") !== entry.base64
      || sha256(bytes) !== entry.sha256
    ) {
      throw new Error("private release artifact audit needle bytes are invalid");
    }
    return {
      category: entry.category,
      sha256: entry.sha256,
      base64: entry.base64,
    };
  });
  if (
    inputs.length !== sortedRequiredFlags.length
    || inputs.some((entry, index) => (
      entry.flag !== sortedRequiredFlags[index]
    ))
    || new Set(inputs.map((entry) => entry.content_sha256)).size !== inputs.length
    || new Set(inputs.map((entry) => entry.semantic_sha256)).size !== inputs.length
    || needles.length < inputs.length
    || new Set(needles.map((entry) => `${entry.sha256}:${entry.base64}`)).size
      !== needles.length
    || needles.some((entry, index) => (
      index > 0
      && (
        needles[index - 1].sha256 > entry.sha256
        || (
          needles[index - 1].sha256 === entry.sha256
          && needles[index - 1].category > entry.category
        )
      )
    ))
  ) {
    throw new Error("private release artifact audit is incomplete");
  }
  return { schema, inputs, needles };
}

function normalizePrivateReleaseArtifactAudit(value) {
  const payload = privateReleaseAuditPayload(value);
  const fingerprintSha256 = sha256(canonicalJsonBytes(payload));
  if (value.fingerprintSha256 !== fingerprintSha256) {
    throw new Error("private release artifact audit fingerprint is invalid");
  }
  return { ...payload, fingerprintSha256 };
}

function normalizePrivateFrontendCandidateArtifactAudit(value) {
  const payload = privateReleaseAuditPayload(value, {
    schema: PRIVATE_FRONTEND_CANDIDATE_AUDIT_SCHEMA,
    sortedRequiredFlags: SORTED_REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS,
  });
  const fingerprintSha256 = sha256(canonicalJsonBytes(payload));
  if (value.fingerprintSha256 !== fingerprintSha256) {
    throw new Error("private frontend candidate artifact audit fingerprint is invalid");
  }
  return { ...payload, fingerprintSha256 };
}

async function readStableRegularFile(
  file,
  label = "Cloudflare release file",
  maximumBytes = 32 * 1024 * 1024,
) {
  let handle;
  try {
    handle = await open(
      file.absolute,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
    );
    const before = await handle.stat({ bigint: true });
    if (file.metadata) {
      const expected = file.metadata;
      if (
        before.dev !== BigInt(expected.dev)
        || before.ino !== BigInt(expected.ino)
        || before.size !== BigInt(expected.size)
        || before.nlink !== BigInt(expected.nlink)
        || before.uid !== BigInt(expected.uid)
        || before.gid !== BigInt(expected.gid)
        || before.mode !== BigInt(expected.mode)
      ) {
        throw new Error(`${label} changed while opening`);
      }
    }
    if (!before.isFile() || before.size > BigInt(maximumBytes)) {
      throw new Error(`${label} is not a bounded regular file`);
    }
    const content = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    const stable = [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]
      .every((field) => before[field] === after[field]);
    if (!stable || BigInt(content.length) !== before.size) {
      throw new Error(`${label} changed during its bounded read`);
    }
    return content;
  } catch (error) {
    if (error instanceof Error && error.message.startsWith(`${label} `)) throw error;
    throw new Error(`${label} could not be read as a stable no-follow regular file`);
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

function posixRelative(root, filePath) {
  return path.relative(root, filePath).split(path.sep).join("/");
}

async function collectRegularFiles(root, {
  excludeTopLevel = new Set(),
  excludePath = () => false,
  maximumFiles = MAX_BUILD_FILES,
  maximumFileBytes = MAX_BUILD_FILE_BYTES,
  maximumTotalBytes = MAX_BUILD_TOTAL_BYTES,
} = {}) {
  const rootStat = await lstat(root).catch(() => null);
  if (!rootStat?.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error("Cloudflare release tree must be a real directory");
  }

  const files = [];
  let totalBytes = 0;
  async function visit(directory) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relative = posixRelative(root, absolute);
      const topLevel = relative.split("/", 1)[0];
      if (excludeTopLevel.has(topLevel) || excludePath(relative)) continue;
      const metadata = await lstat(absolute);
      if (metadata.isSymbolicLink()) {
        throw new Error("Cloudflare release tree contains a symbolic link");
      }
      if (metadata.isDirectory()) {
        await visit(absolute);
        continue;
      }
      if (!metadata.isFile() || metadata.nlink !== 1) {
        throw new Error("Cloudflare release tree contains a non-regular or hard-linked entry");
      }
      if (metadata.size > maximumFileBytes) {
        throw new Error("Cloudflare release tree contains an oversized file");
      }
      totalBytes += metadata.size;
      if (totalBytes > maximumTotalBytes) {
        throw new Error("Cloudflare release tree exceeds the bounded upload size");
      }
      files.push({ absolute, relative, metadata });
      if (files.length > maximumFiles) {
        throw new Error("Cloudflare release tree contains too many files");
      }
    }
  }
  await visit(root);
  return files;
}

export function deploymentViteEnvironmentDigest(env = {}) {
  const values = Object.entries(env)
    .filter(([key]) => key.startsWith("VITE_"))
    .map(([key, value]) => [key, String(value ?? "")])
    .sort(([left], [right]) => left.localeCompare(right, "en"));
  return sha256(`${JSON.stringify(values)}\n`);
}

export async function cloudflareSourceFingerprint(webDir) {
  const files = await collectRegularFiles(webDir, {
    excludeTopLevel: SOURCE_EXCLUSIONS,
    // The generated public environment is bound separately by
    // deploymentViteEnvironmentDigest. Hashing it into the source tree would
    // create a D -> env -> source -> D cycle and would also mix private local
    // operator files into an otherwise public build-source commitment.
    excludePath: (relative) => SOURCE_ENV_OUTPUT_PATH.test(relative),
    maximumFiles: 16_384,
    maximumFileBytes: 32 * 1024 * 1024,
    maximumTotalBytes: 256 * 1024 * 1024,
  });
  const hash = createHash("sha256");
  hash.update(SOURCE_FINGERPRINT_SCHEMA, "utf8");
  hash.update("\0", "ascii");
  for (const file of files) {
    const content = await readStableRegularFile(file, "Cloudflare source file");
    hash.update(file.relative, "utf8");
    hash.update("\0", "ascii");
    hash.update(String(file.metadata.mode & 0o777), "ascii");
    hash.update("\0", "ascii");
    hash.update(String(content.length), "ascii");
    hash.update("\0", "ascii");
    hash.update(content);
    hash.update("\0", "ascii");
  }
  return hash.digest("hex");
}

export async function cloudflareSourceFingerprintSha256(webDir) {
  return `sha256:${await cloudflareSourceFingerprint(webDir)}`;
}

export async function cloudflareFrontendBuildControlFiles(repoRoot) {
  const canonicalRoot = await realpath(repoRoot);
  if (
    !path.isAbsolute(repoRoot)
    || path.resolve(repoRoot) !== repoRoot
    || canonicalRoot !== repoRoot
  ) {
    throw new Error("Cloudflare D build-control root is not canonical");
  }
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : null;
  const files = [];
  for (const relative of CLOUDFLARE_D_BUILD_CONTROL_PATHS) {
    const absolute = path.join(repoRoot, ...relative.split("/"));
    const metadata = await lstat(absolute);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.nlink !== 1
      || (expectedUid !== null && metadata.uid !== expectedUid)
      || (metadata.mode & 0o022) !== 0
      || metadata.size < 1
      || metadata.size > MAX_BUILD_FILE_BYTES
    ) {
      throw new Error(
        "Cloudflare D build control is not a bounded operator-owned single-link file",
      );
    }
    const content = await readStableRegularFile(
      { absolute, metadata },
      "Cloudflare D build control",
      MAX_BUILD_FILE_BYTES,
    );
    files.push(Object.freeze({
      path: relative,
      sha256: `sha256:${sha256(content)}`,
    }));
  }
  return Object.freeze(files);
}

function controlManifestSha256(entries) {
  return sha256(`${JSON.stringify(entries)}\n`);
}

export async function cloudflareUploadControlFingerprint(webDir) {
  const entries = [];
  for (const relative of CLOUDFLARE_UPLOAD_CONTROL_PATHS) {
    const absolute = path.join(webDir, ...relative.split("/"));
    const metadata = await lstat(absolute);
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.nlink !== 1
    ) {
      throw new Error("Cloudflare upload control is not a single-link regular file");
    }
    const content = await readStableRegularFile(
      { absolute, metadata },
      "Cloudflare upload control",
      MAX_BUILD_FILE_BYTES,
    );
    entries.push({
      path: relative,
      mode: metadata.mode & 0o777,
      size: content.length,
      sha256: sha256(content),
    });
  }
  return controlManifestSha256(entries);
}

export function sensitiveEnvironmentValues(env = {}) {
  const values = [];
  for (const [key, raw] of Object.entries(env)) {
    const value = String(raw ?? "");
    if (
      SENSITIVE_ENV_NAME.test(key)
      && value.length >= 8
      && value !== "undefined"
      && value !== "null"
    ) values.push(Buffer.from(value, "utf8"));
  }
  return values;
}

async function loadPrivateArtifactAudit(releaseArguments, {
  requiredFlags,
  schema,
}) {
  const entries = parsePrivateReleaseInputArguments(releaseArguments, requiredFlags);
  const inputs = [];
  const needlesByDigestAndBytes = new Map();
  let totalBytes = 0;
  const canonicalPaths = new Set();
  const contentDigests = new Set();
  const semanticDigests = new Set();

  const addNeedle = (category, bytes) => {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1) return;
    const digest = sha256(bytes);
    const base64 = bytes.toString("base64");
    const identity = `${digest}:${base64}`;
    const existing = needlesByDigestAndBytes.get(identity);
    if (!existing) {
      needlesByDigestAndBytes.set(identity, { category, sha256: digest, base64 });
      return;
    }
    // Prefer the most specific category for diagnostics while retaining one
    // exact byte needle. No private value is ever echoed in an error.
    const priority = [
      "signature",
      "live_wrapper_pretty",
      "live_wrapper_compact",
      "private_path",
      "private_basename",
      "artifact_raw",
      "artifact_pretty",
      "artifact_compact",
    ];
    if (priority.indexOf(category) < priority.indexOf(existing.category)) {
      needlesByDigestAndBytes.set(identity, { category, sha256: digest, base64 });
    }
  };

  for (const entry of entries) {
    let canonicalPath;
    try {
      canonicalPath = await realpath(entry.filePath);
    } catch {
      throw new Error("private release artifact input could not be resolved safely");
    }
    if (canonicalPath !== entry.filePath) {
      throw new Error("private release artifact input path is aliased or noncanonical");
    }
    if (canonicalPaths.has(canonicalPath)) {
      throw new Error("private release artifact inputs must be distinct files");
    }
    canonicalPaths.add(canonicalPath);
    const metadata = await lstat(entry.filePath, { bigint: true });
    if (
      !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.nlink !== 1n
      || (
        typeof process.geteuid === "function"
        && metadata.uid !== BigInt(process.geteuid())
      )
      || (metadata.mode & 0o022n) !== 0n
      || metadata.size < 2n
      || metadata.size > BigInt(PRIVATE_RELEASE_INPUT_MAX_BYTES)
    ) {
      throw new Error("private release artifact input is not a bounded single-link regular file");
    }
    const raw = await readStableRegularFile(
      { absolute: entry.filePath, metadata },
      "private release artifact input",
      PRIVATE_RELEASE_INPUT_MAX_BYTES,
    );
    totalBytes += raw.length;
    if (totalBytes > PRIVATE_RELEASE_INPUT_MAX_TOTAL_BYTES) {
      throw new Error("private release artifact inputs exceed the bounded total size");
    }
    let value;
    try {
      value = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new Error("private release artifact input is not JSON");
    }

    const contentSha256 = sha256(raw);
    const semanticSha256 = sha256(
      compactJsonBytes(semanticCanonicalJsonValue(value)),
    );
    if (contentDigests.has(contentSha256) || semanticDigests.has(semanticSha256)) {
      throw new Error("private release artifact inputs contain a duplicate or colliding object");
    }
    contentDigests.add(contentSha256);
    semanticDigests.add(semanticSha256);
    inputs.push({
      flag: entry.flag,
      content_sha256: contentSha256,
      semantic_sha256: semanticSha256,
    });
    addNeedle("artifact_raw", raw);
    addNeedle("artifact_pretty", canonicalJsonBytes(value));
    addNeedle("artifact_compact", compactJsonBytes(value));
    addNeedle("private_path", Buffer.from(entry.filePath, "utf8"));
    addNeedle("private_basename", Buffer.from(path.basename(entry.filePath), "utf8"));
    collectPrivateJsonNeedles(value, addNeedle);

    if (entry.flag === "--release") {
      const wrapper = value?.operator_policy;
      if (!wrapper || typeof wrapper !== "object" || Array.isArray(wrapper)) {
        throw new Error("private release artifact audit could not extract the live wrapper");
      }
      addNeedle("live_wrapper_pretty", canonicalJsonBytes(wrapper));
      addNeedle("live_wrapper_compact", compactJsonBytes(wrapper));
      collectPrivateJsonNeedles(wrapper, addNeedle);
    }
  }

  inputs.sort((left, right) => left.flag.localeCompare(right.flag, "en"));
  const needles = [...needlesByDigestAndBytes.values()].sort((left, right) => (
    left.sha256.localeCompare(right.sha256, "en")
    || left.category.localeCompare(right.category, "en")
    || left.base64.localeCompare(right.base64, "en")
  ));
  const payload = { schema, inputs, needles };
  return Object.freeze({
    ...payload,
    fingerprintSha256: sha256(canonicalJsonBytes(payload)),
  });
}

export function loadPrivateReleaseArtifactAudit(releaseArguments) {
  return loadPrivateArtifactAudit(releaseArguments, {
    requiredFlags: REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS,
    schema: PRIVATE_RELEASE_AUDIT_SCHEMA,
  });
}

export function loadPrivateFrontendCandidateArtifactAudit(releaseArguments) {
  return loadPrivateArtifactAudit(releaseArguments, {
    requiredFlags: REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS,
    schema: PRIVATE_FRONTEND_CANDIDATE_AUDIT_SCHEMA,
  });
}

function reversibleNeedleRepresentations(bytes) {
  const representations = [bytes];
  if (bytes.length < 8) return representations;
  representations.push(
    Buffer.from(bytes.toString("base64"), "ascii"),
    Buffer.from(bytes.toString("base64url"), "ascii"),
    Buffer.from(bytes.toString("hex"), "ascii"),
  );
  if (bytes.length <= 256 * 1024) {
    const text = bytes.toString("utf8");
    if (Buffer.from(text, "utf8").equals(bytes)) {
      representations.push(
        Buffer.from(encodeURIComponent(text), "ascii"),
        Buffer.from(JSON.stringify(text).slice(1, -1), "utf8"),
      );
    }
  }
  return [...new Map(representations.map((entry) => [
    `${entry.length}:${entry.toString("base64")}`,
    entry,
  ])).values()];
}

function assertNoSecretEgress(content, secretValues) {
  for (const secret of secretValues) {
    if (
      secret.length >= 8
      && reversibleNeedleRepresentations(secret)
        .some((representation) => content.includes(representation))
    ) {
      throw new Error(
        "Cloudflare build contains a sensitive environment value or reversible encoding",
      );
    }
  }
  const text = content.toString("utf8");
  if (TEXT_SECRET_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new Error("Cloudflare build contains a private credential pattern");
  }
}

function assertNoPrivateReleaseArtifactEgress(content, audit) {
  for (const needle of audit.needles) {
    const bytes = Buffer.from(needle.base64, "base64");
    for (const representation of reversibleNeedleRepresentations(bytes)) {
      if (content.includes(representation)) {
        throw new Error(
          "Cloudflare build contains private release authority, receipt, signature, path, or reversible encoding",
        );
      }
    }
  }
}

export async function auditCloudflareBuild({
  distDir,
  env = {},
  mode,
  releaseSha = "",
  sensitiveEnv = process.env,
  privateReleaseAudit,
}) {
  if (!new Set(["candidate", "live", "modeled"]).has(mode)) {
    throw new Error("Cloudflare build audit requires an explicit release mode");
  }
  const files = await collectRegularFiles(distDir);
  if (!files.length) throw new Error("Cloudflare build output is empty");

  const byPath = new Map(files.map((file) => [file.relative, file]));
  for (const required of ["index.html", "_headers", "wikigen-bootstrap-v3.js"]) {
    if (!byPath.has(required)) {
      throw new Error(`Cloudflare build is missing required artifact ${required}`);
    }
  }
  const normalizedPrivateReleaseAudit = mode === "live"
    ? normalizePrivateReleaseArtifactAudit(privateReleaseAudit)
    : mode === "candidate"
      ? normalizePrivateFrontendCandidateArtifactAudit(privateReleaseAudit)
      : null;

  const secretValues = sensitiveEnvironmentValues(sensitiveEnv);
  const manifestEntries = [];
  const contentsByPath = new Map();
  let releaseShaPresent = false;
  for (const file of files) {
    const content = await readStableRegularFile(
      file,
      "Cloudflare build file",
      MAX_BUILD_FILE_BYTES,
    );
    contentsByPath.set(file.relative, content);
    assertNoSecretEgress(content, secretValues);
    if (normalizedPrivateReleaseAudit) {
      assertNoPrivateReleaseArtifactEgress(
        Buffer.from(file.relative, "utf8"),
        normalizedPrivateReleaseAudit,
      );
      assertNoPrivateReleaseArtifactEgress(content, normalizedPrivateReleaseAudit);
    }
    if (FORBIDDEN_BUILD_PATH.test(file.relative)) {
      throw new Error("Cloudflare build contains a forbidden credential or source-map path");
    }
    if (FORBIDDEN_PAGES_BUILD_PATH.test(file.relative)) {
      throw new Error("Cloudflare build contains a competing or ignored Pages control path");
    }
    if (releaseSha && content.includes(Buffer.from(releaseSha, "ascii"))) {
      releaseShaPresent = true;
    }
    manifestEntries.push({
      path: file.relative,
      mode: file.metadata.mode & 0o777,
      size: content.length,
      sha256: sha256(content),
    });
  }

  const expectedHeaders = renderProductionHeadersForEnv(env);
  const actualHeaders = contentsByPath.get("_headers").toString("utf8");
  if (actualHeaders !== expectedHeaders) {
    throw new Error("Cloudflare build security headers do not match the audited release environment");
  }

  const index = contentsByPath.get("index.html").toString("utf8");
  if (
    index.includes('src="/src/')
    || !index.includes('src="/wikigen-bootstrap-v3.js"')
    || !index.includes('href="https://www.wikigen.me/"')
  ) {
    throw new Error("Cloudflare build index is stale or not the canonical production document");
  }
  const referencedAssets = [...index.matchAll(/(?:src|href)="\/(assets\/[^"?#]+)"/g)]
    .map((match) => match[1]);
  if (!referencedAssets.length || !referencedAssets.some((asset) => asset.startsWith("assets/r2/"))) {
    throw new Error("Cloudflare build index does not reference the versioned asset graph");
  }
  for (const asset of referencedAssets) {
    if (
      asset !== path.posix.normalize(asset)
      || asset.startsWith("../")
      || !byPath.has(asset)
    ) {
      throw new Error("Cloudflare build index references a missing or unsafe asset");
    }
  }

  if (mode === "live" || mode === "candidate") {
    if (!/^[0-9a-f]{40}$/.test(releaseSha) || !releaseShaPresent) {
      throw new Error("live Cloudflare build does not contain its exact release SHA");
    }
  } else if (releaseSha) {
    throw new Error("modeled Cloudflare build must not claim a release SHA");
  }

  const manifest = `${JSON.stringify(manifestEntries)}\n`;
  return Object.freeze({
    fileCount: manifestEntries.length,
    totalBytes: manifestEntries.reduce((sum, entry) => sum + entry.size, 0),
    manifestSha256: sha256(manifest),
  });
}

export async function auditCloudflareStage({
  stageDir,
  distAudit,
  mode,
  sensitiveEnv = process.env,
  privateReleaseAudit,
}) {
  if (!new Set(["live", "modeled"]).has(mode)) {
    throw new Error("Cloudflare stage audit requires an explicit release mode");
  }
  if (!distAudit || !/^[0-9a-f]{64}$/.test(String(distAudit.manifestSha256 || ""))) {
    throw new Error("Cloudflare stage audit requires the audited dist manifest");
  }
  const files = await collectRegularFiles(stageDir, {
    maximumFiles: MAX_BUILD_FILES + 16,
    maximumFileBytes: MAX_BUILD_FILE_BYTES,
    maximumTotalBytes: MAX_BUILD_TOTAL_BYTES + (1024 * 1024),
  });
  const paths = files.map((file) => file.relative);
  for (const required of [
    "dist/index.html",
    "dist/_headers",
    "functions/_middleware.js",
    "wrangler.toml",
    "package.json",
  ]) {
    if (!paths.includes(required)) {
      throw new Error(`Cloudflare staged bundle is missing ${required}`);
    }
  }
  const functionPaths = paths.filter((value) => value.startsWith("functions/"));
  if (
    functionPaths.length !== 1
    || functionPaths[0] !== "functions/_middleware.js"
    || paths.some((value) => (
      !value.startsWith("dist/")
      && !value.startsWith("functions/")
      && !new Set(["wrangler.toml", "package.json"]).has(value)
    ))
  ) {
    throw new Error("Cloudflare staged bundle contains an unreviewed upload path");
  }

  const secretValues = sensitiveEnvironmentValues(sensitiveEnv);
  const normalizedPrivateReleaseAudit = mode === "live"
    ? normalizePrivateReleaseArtifactAudit(privateReleaseAudit)
    : null;
  if (mode === "modeled" && privateReleaseAudit !== undefined) {
    throw new Error("modeled Cloudflare stage cannot consume private live release authority");
  }
  const manifestEntries = [];
  const contentsByPath = new Map();
  for (const file of files) {
    if (FORBIDDEN_BUILD_PATH.test(file.relative)) {
      throw new Error("Cloudflare staged bundle contains a forbidden credential or source-map path");
    }
    const content = await readStableRegularFile(
      file,
      "Cloudflare staged file",
      MAX_BUILD_FILE_BYTES,
    );
    contentsByPath.set(file.relative, content);
    assertNoSecretEgress(content, secretValues);
    if (normalizedPrivateReleaseAudit) {
      assertNoPrivateReleaseArtifactEgress(
        Buffer.from(file.relative, "utf8"),
        normalizedPrivateReleaseAudit,
      );
      assertNoPrivateReleaseArtifactEgress(content, normalizedPrivateReleaseAudit);
    }
    manifestEntries.push({
      path: file.relative,
      mode: file.metadata.mode & 0o777,
      size: content.length,
      sha256: sha256(content),
    });
  }
  const wranglerConfig = contentsByPath.get("wrangler.toml").toString("utf8");
  if (wranglerConfig !== EXPECTED_WRANGLER_CONFIG) {
    throw new Error("Cloudflare staged bundle does not use the reviewed Pages configuration");
  }

  const manifest = `${JSON.stringify({
    dist_manifest_sha256: distAudit.manifestSha256,
    files: manifestEntries,
  })}\n`;
  const uploadControlEntries = manifestEntries.filter((entry) => (
    CLOUDFLARE_UPLOAD_CONTROL_PATHS.includes(entry.path)
  ));
  if (uploadControlEntries.length !== CLOUDFLARE_UPLOAD_CONTROL_PATHS.length) {
    throw new Error("Cloudflare staged bundle is missing a release control file");
  }
  return Object.freeze({
    fileCount: manifestEntries.length,
    totalBytes: manifestEntries.reduce((sum, entry) => sum + entry.size, 0),
    bundleManifestSha256: sha256(manifest),
    uploadControlManifestSha256: controlManifestSha256(uploadControlEntries),
    distManifestSha256: distAudit.manifestSha256,
  });
}

async function copyRegularTree(source, target) {
  const sourceMetadata = await lstat(source);
  if (!sourceMetadata.isDirectory() || sourceMetadata.isSymbolicLink()) {
    throw new Error("Cloudflare staging input tree is not a real directory");
  }
  await mkdir(target, { recursive: false, mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const sourcePath = path.join(source, entry.name);
    const targetPath = path.join(target, entry.name);
    const metadata = await lstat(sourcePath);
    if (metadata.isSymbolicLink()) {
      throw new Error("Cloudflare staging input contains a symbolic link");
    }
    if (metadata.isDirectory()) {
      await copyRegularTree(sourcePath, targetPath);
    } else if (metadata.isFile()) {
      const content = await readStableRegularFile(
        { absolute: sourcePath, metadata },
        "Cloudflare staging source file",
        MAX_BUILD_FILE_BYTES,
      );
      const targetHandle = await open(
        targetPath,
        constants.O_WRONLY
          | constants.O_CREAT
          | constants.O_EXCL
          | (constants.O_NOFOLLOW || 0),
        metadata.mode & 0o777,
      );
      try {
        await targetHandle.writeFile(content);
        await targetHandle.sync();
      } finally {
        await targetHandle.close();
      }
      await chmod(targetPath, metadata.mode & 0o777);
    } else {
      throw new Error("Cloudflare staging input contains a non-regular entry");
    }
  }
}

export async function stageCloudflareBundle(webDir) {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const stageDir = await mkdtemp(
    path.join(canonicalTemporaryRoot, "dnai-cloudflare-release-"),
  );
  try {
    await chmod(stageDir, 0o700);
    const canonicalStage = await realpath(stageDir);
    const stageMetadata = await lstat(stageDir);
    const expectedUid = typeof process.geteuid === "function"
      ? process.geteuid()
      : stageMetadata.uid;
    if (
      canonicalStage !== stageDir
      || !stageMetadata.isDirectory()
      || stageMetadata.isSymbolicLink()
      || stageMetadata.uid !== expectedUid
      || (stageMetadata.mode & 0o077) !== 0
    ) {
      throw new Error(
        "Cloudflare staging directory is not private, canonical, and operator-owned",
      );
    }
    await copyRegularTree(path.join(webDir, "dist"), path.join(stageDir, "dist"));
    await copyRegularTree(path.join(webDir, "functions"), path.join(stageDir, "functions"));
    for (const name of ["wrangler.toml", "package.json"]) {
      const source = path.join(webDir, name);
      const metadata = await lstat(source);
      if (
        !metadata.isFile()
        || metadata.isSymbolicLink()
        || metadata.nlink !== 1
      ) {
        throw new Error(`Cloudflare staging input ${name} is not a single-link regular file`);
      }
      const target = path.join(stageDir, name);
      const content = await readStableRegularFile(
        { absolute: source, metadata },
        `Cloudflare staging input ${name}`,
        MAX_BUILD_FILE_BYTES,
      );
      const targetHandle = await open(
        target,
        constants.O_WRONLY
          | constants.O_CREAT
          | constants.O_EXCL
          | (constants.O_NOFOLLOW || 0),
        metadata.mode & 0o777,
      );
      try {
        await targetHandle.writeFile(content);
        await targetHandle.sync();
      } finally {
        await targetHandle.close();
      }
      await chmod(target, metadata.mode & 0o777);
    }
    return stageDir;
  } catch (error) {
    await rm(stageDir, { recursive: true, force: true });
    throw error;
  }
}

export async function resetCloudflareBuildOutput(webDir) {
  await rm(path.join(webDir, "dist"), { recursive: true, force: true });
}

export async function removeCloudflareStage(stageDir) {
  await rm(stageDir, { recursive: true, force: true });
}

export const __test = Object.freeze({
  CLOUDFLARE_UPLOAD_CONTROL_PATHS,
  EXPECTED_WRANGLER_CONFIG,
  FORBIDDEN_PRIVATE_RELEASE_FLAGS,
  FORBIDDEN_BUILD_PATH,
  FORBIDDEN_PAGES_BUILD_PATH,
  PRIVATE_RELEASE_AUDIT_SCHEMA,
  PRIVATE_FRONTEND_CANDIDATE_AUDIT_SCHEMA,
  REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS,
  REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS,
  SOURCE_EXCLUSIONS,
  SOURCE_ENV_OUTPUT_PATH,
  SOURCE_FINGERPRINT_SCHEMA,
  TEXT_SECRET_PATTERNS,
  normalizePrivateReleaseArtifactAudit,
  normalizePrivateFrontendCandidateArtifactAudit,
});
