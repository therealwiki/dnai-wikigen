import { createHash, randomBytes as cryptoRandomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readFile,
  rename,
  rm,
} from "node:fs/promises";
import path from "node:path";

import { REQUIRED_RUNTIME_CREDENTIALS } from "./activation-preflight-core.mjs";

export const ACTIVATION_ENV_SCHEMA = "dnai.activation-environment.v1";
export const MAX_ENV_BYTES = 2 * 1024 * 1024;

// Two pairs intentionally share a value: both clients of the compute-metering
// QVL use that QVL's one bearer, and the compute worker uses the metering
// service's inbound bearer. Every other trust domain receives independent
// entropy.
export const INTERNAL_ACTIVATION_SECRET_GROUPS = Object.freeze([
  Object.freeze(["TINKER_DILIGENCE_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_ARENA_WORKER_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_EXECUTION_POLICY_ANCHOR_WRITER_QVL_AUTH_TOKEN"]),
  Object.freeze(["TINKER_COMPUTE_WORKLOAD_QVL_AUTH_TOKEN"]),
  Object.freeze([
    "TINKER_COMPUTE_METERING_QVL_AUTH_TOKEN",
    "METERING_QVL_AUTH_TOKEN",
  ]),
  Object.freeze([
    "METERING_AUTH_TOKEN",
    "TINKER_COMPUTE_METERING_AUTH_TOKEN",
  ]),
  Object.freeze(["NEKO_PASSWORD"]),
  Object.freeze(["NEKO_PASSWORD_ADMIN"]),
]);

export const INTERNAL_ACTIVATION_SECRET_KEYS = Object.freeze(
  INTERNAL_ACTIVATION_SECRET_GROUPS.flat(),
);
export const FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES = Object.freeze([
  "JUDGE_PRIVATE_KEY",
  "KMS_PRIVATE_KEY",
]);

const expectedPreflightKeys = REQUIRED_RUNTIME_CREDENTIALS
  .map(([, key]) => key)
  .filter((key) => key !== "ETHERSCAN_API_KEY");
if (
  expectedPreflightKeys.length !== INTERNAL_ACTIVATION_SECRET_KEYS.length
  || expectedPreflightKeys.some((key, index) => key !== INTERNAL_ACTIVATION_SECRET_KEYS[index])
) {
  throw new Error("internal activation credential contract drift");
}

const SECRET_VALUE_PATTERN = /^[\x21-\x7e]{32,4096}$/;
const GENERATED_SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const MAX_COLLISION_ATTEMPTS = 32;
const NOFOLLOW = constants.O_NOFOLLOW ?? 0;

export class ActivationEnvError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ActivationEnvError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new ActivationEnvError(code, message);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function stripInlineComment(value) {
  let single = false;
  let double = false;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "'" && !double) single = !single;
    if (character === '"' && !single) double = !double;
    if (character === "#" && !single && !double) {
      const previous = index === 0 ? " " : value[index - 1];
      if (/\s/.test(previous)) return value.slice(0, index).trimEnd();
    }
  }
  return value;
}

function normalizedValue(rawValue) {
  const trimmed = stripInlineComment(rawValue).trim();
  if (
    trimmed.length >= 2
    && ((trimmed.startsWith('"') && trimmed.endsWith('"'))
      || (trimmed.startsWith("'") && trimmed.endsWith("'")))
  ) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function newlineFor(text) {
  return text.includes("\r\n") ? "\r\n" : "\n";
}

function parseDocument(text, label) {
  if (typeof text !== "string" || Buffer.byteLength(text, "utf8") > MAX_ENV_BYTES) {
    fail("input_size", `${label} exceeds the bounded environment size`);
  }
  if (text.includes("\u0000")) fail("input_nul", `${label} contains a NUL byte`);

  const lines = text.split(/\r?\n/);
  const records = new Map();
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const match = line.match(/^(\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*)(.*)$/);
    if (!match) continue;
    const [, prefix, key, rawValue] = match;
    if (records.has(key)) fail("duplicate_key", `${label} contains duplicate key ${key}`);
    records.set(key, {
      key,
      lineIndex: index,
      prefix,
      rawValue,
      value: normalizedValue(rawValue),
    });
  }
  return { lines, records, newline: newlineFor(text) };
}

function appendMissingAssignments(targetText, missingRecords, newline) {
  if (missingRecords.length === 0) return targetText;
  const prefix = targetText.length === 0
    ? ""
    : `${targetText.endsWith("\n") ? "" : newline}${newline}`;
  const assignments = missingRecords.map((record) => `${record.key}=${record.rawValue}`);
  return [
    targetText,
    prefix,
    "# Synced from example.env by scripts/prepare-activation-env.mjs.",
    newline,
    assignments.join(newline),
    newline,
  ].join("");
}

function validateInternalSecret(value) {
  return SECRET_VALUE_PATTERN.test(value)
    && Buffer.byteLength(value, "utf8") === value.length;
}

function analyzeText({ templateText, targetText, targetExists, generateInternalSecrets }) {
  const template = parseDocument(templateText, "example.env");
  const missingTemplateSecrets = INTERNAL_ACTIVATION_SECRET_KEYS.filter(
    (key) => !template.records.has(key),
  );
  if (missingTemplateSecrets.length > 0) {
    fail("template_contract", "example.env is missing an internal activation key");
  }

  let baseText;
  let addedKeys;
  if (!targetExists) {
    baseText = templateText;
    addedKeys = template.records.size;
  } else {
    const target = parseDocument(targetText, ".env");
    const forbiddenLegacyKey = FORBIDDEN_LEGACY_PRIVATE_KEY_NAMES.find(
      (key) => target.records.has(key),
    );
    if (forbiddenLegacyKey) {
      fail(
        "legacy_private_key",
        `.env contains prohibited legacy key ${forbiddenLegacyKey}; migrate it to the documented dstack/Foundry keystore path before retrying`,
      );
    }
    const missing = [...template.records.values()].filter(
      (record) => !target.records.has(record.key),
    );
    baseText = appendMissingAssignments(targetText, missing, target.newline);
    addedKeys = missing.length;
  }

  const merged = parseDocument(baseText, ".env");
  const groupPlans = [];
  const occupied = new Map();
  if (generateInternalSecrets) {
    for (const group of INTERNAL_ACTIVATION_SECRET_GROUPS) {
      const values = group
        .map((key) => merged.records.get(key)?.value ?? "")
        .filter((value) => value.length > 0);
      const distinct = [...new Set(values)];
      if (distinct.length > 1) {
        fail("alias_mismatch", "an internal activation secret alias pair does not match");
      }
      const existingValue = distinct[0] ?? "";
      if (existingValue && !validateInternalSecret(existingValue)) {
        fail("invalid_secret", "an existing internal activation secret has an unsafe format");
      }
      if (existingValue) {
        const priorGroup = occupied.get(existingValue);
        if (priorGroup && priorGroup !== group) {
          fail("secret_reuse", "independent internal activation secret domains reuse a value");
        }
        occupied.set(existingValue, group);
      }
      const keysToFill = group.filter((key) => !merged.records.get(key)?.value);
      groupPlans.push({ group, existingValue, keysToFill });
    }
  }

  const secretFieldsToFill = groupPlans.reduce(
    (count, plan) => count + plan.keysToFill.length,
    0,
  );
  return {
    baseText,
    addedKeys,
    groupPlans,
    occupiedValues: new Set(occupied.keys()),
    secretFieldsToFill,
    changesRequired: !targetExists || baseText !== targetText || secretFieldsToFill > 0,
  };
}

function nextGeneratedSecret(randomBytes, occupiedValues) {
  for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
    let bytes;
    try {
      bytes = randomBytes(32);
    } catch {
      fail("rng_failure", "cryptographic random generation failed");
    }
    if (!Buffer.isBuffer(bytes) || bytes.length !== 32) {
      fail("rng_contract", "cryptographic random generation returned an invalid result");
    }
    const secret = bytes.toString("base64url");
    if (!GENERATED_SECRET_PATTERN.test(secret)) {
      fail("rng_contract", "cryptographic random generation returned an invalid result");
    }
    if (!occupiedValues.has(secret)) {
      occupiedValues.add(secret);
      return secret;
    }
  }
  fail("rng_collision", "cryptographic random generation repeatedly collided");
}

function materializeText(analysis, randomBytes) {
  if (analysis.secretFieldsToFill === 0) {
    return { text: analysis.baseText, randomSecretsGenerated: 0 };
  }
  const document = parseDocument(analysis.baseText, ".env");
  const occupied = new Set(analysis.occupiedValues);
  let randomSecretsGenerated = 0;
  for (const plan of analysis.groupPlans) {
    if (plan.keysToFill.length === 0) continue;
    const secret = plan.existingValue || nextGeneratedSecret(randomBytes, occupied);
    if (!plan.existingValue) randomSecretsGenerated += 1;
    for (const key of plan.keysToFill) {
      const record = document.records.get(key);
      document.lines[record.lineIndex] = `${record.prefix}${secret}`;
    }
  }
  return {
    text: document.lines.join(document.newline),
    randomSecretsGenerated,
  };
}

async function readRegularFile(filePath, label, { requiredMode } = {}) {
  let stat;
  try {
    stat = await lstat(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") return null;
    fail("file_inspection", `${label} could not be inspected safely`);
  }
  if (stat.isSymbolicLink()) fail("symlink", `${label} must not be a symlink`);
  if (!stat.isFile()) fail("non_regular", `${label} must be a regular file`);
  if (stat.nlink !== 1) fail("hard_link", `${label} must have exactly one filesystem link`);
  if (requiredMode !== undefined && (stat.mode & 0o7777) !== requiredMode) {
    fail("unsafe_mode", `${label} must have mode 0600`);
  }
  if (stat.size > MAX_ENV_BYTES) fail("input_size", `${label} exceeds the bounded environment size`);

  let handle;
  try {
    handle = await open(filePath, constants.O_RDONLY | NOFOLLOW);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== stat.dev || opened.ino !== stat.ino) {
      fail("file_race", `${label} changed while it was being inspected`);
    }
    const bytes = await handle.readFile();
    if (bytes.length > MAX_ENV_BYTES) fail("input_size", `${label} exceeds the bounded environment size`);
    const roundTrip = Buffer.from(bytes.toString("utf8"), "utf8");
    if (!roundTrip.equals(bytes)) fail("invalid_utf8", `${label} is not valid UTF-8`);
    return {
      text: bytes.toString("utf8"),
      fingerprint: {
        dev: opened.dev,
        ino: opened.ino,
        mode: opened.mode & 0o7777,
        size: opened.size,
        digest: sha256(bytes),
      },
    };
  } catch (error) {
    if (error instanceof ActivationEnvError) throw error;
    fail("file_read", `${label} could not be read safely`);
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function assertTargetUnchanged(targetPath, expected) {
  const current = await readRegularFile(targetPath, ".env", { requiredMode: 0o600 });
  if (!expected) {
    if (current) fail("concurrent_change", ".env appeared during preparation");
    return;
  }
  if (!current) fail("concurrent_change", ".env disappeared during preparation");
  const left = current.fingerprint;
  const right = expected.fingerprint;
  if (
    left.dev !== right.dev
    || left.ino !== right.ino
    || left.mode !== right.mode
    || left.size !== right.size
    || left.digest !== right.digest
  ) {
    fail("concurrent_change", ".env changed during preparation");
  }
}

async function assertTemplateUnchanged(templatePath, expected) {
  const current = await readRegularFile(templatePath, "example.env");
  if (!current) fail("concurrent_change", "example.env disappeared during preparation");
  const left = current.fingerprint;
  const right = expected.fingerprint;
  if (
    left.dev !== right.dev
    || left.ino !== right.ino
    || left.mode !== right.mode
    || left.size !== right.size
    || left.digest !== right.digest
  ) {
    fail("concurrent_change", "example.env changed during preparation");
  }
}

export function isGitTracked(repoRoot, targetPath) {
  const relative = path.relative(repoRoot, targetPath);
  if (!relative || relative === "." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    return false;
  }
  const result = spawnSync("git", ["ls-files", "--error-unmatch", "--", relative], {
    cwd: repoRoot,
    encoding: "utf8",
    stdio: "ignore",
    timeout: 10_000,
  });
  if (result.error) fail("git_check", "Git tracking status could not be checked safely");
  if (result.status === 0) return true;
  if (result.status === 1) return false;
  fail("git_check", "Git tracking status could not be checked safely");
}

async function atomicReplace({
  targetPath,
  templatePath,
  text,
  expectedTarget,
  expectedTemplate,
  trackedCheck,
  beforeCommit,
}) {
  const parent = path.dirname(targetPath);
  let parentStat;
  try {
    parentStat = await lstat(parent);
  } catch {
    fail("parent_directory", ".env parent directory could not be inspected safely");
  }
  if (parentStat.isSymbolicLink() || !parentStat.isDirectory()) {
    fail("parent_directory", ".env parent must be a real directory");
  }

  const suffix = cryptoRandomBytes(12).toString("hex");
  const temporaryPath = path.join(parent, `.${path.basename(targetPath)}.${process.pid}.${suffix}.tmp`);
  let handle;
  try {
    handle = await open(
      temporaryPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    await handle.writeFile(text, "utf8");
    await handle.sync();
    await handle.close();
    handle = null;

    if (beforeCommit) await beforeCommit();
    await assertTemplateUnchanged(templatePath, expectedTemplate);
    await assertTargetUnchanged(targetPath, expectedTarget);
    if (await trackedCheck(targetPath)) fail("tracked_target", ".env must not be tracked by Git");
    await rename(temporaryPath, targetPath);

    let directoryHandle;
    try {
      directoryHandle = await open(parent, constants.O_RDONLY);
      await directoryHandle.sync();
    } catch (error) {
      // Some filesystems do not support directory fsync. The file itself was
      // flushed before the atomic rename; unsupported directory sync is safe
      // to ignore, while every earlier write/rename failure remains fatal.
      if (!["EINVAL", "ENOTSUP", "EISDIR", "EPERM"].includes(error?.code)) throw error;
    } finally {
      await directoryHandle?.close().catch(() => {});
    }
  } catch (error) {
    if (error instanceof ActivationEnvError) throw error;
    fail("atomic_write", ".env could not be replaced atomically");
  } finally {
    await handle?.close().catch(() => {});
    await rm(temporaryPath, { force: true }).catch(() => {});
  }
}

export async function prepareActivationEnvironment({
  repoRoot,
  templatePath,
  targetPath,
  generateInternalSecrets = false,
  check = false,
  dryRun = false,
  randomBytes = cryptoRandomBytes,
  trackedCheck = (candidate) => isGitTracked(repoRoot, candidate),
  beforeCommit,
} = {}) {
  if (!repoRoot || !templatePath || !targetPath) {
    fail("arguments", "repository, template, and target paths are required");
  }
  if (check && dryRun) fail("arguments", "--check and --dry-run are mutually exclusive");
  if (path.resolve(templatePath) === path.resolve(targetPath)) {
    fail("arguments", "example.env and .env must be different files");
  }
  if (await trackedCheck(targetPath)) fail("tracked_target", ".env must not be tracked by Git");

  const template = await readRegularFile(templatePath, "example.env");
  if (!template) fail("missing_template", "example.env does not exist");
  const target = await readRegularFile(targetPath, ".env", { requiredMode: 0o600 });
  const analysis = analyzeText({
    templateText: template.text,
    targetText: target?.text ?? "",
    targetExists: Boolean(target),
    generateInternalSecrets,
  });

  const baseSummary = {
    schema: ACTIVATION_ENV_SCHEMA,
    changesRequired: analysis.changesRequired,
    addedKeys: analysis.addedKeys,
    secretFieldsPrepared: analysis.secretFieldsToFill,
    internalSecretKeyCount: INTERNAL_ACTIVATION_SECRET_KEYS.length,
    distinctSecretGroupCount: INTERNAL_ACTIVATION_SECRET_GROUPS.length,
  };
  if (check || dryRun || !analysis.changesRequired) {
    return {
      ...baseSummary,
      status: analysis.changesRequired ? "needs-update" : "ready",
      wrote: false,
      randomSecretsGenerated: 0,
    };
  }

  const materialized = materializeText(analysis, randomBytes);
  if (Buffer.byteLength(materialized.text, "utf8") > MAX_ENV_BYTES) {
    fail("output_size", "prepared .env exceeds the bounded environment size");
  }
  await atomicReplace({
    targetPath,
    templatePath,
    text: materialized.text,
    expectedTarget: target,
    expectedTemplate: template,
    trackedCheck,
    beforeCommit,
  });
  return {
    ...baseSummary,
    status: "updated",
    wrote: true,
    randomSecretsGenerated: materialized.randomSecretsGenerated,
  };
}
