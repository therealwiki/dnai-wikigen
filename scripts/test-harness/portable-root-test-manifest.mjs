import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PORTABLE_ROOT_TEST_MANIFEST_SCHEMA =
  "dnai.portable-root-test-manifest.v1";
export const PORTABLE_ROOT_TEST_TRUTH =
  "portable_test_suites_only_not_frozen_operator_host_activation";
export const OPERATOR_HOST_TEST_TRUTH =
  "requires_frozen_operator_host_and_is_not_activated_by_generic_ci";

export const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
);
export const MANIFEST_PATH = path.join(
  ROOT,
  "scripts",
  "test-harness",
  "portable-root-test-manifest.json",
);

const TEST_PATH = /^scripts\/[a-z0-9][a-z0-9.-]*\.test\.mjs$/;
const PORTABLE_SPLIT_KAT = "scripts/portable-ci-test-split.test.mjs";
const REVIEWED_OPERATOR_HOST_TESTS = Object.freeze([
  "scripts/phala-nonlive-bootstrap-authorization-cli.test.mjs",
  "scripts/phala-nonlive-bootstrap-authorization.test.mjs",
  "scripts/phala-pinned-private-directory.test.mjs",
  "scripts/phala-post-measurement-activation-journal.test.mjs",
  "scripts/phala-post-measurement-activation-receipt.test.mjs",
  "scripts/phala-pre-provision-authority-producer.test.mjs",
  "scripts/phala-production-activation-driver.test.mjs",
  "scripts/phala-production-authority-workspace-prepare.test.mjs",
  "scripts/phala-production-execution-replay.test.mjs",
  "scripts/phala-production-executor-core.test.mjs",
  "scripts/phala-production-postlaunch-activation-capability.test.mjs",
  "scripts/phala-production-postlaunch-attach.test.mjs",
  "scripts/phala-production-recovery-journal.test.mjs",
  "scripts/phala-production-resident-io.test.mjs",
  "scripts/phala-production-sdk-adapter.test.mjs",
  "scripts/phala-production-stage-b-attach.test.mjs",
  "scripts/phala-seven-cvm-historical-transcript-persistence.test.mjs",
  "scripts/phala-seven-cvm-verifier-evidence.test.mjs",
  "scripts/release-authority-signature-verifier.test.mjs",
  "scripts/release-ceremony-lock.test.mjs",
  "scripts/royalty-release-finalized-history-evidence.test.mjs",
  "scripts/royalty-release-history-receipt.test.mjs",
  "scripts/tinker-account-binding-ceremony.test.mjs",
]);
const MANIFEST_FIELDS = [
  "discovered_file_count",
  "discovered_files_sha256",
  "discovered_glob",
  "operator_host",
  "operator_host_file_count",
  "operator_host_files_sha256",
  "operator_host_truth_status",
  "portable",
  "portable_file_count",
  "portable_files_sha256",
  "portable_truth_status",
  "schema",
].sort();

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expected)) {
    throw new Error(`${label} fields are not exact`);
  }
}

export function canonicalTestFileSetSha256(files) {
  if (!Array.isArray(files) || files.length === 0
    || files.some((entry) => typeof entry !== "string")) {
    throw new Error("test file set must be one nonempty string array");
  }
  return `sha256:${createHash("sha256")
    .update("dnai-wikigen/portable-root-test-file-set/v1\0", "utf8")
    .update(`${files.join("\n")}\n`, "utf8")
    .digest("hex")}`;
}

export function discoverRootTests() {
  const scripts = path.join(ROOT, "scripts");
  const scriptsStat = fs.lstatSync(scripts);
  if (!scriptsStat.isDirectory() || scriptsStat.isSymbolicLink()
    || fs.realpathSync(scripts) !== scripts) {
    throw new Error("root test directory must be one canonical real directory");
  }
  const discovered = [];
  for (const entry of fs.readdirSync(scripts, { withFileTypes: true })) {
    if (!entry.name.endsWith(".test.mjs")) continue;
    const absolute = path.join(scripts, entry.name);
    const metadata = fs.lstatSync(absolute);
    if (!entry.isFile() || entry.isSymbolicLink()
      || !metadata.isFile() || metadata.isSymbolicLink()
      || metadata.nlink !== 1 || metadata.size < 1
      || metadata.size > 4 * 1024 * 1024
      || fs.realpathSync(absolute) !== absolute) {
      throw new Error(`root test entry is not a regular file: ${entry.name}`);
    }
    discovered.push(`scripts/${entry.name}`);
  }
  return discovered.sort();
}

function exactSortedFileSet(value, label) {
  if (!Array.isArray(value) || value.length === 0
    || value.some((entry) => typeof entry !== "string" || !TEST_PATH.test(entry))) {
    throw new Error(`${label} must contain only canonical root test paths`);
  }
  const sorted = [...value].sort();
  if (new Set(value).size !== value.length
    || JSON.stringify(value) !== JSON.stringify(sorted)) {
    throw new Error(`${label} must be unique and bytewise sorted`);
  }
  return value;
}

export function loadAndAssertPortableRootTestManifest() {
  const stat = fs.lstatSync(MANIFEST_PATH);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1
    || stat.size < 256 || stat.size > 64 * 1024
    || fs.realpathSync(MANIFEST_PATH) !== MANIFEST_PATH) {
    throw new Error("portable root test manifest is not one bounded regular file");
  }
  const bytes = fs.readFileSync(MANIFEST_PATH);
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("portable root test manifest is not JSON");
  }
  exactKeys(manifest, MANIFEST_FIELDS, "portable root test manifest");
  const canonicalManifest = {
    schema: manifest.schema,
    portable_truth_status: manifest.portable_truth_status,
    operator_host_truth_status: manifest.operator_host_truth_status,
    discovered_glob: manifest.discovered_glob,
    discovered_file_count: manifest.discovered_file_count,
    discovered_files_sha256: manifest.discovered_files_sha256,
    portable_file_count: manifest.portable_file_count,
    portable_files_sha256: manifest.portable_files_sha256,
    operator_host_file_count: manifest.operator_host_file_count,
    operator_host_files_sha256: manifest.operator_host_files_sha256,
    portable: manifest.portable,
    operator_host: manifest.operator_host,
  };
  if (bytes.toString("utf8") !== `${JSON.stringify(canonicalManifest, null, 2)}\n`) {
    throw new Error("portable root test manifest bytes are not canonical");
  }
  if (manifest.schema !== PORTABLE_ROOT_TEST_MANIFEST_SCHEMA
    || manifest.discovered_glob !== "scripts/*.test.mjs"
    || manifest.portable_truth_status !== PORTABLE_ROOT_TEST_TRUTH
    || manifest.operator_host_truth_status !== OPERATOR_HOST_TEST_TRUTH) {
    throw new Error("portable root test manifest truth boundary is invalid");
  }
  const portable = exactSortedFileSet(manifest.portable, "portable root tests");
  const operatorHost = exactSortedFileSet(
    manifest.operator_host,
    "operator-host root tests",
  );
  const discovered = discoverRootTests();
  const assigned = [...portable, ...operatorHost].sort();
  if (portable.some((entry) => operatorHost.includes(entry))
    || JSON.stringify(assigned) !== JSON.stringify(discovered)) {
    throw new Error("every discovered root test must be assigned exactly once");
  }
  if (!portable.includes(PORTABLE_SPLIT_KAT)
    || JSON.stringify(operatorHost) !== JSON.stringify(REVIEWED_OPERATOR_HOST_TESTS)) {
    throw new Error(
      "portable split KAT and full reviewed operator-host set must remain in their frozen classes",
    );
  }
  for (const [files, count, digest, label] of [
    [discovered, manifest.discovered_file_count, manifest.discovered_files_sha256, "discovered"],
    [portable, manifest.portable_file_count, manifest.portable_files_sha256, "portable"],
    [
      operatorHost,
      manifest.operator_host_file_count,
      manifest.operator_host_files_sha256,
      "operator-host",
    ],
  ]) {
    if (count !== files.length || digest !== canonicalTestFileSetSha256(files)) {
      throw new Error(`${label} root test count or digest drifted`);
    }
  }
  return Object.freeze({
    ...manifest,
    portable: Object.freeze([...portable]),
    operator_host: Object.freeze([...operatorHost]),
  });
}
