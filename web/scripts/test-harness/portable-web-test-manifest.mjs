import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PORTABLE_WEB_TEST_MANIFEST_SCHEMA =
  "dnai.portable-web-test-manifest.v1";
export const PORTABLE_WEB_TEST_TRUTH =
  "portable_web_source_suites_only_not_frozen_darwin_operator_host_authority";
export const OPERATOR_WEB_TEST_TRUTH =
  "requires_frozen_darwin_node_npm_and_sandbox_operator_host";

export const WEB_ROOT = path.resolve(fileURLToPath(new URL("../..", import.meta.url)));
export const MANIFEST_PATH = path.join(
  WEB_ROOT,
  "scripts",
  "test-harness",
  "portable-web-test-manifest.json",
);

const TEST_PATH = /^scripts\/[a-z0-9][a-z0-9.-]*\.test\.mjs$/;
const PORTABLE_SPLIT_KAT = "scripts/portable-ci-test-split.test.mjs";
const REVIEWED_OPERATOR_HOST_TESTS = Object.freeze([
  "scripts/cloudflare-operator-host-authority.test.mjs",
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
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(expected)
  ) {
    throw new Error(`${label} fields are not exact`);
  }
}

export function canonicalWebTestFileSetSha256(files) {
  if (
    !Array.isArray(files)
    || files.length === 0
    || files.some((entry) => typeof entry !== "string")
  ) {
    throw new Error("web test file set must be one nonempty string array");
  }
  return `sha256:${createHash("sha256")
    .update("dnai-wikigen/portable-web-test-file-set/v1\0", "utf8")
    .update(`${files.join("\n")}\n`, "utf8")
    .digest("hex")}`;
}

export function discoverWebTests() {
  const scripts = path.join(WEB_ROOT, "scripts");
  const scriptsStat = fs.lstatSync(scripts);
  if (
    !scriptsStat.isDirectory()
    || scriptsStat.isSymbolicLink()
    || fs.realpathSync(scripts) !== scripts
  ) {
    throw new Error("web test directory must be one canonical real directory");
  }
  const discovered = [];
  for (const entry of fs.readdirSync(scripts, { withFileTypes: true })) {
    if (!entry.name.endsWith(".test.mjs")) continue;
    const absolute = path.join(scripts, entry.name);
    const metadata = fs.lstatSync(absolute);
    if (
      !entry.isFile()
      || entry.isSymbolicLink()
      || !metadata.isFile()
      || metadata.isSymbolicLink()
      || metadata.nlink !== 1
      || metadata.size < 1
      || metadata.size > 4 * 1024 * 1024
      || fs.realpathSync(absolute) !== absolute
    ) {
      throw new Error(`web test entry is not a regular file: ${entry.name}`);
    }
    discovered.push(`scripts/${entry.name}`);
  }
  return discovered.sort();
}

function exactSortedFileSet(value, label) {
  if (
    !Array.isArray(value)
    || value.length === 0
    || value.some((entry) => typeof entry !== "string" || !TEST_PATH.test(entry))
  ) {
    throw new Error(`${label} must contain only canonical web test paths`);
  }
  const sorted = [...value].sort();
  if (
    new Set(value).size !== value.length
    || JSON.stringify(value) !== JSON.stringify(sorted)
  ) {
    throw new Error(`${label} must be unique and bytewise sorted`);
  }
  return value;
}

export function loadAndAssertPortableWebTestManifest() {
  const stat = fs.lstatSync(MANIFEST_PATH);
  if (
    !stat.isFile()
    || stat.isSymbolicLink()
    || stat.nlink !== 1
    || stat.size < 256
    || stat.size > 64 * 1024
    || fs.realpathSync(MANIFEST_PATH) !== MANIFEST_PATH
  ) {
    throw new Error("portable web test manifest is not one bounded regular file");
  }
  const bytes = fs.readFileSync(MANIFEST_PATH);
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new Error("portable web test manifest is not JSON");
  }
  exactKeys(manifest, MANIFEST_FIELDS, "portable web test manifest");
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
    throw new Error("portable web test manifest bytes are not canonical");
  }
  if (
    manifest.schema !== PORTABLE_WEB_TEST_MANIFEST_SCHEMA
    || manifest.discovered_glob !== "scripts/*.test.mjs"
    || manifest.portable_truth_status !== PORTABLE_WEB_TEST_TRUTH
    || manifest.operator_host_truth_status !== OPERATOR_WEB_TEST_TRUTH
  ) {
    throw new Error("portable web test manifest truth boundary is invalid");
  }
  const portable = exactSortedFileSet(manifest.portable, "portable web tests");
  const operatorHost = exactSortedFileSet(
    manifest.operator_host,
    "operator-host web tests",
  );
  const discovered = discoverWebTests();
  const assigned = [...portable, ...operatorHost].sort();
  if (
    portable.some((entry) => operatorHost.includes(entry))
    || JSON.stringify(assigned) !== JSON.stringify(discovered)
  ) {
    throw new Error("every discovered web test must be assigned exactly once");
  }
  if (
    !portable.includes(PORTABLE_SPLIT_KAT)
    || JSON.stringify(operatorHost) !== JSON.stringify(REVIEWED_OPERATOR_HOST_TESTS)
  ) {
    throw new Error(
      "portable split KAT and reviewed operator-host set must remain in their frozen classes",
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
    if (count !== files.length || digest !== canonicalWebTestFileSetSha256(files)) {
      throw new Error(`${label} web test count or digest drifted`);
    }
  }
  return Object.freeze({
    ...manifest,
    portable: Object.freeze([...portable]),
    operator_host: Object.freeze([...operatorHost]),
  });
}
