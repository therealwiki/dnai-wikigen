import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import {
  lstat,
  open,
  readdir,
  realpath,
} from "node:fs/promises";
import path from "node:path";

export const CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA =
  "dnai.cloudflare-external-build-closure.v1";
export const CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS =
  "exact_external_build_inputs";

const AGGREGATE_DOMAIN =
  "dnai.cloudflare-external-build-closure.aggregate.v1";
const RECEIPT_DOMAIN =
  "dnai.cloudflare-external-build-closure.receipt.v1";
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_WEB_CONSUMER_BYTES = 4 * 1024 * 1024;
const SHA256 = /^sha256:[0-9a-f]{64}$/;

const MODULE_ENTRYPOINT_PATHS = Object.freeze([
  "scripts/canonical-authority-graph.mjs",
  "scripts/compute-workload-activation-observation-core.mjs",
  "scripts/execution-policy-release-core-cli.mjs",
  "scripts/execution-policy-release-core.fixture.mjs",
  "scripts/execution-policy-release-core.mjs",
  "scripts/operator-policy-packet-core.mjs",
  "scripts/phala-seven-cvm-historical-transcript.mjs",
  "scripts/pre-ceremony-runtime-authority-core.mjs",
  "scripts/release-authority-historical-core.mjs",
  "scripts/release-manifest-sigstore-verifier.mjs",
]);

const MODULE_CLOSURE_PATHS = Object.freeze([
  "scripts/canonical-authority-graph.mjs",
  "scripts/compute-workload-activation-observation-core.mjs",
  "scripts/cvm-descriptor-runtime-authority-core.mjs",
  "scripts/cvm-launch-intent-core.mjs",
  "scripts/cvm-release-descriptor-set-constants.mjs",
  "scripts/ethereum-keccak.mjs",
  "scripts/execution-policy-release-core-cli.mjs",
  "scripts/execution-policy-release-core.fixture.mjs",
  "scripts/execution-policy-release-core.mjs",
  "scripts/operator-policy-packet-core.mjs",
  "scripts/phala-post-measurement-activation-core.mjs",
  "scripts/phala-production-execution-policy.mjs",
  "scripts/phala-post-measurement-activation-receipt-core.mjs",
  "scripts/phala-seven-cvm-historical-evidence-core.mjs",
  "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs",
  "scripts/phala-seven-cvm-historical-transcript.mjs",
  "scripts/phala-seven-cvm-measurement-policy.mjs",
  "scripts/phala-seven-cvm-release-verification-authority-core.mjs",
  "scripts/pre-ceremony-runtime-authority-core.mjs",
  "scripts/release-authority-historical-core.mjs",
  "scripts/release-authority-signature-verifier-core.mjs",
  "scripts/release-manifest-sigstore-verifier.mjs",
]);

// The historical signature replay implementation intentionally lives under
// web/scripts so Node resolves its exactly pinned Noble dependencies from the
// web workspace. It is already covered by the web source fingerprint; this
// allowlist only proves that the external pure-core graph reaches that one
// adapter and cannot traverse back into any other web module.
const MODULE_WEB_BACKEDGE_PATHS = Object.freeze([
  "web/scripts/independent-eip191-replay-core.mjs",
]);

const MODULE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@noble/curves/secp256k1",
  "@noble/hashes/sha3",
  "@noble/hashes/utils",
]);

const MODULE_NODE_BUILTIN_IMPORTS = Object.freeze([
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:path",
  "node:url",
  "node:util",
]);

// These are exact upper bounds for static imports in the build-time web
// modules. Package bytes are independently bound by the installed dependency
// projection; this list prevents an already-installed transitive dependency
// from silently becoming a new build input.
const WEB_MODULE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@noble/curves/secp256k1",
  "@noble/hashes/sha3",
  "@noble/hashes/utils",
  "typescript",
  "viem",
  "viem/accounts",
  "vite",
]);

const WEB_MODULE_NODE_BUILTIN_IMPORTS = Object.freeze([
  "node:assert/strict",
  "node:child_process",
  "node:crypto",
  "node:fs",
  "node:fs/promises",
  "node:net",
  "node:os",
  "node:path",
  "node:process",
  "node:test",
  "node:url",
  "node:vm",
]);

const WEB_SOURCE_BARE_PACKAGE_IMPORTS = Object.freeze([
  "@fontsource-variable/jetbrains-mono",
  "@fontsource-variable/manrope",
  "@walletconnect/ethereum-provider",
  "lucide-solid",
  "solid-js",
  "solid-js/web",
  "viem",
  "viem/accounts",
  "viem/chains",
  "vitest",
]);

// This file is imported by a build-time test but lives outside web/scripts.
// Keeping the target explicit lets relative imports be checked against a
// complete enumerated set rather than accepting every path below web/.
const WEB_STATIC_MODULE_PATHS = Object.freeze([
  "web/functions/_middleware.js",
]);

const RESOURCE_DEFINITIONS = Object.freeze([
  Object.freeze({ kind: "sandbox_config", path: ".gitignore", maximumBytes: 64 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "ARCHITECTURE.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "PROJECT.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "README.md", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "asset_provenance_input", path: "outputs/wikigen-pitch-assets/attested-network.png", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "asset_provenance_input", path: "outputs/wikigen-pitch-assets/private-reward-oracle.png", maximumBytes: 4 * 1024 * 1024 }),
  Object.freeze({ kind: "verification_input", path: "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq", maximumBytes: 1024 * 1024 }),
]);

const RESOURCE_CONSUMER_BINDINGS = Object.freeze([
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "ARCHITECTURE.md",
    specifier: "../../ARCHITECTURE.md?raw",
  }),
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "PROJECT.md",
    specifier: "../../PROJECT.md?raw",
  }),
  Object.freeze({
    consumer: "web/src/productTruth.test.ts",
    externalPath: "README.md",
    specifier: "../../README.md?raw",
  }),
  Object.freeze({
    consumer: "web/scripts/release-env-core.test.mjs",
    externalPath:
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    specifier:
      "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
  }),
  Object.freeze({
    consumer: "web/scripts/pitch-assets-provenance.test.mjs",
    externalPath: "outputs/wikigen-pitch-assets/attested-network.png",
    specifier: "../../outputs/wikigen-pitch-assets/attested-network.png",
  }),
  Object.freeze({
    consumer: "web/scripts/pitch-assets-provenance.test.mjs",
    externalPath: "outputs/wikigen-pitch-assets/private-reward-oracle.png",
    specifier: "../../outputs/wikigen-pitch-assets/private-reward-oracle.png",
  }),
]);

function compareCanonical(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an exact object`);
  }
  const keys = Object.keys(value).sort(compareCanonical);
  const wanted = [...expected].sort(compareCanonical);
  if (JSON.stringify(keys) !== JSON.stringify(wanted)) {
    throw new Error(`${label} has an unexpected shape`);
  }
  return value;
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function domainHash(domain, value) {
  return `sha256:${createHash("sha256")
    .update(domain, "utf8")
    .update("\0", "ascii")
    .update(canonicalText(value), "utf8")
    .digest("hex")}`;
}

function safeMode(mode) {
  return Number.isSafeInteger(mode)
    && mode >= 0
    && mode <= 0o777
    && (mode & 0o400) !== 0
    && (mode & 0o133) === 0;
}

function entrypointDefinitions() {
  return [
    ...RESOURCE_DEFINITIONS.map(({ kind, path: filePath }) => ({
      kind,
      path: filePath,
    })),
    ...MODULE_ENTRYPOINT_PATHS.map((filePath) => ({
      kind: "module",
      path: filePath,
    })),
  ]
    .sort((left, right) => compareCanonical(left.path, right.path))
    .map((entry) => Object.freeze(entry));
}

function fileDefinitions() {
  const resources = RESOURCE_DEFINITIONS.map((entry) => ({ ...entry }));
  const modules = MODULE_CLOSURE_PATHS.map((filePath) => ({
    kind: "module",
    path: filePath,
    maximumBytes: 4 * 1024 * 1024,
  }));
  return [...resources, ...modules]
    .sort((left, right) => compareCanonical(left.path, right.path))
    .map((entry) => Object.freeze(entry));
}

export const CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS = Object.freeze(
  entrypointDefinitions(),
);
export const CLOUDFLARE_EXTERNAL_BUILD_FILES = Object.freeze(
  fileDefinitions(),
);

function aggregatePayload({ entrypoints, files }) {
  return {
    schema: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints,
    files,
    raw_secret_egress: false,
  };
}

export function normalizeCloudflareExternalBuildClosure(value) {
  const parsed = exactKeys(value, [
    "aggregate_sha256",
    "entrypoints",
    "files",
    "raw_secret_egress",
    "schema",
    "truth_status",
  ], "Cloudflare external build closure");
  if (
    parsed.schema !== CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA
    || parsed.truth_status !== CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS
    || parsed.raw_secret_egress !== false
    || !Array.isArray(parsed.entrypoints)
    || !Array.isArray(parsed.files)
  ) {
    throw new Error("Cloudflare external build closure truth boundary is invalid");
  }

  const entrypoints = parsed.entrypoints.map((entry, index) => {
    const normalized = exactKeys(
      entry,
      ["kind", "path"],
      `Cloudflare external build entrypoint ${index}`,
    );
    const expected = CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS[index];
    if (
      !expected
      || normalized.kind !== expected.kind
      || normalized.path !== expected.path
    ) {
      throw new Error("Cloudflare external build entrypoints are not exact and ordered");
    }
    return Object.freeze({ kind: normalized.kind, path: normalized.path });
  });
  if (entrypoints.length !== CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.length) {
    throw new Error("Cloudflare external build entrypoints are incomplete");
  }

  const files = parsed.files.map((file, index) => {
    const normalized = exactKeys(
      file,
      ["kind", "mode", "path", "sha256", "size"],
      `Cloudflare external build file ${index}`,
    );
    const expected = CLOUDFLARE_EXTERNAL_BUILD_FILES[index];
    if (
      !expected
      || normalized.kind !== expected.kind
      || normalized.path !== expected.path
      || !safeMode(normalized.mode)
      || !Number.isSafeInteger(normalized.size)
      || normalized.size < 1
      || normalized.size > expected.maximumBytes
      || !SHA256.test(String(normalized.sha256 || ""))
    ) {
      throw new Error("Cloudflare external build files are unsafe or not exact and ordered");
    }
    return Object.freeze({
      kind: normalized.kind,
      path: normalized.path,
      mode: normalized.mode,
      size: normalized.size,
      sha256: normalized.sha256,
    });
  });
  if (files.length !== CLOUDFLARE_EXTERNAL_BUILD_FILES.length) {
    throw new Error("Cloudflare external build file closure is incomplete");
  }

  const payload = aggregatePayload({ entrypoints, files });
  const aggregateSha256 = domainHash(AGGREGATE_DOMAIN, payload);
  if (parsed.aggregate_sha256 !== aggregateSha256) {
    throw new Error("Cloudflare external build closure aggregate is invalid");
  }
  return Object.freeze({
    schema: payload.schema,
    truth_status: payload.truth_status,
    entrypoints: Object.freeze(entrypoints),
    files: Object.freeze(files),
    aggregate_sha256: aggregateSha256,
    raw_secret_egress: false,
  });
}

export function canonicalCloudflareExternalBuildClosureText(value) {
  return canonicalText(normalizeCloudflareExternalBuildClosure(value));
}

export function cloudflareExternalBuildClosureSha256(value) {
  return domainHash(
    RECEIPT_DOMAIN,
    normalizeCloudflareExternalBuildClosure(value),
  );
}

async function canonicalRepositoryRoot(repoRoot) {
  if (
    typeof repoRoot !== "string"
    || !path.isAbsolute(repoRoot)
    || path.resolve(repoRoot) !== repoRoot
    || path.normalize(repoRoot) !== repoRoot
  ) {
    throw new Error("Cloudflare external build closure root must be canonical and absolute");
  }
  const canonical = await realpath(repoRoot);
  if (canonical !== repoRoot) {
    throw new Error("Cloudflare external build closure root is aliased");
  }
  return canonical;
}

function repositoryPath(repoRoot, relative) {
  if (
    typeof relative !== "string"
    || !relative
    || relative.startsWith("/")
    || relative.includes("\\")
    || path.posix.normalize(relative) !== relative
    || relative === ".."
    || relative.startsWith("../")
  ) {
    throw new Error("Cloudflare external build path is not canonical and relative");
  }
  const absolute = path.join(repoRoot, ...relative.split("/"));
  if (!absolute.startsWith(`${repoRoot}${path.sep}`)) {
    throw new Error("Cloudflare external build path escapes the repository");
  }
  return absolute;
}

async function readStableRepositoryFile(
  repoRoot,
  relative,
  maximumBytes,
  label,
) {
  const absolute = repositoryPath(repoRoot, relative);
  let canonical;
  try {
    canonical = await realpath(absolute);
  } catch {
    throw new Error(`${label} is missing`);
  }
  if (canonical !== absolute) {
    throw new Error(`${label} path is symlinked or aliased`);
  }
  const named = await lstat(absolute, { bigint: true });
  const expectedUid = typeof process.geteuid === "function"
    ? BigInt(process.geteuid())
    : named.uid;
  const mode = Number(named.mode & 0o777n);
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1n
    || named.uid !== expectedUid
    || !safeMode(mode)
    || named.size < 1n
    || named.size > BigInt(maximumBytes)
  ) {
    throw new Error(`${label} is not a bounded owner-controlled single-link file`);
  }
  const handle = await open(
    absolute,
    constants.O_RDONLY | (constants.O_NOFOLLOW || 0),
  );
  try {
    const before = await handle.stat({ bigint: true });
    for (const field of ["dev", "ino", "size", "nlink", "uid", "gid", "mode"]) {
      if (before[field] !== named[field]) {
        throw new Error(`${label} changed while opening`);
      }
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    for (const field of [
      "dev", "ino", "size", "nlink", "uid", "gid", "mode", "mtimeNs", "ctimeNs",
    ]) {
      if (before[field] !== after[field]) {
        throw new Error(`${label} changed during its stable read`);
      }
    }
    if (BigInt(bytes.length) !== before.size) {
      throw new Error(`${label} changed size during its stable read`);
    }
    return Object.freeze({ absolute, bytes, mode, size: bytes.length });
  } finally {
    await handle.close();
  }
}

async function collectFiles(repoRoot, relativeDirectory, extensions) {
  const root = repositoryPath(repoRoot, relativeDirectory);
  const output = [];
  async function visit(directory) {
    const metadata = await lstat(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      throw new Error("Cloudflare external build consumer tree is not a real directory");
    }
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => compareCanonical(left.name, right.name));
    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error("Cloudflare external build consumer tree contains a symlink");
      }
      if (entry.isDirectory()) {
        await visit(absolute);
      } else if (entry.isFile() && extensions.has(path.extname(entry.name))) {
        output.push(path.relative(repoRoot, absolute).split(path.sep).join("/"));
      }
    }
  }
  await visit(root);
  return output.sort(compareCanonical);
}

const MODULE_PARSER_SOURCE = String.raw`
import fs from "node:fs";
import acorn from "internal/deps/acorn/acorn/dist/acorn";
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const output = input.map((entry) => {
  const source = Buffer.from(entry.base64, "base64").toString("utf8");
  const ast = acorn.parse(source, {
    allowHashBang: true,
    ecmaVersion: "latest",
    sourceType: "module",
  });
  const requests = [];
  const runtimeRequests = [];
  function memberName(node) {
    if (!node || (node.type !== "MemberExpression"
      && node.type !== "OptionalMemberExpression")) return null;
    if (!node.computed && node.property?.type === "Identifier") {
      return node.property.name;
    }
    if (node.computed && node.property?.type === "Literal"
      && typeof node.property.value === "string") {
      return node.property.value;
    }
    return null;
  }
  function visit(node) {
    if (!node || typeof node !== "object") return;
    if (
      node.type === "ImportDeclaration"
      || node.type === "ExportAllDeclaration"
      || (node.type === "ExportNamedDeclaration" && node.source)
    ) {
      const attributes = [
        ...(Array.isArray(node.attributes) ? node.attributes : []),
        ...(Array.isArray(node.assertions) ? node.assertions : []),
      ];
      requests.push({
        specifier: node.source?.value,
        attributes: attributes.length ? { unsupported: true } : {},
        phase: "evaluation",
      });
      if (new Set([
        "module",
        "node:module",
        "node:worker_threads",
        "worker_threads",
      ])
        .has(node.source?.value)) {
        runtimeRequests.push({
          kind: "commonjs_require",
          literal: true,
          specifier: node.source.value,
        });
      }
    } else if (node.type === "ImportExpression") {
      runtimeRequests.push({
        kind: "dynamic_import",
        literal: node.source?.type === "Literal"
          && typeof node.source.value === "string",
        specifier: node.source?.type === "Literal"
          && typeof node.source.value === "string"
          ? node.source.value
          : null,
      });
    } else if (
      node.type === "CallExpression"
      && (
        (
          node.callee?.type === "Identifier"
          && new Set([
            "AsyncFunction",
            "AsyncGeneratorFunction",
            "Function",
            "GeneratorFunction",
            "SharedWorker",
            "Worker",
            "createRequire",
            "eval",
            "require",
          ])
            .has(node.callee.name)
        )
        || (
          (node.callee?.type === "MemberExpression"
            || node.callee?.type === "OptionalMemberExpression")
          && new Set([
            "AsyncFunction",
            "AsyncGeneratorFunction",
            "Function",
            "GeneratorFunction",
            "SharedWorker",
            "SourceTextModule",
            "Worker",
            "compileFunction",
            "construct",
            "constructor",
            "createRequire",
            "eval",
            "getBuiltinModule",
            "require",
          ])
            .has(memberName(node.callee))
        )
      )
    ) {
      const argument = node.arguments?.length === 1 ? node.arguments[0] : null;
      runtimeRequests.push({
        kind: "commonjs_require",
        literal: argument?.type === "Literal"
          && typeof argument.value === "string",
        specifier: argument?.type === "Literal"
          && typeof argument.value === "string"
          ? argument.value
          : null,
      });
    } else if (
      node.type === "NewExpression"
      && (
        (
          node.callee?.type === "Identifier"
          && new Set([
            "AsyncFunction",
            "AsyncGeneratorFunction",
            "Function",
            "GeneratorFunction",
            "SharedWorker",
            "SourceTextModule",
            "Worker",
          ]).has(node.callee.name)
        )
        || (
          (node.callee?.type === "MemberExpression"
            || node.callee?.type === "OptionalMemberExpression")
          && new Set([
            "AsyncFunction",
            "AsyncGeneratorFunction",
            "Function",
            "GeneratorFunction",
            "SharedWorker",
            "SourceTextModule",
            "Worker",
            "constructor",
          ]).has(memberName(node.callee))
        )
      )
    ) {
      const argument = node.arguments?.length === 1 ? node.arguments[0] : null;
      runtimeRequests.push({
        kind: "commonjs_require",
        literal: argument?.type === "Literal"
          && typeof argument.value === "string",
        specifier: argument?.type === "Literal"
          && typeof argument.value === "string"
          ? argument.value
          : null,
      });
    } else if (
      (node.type === "MemberExpression"
        || node.type === "OptionalMemberExpression")
      && new Set([
        "AsyncFunction",
        "AsyncGeneratorFunction",
        "Function",
        "GeneratorFunction",
        "SharedWorker",
        "SourceTextModule",
        "Worker",
        "compileFunction",
        "construct",
        "constructor",
        "createRequire",
        "eval",
        "getBuiltinModule",
        "require",
      ]).has(memberName(node))
    ) {
      runtimeRequests.push({
        kind: "commonjs_require",
        literal: false,
        specifier: null,
      });
    } else if (
      node.type === "Identifier"
      && new Set([
        "AsyncFunction",
        "AsyncGeneratorFunction",
        "Function",
        "GeneratorFunction",
        "SharedWorker",
        "Worker",
        "eval",
        "require",
      ]).has(node.name)
    ) {
      runtimeRequests.push({
        kind: "commonjs_require",
        literal: false,
        specifier: null,
      });
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === "start" || key === "end" || key === "loc") continue;
      if (Array.isArray(value)) {
        for (const child of value) visit(child);
      } else if (value && typeof value === "object") {
        visit(value);
      }
    }
  }
  visit(ast);
  return {
    path: entry.path,
    requests,
    runtime_requests: runtimeRequests,
  };
});
process.stdout.write(JSON.stringify(output));
`;

function parseStaticModuleRequests(modules) {
  for (const module of modules) {
    const source = module.bytes.toString("utf8");
    if (!Buffer.from(source, "utf8").equals(module.bytes)) {
      throw new Error("Cloudflare external module source is not canonical UTF-8");
    }
  }
  const input = modules.map((module) => ({
    path: module.path,
    base64: module.bytes.toString("base64"),
  }));
  const parsed = spawnSync(
    process.execPath,
    [
      "--no-warnings",
      "--expose-internals",
      "--input-type=module",
      "-e",
      MODULE_PARSER_SOURCE,
    ],
    {
      input: JSON.stringify(input),
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
        LANG: "C",
        LC_ALL: "C",
        NODE_NO_WARNINGS: "1",
      },
      stdio: ["pipe", "pipe", "pipe"],
      maxBuffer: 16 * 1024 * 1024,
      timeout: 15_000,
    },
  );
  if (parsed.error || parsed.status !== 0 || parsed.signal || parsed.stderr) {
    throw new Error("Cloudflare external module closure could not be parsed safely");
  }
  let value;
  try {
    value = JSON.parse(parsed.stdout);
  } catch {
    throw new Error("Cloudflare external module parser returned invalid output");
  }
  if (!Array.isArray(value) || value.length !== modules.length) {
    throw new Error("Cloudflare external module parser returned an incomplete graph");
  }
  const result = new Map();
  for (let index = 0; index < value.length; index += 1) {
    const entry = exactKeys(
      value[index],
      ["path", "requests", "runtime_requests"],
      "Cloudflare parsed module",
    );
    if (
      entry.path !== modules[index].path
      || result.has(entry.path)
      || !Array.isArray(entry.requests)
      || !Array.isArray(entry.runtime_requests)
    ) {
      throw new Error("Cloudflare external module parser reordered or duplicated the graph");
    }
    const requests = entry.requests.map((request) => {
      const normalized = exactKeys(
        request,
        ["attributes", "phase", "specifier"],
        "Cloudflare parsed module request",
      );
      if (
        typeof normalized.specifier !== "string"
        || normalized.phase !== "evaluation"
        || !normalized.attributes
        || typeof normalized.attributes !== "object"
        || Array.isArray(normalized.attributes)
        || Object.keys(normalized.attributes).length !== 0
      ) {
        throw new Error("Cloudflare external module request is nonliteral or attributed");
      }
      return normalized.specifier;
    });
    for (const request of entry.runtime_requests) {
      const normalized = exactKeys(
        request,
        ["kind", "literal", "specifier"],
        "Cloudflare parsed runtime module request",
      );
      if (
        !new Set(["dynamic_import", "commonjs_require"]).has(normalized.kind)
        || typeof normalized.literal !== "boolean"
        || (
          normalized.literal
          && typeof normalized.specifier !== "string"
        )
        || (!normalized.literal && normalized.specifier !== null)
      ) {
        throw new Error("Cloudflare runtime module parser returned an invalid request");
      }
    }
    if (entry.runtime_requests.length) {
      throw new Error(
        "Cloudflare external module closure refuses dynamic import or CommonJS require in any consumer",
      );
    }
    result.set(entry.path, requests);
  }
  return result;
}

const STATIC_SPECIFIER_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:/;

function classifyStaticModuleSpecifier(specifier, {
  allowedBarePackages,
  allowedNodeBuiltins,
  label,
  allowRelativeSuffix = false,
}) {
  if (
    typeof specifier !== "string"
    || specifier.length < 1
    || specifier.includes("\0")
    || specifier.includes("\\")
  ) {
    throw new Error(`${label} contains an invalid static module specifier`);
  }
  if (specifier.startsWith(".")) {
    if (
      !allowRelativeSuffix
      && (specifier.includes("?") || specifier.includes("#"))
    ) {
      throw new Error(`${label} contains a suffixed relative module specifier`);
    }
    return "relative";
  }
  if (specifier.startsWith("/") || specifier.startsWith("//")) {
    throw new Error(`${label} contains an absolute static module specifier`);
  }
  if (STATIC_SPECIFIER_SCHEME.test(specifier)) {
    if (
      specifier.startsWith("node:")
      && allowedNodeBuiltins.has(specifier)
    ) {
      return "node";
    }
    throw new Error(`${label} contains an unsupported or unaudited URI module specifier`);
  }
  if (allowedBarePackages.has(specifier)) return "bare";
  throw new Error(`${label} contains an unaudited bare package import`);
}

function resolveRelativeModule(importer, specifier) {
  if (
    specifier.includes("\\")
    || specifier.includes("?")
    || specifier.includes("#")
  ) {
    throw new Error("Cloudflare external module request is not a canonical file specifier");
  }
  const resolved = path.posix.normalize(path.posix.join(
    path.posix.dirname(importer),
    specifier,
  ));
  if (
    resolved === ".."
    || resolved.startsWith("../")
    || !resolved.endsWith(".mjs")
  ) {
    throw new Error("Cloudflare external module request escapes or is not an exact module");
  }
  return resolved;
}

function assertExactExternalModuleGraph(moduleRequests) {
  const graphPaths = [
    ...MODULE_CLOSURE_PATHS,
    ...MODULE_WEB_BACKEDGE_PATHS,
  ];
  const allowed = new Set(graphPaths);
  const allowedBarePackages = new Set(MODULE_BARE_PACKAGE_IMPORTS);
  const allowedNodeBuiltins = new Set(MODULE_NODE_BUILTIN_IMPORTS);
  const discoveredBarePackages = new Set();
  const graph = new Map();
  for (const modulePath of graphPaths) {
    const requests = moduleRequests.get(modulePath);
    if (!requests) {
      throw new Error("Cloudflare external module graph is missing a closure file");
    }
    const edges = [];
    for (const specifier of requests) {
      const kind = classifyStaticModuleSpecifier(specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: "Cloudflare external module graph",
      });
      if (kind === "node") continue;
      if (kind === "bare") {
        discoveredBarePackages.add(specifier);
        continue;
      }
      const resolved = resolveRelativeModule(modulePath, specifier);
      if (!allowed.has(resolved)) {
        throw new Error("Cloudflare external module graph contains an undeclared import or web back-edge");
      }
      edges.push(resolved);
    }
    graph.set(modulePath, [...new Set(edges)].sort(compareCanonical));
  }

  const reached = new Set();
  const visiting = new Set();
  function visit(modulePath) {
    if (visiting.has(modulePath)) {
      throw new Error("Cloudflare external module graph contains a cycle");
    }
    if (reached.has(modulePath)) return;
    visiting.add(modulePath);
    for (const dependency of graph.get(modulePath) || []) visit(dependency);
    visiting.delete(modulePath);
    reached.add(modulePath);
  }
  for (const entrypoint of MODULE_ENTRYPOINT_PATHS) visit(entrypoint);
  if (
    reached.size !== graphPaths.length
    || graphPaths.some((modulePath) => !reached.has(modulePath))
  ) {
    throw new Error("Cloudflare external module allowlist contains an unreachable extra");
  }
  if (
    discoveredBarePackages.size !== allowedBarePackages.size
    || [...allowedBarePackages].some(
      (specifier) => !discoveredBarePackages.has(specifier),
    )
  ) {
    throw new Error("Cloudflare external package allowlist contains an unreachable extra");
  }
}

function resolveConsumerSpecifier(consumer, specifier) {
  const withoutQuery = specifier.split(/[?#]/, 1)[0];
  return path.posix.normalize(path.posix.join(
    path.posix.dirname(consumer),
    withoutQuery,
  ));
}

function assertExactWebScriptEntrypoints(moduleRequests, webModulePaths) {
  const discovered = new Set();
  const expected = new Set(MODULE_ENTRYPOINT_PATHS);
  const allowedWebModules = new Set(webModulePaths);
  const allowedBarePackages = new Set(WEB_MODULE_BARE_PACKAGE_IMPORTS);
  const allowedNodeBuiltins = new Set(WEB_MODULE_NODE_BUILTIN_IMPORTS);
  for (const consumer of webModulePaths) {
    const requests = moduleRequests.get(consumer) || [];
    for (const specifier of requests) {
      const kind = classifyStaticModuleSpecifier(specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: "Cloudflare web module",
      });
      if (kind !== "relative") continue;
      const resolved = resolveConsumerSpecifier(consumer, specifier);
      if (resolved.startsWith("web/")) {
        if (!allowedWebModules.has(resolved)) {
          throw new Error("Cloudflare web module contains a relative import outside the enumerated module set");
        }
        continue;
      }
      if (!expected.has(resolved)) {
        throw new Error("Cloudflare web script contains an undeclared external import");
      }
      discovered.add(resolved);
    }
  }
  if (
    discovered.size !== expected.size
    || [...expected].some((modulePath) => !discovered.has(modulePath))
  ) {
    throw new Error("Cloudflare external module entrypoints do not match web consumers");
  }
}

function quotedSpecifierCount(source, specifier) {
  return source.split(`"${specifier}"`).length - 1
    + source.split(`'${specifier}'`).length - 1;
}

function typescriptModuleSpecifiers(source) {
  const specifiers = [];
  for (const pattern of [
    /\bfrom\s*(["'])([^"'\r\n]+)\1/g,
    /(?:^|\n)\s*import\s*(["'])([^"'\r\n]+)\1\s*;?/g,
    /\bimport\s*\(\s*(["'])([^"'\r\n]+)\1\s*\)/g,
  ]) {
    for (const match of source.matchAll(pattern)) specifiers.push(match[2]);
  }
  return specifiers;
}

async function assertExactResourceConsumers(repoRoot, sourceConsumers) {
  const sourceByPath = new Map(sourceConsumers.map((entry) => [
    entry.path,
    entry.bytes.toString("utf8"),
  ]));
  for (const binding of RESOURCE_CONSUMER_BINDINGS) {
    let source = sourceByPath.get(binding.consumer);
    if (source === undefined) {
      const file = await readStableRepositoryFile(
        repoRoot,
        binding.consumer,
        MAX_WEB_CONSUMER_BYTES,
        "Cloudflare external resource consumer",
      );
      source = file.bytes.toString("utf8");
      sourceByPath.set(binding.consumer, source);
    }
    if (
      quotedSpecifierCount(source, binding.specifier) !== 1
      || resolveConsumerSpecifier(binding.consumer, binding.specifier)
        !== binding.externalPath
    ) {
      throw new Error("Cloudflare external resource binding is missing, duplicated, or redirected");
    }
  }

  const permitted = new Set(
    CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.map((entry) => entry.path),
  );
  const allowedBarePackages = new Set(WEB_SOURCE_BARE_PACKAGE_IMPORTS);
  const allowedNodeBuiltins = new Set();
  for (const [consumer, source] of sourceByPath) {
    if (!new Set([".ts", ".tsx"]).has(path.posix.extname(consumer))) continue;
    for (const specifier of typescriptModuleSpecifiers(source)) {
      const kind = classifyStaticModuleSpecifier(specifier, {
        allowedBarePackages,
        allowedNodeBuiltins,
        label: "Cloudflare web source",
        allowRelativeSuffix: true,
      });
      if (kind !== "relative") continue;
      const resolved = resolveConsumerSpecifier(consumer, specifier);
      if (!resolved.startsWith("web/") && !permitted.has(resolved)) {
        throw new Error("Cloudflare web source contains an undeclared external resource import");
      }
    }
  }
}

export async function projectCloudflareExternalBuildClosure(repoRoot) {
  const canonicalRoot = await canonicalRepositoryRoot(repoRoot);
  const projectedFiles = [];
  const sourceFiles = new Map();
  let totalBytes = 0;
  for (const definition of CLOUDFLARE_EXTERNAL_BUILD_FILES) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      definition.path,
      definition.maximumBytes,
      "Cloudflare external build input",
    );
    totalBytes += file.size;
    if (totalBytes > MAX_TOTAL_BYTES) {
      throw new Error("Cloudflare external build closure exceeds its bounded total size");
    }
    sourceFiles.set(definition.path, file);
    projectedFiles.push(Object.freeze({
      kind: definition.kind,
      path: definition.path,
      mode: file.mode,
      size: file.size,
      sha256: `sha256:${createHash("sha256").update(file.bytes).digest("hex")}`,
    }));
  }

  const webScriptPaths = await collectFiles(
    canonicalRoot,
    "web/scripts",
    new Set([".mjs"]),
  );
  const webScriptFiles = [];
  for (const consumerPath of webScriptPaths) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      consumerPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare web script consumer",
    );
    webScriptFiles.push({ path: consumerPath, bytes: file.bytes });
  }
  const webStaticModuleFiles = [];
  for (const modulePath of WEB_STATIC_MODULE_PATHS) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      modulePath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare enumerated web module",
    );
    webStaticModuleFiles.push({ path: modulePath, bytes: file.bytes });
  }
  const webModuleFiles = [...webScriptFiles, ...webStaticModuleFiles]
    .sort((left, right) => compareCanonical(left.path, right.path));
  const webModulePaths = webModuleFiles.map((entry) => entry.path);
  const parsedRequests = parseStaticModuleRequests([
    ...MODULE_CLOSURE_PATHS.map((modulePath) => ({
      path: modulePath,
      bytes: sourceFiles.get(modulePath).bytes,
    })),
    ...webModuleFiles,
  ]);
  assertExactExternalModuleGraph(parsedRequests);
  assertExactWebScriptEntrypoints(parsedRequests, webModulePaths);

  const webSourcePaths = await collectFiles(
    canonicalRoot,
    "web/src",
    new Set([".ts", ".tsx"]),
  );
  const webSourceConsumers = [];
  for (const consumerPath of webSourcePaths) {
    const file = await readStableRepositoryFile(
      canonicalRoot,
      consumerPath,
      MAX_WEB_CONSUMER_BYTES,
      "Cloudflare web source consumer",
    );
    webSourceConsumers.push({ path: consumerPath, bytes: file.bytes });
  }
  await assertExactResourceConsumers(
    canonicalRoot,
    [...webScriptFiles, ...webSourceConsumers],
  );

  const entrypoints = CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.map((entry) => ({
    kind: entry.kind,
    path: entry.path,
  }));
  const payload = aggregatePayload({ entrypoints, files: projectedFiles });
  return normalizeCloudflareExternalBuildClosure({
    schema: payload.schema,
    truth_status: payload.truth_status,
    entrypoints,
    files: projectedFiles,
    aggregate_sha256: domainHash(AGGREGATE_DOMAIN, payload),
    raw_secret_egress: false,
  });
}

export const __test = Object.freeze({
  AGGREGATE_DOMAIN,
  MODULE_BARE_PACKAGE_IMPORTS,
  MODULE_CLOSURE_PATHS,
  MODULE_ENTRYPOINT_PATHS,
  MODULE_NODE_BUILTIN_IMPORTS,
  MODULE_WEB_BACKEDGE_PATHS,
  RECEIPT_DOMAIN,
  RESOURCE_CONSUMER_BINDINGS,
  RESOURCE_DEFINITIONS,
  WEB_MODULE_BARE_PACKAGE_IMPORTS,
  WEB_MODULE_NODE_BUILTIN_IMPORTS,
  WEB_SOURCE_BARE_PACKAGE_IMPORTS,
  WEB_STATIC_MODULE_PATHS,
  parseStaticModuleRequests,
});
