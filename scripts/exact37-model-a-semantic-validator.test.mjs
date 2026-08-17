import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  EXACT35_MODEL_A_INPUT_FLAGS,
  EXACT37_MODEL_A_INPUT_FLAGS,
  normalizeExact35ModelAPrebuildInputSet,
  normalizeExact37ModelAInputSet,
  normalizeExactModelAFinalReleaseAuthorityCore,
  validateExact37ModelAHistoricalAuthority,
} from "./exact37-model-a-semantic-validator.mjs";
import {
  FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
} from "./execution-policy-release-core-v3-historical.mjs";
import {
  knownVector,
} from "./execution-policy-release-core-v3-historical.fixture.mjs";

function keyForFlag(flag) {
  return flag.slice(2).replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
}

function staticImportClosure(entrypoint) {
  const sources = new Map();
  const visiting = new Set();
  const externalImports = new Set();
  function visit(file) {
    if (visiting.has(file)) {
      throw new Error(`exact-37 static import closure contains a cycle at ${file}`);
    }
    if (sources.has(file)) return;
    visiting.add(file);
    const source = readFileSync(file, "utf8");
    sources.set(file, source);
    const specifiers = [
      ...source.matchAll(
        /^\s*import(?:[^;]*?\sfrom\s*)?\s*["']([^"']+)["'];/gm,
      ),
      ...source.matchAll(
        /^\s*export\s+(?:\*|\{[^;]*\})\s+from\s+["']([^"']+)["'];/gm,
      ),
    ].map((match) => match[1]);
    for (const specifier of specifiers) {
      if (!specifier.startsWith(".")) {
        externalImports.add(specifier);
        continue;
      }
      visit(path.resolve(path.dirname(file), specifier));
    }
    visiting.delete(file);
  }
  visit(entrypoint);
  return { sources, externalImports };
}

function stableInputSet({ hostileBytesAccessor = false } = {}) {
  let bytesAccessorTouched = false;
  const pathEntries = [];
  const entries = EXACT37_MODEL_A_INPUT_FLAGS.map((flag, index) => {
    const key = keyForFlag(flag);
    const filePath = `/tmp/exact37-${index}.json`;
    const value = { artifact_index: index + 1 };
    const text = `${JSON.stringify(value, null, 2)}\n`;
    const entry = {
      flag,
      key,
      filePath,
      text,
      byteLength: Buffer.byteLength(text),
      value,
      metadata: { dev: 1, ino: index + 1 },
      rawSha256: `sha256:${createHash("sha256").update(text).digest("hex")}`,
    };
    Object.defineProperty(entry, "bytes", {
      enumerable: true,
      get() {
        bytesAccessorTouched = true;
        if (hostileBytesAccessor) throw new Error("bytes accessor executed");
        return Buffer.from(text, "utf8");
      },
    });
    pathEntries.push({ flag, key, filePath });
    return entry;
  });
  const artifactPaths = {
    entries: pathEntries,
    byFlag: Object.fromEntries(pathEntries.map((entry) => [entry.flag, entry.filePath])),
    byKey: Object.fromEntries(pathEntries.map((entry) => [entry.key, entry.filePath])),
  };
  return {
    value: {
      artifactPaths,
      entries,
      byFlag: Object.fromEntries(entries.map((entry) => [entry.flag, entry])),
      byKey: Object.fromEntries(entries.map((entry) => [entry.key, entry])),
      totalBytes: entries.reduce((sum, entry) => sum + entry.byteLength, 0),
    },
    wasBytesAccessorTouched: () => bytesAccessorTouched,
  };
}

test("the exact-37 API validates its explicit clock before consuming caller data", async () => {
  let touched = false;
  const hostile = Object.defineProperty({}, "entries", {
    enumerable: true,
    get() {
      touched = true;
      throw new Error("untrusted getter was evaluated");
    },
  });
  await assert.rejects(
    validateExact37ModelAHistoricalAuthority({ inputs: hostile }),
    /explicit bounded whole-second validationTimeMs/,
  );
  assert.equal(touched, false);
});

test("the exact-35 prebuild recipe is the exact acyclic projection", () => {
  assert.equal(EXACT35_MODEL_A_INPUT_FLAGS.length, 35);
  assert.deepEqual(
    EXACT35_MODEL_A_INPUT_FLAGS,
    EXACT37_MODEL_A_INPUT_FLAGS.filter((flag) => ![
      "--live-activation-authority",
      "--frontend-build-candidate-receipt",
    ].includes(flag)),
  );
  const full = stableInputSet();
  const retained = full.value.entries.filter(({ flag }) => (
    EXACT35_MODEL_A_INPUT_FLAGS.includes(flag)
  ));
  const paths = retained.map(({ flag, key, filePath }) => ({ flag, key, filePath }));
  const prebuild = {
    artifactPaths: {
      entries: paths,
      byFlag: Object.fromEntries(paths.map((entry) => [entry.flag, entry.filePath])),
      byKey: Object.fromEntries(paths.map((entry) => [entry.key, entry.filePath])),
    },
    entries: retained,
    byFlag: Object.fromEntries(retained.map((entry) => [entry.flag, entry])),
    byKey: Object.fromEntries(retained.map((entry) => [entry.key, entry])),
    totalBytes: retained.reduce((sum, entry) => sum + entry.byteLength, 0),
  };
  assert.equal(normalizeExact35ModelAPrebuildInputSet(prebuild).entries.length, 35);
});

test("exact-35 and exact-37 share an explicit frozen-v3 or historical-v2 core boundary", () => {
  const current = knownVector();
  assert.equal(
    normalizeExactModelAFinalReleaseAuthorityCore(current).schema,
    FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
  );

  const historical = structuredClone(current);
  historical.schema = FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA;
  historical.contracts.diligence_room.developer =
    historical.operator_address;
  delete historical.requested_features.tinker_customer;
  delete historical.requested_features.collaboration;
  assert.throws(
    () => normalizeExactModelAFinalReleaseAuthorityCore(historical),
    /schema/,
  );
  const replayed = normalizeExactModelAFinalReleaseAuthorityCore(historical, {
    expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
  });
  assert.equal(replayed.schema, FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA);
  assert.equal(
    Object.hasOwn(replayed.requested_features, "tinker_customer"),
    false,
  );

  const ambiguous = structuredClone(historical);
  ambiguous.requested_features.tinker_customer = false;
  assert.throws(
    () => normalizeExactModelAFinalReleaseAuthorityCore(ambiguous, {
      expectedCoreSchema: FINAL_RELEASE_AUTHORITY_CORE_V2_SCHEMA,
    }),
    /requested_features/,
  );
  const unknown = structuredClone(current);
  unknown.schema = "dnai.final-release-authority-core.v4";
  assert.throws(
    () => normalizeExactModelAFinalReleaseAuthorityCore(unknown),
    /schema/,
  );
});

test("the exact-37 loader snapshots canonical text without executing bytes accessors", () => {
  const fixture = stableInputSet({ hostileBytesAccessor: true });
  const normalized = normalizeExact37ModelAInputSet(fixture.value);
  assert.equal(fixture.wasBytesAccessorTouched(), false);
  assert.equal(normalized.entries.length, EXACT37_MODEL_A_INPUT_FLAGS.length);
  assert.deepEqual(normalized.entries[0].value, { artifact_index: 1 });
  assert.equal(Object.isFrozen(normalized.entries[0].value), true);
  assert.equal(Object.hasOwn(normalized.entries[0], "bytes"), false);
});

test("the exact-37 loader rejects carried-value accessors and custom prototypes", () => {
  const accessor = stableInputSet();
  Object.defineProperty(accessor.value.entries[0].value, "artifact_index", {
    enumerable: true,
    get: () => 1,
  });
  assert.throws(
    () => normalizeExact37ModelAInputSet(accessor.value),
    /accessors and non-enumerable data fields are forbidden/,
  );
  assert.equal(accessor.wasBytesAccessorTouched(), false);

  const custom = stableInputSet();
  Object.setPrototypeOf(custom.value.byKey, { untrusted: true });
  assert.throws(
    () => normalizeExact37ModelAInputSet(custom.value),
    /by-key projection must contain exactly the frozen fields/,
  );
  assert.equal(custom.wasBytesAccessorTouched(), false);
});

test("the exact-37 validator has an explicit recorded-time DCAP replay closure", () => {
  const entrypoint = fileURLToPath(
    new URL("./exact37-model-a-semantic-validator.mjs", import.meta.url),
  );
  const { sources, externalImports } = staticImportClosure(entrypoint);
  const entrypointSource = sources.get(entrypoint);
  const basenames = new Set([...sources.keys()].map((file) => path.basename(file)));
  assert.equal(sources.size, 53, "dual current/historical DCAP closure file count drifted");
  assert.match(
    entrypointSource,
    /TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256[\s\S]*?main\.machine_evidence_sha256/,
    "exact-37 must cross-bind signed R's main-runtime evidence commitment",
  );
  assert.match(
    entrypointSource,
    /reconstructPersistedHistoricalPhalaSevenCvmReleaseVerificationAuthority/,
    "exact-37 must authenticate signed A, L, R, and B before replay",
  );
  assert.match(
    entrypointSource,
    /replayPersistedHistoricalPhalaSevenCvmEvidence/,
    "exact-37 must rerun recorded-time DCAP from the private transcript",
  );

  for (const required of [
    "canonical-public-https-url-core.mjs",
    "release-reviewer-authority-core.mjs",
    "phala-nonlive-bootstrap-authorization-core.mjs",
    "phala-seven-cvm-launch-completion-core.mjs",
    "pre-ceremony-runtime-authority-core.mjs",
    "phala-seven-cvm-historical-release-verification-authority.mjs",
    "phala-seven-cvm-verifier-evidence.mjs",
    "phala-seven-cvm-opened-fd-runtime-core.mjs",
    "release-manifest-descriptor-historical-core.mjs",
    "cvm-descriptor-runtime-authority-v1-policy.mjs",
    "cvm-release-descriptor-set-v3.mjs",
    "release-authority-historical-core.mjs",
    "compute-workload-activation-observation-core.mjs",
    "frontend-release-historical-core.mjs",
    "external-five-historical-evidence-core.mjs",
    "exact-model-a-dependency-graph.mjs",
  ]) {
    assert.equal(basenames.has(required), true, `historical closure omits ${required}`);
  }
  for (const forbidden of [
    "phala-seven-cvm-launch-completion.mjs",
    "pre-ceremony-runtime-authority.mjs",
    "compute-workload-activation-observation.mjs",
    "release-ceremony-authorization.mjs",
    "release-authority-stages.mjs",
    "frontend-build-candidate-core.mjs",
    "release-env-core.mjs",
    "execution-policy-release-core-binding.mjs",
  ]) {
    assert.equal(basenames.has(forbidden), false, `closure reaches ${forbidden}`);
  }

  assert.deepEqual(
    [...externalImports].sort(),
    [
      "@noble/curves/secp256k1",
      "@noble/hashes/sha3",
      "@noble/hashes/utils",
      "node:child_process",
      "node:crypto",
      "node:fs",
      "node:fs/promises",
      "node:os",
      "node:path",
      "node:url",
      "node:util",
    ],
  );
  for (const [file, source] of sources) {
    for (const forbidden of [
      /\bfetch\s*\(/,
      /\bWebSocket\b/,
      /\bXMLHttpRequest\b/,
      /["']node:(?:net|http|https)["']/,
    ]) {
      assert.equal(forbidden.test(source), false,
        `${path.basename(file)} contains network authority ${forbidden}`);
    }
  }
  const historicalAuthoritySource = sources.get(fileURLToPath(
    new URL(
      "./phala-seven-cvm-historical-release-verification-authority.mjs",
      import.meta.url,
    ),
  ));
  for (const source of [entrypointSource, historicalAuthoritySource]) {
    assert.doesNotMatch(source, /\bDate\.now\s*\(/);
    assert.doesNotMatch(source, /\bfetch\s*\(/);
    assert.doesNotMatch(source, /\brandomBytes\s*\(/);
  }
});
