import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  EXACT37_MODEL_A_INPUT_FLAGS,
  EXACT37_MODEL_A_INCOMPLETE_REASON,
  normalizeExact37ModelAInputSet,
  validateExact37ModelAHistoricalAuthority,
} from "./exact37-model-a-semantic-validator.mjs";

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

test("the incomplete exact-37 standalone API fails before consuming caller data", async () => {
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
    (error) => error instanceof TypeError
      && error.message === EXACT37_MODEL_A_INCOMPLETE_REASON,
  );
  assert.equal(touched, false);
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

test("the sealed exact-37 validator has a static historical-replay-only closure", () => {
  const entrypoint = fileURLToPath(
    new URL("./exact37-model-a-semantic-validator.mjs", import.meta.url),
  );
  const { sources, externalImports } = staticImportClosure(entrypoint);
  const entrypointSource = sources.get(entrypoint);
  const basenames = new Set([...sources.keys()].map((file) => path.basename(file)));
  assert.equal(sources.size, 31, "historical closure file count drifted");
  assert.match(
    entrypointSource,
    /TINKER_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256[\s\S]*?main\.machine_evidence_sha256/,
    "exact-37 must cross-bind signed R's main-runtime evidence commitment",
  );

  for (const required of [
    "release-reviewer-authority-core.mjs",
    "phala-nonlive-bootstrap-authorization-core.mjs",
    "phala-seven-cvm-launch-completion-core.mjs",
    "pre-ceremony-runtime-authority-core.mjs",
    "phala-seven-cvm-historical-evidence-core.mjs",
    "release-manifest-descriptor-historical-core.mjs",
    "release-authority-historical-core.mjs",
    "compute-workload-activation-observation-core.mjs",
    "frontend-release-historical-core.mjs",
    "external-five-historical-evidence-core.mjs",
    "exact-model-a-dependency-graph.mjs",
  ]) {
    assert.equal(basenames.has(required), true, `historical closure omits ${required}`);
  }
  for (const forbidden of [
    "release-authority-signature-verifier.mjs",
    "release-authority-current-reviewer-facade.mjs",
    "release-reviewer-authority-genesis.mjs",
    "release-reviewer-authority-genesis-acceptance.mjs",
    "phala-nonlive-bootstrap-authorization.mjs",
    "phala-seven-cvm-launch-completion.mjs",
    "pre-ceremony-runtime-authority.mjs",
    "compute-workload-activation-observation.mjs",
    "phala-seven-cvm-verifier-evidence.mjs",
    "phala-seven-cvm-historical-release-verification-authority.mjs",
    "release-manifest-sigstore-verifier.mjs",
    "cvm-release-descriptor-set.mjs",
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
      "node:crypto",
      "node:util",
    ],
  );
  for (const [file, source] of sources) {
    for (const forbidden of [
      /\bDate\.now\s*\(/,
      /\bWeakMap\b/,
      /\bfetch\s*\(/,
      /\bprocess\s*(?:\.|\[)/,
      /\bimport\s*\(/,
      /\brequire\s*\(/,
      /\bWebSocket\b/,
      /\bXMLHttpRequest\b/,
      /\brandomBytes\s*\(/,
      /\brandomUUID\s*\(/,
      /\bgetRandomValues\s*\(/,
      /\bviem\b/,
      /["']node:(?:child_process|fs|os|path|process|net|http|https)["']/,
    ]) {
      assert.equal(
        forbidden.test(source),
        false,
        `${path.basename(file)} contains ambient authority ${forbidden}`,
      );
    }
  }
});
