import assert from "node:assert/strict";
import { readFileSync, realpathSync } from "node:fs";
import { dirname, extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import * as core from "./compute-workload-activation-observation-core.mjs";
import * as facade from "./compute-workload-activation-observation.mjs";

function staticLocalClosure(entrypoint) {
  const modules = new Map();
  const externalImports = new Set();
  function walk(candidate) {
    const file = realpathSync(candidate);
    if (modules.has(file)) return;
    const source = readFileSync(file, "utf8");
    modules.set(file, source);
    const imports = [
      ...source.matchAll(
        /(?:import|export)\s+(?:[^'";]+?\s+from\s+)?["']([^"']+)["']/g,
      ),
    ].map((match) => match[1]);
    for (const specifier of imports) {
      if (!specifier.startsWith(".")) {
        externalImports.add(specifier);
        continue;
      }
      let target = resolve(dirname(file), specifier);
      if (!extname(target)) target += ".mjs";
      walk(target);
    }
  }
  walk(entrypoint);
  return { modules, externalImports };
}

test("historical O core excludes mutation receipt and every fresh-brand API", () => {
  const source = readFileSync(
    new URL("./compute-workload-activation-observation-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "phala-post-measurement-activation-receipt.mjs",
    "phala-post-measurement-activation-runtime.mjs",
    "phala-production-environment-authority.mjs",
    "release-authority-stages.mjs",
    "registerProductionPhalaPostMeasurementActivationExecutionReceipt",
    "phala-seven-cvm-verifier-evidence.mjs",
    'from "./release-authority-signature-verifier.mjs"',
    "WeakMap",
    "await import(",
    "import(",
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  assert.equal(core.createComputeWorkloadActivationObservation, undefined);
  assert.equal(core.assertVerifiedComputeWorkloadActivationObservation, undefined);
  assert.equal(core.assertPersistedComputeWorkloadActivationObservation, undefined);
  assert.equal(
    typeof core.createUnbrandedComputeWorkloadActivationObservationCandidate,
    "function",
  );
  assert.equal(
    typeof core.assertHistoricallyVerifiedComputeWorkloadActivationObservation,
    "function",
  );
});

test("historical O recursive closure is static, pure, and browser-compatible", () => {
  const entrypoint = fileURLToPath(new URL(
    "./compute-workload-activation-observation-core.mjs",
    import.meta.url,
  ));
  const { modules, externalImports } = staticLocalClosure(entrypoint);
  const relativeModules = [...modules.keys()].map((file) => (
    file.slice(realpathSync(new URL("..", import.meta.url)).length + 1)
  ));
  assert.equal(
    relativeModules.includes("scripts/phala-seven-cvm-historical-evidence-core.mjs"),
    true,
  );
  assert.equal(
    relativeModules.includes("scripts/release-authority-signature-verifier-core.mjs"),
    true,
  );
  assert.equal(
    relativeModules.includes("scripts/phala-seven-cvm-verifier-evidence.mjs"),
    false,
  );
  assert.deepEqual([...externalImports].sort(), [
    "@noble/curves/secp256k1",
    "@noble/hashes/sha3",
    "@noble/hashes/utils",
    "node:crypto",
    "node:util",
  ]);
  for (const [file, source] of modules) {
    for (const forbidden of [
      "node:child_process", "node:fs", "node:os", "node:path",
      "Date.now(", "WeakMap", "process.", "fetch(", "import(",
      "phala-seven-cvm-verifier-evidence.mjs",
      'from "./release-authority-signature-verifier.mjs"',
    ]) {
      assert.equal(
        source.includes(forbidden),
        false,
        `${file} contains forbidden historical dependency ${forbidden}`,
      );
    }
  }
});

test("production facade alone owns receipt-backed fresh O branding", () => {
  const source = readFileSync(
    new URL("./compute-workload-activation-observation.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /from "\.\/phala-post-measurement-activation-receipt\.mjs";/,
  );
  assert.match(
    source,
    /from "\.\/compute-workload-activation-observation-core\.mjs";/,
  );
  assert.equal(source.includes("receipt-brand"), false);
  assert.equal(source.includes("registerProduction"), false);
  assert.equal(typeof facade.createComputeWorkloadActivationObservation, "function");
  assert.equal(
    typeof facade.assertVerifiedComputeWorkloadActivationObservation,
    "function",
  );
  assert.equal(
    typeof facade.assertHistoricallyVerifiedComputeWorkloadActivationObservation,
    "function",
  );
  assert.throws(
    () => facade.assertVerifiedComputeWorkloadActivationObservation(
      Object.freeze({}),
      { checkedAt: 1 },
    ),
    /not reconstructed from branded production evidence/,
  );
});
