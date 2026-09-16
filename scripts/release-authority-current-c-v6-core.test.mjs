import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import * as currentC from "./release-authority-current-c-v6-core.mjs";

function staticLocalClosure(entrypoint) {
  const visiting = new Set();
  const visited = new Map();
  function visit(file) {
    if (visited.has(file)) return;
    if (visiting.has(file)) throw new Error(`current C closure cycle at ${file}`);
    visiting.add(file);
    const source = readFileSync(file, "utf8");
    assert.doesNotMatch(source, /\bimport\s*\(/);
    visited.set(file, source);
    const pattern = /(?:import|export)\s+(?:[^"']*?\s+from\s+)?["']([^"']+)["']/g;
    for (const match of source.matchAll(pattern)) {
      if (!match[1].startsWith(".")) continue;
      visit(path.resolve(path.dirname(file), match[1]));
    }
    visiting.delete(file);
  }
  visit(entrypoint);
  return visited;
}

test("current C facade exposes only the bounded v6 browser-build API", () => {
  assert.equal(
    currentC.CURRENT_LIVE_ACTIVATION_AUTHORITY_SCHEMA,
    "dnai.live-activation-authority.v6",
  );
  assert.deepEqual(Object.keys(currentC).sort(), [
    "CURRENT_LIVE_ACTIVATION_AUTHORITY_SCHEMA",
    "assertHistoricalLiveActivationComputeWorkloadObservationBinding",
    "normalizeLiveActivationAuthority",
    "projectLiveActivationFrontendBinding",
  ]);
});

test("current C facade closure is static and excludes production authority capabilities", () => {
  const entrypoint = fileURLToPath(new URL(
    "./release-authority-current-c-v6-core.mjs",
    import.meta.url,
  ));
  const closure = staticLocalClosure(entrypoint);
  const relative = [...closure.keys()].map((file) => path.relative(
    path.resolve(path.dirname(entrypoint), ".."),
    file,
  ));
  for (const forbidden of [
    "scripts/pre-ceremony-runtime-authority.mjs",
    "scripts/release-ceremony-authorization-production.mjs",
    "scripts/release-ceremony-lock.mjs",
    "scripts/phala-production-executor-core.mjs",
    "scripts/phala-production-sdk-adapter.mjs",
  ]) {
    assert.equal(relative.includes(forbidden), false, `closure reached ${forbidden}`);
  }
  assert.equal(
    relative.includes("scripts/release-ceremony-lock-protocol-core.mjs"),
    true,
  );
  assert.equal(
    relative.includes("scripts/frontend-build-candidate-receipt-core.mjs"),
    true,
  );
  assert.deepEqual(
    relative.filter((file) => file.startsWith("web/scripts/")).sort(),
    ["web/scripts/independent-eip191-replay-core.mjs"],
  );
});
