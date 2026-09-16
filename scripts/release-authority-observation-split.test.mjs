import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const stagesUrl = new URL("./release-authority-stages.mjs", import.meta.url);
const freshBindingUrl = new URL(
  "./release-live-activation-fresh-observation-binding.mjs",
  import.meta.url,
);

test("pure Stage-C authority excludes fresh O receipt provenance", async () => {
  const stages = fs.readFileSync(stagesUrl, "utf8");
  const freshBinding = fs.readFileSync(freshBindingUrl, "utf8");
  assert.match(stages, /compute-workload-activation-observation-core\.mjs/);
  assert.doesNotMatch(
    stages,
    /from "\.\/compute-workload-activation-observation\.mjs"/,
  );
  assert.doesNotMatch(
    stages,
    /export function assertLiveActivationComputeWorkloadObservationBinding/,
  );
  assert.match(
    freshBinding,
    /from "\.\/compute-workload-activation-observation\.mjs"/,
  );
  assert.match(
    freshBinding,
    /export function assertLiveActivationComputeWorkloadObservationBinding/,
  );
  const pure = await import(stagesUrl);
  const production = await import(freshBindingUrl);
  assert.equal(
    typeof pure.assertHistoricalLiveActivationComputeWorkloadObservationBinding,
    "function",
  );
  assert.equal(
    typeof production.assertLiveActivationComputeWorkloadObservationBinding,
    "function",
  );
});
