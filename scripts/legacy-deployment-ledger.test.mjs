import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import { projectFreshContractDeploymentReceipt } from "./cvm-launch-intent-core.mjs";

const ROOT = path.resolve(import.meta.dirname, "..");
const LEGACY_LEDGER = path.join(ROOT, "deployments", "base-sepolia.json");
const CONFIGURE_GUARD = path.join(
  ROOT,
  "⚙️",
  "tinker-delegate",
  "contracts",
  "scripts",
  "operator-policy-configure-guard.sh",
);

test("tracked prior-operator ledger is explicitly historical and contains no present-authority wording", () => {
  const text = fs.readFileSync(LEGACY_LEDGER, "utf8");
  const ledger = JSON.parse(text);
  assert.equal(ledger.schemaVersion, 1);
  assert.equal(ledger.notAuthorityForFreshRelease, true);
  assert.equal(
    ledger.status,
    "historical_untrusted_incomplete_prior_operator_evidence_not_fresh_release_authority",
  );
  assert.match(ledger.supersededBoundary, /schemaVersion 2 seven-contract suite/);
  assert.doesNotMatch(text, /current/i);
  assert.ok(Object.values(ledger.contracts).every(
    (contract) => contract.status === "historical_untrusted_prior_operator_deployment_observation"
      && contract.historicalRecordedOperatorControlled === true,
  ));
  assert.equal(
    ledger.phala.status,
    "historical_untrusted_prior_operator_runtime_observation_not_live_health_evidence",
  );
});

test("fresh receipt projection and shared ceremony guard reject the legacy ledger", () => {
  const ledger = JSON.parse(fs.readFileSync(LEGACY_LEDGER, "utf8"));
  assert.throws(
    () => projectFreshContractDeploymentReceipt(ledger, {
      expectedDeploymentIntentSha256: `sha256:${"1".repeat(64)}`,
      expectedReleaseSha: "a".repeat(40),
    }),
    /schemaVersion|fresh|contract ledger/i,
  );

  const result = spawnSync(
    "bash",
    ["-c", '. "$1"; MANIFEST_PATH="$2"; operator_policy_require_fresh_release_ledger', "bash", CONFIGURE_GUARD, LEGACY_LEDGER],
    { cwd: ROOT, encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Historical schemaVersion 1, superseded, or non-fresh/);
});
