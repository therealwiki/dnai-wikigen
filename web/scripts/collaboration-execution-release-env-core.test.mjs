import assert from "node:assert/strict";
import test from "node:test";

import { knownVector } from "../../scripts/execution-policy-release-core.fixture.mjs";
import {
  COLLABORATION_EXECUTION_RELEASE_ENV_KEYS,
  normalizeCollaborationExecutionReleaseEnv,
  projectCollaborationExecutionReleaseEnv,
} from "./collaboration-execution-release-env-core.mjs";

test("current final-authority v4 projects the exact release-configured Collaboration env", () => {
  const core = knownVector();
  const env = projectCollaborationExecutionReleaseEnv(core);
  assert.deepEqual(Object.keys(env), COLLABORATION_EXECUTION_RELEASE_ENV_KEYS);
  assert.equal(env.VITE_COLLABORATION_EXECUTION_RELEASE_SHA, core.release_sha);
  assert.equal(
    env.VITE_COLLABORATION_EXECUTION_RELEASE_VERIFICATION_SHA256,
    core.seven_cvm_release_verification_authority_sha256,
  );
  assert.equal(
    env.VITE_COLLABORATION_EXECUTION_ENABLED,
    String(core.collaboration_execution.enabled),
  );
  assert.equal(
    env.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED,
    String(core.compute_workload_wallet_adoption.enabled),
  );
  assert.equal(
    env.VITE_ROYALTY_RELEASE_ACTIVE_STATE_SHA256,
    core.royalty_release_active_state_sha256,
  );
  assert.deepEqual(normalizeCollaborationExecutionReleaseEnv(env), env);
});

test("Collaboration env rejects omission, aliasing, noncanonical decisions, and lineage drift", () => {
  const env = projectCollaborationExecutionReleaseEnv(knownVector());
  for (const mutate of [
    (value) => { delete value.VITE_FINAL_RELEASE_AUTHORITY_SHA256; },
    (value) => { value.VITE_COLLABORATION_EXECUTION_SERVICE = "other"; },
    (value) => { value.VITE_COLLABORATION_EXECUTION_ENABLED = "yes"; },
    (value) => { value.VITE_COMPUTE_WORKLOAD_WALLET_ADOPTION_ENABLED = "yes"; },
    (value) => { value.VITE_ROYALTY_RELEASE_HISTORY_SHA256 = `sha256:${"f".repeat(64)}`; },
  ]) {
    const changed = { ...env };
    mutate(changed);
    assert.throws(
      () => normalizeCollaborationExecutionReleaseEnv(changed, {
        VITE_ROYALTY_RELEASE_HISTORY_SHA256:
          env.VITE_ROYALTY_RELEASE_HISTORY_SHA256,
      }),
      /fields|must|drifted/,
    );
  }
});
