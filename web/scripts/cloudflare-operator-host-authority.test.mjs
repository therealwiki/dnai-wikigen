import assert from "node:assert/strict";
import {
  chmod,
  mkdtemp,
  realpath,
  rm,
} from "node:fs/promises";
import { release, tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  assertCloudflareBuildSandboxIsolation,
  cloudflareBuildSandbox,
} from "./cloudflare-build-sandbox-core.mjs";
import { __test as deployRunnerTest } from "./deploy-cloudflare.mjs";
import { cloudflareBuildEnvironment } from "./deploy-cloudflare-core.mjs";
import {
  PINNED_RELEASE_RUNTIME_PROOF,
  assertPinnedReleaseRuntime,
} from "./release-runtime-pins-core.mjs";

function assertFrozenDarwinOperatorIdentity() {
  assert.equal(process.platform, "darwin");
  assert.equal(process.arch, "arm64");
  assert.equal(release(), "25.6.0");
  assert.equal(process.version, "v24.9.0");
  assert.equal(process.execPath, "/opt/homebrew/Cellar/node/24.9.0/bin/node");
}

test("frozen Darwin operator host proves the exact release runtime", () => {
  assertFrozenDarwinOperatorIdentity();
  assert.deepEqual(assertPinnedReleaseRuntime(), PINNED_RELEASE_RUNTIME_PROOF);
});

test("Cloudflare deployment runner uses the same frozen operator runtime authority", () => {
  assertFrozenDarwinOperatorIdentity();
  assert.deepEqual(
    deployRunnerTest.assertPinnedReleaseRuntime(),
    deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
  );
});

test("frozen Darwin sandbox proves host-file and network denial for release dependency installation", async () => {
  assertFrozenDarwinOperatorIdentity();
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const buildRoot = await mkdtemp(path.join(
    canonicalTemporaryRoot,
    "dnai-build-sandbox-test-",
  ));
  await chmod(buildRoot, 0o700);
  try {
    const sandbox = await cloudflareBuildSandbox({ buildRoot });
    const env = cloudflareBuildEnvironment({}, {}, buildRoot);
    await assertCloudflareBuildSandboxIsolation({
      buildRoot,
      profile: sandbox.profile,
      env,
    });
  } finally {
    await rm(buildRoot, { recursive: true, force: true });
  }
});
