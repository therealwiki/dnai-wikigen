import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  MANIFEST_PATH,
  OPERATOR_WEB_TEST_TRUTH,
  PORTABLE_WEB_TEST_TRUTH,
  WEB_ROOT,
  loadAndAssertPortableWebTestManifest,
} from "./test-harness/portable-web-test-manifest.mjs";
import {
  forbiddenPortableWebEnvironmentNames,
} from "./test-harness/portable-web-test-profile.mjs";

const RUNNER = path.join(
  WEB_ROOT,
  "scripts",
  "test-harness",
  "run-portable-web-tests.mjs",
);

function runnerFailure({ args = [], environment = {}, execArgv = [] } = {}) {
  return spawnSync(process.execPath, [
    ...execArgv,
    RUNNER,
    ...args,
  ], {
    cwd: WEB_ROOT,
    encoding: "utf8",
    env: { ...process.env, ...environment },
    maxBuffer: 64 * 1024,
    timeout: 15_000,
  });
}

test("portable/operator manifest assigns every web release test exactly once", () => {
  const manifest = loadAndAssertPortableWebTestManifest();
  const manifestLoader = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "test-harness", "portable-web-test-manifest.mjs"),
    "utf8",
  );
  assert.equal(manifest.portable_truth_status, PORTABLE_WEB_TEST_TRUTH);
  assert.equal(manifest.operator_host_truth_status, OPERATOR_WEB_TEST_TRUTH);
  assert.deepEqual({
    discovered_file_count: manifest.discovered_file_count,
    discovered_files_sha256: manifest.discovered_files_sha256,
    operator_host_file_count: manifest.operator_host_file_count,
    operator_host_files_sha256: manifest.operator_host_files_sha256,
    portable_file_count: manifest.portable_file_count,
    portable_files_sha256: manifest.portable_files_sha256,
  }, {
    discovered_file_count: 24,
    discovered_files_sha256:
      "sha256:ec42278159729dfe5ef6fc599a204598083dc9dfeced503b14c418254f97cbbc",
    operator_host_file_count: 1,
    operator_host_files_sha256:
      "sha256:6a32454cb31280386ee7b144a2ba45a929c1bf282d9b26030d42c3f90d913bd9",
    portable_file_count: 23,
    portable_files_sha256:
      "sha256:88fe1cd893519440feba35ae053468cd95b620ee059c1a49697ad699ea25e122",
  });
  assert.equal(
    createHash("sha256").update(fs.readFileSync(MANIFEST_PATH)).digest("hex"),
    "4ea6c02a827f13f1bc883cf31129899a10283572b799f3229cc039022fba6c0d",
  );
  assert.equal(
    manifest.portable.includes("scripts/portable-ci-test-split.test.mjs"),
    true,
  );
  assert.equal(
    manifest.portable.includes(
      "scripts/cloudflare-production-uploader-authority-core.test.mjs",
    ),
    true,
  );
  assert.deepEqual(manifest.operator_host, [
    "scripts/cloudflare-operator-host-authority.test.mjs",
  ]);
  assert.match(
    manifestLoader,
    /web test directory must be one canonical real directory[\s\S]*metadata\.nlink !== 1[\s\S]*fs\.realpathSync\(absolute\) !== absolute/,
  );
  assert.match(
    manifestLoader,
    /stat\.nlink !== 1[\s\S]*fs\.realpathSync\(MANIFEST_PATH\) !== MANIFEST_PATH/,
  );
});

test("portable web runner rejects hooks, credentials, and entrypoint selection", () => {
  for (const [result, pattern] of [
    [runnerFailure({ args: ["scripts/deploy-cloudflare-runner.test.mjs"] }), /caller-selected/],
    [runnerFailure({ execArgv: ["--trace-warnings"] }), /ordinary Node/],
    [
      runnerFailure({ environment: { DNAI_PORTABLE_CI_AUTHORITY: "forged" } }),
      /authority or credential environment/,
    ],
    [
      runnerFailure({ environment: { PHALA_CLOUD_API_KEY: "not-a-real-key" } }),
      /authority or credential environment/,
    ],
  ]) {
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, pattern);
  }
  const credentialNames = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "CF_API_TOKEN",
    "CLOUDFLARE_API_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "NODE_AUTH_TOKEN",
    "NPM_TOKEN",
    "OPENROUTER_API_KEY",
    "PHALA_CLOUD_API_KEY",
    "TINKER_ARENA_PROVISION_AUTH_KEY_B64",
    "TINKER_COMPUTE_CREDENTIAL_SIGNING_KEY",
  ];
  assert.deepEqual(
    forbiddenPortableWebEnvironmentNames(
      Object.fromEntries(credentialNames.map((name) => [name, "injected"])),
    ),
    [...credentialNames].sort(),
  );
  const aliasRoot = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-web-profile-alias-"));
  try {
    const alias = path.join(aliasRoot, "portable-web-profile.mjs");
    fs.symlinkSync(
      path.join(WEB_ROOT, "scripts", "test-harness", "portable-web-test-profile.mjs"),
      alias,
    );
    const aliased = spawnSync(process.execPath, [alias], {
      cwd: WEB_ROOT,
      encoding: "utf8",
      env: { ...process.env, PHALA_CLOUD_API_KEY: "injected" },
      maxBuffer: 64 * 1024,
      timeout: 15_000,
    });
    assert.notEqual(aliased.status, 0);
    assert.match(`${aliased.stdout}\n${aliased.stderr}`, /authority or credential environment/);
  } finally {
    fs.rmSync(aliasRoot, { force: true, recursive: true });
  }
});

test("portable scripts stay nonauthorizing while the full glob retains operator proof", () => {
  const packageJson = JSON.parse(fs.readFileSync(
    path.join(WEB_ROOT, "package.json"),
    "utf8",
  ));
  assert.equal(packageJson.scripts["test:release"], "node --test scripts/*.test.mjs");
  assert.equal(
    packageJson.scripts["test:release:portable"],
    "node scripts/test-harness/run-portable-web-tests.mjs",
  );
  assert.equal(
    packageJson.scripts["test:portable"],
    "vitest run && npm run test:release:portable",
  );
  assert.equal(
    packageJson.scripts["check:portable"],
    "npm run typecheck && npm run test:portable && npm run build",
  );
  assert.equal(
    packageJson.scripts.check,
    "npm run typecheck && npm run test && npm run build && npm run audit:dependencies",
  );
  assert.equal(
    packageJson.scripts["check:ci"],
    "npm run check:portable && npm run audit:dependencies",
  );
  assert.doesNotMatch(packageJson.scripts.check, /--offline|audit-level=high/);

  const runtimeTest = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "release-runtime-pins-core.test.mjs"),
    "utf8",
  );
  const deployTest = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "deploy-cloudflare-runner.test.mjs"),
    "utf8",
  );
  const sandboxTest = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "cloudflare-build-sandbox-core.test.mjs"),
    "utf8",
  );
  assert.doesNotMatch(runtimeTest, /assertPinnedReleaseRuntime\(\)/);
  assert.doesNotMatch(deployTest, /deployRunnerTest\.assertPinnedReleaseRuntime\(\)/);
  assert.doesNotMatch(
    sandboxTest,
    /assertCloudflareBuildSandboxIsolation|cloudflareBuildSandbox\s*\(/,
  );

  const operatorTest = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "cloudflare-operator-host-authority.test.mjs"),
    "utf8",
  );
  assert.match(operatorTest, /assertPinnedReleaseRuntime\(\)/);
  assert.match(operatorTest, /deployRunnerTest\.assertPinnedReleaseRuntime\(\)/);
  assert.match(operatorTest, /assertCloudflareBuildSandboxIsolation/);
  assert.doesNotMatch(operatorTest, /\bskip\s*:|DNAI_BUILD_SANDBOX_ACTIVE/);

  const rejectionProbe = fs.readFileSync(
    path.join(
      WEB_ROOT,
      "scripts",
      "test-harness",
      "operator-authority-fail-closed-probe.mjs",
    ),
    "utf8",
  );
  assert.match(rejectionProbe, /process\.platform, "linux"/);
  assert.match(rejectionProbe, /assertPinnedReleaseRuntime\(\)/);
  assert.match(rejectionProbe, /cloudflareBuildSandbox\(\{ buildRoot \}\)/);
  assert.doesNotMatch(rejectionProbe, /--import|--loader|NODE_OPTIONS|registerHooks/);

  const sandboxCore = fs.readFileSync(
    path.join(WEB_ROOT, "scripts", "cloudflare-build-sandbox-core.mjs"),
    "utf8",
  );
  assert.doesNotMatch(sandboxCore, /DNAI_BUILD_SANDBOX_ACTIVE/);
  assert.match(sandboxCore, /new Set\(\["check:portable", "build"\]\)/);
  for (const file of [
    "deploy-cloudflare.mjs",
    "frontend-build-candidate-producer-core.mjs",
  ]) {
    const source = fs.readFileSync(path.join(WEB_ROOT, "scripts", file), "utf8");
    assert.match(source, /script: "check:portable"/);
    assert.doesNotMatch(source, /script: "check"/);
  }
});
