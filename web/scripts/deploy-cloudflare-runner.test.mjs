import assert from "node:assert/strict";
import {
  access,
  lstat,
  readFile,
  realpath,
} from "node:fs/promises";
import test from "node:test";

import { semanticValidationReceipt } from "./build-release-env.mjs";
import {
  CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
  CLOUDFLARE_BUILD_SOURCE_KIND_WORKING_TREE,
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
} from "./cloudflare-build-sandbox-core.mjs";
import {
  __test as deployRunnerTest,
  resolvePinnedWranglerCli,
  runCloudflareDeployment,
} from "./deploy-cloudflare.mjs";
import {
  __test as cloudflareTest,
  CLOUDFLARE_MODELED_PREVIEW_BRANCH,
  CLOUDFLARE_PRODUCTION_BRANCH,
} from "./deploy-cloudflare-core.mjs";
import {
  __test as releaseEnvTest,
  arenaReleaseApprovedChallengeSetSha256,
  serializeEnv,
} from "./release-env-core.mjs";
import {
  FRONTEND_BUILD_CANDIDATE_SCHEMA,
  FRONTEND_BUILD_CANDIDATE_STATUS,
  FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
} from "./frontend-build-candidate-core.mjs";

const SHA = "1".repeat(40);
const GIT_TREE_OID = `sha1:${"2".repeat(40)}`;
const EXTERNAL_BUILD_CLOSURE_SHA256 = `sha256:${"9".repeat(64)}`;
const SIGNED_DIST_MANIFEST = "b".repeat(64);
const INSTALLED_DEPENDENCY_PROOF = Object.freeze({
  schema: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
  truth_status: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
  packageCount: 498,
  sha256: `sha256:${"7".repeat(64)}`,
});
const LIVE_AUTHORITY_BINDING = Object.freeze({
  deploymentIntentSha256: `sha256:${"a1".repeat(32)}`,
  reviewerAuthorityGenesisAcceptanceSha256: `sha256:${"a2".repeat(32)}`,
  ceremonyAuthorizationSha256: `sha256:${"a3".repeat(32)}`,
  computeWorkloadActivationObservationSha256: `sha256:${"a8".repeat(32)}`,
  computeWorkloadBrowserBindingSha256: `sha256:${"a9".repeat(32)}`,
  liveActivationAuthoritySha256: `sha256:${"a4".repeat(32)}`,
  runtimeAuthorityDependencySha256: `sha256:${"a5".repeat(32)}`,
  releaseInputsSha256: `sha256:${"a6".repeat(32)}`,
  frontendBuildCandidateReceiptSha256: `sha256:${"a7".repeat(32)}`,
  frontendBuildSha256: `sha256:${SIGNED_DIST_MANIFEST}`,
});
const ARENA_BINDINGS = Object.freeze({
  "variant-call@1.0.0": Object.freeze({
    registry_challenge_id: "1",
    registry_version: 1,
    controller_address: "0x1111111111111111111111111111111111111111",
    pending_controller_address: "0x0000000000000000000000000000000000000000",
    lifecycle: "open",
    paused: false,
    configuration_frozen: true,
    catalog_manifest_hash: "11".repeat(32),
    metadata_uri: "ipfs://bafybeigdyrzt-reviewed-arena-metadata",
    metadata_hash: `0x${"11".repeat(32)}`,
    sealed_artifact_commitment: `0x${"22".repeat(32)}`,
    evaluator_commitment: `0x${"33".repeat(32)}`,
    release_policy_commitment: `0x${"44".repeat(32)}`,
  }),
});
const LIVE_ENV = {
  ...Object.fromEntries(releaseEnvTest.ENV_KEYS.map((key) => [key, ""])),
  ...Object.fromEntries(cloudflareTest.REQUIRED_LIVE_BINDINGS.map((key) => [key, "release-pinned"])),
  VITE_BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
  VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://base-sepolia-rpc.publicnode.com",
  VITE_RELEASE_SHA: SHA,
  VITE_DILIGENCE_ROOM_ADDRESS: "0x1111111111111111111111111111111111111111",
  VITE_COMPUTE_CREDIT_VAULT_ADDRESS: "0x7777777777777777777777777777777777777777",
  VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: `0x${"88".repeat(32)}`,
  VITE_ENABLE_CONTRACT_WRITES: "true",
  VITE_ENABLE_ARTIFACT_UPLOAD: "true",
  VITE_ENABLE_COMPUTE_CONSOLE: "true",
  VITE_ENABLE_ARENA_SUBMISSION: "true",
  VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
  VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
  VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true",
  VITE_COMPUTE_WORKLOAD_QVL_VERIFIER: "0x2222222222222222222222222222222222222222",
  VITE_COMPUTE_WORKLOAD_CVM_ID: "main-runtime-cvm-0001",
  VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256: `sha256:${"23".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256: `sha256:${"24".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE: `0x${"25".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256: `sha256:${"26".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256: `sha256:${"27".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256: `sha256:${"28".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH: `0x${"33".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_COMPOSE_HASH: `0x${"44".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_APP_ID: "55".repeat(20),
  VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH: "66".repeat(32),
  VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: "0x9999999999999999999999999999999999999999",
  VITE_COMPUTE_WORKLOAD_CHAIN_ID: "84532",
  VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS: "0x7777777777777777777777777777777777777777",
  VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH: `0x${"88".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256: `0x${"aa".repeat(32)}`,
  VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS: "300",
  VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON: "[]",
  VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON: JSON.stringify(ARENA_BINDINGS),
  VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256:
    arenaReleaseApprovedChallengeSetSha256(ARENA_BINDINGS),
};

test("release uploader is the exact reviewed Wrangler runtime", () => {
  assert.equal(deployRunnerTest.RELEASE_GIT_PATH, "/usr/bin/git");
  assert.deepEqual(deployRunnerTest.RELEASE_GIT_ENV, {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_LITERAL_PATHSPECS: "1",
  });
  assert.equal(deployRunnerTest.PINNED_WRANGLER_RUNTIME.version, "4.110.0");
  assert.equal(
    resolvePinnedWranglerCli(),
    new URL("../node_modules/wrangler/wrangler-dist/cli.js", import.meta.url).pathname,
  );
  assert.throws(
    () => deployRunnerTest.defaultWrangler([], "/tmp/fake-stage"),
    /fresh isolated release runtime/,
  );
});

test("release executor exposes the exact Node, dylib, and npm proof pins", () => {
  assert.deepEqual(deployRunnerTest.PINNED_NODE_RUNTIME, {
    version: "v24.9.0",
    executablePath: "/opt/homebrew/Cellar/node/24.9.0/bin/node",
    executableMode: 0o555,
    executableSize: 64_221_968,
    executableSha256:
      "3e7673f6552cffd3f9eaa3bcb910198a4d0786e99bb861d24eb81cc3fce563e7",
  });
  assert.deepEqual(deployRunnerTest.PINNED_NPM_RUNTIME, {
    version: "11.6.0",
    executableSymlink: "/opt/homebrew/Cellar/node/24.9.0/bin/npm",
    executableTarget: "/opt/homebrew/lib/node_modules/npm/bin/npm-cli.js",
    treeRoot: "/opt/homebrew/lib/node_modules/npm",
    entryCount: 2_857,
    totalBytes: 11_960_560,
    treeSha256: "417ff144368776eeaf8651a00ec0e3933db96278b1a7efe9e7f53817634c6289",
  });
  if (
    process.version === deployRunnerTest.PINNED_NODE_RUNTIME.version
    && process.execPath === deployRunnerTest.PINNED_NODE_RUNTIME.executablePath
  ) {
    assert.deepEqual(
      deployRunnerTest.assertPinnedReleaseRuntime(),
      deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
    );
  }
});

test("release runtime is pinned before environment, closure, or authority evaluation", async () => {
  let environmentReads = 0;
  let snapshotReads = 0;
  await assert.rejects(
    runCloudflareDeployment({
      assertReleaseRuntime: () => {
        throw new Error("unreviewed release runtime");
      },
      loadReleaseEnvironment: async () => {
        environmentReads += 1;
        return {};
      },
      snapshotDeploymentInputs: async () => {
        snapshotReads += 1;
        return snapshot();
      },
      controlEnv: {},
      sensitiveEnv: {},
    }),
    /unreviewed release runtime/,
  );
  assert.equal(environmentReads, 0);
  assert.equal(snapshotReads, 0);

  let runtimeReads = 0;
  const setup = successfulDependencies({
    assertReleaseRuntime: () => {
      runtimeReads += 1;
      return runtimeReads === 2
        ? {
            ...deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
            npmTreeSha256: "f".repeat(64),
          }
        : deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF;
    },
  });
  await assert.rejects(
    runCloudflareDeployment(setup.dependencies),
    /release runtime changed during authority validation/,
  );
  assert.equal(setup.wranglerCalls(), 0);
  assert.deepEqual(setup.events, []);
});

test("deployment wrapper delegates the full gate to the hardened runner", async () => {
  const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
  const packageLock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
  assert.equal(packageJson.scripts["deploy:cloudflare"], "node scripts/deploy-cloudflare.mjs");
  assert.equal(packageJson.devDependencies.wrangler, "4.110.0");
  assert.equal(packageLock.lockfileVersion, 3);
  assert.equal(packageLock.packages[""].devDependencies.wrangler, "4.110.0");
  assert.equal(packageLock.packages["node_modules/wrangler"].version, "4.110.0");
  for (const [packagePath, descriptor] of Object.entries(packageLock.packages)) {
    if (!packagePath || descriptor.link) continue;
    assert.match(descriptor.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/);
    assert.match(descriptor.resolved, /^https:\/\/registry\.npmjs\.org\//);
  }
});

test("verification HOME is fresh, private, owner-controlled, and removable", async () => {
  const home = await deployRunnerTest.defaultCreateBuildHome();
  try {
    assert.equal(await realpath(home), home);
    const metadata = await lstat(home);
    assert.equal(metadata.isDirectory(), true);
    assert.equal(metadata.mode & 0o077, 0);
    if (typeof process.geteuid === "function") {
      assert.equal(metadata.uid, process.geteuid());
    }
    for (const relative of [
      "tmp",
      ".cache",
      ".config",
      ".local/share",
      ".npm-cache",
    ]) {
      assert.equal((await lstat(`${home}/${relative}`)).isDirectory(), true);
    }
  } finally {
    await deployRunnerTest.defaultRemoveBuildHome(home);
  }
  await assert.rejects(access(home), /ENOENT/);
});

function snapshot(sourceSha256 = "a".repeat(64)) {
  return {
    objectFormat: "sha1",
    headSha: SHA,
    gitTreeOid: GIT_TREE_OID,
    dirty: "?? modeled-change.txt",
    sourceSha256,
    externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
  };
}

function isolatedBuildTestDependencies(sourceRequests = []) {
  return {
    assertReleaseRuntime: () => deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
    createVerificationHome: async () => "/tmp/fake-verification-home",
    removeVerificationHome: async () => {},
    createBuildWorkspace: async ({
      buildRoot,
      sourceKind,
      sourceCommitSha,
      expectedGitTreeOid,
    }) => {
      sourceRequests.push({
        operation: "create",
        sourceKind,
        sourceCommitSha,
        expectedGitTreeOid,
      });
      return {
        rootDir: `${buildRoot}/workspace`,
        webDir: `${buildRoot}/workspace/web`,
        sourceKind,
        sourceCommitSha: sourceCommitSha ?? null,
        gitTreeOid: expectedGitTreeOid ?? null,
      };
    },
    createBuildSandbox: async ({ buildRoot }) => ({
      npmCacheRoot: "/tmp/fake-npm-cache",
      profile: `fake-sandbox-profile:${buildRoot}`,
    }),
    assertBuildSandboxIsolation: async () => {},
    assertBuildWorkspaceIntegrity: async ({
      sourceKind,
      sourceCommitSha,
      expectedGitTreeOid,
    }) => {
      sourceRequests.push({
        operation: "integrity",
        sourceKind,
        sourceCommitSha,
        expectedGitTreeOid,
      });
    },
    installBuildDependencies: async () => {},
    projectInstalledDependencyTree: async () => INSTALLED_DEPENDENCY_PROOF,
    createUploadHome: async () => "/tmp/fake-upload-home",
    removeUploadHome: async () => {},
  };
}

function successfulDependencies(overrides = {}) {
  const events = [];
  const sourceRequests = [];
  let wranglerCalls = 0;
  return {
    events,
    sourceRequests,
    wranglerCalls: () => wranglerCalls,
    dependencies: {
      releaseArguments: [],
      loadReleaseEnvironment: async () => ({}),
      snapshotDeploymentInputs: async () => snapshot(),
      validateRelease: async () => {
        throw new Error("modeled preview must not invoke the live validator");
      },
      verify: async () => { events.push("verify"); },
      createBuildHome: async () => "/tmp/fake-build-home",
      removeBuildHome: async () => {},
      build: async () => { events.push("build"); },
      auditBuild: async ({ distDir }) => {
        events.push(distDir.includes("fake-stage") ? "audit-stage" : "audit-build");
        return { manifestSha256: "b".repeat(64), fileCount: 3, totalBytes: 100 };
      },
      auditStage: async () => {
        events.push("audit-bundle");
        return { bundleManifestSha256: "c".repeat(64) };
      },
      stageBundle: async () => {
        events.push("stage");
        return "/tmp/fake-stage";
      },
      removeStage: async () => { events.push("remove-stage"); },
      invokeWrangler: async (args, cwd, runtime) => {
        wranglerCalls += 1;
        events.push("wrangler");
        assert.equal(cwd, "/tmp/fake-stage");
        assert.equal(runtime.webDir, "/tmp/fake-upload-home/workspace/web");
        assert.deepEqual(args.slice(-5), [
          "--branch",
          CLOUDFLARE_MODELED_PREVIEW_BRANCH,
          "--commit-hash",
          SHA,
          "--commit-dirty=true",
        ]);
      },
      output: () => {},
      sensitiveEnv: {},
      controlEnv: {},
      ...isolatedBuildTestDependencies(sourceRequests),
      ...overrides,
    },
  };
}

test("runner destroys verification state, builds in a fresh workspace, audits staging, and only then invokes Wrangler", async () => {
  const outputLines = [];
  const setup = successfulDependencies({
    output: (line) => outputLines.push(line),
  });
  const result = await runCloudflareDeployment(setup.dependencies);
  assert.equal(result.policy.mode, "modeled");
  assert.equal(result.policy.branch, CLOUDFLARE_MODELED_PREVIEW_BRANCH);
  assert.deepEqual(result.buildSource, {
    sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_WORKING_TREE,
  });
  assert.equal(setup.wranglerCalls(), 1);
  assert.equal(setup.sourceRequests.length, 8);
  for (const request of setup.sourceRequests) {
    assert.deepEqual(request, {
      operation: request.operation,
      sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_WORKING_TREE,
      sourceCommitSha: undefined,
      expectedGitTreeOid: undefined,
    });
  }
  assert.deepEqual(setup.events, [
    "verify",
    "build",
    "audit-build",
    "stage",
    "audit-stage",
    "audit-bundle",
    "audit-stage",
    "audit-bundle",
    "wrangler",
    "remove-stage",
  ]);
  assert.equal(
    outputLines.includes(
      `cloudflare_staged_bundle_manifest_sha256=${"c".repeat(64)}`,
    ),
    true,
  );
  assert.equal(
    outputLines.includes("cloudflare_build_source_kind=working_tree"),
    true,
  );
  assert.equal(
    outputLines.some((line) => line.startsWith("cloudflare_artifact_sha256=")),
    false,
  );
  assert.equal(
    outputLines.includes(
      `cloudflare_installed_dependency_tree_sha256=${INSTALLED_DEPENDENCY_PROOF.sha256}`,
    ),
    true,
  );
});

test("check-generated source or dependency state cannot reach the artifact workspace", async (context) => {
  await context.test("verification source mutation", async () => {
    let checkRan = false;
    const setup = successfulDependencies({
      verify: async () => {
        setup.events.push("verify");
        checkRan = true;
      },
      assertBuildWorkspaceIntegrity: async ({ workspace }) => {
        if (checkRan && workspace.webDir.includes("verification")) {
          throw new Error("check mutated the isolated verification source");
        }
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /check mutated the isolated verification source/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("verification dependency mutation", async () => {
    let projections = 0;
    const setup = successfulDependencies({
      projectInstalledDependencyTree: async () => {
        projections += 1;
        return projections === 2
          ? { ...INSTALLED_DEPENDENCY_PROOF, sha256: `sha256:${"8".repeat(64)}` }
          : INSTALLED_DEPENDENCY_PROOF;
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /dependency tree changed during full release verification/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("artifact-build dependency mutation", async () => {
    let projections = 0;
    const setup = successfulDependencies({
      projectInstalledDependencyTree: async () => {
        projections += 1;
        return projections === 4
          ? { ...INSTALLED_DEPENDENCY_PROOF, sha256: `sha256:${"8".repeat(64)}` }
          : INSTALLED_DEPENDENCY_PROOF;
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /dependency tree changed during the fresh build/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify", "build"]);
  });

  await context.test("Wrangler dependency mutation", async () => {
    let projections = 0;
    const setup = successfulDependencies({
      projectInstalledDependencyTree: async () => {
        projections += 1;
        return projections === 5
          ? { ...INSTALLED_DEPENDENCY_PROOF, sha256: `sha256:${"8".repeat(64)}` }
          : INSTALLED_DEPENDENCY_PROOF;
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /dependency tree changed before Wrangler invocation/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "remove-stage",
    ]);
  });
});

test("verification, artifact-build, and Wrangler HOMEs must be distinct", async () => {
  {
    const setup = successfulDependencies({
      createBuildHome: async () => "/tmp/fake-verification-home",
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /verification and artifact-build HOMEs must be distinct/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  }
  {
    const setup = successfulDependencies({
      createUploadHome: async () => "/tmp/fake-build-home",
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /verification, artifact-build, and Wrangler HOMEs must be distinct/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "remove-stage",
    ]);
  }
});

test("staged middleware and release controls must match the validated source snapshot", async () => {
  const setup = successfulDependencies({
    snapshotDeploymentInputs: async () => ({
      ...snapshot(),
      uploadControlManifestSha256: "d".repeat(64),
    }),
    auditStage: async () => {
      setup.events.push("audit-bundle");
      return {
        bundleManifestSha256: "c".repeat(64),
        uploadControlManifestSha256: "e".repeat(64),
      };
    },
  });
  await assert.rejects(
    runCloudflareDeployment(setup.dependencies),
    /staged release controls do not match the validated source snapshot/,
  );
  assert.equal(setup.wranglerCalls(), 0);
  assert.deepEqual(setup.events, [
    "verify",
    "build",
    "audit-build",
    "stage",
    "audit-stage",
    "audit-bundle",
    "remove-stage",
  ]);
});

test("runner strips operator credentials from the fresh frontend build subprocess", async () => {
  let receivedVerifyEnvironment;
  let receivedBuildEnvironment;
  const dependencyInstalls = [];
  const setup = successfulDependencies({
    buildHostEnv: {
      PATH: "/usr/bin:/bin",
      HOME: "/Users/release",
      CLOUDFLARE_API_TOKEN: "cloudflare-secret",
      PHALA_CLOUD_API_KEY: "phala-secret",
      OPENROUTER_API_KEY: "openrouter-secret",
      GITHUB_TOKEN: "github-secret",
    },
    verify: async ({ env }) => {
      setup.events.push("verify");
      receivedVerifyEnvironment = env;
    },
    build: async ({ env }) => {
      setup.events.push("build");
      receivedBuildEnvironment = env;
    },
    installBuildDependencies: async ({ env, webDir }) => {
      dependencyInstalls.push({ env, webDir });
    },
  });
  await runCloudflareDeployment(setup.dependencies);
  assert.equal(setup.wranglerCalls(), 1);
  assert.notEqual(receivedVerifyEnvironment, receivedBuildEnvironment);
  assert.equal(receivedVerifyEnvironment.HOME, "/tmp/fake-verification-home");
  assert.equal(receivedBuildEnvironment.PATH, cloudflareTest.RELEASE_CHILD_PATH);
  assert.notEqual(receivedBuildEnvironment.PATH, "/usr/bin:/bin");
  assert.equal(receivedBuildEnvironment.NODE_ENV, "production");
  assert.equal(receivedBuildEnvironment.HOME, "/tmp/fake-build-home");
  assert.notEqual(receivedBuildEnvironment.HOME, "/Users/release");
  assert.equal(receivedBuildEnvironment.NPM_CONFIG_USERCONFIG, "/tmp/fake-build-home/.npmrc");
  assert.equal(Object.isFrozen(receivedBuildEnvironment), true);
  assert.equal(dependencyInstalls.length, 3);
  assert.equal(dependencyInstalls[0].webDir, "/tmp/fake-verification-home/workspace/web");
  assert.equal(dependencyInstalls[1].webDir, "/tmp/fake-build-home/workspace/web");
  assert.equal(dependencyInstalls[2].webDir, "/tmp/fake-upload-home/workspace/web");
  assert.equal(dependencyInstalls[2].env.HOME, "/tmp/fake-upload-home");
  assert.equal(
    Object.keys(dependencyInstalls[2].env).some((key) => key.startsWith("VITE_")),
    false,
  );
  for (const key of [
    "CLOUDFLARE_API_TOKEN",
    "PHALA_CLOUD_API_KEY",
    "OPENROUTER_API_KEY",
    "GITHUB_TOKEN",
  ]) {
    assert.equal(Object.prototype.hasOwnProperty.call(receivedBuildEnvironment, key), false);
    assert.equal(
      Object.prototype.hasOwnProperty.call(dependencyInstalls[2].env, key),
      false,
    );
  }
});

test("live runner preserves signed D and binds signed C to the fresh dist manifest", async () => {
  const events = [];
  const sourceRequests = [];
  let wranglerCalls = 0;
  const dependencies = {
    ...isolatedBuildTestDependencies(sourceRequests),
    releaseArguments: ["--release", "/tmp/release.json"],
    loadReleaseEnvironment: async () => LIVE_ENV,
    snapshotDeploymentInputs: async () => ({
      objectFormat: "sha1",
      headSha: SHA,
      gitTreeOid: GIT_TREE_OID,
      dirty: "",
      sourceSha256: "a".repeat(64),
      externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
    }),
    loadPrivateReleaseAudit: async () => ({
      fingerprintSha256: "e".repeat(64),
    }),
    validateRelease: async (args) => {
      events.push("validate-live");
      assert.deepEqual(args, ["--check-only", "--release", "/tmp/release.json"]);
      return semanticValidationReceipt(
        SHA,
        serializeEnv(LIVE_ENV),
        LIVE_AUTHORITY_BINDING,
      );
    },
    verify: async () => { events.push("verify"); },
    createBuildHome: async () => "/tmp/fake-live-build-home",
    removeBuildHome: async () => {},
    build: async () => { events.push("build"); },
    auditBuild: async ({ distDir }) => {
      events.push(distDir.includes("fake-live-stage") ? "audit-stage" : "audit-build");
      return { manifestSha256: SIGNED_DIST_MANIFEST, fileCount: 3, totalBytes: 100 };
    },
    auditStage: async ({ privateReleaseAudit }) => {
      events.push("audit-bundle");
      assert.equal(privateReleaseAudit?.fingerprintSha256, "e".repeat(64));
      return { bundleManifestSha256: "c".repeat(64) };
    },
    stageBundle: async () => {
      events.push("stage");
      return "/tmp/fake-live-stage";
    },
    removeStage: async () => { events.push("remove-stage"); },
    invokeWrangler: async (args) => {
      wranglerCalls += 1;
      events.push("wrangler");
      assert.deepEqual(args.slice(-5), [
        "--branch",
        CLOUDFLARE_PRODUCTION_BRANCH,
        "--commit-hash",
        SHA,
        "--commit-dirty=false",
      ]);
    },
    output: () => {},
    sensitiveEnv: {},
    controlEnv: {},
  };
  const result = await runCloudflareDeployment(dependencies);
  assert.equal(
    result.policy.semanticAuthority.frontendBuildCandidateReceiptSha256,
    LIVE_AUTHORITY_BINDING.frontendBuildCandidateReceiptSha256,
  );
  assert.equal(result.policy.frontendBuildSha256, `sha256:${SIGNED_DIST_MANIFEST}`);
  assert.deepEqual(result.buildSource, {
    sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
    sourceCommitSha: SHA,
    expectedGitTreeOid: GIT_TREE_OID,
  });
  assert.equal(wranglerCalls, 1);
  assert.equal(sourceRequests.length, 8);
  for (const request of sourceRequests) {
    assert.deepEqual(request, {
      operation: request.operation,
      sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
      sourceCommitSha: SHA,
      expectedGitTreeOid: GIT_TREE_OID,
    });
  }
  assert.deepEqual(events, [
    "validate-live",
    "verify",
    "build",
    "audit-build",
    "stage",
    "audit-stage",
    "audit-bundle",
    "audit-stage",
    "audit-bundle",
    "wrangler",
    "remove-stage",
  ]);

  events.length = 0;
  wranglerCalls = 0;
  await assert.rejects(
    runCloudflareDeployment({
      ...isolatedBuildTestDependencies(),
      ...dependencies,
      auditBuild: async () => {
        events.push("audit-build");
        return { manifestSha256: "d".repeat(64), fileCount: 3, totalBytes: 100 };
      },
    }),
    /does not match the signed live activation frontend build/,
  );
  assert.equal(wranglerCalls, 0);
  assert.deepEqual(events, ["validate-live", "verify", "build", "audit-build"]);
});

test("live immutable Git materialization has no working-tree fallback and fails before install or upload", async () => {
  const events = [];
  let wranglerCalls = 0;
  await assert.rejects(
    runCloudflareDeployment({
      ...isolatedBuildTestDependencies(),
      releaseArguments: ["--release", "/tmp/release.json"],
      loadReleaseEnvironment: async () => LIVE_ENV,
      snapshotDeploymentInputs: async () => ({
        ...snapshot(),
        dirty: "",
      }),
      loadPrivateReleaseAudit: async () => ({
        fingerprintSha256: "e".repeat(64),
      }),
      validateRelease: async () => semanticValidationReceipt(
        SHA,
        serializeEnv(LIVE_ENV),
        LIVE_AUTHORITY_BINDING,
      ),
      createBuildWorkspace: async ({
        sourceKind,
        sourceCommitSha,
        expectedGitTreeOid,
      }) => {
        events.push("materialize");
        assert.equal(sourceKind, CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT);
        assert.equal(sourceCommitSha, SHA);
        assert.equal(expectedGitTreeOid, GIT_TREE_OID);
        throw new Error("immutable Git object is unavailable");
      },
      installBuildDependencies: async () => { events.push("install"); },
      verify: async () => { events.push("verify"); },
      build: async () => { events.push("build"); },
      invokeWrangler: async () => { wranglerCalls += 1; },
      output: () => {},
      sensitiveEnv: {},
      controlEnv: {},
    }),
    /immutable Git object is unavailable/,
  );
  assert.deepEqual(events, ["materialize"]);
  assert.equal(wranglerCalls, 0);
});

test("current O-derived D without signed C reaches neither build authority nor Wrangler", async () => {
  const events = [];
  let wranglerCalls = 0;
  await assert.rejects(
    runCloudflareDeployment({
      releaseArguments: [
        "--release",
        "/tmp/release.json",
        "--compute-workload-activation-observation",
        "/tmp/private-compute-workload-activation-observation.json",
      ],
      loadReleaseEnvironment: async () => LIVE_ENV,
      snapshotDeploymentInputs: async () => ({
        objectFormat: "sha1",
        headSha: SHA,
        gitTreeOid: GIT_TREE_OID,
        dirty: "",
        sourceSha256: "a".repeat(64),
        externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
      }),
      loadPrivateReleaseAudit: async () => ({
        fingerprintSha256: "e".repeat(64),
      }),
      validateRelease: async () => {
        events.push("validate-live");
        return {
          schema: FRONTEND_BUILD_CANDIDATE_SCHEMA,
          status: FRONTEND_BUILD_CANDIDATE_STATUS,
          truth_status: FRONTEND_BUILD_CANDIDATE_TRUTH_STATUS,
          release_sha: SHA,
          chain_id: 84_532,
          deployment_intent_sha256:
            LIVE_AUTHORITY_BINDING.deploymentIntentSha256,
          reviewer_authority_genesis_acceptance_sha256:
            LIVE_AUTHORITY_BINDING.reviewerAuthorityGenesisAcceptanceSha256,
          ceremony_authorization_sha256:
            LIVE_AUTHORITY_BINDING.ceremonyAuthorizationSha256,
          runtime_authority_dependency_sha256:
            LIVE_AUTHORITY_BINDING.runtimeAuthorityDependencySha256,
          compute_workload_activation_observation_sha256:
            LIVE_AUTHORITY_BINDING.computeWorkloadActivationObservationSha256,
          frontend_build_sha256: LIVE_AUTHORITY_BINDING.frontendBuildSha256,
          release_inputs_sha256: LIVE_AUTHORITY_BINDING.releaseInputsSha256,
          release_env_sha256: `sha256:${"c1".repeat(32)}`,
          raw_secret_egress: false,
        };
      },
      build: async () => { events.push("build"); },
      auditBuild: async () => { events.push("audit-build"); },
      stageBundle: async () => { events.push("stage"); },
      invokeWrangler: async () => {
        wranglerCalls += 1;
        events.push("wrangler");
      },
      output: () => {},
      sensitiveEnv: {},
      controlEnv: {},
    }),
    /unexpected shape/,
  );
  assert.equal(wranglerCalls, 0);
  assert.deepEqual(events, ["validate-live"]);
});

test("live runner rejects private authority input drift before build or upload", async () => {
  const events = [];
  let reads = 0;
  let wranglerCalls = 0;
  await assert.rejects(
    runCloudflareDeployment({
      releaseArguments: ["--release", "/tmp/release.json"],
      loadReleaseEnvironment: async () => LIVE_ENV,
      snapshotDeploymentInputs: async () => ({
        objectFormat: "sha1",
        headSha: SHA,
        gitTreeOid: GIT_TREE_OID,
        dirty: "",
        sourceSha256: "a".repeat(64),
        externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
      }),
      loadPrivateReleaseAudit: async () => {
        reads += 1;
        return { fingerprintSha256: (reads === 1 ? "e" : "f").repeat(64) };
      },
      validateRelease: async () => {
        events.push("validate-live");
        return semanticValidationReceipt(
          SHA,
          serializeEnv(LIVE_ENV),
          LIVE_AUTHORITY_BINDING,
        );
      },
      build: async () => { events.push("build"); },
      invokeWrangler: async () => {
        wranglerCalls += 1;
      },
      output: () => {},
      sensitiveEnv: {},
      controlEnv: {},
    }),
    /private release authority inputs changed during authority validation/,
  );
  assert.equal(wranglerCalls, 0);
  assert.deepEqual(events, ["validate-live"]);
});

test("full verification fails closed on source or O-derived environment mutation", async (context) => {
  await context.test("source mutation", async () => {
    let snapshots = 0;
    const setup = successfulDependencies({
      snapshotDeploymentInputs: async () => {
        snapshots += 1;
        return snapshot(snapshots >= 3 ? "c".repeat(64) : "a".repeat(64));
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /source changed during the full release verification; upload was not attempted/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("Git tree provenance mutation", async () => {
    let snapshots = 0;
    const setup = successfulDependencies({
      snapshotDeploymentInputs: async () => {
        snapshots += 1;
        return {
          ...snapshot(),
          gitTreeOid: snapshots >= 3
            ? `sha1:${"3".repeat(40)}`
            : GIT_TREE_OID,
        };
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /source changed during the full release verification; upload was not attempted/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("O-derived public environment mutation", async () => {
    let environmentReads = 0;
    const setup = successfulDependencies({
      loadReleaseEnvironment: async () => {
        environmentReads += 1;
        return environmentReads >= 3
          ? { VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER: "0x2222222222222222222222222222222222222222" }
          : {};
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /environment changed during the full release verification; upload was not attempted/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("external build closure mutation", async () => {
    let snapshots = 0;
    const setup = successfulDependencies({
      snapshotDeploymentInputs: async () => {
        snapshots += 1;
        return {
          ...snapshot(),
          externalBuildClosureSha256: snapshots >= 3
            ? `sha256:${"8".repeat(64)}`
            : EXTERNAL_BUILD_CLOSURE_SHA256,
        };
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /source changed during the full release verification; upload was not attempted/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });
});

test("changing the private O artifact after C validation invokes Wrangler zero times", async () => {
  const events = [];
  let privateReads = 0;
  let wranglerCalls = 0;
  await assert.rejects(
    runCloudflareDeployment({
      ...isolatedBuildTestDependencies(),
      releaseArguments: [
        "--compute-workload-activation-observation",
        "/tmp/private-compute-workload-activation-observation.json",
      ],
      loadReleaseEnvironment: async () => LIVE_ENV,
      snapshotDeploymentInputs: async () => ({
        objectFormat: "sha1",
        headSha: SHA,
        gitTreeOid: GIT_TREE_OID,
        dirty: "",
        sourceSha256: "a".repeat(64),
        externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
      }),
      loadPrivateReleaseAudit: async () => {
        privateReads += 1;
        return {
          fingerprintSha256: (privateReads >= 3 ? "f" : "e").repeat(64),
        };
      },
      validateRelease: async () => {
        events.push("validate-live");
        return semanticValidationReceipt(
          SHA,
          serializeEnv(LIVE_ENV),
          LIVE_AUTHORITY_BINDING,
        );
      },
      verify: async () => { events.push("verify"); },
      createBuildHome: async () => "/tmp/fake-o-build-home",
      removeBuildHome: async () => {},
      build: async () => { events.push("build"); },
      invokeWrangler: async () => { wranglerCalls += 1; },
      output: () => {},
      sensitiveEnv: {},
      controlEnv: {},
    }),
    /private release authority inputs changed during the full release verification/,
  );
  assert.equal(wranglerCalls, 0);
  assert.deepEqual(events, ["validate-live", "verify"]);
});

test("control-environment drift fails before build and invokes Wrangler zero times", async () => {
  const setup = successfulDependencies({
    controlEnv: { CLOUDFLARE_BASE_URL: "https://attacker.invalid" },
  });
  await assert.rejects(
    runCloudflareDeployment(setup.dependencies),
    /CLOUDFLARE_BASE_URL control override/,
  );
  assert.equal(setup.wranglerCalls(), 0);
  assert.deepEqual(setup.events, []);
});

test("control environment cannot be redirected after validation, verification, build, or staging", async (context) => {
  await context.test("validator mutation", async () => {
    const controlEnv = {};
    const setup = successfulDependencies({
      controlEnv,
      validateRelease: async () => {
        controlEnv.CLOUDFLARE_API_BASE_URL = "https://attacker.invalid/client/v4";
        return semanticValidationReceipt(
          SHA,
          serializeEnv(LIVE_ENV),
          LIVE_AUTHORITY_BINDING,
        );
      },
      loadReleaseEnvironment: async () => LIVE_ENV,
      loadPrivateReleaseAudit: async () => ({ fingerprintSha256: "e".repeat(64) }),
      snapshotDeploymentInputs: async () => ({
        objectFormat: "sha1",
        headSha: SHA,
        gitTreeOid: GIT_TREE_OID,
        dirty: "",
        sourceSha256: "a".repeat(64),
        externalBuildClosureSha256: EXTERNAL_BUILD_CLOSURE_SHA256,
      }),
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /CLOUDFLARE_API_BASE_URL control override/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, []);
  });

  await context.test("verification mutation", async () => {
    const controlEnv = {};
    const setup = successfulDependencies({
      controlEnv,
      verify: async () => {
        setup.events.push("verify");
        controlEnv.CLOUDFLARE_API_BASE_URL = "https://attacker.invalid/client/v4";
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /CLOUDFLARE_API_BASE_URL control override/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("build mutation", async () => {
    const controlEnv = {};
    const setup = successfulDependencies({
      controlEnv,
      build: async () => {
        setup.events.push("build");
        controlEnv.HTTPS_PROXY = "https://attacker.invalid";
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /HTTPS_PROXY control override/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify", "build"]);
  });

  await context.test("staging mutation", async () => {
    const controlEnv = {};
    const setup = successfulDependencies({
      controlEnv,
      stageBundle: async () => {
        setup.events.push("stage");
        controlEnv.WRANGLER_TOKEN_URL = "https://attacker.invalid/oauth2/token";
        return "/tmp/fake-stage";
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /WRANGLER_TOKEN_URL control override/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "remove-stage",
    ]);
  });
});

test("source mutation during the fresh build fails before audit, staging, or Wrangler", async () => {
  let snapshots = 0;
  const setup = successfulDependencies({
    snapshotDeploymentInputs: async () => {
      snapshots += 1;
      return snapshot(snapshots >= 5 ? "c".repeat(64) : "a".repeat(64));
    },
  });
  await assert.rejects(
    runCloudflareDeployment(setup.dependencies),
    /source changed during the fresh build; upload was not attempted/,
  );
  assert.equal(setup.wranglerCalls(), 0);
  assert.deepEqual(setup.events, ["verify", "build"]);
});

test("VITE environment mutation during the fresh build fails before Wrangler", async () => {
  let environmentReads = 0;
  const setup = successfulDependencies({
    loadReleaseEnvironment: async () => {
      environmentReads += 1;
      return environmentReads >= 5 ? { VITE_UNREVIEWED_VALUE: "changed" } : {};
    },
  });
  await assert.rejects(
    runCloudflareDeployment(setup.dependencies),
    /environment changed during the fresh build; upload was not attempted/,
  );
  assert.equal(setup.wranglerCalls(), 0);
  assert.deepEqual(setup.events, ["verify", "build"]);
});

test("artifact audits include sensitive values loaded from production env files", async () => {
  const secret = "production-env-secret-value";
  const auditedSensitiveEnvironments = [];
  const setup = successfulDependencies({
    loadReleaseEnvironment: async () => ({ OPENROUTER_API_KEY: secret }),
    auditBuild: async ({ distDir, sensitiveEnv }) => {
      auditedSensitiveEnvironments.push(sensitiveEnv);
      setup.events.push(distDir.includes("fake-stage") ? "audit-stage" : "audit-build");
      return { manifestSha256: "b".repeat(64), fileCount: 3, totalBytes: 100 };
    },
    auditStage: async ({ sensitiveEnv }) => {
      auditedSensitiveEnvironments.push(sensitiveEnv);
      setup.events.push("audit-bundle");
      return { bundleManifestSha256: "c".repeat(64) };
    },
  });
  await runCloudflareDeployment(setup.dependencies);
  assert.equal(setup.wranglerCalls(), 1);
  assert.equal(auditedSensitiveEnvironments.length, 5);
  for (const environment of auditedSensitiveEnvironments) {
    assert.equal(environment.OPENROUTER_API_KEY, secret);
  }
});

test("verification, build, audit, or staged-manifest failure never invokes Wrangler and cleans private state", async (context) => {
  await context.test("full verification failure destroys its isolated HOME before any build HOME exists", async () => {
    const events = [];
    let wranglerCalls = 0;
    await assert.rejects(
      runCloudflareDeployment({
        ...successfulDependencies().dependencies,
        verify: async () => {
          events.push("verify");
          throw new Error("full verification failed");
        },
        createVerificationHome: async () => {
          events.push("create-verification-home");
          return "/tmp/fake-failing-verification-home";
        },
        removeVerificationHome: async (home) => {
          assert.equal(home, "/tmp/fake-failing-verification-home");
          events.push("remove-verification-home");
        },
        build: async () => { events.push("build"); },
        invokeWrangler: async () => { wranglerCalls += 1; },
      }),
      /full verification failed/,
    );
    assert.equal(wranglerCalls, 0);
    assert.deepEqual(events, [
      "create-verification-home",
      "verify",
      "remove-verification-home",
    ]);
  });

  await context.test("build failure", async () => {
    const setup = successfulDependencies({
      build: async () => { throw new Error("build failed"); },
    });
    await assert.rejects(runCloudflareDeployment(setup.dependencies), /build failed/);
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify"]);
  });

  await context.test("artifact audit failure", async () => {
    const setup = successfulDependencies({
      auditBuild: async () => { throw new Error("artifact rejected"); },
    });
    await assert.rejects(runCloudflareDeployment(setup.dependencies), /artifact rejected/);
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify", "build"]);
  });

  await context.test("staged manifest mismatch", async () => {
    let audits = 0;
    const setup = successfulDependencies({
      auditBuild: async () => {
        audits += 1;
        return {
          manifestSha256: (audits === 1 ? "a" : "b").repeat(64),
          fileCount: 3,
          totalBytes: 100,
        };
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /staged bundle does not match/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, ["verify", "build", "stage", "remove-stage"]);
  });

  await context.test("fresh Wrangler dependency install failure removes its isolated HOME", async () => {
    let installs = 0;
    const setup = successfulDependencies({
      createUploadHome: async () => {
        setup.events.push("create-upload-home");
        return "/tmp/fake-failing-upload-home";
      },
      removeUploadHome: async (home) => {
        assert.equal(home, "/tmp/fake-failing-upload-home");
        setup.events.push("remove-upload-home");
      },
      installBuildDependencies: async () => {
        installs += 1;
        if (installs === 3) throw new Error("fresh Wrangler install failed");
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /fresh Wrangler install failed/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "create-upload-home",
      "remove-upload-home",
      "remove-stage",
    ]);
  });

  await context.test("staged dist changes after its first complete audit", async () => {
    let audits = 0;
    const setup = successfulDependencies({
      auditBuild: async ({ distDir }) => {
        audits += 1;
        setup.events.push(distDir.includes("fake-stage") ? "audit-stage" : "audit-build");
        return {
          manifestSha256: (audits < 3 ? "a" : "b").repeat(64),
          fileCount: 3,
          totalBytes: 100,
        };
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /staged dist changed after validation/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "audit-stage",
      "remove-stage",
    ]);
  });

  await context.test("staged upload tree changes after its first complete audit", async () => {
    let bundleAudits = 0;
    const setup = successfulDependencies({
      auditStage: async () => {
        bundleAudits += 1;
        setup.events.push("audit-bundle");
        return {
          bundleManifestSha256: (bundleAudits === 1 ? "c" : "d").repeat(64),
          distManifestSha256: "b".repeat(64),
        };
      },
    });
    await assert.rejects(
      runCloudflareDeployment(setup.dependencies),
      /staged upload tree changed after validation/,
    );
    assert.equal(setup.wranglerCalls(), 0);
    assert.deepEqual(setup.events, [
      "verify",
      "build",
      "audit-build",
      "stage",
      "audit-stage",
      "audit-bundle",
      "audit-stage",
      "audit-bundle",
      "remove-stage",
    ]);
  });
});
