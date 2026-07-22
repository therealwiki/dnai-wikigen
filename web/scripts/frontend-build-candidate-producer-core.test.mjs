import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
} from "./cloudflare-build-sandbox-core.mjs";
import {
  CLOUDFLARE_D_BUILD_CONTROL_PATHS,
} from "./cloudflare-release-artifact-core.mjs";
import {
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
  CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
  CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  __test as closureTest,
  cloudflareExternalBuildClosureSha256,
  normalizeCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  __test as deployRunnerTest,
} from "./deploy-cloudflare.mjs";
import {
  FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS,
  FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS,
  createFrontendBuildPreDPrivateInputs,
} from "./frontend-build-candidate-core.mjs";
import {
  __test,
  runFrontendBuildCandidateProduction,
} from "./frontend-build-candidate-producer-core.mjs";
import {
  __test as releaseEnvTest,
  serializeEnv,
} from "./release-env-core.mjs";

const RELEASE_SHA = "a".repeat(40);
const pin = (label) => `sha256:${createHash("sha256")
  .update(`producer-test:${label}`, "utf8")
  .digest("hex")}`;
const qvlRoots = [1, 2, 3, 4, 5]
  .map((value) => `0x${value.toString(16).padStart(40, "0")}`);
const INSTALLED_DEPENDENCY_PROOF = Object.freeze({
  schema: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
  truth_status: CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
  packageCount: 498,
  sha256: pin("installed-dependency-tree"),
});

function withExternalClosureAggregate(value) {
  const payload = {
    schema: value.schema,
    truth_status: value.truth_status,
    entrypoints: value.entrypoints,
    files: value.files,
    raw_secret_egress: value.raw_secret_egress,
  };
  return {
    ...value,
    aggregate_sha256: `sha256:${createHash("sha256")
      .update(closureTest.AGGREGATE_DOMAIN, "utf8")
      .update("\0", "ascii")
      .update(`${JSON.stringify(payload, null, 2)}\n`, "utf8")
      .digest("hex")}`,
  };
}

function externalClosure() {
  return normalizeCloudflareExternalBuildClosure(withExternalClosureAggregate({
    schema: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_SCHEMA,
    truth_status: CLOUDFLARE_EXTERNAL_BUILD_CLOSURE_TRUTH_STATUS,
    entrypoints: CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS.map(({ kind, path }) => ({
      kind,
      path,
    })),
    files: CLOUDFLARE_EXTERNAL_BUILD_FILES.map(({ kind, path }, index) => ({
      kind,
      path,
      mode: 0o600,
      size: index + 1,
      sha256: pin(`external:${index}`),
    })),
    aggregate_sha256: pin("ignored"),
    raw_secret_egress: false,
  }));
}

function projection() {
  const env = Object.fromEntries(
    releaseEnvTest.ENV_KEYS.map((key) => [key, ""]),
  );
  env.VITE_RELEASE_SHA = RELEASE_SHA;
  const semanticLineage = Object.fromEntries(
    FRONTEND_BUILD_SEMANTIC_LINEAGE_FIELDS.map((field) => [
      field,
      pin(`lineage:${field}`),
    ]),
  );
  const authorityRoots = {
    contract_release_set_sha256:
      semanticLineage.fresh_contract_deployment_receipt_sha256,
    cvm_release_set_sha256:
      semanticLineage.seven_cvm_launch_completion_receipt_sha256,
    qvl_measurement_policy_set_sha256:
      semanticLineage.qvl_measurement_policy_set_sha256,
  };
  const preDPrivateInputs = createFrontendBuildPreDPrivateInputs({
    liveCandidatePrebuildProjectionSha256: pin("private:release"),
    rawSha256ByFlag: Object.fromEntries(
      FRONTEND_BUILD_RAW_PRIVATE_INPUT_FLAGS.map((flag) => [
        flag,
        pin(`private:${flag}`),
      ]),
    ),
  });
  return {
    releaseSha: RELEASE_SHA,
    env,
    serializedEnv: serializeEnv(env),
    preDPrivateInputs,
    semanticLineage,
    primaryRpcUrl: "https://sepolia.base.org",
    secondaryRpcUrl: "https://base-sepolia-rpc.publicnode.com",
    qvlVerifierRoots: qvlRoots,
    authorityRoots,
    authorityBinding: {
      deploymentIntentSha256: semanticLineage.deployment_intent_sha256,
      reviewerAuthorityGenesisAcceptanceSha256:
        semanticLineage.reviewer_authority_genesis_acceptance_sha256,
      ceremonyAuthorizationSha256:
        semanticLineage.ceremony_authorization_sha256,
      runtimeAuthorityDependencySha256:
        semanticLineage.runtime_authority_dependency_sha256,
      computeWorkloadActivationObservationSha256:
        semanticLineage.compute_workload_activation_observation_sha256,
    },
  };
}

function snapshot() {
  const closure = externalClosure();
  return {
    headSha: RELEASE_SHA,
    dirty: "",
    gitTreeOid: `sha1:${"b".repeat(40)}`,
    sourceFingerprintSha256: pin("source"),
    uploadControlManifestSha256: pin("upload-controls"),
    buildControls: CLOUDFLARE_D_BUILD_CONTROL_PATHS.map((controlPath) => ({
      path: controlPath,
      sha256: pin(`control:${controlPath}`),
    })),
    externalBuildClosure: closure,
    externalBuildClosureSha256: cloudflareExternalBuildClosureSha256(closure),
  };
}

function privateAudit(value = projection()) {
  return {
    fingerprintSha256: pin("private-audit"),
    inputs: value.preDPrivateInputs
      .map(({ flag, sha256 }) => ({ flag, content_sha256: sha256.slice(7) }))
      .sort((left, right) => left.flag.localeCompare(right.flag, "en")),
  };
}

function dependencies(overrides = {}) {
  const semantic = projection();
  const source = snapshot();
  const audit = privateAudit(semantic);
  const events = [];
  let snapshots = 0;
  let privateAudits = 0;
  const values = {
    releaseArguments: ["--release", "/private/prebuild-release.json"],
    loadSemanticProjection: async () => semantic,
    snapshotCandidateInputs: async () => {
      snapshots += 1;
      return source;
    },
    loadPrivateInputAudit: async () => {
      privateAudits += 1;
      return audit;
    },
    createVerificationHome: async () => {
      events.push("verification-home:create");
      return "/private/tmp/dnai-verification-home";
    },
    removeVerificationHome: async () => {
      events.push("verification-home:remove");
    },
    createBuildHome: async () => {
      events.push("build-home:create");
      return "/private/tmp/dnai-build-home";
    },
    removeBuildHome: async () => {
      events.push("build-home:remove");
    },
    createBuildWorkspace: async ({ buildRoot }) => ({
      rootDir: `${buildRoot}/workspace`,
      webDir: `${buildRoot}/workspace/web`,
    }),
    createBuildSandbox: async ({ buildRoot }) => ({ profile: `test-profile:${buildRoot}` }),
    assertBuildSandboxIsolation: async ({ buildRoot }) => {
      events.push(buildRoot.includes("verification")
        ? "verification-sandbox:proved"
        : "build-sandbox:proved");
    },
    installBuildDependencies: async ({ webDir }) => {
      events.push(webDir.includes("verification")
        ? "verification:install"
        : "build:install");
    },
    projectInstalledDependencyTree: async () => INSTALLED_DEPENDENCY_PROOF,
    assertBuildWorkspaceIntegrity: async ({ workspace }) => {
      events.push(workspace.webDir.includes("verification")
        ? "verification-workspace:checked"
        : "build-workspace:checked");
    },
    verify: async () => {
      events.push("verify");
    },
    build: async () => {
      events.push("build");
    },
    auditBuild: async ({ mode, releaseSha, privateReleaseAudit }) => {
      events.push("audit");
      assert.equal(mode, "candidate");
      assert.equal(releaseSha, RELEASE_SHA);
      assert.equal(privateReleaseAudit, audit);
      return {
        manifestSha256: pin("dist").slice(7),
        fileCount: 5,
        totalBytes: 1024,
      };
    },
    assertReleaseRuntime: () => deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
    sensitiveEnv: {},
    buildHostEnv: {},
    ...overrides,
  };
  return {
    values,
    events,
    semantic,
    source,
    audit,
    counters: () => ({ snapshots, privateAudits }),
  };
}

test("D producer runs exact35 -> isolated verify -> independent fresh build -> audit with no upload hook", async () => {
  const fixture = dependencies();
  assert.equal("invokeWrangler" in fixture.values, false);
  const result = await runFrontendBuildCandidateProduction(fixture.values);
  assert.deepEqual(fixture.events, [
    "verification-home:create",
    "verification-sandbox:proved",
    "verification:install",
    "verification-workspace:checked",
    "verify",
    "verification-workspace:checked",
    "verification-home:remove",
    "build-home:create",
    "build-sandbox:proved",
    "build:install",
    "build-workspace:checked",
    "build",
    "build-workspace:checked",
    "audit",
    "build-home:remove",
  ]);
  assert.deepEqual(fixture.counters(), { snapshots: 4, privateAudits: 4 });
  assert.equal(result.receipt.release_sha, RELEASE_SHA);
  assert.equal(result.receipt.frontend_build_sha256, pin("dist"));
  assert.equal(result.receipt.release_env_sha256,
    result.inputManifest.projected_env_sha256);
  assert.equal(result.serializedEnv, fixture.semantic.serializedEnv);
  assert.equal(result.inputManifest.git_source.source_fingerprint_sha256,
    fixture.source.sourceFingerprintSha256);
  assert.deepEqual(result.inputManifest.build_controls,
    fixture.source.buildControls);
  assert.equal(result.privateInputAuditFingerprintSha256,
    fixture.audit.fingerprintSha256);
  assert.deepEqual(result.installedDependencyProof, INSTALLED_DEPENDENCY_PROOF);
});

test("D producer rejects projection extras and private-byte drift before creating a HOME", async () => {
  {
    const fixture = dependencies();
    fixture.semantic.unreviewed = true;
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /exact frozen shape/,
    );
    assert.deepEqual(fixture.events, []);
  }
  {
    const fixture = dependencies();
    fixture.audit.inputs[0].content_sha256 = "f".repeat(64);
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /does not match the exact scanned private input bytes/,
    );
    assert.deepEqual(fixture.events, []);
  }
});

test("D producer rejects source or private-input mutation before the fresh build", async () => {
  {
    const fixture = dependencies();
    let call = 0;
    fixture.values.snapshotCandidateInputs = async () => {
      call += 1;
      return call === 2
        ? { ...fixture.source, sourceFingerprintSha256: pin("mutated-source") }
        : fixture.source;
    };
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /inputs changed during full verification/,
    );
    assert.equal(fixture.events.includes("build"), false);
    assert.equal(fixture.events.at(-1), "verification-home:remove");
  }
  {
    const fixture = dependencies();
    let call = 0;
    fixture.values.loadPrivateInputAudit = async () => {
      call += 1;
      return call === 2
        ? { ...fixture.audit, fingerprintSha256: pin("mutated-private-audit") }
        : fixture.audit;
    };
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /private inputs changed during full verification/,
    );
    assert.equal(fixture.events.includes("build"), false);
    assert.equal(fixture.events.at(-1), "verification-home:remove");
  }
});

test("check-generated workspace or dependency mutation cannot flow into the build workspace", async () => {
  {
    const fixture = dependencies();
    let checkRan = false;
    fixture.values.verify = async () => {
      fixture.events.push("verify");
      checkRan = true;
    };
    fixture.values.assertBuildWorkspaceIntegrity = async ({ workspace }) => {
      fixture.events.push(workspace.webDir.includes("verification")
        ? "verification-workspace:checked"
        : "build-workspace:checked");
      if (checkRan && workspace.webDir.includes("verification")) {
        throw new Error("verification workspace source mutated by check");
      }
    };
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /verification workspace source mutated by check/,
    );
    assert.equal(fixture.events.includes("build-home:create"), false);
    assert.equal(fixture.events.at(-1), "verification-home:remove");
  }
  {
    const fixture = dependencies();
    let dependencyReads = 0;
    fixture.values.projectInstalledDependencyTree = async () => {
      dependencyReads += 1;
      return dependencyReads === 2
        ? { ...INSTALLED_DEPENDENCY_PROOF, sha256: pin("check-mutated-dependencies") }
        : INSTALLED_DEPENDENCY_PROOF;
    };
    await assert.rejects(
      runFrontendBuildCandidateProduction(fixture.values),
      /dependency tree changed during full verification/,
    );
    assert.equal(fixture.events.includes("build-home:create"), false);
    assert.equal(fixture.events.at(-1), "verification-home:remove");
  }
});

test("D producer requires distinct verification and artifact-build HOMEs", async () => {
  const fixture = dependencies({
    createBuildHome: async () => {
      fixture.events.push("build-home:create");
      return "/private/tmp/dnai-verification-home";
    },
  });
  await assert.rejects(
    runFrontendBuildCandidateProduction(fixture.values),
    /verification and build HOMEs must be distinct/,
  );
  assert.equal(fixture.events.at(-1), "build-home:remove");
  assert.equal(fixture.events.includes("build"), false);
});

test("D producer re-pins runtime immediately before build and always cleans private state", async () => {
  const fixture = dependencies();
  let runtimeCalls = 0;
  fixture.values.assertReleaseRuntime = () => {
    runtimeCalls += 1;
    if (runtimeCalls === 8) {
      return {
        ...deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF,
        npmTreeSha256: "f".repeat(64),
      };
    }
    return deployRunnerTest.PINNED_RELEASE_RUNTIME_PROOF;
  };
  await assert.rejects(
    runFrontendBuildCandidateProduction(fixture.values),
    /release runtime changed before the fresh candidate build/,
  );
  assert.equal(fixture.events.includes("build"), false);
  assert.equal(fixture.events.at(-1), "build-home:remove");
});

test("D producer freezes its exact Git/runtime/semantic API contract", () => {
  assert.equal(__test.PINNED_GIT_EXECUTABLE, "/usr/bin/git");
  assert.deepEqual(__test.PINNED_GIT_ENVIRONMENT, {
    PATH: "/usr/bin:/bin",
    LANG: "C",
    LC_ALL: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_OPTIONAL_LOCKS: "0",
  });
  assert.deepEqual(__test.SEMANTIC_PROJECTION_FIELDS, [
    "authorityBinding",
    "authorityRoots",
    "env",
    "preDPrivateInputs",
    "primaryRpcUrl",
    "qvlVerifierRoots",
    "releaseSha",
    "secondaryRpcUrl",
    "semanticLineage",
    "serializedEnv",
  ]);
  assert.deepEqual(__test.RECEIPT_AUTHORITY_BINDING_FIELDS, [
    "ceremonyAuthorizationSha256",
    "computeWorkloadActivationObservationSha256",
    "deploymentIntentSha256",
    "reviewerAuthorityGenesisAcceptanceSha256",
    "runtimeAuthorityDependencySha256",
  ]);
  assert.deepEqual(__test.INSTALLED_DEPENDENCY_PROOF_FIELDS, [
    "packageCount",
    "schema",
    "sha256",
    "truth_status",
  ]);
});
