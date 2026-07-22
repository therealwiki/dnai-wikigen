#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { loadEnv } from "vite";
import { main as validateReleaseEnvironment } from "./build-release-env.mjs";
import {
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA,
  CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS,
  assertCloudflareBuildSandboxIsolation,
  assertCloudflareBuildWorkspaceIntegrity,
  cloudflareBuildSandbox,
  createIsolatedCloudflareBuildWorkspace,
  installCloudflareBuildDependencies,
  projectCloudflareInstalledDependencyTree,
  runCloudflareBuildNpmScript,
} from "./cloudflare-build-sandbox-core.mjs";
import {
  cloudflareExternalBuildClosureSha256,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  auditCloudflareBuild,
  auditCloudflareStage,
  cloudflareSourceFingerprint,
  cloudflareUploadControlFingerprint,
  deploymentViteEnvironmentDigest,
  loadPrivateReleaseArtifactAudit,
  removeCloudflareStage,
  stageCloudflareBundle,
} from "./cloudflare-release-artifact-core.mjs";
import {
  assertCloudflareControlEnvironment,
  cloudflareBuildEnvironment,
  cloudflareReleaseIntent,
  cloudflareWranglerEnvironment,
  prepareCloudflareDeployment,
} from "./deploy-cloudflare-core.mjs";
import {
  PINNED_NODE_RUNTIME,
  PINNED_NPM_RUNTIME,
  PINNED_RELEASE_RUNTIME_PROOF,
  assertPinnedReleaseRuntime,
  normalizePinnedReleaseRuntimeProof,
} from "./release-runtime-pins-core.mjs";
import {
  createPrivateReleaseBuildHome,
  removePrivateReleaseBuildHome,
} from "./release-build-home-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rootDir = path.resolve(webDir, "..");
const RELEASE_GIT_PATH = "/usr/bin/git";
const RELEASE_GIT_ENV = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
});
const PINNED_WRANGLER_RUNTIME = Object.freeze({
  version: "4.110.0",
  packageJsonSha256:
    "f625bdbdfd80b77c23d0e876ce1e12c3533384de33c131887652f7f1475c9793",
  cliSha256:
    "64e547d8912121a116f8109eacd3c4061e61499de32eb994df5ae62f2eb905dd",
});
const INSTALLED_DEPENDENCY_PROOF_FIELDS = Object.freeze([
  "packageCount",
  "schema",
  "sha256",
  "truth_status",
]);

function readPinnedRuntimeFile(filePath, expectedSha256, maximumBytes, label) {
  if (
    path.resolve(filePath) !== filePath
    || fs.realpathSync.native(filePath) !== filePath
  ) {
    throw new Error(`${label} path is aliased or noncanonical`);
  }
  const named = fs.lstatSync(filePath);
  const expectedUid = typeof process.geteuid === "function"
    ? process.geteuid()
    : named.uid;
  if (
    !named.isFile()
    || named.isSymbolicLink()
    || named.nlink !== 1
    || named.uid !== expectedUid
    || (named.mode & 0o022) !== 0
    || named.size < 2
    || named.size > maximumBytes
  ) {
    throw new Error(`${label} is not a bounded operator-owned non-shared-writable regular file`);
  }
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0),
  );
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (
      before.dev !== BigInt(named.dev)
      || before.ino !== BigInt(named.ino)
      || before.size !== BigInt(named.size)
    ) {
      throw new Error(`${label} changed while opening`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (
      before.dev !== after.dev
      || before.ino !== after.ino
      || before.size !== after.size
      || before.mtimeNs !== after.mtimeNs
      || before.ctimeNs !== after.ctimeNs
      || BigInt(bytes.length) !== before.size
    ) {
      throw new Error(`${label} changed during its bounded read`);
    }
    if (createHash("sha256").update(bytes).digest("hex") !== expectedSha256) {
      throw new Error(`${label} bytes do not match the reviewed release runtime`);
    }
    return bytes;
  } finally {
    fs.closeSync(descriptor);
  }
}

export function resolvePinnedWranglerCli(directory = webDir) {
  const packagePath = path.join(directory, "node_modules", "wrangler", "package.json");
  const cliPath = path.join(
    directory,
    "node_modules",
    "wrangler",
    "wrangler-dist",
    "cli.js",
  );
  let descriptor;
  try {
    descriptor = JSON.parse(readPinnedRuntimeFile(
      packagePath,
      PINNED_WRANGLER_RUNTIME.packageJsonSha256,
      128 * 1024,
      "Wrangler package descriptor",
    ).toString("utf8"));
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Wrangler ")) throw error;
    throw new Error("Wrangler package descriptor is not reviewed canonical JSON");
  }
  if (
    descriptor?.name !== "wrangler"
    || descriptor?.version !== PINNED_WRANGLER_RUNTIME.version
  ) {
    throw new Error("Wrangler package version does not match the reviewed release runtime");
  }
  readPinnedRuntimeFile(
    cliPath,
    PINNED_WRANGLER_RUNTIME.cliSha256,
    20 * 1024 * 1024,
    "Wrangler CLI",
  );
  return cliPath;
}

function git(args) {
  return execFileSync(RELEASE_GIT_PATH, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-C",
    rootDir,
    ...args,
  ], {
    encoding: "utf8",
    env: RELEASE_GIT_ENV,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function readEnvironment() {
  return { ...loadEnv("production", webDir, ""), ...process.env };
}

async function readDeploymentSnapshot() {
  const externalBuildClosure = await projectCloudflareExternalBuildClosure(rootDir);
  return Object.freeze({
    headSha: git(["rev-parse", "HEAD"]),
    dirty: git([
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
      "--ignore-submodules=none",
    ]),
    sourceSha256: await cloudflareSourceFingerprint(webDir),
    uploadControlManifestSha256: await cloudflareUploadControlFingerprint(webDir),
    externalBuildClosure,
    externalBuildClosureSha256:
      cloudflareExternalBuildClosureSha256(externalBuildClosure),
  });
}

function assertSameInputs(baseline, current, baselineEnvDigest, currentEnvDigest, checkpoint) {
  if (
    baseline.headSha !== current.headSha
    || baseline.dirty !== current.dirty
    || baseline.sourceSha256 !== current.sourceSha256
    || baseline.uploadControlManifestSha256
      !== current.uploadControlManifestSha256
    || !/^sha256:[0-9a-f]{64}$/.test(
      String(baseline.externalBuildClosureSha256 || ""),
    )
    || baseline.externalBuildClosureSha256
      !== current.externalBuildClosureSha256
  ) {
    throw new Error(`Cloudflare release source changed ${checkpoint}; upload was not attempted`);
  }
  if (baselineEnvDigest !== currentEnvDigest) {
    throw new Error(`Cloudflare release environment changed ${checkpoint}; upload was not attempted`);
  }
}

function assertSamePrivateReleaseArtifacts(baseline, current, checkpoint) {
  if (
    !baseline
    || !current
    || baseline.fingerprintSha256 !== current.fingerprintSha256
  ) {
    throw new Error(
      `private release authority inputs changed ${checkpoint}; upload was not attempted`,
    );
  }
}

function normalizeInstalledDependencyProof(value) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...INSTALLED_DEPENDENCY_PROOF_FIELDS].sort())
    || value.schema !== CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA
    || value.truth_status !== CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS
    || !Number.isSafeInteger(value.packageCount)
    || value.packageCount < 1
    || !/^sha256:[0-9a-f]{64}$/.test(String(value.sha256 || ""))
    || value.sha256 === `sha256:${"0".repeat(64)}`
  ) {
    throw new Error("Cloudflare installed dependency proof is invalid");
  }
  return Object.freeze({
    schema: value.schema,
    truth_status: value.truth_status,
    packageCount: value.packageCount,
    sha256: value.sha256,
  });
}

function assertSameInstalledDependencyProof(baseline, current, checkpoint) {
  const normalized = normalizeInstalledDependencyProof(current);
  if (JSON.stringify(normalized) !== JSON.stringify(baseline)) {
    throw new Error(
      `Cloudflare installed dependency tree changed ${checkpoint}; upload was not attempted`,
    );
  }
  return normalized;
}

function defaultBuild({ env, webDir: isolatedWebDir, sandbox }) {
  runCloudflareBuildNpmScript({
    sandbox,
    webDir: isolatedWebDir,
    env,
    script: "build",
  });
}

function defaultVerify({ env, webDir: isolatedWebDir, sandbox }) {
  runCloudflareBuildNpmScript({
    sandbox,
    webDir: isolatedWebDir,
    env,
    script: "check",
  });
}

export const defaultCreateBuildHome = createPrivateReleaseBuildHome;
export const defaultRemoveBuildHome = removePrivateReleaseBuildHome;

function defaultWrangler(args, cwd, runtime) {
  if (
    !runtime
    || typeof runtime !== "object"
    || typeof runtime.webDir !== "string"
    || !path.isAbsolute(runtime.webDir)
    || path.resolve(runtime.webDir) !== runtime.webDir
  ) {
    throw new Error("Wrangler requires a fresh isolated release runtime");
  }
  const cliPath = resolvePinnedWranglerCli(runtime.webDir);
  execFileSync(process.execPath, ["--no-warnings", cliPath, ...args], {
    cwd,
    env: cloudflareWranglerEnvironment(process.env),
    stdio: "inherit",
  });
}

export const __test = Object.freeze({
  PINNED_NODE_RUNTIME,
  PINNED_NPM_RUNTIME,
  PINNED_RELEASE_RUNTIME_PROOF,
  PINNED_WRANGLER_RUNTIME,
  RELEASE_GIT_ENV,
  RELEASE_GIT_PATH,
  defaultCreateBuildHome,
  defaultRemoveBuildHome,
  defaultWrangler,
  assertPinnedReleaseRuntime,
  normalizePinnedReleaseRuntimeProof,
});

/**
 * Build, audit, and upload one Pages release. Every effectful operation is
 * injectable so the fail-closed ordering can be tested without invoking
 * Wrangler or any external service.
 */
export async function runCloudflareDeployment({
  releaseArguments = process.argv.slice(2),
  loadReleaseEnvironment = readEnvironment,
  snapshotDeploymentInputs = readDeploymentSnapshot,
  validateRelease = validateReleaseEnvironment,
  verify = defaultVerify,
  build = defaultBuild,
  createBuildWorkspace = createIsolatedCloudflareBuildWorkspace,
  createBuildSandbox = cloudflareBuildSandbox,
  assertBuildSandboxIsolation = assertCloudflareBuildSandboxIsolation,
  assertBuildWorkspaceIntegrity = assertCloudflareBuildWorkspaceIntegrity,
  installBuildDependencies = installCloudflareBuildDependencies,
  projectInstalledDependencyTree = projectCloudflareInstalledDependencyTree,
  auditBuild = auditCloudflareBuild,
  auditStage = auditCloudflareStage,
  stageBundle = (sourceWebDir = webDir) => stageCloudflareBundle(sourceWebDir),
  loadPrivateReleaseAudit = loadPrivateReleaseArtifactAudit,
  removeStage = removeCloudflareStage,
  invokeWrangler = defaultWrangler,
  output = console.log,
  sensitiveEnv = process.env,
  controlEnv = process.env,
  buildHostEnv = process.env,
  createVerificationHome = defaultCreateBuildHome,
  removeVerificationHome = defaultRemoveBuildHome,
  createBuildHome = defaultCreateBuildHome,
  removeBuildHome = defaultRemoveBuildHome,
  createUploadHome = defaultCreateBuildHome,
  removeUploadHome = defaultRemoveBuildHome,
  assertReleaseRuntime = assertPinnedReleaseRuntime,
} = {}) {
  // Pin the interpreter before the first environment projection, AST closure
  // parse, or semantic authority call. A later pin cannot authenticate code
  // that already ran under a substituted runtime.
  const releaseRuntimeProof = normalizePinnedReleaseRuntimeProof(
    assertReleaseRuntime(),
  );
  const reverifyReleaseRuntime = (checkpoint) => {
    let current;
    try {
      current = normalizePinnedReleaseRuntimeProof(assertReleaseRuntime());
    } catch {
      throw new Error(`Cloudflare release runtime changed ${checkpoint}`);
    }
    if (JSON.stringify(current) !== JSON.stringify(releaseRuntimeProof)) {
      throw new Error(`Cloudflare release runtime changed ${checkpoint}`);
    }
    return current;
  };
  assertCloudflareControlEnvironment(controlEnv);
  const env = await loadReleaseEnvironment();
  assertCloudflareControlEnvironment(controlEnv);
  const releaseIntent = cloudflareReleaseIntent(env);
  const auditSensitiveEnv = { ...env, ...(sensitiveEnv || {}) };
  const envDigest = deploymentViteEnvironmentDigest(env);
  const baseline = await snapshotDeploymentInputs();
  const baselinePrivateReleaseAudit = releaseIntent === "live"
    ? await loadPrivateReleaseAudit(releaseArguments)
    : undefined;
  const policy = await prepareCloudflareDeployment({
    env,
    headSha: baseline.headSha,
    dirty: baseline.dirty,
    releaseArguments,
    validateReleaseEnvironment: validateRelease,
  });
  assertCloudflareControlEnvironment(controlEnv);

  const afterAuthority = await snapshotDeploymentInputs();
  const envAfterAuthority = await loadReleaseEnvironment();
  assertSameInputs(
    baseline,
    afterAuthority,
    envDigest,
    deploymentViteEnvironmentDigest(envAfterAuthority),
    "during authority validation",
  );
  if (policy.mode === "live") {
    assertSamePrivateReleaseArtifacts(
      baselinePrivateReleaseAudit,
      await loadPrivateReleaseAudit(releaseArguments),
      "during authority validation",
    );
  }
  reverifyReleaseRuntime("during authority validation");

  let installedDependencyProof;
  const verificationHome = await createVerificationHome();
  try {
    const verificationEnvironment = cloudflareBuildEnvironment(
      env,
      buildHostEnv,
      verificationHome,
    );
    reverifyReleaseRuntime("before the isolated verification workspace projection");
    const verificationWorkspace = await createBuildWorkspace({
      repositoryRoot: rootDir,
      buildRoot: verificationHome,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    const verificationSandbox = await createBuildSandbox({
      buildRoot: verificationHome,
    });
    await assertBuildSandboxIsolation({
      buildRoot: verificationHome,
      profile: verificationSandbox.profile,
      env: verificationEnvironment,
    });
    reverifyReleaseRuntime("before the isolated verification install");
    await installBuildDependencies({
      sandbox: verificationSandbox,
      webDir: verificationWorkspace.webDir,
      env: verificationEnvironment,
    });
    installedDependencyProof = normalizeInstalledDependencyProof(
      await projectInstalledDependencyTree(verificationWorkspace.webDir),
    );
    await assertBuildWorkspaceIntegrity({
      workspace: verificationWorkspace,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertCloudflareControlEnvironment(controlEnv);
    reverifyReleaseRuntime("before the full isolated verification");
    await verify({
      env: verificationEnvironment,
      webDir: verificationWorkspace.webDir,
      sandbox: verificationSandbox,
    });
    assertCloudflareControlEnvironment(controlEnv);
    await assertBuildWorkspaceIntegrity({
      workspace: verificationWorkspace,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(verificationWorkspace.webDir),
      "during full release verification",
    );
    const afterVerify = await snapshotDeploymentInputs();
    const envAfterVerify = await loadReleaseEnvironment();
    assertSameInputs(
      baseline,
      afterVerify,
      envDigest,
      deploymentViteEnvironmentDigest(envAfterVerify),
      "during the full release verification",
    );
    if (policy.mode === "live") {
      assertSamePrivateReleaseArtifacts(
        baselinePrivateReleaseAudit,
        await loadPrivateReleaseAudit(releaseArguments),
        "during the full release verification",
      );
    }
    reverifyReleaseRuntime("during the full isolated verification");
  } finally {
    await removeVerificationHome(verificationHome);
  }

  const buildHome = await createBuildHome();
  try {
    if (buildHome === verificationHome) {
      throw new Error("Cloudflare verification and artifact-build HOMEs must be distinct");
    }
    const buildEnvironment = cloudflareBuildEnvironment(env, buildHostEnv, buildHome);
    reverifyReleaseRuntime("before the isolated artifact-build workspace projection");
    const buildWorkspace = await createBuildWorkspace({
      repositoryRoot: rootDir,
      buildRoot: buildHome,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    const buildSandbox = await createBuildSandbox({ buildRoot: buildHome });
    await assertBuildSandboxIsolation({
      buildRoot: buildHome,
      profile: buildSandbox.profile,
      env: buildEnvironment,
    });
    reverifyReleaseRuntime("before the isolated artifact-build install");
    await installBuildDependencies({
      sandbox: buildSandbox,
      webDir: buildWorkspace.webDir,
      env: buildEnvironment,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(buildWorkspace.webDir),
      "between verification and the fresh artifact build",
    );
    await assertBuildWorkspaceIntegrity({
      workspace: buildWorkspace,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertCloudflareControlEnvironment(controlEnv);

    const beforeBuild = await snapshotDeploymentInputs();
    const envBeforeBuild = await loadReleaseEnvironment();
    assertSameInputs(
      baseline,
      beforeBuild,
      envDigest,
      deploymentViteEnvironmentDigest(envBeforeBuild),
      "before the fresh build",
    );
    if (policy.mode === "live") {
      assertSamePrivateReleaseArtifacts(
        baselinePrivateReleaseAudit,
        await loadPrivateReleaseAudit(releaseArguments),
        "before the fresh build",
      );
    }

    reverifyReleaseRuntime("before the fresh artifact build");
    await build({
      env: buildEnvironment,
      webDir: buildWorkspace.webDir,
      sandbox: buildSandbox,
    });
    assertCloudflareControlEnvironment(controlEnv);
    await assertBuildWorkspaceIntegrity({
      workspace: buildWorkspace,
      expectedSourceSha256: baseline.sourceSha256,
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256,
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(buildWorkspace.webDir),
      "during the fresh build",
    );

    const afterBuild = await snapshotDeploymentInputs();
    const envAfterBuild = await loadReleaseEnvironment();
    assertSameInputs(
      baseline,
      afterBuild,
      envDigest,
      deploymentViteEnvironmentDigest(envAfterBuild),
      "during the fresh build",
    );
    if (policy.mode === "live") {
      assertSamePrivateReleaseArtifacts(
        baselinePrivateReleaseAudit,
        await loadPrivateReleaseAudit(releaseArguments),
        "during the fresh build",
      );
    }
    reverifyReleaseRuntime("during the fresh artifact build");

    const releaseSha = policy.mode === "live" ? String(env.VITE_RELEASE_SHA || "") : "";
    const audit = await auditBuild({
      distDir: path.join(buildWorkspace.webDir, "dist"),
      env,
      mode: policy.mode,
      releaseSha,
      sensitiveEnv: auditSensitiveEnv,
      privateReleaseAudit: baselinePrivateReleaseAudit,
    });
    if (
      policy.mode === "live"
      && policy.frontendBuildSha256 !== `sha256:${audit.manifestSha256}`
    ) {
      throw new Error(
        "fresh Cloudflare dist manifest does not match the signed live activation frontend build",
      );
    }

    let stageDir;
    try {
      stageDir = await stageBundle(buildWorkspace.webDir);
      const stagedAudit = await auditBuild({
        distDir: path.join(stageDir, "dist"),
        env,
        mode: policy.mode,
        releaseSha,
        sensitiveEnv: auditSensitiveEnv,
        privateReleaseAudit: baselinePrivateReleaseAudit,
      });
      if (stagedAudit.manifestSha256 !== audit.manifestSha256) {
        throw new Error("Cloudflare staged bundle does not match the audited fresh build");
      }
      const stagedBundleAudit = await auditStage({
        stageDir,
        distAudit: stagedAudit,
        mode: policy.mode,
        sensitiveEnv: auditSensitiveEnv,
        privateReleaseAudit: baselinePrivateReleaseAudit,
      });
      if (
        stagedBundleAudit.uploadControlManifestSha256
          !== baseline.uploadControlManifestSha256
      ) {
        throw new Error(
          "Cloudflare staged release controls do not match the validated source snapshot",
        );
      }

      // Credentials enter only a third workspace. Neither the check tree nor
      // the artifact-build tree can become Wrangler's executable dependency
      // graph, and all three npm-ci projections must be byte-identical.
      const uploadHome = await createUploadHome();
      try {
        if (new Set([verificationHome, buildHome, uploadHome]).size !== 3) {
          throw new Error(
            "Cloudflare verification, artifact-build, and Wrangler HOMEs must be distinct",
          );
        }
        const uploadEnvironment = cloudflareBuildEnvironment({}, buildHostEnv, uploadHome);
        reverifyReleaseRuntime("before the isolated Wrangler workspace projection");
        const uploadWorkspace = await createBuildWorkspace({
          repositoryRoot: rootDir,
          buildRoot: uploadHome,
          expectedSourceSha256: baseline.sourceSha256,
          expectedUploadControlManifestSha256:
            baseline.uploadControlManifestSha256,
          expectedExternalBuildClosure: baseline.externalBuildClosure,
        });
        const uploadSandbox = await createBuildSandbox({ buildRoot: uploadHome });
        await assertBuildSandboxIsolation({
          buildRoot: uploadHome,
          profile: uploadSandbox.profile,
          env: uploadEnvironment,
        });
        reverifyReleaseRuntime("before the isolated Wrangler install");
        await installBuildDependencies({
          sandbox: uploadSandbox,
          webDir: uploadWorkspace.webDir,
          env: uploadEnvironment,
        });
        assertSameInstalledDependencyProof(
          installedDependencyProof,
          await projectInstalledDependencyTree(uploadWorkspace.webDir),
          "before Wrangler invocation",
        );
        await assertBuildWorkspaceIntegrity({
          workspace: uploadWorkspace,
          expectedSourceSha256: baseline.sourceSha256,
          expectedUploadControlManifestSha256:
            baseline.uploadControlManifestSha256,
          expectedExternalBuildClosure: baseline.externalBuildClosure,
        });
        assertCloudflareControlEnvironment(controlEnv);

        const beforeUpload = await snapshotDeploymentInputs();
        const envBeforeUpload = await loadReleaseEnvironment();
        assertSameInputs(
          baseline,
          beforeUpload,
          envDigest,
          deploymentViteEnvironmentDigest(envBeforeUpload),
          "before upload",
        );
        if (policy.mode === "live") {
          assertSamePrivateReleaseArtifacts(
            baselinePrivateReleaseAudit,
            await loadPrivateReleaseAudit(releaseArguments),
            "before upload",
          );
        }

        const uploadDistAudit = await auditBuild({
          distDir: path.join(stageDir, "dist"),
          env,
          mode: policy.mode,
          releaseSha,
          sensitiveEnv: auditSensitiveEnv,
          privateReleaseAudit: baselinePrivateReleaseAudit,
        });
        if (uploadDistAudit.manifestSha256 !== stagedAudit.manifestSha256) {
          throw new Error(
            "Cloudflare staged dist changed after validation; upload was not attempted",
          );
        }
        const uploadBundleAudit = await auditStage({
          stageDir,
          distAudit: uploadDistAudit,
          mode: policy.mode,
          sensitiveEnv: auditSensitiveEnv,
          privateReleaseAudit: baselinePrivateReleaseAudit,
        });
        if (
          uploadBundleAudit.bundleManifestSha256
            !== stagedBundleAudit.bundleManifestSha256
          || uploadBundleAudit.distManifestSha256
            !== stagedBundleAudit.distManifestSha256
          || uploadBundleAudit.uploadControlManifestSha256
            !== stagedBundleAudit.uploadControlManifestSha256
        ) {
          throw new Error(
            "Cloudflare staged upload tree changed after validation; upload was not attempted",
          );
        }

        // This is deliberately adjacent to the credential-bearing subprocess.
        assertCloudflareControlEnvironment(controlEnv);
        reverifyReleaseRuntime("before Wrangler invocation");

        output(`cloudflare_release_mode=${policy.mode}`);
        output(`cloudflare_release_branch=${policy.branch}`);
        output(`cloudflare_node_version=${releaseRuntimeProof.nodeVersion}`);
        output(`cloudflare_node_sha256=${releaseRuntimeProof.nodeExecutableSha256}`);
        output(`cloudflare_node_dylib_closure_sha256=${releaseRuntimeProof.nodeDylibClosureSha256}`);
        output(`cloudflare_npm_version=${releaseRuntimeProof.npmVersion}`);
        output(`cloudflare_npm_tree_sha256=${releaseRuntimeProof.npmTreeSha256}`);
        output(`cloudflare_installed_dependency_count=${installedDependencyProof.packageCount}`);
        output(`cloudflare_installed_dependency_tree_sha256=${installedDependencyProof.sha256}`);
        output(`cloudflare_wrangler_version=${PINNED_WRANGLER_RUNTIME.version}`);
        output(`cloudflare_wrangler_cli_sha256=${PINNED_WRANGLER_RUNTIME.cliSha256}`);
        output(`cloudflare_dist_sha256=${audit.manifestSha256}`);
        // This commits Wrangler's exact reviewed input tree. Wrangler still
        // bundles the Pages Function and constructs the Cloudflare upload
        // payload internally, so do not label this as an uploaded-artifact
        // digest until a provider receipt/output manifest is independently
        // captured and verified.
        output(
          `cloudflare_staged_bundle_manifest_sha256=${stagedBundleAudit.bundleManifestSha256}`,
        );
        await invokeWrangler(policy.args, stageDir, Object.freeze({
          webDir: uploadWorkspace.webDir,
        }));
        return Object.freeze({
          policy,
          audit,
          stagedBundleAudit,
          releaseRuntimeProof,
          installedDependencyProof,
        });
      } finally {
        await removeUploadHome(uploadHome);
      }
    } finally {
      if (stageDir) await removeStage(stageDir);
    }
  } finally {
    await removeBuildHome(buildHome);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runCloudflareDeployment().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
