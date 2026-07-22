import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
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
  auditCloudflareBuild,
  cloudflareFrontendBuildControlFiles,
  cloudflareSourceFingerprint,
  cloudflareUploadControlFingerprint,
  loadPrivateFrontendCandidateArtifactAudit,
} from "./cloudflare-release-artifact-core.mjs";
import {
  cloudflareExternalBuildClosureSha256,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  cloudflareBuildEnvironment,
} from "./deploy-cloudflare-core.mjs";
import {
  createFrontendBuildCandidateReceipt,
  createFrontendBuildInputManifest,
} from "./frontend-build-candidate-core.mjs";
import {
  assertPinnedReleaseRuntime,
  normalizePinnedReleaseRuntimeProof,
} from "./release-runtime-pins-core.mjs";
import {
  createPrivateReleaseBuildHome,
  removePrivateReleaseBuildHome,
} from "./release-build-home-core.mjs";
import { serializeEnv } from "./release-env-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const rootDir = path.resolve(webDir, "..");
const PINNED_GIT_EXECUTABLE = "/usr/bin/git";
const PINNED_GIT_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_LITERAL_PATHSPECS: "1",
});
const SEMANTIC_PROJECTION_FIELDS = Object.freeze([
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
const RECEIPT_AUTHORITY_BINDING_FIELDS = Object.freeze([
  "ceremonyAuthorizationSha256",
  "computeWorkloadActivationObservationSha256",
  "deploymentIntentSha256",
  "reviewerAuthorityGenesisAcceptanceSha256",
  "runtimeAuthorityDependencySha256",
]);
const INSTALLED_DEPENDENCY_PROOF_FIELDS = Object.freeze([
  "packageCount",
  "schema",
  "sha256",
  "truth_status",
]);

function exactObject(value, fields, label) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())
  ) {
    throw new Error(`${label} does not have the exact frozen shape`);
  }
  return value;
}

function git(args) {
  return execFileSync(PINNED_GIT_EXECUTABLE, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-C",
    rootDir,
    ...args,
  ], {
    encoding: "utf8",
    env: PINNED_GIT_ENVIRONMENT,
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

export async function readFrontendBuildCandidateSnapshot() {
  const [
    sourceFingerprintSha256,
    uploadControlManifestSha256,
    buildControls,
    externalBuildClosure,
  ] = await Promise.all([
    cloudflareSourceFingerprint(webDir).then((value) => `sha256:${value}`),
    cloudflareUploadControlFingerprint(webDir).then((value) => `sha256:${value}`),
    cloudflareFrontendBuildControlFiles(rootDir),
    projectCloudflareExternalBuildClosure(rootDir),
  ]);
  const objectFormat = git(["rev-parse", "--show-object-format"]);
  const headSha = git(["rev-parse", "HEAD"]);
  const treeOid = git(["rev-parse", "HEAD^{tree}"]);
  const topLevel = git(["rev-parse", "--show-toplevel"]);
  const dirty = git([
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
    "--ignore-submodules=none",
  ]);
  if (
    objectFormat !== "sha1"
    || !/^[0-9a-f]{40}$/.test(headSha)
    || !/^[0-9a-f]{40}$/.test(treeOid)
    || path.resolve(topLevel) !== rootDir
  ) {
    throw new Error("frontend candidate source is not the reviewed SHA-1 Git repository");
  }
  return Object.freeze({
    headSha,
    dirty,
    gitTreeOid: `sha1:${treeOid}`,
    sourceFingerprintSha256,
    uploadControlManifestSha256,
    buildControls,
    externalBuildClosure,
    externalBuildClosureSha256:
      cloudflareExternalBuildClosureSha256(externalBuildClosure),
  });
}

function assertCleanCandidateSnapshot(snapshot, releaseSha) {
  if (
    snapshot.headSha !== releaseSha
    || snapshot.dirty !== ""
    || !/^sha1:[0-9a-f]{40}$/.test(snapshot.gitTreeOid)
    || !/^sha256:[0-9a-f]{64}$/.test(snapshot.sourceFingerprintSha256)
    || !/^sha256:[0-9a-f]{64}$/.test(snapshot.uploadControlManifestSha256)
    || !/^sha256:[0-9a-f]{64}$/.test(snapshot.externalBuildClosureSha256)
  ) {
    throw new Error(
      "frontend candidate production requires the exact clean release commit and source closure",
    );
  }
  return snapshot;
}

function assertSameCandidateSnapshot(baseline, current, checkpoint) {
  for (const key of [
    "headSha",
    "dirty",
    "gitTreeOid",
    "sourceFingerprintSha256",
    "uploadControlManifestSha256",
    "externalBuildClosureSha256",
  ]) {
    if (baseline[key] !== current[key]) {
      throw new Error(`frontend candidate inputs changed ${checkpoint}`);
    }
  }
  if (JSON.stringify(baseline.buildControls) !== JSON.stringify(current.buildControls)) {
    throw new Error(`frontend candidate build controls changed ${checkpoint}`);
  }
}

function assertPrivateInputsMatchProjection(privateAudit, preDPrivateInputs) {
  if (!privateAudit || !Array.isArray(privateAudit.inputs)
    || !Array.isArray(preDPrivateInputs)) {
    throw new Error("frontend candidate private input comparison is incomplete");
  }
  const byFlag = new Map(privateAudit.inputs.map((entry) => [entry.flag, entry]));
  if (
    byFlag.size !== preDPrivateInputs.length
    || preDPrivateInputs.some((entry) => (
      byFlag.get(entry.flag)?.content_sha256 !== entry.sha256.slice("sha256:".length)
    ))
  ) {
    throw new Error(
      "frontend candidate semantic projection does not match the exact scanned private input bytes",
    );
  }
}

function normalizeSemanticProjection(value) {
  const projection = exactObject(
    value,
    SEMANTIC_PROJECTION_FIELDS,
    "frontend candidate semantic projection",
  );
  exactObject(
    projection.authorityBinding,
    RECEIPT_AUTHORITY_BINDING_FIELDS,
    "frontend candidate receipt authority binding",
  );
  if (
    !/^[0-9a-f]{40}$/.test(String(projection.releaseSha || ""))
    || serializeEnv(projection.env) !== projection.serializedEnv
  ) {
    throw new Error(
      "frontend candidate semantic projection release or environment is not canonical",
    );
  }
  return projection;
}

function normalizeInstalledDependencyProof(value) {
  const proof = exactObject(
    value,
    INSTALLED_DEPENDENCY_PROOF_FIELDS,
    "frontend candidate installed dependency proof",
  );
  if (
    proof.schema !== CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_SCHEMA
    || proof.truth_status !== CLOUDFLARE_INSTALLED_DEPENDENCY_TREE_TRUTH_STATUS
    || !Number.isSafeInteger(proof.packageCount)
    || proof.packageCount < 1
    || !/^sha256:[0-9a-f]{64}$/.test(String(proof.sha256 || ""))
    || proof.sha256 === `sha256:${"0".repeat(64)}`
  ) {
    throw new Error("frontend candidate installed dependency proof is invalid");
  }
  return Object.freeze({
    schema: proof.schema,
    truth_status: proof.truth_status,
    packageCount: proof.packageCount,
    sha256: proof.sha256,
  });
}

function assertSameInstalledDependencyProof(baseline, current, checkpoint) {
  const normalized = normalizeInstalledDependencyProof(current);
  if (JSON.stringify(normalized) !== JSON.stringify(baseline)) {
    throw new Error(`frontend candidate dependency tree changed ${checkpoint}`);
  }
  return normalized;
}

function defaultVerify({ env, webDir: isolatedWebDir, sandbox }) {
  return runCloudflareBuildNpmScript({
    sandbox,
    webDir: isolatedWebDir,
    env,
    script: "check",
  });
}

function defaultBuild({ env, webDir: isolatedWebDir, sandbox }) {
  return runCloudflareBuildNpmScript({
    sandbox,
    webDir: isolatedWebDir,
    env,
    script: "build",
  });
}

/**
 * Produce nonauthorizing D from a previously authenticated exact-35 semantic
 * projection. This runner has no upload callback and never invokes Wrangler.
 */
export async function runFrontendBuildCandidateProduction({
  releaseArguments = [],
  loadSemanticProjection,
  snapshotCandidateInputs = readFrontendBuildCandidateSnapshot,
  loadPrivateInputAudit = loadPrivateFrontendCandidateArtifactAudit,
  createVerificationHome = createPrivateReleaseBuildHome,
  removeVerificationHome = removePrivateReleaseBuildHome,
  createBuildHome = createPrivateReleaseBuildHome,
  removeBuildHome = removePrivateReleaseBuildHome,
  createBuildWorkspace = createIsolatedCloudflareBuildWorkspace,
  createBuildSandbox = cloudflareBuildSandbox,
  assertBuildSandboxIsolation = assertCloudflareBuildSandboxIsolation,
  assertBuildWorkspaceIntegrity = assertCloudflareBuildWorkspaceIntegrity,
  installBuildDependencies = installCloudflareBuildDependencies,
  projectInstalledDependencyTree = projectCloudflareInstalledDependencyTree,
  verify = defaultVerify,
  build = defaultBuild,
  auditBuild = auditCloudflareBuild,
  assertReleaseRuntime = assertPinnedReleaseRuntime,
  sensitiveEnv = process.env,
  buildHostEnv = process.env,
} = {}) {
  if (typeof loadSemanticProjection !== "function") {
    throw new Error("frontend candidate producer requires the exact-35 semantic validator");
  }
  const releaseRuntimeProof = normalizePinnedReleaseRuntimeProof(
    assertReleaseRuntime(),
  );
  const reverifyRuntime = (checkpoint) => {
    let current;
    try {
      current = normalizePinnedReleaseRuntimeProof(assertReleaseRuntime());
    } catch {
      throw new Error(`frontend candidate release runtime changed ${checkpoint}`);
    }
    if (JSON.stringify(current) !== JSON.stringify(releaseRuntimeProof)) {
      throw new Error(`frontend candidate release runtime changed ${checkpoint}`);
    }
  };
  const projection = normalizeSemanticProjection(
    await loadSemanticProjection(releaseArguments),
  );
  const privateInputAudit = await loadPrivateInputAudit(releaseArguments);
  assertPrivateInputsMatchProjection(
    privateInputAudit,
    projection.preDPrivateInputs,
  );
  const baseline = assertCleanCandidateSnapshot(
    await snapshotCandidateInputs(),
    projection.releaseSha,
  );
  const buildSource = Object.freeze({
    sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
    sourceCommitSha: baseline.headSha,
    expectedGitTreeOid: baseline.gitTreeOid,
  });

  let installedDependencyProof;
  const verificationHome = await createVerificationHome();
  try {
    const verificationEnvironment = cloudflareBuildEnvironment(
      projection.env,
      buildHostEnv,
      verificationHome,
    );
    reverifyRuntime("before the isolated verification workspace projection");
    const verificationWorkspace = await createBuildWorkspace({
      repositoryRoot: rootDir,
      buildRoot: verificationHome,
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
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
    reverifyRuntime("before the isolated verification install");
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
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    reverifyRuntime("before the full isolated verification");
    await verify({
      env: verificationEnvironment,
      webDir: verificationWorkspace.webDir,
      sandbox: verificationSandbox,
    });
    await assertBuildWorkspaceIntegrity({
      workspace: verificationWorkspace,
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(verificationWorkspace.webDir),
      "during full verification",
    );
    assertSameCandidateSnapshot(
      baseline,
      await snapshotCandidateInputs(),
      "during full verification",
    );
    const afterVerifyPrivateAudit = await loadPrivateInputAudit(releaseArguments);
    if (afterVerifyPrivateAudit.fingerprintSha256 !== privateInputAudit.fingerprintSha256) {
      throw new Error("frontend candidate private inputs changed during full verification");
    }
    reverifyRuntime("during the full isolated verification");
  } finally {
    await removeVerificationHome(verificationHome);
  }

  const buildHome = await createBuildHome();
  try {
    if (buildHome === verificationHome) {
      throw new Error("frontend candidate verification and build HOMEs must be distinct");
    }
    const buildEnvironment = cloudflareBuildEnvironment(
      projection.env,
      buildHostEnv,
      buildHome,
    );
    reverifyRuntime("before the isolated artifact-build workspace projection");
    const workspace = await createBuildWorkspace({
      repositoryRoot: rootDir,
      buildRoot: buildHome,
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    const sandbox = await createBuildSandbox({ buildRoot: buildHome });
    await assertBuildSandboxIsolation({
      buildRoot: buildHome,
      profile: sandbox.profile,
      env: buildEnvironment,
    });
    reverifyRuntime("before the isolated artifact-build install");
    await installBuildDependencies({
      sandbox,
      webDir: workspace.webDir,
      env: buildEnvironment,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(workspace.webDir),
      "between verification and the fresh artifact build",
    );
    await assertBuildWorkspaceIntegrity({
      workspace,
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });

    assertSameCandidateSnapshot(
      baseline,
      await snapshotCandidateInputs(),
      "before the fresh build",
    );
    const beforeBuildPrivateAudit = await loadPrivateInputAudit(releaseArguments);
    if (beforeBuildPrivateAudit.fingerprintSha256 !== privateInputAudit.fingerprintSha256) {
      throw new Error("frontend candidate private inputs changed before the fresh build");
    }
    reverifyRuntime("before the fresh candidate build");
    await build({ env: buildEnvironment, webDir: workspace.webDir, sandbox });

    await assertBuildWorkspaceIntegrity({
      workspace,
      ...buildSource,
      expectedSourceSha256: baseline.sourceFingerprintSha256.slice("sha256:".length),
      expectedUploadControlManifestSha256:
        baseline.uploadControlManifestSha256.slice("sha256:".length),
      expectedExternalBuildClosure: baseline.externalBuildClosure,
    });
    assertSameInstalledDependencyProof(
      installedDependencyProof,
      await projectInstalledDependencyTree(workspace.webDir),
      "during the fresh build",
    );

    assertSameCandidateSnapshot(
      baseline,
      await snapshotCandidateInputs(),
      "during the fresh build",
    );
    const afterBuildPrivateAudit = await loadPrivateInputAudit(releaseArguments);
    if (afterBuildPrivateAudit.fingerprintSha256 !== privateInputAudit.fingerprintSha256) {
      throw new Error("frontend candidate private inputs changed during the fresh build");
    }
    reverifyRuntime("during the fresh candidate build");

    const buildAudit = await auditBuild({
      distDir: path.join(workspace.webDir, "dist"),
      env: projection.env,
      mode: "candidate",
      releaseSha: projection.releaseSha,
      sensitiveEnv: { ...projection.env, ...(sensitiveEnv || {}) },
      privateReleaseAudit: privateInputAudit,
    });
    const inputManifest = createFrontendBuildInputManifest({
      releaseSha: projection.releaseSha,
      gitTreeOid: baseline.gitTreeOid,
      sourceFingerprintSha256: baseline.sourceFingerprintSha256,
      preDPrivateInputs: projection.preDPrivateInputs,
      semanticLineage: projection.semanticLineage,
      serializedEnv: projection.serializedEnv,
      primaryRpcUrl: projection.primaryRpcUrl,
      secondaryRpcUrl: projection.secondaryRpcUrl,
      qvlVerifierRoots: projection.qvlVerifierRoots,
      authorityRoots: projection.authorityRoots,
      buildControls: baseline.buildControls,
      externalBuildClosure: baseline.externalBuildClosure,
    });
    const receipt = createFrontendBuildCandidateReceipt({
      releaseSha: projection.releaseSha,
      serializedEnv: projection.serializedEnv,
      ...projection.authorityBinding,
      frontendBuildSha256: `sha256:${buildAudit.manifestSha256}`,
      inputManifest,
    });
    return Object.freeze({
      receipt,
      inputManifest,
      serializedEnv: projection.serializedEnv,
      buildAudit,
      releaseRuntimeProof,
      installedDependencyProof,
      privateInputAuditFingerprintSha256: privateInputAudit.fingerprintSha256,
      sourceSnapshot: Object.freeze({
        sourceKind: buildSource.sourceKind,
        sourceCommitSha: buildSource.sourceCommitSha,
        gitTreeOid: baseline.gitTreeOid,
        sourceFingerprintSha256: baseline.sourceFingerprintSha256,
        externalBuildClosureSha256: baseline.externalBuildClosureSha256,
      }),
    });
  } finally {
    await removeBuildHome(buildHome);
  }
}

export const __test = Object.freeze({
  PINNED_GIT_ENVIRONMENT,
  PINNED_GIT_EXECUTABLE,
  RECEIPT_AUTHORITY_BINDING_FIELDS,
  INSTALLED_DEPENDENCY_PROOF_FIELDS,
  SEMANTIC_PROJECTION_FIELDS,
  assertPrivateInputsMatchProjection,
  normalizeInstalledDependencyProof,
  normalizeSemanticProjection,
});
