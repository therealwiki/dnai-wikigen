import assert from "node:assert/strict";
import {
  access,
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test as cloudflareBuildSandboxTest,
  assertCloudflareBuildSandboxIsolation,
  cloudflareBuildSandbox,
  createIsolatedCloudflareBuildWorkspace,
  projectCloudflareInstalledDependencyTree,
  renderCloudflareBuildSandboxProfile,
} from "./cloudflare-build-sandbox-core.mjs";
import {
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  cloudflareSourceFingerprint,
  cloudflareUploadControlFingerprint,
} from "./cloudflare-release-artifact-core.mjs";
import { cloudflareBuildEnvironment } from "./deploy-cloudflare-core.mjs";

const webDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(webDir, "..");

test("sandbox profile is default-deny, network-deny, and exposes only staged/cache/toolchain bytes", () => {
  const profile = renderCloudflareBuildSandboxProfile({
    buildRoot: "/private/tmp/dnai-build",
    npmCacheRoot: "/Users/release/.npm",
  });
  assert.match(profile, /^\(version 1\)\n\(deny default\)/);
  assert.match(profile, /\(deny network\*\)/);
  assert.match(profile, /\(subpath "\/private\/tmp\/dnai-build"\)/);
  assert.match(profile, /\(subpath "\/Users\/release\/\.npm\/_cacache"\)/);
  assert.match(profile, /\(literal "\/private\/var\/db\/xcode_select_link"\)/);
  assert.match(profile, /\(subpath "\/Library\/Developer\/CommandLineTools"\)/);
  assert.doesNotMatch(profile, /\(subpath "\/private\/var\/db"\)/);
  assert.doesNotMatch(profile, /\(subpath "\/Library"\)/);
  assert.doesNotMatch(profile, /\(allow default\)/);
  assert.doesNotMatch(profile, /CLOUDFLARE|PHALA|OPENROUTER|GITHUB_TOKEN/);
  assert.throws(
    () => renderCloudflareBuildSandboxProfile({
      buildRoot: "/tmp/build\n(allow default)",
      npmCacheRoot: "/Users/release/.npm",
    }),
    /canonical absolute path/,
  );
});

test("isolated source stage excludes mutable dependencies and matches validated source", async () => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const buildRoot = await mkdtemp(path.join(canonicalTemporaryRoot, "dnai-build-stage-test-"));
  await chmod(buildRoot, 0o700);
  try {
    const sourceSha256 = await cloudflareSourceFingerprint(webDir);
    const uploadControlManifestSha256 = await cloudflareUploadControlFingerprint(webDir);
    const externalBuildClosure = await projectCloudflareExternalBuildClosure(
      repositoryRoot,
    );
    const workspace = await createIsolatedCloudflareBuildWorkspace({
      repositoryRoot,
      buildRoot,
      expectedSourceSha256: sourceSha256,
      expectedUploadControlManifestSha256: uploadControlManifestSha256,
      expectedExternalBuildClosure: externalBuildClosure,
    });
    assert.equal(workspace.sourceSha256, sourceSha256);
    assert.equal(
      workspace.uploadControlManifestSha256,
      uploadControlManifestSha256,
    );
    assert.equal(
      JSON.parse(await readFile(path.join(workspace.webDir, "package.json"), "utf8"))
        .devDependencies.wrangler,
      "4.110.0",
    );
    await assert.rejects(access(path.join(workspace.webDir, "node_modules")), /ENOENT/);
    await assert.rejects(access(path.join(workspace.webDir, "dist")), /ENOENT/);
    await assert.rejects(
      access(path.join(workspace.webDir, ".env.production.local")),
      /ENOENT/,
    );
    await access(path.join(workspace.rootDir, "scripts"));
    await access(path.join(workspace.rootDir, "ARCHITECTURE.md"));
    assert.deepEqual(workspace.externalBuildClosure, externalBuildClosure);
    const extraRootScript = path.join(workspace.rootDir, "scripts", "unbound.mjs");
    await writeFile(extraRootScript, "export default true;\n", { mode: 0o600 });
    await assert.rejects(
      cloudflareBuildSandboxTest.assertOnlyDeclaredExternalFiles(workspace.rootDir),
      /unbound external input/,
    );
    await rm(extraRootScript);
    await mkdir(path.join(workspace.rootDir, "unbound-empty-directory"), {
      mode: 0o700,
    });
    await assert.rejects(
      cloudflareBuildSandboxTest.assertOnlyDeclaredExternalFiles(workspace.rootDir),
      /unbound external directory/,
    );
  } finally {
    await rm(buildRoot, { recursive: true, force: true });
  }
});

test("installed dependency proof exact-matches the source lock registry and integrity tree", async () => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(path.join(canonicalTemporaryRoot, "dnai-dependency-tree-test-"));
  await chmod(root, 0o700);
  const web = path.join(root, "web");
  const nodeModules = path.join(web, "node_modules");
  const descriptor = {
    version: "1.2.3",
    resolved: "https://registry.npmjs.org/example/-/example-1.2.3.tgz",
    integrity: `sha512-${Buffer.alloc(64, 7).toString("base64")}`,
  };
  const sourceLock = {
    name: "isolated-test",
    version: "1.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
      "": { name: "isolated-test", version: "1.0.0" },
      "node_modules/example": descriptor,
    },
  };
  const installedLock = {
    name: sourceLock.name,
    version: sourceLock.version,
    lockfileVersion: 3,
    requires: true,
    packages: { "node_modules/example": { ...descriptor } },
  };
  try {
    await mkdir(nodeModules, { recursive: true, mode: 0o700 });
    await writeFile(
      path.join(web, "package-lock.json"),
      `${JSON.stringify(sourceLock, null, 2)}\n`,
      { mode: 0o600 },
    );
    await writeFile(
      path.join(nodeModules, ".package-lock.json"),
      `${JSON.stringify(installedLock, null, 2)}\n`,
      { mode: 0o600 },
    );
    const proof = await projectCloudflareInstalledDependencyTree(web);
    assert.equal(proof.packageCount, 1);
    assert.match(proof.sha256, /^sha256:[0-9a-f]{64}$/);

    installedLock.packages["node_modules/example"].integrity =
      `sha512-${Buffer.alloc(64, 8).toString("base64")}`;
    await writeFile(
      path.join(nodeModules, ".package-lock.json"),
      `${JSON.stringify(installedLock, null, 2)}\n`,
      { mode: 0o600 },
    );
    await assert.rejects(
      projectCloudflareInstalledDependencyTree(web),
      /drifted from the reviewed version, URL, or integrity/,
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("macOS sandbox proves host-file and network denial before dependency install", {
  skip: process.env.DNAI_BUILD_SANDBOX_ACTIVE === "true"
    ? "outer release sandbox already proved this boundary"
    : false,
}, async () => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const buildRoot = await mkdtemp(path.join(canonicalTemporaryRoot, "dnai-build-sandbox-test-"));
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
