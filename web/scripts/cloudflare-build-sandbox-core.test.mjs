import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  access,
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  __test as cloudflareBuildSandboxTest,
  CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
  CLOUDFLARE_BUILD_SOURCE_KIND_WORKING_TREE,
  assertCloudflareBuildSandboxIsolation,
  assertCloudflareBuildWorkspaceIntegrity,
  assertModeledCloudflareWorkingTreeHasNoIgnoredBuildSource,
  cloudflareBuildSandbox,
  createIsolatedCloudflareBuildWorkspace,
  materializeImmutableCloudflareGitSource,
  projectCloudflareInstalledDependencyTree,
  renderCloudflareBuildSandboxProfile,
} from "./cloudflare-build-sandbox-core.mjs";
import {
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";
import {
  cloudflareSourceFingerprint,
  cloudflareUploadControlFingerprint,
} from "./cloudflare-release-artifact-core.mjs";
import { cloudflareBuildEnvironment } from "./deploy-cloudflare-core.mjs";

const modulePath = fileURLToPath(new URL(
  "./cloudflare-build-sandbox-core.test.mjs",
  import.meta.url,
));
const webDir = path.resolve(path.dirname(modulePath), "..");
const repositoryRoot = path.resolve(webDir, "..");
const TEST_GIT_EXECUTABLE = "/usr/bin/git";
const TEST_GIT_ENVIRONMENT = Object.freeze({
  PATH: "/usr/bin:/bin",
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_LITERAL_PATHSPECS: "1",
  GIT_AUTHOR_NAME: "Wikigen materializer test",
  GIT_AUTHOR_EMAIL: "materializer-test@invalid.local",
  GIT_AUTHOR_DATE: "2000-01-01T00:00:00Z",
  GIT_COMMITTER_NAME: "Wikigen materializer test",
  GIT_COMMITTER_EMAIL: "materializer-test@invalid.local",
  GIT_COMMITTER_DATE: "2000-01-01T00:00:00Z",
});

function fixtureGit(repository, args, { input } = {}) {
  return execFileSync(TEST_GIT_EXECUTABLE, [
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.untrackedCache=false",
    "-c",
    "commit.gpgsign=false",
    "-C",
    repository,
    ...args,
  ], {
    encoding: "utf8",
    env: { ...TEST_GIT_ENVIRONMENT, HOME: repository },
    input,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  }).trim();
}

async function writeFixturePath(repository, relative, content, mode = 0o644) {
  const target = path.join(repository, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await writeFile(target, content, { mode });
  await chmod(target, mode);
}

function commitFixture(repository, message) {
  fixtureGit(repository, ["add", "-A"]);
  fixtureGit(repository, ["commit", "-q", "--no-gpg-sign", "-m", message]);
  return Object.freeze({
    commitSha: fixtureGit(repository, ["rev-parse", "HEAD"]),
    gitTreeOid: `sha1:${fixtureGit(repository, ["rev-parse", "HEAD^{tree}"])}`,
  });
}

async function createGitMaterializerFixture({
  trackedFiles = {},
  trackedModes = {},
} = {}) {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(path.join(
    canonicalTemporaryRoot,
    "dnai-git-materializer-test-",
  ));
  await chmod(root, 0o700);
  const repository = path.join(root, "repository");
  await mkdir(repository, { mode: 0o700 });
  fixtureGit(repository, ["init", "-q", "--initial-branch=main", "--template="]);

  for (const { path: externalPath } of CLOUDFLARE_EXTERNAL_BUILD_FILES) {
    await writeFixturePath(
      repository,
      externalPath,
      externalPath === ".gitignore"
        ? "*.private.md\n"
        : `exact external fixture: ${externalPath}\n`,
    );
  }
  const baselineWebFiles = {
    "web/.gitignore": "node_modules/\ndist/\n.wrangler/\n.env\n.env.*\n",
    "web/package.json": "{\"name\":\"immutable-source-fixture\",\"private\":true}\n",
    "web/public/tracked.txt": "committed public bytes\n",
    "web/src/main.ts": "export const committed = true;\n",
    ...trackedFiles,
  };
  for (const [relative, content] of Object.entries(baselineWebFiles)) {
    await writeFixturePath(
      repository,
      relative,
      content,
      trackedModes[relative] ?? 0o644,
    );
  }
  const source = commitFixture(repository, "immutable source fixture");
  return {
    root,
    repository,
    ...source,
    async createWorkspace(label) {
      const workspace = path.join(root, label);
      await mkdir(workspace, { mode: 0o700 });
      return workspace;
    },
  };
}

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
    await assert.rejects(
      createIsolatedCloudflareBuildWorkspace({
        repositoryRoot,
        buildRoot,
        expectedSourceSha256: sourceSha256,
        expectedUploadControlManifestSha256: uploadControlManifestSha256,
        expectedExternalBuildClosure: externalBuildClosure,
      }),
      /source kind must be explicit/,
    );
    const workspace = await createIsolatedCloudflareBuildWorkspace({
      repositoryRoot,
      buildRoot,
      sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_WORKING_TREE,
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
    await access(path.join(
      workspace.rootDir,
      "outputs/wikigen-pitch-assets/attested-network.png",
    ));
    await access(path.join(
      workspace.rootDir,
      "outputs/wikigen-pitch-assets/private-reward-oracle.png",
    ));
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

test("immutable Git source materializes exact commit blobs and excludes ignored and untracked worktree bytes", async () => {
  const fixture = await createGitMaterializerFixture();
  try {
    await writeFixturePath(
      fixture.repository,
      "web/public/ignored.private.md",
      "ignored private bytes must never enter the build\n",
    );
    await writeFixturePath(
      fixture.repository,
      "web/public/untracked.txt",
      "ordinary untracked bytes must never enter the build\n",
    );
    await writeFixturePath(
      fixture.repository,
      "web/public/info-excluded.txt",
      "repository-local excluded bytes must never enter the build\n",
    );
    await mkdir(path.join(fixture.repository, ".git/info"), {
      recursive: true,
      mode: 0o700,
    });
    await writeFile(
      path.join(fixture.repository, ".git/info/exclude"),
      "web/public/info-excluded.txt\n",
    );
    const dirty = fixtureGit(fixture.repository, [
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
    ]);
    assert.doesNotMatch(dirty, /ignored\.private\.md/);
    assert.doesNotMatch(dirty, /info-excluded\.txt/);
    assert.match(dirty, /web\/public\/untracked\.txt/);

    const workspaceRoot = await fixture.createWorkspace("workspace-exact-blobs");
    const result = await materializeImmutableCloudflareGitSource({
      repositoryRoot: fixture.repository,
      workspaceRoot,
      sourceCommitSha: fixture.commitSha,
      expectedGitTreeOid: fixture.gitTreeOid,
    });
    assert.equal(Object.isFrozen(result), true);
    assert.deepEqual(
      {
        sourceKind: result.sourceKind,
        sourceCommitSha: result.sourceCommitSha,
        gitTreeOid: result.gitTreeOid,
      },
      {
        sourceKind: "git_commit",
        sourceCommitSha: fixture.commitSha,
        gitTreeOid: fixture.gitTreeOid,
      },
    );
    assert.equal(Number.isSafeInteger(result.fileCount), true);
    assert.equal(result.fileCount > CLOUDFLARE_EXTERNAL_BUILD_FILES.length, true);
    assert.equal(Number.isSafeInteger(result.totalBytes), true);
    assert.equal(result.totalBytes > 0, true);
    assert.equal(
      await readFile(path.join(workspaceRoot, "web/public/tracked.txt"), "utf8"),
      "committed public bytes\n",
    );
    await assert.rejects(
      access(path.join(workspaceRoot, "web/public/ignored.private.md")),
      /ENOENT/,
    );
    await assert.rejects(
      access(path.join(workspaceRoot, "web/public/untracked.txt")),
      /ENOENT/,
    );
    await assert.rejects(
      access(path.join(workspaceRoot, "web/public/info-excluded.txt")),
      /ENOENT/,
    );
    for (const { path: externalPath } of CLOUDFLARE_EXTERNAL_BUILD_FILES) {
      await access(path.join(workspaceRoot, ...externalPath.split("/")));
    }
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("isolated git_commit workspace binds the real commit source, controls, and external closure end to end", async () => {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(path.join(
    canonicalTemporaryRoot,
    "dnai-git-workspace-integration-test-",
  ));
  await chmod(root, 0o700);
  try {
    const sourceCommitSha = fixtureGit(repositoryRoot, ["rev-parse", "HEAD"]);
    const expectedGitTreeOid = `sha1:${fixtureGit(repositoryRoot, [
      "rev-parse",
      `${sourceCommitSha}^{tree}`,
    ])}`;
    const projectionRoot = path.join(root, "projection");
    await mkdir(projectionRoot, { mode: 0o700 });
    await materializeImmutableCloudflareGitSource({
      repositoryRoot,
      workspaceRoot: projectionRoot,
      sourceCommitSha,
      expectedGitTreeOid,
    });
    const expectedSourceSha256 = await cloudflareSourceFingerprint(
      path.join(projectionRoot, "web"),
    );
    const expectedUploadControlManifestSha256 =
      await cloudflareUploadControlFingerprint(path.join(projectionRoot, "web"));
    const expectedExternalBuildClosure =
      await projectCloudflareExternalBuildClosure(projectionRoot);

    const buildRoot = path.join(root, "build");
    await mkdir(buildRoot, { mode: 0o700 });
    const workspace = await createIsolatedCloudflareBuildWorkspace({
      repositoryRoot,
      buildRoot,
      sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
      sourceCommitSha,
      expectedGitTreeOid,
      expectedSourceSha256,
      expectedUploadControlManifestSha256,
      expectedExternalBuildClosure,
    });
    assert.deepEqual(
      {
        sourceKind: workspace.sourceKind,
        sourceCommitSha: workspace.sourceCommitSha,
        gitTreeOid: workspace.gitTreeOid,
      },
      {
        sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
        sourceCommitSha,
        gitTreeOid: expectedGitTreeOid,
      },
    );
    await assert.doesNotReject(assertCloudflareBuildWorkspaceIntegrity({
      workspace,
      sourceKind: CLOUDFLARE_BUILD_SOURCE_KIND_GIT_COMMIT,
      sourceCommitSha,
      expectedGitTreeOid,
      expectedSourceSha256,
      expectedUploadControlManifestSha256,
      expectedExternalBuildClosure,
    }));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("modeled working-tree source rejects build-reachable repository ignored files", async (context) => {
  await context.test("tracked .gitignore rule", async () => {
    const fixture = await createGitMaterializerFixture();
    try {
      await writeFixturePath(
        fixture.repository,
        "web/public/local.private.md",
        "ignored modeled preview bytes\n",
      );
      await assert.rejects(
        assertModeledCloudflareWorkingTreeHasNoIgnoredBuildSource(
          fixture.repository,
        ),
        /ignored build-reachable file/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await context.test(".git info exclude rule", async () => {
    const fixture = await createGitMaterializerFixture();
    try {
      await mkdir(path.join(fixture.repository, ".git/info"), {
        recursive: true,
        mode: 0o700,
      });
      await writeFile(
        path.join(fixture.repository, ".git/info/exclude"),
        "web/public/info-excluded.txt\n",
      );
      await writeFixturePath(
        fixture.repository,
        "web/public/info-excluded.txt",
        "info-excluded modeled preview bytes\n",
      );
      await assert.rejects(
        assertModeledCloudflareWorkingTreeHasNoIgnoredBuildSource(
          fixture.repository,
        ),
        /ignored build-reachable file/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  await context.test("repository-local excludes file", async () => {
    const fixture = await createGitMaterializerFixture();
    try {
      const excludes = path.join(fixture.repository, ".git/local-excludes");
      await writeFile(excludes, "web/public/repository-excluded.txt\n");
      fixtureGit(fixture.repository, ["config", "core.excludesFile", excludes]);
      await writeFixturePath(
        fixture.repository,
        "web/public/repository-excluded.txt",
        "repository-excluded modeled preview bytes\n",
      );
      await assert.rejects(
        assertModeledCloudflareWorkingTreeHasNoIgnoredBuildSource(
          fixture.repository,
        ),
        /ignored build-reachable file/,
      );
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});

test("modeled working-tree source permits only explicit generated exclusions and tracked index substitutions", async () => {
  const fixture = await createGitMaterializerFixture({
    trackedFiles: {
      "web/public/assume.txt": "committed assume bytes\n",
      "web/public/skip.txt": "committed skip bytes\n",
    },
  });
  try {
    for (const relative of [
      "web/node_modules/local.private.md",
      "web/dist/local.private.md",
      "web/.wrangler/local.private.md",
      "web/src/.env.production.local",
    ]) {
      await writeFixturePath(
        fixture.repository,
        relative,
        "explicitly excluded generated bytes\n",
      );
    }
    await writeFixturePath(
      fixture.repository,
      "web/public/ordinary-untracked.txt",
      "ordinary modeled preview work\n",
    );
    fixtureGit(fixture.repository, [
      "update-index",
      "--assume-unchanged",
      "web/public/assume.txt",
    ]);
    fixtureGit(fixture.repository, [
      "update-index",
      "--skip-worktree",
      "web/public/skip.txt",
    ]);
    await writeFile(
      path.join(fixture.repository, "web/public/assume.txt"),
      "modeled assume substitution\n",
    );
    await writeFile(
      path.join(fixture.repository, "web/public/skip.txt"),
      "modeled skip substitution\n",
    );
    await assert.doesNotReject(
      assertModeledCloudflareWorkingTreeHasNoIgnoredBuildSource(
        fixture.repository,
      ),
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source ignores assume-unchanged and skip-worktree substitutions", async () => {
  const fixture = await createGitMaterializerFixture({
    trackedFiles: {
      "web/public/assume.txt": "committed assume-unchanged bytes\n",
      "web/public/skip.txt": "committed skip-worktree bytes\n",
    },
  });
  try {
    fixtureGit(fixture.repository, [
      "update-index",
      "--assume-unchanged",
      "web/public/assume.txt",
    ]);
    fixtureGit(fixture.repository, [
      "update-index",
      "--skip-worktree",
      "web/public/skip.txt",
    ]);
    await writeFile(
      path.join(fixture.repository, "web/public/assume.txt"),
      "substituted assume-unchanged bytes\n",
    );
    await writeFile(
      path.join(fixture.repository, "web/public/skip.txt"),
      "substituted skip-worktree bytes\n",
    );
    assert.equal(fixtureGit(fixture.repository, [
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
    ]), "");

    const workspaceRoot = await fixture.createWorkspace("workspace-hidden-index-bits");
    await materializeImmutableCloudflareGitSource({
      repositoryRoot: fixture.repository,
      workspaceRoot,
      sourceCommitSha: fixture.commitSha,
      expectedGitTreeOid: fixture.gitTreeOid,
    });
    assert.equal(
      await readFile(path.join(workspaceRoot, "web/public/assume.txt"), "utf8"),
      "committed assume-unchanged bytes\n",
    );
    assert.equal(
      await readFile(path.join(workspaceRoot, "web/public/skip.txt"), "utf8"),
      "committed skip-worktree bytes\n",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source rejects a commit and tree mismatch", async () => {
  const fixture = await createGitMaterializerFixture();
  try {
    await writeFile(
      path.join(fixture.repository, "web/public/tracked.txt"),
      "second commit bytes\n",
    );
    const second = commitFixture(fixture.repository, "second source fixture");
    const workspaceRoot = await fixture.createWorkspace("workspace-tree-mismatch");
    await assert.rejects(
      materializeImmutableCloudflareGitSource({
        repositoryRoot: fixture.repository,
        workspaceRoot,
        sourceCommitSha: fixture.commitSha,
        expectedGitTreeOid: second.gitTreeOid,
      }),
      /tree/i,
    );
    assert.deepEqual(await readdir(workspaceRoot), []);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source ignores replacement refs and checkout filters", async () => {
  const fixture = await createGitMaterializerFixture({
    trackedFiles: {
      ".gitattributes": "web/public/filter.txt filter=materializer-test\n",
      "web/public/filter.txt": "raw committed filter bytes\n",
      "web/public/version.txt": "commit A bytes\n",
    },
  });
  try {
    await writeFile(
      path.join(fixture.repository, "web/public/version.txt"),
      "commit B replacement bytes\n",
    );
    const replacement = commitFixture(fixture.repository, "replacement commit B");
    fixtureGit(fixture.repository, ["replace", fixture.commitSha, replacement.commitSha]);
    fixtureGit(fixture.repository, [
      "config",
      "filter.materializer-test.smudge",
      "/usr/bin/false",
    ]);
    fixtureGit(fixture.repository, [
      "config",
      "filter.materializer-test.required",
      "true",
    ]);

    const workspaceRoot = await fixture.createWorkspace("workspace-replace-filter");
    await materializeImmutableCloudflareGitSource({
      repositoryRoot: fixture.repository,
      workspaceRoot,
      sourceCommitSha: fixture.commitSha,
      expectedGitTreeOid: fixture.gitTreeOid,
    });
    assert.equal(
      await readFile(path.join(workspaceRoot, "web/public/version.txt"), "utf8"),
      "commit A bytes\n",
    );
    assert.equal(
      await readFile(path.join(workspaceRoot, "web/public/filter.txt"), "utf8"),
      "raw committed filter bytes\n",
    );
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source preserves reviewed blob modes and rejects symlink entries", async () => {
  const executableFixture = await createGitMaterializerFixture({
    trackedFiles: {
      "web/bin/reviewed-tool.sh": "#!/bin/sh\nexit 0\n",
    },
    trackedModes: {
      "web/bin/reviewed-tool.sh": 0o755,
    },
  });
  try {
    const workspaceRoot = await executableFixture.createWorkspace(
      "workspace-reviewed-modes",
    );
    await materializeImmutableCloudflareGitSource({
      repositoryRoot: executableFixture.repository,
      workspaceRoot,
      sourceCommitSha: executableFixture.commitSha,
      expectedGitTreeOid: executableFixture.gitTreeOid,
    });
    assert.equal(
      (await lstat(path.join(workspaceRoot, "web/bin/reviewed-tool.sh"))).mode
        & 0o777,
      0o755,
    );
    assert.equal(
      (await lstat(path.join(workspaceRoot, "web/src/main.ts"))).mode & 0o777,
      0o644,
    );
  } finally {
    await rm(executableFixture.root, { recursive: true, force: true });
  }

  const symlinkFixture = await createGitMaterializerFixture();
  try {
    await symlink(
      "tracked.txt",
      path.join(symlinkFixture.repository, "web/public/linked.txt"),
    );
    const symlinkSource = commitFixture(
      symlinkFixture.repository,
      "source fixture with a symlink",
    );
    const workspaceRoot = await symlinkFixture.createWorkspace(
      "workspace-reject-symlink",
    );
    await assert.rejects(
      materializeImmutableCloudflareGitSource({
        repositoryRoot: symlinkFixture.repository,
        workspaceRoot,
        sourceCommitSha: symlinkSource.commitSha,
        expectedGitTreeOid: symlinkSource.gitTreeOid,
      }),
      /mode|symlink/i,
    );
  } finally {
    await rm(symlinkFixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source rejects forcibly tracked generated paths and gitlinks", async () => {
  const generatedFixture = await createGitMaterializerFixture();
  try {
    await writeFixturePath(
      generatedFixture.repository,
      "web/dist/ignored-but-forced.js",
      "export const poison = true;\n",
    );
    fixtureGit(generatedFixture.repository, [
      "add",
      "-f",
      "web/dist/ignored-but-forced.js",
    ]);
    fixtureGit(generatedFixture.repository, [
      "commit",
      "-q",
      "--no-gpg-sign",
      "-m",
      "force tracked generated source",
    ]);
    const sourceCommitSha = fixtureGit(generatedFixture.repository, [
      "rev-parse",
      "HEAD",
    ]);
    const expectedGitTreeOid = `sha1:${fixtureGit(generatedFixture.repository, [
      "rev-parse",
      "HEAD^{tree}",
    ])}`;
    const workspaceRoot = await generatedFixture.createWorkspace(
      "workspace-reject-generated",
    );
    await assert.rejects(
      materializeImmutableCloudflareGitSource({
        repositoryRoot: generatedFixture.repository,
        workspaceRoot,
        sourceCommitSha,
        expectedGitTreeOid,
      }),
      /forbidden generated path/,
    );
  } finally {
    await rm(generatedFixture.root, { recursive: true, force: true });
  }

  const gitlinkFixture = await createGitMaterializerFixture();
  try {
    fixtureGit(gitlinkFixture.repository, [
      "update-index",
      "--add",
      "--cacheinfo",
      `160000,${gitlinkFixture.commitSha},web/rejected-gitlink`,
    ]);
    fixtureGit(gitlinkFixture.repository, [
      "commit",
      "-q",
      "--no-gpg-sign",
      "-m",
      "add rejected gitlink",
    ]);
    const sourceCommitSha = fixtureGit(gitlinkFixture.repository, [
      "rev-parse",
      "HEAD",
    ]);
    const expectedGitTreeOid = `sha1:${fixtureGit(gitlinkFixture.repository, [
      "rev-parse",
      "HEAD^{tree}",
    ])}`;
    const workspaceRoot = await gitlinkFixture.createWorkspace(
      "workspace-reject-gitlink",
    );
    await assert.rejects(
      materializeImmutableCloudflareGitSource({
        repositoryRoot: gitlinkFixture.repository,
        workspaceRoot,
        sourceCommitSha,
        expectedGitTreeOid,
      }),
      /unsupported object or mode/,
    );
  } finally {
    await rm(gitlinkFixture.root, { recursive: true, force: true });
  }
});

test("immutable Git source rejects control characters in committed paths", async () => {
  const fixture = await createGitMaterializerFixture({
    trackedFiles: {
      "web/public/rejected\tcontrol.txt": "control-character path bytes\n",
    },
  });
  try {
    const workspaceRoot = await fixture.createWorkspace(
      "workspace-reject-control-path",
    );
    await assert.rejects(
      materializeImmutableCloudflareGitSource({
        repositoryRoot: fixture.repository,
        workspaceRoot,
        sourceCommitSha: fixture.commitSha,
        expectedGitTreeOid: fixture.gitTreeOid,
      }),
      /noncanonical path/,
    );
    assert.deepEqual(await readdir(workspaceRoot), []);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
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
