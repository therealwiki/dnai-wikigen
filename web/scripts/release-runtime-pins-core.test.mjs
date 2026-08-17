import assert from "node:assert/strict";
import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PINNED_NODE_DYLIB_CLOSURE_SHA256,
  PINNED_NODE_HOMEBREW_DYLIBS,
  PINNED_NODE_RUNTIME,
  PINNED_NPM_RUNTIME,
  PINNED_RELEASE_RUNTIME_PROOF,
  assertPinnedNodeRuntime,
  assertPinnedNpmRuntime,
  assertPinnedReleaseRuntime,
  normalizePinnedReleaseRuntimeProof,
  projectNpmRuntimeTree,
} from "./release-runtime-pins-core.mjs";

async function createNpmFixture() {
  const directory = await realpath(await mkdtemp(
    path.join(tmpdir(), "dnai-npm-runtime-pin-"),
  ));
  const treeRoot = path.join(directory, "npm");
  const binDirectory = path.join(treeRoot, "bin");
  const libDirectory = path.join(treeRoot, "lib");
  const shimDirectory = path.join(treeRoot, "node_modules", ".bin");
  const nodeBinDirectory = path.join(directory, "node", "bin");
  for (const target of [treeRoot, binDirectory, libDirectory, shimDirectory, nodeBinDirectory]) {
    await mkdir(target, { recursive: true, mode: 0o700 });
    await chmod(target, 0o700);
  }
  const packagePath = path.join(treeRoot, "package.json");
  const cliPath = path.join(binDirectory, "npm-cli.js");
  const libraryPath = path.join(libDirectory, "runtime.js");
  const executableSymlink = path.join(nodeBinDirectory, "npm");
  await writeFile(
    packagePath,
    `${JSON.stringify({ name: "npm", version: "11.6.0" }, null, 2)}\n`,
    { mode: 0o600 },
  );
  await writeFile(cliPath, "export const npm = true;\n", { mode: 0o500 });
  await writeFile(libraryPath, "export const runtime = true;\n", { mode: 0o600 });
  await symlink("../../lib/runtime.js", path.join(shimDirectory, "runtime"));
  await symlink(cliPath, executableSymlink);
  const projection = projectNpmRuntimeTree(treeRoot);
  return {
    directory,
    treeRoot,
    packagePath,
    cliPath,
    libraryPath,
    executableSymlink,
    pin: {
      version: "11.6.0",
      executableSymlink,
      executableTarget: cliPath,
      treeRoot,
      entryCount: projection.entryCount,
      totalBytes: projection.totalBytes,
      treeSha256: projection.treeSha256,
    },
  };
}

async function withNpmFixture(callback) {
  const fixture = await createNpmFixture();
  try {
    await callback(fixture);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
}

test("reviewed release runtime pins Node, all Homebrew dylibs, and the npm tree", () => {
  assert.equal(PINNED_NODE_RUNTIME.version, "v24.9.0");
  assert.equal(PINNED_NODE_HOMEBREW_DYLIBS.length, 17);
  assert.equal(
    PINNED_NODE_DYLIB_CLOSURE_SHA256,
    "9d7a826fa8ec4a1f1a2d3d4f3b0f02e36312440234cd4ce45f9581a6771721c7",
  );
  assert.equal(PINNED_NPM_RUNTIME.version, "11.6.0");
  assert.equal(PINNED_NPM_RUNTIME.entryCount, 2_857);
  assert.equal(PINNED_NPM_RUNTIME.totalBytes, 11_960_560);
  assert.equal(
    PINNED_NPM_RUNTIME.treeSha256,
    "417ff144368776eeaf8651a00ec0e3933db96278b1a7efe9e7f53817634c6289",
  );
  assert.deepEqual(
    normalizePinnedReleaseRuntimeProof(PINNED_RELEASE_RUNTIME_PROOF),
    PINNED_RELEASE_RUNTIME_PROOF,
  );
  if (
    process.platform === "darwin"
    && process.version === PINNED_NODE_RUNTIME.version
    && process.execPath === PINNED_NODE_RUNTIME.executablePath
  ) {
    assert.deepEqual(assertPinnedReleaseRuntime(), PINNED_RELEASE_RUNTIME_PROOF);
  }
});

test("Node runtime rejects version, path, and executable-byte substitutions", async () => {
  assert.throws(
    () => assertPinnedNodeRuntime({ version: "v24.9.1" }),
    /version must be exactly/,
  );
  assert.throws(
    () => assertPinnedNodeRuntime({
      executablePath: "/usr/bin/node",
      version: PINNED_NODE_RUNTIME.version,
    }),
    /executable path is not reviewed/,
  );

  const directory = await realpath(await mkdtemp(
    path.join(tmpdir(), "dnai-node-runtime-tamper-"),
  ));
  const executablePath = path.join(directory, "node");
  const bytes = Buffer.from("tampered-node-runtime\n", "utf8");
  try {
    await writeFile(executablePath, bytes, { mode: 0o500 });
    await chmod(executablePath, 0o500);
    assert.throws(
      () => assertPinnedNodeRuntime({
        executablePath,
        version: "v1.2.3",
        pin: {
          version: "v1.2.3",
          executablePath,
          executableMode: 0o500,
          executableSize: bytes.length,
          executableSha256: "0".repeat(64),
        },
        dylibPins: [],
        otool: () => `${executablePath}:\n`,
      }),
      /does not match the reviewed bytes/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("npm runtime rejects executable-symlink retargeting", async () => {
  await withNpmFixture(async (fixture) => {
    const alternate = path.join(path.dirname(fixture.cliPath), "alternate-cli.js");
    await writeFile(alternate, "export default false;\n", { mode: 0o500 });
    await unlink(fixture.executableSymlink);
    await symlink(alternate, fixture.executableSymlink);
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin }),
      /symlink does not match/,
    );
  });
});

test("npm runtime rejects file tampering and undeclared extra files", async () => {
  await withNpmFixture(async (fixture) => {
    await writeFile(fixture.libraryPath, "export const runtime = false;\n", { mode: 0o600 });
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin }),
      /exact manifest/,
    );
  });
  await withNpmFixture(async (fixture) => {
    await writeFile(path.join(fixture.treeRoot, "undeclared.js"), "export default true;\n", {
      mode: 0o600,
    });
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin }),
      /exact manifest/,
    );
  });
});

test("npm runtime rejects unsafe mode, wrong owner, and version drift", async () => {
  await withNpmFixture(async (fixture) => {
    await chmod(fixture.libraryPath, 0o622);
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin }),
      /unsafe owner or mode/,
    );
  });
  await withNpmFixture(async (fixture) => {
    const wrongUid = (typeof process.geteuid === "function" ? process.geteuid() : 0) + 1;
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin, expectedUid: wrongUid }),
      /symlink does not match|unsafe owner or mode/,
    );
  });
  await withNpmFixture(async (fixture) => {
    await writeFile(
      fixture.packagePath,
      `${JSON.stringify({ name: "npm", version: "11.6.1" }, null, 2)}\n`,
      { mode: 0o600 },
    );
    assert.throws(
      () => assertPinnedNpmRuntime({ pin: fixture.pin }),
      /version must be exactly/,
    );
  });
});
