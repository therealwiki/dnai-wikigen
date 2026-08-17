import assert from "node:assert/strict";
import fs from "node:fs";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  realpath,
  rename,
  rm,
  symlink,
  truncate,
  unlink,
  writeFile,
} from "node:fs/promises";
import os, { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA,
  CLOUDFLARE_UPLOADER_CAPSULE_TRUTH_STATUS,
  __test,
  assertPinnedCloudflareUploaderCapsule,
  normalizeCloudflareUploaderCapsulePin,
  pinCloudflareUploaderCapsule,
  projectCloudflareUploaderCapsule,
} from "./cloudflare-uploader-capsule-core.mjs";

const NPM_VERSION = "11.6.0";
const WRANGLER_VERSION = "4.110.0";
const INTEGRITY = `sha512-${Buffer.alloc(64, 7).toString("base64")}`;
const SYNTHETIC_KAT_RUNTIME = Object.freeze({
  architecture: "arm64",
  nodeVersion: "v24.9.0",
  npmVersion: NPM_VERSION,
  osPlatform: "darwin",
  osRelease: "24.6.0",
  wranglerVersion: WRANGLER_VERSION,
});
const SYNTHETIC_KAT_OBSERVED_RUNTIME = Object.freeze({
  architecture: SYNTHETIC_KAT_RUNTIME.architecture,
  nodeVersion: SYNTHETIC_KAT_RUNTIME.nodeVersion,
  osPlatform: SYNTHETIC_KAT_RUNTIME.osPlatform,
  osRelease: SYNTHETIC_KAT_RUNTIME.osRelease,
});
const SYNTHETIC_KAT_MANIFEST_SHA256 =
  "sha256:163126df2da62577e1636ecdbc7eea91004bfd6968605bcc87933e12d1a7ab7a";

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function runtimeIdentity(overrides = {}) {
  return {
    architecture: process.arch,
    nodeVersion: process.version,
    npmVersion: NPM_VERSION,
    osPlatform: process.platform,
    osRelease: os.release(),
    wranglerVersion: WRANGLER_VERSION,
    ...overrides,
  };
}

async function writeOwnedFile(filePath, bytes, mode = 0o600) {
  await writeFile(filePath, bytes, { mode });
  await chmod(filePath, mode);
}

async function makeDirectory(directory, mode = 0o700) {
  await mkdir(directory, { recursive: true, mode });
  await chmod(directory, mode);
}

function rootPackage(nodeVersion = process.version) {
  return {
    dependencies: { wrangler: WRANGLER_VERSION },
    engines: { node: nodeVersion.slice(1) },
    name: "dnai-cloudflare-release-uploader",
    packageManager: `npm@${NPM_VERSION}`,
    private: true,
    version: "0.0.0",
  };
}

function packageLock(overrides = {}) {
  const packages = {
    "": {
      name: "dnai-cloudflare-release-uploader",
      version: "0.0.0",
      dependencies: { wrangler: WRANGLER_VERSION },
    },
    "node_modules/helper": {
      version: "1.2.3",
      resolved: "https://registry.npmjs.org/helper/-/helper-1.2.3.tgz",
      integrity: INTEGRITY,
    },
    "node_modules/wrangler": {
      version: WRANGLER_VERSION,
      resolved: `https://registry.npmjs.org/wrangler/-/wrangler-${WRANGLER_VERSION}.tgz`,
      integrity: INTEGRITY,
      hasInstallScript: true,
      dependencies: { helper: "1.2.3" },
    },
  };
  return {
    name: "dnai-cloudflare-release-uploader",
    version: "0.0.0",
    lockfileVersion: 3,
    requires: true,
    packages,
    ...overrides,
  };
}

function addSortedLockPackage(lock, packagePath, descriptor) {
  lock.packages = Object.fromEntries([
    ...Object.entries(lock.packages),
    [packagePath, descriptor],
  ].sort(([left], [right]) => Buffer.compare(
    Buffer.from(left, "utf8"),
    Buffer.from(right, "utf8"),
  )));
  return lock;
}

async function createFixture({ runtime = runtimeIdentity() } = {}) {
  const root = await realpath(await mkdtemp(
    path.join(tmpdir(), "dnai-cloudflare-uploader-capsule-"),
  ));
  await chmod(root, 0o700);
  for (const directory of [
    "node_modules",
    "node_modules/.bin",
    "node_modules/helper",
    "node_modules/wrangler",
    "node_modules/wrangler/bin",
  ]) {
    await makeDirectory(path.join(root, directory));
  }
  await writeOwnedFile(
    path.join(root, "package.json"),
    canonicalJson(rootPackage(runtime.nodeVersion)),
  );
  await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(packageLock()));
  await writeOwnedFile(
    path.join(root, "node_modules/.package-lock.json"),
    canonicalJson({ lockfileVersion: 3, packages: {} }),
  );
  await writeOwnedFile(
    path.join(root, "node_modules/helper/package.json"),
    canonicalJson({ name: "helper", version: "1.2.3" }),
  );
  await writeOwnedFile(
    path.join(root, "node_modules/helper/index.js"),
    "export const helper = true;\n",
  );
  await writeOwnedFile(
    path.join(root, "node_modules/wrangler/package.json"),
    canonicalJson({
      name: "wrangler",
      version: WRANGLER_VERSION,
      dependencies: { helper: "1.2.3" },
      bin: {
        "cf-wrangler": "bin/cf-wrangler.js",
        wrangler: "bin/wrangler.js",
        wrangler2: "bin/wrangler.js",
      },
      scripts: { postinstall: "node ./install.js", test: "node --test" },
    }),
  );
  await writeOwnedFile(
    path.join(root, "node_modules/wrangler/bin/wrangler.js"),
    "#!/usr/bin/env node\nconsole.log('wrangler');\n",
    0o500,
  );
  await writeOwnedFile(
    path.join(root, "node_modules/wrangler/bin/cf-wrangler.js"),
    "#!/usr/bin/env node\nconsole.log('cf-wrangler');\n",
    0o500,
  );
  await symlink(
    "../wrangler/bin/wrangler.js",
    path.join(root, "node_modules/.bin/wrangler"),
  );
  await symlink(
    "../wrangler/bin/wrangler.js",
    path.join(root, "node_modules/.bin/wrangler2"),
  );
  await symlink(
    "../wrangler/bin/cf-wrangler.js",
    path.join(root, "node_modules/.bin/cf-wrangler"),
  );
  return {
    options: { capsuleRoot: root, runtimeIdentity: runtime },
    root,
  };
}

async function withFixture(callback, fixtureOptions) {
  const fixture = await createFixture(fixtureOptions);
  try {
    await callback(fixture);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
}

test("projects a deterministic exact-byte Wrangler-only uploader capsule", async () => {
  await withFixture(async ({ options }) => {
    const first = projectCloudflareUploaderCapsule(options);
    const second = projectCloudflareUploaderCapsule(options);
    assert.equal(first.manifest.schema, CLOUDFLARE_UPLOADER_CAPSULE_SCHEMA);
    assert.equal(
      first.manifest.truthStatus,
      CLOUDFLARE_UPLOADER_CAPSULE_TRUTH_STATUS,
    );
    assert.equal(first.manifestSha256, second.manifestSha256);
    assert.deepEqual(first.manifest, second.manifest);
    assert.deepEqual(first.manifest.projectionPolicy.allowedRootEntries, [
      "node_modules",
      "package-lock.json",
      "package.json",
    ]);
    assert.equal(
      first.manifest.projectionPolicy.credentialInputs,
      "no_external_credential_api_known_credential_paths_denied_dependency_content_not_semantically_classified",
    );
    assert.equal(
      first.manifest.projectionPolicy.npmRuntimeIdentity,
      "caller_supplied_version_bound_to_package_manager_external_runtime_proof_required",
    );
    assert.equal(
      first.manifest.projectionPolicy.registryIntegrity,
      "lock_declaration_only_external_offline_cache_integrity_and_npm_ci_proof_required",
    );
    assert.equal(first.manifest.projectionPolicy.hardlinks, "rejected");
    assert.equal(
      first.manifest.projectionPolicy.nativeAndWasm,
      "leading_magic_classified_and_digest_bound_not_format_validated",
    );
    assert.equal(
      first.manifest.projectionPolicy.concurrentSameUidPathSwap,
      "out_of_scope_production_blocker_requires_immutable_snapshot_or_descriptor_relative_traversal",
    );
    assert.equal(
      first.manifest.projectionPolicy.ordinaryFileMemory,
      "stream_hashed_with_leading_header_only_not_retained",
    );
    assert.equal(first.manifest.wrangler.version, WRANGLER_VERSION);
    assert.equal(
      first.manifest.wrangler.executablePath,
      "node_modules/wrangler/bin/wrangler.js",
    );
    assert.ok(first.manifest.entryCount > 10);
    assert.ok(first.manifest.totalBytes > 0);
    assert.ok(first.manifest.jsonDescriptorBytes < first.manifest.totalBytes);
    assert.equal(first.manifest.lockfile.dependencyEdgeCount, 2);
    assert.ok(first.manifestByteLength > 1_024);
    assert.deepEqual(first.manifest.capabilities.lifecycleScripts, [{
      packagePath: "node_modules/wrangler",
      scriptNames: ["postinstall"],
    }]);
    assert.deepEqual(first.manifest.capabilities.installScriptPackages, [
      "node_modules/wrangler",
    ]);
    assert.equal(first.manifest.capabilities.executableFiles.length, 2);
    assert.equal(first.manifest.capabilities.symlinks.length, 3);
  });
});

test("synthetic capsule projection matches its fixed host-independent known-answer digest", async () => {
  const fixture = await createFixture({ runtime: SYNTHETIC_KAT_RUNTIME });
  try {
    const projection = __test.repeatedProjection({
      ...fixture.options,
      observedRuntimeIdentity: SYNTHETIC_KAT_OBSERVED_RUNTIME,
    });
    assert.equal(projection.manifestSha256, SYNTHETIC_KAT_MANIFEST_SHA256);
  } finally {
    await rm(fixture.root, { recursive: true, force: true });
  }
});

test("the exact pin round-trips and rejects malformed pin metadata", async () => {
  await withFixture(async ({ options }) => {
    const projection = projectCloudflareUploaderCapsule(options);
    const pin = pinCloudflareUploaderCapsule(projection);
    assert.deepEqual(
      assertPinnedCloudflareUploaderCapsule(options, pin),
      projection,
    );
    assert.throws(
      () => normalizeCloudflareUploaderCapsulePin({ ...pin, surprise: true }),
      /exact reviewed fields/,
    );
    assert.throws(
      () => normalizeCloudflareUploaderCapsulePin({
        ...pin,
        manifestSha256: "sha256:deadbeef",
      }),
      /pin is invalid/,
    );
  });
});

test("content mutation, truncation, and an extra package file invalidate the pin", async () => {
  await withFixture(async ({ root, options }) => {
    const pin = pinCloudflareUploaderCapsule(projectCloudflareUploaderCapsule(options));
    const helper = path.join(root, "node_modules/helper/index.js");
    await writeOwnedFile(helper, "export const helper = null;\n");
    assert.throws(
      () => assertPinnedCloudflareUploaderCapsule(options, pin),
      /does not match its exact reviewed pin/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const pin = pinCloudflareUploaderCapsule(projectCloudflareUploaderCapsule(options));
    await truncate(path.join(root, "node_modules/helper/index.js"), 3);
    assert.throws(
      () => assertPinnedCloudflareUploaderCapsule(options, pin),
      /does not match its exact reviewed pin/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const pin = pinCloudflareUploaderCapsule(projectCloudflareUploaderCapsule(options));
    await writeOwnedFile(path.join(root, "node_modules/helper/extra.js"), "export default 1;\n");
    assert.throws(
      () => assertPinnedCloudflareUploaderCapsule(options, pin),
      /does not match its exact reviewed pin/,
    );
  });
});

test("regular-file mutation during read and tree mutation between passes fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    const target = path.join(root, "node_modules/helper/index.js");
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: {
          afterFileRead(filePath) {
            if (filePath === target) fs.truncateSync(target, 1);
          },
        },
      }),
      /changed during its stable read/,
    );
  });
  await withFixture(async ({ root, options }) => {
    assert.throws(
      () => __test.repeatedProjection(options, () => {
        fs.writeFileSync(
          path.join(root, "node_modules/helper/between.js"),
          "export default false;\n",
          { mode: 0o600 },
        );
      }),
      /changed between repeated projections/,
    );
  });
});

test("directory and symlink retarget races are detected by metadata rechecks", async () => {
  await withFixture(async ({ root, options }) => {
    let changed = false;
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: {
          afterDirectoryRead(directory) {
            if (!changed && directory === root) {
              changed = true;
              fs.writeFileSync(path.join(root, "late-file"), "not-read\n", { mode: 0o600 });
            }
          },
        },
      }),
      /directory changed during projection/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    let changed = false;
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: {
          afterSymlinkRead(linkPath) {
            if (!changed && linkPath === shim) {
              changed = true;
              fs.unlinkSync(shim);
              fs.symlinkSync("../helper/index.js", shim);
            }
          },
        },
      }),
      /symlink changed during projection/,
    );
  });
});

test("initial root identity and every canonical ancestor identity are rechecked", async () => {
  await withFixture(async ({ root, options }) => {
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: {
          beforeTraversal() {
            fs.chmodSync(root, 0o500);
          },
        },
      }),
      /root changed before traversal/,
    );
    await chmod(root, 0o700);
  });
  await withFixture(async ({ root, options }) => {
    const ancestor = `${root}-ancestor`;
    const movedRoot = path.join(ancestor, "capsule");
    await makeDirectory(ancestor);
    await rename(root, movedRoot);
    try {
      await chmod(ancestor, 0o777);
      assert.throws(
        () => projectCloudflareUploaderCapsule({ ...options, capsuleRoot: movedRoot }),
        /unsafe ancestor directory/,
      );
      await chmod(ancestor, 0o700);
      assert.throws(
        () => __test.projectOnce({
          ...options,
          capsuleRoot: movedRoot,
          hooks: {
            beforeTraversal() {
              fs.chmodSync(ancestor, 0o500);
            },
          },
        }),
        /ancestor changed during projection/,
      );
    } finally {
      await chmod(ancestor, 0o700);
      await rename(movedRoot, root);
      await rm(ancestor, { recursive: true, force: true });
    }
  });
});

test("symlink escape, missing targets, cycles, and rogue bin shims fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    await unlink(shim);
    await symlink("../../../outside", shim);
    assert.throws(() => projectCloudflareUploaderCapsule(options), /symlink escapes its root/);
  });
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    await unlink(shim);
    fs.symlinkSync(Buffer.from([0xff]), shim);
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /non-UTF-8 symlink target/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    await unlink(shim);
    await symlink("../wrangler/bin/missing.js", shim);
    assert.throws(() => projectCloudflareUploaderCapsule(options), /target is absent/);
  });
  await withFixture(async ({ root, options }) => {
    const bin = path.join(root, "node_modules/.bin");
    const shim = path.join(bin, "wrangler");
    await unlink(shim);
    await symlink("cycle", shim);
    await symlink("wrangler", path.join(bin, "cycle"));
    assert.throws(() => projectCloudflareUploaderCapsule(options), /symlink cycle/);
  });
  await withFixture(async ({ root, options }) => {
    await symlink("../helper/index.js", path.join(root, "node_modules/.bin/rogue"));
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /does not match a declared package binary/,
    );
  });
});

test("hardlinks, unsafe modes, unsupported entries, and unclassified executables fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    await link(
      path.join(root, "node_modules/helper/index.js"),
      path.join(root, "node_modules/helper/hardlink.js"),
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /hard-linked/,
    );
  });
  await withFixture(async ({ root, options }) => {
    await chmod(path.join(root, "node_modules/helper/index.js"), 0o622);
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /unsafe, hard-linked, or oversized file/,
    );
  });
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(path.join(root, "node_modules/helper/tool"), Buffer.from([1, 2, 3]), 0o500);
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /unclassified executable/,
    );
  });
});

test("Mach-O, ELF, PE, archive, and WASM leading magic is labeled and digest-bound", async () => {
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(
      path.join(root, "node_modules/helper/native.node"),
      Buffer.from("feedfacf00000000", "hex"),
    );
    await writeOwnedFile(
      path.join(root, "node_modules/helper/runtime.wasm"),
      Buffer.from("0061736d01000000", "hex"),
    );
    await writeOwnedFile(
      path.join(root, "node_modules/helper/linux.bin"),
      Buffer.from("7f454c4601010100", "hex"),
    );
    await writeOwnedFile(
      path.join(root, "node_modules/helper/windows.bin"),
      Buffer.from("4d5a90000000", "hex"),
    );
    await writeOwnedFile(
      path.join(root, "node_modules/helper/static.a"),
      Buffer.from("!<arch>\nmember", "ascii"),
    );
    const projection = projectCloudflareUploaderCapsule(options);
    assert.deepEqual(
      projection.manifest.capabilities.nativeFiles.map(({ kind }) => kind),
      ["native_elf", "native_mach_o", "native_archive", "native_pe"],
    );
    assert.deepEqual(
      projection.manifest.capabilities.wasmFiles.map(({ path: filePath }) => filePath),
      ["node_modules/helper/runtime.wasm"],
    );
    const pin = pinCloudflareUploaderCapsule(projection);
    await writeOwnedFile(
      path.join(root, "node_modules/helper/native.node"),
      Buffer.from("feedfacf00000001", "hex"),
    );
    assert.throws(
      () => assertPinnedCloudflareUploaderCapsule(options, pin),
      /does not match its exact reviewed pin/,
    );
  });
});

test("native and WASM extensions require their narrowly allowed leading magic", async () => {
  for (const [name, expected] of [
    ["bad.node", /native addon extension\/magic mismatch/],
    ["bad.wasm", /WASM extension\/magic mismatch/],
    ["bad.dylib", /Mach-O extension\/magic mismatch/],
    ["bad.dll", /PE extension\/magic mismatch/],
    ["bad.exe", /PE extension\/magic mismatch/],
    ["bad.so", /shared-library extension\/magic mismatch/],
    ["bad.a", /native archive extension\/magic mismatch/],
  ]) {
    await withFixture(async ({ root, options }) => {
      await writeOwnedFile(path.join(root, `node_modules/helper/${name}`), "not-a-binary\n");
      assert.throws(() => projectCloudflareUploaderCapsule(options), expected);
    });
  }
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(
      path.join(root, "node_modules/helper/archive.node"),
      Buffer.from("!<arch>\nmember", "ascii"),
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /native addon extension\/magic mismatch/,
    );
  });
});

test("credential paths are rejected before their bodies or sibling file bodies are read", async () => {
  await withFixture(async ({ root, options }) => {
    const credential = path.join(root, ".env");
    await writeOwnedFile(credential, "CLOUDFLARE_API_TOKEN=must-not-be-read\n", 0o000);
    const reads = [];
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: { afterFileRead: (filePath) => reads.push(filePath) },
      }),
      /root contains undeclared files or configuration/,
    );
    assert.deepEqual(reads, []);
  });
  await withFixture(async ({ root, options }) => {
    const credential = path.join(root, "node_modules/helper/.env.local");
    await writeOwnedFile(credential, "SECRET=must-not-be-read\n", 0o000);
    const reads = [];
    assert.throws(
      () => __test.projectOnce({
        ...options,
        hooks: { afterFileRead: (filePath) => reads.push(filePath) },
      }),
      /forbidden credential-bearing path/,
    );
    assert.ok(!reads.includes(credential));
  });
});

test("path tricks, root aliases, and case-fold collisions fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(path.join(root, "node_modules/helper/bad\\name.js"), "export {};\n");
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /noncanonical path component/,
    );
  });
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(
      path.join(root, "node_modules/helper/bidi-\u202e.js"),
      "export {};\n",
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /noncanonical path component/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    await unlink(shim);
    await symlink("../wrangler/bin/\u202ewrangler.js", shim);
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /invalid symlink target/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const alias = `${root}-alias`;
    await symlink(root, alias);
    try {
      assert.throws(
        () => projectCloudflareUploaderCapsule({ ...options, capsuleRoot: alias }),
        /root is aliased or noncanonical/,
      );
    } finally {
      await unlink(alias);
    }
  });
  if (process.platform !== "darwin") {
    await withFixture(async ({ root, options }) => {
      await writeOwnedFile(path.join(root, "node_modules/helper/Case.js"), "export {};\n");
      await writeOwnedFile(path.join(root, "node_modules/helper/case.js"), "export {};\n");
      assert.throws(
        () => projectCloudflareUploaderCapsule(options),
        /case-folding path collision/,
      );
    });
  }
});

test("control and format characters in the absolute capsule root fail before traversal", async () => {
  const parent = await realpath(await mkdtemp(path.join(tmpdir(), "dnai-uploader-root-path-")));
  const unsafeRoot = path.join(parent, "capsule\nroot");
  try {
    await makeDirectory(unsafeRoot);
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        capsuleRoot: unsafeRoot,
        runtimeIdentity: runtimeIdentity(),
      }),
      /root is aliased or noncanonical/,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("entry, file, total, and path caps can only be tightened and fail before excess reads", async () => {
  await withFixture(async ({ options }) => {
    const fileReads = [];
    assert.throws(
      () => __test.projectOnce({
        ...options,
        limits: { maxEntries: 4 },
        hooks: { afterFileRead: (filePath) => fileReads.push(filePath) },
      }),
      /entry-count bound/,
    );
    assert.deepEqual(fileReads, []);
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxFileBytes: 16 },
      }),
      /per-file byte bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxTotalBytes: 32 },
      }),
      /total-byte bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxPathBytes: 20 },
      }),
      /path-byte bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxEntries: 75_001 },
      }),
      /outside its reviewed integer bound/,
    );
  });
});

test("lock, edge, JSON, and manifest complexity have independent strict caps", async () => {
  await withFixture(async ({ options }) => {
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxDependencyEdges: 1 },
      }),
      /dependency-edge bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxJsonFileBytes: 64 },
      }),
      /JSON descriptor byte bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxJsonTotalBytes: 64 },
      }),
      /total JSON byte bound/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxManifestBytes: 1_024 },
      }),
      /manifest-byte bound/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const lock = addSortedLockPackage(packageLock(), "node_modules/third", {
      version: "1.0.0",
      resolved: "https://registry.npmjs.org/third/-/third-1.0.0.tgz",
      integrity: INTEGRITY,
      optional: true,
    });
    await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxLockPackages: 2 },
      }),
      /lock-package bound/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const lock = packageLock();
    lock.packages["node_modules/helper"].boundedMetadata = {
      one: { two: { three: { four: true } } },
    };
    await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        limits: { maxJsonDepth: 4 },
      }),
      /JSON nesting bound/,
    );
  });
});

test("runtime identity substitutions and non-exact dependency versions fail closed", async () => {
  await withFixture(async ({ options }) => {
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        observedRuntimeIdentity: SYNTHETIC_KAT_OBSERVED_RUNTIME,
      }),
      /projection options are not exact/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        runtimeIdentity: runtimeIdentity({ architecture: "substituted" }),
      }),
      /does not match the executing host/,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule({
        ...options,
        runtimeIdentity: runtimeIdentity({ wranglerVersion: "^4.110.0" }),
      }),
      /not an exact version/,
    );
  });
});

test("duplicate JSON keys, lock drift, unlocked packages, and bin drift fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    await writeOwnedFile(
      path.join(root, "node_modules/wrangler/package.json"),
      `{"name":"wrangler","version":"${WRANGLER_VERSION}","version":"${WRANGLER_VERSION}","bin":{"wrangler":"bin/wrangler.js","wrangler2":"bin/wrangler.js","cf-wrangler":"bin/cf-wrangler.js"}}`,
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /duplicate object key/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const lock = packageLock();
    lock.packages["node_modules/helper"].integrity = "sha512-not-base64!";
    await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /unpinned dependency/,
    );
  });
  await withFixture(async ({ root, options }) => {
    await makeDirectory(path.join(root, "node_modules/rogue"));
    await writeOwnedFile(path.join(root, "node_modules/rogue/file.js"), "export {};\n");
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /bytes outside a locked package|undeclared nested package/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const shim = path.join(root, "node_modules/.bin/wrangler");
    await unlink(shim);
    await symlink("../helper/index.js", shim);
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /does not match a declared package binary|Wrangler executable identity is incomplete/,
    );
  });
});

test("lock package keys must use the exact supported npm package-root grammar", async () => {
  for (const invalidPath of [
    "node_modules/helper/not-a-package-root",
    "node_modules/Uppercase",
    "node_modules/@scope",
    "node_modules/@scope/name/child",
  ]) {
    await withFixture(async ({ root, options }) => {
      const lock = addSortedLockPackage(packageLock(), invalidPath, {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/invalid/-/invalid-1.0.0.tgz",
        integrity: INTEGRITY,
        optional: true,
      });
      await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
      assert.throws(
        () => projectCloudflareUploaderCapsule(options),
        /noncanonical package paths or ordering/,
      );
    });
  }
});

test("absent optional lock keys obey npm name, component, and total-path byte caps", async () => {
  const hugeNestedPath = `node_modules/a${"/node_modules/a".repeat(60)}`;
  for (const invalidPath of [
    `node_modules/${"a".repeat(215)}`,
    `node_modules/@${"a".repeat(215)}/name`,
    `node_modules/@scope/${"a".repeat(215)}`,
    `node_modules/${"a".repeat(256)}`,
    hugeNestedPath,
  ]) {
    await withFixture(async ({ root, options }) => {
      const lock = addSortedLockPackage(packageLock(), invalidPath, {
        version: "1.0.0",
        resolved: "https://registry.npmjs.org/invalid/-/invalid-1.0.0.tgz",
        integrity: INTEGRITY,
        optional: true,
      });
      await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
      assert.throws(
        () => projectCloudflareUploaderCapsule(options),
        /noncanonical package paths or ordering/,
      );
    });
  }
});

test("an absent required lock package cannot be blessed into a new pin", async () => {
  await withFixture(async ({ root, options }) => {
    await rm(path.join(root, "node_modules/helper"), { recursive: true, force: true });
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /missing a required locked package/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const lock = packageLock();
    lock.packages["node_modules/helper"].optional = true;
    await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
    await rm(path.join(root, "node_modules/helper"), { recursive: true, force: true });
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /missing a required dependency edge/,
    );
  });
});

test("undeclared nested packages and install-script metadata drift fail closed", async () => {
  await withFixture(async ({ root, options }) => {
    await makeDirectory(path.join(root, "node_modules/helper/node_modules/rogue"));
    await writeOwnedFile(
      path.join(root, "node_modules/helper/node_modules/rogue/payload.js"),
      "export const rogue = true;\n",
    );
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /undeclared node_modules directory|undeclared nested package/,
    );
  });
  await withFixture(async ({ root, options }) => {
    const lock = packageLock();
    delete lock.packages["node_modules/wrangler"].hasInstallScript;
    await writeOwnedFile(path.join(root, "package-lock.json"), canonicalJson(lock));
    assert.throws(
      () => projectCloudflareUploaderCapsule(options),
      /install script is not declared by package-lock.json/,
    );
  });
});
