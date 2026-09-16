import assert from "node:assert/strict";
import fs from "node:fs";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_SCHEMA,
  CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
  __test,
  assertCloudflareProductionUploaderAuthority,
  assertScopedCloudflarePagesToken,
  cloudflareUploaderRuntimeIdentity,
} from "./cloudflare-production-uploader-authority-core.mjs";
import {
  pinCloudflareUploaderCapsule,
  projectCloudflareUploaderCapsule,
} from "./cloudflare-uploader-capsule-core.mjs";

const NPM_VERSION = "11.6.0";
const WRANGLER_VERSION = "4.131.0";
const ACCOUNT_ID = "956388df29525b9e06f81581b485a571";
const PROJECT_NAME = "wikigenme";
const BRANCH = "main";
const TOKEN = "a".repeat(40);
const INTEGRITY = `sha512-${Buffer.alloc(64, 9).toString("base64")}`;
const DIST_MANIFEST = "a".repeat(64);
const BUNDLE_MANIFEST = "b".repeat(64);
const CONTROL_MANIFEST = "c".repeat(64);
const AUTHORITY_SCHEMA_URL = new URL(
  "../../deployments/cloudflare-production-uploader-authority.schema.json",
  import.meta.url,
);
const REPOSITORY_ROOT = path.resolve(
  path.dirname(fileURLToPath(AUTHORITY_SCHEMA_URL)),
  "..",
);
const WEB_ROOT = path.join(REPOSITORY_ROOT, "web");
const TEST_PRODUCER_UID =
  typeof process.geteuid === "function" ? process.geteuid() : 501;
const TEST_EXECUTOR_UID = TEST_PRODUCER_UID + 1;
const PRIVATE_RUNTIME_TEMP = fs.realpathSync.native(tmpdir());
const LOGIN_HOME = fs.realpathSync.native(userInfo().homedir);
const AUTHORITY_FIXTURE_PARENT = selectTrustedAuthorityFixtureParent();
const TEST_MODULE_PATH = path.join(
  WEB_ROOT,
  "scripts",
  "cloudflare-production-uploader-authority-core.test.mjs",
);
const RUNTIME = cloudflareUploaderRuntimeIdentity({
  nodeVersion: process.version,
  npmVersion: NPM_VERSION,
  wranglerVersion: WRANGLER_VERSION,
});

function canonical(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function hasTrustedAuthorityAncestorChain(root) {
  const producerUid = BigInt(TEST_PRODUCER_UID);
  const executorUid = BigInt(TEST_EXECUTOR_UID);
  let current = root;
  while (true) {
    const metadata = fs.lstatSync(current, { bigint: true });
    if (!metadata.isDirectory()
      || metadata.isSymbolicLink()
      || fs.realpathSync.native(current) !== current
      || (metadata.uid !== 0n && metadata.uid !== producerUid)
      || metadata.uid === executorUid
      || (metadata.mode & 0o022n) !== 0n) {
      return false;
    }
    const parent = path.dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

function isInsideRepository(candidate) {
  const relative = path.relative(REPOSITORY_ROOT, candidate);
  return relative === "" || (
    !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative)
  );
}

function selectTrustedAuthorityFixtureParent(
  privateRuntimeTemp = PRIVATE_RUNTIME_TEMP,
  loginHome = LOGIN_HOME,
) {
  for (const candidate of [privateRuntimeTemp, loginHome]) {
    if (!isInsideRepository(candidate)
      && hasTrustedAuthorityAncestorChain(candidate)) return candidate;
  }
  throw new Error("test host has no trusted producer-owned authority fixture root");
}

async function makeDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
}

async function writeOwned(filePath, value, mode = 0o600) {
  await writeFile(filePath, value, { mode });
  await chmod(filePath, mode);
}

async function freezeTree(root) {
  const metadata = await lstat(root);
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    for (const name of await readdir(root)) await freezeTree(path.join(root, name));
    await chmod(root, 0o555);
  } else {
    await chmod(root, (metadata.mode & 0o111) !== 0 ? 0o555 : 0o444);
  }
}

async function thawTree(root) {
  let metadata;
  try {
    metadata = await lstat(root);
  } catch {
    return;
  }
  if (metadata.isSymbolicLink()) return;
  if (metadata.isDirectory()) {
    await chmod(root, 0o700);
    for (const name of await readdir(root)) await thawTree(path.join(root, name));
  } else {
    await chmod(root, 0o600);
  }
}

async function cleanupFixtureRoot(root) {
  let thawError;
  try {
    await thawTree(root);
  } catch (error) {
    thawError = error;
  }
  try {
    await rm(root, { recursive: true, force: true });
  } catch (removeError) {
    if (thawError) {
      throw new AggregateError(
        [thawError, removeError],
        `could not thaw or remove fixture root ${root}`,
      );
    }
    throw removeError;
  }
  if (thawError) throw thawError;
}

function rootPackage() {
  return {
    dependencies: { wrangler: WRANGLER_VERSION },
    engines: { node: process.version.slice(1) },
    name: "dnai-cloudflare-release-uploader",
    packageManager: `npm@${NPM_VERSION}`,
    private: true,
    version: "0.0.0",
  };
}

function packageLock() {
  return {
    name: "dnai-cloudflare-release-uploader",
    version: "0.0.0",
    lockfileVersion: 3,
    requires: true,
    packages: {
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
        dependencies: { helper: "1.2.3" },
        bin: { wrangler: "bin/wrangler.js" },
      },
    },
  };
}

async function createCapsule(root) {
  for (const relative of [
    "node_modules",
    "node_modules/.bin",
    "node_modules/helper",
    "node_modules/wrangler",
    "node_modules/wrangler/bin",
  ]) await makeDirectory(path.join(root, relative));
  await writeOwned(path.join(root, "package.json"), canonical(rootPackage()));
  await writeOwned(path.join(root, "package-lock.json"), canonical(packageLock()));
  await writeOwned(
    path.join(root, "node_modules/.package-lock.json"),
    canonical({ lockfileVersion: 3, packages: {} }),
  );
  await writeOwned(
    path.join(root, "node_modules/helper/package.json"),
    canonical({ name: "helper", version: "1.2.3" }),
  );
  await writeOwned(
    path.join(root, "node_modules/helper/index.js"),
    "export const helper = true;\n",
  );
  await writeOwned(
    path.join(root, "node_modules/wrangler/package.json"),
    canonical({
      name: "wrangler",
      version: WRANGLER_VERSION,
      dependencies: { helper: "1.2.3" },
      bin: { wrangler: "bin/wrangler.js" },
    }),
  );
  await writeOwned(
    path.join(root, "node_modules/wrangler/bin/wrangler.js"),
    "#!/usr/bin/env node\nconsole.log('wrangler');\n",
    0o500,
  );
  await symlink(
    "../wrangler/bin/wrangler.js",
    path.join(root, "node_modules/.bin/wrangler"),
  );
}

async function createFixture() {
  const authorityRoot = await mkdtemp(path.join(
    AUTHORITY_FIXTURE_PARENT,
    ".uploader-authority-test-",
  ));
  try {
  const bundleRoot = path.join(authorityRoot, "bundle");
  const capsuleRoot = path.join(authorityRoot, "uploader");
  await makeDirectory(bundleRoot);
  await makeDirectory(path.join(bundleRoot, "dist"));
  await makeDirectory(path.join(bundleRoot, "functions"));
  await writeOwned(path.join(bundleRoot, "dist/index.html"), "<!doctype html>\n");
  await writeOwned(path.join(bundleRoot, "functions/_middleware.js"), "export default {};\n");
  await writeOwned(path.join(bundleRoot, "package.json"), "{}\n");
  await writeOwned(path.join(bundleRoot, "wrangler.toml"), "name = \"wikigenme\"\n");
  await makeDirectory(capsuleRoot);
  await createCapsule(capsuleRoot);
  await freezeTree(capsuleRoot);

  const producerUid = typeof process.geteuid === "function" ? process.geteuid() : 501;
  const executorUid = producerUid + 1;
  const capsulePin = pinCloudflareUploaderCapsule(
    projectCloudflareUploaderCapsule({
      capsuleRoot,
      delegatedReadOnly: true,
      expectedOwner: producerUid,
      runtimeIdentity: RUNTIME,
    }),
  );
  const authority = {
    account_id: ACCOUNT_ID,
    branch: BRANCH,
    bundle: {
      bundle_manifest_sha256: `sha256:${BUNDLE_MANIFEST}`,
      dist_manifest_sha256: `sha256:${DIST_MANIFEST}`,
      upload_control_manifest_sha256: `sha256:${CONTROL_MANIFEST}`,
    },
    credential_scope: {
      account_resource_id: ACCOUNT_ID,
      global_api_key_allowed: false,
      oauth_home_allowed: false,
      permission: __test.CLOUDFLARE_PAGES_EDIT_PERMISSION,
      review_status: __test.CREDENTIAL_REVIEW_STATUS,
      token_kind: "api_token",
    },
    executor_uid: executorUid,
    producer_uid: producerUid,
    project_name: PROJECT_NAME,
    schema: CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_SCHEMA,
    truth_status: CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
    uploader_capsule_pin: capsulePin,
  };
  await writeOwned(path.join(authorityRoot, "authority.json"), canonical(authority));
  await freezeTree(bundleRoot);
  await chmod(path.join(authorityRoot, "authority.json"), 0o444);
  await chmod(authorityRoot, 0o555);
  return {
    authority,
    authorityRoot,
    capsuleRoot,
    executorUid,
    producerUid,
    async cleanup() {
      await cleanupFixtureRoot(authorityRoot);
    },
  };
  } catch (error) {
    try {
      await cleanupFixtureRoot(authorityRoot);
    } catch (cleanupError) {
      throw new AggregateError(
        [error, cleanupError],
        `fixture construction and cleanup failed for ${authorityRoot}`,
      );
    }
    throw error;
  }
}

function validatorOptions(fixture, overrides = {}) {
  const calls = [];
  return {
    calls,
    options: {
      auditBuild: async ({ distDir, mode }) => {
        calls.push(["dist", distDir, mode]);
        return { manifestSha256: DIST_MANIFEST };
      },
      auditStage: async ({ stageDir, mode }) => {
        calls.push(["bundle", stageDir, mode]);
        return {
          bundleManifestSha256: BUNDLE_MANIFEST,
          distManifestSha256: DIST_MANIFEST,
          uploadControlManifestSha256: CONTROL_MANIFEST,
        };
      },
      authorityRoot: fixture.authorityRoot,
      credentialEnv: { CLOUDFLARE_API_TOKEN: TOKEN },
      env: {
        VITE_RELEASE_SHA: "1".repeat(40),
      },
      executorUid: fixture.executorUid,
      expectedAccountId: ACCOUNT_ID,
      expectedBranch: BRANCH,
      expectedBundleAudit: {
        bundleManifestSha256: BUNDLE_MANIFEST,
        distManifestSha256: DIST_MANIFEST,
        uploadControlManifestSha256: CONTROL_MANIFEST,
      },
      expectedDistAudit: { manifestSha256: DIST_MANIFEST },
      expectedProjectName: PROJECT_NAME,
      privateReleaseAudit: { fixture: true },
      runtimeIdentity: RUNTIME,
      sensitiveEnv: {},
      ...overrides,
    },
  };
}

test("fixture custody root is a trusted producer path outside executor-writable source ancestry", () => {
  assert.equal(fs.realpathSync(WEB_ROOT), WEB_ROOT);
  assert.equal(fs.realpathSync(AUTHORITY_FIXTURE_PARENT), AUTHORITY_FIXTURE_PARENT);
  assert.equal(hasTrustedAuthorityAncestorChain(AUTHORITY_FIXTURE_PARENT), true);
  const fixtureCandidate = path.join(
    AUTHORITY_FIXTURE_PARENT,
    ".uploader-authority-test-candidate",
  );
  const candidateFromWeb = path.relative(WEB_ROOT, fixtureCandidate);
  assert.equal(
    candidateFromWeb === "" || (
      !candidateFromWeb.startsWith(`..${path.sep}`)
      && !path.isAbsolute(candidateFromWeb)
    ),
    false,
  );
  const candidateFromRepository = path.relative(
    REPOSITORY_ROOT,
    fixtureCandidate,
  );
  assert.equal(
    candidateFromRepository === "" || (
      !candidateFromRepository.startsWith(`..${path.sep}`)
      && !path.isAbsolute(candidateFromRepository)
    ),
    false,
  );
  if (!hasTrustedAuthorityAncestorChain(PRIVATE_RUNTIME_TEMP)) {
    assert.equal(AUTHORITY_FIXTURE_PARENT, LOGIN_HOME);
    assert.notEqual(AUTHORITY_FIXTURE_PARENT, PRIVATE_RUNTIME_TEMP);
  }
  assert.equal(
    selectTrustedAuthorityFixtureParent(REPOSITORY_ROOT, AUTHORITY_FIXTURE_PARENT),
    AUTHORITY_FIXTURE_PARENT,
  );
  assert.equal(
    selectTrustedAuthorityFixtureParent(WEB_ROOT, AUTHORITY_FIXTURE_PARENT),
    AUTHORITY_FIXTURE_PARENT,
  );
  assert.equal(
    path.join(WEB_ROOT, "scripts", path.basename(TEST_MODULE_PATH)),
    TEST_MODULE_PATH,
  );
});

test("Linux-style exact-head source under world-writable tmp selects a separate trusted root", async () => {
  const unsafeExactHeadParent = await mkdtemp(path.join(
    fs.realpathSync.native("/tmp"),
    "dnai-exact-head-source-fixture.",
  ));
  try {
    assert.equal(hasTrustedAuthorityAncestorChain(unsafeExactHeadParent), false);
    assert.equal(
      selectTrustedAuthorityFixtureParent(unsafeExactHeadParent, LOGIN_HOME),
      LOGIN_HOME,
    );
  } finally {
    await rm(unsafeExactHeadParent, { recursive: true, force: true });
  }
});

test("accepts only a frozen different-principal bundle and minimal pinned uploader capsule", async () => {
  const fixture = await createFixture();
  try {
    const { calls, options } = validatorOptions(fixture);
    const result = await assertCloudflareProductionUploaderAuthority(options);
    assert.equal(result.exactProductionInput, true);
    assert.equal(result.truthStatus, CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS);
    assert.equal(result.bundleRoot, path.join(fixture.authorityRoot, "bundle"));
    assert.equal(result.uploaderCapsuleRoot, fixture.capsuleRoot);
    assert.equal(result.producerUid, fixture.producerUid);
    assert.match(result.authorityTreeManifestSha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(result.capsuleManifestSha256, /^sha256:[0-9a-f]{64}$/);
    assert.equal("token" in result, false);
    assert.deepEqual(calls, [
      ["dist", path.join(fixture.authorityRoot, "bundle/dist"), "live"],
      ["bundle", path.join(fixture.authorityRoot, "bundle"), "live"],
    ]);
  } finally {
    await fixture.cleanup();
  }
});

test("same-principal, root, writable-tree, and executor-writable-ancestor handoffs fail closed", async (context) => {
  await context.test("same principal", async () => {
    const fixture = await createFixture();
    try {
      await assert.rejects(
        assertCloudflareProductionUploaderAuthority(
          validatorOptions(fixture, { executorUid: fixture.producerUid }).options,
        ),
        /different principal/,
      );
    } finally {
      await fixture.cleanup();
    }
  });
  await context.test("root executor", async () => {
    const fixture = await createFixture();
    try {
      await assert.rejects(
        assertCloudflareProductionUploaderAuthority(
          validatorOptions(fixture, { executorUid: 0 }).options,
        ),
        /different principal/,
      );
    } finally {
      await fixture.cleanup();
    }
  });
  await context.test("writable file", async () => {
    const fixture = await createFixture();
    try {
      const target = path.join(fixture.authorityRoot, "authority.json");
      await chmod(target, 0o644);
      await assert.rejects(
        assertCloudflareProductionUploaderAuthority(validatorOptions(fixture).options),
        /frozen single-link/,
      );
    } finally {
      await fixture.cleanup();
    }
  });
  await context.test("world-writable ancestor", async () => {
    const unsafeParent = await mkdtemp(
      path.join(AUTHORITY_FIXTURE_PARENT, ".uploader-unsafe-parent-"),
    );
    const authorityRoot = path.join(unsafeParent, "authority");
    try {
      await makeDirectory(authorityRoot);
      await makeDirectory(path.join(authorityRoot, "bundle"));
      await makeDirectory(path.join(authorityRoot, "uploader"));
      await writeOwned(path.join(authorityRoot, "authority.json"), "{}\n");
      await freezeTree(authorityRoot);
      await chmod(unsafeParent, 0o777);
      assert.throws(
        () => __test.projectAuthorityTree({
          authorityRoot,
          executorUid: (typeof process.geteuid === "function" ? process.geteuid() : 501) + 1,
        }),
        /executor-writable or aliased ancestor/,
      );
    } finally {
      await chmod(unsafeParent, 0o700);
      await thawTree(authorityRoot);
      await rm(unsafeParent, { recursive: true, force: true });
    }
  });
});

test("bundle files preserve their audited owner mode while remaining read-only to the executor", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.authorityRoot, "bundle/dist/index.html");
    await chmod(target, 0o644);
    const result = await assertCloudflareProductionUploaderAuthority(
      validatorOptions(fixture).options,
    );
    assert.equal(result.exactProductionInput, true);
  } finally {
    await fixture.cleanup();
  }
});

test("credential handling requires a bounded API token and rejects OAuth/global-key fallbacks", () => {
  assert.equal(assertScopedCloudflarePagesToken({ CLOUDFLARE_API_TOKEN: TOKEN }), TOKEN);
  for (const env of [
    {},
    { CLOUDFLARE_API_TOKEN: "short" },
    { CLOUDFLARE_API_TOKEN: `${TOKEN}\n` },
    { CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_API_KEY: "global" },
    { CLOUDFLARE_API_TOKEN: TOKEN, CLOUDFLARE_EMAIL: "operator@example.com" },
  ]) {
    assert.throws(() => assertScopedCloudflarePagesToken(env), /Cloudflare upload/);
  }
});

test("authority metadata cannot bless digest, target, scope, identity, or schema drift", async () => {
  const mutations = [
    (value) => { value.account_id = "0".repeat(32); },
    (value) => { value.branch = "modeled-preview"; },
    (value) => { value.bundle.dist_manifest_sha256 = `sha256:${"d".repeat(64)}`; },
    (value) => { value.credential_scope.oauth_home_allowed = true; },
    (value) => { value.credential_scope.permission = "Account:Edit"; },
    (value) => { value.executor_uid += 1; },
    (value) => { value.schema = "dnai.cloudflare-production-uploader-authority.v0"; },
    (value) => { value.surprise = true; },
  ];
  for (const mutate of mutations) {
    const fixture = await createFixture();
    try {
      const authorityPath = path.join(fixture.authorityRoot, "authority.json");
      await chmod(fixture.authorityRoot, 0o755);
      await chmod(authorityPath, 0o600);
      const value = JSON.parse(await readFile(authorityPath, "utf8"));
      mutate(value);
      await writeOwned(authorityPath, canonical(value));
      await chmod(authorityPath, 0o444);
      await chmod(fixture.authorityRoot, 0o555);
      await assert.rejects(
        assertCloudflareProductionUploaderAuthority(validatorOptions(fixture).options),
        /authority|scope|release/,
      );
    } finally {
      await fixture.cleanup();
    }
  }
});

test("tree mutation between complete projections cannot become uploader authority", async () => {
  const fixture = await createFixture();
  try {
    const target = path.join(fixture.authorityRoot, "bundle/dist/index.html");
    assert.throws(
      () => __test.projectAuthorityTree({
        authorityRoot: fixture.authorityRoot,
        executorUid: fixture.executorUid,
        hooks: {
          betweenProjections() {
            fs.chmodSync(target, 0o644);
            fs.writeFileSync(target, "changed\n");
            fs.chmodSync(target, 0o444);
          },
        },
      }),
      /changed between projections/,
    );
  } finally {
    await fixture.cleanup();
  }
});

test("the descriptor is canonical and the scope declaration is not mislabeled as provider proof", async () => {
  const fixture = await createFixture();
  try {
    const authorityPath = path.join(fixture.authorityRoot, "authority.json");
    const canonicalBytes = await readFile(authorityPath, "utf8");
    await chmod(fixture.authorityRoot, 0o755);
    await chmod(authorityPath, 0o600);
    await writeOwned(authorityPath, canonicalBytes.trimEnd());
    await chmod(authorityPath, 0o444);
    await chmod(fixture.authorityRoot, 0o555);
    await assert.rejects(
      assertCloudflareProductionUploaderAuthority(validatorOptions(fixture).options),
      /not canonical/,
    );
    assert.match(
      CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
      /out_of_band_not_provider_verified/,
    );
  } finally {
    await fixture.cleanup();
  }
});

test("tracked authority schema and template preserve the production truth boundary", async () => {
  const schema = JSON.parse(await readFile(AUTHORITY_SCHEMA_URL, "utf8"));
  const template = JSON.parse(await readFile(new URL(
    "../../deployments/cloudflare-production-uploader-authority.template.json",
    import.meta.url,
  ), "utf8"));
  assert.equal(
    schema.properties.schema.const,
    CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_SCHEMA,
  );
  assert.equal(
    schema.properties.truth_status.const,
    CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
  );
  assert.equal(template.account_id, ACCOUNT_ID);
  assert.equal(template.project_name, PROJECT_NAME);
  assert.equal(template.branch, BRANCH);
  assert.equal(template.credential_scope.oauth_home_allowed, false);
  assert.equal(template.credential_scope.global_api_key_allowed, false);
  assert.equal(template.credential_scope.permission, "Cloudflare Pages:Edit");
  assert.equal(
    template.credential_scope.review_status,
    __test.CREDENTIAL_REVIEW_STATUS,
  );
  assert.equal(
    template.truth_status,
    CLOUDFLARE_PRODUCTION_UPLOADER_AUTHORITY_TRUTH_STATUS,
  );
});
