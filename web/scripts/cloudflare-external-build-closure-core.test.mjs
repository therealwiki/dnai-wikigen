import assert from "node:assert/strict";
import {
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
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
  __test as closureTest,
  canonicalCloudflareExternalBuildClosureText,
  cloudflareExternalBuildClosureSha256,
  CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
  CLOUDFLARE_EXTERNAL_BUILD_FILES,
  normalizeCloudflareExternalBuildClosure,
  projectCloudflareExternalBuildClosure,
} from "./cloudflare-external-build-closure-core.mjs";

const MODULE_SOURCES = Object.freeze({
  "scripts/canonical-authority-graph.mjs": "export const canonical = true;\n",
  "scripts/compute-workload-activation-observation-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { evidence } from "./phala-seven-cvm-historical-evidence-core.mjs";',
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const observation = canonical && evidence && release && signature;",
    "",
  ].join("\n"),
  "scripts/cvm-descriptor-runtime-authority-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { descriptors } from "./cvm-release-descriptor-set-constants.mjs";',
    "export const descriptor = canonical && descriptors;",
    "",
  ].join("\n"),
  "scripts/cvm-launch-intent-core.mjs": [
    'import { policy } from "./phala-production-execution-policy.mjs";',
    "export const launch = policy;",
    "",
  ].join("\n"),
  "scripts/cvm-release-descriptor-set-constants.mjs":
    "export const descriptors = true;\n",
  "scripts/ethereum-keccak.mjs": "export const keccak = true;\n",
  "scripts/execution-policy-release-core-cli.mjs": [
    'import { execution } from "./execution-policy-release-core.mjs";',
    "export const cli = execution;",
    "",
  ].join("\n"),
  "scripts/execution-policy-release-core.fixture.mjs": [
    'import { execution } from "./execution-policy-release-core.mjs";',
    "export const fixture = execution;",
    "",
  ].join("\n"),
  "scripts/execution-policy-release-core.mjs": [
    'import { keccak } from "./ethereum-keccak.mjs";',
    "export const execution = keccak;",
    "",
  ].join("\n"),
  "scripts/operator-policy-packet-core.mjs": [
    'import { execution } from "./execution-policy-release-core.mjs";',
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    "export const packet = execution && launch;",
    "",
  ].join("\n"),
  "scripts/phala-post-measurement-activation-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const activation = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-post-measurement-activation-receipt-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const receipt = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-production-execution-policy.mjs": "export const policy = true;\n",
  "scripts/phala-seven-cvm-historical-evidence-core.mjs": [
    'import { runtime } from "./phala-seven-cvm-historical-runtime-binding-core.mjs";',
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { measurement } from "./phala-seven-cvm-measurement-policy.mjs";',
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    'import { replay } from "../web/scripts/independent-eip191-replay-core.mjs";',
    "export const evidence = runtime && transcript && measurement && release && replay;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-runtime-binding-core.mjs": [
    'import { transcript } from "./phala-seven-cvm-historical-transcript.mjs";',
    'import { release } from "./phala-seven-cvm-release-verification-authority-core.mjs";',
    "export const runtime = transcript && release;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-historical-transcript.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const transcript = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-measurement-policy.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    "export const measurement = canonical;",
    "",
  ].join("\n"),
  "scripts/phala-seven-cvm-release-verification-authority-core.mjs": [
    'import { launch } from "./cvm-launch-intent-core.mjs";',
    'import { descriptor } from "./cvm-descriptor-runtime-authority-core.mjs";',
    'import { measurement } from "./phala-seven-cvm-measurement-policy.mjs";',
    "export const release = launch && descriptor && measurement;",
    "",
  ].join("\n"),
  "scripts/pre-ceremony-runtime-authority-core.mjs": [
    'import { activation } from "./phala-post-measurement-activation-core.mjs";',
    'import { runtime } from "./phala-seven-cvm-historical-runtime-binding-core.mjs";',
    "export const preCeremony = activation && runtime;",
    "",
  ].join("\n"),
  "scripts/release-authority-historical-core.mjs": [
    'import { canonical } from "./canonical-authority-graph.mjs";',
    'import { receipt } from "./phala-post-measurement-activation-receipt-core.mjs";',
    'import { signature } from "./release-authority-signature-verifier-core.mjs";',
    "export const historical = canonical && receipt && signature;",
    "",
  ].join("\n"),
  "scripts/release-authority-signature-verifier-core.mjs": [
    'import { replay } from "../web/scripts/independent-eip191-replay-core.mjs";',
    "export const signature = replay;",
    "",
  ].join("\n"),
  "scripts/release-manifest-sigstore-verifier.mjs": [
    'import { createHash } from "node:crypto";',
    'export const verifier = createHash("sha256").digest("hex");',
    "",
  ].join("\n"),
  "web/scripts/independent-eip191-replay-core.mjs": [
    'import "@noble/curves/secp256k1";',
    'import "@noble/hashes/sha3";',
    'import "@noble/hashes/utils";',
    "export const replay = true;",
    "",
  ].join("\n"),
});

const WEB_SCRIPT_SOURCES = Object.freeze({
  "web/scripts/build-release-env.mjs": [
    'import "../../scripts/execution-policy-release-core-cli.mjs";',
    'import "../../scripts/operator-policy-packet-core.mjs";',
    'import "../../scripts/phala-seven-cvm-historical-transcript.mjs";',
    'import "../../scripts/release-manifest-sigstore-verifier.mjs";',
    "",
  ].join("\n"),
  "web/scripts/deploy-cloudflare-core.test.mjs":
    'import "../../scripts/compute-workload-activation-observation-core.mjs";\n',
  "web/scripts/execution-policy-release-core-binding.mjs": [
    'import "../../scripts/execution-policy-release-core.mjs";',
    'import "../../scripts/pre-ceremony-runtime-authority-core.mjs";',
    "",
  ].join("\n"),
  "web/scripts/external-five-historical-evidence-core.mjs":
    'import "../../scripts/canonical-authority-graph.mjs";\n',
  "web/scripts/frontend-release-historical-core.mjs": [
    'import "../../scripts/canonical-authority-graph.mjs";',
    'import "../../scripts/execution-policy-release-core.mjs";',
    'import "../../scripts/release-authority-historical-core.mjs";',
    "",
  ].join("\n"),
  "web/scripts/frontend-release-historical-core.test.mjs": [
    'import "../../scripts/execution-policy-release-core.fixture.mjs";',
    'import "../../scripts/execution-policy-release-core.mjs";',
    "",
  ].join("\n"),
  "web/scripts/release-env-core.mjs":
    'import "../../scripts/compute-workload-activation-observation-core.mjs";\n',
  "web/scripts/release-env-core.test.mjs": [
    "export const filter = new URL(",
    '  "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",',
    "  import.meta.url,",
    ");",
    "",
  ].join("\n"),
});

const WEB_SOURCE_CONSUMERS = Object.freeze({
  "web/src/productTruth.test.ts": [
    'import architecture from "../../ARCHITECTURE.md?raw";',
    'import project from "../../PROJECT.md?raw";',
    'import readme from "../../README.md?raw";',
    "export { architecture, project, readme };",
    "",
  ].join("\n"),
  "web/src/views/Overview.tsx": [
    'import image from "../assets/pitch/private-reward-oracle.webp";',
    "export const Overview = () => image;",
    "",
  ].join("\n"),
  "web/src/views/Verify.tsx": [
    'import image from "../assets/pitch/attested-network.webp";',
    "export const Verify = () => image;",
    "",
  ].join("\n"),
});

const RESOURCE_BYTES = Object.freeze({
  ".gitignore": "node_modules/\ndist/\n",
  "ARCHITECTURE.md": "# Architecture\nBound fixture.\n",
  "PROJECT.md": "# Project\nBound fixture.\n",
  "README.md": "# Readme\nBound fixture.\n",
  "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq":
    ". as $manifest | $manifest\n",
});

async function writeFixtureFile(root, relative, content) {
  const target = path.join(root, ...relative.split("/"));
  await mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
  await writeFile(target, content, { mode: 0o644 });
  await chmod(target, 0o644);
}

async function createFixture() {
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const root = await mkdtemp(path.join(canonicalTemporaryRoot, "dnai-external-closure-"));
  await chmod(root, 0o700);
  for (const [relative, content] of Object.entries({
    ...MODULE_SOURCES,
    ...WEB_SCRIPT_SOURCES,
    ...WEB_SOURCE_CONSUMERS,
    ...RESOURCE_BYTES,
  })) {
    await writeFixtureFile(root, relative, content);
  }
  return root;
}

async function withFixture(callback) {
  const root = await createFixture();
  try {
    return await callback(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("external closure is exact, typed, canonical, and domain separated", async () => {
  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    assert.deepEqual(
      closure.entrypoints,
      CLOUDFLARE_EXTERNAL_BUILD_ENTRYPOINTS,
    );
    assert.deepEqual(
      closure.files.map(({ kind, path: filePath }) => ({ kind, path: filePath })),
      CLOUDFLARE_EXTERNAL_BUILD_FILES.map(({ kind, path: filePath }) => ({
        kind,
        path: filePath,
      })),
    );
    assert.equal(closure.raw_secret_egress, false);
    assert.deepEqual(normalizeCloudflareExternalBuildClosure(closure), closure);
    assert.equal(
      canonicalCloudflareExternalBuildClosureText(closure),
      `${JSON.stringify(closure, null, 2)}\n`,
    );
    assert.match(closure.aggregate_sha256, /^sha256:[0-9a-f]{64}$/);
    assert.match(
      cloudflareExternalBuildClosureSha256(closure),
      /^sha256:[0-9a-f]{64}$/,
    );
    assert.notEqual(
      cloudflareExternalBuildClosureSha256(closure),
      closure.aggregate_sha256,
    );
    // This KAT freezes the closure algorithm and canonicalization over the
    // synthetic graph above. It is intentionally separate from the real
    // checked-in source projection KAT at the end of this file.
    assert.equal(
      closure.aggregate_sha256,
      "sha256:d27c82d8196b1ea9fe8ca60bffb7033ecc45d9338331c542c077cc6923ea7cd2",
    );
    assert.equal(
      cloudflareExternalBuildClosureSha256(closure),
      "sha256:ed35b3badf8e1fa8ef5ba7a05389f53285703b141b9ae45c269856eb7ebab804",
    );
  });
});

test("closure rejects omission, undeclared transitive imports, extras, and back-edges", async () => {
  await withFixture(async (root) => {
    await unlink(path.join(root, "scripts/ethereum-keccak.mjs"));
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /missing/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "./undeclared.mjs";\nexport const canonical = true;\n',
    );
    await writeFixtureFile(root, "scripts/undeclared.mjs", "export default true;\n");
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared import|back-edge/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/unbound-consumer.mjs",
      'import "../../scripts/unbound.mjs";\n',
    );
    await writeFixtureFile(root, "scripts/unbound.mjs", "export default true;\n");
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared external import/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "../web/scripts/build-release-env.mjs";\nexport const canonical = true;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /undeclared import|back-edge/,
    );
  });

  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    const extra = structuredClone(closure);
    extra.files.push({ ...extra.files.at(-1), path: "scripts/extra.mjs" });
    assert.throws(
      () => normalizeCloudflareExternalBuildClosure(extra),
      /not exact|incomplete/,
    );
  });
});

test("jq, content, mode, and aggregate substitutions cannot preserve authority", async () => {
  await withFixture(async (root) => {
    const baseline = await projectCloudflareExternalBuildClosure(root);
    await writeFixtureFile(
      root,
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
      ". as $substituted | $substituted\n",
    );
    const substituted = await projectCloudflareExternalBuildClosure(root);
    assert.notEqual(substituted.aggregate_sha256, baseline.aggregate_sha256);
    await unlink(path.join(
      root,
      "⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
    ));
    await assert.rejects(projectCloudflareExternalBuildClosure(root), /missing/);
  });

  await withFixture(async (root) => {
    const baseline = await projectCloudflareExternalBuildClosure(root);
    const target = path.join(root, "README.md");
    await chmod(target, 0o600);
    const modeChanged = await projectCloudflareExternalBuildClosure(root);
    assert.notEqual(modeChanged.aggregate_sha256, baseline.aggregate_sha256);
    await chmod(target, 0o664);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /owner-controlled/,
    );
  });

  await withFixture(async (root) => {
    const closure = await projectCloudflareExternalBuildClosure(root);
    const forged = structuredClone(closure);
    forged.files[0].sha256 = `sha256:${"f".repeat(64)}`;
    assert.throws(
      () => normalizeCloudflareExternalBuildClosure(forged),
      /aggregate is invalid/,
    );
  });
});

test("symlinked and hard-linked closure files fail before projection", async () => {
  await withFixture(async (root) => {
    const target = path.join(root, "README.md");
    const real = path.join(root, "README.real.md");
    const content = await readFile(target);
    await unlink(target);
    await writeFixtureFile(root, "README.real.md", content);
    await symlink(real, target);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /symlinked or aliased/,
    );
  });

  await withFixture(async (root) => {
    const target = path.join(root, "PROJECT.md");
    const alias = path.join(root, "PROJECT.alias.md");
    await link(target, alias);
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /single-link/,
    );
  });
});

test("external module parser rejects dynamic loading, CommonJS, bare packages, and cycles", async () => {
  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      'export const escaped = import("../../scripts/canonical-authority-graph.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      'export const escaped = require("../../scripts/canonical-authority-graph.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = import("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "web/scripts/runtime-escape.mjs",
      [
        'import { createRequire } from "node:module";',
        "const loader = createRequire(import.meta.url);",
        'export const escaped = loader("../../scripts/canonical-authority-graph.mjs");',
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require in any consumer/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = module.require("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = module["require"]("./ethereum-keccak.mjs");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = new Function("return true")();\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'const Dynamic = (() => {}).constructor;\nexport const canonical = Dynamic("return true")();\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'export const canonical = (0, eval)("true");\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      [
        'import { Worker as BackgroundTask } from "node:worker_threads";',
        'export const canonical = new BackgroundTask("./ethereum-keccak.mjs");',
        "",
      ].join("\n"),
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'const value = require("./ethereum-keccak.mjs");\nexport { value as canonical };\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /dynamic import or CommonJS require/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import value from "mutable-package";\nexport const canonical = value;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /bare package/,
    );
  });

  await withFixture(async (root) => {
    await writeFixtureFile(
      root,
      "scripts/canonical-authority-graph.mjs",
      'import "./compute-workload-activation-observation-core.mjs";\nexport const canonical = true;\n',
    );
    await assert.rejects(
      projectCloudflareExternalBuildClosure(root),
      /cycle/,
    );
  });
});

test("real checked-in external bytes match the final release projection KAT", async () => {
  const repositoryRoot = path.resolve(new URL("../..", import.meta.url).pathname);
  const closure = await projectCloudflareExternalBuildClosure(repositoryRoot);
  assert.equal(closure.entrypoints.length, 15);
  assert.equal(closure.files.length, 27);
  assert.equal(
    closure.aggregate_sha256,
    "sha256:9020f8b94af2cf176e391f6a3cac7325a57cc9afc8398451058bcc4b853e742f",
  );
  assert.equal(
    cloudflareExternalBuildClosureSha256(closure),
    "sha256:b6760391961abc0759fbdf550caff9e9eebadbc5b73d1b2981c37a800b3fea87",
  );
  assert.equal(closureTest.MODULE_ENTRYPOINT_PATHS.length, 10);
  assert.equal(closureTest.MODULE_CLOSURE_PATHS.length, 22);
  assert.deepEqual(closureTest.MODULE_WEB_BACKEDGE_PATHS, [
    "web/scripts/independent-eip191-replay-core.mjs",
  ]);
  assert.deepEqual(closureTest.MODULE_BARE_PACKAGE_IMPORTS, [
    "@noble/curves/secp256k1",
    "@noble/hashes/sha3",
    "@noble/hashes/utils",
  ]);
  assert.equal(closureTest.RESOURCE_DEFINITIONS.length, 5);
});
