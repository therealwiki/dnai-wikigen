import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  auditCloudflareBuild,
  auditCloudflareStage,
  __test as artifactTest,
  CLOUDFLARE_D_BUILD_CONTROL_PATHS,
  cloudflareFrontendBuildControlFiles,
  cloudflareSourceFingerprint,
  cloudflareSourceFingerprintSha256,
  cloudflareUploadControlFingerprint,
  deploymentViteEnvironmentDigest,
  loadPrivateFrontendCandidateArtifactAudit,
  loadPrivateReleaseArtifactAudit,
  removeCloudflareStage,
  resetCloudflareBuildOutput,
  stageCloudflareBundle,
} from "./cloudflare-release-artifact-core.mjs";
import { renderProductionHeadersForEnv } from "./security-headers-core.mjs";

const SHA = "1".repeat(40);

test("reviewed Pages configuration omits Wrangler's unsupported account_id field", () => {
  assert.doesNotMatch(artifactTest.EXPECTED_WRANGLER_CONFIG, /^account_id\s*=/m);
  assert.match(artifactTest.EXPECTED_WRANGLER_CONFIG, /^name = "wikigenme"$/m);
  assert.match(artifactTest.EXPECTED_WRANGLER_CONFIG, /^pages_build_output_dir = "\.\/dist"$/m);
});

test("D build controls are an exact stable 26-file projection", async () => {
  assert.deepEqual(CLOUDFLARE_D_BUILD_CONTROL_PATHS, [
    "web/functions/_middleware.js",
    "web/index.html",
    "web/package-lock.json",
    "web/package.json",
    "web/public/wikigen-bootstrap-v3.js",
    "web/scripts/build-release-env.mjs",
    "web/scripts/build-security-headers.mjs",
    "web/scripts/cloudflare-build-sandbox-core.mjs",
    "web/scripts/collaboration-execution-release-env-core.mjs",
    "web/scripts/cloudflare-external-build-closure-core.mjs",
    "web/scripts/cloudflare-release-artifact-core.mjs",
    "web/scripts/deploy-cloudflare-core.mjs",
    "web/scripts/deploy-cloudflare.mjs",
    "web/scripts/durable-private-file-core.mjs",
    "web/scripts/execution-policy-release-core-binding.mjs",
    "web/scripts/frontend-build-candidate-core.mjs",
    "web/scripts/frontend-build-candidate-producer-core.mjs",
    "web/scripts/public-https-origin-core.mjs",
    "web/scripts/release-build-home-core.mjs",
    "web/scripts/release-runtime-pins-core.mjs",
    "web/scripts/release-env-core.mjs",
    "web/scripts/royalty-release-env-core.mjs",
    "web/scripts/security-headers-core.mjs",
    "web/tsconfig.json",
    "web/vite.config.ts",
    "web/wrangler.toml",
  ]);
  const repoRoot = path.resolve(new URL("../..", import.meta.url).pathname);
  const files = await cloudflareFrontendBuildControlFiles(repoRoot);
  assert.equal(Object.isFrozen(files), true);
  assert.deepEqual(files.map((entry) => entry.path), CLOUDFLARE_D_BUILD_CONTROL_PATHS);
  for (const entry of files) {
    assert.equal(Object.isFrozen(entry), true);
    assert.match(entry.sha256, /^sha256:[0-9a-f]{64}$/);
  }
});

async function writePrivateReleaseInputs(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const args = [];
  const values = new Map();
  for (const [index, flag] of artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.entries()) {
    const fileName = `${flag.slice(2).replaceAll("-", "_")}_private.json`;
    const filePath = path.join(directory, fileName);
    const value = flag === "--release"
      ? {
        schema: "synthetic-live-release",
        operator_policy: {
          schema: "dnai.live-activation-authority-evidence.v1",
          live_activation_authority_sha256: `sha256:${"ab".repeat(32)}`,
          signature: `0x${"cd".repeat(65)}`,
        },
      }
      : flag === "--compute-workload-activation-observation"
        ? {
          schema: "dnai.compute-workload-activation-observation.v1",
          status: "compute_workload_recipient_activation_machine_verified",
          truth_status:
            "private_nonauthorizing_prebuild_observation_not_live_traffic_or_deploy_authority",
          live_traffic_authorized: false,
          deploy_authorized: false,
          raw_quote_persisted: false,
          raw_secret_egress: false,
          private_receipt_path: `/private/tmp/dnai-release/${fileName}`,
        }
      : {
        schema: `synthetic-private-input-${index}`,
        private_receipt_path: `/private/tmp/dnai-release/${fileName}`,
        signature: `0x${(index + 1).toString(16).padStart(2, "0").repeat(65)}`,
    };
    await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
    const canonicalFilePath = await realpath(filePath);
    args.push(flag, canonicalFilePath);
    values.set(flag, { fileName, filePath: canonicalFilePath, value });
  }
  return {
    args,
    values,
    audit: await loadPrivateReleaseArtifactAudit(args),
  };
}

async function writeValidDist(distDir, {
  env = {},
  releaseSha = "",
  extraAsset = "",
} = {}) {
  await mkdir(path.join(distDir, "assets", "r2"), { recursive: true });
  await writeFile(path.join(distDir, "index.html"), [
    "<!doctype html>",
    '<link rel="canonical" href="https://www.wikigen.me/" />',
    '<script src="/wikigen-bootstrap-v3.js"></script>',
    '<script type="module" src="/assets/r2/index-release.js"></script>',
    '<link rel="stylesheet" href="/assets/r2/index-release.css" />',
    "",
  ].join("\n"));
  await writeFile(path.join(distDir, "wikigen-bootstrap-v3.js"), 'document.documentElement.dataset.bootstrap="v3";\n');
  await writeFile(path.join(distDir, "_headers"), renderProductionHeadersForEnv(env));
  await writeFile(
    path.join(distDir, "assets", "r2", "index-release.js"),
    `globalThis.__release=${JSON.stringify(releaseSha)};${extraAsset}\n`,
  );
  await writeFile(path.join(distDir, "assets", "r2", "index-release.css"), ":root{color-scheme:dark}\n");
}

test("modeled and live build audits bind exact headers, assets, and release SHA", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-artifact-"));
  try {
    const modeled = path.join(directory, "modeled");
    await writeValidDist(modeled);
    const modeledAudit = await auditCloudflareBuild({
      distDir: modeled,
      mode: "modeled",
      sensitiveEnv: {},
    });
    assert.equal(modeledAudit.fileCount, 5);
    assert.match(modeledAudit.manifestSha256, /^[0-9a-f]{64}$/);

    const live = path.join(directory, "live");
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    const env = {
      VITE_ENABLE_ARTIFACT_UPLOAD: "true",
      VITE_DELEGATE_URL: "https://delegate.release.wikigen.me",
    };
    await writeValidDist(live, { env, releaseSha: SHA });
    const liveAudit = await auditCloudflareBuild({
      distDir: live,
      env,
      mode: "live",
      releaseSha: SHA,
      sensitiveEnv: {},
      privateReleaseAudit: privateInputs.audit,
    });
    assert.notEqual(liveAudit.manifestSha256, modeledAudit.manifestSha256);

    await writeFile(path.join(live, "_headers"), renderProductionHeadersForEnv({}));
    await assert.rejects(
      auditCloudflareBuild({
        distDir: live,
        env,
        mode: "live",
        releaseSha: SHA,
        sensitiveEnv: {},
        privateReleaseAudit: privateInputs.audit,
      }),
      /security headers do not match/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("pre-C candidate audit requires exactly 36 acyclic inputs and scans the fresh dist", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-candidate-audit-"));
  try {
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-candidate-inputs"),
    );
    const candidateArgs = privateInputs.args.filter((value, index, values) => (
      index % 2 === 0
        ? artifactTest.REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS.includes(value)
        : artifactTest.REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS.includes(values[index - 1])
    ));
    const audit = await loadPrivateFrontendCandidateArtifactAudit(candidateArgs);
    assert.equal(audit.schema, artifactTest.PRIVATE_FRONTEND_CANDIDATE_AUDIT_SCHEMA);
    assert.equal(audit.inputs.length, 36);
    assert.deepEqual(
      audit.inputs.map(({ flag }) => flag),
      [...artifactTest.REQUIRED_PRIVATE_FRONTEND_CANDIDATE_FLAGS]
        .sort((left, right) => left.localeCompare(right, "en")),
    );

    const dist = path.join(directory, "dist");
    await writeValidDist(dist, { releaseSha: SHA });
    const build = await auditCloudflareBuild({
      distDir: dist,
      mode: "candidate",
      releaseSha: SHA,
      sensitiveEnv: {},
      privateReleaseAudit: audit,
    });
    assert.equal(build.fileCount, 5);

    for (const forbidden of [
      "--live-activation-authority",
      "--frontend-build-candidate-receipt",
    ]) {
      const offset = privateInputs.args.indexOf(forbidden);
      await assert.rejects(
        loadPrivateFrontendCandidateArtifactAudit([
          ...candidateArgs,
          privateInputs.args[offset],
          privateInputs.args[offset + 1],
        ]),
        /unknown or legacy validator argument/,
      );
    }

    const leaked = Buffer.from(
      privateInputs.values.get("--compute-workload-activation-observation")
        .filePath,
      "utf8",
    ).toString("base64");
    await writeFile(
      path.join(dist, "assets", "r2", "index-release.js"),
      `globalThis.__release=${JSON.stringify(SHA)};globalThis.__leak=${JSON.stringify(leaked)};\n`,
    );
    await assert.rejects(
      auditCloudflareBuild({
        distDir: dist,
        mode: "candidate",
        releaseSha: SHA,
        sensitiveEnv: {},
        privateReleaseAudit: audit,
      }),
      /private release authority, receipt, signature, path, or reversible encoding/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("build audit rejects stale source graphs, symlinks, source maps, and missing release binding", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-invalid-"));
  try {
    const dist = path.join(directory, "dist");
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    await writeValidDist(dist);
    await assert.rejects(
      auditCloudflareBuild({
        distDir: dist,
        mode: "live",
        releaseSha: SHA,
        sensitiveEnv: {},
        privateReleaseAudit: privateInputs.audit,
      }),
      /does not contain its exact release SHA/,
    );

    await writeFile(path.join(dist, "assets", "r2", "index-release.js.map"), "{}\n");
    await assert.rejects(
      auditCloudflareBuild({ distDir: dist, mode: "modeled", sensitiveEnv: {} }),
      /forbidden credential or source-map path/,
    );
    await rm(path.join(dist, "assets", "r2", "index-release.js.map"));

    await symlink(path.join(dist, "index.html"), path.join(dist, "linked-index.html"));
    await assert.rejects(
      auditCloudflareBuild({ distDir: dist, mode: "modeled", sensitiveEnv: {} }),
      /symbolic link/,
    );
    await rm(path.join(dist, "linked-index.html"));

    await link(path.join(dist, "index.html"), path.join(dist, "hard-linked-index.html"));
    await assert.rejects(
      auditCloudflareBuild({ distDir: dist, mode: "modeled", sensitiveEnv: {} }),
      /hard-linked entry/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("build audit rejects competing or Wrangler-ignored Pages control paths", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-pages-control-"));
  try {
    const cases = [
      "_redirects",
      "_routes.json",
      "_worker.js",
      "functions/ignored.txt",
      "node_modules/ignored.txt",
      ".git/ignored.txt",
      ".wrangler/ignored.txt",
      "nested/.DS_Store",
    ];
    for (const [index, relative] of cases.entries()) {
      const dist = path.join(directory, `dist-${index}`);
      await writeValidDist(dist);
      const target = path.join(dist, relative);
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, "unreviewed Pages behavior\n");
      await assert.rejects(
        auditCloudflareBuild({ distDir: dist, mode: "modeled", sensitiveEnv: {} }),
        /competing or ignored Pages control path/,
        relative,
      );
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("live build audit rejects raw, canonical, encoded, signature, and private-path release artifact egress", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-private-egress-"));
  try {
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    const c = privateInputs.values.get("--live-activation-authority");
    const observation = privateInputs.values.get(
      "--compute-workload-activation-observation",
    );
    const release = privateInputs.values.get("--release");
    const cases = [
      `${JSON.stringify(c.value)}\n`,
      JSON.stringify(release.value.operator_policy),
      c.value.signature,
      c.filePath,
      c.fileName,
      `${JSON.stringify(observation.value)}\n`,
      JSON.stringify(observation.value, null, 2),
      observation.filePath,
      observation.fileName,
      Buffer.from(c.value.signature, "utf8").toString("base64"),
      Buffer.from(JSON.stringify(observation.value), "utf8").toString("base64url"),
      Buffer.from(c.filePath, "utf8").toString("hex"),
      encodeURIComponent(c.filePath),
    ];
    for (const [index, leaked] of cases.entries()) {
      const dist = path.join(directory, `dist-${index}`);
      await writeValidDist(dist, {
        releaseSha: SHA,
        extraAsset: `globalThis.privateReleaseLeak=${JSON.stringify(leaked)};`,
      });
      await assert.rejects(
        auditCloudflareBuild({
          distDir: dist,
          mode: "live",
          releaseSha: SHA,
          sensitiveEnv: {},
          privateReleaseAudit: privateInputs.audit,
        }),
        /private release authority, receipt, signature, path, or reversible encoding/,
      );
    }

    const cleanDist = path.join(directory, "clean-dist");
    await writeValidDist(cleanDist, { releaseSha: SHA });
    await assert.rejects(
      auditCloudflareBuild({
        distDir: cleanDist,
        mode: "live",
        releaseSha: SHA,
        sensitiveEnv: {},
      }),
      /requires a private release artifact audit/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("private release audit rejects aliased files and duplicate semantic inputs", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-private-inputs-"));
  try {
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    const first = privateInputs.values.get("--bootstrap-authority");
    const second = privateInputs.values.get("--bootstrap-authorization");
    await writeFile(
      second.filePath,
      `${JSON.stringify(first.value, null, 2)}\n`,
      { mode: 0o600 },
    );
    await assert.rejects(
      loadPrivateReleaseArtifactAudit(privateInputs.args),
      /duplicate or colliding object/,
    );

    const refreshed = await writePrivateReleaseInputs(
      path.join(directory, "refreshed-private-release-inputs"),
    );
    const aliasArgs = [...refreshed.args];
    const aliasedIndex = aliasArgs.indexOf("--bootstrap-authorization") + 1;
    aliasArgs[aliasedIndex] = refreshed.values.get("--bootstrap-authority").filePath;
    await assert.rejects(
      loadPrivateReleaseArtifactAudit(aliasArgs),
      /distinct files/,
    );

    const writable = await writePrivateReleaseInputs(
      path.join(directory, "shared-writable-private-release-inputs"),
    );
    const writableObservation = writable.values.get(
      "--compute-workload-activation-observation",
    );
    await chmod(writableObservation.filePath, 0o622);
    await assert.rejects(
      loadPrivateReleaseArtifactAudit(writable.args),
      /bounded single-link regular file/,
    );

    const hardlinked = await writePrivateReleaseInputs(
      path.join(directory, "hardlinked-private-release-inputs"),
    );
    const hardlinkedObservation = hardlinked.values.get(
      "--compute-workload-activation-observation",
    );
    await link(
      hardlinkedObservation.filePath,
      path.join(directory, "observation-hardlink.json"),
    );
    await assert.rejects(
      loadPrivateReleaseArtifactAudit(hardlinked.args),
      /bounded single-link regular file/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("private release audit normalization rejects a fingerprinted 39th input", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-extra-private-input-"));
  try {
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    assert.equal(artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.length, 38);
    assert.equal(privateInputs.audit.inputs.length, 38);
    assert.deepEqual(
      privateInputs.audit.inputs.map(({ flag }) => flag),
      [...artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS]
        .sort((left, right) => left.localeCompare(right, "en")),
    );
    const forged = structuredClone(privateInputs.audit);
    forged.inputs.push({
      flag: "--zz-extra",
      content_sha256: "e".repeat(64),
      semantic_sha256: "f".repeat(64),
    });
    forged.inputs.sort((left, right) => left.flag.localeCompare(right.flag, "en"));
    const payload = {
      schema: forged.schema,
      inputs: forged.inputs,
      needles: forged.needles,
    };
    forged.fingerprintSha256 = createHash("sha256")
      .update(`${JSON.stringify(payload, null, 2)}\n`)
      .digest("hex");
    assert.throws(
      () => artifactTest.normalizePrivateReleaseArtifactAudit(forged),
      /incomplete/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("private release audit requires seven-domain raw proofs and rejects stale six-CVM evidence", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-seven-domain-"));
  try {
    const privateInputs = await writePrivateReleaseInputs(
      path.join(directory, "private-release-inputs"),
    );
    assert.ok(
      artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.includes(
        "--seven-cvm-launch-completion-receipt",
      ),
    );
    assert.equal(
      artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.includes(
        "--six-cvm-launch-completion-receipt",
      ),
      false,
    );
    for (const flag of [
      "--diligence-qvl-identity-request",
      "--diligence-qvl-identity-response",
      "--arena-qvl-identity-request",
      "--arena-qvl-identity-response",
      "--anchor-writer-qvl-identity-request",
      "--anchor-writer-qvl-identity-response",
      "--compute-workload-qvl-identity-request",
      "--compute-workload-qvl-identity-response",
      "--compute-metering-qvl-identity-request",
      "--compute-metering-qvl-identity-response",
      "--main-runtime-qvl-challenge",
      "--main-runtime-independent-tdx-verdict",
      "--independent-metering-qvl-challenge",
      "--independent-metering-independent-tdx-verdict",
    ]) {
      assert.ok(
        artifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS.includes(flag),
        `${flag} is not part of the private upload audit`,
      );
    }

    const stalePath = path.join(directory, "stale-six-cvm.json");
    await writeFile(stalePath, `${JSON.stringify({
      schema: "dnai.phala-six-cvm-verified-evidence-set.v1",
      status: "stale",
    })}\n`, { mode: 0o600 });
    await assert.rejects(
      loadPrivateReleaseArtifactAudit([
        ...privateInputs.args,
        "--six-cvm-launch-completion-receipt",
        await realpath(stalePath),
      ]),
      /refuses stale six-CVM launch evidence/,
    );

    const missingRawProofArgs = [...privateInputs.args];
    const missingIndex = missingRawProofArgs.indexOf("--compute-workload-qvl-identity-response");
    missingRawProofArgs.splice(missingIndex, 2);
    await assert.rejects(
      loadPrivateReleaseArtifactAudit(missingRawProofArgs),
      /missing a required live input/,
    );

    for (const staleOrUnknownArgs of [
      ["--authority-review-envelope", privateInputs.values.get("--release").filePath],
      ["--check-only"],
      ["--prepare-frontend-build"],
      ["--unknown-authority", privateInputs.values.get("--release").filePath],
    ]) {
      await assert.rejects(
        loadPrivateReleaseArtifactAudit([
          ...privateInputs.args,
          ...staleOrUnknownArgs,
        ]),
        /unknown or legacy validator argument/,
      );
    }
    await assert.rejects(
      loadPrivateReleaseArtifactAudit([
        ...privateInputs.args,
        "--release",
        privateInputs.values.get("--release").filePath,
      ]),
      /malformed or duplicate arguments/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("build audit rejects raw or reversibly encoded environment secrets and credential patterns without echoing them", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-secret-"));
  try {
    const dist = path.join(directory, "dist");
    const secret = "operator/secret:value?123456";
    for (const [index, leaked] of [
      secret,
      Buffer.from(secret, "utf8").toString("base64"),
      Buffer.from(secret, "utf8").toString("base64url"),
      Buffer.from(secret, "utf8").toString("hex"),
      encodeURIComponent(secret),
    ].entries()) {
      await writeValidDist(dist, {
        extraAsset: `globalThis.leak${index}=${JSON.stringify(leaked)};`,
      });
      await assert.rejects(
        auditCloudflareBuild({
          distDir: dist,
          mode: "modeled",
          sensitiveEnv: { PHALA_CLOUD_API_KEY: secret },
        }),
        (error) => {
          assert.match(error.message, /sensitive environment value or reversible encoding/);
          assert.equal(error.message.includes(secret), false);
          return true;
        },
      );
    }

    const credentialCanary = ["phak_", "abcdefghijklmnop1234"].join("");
    await writeValidDist(dist, {
      extraAsset: `globalThis.leak="${credentialCanary}";`,
    });
    await assert.rejects(
      auditCloudflareBuild({ distDir: dist, mode: "modeled", sensitiveEnv: {} }),
      /private credential pattern/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("fresh-build reset removes stale ignored dist and staging preserves only the audited bundle", async () => {
  const webDir = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-stage-"));
  let stageDir;
  try {
    await mkdir(path.join(webDir, "dist"));
    await writeFile(path.join(webDir, "dist", "stale-release.js"), "stale\n");
    await mkdir(path.join(webDir, "functions"));
    await writeFile(path.join(webDir, "functions", "_middleware.js"), "export const onRequest = (context) => context.next();\n");
    await writeFile(path.join(webDir, "wrangler.toml"), [
      'name = "wikigenme"',
      'pages_build_output_dir = "./dist"',
      'compatibility_date = "2026-07-13"',
      "",
    ].join("\n"));
    await writeFile(path.join(webDir, "package.json"), '{"type":"module"}\n');

    await resetCloudflareBuildOutput(webDir);
    await assert.rejects(readFile(path.join(webDir, "dist", "stale-release.js")), /ENOENT/);
    await writeValidDist(path.join(webDir, "dist"));
    const sourceControlFingerprint = await cloudflareUploadControlFingerprint(webDir);
    const original = await auditCloudflareBuild({
      distDir: path.join(webDir, "dist"),
      mode: "modeled",
      sensitiveEnv: {},
    });
    stageDir = await stageCloudflareBundle(webDir);
    assert.equal(await realpath(stageDir), stageDir);
    const stageMetadata = await lstat(stageDir);
    assert.equal(stageMetadata.isDirectory(), true);
    assert.equal(stageMetadata.mode & 0o077, 0);
    if (typeof process.geteuid === "function") {
      assert.equal(stageMetadata.uid, process.geteuid());
    }
    const staged = await auditCloudflareBuild({
      distDir: path.join(stageDir, "dist"),
      mode: "modeled",
      sensitiveEnv: {},
    });
    assert.deepEqual(staged, original);
    const bundle = await auditCloudflareStage({
      stageDir,
      distAudit: staged,
      mode: "modeled",
      sensitiveEnv: {},
    });
    assert.equal(bundle.distManifestSha256, original.manifestSha256);
    assert.equal(bundle.uploadControlManifestSha256, sourceControlFingerprint);
    assert.match(bundle.bundleManifestSha256, /^[0-9a-f]{64}$/);
    await assert.rejects(readFile(path.join(stageDir, "dist", "stale-release.js")), /ENOENT/);

    await writeFile(path.join(stageDir, "functions", "unreviewed.js"), "export default {};\n");
    await assert.rejects(
      auditCloudflareStage({
        stageDir,
        distAudit: staged,
        mode: "modeled",
        sensitiveEnv: {},
      }),
      /unreviewed upload path/,
    );
    await rm(path.join(stageDir, "functions", "unreviewed.js"));

    await writeFile(path.join(stageDir, "wrangler.toml"), 'name = "other-project"\n');
    await assert.rejects(
      auditCloudflareStage({
        stageDir,
        distAudit: staged,
        mode: "modeled",
        sensitiveEnv: {},
      }),
      /reviewed Pages configuration/,
    );
  } finally {
    if (stageDir) await removeCloudflareStage(stageDir);
    await rm(webDir, { recursive: true, force: true });
  }
});

test("stage audit rejects private authority bytes outside dist", async () => {
  const webDir = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-stage-egress-"));
  let stageDir;
  try {
    await mkdir(path.join(webDir, "functions"));
    await writeFile(
      path.join(webDir, "functions", "_middleware.js"),
      "export const onRequest = (context) => context.next();\n",
    );
    await writeFile(path.join(webDir, "wrangler.toml"), artifactTest.EXPECTED_WRANGLER_CONFIG);
    await writeFile(path.join(webDir, "package.json"), '{"type":"module"}\n');
    await writeValidDist(path.join(webDir, "dist"));
    const privateInputs = await writePrivateReleaseInputs(
      path.join(webDir, "private-release-inputs"),
    );
    const distAudit = await auditCloudflareBuild({
      distDir: path.join(webDir, "dist"),
      mode: "modeled",
      sensitiveEnv: {},
    });
    stageDir = await stageCloudflareBundle(webDir);
    await auditCloudflareStage({
      stageDir,
      distAudit,
      mode: "live",
      sensitiveEnv: {},
      privateReleaseAudit: privateInputs.audit,
    });

    const activationAuthority = privateInputs.values.get("--live-activation-authority");
    const observation = privateInputs.values.get(
      "--compute-workload-activation-observation",
    );
    const leaks = [
      activationAuthority.value.signature,
      Buffer.from(activationAuthority.value.signature, "utf8").toString("base64"),
      `${JSON.stringify(observation.value)}\n`,
      observation.filePath,
    ];
    for (const relative of [
      "functions/_middleware.js",
      "package.json",
      "wrangler.toml",
    ]) {
      for (const leaked of leaks) {
        const target = path.join(stageDir, relative);
        const original = await readFile(target);
        await writeFile(target, leaked);
        await assert.rejects(
          auditCloudflareStage({
            stageDir,
            distAudit,
            mode: "live",
            sensitiveEnv: {},
            privateReleaseAudit: privateInputs.audit,
          }),
          /private release authority, receipt, signature, path, or reversible encoding/,
          `${relative}:${leaked.length}`,
        );
        await writeFile(target, original);
      }
    }
  } finally {
    if (stageDir) await removeCloudflareStage(stageDir);
    await rm(webDir, { recursive: true, force: true });
  }
});

test("source and VITE environment fingerprints detect relevant mutations but ignore dist churn", async () => {
  const webDir = await mkdtemp(path.join(tmpdir(), "dnai-cloudflare-fingerprint-"));
  try {
    await writeFile(path.join(webDir, "source.ts"), "export const value = 1;\n");
    await chmod(path.join(webDir, "source.ts"), 0o644);
    await mkdir(path.join(webDir, "dist"));
    await writeFile(path.join(webDir, "dist", "ignored.js"), "one\n");
    const before = await cloudflareSourceFingerprint(webDir);
    assert.equal(before, "3cdf5ca651f190d28aef8e74a24aa106b989f17cad88af6c92af223cbdd14071");
    assert.equal(await cloudflareSourceFingerprintSha256(webDir), `sha256:${before}`);
    await writeFile(path.join(webDir, "dist", "ignored.js"), "two\n");
    assert.equal(await cloudflareSourceFingerprint(webDir), before);
    await writeFile(path.join(webDir, ".env.production.local"), "PRIVATE_ONE=one\n");
    assert.equal(await cloudflareSourceFingerprint(webDir), before);
    await writeFile(path.join(webDir, ".env.production.local"), "PRIVATE_ONE=two\n");
    assert.equal(await cloudflareSourceFingerprint(webDir), before);
    await writeFile(path.join(webDir, "source.ts"), "export const value = 2;\n");
    assert.notEqual(await cloudflareSourceFingerprint(webDir), before);

    assert.equal(
      deploymentViteEnvironmentDigest({ VITE_RELEASE_SHA: SHA, NON_PUBLIC_SECRET: "one" }),
      deploymentViteEnvironmentDigest({ VITE_RELEASE_SHA: SHA, NON_PUBLIC_SECRET: "two" }),
    );
    assert.notEqual(
      deploymentViteEnvironmentDigest({ VITE_RELEASE_SHA: SHA }),
      deploymentViteEnvironmentDigest({ VITE_RELEASE_SHA: "2".repeat(40) }),
    );
    assert.notEqual(
      deploymentViteEnvironmentDigest({
        VITE_BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
        VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/base",
      }),
      deploymentViteEnvironmentDigest({
        VITE_BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
        VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: "https://other-secondary.wikigen.net/base",
      }),
    );
  } finally {
    await rm(webDir, { recursive: true, force: true });
  }
});
