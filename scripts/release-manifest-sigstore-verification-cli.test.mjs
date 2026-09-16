import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_CLI_SCHEMA,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
  ReleaseManifestSigstoreVerificationCliError,
  parseReleaseManifestSigstoreVerificationCliArgs,
  produceReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationCliUsage,
  releaseManifestSigstoreVerificationOperatorPaths,
} from "./release-manifest-sigstore-verification-cli.mjs";
import {
  RELEASE_MANIFEST_SIGSTORE_AUTHORITY,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  releaseManifestSigstoreVerificationReceiptSha256,
} from "./release-manifest-sigstore-verifier.mjs";

const RELEASE_SHA = "a".repeat(40);
const CLI_PATH = fileURLToPath(new URL(
  "./release-manifest-sigstore-verification-cli.mjs",
  import.meta.url,
));
const CLI_URL = pathToFileURL(CLI_PATH).href;
const VERIFIER_URL = new URL(
  "./release-manifest-sigstore-verifier.mjs",
  import.meta.url,
).href;
const DURABLE_WRITER_URL = new URL(
  "./durable-json-write.mjs",
  import.meta.url,
).href;

const MOCKED_PRODUCER_PROGRAM = String.raw`
import fs from "node:fs";
import path from "node:path";
import { mock } from "node:test";

const verifierUrl = process.env.DNAI_TEST_VERIFIER_URL;
const durableWriterUrl = process.env.DNAI_TEST_DURABLE_WRITER_URL;
const cliUrl = process.env.DNAI_TEST_CLI_URL;
const repositoryRoot = process.env.DNAI_TEST_REPOSITORY_ROOT;
const expectedReleaseSha = process.env.DNAI_TEST_RELEASE_SHA;
const receipt = JSON.parse(Buffer.from(
  process.env.DNAI_TEST_RECEIPT_BASE64,
  "base64",
).toString("utf8"));
const actualVerifier = await import(verifierUrl);
let observedVerificationInput = null;
const contexts = [];
contexts.push(mock.module(verifierUrl, {
  namedExports: {
    ...actualVerifier,
    verifyReleaseManifestSigstoreAttestation: async (input, ...extra) => {
      if (extra.length !== 0) throw new Error("test verifier received an adapter");
      observedVerificationInput = input;
      return receipt;
    },
  },
}));

const durableFault = process.env.DNAI_TEST_DURABLE_FAULT;
let restoreFsync = null;
if (durableFault) {
  const actualDurableWriter = await import(durableWriterUrl);
  contexts.push(mock.module(durableWriterUrl, {
    namedExports: {
      ...actualDurableWriter,
      durablyPublishJson: (options) => {
        if (durableFault === "before-publish") {
          throw new Error("injected test-only failure before publication");
        }
        if (durableFault === "directory-swap") {
          const originalDirectory = path.dirname(options.outputPath);
          const displacedDirectory = originalDirectory + ".displaced";
          fs.renameSync(originalDirectory, displacedDirectory);
          fs.mkdirSync(originalDirectory, { mode: 0o700 });
          const displacedSource = path.join(
            displacedDirectory,
            path.basename(options.sourcePath),
          );
          fs.copyFileSync(displacedSource, options.sourcePath);
          fs.chmodSync(options.sourcePath, 0o600);
          return actualDurableWriter.durablyPublishJson(options);
        }
        if (durableFault === "late-directory-swap") {
          const originalDirectory = path.dirname(options.outputPath);
          const displacedDirectory = originalDirectory + ".displaced";
          return actualDurableWriter.durablyPublishJson({
            ...options,
            testHookBeforeDirectoryFsync() {
              fs.renameSync(originalDirectory, displacedDirectory);
              fs.mkdirSync(originalDirectory, { mode: 0o700 });
            },
          });
        }
        if (durableFault === "after-link" || durableFault === "after-temp-unlink") {
          return actualDurableWriter.durablyPublishJson({
            ...options,
            faultStage: durableFault,
          });
        }
        const result = actualDurableWriter.durablyPublishJson(options);
        if (durableFault === "staging-hardlink-before-cleanup") {
          fs.linkSync(options.sourcePath, options.sourcePath + ".quarantine-link");
        }
        if (durableFault === "staging-cleanup-fsync") {
          const originalFsync = fs.fsyncSync;
          restoreFsync = () => {
            fs.fsyncSync = originalFsync;
            restoreFsync = null;
          };
          fs.fsyncSync = () => {
            restoreFsync();
            throw new Error("injected test-only staging cleanup fsync failure");
          };
        }
        if (durableFault === "after-publish") {
          throw new Error("injected test-only failure after publication");
        }
        return result;
      },
    },
  }));
}

try {
  const cli = await import(
    cliUrl + "?isolated-test=" + Date.now() + "-" + Math.random()
  );
  const result = await cli.produceReleaseManifestSigstoreVerificationReceipt({
    repositoryRoot,
    expectedReleaseSha,
  });
  process.stdout.write(JSON.stringify({
    ok: true,
    result,
    observedVerificationInput,
  }));
} catch (error) {
  process.stdout.write(JSON.stringify({
    ok: false,
    code: error?.code ?? error?.message ?? "unknown_test_failure",
    observedVerificationInput,
  }));
  process.exitCode = 7;
} finally {
  if (restoreFsync) restoreFsync();
  for (const context of contexts.reverse()) context.restore();
}
`;

function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function domainSha256(domain, value) {
  const valueBytes = Buffer.from(value, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(valueBytes.length));
  return sha256(Buffer.concat([
    Buffer.from(`${domain}\0`, "utf8"),
    length,
    valueBytes,
  ]));
}

function verifiedIdentitySha256(releaseSha, manifestSha256) {
  return domainSha256(
    "dnai.tee-image-release-manifest-sigstore-identity.v1",
    `${JSON.stringify({
      repository: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.repository,
      signer_workflow: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.signer_workflow,
      source_digest: releaseSha,
      source_ref: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.source_ref,
      subject_name: RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
      subject_sha256: manifestSha256,
    })}\n`,
  );
}

function productionReceipt(manifestBytes, bundleBytes) {
  const manifestSha256 = sha256(manifestBytes);
  return {
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY.schema,
    status: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY.status,
    blocker_code:
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY.blocker_code,
    blocker_status:
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY.blocker_status,
    release_sha: RELEASE_SHA,
    release_manifest_sha256: manifestSha256,
    release_manifest_sigstore_bundle_sha256: sha256(bundleBytes),
    gh_executable_sha256:
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY
        .gh_executable_sha256,
    gh_executable_path_sha256:
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY
        .gh_executable_path_sha256,
    gh_version_output_sha256:
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY
        .gh_version_output_sha256,
    verification_command_sha256: `sha256:${"c".repeat(64)}`,
    verification_output_sha256: `sha256:${"d".repeat(64)}`,
    verified_identity_sha256:
      verifiedIdentitySha256(RELEASE_SHA, manifestSha256),
  };
}

function fixture({ releaseMode = 0o700 } = {}) {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-sigstore-receipt-cli-")),
  );
  const releaseDirectory = path.join(root, ".release");
  fs.mkdirSync(releaseDirectory, { mode: releaseMode });
  fs.chmodSync(releaseDirectory, releaseMode);
  const paths = releaseManifestSigstoreVerificationOperatorPaths(root);
  const manifestBytes = Buffer.from(
    '{"fixture":"exact-ci-release-manifest"}\n',
    "utf8",
  );
  const bundleBytes = Buffer.from(
    '{"fixture":"exact-ci-sigstore-bundle"}\n',
    "utf8",
  );
  fs.writeFileSync(paths.manifestPath, manifestBytes, { mode: 0o644 });
  fs.writeFileSync(paths.bundlePath, bundleBytes, { mode: 0o644 });
  return {
    root,
    releaseDirectory,
    paths,
    manifestBytes,
    bundleBytes,
    receipt: productionReceipt(manifestBytes, bundleBytes),
  };
}

function cleanup(value) {
  fs.chmodSync(value.releaseDirectory, 0o700);
  fs.rmSync(value.root, { recursive: true, force: true });
}

function runMockedProductionVerifier(
  value,
  {
    receipt = value.receipt,
    expectedReleaseSha = RELEASE_SHA,
    durableFault = "",
  } = {},
) {
  const execution = spawnSync(
    process.execPath,
    [
      "--experimental-test-module-mocks",
      "--no-warnings",
      "--input-type=module",
      "--eval",
      MOCKED_PRODUCER_PROGRAM,
    ],
    {
      encoding: "utf8",
      env: {
        PATH: process.env.PATH,
        DNAI_TEST_VERIFIER_URL: VERIFIER_URL,
        DNAI_TEST_DURABLE_WRITER_URL: DURABLE_WRITER_URL,
        DNAI_TEST_CLI_URL: CLI_URL,
        DNAI_TEST_REPOSITORY_ROOT: value.root,
        DNAI_TEST_RELEASE_SHA: expectedReleaseSha,
        DNAI_TEST_DURABLE_FAULT: durableFault,
        DNAI_TEST_RECEIPT_BASE64:
          Buffer.from(JSON.stringify(receipt), "utf8").toString("base64"),
      },
    },
  );
  assert.equal(execution.signal, null);
  assert.equal(execution.stderr, "");
  assert.notEqual(execution.stdout, "");
  return Object.freeze({
    exitStatus: execution.status,
    ...JSON.parse(execution.stdout),
  });
}

function assertMockedFailure(result, code) {
  assert.equal(result.exitStatus, 7);
  assert.equal(result.ok, false);
  assert.equal(result.code, code);
}

function assertCliError(callback, code) {
  assert.throws(
    callback,
    (error) => (
      error instanceof ReleaseManifestSigstoreVerificationCliError
      && error.code === code
      && error.message === code
    ),
  );
}

test("operator paths and CLI grammar bind one exact .release artifact set", (t) => {
  const value = fixture();
  t.after(() => cleanup(value));
  assert.deepEqual(value.paths, {
    repositoryRoot: value.root,
    releaseDirectory: path.join(value.root, ".release"),
    manifestPath: path.join(
      value.root,
      ".release",
      "dnai-tee-image-release.json",
    ),
    bundlePath: path.join(
      value.root,
      ".release",
      "dnai-tee-image-release.bundle.json",
    ),
    receiptPath: path.join(
      value.root,
      ".release",
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
    ),
  });
  assert.deepEqual(
    parseReleaseManifestSigstoreVerificationCliArgs([
      "--repository-root",
      value.root,
      "--release-sha",
      RELEASE_SHA,
    ]),
    {
      help: false,
      repositoryRoot: value.root,
      expectedReleaseSha: RELEASE_SHA,
    },
  );
  assert.deepEqual(
    parseReleaseManifestSigstoreVerificationCliArgs(["--help"]),
    { help: true },
  );
  assert.match(releaseManifestSigstoreVerificationCliUsage(), /no-clobber mode-0600/);

  const invalidCases = [
    [[], "cli_argument_missing"],
    [["--repository-root", value.root], "cli_argument_missing"],
    [["--manifest", value.paths.manifestPath], "cli_argument_unknown"],
    [[
      "--repository-root", value.root,
      "--repository-root", value.root,
      "--release-sha", RELEASE_SHA,
    ], "cli_argument_duplicate"],
    [[
      "--repository-root", value.root,
      "--release-sha", "0".repeat(40),
    ], "expected_release_sha_invalid"],
    [[
      "--repository-root", value.root,
      "--release-sha", RELEASE_SHA.toUpperCase(),
    ], "expected_release_sha_invalid"],
  ];
  for (const [argv, code] of invalidCases) {
    assertCliError(
      () => parseReleaseManifestSigstoreVerificationCliArgs(argv),
      code,
    );
  }
  assertCliError(
    () => releaseManifestSigstoreVerificationOperatorPaths(
      `${value.root}/.release/..`,
    ),
    "repository_root_path_invalid",
  );
});

test("canonical production receipt publishes successfully as one durable mode-0600 file", (t) => {
  const value = fixture();
  t.after(() => cleanup(value));
  const shuffled = Object.fromEntries(Object.entries(value.receipt).reverse());
  const canonical =
    canonicalReleaseManifestSigstoreVerificationReceiptText(value.receipt);
  const execution = runMockedProductionVerifier(value, { receipt: shuffled });
  assert.equal(execution.exitStatus, 0);
  assert.equal(execution.ok, true);
  assert.deepEqual(execution.observedVerificationInput, {
    manifestPath: value.paths.manifestPath,
    bundlePath: value.paths.bundlePath,
    expectedReleaseSha: RELEASE_SHA,
  });
  const result = execution.result;

  assert.deepEqual(result, {
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_CLI_SCHEMA,
    status: "persisted_no_clobber_mode_0600",
    release_sha: RELEASE_SHA,
    release_manifest_sha256: sha256(value.manifestBytes),
    release_manifest_sigstore_bundle_sha256: sha256(value.bundleBytes),
    receipt_sha256:
      releaseManifestSigstoreVerificationReceiptSha256(value.receipt),
    receipt_artifact_file_sha256: sha256(canonical),
  });
  assert.equal(fs.readFileSync(value.paths.receiptPath, "utf8"), canonical);
  const metadata = fs.lstatSync(value.paths.receiptPath);
  assert.equal(metadata.isFile(), true);
  assert.equal(metadata.isSymbolicLink(), false);
  assert.equal(metadata.nlink, 1);
  assert.equal(metadata.mode & 0o777, 0o600);
  assert.deepEqual(
    fs.readdirSync(value.releaseDirectory).sort(),
    [
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
      RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
    ].sort(),
  );
  const serialized = JSON.stringify(result);
  assert.doesNotMatch(serialized, /therealwiki|build-tee-images|\.release/);
  assert.equal(serialized.includes(value.root), false);
});

test("receipt production API cannot accept an injected verifier adapter", async () => {
  await assert.rejects(
    produceReleaseManifestSigstoreVerificationReceipt(
      {
        repositoryRoot: "/not/read",
        expectedReleaseSha: RELEASE_SHA,
      },
      { runner: () => ({ status: 0 }) },
    ),
    (error) => (
      error instanceof ReleaseManifestSigstoreVerificationCliError
      && error.code === "production_adapter_injection_forbidden"
    ),
  );
  assert.equal(produceReleaseManifestSigstoreVerificationReceipt.length, 1);
});

test("a fabricated production-branded receipt has no public persistence path", async (t) => {
  const value = fixture();
  t.after(() => cleanup(value));
  const cliNamespace = await import(CLI_URL);
  assert.equal(
    Object.hasOwn(
      cliNamespace,
      "persistProductionReleaseManifestSigstoreVerificationReceipt",
    ),
    false,
  );
  await assert.rejects(
    produceReleaseManifestSigstoreVerificationReceipt({
      repositoryRoot: value.root,
      expectedReleaseSha: RELEASE_SHA,
      receipt: value.receipt,
    }),
    (error) => (
      error instanceof ReleaseManifestSigstoreVerificationCliError
      && error.code === "producer_input_fields_invalid"
    ),
  );
  assert.equal(fs.existsSync(value.paths.receiptPath), false);
  assert.deepEqual(fs.readdirSync(value.releaseDirectory).sort(), [
    RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
    RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
  ].sort());
});

test("source digest drift and non-production brands publish nothing", async (t) => {
  await t.test("explicit release SHA differs from the verified receipt", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, {
        expectedReleaseSha: "b".repeat(40),
      }),
      "release_receipt_release_sha_mismatch",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
  });

  await t.test("bundle digest drift", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    fs.writeFileSync(value.paths.bundlePath, '{"fixture":"changed"}\n');
    assertMockedFailure(
      runMockedProductionVerifier(value),
      "release_receipt_source_digest_mismatch",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
    assert.deepEqual(fs.readdirSync(value.releaseDirectory).sort(), [
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.bundle_filename,
      RELEASE_MANIFEST_SIGSTORE_AUTHORITY.subject_filename,
    ].sort());
  });

  await t.test("test adapter brand", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    const testBrand = {
      ...value.receipt,
      status: "test_adapter_verified_not_release_authority",
      blocker_status: "not_cleared_by_test_adapter",
    };
    assertMockedFailure(
      runMockedProductionVerifier(value, { receipt: testBrand }),
      "release_manifest_sigstore_receipt_authority_invalid",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
  });
});

test("no-clobber publication refuses regular, symlink, and hard-link targets", async (t) => {
  const cases = [
    ["regular", (value) => {
      fs.writeFileSync(value.paths.receiptPath, "existing\n", { mode: 0o600 });
      return () => assert.equal(
        fs.readFileSync(value.paths.receiptPath, "utf8"),
        "existing\n",
      );
    }],
    ["symlink", (value) => {
      const outside = path.join(value.root, "outside.json");
      fs.writeFileSync(outside, "outside\n", { mode: 0o600 });
      fs.symlinkSync(outside, value.paths.receiptPath);
      return () => assert.equal(fs.readFileSync(outside, "utf8"), "outside\n");
    }],
    ["hard link", (value) => {
      const outside = path.join(value.root, "outside.json");
      fs.writeFileSync(outside, "outside\n", { mode: 0o600 });
      fs.linkSync(outside, value.paths.receiptPath);
      return () => {
        assert.equal(fs.readFileSync(outside, "utf8"), "outside\n");
        assert.equal(fs.lstatSync(outside).nlink, 2);
      };
    }],
  ];
  for (const [name, installTarget] of cases) {
    await t.test(name, (t) => {
      const value = fixture();
      t.after(() => cleanup(value));
      const assertUnchanged = installTarget(value);
      assertMockedFailure(
        runMockedProductionVerifier(value),
        "release_receipt_publication_indeterminate",
      );
      assertUnchanged();
      assert.equal(
        fs.readdirSync(value.releaseDirectory)
          .some((name) => name.endsWith(".tmp")),
        false,
      );
    });
  }
});

test("publication failures distinguish definite absence from an indeterminate final target", async (t) => {
  await t.test("failure before publication leaves no target", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, { durableFault: "before-publish" }),
      "release_receipt_publication_failed",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
    assert.equal(
      fs.readdirSync(value.releaseDirectory)
        .some((name) => name.endsWith(".tmp")),
      false,
    );
  });

  await t.test("failure after complete publication is explicitly indeterminate", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, { durableFault: "after-publish" }),
      "release_receipt_publication_indeterminate",
    );
    assert.equal(
      fs.readFileSync(value.paths.receiptPath, "utf8"),
      canonicalReleaseManifestSigstoreVerificationReceiptText(value.receipt),
    );
    assert.equal(fs.lstatSync(value.paths.receiptPath).mode & 0o777, 0o600);
  });

  for (const durableFault of ["after-link", "after-temp-unlink"]) {
    await t.test(`${durableFault} residue is quarantined and never becomes a safe retry`, (t) => {
      const value = fixture();
      t.after(() => cleanup(value));
      assertMockedFailure(
        runMockedProductionVerifier(value, { durableFault }),
        "release_receipt_publication_indeterminate",
      );
      const canonical =
        canonicalReleaseManifestSigstoreVerificationReceiptText(value.receipt);
      assert.equal(fs.readFileSync(value.paths.receiptPath, "utf8"), canonical);
      assert.equal(fs.lstatSync(value.paths.receiptPath).nlink, 1);
      assert.equal(
        fs.readdirSync(value.releaseDirectory)
          .some((name) => name.endsWith(".tmp")),
        false,
      );

      // A later invocation cannot reinterpret a survivor as a definite safe
      // pre-publication failure or overwrite it.
      assertMockedFailure(
        runMockedProductionVerifier(value),
        "release_receipt_publication_indeterminate",
      );
      assert.equal(fs.readFileSync(value.paths.receiptPath, "utf8"), canonical);
    });
  }

  await t.test("late directory replacement is detected at the retained-fd commit boundary", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, { durableFault: "late-directory-swap" }),
      "release_receipt_publication_indeterminate",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
    assert.equal(
      fs.readFileSync(
        path.join(
          `${value.releaseDirectory}.displaced`,
          RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_FILENAME,
        ),
        "utf8",
      ),
      canonicalReleaseManifestSigstoreVerificationReceiptText(value.receipt),
    );
  });

  await t.test("staging identity drift prevents a success return", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, {
        durableFault: "staging-hardlink-before-cleanup",
      }),
      "release_receipt_publication_indeterminate",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), true);
    assert.equal(
      fs.readdirSync(value.releaseDirectory)
        .some((name) => name.endsWith(".quarantine-link")),
      true,
    );
  });

  await t.test("staging unlink fsync failure prevents a success return", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, {
        durableFault: "staging-cleanup-fsync",
      }),
      "release_receipt_publication_indeterminate",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), true);
    assert.equal(
      fs.readdirSync(value.releaseDirectory)
        .some((name) => name.endsWith(".tmp")),
      false,
    );
  });

  await t.test("same-uid directory replacement cannot report false success", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    assertMockedFailure(
      runMockedProductionVerifier(value, { durableFault: "directory-swap" }),
      "release_receipt_publication_indeterminate",
    );
    assert.equal(fs.existsSync(`${value.releaseDirectory}.displaced`), true);
    assert.equal(fs.existsSync(value.paths.receiptPath), true);
    assert.equal(fs.lstatSync(value.paths.receiptPath).mode & 0o777, 0o600);
  });
});

test("symlinked and hard-linked CI inputs fail before publication", async (t) => {
  await t.test("manifest hard link", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    fs.linkSync(
      value.paths.manifestPath,
      path.join(value.root, "manifest-hardlink.json"),
    );
    assertMockedFailure(
      runMockedProductionVerifier(value),
      "release_manifest_path_invalid",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
  });

  await t.test("bundle symlink", (t) => {
    const value = fixture();
    t.after(() => cleanup(value));
    const target = path.join(value.root, "bundle-target.json");
    fs.writeFileSync(target, value.bundleBytes);
    fs.rmSync(value.paths.bundlePath);
    fs.symlinkSync(target, value.paths.bundlePath);
    assertMockedFailure(
      runMockedProductionVerifier(value),
      "release_bundle_path_invalid",
    );
    assert.equal(fs.existsSync(value.paths.receiptPath), false);
  });
});

test("release directory must be canonical, operator-owned, and exact mode-0700", async (t) => {
  for (const mode of [0o755, 0o770, 0o777]) {
    await t.test(mode.toString(8), (t) => {
      const value = fixture({ releaseMode: mode });
      t.after(() => cleanup(value));
      assertMockedFailure(
        runMockedProductionVerifier(value),
        "release_directory_invalid",
      );
      assert.equal(fs.existsSync(value.paths.receiptPath), false);
    });
  }

  await t.test("symlinked .release", (t) => {
    const root = fs.realpathSync.native(
      fs.mkdtempSync(path.join(os.tmpdir(), "dnai-sigstore-receipt-alias-")),
    );
    const realRelease = path.join(root, "real-release");
    const releaseDirectory = path.join(root, ".release");
    fs.mkdirSync(realRelease, { mode: 0o700 });
    fs.symlinkSync(realRelease, releaseDirectory);
    const paths = releaseManifestSigstoreVerificationOperatorPaths(root);
    const manifestBytes = Buffer.from("manifest\n");
    const bundleBytes = Buffer.from("bundle\n");
    fs.writeFileSync(paths.manifestPath, manifestBytes);
    fs.writeFileSync(paths.bundlePath, bundleBytes);
    const value = { root, releaseDirectory, paths };
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    assertMockedFailure(
      runMockedProductionVerifier({
        ...value,
        receipt: productionReceipt(manifestBytes, bundleBytes),
      }),
      "release_directory_invalid",
    );
    assert.equal(fs.existsSync(paths.receiptPath), false);
  });
});

test("CLI help and failures emit only bounded operator-safe output", () => {
  const help = spawnSync(process.execPath, [CLI_PATH, "--help"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(help.status, 0);
  assert.equal(help.stderr, "");
  assert.equal(help.stdout, `${releaseManifestSigstoreVerificationCliUsage()}\n`);

  const secret = "operator-secret-that-must-never-reach-output";
  const invalid = spawnSync(process.execPath, [
    CLI_PATH,
    "--repository-root",
    "/private/operator/release/path",
    "--release-sha",
    "0".repeat(40),
  ], {
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      GH_TOKEN: secret,
      RELEASE_OPERATOR_SECRET: secret,
    },
  });
  assert.equal(invalid.status, 1);
  assert.equal(invalid.stdout, "");
  assert.equal(
    invalid.stderr,
    "release manifest Sigstore receipt production failed: expected_release_sha_invalid\n",
  );
  assert.equal(invalid.stderr.includes(secret), false);
  assert.equal(invalid.stderr.includes("/private/operator"), false);
  assert.ok(Buffer.byteLength(invalid.stderr, "utf8") < 256);
});
