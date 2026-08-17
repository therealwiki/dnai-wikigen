import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmod,
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  GH_ATTESTATION_TIMEOUT_MS,
  GH_VERSION_TIMEOUT_MS,
  MAX_GH_ATTESTATION_OUTPUT_BYTES,
  MAX_GH_VERSION_OUTPUT_BYTES,
  MAX_RELEASE_BUNDLE_BYTES,
  PINNED_GH_TOOL,
  PINNED_GH_EXECUTION_POLICY,
  RELEASE_MANIFEST_SIGSTORE_AUTHORITY,
  RELEASE_MANIFEST_SIGSTORE_BLOCKER,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY,
  RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN,
  ReleaseManifestSigstoreVerificationError,
  assertProductionReleaseManifestSigstoreVerificationReceipt,
  canonicalReleaseManifestSigstoreVerificationReceiptText,
  normalizeReleaseManifestSigstoreVerificationReceipt,
  releaseManifestSigstoreVerificationArgs,
  releaseManifestSigstoreVerificationReceiptSha256,
  verifyReleaseManifestSigstoreAttestation,
  verifyReleaseManifestSigstoreAttestationWithTestAdapter,
} from "./release-manifest-sigstore-verifier.mjs";

const RELEASE_SHA = "a".repeat(40);
const OTHER_SHA = "b".repeat(40);
const SOURCE_REPOSITORY = "therealwiki/dnai-wikigen";
const SOURCE_REF = "refs/heads/main";
const SIGNER_WORKFLOW =
  `${SOURCE_REPOSITORY}/.github/workflows/build-tee-images.yml`;
const SOURCE_REPOSITORY_URI = `https://github.com/${SOURCE_REPOSITORY}`;
const WORKFLOW_IDENTITY =
  `${SOURCE_REPOSITORY_URI}/.github/workflows/build-tee-images.yml@${SOURCE_REF}`;
const IMAGE_NAMES = [
  "tinker-delegate",
  "tee-email-oracle",
  "neko-chrome",
  "attestation-qvl",
  "compute-metering",
];

function sha256(bytes) {
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

function canonicalManifest(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
}

function releaseManifest(releaseSha = RELEASE_SHA) {
  return {
    schema: "dnai.tee-image-release.v1",
    release_sha: releaseSha,
    source_ref: SOURCE_REF,
    generated_at: "2026-07-21T12:00:00.000Z",
    source_repository: SOURCE_REPOSITORY,
    signer_workflow: SIGNER_WORKFLOW,
    workflow_run_id: "123456789",
    workflow_run_url:
      `https://github.com/${SOURCE_REPOSITORY}/actions/runs/123456789`,
    platform: "linux/amd64",
    images: IMAGE_NAMES.map((name, index) => {
      const digest = `sha256:${String(index + 1).repeat(64)}`;
      const repository = `ghcr.io/${SOURCE_REPOSITORY}/${name}`;
      return {
        name,
        repository,
        digest,
        image: `${repository}@${digest}`,
        platform: "linux/amd64",
        sbom_artifact: {
          filename: `${name}.spdx.json`,
          sha256: String(index + 6).repeat(64),
        },
        provenance_subject: { name: repository, digest },
        attestations: {
          provenance: {
            predicate_type: "https://slsa.dev/provenance/v1",
            id: String(index + 1),
            url: `https://github.com/${SOURCE_REPOSITORY}/attestations/${index + 1}`,
          },
          sbom: {
            predicate_type: "https://spdx.dev/Document/v2.3",
            id: String(index + 6),
            url: `https://github.com/${SOURCE_REPOSITORY}/attestations/${index + 6}`,
          },
        },
        verification: {
          repo: SOURCE_REPOSITORY,
          signer_workflow: SIGNER_WORKFLOW,
          source_digest: releaseSha,
          source_ref: SOURCE_REF,
          provenance_attestation: "verified",
          sbom_attestation: "verified",
        },
      };
    }),
  };
}

function sigstoreBundle() {
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: "ZmFrZS1jZXJ0aWZpY2F0ZQ==" },
      tlogEntries: [{ logIndex: "1" }],
    },
    dsseEnvelope: {
      payload: "ZmFrZS1pbi10b3RvLXN0YXRlbWVudA==",
      payloadType: "application/vnd.in-toto+json",
      signatures: [{ sig: "ZmFrZS1zaWduYXR1cmU=" }],
    },
  };
}

function verificationOutput(bundle, manifestDigest, releaseSha = RELEASE_SHA) {
  return [{
    attestation: {
      bundle: structuredClone(bundle),
      bundle_url: "",
      initiator: "",
    },
    verificationResult: {
      statement: {
        _type: "https://in-toto.io/Statement/v1",
        subject: [{
          name: "dnai-tee-image-release.json",
          digest: { sha256: manifestDigest.slice("sha256:".length) },
        }],
        predicateType: "https://slsa.dev/provenance/v1",
        predicate: {
          buildDefinition: {
            buildType:
              "https://actions.github.io/buildtypes/workflow/v1",
            externalParameters: {
              workflow: {
                path: ".github/workflows/build-tee-images.yml",
                ref: SOURCE_REF,
                repository: SOURCE_REPOSITORY_URI,
              },
            },
            internalParameters: {
              github: { runner_environment: "github-hosted" },
            },
            resolvedDependencies: [{
              uri: `git+${SOURCE_REPOSITORY_URI}@${SOURCE_REF}`,
              digest: { gitCommit: releaseSha },
            }],
          },
          runDetails: {
            builder: { id: WORKFLOW_IDENTITY },
            metadata: {
              invocationId:
                `https://github.com/${SOURCE_REPOSITORY}/actions/runs/123456789/attempts/1`,
            },
          },
        },
      },
      signature: {
        certificate: {
          subjectAlternativeName: WORKFLOW_IDENTITY,
          issuer: "https://token.actions.githubusercontent.com",
          githubWorkflowSHA: releaseSha,
          githubWorkflowRepository: SOURCE_REPOSITORY,
          githubWorkflowRef: SOURCE_REF,
          buildSignerURI: WORKFLOW_IDENTITY,
          runnerEnvironment: "github-hosted",
          sourceRepositoryURI: SOURCE_REPOSITORY_URI,
          sourceRepositoryDigest: releaseSha,
          sourceRepositoryRef: SOURCE_REF,
          buildConfigURI: WORKFLOW_IDENTITY,
        },
      },
      verifiedTimestamps: [{
        type: "Tlog",
        uri: "rekor.sigstore.dev",
        timestamp: "2026-07-21T12:00:01Z",
      }],
      verifiedIdentity: {
        issuer: { issuer: "https://token.actions.githubusercontent.com" },
      },
    },
  }];
}

async function fixture() {
  const createdRoot = await mkdtemp(
    path.join(os.tmpdir(), "dnai-release-manifest-sigstore-"),
  );
  const root = await realpath(createdRoot);
  const manifestPath = path.join(root, "dnai-tee-image-release.json");
  const bundlePath = path.join(
    root,
    "dnai-tee-image-release.bundle.json",
  );
  const toolPath = path.join(root, "gh");
  const manifest = releaseManifest();
  const manifestBytes = canonicalManifest(manifest);
  const bundle = sigstoreBundle();
  const bundleBytes = Buffer.from(`${JSON.stringify(bundle)}\n`, "utf8");
  const toolBytes = Buffer.from("test-only-pinned-gh-binary\n", "utf8");
  await Promise.all([
    writeFile(manifestPath, manifestBytes, { mode: 0o644 }),
    writeFile(bundlePath, bundleBytes, { mode: 0o644 }),
    writeFile(toolPath, toolBytes, { mode: 0o755 }),
  ]);
  await chmod(toolPath, 0o755);
  return {
    root,
    manifestPath,
    bundlePath,
    toolPath,
    manifest,
    manifestBytes,
    manifestDigest: sha256(manifestBytes),
    bundle,
    bundleBytes,
    toolBytes,
    toolAuthority: {
      path: toolPath,
      version: "2.87.3",
      sha256: sha256(toolBytes),
    },
    input: { manifestPath, bundlePath, expectedReleaseSha: RELEASE_SHA },
  };
}

function ok(stdout) {
  return { status: 0, signal: null, error: null, stdout, stderr: "" };
}

function failed(stderr = "verification failed") {
  return { status: 1, signal: null, error: null, stdout: "", stderr };
}

function runnerFor(
  value,
  {
    calls = [],
    versionOutput = "",
    onVersion,
    onVerify,
    verificationResult,
  } = {},
) {
  const defaultVersion =
    `gh version ${value.toolAuthority.version} (2026-02-23)\n`
    + `https://github.com/cli/cli/releases/tag/v${value.toolAuthority.version}\n`;
  return async (command, args, options) => {
    calls.push({ command, args: [...args], options });
    if (args.length === 1 && args[0] === "--version") {
      if (onVersion) return onVersion({ command, args, options });
      return ok(versionOutput || defaultVersion);
    }
    if (onVerify) return onVerify({ command, args, options });
    const output = verificationResult
      || verificationOutput(value.bundle, value.manifestDigest);
    return ok(`${JSON.stringify(output)}\n`);
  };
}

async function verifyFixture(value, runner) {
  return verifyReleaseManifestSigstoreAttestationWithTestAdapter(
    value.input,
    { runner, toolAuthority: value.toolAuthority },
  );
}

function productionBrand(testReceipt) {
  return {
    ...testReceipt,
    ...RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY,
  };
}

async function rejectsCode(promise, code) {
  await assert.rejects(
    promise,
    (error) => (
      error instanceof ReleaseManifestSigstoreVerificationError
      && error.code === code
      && error.message === code
    ),
  );
}

test("release authority and local gh pin are exact", () => {
  assert.deepEqual(PINNED_GH_TOOL, {
    path: "/opt/homebrew/Cellar/gh/2.87.3/bin/gh",
    version: "2.87.3",
    sha256:
      "sha256:67b51ba8ca861e0fcd4749d47eba740e8db8c799a8b18645833e904e09f7fb70",
  });
  assert.deepEqual(RELEASE_MANIFEST_SIGSTORE_AUTHORITY, {
    repository: SOURCE_REPOSITORY,
    source_ref: SOURCE_REF,
    signer_workflow: SIGNER_WORKFLOW,
    predicate_type: "https://slsa.dev/provenance/v1",
    subject_filename: "dnai-tee-image-release.json",
    bundle_filename: "dnai-tee-image-release.bundle.json",
  });
  assert.equal(
    RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    "release_manifest_sigstore_bundle_not_cryptographically_verified",
  );
});

test("verification command is the exact installed gh 2.87.3 syntax", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  assert.deepEqual(
    releaseManifestSigstoreVerificationArgs({
      manifestPath: value.manifestPath,
      bundlePath: value.bundlePath,
      releaseSha: RELEASE_SHA,
    }),
    [
      "attestation",
      "verify",
      value.manifestPath,
      "--bundle",
      value.bundlePath,
      "--repo",
      SOURCE_REPOSITORY,
      "--signer-workflow",
      SIGNER_WORKFLOW,
      "--source-digest",
      RELEASE_SHA,
      "--source-ref",
      SOURCE_REF,
      "--deny-self-hosted-runners",
      "--format",
      "json",
    ],
  );
});

test("test seam validates exact evidence but cannot clear the production blocker", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  const calls = [];
  const receipt = await verifyFixture(value, runnerFor(value, { calls }));

  assert.equal(receipt.schema, RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA);
  assert.equal(receipt.status, "test_adapter_verified_not_release_authority");
  assert.equal(receipt.blocker_code, RELEASE_MANIFEST_SIGSTORE_BLOCKER);
  assert.equal(receipt.blocker_status, "not_cleared_by_test_adapter");
  assert.equal(receipt.release_sha, RELEASE_SHA);
  assert.equal(receipt.release_manifest_sha256, value.manifestDigest);
  assert.equal(receipt.release_manifest_sigstore_bundle_sha256, sha256(value.bundleBytes));
  assert.equal(receipt.gh_executable_sha256, value.toolAuthority.sha256);
  assert.equal(
    PINNED_GH_EXECUTION_POLICY,
    "dnai.pinned-gh-execution.private-verified-copy.v1",
  );
  assert.equal(
    receipt.verification_command_sha256,
    domainSha256(
      "dnai.tee-image-release-manifest-sigstore-command.v1",
      `${JSON.stringify({
        args: releaseManifestSigstoreVerificationArgs({
          manifestPath: value.manifestPath,
          bundlePath: value.bundlePath,
          releaseSha: RELEASE_SHA,
        }),
        execution_policy: PINNED_GH_EXECUTION_POLICY,
        logical_executable_path: value.toolAuthority.path,
        logical_executable_sha256: value.toolAuthority.sha256,
      })}\n`,
    ),
  );
  assert.ok(Object.isFrozen(receipt));
  for (const [key, evidence] of Object.entries(receipt)) {
    if (key.endsWith("_sha256")) {
      assert.match(evidence, /^sha256:[0-9a-f]{64}$/);
    }
  }
  const serialized = JSON.stringify(receipt);
  assert.doesNotMatch(serialized, /therealwiki|build-tee-images|2\.87\.3/);
  assert.ok(!serialized.includes(value.root));
  assert.equal(calls.length, 2);
  assert.notEqual(calls[0].command, value.toolPath);
  assert.match(path.basename(calls[0].command), /^gh-[0-9a-f]{32}$/);
  assert.match(
    path.basename(path.dirname(calls[0].command)),
    /^dnai-pinned-gh-/,
  );
  assert.deepEqual(calls[0].args, ["--version"]);
  assert.equal(calls[0].options.timeout, GH_VERSION_TIMEOUT_MS);
  assert.equal(calls[0].options.maxBuffer, MAX_GH_VERSION_OUTPUT_BYTES);
  assert.equal(calls[1].command, calls[0].command);
  assert.deepEqual(
    calls[1].args,
    releaseManifestSigstoreVerificationArgs({
      manifestPath: value.manifestPath,
      bundlePath: value.bundlePath,
      releaseSha: RELEASE_SHA,
    }),
  );
  assert.equal(calls[1].options.timeout, GH_ATTESTATION_TIMEOUT_MS);
  assert.equal(calls[1].options.maxBuffer, MAX_GH_ATTESTATION_OUTPUT_BYTES);
  for (const call of calls) {
    assert.equal(call.options.cwd, value.root);
    assert.equal(call.options.shell, false);
    assert.deepEqual(call.options.stdio, ["ignore", "pipe", "pipe"]);
    assert.deepEqual(call.options.env, {
      PATH: "/usr/bin:/bin",
      HOME: "/var/empty",
      TMPDIR: "/var/empty",
      XDG_CONFIG_HOME: "/var/empty",
      LANG: "C",
      LC_ALL: "C",
      NO_COLOR: "1",
      CLICOLOR: "0",
      GH_PAGER: "cat",
      PAGER: "cat",
      GH_PROMPT_DISABLED: "1",
      GH_NO_UPDATE_NOTIFIER: "1",
    });
    assert.equal(
      Object.keys(call.options.env).some((key) => /token|secret|key/i.test(key)),
      false,
    );
  }
  await assert.rejects(
    readFile(calls[0].command),
    (error) => error?.code === "ENOENT",
  );
  await assert.rejects(
    readFile(path.dirname(calls[0].command)),
    (error) => error?.code === "ENOENT",
  );
});

test("source parent swap-and-restore cannot change executed gh bytes", async (t) => {
  const value = await fixture();
  const parkedRoot = `${value.root}-parked`;
  t.after(() => rm(value.root, { recursive: true, force: true }));
  t.after(() => rm(parkedRoot, { recursive: true, force: true }));

  const exactOutput = `${JSON.stringify(
    verificationOutput(value.bundle, value.manifestDigest),
  )}\n`;
  const shellLiteral = (text) => `'${text.replaceAll("'", `'"'"'`)}'`;
  const verifiedToolBytes = Buffer.from([
    "#!/bin/sh",
    'if [ "$#" -eq 1 ] && [ "$1" = "--version" ]; then',
    `  printf '%s\\n' ${shellLiteral(
      `gh version ${value.toolAuthority.version} (2026-02-23)`,
    )} ${shellLiteral(
      `https://github.com/cli/cli/releases/tag/v${value.toolAuthority.version}`,
    )}`,
    "  exit 0",
    "fi",
    `printf '%s\\n' ${shellLiteral(exactOutput.replace(/\n$/, ""))}`,
    "",
  ].join("\n"), "utf8");
  await writeFile(value.toolPath, verifiedToolBytes, { mode: 0o755 });
  await chmod(value.toolPath, 0o755);
  value.toolBytes = verifiedToolBytes;
  value.toolAuthority.sha256 = sha256(verifiedToolBytes);

  const maliciousToolBytes = Buffer.from(
    "#!/bin/sh\nprintf '%s\\n' 'malicious swapped gh executed'\nexit 9\n",
    "utf8",
  );
  const invokedCommands = [];
  let swapCount = 0;
  const runner = async (command, args, options) => {
    invokedCommands.push(command);
    assert.notEqual(command, value.toolPath);
    await rename(value.root, parkedRoot);
    await mkdir(value.root, { mode: 0o700 });
    await writeFile(value.toolPath, maliciousToolBytes, { mode: 0o755 });
    await chmod(value.toolPath, 0o755);
    swapCount += 1;
    try {
      return spawnSync(command, args, options);
    } finally {
      await rm(value.root, { recursive: true, force: true });
      await rename(parkedRoot, value.root);
    }
  };

  const receipt = await verifyFixture(value, runner);
  assert.equal(swapCount, 2);
  assert.equal(invokedCommands.length, 2);
  assert.equal(invokedCommands[0], invokedCommands[1]);
  assert.equal(receipt.gh_executable_sha256, sha256(verifiedToolBytes));
  assert.deepEqual(await readFile(value.toolPath), verifiedToolBytes);
  assert.ok(Object.isFrozen(receipt));
  await assert.rejects(
    readFile(invokedCommands[0]),
    (error) => error?.code === "ENOENT",
  );
});

test("production receipt normalization accepts only the frozen authority brand", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  const testReceipt = await verifyFixture(value, runnerFor(value));
  await rejectsCode(
    Promise.resolve().then(() => (
      normalizeReleaseManifestSigstoreVerificationReceipt(testReceipt)
    )),
    "release_manifest_sigstore_receipt_authority_invalid",
  );

  const candidate = productionBrand(testReceipt);
  const normalized =
    normalizeReleaseManifestSigstoreVerificationReceipt(candidate);
  assert.ok(Object.isFrozen(normalized));
  assert.deepEqual(normalized, candidate);
  assert.deepEqual(
    assertProductionReleaseManifestSigstoreVerificationReceipt(candidate),
    normalized,
  );
  assert.deepEqual(RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_AUTHORITY, {
    schema: RELEASE_MANIFEST_SIGSTORE_VERIFICATION_SCHEMA,
    status: "verified_by_pinned_gh_sigstore",
    blocker_code: RELEASE_MANIFEST_SIGSTORE_BLOCKER,
    blocker_status: "cleared_by_this_receipt",
    gh_executable_sha256: PINNED_GH_TOOL.sha256,
    gh_executable_path_sha256: normalized.gh_executable_path_sha256,
    gh_version_output_sha256:
      "sha256:b854454a206472d98565ff7c406ff085b3df45b833044782c099302a09c280d9",
  });
});

test("forged receipt fields, test brands, extras, and identity drift fail closed", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  const testReceipt = await verifyFixture(value, runnerFor(value));
  const valid = productionBrand(testReceipt);
  const mutations = [
    ["test status", (receipt) => {
      receipt.status = "test_adapter_verified_not_release_authority";
    }],
    ["test blocker", (receipt) => {
      receipt.blocker_status = "not_cleared_by_test_adapter";
    }],
    ["schema", (receipt) => {
      receipt.schema = "dnai.tee-image-release-manifest-sigstore-verification.v2";
    }],
    ["blocker code", (receipt) => {
      receipt.blocker_code = "different_blocker";
    }],
    ["gh binary", (receipt) => {
      receipt.gh_executable_sha256 = `sha256:${"f".repeat(64)}`;
    }],
    ["gh path", (receipt) => {
      receipt.gh_executable_path_sha256 = `sha256:${"e".repeat(64)}`;
    }],
    ["gh version", (receipt) => {
      receipt.gh_version_output_sha256 = `sha256:${"d".repeat(64)}`;
    }],
    ["manifest digest", (receipt) => {
      receipt.release_manifest_sha256 = `sha256:${"c".repeat(64)}`;
    }],
    ["identity", (receipt) => {
      receipt.verified_identity_sha256 = `sha256:${"b".repeat(64)}`;
    }],
    ["zero digest", (receipt) => {
      receipt.verification_output_sha256 = `sha256:${"0".repeat(64)}`;
    }],
    ["extra", (receipt) => {
      receipt.raw_output = "forged";
    }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      const candidate = structuredClone(valid);
      mutate(candidate);
      assert.throws(
        () => normalizeReleaseManifestSigstoreVerificationReceipt(candidate),
        ReleaseManifestSigstoreVerificationError,
      );
    });
  }
});

test("canonical production receipt text and domain-separated digest are deterministic", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  const testReceipt = await verifyFixture(value, runnerFor(value));
  const valid = productionBrand(testReceipt);
  const shuffled = Object.fromEntries(Object.entries(valid).reverse());
  const canonical =
    canonicalReleaseManifestSigstoreVerificationReceiptText(valid);
  assert.equal(
    canonicalReleaseManifestSigstoreVerificationReceiptText(shuffled),
    canonical,
  );
  assert.equal(
    canonical,
    `${JSON.stringify(
      normalizeReleaseManifestSigstoreVerificationReceipt(valid),
      null,
      2,
    )}\n`,
  );
  assert.ok(canonical.endsWith("\n"));
  assert.equal(canonical.includes(value.root), false);
  assert.equal(
    RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN,
    "dnai-wikigen/tee-image-release-manifest-sigstore-verification/v1\0",
  );
  const expectedDigest = sha256(Buffer.concat([
    Buffer.from(RELEASE_MANIFEST_SIGSTORE_VERIFICATION_RECEIPT_DOMAIN),
    Buffer.from(canonical),
  ]));
  assert.equal(
    releaseManifestSigstoreVerificationReceiptSha256(valid),
    expectedDigest,
  );
  for (let index = 0; index < 50; index += 1) {
    assert.equal(
      releaseManifestSigstoreVerificationReceiptSha256(shuffled),
      expectedDigest,
    );
  }
});

test("production entry point accepts neither runner fields nor extra adapter arguments", async () => {
  await rejectsCode(
    verifyReleaseManifestSigstoreAttestation(
      {
        manifestPath: "/not/read",
        bundlePath: "/not/read",
        expectedReleaseSha: RELEASE_SHA,
      },
      { runner: () => ok("") },
    ),
    "production_adapter_injection_forbidden",
  );
  await rejectsCode(
    verifyReleaseManifestSigstoreAttestation({
      manifestPath: "/not/read",
      bundlePath: "/not/read",
      expectedReleaseSha: RELEASE_SHA,
      runner: () => ok(""),
    }),
    "verification_input_fields_invalid",
  );
  assert.equal(verifyReleaseManifestSigstoreAttestation.length, 1);
});

test("empty, non-structural, and plausibly shaped fabricated bundles cannot self-verify", async (t) => {
  await t.test("empty", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    await writeFile(value.bundlePath, Buffer.alloc(0));
    await assert.rejects(
      verifyFixture(value, runnerFor(value)),
      ReleaseManifestSigstoreVerificationError,
    );
  });

  await t.test("nonempty JSON object", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    await writeFile(value.bundlePath, "{}\n");
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_bundle_shape_invalid",
    );
  });

  await t.test("fabricated Sigstore shape rejected by pinned verifier", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const runner = runnerFor(value, { onVerify: () => failed() });
    await rejectsCode(
      verifyFixture(value, runner),
      "gh_attestation_verification_failed",
    );
  });
});

test("command success without exact structured gh evidence fails closed", async (t) => {
  const cases = [
    ["empty", "", "gh_attestation_output_invalid"],
    ["not JSON", "verified", "gh_attestation_output_json_invalid"],
    ["empty array", "[]\n", "gh_attestation_output_count_invalid"],
    ["two results", "[{},{}]\n", "gh_attestation_output_count_invalid"],
    ["wrong fields", "[{\"ok\":true}]\n", "gh_attestation_output_fields_invalid"],
  ];
  for (const [name, stdout, code] of cases) {
    await t.test(name, async (t) => {
      const value = await fixture();
      t.after(() => rm(value.root, { recursive: true, force: true }));
      const runner = runnerFor(value, { onVerify: () => ok(stdout) });
      await rejectsCode(verifyFixture(value, runner), code);
    });
  }
});

test("wrong SHA, workflow, repository, subject, and bundle binding are rejected", async (t) => {
  const mutations = [
    ["subject digest", (value) => {
      value[0].verificationResult.statement.subject[0].digest.sha256 = "b".repeat(64);
    }],
    ["subject name", (value) => {
      value[0].verificationResult.statement.subject[0].name = "other.json";
    }],
    ["source digest", (value) => {
      value[0].verificationResult.signature.certificate.sourceRepositoryDigest = OTHER_SHA;
    }],
    ["source ref", (value) => {
      value[0].verificationResult.signature.certificate.sourceRepositoryRef = "refs/heads/dev";
    }],
    ["repository", (value) => {
      value[0].verificationResult.signature.certificate.sourceRepositoryURI = "https://github.com/attacker/fork";
    }],
    ["workflow", (value) => {
      value[0].verificationResult.signature.certificate.subjectAlternativeName = "https://github.com/attacker/fork/.github/workflows/build.yml@refs/heads/main";
    }],
    ["statement source", (value) => {
      value[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.repository = "https://github.com/attacker/fork";
    }],
    ["bundle", (value) => {
      value[0].attestation.bundle.dsseEnvelope.signatures[0].sig = "different";
    }],
  ];
  for (const [name, mutate] of mutations) {
    await t.test(name, async (t) => {
      const value = await fixture();
      t.after(() => rm(value.root, { recursive: true, force: true }));
      const output = verificationOutput(value.bundle, value.manifestDigest);
      mutate(output);
      await assert.rejects(
        verifyFixture(value, runnerFor(value, { verificationResult: output })),
        ReleaseManifestSigstoreVerificationError,
      );
    });
  }

  await t.test("expected release SHA differs from exact manifest", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    value.input.expectedReleaseSha = OTHER_SHA;
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_manifest_authority_invalid",
    );
  });
});

test("timeouts and oversized command output fail closed", async (t) => {
  await t.test("version timeout", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const runner = runnerFor(value, {
      onVersion: () => ({
        status: null,
        signal: "SIGTERM",
        error: { code: "ETIMEDOUT" },
        stdout: "",
        stderr: "",
      }),
    });
    await rejectsCode(verifyFixture(value, runner), "gh_version_timeout");
  });

  await t.test("attestation timeout", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const runner = runnerFor(value, {
      onVerify: () => ({
        status: null,
        signal: "SIGTERM",
        error: { code: "ETIMEDOUT" },
        stdout: "",
        stderr: "",
      }),
    });
    await rejectsCode(
      verifyFixture(value, runner),
      "gh_attestation_verification_timeout",
    );
  });

  await t.test("attestation stdout oversize", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const runner = runnerFor(value, {
      onVerify: () => ok("x".repeat(MAX_GH_ATTESTATION_OUTPUT_BYTES + 1)),
    });
    await rejectsCode(
      verifyFixture(value, runner),
      "gh_attestation_verification_output_oversize",
    );
  });
});

test("canonical paths reject aliases, symlinks, and different directories", async (t) => {
  await t.test("dot-dot alias", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    value.input.manifestPath =
      `${value.root}/alias/../dnai-tee-image-release.json`;
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_manifest_path_invalid",
    );
  });

  await t.test(
    "parent directory symlink deterministically rejects the manifest first",
    async (t) => {
      const value = await fixture();
      t.after(() => rm(value.root, { recursive: true, force: true }));
      const alias = `${value.root}-alias`;
      t.after(() => rm(alias, { recursive: true, force: true }));
      await symlink(value.root, alias, "dir");
      value.input.manifestPath = path.join(
        alias,
        path.basename(value.manifestPath),
      );
      value.input.bundlePath = path.join(
        alias,
        path.basename(value.bundlePath),
      );
      await Promise.all(Array.from({ length: 64 }, () => (
        rejectsCode(
          verifyFixture(value, runnerFor(value)),
          "release_manifest_path_invalid",
        )
      )));
    },
  );

  await t.test("bundle symlink", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const target = path.join(value.root, "bundle-target.json");
    await writeFile(target, value.bundleBytes);
    await rm(value.bundlePath);
    await symlink(target, value.bundlePath);
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_bundle_path_invalid",
    );
  });

  await t.test("bundle in another directory", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const other = path.join(value.root, "other");
    await mkdir(other);
    const movedBundle = path.join(other, path.basename(value.bundlePath));
    await writeFile(movedBundle, value.bundleBytes);
    value.input.bundlePath = movedBundle;
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_inputs_directory_mismatch",
    );
  });
});

test("private gh copy rejects an attacker-writable non-sticky temp root", async (t) => {
  const value = await fixture();
  const unsafeTempRoot = await mkdtemp(
    path.join(os.tmpdir(), "dnai-unsafe-gh-temp-root-"),
  );
  t.after(() => rm(value.root, { recursive: true, force: true }));
  t.after(() => rm(unsafeTempRoot, { recursive: true, force: true }));
  await chmod(unsafeTempRoot, 0o777);

  const previousTmpdir = process.env.TMPDIR;
  process.env.TMPDIR = unsafeTempRoot;
  try {
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "gh_private_copy_temp_root_invalid",
    );
  } finally {
    if (previousTmpdir === undefined) delete process.env.TMPDIR;
    else process.env.TMPDIR = previousTmpdir;
  }
});

test("manifest, bundle, and gh bytes cannot change across verification", async (t) => {
  const cases = [
    ["manifest", "release_manifest_changed_after_verification", (value) => {
      writeFileSync(value.manifestPath, Buffer.concat([value.manifestBytes, Buffer.from(" ")]));
    }],
    ["bundle", "release_bundle_changed_after_verification", (value) => {
      writeFileSync(value.bundlePath, Buffer.concat([value.bundleBytes, Buffer.from(" ")]));
    }],
    ["tool", "gh_tool_changed_after_verification", (value) => {
      writeFileSync(value.toolPath, Buffer.concat([value.toolBytes, Buffer.from("changed")]));
    }],
  ];
  for (const [name, code, mutate] of cases) {
    await t.test(name, async (t) => {
      const value = await fixture();
      t.after(() => rm(value.root, { recursive: true, force: true }));
      const output = verificationOutput(value.bundle, value.manifestDigest);
      const runner = runnerFor(value, {
        onVerify: () => {
          mutate(value);
          return ok(`${JSON.stringify(output)}\n`);
        },
      });
      await rejectsCode(verifyFixture(value, runner), code);
    });
  }
});

test("gh digest, version, and executable path identity are pinned", async (t) => {
  await t.test("digest drift", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    value.toolAuthority.sha256 = `sha256:${"f".repeat(64)}`;
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "gh_tool_digest_mismatch",
    );
  });

  await t.test("version output drift", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const runner = runnerFor(value, {
      versionOutput:
        "gh version 2.88.0 (2026-03-01)\n"
        + "https://github.com/cli/cli/releases/tag/v2.88.0\n",
    });
    await rejectsCode(
      verifyFixture(value, runner),
      "gh_version_output_invalid",
    );
  });

  await t.test("tool symlink", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    const target = path.join(value.root, "real-gh");
    await writeFile(target, value.toolBytes, { mode: 0o755 });
    await chmod(target, 0o755);
    await rm(value.toolPath);
    await symlink(target, value.toolPath);
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "gh_tool_path_invalid",
    );
  });
});

test("manifest canonicalization and file bounds are enforced before execution", async (t) => {
  await t.test("compact manifest is semantically valid but noncanonical", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    await writeFile(value.manifestPath, `${JSON.stringify(value.manifest)}\n`);
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_manifest_not_canonical",
    );
  });

  await t.test("oversized bundle", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    await writeFile(
      value.bundlePath,
      Buffer.alloc(MAX_RELEASE_BUNDLE_BYTES + 1, 0x61),
    );
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_bundle_path_invalid",
    );
  });

  await t.test("release manifest source authority drift", async (t) => {
    const value = await fixture();
    t.after(() => rm(value.root, { recursive: true, force: true }));
    value.manifest.source_repository = "attacker/fork";
    await writeFile(value.manifestPath, canonicalManifest(value.manifest));
    await rejectsCode(
      verifyFixture(value, runnerFor(value)),
      "release_manifest_authority_invalid",
    );
  });
});

test("repeated verification is deterministic for unchanged exact evidence", async (t) => {
  const value = await fixture();
  t.after(() => rm(value.root, { recursive: true, force: true }));
  const outputs = [];
  for (let index = 0; index < 25; index += 1) {
    outputs.push(await verifyFixture(value, runnerFor(value)));
  }
  assert.ok(outputs.every((candidate) => (
    JSON.stringify(candidate) === JSON.stringify(outputs[0])
  )));
  assert.deepEqual(await readFile(value.manifestPath), value.manifestBytes);
  assert.deepEqual(await readFile(value.bundlePath), value.bundleBytes);
  assert.deepEqual(await readFile(value.toolPath), value.toolBytes);
});
