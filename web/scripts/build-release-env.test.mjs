import assert from "node:assert/strict";
import {
  chmod,
  link as createHardLink,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  SEMANTIC_VALIDATION_SCHEMA,
  SEMANTIC_VALIDATION_STATUS,
  SEMANTIC_VALIDATION_TRUTH_STATUS,
  SEMANTIC_VALIDATOR_INPUT_FLAGS,
  SEMANTIC_VALIDATOR_WRAPPER_FLAGS,
  PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS,
  assertCleanReleaseSource,
  assertExactSemanticValidatorInputsUnchanged,
  assertLiveActivationAuthorityEvidenceBinding,
  exactSemanticValidatorArtifactPaths,
  loadBoundedArtifact,
  loadDeploymentIntent,
  loadExactSemanticValidatorInputs,
  loadExactPrebuildSemanticValidatorInputs,
  loadJson,
  main,
  parseArgs,
  parsePrebuildArgs,
  releaseRpcEndpoints,
  semanticValidationReceipt,
} from "./build-release-env.mjs";
import { __test as cloudflareReleaseArtifactTest } from "./cloudflare-release-artifact-core.mjs";
import {
  FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS,
  FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
} from "./frontend-build-candidate-core.mjs";

const DEPLOYMENT_INTENT_SHA256 = `sha256:${"a1".repeat(32)}`;
const REVIEWER_ACCEPTANCE_SHA256 = `sha256:${"a2".repeat(32)}`;
const CEREMONY_AUTHORIZATION_SHA256 = `sha256:${"b1".repeat(32)}`;
const LIVE_ACTIVATION_AUTHORITY_SHA256 = `sha256:${"b2".repeat(32)}`;
const RUNTIME_AUTHORITY_DEPENDENCY_SHA256 = `sha256:${"b3".repeat(32)}`;
const RELEASE_INPUTS_SHA256 = `sha256:${"b4".repeat(32)}`;
const FRONTEND_BUILD_SHA256 = `sha256:${"b5".repeat(32)}`;
const COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256 =
  `sha256:${"b6".repeat(32)}`;
const COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256 = `sha256:${"b7".repeat(32)}`;
const FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256 = `sha256:${"b8".repeat(32)}`;
const AUTHORITY_BINDING = Object.freeze({
  deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
  reviewerAuthorityGenesisAcceptanceSha256: REVIEWER_ACCEPTANCE_SHA256,
  ceremonyAuthorizationSha256: CEREMONY_AUTHORIZATION_SHA256,
  liveActivationAuthoritySha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
  runtimeAuthorityDependencySha256: RUNTIME_AUTHORITY_DEPENDENCY_SHA256,
  releaseInputsSha256: RELEASE_INPUTS_SHA256,
  computeWorkloadActivationObservationSha256:
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
  computeWorkloadBrowserBindingSha256:
    COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
  frontendBuildCandidateReceiptSha256:
    FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
  frontendBuildSha256: FRONTEND_BUILD_SHA256,
});

function exactValidatorArgs() {
  return SEMANTIC_VALIDATOR_INPUT_FLAGS.flatMap((flag) => [
    flag,
    `/tmp/dnai-validator/${flag.slice(2)}.json`,
  ]);
}

test("validator parser requires the exact 37 canonical evidence files", () => {
  assert.equal(SEMANTIC_VALIDATOR_INPUT_FLAGS.length, 37);
  assert.deepEqual(SEMANTIC_VALIDATOR_WRAPPER_FLAGS, ["--check-only"]);
  assert.deepEqual(
    SEMANTIC_VALIDATOR_INPUT_FLAGS,
    cloudflareReleaseArtifactTest.REQUIRED_LIVE_PRIVATE_RELEASE_FLAGS,
  );
  assert.deepEqual(
    SEMANTIC_VALIDATOR_INPUT_FLAGS.filter(
      (flag) => !FRONTEND_BUILD_EXCLUDED_CYCLIC_INPUT_FLAGS.includes(flag),
    ),
    FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  );
  const parsed = parseArgs(["--check-only", ...exactValidatorArgs()]);
  assert.equal(parsed.checkOnly, true);
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(parseArgs(exactValidatorArgs()).checkOnly, false);
  assert.equal(parsed.release, "/tmp/dnai-validator/release.json");
  assert.equal(
    parsed.releaseCore,
    "/tmp/dnai-validator/release-core.json",
  );
  assert.equal(
    parsed.runtimeAuthorityDependency,
    "/tmp/dnai-validator/runtime-authority-dependency.json",
  );
  assert.equal(
    parsed.sevenCvmLaunchCompletionReceipt,
    "/tmp/dnai-validator/seven-cvm-launch-completion-receipt.json",
  );
  assert.equal(
    parsed.computeWorkloadActivationObservation,
    "/tmp/dnai-validator/compute-workload-activation-observation.json",
  );
  assert.equal(
    parsed.frontendBuildCandidateReceipt,
    "/tmp/dnai-validator/frontend-build-candidate-receipt.json",
  );
  assert.throws(
    () => parseArgs(["--check-only", "--check-only"]),
    /duplicate argument/,
  );
  assert.throws(
    () => parseArgs([...exactValidatorArgs(), "--check-only"]),
    /check-only must be the first argument/,
  );
  assert.throws(
    () => parseArgs(["--help"]),
    /unknown argument: --help/,
  );
  assert.throws(
    () => parseArgs(["--release", "/tmp/one.json", "--release", "/tmp/two.json"]),
    /duplicate argument: --release/,
  );
  assert.throws(
    () => parseArgs(["--release", "relative.json"]),
    /canonical absolute file path/,
  );
  assert.throws(
    () => parseArgs(["--release", "/tmp/../tmp/release.json"]),
    /canonical absolute file path/,
  );
  assert.throws(
    () => parseArgs(["--authority-review-envelope", "/tmp/review.json"]),
    /unknown argument: --authority-review-envelope/,
  );
  assert.throws(
    () => parseArgs(["--six-cvm-launch-completion-receipt", "/tmp/L.json"]),
    /unknown argument: --six-cvm-launch-completion-receipt/,
  );
  const incomplete = exactValidatorArgs();
  incomplete.splice(incomplete.indexOf("--compute-workload-qvl-identity-request"), 2);
  assert.throws(
    () => parseArgs(incomplete),
    /missing required argument: --compute-workload-qvl-identity-request/,
  );
  const swapped = exactValidatorArgs();
  [swapped[0], swapped[2]] = [swapped[2], swapped[0]];
  [swapped[1], swapped[3]] = [swapped[3], swapped[1]];
  assert.throws(
    () => parseArgs(swapped),
    /out of order: expected --release, received --release-core/,
  );
  assert.throws(
    () => parseArgs([...exactValidatorArgs(), "/tmp/positional.json"]),
    /unexpected positional argument/,
  );

  const paths = exactSemanticValidatorArtifactPaths(parsed);
  assert.equal(paths.entries.length, 37);
  assert.equal(paths.entries[0].flag, "--release");
  assert.equal(paths.byFlag["--release"], parsed.release);
  assert.equal(paths.byKey.release, parsed.release);
  assert.equal(Object.isFrozen(paths.entries), true);
  assert.throws(
    () => exactSemanticValidatorArtifactPaths({ ...parsed, legacyReview: true }),
    /only the exact parsed input arguments/,
  );
});

test("prebuild parser requires exactly the acyclic 35 inputs and rejects C/D", () => {
  assert.equal(PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS.length, 35);
  assert.deepEqual(
    PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS,
    FRONTEND_BUILD_PRE_D_PRIVATE_INPUT_FLAGS,
  );
  const argv = PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS.flatMap((flag) => [
    flag,
    `/tmp/dnai-prebuild/${flag.slice(2)}.json`,
  ]);
  const parsed = parsePrebuildArgs(argv);
  assert.equal(parsed.release, "/tmp/dnai-prebuild/release.json");
  assert.equal(parsed.liveActivationAuthority, undefined);
  assert.equal(parsed.frontendBuildCandidateReceipt, undefined);
  for (const rejected of [
    "--live-activation-authority",
    "--frontend-build-candidate-receipt",
    "--check-only",
  ]) {
    assert.throws(
      () => parsePrebuildArgs([...argv, rejected, "/tmp/forbidden.json"]),
      /unknown argument/,
    );
  }
});

test("release RPC endpoints require exact public HTTPS providers with distinct origins", () => {
  assert.deepEqual(releaseRpcEndpoints({
    BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
    BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/base-sepolia",
  }), {
    primary: "https://sepolia.base.org",
    secondary: "https://secondary-rpc.wikigen.net/base-sepolia",
  });
  for (const env of [
    {},
    { BASE_SEPOLIA_RPC_URL: "https://primary-rpc.wikigen.me/base-sepolia" },
    {
      BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org",
      BASE_SEPOLIA_SECONDARY_RPC_URL: "https://sepolia.base.org/other-path",
    },
    {
      BASE_SEPOLIA_RPC_URL: "https://sepolia.base.org?key=value",
      BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/base-sepolia",
    },
    {
      BASE_SEPOLIA_RPC_URL: "https://user@sepolia.base.org",
      BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/base-sepolia",
    },
    {
      BASE_SEPOLIA_RPC_URL: "https://primary-rpc.wikigen.me/base-sepolia",
      BASE_SEPOLIA_SECONDARY_RPC_URL: "https://secondary-rpc.wikigen.net/base-sepolia",
    },
  ]) {
    assert.throws(() => releaseRpcEndpoints(env), /RPC|BASE_SEPOLIA/);
  }
});

test("source verification ignores an attacker-controlled PATH git shim", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "dnai-fake-git-"));
  const fakeGit = path.join(directory, "git");
  const hostileNames = [
    "PATH", "GIT_DIR", "GIT_INDEX_FILE", "GIT_CONFIG_COUNT",
    "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_GLOBAL",
  ];
  const previous = Object.fromEntries(hostileNames.map((name) => [
    name,
    process.env[name],
  ]));
  try {
    await writeFile(fakeGit, "#!/bin/sh\nprintf '%s\\n' ffffffffffffffffffffffffffffffffffffffff\n");
    await chmod(fakeGit, 0o755);
    Object.assign(process.env, {
      PATH: `${directory}:${previous.PATH || ""}`,
      GIT_DIR: path.join(directory, "counterfeit.git"),
      GIT_INDEX_FILE: path.join(directory, "counterfeit.index"),
      GIT_CONFIG_COUNT: "1",
      GIT_CONFIG_KEY_0: "core.fsmonitor",
      GIT_CONFIG_VALUE_0: fakeGit,
      GIT_CONFIG_GLOBAL: path.join(directory, "counterfeit.gitconfig"),
    });
    assert.throws(
      () => assertCleanReleaseSource("f".repeat(40)),
      /does not match current HEAD/,
    );
  } finally {
    for (const name of hostileNames) {
      if (previous[name] === undefined) delete process.env[name];
      else process.env[name] = previous[name];
    }
    await rm(directory, { recursive: true, force: true });
  }
});

test("semantic receipt is deterministic, bounded, and hash-only", () => {
  const releaseSha = "a".repeat(40);
  const receipt = semanticValidationReceipt(
    releaseSha,
    "VITE_RELEASE_SHA=abc\n",
    AUTHORITY_BINDING,
  );
  assert.deepEqual(Object.keys(receipt).sort(), [
    "ceremony_authorization_sha256",
    "chain_id",
    "compute_workload_activation_observation_sha256",
    "compute_workload_browser_binding_sha256",
    "deployment_intent_sha256",
    "frontend_build_candidate_receipt_sha256",
    "frontend_build_sha256",
    "live_activation_authority_sha256",
    "raw_secret_egress",
    "release_env_sha256",
    "release_inputs_sha256",
    "release_sha",
    "reviewer_authority_genesis_acceptance_sha256",
    "runtime_authority_dependency_sha256",
    "schema",
    "status",
    "truth_status",
  ]);
  assert.equal(receipt.schema, SEMANTIC_VALIDATION_SCHEMA);
  assert.equal(receipt.status, SEMANTIC_VALIDATION_STATUS);
  assert.equal(receipt.truth_status, SEMANTIC_VALIDATION_TRUTH_STATUS);
  assert.equal(receipt.release_sha, releaseSha);
  assert.equal(receipt.chain_id, 84_532);
  assert.equal(receipt.deployment_intent_sha256, DEPLOYMENT_INTENT_SHA256);
  assert.equal(receipt.reviewer_authority_genesis_acceptance_sha256, REVIEWER_ACCEPTANCE_SHA256);
  assert.equal(receipt.ceremony_authorization_sha256, CEREMONY_AUTHORIZATION_SHA256);
  assert.equal(receipt.live_activation_authority_sha256, LIVE_ACTIVATION_AUTHORITY_SHA256);
  assert.equal(receipt.runtime_authority_dependency_sha256, RUNTIME_AUTHORITY_DEPENDENCY_SHA256);
  assert.equal(receipt.release_inputs_sha256, RELEASE_INPUTS_SHA256);
  assert.equal(
    receipt.compute_workload_activation_observation_sha256,
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
  );
  assert.equal(
    receipt.compute_workload_browser_binding_sha256,
    COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
  );
  assert.equal(receipt.frontend_build_sha256, FRONTEND_BUILD_SHA256);
  assert.equal(
    receipt.frontend_build_candidate_receipt_sha256,
    FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
  );
  assert.match(receipt.release_env_sha256, /^sha256:[0-9a-f]{64}$/);
  assert.equal(receipt.raw_secret_egress, false);
  assert.equal(JSON.stringify(receipt).includes("VITE_"), false);
  assert.throws(
    () => semanticValidationReceipt("A".repeat(40), "x\n", AUTHORITY_BINDING),
    /lowercase release SHA/,
  );
  assert.throws(
    () => semanticValidationReceipt(releaseSha, "x\n"),
    /deployment-intent SHA-256/,
  );
  assert.throws(
    () => semanticValidationReceipt(releaseSha, "x\n", {
      ...AUTHORITY_BINDING,
      liveActivationAuthoritySha256: `sha256:${"0".repeat(64)}`,
    }),
    /live-activation-authority SHA-256/,
  );
  assert.throws(
    () => semanticValidationReceipt(releaseSha, "x\n", {
      ...AUTHORITY_BINDING,
      ceremonyAuthorizationSha256: CEREMONY_AUTHORIZATION_SHA256.toUpperCase(),
    }),
    /ceremony-authorization SHA-256/,
  );
  assert.throws(
    () => semanticValidationReceipt(releaseSha, "x\n", {
      ...AUTHORITY_BINDING,
      frontendBuildCandidateReceiptSha256: FRONTEND_BUILD_SHA256,
    }),
    /keep D distinct/,
  );
});

test("live activation evidence binds intent, B, C, runtime dependency, lineage, and release SHA", () => {
  const releaseSha = "a".repeat(40);
  const candidate = {
    release_sha: releaseSha,
    deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
    operator_policy: {
      schema: "dnai.live-activation-authority-evidence.v1",
      ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
      live_activation_authority_sha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
      runtime_authority_dependency_sha256: RUNTIME_AUTHORITY_DEPENDENCY_SHA256,
    },
  };
  const deploymentIntent = {
    ok: true,
    intent: { schema: "dnai.deployment-intent-core.v1" },
    receipt: { deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256, releaseSha },
  };
  const authorityValidation = {
    ok: true,
    releaseSha,
    deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
    reviewerAuthorityGenesisAcceptanceSha256: REVIEWER_ACCEPTANCE_SHA256,
    ceremonyAuthorizationSha256: CEREMONY_AUTHORIZATION_SHA256,
    liveActivationAuthoritySha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
    runtimeAuthorityDependencySha256: RUNTIME_AUTHORITY_DEPENDENCY_SHA256,
    releaseInputsSha256: RELEASE_INPUTS_SHA256,
    computeWorkloadActivationObservationSha256:
      COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SHA256,
    computeWorkloadBrowserBindingSha256:
      COMPUTE_WORKLOAD_BROWSER_BINDING_SHA256,
    frontendBuildCandidateReceiptSha256:
      FRONTEND_BUILD_CANDIDATE_RECEIPT_SHA256,
    frontendBuildSha256: FRONTEND_BUILD_SHA256,
  };
  assert.deepEqual(
    assertLiveActivationAuthorityEvidenceBinding(candidate, deploymentIntent, authorityValidation),
    AUTHORITY_BINDING,
  );

  for (const mutate of [
    (value) => { value.authority.liveActivationAuthoritySha256 = `sha256:${"c3".repeat(32)}`; },
    (value) => { value.authority.runtimeAuthorityDependencySha256 = `sha256:${"d4".repeat(32)}`; },
    (value) => { value.intent.receipt.deploymentIntentSha256 = `sha256:${"e5".repeat(32)}`; },
  ]) {
    const tampered = {
      intent: structuredClone(deploymentIntent),
      authority: structuredClone(authorityValidation),
    };
    mutate(tampered);
    assert.throws(
      () => assertLiveActivationAuthorityEvidenceBinding(candidate, tampered.intent, tampered.authority),
      /does not exactly match/,
    );
  }
  const wrongRelease = structuredClone(deploymentIntent);
  wrongRelease.receipt.releaseSha = "b".repeat(40);
  assert.throws(
    () => assertLiveActivationAuthorityEvidenceBinding(candidate, wrongRelease, authorityValidation),
    /release SHA does not match/,
  );
  assert.throws(
    () => assertLiveActivationAuthorityEvidenceBinding(candidate, { ...deploymentIntent, ok: false }, authorityValidation),
    /was not valid/,
  );
  assert.throws(
    () => assertLiveActivationAuthorityEvidenceBinding(candidate, deploymentIntent, { ok: false }),
    /signed live activation authority chain was not valid/,
  );
});

test("release inputs are canonical, bounded, stable no-follow regular files", async () => {
  const directory = await realpath(
    await mkdtemp(path.join(tmpdir(), "dnai-release-input-")),
  );
  try {
    const canonical = path.join(directory, "canonical.json");
    const link = path.join(directory, "link.json");
    const hardlink = path.join(directory, "hardlink.json");
    const aliasDirectory = path.join(directory, "alias");
    const realDirectory = path.join(directory, "real");
    const noncanonical = path.join(directory, "noncanonical.json");
    const value = { schema: "dnai.test.v1", nested: { safe: true } };
    await writeFile(canonical, `${JSON.stringify(value, null, 2)}\n`);
    await symlink(canonical, link);
    await createHardLink(canonical, hardlink);
    await mkdir(realDirectory);
    await symlink(realDirectory, aliasDirectory);
    const aliased = path.join(aliasDirectory, "aliased.json");
    await writeFile(path.join(realDirectory, "aliased.json"), `${JSON.stringify(value, null, 2)}\n`);
    await writeFile(noncanonical, JSON.stringify(value));

    await rm(hardlink);
    assert.deepEqual(await loadJson(canonical, "test release input"), value);
    await assert.rejects(
      loadJson(link, "test release input"),
      /stable no-follow regular file/,
    );
    await createHardLink(canonical, hardlink);
    await assert.rejects(
      loadJson(hardlink, "test release input"),
      /stable no-follow regular file/,
    );
    await rm(hardlink);
    await assert.rejects(
      loadJson(aliased, "test release input"),
      /stable no-follow regular file/,
    );
    await assert.rejects(
      loadDeploymentIntent(link),
      /stable no-follow regular file/,
    );
    await assert.rejects(
      loadDeploymentIntent(canonical),
      /not a canonical valid predeployment artifact/,
    );
    await assert.rejects(
      loadJson(noncanonical, "test release input"),
      /not canonical duplicate-free release JSON/,
    );
    await chmod(canonical, 0o662);
    await assert.rejects(
      loadJson(canonical, "group-writable release input"),
      /unsafe ownership, mode, or link identity/,
    );
    await chmod(canonical, 0o600);
    const artifact = await loadBoundedArtifact(canonical, "bounded evidence");
    assert.deepEqual(artifact.value, value);
    assert.equal(artifact.raw.equals(Buffer.from(`${JSON.stringify(value, null, 2)}\n`)), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("exact-37 loader reads distinct canonical private transcripts once", async () => {
  const directory = await realpath(await mkdtemp(
    path.join(tmpdir(), "dnai-exact37-inputs-"),
  ));
  try {
    const argv = [];
    for (const [index, flag] of SEMANTIC_VALIDATOR_INPUT_FLAGS.entries()) {
      const filePath = path.join(directory, `${String(index).padStart(2, "0")}.json`);
      await writeFile(filePath, `${JSON.stringify({ flag }, null, 2)}\n`);
      argv.push(flag, filePath);
    }
    const parsed = parseArgs(["--check-only", ...argv]);
    const loaded = await loadExactSemanticValidatorInputs(parsed);
    assert.equal(loaded.entries.length, 37);
    assert.equal(loaded.artifactPaths.entries.length, 37);
    assert.equal(Object.keys(loaded.byFlag).length, 37);
    assert.equal(Object.keys(loaded.byKey).length, 37);
    assert.equal(loaded.byFlag["--release"], loaded.byKey.release);
    assert.equal(loaded.byKey.release.value.flag, "--release");
    assert.equal(loaded.byKey.release.text, `${JSON.stringify({ flag: "--release" }, null, 2)}\n`);
    assert.equal(Object.isFrozen(loaded.byKey.release.value), true);
    assert.equal(Object.isFrozen(loaded.byKey.release.metadata), true);
    const callerBytes = loaded.byKey.release.bytes;
    callerBytes[0] = 0;
    assert.equal(
      loaded.byKey.release.bytes.equals(Buffer.from(loaded.byKey.release.text, "utf8")),
      true,
    );
    assert.match(loaded.byKey.release.rawSha256, /^sha256:[0-9a-f]{64}$/);
    assert.ok(loaded.totalBytes > 74);
    assert.equal(
      await assertExactSemanticValidatorInputsUnchanged(loaded),
      loaded,
    );
    const prebuildArgv = argv.filter((_value, index) => {
      const flagIndex = index % 2 === 0 ? index : index - 1;
      return PREBUILD_SEMANTIC_VALIDATOR_INPUT_FLAGS.includes(argv[flagIndex]);
    });
    const prebuildParsed = parsePrebuildArgs(prebuildArgv);
    const prebuildLoaded = await loadExactPrebuildSemanticValidatorInputs(
      prebuildParsed,
    );
    assert.equal(prebuildLoaded.entries.length, 35);
    assert.equal(Object.keys(prebuildLoaded.byKey).length, 35);
    const duplicate = { ...parsed, releaseCore: parsed.release };
    await assert.rejects(
      loadExactSemanticValidatorInputs(duplicate),
      /37 distinct private input files/,
    );

    await writeFile(parsed.computeWorkloadQvlIdentityRequest, "{\"not\":\"canonical\"}\n");
    await assert.rejects(
      assertExactSemanticValidatorInputsUnchanged(loaded),
      /changed after its exact read/,
    );
    await assert.rejects(
      loadExactSemanticValidatorInputs(parsed),
      /not canonical duplicate-free release JSON/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("main reaches only the fail-closed Model-A handoff after exact-37 loading", async () => {
  const directory = await realpath(await mkdtemp(
    path.join(tmpdir(), "dnai-model-a-handoff-"),
  ));
  const originalLog = console.log;
  const stdout = [];
  try {
    const argv = [];
    for (const [index, flag] of SEMANTIC_VALIDATOR_INPUT_FLAGS.entries()) {
      const filePath = path.join(directory, `${String(index).padStart(2, "0")}.json`);
      await writeFile(filePath, `${JSON.stringify({ flag }, null, 2)}\n`, {
        mode: 0o600,
      });
      argv.push(flag, filePath);
    }
    console.log = (value) => { stdout.push(String(value)); };
    await assert.rejects(
      main(["--check-only", ...argv]),
      /Model-A exact-37 semantic validator integration is incomplete/,
    );
    assert.deepEqual(stdout, []);
    await assert.rejects(
      main([
        "--authority-review-envelope",
        path.join(directory, "legacy-review.json"),
      ]),
      /unknown argument: --authority-review-envelope/,
    );
    assert.deepEqual(stdout, []);
  } finally {
    console.log = originalLog;
    await rm(directory, { recursive: true, force: true });
  }
});
