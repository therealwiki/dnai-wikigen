import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

import {
  CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS,
  validateCurrentModelAPrebuildAuthority,
} from "../web/scripts/current-model-a-prebuild-semantic-validator.mjs";
import {
  loadExactPrebuildSemanticValidatorInputs,
  parsePrebuildArgs,
} from "../web/scripts/build-release-env.mjs";
import { EXACT35_MODEL_A_INPUT_FLAGS, EXACT37_MODEL_A_INPUT_FLAGS }
  from "./exact37-model-a-semantic-validator.mjs";

const root = fileURLToPath(new URL("..", import.meta.url));
const execFileAsync = promisify(execFile);

test("current pre-D37 is distinct from frozen historical35/37 and excludes C/D", () => {
  assert.equal(CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.length, 37);
  assert.equal(EXACT35_MODEL_A_INPUT_FLAGS.length, 35);
  assert.equal(EXACT37_MODEL_A_INPUT_FLAGS.length, 37);
  assert.deepEqual(CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.filter((flag) => ![
    "--royalty-release-history-receipt", "--post-measurement-activation-execution-receipt",
  ].includes(flag)), EXACT35_MODEL_A_INPUT_FLAGS);
  assert.equal(CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.includes("--live-activation-authority"), false);
  assert.equal(CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.includes("--frontend-build-candidate-receipt"), false);
  const index = CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.indexOf("--compute-workload-activation-observation");
  assert.equal(CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS[index - 1], "--post-measurement-activation-execution-receipt");
});

test("current prebuild options reject getters and validate explicit time before input data", async () => {
  let touched = false;
  const inputs = Object.defineProperty({}, "entries", { get() { touched = true; throw new Error("input getter"); } });
  for (const validationTimeMs of [undefined, 0, -1, 1.5, 1_784_635_200_001, 4_102_444_801_000]) {
    await assert.rejects(validateCurrentModelAPrebuildAuthority({ inputs, validationTimeMs, reviewerStatusHistory: [] }),
      /validationTimeMs/);
  }
  assert.equal(touched, false);
  const options = { validationTimeMs: 1_784_635_200_000, reviewerStatusHistory: [] };
  Object.defineProperty(options, "inputs", { enumerable: true, get() { touched = true; throw new Error("option getter"); } });
  await assert.rejects(validateCurrentModelAPrebuildAuthority(options), /required fields/);
  assert.equal(touched, false);
  await assert.rejects(validateCurrentModelAPrebuildAuthority(new Proxy({}, { ownKeys() { touched = true; return []; } })),
    /plain data record/);
  assert.equal(touched, false);
});

test("actual CLI stable-file getter inputs reach current core validation without reading bytes", async () => {
  const directory = await realpath(await mkdtemp(path.join(tmpdir(), "dnai-current-prebuild-loader-")));
  try {
    const argv = [];
    for (const [index, flag] of CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS.entries()) {
      const file = path.join(directory, `${index}.json`);
      await writeFile(file, JSON.stringify({ unique_artifact: flag }, null, 2) + "\n", { mode: 0o600 });
      argv.push(flag, file);
    }
    const inputs = await loadExactPrebuildSemanticValidatorInputs(parsePrebuildArgs(argv));
    assert.equal(typeof Object.getOwnPropertyDescriptor(inputs.entries[0], "bytes").get, "function");
    await assert.rejects(validateCurrentModelAPrebuildAuthority({
      inputs, validationTimeMs: 1_784_635_200_000, reviewerStatusHistory: [],
    }), /final release|release authority core|release core|schema|core fields/i);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

// Explicit isolated unit-orchestration boundary, NOT end-to-end deployment:
// 1. Replace only recorded A/L/R/B/reviewer/raw14/DCAP reconstruction with inert
//    independently constructed facts. The actual shared file normalizer stays.
// 2. Replace full candidate structural/trust-domain normalization with its
//    already-shaped shared-fact projection. Actual current core/R/H binding stays.
// Current core-v4, receipt-v4, signatures, receipt-proof/target/profile binding,
// all independent O expectations, evidence leases and real CLI file loader run.
// No production injection seam or brand waiver is added to make this test pass.
const CURRENT_PREBUILD_HARNESS = String.raw`
import assert from "node:assert/strict";
import { mock } from "node:test";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createCurrentPrebuildObservationFixture } from "./scripts/current-model-a-prebuild-observation.fixture.mjs";
import { syntheticCurrentReleaseCoreBindingFixture } from "./scripts/execution-policy-release-core-binding.fixture.mjs";
import { phalaPostMeasurementActivationExecutionReceiptSha256 } from "./scripts/phala-post-measurement-activation-receipt-v4-core.mjs";
import { assertHistoricallyVerifiedComputeWorkloadActivationObservation,
  normalizeComputeWorkloadActivationObservationHistoricalReplay } from "./scripts/compute-workload-activation-observation-core.mjs";
const at = (relative) => pathToFileURL(path.join(process.cwd(), relative)).href;
const sharedUrl = at("scripts/exact37-model-a-semantic-validator.mjs");
const shared = await import(sharedUrl);
let authenticated;
let prefixCalls = 0;
mock.module(sharedUrl, { namedExports: { ...shared,
  reconstructModelARecordedLaunchAuthority: async ({ exactInputs }) => {
    assert.equal(exactInputs.entries.length, 37);
    assert.equal(Object.hasOwn(exactInputs.byKey, "liveActivationAuthority"), false);
    assert.equal(Object.hasOwn(exactInputs.byKey, "frontendBuildCandidateReceipt"), false);
    prefixCalls += 1;
    return structuredClone(authenticated);
  },
} });
const candidateUrl = at("web/scripts/release-env-core.mjs");
const candidates = await import(candidateUrl);
mock.module(candidateUrl, { namedExports: { ...candidates,
  normalizeReleaseCandidate: (value, options) => {
    assert.deepEqual(options, { authorityStage: "prebuild" });
    assert.equal(value.operator_policy.schema, "dnai.pre-live-activation-authority-evidence.v1",
      "mocked full-candidate boundary must preserve the real prebuild schema");
    return structuredClone(value);
  },
} });
const { validateCurrentModelAPrebuildAuthority, CURRENT_MODEL_A_PREBUILD_INPUT_FLAGS: flags } =
  await import(at("web/scripts/current-model-a-prebuild-semantic-validator.mjs"));
const { loadExactPrebuildSemanticValidatorInputs, parsePrebuildArgs } =
  await import(at("web/scripts/build-release-env.mjs"));
const fixture = await createCurrentPrebuildObservationFixture();
const binding = await syntheticCurrentReleaseCoreBindingFixture({ runtimeAuthority: fixture.runtimeAuthority });
const baseline = Object.fromEntries(flags.map((flag) => [flag, { unique_mocked_prefix_artifact: flag }]));
Object.assign(baseline, {
  "--release": binding.candidate,
  "--release-core": binding.core,
  "--runtime-authority-dependency": binding.runtimeAuthority,
  "--royalty-release-history-receipt": binding.royaltyReleaseHistoryReceipt,
  "--post-measurement-activation-execution-receipt": fixture.receipt,
  "--compute-workload-activation-observation": fixture.observation,
});
const directory = await realpath(await mkdtemp(path.join(tmpdir(), "dnai-prebuild-current-orchestration-")));
let caseCount = 0;
async function run(mutator = () => {}, fixtureOverride = null) {
  const artifacts = structuredClone(baseline);
  authenticated = structuredClone(fixtureOverride?.authority ?? fixture.authority);
  if (fixtureOverride) {
    artifacts["--post-measurement-activation-execution-receipt"] = structuredClone(fixtureOverride.receipt);
    artifacts["--compute-workload-activation-observation"] = structuredClone(fixtureOverride.observation);
  }
  mutator(artifacts, authenticated);
  const argv = [];
  for (const [index, flag] of flags.entries()) {
    const file = path.join(directory, index + ".json");
    await writeFile(file, JSON.stringify(artifacts[flag], null, 2) + "\n", { mode: 0o600 });
    argv.push(flag, file);
  }
  const inputs = await loadExactPrebuildSemanticValidatorInputs(parsePrebuildArgs(argv));
  assert.equal(typeof Object.getOwnPropertyDescriptor(inputs.entries[0], "bytes").get, "function");
  caseCount += 1;
  return validateCurrentModelAPrebuildAuthority({ inputs, validationTimeMs: fixture.now * 1_000, reviewerStatusHistory: [] });
}
const pin = (byte) => "sha256:" + byte.repeat(32);
const receiptKey = "--post-measurement-activation-execution-receipt";
const oKey = "--compute-workload-activation-observation";
try {
  const result = await run();
  assert.equal(result.schema, "dnai.current-model-a-prebuild-semantic-validation.v1");
  assert.equal(result.prebuildObservationReplay.signed_c_authorization_verified, false);
  assert.equal(result.prebuildObservationReplay.production_brand_minted, false);
  assert.equal(result.prebuildObservationReplay.completed_at, fixture.now);
  assert.equal(result.liveTrafficAuthorized, false);
  assert.equal(result.computeWorkloadObservationExpectations.postMeasurementActivationExecutionReceiptSha256,
    phalaPostMeasurementActivationExecutionReceiptSha256(fixture.receipt));
  assert.equal(Object.keys(result.computeWorkloadObservationExpectations).length, 35);
  assert.equal(result.semanticLineage.post_measurement_activation_execution_receipt_sha256,
    result.authorityBinding.postMeasurementActivationExecutionReceiptSha256);
  assert.equal(result.normalizedArtifacts.prebuildObservationReplay, result.prebuildObservationReplay);
  assert.equal(Object.isFrozen(result.computeWorkloadObservationExpectations), true);
  assert.equal(Object.hasOwn(result.normalizedArtifacts, "stageTwo"), false);
  // Final C must use an explicit separate replay at its actual signing second.
  assert.throws(() => normalizeComputeWorkloadActivationObservationHistoricalReplay(result.prebuildObservationReplay), /frozen fields/);
  const laterC = assertHistoricallyVerifiedComputeWorkloadActivationObservation({
    persistedObservation: fixture.observation,
    expected: result.computeWorkloadObservationExpectations,
    authorizedAtMs: (fixture.now + 1) * 1_000,
  });
  assert.equal(laterC.authorized_at, fixture.now + 1);
  assert.throws(() => assertHistoricallyVerifiedComputeWorkloadActivationObservation({
    persistedObservation: fixture.observation,
    expected: result.computeWorkloadObservationExpectations,
    authorizedAtMs: fixture.receipt.terminal_evidence_lease_expires_at * 1_000,
  }), /signed-C historical authority/);
  const laterCompletion = await run((a) => {
    a[receiptKey].completed_at = new Date((fixture.now + 1) * 1_000).toISOString().replace(".000Z", "Z");
    a[oKey].lineage.post_measurement_activation_execution_receipt_sha256 = phalaPostMeasurementActivationExecutionReceiptSha256(a[receiptKey]);
  });
  assert.equal(laterCompletion.prebuildObservationReplay.completed_at, fixture.now + 1,
    "O replay time comes from independently validated receipt, not O.verified_at");

  const before = prefixCalls;
  await assert.rejects(run((a) => { a["--release-core"].schema = "dnai.final-release-authority-core.v3"; }), /schema/);
  await assert.rejects(run((a) => { a[receiptKey].schema = "dnai.phala-post-measurement-activation-execution-receipt.v3"; }), /truth boundary/);
  assert.equal(prefixCalls, before, "old core/receipt fail before authenticated prefix");
  await assert.rejects(run((_a, auth) => { auth.freshContractDescriptorTuple.authority_tuple = "historical"; }), /current contract/);
  for (const field of [
    "deployment_intent_sha256", "cvm_launch_intent_sha256", "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256", "seven_cvm_verified_evidence_set_sha256",
    "phala_recovery_directory_identity_anchor_sha256", "pre_ceremony_runtime_authority_sha256",
    "post_measurement_activation_plan_sha256", "ceremony_authorization_sha256", "batch_id",
    "runtime_commitments_sha256", "runtime_commitment_key_names_sha256",
    "allowed_environment_key_names_sha256", "injected_environment_key_names_sha256",
  ]) await assert.rejects(run((a) => { a[receiptKey][field] = pin("f9"); }), new RegExp(field));
  for (const field of ["descriptor_sha256", "app_id", "cvm_id", "compose_hash", "os_image_hash"]) {
    await assert.rejects(run((a) => { a[receiptKey].target[field] = {
      descriptor_sha256: pin("f9"), app_id: "f9".repeat(20), cvm_id: "cvm-unknown-09",
      compose_hash: "f9".repeat(32), os_image_hash: "f9".repeat(32),
    }[field]; }), new RegExp(field));
  }
  await assert.rejects(run((a) => { a[receiptKey].profile_activation.profile_names = ["compute-execution"]; }), /profile/);
  await assert.rejects(run((_a, auth) => { auth.runtimeAuthority.post_measurement_activation_plan.profile_activation.compose_profiles_value = "compute-execution"; }), /profiles/);
  await assert.rejects(run((a) => { a[receiptKey].initial_activation_evidence_lease_expires_at += 1; }), /initial_activation_evidence_lease|lease/);
  await assert.rejects(run((a) => { a[receiptKey].terminal_evidence_lease_expires_at += 1; }), /exact Arena and Compute proofs/);
  await assert.rejects(run((_a, auth) => { auth.stageOne.review.signed_at = new Date(fixture.now * 1_000).toISOString(); }), /outside signed B/);
  await assert.rejects(run((_a, auth) => { auth.stageOne.review.expires_at = new Date(fixture.now * 1_000).toISOString(); }), /outside signed B/);
  await assert.rejects(run((a) => { a[receiptKey].completed_at = new Date(fixture.receipt.terminal_evidence_lease_expires_at * 1_000).toISOString().replace(".000Z", "Z"); }), /journal-before-mutation and post-restart evidence/);
  await assert.rejects(run((_a, auth) => { auth.launchReceipt.domains.push(structuredClone(auth.launchReceipt.domains[0])); }), /exactly one main_runtime/);
  await assert.rejects(run((_a, auth) => { auth.bootstrapAuthority.domains[0].values.TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE = "0x" + "fe".repeat(32); }), /ceremony nonce/);
  await assert.rejects(run((a) => { a[oKey].lineage.seven_cvm_verified_evidence_set_sha256 = pin("f9"); }), /lineage|authority|set/);
  for (const field of ["source_activation_sha256", "raw_transcript_sha256",
    "qvl_verdict_verifier_signature_sha256", "tdx_quote_sha256", "recipient_key_id",
    "recipient_release_commitment", "challenge_id", "report_data"]) {
    await assert.rejects(run((a) => {
      a[receiptKey].recipient_activation[field] = ["challenge_id", "report_data"].includes(field)
        ? "0x" + "f9".repeat(32) : pin("f9");
      a[oKey].lineage.post_measurement_activation_execution_receipt_sha256 = phalaPostMeasurementActivationExecutionReceiptSha256(a[receiptKey]);
    }), new RegExp("receipt/O recipient " + field));
  }
  for (const field of ["allowed_environment_key_count", "injected_environment_key_count"]) {
    await assert.rejects(run((a) => { a[receiptKey][field] += 1; }), /count|environment/);
  }
  await assert.rejects(run((a) => { a["--release-core"].requested_features.contract_writes = !a["--release-core"].requested_features.contract_writes; }), /shared pre-anchor facts/);
  await assert.rejects(run((a) => { a["--release-core"].royalty_release_history_sha256 = pin("f9"); }), /Royalty history/);
  await assert.rejects(run((a) => { a["--release"].operator_policy.runtime_authority_dependency_sha256 = pin("f9"); }), /candidate R/);
  const forged = await createCurrentPrebuildObservationFixture({ invalidSignature: true });
  await assert.rejects(run(() => {}, forged), /signature|signer|recover/);
  console.log(JSON.stringify({ cases: caseCount, prefixCalls, truth: "two_explicit_test_mocks_real_current_core_receipt_O_and_file_loader_not_E2E" }));
} finally {
  await rm(directory, { recursive: true, force: true });
}
`;

test("isolated current prebuild succeeds without C and rejects independent authority/proof mutations", async () => {
  const { stdout } = await execFileAsync(process.execPath,
    ["--experimental-test-module-mocks", "--input-type=module", "-e", CURRENT_PREBUILD_HARNESS],
    { cwd: root, maxBuffer: 4 * 1024 * 1024 }).catch((error) => {
      assert.fail(`isolated prebuild harness failed:\n${error.stderr || error.message}`);
    });
  const result = JSON.parse(stdout.trim());
  assert.ok(result.cases >= 38);
  assert.ok(result.prefixCalls >= 30);
  assert.equal(result.truth, "two_explicit_test_mocks_real_current_core_receipt_O_and_file_loader_not_E2E");
});

test("current validator contains no injected verifier or synthetic future-C fallback", () => {
  const source = readFileSync(new URL("../web/scripts/current-model-a-prebuild-semantic-validator.mjs", import.meta.url), "utf8");
  for (const forbidden of ["Date.now(", "new Date()", "input.liveActivationAuthority", "stageTwo", "mock.module", "__test", "verifyQuote:"]) {
    assert.equal(source.includes(forbidden), false, forbidden);
  }
  assert.match(source, /assertPrebuildVerifiedComputeWorkloadActivationObservation/);
  assert.match(source, /computeWorkloadObservationExpectations/);
});
