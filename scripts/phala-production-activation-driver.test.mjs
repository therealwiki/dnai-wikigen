import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  PHALA_PRODUCTION_ACTIVATION_DRIVER_REQUEST_SCHEMA,
  PHALA_PRODUCTION_ACTIVATION_DRIVER_STATES,
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
  normalizePhalaProductionPostlaunchInputManifest,
  normalizePhalaProductionActivationDriverRequest,
  waitForPostlaunchActivationInputs,
} from "./phala-production-activation-driver.mjs";
import {
  canonicalResidentJsonText,
  residentRawSha256,
} from "./phala-production-resident-io.mjs";
import {
  closePhalaPinnedPrivateDirectory,
  phalaPinnedPrivateDirectoryIdentityAnchorSha256,
  pinPhalaPrivateDirectory,
} from "./phala-pinned-private-directory.mjs";

const REPOSITORY_ROOT = fs.realpathSync.native(
  fileURLToPath(new URL("../", import.meta.url)),
);
const SOURCE_PATH = fileURLToPath(new URL(
  "./phala-production-activation-driver.mjs",
  import.meta.url,
));
const POSTLAUNCH_CAPABILITY_SOURCE_PATH = fileURLToPath(new URL(
  "./phala-production-postlaunch-activation-capability.mjs",
  import.meta.url,
));
const execFileAsync = promisify(execFile);

function privateRoot(t) {
  const root = fs.realpathSync.native(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-resident-driver-")),
  );
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

function writeBinding(root, basename, value = {}, mode = 0o600) {
  const bytes = Buffer.from(canonicalResidentJsonText(value), "utf8");
  const filePath = path.join(root, basename);
  fs.writeFileSync(filePath, bytes, { mode });
  fs.chmodSync(filePath, mode);
  return Object.freeze({ path: filePath, sha256: residentRawSha256(bytes) });
}

function prepareAuthority(root, basename) {
  const authorityPath = path.join(root, basename);
  fs.mkdirSync(authorityPath, { mode: 0o700 });
  const handle = pinPhalaPrivateDirectory(authorityPath);
  const identityAnchorSha256 =
    phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle);
  closePhalaPinnedPrivateDirectory(handle);
  return Object.freeze({
    path: authorityPath,
    identity_anchor_sha256: identityAnchorSha256,
  });
}

function postlaunchWaitFixture(
  root,
  {
    manifestAcceptanceDeadline = new Date(Date.now() + 60_000).toISOString(),
  } = {},
) {
  const sha = (pair) => `sha256:${pair.repeat(32)}`;
  const expected = Object.freeze({
    release_sha: "ab".repeat(20),
    batch_id: "postlaunch-wait-batch",
    deployment_intent_sha256: sha("21"),
    cvm_launch_intent_sha256: sha("22"),
    release_verification_authority_sha256: sha("23"),
    seven_cvm_verified_evidence_set_sha256: sha("24"),
    seven_cvm_launch_completion_receipt_sha256: sha("25"),
    manifest_acceptance_deadline: manifestAcceptanceDeadline,
    postlaunch_projection_raw_file_sha256: sha("26"),
    postlaunch_request_raw_file_sha256: sha("27"),
  });
  const binding = (name, mode = 0o600) => writeBinding(
    root,
    `${name}.json`,
    { name },
    mode,
  );
  const dependencies = {
    ceremonyLedgerInitial: binding("wait-ledger"),
    ceremonyLedgerInitializationReceipt: binding("wait-ledger-init", 0o444),
    ceremonyTransactionPlan: binding("wait-transaction-plan"),
    deferredAuthorityReview: binding("wait-deferred-review"),
    immutableDeploymentManifest: binding("wait-immutable-manifest", 0o444),
    stageBReviewerStatusHistory: writeBinding(
      root,
      "wait-stage-b-reviewer-status-history.json",
      [],
    ),
    reviewedFinalAuthorityFiles: {
      cvmLaunchIntent: binding("wait-launch-intent"),
      deploymentIntent: binding("wait-deployment-intent"),
      finalAuthority: binding("wait-final-authority"),
      reviewEnvelope: binding("wait-review-envelope"),
      reviewEvidence: binding("wait-review-evidence"),
    },
  };
  const manifest = {
    schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
    status: "postlaunch_activation_inputs_ready_for_validation",
    truth_status:
      "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority",
    ...expected,
    dependencies,
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  };
  return {
    expected,
    manifest,
    handoff: {
      projection: {
        release_sha: expected.release_sha,
        batch_id: expected.batch_id,
        deployment_intent_sha256: expected.deployment_intent_sha256,
        cvm_launch_intent_sha256: expected.cvm_launch_intent_sha256,
        release_verification_authority_sha256:
          expected.release_verification_authority_sha256,
        seven_cvm_verified_evidence_set_sha256:
          expected.seven_cvm_verified_evidence_set_sha256,
        seven_cvm_launch_completion_receipt_sha256:
          expected.seven_cvm_launch_completion_receipt_sha256,
      },
      postlaunch_projection_raw_file_sha256:
        expected.postlaunch_projection_raw_file_sha256,
      postlaunch_request_raw_file_sha256:
        expected.postlaunch_request_raw_file_sha256,
      request: {
        schema: "dnai.phala-production-postlaunch-authority-request.v2",
        manifest_acceptance_deadline:
          expected.manifest_acceptance_deadline,
        required_input: {
          schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
        },
      },
    },
  };
}

function requestFixture(root) {
  const ordinary = (name) => writeBinding(root, `${name}.json`, { name });
  const request = {
    schema: PHALA_PRODUCTION_ACTIVATION_DRIVER_REQUEST_SCHEMA,
    launch: {
      repositoryRoot: REPOSITORY_ROOT,
      releaseDirectory: root,
      imageReleaseManifestPath: path.join(root, "launch-image-manifest.json"),
      imageReleaseSigstoreBundlePath: path.join(root, "launch-sigstore-bundle.json"),
      imageReleaseSigstoreVerificationReceiptPath: path.join(root, "launch-sigstore-receipt.json"),
      authorizationPath: path.join(root, "launch-authorization.json"),
      bootstrapAuthorityPath: path.join(root, "launch-bootstrap.json"),
      deploymentIntentPath: path.join(root, "launch-deployment-intent.json"),
      reviewerAuthorityGenesisPath: path.join(root, "launch-reviewer-genesis.json"),
      reviewerAuthorityGenesisAcceptancePath: path.join(root, "launch-reviewer-acceptance.json"),
      freshContractDeploymentReceiptPath: path.join(root, "launch-contract-receipt.json"),
      compatibilityReceiptPath: path.join(root, "launch-compatibility.json"),
      sdkWireTransformStagingReceiptPath: path.join(root, "launch-staging.json"),
      productionTargetAuthorityPath: path.join(root, "launch-target.json"),
      phaseSecretInputPaths: {},
      recoveryDirectory: path.join(root, "launch-recovery"),
    },
    activation: {
      descriptorSetReceipt: ordinary("descriptor-set"),
      freshContractDeploymentReceipt: ordinary("fresh-contract-receipt"),
      measurementPolicySet: ordinary("measurement-policy-set"),
      releaseManifestSigstoreVerificationReceipt: ordinary("sigstore-verification"),
      reviewerGenesis: ordinary("reviewer-genesis"),
      reviewerGenesisAcceptance: ordinary("reviewer-acceptance"),
      bootstrapPhaseInput: ordinary("bootstrap-phase"),
      finalPhaseInput: ordinary("final-phase"),
      evidenceExchangeAuthority: prepareAuthority(root, "evidence-exchange"),
      postlaunchAuthorityExchangeAuthority:
        prepareAuthority(root, "postlaunch-authority-exchange"),
      signingExchangeAuthority: prepareAuthority(root, "signing-exchange"),
      outputAuthority: prepareAuthority(root, "activation-outputs"),
      evidenceTimeoutSeconds: 20,
      postlaunchAuthorityTimeoutSeconds: 20,
      signingTimeoutSeconds: 20,
      recipientTimeoutSeconds: 10,
      pollIntervalMilliseconds: 25,
      qvlIdentityTtlSeconds: 30,
      independentMeteringPolicySetHash: `0x${"71".repeat(32)}`,
    },
  };
  return request;
}

test("resident request preflights every binding and exact pre-existing authority", (t) => {
  const root = privateRoot(t);
  const request = requestFixture(root);
  const normalized = normalizePhalaProductionActivationDriverRequest(request);
  assert.equal(normalized.schema, PHALA_PRODUCTION_ACTIVATION_DRIVER_REQUEST_SCHEMA);
  assert.equal(
    normalized.activation.bootstrapPhaseInput.path,
    request.activation.bootstrapPhaseInput.path,
  );
  const forged = structuredClone(request);
  forged.activation.evidenceExchangeAuthority.identity_anchor_sha256 =
    `sha256:${"00".repeat(32)}`;
  assert.throws(
    () => normalizePhalaProductionActivationDriverRequest(forged),
    /identity anchor is invalid/,
  );
});

test("resident v3 request contains only prelaunch file bindings", (t) => {
  const root = privateRoot(t);
  const request = requestFixture(root);
  const normalized = normalizePhalaProductionActivationDriverRequest(request);
  for (const field of [
    "ceremonyLedgerInitial",
    "ceremonyLedgerInitializationReceipt",
    "ceremonyTransactionPlan",
    "deferredAuthorityReview",
    "immutableDeploymentManifest",
    "reviewedFinalAuthorityFiles",
    "reviewerStatusHistory",
  ]) {
    assert.equal(Object.hasOwn(normalized.activation, field), false);
    const forged = structuredClone(request);
    forged.activation[field] = {};
    assert.throws(
      () => normalizePhalaProductionActivationDriverRequest(forged),
      /exact schema/,
    );
  }
});

test("resident request rejects legacy v2 and v3 with legacy reviewer history", (t) => {
  const root = privateRoot(t);
  const request = requestFixture(root);

  const legacySchema = structuredClone(request);
  legacySchema.schema = "dnai.phala-production-activation-driver-request.v2";
  assert.throws(
    () => normalizePhalaProductionActivationDriverRequest(legacySchema),
    /request schema is invalid/,
  );

  const legacyHistory = structuredClone(request);
  legacyHistory.activation.reviewerStatusHistory = writeBinding(
    root,
    "legacy-prelaunch-reviewer-history.json",
    [],
  );
  assert.throws(
    () => normalizePhalaProductionActivationDriverRequest(legacyHistory),
    /exact schema/,
  );
});

test("postlaunch authority exchange is identity-bound and disjoint", (t) => {
  const root = privateRoot(t);
  const request = requestFixture(root);
  const duplicate = structuredClone(request);
  duplicate.activation.postlaunchAuthorityExchangeAuthority =
    duplicate.activation.evidenceExchangeAuthority;
  assert.throws(
    () => normalizePhalaProductionActivationDriverRequest(duplicate),
    /must be distinct/,
  );

  const nested = structuredClone(request);
  nested.activation.postlaunchAuthorityExchangeAuthority.path = path.join(
    nested.activation.evidenceExchangeAuthority.path,
    "nested",
  );
  assert.throws(
    () => normalizePhalaProductionActivationDriverRequest(nested),
    /must not contain one another/,
  );
});

test("postlaunch manifest has exact lineage and file-binding shape", (t) => {
  const root = privateRoot(t);
  const binding = (name, mode = 0o600) => writeBinding(
    root,
    `${name}.json`,
    { name },
    mode,
  );
  const sha = (pair) => `sha256:${pair.repeat(32)}`;
  const expected = {
    release_sha: "ab".repeat(20),
    batch_id: "postlaunch-batch",
    deployment_intent_sha256: sha("11"),
    cvm_launch_intent_sha256: sha("12"),
    release_verification_authority_sha256: sha("13"),
    seven_cvm_verified_evidence_set_sha256: sha("14"),
    seven_cvm_launch_completion_receipt_sha256: sha("15"),
    manifest_acceptance_deadline:
      new Date(Date.now() + 60_000).toISOString(),
    postlaunch_projection_raw_file_sha256: sha("16"),
    postlaunch_request_raw_file_sha256: sha("17"),
  };
  const manifest = {
    schema: PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_SCHEMA,
    status: "postlaunch_activation_inputs_ready_for_validation",
    truth_status:
      "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority",
    ...expected,
    dependencies: {
      ceremonyLedgerInitial: binding("ledger"),
      ceremonyLedgerInitializationReceipt: binding("ledger-init", 0o444),
      ceremonyTransactionPlan: binding("transaction-plan"),
      deferredAuthorityReview: binding("deferred-review"),
      immutableDeploymentManifest: binding("immutable-manifest", 0o444),
      stageBReviewerStatusHistory: writeBinding(
        root,
        "stage-b-reviewer-status-history.json",
        [],
      ),
      reviewedFinalAuthorityFiles: {
        cvmLaunchIntent: binding("launch-intent"),
        deploymentIntent: binding("deployment-intent"),
        finalAuthority: binding("final-authority"),
        reviewEnvelope: binding("review-envelope"),
        reviewEvidence: binding("review-evidence"),
      },
    },
    automatic_retry_authorized: false,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  };
  const normalized = normalizePhalaProductionPostlaunchInputManifest(
    manifest,
    expected,
  );
  assert.equal(
    normalized.dependencies.reviewedFinalAuthorityFiles.finalAuthority.path,
    manifest.dependencies.reviewedFinalAuthorityFiles.finalAuthority.path,
  );
  const legacyManifest = structuredClone(manifest);
  legacyManifest.schema =
    "dnai.phala-production-postlaunch-activation-input-manifest.v1";
  assert.throws(
    () => normalizePhalaProductionPostlaunchInputManifest(
      legacyManifest,
      expected,
    ),
    /lineage or posture is invalid/,
  );
  for (const field of Object.keys(expected)) {
    const forged = structuredClone(manifest);
    forged[field] = field === "batch_id" ? "wrong-batch" : sha("ff");
    assert.throws(
      () => normalizePhalaProductionPostlaunchInputManifest(forged, expected),
      /lineage or posture is invalid/,
    );
  }
  const extra = structuredClone(manifest);
  extra.dependencies.unreviewed = binding("unreviewed");
  assert.throws(
    () => normalizePhalaProductionPostlaunchInputManifest(extra, expected),
    /fields do not match the exact schema/,
  );
});

test("postlaunch manifest wait enforces canonical mode, stable bindings, and exact directory", async (t) => {
  const root = privateRoot(t);
  const authority = prepareAuthority(root, "wait-postlaunch-authority");
  const fixture = postlaunchWaitFixture(root);
  const manifestPath = path.join(
    authority.path,
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  );
  fs.writeFileSync(
    manifestPath,
    canonicalResidentJsonText(fixture.manifest),
    { mode: 0o600 },
  );
  fs.chmodSync(manifestPath, 0o600);
  const handle = pinPhalaPrivateDirectory(authority.path, {
    expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
  });
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const dependencies = await waitForPostlaunchActivationInputs({
    handle,
    handoff: fixture.handoff,
    pollIntervalMilliseconds: 25,
  });
  assert.equal(
    dependencies.reviewedFinalAuthorityFiles.finalAuthority.path,
    fixture.manifest.dependencies.reviewedFinalAuthorityFiles.finalAuthority.path,
  );

  fs.writeFileSync(path.join(authority.path, "unexpected.json"), "{}\n", {
    mode: 0o600,
  });
  await assert.rejects(
    waitForPostlaunchActivationInputs({
      handle,
      handoff: fixture.handoff,
      pollIntervalMilliseconds: 25,
    }),
    /unexpected entries/,
  );
});

test("postlaunch wait rejects manifest mode, dependency mutation, and symlink substitution", async (t) => {
  const run = async (scenario) => {
    const root = privateRoot(t);
    const authority = prepareAuthority(root, `postlaunch-${scenario}`);
    const fixture = postlaunchWaitFixture(root);
    if (scenario === "dependency-mutation") {
      fs.writeFileSync(
        fixture.manifest.dependencies.reviewedFinalAuthorityFiles.finalAuthority.path,
        canonicalResidentJsonText({ changed: true }),
        { mode: 0o600 },
      );
    } else if (scenario === "dependency-symlink") {
      const original = fixture.manifest.dependencies.ceremonyTransactionPlan;
      const symlinkPath = path.join(root, "transaction-plan-symlink.json");
      fs.symlinkSync(original.path, symlinkPath);
      fixture.manifest.dependencies.ceremonyTransactionPlan = {
        path: symlinkPath,
        sha256: original.sha256,
      };
    }
    const manifestPath = path.join(
      authority.path,
      PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
    );
    fs.writeFileSync(
      manifestPath,
      canonicalResidentJsonText(fixture.manifest),
      { mode: scenario === "manifest-mode" ? 0o644 : 0o600 },
    );
    fs.chmodSync(manifestPath, scenario === "manifest-mode" ? 0o644 : 0o600);
    const handle = pinPhalaPrivateDirectory(authority.path, {
      expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
    });
    try {
      await assert.rejects(
        waitForPostlaunchActivationInputs({
          handle,
          handoff: fixture.handoff,
          pollIntervalMilliseconds: 25,
        }),
        /mode-0600|invalid 0644 readiness mode|bytes or file identity changed|canonical and symlink-free/,
      );
    } finally {
      closePhalaPinnedPrivateDirectory(handle);
    }
  };
  await run("manifest-mode");
  await run("dependency-mutation");
  await run("dependency-symlink");
});

test("postlaunch wait is bounded when no manifest arrives", async (t) => {
  const root = privateRoot(t);
  const authority = prepareAuthority(root, "empty-postlaunch-authority");
  const fixture = postlaunchWaitFixture(root, {
    manifestAcceptanceDeadline: new Date(Date.now() + 250).toISOString(),
  });
  const handle = pinPhalaPrivateDirectory(authority.path, {
    expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
  });
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  await assert.rejects(
    waitForPostlaunchActivationInputs({
      handle,
      handoff: fixture.handoff,
      pollIntervalMilliseconds: 25,
    }),
    /deadline expired|not supplied before the bounded deadline/,
  );
});

test("postlaunch validation cannot finish after its hard acceptance deadline", async (t) => {
  const root = privateRoot(t);
  const authority = prepareAuthority(root, "deadline-postlaunch-authority");
  const fixture = postlaunchWaitFixture(root, {
    manifestAcceptanceDeadline: new Date(3_000).toISOString(),
  });
  const manifestPath = path.join(
    authority.path,
    PHALA_PRODUCTION_POSTLAUNCH_INPUT_MANIFEST_BASENAME,
  );
  fs.writeFileSync(
    manifestPath,
    canonicalResidentJsonText(fixture.manifest),
    { mode: 0o600 },
  );
  fs.chmodSync(manifestPath, 0o600);
  const handle = pinPhalaPrivateDirectory(authority.path, {
    expectedIdentityAnchorSha256: authority.identity_anchor_sha256,
  });
  t.after(() => closePhalaPinnedPrivateDirectory(handle));
  const originalNow = Date.now;
  let calls = 0;
  Date.now = () => {
    calls += 1;
    return calls < 5 ? 1_000 : 5_000;
  };
  try {
    await assert.rejects(
      waitForPostlaunchActivationInputs({
        handle,
        handoff: fixture.handoff,
        pollIntervalMilliseconds: 25,
      }),
      /deadline expired|not supplied before the bounded deadline/,
    );
    assert.ok(calls >= 5);
  } finally {
    Date.now = originalNow;
  }
});

test("resident request has no credential, callback, client, or serialized-session field", (t) => {
  const root = privateRoot(t);
  const request = requestFixture(root);
  for (const field of [
    "privateKey", "mnemonic", "keystore", "account", "rpcUrl",
    "client", "callback", "session", "runtimeResult",
    "evidenceExchangeDirectory", "signingExchangeDirectory", "outputDirectory",
  ]) {
    const forged = structuredClone(request);
    forged.activation[field] = "forbidden";
    assert.throws(
      () => normalizePhalaProductionActivationDriverRequest(forged),
      /exact schema/,
    );
  }
});

test("source retains capabilities through the exact ordered resident state machine", () => {
  assert.deepEqual(PHALA_PRODUCTION_ACTIVATION_DRIVER_STATES, [
    "request_preflight_complete",
    "seven_cvm_launch_complete_non_live",
    "collecting_five_qvl_identity_proofs",
    "collecting_two_workload_verdict_proofs",
    "launch_completion_persisted_non_live",
    "waiting_for_postlaunch_activation_inputs",
    "waiting_for_external_stage_b_signatures",
    "post_measurement_runtime_mutated_non_live",
    "waiting_for_compute_recipient_activation",
    "activation_finalized_non_live",
    "bounded_outputs_published_non_live",
  ]);
  const source = fs.readFileSync(SOURCE_PATH, "utf8");
  for (const symbol of [
    "executePhalaSevenCvmProductionLaunch",
    "preparePhalaProductionActivationEvidence",
    "readPhalaProductionActivationEvidenceDependencies",
    "createPhalaQvlIdentityChallenge",
    "verifyPhalaQvlIdentityLaunchEvidence",
    "verifyPhalaWorkloadIndependentTdxVerdict",
    "persistPhalaProductionActivationLaunchCompletion",
    "publishPhalaProductionPostlaunchHandoff",
    "waitForPhalaProductionPostlaunchActivationCapability",
    "disposePhalaProductionPostlaunchActivationCapability",
    "resumePhalaProductionActivationWithPinnedSigningExchange",
    "phalaProductionActivationSigningExchangePaths",
    "beginPhalaProductionActivationFromSignedB",
    "completePhalaProductionActivation",
    "readPhalaProductionActivationRuntimeDeadlines",
    "assertProductionPhalaPostMeasurementActivationExecutionReceipt",
    "assertVerifiedComputeWorkloadActivationObservation",
    "assertActivationExecutionReceiptMatchesComputeWorkloadObservation",
    "projectComputeWorkloadBrowserEnvFromObservation",
  ]) {
    assert.match(source, new RegExp(`\\b${symbol}\\b`));
  }
  assert.doesNotMatch(source, /structuredClone|testOnly|callerSupplied|sdkAdapter/);
  assert.doesNotMatch(source, /\b(?:client|callback)\s*:/);
  assert.match(
    source,
    /persistPhalaProductionActivationLaunchCompletion\([\s\S]*?publishPhalaProductionPostlaunchHandoff\([\s\S]*?waitForPhalaProductionPostlaunchActivationCapability\([\s\S]*?resumePhalaProductionActivationWithPinnedSigningExchange\(/,
  );
  assert.match(
    source,
    /publishPhalaProductionPostlaunchHandoff\(\{[\s\S]*?postlaunchAuthorityTimeoutSeconds:\s*activation\.postlaunchAuthorityTimeoutSeconds,[\s\S]*?\}\);/,
  );
  const capabilityWaitCall = source.slice(
    source.indexOf(
      "await waitForPhalaProductionPostlaunchActivationCapability({",
    ),
    source.indexOf(
      "assertPinnedPhalaPrivateDirectoryPathIdentity(evidenceHandle);",
      source.indexOf(
        "await waitForPhalaProductionPostlaunchActivationCapability({",
      ),
    ),
  );
  assert.doesNotMatch(capabilityWaitCall, /timeoutSeconds\s*:/);
  assert.match(
    source,
    /manifest_acceptance_deadline:\s*postlaunchHandoff\.request\.manifest_acceptance_deadline/,
  );
  assert.match(
    source,
    /let postlaunchActivationCapability = null;[\s\S]*?postlaunchActivationCapability =\s*await waitForPhalaProductionPostlaunchActivationCapability\([\s\S]*?const signingSession = await resumePhalaProductionActivationWithPinnedSigningExchange\([\s\S]*?postlaunchActivationCapability = null;\s*liveSession = signingSession;/,
  );
  assert.match(
    source,
    /finally\s*\{\s*disposePhalaProductionPostlaunchActivationCapability\(\s*postlaunchActivationCapability,?\s*\);\s*if \(!completed\) safeDispose\(liveSession\);/,
  );
  const capabilitySource = fs.readFileSync(
    POSTLAUNCH_CAPABILITY_SOURCE_PATH,
    "utf8",
  );
  const postlaunchValidationSource = capabilitySource.slice(
    capabilitySource.indexOf("async function validatePostlaunchActivationInputs"),
    capabilitySource.indexOf("export async function waitForPostlaunchActivationInputs"),
  );
  assert.equal(
    postlaunchValidationSource.match(
      /assertExactPostlaunchAuthorityExchangeEntries\(handle\)/g,
    )?.length,
    2,
  );
  assert.match(
    postlaunchValidationSource,
    /normalizePhalaProductionPostlaunchInputManifest\([\s\S]*?preflightPhalaProductionPostlaunchDependencies\([\s\S]*?expectedIdentity: read\.identity[\s\S]*?assertPinnedPhalaPrivateDirectoryPathIdentity\(handle\);\s*assertExactPostlaunchAuthorityExchangeEntries\(handle\);[\s\S]*?assertDeadlineActive\(deadlineMs\)[\s\S]*?return/,
  );
  assert.match(capabilitySource, /const SESSION_HANDOFFS = new WeakMap\(\);/);
  assert.match(capabilitySource, /const CAPABILITIES = new WeakMap\(\);/);
  assert.match(
    capabilitySource,
    /state\.consumed = true;[\s\S]*?expectedIdentity: state\.manifestIdentity[\s\S]*?preflightPhalaProductionPostlaunchDependencies\(state\.dependencies\)/,
  );
  assert.match(
    source,
    /const completion = await completePhalaProductionActivation\([\s\S]*?liveSession = null;/,
  );
  assert.doesNotMatch(
    source,
    /liveSession = null;\s*const completion = await completePhalaProductionActivation/,
  );
  assert.match(
    source,
    /const value = \{\s*\.\.\.detail,\s*schema:[\s\S]*?automatic_retry_authorized: false,\s*activation_mutation_authorized: false,\s*live_traffic_authorized: false,/,
  );
});

const PUBLICATION_HARNESS = String.raw`
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mock } from "node:test";
import path from "node:path";
import { pathToFileURL } from "node:url";

const scenario = process.env.PUBLICATION_SCENARIO;
const url = (name) => pathToFileURL(path.join(process.cwd(), "scripts", name)).href;
const mockWithOriginal = async (name, namedExports) => {
  const target = url(name);
  const original = await import(target);
  mock.module(target, { namedExports: { ...original, ...namedExports } });
};
const names = [];
const stored = new Map();
let receiptAssertionCount = 0;
const digest = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
await mockWithOriginal("phala-pinned-private-directory.mjs", {
  assertPinnedPhalaPrivateDirectoryPathIdentity(handle) { return handle; },
  listPhalaPinnedPrivateEntries() { return [...stored.keys()].sort(); },
  phalaPinnedPrivateDirectoryIdentityAnchorSha256() {
    return "sha256:" + "91".repeat(32);
  },
  createExclusivePhalaPinnedPrivateFile(_handle, fileName, bytes) {
    names.push(fileName);
    if (scenario === "middle-failure" && names.length === 2) {
      throw new Error("injected middle output failure");
    }
    const identity = {
      sha256: digest(bytes),
      size: bytes.length,
      mode: "0600",
      device: "1",
      inode: String(names.length),
      uid: "1",
      link_count: 1,
      mtime_ns: String(names.length),
      ctime_ns: String(names.length),
    };
    stored.set(fileName, { bytes: Buffer.from(bytes), identity });
    return identity;
  },
  readPhalaPinnedPrivateFile(_handle, fileName, { expectedIdentity }) {
    const entry = stored.get(fileName);
    assert.equal(entry?.identity, expectedIdentity);
    return Buffer.from(entry.bytes);
  },
});
await mockWithOriginal("phala-post-measurement-activation-receipt.mjs", {
  assertProductionPhalaPostMeasurementActivationExecutionReceipt(value) {
    receiptAssertionCount += 1;
    if (scenario === "unbranded") throw new Error("branded receipt required");
    if (scenario === "expiry-before-first-write" && receiptAssertionCount === 2) {
      throw new Error("terminal evidence lease expired before first write");
    }
    if (scenario === "expiry-before-manifest" && receiptAssertionCount === 3) {
      throw new Error("terminal evidence lease expired before manifest");
    }
    return value;
  },
  canonicalPhalaPostMeasurementActivationExecutionReceiptText(value) {
    return JSON.stringify(value) + "\n";
  },
  phalaPostMeasurementActivationExecutionReceiptSha256() {
    return "sha256:" + "92".repeat(32);
  },
});
await mockWithOriginal("compute-workload-activation-observation.mjs", {
  assertVerifiedComputeWorkloadActivationObservation(value) {
    if (scenario === "unbranded") throw new Error("branded O required");
    return value;
  },
  canonicalComputeWorkloadActivationObservationText(value) {
    return JSON.stringify(value) + "\n";
  },
  computeWorkloadActivationObservationSha256() {
    return "sha256:" + "93".repeat(32);
  },
  projectComputeWorkloadBrowserEnvFromObservation() {
    return { VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true" };
  },
});
await mockWithOriginal("release-authority-stages.mjs", {
  assertActivationExecutionReceiptMatchesComputeWorkloadObservation() {
    return "sha256:" + "92".repeat(32);
  },
});
const driver = await import(url("phala-production-activation-driver.mjs") + "?publication=" + scenario);
let error = null;
let result = null;
try {
  result = driver.publishFinalOutputs(
    { path: "/private/output" },
    {
      live_traffic_authorized: false,
      activation_execution_receipt: {
        receipt: true,
        release_sha: "ab".repeat(20),
        batch_id: "publication-test-batch",
      },
      compute_workload_activation_observation: {
        observation: true,
        release_sha: "ab".repeat(20),
      },
    },
    scenario === "mismatched-env"
      ? { VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "false" }
      : { VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD: "true" },
    { releaseSha: "ab".repeat(20), batchId: "publication-test-batch" },
  );
} catch (caught) {
  error = caught;
}
if (scenario === "middle-failure") {
  assert.match(error?.message || "", /injected middle output failure/);
  assert.equal(names.includes(driver.PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME), false);
} else if (scenario === "mismatched-env" || scenario === "unbranded") {
  assert.match(error?.message || "", /browser environment differs|branded/);
  assert.deepEqual(names, []);
} else if (scenario === "expiry-before-first-write") {
  assert.match(error?.message || "", /expired before first write/);
  assert.deepEqual(names, []);
} else if (scenario === "expiry-before-manifest") {
  assert.match(error?.message || "", /expired before manifest/);
  assert.deepEqual(names, [
    "activation-execution-receipt.json",
    "compute-workload-activation-observation.json",
    "compute-workload-browser-env.json",
  ]);
  assert.equal(names.includes(
    driver.PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME,
  ), false);
} else {
  assert.equal(error, null);
  assert.equal(names.at(-1), driver.PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME);
  assert.equal(result.publication_receipt.basename, names.at(-1));
}
console.log(JSON.stringify({ scenario, names, hasReceipt: names.includes(
  driver.PHALA_PRODUCTION_ACTIVATION_PUBLICATION_RECEIPT_BASENAME,
) }));
`;

async function runPublicationHarness(scenario) {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    PUBLICATION_HARNESS,
  ], {
    cwd: REPOSITORY_ROOT,
    env: { ...process.env, PUBLICATION_SCENARIO: scenario },
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  return JSON.parse(result.stdout.trim().split("\n").at(-1));
}

test("publication-complete receipt is create-new and written strictly last", async () => {
  const value = await runPublicationHarness("success");
  assert.equal(value.hasReceipt, true);
  assert.equal(value.names.length, 4);
  assert.equal(value.names.at(-1), "production-activation-publication-receipt.json");
});

test("middle output failure cannot publish a completion receipt", async () => {
  const value = await runPublicationHarness("middle-failure");
  assert.equal(value.hasReceipt, false);
  assert.deepEqual(value.names, [
    "activation-execution-receipt.json",
    "compute-workload-activation-observation.json",
  ]);
});

test("publication rejects unbranded authority and O-mismatched browser config before writes", async () => {
  for (const scenario of ["unbranded", "mismatched-env"]) {
    const value = await runPublicationHarness(scenario);
    assert.equal(value.hasReceipt, false);
    assert.deepEqual(value.names, []);
  }
});

test("publication rechecks the terminal lease before its first write and completion manifest", async () => {
  const beforeFirst = await runPublicationHarness("expiry-before-first-write");
  assert.deepEqual(beforeFirst.names, []);
  const beforeManifest = await runPublicationHarness("expiry-before-manifest");
  assert.equal(beforeManifest.hasReceipt, false);
  assert.equal(beforeManifest.names.length, 3);
});

const RECIPIENT_FAILURE_HARNESS = String.raw`
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mock } from "node:test";
import { pathToFileURL } from "node:url";

const url = (name) => pathToFileURL(path.join(process.cwd(), "scripts", name)).href;
const scenario = process.env.POSTLAUNCH_SCENARIO || "success";
const canonical = (value) => {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
};
const text = (value) => JSON.stringify(canonical(value), null, 2) + "\n";
const digest = (bytes) => "sha256:" + createHash("sha256").update(bytes).digest("hex");
const sha = (pair) => "sha256:" + pair.repeat(32);
const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "dnai-driver-recipient-failure-")));
fs.chmodSync(root, 0o700);
const write = (basename, value, mode = 0o600) => {
  const file = path.join(root, basename);
  const bytes = Buffer.from(text(value));
  fs.writeFileSync(file, bytes, { mode });
  fs.chmodSync(file, mode);
  return { path: file, sha256: digest(bytes) };
};
const originalPinned = await import(url("phala-pinned-private-directory.mjs"));
const originalCreate = originalPinned.createExclusivePhalaPinnedPrivateFile;
const prepareAuthority = (basename) => {
  const authorityPath = path.join(root, basename);
  fs.mkdirSync(authorityPath, { mode: 0o700 });
  const handle = originalPinned.pinPhalaPrivateDirectory(authorityPath);
  const identity_anchor_sha256 =
    originalPinned.phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle);
  originalPinned.closePhalaPinnedPrivateDirectory(handle);
  return { path: authorityPath, identity_anchor_sha256 };
};
const evidenceAuthority = prepareAuthority("evidence-exchange");
const postlaunchAuthority = prepareAuthority("postlaunch-authority-exchange");
const signingAuthority = prepareAuthority("signing-exchange");
const outputAuthority = prepareAuthority("output");
let postlaunchDependencies;
let postlaunchProjectionObserved = false;
let postlaunchRequestObserved = false;
let stageBAttachmentManifestObserved = false;
let postlaunchCapabilityMinted = false;
let injectedPostMintHandleFailure = false;
let mintedPostlaunchCapability;
let capabilityDisposeCalls = 0;
let exactCapabilityDisposeCalls = 0;
let exactCapabilityBurned = false;
const cleanupEvents = [];
await (async () => {
  const target = url("phala-pinned-private-directory.mjs");
  mock.module(target, { namedExports: {
    ...originalPinned,
    assertPinnedPhalaPrivateDirectoryPathIdentity(handle) {
      if (scenario === "post-mint-handle-failure"
        && postlaunchCapabilityMinted && !injectedPostMintHandleFailure) {
        injectedPostMintHandleFailure = true;
        throw new Error("injected post-mint handle identity failure");
      }
      return originalPinned.assertPinnedPhalaPrivateDirectoryPathIdentity(handle);
    },
    createExclusivePhalaPinnedPrivateFile(handle, fileName, bytes, options) {
      const identity = originalCreate(handle, fileName, bytes, options);
      const response = (name, value) => {
        if (!fs.existsSync(path.join(handle.path, name))) {
          originalCreate(handle, name, Buffer.from(text(value)), { mode: 0o600, maximum: 4 * 1024 * 1024 });
        }
      };
      const identityMatch = /^(0[1-5])-(.+)\.identity-request\.json$/.exec(fileName);
      if (identityMatch) {
        response(fileName.replace(".identity-request.json", ".identity-response.json"), {
          domain: identityMatch[2].replaceAll("-", "_"), response: true,
        });
      }
      const workloadMatch = /^(0[67])-(.+)\.challenge-request\.json$/.exec(fileName);
      if (workloadMatch) {
        response(fileName.replace(".challenge-request.json", ".challenge.json"), { domain: workloadMatch[2].replaceAll("-", "_"), challenge: true });
        response(fileName.replace(".challenge-request.json", ".verdict.json"), { domain: workloadMatch[2].replaceAll("-", "_"), verdict: true });
      }
      if (fileName === "postlaunch-final-authority-input.json") {
        const projectionText = bytes.toString("utf8");
        const projection = JSON.parse(projectionText);
        assert.deepEqual(Object.keys(projection), [
          "activation_evidence_lease_expires_at",
          "activation_mutation_authorized",
          "batch_id",
          "chain_id",
          "completed_at",
          "cvm_launch_intent_sha256",
          "deployment_intent_sha256",
          "domains",
          "encrypted_environment_ciphertext_egress",
          "fresh_contract_deployment_receipt_sha256",
          "historical_transcript_file_set_sha256",
          "live_traffic_authorized",
          "private_historical_transcript_contains_raw_quote_bytes",
          "qvl_measurement_policy_set_sha256",
          "raw_private_artifact_egress",
          "raw_quote_external_egress",
          "raw_secret_egress",
          "release_sha",
          "release_verification_authority_sha256",
          "schema",
          "seven_cvm_launch_completion_receipt_sha256",
          "seven_cvm_verified_evidence_set_sha256",
          "status",
          "truth_status",
        ]);
        for (const domain of projection.domains) {
          assert.deepEqual(Object.keys(domain), [
            "app_id", "bound_contract_address", "bound_contract_name",
            "committed_compose_hash", "cvm_id", "descriptor_sha256",
            "disk_size", "domain", "instance_type", "kms_id",
            "machine_evidence_kind", "machine_evidence_sha256",
            "os_image_hash", "production_posture_verification_receipt_sha256",
            "qvl_identity_sha256", "qvl_release_policy_sha256",
            "qvl_verification_receipt_sha256", "tdx_attestation_evidence_sha256",
            "tdx_attestation_verification_receipt_sha256",
            "tdx_measurement_authority_sha256", "tdx_measurements_sha256",
            "tee_identity",
          ]);
        }
        assert.equal(projection.activation_mutation_authorized, false);
        assert.equal(projection.live_traffic_authorized, false);
        assert.equal(projection.raw_quote_external_egress, false);
        assert.equal(projection.raw_secret_egress, false);
        assert.equal(projection.raw_private_artifact_egress, false);
        assert.equal(projection.encrypted_environment_ciphertext_egress, false);
        assert.doesNotMatch(
          projectionText,
          /PHASE_SECRET_SENTINEL|CIPHERTEXT_SENTINEL|PRIVATE_ARTIFACT_SENTINEL/,
        );
        postlaunchProjectionObserved = true;
      }
      if (fileName === "postlaunch-authority-request.json") {
        const request = JSON.parse(bytes.toString("utf8"));
        assert.equal(postlaunchProjectionObserved, true);
        assert.deepEqual(Object.keys(request), [
          "activation_mutation_authorized",
          "automatic_retry_authorized",
          "batch_id",
          "cvm_launch_intent_sha256",
          "deployment_intent_sha256",
          "launch_completion_raw_file_sha256",
          "live_traffic_authorized",
          "manifest_acceptance_deadline",
          "postlaunch_authority_exchange_identity_anchor_sha256",
          "postlaunch_projection_raw_file_sha256",
          "release_sha",
          "release_verification_authority_sha256",
          "required_input",
          "schema",
          "seven_cvm_launch_completion_receipt_sha256",
          "seven_cvm_verified_evidence_set_sha256",
          "status",
          "truth_status",
        ]);
        assert.equal(
          request.schema,
          "dnai.phala-production-postlaunch-authority-request.v2",
        );
        assert.equal(
          request.required_input.schema,
          "dnai.phala-production-postlaunch-activation-input-manifest.v2",
        );
        assert.ok(Date.parse(request.manifest_acceptance_deadline) > Date.now());
        const manifest = {
          schema: "dnai.phala-production-postlaunch-activation-input-manifest.v2",
          status: "postlaunch_activation_inputs_ready_for_validation",
          truth_status: "file_bindings_only_pending_same_process_validation_not_mutation_or_live_authority",
          release_sha: request.release_sha,
          batch_id: scenario === "invalid-lineage"
            ? "wrong-postlaunch-batch"
            : request.batch_id,
          deployment_intent_sha256: request.deployment_intent_sha256,
          cvm_launch_intent_sha256: request.cvm_launch_intent_sha256,
          release_verification_authority_sha256: request.release_verification_authority_sha256,
          seven_cvm_verified_evidence_set_sha256: request.seven_cvm_verified_evidence_set_sha256,
          seven_cvm_launch_completion_receipt_sha256: request.seven_cvm_launch_completion_receipt_sha256,
          manifest_acceptance_deadline: request.manifest_acceptance_deadline,
          postlaunch_projection_raw_file_sha256: request.postlaunch_projection_raw_file_sha256,
          postlaunch_request_raw_file_sha256: identity.sha256,
          dependencies: postlaunchDependencies,
          automatic_retry_authorized: false,
          activation_mutation_authorized: false,
          live_traffic_authorized: false,
        };
        postlaunchRequestObserved = true;
        // The external authority cannot publish into its independently pinned
        // exchange until the resident driver has completed all three
        // create-new handoff writes and returned to its bounded wait.
        setTimeout(() => {
          const manifestPath = path.join(
            postlaunchAuthority.path,
            "postlaunch-activation-input-manifest.json",
          );
          fs.writeFileSync(manifestPath, text(manifest), { mode: 0o600 });
          fs.chmodSync(manifestPath, 0o600);
        }, 0);
      }
      if (fileName === "stage-b-attachment-manifest.json") {
        const manifest = JSON.parse(bytes.toString("utf8"));
        assert.equal(
          manifest.schema,
          "dnai.phala-production-stage-b-attachment-manifest.v2",
        );
        assert.equal(
          manifest.stage_b_reviewer_status_history_raw_file_sha256,
          signingSession.stage_b_reviewer_status_history_raw_file_sha256,
        );
        assert.equal(
          manifest.stage_b_review_reviewer_authority_current_status_epoch,
          signingSession.stage_b_review_reviewer_authority_current_status_epoch,
        );
        assert.equal(
          manifest.stage_b_review_reviewer_authority_current_status_sha256,
          signingSession.stage_b_review_reviewer_authority_current_status_sha256,
        );
        stageBAttachmentManifestObserved = true;
      }
      return identity;
    },
  } });
})();

const mockWithOriginal = async (name, overrides) => {
  const target = url(name);
  const original = await import(target);
  mock.module(target, { namedExports: { ...original, ...overrides } });
};
const launchResult = Object.freeze({ release_sha: "ab".repeat(20), batch_id: "recipient-failure-batch" });
await mockWithOriginal("phala-production-executor-runtime.mjs", {
  async executePhalaSevenCvmProductionLaunch() { return launchResult; },
});
const releaseAuthority = Object.freeze({
  deployment_intent_sha256: sha("11"),
  qvl_measurement_policy_set_sha256: sha("36"),
  ceremony_nonce: "0x" + "12".repeat(32),
  private_phase_secret: "PHASE_SECRET_SENTINEL",
  encrypted_environment_ciphertext: "CIPHERTEXT_SENTINEL",
  private_artifact: "PRIVATE_ARTIFACT_SENTINEL",
  descriptors: Object.freeze([
    Object.freeze({ domain: "main_runtime_cvm", cvm_id: "main-runtime-test" }),
    Object.freeze({ domain: "independent_metering_cvm", cvm_id: "metering-runtime-test" }),
  ]),
});
const completionDomains = [
  "main_runtime_cvm", "diligence_qvl_cvm", "arena_qvl_cvm",
  "anchor_writer_qvl_cvm", "compute_workload_qvl_cvm",
  "compute_metering_qvl_cvm", "independent_metering_cvm",
].map((domain, index) => Object.freeze({
  domain,
  descriptor_sha256: sha(String(40 + index).padStart(2, "0")),
  app_id: String(index + 1).repeat(40),
  cvm_id: "cvm-" + domain,
  committed_compose_hash: String(index + 1).repeat(64),
  kms_id: "kms-test",
  instance_type: index === 0 ? "tdx.large" : "tdx.small",
  disk_size: index === 0 ? 40 : 20,
  os_image_hash: String(index + 2).repeat(64),
  production_posture_verification_receipt_sha256: sha("51"),
  machine_evidence_kind: index > 0 && index < 6
    ? "qvl_identity_local_dcap_verification"
    : "workload_independent_signed_qvl_verdict",
  machine_evidence_sha256: sha("52"),
  tdx_attestation_evidence_sha256: sha("53"),
  tdx_attestation_verification_receipt_sha256: sha("54"),
  tdx_measurements_sha256: sha("55"),
  tdx_measurement_authority_sha256: sha("56"),
  qvl_release_policy_sha256: index > 0 && index < 6 ? sha("57") : null,
  qvl_verification_receipt_sha256: sha("58"),
  qvl_identity_sha256: sha("59"),
  tee_identity: "0x" + String(index + 1).repeat(40),
  bound_contract_name: index === 0 ? "DiligenceRoom" : null,
  bound_contract_address: index === 0 ? "0x" + "a1".repeat(20) : null,
}));
const verifiedEvidenceSet = Object.freeze({ kind: "verified-evidence-set" });
const launchCompletionReceipt = Object.freeze({
  release_sha: launchResult.release_sha,
  batch_id: launchResult.batch_id,
  deployment_intent_sha256: sha("11"),
  cvm_launch_intent_sha256: sha("31"),
  fresh_contract_deployment_receipt_sha256: sha("32"),
  release_verification_authority_sha256: sha("22"),
  machine_verifier_evidence_set_sha256: sha("34"),
  historical_transcript_file_set_sha256: sha("33"),
  completed_at: Math.floor(Date.now() / 1000),
  activation_evidence_lease_expires_at: Math.floor(Date.now() / 1000) + 120,
  domains: Object.freeze(completionDomains),
});
class Ledger { close() {} }
await mockWithOriginal("phala-seven-cvm-verifier-evidence.mjs", {
  PhalaDurableReleaseChallengeLedger: Ledger,
  assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(value) {
    assert.equal(value, releaseAuthority);
    return value;
  },
  assertProductionPhalaSevenCvmEvidenceSet(value) {
    assert.equal(value, verifiedEvidenceSet);
    return value;
  },
  createPhalaQvlIdentityChallenge({ domain }) {
    return Object.freeze({ schema: "identity-request", domain });
  },
  async verifyPhalaQvlIdentityLaunchEvidence({ domain }) {
    return Object.freeze({ domain, measurement_policy_sha256: sha("21") });
  },
  verifyPhalaWorkloadIndependentTdxVerdict({ domain }) {
    return Object.freeze({ domain });
  },
  phalaSevenCvmReleaseVerificationAuthoritySha256() { return sha("22"); },
  phalaSevenCvmVerifiedEvidenceSetSha256() { return sha("34"); },
});
await mockWithOriginal("phala-seven-cvm-launch-completion.mjs", {
  assertFreshProductionPhalaSevenCvmLaunchCompletionReceipt(value) {
    assert.equal(value, launchCompletionReceipt);
    return value;
  },
  canonicalPhalaSevenCvmLaunchCompletionReceiptText(value) { return text(value); },
  phalaSevenCvmLaunchCompletionReceiptSha256() { return sha("35"); },
});
const postlaunchCapabilityTarget = url(
  "phala-production-postlaunch-activation-capability.mjs",
);
const originalPostlaunchCapability = await import(postlaunchCapabilityTarget);
mock.module(postlaunchCapabilityTarget, { namedExports: {
  ...originalPostlaunchCapability,
  async waitForPhalaProductionPostlaunchActivationCapability(input) {
    mintedPostlaunchCapability =
      await originalPostlaunchCapability
        .waitForPhalaProductionPostlaunchActivationCapability(input);
    postlaunchCapabilityMinted = true;
    return mintedPostlaunchCapability;
  },
  disposePhalaProductionPostlaunchActivationCapability(capability) {
    capabilityDisposeCalls += 1;
    cleanupEvents.push("capability");
    if (capability === mintedPostlaunchCapability) {
      exactCapabilityDisposeCalls += 1;
    }
    const disposedCapability = originalPostlaunchCapability
      .disposePhalaProductionPostlaunchActivationCapability(capability);
    if (capability === mintedPostlaunchCapability) {
      exactCapabilityBurned = disposedCapability;
    }
    return disposedCapability;
  },
} });
const evidenceSession = Object.freeze({
  kind: "evidence",
  release_sha: launchResult.release_sha,
  batch_id: launchResult.batch_id,
  release_verification_authority_sha256: sha("22"),
});
let signingSession;
let resumeCalls = 0;
let beginCalls = 0;
const runtimeSession = Object.freeze({
  kind: "runtime",
  release_sha: launchResult.release_sha,
  batch_id: launchResult.batch_id,
  release_verification_authority_sha256: sha("22"),
  ceremony_authorization_sha256: sha("23"),
  durable_state_status: "mutated-non-live",
});
const disposed = [];
await mockWithOriginal("phala-production-activation-coordinator.mjs", {
  preparePhalaProductionActivationEvidence() { return evidenceSession; },
  readPhalaProductionActivationEvidenceDependencies(session) {
    assert.equal(session, evidenceSession);
    return { releaseVerificationAuthority: releaseAuthority };
  },
  async persistPhalaProductionActivationLaunchCompletion({ session }) {
    assert.equal(session, evidenceSession);
    return Object.freeze({
      release_sha: launchResult.release_sha,
      batch_id: launchResult.batch_id,
      releaseVerificationAuthority: releaseAuthority,
      verifiedEvidenceSet,
      launchCompletionReceipt,
      activation_mutation_authorized: false,
      live_traffic_authorized: false,
    });
  },
  async resumePhalaProductionActivationWithPinnedSigningExchange(input) {
    resumeCalls += 1;
    assert.equal(input.session, evidenceSession);
    assert.equal(postlaunchRequestObserved, true);
    assert.equal(typeof input.postlaunchActivationCapability, "object");
    for (const field of [
      "ceremonyLedgerInitial",
      "ceremonyLedgerInitializationReceipt",
      "ceremonyTransactionPlan",
      "deferredAuthorityReview",
      "immutableDeploymentManifest",
      "reviewedFinalAuthorityFiles",
    ]) {
      assert.equal(Object.hasOwn(input, field), false);
    }
    const handle = input.signingExchangeAuthority;
    assert.equal(handle.path, signingAuthority.path);
    const prefix = "stage-b-" + launchResult.release_sha + "-mockresident000000000000";
    const bodyName = prefix + ".unsigned-body.json";
    const payloadName = prefix + ".signing-payload.json";
    const signedName = prefix + ".signed.json";
    const bodyIdentity = originalCreate(handle, bodyName, Buffer.from(text({ body: true })), { mode: 0o600 });
    const payloadIdentity = originalCreate(handle, payloadName, Buffer.from(text({ payload: true })), { mode: 0o600 });
    originalCreate(handle, signedName, Buffer.from(text({ signed: true })), { mode: 0o600 });
    const project = (identity, basename) => ({ basename, sha256: identity.sha256, size: identity.size, mode: identity.mode });
    signingSession = Object.freeze({
      kind: "signing",
      release_sha: launchResult.release_sha,
      batch_id: launchResult.batch_id,
      signing_payload_sha256: sha("24"),
      signing_message: "dnai-wikigen release-authority cryptographic review v2:" + sha("24"),
      stage_b_reviewer_status_history_raw_file_sha256:
        postlaunchDependencies.stageBReviewerStatusHistory.sha256,
      stage_b_review_reviewer_authority_current_status_epoch: 1,
      stage_b_review_reviewer_authority_current_status_sha256: sha("25"),
      signing_exchange_directory_identity_anchor_sha256:
        originalPinned.phalaPinnedPrivateDirectoryIdentityAnchorSha256(handle),
      unsigned_body_file: project(bodyIdentity, bodyName),
      signing_payload_file: project(payloadIdentity, payloadName),
      signed_b_output: { basename: signedName, mode: "0600", canonical_json_required: true },
    });
    return signingSession;
  },
  phalaProductionActivationSigningExchangePaths(session) {
    assert.equal(session, signingSession);
    return {
      unsignedBodyPath: path.join(root, "signing-exchange", session.unsigned_body_file.basename),
      signingPayloadPath: path.join(root, "signing-exchange", session.signing_payload_file.basename),
      signedBOutputPath: path.join(root, "signing-exchange", session.signed_b_output.basename),
    };
  },
  async beginPhalaProductionActivationFromSignedB({ session }) {
    beginCalls += 1;
    assert.equal(session, signingSession);
    const recipientEvidenceLeaseExpiresAt = Math.floor(Date.now() / 1000) + 60;
    const activation = {
      schema: "recipient-source",
      recipient_evidence_lease_expires_at: recipientEvidenceLeaseExpiresAt,
      expires_at: recipientEvidenceLeaseExpiresAt,
    };
    const file = path.join(root, "evidence-exchange", "08-compute-workload-recipient-activation.json");
    fs.writeFileSync(file, text(activation), { mode: 0o600 });
    fs.chmodSync(file, 0o600);
    return runtimeSession;
  },
  readPhalaProductionActivationRuntimeDeadlines(session) {
    assert.equal(session, runtimeSession);
    return {
      activation_authority_expires_at: Math.floor(Date.now() / 1000) + 60,
    };
  },
  async completePhalaProductionActivation({ session }) {
    assert.equal(session, runtimeSession);
    throw new Error("injected pre-consumption recipient rejection");
  },
  disposePhalaProductionActivationSession({ session }) {
    cleanupEvents.push("session");
    disposed.push(session);
    return { disposed: true };
  },
});

const ordinary = (name) => write(name + ".json", { name });
const readonly = (name) => write(name + ".json", { name }, 0o444);
postlaunchDependencies = {
  ceremonyLedgerInitializationReceipt: readonly("init"),
  ceremonyLedgerInitial: ordinary("ledger"),
  ceremonyTransactionPlan: ordinary("plan"),
  deferredAuthorityReview: ordinary("deferred"),
  immutableDeploymentManifest: readonly("manifest"),
  stageBReviewerStatusHistory: write("stage-b-reviewer-history.json", []),
  reviewedFinalAuthorityFiles: {
    deploymentIntent: ordinary("rd"), cvmLaunchIntent: ordinary("rc"),
    finalAuthority: ordinary("rf"), reviewEnvelope: ordinary("re"),
    reviewEvidence: ordinary("rv"),
  },
};
const request = {
  schema: "dnai.phala-production-activation-driver-request.v3",
  launch: {
    repositoryRoot: process.cwd(), releaseDirectory: root,
    imageReleaseManifestPath: path.join(root, "a"), imageReleaseSigstoreBundlePath: path.join(root, "b"),
    imageReleaseSigstoreVerificationReceiptPath: path.join(root, "c"), authorizationPath: path.join(root, "d"),
    bootstrapAuthorityPath: path.join(root, "e"), deploymentIntentPath: path.join(root, "f"),
    reviewerAuthorityGenesisPath: path.join(root, "g"), reviewerAuthorityGenesisAcceptancePath: path.join(root, "h"),
    freshContractDeploymentReceiptPath: path.join(root, "i"), compatibilityReceiptPath: path.join(root, "j"),
    sdkWireTransformStagingReceiptPath: path.join(root, "k"), productionTargetAuthorityPath: path.join(root, "l"),
    phaseSecretInputPaths: {}, recoveryDirectory: path.join(root, "launch-recovery"),
  },
  activation: {
    descriptorSetReceipt: ordinary("descriptor"), freshContractDeploymentReceipt: ordinary("fresh"),
    measurementPolicySet: ordinary("policy"), releaseManifestSigstoreVerificationReceipt: ordinary("sigstore"),
    reviewerGenesis: ordinary("genesis"), reviewerGenesisAcceptance: ordinary("acceptance"),
    bootstrapPhaseInput: ordinary("bootstrap"),
    finalPhaseInput: ordinary("final"),
    evidenceExchangeAuthority: evidenceAuthority,
    postlaunchAuthorityExchangeAuthority: postlaunchAuthority,
    signingExchangeAuthority: signingAuthority,
    outputAuthority, evidenceTimeoutSeconds: 20,
    postlaunchAuthorityTimeoutSeconds: 20, signingTimeoutSeconds: 20,
    recipientTimeoutSeconds: 10, pollIntervalMilliseconds: 25,
    qvlIdentityTtlSeconds: 30, independentMeteringPolicySetHash: "0x" + "71".repeat(32),
  },
};
const requestPath = path.join(root, "request.json");
fs.writeFileSync(requestPath, text(request), { mode: 0o600 });
fs.chmodSync(requestPath, 0o600);
const driver = await import(url("phala-production-activation-driver.mjs") + "?recipient-failure");
let failure;
try { await driver.main(["--execute-request", requestPath]); } catch (error) { failure = error; }
if (scenario === "invalid-lineage") {
  assert.match(failure?.message || "", /manifest lineage or posture is invalid/);
  assert.deepEqual(disposed, [evidenceSession]);
  assert.equal(resumeCalls, 0);
  assert.equal(beginCalls, 0);
} else if (scenario === "post-mint-handle-failure") {
  assert.match(failure?.message || "", /injected post-mint handle identity failure/);
  assert.deepEqual(disposed, [evidenceSession]);
  assert.equal(resumeCalls, 0);
  assert.equal(beginCalls, 0);
  assert.equal(capabilityDisposeCalls, 1);
  assert.equal(exactCapabilityDisposeCalls, 1);
  assert.equal(exactCapabilityBurned, true);
  assert.deepEqual(cleanupEvents, ["capability", "session"]);
} else {
  assert.match(failure?.message || "", /pre-consumption recipient rejection/);
  assert.deepEqual(disposed, [runtimeSession]);
  assert.equal(resumeCalls, 1);
  assert.equal(beginCalls, 1);
}
assert.deepEqual(fs.readdirSync(outputAuthority.path), []);
console.log(JSON.stringify({
  disposedRuntime: disposed[0] === runtimeSession,
  disposedEvidence: disposed[0] === evidenceSession,
  postlaunchProjectionObserved,
  stageBAttachmentManifestObserved,
  resumeCalls,
  beginCalls,
  capabilityDisposeCalls,
  exactCapabilityDisposeCalls,
  exactCapabilityBurned,
  cleanupEvents,
  outputEmpty: true,
}));
fs.rmSync(root, { recursive: true, force: true });
`;

test("pre-consumption recipient rejection retains and disposes the exact runtime session", async () => {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    RECIPIENT_FAILURE_HARNESS,
  ], {
    cwd: REPOSITORY_ROOT,
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const value = JSON.parse(result.stdout.trim().split("\n").at(-1));
  assert.equal(value.disposedRuntime, true);
  assert.equal(value.postlaunchProjectionObserved, true);
  assert.equal(value.stageBAttachmentManifestObserved, true);
  assert.equal(value.outputEmpty, true);
});

test("postlaunch manifest failure disposes evidence session before any postmeasurement mutation", async () => {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    RECIPIENT_FAILURE_HARNESS,
  ], {
    cwd: REPOSITORY_ROOT,
    env: { ...process.env, POSTLAUNCH_SCENARIO: "invalid-lineage" },
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const value = JSON.parse(result.stdout.trim().split("\n").at(-1));
  assert.equal(value.disposedEvidence, true);
  assert.equal(value.postlaunchProjectionObserved, true);
  assert.equal(value.resumeCalls, 0);
  assert.equal(value.beginCalls, 0);
  assert.equal(value.outputEmpty, true);
});

test("post-mint driver failure burns the exact capability before disposing its evidence session", async () => {
  const result = await execFileAsync(process.execPath, [
    "--experimental-test-module-mocks",
    "--input-type=module",
    "-e",
    RECIPIENT_FAILURE_HARNESS,
  ], {
    cwd: REPOSITORY_ROOT,
    env: { ...process.env, POSTLAUNCH_SCENARIO: "post-mint-handle-failure" },
    timeout: 30_000,
    maxBuffer: 4 * 1024 * 1024,
  });
  const value = JSON.parse(result.stdout.trim().split("\n").at(-1));
  assert.equal(value.disposedEvidence, true);
  assert.equal(value.postlaunchProjectionObserved, true);
  assert.equal(value.resumeCalls, 0);
  assert.equal(value.beginCalls, 0);
  assert.equal(value.capabilityDisposeCalls, 1);
  assert.equal(value.exactCapabilityDisposeCalls, 1);
  assert.equal(value.exactCapabilityBurned, true);
  assert.deepEqual(value.cleanupEvents, ["capability", "session"]);
  assert.equal(value.outputEmpty, true);
});
