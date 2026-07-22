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
  normalizePhalaProductionActivationDriverRequest,
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

function requestFixture(root) {
  const ordinary = (name) => writeBinding(root, `${name}.json`, { name });
  const readonly = (name) => writeBinding(root, `${name}.json`, { name }, 0o444);
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
      reviewerStatusHistory: ordinary("reviewer-history"),
      bootstrapPhaseInput: ordinary("bootstrap-phase"),
      ceremonyLedgerInitializationReceipt: readonly("ledger-initialization"),
      ceremonyLedgerInitial: ordinary("ledger-initial"),
      ceremonyTransactionPlan: ordinary("transaction-plan"),
      deferredAuthorityReview: ordinary("deferred-review"),
      finalPhaseInput: ordinary("final-phase"),
      immutableDeploymentManifest: readonly("immutable-manifest"),
      reviewedFinalAuthorityFiles: {
        deploymentIntent: ordinary("reviewed-deployment-intent"),
        cvmLaunchIntent: ordinary("reviewed-cvm-launch-intent"),
        finalAuthority: ordinary("reviewed-final-authority"),
        reviewEnvelope: ordinary("review-envelope"),
        reviewEvidence: ordinary("review-evidence"),
      },
      evidenceExchangeAuthority: prepareAuthority(root, "evidence-exchange"),
      signingExchangeAuthority: prepareAuthority(root, "signing-exchange"),
      outputAuthority: prepareAuthority(root, "activation-outputs"),
      evidenceTimeoutSeconds: 20,
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
    /const completion = await completePhalaProductionActivation\([\s\S]*?liveSession = null;/,
  );
  assert.doesNotMatch(
    source,
    /liveSession = null;\s*const completion = await completePhalaProductionActivation/,
  );
  assert.match(
    source,
    /const value = \{\s*\.\.\.detail,\s*schema:[\s\S]*?automatic_retry_authorized: false,\s*live_traffic_authorized: false,/,
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
const signingAuthority = prepareAuthority("signing-exchange");
const outputAuthority = prepareAuthority("output");
await (async () => {
  const target = url("phala-pinned-private-directory.mjs");
  mock.module(target, { namedExports: {
    ...originalPinned,
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
  ceremony_nonce: "0x" + "12".repeat(32),
  descriptors: Object.freeze([
    Object.freeze({ domain: "main_runtime_cvm", cvm_id: "main-runtime-test" }),
    Object.freeze({ domain: "independent_metering_cvm", cvm_id: "metering-runtime-test" }),
  ]),
});
class Ledger { close() {} }
await mockWithOriginal("phala-seven-cvm-verifier-evidence.mjs", {
  PhalaDurableReleaseChallengeLedger: Ledger,
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
});
const evidenceSession = Object.freeze({ kind: "evidence" });
let signingSession;
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
  async resumePhalaProductionActivationWithPinnedSigningExchange(input) {
    assert.equal(input.session, evidenceSession);
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
      signing_message: "dnai-wikigen release-authority cryptographic review v1:" + sha("24"),
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
    disposed.push(session);
    return { disposed: true };
  },
});

const ordinary = (name) => write(name + ".json", { name });
const readonly = (name) => write(name + ".json", { name }, 0o444);
const request = {
  schema: "dnai.phala-production-activation-driver-request.v1",
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
    reviewerStatusHistory: ordinary("history"), bootstrapPhaseInput: ordinary("bootstrap"),
    ceremonyLedgerInitializationReceipt: readonly("init"), ceremonyLedgerInitial: ordinary("ledger"),
    ceremonyTransactionPlan: ordinary("plan"), deferredAuthorityReview: ordinary("deferred"),
    finalPhaseInput: ordinary("final"), immutableDeploymentManifest: readonly("manifest"),
    reviewedFinalAuthorityFiles: {
      deploymentIntent: ordinary("rd"), cvmLaunchIntent: ordinary("rc"), finalAuthority: ordinary("rf"),
      reviewEnvelope: ordinary("re"), reviewEvidence: ordinary("rv"),
    },
    evidenceExchangeAuthority: evidenceAuthority,
    signingExchangeAuthority: signingAuthority,
    outputAuthority, evidenceTimeoutSeconds: 20,
    signingTimeoutSeconds: 20, recipientTimeoutSeconds: 10, pollIntervalMilliseconds: 25,
    qvlIdentityTtlSeconds: 30, independentMeteringPolicySetHash: "0x" + "71".repeat(32),
  },
};
const requestPath = path.join(root, "request.json");
fs.writeFileSync(requestPath, text(request), { mode: 0o600 });
fs.chmodSync(requestPath, 0o600);
const driver = await import(url("phala-production-activation-driver.mjs") + "?recipient-failure");
let failure;
try { await driver.main(["--execute-request", requestPath]); } catch (error) { failure = error; }
assert.match(failure?.message || "", /pre-consumption recipient rejection/);
assert.deepEqual(disposed, [runtimeSession]);
assert.deepEqual(fs.readdirSync(outputAuthority.path), []);
console.log(JSON.stringify({ disposedRuntime: disposed[0] === runtimeSession, outputEmpty: true }));
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
  assert.equal(value.outputEmpty, true);
});
