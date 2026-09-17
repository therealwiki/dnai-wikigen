import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import vm from "node:vm";

import {
  assertProductionPhalaPostMeasurementActivationSession,
  beginProductionPhalaPostMeasurementActivation,
  completeProductionPhalaPostMeasurementActivation,
  quarantineProductionPhalaPostMeasurementActivationSession,
} from "./phala-post-measurement-activation-runtime.mjs";
import {
  destroyPrivatePostMeasurementEncryptedUpdate,
  readPrivatePostMeasurementEncryptedUpdateCiphertext,
  registerPrivatePostMeasurementEncryptedUpdateObservation,
} from "./phala-post-measurement-activation-receipt.mjs";
import { PHALA_OS_IMAGE_CATALOG_ENTRY } from "./cvm-launch-intent-core.mjs";
import { createSyntheticPhalaContractKmsProjection } from "./phala-contract-kms-test-fixture.mjs";
import { projectProductionCvmPostureReadback } from "./phala-production-posture-core.mjs";
import {
  assertVerifiedProductionCvmPostureReceipt,
  verifyProductionCvmPostureObservation,
} from "./phala-production-posture-receipt.mjs";

const RUNTIME_SOURCE = fs.readFileSync(
  new URL("./phala-post-measurement-activation-runtime.mjs", import.meta.url),
  "utf8",
);

test("current activation uses exactly nine SDK calls and binds fresh committed posture before key lookup", () => {
  const start = RUNTIME_SOURCE.indexOf("export async function beginProductionPhalaPostMeasurementActivation");
  const end = RUNTIME_SOURCE.indexOf("function readLocalPhalaPostMeasurementActivationSession", start);
  const begin = RUNTIME_SOURCE.slice(start, end);
  assert.deepEqual(
    [...begin.matchAll(/adapter\.(getCurrentUser|getWorkspace|getCvmInfo|getAppEnvEncryptPubKey|updateCvmEnvs|restartCvm|getCvmAttestation)\(/g)]
      .map((match) => match[1]),
    ["getCurrentUser", "getWorkspace", "getCvmInfo", "getAppEnvEncryptPubKey",
      "getAppEnvEncryptPubKey", "updateCvmEnvs", "restartCvm", "getCvmInfo", "getCvmAttestation"],
  );
  const billing = begin.indexOf('billing_status !== "active"');
  const currentInfo = begin.indexOf("adapter.getCvmInfo(");
  const binding = begin.indexOf("bindFreshPostMeasurementCommittedPosture(");
  const keyLookup = begin.indexOf("adapter.getAppEnvEncryptPubKey(");
  assert.ok(billing > begin.indexOf("adapter.getWorkspace(") && billing < currentInfo);
  assert.ok(currentInfo < binding && binding < keyLookup);
  assert.match(RUNTIME_SOURCE, /dnai\.phala-post-measurement-activation-session\.v3/);
  assert.match(RUNTIME_SOURCE, /dnai\.phala-post-measurement-activation-completion-result\.v3/);
});

test("recipient completion compares authentication against ninth-call attestation, not seventh-call restart", () => {
  const start = RUNTIME_SOURCE.indexOf("if (activation.authenticated_at");
  const end = RUNTIME_SOURCE.indexOf("const computeVerifiedState", start);
  assert.ok(start >= 0 && end > start);
  const check = new Function("activation", "state", "arenaWorkerPresence",
    RUNTIME_SOURCE.slice(start, end));
  const restartSecond = 1_900_000_000;
  const attestationSecond = restartSecond + 20;
  const state = { sdk_observations: Array.from({ length: 9 }, (_, index) => ({
    observed_at: new Date((index === 8 ? attestationSecond : restartSecond) * 1_000)
      .toISOString(),
  })) };
  const arena = { verified_at: restartSecond };
  assert.throws(() => check({ authenticated_at: restartSecond + 10,
    verified_at: attestationSecond + 1 }, state, arena), /predates/);
  assert.doesNotThrow(() => check({ authenticated_at: attestationSecond,
    verified_at: attestationSecond + 1 }, state, arena));
});

function localCommittedPostureBindingHarness() {
  // Local structural fixtures only: no account, live SDK, or TDX evidence.
  // The production posture projector, validator, and receipt brand run intact.
  const kms = createSyntheticPhalaContractKmsProjection();
  const prepared = {
    kms_contract_id: kms.contract.id,
    kms_id: kms.replicas[0].id,
    kms_url: kms.replicas[0].url,
    node_id: 7,
    teepod_id: 21,
    device_id: "1".repeat(64),
    gateway_app_id: `0x${"1".repeat(40)}`,
  };
  const expected = {
    appId: "1".repeat(40), composeHash: "2".repeat(64),
    instanceType: "tdx.large", diskSize: 40,
    kmsProjection: kms, preparedBinding: prepared,
    environmentPublicKey: "3".repeat(64),
  };
  const raw = {
    id: "cvm-production-main", app_id: expected.appId, compose_hash: expected.composeHash,
    kms_type: "phala",
    kms_info: {
      chain_id: null, dstack_kms_address: null, dstack_app_address: null, deployer_address: null,
      rpc_endpoint: prepared.kms_url, encrypted_env_pubkey: expected.environmentPublicKey,
    },
    node_info: { id: prepared.node_id,
      device_ids: [{ device_id: prepared.device_id, algorithm_version: "v3.0.0", enabled: true }] },
    os: { os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash, is_dev: false },
    resource: { instance_type: expected.instanceType, disk_in_gb: expected.diskSize },
    listed: false, public_logs: false, public_sysinfo: false, public_tcbinfo: false,
  };
  const original = verifyProductionCvmPostureObservation({
    domain: "main_runtime_cvm", cvmId: raw.id, cvmInfo: raw, expected,
  });
  const launch = Object.freeze({ local_fixture: "completed-launch" });
  const adapter = Object.freeze({ local_fixture: "new-adapter" });
  const observation = Object.freeze({ local_fixture: "new-sdk-readback" });
  const bindings = [];
  const dependencies = {
    readPhalaProductionExecutorRuntimeDependencies(value) {
      assert.equal(value, launch);
      return { production_posture_receipts: [original] };
    },
    assertVerifiedProductionCvmPostureReceipt,
    verifyProductionCvmPostureObservation,
    projectProductionCvmPostureReadback,
    observationResponse(value, passedAdapter, method) {
      assert.equal(value, observation);
      assert.equal(passedAdapter, adapter);
      assert.equal(method, "getCvmInfo");
      return raw;
    },
    bindPinnedPhalaCommittedEnvironmentKeyLookup(binding) {
      assert.equal(binding.adapter, adapter);
      assert.equal(binding.cvmInfoObservation, observation);
      assertVerifiedProductionCvmPostureReceipt(binding.postureReceipt);
      bindings.push(binding);
    },
  };
  const start = RUNTIME_SOURCE.indexOf("function bindFreshPostMeasurementCommittedPosture");
  const end = RUNTIME_SOURCE.indexOf("function assertPatchAccepted", start);
  assert.ok(start >= 0 && end > start);
  const bind = new Function(...Object.keys(dependencies),
    `${RUNTIME_SOURCE.slice(start, end)}; return bindFreshPostMeasurementCommittedPosture;`)(
    ...Object.values(dependencies),
  );
  return {
    raw, original, bindings,
    bind: () => bind({ launch, adapter, prePatchCvmInfo: observation,
      plan: { target: { app_id: original.app_id, cvm_id: original.cvm_id, compose_hash: original.compose_hash } },
      targetAuthority: { kms } }),
  };
}

test("committed key lookup uses a freshly verified readback with the original prepared identity", () => {
  const fixture = localCommittedPostureBindingHarness();
  const fresh = fixture.bind();
  assert.equal(fixture.bindings.length, 1);
  assert.notEqual(fresh, fixture.original);
  assert.deepEqual(fresh.prepared_binding, fixture.original.prepared_binding);
  assert.equal(fresh.environment_public_key, fixture.original.environment_public_key);
  assert.equal(fixture.bindings[0].postureReceipt, fresh);
});

test("pre-PATCH KMS, key, placement, privacy, and missing-ID drift cannot authorize key lookup", () => {
  for (const mutate of [
    (raw) => { delete raw.id; },
    (raw) => { raw.kms_info.rpc_endpoint = "https://changed.example/"; },
    (raw) => { raw.kms_info.encrypted_env_pubkey = "4".repeat(64); },
    (raw) => { raw.node_info.id = 8; },
    (raw) => { raw.node_info.device_ids[0].device_id = "2".repeat(64); },
    (raw) => { raw.os.is_dev = true; },
    (raw) => { raw.public_logs = true; },
  ]) {
    const fixture = localCommittedPostureBindingHarness();
    mutate(fixture.raw);
    assert.throws(() => fixture.bind());
    assert.equal(fixture.bindings.length, 0);
  }
});

test("post-measurement signed-B dependencies preserve the complete reviewer lineage", () => {
  const projectorStart = RUNTIME_SOURCE.indexOf(
    "function signedBDeferredAuthorizationDependencies",
  );
  const projectorEnd = RUNTIME_SOURCE.indexOf(
    "function sessionPublic",
    projectorStart,
  );
  assert.ok(projectorStart >= 0 && projectorEnd > projectorStart);
  const projector = RUNTIME_SOURCE.slice(projectorStart, projectorEnd);
  for (const field of [
    "deploymentIntent",
    "freshContractDeploymentReceipt",
    "reviewerGenesis",
    "reviewerGenesisAcceptance",
    "stageBReviewerStatusHistory",
  ]) {
    assert.match(projector, new RegExp(`${field}: value\\.${field}`));
  }
  const environmentSource = fs.readFileSync(
    new URL("./phala-production-environment-authority.mjs", import.meta.url),
    "utf8",
  );
  const authorizationStart = environmentSource.indexOf(
    "export async function authorizePhalaDeferredPublicEnvironmentAuthority",
  );
  const authorizationEnd = environmentSource.indexOf(
    "export function deferredPublicEnvironmentAuthorityDigest",
    authorizationStart,
  );
  const authorization = environmentSource.slice(
    authorizationStart,
    authorizationEnd > authorizationStart
      ? authorizationEnd
      : environmentSource.length,
  );
  assert.match(authorization, /"stageBReviewerStatusHistory"/);
  assert.match(
    authorization,
    /Array\.isArray\(dependencies\.stageBReviewerStatusHistory\)/,
  );
  assert.match(
    authorization,
    /reviewerStatusHistory: dependencies\.stageBReviewerStatusHistory/,
  );
  assert.doesNotMatch(authorization, /"reviewerStatusHistory"/);

  for (const moduleName of [
    "phala-post-measurement-activation-runtime.mjs",
    "phala-production-environment-authority.mjs",
    "phala-post-measurement-activation-receipt.mjs",
    "phala-seven-cvm-historical-release-verification-authority.mjs",
  ]) {
    const source = fs.readFileSync(new URL(`./${moduleName}`, import.meta.url), "utf8");
    assert.match(
      source,
      /"stageBReviewerStatusHistory"/,
      `${moduleName} must exact-name the Stage-B carrier`,
    );
    assert.match(
      source,
      /reviewerStatusHistory: dependencies\.stageBReviewerStatusHistory/,
      `${moduleName} must explicitly remap only at the B normalizer`,
    );
    assert.doesNotMatch(
      source,
      /"reviewerStatusHistory"/,
      `${moduleName} must reject the ambiguous legacy carrier field`,
    );
  }
});

function loadExactRuntimeLeaseHelpers({ nowMs, afterPersist } = {}) {
  let controlledNowMs = nowMs;
  let persistCalls = 0;
  class ControlledDate extends Date {}
  ControlledDate.now = () => controlledNowMs;
  ControlledDate.parse = Date.parse;
  const start = RUNTIME_SOURCE.indexOf("function canonicalAuthorityExpiryMs");
  const end = RUNTIME_SOURCE.indexOf("function ceremonyLineage", start);
  assert.ok(start >= 0 && end > start, "runtime lease-helper source must be extractable");
  const sandbox = {
    Date: ControlledDate,
    persistPhalaPostMeasurementActivationJournal(input) {
      persistCalls += 1;
      afterPersist?.({
        input,
        setNow(value) {
          controlledNowMs = value;
        },
      });
      return Object.freeze({ persisted: true, input });
    },
  };
  vm.runInNewContext(
    `${RUNTIME_SOURCE.slice(start, end)}\n`
      + "globalThis.__leaseHelpers = {"
      + "assertActivationAuthorityDeadlineCurrent,"
      + "assertCompletionEvidenceLeasesCurrent,"
      + "awaitUnderInitialActivationEvidenceLease,"
      + "awaitUnderCompletionEvidenceLeases,"
      + "persistActivationJournalUnderInitialEvidenceLease,"
      + "persistActivationJournalUnderCompletionEvidenceLeases"
      + "};",
    sandbox,
  );
  return {
    helpers: sandbox.__leaseHelpers,
    persistCalls: () => persistCalls,
    setNow(value) {
      controlledNowMs = value;
    },
  };
}

function authorityAt(baseMs, {
  initialSeconds = 90,
  signedBSeconds = 40,
  reviewedSeconds = 50,
  deferredSeconds = 60,
} = {}) {
  return {
    plan: {
      activation_evidence_lease_expires_at:
        Math.floor(baseMs / 1_000) + initialSeconds,
    },
    signedB: {
      review: {
        expires_at: new Date(baseMs + signedBSeconds * 1_000).toISOString(),
      },
    },
    reviewedFinalAuthorityRuntimeProjection: {
      review_expires_at:
        new Date(baseMs + reviewedSeconds * 1_000).toISOString(),
    },
    deferredAuthority: {
      valid_until: new Date(baseMs + deferredSeconds * 1_000).toISOString(),
    },
  };
}

test("post-measurement runtime rejects caller clocks, clients, callbacks, and forged sessions", async () => {
  const widened = {
    plan: {},
    preCeremonyRuntimeAuthority: {},
    ceremonyAuthorization: {},
    ceremonyAuthorizationDependencies: {},
    reviewedFinalAuthorityRuntimeProjection: {},
    launchRuntimeResult: {},
    targetAuthority: {},
    compatibilityReceipt: {},
    sdkWireTransformStagingReceipt: {},
    bootstrapPhaseInput: {
      path: "/tmp/bootstrap.json",
      sha256: `sha256:${"1".repeat(64)}`,
    },
    finalPhaseInput: {
      path: "/tmp/final.json",
      sha256: `sha256:${"2".repeat(64)}`,
    },
    recoveryDirectory: "/tmp/recovery",
    clock: () => Date.now(),
    client: {},
    afterRestart: () => {},
  };
  await assert.rejects(
    beginProductionPhalaPostMeasurementActivation(widened),
    /exactly the frozen fields/,
  );
  const forged = {
    schema: "dnai.phala-post-measurement-activation-session.v2",
    status:
      "combined_profile_patch_restart_authenticated_phala_attestation_observed_and_arena_presence_verified_pending_compute_recipient_activation",
    truth_status:
      "private_live_operator_session_with_reviewed_arena_presence_not_serializable_authority_execution_receipt_or_live_traffic",
    durable_state_status: "arena_worker_activation_verified",
    automatic_retry_authorized: false,
    live_traffic_authorized: false,
  };
  assert.throws(
    () => assertProductionPhalaPostMeasurementActivationSession(forged),
    /live local/,
  );
  assert.throws(
    () => quarantineProductionPhalaPostMeasurementActivationSession(forged),
    /live local/,
  );
  await assert.rejects(
    completeProductionPhalaPostMeasurementActivation({
      session: forged,
      recipientActivation: {},
      qvlIdentityEvidence: {},
      mainRuntimeEvidence: {},
    }),
    /live local/,
  );
  await assert.rejects(
    completeProductionPhalaPostMeasurementActivation({
      session: forged,
      recipientActivation: {},
      qvlIdentityEvidence: {},
      mainRuntimeEvidence: {},
      challengeLedger: {},
      capabilityEndpoint: "https://attacker.invalid/compute/workload-encryption-contract",
    }),
    /exactly the frozen fields/,
  );
});

test("private encrypted-update capability cannot be forged or registered without exact local encryption", () => {
  const forged = Object.freeze({
    schema: "dnai.phala-private-post-measurement-encrypted-update.v1",
  });
  assert.throws(
    () => readPrivatePostMeasurementEncryptedUpdateCiphertext(forged),
    /unregistered local private encrypted update/,
  );
  assert.throws(
    () => registerPrivatePostMeasurementEncryptedUpdateObservation({
      encryptedUpdate: forged,
      adapter: {},
      patchObservation: {},
    }),
    /unregistered private encrypted update/,
  );
  assert.doesNotThrow(() => destroyPrivatePostMeasurementEncryptedUpdate(forged));
});

test("runtime authority deadline is the non-injectable minimum of initial, signed-B, reviewed, and deferred leases", () => {
  const baseMs = Date.parse("2035-01-01T00:00:00.000Z");
  const runtime = loadExactRuntimeLeaseHelpers({ nowMs: baseMs });
  const { assertActivationAuthorityDeadlineCurrent } = runtime.helpers;
  const authority = authorityAt(baseMs);
  assert.equal(
    assertActivationAuthorityDeadlineCurrent(authority, "test authority"),
    baseMs / 1_000,
  );

  const expiryMutations = [
    (value) => {
      value.plan.activation_evidence_lease_expires_at = baseMs / 1_000;
    },
    (value) => {
      value.signedB.review.expires_at = new Date(baseMs).toISOString();
    },
    (value) => {
      value.reviewedFinalAuthorityRuntimeProjection.review_expires_at =
        new Date(baseMs).toISOString();
    },
    (value) => {
      value.deferredAuthority.valid_until = new Date(baseMs).toISOString();
    },
  ];
  for (const mutate of expiryMutations) {
    const expired = structuredClone(authority);
    mutate(expired);
    assert.throws(
      () => assertActivationAuthorityDeadlineCurrent(expired, "expired authority"),
      /outside the minimum signed-B, reviewed, deferred, or initial evidence authority deadline/,
    );
  }
  assert.equal(
    assertActivationAuthorityDeadlineCurrent.length,
    2,
    "the production deadline assertion accepts authority and label only, never a clock",
  );
});

test("runtime fails closed when an external await crosses an authority or recipient lease", async () => {
  const baseMs = Date.parse("2035-01-01T00:00:00.000Z");
  const runtime = loadExactRuntimeLeaseHelpers({ nowMs: baseMs });
  const authority = authorityAt(baseMs, { signedBSeconds: 10 });
  let invoked = 0;
  await assert.rejects(
    runtime.helpers.awaitUnderInitialActivationEvidenceLease(
      authority,
      "slow external operation",
      async () => {
        invoked += 1;
        runtime.setNow(baseMs + 10_000);
        return "late";
      },
    ),
    /after slow external operation is outside the minimum/,
  );
  assert.equal(invoked, 1, "the post-await deadline check must reject a late result");

  runtime.setNow(baseMs + 10_000);
  invoked = 0;
  await assert.rejects(
    runtime.helpers.awaitUnderInitialActivationEvidenceLease(
      authority,
      "already expired operation",
      async () => {
        invoked += 1;
      },
    ),
    /before already expired operation is outside the minimum/,
  );
  assert.equal(invoked, 0, "an expired authority must not invoke the operation");

  runtime.setNow(baseMs);
  const completionAuthority = authorityAt(baseMs, { signedBSeconds: 90 });
  const activation = {
    recipient_evidence_lease_expires_at: baseMs / 1_000 + 20,
    terminal_evidence_lease_expires_at: baseMs / 1_000 + 8,
    expires_at: baseMs / 1_000 + 8,
  };
  await assert.rejects(
    runtime.helpers.awaitUnderCompletionEvidenceLeases(
      completionAuthority,
      activation,
      "slow receipt preflight",
      async () => {
        runtime.setNow(baseMs + 8_000);
      },
    ),
    /after slow receipt preflight is outside the recipient or terminal activation-evidence lease/,
  );
});

test("runtime checks leases immediately before and after every durable normal-path journal write", () => {
  const baseMs = Date.parse("2035-01-01T00:00:00.000Z");
  const authority = authorityAt(baseMs, { signedBSeconds: 10 });
  const runtime = loadExactRuntimeLeaseHelpers({
    nowMs: baseMs,
    afterPersist({ setNow }) {
      setNow(baseMs + 10_000);
    },
  });
  assert.throws(
    () => runtime.helpers.persistActivationJournalUnderInitialEvidenceLease({
      authority,
      label: "slow durable journal",
      directory: "/private/recovery",
      state: {},
      lock: {},
    }),
    /after slow durable journal is outside the minimum/,
  );
  assert.equal(runtime.persistCalls(), 1);

  const alreadyExpired = loadExactRuntimeLeaseHelpers({
    nowMs: baseMs + 10_000,
  });
  assert.throws(
    () => alreadyExpired.helpers.persistActivationJournalUnderInitialEvidenceLease({
      authority,
      label: "expired durable journal",
      directory: "/private/recovery",
      state: {},
      lock: {},
    }),
    /before expired durable journal is outside the minimum/,
  );
  assert.equal(
    alreadyExpired.persistCalls(),
    0,
    "an expired authority must not start a normal-path durable journal write",
  );

  const terminalMs = baseMs + 8_000;
  const completionRuntime = loadExactRuntimeLeaseHelpers({
    nowMs: baseMs,
    afterPersist({ setNow }) {
      setNow(terminalMs);
    },
  });
  const activation = {
    recipient_evidence_lease_expires_at: baseMs / 1_000 + 20,
    terminal_evidence_lease_expires_at: terminalMs / 1_000,
    expires_at: terminalMs / 1_000,
  };
  assert.throws(
    () => completionRuntime.helpers
      .persistActivationJournalUnderCompletionEvidenceLeases({
        authority: authorityAt(baseMs, { signedBSeconds: 90 }),
        activation,
        label: "slow completion journal",
        directory: "/private/recovery",
        state: {},
        lock: {},
      }),
    /after slow completion journal is outside the recipient or terminal activation-evidence lease/,
  );
});

test("runtime orders Compute authentication after Arena and closes every terminal durable ledger", () => {
  const source = RUNTIME_SOURCE;
  const sessionAssertionStart = source.indexOf(
    "function readLocalPhalaPostMeasurementActivationSession",
  );
  const sessionAssertionEnd = source.indexOf(
    "export async function completeProductionPhalaPostMeasurementActivation",
    sessionAssertionStart,
  );
  const sessionAssertion = source.slice(sessionAssertionStart, sessionAssertionEnd);
  const completionEnd = source.indexOf(
    "export function quarantineProductionPhalaPostMeasurementActivationSession",
    sessionAssertionEnd,
  );
  const completion = source.slice(sessionAssertionEnd, completionEnd);
  assert.equal(
    sessionAssertion.match(
      /session\.plan\.phala_recovery_directory_identity_anchor_sha256/g,
    )?.length,
    1,
    "the session anchor must have one comparison, never a chained duplicate",
  );
  assert.match(
    source,
    /minimumAuthenticatedAt:\s*arenaWorkerPresence\.verified_at/,
  );
  assert.match(
    source,
    /activation\.authenticated_at\s*< arenaWorkerPresence\.verified_at/,
  );
  assert.match(
    completion,
    /const completionSecond = assertCompletionEvidenceLeasesCurrent\(/,
  );
  assert.match(
    completion,
    /completionSecond < activation\.verified_at[\s\S]*completionSecond >= session\.plan\.activation_evidence_lease_expires_at[\s\S]*completionSecond >= activation\.recipient_evidence_lease_expires_at[\s\S]*completionSecond >= activation\.terminal_evidence_lease_expires_at/,
  );
  assert.doesNotMatch(
    completion,
    /const completedAt\s*=\s*new Date\(activation\.verified_at/,
  );
  assert.doesNotMatch(
    source,
    /createProductionPhalaPostMeasurementActivationExecutionReceipt|createComputeWorkloadActivationObservation/,
  );
  assert.match(
    completion,
    /recipientVerificationConsumed\s*&& !completionPersistenceAttempted[\s\S]*state\.status === "arena_worker_activation_verified"/,
  );
  const orderedSteps = [
    "const computeVerifiedState",
    "const completionSecond",
    "const proposedCompletedState",
    "projectPhalaPostMeasurementActivationJournal",
    "await awaitUnderCompletionEvidenceLeases",
    "prepareProductionPhalaPostMeasurementActivationExecutionReceipt",
    "prepareProductionComputeWorkloadActivationObservation",
    "persistActivationJournalUnderCompletionEvidenceLeases",
    "completionPersistenceAttempted = true",
    "state = computeVerifiedState",
    "persistActivationJournalUnderCompletionEvidenceLeases",
    "state = proposedCompletedState",
    "finalizeProductionPhalaPostMeasurementActivationExecutionReceipt",
    "finalizeProductionComputeWorkloadActivationObservation",
  ];
  let previousIndex = -1;
  for (const step of orderedSteps) {
    const index = completion.indexOf(step, previousIndex + 1);
    assert.ok(index > previousIndex, `${step} must remain in two-phase order`);
    previousIndex = index;
  }
  assert.equal(
    source.match(/challengeLedger\?\.close\(\)/g)?.length,
    1,
    "begin failure must close its locally opened ledger",
  );
  assert.equal(
    source.match(/session\.challengeLedger\.close\(\)/g)?.length,
    2,
    "completion consumption and quarantine must each close the session ledger",
  );
});

test("every begin await, mutation, restart, and normal journal boundary is authority-deadline guarded", () => {
  const beginStart = RUNTIME_SOURCE.indexOf(
    "export async function beginProductionPhalaPostMeasurementActivation",
  );
  const beginEnd = RUNTIME_SOURCE.indexOf(
    "function readLocalPhalaPostMeasurementActivationSession",
    beginStart,
  );
  const begin = RUNTIME_SOURCE.slice(beginStart, beginEnd);
  const guardedExternalOperations = [
    ["deferred public-environment authorization", "authorizePhalaDeferredPublicEnvironmentAuthority"],
    ["pinned Phala SDK adapter creation", "createPinnedPhalaProductionSdkAdapter"],
    ["authenticated Phala account observation", "adapter.getCurrentUser"],
    ["authenticated active-billing Phala workspace observation", "adapter.getWorkspace"],
    ["pre-PATCH committed CVM info observation", "adapter.getCvmInfo"],
    ["first environment-encryption key observation", "adapter.getAppEnvEncryptPubKey"],
    ["immediate environment-encryption key refetch", "adapter.getAppEnvEncryptPubKey"],
    ["environment-encryption key signature verification", "verifyImmediatePinnedLegacyEnvironmentKeyRefetch"],
    ["private encrypted environment update creation", "createPrivatePostMeasurementEncryptedUpdate"],
    ["pre-PATCH finalized-readiness collection", "collectProductionFinalizedReadiness"],
    ["encrypted-only environment PATCH", "adapter.updateCvmEnvs"],
    ["pre-restart finalized-readiness collection", "collectProductionFinalizedReadiness"],
    ["main-runtime restart mutation", "adapter.restartCvm"],
    ["post-restart CVM info observation", "adapter.getCvmInfo"],
    ["post-restart CVM attestation observation", "adapter.getCvmAttestation"],
    ["Arena worker activation verification", "verifyArenaWorkerActivationCapability"],
  ];
  let searchFrom = 0;
  for (const [label, operation] of guardedExternalOperations) {
    const wrapperIndex = begin.indexOf(
      "await awaitUnderInitialActivationEvidenceLease",
      searchFrom,
    );
    const labelIndex = begin.indexOf(`"${label}"`, wrapperIndex);
    const operationIndex = begin.indexOf(operation, labelIndex);
    assert.ok(wrapperIndex >= searchFrom, `${label} must use the await lease guard`);
    assert.ok(labelIndex > wrapperIndex, `${label} must be inside its lease guard`);
    assert.ok(operationIndex > labelIndex, `${operation} must start only after its guard`);
    searchFrom = operationIndex + operation.length;
  }
  assert.equal(
    begin.match(/await awaitUnderInitialActivationEvidenceLease/g)?.length,
    guardedExternalOperations.length,
    "no begin-side awaited external operation may bypass the lease guard",
  );

  const guardedJournals = [
    "initial activation journal persistence",
    "pre-PATCH observation journal persistence",
    "PATCH mutation-attempt journal persistence",
    "PATCH observation journal persistence",
    "restart mutation-attempt journal persistence",
    "restart observation journal persistence",
    "post-restart attestation journal persistence",
    "Arena activation journal persistence",
  ];
  for (const label of guardedJournals) {
    const labelIndex = begin.indexOf(`label: "${label}"`);
    const wrapperIndex = begin.lastIndexOf(
      "persistActivationJournalUnderInitialEvidenceLease({",
      labelIndex,
    );
    assert.ok(wrapperIndex >= 0 && labelIndex > wrapperIndex, `${label} must be guarded`);
  }
  assert.equal(
    begin.match(/persistActivationJournalUnderInitialEvidenceLease\(\{/g)?.length,
    guardedJournals.length,
  );
  assert.match(
    begin,
    /assertActivationAuthorityDeadlineCurrent\([\s\S]*"before acquiring the post-measurement activation lock"/,
  );
  assert.match(
    begin,
    /assertActivationAuthorityDeadlineCurrent\([\s\S]*"before opening the durable recipient-challenge ledger"/,
  );

  const helperStart = RUNTIME_SOURCE.indexOf(
    "function assertActivationAuthorityDeadlineCurrent",
  );
  const helperEnd = RUNTIME_SOURCE.indexOf(
    "function assertCompletionEvidenceLeasesCurrent",
    helperStart,
  );
  const deadlineHelper = RUNTIME_SOURCE.slice(helperStart, helperEnd);
  assert.match(deadlineHelper, /const checkedAtMs = Date\.now\(\);/);
  assert.match(deadlineHelper, /authority\?\.plan\?\.activation_evidence_lease_expires_at/);
  assert.match(deadlineHelper, /authority\?\.signedB\?\.review\?\.expires_at/);
  assert.match(
    deadlineHelper,
    /authority\?\.reviewedFinalAuthorityRuntimeProjection\?\.review_expires_at/,
  );
  assert.match(deadlineHelper, /authority\?\.deferredAuthority\?\.valid_until/);
  assert.match(
    deadlineHelper,
    /Math\.min\([\s\S]*planExpiresAtMs[\s\S]*signedBReviewExpiresAtMs[\s\S]*reviewedProjectionExpiresAtMs[\s\S]*deferredAuthorityExpiresAtMs/,
  );
});

test("recipient consumption, completion journals, receipt, and O finalizers remain terminal-lease guarded", () => {
  const completionStart = RUNTIME_SOURCE.indexOf(
    "export async function completeProductionPhalaPostMeasurementActivation",
  );
  const completionEnd = RUNTIME_SOURCE.indexOf(
    "export function quarantineProductionPhalaPostMeasurementActivationSession",
    completionStart,
  );
  const completion = RUNTIME_SOURCE.slice(completionStart, completionEnd);
  const consumeGuard = completion.indexOf(
    '"immediately before one-use Compute recipient challenge consumption"',
  );
  const consume = completion.indexOf(
    "verifyPhalaComputeWorkloadRecipientActivation({",
  );
  const consumed = completion.indexOf("recipientVerificationConsumed = true", consume);
  const postConsumeGuard = completion.indexOf(
    '"after one-use Compute recipient challenge consumption"',
    consumed,
  );
  assert.ok(consumeGuard >= 0 && consume > consumeGuard);
  assert.ok(consumed > consume && postConsumeGuard > consumed);

  const preflightWrapper = completion.indexOf("await awaitUnderCompletionEvidenceLeases");
  const receiptPreflight = completion.indexOf(
    "prepareProductionPhalaPostMeasurementActivationExecutionReceipt",
    preflightWrapper,
  );
  assert.ok(preflightWrapper >= 0 && receiptPreflight > preflightWrapper);

  const completionJournalCalls = [
    'label: "Compute recipient-verification journal persistence"',
    'label: "activation-completed journal persistence"',
  ];
  let priorJournal = -1;
  for (const label of completionJournalCalls) {
    const wrapper = completion.indexOf(
      "persistActivationJournalUnderCompletionEvidenceLeases({",
      priorJournal + 1,
    );
    const labelIndex = completion.indexOf(label, wrapper);
    assert.ok(wrapper > priorJournal && labelIndex > wrapper);
    priorJournal = wrapper;
  }

  const receiptGuard = completion.indexOf(
    '"before activation execution-receipt finalization"',
  );
  const receiptFinalizer = completion.indexOf(
    "finalizeProductionPhalaPostMeasurementActivationExecutionReceipt({",
    receiptGuard,
  );
  const receiptPostGuard = completion.indexOf(
    '"after activation execution-receipt finalization"',
    receiptFinalizer,
  );
  const observationGuard = completion.indexOf(
    '"before Compute activation-observation finalization"',
    receiptPostGuard,
  );
  const observationFinalizer = completion.indexOf(
    "finalizeProductionComputeWorkloadActivationObservation({",
    observationGuard,
  );
  const observationPostGuard = completion.indexOf(
    '"after Compute activation-observation finalization"',
    observationFinalizer,
  );
  assert.ok(receiptGuard >= 0 && receiptFinalizer > receiptGuard);
  assert.ok(receiptPostGuard > receiptFinalizer);
  assert.ok(observationGuard > receiptPostGuard && observationFinalizer > observationGuard);
  assert.ok(observationPostGuard > observationFinalizer);
  assert.match(
    completion,
    /completionSecond >= session\.plan\.activation_evidence_lease_expires_at/,
  );
  assert.match(
    completion,
    /completionSecond >= activation\.recipient_evidence_lease_expires_at/,
  );
  assert.match(
    completion,
    /completionSecond >= activation\.terminal_evidence_lease_expires_at/,
  );
});
