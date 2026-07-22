import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import * as productionVerifier from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS,
  PHALA_SEVEN_CVM_EXECUTION_ORDER,
  PHALA_QVL_IDENTITY_DOMAIN_PROFILE,
  PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
  PhalaDurableReleaseChallengeLedger,
  REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_AUTHORITY,
  REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
  PhalaWorkloadVerdictChallengeLedger,
  assertProductionPhalaComputeWorkloadRecipientActivation,
  assertProductionPhalaSevenCvmEvidenceSet,
  assertPinnedSevenCvmLocalDcapVerifierRuntime,
  assertVerifiedPhalaQvlIdentityLaunchEvidence,
  assertVerifiedPhalaComputeWorkloadRecipientActivation,
  assertVerifiedPhalaSevenCvmEvidenceSet,
  assertVerifiedPhalaWorkloadTdxVerdict,
  canonicalPhalaComputeWorkloadRecipientSourceActivationText,
  canonicalPhalaSevenCvmVerifiedEvidenceSetText,
  canonicalPhalaComputeWorkloadRecipientActivationVerificationText,
  computePythonRuntimeTreeSha256,
  createPhalaSevenCvmVerifiedEvidenceSet,
  exportPhalaSevenCvmHistoricalTranscriptFiles,
  normalizePhalaQvlIdentityLaunchEvidence,
  normalizePhalaComputeWorkloadRecipientActivationVerification,
  normalizePhalaComputeWorkloadRecipientSourceActivation,
  normalizePhalaSevenCvmVerifiedEvidenceSet,
  normalizePhalaWorkloadTdxVerdictVerification,
  phalaQvlIdentityLaunchEvidenceSha256,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientSourceActivationSha256,
  phalaComputeWorkloadRecipientReportData,
  phalaSevenCvmVerifiedEvidenceSetSha256,
  phalaWorkloadTdxVerdictVerificationSha256,
  independentTdxVerdictSigningDigest,
  qvlChallengeSigningDigest,
  verifyPhalaQvlIdentityLaunchEvidence,
  verifyPhalaComputeWorkloadRecipientActivation,
  verifyPinnedSevenCvmLocalDcapQuote,
  verifyPinnedSevenCvmIsolatedRuntimeEnvironment,
  verifyPhalaWorkloadIndependentTdxVerdict,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  verifyIndependentEip191PersonalSignature,
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";
import {
  unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime,
  unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime,
} from "./phala-seven-cvm-opened-fd-runtime-test-harness.mjs";
import {
  PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
  appraisePhalaQvlMeasurementsAgainstPolicy,
  normalizePhalaQvlMeasurementPolicy,
  normalizePhalaQvlMeasurementPolicySet,
  phalaQvlMeasurementPolicySha256,
} from "./phala-seven-cvm-measurement-policy.mjs";
import {
  SYNTHETIC_PHALA_SEVEN_CVM_VERIFIER_EVIDENCE_TRUTH,
  syntheticPhalaSevenCvmVerifierEvidenceFixture,
} from "./phala-seven-cvm-verifier-evidence.fixture.mjs";

let fixturePromise;
function fixture() {
  fixturePromise ||= syntheticPhalaSevenCvmVerifierEvidenceFixture();
  return fixturePromise;
}

test("seven machine-verifier proofs have stable domains and canonical form", async () => {
  const value = await fixture();
  assert.equal(
    value.truth_status,
    SYNTHETIC_PHALA_SEVEN_CVM_VERIFIER_EVIDENCE_TRUTH,
  );
  assert.deepEqual(
    value.evidenceSet.domains.map(({ domain }) => domain),
    PHALA_SEVEN_CVM_EXECUTION_ORDER,
  );
  assert.deepEqual(
    Object.keys(PHALA_QVL_IDENTITY_DOMAIN_PROFILE),
    PHALA_SEVEN_CVM_EXECUTION_ORDER.filter((domain) =>
      Object.hasOwn(PHALA_QVL_IDENTITY_DOMAIN_PROFILE, domain)),
  );
  assert.equal(value.evidenceSet.all_seven_machine_verified, true);
  assert.equal(value.evidenceSet.raw_quote_persisted, false);
  assert.equal(value.evidenceSet.raw_secret_egress, false);
  assert.match(phalaQvlIdentityLaunchEvidenceSha256(value.qvlIdentityEvidence[0]),
    /^sha256:[0-9a-f]{64}$/);
  assert.match(phalaWorkloadTdxVerdictVerificationSha256(value.workloadVerdictEvidence[0]),
    /^sha256:[0-9a-f]{64}$/);
  assert.match(phalaSevenCvmVerifiedEvidenceSetSha256(value.evidenceSet),
    /^sha256:[0-9a-f]{64}$/);
  assert.equal(value.evidenceSet.proofs_valid_at_issuance, true);
  assert.ok(
    value.evidenceSet.issued_at
      < value.evidenceSet.minimum_activation_evidence_lease_expires_at,
  );
  assert.ok(value.evidenceSet.proof_collection_skew_seconds <= 300);
  assert.match(value.evidenceSet.historical_transcript_file_set_sha256,
    /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    canonicalPhalaSevenCvmVerifiedEvidenceSetText(value.evidenceSet),
    `${JSON.stringify(JSON.parse(
      canonicalPhalaSevenCvmVerifiedEvidenceSetText(value.evidenceSet),
    ), null, 2)}\n`,
  );
});

test("verified evidence carries exact raw transcript byte identities and a policy-bounded identity lease", async () => {
  const value = await fixture();
  assert.equal(
    value.qvlIdentityEvidence[0].schema,
    "dnai.phala-qvl-identity-launch-verification.v4",
  );
  assert.equal(
    value.workloadVerdictEvidence[0].schema,
    "dnai.phala-workload-tdx-verdict-verification.v4",
  );
  assert.equal(
    value.evidenceSet.schema,
    "dnai.phala-seven-cvm-verified-evidence-set.v4",
  );
  value.qvlIdentityEvidence.forEach((proof, index) => {
    const raw = value.qvlRawInputs[index];
    assert.equal(
      proof.activation_evidence_lease_seconds,
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    );
    assert.equal(proof.activation_evidence_lease_issued_at, proof.verified_at);
    assert.equal(
      proof.activation_evidence_lease_expires_at,
      proof.verified_at + PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    );
    assert.equal(proof.expires_at, proof.activation_evidence_lease_expires_at);
    assert.ok(proof.challenge_expires_at < proof.activation_evidence_lease_expires_at);
    assert.equal(
      proof.identity_attestation_request_file_size,
      Buffer.byteLength(raw.rawRequestText, "utf8"),
    );
    assert.equal(
      proof.identity_attestation_response_file_size,
      Buffer.byteLength(raw.rawResponseText, "utf8"),
    );
  });
  value.workloadVerdictEvidence.forEach((proof) => {
    assert.equal(
      proof.verdict_activation_evidence_lease_expires_at,
      proof.verdict_expires_at,
    );
    assert.equal(proof.expires_at, proof.activation_evidence_lease_expires_at);
    assert.ok(proof.challenge_expires_at < proof.verdict_expires_at);
    assert.equal(proof.verdict_expires_at - proof.verdict_issued_at, 900);
  });
  value.workloadVerdictEvidence.forEach((proof, index) => {
    const raw = value.workloadRawInputs[index];
    assert.equal(
      proof.qvl_challenge_file_size,
      Buffer.byteLength(raw.rawChallengeText, "utf8"),
    );
    assert.equal(
      proof.qvl_verdict_file_size,
      Buffer.byteLength(raw.rawVerdictText, "utf8"),
    );
  });
  const proofByDomain = new Map([
    ...value.qvlIdentityEvidence,
    ...value.workloadVerdictEvidence,
  ].map((proof) => [proof.domain, proof]));
  for (const projection of value.evidenceSet.domains) {
    const proof = proofByDomain.get(projection.domain);
    const expectedSizes = Object.hasOwn(
      PHALA_QVL_IDENTITY_DOMAIN_PROFILE,
      projection.domain,
    )
      ? [
        proof.identity_attestation_request_file_size,
        proof.identity_attestation_response_file_size,
      ]
      : [proof.qvl_challenge_file_size, proof.qvl_verdict_file_size];
    assert.deepEqual(projection.raw_transcript_file_size, expectedSizes);
    assert.equal(
      projection.raw_transcript_file_size.every((size) =>
        Number.isSafeInteger(size) && size > 1),
      true,
    );
  }
});

test("verified proof brands are recursive-immutable, digest-guarded, and non-transferable", async () => {
  const value = await fixture();
  const identity = value.qvlIdentityEvidence[0];
  const workload = value.workloadVerdictEvidence[0];
  const aggregate = value.evidenceSet;
  const identityDigest = phalaQvlIdentityLaunchEvidenceSha256(identity);
  const workloadDigest = phalaWorkloadTdxVerdictVerificationSha256(workload);
  const aggregateDigest = phalaSevenCvmVerifiedEvidenceSetSha256(aggregate);
  assert.throws(() => {
    identity.local_dcap_verification.measurements.mr_td = "00".repeat(48);
  }, TypeError);
  assert.throws(() => {
    workload.report_data_binding.kind = "forged";
  }, TypeError);
  assert.throws(() => aggregate.domains.pop(), TypeError);
  assert.equal(phalaQvlIdentityLaunchEvidenceSha256(identity), identityDigest);
  assert.equal(phalaWorkloadTdxVerdictVerificationSha256(workload), workloadDigest);
  assert.equal(phalaSevenCvmVerifiedEvidenceSetSha256(aggregate), aggregateDigest);
  assert.throws(() => assertVerifiedPhalaQvlIdentityLaunchEvidence(structuredClone(identity)));
  assert.throws(() => assertVerifiedPhalaWorkloadTdxVerdict(structuredClone(workload)));
  assert.throws(() => assertVerifiedPhalaSevenCvmEvidenceSet(structuredClone(aggregate)));
});

test("synthetic verifier adapters are visibly labeled and can never satisfy production assertion", async () => {
  const value = await fixture();
  assert.equal(
    productionVerifier.createSyntheticPhalaSevenCvmReleaseVerificationAuthority,
    undefined,
  );
  assert.throws(
    () => productionVerifier.assertBrandedPhalaSevenCvmReleaseVerificationAuthority(
      value.releaseAuthority,
    ),
    /was not reconstructed from signed dependencies/,
  );
  assert.throws(
    () => productionVerifier.assertFreshProductionPhalaSevenCvmReleaseVerificationAuthority(
      value.releaseAuthority,
    ),
    /was not reconstructed from signed dependencies/,
  );
  assert.throws(
    () => productionVerifier
      .readPhalaSevenCvmReleaseVerificationAuthorityBootstrapAuthority(
        value.releaseAuthority,
      ),
    /was not reconstructed from signed dependencies/,
  );
  assert.equal(assertVerifiedPhalaSevenCvmEvidenceSet(value.evidenceSet), value.evidenceSet);
  assert.throws(
    () => assertProductionPhalaSevenCvmEvidenceSet(value.evidenceSet),
    /synthetic seven-CVM evidence can never authorize/,
  );
  await assert.rejects(
    () => verifyPhalaQvlIdentityLaunchEvidence({
      ...value.qvlRawInputs[0],
      testOnlyVerifyQuote: undefined,
      ledger: new PhalaWorkloadVerdictChallengeLedger(8),
    }),
    /synthetic and production DCAP verifier authority cannot be mixed/,
  );
  assert.deepEqual(Object.values(PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS).flatMap(
    (entry) => Object.values(entry),
  ), [
    "--main-runtime-qvl-challenge",
    "--main-runtime-independent-tdx-verdict",
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
    "--independent-metering-qvl-challenge",
    "--independent-metering-independent-tdx-verdict",
  ]);
});

test("main-runtime bootstrap binds the exact Arena and Compute QVL policies", async () => {
  const value = await fixture();
  const measurementPolicySet = {
    schema: PHALA_QVL_MEASUREMENT_POLICY_SET_SCHEMA,
    chain_id: 84_532,
    deployment_intent_sha256:
      value.releaseAuthority.deployment_intent_sha256,
    activation_evidence_lease_seconds:
      PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
    policies: value.releaseAuthority.qvl_measurement_policies,
  };
  assert.equal(
    value.releaseAuthority.activation_evidence_lease_seconds,
    PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  );
  const wrongAuthorityLease = structuredClone(value.releaseAuthority);
  wrongAuthorityLease.activation_evidence_lease_seconds -= 1;
  assert.throws(
    () => productionVerifier.normalizePhalaSevenCvmReleaseVerificationAuthority(
      wrongAuthorityLease,
    ),
    /release verification authority is invalid/,
  );
  const legacyAuthority = structuredClone(value.releaseAuthority);
  legacyAuthority.schema = "dnai.phala-seven-cvm-release-verification-authority.v2";
  assert.throws(
    () => productionVerifier.normalizePhalaSevenCvmReleaseVerificationAuthority(
      legacyAuthority,
    ),
    /release verification authority is invalid/,
  );
  const wrongSetDigest = structuredClone(value.releaseAuthority);
  wrongSetDigest.qvl_measurement_policy_set_sha256 = `sha256:${"fe".repeat(32)}`;
  assert.throws(
    () => productionVerifier.normalizePhalaSevenCvmReleaseVerificationAuthority(
      wrongSetDigest,
    ),
    /differs from canonical policy bytes/,
  );
  assert.equal(
    normalizePhalaQvlMeasurementPolicySet(measurementPolicySet)
      .activation_evidence_lease_seconds,
    PHALA_ACTIVATION_EVIDENCE_LEASE_SECONDS,
  );
  const commitments =
    productionVerifier.projectMainRuntimeQvlMeasurementPolicyCommitments(
      measurementPolicySet,
    );
  const byDomain = new Map(
    measurementPolicySet.policies.map((policy) => [policy.domain, policy]),
  );
  assert.deepEqual(commitments, {
    TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256:
      phalaQvlMeasurementPolicySha256(byDomain.get("arena_qvl_cvm")),
    TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256:
      phalaQvlMeasurementPolicySha256(
        byDomain.get("compute_workload_qvl_cvm"),
      ),
  });
  assert.equal(Object.isFrozen(commitments), true);

  const wrongLease = structuredClone(measurementPolicySet);
  wrongLease.activation_evidence_lease_seconds -= 1;
  assert.throws(
    () => normalizePhalaQvlMeasurementPolicySet(wrongLease),
    /policy set authority/,
  );
  const legacySet = structuredClone(measurementPolicySet);
  legacySet.schema = "dnai.phala-qvl-measurement-policy-set.v1";
  assert.throws(
    () => normalizePhalaQvlMeasurementPolicySet(legacySet),
    /policy set authority/,
  );

  const drifted = structuredClone(measurementPolicySet);
  const arena = drifted.policies.find(
    (policy) => policy.domain === "arena_qvl_cvm",
  );
  arena.mr_td = "fe".repeat(48);
  const driftedCommitments =
    productionVerifier.projectMainRuntimeQvlMeasurementPolicyCommitments(
      drifted,
    );
  assert.notEqual(
    driftedCommitments.TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256,
    commitments.TINKER_ARENA_QVL_MEASUREMENT_POLICY_SHA256,
  );
  assert.equal(
    driftedCommitments.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
    commitments.TINKER_COMPUTE_WORKLOAD_QVL_MEASUREMENT_POLICY_SHA256,
  );

  const omitted = structuredClone(measurementPolicySet);
  omitted.policies = omitted.policies.filter(
    (policy) => policy.domain !== "arena_qvl_cvm",
  );
  assert.throws(
    () => productionVerifier.projectMainRuntimeQvlMeasurementPolicyCommitments(
      omitted,
    ),
    /policy set authority|five policies|canonical policy order|omits/,
  );
});

test("production exact-14 transcript exporter is real and never exports synthetic evidence", async () => {
  const value = await fixture();
  assert.equal(typeof exportPhalaSevenCvmHistoricalTranscriptFiles, "function");
  assert.throws(
    () => exportPhalaSevenCvmHistoricalTranscriptFiles({
      verifiedEvidenceSet: value.evidenceSet,
      qvlIdentityEvidence: value.qvlIdentityEvidence,
      workloadVerdictEvidence: value.workloadVerdictEvidence,
    }),
    /synthetic seven-CVM evidence can never authorize a live release/,
  );
  assert.throws(
    () => exportPhalaSevenCvmHistoricalTranscriptFiles({
      verifiedEvidenceSet: structuredClone(value.evidenceSet),
      qvlIdentityEvidence: value.qvlIdentityEvidence,
      workloadVerdictEvidence: value.workloadVerdictEvidence,
    }),
    /not reconstructed from seven machine-verifier proofs/,
  );
});

test("paired node-test metadata spoof cannot expose or steer production runtime adapters", () => {
  assert.equal(productionVerifier.verifyPinnedSevenCvmOpenedFdRuntimeForTest, undefined);
  assert.equal(productionVerifier.unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime, undefined);
  assert.equal(productionVerifier.unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime, undefined);
  const verifierUrl = new URL("./phala-seven-cvm-verifier-evidence.mjs", import.meta.url);
  const productionSource = fs.readFileSync(verifierUrl, "utf8");
  assert.doesNotMatch(
    productionSource,
    /bytes32FromSha\(signedA\.authorization_id/,
  );
  assert.match(
    productionSource,
    /TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE/,
  );
  const testEntrypoint = new URL("./phala-seven-cvm-verifier-evidence.test.mjs", import.meta.url);
  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    [
      `process.env.NODE_TEST_CONTEXT = "child-v8";`,
      `process.argv[1] = ${JSON.stringify(testEntrypoint.pathname)};`,
      `const verifier = await import(${JSON.stringify(verifierUrl.href)});`,
      `if ("verifyPinnedSevenCvmOpenedFdRuntimeForTest" in verifier) throw new Error("old seam exported");`,
      `let hookCalled = false;`,
      `const override = {`,
      `  testOnlyPaths: { native: "/does/not/exist/native.so", script: "/does/not/exist/source.py" },`,
      `  testOnlyHost: { platform: "darwin", architecture: "arm64" },`,
      `  testOnlyBeforeSpawn: () => { hookCalled = true; },`,
      `};`,
      `for (const call of [`,
      `  () => verifier.assertPinnedSevenCvmLocalDcapVerifierRuntime(override),`,
      `  () => verifier.verifyPinnedSevenCvmIsolatedRuntimeEnvironment(override),`,
      `  () => verifier.verifyPinnedSevenCvmLocalDcapQuote(Buffer.alloc(1024), {}, override),`,
      `]) {`,
      `  try { call(); throw new Error("production override accepted"); }`,
      `  catch (error) {`,
      `    if (!/production opened-FD verifier does not accept runtime overrides/.test(error.message)) throw error;`,
      `  }`,
      `}`,
      `if (hookCalled) throw new Error("production executed an injected hook");`,
    ].join("\n"),
  ], {
    cwd: path.dirname(new URL(import.meta.url).pathname),
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 16 * 1024,
    env: { ...process.env, NODE_TEST_CONTEXT: "child-v8" },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, "");
});

test("production runtime APIs reject extra arguments before paths, policies, or hooks", () => {
  assert.equal(assertPinnedSevenCvmLocalDcapVerifierRuntime.length, 0);
  assert.equal(verifyPinnedSevenCvmIsolatedRuntimeEnvironment.length, 0);
  assert.equal(verifyPinnedSevenCvmLocalDcapQuote.length, 2);
  let hookCalled = false;
  const override = {
    testOnlyPaths: {
      native: "/does/not/exist/native.so",
      script: "/does/not/exist/source.py",
    },
    testOnlyBeforeSpawn: () => { hookCalled = true; },
  };
  assert.throws(
    () => assertPinnedSevenCvmLocalDcapVerifierRuntime(override),
    /production opened-FD verifier does not accept runtime overrides/,
  );
  assert.throws(
    () => verifyPinnedSevenCvmIsolatedRuntimeEnvironment(override),
    /production opened-FD verifier does not accept runtime overrides/,
  );
  assert.throws(
    () => verifyPinnedSevenCvmLocalDcapQuote(Buffer.alloc(1_024), {}, override),
    /production opened-FD verifier does not accept runtime overrides/,
  );
  assert.equal(hookCalled, false);
});

test("unsafe fixture harness is an explicit utility, not node-test authentication", () => {
  const harnessUrl = new URL(
    "./phala-seven-cvm-opened-fd-runtime-test-harness.mjs",
    import.meta.url,
  );
  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    [
      `delete process.env.NODE_TEST_CONTEXT;`,
      `const harness = await import(${JSON.stringify(harnessUrl.href)});`,
      `try {`,
      `  harness.unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime({`,
      `    testOnlyPaths: { native: "/does/not/exist/native.so", script: "/does/not/exist/source.py" },`,
      `    testOnlyHost: { platform: "linux", architecture: "x64" },`,
      `  });`,
      `  throw new Error("fixture host seam was not reached");`,
      `} catch (error) {`,
      `  if (!/outside the frozen Darwin arm64 authority/.test(error.message)) throw error;`,
      `}`,
    ].join("\n"),
  ], {
    cwd: path.dirname(new URL(import.meta.url).pathname),
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 16 * 1024,
    env: Object.fromEntries(
      Object.entries(process.env).filter(([key]) => key !== "NODE_TEST_CONTEXT"),
    ),
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stderr, "");
});

test("raw QVL identity evidence rejects report-data drift, measurement lies, and replay", async () => {
  const value = await fixture();
  const raw = value.qvlRawInputs[0];
  for (const mutate of [
    (proof) => { proof.activation_evidence_lease_seconds -= 1; },
    (proof) => { proof.activation_evidence_lease_issued_at += 1; },
    (proof) => { proof.activation_evidence_lease_expires_at += 1; },
    (proof) => { proof.expires_at -= 1; },
  ]) {
    const proof = structuredClone(value.qvlIdentityEvidence[0]);
    mutate(proof);
    assert.throws(
      () => normalizePhalaQvlIdentityLaunchEvidence(proof),
      /policy-bounded appraisal lease|activation evidence lease/,
    );
    assert.throws(() => phalaQvlIdentityLaunchEvidenceSha256(proof));
  }
  await assert.rejects(
    () => verifyPhalaQvlIdentityLaunchEvidence({
      ...raw,
      testOnlyNow: raw.request.expires_at,
      ledger: new PhalaWorkloadVerdictChallengeLedger(8),
    }),
    /stale|challenge/,
  );
  const driftedResponse = structuredClone(raw.response);
  driftedResponse.report_data = `0x${"ff".repeat(32)}`;
  await assert.rejects(() => verifyPhalaQvlIdentityLaunchEvidence({
    ...raw,
    response: driftedResponse,
    ledger: new PhalaWorkloadVerdictChallengeLedger(8),
    rawResponseText: `${JSON.stringify(driftedResponse, null, 2)}\n`,
  }));

  const dishonestVerifier = async () => {
    const policy = raw.releaseAuthority.qvl_measurement_policies.find((entry) =>
      entry.domain === raw.domain);
    const result = await raw.testOnlyVerifyQuote(null, policy);
    return { ...result, measurements_sha256: `sha256:${"ff".repeat(32)}` };
  };
  await assert.rejects(() => verifyPhalaQvlIdentityLaunchEvidence({
    ...raw,
    testOnlyVerifyQuote: dishonestVerifier,
    ledger: new PhalaWorkloadVerdictChallengeLedger(8),
  }), /policy-appraised non-debug Intel TDX evidence/);

  const alternateRuntimeVerifier = async (_quote, policy) => ({
    ...await raw.testOnlyVerifyQuote(null, policy),
    runtime_environment_sha256: `sha256:${"fe".repeat(32)}`,
  });
  await assert.rejects(() => verifyPhalaQvlIdentityLaunchEvidence({
    ...raw,
    testOnlyVerifyQuote: alternateRuntimeVerifier,
    ledger: new PhalaWorkloadVerdictChallengeLedger(8),
  }), /frozen distribution closure/);

  const ledger = new PhalaWorkloadVerdictChallengeLedger(8);
  await verifyPhalaQvlIdentityLaunchEvidence({
    ...raw,
    ledger,
  });
  await assert.rejects(() => verifyPhalaQvlIdentityLaunchEvidence({
    ...raw,
    ledger,
  }), /already consumed/);
});

test("measurement appraisal rejects DEBUG, extra fields, accessors, and policy substitution", async () => {
  const value = await fixture();
  const identity = value.qvlIdentityEvidence[0];
  const measurements = structuredClone(identity.local_dcap_verification.measurements);
  const policy = structuredClone(identity.measurement_policy);
  assert.deepEqual(appraisePhalaQvlMeasurementsAgainstPolicy(measurements, policy), {
    measurement_policy_sha256: identity.measurement_policy_sha256,
    measurement_policy_reference_id: policy.reference_id,
    measurement_policy_matched: true,
    debug_td: false,
  });

  const debug = structuredClone(measurements);
  debug.td_attributes = `01${debug.td_attributes.slice(2)}`;
  assert.throws(
    () => appraisePhalaQvlMeasurementsAgainstPolicy(debug, policy),
    /not authorized|DEBUG/,
  );

  const extra = structuredClone(measurements);
  extra.unreviewed_measurement = "00";
  assert.throws(() => appraisePhalaQvlMeasurementsAgainstPolicy(extra, policy));

  const accessor = structuredClone(measurements);
  const mrTd = accessor.mr_td;
  Object.defineProperty(accessor, "mr_td", { enumerable: true, get: () => mrTd });
  assert.throws(() => appraisePhalaQvlMeasurementsAgainstPolicy(accessor, policy));

  const substituted = structuredClone(policy);
  substituted.mr_td = "fe".repeat(48);
  assert.notDeepEqual(normalizePhalaQvlMeasurementPolicy(substituted), policy);
  assert.throws(() => appraisePhalaQvlMeasurementsAgainstPolicy(measurements, substituted));
});

test("workload verdict rejects signature, verifier, policy, report-data, contract, and freshness substitution", async () => {
  const value = await fixture();
  const raw = value.workloadRawInputs[0];
  const qvlIdentityEvidence = value.qvlIdentityEvidence.find((entry) =>
    entry.domain === "diligence_qvl_cvm");
  const mutations = [
    (input) => { input.verdict.schema = "dnai.independent-tdx-verdict.v3"; },
    (input) => { input.verdict.activation_evidence_lease_expires_at -= 1; },
    (input) => { input.verdict.verifier_signature = `0x${"11".repeat(64)}1b`; },
    (input) => { input.verdict.verifier_address = `0x${"99".repeat(20)}`; },
    (input) => { input.verdict.release_policy_hash = `0x${"98".repeat(32)}`; },
    (input) => { input.verdict.report_data = `0x${"97".repeat(32)}`; },
    (input) => { input.verdict.contract_address = `0x${"96".repeat(20)}`; },
    (input) => { input.testOnlyNow = input.verdict.expires_at; },
  ];
  for (const mutate of mutations) {
    const input = {
      domain: "main_runtime_cvm",
      releaseAuthority: value.releaseAuthority,
      verdict: structuredClone(raw.verdict),
      expected: structuredClone(raw.expected),
      qvlIdentityEvidence,
      challenge: structuredClone(raw.challenge),
      rawChallengeText: raw.rawChallengeText,
      rawVerdictText: raw.rawVerdictText,
      challengeLedger: new PhalaWorkloadVerdictChallengeLedger(4),
      testOnlyNow: value.now,
    };
    mutate(input);
    assert.throws(() => verifyPhalaWorkloadIndependentTdxVerdict(input));
  }

  const replayLedger = new PhalaWorkloadVerdictChallengeLedger(4);
  const first = {
    domain: "main_runtime_cvm",
    releaseAuthority: value.releaseAuthority,
    challenge: structuredClone(raw.challenge),
    verdict: structuredClone(raw.verdict),
    rawChallengeText: raw.rawChallengeText,
    rawVerdictText: raw.rawVerdictText,
    expected: structuredClone(raw.expected),
    qvlIdentityEvidence,
    challengeLedger: replayLedger,
    testOnlyNow: value.now,
  };
  assert.doesNotThrow(() => verifyPhalaWorkloadIndependentTdxVerdict(first));
  assert.throws(
    () => verifyPhalaWorkloadIndependentTdxVerdict(first),
    /already consumed/,
  );
});

test("production QVL challenges and verdicts verify raw bytes32 EIP-191, never UTF-8 hex text", async () => {
  const value = await fixture();
  const { challenge, verdict } = value.workloadRawInputs[0];
  const challengeDigest = qvlChallengeSigningDigest(challenge);
  const verdictDigest = independentTdxVerdictSigningDigest(verdict);

  assert.equal(challengeDigest, challenge.challenge_digest);
  assert.equal(
    verifyIndependentEip191RawDigestSignature({
      address: challenge.verifier_address,
      digest: challengeDigest,
      signature: challenge.verifier_signature,
    }).address,
    challenge.verifier_address,
  );
  assert.equal(
    verifyIndependentEip191RawDigestSignature({
      address: verdict.verifier_address,
      digest: verdictDigest,
      signature: verdict.verifier_signature,
    }).address,
    verdict.verifier_address,
  );
  assert.throws(
    () => verifyIndependentEip191PersonalSignature({
      address: challenge.verifier_address,
      message: challengeDigest,
      signature: challenge.verifier_signature,
    }),
    /UTF-8 signature verification failed/i,
  );
  assert.throws(
    () => verifyIndependentEip191PersonalSignature({
      address: verdict.verifier_address,
      message: verdictDigest,
      signature: verdict.verifier_signature,
    }),
    /UTF-8 signature verification failed/i,
  );

  const tamperedDigest = `${verdictDigest.slice(0, -2)}${
    verdictDigest.endsWith("00") ? "01" : "00"
  }`;
  assert.throws(
    () => verifyIndependentEip191RawDigestSignature({
      address: verdict.verifier_address,
      digest: tamperedDigest,
      signature: verdict.verifier_signature,
    }),
    /raw-bytes32 signature verification failed/i,
  );

  const curveOrder = BigInt(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
  );
  const lowS = BigInt(`0x${verdict.verifier_signature.slice(66, 130)}`);
  const highS = (curveOrder - lowS).toString(16).padStart(64, "0");
  const highSignature = `${verdict.verifier_signature.slice(0, 66)}${highS}${
    verdict.verifier_signature.slice(130)
  }`;
  assert.throws(
    () => verifyIndependentEip191RawDigestSignature({
      address: verdict.verifier_address,
      digest: verdictDigest,
      signature: highSignature,
    }),
    /canonical low-s/i,
  );
});

test("compute-workload recipient activation is separately branded and excluded from L", async () => {
  const value = await fixture();
  const proof = value.computeWorkloadActivationEvidence;
  assert.equal(proof.profile, "compute_workload");
  assert.equal(proof.cvm_id, value.releaseAuthority.descriptors[0].cvm_id);
  assert.equal(
    proof.main_runtime_signer_address,
    value.workloadVerdictEvidence[0].tee_identity,
  );
  assert.equal(value.evidenceSet.domains.length, 7);
  assert.equal(
    value.evidenceSet.domains.some((entry) =>
      Object.hasOwn(entry, "recipient_release_commitment")),
    false,
  );
  assert.match(phalaComputeWorkloadRecipientActivationVerificationSha256(proof),
    /^sha256:[0-9a-f]{64}$/);
  assert.equal(proof.source_activation.schema, "dnai.compute.workload-recipient-activation.v3");
  assert.equal(
    proof.recipient_evidence_lease_expires_at,
    proof.source_activation.recipient_evidence_lease_expires_at,
  );
  assert.equal(
    proof.recipient_evidence_lease_expires_at - proof.verdict_issued_at,
    300,
  );
  assert.deepEqual(
    normalizePhalaComputeWorkloadRecipientSourceActivation(
      structuredClone(value.computeWorkloadActivationRaw),
    ),
    proof.source_activation,
  );
  assert.equal(
    canonicalPhalaComputeWorkloadRecipientSourceActivationText(proof.source_activation),
    `${JSON.stringify(JSON.parse(
      canonicalPhalaComputeWorkloadRecipientSourceActivationText(proof.source_activation),
    ), null, 2)}\n`,
  );
  assert.equal(
    phalaComputeWorkloadRecipientSourceActivationSha256(proof.source_activation),
    proof.activation_artifact_sha256,
  );
  assert.throws(() => normalizePhalaComputeWorkloadRecipientSourceActivation({
    ...structuredClone(proof.source_activation),
    extra_authority: true,
  }));
  assert.equal(proof.main_runtime_evidence_sha256,
    phalaWorkloadTdxVerdictVerificationSha256(value.workloadVerdictEvidence[0]));
  assert.equal(
    canonicalPhalaComputeWorkloadRecipientActivationVerificationText(proof),
    `${JSON.stringify(JSON.parse(
      canonicalPhalaComputeWorkloadRecipientActivationVerificationText(proof),
    ), null, 2)}\n`,
  );
  assert.equal(assertVerifiedPhalaComputeWorkloadRecipientActivation(proof), proof);
  assert.throws(
    () => assertProductionPhalaComputeWorkloadRecipientActivation(proof),
    /synthetic compute-workload activation can never authorize/,
  );
  assert.throws(() => {
    proof.activation_signer_key_path = "forged";
  }, TypeError);
  assert.throws(() =>
    assertVerifiedPhalaComputeWorkloadRecipientActivation(structuredClone(proof)));
  const normalized = normalizePhalaComputeWorkloadRecipientActivationVerification(
    structuredClone(proof),
  );
  assert.throws(() => assertVerifiedPhalaComputeWorkloadRecipientActivation(normalized));
});

test("compute-workload recipient report data matches the Python and browser wire vector", () => {
  const vector = JSON.parse(fs.readFileSync(
    new URL("../web/src/lib/computeWorkloadWireVectors.json", import.meta.url),
    "utf8",
  ));
  assert.equal(
    phalaComputeWorkloadRecipientReportData(vector.recipient_attestation),
    `0x${vector.recipient_report_data}`,
  );
});

test("compute-workload activation rejects signer, QVL, recipient, vault, roots, freshness, and replay drift", async () => {
  const value = await fixture();
  const computeQvl = value.qvlIdentityEvidence.find((entry) =>
    entry.domain === "compute_workload_qvl_cvm");
  const verify = ({
    activation,
    qvl = computeQvl,
    mainProof,
    ledger,
    minimumAuthenticatedAt,
    testOnlyNow,
  } = {}) =>
    verifyPhalaComputeWorkloadRecipientActivation({
      activation: activation ?? structuredClone(value.computeWorkloadActivationRaw),
      releaseAuthority: value.releaseAuthority,
      qvlIdentityEvidence: qvl,
      mainRuntimeEvidence: mainProof ?? value.workloadVerdictEvidence[0],
      challengeLedger: ledger ?? new PhalaWorkloadVerdictChallengeLedger(4),
      minimumAuthenticatedAt,
      testOnlyNow: testOnlyNow ?? value.now,
    });
  const mutations = [
    (activation) => { activation.schema = "dnai.compute.workload-recipient-activation.v2"; },
    (activation) => { activation.recipient_evidence_lease_expires_at -= 1; },
    (activation) => {
      activation.authenticated_verdict.activation_evidence_lease_expires_at -= 1;
    },
    (activation) => { activation.authenticated_verdict.verifier_signature = `0x${"11".repeat(64)}1b`; },
    (activation) => { activation.authenticated_verdict.verifier_address = `0x${"91".repeat(20)}`; },
    (activation) => { activation.recipient_attestation.encryption_public_key = "92".repeat(32); },
    (activation) => { activation.recipient_attestation.compute_vault_runtime_code_hash = `0x${"93".repeat(32)}`; },
    (activation) => { activation.recipient_attestation.fresh_contract_deployment_receipt_sha256 = `0x${"94".repeat(32)}`; },
  ];
  for (const mutate of mutations) {
    const activation = structuredClone(value.computeWorkloadActivationRaw);
    mutate(activation);
    assert.throws(() => verify({ activation }));
  }
  assert.throws(() => verify({
    mainProof: structuredClone(value.workloadVerdictEvidence[0]),
  }), /not independently signature-verified in this process/);
  assert.throws(() => verify({ qvl: value.qvlIdentityEvidence[0] }), /dedicated compute-workload QVL/);
  assert.throws(() => verify({
    testOnlyNow: value.computeWorkloadActivationRaw.expires_at,
  }), /expired or outside/);
  const ledger = new PhalaWorkloadVerdictChallengeLedger(4);
  assert.doesNotThrow(() => verify({ ledger }));
  assert.throws(() => verify({ ledger }), /already consumed/);

  const authenticatedAt = value.computeWorkloadActivationRaw.authenticated_at;
  const orderedLedger = new PhalaWorkloadVerdictChallengeLedger(4);
  const staleActivation = structuredClone(value.computeWorkloadActivationRaw);
  staleActivation.authenticated_at = authenticatedAt - 1;
  assert.throws(
    () => verify({
      activation: staleActivation,
      ledger: orderedLedger,
      minimumAuthenticatedAt: authenticatedAt,
    }),
    /predates its required runtime authority/,
  );
  assert.doesNotThrow(() => verify({
    ledger: orderedLedger,
    minimumAuthenticatedAt: authenticatedAt,
  }));
});

test("Compute proof branding finishes before its durable one-use challenge is consumed", () => {
  const source = fs.readFileSync(
    new URL("./phala-seven-cvm-verifier-evidence.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /VERIFIED_COMPUTE_WORKLOAD_RECIPIENT_ACTIVATIONS\.set\([\s\S]*?\n  \);\n  consumeReleaseScopedChallenge\([\s\S]*?\n  \);\n  return normalized;/,
  );
});

test("aggregate rejects omitted, duplicated, reordered, copied, and mixed self-asserted evidence", async () => {
  const value = await fixture();
  assert.throws(() => createPhalaSevenCvmVerifiedEvidenceSet({
    releaseAuthority: value.releaseAuthority,
    qvlIdentityEvidence: value.qvlIdentityEvidence.slice(1),
    workloadVerdictEvidence: value.workloadVerdictEvidence,
    testOnlyNow: value.now,
  }));
  assert.throws(() => createPhalaSevenCvmVerifiedEvidenceSet({
    releaseAuthority: value.releaseAuthority,
    qvlIdentityEvidence: [
      value.qvlIdentityEvidence[0],
      value.qvlIdentityEvidence[0],
      value.qvlIdentityEvidence[2],
      value.qvlIdentityEvidence[3],
      value.qvlIdentityEvidence[4],
    ],
    workloadVerdictEvidence: value.workloadVerdictEvidence,
    testOnlyNow: value.now,
  }));
  assert.throws(() => createPhalaSevenCvmVerifiedEvidenceSet({
    releaseAuthority: value.releaseAuthority,
    qvlIdentityEvidence: value.qvlIdentityEvidence.map((entry) => structuredClone(entry)),
    workloadVerdictEvidence: value.workloadVerdictEvidence,
    testOnlyNow: value.now,
  }));
  const reordered = structuredClone(value.evidenceSet);
  [reordered.domains[0], reordered.domains[1]] = [
    reordered.domains[1],
    reordered.domains[0],
  ];
  assert.throws(() => normalizePhalaSevenCvmVerifiedEvidenceSet(reordered));
  const copied = structuredClone(value.evidenceSet);
  copied.domains[0].qvl_verification_receipt_sha256 = `sha256:${"ff".repeat(32)}`;
  assert.doesNotThrow(() => normalizePhalaSevenCvmVerifiedEvidenceSet(copied));
  assert.throws(() => assertVerifiedPhalaSevenCvmEvidenceSet(copied));
});

test("aggregate enforces the exact 300-second skew boundary and minimum proof expiry", async () => {
  const value = await fixture();
  const atBoundary = structuredClone(value.evidenceSet);
  atBoundary.domains[0].verified_at = value.now - 300;
  atBoundary.first_verified_at = value.now - 300;
  atBoundary.proof_collection_skew_seconds = 300;
  assert.doesNotThrow(() => normalizePhalaSevenCvmVerifiedEvidenceSet(atBoundary));

  const overBoundary = structuredClone(atBoundary);
  overBoundary.domains[0].verified_at = value.now - 301;
  overBoundary.first_verified_at = value.now - 301;
  overBoundary.proof_collection_skew_seconds = 301;
  assert.throws(
    () => normalizePhalaSevenCvmVerifiedEvidenceSet(overBoundary),
    /lineage, transcript, issuance, skew, or expiry/,
  );

  const expiredAtIssuance = structuredClone(value.evidenceSet);
  expiredAtIssuance.domains[0].expires_at = expiredAtIssuance.issued_at;
  expiredAtIssuance.domains[0].activation_evidence_lease_expires_at =
    expiredAtIssuance.issued_at;
  expiredAtIssuance.minimum_activation_evidence_lease_expires_at =
    expiredAtIssuance.issued_at;
  assert.throws(
    () => normalizePhalaSevenCvmVerifiedEvidenceSet(expiredAtIssuance),
    /expiry/,
  );
});

test("durable release challenge ledger closes idempotently and rejects later consumption", () => {
  const directory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-release-ledger-close-"),
  ));
  fs.chmodSync(directory, 0o700);
  const ledger = new PhalaDurableReleaseChallengeLedger(directory);
  try {
    assert.doesNotThrow(() => ledger.close());
    assert.doesNotThrow(() => ledger.close());
    assert.throws(
      () => ledger.consume({
        releaseAuthoritySha256: `sha256:${"11".repeat(32)}`,
        deploymentIntentSha256: `sha256:${"22".repeat(32)}`,
        ceremonyNonce: `0x${"33".repeat(32)}`,
        domain: "main_runtime_cvm",
        challengeId: `0x${"44".repeat(32)}`,
      }),
      /durable challenge ledger is closed/,
    );
  } finally {
    ledger.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("durable release-scoped challenge consumption survives ledger re-instantiation", () => {
  const directory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-release-challenges-"),
  ));
  let firstLedger;
  let secondLedger;
  try {
    fs.chmodSync(directory, 0o700);
    const scope = {
      releaseAuthoritySha256: `sha256:${"11".repeat(32)}`,
      deploymentIntentSha256: `sha256:${"22".repeat(32)}`,
      ceremonyNonce: `0x${"33".repeat(32)}`,
      domain: "main_runtime_cvm",
      challengeId: `0x${"44".repeat(32)}`,
    };
    firstLedger = new PhalaDurableReleaseChallengeLedger(directory);
    firstLedger.consume(scope);
    secondLedger = new PhalaDurableReleaseChallengeLedger(directory);
    assert.throws(
      () => secondLedger.consume(scope),
      /already consumed/,
    );
    assert.equal(fs.readdirSync(directory).length, 1);
    assert.equal(fs.statSync(path.join(directory, fs.readdirSync(directory)[0])).mode & 0o777, 0o600);
  } finally {
    secondLedger?.close();
    firstLedger?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("durable challenge writes stay on the opened directory across pathname replacement", () => {
  const parent = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-release-ledger-swap-"),
  ));
  const directory = path.join(parent, "ledger");
  const held = path.join(parent, "held-ledger");
  const replacement = path.join(parent, "replacement-ledger");
  fs.mkdirSync(directory, { mode: 0o700 });
  const scope = (challengeByte) => ({
    releaseAuthoritySha256: `sha256:${"11".repeat(32)}`,
    deploymentIntentSha256: `sha256:${"22".repeat(32)}`,
    ceremonyNonce: `0x${"33".repeat(32)}`,
    domain: "main_runtime_cvm",
    challengeId: `0x${challengeByte.repeat(32)}`,
  });
  let ledger;
  let replayLedger;
  try {
    ledger = new PhalaDurableReleaseChallengeLedger(directory);
    ledger.consume(scope("44"));
    fs.renameSync(directory, held);
    fs.mkdirSync(directory, { mode: 0o700 });

    assert.throws(() => ledger.consume(scope("44")), /already consumed/);
    ledger.consume(scope("55"));
    assert.equal(fs.readdirSync(held).length, 2);
    assert.equal(fs.readdirSync(directory).length, 0);

    fs.renameSync(directory, replacement);
    fs.renameSync(held, directory);
    replayLedger = new PhalaDurableReleaseChallengeLedger(directory);
    assert.throws(
      () => replayLedger.consume(scope("44")),
      /already consumed/,
    );
    assert.equal(fs.readdirSync(directory).length, 2);
    assert.equal(fs.readdirSync(replacement).length, 0);
  } finally {
    replayLedger?.close();
    ledger?.close();
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("durable challenge replay is rejected after process re-instantiation", () => {
  const directory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-release-ledger-process-"),
  ));
  fs.chmodSync(directory, 0o700);
  const scope = {
    releaseAuthoritySha256: `sha256:${"61".repeat(32)}`,
    deploymentIntentSha256: `sha256:${"62".repeat(32)}`,
    ceremonyNonce: `0x${"63".repeat(32)}`,
    domain: "compute_workload_qvl_cvm",
    challengeId: `0x${"64".repeat(32)}`,
  };
  let ledger;
  try {
    ledger = new PhalaDurableReleaseChallengeLedger(directory);
    ledger.consume(scope);
    const source = [
      "import { PhalaDurableReleaseChallengeLedger as Ledger } from './scripts/phala-seven-cvm-verifier-evidence.mjs';",
      "const directory = process.argv[1];",
      "const scope = JSON.parse(process.argv[2]);",
      "const ledger = new Ledger(directory);",
      "try { ledger.consume(scope); process.exitCode = 90; }",
      "catch (error) {",
      "  if (!String(error?.message || error).includes('already consumed')) throw error;",
      "} finally { ledger.close(); }",
    ].join("\n");
    const child = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", source, directory, JSON.stringify(scope)],
      { cwd: path.resolve(new URL("..", import.meta.url).pathname), encoding: "utf8" },
    );
    assert.equal(child.status, 0, child.stderr);
    assert.equal(fs.readdirSync(directory).length, 1);
  } finally {
    ledger?.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("O projection rejects any drift from its embedded bounded source activation", async () => {
  const value = await fixture();
  const drifted = structuredClone(value.computeWorkloadActivationEvidence);
  drifted.source_activation.main_runtime_evidence_sha256 = `sha256:${"fe".repeat(32)}`;
  assert.throws(
    () => normalizePhalaComputeWorkloadRecipientActivationVerification(drifted),
    /source activation transcript commitment|differs from projected/,
  );
});

test("pure normalizers never mint machine-verification brands", async () => {
  const value = await fixture();
  const identity = normalizePhalaQvlIdentityLaunchEvidence(
    structuredClone(value.qvlIdentityEvidence[0]),
  );
  const workload = normalizePhalaWorkloadTdxVerdictVerification(
    structuredClone(value.workloadVerdictEvidence[0]),
  );
  const aggregate = normalizePhalaSevenCvmVerifiedEvidenceSet(
    structuredClone(value.evidenceSet),
  );
  assert.throws(() => assertVerifiedPhalaQvlIdentityLaunchEvidence(identity));
  assert.throws(() => assertVerifiedPhalaWorkloadTdxVerdict(workload));
  assert.throws(() => assertVerifiedPhalaSevenCvmEvidenceSet(aggregate));

  const accessor = structuredClone(value.evidenceSet);
  const status = accessor.status;
  Object.defineProperty(accessor, "status", {
    enumerable: true,
    get: () => status,
  });
  assert.throws(() => normalizePhalaSevenCvmVerifiedEvidenceSet(accessor));
  const customPrototype = structuredClone(value.evidenceSet);
  Object.setPrototypeOf(customPrototype, { inherited_authority: true });
  assert.throws(() => normalizePhalaSevenCvmVerifiedEvidenceSet(customPrototype));
  const symbolKey = structuredClone(value.evidenceSet);
  symbolKey[Symbol("hidden-authority")] = true;
  assert.throws(() => normalizePhalaSevenCvmVerifiedEvidenceSet(symbolKey));
});

test("the retired six-CVM authority is explicit and rejected by the seven-CVM normalizer", async () => {
  const value = await fixture();
  assert.equal(
    REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_AUTHORITY.schema,
    REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
  );
  assert.match(
    REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_AUTHORITY.status,
    /^revoked_/,
  );
  const retired = {
    ...structuredClone(value.evidenceSet),
    schema: REVOKED_PHALA_SIX_CVM_VERIFIED_EVIDENCE_SET_SCHEMA,
  };
  assert.throws(
    () => normalizePhalaSevenCvmVerifiedEvidenceSet(retired),
    /explicitly revoked/,
  );
});

const DCAP_SOURCE_URL = new URL("./phala-seven-cvm-dcap-verify.py", import.meta.url);
const DCAP_NATIVE_URL = new URL(
  "../⚙️/attestation-qvl/.venv/lib/python3.12/site-packages/dcap_qvl/_dcap_qvl.abi3.so",
  import.meta.url,
);

function createOpenedFdRuntimeCopies(prefix = "dnai-opened-fd-runtime-") {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  const paths = {
    script: path.join(directory, "verify.py"),
    native: path.join(directory, "_dcap_qvl.abi3.so"),
  };
  fs.copyFileSync(DCAP_SOURCE_URL, paths.script);
  fs.copyFileSync(DCAP_NATIVE_URL, paths.native);
  fs.chmodSync(paths.script, 0o644);
  fs.chmodSync(paths.native, 0o755);
  return { directory, paths };
}

test("opened-FD verifier source, native, root runtime, bootstrap, and manifest pins are exact", () => {
  const sourceDigest = createHash("sha256").update(fs.readFileSync(DCAP_SOURCE_URL)).digest("hex");
  const nativeDigest = createHash("sha256").update(fs.readFileSync(DCAP_NATIVE_URL)).digest("hex");
  const runtime = createOpenedFdRuntimeCopies("dnai-pinned-runtime-");
  try {
    assert.equal(sourceDigest, PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.verifier_script_sha256);
    assert.equal(nativeDigest, PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_sha256);
    assert.equal(
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.bootstrap_sha256,
      "9bdc99d17e92ca311326dc21e9ee82093962d05894a326b98f4df9970e930d92",
    );
    assert.equal(
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.system_python_runtime_tree_sha256,
      computePythonRuntimeTreeSha256(
        PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.system_python_runtime_root,
        { expectedUid: 0, allowHardlinks: true },
      ),
    );
    assert.equal(PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_owner_uid, 0);
    assert.equal(PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_mode, "0555");
    assert.equal(
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_path,
      "/Library/Application Support/dnai-wikigen/dcap-qvl/0.5.2/_dcap_qvl.abi3.so",
    );
    assert.equal(
      unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime({
        testOnlyPaths: runtime.paths,
      }).isolated_runtime_environment_sha256,
      "sha256:62be45b60bcf7ad7434ad78247997256ab7282bb91d829ee87c301a3b55a146d",
    );
  } finally {
    fs.rmSync(runtime.directory, { recursive: true, force: true });
  }
});

test("production native authority is root-owned at the frozen path or fails closed", () => {
  const nativePath = PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_path;
  if (!fs.existsSync(nativePath)) {
    assert.throws(
      () => verifyPinnedSevenCvmIsolatedRuntimeEnvironment(),
      /root-owned DCAP native extension is not provisioned/,
    );
    return;
  }
  const stat = fs.lstatSync(nativePath);
  assert.equal(stat.uid, 0);
  assert.equal(stat.mode & 0o7777, 0o555);
  assert.equal(
    verifyPinnedSevenCvmIsolatedRuntimeEnvironment(),
    PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
  );
});

test("opened source and native descriptors survive pathname swaps and execute authenticated bytes", () => {
  for (const kind of ["script", "native"]) {
    const { directory, paths } = createOpenedFdRuntimeCopies(`dnai-${kind}-swap-`);
    const held = path.join(directory, `${kind}.authenticated`);
    const sentinel = path.join(directory, "malicious-executed");
    try {
      const parsed = unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime({
        testOnlyPaths: paths,
        testOnlyBeforeSpawn: () => {
          fs.renameSync(paths[kind], held);
          if (kind === "script") {
            fs.writeFileSync(
              paths.script,
              `from pathlib import Path\nPath(${JSON.stringify(sentinel)}).write_text("bad")\n`,
              { mode: 0o644 },
            );
          } else {
            fs.writeFileSync(paths.native, "malicious-native-replacement\n", { mode: 0o755 });
          }
        },
      });
      assert.equal(
        parsed.runtime_environment_sha256,
        PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
      );
      assert.equal(fs.existsSync(sentinel), false);
      fs.rmSync(paths[kind]);
      fs.renameSync(held, paths[kind]);
      assert.equal(
        createHash("sha256").update(fs.readFileSync(paths[kind])).digest("hex"),
        kind === "script"
          ? PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.verifier_script_sha256
          : PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_sha256,
      );
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("opened descriptor bytes cannot mutate after authentication", () => {
  for (const kind of ["script", "native"]) {
    const { directory, paths } = createOpenedFdRuntimeCopies(`dnai-${kind}-mutation-`);
    try {
      assert.throws(() => unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime({
        testOnlyPaths: paths,
        testOnlyBeforeSpawn: () => fs.appendFileSync(paths[kind], "descriptor-drift"),
      }), /changed after descriptor authentication|opened-FD Intel TDX verifier failed/);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
});

test("swap-then-restore cannot redirect the authenticated source descriptor", () => {
  const { directory, paths } = createOpenedFdRuntimeCopies("dnai-source-swap-back-");
  const held = path.join(directory, "verify.authenticated.py");
  const sentinel = path.join(directory, "swap-back-executed");
  try {
    const parsed = unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime({
      testOnlyPaths: paths,
      testOnlyBeforeSpawn: () => {
        fs.renameSync(paths.script, held);
        fs.writeFileSync(
          paths.script,
          `from pathlib import Path\nPath(${JSON.stringify(sentinel)}).write_text("bad")\n`,
          { mode: 0o644 },
        );
        fs.rmSync(paths.script);
        fs.renameSync(held, paths.script);
      },
    });
    assert.equal(
      parsed.runtime_environment_sha256,
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    );
    assert.equal(fs.existsSync(sentinel), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("isolated flags ignore Python startup and import-path environment injection", () => {
  const directory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-python-injection-"),
  ));
  const runtime = createOpenedFdRuntimeCopies("dnai-python-injection-runtime-");
  const sentinel = path.join(directory, "sitecustomize-executed");
  const startup = path.join(directory, "startup.py");
  try {
    fs.writeFileSync(
      path.join(directory, "sitecustomize.py"),
      `from pathlib import Path\nPath(${JSON.stringify(sentinel)}).write_text("bad")\n`,
    );
    fs.writeFileSync(startup, `open(${JSON.stringify(sentinel)}, "w").write("bad")\n`);
    const parsed = unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime({
      testOnlyPaths: runtime.paths,
      testOnlyExtraEnvironment: {
        PYTHONHOME: directory,
        PYTHONPATH: directory,
        PYTHONSTARTUP: startup,
        PYTHONUSERBASE: directory,
      },
    });
    assert.equal(
      parsed.runtime_environment_sha256,
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    );
    assert.equal(fs.existsSync(sentinel), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
    fs.rmSync(runtime.directory, { recursive: true, force: true });
  }
});

test("operator source/native authority rejects symlinks, hardlinks, modes, size, type, and UID", () => {
  const cases = [
    {
      name: "symlink",
      mutate: ({ directory, paths }) => {
        const original = path.join(directory, "original.py");
        fs.renameSync(paths.script, original);
        fs.symlinkSync(original, paths.script);
      },
      pattern: /canonical, and symlink-free/,
    },
    {
      name: "hardlink",
      mutate: ({ directory, paths }) => {
        const hardlink = path.join(directory, "hardlink.py");
        fs.linkSync(paths.script, hardlink);
        paths.script = hardlink;
      },
      pattern: /single-link operator-owned restricted/,
    },
    {
      name: "group-write",
      mutate: ({ paths }) => fs.chmodSync(paths.script, 0o664),
      pattern: /single-link operator-owned restricted/,
    },
    {
      name: "world-write-native",
      mutate: ({ paths }) => fs.chmodSync(paths.native, 0o777),
      pattern: /single-link operator-owned restricted/,
    },
    {
      name: "oversized",
      mutate: ({ paths }) => fs.writeFileSync(paths.script, Buffer.alloc(256 * 1024 + 1, 0x61)),
      pattern: /outside its frozen byte bound/,
    },
    {
      name: "special-type",
      mutate: ({ directory, paths }) => { paths.script = directory; },
      pattern: /single-link operator-owned restricted/,
    },
    {
      name: "wrong-uid",
      mutate: ({ paths }) => { paths.script = "/usr/bin/python3"; },
      pattern: /single-link operator-owned restricted/,
    },
  ];
  for (const entry of cases) {
    const fixturePaths = createOpenedFdRuntimeCopies(`dnai-authority-${entry.name}-`);
    try {
      entry.mutate(fixturePaths);
      assert.throws(() => unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime({
        testOnlyPaths: fixturePaths.paths,
      }), entry.pattern);
    } finally {
      fs.rmSync(fixturePaths.directory, { recursive: true, force: true });
    }
  }
});

test("unsupported host seams fail before platform paths or spawning", () => {
  const missingPaths = { native: "/does/not/exist/native.so", script: "/does/not/exist/source.py" };
  assert.throws(() => unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime({
    testOnlyHost: { platform: "linux", architecture: "x64" },
    testOnlyPaths: missingPaths,
  }), /outside the frozen Darwin arm64 authority/);
  assert.throws(() => unsafeAssertPinnedSevenCvmOpenedFdFixtureRuntime({
    testOnlyHost: { platform: "darwin", architecture: "x64" },
    testOnlyPaths: missingPaths,
  }), /outside the frozen Darwin arm64 authority/);
});

test("Python interpreter and stdlib bytes are both inside the runtime-tree authority", () => {
  const directory = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-python-runtime-tree-"),
  ));
  const bin = path.join(directory, "bin");
  const stdlib = path.join(directory, "lib", "python3.12");
  const interpreter = path.join(bin, "python3.12");
  const module = path.join(stdlib, "hashlib.py");
  try {
    fs.mkdirSync(bin, { recursive: true });
    fs.mkdirSync(stdlib, { recursive: true });
    fs.writeFileSync(interpreter, "pinned-interpreter\n", { mode: 0o755 });
    fs.writeFileSync(module, "pinned-stdlib\n", { mode: 0o644 });
    const baseline = computePythonRuntimeTreeSha256(directory);
    fs.appendFileSync(interpreter, "interpreter-drift\n");
    const interpreterDrift = computePythonRuntimeTreeSha256(directory);
    assert.notEqual(interpreterDrift, baseline);
    fs.writeFileSync(interpreter, "pinned-interpreter\n", { mode: 0o755 });
    assert.equal(computePythonRuntimeTreeSha256(directory), baseline);
    fs.appendFileSync(module, "stdlib-drift\n");
    assert.notEqual(computePythonRuntimeTreeSha256(directory), baseline);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("two direct opened-FD probes have one exact canonical runtime authority", () => {
  const runtime = createOpenedFdRuntimeCopies("dnai-double-runtime-probe-");
  try {
    const options = { testOnlyPaths: runtime.paths };
    const first = unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime(options);
    const second = unsafeProbePinnedSevenCvmOpenedFdFixtureRuntime(options);
    assert.equal(
      first.runtime_environment_sha256,
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    );
    assert.equal(second.runtime_environment_sha256, first.runtime_environment_sha256);
  } finally {
    fs.rmSync(runtime.directory, { recursive: true, force: true });
  }
});
