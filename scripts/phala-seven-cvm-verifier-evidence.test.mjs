import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
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
  assertHistoricallyVerifiedProductionPhalaComputeWorkloadRecipientActivation,
  assertHistoricallyVerifiedProductionPhalaSevenCvmEvidenceSet,
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
  phalaSevenCvmReleaseVerificationAuthoritySha256,
  phalaWorkloadTdxVerdictVerificationSha256,
  consumePhalaSevenCvmHistoricalTranscriptCapabilities,
  independentTdxVerdictSigningDigest,
  qvlChallengeSigningDigest,
  replayPersistedHistoricalPhalaComputeWorkloadRecipientActivation,
  replayPersistedHistoricalPhalaSevenCvmEvidence,
  verifyPhalaQvlIdentityLaunchEvidence,
  verifyPhalaComputeWorkloadRecipientActivation,
  verifyPinnedSevenCvmLocalDcapQuote,
  verifyPinnedSevenCvmIsolatedRuntimeEnvironment,
  verifyPhalaWorkloadIndependentTdxVerdict,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  OPENED_FD_RUNTIME_AUTHORITY_MODES,
  createPinnedSevenCvmOpenedFdRuntime,
} from "./phala-seven-cvm-opened-fd-runtime-core.mjs";
import {
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
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

const historicalTestSha = (seed) =>
  `sha256:${seed.toString(16).padStart(64, "0")}`;
const historicalTestTimestamp = (seconds) => new Date(seconds * 1_000)
  .toISOString().replace(".000Z", "Z");

function sortedPlainData(value) {
  if (Array.isArray(value)) return value.map(sortedPlainData);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedPlainData(value[key])]),
  );
}

function compactHistoricalText(value) {
  return JSON.stringify(sortedPlainData(value));
}

function canonicalHistoricalText(value) {
  return `${JSON.stringify(sortedPlainData(value), null, 2)}\n`;
}

function historicalFileIdentity(text) {
  return {
    sha256: `sha256:${createHash("sha256").update(text, "utf8").digest("hex")}`,
    size: Buffer.byteLength(text, "utf8"),
  };
}

function syntheticHistoricalPosture(descriptor) {
  return {
    expectedAuthority: {
      domain: descriptor.domain,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      compose_hash: descriptor.compose_hash,
      kms_id: descriptor.kms_id,
      instance_type: descriptor.instance_type,
      disk_size: descriptor.disk_size,
    },
    receipt: {
      schema: "dnai.synthetic-historical-phala-production-cvm-posture-receipt.v2",
      status: "private_posture_fixture_prepared",
      truth_status: "synthetic_node_test_posture_never_production_authority",
      domain: descriptor.domain,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      compose_hash: descriptor.compose_hash,
      os_image_hash: descriptor.os_image_hash,
      kms_id: descriptor.kms_id,
      instance_type: descriptor.instance_type,
      disk_size: descriptor.disk_size,
      listed: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
      observed_at: descriptor.posture_observed_at,
      receipt_sha256: descriptor.posture_receipt_sha256,
      raw_secret_egress: false,
    },
  };
}

function syntheticHistoricalEnvelope({
  flag,
  domain,
  role,
  rawArtifactText,
  artifactSha256,
  verificationRecord,
}) {
  const raw = historicalFileIdentity(rawArtifactText);
  return canonicalHistoricalText({
    schema: "dnai.phala-verifier-historical-transcript-artifact.v2",
    chain_id: 84_532,
    flag,
    domain,
    role,
    artifact_sha256: artifactSha256,
    raw_artifact_sha256: raw.sha256,
    raw_artifact_size: raw.size,
    raw_artifact_text: rawArtifactText,
    verification_record: verificationRecord,
  });
}

function syntheticHistoricalTranscriptFiles(value) {
  const byFlag = new Map();
  value.qvlRawInputs.forEach((raw, index) => {
    const proof = value.qvlIdentityEvidence[index];
    const descriptor = value.releaseAuthority.descriptors.find(
      ({ domain }) => domain === raw.domain,
    );
    const posture = syntheticHistoricalPosture(descriptor);
    const collateralJson = compactHistoricalText({
      schema: "dnai.synthetic-historical-dcap-collateral.v2",
      domain: raw.domain,
      verification_time: proof.verified_at,
      never_production_authority: true,
    });
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[raw.domain];
    const requestText = syntheticHistoricalEnvelope({
      flag: flags.request,
      domain: raw.domain,
      role: "request",
      rawArtifactText: raw.rawRequestText,
      artifactSha256: proof.identity_attestation_request_sha256,
      verificationRecord: null,
    });
    const responseText = syntheticHistoricalEnvelope({
      flag: flags.response,
      domain: raw.domain,
      role: "response",
      rawArtifactText: raw.rawResponseText,
      artifactSha256: proof.identity_attestation_response_sha256,
      verificationRecord: {
        schema: "dnai.phala-verifier-historical-dcap-replay-record.v2",
        verification_time: proof.verified_at,
        activation_evidence_lease_issued_at:
          proof.activation_evidence_lease_issued_at,
        activation_evidence_lease_expires_at:
          proof.activation_evidence_lease_expires_at,
        runtime_environment_sha256:
          PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
        collateral_sha256: historicalFileIdentity(collateralJson).sha256,
        collateral_json: collateralJson,
        local_dcap_verification_receipt_sha256:
          proof.local_dcap_verification_receipt_sha256,
        posture_expected_authority: posture.expectedAuthority,
        production_posture_receipt: posture.receipt,
        production_posture_receipt_sha256: descriptor.posture_receipt_sha256,
      },
    });
    assert.deepEqual(historicalFileIdentity(requestText), {
      sha256: proof.identity_attestation_request_file_sha256,
      size: proof.identity_attestation_request_file_size,
    });
    assert.deepEqual(historicalFileIdentity(responseText), {
      sha256: proof.identity_attestation_response_file_sha256,
      size: proof.identity_attestation_response_file_size,
    });
    byFlag.set(flags.request, requestText);
    byFlag.set(flags.response, responseText);
  });
  value.workloadRawInputs.forEach((raw, index) => {
    const proof = value.workloadVerdictEvidence[index];
    const descriptor = value.releaseAuthority.descriptors.find(
      ({ domain }) => domain === raw.challenge.domain,
    );
    const posture = syntheticHistoricalPosture(descriptor);
    const flags = PHALA_SEVEN_CVM_VERIFIER_RAW_CLI_FLAGS[raw.challenge.domain];
    const challengeText = syntheticHistoricalEnvelope({
      flag: flags.challenge,
      domain: raw.challenge.domain,
      role: "challenge",
      rawArtifactText: raw.rawChallengeText,
      artifactSha256: proof.qvl_challenge_artifact_sha256,
      verificationRecord: null,
    });
    const verdictText = syntheticHistoricalEnvelope({
      flag: flags.verdict,
      domain: raw.challenge.domain,
      role: "verdict",
      rawArtifactText: raw.rawVerdictText,
      artifactSha256: proof.qvl_verdict_artifact_sha256,
      verificationRecord: {
        schema: "dnai.phala-verifier-historical-signature-replay-record.v2",
        verification_time: proof.verified_at,
        verdict_activation_evidence_lease_expires_at:
          proof.verdict_activation_evidence_lease_expires_at,
        activation_evidence_lease_expires_at:
          proof.activation_evidence_lease_expires_at,
        report_data_binding: proof.report_data_binding,
        posture_expected_authority: posture.expectedAuthority,
        production_posture_receipt: posture.receipt,
        production_posture_receipt_sha256: descriptor.posture_receipt_sha256,
      },
    });
    assert.deepEqual(historicalFileIdentity(challengeText), {
      sha256: proof.qvl_challenge_file_sha256,
      size: proof.qvl_challenge_file_size,
    });
    assert.deepEqual(historicalFileIdentity(verdictText), {
      sha256: proof.qvl_verdict_file_sha256,
      size: proof.qvl_verdict_file_size,
    });
    byFlag.set(flags.challenge, challengeText);
    byFlag.set(flags.verdict, verdictText);
  });
  return PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag) => ({
    flag,
    text: byFlag.get(flag),
  }));
}

function syntheticHistoricalPostureAndExecutor(value) {
  const authority = value.releaseAuthority;
  const order = [
    ...PHALA_SEVEN_CVM_EXECUTION_ORDER.slice(1),
    PHALA_SEVEN_CVM_EXECUTION_ORDER[0],
  ];
  const preparationBase = value.now - 300;
  const commitBase = value.now - 180;
  return {
    schema: "dnai.phala-executor-state.v3",
    status: "complete_seven_commits_posture_observed_attestation_unverified",
    sequence: 38,
    batch_id: historicalTestSha(700),
    bootstrap_authorization_id: `sha256:${authority.ceremony_nonce.slice(2)}`,
    bootstrap_authorization_receipt_sha256:
      authority.bootstrap_authorization_receipt_sha256,
    release_sha: authority.release_sha,
    launch_intent_sha256: historicalTestSha(701),
    target_authority_sha256: historicalTestSha(702),
    phala_recovery_directory_identity_anchor_sha256: historicalTestSha(703),
    reservations: order.map((domain, index) => ({
      domain,
      app_id: authority.descriptors.find((entry) => entry.domain === domain).app_id,
      nonce: index + 1,
    })),
    preparations: order.map((domain, index) => ({
      domain,
      request_sha256: historicalTestSha(800 + index * 3),
      readiness_sha256: historicalTestSha(801 + index * 3),
      attempted_at: historicalTestTimestamp(preparationBase + index * 3),
      observed_at: historicalTestTimestamp(preparationBase + index * 3 + 1),
      observation_sha256: historicalTestSha(802 + index * 3),
    })),
    signed_key_bindings: order.map((domain, index) => ({
      domain,
      binding_sha256: historicalTestSha(900 + index * 2),
      public_key_sha256: historicalTestSha(901 + index * 2),
    })),
    committed_prefix: order.map((domain, index) => ({
      domain,
      cvm_id: authority.descriptors.find((entry) => entry.domain === domain).cvm_id,
      request_sha256: historicalTestSha(1_000 + index * 3),
      readiness_sha256: historicalTestSha(1_001 + index * 3),
      attempted_at: historicalTestTimestamp(commitBase + index * 3),
      observed_at: historicalTestTimestamp(commitBase + index * 3 + 1),
      observation_sha256: historicalTestSha(1_002 + index * 3),
    })),
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: order.map((domain) => ({
      domain,
      receipt_sha256: authority.descriptors.find((entry) => entry.domain === domain)
        .posture_receipt_sha256,
    })),
    preparations_validation_sha256: historicalTestSha(1_100),
  };
}

async function syntheticHistoricalReplayInputs(value) {
  const rawTranscriptFiles = syntheticHistoricalTranscriptFiles(value);
  const transcriptFileSet =
    createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
      rawTranscriptFiles,
    );
  assert.equal(
    phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet),
    value.evidenceSet.historical_transcript_file_set_sha256,
  );
  const executorFinalState = syntheticHistoricalPostureAndExecutor(value);
  const localResultByDomain = {};
  for (const raw of value.qvlRawInputs) {
    const policy = value.releaseAuthority.qvl_measurement_policies.find(
      (entry) => entry.domain === raw.domain,
    );
    localResultByDomain[raw.domain] = await raw.testOnlyVerifyQuote(
      Buffer.from(raw.response.quote.slice(2), "hex"),
      policy,
    );
  }
  return {
    releaseAuthority: value.releaseAuthority,
    rawTranscriptFiles,
    executorFinalState,
    persistedEvidenceSet: structuredClone(value.evidenceSet),
    testOnlyHistoricalReplayCommitments: {
      executor_final_state_sha256: phalaExecutorStateDigest(executorFinalState),
      historical_transcript_file_set_sha256:
        phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet),
      seven_cvm_verified_evidence_set_sha256:
        phalaSevenCvmVerifiedEvidenceSetSha256(value.evidenceSet),
    },
    localResultByDomain,
    testOnlyVerifyQuote: async (_quote, policy) =>
      structuredClone(localResultByDomain[policy.domain]),
  };
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
  assert.equal(value.evidenceSet.private_historical_transcript_required, true);
  assert.equal(value.evidenceSet.raw_quote_publicly_disclosed, false);
  assert.equal(value.evidenceSet.raw_collateral_publicly_disclosed, false);
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
    "dnai.phala-qvl-identity-launch-verification.v5",
  );
  assert.equal(
    value.workloadVerdictEvidence[0].schema,
    "dnai.phala-workload-tdx-verdict-verification.v5",
  );
  assert.equal(
    value.evidenceSet.schema,
    "dnai.phala-seven-cvm-verified-evidence-set.v5",
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
    assert.ok(
      proof.identity_attestation_request_file_size
        > Buffer.byteLength(raw.rawRequestText, "utf8"),
    );
    assert.ok(
      proof.identity_attestation_response_file_size
        > Buffer.byteLength(raw.rawResponseText, "utf8"),
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
    assert.ok(
      proof.qvl_challenge_file_size
        > Buffer.byteLength(raw.rawChallengeText, "utf8"),
    );
    assert.ok(
      proof.qvl_verdict_file_size
        > Buffer.byteLength(raw.rawVerdictText, "utf8"),
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

test("exact-seven private transcript capabilities are atomic and one-shot", () => {
  const capabilityStore = new WeakMap();
  const proofs = Array.from({ length: 7 }, () => ({}));
  proofs.forEach((proof, index) => capabilityStore.set(proof, index));
  assert.throws(
    () => consumePhalaSevenCvmHistoricalTranscriptCapabilities(
      capabilityStore,
      [...proofs.slice(0, 6), {}],
    ),
    /unavailable or already consumed/,
  );
  assert.equal(proofs.every((proof) => capabilityStore.has(proof)), true);
  consumePhalaSevenCvmHistoricalTranscriptCapabilities(capabilityStore, proofs);
  assert.equal(proofs.every((proof) => !capabilityStore.has(proof)), true);
  assert.throws(
    () => consumePhalaSevenCvmHistoricalTranscriptCapabilities(
      capabilityStore,
      proofs,
    ),
    /unavailable or already consumed/,
  );
  const verifierSource = fs.readFileSync(
    new URL("./phala-seven-cvm-verifier-evidence.mjs", import.meta.url),
    "utf8",
  );
  const exporterStart = verifierSource.indexOf(
    "export function exportPhalaSevenCvmHistoricalTranscriptFiles",
  );
  const exporterEnd = verifierSource.indexOf(
    "\nfunction parseExactPhalaSevenCvmHistoricalTranscriptFiles",
    exporterStart,
  );
  const exporterSource = verifierSource.slice(exporterStart, exporterEnd);
  const exact14DigestValidation = exporterSource.lastIndexOf(
    "phalaSevenCvmHistoricalTranscriptFileSetSha256",
  );
  const capabilityConsumption = exporterSource.indexOf(
    "consumePhalaSevenCvmHistoricalTranscriptCapabilities",
  );
  assert.equal(exporterStart >= 0 && exporterEnd > exporterStart, true);
  assert.equal(exact14DigestValidation >= 0, true);
  assert.equal(capabilityConsumption > exact14DigestValidation, true);
});

test("exact-14 bounds admit worst-case escaped 512 KiB collateral envelopes", () => {
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES,
    2 * 1024 * 1024,
  );
  assert.equal(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES,
    16 * 1024 * 1024,
  );
  const collateralBudget = 512 * 1024;
  const emptyCollateral = JSON.stringify({ payload: "" });
  const slashCount = Math.floor(
    (collateralBudget - Buffer.byteLength(emptyCollateral, "ascii")) / 2,
  );
  const asciiCount = collateralBudget
    - Buffer.byteLength(emptyCollateral, "ascii")
    - slashCount * 2;
  const collateralJson = JSON.stringify({
    payload: `${"\\".repeat(slashCount)}${"a".repeat(asciiCount)}`,
  });
  assert.equal(Buffer.byteLength(collateralJson, "ascii"), collateralBudget);
  const entries = PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map(
    (flag, index) => ({
      flag,
      text: canonicalHistoricalText({ collateral_json: collateralJson, index }),
    }),
  );
  const sizes = entries.map(({ text }) => Buffer.byteLength(text, "utf8"));
  const totalBytes = sizes.reduce((total, size) => total + size, 0);
  assert.equal(sizes.every((size) => size > 1024 * 1024), true);
  assert.equal(
    sizes.every((size) =>
      size <= PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_FILE_BYTES),
    true,
  );
  assert.equal(totalBytes > 8 * 1024 * 1024, true);
  assert.equal(
    totalBytes <= PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_MAX_AGGREGATE_BYTES,
    true,
  );
  const fileSet = createPhalaSevenCvmHistoricalTranscriptFileSetFromTextEntries(
    entries,
  );
  assert.deepEqual(
    fileSet.files.map(({ size }) => size),
    sizes,
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

test("exact-14 historical replay reconstructs L and O at recorded seconds without fresh brands", async () => {
  const value = await fixture();
  const inputs = await syntheticHistoricalReplayInputs(value);
  const replay = await replayPersistedHistoricalPhalaSevenCvmEvidence(inputs);
  assert.equal(
    phalaSevenCvmVerifiedEvidenceSetSha256(replay.evidenceSet),
    phalaSevenCvmVerifiedEvidenceSetSha256(value.evidenceSet),
  );
  assert.throws(() => assertVerifiedPhalaSevenCvmEvidenceSet(replay.evidenceSet));
  for (const proof of replay.qvlIdentityEvidence) {
    assert.throws(() => assertVerifiedPhalaQvlIdentityLaunchEvidence(proof));
  }
  for (const proof of replay.workloadVerdictEvidence) {
    assert.throws(() => assertVerifiedPhalaWorkloadTdxVerdict(proof));
  }
  assert.throws(
    () => assertHistoricallyVerifiedProductionPhalaSevenCvmEvidenceSet(
      replay.evidenceSet,
    ),
    /synthetic seven-CVM evidence has no production historical authority/,
  );
  const commitmentSelectedReplay =
    await replayPersistedHistoricalPhalaSevenCvmEvidence({
      ...inputs,
      persistedEvidenceSet: undefined,
    });
  assert.equal(
    phalaSevenCvmVerifiedEvidenceSetSha256(
      commitmentSelectedReplay.evidenceSet,
    ),
    phalaSevenCvmVerifiedEvidenceSetSha256(value.evidenceSet),
  );
  const computeQvl = replay.qvlIdentityEvidence.find(
    ({ domain }) => domain === "compute_workload_qvl_cvm",
  );
  const mainProof = replay.workloadVerdictEvidence.find(
    ({ domain }) => domain === "main_runtime_cvm",
  );
  const activation =
    replayPersistedHistoricalPhalaComputeWorkloadRecipientActivation({
      activation: structuredClone(value.computeWorkloadActivationEvidence),
      releaseAuthority: inputs.releaseAuthority,
      qvlIdentityEvidence: computeQvl,
      mainRuntimeEvidence: mainProof,
    });
  assert.equal(
    phalaComputeWorkloadRecipientActivationVerificationSha256(activation),
    phalaComputeWorkloadRecipientActivationVerificationSha256(
      value.computeWorkloadActivationEvidence,
    ),
  );
  assert.throws(
    () => assertVerifiedPhalaComputeWorkloadRecipientActivation(activation),
  );
  assert.throws(
    () => assertHistoricallyVerifiedProductionPhalaComputeWorkloadRecipientActivation(
      activation,
    ),
    /synthetic activation has no production historical authority/,
  );
});

test("historical replay rejects collateral, ordering, persisted-L, posture, and executor drift", async () => {
  const value = await fixture();
  const inputs = await syntheticHistoricalReplayInputs(value);
  const replay = (overrides) => replayPersistedHistoricalPhalaSevenCvmEvidence({
    ...inputs,
    ...overrides,
  });
  const collateralDrift = structuredClone(inputs.rawTranscriptFiles);
  const responseIndex = collateralDrift.findIndex(({ flag }) =>
    flag.endsWith("qvl-identity-response"));
  const responseEnvelope = JSON.parse(collateralDrift[responseIndex].text);
  responseEnvelope.verification_record.collateral_json += " ";
  collateralDrift[responseIndex].text = canonicalHistoricalText(responseEnvelope);
  await assert.rejects(
    () => replay({ rawTranscriptFiles: collateralDrift }),
    /collateral|replay record drifted|transcript file set drifted/,
  );

  const reordered = structuredClone(inputs.rawTranscriptFiles);
  [reordered[0], reordered[1]] = [reordered[1], reordered[0]];
  await assert.rejects(
    () => replay({ rawTranscriptFiles: reordered }),
    /reordered/,
  );

  const postureDrift = structuredClone(inputs.rawTranscriptFiles);
  const verdictIndex = postureDrift.findIndex(({ flag }) =>
    flag.endsWith("independent-tdx-verdict"));
  const verdictEnvelope = JSON.parse(postureDrift[verdictIndex].text);
  verdictEnvelope.verification_record.production_posture_receipt.public_logs = true;
  postureDrift[verdictIndex].text = canonicalHistoricalText(verdictEnvelope);
  await assert.rejects(
    () => replay({ rawTranscriptFiles: postureDrift }),
    /posture|transcript file set drifted/,
  );

  const executorDrift = structuredClone(inputs.executorFinalState);
  executorDrift.committed_prefix[0].cvm_id =
    executorDrift.committed_prefix[1].cvm_id;
  await assert.rejects(
    () => replay({ executorFinalState: executorDrift }),
    /executor|distinct|terminal state/,
  );

  const persistedDrift = structuredClone(inputs.persistedEvidenceSet);
  persistedDrift.issued_at += 1;
  await assert.rejects(
    () => replay({ persistedEvidenceSet: persistedDrift }),
    /persisted seven-CVM evidence set drifted/,
  );
});

test("historical L and O replay survive a spawned verifier-process restart", async () => {
  const value = await fixture();
  const inputs = await syntheticHistoricalReplayInputs(value);
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "dnai-historical-restart-"));
  const bundlePath = path.join(directory, "bundle.json");
  const childPath = path.join(directory, "historical-restart.test.mjs");
  const verifierUrl = new URL(
    "./phala-seven-cvm-verifier-evidence.mjs",
    import.meta.url,
  ).href;
  fs.writeFileSync(bundlePath, JSON.stringify({
    releaseAuthority: value.releaseAuthority,
    rawTranscriptFiles: inputs.rawTranscriptFiles,
    executorFinalState: inputs.executorFinalState,
    persistedEvidenceSet: inputs.persistedEvidenceSet,
    testOnlyHistoricalReplayCommitments:
      inputs.testOnlyHistoricalReplayCommitments,
    localResultByDomain: inputs.localResultByDomain,
    activation: value.computeWorkloadActivationEvidence,
  }));
  fs.writeFileSync(childPath, `
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import {
  assertVerifiedPhalaComputeWorkloadRecipientActivation,
  assertVerifiedPhalaSevenCvmEvidenceSet,
  replayPersistedHistoricalPhalaComputeWorkloadRecipientActivation,
  replayPersistedHistoricalPhalaSevenCvmEvidence,
} from ${JSON.stringify(verifierUrl)};
const bundle = JSON.parse(fs.readFileSync(${JSON.stringify(bundlePath)}, "utf8"));
test("restart replay", async () => {
  const replay = await replayPersistedHistoricalPhalaSevenCvmEvidence({
    releaseAuthority: bundle.releaseAuthority,
    rawTranscriptFiles: bundle.rawTranscriptFiles,
    executorFinalState: bundle.executorFinalState,
    persistedEvidenceSet: bundle.persistedEvidenceSet,
    testOnlyHistoricalReplayCommitments:
      bundle.testOnlyHistoricalReplayCommitments,
    testOnlyVerifyQuote: async (_quote, policy) =>
      bundle.localResultByDomain[policy.domain],
  });
  assert.throws(() => assertVerifiedPhalaSevenCvmEvidenceSet(replay.evidenceSet));
  const activation = replayPersistedHistoricalPhalaComputeWorkloadRecipientActivation({
    activation: bundle.activation,
    releaseAuthority: bundle.releaseAuthority,
    qvlIdentityEvidence: replay.qvlIdentityEvidence.find(
      (proof) => proof.domain === "compute_workload_qvl_cvm",
    ),
    mainRuntimeEvidence: replay.workloadVerdictEvidence.find(
      (proof) => proof.domain === "main_runtime_cvm",
    ),
  });
  assert.throws(() => assertVerifiedPhalaComputeWorkloadRecipientActivation(activation));
});
`);
  try {
    const child = spawnSync(process.execPath, ["--test", childPath], {
      cwd: directory,
      encoding: "utf8",
      timeout: 30_000,
      maxBuffer: 256 * 1024,
    });
    assert.equal(child.status, 0, `${child.stdout}\n${child.stderr}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

const DCAP_SOURCE_URL = new URL("./phala-seven-cvm-dcap-verify.py", import.meta.url);
const DCAP_KAT_URL = new URL("./phala-seven-cvm-dcap-verify-kat.py", import.meta.url);
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

function createOpenedFdSnapshotBarrier() {
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "dnai-snapshot-barrier-")),
  );
  fs.chmodSync(directory, 0o700);
  for (const name of [
    "snapshot-ready",
    "continue",
    "snapshot-loaded",
    "original-restored",
  ]) {
    const created = spawnSync("/usr/bin/mkfifo", ["-m", "600", path.join(directory, name)], {
      encoding: "utf8",
      timeout: 5_000,
    });
    assert.equal(created.status, 0, created.stderr);
  }
  return directory;
}

test("Python recorded-second DCAP KAT makes live and replay collateral paths identical", () => {
  const kat = spawnSync("/usr/bin/python3", [
    "-I", "-S", "-B", DCAP_KAT_URL.pathname,
  ], {
    cwd: "/",
    encoding: "utf8",
    env: { HOME: "/var/empty", LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
    timeout: 10_000,
    maxBuffer: 16 * 1024,
  });
  assert.equal(kat.status, 0, kat.stderr);
  assert.equal(kat.stderr, "");
  assert.deepEqual(JSON.parse(kat.stdout), {
    collateral_sha256:
      "sha256:6c93e4b045e141aeb5b6a02c4c23e772552a84528e5f30c996ca016c2a42ffc7",
    measurements_sha256:
      "sha256:009f360e600a98bded234d15f3a0871953057c452edcb219d8745e97a579ef81",
    policy_sha256:
      "sha256:47765642e5f9bc8f041dd5ba70a371d03765b454cb9413eb3574df838f79bdd7",
    report_data: `0x${"42".repeat(64)}`,
  });
});

test("opened-FD verifier source, native, root runtime, bootstrap, and manifest pins are exact", () => {
  const sourceDigest = createHash("sha256").update(fs.readFileSync(DCAP_SOURCE_URL)).digest("hex");
  const nativeDigest = createHash("sha256").update(fs.readFileSync(DCAP_NATIVE_URL)).digest("hex");
  const runtime = createOpenedFdRuntimeCopies("dnai-pinned-runtime-");
  try {
    assert.equal(sourceDigest, PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.verifier_script_sha256);
    assert.equal(nativeDigest, PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.dcap_qvl_abi3_sha256);
    assert.equal(
      PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.bootstrap_sha256,
      "b6e79f5ca1b214036d7e11e26aac0a249a26faa1ed702ef908ad27d0cdebb968",
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
      "sha256:0acd40fb80dd000f367583017643ac07fe31becd2372bc20ceca3e91aa8b8beb",
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

test("read-only native snapshot is isolated from original mutation, unlinked, and cleaned", async () => {
  const { directory, paths } = createOpenedFdRuntimeCopies("dnai-snapshot-isolation-");
  const barrier = createOpenedFdSnapshotBarrier();
  const beforeSnapshots = new Set(
    fs.readdirSync("/private/tmp").filter((name) => name.startsWith("dnai-dcap-")),
  );
  const originalSha256 = createHash("sha256")
    .update(fs.readFileSync(paths.native)).digest("hex");
  let helper;
  try {
    helper = spawn(process.execPath, ["-e", `
const fs = require("node:fs");
const path = require("node:path");
const nativePath = process.argv[1];
const barrierPath = process.argv[2];
const marker = (name) => path.join(barrierPath, name);
if (fs.readFileSync(marker("snapshot-ready"), "utf8") !== "snapshot-ready\\n") {
  process.exit(31);
}
const original = fs.readFileSync(nativePath);
const drifted = Buffer.from(original);
drifted[Math.floor(drifted.length / 2)] ^= 0xff;
let fd = fs.openSync(nativePath, "r+");
fs.writeSync(fd, drifted, 0, drifted.length, 0);
fs.fsyncSync(fd);
fs.closeSync(fd);
fs.writeFileSync(marker("continue"), "continue\\n");
if (fs.readFileSync(marker("snapshot-loaded"), "utf8") !== "snapshot-loaded\\n") {
  process.exit(32);
}
fd = fs.openSync(nativePath, "r+");
fs.writeSync(fd, original, 0, original.length, 0);
fs.fsyncSync(fd);
fs.closeSync(fd);
fs.writeFileSync(marker("original-restored"), "original-restored\\n");
`, paths.native, barrier], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let helperStdout = "";
    let helperStderr = "";
    helper.stdout.on("data", (chunk) => { helperStdout += chunk; });
    helper.stderr.on("data", (chunk) => { helperStderr += chunk; });
    const helperExit = once(helper, "exit");
    const runtime = createPinnedSevenCvmOpenedFdRuntime({
      authority: PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER,
      host: { platform: process.platform, architecture: process.arch },
      nativeAuthorityMode: OPENED_FD_RUNTIME_AUTHORITY_MODES.operatorOwnedFixture,
      nativePath: paths.native,
      sourcePath: paths.script,
      nativeSnapshotBarrier: barrier,
    });
    const parsed = runtime.probe();
    const [helperStatus] = await helperExit;
    assert.equal(helperStatus, 0, `${helperStdout}\n${helperStderr}`);
    assert.deepEqual(parsed, {
      native_snapshot_authenticated: true,
      native_snapshot_link_count: 0,
      native_snapshot_mode: "0500",
      runtime_environment_sha256:
        PINNED_SEVEN_CVM_LOCAL_DCAP_VERIFIER.isolated_runtime_environment_sha256,
    });
    assert.equal(
      createHash("sha256").update(fs.readFileSync(paths.native)).digest("hex"),
      originalSha256,
    );
    assert.deepEqual(
      new Set(
        fs.readdirSync("/private/tmp")
          .filter((name) => name.startsWith("dnai-dcap-")),
      ),
      beforeSnapshots,
    );
  } finally {
    if (helper && helper.exitCode === null) helper.kill("SIGKILL");
    fs.rmSync(directory, { recursive: true, force: true });
    fs.rmSync(barrier, { recursive: true, force: true });
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
