import assert from "node:assert/strict";
import { test } from "node:test";

import { __test } from "../web/scripts/release-env-core.mjs";
import {
  syntheticPhalaSevenCvmVerifierEvidenceFixture,
} from "./phala-seven-cvm-verifier-evidence.fixture.mjs";
import {
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  COMPUTE_WORKLOAD_BROWSER_ENV_KEYS,
  assertHistoricallyVerifiedComputeWorkloadActivationObservation,
  assertPrebuildVerifiedComputeWorkloadActivationObservation,
  createUnbrandedComputeWorkloadActivationObservationCandidate,
  projectComputeWorkloadBrowserEnvFromHistoricalObservation,
  projectComputeWorkloadBrowserEnvFromPrebuildObservation,
} from "./compute-workload-activation-observation-core.mjs";

const computeReplayPin = (pair) => `sha256:${pair.repeat(32)}`;
const computeReplayWord = (pair) => `0x${pair.repeat(32)}`;

function computeReplayAuthorityBinding(fixture) {
  return {
    capability_endpoint:
      "https://compute.release.wikigen.me/compute/workload-encryption-contract",
    historical_transcript_file_set_sha256:
      fixture.evidenceSet.historical_transcript_file_set_sha256,
    seven_cvm_launch_completion_receipt_sha256: computeReplayPin("e1"),
    seven_cvm_verified_evidence_set_sha256:
      phalaSevenCvmVerifiedEvidenceSetSha256(fixture.evidenceSet),
    pre_ceremony_runtime_authority_sha256: computeReplayPin("e2"),
    post_measurement_activation_plan_sha256: computeReplayPin("e3"),
    post_measurement_activation_execution_receipt_sha256: computeReplayPin("e4"),
    ceremony_authorization_sha256: computeReplayPin("e5"),
    initial_activation_evidence_lease_expires_at:
      fixture.evidenceSet.minimum_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      fixture.computeWorkloadActivationEvidence
        .recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at: Math.min(
      fixture.evidenceSet.minimum_activation_evidence_lease_expires_at,
      fixture.computeWorkloadActivationEvidence
        .recipient_evidence_lease_expires_at,
    ),
    ingress_policy: {
      max_verdict_age_seconds: 120,
      revoked_quote_hashes: [computeReplayWord("01"), computeReplayWord("02")],
    },
  };
}

function independentComputeReplayExpectations(fixture) {
  const release = fixture.releaseAuthority;
  const activation = fixture.computeWorkloadActivationEvidence;
  const binding = computeReplayAuthorityBinding(fixture);
  const main = release.descriptors.find((entry) => entry.domain === "main_runtime_cvm");
  const qvl = release.descriptors.find((entry) => entry.domain === "compute_workload_qvl_cvm");
  return {
    ceremonyAuthorizationSha256: binding.ceremony_authorization_sha256,
    ceremonyNonce: release.ceremony_nonce,
    computeVaultAddress: activation.compute_vault_address,
    computeVaultRuntimeCodeHash: activation.compute_vault_runtime_code_hash,
    computeWorkloadQvlAppId: qvl.app_id,
    computeWorkloadQvlComposeHash: qvl.compose_hash,
    computeWorkloadQvlCvmId: qvl.cvm_id,
    computeWorkloadQvlIdentityEvidenceSha256: activation.qvl_identity_evidence_sha256,
    computeWorkloadQvlMeasurementPolicySha256: activation.measurement_policy_sha256,
    computeWorkloadQvlOsImageHash: qvl.os_image_hash,
    computeWorkloadQvlReleasePolicySha256: activation.qvl_release_policy_sha256,
    computeWorkloadQvlVerifierAddress: activation.qvl_verdict_verifier_address,
    deploymentIntentSha256: release.deployment_intent_sha256,
    freshContractDeploymentReceiptSha256: release.contracts.fresh_contract_deployment_receipt_sha256,
    historicalTranscriptFileSetSha256: binding.historical_transcript_file_set_sha256,
    mainRuntimeAppId: main.app_id,
    mainRuntimeComposeHash: main.compose_hash,
    mainRuntimeCvmId: main.cvm_id,
    mainRuntimeDescriptorSha256: activation.descriptor_sha256,
    mainRuntimeEvidenceSha256: activation.main_runtime_evidence_sha256,
    mainRuntimeOsImageHash: main.os_image_hash,
    mainRuntimePostureReceiptSha256: activation.posture_receipt_sha256,
    mainRuntimeTeeIdentity: activation.main_runtime_signer_address,
    nonliveBootstrapAuthorizationReceiptSha256: release.bootstrap_authorization_receipt_sha256,
    postMeasurementActivationExecutionReceiptSha256: binding.post_measurement_activation_execution_receipt_sha256,
    postMeasurementActivationPlanSha256: binding.post_measurement_activation_plan_sha256,
    preCeremonyRuntimeAuthoritySha256: binding.pre_ceremony_runtime_authority_sha256,
    qvlMeasurementPolicySetSha256: release.qvl_measurement_policy_set_sha256,
    releaseSha: release.release_sha,
    releaseVerificationAuthoritySha256: activation.release_authority_sha256,
    sevenCvmLaunchCompletionReceiptSha256: binding.seven_cvm_launch_completion_receipt_sha256,
    sevenCvmVerifiedEvidenceSetSha256: binding.seven_cvm_verified_evidence_set_sha256,
    initialActivationEvidenceLeaseExpiresAt: binding.initial_activation_evidence_lease_expires_at,
    recipientEvidenceLeaseExpiresAt: binding.recipient_evidence_lease_expires_at,
    terminalEvidenceLeaseExpiresAt: binding.terminal_evidence_lease_expires_at,
  };
}

// This is a focused projection fixture, not a complete live-chain candidate.
// Expected roots come from independent synthetic release/activation artifacts;
// the recipient QVL verdict contains a real verifiable test signature.
async function computeBrowserReplayFixture() {
  const source = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  const binding = computeReplayAuthorityBinding(source);
  const expected = independentComputeReplayExpectations(source);
  const observation = createUnbrandedComputeWorkloadActivationObservationCandidate({
    activationVerification: source.computeWorkloadActivationEvidence,
    releaseVerificationAuthority: source.releaseAuthority,
    authorityBinding: binding,
  });
  const prebuild = assertPrebuildVerifiedComputeWorkloadActivationObservation({
    persistedObservation: observation, expected, completedAtMs: source.now * 1_000,
  });
  const historical = assertHistoricallyVerifiedComputeWorkloadActivationObservation({
    persistedObservation: observation, expected, authorizedAtMs: source.now * 1_000,
  });
  const candidate = {
    release_sha: expected.releaseSha,
    deployment_intent_sha256: expected.deploymentIntentSha256,
    requested_features: { compute_workload_upload: true },
    cvm: {
      delegate_url: "https://compute.release.wikigen.me",
      app_id: expected.mainRuntimeAppId,
      cvm_id: expected.mainRuntimeCvmId,
      compose_hash: expected.mainRuntimeComposeHash,
      os_image_hash: expected.mainRuntimeOsImageHash,
      tee_identity: expected.mainRuntimeTeeIdentity,
      compute_workload_ingress: structuredClone(binding.ingress_policy),
    },
    trust_domains: { compute_workload_qvl: { identity: {
      verifier_address: expected.computeWorkloadQvlVerifierAddress,
      release_policy_hash: `0x${expected.computeWorkloadQvlReleasePolicySha256.slice(7)}`,
    } } },
    attestations: { artifact: { verdict: {
      release_authority_sha256: expected.releaseVerificationAuthoritySha256,
      ceremony_nonce: expected.ceremonyNonce,
    } } },
    contracts: { compute_credit_vault: {
      address: expected.computeVaultAddress,
      runtime_code_hash: expected.computeVaultRuntimeCodeHash,
    } },
  };
  return { candidate, observation, prebuild, historical };
}

test("Compute browser projection unwraps stage-correct signed synthetic O evidence for prebuild and live", async () => {
  const { candidate, prebuild, historical } = await computeBrowserReplayFixture();
  const prebuildEnv = __test.projectComputeWorkloadReleaseBrowserEnv({
    candidate, candidateAuthorityStage: "prebuild",
    prebuildComputeWorkloadActivationObservationReplay: structuredClone(prebuild),
  });
  const liveEnv = __test.projectComputeWorkloadReleaseBrowserEnv({
    candidate, candidateAuthorityStage: "live",
    historicalComputeWorkloadActivationObservation: structuredClone(historical),
  });
  assert.deepEqual(prebuildEnv, projectComputeWorkloadBrowserEnvFromPrebuildObservation(prebuild));
  assert.deepEqual(liveEnv, projectComputeWorkloadBrowserEnvFromHistoricalObservation(historical));
  assert.deepEqual(prebuildEnv, liveEnv);
  assert.deepEqual(Object.keys(prebuildEnv).sort(), [...COMPUTE_WORKLOAD_BROWSER_ENV_KEYS].sort());
  assert.equal(prebuildEnv.VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD, "true");
  assert.equal(prebuildEnv.VITE_COMPUTE_WORKLOAD_APP_ID, candidate.cvm.app_id);
  assert.equal(prebuildEnv.VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS, candidate.contracts.compute_credit_vault.address);
  assert.equal(prebuild.signed_c_authorization_verified, false);
  assert.equal(prebuild.production_brand_minted, false);
  assert.equal(historical.production_brand_minted, false);
});

test("Compute browser projection rejects raw, both, missing, wrong-slot, and wrong-context O replays", async () => {
  const { candidate, observation, prebuild, historical } = await computeBrowserReplayFixture();
  for (const stage of ["prebuild", "live"]) {
    const correctField = stage === "prebuild"
      ? "prebuildComputeWorkloadActivationObservationReplay"
      : "historicalComputeWorkloadActivationObservation";
    const wrongField = stage === "prebuild"
      ? "historicalComputeWorkloadActivationObservation"
      : "prebuildComputeWorkloadActivationObservationReplay";
    const correctReplay = stage === "prebuild" ? prebuild : historical;
    const wrongReplay = stage === "prebuild" ? historical : prebuild;
    for (const supplied of [
      {},
      { [correctField]: null },
      { [correctField]: {} },
      { [correctField]: observation },
      { [correctField]: wrongReplay },
      { [wrongField]: correctReplay },
      { [correctField]: correctReplay, [wrongField]: wrongReplay },
    ]) {
      assert.throws(() => __test.projectComputeWorkloadReleaseBrowserEnv({
        candidate, candidateAuthorityStage: stage, ...supplied,
      }));
    }
  }
  assert.throws(() => __test.projectComputeWorkloadReleaseBrowserEnv({
    candidate, candidateAuthorityStage: "unknown",
    prebuildComputeWorkloadActivationObservationReplay: prebuild,
  }));
});

test("Compute browser projection preserves every reviewed candidate binding after unwrapping O", async () => {
  const { candidate, prebuild, historical } = await computeBrowserReplayFixture();
  const mutations = [
    (value) => { value.release_sha = "f".repeat(40); },
    (value) => { value.deployment_intent_sha256 = computeReplayPin("ff"); },
    (value) => { value.cvm.delegate_url = "https://substitute.example"; },
    (value) => { value.cvm.app_id = "f".repeat(40); },
    (value) => { value.cvm.cvm_id = "cvm-substitute"; },
    (value) => { value.cvm.compose_hash = "f".repeat(64); },
    (value) => { value.cvm.os_image_hash = "f".repeat(64); },
    (value) => { value.cvm.tee_identity = "0x" + "f".repeat(40); },
    (value) => { value.trust_domains.compute_workload_qvl.identity.verifier_address = "0x" + "f".repeat(40); },
    (value) => { value.trust_domains.compute_workload_qvl.identity.release_policy_hash = computeReplayWord("ff"); },
    (value) => { value.attestations.artifact.verdict.release_authority_sha256 = computeReplayPin("ff"); },
    (value) => { value.attestations.artifact.verdict.ceremony_nonce = computeReplayWord("ff"); },
    (value) => { value.contracts.compute_credit_vault.address = "0x" + "f".repeat(40); },
    (value) => { value.contracts.compute_credit_vault.runtime_code_hash = computeReplayWord("ff"); },
    (value) => { value.cvm.compute_workload_ingress.max_verdict_age_seconds += 1; },
    (value) => { value.cvm.compute_workload_ingress.revoked_quote_hashes = []; },
  ];
  for (const candidateAuthorityStage of ["prebuild", "live"]) {
    for (const mutate of mutations) {
      const changed = structuredClone(candidate);
      mutate(changed);
      assert.throws(() => __test.projectComputeWorkloadReleaseBrowserEnv({
        candidate: changed, candidateAuthorityStage,
        ...(candidateAuthorityStage === "prebuild"
          ? { prebuildComputeWorkloadActivationObservationReplay: prebuild }
          : { historicalComputeWorkloadActivationObservation: historical }),
      }), /replayed compute-workload activation observation drifted/);
    }
  }
  const disabled = structuredClone(candidate);
  disabled.requested_features.compute_workload_upload = false;
  const env = __test.projectComputeWorkloadReleaseBrowserEnv({
    candidate: disabled, candidateAuthorityStage: "prebuild",
  });
  assert.equal(env.VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD, "false");
  assert.equal(env.VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON, "[]");
  assert.equal(env.VITE_COMPUTE_WORKLOAD_APP_ID, "");
});
