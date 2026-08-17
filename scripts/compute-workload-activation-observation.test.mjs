import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientSourceActivationSha256,
  phalaSevenCvmVerifiedEvidenceSetSha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  syntheticPhalaSevenCvmVerifierEvidenceFixture,
} from "./phala-seven-cvm-verifier-evidence.fixture.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaArenaWorkerPresenceActivationProofSha256,
  phalaCombinedArenaComputeActivationVerificationSha256,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  assertActivationExecutionReceiptMatchesComputeWorkloadObservation,
} from "./release-authority-stages.mjs";
import {
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_SCHEMA,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_TRUTH,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_CLI_FLAG,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_DOMAIN,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_STATUS,
  COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_TRUTH,
  COMPUTE_WORKLOAD_BROWSER_ENV_KEYS,
  __test,
  assertHistoricallyVerifiedComputeWorkloadActivationObservation,
  assertPersistedComputeWorkloadActivationObservation,
  assertVerifiedComputeWorkloadActivationObservation,
  canonicalComputeWorkloadActivationObservationText,
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  createComputeWorkloadActivationObservation,
  normalizeComputeWorkloadActivationObservation,
  normalizeComputeWorkloadActivationObservationHistoricalReplay,
  normalizeComputeWorkloadBrowserBinding,
  projectComputeWorkloadBrowserBindingFromHistoricalObservation,
  projectComputeWorkloadBrowserBindingFromObservation,
  projectComputeWorkloadBrowserEnvFromHistoricalObservation,
  projectComputeWorkloadBrowserEnvFromObservation,
} from "./compute-workload-activation-observation.mjs";
import {
  verifyIndependentEip191PersonalSignature,
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";

const pin = (pair) => `sha256:${pair.repeat(32)}`;
const word = (pair) => `0x${pair.repeat(32)}`;

function authorityBinding(fixture) {
  return {
    capability_endpoint:
      "https://compute.release.wikigen.me/compute/workload-encryption-contract",
    historical_transcript_file_set_sha256:
      fixture.evidenceSet.historical_transcript_file_set_sha256,
    seven_cvm_launch_completion_receipt_sha256: pin("e1"),
    seven_cvm_verified_evidence_set_sha256:
      phalaSevenCvmVerifiedEvidenceSetSha256(fixture.evidenceSet),
    pre_ceremony_runtime_authority_sha256: pin("e2"),
    post_measurement_activation_plan_sha256: pin("e3"),
    post_measurement_activation_execution_receipt_sha256: pin("e4"),
    ceremony_authorization_sha256: pin("e5"),
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
      revoked_quote_hashes: [word("01"), word("02")],
    },
  };
}

function activationExecutionReceiptForObservation(observation) {
  const verifiedAt = observation.verification.verified_at;
  const authenticatedAt = observation.verification.authenticated_at;
  const instant = (seconds) => new Date(seconds * 1_000)
    .toISOString().replace(".000Z", "Z");
  const profileActivation = {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  };
  const arenaWorkerPresence = {
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: pin("e7"),
    challenge_id: "dnaseq-variant-qc-safe-ir",
    challenge_version: "1.0.0",
    response_sha256: pin("e8"),
    release_binding_sha256: pin("e9"),
    heartbeat_observed_at: authenticatedAt,
    verified_at: authenticatedAt,
  };
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const computeRecipientActivationSha256 =
    observation.verification.activation_verification_sha256;
  return normalizePhalaPostMeasurementActivationExecutionReceipt({
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: 84_532,
    release_sha: observation.release_sha,
    batch_id: pin("d0"),
    deployment_intent_sha256: observation.lineage.deployment_intent_sha256,
    cvm_launch_intent_sha256: pin("d1"),
    release_verification_authority_sha256:
      observation.lineage.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      observation.lineage.seven_cvm_launch_completion_receipt_sha256,
    seven_cvm_verified_evidence_set_sha256:
      observation.lineage.seven_cvm_verified_evidence_set_sha256,
    phala_recovery_directory_identity_anchor_sha256: pin("d2"),
    pre_ceremony_runtime_authority_sha256:
      observation.lineage.pre_ceremony_runtime_authority_sha256,
    post_measurement_activation_plan_sha256:
      observation.lineage.post_measurement_activation_plan_sha256,
    ceremony_authorization_sha256:
      observation.lineage.ceremony_authorization_sha256,
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: observation.main_runtime.descriptor_sha256,
      app_id: observation.main_runtime.app_id,
      cvm_id: observation.main_runtime.cvm_id,
      compose_hash: observation.main_runtime.compose_hash,
      os_image_hash: observation.main_runtime.os_image_hash,
    },
    profile_activation: profileActivation,
    runtime_commitments_sha256: pin("d3"),
    runtime_commitment_key_names_sha256: pin("d4"),
    allowed_environment_key_names_sha256: pin("d5"),
    allowed_environment_key_count: 2,
    injected_environment_key_names_sha256: pin("d6"),
    injected_environment_key_count: 1,
    private_environment_assembly_receipt_sha256: pin("d7"),
    adapter_identity_sha256: pin("d8"),
    activation_journal_state_sha256: pin("d9"),
    activation_journal_sha256: pin("da"),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch: {
      sdk_action: "updateCvmEnvs",
      call_sequence: 4,
      request_semantics_sha256: pin("db"),
      observation_sha256: pin("dc"),
      response_sha256: pin("dd"),
      body_field_names: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
      attempt_recorded_at: instant(authenticatedAt - 5),
      observed_at: instant(authenticatedAt - 4),
      finalized_readiness: {
        readiness_sha256: pin("de"),
        finalized_block_number: 30_000_000,
        finalized_block_hash: word("d0"),
      },
    },
    restart: {
      sdk_action: "restartCvm",
      call_sequence: 5,
      request_semantics_sha256: pin("df"),
      observation_sha256: pin("e0"),
      response_sha256: pin("e1"),
      force: false,
      attempt_recorded_at: instant(authenticatedAt - 3),
      observed_at: instant(authenticatedAt - 2),
      finalized_readiness: {
        readiness_sha256: pin("e2"),
        finalized_block_number: 30_000_001,
        finalized_block_hash: word("d1"),
      },
    },
    post_restart_evidence: {
      get_cvm_info_call_sequence: 6,
      get_cvm_info_observation_sha256: pin("e3"),
      get_cvm_info_response_sha256: pin("e4"),
      get_cvm_info_observed_at: instant(authenticatedAt - 1),
      get_cvm_attestation_call_sequence: 7,
      get_cvm_attestation_observation_sha256: pin("e5"),
      get_cvm_attestation_response_sha256: pin("e6"),
      get_cvm_attestation_observed_at: instant(authenticatedAt - 1),
      cvm_online: true,
      attestation_error_absent: true,
      tcb_info_present: true,
      app_certificate_quote_present: true,
      pre_injection_attestation_sufficient: false,
    },
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: {
      activation_verification_sha256:
        computeRecipientActivationSha256,
      source_activation_sha256:
        observation.verification.activation_artifact_sha256,
      raw_transcript_sha256: observation.verification.raw_transcript_sha256,
      qvl_verdict_verifier_signature_sha256:
        observation.verification.qvl_verdict_verifier_signature_sha256,
      tdx_quote_sha256: observation.verification.tdx_quote_sha256,
      challenge_id: observation.verification.challenge_id,
      report_data: observation.recipient.report_data,
      recipient_key_id: observation.recipient.recipient_key_id,
      recipient_release_commitment:
        observation.recipient.recipient_release_commitment,
      authenticated_at: authenticatedAt,
      verified_at: verifiedAt,
      verdict_activation_evidence_lease_expires_at:
        observation.verification
          .verdict_activation_evidence_lease_expires_at,
      recipient_evidence_lease_expires_at:
        observation.recipient_evidence_lease_expires_at,
      expires_at: observation.verification.activation_verification_expires_at,
      post_restart_source_activation: true,
    },
    compute_recipient_activation_sha256: computeRecipientActivationSha256,
    combined_activation_verification_sha256:
      phalaCombinedArenaComputeActivationVerificationSha256({
        profileActivation,
        arenaWorkerPresenceSha256,
        computeRecipientActivationSha256,
      }),
    initial_activation_evidence_lease_expires_at:
      observation.initial_activation_evidence_lease_expires_at,
    recipient_evidence_lease_expires_at:
      observation.recipient_evidence_lease_expires_at,
    terminal_evidence_lease_expires_at:
      observation.terminal_evidence_lease_expires_at,
    completed_at: instant(verifiedAt),
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  });
}

async function fixtureAndObservation() {
  const fixture = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  const observation = __test.createSyntheticComputeWorkloadActivationObservation({
    activationVerification: fixture.computeWorkloadActivationEvidence,
    releaseVerificationAuthority: fixture.releaseAuthority,
    authorityBinding: authorityBinding(fixture),
  });
  return { fixture, observation };
}

function historicalExpectations(observation) {
  return {
    ceremonyAuthorizationSha256:
      observation.lineage.ceremony_authorization_sha256,
    ceremonyNonce: observation.lineage.ceremony_nonce,
    computeVaultAddress: observation.compute_vault.address,
    computeVaultRuntimeCodeHash: observation.compute_vault.runtime_code_hash,
    computeWorkloadQvlAppId: observation.compute_workload_qvl.app_id,
    computeWorkloadQvlComposeHash: observation.compute_workload_qvl.compose_hash,
    computeWorkloadQvlCvmId: observation.compute_workload_qvl.cvm_id,
    computeWorkloadQvlIdentityEvidenceSha256:
      observation.compute_workload_qvl.identity_evidence_sha256,
    computeWorkloadQvlMeasurementPolicySha256:
      observation.compute_workload_qvl.measurement_policy_sha256,
    computeWorkloadQvlOsImageHash: observation.compute_workload_qvl.os_image_hash,
    computeWorkloadQvlReleasePolicySha256:
      observation.compute_workload_qvl.release_policy_sha256,
    computeWorkloadQvlVerifierAddress:
      observation.compute_workload_qvl.verifier_address,
    deploymentIntentSha256: observation.lineage.deployment_intent_sha256,
    freshContractDeploymentReceiptSha256:
      observation.lineage.fresh_contract_deployment_receipt_sha256,
    historicalTranscriptFileSetSha256:
      observation.lineage.historical_transcript_file_set_sha256,
    mainRuntimeAppId: observation.main_runtime.app_id,
    mainRuntimeComposeHash: observation.main_runtime.compose_hash,
    mainRuntimeCvmId: observation.main_runtime.cvm_id,
    mainRuntimeDescriptorSha256: observation.main_runtime.descriptor_sha256,
    mainRuntimeEvidenceSha256:
      observation.main_runtime.seven_cvm_domain_evidence_sha256,
    mainRuntimeOsImageHash: observation.main_runtime.os_image_hash,
    mainRuntimePostureReceiptSha256:
      observation.main_runtime.posture_receipt_sha256,
    mainRuntimeTeeIdentity: observation.main_runtime.tee_identity,
    nonliveBootstrapAuthorizationReceiptSha256:
      observation.lineage.nonlive_bootstrap_authorization_receipt_sha256,
    postMeasurementActivationExecutionReceiptSha256:
      observation.lineage.post_measurement_activation_execution_receipt_sha256,
    postMeasurementActivationPlanSha256:
      observation.lineage.post_measurement_activation_plan_sha256,
    preCeremonyRuntimeAuthoritySha256:
      observation.lineage.pre_ceremony_runtime_authority_sha256,
    qvlMeasurementPolicySetSha256:
      observation.lineage.qvl_measurement_policy_set_sha256,
    releaseSha: observation.release_sha,
    releaseVerificationAuthoritySha256:
      observation.lineage.release_verification_authority_sha256,
    sevenCvmLaunchCompletionReceiptSha256:
      observation.lineage.seven_cvm_launch_completion_receipt_sha256,
    sevenCvmVerifiedEvidenceSetSha256:
      observation.lineage.seven_cvm_verified_evidence_set_sha256,
    initialActivationEvidenceLeaseExpiresAt:
      observation.initial_activation_evidence_lease_expires_at,
    recipientEvidenceLeaseExpiresAt:
      observation.recipient_evidence_lease_expires_at,
    terminalEvidenceLeaseExpiresAt:
      observation.terminal_evidence_lease_expires_at,
  };
}

test("O v3 schema, domain, CLI flag, exact lineage, leases, and browser key set are frozen", async () => {
  const { observation } = await fixtureAndObservation();
  assert.equal(
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_DOMAIN,
    "dnai-wikigen/compute-workload-activation-observation/v3\0",
  );
  assert.equal(
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_CLI_FLAG,
    "--compute-workload-activation-observation",
  );
  assert.deepEqual(Object.keys(observation), [
    "schema", "status", "truth_status", "release_sha", "chain_id",
    "capability_endpoint", "lineage", "main_runtime", "compute_workload_qvl",
    "compute_vault", "recipient", "verification", "source_activation",
    "initial_activation_evidence_lease_expires_at",
    "recipient_evidence_lease_expires_at",
    "terminal_evidence_lease_expires_at",
    "ingress_policy", "live_traffic_authorized", "deploy_authorized",
    "raw_quote_persisted", "raw_secret_egress",
  ]);
  assert.deepEqual(Object.keys(observation.lineage), [
    "deployment_intent_sha256", "release_verification_authority_sha256",
    "ceremony_nonce", "qvl_measurement_policy_set_sha256",
    "historical_transcript_file_set_sha256",
    "fresh_contract_deployment_receipt_sha256",
    "nonlive_bootstrap_authorization_receipt_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "seven_cvm_verified_evidence_set_sha256",
    "pre_ceremony_runtime_authority_sha256",
    "post_measurement_activation_plan_sha256",
    "post_measurement_activation_execution_receipt_sha256",
    "ceremony_authorization_sha256",
  ]);
  assert.deepEqual(COMPUTE_WORKLOAD_BROWSER_ENV_KEYS, [
    "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD",
    "VITE_COMPUTE_WORKLOAD_QVL_VERIFIER",
    "VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
    "VITE_COMPUTE_WORKLOAD_COMPOSE_HASH",
    "VITE_COMPUTE_WORKLOAD_APP_ID",
    "VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH",
    "VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER",
    "VITE_COMPUTE_WORKLOAD_CHAIN_ID",
    "VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS",
    "VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH",
    "VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
    "VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS",
    "VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON",
    "VITE_COMPUTE_WORKLOAD_CVM_ID",
    "VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
    "VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
    "VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE",
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256",
    "VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
  ]);
});

test("branded activation proof produces deterministic private lease-bounded O v3", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  assert.equal(observation.schema, COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA);
  assert.equal(observation.status, COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_STATUS);
  assert.equal(observation.truth_status, COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_TRUTH);
  assert.deepEqual(normalizeComputeWorkloadActivationObservation(observation), observation);
  assert.deepEqual(
    observation.source_activation,
    fixture.computeWorkloadActivationEvidence.source_activation,
  );
  assert.equal(
    observation.verification.activation_verification_sha256,
    phalaComputeWorkloadRecipientActivationVerificationSha256(
      fixture.computeWorkloadActivationEvidence,
    ),
  );
  assert.equal(
    observation.verification.activation_artifact_sha256,
    phalaComputeWorkloadRecipientSourceActivationSha256(
      observation.source_activation,
    ),
  );
  assert.equal(observation.live_traffic_authorized, false);
  assert.equal(observation.deploy_authorized, false);
  assert.equal(observation.raw_quote_persisted, false);
  assert.equal(observation.raw_secret_egress, false);
  assert.equal(JSON.stringify(observation).includes("verifier_signature"), true);
  assert.equal(JSON.stringify(observation).includes("encryption_private_key"), false);
  const canonical = canonicalComputeWorkloadActivationObservationText(observation);
  assert.deepEqual(JSON.parse(canonical), observation);
  assert.equal(canonical.endsWith("\n"), true);
  assert.equal(canonical.indexOf('"capability_endpoint"')
    < canonical.indexOf('"chain_id"'), true);
  assert.match(
    computeWorkloadActivationObservationSha256(observation),
    /^sha256:[0-9a-f]{64}$/,
  );
});

test("O exact-binds every recipient-proof field to the embedded activation execution receipt", async () => {
  const { observation } = await fixtureAndObservation();
  const receipt = activationExecutionReceiptForObservation(observation);
  const receiptSha256 = phalaPostMeasurementActivationExecutionReceiptSha256(
    receipt,
  );
  const reboundObservation = structuredClone(observation);
  reboundObservation.lineage
    .post_measurement_activation_execution_receipt_sha256 = receiptSha256;
  assert.equal(
    assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
      activationExecutionReceipt: receipt,
      activationExecutionReceiptSha256: receiptSha256,
      observation: reboundObservation,
    }),
    receiptSha256,
  );

  const recipientDrift = structuredClone(receipt);
  recipientDrift.recipient_activation.recipient_key_id = pin("ff");
  assert.throws(
    () => assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
      activationExecutionReceipt: recipientDrift,
      activationExecutionReceiptSha256:
        phalaPostMeasurementActivationExecutionReceiptSha256(recipientDrift),
      observation: reboundObservation,
    }),
    /O differs from the exact post-measurement activation execution receipt/,
  );
});

test("O v3 deterministically projects exactly twenty ceremony-pinned browser keys", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  const binding = projectComputeWorkloadBrowserBindingFromObservation(
    observation,
    { checkedAt: fixture.now },
  );
  assert.deepEqual(binding, normalizeComputeWorkloadBrowserBinding({
    qvl_verifier: observation.compute_workload_qvl.verifier_address,
    qvl_release_policy_hash:
      `0x${observation.compute_workload_qvl.release_policy_sha256.slice(7)}`,
    compose_hash: `0x${observation.main_runtime.compose_hash}`,
    app_id: observation.main_runtime.app_id,
    os_image_hash: observation.main_runtime.os_image_hash,
    activation_signer_address: observation.recipient.activation_signer_address,
    cvm_id: observation.main_runtime.cvm_id,
    deployment_intent_sha256:
      observation.lineage.deployment_intent_sha256,
    release_authority_sha256:
      observation.lineage.release_verification_authority_sha256,
    ceremony_nonce: observation.lineage.ceremony_nonce,
    measurement_policy_set_sha256:
      observation.lineage.qvl_measurement_policy_set_sha256,
    measurement_policy_sha256:
      observation.compute_workload_qvl.measurement_policy_sha256,
    main_runtime_evidence_sha256:
      observation.main_runtime.seven_cvm_domain_evidence_sha256,
    chain_id: 84_532,
    compute_vault_address: observation.compute_vault.address,
    compute_vault_runtime_code_hash: observation.compute_vault.runtime_code_hash,
    fresh_contract_deployment_receipt_sha256:
      `0x${observation.lineage.fresh_contract_deployment_receipt_sha256.slice(7)}`,
    max_verdict_age_seconds: 120,
    revoked_quote_hashes: [word("01"), word("02")],
  }));
  assert.match(computeWorkloadBrowserBindingSha256(binding), /^sha256:[0-9a-f]{64}$/);
  const env = projectComputeWorkloadBrowserEnvFromObservation(
    observation,
    { checkedAt: fixture.now },
  );
  assert.deepEqual(Object.keys(env), COMPUTE_WORKLOAD_BROWSER_ENV_KEYS);
  assert.equal(Object.keys(env).length, 20);
});

test("persisted O revalidates at signed-C time without refreshing QVL or current time", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  const persisted = structuredClone(observation);
  assert.throws(
    () => projectComputeWorkloadBrowserBindingFromHistoricalObservation(persisted),
    /historical compute-workload O replay result/,
  );
  const historicalReplay =
    assertHistoricallyVerifiedComputeWorkloadActivationObservation({
    persistedObservation: persisted,
    expected: historicalExpectations(observation),
    authorizedAtMs: fixture.now * 1_000,
  });
  assert.equal(
    historicalReplay.schema,
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_SCHEMA,
  );
  assert.equal(
    historicalReplay.truth_status,
    COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_HISTORICAL_REPLAY_TRUTH,
  );
  assert.deepEqual(historicalReplay.observation, observation);
  assert.equal(
    historicalReplay.observation_sha256,
    computeWorkloadActivationObservationSha256(observation),
  );
  assert.equal(
    historicalReplay.signature_message_mode,
    "eip191_personal_sign_raw_bytes32",
  );
  assert.equal(historicalReplay.independent_signature_replay_performed, true);
  assert.equal(historicalReplay.original_pinned_cast_verifier_reexecuted, false);
  assert.equal(historicalReplay.current_clock_consulted, false);
  assert.equal(historicalReplay.freshness_renewed, false);
  assert.equal(historicalReplay.production_brand_minted, false);
  assert.equal(historicalReplay.live_traffic_authorized, false);
  assert.deepEqual(
    normalizeComputeWorkloadActivationObservationHistoricalReplay(
      structuredClone(historicalReplay),
    ),
    historicalReplay,
  );
  assert.deepEqual(
    projectComputeWorkloadBrowserBindingFromHistoricalObservation(
      historicalReplay,
    ),
    projectComputeWorkloadBrowserBindingFromObservation(observation, {
      checkedAt: fixture.now,
    }),
  );
  assert.deepEqual(
    projectComputeWorkloadBrowserEnvFromHistoricalObservation(
      structuredClone(historicalReplay),
    ),
    projectComputeWorkloadBrowserEnvFromObservation(observation, {
      checkedAt: fixture.now,
    }),
  );
  const tamperedReplay = structuredClone(historicalReplay);
  tamperedReplay.observation.recipient.recipient_key_id = pin("fe");
  assert.throws(() => projectComputeWorkloadBrowserBindingFromHistoricalObservation(
    tamperedReplay,
  ));
});

test("historical O replays the real verdict signature as raw bytes32, not UTF-8 hex", async () => {
  const { observation } = await fixtureAndObservation();
  const verdict = observation.source_activation.authenticated_verdict;
  const digest = observation.verification.qvl_verdict_signing_digest;
  assert.equal(verifyIndependentEip191RawDigestSignature({
    address: verdict.verifier_address,
    digest,
    signature: verdict.verifier_signature,
  }).address, verdict.verifier_address);
  assert.throws(() => verifyIndependentEip191PersonalSignature({
    address: verdict.verifier_address,
    message: digest,
    signature: verdict.verifier_signature,
  }), /verification failed/i);
});

test("historical O rejects accessors without execution and custom prototypes", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  let getterExecutions = 0;
  const accessor = structuredClone(observation);
  Object.defineProperty(accessor, "schema", {
    enumerable: true,
    get() {
      getterExecutions += 1;
      return COMPUTE_WORKLOAD_ACTIVATION_OBSERVATION_SCHEMA;
    },
  });
  assert.throws(() => assertHistoricallyVerifiedComputeWorkloadActivationObservation({
    persistedObservation: accessor,
    expected: historicalExpectations(observation),
    authorizedAtMs: fixture.now * 1_000,
  }), /accessors/i);
  assert.equal(getterExecutions, 0);

  const customPrototype = structuredClone(observation);
  Object.setPrototypeOf(customPrototype, { forged: true });
  assert.throws(() => normalizeComputeWorkloadActivationObservation(
    customPrototype,
  ), /custom prototypes/i);
});

test("historical O rejects authority drift, invalid authorization time, and signature drift", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  const base = historicalExpectations(observation);
  for (const mutate of [
    (expected) => { expected.releaseSha = "f1".repeat(20); },
    (expected) => { expected.deploymentIntentSha256 = pin("f2"); },
    (expected) => { expected.mainRuntimeDescriptorSha256 = pin("f3"); },
    (expected) => { expected.computeWorkloadQvlIdentityEvidenceSha256 = pin("f4"); },
    (expected) => { expected.computeVaultRuntimeCodeHash = word("f5"); },
    (expected) => {
      expected.postMeasurementActivationExecutionReceiptSha256 = pin("f6");
    },
    (expected) => { expected.computeWorkloadQvlCvmId = "cvm-qvl-forged"; },
  ]) {
    const expected = structuredClone(base);
    mutate(expected);
    assert.throws(
      () => assertHistoricallyVerifiedComputeWorkloadActivationObservation({
        persistedObservation: structuredClone(observation),
        expected,
        authorizedAtMs: fixture.now * 1_000,
      }),
      /differs from signed-C historical authority/,
    );
  }

  for (const authorizedAtMs of [
    (observation.verification.verified_at - 1) * 1_000,
    observation.verification.verdict_expires_at * 1_000,
  ]) {
    assert.throws(
      () => assertHistoricallyVerifiedComputeWorkloadActivationObservation({
        persistedObservation: structuredClone(observation),
        expected: base,
        authorizedAtMs,
      }),
      /differs from signed-C historical authority/,
    );
  }

  const signatureDrift = structuredClone(observation);
  signatureDrift.source_activation.authenticated_verdict.verifier_signature =
    `0x${"01".repeat(64)}1b`;
  assert.throws(
    () => assertHistoricallyVerifiedComputeWorkloadActivationObservation({
      persistedObservation: signatureDrift,
      expected: base,
      authorizedAtMs: fixture.now * 1_000,
    }),
  );
});

test("parsed/cloned O, source activation, and full verification cannot acquire brands", async () => {
  const { fixture, observation } = await fixtureAndObservation();
  const parsed = JSON.parse(JSON.stringify(observation));
  assert.throws(
    () => assertVerifiedComputeWorkloadActivationObservation(parsed, {
      checkedAt: fixture.now,
    }),
    /not reconstructed from branded production evidence/,
  );
  await assert.rejects(
    createComputeWorkloadActivationObservation({
      activationExecutionReceipt: structuredClone(observation),
      capabilityEndpoint:
        "https://compute.release.wikigen.me/compute/workload-encryption-contract",
      ingressPolicy: authorityBinding(fixture).ingress_policy,
    }),
    /activation execution receipt|production activation receipt|truth boundary/,
  );
  await assert.rejects(
    createComputeWorkloadActivationObservation({
      activationExecutionReceipt: structuredClone(observation),
      capabilityEndpoint:
        "https://compute.release.wikigen.me/compute/workload-encryption-contract",
      ingressPolicy: authorityBinding(fixture).ingress_policy,
      callerSelectedReleaseAuthority: fixture.releaseAuthority,
    }),
    /constructor options.*frozen fields/,
  );
  assert.deepEqual(assertPersistedComputeWorkloadActivationObservation({
    persistedObservation: parsed,
    reconstructedObservation: observation,
    checkedAt: fixture.now,
  }), observation);
  assert.throws(() => assertVerifiedComputeWorkloadActivationObservation(
    observation,
    { checkedAt: observation.verification.verdict_expires_at },
  ), /not current/);
});

test("O rejects v1/downgrade, extras, escalation, and every source lineage group drift", async () => {
  const { observation } = await fixtureAndObservation();
  const cases = [
    (copy) => { copy.schema = "dnai.compute-workload-activation-observation.v1"; },
    (copy) => { copy.source_activation.schema = "dnai.compute.workload-recipient-activation.v1"; },
    (copy) => { copy.source_activation.authenticated_verdict.schema = "dnai.independent-tdx-verdict.v2"; },
    (copy) => { copy.source_activation.unreviewed = true; },
    (copy) => { copy.live_traffic_authorized = true; },
    (copy) => { copy.deploy_authorized = true; },
    (copy) => { copy.raw_secret_egress = true; },
    (copy) => { copy.lineage.deployment_intent_sha256 = pin("f1"); },
    (copy) => { copy.lineage.release_verification_authority_sha256 = pin("f2"); },
    (copy) => { copy.lineage.ceremony_nonce = word("f3"); },
    (copy) => { copy.lineage.qvl_measurement_policy_set_sha256 = pin("f4"); },
    (copy) => { copy.main_runtime.cvm_id = "other-main-cvm"; },
    (copy) => { copy.main_runtime.seven_cvm_domain_evidence_sha256 = pin("f5"); },
    (copy) => { copy.compute_workload_qvl.measurement_policy_sha256 = pin("f6"); },
    (copy) => { copy.compute_workload_qvl.verifier_address = `0x${"12".repeat(20)}`; },
    (copy) => { copy.compute_vault.address = `0x${"13".repeat(20)}`; },
    (copy) => { copy.recipient.recipient_key_id = pin("f7"); },
    (copy) => { copy.recipient.report_data = word("f8"); },
    (copy) => { copy.recipient.recipient_release_commitment = pin("f9"); },
    (copy) => { copy.verification.activation_artifact_sha256 = pin("fa"); },
    (copy) => { copy.verification.challenge_id = word("fb"); },
    (copy) => { copy.verification.qvl_verdict_signing_digest = word("fc"); },
    (copy) => { copy.verification.authenticated_at -= 1; },
    (copy) => { copy.ingress_policy.revoked_quote_hashes = [
      `0x${copy.verification.tdx_quote_sha256.slice(7)}`,
    ]; },
  ];
  for (const mutate of cases) {
    const copy = structuredClone(observation);
    mutate(copy);
    assert.throws(() => normalizeComputeWorkloadActivationObservation(copy));
  }
});

test("O producer rejects caller-controlled omissions, extras, and lineage collapse", async () => {
  const fixture = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  const base = authorityBinding(fixture);
  for (const mutate of [
    (copy) => { delete copy.ceremony_authorization_sha256; },
    (copy) => { copy.unknown = pin("ee"); },
    (copy) => { copy.capability_endpoint += "?redirect=1"; },
    (copy) => {
      copy.post_measurement_activation_execution_receipt_sha256 =
        copy.post_measurement_activation_plan_sha256;
    },
  ]) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.throws(() => __test.createSyntheticComputeWorkloadActivationObservation({
      activationVerification: fixture.computeWorkloadActivationEvidence,
      releaseVerificationAuthority: fixture.releaseAuthority,
      authorityBinding: copy,
    }));
  }
});

test("two-phase O preflight is opaque, policy-gated, and receipt-drift resistant", async () => {
  const fixture = await syntheticPhalaSevenCvmVerifierEvidenceFixture();
  const binding = authorityBinding(fixture);
  const observationAuthoritySha256 = pin("ac");
  const preflightToken =
    __test.prepareSyntheticComputeWorkloadActivationObservation({
      activationVerification: fixture.computeWorkloadActivationEvidence,
      releaseVerificationAuthority: fixture.releaseAuthority,
      authorityBinding: binding,
      observationAuthoritySha256,
    });
  assert.deepEqual(Object.keys(preflightToken), []);
  assert.equal(Object.isFrozen(preflightToken), true);
  assert.throws(
    () => __test.finalizeSyntheticComputeWorkloadActivationObservation({
      observationAuthoritySha256,
      preflightToken: structuredClone(preflightToken),
      receiptSha256:
        binding.post_measurement_activation_execution_receipt_sha256,
    }),
    /opaque locally prepared/,
  );
  assert.throws(
    () => __test.finalizeSyntheticComputeWorkloadActivationObservation({
      observationAuthoritySha256,
      preflightToken,
      receiptSha256: pin("ff"),
    }),
    /final activation receipt or reviewed observation authority differs/,
  );
  assert.throws(
    () => __test.finalizeSyntheticComputeWorkloadActivationObservation({
      observationAuthoritySha256: pin("ad"),
      preflightToken,
      receiptSha256:
        binding.post_measurement_activation_execution_receipt_sha256,
    }),
    /final activation receipt or reviewed observation authority differs/,
  );
  const observation =
    __test.finalizeSyntheticComputeWorkloadActivationObservation({
      observationAuthoritySha256,
      preflightToken,
      receiptSha256:
        binding.post_measurement_activation_execution_receipt_sha256,
    });
  assert.equal(
    assertVerifiedComputeWorkloadActivationObservation(observation, {
      checkedAt: fixture.now,
    }),
    observation,
  );
  assert.throws(
    () => assertVerifiedComputeWorkloadActivationObservation(observation, {
      checkedAt: observation.verification.verdict_expires_at,
    }),
    /not current/,
  );

  const invalidPolicy = structuredClone(binding);
  invalidPolicy.ingress_policy.max_verdict_age_seconds = 0;
  assert.throws(
    () => __test.prepareSyntheticComputeWorkloadActivationObservation({
      activationVerification: fixture.computeWorkloadActivationEvidence,
      releaseVerificationAuthority: fixture.releaseAuthority,
      authorityBinding: invalidPolicy,
    }),
    /maximum verdict age/,
  );
  const revokedQuote = structuredClone(binding);
  revokedQuote.ingress_policy.revoked_quote_hashes = [
    `0x${fixture.computeWorkloadActivationEvidence.tdx_quote_sha256.slice(7)}`,
  ];
  assert.throws(
    () => __test.prepareSyntheticComputeWorkloadActivationObservation({
      activationVerification: fixture.computeWorkloadActivationEvidence,
      releaseVerificationAuthority: fixture.releaseAuthority,
      authorityBinding: revokedQuote,
    }),
    /quote is revoked/,
  );
});

test("public finalized-receipt O construction composes the safe two-phase path", () => {
  const source = fs.readFileSync(
    new URL("./compute-workload-activation-observation.mjs", import.meta.url),
    "utf8",
  );
  assert.match(
    source,
    /\|\| sourceActivationSha256\s*\n\s*!== receipt\.recipient_activation\.source_activation_sha256/,
  );
  assert.doesNotMatch(
    source,
    /\|\| sourceActivationSha256\s*\n\s*\|\| sourceActivationSha256/,
  );
  const publicCreatorStart = source.indexOf(
    "export async function createComputeWorkloadActivationObservation",
  );
  const publicCreatorEnd = source.indexOf(
    "function isExactNodeTestEntrypoint",
    publicCreatorStart,
  );
  const publicCreator = source.slice(publicCreatorStart, publicCreatorEnd);
  assert.match(publicCreator, /prepareObservationCandidate/);
  assert.match(
    publicCreator,
    /finalizeProductionComputeWorkloadActivationObservation/,
  );
});
