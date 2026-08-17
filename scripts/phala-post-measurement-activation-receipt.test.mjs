import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
  PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
  PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_FINALIZE_FIELDS,
  PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_PREPARE_FIELDS,
  PHALA_POST_MEASUREMENT_PRIVATE_ASSEMBLY_RECEIPT_DOMAIN,
  PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
  PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
  PHALA_ARENA_SAFE_IR_RUNTIME_POLICY_COMMITMENT,
  PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS,
  PHALA_ARENA_WORKER_LIVE_CAPABILITY_WARNING,
  canonicalPhalaPostMeasurementActivationExecutionReceiptText,
  finalizeProductionPhalaPostMeasurementActivationExecutionReceipt,
  normalizePhalaPostMeasurementActivationExecutionReceipt,
  phalaArenaWorkerPresenceActivationProofSha256,
  phalaArenaWorkerPresenceEndpointCommitmentSha256,
  phalaArenaWorkerHeartbeatBindingSha256,
  phalaArenaWorkerReleaseBindingSha256,
  phalaCombinedArenaComputeActivationVerificationSha256,
  phalaPostMeasurementActivationExecutionReceiptSha256,
  phalaPrivatePostMeasurementAssemblyReceiptSha256,
  phalaPostMeasurementRuntimeCommitmentsSha256,
  prepareProductionPhalaPostMeasurementActivationExecutionReceipt,
  readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies,
  __test,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  normalizePhalaPostMeasurementActivationExecutionReceipt as
    normalizePhalaPostMeasurementActivationExecutionReceiptCore,
  phalaPostMeasurementActivationExecutionReceiptSha256 as
    phalaPostMeasurementActivationExecutionReceiptCoreSha256,
  phalaPostMeasurementRuntimeCommitmentsSha256 as
    phalaPostMeasurementRuntimeCommitmentsCoreSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE,
} from "./phala-post-measurement-activation.mjs";
import {
  acquirePhalaPostMeasurementActivationLock,
  createInitialPhalaPostMeasurementActivationState,
  persistPhalaPostMeasurementActivationJournal,
  phalaPostMeasurementActivationJournalSha256,
  phalaPostMeasurementActivationStateSha256,
  projectPhalaPostMeasurementActivationJournal,
  releasePhalaPostMeasurementActivationLock,
  transitionPhalaPostMeasurementActivationState,
} from "./phala-post-measurement-activation-journal.mjs";

const sha = (digit) => `sha256:${digit.repeat(64)}`;
const bytes32 = (digit) => `0x${digit.repeat(64)}`;

function journalObservation(method, callSequence, digit, observedAt) {
  return {
    method,
    call_sequence: callSequence,
    observation_sha256: sha(digit),
    request_semantics_sha256: sha(digit),
    observed_at: observedAt,
  };
}

function completedActivationStates() {
  let state = createInitialPhalaPostMeasurementActivationState({
    batchId: sha("1"),
    releaseSha: "a".repeat(40),
    activationPlanSha256: sha("2"),
    preCeremonyRuntimeAuthoritySha256: sha("3"),
    ceremonyAuthorizationSha256: sha("4"),
    target: {
      domain: "main_runtime_cvm",
      app_id: "b".repeat(40),
      cvm_id: "cvm-main-0001",
    },
    allowedEnvironmentKeyNamesSha256: sha("5"),
    injectedEnvironmentKeyNamesSha256: sha("6"),
    adapterIdentitySha256: sha("7"),
    assemblyReceiptSha256: sha("8"),
  });
  const states = [state];
  const advance = (event) => {
    state = transitionPhalaPostMeasurementActivationState(state, event);
    states.push(state);
  };
  advance({
    type: "pre_patch_reads_observed",
    observations: [
      journalObservation("getCurrentUser", 1, "9", "2026-07-21T12:00:00Z"),
      journalObservation(
        "getAppEnvEncryptPubKey", 2, "a", "2026-07-21T12:00:01Z",
      ),
      journalObservation(
        "getAppEnvEncryptPubKey", 3, "b", "2026-07-21T12:00:02Z",
      ),
    ],
  });
  advance({
    type: "mutation_attempt_recorded",
    action: "updateCvmEnvs",
    requestSemanticsSha256: sha("c"),
    recordedAt: "2026-07-21T12:00:03Z",
  });
  advance({
    type: "mutation_observed",
    action: "updateCvmEnvs",
    observation: {
      ...journalObservation(
        "updateCvmEnvs", 4, "d", "2026-07-21T12:00:04Z",
      ),
      request_semantics_sha256: sha("c"),
    },
  });
  advance({
    type: "mutation_attempt_recorded",
    action: "restartCvm",
    requestSemanticsSha256: sha("e"),
    recordedAt: "2026-07-21T12:00:05Z",
  });
  advance({
    type: "mutation_observed",
    action: "restartCvm",
    observation: {
      ...journalObservation("restartCvm", 5, "f", "2026-07-21T12:00:06Z"),
      request_semantics_sha256: sha("e"),
    },
  });
  advance({
    type: "post_restart_authenticated_phala_attestation_observation_verified",
    observations: [
      journalObservation("getCvmInfo", 6, "1", "2026-07-21T12:00:07Z"),
      journalObservation(
        "getCvmAttestation", 7, "2", "2026-07-21T12:00:08Z",
      ),
    ],
  });
  advance({
    type: "arena_worker_activation_verified",
    arenaWorkerPresenceSha256: sha("3"),
    verifiedAt: "2026-07-21T12:00:09Z",
  });
  advance({
    type: "compute_recipient_activation_verified",
    computeRecipientActivationSha256: sha("4"),
    verifiedAt: "2026-07-21T12:00:10Z",
  });
  advance({
    type: "completed",
    completedAt: "2026-07-21T12:00:10Z",
  });
  return states;
}

function receiptPreflightInput(arenaWorkerPresence) {
  return Object.fromEntries(
    PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_PREPARE_FIELDS.map((field) => [
      field,
      field === "arenaWorkerPresence" ? arenaWorkerPresence : undefined,
    ]),
  );
}

function receiptFixture() {
  const arenaWorkerPresence = {
    schema: PHALA_ARENA_WORKER_PRESENCE_ACTIVATION_PROOF_SCHEMA,
    heartbeat_schema: PHALA_ARENA_WORKER_HEARTBEAT_SCHEMA,
    evidence_classification:
      PHALA_ARENA_WORKER_PRESENCE_EVIDENCE_CLASSIFICATION,
    endpoint_commitment_sha256: sha("7"),
    challenge_id: "dnaseq-variant-qc-safe-ir",
    challenge_version: "1.0.0",
    response_sha256: sha("8"),
    release_binding_sha256: sha("9"),
    heartbeat_observed_at: Date.parse("2026-07-21T12:00:09Z") / 1_000,
    verified_at: Date.parse("2026-07-21T12:00:10Z") / 1_000,
  };
  const arenaWorkerPresenceSha256 =
    phalaArenaWorkerPresenceActivationProofSha256(arenaWorkerPresence);
  const profileActivation = {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  };
  const computeRecipientActivationSha256 = sha("f");
  return {
    schema: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_SCHEMA,
    status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_STATUS,
    truth_status: PHALA_POST_MEASUREMENT_ACTIVATION_EXECUTION_RECEIPT_TRUTH,
    chain_id: 84_532,
    release_sha: "a".repeat(40),
    batch_id: sha("1"),
    deployment_intent_sha256: sha("2"),
    cvm_launch_intent_sha256: sha("3"),
    release_verification_authority_sha256: sha("4"),
    seven_cvm_launch_completion_receipt_sha256: sha("5"),
    seven_cvm_verified_evidence_set_sha256:
      `sha256:${"10".repeat(32)}`,
    phala_recovery_directory_identity_anchor_sha256:
      `sha256:${"01".repeat(32)}`,
    pre_ceremony_runtime_authority_sha256: sha("6"),
    post_measurement_activation_plan_sha256: sha("7"),
    ceremony_authorization_sha256: sha("8"),
    target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: sha("9"),
      app_id: "b".repeat(40),
      cvm_id: "cvm-main-0001",
      compose_hash: "c".repeat(64),
      os_image_hash: "d".repeat(64),
    },
    profile_activation: profileActivation,
    runtime_commitments_sha256: sha("a"),
    runtime_commitment_key_names_sha256: sha("b"),
    allowed_environment_key_names_sha256: sha("c"),
    allowed_environment_key_count: 79,
    injected_environment_key_names_sha256: sha("d"),
    injected_environment_key_count: 78,
    private_environment_assembly_receipt_sha256: sha("e"),
    adapter_identity_sha256: sha("f"),
    activation_journal_state_sha256: sha("1"),
    activation_journal_sha256: sha("2"),
    mutation_sequence: [...PHALA_POST_MEASUREMENT_ACTIVATION_MUTATION_SEQUENCE],
    patch: {
      sdk_action: "updateCvmEnvs",
      call_sequence: 4,
      request_semantics_sha256: sha("3"),
      observation_sha256: sha("4"),
      response_sha256: sha("5"),
      body_field_names: ["encrypted_env"],
      encrypted_environment_only: true,
      allowed_environment_keys_mutated: false,
      attempt_recorded_at: "2026-07-21T12:00:03Z",
      observed_at: "2026-07-21T12:00:04Z",
      finalized_readiness: {
        readiness_sha256: sha("6"),
        finalized_block_number: 30_000_000,
        finalized_block_hash: bytes32("1"),
      },
    },
    restart: {
      sdk_action: "restartCvm",
      call_sequence: 5,
      request_semantics_sha256: sha("7"),
      observation_sha256: sha("8"),
      response_sha256: sha("9"),
      force: false,
      attempt_recorded_at: "2026-07-21T12:00:05Z",
      observed_at: "2026-07-21T12:00:06Z",
      finalized_readiness: {
        readiness_sha256: sha("a"),
        finalized_block_number: 30_000_001,
        finalized_block_hash: bytes32("2"),
      },
    },
    post_restart_evidence: {
      get_cvm_info_call_sequence: 6,
      get_cvm_info_observation_sha256: sha("b"),
      get_cvm_info_response_sha256: sha("c"),
      get_cvm_info_observed_at: "2026-07-21T12:00:07Z",
      get_cvm_attestation_call_sequence: 7,
      get_cvm_attestation_observation_sha256: sha("d"),
      get_cvm_attestation_response_sha256: sha("e"),
      get_cvm_attestation_observed_at: "2026-07-21T12:00:08Z",
      cvm_online: true,
      attestation_error_absent: true,
      tcb_info_present: true,
      app_certificate_quote_present: true,
      pre_injection_attestation_sufficient: false,
    },
    arena_worker_presence: arenaWorkerPresence,
    arena_worker_presence_sha256: arenaWorkerPresenceSha256,
    recipient_activation: {
      activation_verification_sha256: computeRecipientActivationSha256,
      source_activation_sha256: sha("1"),
      raw_transcript_sha256: sha("2"),
      qvl_verdict_verifier_signature_sha256: sha("3"),
      tdx_quote_sha256: sha("4"),
      challenge_id: bytes32("3"),
      report_data: bytes32("4"),
      recipient_key_id: sha("5"),
      recipient_release_commitment: sha("6"),
      authenticated_at: Date.parse("2026-07-21T12:00:10Z") / 1_000,
      verified_at: Date.parse("2026-07-21T12:00:11Z") / 1_000,
      verdict_activation_evidence_lease_expires_at:
        Date.parse("2026-07-21T12:01:00Z") / 1_000,
      recipient_evidence_lease_expires_at:
        Date.parse("2026-07-21T12:01:00Z") / 1_000,
      expires_at: Date.parse("2026-07-21T12:01:00Z") / 1_000,
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
      Date.parse("2026-07-21T12:02:00Z") / 1_000,
    recipient_evidence_lease_expires_at:
      Date.parse("2026-07-21T12:01:00Z") / 1_000,
    terminal_evidence_lease_expires_at:
      Date.parse("2026-07-21T12:01:00Z") / 1_000,
    completed_at: "2026-07-21T12:00:11Z",
    automatic_retry_authorized: false,
    ambiguous_outcome_quarantine_required: true,
    pre_injection_attestation_sufficient: false,
    raw_quote_persisted: false,
    raw_secret_egress: false,
    ciphertext_persisted: false,
    live_traffic_authorized: false,
  };
}

test("Arena worker proof is branded only from an exact fresh HTTPS capability response", async () => {
  const endpoint = "https://arena.release.wikigen.me/arena/challenges/dnaseq-variant-qc-safe-ir/versions/1.0.0/worker-capability";
  const challengeId = "dnaseq-variant-qc-safe-ir";
  const challengeVersion = "1.0.0";
  const heartbeatObservedAt = Math.floor(Date.now() / 1_000);
  const releaseBinding = {
    release_sha: "a".repeat(40),
    image_digest: sha("1"),
    release_manifest_sha256: sha("2"),
    approved_challenge_set_sha256: sha("3"),
    approved_challenge_key: `${challengeId}@${challengeVersion}`,
    release_policy_commitment: bytes32("4"),
    catalog_manifest_hash: "5".repeat(64),
    runtime: "dnai-safe-ir-v1",
    runtime_policy_commitment:
      PHALA_ARENA_SAFE_IR_RUNTIME_POLICY_COMMITMENT,
    compose_hash: "7".repeat(64),
    app_id: "b".repeat(40),
    os_image_hash: "8".repeat(64),
  };
  const releaseBindingSha256 = phalaArenaWorkerReleaseBindingSha256(
    releaseBinding,
    { challengeId, challengeVersion },
  );
  assert.equal(
    phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint),
    "sha256:c1ec5f3078248abc7de622613a3b8e4fa732148f0b65753bd17f508d100b2823",
  );
  assert.equal(
    releaseBindingSha256,
    "sha256:af3639249d8457e6eb9322386003d4d085d268ac4cc95419804771b91e0f5a34",
  );
  assert.equal(
    phalaArenaWorkerHeartbeatBindingSha256({
      challengeId,
      challengeVersion,
      heartbeatObservedAt: Date.parse("2026-07-21T12:00:09Z") / 1_000,
      releaseBindingSha256,
    }),
    "sha256:56a54d86b23b88e2cc1207a8a09387b4c9c1e61196403eeebf9ca8a88c0a1363",
  );
  const heartbeatBindingSha256 = phalaArenaWorkerHeartbeatBindingSha256({
    challengeId,
    challengeVersion,
    heartbeatObservedAt,
    releaseBindingSha256,
  });
  const capability = {
    surface: "arena_worker_capability",
    schema_version: 2,
    challenge_id: challengeId,
    challenge_version: challengeVersion,
    status: "live",
    backend: "release_bound_safe_ir_worker",
    isolation: "independent_job_gate_required",
    live_execution: true,
    worker_connected: true,
    safe_ir_execution_ready: true,
    hostile_general_code_ready: false,
    python_preview_live: false,
    freshness: "fresh",
    evidence_authenticity: "hmac_verified",
    evidence_classification:
      "authenticated_worker_presence_not_tdx_attestation",
    gate_reason: "ready",
    heartbeat_observed_at: heartbeatObservedAt,
    heartbeat_binding_sha256: heartbeatBindingSha256,
    release_binding_sha256: releaseBindingSha256,
    release_binding: releaseBinding,
    warning: PHALA_ARENA_WORKER_LIVE_CAPABILITY_WARNING,
    product_status: "live",
    exact_timing_egress: false,
    internal_error_egress: false,
    raw_candidate_egress: false,
    tdx_attestation_egress: false,
  };
  let responseBytes = Buffer.from(JSON.stringify(capability), "utf8");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, endpoint);
    assert.equal(options.method, "GET");
    assert.equal(options.redirect, "error");
    return {
      ok: true,
      status: 200,
      redirected: false,
      url,
      headers: {
        get(name) {
          if (name === "content-type") return "application/json";
          if (name === "content-length") return String(responseBytes.length);
          return null;
        },
      },
      async arrayBuffer() {
        return responseBytes;
      },
    };
  };
  try {
    const verifier = await import(
      `./phala-post-measurement-activation-receipt.mjs?arena-proof-test=${Date.now()}`
    );
    globalThis.fetch = async () => {
      throw new Error("mutable global fetch must not be consulted after import");
    };
    assert.equal(
      new Set(PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS).size,
      PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS.length,
    );
    assert.equal(
      PHALA_ARENA_WORKER_LIVE_CAPABILITY_FIELDS.filter(
        (field) => field === "challenge_version",
      ).length,
      1,
    );
    const proof = await verifier.verifyProductionPhalaArenaWorkerPresenceActivation({
      endpoint,
      expectedEndpointCommitmentSha256:
        phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint),
      expectedReleaseBindingSha256: releaseBindingSha256,
      challengeId,
      challengeVersion,
    });
    assert.equal(
      verifier.assertFreshProductionPhalaArenaWorkerPresenceActivationProof(proof),
      proof,
    );
    assert.equal(proof.release_binding_sha256, releaseBindingSha256);
    assert.equal(proof.heartbeat_observed_at, heartbeatObservedAt);
    assert.equal(JSON.stringify(proof).includes(endpoint), false);
    for (const forbidden of ["mac", "key", "response_body", "raw_url"]) {
      assert.equal(JSON.stringify(proof).includes(`\"${forbidden}\"`), false);
    }
    await assert.rejects(
      () => prepareProductionPhalaPostMeasurementActivationExecutionReceipt(
        receiptPreflightInput(proof),
      ),
      /lacks live production provenance/,
    );
    assert.throws(
      () => verifier.assertFreshProductionPhalaArenaWorkerPresenceActivationProof(
        structuredClone(proof),
      ),
      /fresh locally verified/,
    );
    responseBytes = Buffer.from(JSON.stringify({
      ...capability,
      release_binding_sha256: sha("9"),
    }), "utf8");
    await assert.rejects(
      () => verifier.verifyProductionPhalaArenaWorkerPresenceActivation({
        endpoint,
        expectedEndpointCommitmentSha256:
          phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint),
        expectedReleaseBindingSha256: releaseBindingSha256,
        challengeId,
        challengeVersion,
      }),
      /binding digests drifted/,
    );
    responseBytes = Buffer.from(JSON.stringify({
      ...capability,
      warning: "Authenticated worker presence",
    }), "utf8");
    await assert.rejects(
      () => verifier.verifyProductionPhalaArenaWorkerPresenceActivation({
        endpoint,
        expectedEndpointCommitmentSha256:
          phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint),
        expectedReleaseBindingSha256: releaseBindingSha256,
        challengeId,
        challengeVersion,
      }),
      /not fresh authenticated safe-IR presence/,
    );
    const canonicalResponseText = JSON.stringify(capability);
    responseBytes = Buffer.from(canonicalResponseText.replace(
      `\"challenge_version\":\"${challengeVersion}\"`,
      `\"challenge_version\":\"${challengeVersion}\",\"challenge_version\":\"${challengeVersion}\"`,
    ), "utf8");
    await assert.rejects(
      () => verifier.verifyProductionPhalaArenaWorkerPresenceActivation({
        endpoint,
        expectedEndpointCommitmentSha256:
          phalaArenaWorkerPresenceEndpointCommitmentSha256(endpoint),
        expectedReleaseBindingSha256: releaseBindingSha256,
        challengeId,
        challengeVersion,
      }),
      /canonical compact duplicate-free ASCII JSON/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("receipt preflight token is opaque and finalization requires exact durable completion", () => {
  assert.deepEqual(
    PHALA_POST_MEASUREMENT_ACTIVATION_RECEIPT_FINALIZE_FIELDS,
    [
      "preflightToken",
      "journal",
      "journalDirectory",
      "journalState",
      "journalLock",
    ],
  );
  const states = completedActivationStates();
  const completedState = states.at(-1);
  const projectedJournal =
    projectPhalaPostMeasurementActivationJournal(completedState);
  const completedStateSha256 =
    phalaPostMeasurementActivationStateSha256(completedState);
  const projectedJournalSha256 =
    phalaPostMeasurementActivationJournalSha256(projectedJournal);
  const token = __test.createReceiptPreflightForDurabilityChecks({
    receipt: receiptFixture(),
    proposedStateSha256: completedStateSha256,
    projectedJournalSha256,
  });
  assert.deepEqual(Object.keys(token), []);
  assert.equal(Object.isFrozen(token), true);
  const clonedToken = structuredClone(token);
  assert.throws(
    () => readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies(
      clonedToken,
    ),
    /opaque locally prepared/,
  );
  const finalizeInput = ({
    preflightToken = token,
    journal = projectedJournal,
    journalDirectory = "/not-a-durable-completion",
    journalState = completedState,
    journalLock = null,
  } = {}) => ({
    preflightToken,
    journal,
    journalDirectory,
    journalState,
    journalLock,
  });
  assert.throws(
    () => finalizeProductionPhalaPostMeasurementActivationExecutionReceipt(
      finalizeInput({ preflightToken: clonedToken }),
    ),
    /opaque locally prepared/,
  );
  assert.throws(
    () => finalizeProductionPhalaPostMeasurementActivationExecutionReceipt(
      finalizeInput(),
    ),
    /durably persisted completed activation journal/,
  );

  const parent = fs.realpathSync(fs.mkdtempSync(
    path.join(os.tmpdir(), "dnai-receipt-finalize-"),
  ));
  fs.chmodSync(parent, 0o700);
  const directory = path.join(parent, "state");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.chmodSync(directory, 0o700);
  const lock = acquirePhalaPostMeasurementActivationLock({
    directory,
    activationPlanSha256: sha("2"),
    ceremonyAuthorizationSha256: sha("4"),
    acquiredAt: "2026-07-21T12:00:00Z",
  });
  try {
    let durableJournal;
    for (const state of states) {
      durableJournal = persistPhalaPostMeasurementActivationJournal({
        directory,
        state,
        lock,
      });
    }
    const driftState = structuredClone(completedState);
    driftState.completed_at = "2026-07-21T12:00:11Z";
    const driftJournal = projectPhalaPostMeasurementActivationJournal(driftState);
    const driftToken = __test.createReceiptPreflightForDurabilityChecks({
      receipt: receiptFixture(),
      proposedStateSha256:
        phalaPostMeasurementActivationStateSha256(driftState),
      projectedJournalSha256:
        phalaPostMeasurementActivationJournalSha256(driftJournal),
    });
    assert.throws(
      () => finalizeProductionPhalaPostMeasurementActivationExecutionReceipt(
        finalizeInput({
          preflightToken: driftToken,
          journal: durableJournal,
          journalDirectory: directory,
          journalState: completedState,
          journalLock: lock,
        }),
      ),
      /differs from receipt preflight/,
    );
    assert.throws(
      () => finalizeProductionPhalaPostMeasurementActivationExecutionReceipt(
        finalizeInput({
          journal: durableJournal,
          journalDirectory: directory,
          journalState: completedState,
          journalLock: lock,
        }),
      ),
      /test-only receipt preflights cannot mint production authority/,
    );
  } finally {
    releasePhalaPostMeasurementActivationLock(lock);
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("activation execution receipt KAT freezes signed authorization through fresh post-restart proof", () => {
  const receipt = receiptFixture();
  assert.deepEqual(
    normalizePhalaPostMeasurementActivationExecutionReceipt(receipt),
    receipt,
  );
  assert.deepEqual(
    normalizePhalaPostMeasurementActivationExecutionReceiptCore(receipt),
    receipt,
  );
  assert.equal(
    phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
    "sha256:64653fbac10719adcd121f417d448253dbc4666eb7c26d2d08abdd9b0dd08e73",
  );
  assert.equal(
    phalaPostMeasurementActivationExecutionReceiptCoreSha256(receipt),
    "sha256:64653fbac10719adcd121f417d448253dbc4666eb7c26d2d08abdd9b0dd08e73",
  );
  const runtimeCommitments = {
    TINKER_COMPUTE_WORKLOAD_CEREMONY_NONCE: bytes32("a"),
    TINKER_COMPUTE_WORKLOAD_CVM_ID: "cvm-main-0001",
  };
  assert.equal(
    phalaPostMeasurementRuntimeCommitmentsCoreSha256(runtimeCommitments),
    phalaPostMeasurementRuntimeCommitmentsSha256(runtimeCommitments),
  );
  assert.equal(
    PHALA_POST_MEASUREMENT_PRIVATE_ASSEMBLY_RECEIPT_DOMAIN,
    "dnai-wikigen/phala-private-post-measurement-environment-assembly-receipt/v2\0",
  );
  assert.equal(
    phalaPrivatePostMeasurementAssemblyReceiptSha256({
      schema: "dnai.phala-private-post-measurement-environment-assembly-receipt.v2",
      profile_activation: {
        profile_names: ["arena-runtime", "compute-execution"],
        compose_profiles_value: "arena-runtime,compute-execution",
      },
      arena_sealed_policy_payload_hash_verified: true,
      arena_sealed_policy_auth_tag_verified: true,
    }),
    "sha256:bf28beb101f4f321e29172a78a26ec440066b0451f5ed9e9a4e7080523395a20",
  );
  assert.equal(
    canonicalPhalaPostMeasurementActivationExecutionReceiptText(receipt).endsWith("\n"),
    true,
  );
  assert.equal(receipt.patch.allowed_environment_keys_mutated, false);
  assert.equal(receipt.restart.force, false);
  assert.deepEqual(receipt.profile_activation, {
    profile_names: ["arena-runtime", "compute-execution"],
    compose_profiles_value: "arena-runtime,compute-execution",
  });
  assert.equal(
    receipt.arena_worker_presence.evidence_classification,
    "authenticated_worker_presence_not_tdx_attestation",
  );
  assert.equal(
    receipt.compute_recipient_activation_sha256,
    receipt.recipient_activation.activation_verification_sha256,
  );
  assert.equal(
    receipt.arena_worker_presence_sha256,
    "sha256:3129d9f597ec563053908537603aeae7f18eee29eb69fc2d067391e57d04ca4f",
  );
  assert.equal(
    receipt.combined_activation_verification_sha256,
    "sha256:4148bf5f59cafabce3c82dbc195dc1f07c9e3c575306540f41a947c85fa71813",
  );
  assert.equal(
    receipt.combined_activation_verification_sha256,
    phalaCombinedArenaComputeActivationVerificationSha256({
      profileActivation: receipt.profile_activation,
      arenaWorkerPresenceSha256: receipt.arena_worker_presence_sha256,
      computeRecipientActivationSha256:
        receipt.compute_recipient_activation_sha256,
    }),
  );
  for (const forbidden of ["raw_url", "mac", "key", "response_body"]) {
    assert.equal(JSON.stringify(receipt).includes(`\"${forbidden}\"`), false);
  }
  assert.equal(receipt.post_restart_evidence.pre_injection_attestation_sufficient, false);
  assert.equal(receipt.live_traffic_authorized, false);
});

test("receipt facade and core accept Compute authentication at the Arena boundary only", () => {
  const atBoundary = receiptFixture();
  assert.equal(
    atBoundary.recipient_activation.authenticated_at,
    atBoundary.arena_worker_presence.verified_at,
  );
  assert.doesNotThrow(
    () => normalizePhalaPostMeasurementActivationExecutionReceipt(atBoundary),
  );
  assert.doesNotThrow(
    () => normalizePhalaPostMeasurementActivationExecutionReceiptCore(atBoundary),
  );

  const oneSecondBefore = receiptFixture();
  oneSecondBefore.recipient_activation.authenticated_at =
    oneSecondBefore.arena_worker_presence.verified_at - 1;
  assert.throws(
    () => normalizePhalaPostMeasurementActivationExecutionReceipt(oneSecondBefore),
    /post-restart evidence/,
  );
  assert.throws(
    () => normalizePhalaPostMeasurementActivationExecutionReceiptCore(oneSecondBefore),
    /post-restart evidence/,
  );
});

test("activation receipt facade requires real calendar seconds and accepts a leap-day month boundary", () => {
  const leapBoundary = receiptFixture();
  leapBoundary.patch.attempt_recorded_at = "2024-02-29T23:59:54Z";
  leapBoundary.patch.observed_at = "2024-02-29T23:59:55Z";
  leapBoundary.restart.attempt_recorded_at = "2024-02-29T23:59:56Z";
  leapBoundary.restart.observed_at = "2024-02-29T23:59:57Z";
  leapBoundary.post_restart_evidence.get_cvm_info_observed_at =
    "2024-02-29T23:59:58Z";
  leapBoundary.post_restart_evidence.get_cvm_attestation_observed_at =
    "2024-02-29T23:59:59Z";
  leapBoundary.arena_worker_presence.heartbeat_observed_at =
    Date.parse("2024-03-01T00:00:00Z") / 1_000;
  leapBoundary.arena_worker_presence.verified_at =
    Date.parse("2024-03-01T00:00:00Z") / 1_000;
  leapBoundary.arena_worker_presence_sha256 =
    phalaArenaWorkerPresenceActivationProofSha256(
      leapBoundary.arena_worker_presence,
    );
  leapBoundary.recipient_activation.authenticated_at =
    Date.parse("2024-03-01T00:00:00Z") / 1_000;
  leapBoundary.recipient_activation.verified_at =
    Date.parse("2024-03-01T00:00:01Z") / 1_000;
  leapBoundary.recipient_activation.expires_at =
    Date.parse("2024-03-01T00:01:00Z") / 1_000;
  leapBoundary.recipient_activation
    .verdict_activation_evidence_lease_expires_at =
      leapBoundary.recipient_activation.expires_at;
  leapBoundary.recipient_activation.recipient_evidence_lease_expires_at =
    leapBoundary.recipient_activation.expires_at;
  leapBoundary.initial_activation_evidence_lease_expires_at =
    Date.parse("2024-03-01T00:02:00Z") / 1_000;
  leapBoundary.recipient_evidence_lease_expires_at =
    leapBoundary.recipient_activation.expires_at;
  leapBoundary.terminal_evidence_lease_expires_at =
    leapBoundary.recipient_activation.expires_at;
  leapBoundary.combined_activation_verification_sha256 =
    phalaCombinedArenaComputeActivationVerificationSha256({
      profileActivation: leapBoundary.profile_activation,
      arenaWorkerPresenceSha256: leapBoundary.arena_worker_presence_sha256,
      computeRecipientActivationSha256:
        leapBoundary.compute_recipient_activation_sha256,
    });
  leapBoundary.completed_at = "2024-03-01T00:00:01Z";
  assert.deepEqual(
    normalizePhalaPostMeasurementActivationExecutionReceipt(leapBoundary),
    leapBoundary,
  );

  for (const impossible of [
    "2026-02-29T12:00:00Z",
    "2026-02-30T12:00:00Z",
  ]) {
    const invalid = receiptFixture();
    invalid.patch.attempt_recorded_at = impossible;
    assert.throws(
      () => normalizePhalaPostMeasurementActivationExecutionReceipt(invalid),
      /canonical UTC second/,
    );
  }
});

test("activation execution receipt rejects mutation widening, reordered evidence, stale proof, and live claims", () => {
  const mutations = [
    (value) => { value.patch.body_field_names.push("env_keys"); },
    (value) => { value.patch.allowed_environment_keys_mutated = true; },
    (value) => { value.patch.attempt_recorded_at = "2026-07-21T12:00:05Z"; },
    (value) => {
      value.patch.finalized_readiness.finalized_block_number =
        value.restart.finalized_readiness.finalized_block_number + 1;
    },
    (value) => { value.restart.force = true; },
    (value) => { value.restart.call_sequence = 6; },
    (value) => { value.profile_activation.profile_names = ["compute-execution"]; },
    (value) => { value.profile_activation.compose_profiles_value = "compute-execution"; },
    (value) => { value.post_restart_evidence.get_cvm_attestation_call_sequence = 6; },
    (value) => { value.post_restart_evidence.tcb_info_present = false; },
    (value) => { value.post_restart_evidence.pre_injection_attestation_sufficient = true; },
    (value) => {
      value.arena_worker_presence.evidence_classification = "tdx_attestation";
    },
    (value) => { value.arena_worker_presence.raw_url = "https://secret.invalid"; },
    (value) => {
      value.arena_worker_presence.heartbeat_observed_at =
        Date.parse("2026-07-21T12:00:08Z") / 1_000;
      value.arena_worker_presence_sha256 =
        phalaArenaWorkerPresenceActivationProofSha256(
          value.arena_worker_presence,
        );
      value.combined_activation_verification_sha256 =
        phalaCombinedArenaComputeActivationVerificationSha256({
          profileActivation: value.profile_activation,
          arenaWorkerPresenceSha256: value.arena_worker_presence_sha256,
          computeRecipientActivationSha256:
            value.compute_recipient_activation_sha256,
        });
    },
    (value) => { value.arena_worker_presence.verified_at -= 2; },
    (value) => { value.arena_worker_presence_sha256 = sha("1"); },
    (value) => { value.recipient_activation.authenticated_at -= 1; },
    (value) => { value.recipient_activation.post_restart_source_activation = false; },
    (value) => { value.compute_recipient_activation_sha256 = sha("1"); },
    (value) => { value.combined_activation_verification_sha256 = sha("2"); },
    (value) => {
      value.phala_recovery_directory_identity_anchor_sha256 = "sha256:bad";
    },
    (value) => { value.completed_at = "2026-07-21T12:00:08Z"; },
    (value) => { value.automatic_retry_authorized = true; },
    (value) => { value.raw_quote_persisted = true; },
    (value) => { value.ciphertext_persisted = true; },
    (value) => { value.live_traffic_authorized = true; },
  ];
  for (const mutate of mutations) {
    const receipt = receiptFixture();
    mutate(receipt);
    assert.throws(
      () => normalizePhalaPostMeasurementActivationExecutionReceipt(receipt),
      undefined,
      `must reject ${mutate.toString()}`,
    );
    assert.throws(
      () => normalizePhalaPostMeasurementActivationExecutionReceiptCore(receipt),
      undefined,
      `pure core must reject ${mutate.toString()}`,
    );
  }
});

test("combined completion is impossible when either Arena or Compute proof is absent", () => {
  for (const field of [
    "arena_worker_presence",
    "arena_worker_presence_sha256",
    "recipient_activation",
    "compute_recipient_activation_sha256",
    "combined_activation_verification_sha256",
  ]) {
    const receipt = receiptFixture();
    delete receipt[field];
    assert.throws(
      () => normalizePhalaPostMeasurementActivationExecutionReceipt(receipt),
      /exactly the frozen fields/,
    );
    assert.throws(
      () => normalizePhalaPostMeasurementActivationExecutionReceiptCore(receipt),
      /exactly the frozen fields/,
    );
  }
});

test("activation execution receipt core remains a clock-free historical leaf", () => {
  const source = fs.readFileSync(
    new URL("./phala-post-measurement-activation-receipt-core.mjs", import.meta.url),
    "utf8",
  );
  for (const forbidden of [
    "Date.now(", "WeakMap(", "import(", "node:fs", "node:child_process",
    "phala-production-", "pre-ceremony-runtime-authority.mjs",
    "release-ceremony-authorization.mjs",
  ]) {
    assert.equal(
      source.includes(forbidden),
      false,
      `historical receipt core must exclude ${forbidden}`,
    );
  }
  assert.match(
    source,
    /from "\.\/canonical-authority-graph\.mjs";/,
  );
});
