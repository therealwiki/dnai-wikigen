import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import {
  validateCompletedLaunchContinuationProvenanceDependencies,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_EXECUTION_ORDER,
} from "./phala-production-posture-core.mjs";
import {
  PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
  PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
  PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE,
  normalizePhalaNonLiveBootstrapAuthorizationReceipt,
  phalaNonLiveBootstrapAuthorizationReceiptSha256,
} from "./phala-nonlive-bootstrap-authorization-core.mjs";
import {
  createPhalaCompletedLaunchContinuityReceipt,
  normalizePhalaCompletedLaunchContinuityReceipt,
  phalaCompletedLaunchContinuityReceiptSha256,
} from "./phala-completed-launch-continuation-core.mjs";
import * as continuation from "./phala-completed-launch-continuation.mjs";
import {
  syntheticPhalaSevenCvmLaunchCompletionFixture,
} from "./phala-seven-cvm-launch-completion.fixture.mjs";
import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
} from "./release-authority-signature-verifier-core.mjs";

const sha = (index) => `sha256:${index.toString(16).padStart(64, "0")}`;
const at = (seconds) => new Date(Date.UTC(2026, 6, 21, 10, 0, seconds))
  .toISOString().replace(".000Z", "Z");

function signedA(value) {
  const expected = value.expectedAuthority;
  return normalizePhalaNonLiveBootstrapAuthorizationReceipt({
    schema: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_SCHEMA,
    status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_STATUS,
    truth_status: PHALA_NONLIVE_BOOTSTRAP_AUTHORIZATION_RECEIPT_TRUTH,
    authorization_id: expected.bootstrap_authorization_id,
    batch_id: expected.batch_id,
    release_sha: expected.release_sha,
    bootstrap_public_environment_authority_sha256: sha(900),
    image_release_manifest_sha256: expected.image_release_manifest_sha256,
    topology_sha256: expected.topology_sha256,
    descriptor_sha256_by_domain: expected.descriptor_sha256_by_domain,
    deployment_intent_sha256: expected.deployment_intent_sha256,
    fresh_contract_deployment_receipt_sha256:
      expected.fresh_contract_deployment_receipt_sha256,
    image_release_sigstore_verification_receipt_sha256:
      expected.image_release_sigstore_verification_receipt_sha256,
    cvm_launch_intent_sha256: expected.cvm_launch_intent_sha256,
    cvm_launch_review_receipt_sha256: sha(901),
    production_target_authority_sha256:
      expected.production_target_authority_sha256,
    sdk_wire_transform_staging_receipt_sha256: sha(902),
    qvl_measurement_policy_set_sha256: sha(903),
    action_scope: [...PHALA_NONLIVE_BOOTSTRAP_ACTION_SCOPE],
    forbidden_scope: [...PHALA_NONLIVE_BOOTSTRAP_FORBIDDEN_SCOPE],
    signed_payload_sha256: sha(904),
    authorization_artifact_file_sha256: sha(905),
    bootstrap_authority_artifact_file_sha256: sha(906),
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
    reviewer_root_hash: "91".repeat(32),
    reviewer_set_sha256: sha(907),
    signer_count: 2,
    signers: [
      {
        address: `0x${"11".repeat(20)}`,
        controller_id: "controller-alpha",
        signature_sha256: sha(908),
      },
      {
        address: `0x${"22".repeat(20)}`,
        controller_id: "controller-bravo",
        signature_sha256: sha(909),
      },
    ],
    issued_at: expected.bootstrap_authorization_issued_at,
    expires_at: expected.bootstrap_authorization_expires_at,
    live_traffic_authorized: false,
    late_secret_activation_authorized: false,
    mutation_performed: false,
  });
}

function fixture() {
  const value = structuredClone(syntheticPhalaSevenCvmLaunchCompletionFixture());
  const launchByDomain = new Map(value.receipt.domains.map((entry) => [
    entry.domain,
    entry,
  ]));
  const authorization = signedA(value);
  const signedASha256 = phalaNonLiveBootstrapAuthorizationReceiptSha256(
    authorization,
  );
  value.expectedAuthority.nonlive_bootstrap_authorization_receipt_sha256 =
    signedASha256;
  value.receipt.nonlive_bootstrap_authorization_receipt_sha256 = signedASha256;
  const state = normalizeCompletedPhalaExecutorState({
    schema: PHALA_EXECUTOR_STATE_SCHEMA,
    status: "complete_seven_commits_posture_observed_attestation_unverified",
    sequence: 38,
    batch_id: value.receipt.batch_id,
    bootstrap_authorization_id: value.receipt.bootstrap_authorization_id,
    bootstrap_authorization_receipt_sha256: signedASha256,
    release_sha: value.receipt.release_sha,
    launch_intent_sha256: value.receipt.cvm_launch_intent_sha256,
    target_authority_sha256: value.receipt.production_target_authority_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      value.receipt.phala_recovery_directory_identity_anchor_sha256,
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: launchByDomain.get(domain).app_id,
      nonce: index + 1,
    })),
    preparations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      request_sha256: sha(1_000 + index),
      readiness_sha256: sha(1_010 + index),
      attempted_at: launchByDomain.get(domain).provision_attempted_at,
      observed_at: launchByDomain.get(domain).provision_observed_at,
      observation_sha256:
        launchByDomain.get(domain).provision_observation_sha256,
    })),
    signed_key_bindings: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      binding_sha256: sha(1_020 + index),
      public_key_sha256: sha(1_030 + index),
    })),
    committed_prefix: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      cvm_id: launchByDomain.get(domain).cvm_id,
      request_sha256: sha(1_040 + index),
      readiness_sha256: sha(1_050 + index),
      attempted_at: launchByDomain.get(domain).commit_attempted_at,
      observed_at: launchByDomain.get(domain).commit_observed_at,
      observation_sha256: launchByDomain.get(domain).commit_observation_sha256,
    })),
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: PHALA_EXECUTION_ORDER.map((domain) => ({
      domain,
      receipt_sha256:
        launchByDomain.get(domain).production_posture_verification_receipt_sha256,
    })),
    preparations_validation_sha256: sha(1_060),
  });
  const stateSha256 = phalaExecutorStateDigest(state);
  value.expectedAuthority.executor_final_state_sha256 = stateSha256;
  value.receipt.executor_final_state_sha256 = stateSha256;
  const journal = {
    schema: "dnai.phala-production-recovery-journal.v2",
    truth_status:
      "private_recovery_metadata_no_secrets_ciphertext_or_phala_atomicity_claim",
    batch_id: state.batch_id,
    state_sha256: stateSha256,
    state: structuredClone(state),
    seven_commit_batch_is_atomic: false,
    automatic_retry_authorized: false,
    automatic_cleanup_authorized: false,
  };
  const currentDomains = PHALA_EXECUTION_ORDER.map((domain, index) => {
    const launch = launchByDomain.get(domain);
    const binding = state.signed_key_bindings[index];
    const firstSequence = 2 + index * 3;
    return {
      domain,
      app_id: launch.app_id,
      cvm_id: launch.cvm_id,
      compose_hash: launch.committed_compose_hash,
      kms_id: launch.kms_id,
      instance_type: launch.instance_type,
      disk_size: launch.disk_size,
      os_image_hash: launch.os_image_hash,
      kms_type: "phala",
      listed: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
      cvm_info_call_sequence: firstSequence,
      cvm_info_observation_sha256: sha(1_100 + index * 3),
      cvm_info_observed_at: at(300 + index * 3),
      production_posture_verification_receipt_sha256: sha(1_200 + index),
      attestation_call_sequence: firstSequence + 1,
      attestation_observation_sha256: sha(1_101 + index * 3),
      attestation_response_sha256: sha(1_300 + index),
      attestation_observed_at: at(301 + index * 3),
      environment_key_call_sequence: firstSequence + 2,
      environment_key_observation_sha256: sha(1_102 + index * 3),
      environment_key_binding_sha256: binding.binding_sha256,
      environment_public_key_sha256: binding.public_key_sha256,
      environment_key_observed_at: at(302 + index * 3),
    };
  });
  return {
    adapterIdentitySha256: sha(1_400),
    completedAt: at(325),
    completedJournal: journal,
    currentAccount: {
      account_subject_sha256: sha(1_401),
      call_sequence: 1,
      observation_sha256: sha(1_402),
      observed_at: at(299),
    },
    currentDomains,
    historicalEvidenceReconstruction: {
      schema: "dnai.phala-seven-cvm-recorded-time-dcap-replay.v1",
      truth_status:
        "signed_a_l_r_b_authority_exact14_protocol_signatures_recorded_time_dcap_and_persisted_intel_collateral_replayed_without_freshness_renewal_or_live_authority",
      launch_completion_receipt_sha256: sha(1_403),
      release_verification_authority_sha256:
        value.receipt.release_verification_authority_sha256,
      seven_cvm_verified_evidence_set_sha256:
        value.receipt.machine_verifier_evidence_set_sha256,
      historical_transcript_file_set_sha256:
        value.receipt.historical_transcript_file_set_sha256,
      all_seven_recorded_time_dcap_replayed: true,
      persisted_intel_collateral_revalidated: true,
      workload_eip191_signatures_replayed: true,
      freshness_renewed: false,
      production_live_brand_minted: false,
      live_traffic_authorized: false,
      raw_quote_publicly_disclosed: false,
      raw_collateral_publicly_disclosed: false,
      raw_secret_egress: false,
    },
    launchCompletionReceipt: value.receipt,
    launchCompletionReceiptSha256: sha(1_403),
    launchCompletionRawFileSha256: sha(1_404),
    signedAReceipt: structuredClone(authorization),
    startedAt: at(298),
  };
}

test("current continuity receipt binds exact journal, historical L/A/proofs, and 22 read-only observations", () => {
  const input = fixture();
  const receipt = createPhalaCompletedLaunchContinuityReceipt(input);
  assert.equal(receipt.continuity_observation_count, 22);
  assert.equal(receipt.domains.length, 7);
  assert.equal(receipt.mutation_methods_called, false);
  assert.equal(receipt.launch_completion_refreshed, false);
  assert.equal(receipt.historical_evidence_refreshed, false);
  assert.equal(receipt.post_measurement_mutation_observed, false);
  assert.equal(receipt.live_traffic_authorized, false);
  assert.match(
    phalaCompletedLaunchContinuityReceiptSha256(receipt),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.deepEqual(normalizePhalaCompletedLaunchContinuityReceipt(receipt), receipt);
  assert.throws(() => { receipt.domains[0].cvm_id = "cvm-tampered"; }, TypeError);
});

test("standalone receipt normalization rejects recomputed field and uniqueness tampering", () => {
  const receipt = createPhalaCompletedLaunchContinuityReceipt(fixture());
  for (const mutate of [
    (value) => { value.domains[0].listed = true; },
    (value) => { value.domains[0].cvm_info_call_sequence = 22; },
    (value) => { value.domains[0].cvm_info_observed_at = at(400); },
    (value) => { value.domains[1].app_id = value.domains[0].app_id; },
    (value) => { value.domains[1].environment_public_key_sha256 =
      value.domains[0].environment_public_key_sha256; },
  ]) {
    const tampered = structuredClone(receipt);
    mutate(tampered);
    assert.throws(
      () => normalizePhalaCompletedLaunchContinuityReceipt(tampered),
    );
    assert.throws(() => phalaCompletedLaunchContinuityReceiptSha256(tampered));
  }
});

test("continuation provenance accepts actual L v5 and rejects v4 or truth drift", () => {
  const input = fixture();
  const receipt = createPhalaCompletedLaunchContinuityReceipt(input);
  const dependencies = {
    executor_final_state: input.completedJournal.state,
    completed_recovery_journal: input.completedJournal,
    persisted_launch_completion_receipt: input.launchCompletionReceipt,
    persisted_launch_completion_receipt_sha256:
      input.launchCompletionReceiptSha256,
    persisted_launch_completion_raw_file_sha256:
      input.launchCompletionRawFileSha256,
    signed_a_receipt: input.signedAReceipt,
    production_target_authority_evidence: {
      productionTargetAuthoritySha256:
        input.completedJournal.state.target_authority_sha256,
    },
    historical_evidence_reconstruction:
      input.historicalEvidenceReconstruction,
    current_continuity_receipt: receipt,
    current_continuity_receipt_sha256:
      phalaCompletedLaunchContinuityReceiptSha256(receipt),
    historical_launch_refreshed: false,
    historical_evidence_refreshed: false,
    live_traffic_authorized: false,
  };
  assert.equal(
    dependencies.persisted_launch_completion_receipt.schema,
    "dnai.phala-seven-cvm-launch-completion-receipt.v5",
  );
  assert.equal(
    validateCompletedLaunchContinuationProvenanceDependencies(dependencies).state,
    input.completedJournal.state,
  );
  for (const mutate of [
    (value) => {
      value.persisted_launch_completion_receipt.schema =
        "dnai.phala-seven-cvm-launch-completion-receipt.v4";
    },
    (value) => {
      value.persisted_launch_completion_receipt.truth_status = "drifted";
    },
  ]) {
    const drifted = structuredClone(dependencies);
    mutate(drifted);
    assert.throws(
      () => validateCompletedLaunchContinuationProvenanceDependencies(drifted),
      /one exact historical executor lineage/,
    );
  }
});

test("ordinary Node cannot spoof a completed-launch continuation capability", () => {
  const input = fixture();
  const receipt = createPhalaCompletedLaunchContinuityReceipt(input);
  const receiptSha256 = phalaCompletedLaunchContinuityReceiptSha256(receipt);
  const forged = {
    schema: continuation.PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_SCHEMA,
    status: continuation.PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_STATUS,
    truth_status: continuation.PHALA_COMPLETED_LAUNCH_CONTINUATION_CAPABILITY_TRUTH,
    release_sha: receipt.release_sha,
    batch_id: receipt.batch_id,
    launch_completion_receipt_sha256:
      receipt.launch_completion_receipt_sha256,
    continuity_receipt_sha256: receiptSha256,
    historical_launch_refreshed: false,
    historical_evidence_refreshed: false,
    capability_serialized: false,
    one_shot: true,
    activation_mutation_authorized: false,
    live_traffic_authorized: false,
  };
  assert.equal(continuation.__test, undefined);
  assert.throws(
    () => continuation.assertCompletedPhalaSevenCvmLaunchContinuationCapability(
      forged,
    ),
    /exact unmodified completed-launch continuation capability/,
  );
  assert.throws(
    () => continuation.claimCompletedPhalaSevenCvmLaunchContinuationForProvenance(
      forged,
    ),
    /exact unmodified completed-launch continuation capability/,
  );
  assert.throws(
    () => continuation.consumeCompletedPhalaSevenCvmLaunchContinuationCapability(
      forged,
    ),
    /exact unmodified completed-launch continuation capability/,
  );
  const moduleUrl = new URL(
    "./phala-completed-launch-continuation.mjs",
    import.meta.url,
  );
  const spoofedEntrypoint = new URL(
    "./phala-completed-launch-continuation-core.test.mjs",
    import.meta.url,
  );
  const child = spawnSync(process.execPath, [
    "--input-type=module",
    "--eval",
    [
      `process.env.NODE_TEST_CONTEXT = "child-v8";`,
      `process.argv[1] = ${JSON.stringify(spoofedEntrypoint.pathname)};`,
      `const module = await import(${JSON.stringify(moduleUrl.href)});`,
      `if (module.__test !== undefined) process.exit(91);`,
      `const forged = JSON.parse(process.argv[2]);`,
      `try {`,
      `  module.claimCompletedPhalaSevenCvmLaunchContinuationForProvenance(forged);`,
      `  process.exit(92);`,
      `} catch { process.stdout.write("rejected"); }`,
    ].join("\n"),
    spoofedEntrypoint.pathname,
    JSON.stringify(forged),
  ], {
    cwd: new URL("..", import.meta.url),
    env: { ...process.env, NODE_TEST_CONTEXT: "child-v8" },
    encoding: "utf8",
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout, "rejected");
});

test("continuity rejects incomplete, ambiguous, or postmeasurement-shaped executor state", () => {
  for (const status of [
    "ambiguous_reconcile_required",
    "partial_commit_requires_operator_reconciliation",
    "post_measurement_activation_complete",
  ]) {
    const input = fixture();
    input.completedJournal.state.status = status;
    assert.throws(
      () => createPhalaCompletedLaunchContinuityReceipt(input),
      /exact complete seven-CVM|completed executor|pre-attestation/i,
    );
  }
});

test("continuity rejects journal/L tampering and original historical-A timing drift", () => {
  const mutations = [
    (input) => { input.completedJournal.state.committed_prefix[0].cvm_id = "cvm-drifted"; },
    (input) => { input.launchCompletionReceipt.domains[0].committed_compose_hash = "fe".repeat(32); },
    (input) => { input.completedJournal.state.preparations[0].attempted_at = at(599); },
    (input) => { input.signedAReceipt.expires_at = at(10); },
  ];
  for (const mutate of mutations) {
    const input = fixture();
    mutate(input);
    assert.throws(() => createPhalaCompletedLaunchContinuityReceipt(input));
  }
});

test("continuity rejects current app/CVM/compose/OS/KMS/resource/privacy/key drift", () => {
  const mutations = [
    (entry) => { entry.app_id = "ef".repeat(20); },
    (entry) => { entry.cvm_id = "cvm-drifted"; },
    (entry) => { entry.compose_hash = "ef".repeat(32); },
    (entry) => { entry.os_image_hash = "ef".repeat(32); },
    (entry) => { entry.kms_id = "kms-drifted"; },
    (entry) => { entry.instance_type = "tdx.drifted"; },
    (entry) => { entry.disk_size += 1; },
    (entry) => { entry.public_logs = true; },
    (entry) => { entry.environment_public_key_sha256 = sha(9_999); },
  ];
  for (const mutate of mutations) {
    const input = fixture();
    mutate(input.currentDomains[0]);
    assert.throws(() => createPhalaCompletedLaunchContinuityReceipt(input));
  }
});

test("continuity rejects replay-shaped call order, stale observations, and proof/transcript drift", () => {
  const mutations = [
    (input) => { input.currentDomains[0].cvm_info_call_sequence = 99; },
    (input) => { input.currentDomains[0].attestation_observed_at = at(297); },
    (input) => {
      input.historicalEvidenceReconstruction
        .seven_cvm_verified_evidence_set_sha256 = sha(9_900);
    },
    (input) => {
      input.historicalEvidenceReconstruction
        .historical_transcript_file_set_sha256 = sha(9_901);
    },
  ];
  for (const mutate of mutations) {
    const input = fixture();
    mutate(input);
    assert.throws(() => createPhalaCompletedLaunchContinuityReceipt(input));
  }
});
