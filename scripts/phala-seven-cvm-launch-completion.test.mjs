import assert from "node:assert/strict";
import test from "node:test";

import {
  PHALA_EXECUTION_ORDER,
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-production-executor-core.mjs";
import {
  PHALA_SEVEN_CVM_COMPLETION_ORDER,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN,
  REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
  assertBrandedPhalaSevenCvmLaunchCompletionReceipt,
  assertPersistedPhalaSevenCvmLaunchCompletionReceipt,
  canonicalPhalaSevenCvmLaunchCompletionReceiptText,
  createPhalaSevenCvmLaunchCompletionReceipt,
  normalizePhalaSevenCvmLaunchCompletionReceipt,
  phalaSevenCvmLaunchCompletionReceiptSha256,
  reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency,
} from "./phala-seven-cvm-launch-completion.mjs";
import {
  syntheticPhalaSevenCvmLaunchCompletionFixture,
} from "./phala-seven-cvm-launch-completion.fixture.mjs";
import {
  syntheticPreCeremonyRuntimeAuthorityFromPlanFixture,
  syntheticPostMeasurementActivationPlanFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  normalizePhalaPostMeasurementActivationPlan,
} from "./phala-post-measurement-activation.mjs";

function fixture() {
  return structuredClone(syntheticPhalaSevenCvmLaunchCompletionFixture());
}

const pin = (index) => `sha256:${index.toString(16).padStart(64, "0")}`;

function historicalFixture() {
  const value = fixture();
  const mainReceipt = value.receipt.domains.find(
    (entry) => entry.domain === "main_runtime_cvm",
  );
  mainReceipt.cvm_id = "cvm-main-0001";
  value.expectedAuthority.domain_completion_authority_by_domain
    .main_runtime_cvm.cvm_id = mainReceipt.cvm_id;
  const byDomain = new Map(value.receipt.domains.map((entry) => [
    entry.domain,
    entry,
  ]));
  const executor = normalizeCompletedPhalaExecutorState({
    schema: PHALA_EXECUTOR_STATE_SCHEMA,
    status: "complete_seven_commits_posture_observed_attestation_unverified",
    sequence: 38,
    batch_id: value.receipt.batch_id,
    bootstrap_authorization_id: value.receipt.bootstrap_authorization_id,
    bootstrap_authorization_receipt_sha256:
      value.receipt.nonlive_bootstrap_authorization_receipt_sha256,
    release_sha: value.receipt.release_sha,
    launch_intent_sha256: value.receipt.cvm_launch_intent_sha256,
    target_authority_sha256:
      value.receipt.production_target_authority_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      value.receipt.phala_recovery_directory_identity_anchor_sha256,
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: byDomain.get(domain).app_id,
      nonce: index + 1,
    })),
    preparations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      request_sha256: pin(700 + index),
      readiness_sha256: pin(720 + index),
      attempted_at: byDomain.get(domain).provision_attempted_at,
      observed_at: byDomain.get(domain).provision_observed_at,
      observation_sha256: byDomain.get(domain).provision_observation_sha256,
    })),
    signed_key_bindings: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      binding_sha256: pin(740 + index),
      public_key_sha256: pin(760 + index),
    })),
    committed_prefix: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      cvm_id: byDomain.get(domain).cvm_id,
      request_sha256: pin(780 + index),
      readiness_sha256: pin(800 + index),
      attempted_at: byDomain.get(domain).commit_attempted_at,
      observed_at: byDomain.get(domain).commit_observed_at,
      observation_sha256: byDomain.get(domain).commit_observation_sha256,
    })),
    pending_mutation: null,
    reconciliation: null,
    posture_receipts: PHALA_EXECUTION_ORDER.map((domain) => ({
      domain,
      receipt_sha256:
        byDomain.get(domain).production_posture_verification_receipt_sha256,
    })),
    preparations_validation_sha256: pin(820),
  });
  value.expectedAuthority.executor_final_state_sha256 =
    phalaExecutorStateDigest(executor);
  value.receipt.executor_final_state_sha256 =
    value.expectedAuthority.executor_final_state_sha256;
  const main = byDomain.get("main_runtime_cvm");
  const releaseDescriptors = syntheticPhalaSevenCvmReleaseDescriptorsFixture({
    mainRuntime: {
      descriptor_sha256: main.descriptor_sha256,
      app_id: main.app_id,
      cvm_id: main.cvm_id,
      compose_hash: main.committed_compose_hash,
      os_image_hash: main.os_image_hash,
    },
  }).map((descriptor) => {
    const completion = byDomain.get(descriptor.domain);
    return {
      ...descriptor,
      descriptor_sha256: completion.descriptor_sha256,
      app_id: completion.app_id,
      cvm_id: completion.cvm_id,
      compose_hash: completion.committed_compose_hash,
      os_image_hash: completion.os_image_hash,
      posture_receipt_sha256:
        completion.production_posture_verification_receipt_sha256,
      posture_observed_at: completion.production_posture_verified_at,
      kms_id: completion.kms_id,
      instance_type: completion.instance_type,
      disk_size: completion.disk_size,
    };
  });
  const releaseVerificationAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority({
      ...syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha: value.receipt.release_sha,
      deploymentIntentSha256: value.receipt.deployment_intent_sha256,
      bootstrapAuthorizationReceiptSha256:
        value.receipt.nonlive_bootstrap_authorization_receipt_sha256,
      ceremonyNonce: `0x${"11".repeat(32)}`,
      freshContractDeploymentReceiptSha256:
        value.receipt.fresh_contract_deployment_receipt_sha256,
      diligenceRoom: value.expectedAuthority.diligence_room_address,
      computeCreditVault:
        value.expectedAuthority.compute_credit_vault_address,
      releaseDescriptors,
      }),
      evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    });
  const releaseVerificationAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(
      releaseVerificationAuthority,
    );
  value.expectedAuthority.release_verification_authority_sha256 =
    releaseVerificationAuthoritySha256;
  value.expectedAuthority.release_verification_authority =
    releaseVerificationAuthority;
  value.receipt.release_verification_authority_sha256 =
    releaseVerificationAuthoritySha256;
  const plan = structuredClone(syntheticPostMeasurementActivationPlanFixture({
    releaseSha: value.receipt.release_sha,
    deploymentIntentSha256: value.receipt.deployment_intent_sha256,
    cvmLaunchIntentSha256: value.receipt.cvm_launch_intent_sha256,
    releaseVerificationAuthority,
    sevenCvmLaunchCompletionReceiptSha256: pin(900),
    createdAt: "2026-07-21T10:04:00Z",
    activationEvidenceLeaseExpiresAt:
      value.expectedAuthority.activation_evidence_lease_expires_at,
  }));
  plan.batch_id = value.receipt.batch_id;
  plan.phala_recovery_directory_identity_anchor_sha256 =
    value.receipt.phala_recovery_directory_identity_anchor_sha256;
  plan.seven_cvm_verified_evidence_set_sha256 =
    value.receipt.machine_verifier_evidence_set_sha256;
  plan.runtime_commitments.TINKER_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256 =
    value.receipt.deployment_intent_sha256;
  const normalizedBeforeL = normalizePhalaPostMeasurementActivationPlan(plan);
  const receiptSha256 = phalaSevenCvmLaunchCompletionReceiptSha256(
    value.receipt,
    { expectedAuthority: value.expectedAuthority },
  );
  const planWithReceipt = structuredClone(normalizedBeforeL);
  planWithReceipt.seven_cvm_launch_completion_receipt_sha256 = receiptSha256;
  const normalizedPlan = normalizePhalaPostMeasurementActivationPlan(
    planWithReceipt,
  );
  const runtimeAuthority =
    syntheticPreCeremonyRuntimeAuthorityFromPlanFixture({
      postMeasurementActivationPlan: normalizedPlan,
      historicalTranscriptFileSetSha256: pin(901),
      issuedAt: Math.floor(Date.parse("2026-07-21T10:04:30Z") / 1_000),
      machineVerifierEvidenceIssuedAt:
        value.expectedAuthority.machine_verifier_evidence_issued_at,
    });
  const runtimeBinding = {
    schema: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
    release_sha: runtimeAuthority.release_sha,
    deployment_intent_sha256: runtimeAuthority.deployment_intent_sha256,
    cvm_launch_intent_sha256: runtimeAuthority.cvm_launch_intent_sha256,
    release_verification_authority: releaseVerificationAuthority,
    release_verification_authority_sha256:
      releaseVerificationAuthoritySha256,
    seven_cvm_launch_completion_receipt_sha256:
      runtimeAuthority.seven_cvm_launch_completion_receipt_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      runtimeAuthority.phala_recovery_directory_identity_anchor_sha256,
    batch_id: runtimeAuthority.post_measurement_activation_plan.batch_id,
    seven_cvm_verified_evidence_set_sha256:
      runtimeAuthority.post_measurement_activation_plan
        .seven_cvm_verified_evidence_set_sha256,
    main_runtime_target: structuredClone(
      runtimeAuthority.post_measurement_activation_plan.target,
    ),
    activation_plan_created_at:
      runtimeAuthority.post_measurement_activation_plan.created_at,
    machine_verifier_evidence_issued_at:
      value.expectedAuthority.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      runtimeAuthority.activation_evidence_lease_expires_at,
  };
  return {
    ...value,
    executor,
    runtimeAuthority,
    runtimeBinding,
    bootstrapBinding: {
      authorization_id: value.receipt.bootstrap_authorization_id,
      batch_id: value.receipt.batch_id,
      receipt_sha256:
        value.receipt.nonlive_bootstrap_authorization_receipt_sha256,
      issued_at: value.expectedAuthority.bootstrap_authorization_issued_at,
      expires_at: value.expectedAuthority.bootstrap_authorization_expires_at,
    },
  };
}

test("exact-seven completion canonical form and separate final/mutation orders are stable", () => {
  const { receipt, expectedAuthority } = fixture();
  const normalized = normalizePhalaSevenCvmLaunchCompletionReceipt(receipt, {
    expectedAuthority,
  });
  assert.deepEqual(normalized.completion_order, PHALA_SEVEN_CVM_COMPLETION_ORDER);
  assert.deepEqual(normalized.mutation_order, PHALA_EXECUTION_ORDER);
  assert.deepEqual(normalized.completion_order, [
    "main_runtime_cvm",
    "diligence_qvl_cvm",
    "arena_qvl_cvm",
    "anchor_writer_qvl_cvm",
    "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm",
    "independent_metering_cvm",
  ]);
  assert.deepEqual(normalized.mutation_order, [
    "diligence_qvl_cvm",
    "arena_qvl_cvm",
    "anchor_writer_qvl_cvm",
    "compute_workload_qvl_cvm",
    "compute_metering_qvl_cvm",
    "independent_metering_cvm",
    "main_runtime_cvm",
  ]);
  assert.notDeepEqual(normalized.completion_order, normalized.mutation_order);
  assert.equal(normalized.completion_order[0], "main_runtime_cvm");
  assert.equal(normalized.mutation_order.at(-1), "main_runtime_cvm");
  for (const order of [normalized.completion_order, normalized.mutation_order]) {
    assert.ok(
      order.indexOf("compute_workload_qvl_cvm")
        < order.indexOf("compute_metering_qvl_cvm"),
    );
  }
  assert.deepEqual(
    normalized.domains.map(({ domain }) => domain),
    PHALA_SEVEN_CVM_COMPLETION_ORDER,
  );
  assert.equal(normalized.commit_count, 7);
  assert.equal(normalized.five_qvl_identities_machine_verified, true);
  assert.equal(normalized.two_workload_verdicts_machine_verified, true);
  assert.equal(normalized.compute_workload_recipient_activation_authorized, false);
  assert.equal(
    normalized.private_historical_identity_response_quote_bytes_persisted,
    true,
  );
  assert.equal(normalized.raw_quote_external_egress, false);
  assert.equal(normalized.raw_private_artifact_egress, false);
  assert.equal(normalized.raw_secret_egress, false);
  assert.throws(() => normalized.domains.pop(), TypeError);
  assert.equal(
    canonicalPhalaSevenCvmLaunchCompletionReceiptText(receipt, { expectedAuthority }),
    `${JSON.stringify(JSON.parse(
      canonicalPhalaSevenCvmLaunchCompletionReceiptText(receipt, { expectedAuthority }),
    ), null, 2)}\n`,
  );
  assert.equal(PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN.endsWith("\0"), true);
  assert.match(
    phalaSevenCvmLaunchCompletionReceiptSha256(receipt, { expectedAuthority }),
    /^sha256:[0-9a-f]{64}$/,
  );
});

test("exact-seven completion rejects omission, lineage drift, replay, and mixed proof roles", () => {
  const mutations = [
    (value) => { value.receipt.domains.pop(); },
    (value) => { value.receipt.domains[0].descriptor_sha256 = `sha256:${"f".repeat(64)}`; },
    (value) => { value.receipt.domains[0].app_id = value.receipt.domains[1].app_id; },
    (value) => { value.receipt.domains[0].commit_observed_at = "2026-07-21T10:30:00Z"; },
    (value) => {
      value.receipt.domains[1].machine_evidence_kind =
        "workload_independent_signed_qvl_verdict";
    },
    (value) => { value.receipt.completed_at -= 1; },
    (value) => { value.receipt.compute_workload_recipient_activation_authorized = true; },
    (value) => { value.receipt.raw_quote_external_egress = true; },
    (value) => {
      value.expectedAuthority.domain_completion_authority_by_domain
        .main_runtime_cvm.bound_contract_address =
          value.expectedAuthority.compute_credit_vault_address;
    },
    (value) => {
      value.expectedAuthority.domain_completion_authority_by_domain
        .independent_metering_cvm.bound_contract_address =
          value.expectedAuthority.diligence_room_address;
    },
  ];
  for (const mutate of mutations) {
    const value = fixture();
    mutate(value);
    assert.throws(() => normalizePhalaSevenCvmLaunchCompletionReceipt(
      value.receipt,
      { expectedAuthority: value.expectedAuthority },
    ));
  }
});

test("retired six-CVM completion is explicitly revoked", () => {
  const { expectedAuthority } = fixture();
  const retired = {
    schema: REVOKED_PHALA_SIX_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
  };
  for (const operation of [
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(retired, { expectedAuthority }),
    () => canonicalPhalaSevenCvmLaunchCompletionReceiptText(retired, { expectedAuthority }),
    () => phalaSevenCvmLaunchCompletionReceiptSha256(retired, { expectedAuthority }),
    () => assertBrandedPhalaSevenCvmLaunchCompletionReceipt(retired),
    () => assertPersistedPhalaSevenCvmLaunchCompletionReceipt({
      persistedReceipt: retired,
    }),
  ]) {
    assert.throws(
      operation,
      /retired six-CVM launch completion schema is explicitly revoked/,
    );
  }
});

test("normalization never brands and production creation requires branded raw dependencies", () => {
  const { receipt, expectedAuthority } = fixture();
  const normalized = normalizePhalaSevenCvmLaunchCompletionReceipt(receipt, {
    expectedAuthority,
  });
  assert.throws(
    () => assertBrandedPhalaSevenCvmLaunchCompletionReceipt(normalized),
    /not reconstructed from production dependencies/,
  );
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(structuredClone(receipt)),
    /requires external authority/,
  );
  assert.throws(
    () => createPhalaSevenCvmLaunchCompletionReceipt({}),
    /historically cryptographically reconstructed/,
  );

  let getterCalls = 0;
  const accessorOptions = Object.defineProperty({}, "expectedAuthority", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return expectedAuthority;
    },
  });
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(
      receipt,
      accessorOptions,
    ),
    /canonical plain-data graph/i,
  );
  assert.equal(getterCalls, 0);
});

test("exact-37 historical reconstruction binds persisted L and executor to R without refreshing freshness", async () => {
  const value = historicalFixture();
  const result = await reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
    persistedReceipt: value.receipt,
    persistedExecutorFinalState: value.executor,
    historicalPreCeremonyRuntimeBinding: value.runtimeBinding,
    historicalBootstrapAuthorizationBinding: value.bootstrapBinding,
  });
  assert.equal(
    result.receipt_sha256,
    value.runtimeAuthority.seven_cvm_launch_completion_receipt_sha256,
  );
  assert.equal(
    result.executor_final_state_sha256,
    value.receipt.executor_final_state_sha256,
  );
  assert.equal(result.freshness_renewed, false);
  assert.equal(result.production_brand_minted, false);
  assert.equal(result.live_traffic_authorized, false);
  assert.equal(
    phalaSevenCvmLaunchCompletionReceiptSha256(
      result.receipt,
      { expectedAuthority: value.expectedAuthority },
    ),
    result.receipt_sha256,
  );
  assert.throws(
    () => assertBrandedPhalaSevenCvmLaunchCompletionReceipt(result.receipt),
    /not reconstructed from production dependencies/,
  );
});

test("exact-37 historical reconstruction rejects L, executor, R, signed-A window, and target drift", async () => {
  const mutations = [
    (value) => {
      value.receipt.domains[0].machine_evidence_sha256 = pin(990);
    },
    (value) => {
      value.executor = structuredClone(value.executor);
      value.executor.preparations[0].observation_sha256 = pin(991);
    },
    (value) => {
      value.runtimeBinding.seven_cvm_launch_completion_receipt_sha256 = pin(992);
    },
    (value) => {
      value.bootstrapBinding.expires_at = "2026-07-21T10:01:00Z";
    },
    (value) => {
      value.runtimeBinding.main_runtime_target.cvm_id =
        "cvm-drifted-main";
    },
  ];
  for (const mutate of mutations) {
    const value = historicalFixture();
    mutate(value);
    await assert.rejects(
      reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
        persistedReceipt: value.receipt,
        persistedExecutorFinalState: value.executor,
        historicalPreCeremonyRuntimeBinding: value.runtimeBinding,
        historicalBootstrapAuthorizationBinding: value.bootstrapBinding,
      }),
    );
  }
  const value = historicalFixture();
  await assert.rejects(
    reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
      persistedReceipt: value.receipt,
      persistedExecutorFinalState: value.executor,
      historicalPreCeremonyRuntimeBinding: value.runtimeBinding,
      historicalBootstrapAuthorizationBinding: value.bootstrapBinding,
      callerClock: () => Date.now(),
    }),
    /canonical plain-data graph|exactly the frozen fields/,
  );
});
