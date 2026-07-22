import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  PHALA_EXECUTOR_STATE_SCHEMA,
  normalizeCompletedPhalaExecutorState,
  phalaExecutorStateDigest,
} from "./phala-executor-state-core.mjs";
import { PHALA_EXECUTION_ORDER } from "./phala-production-posture-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN,
  PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA,
  canonicalPhalaSevenCvmLaunchCompletionReceiptText,
  normalizePhalaSevenCvmLaunchCompletionReceipt,
  phalaSevenCvmLaunchCompletionReceiptSha256,
  reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency,
} from "./phala-seven-cvm-launch-completion-core.mjs";
import {
  syntheticPhalaSevenCvmLaunchCompletionFixture,
} from "./phala-seven-cvm-launch-completion.fixture.mjs";
import {
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";

const sha = (index) => `sha256:${index.toString(16).padStart(64, "0")}`;

function fixture() {
  return structuredClone(syntheticPhalaSevenCvmLaunchCompletionFixture());
}

function historicalFixture() {
  const value = fixture();
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
    target_authority_sha256: value.receipt.production_target_authority_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      value.receipt.phala_recovery_directory_identity_anchor_sha256,
    reservations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      app_id: byDomain.get(domain).app_id,
      nonce: index + 1,
    })),
    preparations: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      request_sha256: sha(700 + index),
      readiness_sha256: sha(720 + index),
      attempted_at: byDomain.get(domain).provision_attempted_at,
      observed_at: byDomain.get(domain).provision_observed_at,
      observation_sha256: byDomain.get(domain).provision_observation_sha256,
    })),
    signed_key_bindings: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      binding_sha256: sha(740 + index),
      public_key_sha256: sha(760 + index),
    })),
    committed_prefix: PHALA_EXECUTION_ORDER.map((domain, index) => ({
      domain,
      cvm_id: byDomain.get(domain).cvm_id,
      request_sha256: sha(780 + index),
      readiness_sha256: sha(800 + index),
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
    preparations_validation_sha256: sha(820),
  });
  value.expectedAuthority.executor_final_state_sha256 =
    phalaExecutorStateDigest(executor);
  value.receipt.executor_final_state_sha256 =
    value.expectedAuthority.executor_final_state_sha256;
  const receiptSha256 = phalaSevenCvmLaunchCompletionReceiptSha256(
    value.receipt,
    { expectedAuthority: value.expectedAuthority },
  );
  const main = byDomain.get("main_runtime_cvm");
  const runtimeBinding = normalizePhalaSevenCvmHistoricalRuntimeBinding({
    schema: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
    truth_status: PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
    release_sha: value.receipt.release_sha,
    deployment_intent_sha256: value.receipt.deployment_intent_sha256,
    cvm_launch_intent_sha256: value.receipt.cvm_launch_intent_sha256,
    release_verification_authority:
      value.expectedAuthority.release_verification_authority,
    release_verification_authority_sha256:
      value.expectedAuthority.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256: receiptSha256,
    phala_recovery_directory_identity_anchor_sha256:
      value.receipt.phala_recovery_directory_identity_anchor_sha256,
    batch_id: value.receipt.batch_id,
    seven_cvm_verified_evidence_set_sha256:
      value.receipt.machine_verifier_evidence_set_sha256,
    main_runtime_target: {
      domain: "main_runtime_cvm",
      descriptor_sha256: main.descriptor_sha256,
      app_id: main.app_id,
      cvm_id: main.cvm_id,
      compose_hash: main.committed_compose_hash,
      os_image_hash: main.os_image_hash,
    },
    activation_plan_created_at: "2026-07-21T10:04:00Z",
    machine_verifier_evidence_issued_at:
      value.receipt.machine_verifier_evidence_issued_at,
    activation_evidence_lease_expires_at:
      value.expectedAuthority.activation_evidence_lease_expires_at,
  });
  return {
    ...value,
    executor,
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

test("L v4 binds five private quote transcripts and activation leases without claiming external egress", () => {
  const { receipt, expectedAuthority } = fixture();
  const normalized = normalizePhalaSevenCvmLaunchCompletionReceipt(receipt, {
    expectedAuthority,
  });
  assert.equal(normalized.schema, PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA);
  assert.equal(PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_DOMAIN.endsWith("/v4\0"), true);
  assert.equal(
    normalized.activation_evidence_lease_expires_at,
    Math.min(...normalized.domains.map((entry) => (
      entry.activation_evidence_lease_expires_at
    ))),
  );
  assert.equal(
    normalized.private_historical_identity_response_quote_bytes_persisted,
    true,
  );
  assert.equal(normalized.raw_quote_external_egress, false);
  assert.equal(normalized.raw_private_artifact_egress, false);
  assert.equal(normalized.domains.filter((entry) => (
    entry.private_historical_transcript_contains_quote_bytes
  )).length, 5);
  assert.equal(normalized.domains.filter((entry) => (
    entry.tdx_measurements_sha256 !== null
  )).length, 5);
  assert.match(
    canonicalPhalaSevenCvmLaunchCompletionReceiptText(receipt, {
      expectedAuthority,
    }),
    /private_historical_identity_response_quote_bytes_persisted/,
  );
});

test("L v4 rejects missing measurements and false private-quote claims", () => {
  const missingMeasurements = fixture();
  const identity = missingMeasurements.receipt.domains.find((entry) => (
    entry.machine_evidence_kind === "qvl_identity_local_dcap_verification"
  ));
  identity.tdx_measurements_sha256 = null;
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(
      missingMeasurements.receipt,
      { expectedAuthority: missingMeasurements.expectedAuthority },
    ),
    /observed TDX measurements/i,
  );
  const falsePersistence = fixture();
  falsePersistence.receipt
    .private_historical_identity_response_quote_bytes_persisted = false;
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(
      falsePersistence.receipt,
      { expectedAuthority: falsePersistence.expectedAuthority },
    ),
    /authority or posture/i,
  );
});

test("L and embedded release authority reject impossible UTC dates", () => {
  for (const impossible of [
    "2026-02-30T10:00:00Z",
    "2026-04-31T10:00:00Z",
    "2026-12-31T23:59:60Z",
  ]) {
    const launch = fixture();
    launch.expectedAuthority.bootstrap_authorization_issued_at = impossible;
    assert.throws(
      () => normalizePhalaSevenCvmLaunchCompletionReceipt(launch.receipt, {
        expectedAuthority: launch.expectedAuthority,
      }),
      /canonical UTC second/,
    );

    const releaseAuthority = structuredClone(
      fixture().expectedAuthority.release_verification_authority,
    );
    releaseAuthority.descriptors[0].posture_observed_at = impossible;
    assert.throws(
      () => normalizePhalaSevenCvmReleaseVerificationAuthority(
        releaseAuthority,
      ),
      /canonical UTC second/,
    );
  }

  const leapDayAuthority = structuredClone(
    fixture().expectedAuthority.release_verification_authority,
  );
  leapDayAuthority.descriptors[0].posture_observed_at =
    "2024-02-29T10:00:00Z";
  assert.equal(
    normalizePhalaSevenCvmReleaseVerificationAuthority(leapDayAuthority)
      .descriptors[0].posture_observed_at,
    "2024-02-29T10:00:00Z",
  );
});

test("L v4 cross-checks every release resource field", () => {
  for (const [field, replacement] of [
    ["kms_id", "kms-tampered-01"],
    ["instance_type", "tdx.tampered"],
    ["disk_size", 999],
    ["committed_compose_hash", "fe".repeat(32)],
    ["production_posture_verification_receipt_sha256", sha(999)],
  ]) {
    const { receipt, expectedAuthority } = fixture();
    receipt.domains[0][field] = replacement;
    assert.throws(
      () => normalizePhalaSevenCvmLaunchCompletionReceipt(receipt, {
        expectedAuthority,
      }),
      /external authority|release resource authority/i,
      field,
    );
  }
});

test("historical L reconstruction is synchronous, unbranded, and exact", () => {
  const value = historicalFixture();
  const result = reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency({
    persistedReceipt: value.receipt,
    persistedExecutorFinalState: value.executor,
    historicalPreCeremonyRuntimeBinding: value.runtimeBinding,
    historicalBootstrapAuthorizationBinding: value.bootstrapBinding,
  });
  assert.equal(result.receipt.schema, PHALA_SEVEN_CVM_LAUNCH_COMPLETION_RECEIPT_SCHEMA);
  assert.equal(result.receipt_sha256,
    value.runtimeBinding.seven_cvm_launch_completion_receipt_sha256);
  assert.equal(result.freshness_renewed, false);
  assert.equal(result.production_brand_minted, false);
  assert.equal(result.live_traffic_authorized, false);
  assert.equal(Object.hasOwn(result, "launch_completion_options"), false);
});

test("historical L rejects accessors before execution and has a pure closure", () => {
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, "persistedReceipt", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return {};
    },
  });
  assert.throws(
    () => reconstructPersistedPhalaSevenCvmLaunchCompletionHistoricalDependency(
      accessor,
    ),
    /canonical plain-data graph/i,
  );
  assert.equal(getterCalls, 0);

  const { receipt } = fixture();
  const optionAccessor = Object.defineProperty({}, "expectedAuthority", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return {};
    },
  });
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(
      receipt,
      optionAccessor,
    ),
    /canonical plain-data graph/i,
  );
  assert.equal(getterCalls, 0);

  const sources = [
    "phala-seven-cvm-launch-completion-core.mjs",
    "phala-seven-cvm-historical-runtime-binding-core.mjs",
    "phala-executor-state-core.mjs",
    "phala-production-posture-core.mjs",
    "phala-seven-cvm-historical-transcript.mjs",
    "phala-seven-cvm-release-verification-authority-core.mjs",
    "cvm-descriptor-runtime-authority-core.mjs",
    "phala-seven-cvm-measurement-policy.mjs",
    "cvm-launch-intent-core.mjs",
  ].map((basename) => readFileSync(
    new URL(`./${basename}`, import.meta.url),
    "utf8",
  )).join("\n");
  for (const forbidden of [
    "node:fs",
    "node:path",
    "node:os",
    "node:child_process",
    "Date.now",
    "process.",
    "WeakMap",
    "import(",
  ]) assert.equal(sources.includes(forbidden), false, forbidden);
});

test("domain v4 schema is distinct from the superseded v3 shape", () => {
  assert.equal(
    PHALA_CVM_DOMAIN_LAUNCH_COMPLETION_EVIDENCE_SCHEMA,
    "dnai.phala-cvm-domain-launch-completion-evidence.v4",
  );
  const { receipt, expectedAuthority } = fixture();
  receipt.domains[0].schema =
    "dnai.phala-cvm-domain-launch-completion-evidence.v2";
  assert.throws(
    () => normalizePhalaSevenCvmLaunchCompletionReceipt(receipt, {
      expectedAuthority,
    }),
    /schema or status/i,
  );
});
