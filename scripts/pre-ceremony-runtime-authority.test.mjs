import assert from "node:assert/strict";
import test from "node:test";

import {
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_CLI_FLAG,
  PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
  PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
  canonicalPreCeremonyRuntimeAuthorityText,
  createPreCeremonyRuntimeAuthority,
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority.mjs";
import {
  syntheticHistoricalTranscriptFileSetFixture,
  syntheticPostMeasurementActivationPlanFixture,
  syntheticPreCeremonyRuntimeAuthorityFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";

const sha = (digit) => `sha256:${digit.repeat(64)}`;

function planFixture() {
  return syntheticPostMeasurementActivationPlanFixture();
}

function authorityFixture() {
  return syntheticPreCeremonyRuntimeAuthorityFixture();
}

function historicalTranscriptFixture() {
  return syntheticHistoricalTranscriptFileSetFixture();
}

test("R v4 commits exact L and the combined future O policy without containing O", () => {
  const authority = authorityFixture();
  const plan = authority.post_measurement_activation_plan;
  assert.equal(PRE_CEREMONY_RUNTIME_AUTHORITY_CLI_FLAG,
    "--runtime-authority-dependency");
  assert.equal(PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
    "dnai-wikigen/pre-ceremony-runtime-authority/v4\0");
  assert.equal(authority.schema, PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA);
  assert.deepEqual(Object.keys(authority), [
    "schema", "status", "truth_status", "release_sha", "chain_id",
    "issued_at", "machine_verifier_evidence_issued_at",
    "activation_evidence_lease_expires_at", "proofs_valid_at_issuance",
    "deployment_intent_sha256", "cvm_launch_intent_sha256",
    "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "phala_recovery_directory_identity_anchor_sha256",
    "historical_transcript_file_set_sha256",
    "post_measurement_activation_plan_sha256",
    "post_measurement_activation_plan",
    "future_activation_authorization_transcript_policy",
    "activation_execution_authorized", "live_traffic_authorized",
    "contains_activation_observation", "contains_activation_execution_receipt",
    "private_historical_identity_response_quote_bytes_persisted",
    "raw_quote_external_egress", "raw_private_artifact_egress",
    "raw_secret_egress",
  ]);
  assert.equal(authority.seven_cvm_launch_completion_receipt_sha256,
    plan.seven_cvm_launch_completion_receipt_sha256);
  assert.equal(authority.post_measurement_activation_plan_sha256,
    phalaPostMeasurementActivationPlanSha256(plan));
  assert.equal(authority.historical_transcript_file_set_sha256,
    phalaSevenCvmHistoricalTranscriptFileSetSha256(
      historicalTranscriptFixture(),
    ));
  assert.deepEqual(
    authority.future_activation_authorization_transcript_policy
      .historical_transcript_flag_order,
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  );
  assert.deepEqual(
    authority.future_activation_authorization_transcript_policy
      .required_observation_lineage_fields,
    PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
  );
  assert.deepEqual(
    authority.future_activation_authorization_transcript_policy
      .required_observation_verification_fields,
    PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
  );
  assert.equal(authority.contains_activation_observation, false);
  assert.equal(authority.contains_activation_execution_receipt, false);
  assert.equal(
    authority.private_historical_identity_response_quote_bytes_persisted,
    true,
  );
  assert.equal(authority.raw_quote_external_egress, false);
  assert.equal(authority.raw_private_artifact_egress, false);
  assert.equal(JSON.stringify(authority).includes("source_activation"), true);
  assert.equal(JSON.stringify(authority).includes("activation_artifact_sha256"), true);
  assert.equal(JSON.stringify(authority).includes("source_activation_sha256"), false);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .signed_ceremony_authorization_required, true);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .activation_execution_receipt_required, true);
  assert.deepEqual(
    authority.future_activation_authorization_transcript_policy
      .required_main_runtime_profile_activation,
    {
      profile_names: ["arena-runtime", "compute-execution"],
      compose_profiles_value: "arena-runtime,compute-execution",
    },
  );
  assert.equal(authority.future_activation_authorization_transcript_policy
    .post_restart_arena_runtime_authenticated_worker_presence_required, true);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .post_restart_compute_workload_source_activation_required, true);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .private_historical_identity_response_quote_bytes_persistence_required, true);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .raw_quote_external_egress_allowed, false);
  assert.equal(authority.future_activation_authorization_transcript_policy
    .raw_private_artifact_egress_allowed, false);
  assert.deepEqual(normalizePreCeremonyRuntimeAuthority(authority), authority);
  assert.deepEqual(JSON.parse(canonicalPreCeremonyRuntimeAuthorityText(authority)),
    authority);
  assert.match(preCeremonyRuntimeAuthoritySha256(authority),
    /^sha256:[0-9a-f]{64}$/);

  const historicalLaunchBinding =
    projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(authority);
  assert.deepEqual(Object.keys(historicalLaunchBinding), [
    "schema", "truth_status", "release_sha", "deployment_intent_sha256",
    "cvm_launch_intent_sha256", "release_verification_authority",
    "release_verification_authority_sha256",
    "seven_cvm_launch_completion_receipt_sha256",
    "phala_recovery_directory_identity_anchor_sha256", "batch_id",
    "seven_cvm_verified_evidence_set_sha256", "main_runtime_target",
    "activation_plan_created_at", "machine_verifier_evidence_issued_at",
    "activation_evidence_lease_expires_at",
  ]);
  assert.equal(historicalLaunchBinding.release_sha, authority.release_sha);
  assert.equal(
    historicalLaunchBinding.seven_cvm_launch_completion_receipt_sha256,
    authority.seven_cvm_launch_completion_receipt_sha256,
  );
  assert.equal(
    historicalLaunchBinding.phala_recovery_directory_identity_anchor_sha256,
    authority.phala_recovery_directory_identity_anchor_sha256,
  );
  assert.deepEqual(
    historicalLaunchBinding.main_runtime_target,
    authority.post_measurement_activation_plan.target,
  );
  assert.equal(Object.isFrozen(historicalLaunchBinding), true);
});

test("R v4 rejects combined-profile/L drift, downgrade, O injection, and authorization", () => {
  const authority = authorityFixture();
  const mutations = [
    (value) => { value.schema = "dnai.pre-ceremony-runtime-authority.v0"; },
    (value) => { value.unknown = true; },
    (value) => { value.live_traffic_authorized = true; },
    (value) => { value.activation_execution_authorized = true; },
    (value) => { value.contains_activation_observation = true; },
    (value) => { value.contains_activation_execution_receipt = true; },
    (value) => {
      value.private_historical_identity_response_quote_bytes_persisted = false;
    },
    (value) => { value.raw_quote_external_egress = true; },
    (value) => { value.raw_private_artifact_egress = true; },
    (value) => { value.raw_secret_egress = true; },
    (value) => { value.activation_observation_sha256 = sha("b"); },
    (value) => { value.seven_cvm_launch_completion_receipt_sha256 = sha("c"); },
    (value) => { value.proofs_valid_at_issuance = false; },
    (value) => {
      value.issued_at = value.activation_evidence_lease_expires_at;
    },
    (value) => {
      value.machine_verifier_evidence_issued_at = value.issued_at + 1;
    },
    (value) => { value.post_measurement_activation_plan_sha256 = sha("d"); },
    (value) => { value.post_measurement_activation_plan.restart.force = true; },
    (value) => {
      value.post_measurement_activation_plan.profile_activation.profile_names =
        ["compute-execution"];
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .signed_ceremony_authorization_required = false;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_main_runtime_profile_activation.profile_names.reverse();
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .post_restart_arena_runtime_authenticated_worker_presence_required =
          false;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .source_activation_schema =
        "dnai.compute.workload-recipient-activation.v1";
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .historical_transcript_flag_order.pop();
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_observation_lineage_fields
        .splice(1, 1);
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .pre_injection_attestation_sufficient =
        true;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .raw_quote_external_egress_allowed = true;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .raw_secret_egress_allowed = true;
    },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(authority);
    mutate(copy);
    assert.throws(() => normalizePreCeremonyRuntimeAuthority(copy));
  }
});

test("R production constructor refuses an unbranded normalized activation plan", () => {
  assert.throws(() => createPreCeremonyRuntimeAuthority({
    postMeasurementActivationPlan: planFixture(),
  }), /fresh dependency-reconstructed activation plan/);
});

test("R production constructor rejects accessors, prototypes, and extra options", () => {
  let getterExecuted = false;
  const accessorInput = {};
  Object.defineProperty(accessorInput, "postMeasurementActivationPlan", {
    enumerable: true,
    get() {
      getterExecuted = true;
      return planFixture();
    },
  });
  assert.throws(() => createPreCeremonyRuntimeAuthority(accessorInput),
    /accessors/);
  assert.equal(getterExecuted, false);

  assert.throws(() => createPreCeremonyRuntimeAuthority({
    postMeasurementActivationPlan: planFixture(),
    unexpected: true,
  }), /contain exactly postMeasurementActivationPlan/);

  const inherited = Object.create({ postMeasurementActivationPlan: planFixture() });
  assert.throws(() => createPreCeremonyRuntimeAuthority(inherited),
    /custom prototypes/);
});
