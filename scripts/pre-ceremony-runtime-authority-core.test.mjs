import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  PHALA_OS_IMAGE_CATALOG_ENTRY,
} from "./cvm-launch-intent-core.mjs";
import {
  PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA,
  phalaPostMeasurementActivationPlanSha256,
} from "./phala-post-measurement-activation-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  normalizePhalaSevenCvmHistoricalRuntimeBinding,
} from "./phala-seven-cvm-historical-runtime-binding-core.mjs";
import {
  PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER,
  createPhalaSevenCvmHistoricalTranscriptFileSet,
  phalaSevenCvmHistoricalTranscriptFileSetSha256,
} from "./phala-seven-cvm-historical-transcript.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  syntheticPhalaSevenCvmReleaseDescriptorsFixture,
  syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture,
} from "./phala-seven-cvm-release-verification-authority.fixture.mjs";
import {
  FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
  PRE_CEREMONY_REQUIRED_OBSERVATION_LINEAGE_FIELDS,
  PRE_CEREMONY_REQUIRED_OBSERVATION_VERIFICATION_FIELDS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
  PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
  PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
  PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
  assertPersistedPreCeremonyRuntimeAuthority,
  canonicalPreCeremonyRuntimeAuthorityText,
  futureActivationAuthorizationTranscriptPolicy,
  normalizePreCeremonyRuntimeAuthority,
  preCeremonyRuntimeAuthoritySha256,
  projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding,
} from "./pre-ceremony-runtime-authority-core.mjs";
import {
  syntheticPostMeasurementActivationPlanFixture,
} from "./pre-ceremony-runtime-authority.fixture.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));

function localModuleClosure(entrypoint) {
  const seen = new Set();
  function visit(filename) {
    const resolved = fs.realpathSync(filename);
    if (seen.has(resolved)) return;
    seen.add(resolved);
    const source = fs.readFileSync(resolved, "utf8");
    assert.doesNotMatch(
      source,
      /from\s+["']node:(?:fs|path|os|child_process)(?:\/[^"']*)?["']/,
    );
    assert.doesNotMatch(source, /\bWeakMap\b/);
    assert.doesNotMatch(source, /\bDate\.now\s*\(/);
    assert.doesNotMatch(source, /\bprocess\s*\./);
    assert.doesNotMatch(source, /\bimport\s*\(/);
    for (const match of source.matchAll(/from\s+["'](\.\.?\/[^"']+)["']/g)) {
      const dependency = path.resolve(path.dirname(resolved), match[1]);
      if (dependency.startsWith(HERE) && dependency.endsWith(".mjs")) {
        visit(dependency);
      }
    }
  }
  visit(entrypoint);
  return [...seen].sort();
}

function historicalTranscriptFixture() {
  return createPhalaSevenCvmHistoricalTranscriptFileSet(Object.fromEntries(
    PHALA_SEVEN_CVM_HISTORICAL_TRANSCRIPT_FLAG_ORDER.map((flag, index) => [
      flag,
      {
        sha256:
          `sha256:${(index + 17).toString(16).padStart(2, "0").repeat(32)}`,
        size: 1_000 + index,
      },
    ]),
  ));
}

function authorityFixture() {
  const releaseSha = "a".repeat(40);
  const deploymentIntentSha256 = `sha256:${"22".repeat(32)}`;
  const syntheticReleaseAuthority =
    syntheticPhalaSevenCvmReleaseVerificationAuthorityFixture({
      releaseSha,
      deploymentIntentSha256,
      ceremonyNonce: `0x${"11".repeat(32)}`,
      releaseDescriptors: syntheticPhalaSevenCvmReleaseDescriptorsFixture({
        mainRuntime: {
          descriptor_sha256: `sha256:${"aa".repeat(32)}`,
          app_id: "bb".repeat(20),
          cvm_id: "cvm-main-0001",
          compose_hash: "cc".repeat(32),
          os_image_hash: PHALA_OS_IMAGE_CATALOG_ENTRY.os_image_hash,
        },
      }),
    });
  const releaseVerificationAuthority =
    normalizePhalaSevenCvmReleaseVerificationAuthority({
      ...structuredClone(syntheticReleaseAuthority),
      evidence_mode: PHALA_VERIFIER_EVIDENCE_PRODUCTION_MODE,
    });
  const plan = syntheticPostMeasurementActivationPlanFixture({
    releaseSha,
    deploymentIntentSha256,
    releaseVerificationAuthority,
  });
  const transcriptFileSet = historicalTranscriptFixture();
  const issuedAt = Math.floor(Date.parse(plan.created_at) / 1_000);
  const authority = normalizePreCeremonyRuntimeAuthority({
    schema: PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
    status: PRE_CEREMONY_RUNTIME_AUTHORITY_STATUS,
    truth_status: PRE_CEREMONY_RUNTIME_AUTHORITY_TRUTH,
    release_sha: plan.release_sha,
    chain_id: 84_532,
    issued_at: issuedAt,
    machine_verifier_evidence_issued_at: issuedAt - 1,
    activation_evidence_lease_expires_at:
      plan.activation_evidence_lease_expires_at,
    proofs_valid_at_issuance: true,
    deployment_intent_sha256: plan.deployment_intent_sha256,
    cvm_launch_intent_sha256: plan.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      plan.release_verification_authority_sha256,
    seven_cvm_launch_completion_receipt_sha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    historical_transcript_file_set_sha256:
      phalaSevenCvmHistoricalTranscriptFileSetSha256(transcriptFileSet),
    post_measurement_activation_plan_sha256:
      phalaPostMeasurementActivationPlanSha256(plan),
    post_measurement_activation_plan: plan,
    future_activation_authorization_transcript_policy:
      futureActivationAuthorizationTranscriptPolicy(),
    activation_execution_authorized: false,
    live_traffic_authorized: false,
    contains_activation_observation: false,
    contains_activation_execution_receipt: false,
    private_historical_identity_response_quote_bytes_persisted: true,
    raw_quote_external_egress: false,
    raw_private_artifact_egress: false,
    raw_secret_egress: false,
  });
  return { authority, plan, transcriptFileSet, issuedAt };
}

test("R v4 commits activation-plan v4 and the complete combined future policy v4", () => {
  const { authority, plan } = authorityFixture();
  assert.equal(PRE_CEREMONY_RUNTIME_AUTHORITY_SCHEMA,
    "dnai.pre-ceremony-runtime-authority.v4");
  assert.equal(PRE_CEREMONY_RUNTIME_AUTHORITY_DOMAIN,
    "dnai-wikigen/pre-ceremony-runtime-authority/v4\0");
  assert.equal(plan.schema, PHALA_POST_MEASUREMENT_ACTIVATION_PLAN_SCHEMA);
  assert.equal(plan.schema, "dnai.phala-post-measurement-activation-plan.v4");
  assert.equal(
    authority.future_activation_authorization_transcript_policy.schema,
    FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
  );
  assert.equal(
    FUTURE_WORKLOAD_ACTIVATION_AUTHORIZATION_TRANSCRIPT_POLICY_SCHEMA,
    "dnai.future-workload-activation-authorization-transcript-policy.v4",
  );
  assert.deepEqual(
    authority.future_activation_authorization_transcript_policy
      .required_main_runtime_profile_activation,
    {
      profile_names: ["arena-runtime", "compute-execution"],
      compose_profiles_value: "arena-runtime,compute-execution",
    },
  );
  assert.equal(
    authority.future_activation_authorization_transcript_policy
      .post_restart_arena_runtime_authenticated_worker_presence_required,
    true,
  );
  assert.equal(
    authority.future_activation_authorization_transcript_policy
      .arena_worker_presence_evidence_classification,
    "authenticated_worker_presence_not_tdx_attestation",
  );
  assert.equal(
    authority.future_activation_authorization_transcript_policy
      .private_historical_identity_response_quote_bytes_persistence_required,
    true,
  );
  assert.equal(
    authority.future_activation_authorization_transcript_policy
      .raw_quote_external_egress_allowed,
    false,
  );
  assert.equal(
    authority.future_activation_authorization_transcript_policy
      .raw_private_artifact_egress_allowed,
    false,
  );
  assert.equal(
    authority.private_historical_identity_response_quote_bytes_persisted,
    true,
  );
  assert.equal(authority.raw_quote_external_egress, false);
  assert.equal(authority.raw_private_artifact_egress, false);
  assert.equal(
    Object.hasOwn(
      authority.future_activation_authorization_transcript_policy,
      "raw_quote_persistence_allowed",
    ),
    false,
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
  assert.deepEqual(normalizePreCeremonyRuntimeAuthority(authority), authority);
  assert.equal(Object.isFrozen(authority), true);
  assert.equal(Object.isFrozen(authority.post_measurement_activation_plan), true);
  assert.deepEqual(
    JSON.parse(canonicalPreCeremonyRuntimeAuthorityText(authority)),
    authority,
  );
  assert.match(
    preCeremonyRuntimeAuthoritySha256(authority),
    /^sha256:[0-9a-f]{64}$/,
  );
});

test("R v4 historical projection carries the exact embedded release authority and lease", () => {
  const { authority, plan } = authorityFixture();
  const binding = projectPreCeremonyRuntimeAuthorityHistoricalLaunchBinding(
    authority,
  );
  assert.equal(
    binding.schema,
    PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_SCHEMA,
  );
  assert.equal(
    binding.truth_status,
    PHALA_SEVEN_CVM_HISTORICAL_RUNTIME_BINDING_TRUTH,
  );
  assert.deepEqual(
    binding.release_verification_authority,
    plan.release_verification_authority,
  );
  assert.equal(
    binding.release_verification_authority_sha256,
    plan.release_verification_authority_sha256,
  );
  assert.deepEqual(binding.main_runtime_target, plan.target);
  assert.equal(
    binding.machine_verifier_evidence_issued_at,
    authority.machine_verifier_evidence_issued_at,
  );
  assert.deepEqual(
    normalizePhalaSevenCvmHistoricalRuntimeBinding(binding),
    binding,
  );
  assert.equal(Object.isFrozen(binding), true);
});

test("R v4 rejects policy downgrade, profile drift, authority drift, and activation claims", () => {
  const mutations = [
    (value) => { value.schema = "dnai.pre-ceremony-runtime-authority.v1"; },
    (value) => {
      value.future_activation_authorization_transcript_policy.schema =
        "dnai.future-workload-activation-authorization-transcript-policy.v1";
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_main_runtime_profile_activation.profile_names.reverse();
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_main_runtime_profile_activation.profile_names.pop();
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_main_runtime_profile_activation.profile_names
        .push("deal-settlement");
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .required_main_runtime_profile_activation.compose_profiles_value =
          "compute-execution";
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .post_restart_arena_runtime_authenticated_worker_presence_required =
          false;
    },
    (value) => { value.release_verification_authority_sha256 = `sha256:${"41".repeat(32)}`; },
    (value) => { value.post_measurement_activation_plan_sha256 = `sha256:${"42".repeat(32)}`; },
    (value) => { value.post_measurement_activation_plan.target.cvm_id = "synthetic-main-drift-01"; },
    (value) => { value.activation_execution_authorized = true; },
    (value) => { value.contains_activation_observation = true; },
    (value) => { value.contains_activation_execution_receipt = true; },
    (value) => { value.live_traffic_authorized = true; },
    (value) => {
      value.private_historical_identity_response_quote_bytes_persisted = false;
    },
    (value) => { value.raw_quote_external_egress = true; },
    (value) => { value.raw_private_artifact_egress = true; },
    (value) => { value.raw_secret_egress = true; },
    (value) => {
      value.machine_verifier_evidence_issued_at =
        value.activation_evidence_lease_expires_at;
    },
    (value) => {
      value.machine_verifier_evidence_issued_at = value.issued_at + 1;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .private_historical_identity_response_quote_bytes_persistence_required =
          false;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .raw_quote_external_egress_allowed = true;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .raw_private_artifact_egress_allowed = true;
    },
    (value) => {
      value.future_activation_authorization_transcript_policy
        .raw_secret_egress_allowed = true;
    },
    (value) => { value.unknown = true; },
  ];
  for (const mutate of mutations) {
    const fixture = structuredClone(authorityFixture().authority);
    mutate(fixture);
    assert.throws(() => normalizePreCeremonyRuntimeAuthority(fixture));
  }
});

test("persisted R assertion consumes the reconstructed L digest without refreshing it", () => {
  const { authority, transcriptFileSet, issuedAt } = authorityFixture();
  const asserted = assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: authority,
    reconstructedLaunchCompletionReceiptSha256:
      authority.seven_cvm_launch_completion_receipt_sha256,
    reconstructedHistoricalTranscriptFileSet: transcriptFileSet,
    signedAtMs: issuedAt * 1_000,
    reviewExpiresAtMs: (issuedAt + 60) * 1_000,
  });
  assert.deepEqual(asserted, authority);
  assert.equal(Object.isFrozen(asserted), true);

  assert.throws(() => assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: authority,
    reconstructedLaunchCompletionReceiptSha256:
      `sha256:${"51".repeat(32)}`,
    reconstructedHistoricalTranscriptFileSet: transcriptFileSet,
    signedAtMs: issuedAt * 1_000,
    reviewExpiresAtMs: (issuedAt + 60) * 1_000,
  }), /does not match exact L\/transcript dependencies/);

  assert.throws(() => assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: authority,
    reconstructedLaunchCompletionReceiptSha256:
      authority.seven_cvm_launch_completion_receipt_sha256,
    reconstructedHistoricalTranscriptFileSet: transcriptFileSet,
    signedAtMs: (issuedAt * 1_000) + 0.5,
    reviewExpiresAtMs: (issuedAt + 60) * 1_000,
  }), /requires original signed-B timing/);

  assert.throws(() => assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: authority,
    reconstructedLaunchCompletionReceiptSha256:
      authority.seven_cvm_launch_completion_receipt_sha256,
    reconstructedHistoricalTranscriptFileSet: transcriptFileSet,
    signedAtMs: (issuedAt * 1_000) + 999,
    reviewExpiresAtMs: (issuedAt * 1_000) + 1,
  }), /does not match exact L\/transcript dependencies/);

  assert.deepEqual(assertPersistedPreCeremonyRuntimeAuthority({
    persistedAuthority: authority,
    reconstructedLaunchCompletionReceiptSha256:
      authority.seven_cvm_launch_completion_receipt_sha256,
    reconstructedHistoricalTranscriptFileSet: transcriptFileSet,
    signedAtMs: (issuedAt * 1_000) + 1,
    reviewExpiresAtMs: (issuedAt * 1_000) + 999,
  }), authority);
});

test("R core and its local import closure contain no clocks, effects, or brands", () => {
  const corePath = fileURLToPath(
    new URL("./pre-ceremony-runtime-authority-core.mjs", import.meta.url),
  );
  const closure = localModuleClosure(corePath);
  assert.ok(closure.includes(corePath));
  assert.ok(closure.some((entry) => entry.endsWith(
    "phala-post-measurement-activation-core.mjs",
  )));
  assert.ok(closure.some((entry) => entry.endsWith(
    "phala-seven-cvm-historical-runtime-binding-core.mjs",
  )));
  assert.equal(closure.some((entry) => entry.endsWith(
    "pre-ceremony-runtime-authority.mjs",
  )), false);
  assert.equal(closure.some((entry) => entry.endsWith(
    "phala-seven-cvm-launch-completion.mjs",
  )), false);
  assert.equal(closure.some((entry) => entry.endsWith(
    "phala-seven-cvm-verifier-evidence.mjs",
  )), false);
});
