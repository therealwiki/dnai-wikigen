import fs from "node:fs";
import path from "node:path";

import {
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  assertBrandedPhalaSevenCvmReleaseVerificationAuthority,
  assertProductionPhalaComputeWorkloadRecipientActivation,
  assertVerifiedPhalaComputeWorkloadRecipientActivation,
  phalaComputeWorkloadRecipientActivationVerificationSha256,
  phalaComputeWorkloadRecipientSourceActivationSha256,
  phalaSevenCvmReleaseVerificationAuthoritySha256,
} from "./phala-seven-cvm-verifier-evidence.mjs";
import {
  PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE,
  normalizePhalaSevenCvmReleaseVerificationAuthority,
} from "./phala-seven-cvm-release-verification-authority-core.mjs";
import {
  assertProductionPhalaPostMeasurementActivationExecutionReceipt,
  phalaPostMeasurementActivationExecutionReceiptSha256,
  readFinalizedProductionPhalaPostMeasurementActivationExecutionIdentity,
  readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies,
  readProductionPhalaPostMeasurementActivationExecutionDependencies,
} from "./phala-post-measurement-activation-receipt.mjs";
import {
  __coreTest,
  computeWorkloadActivationObservationSha256,
  createUnbrandedComputeWorkloadActivationObservationCandidate,
  normalizeComputeWorkloadActivationObservation,
  projectComputeWorkloadBrowserEnvFromBinding,
  projectNormalizedComputeWorkloadBrowserBinding,
} from "./compute-workload-activation-observation-core.mjs";

export * from "./compute-workload-activation-observation-core.mjs";

const CHAIN_ID = 84_532;
const VERIFIED_OBSERVATIONS = new WeakMap();
const OBSERVATION_PREFLIGHTS = new WeakMap();

function fail(message) {
  throw new Error(message);
}

function exactOptions(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the frozen fields`);
  }
  return value;
}

function canonicalText(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function second(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail(`${label} must be a positive epoch second`);
  }
  return value;
}

function prepareObservationCandidate({
  activationVerification,
  releaseVerificationAuthority,
  authorityBinding,
  expectedObservationAuthoritySha256 = null,
  expectedReceiptSha256,
  testOnly = false,
}) {
  const normalized = deepFreezeCanonicalPlainDataGraph(
    createUnbrandedComputeWorkloadActivationObservationCandidate({
      activationVerification,
      releaseVerificationAuthority,
      authorityBinding,
    }),
    { label: "prepared compute-workload activation observation" },
  );
  if (normalized.lineage.post_measurement_activation_execution_receipt_sha256
      !== expectedReceiptSha256) {
    fail("prepared Compute O differs from its activation receipt preflight");
  }
  const token = Object.freeze({});
  OBSERVATION_PREFLIGHTS.set(token, Object.freeze({
    candidate: normalized,
    candidate_sha256: computeWorkloadActivationObservationSha256(normalized),
    observation_authority_sha256: expectedObservationAuthoritySha256,
    receipt_sha256: expectedReceiptSha256,
    test_only: testOnly,
  }));
  return token;
}

function finalizePreparedObservation(preflightToken, receiptSha256, {
  observationAuthoritySha256 = null,
  testOnly,
}) {
  const prepared = preflightToken && OBSERVATION_PREFLIGHTS.get(preflightToken);
  if (!prepared || prepared.test_only !== testOnly) {
    fail("an opaque locally prepared Compute O preflight token is required");
  }
  if (receiptSha256 !== prepared.receipt_sha256
    || observationAuthoritySha256 !== prepared.observation_authority_sha256
    || prepared.candidate.lineage
      .post_measurement_activation_execution_receipt_sha256 !== receiptSha256) {
    fail(
      "final activation receipt or reviewed observation authority differs from the prepared Compute O binding",
    );
  }
  if (!testOnly) {
    const now = Math.floor(Date.now() / 1_000);
    if (now < prepared.candidate.verification.verified_at
      || now >= prepared.candidate.terminal_evidence_lease_expires_at) {
      fail(
        "Compute O terminal evidence lease expired before finalization",
      );
    }
  }
  VERIFIED_OBSERVATIONS.set(prepared.candidate, prepared.candidate_sha256);
  OBSERVATION_PREFLIGHTS.delete(preflightToken);
  return prepared.candidate;
}

export function assertVerifiedComputeWorkloadActivationObservation(value, {
  checkedAt = Math.floor(Date.now() / 1_000),
} = {}) {
  const expected = VERIFIED_OBSERVATIONS.get(value);
  if (!expected || computeWorkloadActivationObservationSha256(value) !== expected) {
    fail("compute-workload activation observation was not reconstructed from branded production evidence");
  }
  const normalized = normalizeComputeWorkloadActivationObservation(value);
  const now = second(checkedAt, "compute-workload observation recheck time");
  if (now < normalized.verification.verified_at
    || now >= normalized.terminal_evidence_lease_expires_at
    || now - normalized.verification.verdict_issued_at
      > normalized.ingress_policy.max_verdict_age_seconds) {
    fail("compute-workload activation observation is not current at revalidation time");
  }
  return value;
}

export function assertPersistedComputeWorkloadActivationObservation({
  persistedObservation,
  reconstructedObservation,
  checkedAt = Math.floor(Date.now() / 1_000),
} = {}) {
  const reconstructed = assertVerifiedComputeWorkloadActivationObservation(
    reconstructedObservation,
    { checkedAt },
  );
  const persisted = normalizeComputeWorkloadActivationObservation(persistedObservation);
  if (canonicalText(persisted) !== canonicalText(reconstructed)
    || computeWorkloadActivationObservationSha256(persisted)
      !== computeWorkloadActivationObservationSha256(reconstructed)) {
    fail("persisted compute-workload observation does not equal its fresh reconstruction");
  }
  return reconstructed;
}

export function projectComputeWorkloadBrowserBindingFromObservation(value, options) {
  const observation = assertVerifiedComputeWorkloadActivationObservation(value, options);
  return deepFreezeCanonicalPlainDataGraph(
    projectNormalizedComputeWorkloadBrowserBinding(observation),
    { label: "compute-workload browser binding" },
  );
}

export function projectComputeWorkloadBrowserEnvFromObservation(value, options) {
  return projectComputeWorkloadBrowserEnvFromBinding(
    projectComputeWorkloadBrowserBindingFromObservation(value, options),
  );
}

export function prepareProductionComputeWorkloadActivationObservation(options = {}) {
  const parsed = exactOptions(options, [
    "activationExecutionReceiptPreflightToken",
    "activationVerification",
    "releaseVerificationAuthority",
  ], "production compute-workload O preflight options");
  const receiptDependencies =
    readPreparedProductionPhalaPostMeasurementActivationExecutionDependencies(
      parsed.activationExecutionReceiptPreflightToken,
    );
  const activation = assertProductionPhalaComputeWorkloadRecipientActivation(
    parsed.activationVerification,
  );
  const releaseAuthority =
    assertBrandedPhalaSevenCvmReleaseVerificationAuthority(
      parsed.releaseVerificationAuthority,
    );
  if (phalaComputeWorkloadRecipientActivationVerificationSha256(activation)
      !== receiptDependencies.compute_recipient_activation_sha256
    || phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority)
      !== receiptDependencies.release_verification_authority_sha256) {
    fail("Compute O proof authority differs from its activation receipt preflight");
  }
  return prepareObservationCandidate({
    activationVerification: activation,
    releaseVerificationAuthority: releaseAuthority,
    authorityBinding:
      receiptDependencies.compute_workload_observation_binding,
    expectedObservationAuthoritySha256:
      receiptDependencies.compute_workload_observation_authority_sha256,
    expectedReceiptSha256:
      receiptDependencies.post_measurement_activation_execution_receipt_sha256,
  });
}

export function finalizeProductionComputeWorkloadActivationObservation(options = {}) {
  const parsed = exactOptions(options, [
    "activationExecutionReceipt",
    "preflightToken",
  ], "production compute-workload O finalization options");
  const receiptIdentity =
    readFinalizedProductionPhalaPostMeasurementActivationExecutionIdentity(
      parsed.activationExecutionReceipt,
    );
  return finalizePreparedObservation(
    parsed.preflightToken,
    receiptIdentity.post_measurement_activation_execution_receipt_sha256,
    {
      observationAuthoritySha256:
        receiptIdentity.compute_workload_observation_authority_sha256,
      testOnly: false,
    },
  );
}

export async function createComputeWorkloadActivationObservation(options = {}) {
  const parsed = exactOptions(options, [
    "activationExecutionReceipt",
    "capabilityEndpoint",
    "ingressPolicy",
  ], "production compute-workload O constructor options");
  const receipt =
    assertProductionPhalaPostMeasurementActivationExecutionReceipt(
      parsed.activationExecutionReceipt,
    );
  const dependencies =
    readProductionPhalaPostMeasurementActivationExecutionDependencies(receipt);
  const activation = assertProductionPhalaComputeWorkloadRecipientActivation(
    dependencies.recipient_activation,
  );
  const releaseAuthority =
    assertBrandedPhalaSevenCvmReleaseVerificationAuthority(
      dependencies.release_verification_authority,
    );
  const runtimeAuthority = dependencies.pre_ceremony_runtime_authority;
  const plan = dependencies.plan;
  const ceremonyAuthorization = dependencies.ceremony_authorization;
  const reviewedObservationAuthority =
    dependencies.compute_workload_observation_authority;
  if (parsed.capabilityEndpoint
      !== reviewedObservationAuthority.capabilityEndpoint
    || canonicalText(parsed.ingressPolicy)
      !== canonicalText(reviewedObservationAuthority.ingressPolicy)) {
    fail("production O endpoint or ingress policy differs from reviewed receipt authority");
  }
  const releaseAuthoritySha256 =
    phalaSevenCvmReleaseVerificationAuthoritySha256(releaseAuthority);
  const activationVerificationSha256 =
    phalaComputeWorkloadRecipientActivationVerificationSha256(activation);
  const sourceActivationSha256 =
    phalaComputeWorkloadRecipientSourceActivationSha256(
      activation.source_activation,
    );
  const target = receipt.target;
  if (receipt.release_sha !== releaseAuthority.release_sha
    || receipt.release_sha !== runtimeAuthority.release_sha
    || receipt.deployment_intent_sha256
      !== releaseAuthority.deployment_intent_sha256
    || receipt.deployment_intent_sha256
      !== runtimeAuthority.deployment_intent_sha256
    || receipt.release_verification_authority_sha256 !== releaseAuthoritySha256
    || receipt.seven_cvm_launch_completion_receipt_sha256
      !== runtimeAuthority.seven_cvm_launch_completion_receipt_sha256
    || receipt.seven_cvm_launch_completion_receipt_sha256
      !== plan.seven_cvm_launch_completion_receipt_sha256
    || receipt.post_measurement_activation_plan_sha256
      !== runtimeAuthority.post_measurement_activation_plan_sha256
    || ceremonyAuthorization.pre_ceremony_runtime_authority_sha256
      !== receipt.pre_ceremony_runtime_authority_sha256
    || ceremonyAuthorization.cvm_launch_intent_sha256
      !== receipt.cvm_launch_intent_sha256
    || activationVerificationSha256
      !== receipt.recipient_activation.activation_verification_sha256
    || sourceActivationSha256
      !== receipt.recipient_activation.source_activation_sha256
    || activation.release_authority_sha256 !== releaseAuthoritySha256
    || activation.deployment_intent_sha256
      !== receipt.deployment_intent_sha256
    || activation.app_id !== target.app_id
    || activation.cvm_id !== target.cvm_id
    || activation.compose_hash !== target.compose_hash
    || activation.os_image_hash !== target.os_image_hash) {
    fail("production O execution receipt and branded L/R/B/plan/activation dependencies drifted");
  }
  const preflightToken = prepareObservationCandidate({
    activationVerification: activation,
    releaseVerificationAuthority: releaseAuthority,
    authorityBinding: dependencies.compute_workload_observation_binding,
    expectedObservationAuthoritySha256:
      dependencies.compute_workload_observation_authority_sha256,
    expectedReceiptSha256:
      phalaPostMeasurementActivationExecutionReceiptSha256(receipt),
  });
  return finalizeProductionComputeWorkloadActivationObservation({
    preflightToken,
    activationExecutionReceipt: receipt,
  });
}

function isExactNodeTestEntrypoint() {
  const entrypoint = process.argv[1];
  if (process.env.NODE_TEST_CONTEXT !== "child-v8"
    || typeof entrypoint !== "string" || !entrypoint.endsWith(".test.mjs")) {
    return false;
  }
  try {
    return path.resolve(entrypoint) === fs.realpathSync.native(entrypoint);
  } catch {
    return false;
  }
}

function prepareSyntheticComputeWorkloadActivationObservation(options = {}) {
  if (!isExactNodeTestEntrypoint()) {
    fail("synthetic O preflight is available only inside node --test");
  }
  const activation = assertVerifiedPhalaComputeWorkloadRecipientActivation(
    options.activationVerification,
  );
  const releaseAuthority = normalizePhalaSevenCvmReleaseVerificationAuthority(
    options.releaseVerificationAuthority,
  );
  if (releaseAuthority.evidence_mode
    !== PHALA_VERIFIER_EVIDENCE_SYNTHETIC_MODE) {
    fail("synthetic O construction requires explicitly synthetic release evidence");
  }
  return prepareObservationCandidate({
    activationVerification: activation,
    releaseVerificationAuthority: releaseAuthority,
    authorityBinding: options.authorityBinding,
    expectedObservationAuthoritySha256:
      options.observationAuthoritySha256 ?? null,
    expectedReceiptSha256:
      options.authorityBinding
        ?.post_measurement_activation_execution_receipt_sha256,
    testOnly: true,
  });
}

function finalizeSyntheticComputeWorkloadActivationObservation(options = {}) {
  if (!isExactNodeTestEntrypoint()) {
    fail("synthetic O finalization is available only inside node --test");
  }
  const parsed = exactOptions(options, [
    "observationAuthoritySha256",
    "preflightToken",
    "receiptSha256",
  ], "synthetic compute-workload O finalization options");
  return finalizePreparedObservation(
    parsed.preflightToken,
    parsed.receiptSha256,
    {
      observationAuthoritySha256: parsed.observationAuthoritySha256,
      testOnly: true,
    },
  );
}

function createSyntheticComputeWorkloadActivationObservation(options = {}) {
  const preflightToken =
    prepareSyntheticComputeWorkloadActivationObservation(options);
  return finalizeSyntheticComputeWorkloadActivationObservation({
    observationAuthoritySha256: options.observationAuthoritySha256 ?? null,
    preflightToken,
    receiptSha256:
      options.authorityBinding
        .post_measurement_activation_execution_receipt_sha256,
  });
}

export const __test = Object.freeze({
  CHAIN_ID,
  createSyntheticComputeWorkloadActivationObservation,
  finalizeSyntheticComputeWorkloadActivationObservation,
  prepareSyntheticComputeWorkloadActivationObservation,
  projectNormalizedBrowserBinding:
    __coreTest.projectNormalizedBrowserBinding,
});
