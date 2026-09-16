import { createHash } from "node:crypto";

import {
  assertPersistedComputeWorkloadActivationObservation,
  computeWorkloadActivationObservationSha256,
  computeWorkloadBrowserBindingSha256,
  projectComputeWorkloadBrowserBindingFromObservation,
} from "./compute-workload-activation-observation.mjs";
import {
  assertActivationExecutionReceiptMatchesComputeWorkloadObservation,
  liveActivationAuthoritySha256,
  normalizeLiveActivationAuthority,
} from "./release-authority-stages.mjs";
import {
  frontendBuildCandidateReceiptSha256,
  normalizeFrontendBuildCandidateReceipt,
} from "../web/scripts/frontend-build-candidate-core.mjs";

function fail(message) {
  throw new Error(message);
}

/**
 * Production-only fresh O/C binder.
 *
 * Keeping this function outside the pure Stage-C module prevents the fresh O
 * facade and mutation-capable activation receipt graph from entering the
 * historical exact-37 or Cloudflare source closure. No capability registrar
 * or caller-mintable production brand is exposed.
 */
export function assertLiveActivationComputeWorkloadObservationBinding({
  liveActivationAuthority,
  liveActivationOptions,
  persistedObservation,
  reconstructedObservation,
  frontendBuildCandidateReceipt,
  serializedEnv,
  checkedAt = Math.floor(Date.now() / 1_000),
} = {}) {
  const observation = assertPersistedComputeWorkloadActivationObservation({
    persistedObservation,
    reconstructedObservation,
    checkedAt,
  });
  const authority = normalizeLiveActivationAuthority(
    liveActivationAuthority,
    liveActivationOptions,
  );
  const buildReceipt = normalizeFrontendBuildCandidateReceipt(
    frontendBuildCandidateReceipt,
  );
  if (typeof serializedEnv !== "string" || serializedEnv.length < 2
    || !serializedEnv.endsWith("\n") || serializedEnv.includes("\r")) {
    fail("final C workload binding requires the exact normalized frontend environment bytes");
  }
  const observationSha256 = computeWorkloadActivationObservationSha256(observation);
  const browserBinding = projectComputeWorkloadBrowserBindingFromObservation(
    observation,
    { checkedAt },
  );
  const releaseEnvSha256 = `sha256:${createHash("sha256")
    .update(serializedEnv, "utf8")
    .digest("hex")}`;
  const buildReceiptSha256 = frontendBuildCandidateReceiptSha256(buildReceipt);
  const post = authority.post_ceremony_evidence;
  const activationExecutionReceipt =
    post.post_measurement_activation_execution_receipt;
  const activationExecutionReceiptSha256 =
    assertActivationExecutionReceiptMatchesComputeWorkloadObservation({
      activationExecutionReceipt,
      activationExecutionReceiptSha256:
        post.post_measurement_activation_execution_receipt_sha256,
      observation,
    });
  if (post.compute_workload_activation_observation_sha256 !== observationSha256
    || JSON.stringify(post.compute_workload_browser_binding)
      !== JSON.stringify(browserBinding)
    || post.frontend_release_env_sha256 !== releaseEnvSha256
    || post.frontend_build_candidate_receipt_sha256 !== buildReceiptSha256
    || post.frontend_build_sha256 !== buildReceipt.frontend_build_sha256
    || buildReceipt.compute_workload_activation_observation_sha256
      !== observationSha256
    || buildReceipt.release_env_sha256 !== releaseEnvSha256
    || buildReceipt.release_sha !== authority.release_sha
    || buildReceipt.ceremony_authorization_sha256
      !== authority.ceremony_authorization_sha256
    || buildReceipt.runtime_authority_dependency_sha256
      !== liveActivationOptions?.ceremonyAuthorization
        ?.pre_ceremony_runtime_authority_sha256) {
    fail("final C does not exact-bind the reverified O, deterministic environment, and D receipt");
  }
  return Object.freeze({
    computeWorkloadActivationObservationSha256: observationSha256,
    computeWorkloadBrowserBindingSha256:
      computeWorkloadBrowserBindingSha256(browserBinding),
    postMeasurementActivationExecutionReceiptSha256:
      activationExecutionReceiptSha256,
    frontendReleaseEnvSha256: releaseEnvSha256,
    frontendBuildCandidateReceiptSha256: buildReceiptSha256,
    frontendBuildSha256: buildReceipt.frontend_build_sha256,
    liveActivationAuthoritySha256: liveActivationAuthoritySha256(
      liveActivationAuthority,
      liveActivationOptions,
    ),
  });
}
