import assert from "node:assert/strict";
import test from "node:test";

import {
  frontendBuildCandidateReceiptSha256 as pureReceiptSha256,
  normalizeFrontendBuildCandidateReceipt as normalizePureReceipt,
} from "./frontend-build-candidate-receipt-core.mjs";
import {
  frontendBuildCandidateReceiptSha256 as webReceiptSha256,
  normalizeFrontendBuildCandidateReceipt as normalizeWebReceipt,
} from "../web/scripts/frontend-build-candidate-core.mjs";

function pin(byte) {
  return `sha256:${byte.toString(16).padStart(2, "0").repeat(32)}`;
}

function receipt() {
  return {
    schema: "dnai.frontend-build-candidate.v3",
    status: "pre_live_activation_candidate",
    truth_status: "pre_live_activation_candidate_not_deploy_authority",
    release_sha: "1".repeat(40),
    chain_id: 84_532,
    deployment_intent_sha256: pin(1),
    reviewer_authority_genesis_acceptance_sha256: pin(2),
    ceremony_authorization_sha256: pin(3),
    runtime_authority_dependency_sha256: pin(4),
    royalty_release_history_sha256: pin(5),
    royalty_release_history_receipt_sha256: pin(6),
    compute_workload_activation_observation_sha256: pin(7),
    frontend_build_sha256: pin(8),
    release_inputs_sha256: pin(9),
    release_env_sha256: pin(10),
    raw_secret_egress: false,
  };
}

test("pure current-D receipt parser remains byte-compatible with the web producer", () => {
  const value = receipt();
  assert.deepEqual(normalizePureReceipt(value), normalizeWebReceipt(value));
  assert.equal(pureReceiptSha256(value), webReceiptSha256(value));
  assert.equal(
    pureReceiptSha256(value),
    "sha256:b5ec10a412cb57df8f298737acf06fed5e2524e658b28663e9f94596c0740d14",
  );
});

test("pure current-D receipt parser rejects accessors and zero authority pins", () => {
  const accessor = receipt();
  Object.defineProperty(accessor, "release_sha", {
    enumerable: true,
    get() {
      throw new Error("untrusted accessor evaluated");
    },
  });
  assert.throws(() => normalizePureReceipt(accessor), /canonical plain-data graph/);

  const zero = receipt();
  zero.frontend_build_sha256 = `sha256:${"0".repeat(64)}`;
  assert.throws(() => normalizePureReceipt(zero), /nonzero sha256/);
});
