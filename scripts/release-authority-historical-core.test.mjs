import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_SCHEMA,
  HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_TRUTH,
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX,
  historicalCeremonyAuthorizationReviewSigningPayload,
  historicalCeremonyAuthorizationCoreSha256,
  historicalLiveActivationAuthoritySha256,
  historicalLiveActivationFrontendBindingSha256,
  historicalLiveActivationReviewSigningPayload,
  historicalReleaseAuthorityReviewSigningPayloadSha256,
  normalizeHistoricalCeremonyAuthorizationCore,
  normalizeHistoricalLiveActivationAuthority,
  projectHistoricalLiveActivationFrontendBinding,
  projectHistoricalCeremonyExpectedContext,
  projectHistoricalLiveActivationExpectedContext,
} from "./release-authority-historical-core.mjs";
import {
  assertExact37GenesisReviewerStatusCurrentForLiveActivation,
} from "./release-authority-current-reviewer-facade.mjs";
import {
  syntheticHistoricalReleaseAuthorityFixture,
} from "./release-authority-historical-core.fixture.mjs";

const syntheticReleaseAuthorityStagesFixture =
  syntheticHistoricalReleaseAuthorityFixture;
const HISTORICAL_B_KAT =
  "sha256:6b94f9373fa6583497621bf4b6cdc41fbdc65d6f254bcad62b4d284366c02fd6";
const HISTORICAL_C_KAT =
  "sha256:d25504835882baeddb43592c94bb9138c5805e6fd3d6e5dc3463afd746ab3228";
const HISTORICAL_FRONTEND_KAT =
  "sha256:a222e8e444063534a979cf1c83a281ca09b559c1d1148e2322e678c861d3abea";

function clone(value) {
  return structuredClone(value);
}

function pin(byte) {
  return `sha256:${byte.repeat(32)}`;
}

function address(index) {
  return `0x${index.toString(16).padStart(40, "0")}`;
}

function reviewerAuthority(value) {
  const status = value.genesisAcceptance.reviewer_authority_current_status;
  return {
    reviewer_authority_genesis_sha256:
      value.stageOne.review.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      value.stageOne.review.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      value.stageOne.review.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_not_before: status.not_before,
    reviewer_authority_current_status_expires_at: status.expires_at,
    reviewer_authority_current_status_sha256:
      value.stageOne.review.reviewer_authority_current_status_sha256,
    approved_reviewers: clone(value.reviewers),
    approved_reviewer_hashes: clone(status.approved_reviewer_hashes),
    reviewer_root_hash: status.reviewer_root_hash,
    reviewer_set_sha256: status.reviewer_set_sha256,
  };
}

function exactReviewVerifier(expectedReview) {
  return ({ signatures, message }) => (
    JSON.stringify(signatures) === JSON.stringify(expectedReview.signatures)
    && message === `${RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX}${
      expectedReview.signing_payload_sha256
    }`
  );
}

function ceremonyOptions(value) {
  const expectedContext = projectHistoricalCeremonyExpectedContext({
    runtimeAuthority: value.runtimeAuthority,
    runtimeAuthoritySha256:
      value.stageOne.pre_ceremony_runtime_authority_sha256,
    freshContractDeploymentReceiptSha256:
      value.stageOne.deployment_authority.fresh_contract_deployment_receipt_sha256,
    signedABootstrapAuthorizationReceiptSha256:
      value.stageOne.cvm_bootstrap_authorization_receipt_sha256,
    toolchain: value.stageOne.deployment_authority.toolchain,
  });
  return {
    expectedContext,
    reviewerAuthority: reviewerAuthority(value),
    expectedSignatureVerifier: value.stageOne.review.signature_verifier,
    verifyReviewSignatures: exactReviewVerifier(value.stageOne.review),
  };
}

async function resignedHistoricalStageOne(value, { signedAt, expiresAt }) {
  const options = ceremonyOptions(value);
  const body = clone(value.stageOne);
  delete body.review;
  const prior = value.stageOne.review;
  const payload = historicalCeremonyAuthorizationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256:
      prior.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      prior.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      prior.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      prior.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: clone(prior.approved_reviewer_hashes),
    reviewer_root_hash: prior.reviewer_root_hash,
    reviewer_set_sha256: prior.reviewer_set_sha256,
    signed_at: signedAt,
    expires_at: expiresAt,
  }, options);
  const signingPayloadSha256 =
    historicalReleaseAuthorityReviewSigningPayloadSha256(payload, {
      expectedSignatureVerifier: prior.signature_verifier,
    });
  const message = `${RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX}${signingPayloadSha256}`;
  const accounts = new Map(
    value.accounts.map((account) => [account.address.toLowerCase(), account]),
  );
  const review = {
    ...payload,
    schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
    signing_payload_sha256: signingPayloadSha256,
    signatures: await Promise.all(value.reviewers.map(async (reviewer) => ({
      ...reviewer,
      signature: (await accounts.get(reviewer.address)
        .signMessage({ message })).toLowerCase(),
    }))),
  };
  return {
    artifact: { ...body, review },
    options: {
      ...options,
      verifyReviewSignatures: exactReviewVerifier(review),
    },
  };
}

function syntheticLaunchProjection(value) {
  const plan = value.runtimeAuthority.post_measurement_activation_plan;
  const releaseAuthority = plan.release_verification_authority;
  return {
    release_sha: value.runtimeAuthority.release_sha,
    deployment_intent_sha256: value.runtimeAuthority.deployment_intent_sha256,
    cvm_launch_intent_sha256: value.runtimeAuthority.cvm_launch_intent_sha256,
    release_verification_authority_sha256:
      plan.release_verification_authority_sha256,
    batch_id: plan.batch_id,
    phala_recovery_directory_identity_anchor_sha256:
      plan.phala_recovery_directory_identity_anchor_sha256,
    domains: releaseAuthority.descriptors.map((descriptor, index) => ({
      domain: descriptor.domain,
      descriptor_sha256: descriptor.descriptor_sha256,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      committed_compose_hash: descriptor.compose_hash,
      os_image_hash: descriptor.os_image_hash,
      production_posture_verification_receipt_sha256:
        descriptor.posture_receipt_sha256,
      production_posture_verified_at: descriptor.posture_observed_at,
      kms_id: descriptor.kms_id,
      instance_type: descriptor.instance_type,
      disk_size: descriptor.disk_size,
      tee_identity: address(500 + index),
      machine_evidence_sha256: pin((150 + index).toString(16).padStart(2, "0")),
      qvl_release_policy_sha256:
        pin((170 + index).toString(16).padStart(2, "0")),
      activation_evidence_lease_expires_at:
        plan.activation_evidence_lease_expires_at,
    })),
  };
}

async function liveFixture({
  cSignedAt,
  cExpiresAt,
} = {}) {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const bOptions = ceremonyOptions(value);
  const b = normalizeHistoricalCeremonyAuthorizationCore(value.stageOne, bOptions);
  const bSha256 = historicalCeremonyAuthorizationCoreSha256(value.stageOne, bOptions);
  assert.equal(bSha256, value.stageTwo.ceremony_authorization_sha256);
  const plan = value.runtimeAuthority.post_measurement_activation_plan;
  const releaseAuthority = plan.release_verification_authority;
  const launch = syntheticLaunchProjection(value);
  const expectedContext = projectHistoricalLiveActivationExpectedContext({
    runtimeAuthority: value.runtimeAuthority,
    runtimeAuthoritySha256:
      value.stageOne.pre_ceremony_runtime_authority_sha256,
    launchCompletionReceipt: launch,
    launchCompletionReceiptSha256:
      plan.seven_cvm_launch_completion_receipt_sha256,
    releaseVerificationAuthority: releaseAuthority,
    releaseVerificationAuthoritySha256:
      plan.release_verification_authority_sha256,
  });
  assert.equal(
    expectedContext.schema,
    HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_SCHEMA,
  );
  assert.equal(
    expectedContext.truth_status,
    HISTORICAL_LIVE_ACTIVATION_EXPECTED_CONTEXT_TRUTH,
  );

  const unsigned = clone(value.stageTwo);
  delete unsigned.review;
  unsigned.post_ceremony_evidence.final_cvms = launch.domains.map((domain, index) => ({
    cvm_key: domain.domain,
    app_id: domain.app_id,
    cvm_id: domain.cvm_id,
    compose_hash_sha256: `sha256:${domain.committed_compose_hash}`,
    tee_identity: domain.tee_identity,
    attestation_evidence_sha256: index === 0
      ? unsigned.post_ceremony_evidence
        .post_measurement_activation_execution_receipt
        .post_restart_evidence.get_cvm_attestation_observation_sha256
      : domain.machine_evidence_sha256,
  }));
  const browser = unsigned.post_ceremony_evidence.compute_workload_browser_binding;
  const main = launch.domains[0];
  const computeQvl = launch.domains[4];
  const computeVault = unsigned.contract_state.contracts.find(
    (entry) => entry.contract_key === "compute_credit_vault",
  );
  browser.app_id = main.app_id;
  browser.cvm_id = main.cvm_id;
  browser.compose_hash = `0x${main.committed_compose_hash}`;
  browser.os_image_hash = main.os_image_hash;
  browser.main_runtime_evidence_sha256 = main.machine_evidence_sha256;
  browser.qvl_verifier = computeQvl.tee_identity;
  browser.qvl_release_policy_hash =
    `0x${computeQvl.qvl_release_policy_sha256.slice(7)}`;
  browser.deployment_intent_sha256 = expectedContext.deployment_intent_sha256;
  browser.release_authority_sha256 =
    expectedContext.release_verification_authority_sha256;
  browser.ceremony_nonce = expectedContext.ceremony_nonce;
  browser.measurement_policy_set_sha256 =
    expectedContext.qvl_measurement_policy_set_sha256;
  browser.measurement_policy_sha256 =
    expectedContext.compute_workload_qvl_measurement_policy_sha256;
  browser.compute_vault_address = computeVault.address;
  browser.compute_vault_runtime_code_hash = computeVault.runtime_code_hash;
  browser.fresh_contract_deployment_receipt_sha256 =
    `0x${b.deployment_authority.fresh_contract_deployment_receipt_sha256.slice(7)}`;

  const reviewMetadata = {
    reviewer_authority_genesis_sha256:
      value.stageTwo.review.reviewer_authority_genesis_sha256,
    reviewer_authority_genesis_acceptance_sha256:
      value.stageTwo.review.reviewer_authority_genesis_acceptance_sha256,
    reviewer_authority_current_status_epoch:
      value.stageTwo.review.reviewer_authority_current_status_epoch,
    reviewer_authority_current_status_sha256:
      value.stageTwo.review.reviewer_authority_current_status_sha256,
    approved_reviewer_hashes: clone(value.stageTwo.review.approved_reviewer_hashes),
    reviewer_root_hash: value.stageTwo.review.reviewer_root_hash,
    reviewer_set_sha256: value.stageTwo.review.reviewer_set_sha256,
    signed_at: cSignedAt ?? value.stageTwo.review.signed_at,
    expires_at: cExpiresAt ?? value.stageTwo.review.expires_at,
  };
  const commonOptions = {
    ceremonyAuthorization: value.stageOne,
    ceremonyAuthorizationOptions: bOptions,
    expectedContext,
    reviewerAuthority: reviewerAuthority(value),
    expectedSignatureVerifier: value.stageTwo.review.signature_verifier,
  };
  const payload = historicalLiveActivationReviewSigningPayload(
    unsigned,
    reviewMetadata,
    commonOptions,
  );
  const signingPayloadSha256 =
    historicalReleaseAuthorityReviewSigningPayloadSha256(payload, {
      expectedSignatureVerifier: value.stageTwo.review.signature_verifier,
    });
  const message = `${RELEASE_AUTHORITY_REVIEW_MESSAGE_PREFIX}${signingPayloadSha256}`;
  const byAddress = new Map(
    value.accounts.map((account) => [account.address.toLowerCase(), account]),
  );
  const signatures = await Promise.all(value.reviewers.map(async (reviewer) => ({
    ...reviewer,
    signature: (await byAddress.get(reviewer.address).signMessage({ message }))
      .toLowerCase(),
  })));
  const stageTwo = {
    ...unsigned,
    review: {
      ...payload,
      schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
      signing_payload_sha256: signingPayloadSha256,
      signatures,
    },
  };
  return {
    value,
    bOptions,
    expectedContext,
    stageTwo,
    options: {
      ...commonOptions,
      verifyReviewSignatures: exactReviewVerifier(stageTwo.review),
    },
  };
}

test("historical B exact-binds the independently reconstructed signed-A receipt", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const options = ceremonyOptions(value);
  const normalized = normalizeHistoricalCeremonyAuthorizationCore(
    value.stageOne,
    options,
  );
  assert.equal(
    historicalCeremonyAuthorizationCoreSha256(value.stageOne, options),
    HISTORICAL_B_KAT,
  );
  assert.equal(
    normalized.cvm_bootstrap_authorization_receipt_sha256,
    options.expectedContext.signed_a_bootstrap_authorization_receipt_sha256,
  );
  const drift = clone(options.expectedContext);
  drift.signed_a_bootstrap_authorization_receipt_sha256 = pin("fe");
  assert.throws(
    () => normalizeHistoricalCeremonyAuthorizationCore(value.stageOne, {
      ...options,
      expectedContext: drift,
    }),
    /signed-A/,
  );
});

test("historical B review cannot outlive its authenticated reviewer status", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const overflow = await resignedHistoricalStageOne(value, {
    signedAt: "2026-07-21T12:00:00.000Z",
    expiresAt: "2026-07-21T12:10:00.001Z",
  });
  assert.throws(
    () => normalizeHistoricalCeremonyAuthorizationCore(
      overflow.artifact,
      overflow.options,
    ),
    /selected reviewer-status validity window/,
  );
});

test("historical C binds its full receipt and all seven CVMs to L, R, plan, and release authority", async () => {
  const fixture = await liveFixture();
  const normalized = normalizeHistoricalLiveActivationAuthority(
    fixture.stageTwo,
    fixture.options,
  );
  assert.equal(normalized.schema, "dnai.live-activation-authority.v5");
  assert.match(
    historicalLiveActivationAuthoritySha256(fixture.stageTwo, fixture.options),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(
    normalized.post_ceremony_evidence.final_cvms.length,
    7,
  );
  const frontendBinding = projectHistoricalLiveActivationFrontendBinding(
    fixture.stageTwo,
    fixture.options,
  );
  assert.equal(
    frontendBinding.live_activation_authority_sha256,
    historicalLiveActivationAuthoritySha256(fixture.stageTwo, fixture.options),
  );
  assert.match(
    historicalLiveActivationFrontendBindingSha256(frontendBinding),
    /^sha256:[0-9a-f]{64}$/,
  );
  assert.equal(
    historicalLiveActivationAuthoritySha256(fixture.stageTwo, fixture.options),
    HISTORICAL_C_KAT,
  );
  assert.equal(
    historicalLiveActivationFrontendBindingSha256(frontendBinding),
    HISTORICAL_FRONTEND_KAT,
  );

  const receiptDrift = clone(fixture.stageTwo);
  receiptDrift.post_ceremony_evidence
    .post_measurement_activation_execution_receipt.batch_id = pin("fd");
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(receiptDrift, fixture.options),
    /receipt digest|activation execution receipt|injected L\/R\/plan/,
  );

  const descriptorDrift = clone(fixture.expectedContext);
  descriptorDrift.launch_completion_domains[6].disk_size += 1;
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(fixture.stageTwo, {
      ...fixture.options,
      expectedContext: descriptorDrift,
    }),
    /disk_size differs from release authority/,
  );

  const finalCvmDrift = clone(fixture.stageTwo);
  finalCvmDrift.post_ceremony_evidence.final_cvms[5].cvm_id = "cvm-drifted-005";
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(finalCvmDrift, fixture.options),
    /differs from historical L descriptor/,
  );
});

test("historical B and C consume independent authenticated status-window projections", async () => {
  const fixture = await liveFixture();
  const lateC = clone(fixture.options.reviewerAuthority);
  lateC.reviewer_authority_current_status_not_before =
    "2026-07-21T12:00:11Z";
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(fixture.stageTwo, {
      ...fixture.options,
      reviewerAuthority: lateC,
    }),
    /selected reviewer-status validity window/,
  );

  const expiredB = clone(
    fixture.options.ceremonyAuthorizationOptions.reviewerAuthority,
  );
  expiredB.reviewer_authority_current_status_expires_at =
    "2026-07-21T12:00:00Z";
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(fixture.stageTwo, {
      ...fixture.options,
      ceremonyAuthorizationOptions: {
        ...fixture.options.ceremonyAuthorizationOptions,
        reviewerAuthority: expiredB,
      },
    }),
    /selected reviewer-status validity window/,
  );
});

test("historical C review cannot outlive its independently projected reviewer status", async () => {
  const fixture = await liveFixture({
    cExpiresAt: "2026-07-21T12:10:00.001Z",
  });
  assert.throws(
    () => normalizeHistoricalLiveActivationAuthority(
      fixture.stageTwo,
      fixture.options,
    ),
    /selected reviewer-status validity window/,
  );
});

test("historical B/C reject accessor and custom-prototype graphs before nested reads", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const options = ceremonyOptions(value);
  const accessor = clone(value.stageOne);
  Object.defineProperty(accessor, "release_sha", {
    enumerable: true,
    get() {
      throw new Error("accessor executed");
    },
  });
  assert.throws(
    () => normalizeHistoricalCeremonyAuthorizationCore(accessor, options),
    /accessors/,
  );
  const custom = clone(value.stageOne);
  Object.setPrototypeOf(custom, { forged: true });
  assert.throws(
    () => normalizeHistoricalCeremonyAuthorizationCore(custom, options),
    /custom prototypes/,
  );
});

test("exact37 reviewer-currentness accepts only deployment-anchored epoch one with empty history", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const options = {
    liveActivationReview: value.stageTwo.review,
    reviewerGenesis: value.genesis,
    reviewerGenesisAcceptance: value.genesisAcceptance,
    deploymentIntent: value.intent,
    checkedAtMs: Date.parse("2026-07-21T12:00:20.000Z"),
  };
  const assertion =
    assertExact37GenesisReviewerStatusCurrentForLiveActivation(options);
  assert.equal(assertion.reviewer_status_epoch, 1);
  assert.equal(assertion.authenticated_status_history_entries, 0);
  assert.equal(assertion.later_epoch_supported, false);
  assert.throws(
    () => assertExact37GenesisReviewerStatusCurrentForLiveActivation({
      ...options,
      reviewerStatusHistory: [],
    }),
    /exactly the supported fields/,
  );
  const epochTwo = clone(value.genesisAcceptance);
  epochTwo.reviewer_authority_current_status.epoch = 2;
  assert.throws(
    () => assertExact37GenesisReviewerStatusCurrentForLiveActivation({
      ...options,
      reviewerGenesisAcceptance: epochTwo,
    }),
    /cannot prove reviewer currentness after epoch one/,
  );
});

test("historical authority core has an acyclic, side-effect-free local import closure", () => {
  const scripts = path.dirname(fileURLToPath(import.meta.url));
  const entry = path.join(scripts, "release-authority-historical-core.mjs");
  const visited = new Set();
  const active = new Set();
  const localFiles = [];
  function visit(file) {
    const normalized = path.resolve(file);
    assert.equal(active.has(normalized), false, `cycle at ${normalized}`);
    if (visited.has(normalized)) return;
    active.add(normalized);
    const source = fs.readFileSync(normalized, "utf8");
    localFiles.push([normalized, source]);
    for (const match of source.matchAll(/from\s+["'](\.\.?\/[^"']+)["']/g)) {
      visit(path.resolve(path.dirname(normalized), match[1]));
    }
    active.delete(normalized);
    visited.add(normalized);
  }
  visit(entry);
  assert.deepEqual(
    [...visited].map((file) => path.basename(file)).sort(),
    [
      "canonical-authority-graph.mjs",
      "cvm-launch-intent-core.mjs",
      "phala-post-measurement-activation-receipt-core.mjs",
      "phala-production-execution-policy.mjs",
      "phala-seven-cvm-measurement-policy.mjs",
      "release-authority-historical-core.mjs",
    ],
  );
  for (const [file, source] of localFiles) {
    assert.doesNotMatch(source, /node:(?:fs|path|child_process)/, file);
    assert.doesNotMatch(source, /\bprocess\s*\./, file);
    assert.doesNotMatch(source, /\bDate\.now\s*\(/, file);
    assert.doesNotMatch(source, /\bWeakMap\b/, file);
    assert.doesNotMatch(source, /\bimport\s*\(/, file);
    assert.doesNotMatch(source, /production-(?:executor|environment|sdk|replay)/, file);
  }
});

test("frozen historical fixture imports no current C-v6 builder", async () => {
  const scripts = path.dirname(fileURLToPath(import.meta.url));
  const fixturePath = path.join(
    scripts,
    "release-authority-historical-core.fixture.mjs",
  );
  const source = fs.readFileSync(fixturePath, "utf8");
  assert.doesNotMatch(source, /release-authority-stages\.fixture/);
  assert.doesNotMatch(source, /syntheticReleaseAuthorityStagesFixture/);
  assert.doesNotMatch(source, /live-activation-authority\.v6/);
  const value = await syntheticHistoricalReleaseAuthorityFixture();
  assert.equal(value.stageTwo.schema, "dnai.live-activation-authority.v5");
  const royalty = value.stageTwo.contract_state.contracts.find(
    (entry) => entry.contract_key === "royalty_distributor",
  );
  assert.deepEqual(
    { role: royalty.control_role, address: royalty.control_address },
    { role: "immutable_no_owner", address: `0x${"0".repeat(40)}` },
  );
});
