import assert from "node:assert/strict";
import test from "node:test";

import {
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  normalizeStageAPinnedReviewerAuthority,
  normalizeStageBSuccessorReviewerAuthority,
} from "./release-authority-current-reviewer-facade.mjs";
import {
  RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
  ceremonyAuthorizationCoreSha256,
  ceremonyAuthorizationReviewSigningPayload,
  liveActivationReviewSigningPayload,
  normalizeCeremonyAuthorizationCore,
  normalizeLiveActivationAuthority,
  releaseAuthorityReviewSigningMessage,
  releaseAuthorityReviewSigningPayloadSha256,
} from "./release-authority-stages.mjs";
import {
  phalaArenaWorkerPresenceActivationProofSha256,
  phalaCombinedArenaComputeActivationVerificationSha256,
  phalaPostMeasurementActivationExecutionReceiptSha256,
} from "./phala-post-measurement-activation-receipt-core.mjs";
import {
  syntheticReleaseAuthorityStagesFixture,
} from "./release-authority-stages.fixture.mjs";

const SUCCESSOR_SIGNED_AT = "2026-07-21T12:10:01.000Z";
const SUCCESSOR_CHECKED_AT = Date.parse("2026-07-21T12:10:02.000Z");

function accountsByAddress(accounts) {
  return new Map(accounts.map((account) => [
    account.address.toLowerCase(),
    account,
  ]));
}

async function signedSuccessorStatus(value, overrides = {}) {
  const statusHistory = [value.currentStatus];
  const options = {
    reviewerGenesis: value.genesis,
    statusHistory,
  };
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 2,
    not_before: value.currentStatus.expires_at,
    expires_at: "2026-07-21T12:20:00Z",
    previous_status_sha256: releaseReviewerAuthorityCurrentStatusSha256(
      value.currentStatus,
      { reviewerGenesis: value.genesis },
    ),
    active_reviewers: value.successorReviewers,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
    ...overrides,
  }, options);
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    options,
  );
  const guardians = accountsByAddress(value.guardianAccounts);
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
        payload,
        options,
      ),
    guardian_signatures: await Promise.all(
      value.genesis.status_guardians.map(async (guardian) => ({
        ...guardian,
        signature: (await guardians.get(guardian.address)
          .signMessage({ message })).toLowerCase(),
      })),
    ),
  };
}

async function signedEpochTwoAcceptance(value, successor) {
  const statusHistory = [value.currentStatus];
  const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    value.genesis,
    { reviewerCurrentStatus: successor, statusHistory },
  );
  const options = { reviewerGenesis: value.genesis, statusHistory };
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    options,
  );
  const accounts = accountsByAddress(value.accounts);
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        options,
      ),
    acceptances: await Promise.all(
      successor.active_reviewers.map(async (reviewer) => ({
        ...reviewer,
        signature: (await accounts.get(reviewer.address)
          .signMessage({ message })).toLowerCase(),
      })),
    ),
  };
}

async function signedStageB(value, successor, {
  signingReviewers = value.successorReviewers,
  checkedAtMs = SUCCESSOR_CHECKED_AT,
} = {}) {
  const reviewerStatusHistory = [value.currentStatus, successor];
  const reviewerStage = normalizeStageBSuccessorReviewerAuthority({
    reviewerGenesis: value.genesis,
    reviewerGenesisAcceptance: value.genesisAcceptance,
    reviewerStatusHistory,
    deploymentIntent: value.intent,
    checkedAtMs,
    enforceFreshness: true,
  });
  const body = structuredClone(value.stageOne);
  delete body.review;
  const payload = ceremonyAuthorizationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256: reviewerStage.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerStage.acceptanceSha256,
    reviewer_authority_current_status_epoch: reviewerStage.currentStatus.epoch,
    reviewer_authority_current_status_sha256:
      reviewerStage.currentStatusSha256,
    approved_reviewer_hashes:
      reviewerStage.currentStatus.approved_reviewer_hashes,
    reviewer_root_hash: reviewerStage.currentStatus.reviewer_root_hash,
    reviewer_set_sha256: reviewerStage.currentStatus.reviewer_set_sha256,
    signed_at: SUCCESSOR_SIGNED_AT,
    expires_at: "2026-07-21T12:19:59.000Z",
  });
  const message = releaseAuthorityReviewSigningMessage(payload);
  const accounts = accountsByAddress(value.accounts);
  const review = {
    ...payload,
    schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
    signing_payload_sha256:
      releaseAuthorityReviewSigningPayloadSha256(payload),
    signatures: await Promise.all(signingReviewers.map(async (reviewer) => ({
      ...reviewer,
      signature: (await accounts.get(reviewer.address)
        .signMessage({ message })).toLowerCase(),
    }))),
  };
  return {
    stageB: { ...body, review },
    options: {
      ...value.stageOneOptions,
      reviewerStatusHistory,
      checkedAtMs,
    },
    reviewerStage,
  };
}

function moveActivationReceiptAfterRootExpiry(body, ceremonyAuthorizationSha256) {
  const receipt = body.post_ceremony_evidence
    .post_measurement_activation_execution_receipt;
  receipt.ceremony_authorization_sha256 = ceremonyAuthorizationSha256;
  receipt.patch.attempt_recorded_at = "2026-07-21T12:09:51Z";
  receipt.patch.observed_at = "2026-07-21T12:09:52Z";
  receipt.restart.attempt_recorded_at = "2026-07-21T12:09:53Z";
  receipt.restart.observed_at = "2026-07-21T12:09:54Z";
  receipt.post_restart_evidence.get_cvm_info_observed_at =
    "2026-07-21T12:09:55Z";
  receipt.post_restart_evidence.get_cvm_attestation_observed_at =
    "2026-07-21T12:09:56Z";
  receipt.arena_worker_presence.heartbeat_observed_at =
    Date.parse("2026-07-21T12:09:57Z") / 1_000;
  receipt.arena_worker_presence.verified_at =
    Date.parse("2026-07-21T12:09:57Z") / 1_000;
  receipt.arena_worker_presence_sha256 =
    phalaArenaWorkerPresenceActivationProofSha256(
      receipt.arena_worker_presence,
    );
  receipt.recipient_activation.authenticated_at =
    Date.parse("2026-07-21T12:09:57Z") / 1_000;
  receipt.recipient_activation.verified_at =
    Date.parse("2026-07-21T12:09:58Z") / 1_000;
  const leaseExpiry = Date.parse("2026-07-21T12:11:00Z") / 1_000;
  receipt.recipient_activation.verdict_activation_evidence_lease_expires_at =
    leaseExpiry;
  receipt.recipient_activation.recipient_evidence_lease_expires_at = leaseExpiry;
  receipt.recipient_activation.expires_at = leaseExpiry;
  receipt.initial_activation_evidence_lease_expires_at = leaseExpiry;
  receipt.recipient_evidence_lease_expires_at = leaseExpiry;
  receipt.terminal_evidence_lease_expires_at = leaseExpiry;
  receipt.completed_at = "2026-07-21T12:09:59Z";
  receipt.combined_activation_verification_sha256 =
    phalaCombinedArenaComputeActivationVerificationSha256({
      profileActivation: receipt.profile_activation,
      arenaWorkerPresenceSha256: receipt.arena_worker_presence_sha256,
      computeRecipientActivationSha256:
        receipt.compute_recipient_activation_sha256,
    });
  body.post_ceremony_evidence
    .post_measurement_activation_execution_receipt_sha256 =
      phalaPostMeasurementActivationExecutionReceiptSha256(receipt);
}

async function signedStageCAfterRootExpiry(value, successor) {
  const stageBReviewerStatusHistory = [];
  const stageCReviewerStatusHistory = [value.currentStatus, successor];
  const options = {
    ...value.stageOneOptions,
    ceremonyAuthorization: value.stageOne,
    stageBReviewerStatusHistory,
    stageCReviewerStatusHistory,
    checkedAtMs: Date.parse("2026-07-21T12:10:11.000Z"),
  };
  const reviewerStage = normalizeStageBSuccessorReviewerAuthority({
    reviewerGenesis: value.genesis,
    reviewerGenesisAcceptance: value.genesisAcceptance,
    reviewerStatusHistory: stageCReviewerStatusHistory,
    deploymentIntent: value.intent,
    checkedAtMs: options.checkedAtMs,
    enforceFreshness: true,
  });
  const body = structuredClone(value.stageTwo);
  delete body.review;
  const ceremonyAuthorizationSha256 = ceremonyAuthorizationCoreSha256(
    value.stageOne,
    value.stageOneOptions,
  );
  body.ceremony_authorization_sha256 = ceremonyAuthorizationSha256;
  moveActivationReceiptAfterRootExpiry(body, ceremonyAuthorizationSha256);
  const payload = liveActivationReviewSigningPayload(body, {
    reviewer_authority_genesis_sha256: reviewerStage.genesisSha256,
    reviewer_authority_genesis_acceptance_sha256:
      reviewerStage.acceptanceSha256,
    reviewer_authority_current_status_epoch: reviewerStage.currentStatus.epoch,
    reviewer_authority_current_status_sha256:
      reviewerStage.currentStatusSha256,
    approved_reviewer_hashes:
      reviewerStage.currentStatus.approved_reviewer_hashes,
    reviewer_root_hash: reviewerStage.currentStatus.reviewer_root_hash,
    reviewer_set_sha256: reviewerStage.currentStatus.reviewer_set_sha256,
    signed_at: "2026-07-21T12:10:10.000Z",
    expires_at: "2026-07-21T12:19:59.000Z",
  }, options);
  const message = releaseAuthorityReviewSigningMessage(payload);
  const accounts = accountsByAddress(value.accounts);
  return {
    stageC: {
      ...body,
      review: {
        ...payload,
        schema: RELEASE_AUTHORITY_CRYPTOGRAPHIC_REVIEW_SCHEMA,
        signing_payload_sha256:
          releaseAuthorityReviewSigningPayloadSha256(payload),
        signatures: await Promise.all(
          value.successorReviewers.map(async (reviewer) => ({
            ...reviewer,
            signature: (await accounts.get(reviewer.address)
              .signMessage({ message })).toLowerCase(),
          })),
        ),
      },
    },
    options,
    reviewerStage,
  };
}

test("Stage B accepts a complete guardian-signed successor chain while Stage A remains pinned to its immutable root", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const successor = await signedSuccessorStatus(value);
  const rooted = normalizeStageAPinnedReviewerAuthority({
    reviewerGenesis: value.genesis,
    reviewerGenesisAcceptance: value.genesisAcceptance,
    reviewerStatusHistory: [],
    deploymentIntent: value.intent,
    checkedAtMs: Date.parse("2026-07-21T12:00:00.000Z"),
    enforceFreshness: true,
  });
  assert.equal(rooted.currentStatus.epoch, 1);
  assert.equal(rooted.successorStatusCount, 0);
  assert.equal(rooted.completeStatusLineage.length, 1);
  assert.equal(rooted.completeStatusLineage[0], rooted.currentStatus);
  assert.equal(rooted.currentStatusNotBefore, rooted.currentStatus.not_before);
  assert.equal(rooted.currentStatusExpiresAt, rooted.currentStatus.expires_at);
  assert.equal(Object.isFrozen(rooted), true);
  assert.equal(Object.isFrozen(rooted.completeStatusLineage), true);
  assert.throws(
    () => normalizeStageAPinnedReviewerAuthority({
      reviewerGenesis: value.genesis,
      reviewerGenesisAcceptance: value.genesisAcceptance,
      reviewerStatusHistory: [value.currentStatus, successor],
      deploymentIntent: value.intent,
      checkedAtMs: SUCCESSOR_CHECKED_AT,
      enforceFreshness: true,
    }),
    /Stage A requires an exact empty epoch-one predecessor history/,
  );

  const epochTwoAcceptance = await signedEpochTwoAcceptance(value, successor);
  const authenticatedEpochTwoAcceptance =
    normalizeReleaseReviewerAuthorityGenesisAcceptance(
      epochTwoAcceptance,
      { reviewerGenesis: value.genesis, statusHistory: [value.currentStatus] },
    );
  assert.equal(
    authenticatedEpochTwoAcceptance.reviewer_authority_current_status.epoch,
    2,
  );
  assert.throws(
    () => normalizeStageAPinnedReviewerAuthority({
      reviewerGenesis: value.genesis,
      reviewerGenesisAcceptance: authenticatedEpochTwoAcceptance,
      reviewerStatusHistory: [value.currentStatus],
      deploymentIntent: value.intent,
      checkedAtMs: SUCCESSOR_CHECKED_AT,
      enforceFreshness: false,
    }),
    /Stage A requires an exact empty epoch-one predecessor history/,
  );

  const { stageB, options, reviewerStage } = await signedStageB(
    value,
    successor,
  );
  const normalized = normalizeCeremonyAuthorizationCore(stageB, options);
  assert.equal(reviewerStage.rootStatus.epoch, 1);
  assert.equal(reviewerStage.currentStatus.epoch, 2);
  assert.equal(reviewerStage.successorStatusCount, 1);
  assert.equal(reviewerStage.completeStatusLineage.length, 2);
  assert.deepEqual(
    reviewerStage.completeStatusLineage,
    [reviewerStage.rootStatus, reviewerStage.currentStatus],
  );
  assert.equal(normalized.review.reviewer_authority_current_status_epoch, 2);
  assert.equal(
    normalized.review.reviewer_authority_current_status_sha256,
    reviewerStage.currentStatusSha256,
  );
  assert.equal(
    normalized.review.reviewer_root_hash,
    successor.reviewer_root_hash,
  );
  assert.equal(
    normalized.review.reviewer_set_sha256,
    successor.reviewer_set_sha256,
  );
  assert.match(
    normalized.review.signing_payload_sha256,
    /^sha256:[0-9a-f]{64}$/,
  );

  const legacyReview = structuredClone(stageB);
  legacyReview.review.schema =
    "dnai.release-authority-cryptographic-review.v1";
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(legacyReview, options),
    /review schema/,
  );

  const bodyDrift = structuredClone(stageB);
  bodyDrift.ceremony_ledger_initialization.initialization_receipt_sha256 =
    `sha256:${"e".repeat(64)}`;
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(bodyDrift, options),
    /subject binding|dependency.*does not match|signing payload digest/,
  );
  const headDrift = structuredClone(stageB);
  headDrift.review.reviewer_authority_current_status_sha256 =
    reviewerStage.rootStatusSha256;
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(headDrift, options),
    /does not match the reviewed signer authority|signing payload digest/,
  );
});

test("Stage C accepts a fresh successor after B's reviewer head expires", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const successor = await signedSuccessorStatus(value);
  const { stageC, options, reviewerStage } =
    await signedStageCAfterRootExpiry(value, successor);
  const normalized = normalizeLiveActivationAuthority(stageC, options);
  assert.equal(normalized.review.reviewer_authority_current_status_epoch, 2);
  assert.equal(
    normalized.review.reviewer_authority_current_status_sha256,
    reviewerStage.currentStatusSha256,
  );
  assert.equal(
    Date.parse(value.stageOne.review.expires_at),
    Date.parse(value.currentStatus.expires_at),
  );
  assert.ok(
    Date.parse(normalized.review.signed_at)
      >= Date.parse(value.currentStatus.expires_at),
  );
});

test("Stage C rejects reviewer rollback, fork, non-prefix, and swapped B/C histories", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const successor = await signedSuccessorStatus(value);
  const fork = await signedSuccessorStatus(value, {
    expires_at: "2026-07-21T12:19:59Z",
  });
  const signedB = await signedStageB(value, successor);
  const base = {
    ...value.stageOneOptions,
    ceremonyAuthorization: signedB.stageB,
    stageBReviewerStatusHistory: [value.currentStatus, successor],
    stageCReviewerStatusHistory: [value.currentStatus, fork],
    checkedAtMs: SUCCESSOR_CHECKED_AT,
  };
  assert.throws(
    () => normalizeLiveActivationAuthority(value.stageTwo, base),
    /exact prefix/,
  );
  assert.throws(
    () => normalizeLiveActivationAuthority(value.stageTwo, {
      ...base,
      stageCReviewerStatusHistory: [],
      checkedAtMs: Date.parse("2026-07-21T12:09:59.000Z"),
    }),
    /exact prefix/,
  );
  assert.throws(
    () => normalizeLiveActivationAuthority(value.stageTwo, {
      ...value.stageTwoOptions,
      stageBReviewerStatusHistory: [value.currentStatus, successor],
      stageCReviewerStatusHistory: [],
    }),
    /reviewed signer authority|exact current reviewer-status|reviewer authority is invalid/,
  );
});

test("Stage B rejects a missing root, predecessor fork, overlap, bad guardian, expiry, and root-reviewer replay", async () => {
  const value = await syntheticReleaseAuthorityStagesFixture();
  const successor = await signedSuccessorStatus(value);
  const baseOptions = {
    reviewerGenesis: value.genesis,
    reviewerGenesisAcceptance: value.genesisAcceptance,
    deploymentIntent: value.intent,
    checkedAtMs: SUCCESSOR_CHECKED_AT,
    enforceFreshness: true,
  };
  assert.throws(
    () => normalizeStageBSuccessorReviewerAuthority({
      ...baseOptions,
      reviewerStatusHistory: [successor],
    }),
    /epoch must be strictly monotonic|replay the exact deployment-intent root/,
  );
  assert.throws(
    () => normalizeStageBSuccessorReviewerAuthority({
      ...baseOptions,
      reviewerStatusHistory: [value.currentStatus],
    }),
    /lone repeated root/,
  );

  const forked = structuredClone(successor);
  forked.previous_status_sha256 = `sha256:${"7".repeat(64)}`;
  assert.throws(
    () => normalizeStageBSuccessorReviewerAuthority({
      ...baseOptions,
      reviewerStatusHistory: [value.currentStatus, forked],
    }),
    /rollback or fork|exact signing payload/,
  );

  await assert.rejects(
    () => signedSuccessorStatus(value, {
      not_before: "2026-07-21T12:09:59Z",
      expires_at: "2026-07-21T12:19:59Z",
    }),
    /windows must not overlap/,
  );

  const badGuardian = structuredClone(successor);
  badGuardian.guardian_signatures[0].signature =
    badGuardian.guardian_signatures[1].signature;
  assert.throws(
    () => normalizeStageBSuccessorReviewerAuthority({
      ...baseOptions,
      reviewerStatusHistory: [value.currentStatus, badGuardian],
    }),
    /signature verification failed/,
  );

  assert.throws(
    () => normalizeStageBSuccessorReviewerAuthority({
      ...baseOptions,
      reviewerStatusHistory: [value.currentStatus, successor],
      checkedAtMs: Date.parse(successor.expires_at),
    }),
    /expired/,
  );

  const replayedRootReview = await signedStageB(value, successor, {
    signingReviewers: value.reviewers,
  });
  assert.throws(
    () => normalizeCeremonyAuthorizationCore(
      replayedRootReview.stageB,
      replayedRootReview.options,
    ),
    /transitively pinned reviewer set|signature verification failed/,
  );
});
