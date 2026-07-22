import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  deploymentIntentReviewerAuthorityCurrentStatusBinding,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";

export const EXACT37_CURRENT_REVIEWER_AUTHORITY_ASSERTION_TRUTH =
  "deployment_intent_anchored_epoch_one_acceptance_status_current_with_no_unprovided_history";

const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const MIN_REVIEW_HEADROOM_MS = 5 * 60 * 1_000;
const MAX_FUTURE_SKEW_MS = 5 * 60 * 1_000;

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, fields, label) {
  assertCanonicalPlainDataGraph(value, { label });
  if (!isRecord(value)
    || JSON.stringify(Object.keys(value).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} must contain exactly the supported fields`);
  }
  return value;
}

function checkedAtSecond(checkedAtMs) {
  if (!Number.isFinite(checkedAtMs) || checkedAtMs < 1) {
    fail("exact37 reviewer-currentness requires wrapper-derived checkedAtMs");
  }
  return new Date(Math.floor(checkedAtMs / 1_000) * 1_000)
    .toISOString()
    .replace(".000Z", "Z");
}

/**
 * Exact37 has no reviewer-status-history input. Therefore it may prove current
 * reviewer authority only while the deployment-intent head is the epoch-one
 * status embedded in the signed genesis acceptance. Any later epoch fails
 * closed instead of treating caller-supplied history as authenticated.
 */
export function assertExact37GenesisReviewerStatusCurrentForLiveActivation(
  options,
) {
  const parsed = exactRecord(options, [
    "checkedAtMs", "deploymentIntent", "liveActivationReview",
    "reviewerGenesis", "reviewerGenesisAcceptance",
  ], "exact37 reviewer-currentness assertion options");
  const validation = validateDeploymentIntentCore(parsed.deploymentIntent);
  if (!validation.ok) {
    fail("exact37 reviewer-currentness requires the exact deployment intent");
  }
  const deploymentRoleAddresses = [...new Set([
    parsed.deploymentIntent.deploymentControl.operatorAddress,
    parsed.deploymentIntent.staticContractInputs.computeCreditVault.developer,
  ])].sort();
  const deploymentRoleControllerIds = [
    parsed.deploymentIntent.deploymentControl.controllerId,
  ];
  const genesis = assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
    parsed.reviewerGenesis,
    { deploymentRoleAddresses, deploymentRoleControllerIds },
  );
  const embeddedStatus = parsed.reviewerGenesisAcceptance
    ?.reviewer_authority_current_status;
  if (!isRecord(embeddedStatus) || embeddedStatus.epoch !== 1
    || embeddedStatus.previous_status_sha256 !== ZERO_SHA256) {
    fail("exact37 cannot prove reviewer currentness after epoch one without an authenticated history artifact");
  }
  const anchoredHead = deploymentIntentReviewerAuthorityCurrentStatusBinding(
    parsed.deploymentIntent,
  );
  const acceptance =
    assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
      parsed.reviewerGenesisAcceptance,
      {
        reviewerGenesis: genesis,
        statusHistory: [],
        deploymentRoleAddresses,
        deploymentRoleControllerIds,
        now: checkedAtSecond(parsed.checkedAtMs),
        expectedCurrentStatusEpoch: 1,
        expectedCurrentStatusSha256:
          anchoredHead.reviewerAuthorityCurrentStatusSha256,
      },
    );
  const status = acceptance.reviewer_authority_current_status;
  const statusSha256 = releaseReviewerAuthorityCurrentStatusSha256(status, {
    reviewerGenesis: genesis,
    statusHistory: [],
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  });
  if (anchoredHead.reviewerAuthorityCurrentStatusEpoch !== 1
    || anchoredHead.reviewerAuthorityCurrentStatusSha256 !== statusSha256) {
    fail("deployment intent is not anchored to the epoch-one acceptance status");
  }
  const review = exactRecord(parsed.liveActivationReview, [
    "approved_reviewer_hashes", "chain_id", "dependencies", "expires_at",
    "release_sha", "reviewer_authority_genesis_acceptance_sha256",
    "reviewer_authority_genesis_sha256", "reviewer_root_hash",
    "reviewer_set_sha256", "schema", "signature_scheme",
    "signature_verifier", "signatures", "signed_at",
    "signing_payload_sha256", "stage", "subject_kind", "subject_sha256",
  ], "exact37 live activation review");
  const signedAtMs = Date.parse(review.signed_at);
  const expiresAtMs = Date.parse(review.expires_at);
  if (!Number.isFinite(signedAtMs) || !Number.isFinite(expiresAtMs)
    || signedAtMs > parsed.checkedAtMs + MAX_FUTURE_SKEW_MS
    || expiresAtMs - parsed.checkedAtMs < MIN_REVIEW_HEADROOM_MS) {
    fail("live activation review is expired or lacks the required current headroom");
  }
  const genesisSha256 = releaseReviewerAuthorityGenesisSha256(genesis);
  const acceptanceSha256 = releaseReviewerAuthorityGenesisAcceptanceSha256(
    acceptance,
    {
      reviewerGenesis: genesis,
      statusHistory: [],
      deploymentRoleAddresses,
      deploymentRoleControllerIds,
    },
  );
  if (review.reviewer_authority_genesis_sha256 !== genesisSha256
    || review.reviewer_authority_genesis_acceptance_sha256 !== acceptanceSha256
    || review.reviewer_root_hash !== status.reviewer_root_hash
    || review.reviewer_set_sha256 !== status.reviewer_set_sha256
    || JSON.stringify(review.approved_reviewer_hashes)
      !== JSON.stringify(status.approved_reviewer_hashes)) {
    fail("live activation review is not signed under the current epoch-one reviewer status");
  }
  return deepFreezeCanonicalPlainDataGraph({
    truth_status: EXACT37_CURRENT_REVIEWER_AUTHORITY_ASSERTION_TRUTH,
    checked_at: checkedAtSecond(parsed.checkedAtMs),
    reviewer_status_epoch: 1,
    reviewer_status_sha256: statusSha256,
    reviewer_authority_genesis_sha256: genesisSha256,
    reviewer_authority_genesis_acceptance_sha256: acceptanceSha256,
    authenticated_status_history_entries: 0,
    later_epoch_supported: false,
  }, { label: "exact37 current reviewer assertion result" });
}
