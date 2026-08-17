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
  assertReleaseReviewerAuthorityCurrentStatusAtTime,
  assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  normalizeExpectedReviewerAuthority,
} from "./release-authority-signature-verifier-core.mjs";

export const EXACT37_CURRENT_REVIEWER_AUTHORITY_ASSERTION_TRUTH =
  "deployment_intent_anchored_epoch_one_acceptance_status_current_with_no_unprovided_history";
export const STAGE_A_PINNED_REVIEWER_AUTHORITY_ASSERTION_TRUTH =
  "stage_a_uses_exact_deployment_intent_pinned_reviewer_status_without_successors";
export const STAGE_B_SUCCESSOR_REVIEWER_AUTHORITY_ASSERTION_TRUTH =
  "stage_b_uses_complete_guardian_signed_successor_chain_rooted_at_the_deployment_intent_status";

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

function deploymentRoleSeparation(deploymentIntent) {
  return {
    deploymentRoleAddresses: [...new Set([
      deploymentIntent.deploymentControl.operatorAddress,
      deploymentIntent.staticContractInputs.computeCreditVault.developer,
    ])].sort(),
    deploymentRoleControllerIds: [
      deploymentIntent.deploymentControl.controllerId,
    ],
  };
}

function activeAuthorityFromStatus(status) {
  return normalizeExpectedReviewerAuthority({
    approved_reviewers: status.active_reviewers,
    approved_reviewer_hashes: status.approved_reviewer_hashes,
    reviewer_root_hash: status.reviewer_root_hash,
    reviewer_set_sha256: status.reviewer_set_sha256,
  }, {
    expectedReviewerRootHash: status.reviewer_root_hash,
    expectedReviewerSetSha256: status.reviewer_set_sha256,
  });
}

export function deploymentIntentPinnedReviewerStatusHistoryPrefix(options) {
  const parsed = exactRecord(options, [
    "reviewerGenesisAcceptance", "reviewerStatusHistory",
  ], "deployment-intent reviewer root history options");
  if (!Array.isArray(parsed.reviewerStatusHistory)) {
    fail("reviewer status history must be a complete canonical array");
  }
  const rootEpoch = parsed.reviewerGenesisAcceptance
    ?.reviewer_authority_current_status?.epoch;
  if (!Number.isSafeInteger(rootEpoch) || rootEpoch < 1
    || rootEpoch > 0xffff_ffff) {
    fail("reviewer genesis acceptance has no canonical root epoch");
  }
  const prefixLength = rootEpoch - 1;
  if (parsed.reviewerStatusHistory.length < prefixLength) {
    fail("reviewer status history omits a predecessor before the deployment-intent root");
  }
  return parsed.reviewerStatusHistory.slice(0, prefixLength);
}

/**
 * Split the caller-supplied complete status lineage around the immutable
 * deployment-intent root. The prefix authenticates a root whose epoch may be
 * greater than one. A Stage-B successor lineage, when present, must then carry
 * that exact root followed by every successor through the current head.
 *
 * This representation deliberately makes omission visible: a caller cannot
 * present only a later status, because the first post-prefix entry must replay
 * the exact deployment-intent-pinned root.
 */
function normalizeDeploymentRootedReviewerAuthority(options, {
  allowSuccessors,
  truthStatus,
}) {
  const parsed = exactRecord(options, [
    "checkedAtMs", "deploymentIntent", "enforceFreshness",
    "reviewerGenesis", "reviewerGenesisAcceptance",
    "reviewerStatusHistory",
  ], "deployment-rooted reviewer authority options");
  if (!Array.isArray(parsed.reviewerStatusHistory)) {
    fail("reviewer status history must be a complete canonical array");
  }
  if (typeof parsed.enforceFreshness !== "boolean") {
    fail("reviewer authority freshness policy must be explicit");
  }
  const validation = validateDeploymentIntentCore(parsed.deploymentIntent);
  if (!validation.ok) {
    fail("reviewer authority requires the exact deployment intent");
  }
  const anchoredHead = deploymentIntentReviewerAuthorityCurrentStatusBinding(
    parsed.deploymentIntent,
  );
  const roleSeparation = deploymentRoleSeparation(parsed.deploymentIntent);
  const genesis = assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
    parsed.reviewerGenesis,
    roleSeparation,
  );
  const embeddedRoot = parsed.reviewerGenesisAcceptance
    ?.reviewer_authority_current_status;
  if (!isRecord(embeddedRoot)
    || embeddedRoot.epoch !== anchoredHead.reviewerAuthorityCurrentStatusEpoch) {
    fail("reviewer genesis acceptance does not embed the deployment-intent-pinned root epoch");
  }
  const rootPrefixLength = anchoredHead.reviewerAuthorityCurrentStatusEpoch - 1;
  const rootPrefix = deploymentIntentPinnedReviewerStatusHistoryPrefix({
    reviewerGenesisAcceptance: parsed.reviewerGenesisAcceptance,
    reviewerStatusHistory: parsed.reviewerStatusHistory,
  });
  const acceptanceOptions = {
    reviewerGenesis: genesis,
    statusHistory: rootPrefix,
    ...roleSeparation,
  };
  const acceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(
    parsed.reviewerGenesisAcceptance,
    acceptanceOptions,
  );
  const rootStatus = acceptance.reviewer_authority_current_status;
  const rootStatusSha256 = releaseReviewerAuthorityCurrentStatusSha256(
    rootStatus,
    {
      reviewerGenesis: genesis,
      statusHistory: rootPrefix,
      ...roleSeparation,
    },
  );
  const acceptanceSha256 = releaseReviewerAuthorityGenesisAcceptanceSha256(
    acceptance,
    acceptanceOptions,
  );
  if (rootStatusSha256 !== anchoredHead.reviewerAuthorityCurrentStatusSha256
    || acceptanceSha256
      !== parsed.deploymentIntent.release
        .reviewerAuthorityGenesisAcceptanceSha256) {
    fail("reviewer authority root or acceptance differs from the immutable deployment-intent pins");
  }

  const tail = parsed.reviewerStatusHistory.slice(rootPrefixLength);
  if (!allowSuccessors && tail.length !== 0) {
    fail("Stage A requires exactly the deployment-intent-pinned reviewer status and forbids successor history");
  }
  let currentStatus = rootStatus;
  let currentStatusHistory = rootPrefix;
  let successorStatusCount = 0;
  if (tail.length !== 0) {
    const carriedRoot = normalizeReleaseReviewerAuthorityCurrentStatus(
      tail[0],
      {
        reviewerGenesis: genesis,
        statusHistory: rootPrefix,
        ...roleSeparation,
      },
    );
    const carriedRootSha256 = releaseReviewerAuthorityCurrentStatusSha256(
      carriedRoot,
      {
        reviewerGenesis: genesis,
        statusHistory: rootPrefix,
        ...roleSeparation,
      },
    );
    if (carriedRootSha256 !== rootStatusSha256
      || JSON.stringify(carriedRoot) !== JSON.stringify(rootStatus)) {
      fail("Stage-B reviewer status chain does not replay the exact deployment-intent root");
    }
    if (allowSuccessors && tail.length === 1) {
      fail("Stage-B reviewer status history must omit a lone repeated root or carry it followed by at least one successor");
    }
    const completeHistory = [...rootPrefix, carriedRoot];
    for (const successor of tail.slice(1)) {
      currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
        successor,
        {
          reviewerGenesis: genesis,
          statusHistory: completeHistory,
          ...roleSeparation,
        },
      );
      currentStatusHistory = [...completeHistory];
      completeHistory.push(currentStatus);
      successorStatusCount += 1;
    }
  }
  const currentStatusSha256 = releaseReviewerAuthorityCurrentStatusSha256(
    currentStatus,
    {
      reviewerGenesis: genesis,
      statusHistory: currentStatusHistory,
      ...roleSeparation,
    },
  );
  if (parsed.enforceFreshness) {
    assertReleaseReviewerAuthorityCurrentStatusAtTime(currentStatus, {
      reviewerGenesis: genesis,
      statusHistory: currentStatusHistory,
      ...roleSeparation,
      now: checkedAtSecond(parsed.checkedAtMs),
      expectedCurrentStatusEpoch: currentStatus.epoch,
      expectedCurrentStatusSha256: currentStatusSha256,
    });
  }
  const completeStatusLineage = [...currentStatusHistory, currentStatus];
  return deepFreezeCanonicalPlainDataGraph({
    truth_status: truthStatus,
    acceptance,
    acceptanceSha256,
    genesis,
    genesisSha256: releaseReviewerAuthorityGenesisSha256(genesis),
    roleSeparation,
    rootStatus,
    rootStatusHistory: rootPrefix,
    rootStatusSha256,
    currentStatus,
    currentStatusNotBefore: currentStatus.not_before,
    currentStatusExpiresAt: currentStatus.expires_at,
    currentStatusSha256,
    completeStatusLineage,
    successorStatusCount,
    authority: activeAuthorityFromStatus(currentStatus),
  }, { label: "deployment-rooted reviewer authority" });
}

/** Stage A is permanently rooted at exactly the deployment-intent status. */
export function normalizeStageAPinnedReviewerAuthority(options) {
  const parsed = exactRecord(options, [
    "checkedAtMs", "deploymentIntent", "enforceFreshness",
    "reviewerGenesis", "reviewerGenesisAcceptance",
    "reviewerStatusHistory",
  ], "Stage-A pinned reviewer authority options");
  if (!Array.isArray(parsed.reviewerStatusHistory)
    || parsed.reviewerStatusHistory.length !== 0) {
    fail("Stage A requires an exact empty epoch-one predecessor history");
  }
  const normalized = normalizeDeploymentRootedReviewerAuthority(parsed, {
    allowSuccessors: false,
    truthStatus: STAGE_A_PINNED_REVIEWER_AUTHORITY_ASSERTION_TRUTH,
  });
  if (normalized.rootStatus.epoch !== 1
    || normalized.rootStatus.previous_status_sha256 !== ZERO_SHA256
    || normalized.rootStatusHistory.length !== 0
    || normalized.successorStatusCount !== 0) {
    fail("Stage A is restricted to the exact epoch-one reviewer root");
  }
  return normalized;
}

/**
 * Stage B may use the root itself or a complete, guardian-signed,
 * nonoverlapping successor chain. All transition invariants are enforced by the current
 * status normalizer for every link before the final head is returned.
 */
export function normalizeStageBSuccessorReviewerAuthority(options) {
  return normalizeDeploymentRootedReviewerAuthority(options, {
    allowSuccessors: true,
    truthStatus: STAGE_B_SUCCESSOR_REVIEWER_AUTHORITY_ASSERTION_TRUTH,
  });
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
    "reviewer_authority_current_status_epoch",
    "reviewer_authority_current_status_sha256",
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
    || review.reviewer_authority_current_status_epoch !== 1
    || review.reviewer_authority_current_status_sha256 !== statusSha256
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
