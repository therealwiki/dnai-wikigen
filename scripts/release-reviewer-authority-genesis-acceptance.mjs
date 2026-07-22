import { createHash } from "node:crypto";

import {
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  reviewerSetSha256,
  verifyPinnedAllReviewerAuthorization,
  verifyPinnedTwoSignerAuthorization,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
} from "./release-reviewer-authority-genesis.mjs";

export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA =
  "dnai.release-reviewer-authority-current-status.v1";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA =
  "dnai.release-reviewer-authority-current-status-signing-payload.v1";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DOMAIN =
  "dnai-wikigen/release-reviewer-authority-current-status/v1\0";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SIGNING_DOMAIN =
  "dnai-wikigen/release-reviewer-authority-current-status-signing/v1\0";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MESSAGE_PREFIX =
  "dnai-wikigen reviewer-authority current status v1:";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS =
  "two_genesis_pinned_guardians_are_the_status_root_status_windows_never_overlap_and_omission_cannot_extend_the_anchored_status_past_its_bounded_expiry";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION =
  "both_genesis_pinned_guardians_authorize_only_this_nonoverlapping_release_scoped_status_selected_from_finite_preauthorized_reviewer_keys_for_at_most_fifteen_minutes";
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_LIFETIME_SECONDS = 15 * 60;

export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA =
  "dnai.release-reviewer-authority-genesis-acceptance.v2";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA =
  "dnai.release-reviewer-authority-genesis-acceptance-signing-payload.v2";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DOMAIN =
  "dnai-wikigen/release-reviewer-authority-genesis-acceptance/v2\0";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SIGNING_DOMAIN =
  "dnai-wikigen/release-reviewer-authority-genesis-acceptance-signing/v2\0";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_MESSAGE_PREFIX =
  "dnai-wikigen reviewer-authority genesis acceptance v2:";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DECLARATION =
  "every_guardian_selected_active_reviewer_accepts_this_exact_genesis_and_full_guardian_signed_current_status_instance";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS =
  "all_current_active_reviewers_accepted_the_exact_guardian_signed_status_guardians_remain_the_only_status_root_and_status_is_nonoverlapping_and_expires_within_fifteen_minutes";

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const MAX_EPOCH = 0xffff_ffff;

function fail(message) {
  throw new TypeError(message);
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function exact(value, fields, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function nonzeroAddress(value, label) {
  if (!ADDRESS.test(value) || value === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function controllerId(value, label) {
  if (!CONTROLLER.test(value)) fail(`${label} must be a canonical controller ID`);
  return value;
}

function sha256(value, label, { allowZero = false } = {}) {
  if (!SHA256.test(value) || (!allowZero && value === ZERO_SHA256)) {
    fail(`${label} must be a ${allowZero ? "canonical" : "nonzero"} SHA-256 digest`);
  }
  return value;
}

function canonicalInstant(value, label) {
  if (!INSTANT.test(value)) fail(`${label} must be a canonical UTC whole-second instant`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a real canonical UTC whole-second instant`);
  }
  return { value, milliseconds };
}

function exactCanonicalStrings(values, normalizer, label) {
  if (!Array.isArray(values)) fail(`${label} must be an array`);
  const normalized = values.map((entry, index) => normalizer(entry, `${label} ${index}`));
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1] >= normalized[index]) {
      fail(`${label} must be strictly sorted and distinct`);
    }
  }
  return normalized;
}

function exactSignatureVerifier(value, label) {
  const parsed = exact(value, [
    "build_profile", "commit_sha", "executable_sha256",
    "executable_user_relative_path", "tool", "version",
  ], label);
  for (const [key, expected] of Object.entries(PINNED_CAST_SIGNATURE_VERIFIER)) {
    if (parsed[key] !== expected) fail(`${label} does not use the pinned signature verifier`);
  }
  return { ...PINNED_CAST_SIGNATURE_VERIFIER };
}

function normalizeGenesis(reviewerGenesis, options) {
  return normalizeReleaseReviewerAuthorityGenesis(reviewerGenesis, {
    deploymentRoleAddresses: options?.deploymentRoleAddresses,
    deploymentRoleControllerIds: options?.deploymentRoleControllerIds,
  });
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

function guardianAuthorityFromGenesis(genesis) {
  return normalizeExpectedReviewerAuthority({
    approved_reviewers: genesis.status_guardians,
    approved_reviewer_hashes: genesis.status_guardian_hashes,
    reviewer_root_hash: genesis.status_guardian_root_hash,
    reviewer_set_sha256: genesis.status_guardian_set_sha256,
  }, {
    expectedReviewerRootHash: genesis.status_guardian_root_hash,
    expectedReviewerSetSha256: genesis.status_guardian_set_sha256,
  });
}

function normalizeStatusProposal(value) {
  const parsed = exact(value, [
    "active_reviewers", "epoch", "expires_at", "not_before",
    "previous_status_sha256", "revoked_controller_ids",
    "revoked_reviewer_addresses",
  ], "reviewer current-status proposal");
  if (!Number.isSafeInteger(parsed.epoch) || parsed.epoch < 1 || parsed.epoch > MAX_EPOCH) {
    fail("reviewer current-status epoch is invalid");
  }
  const notBefore = canonicalInstant(parsed.not_before, "reviewer current-status not_before");
  const expiresAt = canonicalInstant(parsed.expires_at, "reviewer current-status expires_at");
  if (expiresAt.milliseconds <= notBefore.milliseconds
    || expiresAt.milliseconds - notBefore.milliseconds
      > RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_LIFETIME_SECONDS * 1_000) {
    fail("reviewer current-status validity window must be positive and no longer than 15 minutes");
  }
  const activeReviewers = (() => {
    if (!Array.isArray(parsed.active_reviewers)) {
      fail("reviewer current-status active reviewers must be an array");
    }
    const normalized = parsed.active_reviewers.map((entry, index) => {
      const reviewer = exact(
        entry,
        ["address", "controller_id"],
        `reviewer current-status active reviewer ${index}`,
      );
      return {
        address: nonzeroAddress(
          reviewer.address,
          `reviewer current-status active reviewer ${index} address`,
        ),
        controller_id: controllerId(
          reviewer.controller_id,
          `reviewer current-status active reviewer ${index} controller`,
        ),
      };
    });
    for (let index = 1; index < normalized.length; index += 1) {
      if (normalized[index - 1].address >= normalized[index].address) {
        fail("reviewer current-status active reviewers must be strictly address-sorted and distinct");
      }
    }
    if (new Set(normalized.map((entry) => entry.controller_id)).size !== normalized.length) {
      fail("reviewer current-status may select at most one key for each controller");
    }
    return normalized;
  })();
  return {
    epoch: parsed.epoch,
    not_before: notBefore.value,
    expires_at: expiresAt.value,
    previous_status_sha256: sha256(
      parsed.previous_status_sha256,
      "reviewer current-status previous digest",
      { allowZero: true },
    ),
    active_reviewers: activeReviewers,
    revoked_controller_ids: exactCanonicalStrings(
      parsed.revoked_controller_ids,
      controllerId,
      "reviewer current-status revoked controller IDs",
    ),
    revoked_reviewer_addresses: exactCanonicalStrings(
      parsed.revoked_reviewer_addresses,
      nonzeroAddress,
      "reviewer current-status revoked reviewer addresses",
    ),
  };
}

function statusArtifactSha256(normalized) {
  return `sha256:${statusArtifactDigest(normalized)}`;
}

function statusArtifactDigest(normalized) {
  return createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DOMAIN, "utf8")
    .update(canonicalText(normalized), "utf8")
    .digest("hex");
}

function normalizeStatusHistory(statusHistory, genesis, options) {
  if (!Array.isArray(statusHistory)) fail("reviewer current-status history must be an array");
  const normalized = [];
  for (const [index, status] of statusHistory.entries()) {
    const next = normalizeCurrentStatusAgainstPrevious(status, {
      genesis,
      previousStatus: normalized.at(-1) ?? null,
      expectedEpoch: index + 1,
      options,
    });
    normalized.push(next);
  }
  return normalized;
}

function validateStatusSelection(proposal, { genesis, previousStatus }) {
  const controllerById = new Map(
    genesis.reviewer_controllers.map((entry) => [entry.controller_id, entry]),
  );
  const allPreauthorizedKeys = new Set(
    genesis.reviewer_controllers.flatMap((entry) => entry.preauthorized_addresses),
  );
  if (proposal.active_reviewers.length < genesis.minimum_active_reviewers) {
    fail("reviewer current-status active set is below the genesis minimum threshold");
  }
  if (proposal.active_reviewers.length > genesis.reviewer_controllers.length) {
    fail("reviewer current-status active set exceeds the finite genesis controllers");
  }
  const revokedControllers = new Set(proposal.revoked_controller_ids);
  const revokedKeys = new Set(proposal.revoked_reviewer_addresses);
  for (const controller of revokedControllers) {
    if (!controllerById.has(controller)) {
      fail("reviewer current-status may revoke only genesis-preauthorized controllers");
    }
  }
  for (const reviewerAddress of revokedKeys) {
    if (!allPreauthorizedKeys.has(reviewerAddress)) {
      fail("reviewer current-status may revoke only genesis-preauthorized reviewer keys");
    }
  }
  for (const reviewer of proposal.active_reviewers) {
    const controller = controllerById.get(reviewer.controller_id);
    if (!controller || !controller.preauthorized_addresses.includes(reviewer.address)) {
      fail("reviewer current-status cannot add or select a key outside the finite genesis inventory");
    }
    if (revokedControllers.has(reviewer.controller_id) || revokedKeys.has(reviewer.address)) {
      fail("reviewer current-status cannot activate a revoked controller or key");
    }
  }
  if (previousStatus) {
    const previousControllers = new Set(
      previousStatus.active_reviewers.map((entry) => entry.controller_id),
    );
    if (proposal.active_reviewers.some((entry) => !previousControllers.has(entry.controller_id))) {
      fail("reviewer current-status successors may rotate preauthorized keys or remove controllers but never add or reactivate controllers");
    }
    if (previousStatus.revoked_controller_ids.some((entry) => !revokedControllers.has(entry))
      || previousStatus.revoked_reviewer_addresses.some((entry) => !revokedKeys.has(entry))) {
      fail("reviewer current-status revocations are monotonic and cannot be removed");
    }
    if (Date.parse(proposal.not_before) < Date.parse(previousStatus.not_before)) {
      fail("reviewer current-status successor not_before cannot move backwards");
    }
    if (Date.parse(proposal.not_before) < Date.parse(previousStatus.expires_at)) {
      fail("reviewer current-status successor windows must not overlap");
    }
  }
}

function createCurrentStatusSigningPayloadFromNormalizedProposal(proposal, {
  genesis,
  previousStatus,
  expectedEpoch,
}) {
  if (proposal.epoch !== expectedEpoch) {
    fail("reviewer current-status epoch must be strictly monotonic with its complete history");
  }
  const expectedPreviousSha256 = previousStatus
    ? statusArtifactSha256(previousStatus)
    : ZERO_SHA256;
  if (proposal.previous_status_sha256 !== expectedPreviousSha256) {
    fail(previousStatus
      ? "reviewer current-status predecessor digest is a rollback or fork"
      : "reviewer current-status epoch 1 must use the zero predecessor digest");
  }
  validateStatusSelection(proposal, { genesis, previousStatus });
  const reviewerHashes = proposal.active_reviewers
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  const reviewerRootHash = executionPolicyReviewerRootHash(reviewerHashes);
  const reviewerSetDigest = reviewerSetSha256(proposal.active_reviewers);
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS,
    declaration: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION,
    release_sha: genesis.release_sha,
    chain_id: genesis.chain_id,
    reviewer_authority_genesis_sha256: releaseReviewerAuthorityGenesisSha256(genesis),
    epoch: proposal.epoch,
    not_before: proposal.not_before,
    expires_at: proposal.expires_at,
    previous_status_sha256: proposal.previous_status_sha256,
    active_reviewers: proposal.active_reviewers,
    approved_reviewer_hashes: reviewerHashes,
    reviewer_root_hash: reviewerRootHash,
    reviewer_set_sha256: reviewerSetDigest,
    minimum_active_reviewers: genesis.minimum_active_reviewers,
    revoked_controller_ids: proposal.revoked_controller_ids,
    revoked_reviewer_addresses: proposal.revoked_reviewer_addresses,
    status_guardian_root_hash: genesis.status_guardian_root_hash,
    status_guardian_set_sha256: genesis.status_guardian_set_sha256,
    guardian_count: genesis.status_guardians.length,
    all_guardians_required: true,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  };
}

export function createReleaseReviewerAuthorityCurrentStatusSigningPayload(value, {
  reviewerGenesis,
  statusHistory = [],
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  const options = { deploymentRoleAddresses, deploymentRoleControllerIds };
  const genesis = normalizeGenesis(reviewerGenesis, options);
  const history = normalizeStatusHistory(statusHistory, genesis, options);
  const proposal = normalizeStatusProposal(value);
  return createCurrentStatusSigningPayloadFromNormalizedProposal(proposal, {
    genesis,
    previousStatus: history.at(-1) ?? null,
    expectedEpoch: history.length + 1,
  });
}

const CURRENT_STATUS_PAYLOAD_FIELDS = Object.freeze([
  "active_reviewers", "all_guardians_required", "approved_reviewer_hashes",
  "chain_id", "declaration", "epoch", "expires_at", "guardian_count",
  "minimum_active_reviewers", "not_before", "previous_status_sha256",
  "release_sha", "reviewer_authority_genesis_sha256", "reviewer_root_hash",
  "reviewer_set_sha256", "revoked_controller_ids", "revoked_reviewer_addresses",
  "schema", "signature_scheme", "signature_verifier", "status_guardian_root_hash",
  "status_guardian_set_sha256", "truth_status",
]);

function statusProposalFromPayload(value) {
  return {
    epoch: value.epoch,
    not_before: value.not_before,
    expires_at: value.expires_at,
    previous_status_sha256: value.previous_status_sha256,
    active_reviewers: value.active_reviewers,
    revoked_controller_ids: value.revoked_controller_ids,
    revoked_reviewer_addresses: value.revoked_reviewer_addresses,
  };
}

function normalizeCurrentStatusSigningPayload(value, options) {
  const parsed = exact(
    value,
    CURRENT_STATUS_PAYLOAD_FIELDS,
    "reviewer current-status signing payload",
  );
  const expected = createReleaseReviewerAuthorityCurrentStatusSigningPayload(
    statusProposalFromPayload(parsed),
    options,
  );
  if (JSON.stringify(sorted(parsed)) !== JSON.stringify(sorted(expected))) {
    fail("reviewer current-status signing payload does not match the finite genesis authority and complete predecessor history");
  }
  return expected;
}

export function releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(value, options) {
  const payload = normalizeCurrentStatusSigningPayload(value, options);
  return eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SIGNING_DOMAIN,
    payload,
  });
}

export function releaseReviewerAuthorityCurrentStatusSigningMessage(value, options) {
  return eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MESSAGE_PREFIX,
    digest: releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(value, options),
  });
}

function normalizeGuardianSignatures(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    fail("reviewer current-status requires both guardian signatures");
  }
  return value.map((entry, index) => {
    const parsed = exact(
      entry,
      ["address", "controller_id", "signature"],
      `reviewer current-status guardian signature ${index}`,
    );
    return {
      address: parsed.address,
      controller_id: parsed.controller_id,
      signature: parsed.signature,
    };
  });
}

function normalizeCurrentStatusAgainstPrevious(value, {
  genesis,
  previousStatus,
  expectedEpoch,
  options,
}) {
  const parsed = exact(value, [
    ...CURRENT_STATUS_PAYLOAD_FIELDS.filter((field) => field !== "schema"),
    "guardian_signatures", "schema", "signing_payload_sha256",
  ], "release reviewer authority current status");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA) {
    fail("reviewer authority current-status v1 schema is required");
  }
  const proposal = normalizeStatusProposal(statusProposalFromPayload(parsed));
  const signingPayload = createCurrentStatusSigningPayloadFromNormalizedProposal(proposal, {
    genesis,
    previousStatus,
    expectedEpoch,
  });
  const payloadCarriedByArtifact = {
    ...parsed,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
  };
  delete payloadCarriedByArtifact.signing_payload_sha256;
  delete payloadCarriedByArtifact.guardian_signatures;
  if (JSON.stringify(sorted(payloadCarriedByArtifact))
    !== JSON.stringify(sorted(signingPayload))) {
    fail("reviewer current-status artifact does not match its exact signing payload");
  }
  exactSignatureVerifier(
    signingPayload.signature_verifier,
    "reviewer current-status signature verifier",
  );
  const signingPayloadSha256 = eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SIGNING_DOMAIN,
    payload: signingPayload,
  });
  if (parsed.signing_payload_sha256 !== signingPayloadSha256) {
    fail("reviewer current-status signing payload digest is invalid");
  }
  const guardianSignatures = normalizeGuardianSignatures(parsed.guardian_signatures);
  const message = eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MESSAGE_PREFIX,
    digest: signingPayloadSha256,
  });
  verifyPinnedTwoSignerAuthorization({
    signatures: guardianSignatures,
    message,
    reviewerAuthority: guardianAuthorityFromGenesis(genesis),
  });
  return {
    ...signingPayload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256: signingPayloadSha256,
    guardian_signatures: guardianSignatures,
  };
}

export function normalizeReleaseReviewerAuthorityCurrentStatus(value, {
  reviewerGenesis,
  statusHistory = [],
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  const options = { deploymentRoleAddresses, deploymentRoleControllerIds };
  const genesis = normalizeGenesis(reviewerGenesis, options);
  const history = normalizeStatusHistory(statusHistory, genesis, options);
  return normalizeCurrentStatusAgainstPrevious(value, {
    genesis,
    previousStatus: history.at(-1) ?? null,
    expectedEpoch: history.length + 1,
    options,
  });
}

export function canonicalReleaseReviewerAuthorityCurrentStatusArtifactText(value, options) {
  return canonicalText(normalizeReleaseReviewerAuthorityCurrentStatus(value, options));
}

export function releaseReviewerAuthorityCurrentStatusDigest(value, options) {
  return statusArtifactDigest(normalizeReleaseReviewerAuthorityCurrentStatus(value, options));
}

export function releaseReviewerAuthorityCurrentStatusSha256(value, options) {
  return `sha256:${releaseReviewerAuthorityCurrentStatusDigest(value, options)}`;
}

export function assertReleaseReviewerAuthorityCurrentStatusAtTime(value, {
  now,
  expectedCurrentStatusEpoch,
  expectedCurrentStatusSha256,
  ...options
} = {}) {
  const normalized = normalizeReleaseReviewerAuthorityCurrentStatus(value, options);
  if (!Number.isSafeInteger(expectedCurrentStatusEpoch)
    || expectedCurrentStatusEpoch < 1
    || expectedCurrentStatusEpoch > MAX_EPOCH
    || normalized.epoch !== expectedCurrentStatusEpoch
    || sha256(
      expectedCurrentStatusSha256,
      "independently anchored reviewer current-status head digest",
    ) !== statusArtifactSha256(normalized)) {
    fail("reviewer current-status is stale or forked from the independently anchored head");
  }
  const current = canonicalInstant(now, "reviewer current-status validation time");
  if (current.milliseconds < Date.parse(normalized.not_before)) {
    fail("reviewer current-status is not active yet");
  }
  if (current.milliseconds >= Date.parse(normalized.expires_at)) {
    fail("reviewer current-status is expired");
  }
  return normalized;
}

export const validateReleaseReviewerAuthorityCurrentStatusAtTime =
  assertReleaseReviewerAuthorityCurrentStatusAtTime;

export function createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
  reviewerGenesis,
  {
    reviewerCurrentStatus,
    statusHistory = [],
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  } = {},
) {
  const options = { deploymentRoleAddresses, deploymentRoleControllerIds };
  const genesis = normalizeGenesis(reviewerGenesis, options);
  const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
    reviewerCurrentStatus,
    {
      reviewerGenesis: genesis,
      statusHistory,
      ...options,
    },
  );
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS,
    declaration: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DECLARATION,
    release_sha: genesis.release_sha,
    chain_id: genesis.chain_id,
    reviewer_authority_genesis_sha256: releaseReviewerAuthorityGenesisSha256(genesis),
    reviewer_authority_genesis_truth_status:
      RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    reviewer_authority_current_status: currentStatus,
    reviewer_authority_current_status_sha256: statusArtifactSha256(currentStatus),
    status_epoch: currentStatus.epoch,
    reviewer_root_hash: currentStatus.reviewer_root_hash,
    reviewer_set_sha256: currentStatus.reviewer_set_sha256,
    reviewer_count: currentStatus.active_reviewers.length,
    minimum_active_reviewers: genesis.minimum_active_reviewers,
    all_active_reviewers_required: true,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  };
}

const ACCEPTANCE_PAYLOAD_FIELDS = Object.freeze([
  "all_active_reviewers_required", "chain_id", "declaration",
  "minimum_active_reviewers", "release_sha", "reviewer_authority_current_status",
  "reviewer_authority_current_status_sha256", "reviewer_authority_genesis_sha256",
  "reviewer_authority_genesis_truth_status", "reviewer_count", "reviewer_root_hash",
  "reviewer_set_sha256", "schema", "signature_scheme", "signature_verifier",
  "status_epoch", "truth_status",
]);

function normalizeAcceptanceSigningPayload(value, reviewerGenesis, options) {
  const parsed = exact(
    value,
    ACCEPTANCE_PAYLOAD_FIELDS,
    "reviewer genesis acceptance signing payload",
  );
  const expected = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    reviewerGenesis,
    {
      reviewerCurrentStatus: parsed.reviewer_authority_current_status,
      statusHistory: options?.statusHistory,
      deploymentRoleAddresses: options?.deploymentRoleAddresses,
      deploymentRoleControllerIds: options?.deploymentRoleControllerIds,
    },
  );
  if (JSON.stringify(sorted(parsed)) !== JSON.stringify(sorted(expected))) {
    fail("reviewer genesis acceptance signing payload does not match the exact genesis and full guardian-signed current status");
  }
  if (!SHA40.test(parsed.release_sha)
    || !SHA256.test(parsed.reviewer_authority_genesis_sha256)
    || !SHA256.test(parsed.reviewer_authority_current_status_sha256)) {
    fail("reviewer genesis acceptance signing payload identifiers are invalid");
  }
  return expected;
}

export function releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
  value,
  { reviewerGenesis, ...options } = {},
) {
  const payload = normalizeAcceptanceSigningPayload(value, reviewerGenesis, options);
  return eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SIGNING_DOMAIN,
    payload,
  });
}

export function releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
  value,
  { reviewerGenesis, ...options } = {},
) {
  return eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_MESSAGE_PREFIX,
    digest: releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
      value,
      { reviewerGenesis, ...options },
    ),
  });
}

export function normalizeReleaseReviewerAuthorityGenesisAcceptance(value, {
  reviewerGenesis,
  statusHistory = [],
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  const options = {
    statusHistory,
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  };
  const genesis = normalizeGenesis(reviewerGenesis, options);
  const parsed = exact(value, [
    ...ACCEPTANCE_PAYLOAD_FIELDS.filter((field) => field !== "schema"),
    "acceptances", "schema", "signing_payload_sha256",
  ], "release reviewer authority genesis acceptance");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA) {
    fail("reviewer authority genesis acceptance v2 schema is required; v1 is not accepted");
  }
  const carriedPayload = { ...parsed, schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA };
  delete carriedPayload.acceptances;
  delete carriedPayload.signing_payload_sha256;
  const signingPayload = normalizeAcceptanceSigningPayload(
    carriedPayload,
    genesis,
    options,
  );
  exactSignatureVerifier(
    signingPayload.signature_verifier,
    "reviewer genesis acceptance signature verifier",
  );
  const signingPayloadSha256 = eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SIGNING_DOMAIN,
    payload: signingPayload,
  });
  if (parsed.signing_payload_sha256 !== signingPayloadSha256) {
    fail("reviewer genesis acceptance signing payload digest is invalid");
  }
  const currentStatus = signingPayload.reviewer_authority_current_status;
  if (!Array.isArray(parsed.acceptances)
    || parsed.acceptances.length !== currentStatus.active_reviewers.length) {
    fail("reviewer genesis acceptance requires every guardian-selected active reviewer signature");
  }
  const acceptances = parsed.acceptances.map((entry, index) => {
    const acceptance = exact(
      entry,
      ["address", "controller_id", "signature"],
      `reviewer genesis acceptance ${index}`,
    );
    return {
      address: acceptance.address,
      controller_id: acceptance.controller_id,
      signature: acceptance.signature,
    };
  });
  const message = eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_MESSAGE_PREFIX,
    digest: signingPayloadSha256,
  });
  verifyPinnedAllReviewerAuthorization({
    signatures: acceptances,
    message,
    reviewerAuthority: activeAuthorityFromStatus(currentStatus),
  });
  return {
    ...signingPayload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256: signingPayloadSha256,
    acceptances,
  };
}

export function canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(value, options) {
  return canonicalText(normalizeReleaseReviewerAuthorityGenesisAcceptance(value, options));
}

export function releaseReviewerAuthorityGenesisAcceptanceDigest(value, options) {
  return createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DOMAIN, "utf8")
    .update(canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(value, options), "utf8")
    .digest("hex");
}

export function releaseReviewerAuthorityGenesisAcceptanceSha256(value, options) {
  return `sha256:${releaseReviewerAuthorityGenesisAcceptanceDigest(value, options)}`;
}

export function assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(value, {
  now,
  expectedCurrentStatusEpoch,
  expectedCurrentStatusSha256,
  reviewerGenesis,
  statusHistory = [],
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  const options = {
    reviewerGenesis,
    statusHistory,
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  };
  const normalized = normalizeReleaseReviewerAuthorityGenesisAcceptance(value, options);
  assertReleaseReviewerAuthorityCurrentStatusAtTime(
    normalized.reviewer_authority_current_status,
    {
      now,
      expectedCurrentStatusEpoch,
      expectedCurrentStatusSha256,
      ...options,
    },
  );
  return normalized;
}
