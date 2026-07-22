import { createHash } from "node:crypto";

import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";

export const RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA =
  "dnai.release-reviewer-authority-genesis.v2";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_DOMAIN =
  "dnai-wikigen/release-reviewer-authority-genesis/v2\0";
export const RELEASE_REVIEWER_CONTROLLER_SET_DOMAIN =
  "dnai-wikigen/release-reviewer-controller-set/v2\0";
export const RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS =
  "release_scoped_finite_reviewer_keys_and_two_guardians_precommitted_guardians_are_status_root_nonoverlapping_statuses_expire_within_fifteen_minutes";
export const RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS = 2;
export const RELEASE_REVIEWER_MAX_CONTROLLERS = 32;
export const RELEASE_REVIEWER_MAX_KEYS_PER_CONTROLLER = 8;
export const RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT = 2;

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const ZERO_SHA40 = "0".repeat(40);
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;

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

function exact(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return value;
}

function address(value, label) {
  if (!ADDRESS.test(value) || value === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function controllerId(value, label) {
  if (!CONTROLLER.test(value)) fail(`${label} must be a canonical controller ID`);
  return value;
}

function exactCanonicalSet(values, normalizer, label) {
  if (!Array.isArray(values)) fail(`${label} must be an array`);
  const normalized = values.map((entry, index) => normalizer(entry, `${label} ${index}`));
  for (let index = 1; index < normalized.length; index += 1) {
    if (normalized[index - 1] >= normalized[index]) {
      fail(`${label} must be strictly sorted and distinct`);
    }
  }
  return normalized;
}

function normalizeDependencySet(values, normalizer, label) {
  if (values === undefined) return new Set();
  return new Set(exactCanonicalSet(values, normalizer, label));
}

function normalizeReviewerControllers(value) {
  if (!Array.isArray(value)
    || value.length < RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS
    || value.length > RELEASE_REVIEWER_MAX_CONTROLLERS) {
    fail(`reviewer controllers must contain from ${RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS} through ${RELEASE_REVIEWER_MAX_CONTROLLERS} entries`);
  }
  const controllers = value.map((entry, index) => {
    const parsed = exact(
      entry,
      ["controller_id", "preauthorized_addresses"],
      `reviewer controller ${index}`,
    );
    const controller = controllerId(parsed.controller_id, `reviewer controller ${index}`);
    if (!Array.isArray(parsed.preauthorized_addresses)
      || parsed.preauthorized_addresses.length < 1
      || parsed.preauthorized_addresses.length > RELEASE_REVIEWER_MAX_KEYS_PER_CONTROLLER) {
      fail(`reviewer controller ${index} must preauthorize from one through ${RELEASE_REVIEWER_MAX_KEYS_PER_CONTROLLER} keys`);
    }
    const preauthorizedAddresses = exactCanonicalSet(
      parsed.preauthorized_addresses,
      address,
      `reviewer controller ${index} preauthorized addresses`,
    );
    return {
      controller_id: controller,
      preauthorized_addresses: preauthorizedAddresses,
    };
  });
  for (let index = 1; index < controllers.length; index += 1) {
    if (controllers[index - 1].controller_id >= controllers[index].controller_id) {
      fail("reviewer controllers must be strictly controller-ID-sorted and distinct");
    }
  }
  const allKeys = controllers.flatMap((entry) => entry.preauthorized_addresses);
  if (new Set(allKeys).size !== allKeys.length) {
    fail("a preauthorized reviewer key may belong to exactly one reviewer controller");
  }
  return controllers;
}

function normalizeStatusGuardians(value, {
  reviewerControllers,
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
}) {
  if (!Array.isArray(value) || value.length !== RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT) {
    fail(`reviewer status authority requires exactly ${RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT} guardians`);
  }
  const reviewerAddresses = new Set(
    reviewerControllers.flatMap((entry) => entry.preauthorized_addresses),
  );
  const reviewerControllerIds = new Set(
    reviewerControllers.map((entry) => entry.controller_id),
  );
  const guardians = value.map((entry, index) => {
    const parsed = exact(entry, ["address", "controller_id"], `status guardian ${index}`);
    const guardianAddress = address(parsed.address, `status guardian ${index} address`);
    const guardianController = controllerId(
      parsed.controller_id,
      `status guardian ${index} controller`,
    );
    if (reviewerAddresses.has(guardianAddress)
      || reviewerControllerIds.has(guardianController)) {
      fail("status guardians must be distinct from every reviewer key and controller");
    }
    if (deploymentRoleAddresses.has(guardianAddress)
      || deploymentRoleControllerIds.has(guardianController)) {
      fail("status guardians must be distinct from supplied deployment-role identities");
    }
    return { address: guardianAddress, controller_id: guardianController };
  });
  for (let index = 1; index < guardians.length; index += 1) {
    if (guardians[index - 1].address >= guardians[index].address) {
      fail("status guardians must be strictly address-sorted and distinct");
    }
  }
  if (new Set(guardians.map((entry) => entry.controller_id)).size !== guardians.length) {
    fail("status guardian controller IDs must be distinct");
  }
  return guardians;
}

export function reviewerControllerSetSha256(value) {
  const controllers = normalizeReviewerControllers(value);
  return `sha256:${createHash("sha256")
    .update(RELEASE_REVIEWER_CONTROLLER_SET_DOMAIN, "utf8")
    .update(canonicalText(controllers), "utf8")
    .digest("hex")}`;
}

/**
 * Normalize the release-scoped finite reviewer inventory and its independent
 * two-guardian status root. When deployment identities are known, callers must
 * pass their canonical sorted address/controller sets so guardian separation is
 * checked transitively instead of being asserted by this artifact itself.
 */
export function normalizeReleaseReviewerAuthorityGenesis(value, {
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  const parsed = exact(value, [
    "chain_id", "minimum_active_reviewers", "release_sha",
    "reviewer_controller_set_sha256", "reviewer_controllers", "schema",
    "status_guardian_hashes", "status_guardian_root_hash",
    "status_guardian_set_sha256", "status_guardians", "truth_status",
  ], "release reviewer authority genesis");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA) {
    fail("release reviewer authority genesis v2 schema is required; v1 is not accepted");
  }
  if (parsed.truth_status !== RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS
    || !SHA40.test(parsed.release_sha) || parsed.release_sha === ZERO_SHA40
    || parsed.chain_id !== 84_532
    || parsed.minimum_active_reviewers !== RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS) {
    fail("release reviewer authority genesis header is invalid");
  }
  const reviewers = normalizeReviewerControllers(parsed.reviewer_controllers);
  const controllerSetSha256 = reviewerControllerSetSha256(reviewers);
  if (!SHA256.test(parsed.reviewer_controller_set_sha256)
    || parsed.reviewer_controller_set_sha256 !== controllerSetSha256) {
    fail("reviewer controller inventory does not match its domain-separated digest");
  }
  const roleAddresses = normalizeDependencySet(
    deploymentRoleAddresses,
    address,
    "deployment role addresses",
  );
  const roleControllerIds = normalizeDependencySet(
    deploymentRoleControllerIds,
    controllerId,
    "deployment role controller IDs",
  );
  const guardians = normalizeStatusGuardians(parsed.status_guardians, {
    reviewerControllers: reviewers,
    deploymentRoleAddresses: roleAddresses,
    deploymentRoleControllerIds: roleControllerIds,
  });
  const guardianHashes = guardians
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  const guardianRootHash = executionPolicyReviewerRootHash(guardianHashes);
  const guardianSetSha256 = reviewerSetSha256(guardians);
  if (!Array.isArray(parsed.status_guardian_hashes)
    || parsed.status_guardian_hashes.some((entry) => !BARE_SHA256.test(entry))
    || JSON.stringify(parsed.status_guardian_hashes) !== JSON.stringify(guardianHashes)
    || parsed.status_guardian_root_hash !== guardianRootHash
    || parsed.status_guardian_set_sha256 !== guardianSetSha256) {
    fail("status guardian identities do not match their hashes/root/set digest");
  }
  return {
    schema: parsed.schema,
    truth_status: parsed.truth_status,
    release_sha: parsed.release_sha,
    chain_id: parsed.chain_id,
    minimum_active_reviewers: parsed.minimum_active_reviewers,
    reviewer_controllers: reviewers,
    reviewer_controller_set_sha256: controllerSetSha256,
    status_guardians: guardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: guardianRootHash,
    status_guardian_set_sha256: guardianSetSha256,
  };
}

/**
 * Cross-authority validator for stages where deployment identities are known.
 * Keeping this separate avoids a genesis/deployment-intent digest cycle while
 * making omission of the dependency an explicit error at A/B/C validation.
 */
export function assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(value, {
  deploymentRoleAddresses,
  deploymentRoleControllerIds,
} = {}) {
  if (!Array.isArray(deploymentRoleAddresses)
    || !Array.isArray(deploymentRoleControllerIds)
    || deploymentRoleAddresses.length + deploymentRoleControllerIds.length < 1) {
    fail("deployment-role separation requires explicit authoritative address and controller-ID arrays");
  }
  return normalizeReleaseReviewerAuthorityGenesis(value, {
    deploymentRoleAddresses,
    deploymentRoleControllerIds,
  });
}

export function canonicalReleaseReviewerAuthorityGenesisArtifactText(value, options) {
  return canonicalText(normalizeReleaseReviewerAuthorityGenesis(value, options));
}

export function releaseReviewerAuthorityGenesisDigest(value, options) {
  return createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_DOMAIN, "utf8")
    .update(canonicalReleaseReviewerAuthorityGenesisArtifactText(value, options), "utf8")
    .digest("hex");
}

export function releaseReviewerAuthorityGenesisSha256(value, options) {
  return `sha256:${releaseReviewerAuthorityGenesisDigest(value, options)}`;
}
