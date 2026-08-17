import { createHash } from "node:crypto";

import {
  assertCanonicalPlainDataGraph,
  deepFreezeCanonicalPlainDataGraph,
} from "./canonical-authority-graph.mjs";
import {
  INDEPENDENT_EIP191_REPLAY_VERIFIER,
  PINNED_CAST_SIGNATURE_VERIFIER,
  PINNED_EIP191_SIGNATURE_SCHEME,
  eip191AuthorizationSigningDigest,
  eip191AuthorizationSigningMessage,
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  normalizeExpectedReviewerAuthority,
  normalizeReviewerAuthorizationSignatures,
  reviewerSetSha256,
  verifyIndependentEip191PersonalSignature,
} from "./release-authority-signature-verifier-core.mjs";

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
export const RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_LIFETIME_SECONDS =
  15 * 60;

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

export const RELEASE_REVIEWER_AUTHORITY_HISTORICAL_RECONSTRUCTION_SCHEMA =
  "dnai.release-reviewer-authority-historical-reconstruction.v1";
export const RELEASE_REVIEWER_AUTHORITY_HISTORICAL_RECONSTRUCTION_TRUTH =
  "persisted_epoch_one_guardian_and_active_reviewer_signatures_independently_replayed_at_explicit_historical_time_with_no_uncommitted_status_history_current_clock_brand_or_live_authority";
export const EXACT37_CURRENT_REVIEWER_AUTHORITY_ASSERTION_TRUTH =
  "deployment_intent_anchored_epoch_one_acceptance_status_current_with_no_unprovided_history";

const SHA40 = /^[0-9a-f]{40}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const BARE_SHA256 = /^[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const CONTROLLER = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ZERO_SHA40 = "0".repeat(40);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const MAX_EPOCH = 0xffff_ffff;
const ARRAY_INDEX = /^(?:0|[1-9][0-9]*)$/;
const MAXIMUM_CANONICAL_DEPTH = 64;
const MAXIMUM_CANONICAL_NODES = 100_000;

const CURRENT_STATUS_PAYLOAD_FIELDS = Object.freeze([
  "active_reviewers", "all_guardians_required", "approved_reviewer_hashes",
  "chain_id", "declaration", "epoch", "expires_at", "guardian_count",
  "minimum_active_reviewers", "not_before", "previous_status_sha256",
  "release_sha", "reviewer_authority_genesis_sha256", "reviewer_root_hash",
  "reviewer_set_sha256", "revoked_controller_ids", "revoked_reviewer_addresses",
  "schema", "signature_scheme", "signature_verifier", "status_guardian_root_hash",
  "status_guardian_set_sha256", "truth_status",
]);

const ACCEPTANCE_PAYLOAD_FIELDS = Object.freeze([
  "all_active_reviewers_required", "chain_id", "declaration",
  "minimum_active_reviewers", "release_sha", "reviewer_authority_current_status",
  "reviewer_authority_current_status_sha256", "reviewer_authority_genesis_sha256",
  "reviewer_authority_genesis_truth_status", "reviewer_count", "reviewer_root_hash",
  "reviewer_set_sha256", "schema", "signature_scheme", "signature_verifier",
  "status_epoch", "truth_status",
]);

const HISTORICAL_RECONSTRUCTION_INPUT_FIELDS = Object.freeze([
  "deploymentRoleAddresses",
  "deploymentRoleControllerIds",
  "expectedChainId",
  "expectedCurrentStatusSha256",
  "expectedReleaseSha",
  "expectedReviewerGenesisAcceptanceSha256",
  "expectedReviewerGenesisSha256",
  "expectedReviewerRootHash",
  "expectedReviewerSetSha256",
  "expectedStatusGuardianRootHash",
  "expectedStatusGuardianSetSha256",
  "reviewerGenesis",
  "reviewerGenesisAcceptance",
  "validationTime",
]);

function fail(message) {
  throw new TypeError(message);
}

/**
 * Reject Proxies non-trapping in the shared canonical validator, then detach
 * caller-owned values using only own data descriptors. Semantic code reads
 * only the snapshot, never the original graph.
 */
function snapshotCanonicalOwnDataGraph(value, label) {
  assertCanonicalPlainDataGraph(value, { label });
  const active = [];
  let nodes = 0;

  function visit(entry, depth) {
    if (entry === null || typeof entry === "string"
      || typeof entry === "boolean") return entry;
    if (typeof entry === "number") {
      if (!Number.isFinite(entry) || Object.is(entry, -0)) {
        fail(`${label} numbers must be finite and must not be negative zero`);
      }
      return entry;
    }
    if (typeof entry !== "object") {
      fail(`${label} allows only JSON data types`);
    }
    if (depth > MAXIMUM_CANONICAL_DEPTH) {
      fail(`${label} maximum depth exceeded`);
    }
    if (active.includes(entry)) fail(`${label} cycles are forbidden`);
    nodes += 1;
    if (nodes > MAXIMUM_CANONICAL_NODES) {
      fail(`${label} maximum node count exceeded`);
    }
    if (ArrayBuffer.isView(entry) || entry instanceof ArrayBuffer
      || (typeof SharedArrayBuffer !== "undefined"
        && entry instanceof SharedArrayBuffer)) {
      fail(`${label} typed, binary, or shared mutable buffers are forbidden`);
    }

    const isArray = Array.isArray(entry);
    let prototype;
    let descriptors;
    try {
      prototype = Object.getPrototypeOf(entry);
      descriptors = Object.getOwnPropertyDescriptors(entry);
    } catch {
      fail(`${label} could not be snapshotted as own data`);
    }
    if (isArray ? prototype !== Array.prototype
      : prototype !== Object.prototype && prototype !== null) {
      fail(`${label} custom prototypes are forbidden`);
    }
    const keys = Reflect.ownKeys(descriptors);
    if (keys.some((key) => typeof key !== "string")) {
      fail(`${label} symbol keys are forbidden`);
    }
    let output;
    if (isArray) {
      const lengthDescriptor = descriptors.length;
      const stringKeys = keys.filter((key) => key !== "length");
      const length = lengthDescriptor?.value;
      if (!lengthDescriptor || lengthDescriptor.enumerable
        || !Object.hasOwn(lengthDescriptor, "value")
        || !Number.isSafeInteger(length) || length < 0
        || stringKeys.length !== length
        || stringKeys.some((key) => !ARRAY_INDEX.test(key))
        || stringKeys.map(Number).sort((left, right) => left - right)
          .some((index, position) => index !== position)) {
        fail(`${label} arrays must be dense and cannot have extra properties`);
      }
      output = [];
    } else {
      output = {};
    }

    for (const key of keys) {
      if (isArray && key === "length") continue;
      const descriptor = descriptors[key];
      if (!descriptor || !descriptor.enumerable
        || !Object.hasOwn(descriptor, "value")
        || typeof descriptor.get === "function"
        || typeof descriptor.set === "function") {
        fail(`${label} accessors and non-enumerable data fields are forbidden`);
      }
    }

    active.push(entry);
    for (const key of keys) {
      if (isArray && key === "length") continue;
      const child = visit(descriptors[key].value, depth + 1);
      Object.defineProperty(output, key, {
        value: child,
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    active.pop();
    return output;
  }

  return deepFreezeCanonicalPlainDataGraph(visit(value, 0), {
    label: `${label} snapshot`,
  });
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value, fields, label) {
  const snapshot = snapshotCanonicalOwnDataGraph(value, label);
  if (!isRecord(snapshot)
    || JSON.stringify(Object.keys(snapshot).sort())
      !== JSON.stringify([...fields].sort())) {
    fail(`${label} fields do not match the exact schema`);
  }
  return snapshot;
}

function canonicalOptions(value, label) {
  const options = snapshotCanonicalOwnDataGraph(value ?? {}, label);
  if (!isRecord(options)) fail(`${label} must be an object`);
  return options;
}

function definedOptions(value) {
  return Object.fromEntries(
    Object.entries(value).filter(([, entry]) => entry !== undefined),
  );
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (!isRecord(value)) return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sorted(value[key])]),
  );
}

function canonicalText(value) {
  return `${JSON.stringify(sorted(value), null, 2)}\n`;
}

function nonzeroAddress(value, label) {
  if (typeof value !== "string" || !ADDRESS.test(value)
    || value === ZERO_ADDRESS) {
    fail(`${label} must be a nonzero lowercase address`);
  }
  return value;
}

function controllerId(value, label) {
  if (typeof value !== "string" || !CONTROLLER.test(value)) {
    fail(`${label} must be a canonical controller ID`);
  }
  return value;
}

function releaseSha(value, label) {
  if (typeof value !== "string" || !SHA40.test(value)
    || value === ZERO_SHA40) {
    fail(`${label} must be a nonzero lowercase 40-hex release SHA`);
  }
  return value;
}

function sha256(value, label, { allowZero = false } = {}) {
  if (typeof value !== "string" || !SHA256.test(value)
    || (!allowZero && value === ZERO_SHA256)) {
    fail(`${label} must be a ${allowZero ? "canonical" : "nonzero"} SHA-256 digest`);
  }
  return value;
}

function bareSha256(value, label) {
  if (typeof value !== "string" || !BARE_SHA256.test(value)
    || value === "0".repeat(64)) {
    fail(`${label} must be a nonzero bare SHA-256 digest`);
  }
  return value;
}

function canonicalInstant(value, label) {
  if (typeof value !== "string" || !INSTANT.test(value)) {
    fail(`${label} must be a canonical UTC whole-second instant`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)
    || new Date(milliseconds).toISOString().replace(".000Z", "Z") !== value) {
    fail(`${label} must be a real canonical UTC whole-second instant`);
  }
  return { value, milliseconds };
}

function exactCanonicalSet(values, normalizer, label) {
  const snapshot = snapshotCanonicalOwnDataGraph(values, label);
  if (!Array.isArray(snapshot)) fail(`${label} must be an array`);
  const normalized = snapshot.map((entry, index) => (
    normalizer(entry, `${label} ${index}`)
  ));
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

function exactSignatureVerifier(value, label) {
  const parsed = exact(value, [
    "build_profile", "commit_sha", "executable_sha256",
    "executable_user_relative_path", "tool", "version",
  ], label);
  for (const [key, expected] of Object.entries(PINNED_CAST_SIGNATURE_VERIFIER)) {
    if (parsed[key] !== expected) {
      fail(`${label} does not use the pinned signature verifier`);
    }
  }
  return { ...PINNED_CAST_SIGNATURE_VERIFIER };
}

function normalizeReviewerControllers(value) {
  const snapshot = snapshotCanonicalOwnDataGraph(value, "reviewer controllers");
  if (!Array.isArray(snapshot)
    || snapshot.length < RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS
    || snapshot.length > RELEASE_REVIEWER_MAX_CONTROLLERS) {
    fail(`reviewer controllers must contain from ${RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS} through ${RELEASE_REVIEWER_MAX_CONTROLLERS} entries`);
  }
  const controllers = snapshot.map((entry, index) => {
    const parsed = exact(
      entry,
      ["controller_id", "preauthorized_addresses"],
      `reviewer controller ${index}`,
    );
    const controller = controllerId(
      parsed.controller_id,
      `reviewer controller ${index}`,
    );
    if (!Array.isArray(parsed.preauthorized_addresses)
      || parsed.preauthorized_addresses.length < 1
      || parsed.preauthorized_addresses.length
        > RELEASE_REVIEWER_MAX_KEYS_PER_CONTROLLER) {
      fail(`reviewer controller ${index} must preauthorize from one through ${RELEASE_REVIEWER_MAX_KEYS_PER_CONTROLLER} keys`);
    }
    return {
      controller_id: controller,
      preauthorized_addresses: exactCanonicalSet(
        parsed.preauthorized_addresses,
        nonzeroAddress,
        `reviewer controller ${index} preauthorized addresses`,
      ),
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
  const snapshot = snapshotCanonicalOwnDataGraph(
    value,
    "reviewer status guardians",
  );
  if (!Array.isArray(snapshot)
    || snapshot.length !== RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT) {
    fail(`reviewer status authority requires exactly ${RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT} guardians`);
  }
  const reviewerAddresses = new Set(
    reviewerControllers.flatMap((entry) => entry.preauthorized_addresses),
  );
  const reviewerControllerIds = new Set(
    reviewerControllers.map((entry) => entry.controller_id),
  );
  const guardians = snapshot.map((entry, index) => {
    const parsed = exact(entry, ["address", "controller_id"], `status guardian ${index}`);
    const guardianAddress = nonzeroAddress(
      parsed.address,
      `status guardian ${index} address`,
    );
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
  if (new Set(guardians.map((entry) => entry.controller_id)).size
      !== guardians.length) {
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

export function normalizeReleaseReviewerAuthorityGenesis(value, optionsValue) {
  const options = canonicalOptions(
    optionsValue,
    "release reviewer authority genesis options",
  );
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
    || parsed.minimum_active_reviewers
      !== RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS) {
    fail("release reviewer authority genesis header is invalid");
  }
  const reviewers = normalizeReviewerControllers(parsed.reviewer_controllers);
  const controllerSetSha256 = reviewerControllerSetSha256(reviewers);
  if (!SHA256.test(parsed.reviewer_controller_set_sha256)
    || parsed.reviewer_controller_set_sha256 !== controllerSetSha256) {
    fail("reviewer controller inventory does not match its domain-separated digest");
  }
  const roleAddresses = normalizeDependencySet(
    options.deploymentRoleAddresses,
    nonzeroAddress,
    "deployment role addresses",
  );
  const roleControllerIds = normalizeDependencySet(
    options.deploymentRoleControllerIds,
    controllerId,
    "deployment role controller IDs",
  );
  const reviewerAddresses = reviewers.flatMap(
    (entry) => entry.preauthorized_addresses,
  );
  const reviewerControllerIds = reviewers.map((entry) => entry.controller_id);
  if (reviewerAddresses.some((entry) => roleAddresses.has(entry))
    || reviewerControllerIds.some((entry) => roleControllerIds.has(entry))) {
    fail("reviewer keys and controllers must be distinct from supplied deployment-role identities");
  }
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
    || JSON.stringify(parsed.status_guardian_hashes)
      !== JSON.stringify(guardianHashes)
    || parsed.status_guardian_root_hash !== guardianRootHash
    || parsed.status_guardian_set_sha256 !== guardianSetSha256) {
    fail("status guardian identities do not match their hashes/root/set digest");
  }
  return deepFreezeCanonicalPlainDataGraph({
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
  }, { label: "normalized release reviewer authority genesis" });
}

export function assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
  value,
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "release reviewer deployment-role separation options",
  );
  if (!Array.isArray(options.deploymentRoleAddresses)
    || !Array.isArray(options.deploymentRoleControllerIds)
    || options.deploymentRoleAddresses.length
      + options.deploymentRoleControllerIds.length < 1) {
    fail("deployment-role separation requires explicit authoritative address and controller-ID arrays");
  }
  return normalizeReleaseReviewerAuthorityGenesis(value, options);
}

export function canonicalReleaseReviewerAuthorityGenesisArtifactText(
  value,
  options,
) {
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

function normalizeGenesis(reviewerGenesis, options) {
  return normalizeReleaseReviewerAuthorityGenesis(reviewerGenesis, definedOptions({
    deploymentRoleAddresses: options?.deploymentRoleAddresses,
    deploymentRoleControllerIds: options?.deploymentRoleControllerIds,
  }));
}

function activeAuthorityFromStatus(status, options = {}) {
  const expectedReviewerRootHash = options.expectedReviewerRootHash
    ?? status.reviewer_root_hash;
  const expectedReviewerSetSha256 = options.expectedReviewerSetSha256
    ?? status.reviewer_set_sha256;
  return normalizeExpectedReviewerAuthority({
    approved_reviewers: status.active_reviewers,
    approved_reviewer_hashes: status.approved_reviewer_hashes,
    reviewer_root_hash: status.reviewer_root_hash,
    reviewer_set_sha256: status.reviewer_set_sha256,
  }, { expectedReviewerRootHash, expectedReviewerSetSha256 });
}

function guardianAuthorityFromGenesis(genesis, options = {}) {
  const expectedReviewerRootHash = options.expectedStatusGuardianRootHash
    ?? genesis.status_guardian_root_hash;
  const expectedReviewerSetSha256 = options.expectedStatusGuardianSetSha256
    ?? genesis.status_guardian_set_sha256;
  return normalizeExpectedReviewerAuthority({
    approved_reviewers: genesis.status_guardians,
    approved_reviewer_hashes: genesis.status_guardian_hashes,
    reviewer_root_hash: genesis.status_guardian_root_hash,
    reviewer_set_sha256: genesis.status_guardian_set_sha256,
  }, { expectedReviewerRootHash, expectedReviewerSetSha256 });
}

function normalizeStatusProposal(value) {
  const parsed = exact(value, [
    "active_reviewers", "epoch", "expires_at", "not_before",
    "previous_status_sha256", "revoked_controller_ids",
    "revoked_reviewer_addresses",
  ], "reviewer current-status proposal");
  if (!Number.isSafeInteger(parsed.epoch)
    || parsed.epoch < 1 || parsed.epoch > MAX_EPOCH) {
    fail("reviewer current-status epoch is invalid");
  }
  const notBefore = canonicalInstant(
    parsed.not_before,
    "reviewer current-status not_before",
  );
  const expiresAt = canonicalInstant(
    parsed.expires_at,
    "reviewer current-status expires_at",
  );
  if (expiresAt.milliseconds <= notBefore.milliseconds
    || expiresAt.milliseconds - notBefore.milliseconds
      > RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_LIFETIME_SECONDS * 1_000) {
    fail("reviewer current-status validity window must be positive and no longer than 15 minutes");
  }
  if (!Array.isArray(parsed.active_reviewers)) {
    fail("reviewer current-status active reviewers must be an array");
  }
  const activeReviewers = parsed.active_reviewers.map((entry, index) => {
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
  for (let index = 1; index < activeReviewers.length; index += 1) {
    if (activeReviewers[index - 1].address >= activeReviewers[index].address) {
      fail("reviewer current-status active reviewers must be strictly address-sorted and distinct");
    }
  }
  if (new Set(activeReviewers.map((entry) => entry.controller_id)).size
      !== activeReviewers.length) {
    fail("reviewer current-status may select at most one key for each controller");
  }
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
    revoked_controller_ids: exactCanonicalSet(
      parsed.revoked_controller_ids,
      controllerId,
      "reviewer current-status revoked controller IDs",
    ),
    revoked_reviewer_addresses: exactCanonicalSet(
      parsed.revoked_reviewer_addresses,
      nonzeroAddress,
      "reviewer current-status revoked reviewer addresses",
    ),
  };
}

function statusArtifactDigest(normalized) {
  return createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DOMAIN, "utf8")
    .update(canonicalText(normalized), "utf8")
    .digest("hex");
}

function statusArtifactSha256(normalized) {
  return `sha256:${statusArtifactDigest(normalized)}`;
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
    if (!controller
      || !controller.preauthorized_addresses.includes(reviewer.address)) {
      fail("reviewer current-status cannot add or select a key outside the finite genesis inventory");
    }
    if (revokedControllers.has(reviewer.controller_id)
      || revokedKeys.has(reviewer.address)) {
      fail("reviewer current-status cannot activate a revoked controller or key");
    }
  }
  if (previousStatus) {
    const previousControllers = new Set(
      previousStatus.active_reviewers.map((entry) => entry.controller_id),
    );
    if (proposal.active_reviewers.some(
      (entry) => !previousControllers.has(entry.controller_id),
    )) {
      fail("reviewer current-status successors may rotate preauthorized keys or remove controllers but never add or reactivate controllers");
    }
    if (previousStatus.revoked_controller_ids.some(
      (entry) => !revokedControllers.has(entry),
    ) || previousStatus.revoked_reviewer_addresses.some(
      (entry) => !revokedKeys.has(entry),
    )) {
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
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_TRUTH_STATUS,
    declaration: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DECLARATION,
    release_sha: genesis.release_sha,
    chain_id: genesis.chain_id,
    reviewer_authority_genesis_sha256:
      releaseReviewerAuthorityGenesisSha256(genesis),
    epoch: proposal.epoch,
    not_before: proposal.not_before,
    expires_at: proposal.expires_at,
    previous_status_sha256: proposal.previous_status_sha256,
    active_reviewers: proposal.active_reviewers,
    approved_reviewer_hashes: reviewerHashes,
    reviewer_root_hash: executionPolicyReviewerRootHash(reviewerHashes),
    reviewer_set_sha256: reviewerSetSha256(proposal.active_reviewers),
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

function normalizeStatusHistory(statusHistory, genesis, options) {
  const snapshot = snapshotCanonicalOwnDataGraph(
    statusHistory,
    "reviewer current-status history",
  );
  if (!Array.isArray(snapshot)) {
    fail("reviewer current-status history must be an array");
  }
  const normalized = [];
  for (const [index, status] of snapshot.entries()) {
    const result = normalizeCurrentStatusAgainstPrevious(status, {
      genesis,
      previousStatus: normalized.at(-1) ?? null,
      expectedEpoch: index + 1,
      options,
    });
    normalized.push(result.artifact);
  }
  return normalized;
}

export function createReleaseReviewerAuthorityCurrentStatusSigningPayload(
  value,
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer current-status signing payload options",
  );
  const genesis = normalizeGenesis(options.reviewerGenesis, options);
  const history = normalizeStatusHistory(
    options.statusHistory ?? [],
    genesis,
    options,
  );
  const proposal = normalizeStatusProposal(value);
  return deepFreezeCanonicalPlainDataGraph(
    createCurrentStatusSigningPayloadFromNormalizedProposal(proposal, {
      genesis,
      previousStatus: history.at(-1) ?? null,
      expectedEpoch: history.length + 1,
    }),
    { label: "release reviewer current-status signing payload" },
  );
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

export function releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
  value,
  options,
) {
  const payload = normalizeCurrentStatusSigningPayload(value, options);
  return eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SIGNING_DOMAIN,
    payload,
  });
}

export function releaseReviewerAuthorityCurrentStatusSigningMessage(
  value,
  options,
) {
  return eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MESSAGE_PREFIX,
    digest: releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
      value,
      options,
    ),
  });
}

function normalizeWireSignatures(value, label) {
  const snapshot = snapshotCanonicalOwnDataGraph(value, label);
  if (!Array.isArray(snapshot)) fail(`${label} must be an array`);
  return snapshot.map((entry, index) => {
    const parsed = exact(
      entry,
      ["address", "controller_id", "signature"],
      `${label} ${index}`,
    );
    return {
      address: parsed.address,
      controller_id: parsed.controller_id,
      signature: parsed.signature,
    };
  });
}

function replayReviewerSignatures({
  signatures,
  message,
  reviewerAuthority,
  expectedReviewerRootHash,
  expectedReviewerSetSha256,
  expectedSignerCount,
  requireEveryReviewer,
  label,
}) {
  const structure = normalizeReviewerAuthorizationSignatures({
    signatures,
    reviewerAuthority,
    expectedReviewerRootHash,
    expectedReviewerSetSha256,
    expectedSignerCount,
    requireEveryReviewer,
  });
  const wireSignatures = structure.signatures.map((entry) => ({
    address: entry.address,
    controller_id: entry.controller_id,
    signature: entry.signature,
  }));
  const replay = structure.signatures.map((entry) => {
    const verified = verifyIndependentEip191PersonalSignature({
      address: entry.address,
      message,
      signature: entry.signature,
    });
    return {
      address: entry.address,
      controller_id: entry.controller_id,
      signature_sha256: verified.signature_sha256,
    };
  });
  return {
    wireSignatures: deepFreezeCanonicalPlainDataGraph(wireSignatures, {
      label: `${label} wire signatures`,
    }),
    replay: deepFreezeCanonicalPlainDataGraph(replay, {
      label: `${label} replay evidence`,
    }),
  };
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
  const signingPayload = createCurrentStatusSigningPayloadFromNormalizedProposal(
    proposal,
    { genesis, previousStatus, expectedEpoch },
  );
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
  const guardianSignatures = normalizeWireSignatures(
    parsed.guardian_signatures,
    "reviewer current-status guardian signatures",
  );
  if (guardianSignatures.length !== RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT) {
    fail("reviewer current-status requires both guardian signatures");
  }
  const guardianAuthority = guardianAuthorityFromGenesis(genesis, options);
  const replay = replayReviewerSignatures({
    signatures: guardianSignatures,
    message: eip191AuthorizationSigningMessage({
      prefix: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_MESSAGE_PREFIX,
      digest: signingPayloadSha256,
    }),
    reviewerAuthority: guardianAuthority,
    expectedReviewerRootHash: options.expectedStatusGuardianRootHash
      ?? genesis.status_guardian_root_hash,
    expectedReviewerSetSha256: options.expectedStatusGuardianSetSha256
      ?? genesis.status_guardian_set_sha256,
    expectedSignerCount: RELEASE_REVIEWER_STATUS_GUARDIAN_COUNT,
    requireEveryReviewer: true,
    label: "reviewer current-status guardian",
  });
  const artifact = deepFreezeCanonicalPlainDataGraph({
    ...signingPayload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256: signingPayloadSha256,
    guardian_signatures: replay.wireSignatures,
  }, { label: "normalized release reviewer authority current status" });
  return { artifact, replay: replay.replay };
}

function normalizeCurrentStatusWithReplay(value, optionsValue) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer current-status normalization options",
  );
  const genesis = normalizeGenesis(options.reviewerGenesis, options);
  const history = normalizeStatusHistory(
    options.statusHistory ?? [],
    genesis,
    options,
  );
  return normalizeCurrentStatusAgainstPrevious(value, {
    genesis,
    previousStatus: history.at(-1) ?? null,
    expectedEpoch: history.length + 1,
    options,
  });
}

export function normalizeReleaseReviewerAuthorityCurrentStatus(
  value,
  options,
) {
  return normalizeCurrentStatusWithReplay(value, options).artifact;
}

export function canonicalReleaseReviewerAuthorityCurrentStatusArtifactText(
  value,
  options,
) {
  return canonicalText(normalizeReleaseReviewerAuthorityCurrentStatus(value, options));
}

export function releaseReviewerAuthorityCurrentStatusDigest(value, options) {
  return statusArtifactDigest(
    normalizeReleaseReviewerAuthorityCurrentStatus(value, options),
  );
}

export function releaseReviewerAuthorityCurrentStatusSha256(value, options) {
  return `sha256:${releaseReviewerAuthorityCurrentStatusDigest(value, options)}`;
}

export function assertReleaseReviewerAuthorityCurrentStatusAtTime(
  value,
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer current-status currentness options",
  );
  const normalized = normalizeReleaseReviewerAuthorityCurrentStatus(
    value,
    options,
  );
  if (!Number.isSafeInteger(options.expectedCurrentStatusEpoch)
    || options.expectedCurrentStatusEpoch < 1
    || options.expectedCurrentStatusEpoch > MAX_EPOCH
    || normalized.epoch !== options.expectedCurrentStatusEpoch
    || sha256(
      options.expectedCurrentStatusSha256,
      "independently anchored reviewer current-status head digest",
    ) !== statusArtifactSha256(normalized)) {
    fail("reviewer current-status is stale or forked from the independently anchored head");
  }
  const current = canonicalInstant(
    options.now,
    "reviewer current-status validation time",
  );
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
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer genesis acceptance signing payload options",
  );
  const genesis = normalizeGenesis(reviewerGenesis, options);
  const currentStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
    options.reviewerCurrentStatus,
    definedOptions({
      reviewerGenesis: genesis,
      statusHistory: options.statusHistory ?? [],
      deploymentRoleAddresses: options.deploymentRoleAddresses,
      deploymentRoleControllerIds: options.deploymentRoleControllerIds,
      expectedStatusGuardianRootHash: options.expectedStatusGuardianRootHash,
      expectedStatusGuardianSetSha256: options.expectedStatusGuardianSetSha256,
    }),
  );
  return deepFreezeCanonicalPlainDataGraph({
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_TRUTH_STATUS,
    declaration: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DECLARATION,
    release_sha: genesis.release_sha,
    chain_id: genesis.chain_id,
    reviewer_authority_genesis_sha256:
      releaseReviewerAuthorityGenesisSha256(genesis),
    reviewer_authority_genesis_truth_status:
      RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    reviewer_authority_current_status: currentStatus,
    reviewer_authority_current_status_sha256:
      statusArtifactSha256(currentStatus),
    status_epoch: currentStatus.epoch,
    reviewer_root_hash: currentStatus.reviewer_root_hash,
    reviewer_set_sha256: currentStatus.reviewer_set_sha256,
    reviewer_count: currentStatus.active_reviewers.length,
    minimum_active_reviewers: genesis.minimum_active_reviewers,
    all_active_reviewers_required: true,
    signature_scheme: PINNED_EIP191_SIGNATURE_SCHEME,
    signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
  }, { label: "release reviewer genesis acceptance signing payload" });
}

function normalizeAcceptanceSigningPayload(value, reviewerGenesis, options) {
  const parsed = exact(
    value,
    ACCEPTANCE_PAYLOAD_FIELDS,
    "reviewer genesis acceptance signing payload",
  );
  const expected = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    reviewerGenesis,
    definedOptions({
      reviewerCurrentStatus: parsed.reviewer_authority_current_status,
      statusHistory: options.statusHistory ?? [],
      deploymentRoleAddresses: options.deploymentRoleAddresses,
      deploymentRoleControllerIds: options.deploymentRoleControllerIds,
      expectedStatusGuardianRootHash: options.expectedStatusGuardianRootHash,
      expectedStatusGuardianSetSha256: options.expectedStatusGuardianSetSha256,
    }),
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
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer genesis acceptance signing digest options",
  );
  const payload = normalizeAcceptanceSigningPayload(
    value,
    options.reviewerGenesis,
    options,
  );
  return eip191AuthorizationSigningDigest({
    domain: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SIGNING_DOMAIN,
    payload,
  });
}

export function releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
  value,
  options,
) {
  return eip191AuthorizationSigningMessage({
    prefix: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_MESSAGE_PREFIX,
    digest: releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
      value,
      options,
    ),
  });
}

function normalizeGenesisAcceptanceWithReplay(value, optionsValue) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer genesis acceptance normalization options",
  );
  const genesis = normalizeGenesis(options.reviewerGenesis, options);
  const parsed = exact(value, [
    ...ACCEPTANCE_PAYLOAD_FIELDS.filter((field) => field !== "schema"),
    "acceptances", "schema", "signing_payload_sha256",
  ], "release reviewer authority genesis acceptance");
  if (parsed.schema !== RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA) {
    fail("reviewer authority genesis acceptance v2 schema is required; v1 is not accepted");
  }
  const carriedPayload = {
    ...parsed,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA,
  };
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
  const acceptances = normalizeWireSignatures(
    parsed.acceptances,
    "reviewer genesis acceptances",
  );
  if (acceptances.length !== currentStatus.active_reviewers.length) {
    fail("reviewer genesis acceptance requires every guardian-selected active reviewer signature");
  }
  const reviewerAuthority = activeAuthorityFromStatus(currentStatus, options);
  const replay = replayReviewerSignatures({
    signatures: acceptances,
    message: eip191AuthorizationSigningMessage({
      prefix: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_MESSAGE_PREFIX,
      digest: signingPayloadSha256,
    }),
    reviewerAuthority,
    expectedReviewerRootHash: options.expectedReviewerRootHash
      ?? currentStatus.reviewer_root_hash,
    expectedReviewerSetSha256: options.expectedReviewerSetSha256
      ?? currentStatus.reviewer_set_sha256,
    expectedSignerCount: currentStatus.active_reviewers.length,
    requireEveryReviewer: true,
    label: "reviewer genesis acceptance",
  });
  const statusResult = normalizeCurrentStatusWithReplay(
    currentStatus,
    definedOptions({
      reviewerGenesis: genesis,
      statusHistory: options.statusHistory ?? [],
      deploymentRoleAddresses: options.deploymentRoleAddresses,
      deploymentRoleControllerIds: options.deploymentRoleControllerIds,
      expectedStatusGuardianRootHash: options.expectedStatusGuardianRootHash,
      expectedStatusGuardianSetSha256: options.expectedStatusGuardianSetSha256,
    }),
  );
  const artifact = deepFreezeCanonicalPlainDataGraph({
    ...signingPayload,
    reviewer_authority_current_status: statusResult.artifact,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256: signingPayloadSha256,
    acceptances: replay.wireSignatures,
  }, { label: "normalized release reviewer authority genesis acceptance" });
  return {
    artifact,
    guardianReplay: statusResult.replay,
    acceptanceReplay: replay.replay,
  };
}

export function normalizeReleaseReviewerAuthorityGenesisAcceptance(
  value,
  options,
) {
  return normalizeGenesisAcceptanceWithReplay(value, options).artifact;
}

export function canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
  value,
  options,
) {
  return canonicalText(
    normalizeReleaseReviewerAuthorityGenesisAcceptance(value, options),
  );
}

export function releaseReviewerAuthorityGenesisAcceptanceDigest(value, options) {
  return createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DOMAIN, "utf8")
    .update(
      canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
        value,
        options,
      ),
      "utf8",
    )
    .digest("hex");
}

export function releaseReviewerAuthorityGenesisAcceptanceSha256(value, options) {
  return `sha256:${releaseReviewerAuthorityGenesisAcceptanceDigest(value, options)}`;
}

export function assertReleaseReviewerAuthorityGenesisAcceptanceCurrentAtTime(
  value,
  optionsValue,
) {
  const options = canonicalOptions(
    optionsValue,
    "reviewer genesis acceptance currentness options",
  );
  const normalized = normalizeReleaseReviewerAuthorityGenesisAcceptance(
    value,
    options,
  );
  assertReleaseReviewerAuthorityCurrentStatusAtTime(
    normalized.reviewer_authority_current_status,
    definedOptions({
      now: options.now,
      expectedCurrentStatusEpoch: options.expectedCurrentStatusEpoch,
      expectedCurrentStatusSha256: options.expectedCurrentStatusSha256,
      reviewerGenesis: options.reviewerGenesis,
      statusHistory: options.statusHistory ?? [],
      deploymentRoleAddresses: options.deploymentRoleAddresses,
      deploymentRoleControllerIds: options.deploymentRoleControllerIds,
      expectedStatusGuardianRootHash: options.expectedStatusGuardianRootHash,
      expectedStatusGuardianSetSha256: options.expectedStatusGuardianSetSha256,
    }),
  );
  return normalized;
}

/**
 * Reconstruct the exact persisted epoch-one reviewer authority for a historical
 * activation instant. The input intentionally has no status-history field:
 * exact37 does not commit such a file, so later epochs and caller-supplied
 * uncommitted history fail closed. Both signature layers are independently
 * replayed as UTF-8 EIP-191 personal-sign messages. The original Cast metadata
 * remains part of the normalized wire artifacts but Cast is not re-executed.
 */
export function reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
  input = {},
) {
  const parsed = exact(
    input,
    HISTORICAL_RECONSTRUCTION_INPUT_FIELDS,
    "persisted release reviewer authority historical reconstruction input",
  );
  const expectedReleaseSha = releaseSha(
    parsed.expectedReleaseSha,
    "expected reviewer release SHA",
  );
  if (parsed.expectedChainId !== 84_532) {
    fail("expected reviewer chain ID must be Base Sepolia 84532");
  }
  const expectedGenesisSha256 = sha256(
    parsed.expectedReviewerGenesisSha256,
    "expected reviewer genesis digest",
  );
  const expectedAcceptanceSha256 = sha256(
    parsed.expectedReviewerGenesisAcceptanceSha256,
    "expected reviewer genesis acceptance digest",
  );
  const expectedStatusSha256 = sha256(
    parsed.expectedCurrentStatusSha256,
    "expected reviewer current-status digest",
  );
  const expectedStatusGuardianRootHash = bareSha256(
    parsed.expectedStatusGuardianRootHash,
    "expected reviewer status guardian root",
  );
  const expectedStatusGuardianSetSha256 = sha256(
    parsed.expectedStatusGuardianSetSha256,
    "expected reviewer status guardian set digest",
  );
  const expectedReviewerRootHash = bareSha256(
    parsed.expectedReviewerRootHash,
    "expected active reviewer root",
  );
  const expectedReviewerSetSha256 = sha256(
    parsed.expectedReviewerSetSha256,
    "expected active reviewer set digest",
  );
  const validationTime = canonicalInstant(
    parsed.validationTime,
    "historical reviewer validation time",
  );
  const embeddedStatus = parsed.reviewerGenesisAcceptance
    ?.reviewer_authority_current_status;
  const rawGenesisSha256 = `sha256:${createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_DOMAIN, "utf8")
    .update(canonicalText(parsed.reviewerGenesis), "utf8")
    .digest("hex")}`;
  const rawAcceptanceSha256 = `sha256:${createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DOMAIN, "utf8")
    .update(canonicalText(parsed.reviewerGenesisAcceptance), "utf8")
    .digest("hex")}`;
  const rawStatusSha256 = isRecord(embeddedStatus)
    ? `sha256:${createHash("sha256")
      .update(RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_DOMAIN, "utf8")
      .update(canonicalText(embeddedStatus), "utf8")
      .digest("hex")}`
    : null;
  if (rawAcceptanceSha256 !== expectedAcceptanceSha256
    || rawStatusSha256 !== expectedStatusSha256) {
    fail("persisted reviewer acceptance or current status differs from the independently anchored raw digest");
  }
  if (rawGenesisSha256 !== expectedGenesisSha256
    || parsed.reviewerGenesisAcceptance
      ?.reviewer_authority_genesis_sha256 !== expectedGenesisSha256) {
    fail("persisted reviewer genesis differs from the genesis digest inside the anchored acceptance");
  }
  if (!isRecord(embeddedStatus)
    || embeddedStatus.epoch !== 1
    || embeddedStatus.previous_status_sha256 !== ZERO_SHA256) {
    fail("historical reviewer reconstruction supports only the committed epoch-one status with zero predecessor");
  }
  const roleOptions = {
    deploymentRoleAddresses: parsed.deploymentRoleAddresses,
    deploymentRoleControllerIds: parsed.deploymentRoleControllerIds,
  };
  const genesis = assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(
    parsed.reviewerGenesis,
    roleOptions,
  );
  if (genesis.release_sha !== expectedReleaseSha
    || genesis.chain_id !== parsed.expectedChainId
    || genesis.status_guardian_root_hash !== expectedStatusGuardianRootHash
    || genesis.status_guardian_set_sha256
      !== expectedStatusGuardianSetSha256) {
    fail("reviewer genesis differs from the explicit release, chain, or guardian pins");
  }
  const genesisSha256 = releaseReviewerAuthorityGenesisSha256(genesis);
  if (genesisSha256 !== expectedGenesisSha256) {
    fail("reviewer genesis differs from its explicit digest pin");
  }
  const acceptanceResult = normalizeGenesisAcceptanceWithReplay(
    parsed.reviewerGenesisAcceptance,
    {
      reviewerGenesis: genesis,
      statusHistory: [],
      ...roleOptions,
      expectedStatusGuardianRootHash,
      expectedStatusGuardianSetSha256,
      expectedReviewerRootHash,
      expectedReviewerSetSha256,
    },
  );
  const acceptance = acceptanceResult.artifact;
  const status = acceptance.reviewer_authority_current_status;
  if (status.epoch !== 1 || status.previous_status_sha256 !== ZERO_SHA256) {
    fail("historical reviewer reconstruction cannot authenticate later-epoch or predecessor history");
  }
  if (status.reviewer_root_hash !== expectedReviewerRootHash
    || status.reviewer_set_sha256 !== expectedReviewerSetSha256
    || status.status_guardian_root_hash !== expectedStatusGuardianRootHash
    || status.status_guardian_set_sha256
      !== expectedStatusGuardianSetSha256) {
    fail("reviewer current status differs from the explicit reviewer or guardian pins");
  }
  const statusSha256 = statusArtifactSha256(status);
  if (statusSha256 !== expectedStatusSha256) {
    fail("reviewer current status differs from its explicit digest pin");
  }
  const acceptanceSha256 = `sha256:${createHash("sha256")
    .update(RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_DOMAIN, "utf8")
    .update(canonicalText(acceptance), "utf8")
    .digest("hex")}`;
  if (acceptanceSha256 !== expectedAcceptanceSha256) {
    fail("reviewer genesis acceptance differs from its explicit digest pin");
  }
  if (acceptance.release_sha !== expectedReleaseSha
    || acceptance.chain_id !== parsed.expectedChainId
    || acceptance.reviewer_authority_genesis_sha256 !== genesisSha256
    || acceptance.reviewer_authority_current_status_sha256 !== statusSha256) {
    fail("reviewer acceptance lineage differs from the explicit historical authority");
  }
  if (validationTime.milliseconds < Date.parse(status.not_before)) {
    fail("reviewer epoch-one status was not active at the explicit historical validation time");
  }
  if (validationTime.milliseconds >= Date.parse(status.expires_at)) {
    fail("reviewer epoch-one status was expired at the explicit historical validation time");
  }
  const reviewerAuthority = activeAuthorityFromStatus(status, {
    expectedReviewerRootHash,
    expectedReviewerSetSha256,
  });
  return deepFreezeCanonicalPlainDataGraph({
    schema: RELEASE_REVIEWER_AUTHORITY_HISTORICAL_RECONSTRUCTION_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_HISTORICAL_RECONSTRUCTION_TRUTH,
    exact37_current_reviewer_authority_assertion_truth:
      EXACT37_CURRENT_REVIEWER_AUTHORITY_ASSERTION_TRUTH,
    release_sha: expectedReleaseSha,
    chain_id: parsed.expectedChainId,
    validation_time: validationTime.value,
    reviewer_authority_genesis: genesis,
    reviewer_authority_genesis_sha256: genesisSha256,
    reviewer_authority_current_status: status,
    reviewer_authority_current_status_sha256: statusSha256,
    reviewer_authority_genesis_acceptance: acceptance,
    reviewer_authority_genesis_acceptance_sha256: acceptanceSha256,
    reviewer_authority: reviewerAuthority,
    reviewer_status_epoch: 1,
    authenticated_status_history_entries: 0,
    uncommitted_status_history_accepted: false,
    later_epoch_supported: false,
    signature_replay: {
      message_mode: "utf8_eip191_personal_sign",
      original_signature_verifier: { ...PINNED_CAST_SIGNATURE_VERIFIER },
      replay_signature_verifier: { ...INDEPENDENT_EIP191_REPLAY_VERIFIER },
      guardian_signers: acceptanceResult.guardianReplay,
      active_reviewer_signers: acceptanceResult.acceptanceReplay,
      original_signature_verifier_reexecuted: false,
      independent_signature_replay_performed: true,
    },
    signature_verification_performed: true,
    current_clock_consulted: false,
    freshness_renewed: false,
    production_brand_minted: false,
    live_traffic_authorized: false,
  }, { label: "persisted release reviewer authority historical reconstruction" });
}
