import assert from "node:assert/strict";
import test from "node:test";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
} from "./release-authority-signature-verifier.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
  RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
  assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation,
  normalizeReleaseReviewerAuthorityGenesis,
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";

const RELEASE_SHA = "ab".repeat(20);
const account = (byte) => privateKeyToAccount(`0x${byte.repeat(32)}`);
const REVIEWER_ACCOUNTS = ["11", "12", "21", "22", "31", "32"].map(account);
const GUARDIAN_ACCOUNTS = ["41", "42"].map(account);
const DEPLOYMENT_ACCOUNT = account("51");

function addressOf(value) {
  return value.address.toLowerCase();
}

function genesis({
  guardians = GUARDIAN_ACCOUNTS.map((value, index) => ({
    address: addressOf(value),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address)),
  controllers = [
    { controller_id: "reviewer-alpha", accounts: REVIEWER_ACCOUNTS.slice(0, 2) },
    { controller_id: "reviewer-bravo", accounts: REVIEWER_ACCOUNTS.slice(2, 4) },
    { controller_id: "reviewer-charlie", accounts: REVIEWER_ACCOUNTS.slice(4, 6) },
  ].map((entry) => ({
    controller_id: entry.controller_id,
    preauthorized_addresses: entry.accounts.map(addressOf).sort(),
  })),
} = {}) {
  const guardianHashes = guardians
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: controllers,
    reviewer_controller_set_sha256: reviewerControllerSetSha256(controllers),
    status_guardians: guardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(guardians),
  };
}

test("v2 genesis commits finite per-controller key inventories and exactly two guardians", () => {
  const artifact = genesis();
  const normalized = normalizeReleaseReviewerAuthorityGenesis(artifact, {
    deploymentRoleAddresses: [addressOf(DEPLOYMENT_ACCOUNT)],
    deploymentRoleControllerIds: ["deployment-operator"],
  });
  assert.equal(normalized.reviewer_controllers.length, 3);
  assert.equal(normalized.status_guardians.length, 2);
  assert.equal(normalized.minimum_active_reviewers, 2);
  assert.match(releaseReviewerAuthorityGenesisSha256(artifact), /^sha256:[0-9a-f]{64}$/);
});

test("v1 and uncommitted inventory mutations have no fallback", () => {
  const artifact = genesis();
  const legacy = structuredClone(artifact);
  legacy.schema = "dnai.release-reviewer-authority-genesis.v1";
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(legacy),
    /v2 schema is required; v1 is not accepted/,
  );

  const zeroRelease = structuredClone(artifact);
  zeroRelease.release_sha = "0".repeat(40);
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(zeroRelease),
    /header is invalid/,
  );

  const alteredKey = structuredClone(artifact);
  alteredKey.reviewer_controllers[0].preauthorized_addresses[0] =
    addressOf(DEPLOYMENT_ACCOUNT);
  alteredKey.reviewer_controllers[0].preauthorized_addresses.sort();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(alteredKey),
    /inventory does not match/,
  );

  const duplicateKey = structuredClone(artifact);
  duplicateKey.reviewer_controllers[1].preauthorized_addresses[0] =
    duplicateKey.reviewer_controllers[0].preauthorized_addresses[0];
  duplicateKey.reviewer_controllers[1].preauthorized_addresses.sort();
  assert.throws(
    () => reviewerControllerSetSha256(duplicateKey.reviewer_controllers),
    /exactly one reviewer controller/,
  );
});

test("guardian identities are two-of-two and separated from reviewers and supplied deployment roles", () => {
  const artifact = genesis();
  const oneGuardian = structuredClone(artifact);
  oneGuardian.status_guardians.pop();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(oneGuardian),
    /exactly 2 guardians/,
  );

  const reviewerOverlap = structuredClone(artifact);
  reviewerOverlap.status_guardians[0].address =
    reviewerOverlap.reviewer_controllers[0].preauthorized_addresses[0];
  reviewerOverlap.status_guardians.sort((left, right) => left.address.localeCompare(right.address));
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(reviewerOverlap),
    /distinct from every reviewer key/,
  );

  assert.throws(
    () => assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(artifact),
    /requires explicit authoritative/,
  );
  assert.doesNotThrow(
    () => assertReleaseReviewerAuthorityGenesisDeploymentRoleSeparation(artifact, {
      deploymentRoleAddresses: [addressOf(DEPLOYMENT_ACCOUNT)],
      deploymentRoleControllerIds: ["deployment-operator"],
    }),
  );
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(artifact, {
      deploymentRoleAddresses: [artifact.status_guardians[0].address],
      deploymentRoleControllerIds: ["deployment-operator"],
    }),
    /distinct from supplied deployment-role/,
  );
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(artifact, {
      deploymentRoleAddresses: [addressOf(DEPLOYMENT_ACCOUNT)],
      deploymentRoleControllerIds: [artifact.status_guardians[1].controller_id],
    }),
    /distinct from supplied deployment-role/,
  );
});

test("reviewer identities are separated from supplied deployment roles", () => {
  const addressOverlap = genesis();
  addressOverlap.reviewer_controllers[0].preauthorized_addresses[0] =
    addressOf(DEPLOYMENT_ACCOUNT);
  addressOverlap.reviewer_controllers[0].preauthorized_addresses.sort();
  addressOverlap.reviewer_controller_set_sha256 = reviewerControllerSetSha256(
    addressOverlap.reviewer_controllers,
  );
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(addressOverlap, {
      deploymentRoleAddresses: [addressOf(DEPLOYMENT_ACCOUNT)],
      deploymentRoleControllerIds: ["deployment-operator"],
    }),
    /reviewer keys and controllers must be distinct from supplied deployment-role identities/,
  );

  const controllerOverlap = genesis();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesis(controllerOverlap, {
      deploymentRoleAddresses: [addressOf(DEPLOYMENT_ACCOUNT)],
      deploymentRoleControllerIds: [
        controllerOverlap.reviewer_controllers[0].controller_id,
      ],
    }),
    /reviewer keys and controllers must be distinct from supplied deployment-role identities/,
  );
});
