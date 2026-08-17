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
  releaseReviewerAuthorityGenesisSha256,
  reviewerControllerSetSha256,
} from "./release-reviewer-authority-genesis.mjs";
import {
  RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
  RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
  assertReleaseReviewerAuthorityCurrentStatusAtTime,
  createReleaseReviewerAuthorityCurrentStatusSigningPayload,
  createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload,
  normalizeReleaseReviewerAuthorityCurrentStatus,
  normalizeReleaseReviewerAuthorityGenesisAcceptance,
  releaseReviewerAuthorityCurrentStatusSha256,
  releaseReviewerAuthorityCurrentStatusSigningMessage,
  releaseReviewerAuthorityCurrentStatusSigningPayloadSha256,
  releaseReviewerAuthorityGenesisAcceptanceSha256,
  releaseReviewerAuthorityGenesisAcceptanceSigningMessage,
  releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256,
} from "./release-reviewer-authority-genesis-acceptance.mjs";

const RELEASE_SHA = "ab".repeat(20);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const account = (byte) => privateKeyToAccount(`0x${byte.repeat(32)}`);
const REVIEWER_ACCOUNTS = ["11", "12", "21", "22", "31", "32"].map(account);
const GUARDIAN_ACCOUNTS = ["41", "42"].map(account);
const FORGED = account("55");

function addressOf(value) {
  return value.address.toLowerCase();
}

const ACCOUNT_BY_ADDRESS = new Map(
  [...REVIEWER_ACCOUNTS, ...GUARDIAN_ACCOUNTS, FORGED]
    .map((value) => [addressOf(value), value]),
);

function genesis() {
  const reviewerControllers = [
    { controller_id: "reviewer-alpha", accounts: REVIEWER_ACCOUNTS.slice(0, 2) },
    { controller_id: "reviewer-bravo", accounts: REVIEWER_ACCOUNTS.slice(2, 4) },
    { controller_id: "reviewer-charlie", accounts: REVIEWER_ACCOUNTS.slice(4, 6) },
  ].map((entry) => ({
    controller_id: entry.controller_id,
    preauthorized_addresses: entry.accounts.map(addressOf).sort(),
  }));
  const guardians = GUARDIAN_ACCOUNTS.map((value, index) => ({
    address: addressOf(value),
    controller_id: `status-guardian-${index + 1}`,
  })).sort((left, right) => left.address.localeCompare(right.address));
  const guardianHashes = guardians
    .map((entry) => executionPolicyReviewerHash(entry.address))
    .sort();
  return {
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    minimum_active_reviewers: RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: reviewerControllers,
    reviewer_controller_set_sha256: reviewerControllerSetSha256(reviewerControllers),
    status_guardians: guardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash: executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(guardians),
  };
}

function selections(core, keyIndex = 0, controllerIds = null) {
  return core.reviewer_controllers
    .filter((entry) => controllerIds === null || controllerIds.includes(entry.controller_id))
    .map((entry) => ({
      address: entry.preauthorized_addresses[keyIndex],
      controller_id: entry.controller_id,
    }))
    .sort((left, right) => left.address.localeCompare(right.address));
}

async function currentStatus(core, {
  epoch = 1,
  statusHistory = [],
  activeReviewers = selections(core),
  revokedControllerIds = [],
  revokedReviewerAddresses = [],
  notBefore = epoch === 1
    ? "2026-07-21T12:00:00Z"
    : new Date(Date.parse("2026-07-21T12:00:00Z") + ((epoch - 1) * 15 * 60_000))
      .toISOString().replace(".000Z", "Z"),
  expiresAt = new Date(Date.parse("2026-07-21T12:00:00Z") + (epoch * 15 * 60_000))
    .toISOString().replace(".000Z", "Z"),
  previousStatusSha256 = statusHistory.length === 0
    ? ZERO_SHA256
    : releaseReviewerAuthorityCurrentStatusSha256(
      statusHistory.at(-1),
      { reviewerGenesis: core, statusHistory: statusHistory.slice(0, -1) },
    ),
  guardianSignerByAddress = null,
} = {}) {
  const options = { reviewerGenesis: core, statusHistory };
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch,
    not_before: notBefore,
    expires_at: expiresAt,
    previous_status_sha256: previousStatusSha256,
    active_reviewers: activeReviewers,
    revoked_controller_ids: revokedControllerIds,
    revoked_reviewer_addresses: revokedReviewerAddresses,
  }, options);
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(payload, options);
  const signerByAddress = guardianSignerByAddress
    ?? new Map(GUARDIAN_ACCOUNTS.map((value) => [addressOf(value), value]));
  const guardianSignatures = [];
  for (const guardian of core.status_guardians) {
    guardianSignatures.push({
      ...guardian,
      signature: (await signerByAddress.get(guardian.address)
        .signMessage({ message })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(payload, options),
    guardian_signatures: guardianSignatures,
  };
}

async function acceptance(core, status, {
  statusHistory = [],
  signerByAddress = ACCOUNT_BY_ADDRESS,
} = {}) {
  const options = {
    reviewerGenesis: core,
    reviewerCurrentStatus: status,
    statusHistory,
  };
  const payload = createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    core,
    { reviewerCurrentStatus: status, statusHistory },
  );
  const signingOptions = { reviewerGenesis: core, statusHistory };
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    signingOptions,
  );
  const acceptances = [];
  for (const reviewer of status.active_reviewers) {
    acceptances.push({
      ...reviewer,
      signature: (await signerByAddress.get(reviewer.address)
        .signMessage({ message })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        signingOptions,
      ),
    acceptances,
  };
}

test("two guardians select the active set and every selected reviewer accepts the full status", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);
  const normalizedStatus = normalizeReleaseReviewerAuthorityCurrentStatus(
    status,
    { reviewerGenesis: core },
  );
  const normalizedAcceptance = normalizeReleaseReviewerAuthorityGenesisAcceptance(
    artifact,
    { reviewerGenesis: core },
  );
  assert.equal(normalizedStatus.guardian_signatures.length, 2);
  assert.equal(normalizedAcceptance.acceptances.length, 3);
  assert.deepEqual(
    normalizedAcceptance.reviewer_authority_current_status,
    normalizedStatus,
  );
  assert.equal(
    normalizedAcceptance.reviewer_authority_genesis_sha256,
    releaseReviewerAuthorityGenesisSha256(core),
  );
  assert.equal(
    releaseReviewerAuthorityGenesisSha256(core),
    "sha256:be1419fb08b3729026c2fae469f377b25d7c95dbe8f1943d54d11c3ec6ea28e3",
  );
  assert.equal(
    releaseReviewerAuthorityCurrentStatusSha256(
      status,
      { reviewerGenesis: core },
    ),
    "sha256:c85347687da8c92a4680ae9fd7f1514bb617fab8cb3f20f5c306f792348a343f",
  );
  assert.equal(
    releaseReviewerAuthorityGenesisAcceptanceSha256(
      artifact,
      { reviewerGenesis: core },
    ),
    "sha256:daf09e913885f29ec29019ef15cb2dc9e9e035a2afd315b400fb2eb90c50f136",
  );
});

test("a compromised reviewer cannot assert itself active or mutate the guardian-selected status", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);

  const unapproved = selections(core);
  unapproved[0] = {
    address: addressOf(FORGED),
    controller_id: unapproved[0].controller_id,
  };
  unapproved.sort((left, right) => left.address.localeCompare(right.address));
  assert.throws(
    () => createReleaseReviewerAuthorityCurrentStatusSigningPayload({
      epoch: 1,
      not_before: "2026-07-21T12:00:00Z",
      expires_at: "2026-07-21T12:15:00Z",
      previous_status_sha256: ZERO_SHA256,
      active_reviewers: unapproved,
      revoked_controller_ids: [],
      revoked_reviewer_addresses: [],
    }, { reviewerGenesis: core }),
    /cannot add or select a key outside/,
  );

  const selfAssertedRotation = structuredClone(artifact);
  const alpha = core.reviewer_controllers[0];
  const activeIndex = selfAssertedRotation.reviewer_authority_current_status
    .active_reviewers.findIndex((entry) => entry.controller_id === alpha.controller_id);
  selfAssertedRotation.reviewer_authority_current_status
    .active_reviewers[activeIndex].address = alpha.preauthorized_addresses[1];
  selfAssertedRotation.reviewer_authority_current_status.active_reviewers
    .sort((left, right) => left.address.localeCompare(right.address));
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesisAcceptance(
      selfAssertedRotation,
      { reviewerGenesis: core },
    ),
    /does not match its exact signing payload|does not match the exact genesis/,
  );
});

test("one guardian, a forged guardian, or reviewer-key guardian impersonation is insufficient", async () => {
  const core = genesis();
  const status = await currentStatus(core);

  const missing = structuredClone(status);
  missing.guardian_signatures.pop();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityCurrentStatus(
      missing,
      { reviewerGenesis: core },
    ),
    /requires both guardian signatures/,
  );

  const forged = structuredClone(status);
  const payload = createReleaseReviewerAuthorityCurrentStatusSigningPayload(
    {
      epoch: status.epoch,
      not_before: status.not_before,
      expires_at: status.expires_at,
      previous_status_sha256: status.previous_status_sha256,
      active_reviewers: status.active_reviewers,
      revoked_controller_ids: status.revoked_controller_ids,
      revoked_reviewer_addresses: status.revoked_reviewer_addresses,
    },
    { reviewerGenesis: core },
  );
  const message = releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    { reviewerGenesis: core },
  );
  forged.guardian_signatures[0].signature =
    (await FORGED.signMessage({ message })).toLowerCase();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityCurrentStatus(
      forged,
      { reviewerGenesis: core },
    ),
    /signature verification failed/,
  );
});

test("current-time validation rejects not-yet-active and expired status", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const head = releaseReviewerAuthorityCurrentStatusSha256(
    status,
    { reviewerGenesis: core },
  );
  const headOptions = {
    expectedCurrentStatusEpoch: 1,
    expectedCurrentStatusSha256: head,
  };
  assert.throws(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      status,
      { reviewerGenesis: core, now: "2026-07-21T12:00:00Z" },
    ),
    /head digest|stale or forked/,
  );
  assert.throws(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      status,
      {
        reviewerGenesis: core,
        now: "2026-07-21T11:59:59Z",
        ...headOptions,
      },
    ),
    /not active yet/,
  );
  assert.doesNotThrow(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      status,
      {
        reviewerGenesis: core,
        now: "2026-07-21T12:00:00Z",
        ...headOptions,
      },
    ),
  );
  assert.throws(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      status,
      {
        reviewerGenesis: core,
        now: "2026-07-21T12:15:00Z",
        ...headOptions,
      },
    ),
    /expired/,
  );
  assert.throws(
    () => createReleaseReviewerAuthorityCurrentStatusSigningPayload({
      epoch: 1,
      not_before: "2026-07-21T12:00:00Z",
      expires_at: "2026-07-21T12:15:01Z",
      previous_status_sha256: ZERO_SHA256,
      active_reviewers: selections(core),
      revoked_controller_ids: [],
      revoked_reviewer_addresses: [],
    }, { reviewerGenesis: core }),
    /no longer than 15 minutes/,
  );
});

test("complete history rejects epoch rollback, predecessor fork, and controller reactivation", async () => {
  const core = genesis();
  const first = await currentStatus(core);
  await assert.rejects(
    () => currentStatus(core, {
      epoch: 2,
      statusHistory: [first],
      notBefore: "2026-07-21T12:14:59Z",
      expiresAt: "2026-07-21T12:29:59Z",
    }),
    /windows must not overlap/,
  );
  const activeWithoutCharlie = selections(
    core,
    1,
    ["reviewer-alpha", "reviewer-bravo"],
  );
  const second = await currentStatus(core, {
    epoch: 2,
    statusHistory: [first],
    activeReviewers: activeWithoutCharlie,
    revokedControllerIds: ["reviewer-charlie"],
  });
  assert.doesNotThrow(() => normalizeReleaseReviewerAuthorityCurrentStatus(
    second,
    { reviewerGenesis: core, statusHistory: [first] },
  ));
  const secondHead = releaseReviewerAuthorityCurrentStatusSha256(
    second,
    { reviewerGenesis: core, statusHistory: [first] },
  );
  assert.throws(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      first,
      {
        reviewerGenesis: core,
        now: "2026-07-21T12:15:00Z",
        expectedCurrentStatusEpoch: 2,
        expectedCurrentStatusSha256: secondHead,
      },
    ),
    /stale or forked/,
  );
  assert.throws(
    () => normalizeReleaseReviewerAuthorityCurrentStatus(
      second,
      { reviewerGenesis: core },
    ),
    /epoch must be strictly monotonic/,
  );

  await assert.rejects(
    () => currentStatus(core, {
      epoch: 2,
      statusHistory: [first],
      previousStatusSha256: `sha256:${"7".repeat(64)}`,
    }),
    /rollback or fork/,
  );

  await assert.rejects(
    () => currentStatus(core, {
      epoch: 3,
      statusHistory: [first, second],
      activeReviewers: selections(core, 0),
      revokedControllerIds: ["reviewer-charlie"],
      notBefore: "2026-07-21T12:30:00Z",
      expiresAt: "2026-07-21T12:45:00Z",
    }),
    /never add or reactivate controllers|cannot activate a revoked/,
  );

  await assert.rejects(
    () => currentStatus(core, {
      epoch: 3,
      statusHistory: [first, second],
      activeReviewers: activeWithoutCharlie,
      revokedControllerIds: [],
      notBefore: "2026-07-21T12:30:00Z",
      expiresAt: "2026-07-21T12:45:00Z",
    }),
    /revocations are monotonic/,
  );

  const sibling = await currentStatus(core, {
    epoch: 2,
    statusHistory: [first],
    activeReviewers: selections(core, 0, ["reviewer-alpha", "reviewer-bravo"]),
  });
  await assert.rejects(
    () => currentStatus(core, {
      epoch: 3,
      statusHistory: [first, sibling],
      activeReviewers: selections(core, 0),
      notBefore: "2026-07-21T12:30:00Z",
      expiresAt: "2026-07-21T12:45:00Z",
    }),
    /never add or reactivate controllers/,
  );
  assert.throws(
    () => normalizeReleaseReviewerAuthorityCurrentStatus(
      sibling,
      { reviewerGenesis: core, statusHistory: [first, second] },
    ),
    /epoch must be strictly monotonic/,
  );
  assert.throws(
    () => assertReleaseReviewerAuthorityCurrentStatusAtTime(
      sibling,
      {
        reviewerGenesis: core,
        statusHistory: [first],
        now: "2026-07-21T12:15:00Z",
        expectedCurrentStatusEpoch: 2,
        expectedCurrentStatusSha256: secondHead,
      },
    ),
    /stale or forked/,
  );
});

test("altered keys, empty/below-threshold sets, and revoked selections fail closed", async () => {
  const core = genesis();
  const proposal = (activeReviewers, overrides = {}) => ({
    epoch: 1,
    not_before: "2026-07-21T12:00:00Z",
    expires_at: "2026-07-21T12:15:00Z",
    previous_status_sha256: ZERO_SHA256,
    active_reviewers: activeReviewers,
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
    ...overrides,
  });
  assert.throws(
    () => createReleaseReviewerAuthorityCurrentStatusSigningPayload(
      proposal([]),
      { reviewerGenesis: core },
    ),
    /below the genesis minimum threshold/,
  );
  assert.throws(
    () => createReleaseReviewerAuthorityCurrentStatusSigningPayload(
      proposal(selections(core).slice(0, 1)),
      { reviewerGenesis: core },
    ),
    /below the genesis minimum threshold/,
  );
  const active = selections(core);
  assert.throws(
    () => createReleaseReviewerAuthorityCurrentStatusSigningPayload(
      proposal(active, { revoked_reviewer_addresses: [active[0].address] }),
      { reviewerGenesis: core },
    ),
    /cannot activate a revoked/,
  );
});

test("acceptance requires every selected reviewer and rejects v1 artifacts", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);

  const missing = structuredClone(artifact);
  missing.acceptances.pop();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesisAcceptance(
      missing,
      { reviewerGenesis: core },
    ),
    /every guardian-selected active reviewer/,
  );

  const forged = structuredClone(artifact);
  const message = releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
      core,
      { reviewerCurrentStatus: status },
    ),
    { reviewerGenesis: core },
  );
  forged.acceptances[0].signature =
    (await FORGED.signMessage({ message })).toLowerCase();
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesisAcceptance(
      forged,
      { reviewerGenesis: core },
    ),
    /signature verification failed/,
  );

  const legacy = structuredClone(artifact);
  legacy.schema = "dnai.release-reviewer-authority-genesis-acceptance.v1";
  assert.throws(
    () => normalizeReleaseReviewerAuthorityGenesisAcceptance(
      legacy,
      { reviewerGenesis: core },
    ),
    /v2 schema is required; v1 is not accepted/,
  );
});
