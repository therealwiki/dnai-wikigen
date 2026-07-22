import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { privateKeyToAccount } from "../web/node_modules/viem/_esm/accounts/index.js";

import * as pure from "./release-reviewer-authority-core.mjs";
import * as genesisFacade from "./release-reviewer-authority-genesis.mjs";
import * as acceptanceFacade from "./release-reviewer-authority-genesis-acceptance.mjs";
import {
  executionPolicyReviewerHash,
  executionPolicyReviewerRootHash,
  reviewerSetSha256,
  verifyIndependentEip191PersonalSignature,
  verifyIndependentEip191RawDigestSignature,
} from "./release-authority-signature-verifier-core.mjs";

const RELEASE_SHA = "ab".repeat(20);
const ZERO_SHA256 = `sha256:${"0".repeat(64)}`;
const account = (byte) => privateKeyToAccount(`0x${byte.repeat(32)}`);
const REVIEWER_ACCOUNTS = ["11", "12", "21", "22", "31", "32"].map(account);
const GUARDIAN_ACCOUNTS = ["41", "42"].map(account);
const DEPLOYMENT_ACCOUNT = account("51");
const FORGED_ACCOUNT = account("55");

const DEPLOYMENT_ROLE_ADDRESSES = Object.freeze([
  DEPLOYMENT_ACCOUNT.address.toLowerCase(),
]);
const DEPLOYMENT_ROLE_CONTROLLER_IDS = Object.freeze([
  "deployment-operator",
]);

function addressOf(value) {
  return value.address.toLowerCase();
}

const ACCOUNT_BY_ADDRESS = new Map(
  [...REVIEWER_ACCOUNTS, ...GUARDIAN_ACCOUNTS, FORGED_ACCOUNT]
    .map((value) => [addressOf(value), value]),
);

function roleOptions() {
  return {
    deploymentRoleAddresses: [...DEPLOYMENT_ROLE_ADDRESSES],
    deploymentRoleControllerIds: [...DEPLOYMENT_ROLE_CONTROLLER_IDS],
  };
}

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
    schema: pure.RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA,
    truth_status: pure.RELEASE_REVIEWER_AUTHORITY_GENESIS_TRUTH_STATUS,
    release_sha: RELEASE_SHA,
    chain_id: 84_532,
    minimum_active_reviewers: pure.RELEASE_REVIEWER_MINIMUM_ACTIVE_REVIEWERS,
    reviewer_controllers: reviewerControllers,
    reviewer_controller_set_sha256:
      pure.reviewerControllerSetSha256(reviewerControllers),
    status_guardians: guardians,
    status_guardian_hashes: guardianHashes,
    status_guardian_root_hash:
      executionPolicyReviewerRootHash(guardianHashes),
    status_guardian_set_sha256: reviewerSetSha256(guardians),
  };
}

function activeReviewers(core) {
  return core.reviewer_controllers.map((entry) => ({
    address: entry.preauthorized_addresses[0],
    controller_id: entry.controller_id,
  })).sort((left, right) => left.address.localeCompare(right.address));
}

async function currentStatus(core, { messageMode = "utf8" } = {}) {
  const options = { reviewerGenesis: core, ...roleOptions() };
  const payload = pure.createReleaseReviewerAuthorityCurrentStatusSigningPayload({
    epoch: 1,
    not_before: "2026-07-21T12:00:00Z",
    expires_at: "2026-07-21T12:15:00Z",
    previous_status_sha256: ZERO_SHA256,
    active_reviewers: activeReviewers(core),
    revoked_controller_ids: [],
    revoked_reviewer_addresses: [],
  }, options);
  const message = pure.releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    options,
  );
  const digest = pure.releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
    payload,
    options,
  );
  const guardianSignatures = [];
  for (const guardian of core.status_guardians) {
    const signer = ACCOUNT_BY_ADDRESS.get(guardian.address);
    guardianSignatures.push({
      ...guardian,
      signature: (await signer.signMessage({
        message: messageMode === "utf8"
          ? message
          : { raw: `0x${digest.slice(7)}` },
      })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: pure.RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_SCHEMA,
    signing_payload_sha256: digest,
    guardian_signatures: guardianSignatures,
  };
}

async function acceptance(core, status) {
  const payload = pure.createReleaseReviewerAuthorityGenesisAcceptanceSigningPayload(
    core,
    { reviewerCurrentStatus: status, ...roleOptions() },
  );
  const options = { reviewerGenesis: core, ...roleOptions() };
  const message = pure.releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
    payload,
    options,
  );
  const acceptances = [];
  for (const reviewer of status.active_reviewers) {
    acceptances.push({
      ...reviewer,
      signature: (await ACCOUNT_BY_ADDRESS.get(reviewer.address)
        .signMessage({ message })).toLowerCase(),
    });
  }
  return {
    ...payload,
    schema: pure.RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SCHEMA,
    signing_payload_sha256:
      pure.releaseReviewerAuthorityGenesisAcceptanceSigningPayloadSha256(
        payload,
        options,
      ),
    acceptances,
  };
}

function highLevelInput(core, artifact) {
  const options = { reviewerGenesis: core, ...roleOptions() };
  const status = artifact.reviewer_authority_current_status;
  return {
    reviewerGenesis: core,
    reviewerGenesisAcceptance: artifact,
    ...roleOptions(),
    validationTime: "2026-07-21T12:05:00Z",
    expectedChainId: 84_532,
    expectedReleaseSha: RELEASE_SHA,
    expectedReviewerGenesisSha256:
      pure.releaseReviewerAuthorityGenesisSha256(core, roleOptions()),
    expectedReviewerGenesisAcceptanceSha256:
      pure.releaseReviewerAuthorityGenesisAcceptanceSha256(artifact, options),
    expectedCurrentStatusSha256:
      pure.releaseReviewerAuthorityCurrentStatusSha256(status, options),
    expectedStatusGuardianRootHash: core.status_guardian_root_hash,
    expectedStatusGuardianSetSha256: core.status_guardian_set_sha256,
    expectedReviewerRootHash: status.reviewer_root_hash,
    expectedReviewerSetSha256: status.reviewer_set_sha256,
  };
}

test("pure core preserves the existing genesis/status/acceptance bytes and known digests", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);
  const options = { reviewerGenesis: core, ...roleOptions() };

  assert.deepEqual(
    pure.normalizeReleaseReviewerAuthorityGenesis(core, roleOptions()),
    genesisFacade.normalizeReleaseReviewerAuthorityGenesis(core, roleOptions()),
  );
  assert.deepEqual(
    pure.normalizeReleaseReviewerAuthorityCurrentStatus(status, options),
    acceptanceFacade.normalizeReleaseReviewerAuthorityCurrentStatus(status, options),
  );
  assert.deepEqual(
    pure.normalizeReleaseReviewerAuthorityGenesisAcceptance(artifact, options),
    acceptanceFacade.normalizeReleaseReviewerAuthorityGenesisAcceptance(
      artifact,
      options,
    ),
  );
  assert.equal(
    pure.canonicalReleaseReviewerAuthorityGenesisArtifactText(core, roleOptions()),
    genesisFacade.canonicalReleaseReviewerAuthorityGenesisArtifactText(
      core,
      roleOptions(),
    ),
  );
  assert.equal(
    pure.canonicalReleaseReviewerAuthorityCurrentStatusArtifactText(
      status,
      options,
    ),
    acceptanceFacade.canonicalReleaseReviewerAuthorityCurrentStatusArtifactText(
      status,
      options,
    ),
  );
  assert.equal(
    pure.canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      artifact,
      options,
    ),
    acceptanceFacade.canonicalReleaseReviewerAuthorityGenesisAcceptanceArtifactText(
      artifact,
      options,
    ),
  );
  assert.equal(
    pure.releaseReviewerAuthorityGenesisSha256(core, roleOptions()),
    "sha256:be1419fb08b3729026c2fae469f377b25d7c95dbe8f1943d54d11c3ec6ea28e3",
  );
  assert.equal(
    pure.releaseReviewerAuthorityCurrentStatusSha256(status, options),
    "sha256:c85347687da8c92a4680ae9fd7f1514bb617fab8cb3f20f5c306f792348a343f",
  );
  assert.equal(
    pure.releaseReviewerAuthorityGenesisAcceptanceSha256(artifact, options),
    "sha256:daf09e913885f29ec29019ef15cb2dc9e9e035a2afd315b400fb2eb90c50f136",
  );
});

test("historical reconstruction requires every external pin and returns replay evidence separately from wire signatures", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);
  const input = highLevelInput(core, artifact);
  const result =
    pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(input);

  assert.equal(result.reviewer_status_epoch, 1);
  assert.equal(result.authenticated_status_history_entries, 0);
  assert.equal(result.uncommitted_status_history_accepted, false);
  assert.equal(result.later_epoch_supported, false);
  assert.equal(result.validation_time, input.validationTime);
  assert.equal(result.current_clock_consulted, false);
  assert.equal(result.freshness_renewed, false);
  assert.equal(result.production_brand_minted, false);
  assert.equal(result.live_traffic_authorized, false);
  assert.equal(result.signature_replay.message_mode, "utf8_eip191_personal_sign");
  assert.equal(
    result.signature_replay.original_signature_verifier_reexecuted,
    false,
  );
  assert.equal(
    result.signature_replay.independent_signature_replay_performed,
    true,
  );
  assert.equal(result.signature_replay.guardian_signers.length, 2);
  assert.equal(result.signature_replay.active_reviewer_signers.length, 3);
  assert.deepEqual(
    Object.keys(
      result.reviewer_authority_current_status.guardian_signatures[0],
    ).sort(),
    ["address", "controller_id", "signature"],
  );
  assert.deepEqual(
    Object.keys(
      result.reviewer_authority_genesis_acceptance.acceptances[0],
    ).sort(),
    ["address", "controller_id", "signature"],
  );
  assert.deepEqual(
    Object.keys(result.signature_replay.guardian_signers[0]).sort(),
    ["address", "controller_id", "signature_sha256"],
  );
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.reviewer_authority));

  for (const requiredPin of [
    "expectedReviewerGenesisSha256",
    "expectedReviewerGenesisAcceptanceSha256",
    "expectedCurrentStatusSha256",
    "expectedStatusGuardianRootHash",
    "expectedStatusGuardianSetSha256",
    "expectedReviewerRootHash",
    "expectedReviewerSetSha256",
  ]) {
    const omitted = structuredClone(input);
    delete omitted[requiredPin];
    assert.throws(
      () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
        omitted,
      ),
      /exact schema/,
    );
  }
});

test("reviewer signatures are replayed in UTF-8 EIP-191 mode, never raw-bytes32 mode", async () => {
  const core = genesis();
  const options = { reviewerGenesis: core, ...roleOptions() };
  const valid = await currentStatus(core);
  const payload = {
    ...valid,
    schema: pure.RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
  };
  delete payload.guardian_signatures;
  delete payload.signing_payload_sha256;
  const message = pure.releaseReviewerAuthorityCurrentStatusSigningMessage(
    payload,
    options,
  );
  const digest = pure.releaseReviewerAuthorityCurrentStatusSigningPayloadSha256(
    payload,
    options,
  );
  const firstGuardian = core.status_guardians[0];
  const signer = ACCOUNT_BY_ADDRESS.get(firstGuardian.address);
  const utf8Signature = (await signer.signMessage({ message })).toLowerCase();
  const rawSignature = (await signer.signMessage({
    message: { raw: `0x${digest.slice(7)}` },
  })).toLowerCase();

  assert.doesNotThrow(() => verifyIndependentEip191PersonalSignature({
    address: firstGuardian.address,
    message,
    signature: utf8Signature,
  }));
  assert.doesNotThrow(() => verifyIndependentEip191RawDigestSignature({
    address: firstGuardian.address,
    digest: `0x${digest.slice(7)}`,
    signature: rawSignature,
  }));
  assert.throws(() => verifyIndependentEip191PersonalSignature({
    address: firstGuardian.address,
    message,
    signature: rawSignature,
  }), /verification failed/);

  const wrongMode = await currentStatus(core, { messageMode: "raw" });
  assert.throws(
    () => pure.normalizeReleaseReviewerAuthorityCurrentStatus(
      wrongMode,
      options,
    ),
    /verification failed/,
  );
});

test("forged guardian and active-reviewer signatures fail independent replay", async () => {
  const core = genesis();
  const options = { reviewerGenesis: core, ...roleOptions() };
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);

  const statusPayload = {
    ...status,
    schema: pure.RELEASE_REVIEWER_AUTHORITY_CURRENT_STATUS_PAYLOAD_SCHEMA,
  };
  delete statusPayload.guardian_signatures;
  delete statusPayload.signing_payload_sha256;
  const statusMessage = pure.releaseReviewerAuthorityCurrentStatusSigningMessage(
    statusPayload,
    options,
  );
  const forgedStatus = structuredClone(status);
  forgedStatus.guardian_signatures[0].signature =
    (await FORGED_ACCOUNT.signMessage({ message: statusMessage })).toLowerCase();
  assert.throws(
    () => pure.normalizeReleaseReviewerAuthorityCurrentStatus(
      forgedStatus,
      options,
    ),
    /verification failed/,
  );

  const acceptancePayload = {
    ...artifact,
    schema: pure.RELEASE_REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_PAYLOAD_SCHEMA,
  };
  delete acceptancePayload.acceptances;
  delete acceptancePayload.signing_payload_sha256;
  const acceptanceMessage =
    pure.releaseReviewerAuthorityGenesisAcceptanceSigningMessage(
      acceptancePayload,
      options,
    );
  const forgedAcceptance = structuredClone(artifact);
  forgedAcceptance.acceptances[0].signature =
    (await FORGED_ACCOUNT.signMessage({ message: acceptanceMessage }))
      .toLowerCase();
  assert.throws(
    () => pure.normalizeReleaseReviewerAuthorityGenesisAcceptance(
      forgedAcceptance,
      options,
    ),
    /verification failed/,
  );
});

test("high-level exact37 path rejects later epochs, uncommitted history, stale time, and role overlap", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);
  const input = highLevelInput(core, artifact);

  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation({
      ...input,
      reviewerStatusHistory: [],
    }),
    /exact schema/,
  );

  const laterEpoch = structuredClone(input);
  laterEpoch.reviewerGenesisAcceptance
    .reviewer_authority_current_status.epoch = 2;
  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
      laterEpoch,
    ),
    /anchored raw digest|only the committed epoch-one status/,
  );

  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation({
      ...input,
      validationTime: "2026-07-21T12:15:00Z",
    }),
    /expired at the explicit historical validation time/,
  );
  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation({
      ...input,
      deploymentRoleAddresses: [core.status_guardians[0].address],
    }),
    /distinct from supplied deployment-role identities/,
  );
});

test("canonical graph rejection never invokes accessors and rejects custom prototypes", async () => {
  const core = genesis();
  const status = await currentStatus(core);
  const artifact = await acceptance(core, status);
  const input = highLevelInput(core, artifact);

  let accessorReads = 0;
  const accessorInput = structuredClone(input);
  Object.defineProperty(accessorInput.reviewerGenesis, "schema", {
    configurable: true,
    enumerable: true,
    get() {
      accessorReads += 1;
      return pure.RELEASE_REVIEWER_AUTHORITY_GENESIS_SCHEMA;
    },
  });
  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
      accessorInput,
    ),
    /accessors.*forbidden/,
  );
  assert.equal(accessorReads, 0);

  const customPrototypeInput = structuredClone(input);
  Object.setPrototypeOf(customPrototypeInput.reviewerGenesis, {
    attacker: true,
  });
  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
      customPrototypeInput,
    ),
    /custom prototypes are forbidden/,
  );

  let proxyGetCalls = 0;
  let proxyDescriptorCalls = 0;
  const divergentProxy = new Proxy(input, {
    get() {
      proxyGetCalls += 1;
      return "attacker-controlled get view";
    },
    getOwnPropertyDescriptor(target, property) {
      proxyDescriptorCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
  });
  assert.throws(
    () => pure.reconstructPersistedReleaseReviewerAuthorityForHistoricalActivation(
      divergentProxy,
    ),
    /Proxy objects are forbidden/i,
  );
  assert.equal(proxyGetCalls, 0);
  assert.equal(proxyDescriptorCalls, 0);
});

test("reviewer historical core local import closure has no effectful authority edge", () => {
  const start = fileURLToPath(
    new URL("./release-reviewer-authority-core.mjs", import.meta.url),
  );
  const visited = new Set();
  const sources = [];

  function visit(file) {
    const resolved = path.resolve(file);
    if (visited.has(resolved)) return;
    visited.add(resolved);
    const source = readFileSync(resolved, "utf8");
    sources.push([resolved, source]);
    for (const match of source.matchAll(
      /(?:from\s+|import\s*)["'](\.[^"']+)["']/g,
    )) {
      const child = path.resolve(path.dirname(resolved), match[1]);
      visit(child);
    }
  }

  visit(start);
  const forbidden = [
    /node:(?:fs|path|os|child_process|net|http|https)/,
    /\bfrom\s+["']viem(?:\/|["'])/,
    /\bimport\s*\(/,
    /\bDate\.now\s*\(/,
    /\bprocess(?:\.|\[)/,
    /\bfetch\s*\(/,
    /\bspawn(?:Sync)?\s*\(/,
    /\bWeakMap\s*\(/,
  ];
  for (const [file, source] of sources) {
    for (const pattern of forbidden) {
      assert.doesNotMatch(source, pattern, `${file} contains ${pattern}`);
    }
  }
  assert.deepEqual(
    [...visited].map((file) => path.relative(process.cwd(), file)).sort(),
    [
      "scripts/canonical-authority-graph.mjs",
      "scripts/release-authority-signature-verifier-core.mjs",
      "scripts/release-reviewer-authority-core.mjs",
      "web/scripts/independent-eip191-replay-core.mjs",
    ],
  );
});
