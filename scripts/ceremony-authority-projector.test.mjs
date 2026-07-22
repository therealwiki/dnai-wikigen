import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CEREMONY_AUTHORITY_ASSERTION_COUNT,
  CEREMONY_AUTHORITY_ALIAS_COUNT,
  CeremonyAuthorityProjectionError,
  DEPLOYMENT_INTENT_ENVIRONMENT_ASSERTION_COUNT,
  assertReviewedCeremonyAuthorityProjection,
  projectCanonicalDeploymentIntentEnvironmentText,
  projectCeremonyAuthorityEnvironment,
  projectDeploymentIntentEnvironment,
  projectReviewedCanonicalCeremonyAuthorityText,
  runCeremonyAuthorityProjectorCli,
} from "./ceremony-authority-projector.mjs";
import {
  canonicalArtifactSha256,
  canonicalArtifactText,
  createDraftAuthorityReviewEnvelope,
  createDraftDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  canonicalCvmLaunchIntentCoreArtifactText,
  createDraftCvmLaunchIntentCore,
  cvmLaunchIntentCoreDigest,
} from "./cvm-launch-intent-core.mjs";
import {
  canonicalFinalReleaseAuthorityCoreArtifactText,
  finalReleaseAuthorityCoreDigest,
} from "./execution-policy-release-core.mjs";
import { knownVector } from "./execution-policy-release-core.fixture.mjs";

function validQvlPolicy() {
  return {
    challengeCapacity: 1_024,
    challengeTtlSeconds: 60,
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    verificationTimeoutSeconds: "20",
  };
}

test("deployment-intent projector owns the exact eight prebroadcast environment values", () => {
  const { intent } = authorityPair();
  const projection = projectDeploymentIntentEnvironment(intent);
  assert.equal(
    projection.assertionCount,
    DEPLOYMENT_INTENT_ENVIRONMENT_ASSERTION_COUNT,
  );
  assert.deepEqual(Object.keys(projection.assertions), [
    "DEPLOYMENT_OPERATOR",
    "RELEASE_SHA",
    "COMPUTE_VAULT_DEVELOPER",
    "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT",
    "COMPUTE_VAULT_DEVELOPER_FEE_BPS",
    "EMAIL_ORACLE_UPGRADE_DELAY",
    "TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI",
    "TINKER_ENCUMBRANCE_MAX_SPEND_WEI",
  ]);
  for (const [name, entry] of Object.entries(projection.assertions)) {
    assert.equal(entry.section, "contractEnv");
    assert.equal(entry.projectionName, name);
  }
  assert.equal(
    projection.assertions.TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT.value,
    intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment,
  );
  assert.deepEqual(
    projectCanonicalDeploymentIntentEnvironmentText(canonicalArtifactText(intent)),
    projection,
  );
  const invalid = structuredClone(intent);
  invalid.dynamicRuntimeAuthorities.mainRuntimeAppId = "premature-runtime-fact";
  assert.throws(
    () => projectDeploymentIntentEnvironment(invalid),
    CeremonyAuthorityProjectionError,
  );
});

function authorityPair() {
  const intent = createDraftDeploymentIntentCore();
  intent.release.releaseSha = "0123456789abcdef0123456789abcdef01234567";
  intent.release.reviewerAuthorityGenesisAcceptanceSha256 = `sha256:${"91".repeat(32)}`;
  intent.release.reviewerAuthorityCurrentStatusEpoch = 1;
  intent.release.reviewerAuthorityCurrentStatusSha256 = `sha256:${"92".repeat(32)}`;
  intent.deploymentControl.controllerId = "operator-control-01";
  intent.deploymentControl.operatorAddress =
    "0x0000000000000000000000000000000000000001";
  intent.staticContractInputs.computeCreditVault.developer =
    "0x000000000000000000000000000000000000000a";
  intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
    `0x${"22".repeat(32)}`;
  intent.numericPolicy.contract = {
    computeDeveloperFeeBps: 500,
    emailOracleUpgradeDelaySeconds: 172_800,
    tinkerMaxAddBalanceWei: "1000000000000000000",
    tinkerMaxSpendWei: "250000000000000000",
  };
  intent.numericPolicy.metering = {
    maxConcurrency: 4,
    rateCapacity: 30,
    rateRefillPerSecond: "0.5",
    requestBodyTimeoutSeconds: "5",
    rpcTimeoutSeconds: "8",
  };
  for (const name of Object.keys(intent.numericPolicy.qvl)) {
    intent.numericPolicy.qvl[name] = validQvlPolicy();
  }
  const authority = knownVector();
  authority.deployment_intent_sha256 = canonicalArtifactSha256(intent);
  return { intent, authority };
}

function reviewedAuthorityContext() {
  const checkedAtMs = Date.parse("2026-07-21T12:00:00Z");
  const { intent, authority } = authorityPair();
  const launch = createDraftCvmLaunchIntentCore();
  launch.release_sha = intent.release.releaseSha;
  launch.deployment_intent_sha256 = canonicalArtifactSha256(intent);
  launch.contract_deployment_receipt_sha256 = `sha256:${"a1".repeat(32)}`;
  launch.topology_sha256 = `sha256:${"a2".repeat(32)}`;
  launch.image_release_manifest_sha256 = `sha256:${"a3".repeat(32)}`;
  launch.image_attestation_bundle_sha256 = `sha256:${"a4".repeat(32)}`;
  launch.descriptors.forEach((descriptor, index) => {
    descriptor.descriptor_sha256 =
      `sha256:${(index + 16).toString(16).padStart(2, "0").repeat(32)}`;
    descriptor.app_compose_candidate.docker_compose_file_sha256 =
      descriptor.descriptor_sha256;
    descriptor.app_compose_candidate.docker_compose_file_byte_length = 2_000 + index;
    descriptor.app_compose_candidate.expected_compose_hash =
      (index + 1).toString(16).repeat(64);
  });
  const launchDigest = cvmLaunchIntentCoreDigest(launch);
  authority.cvm_launch_intent_sha256 = `sha256:${launchDigest}`;
  authority.execution_policy.rollback_anchor_target.writer_release_commitment =
    `0x${launchDigest}`;
  const finalAuthoritySha256 = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const reviewEvidenceBytes = Buffer.from('{"review":"approved"}\n', "utf8");
  const reviewEnvelope = createDraftAuthorityReviewEnvelope(
    "final_release_authority",
    finalAuthoritySha256,
  );
  reviewEnvelope.approved_at = "2026-07-21T11:59:00Z";
  reviewEnvelope.expires_at = "2026-07-22T12:00:00Z";
  reviewEnvelope.review_evidence_sha256 = `sha256:${createHash("sha256")
    .update(reviewEvidenceBytes)
    .digest("hex")}`;
  reviewEnvelope.reviewers = [
    {
      address: "0x0000000000000000000000000000000000000028",
      controllerId: "reviewer-root-01",
    },
    {
      address: "0x0000000000000000000000000000000000000029",
      controllerId: "reviewer-root-02",
    },
  ];
  return {
    checkedAtMs,
    deploymentIntentText: canonicalArtifactText(intent),
    cvmLaunchIntentText: canonicalCvmLaunchIntentCoreArtifactText(launch),
    finalAuthorityText: canonicalFinalReleaseAuthorityCoreArtifactText(authority),
    reviewEnvelopeText: canonicalArtifactText(reviewEnvelope),
    reviewEvidenceBytes,
  };
}

test("code-owned projector emits the exact 31 ceremony assertions and aliases", () => {
  const { intent, authority } = authorityPair();
  const projection = projectCeremonyAuthorityEnvironment(intent, authority);
  assert.equal(projection.assertionCount, CEREMONY_AUTHORITY_ASSERTION_COUNT);
  assert.equal(Object.keys(projection.assertions).length, 31);
  assert.equal(projection.aliasCount, CEREMONY_AUTHORITY_ALIAS_COUNT);
  assert.equal(Object.keys(projection.aliases).length, 4);
  for (const [name, entry] of Object.entries(projection.assertions)) {
    assert.equal(entry.projectionName, name);
  }
  assert.equal(
    projection.finalAuthoritySha256,
    `sha256:${finalReleaseAuthorityCoreDigest(authority)}`,
  );
  assert.equal(
    projection.cvmLaunchIntentSha256,
    authority.cvm_launch_intent_sha256,
  );
  assert.deepEqual(
    Object.fromEntries(Object.entries(projection.assertions).map(([name, entry]) => [
      name,
      [entry.section, entry.projectionName],
    ])),
    {
      DILIGENCE_RESULT_VERIFIER: ["contractEnv", "DILIGENCE_RESULT_VERIFIER"],
      DILIGENCE_TEE_IDENTITY: ["postDeployEnv", "DILIGENCE_TEE_IDENTITY"],
      DILIGENCE_COMPOSE_HASH: ["postDeployEnv", "DILIGENCE_COMPOSE_HASH"],
      DILIGENCE_ATTESTATION_VERIFIER: ["postDeployEnv", "DILIGENCE_ATTESTATION_VERIFIER"],
      DILIGENCE_QVL_RELEASE_POLICY_HASH: ["postDeployEnv", "DILIGENCE_QVL_RELEASE_POLICY_HASH"],
      DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1: ["postDeployEnv", "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1"],
      DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2: ["postDeployEnv", "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2"],
      DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3: ["postDeployEnv", "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3"],
      DILIGENCE_EVALUATOR_POLICY_SET_ROOT: ["postDeployEnv", "DILIGENCE_EVALUATOR_POLICY_SET_ROOT"],
      COMPUTE_VAULT_DEVELOPER: ["contractEnv", "COMPUTE_VAULT_DEVELOPER"],
      COMPUTE_VAULT_DEVELOPER_FEE_BPS: ["contractEnv", "COMPUTE_VAULT_DEVELOPER_FEE_BPS"],
      COMPUTE_VAULT_METERING_VERIFIER: ["contractEnv", "COMPUTE_VAULT_METERING_VERIFIER"],
      COMPUTE_VAULT_METERING_QVL_VERIFIER: ["contractEnv", "COMPUTE_VAULT_METERING_QVL_VERIFIER"],
      COMPUTE_VAULT_TEE_IDENTITY: ["postDeployEnv", "COMPUTE_VAULT_TEE_IDENTITY"],
      COMPUTE_VAULT_COMPOSE_HASH: ["postDeployEnv", "COMPUTE_VAULT_COMPOSE_HASH"],
      COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT: ["postDeployEnv", "COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT"],
      COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT: ["postDeployEnv", "COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT"],
      COMPUTE_VAULT_NATIVE_PROVIDER: ["postDeployEnv", "COMPUTE_VAULT_NATIVE_PROVIDER"],
      COMPUTE_VAULT_ERC20_PROVIDER: ["postDeployEnv", "COMPUTE_VAULT_ERC20_PROVIDER"],
      COMPUTE_METERING_POLICY_SET_HASH: ["postDeployEnv", "COMPUTE_METERING_POLICY_SET_HASH"],
      EMAIL_ORACLE_UPGRADE_DELAY: ["contractEnv", "EMAIL_ORACLE_UPGRADE_DELAY"],
      EMAIL_ORACLE_CONSUMER_APP_ID: ["postDeployEnv", "EMAIL_ORACLE_CONSUMER_APP_ID"],
      EMAIL_ORACLE_COMPOSE_HASH: ["postDeployEnv", "EMAIL_ORACLE_COMPOSE_HASH"],
      EMAIL_ORACLE_CONSUMER_COMPOSE_HASH: ["postDeployEnv", "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH"],
      EXECUTION_POLICY_ANCHOR_WRITER: ["postDeployEnv", "EXECUTION_POLICY_ANCHOR_WRITER"],
      EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT: ["postDeployEnv", "EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT"],
      TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT: ["postDeployEnv", "TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT"],
      TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI: ["postDeployEnv", "TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI"],
      TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI: ["postDeployEnv", "TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI"],
      TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH: ["postDeployEnv", "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH"],
      TINKER_ENCUMBRANCE_RELEASE_MANAGER: ["postDeployEnv", "TINKER_ENCUMBRANCE_RELEASE_MANAGER"],
    },
  );
  assert.deepEqual(projection.aliases, {
    EMAIL_ORACLE_CONSUMER_APP_ID: "TINKER_ENCUMBRANCE_RELEASE_MANAGER",
    EMAIL_ORACLE_COMPOSE_HASH: "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH",
    EMAIL_ORACLE_CONSUMER_COMPOSE_HASH: "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH",
    EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT:
      "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  });
  assert.equal(
    projection.assertions.COMPUTE_VAULT_NATIVE_PROVIDER.value,
    authority.contracts.compute_credit_vault.rate_policies.native.provider,
  );
  assert.equal(
    projection.assertions.COMPUTE_VAULT_ERC20_PROVIDER.value,
    authority.contracts.compute_credit_vault.rate_policies.erc20.provider,
  );
  assert.equal(
    projection.assertions.EMAIL_ORACLE_COMPOSE_HASH.value,
    projection.assertions.TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH.value,
  );
  assert.equal(
    projection.assertions.EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT.value,
    `0x${authority.cvm_launch_intent_sha256.slice("sha256:".length)}`,
  );
});

test("reviewed projector brands and deep-freezes only the exact live review lineage", () => {
  const context = reviewedAuthorityContext();
  const projection = projectReviewedCanonicalCeremonyAuthorityText(context);
  assert.equal(assertReviewedCeremonyAuthorityProjection(projection), projection);

  const pending = [projection];
  const seen = new WeakSet();
  while (pending.length > 0) {
    const value = pending.pop();
    if (!value || typeof value !== "object" || seen.has(value)) continue;
    seen.add(value);
    assert.equal(Object.isFrozen(value), true);
    pending.push(...Object.values(value));
  }
  assert.throws(
    () => assertReviewedCeremonyAuthorityProjection(structuredClone(projection)),
    /lacks current review provenance/,
  );
  assert.throws(
    () => assertReviewedCeremonyAuthorityProjection(
      projectCeremonyAuthorityEnvironment(
        authorityPair().intent,
        authorityPair().authority,
      ),
    ),
    /lacks current review provenance/,
  );

  assert.throws(
    () => projectReviewedCanonicalCeremonyAuthorityText({
      ...context,
      reviewEvidenceBytes: Buffer.from('{"review":"different"}\n', "utf8"),
    }),
    /review-evidence SHA-256 pin/,
  );
  assert.throws(
    () => projectReviewedCanonicalCeremonyAuthorityText({
      ...context,
      checkedAtMs: Date.parse("2026-07-23T12:00:00Z"),
    }),
    /must still be active when checked/,
  );
});

test("intent-to-final static and numeric mismatches fail closed", () => {
  const cases = [
    ["ComputeCreditVault constructor developer", (intent) => {
      intent.staticContractInputs.computeCreditVault.developer =
        "0x0000000000000000000000000000000000000020";
    }],
    ["TinkerAccountEncumbrance constructor account commitment", (intent) => {
      intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment =
        `0x${"23".repeat(32)}`;
    }],
    ["ComputeCreditVault developer fee", (intent) => {
      intent.numericPolicy.contract.computeDeveloperFeeBps = 501;
    }],
    ["EmailOracleAuth upgrade delay", (intent) => {
      intent.numericPolicy.contract.emailOracleUpgradeDelaySeconds = 172_801;
    }],
    ["Tinker active add-balance cap", (intent) => {
      intent.numericPolicy.contract.tinkerMaxAddBalanceWei = "999999999999999999";
    }],
    ["Tinker active spend cap", (intent) => {
      intent.numericPolicy.contract.tinkerMaxSpendWei = "249999999999999999";
    }],
  ];
  for (const [label, mutate] of cases) {
    const { intent, authority } = authorityPair();
    mutate(intent);
    authority.deployment_intent_sha256 = canonicalArtifactSha256(intent);
    assert.throws(
      () => projectCeremonyAuthorityEnvironment(intent, authority),
      new RegExp(label),
    );
  }
});

test("explicit Diligence, Email, Compute, and main-CVM cross-bindings reject drift", () => {
  for (const mutate of [
    (authority) => { authority.contracts.diligence_room.release_admission.compose_hash = "34".repeat(32); },
    (authority) => { authority.contracts.email_oracle_auth.release.oracle_compose_hash = `0x${"34".repeat(32)}`; },
    (authority) => { authority.contracts.compute_credit_vault.rate_policies.native.provider = authority.operator_address; },
    (authority) => { authority.contracts.compute_credit_vault.rate_policies.erc20.provider = authority.contracts.compute_credit_vault.rate_policies.native.provider; },
    (authority) => { authority.execution_policy.rollback_anchor_target.writer_release_commitment = `0x${"ff".repeat(32)}`; },
  ]) {
    const { intent, authority } = authorityPair();
    mutate(authority);
    assert.throws(
      () => projectCeremonyAuthorityEnvironment(intent, authority),
      CeremonyAuthorityProjectionError,
    );
  }
});

test("CLI checks canonical files and all three supplied pins", async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "dnai-ceremony-projector-"));
  try {
    const { intent, authority } = authorityPair();
    const intentPath = path.join(directory, "intent.json");
    const authorityPath = path.join(directory, "authority.json");
    await writeFile(intentPath, canonicalArtifactText(intent), "utf8");
    await writeFile(
      authorityPath,
      canonicalFinalReleaseAuthorityCoreArtifactText(authority),
      "utf8",
    );
    const args = [
      "--intent", intentPath,
      "--final-authority", authorityPath,
      "--intent-sha256", canonicalArtifactSha256(intent),
      "--final-authority-sha256", `sha256:${finalReleaseAuthorityCoreDigest(authority)}`,
      "--release-sha", intent.release.releaseSha,
    ];
    const projection = await runCeremonyAuthorityProjectorCli(args);
    assert.equal(projection.assertionCount, 31);
    await assert.rejects(
      runCeremonyAuthorityProjectorCli(args.with(7, `sha256:${"ff".repeat(32)}`)),
      /final-authority SHA-256 pin/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
