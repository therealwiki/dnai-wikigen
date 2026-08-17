#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalArtifactSha256,
  parseDeploymentIntentCoreText,
  describeAuthorityReviewSubjectText,
  parseAuthorityReviewEnvelopeText,
  validateDeploymentIntentCore,
} from "./operator-policy-packet-core.mjs";
import {
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core.mjs";

export const CEREMONY_AUTHORITY_PROJECTION_SCHEMA =
  "dnai.ceremony-authority-projection.v1";
export const CEREMONY_AUTHORITY_ASSERTION_COUNT = 36;
export const CEREMONY_AUTHORITY_ALIAS_COUNT = 4;
export const DEPLOYMENT_INTENT_ENVIRONMENT_PROJECTION_SCHEMA =
  "dnai.deployment-intent-environment-projection.v1";
export const DEPLOYMENT_INTENT_ENVIRONMENT_ASSERTION_COUNT = 9;

const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const SHA256_PIN = /^sha256:[0-9a-f]{64}$/;
const RELEASE_SHA = /^[0-9a-f]{40}$/;
const MAX_REVIEW_EVIDENCE_BYTES = 2 * 1024 * 1024;
const REVIEWED_CEREMONY_AUTHORITY_PROJECTIONS = new WeakMap();

export class CeremonyAuthorityProjectionError extends TypeError {}

function fail(message) {
  throw new CeremonyAuthorityProjectionError(message);
}

function same(actual, expected, label) {
  if (actual !== expected) fail(`${label} does not match across the reviewed authority artifacts`);
}

function assertion(section, projectionName, value, source) {
  return Object.freeze({ section, projectionName, value: String(value), source });
}

function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== "object" || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

/**
 * Project only facts available before any contract broadcast or CVM launch.
 * This is the single code-owned mapping used by fresh-deployment preflight;
 * final authority and postmeasurement facts are deliberately out of scope.
 */
export function projectDeploymentIntentEnvironment(deploymentIntentValue) {
  const validation = validateDeploymentIntentCore(deploymentIntentValue);
  if (!validation.ok) {
    fail(`deployment intent is invalid: ${validation.errors?.[0]?.message || "unknown error"}`);
  }
  const intent = deploymentIntentValue;
  const contractPolicy = intent.numericPolicy.contract;
  const assertions = {
    DEPLOYMENT_OPERATOR: assertion(
      "contractEnv",
      "DEPLOYMENT_OPERATOR",
      intent.deploymentControl.operatorAddress,
      "deployment_intent.deploymentControl.operatorAddress",
    ),
    RELEASE_SHA: assertion(
      "contractEnv",
      "RELEASE_SHA",
      intent.release.releaseSha,
      "deployment_intent.release.releaseSha",
    ),
    DILIGENCE_GOVERNANCE_CONTROLLER: assertion(
      "contractEnv",
      "DILIGENCE_GOVERNANCE_CONTROLLER",
      intent.staticContractInputs.diligenceRoom.governanceController,
      "deployment_intent.staticContractInputs.diligenceRoom.governanceController",
    ),
    COMPUTE_VAULT_DEVELOPER: assertion(
      "contractEnv",
      "COMPUTE_VAULT_DEVELOPER",
      intent.staticContractInputs.computeCreditVault.developer,
      "deployment_intent.staticContractInputs.computeCreditVault.developer",
    ),
    TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT: assertion(
      "contractEnv",
      "TINKER_ENCUMBRANCE_ACCOUNT_COMMITMENT",
      intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment,
      "deployment_intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment",
    ),
    COMPUTE_VAULT_DEVELOPER_FEE_BPS: assertion(
      "contractEnv",
      "COMPUTE_VAULT_DEVELOPER_FEE_BPS",
      contractPolicy.computeDeveloperFeeBps,
      "deployment_intent.numericPolicy.contract.computeDeveloperFeeBps",
    ),
    EMAIL_ORACLE_UPGRADE_DELAY: assertion(
      "contractEnv",
      "EMAIL_ORACLE_UPGRADE_DELAY",
      contractPolicy.emailOracleUpgradeDelaySeconds,
      "deployment_intent.numericPolicy.contract.emailOracleUpgradeDelaySeconds",
    ),
    TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI: assertion(
      "contractEnv",
      "TINKER_ENCUMBRANCE_MAX_ADD_BALANCE_WEI",
      contractPolicy.tinkerMaxAddBalanceWei,
      "deployment_intent.numericPolicy.contract.tinkerMaxAddBalanceWei",
    ),
    TINKER_ENCUMBRANCE_MAX_SPEND_WEI: assertion(
      "contractEnv",
      "TINKER_ENCUMBRANCE_MAX_SPEND_WEI",
      contractPolicy.tinkerMaxSpendWei,
      "deployment_intent.numericPolicy.contract.tinkerMaxSpendWei",
    ),
  };
  if (Object.keys(assertions).length !== DEPLOYMENT_INTENT_ENVIRONMENT_ASSERTION_COUNT) {
    fail("internal deployment-intent assertion map is incomplete");
  }
  for (const [name, entry] of Object.entries(assertions)) {
    if (entry.projectionName !== name) {
      fail("internal deployment-intent projection names must equal their environment keys");
    }
  }
  return {
    schema: DEPLOYMENT_INTENT_ENVIRONMENT_PROJECTION_SCHEMA,
    releaseSha: intent.release.releaseSha,
    chainId: intent.network.chainId,
    deploymentIntentSha256: canonicalArtifactSha256(intent),
    assertionCount: DEPLOYMENT_INTENT_ENVIRONMENT_ASSERTION_COUNT,
    assertions,
  };
}

export function projectCanonicalDeploymentIntentEnvironmentText(deploymentIntentText) {
  const descriptor = parseDeploymentIntentCoreText(deploymentIntentText);
  if (!descriptor.ok) {
    fail(`deployment intent is invalid: ${descriptor.errors?.[0]?.message || "unknown error"}`);
  }
  return projectDeploymentIntentEnvironment(descriptor.intent);
}

/**
 * Project the complete public environment asserted by all five post-deployment
 * ceremonies. Both inputs must already be parsed authority artifacts; this
 * function validates them again and accepts no operator-authored projection.
 */
export function projectCeremonyAuthorityEnvironment(
  deploymentIntentValue,
  finalAuthorityValue,
) {
  const intentValidation = validateDeploymentIntentCore(deploymentIntentValue);
  if (!intentValidation.ok) {
    fail(`deployment intent is invalid: ${intentValidation.errors?.[0]?.message || "unknown error"}`);
  }

  let authority;
  try {
    authority = normalizeFinalReleaseAuthorityCore(finalAuthorityValue);
  } catch (error) {
    fail(`final authority is invalid: ${String(error?.message || "unsupported subject")}`);
  }

  const intent = deploymentIntentValue;
  const intentSha256 = canonicalArtifactSha256(intent);
  const finalAuthoritySha256 = `sha256:${finalReleaseAuthorityCoreDigest(authority)}`;
  const cvmLaunchIntentSha256 = authority.cvm_launch_intent_sha256;

  same(authority.deployment_intent_sha256, intentSha256, "final-authority deployment-intent digest");
  same(authority.release_sha, intent.release.releaseSha, "release SHA");
  same(authority.network.chain_id, intent.network.chainId, "chain ID");
  same(authority.contracts.usdc.address, intent.network.canonicalUsdc, "canonical USDC");
  same(authority.operator_address, intent.deploymentControl.operatorAddress, "deployment operator");

  const intentStatic = intent.staticContractInputs;
  const contractPolicy = intent.numericPolicy.contract;
  const diligence = authority.contracts.diligence_room;
  const tinker = authority.contracts.tinker_account_encumbrance;
  const compute = authority.contracts.compute_credit_vault;
  const usdc = authority.contracts.usdc;
  const email = authority.contracts.email_oracle_auth;
  const nativeRate = compute.rate_policies.native;
  const erc20Rate = compute.rate_policies.erc20;
  const anchor = authority.execution_policy.rollback_anchor_target;

  if (!SHA256_PIN.test(cvmLaunchIntentSha256)
    || cvmLaunchIntentSha256 === `sha256:${"0".repeat(64)}`) {
    fail("final-authority CVM launch-intent digest is invalid");
  }
  const launchIntentCommitment =
    `0x${cvmLaunchIntentSha256.slice("sha256:".length)}`;
  same(
    anchor.writer_release_commitment,
    launchIntentCommitment,
    "ExecutionPolicyAnchor writer launch-intent commitment",
  );

  same(
    diligence.developer,
    intentStatic.diligenceRoom.governanceController,
    "DiligenceRoom constructor release governance controller",
  );
  same(
    compute.developer,
    intentStatic.computeCreditVault.developer,
    "ComputeCreditVault constructor developer",
  );
  same(
    tinker.account_commitment,
    intentStatic.tinkerAccountEncumbrance.accountCommitment,
    "TinkerAccountEncumbrance constructor account commitment",
  );
  same(
    compute.developer_fee_bps,
    contractPolicy.computeDeveloperFeeBps,
    "ComputeCreditVault developer fee",
  );
  same(
    nativeRate.developer_fee_bps,
    contractPolicy.computeDeveloperFeeBps,
    "native Compute rate-policy developer fee",
  );
  same(
    erc20Rate.developer_fee_bps,
    contractPolicy.computeDeveloperFeeBps,
    "ERC20 Compute rate-policy developer fee",
  );
  same(
    email.upgrade_delay_seconds,
    contractPolicy.emailOracleUpgradeDelaySeconds,
    "EmailOracleAuth upgrade delay",
  );
  for (const [label, actual] of [
    ["active add-balance cap", tinker.max_add_balance_wei],
    ["release add-balance cap", tinker.release_max_add_balance_wei],
  ]) {
    same(actual, contractPolicy.tinkerMaxAddBalanceWei, `Tinker ${label}`);
  }
  for (const [label, actual] of [
    ["active spend cap", tinker.max_spend_wei],
    ["release spend cap", tinker.release_max_spend_wei],
  ]) {
    same(actual, contractPolicy.tinkerMaxSpendWei, `Tinker ${label}`);
  }

  const assertions = {
    DILIGENCE_GOVERNANCE_CONTROLLER: assertion(
      "contractEnv",
      "DILIGENCE_GOVERNANCE_CONTROLLER",
      intentStatic.diligenceRoom.governanceController,
      "deployment_intent.staticContractInputs.diligenceRoom.governanceController",
    ),
    DILIGENCE_RESULT_VERIFIER: assertion(
      "contractEnv",
      "DILIGENCE_RESULT_VERIFIER",
      diligence.result_verifier,
      "final_authority.contracts.diligence_room.result_verifier",
    ),
    DILIGENCE_TEE_IDENTITY: assertion(
      "postDeployEnv",
      "DILIGENCE_TEE_IDENTITY",
      diligence.release_admission.tee_identity,
      "final_authority.contracts.diligence_room.release_admission.tee_identity",
    ),
    DILIGENCE_COMPOSE_HASH: assertion(
      "postDeployEnv",
      "DILIGENCE_COMPOSE_HASH",
      `0x${diligence.release_admission.compose_hash}`,
      "final_authority.contracts.diligence_room.release_admission.compose_hash",
    ),
    DILIGENCE_ATTESTATION_VERIFIER: assertion(
      "postDeployEnv",
      "DILIGENCE_ATTESTATION_VERIFIER",
      diligence.attestation_verifier,
      "final_authority.contracts.diligence_room.attestation_verifier",
    ),
    DILIGENCE_QVL_RELEASE_POLICY_HASH: assertion(
      "postDeployEnv",
      "DILIGENCE_QVL_RELEASE_POLICY_HASH",
      diligence.attestation_release_policy_hash,
      "final_authority.contracts.diligence_room.attestation_release_policy_hash",
    ),
    DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1: assertion(
      "postDeployEnv",
      "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_1",
      diligence.evaluator_policy_commitments[0],
      "final_authority.contracts.diligence_room.evaluator_policy_commitments[0]",
    ),
    DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2: assertion(
      "postDeployEnv",
      "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_2",
      diligence.evaluator_policy_commitments[1],
      "final_authority.contracts.diligence_room.evaluator_policy_commitments[1]",
    ),
    DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3: assertion(
      "postDeployEnv",
      "DILIGENCE_EVALUATOR_POLICY_COMMITMENT_3",
      diligence.evaluator_policy_commitments[2],
      "final_authority.contracts.diligence_room.evaluator_policy_commitments[2]",
    ),
    DILIGENCE_EVALUATOR_POLICY_SET_ROOT: assertion(
      "postDeployEnv",
      "DILIGENCE_EVALUATOR_POLICY_SET_ROOT",
      diligence.evaluator_policy_set_root,
      "final_authority.contracts.diligence_room.evaluator_policy_set_root",
    ),

    COMPUTE_VAULT_DEVELOPER: assertion(
      "contractEnv",
      "COMPUTE_VAULT_DEVELOPER",
      compute.developer,
      "deployment_intent.staticContractInputs.computeCreditVault.developer",
    ),
    COMPUTE_VAULT_DEVELOPER_FEE_BPS: assertion(
      "contractEnv",
      "COMPUTE_VAULT_DEVELOPER_FEE_BPS",
      contractPolicy.computeDeveloperFeeBps,
      "deployment_intent.numericPolicy.contract.computeDeveloperFeeBps",
    ),
    COMPUTE_VAULT_METERING_VERIFIER: assertion(
      "contractEnv",
      "COMPUTE_VAULT_METERING_VERIFIER",
      compute.metering_verifier,
      "final_authority.contracts.compute_credit_vault.metering_verifier",
    ),
    COMPUTE_VAULT_METERING_QVL_VERIFIER: assertion(
      "contractEnv",
      "COMPUTE_VAULT_METERING_QVL_VERIFIER",
      compute.metering_qvl_verifier,
      "final_authority.contracts.compute_credit_vault.metering_qvl_verifier",
    ),
    COMPUTE_VAULT_TEE_IDENTITY: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_TEE_IDENTITY",
      compute.tee_identity,
      "final_authority.contracts.compute_credit_vault.tee_identity",
    ),
    COMPUTE_VAULT_COMPOSE_HASH: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_COMPOSE_HASH",
      `0x${compute.compose_hash}`,
      "final_authority.contracts.compute_credit_vault.compose_hash",
    ),
    COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT",
      nativeRate.commitment,
      "final_authority.contracts.compute_credit_vault.rate_policies.native.commitment",
    ),
    COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT",
      erc20Rate.commitment,
      "final_authority.contracts.compute_credit_vault.rate_policies.erc20.commitment",
    ),
    COMPUTE_VAULT_NATIVE_PROVIDER: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_NATIVE_PROVIDER",
      nativeRate.provider,
      "final_authority.contracts.compute_credit_vault.rate_policies.native.provider",
    ),
    COMPUTE_VAULT_ERC20_PROVIDER: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_PROVIDER",
      erc20Rate.provider,
      "final_authority.contracts.compute_credit_vault.rate_policies.erc20.provider",
    ),
    COMPUTE_METERING_POLICY_SET_HASH: assertion(
      "postDeployEnv",
      "COMPUTE_METERING_POLICY_SET_HASH",
      compute.metering_policy_set_hash,
      "final_authority.contracts.compute_credit_vault.metering_policy_set_hash",
    ),
    COMPUTE_VAULT_ERC20_ASSET_ADDRESS: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_ASSET_ADDRESS",
      usdc.address,
      "final_authority.contracts.usdc.address",
    ),
    COMPUTE_VAULT_ERC20_ASSET_CODE_HASH: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_ASSET_CODE_HASH",
      usdc.runtime_code_hash,
      "final_authority.contracts.usdc.runtime_code_hash",
    ),
    COMPUTE_VAULT_ERC20_ASSET_SYMBOL: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_ASSET_SYMBOL",
      usdc.symbol,
      "final_authority.contracts.usdc.symbol",
    ),
    COMPUTE_VAULT_ERC20_ASSET_DECIMALS: assertion(
      "postDeployEnv",
      "COMPUTE_VAULT_ERC20_ASSET_DECIMALS",
      usdc.decimals,
      "final_authority.contracts.usdc.decimals",
    ),

    EMAIL_ORACLE_UPGRADE_DELAY: assertion(
      "contractEnv",
      "EMAIL_ORACLE_UPGRADE_DELAY",
      contractPolicy.emailOracleUpgradeDelaySeconds,
      "deployment_intent.numericPolicy.contract.emailOracleUpgradeDelaySeconds",
    ),
    EMAIL_ORACLE_CONSUMER_APP_ID: assertion(
      "postDeployEnv",
      "EMAIL_ORACLE_CONSUMER_APP_ID",
      email.consumer_address,
      "final_authority.contracts.email_oracle_auth.consumer_address",
    ),
    EMAIL_ORACLE_COMPOSE_HASH: assertion(
      "postDeployEnv",
      "EMAIL_ORACLE_COMPOSE_HASH",
      email.release.oracle_compose_hash,
      "final_authority.contracts.email_oracle_auth.release.oracle_compose_hash",
    ),
    EMAIL_ORACLE_CONSUMER_COMPOSE_HASH: assertion(
      "postDeployEnv",
      "EMAIL_ORACLE_CONSUMER_COMPOSE_HASH",
      email.release.consumer_compose_hash,
      "final_authority.contracts.email_oracle_auth.release.consumer_compose_hash",
    ),

    EXECUTION_POLICY_ANCHOR_WRITER: assertion(
      "postDeployEnv",
      "EXECUTION_POLICY_ANCHOR_WRITER",
      anchor.writer_address,
      "final_authority.execution_policy.rollback_anchor_target.writer_address",
    ),
    EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT: assertion(
      "postDeployEnv",
      "EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT",
      launchIntentCommitment,
      "derived.domain_separated_cvm_launch_intent_sha256",
    ),

    TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT: assertion(
      "postDeployEnv",
      "TINKER_ENCUMBRANCE_RELEASE_ACCOUNT_COMMITMENT",
      intentStatic.tinkerAccountEncumbrance.accountCommitment,
      "deployment_intent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment",
    ),
    TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI: assertion(
      "postDeployEnv",
      "TINKER_ENCUMBRANCE_RELEASE_MAX_ADD_BALANCE_WEI",
      contractPolicy.tinkerMaxAddBalanceWei,
      "deployment_intent.numericPolicy.contract.tinkerMaxAddBalanceWei",
    ),
    TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI: assertion(
      "postDeployEnv",
      "TINKER_ENCUMBRANCE_RELEASE_MAX_SPEND_WEI",
      contractPolicy.tinkerMaxSpendWei,
      "deployment_intent.numericPolicy.contract.tinkerMaxSpendWei",
    ),
    TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH: assertion(
      "postDeployEnv",
      "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH",
      tinker.approved_compose_hashes[0],
      "final_authority.contracts.tinker_account_encumbrance.approved_compose_hashes[0]",
    ),
    TINKER_ENCUMBRANCE_RELEASE_MANAGER: assertion(
      "postDeployEnv",
      "TINKER_ENCUMBRANCE_RELEASE_MANAGER",
      tinker.managers[0],
      "final_authority.contracts.tinker_account_encumbrance.managers[0]",
    ),
  };

  if (Object.keys(assertions).length !== CEREMONY_AUTHORITY_ASSERTION_COUNT) {
    fail("internal ceremony assertion map is incomplete");
  }
  for (const [name, entry] of Object.entries(assertions)) {
    if (entry.projectionName !== name) {
      fail("internal ceremony assertion projection names must equal their environment keys");
    }
  }
  const aliases = {
    EMAIL_ORACLE_CONSUMER_APP_ID: "TINKER_ENCUMBRANCE_RELEASE_MANAGER",
    EMAIL_ORACLE_COMPOSE_HASH: "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH",
    EMAIL_ORACLE_CONSUMER_COMPOSE_HASH: "TINKER_ENCUMBRANCE_RELEASE_COMPOSE_HASH",
    EXECUTION_POLICY_WRITER_RELEASE_COMMITMENT:
      "TINKER_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  };
  if (Object.keys(aliases).length !== CEREMONY_AUTHORITY_ALIAS_COUNT) {
    fail("internal ceremony assertion alias map is incomplete");
  }
  return {
    schema: CEREMONY_AUTHORITY_PROJECTION_SCHEMA,
    releaseSha: authority.release_sha,
    chainId: authority.network.chain_id,
    deploymentIntentSha256: intentSha256,
    cvmLaunchIntentSha256,
    finalAuthoritySha256,
    assertionCount: CEREMONY_AUTHORITY_ASSERTION_COUNT,
    aliasCount: CEREMONY_AUTHORITY_ALIAS_COUNT,
    assertions,
    aliases,
  };
}

export function projectCanonicalCeremonyAuthorityText(
  deploymentIntentText,
  finalAuthorityText,
) {
  const intentDescriptor = parseDeploymentIntentCoreText(deploymentIntentText);
  if (!intentDescriptor.ok) {
    fail(`deployment intent is invalid: ${intentDescriptor.errors?.[0]?.message || "unknown error"}`);
  }
  const finalDescriptor = describeAuthorityReviewSubjectText(finalAuthorityText);
  if (
    !finalDescriptor.ok
    || finalDescriptor.subjectKind !== "final_release_authority"
    || finalDescriptor.semanticValidation !== "final_release_authority_validated"
  ) {
    fail(`final authority is invalid: ${finalDescriptor.errors?.[0]?.message || "unsupported subject"}`);
  }
  return projectCeremonyAuthorityEnvironment(
    intentDescriptor.intent,
    finalDescriptor.subject,
  );
}

/**
 * Mint the production-only in-process provenance used by downstream runtime
 * projectors. Unlike the human/CLI projector above, this path requires the
 * exact canonical launch dependency, a live final-authority review envelope,
 * and the independently read public evidence bytes committed by that envelope.
 */
export function projectReviewedCanonicalCeremonyAuthorityText({
  deploymentIntentText,
  cvmLaunchIntentText,
  finalAuthorityText,
  reviewEnvelopeText,
  reviewEvidenceBytes,
  checkedAtMs,
} = {}) {
  const intentDescriptor = parseDeploymentIntentCoreText(deploymentIntentText);
  if (!intentDescriptor.ok) {
    fail(`deployment intent is invalid: ${intentDescriptor.errors?.[0]?.message || "unknown error"}`);
  }
  const launchDescriptor = describeAuthorityReviewSubjectText(cvmLaunchIntentText);
  if (!launchDescriptor.ok || launchDescriptor.subjectKind !== "cvm_launch_intent"
    || launchDescriptor.semanticValidation !== "cvm_launch_intent_validated") {
    fail(`CVM launch intent is invalid: ${launchDescriptor.errors?.[0]?.message || "unsupported subject"}`);
  }
  const finalDescriptor = describeAuthorityReviewSubjectText(finalAuthorityText);
  if (!finalDescriptor.ok || finalDescriptor.subjectKind !== "final_release_authority"
    || finalDescriptor.semanticValidation !== "final_release_authority_validated") {
    fail(`final authority is invalid: ${finalDescriptor.errors?.[0]?.message || "unsupported subject"}`);
  }
  const review = parseAuthorityReviewEnvelopeText(reviewEnvelopeText, {
    checkedAtMs,
    subjectDescriptor: finalDescriptor,
    authorityDependencies: {
      deploymentIntent: intentDescriptor.intent,
      cvmLaunchIntent: launchDescriptor.subject,
    },
  });
  if (!review.ok) {
    fail(`final-authority review is invalid: ${review.errors?.[0]?.message || "unknown error"}`);
  }
  if (!(reviewEvidenceBytes instanceof Uint8Array)
    || reviewEvidenceBytes.byteLength < 1
    || reviewEvidenceBytes.byteLength > MAX_REVIEW_EVIDENCE_BYTES) {
    fail("final-authority review evidence must be bounded raw bytes");
  }
  const reviewEvidenceSha256 = `sha256:${createHash("sha256")
    .update(Buffer.from(reviewEvidenceBytes))
    .digest("hex")}`;
  same(
    reviewEvidenceSha256,
    review.receipt.reviewEvidenceSha256,
    "final-authority review-evidence SHA-256 pin",
  );

  const projection = deepFreeze(projectCeremonyAuthorityEnvironment(
    intentDescriptor.intent,
    finalDescriptor.subject,
  ));
  REVIEWED_CEREMONY_AUTHORITY_PROJECTIONS.set(projection, Object.freeze({
    projectionSha256: canonicalArtifactSha256(projection),
    finalAuthoritySha256: finalDescriptor.subjectSha256,
    reviewEnvelopeSha256: review.receipt.reviewEnvelopeSha256,
    reviewEvidenceSha256,
  }));
  return projection;
}

export function assertReviewedCeremonyAuthorityProjection(value) {
  const provenance = value && REVIEWED_CEREMONY_AUTHORITY_PROJECTIONS.get(value);
  if (!provenance
    || value.schema !== CEREMONY_AUTHORITY_PROJECTION_SCHEMA
    || provenance.projectionSha256 !== canonicalArtifactSha256(value)
    || provenance.finalAuthoritySha256 !== value.finalAuthoritySha256
    || !SHA256_PIN.test(provenance.reviewEnvelopeSha256)
    || !SHA256_PIN.test(provenance.reviewEvidenceSha256)) {
    fail("ceremony authority projection lacks current review provenance");
  }
  return value;
}

async function readAuthorityFile(filePath, label) {
  if (!path.isAbsolute(filePath)) fail(`${label} path must be absolute`);
  const info = await lstat(filePath);
  if (!info.isFile() || info.isSymbolicLink()) {
    fail(`${label} must be a non-symlink regular file`);
  }
  if (info.size <= 0 || info.size > 65_536) fail(`${label} size is outside the supported bound`);
  return readFile(filePath, "utf8");
}

function parseCliArgs(argv) {
  const options = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!name?.startsWith("--") || value === undefined || value.startsWith("--")) {
      fail("usage: ceremony-authority-projector.mjs --intent FILE --final-authority FILE --intent-sha256 SHA --final-authority-sha256 SHA --release-sha SHA");
    }
    if (options.has(name)) fail(`duplicate argument ${name}`);
    options.set(name, value);
  }
  const allowed = new Set([
    "--intent",
    "--final-authority",
    "--intent-sha256",
    "--final-authority-sha256",
    "--release-sha",
  ]);
  if (options.size !== allowed.size || [...options.keys()].some((key) => !allowed.has(key))) {
    fail("all five exact projector arguments are required");
  }
  return Object.fromEntries([...options].map(([key, value]) => [key.slice(2), value]));
}

export async function runCeremonyAuthorityProjectorCli(argv) {
  const options = parseCliArgs(argv);
  if (!SHA256_PIN.test(options["intent-sha256"])) fail("intent SHA-256 pin is malformed");
  if (!SHA256_PIN.test(options["final-authority-sha256"])) fail("final-authority SHA-256 pin is malformed");
  if (!RELEASE_SHA.test(options["release-sha"])) fail("release SHA is malformed");
  const [intentText, authorityText] = await Promise.all([
    readAuthorityFile(options.intent, "deployment intent"),
    readAuthorityFile(options["final-authority"], "final authority"),
  ]);
  const projection = projectCanonicalCeremonyAuthorityText(intentText, authorityText);
  same(projection.deploymentIntentSha256, options["intent-sha256"], "deployment-intent SHA-256 pin");
  same(projection.finalAuthoritySha256, options["final-authority-sha256"], "final-authority SHA-256 pin");
  same(projection.releaseSha, options["release-sha"], "release SHA argument");
  return projection;
}

const isEntrypoint = process.argv[1]
  && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isEntrypoint) {
  try {
    const projection = await runCeremonyAuthorityProjectorCli(process.argv.slice(2));
    process.stdout.write(`${JSON.stringify(projection)}\n`);
  } catch (error) {
    process.stderr.write(`Ceremony authority projection failed: ${String(error?.message || error).replace(/[\r\n]+/g, " ").slice(0, 512)}\n`);
    process.exitCode = 1;
  }
}
