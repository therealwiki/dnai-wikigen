import { createHash } from "node:crypto";

import {
  canonicalFinalReleaseAuthorityCoreArtifactText,
  finalReleaseAuthorityCoreDigest,
  normalizeFinalReleaseAuthorityCore,
} from "./execution-policy-release-core.mjs";
import {
  canonicalCvmLaunchIntentCoreArtifactText,
  CVM_LAUNCH_INTENT_CORE_SCHEMA,
  cvmLaunchIntentCoreDigest,
  freshContractDeploymentReceiptDigest,
  normalizeFreshContractDeploymentReceipt,
  normalizeCvmLaunchIntentCore,
} from "./cvm-launch-intent-core.mjs";

export const DEPLOYMENT_INTENT_CORE_SCHEMA = "dnai.deployment-intent-core.v6";
export const FINAL_RELEASE_AUTHORITY_CORE_SCHEMA =
  "dnai.final-release-authority-core.v2";
export const AUTHORITY_REVIEW_ENVELOPE_SCHEMA =
  "dnai.authority-review-envelope.v1";
export const FINAL_RELEASE_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.final-release-authority-evidence.v1";
export const DEPLOYMENT_INTENT_RECEIPT_SCHEMA =
  "dnai.deployment-intent-validation-receipt.v6";
export const AUTHORITY_REVIEW_RECEIPT_SCHEMA =
  "dnai.authority-review-envelope-validation-receipt.v1";
export const OPERATOR_POLICY_ERROR_SCHEMA =
  "dnai.operator-policy-artifact-validation-error.v6";
export const MAX_PACKET_BYTES = 98_304;

export const CANONICAL_CONTRACTS = Object.freeze([
  "DiligenceRoom",
  "TinkerAccountEncumbrance",
  "RoyaltyDistributor",
  "ChallengeRegistry",
  "ComputeCreditVault",
  "EmailOracleAuth",
  "ExecutionPolicyAnchor",
]);

export const CANONICAL_CVMS = Object.freeze([
  "main_runtime",
  "diligence_qvl",
  "arena_qvl",
  "anchor_writer_qvl",
  "compute_workload_qvl",
  "compute_metering_qvl",
  "independent_metering",
]);

export const QVL_POLICY_KEYS = Object.freeze([
  "diligence",
  "arena",
  "anchorWriter",
  "computeWorkload",
  "computeMetering",
]);

export const DEPLOYMENT_TOOLCHAIN_AUTHORITY = Object.freeze({
  foundry: Object.freeze({
    buildProfile: "maxperf",
    castExecutableSha256: "f7373e6e34939415fe048560ecf275463ea891fec5a124a38958983f3955542d",
    castVersion: "1.5.1-stable",
    commitSha: "b0a9dd9ceda36f63e2326ce530c10e6916f4b8a2",
    forgeVersion: "1.5.1-stable",
  }),
  solidity: Object.freeze({
    bytecodeHash: "ipfs",
    cborMetadata: true,
    compilerVersion: "0.8.28+commit.7893614a",
    configuredVersion: "0.8.28",
    evmVersion: "prague",
    libraries: Object.freeze([]),
    optimizer: true,
    optimizerRuns: 200,
    profile: "default",
    useLiteralContent: false,
    viaIr: true,
  }),
});

export const DEPLOYMENT_INTENT_ACTION_SCOPE = Object.freeze([
  "release_source_and_network",
  "precommitted_signed_reviewer_authority_genesis_acceptance",
  "precommitted_guardian_signed_reviewer_authority_current_status_head",
  "pinned_contract_build_toolchain",
  "deployment_operator_control",
  "static_contract_inputs",
  "contract_numeric_policy",
  "qvl_numeric_policy",
  "metering_numeric_policy",
  "dynamic_runtime_authorities_empty",
]);

export const FINAL_RELEASE_AUTHORITY_ACTION_SCOPE = Object.freeze([
  "release_source_and_network",
  "deployment_intent_binding",
  "cvm_launch_intent_binding",
  "contract_suite",
  "arena_genesis_catalog",
  "cvm_topology",
  "runtime_authorities",
  "release_policy",
]);

export const CVM_LAUNCH_INTENT_ACTION_SCOPE = Object.freeze([
  "deployment_intent_and_release_source",
  "verified_contract_poststate",
  "exact_image_subjects",
  "seven_descriptor_hashes",
  "production_phala_posture",
  "public_runtime_numeric_policy",
  "encrypted_env_key_contract",
  "staged_bootstrap_and_deferred_bindings",
]);

export const REVIEW_SUBJECT_POLICY = Object.freeze({
  deployment_intent: Object.freeze({
    schema: DEPLOYMENT_INTENT_CORE_SCHEMA,
    checkpoint: "before_any_contract_broadcast_or_cvm_deployment",
    actionScope: DEPLOYMENT_INTENT_ACTION_SCOPE,
  }),
  cvm_launch_intent: Object.freeze({
    schema: CVM_LAUNCH_INTENT_CORE_SCHEMA,
    checkpoint:
      "after_verified_fresh_contract_suite_before_any_phala_cvm_provision_or_commit",
    actionScope: CVM_LAUNCH_INTENT_ACTION_SCOPE,
  }),
  final_release_authority: Object.freeze({
    schema: FINAL_RELEASE_AUTHORITY_CORE_SCHEMA,
    checkpoint: "after_measured_cvms_before_any_release_ceremony_transaction",
    actionScope: FINAL_RELEASE_AUTHORITY_ACTION_SCOPE,
  }),
});

const ZERO_ADDRESS = `0x${"0".repeat(40)}`;
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const ZERO_SHA = "0".repeat(40);
const UINT256_MAX = (1n << 256n) - 1n;
export const TINKER_MAX_POLICY_UNITS_PER_OPERATION = 10_000_000_000_000_000_000n;
export const OPERATOR_POLICY_REVIEW_MAX_LIFETIME_MS = 7 * 24 * 60 * 60 * 1_000;
export const OPERATOR_POLICY_REVIEW_FUTURE_SKEW_MS = 5 * 60 * 1_000;
export const QVL_CLIENT_TIMEOUT_SECONDS = 30;
export const QVL_CLIENT_HEADROOM_SECONDS = 5;
export const REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_EPOCH = 0xffff_ffff;

const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const BYTES32_PATTERN = /^0x[0-9a-f]{64}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const CONTROLLER_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{7,63}$/;
const UINT_PATTERN = /^(0|[1-9][0-9]{0,77})$/;
const DECIMAL_PATTERN = /^(?:0\.[0-9]{0,5}[1-9]|[1-9][0-9]{0,2}(?:\.[0-9]{0,5}[1-9])?)$/;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

const DEPLOYMENT_INTENT_TRUTH_STATUS =
  "pre_deployment_intent_not_deployment_attestation_or_runtime_authority_evidence";
const REVIEW_ENVELOPE_TRUTH_STATUS =
  "renewable_review_declaration_not_signature_key_control_deployment_or_tdx_evidence";
const REVIEW_DECLARATION =
  "out_of_band_review_collected_not_signature_verified";

function sortedObject(value) {
  if (Array.isArray(value)) return value.map((item) => sortedObject(item));
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, sortedObject(value[key])]),
  );
}

export function canonicalArtifactText(artifact) {
  return `${JSON.stringify(sortedObject(artifact), null, 2)}\n`;
}

// Transitional source-compatible spelling. It canonicalizes any supported
// artifact; it does not imply the removed v1 reviewed-packet model.
export const canonicalPacketText = canonicalArtifactText;

export function canonicalArtifactSha256(artifact) {
  return `sha256:${createHash("sha256").update(canonicalArtifactText(artifact)).digest("hex")}`;
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function boundedJsonShape(value, { maxDepth = 16, maxNodes = 2_048 } = {}) {
  const pending = [{ value, depth: 0 }];
  let nodes = 0;
  while (pending.length) {
    const current = pending.pop();
    nodes += 1;
    if (nodes > maxNodes || current.depth > maxDepth) return false;
    if (!current.value || typeof current.value !== "object") continue;
    for (const child of Array.isArray(current.value)
      ? current.value
      : Object.values(current.value)) {
      pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  return true;
}

function addError(errors, path, message) {
  if (errors.length < 96) errors.push({ path, message });
}

function exactKeys(errors, value, path, keys) {
  if (!isPlainObject(value)) {
    addError(errors, path, "must be an object");
    return false;
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    addError(errors, path, "must contain exactly the documented fields");
    return false;
  }
  return true;
}

function exactArray(errors, value, path, expected) {
  if (!Array.isArray(value) || JSON.stringify(value) !== JSON.stringify(expected)) {
    addError(errors, path, "must equal the canonical ordered list");
    return false;
  }
  return true;
}

function validAddress(value) {
  return typeof value === "string" && ADDRESS_PATTERN.test(value) && value !== ZERO_ADDRESS;
}

function requireAddress(errors, value, path) {
  if (!validAddress(value)) addError(errors, path, "must be a lowercase nonzero Ethereum address");
}

function requireBytes32(errors, value, path) {
  if (typeof value !== "string"
    || !BYTES32_PATTERN.test(value)
    || value === ZERO_BYTES32) {
    addError(errors, path, "must be a lowercase nonzero 0x-prefixed bytes32");
  }
}

function requireControllerId(errors, value, path) {
  if (typeof value !== "string" || !CONTROLLER_ID_PATTERN.test(value)) {
    addError(errors, path, "must be a public 8-64 character controller identifier");
  }
}

function requireInteger(errors, value, path, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    addError(errors, path, `must be an integer between ${minimum} and ${maximum}`);
  }
}

function requireDecimalString(errors, value, path, minimum, maximum) {
  if (typeof value !== "string" || !DECIMAL_PATTERN.test(value)) {
    addError(errors, path, "must be an explicit canonical decimal string with at most 6 fractional digits");
    return;
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum || parsed > maximum) {
    addError(errors, path, `must be between ${minimum} and ${maximum}`);
  }
}

function decimalNumber(value) {
  return typeof value === "string" && DECIMAL_PATTERN.test(value) ? Number(value) : NaN;
}

function requireUint256String(errors, value, path, { positive = false } = {}) {
  if (typeof value !== "string" || !UINT_PATTERN.test(value)) {
    addError(errors, path, "must be a canonical base-10 uint256 string");
    return;
  }
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX || (positive && parsed === 0n)) {
    addError(errors, path, positive ? "must be a positive uint256" : "must fit uint256");
  }
}

function draftQvlPolicy() {
  return {
    challengeCapacity: null,
    challengeTtlSeconds: null,
    maxConcurrency: null,
    rateCapacity: null,
    rateRefillPerSecond: null,
    requestBodyTimeoutSeconds: null,
    verificationTimeoutSeconds: null,
  };
}

function draftNumericPolicy() {
  return {
    contract: {
      computeDeveloperFeeBps: null,
      emailOracleUpgradeDelaySeconds: null,
      tinkerMaxAddBalanceWei: null,
      tinkerMaxSpendWei: null,
    },
    metering: {
      maxConcurrency: null,
      rateCapacity: null,
      rateRefillPerSecond: null,
      requestBodyTimeoutSeconds: null,
      rpcTimeoutSeconds: null,
    },
    qvl: Object.fromEntries(QVL_POLICY_KEYS.map((name) => [name, draftQvlPolicy()])),
  };
}

export function createDraftDeploymentIntentCore() {
  return {
    schema: DEPLOYMENT_INTENT_CORE_SCHEMA,
    truthStatus: DEPLOYMENT_INTENT_TRUTH_STATUS,
    network: {
      chainId: 84_532,
      name: "base-sepolia",
      canonicalUsdc: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    },
    release: {
      releaseSha: null,
      reviewerAuthorityGenesisAcceptanceSha256: null,
      reviewerAuthorityCurrentStatusEpoch: null,
      reviewerAuthorityCurrentStatusSha256: null,
      toolchain: {
        foundry: { ...DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry },
        solidity: {
          ...DEPLOYMENT_TOOLCHAIN_AUTHORITY.solidity,
          libraries: [],
        },
      },
    },
    scope: {
      contracts: [...CANONICAL_CONTRACTS],
      cvms: [...CANONICAL_CVMS],
    },
    deploymentControl: {
      controllerId: null,
      controllerKind: "encrypted_foundry_keystore_eoa",
      foundryAccount: "dev",
      operatorAddress: null,
    },
    staticContractInputs: {
      computeCreditVault: {
        developer: null,
      },
      tinkerAccountEncumbrance: {
        accountCommitment: null,
      },
    },
    numericPolicy: draftNumericPolicy(),
    dynamicRuntimeAuthorities: {
      contractAddresses: [],
      cvmIdentities: [],
      downstreamAnchorState: [],
      releaseCommitments: [],
      roleAddresses: [],
    },
  };
}

export function createDraftAuthorityReviewEnvelope(
  subjectKind = null,
  subjectSha256 = null,
) {
  const policy = subjectKind ? REVIEW_SUBJECT_POLICY[subjectKind] : null;
  if (subjectKind && !policy) throw new Error("unsupported review subject kind");
  return {
    schema: AUTHORITY_REVIEW_ENVELOPE_SCHEMA,
    truthStatus: REVIEW_ENVELOPE_TRUTH_STATUS,
    subject_kind: subjectKind,
    subject_sha256: subjectSha256,
    action_scope: policy ? [...policy.actionScope] : [],
    checkpoint: policy?.checkpoint ?? null,
    approved_at: null,
    declaration: REVIEW_DECLARATION,
    expires_at: null,
    review_evidence_sha256: null,
    reviewers: [
      { address: null, controllerId: null },
      { address: null, controllerId: null },
    ],
  };
}

function validateNetwork(errors, network, path) {
  if (!exactKeys(errors, network, path, ["canonicalUsdc", "chainId", "name"])) return;
  if (network.chainId !== 84_532) addError(errors, `${path}.chainId`, "must be Base Sepolia chain ID 84532");
  if (network.name !== "base-sepolia") addError(errors, `${path}.name`, "must be base-sepolia");
  if (network.canonicalUsdc !== "0x036cbd53842c5426634e7929541ec2318f3dcf7e") {
    addError(errors, `${path}.canonicalUsdc`, "must be the canonical Base Sepolia USDC address");
  }
}

function validateRelease(errors, release, path) {
  if (!exactKeys(errors, release, path, [
    "releaseSha",
    "reviewerAuthorityGenesisAcceptanceSha256",
    "reviewerAuthorityCurrentStatusEpoch",
    "reviewerAuthorityCurrentStatusSha256",
    "toolchain",
  ])) return;
  if (typeof release.releaseSha !== "string"
    || !SHA_PATTERN.test(release.releaseSha)
    || release.releaseSha === ZERO_SHA) {
    addError(errors, `${path}.releaseSha`, "must be an explicit lowercase nonzero 40-hex release SHA");
  }
  if (typeof release.reviewerAuthorityGenesisAcceptanceSha256 !== "string"
    || !HASH_PATTERN.test(release.reviewerAuthorityGenesisAcceptanceSha256)
    || release.reviewerAuthorityGenesisAcceptanceSha256 === `sha256:${"0".repeat(64)}`) {
    addError(
      errors,
      `${path}.reviewerAuthorityGenesisAcceptanceSha256`,
      "must bind the exact nonzero all-reviewer-signed genesis acceptance artifact digest",
    );
  }
  requireInteger(
    errors,
    release.reviewerAuthorityCurrentStatusEpoch,
    `${path}.reviewerAuthorityCurrentStatusEpoch`,
    1,
    REVIEWER_AUTHORITY_CURRENT_STATUS_MAX_EPOCH,
  );
  if (typeof release.reviewerAuthorityCurrentStatusSha256 !== "string"
    || !HASH_PATTERN.test(release.reviewerAuthorityCurrentStatusSha256)
    || release.reviewerAuthorityCurrentStatusSha256 === `sha256:${"0".repeat(64)}`) {
    addError(
      errors,
      `${path}.reviewerAuthorityCurrentStatusSha256`,
      "must bind the exact nonzero guardian-signed reviewer current-status artifact digest",
    );
  }
  if (!exactKeys(errors, release.toolchain, `${path}.toolchain`, ["foundry", "solidity"])) return;
  const foundry = release.toolchain.foundry;
  if (exactKeys(errors, foundry, `${path}.toolchain.foundry`, [
    "buildProfile",
    "castExecutableSha256",
    "castVersion",
    "commitSha",
    "forgeVersion",
  ])) {
    for (const [key, expected] of Object.entries(DEPLOYMENT_TOOLCHAIN_AUTHORITY.foundry)) {
      if (foundry[key] !== expected) {
        addError(errors, `${path}.toolchain.foundry.${key}`, `must equal the supported release toolchain value ${expected}`);
      }
    }
  }
  const solidity = release.toolchain.solidity;
  if (exactKeys(errors, solidity, `${path}.toolchain.solidity`, [
    "bytecodeHash",
    "cborMetadata",
    "compilerVersion",
    "configuredVersion",
    "evmVersion",
    "libraries",
    "optimizer",
    "optimizerRuns",
    "profile",
    "useLiteralContent",
    "viaIr",
  ])) {
    for (const [key, expected] of Object.entries(DEPLOYMENT_TOOLCHAIN_AUTHORITY.solidity)) {
      if (Array.isArray(expected)) {
        if (!Array.isArray(solidity[key]) || solidity[key].length !== 0) {
          addError(errors, `${path}.toolchain.solidity.${key}`, "must be the supported empty library-linking set");
        }
      } else if (solidity[key] !== expected) {
        addError(errors, `${path}.toolchain.solidity.${key}`, `must equal the supported release compilation value ${expected}`);
      }
    }
  }
}

function validateScope(errors, scope, path) {
  if (!exactKeys(errors, scope, path, ["contracts", "cvms"])) return;
  exactArray(errors, scope.contracts, `${path}.contracts`, CANONICAL_CONTRACTS);
  exactArray(errors, scope.cvms, `${path}.cvms`, CANONICAL_CVMS);
}

function validateStaticContractInputs(errors, inputs, path) {
  if (!exactKeys(errors, inputs, path, [
    "computeCreditVault",
    "tinkerAccountEncumbrance",
  ])) return;
  if (exactKeys(errors, inputs.computeCreditVault, `${path}.computeCreditVault`, [
    "developer",
  ])) {
    requireAddress(
      errors,
      inputs.computeCreditVault.developer,
      `${path}.computeCreditVault.developer`,
    );
  }
  if (exactKeys(
    errors,
    inputs.tinkerAccountEncumbrance,
    `${path}.tinkerAccountEncumbrance`,
    ["accountCommitment"],
  )) {
    requireBytes32(
      errors,
      inputs.tinkerAccountEncumbrance.accountCommitment,
      `${path}.tinkerAccountEncumbrance.accountCommitment`,
    );
  }
}

function validateQvlPolicy(errors, policy, path) {
  if (!exactKeys(errors, policy, path, [
    "challengeCapacity",
    "challengeTtlSeconds",
    "maxConcurrency",
    "rateCapacity",
    "rateRefillPerSecond",
    "requestBodyTimeoutSeconds",
    "verificationTimeoutSeconds",
  ])) return;
  requireInteger(errors, policy.challengeCapacity, `${path}.challengeCapacity`, 16, 65_536);
  requireInteger(errors, policy.challengeTtlSeconds, `${path}.challengeTtlSeconds`, 10, 120);
  requireInteger(errors, policy.maxConcurrency, `${path}.maxConcurrency`, 1, 16);
  requireInteger(errors, policy.rateCapacity, `${path}.rateCapacity`, 1, 600);
  requireDecimalString(errors, policy.rateRefillPerSecond, `${path}.rateRefillPerSecond`, Number.MIN_VALUE, 100);
  requireDecimalString(errors, policy.requestBodyTimeoutSeconds, `${path}.requestBodyTimeoutSeconds`, 0.5, 15);
  requireDecimalString(errors, policy.verificationTimeoutSeconds, `${path}.verificationTimeoutSeconds`, 1, 60);
  const phaseBudget = decimalNumber(policy.requestBodyTimeoutSeconds)
    + decimalNumber(policy.verificationTimeoutSeconds);
  if (Number.isFinite(phaseBudget)
    && phaseBudget > QVL_CLIENT_TIMEOUT_SECONDS - QVL_CLIENT_HEADROOM_SECONDS) {
    addError(errors, path, "body plus verification timeouts must be at most 25 seconds");
  }
  if (Number.isFinite(phaseBudget)
    && Number.isSafeInteger(policy.challengeTtlSeconds)
    && policy.challengeTtlSeconds < Math.ceil(phaseBudget) + QVL_CLIENT_HEADROOM_SECONDS) {
    addError(errors, `${path}.challengeTtlSeconds`, "must cover both server phases plus the five-second client headroom");
  }
}

function validateNumericPolicy(errors, numericPolicy, path) {
  if (!exactKeys(errors, numericPolicy, path, ["contract", "metering", "qvl"])) return;
  const contract = numericPolicy.contract;
  if (exactKeys(errors, contract, `${path}.contract`, [
    "computeDeveloperFeeBps",
    "emailOracleUpgradeDelaySeconds",
    "tinkerMaxAddBalanceWei",
    "tinkerMaxSpendWei",
  ])) {
    requireInteger(errors, contract.computeDeveloperFeeBps, `${path}.contract.computeDeveloperFeeBps`, 0, 2_000);
    requireInteger(errors, contract.emailOracleUpgradeDelaySeconds, `${path}.contract.emailOracleUpgradeDelaySeconds`, 172_800, 31_536_000);
    requireUint256String(errors, contract.tinkerMaxAddBalanceWei, `${path}.contract.tinkerMaxAddBalanceWei`, { positive: true });
    requireUint256String(errors, contract.tinkerMaxSpendWei, `${path}.contract.tinkerMaxSpendWei`, { positive: true });
    if (UINT_PATTERN.test(contract.tinkerMaxAddBalanceWei || "")
      && BigInt(contract.tinkerMaxAddBalanceWei) > TINKER_MAX_POLICY_UNITS_PER_OPERATION) {
      addError(errors, `${path}.contract.tinkerMaxAddBalanceWei`, `must not exceed ${TINKER_MAX_POLICY_UNITS_PER_OPERATION} policy units per operation`);
    }
    if (UINT_PATTERN.test(contract.tinkerMaxSpendWei || "")
      && BigInt(contract.tinkerMaxSpendWei) > TINKER_MAX_POLICY_UNITS_PER_OPERATION) {
      addError(errors, `${path}.contract.tinkerMaxSpendWei`, `must not exceed ${TINKER_MAX_POLICY_UNITS_PER_OPERATION} policy units per operation`);
    }
    if (UINT_PATTERN.test(contract.tinkerMaxAddBalanceWei || "")
      && UINT_PATTERN.test(contract.tinkerMaxSpendWei || "")
      && BigInt(contract.tinkerMaxSpendWei) > BigInt(contract.tinkerMaxAddBalanceWei)) {
      addError(errors, `${path}.contract.tinkerMaxSpendWei`, "must not exceed the reviewed add-balance cap");
    }
  }
  const metering = numericPolicy.metering;
  if (exactKeys(errors, metering, `${path}.metering`, [
    "maxConcurrency",
    "rateCapacity",
    "rateRefillPerSecond",
    "requestBodyTimeoutSeconds",
    "rpcTimeoutSeconds",
  ])) {
    requireInteger(errors, metering.maxConcurrency, `${path}.metering.maxConcurrency`, 1, 16);
    requireInteger(errors, metering.rateCapacity, `${path}.metering.rateCapacity`, 1, 600);
    requireDecimalString(errors, metering.rateRefillPerSecond, `${path}.metering.rateRefillPerSecond`, Number.MIN_VALUE, 100);
    requireDecimalString(errors, metering.requestBodyTimeoutSeconds, `${path}.metering.requestBodyTimeoutSeconds`, 0.5, 15);
    requireDecimalString(errors, metering.rpcTimeoutSeconds, `${path}.metering.rpcTimeoutSeconds`, 1, 30);
  }
  if (exactKeys(errors, numericPolicy.qvl, `${path}.qvl`, QVL_POLICY_KEYS)) {
    for (const name of QVL_POLICY_KEYS) validateQvlPolicy(errors, numericPolicy.qvl[name], `${path}.qvl.${name}`);
    const policies = QVL_POLICY_KEYS.map((name) => JSON.stringify(numericPolicy.qvl[name]));
    if (new Set(policies).size !== 1) {
      addError(errors, `${path}.qvl`, "all five isolated QVLs must use the same reviewed numeric request budget");
    }
  }
}

export function validateDeploymentIntentCore(intent) {
  const errors = [];
  if (!exactKeys(errors, intent, "$", [
    "schema",
    "truthStatus",
    "network",
    "release",
    "scope",
    "deploymentControl",
    "staticContractInputs",
    "numericPolicy",
    "dynamicRuntimeAuthorities",
  ])) return { ok: false, errors };
  if (intent.schema !== DEPLOYMENT_INTENT_CORE_SCHEMA) addError(errors, "$.schema", "must be the supported deployment-intent schema");
  if (intent.truthStatus !== DEPLOYMENT_INTENT_TRUTH_STATUS) addError(errors, "$.truthStatus", "must preserve the non-evidence truth label");
  validateNetwork(errors, intent.network, "$.network");
  validateRelease(errors, intent.release, "$.release");
  validateScope(errors, intent.scope, "$.scope");
  validateStaticContractInputs(
    errors,
    intent.staticContractInputs,
    "$.staticContractInputs",
  );
  if (exactKeys(errors, intent.deploymentControl, "$.deploymentControl", [
    "controllerId",
    "controllerKind",
    "foundryAccount",
    "operatorAddress",
  ])) {
    requireControllerId(errors, intent.deploymentControl.controllerId, "$.deploymentControl.controllerId");
    requireAddress(errors, intent.deploymentControl.operatorAddress, "$.deploymentControl.operatorAddress");
    if (intent.deploymentControl.controllerKind !== "encrypted_foundry_keystore_eoa") {
      addError(errors, "$.deploymentControl.controllerKind", "must match the encrypted Foundry keystore deployment path");
    }
    if (intent.deploymentControl.foundryAccount !== "dev") {
      addError(errors, "$.deploymentControl.foundryAccount", "must name the supported encrypted Foundry account dev");
    }
  }
  validateNumericPolicy(errors, intent.numericPolicy, "$.numericPolicy");
  if (exactKeys(errors, intent.dynamicRuntimeAuthorities, "$.dynamicRuntimeAuthorities", [
    "contractAddresses",
    "cvmIdentities",
    "downstreamAnchorState",
    "releaseCommitments",
    "roleAddresses",
  ])) {
    for (const name of [
      "contractAddresses",
      "cvmIdentities",
      "downstreamAnchorState",
      "releaseCommitments",
      "roleAddresses",
    ]) {
      if (!Array.isArray(intent.dynamicRuntimeAuthorities[name])
        || intent.dynamicRuntimeAuthorities[name].length !== 0) {
        addError(errors, `$.dynamicRuntimeAuthorities.${name}`, "must be an explicit empty array before deployment");
      }
    }
  }
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    errors: [],
    receipt: {
      schema: DEPLOYMENT_INTENT_RECEIPT_SCHEMA,
      status: "valid",
      truthStatus: "intent_shape_and_bounds_validated_not_signer_control_deployment_or_tdx",
      deploymentIntentSha256: canonicalArtifactSha256(intent),
      releaseSha: intent.release.releaseSha,
      chainId: intent.network.chainId,
      reviewerAuthorityCurrentStatusEpoch:
        intent.release.reviewerAuthorityCurrentStatusEpoch,
      reviewerAuthorityCurrentStatusSha256:
        intent.release.reviewerAuthorityCurrentStatusSha256,
      canonicalContractCount: CANONICAL_CONTRACTS.length,
      canonicalCvmCount: CANONICAL_CVMS.length,
      dynamicRuntimeAuthorityCount: 0,
      qvlNumericPolicyCount: QVL_POLICY_KEYS.length,
      staticContractInputCount: 2,
    },
  };
}

export function deploymentIntentReviewerAuthorityCurrentStatusBinding(intent) {
  const validation = validateDeploymentIntentCore(intent);
  if (!validation.ok) {
    throw new TypeError(
      "deployment intent must be a valid v6 artifact before projecting its reviewer current-status binding",
    );
  }
  return Object.freeze({
    reviewerAuthorityCurrentStatusEpoch:
      intent.release.reviewerAuthorityCurrentStatusEpoch,
    reviewerAuthorityCurrentStatusSha256:
      intent.release.reviewerAuthorityCurrentStatusSha256,
  });
}

export function parseCanonicalArtifactText(text, { label = "artifact" } = {}) {
  const valueText = String(text);
  const bytes = Buffer.byteLength(valueText, "utf8");
  if (bytes === 0 || bytes > MAX_PACKET_BYTES) {
    return { ok: false, errors: [{ path: "$", message: `${label} must be between 1 and ${MAX_PACKET_BYTES} UTF-8 bytes` }] };
  }
  let artifact;
  try {
    artifact = JSON.parse(valueText);
  } catch {
    return { ok: false, errors: [{ path: "$", message: `${label} must be valid JSON` }] };
  }
  if (!boundedJsonShape(artifact)) {
    return { ok: false, errors: [{ path: "$", message: `${label} nesting or node count exceeds the bounded schema` }] };
  }
  if (valueText !== canonicalArtifactText(artifact)) {
    return { ok: false, errors: [{ path: "$", message: `${label} must use canonical sorted two-space JSON with one trailing newline` }] };
  }
  return { ok: true, artifact };
}

export function parseDeploymentIntentCoreText(text) {
  const parsed = parseCanonicalArtifactText(text, { label: "deployment intent" });
  if (!parsed.ok) return parsed;
  const validation = validateDeploymentIntentCore(parsed.artifact);
  return validation.ok ? { ...validation, intent: parsed.artifact } : validation;
}

export function parseFreshContractDeploymentReceiptText(text, {
  expectedDeploymentIntentSha256,
  expectedReviewerAuthorityGenesisAcceptanceSha256,
} = {}) {
  const parsed = parseCanonicalArtifactText(text, {
    label: "fresh-contract deployment receipt",
  });
  if (!parsed.ok) return parsed;
  let receipt;
  try {
    receipt = normalizeFreshContractDeploymentReceipt(parsed.artifact, {
      expectedDeploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256,
    });
  } catch (error) {
    return {
      ok: false,
      errors: [{
        path: "$",
        message: `fresh-contract deployment receipt failed semantic validation: ${String(error?.message || "invalid receipt").replace(/[\r\n]+/g, " ").slice(0, 180)}`,
      }],
    };
  }
  if (String(text) !== canonicalArtifactText(receipt)) {
    return {
      ok: false,
      errors: [{
        path: "$",
        message: "fresh-contract deployment receipt must use its authoritative normalized canonical serialization",
      }],
    };
  }
  return {
    ok: true,
    receipt,
    receiptSha256: `sha256:${freshContractDeploymentReceiptDigest(receipt, {
      expectedDeploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256,
    })}`,
  };
}

export function describeAuthorityReviewSubjectText(text) {
  const parsed = parseCanonicalArtifactText(text, { label: "review subject" });
  if (!parsed.ok) return parsed;
  const schema = parsed.artifact?.schema;
  const entry = Object.entries(REVIEW_SUBJECT_POLICY)
    .find(([, policy]) => policy.schema === schema);
  if (!entry) {
    return { ok: false, errors: [{ path: "$.schema", message: "must be a supported review-subject schema" }] };
  }
  const [subjectKind] = entry;
  let subject = parsed.artifact;
  let subjectSha256;
  let semanticValidation;
  if (subjectKind === "deployment_intent") {
    const validation = validateDeploymentIntentCore(parsed.artifact);
    if (!validation.ok) return validation;
    subjectSha256 = canonicalArtifactSha256(parsed.artifact);
    semanticValidation = "deployment_intent_validated";
  } else if (subjectKind === "cvm_launch_intent") {
    try {
      subject = normalizeCvmLaunchIntentCore(parsed.artifact);
    } catch (error) {
      return {
        ok: false,
        errors: [{
          path: "$",
          message: `CVM launch intent subject failed semantic validation: ${String(error?.message || "invalid core").replace(/[\r\n]+/g, " ").slice(0, 180)}`,
        }],
      };
    }
    if (String(text) !== canonicalCvmLaunchIntentCoreArtifactText(subject)) {
      return {
        ok: false,
        errors: [{
          path: "$",
          message: "CVM launch intent subject must use its authoritative normalized canonical serialization",
        }],
      };
    }
    subjectSha256 = `sha256:${cvmLaunchIntentCoreDigest(subject)}`;
    semanticValidation = "cvm_launch_intent_validated";
  } else {
    try {
      subject = normalizeFinalReleaseAuthorityCore(parsed.artifact);
    } catch (error) {
      return {
        ok: false,
        errors: [{
          path: "$",
          message: `final authority subject failed semantic validation: ${String(error?.message || "invalid core").replace(/[\r\n]+/g, " ").slice(0, 180)}`,
        }],
      };
    }
    if (String(text) !== canonicalFinalReleaseAuthorityCoreArtifactText(subject)) {
      return {
        ok: false,
        errors: [{
          path: "$",
          message: "final authority subject must use its authoritative normalized canonical serialization",
        }],
      };
    }
    subjectSha256 = `sha256:${finalReleaseAuthorityCoreDigest(subject)}`;
    semanticValidation = "final_release_authority_validated";
  }
  return {
    ok: true,
    subject,
    subjectKind,
    subjectSchema: schema,
    subjectSha256,
    semanticValidation,
  };
}

function canonicalUtcTimestamp(value) {
  if (typeof value !== "string" || !UTC_TIMESTAMP_PATTERN.test(value)) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().replace(".000Z", "Z") === value ? date : null;
}

function collectOccupiedIdentities(subject) {
  const addresses = new Set();
  const controllerIds = new Set();
  const pending = [subject];
  while (pending.length) {
    const value = pending.pop();
    if (Array.isArray(value)) {
      pending.push(...value);
      continue;
    }
    if (!isPlainObject(value)) continue;
    for (const [key, child] of Object.entries(value)) {
      if (validAddress(child)) addresses.add(child);
      if ((key === "controllerId" || key === "controller_id")
        && typeof child === "string" && CONTROLLER_ID_PATTERN.test(child)) {
        controllerIds.add(child);
      }
      if (child && typeof child === "object") pending.push(child);
    }
  }
  return { addresses, controllerIds };
}

function validateAuthorityDependencies(subjectDescriptor, authorityDependencies, errors) {
  const kind = subjectDescriptor?.subjectKind;
  if (kind === "deployment_intent") {
    if (authorityDependencies !== undefined
      && (!isPlainObject(authorityDependencies)
        || Object.keys(authorityDependencies).length !== 0)) {
      addError(
        errors,
        "$options.authorityDependencies",
        "deployment-intent review must not accept downstream authority dependencies",
      );
    }
    return [];
  }
  const requiredKeys = kind === "cvm_launch_intent"
    ? ["deploymentIntent", "freshContractDeploymentReceipt"]
    : kind === "final_release_authority"
      ? ["deploymentIntent", "cvmLaunchIntent"]
      : [];
  if (!isPlainObject(authorityDependencies)) {
    addError(
      errors,
      "$options.authorityDependencies",
      `must contain the exact validated dependencies for ${kind || "the review subject"}`,
    );
    return [];
  }
  const actualKeys = Object.keys(authorityDependencies).sort();
  const expectedKeys = [...requiredKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    addError(
      errors,
      "$options.authorityDependencies",
      `must contain exactly ${expectedKeys.join(" and ")}`,
    );
    return [];
  }

  const deploymentIntent = authorityDependencies.deploymentIntent;
  const deploymentValidation = validateDeploymentIntentCore(deploymentIntent);
  if (!deploymentValidation.ok) {
    addError(
      errors,
      "$options.authorityDependencies.deploymentIntent",
      "must be a semantically valid deployment intent",
    );
    return [];
  }
  const deploymentIntentSha256 = canonicalArtifactSha256(deploymentIntent);
  const reviewedSubject = subjectDescriptor?.subject;
  if (reviewedSubject?.deployment_intent_sha256 !== deploymentIntentSha256
    || reviewedSubject?.release_sha !== deploymentIntent.release.releaseSha) {
    addError(
      errors,
      "$options.authorityDependencies.deploymentIntent",
      "digest and release must match the reviewed subject",
    );
  }

  if (kind === "cvm_launch_intent") {
    const freshReceiptAuthorityPins = {
      expectedDeploymentIntentSha256: deploymentIntentSha256,
      expectedReviewerAuthorityGenesisAcceptanceSha256:
        deploymentIntent.release.reviewerAuthorityGenesisAcceptanceSha256,
    };
    let receipt;
    try {
      receipt = normalizeFreshContractDeploymentReceipt(
        authorityDependencies.freshContractDeploymentReceipt,
        freshReceiptAuthorityPins,
      );
    } catch {
      addError(
        errors,
        "$options.authorityDependencies.freshContractDeploymentReceipt",
        "must be a semantically valid fresh-contract deployment receipt",
      );
      return [deploymentIntent];
    }
    const receiptSha256 = `sha256:${freshContractDeploymentReceiptDigest(
      receipt,
      freshReceiptAuthorityPins,
    )}`;
    if (reviewedSubject?.contract_deployment_receipt_sha256 !== receiptSha256
      || receipt.release_sha !== deploymentIntent.release.releaseSha
      || receipt.deployment_intent_sha256 !== deploymentIntentSha256
      || receipt.operator_address !== deploymentIntent.deploymentControl.operatorAddress) {
      addError(
        errors,
        "$options.authorityDependencies.freshContractDeploymentReceipt",
        "digest, release, intent, and deployment operator must match the reviewed launch subject",
      );
    }
    return [deploymentIntent, receipt];
  }

  let launchIntent;
  try {
    launchIntent = normalizeCvmLaunchIntentCore(authorityDependencies.cvmLaunchIntent);
  } catch {
    addError(
      errors,
      "$options.authorityDependencies.cvmLaunchIntent",
      "must be a semantically valid CVM launch intent",
    );
    return [deploymentIntent];
  }
  const launchIntentSha256 = `sha256:${cvmLaunchIntentCoreDigest(launchIntent)}`;
  if (reviewedSubject?.cvm_launch_intent_sha256 !== launchIntentSha256
    || launchIntent.deployment_intent_sha256 !== deploymentIntentSha256
    || launchIntent.release_sha !== deploymentIntent.release.releaseSha) {
    addError(
      errors,
      "$options.authorityDependencies.cvmLaunchIntent",
      "digest, release, and deployment-intent binding must match the reviewed final authority",
    );
  }
  if (reviewedSubject?.operator_address !== deploymentIntent.deploymentControl.operatorAddress
    || reviewedSubject?.contracts?.compute_credit_vault?.developer
      !== deploymentIntent.staticContractInputs.computeCreditVault.developer
    || reviewedSubject?.contracts?.tinker_account_encumbrance?.account_commitment
      !== deploymentIntent.staticContractInputs.tinkerAccountEncumbrance.accountCommitment
    || reviewedSubject?.contracts?.compute_credit_vault?.developer_fee_bps
      !== deploymentIntent.numericPolicy.contract.computeDeveloperFeeBps
    || reviewedSubject?.contracts?.email_oracle_auth?.upgrade_delay_seconds
      !== deploymentIntent.numericPolicy.contract.emailOracleUpgradeDelaySeconds
    || reviewedSubject?.contracts?.tinker_account_encumbrance?.max_add_balance_wei
      !== deploymentIntent.numericPolicy.contract.tinkerMaxAddBalanceWei
    || reviewedSubject?.contracts?.tinker_account_encumbrance?.max_spend_wei
      !== deploymentIntent.numericPolicy.contract.tinkerMaxSpendWei) {
    addError(
      errors,
      "$options.authorityDependencies.deploymentIntent",
      "operator, static constructor inputs, and contract numeric policy must match the reviewed final authority",
    );
  }
  return [deploymentIntent, launchIntent];
}

export function validateAuthorityReviewEnvelope(envelope, {
  checkedAtMs,
  subjectDescriptor,
  authorityDependencies,
} = {}) {
  const errors = [];
  if (!exactKeys(errors, envelope, "$", [
    "schema",
    "truthStatus",
    "subject_kind",
    "subject_sha256",
    "action_scope",
    "checkpoint",
    "approved_at",
    "declaration",
    "expires_at",
    "review_evidence_sha256",
    "reviewers",
  ])) return { ok: false, errors };
  const hasExplicitCheckedAtMs = Number.isFinite(checkedAtMs);
  if (!hasExplicitCheckedAtMs) {
    addError(
      errors,
      "$options.checkedAtMs",
      "must be supplied explicitly as a finite caller-observed Unix time in milliseconds",
    );
  }
  if (envelope.schema !== AUTHORITY_REVIEW_ENVELOPE_SCHEMA) addError(errors, "$.schema", "must be the supported review-envelope schema");
  if (envelope.truthStatus !== REVIEW_ENVELOPE_TRUTH_STATUS) addError(errors, "$.truthStatus", "must preserve the renewable non-evidence truth label");
  const policy = REVIEW_SUBJECT_POLICY[envelope.subject_kind];
  if (!policy) {
    addError(errors, "$.subject_kind", "must identify deployment_intent, cvm_launch_intent, or final_release_authority");
  } else {
    exactArray(errors, envelope.action_scope, "$.action_scope", policy.actionScope);
    if (envelope.checkpoint !== policy.checkpoint) addError(errors, "$.checkpoint", "must equal the canonical checkpoint for the subject kind");
  }
  if (typeof envelope.subject_sha256 !== "string"
    || !HASH_PATTERN.test(envelope.subject_sha256)
    || envelope.subject_sha256 === `sha256:${"0".repeat(64)}`) {
    addError(errors, "$.subject_sha256", "must be a nonzero canonical sha256 digest");
  }
  if (!subjectDescriptor?.ok) {
    addError(errors, "$.subject_sha256", "must be checked against the exact canonical subject bytes");
  } else {
    if (envelope.subject_kind !== subjectDescriptor.subjectKind) addError(errors, "$.subject_kind", "does not match the supplied subject schema");
    if (envelope.subject_sha256 !== subjectDescriptor.subjectSha256) addError(errors, "$.subject_sha256", "does not match the supplied canonical subject bytes");
  }
  const approvedAt = canonicalUtcTimestamp(envelope.approved_at);
  const expiresAt = canonicalUtcTimestamp(envelope.expires_at);
  if (!approvedAt) addError(errors, "$.approved_at", "must be an exact UTC timestamp with second precision");
  if (!expiresAt) addError(errors, "$.expires_at", "must be an exact UTC timestamp with second precision");
  if (approvedAt && expiresAt) {
    const lifetime = expiresAt.getTime() - approvedAt.getTime();
    if (lifetime <= 0 || lifetime > OPERATOR_POLICY_REVIEW_MAX_LIFETIME_MS) {
      addError(errors, "$.expires_at", "must be after approval and no more than seven days later");
    }
    if (hasExplicitCheckedAtMs
      && approvedAt.getTime() > checkedAtMs + OPERATOR_POLICY_REVIEW_FUTURE_SKEW_MS) {
      addError(errors, "$.approved_at", "must not be more than five minutes in the future");
    }
    if (hasExplicitCheckedAtMs && expiresAt.getTime() <= checkedAtMs) {
      addError(errors, "$.expires_at", "must still be active when checked");
    }
  }
  if (envelope.declaration !== REVIEW_DECLARATION) {
    addError(errors, "$.declaration", "must preserve the out-of-band, not-signature-verified declaration");
  }
  if (typeof envelope.review_evidence_sha256 !== "string"
    || !HASH_PATTERN.test(envelope.review_evidence_sha256)
    || envelope.review_evidence_sha256 === `sha256:${"0".repeat(64)}`) {
    addError(errors, "$.review_evidence_sha256", "must be a nonzero sha256 digest of public review evidence");
  }
  const reviewerAddresses = [];
  const reviewerControllerIds = [];
  if (!Array.isArray(envelope.reviewers) || envelope.reviewers.length !== 2) {
    addError(errors, "$.reviewers", "must contain exactly two independent review declarations");
  } else {
    envelope.reviewers.forEach((reviewer, index) => {
      const path = `$.reviewers[${index}]`;
      if (!exactKeys(errors, reviewer, path, ["address", "controllerId"])) return;
      requireAddress(errors, reviewer.address, `${path}.address`);
      requireControllerId(errors, reviewer.controllerId, `${path}.controllerId`);
      reviewerAddresses.push(reviewer.address);
      reviewerControllerIds.push(reviewer.controllerId);
    });
    const ordered = [...envelope.reviewers].sort((left, right) => (
      `${left?.controllerId || ""}\0${left?.address || ""}`
        .localeCompare(`${right?.controllerId || ""}\0${right?.address || ""}`)
    ));
    if (JSON.stringify(ordered) !== JSON.stringify(envelope.reviewers)) {
      addError(errors, "$.reviewers", "must use canonical controller-id then address order");
    }
  }
  if (new Set(reviewerAddresses).size !== reviewerAddresses.length
    || new Set(reviewerControllerIds).size !== reviewerControllerIds.length) {
    addError(errors, "$.reviewers", "reviewers must use distinct addresses and controller identifiers");
  }
  const occupiedIdentitySubjects = subjectDescriptor?.subject
    ? [
      subjectDescriptor.subject,
      ...validateAuthorityDependencies(subjectDescriptor, authorityDependencies, errors),
    ]
    : [];
  if (occupiedIdentitySubjects.length) {
    const occupied = { addresses: new Set(), controllerIds: new Set() };
    for (const identitySubject of occupiedIdentitySubjects) {
      const subjectIdentities = collectOccupiedIdentities(identitySubject);
      for (const value of subjectIdentities.addresses) occupied.addresses.add(value);
      for (const value of subjectIdentities.controllerIds) occupied.controllerIds.add(value);
    }
    if (reviewerAddresses.some((value) => occupied.addresses.has(value))) {
      addError(errors, "$.reviewers", "reviewers must not reuse an address in the reviewed subject or its validated authority dependencies");
    }
    if (reviewerControllerIds.some((value) => occupied.controllerIds.has(value))) {
      addError(errors, "$.reviewers", "reviewers must not reuse a controller identifier in the reviewed subject or its validated authority dependencies");
    }
  }
  if (errors.length) return { ok: false, errors };
  return {
    ok: true,
    errors: [],
    receipt: {
      schema: AUTHORITY_REVIEW_RECEIPT_SCHEMA,
      status: "valid",
      truthStatus: "canonical_subject_binding_and_review_declarations_validated_not_signatures_key_control_deployment_or_tdx",
      subjectKind: envelope.subject_kind,
      subjectSha256: envelope.subject_sha256,
      reviewEnvelopeSha256: canonicalArtifactSha256(envelope),
      reviewEvidenceSha256: envelope.review_evidence_sha256,
      checkpoint: envelope.checkpoint,
      actionScopeCount: envelope.action_scope.length,
      reviewerDeclarationCount: 2,
      subjectSemanticValidation: subjectDescriptor.semanticValidation,
    },
  };
}

export function parseAuthorityReviewEnvelopeText(text, options = {}) {
  const parsed = parseCanonicalArtifactText(text, { label: "authority review envelope" });
  if (!parsed.ok) return parsed;
  const validation = validateAuthorityReviewEnvelope(parsed.artifact, options);
  return validation.ok ? { ...validation, envelope: parsed.artifact } : validation;
}

export function validationErrorDocument(errors) {
  return {
    schema: OPERATOR_POLICY_ERROR_SCHEMA,
    status: "invalid",
    truthStatus: "no_deployment_or_activation_authority_created",
    errors: (Array.isArray(errors) ? errors : []).slice(0, 96).map((error) => ({
      path: String(error?.path || "$ ").trim().slice(0, 160),
      message: String(error?.message || "invalid artifact").replace(/[\r\n]+/g, " ").slice(0, 240),
    })),
  };
}

// The reviewed v1 packet is intentionally unsupported. These transitional
// exports keep parallel callers loadable while making any attempted use fail
// closed until they migrate to intent + final-authority + review-envelope.
export function parseOperatorPolicyPacketText() {
  return {
    ok: false,
    errors: [{ path: "$.schema", message: "reviewed operator-policy packets are retired; use the staged authority artifacts" }],
  };
}

export function projectOperatorPolicyPacket() {
  throw new Error("reviewed operator-policy packet projection is retired");
}

export function validateOperatorPolicyEnvironmentProjection() {
  return { ok: false, checkedKeys: [], mismatchKeys: ["retired_operator_policy_packet"] };
}

export function validateOperatorPolicyReleaseProjection() {
  return { ok: false, mismatchFields: ["retired_operator_policy_packet"] };
}
