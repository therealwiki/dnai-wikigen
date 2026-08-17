import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  parseAbi,
  toHex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  __test,
  assertLiveActivationFinalCvmsMatchCandidate,
  assertLiveReleaseCandidateMatchesPrebuild,
  arenaReleaseApprovedChallengeSetSha256,
  buildReleaseEnv,
  canonicalLiveReleaseCandidatePrebuildProjectionText,
  canonicalPreLiveActivationReleaseCandidateText,
  githubAttestationCommands,
  liveReleaseCandidatePrebuildProjectionSha256,
  normalizePreLiveActivationReleaseCandidate,
  normalizeReleaseCandidate,
  projectLiveReleaseCandidateToPrebuild,
  serializeEnv,
  validateDeploymentEvidence,
} from "./release-env-core.mjs";

const NOW = 2_000_000;
const PRIMARY_RPC_URL = "https://sepolia.base.org";
const SECONDARY_RPC_URL = "https://base-sepolia-rpc.publicnode.com";
const FRESH_SUITE_MANIFEST_FILTER = fileURLToPath(new URL(
  "../../⚙️/tinker-delegate/contracts/scripts/merge-base-sepolia-suite-manifest.jq",
  import.meta.url,
));
const RELEASE_MANIFEST_PATH = fileURLToPath(new URL(
  "../RELEASE-MANIFEST.md",
  import.meta.url,
));
const SHA = "a".repeat(40);
const OPERATOR = "0x1000000000000000000000000000000000000001";
const DILIGENCE_GOVERNANCE = "0x1100000000000000000000000000000000000011";
const RESULT_VERIFIER = "0x2000000000000000000000000000000000000002";
const TEE = "0x3000000000000000000000000000000000000003";
const DILIGENCE = "0x4000000000000000000000000000000000000004";
const CHALLENGE = "0x5000000000000000000000000000000000000005";
const ROYALTY = "0x6000000000000000000000000000000000000006";
const ENCUMBRANCE = "0x7000000000000000000000000000000000000007";
const EMAIL = "0x8000000000000000000000000000000000000008";
const COMPUTE = "0x9000000000000000000000000000000000000009";
const COMPUTE_DEVELOPER = "0xa00000000000000000000000000000000000000a";
const COMPUTE_METERING_VERIFIER = "0xb00000000000000000000000000000000000000b";
const COMPUTE_PROVIDER = "0xc00000000000000000000000000000000000000c";
const COMPUTE_ERC20_PROVIDER = "0xc00000000000000000000000000000000000000d";
const EXECUTION_POLICY_ANCHOR = "0xd00000000000000000000000000000000000000d";
const EXECUTION_POLICY_WRITER = "0xe00000000000000000000000000000000000000e";
const KMS = "0xf100000000000000000000000000000000000001";
const KMS_IMPLEMENTATION = "0xf200000000000000000000000000000000000002";
const BOOT_INSTANCE = "0xf300000000000000000000000000000000000003";
const USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const COMPOSE = "b".repeat(64);
const LOCAL_COMPOSE = "f".repeat(64);
const RENDERED_COMPOSE = "a1".repeat(32);
const OS_IMAGE = "c".repeat(64);
const ACCOUNT_COMMITMENT = `0x${"d".repeat(64)}`;
const TINKER_MAX_ADD_BALANCE_WEI = "1000000000000000000";
const TINKER_MAX_SPEND_WEI = "250000000000000000";
const TINKER_COMPOSE_ROOT = `0x${"31".repeat(32)}`;
const TINKER_MANAGER_ROOT = `0x${"32".repeat(32)}`;
const TINKER_RELEASE_POLICY = `0x${"33".repeat(32)}`;
const DILIGENCE_EVALUATOR_POLICIES = Object.freeze([
  `0x${"b4".repeat(32)}`,
  `0x${"b5".repeat(32)}`,
  `0x${"b6".repeat(32)}`,
]);
const DILIGENCE_EVALUATOR_POLICY_SET_ROOT = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "bytes32[3]" }],
  [
    keccak256(toHex(
      "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)",
    )),
    DILIGENCE_EVALUATOR_POLICIES,
  ],
));
const TINKER_EMPTY_COMPOSE_ROOT = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "bytes32[]" }],
  [keccak256(toHex("TinkerComposeSet(bytes32[] composeHashes)")), []],
));
const TINKER_EMPTY_MANAGER_ROOT = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "address[]" }],
  [keccak256(toHex("TinkerManagerSet(address[] managers)")), []],
));
const TINKER_DEPLOYMENT_TX = `0x${"2".repeat(64)}`;
const TINKER_PHASE_ONE_TX = `0x${"8".repeat(64)}`;
const TINKER_PHASE_TWO_TX = `0x${"9".repeat(64)}`;
const TINKER_PHASE_ONE_SOURCE = "b".repeat(40);
const TINKER_PHASE_TWO_SOURCE = "c".repeat(40);
const TINKER_PHASE_ONE_BLOCK = 20_000;
const TINKER_PHASE_TWO_BLOCK = 30_000;
const TINKER_PHASE_ONE_RECORDED_AT = "2026-07-13T00:00:01Z";
const TINKER_PHASE_TWO_RECORDED_AT = "2026-07-15T00:00:01Z";
const TINKER_REVIEW_ELIGIBLE_AT = 1_784_073_600;
const NATIVE_RATE_POLICY = `0x${"4".repeat(64)}`;
const ERC20_RATE_POLICY = `0x${"5".repeat(64)}`;
const ARENA_MANIFEST = "e".repeat(64);
const ARENA_SEALED = `0x${"7".repeat(64)}`;
const ARENA_EVALUATOR = `0x${"8".repeat(64)}`;
const ARENA_POLICY = `0x${"9".repeat(64)}`;
const DILIGENCE_QVL_POLICY = `0x${"10".repeat(32)}`;
const ARENA_QVL_POLICY = `0x${"11".repeat(32)}`;
const ANCHOR_WRITER_QVL_POLICY = `0x${"18".repeat(32)}`;
const COMPUTE_METERING_QVL_POLICY = `0x${"1d".repeat(32)}`;
const COMPUTE_WORKLOAD_QVL_POLICY = `0x${"1f".repeat(32)}`;
const RELEASE_AUTHORITY_SHA256 = `sha256:${"28".repeat(32)}`;
const CEREMONY_NONCE = `0x${"29".repeat(32)}`;
const DILIGENCE_MEASUREMENT_POLICY_SHA256 = `sha256:${"31".repeat(32)}`;
const ARENA_MEASUREMENT_POLICY_SHA256 = `sha256:${"32".repeat(32)}`;
const ANCHOR_WRITER_MEASUREMENT_POLICY_SHA256 = `sha256:${"33".repeat(32)}`;
const COMPUTE_METERING_MEASUREMENT_POLICY_SHA256 = `sha256:${"34".repeat(32)}`;
const COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256 = `sha256:${"35".repeat(32)}`;
const MAIN_APP_ID = "a0".repeat(20);
const DILIGENCE_QVL_APP_ID = "a1".repeat(20);
const ARENA_QVL_APP_ID = "a2".repeat(20);
const ANCHOR_WRITER_QVL_APP_ID = "a3".repeat(20);
const COMPUTE_METERING_QVL_APP_ID = "a4".repeat(20);
const COMPUTE_WORKLOAD_QVL_APP_ID = "a5".repeat(20);
const COMPUTE_METERING_APP_ID = "a6".repeat(20);
const MAIN_CVM_ID = "cvm_fresh_release";
const COMPUTE_METERING_CVM_ID = "cvm_compute_metering_release";
const EMAIL_DEVICE = `0x${"21".repeat(32)}`;
const EMAIL_BOOT_MR_AGGREGATED = `0x${"22".repeat(32)}`;
const EMAIL_BOOT_MR_SYSTEM = `0x${"23".repeat(32)}`;
const KMS_REGISTRATION_TX = `0x${"24".repeat(32)}`;
const KMS_REGISTRATION_BLOCK = 12_000;
const KMS_REGISTRATION_BLOCK_HASH = `0x${"25".repeat(32)}`;
const EMAIL_RESTART_COMMITMENT = `0x${"26".repeat(32)}`;
const EMAIL_RESTART_PROOF_HASH = `0x${"27".repeat(32)}`;
const EMAIL_ORACLE_UPGRADE_DELAY_SECONDS = 172_800;
const DEPLOYMENT_REVIEW_ENVELOPE_SHA256 = `sha256:${"2a".repeat(32)}`;
const DEPLOYMENT_REVIEW_EVIDENCE_SHA256 = `sha256:${"2b".repeat(32)}`;
const LIVE_ACTIVATION_AUTHORITY_SHA256 = `sha256:${"2b".repeat(32)}`;
const DEPLOYMENT_INTENT_SHA256 = `sha256:${"2c".repeat(32)}`;
const REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256 =
  `sha256:${"2e".repeat(32)}`;
const TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256 =
  `sha256:${"36".repeat(32)}`;
const CVM_LAUNCH_INTENT_COMMITMENT = "2f".repeat(32);
const CVM_LAUNCH_INTENT_SHA256 = `sha256:${CVM_LAUNCH_INTENT_COMMITMENT}`;
const CEREMONY_AUTHORIZATION_SHA256 = `sha256:${"2d".repeat(32)}`;
const COMPUTE_POLICY_SET = `0x${"12".repeat(32)}`;
const DILIGENCE_QVL_COMPOSE = "13".repeat(32);
const ARENA_QVL_COMPOSE = "14".repeat(32);
const ANCHOR_WRITER_QVL_COMPOSE = "1a".repeat(32);
const COMPUTE_METERING_QVL_COMPOSE = "1e".repeat(32);
const COMPUTE_WORKLOAD_QVL_COMPOSE = "20".repeat(32);
const METERING_COMPOSE = "15".repeat(32);
const EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT = "16".repeat(32);
const EXECUTION_POLICY_EVIDENCE_PLACEHOLDER = `sha256:${"17".repeat(32)}`;
const EXECUTION_POLICY_APPROVER_HASHES = Object.freeze([
  "20".repeat(32),
  "30".repeat(32),
]);
const EXECUTION_POLICY_APPROVER_ROOT = createHash("sha256")
  .update(Buffer.from("dnai-wikigen/execution-policy-approver-root/v1\0", "utf8"))
  .update(Buffer.from(JSON.stringify(EXECUTION_POLICY_APPROVER_HASHES), "utf8"))
  .digest("hex");
const EXECUTION_POLICY_APPROVAL_DOMAIN = [
  "base-sepolia",
  "84532",
  EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT,
  `0x${COMPOSE}`,
  createHash("sha256").update(MAIN_APP_ID, "utf8").digest("hex"),
  EXECUTION_POLICY_APPROVER_ROOT,
].join(":");
const EXECUTION_POLICY_APPROVAL_DOMAIN_HASH = createHash("sha256")
  .update(Buffer.from("dnai-wikigen/execution-policy-approval-domain/v1\0", "utf8"))
  .update(EXECUTION_POLICY_APPROVAL_DOMAIN, "ascii")
  .digest("hex");
const diligenceQvl = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const arenaQvl = privateKeyToAccount(
  "0x8b3a350cf5c34c9194ca3a545d2cfb6c2c40a94e2b8f7c02d3f3f6b7255f4b54",
);
const anchorWriterQvl = privateKeyToAccount(
  "0x0dbbe8e4e6f35c5bca5bce9a8accab45ce98869593c7753740f5985b44b8df9d",
);
const computeMeteringQvl = privateKeyToAccount(
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
);
const computeWorkloadQvl = privateKeyToAccount(
  "0x5de4111afa1c4b3daadb3dcd3b56f87df3f4d4dfd1e4f2394f531e9be6c68f97",
);

const codes = Object.freeze({
  diligence_room: "0x6001600055",
  challenge_registry: "0x6002600055",
  royalty_distributor: "0x6003600055",
  tinker_account_encumbrance: "0x6004600055",
  compute_credit_vault: "0x6005600055",
  email_oracle_auth: "0x6006600055",
  usdc: "0x6007600055",
  execution_policy_anchor: "0x6008600055",
  kms: "0x6009600055",
  kms_implementation: "0x6010600055",
});

const addresses = Object.freeze({
  diligence_room: DILIGENCE,
  challenge_registry: CHALLENGE,
  royalty_distributor: ROYALTY,
  tinker_account_encumbrance: ENCUMBRANCE,
  compute_credit_vault: COMPUTE,
  email_oracle_auth: EMAIL,
  usdc: USDC,
  execution_policy_anchor: EXECUTION_POLICY_ANCHOR,
  kms: KMS,
  kms_implementation: KMS_IMPLEMENTATION,
});

const DSTACK_KMS_TEST_ABI = parseAbi([
  "function registerApp(address appId)",
]);
const APP_BOOT_INFO_ABI_PARAMETER = {
  type: "tuple",
  components: [
    { name: "appId", type: "address" },
    { name: "composeHash", type: "bytes32" },
    { name: "instanceId", type: "address" },
    { name: "deviceId", type: "bytes32" },
    { name: "mrAggregated", type: "bytes32" },
    { name: "mrSystem", type: "bytes32" },
    { name: "osImageHash", type: "bytes32" },
    { name: "tcbStatus", type: "string" },
    { name: "advisoryIds", type: "string[]" },
  ],
};

function clone(value) {
  return structuredClone(value);
}

function refreshAnchorWriterEvidence(input) {
  input.anchorWriterEvidenceBytes = Buffer.from(
    `${canonicalJson(input.anchorWriterEvidence)}\n`,
    "ascii",
  );
  input.candidate.execution_policy.rollback_anchor.evidence_sha256 =
    `sha256:${createHash("sha256")
      .update(input.anchorWriterEvidenceBytes)
      .digest("hex")}`;
  return input;
}

function refreshEmailOracleEvidence(input) {
  input.emailOracleEvidenceBytes = Buffer.from(
    `${canonicalJson(input.emailOracleEvidence)}\n`,
    "utf8",
  );
  input.candidate.contracts.email_oracle_auth.release.external_evidence_sha256 =
    `0x${createHash("sha256").update(input.emailOracleEvidenceBytes).digest("hex")}`;
  return input;
}

function generatedFreshSuiteLedger(phala) {
  const transactionHash = (digit) => `0x${digit.repeat(64)}`;
  const deploymentReceipts = Object.fromEntries(
    [
      ["diligenceRoom", DILIGENCE],
      ["tinkerAccountEncumbrance", ENCUMBRANCE],
      ["royaltyDistributor", ROYALTY],
      ["challengeRegistry", CHALLENGE],
      ["computeCreditVault", COMPUTE],
      ["emailOracleAuth", EMAIL],
      ["executionPolicyAnchor", EXECUTION_POLICY_ANCHOR],
    ].map(([key, address], index) => [
      key,
      {
        deploymentTxFrom: OPERATOR,
        deploymentReceiptStatus: "success",
        deploymentReceiptContractAddress: address,
        deploymentBlock: 1_000 + index,
        deploymentBlockHash: transactionHash((index + 8).toString(16)),
        creationInputSha256: `sha256:${(index + 1).toString(16).padStart(2, "0").repeat(32)}`,
      },
    ]),
  );
  const transactionPlan = [
    ["diligenceRoom", "DiligenceRoom", "CREATE", "constructor(bool,address)", ZERO_ADDRESS, DILIGENCE],
    ["diligenceRoom", "DiligenceRoom", "CALL", "freezeFeeBps()", DILIGENCE, ZERO_ADDRESS],
    ["diligenceRoom", "DiligenceRoom", "CALL", "enableComputeSettlementPolicy()", DILIGENCE, ZERO_ADDRESS],
    ["diligenceRoom", "DiligenceRoom", "CALL", "setComposeApprovalRequired(bool)", DILIGENCE, ZERO_ADDRESS],
    ["diligenceRoom", "DiligenceRoom", "CALL", "setTeeIdentityApprovalRequired(bool)", DILIGENCE, ZERO_ADDRESS],
    ["diligenceRoom", "DiligenceRoom", "CALL", "freezeApprovalRequirements()", DILIGENCE, ZERO_ADDRESS],
    ["tinkerAccountEncumbrance", "TinkerAccountEncumbrance", "CREATE", "constructor(address,bytes32,bytes32,uint256,uint256)", ZERO_ADDRESS, ENCUMBRANCE],
    ["royaltyDistributor", "RoyaltyDistributor", "CREATE", "constructor(address)", ZERO_ADDRESS, ROYALTY],
    ["challengeRegistry", "ChallengeRegistry", "CREATE", "constructor(address)", ZERO_ADDRESS, CHALLENGE],
    ["computeCreditVault", "ComputeCreditVault", "CREATE", "constructor(address,address,uint16)", ZERO_ADDRESS, COMPUTE],
    ["computeCreditVault", "ComputeCreditVault", "CALL", "freezeDeveloperFee()", COMPUTE, ZERO_ADDRESS],
    ["emailOracleAuth", "EmailOracleAuth", "CREATE", "constructor(address,uint256,bool,bytes32,bytes32,bool)", ZERO_ADDRESS, EMAIL],
    ["executionPolicyAnchor", "ExecutionPolicyAnchor", "CREATE", "constructor(address,bytes32,bytes32)", ZERO_ADDRESS, EXECUTION_POLICY_ANCHOR],
  ];
  const broadcastTransactions = transactionPlan.map(([
    contractKey,
    contractName,
    transactionType,
    functionSignature,
    transactionTo,
    receiptContractAddress,
  ], index) => ({
    blockHash: `0x${(index + 32).toString(16).padStart(2, "0").repeat(32)}`,
    blockNumber: 2_000 + index,
    contractKey,
    contractName,
    functionSignature,
    receiptContractAddress,
    receiptStatus: "success",
    sequence: index,
    transactionFrom: OPERATOR,
    transactionHash: `0x${(index + 64).toString(16).padStart(2, "0").repeat(32)}`,
    transactionInputSha256:
      `sha256:${(index + 96).toString(16).padStart(2, "0").repeat(32)}`,
    transactionNonce: 100 + index,
    transactionTo,
    transactionType,
  }));
  const args = [
    "--arg", "deployedAt", "2026-07-13T00:00:00Z",
    "--arg", "operator", OPERATOR,
    "--arg", "verifier", ZERO_ADDRESS,
    "--arg", "sourceCommit", SHA,
    "--arg", "deploymentIntentSha256", DEPLOYMENT_INTENT_SHA256,
    "--arg", "reviewerAuthorityGenesisAcceptanceSha256",
    REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
    "--arg", "tinkerAccountBindingCeremonyReceiptSha256",
    TINKER_ACCOUNT_BINDING_CEREMONY_RECEIPT_SHA256,
    "--arg", "deploymentReviewEnvelopeSha256", DEPLOYMENT_REVIEW_ENVELOPE_SHA256,
    "--arg", "deploymentReviewEvidenceSha256", DEPLOYMENT_REVIEW_EVIDENCE_SHA256,
    "--argjson", "deploymentReceipts", JSON.stringify(deploymentReceipts),
    "--argjson", "broadcastTransactions", JSON.stringify(broadcastTransactions),
    "--arg", "broadcastTransactionsSha256", `sha256:${"aa".repeat(32)}`,
    "--arg", "diligence", DILIGENCE,
    "--arg", "diligenceTx", transactionHash("1"),
    "--arg", "diligenceRuntimeCodeHash", keccak256(codes.diligence_room),
    "--arg", "diligenceInitialDeveloper", OPERATOR,
    "--arg", "diligenceGovernanceController", DILIGENCE_GOVERNANCE,
    "--arg", "diligenceReleaseGovernanceController", DILIGENCE_GOVERNANCE,
    "--arg", "diligenceProtocolFeeRecipient", DILIGENCE_GOVERNANCE,
    "--arg", "diligenceDeveloper", OPERATOR,
    "--arg", "diligencePendingDeveloper", ZERO_ADDRESS,
    "--arg", "diligencePendingDeveloperAt", "0",
    "--arg", "diligenceDeveloperTransferDelay", "172800",
    "--arg", "diligencePendingVerifier", ZERO_ADDRESS,
    "--arg", "diligencePendingVerifierAt", "0",
    "--argjson", "diligenceVerifierFrozen", "false",
    "--arg", "diligenceAttestationVerifier", ZERO_ADDRESS,
    "--arg", "diligenceAttestationPolicyHash", `0x${"0".repeat(64)}`,
    "--arg", "diligencePendingAttestationVerifier", ZERO_ADDRESS,
    "--arg", "diligencePendingAttestationPolicyHash", `0x${"0".repeat(64)}`,
    "--arg", "diligencePendingAttestationAt", "0",
    "--argjson", "diligenceAttestationBindingFrozen", "false",
    "--arg", "diligenceEvaluatorPoliciesAbi", `0x${"0".repeat(192)}`,
    "--arg", "diligenceEvaluatorPolicySetRoot", `0x${"0".repeat(64)}`,
    "--arg", "diligenceApprovedEvaluatorPolicyCount", "0",
    "--arg", "diligencePendingEvaluatorPolicyCount", "0",
    "--argjson", "diligenceEvaluatorPolicySetFrozen", "false",
    "--arg", "diligenceRequiredEvaluatorPolicyCount", "3",
    "--argjson", "diligenceComposeRequired", "true",
    "--argjson", "diligenceIdentityRequired", "true",
    "--argjson", "diligenceApprovalRequirementsFrozen", "true",
    "--arg", "diligenceApprovedComposeCount", "0",
    "--arg", "diligenceApprovedTeeCount", "0",
    "--arg", "diligencePendingComposeCount", "0",
    "--arg", "diligencePendingTeeCount", "0",
    "--argjson", "diligenceComposeAdditionsFrozen", "false",
    "--argjson", "diligenceTeeAdditionsFrozen", "false",
    "--arg", "diligenceFeeBps", "100",
    "--argjson", "diligenceFeeBpsFrozen", "true",
    "--arg", "diligenceComputeSettlementBps", "100",
    "--argjson", "diligenceComputeSettlementPolicyEnabled", "true",
    "--argjson", "diligenceProductionRelease", "false",
    "--arg", "diligenceDealCount", "0",
    "--arg", "encumbrance", ENCUMBRANCE,
    "--arg", "encumbranceTx", TINKER_DEPLOYMENT_TX,
    "--arg", "encumbranceRuntimeCodeHash", keccak256(codes.tinker_account_encumbrance),
    "--arg", "accountCommitment", ACCOUNT_COMMITMENT,
    "--arg", "encumbrancePendingOwner", "0x0000000000000000000000000000000000000000",
    "--arg", "maxAddBalanceWei", TINKER_MAX_ADD_BALANCE_WEI,
    "--arg", "maxSpendWei", TINKER_MAX_SPEND_WEI,
    "--argjson", "measurementsFrozen", "false",
    "--arg", "encumbranceComposeRoot", TINKER_EMPTY_COMPOSE_ROOT,
    "--arg", "encumbranceComposeCount", "0",
    "--arg", "encumbranceManagerRoot", TINKER_EMPTY_MANAGER_ROOT,
    "--arg", "encumbranceManagerCount", "0",
    "--arg", "encumbranceReleaseCommitment", `0x${"0".repeat(64)}`,
    "--arg", "encumbranceReleaseMaxAddBalanceWei", "0",
    "--arg", "encumbranceReleaseMaxSpendWei", "0",
    "--arg", "encumbranceReleaseComposeRoot", `0x${"0".repeat(64)}`,
    "--arg", "encumbranceReleaseComposeCount", "0",
    "--arg", "encumbranceReleaseManagerRoot", `0x${"0".repeat(64)}`,
    "--arg", "encumbranceReleaseManagerCount", "0",
    "--arg", "encumbrancePendingAccountCommitment", `0x${"0".repeat(64)}`,
    "--arg", "encumbrancePendingMaxAddBalanceWei", "0",
    "--arg", "encumbrancePendingMaxSpendWei", "0",
    "--arg", "encumbrancePendingComposeRoot", `0x${"0".repeat(64)}`,
    "--arg", "encumbrancePendingManagerRoot", `0x${"0".repeat(64)}`,
    "--arg", "encumbrancePendingCommitment", `0x${"0".repeat(64)}`,
    "--arg", "encumbrancePendingAt", "0",
    "--arg", "encumbrancePendingComposeCount", "0",
    "--arg", "encumbrancePendingManagerCount", "0",
    "--argjson", "encumbranceReleasePolicyFrozen", "false",
    "--argjson", "encumbranceEmergencyHalted", "true",
    "--arg", "royalty", ROYALTY,
    "--arg", "royaltyTx", transactionHash("3"),
    "--arg", "royaltyRuntimeCodeHash", keccak256(codes.royalty_distributor),
    "--arg", "royaltyOwner", OPERATOR,
    "--arg", "royaltyPendingOwner", ZERO_ADDRESS,
    "--argjson", "royaltyPaused", "true",
    "--arg", "royaltySettlementVerifier", ZERO_ADDRESS,
    "--arg", "royaltyQvlVerifier", ZERO_ADDRESS,
    "--arg", "royaltyExecutionPolicyAnchor", ZERO_ADDRESS,
    "--arg", "royaltyAnchorWriterRelease", `0x${"0".repeat(64)}`,
    "--arg", "royaltyReleasePolicy", `0x${"0".repeat(64)}`,
    "--arg", "royaltyAuthorityNonce", "0",
    "--arg", "royaltyPendingAuthorityAt", "0",
    "--arg", "challenge", CHALLENGE,
    "--arg", "challengeTx", transactionHash("4"),
    "--arg", "challengeRuntimeCodeHash", keccak256(codes.challenge_registry),
    "--arg", "challengePendingOwner", ZERO_ADDRESS,
    "--arg", "challengeNextId", "1",
    "--arg", "challengeMinVersionReviewDelay", "172800",
    "--arg", "computeVault", COMPUTE,
    "--arg", "computeVaultTx", transactionHash("6"),
    "--arg", "computeVaultRuntimeCodeHash", keccak256(codes.compute_credit_vault),
    "--arg", "computeVaultOwner", OPERATOR,
    "--arg", "computeVaultDeveloper", COMPUTE_DEVELOPER,
    "--arg", "computeVaultMeteringVerifier", "0x0000000000000000000000000000000000000000",
    "--arg", "computeVaultMeteringQvlVerifier", "0x0000000000000000000000000000000000000000",
    "--arg", "computeVaultMeteringPolicySetHash", `0x${"0".repeat(64)}`,
    "--arg", "computeVaultPendingMeteringVerifier", "0x0000000000000000000000000000000000000000",
    "--arg", "computeVaultPendingMeteringQvlVerifier", "0x0000000000000000000000000000000000000000",
    "--arg", "computeVaultPendingMeteringPolicySetHash", `0x${"0".repeat(64)}`,
    "--arg", "computeVaultPendingMeteringAt", "0",
    "--argjson", "computeVaultMeteringBindingFrozen", "false",
    "--argjson", "computeVaultPaused", "true",
    "--arg", "computeVaultFeeBps", "100",
    "--argjson", "computeVaultFeeFrozen", "true",
    "--arg", "computeVaultAllowedAssetCount", "0",
    "--arg", "computeVaultActiveRateCount", "0",
    "--arg", "computeVaultApprovedComposeCount", "0",
    "--arg", "computeVaultApprovedTeeCount", "0",
    "--arg", "computeVaultPendingAssetCount", "0",
    "--arg", "computeVaultPendingRateCount", "0",
    "--arg", "computeVaultPendingComposeCount", "0",
    "--arg", "computeVaultPendingTeeCount", "0",
    "--argjson", "computeVaultComposePolicyFrozen", "false",
    "--argjson", "computeVaultTeeAdditionsFrozen", "false",
    "--argjson", "computeVaultRateAdditionsFrozen", "false",
    "--argjson", "computeVaultAssetAdditionsFrozen", "false",
    "--arg", "emailOracle", EMAIL,
    "--arg", "emailOracleTx", transactionHash("5"),
    "--arg", "emailOracleOwner", OPERATOR,
    "--arg", "emailOracleDelay", "172800",
    "--argjson", "emailOracleAllowAny", "false",
    "--argjson", "emailOracleCodeFrozen", "false",
    "--argjson", "emailOracleConsumersFrozen", "false",
    "--arg", "emailOracleRuntimeCodeHash", keccak256(codes.email_oracle_auth),
    "--arg", "emailOraclePendingOwner", "0x0000000000000000000000000000000000000000",
    "--argjson", "emailOracleManagerAdditionsFrozen", "false",
    "--argjson", "emailOracleKmsFrozen", "false",
    "--arg", "emailOracleAllowedComposeCount", "0",
    "--arg", "emailOraclePendingComposeCount", "0",
    "--arg", "emailOracleAllowedDeviceCount", "0",
    "--arg", "emailOracleManagerCount", "0",
    "--arg", "emailOracleConsumerComposeCount", "0",
    "--arg", "emailOracleReleaseCompose", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleReleaseDevice", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleReleaseManager", "0x0000000000000000000000000000000000000000",
    "--arg", "emailOracleReleaseApp", "0x0000000000000000000000000000000000000000",
    "--arg", "emailOracleReleaseConsumerCompose", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleKmsContract", "0x0000000000000000000000000000000000000000",
    "--arg", "emailOracleKmsRuntimeHash", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleKmsImplementation", "0x0000000000000000000000000000000000000000",
    "--arg", "emailOracleKmsImplementationRuntimeHash", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleKmsRegistrationTx", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleKmsRegistrationBlock", "0",
    "--arg", "emailOracleKmsRegistrationBlockHash", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleBootInfoHash", `0x${"0".repeat(64)}`,
    "--arg", "emailOracleRestartProofHash", `0x${"0".repeat(64)}`,
    "--argjson", "emailOracleReleaseReady", "false",
    "--argjson", "emailOracleProductionRelease", "false",
    "--arg", "executionPolicyAnchor", EXECUTION_POLICY_ANCHOR,
    "--arg", "executionPolicyAnchorTx", transactionHash("7"),
    "--arg", "executionPolicyAnchorRuntimeCodeHash", keccak256(codes.execution_policy_anchor),
    "--arg", "executionPolicyAnchorOwner", OPERATOR,
    "--arg", "executionPolicyAnchorDeploymentIntentSha256Bytes32",
    `0x${DEPLOYMENT_INTENT_SHA256.slice("sha256:".length)}`,
    "--arg", "executionPolicyAnchorReviewerGenesisAcceptanceSha256Bytes32",
    `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
    "--arg", "executionPolicyAnchorAuthorityCommitmentReadProof",
    "historical_onchain_immutable_getter_readback",
    "--arg", "executionPolicyAnchorAuthorityCommitmentReadBlock", "1006",
    "--arg", "executionPolicyAnchorAuthorityCommitmentReadBlockHash",
    transactionHash("e"),
    "--arg", "executionPolicyAnchorWriter", "0x0000000000000000000000000000000000000000",
    "--arg", "executionPolicyAnchorWriterRelease", `0x${"0".repeat(64)}`,
    "--arg", "executionPolicyAnchorPendingWriter", "0x0000000000000000000000000000000000000000",
    "--arg", "executionPolicyAnchorPendingRelease", `0x${"0".repeat(64)}`,
    "--arg", "executionPolicyAnchorPendingAt", "0",
    "--argjson", "executionPolicyAnchorRotationsFrozen", "false",
    "--argjson", "executionPolicyAnchorPaused", "true",
    "--arg", "executionPolicyAnchorGlobalSequence", "0",
    "--arg", "executionPolicyAnchorGlobalHead", `0x${"0".repeat(64)}`,
    "--argjson", "verificationRequested", "false",
    "-f", FRESH_SUITE_MANIFEST_FILTER,
  ];
  const output = execFileSync("jq", args, {
    input: JSON.stringify({ phala }),
    encoding: "utf8",
  });
  return JSON.parse(output);
}

function recordActiveAnchorSnapshot(
  ledger,
  { blockNumber = 12_345, globalSequence = 0, globalHead = `0x${"0".repeat(64)}` } = {},
) {
  Object.assign(ledger.contracts.executionPolicyAnchor, {
    status: "verified_active_frozen_release_writer",
    writer: EXECUTION_POLICY_WRITER,
    writerReleaseCommitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
    pendingWriter: "0x0000000000000000000000000000000000000000",
    pendingWriterReleaseCommitment: `0x${"0".repeat(64)}`,
    pendingWriterActivatesAt: 0,
    writerRotationsFrozen: true,
    paused: false,
    globalSequence,
    globalHead,
    releaseSnapshotBlockNumber: blockNumber,
    resourceAndDecisionPayloadsOnChain: false,
    opaqueCommitmentsOnly: true,
    policyState: "anchoring_active_frozen_release_writer",
  });
  return ledger;
}

function tinkerDraftLedgerState() {
  return {
    status: "deployed_halted_draft_pending_timelocked_release_policy",
    owner: OPERATOR,
    pendingOwner: "0x0000000000000000000000000000000000000000",
    accountCommitment: ACCOUNT_COMMITMENT,
    initialComposeHash: `0x${"0".repeat(64)}`,
    initialComposeHashApproved: false,
    approvedComposeHashes: [],
    approvedComposeRoot: TINKER_EMPTY_COMPOSE_ROOT,
    approvedComposeCount: 0,
    managers: [],
    managerRoot: TINKER_EMPTY_MANAGER_ROOT,
    managerCount: 0,
    maxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
    maxSpendWei: TINKER_MAX_SPEND_WEI,
    perOperationCaps: true,
    custodiesFunds: false,
    releasePolicyCommitment: `0x${"0".repeat(64)}`,
    releaseMaxAddBalanceWei: "0",
    releaseMaxSpendWei: "0",
    releaseComposeHashes: [],
    releaseComposeRoot: `0x${"0".repeat(64)}`,
    releaseComposeCount: 0,
    releaseManagers: [],
    releaseManagerRoot: `0x${"0".repeat(64)}`,
    releaseManagerCount: 0,
    pendingAccountCommitment: `0x${"0".repeat(64)}`,
    pendingMaxAddBalanceWei: "0",
    pendingMaxSpendWei: "0",
    pendingComposeHashes: [],
    pendingComposeRoot: `0x${"0".repeat(64)}`,
    pendingComposeCount: 0,
    pendingManagers: [],
    pendingManagerRoot: `0x${"0".repeat(64)}`,
    pendingManagerCount: 0,
    pendingReleasePolicyCommitment: `0x${"0".repeat(64)}`,
    pendingReleasePolicyActivatesAt: 0,
    releasePolicyFrozen: false,
    emergencyHalted: true,
    policyState: "operations_fail_closed_pending_exact_timelocked_release_policy",
  };
}

function tinkerActiveLedgerState() {
  return {
    status: "deployed_exact_release_policy_frozen_active",
    owner: OPERATOR,
    pendingOwner: "0x0000000000000000000000000000000000000000",
    accountCommitment: ACCOUNT_COMMITMENT,
    initialComposeHash: `0x${"0".repeat(64)}`,
    initialComposeHashApproved: false,
    approvedComposeHashes: [`0x${COMPOSE}`],
    approvedComposeRoot: TINKER_COMPOSE_ROOT,
    approvedComposeCount: 1,
    managers: [TEE],
    managerRoot: TINKER_MANAGER_ROOT,
    managerCount: 1,
    maxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
    maxSpendWei: TINKER_MAX_SPEND_WEI,
    perOperationCaps: true,
    custodiesFunds: false,
    releasePolicyCommitment: TINKER_RELEASE_POLICY,
    releaseMaxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
    releaseMaxSpendWei: TINKER_MAX_SPEND_WEI,
    releaseComposeHashes: [`0x${COMPOSE}`],
    releaseComposeRoot: TINKER_COMPOSE_ROOT,
    releaseComposeCount: 1,
    releaseManagers: [TEE],
    releaseManagerRoot: TINKER_MANAGER_ROOT,
    releaseManagerCount: 1,
    pendingAccountCommitment: `0x${"0".repeat(64)}`,
    pendingMaxAddBalanceWei: "0",
    pendingMaxSpendWei: "0",
    pendingComposeHashes: [],
    pendingComposeRoot: `0x${"0".repeat(64)}`,
    pendingComposeCount: 0,
    pendingManagers: [],
    pendingManagerRoot: `0x${"0".repeat(64)}`,
    pendingManagerCount: 0,
    pendingReleasePolicyCommitment: `0x${"0".repeat(64)}`,
    pendingReleasePolicyActivatesAt: 0,
    releasePolicyFrozen: true,
    emergencyHalted: false,
    policyState: "exact_timelocked_release_policy_frozen_active",
    latestReleasePhase: 2,
    latestReleaseTx: TINKER_PHASE_TWO_TX,
    latestReleaseBlock: TINKER_PHASE_TWO_BLOCK,
    latestReleaseRecordedAt: TINKER_PHASE_TWO_RECORDED_AT,
    latestReleaseSourceCommit: TINKER_PHASE_TWO_SOURCE,
  };
}

function tinkerReleaseHistoryRecords() {
  const common = {
    kind: "tinker_exact_release_policy_phase",
    chainId: 84_532,
    encumbranceAddress: ENCUMBRANCE,
    runtimeCodeHash: keccak256(codes.tinker_account_encumbrance),
    pendingOwner: "0x0000000000000000000000000000000000000000",
    accountCommitment: ACCOUNT_COMMITMENT,
    maxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
    maxSpendWei: TINKER_MAX_SPEND_WEI,
    perOperationCaps: true,
    custodiesFunds: false,
    approvedComposeHashes: [`0x${COMPOSE}`],
    composeRoot: TINKER_COMPOSE_ROOT,
    composeCount: 1,
  };
  return [
    {
      ...common,
      phase: 1,
      recordedAt: TINKER_PHASE_ONE_RECORDED_AT,
      sourceCommit: TINKER_PHASE_ONE_SOURCE,
      transactionHash: TINKER_PHASE_ONE_TX,
      blockNumber: TINKER_PHASE_ONE_BLOCK,
      status: "deployed_halted_release_policy_pending_timelock",
      policyState: "operations_fail_closed_pending_exact_timelocked_release_policy",
      managers: [],
      managerRoot: TINKER_EMPTY_MANAGER_ROOT,
      managerCount: 0,
      releasePolicyCommitment: `0x${"0".repeat(64)}`,
      releaseMaxAddBalanceWei: "0",
      releaseMaxSpendWei: "0",
      releaseComposeHashes: [],
      releaseComposeRoot: `0x${"0".repeat(64)}`,
      releaseComposeCount: 0,
      releaseManagers: [],
      releaseManagerRoot: `0x${"0".repeat(64)}`,
      releaseManagerCount: 0,
      pendingAccountCommitment: ACCOUNT_COMMITMENT,
      pendingMaxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
      pendingMaxSpendWei: TINKER_MAX_SPEND_WEI,
      pendingComposeHashes: [`0x${COMPOSE}`],
      pendingComposeRoot: TINKER_COMPOSE_ROOT,
      pendingComposeCount: 1,
      pendingManagers: [TEE],
      pendingManagerRoot: TINKER_MANAGER_ROOT,
      pendingManagerCount: 1,
      pendingReleasePolicyCommitment: TINKER_RELEASE_POLICY,
      pendingReleasePolicyActivatesAt: TINKER_REVIEW_ELIGIBLE_AT,
      releasePolicyFrozen: false,
      emergencyHalted: true,
    },
    {
      ...common,
      phase: 2,
      recordedAt: TINKER_PHASE_TWO_RECORDED_AT,
      sourceCommit: TINKER_PHASE_TWO_SOURCE,
      transactionHash: TINKER_PHASE_TWO_TX,
      blockNumber: TINKER_PHASE_TWO_BLOCK,
      status: "deployed_exact_release_policy_frozen_active",
      policyState: "exact_timelocked_release_policy_frozen_active",
      managers: [TEE],
      managerRoot: TINKER_MANAGER_ROOT,
      managerCount: 1,
      releasePolicyCommitment: TINKER_RELEASE_POLICY,
      releaseMaxAddBalanceWei: TINKER_MAX_ADD_BALANCE_WEI,
      releaseMaxSpendWei: TINKER_MAX_SPEND_WEI,
      releaseComposeHashes: [`0x${COMPOSE}`],
      releaseComposeRoot: TINKER_COMPOSE_ROOT,
      releaseComposeCount: 1,
      releaseManagers: [TEE],
      releaseManagerRoot: TINKER_MANAGER_ROOT,
      releaseManagerCount: 1,
      pendingAccountCommitment: `0x${"0".repeat(64)}`,
      pendingMaxAddBalanceWei: "0",
      pendingMaxSpendWei: "0",
      pendingComposeHashes: [],
      pendingComposeRoot: `0x${"0".repeat(64)}`,
      pendingComposeCount: 0,
      pendingManagers: [],
      pendingManagerRoot: `0x${"0".repeat(64)}`,
      pendingManagerCount: 0,
      pendingReleasePolicyCommitment: `0x${"0".repeat(64)}`,
      pendingReleasePolicyActivatesAt: 0,
      releasePolicyFrozen: true,
      emergencyHalted: false,
    },
  ];
}

function recordActiveTinkerSnapshot(ledger) {
  Object.assign(ledger.contracts.tinkerAccountEncumbrance, tinkerActiveLedgerState());
  ledger.tinkerReleaseHistory = tinkerReleaseHistoryRecords();
  return ledger;
}

function recordActiveDiligenceResultVerifierSnapshot(ledger) {
  Object.assign(ledger.contracts.diligenceRoom, {
    resultVerifier: RESULT_VERIFIER,
    pendingResultVerifier: ZERO_ADDRESS,
    pendingResultVerifierActivatesAt: 0,
    resultVerifierFrozen: true,
  });
  return ledger;
}

function canonicalJson(value) {
  const normalize = (item) => {
    if (Array.isArray(item)) return item.map(normalize);
    if (item && typeof item === "object") {
      return Object.fromEntries(
        Object.keys(item).sort().map((key) => [key, normalize(item[key])]),
      );
    }
    return item;
  };
  return JSON.stringify(normalize(value));
}

function emailTargetBootInfo() {
  return {
    appId: EMAIL,
    composeHash: `0x${COMPOSE}`,
    instanceId: BOOT_INSTANCE,
    deviceId: EMAIL_DEVICE,
    mrAggregated: EMAIL_BOOT_MR_AGGREGATED,
    mrSystem: EMAIL_BOOT_MR_SYSTEM,
    osImageHash: `0x${OS_IMAGE}`,
    tcbStatus: "UpToDate",
    advisoryIds: [],
  };
}

function emailTargetBootInfoHash() {
  return keccak256(encodeAbiParameters(
    [APP_BOOT_INFO_ABI_PARAMETER],
    [emailTargetBootInfo()],
  ));
}

function anchorWriterReportData() {
  const payload = {
    schema: "dnai.execution-policy-anchor-writer-qvl-evidence.v1",
    chain_id: 84_532,
    anchor_address: EXECUTION_POLICY_ANCHOR.toLowerCase(),
    writer_address: EXECUTION_POLICY_WRITER.toLowerCase(),
    writer_release_commitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
    writer_key_path: "tinker/execution_policy_anchor_writer",
    writer_custody: "dstack_derived_execution_policy_anchor_writer",
  };
  return `0x${createHash("sha256")
    .update(Buffer.from("dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0", "utf8"))
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function computeMeteringReportData() {
  const payload = {
    schema: "dnai.compute-metering-signer-attestation.v1",
    chain_id: 84_532,
    vault_address: COMPUTE.toLowerCase(),
    metering_verifier: COMPUTE_METERING_VERIFIER.toLowerCase(),
    policy_set_hash: COMPUTE_POLICY_SET,
    signer_custody: "dstack_derived_independent_cvm",
  };
  return `0x${createHash("sha256")
    .update(Buffer.from("dnai-wikigen/compute-metering-signer-attestation/v1\0", "utf8"))
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function emailKmsRestartBinding() {
  return {
    kind: "email_oracle_kms_restart_v1",
    email_oracle_auth_address: EMAIL.toLowerCase(),
    email_oracle_auth_runtime_code_hash: keccak256(codes.email_oracle_auth),
    kms_proxy_address: KMS.toLowerCase(),
    kms_proxy_runtime_code_hash: keccak256(codes.kms),
    kms_implementation_address: KMS_IMPLEMENTATION.toLowerCase(),
    kms_implementation_runtime_code_hash: keccak256(codes.kms_implementation),
    kms_eip1967_implementation_slot_word:
      `0x${"0".repeat(24)}${KMS_IMPLEMENTATION.toLowerCase().slice(2)}`,
    registration_tx_hash: KMS_REGISTRATION_TX,
    registration_block_number: KMS_REGISTRATION_BLOCK,
    registration_block_hash: KMS_REGISTRATION_BLOCK_HASH,
    target_boot_tuple_hash: emailTargetBootInfoHash(),
    restart_proof_hash: EMAIL_RESTART_PROOF_HASH,
  };
}

function emailKmsRestartReportData() {
  const { kind: _kind, ...binding } = emailKmsRestartBinding();
  const payload = {
    schema: "dnai.email-oracle-kms-restart-attestation.v1",
    chain_id: 84_532,
    main_cvm_signer: TEE.toLowerCase(),
    ...binding,
  };
  return `0x${createHash("sha256")
    .update(Buffer.from("dnai-wikigen/email-oracle-kms-restart-attestation/v1\0", "utf8"))
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

async function signedVerdict({
  context,
  quoteByte,
  reportByte,
  reportData,
  contract,
  signer,
  signerAddress = TEE,
  profile,
  releasePolicyHash,
  composeHash = COMPOSE,
  appId = MAIN_APP_ID,
  cvmId = MAIN_CVM_ID,
  domain = "main_runtime_cvm",
  measurementPolicySha256 = ({
    artifact: DILIGENCE_MEASUREMENT_POLICY_SHA256,
    arena: ARENA_MEASUREMENT_POLICY_SHA256,
    anchor_writer: ANCHOR_WRITER_MEASUREMENT_POLICY_SHA256,
    email_oracle_kms_restart: DILIGENCE_MEASUREMENT_POLICY_SHA256,
    compute_metering: COMPUTE_METERING_MEASUREMENT_POLICY_SHA256,
  })[context],
  deploymentIntentSha256 = DEPLOYMENT_INTENT_SHA256,
  releaseAuthoritySha256 = RELEASE_AUTHORITY_SHA256,
  ceremonyNonce = CEREMONY_NONCE,
  osImageHash = OS_IMAGE,
  challengeIssuedAt = NOW - 20,
  challengeExpiresAt = NOW - 5,
  issuedAt = NOW - 10,
  expiresAt = NOW + 90,
  activationEvidenceLeaseExpiresAt = expiresAt,
  challengeDigest: suppliedChallengeDigest,
}) {
  const challengeId = `0x${quoteByte.repeat(64)}`;
  const challengeDigest = suppliedChallengeDigest || `0x${createHash("sha256")
    .update(`${context}:${quoteByte}`, "ascii")
    .digest("hex")}`;
  const verdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    chain_id: 84_532,
    domain,
    profile,
    cvm_id: cvmId,
    deployment_intent_sha256: deploymentIntentSha256,
    release_authority_sha256: releaseAuthoritySha256,
    ceremony_nonce: ceremonyNonce,
    measurement_policy_sha256: measurementPolicySha256,
    release_policy_hash: releasePolicyHash,
    challenge_id: challengeId,
    challenge_digest: challengeDigest,
    challenge_issued_at: challengeIssuedAt,
    challenge_expires_at: challengeExpiresAt,
    quote_hash: `0x${quoteByte.repeat(64)}`,
    report_data: reportData || `0x${reportByte.repeat(64)}`,
    compose_hash: `0x${composeHash}`,
    app_id: appId,
    os_image_hash: osImageHash,
    signer_address: signerAddress,
    contract_address: contract,
    issued_at: issuedAt,
    activation_evidence_lease_expires_at: activationEvidenceLeaseExpiresAt,
    expires_at: expiresAt,
    verifier_address: signer.address.toLowerCase(),
    verifier_signature: "",
  };
  const digest = __test.canonicalVerdictDigest(verdict);
  verdict.verifier_signature = await signer.signMessage({ message: { raw: digest } });
  return {
    context,
    quote_sha256: `sha256:${quoteByte.repeat(64)}`,
    verdict,
  };
}

async function fixture() {
  const artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    measurementPolicySha256: DILIGENCE_MEASUREMENT_POLICY_SHA256,
  });
  const arena = await signedVerdict({
    context: "arena",
    quoteByte: "3",
    reportByte: "4",
    contract: CHALLENGE,
    signer: arenaQvl,
    profile: "arena",
    releasePolicyHash: ARENA_QVL_POLICY,
    measurementPolicySha256: ARENA_MEASUREMENT_POLICY_SHA256,
  });
  const computeMetering = await signedVerdict({
    context: "compute_metering",
    quoteByte: "6",
    reportData: computeMeteringReportData(),
    contract: COMPUTE,
    signer: computeMeteringQvl,
    signerAddress: COMPUTE_METERING_VERIFIER,
    profile: "compute_metering",
    releasePolicyHash: COMPUTE_METERING_QVL_POLICY,
    composeHash: METERING_COMPOSE,
    appId: COMPUTE_METERING_APP_ID,
    cvmId: COMPUTE_METERING_CVM_ID,
    domain: "independent_metering_cvm",
    measurementPolicySha256: COMPUTE_METERING_MEASUREMENT_POLICY_SHA256,
    osImageHash: "1f".repeat(32),
  });
  const images = [
    {
      service: "delegate",
      image: `ghcr.io/therealwiki/dnai-wikigen/tinker-delegate@sha256:${"5".repeat(64)}`,
      source_digest: SHA,
      source_ref: "refs/heads/main",
      repo: "therealwiki/dnai-wikigen",
      signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
      provenance_attestation: "verified",
      sbom_attestation: "verified",
    },
    {
      service: "oracle",
      image: `ghcr.io/therealwiki/dnai-wikigen/tee-email-oracle@sha256:${"6".repeat(64)}`,
      source_digest: SHA,
      source_ref: "refs/heads/main",
      repo: "therealwiki/dnai-wikigen",
      signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
      provenance_attestation: "verified",
      sbom_attestation: "verified",
    },
    {
      service: "neko",
      image: `ghcr.io/therealwiki/dnai-wikigen/neko-chrome@sha256:${"7".repeat(64)}`,
      source_digest: SHA,
      source_ref: "refs/heads/main",
      repo: "therealwiki/dnai-wikigen",
      signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
      provenance_attestation: "verified",
      sbom_attestation: "verified",
    },
  ];
  const trustImage = (repository, digestByte) => ({
    image: `ghcr.io/therealwiki/dnai-wikigen/${repository}@sha256:${digestByte.repeat(64)}`,
    source_digest: SHA,
    source_ref: "refs/heads/main",
    repo: "therealwiki/dnai-wikigen",
    signer_workflow: "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml",
    provenance_attestation: "verified",
    sbom_attestation: "verified",
  });
  const trustBase = ({ schema, appId, cvmId, composeHash, suffix, endpoint, image }) => ({
    schema,
    platform: "phala_cloud",
    release_sha: SHA,
    app_id: appId,
    cvm_id: cvmId,
    compose_hash: composeHash,
    local_compose_hash: suffix.repeat(32),
    rendered_compose_sha256: `${suffix[1]}${suffix[0]}`.repeat(32),
    os_image_hash: `${suffix[0]}f`.repeat(32),
    os_is_dev: false,
    public_logs: false,
    public_sysinfo: false,
    public_tcbinfo: false,
    ssh_enabled: false,
    endpoint,
    endpoint_authentication: "bearer_required",
    image,
    identity_evidence_classification: "deployment_pins_require_external_platform_verification",
  });
  const candidate = {
    schema: "dnai.web-release.v4",
    release_sha: SHA,
    network: { chain_id: 84_532, public_rpc_url: "https://sepolia.base.org" },
    operator_address: OPERATOR,
    deployment_intent_sha256: DEPLOYMENT_INTENT_SHA256,
    cvm_launch_intent_sha256: CVM_LAUNCH_INTENT_SHA256,
    operator_policy: {
      schema: "dnai.live-activation-authority-evidence.v1",
      ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
      live_activation_authority_sha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
      runtime_authority_dependency_sha256:
        `sha256:${EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT}`,
    },
    contracts: {
      diligence_room: {
        address: DILIGENCE,
        runtime_code_hash: keccak256(codes.diligence_room),
        developer: DILIGENCE_GOVERNANCE,
        result_verifier: RESULT_VERIFIER,
        attestation_verifier: diligenceQvl.address.toLowerCase(),
        attestation_release_policy_hash: DILIGENCE_QVL_POLICY,
        attestation_binding_frozen: true,
        evaluator_policy_commitments: [...DILIGENCE_EVALUATOR_POLICIES],
        evaluator_policy_set_root: DILIGENCE_EVALUATOR_POLICY_SET_ROOT,
      },
      challenge_registry: {
        address: CHALLENGE,
        runtime_code_hash: keccak256(codes.challenge_registry),
        owner: OPERATOR,
        pending_owner: ZERO_ADDRESS,
        registry_paused: false,
        minimum_version_review_delay_seconds: 172_800,
        expected_challenge_count: 1,
      },
      royalty_distributor: {
        address: ROYALTY,
        runtime_code_hash: keccak256(codes.royalty_distributor),
      },
      tinker_account_encumbrance: {
        address: ENCUMBRANCE,
        runtime_code_hash: keccak256(codes.tinker_account_encumbrance),
        owner: OPERATOR,
        account_commitment: ACCOUNT_COMMITMENT,
        max_add_balance_wei: TINKER_MAX_ADD_BALANCE_WEI,
        max_spend_wei: TINKER_MAX_SPEND_WEI,
        approved_compose_hashes: [`0x${COMPOSE}`],
        approved_compose_root: TINKER_COMPOSE_ROOT,
        approved_compose_count: 1,
        managers: [TEE],
        manager_root: TINKER_MANAGER_ROOT,
        manager_count: 1,
        release_policy_commitment: TINKER_RELEASE_POLICY,
        release_max_add_balance_wei: TINKER_MAX_ADD_BALANCE_WEI,
        release_max_spend_wei: TINKER_MAX_SPEND_WEI,
        release_compose_root: TINKER_COMPOSE_ROOT,
        release_compose_count: 1,
        release_manager_root: TINKER_MANAGER_ROOT,
        release_manager_count: 1,
        release_policy_frozen: true,
        emergency_halted: false,
        per_operation_caps: true,
        custodies_funds: false,
      },
      compute_credit_vault: {
        address: COMPUTE,
        runtime_code_hash: keccak256(codes.compute_credit_vault),
        owner: OPERATOR,
        developer: COMPUTE_DEVELOPER,
        metering_verifier: COMPUTE_METERING_VERIFIER,
        metering_qvl_verifier: computeMeteringQvl.address.toLowerCase(),
        metering_policy_set_hash: COMPUTE_POLICY_SET,
        metering_binding_frozen: true,
        developer_fee_bps: 100,
        tee_identity: TEE,
        compose_hash: COMPOSE,
        native_rate_policy_commitment: NATIVE_RATE_POLICY,
        native_provider: COMPUTE_PROVIDER,
        erc20_asset_address: USDC,
        erc20_rate_policy_commitment: ERC20_RATE_POLICY,
        erc20_provider: COMPUTE_ERC20_PROVIDER,
      },
      email_oracle_auth: {
        address: EMAIL,
        runtime_code_hash: keccak256(codes.email_oracle_auth),
        owner: OPERATOR,
        consumer_address: TEE,
        upgrade_delay_seconds: EMAIL_ORACLE_UPGRADE_DELAY_SECONDS,
        release: {
          device_id: EMAIL_DEVICE,
          kms_contract_address: KMS,
          kms_runtime_code_hash: keccak256(codes.kms),
          kms_implementation_address: KMS_IMPLEMENTATION,
          kms_implementation_runtime_code_hash: keccak256(codes.kms_implementation),
          kms_registration_tx_hash: KMS_REGISTRATION_TX,
          kms_registration_block: KMS_REGISTRATION_BLOCK,
          kms_registration_block_hash: KMS_REGISTRATION_BLOCK_HASH,
          target_boot: {
            instance_id: BOOT_INSTANCE,
            mr_aggregated: EMAIL_BOOT_MR_AGGREGATED,
            mr_system: EMAIL_BOOT_MR_SYSTEM,
            os_image_hash: `0x${OS_IMAGE}`,
            tcb_status: "UpToDate",
            advisory_ids: [],
            info_hash: emailTargetBootInfoHash(),
          },
          restart_key_derivation_proof_hash: EMAIL_RESTART_PROOF_HASH,
          external_evidence_sha256: `0x${"28".repeat(32)}`,
        },
      },
      usdc: {
        address: USDC,
        runtime_code_hash: keccak256(codes.usdc),
        symbol: "USDC",
        decimals: 6,
      },
    },
    cvm: {
      app_id: MAIN_APP_ID,
      cvm_id: MAIN_CVM_ID,
      compose_hash: COMPOSE,
      local_compose_hash: LOCAL_COMPOSE,
      rendered_compose_sha256: RENDERED_COMPOSE,
      os_image_hash: OS_IMAGE,
      os_is_dev: false,
      public_logs: false,
      public_sysinfo: false,
      public_tcbinfo: false,
      tee_identity: TEE,
      delegate_url: "https://delegate.release.wikigen.me",
      images,
      allowed_browser_origins: [
        "https://wikigen.me",
        "https://www.wikigen.me",
        "https://wikigenme.pages.dev",
      ],
      compute_workload_ingress: {
        max_verdict_age_seconds: 300,
        revoked_quote_hashes: [],
      },
      runtime_controls: {
        wallet_auth_required: true,
        runtime_bearer_required: true,
        durable_compute_store: true,
        durable_arena_store: true,
        durable_arena_ingress_store: true,
        artifact_ciphertext_only: true,
        plaintext_artifact_endpoint_disabled: true,
        plaintext_card_endpoint_disabled: true,
        bootstrap_fail_open_disabled: true,
        browser_ports_internal_only: true,
        nondefault_browser_credentials_required: true,
        project_owned_browser_images: true,
        oracle_internal_only: true,
        oracle_runtime_auth_required: true,
        oracle_health_liveness_only: true,
        oracle_pin_response_minimized: true,
        oracle_private_metadata_egress_prohibited: true,
        oracle_replay_fail_closed: true,
        provider_dispatch_enabled: false,
        hostile_candidate_execution_enabled: false,
        deal_settlement_enabled: false,
        remote_artifact_evaluator_enabled: false,
        raw_secret_egress_prohibited: true,
      },
    },
    trust_domains: {
      diligence_qvl: {
        ...trustBase({
          schema: "dnai.release-qvl-cvm.v1",
          appId: DILIGENCE_QVL_APP_ID,
          cvmId: "cvm_diligence_qvl_release",
          composeHash: DILIGENCE_QVL_COMPOSE,
          suffix: "16",
          endpoint: "https://qvl-diligence.release.wikigen.me/verify",
          image: trustImage("attestation-qvl", "8"),
        }),
        context: "diligence",
        identity: {
          schema: "dnai.attestation-qvl-identity.v1",
          verifier_address: diligenceQvl.address.toLowerCase(),
          release_policy_hash: DILIGENCE_QVL_POLICY,
          signer_custody: "dstack_derived_separate_cvm",
          raw_secret_egress: false,
        },
        policy_binding: {
          chain_id: 84_532,
          contract_address: DILIGENCE,
          evaluated_app_id: MAIN_APP_ID,
          evaluated_compose_hash: `0x${COMPOSE}`,
          evaluated_os_image_hash: OS_IMAGE,
          allowed_signer_address: TEE,
          report_data_binding_kind: "diligence_result_signer_v1",
          email_oracle_kms_restart_binding: emailKmsRestartBinding(),
        },
      },
      arena_qvl: {
        ...trustBase({
          schema: "dnai.release-qvl-cvm.v1",
          appId: ARENA_QVL_APP_ID,
          cvmId: "cvm_arena_qvl_release",
          composeHash: ARENA_QVL_COMPOSE,
          suffix: "19",
          endpoint: "https://qvl-arena.release.wikigen.me/verify",
          image: trustImage("attestation-qvl", "8"),
        }),
        context: "arena",
        identity: {
          schema: "dnai.attestation-qvl-identity.v1",
          verifier_address: arenaQvl.address.toLowerCase(),
          release_policy_hash: ARENA_QVL_POLICY,
          signer_custody: "dstack_derived_separate_cvm",
          raw_secret_egress: false,
        },
        policy_binding: {
          chain_id: 84_532,
          contract_address: CHALLENGE,
          evaluated_app_id: MAIN_APP_ID,
          evaluated_compose_hash: `0x${COMPOSE}`,
          evaluated_os_image_hash: OS_IMAGE,
          allowed_signer_address: TEE,
          report_data_binding_kind: "arena_candidate_ingress_v1",
        },
      },
      anchor_writer_qvl: {
        ...trustBase({
          schema: "dnai.release-qvl-cvm.v1",
          appId: ANCHOR_WRITER_QVL_APP_ID,
          cvmId: "cvm_anchor_writer_qvl_release",
          composeHash: ANCHOR_WRITER_QVL_COMPOSE,
          suffix: "1b",
          endpoint: "https://qvl-anchor-writer.release.wikigen.me/verify",
          image: trustImage("attestation-qvl", "8"),
        }),
        context: "execution_policy_anchor_writer",
        identity: {
          schema: "dnai.attestation-qvl-identity.v1",
          verifier_address: anchorWriterQvl.address.toLowerCase(),
          release_policy_hash: ANCHOR_WRITER_QVL_POLICY,
          signer_custody: "dstack_derived_separate_cvm",
          raw_secret_egress: false,
        },
        policy_binding: {
          chain_id: 84_532,
          contract_address: EXECUTION_POLICY_ANCHOR,
          evaluated_app_id: MAIN_APP_ID,
          evaluated_compose_hash: `0x${COMPOSE}`,
          evaluated_os_image_hash: OS_IMAGE,
          allowed_signer_address: EXECUTION_POLICY_WRITER,
          report_data_binding_kind: "execution_policy_anchor_writer_v1",
          writer_release_commitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
          writer_key_path: "tinker/execution_policy_anchor_writer",
          writer_custody: "dstack_derived_execution_policy_anchor_writer",
        },
      },
      compute_metering_qvl: {
        ...trustBase({
          schema: "dnai.release-qvl-cvm.v1",
          appId: COMPUTE_METERING_QVL_APP_ID,
          cvmId: "cvm_compute_metering_qvl_release",
          composeHash: COMPUTE_METERING_QVL_COMPOSE,
          suffix: "1e",
          endpoint: "https://qvl-compute-metering.release.wikigen.me/verify",
          image: trustImage("attestation-qvl", "8"),
        }),
        context: "compute_metering",
        identity: {
          schema: "dnai.attestation-qvl-identity.v1",
          verifier_address: computeMeteringQvl.address.toLowerCase(),
          release_policy_hash: COMPUTE_METERING_QVL_POLICY,
          signer_custody: "dstack_derived_separate_cvm",
          raw_secret_egress: false,
        },
        policy_binding: {
          chain_id: 84_532,
          contract_address: COMPUTE,
          evaluated_app_id: COMPUTE_METERING_APP_ID,
          evaluated_compose_hash: `0x${METERING_COMPOSE}`,
          evaluated_os_image_hash: "1f".repeat(32),
          allowed_signer_address: COMPUTE_METERING_VERIFIER,
          report_data_binding_kind: "compute_metering_signer_v1",
          policy_set_hash: COMPUTE_POLICY_SET,
          signer_custody: "dstack_derived_independent_cvm",
        },
      },
      compute_workload_qvl: {
        ...trustBase({
          schema: "dnai.release-qvl-cvm.v1",
          appId: COMPUTE_WORKLOAD_QVL_APP_ID,
          cvmId: "cvm_compute_workload_qvl_release",
          composeHash: COMPUTE_WORKLOAD_QVL_COMPOSE,
          suffix: "22",
          endpoint: "https://qvl-compute-workload.release.wikigen.me/verify",
          image: trustImage("attestation-qvl", "8"),
        }),
        context: "compute_workload",
        identity: {
          schema: "dnai.attestation-qvl-identity.v1",
          verifier_address: computeWorkloadQvl.address.toLowerCase(),
          release_policy_hash: COMPUTE_WORKLOAD_QVL_POLICY,
          signer_custody: "dstack_derived_separate_cvm",
          raw_secret_egress: false,
        },
        policy_binding: {
          kind: "compute_workload_recipient_v1",
        },
      },
      compute_metering: {
        ...trustBase({
          schema: "dnai.release-compute-metering-cvm.v1",
          appId: COMPUTE_METERING_APP_ID,
          cvmId: COMPUTE_METERING_CVM_ID,
          composeHash: METERING_COMPOSE,
          suffix: "1c",
          endpoint: "https://metering.release.wikigen.me/meter",
          image: trustImage("compute-metering", "9"),
        }),
        identity: {
          schema: "dnai.compute-metering-identity.v1",
          classification: "attested_deterministic_metering",
          provider_authoritative_invoice: false,
          chain_id: 84_532,
          vault_address: COMPUTE,
          policy_set_hash: COMPUTE_POLICY_SET,
          metering_verifier: COMPUTE_METERING_VERIFIER,
          assets: [
            {
              asset: "0x0000000000000000000000000000000000000000",
              provider: COMPUTE_PROVIDER,
              rate_policy_commitment: NATIVE_RATE_POLICY,
            },
            {
              asset: USDC,
              provider: COMPUTE_ERC20_PROVIDER,
              rate_policy_commitment: ERC20_RATE_POLICY,
            },
          ],
          signer_custody: "dstack_derived_independent_cvm",
          raw_secret_egress: false,
        },
      },
    },
    wallet_auth: {
      domain: "www.wikigen.me",
      uri: "https://www.wikigen.me",
      walletconnect_project_id: "12".repeat(16),
    },
    execution_policy: {
      canonicalization_version: "policy-kernel-canonicalization/v2",
      approval_schema: "dnai-wikigen/execution-policy-approval/v3",
      api_schema_version: 3,
      store_schema_version: 6,
      approval_domain: EXECUTION_POLICY_APPROVAL_DOMAIN,
      approval_domain_hash: EXECUTION_POLICY_APPROVAL_DOMAIN_HASH,
      approver_hashes: [...EXECUTION_POLICY_APPROVER_HASHES],
      approver_root_hash: EXECUTION_POLICY_APPROVER_ROOT,
      rollback_anchor: {
        schema: "dnai.execution-policy-rollback-anchor.v1",
        status: "verified_active_frozen_release_writer",
        chain_id: 84_532,
        contract_address: EXECUTION_POLICY_ANCHOR,
        runtime_code_hash: keccak256(codes.execution_policy_anchor),
        release_manifest_commitment: EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT,
        evidence_sha256: EXECUTION_POLICY_EVIDENCE_PLACEHOLDER,
        writer_address: EXECUTION_POLICY_WRITER,
        writer_release_commitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
        writer_custody: "dstack_derived_execution_policy_anchor_writer",
        writer_key_path: "tinker/execution_policy_anchor_writer",
        confirmations: 12,
        max_block_age_seconds: 3_600,
        max_future_block_skew_seconds: 30,
        verification_model: "single_rpc_reported_finalized_with_confirmation_depth",
        independent_rpc_quorum_verified: false,
        consensus_proof_verified: false,
      },
    },
    attestations: { artifact, arena, compute_metering: computeMetering },
    arena_registry_bindings: {
      "synthetic-bio-assay-qc@1.0.0": {
        registry_challenge_id: "1",
        registry_version: 1,
        controller_address: OPERATOR,
        pending_controller_address: ZERO_ADDRESS,
        lifecycle: "open",
        paused: false,
        configuration_frozen: true,
        catalog_manifest_hash: ARENA_MANIFEST,
        metadata_uri: "ipfs://bafy-arena-release",
        metadata_hash: `0x${ARENA_MANIFEST}`,
        sealed_artifact_commitment: ARENA_SEALED,
        evaluator_commitment: ARENA_EVALUATOR,
        release_policy_commitment: ARENA_POLICY,
      },
    },
    requested_features: {
      contract_writes: true,
      artifact_upload: true,
      compute_console: true,
      tinker_customer: false,
      collaboration: false,
      compute_vault_funding: true,
      compute_vault_authorization: true,
      compute_workload_upload: false,
      arena_submission: true,
    },
  };
  const contractEntry = (key, status, extras = {}) => ({
    status,
    address: addresses[key],
    sourceCommit: SHA,
    runtimeCodeHash: keccak256(codes[key]),
    ...extras,
  });
  const ledger = {
    schemaVersion: 1,
    network: { name: "Base Sepolia", chainId: 84_532 },
    currentOperatorDeployer: {
      address: OPERATOR,
      keystoreAccount: "dev",
      fundingStatus: "verified_during_deployment_preflight",
      privateKeyMaterial: "not_used",
    },
    freshDeployment: {
      contractSuite: {
        status: "broadcast_complete_pending_cvm_binding",
        keystoreAccount: "dev",
        sourceCommit: SHA,
        deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
        reviewerAuthorityGenesisAcceptanceSha256:
          REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
        includesReviewedComputeCreditVault: true,
        excludesChallengePrizeAndCandidateCustodyContracts: true,
        runtimeCodeProof: "exact_creation_reexecution_match_all_contracts",
        diligencePolicyState: "fail_closed_pending_cvm_binding",
        computeVaultPolicyState: "execution_fail_closed_pending_timelocked_release_binding",
        emailOraclePolicyState: "deny_all_pending_cvm_binding",
        executionPolicyAnchorState: "anchoring_fail_closed_pending_timelocked_release_writer",
      },
    },
    contracts: {
      diligenceRoom: contractEntry("diligence_room", "deployed_fail_closed_pending_tee_binding", {
        developer: OPERATOR,
        pendingDeveloper: ZERO_ADDRESS,
        pendingDeveloperActivatesAt: 0,
        developerTransferDelaySeconds: 172_800,
        governanceHandoffStatus: "pending_final_authority_and_release_ceremony",
        resultVerifier: RESULT_VERIFIER,
        pendingResultVerifier: ZERO_ADDRESS,
        pendingResultVerifierActivatesAt: 0,
        resultVerifierFrozen: true,
        attestationVerifier: "0x0000000000000000000000000000000000000000",
        attestationReleasePolicyHash: `0x${"0".repeat(64)}`,
        pendingAttestationVerifier: "0x0000000000000000000000000000000000000000",
        pendingAttestationReleasePolicyHash: `0x${"0".repeat(64)}`,
        pendingAttestationBindingActivatesAt: 0,
        attestationBindingFrozen: false,
        feeBps: 100,
        feeBpsFrozen: true,
        computeSettlementBps: 100,
        computeSettlementPolicyEnabled: true,
        composeApprovalRequired: true,
        teeIdentityApprovalRequired: true,
        approvalRequirementsFrozen: true,
        evaluatorPolicyCommitments: [],
        evaluatorPolicySetRoot: `0x${"0".repeat(64)}`,
        approvedEvaluatorPolicyCount: 0,
        pendingEvaluatorPolicyCount: 0,
        evaluatorPolicySetFrozen: false,
        pendingEvaluatorPolicyProposals: [],
        approvedComposeCount: 0,
        approvedTeeIdentityCount: 0,
        pendingComposeCount: 0,
        pendingTeeIdentityCount: 0,
        composeAdditionsFrozen: false,
        teeIdentityAdditionsFrozen: false,
        initialApprovedComposeHashes: [],
        initialApprovedTeeIdentities: [],
        policyState: "fail_closed_pending_cvm_binding",
      }),
      challengeRegistry: contractEntry("challenge_registry", "deployed_empty_active_registry", { owner: OPERATOR }),
      royaltyDistributor: contractEntry(
        "royalty_distributor",
        "deployed_paused_unbound_pending_royalty_release",
        {
          owner: OPERATOR,
          pendingOwner: "0x0000000000000000000000000000000000000000",
          paused: true,
          settlementVerifier: "0x0000000000000000000000000000000000000000",
          qvlVerifier: "0x0000000000000000000000000000000000000000",
          executionPolicyAnchor: "0x0000000000000000000000000000000000000000",
          anchorWriterReleaseCommitment: `0x${"0".repeat(64)}`,
          releasePolicyCommitment: `0x${"0".repeat(64)}`,
          authorityNonce: 0,
          pendingAuthorityActivatesAt: 0,
          settlementReplayDomain: "global_settlement_id_and_global_settlement_nonce",
          policyState: "settlements_fail_closed_pending_dual_signer_anchor_release",
        },
      ),
      tinkerAccountEncumbrance: contractEntry(
        "tinker_account_encumbrance",
        "deployed_exact_release_policy_frozen_active",
        {
          deploymentTx: TINKER_DEPLOYMENT_TX,
          ...tinkerActiveLedgerState(),
        },
      ),
      computeCreditVault: contractEntry(
        "compute_credit_vault",
        "deployed_paused_fee_frozen_unbound_pending_release_binding",
        {
          owner: OPERATOR,
          developer: COMPUTE_DEVELOPER,
          meteringVerifier: "0x0000000000000000000000000000000000000000",
          meteringQvlVerifier: "0x0000000000000000000000000000000000000000",
          meteringPolicySetHash: `0x${"0".repeat(64)}`,
          pendingMeteringVerifier: "0x0000000000000000000000000000000000000000",
          pendingMeteringQvlVerifier: "0x0000000000000000000000000000000000000000",
          pendingMeteringPolicySetHash: `0x${"0".repeat(64)}`,
          pendingMeteringBindingActivatesAt: 0,
          meteringBindingFrozen: false,
          paused: true,
          developerFeeBps: 100,
          developerFeeFrozen: true,
          allowedAssetCount: 0,
          activeRatePolicyCount: 0,
          approvedComposeCount: 0,
          approvedTeeIdentityCount: 0,
          pendingAssetCount: 0,
          pendingRatePolicyCount: 0,
          pendingComposeCount: 0,
          pendingTeeIdentityCount: 0,
          approvedComposeHashes: [],
          approvedTeeIdentities: [],
          activeRatePolicies: [],
          enabledErc20Assets: [],
          nativeFundingSupported: true,
          creditsTransferable: false,
          priceOracle: false,
          composePolicyFrozen: false,
          teeIdentityAdditionsFrozen: false,
          ratePolicyAdditionsFrozen: false,
          assetAdditionsFrozen: false,
          policyState: "execution_fail_closed_pending_timelocked_release_binding",
        },
      ),
      emailOracleAuth: contractEntry("email_oracle_auth", "deployed_deny_all_pending_cvm_binding", {
        owner: OPERATOR,
        runtimeCodeHash: keccak256(codes.email_oracle_auth),
        oracleUpgradeDelaySeconds: EMAIL_ORACLE_UPGRADE_DELAY_SECONDS,
        allowAnyDevice: false,
        oracleCodeFrozen: false,
        consumerRegistryFrozen: false,
        initialOracleComposeHash: null,
        initialDeviceId: null,
        initialConsumerBindings: [],
        policyState: "deny_all_pending_cvm_binding",
      }),
      executionPolicyAnchor: contractEntry(
        "execution_policy_anchor",
        "verified_active_frozen_release_writer",
        {
          owner: OPERATOR,
          deploymentIntentSha256Bytes32:
            `0x${DEPLOYMENT_INTENT_SHA256.slice("sha256:".length)}`,
          reviewerAuthorityGenesisAcceptanceSha256Bytes32:
            `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
          writer: EXECUTION_POLICY_WRITER,
          writerReleaseCommitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
          pendingWriter: "0x0000000000000000000000000000000000000000",
          pendingWriterReleaseCommitment: `0x${"0".repeat(64)}`,
          pendingWriterActivatesAt: 0,
          writerRotationDelaySeconds: 172800,
          writerRotationsFrozen: true,
          paused: false,
          globalSequence: 0,
          globalHead: `0x${"0".repeat(64)}`,
          releaseSnapshotBlockNumber: 12_345,
          resourceAndDecisionPayloadsOnChain: false,
          opaqueCommitmentsOnly: true,
          policyState: "anchoring_active_frozen_release_writer",
        },
      ),
    },
    deploymentHistory: [{
      kind: "fresh_reviewed_scope_contract_suite",
      sourceCommit: SHA,
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      operator: OPERATOR,
      resultVerifier: ZERO_ADDRESS,
      deployedContracts: {
        diligenceRoom: {
          address: DILIGENCE,
          runtimeCodeHash: keccak256(codes.diligence_room),
          resultVerifier: ZERO_ADDRESS,
          pendingResultVerifier: ZERO_ADDRESS,
          pendingResultVerifierActivatesAt: 0,
          resultVerifierFrozen: false,
          feeBps: 100,
          feeBpsFrozen: true,
          computeSettlementBps: 100,
          computeSettlementPolicyEnabled: true,
          composeApprovalRequired: true,
          teeIdentityApprovalRequired: true,
          approvalRequirementsFrozen: true,
          attestationVerifier: "0x0000000000000000000000000000000000000000",
          attestationReleasePolicyHash: `0x${"0".repeat(64)}`,
          pendingAttestationVerifier: "0x0000000000000000000000000000000000000000",
          pendingAttestationReleasePolicyHash: `0x${"0".repeat(64)}`,
          pendingAttestationBindingActivatesAt: 0,
          attestationBindingFrozen: false,
          evaluatorPolicyCommitments: [],
          evaluatorPolicySetRoot: `0x${"0".repeat(64)}`,
          approvedEvaluatorPolicyCount: 0,
          pendingEvaluatorPolicyCount: 0,
          evaluatorPolicySetFrozen: false,
          pendingEvaluatorPolicyProposals: [],
          approvedComposeCount: 0,
          approvedTeeIdentityCount: 0,
          pendingComposeCount: 0,
          pendingTeeIdentityCount: 0,
          composeAdditionsFrozen: false,
          teeIdentityAdditionsFrozen: false,
          initialApprovedComposeHashes: [],
          initialApprovedTeeIdentities: [],
          policyState: "fail_closed_pending_cvm_binding",
        },
        challengeRegistry: {
          address: CHALLENGE,
          runtimeCodeHash: keccak256(codes.challenge_registry),
        },
        royaltyDistributor: {
          address: ROYALTY,
          runtimeCodeHash: keccak256(codes.royalty_distributor),
        },
        tinkerAccountEncumbrance: {
          address: ENCUMBRANCE,
          deploymentTx: TINKER_DEPLOYMENT_TX,
          runtimeCodeHash: keccak256(codes.tinker_account_encumbrance),
          ...tinkerDraftLedgerState(),
        },
        computeCreditVault: {
          status: "deployed_paused_fee_frozen_unbound_pending_release_binding",
          address: COMPUTE,
          runtimeCodeHash: keccak256(codes.compute_credit_vault),
          owner: OPERATOR,
          developer: COMPUTE_DEVELOPER,
          meteringVerifier: "0x0000000000000000000000000000000000000000",
          meteringQvlVerifier: "0x0000000000000000000000000000000000000000",
          meteringPolicySetHash: `0x${"0".repeat(64)}`,
          pendingMeteringVerifier: "0x0000000000000000000000000000000000000000",
          pendingMeteringQvlVerifier: "0x0000000000000000000000000000000000000000",
          pendingMeteringPolicySetHash: `0x${"0".repeat(64)}`,
          pendingMeteringBindingActivatesAt: 0,
          meteringBindingFrozen: false,
          paused: true,
          developerFeeBps: 100,
          developerFeeFrozen: true,
          allowedAssetCount: 0,
          activeRatePolicyCount: 0,
          approvedComposeCount: 0,
          approvedTeeIdentityCount: 0,
          pendingAssetCount: 0,
          pendingRatePolicyCount: 0,
          pendingComposeCount: 0,
          pendingTeeIdentityCount: 0,
          composePolicyFrozen: false,
          teeIdentityAdditionsFrozen: false,
          ratePolicyAdditionsFrozen: false,
          assetAdditionsFrozen: false,
          policyState: "execution_fail_closed_pending_timelocked_release_binding",
        },
        emailOracleAuth: {
          status: "deployed_deny_all_pending_cvm_binding",
          address: EMAIL,
          owner: OPERATOR,
          runtimeCodeHash: keccak256(codes.email_oracle_auth),
          allowAnyDevice: false,
          oracleCodeFrozen: false,
          consumerRegistryFrozen: false,
          policyState: "deny_all_pending_cvm_binding",
        },
        executionPolicyAnchor: {
          status: "deployed_paused_writer_unset_pending_timelocked_release_binding",
          address: EXECUTION_POLICY_ANCHOR,
          runtimeCodeHash: keccak256(codes.execution_policy_anchor),
          owner: OPERATOR,
          deploymentIntentSha256Bytes32:
            `0x${DEPLOYMENT_INTENT_SHA256.slice("sha256:".length)}`,
          reviewerAuthorityGenesisAcceptanceSha256Bytes32:
            `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
          writer: "0x0000000000000000000000000000000000000000",
          writerReleaseCommitment: `0x${"0".repeat(64)}`,
          pendingWriter: "0x0000000000000000000000000000000000000000",
          pendingWriterReleaseCommitment: `0x${"0".repeat(64)}`,
          pendingWriterActivatesAt: 0,
          writerRotationsFrozen: false,
          paused: true,
          globalSequence: 0,
          globalHead: `0x${"0".repeat(64)}`,
          policyState: "anchoring_fail_closed_pending_timelocked_release_writer",
        },
      },
    }],
    tinkerReleaseHistory: tinkerReleaseHistoryRecords(),
    phala: {
      cvmId: MAIN_CVM_ID,
      appId: MAIN_APP_ID,
      composeHash: COMPOSE,
      localRawComposeImagePolicyHash: LOCAL_COMPOSE,
      renderedComposeSha256: RENDERED_COMPOSE,
      osImageHash: OS_IMAGE,
      osIsDev: false,
      publicLogs: false,
      publicSysinfo: false,
      publicTcbinfo: false,
      sourceDigest: SHA,
      endpoints: {
        delegate: "https://delegate.release.wikigen.me",
      },
      imageDigests: images.map((image) => ({
        service: image.service,
        image: image.image,
        githubProvenanceAttestation: "verified",
        githubSbomAttestation: "verified",
      })),
    },
  };
  const deploymentEvidence = (context, verdict) => ({
    schema: "dnai.deployment.evidence.v2",
    api_url: "https://delegate.release.wikigen.me",
    context,
    status: "evidence_checked_tdx_unverified",
    images: images.map((image) => ({
      image: image.image,
      repo: image.repo,
      signer_workflow: image.signer_workflow,
      source_digest: image.source_digest,
      source_ref: image.source_ref,
      provenance_attestation: "verified",
      sbom_attestation: "verified",
    })),
    cvm: {
      api_url: "https://delegate.release.wikigen.me",
      context,
      mode: "tdx",
      compose_hash: LOCAL_COMPOSE,
      attested_compose_hash: COMPOSE,
      rendered_compose_sha256: RENDERED_COMPOSE,
      images: images.map((image) => ({ service: image.service, image: image.image })),
      app_id: MAIN_APP_ID,
      os_image_hash: OS_IMAGE,
      report_data: verdict.verdict.report_data.slice(2),
      encryption_public_key: context === "artifact" ? "ab".repeat(32) : "cd".repeat(32),
      quote_size: 5_010,
      fetched_at: NOW,
      quote_verification: "public-envelope-only; Intel TDX quote internals not parsed",
    },
    checks: {
      github_provenance_attestations: "verified_by_github_cli",
      github_sbom_attestations: "verified_by_github_cli",
      digest_pinned_compose: "matched_expected_inputs",
      cvm_attestation_envelope: "matched_claimed_identity_not_cryptographically_verified",
      intel_tdx_quote: "not_verified_no_independent_qvl_verdict",
      raw_secret_egress: false,
    },
    claims: {
      intel_tdx_quote_verified: false,
      independent_attestation_verdict_present: false,
      production_authorization_allowed: false,
    },
  });
  const anchorVerdict = await signedVerdict({
    context: "anchor_writer",
    quoteByte: "a",
    reportData: anchorWriterReportData(),
    contract: EXECUTION_POLICY_ANCHOR,
    signer: anchorWriterQvl,
    signerAddress: EXECUTION_POLICY_WRITER,
    profile: "execution_policy_anchor_writer",
    releasePolicyHash: ANCHOR_WRITER_QVL_POLICY,
  });
  const anchorWriterEvidence = {
    schema: "dnai.execution-policy-anchor-writer-qvl-evidence.v2",
    status: "independent_qvl_verified",
    chain_id: 84_532,
    anchor_address: EXECUTION_POLICY_ANCHOR.toLowerCase(),
    writer_address: EXECUTION_POLICY_WRITER.toLowerCase(),
    writer_release_commitment: `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
    writer_key_path: "tinker/execution_policy_anchor_writer",
    writer_key_path_sha256: createHash("sha256")
      .update(Buffer.from("dnai-wikigen/execution-policy-anchor-writer-key-path/v1\0", "utf8"))
      .update(Buffer.from("tinker/execution_policy_anchor_writer", "ascii"))
      .digest("hex"),
    writer_custody: "dstack_derived_execution_policy_anchor_writer",
    app_id: MAIN_APP_ID,
    compose_hash: `0x${COMPOSE}`,
    os_image_hash: OS_IMAGE,
    report_data: anchorVerdict.verdict.report_data,
    quote_report_data:
      `${anchorVerdict.verdict.report_data}${anchorVerdict.verdict.challenge_digest.slice(2)}`,
    quote_sha256: anchorVerdict.quote_sha256,
    quote_size: 2_048,
    qvl_release_policy_hash: ANCHOR_WRITER_QVL_POLICY,
    qvl_verifier_address: anchorWriterQvl.address.toLowerCase(),
    qvl_verdict: anchorVerdict.verdict,
    verification_method: "intel_tdx_dcap_qvl",
    tdx_measurement_policy: "exact_release_pinned_measurements",
    raw_quote_egress: "authenticated_https_qvl_only",
    raw_quote_in_artifact: false,
    raw_private_key_egress: false,
  };
  const anchorWriterEvidenceBytes = Buffer.from(
    `${canonicalJson(anchorWriterEvidence)}\n`,
    "ascii",
  );
  candidate.execution_policy.rollback_anchor.evidence_sha256 =
    `sha256:${createHash("sha256").update(anchorWriterEvidenceBytes).digest("hex")}`;
  const emailRestartVerdict = await signedVerdict({
    context: "email_oracle_kms_restart",
    quoteByte: "7",
    reportData: emailKmsRestartReportData(),
    contract: DILIGENCE,
    signer: diligenceQvl,
    signerAddress: TEE,
    profile: "email_oracle_kms_restart",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
  });
  const emailOracleEvidence = {
    schema: "dnai.email-oracle-external-release-evidence.v1",
    status: "external_evidence_verified",
    chain_id: 84_532,
    release_sha: SHA,
    email_oracle_auth: EMAIL.toLowerCase(),
    main_cvm: {
      compose_hash: `0x${COMPOSE}`,
      consumer_app_id: TEE.toLowerCase(),
      cvm_id: MAIN_CVM_ID,
      device_id: EMAIL_DEVICE,
    },
    kms: {
      contract_address: KMS.toLowerCase(),
      implementation_address: KMS_IMPLEMENTATION.toLowerCase(),
      implementation_runtime_code_hash: keccak256(codes.kms_implementation),
      kms_eip1967_implementation_slot_word:
        `0x${"0".repeat(24)}${KMS_IMPLEMENTATION.toLowerCase().slice(2)}`,
      runtime_code_hash: keccak256(codes.kms),
      source_commit: "d".repeat(40),
      source_repository: "https://github.com/Dstack-TEE/dstack",
      verification_status: "verified_source_and_runtime",
      verification_url: "https://sepolia.basescan.org/address/0xf200000000000000000000000000000000000002",
    },
    registration: {
      block_hash: KMS_REGISTRATION_BLOCK_HASH,
      block_number: KMS_REGISTRATION_BLOCK,
      registered_apps_readback: true,
      transaction_hash: KMS_REGISTRATION_TX,
    },
    target_boot: {
      advisory_ids: [],
      instance_id: BOOT_INSTANCE.toLowerCase(),
      kms_is_app_allowed: true,
      mr_aggregated: EMAIL_BOOT_MR_AGGREGATED,
      mr_system: EMAIL_BOOT_MR_SYSTEM,
      os_image_hash: `0x${OS_IMAGE}`,
      tcb_status: "UpToDate",
    },
    restart_key_derivation: {
      derive_key_succeeded_after: true,
      derive_key_succeeded_before: true,
      key_path: "email/creds",
      post_restart_commitment: EMAIL_RESTART_COMMITMENT,
      pre_restart_commitment: EMAIL_RESTART_COMMITMENT,
      raw_key_egress: false,
      raw_secret_egress: false,
      restart_proof_hash: EMAIL_RESTART_PROOF_HASH,
      restart_observed: true,
      status: "verified_after_real_cvm_restart",
    },
    qvl_verification: {
      status: "independent_qvl_verified",
      quote_sha256: emailRestartVerdict.quote_sha256,
      qvl_release_policy_hash: DILIGENCE_QVL_POLICY,
      qvl_verifier_address: diligenceQvl.address.toLowerCase(),
      qvl_verdict: emailRestartVerdict.verdict,
      verification_method: "intel_tdx_dcap_qvl",
    },
  };
  const emailOracleEvidenceBytes = Buffer.from(
    `${canonicalJson(emailOracleEvidence)}\n`,
    "utf8",
  );
  candidate.contracts.email_oracle_auth.release.external_evidence_sha256 =
    `0x${createHash("sha256").update(emailOracleEvidenceBytes).digest("hex")}`;
  return {
    candidate,
    ledger,
    authorityBinding: {
      deploymentIntentSha256: DEPLOYMENT_INTENT_SHA256,
      reviewerAuthorityGenesisAcceptanceSha256:
        REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256,
      ceremonyAuthorizationSha256: CEREMONY_AUTHORIZATION_SHA256,
      runtimeAuthorityDependencySha256:
        `sha256:${EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT}`,
    },
    artifactEvidence: deploymentEvidence("artifact", artifact),
    arenaEvidence: deploymentEvidence("arena", arena),
    anchorWriterEvidence,
    anchorWriterEvidenceBytes,
    emailOracleEvidence,
    emailOracleEvidenceBytes,
  };
}

function fakeClient(candidate, overrides = {}) {
  const addressToKey = new Map(Object.entries(addresses).map(([key, value]) => [value.toLowerCase(), key]));
  return {
    async getChainId() {
      return overrides.chainId ?? 84_532;
    },
    async getBlockNumber() {
      return overrides.headBlockNumber ?? 12_356n;
    },
    async getBlock(request) {
      overrides.observe?.("getBlock", request);
      if (request.blockTag === "finalized") {
        const head = overrides.headBlockNumber ?? 12_356n;
        return {
          number: overrides.finalizedBlockNumber ?? head - 1n,
          timestamp: BigInt(overrides.finalizedBlockTimestamp ?? NOW - 4),
          hash: overrides.finalizedBlockHash ?? `0x${"98".repeat(32)}`,
        };
      }
      if (request.blockNumber === BigInt(KMS_REGISTRATION_BLOCK)) {
        return {
          number: BigInt(KMS_REGISTRATION_BLOCK),
          timestamp: BigInt(NOW - 100),
          hash: overrides.registrationBlockHash ?? KMS_REGISTRATION_BLOCK_HASH,
          ...overrides.registrationBlockHeader,
        };
      }
      return {
        number: request.blockNumber,
        timestamp: BigInt(overrides.blockTimestamp ?? NOW - 2),
        hash: overrides.snapshotBlockHash ?? `0x${"99".repeat(32)}`,
      };
    },
    async getBytecode(request) {
      overrides.observe?.("getBytecode", request);
      const { address } = request;
      const key = addressToKey.get(address.toLowerCase());
      return overrides.code?.[key] ?? codes[key];
    },
    async getStorageAt(request) {
      overrides.observe?.("getStorageAt", request);
      return overrides.kmsImplementationSlot
        ?? `0x${"0".repeat(24)}${KMS_IMPLEMENTATION.slice(2).toLowerCase()}`;
    },
    async getTransactionReceipt(request) {
      overrides.observe?.("getTransactionReceipt", request);
      return {
        status: "success",
        to: KMS,
        transactionHash: KMS_REGISTRATION_TX,
        blockNumber: BigInt(KMS_REGISTRATION_BLOCK),
        blockHash: KMS_REGISTRATION_BLOCK_HASH,
        logs: [{
          address: KMS,
          topics: [keccak256(toHex("AppRegistered(address)"))],
          data: encodeAbiParameters([{ type: "address" }], [EMAIL]),
        }],
        ...overrides.registrationReceipt,
      };
    },
    async getTransaction(request) {
      overrides.observe?.("getTransaction", request);
      return {
        hash: KMS_REGISTRATION_TX,
        to: KMS,
        blockNumber: BigInt(KMS_REGISTRATION_BLOCK),
        input: encodeFunctionData({
          abi: DSTACK_KMS_TEST_ABI,
          functionName: "registerApp",
          args: [EMAIL],
        }),
        ...overrides.registrationTransaction,
      };
    },
    async readContract(request) {
      overrides.observe?.("readContract", request);
      const { address, functionName } = request;
      const key = addressToKey.get(address.toLowerCase());
      const override = overrides.read?.[`${key}.${functionName}`];
      if (override !== undefined) return override;
      const values = {
        "diligence_room.developer": DILIGENCE_GOVERNANCE,
        "diligence_room.initialDeveloper": OPERATOR,
        "diligence_room.releaseGovernanceController": DILIGENCE_GOVERNANCE,
        "diligence_room.pendingDeveloper": ZERO_ADDRESS,
        "diligence_room.pendingDeveloperActivatesAt": 0n,
        "diligence_room.DEVELOPER_TRANSFER_DELAY": 172_800n,
        "diligence_room.resultVerifier": RESULT_VERIFIER,
        "diligence_room.attestationVerifier": diligenceQvl.address.toLowerCase(),
        "diligence_room.attestationReleasePolicyHash": DILIGENCE_QVL_POLICY,
        "diligence_room.pendingAttestationVerifier": "0x0000000000000000000000000000000000000000",
        "diligence_room.pendingAttestationReleasePolicyHash": `0x${"0".repeat(64)}`,
        "diligence_room.pendingAttestationBindingActivatesAt": 0n,
        "diligence_room.attestationBindingFrozen": true,
        "diligence_room.approvedEvaluatorPolicyCount": 3n,
        "diligence_room.pendingEvaluatorPolicyCount": 0n,
        "diligence_room.evaluatorPolicySetFrozen": true,
        "diligence_room.evaluatorPolicySetRoot": DILIGENCE_EVALUATOR_POLICY_SET_ROOT,
        "diligence_room.evaluatorPolicies": [...DILIGENCE_EVALUATOR_POLICIES],
        "diligence_room.approvedEvaluatorPolicies": true,
        "diligence_room.pendingEvaluatorPolicyActivations": 0n,
        "diligence_room.feeBps": 100n,
        "diligence_room.feeBpsFrozen": true,
        "diligence_room.pendingFeeBpsActivatesAt": 0n,
        "diligence_room.COMPUTE_SETTLEMENT_BPS": 100n,
        "diligence_room.computeSettlementPolicyEnabled": true,
        "diligence_room.composeApprovalRequired": true,
        "diligence_room.teeIdentityApprovalRequired": true,
        "diligence_room.approvalRequirementsFrozen": true,
        "diligence_room.composeAdditionsFrozen": true,
        "diligence_room.teeIdentityAdditionsFrozen": true,
        "diligence_room.approvedComposeCount": 1n,
        "diligence_room.approvedTeeIdentityCount": 1n,
        "diligence_room.pendingComposeCount": 0n,
        "diligence_room.pendingTeeIdentityCount": 0n,
        "diligence_room.approvedComposeHashes": true,
        "diligence_room.teeIdentityComposeHash": `0x${COMPOSE}`,
        "challenge_registry.owner": OPERATOR,
        "challenge_registry.pendingOwner": ZERO_ADDRESS,
        "challenge_registry.registryPaused": false,
        "challenge_registry.challengeCount": 1n,
        "challenge_registry.nextChallengeId": 2n,
        "challenge_registry.MIN_VERSION_REVIEW_DELAY": 172_800n,
        "challenge_registry.challengeExists": true,
        "challenge_registry.reviewEligibleAt": 172_801n,
        "challenge_registry.getChallenge": {
          controller: OPERATOR,
          pendingController: "0x0000000000000000000000000000000000000000",
          lifecycle: 1,
          createdAt: 1n,
          updatedAt: 2n,
          latestVersion: 1,
          paused: false,
          configurationFrozen: true,
        },
        "challenge_registry.getVersion": {
          metadataURI: "ipfs://bafy-arena-release",
          metadataHash: `0x${ARENA_MANIFEST}`,
          sealedArtifactCommitment: ARENA_SEALED,
          evaluatorCommitment: ARENA_EVALUATOR,
          releasePolicyCommitment: ARENA_POLICY,
          createdAt: 1n,
        },
        "tinker_account_encumbrance.owner": OPERATOR,
        "tinker_account_encumbrance.pendingOwner": "0x0000000000000000000000000000000000000000",
        "tinker_account_encumbrance.accountCommitment": ACCOUNT_COMMITMENT,
        "tinker_account_encumbrance.maxAddBalanceWei": BigInt(TINKER_MAX_ADD_BALANCE_WEI),
        "tinker_account_encumbrance.maxSpendWei": BigInt(TINKER_MAX_SPEND_WEI),
        "tinker_account_encumbrance.approvedComposeRoot": TINKER_COMPOSE_ROOT,
        "tinker_account_encumbrance.approvedComposeCount": 1n,
        "tinker_account_encumbrance.approvedComposeHashAt": `0x${COMPOSE}`,
        "tinker_account_encumbrance.managerRoot": TINKER_MANAGER_ROOT,
        "tinker_account_encumbrance.managerCount": 1n,
        "tinker_account_encumbrance.managerAt": TEE,
        "tinker_account_encumbrance.releasePolicyCommitment": TINKER_RELEASE_POLICY,
        "tinker_account_encumbrance.releaseMaxAddBalanceWei": BigInt(TINKER_MAX_ADD_BALANCE_WEI),
        "tinker_account_encumbrance.releaseMaxSpendWei": BigInt(TINKER_MAX_SPEND_WEI),
        "tinker_account_encumbrance.releaseComposeRoot": TINKER_COMPOSE_ROOT,
        "tinker_account_encumbrance.releaseComposeCount": 1n,
        "tinker_account_encumbrance.releaseManagerRoot": TINKER_MANAGER_ROOT,
        "tinker_account_encumbrance.releaseManagerCount": 1n,
        "tinker_account_encumbrance.releasePolicyFrozen": true,
        "tinker_account_encumbrance.pendingAccountCommitment": `0x${"0".repeat(64)}`,
        "tinker_account_encumbrance.pendingMaxAddBalanceWei": 0n,
        "tinker_account_encumbrance.pendingMaxSpendWei": 0n,
        "tinker_account_encumbrance.pendingComposeRoot": `0x${"0".repeat(64)}`,
        "tinker_account_encumbrance.pendingManagerRoot": `0x${"0".repeat(64)}`,
        "tinker_account_encumbrance.pendingReleasePolicyCommitment": `0x${"0".repeat(64)}`,
        "tinker_account_encumbrance.pendingReleasePolicyActivatesAt": 0n,
        "tinker_account_encumbrance.pendingComposeCount": 0n,
        "tinker_account_encumbrance.pendingManagerCount": 0n,
        "tinker_account_encumbrance.RELEASE_POLICY_DELAY": 172_800n,
        "tinker_account_encumbrance.approvedComposeHashes": true,
        "tinker_account_encumbrance.managers": true,
        "tinker_account_encumbrance.emergencyHalted": false,
        "compute_credit_vault.owner": OPERATOR,
        "compute_credit_vault.developer": COMPUTE_DEVELOPER,
        "compute_credit_vault.meteringVerifier": COMPUTE_METERING_VERIFIER,
        "compute_credit_vault.meteringQvlVerifier": computeMeteringQvl.address,
        "compute_credit_vault.meteringPolicySetHash": COMPUTE_POLICY_SET,
        "compute_credit_vault.pendingMeteringVerifier": "0x0000000000000000000000000000000000000000",
        "compute_credit_vault.pendingMeteringQvlVerifier": "0x0000000000000000000000000000000000000000",
        "compute_credit_vault.pendingMeteringPolicySetHash": `0x${"0".repeat(64)}`,
        "compute_credit_vault.pendingMeteringBindingActivatesAt": 0n,
        "compute_credit_vault.meteringBindingFrozen": true,
        "compute_credit_vault.paused": false,
        "compute_credit_vault.developerFeeBps": 100,
        "compute_credit_vault.developerFeeFrozen": true,
        "compute_credit_vault.pendingDeveloperFeeActivatesAt": 0n,
        "compute_credit_vault.composePolicyFrozen": true,
        "compute_credit_vault.teeIdentityAdditionsFrozen": true,
        "compute_credit_vault.ratePolicyAdditionsFrozen": true,
        "compute_credit_vault.assetAdditionsFrozen": true,
        "compute_credit_vault.allowedAssetCount": 1n,
        "compute_credit_vault.activeRatePolicyCount": 2n,
        "compute_credit_vault.approvedComposeCount": 1n,
        "compute_credit_vault.approvedTeeIdentityCount": 1n,
        "compute_credit_vault.pendingAssetCount": 0n,
        "compute_credit_vault.pendingRatePolicyCount": 0n,
        "compute_credit_vault.pendingComposeCount": 0n,
        "compute_credit_vault.pendingTeeIdentityCount": 0n,
        "compute_credit_vault.approvedComposeHashes": true,
        "compute_credit_vault.teeIdentityComposeHash": `0x${COMPOSE}`,
        "compute_credit_vault.allowedAssets": true,
        "compute_credit_vault.ratePolicies": request.args?.[0] === NATIVE_RATE_POLICY
          ? {
              asset: "0x0000000000000000000000000000000000000000",
              provider: COMPUTE_PROVIDER,
              developerFeeBps: 100,
              active: true,
            }
          : {
              asset: USDC,
              provider: COMPUTE_ERC20_PROVIDER,
              developerFeeBps: 100,
              active: true,
            },
        "email_oracle_auth.owner": OPERATOR,
        "email_oracle_auth.pendingOwner": "0x0000000000000000000000000000000000000000",
        "email_oracle_auth.ORACLE_UPGRADE_DELAY": BigInt(EMAIL_ORACLE_UPGRADE_DELAY_SECONDS),
        "email_oracle_auth.allowAnyDevice": false,
        "email_oracle_auth.oracleCodeFrozen": true,
        "email_oracle_auth.consumerRegistryFrozen": true,
        "email_oracle_auth.consumerManagerAdditionsFrozen": true,
        "email_oracle_auth.kmsBindingFrozen": true,
        "email_oracle_auth.allowedOracleComposeHashCount": 1n,
        "email_oracle_auth.pendingOracleComposeHashCount": 0n,
        "email_oracle_auth.allowedDeviceIdCount": 1n,
        "email_oracle_auth.consumerManagerCount": 1n,
        "email_oracle_auth.totalConsumerComposeHashCount": 1n,
        "email_oracle_auth.releaseOracleComposeHash": `0x${COMPOSE}`,
        "email_oracle_auth.releaseDeviceId": EMAIL_DEVICE,
        "email_oracle_auth.releaseConsumerManager": TEE,
        "email_oracle_auth.releaseConsumerAppId": TEE,
        "email_oracle_auth.releaseConsumerComposeHash": `0x${COMPOSE}`,
        "email_oracle_auth.allowedOracleComposeHashes": true,
        "email_oracle_auth.allowedDeviceIds": true,
        "email_oracle_auth.consumerManagers": true,
        "email_oracle_auth.consumerEmergencyRevoked": false,
        "email_oracle_auth.consumerComposeHashCount": 1n,
        "email_oracle_auth.isConsumerAuthorized": true,
        "email_oracle_auth.kmsContract": KMS,
        "email_oracle_auth.kmsRuntimeCodeHash": keccak256(codes.kms),
        "email_oracle_auth.kmsImplementation": KMS_IMPLEMENTATION,
        "email_oracle_auth.kmsImplementationRuntimeCodeHash": keccak256(codes.kms_implementation),
        "email_oracle_auth.kmsRegistrationTxHash": KMS_REGISTRATION_TX,
        "email_oracle_auth.kmsRegistrationBlock": BigInt(KMS_REGISTRATION_BLOCK),
        "email_oracle_auth.kmsRegistrationBlockHash": KMS_REGISTRATION_BLOCK_HASH,
        "email_oracle_auth.targetBootInfoHash": emailTargetBootInfoHash(),
        "email_oracle_auth.restartKeyDerivationProofHash":
          candidate.contracts.email_oracle_auth.release.restart_key_derivation_proof_hash,
        "email_oracle_auth.pendingKmsContract": "0x0000000000000000000000000000000000000000",
        "email_oracle_auth.pendingKmsRuntimeCodeHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingKmsImplementation": "0x0000000000000000000000000000000000000000",
        "email_oracle_auth.pendingKmsImplementationRuntimeCodeHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingKmsRegistrationTxHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingKmsRegistrationBlock": 0n,
        "email_oracle_auth.pendingKmsRegistrationBlockHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingTargetBootInfoHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingRestartKeyDerivationProofHash": `0x${"0".repeat(64)}`,
        "email_oracle_auth.pendingKmsBindingActivatesAt": 0n,
        "email_oracle_auth.releaseConfigurationReady": true,
        "kms.registeredApps": true,
        "kms.isAppAllowed": [true, ""],
        "execution_policy_anchor.owner": OPERATOR,
        "execution_policy_anchor.deploymentIntentSha256":
          `0x${DEPLOYMENT_INTENT_SHA256.slice("sha256:".length)}`,
        "execution_policy_anchor.reviewerAuthorityGenesisAcceptanceSha256":
          `0x${REVIEWER_AUTHORITY_GENESIS_ACCEPTANCE_SHA256.slice("sha256:".length)}`,
        "execution_policy_anchor.writer": EXECUTION_POLICY_WRITER,
        "execution_policy_anchor.writerReleaseCommitment": `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
        "execution_policy_anchor.pendingWriter": "0x0000000000000000000000000000000000000000",
        "execution_policy_anchor.pendingWriterReleaseCommitment": `0x${"0".repeat(64)}`,
        "execution_policy_anchor.pendingWriterActivatesAt": 0n,
        "execution_policy_anchor.writerRotationsFrozen": true,
        "execution_policy_anchor.paused": false,
        "execution_policy_anchor.globalSequence": 0n,
        "execution_policy_anchor.globalHead": `0x${"0".repeat(64)}`,
        "usdc.symbol": "USDC",
        "usdc.decimals": 6,
      };
      if (!( `${key}.${functionName}` in values)) throw new Error(`unexpected read ${key}.${functionName}`);
      return values[`${key}.${functionName}`];
    },
  };
}

async function build(input, overrides = {}, rpcOverrides = {}) {
  return buildWithTrusted(
    input,
    [
      diligenceQvl.address,
      arenaQvl.address,
      anchorWriterQvl.address,
      computeMeteringQvl.address,
      computeWorkloadQvl.address,
    ],
    overrides,
    rpcOverrides,
  );
}

async function buildWithTrusted(
  input,
  trustedVerifierAddresses,
  overrides = {},
  rpcOverrides = {},
) {
  return buildReleaseEnv({
    candidate: input.candidate,
    ledger: input.ledger,
    artifactEvidence: input.artifactEvidence,
    arenaEvidence: input.arenaEvidence,
    anchorWriterEvidence: input.anchorWriterEvidence,
    anchorWriterEvidenceBytes: input.anchorWriterEvidenceBytes,
    emailOracleEvidence: input.emailOracleEvidence,
    emailOracleEvidenceBytes: input.emailOracleEvidenceBytes,
    client: fakeClient(input.candidate, overrides),
    primaryRpcUrl: rpcOverrides.primaryRpcUrl ?? input.candidate.network.public_rpc_url,
    secondaryRpcUrl: rpcOverrides.secondaryRpcUrl ?? SECONDARY_RPC_URL,
    now: NOW,
    trustedVerifierAddresses,
    authorityBinding: input.authorityBinding,
    candidateAuthorityStage: input.candidateAuthorityStage ?? "live",
    historicalComputeWorkloadActivationObservation:
      input.historicalComputeWorkloadActivationObservation,
  });
}

test("release-env matches the canonical verifier's frozen verdict-v4 signing KAT", () => {
  const verdict = {
    schema: "dnai.independent-tdx-verdict.v4",
    verification_method: "intel_tdx_dcap_qvl",
    verified: true,
    chain_id: 84_532,
    domain: "main_runtime_cvm",
    profile: "compute_workload",
    cvm_id: "main-runtime-cvm-0001",
    deployment_intent_sha256: `sha256:${"11".repeat(32)}`,
    release_authority_sha256: `sha256:${"12".repeat(32)}`,
    ceremony_nonce: `0x${"13".repeat(32)}`,
    measurement_policy_sha256: `sha256:${"14".repeat(32)}`,
    release_policy_hash: `0x${"15".repeat(32)}`,
    challenge_id: `0x${"16".repeat(32)}`,
    challenge_digest: `0x${"17".repeat(32)}`,
    challenge_issued_at: 1_800_000_000,
    challenge_expires_at: 1_800_000_120,
    quote_hash: `0x${"18".repeat(32)}`,
    report_data: `0x${"19".repeat(32)}`,
    compose_hash: `0x${"1a".repeat(32)}`,
    app_id: "1b".repeat(20),
    os_image_hash: "1c".repeat(32),
    signer_address: `0x${"1d".repeat(20)}`,
    contract_address: `0x${"1e".repeat(20)}`,
    issued_at: 1_800_000_001,
    activation_evidence_lease_expires_at: 1_800_000_119,
    expires_at: 1_800_000_119,
    verifier_address: `0x${"1f".repeat(20)}`,
    verifier_signature: `0x${"20".repeat(64)}1b`,
  };
  assert.equal(
    __test.canonicalVerdictDigest(verdict),
    "0xe5030817bc86cb01586826ce35631bf1382d9c5deece6a46e21484d9b48512b6",
  );
});

test("builds only the allowlisted production Vite environment after every binding passes", async () => {
  const input = await fixture();
  assert.ok(
    input.candidate.attestations.artifact.verdict.challenge_expires_at < NOW,
    "the one-time QVL challenge is deliberately closed before release projection",
  );
  assert.ok(
    input.candidate.attestations.artifact.verdict.activation_evidence_lease_expires_at > NOW,
    "the separately signed activation-evidence lease remains current",
  );
  const env = await build(input);
  assert.equal(env.VITE_ENABLE_CONTRACT_WRITES, "true");
  assert.equal(env.VITE_ENABLE_ARTIFACT_UPLOAD, "true");
  assert.equal(env.VITE_ENABLE_COMPUTE_CONSOLE, "true");
  assert.equal(env.VITE_ENABLE_TINKER_CUSTOMER, "false");
  assert.equal(env.VITE_ENABLE_COLLABORATION, "false");
  assert.equal(env.VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD, "false");
  assert.equal(env.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER, "");
  assert.equal(env.VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON, "[]");
  assert.equal(env.VITE_ENABLE_COMPUTE_VAULT_FUNDING, "true");
  assert.equal(env.VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION, "true");
  assert.equal(env.VITE_DILIGENCE_ROOM_INITIAL_DEVELOPER, OPERATOR.toLowerCase());
  assert.equal(
    env.VITE_DILIGENCE_ROOM_RELEASE_GOVERNANCE_CONTROLLER,
    DILIGENCE_GOVERNANCE.toLowerCase(),
  );
  assert.equal(env.VITE_COMPUTE_CREDIT_VAULT_ADDRESS, COMPUTE.toLowerCase());
  assert.equal(env.VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH, COMPUTE_POLICY_SET);
  assert.equal(env.VITE_COMPUTE_VAULT_DEVELOPER_FEE_BPS, "100");
  assert.equal(env.VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS, USDC.toLowerCase());
  assert.equal(env.VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT, NATIVE_RATE_POLICY);
  assert.equal(env.VITE_COMPUTE_VAULT_NATIVE_PROVIDER, COMPUTE_PROVIDER.toLowerCase());
  assert.equal(env.VITE_COMPUTE_VAULT_ERC20_PROVIDER, COMPUTE_ERC20_PROVIDER.toLowerCase());
  assert.equal(env.VITE_ENABLE_ARENA_SUBMISSION, "true");
  assert.equal(
    env.VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256,
    arenaReleaseApprovedChallengeSetSha256(input.candidate.arena_registry_bindings),
  );
  assert.equal(env.VITE_RELEASE_SHA, SHA);
  assert.equal(
    env.VITE_ROYALTY_DISTRIBUTOR_CODE_HASH,
    keccak256(codes.royalty_distributor),
  );
  assert.equal(
    env.VITE_TINKER_ENCUMBRANCE_CODE_HASH,
    keccak256(codes.tinker_account_encumbrance),
  );
  assert.equal(
    env.VITE_EMAIL_ORACLE_AUTH_CODE_HASH,
    keccak256(codes.email_oracle_auth),
  );
  assert.equal(env.VITE_PHALA_COMPOSE_HASH, COMPOSE);
  assert.equal(env.VITE_WALLETCONNECT_PROJECT_ID, "12".repeat(16));
  assert.equal(env.VITE_ARTIFACT_VERIFIED_QUOTE_SHA256, `sha256:${"1".repeat(64)}`);
  assert.equal(
    env.VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256,
    `sha256:${"6".repeat(64)}`,
  );
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_ADDRESS, EXECUTION_POLICY_ANCHOR.toLowerCase());
  assert.equal(
    env.VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH,
    keccak256(codes.execution_policy_anchor),
  );
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_WRITER, EXECUTION_POLICY_WRITER.toLowerCase());
  assert.equal(
    env.VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT,
    `0x${CVM_LAUNCH_INTENT_COMMITMENT}`,
  );
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS, "12");
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS, "3600");
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS, "30");
  assert.equal(
    env.VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH,
    EXECUTION_POLICY_APPROVAL_DOMAIN_HASH,
  );
  assert.equal(
    env.VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH,
    EXECUTION_POLICY_APPROVER_ROOT,
  );
  assert.deepEqual(
    JSON.parse(env.VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON),
    EXECUTION_POLICY_APPROVER_HASHES,
  );
  assert.equal("VITE_ORACLE_URL" in env, false);
  assert.equal(env.VITE_BASE_SEPOLIA_RPC_URL, PRIMARY_RPC_URL);
  assert.equal(env.VITE_BASE_SEPOLIA_SECONDARY_RPC_URL, SECONDARY_RPC_URL);
  const serialized = serializeEnv(env);
  assert.match(serialized, /^VITE_BASE_SEPOLIA_RPC_URL=/);
  assert.match(serialized, /^VITE_BASE_SEPOLIA_SECONDARY_RPC_URL=/m);
  assert.equal(serialized.split("\n").filter(Boolean).length, __test.ENV_KEYS.length);
  assert.doesNotMatch(serialized, /PRIVATE|SECRET|TOKEN=.+|PHALA_CLOUD_API_KEY/);
  assert.doesNotMatch(serialized, /VITE_ORACLE_URL|oracle\.example/);
});

test("Tinker customer and collaboration browser gates project independently from signed authority", async () => {
  const baseline = await fixture();
  assert.equal(baseline.candidate.requested_features.compute_console, true);
  assert.equal(baseline.candidate.requested_features.tinker_customer, false);
  assert.equal(baseline.candidate.requested_features.collaboration, false);
  const baselineEnv = await build(baseline);
  assert.equal(baselineEnv.VITE_ENABLE_COMPUTE_CONSOLE, "true");
  assert.equal(baselineEnv.VITE_ENABLE_TINKER_CUSTOMER, "false");
  assert.equal(baselineEnv.VITE_ENABLE_COLLABORATION, "false");

  const tinkerOnly = await fixture();
  tinkerOnly.candidate.requested_features.tinker_customer = true;
  const tinkerEnv = await build(tinkerOnly);
  assert.equal(tinkerEnv.VITE_ENABLE_TINKER_CUSTOMER, "true");
  assert.equal(tinkerEnv.VITE_ENABLE_COLLABORATION, "false");

  const collaborationOnly = await fixture();
  collaborationOnly.candidate.requested_features.collaboration = true;
  const collaborationEnv = await build(collaborationOnly);
  assert.equal(collaborationEnv.VITE_ENABLE_TINKER_CUSTOMER, "false");
  assert.equal(collaborationEnv.VITE_ENABLE_COLLABORATION, "true");

  for (const key of ["tinker_customer", "collaboration"]) {
    for (const invalid of [undefined, null, 0, 1, "false", "true"]) {
      const malformed = await fixture();
      if (invalid === undefined) {
        delete malformed.candidate.requested_features[key];
      } else {
        malformed.candidate.requested_features[key] = invalid;
      }
      assert.throws(
        () => normalizeReleaseCandidate(malformed.candidate),
        /requested_features/,
      );
    }
  }
});

test("Compute workload upload cannot project browser pins without authenticated historical O replay", async () => {
  const input = await fixture();
  input.candidate.requested_features.compute_workload_upload = true;
  await assert.rejects(
    build(input),
    /requires a revalidated signed-C historical observation/,
  );
  input.historicalComputeWorkloadActivationObservation = {};
  await assert.rejects(
    build(input),
    /historical compute-workload O replay result must contain exactly the frozen fields/,
  );
});

test("browser RPC release bindings are public, exact, independently hosted, and candidate-bound", async () => {
  const alternate = await fixture();
  alternate.candidate.network.public_rpc_url = "https://primary-rpc.wikigen.me/base-sepolia";
  await assert.rejects(
    build(alternate, {}, {
      primaryRpcUrl: "https://primary-rpc.wikigen.me/base-sepolia",
      secondaryRpcUrl: "https://secondary-rpc.wikigen.net/base-sepolia",
    }),
    /canonical https:\/\/sepolia\.base\.org endpoint/,
  );

  const invalidCandidate = await fixture();
  invalidCandidate.candidate.network.public_rpc_url =
    "https://user:password@primary-rpc.wikigen.me/base-sepolia";
  await assert.rejects(
    build(invalidCandidate),
    /canonical https:\/\/sepolia\.base\.org endpoint/,
  );

  for (const secondaryRpcUrl of [
    "https://user@secondary-rpc.wikigen.net/base-sepolia",
    "https://secondary-rpc.wikigen.net/base-sepolia?api_key=value",
    "https://secondary-rpc.wikigen.net/base-sepolia#fragment",
    "https://127.0.0.1/base-sepolia",
    "https://sepolia.base.org/independent-in-name-only",
  ]) {
    const input = await fixture();
    await assert.rejects(
      build(input, {}, { secondaryRpcUrl }),
      /browser RPC release binding is invalid/,
      secondaryRpcUrl,
    );
  }

  const mismatched = await fixture();
  await assert.rejects(
    build(mismatched, {}, {
      primaryRpcUrl: "https://primary-rpc.wikigen.me/base-sepolia",
      secondaryRpcUrl: "https://secondary-rpc.wikigen.net/base-sepolia",
    }),
    /does not match the reviewed release candidate/,
  );
});

test("WalletConnect public configuration is authority-bound and strictly normalized", async () => {
  const empty = await fixture();
  empty.candidate.wallet_auth.walletconnect_project_id = "";
  const emptyEnv = await build(empty);
  assert.equal(emptyEnv.VITE_WALLETCONNECT_PROJECT_ID, "");

  for (const invalid of ["1".repeat(31), "1".repeat(33), "AB".repeat(16), "zz".repeat(16)]) {
    const input = await fixture();
    input.candidate.wallet_auth.walletconnect_project_id = invalid;
    await assert.rejects(build(input), /walletconnect_project_id/);
  }
});

test("the normalized v4 descriptor remains exact when the CLI validates it again", async () => {
  const input = await fixture();
  const once = normalizeReleaseCandidate(input.candidate);
  const twice = normalizeReleaseCandidate(once);
  assert.deepEqual(twice, once);
  input.candidate = once;
  const env = await build(input);
  assert.equal(env.VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION, "true");
  assert.equal(env.VITE_ENABLE_ARENA_SUBMISSION, "true");
});

test("release-manifest exact-shape examples track the live candidate normalizer", async () => {
  const source = readFileSync(RELEASE_MANIFEST_PATH, "utf8");
  const markedJson = (marker) => {
    const opening = `<!-- ${marker}:start -->`;
    const closing = `<!-- ${marker}:end -->`;
    const start = source.indexOf(opening);
    const end = source.indexOf(closing);
    assert.notEqual(start, -1, `${marker} opening marker is missing`);
    assert.notEqual(end, -1, `${marker} closing marker is missing`);
    assert.ok(end > start, `${marker} markers are out of order`);
    assert.equal(
      source.indexOf(opening, start + opening.length),
      -1,
      `${marker} opening marker must be unique`,
    );
    assert.equal(
      source.indexOf(closing, end + closing.length),
      -1,
      `${marker} closing marker must be unique`,
    );
    const section = source.slice(start + opening.length, end);
    const fences = [...section.matchAll(/```json\n([\s\S]*?)\n```/g)];
    assert.equal(fences.length, 1, `${marker} must contain exactly one JSON fence`);
    return JSON.parse(fences[0][1]);
  };
  const keys = (value) => Object.keys(value).sort();

  const documentedCandidate = markedJson("release-candidate-shape");
  const documentedCvm = markedJson("release-cvm-shape");
  const input = await fixture();
  const normalized = normalizeReleaseCandidate(input.candidate);

  assert.deepEqual(keys(documentedCandidate), keys(normalized));
  assert.deepEqual(
    keys(documentedCandidate.operator_policy),
    keys(normalized.operator_policy),
  );
  assert.deepEqual(
    keys(documentedCandidate.trust_domains),
    keys(normalized.trust_domains),
  );
  assert.deepEqual(keys(documentedCandidate.wallet_auth), keys(normalized.wallet_auth));
  assert.deepEqual(
    keys(documentedCandidate.requested_features),
    keys(normalized.requested_features),
  );
  assert.deepEqual(keys(documentedCvm), keys(normalized.cvm));
  assert.deepEqual(
    keys(documentedCvm.compute_workload_ingress),
    keys(normalized.cvm.compute_workload_ingress),
  );
  assert.deepEqual(
    keys(documentedCvm.runtime_controls),
    keys(normalized.cvm.runtime_controls),
  );

  assert.equal(documentedCandidate.schema, normalized.schema);
  assert.deepEqual(documentedCandidate.network, normalized.network);
  assert.equal(
    documentedCandidate.operator_policy.schema,
    normalized.operator_policy.schema,
  );
  assert.equal(documentedCandidate.wallet_auth.domain, normalized.wallet_auth.domain);
  assert.equal(documentedCandidate.wallet_auth.uri, normalized.wallet_auth.uri);
  assert.equal(documentedCandidate.wallet_auth.walletconnect_project_id, "");
  assert.deepEqual(documentedCandidate.requested_features, normalized.requested_features);
  assert.deepEqual(
    [...documentedCvm.allowed_browser_origins].sort(),
    [...normalized.cvm.allowed_browser_origins].sort(),
  );
  assert.deepEqual(
    documentedCvm.compute_workload_ingress,
    normalized.cvm.compute_workload_ingress,
  );
  assert.deepEqual(documentedCvm.runtime_controls, normalized.cvm.runtime_controls);

  const qvlKeys = keys(documentedCandidate.trust_domains)
    .filter((key) => key.endsWith("_qvl"));
  assert.equal(qvlKeys.length, 5);
  assert.equal(keys(documentedCandidate.trust_domains).length, 6);
  assert.equal(keys(documentedCandidate.trust_domains).length + 1, 7);
  assert.doesNotMatch(
    JSON.stringify(documentedCandidate),
    /dnai\.final-release-authority-evidence\.v1/,
  );

  const walletConnectDisabled = structuredClone(input.candidate);
  walletConnectDisabled.wallet_auth.walletconnect_project_id =
    documentedCandidate.wallet_auth.walletconnect_project_id;
  assert.equal(
    normalizeReleaseCandidate(walletConnectDisabled).wallet_auth.walletconnect_project_id,
    "",
  );
});

test("the nonauthorizing prebuild candidate is the live candidate minus only signed C", async () => {
  const input = await fixture();
  const projected = projectLiveReleaseCandidateToPrebuild(input.candidate);
  const projectedSha256 = liveReleaseCandidatePrebuildProjectionSha256(
    input.candidate,
  );
  assert.deepEqual(normalizePreLiveActivationReleaseCandidate(projected), projected);
  assert.equal(
    canonicalLiveReleaseCandidatePrebuildProjectionText(input.candidate),
    canonicalPreLiveActivationReleaseCandidateText(projected),
  );
  const matched = assertLiveReleaseCandidateMatchesPrebuild(
    projected,
    input.candidate,
  );
  assert.deepEqual(matched.prebuild, projected);
  assert.equal(
    matched.live.operator_policy.live_activation_authority_sha256,
    LIVE_ACTIVATION_AUTHORITY_SHA256,
  );
  assert.deepEqual(projected.operator_policy, {
    schema: "dnai.pre-live-activation-authority-evidence.v1",
    ceremony_authorization_sha256: CEREMONY_AUTHORIZATION_SHA256,
    runtime_authority_dependency_sha256:
      `sha256:${EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT}`,
  });

  const alternateSignedC = structuredClone(input.candidate);
  alternateSignedC.operator_policy.live_activation_authority_sha256 =
    `sha256:${"ab".repeat(32)}`;
  assert.equal(
    canonicalLiveReleaseCandidatePrebuildProjectionText(alternateSignedC),
    canonicalLiveReleaseCandidatePrebuildProjectionText(input.candidate),
  );
  assert.equal(
    liveReleaseCandidatePrebuildProjectionSha256(alternateSignedC),
    projectedSha256,
  );

  const driftedPrebuild = structuredClone(projected);
  driftedPrebuild.wallet_auth.walletconnect_project_id = "ab".repeat(16);
  const upstreamDrift = structuredClone(input.candidate);
  upstreamDrift.wallet_auth.walletconnect_project_id = "ab".repeat(16);
  assert.notEqual(
    liveReleaseCandidatePrebuildProjectionSha256(upstreamDrift),
    projectedSha256,
  );
  assert.throws(
    () => assertLiveReleaseCandidateMatchesPrebuild(
      driftedPrebuild,
      input.candidate,
    ),
    /differs from the immutable prebuild candidate/,
  );

  const cEmbedded = structuredClone(projected);
  cEmbedded.operator_policy.live_activation_authority_sha256 =
    LIVE_ACTIVATION_AUTHORITY_SHA256;
  assert.throws(
    () => normalizePreLiveActivationReleaseCandidate(cEmbedded),
    /fields are not exact/,
  );

  const cMissing = structuredClone(input.candidate);
  delete cMissing.operator_policy.live_activation_authority_sha256;
  assert.throws(
    () => normalizeReleaseCandidate(cMissing),
    /missing live_activation_authority_sha256/,
  );

  const prebuildInput = await fixture();
  const liveEnv = await build(prebuildInput);
  prebuildInput.candidate = projectLiveReleaseCandidateToPrebuild(
    prebuildInput.candidate,
  );
  prebuildInput.candidateAuthorityStage = "prebuild";
  assert.deepEqual(await build(prebuildInput), liveEnv);
});

test("signed live activation exact-binds all seven candidate CVM identities", async () => {
  const input = await fixture();
  const candidate = normalizeReleaseCandidate(input.candidate);
  const descriptors = [
    ["main_runtime", candidate.cvm, candidate.cvm.tee_identity],
    [
      "diligence_qvl",
      candidate.trust_domains.diligence_qvl,
      candidate.trust_domains.diligence_qvl.identity.verifier_address,
    ],
    [
      "arena_qvl",
      candidate.trust_domains.arena_qvl,
      candidate.trust_domains.arena_qvl.identity.verifier_address,
    ],
    [
      "anchor_writer_qvl",
      candidate.trust_domains.anchor_writer_qvl,
      candidate.trust_domains.anchor_writer_qvl.identity.verifier_address,
    ],
    [
      "compute_metering_qvl",
      candidate.trust_domains.compute_metering_qvl,
      candidate.trust_domains.compute_metering_qvl.identity.verifier_address,
    ],
    [
      "compute_workload_qvl",
      candidate.trust_domains.compute_workload_qvl,
      candidate.trust_domains.compute_workload_qvl.identity.verifier_address,
    ],
    [
      "independent_metering",
      candidate.trust_domains.compute_metering,
      candidate.trust_domains.compute_metering.identity.metering_verifier,
    ],
  ];
  const binding = {
    final_cvms: descriptors.map(([cvmKey, descriptor, teeIdentity], index) => ({
      cvm_key: cvmKey,
      app_id: descriptor.app_id,
      cvm_id: descriptor.cvm_id,
      compose_hash_sha256: `sha256:${descriptor.compose_hash}`,
      tee_identity: teeIdentity,
      attestation_evidence_sha256:
        `sha256:${(index + 1).toString(16).padStart(64, "0")}`,
    })),
  };
  assert.equal(
    assertLiveActivationFinalCvmsMatchCandidate(binding, candidate),
    true,
  );

  for (let index = 0; index < binding.final_cvms.length; index += 1) {
    for (const [field, value] of [
      ["app_id", "app_drifted_release"],
      ["cvm_id", "cvm_drifted_release"],
      ["compose_hash_sha256", `sha256:${"ee".repeat(32)}`],
      ["tee_identity", "0xffffffffffffffffffffffffffffffffffffffff"],
    ]) {
      const drifted = structuredClone(binding);
      drifted.final_cvms[index][field] = value;
      assert.throws(
        () => assertLiveActivationFinalCvmsMatchCandidate(drifted, candidate),
        /identity does not match/,
      );
    }
  }

  const sharedEvidence = structuredClone(binding);
  sharedEvidence.final_cvms[6].attestation_evidence_sha256 =
    sharedEvidence.final_cvms[0].attestation_evidence_sha256;
  assert.throws(
    () => assertLiveActivationFinalCvmsMatchCandidate(sharedEvidence, candidate),
    /distinct attestation evidence/,
  );
});

test("v4 release candidates require complete descriptors instead of bare trust-root addresses", async () => {
  const legacy = await fixture();
  legacy.candidate.schema = "dnai.web-release.v1";
  assert.throws(
    () => normalizeReleaseCandidate(legacy.candidate),
    /release schema must be dnai\.web-release\.v4/,
  );

  const missing = await fixture();
  delete missing.candidate.trust_domains;
  assert.throws(
    () => normalizeReleaseCandidate(missing.candidate),
    /missing trust_domains/,
  );

  const addressesOnly = await fixture();
  addressesOnly.candidate.trust_domains = {
    diligence_qvl: diligenceQvl.address,
    arena_qvl: arenaQvl.address,
    compute_metering: COMPUTE_METERING_VERIFIER,
  };
  assert.throws(
    () => normalizeReleaseCandidate(addressesOnly.candidate),
    /trust_domains fields are not exact: missing anchor_writer_qvl/,
  );
});

test("live activation evidence, deployment intent, and CVM launch intent are exact nonzero hash pins", async () => {
  const cases = [
    [(candidate) => { delete candidate.deployment_intent_sha256; }, /missing deployment_intent_sha256/],
    [
      (candidate) => { candidate.deployment_intent_sha256 = `sha256:${"0".repeat(64)}`; },
      /deployment_intent_sha256 cannot be zero/,
    ],
    [(candidate) => { delete candidate.cvm_launch_intent_sha256; }, /missing cvm_launch_intent_sha256/],
    [
      (candidate) => { candidate.cvm_launch_intent_sha256 = `sha256:${"0".repeat(64)}`; },
      /cvm_launch_intent_sha256 cannot be zero/,
    ],
    [
      (candidate) => { candidate.cvm_launch_intent_sha256 = `sha256:${"AB".repeat(32)}`; },
      /cvm_launch_intent_sha256 must be sha256 followed by 64 lowercase hex characters/,
    ],
    [(candidate) => { delete candidate.operator_policy; }, /missing operator_policy/],
    [
      (candidate) => { candidate.operator_policy.schema = "dnai.operator-role-policy-packet.v2"; },
      /operator_policy\.schema/,
    ],
    [
      (candidate) => { candidate.operator_policy.ceremony_authorization_sha256 = `sha256:${"0".repeat(64)}`; },
      /ceremony_authorization_sha256 cannot be zero/,
    ],
    [
      (candidate) => { candidate.operator_policy.live_activation_authority_sha256 = `sha256:${"AB".repeat(32)}`; },
      /64 lowercase hex characters/,
    ],
    [
      (candidate) => { candidate.operator_policy.ceremony_authorization_sha256 = "2d".repeat(32); },
      /64 lowercase hex characters/,
    ],
    [
      (candidate) => { candidate.operator_policy.runtime_authority_dependency_sha256 = "2b".repeat(32); },
      /64 lowercase hex characters/,
    ],
    [
      (candidate) => { candidate.operator_policy.runtime_authority_dependency_sha256 = `sha256:${"2e".repeat(32)}`; },
      /must equal the execution-policy release-manifest commitment/,
    ],
    [
      (candidate) => {
        candidate.operator_policy = {
          schema: "dnai.final-release-authority-evidence.v1",
          final_authority_sha256: `sha256:${EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT}`,
          review_envelope_sha256: CEREMONY_AUTHORIZATION_SHA256,
          review_evidence_sha256: LIVE_ACTIVATION_AUTHORITY_SHA256,
        };
      },
      /operator_policy fields are not exact/,
    ],
    [
      (candidate) => { candidate.operator_policy.note = "uncommitted"; },
      /operator_policy fields are not exact/,
    ],
  ];
  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input.candidate);
    assert.throws(() => normalizeReleaseCandidate(input.candidate), expected);
  }
});

test("EmailOracleAuth upgrade delay is bounded and matches ledger and live chain", async () => {
  for (const invalid of [172_799, 31_536_001, 172_800.5, "172800"]) {
    const input = await fixture();
    input.candidate.contracts.email_oracle_auth.upgrade_delay_seconds = invalid;
    assert.throws(() => normalizeReleaseCandidate(input.candidate), /upgrade_delay_seconds/);
  }

  const ledgerDrift = await fixture();
  ledgerDrift.ledger.contracts.emailOracleAuth.oracleUpgradeDelaySeconds = 172_801;
  await assert.rejects(build(ledgerDrift), /upgrade delay does not match the release candidate/);

  const liveDrift = await fixture();
  await assert.rejects(
    build(liveDrift, {
      read: { "email_oracle_auth.ORACLE_UPGRADE_DELAY": 172_801n },
    }),
    /live EmailOracleAuth upgrade delay does not match the release pin/,
  );
});

test("execution-policy release roots are exact, derived, sorted, and fail closed", async () => {
  const cases = [
    [
      (candidate) => { delete candidate.execution_policy; },
      /missing execution_policy/,
    ],
    [
      (candidate) => { candidate.execution_policy.canonicalization_version = "policy-kernel-canonicalization/v1"; },
      /canonicalization version/,
    ],
    [
      (candidate) => { candidate.execution_policy.approval_schema = "dnai-wikigen\/execution-policy-approval\/v1"; },
      /approval schema/,
    ],
    [
      (candidate) => { candidate.execution_policy.api_schema_version = 1; },
      /API schema version/,
    ],
    [
      (candidate) => { candidate.execution_policy.store_schema_version = 2; },
      /store schema version/,
    ],
    [
      (candidate) => { candidate.execution_policy.approver_hashes.reverse(); },
      /lowercase, sorted, and unique/,
    ],
    [
      (candidate) => { candidate.execution_policy.approver_hashes[1] = candidate.execution_policy.approver_hashes[0]; },
      /lowercase, sorted, and unique/,
    ],
    [
      (candidate) => { candidate.execution_policy.approver_root_hash = "4".repeat(64); },
      /approver root/,
    ],
    [
      (candidate) => { candidate.execution_policy.approval_domain = `${candidate.execution_policy.approval_domain}:operator`; },
      /exactly derived/,
    ],
    [
      (candidate) => { candidate.execution_policy.approval_domain_hash = "4".repeat(64); },
      /domain hash/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.status = "unavailable"; },
      /unavailable or not the active frozen release writer/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.status = "verified"; },
      /not the active frozen release writer/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.contract_address = "0x0000000000000000000000000000000000000000"; },
      /zero address/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.evidence_sha256 = `sha256:${"0".repeat(64)}`; },
      /evidence cannot be a placeholder/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.writer_address = "0x0000000000000000000000000000000000000000"; },
      /writer_address cannot be the zero address/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.writer_release_commitment = `0x${"18".repeat(32)}`; },
      /writer release must equal the reviewed CVM launch-intent digest/,
    ],
    [
      (candidate) => {
        candidate.execution_policy.rollback_anchor.writer_release_commitment =
          `0x${EXECUTION_POLICY_RELEASE_MANIFEST_COMMITMENT}`;
      },
      /writer release must equal the reviewed CVM launch-intent digest/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.writer_custody = "operator_key"; },
      /writer custody is not the reviewed dstack key domain/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.writer_key_path = "tinker/shared"; },
      /writer custody is not the reviewed dstack key domain/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.confirmations = 1; },
      /confirmations must be a safe integer >= 2/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.confirmations = 257; },
      /confirmations must be <= 256/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.max_block_age_seconds = 29; },
      /max_block_age_seconds must be a safe integer >= 30/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.max_block_age_seconds = 3_601; },
      /max block age must be <= 3600 seconds/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.max_future_block_skew_seconds = -1; },
      /max_future_block_skew_seconds must be a safe integer >= 0/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.max_future_block_skew_seconds = 301; },
      /max future block skew must be <= 300 seconds/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.verification_model = "consensus_finalized"; },
      /exact single-RPC finality trust label/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.independent_rpc_quorum_verified = true; },
      /exact single-RPC finality trust label/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.consensus_proof_verified = true; },
      /exact single-RPC finality trust label/,
    ],
    [
      (candidate) => { candidate.execution_policy.rollback_anchor.operator_note = "trust me"; },
      /unexpected operator_note/,
    ],
  ];
  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input.candidate);
    assert.throws(() => normalizeReleaseCandidate(input.candidate), expected);
  }

  const runtimeDrift = await fixture();
  await assert.rejects(
    build(runtimeDrift, { code: { execution_policy_anchor: "0x60006000" } }),
    /rollback anchor runtime bytecode hash/,
  );
});

test("every independent CVM descriptor is release-bound, provenance-bound, private, and endpoint-bounded", async () => {
  const cases = [
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.release_sha = "b".repeat(40); },
      /release SHA mismatch/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.platform = "operator_vm"; },
      /must be deployed on Phala Cloud/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.os_is_dev = true; },
      /non-dev private Phala posture/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.public_logs = true; },
      /non-dev private Phala posture/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.ssh_enabled = true; },
      /non-dev private Phala posture/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.endpoint = "http://metering.example.test/meter"; },
      /exact public HTTPS/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.endpoint = "https://169.254.169.254/meter"; },
      /exact public HTTPS/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.endpoint = "https://[2001:db8::1]/verify"; },
      /exact public HTTPS/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.endpoint = "https://qvl-diligence.release.wikigen.me/health"; },
      /bounded HTTPS \/verify endpoint/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.endpoint = "https://qvl-arena.release.wikigen.me/verify?root=1"; },
      /exact public HTTPS/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.endpoint_authentication = "none"; },
      /must require bearer authentication/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.identity_evidence_classification = "self_verified"; },
      /non-self-verifying deployment-pin classification/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.image.image = `ghcr.io/therealwiki/dnai-wikigen/tinker-delegate@sha256:${"8".repeat(64)}`; },
      /project-owned digest-pinned.*attestation-qvl image/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.image.source_digest = "b".repeat(40); },
      /source digest must equal the release SHA/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.image.repo = "fork/dnai-wikigen"; },
      /untrusted GitHub provenance identity/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.image.signer_workflow = "therealwiki/dnai-wikigen/.github/workflows/other.yml"; },
      /untrusted GitHub provenance identity/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.image.sbom_attestation = "missing"; },
      /lacks verified provenance or SBOM evidence/,
    ],
  ];
  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input.candidate);
    assert.throws(() => normalizeReleaseCandidate(input.candidate), expected);
  }
});

test("anchor writer promotion requires the exact independently signed QVL artifact", async () => {
  const arbitraryHash = await fixture();
  arbitraryHash.candidate.execution_policy.rollback_anchor.evidence_sha256 =
    `sha256:${"99".repeat(32)}`;
  await assert.rejects(
    build(arbitraryHash),
    /evidence hash does not match the release descriptor/,
  );

  const noncanonical = await fixture();
  noncanonical.anchorWriterEvidenceBytes = Buffer.concat([
    noncanonical.anchorWriterEvidenceBytes,
    Buffer.from(" ", "ascii"),
  ]);
  noncanonical.candidate.execution_policy.rollback_anchor.evidence_sha256 =
    `sha256:${createHash("sha256")
      .update(noncanonical.anchorWriterEvidenceBytes)
      .digest("hex")}`;
  await assert.rejects(
    build(noncanonical),
    /must be exact canonical JSON bytes/,
  );

  const selfProduced = await fixture();
  selfProduced.anchorWriterEvidence = {
    schema: "dnai-wikigen/execution-policy-anchor-writer-bootstrap/v1",
    status: "dstack_derived_not_independently_verified",
    evidence_sha256: `sha256:${"11".repeat(32)}`,
  };
  refreshAnchorWriterEvidence(selfProduced);
  await assert.rejects(
    build(selfProduced),
    /writer evidence fields are not exact/,
  );

  const reportDrift = await fixture();
  reportDrift.anchorWriterEvidence.report_data = `0x${"77".repeat(32)}`;
  reportDrift.anchorWriterEvidence.quote_report_data = `0x${"77".repeat(32)}`;
  reportDrift.anchorWriterEvidence.qvl_verdict.report_data = `0x${"77".repeat(32)}`;
  refreshAnchorWriterEvidence(reportDrift);
  await assert.rejects(build(reportDrift), /report-data binding mismatch/);

  const forgedSignature = await fixture();
  forgedSignature.anchorWriterEvidence.qvl_verdict.verifier_signature =
    `0x${"01".repeat(65)}`;
  refreshAnchorWriterEvidence(forgedSignature);
  await assert.rejects(
    build(forgedSignature),
    /signature is not authenticated|signature cannot be recovered|canonical low-s/,
  );

  const wrongQvlRoot = await fixture();
  wrongQvlRoot.anchorWriterEvidence.qvl_release_policy_hash = `0x${"88".repeat(32)}`;
  refreshAnchorWriterEvidence(wrongQvlRoot);
  await assert.rejects(build(wrongQvlRoot), /evidence QVL root mismatch/);

  const quoteLeak = await fixture();
  quoteLeak.anchorWriterEvidence.raw_quote = `0x${"ab".repeat(1_024)}`;
  refreshAnchorWriterEvidence(quoteLeak);
  await assert.rejects(
    build(quoteLeak),
    /writer evidence fields are not exact/,
  );
});

test("QVL descriptors bind distinct canonical policies to the evaluated release without self-trusting", async () => {
  const driftedBinding = await fixture();
  driftedBinding.candidate.trust_domains.diligence_qvl.policy_binding.contract_address = CHALLENGE;
  assert.throws(
    () => normalizeReleaseCandidate(driftedBinding.candidate),
    /canonical QVL policy binding does not match/,
  );

  const driftedWriterBinding = await fixture();
  driftedWriterBinding.candidate.trust_domains.anchor_writer_qvl.policy_binding.writer_key_path =
    "tinker/shared";
  assert.throws(
    () => normalizeReleaseCandidate(driftedWriterBinding.candidate),
    /canonical QVL policy binding does not match/,
  );

  const collapsedPolicies = await fixture();
  collapsedPolicies.candidate.trust_domains.arena_qvl.identity.release_policy_hash = DILIGENCE_QVL_POLICY;
  assert.throws(
    () => normalizeReleaseCandidate(collapsedPolicies.candidate),
    /policy root must be distinct|policy roots.*distinct/i,
  );

  const wrongCustody = await fixture();
  wrongCustody.candidate.trust_domains.arena_qvl.identity.signer_custody = "raw_private_key";
  assert.throws(
    () => normalizeReleaseCandidate(wrongCustody.candidate),
    /production QVL identity schema/,
  );

  const wrongDomainSigner = await fixture();
  wrongDomainSigner.candidate.attestations.artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: arenaQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
  });
  await assert.rejects(
    build(wrongDomainSigner),
    /does not match its full release-pinned QVL CVM descriptor/,
  );

  const externalTrustMissing = await fixture();
  await assert.rejects(
    buildWithTrusted(
      externalTrustMissing,
      [diligenceQvl.address, anchorWriterQvl.address],
    ),
    /must contain exactly five distinct QVL roots/,
  );
});

test("Diligence QVL binding and the external five-root policy are exact", async () => {
  const verifierDrift = await fixture();
  verifierDrift.candidate.contracts.diligence_room.attestation_verifier =
    arenaQvl.address;
  assert.throws(
    () => normalizeReleaseCandidate(verifierDrift.candidate),
    /attestation verifier does not match/,
  );

  const policyDrift = await fixture();
  policyDrift.candidate.contracts.diligence_room.attestation_release_policy_hash =
    ARENA_QVL_POLICY;
  assert.throws(
    () => normalizeReleaseCandidate(policyDrift.candidate),
    /attestation policy hash does not match/,
  );

  const mutableCandidate = await fixture();
  mutableCandidate.candidate.contracts.diligence_room.attestation_binding_frozen = false;
  assert.throws(
    () => normalizeReleaseCandidate(mutableCandidate.candidate),
    /attestation_binding_frozen must be true/,
  );

  for (const [roots, expected] of [
    [
      [
        diligenceQvl.address,
        diligenceQvl.address,
        anchorWriterQvl.address,
        computeMeteringQvl.address,
      ],
      /exactly five distinct/,
    ],
    [
      [
        diligenceQvl.address,
        arenaQvl.address,
        anchorWriterQvl.address,
        computeMeteringQvl.address,
        "0x" + "ef".repeat(20),
      ],
      /must equal all five release-pinned/,
    ],
    [
      [
        diligenceQvl.address,
        arenaQvl.address,
        anchorWriterQvl.address,
        "0x" + "ef".repeat(20),
      ],
      /exactly five distinct/,
    ],
  ]) {
    const input = await fixture();
    await assert.rejects(buildWithTrusted(input, roots), expected);
  }

  const unfrozen = await fixture();
  await assert.rejects(
    build(unfrozen, { read: { "diligence_room.attestationBindingFrozen": false } }),
    /attestation binding is not the exact permanently frozen release binding/,
  );
  for (const [field, value] of [
    ["pendingAttestationVerifier", arenaQvl.address],
    ["pendingAttestationReleasePolicyHash", ARENA_QVL_POLICY],
    ["pendingAttestationBindingActivatesAt", 1n],
  ]) {
    const pending = await fixture();
    await assert.rejects(
      build(pending, { read: { [`diligence_room.${field}`]: value } }),
      /attestation binding is not the exact permanently frozen release binding/,
    );
  }
  const livePolicyDrift = await fixture();
  await assert.rejects(
    build(livePolicyDrift, {
      read: { "diligence_room.attestationReleasePolicyHash": ARENA_QVL_POLICY },
    }),
    /attestation release policy hash mismatch/,
  );
});

test("all independent control roots and CVM identities remain separate", async () => {
  const rootCases = [
    OPERATOR,
    TEE,
    RESULT_VERIFIER,
    COMPUTE_DEVELOPER,
    COMPUTE_METERING_VERIFIER,
    EXECUTION_POLICY_WRITER,
    arenaQvl.address,
    anchorWriterQvl.address,
  ];
  for (const collapsedRoot of rootCases) {
    const input = await fixture();
    input.candidate.trust_domains.diligence_qvl.identity.verifier_address = collapsedRoot;
    input.candidate.contracts.diligence_room.attestation_verifier = collapsedRoot;
    assert.throws(
      () => normalizeReleaseCandidate(input.candidate),
      /must all be distinct|conflicts with a release role/,
    );
  }

  const collapsedMeteringRoot = await fixture();
  collapsedMeteringRoot.candidate.contracts.compute_credit_vault.metering_verifier = diligenceQvl.address;
  collapsedMeteringRoot.candidate.trust_domains.compute_metering.identity.metering_verifier = diligenceQvl.address;
  collapsedMeteringRoot.candidate.trust_domains.compute_metering_qvl.policy_binding.allowed_signer_address = diligenceQvl.address;
  assert.throws(
    () => normalizeReleaseCandidate(collapsedMeteringRoot.candidate),
    /must all be distinct/,
  );

  const identityCases = [
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.app_id = candidate.cvm.app_id; },
      /distinct app IDs/,
    ],
    [
      (candidate) => { candidate.trust_domains.arena_qvl.cvm_id = candidate.trust_domains.diligence_qvl.cvm_id; },
      /distinct CVM IDs/,
    ],
    [
      (candidate) => {
        candidate.trust_domains.compute_metering.compose_hash =
          candidate.trust_domains.arena_qvl.compose_hash;
        candidate.trust_domains.compute_metering_qvl.policy_binding.evaluated_compose_hash =
          `0x${candidate.trust_domains.arena_qvl.compose_hash}`;
      },
      /distinct compose hashes/,
    ],
    [
      (candidate) => { candidate.trust_domains.diligence_qvl.endpoint = "https://delegate.release.wikigen.me/verify"; },
      /distinct HTTPS origins/,
    ],
  ];
  for (const [mutate, expected] of identityCases) {
    const input = await fixture();
    mutate(input.candidate);
    assert.throws(() => normalizeReleaseCandidate(input.candidate), expected);
  }
});

test("compute authorization requires the full canonical policy set and exact immutable verifier", async () => {
  const cases = [
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.assets.pop(); },
      /must match every funding-enabled native and canonical-USDC policy/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.assets.reverse(); },
      /must be sorted by address/,
    ],
    [
      (candidate) => {
        candidate.trust_domains.compute_metering.identity.assets[1] = {
          ...candidate.trust_domains.compute_metering.identity.assets[0],
        };
      },
      /assets and commitments must be unique/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.assets[0].rate_policy_commitment = ERC20_RATE_POLICY; },
      /assets and commitments must be unique/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.assets[1].asset = COMPUTE_PROVIDER; },
      /unsupported Base Sepolia asset/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.assets[0].provider = TEE; },
      /policy provider conflicts with a control-plane role/,
    ],
    [
      (candidate) => { candidate.contracts.compute_credit_vault.native_provider = "0x9999999999999999999999999999999999999999"; },
      /provider recipients must equal the reviewed native\/ERC20 metering policies/,
    ],
    [
      (candidate) => { candidate.contracts.compute_credit_vault.erc20_provider = COMPUTE_PROVIDER; },
      /native and ERC20 payout recipients must be distinct/,
    ],
    [
      (candidate) => {
        candidate.trust_domains.compute_metering.identity.assets.push({
          asset: COMPUTE_PROVIDER,
          rate_policy_commitment: `0x${"20".repeat(32)}`,
        });
      },
      /must contain one or two policy entries/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.vault_address = DILIGENCE; },
      /descriptor vault does not match ComputeCreditVault/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.metering_verifier = RESULT_VERIFIER; },
      /address does not match ComputeCreditVault\.meteringVerifier/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.policy_set_hash = `0x${"0".repeat(64)}`; },
      /policy_set_hash cannot be zero/,
    ],
    [
      (candidate) => { candidate.contracts.compute_credit_vault.metering_policy_set_hash = `0x${"19".repeat(32)}`; },
      /policy set does not match ComputeCreditVault\.meteringPolicySetHash/,
    ],
    [
      (candidate) => { candidate.contracts.compute_credit_vault.metering_binding_frozen = false; },
      /metering_binding_frozen must be true/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.provider_authoritative_invoice = true; },
      /bounded production schema/,
    ],
    [
      (candidate) => { candidate.trust_domains.compute_metering.identity.signer_custody = "operator_key"; },
      /bounded production schema/,
    ],
  ];
  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input.candidate);
    assert.throws(() => normalizeReleaseCandidate(input.candidate), expected);
  }

  const fundingOnly = await fixture();
  fundingOnly.candidate.requested_features.compute_vault_authorization = false;
  fundingOnly.candidate.trust_domains.compute_metering.identity.assets.pop();
  assert.throws(
    () => normalizeReleaseCandidate(fundingOnly.candidate),
    /must match every funding-enabled native and canonical-USDC policy/,
  );
});

test("accepts the matching fresh suite when later CVM governance evidence is append-only", async () => {
  const input = await fixture();
  input.ledger.deploymentHistory.push({
    kind: "post_cvm_binding_governance",
    sourceCommit: SHA,
    diligenceRoom: {
      composeHash: `0x${COMPOSE}`,
      teeIdentity: TEE,
      approvalRequirementsFrozen: true,
    },
    emailOracleAuth: {
      oracleCodeFrozen: true,
      consumerRegistryFrozen: true,
    },
  });

  const env = await build(input);
  assert.equal(env.VITE_ENABLE_CONTRACT_WRITES, "true");
});

test("keeps the exact jq-produced draft as deployment evidence but requires an active Tinker ceremony", async () => {
  const input = await fixture();
  input.ledger = recordActiveAnchorSnapshot(
    generatedFreshSuiteLedger(input.ledger.phala),
  );

  assert.equal(
    input.ledger.freshDeployment.contractSuite.runtimeCodeProof,
    "exact_creation_reexecution_match_all_contracts",
  );
  assert.equal(input.ledger.contracts.diligenceRoom.approvalRequirementsFrozen, true);
  assert.equal(
    input.ledger.contracts.emailOracleAuth.status,
    "deployed_deny_all_pending_cvm_binding",
  );
  for (const entry of Object.values(input.ledger.deploymentHistory.at(-1).deployedContracts)) {
    assert.match(entry.runtimeCodeHash, /^0x[0-9a-f]{64}$/);
  }

  assert.equal(
    input.ledger.contracts.tinkerAccountEncumbrance.status,
    "deployed_halted_draft_pending_timelocked_release_policy",
  );
  await assert.rejects(
    build(input),
    /encumbrance current entry is not the active frozen release/,
  );

  recordActiveTinkerSnapshot(input.ledger);
  recordActiveDiligenceResultVerifierSnapshot(input.ledger);
  assert.equal(
    input.ledger.deploymentHistory.at(-1).deployedContracts
      .tinkerAccountEncumbrance.status,
    "deployed_halted_draft_pending_timelocked_release_policy",
  );
  const env = await build(input);
  assert.equal(env.VITE_DILIGENCE_ROOM_CODE_HASH, keccak256(codes.diligence_room));
  assert.equal(env.VITE_ENABLE_CONTRACT_WRITES, "true");
});

test("selects the active Tinker ceremony without trusting older deployment history", async () => {
  const input = await fixture();
  input.ledger.tinkerReleaseHistory.unshift({
    kind: "tinker_exact_release_policy_phase",
    chainId: 84_532,
    encumbranceAddress: COMPUTE,
    runtimeCodeHash: keccak256(codes.compute_credit_vault),
    phase: 2,
    transactionHash: `0x${"7".repeat(64)}`,
  });

  const env = await build(input);
  assert.equal(env.VITE_TINKER_ENCUMBRANCE_ADDRESS, ENCUMBRANCE.toLowerCase());
});

test("rejects missing, duplicate, mixed, reordered, and replayed Tinker ceremonies", async () => {
  const cases = [
    [
      (input) => { delete input.ledger.tinkerReleaseHistory; },
      /Tinker release history is required/,
    ],
    [
      (input) => { input.ledger.tinkerReleaseHistory.pop(); },
      /exactly one phase-1 and one phase-2/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory.push({
          ...clone(input.ledger.tinkerReleaseHistory[1]),
          transactionHash: `0x${"6".repeat(64)}`,
          blockNumber: TINKER_PHASE_TWO_BLOCK + 1,
        });
      },
      /exactly one phase-1 and one phase-2/,
    ],
    [
      (input) => { input.ledger.tinkerReleaseHistory.reverse(); },
      /ordered phase 1 then phase 2/,
    ],
    [
      (input) => { input.ledger.tinkerReleaseHistory[1].encumbranceAddress = COMPUTE; },
      /exactly one phase-1 and one phase-2/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[1].runtimeCodeHash =
          keccak256(codes.compute_credit_vault);
      },
      /exactly one phase-1 and one phase-2/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory.unshift({
          chainId: 84_532,
          encumbranceAddress: COMPUTE,
          runtimeCodeHash: keccak256(codes.compute_credit_vault),
          transactionHash: TINKER_PHASE_TWO_TX,
        });
      },
      /transaction evidence is replayed/,
    ],
  ];

  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input);
    await assert.rejects(build(input), expected);
  }
});

test("rejects Tinker draft, proposal, activation, and current-policy drift", async () => {
  const cases = [
    [
      (input) => {
        input.ledger.contracts.tinkerAccountEncumbrance.maxAddBalanceWei =
          Number(TINKER_MAX_ADD_BALANCE_WEI);
      },
      /canonical uint256 decimal string/,
    ],
    [
      (input) => {
        input.ledger.deploymentHistory[0].deployedContracts
          .tinkerAccountEncumbrance.pendingMaxSpendWei = 0;
      },
      /canonical uint256 decimal string/,
    ],
    [
      (input) => {
        input.ledger.deploymentHistory[0].deployedContracts
          .tinkerAccountEncumbrance.deploymentTx = `0x${"7".repeat(64)}`;
      },
      /not bound to the active deployment transaction and source/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[0].pendingReleasePolicyCommitment =
          `0x${"44".repeat(32)}`;
      },
      /pendingReleasePolicyCommitment mismatch/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[0].pendingMaxAddBalanceWei =
          "9007199254740993";
      },
      /pending caps do not match/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[1].releaseManagerRoot =
          `0x${"45".repeat(32)}`;
      },
      /releaseManagerRoot mismatch/,
    ],
    [
      (input) => { input.ledger.tinkerReleaseHistory[1].pendingMaxSpendWei = "1"; },
      /pending caps must be canonical zero strings/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[1].sourceCommit =
          TINKER_PHASE_TWO_SOURCE.toUpperCase();
      },
      /full lowercase Git commit SHA/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[1].transactionHash = `0x${"0".repeat(64)}`;
      },
      /nonzero lowercase transaction hash/,
    ],
    [
      (input) => {
        input.ledger.tinkerReleaseHistory[1].blockNumber = TINKER_PHASE_ONE_BLOCK;
      },
      /unique ordered transaction evidence/,
    ],
    [
      (input) => {
        input.ledger.contracts.tinkerAccountEncumbrance.latestReleaseSourceCommit =
          TINKER_PHASE_ONE_SOURCE;
      },
      /latest-release fields do not identify the exact phase-2 record/,
    ],
    [
      (input) => {
        input.ledger.contracts.tinkerAccountEncumbrance.releaseComposeRoot =
          `0x${"46".repeat(32)}`;
      },
      /releaseComposeRoot mismatch/,
    ],
  ];

  for (const [mutate, expected] of cases) {
    const input = await fixture();
    mutate(input);
    await assert.rejects(build(input), expected);
  }
});

test("pins every live bytecode and contract read to one Base Sepolia block", async () => {
  const input = await fixture();
  input.ledger.contracts.executionPolicyAnchor.releaseSnapshotBlockNumber = 98_765;
  const observed = [];
  await build(input, {
    headBlockNumber: 98_776n,
    observe(kind, request) {
      observed.push({ kind, blockNumber: request.blockNumber });
    },
  });
  assert.ok(observed.length > 20);
  assert.equal(
    observed.some((item) => item.kind === "getBlock" && item.blockNumber === undefined),
    true,
  );
  assert.deepEqual(
    new Set(
      observed
        .filter((item) => item.blockNumber !== undefined)
        .map((item) => item.blockNumber),
    ),
    new Set([98_765n, BigInt(KMS_REGISTRATION_BLOCK)]),
  );
  assert.equal(
    observed
      .filter((item) => item.blockNumber === BigInt(KMS_REGISTRATION_BLOCK))
      .every((item) => item.kind === "getBlock"),
    true,
  );
});

test("chooses the older same-RPC finalized tag when it trails confirmation depth", async () => {
  const input = await fixture();
  input.ledger.contracts.executionPolicyAnchor.releaseSnapshotBlockNumber = 12_340;
  const observed = [];
  const env = await build(input, {
    finalizedBlockNumber: 12_340n,
    observe(kind, request) {
      observed.push({ kind, blockNumber: request.blockNumber, blockTag: request.blockTag });
    },
  });
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS, "12");
  assert.equal(
    observed.some((item) => item.kind === "getBlock" && item.blockTag === "finalized"),
    true,
  );
  assert.deepEqual(
    new Set(
      observed
        .filter((item) => item.blockNumber !== undefined)
        .map((item) => item.blockNumber),
    ),
    new Set([12_340n, BigInt(KMS_REGISTRATION_BLOCK)]),
  );
});

test("accepts a consistent nonzero monotonic anchor head and rejects ledger-chain drift", async () => {
  const head = `0x${"42".repeat(32)}`;
  const input = await fixture();
  input.ledger.contracts.executionPolicyAnchor.globalSequence = 7;
  input.ledger.contracts.executionPolicyAnchor.globalHead = head;
  const env = await build(input, {
    read: {
      "execution_policy_anchor.globalSequence": 7n,
      "execution_policy_anchor.globalHead": head,
    },
  });
  assert.equal(env.VITE_EXECUTION_POLICY_ANCHOR_ADDRESS, EXECUTION_POLICY_ANCHOR.toLowerCase());

  const drift = await fixture();
  drift.ledger.contracts.executionPolicyAnchor.globalSequence = 7;
  drift.ledger.contracts.executionPolicyAnchor.globalHead = head;
  await assert.rejects(
    build(drift, {
      read: {
        "execution_policy_anchor.globalSequence": 8n,
        "execution_policy_anchor.globalHead": `0x${"43".repeat(32)}`,
      },
    }),
    /live ExecutionPolicyAnchor head does not match the release-pinned ledger snapshot/,
  );
});

test("requires external authority pins to match the suite ledger and immutable anchor reads", async () => {
  const missingBinding = await fixture();
  delete missingBinding.authorityBinding;
  await assert.rejects(build(missingBinding), /release authority binding/);

  const suiteIntentDrift = await fixture();
  suiteIntentDrift.ledger.freshDeployment.contractSuite.deploymentIntentSha256 =
    `sha256:${"44".repeat(32)}`;
  await assert.rejects(
    build(suiteIntentDrift),
    /fresh suite ledger does not bind the exact deployment intent/,
  );

  const ledgerAcceptanceDrift = await fixture();
  ledgerAcceptanceDrift.ledger.contracts.executionPolicyAnchor
    .reviewerAuthorityGenesisAcceptanceSha256Bytes32 = `0x${"45".repeat(32)}`;
  await assert.rejects(
    build(ledgerAcceptanceDrift),
    /ledger ExecutionPolicyAnchor reviewer-genesis-acceptance digest mismatch/,
  );

  const liveIntentDrift = await fixture();
  await assert.rejects(
    build(liveIntentDrift, {
      read: {
        "execution_policy_anchor.deploymentIntentSha256": `0x${"46".repeat(32)}`,
      },
    }),
    /live ExecutionPolicyAnchor deployment-intent digest mismatch/,
  );

  const liveAcceptanceDrift = await fixture();
  await assert.rejects(
    build(liveAcceptanceDrift, {
      read: {
        "execution_policy_anchor.reviewerAuthorityGenesisAcceptanceSha256":
          `0x${"47".repeat(32)}`,
      },
    }),
    /live ExecutionPolicyAnchor reviewer-genesis-acceptance digest mismatch/,
  );

  const candidateStageBindingDrift = await fixture();
  candidateStageBindingDrift.authorityBinding.ceremonyAuthorizationSha256 =
    `sha256:${"48".repeat(32)}`;
  await assert.rejects(
    build(candidateStageBindingDrift),
    /release candidate does not exactly match the independently validated authority binding/,
  );
});

test("rejects the prior-operator ledger instead of treating currentOperatorControlled as fresh evidence", async () => {
  const input = await fixture();
  delete input.ledger.freshDeployment.contractSuite;
  input.ledger.contracts.diligenceRoom.status = "deployed_current_operator_controlled";
  await assert.rejects(build(input), /freshDeployment\.contractSuite/);
});

test("rejects drift in exact fresh-suite policy and runtime-proof field names", async () => {
  const missingRuntimeProof = await fixture();
  delete missingRuntimeProof.ledger.freshDeployment.contractSuite.runtimeCodeProof;
  await assert.rejects(build(missingRuntimeProof), /exact-runtime proof markers/);

  const mutableInitialGate = await fixture();
  mutableInitialGate.ledger.contracts.diligenceRoom.composeApprovalRequired = false;
  await assert.rejects(build(mutableInitialGate), /empty-allowlist release posture/);

  const wrongEmailStatus = await fixture();
  wrongEmailStatus.ledger.contracts.emailOracleAuth.status = "deployed_current_operator_controlled";
  await assert.rejects(build(wrongEmailStatus), /fresh deny-all suite entry/);

  const wrongHistoryHashName = await fixture();
  const historyEmail = wrongHistoryHashName.ledger.deploymentHistory.at(-1)
    .deployedContracts.emailOracleAuth;
  historyEmail.runtime_code_hash = historyEmail.runtimeCodeHash;
  delete historyEmail.runtimeCodeHash;
  await assert.rejects(build(wrongHistoryHashName), /deployment history emailOracleAuth runtime code hash/);

  const missingAnchorState = await fixture();
  delete missingAnchorState.ledger.freshDeployment.contractSuite.executionPolicyAnchorState;
  await assert.rejects(build(missingAnchorState), /exact-runtime proof markers/);

  const pausedAnchor = await fixture();
  pausedAnchor.ledger.contracts.executionPolicyAnchor.paused = true;
  await assert.rejects(
    build(pausedAnchor),
    /ExecutionPolicyAnchor does not prove the exact active frozen release writer snapshot/,
  );

  const mutableWriter = await fixture();
  mutableWriter.ledger.contracts.executionPolicyAnchor.writerRotationsFrozen = false;
  await assert.rejects(
    build(mutableWriter),
    /ExecutionPolicyAnchor does not prove the exact active frozen release writer snapshot/,
  );

  const shortenedWriterDelay = await fixture();
  shortenedWriterDelay.ledger.contracts.executionPolicyAnchor.writerRotationDelaySeconds = 0;
  await assert.rejects(
    build(shortenedWriterDelay),
    /ExecutionPolicyAnchor does not prove the exact active frozen release writer snapshot/,
  );

  const inconsistentAnchorHead = await fixture();
  inconsistentAnchorHead.ledger.contracts.executionPolicyAnchor.globalSequence = 1;
  await assert.rejects(
    build(inconsistentAnchorHead),
    /ExecutionPolicyAnchor does not prove the exact active frozen release writer snapshot/,
  );

  const unpinnedAnchor = await fixture();
  delete unpinnedAnchor.ledger.contracts.executionPolicyAnchor.releaseSnapshotBlockNumber;
  await assert.rejects(build(unpinnedAnchor), /releaseSnapshotBlockNumber/);

  const anchorWriter = await fixture();
  anchorWriter.ledger.deploymentHistory.at(-1).deployedContracts
    .executionPolicyAnchor.writer = TEE;
  await assert.rejects(build(anchorWriter), /initial ExecutionPolicyAnchor fail-closed posture/);

  const anchorRuntime = await fixture();
  anchorRuntime.ledger.contracts.executionPolicyAnchor.runtimeCodeHash = keccak256("0x60006000");
  await assert.rejects(build(anchorRuntime), /ledger ExecutionPolicyAnchor runtime code hash mismatch/);
});

test("rejects mutable or evaluator-modulated settlement policy evidence", async () => {
  const mutableLedger = await fixture();
  mutableLedger.ledger.contracts.diligenceRoom.feeBpsFrozen = false;
  await assert.rejects(build(mutableLedger), /settlement tariffs/);

  const missingHistory = await fixture();
  missingHistory.ledger.deploymentHistory.at(-1).deployedContracts.diligenceRoom
    .computeSettlementPolicyEnabled = false;
  await assert.rejects(build(missingHistory), /fixed settlement policy/);

  const mutableApprovalPolicy = await fixture();
  mutableApprovalPolicy.ledger.contracts.diligenceRoom.approvalRequirementsFrozen = false;
  await assert.rejects(build(mutableApprovalPolicy), /approval requirements/);

  const mutableInitialAdmission = await fixture();
  mutableInitialAdmission.ledger.contracts.diligenceRoom.composeAdditionsFrozen = true;
  await assert.rejects(build(mutableInitialAdmission), /empty-allowlist release posture/);

  const pendingInitialAdmission = await fixture();
  pendingInitialAdmission.ledger.deploymentHistory.at(-1).deployedContracts.diligenceRoom
    .pendingTeeIdentityCount = 1;
  await assert.rejects(build(pendingInitialAdmission), /empty-allowlist release posture/);

  const mutableChain = await fixture();
  await assert.rejects(
    build(mutableChain, { read: { "diligence_room.computeSettlementPolicyEnabled": false } }),
    /settlement tariffs/,
  );
});

test("release projection observes the immutable Diligence governance handoff identity", async () => {
  const wrongInitialDeveloper = await fixture();
  await assert.rejects(
    build(wrongInitialDeveloper, {
      read: {
        "diligence_room.initialDeveloper":
          "0x9999999999999999999999999999999999999999",
      },
    }),
    /live DiligenceRoom initial developer mismatch/,
  );

  const wrongGovernanceController = await fixture();
  await assert.rejects(
    build(wrongGovernanceController, {
      read: {
        "diligence_room.releaseGovernanceController":
          "0x9999999999999999999999999999999999999999",
      },
    }),
    /live DiligenceRoom immutable release governance controller mismatch/,
  );

  const controllerNotAccepted = await fixture();
  await assert.rejects(
    build(controllerNotAccepted, {
      read: {
        "diligence_room.developer": OPERATOR,
      },
    }),
    /live DiligenceRoom developer mismatch/,
  );
});

test("rejects ComputeCreditVault role collapse and an authorization-only feature flag", async () => {
  const distinctRoleError = /owner, developer, metering signer, metering QVL verifier, TEE, and diligence verifier must be distinct/;
  const collapsed = await fixture();
  collapsed.candidate.contracts.compute_credit_vault.metering_verifier = OPERATOR;
  assert.throws(
    () => normalizeReleaseCandidate(collapsed.candidate),
    distinctRoleError,
  );

  const selfRole = await fixture();
  selfRole.candidate.contracts.compute_credit_vault.developer = COMPUTE;
  assert.throws(
    () => normalizeReleaseCandidate(selfRole.candidate),
    distinctRoleError,
  );

  const qvlOperatorCollapse = await fixture();
  qvlOperatorCollapse.candidate.contracts.compute_credit_vault.metering_qvl_verifier = OPERATOR;
  assert.throws(
    () => normalizeReleaseCandidate(qvlOperatorCollapse.candidate),
    distinctRoleError,
  );

  const signerQvlCollapse = await fixture();
  signerQvlCollapse.candidate.contracts.compute_credit_vault.metering_qvl_verifier =
    signerQvlCollapse.candidate.contracts.compute_credit_vault.metering_verifier;
  assert.throws(
    () => normalizeReleaseCandidate(signerQvlCollapse.candidate),
    distinctRoleError,
  );

  const authorizationOnly = await fixture();
  authorizationOnly.candidate.requested_features.compute_vault_funding = false;
  assert.throws(
    () => normalizeReleaseCandidate(authorizationOnly.candidate),
    /authorization cannot be enabled while vault funding is disabled/,
  );
});

test("rejects mutable initial vault evidence and unsafe live funding or execution gates", async () => {
  const mutableLedger = await fixture();
  mutableLedger.ledger.contracts.computeCreditVault.developerFeeFrozen = false;
  await assert.rejects(build(mutableLedger), /empty-admission release posture/);

  const paused = await fixture();
  await assert.rejects(
    build(paused, { read: { "compute_credit_vault.paused": true } }),
    /funding rail or pinned ERC20 asset is not active/,
  );

  const unbound = await fixture();
  await assert.rejects(
    build(unbound, { read: { "compute_credit_vault.composePolicyFrozen": false } }),
    /admission set is not approved and irreversibly closed/,
  );

  for (const mutableGate of ["ratePolicyAdditionsFrozen", "assetAdditionsFrozen", "teeIdentityAdditionsFrozen"]) {
    const mutableAdmission = await fixture();
    await assert.rejects(
      build(mutableAdmission, { read: { [`compute_credit_vault.${mutableGate}`]: false } }),
      /admission set is not approved and irreversibly closed/,
    );
  }

  for (const [counter, value] of [
    ["allowedAssetCount", 2n],
    ["activeRatePolicyCount", 3n],
    ["approvedComposeCount", 2n],
    ["approvedTeeIdentityCount", 2n],
    ["pendingAssetCount", 1n],
    ["pendingRatePolicyCount", 1n],
    ["pendingComposeCount", 1n],
    ["pendingTeeIdentityCount", 1n],
  ]) {
    const extraAdmission = await fixture();
    await assert.rejects(
      build(extraAdmission, { read: { [`compute_credit_vault.${counter}`]: value } }),
      /admission set is not approved and irreversibly closed/,
    );
  }

  for (const [field, value] of [
    ["meteringBindingFrozen", false],
    ["pendingMeteringVerifier", RESULT_VERIFIER],
    ["pendingMeteringPolicySetHash", ARENA_QVL_POLICY],
    ["pendingMeteringBindingActivatesAt", 1n],
  ]) {
    const mutableMetering = await fixture();
    await assert.rejects(
      build(mutableMetering, { read: { [`compute_credit_vault.${field}`]: value } }),
      /metering binding is not the exact permanently frozen release binding/,
    );
  }

  const policySetDrift = await fixture();
  await assert.rejects(
    build(policySetDrift, {
      read: { "compute_credit_vault.meteringPolicySetHash": ARENA_QVL_POLICY },
    }),
    /metering policy set hash mismatch/,
  );

  const wrongRateAsset = await fixture();
  await assert.rejects(
    build(wrongRateAsset, {
      read: {
        "compute_credit_vault.ratePolicies": {
          asset: USDC,
          provider: COMPUTE_PROVIDER,
          developerFeeBps: 100,
          active: true,
        },
      },
    }),
    /rate policies are not the active pinned native\/ERC20 policies/,
  );

  const wrongProvider = await fixture();
  await assert.rejects(
    build(wrongProvider, {
      read: {
        "compute_credit_vault.ratePolicies": {
          asset: "0x0000000000000000000000000000000000000000",
          provider: "0x9999999999999999999999999999999999999999",
          developerFeeBps: 100,
          active: true,
        },
      },
    }),
    /rate policies are not the active pinned native\/ERC20 policies/,
  );
});

test("rejects dev OS, public debug surfaces, mutable images, and wildcard origins", async () => {
  const input = await fixture();
  input.candidate.cvm.os_is_dev = true;
  assert.throws(() => normalizeReleaseCandidate(input.candidate), /non-dev OS/);
  const input2 = await fixture();
  input2.candidate.cvm.images[0].image = "ghcr.io/therealwiki/dnai-wikigen/tinker-delegate:latest";
  assert.throws(() => normalizeReleaseCandidate(input2.candidate), /digest-pinned/);
  const input3 = await fixture();
  input3.candidate.cvm.allowed_browser_origins.push("https://*.example.test");
  assert.throws(() => normalizeReleaseCandidate(input3.candidate), /exact public HTTPS/);
  const input4 = await fixture();
  input4.candidate.cvm.allowed_browser_origins.push("https://preview.evil.com");
  assert.throws(() => normalizeReleaseCandidate(input4.candidate), /only the reviewed Wikigen origins/);
  const input5 = await fixture();
  input5.candidate.cvm.delegate_url = "https://delegate.release.wikigen.me/api";
  assert.throws(() => normalizeReleaseCandidate(input5.candidate), /origin without a path/);
  const privateDelegate = await fixture();
  privateDelegate.candidate.cvm.delegate_url = "https://10.0.0.1";
  assert.throws(
    () => normalizeReleaseCandidate(privateDelegate.candidate),
    /exact public HTTPS/,
  );
  const input6 = await fixture();
  input6.candidate.cvm.runtime_controls.browser_ports_internal_only = false;
  assert.throws(() => normalizeReleaseCandidate(input6.candidate), /browser_ports_internal_only must be true/);
  const input7 = await fixture();
  input7.candidate.cvm.runtime_controls.bootstrap_fail_open_disabled = false;
  assert.throws(() => normalizeReleaseCandidate(input7.candidate), /bootstrap_fail_open_disabled must be true/);

  for (const [control, expected] of [
    ["deal_settlement_enabled", /deal settlement is not enabled/],
    ["remote_artifact_evaluator_enabled", /remote artifact evaluation is not enabled/],
  ]) {
    const enabled = await fixture();
    enabled.candidate.cvm.runtime_controls[control] = true;
    assert.throws(() => normalizeReleaseCandidate(enabled.candidate), expected);

    const omitted = await fixture();
    delete omitted.candidate.cvm.runtime_controls[control];
    assert.throws(
      () => normalizeReleaseCandidate(omitted.candidate),
      new RegExp(`missing ${control}`),
    );
  }

  const priorOperatorImage = await fixture();
  priorOperatorImage.candidate.cvm.images[0].image =
    `ghcr.io/g-structure/dnai-wikigen/tinker-delegate@sha256:${"5".repeat(64)}`;
  priorOperatorImage.candidate.cvm.images[0].repo = "G-structure/dnai-wikigen";
  priorOperatorImage.candidate.cvm.images[0].signer_workflow =
    "G-structure/dnai-wikigen/.github/workflows/build-tee-images.yml";
  assert.throws(
    () => normalizeReleaseCandidate(priorOperatorImage.candidate),
    /project-owned .*therealwiki\/dnai-wikigen/,
  );
});

test("requires exactly the delegate, oracle, and Neko project images", async () => {
  const missingNeko = await fixture();
  missingNeko.candidate.cvm.images = missingNeko.candidate.cvm.images.filter(
    (image) => image.service !== "neko",
  );
  assert.throws(
    () => normalizeReleaseCandidate(missingNeko.candidate),
    /exactly delegate, oracle, and neko/,
  );

  const unknownService = await fixture();
  unknownService.candidate.cvm.images[2].service = "props-room";
  unknownService.candidate.cvm.images[2].image =
    `ghcr.io/therealwiki/dnai-wikigen/props-room@sha256:${"7".repeat(64)}`;
  assert.throws(
    () => normalizeReleaseCandidate(unknownService.candidate),
    /not in the production allowlist/,
  );

  const extraStub = await fixture();
  extraStub.candidate.cvm.images.push({
    ...extraStub.candidate.cvm.images[0],
    service: "whatsapp-delegate",
    image: `ghcr.io/therealwiki/dnai-wikigen/whatsapp-delegate@sha256:${"8".repeat(64)}`,
  });
  assert.throws(
    () => normalizeReleaseCandidate(extraStub.candidate),
    /exactly delegate, oracle, and neko/,
  );

  const mislabeledStub = await fixture();
  mislabeledStub.candidate.cvm.images[2].image =
    `ghcr.io/therealwiki/dnai-wikigen/cdp-playground@sha256:${"7".repeat(64)}`;
  assert.throws(
    () => normalizeReleaseCandidate(mislabeledStub.candidate),
    /project-owned .*neko-chrome digest/,
  );
});

test("requires provenance and SBOM evidence for Neko as well as delegate and oracle", async () => {
  for (const field of ["provenance_attestation", "sbom_attestation"]) {
    const input = await fixture();
    input.candidate.cvm.images.find((image) => image.service === "neko")[field] = "missing";
    assert.throws(
      () => normalizeReleaseCandidate(input.candidate),
      /lacks verified provenance or SBOM evidence/,
    );
  }
});

test("release schema proves the oracle is internal, authenticated, minimized, and fail-closed", async () => {
  const publicCandidate = await fixture();
  publicCandidate.candidate.cvm.oracle_url = "https://oracle.example.test";
  assert.throws(
    () => normalizeReleaseCandidate(publicCandidate.candidate),
    /unexpected oracle_url/,
  );

  for (const control of [
    "oracle_internal_only",
    "oracle_runtime_auth_required",
    "oracle_health_liveness_only",
    "oracle_pin_response_minimized",
    "oracle_private_metadata_egress_prohibited",
    "oracle_replay_fail_closed",
  ]) {
    const input = await fixture();
    input.candidate.cvm.runtime_controls[control] = false;
    assert.throws(
      () => normalizeReleaseCandidate(input.candidate),
      new RegExp(`${control} must be true`),
    );
  }

  const publicLedger = await fixture();
  publicLedger.ledger.phala.endpoints.oracle = "https://oracle.example.test";
  await assert.rejects(
    build(publicLedger),
    /deployment ledger Phala endpoints fields are not exact: unexpected oracle/,
  );
});

test("rejects a six-decimal USDC lookalike instead of trusting token metadata", async () => {
  const input = await fixture();
  input.candidate.contracts.usdc.address = "0x9000000000000000000000000000000000000009";
  assert.throws(
    () => normalizeReleaseCandidate(input.candidate),
    /Circle's canonical Base Sepolia USDC address/,
  );
});

test("rejects a result authorizer controlled by the operator or TEE", async () => {
  const operatorVerifier = await fixture();
  operatorVerifier.candidate.contracts.diligence_room.result_verifier = OPERATOR;
  assert.throws(
    () => normalizeReleaseCandidate(operatorVerifier.candidate),
    /distinct from the release operator/,
  );

  const teeVerifier = await fixture();
  teeVerifier.candidate.contracts.diligence_room.result_verifier = TEE;
  assert.throws(
    () => normalizeReleaseCandidate(teeVerifier.candidate),
    /distinct from the TEE identity/,
  );

  const operatorTee = await fixture();
  operatorTee.candidate.cvm.tee_identity = OPERATOR;
  operatorTee.candidate.contracts.email_oracle_auth.consumer_address = OPERATOR;
  assert.throws(
    () => normalizeReleaseCandidate(operatorTee.candidate),
    /operator and attested TEE identity must be distinct/,
  );
});

test("rejects stale, self-declared, and unauthenticated independent verdicts", async () => {
  const stale = await fixture();
  stale.candidate.attestations.artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    challengeIssuedAt: NOW - 120,
    challengeExpiresAt: NOW,
    issuedAt: NOW - 110,
    expiresAt: NOW,
  });
  await assert.rejects(build(stale), /activation evidence lease is expired/);

  const untrusted = await fixture();
  await assert.rejects(
    buildReleaseEnv({
      candidate: untrusted.candidate,
      ledger: untrusted.ledger,
      artifactEvidence: untrusted.artifactEvidence,
      arenaEvidence: untrusted.arenaEvidence,
      anchorWriterEvidence: untrusted.anchorWriterEvidence,
      anchorWriterEvidenceBytes: untrusted.anchorWriterEvidenceBytes,
      emailOracleEvidence: untrusted.emailOracleEvidence,
      emailOracleEvidenceBytes: untrusted.emailOracleEvidenceBytes,
      client: fakeClient(untrusted.candidate),
      primaryRpcUrl: untrusted.candidate.network.public_rpc_url,
      secondaryRpcUrl: SECONDARY_RPC_URL,
      now: NOW,
      trustedVerifierAddresses: ["0xa00000000000000000000000000000000000000a"],
      authorityBinding: untrusted.authorityBinding,
    }),
    /external trusted-verifier policy/,
  );

  const forged = await fixture();
  forged.candidate.attestations.arena.verdict.report_data = `0x${"9".repeat(64)}`;
  forged.arenaEvidence.cvm.report_data = "9".repeat(64);
  await assert.rejects(build(forged), /signature is not authenticated/);
});

test("independent verdict validation is single-version v4 and exact-lineage only", async () => {
  const legacy = await fixture();
  legacy.candidate.attestations.artifact.verdict.schema =
    "dnai.independent-tdx-verdict.v3";
  await assert.rejects(
    build(legacy),
    /not an independently verified Intel TDX DCAP\/QVL result/,
  );

  for (const field of [
    "chain_id",
    "domain",
    "cvm_id",
    "deployment_intent_sha256",
    "release_authority_sha256",
    "ceremony_nonce",
    "measurement_policy_sha256",
    "activation_evidence_lease_expires_at",
  ]) {
    const missing = await fixture();
    delete missing.candidate.attestations.artifact.verdict[field];
    assert.throws(
      () => normalizeReleaseCandidate(missing.candidate),
      /fields are not exact/,
    );
  }

  const extra = await fixture();
  extra.candidate.attestations.artifact.verdict.legacy_authority =
    RELEASE_AUTHORITY_SHA256;
  assert.throws(
    () => normalizeReleaseCandidate(extra.candidate),
    /fields are not exact/,
  );

  const uppercaseHash = await fixture();
  uppercaseHash.candidate.attestations.artifact.verdict.os_image_hash =
    uppercaseHash.candidate.attestations.artifact.verdict.os_image_hash.toUpperCase();
  await assert.rejects(build(uppercaseHash), /canonical lowercase bare bytes32/);

  const wrongDomain = await fixture();
  wrongDomain.candidate.attestations.artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    domain: "independent_metering_cvm",
  });
  await assert.rejects(build(wrongDomain), /domain does not match/);

  const wrongCvm = await fixture();
  wrongCvm.candidate.attestations.artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    cvmId: "main-runtime-cvm-substitution",
  });
  await assert.rejects(build(wrongCvm), /not bound to this CVM, chain, and contract/);

  const wrongIntent = await fixture();
  wrongIntent.candidate.attestations.artifact = await signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    deploymentIntentSha256: `sha256:${"9a".repeat(32)}`,
  });
  await assert.rejects(build(wrongIntent), /not bound to this CVM, chain, and contract/);

  const crossCeremony = await fixture();
  crossCeremony.candidate.attestations.arena = await signedVerdict({
    context: "arena",
    quoteByte: "3",
    reportByte: "4",
    contract: CHALLENGE,
    signer: arenaQvl,
    profile: "arena",
    releasePolicyHash: ARENA_QVL_POLICY,
    releaseAuthoritySha256: `sha256:${"9b".repeat(32)}`,
    ceremonyNonce: `0x${"9c".repeat(32)}`,
  });
  await assert.rejects(
    build(crossCeremony),
    /release authority does not match the canonical ceremony|ceremony nonce does not match/,
  );
});

test("challenge-bound verdicts reject cross-profile, cross-policy, future, and zero-tail substitutions", async () => {
  const replacement = async (overrides = {}) => signedVerdict({
    context: "artifact",
    quoteByte: "1",
    reportByte: "2",
    contract: DILIGENCE,
    signer: diligenceQvl,
    profile: "diligence",
    releasePolicyHash: DILIGENCE_QVL_POLICY,
    ...overrides,
  });

  const crossProfile = await fixture();
  crossProfile.candidate.attestations.artifact = await replacement({ profile: "arena" });
  await assert.rejects(build(crossProfile), /profile does not match/);

  const crossPolicy = await fixture();
  crossPolicy.candidate.attestations.artifact = await replacement({
    releasePolicyHash: ARENA_QVL_POLICY,
  });
  await assert.rejects(build(crossPolicy), /release-policy hash does not match/);

  const future = await fixture();
  future.candidate.attestations.artifact = await replacement({
    challengeIssuedAt: NOW + 6,
    challengeExpiresAt: NOW + 100,
    issuedAt: NOW + 6,
    expiresAt: NOW + 90,
  });
  await assert.rejects(build(future), /future-dated/);

  const completedAtChallengeExpiry = await fixture();
  completedAtChallengeExpiry.candidate.attestations.artifact = await replacement({
    challengeExpiresAt: NOW - 10,
    issuedAt: NOW - 10,
  });
  await assert.rejects(
    build(completedAtChallengeExpiry),
    /challenge or activation evidence lease is invalid/,
  );

  const driftedLeaseAlias = await fixture();
  driftedLeaseAlias.candidate.attestations.artifact = await replacement({
    activationEvidenceLeaseExpiresAt: NOW + 89,
    expiresAt: NOW + 90,
  });
  await assert.rejects(
    build(driftedLeaseAlias),
    /challenge or activation evidence lease is invalid/,
  );

  const oversizedLease = await fixture();
  oversizedLease.candidate.attestations.artifact = await replacement({
    issuedAt: NOW - 10,
    expiresAt: NOW + 891,
  });
  await assert.rejects(
    build(oversizedLease),
    /challenge or activation evidence lease is invalid/,
  );

  const zeroTail = await fixture();
  zeroTail.candidate.attestations.artifact = await replacement({
    challengeDigest: `0x${"0".repeat(64)}`,
  });
  await assert.rejects(build(zeroTail), /challenge_digest.*nonzero|challenge_digest cannot be zero/);

  const anchorZeroTail = await fixture();
  anchorZeroTail.anchorWriterEvidence.quote_report_data =
    `${anchorZeroTail.anchorWriterEvidence.report_data}${"0".repeat(64)}`;
  refreshAnchorWriterEvidence(anchorZeroTail);
  await assert.rejects(build(anchorZeroTail), /report-data binding mismatch/);
});

test("binds structural deployment evidence to its signed appraisal without re-aging it downstream", async () => {
  const delayedProjection = await fixture();
  delayedProjection.artifactEvidence.cvm.fetched_at = NOW - 310;
  assert.equal(
    validateDeploymentEvidence(
      delayedProjection.artifactEvidence,
      normalizeReleaseCandidate(delayedProjection.candidate),
      "artifact",
      NOW + 800,
    ),
    true,
  );

  const stale = await fixture();
  stale.artifactEvidence.cvm.fetched_at = NOW - 311;
  await assert.rejects(build(stale), /outside its signed QVL appraisal window/);

  const fractional = await fixture();
  fractional.artifactEvidence.cvm.fetched_at = NOW - 10.5;
  await assert.rejects(build(fractional), /fetched_at must be a safe integer/);

  const promoted = await fixture();
  promoted.arenaEvidence.claims.intel_tdx_quote_verified = true;
  promoted.arenaEvidence.claims.production_authorization_allowed = true;
  await assert.rejects(build(promoted), /must preserve its unverified TDX trust label/);

  const driftedImage = await fixture();
  driftedImage.artifactEvidence.cvm.images[0].image = `ghcr.io/therealwiki/dnai-wikigen/tinker-delegate@sha256:${"0".repeat(64)}`;
  await assert.rejects(build(driftedImage), /compose image mismatch/);
});

test("Email oracle release evidence is canonical, hash-bound, exact, and proves restart continuity", async () => {
  const noncanonical = await fixture();
  noncanonical.emailOracleEvidenceBytes = Buffer.concat([
    noncanonical.emailOracleEvidenceBytes,
    Buffer.from(" "),
  ]);
  await assert.rejects(build(noncanonical), /exact canonical JSON bytes/);

  const kmsDrift = await fixture();
  kmsDrift.emailOracleEvidence.kms.runtime_code_hash = `0x${"29".repeat(32)}`;
  refreshEmailOracleEvidence(kmsDrift);
  await assert.rejects(build(kmsDrift), /KMS source\/runtime binding mismatch/);

  const slotDrift = await fixture();
  slotDrift.emailOracleEvidence.kms.kms_eip1967_implementation_slot_word =
    `0x${"31".repeat(32)}`;
  refreshEmailOracleEvidence(slotDrift);
  await assert.rejects(build(slotDrift), /KMS source\/runtime binding mismatch/);

  const restartDrift = await fixture();
  restartDrift.emailOracleEvidence.restart_key_derivation.post_restart_commitment =
    `0x${"30".repeat(32)}`;
  refreshEmailOracleEvidence(restartDrift);
  await assert.rejects(build(restartDrift), /key continuity across a real CVM restart/);

  const qvlSelfClaim = await fixture();
  qvlSelfClaim.emailOracleEvidence.qvl_verification.status = "modeled";
  refreshEmailOracleEvidence(qvlSelfClaim);
  await assert.rejects(build(qvlSelfClaim), /QVL status is not verified/);
});

test("Email oracle and Challenge live validation rechecks every frozen/KMS/registration root", async () => {
  const cases = [
    [{ read: { "challenge_registry.MIN_VERSION_REVIEW_DELAY": 1n } }, /review delay is not exactly 172800/],
    [{ read: { "challenge_registry.pendingOwner": OPERATOR } }, /pending owner/],
    [{ read: { "challenge_registry.nextChallengeId": 3n } }, /id sequence is inconsistent/],
    [{ read: { "challenge_registry.getChallenge": {
      controller: RESULT_VERIFIER,
      pendingController: ZERO_ADDRESS,
      lifecycle: 1,
      createdAt: 1n,
      updatedAt: 2n,
      latestVersion: 1,
      paused: false,
      configurationFrozen: true,
    } } }, /controller mismatch/],
    [{ read: { "challenge_registry.reviewEligibleAt": 172_802n } }, /immutable version review delay/],
    [{ read: { "email_oracle_auth.pendingOwner": OPERATOR } }, /pending owner/],
    [{ read: { "email_oracle_auth.consumerManagerAdditionsFrozen": false } }, /exact enumerable/],
    [{ read: { "email_oracle_auth.allowedOracleComposeHashCount": 2n } }, /exact enumerable/],
    [{ read: { "email_oracle_auth.consumerEmergencyRevoked": true } }, /exact enumerable/],
    [{ read: { "email_oracle_auth.releaseConfigurationReady": false } }, /exact enumerable/],
    [{ read: { "email_oracle_auth.releaseDeviceId": `0x${"31".repeat(32)}` } }, /release device mismatch/],
    [{ read: { "email_oracle_auth.kmsRuntimeCodeHash": `0x${"32".repeat(32)}` } }, /KMS runtime hash mismatch/],
    [{ read: { "email_oracle_auth.pendingKmsBindingActivatesAt": 1n } }, /pending KMS binding/],
    [{ code: { kms: "0x60006000" } }, /KMS proxy runtime bytecode hash/],
    [{ kmsImplementationSlot: `0x${"0".repeat(64)}` }, /EIP-1967 implementation slot/],
    [{ read: { "kms.registeredApps": false } }, /registration\/readback/],
    [{ read: { "kms.isAppAllowed": [false, "denied"] } }, /exact target boot tuple/],
    [{ registrationReceipt: { status: "reverted" } }, /registration receipt/],
    [{ registrationReceipt: { logs: [] } }, /AppRegistered/],
    [{ registrationTransaction: { input: "0x1234" } }, /exact registerApp/],
    [{ registrationBlockHash: `0x${"33".repeat(32)}` }, /block hash is not canonical/],
  ];
  for (const [overrides, expected] of cases) {
    const input = await fixture();
    await assert.rejects(build(input, overrides), expected);
  }

  const extendedRegistry = await fixture();
  await assert.doesNotReject(build(extendedRegistry, {
    read: {
      "challenge_registry.challengeCount": 2n,
      "challenge_registry.nextChallengeId": 3n,
    },
  }));
});

test("rejects live bytecode, gate, registry, encumbrance, oracle, and token mismatches", async () => {
  const cases = [
    [{ code: { diligence_room: "0x60006000" } }, /runtime bytecode hash/],
    [{ headBlockNumber: 0n }, /head block/],
    [{ headBlockNumber: 12_346n }, /release-pinned ledger block/],
    [{ finalizedBlockNumber: 12_340n }, /release-pinned ledger block/],
    [{ finalizedBlockNumber: 12_357n }, /invalid Base Sepolia finalized-tag block number/],
    [{ finalizedBlockHash: `0x${"0".repeat(64)}` }, /finalized-tag block hash cannot be zero/],
    [{ snapshotBlockHash: `0x${"0".repeat(64)}` }, /release-pinned Base Sepolia block hash cannot be zero/],
    [{ blockTimestamp: NOW - 3_601 }, /stale or future-dated/],
    [{ blockTimestamp: NOW + 31 }, /stale or future-dated/],
    [{ read: { "execution_policy_anchor.writer": TEE } }, /live ExecutionPolicyAnchor writer mismatch/],
    [{ read: { "execution_policy_anchor.writerRotationsFrozen": false } }, /not the exact active frozen release writer/],
    [{ read: { "execution_policy_anchor.paused": true } }, /not the exact active frozen release writer/],
    [{ read: { "execution_policy_anchor.globalSequence": 1n } }, /not the exact active frozen release writer/],
    [{ read: { "diligence_room.composeApprovalRequired": false } }, /approval gates/],
    [{ read: { "diligence_room.approvalRequirementsFrozen": false } }, /irreversibly required/],
    [{ read: { "diligence_room.composeAdditionsFrozen": false } }, /admission set is not exactly bound/],
    [{ read: { "diligence_room.teeIdentityAdditionsFrozen": false } }, /admission set is not exactly bound/],
    [{ read: { "diligence_room.approvedComposeCount": 2n } }, /admission set is not exactly bound/],
    [{ read: { "diligence_room.approvedTeeIdentityCount": 2n } }, /admission set is not exactly bound/],
    [{ read: { "diligence_room.pendingComposeCount": 1n } }, /admission set is not exactly bound/],
    [{ read: { "diligence_room.pendingTeeIdentityCount": 1n } }, /admission set is not exactly bound/],
    [{ read: { "challenge_registry.challengeCount": 0n } }, /missing a release-approved genesis challenge/],
    [{ read: { "tinker_account_encumbrance.releasePolicyFrozen": false } }, /exact active, frozen/],
    [{ read: { "tinker_account_encumbrance.pendingOwner": OPERATOR } }, /exact active, frozen/],
    [{ read: { "tinker_account_encumbrance.releaseMaxSpendWei": 1n } }, /exact active, frozen/],
    [{ read: { "tinker_account_encumbrance.pendingReleasePolicyActivatesAt": 1n } }, /exact active, frozen/],
    [{ read: { "email_oracle_auth.allowAnyDevice": true } }, /exact enumerable/],
    [{ read: { "usdc.decimals": 18 } }, /USDC metadata/],
  ];
  for (const [overrides, expected] of cases) {
    const input = await fixture();
    await assert.rejects(build(input, overrides), expected);
  }
});

test("dotenv serializer refuses extra keys and line injection", async () => {
  const input = await fixture();
  const env = await build(input);
  assert.throws(() => serializeEnv({ ...env, VITE_PRIVATE_KEY: "nope" }), /non-allowlisted/);
  assert.throws(() => serializeEnv({ ...env, VITE_RELEASE_SHA: "ok\nVITE_EVIL=true" }), /not safe/);
});

test("GitHub provenance commands are argument arrays with both required predicates", async () => {
  const input = await fixture();
  const candidate = normalizeReleaseCandidate(input.candidate);
  const commands = githubAttestationCommands(candidate);
  assert.equal(commands.length, 10);
  for (const command of commands) {
    assert.equal(command[0], "attestation");
    assert.ok(command.includes("--deny-self-hosted-runners"));
    assert.ok(command.includes(SHA));
    assert.equal(command.some((value) => value.includes(";")), false);
  }
  assert.deepEqual(
    new Set(commands.map((command) => command.at(-1))),
    new Set(["https://slsa.dev/provenance/v1", "https://spdx.dev/Document/v2.3"]),
  );
  const subjects = new Set(commands.map((command) => command[2]));
  assert.equal(subjects.size, 5);
  assert.ok([...subjects].some((subject) => subject.includes("attestation-qvl@sha256:")));
  assert.ok([...subjects].some((subject) => subject.includes("compute-metering@sha256:")));
});

test("fixture helper does not share mutable release objects between tests", async () => {
  const first = await fixture();
  const second = clone(first);
  second.candidate.requested_features.compute_console = false;
  assert.equal(first.candidate.requested_features.compute_console, true);
});
