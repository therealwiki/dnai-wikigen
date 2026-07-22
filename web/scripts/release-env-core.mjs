import { createHash } from "node:crypto";
import {
  encodeAbiParameters,
  encodeFunctionData,
  getAddress,
  isAddress,
  keccak256,
  parseAbi,
  recoverMessageAddress,
  toHex,
} from "viem";
import {
  exactDistinctPublicHttpsEndpoints,
  parseExactPublicHttpsUrl,
} from "./public-https-origin-core.mjs";
import {
  COMPUTE_WORKLOAD_BROWSER_ENV_KEYS,
  projectComputeWorkloadBrowserEnvFromHistoricalObservation,
} from "../../scripts/compute-workload-activation-observation-core.mjs";

export const RELEASE_SCHEMA = "dnai.web-release.v4";
export const SEMANTIC_VALIDATION_SCHEMA =
  "dnai.semantic-live-activation-validation.v3";
export const SEMANTIC_VALIDATION_STATUS =
  "live_activation_authority_validated";
export const SEMANTIC_VALIDATION_TRUTH_STATUS =
  "verified_signed_post_ceremony_C_revalidated_private_O_exact_env_D_and_dist_manifest_lineage";
export const BASE_SEPOLIA_CHAIN_ID = 84_532;
export const CANONICAL_PUBLIC_RPC = "https://sepolia.base.org";
// Circle's canonical Base Sepolia testnet USDC, not an operator-supplied
// six-decimal lookalike: https://developers.circle.com/stablecoins/usdc-contract-addresses
export const BASE_SEPOLIA_USDC = "0x036cbd53842c5426634e7929541ec2318f3dcf7e";
export const GITHUB_REPOSITORY = "therealwiki/dnai-wikigen";
export const GITHUB_SIGNER_WORKFLOW =
  "therealwiki/dnai-wikigen/.github/workflows/build-tee-images.yml";
export const EXECUTION_POLICY_CANONICALIZATION_VERSION =
  "policy-kernel-canonicalization/v2";
export const EXECUTION_POLICY_APPROVAL_SCHEMA =
  "dnai-wikigen/execution-policy-approval/v3";
export const EXECUTION_POLICY_API_SCHEMA_VERSION = 3;
export const EXECUTION_POLICY_STORE_SCHEMA_VERSION = 5;
export const EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA =
  "dnai.execution-policy-rollback-anchor.v1";
export const EXECUTION_POLICY_ANCHOR_VERIFICATION_MODEL =
  "single_rpc_reported_finalized_with_confirmation_depth";
export const EXECUTION_POLICY_ANCHOR_WRITER_EVIDENCE_SCHEMA =
  "dnai.execution-policy-anchor-writer-qvl-evidence.v2";
const EXECUTION_POLICY_ANCHOR_WRITER_REPORT_DATA_SCHEMA =
  "dnai.execution-policy-anchor-writer-qvl-evidence.v1";
export const EMAIL_ORACLE_EXTERNAL_EVIDENCE_SCHEMA =
  "dnai.email-oracle-external-release-evidence.v1";
export const LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.live-activation-authority-evidence.v1";
export const PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA =
  "dnai.pre-live-activation-authority-evidence.v1";
export const OPERATOR_POLICY_SCHEMA = LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;

const EXECUTION_POLICY_APPROVER_ROOT_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-approver-root/v1\0",
  "utf8",
);
const EXECUTION_POLICY_APPROVAL_DOMAIN_HASH_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-approval-domain/v1\0",
  "utf8",
);
const ARENA_APPROVED_CHALLENGE_SET_DOMAIN = Buffer.from(
  "dnai-wikigen/arena-release-approved-challenge-set/v1\0",
  "utf8",
);
export const ARENA_APPROVED_CHALLENGE_SET_SCHEMA =
  "dnai.arena.release-approved-challenge-set.v1";
const EXECUTION_POLICY_ANCHOR_WRITER_EVIDENCE_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-evidence/v1\0",
  "utf8",
);
const EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH_DOMAIN = Buffer.from(
  "dnai-wikigen/execution-policy-anchor-writer-key-path/v1\0",
  "utf8",
);
const COMPUTE_METERING_REPORT_DATA_DOMAIN = Buffer.from(
  "dnai-wikigen/compute-metering-signer-attestation/v1\0",
  "utf8",
);
const EMAIL_ORACLE_KMS_RESTART_DOMAIN = Buffer.from(
  "dnai-wikigen/email-oracle-kms-restart-attestation/v1\0",
  "utf8",
);
const EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH =
  "tinker/execution_policy_anchor_writer";
const EXECUTION_POLICY_ANCHOR_WRITER_CUSTODY =
  "dstack_derived_execution_policy_anchor_writer";

const VERDICT_SCHEMA = "dnai.independent-tdx-verdict.v4";
const VERIFICATION_METHOD = "intel_tdx_dcap_qvl";
const VERDICT_DOMAIN = Buffer.from(
  "dnai-wikigen/independent-tdx-verdict/v4\0",
  "utf8",
);
const MAX_ACTIVATION_EVIDENCE_LEASE_SECONDS = 900;
const VERDICT_EXECUTION_DOMAINS = Object.freeze(new Set([
  "main_runtime_cvm",
  "independent_metering_cvm",
]));
const CANONICAL_CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const CANONICAL_APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const SECP256K1_N = BigInt(
  "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
);
const REQUIRED_BROWSER_ORIGINS = new Set([
  "https://wikigen.me",
  "https://www.wikigen.me",
  "https://wikigenme.pages.dev",
]);
const IMAGE_PREFIX = "ghcr.io/therealwiki/dnai-wikigen/";
const REQUIRED_IMAGE_REPOSITORIES = Object.freeze({
  delegate: `${IMAGE_PREFIX}tinker-delegate`,
  oracle: `${IMAGE_PREFIX}tee-email-oracle`,
  neko: `${IMAGE_PREFIX}neko-chrome`,
});
const TRUST_DOMAIN_IMAGE_REPOSITORIES = Object.freeze({
  diligence_qvl: `${IMAGE_PREFIX}attestation-qvl`,
  arena_qvl: `${IMAGE_PREFIX}attestation-qvl`,
  anchor_writer_qvl: `${IMAGE_PREFIX}attestation-qvl`,
  compute_metering_qvl: `${IMAGE_PREFIX}attestation-qvl`,
  compute_workload_qvl: `${IMAGE_PREFIX}attestation-qvl`,
  compute_metering: `${IMAGE_PREFIX}compute-metering`,
});
const TRUST_DOMAIN_KEYS = Object.freeze([
  "diligence_qvl",
  "arena_qvl",
  "anchor_writer_qvl",
  "compute_metering_qvl",
  "compute_workload_qvl",
  "compute_metering",
]);
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const ZERO_BYTES32 = `0x${"0".repeat(64)}`;
const TINKER_COMPOSE_SET_TYPEHASH = keccak256(
  toHex("TinkerComposeSet(bytes32[] composeHashes)"),
);
const TINKER_EMPTY_COMPOSE_ROOT = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "bytes32[]" }],
  [TINKER_COMPOSE_SET_TYPEHASH, []],
));
const TINKER_MANAGER_SET_TYPEHASH = keccak256(
  toHex("TinkerManagerSet(address[] managers)"),
);
const TINKER_EMPTY_MANAGER_ROOT = keccak256(encodeAbiParameters(
  [{ type: "bytes32" }, { type: "address[]" }],
  [TINKER_MANAGER_SET_TYPEHASH, []],
));
const DILIGENCE_EVALUATOR_POLICY_SET_TYPE =
  "DiligenceRoomEvaluatorPolicySet(bytes32[3] evaluatorPolicies)";
const DILIGENCE_EVALUATOR_POLICY_SET_TYPEHASH = keccak256(
  toHex(DILIGENCE_EVALUATOR_POLICY_SET_TYPE),
);

function diligenceEvaluatorPolicySetRoot(values) {
  if (!Array.isArray(values) || values.length !== 3) {
    throw new Error("DiligenceRoom evaluator policy set must contain exactly three commitments");
  }
  const policies = values.map((value, index) => bytes32(
    value,
    `DiligenceRoom evaluator policy commitment[${index}]`,
  )).sort();
  if (new Set(policies).size !== 3) {
    throw new Error("DiligenceRoom evaluator policy commitments must be pairwise distinct");
  }
  return keccak256(encodeAbiParameters(
    [{ type: "bytes32" }, { type: "bytes32[3]" }],
    [DILIGENCE_EVALUATOR_POLICY_SET_TYPEHASH, policies],
  )).toLowerCase();
}
const TINKER_RELEASE_HISTORY_KEYS = Object.freeze([
  "kind",
  "chainId",
  "encumbranceAddress",
  "runtimeCodeHash",
  "phase",
  "recordedAt",
  "sourceCommit",
  "transactionHash",
  "blockNumber",
  "status",
  "policyState",
  "pendingOwner",
  "accountCommitment",
  "maxAddBalanceWei",
  "maxSpendWei",
  "perOperationCaps",
  "custodiesFunds",
  "approvedComposeHashes",
  "composeRoot",
  "composeCount",
  "managers",
  "managerRoot",
  "managerCount",
  "releasePolicyCommitment",
  "releaseMaxAddBalanceWei",
  "releaseMaxSpendWei",
  "releaseComposeHashes",
  "releaseComposeRoot",
  "releaseComposeCount",
  "releaseManagers",
  "releaseManagerRoot",
  "releaseManagerCount",
  "pendingAccountCommitment",
  "pendingMaxAddBalanceWei",
  "pendingMaxSpendWei",
  "pendingComposeHashes",
  "pendingComposeRoot",
  "pendingComposeCount",
  "pendingManagers",
  "pendingManagerRoot",
  "pendingManagerCount",
  "pendingReleasePolicyCommitment",
  "pendingReleasePolicyActivatesAt",
  "releasePolicyFrozen",
  "emergencyHalted",
]);
const CHALLENGE_VERSION_REVIEW_DELAY_SECONDS = 172_800n;
const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const APP_REGISTERED_TOPIC = keccak256(toHex("AppRegistered(address)"));
const APP_BOOT_INFO_ABI_PARAMETER = Object.freeze({
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
});

const DILIGENCE_ABI = parseAbi([
  "function developer() view returns (address)",
  "function resultVerifier() view returns (address)",
  "function attestationVerifier() view returns (address)",
  "function attestationReleasePolicyHash() view returns (bytes32)",
  "function pendingAttestationVerifier() view returns (address)",
  "function pendingAttestationReleasePolicyHash() view returns (bytes32)",
  "function pendingAttestationBindingActivatesAt() view returns (uint256)",
  "function attestationBindingFrozen() view returns (bool)",
  "function approvedEvaluatorPolicyCount() view returns (uint256)",
  "function pendingEvaluatorPolicyCount() view returns (uint256)",
  "function evaluatorPolicySetFrozen() view returns (bool)",
  "function evaluatorPolicySetRoot() view returns (bytes32)",
  "function evaluatorPolicies() view returns (bytes32[3])",
  "function approvedEvaluatorPolicies(bytes32) view returns (bool)",
  "function pendingEvaluatorPolicyActivations(bytes32) view returns (uint256)",
  "function feeBps() view returns (uint256)",
  "function feeBpsFrozen() view returns (bool)",
  "function pendingFeeBpsActivatesAt() view returns (uint256)",
  "function COMPUTE_SETTLEMENT_BPS() view returns (uint256)",
  "function computeSettlementPolicyEnabled() view returns (bool)",
  "function composeApprovalRequired() view returns (bool)",
  "function teeIdentityApprovalRequired() view returns (bool)",
  "function approvalRequirementsFrozen() view returns (bool)",
  "function composeAdditionsFrozen() view returns (bool)",
  "function teeIdentityAdditionsFrozen() view returns (bool)",
  "function approvedComposeCount() view returns (uint256)",
  "function approvedTeeIdentityCount() view returns (uint256)",
  "function pendingComposeCount() view returns (uint256)",
  "function pendingTeeIdentityCount() view returns (uint256)",
  "function approvedComposeHashes(bytes32) view returns (bool)",
  "function teeIdentityComposeHash(address) view returns (bytes32)",
]);
const CHALLENGE_ABI = parseAbi([
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function registryPaused() view returns (bool)",
  "function nextChallengeId() view returns (uint256)",
  "function challengeCount() view returns (uint256)",
  "function challengeExists(uint256) view returns (bool)",
  "function MIN_VERSION_REVIEW_DELAY() view returns (uint64)",
  "function reviewEligibleAt(uint256) view returns (uint64)",
]);
const CHALLENGE_DETAIL_ABI = [
  {
    type: "function",
    name: "getChallenge",
    stateMutability: "view",
    inputs: [{ name: "challengeId", type: "uint256" }],
    outputs: [{
      name: "",
      type: "tuple",
      components: [
        { name: "controller", type: "address" },
        { name: "pendingController", type: "address" },
        { name: "lifecycle", type: "uint8" },
        { name: "createdAt", type: "uint64" },
        { name: "updatedAt", type: "uint64" },
        { name: "latestVersion", type: "uint32" },
        { name: "paused", type: "bool" },
        { name: "configurationFrozen", type: "bool" },
      ],
    }],
  },
  {
    type: "function",
    name: "getVersion",
    stateMutability: "view",
    inputs: [
      { name: "challengeId", type: "uint256" },
      { name: "version", type: "uint32" },
    ],
    outputs: [{
      name: "",
      type: "tuple",
      components: [
        { name: "metadataURI", type: "string" },
        { name: "metadataHash", type: "bytes32" },
        { name: "sealedArtifactCommitment", type: "bytes32" },
        { name: "evaluatorCommitment", type: "bytes32" },
        { name: "releasePolicyCommitment", type: "bytes32" },
        { name: "createdAt", type: "uint64" },
      ],
    }],
  },
];
const ENCUMBRANCE_ABI = parseAbi([
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function accountCommitment() view returns (bytes32)",
  "function maxAddBalanceWei() view returns (uint256)",
  "function maxSpendWei() view returns (uint256)",
  "function approvedComposeRoot() view returns (bytes32)",
  "function approvedComposeCount() view returns (uint256)",
  "function approvedComposeHashAt(uint256) view returns (bytes32)",
  "function managerRoot() view returns (bytes32)",
  "function managerCount() view returns (uint256)",
  "function managerAt(uint256) view returns (address)",
  "function releasePolicyCommitment() view returns (bytes32)",
  "function releaseMaxAddBalanceWei() view returns (uint256)",
  "function releaseMaxSpendWei() view returns (uint256)",
  "function releaseComposeRoot() view returns (bytes32)",
  "function releaseComposeCount() view returns (uint256)",
  "function releaseManagerRoot() view returns (bytes32)",
  "function releaseManagerCount() view returns (uint256)",
  "function releasePolicyFrozen() view returns (bool)",
  "function pendingAccountCommitment() view returns (bytes32)",
  "function pendingMaxAddBalanceWei() view returns (uint256)",
  "function pendingMaxSpendWei() view returns (uint256)",
  "function pendingComposeRoot() view returns (bytes32)",
  "function pendingManagerRoot() view returns (bytes32)",
  "function pendingReleasePolicyCommitment() view returns (bytes32)",
  "function pendingReleasePolicyActivatesAt() view returns (uint64)",
  "function pendingComposeCount() view returns (uint256)",
  "function pendingManagerCount() view returns (uint256)",
  "function RELEASE_POLICY_DELAY() view returns (uint256)",
  "function approvedComposeHashes(bytes32) view returns (bool)",
  "function managers(address) view returns (bool)",
  "function emergencyHalted() view returns (bool)",
]);
const EMAIL_ORACLE_ABI = parseAbi([
  "function owner() view returns (address)",
  "function pendingOwner() view returns (address)",
  "function ORACLE_UPGRADE_DELAY() view returns (uint256)",
  "function allowAnyDevice() view returns (bool)",
  "function oracleCodeFrozen() view returns (bool)",
  "function consumerRegistryFrozen() view returns (bool)",
  "function consumerManagerAdditionsFrozen() view returns (bool)",
  "function kmsBindingFrozen() view returns (bool)",
  "function allowedOracleComposeHashCount() view returns (uint256)",
  "function pendingOracleComposeHashCount() view returns (uint256)",
  "function allowedDeviceIdCount() view returns (uint256)",
  "function consumerManagerCount() view returns (uint256)",
  "function totalConsumerComposeHashCount() view returns (uint256)",
  "function releaseOracleComposeHash() view returns (bytes32)",
  "function releaseDeviceId() view returns (bytes32)",
  "function releaseConsumerManager() view returns (address)",
  "function releaseConsumerAppId() view returns (address)",
  "function releaseConsumerComposeHash() view returns (bytes32)",
  "function allowedOracleComposeHashes(bytes32) view returns (bool)",
  "function allowedDeviceIds(bytes32) view returns (bool)",
  "function consumerManagers(address) view returns (bool)",
  "function consumerEmergencyRevoked(address) view returns (bool)",
  "function consumerComposeHashCount(address) view returns (uint256)",
  "function isConsumerAuthorized(address,bytes32) view returns (bool)",
  "function kmsContract() view returns (address)",
  "function kmsRuntimeCodeHash() view returns (bytes32)",
  "function kmsImplementation() view returns (address)",
  "function kmsImplementationRuntimeCodeHash() view returns (bytes32)",
  "function kmsRegistrationTxHash() view returns (bytes32)",
  "function kmsRegistrationBlock() view returns (uint64)",
  "function kmsRegistrationBlockHash() view returns (bytes32)",
  "function targetBootInfoHash() view returns (bytes32)",
  "function restartKeyDerivationProofHash() view returns (bytes32)",
  "function pendingKmsContract() view returns (address)",
  "function pendingKmsRuntimeCodeHash() view returns (bytes32)",
  "function pendingKmsImplementation() view returns (address)",
  "function pendingKmsImplementationRuntimeCodeHash() view returns (bytes32)",
  "function pendingKmsRegistrationTxHash() view returns (bytes32)",
  "function pendingKmsRegistrationBlock() view returns (uint64)",
  "function pendingKmsRegistrationBlockHash() view returns (bytes32)",
  "function pendingTargetBootInfoHash() view returns (bytes32)",
  "function pendingRestartKeyDerivationProofHash() view returns (bytes32)",
  "function pendingKmsBindingActivatesAt() view returns (uint256)",
  "function releaseConfigurationReady() view returns (bool)",
]);
const DSTACK_KMS_ABI = parseAbi([
  "function registerApp(address appId)",
  "function registeredApps(address appId) view returns (bool)",
  "function isAppAllowed((address appId,bytes32 composeHash,address instanceId,bytes32 deviceId,bytes32 mrAggregated,bytes32 mrSystem,bytes32 osImageHash,string tcbStatus,string[] advisoryIds) bootInfo) view returns (bool isAllowed,string reason)",
  "event AppRegistered(address appId)",
]);
const COMPUTE_VAULT_ABI = parseAbi([
  "function owner() view returns (address)",
  "function developer() view returns (address)",
  "function meteringVerifier() view returns (address)",
  "function meteringQvlVerifier() view returns (address)",
  "function meteringPolicySetHash() view returns (bytes32)",
  "function pendingMeteringVerifier() view returns (address)",
  "function pendingMeteringQvlVerifier() view returns (address)",
  "function pendingMeteringPolicySetHash() view returns (bytes32)",
  "function pendingMeteringBindingActivatesAt() view returns (uint64)",
  "function meteringBindingFrozen() view returns (bool)",
  "function paused() view returns (bool)",
  "function developerFeeBps() view returns (uint16)",
  "function developerFeeFrozen() view returns (bool)",
  "function pendingDeveloperFeeActivatesAt() view returns (uint64)",
  "function composePolicyFrozen() view returns (bool)",
  "function teeIdentityAdditionsFrozen() view returns (bool)",
  "function ratePolicyAdditionsFrozen() view returns (bool)",
  "function assetAdditionsFrozen() view returns (bool)",
  "function allowedAssetCount() view returns (uint256)",
  "function activeRatePolicyCount() view returns (uint256)",
  "function approvedComposeCount() view returns (uint256)",
  "function approvedTeeIdentityCount() view returns (uint256)",
  "function pendingAssetCount() view returns (uint256)",
  "function pendingRatePolicyCount() view returns (uint256)",
  "function pendingComposeCount() view returns (uint256)",
  "function pendingTeeIdentityCount() view returns (uint256)",
  "function approvedComposeHashes(bytes32) view returns (bool)",
  "function teeIdentityComposeHash(address) view returns (bytes32)",
  "function allowedAssets(address) view returns (bool)",
  "function ratePolicies(bytes32) view returns (address asset,address provider,uint16 developerFeeBps,bool active)",
]);
const ERC20_ABI = parseAbi([
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
]);
const EXECUTION_POLICY_ANCHOR_ABI = parseAbi([
  "function owner() view returns (address)",
  "function deploymentIntentSha256() view returns (bytes32)",
  "function reviewerAuthorityGenesisAcceptanceSha256() view returns (bytes32)",
  "function writer() view returns (address)",
  "function writerReleaseCommitment() view returns (bytes32)",
  "function pendingWriter() view returns (address)",
  "function pendingWriterReleaseCommitment() view returns (bytes32)",
  "function pendingWriterActivatesAt() view returns (uint64)",
  "function writerRotationsFrozen() view returns (bool)",
  "function paused() view returns (bool)",
  "function globalSequence() view returns (uint256)",
  "function globalHead() view returns (bytes32)",
]);

const CONTRACT_KEYS = Object.freeze([
  "diligence_room",
  "challenge_registry",
  "royalty_distributor",
  "tinker_account_encumbrance",
  "compute_credit_vault",
  "email_oracle_auth",
  "usdc",
]);

const ENV_KEYS = Object.freeze([
  "VITE_BASE_SEPOLIA_RPC_URL",
  "VITE_BASE_SEPOLIA_SECONDARY_RPC_URL",
  "VITE_RELEASE_SHA",
  "VITE_DILIGENCE_ROOM_ADDRESS",
  "VITE_DILIGENCE_ROOM_CODE_HASH",
  "VITE_DILIGENCE_ROOM_DEVELOPER",
  "VITE_DILIGENCE_RESULT_VERIFIER",
  "VITE_DILIGENCE_ATTESTATION_VERIFIER",
  "VITE_DILIGENCE_QVL_RELEASE_POLICY_HASH",
  "VITE_CHALLENGE_REGISTRY_ADDRESS",
  "VITE_CHALLENGE_REGISTRY_CODE_HASH",
  "VITE_ROYALTY_DISTRIBUTOR_ADDRESS",
  "VITE_ROYALTY_DISTRIBUTOR_CODE_HASH",
  "VITE_TINKER_ENCUMBRANCE_ADDRESS",
  "VITE_TINKER_ENCUMBRANCE_CODE_HASH",
  "VITE_EMAIL_ORACLE_AUTH_ADDRESS",
  "VITE_EMAIL_ORACLE_AUTH_CODE_HASH",
  "VITE_COMPUTE_CREDIT_VAULT_ADDRESS",
  "VITE_COMPUTE_CREDIT_VAULT_CODE_HASH",
  "VITE_ENABLE_COMPUTE_VAULT_FUNDING",
  "VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION",
  "VITE_COMPUTE_VAULT_DEVELOPER",
  "VITE_COMPUTE_VAULT_METERING_VERIFIER",
  "VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER",
  "VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH",
  "VITE_COMPUTE_VAULT_TEE_IDENTITY",
  "VITE_COMPUTE_VAULT_COMPOSE_HASH",
  "VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT",
  "VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS",
  "VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH",
  "VITE_COMPUTE_VAULT_ERC20_SYMBOL",
  "VITE_COMPUTE_VAULT_ERC20_DECIMALS",
  "VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT",
  "VITE_TEE_IDENTITY",
  "VITE_USDC_ADDRESS",
  "VITE_ENABLE_CONTRACT_WRITES",
  "VITE_DELEGATE_URL",
  "VITE_PHALA_APP_ID",
  "VITE_PHALA_CVM_ID",
  "VITE_PHALA_COMPOSE_HASH",
  "VITE_PHALA_OS_IMAGE_HASH",
  "VITE_DELEGATE_IMAGE_DIGEST",
  "VITE_WALLETCONNECT_PROJECT_ID",
  "VITE_WALLET_AUTH_DOMAIN",
  "VITE_WALLET_AUTH_URI",
  "VITE_ENABLE_ARTIFACT_UPLOAD",
  "VITE_ARTIFACT_VERIFIED_QUOTE_SHA256",
  "VITE_ENABLE_COMPUTE_CONSOLE",
  ...COMPUTE_WORKLOAD_BROWSER_ENV_KEYS,
  "VITE_ENABLE_ARENA_SUBMISSION",
  "VITE_ARENA_VERIFIED_QUOTE_SHA256",
  "VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256",
  "VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON",
  "VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256",
  "VITE_EXECUTION_POLICY_ANCHOR_ADDRESS",
  "VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH",
  "VITE_EXECUTION_POLICY_ANCHOR_WRITER",
  "VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT",
  "VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS",
  "VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS",
  "VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS",
  "VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH",
  "VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH",
  "VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON",
]);

function record(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

function exactRecord(value, keys, label) {
  const parsed = record(value, label);
  const actual = Object.keys(parsed).sort();
  const expected = [...keys].sort();
  const missing = expected.filter((key) => !actual.includes(key));
  const extra = actual.filter((key) => !expected.includes(key));
  if (missing.length || extra.length) {
    const details = [
      missing.length ? `missing ${missing.join(", ")}` : "",
      extra.length ? `unexpected ${extra.join(", ")}` : "",
    ].filter(Boolean).join("; ");
    throw new Error(`${label} fields are not exact: ${details}`);
  }
  return parsed;
}

function nonEmptyString(value, label, maximum = 512) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > maximum
    || /[\0\r\n]/.test(value)
  ) {
    throw new Error(`${label} must be a bounded single-line string`);
  }
  return value;
}

function bool(value, label) {
  if (typeof value !== "boolean") throw new Error(`${label} must be boolean`);
  return value;
}

function integer(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    throw new Error(`${label} must be a safe integer >= ${minimum}`);
  }
  return value;
}

function boundedInteger(value, label, minimum, maximum) {
  const normalized = integer(value, label, minimum);
  if (normalized > maximum) {
    throw new Error(`${label} must be a safe integer <= ${maximum}`);
  }
  return normalized;
}

function uint256Decimal(value, label) {
  if (typeof value !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${label} must be a canonical uint256 decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed < 0n || parsed >= (1n << 256n)) {
    throw new Error(`${label} must fit uint256`);
  }
  return value;
}

function address(value, label) {
  if (typeof value !== "string" || !isAddress(value, { strict: true })) {
    throw new Error(`${label} must be an Ethereum address`);
  }
  const normalized = getAddress(value).toLowerCase();
  if (normalized === "0x0000000000000000000000000000000000000000") {
    throw new Error(`${label} cannot be the zero address`);
  }
  return normalized;
}

function assetAddress(value, label) {
  if (typeof value !== "string" || !isAddress(value, { strict: true })) {
    throw new Error(`${label} must be an Ethereum asset address`);
  }
  return getAddress(value).toLowerCase();
}

function bytes32(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be a 0x-prefixed bytes32`);
  }
  const normalized = value.toLowerCase();
  if (normalized === `0x${"0".repeat(64)}`) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function bareBytes32(value, label) {
  if (typeof value !== "string" || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${label} must be 32-byte lowercase-compatible hex without 0x`);
  }
  const normalized = value.toLowerCase();
  if (normalized === "0".repeat(64)) throw new Error(`${label} cannot be zero`);
  return normalized;
}

function sha256Pin(value, label) {
  if (typeof value !== "string" || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be sha256 followed by 64 lowercase hex characters`);
  }
  return value;
}

function nonzeroSha256Pin(value, label) {
  const normalized = sha256Pin(value, label);
  if (normalized === `sha256:${"0".repeat(64)}`) {
    throw new Error(`${label} cannot be zero`);
  }
  return normalized;
}

function canonicalVerdictBytes32(value, label) {
  if (typeof value !== "string" || !/^0x(?!0{64}$)[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a nonzero canonical lowercase bytes32`);
  }
  return value;
}

function canonicalVerdictBareBytes32(value, label) {
  if (typeof value !== "string" || !/^(?!0{64}$)[0-9a-f]{64}$/.test(value)) {
    throw new Error(`${label} must be a nonzero canonical lowercase bare bytes32`);
  }
  return value;
}

function canonicalVerdictAddress(value, label) {
  const normalized = address(value, label);
  if (value !== normalized) {
    throw new Error(`${label} must be a canonical lowercase address`);
  }
  return normalized;
}

function canonicalVerdictAppId(value, label) {
  if (typeof value !== "string" || !CANONICAL_APP_ID.test(value)) {
    throw new Error(`${label} must be a nonzero canonical lowercase Phala app ID`);
  }
  return value;
}

function canonicalVerdictCvmId(value, label) {
  if (typeof value !== "string" || !CANONICAL_CVM_ID.test(value)) {
    throw new Error(`${label} must be a canonical lowercase CVM ID`);
  }
  return value;
}

function normalizeReleaseAuthorityBinding(value) {
  const parsed = exactRecord(value, [
    "deploymentIntentSha256",
    "reviewerAuthorityGenesisAcceptanceSha256",
    "ceremonyAuthorizationSha256",
    "runtimeAuthorityDependencySha256",
  ], "release authority binding");
  return {
    deploymentIntentSha256: nonzeroSha256Pin(
      parsed.deploymentIntentSha256,
      "release authority deployment-intent digest",
    ),
    reviewerAuthorityGenesisAcceptanceSha256: nonzeroSha256Pin(
      parsed.reviewerAuthorityGenesisAcceptanceSha256,
      "release authority reviewer-genesis-acceptance digest",
    ),
    ceremonyAuthorizationSha256: nonzeroSha256Pin(
      parsed.ceremonyAuthorizationSha256,
      "release authority ceremony-authorization digest",
    ),
    runtimeAuthorityDependencySha256: nonzeroSha256Pin(
      parsed.runtimeAuthorityDependencySha256,
      "release authority runtime-dependency digest",
    ),
  };
}

function sha256PinAsBytes32(value, label) {
  return `0x${nonzeroSha256Pin(value, label).slice("sha256:".length)}`;
}

function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function executionPolicyApproverRootHash(approverHashes) {
  const encoded = Buffer.from(JSON.stringify(approverHashes), "utf8");
  return createHash("sha256")
    .update(EXECUTION_POLICY_APPROVER_ROOT_DOMAIN)
    .update(encoded)
    .digest("hex");
}

export function executionPolicyApprovalDomainHash(approvalDomain) {
  return createHash("sha256")
    .update(EXECUTION_POLICY_APPROVAL_DOMAIN_HASH_DOMAIN)
    .update(Buffer.from(approvalDomain, "ascii"))
    .digest("hex");
}

function normalizeExecutionPolicy(value, { cvm, cvmLaunchIntentSha256 }) {
  const parsed = exactRecord(value, [
    "canonicalization_version",
    "approval_schema",
    "api_schema_version",
    "store_schema_version",
    "approval_domain",
    "approval_domain_hash",
    "approver_hashes",
    "approver_root_hash",
    "rollback_anchor",
  ], "execution_policy");
  if (parsed.canonicalization_version !== EXECUTION_POLICY_CANONICALIZATION_VERSION) {
    throw new Error("execution_policy canonicalization version is not the reviewed release version");
  }
  if (parsed.approval_schema !== EXECUTION_POLICY_APPROVAL_SCHEMA) {
    throw new Error("execution_policy approval schema is not the reviewed release version");
  }
  if (parsed.api_schema_version !== EXECUTION_POLICY_API_SCHEMA_VERSION) {
    throw new Error("execution_policy API schema version is not the reviewed release version");
  }
  if (parsed.store_schema_version !== EXECUTION_POLICY_STORE_SCHEMA_VERSION) {
    throw new Error("execution_policy store schema version is not the reviewed release version");
  }

  if (!Array.isArray(parsed.approver_hashes) || !parsed.approver_hashes.length || parsed.approver_hashes.length > 64) {
    throw new Error("execution_policy.approver_hashes must contain 1 to 64 reviewed signer commitments");
  }
  const approverHashes = parsed.approver_hashes.map((item, index) =>
    bareBytes32(item, `execution_policy.approver_hashes[${index}]`));
  const sortedApproverHashes = [...new Set(approverHashes)].sort();
  if (
    sortedApproverHashes.length !== approverHashes.length
    || sortedApproverHashes.some((item, index) => item !== parsed.approver_hashes[index])
  ) {
    throw new Error("execution_policy.approver_hashes must be lowercase, sorted, and unique");
  }
  const approverRootHash = bareBytes32(
    parsed.approver_root_hash,
    "execution_policy.approver_root_hash",
  );
  if (approverRootHash !== executionPolicyApproverRootHash(sortedApproverHashes)) {
    throw new Error("execution_policy approver root does not match the exact signer set");
  }

  const rawAnchor = exactRecord(parsed.rollback_anchor, [
    "schema",
    "status",
    "chain_id",
    "contract_address",
    "runtime_code_hash",
    "release_manifest_commitment",
    "evidence_sha256",
    "writer_address",
    "writer_release_commitment",
    "writer_custody",
    "writer_key_path",
    "confirmations",
    "max_block_age_seconds",
    "max_future_block_skew_seconds",
    "verification_model",
    "independent_rpc_quorum_verified",
    "consensus_proof_verified",
  ], "execution_policy.rollback_anchor");
  if (rawAnchor.schema !== EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA) {
    throw new Error("execution-policy rollback anchor schema is not supported");
  }
  if (rawAnchor.status !== "verified_active_frozen_release_writer") {
    throw new Error("execution-policy rollback anchor is unavailable or not the active frozen release writer");
  }
  if (rawAnchor.chain_id !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error("execution-policy rollback anchor is not pinned to Base Sepolia");
  }
  const rollbackAnchor = {
    schema: EXECUTION_POLICY_ROLLBACK_ANCHOR_SCHEMA,
    status: "verified_active_frozen_release_writer",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    contract_address: address(
      rawAnchor.contract_address,
      "execution_policy.rollback_anchor.contract_address",
    ),
    runtime_code_hash: bytes32(
      rawAnchor.runtime_code_hash,
      "execution_policy.rollback_anchor.runtime_code_hash",
    ),
    release_manifest_commitment: bareBytes32(
      rawAnchor.release_manifest_commitment,
      "execution_policy.rollback_anchor.release_manifest_commitment",
    ),
    evidence_sha256: sha256Pin(
      rawAnchor.evidence_sha256,
      "execution_policy.rollback_anchor.evidence_sha256",
    ),
    writer_address: address(
      rawAnchor.writer_address,
      "execution_policy.rollback_anchor.writer_address",
    ),
    writer_release_commitment: bytes32(
      rawAnchor.writer_release_commitment,
      "execution_policy.rollback_anchor.writer_release_commitment",
    ),
    writer_custody: nonEmptyString(
      rawAnchor.writer_custody,
      "execution_policy.rollback_anchor.writer_custody",
      128,
    ),
    writer_key_path: nonEmptyString(
      rawAnchor.writer_key_path,
      "execution_policy.rollback_anchor.writer_key_path",
      128,
    ),
    confirmations: integer(
      rawAnchor.confirmations,
      "execution_policy.rollback_anchor.confirmations",
      2,
    ),
    max_block_age_seconds: integer(
      rawAnchor.max_block_age_seconds,
      "execution_policy.rollback_anchor.max_block_age_seconds",
      30,
    ),
    max_future_block_skew_seconds: integer(
      rawAnchor.max_future_block_skew_seconds,
      "execution_policy.rollback_anchor.max_future_block_skew_seconds",
      0,
    ),
    verification_model: nonEmptyString(
      rawAnchor.verification_model,
      "execution_policy.rollback_anchor.verification_model",
      128,
    ),
    independent_rpc_quorum_verified: bool(
      rawAnchor.independent_rpc_quorum_verified,
      "execution_policy.rollback_anchor.independent_rpc_quorum_verified",
    ),
    consensus_proof_verified: bool(
      rawAnchor.consensus_proof_verified,
      "execution_policy.rollback_anchor.consensus_proof_verified",
    ),
  };
  if (rollbackAnchor.evidence_sha256 === `sha256:${"0".repeat(64)}`) {
    throw new Error("execution-policy rollback anchor evidence cannot be a placeholder");
  }
  if (
    rollbackAnchor.writer_release_commitment
    !== `0x${cvmLaunchIntentSha256.slice("sha256:".length)}`
  ) {
    throw new Error(
      "execution-policy anchor writer release must equal the reviewed CVM launch-intent digest",
    );
  }
  if (
    rollbackAnchor.writer_custody
      !== "dstack_derived_execution_policy_anchor_writer"
    || rollbackAnchor.writer_key_path
      !== "tinker/execution_policy_anchor_writer"
  ) {
    throw new Error("execution-policy anchor writer custody is not the reviewed dstack key domain");
  }
  if (rollbackAnchor.confirmations > 256) {
    throw new Error("execution-policy anchor confirmations must be <= 256");
  }
  if (rollbackAnchor.max_block_age_seconds > 3_600) {
    throw new Error("execution-policy anchor max block age must be <= 3600 seconds");
  }
  if (rollbackAnchor.max_future_block_skew_seconds > 300) {
    throw new Error("execution-policy anchor max future block skew must be <= 300 seconds");
  }
  if (
    rollbackAnchor.verification_model !== EXECUTION_POLICY_ANCHOR_VERIFICATION_MODEL
    || rollbackAnchor.independent_rpc_quorum_verified !== false
    || rollbackAnchor.consensus_proof_verified !== false
  ) {
    throw new Error("execution-policy anchor must preserve the exact single-RPC finality trust label");
  }

  const expectedDomain = [
    "base-sepolia",
    String(BASE_SEPOLIA_CHAIN_ID),
    rollbackAnchor.release_manifest_commitment,
    `0x${cvm.compose_hash}`,
    sha256Hex(Buffer.from(cvm.app_id, "utf8")),
    approverRootHash,
  ].join(":");
  const approvalDomain = nonEmptyString(
    parsed.approval_domain,
    "execution_policy.approval_domain",
    512,
  );
  if (approvalDomain !== expectedDomain) {
    throw new Error("execution_policy approval domain is not exactly derived from the release roots");
  }
  const approvalDomainHash = bareBytes32(
    parsed.approval_domain_hash,
    "execution_policy.approval_domain_hash",
  );
  if (approvalDomainHash !== executionPolicyApprovalDomainHash(approvalDomain)) {
    throw new Error("execution_policy approval domain hash does not match the exact domain");
  }

  return {
    canonicalization_version: EXECUTION_POLICY_CANONICALIZATION_VERSION,
    approval_schema: EXECUTION_POLICY_APPROVAL_SCHEMA,
    api_schema_version: EXECUTION_POLICY_API_SCHEMA_VERSION,
    store_schema_version: EXECUTION_POLICY_STORE_SCHEMA_VERSION,
    approval_domain: approvalDomain,
    approval_domain_hash: approvalDomainHash,
    approver_hashes: sortedApproverHashes,
    approver_root_hash: approverRootHash,
    rollback_anchor: rollbackAnchor,
  };
}

function releaseSha(value, label = "release_sha") {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error(`${label} must be a full lowercase Git commit SHA`);
  }
  return value;
}

function httpsUrl(value, label) {
  const raw = nonEmptyString(value, label, 2_048);
  let parsed;
  try {
    parsed = parseExactPublicHttpsUrl(raw, label);
  } catch {
    throw new Error(`${label} must be an exact public HTTPS origin or endpoint`);
  }
  return parsed.toString().replace(/\/$/, "");
}

function httpsOrigin(value, label) {
  const normalized = httpsUrl(value, label);
  const parsed = new URL(normalized);
  if (parsed.pathname !== "/") {
    throw new Error(`${label} must be an HTTPS origin without a path`);
  }
  return parsed.origin;
}

function boundedServiceEndpoint(value, label, expectedPath) {
  const raw = nonEmptyString(value, label, 512);
  const normalized = httpsUrl(raw, label);
  const parsed = new URL(normalized);
  if (normalized !== raw || parsed.pathname !== expectedPath) {
    throw new Error(`${label} must be the canonical bounded HTTPS ${expectedPath} endpoint`);
  }
  return normalized;
}

function sameAddress(actual, expected, label) {
  if (address(actual, label) !== address(expected, `${label} expected`)) {
    throw new Error(`${label} mismatch`);
  }
}

function sameBytes32(actual, expected, label) {
  if (bytes32(String(actual), label) !== bytes32(expected, `${label} expected`)) {
    throw new Error(`${label} mismatch`);
  }
}

function zeroAddress(value, label) {
  if (typeof value !== "string" || value.toLowerCase() !== ZERO_ADDRESS) {
    throw new Error(`${label} must be the zero address`);
  }
  return ZERO_ADDRESS;
}

function zeroBytes32(value, label) {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-fA-F]{64}$/.test(value)
    || value.toLowerCase() !== ZERO_BYTES32
  ) {
    throw new Error(`${label} must be the zero bytes32 value`);
  }
  return ZERO_BYTES32;
}

function exactBytes32Array(value, expected, label) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} must contain the exact reviewed bytes32 members`);
  }
  value.forEach((entry, index) => {
    sameBytes32(entry, expected[index], `${label}[${index}]`);
  });
  return value;
}

function exactAddressArray(value, expected, label) {
  if (!Array.isArray(value) || value.length !== expected.length) {
    throw new Error(`${label} must contain the exact reviewed address members`);
  }
  value.forEach((entry, index) => {
    sameAddress(entry, expected[index], `${label}[${index}]`);
  });
  return value;
}

function transactionHash(value, label) {
  if (
    typeof value !== "string"
    || !/^0x[0-9a-f]{64}$/.test(value)
    || value === ZERO_BYTES32
  ) {
    throw new Error(`${label} must be a nonzero lowercase transaction hash`);
  }
  return value;
}

function utcTimestampSeconds(value, label) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) {
    throw new Error(`${label} must be a canonical second-resolution UTC timestamp`);
  }
  const milliseconds = Date.parse(value);
  if (
    !Number.isSafeInteger(milliseconds)
    || new Date(milliseconds).toISOString() !== value.replace(/Z$/, ".000Z")
  ) {
    throw new Error(`${label} must be a valid canonical UTC timestamp`);
  }
  return Math.floor(milliseconds / 1_000);
}

function normalizeEmailOracleRelease(value) {
  const parsed = exactRecord(value, [
    "device_id",
    "kms_contract_address",
    "kms_runtime_code_hash",
    "kms_implementation_address",
    "kms_implementation_runtime_code_hash",
    "kms_registration_tx_hash",
    "kms_registration_block",
    "kms_registration_block_hash",
    "target_boot",
    "restart_key_derivation_proof_hash",
    "external_evidence_sha256",
  ], "email_oracle_auth.release");
  const boot = exactRecord(parsed.target_boot, [
    "instance_id",
    "mr_aggregated",
    "mr_system",
    "os_image_hash",
    "tcb_status",
    "advisory_ids",
    "info_hash",
  ], "email_oracle_auth.release.target_boot");
  if (boot.tcb_status !== "UpToDate") {
    throw new Error("EmailOracleAuth target boot TCB status must be exactly UpToDate");
  }
  if (!Array.isArray(boot.advisory_ids) || boot.advisory_ids.length !== 0) {
    throw new Error("EmailOracleAuth target boot advisory set must be exactly empty");
  }
  return {
    device_id: bytes32(parsed.device_id, "email_oracle_auth.release.device_id"),
    kms_contract_address: address(
      parsed.kms_contract_address,
      "email_oracle_auth.release.kms_contract_address",
    ),
    kms_runtime_code_hash: bytes32(
      parsed.kms_runtime_code_hash,
      "email_oracle_auth.release.kms_runtime_code_hash",
    ),
    kms_implementation_address: address(
      parsed.kms_implementation_address,
      "email_oracle_auth.release.kms_implementation_address",
    ),
    kms_implementation_runtime_code_hash: bytes32(
      parsed.kms_implementation_runtime_code_hash,
      "email_oracle_auth.release.kms_implementation_runtime_code_hash",
    ),
    kms_registration_tx_hash: bytes32(
      parsed.kms_registration_tx_hash,
      "email_oracle_auth.release.kms_registration_tx_hash",
    ),
    kms_registration_block: integer(
      parsed.kms_registration_block,
      "email_oracle_auth.release.kms_registration_block",
      1,
    ),
    kms_registration_block_hash: bytes32(
      parsed.kms_registration_block_hash,
      "email_oracle_auth.release.kms_registration_block_hash",
    ),
    target_boot: {
      instance_id: address(
        boot.instance_id,
        "email_oracle_auth.release.target_boot.instance_id",
      ),
      mr_aggregated: bytes32(
        boot.mr_aggregated,
        "email_oracle_auth.release.target_boot.mr_aggregated",
      ),
      mr_system: bytes32(
        boot.mr_system,
        "email_oracle_auth.release.target_boot.mr_system",
      ),
      os_image_hash: bytes32(
        boot.os_image_hash,
        "email_oracle_auth.release.target_boot.os_image_hash",
      ),
      tcb_status: "UpToDate",
      advisory_ids: [],
      info_hash: bytes32(
        boot.info_hash,
        "email_oracle_auth.release.target_boot.info_hash",
      ),
    },
    restart_key_derivation_proof_hash: bytes32(
      parsed.restart_key_derivation_proof_hash,
      "email_oracle_auth.release.restart_key_derivation_proof_hash",
    ),
    external_evidence_sha256: bytes32(
      parsed.external_evidence_sha256,
      "email_oracle_auth.release.external_evidence_sha256",
    ),
  };
}

function normalizeOperatorPolicy(value, authorityStage) {
  if (authorityStage !== "live" && authorityStage !== "prebuild") {
    throw new Error("release candidate authority stage is invalid");
  }
  const live = authorityStage === "live";
  const expectedSchema = live
    ? LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA
    : PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA;
  const parsed = exactRecord(value, live ? [
    "schema",
    "ceremony_authorization_sha256",
    "live_activation_authority_sha256",
    "runtime_authority_dependency_sha256",
  ] : [
    "schema",
    "ceremony_authorization_sha256",
    "runtime_authority_dependency_sha256",
  ], "operator_policy");
  if (parsed.schema !== expectedSchema) {
    throw new Error(
      `operator_policy.schema must be ${expectedSchema}`,
    );
  }
  return {
    schema: expectedSchema,
    ceremony_authorization_sha256: nonzeroSha256Pin(
      parsed.ceremony_authorization_sha256,
      "operator_policy.ceremony_authorization_sha256",
    ),
    ...(live ? {
      live_activation_authority_sha256: nonzeroSha256Pin(
        parsed.live_activation_authority_sha256,
        "operator_policy.live_activation_authority_sha256",
      ),
    } : {}),
    runtime_authority_dependency_sha256: nonzeroSha256Pin(
      parsed.runtime_authority_dependency_sha256,
      "operator_policy.runtime_authority_dependency_sha256",
    ),
  };
}

function emailOracleTargetBootInfo(email, cvm) {
  return {
    appId: email.address,
    composeHash: `0x${cvm.compose_hash}`,
    instanceId: email.release.target_boot.instance_id,
    deviceId: email.release.device_id,
    mrAggregated: email.release.target_boot.mr_aggregated,
    mrSystem: email.release.target_boot.mr_system,
    osImageHash: email.release.target_boot.os_image_hash,
    tcbStatus: "UpToDate",
    advisoryIds: [],
  };
}

function appBootInfoHash(bootInfo) {
  return keccak256(encodeAbiParameters([APP_BOOT_INFO_ABI_PARAMETER], [bootInfo])).toLowerCase();
}

function normalizeContract(value, key) {
  const baseKeys = ["address", "runtime_code_hash"];
  let keys = baseKeys;
  if (key === "diligence_room") {
    keys = [
      ...baseKeys,
      "developer",
      "result_verifier",
      "attestation_verifier",
      "attestation_release_policy_hash",
      "attestation_binding_frozen",
      "evaluator_policy_commitments",
      "evaluator_policy_set_root",
    ];
  }
  if (key === "challenge_registry") {
    keys = [
      ...baseKeys,
      "owner",
      "pending_owner",
      "registry_paused",
      "minimum_version_review_delay_seconds",
      "expected_challenge_count",
    ];
  }
  if (key === "tinker_account_encumbrance") {
    keys = [
      ...baseKeys,
      "owner",
      "account_commitment",
      "max_add_balance_wei",
      "max_spend_wei",
      "approved_compose_hashes",
      "approved_compose_root",
      "approved_compose_count",
      "managers",
      "manager_root",
      "manager_count",
      "release_policy_commitment",
      "release_max_add_balance_wei",
      "release_max_spend_wei",
      "release_compose_root",
      "release_compose_count",
      "release_manager_root",
      "release_manager_count",
      "release_policy_frozen",
      "emergency_halted",
      "per_operation_caps",
      "custodies_funds",
    ];
  }
  if (key === "compute_credit_vault") {
    keys = [
      ...baseKeys,
      "owner",
      "developer",
      "metering_verifier",
      "metering_qvl_verifier",
      "metering_policy_set_hash",
      "metering_binding_frozen",
      "developer_fee_bps",
      "tee_identity",
      "compose_hash",
      "native_rate_policy_commitment",
      "native_provider",
      "erc20_asset_address",
      "erc20_rate_policy_commitment",
      "erc20_provider",
    ];
  }
  if (key === "email_oracle_auth") {
    keys = [
      ...baseKeys,
      "owner",
      "consumer_address",
      "upgrade_delay_seconds",
      "release",
    ];
  }
  if (key === "usdc") keys = [...baseKeys, "symbol", "decimals"];
  const parsed = exactRecord(value, keys, `contracts.${key}`);
  const normalized = {
    address: address(parsed.address, `contracts.${key}.address`),
    runtime_code_hash: bytes32(parsed.runtime_code_hash, `contracts.${key}.runtime_code_hash`),
  };
  if ("developer" in parsed) normalized.developer = address(parsed.developer, `${key}.developer`);
  if ("result_verifier" in parsed) {
    normalized.result_verifier = address(parsed.result_verifier, `${key}.result_verifier`);
  }
  if ("attestation_verifier" in parsed) {
    normalized.attestation_verifier = address(
      parsed.attestation_verifier,
      `${key}.attestation_verifier`,
    );
  }
  if ("attestation_release_policy_hash" in parsed) {
    normalized.attestation_release_policy_hash = bytes32(
      parsed.attestation_release_policy_hash,
      `${key}.attestation_release_policy_hash`,
    );
  }
  if ("attestation_binding_frozen" in parsed) {
    normalized.attestation_binding_frozen = bool(
      parsed.attestation_binding_frozen,
      `${key}.attestation_binding_frozen`,
    );
    if (normalized.attestation_binding_frozen !== true) {
      throw new Error(`${key}.attestation_binding_frozen must be true for a release candidate`);
    }
  }
  if (key === "diligence_room") {
    normalized.evaluator_policy_commitments = Array.isArray(
      parsed.evaluator_policy_commitments,
    ) ? parsed.evaluator_policy_commitments.map((value, index) => bytes32(
        value,
        `${key}.evaluator_policy_commitments[${index}]`,
      )).sort() : (() => {
        throw new Error(`${key}.evaluator_policy_commitments must be an array`);
      })();
    const derivedPolicyRoot = diligenceEvaluatorPolicySetRoot(
      normalized.evaluator_policy_commitments,
    );
    normalized.evaluator_policy_set_root = bytes32(
      parsed.evaluator_policy_set_root,
      `${key}.evaluator_policy_set_root`,
    );
    if (normalized.evaluator_policy_set_root !== derivedPolicyRoot) {
      throw new Error(`${key}.evaluator_policy_set_root is not derived from the exact policy set`);
    }
  }
  if ("owner" in parsed) normalized.owner = address(parsed.owner, `${key}.owner`);
  if (key === "challenge_registry") {
    if (parsed.pending_owner !== ZERO_ADDRESS) {
      throw new Error("challenge_registry.pending_owner must be the zero address");
    }
    normalized.pending_owner = ZERO_ADDRESS;
    normalized.registry_paused = bool(
      parsed.registry_paused,
      "challenge_registry.registry_paused",
    );
    if (normalized.registry_paused !== false) {
      throw new Error("challenge_registry must be active for the reviewed genesis catalog");
    }
    normalized.minimum_version_review_delay_seconds = integer(
      parsed.minimum_version_review_delay_seconds,
      "challenge_registry.minimum_version_review_delay_seconds",
      Number(CHALLENGE_VERSION_REVIEW_DELAY_SECONDS),
      Number(CHALLENGE_VERSION_REVIEW_DELAY_SECONDS),
    );
    normalized.expected_challenge_count = integer(
      parsed.expected_challenge_count,
      "challenge_registry.expected_challenge_count",
      1,
      32,
    );
  }
  if ("account_commitment" in parsed) {
    normalized.account_commitment = bytes32(parsed.account_commitment, `${key}.account_commitment`);
  }
  if (key === "tinker_account_encumbrance") {
    if (!Array.isArray(parsed.approved_compose_hashes) || parsed.approved_compose_hashes.length !== 1) {
      throw new Error("tinker_account_encumbrance.approved_compose_hashes must contain exactly one release compose hash");
    }
    if (!Array.isArray(parsed.managers) || parsed.managers.length !== 1) {
      throw new Error("tinker_account_encumbrance.managers must contain exactly one release manager");
    }
    normalized.max_add_balance_wei = uint256Decimal(
      parsed.max_add_balance_wei,
      `${key}.max_add_balance_wei`,
    );
    normalized.max_spend_wei = uint256Decimal(parsed.max_spend_wei, `${key}.max_spend_wei`);
    normalized.approved_compose_hashes = parsed.approved_compose_hashes.map((entry, index) =>
      bytes32(entry, `${key}.approved_compose_hashes[${index}]`));
    normalized.approved_compose_root = bytes32(
      parsed.approved_compose_root,
      `${key}.approved_compose_root`,
    );
    normalized.approved_compose_count = integer(
      parsed.approved_compose_count,
      `${key}.approved_compose_count`,
      1,
    );
    normalized.managers = parsed.managers.map((entry, index) =>
      address(entry, `${key}.managers[${index}]`));
    normalized.manager_root = bytes32(parsed.manager_root, `${key}.manager_root`);
    normalized.manager_count = integer(parsed.manager_count, `${key}.manager_count`, 1);
    normalized.release_policy_commitment = bytes32(
      parsed.release_policy_commitment,
      `${key}.release_policy_commitment`,
    );
    normalized.release_max_add_balance_wei = uint256Decimal(
      parsed.release_max_add_balance_wei,
      `${key}.release_max_add_balance_wei`,
    );
    normalized.release_max_spend_wei = uint256Decimal(
      parsed.release_max_spend_wei,
      `${key}.release_max_spend_wei`,
    );
    normalized.release_compose_root = bytes32(
      parsed.release_compose_root,
      `${key}.release_compose_root`,
    );
    normalized.release_compose_count = integer(
      parsed.release_compose_count,
      `${key}.release_compose_count`,
      1,
    );
    normalized.release_manager_root = bytes32(
      parsed.release_manager_root,
      `${key}.release_manager_root`,
    );
    normalized.release_manager_count = integer(
      parsed.release_manager_count,
      `${key}.release_manager_count`,
      1,
    );
    normalized.release_policy_frozen = bool(
      parsed.release_policy_frozen,
      `${key}.release_policy_frozen`,
    );
    normalized.emergency_halted = bool(parsed.emergency_halted, `${key}.emergency_halted`);
    normalized.per_operation_caps = bool(parsed.per_operation_caps, `${key}.per_operation_caps`);
    normalized.custodies_funds = bool(parsed.custodies_funds, `${key}.custodies_funds`);
    if (
      normalized.approved_compose_count !== 1
      || normalized.manager_count !== 1
      || normalized.release_compose_count !== 1
      || normalized.release_manager_count !== 1
      || normalized.approved_compose_root !== normalized.release_compose_root
      || normalized.manager_root !== normalized.release_manager_root
      || normalized.max_add_balance_wei !== normalized.release_max_add_balance_wei
      || normalized.max_spend_wei !== normalized.release_max_spend_wei
      || normalized.release_policy_frozen !== true
      || normalized.emergency_halted !== false
      || normalized.per_operation_caps !== true
      || normalized.custodies_funds !== false
    ) {
      throw new Error("tinker_account_encumbrance must bind one exact active frozen noncustodial release policy");
    }
  }
  if ("consumer_address" in parsed) {
    normalized.consumer_address = address(parsed.consumer_address, `${key}.consumer_address`);
  }
  if ("upgrade_delay_seconds" in parsed) {
    normalized.upgrade_delay_seconds = boundedInteger(
      parsed.upgrade_delay_seconds,
      `${key}.upgrade_delay_seconds`,
      172_800,
      31_536_000,
    );
  }
  if ("release" in parsed) {
    normalized.release = normalizeEmailOracleRelease(parsed.release);
  }
  if ("metering_verifier" in parsed) {
    normalized.metering_verifier = address(parsed.metering_verifier, `${key}.metering_verifier`);
  }
  if ("metering_qvl_verifier" in parsed) {
    normalized.metering_qvl_verifier = address(
      parsed.metering_qvl_verifier,
      `${key}.metering_qvl_verifier`,
    );
  }
  if ("metering_policy_set_hash" in parsed) {
    normalized.metering_policy_set_hash = bytes32(
      parsed.metering_policy_set_hash,
      `${key}.metering_policy_set_hash`,
    );
  }
  if ("metering_binding_frozen" in parsed) {
    normalized.metering_binding_frozen = bool(
      parsed.metering_binding_frozen,
      `${key}.metering_binding_frozen`,
    );
    if (normalized.metering_binding_frozen !== true) {
      throw new Error(`${key}.metering_binding_frozen must be true for a release candidate`);
    }
  }
  if ("developer_fee_bps" in parsed) {
    normalized.developer_fee_bps = integer(parsed.developer_fee_bps, `${key}.developer_fee_bps`);
    if (normalized.developer_fee_bps > 2_000) {
      throw new Error(`${key}.developer_fee_bps exceeds the contract maximum`);
    }
  }
  if ("tee_identity" in parsed) {
    normalized.tee_identity = address(parsed.tee_identity, `${key}.tee_identity`);
  }
  if ("compose_hash" in parsed) {
    normalized.compose_hash = bareBytes32(parsed.compose_hash, `${key}.compose_hash`);
  }
  if ("native_rate_policy_commitment" in parsed) {
    normalized.native_rate_policy_commitment = bytes32(
      parsed.native_rate_policy_commitment,
      `${key}.native_rate_policy_commitment`,
    );
  }
  if ("native_provider" in parsed) {
    normalized.native_provider = address(parsed.native_provider, `${key}.native_provider`);
  }
  if ("erc20_asset_address" in parsed) {
    normalized.erc20_asset_address = address(parsed.erc20_asset_address, `${key}.erc20_asset_address`);
  }
  if ("erc20_rate_policy_commitment" in parsed) {
    normalized.erc20_rate_policy_commitment = bytes32(
      parsed.erc20_rate_policy_commitment,
      `${key}.erc20_rate_policy_commitment`,
    );
  }
  if ("erc20_provider" in parsed) {
    normalized.erc20_provider = address(parsed.erc20_provider, `${key}.erc20_provider`);
  }
  if (key === "usdc") {
    if (parsed.symbol !== "USDC" || parsed.decimals !== 6) {
      throw new Error("contracts.usdc must pin symbol USDC and 6 decimals");
    }
    if (normalized.address !== BASE_SEPOLIA_USDC) {
      throw new Error("contracts.usdc must be Circle's canonical Base Sepolia USDC address");
    }
    normalized.symbol = "USDC";
    normalized.decimals = 6;
  }
  return normalized;
}

function normalizeImages(value, expectedSha) {
  const requiredServices = Object.keys(REQUIRED_IMAGE_REPOSITORIES);
  if (!Array.isArray(value) || value.length !== requiredServices.length) {
    throw new Error("cvm.images must contain exactly delegate, oracle, and neko");
  }
  const services = new Set();
  const images = value.map((entry, index) => {
    const parsed = exactRecord(entry, [
      "service",
      "image",
      "source_digest",
      "source_ref",
      "repo",
      "signer_workflow",
      "provenance_attestation",
      "sbom_attestation",
    ], `cvm.images[${index}]`);
    const service = nonEmptyString(parsed.service, `cvm.images[${index}].service`, 64);
    if (!Object.hasOwn(REQUIRED_IMAGE_REPOSITORIES, service)) {
      throw new Error(`cvm image service ${service} is not in the production allowlist`);
    }
    if (services.has(service)) {
      throw new Error("cvm image service names must be unique");
    }
    services.add(service);
    const image = nonEmptyString(parsed.image, `cvm.images[${index}].image`, 512);
    const requiredRepository = REQUIRED_IMAGE_REPOSITORIES[service];
    if (!image.startsWith(`${requiredRepository}@sha256:`) || !/@sha256:[0-9a-f]{64}$/.test(image)) {
      throw new Error(
        `cvm image ${service} must be the project-owned digest-pinned ${requiredRepository} digest`,
      );
    }
    if (parsed.source_digest !== expectedSha) throw new Error(`cvm image ${service} source digest mismatch`);
    if (
      parsed.source_ref !== "refs/heads/main"
      && !/^refs\/tags\/v[0-9][0-9A-Za-z._-]*$/.test(parsed.source_ref)
    ) {
      throw new Error(`cvm image ${service} must be built from main or a version tag`);
    }
    if (parsed.repo !== GITHUB_REPOSITORY || parsed.signer_workflow !== GITHUB_SIGNER_WORKFLOW) {
      throw new Error(`cvm image ${service} has an untrusted GitHub provenance identity`);
    }
    if (parsed.provenance_attestation !== "verified" || parsed.sbom_attestation !== "verified") {
      throw new Error(`cvm image ${service} lacks verified provenance or SBOM evidence`);
    }
    return { ...parsed, service, image };
  });
  for (const required of requiredServices) {
    if (!services.has(required)) throw new Error(`cvm.images is missing required ${required} image`);
  }
  return images;
}

function normalizeTrustDomainImage(value, domain, expectedSha) {
  const parsed = exactRecord(value, [
    "image",
    "source_digest",
    "source_ref",
    "repo",
    "signer_workflow",
    "provenance_attestation",
    "sbom_attestation",
  ], `trust_domains.${domain}.image`);
  const image = nonEmptyString(parsed.image, `trust_domains.${domain}.image.image`, 512);
  const requiredRepository = TRUST_DOMAIN_IMAGE_REPOSITORIES[domain];
  if (!image.startsWith(`${requiredRepository}@sha256:`) || !/@sha256:[0-9a-f]{64}$/.test(image)) {
    throw new Error(
      `trust_domains.${domain} must use the project-owned digest-pinned ${requiredRepository} image`,
    );
  }
  if (parsed.source_digest !== expectedSha) {
    throw new Error(`trust_domains.${domain} image source digest must equal the release SHA`);
  }
  if (
    parsed.source_ref !== "refs/heads/main"
    && !/^refs\/tags\/v[0-9][0-9A-Za-z._-]*$/.test(parsed.source_ref)
  ) {
    throw new Error(`trust_domains.${domain} image must be built from main or a version tag`);
  }
  if (parsed.repo !== GITHUB_REPOSITORY || parsed.signer_workflow !== GITHUB_SIGNER_WORKFLOW) {
    throw new Error(`trust_domains.${domain} image has an untrusted GitHub provenance identity`);
  }
  if (parsed.provenance_attestation !== "verified" || parsed.sbom_attestation !== "verified") {
    throw new Error(`trust_domains.${domain} image lacks verified provenance or SBOM evidence`);
  }
  return { ...parsed, image };
}

const TRUST_DOMAIN_BASE_KEYS = Object.freeze([
  "schema",
  "platform",
  "release_sha",
  "app_id",
  "cvm_id",
  "compose_hash",
  "local_compose_hash",
  "rendered_compose_sha256",
  "os_image_hash",
  "os_is_dev",
  "public_logs",
  "public_sysinfo",
  "public_tcbinfo",
  "ssh_enabled",
  "endpoint",
  "endpoint_authentication",
  "image",
  "identity_evidence_classification",
  "identity",
]);

function normalizeTrustDomainBase(parsed, domain, expectedSha, expectedSchema, expectedPath) {
  if (parsed.schema !== expectedSchema) {
    throw new Error(`trust_domains.${domain}.schema must be ${expectedSchema}`);
  }
  if (parsed.platform !== "phala_cloud") {
    throw new Error(`trust_domains.${domain} must be deployed on Phala Cloud`);
  }
  if (releaseSha(parsed.release_sha, `trust_domains.${domain}.release_sha`) !== expectedSha) {
    throw new Error(`trust_domains.${domain} release SHA mismatch`);
  }
  const normalized = {
    schema: expectedSchema,
    platform: "phala_cloud",
    release_sha: expectedSha,
    app_id: nonEmptyString(parsed.app_id, `trust_domains.${domain}.app_id`, 128),
    cvm_id: nonEmptyString(parsed.cvm_id, `trust_domains.${domain}.cvm_id`, 128),
    compose_hash: bareBytes32(parsed.compose_hash, `trust_domains.${domain}.compose_hash`),
    local_compose_hash: bareBytes32(
      parsed.local_compose_hash,
      `trust_domains.${domain}.local_compose_hash`,
    ),
    rendered_compose_sha256: bareBytes32(
      parsed.rendered_compose_sha256,
      `trust_domains.${domain}.rendered_compose_sha256`,
    ),
    os_image_hash: bareBytes32(parsed.os_image_hash, `trust_domains.${domain}.os_image_hash`),
    os_is_dev: bool(parsed.os_is_dev, `trust_domains.${domain}.os_is_dev`),
    public_logs: bool(parsed.public_logs, `trust_domains.${domain}.public_logs`),
    public_sysinfo: bool(parsed.public_sysinfo, `trust_domains.${domain}.public_sysinfo`),
    public_tcbinfo: bool(parsed.public_tcbinfo, `trust_domains.${domain}.public_tcbinfo`),
    ssh_enabled: bool(parsed.ssh_enabled, `trust_domains.${domain}.ssh_enabled`),
    endpoint: boundedServiceEndpoint(
      parsed.endpoint,
      `trust_domains.${domain}.endpoint`,
      expectedPath,
    ),
    image: normalizeTrustDomainImage(parsed.image, domain, expectedSha),
  };

  if (
    normalized.os_is_dev
    || normalized.public_logs
    || normalized.public_sysinfo
    || normalized.public_tcbinfo
    || normalized.ssh_enabled
  ) {
    throw new Error(
      `trust_domains.${domain} must use a non-dev private Phala posture without SSH or public diagnostics`,
    );
  }
  if (parsed.endpoint_authentication !== "bearer_required") {
    throw new Error(`trust_domains.${domain} endpoint must require bearer authentication`);
  }
  if (parsed.identity_evidence_classification !== "deployment_pins_require_external_platform_verification") {
    throw new Error(
      `trust_domains.${domain} must preserve the non-self-verifying deployment-pin classification`,
    );
  }
  return {
    ...normalized,
    endpoint_authentication: "bearer_required",
    identity_evidence_classification: "deployment_pins_require_external_platform_verification",
  };
}

function normalizeQvlTrustDomain(
  value,
  domain,
  expectedSha,
  contracts,
  cvm,
  executionPolicy,
  computeMetering,
) {
  const contextByDomain = {
    diligence_qvl: "diligence",
    arena_qvl: "arena",
    anchor_writer_qvl: "execution_policy_anchor_writer",
    compute_metering_qvl: "compute_metering",
    compute_workload_qvl: "compute_workload",
  };
  const context = contextByDomain[domain];
  if (!context) throw new Error(`trust_domains.${domain} is not a reviewed QVL context`);
  const parsed = exactRecord(
    value,
    [...TRUST_DOMAIN_BASE_KEYS, "context", "policy_binding"],
    `trust_domains.${domain}`,
  );
  if (parsed.context !== context) throw new Error(`trust_domains.${domain} context mismatch`);
  const normalized = normalizeTrustDomainBase(
    parsed,
    domain,
    expectedSha,
    "dnai.release-qvl-cvm.v1",
    "/verify",
  );
  const identity = exactRecord(parsed.identity, [
    "schema",
    "verifier_address",
    "release_policy_hash",
    "signer_custody",
    "raw_secret_egress",
  ], `trust_domains.${domain}.identity`);
  if (
    identity.schema !== "dnai.attestation-qvl-identity.v1"
    || identity.signer_custody !== "dstack_derived_separate_cvm"
    || identity.raw_secret_egress !== false
  ) {
    throw new Error(`trust_domains.${domain} identity does not match the production QVL identity schema`);
  }
  const normalizedIdentity = {
    schema: identity.schema,
    verifier_address: address(identity.verifier_address, `trust_domains.${domain}.identity.verifier_address`),
    release_policy_hash: bytes32(
      identity.release_policy_hash,
      `trust_domains.${domain}.identity.release_policy_hash`,
    ),
    signer_custody: identity.signer_custody,
    raw_secret_egress: false,
  };
  if (domain === "compute_workload_qvl") {
    const binding = exactRecord(
      parsed.policy_binding,
      ["kind"],
      "trust_domains.compute_workload_qvl.policy_binding",
    );
    if (binding.kind !== "compute_workload_recipient_v1") {
      throw new Error(
        "trust_domains.compute_workload_qvl policy binding must authorize only the reviewed dynamic recipient-attestation protocol",
      );
    }
    return {
      ...normalized,
      context,
      identity: normalizedIdentity,
      policy_binding: { kind: "compute_workload_recipient_v1" },
    };
  }
  const bindingKeys = [
    "chain_id",
    "contract_address",
    "evaluated_app_id",
    "evaluated_compose_hash",
    "evaluated_os_image_hash",
    "allowed_signer_address",
    "report_data_binding_kind",
  ];
  if (domain === "anchor_writer_qvl") {
    bindingKeys.push(
      "writer_release_commitment",
      "writer_key_path",
      "writer_custody",
    );
  }
  if (domain === "diligence_qvl") {
    bindingKeys.push("email_oracle_kms_restart_binding");
  }
  if (domain === "compute_metering_qvl") {
    bindingKeys.push("policy_set_hash", "signer_custody");
  }
  const binding = exactRecord(
    parsed.policy_binding,
    bindingKeys,
    `trust_domains.${domain}.policy_binding`,
  );
  const expectedContract = domain === "diligence_qvl"
    ? contracts.diligence_room.address
    : domain === "arena_qvl"
      ? contracts.challenge_registry.address
      : domain === "anchor_writer_qvl"
        ? executionPolicy.rollback_anchor.contract_address
        : contracts.compute_credit_vault.address;
  const expectedBindingKind = domain === "diligence_qvl"
    ? "diligence_result_signer_v1"
    : domain === "arena_qvl"
      ? "arena_candidate_ingress_v1"
      : domain === "anchor_writer_qvl"
        ? "execution_policy_anchor_writer_v1"
        : "compute_metering_signer_v1";
  const expectedSigner = domain === "anchor_writer_qvl"
    ? executionPolicy.rollback_anchor.writer_address
    : domain === "compute_metering_qvl"
      ? contracts.compute_credit_vault.metering_verifier
      : cvm.tee_identity;
  const evaluatedCvm = domain === "compute_metering_qvl" ? computeMetering : cvm;
  if (!evaluatedCvm) {
    throw new Error(`trust_domains.${domain} is missing its evaluated CVM descriptor`);
  }
  const email = contracts.email_oracle_auth;
  const expectedEmailBinding = {
    kind: "email_oracle_kms_restart_v1",
    email_oracle_auth_address: email.address,
    email_oracle_auth_runtime_code_hash: email.runtime_code_hash,
    kms_proxy_address: email.release.kms_contract_address,
    kms_proxy_runtime_code_hash: email.release.kms_runtime_code_hash,
    kms_implementation_address: email.release.kms_implementation_address,
    kms_implementation_runtime_code_hash:
      email.release.kms_implementation_runtime_code_hash,
    kms_eip1967_implementation_slot_word:
      `0x${"0".repeat(24)}${email.release.kms_implementation_address.slice(2)}`,
    registration_tx_hash: email.release.kms_registration_tx_hash,
    registration_block_number: email.release.kms_registration_block,
    registration_block_hash: email.release.kms_registration_block_hash,
    target_boot_tuple_hash: email.release.target_boot.info_hash,
    restart_proof_hash: email.release.restart_key_derivation_proof_hash,
  };
  if (
    binding.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || address(binding.contract_address, `trust_domains.${domain}.policy_binding.contract_address`)
      !== expectedContract
    || nonEmptyString(binding.evaluated_app_id, `trust_domains.${domain}.policy_binding.evaluated_app_id`, 128)
      !== evaluatedCvm.app_id
    || bytes32(binding.evaluated_compose_hash, `trust_domains.${domain}.policy_binding.evaluated_compose_hash`)
      !== `0x${evaluatedCvm.compose_hash}`
    || bareBytes32(binding.evaluated_os_image_hash, `trust_domains.${domain}.policy_binding.evaluated_os_image_hash`)
      !== evaluatedCvm.os_image_hash
    || address(binding.allowed_signer_address, `trust_domains.${domain}.policy_binding.allowed_signer_address`)
      !== expectedSigner
    || binding.report_data_binding_kind !== expectedBindingKind
    || (
      domain === "diligence_qvl"
      && canonicalJson(binding.email_oracle_kms_restart_binding)
        !== canonicalJson(expectedEmailBinding)
    )
    || (
      domain === "anchor_writer_qvl"
      && (
        bytes32(
          binding.writer_release_commitment,
          `trust_domains.${domain}.policy_binding.writer_release_commitment`,
        ) !== executionPolicy.rollback_anchor.writer_release_commitment
        || binding.writer_key_path !== EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH
        || binding.writer_custody !== EXECUTION_POLICY_ANCHOR_WRITER_CUSTODY
      )
    )
    || (
      domain === "compute_metering_qvl"
      && (
        bytes32(
          binding.policy_set_hash,
          `trust_domains.${domain}.policy_binding.policy_set_hash`,
        ) !== contracts.compute_credit_vault.metering_policy_set_hash
        || binding.signer_custody !== "dstack_derived_independent_cvm"
      )
    )
  ) {
    throw new Error(`trust_domains.${domain} canonical QVL policy binding does not match the evaluated release`);
  }
  return {
    ...normalized,
    context,
    identity: normalizedIdentity,
    policy_binding: {
      chain_id: BASE_SEPOLIA_CHAIN_ID,
      contract_address: expectedContract,
      evaluated_app_id: evaluatedCvm.app_id,
      evaluated_compose_hash: `0x${evaluatedCvm.compose_hash}`,
      evaluated_os_image_hash: evaluatedCvm.os_image_hash,
      allowed_signer_address: expectedSigner,
      report_data_binding_kind: expectedBindingKind,
      ...(domain === "diligence_qvl" ? {
        email_oracle_kms_restart_binding: expectedEmailBinding,
      } : {}),
      ...(domain === "anchor_writer_qvl" ? {
        writer_release_commitment:
          executionPolicy.rollback_anchor.writer_release_commitment,
        writer_key_path: EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH,
        writer_custody: EXECUTION_POLICY_ANCHOR_WRITER_CUSTODY,
      } : {}),
      ...(domain === "compute_metering_qvl" ? {
        policy_set_hash: contracts.compute_credit_vault.metering_policy_set_hash,
        signer_custody: "dstack_derived_independent_cvm",
      } : {}),
    },
  };
}

function normalizeMeteringAssets(value) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) {
    throw new Error("trust_domains.compute_metering.identity.assets must contain one or two policy entries");
  }
  const assets = value.map((entry, index) => {
    const parsed = exactRecord(
      entry,
      ["asset", "provider", "rate_policy_commitment"],
      `trust_domains.compute_metering.identity.assets[${index}]`,
    );
    return {
      asset: assetAddress(parsed.asset, `trust_domains.compute_metering.identity.assets[${index}].asset`),
      provider: address(parsed.provider, `trust_domains.compute_metering.identity.assets[${index}].provider`),
      rate_policy_commitment: bytes32(
        parsed.rate_policy_commitment,
        `trust_domains.compute_metering.identity.assets[${index}].rate_policy_commitment`,
      ),
    };
  });
  const sorted = [...assets].sort((left, right) => left.asset.localeCompare(right.asset));
  if (assets.some((entry, index) => entry.asset !== sorted[index].asset)) {
    throw new Error("trust_domains.compute_metering identity assets must be sorted by address");
  }
  if (
    new Set(assets.map((entry) => entry.asset)).size !== assets.length
    || new Set(assets.map((entry) => entry.rate_policy_commitment)).size !== assets.length
  ) {
    throw new Error("trust_domains.compute_metering identity assets and commitments must be unique");
  }
  const supportedAssets = new Set([ZERO_ADDRESS, BASE_SEPOLIA_USDC]);
  if (assets.some((entry) => !supportedAssets.has(entry.asset))) {
    throw new Error(
      "trust_domains.compute_metering policy set contains an unsupported Base Sepolia asset",
    );
  }
  return assets;
}

function normalizeComputeMeteringTrustDomain(value, expectedSha, contracts) {
  const domain = "compute_metering";
  const parsed = exactRecord(value, TRUST_DOMAIN_BASE_KEYS, `trust_domains.${domain}`);
  const normalized = normalizeTrustDomainBase(
    parsed,
    domain,
    expectedSha,
    "dnai.release-compute-metering-cvm.v1",
    "/meter",
  );
  const identity = exactRecord(parsed.identity, [
    "schema",
    "classification",
    "provider_authoritative_invoice",
    "chain_id",
    "vault_address",
    "policy_set_hash",
    "metering_verifier",
    "assets",
    "signer_custody",
    "raw_secret_egress",
  ], `trust_domains.${domain}.identity`);
  if (
    identity.schema !== "dnai.compute-metering-identity.v1"
    || identity.classification !== "attested_deterministic_metering"
    || identity.provider_authoritative_invoice !== false
    || identity.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || identity.signer_custody !== "dstack_derived_independent_cvm"
    || identity.raw_secret_egress !== false
  ) {
    throw new Error("trust_domains.compute_metering identity does not match the bounded production schema");
  }
  const normalizedIdentity = {
    schema: identity.schema,
    classification: identity.classification,
    provider_authoritative_invoice: false,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    vault_address: address(identity.vault_address, "trust_domains.compute_metering.identity.vault_address"),
    policy_set_hash: bytes32(
      identity.policy_set_hash,
      "trust_domains.compute_metering.identity.policy_set_hash",
    ),
    metering_verifier: address(
      identity.metering_verifier,
      "trust_domains.compute_metering.identity.metering_verifier",
    ),
    assets: normalizeMeteringAssets(identity.assets),
    signer_custody: identity.signer_custody,
    raw_secret_egress: false,
  };
  if (normalizedIdentity.vault_address !== contracts.compute_credit_vault.address) {
    throw new Error("compute metering descriptor vault does not match ComputeCreditVault");
  }
  if (normalizedIdentity.metering_verifier !== contracts.compute_credit_vault.metering_verifier) {
    throw new Error("compute metering descriptor address does not match ComputeCreditVault.meteringVerifier");
  }
  if (normalizedIdentity.policy_set_hash !== contracts.compute_credit_vault.metering_policy_set_hash) {
    throw new Error("compute metering descriptor policy set does not match ComputeCreditVault.meteringPolicySetHash");
  }
  const forbiddenProviders = new Set([
    contracts.compute_credit_vault.owner,
    contracts.compute_credit_vault.developer,
    contracts.compute_credit_vault.metering_verifier,
    contracts.compute_credit_vault.metering_qvl_verifier,
    contracts.compute_credit_vault.tee_identity,
    contracts.compute_credit_vault.address,
  ]);
  if (normalizedIdentity.assets.some((entry) => forbiddenProviders.has(entry.provider))) {
    throw new Error("compute metering policy provider conflicts with a control-plane role");
  }
  return { ...normalized, identity: normalizedIdentity };
}

function normalizeTrustDomains(
  value,
  expectedSha,
  contracts,
  cvm,
  features,
  executionPolicy,
) {
  const parsed = exactRecord(value, TRUST_DOMAIN_KEYS, "trust_domains");
  const computeMetering = normalizeComputeMeteringTrustDomain(
    parsed.compute_metering,
    expectedSha,
    contracts,
  );
  const normalized = {
    diligence_qvl: normalizeQvlTrustDomain(
      parsed.diligence_qvl,
      "diligence_qvl",
      expectedSha,
      contracts,
      cvm,
      executionPolicy,
      computeMetering,
    ),
    arena_qvl: normalizeQvlTrustDomain(
      parsed.arena_qvl,
      "arena_qvl",
      expectedSha,
      contracts,
      cvm,
      executionPolicy,
      computeMetering,
    ),
    anchor_writer_qvl: normalizeQvlTrustDomain(
      parsed.anchor_writer_qvl,
      "anchor_writer_qvl",
      expectedSha,
      contracts,
      cvm,
      executionPolicy,
      computeMetering,
    ),
    compute_metering_qvl: normalizeQvlTrustDomain(
      parsed.compute_metering_qvl,
      "compute_metering_qvl",
      expectedSha,
      contracts,
      cvm,
      executionPolicy,
      computeMetering,
    ),
    compute_workload_qvl: normalizeQvlTrustDomain(
      parsed.compute_workload_qvl,
      "compute_workload_qvl",
      expectedSha,
      contracts,
      cvm,
      executionPolicy,
      computeMetering,
    ),
    compute_metering: computeMetering,
  };

  if (
    contracts.diligence_room.attestation_verifier
      !== normalized.diligence_qvl.identity.verifier_address
  ) {
    throw new Error(
      "DiligenceRoom attestation verifier does not match the release-pinned Diligence QVL root",
    );
  }
  if (
    contracts.diligence_room.attestation_release_policy_hash
      !== normalized.diligence_qvl.identity.release_policy_hash
  ) {
    throw new Error(
      "DiligenceRoom attestation policy hash does not match the release-pinned Diligence QVL policy",
    );
  }
  if (
    contracts.compute_credit_vault.metering_qvl_verifier
      !== normalized.compute_metering_qvl.identity.verifier_address
  ) {
    throw new Error(
      "ComputeCreditVault metering QVL verifier does not match the release-pinned Compute Metering QVL root",
    );
  }

  const roots = [
    contracts.diligence_room.developer,
    contracts.diligence_room.result_verifier,
    contracts.compute_credit_vault.developer,
    cvm.tee_identity,
    executionPolicy.rollback_anchor.writer_address,
    normalized.diligence_qvl.identity.verifier_address,
    normalized.arena_qvl.identity.verifier_address,
    normalized.anchor_writer_qvl.identity.verifier_address,
    normalized.compute_metering_qvl.identity.verifier_address,
    normalized.compute_workload_qvl.identity.verifier_address,
    normalized.compute_metering.identity.metering_verifier,
  ];
  if (new Set(roots).size !== roots.length) {
    throw new Error(
      "operator, main TEE, anchor writer, result verifier, Compute developer, all QVL roots, and metering root must all be distinct",
    );
  }
  const policyRoots = [
    normalized.diligence_qvl.identity.release_policy_hash,
    normalized.arena_qvl.identity.release_policy_hash,
    normalized.anchor_writer_qvl.identity.release_policy_hash,
    normalized.compute_metering_qvl.identity.release_policy_hash,
    normalized.compute_workload_qvl.identity.release_policy_hash,
    normalized.compute_metering.identity.policy_set_hash,
  ];
  if (new Set(policyRoots).size !== policyRoots.length) {
    throw new Error("all five QVL policies and the compute metering policy root must be distinct");
  }
  for (const [label, values] of [
    ["app IDs", [cvm.app_id, ...TRUST_DOMAIN_KEYS.map((key) => normalized[key].app_id)]],
    ["CVM IDs", [cvm.cvm_id, ...TRUST_DOMAIN_KEYS.map((key) => normalized[key].cvm_id)]],
    ["compose hashes", [cvm.compose_hash, ...TRUST_DOMAIN_KEYS.map((key) => normalized[key].compose_hash)]],
    ["HTTPS origins", [cvm.delegate_url, ...TRUST_DOMAIN_KEYS.map((key) => new URL(normalized[key].endpoint).origin)]],
  ]) {
    if (new Set(values).size !== values.length) {
      throw new Error(`all seven main, QVL, and metering CVMs must have distinct ${label}`);
    }
  }

  if (features.compute_vault_funding || features.compute_vault_authorization) {
    const expectedAssets = new Map([
      [ZERO_ADDRESS, contracts.compute_credit_vault.native_rate_policy_commitment],
      [contracts.compute_credit_vault.erc20_asset_address, contracts.compute_credit_vault.erc20_rate_policy_commitment],
    ]);
    const meteringAssets = normalized.compute_metering.identity.assets;
    if (
      meteringAssets.length !== expectedAssets.size
      || meteringAssets.some((entry) => expectedAssets.get(entry.asset) !== entry.rate_policy_commitment)
    ) {
      throw new Error(
        "compute metering policy set must match every funding-enabled native and canonical-USDC policy",
      );
    }
  }
  return normalized;
}

function normalizeControls(value) {
  const keys = [
    "wallet_auth_required",
    "runtime_bearer_required",
    "durable_compute_store",
    "durable_arena_store",
    "durable_arena_ingress_store",
    "artifact_ciphertext_only",
    "plaintext_artifact_endpoint_disabled",
    "plaintext_card_endpoint_disabled",
    "bootstrap_fail_open_disabled",
    "browser_ports_internal_only",
    "nondefault_browser_credentials_required",
    "project_owned_browser_images",
    "oracle_internal_only",
    "oracle_runtime_auth_required",
    "oracle_health_liveness_only",
    "oracle_pin_response_minimized",
    "oracle_private_metadata_egress_prohibited",
    "oracle_replay_fail_closed",
    "provider_dispatch_enabled",
    "hostile_candidate_execution_enabled",
    "deal_settlement_enabled",
    "remote_artifact_evaluator_enabled",
    "raw_secret_egress_prohibited",
  ];
  const parsed = exactRecord(value, keys, "cvm.runtime_controls");
  for (const key of keys) bool(parsed[key], `cvm.runtime_controls.${key}`);
  for (const required of [
    "wallet_auth_required",
    "runtime_bearer_required",
    "durable_compute_store",
    "durable_arena_store",
    "durable_arena_ingress_store",
    "artifact_ciphertext_only",
    "plaintext_artifact_endpoint_disabled",
    "plaintext_card_endpoint_disabled",
    "bootstrap_fail_open_disabled",
    "browser_ports_internal_only",
    "nondefault_browser_credentials_required",
    "project_owned_browser_images",
    "oracle_internal_only",
    "oracle_runtime_auth_required",
    "oracle_health_liveness_only",
    "oracle_pin_response_minimized",
    "oracle_private_metadata_egress_prohibited",
    "oracle_replay_fail_closed",
    "raw_secret_egress_prohibited",
  ]) {
    if (parsed[required] !== true) throw new Error(`cvm runtime control ${required} must be true`);
  }
  if (parsed.provider_dispatch_enabled !== false) {
    throw new Error("provider dispatch cannot be enabled by the current reviewed frontend release");
  }
  if (parsed.hostile_candidate_execution_enabled !== false) {
    throw new Error("hostile Arena candidate execution is not an approved capability");
  }
  if (parsed.deal_settlement_enabled !== false) {
    throw new Error("deal settlement is not enabled by the current reviewed frontend release");
  }
  if (parsed.remote_artifact_evaluator_enabled !== false) {
    throw new Error("remote artifact evaluation is not enabled by the current reviewed frontend release");
  }
  return parsed;
}

function normalizeComputeWorkloadIngress(value) {
  const parsed = exactRecord(value, [
    "max_verdict_age_seconds",
    "revoked_quote_hashes",
  ], "cvm.compute_workload_ingress");
  const maximumAge = boundedInteger(
    parsed.max_verdict_age_seconds,
    "cvm.compute_workload_ingress.max_verdict_age_seconds",
    1,
    300,
  );
  if (!Array.isArray(parsed.revoked_quote_hashes)
    || parsed.revoked_quote_hashes.length > 256) {
    throw new Error(
      "cvm.compute_workload_ingress.revoked_quote_hashes must contain at most 256 entries",
    );
  }
  const revoked = parsed.revoked_quote_hashes.map((value, index) => bytes32(
    value,
    `cvm.compute_workload_ingress.revoked_quote_hashes[${index}]`,
  ));
  if (new Set(revoked).size !== revoked.length
    || revoked.some((value, index) => index > 0 && revoked[index - 1] >= value)) {
    throw new Error(
      "cvm.compute_workload_ingress.revoked_quote_hashes must be strictly sorted and unique",
    );
  }
  return {
    max_verdict_age_seconds: maximumAge,
    revoked_quote_hashes: revoked,
  };
}

function printableAscii(value, label, maximumBytes) {
  if (
    typeof value !== "string"
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > maximumBytes
    || /[^\x20-\x7e]/.test(value)
  ) {
    throw new Error(`${label} must be bounded printable ASCII`);
  }
  return value;
}

function normalizeArenaRegistryBindings(value) {
  const root = record(value, "arena_registry_bindings");
  const entries = Object.entries(root).sort(([left], [right]) => left.localeCompare(right));
  if (entries.length < 1 || entries.length > 32) {
    throw new Error("arena_registry_bindings must contain one to 32 exact catalog bindings");
  }
  const seenRegistryChallengeIds = new Set();
  const seenRegistryVersions = new Set();
  const normalized = {};
  for (const [catalogKey, raw] of entries) {
    const separator = catalogKey.lastIndexOf("@");
    const challengeId = catalogKey.slice(0, separator);
    const version = catalogKey.slice(separator + 1);
    if (
      separator < 1
      || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(challengeId)
      || !/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(version)
    ) {
      throw new Error(`Arena registry binding key ${catalogKey} is malformed`);
    }
    const binding = exactRecord(raw, [
      "registry_challenge_id",
      "registry_version",
      "controller_address",
      "pending_controller_address",
      "lifecycle",
      "paused",
      "configuration_frozen",
      "catalog_manifest_hash",
      "metadata_uri",
      "metadata_hash",
      "sealed_artifact_commitment",
      "evaluator_commitment",
      "release_policy_commitment",
    ], `Arena registry binding ${catalogKey}`);
    if (
      typeof binding.registry_challenge_id !== "string"
      || !/^[1-9][0-9]{0,77}$/.test(binding.registry_challenge_id)
      || BigInt(binding.registry_challenge_id) >= (1n << 256n)
    ) {
      throw new Error(`Arena registry binding ${catalogKey} has an invalid uint256 challenge id`);
    }
    const registryVersion = integer(
      binding.registry_version,
      `Arena registry binding ${catalogKey} version`,
      1,
    );
    if (registryVersion > 0xffff_ffff) {
      throw new Error(`Arena registry binding ${catalogKey} version exceeds uint32`);
    }
    const registryKey = `${binding.registry_challenge_id}@${registryVersion}`;
    if (seenRegistryChallengeIds.has(binding.registry_challenge_id)) {
      throw new Error(`Arena registry challenge ${binding.registry_challenge_id} is bound more than once`);
    }
    if (seenRegistryVersions.has(registryKey)) {
      throw new Error(`Arena registry version ${registryKey} is bound more than once`);
    }
    seenRegistryChallengeIds.add(binding.registry_challenge_id);
    seenRegistryVersions.add(registryKey);
    const manifestHash = bareBytes32(
      binding.catalog_manifest_hash,
      `Arena registry binding ${catalogKey} catalog manifest hash`,
    );
    const metadataHash = bytes32(
      binding.metadata_hash,
      `Arena registry binding ${catalogKey} metadata hash`,
    );
    if (metadataHash !== `0x${manifestHash}`) {
      throw new Error(`Arena registry binding ${catalogKey} metadata hash does not commit to its catalog manifest`);
    }
    normalized[catalogKey] = {
      registry_challenge_id: binding.registry_challenge_id,
      registry_version: registryVersion,
      controller_address: address(
        binding.controller_address,
        `Arena registry binding ${catalogKey} controller`,
      ),
      pending_controller_address: (() => {
        if (binding.pending_controller_address !== ZERO_ADDRESS) {
          throw new Error(`Arena registry binding ${catalogKey} pending controller must be empty`);
        }
        return ZERO_ADDRESS;
      })(),
      lifecycle: (() => {
        if (binding.lifecycle !== "open") {
          throw new Error(`Arena registry binding ${catalogKey} lifecycle must be open`);
        }
        return "open";
      })(),
      paused: (() => {
        if (bool(binding.paused, `Arena registry binding ${catalogKey} paused`) !== false) {
          throw new Error(`Arena registry binding ${catalogKey} must be unpaused`);
        }
        return false;
      })(),
      configuration_frozen: (() => {
        if (bool(
          binding.configuration_frozen,
          `Arena registry binding ${catalogKey} configuration_frozen`,
        ) !== true) {
          throw new Error(`Arena registry binding ${catalogKey} configuration must be frozen`);
        }
        return true;
      })(),
      catalog_manifest_hash: manifestHash,
      metadata_uri: printableAscii(
        binding.metadata_uri,
        `Arena registry binding ${catalogKey} metadata URI`,
        256,
      ),
      metadata_hash: metadataHash,
      sealed_artifact_commitment: bytes32(
        binding.sealed_artifact_commitment,
        `Arena registry binding ${catalogKey} sealed artifact commitment`,
      ),
      evaluator_commitment: bytes32(
        binding.evaluator_commitment,
        `Arena registry binding ${catalogKey} evaluator commitment`,
      ),
      release_policy_commitment: bytes32(
        binding.release_policy_commitment,
        `Arena registry binding ${catalogKey} release policy commitment`,
      ),
    };
    if (new Set([
      normalized[catalogKey].metadata_hash,
      normalized[catalogKey].sealed_artifact_commitment,
      normalized[catalogKey].evaluator_commitment,
      normalized[catalogKey].release_policy_commitment,
    ]).size !== 4) {
      throw new Error(`Arena registry binding ${catalogKey} commitments must be pairwise distinct`);
    }
  }
  const expectedIds = Array.from({ length: entries.length }, (_, index) => String(index + 1));
  const actualIds = [...seenRegistryChallengeIds].sort((left, right) => (
    BigInt(left) < BigInt(right) ? -1 : BigInt(left) > BigInt(right) ? 1 : 0
  ));
  if (JSON.stringify(actualIds) !== JSON.stringify(expectedIds)) {
    throw new Error("Arena genesis catalog registry ids must be the exact contiguous range 1..N");
  }
  return normalized;
}

export function arenaReleaseApprovedChallengeSetSha256(value) {
  const normalized = normalizeArenaRegistryBindings(value);
  const bindings = Object.fromEntries(Object.entries(normalized).map(([key, binding]) => [
    key,
    Object.fromEntries(Object.entries(binding).filter(
      ([field]) => field !== "release_policy_commitment",
    )),
  ]));
  return `sha256:${createHash("sha256")
    .update(ARENA_APPROVED_CHALLENGE_SET_DOMAIN)
    .update(Buffer.from(canonicalJson({
      schema: ARENA_APPROVED_CHALLENGE_SET_SCHEMA,
      bindings,
    }), "ascii"))
    .digest("hex")}`;
}

function normalizeVerdictWrapper(value, context) {
  const wrapper = exactRecord(value, ["context", "quote_sha256", "verdict"], `attestations.${context}`);
  if (wrapper.context !== context) throw new Error(`${context} attestation context mismatch`);
  return {
    context,
    quote_sha256: sha256Pin(wrapper.quote_sha256, `${context} quote_sha256`),
    verdict: exactRecord(wrapper.verdict, [
      "schema",
      "verification_method",
      "verified",
      "chain_id",
      "domain",
      "profile",
      "cvm_id",
      "deployment_intent_sha256",
      "release_authority_sha256",
      "ceremony_nonce",
      "measurement_policy_sha256",
      "release_policy_hash",
      "challenge_id",
      "challenge_digest",
      "challenge_issued_at",
      "challenge_expires_at",
      "quote_hash",
      "report_data",
      "compose_hash",
      "app_id",
      "os_image_hash",
      "signer_address",
      "contract_address",
      "issued_at",
      "activation_evidence_lease_expires_at",
      "expires_at",
      "verifier_address",
      "verifier_signature",
    ], `${context} verdict`),
  };
}

export function normalizeReleaseCandidate(value, { authorityStage = "live" } = {}) {
  if (authorityStage !== "live" && authorityStage !== "prebuild") {
    throw new Error("release candidate authority stage is invalid");
  }
  const candidate = exactRecord(value, [
    "schema",
    "release_sha",
    "network",
    "operator_address",
    "deployment_intent_sha256",
    "cvm_launch_intent_sha256",
    "operator_policy",
    "contracts",
    "cvm",
    "trust_domains",
    "wallet_auth",
    "execution_policy",
    "attestations",
    "arena_registry_bindings",
    "requested_features",
  ], "release candidate");
  if (candidate.schema !== RELEASE_SCHEMA) throw new Error(`release schema must be ${RELEASE_SCHEMA}`);
  const sha = releaseSha(candidate.release_sha);
  const networkValue = exactRecord(
    candidate.network,
    ["chain_id", "public_rpc_url"],
    "network",
  );
  if (networkValue.chain_id !== BASE_SEPOLIA_CHAIN_ID) {
    throw new Error("release network must be Base Sepolia");
  }
  if (networkValue.public_rpc_url !== CANONICAL_PUBLIC_RPC) {
    throw new Error(
      `release network public RPC must be the canonical ${CANONICAL_PUBLIC_RPC} endpoint`,
    );
  }
  const network = {
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    public_rpc_url: CANONICAL_PUBLIC_RPC,
  };
  const operator = address(candidate.operator_address, "operator_address");
  const deploymentIntentSha256 = nonzeroSha256Pin(
    candidate.deployment_intent_sha256,
    "deployment_intent_sha256",
  );
  const cvmLaunchIntentSha256 = nonzeroSha256Pin(
    candidate.cvm_launch_intent_sha256,
    "cvm_launch_intent_sha256",
  );
  const operatorPolicy = normalizeOperatorPolicy(
    candidate.operator_policy,
    authorityStage,
  );

  const contractRecord = exactRecord(candidate.contracts, CONTRACT_KEYS, "contracts");
  const contracts = Object.fromEntries(
    CONTRACT_KEYS.map((key) => [key, normalizeContract(contractRecord[key], key)]),
  );
  if (contracts.diligence_room.developer !== operator) throw new Error("DiligenceRoom developer must be the release operator");
  if (contracts.diligence_room.developer === contracts.diligence_room.address) {
    throw new Error("DiligenceRoom developer cannot be the room contract");
  }
  if (
    contracts.diligence_room.result_verifier === operator
    || contracts.diligence_room.result_verifier === contracts.diligence_room.address
  ) {
    throw new Error("DiligenceRoom result verifier must be distinct from the release operator and room contract");
  }
  if (
    contracts.diligence_room.attestation_verifier === operator
    || contracts.diligence_room.attestation_verifier
      === contracts.diligence_room.result_verifier
    || contracts.diligence_room.attestation_verifier
      === contracts.diligence_room.address
  ) {
    throw new Error("DiligenceRoom attestation verifier conflicts with a release role");
  }
  if (contracts.challenge_registry.owner !== operator) throw new Error("ChallengeRegistry owner must be the release operator");
  if (contracts.tinker_account_encumbrance.owner !== operator) throw new Error("encumbrance owner must be the release operator");
  if (contracts.compute_credit_vault.owner !== operator) throw new Error("ComputeCreditVault owner must be the release operator");
  if (contracts.email_oracle_auth.owner !== operator) throw new Error("EmailOracleAuth owner must be the release operator");
  if (contracts.compute_credit_vault.erc20_asset_address !== contracts.usdc.address) {
    throw new Error("ComputeCreditVault ERC20 asset must be the pinned canonical Base Sepolia USDC");
  }
  if (
    contracts.compute_credit_vault.native_rate_policy_commitment
    === contracts.compute_credit_vault.erc20_rate_policy_commitment
  ) {
    throw new Error("ComputeCreditVault native and ERC20 rate policies must be distinct");
  }
  if (
    contracts.compute_credit_vault.native_provider
      === contracts.compute_credit_vault.erc20_provider
  ) {
    throw new Error("ComputeCreditVault native and ERC20 payout recipients must be distinct");
  }

  const cvm = exactRecord(candidate.cvm, [
    "app_id",
    "cvm_id",
    "compose_hash",
    "local_compose_hash",
    "rendered_compose_sha256",
    "os_image_hash",
    "os_is_dev",
    "public_logs",
    "public_sysinfo",
    "public_tcbinfo",
    "tee_identity",
    "delegate_url",
    "images",
    "allowed_browser_origins",
    "compute_workload_ingress",
    "runtime_controls",
  ], "cvm");
  const normalizedCvm = {
    app_id: nonEmptyString(cvm.app_id, "cvm.app_id", 128),
    cvm_id: nonEmptyString(cvm.cvm_id, "cvm.cvm_id", 128),
    compose_hash: bareBytes32(cvm.compose_hash, "cvm.compose_hash"),
    local_compose_hash: bareBytes32(cvm.local_compose_hash, "cvm.local_compose_hash"),
    rendered_compose_sha256: bareBytes32(cvm.rendered_compose_sha256, "cvm.rendered_compose_sha256"),
    os_image_hash: bareBytes32(cvm.os_image_hash, "cvm.os_image_hash"),
    os_is_dev: bool(cvm.os_is_dev, "cvm.os_is_dev"),
    public_logs: bool(cvm.public_logs, "cvm.public_logs"),
    public_sysinfo: bool(cvm.public_sysinfo, "cvm.public_sysinfo"),
    public_tcbinfo: bool(cvm.public_tcbinfo, "cvm.public_tcbinfo"),
    tee_identity: address(cvm.tee_identity, "cvm.tee_identity"),
    delegate_url: httpsOrigin(cvm.delegate_url, "cvm.delegate_url"),
    images: normalizeImages(cvm.images, sha),
    compute_workload_ingress: normalizeComputeWorkloadIngress(
      cvm.compute_workload_ingress,
    ),
    runtime_controls: normalizeControls(cvm.runtime_controls),
  };
  if (normalizedCvm.os_is_dev || normalizedCvm.public_logs || normalizedCvm.public_sysinfo || normalizedCvm.public_tcbinfo) {
    throw new Error("production CVM must use non-dev OS with logs, sysinfo, and TCB info private");
  }
  if (normalizedCvm.tee_identity === operator) {
    throw new Error("release operator and attested TEE identity must be distinct");
  }
  if (
    contracts.tinker_account_encumbrance.approved_compose_hashes[0]
      !== `0x${normalizedCvm.compose_hash}`
    || contracts.tinker_account_encumbrance.managers[0] !== normalizedCvm.tee_identity
  ) {
    throw new Error("TinkerAccountEncumbrance release authority must equal the one reviewed main CVM compose and TEE identity");
  }
  if (contracts.email_oracle_auth.consumer_address !== normalizedCvm.tee_identity) {
    throw new Error("EmailOracleAuth consumer must be the release-pinned TEE identity");
  }
  const emailRelease = contracts.email_oracle_auth.release;
  if (emailRelease.target_boot.os_image_hash !== `0x${normalizedCvm.os_image_hash}`) {
    throw new Error("EmailOracleAuth target boot OS image must match the release-pinned CVM");
  }
  if (
    appBootInfoHash(emailOracleTargetBootInfo(contracts.email_oracle_auth, normalizedCvm))
      !== emailRelease.target_boot.info_hash
  ) {
    throw new Error("EmailOracleAuth target boot info hash is not independently derived from the exact boot tuple");
  }
  const emailInfrastructureRoles = new Set([
    contracts.email_oracle_auth.address,
    contracts.email_oracle_auth.owner,
    contracts.email_oracle_auth.consumer_address,
    emailRelease.kms_contract_address,
    emailRelease.kms_implementation_address,
    emailRelease.target_boot.instance_id,
  ]);
  if (emailInfrastructureRoles.size !== 6) {
    throw new Error("EmailOracleAuth owner, consumer, KMS proxy, implementation, instance, and auth roles must be distinct");
  }
  if (contracts.diligence_room.result_verifier === normalizedCvm.tee_identity) {
    throw new Error("DiligenceRoom result verifier must be distinct from the TEE identity");
  }
  const computeVault = contracts.compute_credit_vault;
  if (
    computeVault.tee_identity !== normalizedCvm.tee_identity
    || computeVault.compose_hash !== normalizedCvm.compose_hash
  ) {
    throw new Error("ComputeCreditVault execution roots must match the release-pinned CVM");
  }
  const separatedComputeRoles = new Set([
    operator,
    contracts.diligence_room.result_verifier,
    normalizedCvm.tee_identity,
    computeVault.developer,
    computeVault.metering_verifier,
    computeVault.metering_qvl_verifier,
    computeVault.address,
  ]);
  if (separatedComputeRoles.size !== 7) {
    throw new Error("ComputeCreditVault owner, developer, metering signer, metering QVL verifier, TEE, and diligence verifier must be distinct");
  }

  if (!Array.isArray(cvm.allowed_browser_origins)) throw new Error("cvm.allowed_browser_origins must be an array");
  const origins = cvm.allowed_browser_origins.map((item, index) => {
    const normalized = httpsUrl(item, `cvm.allowed_browser_origins[${index}]`);
    const parsed = new URL(normalized);
    if (parsed.pathname !== "/" && parsed.pathname !== "") {
      throw new Error("browser CORS entries must be origins without paths");
    }
    return parsed.origin;
  });
  if (new Set(origins).size !== origins.length) throw new Error("browser CORS origins cannot be duplicated");
  if (origins.length !== REQUIRED_BROWSER_ORIGINS.size) {
    throw new Error("production browser CORS policy must contain only the reviewed Wikigen origins");
  }
  for (const required of REQUIRED_BROWSER_ORIGINS) {
    if (!origins.includes(required)) throw new Error(`browser CORS policy is missing ${required}`);
  }
  normalizedCvm.allowed_browser_origins = origins;

  const walletAuthRaw = exactRecord(
    candidate.wallet_auth,
    ["domain", "uri", "walletconnect_project_id"],
    "wallet_auth",
  );
  if (
    walletAuthRaw.domain !== "www.wikigen.me"
    || walletAuthRaw.uri !== "https://www.wikigen.me"
  ) {
    throw new Error("wallet auth must match the reviewed production signing domain and URI");
  }
  if (typeof walletAuthRaw.walletconnect_project_id !== "string"
    || !/^(?:|[0-9a-f]{32})$/.test(walletAuthRaw.walletconnect_project_id)) {
    throw new Error(
      "wallet_auth.walletconnect_project_id must be empty or exactly 32 lowercase hexadecimal characters",
    );
  }
  const walletAuth = {
    domain: "www.wikigen.me",
    uri: "https://www.wikigen.me",
    walletconnect_project_id: walletAuthRaw.walletconnect_project_id,
  };
  const executionPolicy = normalizeExecutionPolicy(candidate.execution_policy, {
    cvm: normalizedCvm,
    cvmLaunchIntentSha256,
  });
  if (
    operatorPolicy.runtime_authority_dependency_sha256
    !== `sha256:${executionPolicy.rollback_anchor.release_manifest_commitment}`
  ) {
    throw new Error(
      "operator_policy.runtime_authority_dependency_sha256 must equal the execution-policy release-manifest commitment",
    );
  }
  if (
    executionPolicy.rollback_anchor.writer_address === operator
    || executionPolicy.rollback_anchor.writer_address
      === executionPolicy.rollback_anchor.contract_address
  ) {
    throw new Error("execution-policy anchor writer must be separate from governance and the anchor contract");
  }
  const applicationAddresses = new Set(Object.values(contracts).map((entry) => entry.address));
  const emailExternalAddresses = [
    emailRelease.kms_contract_address,
    emailRelease.kms_implementation_address,
    emailRelease.target_boot.instance_id,
  ];
  const controlAddresses = new Set([
    operator,
    normalizedCvm.tee_identity,
    contracts.diligence_room.result_verifier,
    contracts.diligence_room.attestation_verifier,
    computeVault.developer,
    computeVault.metering_verifier,
    computeVault.metering_qvl_verifier,
    executionPolicy.rollback_anchor.writer_address,
    executionPolicy.rollback_anchor.contract_address,
  ]);
  for (const provider of [computeVault.native_provider, computeVault.erc20_provider]) {
    if (applicationAddresses.has(provider) || controlAddresses.has(provider)) {
      throw new Error(
        "ComputeCreditVault payout recipients must be separate from application and control-plane roles",
      );
    }
  }
  if (emailExternalAddresses.some((value) => applicationAddresses.has(value) || controlAddresses.has(value))) {
    throw new Error("Email KMS and target-instance addresses must be separate from application, control-plane, and anchor roles");
  }

  const attestations = exactRecord(
    candidate.attestations,
    ["artifact", "arena", "compute_metering"],
    "attestations",
  );
  const features = exactRecord(candidate.requested_features, [
    "contract_writes",
    "artifact_upload",
    "compute_console",
    "compute_vault_funding",
    "compute_vault_authorization",
    "compute_workload_upload",
    "arena_submission",
  ], "requested_features");
  for (const key of Object.keys(features)) bool(features[key], `requested_features.${key}`);
  if (features.compute_vault_authorization && !features.compute_vault_funding) {
    throw new Error("ComputeCreditVault authorization cannot be enabled while vault funding is disabled");
  }
  const trustDomains = normalizeTrustDomains(
    candidate.trust_domains,
    sha,
    contracts,
    normalizedCvm,
    features,
    executionPolicy,
  );
  const nativeMeteringPolicy = trustDomains.compute_metering.identity.assets
    .find((entry) => entry.asset === ZERO_ADDRESS);
  const erc20MeteringPolicy = trustDomains.compute_metering.identity.assets
    .find((entry) => entry.asset === contracts.compute_credit_vault.erc20_asset_address);
  if (
    nativeMeteringPolicy?.provider !== contracts.compute_credit_vault.native_provider
    || erc20MeteringPolicy?.provider !== contracts.compute_credit_vault.erc20_provider
  ) {
    throw new Error(
      "ComputeCreditVault provider recipients must equal the reviewed native/ERC20 metering policies",
    );
  }
  const arenaRegistryBindings = normalizeArenaRegistryBindings(
    candidate.arena_registry_bindings,
  );
  if (Object.keys(arenaRegistryBindings).length
    !== contracts.challenge_registry.expected_challenge_count) {
    throw new Error(
      "ChallengeRegistry expected challenge count must equal the exact Arena genesis catalog",
    );
  }

  return {
    schema: RELEASE_SCHEMA,
    release_sha: sha,
    network,
    operator_address: operator,
    deployment_intent_sha256: deploymentIntentSha256,
    cvm_launch_intent_sha256: cvmLaunchIntentSha256,
    operator_policy: operatorPolicy,
    contracts,
    cvm: normalizedCvm,
    trust_domains: trustDomains,
    wallet_auth: walletAuth,
    execution_policy: executionPolicy,
    attestations: {
      artifact: normalizeVerdictWrapper(attestations.artifact, "artifact"),
      arena: normalizeVerdictWrapper(attestations.arena, "arena"),
      compute_metering: normalizeVerdictWrapper(
        attestations.compute_metering,
        "compute_metering",
      ),
    },
    arena_registry_bindings: arenaRegistryBindings,
    requested_features: features,
  };
}

export function normalizePreLiveActivationReleaseCandidate(value) {
  return normalizeReleaseCandidate(value, { authorityStage: "prebuild" });
}

export function projectLiveReleaseCandidateToPrebuild(value) {
  const candidate = normalizeReleaseCandidate(value, { authorityStage: "live" });
  return {
    ...candidate,
    operator_policy: {
      schema: PRE_LIVE_ACTIVATION_AUTHORITY_EVIDENCE_SCHEMA,
      ceremony_authorization_sha256:
        candidate.operator_policy.ceremony_authorization_sha256,
      runtime_authority_dependency_sha256:
        candidate.operator_policy.runtime_authority_dependency_sha256,
    },
  };
}

export function canonicalPreLiveActivationReleaseCandidateText(value) {
  return `${JSON.stringify(
    normalizePreLiveActivationReleaseCandidate(value),
    null,
    2,
  )}\n`;
}

export function canonicalLiveReleaseCandidatePrebuildProjectionText(value) {
  return `${JSON.stringify(projectLiveReleaseCandidateToPrebuild(value), null, 2)}\n`;
}

export function liveReleaseCandidatePrebuildProjectionSha256(value) {
  return `sha256:${createHash("sha256")
    .update(canonicalLiveReleaseCandidatePrebuildProjectionText(value), "utf8")
    .digest("hex")}`;
}

export function assertLiveReleaseCandidateMatchesPrebuild(
  prebuildValue,
  liveValue,
) {
  const prebuild = normalizePreLiveActivationReleaseCandidate(prebuildValue);
  const projected = projectLiveReleaseCandidateToPrebuild(liveValue);
  if (
    `${JSON.stringify(prebuild, null, 2)}\n`
    !== `${JSON.stringify(projected, null, 2)}\n`
  ) {
    throw new Error(
      "live release candidate differs from the immutable prebuild candidate beyond insertion of signed live authority",
    );
  }
  return { prebuild, live: normalizeReleaseCandidate(liveValue) };
}

export function assertLiveActivationFinalCvmsMatchCandidate(
  liveActivationFrontendBinding,
  candidateValue,
) {
  const candidate = normalizeReleaseCandidate(candidateValue, {
    authorityStage: "live",
  });
  const finalCvms = liveActivationFrontendBinding?.final_cvms;
  const topology = [
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
  if (!Array.isArray(finalCvms) || finalCvms.length !== topology.length) {
    throw new Error("signed live activation does not contain the exact seven-CVM topology");
  }
  const evidencePins = [];
  const finalCvmKeys = [
    "app_id",
    "attestation_evidence_sha256",
    "compose_hash_sha256",
    "cvm_id",
    "cvm_key",
    "tee_identity",
  ].sort();
  for (const [index, [key, descriptor, teeIdentity]] of topology.entries()) {
    const observed = finalCvms[index];
    if (
      !observed
      || typeof observed !== "object"
      || Array.isArray(observed)
      || JSON.stringify(Object.keys(observed).sort()) !== JSON.stringify(finalCvmKeys)
      || observed.cvm_key !== key
      || observed.app_id !== descriptor.app_id
      || observed.cvm_id !== descriptor.cvm_id
      || observed.compose_hash_sha256 !== `sha256:${descriptor.compose_hash}`
      || observed.tee_identity !== teeIdentity
      || !/^sha256:[0-9a-f]{64}$/.test(
        String(observed.attestation_evidence_sha256 || ""),
      )
      || observed.attestation_evidence_sha256 === `sha256:${"0".repeat(64)}`
    ) {
      throw new Error(
        `signed live activation ${key} identity does not match the normalized release candidate`,
      );
    }
    evidencePins.push(observed.attestation_evidence_sha256);
  }
  if (new Set(evidencePins).size !== evidencePins.length) {
    throw new Error("signed live activation must bind distinct attestation evidence for all seven CVMs");
  }
  return true;
}

function requireLedgerAddress(candidateAddress, entry, label) {
  const parsed = record(entry, label);
  sameAddress(parsed.address, candidateAddress, `${label}.address`);
  return parsed;
}

function validateActiveTinkerLedgerEntry(encumbrance, candidate) {
  const label = "ledger active TinkerAccountEncumbrance";
  const policy = candidate.contracts.tinker_account_encumbrance;
  const composeHash = policy.approved_compose_hashes[0];
  const manager = policy.managers[0];

  if (
    encumbrance.status !== "deployed_exact_release_policy_frozen_active"
    || encumbrance.policyState !== "exact_timelocked_release_policy_frozen_active"
  ) {
    throw new Error("encumbrance current entry is not the exact active frozen release");
  }
  sameAddress(encumbrance.owner, candidate.operator_address, `${label}.owner`);
  zeroAddress(encumbrance.pendingOwner, `${label}.pendingOwner`);
  sameBytes32(encumbrance.accountCommitment, policy.account_commitment, `${label}.accountCommitment`);
  zeroBytes32(encumbrance.initialComposeHash, `${label}.initialComposeHash`);
  if (encumbrance.initialComposeHashApproved !== false) {
    throw new Error(`${label}.initialComposeHashApproved must preserve the empty bootstrap`);
  }
  if (
    uint256Decimal(encumbrance.maxAddBalanceWei, `${label}.maxAddBalanceWei`)
      !== policy.max_add_balance_wei
    || uint256Decimal(encumbrance.maxSpendWei, `${label}.maxSpendWei`)
      !== policy.max_spend_wei
  ) {
    throw new Error(`${label} current caps do not match the release candidate`);
  }
  exactBytes32Array(encumbrance.approvedComposeHashes, [composeHash], `${label}.approvedComposeHashes`);
  sameBytes32(encumbrance.approvedComposeRoot, policy.approved_compose_root, `${label}.approvedComposeRoot`);
  if (integer(encumbrance.approvedComposeCount, `${label}.approvedComposeCount`) !== 1) {
    throw new Error(`${label}.approvedComposeCount must be exactly one`);
  }
  exactAddressArray(encumbrance.managers, [manager], `${label}.managers`);
  sameBytes32(encumbrance.managerRoot, policy.manager_root, `${label}.managerRoot`);
  if (integer(encumbrance.managerCount, `${label}.managerCount`) !== 1) {
    throw new Error(`${label}.managerCount must be exactly one`);
  }

  sameBytes32(
    encumbrance.releasePolicyCommitment,
    policy.release_policy_commitment,
    `${label}.releasePolicyCommitment`,
  );
  if (
    uint256Decimal(encumbrance.releaseMaxAddBalanceWei, `${label}.releaseMaxAddBalanceWei`)
      !== policy.release_max_add_balance_wei
    || uint256Decimal(encumbrance.releaseMaxSpendWei, `${label}.releaseMaxSpendWei`)
      !== policy.release_max_spend_wei
  ) {
    throw new Error(`${label} frozen-baseline caps do not match the release candidate`);
  }
  exactBytes32Array(encumbrance.releaseComposeHashes, [composeHash], `${label}.releaseComposeHashes`);
  sameBytes32(encumbrance.releaseComposeRoot, policy.release_compose_root, `${label}.releaseComposeRoot`);
  if (integer(encumbrance.releaseComposeCount, `${label}.releaseComposeCount`) !== 1) {
    throw new Error(`${label}.releaseComposeCount must be exactly one`);
  }
  exactAddressArray(encumbrance.releaseManagers, [manager], `${label}.releaseManagers`);
  sameBytes32(encumbrance.releaseManagerRoot, policy.release_manager_root, `${label}.releaseManagerRoot`);
  if (integer(encumbrance.releaseManagerCount, `${label}.releaseManagerCount`) !== 1) {
    throw new Error(`${label}.releaseManagerCount must be exactly one`);
  }

  zeroBytes32(encumbrance.pendingAccountCommitment, `${label}.pendingAccountCommitment`);
  if (
    uint256Decimal(encumbrance.pendingMaxAddBalanceWei, `${label}.pendingMaxAddBalanceWei`) !== "0"
    || uint256Decimal(encumbrance.pendingMaxSpendWei, `${label}.pendingMaxSpendWei`) !== "0"
  ) {
    throw new Error(`${label} pending caps must be canonical zero strings`);
  }
  exactBytes32Array(encumbrance.pendingComposeHashes, [], `${label}.pendingComposeHashes`);
  zeroBytes32(encumbrance.pendingComposeRoot, `${label}.pendingComposeRoot`);
  if (integer(encumbrance.pendingComposeCount, `${label}.pendingComposeCount`) !== 0) {
    throw new Error(`${label}.pendingComposeCount must be zero`);
  }
  exactAddressArray(encumbrance.pendingManagers, [], `${label}.pendingManagers`);
  zeroBytes32(encumbrance.pendingManagerRoot, `${label}.pendingManagerRoot`);
  if (integer(encumbrance.pendingManagerCount, `${label}.pendingManagerCount`) !== 0) {
    throw new Error(`${label}.pendingManagerCount must be zero`);
  }
  zeroBytes32(
    encumbrance.pendingReleasePolicyCommitment,
    `${label}.pendingReleasePolicyCommitment`,
  );
  if (
    boundedInteger(
      encumbrance.pendingReleasePolicyActivatesAt,
      `${label}.pendingReleasePolicyActivatesAt`,
    ) !== 0
  ) {
    throw new Error(`${label}.pendingReleasePolicyActivatesAt must be zero`);
  }
  if (
    encumbrance.releasePolicyFrozen !== true
    || encumbrance.emergencyHalted !== false
    || encumbrance.perOperationCaps !== true
    || encumbrance.custodiesFunds !== false
  ) {
    throw new Error(`${label} does not prove the frozen, active, noncustodial posture`);
  }

  const deploymentTx = transactionHash(encumbrance.deploymentTx, `${label}.deploymentTx`);
  const deploymentSourceCommit = releaseSha(encumbrance.sourceCommit, `${label}.sourceCommit`);
  const latestReleasePhase = integer(encumbrance.latestReleasePhase, `${label}.latestReleasePhase`, 1);
  const latestReleaseTx = transactionHash(encumbrance.latestReleaseTx, `${label}.latestReleaseTx`);
  const latestReleaseBlock = integer(encumbrance.latestReleaseBlock, `${label}.latestReleaseBlock`, 1);
  const latestReleaseRecordedAtSeconds = utcTimestampSeconds(
    encumbrance.latestReleaseRecordedAt,
    `${label}.latestReleaseRecordedAt`,
  );
  const latestReleaseSourceCommit = releaseSha(
    encumbrance.latestReleaseSourceCommit,
    `${label}.latestReleaseSourceCommit`,
  );
  if (latestReleasePhase !== 2) {
    throw new Error(`${label}.latestReleasePhase must be phase 2`);
  }

  return {
    deploymentTx,
    deploymentSourceCommit,
    latestReleaseTx,
    latestReleaseBlock,
    latestReleaseRecordedAt: encumbrance.latestReleaseRecordedAt,
    latestReleaseRecordedAtSeconds,
    latestReleaseSourceCommit,
  };
}

function validatePristineTinkerDraft(draftValue, suiteHistory, active, candidate) {
  const label = "deployment history pristine TinkerAccountEncumbrance draft";
  const draft = record(draftValue, label);
  const policy = candidate.contracts.tinker_account_encumbrance;
  const suiteSourceCommit = releaseSha(suiteHistory.sourceCommit, `${label}.sourceCommit`);

  sameAddress(draft.address, policy.address, `${label}.address`);
  sameBytes32(draft.runtimeCodeHash, policy.runtime_code_hash, `${label}.runtimeCodeHash`);
  if (
    transactionHash(draft.deploymentTx, `${label}.deploymentTx`) !== active.deploymentTx
    || suiteSourceCommit !== active.deploymentSourceCommit
  ) {
    throw new Error(`${label} is not bound to the active deployment transaction and source`);
  }
  if (
    draft.status !== "deployed_halted_draft_pending_timelocked_release_policy"
    || draft.policyState !== "operations_fail_closed_pending_exact_timelocked_release_policy"
  ) {
    throw new Error(`${label} does not preserve the original fail-closed status`);
  }
  sameAddress(draft.owner, candidate.operator_address, `${label}.owner`);
  zeroAddress(draft.pendingOwner, `${label}.pendingOwner`);
  sameBytes32(draft.accountCommitment, policy.account_commitment, `${label}.accountCommitment`);
  if (
    uint256Decimal(draft.maxAddBalanceWei, `${label}.maxAddBalanceWei`)
      !== policy.max_add_balance_wei
    || uint256Decimal(draft.maxSpendWei, `${label}.maxSpendWei`)
      !== policy.max_spend_wei
  ) {
    throw new Error(`${label} draft caps do not match the reviewed release`);
  }
  exactBytes32Array(draft.approvedComposeHashes, [], `${label}.approvedComposeHashes`);
  sameBytes32(
    draft.approvedComposeRoot,
    TINKER_EMPTY_COMPOSE_ROOT,
    `${label}.approvedComposeRoot`,
  );
  if (integer(draft.approvedComposeCount, `${label}.approvedComposeCount`) !== 0) {
    throw new Error(`${label}.approvedComposeCount must be zero`);
  }
  exactAddressArray(draft.managers, [], `${label}.managers`);
  sameBytes32(draft.managerRoot, TINKER_EMPTY_MANAGER_ROOT, `${label}.managerRoot`);
  if (integer(draft.managerCount, `${label}.managerCount`) !== 0) {
    throw new Error(`${label}.managerCount must be zero`);
  }

  zeroBytes32(draft.releasePolicyCommitment, `${label}.releasePolicyCommitment`);
  if (
    uint256Decimal(draft.releaseMaxAddBalanceWei, `${label}.releaseMaxAddBalanceWei`) !== "0"
    || uint256Decimal(draft.releaseMaxSpendWei, `${label}.releaseMaxSpendWei`) !== "0"
  ) {
    throw new Error(`${label} frozen-baseline caps must be canonical zero strings`);
  }
  exactBytes32Array(draft.releaseComposeHashes, [], `${label}.releaseComposeHashes`);
  zeroBytes32(draft.releaseComposeRoot, `${label}.releaseComposeRoot`);
  if (integer(draft.releaseComposeCount, `${label}.releaseComposeCount`) !== 0) {
    throw new Error(`${label}.releaseComposeCount must be zero`);
  }
  exactAddressArray(draft.releaseManagers, [], `${label}.releaseManagers`);
  zeroBytes32(draft.releaseManagerRoot, `${label}.releaseManagerRoot`);
  if (integer(draft.releaseManagerCount, `${label}.releaseManagerCount`) !== 0) {
    throw new Error(`${label}.releaseManagerCount must be zero`);
  }

  zeroBytes32(draft.pendingAccountCommitment, `${label}.pendingAccountCommitment`);
  if (
    uint256Decimal(draft.pendingMaxAddBalanceWei, `${label}.pendingMaxAddBalanceWei`) !== "0"
    || uint256Decimal(draft.pendingMaxSpendWei, `${label}.pendingMaxSpendWei`) !== "0"
  ) {
    throw new Error(`${label} pending caps must be canonical zero strings`);
  }
  exactBytes32Array(draft.pendingComposeHashes, [], `${label}.pendingComposeHashes`);
  zeroBytes32(draft.pendingComposeRoot, `${label}.pendingComposeRoot`);
  if (integer(draft.pendingComposeCount, `${label}.pendingComposeCount`) !== 0) {
    throw new Error(`${label}.pendingComposeCount must be zero`);
  }
  exactAddressArray(draft.pendingManagers, [], `${label}.pendingManagers`);
  zeroBytes32(draft.pendingManagerRoot, `${label}.pendingManagerRoot`);
  if (integer(draft.pendingManagerCount, `${label}.pendingManagerCount`) !== 0) {
    throw new Error(`${label}.pendingManagerCount must be zero`);
  }
  zeroBytes32(
    draft.pendingReleasePolicyCommitment,
    `${label}.pendingReleasePolicyCommitment`,
  );
  if (
    integer(
      draft.pendingReleasePolicyActivatesAt,
      `${label}.pendingReleasePolicyActivatesAt`,
    ) !== 0
  ) {
    throw new Error(`${label}.pendingReleasePolicyActivatesAt must be zero`);
  }
  if (
    draft.releasePolicyFrozen !== false
    || draft.emergencyHalted !== true
    || draft.perOperationCaps !== true
    || draft.custodiesFunds !== false
  ) {
    throw new Error(`${label} does not prove the pristine halted noncustodial draft`);
  }

  return { managerRoot: TINKER_EMPTY_MANAGER_ROOT };
}

function validateTinkerReleaseHistory(ledger, active, draft, candidate) {
  const history = ledger.tinkerReleaseHistory;
  if (!Array.isArray(history)) {
    throw new Error("Tinker release history is required for a production release candidate");
  }
  const policy = candidate.contracts.tinker_account_encumbrance;
  const composeHash = policy.approved_compose_hashes[0];
  const manager = policy.managers[0];
  const activeAddress = policy.address.toLowerCase();
  const activeRuntimeCodeHash = policy.runtime_code_hash.toLowerCase();
  const selected = history.filter((entry) => (
    entry
    && typeof entry === "object"
    && !Array.isArray(entry)
    && entry.chainId === BASE_SEPOLIA_CHAIN_ID
    && typeof entry.encumbranceAddress === "string"
    && entry.encumbranceAddress.toLowerCase() === activeAddress
    && typeof entry.runtimeCodeHash === "string"
    && entry.runtimeCodeHash.toLowerCase() === activeRuntimeCodeHash
  ));
  if (selected.length !== 2) {
    throw new Error("active Tinker deployment must have exactly one phase-1 and one phase-2 history record");
  }

  const phases = selected.map((value, index) => {
    const label = `active Tinker release history[${index}]`;
    const entry = exactRecord(value, TINKER_RELEASE_HISTORY_KEYS, label);
    if (entry.kind !== "tinker_exact_release_policy_phase") {
      throw new Error(`${label}.kind is not the exact Tinker release ceremony`);
    }
    if (integer(entry.chainId, `${label}.chainId`) !== BASE_SEPOLIA_CHAIN_ID) {
      throw new Error(`${label}.chainId is not Base Sepolia`);
    }
    sameAddress(entry.encumbranceAddress, activeAddress, `${label}.encumbranceAddress`);
    sameBytes32(entry.runtimeCodeHash, activeRuntimeCodeHash, `${label}.runtimeCodeHash`);
    zeroAddress(entry.pendingOwner, `${label}.pendingOwner`);
    sameBytes32(entry.accountCommitment, policy.account_commitment, `${label}.accountCommitment`);
    if (
      uint256Decimal(entry.maxAddBalanceWei, `${label}.maxAddBalanceWei`)
        !== policy.max_add_balance_wei
      || uint256Decimal(entry.maxSpendWei, `${label}.maxSpendWei`)
        !== policy.max_spend_wei
    ) {
      throw new Error(`${label} current caps do not match the reviewed policy`);
    }
    exactBytes32Array(entry.approvedComposeHashes, [composeHash], `${label}.approvedComposeHashes`);
    sameBytes32(entry.composeRoot, policy.approved_compose_root, `${label}.composeRoot`);
    if (integer(entry.composeCount, `${label}.composeCount`) !== 1) {
      throw new Error(`${label}.composeCount must be exactly one`);
    }
    if (entry.perOperationCaps !== true || entry.custodiesFunds !== false) {
      throw new Error(`${label} does not preserve noncustodial per-operation semantics`);
    }

    return {
      entry,
      label,
      phase: integer(entry.phase, `${label}.phase`, 1),
      sourceCommit: releaseSha(entry.sourceCommit, `${label}.sourceCommit`),
      transactionHash: transactionHash(entry.transactionHash, `${label}.transactionHash`),
      blockNumber: integer(entry.blockNumber, `${label}.blockNumber`, 1),
      recordedAtSeconds: utcTimestampSeconds(entry.recordedAt, `${label}.recordedAt`),
    };
  });

  const [phaseOne, phaseTwo] = phases;
  if (phaseOne.phase !== 1 || phaseTwo.phase !== 2) {
    throw new Error("active Tinker release history must be ordered phase 1 then phase 2");
  }
  if (
    phaseOne.transactionHash === phaseTwo.transactionHash
    || phaseOne.blockNumber >= phaseTwo.blockNumber
    || phaseOne.recordedAtSeconds >= phaseTwo.recordedAtSeconds
  ) {
    throw new Error("active Tinker release phases must have unique ordered transaction evidence");
  }
  for (const phase of phases) {
    const replayCount = history.filter((entry) => (
      typeof entry?.transactionHash === "string"
      && entry.transactionHash.toLowerCase() === phase.transactionHash
    )).length;
    if (replayCount !== 1) {
      throw new Error("active Tinker release transaction evidence is replayed in history");
    }
  }

  const phaseOneEntry = phaseOne.entry;
  if (
    phaseOneEntry.status !== "deployed_halted_release_policy_pending_timelock"
    || phaseOneEntry.policyState !== "operations_fail_closed_pending_exact_timelocked_release_policy"
    || phaseOneEntry.releasePolicyFrozen !== false
    || phaseOneEntry.emergencyHalted !== true
  ) {
    throw new Error("Tinker phase-1 history does not prove the halted pending review state");
  }
  exactAddressArray(phaseOneEntry.managers, [], `${phaseOne.label}.managers`);
  sameBytes32(phaseOneEntry.managerRoot, draft.managerRoot, `${phaseOne.label}.managerRoot`);
  if (integer(phaseOneEntry.managerCount, `${phaseOne.label}.managerCount`) !== 0) {
    throw new Error(`${phaseOne.label}.managerCount must be zero`);
  }
  zeroBytes32(
    phaseOneEntry.releasePolicyCommitment,
    `${phaseOne.label}.releasePolicyCommitment`,
  );
  if (
    uint256Decimal(
      phaseOneEntry.releaseMaxAddBalanceWei,
      `${phaseOne.label}.releaseMaxAddBalanceWei`,
    ) !== "0"
    || uint256Decimal(
      phaseOneEntry.releaseMaxSpendWei,
      `${phaseOne.label}.releaseMaxSpendWei`,
    ) !== "0"
  ) {
    throw new Error("Tinker phase-1 frozen-baseline caps must be canonical zero strings");
  }
  exactBytes32Array(
    phaseOneEntry.releaseComposeHashes,
    [],
    `${phaseOne.label}.releaseComposeHashes`,
  );
  zeroBytes32(phaseOneEntry.releaseComposeRoot, `${phaseOne.label}.releaseComposeRoot`);
  if (integer(phaseOneEntry.releaseComposeCount, `${phaseOne.label}.releaseComposeCount`) !== 0) {
    throw new Error(`${phaseOne.label}.releaseComposeCount must be zero`);
  }
  exactAddressArray(phaseOneEntry.releaseManagers, [], `${phaseOne.label}.releaseManagers`);
  zeroBytes32(phaseOneEntry.releaseManagerRoot, `${phaseOne.label}.releaseManagerRoot`);
  if (integer(phaseOneEntry.releaseManagerCount, `${phaseOne.label}.releaseManagerCount`) !== 0) {
    throw new Error(`${phaseOne.label}.releaseManagerCount must be zero`);
  }
  sameBytes32(
    phaseOneEntry.pendingAccountCommitment,
    policy.account_commitment,
    `${phaseOne.label}.pendingAccountCommitment`,
  );
  if (
    uint256Decimal(
      phaseOneEntry.pendingMaxAddBalanceWei,
      `${phaseOne.label}.pendingMaxAddBalanceWei`,
    ) !== policy.max_add_balance_wei
    || uint256Decimal(
      phaseOneEntry.pendingMaxSpendWei,
      `${phaseOne.label}.pendingMaxSpendWei`,
    ) !== policy.max_spend_wei
  ) {
    throw new Error("Tinker phase-1 pending caps do not match the reviewed policy");
  }
  exactBytes32Array(
    phaseOneEntry.pendingComposeHashes,
    [composeHash],
    `${phaseOne.label}.pendingComposeHashes`,
  );
  sameBytes32(
    phaseOneEntry.pendingComposeRoot,
    policy.release_compose_root,
    `${phaseOne.label}.pendingComposeRoot`,
  );
  if (integer(phaseOneEntry.pendingComposeCount, `${phaseOne.label}.pendingComposeCount`) !== 1) {
    throw new Error(`${phaseOne.label}.pendingComposeCount must be exactly one`);
  }
  exactAddressArray(
    phaseOneEntry.pendingManagers,
    [manager],
    `${phaseOne.label}.pendingManagers`,
  );
  sameBytes32(
    phaseOneEntry.pendingManagerRoot,
    policy.release_manager_root,
    `${phaseOne.label}.pendingManagerRoot`,
  );
  if (integer(phaseOneEntry.pendingManagerCount, `${phaseOne.label}.pendingManagerCount`) !== 1) {
    throw new Error(`${phaseOne.label}.pendingManagerCount must be exactly one`);
  }
  sameBytes32(
    phaseOneEntry.pendingReleasePolicyCommitment,
    policy.release_policy_commitment,
    `${phaseOne.label}.pendingReleasePolicyCommitment`,
  );
  const reviewEligibleAt = integer(
    phaseOneEntry.pendingReleasePolicyActivatesAt,
    `${phaseOne.label}.pendingReleasePolicyActivatesAt`,
    1,
  );
  if (
    reviewEligibleAt <= phaseOne.recordedAtSeconds
    || phaseTwo.recordedAtSeconds < reviewEligibleAt
  ) {
    throw new Error("Tinker release history does not span the recorded review deadline");
  }

  const phaseTwoEntry = phaseTwo.entry;
  if (
    phaseTwoEntry.status !== "deployed_exact_release_policy_frozen_active"
    || phaseTwoEntry.policyState !== "exact_timelocked_release_policy_frozen_active"
    || phaseTwoEntry.releasePolicyFrozen !== true
    || phaseTwoEntry.emergencyHalted !== false
  ) {
    throw new Error("Tinker phase-2 history does not prove the exact active frozen state");
  }
  exactAddressArray(phaseTwoEntry.managers, [manager], `${phaseTwo.label}.managers`);
  sameBytes32(phaseTwoEntry.managerRoot, policy.manager_root, `${phaseTwo.label}.managerRoot`);
  if (integer(phaseTwoEntry.managerCount, `${phaseTwo.label}.managerCount`) !== 1) {
    throw new Error(`${phaseTwo.label}.managerCount must be exactly one`);
  }
  sameBytes32(
    phaseTwoEntry.releasePolicyCommitment,
    policy.release_policy_commitment,
    `${phaseTwo.label}.releasePolicyCommitment`,
  );
  if (
    uint256Decimal(
      phaseTwoEntry.releaseMaxAddBalanceWei,
      `${phaseTwo.label}.releaseMaxAddBalanceWei`,
    ) !== policy.release_max_add_balance_wei
    || uint256Decimal(
      phaseTwoEntry.releaseMaxSpendWei,
      `${phaseTwo.label}.releaseMaxSpendWei`,
    ) !== policy.release_max_spend_wei
  ) {
    throw new Error("Tinker phase-2 frozen-baseline caps do not match the reviewed policy");
  }
  exactBytes32Array(
    phaseTwoEntry.releaseComposeHashes,
    [composeHash],
    `${phaseTwo.label}.releaseComposeHashes`,
  );
  sameBytes32(
    phaseTwoEntry.releaseComposeRoot,
    policy.release_compose_root,
    `${phaseTwo.label}.releaseComposeRoot`,
  );
  if (integer(phaseTwoEntry.releaseComposeCount, `${phaseTwo.label}.releaseComposeCount`) !== 1) {
    throw new Error(`${phaseTwo.label}.releaseComposeCount must be exactly one`);
  }
  exactAddressArray(phaseTwoEntry.releaseManagers, [manager], `${phaseTwo.label}.releaseManagers`);
  sameBytes32(
    phaseTwoEntry.releaseManagerRoot,
    policy.release_manager_root,
    `${phaseTwo.label}.releaseManagerRoot`,
  );
  if (integer(phaseTwoEntry.releaseManagerCount, `${phaseTwo.label}.releaseManagerCount`) !== 1) {
    throw new Error(`${phaseTwo.label}.releaseManagerCount must be exactly one`);
  }
  zeroBytes32(
    phaseTwoEntry.pendingAccountCommitment,
    `${phaseTwo.label}.pendingAccountCommitment`,
  );
  if (
    uint256Decimal(
      phaseTwoEntry.pendingMaxAddBalanceWei,
      `${phaseTwo.label}.pendingMaxAddBalanceWei`,
    ) !== "0"
    || uint256Decimal(
      phaseTwoEntry.pendingMaxSpendWei,
      `${phaseTwo.label}.pendingMaxSpendWei`,
    ) !== "0"
  ) {
    throw new Error("Tinker phase-2 pending caps must be canonical zero strings");
  }
  exactBytes32Array(
    phaseTwoEntry.pendingComposeHashes,
    [],
    `${phaseTwo.label}.pendingComposeHashes`,
  );
  zeroBytes32(phaseTwoEntry.pendingComposeRoot, `${phaseTwo.label}.pendingComposeRoot`);
  if (integer(phaseTwoEntry.pendingComposeCount, `${phaseTwo.label}.pendingComposeCount`) !== 0) {
    throw new Error(`${phaseTwo.label}.pendingComposeCount must be zero`);
  }
  exactAddressArray(phaseTwoEntry.pendingManagers, [], `${phaseTwo.label}.pendingManagers`);
  zeroBytes32(phaseTwoEntry.pendingManagerRoot, `${phaseTwo.label}.pendingManagerRoot`);
  if (integer(phaseTwoEntry.pendingManagerCount, `${phaseTwo.label}.pendingManagerCount`) !== 0) {
    throw new Error(`${phaseTwo.label}.pendingManagerCount must be zero`);
  }
  zeroBytes32(
    phaseTwoEntry.pendingReleasePolicyCommitment,
    `${phaseTwo.label}.pendingReleasePolicyCommitment`,
  );
  if (
    integer(
      phaseTwoEntry.pendingReleasePolicyActivatesAt,
      `${phaseTwo.label}.pendingReleasePolicyActivatesAt`,
    ) !== 0
  ) {
    throw new Error(`${phaseTwo.label}.pendingReleasePolicyActivatesAt must be zero`);
  }

  if (
    active.latestReleaseTx !== phaseTwo.transactionHash
    || active.latestReleaseBlock !== phaseTwo.blockNumber
    || active.latestReleaseRecordedAt !== phaseTwoEntry.recordedAt
    || active.latestReleaseRecordedAtSeconds !== phaseTwo.recordedAtSeconds
    || active.latestReleaseSourceCommit !== phaseTwo.sourceCommit
  ) {
    throw new Error("active Tinker latest-release fields do not identify the exact phase-2 record");
  }
}

export function validateDeploymentLedger(value, candidate, authorityBindingValue) {
  const authorityBinding = normalizeReleaseAuthorityBinding(authorityBindingValue);
  if (
    candidate.deployment_intent_sha256
      !== authorityBinding.deploymentIntentSha256
    || candidate.operator_policy.ceremony_authorization_sha256
      !== authorityBinding.ceremonyAuthorizationSha256
    || candidate.operator_policy.runtime_authority_dependency_sha256
      !== authorityBinding.runtimeAuthorityDependencySha256
  ) {
    throw new Error(
      "release candidate does not exactly match the independently validated authority binding",
    );
  }
  const ledger = record(value, "deployment ledger");
  const network = record(ledger.network, "deployment ledger network");
  if (network.chainId !== BASE_SEPOLIA_CHAIN_ID || network.name !== "Base Sepolia") {
    throw new Error("deployment ledger is not Base Sepolia");
  }
  const operator = record(ledger.currentOperatorDeployer, "currentOperatorDeployer");
  sameAddress(operator.address, candidate.operator_address, "deployment operator");
  if (operator.keystoreAccount !== "dev" || operator.privateKeyMaterial !== "not_used") {
    throw new Error("fresh suite ledger must record the dev keystore and no raw private key use");
  }

  const fresh = record(ledger.freshDeployment, "freshDeployment");
  const suite = record(fresh.contractSuite, "freshDeployment.contractSuite");
  if (suite.status !== "broadcast_complete_pending_cvm_binding") {
    throw new Error("ledger does not contain the fresh reviewed-scope suite deployment");
  }
  if (
    suite.keystoreAccount !== "dev"
    || suite.includesReviewedComputeCreditVault !== true
    || suite.excludesChallengePrizeAndCandidateCustodyContracts !== true
  ) {
    throw new Error("fresh suite ledger safety markers are missing");
  }
  if (
    suite.deploymentIntentSha256 !== authorityBinding.deploymentIntentSha256
    || suite.reviewerAuthorityGenesisAcceptanceSha256
      !== authorityBinding.reviewerAuthorityGenesisAcceptanceSha256
  ) {
    throw new Error(
      "fresh suite ledger does not bind the exact deployment intent and signed reviewer-genesis acceptance",
    );
  }
  if (
    suite.runtimeCodeProof !== "exact_creation_reexecution_match_all_contracts"
    || suite.diligencePolicyState !== "fail_closed_pending_cvm_binding"
    || suite.computeVaultPolicyState !== "execution_fail_closed_pending_timelocked_release_binding"
    || suite.emailOraclePolicyState !== "deny_all_pending_cvm_binding"
    || suite.executionPolicyAnchorState !== "anchoring_fail_closed_pending_timelocked_release_writer"
  ) {
    throw new Error("fresh suite ledger policy or exact-runtime proof markers are missing");
  }
  if (suite.sourceCommit !== candidate.release_sha) throw new Error("fresh suite source commit mismatch");

  const contracts = record(ledger.contracts, "deployment ledger contracts");
  const diligence = requireLedgerAddress(candidate.contracts.diligence_room.address, contracts.diligenceRoom, "ledger DiligenceRoom");
  const challenge = requireLedgerAddress(candidate.contracts.challenge_registry.address, contracts.challengeRegistry, "ledger ChallengeRegistry");
  const royalty = requireLedgerAddress(candidate.contracts.royalty_distributor.address, contracts.royaltyDistributor, "ledger RoyaltyDistributor");
  const encumbrance = requireLedgerAddress(candidate.contracts.tinker_account_encumbrance.address, contracts.tinkerAccountEncumbrance, "ledger TinkerAccountEncumbrance");
  const compute = requireLedgerAddress(candidate.contracts.compute_credit_vault.address, contracts.computeCreditVault, "ledger ComputeCreditVault");
  const email = requireLedgerAddress(candidate.contracts.email_oracle_auth.address, contracts.emailOracleAuth, "ledger EmailOracleAuth");
  const executionPolicyAnchor = requireLedgerAddress(
    candidate.execution_policy.rollback_anchor.contract_address,
    contracts.executionPolicyAnchor,
    "ledger ExecutionPolicyAnchor",
  );
  if (diligence.status !== "deployed_fail_closed_pending_tee_binding") {
    throw new Error("DiligenceRoom is not the fail-closed fresh suite entry");
  }
  if (challenge.status !== "deployed_empty_active_registry") throw new Error("ChallengeRegistry is not the fresh suite entry");
  if (royalty.status !== "deployed_ownerless_pull_payment_rail") throw new Error("RoyaltyDistributor is not the fresh suite entry");
  if (encumbrance.status !== "deployed_exact_release_policy_frozen_active") {
    throw new Error("encumbrance current entry is not the active frozen release");
  }
  if (compute.status !== "deployed_paused_fee_frozen_unbound_pending_release_binding") {
    throw new Error("ComputeCreditVault is not the fresh fail-closed suite entry");
  }
  if (email.status !== "deployed_deny_all_pending_cvm_binding") {
    throw new Error("EmailOracleAuth is not the fresh deny-all suite entry");
  }
  if (executionPolicyAnchor.status !== "verified_active_frozen_release_writer") {
    throw new Error("ExecutionPolicyAnchor is not the verified active frozen release writer");
  }
  for (const [entry, label, candidateKey] of [
    [diligence, "DiligenceRoom", "diligence_room"],
    [challenge, "ChallengeRegistry", "challenge_registry"],
    [royalty, "RoyaltyDistributor", "royalty_distributor"],
    [encumbrance, "TinkerAccountEncumbrance", "tinker_account_encumbrance"],
    [compute, "ComputeCreditVault", "compute_credit_vault"],
    [email, "EmailOracleAuth", "email_oracle_auth"],
  ]) {
    if (entry.sourceCommit !== candidate.release_sha) {
      throw new Error(`${label} ledger entry was not deployed from this release commit`);
    }
    sameBytes32(
      entry.runtimeCodeHash,
      candidate.contracts[candidateKey].runtime_code_hash,
      `ledger ${label} runtime code hash`,
    );
  }
  if (executionPolicyAnchor.sourceCommit !== candidate.release_sha) {
    throw new Error("ExecutionPolicyAnchor ledger entry was not deployed from this release commit");
  }
  sameBytes32(
    executionPolicyAnchor.runtimeCodeHash,
    candidate.execution_policy.rollback_anchor.runtime_code_hash,
    "ledger ExecutionPolicyAnchor runtime code hash",
  );
  sameAddress(
    executionPolicyAnchor.owner,
    candidate.operator_address,
    "ledger ExecutionPolicyAnchor owner",
  );
  sameBytes32(
    executionPolicyAnchor.deploymentIntentSha256Bytes32,
    sha256PinAsBytes32(
      authorityBinding.deploymentIntentSha256,
      "release authority deployment-intent digest",
    ),
    "ledger ExecutionPolicyAnchor deployment-intent digest",
  );
  sameBytes32(
    executionPolicyAnchor.reviewerAuthorityGenesisAcceptanceSha256Bytes32,
    sha256PinAsBytes32(
      authorityBinding.reviewerAuthorityGenesisAcceptanceSha256,
      "release authority reviewer-genesis-acceptance digest",
    ),
    "ledger ExecutionPolicyAnchor reviewer-genesis-acceptance digest",
  );
  const anchorGlobalSequence = integer(
    executionPolicyAnchor.globalSequence,
    "ledger ExecutionPolicyAnchor globalSequence",
  );
  const anchorGlobalHead = String(executionPolicyAnchor.globalHead).toLowerCase();
  const anchorReleaseSnapshotBlockNumber = integer(
    executionPolicyAnchor.releaseSnapshotBlockNumber,
    "ledger ExecutionPolicyAnchor releaseSnapshotBlockNumber",
    1,
  );
  if (
    address(executionPolicyAnchor.writer, "ledger ExecutionPolicyAnchor writer")
      !== candidate.execution_policy.rollback_anchor.writer_address
    || bytes32(
      executionPolicyAnchor.writerReleaseCommitment,
      "ledger ExecutionPolicyAnchor writer release commitment",
    ) !== candidate.execution_policy.rollback_anchor.writer_release_commitment
    || String(executionPolicyAnchor.pendingWriter).toLowerCase() !== ZERO_ADDRESS
    || String(executionPolicyAnchor.pendingWriterReleaseCommitment).toLowerCase() !== ZERO_BYTES32
    || executionPolicyAnchor.pendingWriterActivatesAt !== 0
    || executionPolicyAnchor.writerRotationDelaySeconds !== 172_800
    || executionPolicyAnchor.writerRotationsFrozen !== true
    || executionPolicyAnchor.paused !== false
    || !/^0x[0-9a-f]{64}$/.test(anchorGlobalHead)
    || (anchorGlobalSequence === 0) !== (anchorGlobalHead === ZERO_BYTES32)
    || executionPolicyAnchor.resourceAndDecisionPayloadsOnChain !== false
    || executionPolicyAnchor.opaqueCommitmentsOnly !== true
    || executionPolicyAnchor.policyState !== "anchoring_active_frozen_release_writer"
  ) {
    throw new Error("ledger ExecutionPolicyAnchor does not prove the exact active frozen release writer snapshot");
  }
  sameAddress(diligence.developer, candidate.operator_address, "ledger DiligenceRoom developer");
  sameAddress(diligence.resultVerifier, candidate.contracts.diligence_room.result_verifier, "ledger DiligenceRoom result verifier");
  if (
    String(diligence.pendingResultVerifier).toLowerCase() !== ZERO_ADDRESS
    || diligence.pendingResultVerifierActivatesAt !== 0
    || diligence.resultVerifierFrozen !== true
  ) {
    throw new Error(
      "ledger DiligenceRoom does not prove the final timelocked result verifier is active and frozen",
    );
  }
  if (String(diligence.attestationVerifier).toLowerCase() !== ZERO_ADDRESS) {
    throw new Error("ledger initial DiligenceRoom attestation verifier must be unset");
  }
  if (String(diligence.attestationReleasePolicyHash).toLowerCase() !== ZERO_BYTES32) {
    throw new Error("ledger initial DiligenceRoom attestation policy hash must be unset");
  }
  if (
    diligence.feeBps !== 100
    || diligence.feeBpsFrozen !== true
    || diligence.computeSettlementBps !== 100
    || diligence.computeSettlementPolicyEnabled !== true
  ) {
    throw new Error("ledger DiligenceRoom settlement tariffs are not fixed to the reviewed policy");
  }
  if (diligence.approvalRequirementsFrozen !== true) {
    throw new Error("ledger DiligenceRoom approval requirements are not irreversibly frozen");
  }
  if (
    diligence.composeApprovalRequired !== true
    || diligence.teeIdentityApprovalRequired !== true
    || diligence.approvedComposeCount !== 0
    || diligence.approvedTeeIdentityCount !== 0
    || diligence.pendingComposeCount !== 0
    || diligence.pendingTeeIdentityCount !== 0
    || String(diligence.pendingAttestationVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(diligence.pendingAttestationReleasePolicyHash).toLowerCase() !== ZERO_BYTES32
    || diligence.pendingAttestationBindingActivatesAt !== 0
    || diligence.attestationBindingFrozen !== false
    || !Array.isArray(diligence.evaluatorPolicyCommitments)
    || diligence.evaluatorPolicyCommitments.length !== 0
    || String(diligence.evaluatorPolicySetRoot).toLowerCase() !== ZERO_BYTES32
    || diligence.approvedEvaluatorPolicyCount !== 0
    || diligence.pendingEvaluatorPolicyCount !== 0
    || diligence.evaluatorPolicySetFrozen !== false
    || !Array.isArray(diligence.pendingEvaluatorPolicyProposals)
    || diligence.pendingEvaluatorPolicyProposals.length !== 0
    || diligence.composeAdditionsFrozen !== false
    || diligence.teeIdentityAdditionsFrozen !== false
    || diligence.policyState !== "fail_closed_pending_cvm_binding"
    || !Array.isArray(diligence.initialApprovedComposeHashes)
    || diligence.initialApprovedComposeHashes.length !== 0
    || !Array.isArray(diligence.initialApprovedTeeIdentities)
    || diligence.initialApprovedTeeIdentities.length !== 0
  ) {
    throw new Error("ledger DiligenceRoom does not prove the frozen empty-allowlist release posture");
  }
  sameAddress(challenge.owner, candidate.operator_address, "ledger ChallengeRegistry owner");
  const activeTinker = validateActiveTinkerLedgerEntry(encumbrance, candidate);
  sameAddress(compute.owner, candidate.operator_address, "ledger ComputeCreditVault owner");
  sameAddress(compute.developer, candidate.contracts.compute_credit_vault.developer, "ledger ComputeCreditVault developer");
  if (
    compute.status !== "deployed_paused_fee_frozen_unbound_pending_release_binding"
    || String(compute.meteringVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(compute.meteringQvlVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(compute.meteringPolicySetHash).toLowerCase() !== ZERO_BYTES32
    || String(compute.pendingMeteringVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(compute.pendingMeteringQvlVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(compute.pendingMeteringPolicySetHash).toLowerCase() !== ZERO_BYTES32
    || compute.pendingMeteringBindingActivatesAt !== 0
    || compute.meteringBindingFrozen !== false
    || compute.paused !== true
    || compute.developerFeeFrozen !== true
    || !Number.isSafeInteger(compute.developerFeeBps)
    || compute.developerFeeBps !== candidate.contracts.compute_credit_vault.developer_fee_bps
    || compute.allowedAssetCount !== 0
    || compute.activeRatePolicyCount !== 0
    || compute.approvedComposeCount !== 0
    || compute.approvedTeeIdentityCount !== 0
    || compute.pendingAssetCount !== 0
    || compute.pendingRatePolicyCount !== 0
    || compute.pendingComposeCount !== 0
    || compute.pendingTeeIdentityCount !== 0
    || compute.composePolicyFrozen !== false
    || compute.teeIdentityAdditionsFrozen !== false
    || compute.ratePolicyAdditionsFrozen !== false
    || compute.assetAdditionsFrozen !== false
    || compute.policyState !== "execution_fail_closed_pending_timelocked_release_binding"
    || !Array.isArray(compute.approvedComposeHashes)
    || compute.approvedComposeHashes.length !== 0
    || !Array.isArray(compute.approvedTeeIdentities)
    || compute.approvedTeeIdentities.length !== 0
    || !Array.isArray(compute.activeRatePolicies)
    || compute.activeRatePolicies.length !== 0
    || !Array.isArray(compute.enabledErc20Assets)
    || compute.enabledErc20Assets.length !== 0
    || compute.nativeFundingSupported !== true
    || compute.creditsTransferable !== false
    || compute.priceOracle !== false
  ) {
    throw new Error("ledger ComputeCreditVault does not prove its frozen-fee, empty-admission release posture");
  }
  sameAddress(email.owner, candidate.operator_address, "ledger EmailOracleAuth owner");
  if (
    integer(
      email.oracleUpgradeDelaySeconds,
      "ledger EmailOracleAuth oracleUpgradeDelaySeconds",
      172_800,
      31_536_000,
    ) !== candidate.contracts.email_oracle_auth.upgrade_delay_seconds
  ) {
    throw new Error("ledger EmailOracleAuth upgrade delay does not match the release candidate");
  }
  if (
    email.policyState !== "deny_all_pending_cvm_binding"
    || email.allowAnyDevice !== false
    || email.oracleCodeFrozen !== false
    || email.consumerRegistryFrozen !== false
    || email.initialOracleComposeHash !== null
    || email.initialDeviceId !== null
    || !Array.isArray(email.initialConsumerBindings)
    || email.initialConsumerBindings.length !== 0
  ) {
    throw new Error("ledger EmailOracleAuth does not prove its initial deny-all release posture");
  }

  if (!Array.isArray(ledger.deploymentHistory) || ledger.deploymentHistory.length === 0) {
    throw new Error("fresh suite deployment history entry is required");
  }
  // CVM binding and freeze transactions are appended after contract deployment.
  // Select the newest matching suite record rather than requiring it to remain
  // the last item in an append-only, multi-kind history.
  const historyEntry = [...ledger.deploymentHistory].reverse().find((entry) => (
    entry
    && typeof entry === "object"
    && !Array.isArray(entry)
    && entry.kind === "fresh_reviewed_scope_contract_suite"
    && entry.sourceCommit === candidate.release_sha
  ));
  if (!historyEntry) throw new Error("deployment history does not contain this fresh suite");
  const history = record(historyEntry, "matching fresh-suite deployment history");
  sameAddress(history.operator, candidate.operator_address, "deployment history operator");
  if (
    history.deploymentIntentSha256 !== authorityBinding.deploymentIntentSha256
    || history.reviewerAuthorityGenesisAcceptanceSha256
      !== authorityBinding.reviewerAuthorityGenesisAcceptanceSha256
  ) {
    throw new Error(
      "deployment history does not bind the exact deployment intent and signed reviewer-genesis acceptance",
    );
  }
  if (String(history.resultVerifier).toLowerCase() !== ZERO_ADDRESS) {
    throw new Error("fresh deployment history result verifier must be unset");
  }
  const deployed = record(history.deployedContracts, "deployment history contracts");
  for (const [manifestKey, candidateKey] of [
    ["diligenceRoom", "diligence_room"],
    ["challengeRegistry", "challenge_registry"],
    ["royaltyDistributor", "royalty_distributor"],
    ["tinkerAccountEncumbrance", "tinker_account_encumbrance"],
    ["computeCreditVault", "compute_credit_vault"],
    ["emailOracleAuth", "email_oracle_auth"],
  ]) {
    sameAddress(deployed[manifestKey]?.address, candidate.contracts[candidateKey].address, `deployment history ${manifestKey}`);
    sameBytes32(
      deployed[manifestKey]?.runtimeCodeHash,
      candidate.contracts[candidateKey].runtime_code_hash,
      `deployment history ${manifestKey} runtime code hash`,
    );
  }
  const deployedDiligence = record(
    deployed.diligenceRoom,
    "deployment history DiligenceRoom",
  );
  if (
    String(deployedDiligence.resultVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(deployedDiligence.pendingResultVerifier).toLowerCase() !== ZERO_ADDRESS
    || deployedDiligence.pendingResultVerifierActivatesAt !== 0
    || deployedDiligence.resultVerifierFrozen !== false
  ) {
    throw new Error(
      "fresh deployment history must preserve the unset, unfrozen Diligence result-verifier bootstrap",
    );
  }
  const pristineTinker = validatePristineTinkerDraft(
    deployed.tinkerAccountEncumbrance,
    history,
    activeTinker,
    candidate,
  );
  validateTinkerReleaseHistory(ledger, activeTinker, pristineTinker, candidate);
  const historyAnchor = record(
    deployed.executionPolicyAnchor,
    "deployment history ExecutionPolicyAnchor",
  );
  sameAddress(
    historyAnchor.address,
    candidate.execution_policy.rollback_anchor.contract_address,
    "deployment history ExecutionPolicyAnchor",
  );
  sameBytes32(
    historyAnchor.runtimeCodeHash,
    candidate.execution_policy.rollback_anchor.runtime_code_hash,
    "deployment history ExecutionPolicyAnchor runtime code hash",
  );
  sameAddress(
    historyAnchor.owner,
    candidate.operator_address,
    "deployment history ExecutionPolicyAnchor owner",
  );
  sameBytes32(
    historyAnchor.deploymentIntentSha256Bytes32,
    sha256PinAsBytes32(
      authorityBinding.deploymentIntentSha256,
      "release authority deployment-intent digest",
    ),
    "deployment history ExecutionPolicyAnchor deployment-intent digest",
  );
  sameBytes32(
    historyAnchor.reviewerAuthorityGenesisAcceptanceSha256Bytes32,
    sha256PinAsBytes32(
      authorityBinding.reviewerAuthorityGenesisAcceptanceSha256,
      "release authority reviewer-genesis-acceptance digest",
    ),
    "deployment history ExecutionPolicyAnchor reviewer-genesis-acceptance digest",
  );
  if (
    historyAnchor.status !== "deployed_paused_writer_unset_pending_timelocked_release_binding"
    || String(historyAnchor.writer).toLowerCase() !== ZERO_ADDRESS
    || String(historyAnchor.writerReleaseCommitment).toLowerCase() !== ZERO_BYTES32
    || String(historyAnchor.pendingWriter).toLowerCase() !== ZERO_ADDRESS
    || String(historyAnchor.pendingWriterReleaseCommitment).toLowerCase() !== ZERO_BYTES32
    || historyAnchor.pendingWriterActivatesAt !== 0
    || historyAnchor.writerRotationsFrozen !== false
    || historyAnchor.paused !== true
    || historyAnchor.globalSequence !== 0
    || String(historyAnchor.globalHead).toLowerCase() !== ZERO_BYTES32
    || historyAnchor.policyState !== "anchoring_fail_closed_pending_timelocked_release_writer"
  ) {
    throw new Error("deployment history does not prove the initial ExecutionPolicyAnchor fail-closed posture");
  }
  const historyDiligence = record(deployed.diligenceRoom, "deployment history DiligenceRoom");
  if (String(historyDiligence.attestationVerifier).toLowerCase() !== ZERO_ADDRESS) {
    throw new Error(
      "deployment history initial DiligenceRoom attestation verifier must be unset",
    );
  }
  if (
    String(historyDiligence.attestationReleasePolicyHash).toLowerCase()
      !== ZERO_BYTES32
  ) {
    throw new Error(
      "deployment history initial DiligenceRoom attestation policy hash must be unset",
    );
  }
  if (
    historyDiligence.feeBps !== 100
    || historyDiligence.feeBpsFrozen !== true
    || historyDiligence.computeSettlementBps !== 100
    || historyDiligence.computeSettlementPolicyEnabled !== true
  ) {
    throw new Error("deployment history does not prove the reviewed fixed settlement policy");
  }
  if (historyDiligence.approvalRequirementsFrozen !== true) {
    throw new Error("deployment history does not prove frozen approval requirements");
  }
  if (
    historyDiligence.composeApprovalRequired !== true
    || historyDiligence.teeIdentityApprovalRequired !== true
    || historyDiligence.approvedComposeCount !== 0
    || historyDiligence.approvedTeeIdentityCount !== 0
    || historyDiligence.pendingComposeCount !== 0
    || historyDiligence.pendingTeeIdentityCount !== 0
    || String(historyDiligence.pendingAttestationVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(historyDiligence.pendingAttestationReleasePolicyHash).toLowerCase() !== ZERO_BYTES32
    || historyDiligence.pendingAttestationBindingActivatesAt !== 0
    || historyDiligence.attestationBindingFrozen !== false
    || !Array.isArray(historyDiligence.evaluatorPolicyCommitments)
    || historyDiligence.evaluatorPolicyCommitments.length !== 0
    || String(historyDiligence.evaluatorPolicySetRoot).toLowerCase() !== ZERO_BYTES32
    || historyDiligence.approvedEvaluatorPolicyCount !== 0
    || historyDiligence.pendingEvaluatorPolicyCount !== 0
    || historyDiligence.evaluatorPolicySetFrozen !== false
    || !Array.isArray(historyDiligence.pendingEvaluatorPolicyProposals)
    || historyDiligence.pendingEvaluatorPolicyProposals.length !== 0
    || historyDiligence.composeAdditionsFrozen !== false
    || historyDiligence.teeIdentityAdditionsFrozen !== false
    || historyDiligence.policyState !== "fail_closed_pending_cvm_binding"
    || !Array.isArray(historyDiligence.initialApprovedComposeHashes)
    || historyDiligence.initialApprovedComposeHashes.length !== 0
    || !Array.isArray(historyDiligence.initialApprovedTeeIdentities)
    || historyDiligence.initialApprovedTeeIdentities.length !== 0
  ) {
    throw new Error("deployment history does not prove the frozen empty-allowlist release posture");
  }
  const historyCompute = record(deployed.computeCreditVault, "deployment history ComputeCreditVault");
  sameAddress(historyCompute.owner, candidate.operator_address, "deployment history ComputeCreditVault owner");
  sameAddress(
    historyCompute.developer,
    candidate.contracts.compute_credit_vault.developer,
    "deployment history ComputeCreditVault developer",
  );
  if (
    historyCompute.status !== "deployed_paused_fee_frozen_unbound_pending_release_binding"
    || String(historyCompute.meteringVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(historyCompute.meteringQvlVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(historyCompute.meteringPolicySetHash).toLowerCase() !== ZERO_BYTES32
    || String(historyCompute.pendingMeteringVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(historyCompute.pendingMeteringQvlVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(historyCompute.pendingMeteringPolicySetHash).toLowerCase() !== ZERO_BYTES32
    || historyCompute.pendingMeteringBindingActivatesAt !== 0
    || historyCompute.meteringBindingFrozen !== false
    || historyCompute.paused !== true
    || historyCompute.developerFeeBps !== candidate.contracts.compute_credit_vault.developer_fee_bps
    || historyCompute.developerFeeFrozen !== true
    || historyCompute.allowedAssetCount !== 0
    || historyCompute.activeRatePolicyCount !== 0
    || historyCompute.approvedComposeCount !== 0
    || historyCompute.approvedTeeIdentityCount !== 0
    || historyCompute.pendingAssetCount !== 0
    || historyCompute.pendingRatePolicyCount !== 0
    || historyCompute.pendingComposeCount !== 0
    || historyCompute.pendingTeeIdentityCount !== 0
    || historyCompute.composePolicyFrozen !== false
    || historyCompute.teeIdentityAdditionsFrozen !== false
    || historyCompute.ratePolicyAdditionsFrozen !== false
    || historyCompute.assetAdditionsFrozen !== false
    || historyCompute.policyState !== "execution_fail_closed_pending_timelocked_release_binding"
  ) {
    throw new Error("deployment history does not prove the initial ComputeCreditVault fail-closed posture");
  }
  const historyEmail = record(deployed.emailOracleAuth, "deployment history EmailOracleAuth");
  sameAddress(historyEmail.owner, candidate.operator_address, "deployment history EmailOracleAuth owner");
  if (
    historyEmail.status !== "deployed_deny_all_pending_cvm_binding"
    || historyEmail.policyState !== "deny_all_pending_cvm_binding"
    || historyEmail.allowAnyDevice !== false
    || historyEmail.oracleCodeFrozen !== false
    || historyEmail.consumerRegistryFrozen !== false
  ) {
    throw new Error("deployment history does not prove the initial EmailOracleAuth deny-all posture");
  }

  const phala = record(ledger.phala, "deployment ledger phala");
  if (
    phala.cvmId !== candidate.cvm.cvm_id
    || phala.appId !== candidate.cvm.app_id
    || String(phala.composeHash).toLowerCase().replace(/^0x/, "") !== candidate.cvm.compose_hash
    || String(phala.localRawComposeImagePolicyHash).toLowerCase().replace(/^0x/, "") !== candidate.cvm.local_compose_hash
    || String(phala.renderedComposeSha256).toLowerCase().replace(/^0x/, "") !== candidate.cvm.rendered_compose_sha256
    || String(phala.osImageHash).toLowerCase().replace(/^0x/, "") !== candidate.cvm.os_image_hash
  ) {
    throw new Error("deployment ledger Phala identity does not match the release candidate");
  }
  if (phala.osIsDev !== false || phala.publicLogs !== false || phala.publicSysinfo !== false || phala.publicTcbinfo !== false) {
    throw new Error("deployment ledger still describes a dev or publicly observable CVM");
  }
  if (phala.temporaryDebugException?.active === true) {
    throw new Error("deployment ledger still has an active CVM debug exception");
  }
  if (phala.sourceDigest !== candidate.release_sha) throw new Error("Phala source digest mismatch");
  const endpoints = exactRecord(
    phala.endpoints,
    ["delegate"],
    "deployment ledger Phala endpoints",
  );
  if (httpsUrl(endpoints.delegate, "ledger delegate endpoint") !== candidate.cvm.delegate_url) {
    throw new Error("ledger delegate endpoint mismatch");
  }
  if (!Array.isArray(phala.imageDigests)) throw new Error("ledger image digests are missing");
  for (const image of candidate.cvm.images) {
    const entry = phala.imageDigests.find((item) => item?.service === image.service);
    if (
      !entry
      || entry.image !== image.image
      || entry.githubProvenanceAttestation !== "verified"
      || entry.githubSbomAttestation !== "verified"
    ) {
      throw new Error(`ledger image evidence mismatch for ${image.service}`);
    }
  }
  return anchorReleaseSnapshotBlockNumber;
}

export function validateDeploymentEvidence(value, candidate, context, _now) {
  if (!["artifact", "arena"].includes(context)) throw new Error("deployment evidence context is unsupported");
  const evidence = exactRecord(value, [
    "schema",
    "api_url",
    "context",
    "status",
    "images",
    "cvm",
    "checks",
    "claims",
  ], `${context} deployment evidence`);
  if (
    evidence.schema !== "dnai.deployment.evidence.v2"
    || evidence.context !== context
    || evidence.status !== "evidence_checked_tdx_unverified"
  ) {
    throw new Error(`${context} deployment evidence has an unsupported schema, context, or trust label`);
  }
  if (httpsUrl(evidence.api_url, `${context} evidence api_url`) !== candidate.cvm.delegate_url) {
    throw new Error(`${context} deployment evidence API endpoint mismatch`);
  }

  if (!Array.isArray(evidence.images) || evidence.images.length !== candidate.cvm.images.length) {
    throw new Error(`${context} deployment evidence image count mismatch`);
  }
  for (const [index, rawImage] of evidence.images.entries()) {
    const image = exactRecord(rawImage, [
      "image",
      "repo",
      "signer_workflow",
      "source_digest",
      "source_ref",
      "provenance_attestation",
      "sbom_attestation",
    ], `${context} deployment evidence image ${index}`);
    const candidateImage = candidate.cvm.images.find((item) => item.image === image.image);
    if (!candidateImage) throw new Error(`${context} deployment evidence contains an unpinned image`);
    for (const field of [
      "repo",
      "signer_workflow",
      "source_digest",
      "source_ref",
      "provenance_attestation",
      "sbom_attestation",
    ]) {
      if (image[field] !== candidateImage[field]) {
        throw new Error(`${context} deployment evidence image ${field} mismatch`);
      }
    }
  }

  const checks = exactRecord(evidence.checks, [
    "github_provenance_attestations",
    "github_sbom_attestations",
    "digest_pinned_compose",
    "cvm_attestation_envelope",
    "intel_tdx_quote",
    "raw_secret_egress",
  ], `${context} deployment evidence checks`);
  if (
    checks.github_provenance_attestations !== "verified_by_github_cli"
    || checks.github_sbom_attestations !== "verified_by_github_cli"
    || checks.digest_pinned_compose !== "matched_expected_inputs"
    || checks.cvm_attestation_envelope !== "matched_claimed_identity_not_cryptographically_verified"
    || checks.intel_tdx_quote !== "not_verified_no_independent_qvl_verdict"
    || checks.raw_secret_egress !== false
  ) {
    throw new Error(`${context} deployment evidence consistency checks are incomplete`);
  }
  const claims = exactRecord(evidence.claims, [
    "intel_tdx_quote_verified",
    "independent_attestation_verdict_present",
    "production_authorization_allowed",
  ], `${context} deployment evidence claims`);
  if (
    claims.intel_tdx_quote_verified !== false
    || claims.independent_attestation_verdict_present !== false
    || claims.production_authorization_allowed !== false
  ) {
    throw new Error(`${context} deployment evidence must preserve its unverified TDX trust label`);
  }

  const cvm = exactRecord(evidence.cvm, [
    "api_url",
    "context",
    "mode",
    "compose_hash",
    "attested_compose_hash",
    "rendered_compose_sha256",
    "images",
    "app_id",
    "os_image_hash",
    "report_data",
    "encryption_public_key",
    "quote_size",
    "fetched_at",
    "quote_verification",
  ], `${context} CVM deployment evidence`);
  if (
    httpsUrl(cvm.api_url, `${context} CVM api_url`) !== candidate.cvm.delegate_url
    || cvm.context !== context
    || cvm.mode !== "tdx"
    || bareBytes32(cvm.compose_hash, `${context} evidence local compose hash`) !== candidate.cvm.local_compose_hash
    || bareBytes32(cvm.attested_compose_hash, `${context} evidence attested compose hash`) !== candidate.cvm.compose_hash
    || bareBytes32(cvm.rendered_compose_sha256, `${context} evidence rendered compose hash`) !== candidate.cvm.rendered_compose_sha256
    || cvm.app_id !== candidate.cvm.app_id
    || bareBytes32(cvm.os_image_hash, `${context} evidence OS image hash`) !== candidate.cvm.os_image_hash
    || cvm.quote_verification !== "public-envelope-only; Intel TDX quote internals not parsed"
  ) {
    throw new Error(`${context} CVM deployment evidence does not match the release identity`);
  }
  const signedReportData = bytes32(
    candidate.attestations[context].verdict.report_data,
    `${context} signed verdict report data`,
  );
  if (
    bytes32(`0x${bareBytes32(cvm.report_data, `${context} evidence report data`)}`, `${context} report data`)
      !== signedReportData
  ) {
    throw new Error(`${context} deployment evidence report data does not match the independent verdict`);
  }
  bareBytes32(cvm.encryption_public_key, `${context} evidence encryption public key`);
  integer(cvm.quote_size, `${context} evidence quote size`, 632);
  if (cvm.quote_size > 16 * 1024) throw new Error(`${context} deployment evidence quote is too large`);
  const fetchedAt = integer(
    cvm.fetched_at,
    `${context} deployment evidence fetched_at`,
    1,
  );
  const appraisalIssuedAt = integer(
    candidate.attestations[context].verdict.issued_at,
    `${context} signed QVL appraisal issued_at`,
    1,
  );
  if (
    fetchedAt > appraisalIssuedAt + 300
    || fetchedAt < appraisalIssuedAt - 300
  ) {
    throw new Error(
      `${context} deployment evidence is outside its signed QVL appraisal window`,
    );
  }
  if (!Array.isArray(cvm.images) || cvm.images.length !== candidate.cvm.images.length) {
    throw new Error(`${context} CVM compose image count mismatch`);
  }
  const composeImages = new Map(cvm.images.map((entry, index) => {
    const parsed = exactRecord(entry, ["service", "image"], `${context} CVM compose image ${index}`);
    return [parsed.service, parsed.image];
  }));
  for (const image of candidate.cvm.images) {
    if (composeImages.get(image.service) !== image.image) {
      throw new Error(`${context} CVM compose image mismatch for ${image.service}`);
    }
  }
  return true;
}

function canonicalVerdictDigest(verdict) {
  const signedPayload = {
    app_id: verdict.app_id,
    ceremony_nonce: verdict.ceremony_nonce,
    chain_id: verdict.chain_id,
    challenge_digest: verdict.challenge_digest,
    challenge_expires_at: verdict.challenge_expires_at,
    challenge_id: verdict.challenge_id,
    challenge_issued_at: verdict.challenge_issued_at,
    compose_hash: verdict.compose_hash,
    contract_address: verdict.contract_address,
    cvm_id: verdict.cvm_id,
    deployment_intent_sha256: verdict.deployment_intent_sha256,
    domain: verdict.domain,
    activation_evidence_lease_expires_at:
      verdict.activation_evidence_lease_expires_at,
    expires_at: verdict.expires_at,
    issued_at: verdict.issued_at,
    measurement_policy_sha256: verdict.measurement_policy_sha256,
    os_image_hash: verdict.os_image_hash,
    profile: verdict.profile,
    quote_hash: verdict.quote_hash,
    release_policy_hash: verdict.release_policy_hash,
    report_data: verdict.report_data,
    release_authority_sha256: verdict.release_authority_sha256,
    schema: verdict.schema,
    signer_address: verdict.signer_address,
    verification_method: verdict.verification_method,
    verified: verdict.verified,
    verifier_address: verdict.verifier_address,
  };
  const sorted = Object.fromEntries(Object.entries(signedPayload).sort(([a], [b]) => a.localeCompare(b)));
  const encoded = Buffer.from(JSON.stringify(sorted), "utf8");
  return `0x${createHash("sha256").update(VERDICT_DOMAIN).update(encoded).digest("hex")}`;
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

function computeMeteringReportData(candidate) {
  const identity = candidate.trust_domains.compute_metering.identity;
  const payload = {
    schema: "dnai.compute-metering-signer-attestation.v1",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    vault_address: identity.vault_address,
    metering_verifier: identity.metering_verifier,
    policy_set_hash: identity.policy_set_hash,
    signer_custody: identity.signer_custody,
  };
  return `0x${createHash("sha256")
    .update(COMPUTE_METERING_REPORT_DATA_DOMAIN)
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function emailOracleKmsRestartBinding(candidate) {
  return candidate.trust_domains.diligence_qvl.policy_binding
    .email_oracle_kms_restart_binding;
}

function emailOracleKmsRestartReportData(candidate) {
  const payload = {
    schema: "dnai.email-oracle-kms-restart-attestation.v1",
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    main_cvm_signer: candidate.cvm.tee_identity,
    ...Object.fromEntries(
      Object.entries(emailOracleKmsRestartBinding(candidate))
        .filter(([key]) => key !== "kind"),
    ),
  };
  return `0x${createHash("sha256")
    .update(EMAIL_ORACLE_KMS_RESTART_DOMAIN)
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function executionPolicyAnchorWriterReportData(rollbackAnchor) {
  const payload = {
    schema: EXECUTION_POLICY_ANCHOR_WRITER_REPORT_DATA_SCHEMA,
    chain_id: BASE_SEPOLIA_CHAIN_ID,
    anchor_address: rollbackAnchor.contract_address,
    writer_address: rollbackAnchor.writer_address,
    writer_release_commitment: rollbackAnchor.writer_release_commitment,
    writer_key_path: EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH,
    writer_custody: EXECUTION_POLICY_ANCHOR_WRITER_CUSTODY,
  };
  return `0x${createHash("sha256")
    .update(EXECUTION_POLICY_ANCHOR_WRITER_EVIDENCE_DOMAIN)
    .update(Buffer.from(canonicalJson(payload), "ascii"))
    .digest("hex")}`;
}

function validateCanonicalSignature(value, label) {
  if (typeof value !== "string" || !/^0x[0-9a-f]{130}$/.test(value)) {
    throw new Error(`${label} must be a canonical lowercase 65-byte Ethereum signature`);
  }
  const bytes = Buffer.from(value.slice(2), "hex");
  const r = BigInt(`0x${bytes.subarray(0, 32).toString("hex")}`);
  const s = BigInt(`0x${bytes.subarray(32, 64).toString("hex")}`);
  const v = bytes[64];
  if (r < 1n || r >= SECP256K1_N || s < 1n || s > SECP256K1_N / 2n || ![27, 28].includes(v)) {
    throw new Error(`${label} must be canonical low-s ECDSA with v 27 or 28`);
  }
  return `0x${bytes.toString("hex")}`;
}

export async function validateIndependentVerdict(wrapper, candidate, expectedContract, options) {
  const verdict = wrapper.verdict;
  if (verdict.schema !== VERDICT_SCHEMA || verdict.verification_method !== VERIFICATION_METHOD || verdict.verified !== true) {
    throw new Error(`${wrapper.context} verdict is not an independently verified Intel TDX DCAP/QVL result`);
  }
  const normalized = {
    ...verdict,
    chain_id: integer(verdict.chain_id, `${wrapper.context} verdict chain_id`, 1),
    domain: nonEmptyString(verdict.domain, `${wrapper.context} verdict domain`, 64),
    cvm_id: canonicalVerdictCvmId(verdict.cvm_id, `${wrapper.context} verdict cvm_id`),
    deployment_intent_sha256: nonzeroSha256Pin(
      verdict.deployment_intent_sha256,
      `${wrapper.context} verdict deployment_intent_sha256`,
    ),
    release_authority_sha256: nonzeroSha256Pin(
      verdict.release_authority_sha256,
      `${wrapper.context} verdict release_authority_sha256`,
    ),
    ceremony_nonce: canonicalVerdictBytes32(
      verdict.ceremony_nonce,
      `${wrapper.context} verdict ceremony_nonce`,
    ),
    measurement_policy_sha256: nonzeroSha256Pin(
      verdict.measurement_policy_sha256,
      `${wrapper.context} verdict measurement_policy_sha256`,
    ),
    release_policy_hash: canonicalVerdictBytes32(
      verdict.release_policy_hash,
      `${wrapper.context} verdict release_policy_hash`,
    ),
    challenge_id: canonicalVerdictBytes32(verdict.challenge_id, `${wrapper.context} verdict challenge_id`),
    challenge_digest: canonicalVerdictBytes32(
      verdict.challenge_digest,
      `${wrapper.context} verdict challenge_digest`,
    ),
    challenge_issued_at: integer(
      verdict.challenge_issued_at,
      `${wrapper.context} verdict challenge_issued_at`,
      1,
    ),
    challenge_expires_at: integer(
      verdict.challenge_expires_at,
      `${wrapper.context} verdict challenge_expires_at`,
      1,
    ),
    quote_hash: canonicalVerdictBytes32(verdict.quote_hash, `${wrapper.context} verdict quote_hash`),
    report_data: canonicalVerdictBytes32(verdict.report_data, `${wrapper.context} verdict report_data`),
    compose_hash: canonicalVerdictBytes32(verdict.compose_hash, `${wrapper.context} verdict compose_hash`),
    app_id: canonicalVerdictAppId(verdict.app_id, `${wrapper.context} verdict app_id`),
    os_image_hash: canonicalVerdictBareBytes32(
      verdict.os_image_hash,
      `${wrapper.context} verdict os_image_hash`,
    ),
    signer_address: canonicalVerdictAddress(verdict.signer_address, `${wrapper.context} verdict signer_address`),
    contract_address: canonicalVerdictAddress(verdict.contract_address, `${wrapper.context} verdict contract_address`),
    verifier_address: canonicalVerdictAddress(verdict.verifier_address, `${wrapper.context} verdict verifier_address`),
    issued_at: integer(verdict.issued_at, `${wrapper.context} verdict issued_at`, 1),
    activation_evidence_lease_expires_at: integer(
      verdict.activation_evidence_lease_expires_at,
      `${wrapper.context} verdict activation_evidence_lease_expires_at`,
      1,
    ),
    expires_at: integer(verdict.expires_at, `${wrapper.context} verdict expires_at`, 1),
    verifier_signature: validateCanonicalSignature(verdict.verifier_signature, `${wrapper.context} verdict signature`),
  };
  const expectedProfile = options.expectedProfile || ({
    artifact: "diligence",
    arena: "arena",
    compute_metering: "compute_metering",
    anchor_writer: "execution_policy_anchor_writer",
    email_oracle_kms_restart: "email_oracle_kms_restart",
  })[wrapper.context];
  if (!expectedProfile || verdict.profile !== expectedProfile) {
    throw new Error(`${wrapper.context} verdict profile does not match its release purpose`);
  }
  const expectedDomain = options.expectedDomain || (
    wrapper.context === "compute_metering"
      ? "independent_metering_cvm"
      : "main_runtime_cvm"
  );
  if (!VERDICT_EXECUTION_DOMAINS.has(normalized.domain)
    || normalized.domain !== expectedDomain) {
    throw new Error(`${wrapper.context} verdict domain does not match its release purpose`);
  }
  if (options.expectedReleaseAuthoritySha256
    && normalized.release_authority_sha256
      !== nonzeroSha256Pin(
        options.expectedReleaseAuthoritySha256,
        `${wrapper.context} expected release authority`,
      )) {
    throw new Error(`${wrapper.context} verdict release authority does not match the canonical ceremony`);
  }
  if (options.expectedCeremonyNonce
    && normalized.ceremony_nonce
      !== canonicalVerdictBytes32(
        options.expectedCeremonyNonce,
        `${wrapper.context} expected ceremony nonce`,
      )) {
    throw new Error(`${wrapper.context} verdict ceremony nonce does not match the canonical ceremony`);
  }
  if (options.expectedMeasurementPolicySha256
    && normalized.measurement_policy_sha256
      !== nonzeroSha256Pin(
        options.expectedMeasurementPolicySha256,
        `${wrapper.context} expected measurement policy`,
      )) {
    throw new Error(`${wrapper.context} verdict measurement policy does not match the canonical QVL authority`);
  }
  const now = integer(options.now, "release clock", 1);
  if (normalized.challenge_issued_at > now + 5 || normalized.issued_at > now + 5) {
    throw new Error(`${wrapper.context} verdict or challenge is future-dated`);
  }
  if (normalized.activation_evidence_lease_expires_at <= now) {
    throw new Error(`${wrapper.context} verdict activation evidence lease is expired`);
  }
  if (
    normalized.challenge_expires_at <= normalized.challenge_issued_at
    || normalized.challenge_expires_at - normalized.challenge_issued_at > 120
    || normalized.issued_at < normalized.challenge_issued_at
    || normalized.issued_at >= normalized.challenge_expires_at
    || normalized.activation_evidence_lease_expires_at !== normalized.expires_at
    || normalized.expires_at <= normalized.issued_at
    || normalized.expires_at - normalized.issued_at
      > MAX_ACTIVATION_EVIDENCE_LEASE_SECONDS
  ) {
    throw new Error(`${wrapper.context} verdict challenge or activation evidence lease is invalid`);
  }
  if (wrapper.quote_sha256 !== `sha256:${normalized.quote_hash.slice(2)}`) {
    throw new Error(`${wrapper.context} quote pin does not match the signed verdict`);
  }
  const expectedCvm = options.expectedCvm || candidate.cvm;
  if (
    normalized.compose_hash !== `0x${expectedCvm.compose_hash}`
    || normalized.app_id !== expectedCvm.app_id
    || normalized.cvm_id !== expectedCvm.cvm_id
    || normalized.os_image_hash !== expectedCvm.os_image_hash
    || normalized.signer_address
      !== (options.expectedSignerAddress || candidate.cvm.tee_identity)
    || normalized.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || normalized.deployment_intent_sha256 !== candidate.deployment_intent_sha256
    || normalized.contract_address !== expectedContract
  ) {
    throw new Error(`${wrapper.context} verdict is not bound to this CVM, chain, and contract`);
  }
  const qvlDomainKey = options.qvlDomainKey || ({
    artifact: "diligence_qvl",
    arena: "arena_qvl",
    compute_metering: "compute_metering_qvl",
    anchor_writer: "anchor_writer_qvl",
    email_oracle_kms_restart: "diligence_qvl",
  })[wrapper.context];
  const qvlDomain = candidate.trust_domains[qvlDomainKey];
  if (!qvlDomain || !qvlDomain.identity?.release_policy_hash) {
    throw new Error(`${wrapper.context} verdict has no release-pinned independent QVL domain`);
  }
  if (normalized.release_policy_hash !== qvlDomain.identity.release_policy_hash) {
    throw new Error(`${wrapper.context} verdict release-policy hash does not match its QVL root`);
  }
  if (normalized.verifier_address !== qvlDomain.identity.verifier_address) {
    throw new Error(
      `${wrapper.context} verdict signer does not match its full release-pinned QVL CVM descriptor`,
    );
  }
  const trusted = new Set((options.trustedVerifierAddresses || []).map((item) => address(item, "trusted verifier")));
  if (!trusted.size || !trusted.has(normalized.verifier_address)) {
    throw new Error(`${wrapper.context} verdict signer is not in the external trusted-verifier policy`);
  }
  const forbidden = new Set([
    candidate.operator_address,
    candidate.cvm.tee_identity,
    candidate.contracts.diligence_room.result_verifier,
    candidate.contracts.compute_credit_vault.developer,
    candidate.trust_domains.compute_metering.identity.metering_verifier,
    candidate.execution_policy.rollback_anchor.writer_address,
  ]);
  if (forbidden.has(normalized.verifier_address)) {
    throw new Error(`${wrapper.context} attestation verifier is not an independent trust root`);
  }
  const digest = canonicalVerdictDigest(normalized);
  let recovered;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: digest },
      signature: normalized.verifier_signature,
    });
  } catch {
    throw new Error(`${wrapper.context} verdict signature cannot be recovered`);
  }
  if (address(recovered, `${wrapper.context} recovered verifier`) !== normalized.verifier_address) {
    throw new Error(`${wrapper.context} verdict signature is not authenticated`);
  }
  return normalized;
}

function validateExternalTrustedVerifierSet(candidate, values) {
  if (!Array.isArray(values)) {
    throw new Error("external trusted-verifier policy must be an address list");
  }
  const normalized = values.map((item) => address(item, "trusted verifier"));
  if (normalized.length !== 5 || new Set(normalized).size !== 5) {
    throw new Error(
      "external trusted-verifier policy must contain exactly five distinct QVL roots",
    );
  }
  const expected = new Set([
    candidate.trust_domains.diligence_qvl.identity.verifier_address,
    candidate.trust_domains.arena_qvl.identity.verifier_address,
    candidate.trust_domains.anchor_writer_qvl.identity.verifier_address,
    candidate.trust_domains.compute_metering_qvl.identity.verifier_address,
    candidate.trust_domains.compute_workload_qvl.identity.verifier_address,
  ]);
  if (normalized.some((root) => !expected.has(root))) {
    throw new Error(
      "external trusted-verifier policy must equal all five release-pinned purpose-separated QVL roots",
    );
  }
  return normalized;
}

async function validateAnchorWriterEvidence(
  value,
  rawBytes,
  candidate,
  {
    now,
    trustedVerifierAddresses,
    expectedReleaseAuthoritySha256,
    expectedCeremonyNonce,
  },
) {
  const artifact = exactRecord(value, [
    "schema",
    "status",
    "chain_id",
    "anchor_address",
    "writer_address",
    "writer_release_commitment",
    "writer_key_path",
    "writer_key_path_sha256",
    "writer_custody",
    "app_id",
    "compose_hash",
    "os_image_hash",
    "report_data",
    "quote_report_data",
    "quote_sha256",
    "quote_size",
    "qvl_release_policy_hash",
    "qvl_verifier_address",
    "qvl_verdict",
    "verification_method",
    "tdx_measurement_policy",
    "raw_quote_egress",
    "raw_quote_in_artifact",
    "raw_private_key_egress",
  ], "execution-policy anchor writer evidence");
  if (
    !Buffer.isBuffer(rawBytes)
    || rawBytes.length < 2
    || rawBytes.length > 64 * 1024
  ) {
    throw new Error("execution-policy anchor writer evidence bytes are required and bounded");
  }
  const canonicalBytes = Buffer.from(`${canonicalJson(artifact)}\n`, "ascii");
  if (!rawBytes.equals(canonicalBytes)) {
    throw new Error("execution-policy anchor writer evidence must be exact canonical JSON bytes");
  }
  const artifactHash = `sha256:${createHash("sha256").update(rawBytes).digest("hex")}`;
  const rollbackAnchor = candidate.execution_policy.rollback_anchor;
  if (artifactHash !== rollbackAnchor.evidence_sha256) {
    throw new Error("execution-policy anchor writer evidence hash does not match the release descriptor");
  }
  if (
    artifact.schema !== EXECUTION_POLICY_ANCHOR_WRITER_EVIDENCE_SCHEMA
    || artifact.status !== "independent_qvl_verified"
    || artifact.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || address(artifact.anchor_address, "anchor writer evidence anchor")
      !== rollbackAnchor.contract_address
    || address(artifact.writer_address, "anchor writer evidence writer")
      !== rollbackAnchor.writer_address
    || bytes32(
      artifact.writer_release_commitment,
      "anchor writer evidence release commitment",
    ) !== rollbackAnchor.writer_release_commitment
    || artifact.writer_key_path !== EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH
    || artifact.writer_custody !== EXECUTION_POLICY_ANCHOR_WRITER_CUSTODY
    || artifact.app_id !== candidate.cvm.app_id
    || bytes32(artifact.compose_hash, "anchor writer evidence compose hash")
      !== `0x${candidate.cvm.compose_hash}`
    || bareBytes32(artifact.os_image_hash, "anchor writer evidence OS image hash")
      !== candidate.cvm.os_image_hash
    || artifact.verification_method !== VERIFICATION_METHOD
    || artifact.tdx_measurement_policy !== "exact_release_pinned_measurements"
    || artifact.raw_quote_egress !== "authenticated_https_qvl_only"
    || artifact.raw_quote_in_artifact !== false
    || artifact.raw_private_key_egress !== false
  ) {
    throw new Error("execution-policy anchor writer evidence does not match the exact release binding");
  }
  const expectedKeyPathHash = sha256Hex(Buffer.concat([
    EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH_DOMAIN,
    Buffer.from(EXECUTION_POLICY_ANCHOR_WRITER_KEY_PATH, "ascii"),
  ]));
  if (
    bareBytes32(
      artifact.writer_key_path_sha256,
      "anchor writer evidence key-path hash",
    ) !== expectedKeyPathHash
  ) {
    throw new Error("execution-policy anchor writer key-path commitment mismatch");
  }
  const reportData = bytes32(artifact.report_data, "anchor writer evidence report data");
  if (
    reportData !== executionPolicyAnchorWriterReportData(rollbackAnchor)
    || typeof artifact.quote_report_data !== "string"
    || artifact.quote_report_data.toLowerCase()
      !== `${reportData}${artifact.qvl_verdict.challenge_digest.slice(2)}`
  ) {
    throw new Error("execution-policy anchor writer report-data binding mismatch");
  }
  const quotePin = sha256Pin(artifact.quote_sha256, "anchor writer evidence quote hash");
  const quoteSize = integer(artifact.quote_size, "anchor writer evidence quote size", 1_024);
  if (quoteSize > 16 * 1024) {
    throw new Error("execution-policy anchor writer quote size exceeds the QVL bound");
  }
  const qvlDomain = candidate.trust_domains.anchor_writer_qvl;
  if (
    bytes32(
      artifact.qvl_release_policy_hash,
      "anchor writer evidence QVL policy hash",
    ) !== qvlDomain.identity.release_policy_hash
    || address(
      artifact.qvl_verifier_address,
      "anchor writer evidence QVL verifier",
    ) !== qvlDomain.identity.verifier_address
  ) {
    throw new Error("execution-policy anchor writer evidence QVL root mismatch");
  }
  const wrapper = normalizeVerdictWrapper({
    context: "anchor_writer",
    quote_sha256: quotePin,
    verdict: artifact.qvl_verdict,
  }, "anchor_writer");
  if (
    bytes32(wrapper.verdict.report_data, "anchor writer verdict report data")
      !== reportData
    || address(wrapper.verdict.verifier_address, "anchor writer verdict verifier")
      !== qvlDomain.identity.verifier_address
  ) {
    throw new Error("execution-policy anchor writer verdict wrapper mismatch");
  }
  await validateIndependentVerdict(
    wrapper,
    candidate,
    rollbackAnchor.contract_address,
    {
      now,
      trustedVerifierAddresses,
      qvlDomainKey: "anchor_writer_qvl",
      expectedSignerAddress: rollbackAnchor.writer_address,
      expectedReleaseAuthoritySha256,
      expectedCeremonyNonce,
    },
  );
  return true;
}

export async function validateEmailOracleEvidence(
  value,
  rawBytes,
  candidate,
  {
    now,
    trustedVerifierAddresses,
    expectedReleaseAuthoritySha256,
    expectedCeremonyNonce,
  },
) {
  const artifact = exactRecord(value, [
    "schema",
    "status",
    "chain_id",
    "release_sha",
    "email_oracle_auth",
    "main_cvm",
    "kms",
    "registration",
    "target_boot",
    "restart_key_derivation",
    "qvl_verification",
  ], "Email oracle external evidence");
  if (!Buffer.isBuffer(rawBytes) || rawBytes.length < 2 || rawBytes.length > 64 * 1024) {
    throw new Error("Email oracle external evidence bytes are required and bounded");
  }
  const canonicalBytes = Buffer.from(`${canonicalJson(artifact)}\n`, "utf8");
  if (!rawBytes.equals(canonicalBytes)) {
    throw new Error("Email oracle external evidence must be exact canonical JSON bytes");
  }
  const email = candidate.contracts.email_oracle_auth;
  const release = email.release;
  const artifactHash = `0x${createHash("sha256").update(rawBytes).digest("hex")}`;
  if (artifactHash !== release.external_evidence_sha256) {
    throw new Error("Email oracle external evidence hash does not match the release descriptor");
  }
  if (
    artifact.schema !== EMAIL_ORACLE_EXTERNAL_EVIDENCE_SCHEMA
    || artifact.status !== "external_evidence_verified"
    || artifact.chain_id !== BASE_SEPOLIA_CHAIN_ID
    || artifact.release_sha !== candidate.release_sha
    || address(artifact.email_oracle_auth, "Email evidence auth contract") !== email.address
  ) {
    throw new Error("Email oracle external evidence does not match the release identity");
  }

  const mainCvm = exactRecord(artifact.main_cvm, [
    "compose_hash",
    "consumer_app_id",
    "cvm_id",
    "device_id",
  ], "Email evidence main_cvm");
  if (
    nonEmptyString(mainCvm.cvm_id, "Email evidence main CVM id", 160) !== candidate.cvm.cvm_id
    || bytes32(mainCvm.compose_hash, "Email evidence main CVM compose hash")
      !== `0x${candidate.cvm.compose_hash}`
    || address(mainCvm.consumer_app_id, "Email evidence consumer app")
      !== email.consumer_address
    || bytes32(mainCvm.device_id, "Email evidence device id") !== release.device_id
  ) {
    throw new Error("Email oracle evidence main CVM binding mismatch");
  }

  const kms = exactRecord(artifact.kms, [
    "contract_address",
    "implementation_address",
    "implementation_runtime_code_hash",
    "kms_eip1967_implementation_slot_word",
    "runtime_code_hash",
    "source_commit",
    "source_repository",
    "verification_status",
    "verification_url",
  ], "Email evidence KMS");
  if (
    address(kms.contract_address, "Email evidence KMS contract")
      !== release.kms_contract_address
    || bytes32(kms.runtime_code_hash, "Email evidence KMS runtime hash")
      !== release.kms_runtime_code_hash
    || address(kms.implementation_address, "Email evidence KMS implementation")
      !== release.kms_implementation_address
    || bytes32(
      kms.implementation_runtime_code_hash,
      "Email evidence KMS implementation runtime hash",
    ) !== release.kms_implementation_runtime_code_hash
    || bytes32(
      kms.kms_eip1967_implementation_slot_word,
      "Email evidence KMS EIP-1967 implementation slot word",
    ) !== `0x${"0".repeat(24)}${release.kms_implementation_address.slice(2)}`
    || kms.source_repository !== "https://github.com/Dstack-TEE/dstack"
    || kms.verification_status !== "verified_source_and_runtime"
  ) {
    throw new Error("Email oracle evidence KMS source/runtime binding mismatch");
  }
  releaseSha(kms.source_commit, "Email evidence Dstack source commit");
  httpsUrl(kms.verification_url, "Email evidence KMS verification URL");

  const registration = exactRecord(artifact.registration, [
    "block_hash",
    "block_number",
    "registered_apps_readback",
    "transaction_hash",
  ], "Email evidence KMS registration");
  if (
    bytes32(registration.transaction_hash, "Email evidence registration transaction")
      !== release.kms_registration_tx_hash
    || integer(registration.block_number, "Email evidence registration block", 1)
      !== release.kms_registration_block
    || bytes32(registration.block_hash, "Email evidence registration block hash")
      !== release.kms_registration_block_hash
    || registration.registered_apps_readback !== true
  ) {
    throw new Error("Email oracle evidence KMS registration binding mismatch");
  }

  const boot = exactRecord(artifact.target_boot, [
    "advisory_ids",
    "instance_id",
    "kms_is_app_allowed",
    "mr_aggregated",
    "mr_system",
    "os_image_hash",
    "tcb_status",
  ], "Email evidence target boot");
  if (
    address(boot.instance_id, "Email evidence target boot instance")
      !== release.target_boot.instance_id
    || bytes32(boot.mr_aggregated, "Email evidence target boot mr_aggregated")
      !== release.target_boot.mr_aggregated
    || bytes32(boot.mr_system, "Email evidence target boot mr_system")
      !== release.target_boot.mr_system
    || bytes32(boot.os_image_hash, "Email evidence target boot OS image")
      !== release.target_boot.os_image_hash
    || boot.tcb_status !== "UpToDate"
    || !Array.isArray(boot.advisory_ids)
    || boot.advisory_ids.length !== 0
    || boot.kms_is_app_allowed !== true
  ) {
    throw new Error("Email oracle evidence target boot mismatch");
  }

  const restart = exactRecord(artifact.restart_key_derivation, [
    "derive_key_succeeded_after",
    "derive_key_succeeded_before",
    "key_path",
    "post_restart_commitment",
    "pre_restart_commitment",
    "raw_key_egress",
    "raw_secret_egress",
    "restart_proof_hash",
    "restart_observed",
    "status",
  ], "Email evidence restart key derivation");
  const preRestartCommitment = bytes32(
    restart.pre_restart_commitment,
    "Email evidence pre-restart key commitment",
  );
  if (
    restart.status !== "verified_after_real_cvm_restart"
    || restart.key_path !== "email/creds"
    || restart.restart_observed !== true
    || restart.derive_key_succeeded_before !== true
    || restart.derive_key_succeeded_after !== true
    || restart.raw_key_egress !== false
    || restart.raw_secret_egress !== false
    || bytes32(
      restart.restart_proof_hash,
      "Email evidence restart proof hash",
    ) !== release.restart_key_derivation_proof_hash
    || bytes32(
      restart.post_restart_commitment,
      "Email evidence post-restart key commitment",
    ) !== preRestartCommitment
  ) {
    throw new Error("Email oracle evidence does not prove bounded key continuity across a real CVM restart");
  }

  const qvl = exactRecord(artifact.qvl_verification, [
    "qvl_release_policy_hash",
    "qvl_verdict",
    "qvl_verifier_address",
    "quote_sha256",
    "status",
    "verification_method",
  ], "Email evidence QVL verification");
  if (
    qvl.status !== "independent_qvl_verified"
    || qvl.verification_method !== VERIFICATION_METHOD
    || bytes32(
      qvl.qvl_release_policy_hash,
      "Email evidence QVL policy hash",
    ) !== candidate.trust_domains.diligence_qvl.identity.release_policy_hash
    || address(
      qvl.qvl_verifier_address,
      "Email evidence QVL verifier",
    ) !== candidate.trust_domains.diligence_qvl.identity.verifier_address
  ) {
    throw new Error("Email oracle external evidence QVL status is not verified");
  }
  const wrapper = normalizeVerdictWrapper({
    context: "email_oracle_kms_restart",
    quote_sha256: sha256Pin(qvl.quote_sha256, "Email evidence quote hash"),
    verdict: qvl.qvl_verdict,
  }, "email_oracle_kms_restart");
  if (
    bytes32(wrapper.verdict.report_data, "Email evidence QVL report data")
      !== emailOracleKmsRestartReportData(candidate)
  ) {
    throw new Error("Email oracle QVL verdict does not bind the exact KMS/restart tuple");
  }
  await validateIndependentVerdict(
    wrapper,
    candidate,
    candidate.contracts.diligence_room.address,
    {
      now,
      trustedVerifierAddresses,
      qvlDomainKey: "diligence_qvl",
      expectedProfile: "email_oracle_kms_restart",
      expectedSignerAddress: candidate.cvm.tee_identity,
      expectedReleaseAuthoritySha256,
      expectedCeremonyNonce,
    },
  );
  return true;
}

async function read(client, contract, abi, functionName, args, blockNumber) {
  return client.readContract({
    address: contract,
    abi,
    functionName,
    args: args ?? [],
    blockNumber,
  });
}

async function validateLiveEmailOracle(candidate, client, blockNumber) {
  const email = candidate.contracts.email_oracle_auth;
  const release = email.release;
  const compose = `0x${candidate.cvm.compose_hash}`;
  const consumer = email.consumer_address;
  const targetBootInfo = emailOracleTargetBootInfo(email, candidate.cvm);
  const registrationBlock = BigInt(release.kms_registration_block);
  if (registrationBlock >= blockNumber) {
    throw new Error("EmailOracleAuth KMS registration must precede the release-pinned snapshot");
  }

  const [
    emailOwner,
    emailPendingOwner,
    emailUpgradeDelay,
    allowAnyDevice,
    oracleCodeFrozen,
    consumerRegistryFrozen,
    consumerManagerAdditionsFrozen,
    kmsBindingFrozen,
    allowedOracleComposeHashCount,
    pendingOracleComposeHashCount,
    allowedDeviceIdCount,
    consumerManagerCount,
    totalConsumerComposeHashCount,
    releaseOracleComposeHash,
    releaseDeviceId,
    releaseConsumerManager,
    releaseConsumerAppId,
    releaseConsumerComposeHash,
    oracleComposeApproved,
    deviceApproved,
    consumerManagerApproved,
    consumerEmergencyRevoked,
    consumerComposeHashCount,
    consumerAuthorized,
    kmsContract,
    kmsRuntimeCodeHash,
    kmsImplementation,
    kmsImplementationRuntimeCodeHash,
    kmsRegistrationTxHash,
    kmsRegistrationBlock,
    kmsRegistrationBlockHash,
    targetBootInfoHash,
    restartKeyDerivationProofHash,
    pendingKmsContract,
    pendingKmsRuntimeCodeHash,
    pendingKmsImplementation,
    pendingKmsImplementationRuntimeCodeHash,
    pendingKmsRegistrationTxHash,
    pendingKmsRegistrationBlock,
    pendingKmsRegistrationBlockHash,
    pendingTargetBootInfoHash,
    pendingRestartKeyDerivationProofHash,
    pendingKmsBindingActivatesAt,
    releaseConfigurationReady,
    kmsRegisteredApps,
    kmsBootAuthorization,
    kmsProxyCode,
    kmsImplementationCode,
    kmsImplementationSlot,
    registrationReceipt,
    registrationTransaction,
    registrationBlockHeader,
  ] = await Promise.all([
    read(client, email.address, EMAIL_ORACLE_ABI, "owner", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingOwner", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "ORACLE_UPGRADE_DELAY", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "allowAnyDevice", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "oracleCodeFrozen", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerRegistryFrozen", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerManagerAdditionsFrozen", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsBindingFrozen", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "allowedOracleComposeHashCount", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingOracleComposeHashCount", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "allowedDeviceIdCount", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerManagerCount", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "totalConsumerComposeHashCount", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseOracleComposeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseDeviceId", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseConsumerManager", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseConsumerAppId", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseConsumerComposeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "allowedOracleComposeHashes", [compose], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "allowedDeviceIds", [release.device_id], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerManagers", [consumer], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerEmergencyRevoked", [consumer], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "consumerComposeHashCount", [consumer], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "isConsumerAuthorized", [consumer, compose], blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsContract", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsRuntimeCodeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsImplementation", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsImplementationRuntimeCodeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsRegistrationTxHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsRegistrationBlock", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "kmsRegistrationBlockHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "targetBootInfoHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "restartKeyDerivationProofHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsContract", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsRuntimeCodeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsImplementation", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsImplementationRuntimeCodeHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsRegistrationTxHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsRegistrationBlock", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsRegistrationBlockHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingTargetBootInfoHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingRestartKeyDerivationProofHash", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "pendingKmsBindingActivatesAt", undefined, blockNumber),
    read(client, email.address, EMAIL_ORACLE_ABI, "releaseConfigurationReady", undefined, blockNumber),
    read(client, release.kms_contract_address, DSTACK_KMS_ABI, "registeredApps", [email.address], blockNumber),
    read(client, release.kms_contract_address, DSTACK_KMS_ABI, "isAppAllowed", [targetBootInfo], blockNumber),
    client.getBytecode({ address: release.kms_contract_address, blockNumber }),
    client.getBytecode({ address: release.kms_implementation_address, blockNumber }),
    client.getStorageAt({
      address: release.kms_contract_address,
      slot: EIP1967_IMPLEMENTATION_SLOT,
      blockNumber,
    }),
    client.getTransactionReceipt({ hash: release.kms_registration_tx_hash }),
    client.getTransaction({ hash: release.kms_registration_tx_hash }),
    client.getBlock({ blockNumber: registrationBlock }),
  ]);

  sameAddress(emailOwner, email.owner, "live EmailOracleAuth owner");
  if (String(emailPendingOwner).toLowerCase() !== ZERO_ADDRESS) {
    throw new Error("live EmailOracleAuth has a pending owner");
  }
  if (BigInt(emailUpgradeDelay) !== BigInt(email.upgrade_delay_seconds)) {
    throw new Error("live EmailOracleAuth upgrade delay does not match the release pin");
  }
  if (
    allowAnyDevice !== false
    || oracleCodeFrozen !== true
    || consumerRegistryFrozen !== true
    || consumerManagerAdditionsFrozen !== true
    || kmsBindingFrozen !== true
    || BigInt(allowedOracleComposeHashCount) !== 1n
    || BigInt(pendingOracleComposeHashCount) !== 0n
    || BigInt(allowedDeviceIdCount) !== 1n
    || BigInt(consumerManagerCount) !== 1n
    || BigInt(totalConsumerComposeHashCount) !== 1n
    || oracleComposeApproved !== true
    || deviceApproved !== true
    || consumerManagerApproved !== true
    || consumerEmergencyRevoked !== false
    || BigInt(consumerComposeHashCount) !== 1n
    || consumerAuthorized !== true
    || releaseConfigurationReady !== true
  ) {
    throw new Error(
      "live EmailOracleAuth is not the exact enumerable, permanently frozen, release-ready policy",
    );
  }
  sameBytes32(releaseOracleComposeHash, compose, "live EmailOracleAuth release oracle compose");
  sameBytes32(releaseDeviceId, release.device_id, "live EmailOracleAuth release device");
  sameAddress(releaseConsumerManager, consumer, "live EmailOracleAuth release consumer manager");
  sameAddress(releaseConsumerAppId, consumer, "live EmailOracleAuth release consumer app");
  sameBytes32(releaseConsumerComposeHash, compose, "live EmailOracleAuth release consumer compose");

  sameAddress(kmsContract, release.kms_contract_address, "live EmailOracleAuth KMS contract");
  sameBytes32(kmsRuntimeCodeHash, release.kms_runtime_code_hash, "live EmailOracleAuth KMS runtime hash");
  sameAddress(
    kmsImplementation,
    release.kms_implementation_address,
    "live EmailOracleAuth KMS implementation",
  );
  sameBytes32(
    kmsImplementationRuntimeCodeHash,
    release.kms_implementation_runtime_code_hash,
    "live EmailOracleAuth KMS implementation runtime hash",
  );
  sameBytes32(kmsRegistrationTxHash, release.kms_registration_tx_hash, "live EmailOracleAuth KMS registration transaction");
  if (BigInt(kmsRegistrationBlock) !== registrationBlock) {
    throw new Error("live EmailOracleAuth KMS registration block mismatch");
  }
  sameBytes32(kmsRegistrationBlockHash, release.kms_registration_block_hash, "live EmailOracleAuth KMS registration block hash");
  sameBytes32(targetBootInfoHash, release.target_boot.info_hash, "live EmailOracleAuth target boot info hash");
  sameBytes32(
    restartKeyDerivationProofHash,
    release.restart_key_derivation_proof_hash,
    "live EmailOracleAuth restart key-derivation proof hash",
  );
  if (
    String(pendingKmsContract).toLowerCase() !== ZERO_ADDRESS
    || String(pendingKmsRuntimeCodeHash).toLowerCase() !== ZERO_BYTES32
    || String(pendingKmsImplementation).toLowerCase() !== ZERO_ADDRESS
    || String(pendingKmsImplementationRuntimeCodeHash).toLowerCase() !== ZERO_BYTES32
    || String(pendingKmsRegistrationTxHash).toLowerCase() !== ZERO_BYTES32
    || BigInt(pendingKmsRegistrationBlock) !== 0n
    || String(pendingKmsRegistrationBlockHash).toLowerCase() !== ZERO_BYTES32
    || String(pendingTargetBootInfoHash).toLowerCase() !== ZERO_BYTES32
    || String(pendingRestartKeyDerivationProofHash).toLowerCase() !== ZERO_BYTES32
    || BigInt(pendingKmsBindingActivatesAt) !== 0n
  ) {
    throw new Error("live EmailOracleAuth has a pending KMS binding");
  }

  if (!kmsProxyCode || kmsProxyCode === "0x" || keccak256(kmsProxyCode).toLowerCase() !== release.kms_runtime_code_hash) {
    throw new Error("live Dstack KMS proxy runtime bytecode hash does not match the release pin");
  }
  if (
    !kmsImplementationCode
    || kmsImplementationCode === "0x"
    || keccak256(kmsImplementationCode).toLowerCase()
      !== release.kms_implementation_runtime_code_hash
  ) {
    throw new Error("live Dstack KMS implementation runtime bytecode hash does not match the release pin");
  }
  const expectedImplementationSlot = `0x${"0".repeat(24)}${release.kms_implementation_address.slice(2)}`;
  if (String(kmsImplementationSlot).toLowerCase() !== expectedImplementationSlot) {
    throw new Error("live Dstack KMS EIP-1967 implementation slot mismatch");
  }
  const kmsAllowed = Array.isArray(kmsBootAuthorization)
    ? kmsBootAuthorization[0]
    : kmsBootAuthorization?.isAllowed;
  const kmsReason = Array.isArray(kmsBootAuthorization)
    ? kmsBootAuthorization[1]
    : kmsBootAuthorization?.reason;
  if (kmsRegisteredApps !== true || kmsAllowed !== true || kmsReason !== "") {
    throw new Error("live Dstack KMS registration/readback does not authorize the exact target boot tuple");
  }

  if (
    registrationReceipt?.status !== "success"
    || address(registrationReceipt?.to, "KMS registration receipt target")
      !== release.kms_contract_address
    || bytes32(
      String(registrationReceipt?.transactionHash),
      "KMS registration receipt transaction hash",
    ) !== release.kms_registration_tx_hash
    || BigInt(registrationReceipt?.blockNumber) !== registrationBlock
    || bytes32(String(registrationReceipt?.blockHash), "KMS registration receipt block hash")
      !== release.kms_registration_block_hash
  ) {
    throw new Error("Dstack KMS registration receipt does not match the release binding");
  }
  const expectedRegistrationInput = encodeFunctionData({
    abi: DSTACK_KMS_ABI,
    functionName: "registerApp",
    args: [email.address],
  }).toLowerCase();
  if (
    address(registrationTransaction?.to, "KMS registration transaction target")
      !== release.kms_contract_address
    || bytes32(
      String(registrationTransaction?.hash),
      "KMS registration transaction hash",
    ) !== release.kms_registration_tx_hash
    || BigInt(registrationTransaction?.blockNumber) !== registrationBlock
    || String(registrationTransaction?.input).toLowerCase() !== expectedRegistrationInput
  ) {
    throw new Error("Dstack KMS registration transaction is not exact registerApp(EmailOracleAuth)");
  }
  if (
    BigInt(registrationBlockHeader?.number) !== registrationBlock
    || bytes32(String(registrationBlockHeader?.hash), "KMS registration canonical block hash")
      !== release.kms_registration_block_hash
  ) {
    throw new Error("Dstack KMS registration block hash is not canonical");
  }
  const registrationLogs = Array.isArray(registrationReceipt?.logs)
    ? registrationReceipt.logs.filter((log) => (
      String(log?.address).toLowerCase() === release.kms_contract_address
      && String(log?.topics?.[0]).toLowerCase() === APP_REGISTERED_TOPIC
    ))
    : [];
  const expectedRegistrationData = encodeAbiParameters(
    [{ type: "address" }],
    [email.address],
  ).toLowerCase();
  if (
    registrationLogs.length !== 1
    || registrationLogs[0].topics.length !== 1
    || String(registrationLogs[0].data).toLowerCase() !== expectedRegistrationData
  ) {
    throw new Error("Dstack KMS registration receipt lacks the exact AppRegistered(EmailOracleAuth) log");
  }
}

export async function validateLiveChain(
  candidate,
  client,
  releaseSnapshotBlockNumber,
  now,
  authorityBindingValue,
) {
  const authorityBinding = normalizeReleaseAuthorityBinding(authorityBindingValue);
  const chainId = await client.getChainId();
  if (chainId !== BASE_SEPOLIA_CHAIN_ID) throw new Error(`RPC reports chain ${chainId}, expected Base Sepolia`);
  const latestBlockNumber = await client.getBlockNumber();
  if (typeof latestBlockNumber !== "bigint" || latestBlockNumber < 1n) {
    throw new Error("RPC did not return a valid Base Sepolia head block");
  }
  if (
    !Number.isSafeInteger(releaseSnapshotBlockNumber)
    || releaseSnapshotBlockNumber < 1
  ) {
    throw new Error("deployment ledger does not contain a valid release snapshot block");
  }
  const blockNumber = BigInt(releaseSnapshotBlockNumber);
  const confirmationDepthBlockNumber = latestBlockNumber
    - BigInt(candidate.execution_policy.rollback_anchor.confirmations)
    + 1n;
  if (confirmationDepthBlockNumber < 1n) {
    throw new Error("RPC head does not satisfy the release confirmation depth");
  }
  const rpcFinalizedBlock = await client.getBlock({ blockTag: "finalized" });
  if (!rpcFinalizedBlock || typeof rpcFinalizedBlock.number !== "bigint") {
    throw new Error("RPC did not return a numbered Base Sepolia finalized-tag block");
  }
  const rpcFinalizedBlockNumber = rpcFinalizedBlock.number;
  if (rpcFinalizedBlockNumber < 1n || rpcFinalizedBlockNumber > latestBlockNumber) {
    throw new Error("RPC returned an invalid Base Sepolia finalized-tag block number");
  }
  const rpcFinalizedBlockHash = bytes32(
    String(rpcFinalizedBlock.hash),
    "RPC Base Sepolia finalized-tag block hash",
  );
  const chosenBlockNumber = rpcFinalizedBlockNumber < confirmationDepthBlockNumber
    ? rpcFinalizedBlockNumber
    : confirmationDepthBlockNumber;
  if (blockNumber !== chosenBlockNumber) {
    throw new Error("single-RPC finalized/depth snapshot does not match the release-pinned ledger block");
  }
  if (!Number.isSafeInteger(now) || now < 1) {
    throw new Error("release validation time is invalid");
  }
  const snapshotBlock = await client.getBlock({ blockNumber });
  if (!snapshotBlock || BigInt(snapshotBlock.number) !== blockNumber) {
    throw new Error("RPC did not return the release-pinned Base Sepolia block");
  }
  const snapshotBlockHash = bytes32(
    String(snapshotBlock.hash),
    "release-pinned Base Sepolia block hash",
  );
  const snapshotTimestamp = BigInt(snapshotBlock.timestamp);
  const nowSeconds = BigInt(now);
  if (
    snapshotTimestamp
      > nowSeconds
        + BigInt(candidate.execution_policy.rollback_anchor.max_future_block_skew_seconds)
    || nowSeconds - snapshotTimestamp
      > BigInt(candidate.execution_policy.rollback_anchor.max_block_age_seconds)
  ) {
    throw new Error("release-pinned Base Sepolia block is stale or future-dated");
  }
  for (const key of CONTRACT_KEYS) {
    const contract = candidate.contracts[key];
    const code = await client.getBytecode({ address: contract.address, blockNumber });
    if (!code || code === "0x") throw new Error(`${key} has no runtime bytecode`);
    if (keccak256(code).toLowerCase() !== contract.runtime_code_hash) {
      throw new Error(`${key} runtime bytecode hash does not match the release pin`);
    }
  }
  const rollbackAnchor = candidate.execution_policy.rollback_anchor;
  const rollbackAnchorCode = await client.getBytecode({
    address: rollbackAnchor.contract_address,
    blockNumber,
  });
  if (!rollbackAnchorCode || rollbackAnchorCode === "0x") {
    throw new Error("execution-policy rollback anchor has no runtime bytecode");
  }
  if (keccak256(rollbackAnchorCode).toLowerCase() !== rollbackAnchor.runtime_code_hash) {
    throw new Error("execution-policy rollback anchor runtime bytecode hash does not match the release pin");
  }
  const [
    anchorOwner,
    anchorDeploymentIntentSha256,
    anchorReviewerGenesisAcceptanceSha256,
    anchorWriter,
    anchorWriterRelease,
    anchorPendingWriter,
    anchorPendingRelease,
    anchorPendingAt,
    anchorFrozen,
    anchorPaused,
    anchorGlobalSequence,
    anchorGlobalHead,
  ] = await Promise.all([
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "owner", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "deploymentIntentSha256", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "reviewerAuthorityGenesisAcceptanceSha256", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "writer", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "writerReleaseCommitment", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "pendingWriter", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "pendingWriterReleaseCommitment", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "pendingWriterActivatesAt", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "writerRotationsFrozen", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "paused", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "globalSequence", undefined, blockNumber),
    read(client, rollbackAnchor.contract_address, EXECUTION_POLICY_ANCHOR_ABI, "globalHead", undefined, blockNumber),
  ]);
  sameAddress(anchorOwner, candidate.operator_address, "live ExecutionPolicyAnchor owner");
  sameBytes32(
    anchorDeploymentIntentSha256,
    sha256PinAsBytes32(
      authorityBinding.deploymentIntentSha256,
      "release authority deployment-intent digest",
    ),
    "live ExecutionPolicyAnchor deployment-intent digest",
  );
  sameBytes32(
    anchorReviewerGenesisAcceptanceSha256,
    sha256PinAsBytes32(
      authorityBinding.reviewerAuthorityGenesisAcceptanceSha256,
      "release authority reviewer-genesis-acceptance digest",
    ),
    "live ExecutionPolicyAnchor reviewer-genesis-acceptance digest",
  );
  sameAddress(anchorWriter, rollbackAnchor.writer_address, "live ExecutionPolicyAnchor writer");
  sameBytes32(
    anchorWriterRelease,
    rollbackAnchor.writer_release_commitment,
    "live ExecutionPolicyAnchor writer release commitment",
  );
  const liveAnchorSequence = BigInt(anchorGlobalSequence);
  const liveAnchorHead = String(anchorGlobalHead).toLowerCase();
  if (
    String(anchorPendingWriter).toLowerCase() !== ZERO_ADDRESS
    || String(anchorPendingRelease).toLowerCase() !== ZERO_BYTES32
    || BigInt(anchorPendingAt) !== 0n
    || anchorFrozen !== true
    || anchorPaused !== false
    || !/^0x[0-9a-f]{64}$/.test(liveAnchorHead)
    || (liveAnchorSequence === 0n) !== (liveAnchorHead === ZERO_BYTES32)
  ) {
    throw new Error("live ExecutionPolicyAnchor is not the exact active frozen release writer");
  }

  const diligence = candidate.contracts.diligence_room;
  const compose = `0x${candidate.cvm.compose_hash}`;
  const tee = candidate.cvm.tee_identity;
  const [
    developer,
    resultVerifier,
    attestationVerifier,
    attestationReleasePolicyHash,
    pendingAttestationVerifier,
    pendingAttestationReleasePolicyHash,
    pendingAttestationBindingActivatesAt,
    attestationBindingFrozen,
    approvedEvaluatorPolicyCount,
    pendingEvaluatorPolicyCount,
    evaluatorPolicySetFrozen,
    evaluatorPolicySetRoot,
    evaluatorPolicies,
    feeBps,
    feeBpsFrozen,
    pendingFeeBpsActivatesAt,
    computeSettlementBps,
    computeSettlementPolicyEnabled,
    composeRequired,
    identityRequired,
    approvalRequirementsFrozen,
    composeAdditionsFrozen,
    teeIdentityAdditionsFrozen,
    approvedComposeCount,
    approvedTeeIdentityCount,
    pendingComposeCount,
    pendingTeeIdentityCount,
    composeApproved,
    identityCompose,
  ] = await Promise.all([
    read(client, diligence.address, DILIGENCE_ABI, "developer", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "resultVerifier", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "attestationVerifier", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "attestationReleasePolicyHash", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingAttestationVerifier", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingAttestationReleasePolicyHash", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingAttestationBindingActivatesAt", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "attestationBindingFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "approvedEvaluatorPolicyCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingEvaluatorPolicyCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "evaluatorPolicySetFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "evaluatorPolicySetRoot", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "evaluatorPolicies", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "feeBps", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "feeBpsFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingFeeBpsActivatesAt", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "COMPUTE_SETTLEMENT_BPS", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "computeSettlementPolicyEnabled", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "composeApprovalRequired", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "teeIdentityApprovalRequired", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "approvalRequirementsFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "composeAdditionsFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "teeIdentityAdditionsFrozen", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "approvedComposeCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "approvedTeeIdentityCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingComposeCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "pendingTeeIdentityCount", undefined, blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "approvedComposeHashes", [compose], blockNumber),
    read(client, diligence.address, DILIGENCE_ABI, "teeIdentityComposeHash", [tee], blockNumber),
  ]);
  sameAddress(developer, diligence.developer, "live DiligenceRoom developer");
  sameAddress(resultVerifier, diligence.result_verifier, "live DiligenceRoom result verifier");
  sameAddress(
    attestationVerifier,
    diligence.attestation_verifier,
    "live DiligenceRoom attestation verifier",
  );
  sameBytes32(
    attestationReleasePolicyHash,
    diligence.attestation_release_policy_hash,
    "live DiligenceRoom attestation release policy hash",
  );
  if (
    attestationBindingFrozen !== true
    || String(pendingAttestationVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(pendingAttestationReleasePolicyHash).toLowerCase() !== ZERO_BYTES32
    || BigInt(pendingAttestationBindingActivatesAt) !== 0n
  ) {
    throw new Error("live DiligenceRoom attestation binding is not the exact permanently frozen release binding");
  }
  const observedEvaluatorPolicies = Array.isArray(evaluatorPolicies)
    ? evaluatorPolicies.map((value) => String(value).toLowerCase())
    : [];
  const expectedEvaluatorPolicies = diligence.evaluator_policy_commitments;
  const evaluatorMembership = await Promise.all(expectedEvaluatorPolicies.flatMap((policy) => [
    read(
      client,
      diligence.address,
      DILIGENCE_ABI,
      "approvedEvaluatorPolicies",
      [policy],
      blockNumber,
    ),
    read(
      client,
      diligence.address,
      DILIGENCE_ABI,
      "pendingEvaluatorPolicyActivations",
      [policy],
      blockNumber,
    ),
  ]));
  if (
    BigInt(approvedEvaluatorPolicyCount) !== 3n
    || BigInt(pendingEvaluatorPolicyCount) !== 0n
    || evaluatorPolicySetFrozen !== true
    || String(evaluatorPolicySetRoot).toLowerCase()
      !== diligence.evaluator_policy_set_root
    || observedEvaluatorPolicies.length !== 3
    || JSON.stringify([...observedEvaluatorPolicies].sort())
      !== JSON.stringify(expectedEvaluatorPolicies)
    || evaluatorMembership.some((value, index) => (
      index % 2 === 0 ? value !== true : BigInt(value) !== 0n
    ))
  ) {
    throw new Error(
      "live DiligenceRoom evaluator policy set is not the exact active frozen three-policy authority",
    );
  }
  if (
    BigInt(feeBps) !== 100n
    || feeBpsFrozen !== true
    || BigInt(pendingFeeBpsActivatesAt) !== 0n
    || BigInt(computeSettlementBps) !== 100n
    || computeSettlementPolicyEnabled !== true
  ) {
    throw new Error("live DiligenceRoom settlement tariffs are not fixed to the reviewed policy");
  }
  if (
    composeRequired !== true
    || identityRequired !== true
    || approvalRequirementsFrozen !== true
  ) {
    throw new Error("live DiligenceRoom compose and TEE approval gates are not active and irreversibly required");
  }
  if (
    composeAdditionsFrozen !== true
    || teeIdentityAdditionsFrozen !== true
    || BigInt(approvedComposeCount) !== 1n
    || BigInt(approvedTeeIdentityCount) !== 1n
    || BigInt(pendingComposeCount) !== 0n
    || BigInt(pendingTeeIdentityCount) !== 0n
    || composeApproved !== true
  ) {
    throw new Error("live DiligenceRoom admission set is not exactly bound and irreversibly closed");
  }
  sameBytes32(identityCompose, compose, "live DiligenceRoom TEE compose binding");

  const challenge = candidate.contracts.challenge_registry;
  const [
    challengeOwner,
    challengePendingOwner,
    registryPaused,
    challengeCount,
    nextChallengeId,
    versionReviewDelay,
  ] = await Promise.all([
    read(client, challenge.address, CHALLENGE_ABI, "owner", undefined, blockNumber),
    read(client, challenge.address, CHALLENGE_ABI, "pendingOwner", undefined, blockNumber),
    read(client, challenge.address, CHALLENGE_ABI, "registryPaused", undefined, blockNumber),
    read(client, challenge.address, CHALLENGE_ABI, "challengeCount", undefined, blockNumber),
    read(client, challenge.address, CHALLENGE_ABI, "nextChallengeId", undefined, blockNumber),
    read(client, challenge.address, CHALLENGE_ABI, "MIN_VERSION_REVIEW_DELAY", undefined, blockNumber),
  ]);
  sameAddress(challengeOwner, challenge.owner, "live ChallengeRegistry owner");
  zeroAddress(challengePendingOwner, "live ChallengeRegistry pending owner");
  const expectedChallengeCount = BigInt(challenge.expected_challenge_count);
  if (registryPaused !== challenge.registry_paused) {
    throw new Error("live ChallengeRegistry pause state differs from final authority");
  }
  if (BigInt(challengeCount) < expectedChallengeCount) {
    throw new Error("live ChallengeRegistry is missing a release-approved genesis challenge");
  }
  if (BigInt(nextChallengeId) !== BigInt(challengeCount) + 1n) {
    throw new Error("live ChallengeRegistry id sequence is inconsistent");
  }
  if (BigInt(versionReviewDelay)
    !== BigInt(challenge.minimum_version_review_delay_seconds)) {
    throw new Error("live ChallengeRegistry minimum version review delay is not exactly 172800 seconds");
  }
  for (const [catalogKey, binding] of Object.entries(candidate.arena_registry_bindings)) {
    const challengeId = BigInt(binding.registry_challenge_id);
    const [exists, challengeState, versionState, reviewEligibleAt] = await Promise.all([
      read(client, challenge.address, CHALLENGE_ABI, "challengeExists", [challengeId], blockNumber),
      read(client, challenge.address, CHALLENGE_DETAIL_ABI, "getChallenge", [challengeId], blockNumber),
      read(client, challenge.address, CHALLENGE_DETAIL_ABI, "getVersion", [challengeId, binding.registry_version], blockNumber),
      read(client, challenge.address, CHALLENGE_ABI, "reviewEligibleAt", [challengeId], blockNumber),
    ]);
    if (exists !== true) throw new Error(`Arena registry binding ${catalogKey} does not exist on-chain`);
    sameAddress(
      challengeState.controller,
      binding.controller_address,
      `Arena registry binding ${catalogKey} controller`,
    );
    zeroAddress(
      challengeState.pendingController,
      `Arena registry binding ${catalogKey} pending controller`,
    );
    if (
      Number(challengeState.lifecycle) !== 1
      || challengeState.paused !== binding.paused
      || challengeState.configurationFrozen !== binding.configuration_frozen
      || Number(challengeState.latestVersion) !== binding.registry_version
    ) {
      throw new Error(`Arena registry binding ${catalogKey} is not the exact frozen current Open version`);
    }
    if (
      versionState.metadataURI !== binding.metadata_uri
      || String(versionState.metadataHash).toLowerCase() !== binding.metadata_hash
      || String(versionState.sealedArtifactCommitment).toLowerCase() !== binding.sealed_artifact_commitment
      || String(versionState.evaluatorCommitment).toLowerCase() !== binding.evaluator_commitment
      || String(versionState.releasePolicyCommitment).toLowerCase() !== binding.release_policy_commitment
    ) {
      throw new Error(`Arena registry binding ${catalogKey} commitments do not match live state`);
    }
    const expectedReviewEligibleAt = BigInt(versionState.createdAt)
      + CHALLENGE_VERSION_REVIEW_DELAY_SECONDS;
    if (
      BigInt(reviewEligibleAt) !== expectedReviewEligibleAt
      || snapshotTimestamp < expectedReviewEligibleAt
    ) {
      throw new Error(
        `Arena registry binding ${catalogKey} did not complete the exact immutable version review delay before the release snapshot`,
      );
    }
  }

  const encumbrance = candidate.contracts.tinker_account_encumbrance;
  const encumbranceCompose = encumbrance.approved_compose_hashes[0];
  const encumbranceManager = encumbrance.managers[0];
  const [
    encumbranceOwner,
    encumbrancePendingOwner,
    accountCommitment,
    maxAddBalanceWei,
    maxSpendWei,
    encumbranceApprovedComposeRoot,
    encumbranceApprovedComposeCount,
    encumbranceApprovedComposeAtZero,
    encumbranceManagerRoot,
    encumbranceManagerCount,
    encumbranceManagerAtZero,
    encumbranceReleasePolicyCommitment,
    encumbranceReleaseMaxAddBalanceWei,
    encumbranceReleaseMaxSpendWei,
    encumbranceReleaseComposeRoot,
    encumbranceReleaseComposeCount,
    encumbranceReleaseManagerRoot,
    encumbranceReleaseManagerCount,
    encumbranceReleasePolicyFrozen,
    encumbrancePendingAccountCommitment,
    encumbrancePendingMaxAddBalanceWei,
    encumbrancePendingMaxSpendWei,
    encumbrancePendingComposeRoot,
    encumbrancePendingManagerRoot,
    encumbrancePendingReleasePolicyCommitment,
    encumbrancePendingReleasePolicyActivatesAt,
    encumbrancePendingComposeCount,
    encumbrancePendingManagerCount,
    encumbranceReleasePolicyDelay,
    encumbranceComposeApproved,
    encumbranceManagerApproved,
    halted,
  ] = await Promise.all([
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "owner", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingOwner", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "accountCommitment", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "maxAddBalanceWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "maxSpendWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "approvedComposeRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "approvedComposeCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "approvedComposeHashAt", [0n], blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "managerRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "managerCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "managerAt", [0n], blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releasePolicyCommitment", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseMaxAddBalanceWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseMaxSpendWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseComposeRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseComposeCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseManagerRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releaseManagerCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "releasePolicyFrozen", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingAccountCommitment", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingMaxAddBalanceWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingMaxSpendWei", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingComposeRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingManagerRoot", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingReleasePolicyCommitment", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingReleasePolicyActivatesAt", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingComposeCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "pendingManagerCount", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "RELEASE_POLICY_DELAY", undefined, blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "approvedComposeHashes", [encumbranceCompose], blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "managers", [encumbranceManager], blockNumber),
    read(client, encumbrance.address, ENCUMBRANCE_ABI, "emergencyHalted", undefined, blockNumber),
  ]);
  sameAddress(encumbranceOwner, encumbrance.owner, "live encumbrance owner");
  sameBytes32(accountCommitment, encumbrance.account_commitment, "live account commitment");
  sameBytes32(encumbranceApprovedComposeRoot, encumbrance.approved_compose_root, "live encumbrance compose root");
  sameBytes32(encumbranceManagerRoot, encumbrance.manager_root, "live encumbrance manager root");
  sameBytes32(encumbranceReleasePolicyCommitment, encumbrance.release_policy_commitment, "live encumbrance release policy commitment");
  sameBytes32(encumbranceReleaseComposeRoot, encumbrance.release_compose_root, "live encumbrance release compose root");
  sameBytes32(encumbranceReleaseManagerRoot, encumbrance.release_manager_root, "live encumbrance release manager root");
  sameBytes32(encumbranceApprovedComposeAtZero, encumbranceCompose, "live encumbrance compose member");
  sameAddress(encumbranceManagerAtZero, encumbranceManager, "live encumbrance manager member");
  if (
    String(encumbrancePendingOwner).toLowerCase() !== ZERO_ADDRESS
    || BigInt(maxAddBalanceWei).toString() !== encumbrance.max_add_balance_wei
    || BigInt(maxSpendWei).toString() !== encumbrance.max_spend_wei
    || Number(encumbranceApprovedComposeCount) !== encumbrance.approved_compose_count
    || Number(encumbranceManagerCount) !== encumbrance.manager_count
    || BigInt(encumbranceReleaseMaxAddBalanceWei).toString() !== encumbrance.release_max_add_balance_wei
    || BigInt(encumbranceReleaseMaxSpendWei).toString() !== encumbrance.release_max_spend_wei
    || Number(encumbranceReleaseComposeCount) !== encumbrance.release_compose_count
    || Number(encumbranceReleaseManagerCount) !== encumbrance.release_manager_count
    || encumbranceReleasePolicyFrozen !== true
    || encumbranceComposeApproved !== true
    || encumbranceManagerApproved !== true
    || halted !== false
    || String(encumbrancePendingAccountCommitment).toLowerCase() !== ZERO_BYTES32
    || BigInt(encumbrancePendingMaxAddBalanceWei) !== 0n
    || BigInt(encumbrancePendingMaxSpendWei) !== 0n
    || String(encumbrancePendingComposeRoot).toLowerCase() !== ZERO_BYTES32
    || String(encumbrancePendingManagerRoot).toLowerCase() !== ZERO_BYTES32
    || String(encumbrancePendingReleasePolicyCommitment).toLowerCase() !== ZERO_BYTES32
    || BigInt(encumbrancePendingReleasePolicyActivatesAt) !== 0n
    || BigInt(encumbrancePendingComposeCount) !== 0n
    || BigInt(encumbrancePendingManagerCount) !== 0n
    || BigInt(encumbranceReleasePolicyDelay) !== 172_800n
  ) {
    throw new Error("live encumbrance does not prove the exact active, frozen, delay-reviewed release policy");
  }

  const computeVault = candidate.contracts.compute_credit_vault;
  const [
    computeOwner,
    computeDeveloper,
    computeMeteringVerifier,
    computeMeteringQvlVerifier,
    computeMeteringPolicySetHash,
    computePendingMeteringVerifier,
    computePendingMeteringQvlVerifier,
    computePendingMeteringPolicySetHash,
    computePendingMeteringBindingActivatesAt,
    computeMeteringBindingFrozen,
    computePaused,
    computeFeeBps,
    computeFeeFrozen,
    computePendingDeveloperFeeActivatesAt,
    computeComposePolicyFrozen,
    computeTeeIdentityAdditionsFrozen,
    computeRatePolicyAdditionsFrozen,
    computeAssetAdditionsFrozen,
    computeAllowedAssetCount,
    computeActiveRatePolicyCount,
    computeApprovedComposeCount,
    computeApprovedTeeIdentityCount,
    computePendingAssetCount,
    computePendingRatePolicyCount,
    computePendingComposeCount,
    computePendingTeeIdentityCount,
    computeComposeApproved,
    computeTeeCompose,
    computeErc20Allowed,
    nativeRatePolicyRaw,
    erc20RatePolicyRaw,
  ] = await Promise.all([
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "owner", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "developer", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "meteringVerifier", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "meteringQvlVerifier", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "meteringPolicySetHash", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingMeteringVerifier", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingMeteringQvlVerifier", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingMeteringPolicySetHash", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingMeteringBindingActivatesAt", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "meteringBindingFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "paused", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "developerFeeBps", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "developerFeeFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingDeveloperFeeActivatesAt", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "composePolicyFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "teeIdentityAdditionsFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "ratePolicyAdditionsFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "assetAdditionsFrozen", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "allowedAssetCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "activeRatePolicyCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "approvedComposeCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "approvedTeeIdentityCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingAssetCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingRatePolicyCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingComposeCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "pendingTeeIdentityCount", undefined, blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "approvedComposeHashes", [compose], blockNumber),
    read(client, computeVault.address, COMPUTE_VAULT_ABI, "teeIdentityComposeHash", [tee], blockNumber),
    read(
      client,
      computeVault.address,
      COMPUTE_VAULT_ABI,
      "allowedAssets",
      [computeVault.erc20_asset_address],
      blockNumber,
    ),
    read(
      client,
      computeVault.address,
      COMPUTE_VAULT_ABI,
      "ratePolicies",
      [computeVault.native_rate_policy_commitment],
      blockNumber,
    ),
    read(
      client,
      computeVault.address,
      COMPUTE_VAULT_ABI,
      "ratePolicies",
      [computeVault.erc20_rate_policy_commitment],
      blockNumber,
    ),
  ]);
  sameAddress(computeOwner, computeVault.owner, "live ComputeCreditVault owner");
  sameAddress(computeDeveloper, computeVault.developer, "live ComputeCreditVault developer");
  sameAddress(
    computeMeteringVerifier,
    computeVault.metering_verifier,
    "live ComputeCreditVault metering verifier",
  );
  sameAddress(
    computeMeteringQvlVerifier,
    computeVault.metering_qvl_verifier,
    "live ComputeCreditVault metering QVL verifier",
  );
  sameBytes32(
    computeMeteringPolicySetHash,
    computeVault.metering_policy_set_hash,
    "live ComputeCreditVault metering policy set hash",
  );
  if (
    computeMeteringBindingFrozen !== true
    || String(computePendingMeteringVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(computePendingMeteringQvlVerifier).toLowerCase() !== ZERO_ADDRESS
    || String(computePendingMeteringPolicySetHash).toLowerCase() !== ZERO_BYTES32
    || BigInt(computePendingMeteringBindingActivatesAt) !== 0n
  ) {
    throw new Error("live ComputeCreditVault metering binding is not the exact permanently frozen release binding");
  }
  if (
    BigInt(computeFeeBps) !== BigInt(computeVault.developer_fee_bps)
    || computeFeeFrozen !== true
    || BigInt(computePendingDeveloperFeeActivatesAt) !== 0n
  ) {
    throw new Error("live ComputeCreditVault developer fee is not pinned and frozen");
  }
  if (
    computeComposePolicyFrozen !== true
    || computeTeeIdentityAdditionsFrozen !== true
    || computeRatePolicyAdditionsFrozen !== true
    || computeAssetAdditionsFrozen !== true
    || BigInt(computeAllowedAssetCount) !== 1n
    || BigInt(computeActiveRatePolicyCount) !== 2n
    || BigInt(computeApprovedComposeCount) !== 1n
    || BigInt(computeApprovedTeeIdentityCount) !== 1n
    || BigInt(computePendingAssetCount) !== 0n
    || BigInt(computePendingRatePolicyCount) !== 0n
    || BigInt(computePendingComposeCount) !== 0n
    || BigInt(computePendingTeeIdentityCount) !== 0n
    || computeComposeApproved !== true
    || computeErc20Allowed !== true
  ) {
    throw new Error(
      "live ComputeCreditVault exact compose, TEE, rate-policy, and asset admission set is not approved and irreversibly closed",
    );
  }
  sameBytes32(computeTeeCompose, compose, "live ComputeCreditVault TEE compose binding");
  if (candidate.requested_features.compute_vault_funding) {
    if (computePaused !== false || computeErc20Allowed !== true) {
      throw new Error("live ComputeCreditVault funding rail or pinned ERC20 asset is not active");
    }
  }
  if (candidate.requested_features.compute_vault_authorization) {
    if (
      computePaused !== false
    ) {
      throw new Error("live ComputeCreditVault authorization rail is paused");
    }
    const normalizeRatePolicy = (value, label) => {
      const tuple = Array.isArray(value)
        ? value
        : [value?.asset, value?.provider, value?.developerFeeBps, value?.active];
      if (tuple.length !== 4) throw new Error(`${label} has an invalid ABI shape`);
      const rawAsset = String(tuple[0]);
      if (!isAddress(rawAsset, { strict: true })) throw new Error(`${label}.asset must be an Ethereum address`);
      return {
        asset: getAddress(rawAsset).toLowerCase(),
        provider: address(String(tuple[1]), `${label}.provider`),
        developerFeeBps: BigInt(tuple[2]),
        active: tuple[3],
      };
    };
    const nativeRate = normalizeRatePolicy(nativeRatePolicyRaw, "live native rate policy");
    const erc20Rate = normalizeRatePolicy(erc20RatePolicyRaw, "live ERC20 rate policy");
    const meteringAssets = candidate.trust_domains.compute_metering.identity.assets;
    const expectedNative = meteringAssets.find((entry) => entry.asset === ZERO_ADDRESS);
    const expectedErc20 = meteringAssets.find((entry) => entry.asset === computeVault.erc20_asset_address);
    if (
      !expectedNative
      || !expectedErc20
      || nativeRate.asset !== "0x0000000000000000000000000000000000000000"
      || nativeRate.provider !== expectedNative.provider
      || nativeRate.active !== true
      || nativeRate.developerFeeBps !== BigInt(computeVault.developer_fee_bps)
      || erc20Rate.asset !== computeVault.erc20_asset_address
      || erc20Rate.provider !== expectedErc20.provider
      || erc20Rate.active !== true
      || erc20Rate.developerFeeBps !== BigInt(computeVault.developer_fee_bps)
    ) {
      throw new Error("live ComputeCreditVault rate policies are not the active pinned native/ERC20 policies");
    }
    const forbiddenProviders = new Set([
      computeVault.owner,
      computeVault.developer,
      computeVault.metering_verifier,
      computeVault.metering_qvl_verifier,
      computeVault.tee_identity,
    ]);
    if (forbiddenProviders.has(nativeRate.provider) || forbiddenProviders.has(erc20Rate.provider)) {
      throw new Error("live ComputeCreditVault rate-policy provider conflicts with a control-plane role");
    }
  }

  await validateLiveEmailOracle(candidate, client, blockNumber);

  const usdc = candidate.contracts.usdc;
  const [symbol, decimals] = await Promise.all([
    read(client, usdc.address, ERC20_ABI, "symbol", undefined, blockNumber),
    read(client, usdc.address, ERC20_ABI, "decimals", undefined, blockNumber),
  ]);
  if (symbol !== "USDC" || decimals !== 6) throw new Error("live USDC metadata mismatch");
  return {
    blockNumber,
    blockHash: snapshotBlockHash,
    verificationModel: EXECUTION_POLICY_ANCHOR_VERIFICATION_MODEL,
    latestBlockNumber,
    rpcFinalizedBlockNumber,
    rpcFinalizedBlockHash,
    minimumConfirmationDepth: candidate.execution_policy.rollback_anchor.confirmations,
    observedConfirmationDepth: Number(latestBlockNumber - blockNumber + 1n),
    independentRpcQuorumVerified: false,
    consensusProofVerified: false,
    executionPolicyAnchor: {
      deploymentIntentSha256:
        String(anchorDeploymentIntentSha256).toLowerCase(),
      reviewerAuthorityGenesisAcceptanceSha256:
        String(anchorReviewerGenesisAcceptanceSha256).toLowerCase(),
      globalSequence: liveAnchorSequence,
      globalHead: liveAnchorHead,
    },
  };
}

export async function buildReleaseEnv({
  candidate: candidateValue,
  ledger,
  artifactEvidence,
  arenaEvidence,
  anchorWriterEvidence,
  anchorWriterEvidenceBytes,
  emailOracleEvidence,
  emailOracleEvidenceBytes,
  client,
  primaryRpcUrl,
  secondaryRpcUrl,
  now,
  trustedVerifierAddresses,
  authorityBinding: authorityBindingValue,
  candidateAuthorityStage = "live",
  historicalComputeWorkloadActivationObservation,
}) {
  const authorityBinding = normalizeReleaseAuthorityBinding(authorityBindingValue);
  const candidate = normalizeReleaseCandidate(candidateValue, {
    authorityStage: candidateAuthorityStage,
  });
  let publicRpcEndpoints;
  try {
    publicRpcEndpoints = exactDistinctPublicHttpsEndpoints(
      primaryRpcUrl,
      secondaryRpcUrl,
      {
        primaryLabel: "primary Base Sepolia RPC URL",
        secondaryLabel: "secondary Base Sepolia RPC URL",
      },
    );
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`browser RPC release binding is invalid: ${detail}`);
  }
  if (publicRpcEndpoints.primary !== candidate.network.public_rpc_url) {
    throw new Error("primary Base Sepolia RPC does not match the reviewed release candidate");
  }
  const trustedRoots = validateExternalTrustedVerifierSet(
    candidate,
    trustedVerifierAddresses,
  );
  const releaseSnapshotBlockNumber = validateDeploymentLedger(
    ledger,
    candidate,
    authorityBinding,
  );
  validateDeploymentEvidence(artifactEvidence, candidate, "artifact", now);
  validateDeploymentEvidence(arenaEvidence, candidate, "arena", now);
  const artifactVerdict = await validateIndependentVerdict(
    candidate.attestations.artifact,
    candidate,
    candidate.contracts.diligence_room.address,
    { now, trustedVerifierAddresses: trustedRoots },
  );
  const sharedVerdictLineage = {
    expectedReleaseAuthoritySha256: artifactVerdict.release_authority_sha256,
    expectedCeremonyNonce: artifactVerdict.ceremony_nonce,
  };
  await validateIndependentVerdict(
    candidate.attestations.arena,
    candidate,
    candidate.contracts.challenge_registry.address,
    { now, trustedVerifierAddresses: trustedRoots, ...sharedVerdictLineage },
  );
  if (
    bytes32(
      candidate.attestations.compute_metering.verdict.report_data,
      "compute metering verdict report data",
    ) !== computeMeteringReportData(candidate)
  ) {
    throw new Error("compute metering verdict does not bind the exact metering policy");
  }
  await validateIndependentVerdict(
    candidate.attestations.compute_metering,
    candidate,
    candidate.contracts.compute_credit_vault.address,
    {
      now,
      trustedVerifierAddresses: trustedRoots,
      qvlDomainKey: "compute_metering_qvl",
      expectedProfile: "compute_metering",
      expectedSignerAddress:
        candidate.trust_domains.compute_metering.identity.metering_verifier,
      expectedCvm: candidate.trust_domains.compute_metering,
      ...sharedVerdictLineage,
    },
  );
  await validateAnchorWriterEvidence(
    anchorWriterEvidence,
    anchorWriterEvidenceBytes,
    candidate,
    { now, trustedVerifierAddresses: trustedRoots, ...sharedVerdictLineage },
  );
  await validateEmailOracleEvidence(
    emailOracleEvidence,
    emailOracleEvidenceBytes,
    candidate,
    { now, trustedVerifierAddresses: trustedRoots, ...sharedVerdictLineage },
  );
  if (!client) throw new Error("a live Base Sepolia client is required");
  const liveSnapshot = await validateLiveChain(
    candidate,
    client,
    releaseSnapshotBlockNumber,
    now,
    authorityBinding,
  );
  const ledgerAnchor = record(
    record(ledger, "deployment ledger").contracts.executionPolicyAnchor,
    "ledger ExecutionPolicyAnchor",
  );
  if (
    liveSnapshot.executionPolicyAnchor.globalSequence
      !== BigInt(ledgerAnchor.globalSequence)
    || liveSnapshot.executionPolicyAnchor.globalHead
      !== String(ledgerAnchor.globalHead).toLowerCase()
  ) {
    throw new Error("live ExecutionPolicyAnchor head does not match the release-pinned ledger snapshot");
  }
  const delegate = candidate.cvm.images.find((image) => image.service === "delegate");
  const requested = candidate.requested_features;
  let computeWorkloadEnv = Object.fromEntries(
    COMPUTE_WORKLOAD_BROWSER_ENV_KEYS.map((key) => [key, ""]),
  );
  computeWorkloadEnv.VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD = "false";
  computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON = "[]";
  if (requested.compute_workload_upload) {
    if (!historicalComputeWorkloadActivationObservation) {
      throw new Error(
        "compute-workload upload requires a revalidated signed-C historical observation",
      );
    }
    const observation = historicalComputeWorkloadActivationObservation;
    computeWorkloadEnv =
      projectComputeWorkloadBrowserEnvFromHistoricalObservation(observation);
    const expectedCapabilityEndpoint =
      `${candidate.cvm.delegate_url}/compute/workload-encryption-contract`;
    if (observation.release_sha !== candidate.release_sha
      || observation.chain_id !== BASE_SEPOLIA_CHAIN_ID
      || observation.capability_endpoint
        !== expectedCapabilityEndpoint
      || observation.main_runtime.app_id !== candidate.cvm.app_id
      || observation.main_runtime.cvm_id !== candidate.cvm.cvm_id
      || observation.main_runtime.compose_hash
        !== candidate.cvm.compose_hash
      || observation.main_runtime.os_image_hash
        !== candidate.cvm.os_image_hash
      || observation.main_runtime.tee_identity
        !== candidate.cvm.tee_identity
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_QVL_VERIFIER
        !== candidate.trust_domains.compute_workload_qvl.identity.verifier_address
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_CVM_ID
        !== candidate.cvm.cvm_id
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256
        !== candidate.deployment_intent_sha256
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256
        !== candidate.attestations.artifact.verdict.release_authority_sha256
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE
        !== candidate.attestations.artifact.verdict.ceremony_nonce
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256
        !== observation.lineage.qvl_measurement_policy_set_sha256
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256
        !== observation.compute_workload_qvl.measurement_policy_sha256
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256
        !== observation.main_runtime.seven_cvm_domain_evidence_sha256
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH
        !== candidate.trust_domains.compute_workload_qvl.identity.release_policy_hash
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS
        !== candidate.contracts.compute_credit_vault.address
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH
        !== candidate.contracts.compute_credit_vault.runtime_code_hash
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS
        !== String(candidate.cvm.compute_workload_ingress.max_verdict_age_seconds)
      || computeWorkloadEnv.VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON
        !== JSON.stringify(candidate.cvm.compute_workload_ingress.revoked_quote_hashes)) {
      throw new Error(
        "branded compute-workload activation observation drifted from the exact reviewed release candidate",
      );
    }
  }
  return {
    VITE_BASE_SEPOLIA_RPC_URL: publicRpcEndpoints.primary,
    VITE_BASE_SEPOLIA_SECONDARY_RPC_URL: publicRpcEndpoints.secondary,
    VITE_RELEASE_SHA: candidate.release_sha,
    VITE_DILIGENCE_ROOM_ADDRESS: candidate.contracts.diligence_room.address,
    VITE_DILIGENCE_ROOM_CODE_HASH: candidate.contracts.diligence_room.runtime_code_hash,
    VITE_DILIGENCE_ROOM_DEVELOPER: candidate.contracts.diligence_room.developer,
    VITE_DILIGENCE_RESULT_VERIFIER: candidate.contracts.diligence_room.result_verifier,
    VITE_DILIGENCE_ATTESTATION_VERIFIER:
      candidate.contracts.diligence_room.attestation_verifier,
    VITE_DILIGENCE_QVL_RELEASE_POLICY_HASH:
      candidate.contracts.diligence_room.attestation_release_policy_hash,
    VITE_CHALLENGE_REGISTRY_ADDRESS: candidate.contracts.challenge_registry.address,
    VITE_CHALLENGE_REGISTRY_CODE_HASH: candidate.contracts.challenge_registry.runtime_code_hash,
    VITE_ROYALTY_DISTRIBUTOR_ADDRESS: candidate.contracts.royalty_distributor.address,
    VITE_ROYALTY_DISTRIBUTOR_CODE_HASH: candidate.contracts.royalty_distributor.runtime_code_hash,
    VITE_TINKER_ENCUMBRANCE_ADDRESS: candidate.contracts.tinker_account_encumbrance.address,
    VITE_TINKER_ENCUMBRANCE_CODE_HASH: candidate.contracts.tinker_account_encumbrance.runtime_code_hash,
    VITE_EMAIL_ORACLE_AUTH_ADDRESS: candidate.contracts.email_oracle_auth.address,
    VITE_EMAIL_ORACLE_AUTH_CODE_HASH: candidate.contracts.email_oracle_auth.runtime_code_hash,
    VITE_COMPUTE_CREDIT_VAULT_ADDRESS: candidate.contracts.compute_credit_vault.address,
    VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: candidate.contracts.compute_credit_vault.runtime_code_hash,
    VITE_ENABLE_COMPUTE_VAULT_FUNDING: String(requested.compute_vault_funding),
    VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: String(requested.compute_vault_authorization),
    VITE_COMPUTE_VAULT_DEVELOPER: candidate.contracts.compute_credit_vault.developer,
    VITE_COMPUTE_VAULT_METERING_VERIFIER: candidate.contracts.compute_credit_vault.metering_verifier,
    VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER:
      candidate.contracts.compute_credit_vault.metering_qvl_verifier,
    VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH:
      candidate.contracts.compute_credit_vault.metering_policy_set_hash,
    VITE_COMPUTE_VAULT_TEE_IDENTITY: candidate.contracts.compute_credit_vault.tee_identity,
    VITE_COMPUTE_VAULT_COMPOSE_HASH: `0x${candidate.contracts.compute_credit_vault.compose_hash}`,
    VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT:
      candidate.contracts.compute_credit_vault.native_rate_policy_commitment,
    VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS: candidate.contracts.compute_credit_vault.erc20_asset_address,
    VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH: candidate.contracts.usdc.runtime_code_hash,
    VITE_COMPUTE_VAULT_ERC20_SYMBOL: candidate.contracts.usdc.symbol,
    VITE_COMPUTE_VAULT_ERC20_DECIMALS: String(candidate.contracts.usdc.decimals),
    VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT:
      candidate.contracts.compute_credit_vault.erc20_rate_policy_commitment,
    VITE_TEE_IDENTITY: candidate.cvm.tee_identity,
    VITE_USDC_ADDRESS: candidate.contracts.usdc.address,
    VITE_ENABLE_CONTRACT_WRITES: String(requested.contract_writes),
    VITE_DELEGATE_URL: candidate.cvm.delegate_url,
    VITE_PHALA_APP_ID: candidate.cvm.app_id,
    VITE_PHALA_CVM_ID: candidate.cvm.cvm_id,
    VITE_PHALA_COMPOSE_HASH: candidate.cvm.compose_hash,
    VITE_PHALA_OS_IMAGE_HASH: candidate.cvm.os_image_hash,
    VITE_DELEGATE_IMAGE_DIGEST: delegate.image,
    VITE_WALLETCONNECT_PROJECT_ID: candidate.wallet_auth.walletconnect_project_id,
    VITE_WALLET_AUTH_DOMAIN: candidate.wallet_auth.domain,
    VITE_WALLET_AUTH_URI: candidate.wallet_auth.uri,
    VITE_ENABLE_ARTIFACT_UPLOAD: String(requested.artifact_upload),
    VITE_ARTIFACT_VERIFIED_QUOTE_SHA256: candidate.attestations.artifact.quote_sha256,
    VITE_ENABLE_COMPUTE_CONSOLE: String(requested.compute_console),
    ...computeWorkloadEnv,
    VITE_ENABLE_ARENA_SUBMISSION: String(requested.arena_submission),
    VITE_ARENA_VERIFIED_QUOTE_SHA256: candidate.attestations.arena.quote_sha256,
    VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256:
      candidate.attestations.compute_metering.quote_sha256,
    VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON: JSON.stringify(candidate.arena_registry_bindings),
    VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256:
      arenaReleaseApprovedChallengeSetSha256(candidate.arena_registry_bindings),
    VITE_EXECUTION_POLICY_ANCHOR_ADDRESS:
      candidate.execution_policy.rollback_anchor.contract_address,
    VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH:
      candidate.execution_policy.rollback_anchor.runtime_code_hash,
    VITE_EXECUTION_POLICY_ANCHOR_WRITER:
      candidate.execution_policy.rollback_anchor.writer_address,
    VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT:
      candidate.execution_policy.rollback_anchor.writer_release_commitment,
    VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS:
      String(candidate.execution_policy.rollback_anchor.confirmations),
    VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS:
      String(candidate.execution_policy.rollback_anchor.max_block_age_seconds),
    VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS:
      String(candidate.execution_policy.rollback_anchor.max_future_block_skew_seconds),
    VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH:
      candidate.execution_policy.approval_domain_hash,
    VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH:
      candidate.execution_policy.approver_root_hash,
    VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON:
      JSON.stringify(candidate.execution_policy.approver_hashes),
  };
}

export function serializeEnv(env) {
  const actual = Object.keys(record(env, "release env")).sort();
  const expected = [...ENV_KEYS].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("release env contains a missing or non-allowlisted key");
  }
  return `${ENV_KEYS.map((key) => {
    const value = env[key];
    if (typeof value !== "string" || /[\0\r\n]/.test(value)) {
      throw new Error(`${key} is not safe for dotenv serialization`);
    }
    return `${key}=${value}`;
  }).join("\n")}\n`;
}

export function githubAttestationCommands(value) {
  const imageEntries = Array.isArray(value)
    ? value
    : [
        ...record(value, "release candidate for image verification").cvm.images,
        ...TRUST_DOMAIN_KEYS.map((key) => value.trust_domains[key].image),
      ];
  const images = [...new Map(imageEntries.map((image) => [image.image, image])).values()];
  return images.flatMap((image) => [
    "https://slsa.dev/provenance/v1",
    "https://spdx.dev/Document/v2.3",
  ].map((predicate) => [
    "attestation",
    "verify",
    `oci://${image.image}`,
    "--repo",
    GITHUB_REPOSITORY,
    "--bundle-from-oci",
    "--signer-workflow",
    GITHUB_SIGNER_WORKFLOW,
    "--source-digest",
    image.source_digest,
    "--source-ref",
    image.source_ref,
    "--deny-self-hosted-runners",
    "--predicate-type",
    predicate,
  ]));
}

export const __test = Object.freeze({ canonicalVerdictDigest, ENV_KEYS });

// Additive compatibility exports only. Historical exact-37 must import the
// pure module directly rather than this viem-backed production facade.
export {
  assertHistoricalLiveActivationFinalCvmsMatchCandidate,
  historicalLiveReleaseCandidatePrebuildProjectionSha256,
  normalizeHistoricalFrontendReleaseCandidate,
  projectHistoricalLiveReleaseCandidateToPrebuild,
} from "./frontend-release-historical-core.mjs";
