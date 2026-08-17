import type { Address } from "viem";
import { parseComputeVaultConfig } from "./lib/computeVaultConfig";
import { parseComputeWorkloadConfig } from "./lib/computeWorkloadConfig";
import { parseDiligenceEvaluatorConfig } from "./lib/diligencePolicies";
import { parseFrontendReleaseIdentity } from "./lib/releaseIdentity";
import { parseRoyaltyReleaseConfiguration } from "./lib/royaltyReleaseAuthority";
import { parseCollaborationExecutionReleaseConfig } from "./lib/collaborationExecutionReleaseConfig";

const env = import.meta.env;
const PRODUCTION_WALLET_AUTH_DOMAIN = "www.wikigen.me";
const PRODUCTION_WALLET_AUTH_URI = "https://www.wikigen.me";

function clean(value: string | undefined): string {
  const trimmed = value?.trim() ?? "";
  return trimmed === "undefined" || trimmed === "null" ? "" : trimmed;
}

function address(value: string | undefined): Address | undefined {
  const candidate = clean(value);
  return /^0x[0-9a-fA-F]{40}$/.test(candidate) ? (candidate as Address) : undefined;
}

function bytes32(value: string | undefined): `0x${string}` | undefined {
  const candidate = clean(value).toLowerCase();
  return /^0x[0-9a-f]{64}$/.test(candidate) ? (candidate as `0x${string}`) : undefined;
}

function sha256(value: string | undefined): string | undefined {
  const candidate = clean(value).toLowerCase();
  return /^[0-9a-f]{64}$/.test(candidate) ? candidate : undefined;
}

function sha256Pin(value: string | undefined): `sha256:${string}` | undefined {
  const candidate = clean(value).toLowerCase();
  return /^sha256:(?!0{64}$)[0-9a-f]{64}$/.test(candidate)
    ? (candidate as `sha256:${string}`)
    : undefined;
}

function sha256ListJson(value: string | undefined): readonly string[] | undefined {
  const candidate = clean(value);
  if (!candidate) return undefined;
  try {
    const decoded: unknown = JSON.parse(candidate);
    if (
      !Array.isArray(decoded)
      || decoded.length < 1
      || decoded.length > 64
      || decoded.some((item) => typeof item !== "string" || !/^[0-9a-f]{64}$/.test(item))
      || new Set(decoded).size !== decoded.length
      || decoded.some((item, index) => index > 0 && decoded[index - 1] >= item)
    ) return undefined;
    return Object.freeze([...decoded]);
  } catch {
    return undefined;
  }
}

function walletAuthConfiguration(): Readonly<{ domain: string; uri: string }> {
  const configuredDomain = clean(env.VITE_WALLET_AUTH_DOMAIN);
  const configuredUri = clean(env.VITE_WALLET_AUTH_URI);
  if (env.PROD) {
    if ((configuredDomain && configuredDomain !== PRODUCTION_WALLET_AUTH_DOMAIN)
      || (configuredUri && configuredUri !== PRODUCTION_WALLET_AUTH_URI)) {
      throw new Error("Production wallet auth must remain pinned to www.wikigen.me");
    }
    return Object.freeze({
      domain: PRODUCTION_WALLET_AUTH_DOMAIN,
      uri: PRODUCTION_WALLET_AUTH_URI,
    });
  }
  if (Boolean(configuredDomain) !== Boolean(configuredUri)) {
    throw new Error("Local wallet auth domain and URI must be configured together");
  }
  if (configuredDomain && configuredUri) {
    return Object.freeze({ domain: configuredDomain, uri: configuredUri });
  }
  const location = globalThis.location;
  if (location
    && ["http:", "https:"].includes(location.protocol)
    && ["localhost", "127.0.0.1", "[::1]", "::1"].includes(
      location.hostname.toLowerCase(),
    )) {
    return Object.freeze({
      domain: location.host.toLowerCase(),
      uri: location.origin,
    });
  }
  return Object.freeze({
    domain: "localhost:5175",
    uri: "http://localhost:5175",
  });
}

function boundedInteger(value: string | undefined, minimum: number, maximum: number): number | undefined {
  const candidate = clean(value);
  if (!/^(0|[1-9][0-9]*)$/.test(candidate)) return undefined;
  const parsed = Number(candidate);
  return Number.isSafeInteger(parsed) && parsed >= minimum && parsed <= maximum ? parsed : undefined;
}

export const BASE_SEPOLIA = {
  id: 84532,
  hexId: "0x14a34",
  name: "Base Sepolia",
  rpcUrl: clean(env.VITE_BASE_SEPOLIA_RPC_URL) || "https://sepolia.base.org",
  secondaryRpcUrl: clean(env.VITE_BASE_SEPOLIA_SECONDARY_RPC_URL),
  explorerUrl: "https://sepolia.basescan.org",
  currency: { name: "Sepolia Ether", symbol: "ETH", decimals: 18 },
} as const;

export const BASE_SEPOLIA_USDC_ADDRESS =
  "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;

const configuredUsdcAddress = address(env.VITE_USDC_ADDRESS);
const approvedUsdcAddress = configuredUsdcAddress?.toLowerCase()
  === BASE_SEPOLIA_USDC_ADDRESS.toLowerCase()
  ? configuredUsdcAddress
  : undefined;

export const computeVaultDeployment = parseComputeVaultConfig(env);
export const computeWorkloadDeployment = parseComputeWorkloadConfig(env);
export const diligenceEvaluatorDeployment = parseDiligenceEvaluatorConfig(env);

const executionPolicyAnchorAddress = address(env.VITE_EXECUTION_POLICY_ANCHOR_ADDRESS);
const executionPolicyAnchorCodeHash = bytes32(env.VITE_EXECUTION_POLICY_ANCHOR_CODE_HASH);
const executionPolicyAnchorWriter = address(env.VITE_EXECUTION_POLICY_ANCHOR_WRITER);
const executionPolicyAnchorWriterReleaseCommitment = bytes32(
  env.VITE_EXECUTION_POLICY_ANCHOR_WRITER_RELEASE_COMMITMENT,
);
const executionPolicyAnchorConfirmations = boundedInteger(
  env.VITE_EXECUTION_POLICY_ANCHOR_CONFIRMATIONS,
  2,
  256,
);
const executionPolicyAnchorMaxBlockAgeSeconds = boundedInteger(
  env.VITE_EXECUTION_POLICY_ANCHOR_MAX_BLOCK_AGE_SECONDS,
  30,
  3_600,
);
const executionPolicyAnchorMaxFutureBlockSkewSeconds = boundedInteger(
  env.VITE_EXECUTION_POLICY_ANCHOR_MAX_FUTURE_BLOCK_SKEW_SECONDS,
  0,
  300,
);
const executionPolicyAnchorRelease = executionPolicyAnchorAddress
  && executionPolicyAnchorCodeHash
  && executionPolicyAnchorWriter
  && executionPolicyAnchorWriterReleaseCommitment
  && executionPolicyAnchorConfirmations !== undefined
  && executionPolicyAnchorMaxBlockAgeSeconds !== undefined
  && executionPolicyAnchorMaxFutureBlockSkewSeconds !== undefined
  ? Object.freeze({
      address: executionPolicyAnchorAddress,
      runtimeCodeHash: executionPolicyAnchorCodeHash,
      writer: executionPolicyAnchorWriter,
      writerReleaseCommitment: executionPolicyAnchorWriterReleaseCommitment,
      confirmations: executionPolicyAnchorConfirmations,
      maxBlockAgeSeconds: executionPolicyAnchorMaxBlockAgeSeconds,
      maxFutureBlockSkewSeconds: executionPolicyAnchorMaxFutureBlockSkewSeconds,
    })
  : undefined;
const frontendReleaseIdentity = parseFrontendReleaseIdentity(env.VITE_RELEASE_SHA);
const royaltyRelease = parseRoyaltyReleaseConfiguration(env);
const collaborationFeatureEnabled = clean(env.VITE_ENABLE_COLLABORATION) === "true";
export const collaborationExecutionReleaseConfig =
  parseCollaborationExecutionReleaseConfig(env, {
    releaseSha: frontendReleaseIdentity.releaseSha,
    mainRuntimeCvmId: clean(env.VITE_PHALA_CVM_ID) || undefined,
    collaborationEnabled: collaborationFeatureEnabled,
    royaltyRelease,
  });
const walletAuth = walletAuthConfiguration();

export const deployment = {
  release: frontendReleaseIdentity.display,
  releaseSha: frontendReleaseIdentity.releaseSha,
  releaseIdentityStatus: frontendReleaseIdentity.status,
  verificationChainReleaseSha: frontendReleaseIdentity.verificationChainReleaseSha,
  contractAddress: address(env.VITE_DILIGENCE_ROOM_ADDRESS),
  contractCodeHash: bytes32(env.VITE_DILIGENCE_ROOM_CODE_HASH),
  contractDeveloper: address(env.VITE_DILIGENCE_ROOM_DEVELOPER),
  contractInitialDeveloper: address(env.VITE_DILIGENCE_ROOM_INITIAL_DEVELOPER),
  contractReleaseGovernanceController: address(
    env.VITE_DILIGENCE_ROOM_RELEASE_GOVERNANCE_CONTROLLER,
  ),
  resultVerifierAddress: address(env.VITE_DILIGENCE_RESULT_VERIFIER),
  attestationVerifierAddress: address(env.VITE_DILIGENCE_ATTESTATION_VERIFIER),
  attestationReleasePolicyHash: bytes32(env.VITE_DILIGENCE_QVL_RELEASE_POLICY_HASH),
  evaluatorPolicies: diligenceEvaluatorDeployment.descriptors,
  evaluatorPolicySetRoot: diligenceEvaluatorDeployment.policySetRoot,
  evaluatorPolicyReleaseConfigured: diligenceEvaluatorDeployment.configured,
  evaluatorPolicyReleaseIssues: diligenceEvaluatorDeployment.issues,
  challengeRegistryAddress: address(env.VITE_CHALLENGE_REGISTRY_ADDRESS),
  challengeRegistryCodeHash: bytes32(env.VITE_CHALLENGE_REGISTRY_CODE_HASH),
  royaltyDistributorAddress: address(env.VITE_ROYALTY_DISTRIBUTOR_ADDRESS),
  royaltyDistributorCodeHash: bytes32(env.VITE_ROYALTY_DISTRIBUTOR_CODE_HASH),
  royaltyRelease,
  collaborationExecutionRelease: collaborationExecutionReleaseConfig,
  teeIdentity: address(env.VITE_TEE_IDENTITY),
  emailOracleAuthAddress: address(env.VITE_EMAIL_ORACLE_AUTH_ADDRESS),
  emailOracleAuthCodeHash: bytes32(env.VITE_EMAIL_ORACLE_AUTH_CODE_HASH),
  encumbranceAddress: address(env.VITE_TINKER_ENCUMBRANCE_ADDRESS),
  encumbranceCodeHash: bytes32(env.VITE_TINKER_ENCUMBRANCE_CODE_HASH),
  delegateUrl: clean(env.VITE_DELEGATE_URL),
  appId: clean(env.VITE_PHALA_APP_ID),
  cvmId: clean(env.VITE_PHALA_CVM_ID),
  composeHash: clean(env.VITE_PHALA_COMPOSE_HASH),
  osImageHash: clean(env.VITE_PHALA_OS_IMAGE_HASH),
  imageDigest: clean(env.VITE_DELEGATE_IMAGE_DIGEST),
  walletConnectProjectId: clean(env.VITE_WALLETCONNECT_PROJECT_ID),
  walletAuthDomain: walletAuth.domain,
  walletAuthUri: walletAuth.uri,
  executionPolicyAnchorAddress,
  executionPolicyAnchorCodeHash,
  executionPolicyAnchorRelease,
  executionPolicyApprovalDomainHash: sha256(env.VITE_EXECUTION_POLICY_APPROVAL_DOMAIN_HASH),
  executionPolicyApproverRootHash: sha256(env.VITE_EXECUTION_POLICY_APPROVER_ROOT_HASH),
  executionPolicyApprovedApproverHashes: sha256ListJson(env.VITE_EXECUTION_POLICY_APPROVER_HASHES_JSON),
  usdcAddress: approvedUsdcAddress,
  contractWritesEnabled: clean(env.VITE_ENABLE_CONTRACT_WRITES) === "true",
  artifactUploadEnabled: clean(env.VITE_ENABLE_ARTIFACT_UPLOAD) === "true",
  artifactVerifiedQuoteSha256: clean(env.VITE_ARTIFACT_VERIFIED_QUOTE_SHA256),
  computeConsoleEnabled: clean(env.VITE_ENABLE_COMPUTE_CONSOLE) === "true",
  tinkerCustomerEnabled: clean(env.VITE_ENABLE_TINKER_CUSTOMER) === "true",
  collaborationEnabled: collaborationFeatureEnabled,
  arenaSubmissionEnabled: clean(env.VITE_ENABLE_ARENA_SUBMISSION) === "true",
  arenaVerifiedQuoteSha256: clean(env.VITE_ARENA_VERIFIED_QUOTE_SHA256),
  computeMeteringVerifiedQuoteSha256: clean(
    env.VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256,
  ),
  arenaChallengeRegistryBindingsJson: clean(env.VITE_ARENA_CHALLENGE_REGISTRY_BINDINGS_JSON),
  arenaApprovedChallengeSetSha256: sha256Pin(
    env.VITE_ARENA_APPROVED_CHALLENGE_SET_SHA256,
  ),
} as const;

export const hasFreshDeployment = Boolean(
  deployment.contractAddress && deployment.delegateUrl && deployment.composeHash,
);

export function explorerAddress(value: string): string {
  return `${BASE_SEPOLIA.explorerUrl}/address/${value}`;
}

export function explorerTx(value: string): string {
  return `${BASE_SEPOLIA.explorerUrl}/tx/${value}`;
}
