import {
  parseEventLogs,
  formatUnits,
  getAddress,
  keccak256,
  parseUnits,
  stringToHex,
  zeroAddress,
  zeroHash,
  type Address,
  type Hex,
} from "viem";
import { BASE_SEPOLIA, computeVaultDeployment } from "../config";
import type { ComputeVaultDeploymentConfig } from "./computeVaultConfig";
import { computeDispatchIntentCommitment } from "./computeDispatchCommitment";
import { publicClient } from "./contract";
import { wallet } from "./wallet";

const NONZERO_BYTES32 = /^0x(?!0{64}$)[0-9a-fA-F]{64}$/;
const UINT256_MAX = (1n << 256n) - 1n;

// invalidateAuthorizationNonce(max) would leave no value that authorizeJob can
// increment to. Keep that irreversible footgun out of the browser client.
export const MAX_VAULT_AUTHORIZATION_NONCE = UINT256_MAX - 1n;

export const computeCreditVaultAbi = [
  { type: "function", name: "paused", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "developer", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "meteringVerifier", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "meteringQvlVerifier", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "meteringPolicySetHash", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingMeteringVerifier", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "pendingMeteringQvlVerifier", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "pendingMeteringPolicySetHash", stateMutability: "view", inputs: [], outputs: [{ type: "bytes32" }] },
  { type: "function", name: "pendingMeteringBindingActivatesAt", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "meteringBindingFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "developerFeeFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "pendingDeveloperFeeActivatesAt", stateMutability: "view", inputs: [], outputs: [{ type: "uint64" }] },
  { type: "function", name: "composePolicyFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "teeIdentityAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "assetAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "ratePolicyAdditionsFrozen", stateMutability: "view", inputs: [], outputs: [{ type: "bool" }] },
  { type: "function", name: "allowedAssetCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "activeRatePolicyCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "approvedComposeCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "approvedTeeIdentityCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingAssetCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingRatePolicyCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingComposeCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  { type: "function", name: "pendingTeeIdentityCount", stateMutability: "view", inputs: [], outputs: [{ type: "uint256" }] },
  {
    type: "function",
    name: "allowedAssets",
    stateMutability: "view",
    inputs: [{ name: "asset", type: "address" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "approvedComposeHashes",
    stateMutability: "view",
    inputs: [{ name: "composeHash", type: "bytes32" }],
    outputs: [{ type: "bool" }],
  },
  {
    type: "function",
    name: "teeIdentityComposeHash",
    stateMutability: "view",
    inputs: [{ name: "teeIdentity", type: "address" }],
    outputs: [{ type: "bytes32" }],
  },
  {
    type: "function",
    name: "ratePolicies",
    stateMutability: "view",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [
      { name: "asset", type: "address" },
      { name: "provider", type: "address" },
      { name: "developerFeeBps", type: "uint16" },
      { name: "active", type: "bool" },
    ],
  },
  {
    type: "function",
    name: "credits",
    stateMutability: "view",
    inputs: [
      { name: "projectId", type: "bytes32" },
      { name: "user", type: "address" },
      { name: "asset", type: "address" },
    ],
    outputs: [
      { name: "available", type: "uint256" },
      { name: "reserved", type: "uint256" },
    ],
  },
  {
    type: "function",
    name: "nextAuthorizationNonce",
    stateMutability: "view",
    inputs: [{ name: "projectId", type: "bytes32" }, { name: "user", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "claimableAccrual",
    stateMutability: "view",
    inputs: [{ name: "asset", type: "address" }, { name: "recipient", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "getJob",
    stateMutability: "view",
    inputs: [{ name: "jobId", type: "bytes32" }],
    outputs: [{
      type: "tuple",
      components: [
        { name: "projectId", type: "bytes32" },
        { name: "user", type: "address" },
        { name: "asset", type: "address" },
        { name: "authorizationNonce", type: "uint256" },
        { name: "maxAssetDebit", type: "uint256" },
        { name: "actualAssetDebit", type: "uint256" },
        { name: "authorizationExpiry", type: "uint64" },
        { name: "startedAt", type: "uint64" },
        { name: "usageEndedAt", type: "uint64" },
        { name: "receiptExpiry", type: "uint64" },
        { name: "ratePolicyCommitment", type: "bytes32" },
        { name: "workloadCommitment", type: "bytes32" },
        { name: "manifestCommitment", type: "bytes32" },
        { name: "dispatchIntentCommitment", type: "bytes32" },
        { name: "composeHash", type: "bytes32" },
        { name: "startCommitment", type: "bytes32" },
        { name: "usageCommitment", type: "bytes32" },
        { name: "attestationEvidenceHash", type: "bytes32" },
        { name: "billableComputeUnits", type: "uint256" },
        { name: "teeIdentity", type: "address" },
        { name: "state", type: "uint8" },
      ],
    }],
  },
  {
    type: "function",
    name: "fundNative",
    stateMutability: "payable",
    inputs: [{ name: "projectId", type: "bytes32" }, { name: "beneficiary", type: "address" }],
    outputs: [],
  },
  {
    type: "function",
    name: "fundERC20",
    stateMutability: "nonpayable",
    inputs: [
      { name: "projectId", type: "bytes32" },
      { name: "beneficiary", type: "address" },
      { name: "asset", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "withdrawUnused",
    stateMutability: "nonpayable",
    inputs: [
      { name: "projectId", type: "bytes32" },
      { name: "asset", type: "address" },
      { name: "amount", type: "uint256" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "withdrawAccrued",
    stateMutability: "nonpayable",
    inputs: [{ name: "asset", type: "address" }],
    outputs: [],
  },
  {
    type: "function",
    name: "invalidateAuthorizationNonce",
    stateMutability: "nonpayable",
    inputs: [{ name: "projectId", type: "bytes32" }, { name: "newNonce", type: "uint256" }],
    outputs: [],
  },
  {
    type: "function",
    name: "authorizeJob",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "authorization",
        type: "tuple",
        components: [
          { name: "projectId", type: "bytes32" },
          { name: "jobId", type: "bytes32" },
          { name: "user", type: "address" },
          { name: "asset", type: "address" },
          { name: "nonce", type: "uint256" },
          { name: "maxAssetDebit", type: "uint256" },
          { name: "expiry", type: "uint256" },
          { name: "ratePolicyCommitment", type: "bytes32" },
          { name: "workloadCommitment", type: "bytes32" },
          { name: "manifestCommitment", type: "bytes32" },
          { name: "dispatchIntentCommitment", type: "bytes32" },
        ],
      },
      { name: "userSignature", type: "bytes" },
    ],
    outputs: [],
  },
  {
    type: "function",
    name: "cancelJob",
    stateMutability: "nonpayable",
    inputs: [{ name: "jobId", type: "bytes32" }],
    outputs: [],
  },
  {
    type: "function",
    name: "expireJob",
    stateMutability: "nonpayable",
    inputs: [{ name: "jobId", type: "bytes32" }],
    outputs: [],
  },
  {
    type: "event",
    name: "CreditFunded",
    anonymous: false,
    inputs: [
      { name: "projectId", type: "bytes32", indexed: true },
      { name: "beneficiary", type: "address", indexed: true },
      { name: "asset", type: "address", indexed: true },
      { name: "sponsor", type: "address", indexed: false },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "AuthorizationNonceInvalidated",
    anonymous: false,
    inputs: [
      { name: "projectId", type: "bytes32", indexed: true },
      { name: "user", type: "address", indexed: true },
      { name: "previousNonce", type: "uint256", indexed: false },
      { name: "newNonce", type: "uint256", indexed: false },
    ],
  },
  {
    type: "event",
    name: "AccrualWithdrawn",
    anonymous: false,
    inputs: [
      { name: "recipient", type: "address", indexed: true },
      { name: "asset", type: "address", indexed: true },
      { name: "amount", type: "uint256", indexed: false },
    ],
  },
] as const;

export const exactErc20Abi = [
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "account", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "allowance",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }, { name: "spender", type: "address" }],
    outputs: [{ type: "uint256" }],
  },
  {
    type: "function",
    name: "approve",
    stateMutability: "nonpayable",
    inputs: [{ name: "spender", type: "address" }, { name: "amount", type: "uint256" }],
    outputs: [{ type: "bool" }],
  },
  { type: "function", name: "symbol", stateMutability: "view", inputs: [], outputs: [{ type: "string" }] },
  { type: "function", name: "decimals", stateMutability: "view", inputs: [], outputs: [{ type: "uint8" }] },
] as const;

export type VaultAssetKind = "native" | "erc20";

export interface VaultRatePolicy {
  asset: Address;
  provider: Address;
  developerFeeBps: number;
  active: boolean;
}

export interface VaultCapacity {
  asset: Address;
  symbol: string;
  decimals: number;
  available: bigint;
  reserved: bigint;
}

export interface VaultChainSnapshot {
  runtimeCodeHash?: Hex;
  paused?: boolean;
  developer?: Address;
  meteringVerifier?: Address;
  meteringQvlVerifier?: Address;
  meteringPolicySetHash?: Hex;
  pendingMeteringVerifier?: Address;
  pendingMeteringQvlVerifier?: Address;
  pendingMeteringPolicySetHash?: Hex;
  pendingMeteringBindingActivatesAt?: bigint;
  meteringBindingFrozen?: boolean;
  developerFeeFrozen?: boolean;
  pendingDeveloperFeeActivatesAt?: bigint;
  composePolicyFrozen?: boolean;
  teeIdentityAdditionsFrozen?: boolean;
  assetAdditionsFrozen?: boolean;
  ratePolicyAdditionsFrozen?: boolean;
  allowedAssetCount?: bigint;
  activeRatePolicyCount?: bigint;
  approvedComposeCount?: bigint;
  approvedTeeIdentityCount?: bigint;
  pendingAssetCount?: bigint;
  pendingRatePolicyCount?: bigint;
  pendingComposeCount?: bigint;
  pendingTeeIdentityCount?: bigint;
  composeApproved?: boolean;
  teeComposeHash?: Hex;
  nativePolicy?: VaultRatePolicy;
  tokenPolicy?: VaultRatePolicy;
  tokenAllowed?: boolean;
  tokenRuntimeCodeHash?: Hex;
  tokenSymbol?: string;
  tokenDecimals?: number;
}

export interface VaultReadiness {
  deploymentVerified: boolean;
  withdrawalReady: boolean;
  nativeFundingReady: boolean;
  tokenFundingReady: boolean;
  nativeAuthorizationReady: boolean;
  tokenAuthorizationReady: boolean;
  deploymentReasons: readonly string[];
  fundingReasons: readonly string[];
  executionReasons: readonly string[];
  tokenReasons: readonly string[];
}

export interface ComputeVaultState {
  config: ComputeVaultDeploymentConfig;
  checkedAt: number;
  blockNumber?: bigint;
  projectId?: Hex;
  account?: Address;
  nativeCapacity?: VaultCapacity;
  tokenCapacity?: VaultCapacity;
  nextAuthorizationNonce?: bigint;
  nativeClaimableAccrual?: bigint;
  tokenClaimableAccrual?: bigint;
  snapshot: VaultChainSnapshot;
  readiness: VaultReadiness;
}

export interface VaultTokenSafetyIdentity {
  configured: boolean;
  verified: boolean;
  runtimeCodeHash?: Hex;
  symbol?: string;
  decimals?: number;
  reasons: readonly string[];
}

export interface ComputeVaultSafetyState {
  config: ComputeVaultDeploymentConfig;
  checkedAt: number;
  blockNumber?: bigint;
  runtimeCodeHash?: Hex;
  deploymentVerified: boolean;
  deploymentReasons: readonly string[];
  projectId?: Hex;
  account?: Address;
  nativeCapacity?: VaultCapacity;
  tokenCapacity?: VaultCapacity;
  nextAuthorizationNonce?: bigint;
  nativeClaimableAccrual?: bigint;
  tokenClaimableAccrual?: bigint;
  tokenIdentity: VaultTokenSafetyIdentity;
  readIssues: readonly string[];
}

function sameAddress(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function sameHex(left: string | undefined, right: string | undefined): boolean {
  return Boolean(left && right && left.toLowerCase() === right.toLowerCase());
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

export function assessComputeVaultReadiness(
  config: ComputeVaultDeploymentConfig,
  snapshot: VaultChainSnapshot,
): VaultReadiness {
  const deploymentReasons: string[] = [];
  if (!config.address || !config.codeHash) deploymentReasons.push("vault address and runtime code hash are not pinned");
  if (config.address && config.codeHash && !sameHex(snapshot.runtimeCodeHash, config.codeHash)) {
    deploymentReasons.push("live vault runtime code does not match the pinned release hash");
  }
  const deploymentVerified = Boolean(config.address && config.codeHash && deploymentReasons.length === 0);

  const releaseReasons = [...deploymentReasons];
  if (!config.fundingConfigured) releaseReasons.push("complete vault release roots are not configured");
  if (!sameAddress(snapshot.developer, config.developer)) releaseReasons.push("developer role does not match release configuration");
  if (!sameAddress(snapshot.meteringVerifier, config.meteringVerifier)) releaseReasons.push("metering verifier does not match release configuration");
  if (!sameAddress(snapshot.meteringQvlVerifier, config.meteringQvlVerifier)) {
    releaseReasons.push("metering QVL verifier does not match release configuration");
  }
  if (sameAddress(snapshot.meteringVerifier, snapshot.meteringQvlVerifier)) {
    releaseReasons.push("metering and metering QVL roles are not distinct");
  }
  if (!sameHex(snapshot.meteringPolicySetHash, config.meteringPolicySetHash)) {
    releaseReasons.push("metering policy set does not match release configuration");
  }
  if (snapshot.meteringBindingFrozen !== true) releaseReasons.push("metering binding is not verified frozen");
  if (!sameAddress(snapshot.pendingMeteringVerifier, zeroAddress)) releaseReasons.push("metering binding has an unexpected pending verifier");
  if (!sameAddress(snapshot.pendingMeteringQvlVerifier, zeroAddress)) {
    releaseReasons.push("metering binding has an unexpected pending QVL verifier");
  }
  if (!sameHex(snapshot.pendingMeteringPolicySetHash, zeroHash)) releaseReasons.push("metering binding has an unexpected pending policy set");
  if (snapshot.pendingMeteringBindingActivatesAt !== 0n) releaseReasons.push("metering binding has an unexpected pending activation");
  if (snapshot.developerFeeFrozen !== true) releaseReasons.push("developer fee is not verified frozen");
  if (snapshot.pendingDeveloperFeeActivatesAt !== 0n) releaseReasons.push("developer fee has an unexpected pending activation");
  if (snapshot.composePolicyFrozen !== true) releaseReasons.push("mandatory compose policy is not verified frozen");
  if (snapshot.teeIdentityAdditionsFrozen !== true) releaseReasons.push("TEE identity additions are not verified frozen");
  if (snapshot.assetAdditionsFrozen !== true) releaseReasons.push("asset additions are not verified frozen");
  if (snapshot.ratePolicyAdditionsFrozen !== true) releaseReasons.push("rate-policy additions are not verified frozen");
  if (snapshot.allowedAssetCount !== 1n) releaseReasons.push("allowed-asset set is not the exact one-asset release set");
  if (snapshot.activeRatePolicyCount !== 2n) releaseReasons.push("active rate-policy set is not the exact two-policy release set");
  if (snapshot.approvedComposeCount !== 1n) releaseReasons.push("approved compose set is not the exact one-compose release set");
  if (snapshot.approvedTeeIdentityCount !== 1n) releaseReasons.push("registered TEE set is not the exact one-identity release set");
  if (snapshot.pendingAssetCount !== 0n) releaseReasons.push("asset admission has an unexpected pending proposal");
  if (snapshot.pendingRatePolicyCount !== 0n) releaseReasons.push("rate-policy admission has an unexpected pending proposal");
  if (snapshot.pendingComposeCount !== 0n) releaseReasons.push("compose admission has an unexpected pending proposal");
  if (snapshot.pendingTeeIdentityCount !== 0n) releaseReasons.push("TEE identity admission has an unexpected pending proposal");
  if (snapshot.composeApproved !== true) releaseReasons.push("configured compose hash is not currently approved");
  if (!sameHex(snapshot.teeComposeHash, config.composeHash)) releaseReasons.push("TEE identity is not bound to the configured compose hash");
  if (!snapshot.nativePolicy?.active || !sameAddress(snapshot.nativePolicy.asset, zeroAddress)) {
    releaseReasons.push("native exact-asset rate policy is not active");
  }

  const fundingReasons = [...releaseReasons];
  if (!config.fundingEnabled) fundingReasons.push("vault funding is disabled by release configuration");
  if (snapshot.paused !== false) fundingReasons.push(snapshot.paused ? "vault is paused" : "vault pause state is unverified");
  const nativeFundingReady = deploymentVerified
    && config.fundingEnabled
    && config.fundingConfigured
    && fundingReasons.length === 0;

  const executionReasons = [...releaseReasons];
  if (!config.authorizationEnabled || !config.authorizationConfigured) {
    executionReasons.push("execution authorization release roots are incomplete or disabled");
  }
  if (snapshot.paused !== false) executionReasons.push(snapshot.paused ? "vault is paused" : "vault pause state is unverified");
  const nativeAuthorizationReady = deploymentVerified
    && config.authorizationConfigured
    && executionReasons.length === 0;

  const tokenReasons: string[] = [];
  if (!config.token) tokenReasons.push("no exact ERC20 asset is release configured");
  if (config.token && !sameHex(snapshot.tokenRuntimeCodeHash, config.token.codeHash)) {
    tokenReasons.push("ERC20 runtime code does not match the pinned hash");
  }
  if (config.token && snapshot.tokenSymbol !== config.token.symbol) tokenReasons.push("ERC20 symbol does not match release metadata");
  if (config.token && snapshot.tokenDecimals !== config.token.decimals) tokenReasons.push("ERC20 decimals do not match release metadata");
  if (config.token && snapshot.tokenAllowed !== true) tokenReasons.push("ERC20 asset is not currently allowlisted by the vault");
  if (
    config.token
    && (!config.token.ratePolicyCommitment
      || !snapshot.tokenPolicy?.active
      || !sameAddress(snapshot.tokenPolicy.asset, config.token.address))
  ) tokenReasons.push("ERC20 exact-asset rate policy is not active");
  const tokenFundingReady = nativeFundingReady && Boolean(config.token) && tokenReasons.length === 0;
  const tokenAuthorizationReady = nativeAuthorizationReady && tokenReasons.length === 0;

  return {
    deploymentVerified,
    withdrawalReady: deploymentVerified,
    nativeFundingReady,
    tokenFundingReady,
    nativeAuthorizationReady,
    tokenAuthorizationReady,
    deploymentReasons: unique(deploymentReasons),
    fundingReasons: unique(fundingReasons),
    executionReasons: unique(executionReasons),
    tokenReasons: unique(tokenReasons),
  };
}

function boundedReference(value: string, label: string): string {
  const normalized = value.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(normalized)) return normalized.toLowerCase();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(normalized)) {
    throw new Error(`${label} must be a bytes32 value or a bounded project identifier`);
  }
  return normalized;
}

export function computeVaultProjectId(reference: string): Hex {
  const normalized = boundedReference(reference, "Project reference");
  if (normalized.startsWith("0x")) {
    if (sameHex(normalized, zeroHash)) throw new Error("Project reference must be a nonzero bytes32 value");
    return normalized as Hex;
  }
  return keccak256(stringToHex(`dnai.wikigen.compute.project.v1:${normalized}`));
}

export function computeVaultJobId(reference: string): Hex {
  const normalized = boundedReference(reference, "Job reference");
  if (normalized.startsWith("0x")) {
    if (sameHex(normalized, zeroHash)) throw new Error("Job reference must be a nonzero bytes32 value");
    return normalized as Hex;
  }
  return keccak256(stringToHex(`dnai.wikigen.compute.job.v1:${normalized}`));
}

export function parseExactAssetAmount(value: string, decimals: number): bigint {
  const normalized = value.trim();
  if (normalized.length === 0 || normalized.length > 96 || decimals < 0 || decimals > 36) {
    throw new Error("Enter a bounded positive exact-asset amount");
  }
  const pattern = decimals === 0
    ? /^(?:0|[1-9][0-9]*)$/
    : new RegExp(`^(?:0|[1-9][0-9]*)(?:\\.[0-9]{1,${decimals}})?$`);
  if (!pattern.test(normalized)) throw new Error(`Amount must use at most ${decimals} decimal places`);
  const amount = parseUnits(normalized, decimals);
  if (amount <= 0n) throw new Error("Amount must be greater than zero");
  if (amount > UINT256_MAX) throw new Error("Amount exceeds the contract's uint256 limit");
  return amount;
}

export function normalizeVaultBeneficiary(value: string | undefined, fallback: Address): Address {
  const candidate = value?.trim() || fallback;
  try {
    const beneficiary = getAddress(candidate);
    if (sameAddress(beneficiary, zeroAddress)) throw new Error("zero address");
    return beneficiary;
  } catch {
    throw new Error("Capacity recipient must be one exact EVM address and cannot be zero");
  }
}

export function parseVaultAuthorizationNonce(value: string): bigint {
  const candidate = value.trim();
  if (!/^(?:0|[1-9][0-9]{0,77})$/.test(candidate)) {
    throw new Error("Authorization nonce must be one uint256 integer");
  }
  const nonce = BigInt(candidate);
  if (nonce > UINT256_MAX) throw new Error("Authorization nonce exceeds uint256");
  return nonce;
}

export function formatExactAssetAmount(value: bigint, decimals: number, maximumFractionDigits = 6): string {
  const [whole, fraction = ""] = formatUnits(value, decimals).split(".");
  const boundedFraction = fraction.slice(0, Math.max(0, maximumFractionDigits)).replace(/0+$/, "");
  return boundedFraction ? `${whole}.${boundedFraction}` : whole;
}

function unpackPolicy(value: readonly [Address, Address, number, boolean]): VaultRatePolicy {
  return { asset: value[0], provider: value[1], developerFeeBps: Number(value[2]), active: value[3] };
}

async function readCapacity(
  address: Address,
  projectId: Hex,
  account: Address,
  asset: Address,
  symbol: string,
  decimals: number,
  blockNumber: bigint,
): Promise<VaultCapacity> {
  const [available, reserved] = await publicClient.readContract({
    address,
    abi: computeCreditVaultAbi,
    functionName: "credits",
    args: [projectId, account, asset],
    blockNumber,
  });
  return { asset, symbol, decimals, available, reserved };
}

/**
 * Read only the code identity and account slots needed for risk-reducing user
 * actions. Governance, metering, compose, provider, and rate-policy reads are
 * intentionally absent so drift or RPC failure in those release surfaces
 * cannot hide nonce invalidation or asset exits.
 */
export async function loadComputeVaultSafetyState(
  account?: Address,
  projectReference?: string,
): Promise<ComputeVaultSafetyState> {
  const config = computeVaultDeployment;
  const projectId = projectReference ? computeVaultProjectId(projectReference) : undefined;
  const deploymentReasons: string[] = [];
  const readIssues: string[] = [];
  const tokenIdentity: VaultTokenSafetyIdentity = {
    configured: Boolean(config.token),
    verified: false,
    reasons: config.token ? [] : ["no ERC20 exit asset is release configured"],
  };
  const result = (): ComputeVaultSafetyState => ({
    config,
    checkedAt: Date.now(),
    blockNumber,
    runtimeCodeHash,
    deploymentVerified: deploymentReasons.length === 0 && Boolean(config.address && config.codeHash && runtimeCodeHash),
    deploymentReasons: unique(deploymentReasons),
    projectId,
    account,
    nativeCapacity,
    tokenCapacity,
    nextAuthorizationNonce,
    nativeClaimableAccrual,
    tokenClaimableAccrual,
    tokenIdentity,
    readIssues: unique(readIssues),
  });

  let blockNumber: bigint | undefined;
  let runtimeCodeHash: Hex | undefined;
  let nativeCapacity: VaultCapacity | undefined;
  let tokenCapacity: VaultCapacity | undefined;
  let nextAuthorizationNonce: bigint | undefined;
  let nativeClaimableAccrual: bigint | undefined;
  let tokenClaimableAccrual: bigint | undefined;

  if (!config.address || !config.codeHash) {
    deploymentReasons.push("vault address and runtime code hash are not pinned");
    return result();
  }

  blockNumber = await publicClient.getBlockNumber();
  const runtime = await publicClient.getBytecode({ address: config.address, blockNumber });
  runtimeCodeHash = runtime && runtime !== "0x" ? keccak256(runtime) : undefined;
  if (!sameHex(runtimeCodeHash, config.codeHash)) {
    deploymentReasons.push("live vault runtime code does not match the pinned release hash");
    return result();
  }

  if (config.token) {
    const tokenReasons: string[] = [];
    try {
      const tokenRuntime = await publicClient.getBytecode({ address: config.token.address, blockNumber });
      tokenIdentity.runtimeCodeHash = tokenRuntime && tokenRuntime !== "0x" ? keccak256(tokenRuntime) : undefined;
      if (!sameHex(tokenIdentity.runtimeCodeHash, config.token.codeHash)) {
        tokenReasons.push("configured ERC20 runtime does not match its release pin");
      } else {
        const [symbolRead, decimalsRead] = await Promise.allSettled([
          publicClient.readContract({
            address: config.token.address,
            abi: exactErc20Abi,
            functionName: "symbol",
            blockNumber,
          }),
          publicClient.readContract({
            address: config.token.address,
            abi: exactErc20Abi,
            functionName: "decimals",
            blockNumber,
          }),
        ]);
        if (symbolRead.status === "fulfilled") tokenIdentity.symbol = symbolRead.value;
        else tokenReasons.push("configured ERC20 symbol could not be read");
        if (decimalsRead.status === "fulfilled") tokenIdentity.decimals = decimalsRead.value;
        else tokenReasons.push("configured ERC20 decimals could not be read");
        if (tokenIdentity.symbol !== config.token.symbol) tokenReasons.push("configured ERC20 symbol does not match release metadata");
        if (tokenIdentity.decimals !== config.token.decimals) tokenReasons.push("configured ERC20 decimals do not match release metadata");
      }
    } catch {
      tokenReasons.push("configured ERC20 runtime could not be read");
    }
    tokenIdentity.reasons = unique(tokenReasons);
    tokenIdentity.verified = tokenReasons.length === 0;
  }

  const safetyReads: Array<Promise<void>> = [];
  if (account) {
    safetyReads.push(
      publicClient.readContract({
        address: config.address,
        abi: computeCreditVaultAbi,
        functionName: "claimableAccrual",
        args: [zeroAddress, account],
        blockNumber,
      }).then((value) => { nativeClaimableAccrual = value; }).catch(() => {
        readIssues.push("native wallet accrual could not be read");
      }),
    );
    if (config.token) {
      safetyReads.push(
        publicClient.readContract({
          address: config.address,
          abi: computeCreditVaultAbi,
          functionName: "claimableAccrual",
          args: [config.token.address, account],
          blockNumber,
        }).then((value) => { tokenClaimableAccrual = value; }).catch(() => {
          readIssues.push("configured ERC20 wallet accrual could not be read");
        }),
      );
    }
  }
  if (account && projectId) {
    safetyReads.push(
      readCapacity(config.address, projectId, account, zeroAddress, "ETH", 18, blockNumber)
        .then((value) => { nativeCapacity = value; })
        .catch(() => { readIssues.push("native project capacity could not be read"); }),
      publicClient.readContract({
        address: config.address,
        abi: computeCreditVaultAbi,
        functionName: "nextAuthorizationNonce",
        args: [projectId, account],
        blockNumber,
      }).then((value) => { nextAuthorizationNonce = value; }).catch(() => {
        readIssues.push("project authorization nonce could not be read");
      }),
    );
    if (config.token) {
      safetyReads.push(
        readCapacity(
          config.address,
          projectId,
          account,
          config.token.address,
          tokenIdentity.verified ? tokenIdentity.symbol! : "RAW BASE UNITS",
          tokenIdentity.verified ? tokenIdentity.decimals! : 0,
          blockNumber,
        ).then((value) => { tokenCapacity = value; }).catch(() => {
          readIssues.push("configured ERC20 project capacity could not be read");
        }),
      );
    }
  }
  await Promise.all(safetyReads);
  return result();
}

export async function loadComputeVaultState(
  account?: Address,
  projectReference?: string,
): Promise<ComputeVaultState> {
  const config = computeVaultDeployment;
  const projectId = projectReference ? computeVaultProjectId(projectReference) : undefined;
  const snapshot: VaultChainSnapshot = {};
  const empty = (blockNumber?: bigint): ComputeVaultState => ({
    config,
    checkedAt: Date.now(),
    blockNumber,
    projectId,
    account,
    snapshot,
    readiness: assessComputeVaultReadiness(config, snapshot),
  });
  if (!config.address || !config.codeHash) return empty();

  // Every release root and account balance below is evaluated at one immutable
  // block. Mixing latest-state reads could otherwise produce a readiness
  // result that never existed on chain.
  const blockNumber = await publicClient.getBlockNumber();
  const runtimeCode = await publicClient.getBytecode({ address: config.address, blockNumber });
  snapshot.runtimeCodeHash = runtimeCode && runtimeCode !== "0x" ? keccak256(runtimeCode) : undefined;
  if (!sameHex(snapshot.runtimeCodeHash, config.codeHash)) return empty(blockNumber);

  const [
    paused,
    developer,
    meteringVerifier,
    meteringQvlVerifier,
    meteringPolicySetHash,
    pendingMeteringVerifier,
    pendingMeteringQvlVerifier,
    pendingMeteringPolicySetHash,
    pendingMeteringBindingActivatesAt,
    meteringBindingFrozen,
    developerFeeFrozen,
    pendingDeveloperFeeActivatesAt,
    composePolicyFrozen,
    teeIdentityAdditionsFrozen,
    assetAdditionsFrozen,
    ratePolicyAdditionsFrozen,
    allowedAssetCount,
    activeRatePolicyCount,
    approvedComposeCount,
    approvedTeeIdentityCount,
    pendingAssetCount,
    pendingRatePolicyCount,
    pendingComposeCount,
    pendingTeeIdentityCount,
    composeApproved,
    teeComposeHash,
    nativePolicy,
  ] = await Promise.all([
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "paused", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "developer", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "meteringVerifier", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "meteringQvlVerifier", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "meteringPolicySetHash", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingMeteringVerifier", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingMeteringQvlVerifier", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingMeteringPolicySetHash", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingMeteringBindingActivatesAt", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "meteringBindingFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "developerFeeFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingDeveloperFeeActivatesAt", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "composePolicyFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "teeIdentityAdditionsFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "assetAdditionsFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "ratePolicyAdditionsFrozen", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "allowedAssetCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "activeRatePolicyCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "approvedComposeCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "approvedTeeIdentityCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingAssetCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingRatePolicyCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingComposeCount", blockNumber }),
    publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "pendingTeeIdentityCount", blockNumber }),
    config.composeHash
      ? publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "approvedComposeHashes", args: [config.composeHash], blockNumber })
      : Promise.resolve(undefined),
    config.teeIdentity
      ? publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "teeIdentityComposeHash", args: [config.teeIdentity], blockNumber })
      : Promise.resolve(undefined),
    config.nativeRatePolicyCommitment
      ? publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "ratePolicies", args: [config.nativeRatePolicyCommitment], blockNumber })
      : Promise.resolve(undefined),
  ]);
  Object.assign(snapshot, {
    paused,
    developer,
    meteringVerifier,
    meteringQvlVerifier,
    meteringPolicySetHash,
    pendingMeteringVerifier,
    pendingMeteringQvlVerifier,
    pendingMeteringPolicySetHash,
    pendingMeteringBindingActivatesAt,
    meteringBindingFrozen,
    developerFeeFrozen,
    pendingDeveloperFeeActivatesAt,
    composePolicyFrozen,
    teeIdentityAdditionsFrozen,
    assetAdditionsFrozen,
    ratePolicyAdditionsFrozen,
    allowedAssetCount,
    activeRatePolicyCount,
    approvedComposeCount,
    approvedTeeIdentityCount,
    pendingAssetCount,
    pendingRatePolicyCount,
    pendingComposeCount,
    pendingTeeIdentityCount,
    composeApproved,
    teeComposeHash,
    nativePolicy: nativePolicy ? unpackPolicy(nativePolicy) : undefined,
  });

  if (config.token) {
    const tokenRuntime = await publicClient.getBytecode({ address: config.token.address, blockNumber });
    snapshot.tokenRuntimeCodeHash = tokenRuntime && tokenRuntime !== "0x" ? keccak256(tokenRuntime) : undefined;
    const [tokenAllowed, tokenSymbol, tokenDecimals, tokenPolicy] = await Promise.all([
      publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "allowedAssets", args: [config.token.address], blockNumber }),
      publicClient.readContract({ address: config.token.address, abi: exactErc20Abi, functionName: "symbol", blockNumber }),
      publicClient.readContract({ address: config.token.address, abi: exactErc20Abi, functionName: "decimals", blockNumber }),
      config.token.ratePolicyCommitment
        ? publicClient.readContract({ address: config.address, abi: computeCreditVaultAbi, functionName: "ratePolicies", args: [config.token.ratePolicyCommitment], blockNumber })
        : Promise.resolve(undefined),
    ]);
    Object.assign(snapshot, {
      tokenAllowed,
      tokenSymbol,
      tokenDecimals,
      tokenPolicy: tokenPolicy ? unpackPolicy(tokenPolicy) : undefined,
    });
  }

  let nativeClaimableAccrual: bigint | undefined;
  let tokenClaimableAccrual: bigint | undefined;
  if (account) {
    [nativeClaimableAccrual, tokenClaimableAccrual] = await Promise.all([
      publicClient.readContract({
        address: config.address,
        abi: computeCreditVaultAbi,
        functionName: "claimableAccrual",
        args: [zeroAddress, account],
        blockNumber,
      }),
      config.token
        ? publicClient.readContract({
          address: config.address,
          abi: computeCreditVaultAbi,
          functionName: "claimableAccrual",
          args: [config.token.address, account],
          blockNumber,
        })
        : Promise.resolve(undefined),
    ]);
  }

  let nativeCapacity: VaultCapacity | undefined;
  let tokenCapacity: VaultCapacity | undefined;
  let nextAuthorizationNonce: bigint | undefined;
  if (account && projectId) {
    [
      nativeCapacity,
      tokenCapacity,
      nextAuthorizationNonce,
    ] = await Promise.all([
      readCapacity(config.address, projectId, account, zeroAddress, "ETH", 18, blockNumber),
      config.token
        ? readCapacity(config.address, projectId, account, config.token.address, config.token.symbol, config.token.decimals, blockNumber)
        : Promise.resolve(undefined),
      publicClient.readContract({
        address: config.address,
        abi: computeCreditVaultAbi,
        functionName: "nextAuthorizationNonce",
        args: [projectId, account],
        blockNumber,
      }),
    ]);
  }

  return {
    config,
    checkedAt: Date.now(),
    blockNumber,
    projectId,
    account,
    nativeCapacity,
    tokenCapacity,
    nextAuthorizationNonce,
    nativeClaimableAccrual,
    tokenClaimableAccrual,
    snapshot,
    readiness: assessComputeVaultReadiness(config, snapshot),
  };
}

export interface JobAuthorization {
  projectId: Hex;
  jobId: Hex;
  user: Address;
  asset: Address;
  nonce: bigint;
  maxAssetDebit: bigint;
  expiry: bigint;
  ratePolicyCommitment: Hex;
  workloadCommitment: Hex;
  manifestCommitment: Hex;
  dispatchIntentCommitment: Hex;
}

export interface VaultWorkloadAuthorizationBinding {
  workloadId: string;
  workloadSchema: "dnai.compute.workload.inference.v1" | "dnai.compute.workload.sft-jsonl.v1";
  workloadCommitment: Hex;
  manifestCommitment: Hex;
  operation: "inference" | "training";
  model: "qwen3_8b";
  recipe: "qwen3_8b_bounded" | "qwen3_8b_lora_r32";
  resultPolicy: "bounded_summary_receipt" | "score_band_hash";
  maxPrefillTokens: number;
  maxSampleTokens: number;
  maxTrainTokens: number;
}

export function buildJobAuthorizationTypedData(
  config: ComputeVaultDeploymentConfig,
  authorization: JobAuthorization,
) {
  if (!config.address) throw new Error("Compute vault address is not configured");
  return {
    account: authorization.user,
    domain: {
      name: "DNAI Compute Credit Vault",
      version: "2",
      chainId: BASE_SEPOLIA.id,
      verifyingContract: config.address,
    },
    types: {
      ComputeJobAuthorization: [
        { name: "projectId", type: "bytes32" },
        { name: "jobId", type: "bytes32" },
        { name: "user", type: "address" },
        { name: "asset", type: "address" },
        { name: "nonce", type: "uint256" },
        { name: "maxAssetDebit", type: "uint256" },
        { name: "expiry", type: "uint256" },
        { name: "ratePolicyCommitment", type: "bytes32" },
        { name: "workloadCommitment", type: "bytes32" },
        { name: "manifestCommitment", type: "bytes32" },
        { name: "dispatchIntentCommitment", type: "bytes32" },
      ],
    },
    primaryType: "ComputeJobAuthorization" as const,
    message: authorization,
  } as const;
}

async function walletContext(): Promise<{
  account: Address;
  client: NonNullable<ReturnType<typeof wallet.client>>;
  authorizationVersion: number;
}> {
  if (!wallet.account() || !wallet.client()) throw new Error("Connect a wallet before using exact-asset capacity");
  if (!wallet.isCorrectChain()) await wallet.switchToBase();
  const account = wallet.account();
  const client = wallet.client();
  if (!account || !client || !wallet.isCorrectChain()) throw new Error("Wallet is not connected to Base Sepolia");
  return { account, client, authorizationVersion: wallet.authorizationVersion() };
}

function assertStableWallet(
  expected: Address,
  expectedClient: NonNullable<ReturnType<typeof wallet.client>>,
  expectedAuthorizationVersion: number,
): void {
  if (
    !wallet.isCorrectChain()
    || !sameAddress(wallet.account(), expected)
    || wallet.client() !== expectedClient
    || wallet.authorizationVersion() !== expectedAuthorizationVersion
  ) {
    throw new Error("Wallet account, provider, or chain changed before transaction submission");
  }
}

type ComputeWriteReceipt = Awaited<ReturnType<typeof publicClient.waitForTransactionReceipt>>;

async function confirmWriteReceipt(
  account: Address,
  client: NonNullable<ReturnType<typeof wallet.client>>,
  authorizationVersion: number,
  request: unknown,
): Promise<{ hash: Hex; receipt: ComputeWriteReceipt }> {
  assertStableWallet(account, client, authorizationVersion);
  const hash = await client.writeContract(request as never) as Hex;
  const receipt = await publicClient.waitForTransactionReceipt({ hash, confirmations: 2, timeout: 120_000 });
  if (receipt.status !== "success") throw new Error("Base Sepolia transaction reverted");
  assertStableWallet(account, client, authorizationVersion);
  await wallet.refreshBalance(account);
  assertStableWallet(account, client, authorizationVersion);
  return { hash, receipt };
}

async function confirmWrite(
  account: Address,
  client: NonNullable<ReturnType<typeof wallet.client>>,
  authorizationVersion: number,
  request: unknown,
): Promise<Hex> {
  return (await confirmWriteReceipt(account, client, authorizationVersion, request)).hash;
}

type ComputeVaultReceiptEvent = "CreditFunded" | "AuthorizationNonceInvalidated" | "AccrualWithdrawn";

function exactVaultReceiptEvent(
  receipt: ComputeWriteReceipt,
  vaultAddress: Address,
  eventName: ComputeVaultReceiptEvent,
): Record<string, unknown> {
  const events = parseEventLogs({
    abi: computeCreditVaultAbi,
    eventName,
    logs: receipt.logs,
    strict: true,
  }).filter((event) => sameAddress(event.address, vaultAddress));
  if (events.length !== 1) {
    throw new Error(`Confirmed transaction did not emit one exact ${eventName} event from the pinned Compute vault`);
  }
  return events[0].args as unknown as Record<string, unknown>;
}

export async function fundVaultNative(
  projectReference: string,
  amount: bigint,
  beneficiaryInput?: string,
): Promise<Hex> {
  if (amount <= 0n || amount > UINT256_MAX) throw new Error("Funding amount must be one positive uint256 value");
  const { account, client, authorizationVersion } = await walletContext();
  const beneficiary = normalizeVaultBeneficiary(beneficiaryInput, account);
  const state = await loadComputeVaultState(account, projectReference);
  if (!state.readiness.nativeFundingReady || !state.config.address || !state.projectId) {
    throw new Error(state.readiness.fundingReasons[0] ?? "Native capacity funding is not release ready");
  }
  const { request } = await publicClient.simulateContract({
    account,
    address: state.config.address,
    abi: computeCreditVaultAbi,
    functionName: "fundNative",
    args: [state.projectId, beneficiary],
    value: amount,
  });
  const confirmed = await confirmWriteReceipt(account, client, authorizationVersion, request);
  const funded = exactVaultReceiptEvent(confirmed.receipt, state.config.address, "CreditFunded");
  if (
    !sameHex(funded.projectId as string | undefined, state.projectId)
    || !sameAddress(funded.beneficiary as string | undefined, beneficiary)
    || !sameAddress(funded.asset as string | undefined, zeroAddress)
    || !sameAddress(funded.sponsor as string | undefined, account)
    || funded.amount !== amount
  ) throw new Error("Confirmed native funding event does not match the payer, beneficiary, project, asset, and amount");
  return confirmed.hash;
}

export async function fundVaultErc20(
  projectReference: string,
  amount: bigint,
  beneficiaryInput?: string,
): Promise<Hex> {
  if (amount <= 0n || amount > UINT256_MAX) throw new Error("Funding amount must be one positive uint256 value");
  const { account, client, authorizationVersion } = await walletContext();
  const beneficiary = normalizeVaultBeneficiary(beneficiaryInput, account);
  let state = await loadComputeVaultState(account, projectReference);
  const token = state.config.token;
  if (!state.readiness.tokenFundingReady || !state.config.address || !state.projectId || !token) {
    throw new Error(state.readiness.tokenReasons[0] ?? state.readiness.fundingReasons[0] ?? "ERC20 capacity funding is not release ready");
  }
  const vaultAddress = state.config.address;
  const projectId = state.projectId;
  const [walletBalance, allowance] = await Promise.all([
    publicClient.readContract({ address: token.address, abi: exactErc20Abi, functionName: "balanceOf", args: [account] }),
    publicClient.readContract({ address: token.address, abi: exactErc20Abi, functionName: "allowance", args: [account, vaultAddress] }),
  ]);
  if (walletBalance < amount) throw new Error(`Wallet does not hold enough ${token.symbol}`);
  if (allowance < amount) {
    const { request } = await publicClient.simulateContract({
      account,
      address: token.address,
      abi: exactErc20Abi,
      functionName: "approve",
      args: [vaultAddress, amount],
    });
    await confirmWrite(account, client, authorizationVersion, request);
    state = await loadComputeVaultState(account, projectReference);
    if (!state.readiness.tokenFundingReady) throw new Error("Vault release state changed after ERC20 approval");
  }
  const { request } = await publicClient.simulateContract({
    account,
    address: vaultAddress,
    abi: computeCreditVaultAbi,
    functionName: "fundERC20",
    args: [projectId, beneficiary, token.address, amount],
  });
  const confirmed = await confirmWriteReceipt(account, client, authorizationVersion, request);
  const funded = exactVaultReceiptEvent(confirmed.receipt, vaultAddress, "CreditFunded");
  if (
    !sameHex(funded.projectId as string | undefined, projectId)
    || !sameAddress(funded.beneficiary as string | undefined, beneficiary)
    || !sameAddress(funded.asset as string | undefined, token.address)
    || !sameAddress(funded.sponsor as string | undefined, account)
    || funded.amount !== amount
  ) throw new Error("Confirmed ERC20 funding event does not match the payer, beneficiary, project, asset, and amount");
  return confirmed.hash;
}

export async function withdrawVaultUnused(
  projectReference: string,
  assetKind: VaultAssetKind,
  amount: bigint,
): Promise<Hex> {
  if (amount <= 0n) throw new Error("Withdrawal amount must be greater than zero");
  const { account, client, authorizationVersion } = await walletContext();
  const state = await loadComputeVaultSafetyState(account, projectReference);
  const capacity = assetKind === "native" ? state.nativeCapacity : state.tokenCapacity;
  if (!state.deploymentVerified || !state.config.address || !state.projectId) {
    throw new Error(state.deploymentReasons[0] ?? "Safety withdrawal is not bound to the pinned vault runtime");
  }
  if (!capacity) throw new Error(state.readIssues[0] ?? "Selected project capacity could not be read");
  if (amount > capacity.available) throw new Error("Withdrawal exceeds wallet-owned available capacity");
  const { request } = await publicClient.simulateContract({
    account,
    address: state.config.address,
    abi: computeCreditVaultAbi,
    functionName: "withdrawUnused",
    args: [state.projectId, capacity.asset, amount],
  });
  return confirmWrite(account, client, authorizationVersion, request);
}

export async function invalidateVaultAuthorizationNonce(
  projectReference: string,
  newNonce: bigint,
): Promise<Hex> {
  if (newNonce < 0n || newNonce > UINT256_MAX) throw new Error("Authorization nonce must be one uint256 integer");
  if (newNonce > MAX_VAULT_AUTHORIZATION_NONCE) {
    throw new Error("Authorization nonce cannot equal uint256 maximum because that would permanently block future job authorization");
  }
  const { account, client, authorizationVersion } = await walletContext();
  const state = await loadComputeVaultSafetyState(account, projectReference);
  if (
    !state.deploymentVerified
    || !state.config.address
    || !state.projectId
  ) {
    throw new Error(state.deploymentReasons[0] ?? "Nonce invalidation is not bound to the pinned vault runtime");
  }
  if (state.nextAuthorizationNonce === undefined) {
    throw new Error(state.readIssues[0] ?? "Project authorization nonce could not be read");
  }
  if (newNonce <= state.nextAuthorizationNonce) {
    throw new Error(`New nonce must be greater than the current nonce ${state.nextAuthorizationNonce.toString()}`);
  }
  const { request } = await publicClient.simulateContract({
    account,
    address: state.config.address,
    abi: computeCreditVaultAbi,
    functionName: "invalidateAuthorizationNonce",
    args: [state.projectId, newNonce],
  });
  const confirmed = await confirmWriteReceipt(account, client, authorizationVersion, request);
  const invalidated = exactVaultReceiptEvent(confirmed.receipt, state.config.address, "AuthorizationNonceInvalidated");
  if (
    !sameHex(invalidated.projectId as string | undefined, state.projectId)
    || !sameAddress(invalidated.user as string | undefined, account)
    || invalidated.previousNonce !== state.nextAuthorizationNonce
    || invalidated.newNonce !== newNonce
  ) throw new Error("Confirmed nonce invalidation event does not match the connected user, project, or nonce transition");
  return confirmed.hash;
}

export async function withdrawVaultAccrued(
  assetKind: VaultAssetKind,
): Promise<{ hash: Hex; amount: bigint; symbol: string; decimals: number; unitVerified: boolean }> {
  const { account, client, authorizationVersion } = await walletContext();
  const state = await loadComputeVaultSafetyState(account);
  const token = state.config.token;
  const asset = assetKind === "native" ? zeroAddress : token?.address;
  const amount = assetKind === "native" ? state.nativeClaimableAccrual : state.tokenClaimableAccrual;
  const unitVerified = assetKind === "native" || state.tokenIdentity.verified;
  const symbol = assetKind === "native"
    ? "ETH"
    : unitVerified ? state.tokenIdentity.symbol : "raw base units";
  const decimals = assetKind === "native"
    ? 18
    : unitVerified ? state.tokenIdentity.decimals : 0;
  if (!state.deploymentVerified || !state.config.address || !asset || !symbol || decimals === undefined) {
    throw new Error(state.deploymentReasons[0] ?? "Accrued withdrawal is not bound to the pinned vault runtime");
  }
  if (amount === undefined) throw new Error(state.readIssues[0] ?? "Selected wallet accrual could not be read");
  if (amount <= 0n) throw new Error(`No ${symbol} provider or developer accrual is claimable by this wallet`);
  const { request } = await publicClient.simulateContract({
    account,
    address: state.config.address,
    abi: computeCreditVaultAbi,
    functionName: "withdrawAccrued",
    args: [asset],
  });
  const confirmed = await confirmWriteReceipt(account, client, authorizationVersion, request);
  const withdrawn = exactVaultReceiptEvent(confirmed.receipt, state.config.address, "AccrualWithdrawn");
  if (
    !sameAddress(withdrawn.recipient as string | undefined, account)
    || !sameAddress(withdrawn.asset as string | undefined, asset)
    || typeof withdrawn.amount !== "bigint"
    || withdrawn.amount <= 0n
  ) throw new Error("Confirmed accrual withdrawal event does not match the connected recipient and exact asset");
  return { hash: confirmed.hash, amount: withdrawn.amount, symbol, decimals, unitVerified };
}

function validateWorkloadAuthorizationBinding(
  binding: VaultWorkloadAuthorizationBinding,
): void {
  if (!/^wrk_[0-9a-f]{32}$/.test(binding.workloadId)) {
    throw new Error("Prepare a sealed workload before authorizing the job");
  }
  if (
    !NONZERO_BYTES32.test(binding.workloadCommitment)
    || !NONZERO_BYTES32.test(binding.manifestCommitment)
  ) {
    throw new Error("Workload and manifest commitments must be exact nonzero bytes32 values");
  }
  const limits = [binding.maxPrefillTokens, binding.maxSampleTokens, binding.maxTrainTokens];
  if (limits.some((value) => !Number.isSafeInteger(value) || value < 0 || value > 100_000_000)) {
    throw new Error("Workload authorization limits are outside the bounded release policy");
  }
  if (
    binding.model !== "qwen3_8b"
    || !["inference", "training"].includes(binding.operation)
    || !["bounded_summary_receipt", "score_band_hash"].includes(binding.resultPolicy)
    || (binding.operation === "inference" && (
      binding.workloadSchema !== "dnai.compute.workload.inference.v1"
      || binding.recipe !== "qwen3_8b_bounded"
      || binding.maxPrefillTokens < 1
      || binding.maxPrefillTokens > 32_768
      || binding.maxSampleTokens < 1
      || binding.maxSampleTokens > 4_096
      || binding.maxTrainTokens !== 0
    ))
    || (binding.operation === "training" && (
      binding.workloadSchema !== "dnai.compute.workload.sft-jsonl.v1"
      || binding.recipe !== "qwen3_8b_lora_r32"
      || binding.maxPrefillTokens !== 0
      || binding.maxSampleTokens !== 0
      || binding.maxTrainTokens < 1
      || binding.maxTrainTokens > 10_000_000
    ))
  ) {
    throw new Error("Workload binding does not match a compiled release recipe");
  }
}

export async function authorizeVaultJob(input: {
  projectReference: string;
  jobReference: string;
  assetKind: VaultAssetKind;
  maxAssetDebit: bigint;
  lifetimeSeconds: number;
  workload: VaultWorkloadAuthorizationBinding;
}): Promise<{ hash: Hex; jobId: Hex; authorization: JobAuthorization }> {
  if (input.maxAssetDebit <= 0n) throw new Error("Job cap must be greater than zero");
  if (!Number.isInteger(input.lifetimeSeconds) || input.lifetimeSeconds < 900 || input.lifetimeSeconds > 604_800) {
    throw new Error("Authorization lifetime must be between 15 minutes and 7 days");
  }
  validateWorkloadAuthorizationBinding(input.workload);
  const { account, client, authorizationVersion } = await walletContext();
  const state = await loadComputeVaultState(account, input.projectReference);
  const ready = input.assetKind === "native"
    ? state.readiness.nativeAuthorizationReady
    : state.readiness.tokenAuthorizationReady;
  const capacity = input.assetKind === "native" ? state.nativeCapacity : state.tokenCapacity;
  const policy = input.assetKind === "native"
    ? state.config.nativeRatePolicyCommitment
    : state.config.token?.ratePolicyCommitment;
  if (!ready || !state.config.address || !state.projectId || !capacity || !policy || state.nextAuthorizationNonce === undefined) {
    throw new Error(state.readiness.executionReasons[0] ?? state.readiness.tokenReasons[0] ?? "Execution authorization is fail closed");
  }
  if (input.maxAssetDebit > capacity.available) throw new Error("Job cap exceeds wallet-owned available capacity");
  const block = await publicClient.getBlock({ blockTag: "latest" });
  const jobId = computeVaultJobId(input.jobReference);
  const expiry = block.timestamp + BigInt(input.lifetimeSeconds);
  const dispatchIntentCommitment = computeDispatchIntentCommitment({
    projectReference: input.projectReference,
    jobReference: input.jobReference,
    projectId: state.projectId,
    jobId,
    user: account,
    asset: capacity.asset,
    authorizationNonce: state.nextAuthorizationNonce,
    maxAssetDebit: input.maxAssetDebit,
    authorizationExpiry: Number(expiry),
    ratePolicyCommitment: policy,
    composeHash: state.config.composeHash!,
    operation: input.workload.operation,
    model: input.workload.model,
    recipe: input.workload.recipe,
    resultPolicy: input.workload.resultPolicy,
    maxPrefillTokens: input.workload.maxPrefillTokens,
    maxSampleTokens: input.workload.maxSampleTokens,
    maxTrainTokens: input.workload.maxTrainTokens,
    workloadId: input.workload.workloadId,
    workloadSchema: input.workload.workloadSchema,
    manifestCommitment: input.workload.manifestCommitment,
    workloadCommitment: input.workload.workloadCommitment,
  });
  const authorization: JobAuthorization = {
    projectId: state.projectId,
    jobId,
    user: account,
    asset: capacity.asset,
    nonce: state.nextAuthorizationNonce,
    maxAssetDebit: input.maxAssetDebit,
    expiry,
    ratePolicyCommitment: policy,
    workloadCommitment: input.workload.workloadCommitment,
    manifestCommitment: input.workload.manifestCommitment,
    dispatchIntentCommitment,
  };
  assertStableWallet(account, client, authorizationVersion);
  const signature = await client.signTypedData(buildJobAuthorizationTypedData(state.config, authorization));
  assertStableWallet(account, client, authorizationVersion);
  const refreshed = await loadComputeVaultState(account, input.projectReference);
  if (
    refreshed.nextAuthorizationNonce !== authorization.nonce
    || !(input.assetKind === "native" ? refreshed.readiness.nativeAuthorizationReady : refreshed.readiness.tokenAuthorizationReady)
  ) throw new Error("Vault nonce or release state changed while signing; no transaction was submitted");
  const { request } = await publicClient.simulateContract({
    account,
    address: state.config.address,
    abi: computeCreditVaultAbi,
    functionName: "authorizeJob",
    args: [authorization, signature],
  });
  const hash = await confirmWrite(account, client, authorizationVersion, request);
  return { hash, jobId: authorization.jobId, authorization };
}

export interface VaultJob {
  projectId: Hex;
  user: Address;
  asset: Address;
  authorizationNonce: bigint;
  maxAssetDebit: bigint;
  actualAssetDebit: bigint;
  authorizationExpiry: bigint;
  startedAt: bigint;
  usageEndedAt: bigint;
  receiptExpiry: bigint;
  ratePolicyCommitment: Hex;
  workloadCommitment: Hex;
  manifestCommitment: Hex;
  dispatchIntentCommitment: Hex;
  composeHash: Hex;
  startCommitment: Hex;
  usageCommitment: Hex;
  attestationEvidenceHash: Hex;
  billableComputeUnits: bigint;
  teeIdentity: Address;
  state: number;
}

export interface VaultJobRead {
  jobId: Hex;
  job: VaultJob;
  blockNumber: bigint;
  blockTimestamp: bigint;
}

export async function loadVaultJob(jobReference: string, pinnedBlockNumber?: bigint): Promise<VaultJobRead> {
  const config = computeVaultDeployment;
  if (!config.address || !config.codeHash) throw new Error("Vault deployment is not pinned");
  const blockNumber = pinnedBlockNumber ?? await publicClient.getBlockNumber();
  const runtimeCode = await publicClient.getBytecode({ address: config.address, blockNumber });
  if (!runtimeCode || !sameHex(keccak256(runtimeCode), config.codeHash)) throw new Error("Vault runtime code hash mismatch");
  const jobId = computeVaultJobId(jobReference);
  const [job, block] = await Promise.all([
    publicClient.readContract({
      address: config.address,
      abi: computeCreditVaultAbi,
      functionName: "getJob",
      args: [jobId],
      blockNumber,
    }),
    publicClient.getBlock({ blockNumber }),
  ]);
  return {
    jobId,
    job: { ...job, state: Number(job.state) },
    blockNumber,
    blockTimestamp: block.timestamp,
  };
}

export async function cancelVaultJob(jobReference: string): Promise<Hex> {
  const { account, client, authorizationVersion } = await walletContext();
  const config = computeVaultDeployment;
  const { jobId, job } = await loadVaultJob(jobReference);
  if (!config.address || !sameAddress(job.user, account)) throw new Error("Connected wallet does not own this job authorization");
  if (job.state !== 1) throw new Error("Only an authorized, not-yet-started job can be cancelled");
  const { request } = await publicClient.simulateContract({
    account,
    address: config.address,
    abi: computeCreditVaultAbi,
    functionName: "cancelJob",
    args: [jobId],
  });
  return confirmWrite(account, client, authorizationVersion, request);
}

export async function expireVaultJob(jobReference: string): Promise<Hex> {
  const { account, client, authorizationVersion } = await walletContext();
  const config = computeVaultDeployment;
  const { jobId, job } = await loadVaultJob(jobReference);
  if (!config.address || (job.state !== 1 && job.state !== 2)) throw new Error("Job is not open for expiry release");
  const block = await publicClient.getBlock({ blockTag: "latest" });
  if (block.timestamp <= job.authorizationExpiry) throw new Error("Job authorization has not expired yet");
  const { request } = await publicClient.simulateContract({
    account,
    address: config.address,
    abi: computeCreditVaultAbi,
    functionName: "expireJob",
    args: [jobId],
  });
  return confirmWrite(account, client, authorizationVersion, request);
}
