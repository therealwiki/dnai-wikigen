import { getAddress, type Address, type Hex } from "viem";

type EnvLike = Record<string, unknown>;

export interface ComputeVaultTokenConfig {
  address: Address;
  codeHash: Hex;
  symbol: string;
  decimals: number;
  ratePolicyCommitment?: Hex;
}

export interface ComputeVaultDeploymentConfig {
  address?: Address;
  codeHash?: Hex;
  fundingEnabled: boolean;
  authorizationEnabled: boolean;
  developer?: Address;
  meteringVerifier?: Address;
  meteringQvlVerifier?: Address;
  meteringPolicySetHash?: Hex;
  meteringVerifiedQuoteSha256?: `sha256:${string}`;
  teeIdentity?: Address;
  composeHash?: Hex;
  nativeRatePolicyCommitment?: Hex;
  token?: ComputeVaultTokenConfig;
  fundingConfigured: boolean;
  authorizationConfigured: boolean;
  issues: readonly string[];
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const SHA256_PIN = /^sha256:[0-9a-f]{64}$/;

function clean(value: unknown): string {
  if (typeof value !== "string") return "";
  const normalized = value.trim();
  return normalized === "undefined" || normalized === "null" ? "" : normalized;
}

function booleanValue(env: EnvLike, key: string, issues: string[]): boolean {
  const value = clean(env[key]);
  if (!value || value === "false") return false;
  if (value === "true") return true;
  issues.push(`${key} must be exactly true or false`);
  return false;
}

function addressValue(env: EnvLike, key: string, issues: string[]): Address | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!ADDRESS.test(value)) {
    issues.push(`${key} must be a 20-byte 0x-prefixed address`);
    return undefined;
  }
  try {
    return getAddress(value);
  } catch {
    issues.push(`${key} must be a valid Ethereum address`);
    return undefined;
  }
}

function bytes32Value(env: EnvLike, key: string, issues: string[]): Hex | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!BYTES32.test(value)) {
    issues.push(`${key} must be a 32-byte 0x-prefixed value`);
    return undefined;
  }
  return value.toLowerCase() as Hex;
}

function sha256PinValue(
  env: EnvLike,
  key: string,
  issues: string[],
): `sha256:${string}` | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!SHA256_PIN.test(value)) {
    issues.push(`${key} must be sha256: followed by 64 lowercase hexadecimal characters`);
    return undefined;
  }
  return value as `sha256:${string}`;
}

function requireWhen(enabled: boolean, value: unknown, key: string, issues: string[]): void {
  if (enabled && value === undefined) issues.push(`${key} is required by the enabled Compute vault gate`);
}

export function parseComputeVaultConfig(env: EnvLike): ComputeVaultDeploymentConfig {
  const issues: string[] = [];
  const fundingEnabled = booleanValue(env, "VITE_ENABLE_COMPUTE_VAULT_FUNDING", issues);
  const authorizationEnabled = booleanValue(env, "VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION", issues);
  const address = addressValue(env, "VITE_COMPUTE_CREDIT_VAULT_ADDRESS", issues);
  const codeHash = bytes32Value(env, "VITE_COMPUTE_CREDIT_VAULT_CODE_HASH", issues);
  const developer = addressValue(env, "VITE_COMPUTE_VAULT_DEVELOPER", issues);
  const meteringVerifier = addressValue(env, "VITE_COMPUTE_VAULT_METERING_VERIFIER", issues);
  const meteringQvlVerifier = addressValue(
    env,
    "VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER",
    issues,
  );
  const meteringPolicySetHash = bytes32Value(
    env,
    "VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH",
    issues,
  );
  const meteringVerifiedQuoteSha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256",
    issues,
  );
  const teeIdentity = addressValue(env, "VITE_COMPUTE_VAULT_TEE_IDENTITY", issues);
  const composeHash = bytes32Value(env, "VITE_COMPUTE_VAULT_COMPOSE_HASH", issues);
  const nativeRatePolicyCommitment = bytes32Value(
    env,
    "VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT",
    issues,
  );

  const tokenAddress = addressValue(env, "VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS", issues);
  const tokenCodeHash = bytes32Value(env, "VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH", issues);
  const tokenRatePolicyCommitment = bytes32Value(
    env,
    "VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT",
    issues,
  );
  const tokenSymbol = clean(env.VITE_COMPUTE_VAULT_ERC20_SYMBOL).toUpperCase();
  const decimalsRaw = clean(env.VITE_COMPUTE_VAULT_ERC20_DECIMALS);
  const tokenGroupPresent = Boolean(
    tokenAddress || tokenCodeHash || tokenRatePolicyCommitment || tokenSymbol || decimalsRaw,
  );
  let tokenDecimals: number | undefined;
  if (decimalsRaw) {
    const candidate = Number(decimalsRaw);
    if (!Number.isInteger(candidate) || candidate < 0 || candidate > 36) {
      issues.push("VITE_COMPUTE_VAULT_ERC20_DECIMALS must be an integer from 0 through 36");
    } else {
      tokenDecimals = candidate;
    }
  }
  if (tokenSymbol && !/^[A-Z][A-Z0-9]{1,11}$/.test(tokenSymbol)) {
    issues.push("VITE_COMPUTE_VAULT_ERC20_SYMBOL must be 2-12 uppercase alphanumeric characters");
  }
  if (tokenGroupPresent) {
    requireWhen(true, tokenAddress, "VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS", issues);
    requireWhen(true, tokenCodeHash, "VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH", issues);
    requireWhen(true, tokenSymbol || undefined, "VITE_COMPUTE_VAULT_ERC20_SYMBOL", issues);
    requireWhen(true, tokenDecimals, "VITE_COMPUTE_VAULT_ERC20_DECIMALS", issues);
  }
  const fundingRequested = fundingEnabled || authorizationEnabled;
  if (fundingRequested && tokenGroupPresent) {
    requireWhen(
      true,
      tokenRatePolicyCommitment,
      "VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT",
      issues,
    );
  }
  if (fundingRequested && !tokenGroupPresent) {
    issues.push("enabled Compute vault funding requires the complete release-pinned ERC20 asset and rate policy");
  }

  requireWhen(fundingRequested, address, "VITE_COMPUTE_CREDIT_VAULT_ADDRESS", issues);
  requireWhen(fundingRequested, codeHash, "VITE_COMPUTE_CREDIT_VAULT_CODE_HASH", issues);
  if (authorizationEnabled && !fundingEnabled) {
    issues.push("VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION requires the funding gate");
  }
  requireWhen(fundingRequested, developer, "VITE_COMPUTE_VAULT_DEVELOPER", issues);
  requireWhen(
    fundingRequested,
    meteringVerifier,
    "VITE_COMPUTE_VAULT_METERING_VERIFIER",
    issues,
  );
  requireWhen(
    fundingRequested,
    meteringQvlVerifier,
    "VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER",
    issues,
  );
  if (
    meteringVerifier
    && meteringQvlVerifier
    && meteringVerifier.toLowerCase() === meteringQvlVerifier.toLowerCase()
  ) {
    issues.push("Compute vault meter and metering-QVL verifiers must be distinct");
  }
  requireWhen(
    fundingRequested,
    meteringPolicySetHash,
    "VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH",
    issues,
  );
  requireWhen(
    fundingRequested,
    meteringVerifiedQuoteSha256,
    "VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256",
    issues,
  );
  requireWhen(fundingRequested, teeIdentity, "VITE_COMPUTE_VAULT_TEE_IDENTITY", issues);
  requireWhen(fundingRequested, composeHash, "VITE_COMPUTE_VAULT_COMPOSE_HASH", issues);
  requireWhen(
    fundingRequested,
    nativeRatePolicyCommitment,
    "VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT",
    issues,
  );

  const token = tokenAddress && tokenCodeHash && tokenSymbol && tokenDecimals !== undefined
    ? {
        address: tokenAddress,
        codeHash: tokenCodeHash,
        symbol: tokenSymbol,
        decimals: tokenDecimals,
        ratePolicyCommitment: tokenRatePolicyCommitment,
      }
    : undefined;
  // Funding is risk-increasing in the vault and is guarded by the same exact,
  // frozen release policy as authorization and metering.
  const fundingConfigured = Boolean(
    address
      && codeHash
      && developer
      && meteringVerifier
      && meteringQvlVerifier
      && meteringPolicySetHash
      && meteringVerifiedQuoteSha256
      && teeIdentity
      && composeHash
      && nativeRatePolicyCommitment
      && token
      && token.ratePolicyCommitment
      && issues.length === 0,
  );
  const authorizationConfigured = Boolean(
    fundingConfigured
      && fundingEnabled
      && authorizationEnabled
      && developer
      && meteringVerifier
      && meteringQvlVerifier
      && meteringPolicySetHash
      && meteringVerifiedQuoteSha256
      && teeIdentity
      && composeHash
      && nativeRatePolicyCommitment
      && token
      && token.ratePolicyCommitment
      && issues.length === 0,
  );

  return {
    address,
    codeHash,
    fundingEnabled,
    authorizationEnabled,
    developer,
    meteringVerifier,
    meteringQvlVerifier,
    meteringPolicySetHash,
    meteringVerifiedQuoteSha256,
    teeIdentity,
    composeHash,
    nativeRatePolicyCommitment,
    token,
    fundingConfigured,
    authorizationConfigured,
    issues,
  };
}
