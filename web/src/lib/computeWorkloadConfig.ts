import { getAddress, type Address, type Hex } from "viem";
import type { ComputeWorkloadTrustPolicy } from "./computeWorkload";

type EnvLike = Record<string, unknown>;

export interface ComputeWorkloadDeploymentConfig {
  enabled: boolean;
  configured: boolean;
  trustPolicy?: ComputeWorkloadTrustPolicy;
  issues: readonly string[];
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const BYTES32 = /^0x[0-9a-fA-F]{64}$/;
const OS_IMAGE_HASH = /^(?!0{64}$)[0-9a-f]{64}$/;
const APP_ID = /^(?!0{40}$)[0-9a-f]{40}$/;
const CVM_ID = /^[a-z0-9][a-z0-9._:-]{7,127}$/;
const SHA256_PIN = /^sha256:(?!0{64}$)[0-9a-f]{64}$/;
const CANONICAL_BYTES32 = /^0x(?!0{64}$)[0-9a-f]{64}$/;

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
  if (!ADDRESS.test(value) || /^0x0{40}$/i.test(value)) {
    issues.push(`${key} must be a nonzero 20-byte 0x-prefixed address`);
    return undefined;
  }
  try {
    return getAddress(value).toLowerCase() as Address;
  } catch {
    issues.push(`${key} must be a valid Ethereum address`);
    return undefined;
  }
}

function bytes32Value(env: EnvLike, key: string, issues: string[]): Hex | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!BYTES32.test(value) || /^0x0{64}$/i.test(value)) {
    issues.push(`${key} must be a nonzero 32-byte 0x-prefixed value`);
    return undefined;
  }
  return value.toLowerCase() as Hex;
}

function canonicalBytes32Value(env: EnvLike, key: string, issues: string[]): Hex | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!CANONICAL_BYTES32.test(value)) {
    issues.push(`${key} must be a nonzero canonical lowercase 32-byte 0x-prefixed value`);
    return undefined;
  }
  return value as Hex;
}

function sha256PinValue(env: EnvLike, key: string, issues: string[]): string | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!SHA256_PIN.test(value)) {
    issues.push(`${key} must be a nonzero canonical lowercase sha256 pin`);
    return undefined;
  }
  return value;
}

function cvmIdValue(env: EnvLike, key: string, issues: string[]): string | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!CVM_ID.test(value)) {
    issues.push(`${key} must be a canonical lowercase CVM id`);
    return undefined;
  }
  return value;
}

function appIdValue(env: EnvLike, key: string, issues: string[]): string | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!APP_ID.test(value)) {
    issues.push(`${key} must be a nonzero lowercase bare 40-hex Phala app id`);
    return undefined;
  }
  return value;
}

function osImageHashValue(env: EnvLike, key: string, issues: string[]): string | undefined {
  const value = clean(env[key]).toLowerCase();
  if (!value) return undefined;
  if (!OS_IMAGE_HASH.test(value)) {
    issues.push(`${key} must be 64 nonzero lowercase hexadecimal characters without 0x`);
    return undefined;
  }
  return value;
}

function chainIdValue(env: EnvLike, key: string, issues: string[]): number | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (value !== "84532") {
    issues.push(`${key} must be exactly 84532 for Base Sepolia`);
    return undefined;
  }
  return 84_532;
}

function maxAgeValue(env: EnvLike, key: string, issues: string[]): number | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  if (!/^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$/.test(value)) {
    issues.push(`${key} must be an integer from 1 through 300 seconds`);
    return undefined;
  }
  return Number(value);
}

function revokedQuoteHashesValue(
  env: EnvLike,
  key: string,
  issues: string[],
): readonly Hex[] | undefined {
  const value = clean(env[key]);
  if (!value) return undefined;
  try {
    const decoded: unknown = JSON.parse(value);
    if (
      !Array.isArray(decoded)
      || decoded.length > 256
      || decoded.some((item) => typeof item !== "string" || !BYTES32.test(item) || /^0x0{64}$/i.test(item))
    ) {
      issues.push(`${key} must be a JSON array of at most 256 nonzero bytes32 quote hashes`);
      return undefined;
    }
    const normalized = decoded.map((item) => item.toLowerCase() as Hex);
    if (new Set(normalized).size !== normalized.length) {
      issues.push(`${key} must not contain duplicate quote hashes`);
      return undefined;
    }
    if (normalized.some((item, index) => index > 0 && normalized[index - 1] >= item)) {
      issues.push(`${key} quote hashes must be strictly sorted`);
      return undefined;
    }
    return Object.freeze(normalized);
  } catch {
    issues.push(`${key} must be valid JSON`);
    return undefined;
  }
}

function requireValue(
  required: boolean,
  value: unknown,
  key: string,
  issues: string[],
): void {
  if (required && value === undefined) issues.push(`${key} is required by the enabled Compute workload gate`);
}

export function parseComputeWorkloadConfig(env: EnvLike): ComputeWorkloadDeploymentConfig {
  const issues: string[] = [];
  const enabled = booleanValue(env, "VITE_ENABLE_COMPUTE_WORKLOAD_UPLOAD", issues);
  const verifier = addressValue(env, "VITE_COMPUTE_WORKLOAD_QVL_VERIFIER", issues);
  const cvmId = cvmIdValue(env, "VITE_COMPUTE_WORKLOAD_CVM_ID", issues);
  const deploymentIntentSha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
    issues,
  );
  const releaseAuthoritySha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
    issues,
  );
  const ceremonyNonce = canonicalBytes32Value(
    env,
    "VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE",
    issues,
  );
  const measurementPolicySetSha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
    issues,
  );
  const measurementPolicySha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256",
    issues,
  );
  const mainRuntimeEvidenceSha256 = sha256PinValue(
    env,
    "VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
    issues,
  );
  const releasePolicyHash = bytes32Value(
    env,
    "VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH",
    issues,
  );
  const composeHash = bytes32Value(env, "VITE_COMPUTE_WORKLOAD_COMPOSE_HASH", issues);
  const appId = appIdValue(env, "VITE_COMPUTE_WORKLOAD_APP_ID", issues);
  const osImageHash = osImageHashValue(env, "VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH", issues);
  const activationSignerAddress = addressValue(
    env,
    "VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER",
    issues,
  );
  if (Object.prototype.hasOwnProperty.call(env, "VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER")) {
    issues.push("VITE_COMPUTE_WORKLOAD_EXECUTION_SIGNER is rejected legacy; use the C-projected workload activation signer only");
  }
  const chainId = chainIdValue(env, "VITE_COMPUTE_WORKLOAD_CHAIN_ID", issues);
  const contractAddress = addressValue(env, "VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS", issues);
  const vaultRuntimeCodeHash = bytes32Value(
    env,
    "VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH",
    issues,
  );
  const freshDeploymentReceiptSha256 = bytes32Value(
    env,
    "VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
    issues,
  );
  const maxVerdictAgeSeconds = maxAgeValue(
    env,
    "VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS",
    issues,
  );
  const revokedQuoteHashes = revokedQuoteHashesValue(
    env,
    "VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON",
    issues,
  );
  const anyTrustValue = Boolean(
    verifier
      || cvmId
      || deploymentIntentSha256
      || releaseAuthoritySha256
      || ceremonyNonce
      || measurementPolicySetSha256
      || measurementPolicySha256
      || mainRuntimeEvidenceSha256
      || releasePolicyHash
      || composeHash
      || appId
      || osImageHash
      || activationSignerAddress
      || chainId
      || contractAddress
      || vaultRuntimeCodeHash
      || freshDeploymentReceiptSha256
      || maxVerdictAgeSeconds
      || (revokedQuoteHashes?.length ?? 0) > 0,
  );
  const required = enabled || anyTrustValue;

  const configuredVaultAddress = clean(env.VITE_COMPUTE_CREDIT_VAULT_ADDRESS);
  if (
    contractAddress
    && ADDRESS.test(configuredVaultAddress)
    && contractAddress !== configuredVaultAddress.toLowerCase()
  ) {
    issues.push("VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS must equal the configured ComputeCreditVault address");
  }
  const configuredVaultRuntimeCodeHash = clean(env.VITE_COMPUTE_CREDIT_VAULT_CODE_HASH).toLowerCase();
  if (
    vaultRuntimeCodeHash
    && BYTES32.test(configuredVaultRuntimeCodeHash)
    && vaultRuntimeCodeHash !== configuredVaultRuntimeCodeHash
  ) {
    issues.push("VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH must equal the configured ComputeCreditVault runtime hash");
  }
  if (verifier && activationSignerAddress && verifier === activationSignerAddress) {
    issues.push("Compute workload QVL verifier and activation signer must be distinct addresses");
  }

  requireValue(required, verifier, "VITE_COMPUTE_WORKLOAD_QVL_VERIFIER", issues);
  requireValue(required, cvmId, "VITE_COMPUTE_WORKLOAD_CVM_ID", issues);
  requireValue(
    required,
    deploymentIntentSha256,
    "VITE_COMPUTE_WORKLOAD_DEPLOYMENT_INTENT_SHA256",
    issues,
  );
  requireValue(
    required,
    releaseAuthoritySha256,
    "VITE_COMPUTE_WORKLOAD_RELEASE_AUTHORITY_SHA256",
    issues,
  );
  requireValue(required, ceremonyNonce, "VITE_COMPUTE_WORKLOAD_CEREMONY_NONCE", issues);
  requireValue(
    required,
    measurementPolicySetSha256,
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SET_SHA256",
    issues,
  );
  requireValue(
    required,
    measurementPolicySha256,
    "VITE_COMPUTE_WORKLOAD_MEASUREMENT_POLICY_SHA256",
    issues,
  );
  requireValue(
    required,
    mainRuntimeEvidenceSha256,
    "VITE_COMPUTE_WORKLOAD_MAIN_RUNTIME_EVIDENCE_SHA256",
    issues,
  );
  requireValue(required, releasePolicyHash, "VITE_COMPUTE_WORKLOAD_QVL_RELEASE_POLICY_HASH", issues);
  requireValue(required, composeHash, "VITE_COMPUTE_WORKLOAD_COMPOSE_HASH", issues);
  requireValue(required, appId, "VITE_COMPUTE_WORKLOAD_APP_ID", issues);
  requireValue(required, osImageHash, "VITE_COMPUTE_WORKLOAD_OS_IMAGE_HASH", issues);
  requireValue(required, activationSignerAddress, "VITE_COMPUTE_WORKLOAD_ACTIVATION_SIGNER", issues);
  requireValue(required, chainId, "VITE_COMPUTE_WORKLOAD_CHAIN_ID", issues);
  requireValue(required, contractAddress, "VITE_COMPUTE_WORKLOAD_CONTRACT_ADDRESS", issues);
  requireValue(
    required,
    vaultRuntimeCodeHash,
    "VITE_COMPUTE_WORKLOAD_VAULT_RUNTIME_CODE_HASH",
    issues,
  );
  requireValue(
    required,
    freshDeploymentReceiptSha256,
    "VITE_COMPUTE_WORKLOAD_FRESH_DEPLOYMENT_RECEIPT_SHA256",
    issues,
  );
  requireValue(
    required,
    maxVerdictAgeSeconds,
    "VITE_COMPUTE_WORKLOAD_MAX_VERDICT_AGE_SECONDS",
    issues,
  );
  requireValue(
    required,
    revokedQuoteHashes,
    "VITE_COMPUTE_WORKLOAD_REVOKED_QUOTE_HASHES_JSON",
    issues,
  );

  const trustPolicy = verifier
    && cvmId
    && deploymentIntentSha256
    && releaseAuthoritySha256
    && ceremonyNonce
    && measurementPolicySetSha256
    && measurementPolicySha256
    && mainRuntimeEvidenceSha256
    && releasePolicyHash
    && composeHash
    && appId
    && osImageHash
    && activationSignerAddress
    && chainId
    && contractAddress
    && vaultRuntimeCodeHash
    && freshDeploymentReceiptSha256
    && maxVerdictAgeSeconds
    && revokedQuoteHashes
    && issues.length === 0
      ? Object.freeze({
        trustedVerifierAddresses: Object.freeze([verifier]),
        cvmId,
        deploymentIntentSha256,
        releaseAuthoritySha256,
        ceremonyNonce,
        measurementPolicySetSha256,
        measurementPolicySha256,
        mainRuntimeEvidenceSha256,
        releasePolicyHash,
        composeHash,
        appId,
        osImageHash,
        activationSignerAddress,
        chainId,
        contractAddress,
        vaultRuntimeCodeHash,
        freshDeploymentReceiptSha256,
        maxVerdictAgeSeconds,
        revokedQuoteHashes,
      }) satisfies ComputeWorkloadTrustPolicy
    : undefined;

  return Object.freeze({
    enabled,
    configured: Boolean(enabled && trustPolicy),
    trustPolicy,
    issues: Object.freeze(issues),
  });
}
