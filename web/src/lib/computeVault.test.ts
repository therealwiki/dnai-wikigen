import { afterEach, describe, expect, it, vi } from "vitest";
import {
  encodeAbiParameters,
  encodeEventTopics,
  keccak256,
  zeroAddress,
  zeroHash,
  type Address,
  type Hex,
} from "viem";
import { computeVaultDeployment } from "../config";
import {
  assessComputeVaultReadiness,
  authorizeVaultJob,
  buildJobAuthorizationTypedData,
  computeCreditVaultAbi,
  computeVaultJobId,
  computeVaultProjectId,
  formatExactAssetAmount,
  fundVaultErc20,
  fundVaultNative,
  invalidateVaultAuthorizationNonce,
  loadComputeVaultSafetyState,
  loadComputeVaultState,
  loadVaultJob,
  MAX_VAULT_AUTHORIZATION_NONCE,
  normalizeVaultBeneficiary,
  parseExactAssetAmount,
  parseVaultAuthorizationNonce,
  withdrawVaultAccrued,
  withdrawVaultUnused,
  type VaultChainSnapshot,
} from "./computeVault";
import { parseComputeVaultConfig } from "./computeVaultConfig";
import { publicClient } from "./contract";
import { wallet } from "./wallet";

const vault = "0x1111111111111111111111111111111111111111";
const developer = "0x2222222222222222222222222222222222222222";
const verifier = "0x3333333333333333333333333333333333333333";
const qvlVerifier = "0x7777777777777777777777777777777777777777";
const tee = "0x4444444444444444444444444444444444444444";
const token = "0x5555555555555555555555555555555555555555";
const provider = "0x6666666666666666666666666666666666666666";
const hash = `0x${"ab".repeat(32)}` as Hex;
const tokenHash = `0x${"cd".repeat(32)}` as Hex;
const nativePolicy = `0x${"11".repeat(32)}` as Hex;
const tokenPolicy = `0x${"22".repeat(32)}` as Hex;
const meteringPolicySet = `0x${"33".repeat(32)}` as Hex;
const meteringQuotePin = `sha256:${"44".repeat(32)}`;

function configured() {
  return parseComputeVaultConfig({
    VITE_ENABLE_COMPUTE_VAULT_FUNDING: "true",
    VITE_ENABLE_COMPUTE_VAULT_AUTHORIZATION: "true",
    VITE_COMPUTE_CREDIT_VAULT_ADDRESS: vault,
    VITE_COMPUTE_CREDIT_VAULT_CODE_HASH: hash,
    VITE_COMPUTE_VAULT_DEVELOPER: developer,
    VITE_COMPUTE_VAULT_METERING_VERIFIER: verifier,
    VITE_COMPUTE_VAULT_METERING_QVL_VERIFIER: qvlVerifier,
    VITE_COMPUTE_VAULT_METERING_POLICY_SET_HASH: meteringPolicySet,
    VITE_COMPUTE_METERING_VERIFIED_QUOTE_SHA256: meteringQuotePin,
    VITE_COMPUTE_VAULT_TEE_IDENTITY: tee,
    VITE_COMPUTE_VAULT_COMPOSE_HASH: hash,
    VITE_COMPUTE_VAULT_NATIVE_RATE_POLICY_COMMITMENT: nativePolicy,
    VITE_COMPUTE_VAULT_ERC20_ASSET_ADDRESS: token,
    VITE_COMPUTE_VAULT_ERC20_ASSET_CODE_HASH: tokenHash,
    VITE_COMPUTE_VAULT_ERC20_SYMBOL: "USDC",
    VITE_COMPUTE_VAULT_ERC20_DECIMALS: "6",
    VITE_COMPUTE_VAULT_ERC20_RATE_POLICY_COMMITMENT: tokenPolicy,
  });
}

function liveSnapshot(): VaultChainSnapshot {
  return {
    runtimeCodeHash: hash,
    paused: false,
    developer: developer as Address,
    meteringVerifier: verifier as Address,
    meteringQvlVerifier: qvlVerifier as Address,
    meteringPolicySetHash: meteringPolicySet,
    pendingMeteringVerifier: zeroAddress,
    pendingMeteringQvlVerifier: zeroAddress,
    pendingMeteringPolicySetHash: zeroHash,
    pendingMeteringBindingActivatesAt: 0n,
    meteringBindingFrozen: true,
    developerFeeFrozen: true,
    pendingDeveloperFeeActivatesAt: 0n,
    composePolicyFrozen: true,
    teeIdentityAdditionsFrozen: true,
    assetAdditionsFrozen: true,
    ratePolicyAdditionsFrozen: true,
    allowedAssetCount: 1n,
    activeRatePolicyCount: 2n,
    approvedComposeCount: 1n,
    approvedTeeIdentityCount: 1n,
    pendingAssetCount: 0n,
    pendingRatePolicyCount: 0n,
    pendingComposeCount: 0n,
    pendingTeeIdentityCount: 0n,
    composeApproved: true,
    teeComposeHash: hash,
    nativePolicy: { asset: zeroAddress, provider: provider as Address, developerFeeBps: 500, active: true },
    tokenPolicy: { asset: token as Address, provider: provider as Address, developerFeeBps: 500, active: true },
    tokenAllowed: true,
    tokenRuntimeCodeHash: tokenHash,
    tokenSymbol: "USDC",
    tokenDecimals: 6,
  };
}

describe("Compute vault fail-closed readiness", () => {
  it("requires every pinned root before exposing execution authorization", () => {
    const status = assessComputeVaultReadiness(configured(), liveSnapshot());
    expect(status.deploymentVerified).toBe(true);
    expect(status.nativeFundingReady).toBe(true);
    expect(status.tokenFundingReady).toBe(true);
    expect(status.nativeAuthorizationReady).toBe(true);
    expect(status.tokenAuthorizationReady).toBe(true);
  });

  it("blocks every action on a runtime code mismatch", () => {
    const status = assessComputeVaultReadiness(configured(), {
      ...liveSnapshot(),
      runtimeCodeHash: `0x${"ff".repeat(32)}` as Hex,
    });
    expect(status.deploymentVerified).toBe(false);
    expect(status.withdrawalReady).toBe(false);
    expect(status.nativeFundingReady).toBe(false);
    expect(status.nativeAuthorizationReady).toBe(false);
  });

  it("keeps safety withdrawal available while pause blocks funding and authorization", () => {
    const status = assessComputeVaultReadiness(configured(), { ...liveSnapshot(), paused: true });
    expect(status.withdrawalReady).toBe(true);
    expect(status.nativeFundingReady).toBe(false);
    expect(status.nativeAuthorizationReady).toBe(false);
    expect(status.fundingReasons).toContain("vault is paused");
  });

  it("isolates token metadata failure without misrepresenting native capacity", () => {
    const status = assessComputeVaultReadiness(configured(), { ...liveSnapshot(), tokenDecimals: 18 });
    expect(status.nativeFundingReady).toBe(true);
    expect(status.nativeAuthorizationReady).toBe(true);
    expect(status.tokenFundingReady).toBe(false);
    expect(status.tokenAuthorizationReady).toBe(false);
  });

  it("fails token funding closed when the exact token rate policy is inactive or misbound", () => {
    for (const tokenPolicyDrift of [
      { asset: token as Address, provider: provider as Address, developerFeeBps: 500, active: false },
      { asset: developer as Address, provider: provider as Address, developerFeeBps: 500, active: true },
    ]) {
      const status = assessComputeVaultReadiness(configured(), {
        ...liveSnapshot(),
        tokenPolicy: tokenPolicyDrift,
      });
      expect(status.nativeFundingReady).toBe(true);
      expect(status.tokenFundingReady).toBe(false);
      expect(status.tokenAuthorizationReady).toBe(false);
      expect(status.tokenReasons).toContain("ERC20 exact-asset rate policy is not active");
    }
  });

  it("fails execution closed when compose, TEE, or policy roots drift", () => {
    const status = assessComputeVaultReadiness(configured(), {
      ...liveSnapshot(),
      composeApproved: false,
      teeComposeHash: tokenHash,
      nativePolicy: { asset: zeroAddress, provider: provider as Address, developerFeeBps: 500, active: false },
    });
    expect(status.nativeFundingReady).toBe(false);
    expect(status.nativeAuthorizationReady).toBe(false);
    expect(status.executionReasons.join(" ")).toMatch(/compose/);
    expect(status.executionReasons.join(" ")).toMatch(/TEE/);
    expect(status.executionReasons.join(" ")).toMatch(/rate policy/);
  });

  it("fails execution closed for a surplus registered or pending admission", () => {
    for (const mutation of [
      { approvedTeeIdentityCount: 2n },
      { pendingAssetCount: 1n },
      { pendingRatePolicyCount: 1n },
      { pendingComposeCount: 1n },
      { pendingTeeIdentityCount: 1n },
    ]) {
      const status = assessComputeVaultReadiness(configured(), { ...liveSnapshot(), ...mutation });
      expect(status.nativeAuthorizationReady).toBe(false);
      expect(status.nativeFundingReady).toBe(false);
    }
  });

  it("fails authorization closed unless the governance sets are frozen and exact", () => {
    for (const drift of [
      { assetAdditionsFrozen: false },
      { ratePolicyAdditionsFrozen: false },
      { teeIdentityAdditionsFrozen: false },
      { meteringBindingFrozen: false },
      { allowedAssetCount: 2n },
      { activeRatePolicyCount: 3n },
      { approvedComposeCount: 2n },
    ]) {
      const status = assessComputeVaultReadiness(configured(), { ...liveSnapshot(), ...drift });
      expect(status.nativeFundingReady).toBe(false);
      expect(status.nativeAuthorizationReady).toBe(false);
      expect(status.tokenAuthorizationReady).toBe(false);
    }
  });

  it("fails funding and authorization closed when the metering policy cross-binding drifts", () => {
    for (const drift of [
      { meteringPolicySetHash: tokenHash },
      { meteringQvlVerifier: verifier as Address },
      { pendingMeteringVerifier: verifier as Address },
      { pendingMeteringQvlVerifier: qvlVerifier as Address },
      { pendingMeteringPolicySetHash: tokenHash },
      { pendingMeteringBindingActivatesAt: 1n },
      { pendingDeveloperFeeActivatesAt: 1n },
    ]) {
      const status = assessComputeVaultReadiness(configured(), { ...liveSnapshot(), ...drift });
      expect(status.nativeFundingReady).toBe(false);
      expect(status.nativeAuthorizationReady).toBe(false);
    }
  });
});

describe("Compute vault identifiers and exact amounts", () => {
  it("domain-separates deterministic project and job identifiers", () => {
    expect(computeVaultProjectId("project_alpha")).toBe(computeVaultProjectId("project_alpha"));
    expect(computeVaultProjectId("project_alpha")).not.toBe(computeVaultJobId("project_alpha"));
    expect(computeVaultProjectId(hash)).toBe(hash);
  });

  it("rejects unbounded references and ambiguous amount syntax", () => {
    expect(() => computeVaultProjectId("../../project")).toThrow(/bounded/);
    expect(() => parseExactAssetAmount("1e6", 6)).toThrow(/decimal places/);
    expect(() => parseExactAssetAmount("01", 6)).toThrow(/decimal places/);
    expect(() => parseExactAssetAmount("0", 6)).toThrow(/greater than zero/);
    expect(() => parseExactAssetAmount("1.0000001", 6)).toThrow(/decimal places/);
  });

  it("parses and formats only the configured asset unit", () => {
    expect(parseExactAssetAmount("12.345678", 6)).toBe(12_345_678n);
    expect(formatExactAssetAmount(12_345_678n, 6)).toBe("12.345678");
    expect(formatExactAssetAmount(1_500_000_000_000_000_000n, 18)).toBe("1.5");
  });

  it("accepts only an exact beneficiary address and uint256 nonce", () => {
    expect(normalizeVaultBeneficiary("", developer as Address).toLowerCase()).toBe(developer);
    expect(normalizeVaultBeneficiary(provider, developer as Address).toLowerCase()).toBe(provider);
    expect(() => normalizeVaultBeneficiary("vitalik.eth", developer as Address)).toThrow(/exact EVM address/);
    expect(() => normalizeVaultBeneficiary("0x1234", developer as Address)).toThrow(/exact EVM address/);
    expect(() => normalizeVaultBeneficiary(zeroAddress, developer as Address)).toThrow(/cannot be zero/);
    expect(parseVaultAuthorizationNonce("10")).toBe(10n);
    expect(() => parseVaultAuthorizationNonce("01")).toThrow(/uint256/);
    expect(() => parseVaultAuthorizationNonce("-1")).toThrow(/uint256/);
    expect(() => parseVaultAuthorizationNonce((1n << 256n).toString())).toThrow(/exceeds uint256/);
    expect(MAX_VAULT_AUTHORIZATION_NONCE).toBe((1n << 256n) - 2n);
  });

  it("rejects explicit zero project and job identifiers", () => {
    expect(() => computeVaultProjectId(zeroHash)).toThrow(/nonzero bytes32/);
    expect(() => computeVaultJobId(zeroHash)).toThrow(/nonzero bytes32/);
  });
});

describe("Compute vault EIP-712 ABI", () => {
  const validWorkload = {
    workloadId: `wrk_${"1".repeat(32)}`,
    workloadSchema: "dnai.compute.workload.inference.v1" as const,
    workloadCommitment: `0x${"44".repeat(32)}` as Hex,
    manifestCommitment: `0x${"55".repeat(32)}` as Hex,
    operation: "inference" as const,
    model: "qwen3_8b" as const,
    recipe: "qwen3_8b_bounded" as const,
    resultPolicy: "bounded_summary_receipt" as const,
    maxPrefillTokens: 1_024,
    maxSampleTokens: 128,
    maxTrainTokens: 0,
  };

  it("uses the contract's exact authorization domain and field order", () => {
    const config = configured();
    const message = {
      projectId: hash,
      jobId: tokenHash,
      user: developer as Address,
      asset: zeroAddress,
      nonce: 7n,
      maxAssetDebit: 9n,
      expiry: 100n,
      ratePolicyCommitment: nativePolicy,
      workloadCommitment: `0x${"44".repeat(32)}` as Hex,
      manifestCommitment: `0x${"55".repeat(32)}` as Hex,
      dispatchIntentCommitment: `0x${"66".repeat(32)}` as Hex,
    };
    const typedData = buildJobAuthorizationTypedData(config, message);
    expect(typedData.domain).toMatchObject({
      name: "DNAI Compute Credit Vault",
      version: "2",
      chainId: 84532,
      verifyingContract: vault,
    });
    expect(typedData.types.ComputeJobAuthorization.map((field) => field.name)).toEqual([
      "projectId",
      "jobId",
      "user",
      "asset",
      "nonce",
      "maxAssetDebit",
      "expiry",
      "ratePolicyCommitment",
      "workloadCommitment",
      "manifestCommitment",
      "dispatchIntentCommitment",
    ]);
    expect(typedData.types.ComputeJobAuthorization.map((field) => `${field.name}:${field.type}`)).toEqual([
      "projectId:bytes32",
      "jobId:bytes32",
      "user:address",
      "asset:address",
      "nonce:uint256",
      "maxAssetDebit:uint256",
      "expiry:uint256",
      "ratePolicyCommitment:bytes32",
      "workloadCommitment:bytes32",
      "manifestCommitment:bytes32",
      "dispatchIntentCommitment:bytes32",
    ]);
    expect(typedData.primaryType).toBe("ComputeJobAuthorization");
  });

  it("pins the exact v2 authorization and 21-field job tuple shapes", () => {
    const authorization = computeCreditVaultAbi.find((entry) => entry.name === "authorizeJob") as unknown as {
      inputs: readonly [{ components: readonly { name: string; type: string }[] }];
    };
    expect(authorization.inputs[0].components.map((field) => `${field.name}:${field.type}`)).toEqual([
      "projectId:bytes32",
      "jobId:bytes32",
      "user:address",
      "asset:address",
      "nonce:uint256",
      "maxAssetDebit:uint256",
      "expiry:uint256",
      "ratePolicyCommitment:bytes32",
      "workloadCommitment:bytes32",
      "manifestCommitment:bytes32",
      "dispatchIntentCommitment:bytes32",
    ]);

    const getJob = computeCreditVaultAbi.find((entry) => entry.name === "getJob") as unknown as {
      outputs: readonly [{ components: readonly { name: string; type: string }[] }];
    };
    expect(getJob.outputs[0].components.map((field) => `${field.name}:${field.type}`)).toEqual([
      "projectId:bytes32",
      "user:address",
      "asset:address",
      "authorizationNonce:uint256",
      "maxAssetDebit:uint256",
      "actualAssetDebit:uint256",
      "authorizationExpiry:uint64",
      "startedAt:uint64",
      "usageEndedAt:uint64",
      "receiptExpiry:uint64",
      "ratePolicyCommitment:bytes32",
      "workloadCommitment:bytes32",
      "manifestCommitment:bytes32",
      "dispatchIntentCommitment:bytes32",
      "composeHash:bytes32",
      "startCommitment:bytes32",
      "usageCommitment:bytes32",
      "attestationEvidenceHash:bytes32",
      "billableComputeUnits:uint256",
      "teeIdentity:address",
      "state:uint8",
    ]);
  });

  it("rejects malformed or non-release workload metadata before opening a wallet flow", async () => {
    const authorize = (workload: typeof validWorkload) => authorizeVaultJob({
      projectReference: "project-alpha",
      jobReference: "job-alpha",
      assetKind: "native",
      maxAssetDebit: 1n,
      lifetimeSeconds: 900,
      workload,
    });
    await expect(authorize({
      ...validWorkload,
      workloadCommitment: "0x12" as Hex,
    })).rejects.toThrow(/exact nonzero bytes32/);
    await expect(authorize({
      ...validWorkload,
      operation: "arbitrary_program" as never,
    })).rejects.toThrow(/compiled release recipe/);
    await expect(authorize({
      ...validWorkload,
      resultPolicy: "raw_output" as never,
    })).rejects.toThrow(/compiled release recipe/);
  });

  it("does not expose TEE-only dispatch or metering writes in the browser ABI", () => {
    const names = computeCreditVaultAbi.map((entry) => entry.name);
    expect(names).toContain("authorizeJob");
    expect(names).toContain("cancelJob");
    expect(names).toContain("invalidateAuthorizationNonce");
    expect(names).toContain("claimableAccrual");
    expect(names).toContain("withdrawAccrued");
    expect(names).not.toContain("startJob");
    expect(names).not.toContain("submitMeteringReceipt");
  });
});

describe("Compute vault pinned-block reads", () => {
  const originalDeployment = {
    ...computeVaultDeployment,
    issues: [...computeVaultDeployment.issues],
    token: computeVaultDeployment.token ? { ...computeVaultDeployment.token } : undefined,
  };
  const runtime = "0x60006000" as Hex;
  const blockNumber = 12_345n;

  afterEach(() => {
    Object.assign(computeVaultDeployment, originalDeployment);
    vi.restoreAllMocks();
  });

  function configurePinnedRuntime(): void {
    Object.assign(computeVaultDeployment, {
      address: vault as Address,
      codeHash: keccak256(runtime),
      fundingEnabled: true,
      authorizationEnabled: false,
      developer: undefined,
      meteringVerifier: undefined,
      meteringQvlVerifier: undefined,
      meteringPolicySetHash: undefined,
      teeIdentity: undefined,
      composeHash: undefined,
      nativeRatePolicyCommitment: undefined,
      token: undefined,
      fundingConfigured: true,
      authorizationConfigured: false,
      issues: [],
    });
  }

  it("evaluates runtime, roles, policy state, and balances at one block", async () => {
    configurePinnedRuntime();
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const bytecodeRead = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const contractRead = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "paused") return false;
      if (request.functionName === "developer") return developer;
      if (request.functionName === "meteringVerifier") return verifier;
      if (request.functionName === "meteringQvlVerifier") return qvlVerifier;
      if (request.functionName === "meteringPolicySetHash") return meteringPolicySet;
      if (request.functionName === "pendingMeteringVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringQvlVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringPolicySetHash") return zeroHash;
      if (["pendingMeteringBindingActivatesAt", "pendingDeveloperFeeActivatesAt"].includes(request.functionName)) return 0n;
      if (["meteringBindingFrozen", "developerFeeFrozen", "composePolicyFrozen", "teeIdentityAdditionsFrozen", "assetAdditionsFrozen", "ratePolicyAdditionsFrozen"].includes(request.functionName)) return true;
      if (request.functionName === "allowedAssetCount" || request.functionName === "approvedComposeCount") return 1n;
      if (request.functionName === "activeRatePolicyCount") return 2n;
      if (request.functionName === "approvedTeeIdentityCount") return 1n;
      if (["pendingAssetCount", "pendingRatePolicyCount", "pendingComposeCount", "pendingTeeIdentityCount"].includes(request.functionName)) return 0n;
      if (request.functionName === "credits") return [4n, 2n];
      if (request.functionName === "nextAuthorizationNonce") return 9n;
      if (request.functionName === "claimableAccrual") return 3n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await loadComputeVaultState(developer as Address, "project-alpha");

    expect(result.blockNumber).toBe(blockNumber);
    expect(result.nativeCapacity).toMatchObject({ available: 4n, reserved: 2n });
    expect(result.nativeClaimableAccrual).toBe(3n);
    expect(bytecodeRead).toHaveBeenCalledWith(expect.objectContaining({ blockNumber }));
    for (const [request] of contractRead.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
  });

  it("reads wallet-wide accrual without requiring a project", async () => {
    configurePinnedRuntime();
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "paused") return false;
      if (request.functionName === "developer") return developer;
      if (request.functionName === "meteringVerifier") return verifier;
      if (request.functionName === "meteringQvlVerifier") return qvlVerifier;
      if (request.functionName === "meteringPolicySetHash") return meteringPolicySet;
      if (request.functionName === "pendingMeteringVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringQvlVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringPolicySetHash") return zeroHash;
      if (["pendingMeteringBindingActivatesAt", "pendingDeveloperFeeActivatesAt"].includes(request.functionName)) return 0n;
      if (["meteringBindingFrozen", "developerFeeFrozen", "composePolicyFrozen", "teeIdentityAdditionsFrozen", "assetAdditionsFrozen", "ratePolicyAdditionsFrozen"].includes(request.functionName)) return true;
      if (request.functionName === "allowedAssetCount" || request.functionName === "approvedComposeCount") return 1n;
      if (request.functionName === "activeRatePolicyCount") return 2n;
      if (request.functionName === "approvedTeeIdentityCount") return 1n;
      if (["pendingAssetCount", "pendingRatePolicyCount", "pendingComposeCount", "pendingTeeIdentityCount"].includes(request.functionName)) return 0n;
      if (request.functionName === "claimableAccrual") return 17n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const result = await loadComputeVaultState(developer as Address);

    expect(result.projectId).toBeUndefined();
    expect(result.nativeCapacity).toBeUndefined();
    expect(result.nextAuthorizationNonce).toBeUndefined();
    expect(result.nativeClaimableAccrual).toBe(17n);
    expect(reads).toHaveBeenCalledWith(expect.objectContaining({
      functionName: "claimableAccrual",
      args: [zeroAddress, developer],
      blockNumber,
    }));
  });

  it("evaluates job runtime, tuple, and expiry clock at one block", async () => {
    configurePinnedRuntime();
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const bytecodeRead = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const contractRead = vi.spyOn(publicClient, "readContract").mockResolvedValue({
      projectId: hash,
      user: developer as Address,
      asset: zeroAddress,
      authorizationNonce: 1n,
      maxAssetDebit: 2n,
      actualAssetDebit: 0n,
      authorizationExpiry: 20_000n,
      startedAt: 0n,
      usageEndedAt: 0n,
      receiptExpiry: 0n,
      ratePolicyCommitment: nativePolicy,
      workloadCommitment: `0x${"44".repeat(32)}` as Hex,
      manifestCommitment: `0x${"55".repeat(32)}` as Hex,
      dispatchIntentCommitment: `0x${"66".repeat(32)}` as Hex,
      composeHash: hash,
      startCommitment: hash,
      usageCommitment: hash,
      attestationEvidenceHash: hash,
      billableComputeUnits: 1n,
      teeIdentity: tee as Address,
      state: 1,
    } as never);
    const blockRead = vi.spyOn(publicClient, "getBlock").mockResolvedValue({ timestamp: 19_000n } as never);

    const result = await loadVaultJob("job-alpha");

    expect(result.blockNumber).toBe(blockNumber);
    expect(result.blockTimestamp).toBe(19_000n);
    expect(bytecodeRead).toHaveBeenCalledWith(expect.objectContaining({ blockNumber }));
    expect(contractRead).toHaveBeenCalledWith(expect.objectContaining({ blockNumber }));
    expect(blockRead).toHaveBeenCalledWith({ blockNumber });
  });
});

describe("Compute vault verified end-user writes", () => {
  const originalDeployment = {
    ...computeVaultDeployment,
    issues: [...computeVaultDeployment.issues],
    token: computeVaultDeployment.token ? { ...computeVaultDeployment.token } : undefined,
  };
  const vaultRuntime = "0x6001600055" as Hex;
  const tokenRuntime = "0x6002600055" as Hex;
  const blockNumber = 55_555n;
  const projectReference = "project-sponsored";
  const projectId = computeVaultProjectId(projectReference);
  const nativeClaimable = 3_000_000_000_000_000n;
  const tokenClaimable = 7_000_000n;

  afterEach(() => {
    Object.assign(computeVaultDeployment, originalDeployment);
    vi.restoreAllMocks();
  });

  function configureActionRelease(): void {
    const config = configured();
    Object.assign(computeVaultDeployment, config, {
      codeHash: keccak256(vaultRuntime),
      token: {
        ...config.token!,
        codeHash: keccak256(tokenRuntime),
      },
    });
  }

  function mockActionReads(allowance = 100_000_000n): void {
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    vi.spyOn(publicClient, "getBytecode").mockImplementation((async (request: { address: Address }) => (
      request.address.toLowerCase() === token ? tokenRuntime : vaultRuntime
    )) as never);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: {
      functionName: string;
      args?: readonly unknown[];
      address?: Address;
    }) => {
      if (request.functionName === "paused") return false;
      if (request.functionName === "developer") return developer;
      if (request.functionName === "meteringVerifier") return verifier;
      if (request.functionName === "meteringQvlVerifier") return qvlVerifier;
      if (request.functionName === "meteringPolicySetHash") return meteringPolicySet;
      if (request.functionName === "pendingMeteringVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringQvlVerifier") return zeroAddress;
      if (request.functionName === "pendingMeteringPolicySetHash") return zeroHash;
      if (["pendingMeteringBindingActivatesAt", "pendingDeveloperFeeActivatesAt"].includes(request.functionName)) return 0n;
      if (["meteringBindingFrozen", "developerFeeFrozen", "composePolicyFrozen", "teeIdentityAdditionsFrozen", "assetAdditionsFrozen", "ratePolicyAdditionsFrozen"].includes(request.functionName)) return true;
      if (request.functionName === "allowedAssetCount" || request.functionName === "approvedComposeCount") return 1n;
      if (request.functionName === "activeRatePolicyCount") return 2n;
      if (request.functionName === "approvedTeeIdentityCount") return 1n;
      if (["pendingAssetCount", "pendingRatePolicyCount", "pendingComposeCount", "pendingTeeIdentityCount"].includes(request.functionName)) return 0n;
      if (request.functionName === "approvedComposeHashes") return true;
      if (request.functionName === "teeIdentityComposeHash") return hash;
      if (request.functionName === "ratePolicies") {
        return request.args?.[0] === tokenPolicy
          ? [token, provider, 500, true]
          : [zeroAddress, provider, 500, true];
      }
      if (request.functionName === "allowedAssets") return true;
      if (request.functionName === "symbol") return "USDC";
      if (request.functionName === "decimals") return 6;
      if (request.functionName === "credits") {
        return request.args?.[2] === zeroAddress
          ? [2_000_000_000_000_000_000n, 0n]
          : [200_000_000n, 0n];
      }
      if (request.functionName === "nextAuthorizationNonce") return 4n;
      if (request.functionName === "claimableAccrual") {
        return request.args?.[0] === zeroAddress ? nativeClaimable : tokenClaimable;
      }
      if (request.functionName === "balanceOf") return 500_000_000n;
      if (request.functionName === "allowance") return allowance;
      throw new Error(`Unexpected read ${request.functionName} at ${request.address ?? "unknown"}`);
    }) as never);
  }

  function mockSafetyOnlyReads(options: {
    tokenRuntime?: Hex;
    rejectTokenMetadata?: boolean;
  } = {}) {
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    vi.spyOn(publicClient, "getBytecode").mockImplementation((async (request: { address: Address }) => (
      request.address.toLowerCase() === token
        ? options.tokenRuntime ?? tokenRuntime
        : vaultRuntime
    )) as never);
    return vi.spyOn(publicClient, "readContract").mockImplementation((async (request: {
      functionName: string;
      args?: readonly unknown[];
    }) => {
      if (request.functionName === "symbol") {
        if (options.rejectTokenMetadata) throw new Error("token symbol RPC unavailable");
        return "USDC";
      }
      if (request.functionName === "decimals") {
        if (options.rejectTokenMetadata) throw new Error("token decimals RPC unavailable");
        return 6;
      }
      if (request.functionName === "credits") {
        return request.args?.[2] === zeroAddress
          ? [2_000_000_000_000_000_000n, 50_000_000_000_000_000n]
          : [200_000_000n, 25_000_000n];
      }
      if (request.functionName === "nextAuthorizationNonce") return 4n;
      if (request.functionName === "claimableAccrual") {
        return request.args?.[0] === zeroAddress ? nativeClaimable : tokenClaimable;
      }
      throw new Error(`Release-only read ${request.functionName} must not gate a safety action`);
    }) as never);
  }

  function mockWalletWrites(hashes: readonly Hex[]) {
    const writeContract = vi.fn();
    for (const transactionHash of hashes) writeContract.mockResolvedValueOnce(transactionHash);
    const client = { writeContract };
    vi.spyOn(wallet, "account").mockReturnValue(developer as Address);
    vi.spyOn(wallet, "client").mockReturnValue(client as never);
    vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
    vi.spyOn(wallet, "authorizationVersion").mockReturnValue(12);
    vi.spyOn(wallet, "refreshBalance").mockResolvedValue(undefined);
    const simulate = vi.spyOn(publicClient, "simulateContract").mockImplementation((async (request: {
      address: Address;
      functionName: string;
      args?: readonly unknown[];
      value?: bigint;
    }) => ({ request: { ...request, simulated: true } })) as never);
    return { writeContract, simulate };
  }

  function creditFundedLog(asset: Address, beneficiary: Address, amount: bigint) {
    return {
      address: vault as Address,
      topics: encodeEventTopics({
        abi: computeCreditVaultAbi,
        eventName: "CreditFunded",
        args: { projectId, beneficiary, asset },
      }),
      data: encodeAbiParameters(
        [{ name: "sponsor", type: "address" }, { name: "amount", type: "uint256" }],
        [developer as Address, amount],
      ),
    };
  }

  function nonceInvalidatedLog(previousNonce: bigint, newNonce: bigint) {
    return {
      address: vault as Address,
      topics: encodeEventTopics({
        abi: computeCreditVaultAbi,
        eventName: "AuthorizationNonceInvalidated",
        args: { projectId, user: developer as Address },
      }),
      data: encodeAbiParameters(
        [{ name: "previousNonce", type: "uint256" }, { name: "newNonce", type: "uint256" }],
        [previousNonce, newNonce],
      ),
    };
  }

  function accrualWithdrawnLog(asset: Address, amount: bigint) {
    return {
      address: vault as Address,
      topics: encodeEventTopics({
        abi: computeCreditVaultAbi,
        eventName: "AccrualWithdrawn",
        args: { recipient: developer as Address, asset },
      }),
      data: encodeAbiParameters([{ name: "amount", type: "uint256" }], [amount]),
    };
  }

  it("loads every risk-reducing slot without governance reads and survives token metadata failure", async () => {
    configureActionRelease();
    const contractRead = mockSafetyOnlyReads({ rejectTokenMetadata: true });

    const state = await loadComputeVaultSafetyState(developer as Address, projectReference);

    expect(state.deploymentVerified).toBe(true);
    expect(state.nextAuthorizationNonce).toBe(4n);
    expect(state.nativeCapacity).toMatchObject({ available: 2_000_000_000_000_000_000n, reserved: 50_000_000_000_000_000n });
    expect(state.tokenCapacity).toMatchObject({
      available: 200_000_000n,
      reserved: 25_000_000n,
      symbol: "RAW BASE UNITS",
      decimals: 0,
    });
    expect(state.nativeClaimableAccrual).toBe(nativeClaimable);
    expect(state.tokenClaimableAccrual).toBe(tokenClaimable);
    expect(state.tokenIdentity.verified).toBe(false);
    expect(state.tokenIdentity.reasons.join(" ")).toMatch(/symbol.*decimals/);

    const functionNames = contractRead.mock.calls.map(([request]) => (
      request as { functionName: string }
    ).functionName);
    expect(functionNames).not.toContain("paused");
    expect(functionNames).not.toContain("developer");
    expect(functionNames).not.toContain("meteringVerifier");
    expect(functionNames).not.toContain("ratePolicies");
    expect(functionNames).not.toContain("approvedComposeHashes");
  });

  it("keeps native unused withdrawal and nonce revocation available when token metadata reads fail", async () => {
    configureActionRelease();
    mockSafetyOnlyReads({ rejectTokenMetadata: true });
    const withdrawalHash = `0x${"77".repeat(32)}` as Hex;
    const nonceHash = `0x${"78".repeat(32)}` as Hex;
    const { simulate } = mockWalletWrites([withdrawalHash, nonceHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockImplementation((async ({ hash: receivedHash }: { hash: Hex }) => ({
      status: "success",
      logs: receivedHash === nonceHash ? [nonceInvalidatedLog(4n, 9n)] : [],
    })) as never);

    await expect(withdrawVaultUnused(projectReference, "native", 10_000n)).resolves.toBe(withdrawalHash);
    await expect(invalidateVaultAuthorizationNonce(projectReference, 9n)).resolves.toBe(nonceHash);

    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      address: vault,
      functionName: "withdrawUnused",
      args: [projectId, zeroAddress, 10_000n],
    }));
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      address: vault,
      functionName: "invalidateAuthorizationNonce",
      args: [projectId, 9n],
    }));
  });

  it("keeps ERC20 unused and accrued exits available in raw units when token identity drifts", async () => {
    configureActionRelease();
    mockSafetyOnlyReads({ tokenRuntime: "0x6003600055" as Hex });
    const withdrawalHash = `0x${"79".repeat(32)}` as Hex;
    const accrualHash = `0x${"7a".repeat(32)}` as Hex;
    const amountAtExecution = tokenClaimable + 900_000n;
    const { simulate } = mockWalletWrites([withdrawalHash, accrualHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockImplementation((async ({ hash: receivedHash }: { hash: Hex }) => ({
      status: "success",
      logs: receivedHash === accrualHash
        ? [accrualWithdrawnLog(token as Address, amountAtExecution)]
        : [],
    })) as never);

    await expect(withdrawVaultUnused(projectReference, "erc20", 100_000n)).resolves.toBe(withdrawalHash);
    await expect(withdrawVaultAccrued("erc20")).resolves.toEqual({
      hash: accrualHash,
      amount: amountAtExecution,
      symbol: "raw base units",
      decimals: 0,
      unitVerified: false,
    });

    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      address: vault,
      functionName: "withdrawUnused",
      args: [projectId, token, 100_000n],
    }));
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      address: vault,
      functionName: "withdrawAccrued",
      args: [token],
    }));
  });

  it("funds native capacity for a distinct beneficiary and verifies every receipt field", async () => {
    configureActionRelease();
    mockActionReads();
    const transactionHash = `0x${"71".repeat(32)}` as Hex;
    const amount = 25_000_000_000_000_000n;
    const { writeContract, simulate } = mockWalletWrites([transactionHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue({
      status: "success",
      logs: [creditFundedLog(zeroAddress, provider as Address, amount)],
    } as never);

    const result = await fundVaultNative(projectReference, amount, provider);

    expect(result).toBe(transactionHash);
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: developer,
      address: vault,
      functionName: "fundNative",
      args: [projectId, provider],
      value: amount,
    }));
    expect(writeContract).toHaveBeenCalledTimes(1);
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: transactionHash,
      confirmations: 2,
      timeout: 120_000,
    });
  });

  it("requests only the exact ERC20 approval when needed, then verifies sponsored funding", async () => {
    configureActionRelease();
    mockActionReads(0n);
    const approvalHash = `0x${"72".repeat(32)}` as Hex;
    const fundingHash = `0x${"73".repeat(32)}` as Hex;
    const amount = 12_500_000n;
    const { writeContract, simulate } = mockWalletWrites([approvalHash, fundingHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockImplementation((async ({ hash: receivedHash }: { hash: Hex }) => ({
      status: "success",
      logs: receivedHash === fundingHash ? [creditFundedLog(token as Address, provider as Address, amount)] : [],
    })) as never);

    const result = await fundVaultErc20(projectReference, amount, provider);

    expect(result).toBe(fundingHash);
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      address: token,
      functionName: "approve",
      args: [vault, amount],
    }));
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: developer,
      address: vault,
      functionName: "fundERC20",
      args: [projectId, provider, token, amount],
    }));
    expect(writeContract).toHaveBeenCalledTimes(2);
  });

  it("requires the exact monotonic nonce event and rejects the permanent uint256-max lock", async () => {
    configureActionRelease();
    mockActionReads();
    const transactionHash = `0x${"74".repeat(32)}` as Hex;
    const { simulate } = mockWalletWrites([transactionHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue({
      status: "success",
      logs: [nonceInvalidatedLog(4n, 9n)],
    } as never);

    expect(await invalidateVaultAuthorizationNonce(projectReference, 9n)).toBe(transactionHash);
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: developer,
      address: vault,
      functionName: "invalidateAuthorizationNonce",
      args: [projectId, 9n],
    }));
    await expect(invalidateVaultAuthorizationNonce(projectReference, (1n << 256n) - 1n)).rejects.toThrow(/permanently block/);
  });

  it("claims wallet-wide accrual without a project and returns the live receipt amount", async () => {
    configureActionRelease();
    mockActionReads();
    const transactionHash = `0x${"75".repeat(32)}` as Hex;
    const amountAtExecution = nativeClaimable + 2_000_000_000_000_000n;
    const { simulate } = mockWalletWrites([transactionHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue({
      status: "success",
      logs: [accrualWithdrawnLog(zeroAddress, amountAtExecution)],
    } as never);

    const result = await withdrawVaultAccrued("native");

    expect(result).toEqual({
      hash: transactionHash,
      amount: amountAtExecution,
      symbol: "ETH",
      decimals: 18,
      unitVerified: true,
    });
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: developer,
      address: vault,
      functionName: "withdrawAccrued",
      args: [zeroAddress],
    }));
  });

  it("rejects a successful receipt whose funding event names a different beneficiary", async () => {
    configureActionRelease();
    mockActionReads();
    const transactionHash = `0x${"76".repeat(32)}` as Hex;
    const amount = 1_000_000_000_000_000n;
    mockWalletWrites([transactionHash]);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue({
      status: "success",
      logs: [creditFundedLog(zeroAddress, developer as Address, amount)],
    } as never);

    await expect(fundVaultNative(projectReference, amount, provider)).rejects.toThrow(/does not match the payer, beneficiary/);
  });
});
