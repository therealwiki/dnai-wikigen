import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, type Address, type Hex } from "viem";
import { publicClient } from "./contract";
import {
  assessEmailOracleReadiness,
  configuredEmailOracleRelease,
  observeEmailOracleReadiness,
  type EmailOracleReadinessObservation,
  type EmailOracleRelease,
} from "./emailOracleReadiness";

afterEach(() => vi.restoreAllMocks());

const ORACLE = "0x1000000000000000000000000000000000000001" as Address;
const CONSUMER = "0x2000000000000000000000000000000000000002" as Address;
const KMS = "0x3000000000000000000000000000000000000003" as Address;
const KMS_IMPLEMENTATION = "0x4000000000000000000000000000000000000004" as Address;
const ZERO_ADDRESS = `0x${"0".repeat(40)}` as Address;
const ORACLE_CODE = "0x60016000" as Hex;
const KMS_CODE = "0x60026000" as Hex;
const KMS_IMPLEMENTATION_CODE = "0x60036000" as Hex;
const BLOCK_HASH = `0x${"a".repeat(64)}` as Hex;
const COMPOSE_HASH = `0x${"b".repeat(64)}` as Hex;
const DEVICE_ID = `0x${"c".repeat(64)}` as Hex;
const CONSUMER_COMPOSE_HASH = `0x${"d".repeat(64)}` as Hex;
const REGISTRATION_TX_HASH = `0x${"e".repeat(64)}` as Hex;
const REGISTRATION_BLOCK_HASH = `0x${"f".repeat(64)}` as Hex;
const TARGET_BOOT_HASH = `0x${"1".repeat(64)}` as Hex;
const RESTART_PROOF_HASH = `0x${"2".repeat(64)}` as Hex;

const RELEASE: EmailOracleRelease = {
  address: ORACLE,
  runtimeCodeHash: keccak256(ORACLE_CODE),
};

function readyObservation(overrides: Partial<EmailOracleReadinessObservation> = {}): EmailOracleReadinessObservation {
  return {
    chainId: 84_532,
    blockNumber: 1_000n,
    blockHash: BLOCK_HASH,
    runtimeCodeHash: RELEASE.runtimeCodeHash,
    productionRelease: true,
    releaseConfigurationReady: true,
    oracleCodeFrozen: true,
    consumerRegistryFrozen: true,
    consumerManagerAdditionsFrozen: true,
    kmsBindingFrozen: true,
    allowAnyDevice: false,
    pendingOwner: ZERO_ADDRESS,
    allowedOracleComposeHashCount: 1n,
    pendingOracleComposeHashCount: 0n,
    allowedDeviceIdCount: 1n,
    consumerManagerCount: 1n,
    totalConsumerComposeHashCount: 1n,
    releaseOracleComposeHash: COMPOSE_HASH,
    releaseDeviceId: DEVICE_ID,
    releaseConsumerManager: CONSUMER,
    releaseConsumerAppId: CONSUMER,
    releaseConsumerComposeHash: CONSUMER_COMPOSE_HASH,
    oracleComposeRegistered: true,
    deviceRegistered: true,
    consumerManagerActive: true,
    consumerComposeHashCount: 1n,
    consumerComposeRegistered: true,
    consumerEmergencyRevoked: false,
    consumerAuthorized: true,
    kmsContract: KMS,
    kmsRuntimeCodeHash: keccak256(KMS_CODE),
    observedKmsRuntimeCodeHash: keccak256(KMS_CODE),
    kmsImplementation: KMS_IMPLEMENTATION,
    kmsImplementationRuntimeCodeHash: keccak256(KMS_IMPLEMENTATION_CODE),
    observedKmsImplementationRuntimeCodeHash: keccak256(KMS_IMPLEMENTATION_CODE),
    kmsRegistrationTxHash: REGISTRATION_TX_HASH,
    kmsRegistrationBlock: 900n,
    kmsRegistrationBlockHash: REGISTRATION_BLOCK_HASH,
    targetBootInfoHash: TARGET_BOOT_HASH,
    restartKeyDerivationProofHash: RESTART_PROOF_HASH,
    pendingKmsBindingActivatesAt: 0n,
    kmsRegisteredApp: true,
    ...overrides,
  };
}

describe("EmailOracleAuth finalized-block readiness", () => {
  it("fails closed unless both non-zero release identity pins are present", () => {
    expect(() => configuredEmailOracleRelease(undefined, RELEASE.runtimeCodeHash)).toThrow(/address and runtime code-hash pin/);
    expect(() => configuredEmailOracleRelease(RELEASE.address, undefined)).toThrow(/address and runtime code-hash pin/);
    expect(() => configuredEmailOracleRelease(ZERO_ADDRESS, RELEASE.runtimeCodeHash)).toThrow(/zero values/);
    expect(() => configuredEmailOracleRelease(RELEASE.address, `0x${"0".repeat(64)}`)).toThrow(/zero values/);
    expect(configuredEmailOracleRelease(RELEASE.address, RELEASE.runtimeCodeHash)).toEqual(RELEASE);
  });

  it("reads every release and membership fact at one finalized Base Sepolia block", async () => {
    const getterValues: Record<string, unknown> = {
      productionRelease: true,
      releaseConfigurationReady: true,
      oracleCodeFrozen: true,
      consumerRegistryFrozen: true,
      consumerManagerAdditionsFrozen: true,
      kmsBindingFrozen: true,
      allowAnyDevice: false,
      pendingOwner: ZERO_ADDRESS,
      allowedOracleComposeHashCount: 1n,
      pendingOracleComposeHashCount: 0n,
      allowedDeviceIdCount: 1n,
      consumerManagerCount: 1n,
      totalConsumerComposeHashCount: 1n,
      releaseOracleComposeHash: COMPOSE_HASH,
      releaseDeviceId: DEVICE_ID,
      releaseConsumerManager: CONSUMER,
      releaseConsumerAppId: CONSUMER,
      releaseConsumerComposeHash: CONSUMER_COMPOSE_HASH,
      allowedOracleComposeHashes: true,
      allowedDeviceIds: true,
      consumerManagers: true,
      consumerComposeHashCount: 1n,
      isConsumerComposeHashRegistered: true,
      consumerEmergencyRevoked: false,
      isConsumerAuthorized: true,
      kmsContract: KMS,
      kmsRuntimeCodeHash: keccak256(KMS_CODE),
      kmsImplementation: KMS_IMPLEMENTATION,
      kmsImplementationRuntimeCodeHash: keccak256(KMS_IMPLEMENTATION_CODE),
      kmsRegistrationTxHash: REGISTRATION_TX_HASH,
      kmsRegistrationBlock: 900n,
      kmsRegistrationBlockHash: REGISTRATION_BLOCK_HASH,
      targetBootInfoHash: TARGET_BOOT_HASH,
      restartKeyDerivationProofHash: RESTART_PROOF_HASH,
      pendingKmsBindingActivatesAt: 0n,
    };
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    const blocks = vi.spyOn(publicClient, "getBlock").mockImplementation((async () => ({
      number: 1_000n,
      hash: BLOCK_HASH,
    })) as typeof publicClient.getBlock);
    const bytecode = vi.spyOn(publicClient, "getBytecode").mockImplementation((async (request: { address: Address }) => {
      if (request.address.toLowerCase() === ORACLE.toLowerCase()) return ORACLE_CODE;
      if (request.address.toLowerCase() === KMS.toLowerCase()) return KMS_CODE;
      if (request.address.toLowerCase() === KMS_IMPLEMENTATION.toLowerCase()) return KMS_IMPLEMENTATION_CODE;
      return undefined;
    }) as typeof publicClient.getBytecode);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { address: Address; functionName: string }) => {
      if (request.address.toLowerCase() === KMS.toLowerCase() && request.functionName === "registeredApps") return true;
      return getterValues[request.functionName];
    }) as typeof publicClient.readContract);

    const result = await observeEmailOracleReadiness(RELEASE);
    expect(result).toMatchObject({
      blockNumber: 1_000n,
      blockHash: BLOCK_HASH,
      runtimeCodeHash: RELEASE.runtimeCodeHash,
      releaseConfigurationReady: true,
      consumerEmergencyRevoked: false,
      kmsRegisteredApp: true,
      observedKmsRuntimeCodeHash: keccak256(KMS_CODE),
      observedKmsImplementationRuntimeCodeHash: keccak256(KMS_IMPLEMENTATION_CODE),
    });
    expect(assessEmailOracleReadiness(result, RELEASE)).toEqual({ ready: true, blockers: [] });
    expect(blocks).toHaveBeenCalledTimes(2);
    expect(blocks.mock.calls[0]?.[0]).toEqual({ blockTag: "finalized" });
    expect(blocks.mock.calls[1]?.[0]).toEqual({ blockNumber: 1_000n });
    expect(bytecode.mock.calls.every(([request]) => request.blockNumber === 1_000n)).toBe(true);
    expect(reads.mock.calls.every(([request]) => request.blockNumber === 1_000n)).toBe(true);
    expect(reads.mock.calls.map(([request]) => request.functionName)).toContain("releaseConfigurationReady");
    expect(reads.mock.calls.map(([request]) => request.functionName)).toContain("consumerEmergencyRevoked");
    expect(reads.mock.calls.map(([request]) => request.functionName)).toContain("registeredApps");
  });

  it("rejects a contract runtime that differs from the release pin before trusting getters", async () => {
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({ number: 1_000n, hash: BLOCK_HASH } as never);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue("0x6009");
    const reads = vi.spyOn(publicClient, "readContract");
    await expect(observeEmailOracleReadiness(RELEASE)).rejects.toThrow(/runtime does not match/);
    expect(reads).not.toHaveBeenCalled();
  });

  it("keeps one-way freeze flags separate from dynamic emergency and KMS readiness", () => {
    const revoked = readyObservation({
      releaseConfigurationReady: false,
      consumerEmergencyRevoked: true,
      consumerAuthorized: false,
      kmsRegisteredApp: false,
    });
    const result = assessEmailOracleReadiness(revoked, RELEASE);
    expect(result.ready).toBe(false);
    expect(result.blockers).toContain("dynamic releaseConfigurationReady() is false");
    expect(result.blockers).toContain("release consumer is emergency revoked");
    expect(result.blockers).toContain("KMS registeredApps readback is false");
    expect(revoked.oracleCodeFrozen).toBe(true);
    expect(revoked.consumerRegistryFrozen).toBe(true);
  });

  it("blocks on KMS runtime drift even if the contract's dynamic read were reported true", () => {
    const drifted = readyObservation({ observedKmsRuntimeCodeHash: keccak256("0x6009") });
    const result = assessEmailOracleReadiness(drifted, RELEASE);
    expect(result.ready).toBe(false);
    expect(result.blockers).toContain("KMS proxy runtime differs from its frozen on-chain pin");
  });
});
