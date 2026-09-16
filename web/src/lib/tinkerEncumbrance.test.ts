import { afterEach, describe, expect, it, vi } from "vitest";
import { keccak256, zeroAddress, zeroHash, type Address, type Hex } from "viem";
import { deployment } from "../config";
import { publicClient } from "./contract";
import {
  assessTinkerRuntime,
  classifyTinkerPolicy,
  loadTinkerEncumbranceObservation,
  normalizeTinkerOperationId,
  tinkerAccountEncumbranceAbi,
} from "./tinkerEncumbrance";

const contract = "0x1111111111111111111111111111111111111111" as Address;
const owner = "0x2222222222222222222222222222222222222222" as Address;
const manager = "0x3333333333333333333333333333333333333333" as Address;
const requester = "0x4444444444444444444444444444444444444444" as Address;
const runtime = "0x60006000" as Hex;
const codeHash = keccak256(runtime);
const hash = `0x${"ab".repeat(32)}` as Hex;
const secondHash = `0x${"cd".repeat(32)}` as Hex;
const operationId = `0x${"ef".repeat(32)}` as Hex;
const blockHash = `0x${"12".repeat(32)}` as Hex;

describe("TinkerAccountEncumbrance public read boundary", () => {
  it("requires an exact configured address and matching runtime pin", () => {
    expect(assessTinkerRuntime({})).toMatchObject({ verified: false });
    expect(assessTinkerRuntime({ address: contract, configuredCodeHash: codeHash })).toMatchObject({ verified: false });
    expect(assessTinkerRuntime({ address: contract, configuredCodeHash: codeHash, observedCodeHash: codeHash })).toEqual({ verified: true, issues: [] });
    expect(assessTinkerRuntime({ address: zeroAddress, configuredCodeHash: codeHash, observedCodeHash: codeHash })).toMatchObject({ verified: false });
    expect(assessTinkerRuntime({ address: contract, configuredCodeHash: zeroHash, observedCodeHash: codeHash })).toMatchObject({ verified: false });
    expect(assessTinkerRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: `0x${"ff".repeat(32)}` as Hex,
    }).issues.join(" ")).toMatch(/does not match/);
  });

  it("accepts only one exact nonzero bytes32 operation ID", () => {
    expect(normalizeTinkerOperationId(`  ${operationId.toUpperCase().replace("0X", "0x")}  `)).toBe(operationId);
    expect(() => normalizeTinkerOperationId("operation-7")).toThrow(/exact nonzero bytes32/);
    expect(() => normalizeTinkerOperationId(zeroHash)).toThrow(/exact nonzero bytes32/);
  });

  it("classifies draft, review, frozen active, and frozen halted states without inventing runtime evidence", () => {
    const base = {
      releasePolicyFrozen: false,
      emergencyHalted: true,
      pendingReleasePolicyActivatesAt: 0n,
      pendingComposeCount: 0n,
      pendingManagerCount: 0n,
      pendingReleasePolicyCommitment: zeroHash,
    };
    expect(classifyTinkerPolicy(base)).toBe("draft_halted");
    expect(classifyTinkerPolicy({ ...base, pendingReleasePolicyActivatesAt: 9n })).toBe("pending_review");
    expect(classifyTinkerPolicy({ ...base, releasePolicyFrozen: true, emergencyHalted: false })).toBe("frozen_active");
    expect(classifyTinkerPolicy({ ...base, releasePolicyFrozen: true })).toBe("frozen_halted");
    expect(classifyTinkerPolicy({ ...base, emergencyHalted: false })).toBe("unfrozen_unhalted");
  });

  it("exposes only view functions and no account, funding, authorization, or settlement mutation", () => {
    const functions = tinkerAccountEncumbranceAbi.filter((entry) => entry.type === "function");
    expect(functions.every((entry) => entry.stateMutability === "view")).toBe(true);
    expect(functions.map((entry) => entry.name)).toContain("operation");
    expect(functions.map((entry) => entry.name)).not.toContain("authorizeOperation");
    expect(functions.map((entry) => entry.name)).not.toContain("settleOperation");
    expect(functions.map((entry) => entry.name)).not.toContain("proposeReleasePolicy");
  });
});

describe("TinkerAccountEncumbrance pinned observations", () => {
  const original = {
    encumbranceAddress: deployment.encumbranceAddress,
    encumbranceCodeHash: deployment.encumbranceCodeHash,
  };

  afterEach(() => {
    Object.assign(deployment, original);
    vi.restoreAllMocks();
  });

  function configure(): void {
    Object.assign(deployment, {
      encumbranceAddress: contract,
      encumbranceCodeHash: codeHash,
    });
  }

  function mockRead(request: { functionName: string }): unknown {
    const values: Record<string, unknown> = {
      owner,
      pendingOwner: zeroAddress,
      accountCommitment: hash,
      maxAddBalanceWei: 10_000_000_000_000_000_000n,
      maxSpendWei: 8_000_000_000_000_000_000n,
      emergencyHalted: false,
      releasePolicyFrozen: true,
      approvedComposeRoot: hash,
      approvedComposeCount: 1n,
      managerRoot: secondHash,
      managerCount: 1n,
      releasePolicyCommitment: secondHash,
      releaseMaxAddBalanceWei: 10_000_000_000_000_000_000n,
      releaseMaxSpendWei: 10_000_000_000_000_000_000n,
      releaseComposeRoot: hash,
      releaseComposeCount: 1n,
      releaseManagerRoot: secondHash,
      releaseManagerCount: 1n,
      pendingAccountCommitment: zeroHash,
      pendingMaxAddBalanceWei: 0n,
      pendingMaxSpendWei: 0n,
      pendingComposeRoot: zeroHash,
      pendingManagerRoot: zeroHash,
      pendingReleasePolicyCommitment: zeroHash,
      pendingReleasePolicyActivatesAt: 0n,
      pendingComposeCount: 0n,
      pendingManagerCount: 0n,
      operation: {
        kind: 2,
        requester,
        authorizer: manager,
        composeHash: hash,
        amountWei: 5_000_000_000_000_000_000n,
        settled: true,
        success: true,
        receiptHash: secondHash,
      },
    };
    if (!(request.functionName in values)) throw new Error(`Unexpected read ${request.functionName}`);
    return values[request.functionName];
  }

  it("verifies runtime and reads all policy plus one operation at the same block", async () => {
    configure();
    const blockNumber = 55_555n;
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    const blocks = vi.spyOn(publicClient, "getBlock").mockImplementation((async () => ({ number: blockNumber, hash: blockHash })) as typeof publicClient.getBlock);
    const bytecode = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => mockRead(request)) as never);

    const state = await loadTinkerEncumbranceObservation(operationId);

    expect(state).toMatchObject({
      runtimeVerified: true,
      chainId: 84_532,
      blockNumber,
      blockHash,
      phase: "frozen_active",
      maxAddBalancePolicyUnits: 10_000_000_000_000_000_000n,
      maxSpendPolicyUnits: 8_000_000_000_000_000_000n,
      approvedComposeCount: 1n,
      managerCount: 1n,
      pendingComposeCount: 0n,
      pendingManagerCount: 0n,
      issues: [],
      operation: {
        operationId,
        found: true,
        kind: 2,
        requester,
        authorizer: manager,
        amountPolicyUnits: 5_000_000_000_000_000_000n,
        settled: true,
        success: true,
      },
    });
    expect(bytecode).toHaveBeenCalledWith({ address: contract, blockNumber });
    expect(blocks.mock.calls[0]?.[0]).toEqual({ blockTag: "finalized" });
    expect(blocks.mock.calls[1]?.[0]).toEqual({ blockNumber });
    for (const [request] of reads.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
  });

  it("reports an exact missing operation without converting unrelated RPC errors into absence", async () => {
    configure();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({ number: 55_555n, hash: blockHash } as never);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "operation") throw new Error("execution reverted: UnknownOperation()");
      return mockRead(request);
    }) as never);

    const missing = await loadTinkerEncumbranceObservation(operationId);
    expect(missing.operation).toEqual({ operationId, found: false });

    vi.restoreAllMocks();
    configure();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({ number: 55_555n, hash: blockHash } as never);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "operation") throw new Error("RPC timeout");
      return mockRead(request);
    }) as never);
    await expect(loadTinkerEncumbranceObservation(operationId)).rejects.toThrow(/RPC timeout/);
  });

  it("stops before every policy and operation read when runtime bytes drift", async () => {
    configure();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({ number: 55_555n, hash: blockHash } as never);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue("0x6001" as Hex);
    const reads = vi.spyOn(publicClient, "readContract");

    const state = await loadTinkerEncumbranceObservation(operationId);

    expect(state.runtimeVerified).toBe(false);
    expect(state.issues.join(" ")).toMatch(/does not match/);
    expect(state.owner).toBeUndefined();
    expect(state.operation).toBeUndefined();
    expect(reads).not.toHaveBeenCalled();
  });

  it("performs no RPC call when either release identity input is absent", async () => {
    Object.assign(deployment, { encumbranceAddress: undefined, encumbranceCodeHash: undefined });
    const chain = vi.spyOn(publicClient, "getChainId");
    const block = vi.spyOn(publicClient, "getBlock");
    const bytecode = vi.spyOn(publicClient, "getBytecode");
    const reads = vi.spyOn(publicClient, "readContract");

    const state = await loadTinkerEncumbranceObservation();

    expect(state.runtimeVerified).toBe(false);
    expect(state.issues).toHaveLength(2);
    expect(chain).not.toHaveBeenCalled();
    expect(block).not.toHaveBeenCalled();
    expect(bytecode).not.toHaveBeenCalled();
    expect(reads).not.toHaveBeenCalled();
  });

  it("rejects a wrong chain before runtime or policy reads", async () => {
    configure();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(1);
    vi.spyOn(publicClient, "getBlock").mockResolvedValue({ number: 55_555n, hash: blockHash } as never);
    const bytecode = vi.spyOn(publicClient, "getBytecode");
    const reads = vi.spyOn(publicClient, "readContract");

    await expect(loadTinkerEncumbranceObservation()).rejects.toThrow(/Base Sepolia \(chain 84532\)/);
    expect(bytecode).not.toHaveBeenCalled();
    expect(reads).not.toHaveBeenCalled();
  });

  it("rejects if the finalized block hash changes after the read", async () => {
    configure();
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84_532);
    vi.spyOn(publicClient, "getBlock")
      .mockResolvedValueOnce({ number: 55_555n, hash: blockHash } as never)
      .mockResolvedValueOnce({ number: 55_555n, hash: secondHash } as never);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => mockRead(request)) as never);

    await expect(loadTinkerEncumbranceObservation()).rejects.toThrow(/block pin changed/);
  });
});
