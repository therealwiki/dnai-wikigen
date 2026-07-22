import { afterEach, describe, expect, it, vi } from "vitest";
import {
  encodeAbiParameters,
  encodeEventTopics,
  keccak256,
  zeroAddress,
  type Address,
  type Hex,
} from "viem";
import { deployment } from "../config";
import { publicClient } from "./contract";
import { wallet } from "./wallet";
import {
  assessRoyaltyRuntime,
  formatRoyaltyAmount,
  loadRoyaltyRailState,
  normalizeRoyaltyDistributor,
  normalizeRoyaltyQueryRef,
  royaltyDistributorAbi,
  withdrawRoyaltyBalance,
} from "./royalty";

const contract = "0x1111111111111111111111111111111111111111" as Address;
const owner = "0x2222222222222222222222222222222222222222" as Address;
const distributor = "0x3333333333333333333333333333333333333333" as Address;
const usdc = "0x036CbD53842c5426634e7929541eC2318f3dCF7e" as Address;
const queryRef = `0x${"ab".repeat(32)}` as Hex;
const runtime = "0x60006000" as Hex;
const codeHash = keccak256(runtime);

function withdrawalReceipt(hash: Hex, token: Address, amount: bigint) {
  return {
    status: "success" as const,
    transactionHash: hash,
    from: owner,
    to: contract,
    logs: [{
      address: contract,
      topics: encodeEventTopics({
        abi: royaltyDistributorAbi,
        eventName: "RoyaltyWithdrawn",
        args: { owner, token },
      }),
      data: encodeAbiParameters([{ type: "uint256" }], [amount]),
    }],
  };
}

describe("RoyaltyDistributor exact public boundary", () => {
  it("requires the configured address and matching runtime pin", () => {
    expect(assessRoyaltyRuntime({})).toMatchObject({ verified: false });
    expect(assessRoyaltyRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: codeHash,
    }).issues.join(" ")).toMatch(/chain has not been verified/);
    expect(assessRoyaltyRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: codeHash,
      observedChainId: 84532,
    })).toEqual({ verified: true, issues: [] });
    expect(assessRoyaltyRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: `0x${"ff".repeat(32)}` as Hex,
      observedChainId: 84532,
    }).issues.join(" ")).toMatch(/does not match/);
    expect(assessRoyaltyRuntime({
      address: contract,
      configuredCodeHash: codeHash,
      observedCodeHash: codeHash,
      observedChainId: 1,
    }).issues.join(" ")).toMatch(/not Base Sepolia 84532/);
  });

  it("accepts only an exact address and nonzero bytes32 replay key", () => {
    expect(normalizeRoyaltyDistributor(distributor).toLowerCase()).toBe(distributor);
    expect(normalizeRoyaltyQueryRef(queryRef)).toBe(queryRef);
    expect(() => normalizeRoyaltyDistributor("alice.eth")).toThrow(/exact EVM address/);
    expect(() => normalizeRoyaltyDistributor(zeroAddress)).toThrow(/nonzero exact EVM address/);
    expect(() => normalizeRoyaltyQueryRef("query-1")).toThrow(/exact nonzero bytes32/);
    expect(() => normalizeRoyaltyQueryRef(`0x${"00".repeat(32)}`)).toThrow(/exact nonzero bytes32/);
  });

  it("formats exact asset units without inventing an exchange rate", () => {
    expect(formatRoyaltyAmount(1_250_000n, 6)).toBe("1.25");
    expect(formatRoyaltyAmount(3_000_000_000_000_000n, 18)).toBe("0.003");
  });

  it("exposes reads and self-withdrawals but no browser distribution ABI", () => {
    const names = royaltyDistributorAbi.map((entry) => entry.name);
    expect(names).toContain("pending");
    expect(names).toContain("processedQueries");
    expect(names.filter((name) => name === "withdraw")).toHaveLength(2);
    expect(names).not.toContain("distributeNative");
    expect(names).not.toContain("distributeERC20");
  });
});

describe("RoyaltyDistributor pinned reads", () => {
  const original = {
    royaltyDistributorAddress: deployment.royaltyDistributorAddress,
    royaltyDistributorCodeHash: deployment.royaltyDistributorCodeHash,
    usdcAddress: deployment.usdcAddress,
  };

  afterEach(() => {
    Object.assign(deployment, original);
    vi.restoreAllMocks();
  });

  it("simulates and confirms only the connected owner's native pull payment", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const transactionHash = `0x${"44".repeat(32)}` as Hex;
    const writeContract = vi.fn().mockResolvedValue(transactionHash);
    vi.spyOn(wallet, "account").mockReturnValue(owner);
    vi.spyOn(wallet, "client").mockReturnValue({ writeContract } as never);
    vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
    vi.spyOn(wallet, "authorizationVersion").mockReturnValue(9);
    vi.spyOn(wallet, "refreshBalance").mockResolvedValue(undefined);
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(22_222n);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: { functionName: string }) => {
      if (request.functionName === "pending") return 5n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);
    const simulate = vi.spyOn(publicClient, "simulateContract").mockResolvedValue({ request: { exact: true } } as never);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue(
      withdrawalReceipt(transactionHash, zeroAddress, 5n) as never,
    );

    const result = await withdrawRoyaltyBalance("native");

    expect(result).toEqual({ hash: transactionHash, amount: 5n, symbol: "ETH", decimals: 18 });
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: owner,
      address: contract,
      functionName: "withdraw",
      args: [],
    }));
    expect(writeContract).toHaveBeenCalledWith({ exact: true });
    expect(publicClient.waitForTransactionReceipt).toHaveBeenCalledWith({
      hash: transactionHash,
      confirmations: 2,
      timeout: 120_000,
    });
  });

  it("rejects a successful-looking receipt without the exact withdrawal event", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const transactionHash = `0x${"45".repeat(32)}` as Hex;
    vi.spyOn(wallet, "account").mockReturnValue(owner);
    vi.spyOn(wallet, "client").mockReturnValue({
      writeContract: vi.fn().mockResolvedValue(transactionHash),
    } as never);
    vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
    vi.spyOn(wallet, "authorizationVersion").mockReturnValue(9);
    const refreshBalance = vi.spyOn(wallet, "refreshBalance").mockResolvedValue(undefined);
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(22_222n);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockResolvedValue(5n as never);
    vi.spyOn(publicClient, "simulateContract").mockResolvedValue({ request: { exact: true } } as never);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue({
      status: "success",
      transactionHash,
      from: owner,
      to: contract,
      logs: [],
    } as never);

    await expect(withdrawRoyaltyBalance("native")).rejects.toThrow(/one exact royalty withdrawal event/);
    expect(refreshBalance).not.toHaveBeenCalled();
  });

  it("simulates the canonical ERC20 overload and reports its execution-time event amount", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const transactionHash = `0x${"55".repeat(32)}` as Hex;
    const writeContract = vi.fn().mockResolvedValue(transactionHash);
    vi.spyOn(wallet, "account").mockReturnValue(owner);
    vi.spyOn(wallet, "client").mockReturnValue({ writeContract } as never);
    vi.spyOn(wallet, "isCorrectChain").mockReturnValue(true);
    vi.spyOn(wallet, "authorizationVersion").mockReturnValue(9);
    vi.spyOn(wallet, "refreshBalance").mockResolvedValue(undefined);
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(22_222n);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    vi.spyOn(publicClient, "readContract").mockImplementation((async (request: {
      functionName: string;
      args?: readonly unknown[];
    }) => {
      if (request.functionName === "pending") return request.args?.[0] === zeroAddress ? 5n : 7n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);
    const simulate = vi.spyOn(publicClient, "simulateContract").mockResolvedValue({ request: { exact: true } } as never);
    // ERC20 withdrawals also emit a token Transfer log. The contract's exact
    // RoyaltyWithdrawn event remains independently identifiable among it.
    // Nine rather than the pinned seven also models an accrual landing between
    // the read and execution; the event is authoritative for the pulled amount.
    const receipt = withdrawalReceipt(transactionHash, usdc, 9n);
    receipt.logs.unshift({
      address: usdc,
      topics: [`0x${"66".repeat(32)}` as Hex],
      data: "0x" as Hex,
    } as never);
    vi.spyOn(publicClient, "waitForTransactionReceipt").mockResolvedValue(receipt as never);

    const result = await withdrawRoyaltyBalance("usdc");

    expect(result).toEqual({ hash: transactionHash, amount: 9n, symbol: "USDC", decimals: 6 });
    expect(simulate).toHaveBeenCalledWith(expect.objectContaining({
      account: owner,
      address: contract,
      functionName: "withdraw",
      args: [usdc],
    }));
    expect(writeContract).toHaveBeenCalledWith({ exact: true });
  });

  it("reads runtime, owner balances, and a replay slot from one block", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    const blockNumber = 22_222n;
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(blockNumber);
    const bytecode = vi.spyOn(publicClient, "getBytecode").mockResolvedValue(runtime);
    const reads = vi.spyOn(publicClient, "readContract").mockImplementation((async (request: {
      functionName: string;
      args?: readonly unknown[];
    }) => {
      if (request.functionName === "processedQueries") return true;
      if (request.functionName === "pending") return request.args?.[0] === zeroAddress ? 5n : 7n;
      throw new Error(`Unexpected read ${request.functionName}`);
    }) as never);

    const state = await loadRoyaltyRailState(owner, { distributor, queryRef });

    expect(state).toMatchObject({
      runtimeVerified: true,
      observedChainId: 84532,
      blockNumber,
      nativePending: 5n,
      usdcPending: 7n,
      replay: { distributor, queryRef, processed: true },
    });
    expect(bytecode).toHaveBeenCalledWith({ address: contract, blockNumber });
    for (const [request] of reads.mock.calls as unknown as Array<[{ blockNumber?: bigint }]>) {
      expect(request.blockNumber).toBe(blockNumber);
    }
  });

  it("stops before balance reads when runtime bytes drift", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(84532);
    vi.spyOn(publicClient, "getBlockNumber").mockResolvedValue(22_222n);
    vi.spyOn(publicClient, "getBytecode").mockResolvedValue("0x6001" as Hex);
    const reads = vi.spyOn(publicClient, "readContract");

    const state = await loadRoyaltyRailState(owner);

    expect(state.runtimeVerified).toBe(false);
    expect(state.nativePending).toBeUndefined();
    expect(reads).not.toHaveBeenCalled();
  });

  it("stops before block and bytecode reads when the RPC is not Base Sepolia", async () => {
    Object.assign(deployment, {
      royaltyDistributorAddress: contract,
      royaltyDistributorCodeHash: codeHash,
      usdcAddress: usdc,
    });
    vi.spyOn(publicClient, "getChainId").mockResolvedValue(1);
    const getBlockNumber = vi.spyOn(publicClient, "getBlockNumber");
    const getBytecode = vi.spyOn(publicClient, "getBytecode");
    const reads = vi.spyOn(publicClient, "readContract");

    const state = await loadRoyaltyRailState(owner);

    expect(state).toMatchObject({ runtimeVerified: false, observedChainId: 1 });
    expect(state.issues.join(" ")).toMatch(/not Base Sepolia 84532/);
    expect(getBlockNumber).not.toHaveBeenCalled();
    expect(getBytecode).not.toHaveBeenCalled();
    expect(reads).not.toHaveBeenCalled();
  });
});
